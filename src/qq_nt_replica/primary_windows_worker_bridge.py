import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import itertools
import json
import os
from pathlib import Path
import struct
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


_COOKIE = 0x5057425249444731
_HOST_FAILURE = 0xE0001046
_LIVE_BRIDGES = set()
_ACTIONS = {'return': 0, 'ExitThread': 1, 'FreeLibraryAndExitThread': 2}


class _LaunchRecord(ctypes.Structure):
    _fields_ = [('abi_version', ctypes.c_uint32), ('size', ctypes.c_uint32),
                ('dispatch', ctypes.c_uint64), ('token', ctypes.c_uint64), ('module', ctypes.c_uint64),
                ('action', ctypes.c_uint32), ('exit_code', ctypes.c_uint32),
                ('host_status', ctypes.c_uint32), ('state', ctypes.c_uint32),
                ('callback_result', ctypes.c_uint32), ('win32_error', ctypes.c_uint32),
                ('process_id', ctypes.c_uint32), ('thread_id', ctypes.c_uint32),
                ('marker', ctypes.c_uint64), ('cookie', ctypes.c_uint64)]


@dataclass(frozen=True)
class NativeWorkerExit:
    action: str
    code: int
    module: int = 0


class WorkerModuleReference:
    def __init__(self, bridge, module, result, error):
        self.bridge, self._module = bridge, module
        self.result, self.error = result, error
        self.state = 'acquired' if result else 'lookup_failed'
        self.launch = None

    @property
    def module(self):
        return self._module

    def close_host_reference(self):
        self.bridge._check_owner()
        if self not in self.bridge._references:
            raise InputError('worker module release requires its registered reference')
        if self.state in ('host_released', 'lookup_failed'):
            return
        if self.module != self.bridge._owner_module:
            raise InputError('worker module release requires its personally loaded module')
        if self.state != 'acquired':
            raise InputError('worker module reference was already consumed by its native epilogue')
        if self.launch is not None and self.launch.handle and not self.launch.joined:
            raise InputError('worker module reference cannot be released before its native thread joins')
        ctypes.set_last_error(0)
        result = self.bridge.kernel.FreeLibrary(self.module)
        error = ctypes.get_last_error()
        self.bridge.records.append({'api': 'FreeLibrary', 'ownership': 'standalone_host_lease', 'result': result, 'error': error})
        if not result:
            raise PrimarySemanticUnavailable('worker host module reference release failed: ' + str(error))
        self.state = 'host_released'


class WorkerBridgeLaunch:
    def __init__(self, bridge, token, dispatch, context, reference, quiescence_check):
        self.bridge, self.token, self.dispatch, self.context = bridge, token, dispatch, context
        self.reference, self.quiescence_check = reference, quiescence_check
        self.handle = self.thread_id = self.creation_error = 0
        self.joined = self.handle_closed = self.retired = False
        self.exit_code = None
        self.failure = None
        self._dispatch_failure = None
        self.request = None
        self.record = _LaunchRecord(1, 80, 0, token, reference.module if reference else 0,
                                    0, 0, 0, 0, 0, 0, bridge._owner[0], 0, bridge.marker, _COOKIE)
        self.callback = bridge._callback_type(self._dispatch)
        self.record.dispatch = ctypes.cast(self.callback, ctypes.c_void_p).value

    def _dispatch(self, token, pointer):
        try:
            if (os.getpid() != self.bridge._owner[0] or token != self.token or
                    self.bridge._launches.get(token) is not self or ctypes.addressof(pointer.contents) != ctypes.addressof(self.record) or
                    self.record.state != 1 or self.record.thread_id != threading.get_native_id()):
                raise InputError('worker dispatch requires its retained launch record and exact native thread')
            request = self.dispatch(self.context)
            if not isinstance(request, NativeWorkerExit) or request.action not in _ACTIONS or type(request.code) is not int or not 0 <= request.code <= 0xFFFFFFFF or type(request.module) is not int:
                raise InputError('worker dispatch requires an exact structured DWORD native exit request')
            if request.action == 'FreeLibraryAndExitThread':
                if self.reference is None or self.reference.state != 'acquired' or request.module != self.reference.module:
                    raise InputError('worker native free-and-exit requires this launch personally acquired module reference')
            elif request.module != 0 or request.action == 'ExitThread' and self.reference is not None and self.reference.state == 'acquired':
                raise InputError('worker exit request module ownership does not match its native action')
            self.request = request
            self.record.action, self.record.exit_code, self.record.module = _ACTIONS[request.action], request.code, request.module
            return 0
        except BaseException as error:
            self.failure = error
            self._dispatch_failure = error
            self.record.host_status = 2
            return 1

    def get_thread_id(self):
        self.bridge._check_creator()
        if not self.handle or self.handle_closed:
            raise InputError('worker thread ID query requires its still-owned native handle')
        ctypes.set_last_error(0)
        identifier = self.bridge.kernel.GetThreadId(self.handle)
        error = ctypes.get_last_error()
        self.bridge.records.append({'api': 'GetThreadId', 'result': identifier, 'error': error})
        if not identifier or identifier != self.thread_id:
            raise PrimarySemanticUnavailable('worker thread ID query failed or changed: ' + str(error))
        return identifier

    def join(self, timeout_ms=10000):
        self.bridge._check_owner()
        if type(timeout_ms) is not int or not 0 <= timeout_ms < 0xFFFFFFFF or not self.handle:
            raise InputError('worker join requires an actual handle and bounded DWORD timeout')
        if self.joined:
            return self.snapshot()
        ctypes.set_last_error(0)
        result = self.bridge.kernel.WaitForSingleObject(self.handle, timeout_ms)
        error = ctypes.get_last_error()
        self.bridge.records.append({'api': 'WaitForSingleObject', 'result': result, 'error': error})
        if result != 0:
            raise PrimarySemanticUnavailable('worker native termination remains unproved: ' + str(result))
        code = ctypes.c_uint32()
        if not self.bridge.kernel.GetExitCodeThread(self.handle, ctypes.byref(code)):
            raise PrimarySemanticUnavailable('worker native exit-code query failed: ' + str(ctypes.get_last_error()))
        self.exit_code = code.value
        self.joined = True
        if not self.bridge.kernel.CloseHandle(self.handle):
            raise PrimarySemanticUnavailable('worker native thread handle close failed: ' + str(ctypes.get_last_error()))
        self.handle_closed = True
        valid = (self.request is not None and not self.record.host_status and not self.record.callback_result and
                 self.exit_code == self.request.code and self.record.thread_id == self.thread_id and
                 self.record.state == (5 if self.request.action == 'return' else 3))
        if valid and self.request.action == 'FreeLibraryAndExitThread':
            self.reference.state = 'native_epilogue_consumed'
        elif not valid and self.failure is None:
            self.failure = PrimarySemanticUnavailable('worker native epilogue differs from its validated dispatch request')
        return self.snapshot()

    def close_host_failure_reference(self, reference):
        self.bridge._check_owner()
        record, bridge = self.record, self.bridge
        if (type(reference) is not WorkerModuleReference or reference is not self.reference or
                reference.bridge is not bridge or reference.launch is not self or
                reference not in bridge._references or reference.state != 'acquired' or not reference.result or
                not bridge._owner_module or reference.module != bridge._owner_module or
                bridge._launches.get(self.token) is not self or not self.token or
                not self.handle or not self.joined or not self.handle_closed or self.retired or
                not self.thread_id or self.thread_id == bridge._owner[1] or
                not isinstance(self._dispatch_failure, BaseException) or self.failure is not self._dispatch_failure or
                self.request is not None or self.exit_code != _HOST_FAILURE or
                type(record) is not _LaunchRecord or record.abi_version != 1 or record.size != 80 or
                record.cookie != _COOKIE or record.token != self.token or
                record.module != reference.module or record.action != 0 or record.exit_code != 0 or
                record.state != 2 or record.host_status != 2 or record.callback_result != 1 or record.win32_error != 0 or
                record.process_id != bridge._owner[0] or record.thread_id != self.thread_id or
                record.marker != bridge.marker or not record.marker or not callable(self.dispatch) or
                type(self.callback) is not bridge._callback_type or
                record.dispatch != ctypes.cast(self.callback, ctypes.c_void_p).value or
                self.quiescence_check() is not True):
            return False
        reference.close_host_reference()
        return True

    def retire_host_resources(self):
        self.bridge._check_owner()
        if self.retired:
            return
        if self.handle and (not self.joined or not self.handle_closed):
            raise InputError('worker launch dependencies require actual native join and handle close')
        if self.reference is not None and self.reference.state == 'acquired':
            raise InputError('worker launch retains its separate module reference; source cleanup is not implied')
        if self.quiescence_check() is not True:
            raise PrimarySemanticUnavailable('worker launch retains unknown or failed FLS/domain obligations')
        self.retired = True
        self.bridge._launches.pop(self.token)
        self.dispatch = self.context = self.callback = self.quiescence_check = None

    def snapshot(self):
        return {'handle': self.handle, 'thread_id': self.thread_id, 'callback_thread_id': self.record.thread_id,
                'creation_error': self.creation_error, 'joined': self.joined, 'handle_closed': self.handle_closed,
                'native_exit_code': self.exit_code, 'native_record_state': self.record.state,
                'host_status': self.record.host_status, 'callback_result': self.record.callback_result,
                'native_error': self.record.win32_error, 'retired': self.retired,
                'requested_action': None if self.request is None else self.request.action,
                'failure_type': None if self.failure is None else type(self.failure).__name__,
                'module_reference_state': None if self.reference is None else self.reference.state}


class WindowsWorkerBridge:
    def __init__(self, dll_path):
        offsets = tuple(getattr(_LaunchRecord, name).offset for name in (
            'dispatch', 'token', 'module', 'action', 'host_status', 'state',
            'callback_result', 'process_id', 'thread_id', 'marker', 'cookie'))
        if (os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(_LaunchRecord) != 80 or
                offsets != (8, 16, 24, 32, 40, 44, 48, 56, 60, 64, 72)):
            raise PrimarySemanticUnavailable('worker bridge requires Windows x64 launch ABI80')
        self._owner = os.getpid(), threading.get_native_id()
        self._closed = False
        self._owner_module = 0
        self._launches, self._references = {}, []
        self._tokens = itertools.count(1)
        self.records = []
        self.close_status = 'not_loaded'
        path = Path(dll_path)
        if not path.is_absolute() or '..' in path.parts:
            raise InputError('worker bridge requires an absolute owned DLL path')
        for candidate in (path, *path.parents):
            information = candidate.lstat()
            if candidate.is_symlink() or getattr(information, 'st_file_attributes', 0) & 0x400:
                raise InputError('worker bridge paths cannot traverse reparse points')
        manifest_path = Path(str(path) + '.manifest.json')
        if manifest_path.is_symlink() or getattr(manifest_path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise InputError('worker bridge manifest cannot be a reparse point')
        raw, manifest = path.read_bytes(), json.loads(manifest_path.read_text(encoding='utf-8'))
        source = Path(__file__).with_name('native') / 'primary_worker_bridge.c'
        header = source.with_suffix('.h')
        pe = int.from_bytes(raw[60:64], 'little') if raw[:2] == b'MZ' else 0
        if (not pe or pe > len(raw) - 26 or raw[pe:pe + 4] != b'PE\0\0' or struct.unpack_from('<H', raw, pe + 4)[0] != 0x8664 or
                struct.unpack_from('<H', raw, pe + 24)[0] != 0x20B or manifest.get('abi_version') != 1 or
                manifest.get('architecture') != 'AMD64' or manifest.get('dll_sha256') != hashlib.sha256(raw).hexdigest() or
                manifest.get('c_sha256') != hashlib.sha256(source.read_bytes()).hexdigest() or
                manifest.get('header_sha256') != hashlib.sha256(header.read_bytes()).hexdigest() or
                manifest.get('build_script_sha256') != hashlib.sha256((Path(__file__).with_name('tools') / 'build_primary_worker_bridge.py').read_bytes()).hexdigest() or
                manifest.get('source_identity') != hashlib.sha256(source.read_bytes() + header.read_bytes()).hexdigest()):
            raise InputError('worker bridge owned source/build/DLL identity mismatch')
        self.kernel = ctypes.WinDLL('kernel32', handle=ctypes.windll.kernel32._handle, use_last_error=True)
        for name, result, arguments in (
                ('GetModuleHandleExW', ctypes.c_int32, (ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))),
                ('FreeLibrary', ctypes.c_int32, (ctypes.c_void_p,)),
                ('CreateThread', ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))),
                ('GetThreadId', ctypes.c_uint32, (ctypes.c_void_p,)),
                ('WaitForSingleObject', ctypes.c_uint32, (ctypes.c_void_p, ctypes.c_uint32)),
                ('GetExitCodeThread', ctypes.c_int32, (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))),
                ('CloseHandle', ctypes.c_int32, (ctypes.c_void_p,))):
            function = getattr(self.kernel, name)
            function.restype, function.argtypes = result, arguments
        self._callback_type = ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_uint64, ctypes.POINTER(_LaunchRecord))
        self._dll = ctypes.WinDLL(str(path), use_last_error=True)
        self._owner_module = self._dll._handle
        try:
            for name in ('pwbridge_record_size_v1', 'pwbridge_abi_version_v1'):
                function = getattr(self._dll, name)
                function.restype, function.argtypes = ctypes.c_uint32, ()
            if (self._dll.pwbridge_record_size_v1(), self._dll.pwbridge_abi_version_v1()) != (80, 1):
                raise PrimarySemanticUnavailable('worker bridge native exported launch ABI mismatch')
            self.marker = ctypes.cast(self._dll.pwbridge_module_marker_v1, ctypes.c_void_p).value
            self.entry = ctypes.cast(self._dll.pwbridge_thread_entry_v1, ctypes.c_void_p).value
            self.close_status = 'loaded'
            _LIVE_BRIDGES.add(self)
        except BaseException as original:
            ctypes.set_last_error(0)
            result = self.kernel.FreeLibrary(self._owner_module)
            error = ctypes.get_last_error()
            self.records.append({'api': 'FreeLibrary', 'ownership': 'failed_construction_owner', 'result': result, 'error': error})
            if not result:
                _LIVE_BRIDGES.add(self)
                failure = BaseExceptionGroup('worker bridge construction retains its module reference',
                    [original, PrimarySemanticUnavailable('worker construction module release failed: ' + str(error))])
                failure.worker_bridge = self
                raise failure
            self._owner_module = 0
            raise

    def _check_owner(self):
        if self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('worker bridge requires its live creating process and native thread')

    def authorize_service(self, execution_check):
        self._check_owner()
        if not callable(execution_check) or hasattr(self, '_service_capability'):
            raise InputError('worker bridge requires one owner-issued execution capability')
        self._service_capability = object()
        self._service_execution_check = execution_check
        self._service_creators = set()
        return self._service_capability

    @contextmanager
    def service_creation(self, capability):
        if (self._closed or os.getpid() != self._owner[0] or capability is not getattr(self, '_service_capability', None) or
                capability is None or self._service_execution_check() is not True):
            raise InputError('worker service creation requires its owner capability and current runtime execution lease')
        tid = threading.get_native_id()
        if tid in self._service_creators:
            raise InputError('worker service creation scope cannot nest')
        self._service_creators.add(tid)
        try:
            yield
        finally:
            self._service_creators.remove(tid)

    def _check_creator(self):
        if (not self._closed and os.getpid() == self._owner[0] and
                threading.get_native_id() in getattr(self, '_service_creators', ()) and
                self._service_execution_check() is True):
            return
        self._check_owner()

    def acquire_worker_reference(self, image_base, guest_callback):
        self._check_creator()
        if type(image_base) is not int or type(guest_callback) is not int or not 0 < image_base <= (1 << 64) - 1 - 0x7879A0 or guest_callback != image_base + 0x7879A0:
            raise InputError('worker module lookup requires the exact source7879A0 callback mapping')
        module = ctypes.c_void_p()
        ctypes.set_last_error(0)
        result = self.kernel.GetModuleHandleExW(4, self.marker, ctypes.byref(module))
        error = ctypes.get_last_error()
        reference = WorkerModuleReference(self, int(module.value or 0), result & 0xFFFFFFFF, error)
        self._references.append(reference)
        self.records.append({'api': 'GetModuleHandleExW', 'flags': 4, 'result': result, 'error': error})
        if result and reference.module != self._owner_module:
            raise PrimarySemanticUnavailable('worker marker lookup did not identify the personally loaded worker DLL')
        return reference

    def launch(self, dispatch, context, *, module_reference=None, quiescence_check):
        self._check_creator()
        if not callable(dispatch) or not callable(quiescence_check):
            raise InputError('worker bridge launch requires retained dispatch and authoritative cleanup check')
        if module_reference is not None and (not isinstance(module_reference, WorkerModuleReference) or module_reference.bridge is not self or module_reference.state != 'acquired' or module_reference.module != self._owner_module or module_reference not in self._references or module_reference.launch is not None):
            raise InputError('worker launch requires an untransferred personally acquired module reference')
        token = next(self._tokens)
        launch = WorkerBridgeLaunch(self, token, dispatch, context, module_reference, quiescence_check)
        self._launches[token] = launch
        if module_reference is not None:
            module_reference.launch = launch
        identifier = ctypes.c_uint32()
        ctypes.set_last_error(0)
        handle = self.kernel.CreateThread(None, 0, self.entry, ctypes.byref(launch.record), 0, ctypes.byref(identifier))
        launch.handle, launch.thread_id, launch.creation_error = int(handle or 0), identifier.value, ctypes.get_last_error()
        self.records.append({'api': 'CreateThread', 'created': bool(handle), 'error': launch.creation_error})
        if handle and (not launch.thread_id or self.kernel.GetThreadId(handle) != launch.thread_id or launch.thread_id == self._owner[1]):
            launch.failure = PrimarySemanticUnavailable('worker real handle/native thread identity validation failed')
        return launch

    def close(self):
        if self._closed:
            return
        self._check_owner()
        if self._launches or any(reference.state == 'acquired' for reference in self._references):
            raise PrimarySemanticUnavailable('worker bridge retains launch/FLS obligations or acquired module references')
        ctypes.set_last_error(0)
        result = self.kernel.FreeLibrary(self._owner_module)
        error = ctypes.get_last_error()
        self.records.append({'api': 'FreeLibrary', 'ownership': 'owner_base', 'result': result, 'error': error})
        if not result:
            raise PrimarySemanticUnavailable('worker bridge owner module release failed: ' + str(error))
        self._owner_module = 0
        self._closed = True
        module = ctypes.c_void_p()
        ctypes.set_last_error(0)
        remaining = self.kernel.GetModuleHandleExW(6, self.marker, ctypes.byref(module))
        self.close_status = 'unloaded' if not remaining and ctypes.get_last_error() == 126 else 'owner_released_unload_unproved'
        _LIVE_BRIDGES.discard(self)
        if self.close_status != 'unloaded':
            raise PrimarySemanticUnavailable('worker bridge owner reference released but actual final unload is unproved')
