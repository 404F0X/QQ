import ctypes
import hashlib
import os
import threading

from .errors import CapabilityUnavailable, InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_MASK = (1 << 64) - 1
_COUNTS = {'GetModuleHandleA': 1, 'GetProcAddress': 2, 'GetModuleHandleExW': 2,
           'GetModuleFileNameA': 2, 'RtlCaptureStackBackTrace': 3,
           'RtlCaptureContext': 0, 'RtlLookupFunctionEntry': 1, 'RtlVirtualUnwind': 5,
           'GetForegroundWindow': 0, 'GetWindowTextA': 2, 'GetClassNameA': 2,
           'GetWindowRect': 1, 'IsWindowVisible': 1, 'GetWindowThreadProcessId': 1,
           'GetCurrentProcessId': 0, 'GetCursorPos': 0, 'GetLastError': 0,
           'MultiByteToWideChar': 6, 'WideCharToMultiByte': 8,
           '_localtime64': 1, 'CRT.lc_locale_name': 0, 'PathFindFileNameA': 1}


class WindowsCallerObservations(WorkerObservations):
    def __init__(self, fallback=None, *, backend=None, ownimage_module=None,
                 allow_qqprotect_registry=False, registry_backend=None):
        if type(allow_qqprotect_registry) is not bool or (registry_backend is not None and not allow_qqprotect_registry):
            raise InputError('QQProtect registry backing requires its explicit boolean opt-in')
        self._protection_registry = None
        if allow_qqprotect_registry:
            from .primary_windows_protection_registry import WindowsProtectionRegistryObservations
            self._protection_registry = WindowsProtectionRegistryObservations(allow_qqprotect_registry=True, backend=registry_backend)
        self._backend = backend if backend is not None else WindowsCallerAPIBackend()
        self._fallback = WorkerObservations(fallback) if callable(fallback) else fallback
        self._ownimage_module = ownimage_module
        self._runtime = None
        self._identity = (os.getpid(), threading.get_native_id())
        self._closed = False
        self._snapshot = None
        self._step = 0
        self._lookup = False
        self._terminal = False
        self._modules = set()
        self._exports = set()
        self._addresses = set()
        self._windows = set()
        self._calendars = set()
        self._sequence = 0
        self._capture_provenance = None
        self._last_error = None
        self._last_error_origin = None
        self.records = []

    @property
    def diagnostics(self):
        return {'closed': self._closed, 'process_id': self._identity[0],
                'thread_id': self._identity[1], 'last_error_origin': self._last_error_origin,
                'protection_registry': None if self._protection_registry is None else self._protection_registry.snapshot(),
                'records': tuple(self.records)}

    def filetime(self):
        self._check(self._runtime)
        result, effects, error = self._backend.request('GetSystemTimePreciseAsFileTime', ())
        if result != 0 or not isinstance(effects, bytes) or len(effects) != 8:
            raise InputError('precise clock requires the actual FILETIME output buffer')
        self._last_error = error
        return int.from_bytes(effects, 'little')

    def core_request(self, runtime, name, arguments, output, *, observed_modules=()):
        self._check(runtime)
        if name == 'GetCurrentProcessId' and arguments == ():
            return self._backend.request(name, arguments)[0]
        if name == 'IsWindowVisible' and len(arguments) == 1:
            return self._backend.request(name, arguments)[0]
        if name == 'GetModuleHandleExA' and len(arguments) == 2 and arguments[0] == 6:
            result = self._backend.core_request(name, arguments, output)
            if result:
                module = int.from_bytes(output.raw, 'little')
                if self._ownimage_module is not None:
                    cap = self.ownimage_capability(runtime)
                    if module in (cap['guest_identity']['base'], cap['native_identity']['hmodule']):
                        raise PrimarySemanticUnavailable('own-image filename authority cannot enter general module provenance')
                self._modules.add(module)
            return result
        if name == 'GetModuleFileNameA':
            return self.core_filename_request(runtime, arguments, output, observed_modules=observed_modules)[0]
        raise PrimarySemanticUnavailable('raw main caller API is outside its observed support domain: ' + name)

    def ownimage_capability(self, runtime):
        self._check(runtime)
        if self._ownimage_module is None:
            return None
        if runtime is not self._ownimage_module._runtime:
            raise InputError('own-image capability belongs to another runtime')
        return self._ownimage_module.capability_snapshot()

    def core_filename_request(self, runtime, arguments, output, *, observed_modules=()):
        self._check(runtime)
        if type(arguments) is not tuple or len(arguments) != 2 or any(type(value) is not int for value in arguments):
            raise InputError('raw filename requires explicit module and DWORD capacity')
        if self._ownimage_module is not None and arguments[0] == self._ownimage_module.spec.guest_base:
            native_arguments, relocation = self._ownimage_module.filename_relocation(runtime, arguments)
            return self._backend.core_request('GetModuleFileNameA', native_arguments, output), relocation
        if ((arguments[0] == 0 or arguments[0] in self._modules or arguments[0] in observed_modules) and
                1 <= arguments[1] <= 520):
            return self._backend.core_request('GetModuleFileNameA', arguments, output), None
        raise PrimarySemanticUnavailable('raw main caller API is outside its observed support domain: GetModuleFileNameA')

    def core_path_request(self, runtime, name, output):
        self._check(runtime)
        return self._backend.core_path_request(name, output)

    def _check(self, runtime):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('Windows caller provider requires its live owning process and thread')
        if self._runtime is None:
            self._runtime = runtime
        elif self._runtime is not runtime:
            raise InputError('Windows caller provider is bound to one runtime')

    def _capture(self, address):
        snapshot = self._backend.capture(address)
        if (snapshot.process_id, snapshot.thread_id) != self._identity:
            raise InputError('caller bridge snapshot belongs to another process or thread')
        if snapshot.capture_address != address or not isinstance(snapshot.provenance, dict) or not snapshot.provenance:
            raise InputError('caller bridge capture provenance is missing or mismatched')
        provenance = snapshot.provenance
        expected = {'abi_version': 1, 'process_id': snapshot.process_id, 'thread_id': snapshot.thread_id,
                    'sequence': snapshot.sequence, 'requested_capture_address': address,
                    'capture_boundary': 'self-written helper / Python FFI'}
        if any(provenance.get(key) != value for key, value in expected.items()):
            raise InputError('caller bridge provenance differs from the current capture')
        for key in ('build_identity', 'source_identity'):
            digest = provenance.get(key)
            if not isinstance(digest, str) or len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest):
                raise InputError('caller bridge provenance requires build and source SHA256')
        self._host(provenance.get('native_capture_site'))
        if type(snapshot.sequence) is not int or snapshot.sequence <= self._sequence:
            raise InputError('caller bridge snapshot sequence must advance')
        if not isinstance(snapshot.context, bytes) or len(snapshot.context) != 1232 or len(snapshot.frames) > 2 or len(snapshot.steps) > 3:
            raise InputError('caller bridge snapshot exceeds its fixed ABI')
        for pc in snapshot.frames:
            self._host(pc)
        self._addresses.update(snapshot.frames)
        self._sequence = snapshot.sequence
        self._capture_provenance = dict(snapshot.provenance, requested_at_ordinal=len(self.records))
        return snapshot

    @staticmethod
    def _host(value):
        if type(value) is not int or not 0 < value <= _MASK:
            raise InputError('caller API requires an observed nonzero host address')

    def _dispatch(self, name, args):
        if name == 'GetLastError':
            if self._last_error is None:
                raise PrimarySemanticUnavailable('caller has no preceding native last-error observation')
            return self._last_error, None
        if name == 'GetModuleHandleA' and args != (b'ntdll.dll',):
            raise InputError('caller resolver only requests ntdll.dll')
        if name == 'GetProcAddress' and (args[0] not in self._modules or args[1] != b'RtlCaptureStackBackTrace'):
            raise InputError('caller export resolution requires the observed ntdll handle')
        if name == 'RtlCaptureStackBackTrace':
            if args[0] not in self._exports or args[1:] != (0, 2):
                raise InputError('caller backtrace requires the observed export and two-frame ABI')
            snapshot = self._capture(args[0])
            return len(snapshot.frames), b''.join(pc.to_bytes(8, 'little') for pc in snapshot.frames)
        if name == 'RtlCaptureContext':
            snapshot = self._capture(None)
            self._snapshot, self._step, self._lookup, self._terminal = snapshot, 0, False, False
            return None, snapshot.context
        if name in ('RtlLookupFunctionEntry', 'RtlVirtualUnwind'):
            snapshot = self._snapshot
            if snapshot is None or self._step >= len(snapshot.steps) or self._terminal:
                raise PrimarySemanticUnavailable('caller bridge has no coherent unwind step')
            step = snapshot.steps[self._step]
            if not isinstance(step.before, bytes) or len(step.before) != 1232:
                raise InputError('caller bridge before-context ABI mismatch')
            expected = snapshot.context if self._step == 0 else snapshot.steps[self._step - 1].after
            if step.before != expected or int.from_bytes(step.before[248:256], 'little') != step.pc:
                raise InputError('caller bridge unwind chain is incoherent')
            if name == 'RtlLookupFunctionEntry':
                if args != (step.pc,) or self._lookup:
                    raise InputError('caller lookup PC differs from captured context')
                if step.error and not step.entry:
                    raise PrimarySemanticUnavailable('caller bridge lookup failed: ' + step.error)
                self._addresses.add(step.pc)
                self._lookup = True
                self._terminal = step.entry == 0
                return step.entry, None if not step.entry else step.image_base.to_bytes(8, 'little')
            if not self._lookup or args != (0, step.image_base, step.pc, step.entry, step.before) or not step.entry:
                raise InputError('caller unwind inputs differ from the coherent native snapshot')
            if step.error:
                raise PrimarySemanticUnavailable('caller bridge unwind failed: ' + step.error)
            if not isinstance(step.after, bytes) or len(step.after) != 1232 or type(step.unwind_result) is not int:
                raise InputError('caller bridge after-context ABI mismatch')
            self._step += 1
            self._lookup = False
            return step.unwind_result, step.after
        if name == 'GetModuleHandleExW' and (args[0] != 6 or args[1] not in self._addresses):
            raise InputError('caller module lookup requires an observed captured host PC and flags6')
        if name == 'GetModuleFileNameA' and (args[0] not in self._modules or type(args[1]) is not int or not 1 <= args[1] <= 519):
            raise InputError('caller filename requires an observed module and bounded output')
        if name in ('GetWindowTextA', 'GetClassNameA') and (type(args[1]) is not int or not 1 <= args[1] <= 259):
            raise InputError('caller window text capacity exceeds the source ABI')
        if name in ('GetWindowTextA', 'GetClassNameA', 'GetWindowRect', 'IsWindowVisible', 'GetWindowThreadProcessId') and args[0] not in self._windows:
            raise InputError('caller window API requires an observed foreground handle')
        result, effects, error = self._backend.request(name, args)
        if type(error) is not int or not 0 <= error <= 0xFFFFFFFF:
            raise InputError('native backend must return its immediately captured last-error DWORD')
        self._last_error = error
        self._last_error_origin = (name, len(self.records))
        if name == 'GetModuleHandleA' and result:
            self._host(result)
            self._modules.add(result)
        if name == 'GetProcAddress' and result:
            self._host(result)
            self._exports.add(result)
        if name == 'GetForegroundWindow' and result:
            self._host(result)
            self._windows.add(result)
        if name == 'GetModuleHandleExW' and result:
            if not isinstance(effects, bytes) or len(effects) != 8:
                raise InputError('native module lookup requires its handle output buffer')
            handle = int.from_bytes(effects, 'little')
            self._host(handle)
            self._modules.add(handle)
        return result, effects

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if self._protection_registry is not None and self._protection_registry.handles(name, arguments):
            return self._protection_registry.take(runtime, name, arguments)
        if name not in _COUNTS:
            if self._fallback is not None:
                return self._fallback.take(runtime, name, arguments)
            raise PrimarySemanticUnavailable('unsupported Windows caller observation: ' + name)
        if not isinstance(arguments, tuple) or len(arguments) != _COUNTS[name]:
            raise InputError('caller observation argument count mismatch: ' + name)
        try:
            result, effects = self._dispatch(name, arguments)
            if not (result is None and name == 'RtlCaptureContext') and (type(result) is not int or not 0 <= result <= _MASK):
                raise InputError('caller native result is outside its unsigned ABI')
            if name == '_localtime64' and result:
                if not isinstance(effects, bytes) or len(effects) != 36 or result > _MASK - 36:
                    raise InputError('caller CRT calendar requires its complete nonwrapping buffer')
                for region in runtime.memory._regions:
                    if result < region.address + len(region.data) and region.address < result + 36:
                        if not (result in self._calendars and region.address == result and len(region.data) == 36 and
                                region.name == 'explicit CRT localtime64 calendar buffer'):
                            raise PrimarySemanticUnavailable('actual CRT calendar address overlaps unrelated guest memory')
                self._calendars.add(result)
        except Exception as error:
            self.records.append({'api': name, 'status': type(error).__name__})
            raise
        self.records.append({'api': name, 'status': 'observed', 'effect_bytes': len(effects) if isinstance(effects, bytes) else 0,
                             'effect_sha256': hashlib.sha256(effects).hexdigest() if isinstance(effects, bytes) else None,
                             'capture_provenance': dict(self._capture_provenance) if name in ('RtlCaptureStackBackTrace', 'RtlCaptureContext') else None})
        runtime.events.append(('worker.API', name, arguments, result, effects))
        return result, effects

    def close(self):
        if self._closed:
            return
        self._check(self._runtime)
        if self._protection_registry is not None:
            self._protection_registry.close()
        self._backend.close()
        self._snapshot = None
        self._closed = True


class WindowsCallerAPIBackend:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable('Windows caller observations require Windows x64')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.user = ctypes.WinDLL('user32', use_last_error=True)
        self.crt = ctypes.CDLL('ucrtbase', use_last_error=True)
        self.shell = ctypes.WinDLL('shlwapi', use_last_error=True)
        self.bridge = None

    def _call(self, library, name, result_type, types, values):
        try:
            function = getattr(library, name)
        except AttributeError as error:
            raise PrimarySemanticUnavailable('native caller export is unavailable: ' + name) from error
        function.restype, function.argtypes = result_type, types
        result = function(*values)
        error = ctypes.get_last_error()
        return (int(result or 0) & _MASK), error

    def core_request(self, name, args, output):
        p, u = ctypes.c_void_p, ctypes.c_uint32
        if name == 'GetModuleHandleExA':
            result, _ = self._call(self.kernel, name, ctypes.c_int32, (u, p, p), (*args, output))
            return result & 0xFFFFFFFF
        if name == 'GetModuleFileNameA':
            result, _ = self._call(self.kernel, name, u, (p, p, u), (args[0], output, args[1]))
            return result
        raise PrimarySemanticUnavailable('unsupported raw main caller output API: ' + name)

    def core_path_request(self, name, output):
        p = ctypes.c_void_p
        if name == 'PathFindFileNameA':
            result, _ = self._call(self.shell, name, p, (p,), (output,))
            offset = result - ctypes.addressof(output)
            if not 0 <= offset < len(output):
                raise PrimarySemanticUnavailable('raw path filename pointer is outside its own actual input buffer')
            return result, offset
        if name == 'PathStripPathA':
            function = self.shell.PathStripPathA
            function.restype, function.argtypes = None, (p,)
            function(output)
            return None, None
        raise PrimarySemanticUnavailable('unsupported raw main path API: ' + name)

    def request(self, name, args):
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int
        if name == 'GetModuleHandleA':
            result, error = self._call(self.kernel, name, p, (ctypes.c_char_p,), args)
            return result, None, error
        if name == 'GetProcAddress':
            result, error = self._call(self.kernel, name, p, (p, ctypes.c_char_p), args)
            return result, None, error
        if name == 'PathFindFileNameA':
            raw = args[0]
            if not isinstance(raw, bytes) or not 1 <= len(raw) <= 520 or raw[-1:] != b'\0' or b'\0' in raw[:-1]:
                raise InputError('caller filename parsing requires one bounded terminated ANSI string')
            source = ctypes.create_string_buffer(raw)
            result, error = self._call(self.shell, name, p, (p,), (source,))
            offset = result - ctypes.addressof(source)
            if not 0 <= offset < len(raw):
                raise PrimarySemanticUnavailable('PathFindFileNameA returned outside its actual input buffer')
            return offset, None, error
        if name == 'GetModuleHandleExW':
            output = p()
            result, error = self._call(self.kernel, name, i, (u, p, ctypes.POINTER(p)), (*args, ctypes.byref(output)))
            return result, bytes(output) if result else b'', error
        if name in ('GetModuleFileNameA', 'GetWindowTextA', 'GetClassNameA'):
            output = ctypes.create_string_buffer(args[1] if name == 'GetModuleFileNameA' else 260)
            library = self.kernel if name == 'GetModuleFileNameA' else self.user
            result, error = self._call(library, name, u, (p, p, u), (args[0], output, args[1]))
            size = min(result + 1, args[1]) if result else 0
            return result, output.raw[:size], error
        if name in ('GetWindowRect', 'GetCursorPos', 'GetWindowThreadProcessId'):
            size = {'GetWindowRect': 16, 'GetCursorPos': 8, 'GetWindowThreadProcessId': 4}[name]
            output = ctypes.create_string_buffer(size)
            result, error = self._call(self.user, name, u, (p,) * (len(args) + 1), (*args, output))
            if not result and name in ('GetWindowRect', 'GetCursorPos'):
                raise PrimarySemanticUnavailable(name + ' did not initialize its native output')
            return result, output.raw if result else b'', error
        if name in ('GetForegroundWindow', 'IsWindowVisible', 'GetCurrentProcessId'):
            library = self.kernel if name == 'GetCurrentProcessId' else self.user
            result, error = self._call(library, name, p if name == 'GetForegroundWindow' else u, (p,) * len(args), args)
            return result, None, error
        if name in ('MultiByteToWideChar', 'WideCharToMultiByte'):
            wide = name == 'WideCharToMultiByte'
            cp, flags, raw, count, destination, capacity = args[:6]
            unit = 2 if wide else 1
            if (not isinstance(raw, bytes) or not raw.endswith(bytes(unit)) or len(raw) % unit or
                    count != -1 or type(destination) is not bool or type(capacity) is not int or
                    not 0 <= capacity <= 1 << 20 or destination != (capacity != 0) or
                    cp != (65001 if wide else 0) or flags != 0 or (wide and args[6:] != (0, 0))):
                raise InputError('caller conversion differs from its compressed source ABI')
            source = ctypes.create_string_buffer(raw)
            output = ctypes.create_string_buffer(capacity * (1 if wide else 2)) if destination else None
            values = (cp, flags, source, count, output, capacity) + ((None, None) if wide else ())
            types = (u, u, p, i, p, i) + ((p, p) if wide else ())
            result, error = self._call(self.kernel, name, i, types, values)
            return result, output.raw[:result * (1 if wide else 2)] if output is not None else b'', error
        if name == '_localtime64':
            if type(args[0]) is not int or not -(1 << 63) <= args[0] < 1 << 63:
                raise InputError('caller CRT seconds require signed64')
            seconds = ctypes.c_int64(args[0])
            result, error = self._call(self.crt, name, p, (ctypes.POINTER(ctypes.c_int64),), (ctypes.byref(seconds),))
            return result, ctypes.string_at(result, 36) if result else None, error
        if name == 'GetSystemTimePreciseAsFileTime':
            output = ctypes.c_uint64()
            function = self.kernel.GetSystemTimePreciseAsFileTime
            function.restype, function.argtypes = None, (ctypes.POINTER(ctypes.c_uint64),)
            function(ctypes.byref(output))
            error = ctypes.get_last_error()
            return 0, bytes(output), error
        if name == 'CRT.lc_locale_name':
            result, error = self._call(self.crt, '___lc_locale_name_func', p, (), ())
            if not result:
                raise PrimarySemanticUnavailable('CRT locale-name array is unavailable')
            value = ctypes.cast(result, ctypes.POINTER(p))[5]
            return int(value or 0), None, error
        raise PrimarySemanticUnavailable('native caller API is unsupported: ' + name)

    def capture(self, address):
        if self.bridge is None:
            from .primary_windows_caller_bridge import WindowsCallerBridge
            path = os.environ.get('QQ_NT_REPLICA_CALLER_BRIDGE')
            if not path or not os.path.isabs(path):
                raise CapabilityUnavailable('QQ_NT_REPLICA_CALLER_BRIDGE must identify the owned native bridge DLL')
            self.bridge = WindowsCallerBridge(path)
        return self.bridge.capture(address)

    def close(self):
        if self.bridge is not None:
            self.bridge.close()
