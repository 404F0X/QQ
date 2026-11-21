import ctypes
import os
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_MASK64 = (1 << 64) - 1
_RETAINED = set()
_MODULE_EXPORTS = {'api-ms-win-core-fibers-l1-1-2': {b'FlsGetValue2'}, 'kernelbase': {b'FlsGetValue2'},
                   'api-ms-win-core-winrt-l1-1-0': {b'RoInitialize', b'RoUninitialize'},
                   'api-ms-win-appmodel-runtime-l1-1-2': {b'AppPolicyGetThreadInitializationType'}}
_CACHE_EXPORTS = {24: b'FlsGetValue2', 0xC0: b'RoInitialize', 0xC8: b'RoUninitialize',
                  0xD8: b'AppPolicyGetThreadInitializationType'}


class WindowsCRTObservations(WorkerObservations):
    def __init__(self, *, callback_context=None, environment_factory=None):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise PrimarySemanticUnavailable('CRT observations require Windows x64')
        self._owner = os.getpid(), threading.get_native_id()
        self._runtime = None
        self._callback_context = callback_context
        self._environment_factory = environment_factory
        self._device_time = None
        self._closed = False
        self._locks = {}
        self._slots = {}
        self._tokens = {}
        self._values = {}
        self._modules = {}
        self._module_names = {}
        self._procedures = {}
        self._procedure_names = {}
        self._next_token = 0x7E1000000000
        self._cache = 0
        self._cache_writable = False
        self._callback_failure = None
        self._callbacks_active = 0
        self._active_callback_threads = {}
        self._retired_callbacks = []
        self._fls_free_records = []
        self.records = []
        self._mutex = threading.RLock()
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self._raw_kernel = ctypes.WinDLL('kernel32', handle=self.kernel._handle, use_last_error=False)
        self._raw_kernel.GetLastError.restype, self._raw_kernel.GetLastError.argtypes = ctypes.c_uint32, ()
        self._raw_kernel.SetLastError.restype, self._raw_kernel.SetLastError.argtypes = None, (ctypes.c_uint32,)
        self._callback_type = ctypes.WINFUNCTYPE(None, ctypes.c_void_p)
        signatures = (
            ('FlsAlloc', ctypes.c_uint32, (self._callback_type,)),
            ('FlsGetValue', ctypes.c_void_p, (ctypes.c_uint32,)),
            ('FlsSetValue', ctypes.c_int32, (ctypes.c_uint32, ctypes.c_void_p)),
            ('FlsFree', ctypes.c_int32, (ctypes.c_uint32,)),
            ('InitializeCriticalSectionEx', ctypes.c_int32, (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32)),
            ('EnterCriticalSection', None, (ctypes.c_void_p,)),
            ('LeaveCriticalSection', None, (ctypes.c_void_p,)),
            ('DeleteCriticalSection', None, (ctypes.c_void_p,)),
            ('LoadLibraryExW', ctypes.c_void_p, (ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32)),
            ('GetProcAddress', ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_char_p)),
            ('FreeLibrary', ctypes.c_int32, (ctypes.c_void_p,)),
            ('VirtualAlloc', ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32)),
            ('VirtualProtect', ctypes.c_int32, (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))),
            ('VirtualFree', ctypes.c_int32, (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32)),
        )
        for name, result, arguments in signatures:
            function = getattr(self.kernel, name)
            function.restype, function.argtypes = result, arguments

    def bind(self, runtime):
        if self._runtime is not None or self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('CRT observations require one binding on their creating native thread')
        self._runtime = runtime

    def _check(self, runtime):
        if self._closed or self._owner[0] != os.getpid() or self._runtime is not runtime:
            raise InputError('CRT observations require their live process and bound runtime')
        if self._callback_failure is not None:
            raise PrimarySemanticUnavailable('CRT FLS callback failed; backing retained') from self._callback_failure

    def _new_token(self):
        self._next_token += 16
        return self._next_token

    def _call(self, name, *arguments):
        result = getattr(self.kernel, name)(*arguments)
        error = ctypes.get_last_error()
        return result, error

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if not isinstance(arguments, tuple):
            raise InputError('CRT observations require tuple arguments')
        if name == '_ftime64_s':
            if self._device_time is None:
                if self._owner != (os.getpid(), threading.get_native_id()):
                    raise InputError('CRT device time requires its creating native thread')
                from .primary_windows_device_time import WindowsDeviceTimeObservations
                self._device_time = WindowsDeviceTimeObservations()
            return self._device_time.take(runtime, name, arguments)
        if name == 'CRT.AppPolicyGetThreadInitializationType':
            result, effects = self._app_policy(runtime, arguments)
        else:
            result, effects = self._take(runtime, name, arguments), b''
        self.records.append({'api': name, 'thread_id': threading.get_native_id(), 'status': 'observed'})
        runtime.events.append(('worker.API', name, arguments, result, effects))
        return result, effects

    def _take(self, runtime, name, arguments):
        base = runtime.image_base
        if name == 'GetLastError' and not arguments:
            return ctypes.get_last_error()
        if name == 'SetLastError' and len(arguments) == 1 and type(arguments[0]) is int and 0 <= arguments[0] <= 0xFFFFFFFF:
            ctypes.set_last_error(arguments[0])
            return None
        if name == 'CRT.ProcessParametersFlags' and not arguments:
            native_error, private_error = self._raw_kernel.GetLastError(), ctypes.get_last_error()
            collector = None
            try:
                factory = self._environment_factory
                if factory is None:
                    from .primary_windows_crt_environment import WindowsCRTEnvironmentObservations
                    factory = WindowsCRTEnvironmentObservations
                collector = factory()
                result = collector.read_process_parameters_flags()
                if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
                    raise InputError('CRT environment requires observed DWORD process-parameter flags')
                return result
            finally:
                try:
                    if collector is not None:
                        collector.close()
                finally:
                    self._raw_kernel.SetLastError(native_error)
                    ctypes.set_last_error(private_error)
        if name == 'CRT.RoInitialize' and len(arguments) == 2:
            token, flags = arguments
            if type(flags) is not int or not 0 <= flags <= 0xFFFFFFFF:
                raise InputError('CRT RoInitialize requires a source DWORD argument')
            pointer = self._procedure(token, b'RoInitialize')
            function = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_uint32, use_last_error=True)(pointer)
            return function(flags) & 0xFFFFFFFF
        if name == 'CRT.RoUninitialize' and len(arguments) == 1:
            pointer = self._procedure(arguments[0], b'RoUninitialize')
            function = ctypes.WINFUNCTYPE(None, use_last_error=True)(pointer)
            function()
            return None
        if name == 'CRT.InitializeCriticalSectionEx' and len(arguments) == 3:
            address, spin, flags = arguments
            if (type(address) is not int or not base + 0x6D8EA30 <= address < base + 0x6D8EC88 or
                    (address - base - 0x6D8EA30) % 40 or (spin, flags) != (4000, 0) or address in self._locks):
                raise InputError('CRT lock initialization requires a new exact source lock and parameters')
            storage = ctypes.create_string_buffer(40)
            result, error = self._call('InitializeCriticalSectionEx', storage, spin, flags)
            if result:
                self._locks[address] = {'storage': storage, 'owner': None, 'depth': 0}
                _RETAINED.add(self)
            return int(result) & 0xFFFFFFFF
        if name in ('EnterCriticalSection', 'LeaveCriticalSection') and len(arguments) == 1:
            lock = self._locks.get(arguments[0])
            if lock is None:
                raise PrimarySemanticUnavailable('CRT critical section has no source-initialized native backing')
            tid = threading.get_native_id()
            if name == 'LeaveCriticalSection' and (lock['owner'] != tid or not lock['depth']):
                raise InputError('CRT native critical section release requires native-thread ownership')
            self._call(name, lock['storage'])
            lock['depth'] += 1 if name == 'EnterCriticalSection' else -1
            lock['owner'] = tid if lock['depth'] else None
            return None
        if name == 'CRT.DeleteCriticalSection' and len(arguments) == 1:
            address = arguments[0]
            row = self._locks.get(address)
            if row is None or row['depth']:
                raise InputError('CRT source lock deletion requires initialized unheld native backing')
            self._call('DeleteCriticalSection', row['storage'])
            del self._locks[address]
            return None
        if name == 'CRT.FlsAlloc' and arguments == (base + 0x3EA0CCC,):
            if not callable(self._callback_context):
                raise PrimarySemanticUnavailable('CRT FLS allocation requires a source per-thread callback context owner')
            callback = self._callback_type(lambda token: self._cleanup_token(token))
            identifier, error = self._call('FlsAlloc', callback)
            if identifier != 0xFFFFFFFF:
                self._slots[identifier] = callback
                _RETAINED.add(self)
            return identifier
        if name == 'CRT.FlsFree' and len(arguments) == 1:
            identifier = arguments[0]
            if type(identifier) is not int or identifier not in self._slots:
                raise InputError('CRT source FLS release requires an owned allocated slot')
            result, error = self._call('FlsFree', identifier)
            self._fls_free_records.append({'index': identifier, 'result': int(result) & 0xFFFFFFFF,
                                           'last_error': error, 'native_freed': bool(result)})
            if result:
                self._retired_callbacks.append(self._slots.pop(identifier))
            return int(result) & 0xFFFFFFFF
        if name in ('FlsGetValue', 'CRT.FlsGetValue2', 'FlsSetValue'):
            return self._fls(name, arguments)
        if name == 'LoadLibraryExW' and len(arguments) == 3:
            module, reserved, flags = arguments
            if (module not in _MODULE_EXPORTS or reserved != 0 or
                    flags != 0x800 and (module, flags) != ('kernelbase', 0)):
                raise InputError('CRT resolver module request differs from its source allowlist')
            handle, error = self._call(name, arguments[0], None, arguments[2])
            if not handle:
                return 0
            token = self._new_token()
            self._modules[token] = int(handle)
            self._module_names[token] = module
            _RETAINED.add(self)
            return token
        if name == 'GetProcAddress' and len(arguments) == 2:
            module, export = arguments
            if module not in self._modules or export not in _MODULE_EXPORTS[self._module_names[module]]:
                raise InputError('CRT resolver requires its owned module and exact source export')
            pointer, error = self._call(name, self._modules[module], export)
            if not pointer:
                return 0
            token = self._new_token()
            self._procedures[token] = (int(pointer), module)
            self._procedure_names[token] = export
            return token
        if name == 'FreeLibrary' and len(arguments) == 1:
            module = arguments[0]
            if module not in self._modules:
                raise InputError('CRT FreeLibrary requires an owned module token')
            if any(owner == module for _, owner in self._procedures.values()):
                raise PrimarySemanticUnavailable('CRT module retains callable exports')
            result, error = self._call(name, self._modules[module])
            if result:
                del self._modules[module]
                del self._module_names[module]
            return int(result) & 0xFFFFFFFF
        if name == 'CRT.VirtualProtectCache' and len(arguments) == 3:
            address, size, protection = arguments
            if (address, size) != (base + 0x7394000, 0x100) or protection not in (2, 4):
                raise InputError('CRT protection requires the isolated source cache backing')
            if not self._cache:
                data = b''.join(runtime.memory.read(address + offset, 1) for offset in range(size))
                if data[24:32] != bytes(8):
                    raise PrimarySemanticUnavailable('CRT getter cache backing requires its source-cold slot')
                pointer, error = self._call('VirtualAlloc', None, 4096, 0x3000, 4)
                if not pointer:
                    raise PrimarySemanticUnavailable('CRT isolated cache allocation failed: ' + str(error))
                self._cache = int(pointer)
                _RETAINED.add(self)
                ctypes.memmove(self._cache, data, size)
                initial = ctypes.c_uint32()
                result, error = self._call('VirtualProtect', self._cache, 0x100, 2, ctypes.byref(initial))
                if not result:
                    raise PrimarySemanticUnavailable('CRT isolated cache initial protection failed: ' + str(error))
            previous = ctypes.c_uint32()
            result, error = self._call('VirtualProtect', self._cache, size, protection, ctypes.byref(previous))
            if result:
                self._cache_writable = protection == 4
            return int(result) & 0xFFFFFFFF
        if name == 'CRT.ExchangeCache' and len(arguments) == 2:
            address, value = arguments
            offset = address - base - 0x7394000
            if (offset not in _CACHE_EXPORTS or not self._cache or not self._cache_writable or
                    value != _MASK64 and (value not in self._procedures or
                                         self._procedure_names[value] != _CACHE_EXPORTS[offset])):
                raise InputError('CRT cache exchange requires writable isolated backing and an owned export token')
            lock = self._locks.get(base + 0x6D8EA30 + 14 * 40)
            if lock is None or lock['owner'] != threading.get_native_id() or not lock['depth']:
                raise InputError('CRT cache exchange requires source lock14 ownership')
            with self._mutex:
                previous = ctypes.c_uint64.from_address(self._cache + offset).value
                ctypes.c_uint64.from_address(self._cache + offset).value = value
            return previous
        raise PrimarySemanticUnavailable('unsupported native CRT observation: ' + name)

    def _procedure(self, token, name):
        if token not in self._procedures or self._procedure_names.get(token) != name:
            raise InputError('CRT native call requires its exact owned resolved export token')
        return self._procedures[token][0]

    def _app_policy(self, runtime, arguments):
        if len(arguments) != 3 or arguments[1] != _MASK64 - 5:
            raise InputError('CRT AppPolicy requires its source current-thread-effective-token ABI')
        token, handle, output = arguments
        if type(output) is not int or not 0 < output <= _MASK64 - 4:
            raise PrimarySemanticUnavailable('native CRT AppPolicy requires its known nonnull source local backing')
        pointer = self._procedure(token, b'AppPolicyGetThreadInitializationType')
        initial = runtime.memory.read(output, 4)
        backing = ctypes.c_uint32(int.from_bytes(initial, 'little'))
        function = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                                     use_last_error=True)(pointer)
        result = function(handle, ctypes.byref(backing))
        return result & 0xFFFFFFFF, backing.value.to_bytes(4, 'little')

    def _fls(self, name, arguments):
        count = 2 if name == 'FlsSetValue' else 1
        if (len(arguments) != count or type(arguments[0]) is not int or
                arguments[0] not in self._slots):
            raise InputError('CRT FLS operation requires an owned source-allocated native slot')
        identifier = arguments[0]
        tid = threading.get_native_id()
        if name == 'FlsSetValue':
            value = arguments[1]
            if type(value) is not int or not 0 <= value <= _MASK64:
                raise InputError('CRT FLS requires an unsigned model pointer or sentinel')
            storage = ctypes.c_uint64(value) if value else None
            token = ctypes.addressof(storage) if storage is not None else 0
            if token:
                self._tokens[token] = (storage, value, tid, identifier)
            from .primary_creator_domain import _fls_attempt,_fls_return
            attempt=_fls_attempt(self,name,identifier,value,token,storage)
            try:result,error=self._call(name,identifier,token or None)
            except BaseException as failure:
                _fls_return(self,attempt,None,None,failure)
                raise
            _fls_return(self,attempt,result,error)
            if result:
                previous = self._values.pop((tid, identifier), None)
                if previous:
                    self._tokens.pop(previous, None)
                if token:
                    self._values[tid, identifier] = token
            elif token:
                self._tokens.pop(token, None)
            return int(result) & 0xFFFFFFFF
        if name == 'CRT.FlsGetValue2':
            token = self._runtime.memory.load(self._runtime.image_base + 0x7394018, 8)
            pointer = self._procedure(token, b'FlsGetValue2')
            function = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_uint32)(pointer)
            pointer = function(identifier)
        else:
            pointer, error = self._call(name, identifier)
        if not pointer:
            return 0
        record = self._tokens.get(int(pointer))
        if record is None or record[2:] != (tid, identifier):
            raise PrimarySemanticUnavailable('native CRT FLS returned an unowned or foreign-thread token')
        from .primary_creator_domain import _fls_get
        _fls_get(self,identifier,int(pointer),record)
        return record[1]

    def _cleanup_token(self, pointer):
        tid = threading.get_native_id()
        self._callbacks_active += 1
        self._active_callback_threads[tid] = self._active_callback_threads.get(tid, 0) + 1
        completed = False
        record = None
        try:
            record = self._tokens.get(int(pointer or 0))
            if record is None or record[2] != tid:
                raise PrimarySemanticUnavailable('native CRT FLS callback requires its original thread and owned token')
            value, identifier = record[1], record[3]
            from .primary_creator_domain import _callback_ptd
            _callback_ptd(self,int(pointer),'begin')
            with self._callback_context(self._runtime, tid):
                from .primary_crt_startup import fls_callback
                fls_callback(self._runtime, value)
            _callback_ptd(self,int(pointer),'consumed')
            completed = True
        except BaseException as error:
            if self._callback_failure is None:self._callback_failure = error
        finally:
            if completed:
                self._tokens.pop(int(pointer), None)
                self._values.pop((tid, record[3]), None)
            self._callbacks_active -= 1
            self._active_callback_threads[tid] -= 1
            if not self._active_callback_threads[tid]:
                del self._active_callback_threads[tid]

    def snapshot(self):
        return {'closed': self._closed, 'slots': tuple(self._slots), 'pending_values': len(self._values),
                'pending_thread_ids': tuple(sorted({tid for tid, slot in tuple(self._values)} |
                                                   set(tuple(self._active_callback_threads)))),
                'fls_free_records': [dict(row) for row in self._fls_free_records],
                'lock_count': len(self._locks), 'module_count': len(self._modules),
                'cache_allocated': bool(self._cache),
                'callbacks_active': self._callbacks_active,
                'callback_failure': None if self._callback_failure is None else type(self._callback_failure).__name__}

    def close(self):
        if self._closed:
            return
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('CRT backing close requires its creating native thread')
        if (self._callback_failure is not None or self._values or self._callbacks_active or
                any(row['depth'] for row in self._locks.values())):
            raise PrimarySemanticUnavailable('CRT backing retains FLS values, callback failure or held locks')
        if self._device_time is not None:
            self._device_time.close()
        for identifier in tuple(self._slots):
            result, error = self._call('FlsFree', identifier)
            if not result:
                raise PrimarySemanticUnavailable('native CRT FLS free failed: ' + str(error))
            del self._slots[identifier]
        for address, row in tuple(self._locks.items()):
            self._call('DeleteCriticalSection', row['storage'])
            del self._locks[address]
        self._procedures.clear()
        self._procedure_names.clear()
        for token, handle in tuple(self._modules.items()):
            result, error = self._call('FreeLibrary', handle)
            if not result:
                raise PrimarySemanticUnavailable('CRT module release failed: ' + str(error))
            del self._modules[token]
            del self._module_names[token]
        if self._cache:
            result, error = self._call('VirtualFree', self._cache, 0, 0x8000)
            if not result:
                raise PrimarySemanticUnavailable('CRT isolated cache release failed: ' + str(error))
            self._cache = 0
        self._closed = True
        self._retired_callbacks.clear()
        _RETAINED.discard(self)
