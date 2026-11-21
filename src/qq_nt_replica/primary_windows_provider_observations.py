import ctypes
import _ctypes
import os
import threading

from .errors import CapabilityUnavailable, InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations
from .primary_device_native import _HARDWARE_EXPORTS


_MASK = (1 << 64) - 1
_COUNTS = {'CPUID': 2, 'GetCurrentProcess': 0, 'GetModuleHandleW': 1,
           'GetProcAddress': 2, 'GetVersionExW': 1, 'IsWow64Process': 2,
           'GetProductInfo': 5, 'RtlGetNtVersionNumbers': 1, 'GetNativeSystemInfo': 0,
           'GetComputerNameA': 1, 'GetUserNameA': 1, 'GetCurrentHwProfileA': 0,
           'GetKeyboardType': 1, 'IsDebuggerPresent': 0, 'GetSystemDefaultLCID': 0, 'SHGetFolderPathW': 5}
_SH_FOLDER = (0, 26, 0, 0, 260)
_EXPORTS = {'kernel32.dll': {b'IsWow64Process', b'GetProductInfo'},
            'ntdll.dll': {b'RtlGetNtVersionNumbers'},
            'ntdll': {name for name, slot in _HARDWARE_EXPORTS}}


class _NativeSystemInfo(ctypes.Structure):
    _fields_ = [('architecture', ctypes.c_uint16), ('reserved', ctypes.c_uint16),
                ('page_size', ctypes.c_uint32), ('minimum_address', ctypes.c_void_p),
                ('maximum_address', ctypes.c_void_p), ('active_processor_mask', ctypes.c_size_t),
                ('processor_count', ctypes.c_uint32), ('processor_type', ctypes.c_uint32),
                ('allocation_granularity', ctypes.c_uint32), ('processor_level', ctypes.c_uint16),
                ('processor_revision', ctypes.c_uint16)]


class WindowsProviderAPIBackend:
    def __init__(self):
        self.kernel = self.advapi = self.user = self.shell = None
        self._owner = os.getpid(), threading.get_native_id()
        self._closed = False
        try:
            self._initialize()
        except BaseException:
            self.close()
            raise

    def _initialize(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_wchar) != 2:
            raise CapabilityUnavailable('provider observations require Windows x64')
        if (ctypes.sizeof(_NativeSystemInfo), _NativeSystemInfo.architecture.offset,
                _NativeSystemInfo.processor_count.offset, _NativeSystemInfo.processor_revision.offset) != (48, 0, 32, 46):
            raise CapabilityUnavailable('provider SYSTEM_INFO layout differs from the fixed Win64 source ABI')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.advapi = None
        for name, result, arguments in (
                ('GetCurrentProcess', ctypes.c_void_p, ()),
                ('IsDebuggerPresent', ctypes.c_int32, ()),
                ('GetSystemDefaultLCID', ctypes.c_uint32, ()),
                ('GetModuleHandleW', ctypes.c_void_p, (ctypes.c_wchar_p,)),
                ('GetProcAddress', ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_char_p)),
                ('GetVersionExW', ctypes.c_int32, (ctypes.c_void_p,)),
                ('GetComputerNameA', ctypes.c_int32, (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))),
                ('GetNativeSystemInfo', None, (ctypes.POINTER(_NativeSystemInfo),))):
            function = getattr(self.kernel, name)
            function.restype, function.argtypes = result, arguments

    def _user(self):
        if self.user is None:
            self.user = ctypes.WinDLL('user32', use_last_error=True)
            self.user.GetKeyboardType.restype = ctypes.c_int32
            self.user.GetKeyboardType.argtypes = (ctypes.c_int32,)
        return self.user

    def _advapi(self):
        if self.advapi is None:
            self.advapi = ctypes.WinDLL('advapi32', use_last_error=True)
            self.advapi.GetUserNameA.restype = ctypes.c_int32
            self.advapi.GetUserNameA.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
            self.advapi.GetCurrentHwProfileA.restype = ctypes.c_int32
            self.advapi.GetCurrentHwProfileA.argtypes = (ctypes.c_void_p,)
        return self.advapi

    def _check(self):
        if self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('provider backing requires its live creator process and thread')

    def _folder(self, arguments):
        if type(arguments) is not tuple or arguments != _SH_FOLDER or any(type(value) is not int for value in arguments):
            raise InputError('folder query requires its exact source NULL APPDATA CURRENT MAX_PATH tuple')
        if self.shell is None:
            self.shell = ctypes.WinDLL('shell32', use_last_error=True)
            self.shell.SHGetFolderPathW.restype = ctypes.c_int32
            self.shell.SHGetFolderPathW.argtypes = (ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p,
                ctypes.c_uint32, ctypes.POINTER(ctypes.c_wchar))
        output = ctypes.create_string_buffer(b'\xCC' * 520, 520)
        result = self.shell.SHGetFolderPathW(None, 26, None, 0, ctypes.cast(output, ctypes.POINTER(ctypes.c_wchar)))
        if type(result) is not int or not -(1 << 31) <= result < 1 << 31:
            raise InputError('folder query requires its native signed HRESULT32')
        if result < 0:
            return result & 0xFFFFFFFF, b''
        raw = output.raw
        end = next((offset for offset in range(0, 520, 2) if raw[offset:offset + 2] == b'\0\0'), None)
        if end is None:
            raise PrimarySemanticUnavailable('folder query success lacks its actual bounded UTF16 terminator')
        if result == 1 and end != 0:
            raise PrimarySemanticUnavailable('folder query S_FALSE differs from its documented actual empty output')
        return result, raw[:end + 2]

    def request(self, name, arguments):
        self._check()
        if name == 'SHGetFolderPathW':
            return self._folder(arguments)
        if name in ('GetKeyboardType', 'IsDebuggerPresent', 'GetSystemDefaultLCID'):
            library = self._user() if name == 'GetKeyboardType' else self.kernel
            return getattr(library, name)(*arguments) & 0xFFFFFFFF, b''
        if name == 'GetCurrentHwProfileA':
            output = ctypes.create_string_buffer(124)
            result = self._advapi().GetCurrentHwProfileA(output) & 0xFFFFFFFF
            if not result:
                return result, (b'', b'')
            raw, known = output.raw, bytearray(124)
            known[:4] = bytes([1]) * 4
            for start, width in ((4, 39), (43, 80)):
                end = raw.find(b'\0', start, start + width)
                if end < 0:
                    raise InputError('native hardware profile requires terminated fixed-size ANSI fields')
                known[start:end + 1] = bytes([1]) * (end + 1 - start)
            return result, (raw, bytes(known))
        if name in ('GetComputerNameA', 'GetUserNameA'):
            output = ctypes.create_string_buffer(260)
            size = ctypes.c_uint32(arguments[0])
            library = self.kernel if name == 'GetComputerNameA' else self._advapi()
            result = getattr(library, name)(output, ctypes.byref(size))
            return result & 0xFFFFFFFF, (output.raw, size.value)
        if name == 'GetNativeSystemInfo':
            output = _NativeSystemInfo()
            result = self.kernel.GetNativeSystemInfo(ctypes.byref(output))
            if result is not None:
                raise InputError('provider native system information requires the actual void ABI')
            return None, ctypes.string_at(ctypes.byref(output), ctypes.sizeof(output))
        if name in ('IsWow64Process', 'GetProductInfo'):
            output = ctypes.c_uint32(0)
            if name == 'IsWow64Process':
                function = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))(arguments[0])
                result = function(arguments[1], ctypes.byref(output))
            else:
                function = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
                                             ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))(arguments[0])
                result = function(*arguments[1:], ctypes.byref(output))
            return result & 0xFFFFFFFF, output.value.to_bytes(4, 'little')
        if name == 'RtlGetNtVersionNumbers':
            output = [ctypes.c_uint32() for _ in range(3)]
            pointer = ctypes.POINTER(ctypes.c_uint32)
            function = ctypes.WINFUNCTYPE(None, pointer, pointer, pointer)(arguments[0])
            function(*(ctypes.byref(value) for value in output))
            return 0, tuple(value.value.to_bytes(4, 'little') for value in output)
        if name == 'GetVersionExW':
            output = ctypes.create_string_buffer(0x11C)
            output[:4] = (0x11C).to_bytes(4, 'little')
            result = self.kernel.GetVersionExW(output)
            return result & 0xFFFFFFFF, output.raw
        result = getattr(self.kernel, name)(*arguments)
        return int(result or 0) & _MASK, b''

    def close(self):
        if self._closed:
            return
        self._check()
        for name in ('shell', 'user', 'advapi', 'kernel'):
            library = getattr(self, name, None)
            if library is not None:
                _ctypes.FreeLibrary(library._handle)
                setattr(self, name, None)
        self._closed = True


class WindowsProviderObservations(WorkerObservations):
    def __init__(self, fallback=None, *, backend=None, source=None):
        self._fallback, self._backend, self._source = fallback, backend, source
        self._identity = os.getpid(), threading.get_native_id()
        self._runtime = None
        self._closed = False
        self._modules = {}
        self._module_domains = {}
        self._exports = {}
        self._process = None
        self._device_time = None
        self.records = []

    def bind_source(self, source):
        self._check(self._runtime)
        if self._closed or self._source is not None:
            raise InputError('provider CPUID source can only be bound once while open')
        self._source = source

    def _check(self, runtime):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('provider observations require their live owning process and thread')
        if self._runtime is None:
            self._runtime = runtime
        elif self._runtime is not runtime:
            raise InputError('provider observations require their owning runtime')

    def _api(self, name, arguments):
        if self._backend is None:
            self._backend = WindowsProviderAPIBackend()
        result, effects = self._backend.request(name, arguments)
        if name == 'GetNativeSystemInfo':
            if result is not None or not isinstance(effects, bytes) or len(effects) != 48:
                raise InputError('provider native system information requires void result and complete source-zeroed SYSTEM_INFO48')
            return result, effects
        width = 32 if name in ('SHGetFolderPathW', 'GetVersionExW', 'IsWow64Process', 'GetProductInfo', 'RtlGetNtVersionNumbers', 'GetComputerNameA', 'GetUserNameA', 'GetCurrentHwProfileA', 'GetKeyboardType', 'IsDebuggerPresent', 'GetSystemDefaultLCID') else 64
        if type(result) is not int or not 0 <= result < 1 << width:
            raise InputError('provider OS result width differs from source ABI')
        if name == 'SHGetFolderPathW':
            if type(effects) is not bytes or len(effects) > 520 or len(effects) & 1:
                raise InputError('folder query requires bounded raw UTF16 output effects')
            if result & 0x80000000:
                if effects:
                    raise InputError('failed folder query has no successful output effects')
            else:
                end = next((offset for offset in range(0, len(effects), 2) if effects[offset:offset + 2] == b'\0\0'), None)
                if end is None or end != len(effects) - 2 or result == 1 and end != 0:
                    raise InputError('folder query success requires its actual first terminated UTF16 prefix')
        elif name == 'GetCurrentHwProfileA':
            if (not isinstance(effects, tuple) or len(effects) != 2 or not all(isinstance(raw, bytes) for raw in effects)
                    or len(effects[0]) != len(effects[1]) or len(effects[0]) > 124
                    or any(value not in (0, 1) for value in effects[1]) or result == 0 and effects != (b'', b'')):
                raise InputError('provider hardware profile requires sparse known output and no failed-BOOL output')
        elif name in ('GetComputerNameA', 'GetUserNameA'):
            if (not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], bytes)
                    or len(effects[0]) != 260 or type(effects[1]) is not int or not 0 <= effects[1] <= 0xFFFFFFFF):
                raise InputError('provider name requires complete source-prezeroed buffer260 and actual DWORD size output')
        elif name == 'GetVersionExW':
            if not isinstance(effects, bytes) or len(effects) != 0x11C:
                raise InputError('provider version requires the complete source-initialized buffer')
        elif name in ('IsWow64Process', 'GetProductInfo'):
            if not isinstance(effects, bytes) or len(effects) != 4:
                raise InputError('provider version BOOL API requires its source-initialized DWORD output')
        elif name == 'RtlGetNtVersionNumbers':
            if result != 0 or not isinstance(effects, tuple) or len(effects) != 3 or any(not isinstance(raw, bytes) or len(raw) != 4 for raw in effects):
                raise InputError('provider NT version requires three complete DWORD outputs and a void result')
        elif effects != b'':
            raise InputError('provider OS operation has no output buffer')
        return result, effects

    def _dispatch(self, name, arguments):
        if name == 'SHGetFolderPathW' and (type(arguments) is not tuple or arguments != _SH_FOLDER or any(type(value) is not int for value in arguments)):
            raise InputError('folder query requires its exact source NULL APPDATA CURRENT MAX_PATH tuple')
        if name in ('GetComputerNameA', 'GetUserNameA') and (type(arguments[0]) is not int or not 0 <= arguments[0] <= 260):
            raise InputError('provider name capacity is outside the source260-byte buffer')
        if name == 'GetKeyboardType' and (type(arguments[0]) is not int or arguments != (0,)):
            raise InputError('provider keyboard query requires source selector zero')
        if name == 'CPUID':
            leaf, subleaf = (arguments[0], 0) if len(arguments) == 1 else arguments
            ordinary = leaf in (1, 0x80000002, 0x80000003, 0x80000004) and subleaf == 0
            hypervisor = (leaf, subleaf) == (0x40000000, 0x40000000) and len(arguments) == 2
            if type(leaf) is not int or type(subleaf) is not int or not (ordinary or hypervisor):
                raise InputError('provider CPUID requires its exact source leaf and subleaf pair')
            if len(arguments) == 1 and leaf != 1:
                raise InputError('provider single-argument CPUID requires source leaf1')
            if self._source is None or not callable(getattr(self._source, 'cpuid', None)):
                raise PrimarySemanticUnavailable('provider CPUID requires its bound Windows device source')
            words = self._source.cpuid(leaf, subleaf)
            if not isinstance(words, tuple) or len(words) != 4 or any(type(w) is not int or not 0 <= w <= 0xFFFFFFFF for w in words):
                raise InputError('provider CPUID requires four complete DWORD registers')
            return 0, words
        if name == 'GetVersionExW' and (type(arguments[0]) is not int or arguments != (0x11C,)):
            raise InputError('provider version requires source OSVERSIONINFOEXW size284')
        if name == 'GetModuleHandleW':
            raw = arguments[0]
            allowed = {key.encode('utf-16-le') + b'\0\0': key for key in _EXPORTS}
            if not isinstance(raw, bytes) or raw not in allowed:
                raise InputError('provider module lookup is outside the source system-version domain')
            module = allowed[raw]
            result, effects = self._api(name, (module,))
            if result:
                canonical = 'ntdll.dll' if module == 'ntdll' else module
                if result in self._modules and self._modules[result] != canonical:
                    raise PrimarySemanticUnavailable('provider module handles alias different source modules')
                self._modules[result] = canonical
                self._module_domains.setdefault(result, set()).add(module)
            else:
                self._modules[0] = module
                self._module_domains[0] = {module}
            return result, effects
        if name == 'GetProcAddress':
            handle, symbol = arguments
            if (type(handle) is not int or handle not in self._modules or not isinstance(symbol, bytes) or
                    not any(symbol in _EXPORTS[module] for module in self._module_domains[handle])):
                raise InputError('provider export requires its observed source module and exact symbol')
            result, effects = self._api(name, arguments)
            self._exports[symbol.decode('ascii')] = result
            return result, effects
        if name in ('IsWow64Process', 'GetProductInfo', 'RtlGetNtVersionNumbers'):
            if type(arguments[0]) is not int or not arguments[0] or arguments[0] != self._exports.get(name):
                raise InputError('provider dynamic call requires its personally resolved exact target')
            if name == 'IsWow64Process' and (type(arguments[1]) is not int or self._process is None or arguments[1] != self._process):
                raise InputError('provider WOW64 query requires its observed current-process pseudo handle')
            if name == 'GetProductInfo' and (any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in arguments[1:]) or arguments[1] not in (6, 10) or arguments[3:] != (0, 0)):
                raise InputError('provider product query differs from the source DWORD version domain')
        result, effects = self._api(name, arguments)
        if name == 'GetCurrentProcess':
            if result != _MASK:
                raise InputError('provider current-process API did not return its pseudo handle')
            self._process = result
        return result, effects

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if name == '_ftime64_s':
            if self._device_time is None:
                from .primary_windows_device_time import WindowsDeviceTimeObservations
                self._device_time = WindowsDeviceTimeObservations()
            return self._device_time.take(runtime, name, arguments)
        if name not in _COUNTS or name == 'GetProcAddress' and isinstance(arguments, tuple) and len(arguments) == 2 and arguments[1] == b'RtlCaptureStackBackTrace':
            if self._fallback is None:
                raise PrimarySemanticUnavailable('unsupported Windows provider observation: ' + name)
            return self._fallback.take(runtime, name, arguments)
        if not isinstance(arguments, tuple) or len(arguments) not in ((1, 2) if name == 'CPUID' else (_COUNTS[name],)):
            raise InputError('provider observation argument count mismatch: ' + name)
        try:
            result, effects = self._dispatch(name, arguments)
        except Exception as error:
            self.records.append({'api': name, 'status': type(error).__name__})
            raise
        self.records.append({'api': name, 'status': 'observed', 'effect_bytes': len(effects) if isinstance(effects, bytes) else 0})
        runtime.events.append(('worker.API', name, arguments, result, effects))
        return result, effects

    def close(self):
        if self._closed:
            return
        self._check(self._runtime)
        if self._device_time is not None:
            self._device_time.close()
        close = getattr(self._backend, 'close', None)
        if close is not None:
            close()
        self._closed = True
