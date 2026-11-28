import ctypes
import os
import threading

from .errors import CapabilityUnavailable, InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_MASK = (1 << 64) - 1
_COUNTS = {'GetTickCount': 0, 'Sleep': 1, 'GetCurrentProcess': 0,
           'GetCurrentProcessId': 0, 'K32EnumProcessModules': 2,
           'GetModuleFileNameW': 2, 'GetModuleFileNameA': 2, 'EnumWindows': 2,
           'GetWindowThreadProcessId': 1, 'GetClassNameW': 2,
           'GetModuleHandleW': 1, 'GetSystemPowerStatus': 0, 'FindWindowA': 2, 'StrStrIA': 2, 'GetForegroundWindow': 0, 'GetWindowTextA': 2, 'GetClassNameA': 2, 'GetWindowRect': 1, 'IsWindowVisible': 1}
_PROBE = 'frida-agent.dll'.encode('utf-16-le')


class WindowsWorkerAPIBackend:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable('worker observations require Windows x64')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.user = ctypes.WinDLL('user32', use_last_error=True)
        self.callback_type = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_ssize_t)
        signatures = (
            (self.kernel, 'GetTickCount', ctypes.c_uint32, ()),
            (self.kernel, 'Sleep', None, (ctypes.c_uint32,)),
            (self.kernel, 'GetCurrentProcess', ctypes.c_void_p, ()),
            (self.kernel, 'GetCurrentProcessId', ctypes.c_uint32, ()),
            (self.kernel, 'K32EnumProcessModules', ctypes.c_int32, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)),
            (self.kernel, 'GetModuleFileNameW', ctypes.c_uint32, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)),
            (self.kernel, 'GetModuleFileNameA', ctypes.c_uint32, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)),
            (self.kernel, 'GetModuleHandleW', ctypes.c_void_p, (ctypes.c_wchar_p,)),
            (self.kernel, 'GetSystemPowerStatus', ctypes.c_int32, (ctypes.c_void_p,)),
            (self.user, 'EnumWindows', ctypes.c_int32, (self.callback_type, ctypes.c_ssize_t)),
            (self.user, 'GetWindowThreadProcessId', ctypes.c_uint32, (ctypes.c_void_p, ctypes.c_void_p)),
            (self.user, 'GetClassNameW', ctypes.c_int32, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32)),
        )
        for library, name, result, arguments in signatures:
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
        self.last_error = 0

    def request(self, name, arguments):
        ctypes.set_last_error(0)
        try:
            return self._request(name, arguments)
        finally:
            self.last_error = ctypes.get_last_error()

    def module_request(self, name, arguments, initial):
        if name not in ('GetModuleFileNameA', 'K32GetModuleFileNameExA', 'PathRemoveFileSpecA', 'PathFindFileNameA'):
            raise InputError('module backend requires its finite ANSI API')
        if type(initial) is not tuple or len(initial) != 2:
            raise InputError('module backend requires source bytes and knownness')
        raw, known = initial
        if (type(raw) is not bytes or type(known) is not bytes or len(raw) != len(known) or
                not 0 < len(raw) <= 520 or any(value not in (0, 1) for value in known)):
            raise InputError('module backend source buffer shape differs')
        if type(arguments) is not tuple or any(type(value) is not int for value in arguments):
            raise InputError('module backend requires exact scalar arguments')
        capacity = len(raw)
        if name == 'GetModuleFileNameA':
            if len(arguments) != 2 or arguments[1] != capacity or capacity not in (260, 261) or not 0 <= arguments[0] < 1 << 64:
                raise InputError('module backend filename ABI differs')
        elif name == 'K32GetModuleFileNameExA':
            if len(arguments) != 3 or arguments[0] != _MASK or not 0 < arguments[1] < 1 << 64 or arguments[2] != capacity or capacity != 260:
                raise InputError('module backend enumerated filename ABI differs')
        elif arguments or not all(known) or b'\0' not in raw:
            raise InputError('module backend path requires its terminated known source bytes')
        if name == 'PathFindFileNameA' and raw.index(0) != capacity - 1:
            raise InputError('module alias requires the exact input CString span')
        native = bytes(value if known[index] else 0 for index, value in enumerate(raw))
        buffer = ctypes.create_string_buffer(native, capacity)
        ctypes.set_last_error(0)
        try:
            if name == 'GetModuleFileNameA':
                function = self.kernel.GetModuleFileNameA
                function.restype, function.argtypes = ctypes.c_uint32, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)
                result = function(arguments[0], buffer, capacity)
            elif name == 'K32GetModuleFileNameExA':
                function = self.kernel.K32GetModuleFileNameExA
                function.restype, function.argtypes = ctypes.c_uint32, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)
                result = function(arguments[0], arguments[1], buffer, capacity)
            else:
                if not hasattr(self, 'shlwapi'):
                    self.shlwapi = ctypes.WinDLL('shlwapi', use_last_error=True)
                function = getattr(self.shlwapi, name)
                function.restype, function.argtypes = (ctypes.c_void_p if name == 'PathFindFileNameA' else ctypes.c_int32), (ctypes.c_void_p,)
                result = function(buffer)
                if name == 'PathFindFileNameA':
                    pointer = int(result or 0)
                    offset = pointer - ctypes.addressof(buffer)
                    if buffer.raw != native or not 0 <= offset < capacity:
                        raise InputError('module alias mutated input or returned an external pointer')
                    return offset, (buffer.raw, known)
            result = int(result) & 0xFFFFFFFF
            mask = bytearray(known)
            if name in ('GetModuleFileNameA', 'K32GetModuleFileNameExA'):
                if result > capacity:
                    raise InputError('module filename result exceeds its native capacity')
                if result:
                    count = result if result == capacity else result + 1
                    if result < capacity and buffer.raw[result] != 0:
                        raise InputError('module filename success lacks its actual terminator')
                    mask[:count] = b'\1' * count
            return result, (buffer.raw, bytes(mask))
        finally:
            self.last_error = ctypes.get_last_error()

    def _request(self, name, arguments):
        if name in ('GetForegroundWindow', 'GetWindowTextA', 'GetClassNameA', 'GetWindowRect', 'IsWindowVisible'):
            function = getattr(self.user, name)
            if name == 'GetForegroundWindow':
                function.restype, function.argtypes = ctypes.c_void_p, ()
                return int(function() or 0), None
            function.restype = ctypes.c_int32
            if name == 'IsWindowVisible':
                function.argtypes = (ctypes.c_void_p,)
                return function(arguments[0]) & 0xFFFFFFFF, None
            if name == 'GetWindowRect':
                function.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
                buffer = ctypes.create_string_buffer(16)
                result = function(arguments[0], buffer)
                return result & 0xFFFFFFFF, buffer.raw if result else None
            function.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32)
            buffer = ctypes.create_string_buffer(260)
            result = function(arguments[0], buffer, arguments[1])
            return result & 0xFFFFFFFF, buffer.raw[:result + 1] if result > 0 else b''
        if name == 'K32EnumProcessModules':
            buffer = ctypes.create_string_buffer(8192)
            needed = ctypes.c_uint32()
            result = self.kernel.K32EnumProcessModules(arguments[0], buffer, 8192, ctypes.byref(needed))
            if not result:
                raise PrimarySemanticUnavailable('module enumeration failed with undefined needed output')
            return result, (needed.value, buffer.raw[:min(needed.value, 8192)])
        if name in ('GetModuleFileNameW', 'GetModuleFileNameA', 'GetClassNameW'):
            wide = name != 'GetModuleFileNameA'
            capacity = arguments[1]
            buffer = ctypes.create_string_buffer(capacity * (2 if wide else 1))
            library = self.user if name == 'GetClassNameW' else self.kernel
            result = getattr(library, name)(arguments[0], buffer, capacity)
            if not result:
                if name == 'GetClassNameW':
                    raise PrimarySemanticUnavailable('window class query failed with undefined string output')
                return 0, b''
            count = min(result + 1, capacity)
            return result, buffer.raw[:count * (2 if wide else 1)]
        if name == 'EnumWindows':
            windows = []
            failures = []
            def collect(window, parameter):
                try:
                    windows.append(int(window or 0))
                    return 1
                except BaseException as error:
                    failures.append(error)
                    return 0
            callback = self.callback_type(collect)
            result = self.user.EnumWindows(callback, arguments[1])
            if failures:
                raise failures[0]
            return result & 0xFFFFFFFF, tuple(windows)
        if name == 'GetWindowThreadProcessId':
            process = ctypes.c_uint32()
            result = self.user.GetWindowThreadProcessId(arguments[0], ctypes.byref(process))
            return result, process.value if result else None
        if name == 'GetSystemPowerStatus':
            buffer = ctypes.create_string_buffer(12)
            result = self.kernel.GetSystemPowerStatus(buffer)
            return result & 0xFFFFFFFF, buffer.raw if result else None
        if name == 'GetModuleHandleW':
            return int(self.kernel.GetModuleHandleW('frida-agent.dll') or 0), None
        if name in ('FindWindowA', 'StrStrIA'):
            if name == 'FindWindowA':
                function = self.user.FindWindowA
            else:
                if not hasattr(self, 'shlwapi'):
                    self.shlwapi = ctypes.WinDLL('shlwapi', use_last_error=True)
                function = self.shlwapi.StrStrIA
            function.restype = ctypes.c_void_p
            function.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
            values = tuple(None if value == 0 else value for value in arguments)
            return int(function(*values) or 0), None
        result = getattr(self.kernel, name)(*arguments)
        return (int(result) & _MASK if result is not None else None), None


class WindowsWorkerObservations(WorkerObservations):
    def __init__(self, fallback=None, *, backend=None):
        self._fallback, self._backend = fallback, backend
        self._identity = os.getpid(), threading.get_native_id()
        self._runtime = None
        self._closed = False
        self._process = None
        self._pid = None
        self._modules = set()
        self._windows = set()
        self._foreground = set()
        self.records = []

    def _check(self, runtime):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('worker observations require their live owning process and thread')
        if self._runtime is None:
            self._runtime = runtime
        elif runtime is not self._runtime:
            raise InputError('worker observations require their owning runtime')

    def _arguments(self, runtime, name, arguments):
        if name == 'Sleep':
            arity = type(arguments) is tuple and len(arguments) == 1
            exact = arity and type(arguments[0]) is int
            shape = {'arity1': arity, 'all_exactint': exact,
                     'in_u32': exact and 0 <= arguments[0] <= 0xFFFFFFFF,
                     'equals1': exact and arguments == (1,), 'equals3000': exact and arguments == (3000,)}
            if not exact or arguments not in ((1,), (3000,)):
                error = InputError('worker sleep requires a supported exact source interval')
                error.sleep_argument_shape = shape
                raise error
        if not isinstance(arguments, tuple) or len(arguments) != _COUNTS[name]:
            raise InputError('worker observation argument count mismatch: ' + name)
        if any(type(value) is not int for value in arguments) and name not in ('GetModuleHandleW', 'FindWindowA', 'StrStrIA'):
            raise InputError('worker source arguments require exact integers')
        if name == 'FindWindowA' and (type(arguments[0]) is not bytes or type(arguments[1]) is not int or arguments != (b'WTWindow\0', 0)):
            raise InputError('public window lookup requires the source class and NULL title')
        if name == 'StrStrIA':
            command, needle = arguments
            if type(command) is not bytes or not command.endswith(b'\0') or b'\0' in command[:-1] or type(needle) is not bytes or needle != b'login\0':
                raise InputError('public command search requires exact terminated source strings')
        if name == 'K32EnumProcessModules' and arguments != (_MASK, 8192):
            raise InputError('worker modules require the current-process pseudo handle and source capacity')
        if name in ('GetModuleFileNameW', 'GetModuleFileNameA'):
            handle, capacity = arguments
            if type(handle) is not int or capacity != 260 or (name.endswith('A') and handle != 0) or (name.endswith('W') and handle not in self._modules):
                raise InputError('worker filename requires its source capacity and personally enumerated module')
        if name == 'EnumWindows' and arguments != (runtime.image_base + 0x2DE9570, self._identity[0]):
            raise InputError('worker windows require the exact modeled callback and owning process ID')
        if name in ('GetWindowThreadProcessId', 'GetClassNameW'):
            if type(arguments[0]) is not int or arguments[0] not in self._windows | self._foreground or (name == 'GetClassNameW' and arguments[1] != 100):
                raise InputError('worker window query requires a personally enumerated window and source capacity')

        if name in ('GetWindowTextA', 'GetClassNameA', 'GetWindowRect', 'IsWindowVisible'):
            if arguments[0] not in self._foreground or (name in ('GetWindowTextA', 'GetClassNameA') and arguments[1] != 259):
                raise InputError('public window observation requires its observed foreground handle and exact source capacity')

    def _result(self, name, result, effects, *, foreground=False):
        width = 64 if name in ('GetCurrentProcess', 'GetModuleHandleW', 'FindWindowA', 'StrStrIA', 'GetForegroundWindow') else 32
        if name == 'Sleep':
            if result is not None or effects is not None:
                raise InputError('worker Sleep requires void result and no synthetic memory effects')
            return
        if type(result) is not int or not 0 <= result < 1 << width:
            raise InputError('worker result width differs from source ABI')
        if name == 'GetForegroundWindow':
            if effects is not None:
                raise InputError('foreground window has no output buffer')
            if result:
                self._foreground.add(result)
        elif name in ('GetWindowTextA', 'GetClassNameA'):
            if type(effects) is not bytes or result >= 259 or len(effects) != (result + 1 if result else 0) or result and effects[-1:] != b'\0':
                raise InputError('public window text requires only its actual written string prefix')
        elif name == 'GetWindowRect':
            if effects is not None and (type(effects) is not bytes or len(effects) != 16) or result and effects is None:
                raise InputError('public rectangle requires successful raw output or undefined failure')
        elif name == 'K32EnumProcessModules':
            if not result:
                raise PrimarySemanticUnavailable('failed module enumeration cannot define its source needed output')
            if not isinstance(effects, tuple) or len(effects) != 2 or type(effects[0]) is not int or not 0 <= effects[0] <= 0xFFFFFFFF or effects[0] % 8 or not isinstance(effects[1], bytes) or len(effects[1]) != min(effects[0], 8192):
                raise InputError('worker modules require exactly the written handle prefix and DWORD needed')
            self._modules = {int.from_bytes(effects[1][i:i + 8], 'little') for i in range(0, len(effects[1]), 8)}
        elif name == 'EnumWindows':
            if not isinstance(effects, tuple) or any(type(v) is not int or not 0 < v <= _MASK for v in effects):
                raise InputError('worker windows require actual HWND observations')
            self._windows = set(effects)
        elif name in ('GetModuleFileNameA', 'GetModuleFileNameW', 'GetClassNameW'):
            unit = 1 if name.endswith('A') else 2
            capacity = 100 if name == 'GetClassNameW' else 260
            count = min(result + 1, capacity) if result else 0
            if not isinstance(effects, bytes) or result > capacity or len(effects) != count * unit or (result and result < capacity and effects[-unit:] != bytes(unit)):
                raise InputError('worker filename/class requires exactly its native string prefix')
            if name == 'GetClassNameW' and not result:
                raise PrimarySemanticUnavailable('failed window class cannot define its source string output')
        elif name == 'GetWindowThreadProcessId':
            if foreground:
                if effects is not None and (type(effects) is not int or not 0 <= effects <= 0xFFFFFFFF):
                    raise InputError('public window process output requires a written DWORD or unknown output')
                if result and effects is None:
                    raise InputError('successful public window process query requires its output')
                return
            if not result:
                raise PrimarySemanticUnavailable('failed window query cannot define its source process output')
            if type(effects) is not int or not 0 <= effects <= 0xFFFFFFFF:
                raise InputError('worker window process output requires DWORD')
        elif name == 'GetSystemPowerStatus':
            if (result and (not isinstance(effects, bytes) or len(effects) != 12)) or (not result and effects is not None):
                raise InputError('worker power status requires successful complete output or undefined failure')
        elif effects is not None:
            raise InputError('worker API has no output buffer')
        if name == 'GetCurrentProcess':
            if result != _MASK:
                raise InputError('worker own-process pseudo handle mismatch')
            self._process = result
        if name == 'GetCurrentProcessId':
            if result != os.getpid():
                raise InputError('worker process ID differs from owning process')
            self._pid = result

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if name not in _COUNTS or name == 'GetModuleHandleW' and arguments != (_PROBE,):
            if self._fallback is None:
                raise PrimarySemanticUnavailable('unsupported Windows worker observation: ' + name)
            return self._fallback.take(runtime, name, arguments)
        try:
            self._arguments(runtime, name, arguments)
            forwarded = name == 'GetCurrentProcess' and self._fallback is not None
            if forwarded:
                result, effects = self._fallback.take(runtime, name, arguments)
                if effects == b'':
                    effects = None
            else:
                if self._backend is None:
                    self._backend = WindowsWorkerAPIBackend()
                result, effects = self._backend.request(name, arguments)
            foreground = name == 'GetWindowThreadProcessId' and arguments[0] in self._foreground
            self._result(name, result, effects, foreground=foreground)
        except Exception as error:
            self.records.append({'api': name, 'status': type(error).__name__, 'last_error': getattr(self._backend, 'last_error', None)})
            raise
        self.records.append({'api': name, 'status': 'forwarded' if forwarded else 'observed', 'last_error': getattr(self._backend, 'last_error', None), 'effect_bytes': len(effects) if isinstance(effects, bytes) else 0})
        if not forwarded:
            runtime.events.append(('worker.API', name, arguments, result, effects))
        return result, effects

    def close(self):
        if self._closed:
            return
        self._check(self._runtime)
        self._closed = True
