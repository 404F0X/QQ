import ctypes as C
import os

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


APIS = frozenset(('GetModuleHandleW', 'GetProcAddress', 'GetCurrentProcess',
                  'NtQueryInformationProcess', 'OpenProcess', 'QueryFullProcessImageNameA', 'CloseHandle'))
_MODULE = 'ntdll.dll'.encode('utf-16le') + bytes(2)
_EXPORT = b'NtQueryInformationProcess\0'
_SIGNATURES = {
    'GetModuleHandleW': (C.c_void_p, (C.c_void_p,)),
    'GetProcAddress': (C.c_void_p, (C.c_void_p, C.c_char_p)),
    'GetCurrentProcess': (C.c_void_p, ()),
    'OpenProcess': (C.c_void_p, (C.c_uint32, C.c_int32, C.c_uint32)),
    'QueryFullProcessImageNameA': (C.c_int32, (C.c_void_p, C.c_uint32, C.c_void_p, C.c_void_p)),
    'CloseHandle': (C.c_int32, (C.c_void_p,)),
}


class _ProcessBasicInformation(C.Structure):
    _fields_ = [('Reserved1', C.c_void_p), ('PebBaseAddress', C.c_void_p),
                ('Reserved2', C.c_void_p * 2), ('UniqueProcessId', C.c_size_t), ('Reserved3', C.c_void_p)]


class WindowsNotificationProcessAPIBackend:
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8 or C.sizeof(_ProcessBasicInformation) != 48:
            raise PrimarySemanticUnavailable('parent process APIs require Windows AMD64 PBI48')
        self._library = C.WinDLL('kernel32', use_last_error=True)
        self._functions = {}
        for name, (result, arguments) in _SIGNATURES.items():
            function = getattr(self._library, name)
            function.restype, function.argtypes = result, arguments
            self._functions[name] = function
        self._module = self._query = None
        self.last_error = None

    def call(self, name, *arguments):
        if name == 'GetModuleHandleW':
            if len(arguments) != 1 or not isinstance(arguments[0], C.Array) or arguments[0].raw != _MODULE:
                raise InputError('parent process backend requires its fixed borrowed ntdll role')
            result = self._functions[name](*arguments)
            self._module = int(result or 0)
            self._query = None
        elif name == 'GetProcAddress':
            if arguments != (self._module, _EXPORT):
                raise InputError('parent process backend requires its fixed source export')
            result = self._functions[name](*arguments)
            if result:
                if not self._module:
                    raise InputError('parent query export has no borrowed source module')
                signature = C.WINFUNCTYPE(C.c_int32, C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32, C.c_void_p,
                                          use_last_error=True)
                self._query = signature(result)
        elif name == 'NtQueryInformationProcess':
            if self._query is None or len(arguments) != 5 or arguments[1] != 0 or arguments[3:] != (48, None):
                raise InputError('parent process backend requires its resolved class0 PBI48 NULL-return-length query')
            result = self._query(*arguments)
        elif name in _SIGNATURES:
            result = self._functions[name](*arguments)
        else:
            raise InputError('parent process backend supports only its finite source APIs')
        self.last_error = C.get_last_error()
        mask = (1 << 64) - 1 if name in ('GetModuleHandleW', 'GetProcAddress', 'GetCurrentProcess', 'OpenProcess') else 0xFFFFFFFF
        return int(result or 0) & mask


class WindowsNotificationProcessService:
    def __init__(self, observer, backend=None):
        self._observer, self._backend = observer, backend
        self._stage, self._serial = 'fresh', 0
        self._module = self._function = self._current = self._parent = 0
        self._tokens, self._owned = {}, {}
        self._closing = False

    def _call(self, event, name, arguments):
        if self._backend is None:
            self._backend = WindowsNotificationProcessAPIBackend()
        event['native_arguments'] = tuple(C.addressof(value) if isinstance(value, C.Array) else value for value in arguments)
        result = self._backend.call(name, *arguments)
        limit = (1 << 64) - 1 if name in ('GetModuleHandleW', 'GetProcAddress', 'GetCurrentProcess', 'OpenProcess') else 0xFFFFFFFF
        if type(result) is not int or not 0 <= result <= limit:
            raise InputError('parent process backend returned an invalid typed scalar')
        event['result'], event['last_error'] = result, getattr(self._backend, 'last_error', None)
        return result

    def _expect(self, stage, actual, expected):
        if (self._stage != stage or actual != expected or
                any(type(value) is not type(wanted) for value, wanted in zip(actual, expected))):
            raise InputError('parent process API arguments/order differ from the fixed source role')

    def take(self, runtime, name, arguments, event, summary):
        self._observer._check(runtime)
        if self._closing:
            raise InputError('parent process service is closing with retained handle ownership')
        event['variant'] = summary['variant'] = 'A' if name == 'QueryFullProcessImageNameA' else 'source-parent-process'
        summary['role'] = 'source35BF640-parent-process'
        if name == 'GetModuleHandleW':
            if self._stage not in ('fresh', 'done') or arguments != (_MODULE,) or type(arguments[0]) is not bytes:
                raise InputError('parent process module lookup requires its fixed fresh source role')
            self._serial += 1
            self._tokens = {role: 0x70000000 + self._serial * 16 + index for index, role in enumerate(('module', 'function', 'current', 'process'), 1)}
            self._module = self._call(event, name, (C.create_string_buffer(_MODULE, len(_MODULE)),))
            self._stage = 'export'
            summary['_safe_result'] = int(bool(self._module))
            return self._tokens['module'] if self._module else 0, b''
        if name == 'GetProcAddress':
            self._expect('export', arguments, (self._tokens.get('module', 0) if self._module else 0, _EXPORT))
            self._function = self._call(event, name, (self._module, _EXPORT))
            if self._function and not self._module:
                raise InputError('parent process export lacks its borrowed module provenance')
            self._stage = 'current' if self._function else 'done'
            summary['_safe_result'] = int(bool(self._function))
            return self._tokens['function'] if self._function else 0, b''
        if name == 'GetCurrentProcess':
            self._expect('current', arguments, ())
            self._current = self._call(event, name, ())
            self._stage = 'query'
            summary['_safe_result'] = int(bool(self._current))
            return self._tokens['current'], b''
        if name == 'NtQueryInformationProcess':
            self._expect('query', arguments, (self._tokens.get('function'), self._tokens.get('current'), 0, bytes(48), 48, 0))
            buffer = C.create_string_buffer(bytes(48), 48)
            result = self._call(event, name, (self._current, 0, buffer, 48, None))
            self._observer._buffer(event, summary, 'parent-PBI48', bytes(48), buffer.raw, b'\1' * 48)
            self._parent = int.from_bytes(buffer.raw[40:48], 'little')
            self._stage = 'open' if not result & 0x80000000 and self._parent else 'done'
            return result, buffer.raw
        if name == 'OpenProcess':
            self._expect('open', arguments, (0x1000, 0, self._parent))
            native = self._call(event, name, (0x1000, 0, self._parent & 0xFFFFFFFF))
            token = self._tokens['process']
            if native:
                self._owned[token] = native
            self._stage = 'image' if native else 'done'
            summary['_safe_result'] = int(bool(native))
            return token if native else 0, b''
        if name == 'QueryFullProcessImageNameA':
            token = self._tokens.get('process')
            self._expect('image', arguments, (token, 0, bytes(260), 260))
            if token not in self._owned:
                raise InputError('parent image query lost its owned process capability')
            self._stage = 'close'
            buffer = C.create_string_buffer(bytes(260), 260)
            capacity = C.create_string_buffer((260).to_bytes(4, 'little'), 4)
            result = self._call(event, name, (self._owned[token], 0, buffer, capacity))
            self._observer._buffer(event, summary, 'parent-ANSI260', bytes(260), buffer.raw, b'\1' * 260)
            self._observer._buffer(event, summary, 'parent-capacityDWORD', (260).to_bytes(4, 'little'), capacity.raw, b'\1' * 4)
            return result, (buffer.raw, capacity.raw)
        if name == 'CloseHandle':
            token = self._tokens.get('process')
            self._expect('close', arguments, (token,))
            if token not in self._owned:
                raise InputError('parent process close lacks its source-owned handle')
            result = self._call(event, name, (self._owned[token],))
            if result:
                del self._owned[token]
            self._stage = 'done'
            summary['retained_handles'] = len(self._owned)
            return result, b''
        raise InputError('unsupported parent process API')

    def close(self):
        self._closing = True
        for token, native in tuple(self._owned.items()):
            result = self._call({}, 'CloseHandle', (native,))
            if result:
                del self._owned[token]
            self._observer.records.append(dict(api='CloseHandle', phase='notification-process-cleanup',
                                                result=result, retained_handles=len(self._owned),
                                                status='observed', buffers=[]))
        if self._owned:
            raise PrimarySemanticUnavailable('parent process service retains an unreleased native handle')
        self._module = self._function = self._current = self._parent = 0
        self._tokens.clear()
        self._stage = 'closed'

    @property
    def resource_count(self):
        return len(self._owned)
