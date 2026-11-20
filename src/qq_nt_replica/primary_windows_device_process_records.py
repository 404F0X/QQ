import _ctypes
import ctypes
import itertools
import os
import re
import struct
import threading

from .errors import InputError
from .primary_device_process_records import ProcessBufferEffect
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_MASK = (1 << 64) - 1
_LIMIT = 1 << 20
_TOKENS = itertools.count(1)
_COUNTS = {'GetCurrentProcessId': 0, 'GetCurrentProcess': 0, 'GetProcessTimes': 1,
    'QueryFullProcessImageNameW': 4, 'GetFileAttributesExW': 2, 'GetCommandLineW': 0,
    'GetCurrentDirectoryW': 2, 'FileTimeToSystemTime': 1, 'MultiByteToWideChar': 6,
    'GetModuleHandleA': 1, 'GetProcAddress': 2, 'NtQueryInformationProcess': 4,
    'OpenProcess': 3, 'CloseHandle': 1, 'CryptQueryObject': 11, 'CryptMsgGetParam': 5,
    'CertFindCertificateInStore': 6, 'CertGetNameStringW': 6, 'CryptMsgClose': 1,
    'CertFreeCertificateContext': 1, 'CertCloseStore': 2, 'GetFileVersionInfoSizeW': 1,
    'GetFileVersionInfoW': 4, 'VerQueryValueW': 2}
_POINTER_RESULTS = {'GetCurrentProcess', 'GetCommandLineW', 'GetModuleHandleA',
    'GetProcAddress', 'OpenProcess', 'CertFindCertificateInStore'}


def _wide(raw):
    if type(raw) is not bytes or not 2 <= len(raw) <= 65536 or len(raw) % 2 or raw[-2:] != b'\0\0':
        raise InputError('process observation requires bounded terminated UTF16 bytes')
    if any(raw[o:o+2] == b'\0\0' for o in range(0, len(raw)-2, 2)):
        raise InputError('process observation UTF16 contains an embedded terminator')
    return raw[:-2].decode('utf-16-le', 'surrogatepass')


def _arguments(domain, name, args):
    if type(args) is not tuple or len(args) != _COUNTS[name]:
        raise InputError('process observation argument count mismatch')
    valid = True
    process = lambda value: type(value) is int and value in domain._processes | domain._pseudo
    if name == 'GetProcessTimes':
        valid = process(args[0])
    elif name == 'QueryFullProcessImageNameW':
        valid = process(args[0]) and args[1:] == (0, True, 4096) and type(args[1]) is int and type(args[2]) is bool and type(args[3]) is int
    elif name == 'GetFileAttributesExW':
        _wide(args[0])
        valid = type(args[1]) is int and args[1] == 0
    elif name == 'GetCurrentDirectoryW':
        valid = type(args[0]) is int and type(args[1]) is bool and (args == (0, False) or 1 <= args[0] <= 32767 and args[1])
    elif name == 'FileTimeToSystemTime':
        valid = type(args[0]) is bytes and len(args[0]) == 8
    elif name == 'MultiByteToWideChar':
        valid = (type(args[0]) is int and type(args[1]) is int and args[:2] == (65001, 0)
            and type(args[2]) is bytes and 1 <= len(args[2]) <= _LIMIT and args[2][-1:] == b'\0'
            and b'\0' not in args[2][:-1] and type(args[3]) is int and args[3] == -1
            and type(args[4]) is bool and type(args[5]) is int
            and (args[4] and 1 <= args[5] <= _LIMIT//2 or not args[4] and args[5] == 0))
    elif name == 'GetModuleHandleA':
        valid = args == (b'ntdll.dll',)
    elif name == 'GetProcAddress':
        valid = type(args[0]) is int and args[0] in domain._modules and args[1] == b'NtQueryInformationProcess'
    elif name == 'NtQueryInformationProcess':
        valid = type(args[0]) is int and args[0] in domain._targets and process(args[1]) and all(type(v) is int for v in args[2:]) and args[2:] == (0, 48)
    elif name == 'OpenProcess':
        valid = all(type(v) is int for v in args) and args[:2] == (0x1000, 0) and 0 < args[2] <= 0xFFFFFFFF and args[2] in domain._parents
    elif name == 'CloseHandle':
        valid = type(args[0]) is int and args[0] in domain._processes
    elif name == 'CryptQueryObject':
        _wide(args[1])
        valid = all(type(args[o]) is int for o in (0, 2, 3, 4)) and args[0] == 1 and args[2:5] == (0x400, 2, 0) and args[5:] == (True, True, True, True, True, False) and all(type(v) is bool for v in args[5:])
    elif name == 'CryptMsgGetParam':
        valid = type(args[0]) is int and args[0] in domain._messages and all(type(args[o]) is int for o in (1, 2, 4)) and args[1:3] == (6, 0) and type(args[3]) is bool and (args[3] and 0 < args[4] < _LIMIT or not args[3] and args[4] == 0)
    elif name == 'CertFindCertificateInStore':
        valid = type(args[0]) is int and args[0] in domain._stores and all(type(args[o]) is int for o in (1, 2, 3, 5)) and args[1:4] == (0x10001, 0, 0xB0000) and type(args[4]) is bytes and len(args[4]) == 208 and args[5] == 0
    elif name == 'CertGetNameStringW':
        valid = type(args[0]) is int and args[0] in domain._certificates and all(type(args[o]) is int for o in (1, 2, 5)) and args[1:4] == (3, 0, b'2.5.4.3') and type(args[4]) is bool and (args[4] and 2 <= args[5] <= 4095 or not args[4] and args[5] == 0)
    elif name in ('CryptMsgClose', 'CertFreeCertificateContext', 'CertCloseStore'):
        table = domain._messages if name == 'CryptMsgClose' else domain._certificates if name == 'CertFreeCertificateContext' else domain._stores
        valid = type(args[0]) is int and args[0] in table and (name != 'CertCloseStore' or type(args[1]) is int and args[1] == 0)
    elif name in ('GetFileVersionInfoSizeW', 'GetFileVersionInfoW'):
        _wide(args[0])
        if name == 'GetFileVersionInfoW':
            valid = type(args[1]) is int and args[1] == 0 and type(args[2]) is int and 0 < args[2] <= _LIMIT and args[3] is True
    elif name == 'VerQueryValueW':
        query = _wide(args[1])
        valid = type(args[0]) is int and 0 < args[0] < 1 << 64 and (query == '\\VarFileInfo\\Translation' or re.fullmatch(r'\\StringFileInfo\\[0-9A-Fa-f]{8}\\(CompanyName|ProductName|FileVersion)', query) is not None)
    if not valid:
        raise InputError('process observation leaves the fixed source allowlist')
    return args


class _Domain:
    def _initialize_domain(self):
        self._owner = os.getpid(), threading.get_native_id()
        self._processes, self._pseudo, self._modules, self._targets = set(), set(), set(), set()
        self._messages, self._stores, self._certificates = set(), set(), set()
        self._parents = set()
        self.closed = False

    def _check(self):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('process observations require their open creator process and thread')

    def _track(self, name, args, result, effects):
        if name == 'GetCurrentProcess' and result:
            self._pseudo.add(result)
        elif name == 'OpenProcess' and result:
            self._processes.add(result)
        elif name == 'GetModuleHandleA' and result:
            self._modules.add(result)
        elif name == 'GetProcAddress' and result:
            self._targets.add(result)
        elif name == 'NtQueryInformationProcess' and not result & 0x80000000:
            raw = effects[0]
            if type(raw) is ProcessBufferEffect:
                raw = raw.spans[0][1]
            else:
                raw = raw[40:48]
            self._parents.add(int.from_bytes(raw[:4], 'little'))
        elif name == 'CertFindCertificateInStore' and result:
            self._certificates.add(result)
        elif name == 'CryptQueryObject' and result:
            for table, raw in ((self._stores, effects[3]), (self._messages, effects[4])):
                value = int.from_bytes(raw, 'little')
                if value:
                    table.add(value)
        elif name in ('CloseHandle', 'CryptMsgClose', 'CertFreeCertificateContext', 'CertCloseStore') and result:
            table = {'CloseHandle': self._processes, 'CryptMsgClose': self._messages,
                'CertFreeCertificateContext': self._certificates, 'CertCloseStore': self._stores}[name]
            table.remove(args[0])


class WindowsDeviceProcessRecordAPIBackend(_Domain):
    def __init__(self, *, libraries=None, last_error=None, dynamic=None):
        if libraries is None and (os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8):
            raise PrimarySemanticUnavailable('native process records require Windows x64')
        self._initialize_domain()
        self._libraries = {} if libraries is None else dict(libraries)
        self._owned_libraries = set()
        self._last_error = ctypes.get_last_error if last_error is None else last_error
        self._dynamic = dynamic
        self._signer = None
        self._version = None
        self._version_guest = None
        self._version_size = None
        self.cleanup_records = []

    def _call(self, library, name, result, types, values):
        self._check()
        if library not in self._libraries:
            self._libraries[library] = ctypes.WinDLL(library, use_last_error=True)
            self._owned_libraries.add(library)
        function = getattr(self._libraries[library], name)
        function.restype, function.argtypes = result, types
        value = function(*values)
        return value, self._last_error() & 0xFFFFFFFF

    def bind_current_process(self, observations):
        self._check()
        if type(observations) is not WindowsDeviceProcessRecordObservations:
            raise InputError('process backend requires its canonical current-process observations')
        observations._check()
        if observations._owner != self._owner or observations._pseudo != {_MASK}:
            raise InputError('process backend requires the same owner verified current-process result')
        self._pseudo.update(observations._pseudo)

    def request(self, name, args):
        self._check()
        if name not in _COUNTS:
            raise InputError('unsupported native process observation')
        _arguments(self, name, args)
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        pu, pp = ctypes.POINTER(u), ctypes.POINTER(p)
        effects = b''
        if name in ('GetCurrentProcessId', 'GetCurrentProcess'):
            value, error = self._call('kernel32', name, p if name == 'GetCurrentProcess' else u, (), ())
        elif name == 'GetProcessTimes':
            outputs = [ctypes.create_string_buffer(8) for _ in range(4)]
            value, error = self._call('kernel32', name, i, (p, p, p, p, p), (args[0], *outputs))
            effects = tuple(output.raw if value and index != 1 else b'' for index,output in enumerate(outputs))
        elif name == 'QueryFullProcessImageNameW':
            output, count = ctypes.create_string_buffer(8192), u(4096)
            value, error = self._call('kernel32', name, i, (p, u, p, pu), (args[0], 0, output, ctypes.byref(count)))
            if value and not count.value < 4096:
                raise PrimarySemanticUnavailable('process image name success exceeds its actual buffer')
            effects = (output.raw[:2*(count.value+1)], struct.pack('<I', count.value)) if value else (b'', b'')
        elif name in ('GetFileAttributesExW', 'FileTimeToSystemTime'):
            output = ctypes.create_string_buffer(36 if name == 'GetFileAttributesExW' else 16)
            if name == 'GetFileAttributesExW':
                value, error = self._call('kernel32', name, i, (ctypes.c_wchar_p, i, p), (_wide(args[0]), 0, output))
            else:
                source = ctypes.create_string_buffer(args[0], 8)
                value, error = self._call('kernel32', name, i, (p, p), (source, output))
            effects = (output.raw if value else b'',)
        elif name == 'GetCommandLineW':
            value, error = self._call('kernel32', name, p, (), ())
            raw = bytearray()
            if value:
                for offset in range(32768):
                    unit = ctypes.string_at(value+2*offset, 2)
                    raw.extend(unit)
                    if unit == b'\0\0':
                        break
                else:
                    raise PrimarySemanticUnavailable('process command line exceeds its fixed bound')
            effects = ((int(value), bytes(raw)),) if value else ()
        elif name == 'GetCurrentDirectoryW':
            capacity, present = args
            output = ctypes.create_string_buffer(2*capacity) if present else None
            value, error = self._call('kernel32', name, u, (u, p), (capacity, output))
            if present:
                effects = (output.raw[:2*(value+1)] if 0 < value < capacity else b'',)
        elif name == 'MultiByteToWideChar':
            output = ctypes.create_string_buffer(2*args[5]) if args[4] else None
            source = ctypes.create_string_buffer(args[2])
            value, error = self._call('kernel32', name, i, (u, u, p, i, p, i), (65001, 0, source, -1, output, args[5]))
            if args[4]:
                if value > args[5]:
                    raise PrimarySemanticUnavailable('process conversion exceeds its output capacity')
                effects = (output.raw[:2*value] if value > 0 else b'',)
        elif name == 'GetModuleHandleA':
            value, error = self._call('kernel32', name, p, (ctypes.c_char_p,), args)
        elif name == 'GetProcAddress':
            value, error = self._call('kernel32', name, p, (p, ctypes.c_char_p), args)
        elif name == 'NtQueryInformationProcess':
            output, count = ctypes.create_string_buffer(48), u()
            function = (self._dynamic or (lambda target: ctypes.WINFUNCTYPE(i, p, u, p, u, pu, use_last_error=True)(target)))(args[0])
            value = function(args[1], 0, output, 48, ctypes.byref(count))
            error = self._last_error() & 0xFFFFFFFF
            value &= 0xFFFFFFFF
            effects = (ProcessBufferEffect(((40, output.raw[40:48]),)), struct.pack('<I', count.value)) if not value & 0x80000000 else (b'', struct.pack('<I', count.value) if value == 0xC0000004 else b'')
        elif name == 'OpenProcess':
            value, error = self._call('kernel32', name, p, (u, i, u), args)
        elif name == 'CloseHandle':
            value, error = self._call('kernel32', name, i, (p,), args)
        elif name == 'CryptQueryObject':
            encoding, content, form, store, message = u(), u(), u(), p(), p()
            value, error = self._call('crypt32', name, i, (u, p, u, u, u, pu, pu, pu, pp, pp, pp),
                (1, ctypes.c_wchar_p(_wide(args[1])), 0x400, 2, 0, ctypes.byref(encoding), ctypes.byref(content), ctypes.byref(form), ctypes.byref(store), ctypes.byref(message), None))
            for table, pointer in ((self._stores, store.value), (self._messages, message.value)):
                if pointer:
                    table.add(pointer)
            effects = tuple(struct.pack('<I', item.value) for item in (encoding, content, form)) + tuple(struct.pack('<Q', item.value or 0) for item in (store, message)) if value else (b'',)*5
        elif name == 'CryptMsgGetParam':
            output = ctypes.create_string_buffer(args[4]) if args[3] else None
            count = u(args[4])
            value, error = self._call('crypt32', name, i, (p, u, u, p, pu), (args[0], 6, 0, output, ctypes.byref(count)))
            size_effect = struct.pack('<I', count.value) if value or error == 234 else b''
            if args[3]:
                if value:
                    if not 40 <= count.value <= args[4]:
                        raise PrimarySemanticUnavailable('process signer info success has invalid size')
                    self._signer = output, count.value, args[0]
                effects = (ProcessBufferEffect(tuple((offset, output.raw[offset:offset+size]) for offset,size in ((8,4),(16,8),(24,4),(32,8)))) if value else b'', size_effect)
            else:
                effects = (size_effect,)
        elif name == 'CertFindCertificateInStore':
            raw = args[4]
            if self._signer is None or self._signer[2] not in self._messages:
                raise InputError('certificate find requires its live signer-info allocation')
            output, size, message = self._signer
            origin = ctypes.addressof(output)
            expected = bytearray(208)
            for target, source in ((8,24),(48,8)):
                expected[target:target+4] = output.raw[source:source+4]
                expected[target+8:target+16] = output.raw[source+8:source+16]
            if raw != bytes(expected):
                raise InputError('certificate find differs from its exact source signer projection')
            for offset in (8, 48):
                count, pointer = struct.unpack_from('<I4xQ', raw, offset)
                if count and not origin <= pointer <= origin+size-count:
                    raise InputError('certificate find blob leaves its owned signer allocation')
            source = ctypes.create_string_buffer(raw, 208)
            value, error = self._call('crypt32', name, p, (p, u, u, u, p, p), (*args[:4], source, None))
        elif name == 'CertGetNameStringW':
            output = ctypes.create_string_buffer(2*args[5]) if args[4] else None
            value, error = self._call('crypt32', name, u, (p, u, u, p, p, u), (args[0], 3, 0, ctypes.c_char_p(args[3]), output, args[5]))
            if args[4]:
                if value > args[5]:
                    raise PrimarySemanticUnavailable('certificate name success exceeds its output capacity')
                effects = (output.raw[:2*value] if value else b'',)
        elif name in ('CryptMsgClose', 'CertFreeCertificateContext', 'CertCloseStore'):
            value, error = self._call('crypt32', name, i, (p, u) if name == 'CertCloseStore' else (p,), args)
            if value and name == 'CryptMsgClose' and self._signer is not None and self._signer[2] == args[0]:
                self._signer = None
        elif name == 'GetFileVersionInfoSizeW':
            count = u()
            value, error = self._call('version', name, u, (ctypes.c_wchar_p, pu), (_wide(args[0]), ctypes.byref(count)))
            effects = (struct.pack('<I', count.value) if value else b'',)
            self._version_size = (args[0], value) if value else None
        elif name == 'GetFileVersionInfoW':
            if self._version_size != (args[0], args[2]):
                raise InputError('version fill requires its exact prior path and observed size')
            output = ctypes.create_string_buffer(args[2])
            value, error = self._call('version', name, i, (ctypes.c_wchar_p, u, u, p), (_wide(args[0]), 0, args[2], output))
            self._version, self._version_guest = None, None
            if value:
                size = int.from_bytes(output.raw[:2], 'little')
                if not 6 <= size <= args[2]:
                    raise PrimarySemanticUnavailable('version info success lacks its bounded root block')
                self._version = output
                effects = (ProcessBufferEffect(((0, output.raw[:6]),)),)
            else:
                effects = (b'',)
        elif name == 'VerQueryValueW':
            if self._version is None or self._version_guest not in (None, args[0]):
                raise InputError('version query requires its current owned version allocation')
            self._version_guest = args[0]
            pointer, count = p(), u()
            query = _wide(args[1])
            value, error = self._call('version', name, i, (p, ctypes.c_wchar_p, pp, pu), (self._version, query, ctypes.byref(pointer), ctypes.byref(count)))
            effects = (b'', b'', ())
            if value:
                size = count.value * (1 if query == '\\VarFileInfo\\Translation' else 2)
                origin, address = ctypes.addressof(self._version), pointer.value or 0
                if not 0 < size <= len(self._version) or not origin <= address <= origin+len(self._version)-size:
                    raise PrimarySemanticUnavailable('version query pointer leaves its owned version allocation')
                raw = self._version.raw[address-origin:address-origin+size]
                effects = struct.pack('<Q', address), struct.pack('<I', count.value), ((address, raw),)
        value = int(value or 0) & (_MASK if name in _POINTER_RESULTS else 0xFFFFFFFF)
        self._track(name, args, value, effects)
        return value, effects, error

    def close(self):
        if self.closed:
            return
        self._check()
        for name, table in (('CertFreeCertificateContext', self._certificates), ('CryptMsgClose', self._messages), ('CertCloseStore', self._stores), ('CloseHandle', self._processes)):
            for value in tuple(table):
                result, effects, error = self.request(name, (value, 0) if name == 'CertCloseStore' else (value,))
                self.cleanup_records.append((name, bool(result), error))
                if not result:
                    raise PrimarySemanticUnavailable('native process record cleanup failed: '+name)
        self._signer = self._version = None
        self._version_size = self._version_guest = None
        for library in tuple(self._owned_libraries):
            _ctypes.FreeLibrary(self._libraries[library]._handle)
            self._owned_libraries.remove(library)
            del self._libraries[library]
        self.closed = True


class WindowsDeviceProcessRecordObservations(WorkerObservations, _Domain):
    def __init__(self, fallback=None, *, backend=None):
        self._initialize_domain()
        self.fallback, self.backend = fallback, backend
        self._runtime = None
        self.records, self._tokens = [], {}

    def _foreign(self, name, args):
        if type(args) is not tuple:
            return False
        if name == 'CloseHandle' and len(args) == 1:
            return type(args[0]) is int and args[0] not in self._processes
        if name == 'GetModuleHandleA' and len(args) == 1:
            return args != (b'ntdll.dll',)
        if name == 'GetProcAddress' and len(args) == 2:
            return args[1] != b'NtQueryInformationProcess' and args[0] not in self._modules
        if name == 'MultiByteToWideChar' and len(args) == 6:
            return args[:2] != (65001, 0)
        return False

    def _token(self, address, raw):
        key = address, raw
        if key not in self._tokens:
            memory = getattr(self._runtime, 'memory', None)
            while True:
                token = 0x6D0000000000 + next(_TOKENS)*0x200000
                if not any(token < region.address+len(region.data) and region.address < token+len(raw) for region in getattr(memory, '_regions', ())):
                    self._tokens[key] = token
                    break
        return self._tokens[key]

    def take(self, runtime, name, arguments):
        self._check()
        if self._runtime is not None and self._runtime is not runtime:
            raise InputError('process observations require their unique runtime')
        self._runtime = runtime
        if name not in _COUNTS or self._foreign(name, arguments):
            if self.fallback is None:
                raise PrimarySemanticUnavailable('unsupported process observation: '+name)
            return self.fallback.take(runtime, name, arguments)
        args = _arguments(self, name, arguments)
        if name == 'GetCurrentProcess' and self.fallback is not None:
            result, effects = self.fallback.take(runtime, name, args)
            if type(result) is not int or result != _MASK:
                raise InputError('process current-process fallback requires its exact pseudo handle')
            if effects is None:
                effects = b''
            self._validate_effects(name, args, result, effects)
            self._track(name, args, result, effects)
            if self.backend is None:
                self.backend = WindowsDeviceProcessRecordAPIBackend()
            self.backend.bind_current_process(self)
            self.records.append({'api': name, 'status': 'forwarded'})
            return result, effects
        if self.backend is None:
            self.backend = WindowsDeviceProcessRecordAPIBackend()
        result, effects, error = self.backend.request(name, args)
        if type(result) is not int or not 0 <= result < 1 << (64 if name in _POINTER_RESULTS else 32) or type(error) is not int or not 0 <= error <= 0xFFFFFFFF:
            raise InputError('process observation requires exact native result and last-error widths')
        self._validate_effects(name, args, result, effects)
        self._track(name, args, result, effects)
        if name == 'GetCommandLineW' and result:
            raw = effects[0][1]
            result = self._token(result, raw)
            effects = ((result, raw),)
        elif name == 'VerQueryValueW' and result:
            raw = effects[2][0][1]
            token = self._token(int.from_bytes(effects[0], 'little'), raw)
            effects = struct.pack('<Q', token), effects[1], ((token, raw),)
        self.records.append({'api': name, 'status': 'observed', 'error': error})
        runtime.events.append(('worker.API', name, arguments, result, effects))
        return result, effects

    def _validate_effects(self, name, args, result, effects):
        if name == 'GetCommandLineW':
            if type(effects) is not tuple or len(effects) != bool(result):
                raise InputError('command line requires exactly its returned API-owned image')
            if result:
                address, raw = effects[0]
                if type(address) is not int or address != result:
                    raise InputError('command line image differs from its returned pointer')
                _wide(raw)
            return
        if name == 'VerQueryValueW':
            if type(effects) is not tuple or len(effects) != 3:
                raise InputError('version query requires pointer, length and owned image')
            pointer, length, images = effects
            if not result:
                if effects != (b'', b'', ()):
                    raise InputError('failed version query has no defined outputs')
            elif (type(pointer) is not bytes or len(pointer) != 8 or type(length) is not bytes or len(length) != 4
                    or type(images) is not tuple or len(images) != 1 or images[0][0] != int.from_bytes(pointer, 'little')
                    or type(images[0][1]) is not bytes or not 0 < len(images[0][1]) <= _LIMIT
                    or len(images[0][1]) != int.from_bytes(length, 'little')*(1 if _wide(args[1]) == '\\VarFileInfo\\Translation' else 2)):
                raise InputError('version query requires a bounded exact owned image')
            return
        capacities = {'GetProcessTimes': (8,)*4, 'QueryFullProcessImageNameW': (8192, 4),
            'GetFileAttributesExW': (36,), 'FileTimeToSystemTime': (16,),
            'CryptQueryObject': (4, 4, 4, 8, 8), 'GetFileVersionInfoSizeW': (4,),
            'NtQueryInformationProcess': (48, 4)}
        if name == 'GetCurrentDirectoryW' and args[1]:
            capacities[name] = (2*args[0],)
        elif name == 'MultiByteToWideChar' and args[4]:
            capacities[name] = (2*args[5],)
        elif name == 'CryptMsgGetParam':
            capacities[name] = (args[4], 4) if args[3] else (4,)
        elif name == 'CertGetNameStringW' and args[4]:
            capacities[name] = (2*args[5],)
        elif name == 'GetFileVersionInfoW':
            capacities[name] = (args[2],)
        if name not in capacities:
            if type(effects) is not bytes or effects != b'':
                raise InputError('process scalar observation requires exact empty bytes')
            return
        if type(effects) is not tuple or len(effects) != len(capacities[name]):
            raise InputError('process buffer observation requires exact output arity')
        for raw, capacity in zip(effects, capacities[name]):
            if type(raw) is ProcessBufferEffect and name == 'GetFileVersionInfoW':
                if len(raw.spans) != 1 or raw.spans[0][0] != 0 or type(raw.spans[0][1]) is not bytes or len(raw.spans[0][1]) != 6:
                    raise InputError('version info exposes only its defined root header and queried views')
            elif type(raw) is ProcessBufferEffect and name == 'CryptMsgGetParam' and args[3]:
                if tuple((offset,len(data)) for offset,data in raw.spans) != ((8,4),(16,8),(24,4),(32,8)) or any(type(data) is not bytes for offset,data in raw.spans):
                    raise InputError('signer info exposes only its consumed blob fields')
            elif type(raw) is ProcessBufferEffect and name == 'NtQueryInformationProcess':
                if raw.spans != () and not (len(raw.spans) == 1 and raw.spans[0][0] == 40 and type(raw.spans[0][1]) is bytes and len(raw.spans[0][1]) == 8):
                    raise InputError('process basic info exposes only its consumed parent identifier')
            elif type(raw) is not bytes or len(raw) > capacity:
                raise InputError('process output leaves its native buffer')
        if name == 'CryptQueryObject' and result and tuple(map(len, effects)) != (4, 4, 4, 8, 8):
            raise InputError('successful certificate query requires every defined scalar output')
        if name == 'NtQueryInformationProcess':
            if not result & 0x80000000:
                if type(effects[0]) is not ProcessBufferEffect or len(effects[0].spans) != 1 or len(effects[1]) != 4:
                    raise InputError('process basic info success requires its parent and actual return length')
            elif effects[0] != b'' or effects[1] != b'' and result != 0xC0000004:
                raise InputError('failed process basic info exposes no valid structure')
        required = {'GetProcessTimes': (8,0,8,8), 'GetFileAttributesExW': (36,), 'FileTimeToSystemTime': (16,), 'GetFileVersionInfoSizeW': (4,)}
        if name in required and result and tuple(map(len, effects)) != required[name]:
            raise InputError('successful process query requires complete defined outputs')
        if name == 'QueryFullProcessImageNameW' and result:
            if len(effects[1]) != 4:
                raise InputError('process image success requires its actual character count')
            count = int.from_bytes(effects[1], 'little')
            if count >= 4096 or len(effects[0]) != 2*(count+1) or effects[0][-2:] != b'\0\0':
                raise InputError('process image success requires its bounded terminated path')
        if name in ('MultiByteToWideChar', 'CertGetNameStringW') and args[4] and result and len(effects[0]) != 2*result:
            raise InputError('process string success requires its exact native output length')
        if name == 'GetCurrentDirectoryW' and args[1] and 0 < result < args[0] and (len(effects[0]) != 2*(result+1) or effects[0][-2:] != b'\0\0'):
            raise InputError('directory success requires its bounded terminated path')
        failed = name in ('GetProcessTimes', 'QueryFullProcessImageNameW', 'GetFileAttributesExW', 'FileTimeToSystemTime', 'CryptQueryObject', 'GetFileVersionInfoSizeW', 'GetFileVersionInfoW') and result == 0
        if failed and any(raw != b'' for raw in effects):
            raise InputError('failed process query exposes no defined output buffer')

    def snapshot(self):
        return {'closed': self.closed, 'processes': len(self._processes), 'messages': len(self._messages),
            'stores': len(self._stores), 'certificates': len(self._certificates), 'observations': len(self.records),
            'backend_closed': bool(getattr(self.backend, 'closed', False))}

    def close(self):
        if self.closed:
            return
        self._check()
        if self.backend is not None:
            self.backend.close()
        for table in (self._processes, self._pseudo, self._modules, self._targets, self._parents, self._messages, self._stores, self._certificates, self._tokens):
            table.clear()
        self.closed = True
