import ctypes
import _ctypes
import hashlib
import os
import threading

from .errors import InputError
from .primary_device_system_records import _image
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_LIMIT = 1 << 20
_MASK = (1 << 64) - 1
_UNBOUND = object()
_VOID = {'GetSystemInfo', 'GetNativeSystemInfo', 'GetSystemTimeAsFileTime', 'GetSystemTime', 'GetLocalTime'}
_COLD_QUERIES = {'GetSystemInfo', 'EnumDisplaySettingsW', 'GetSystemMetrics', 'CallNtPowerInformation', 'GlobalMemoryStatusEx'}
_WLAN_NAMES = (b'WlanOpenHandle', b'WlanEnumInterfaces', b'WlanQueryInterface', b'WlanGetAvailableNetworkList', b'WlanFreeMemory', b'WlanCloseHandle')
_WLAN_PATTERN = '%s\\Wlanapi.dll'
_WLAN_LOADER = {'LoadLibraryExW', 'GetProcAddress', 'FreeLibrary'}
_SURFACE = set(_image()['imports']) | {'_localtime64_s', 'GetSystemDirectoryW'} | _COLD_QUERIES | _WLAN_LOADER


def _sparse(raw, ranges):
    known = bytearray(len(raw))
    for start, end in ranges:
        known[start:end] = b'\1' * (end - start)
    return raw, bytes(known)


def _display_input(args):
    if (type(args) is not tuple or len(args) != 3 or type(args[0]) is not int or args[0] != 0 or
            type(args[1]) is not int or not 0 <= args[1] < 4096 or type(args[2]) is not tuple or len(args[2]) != 2):
        raise InputError('native display query requires device, mode and explicit buffer preimage')
    raw, known = args[2]
    if (type(raw) is not bytes or len(raw) != 220 or type(known) is not bytes or len(known) != 220 or
            any(value not in (0, 1) for value in known)):
        raise InputError('native display query requires its exact DEVMODEW bytes and knownness')
    if known[68:72] != b'\1' * 4:
        raise PrimarySemanticUnavailable('EnumDisplaySettingsW input_preimage_unavailable')
    size, extra = int.from_bytes(raw[68:70], 'little'), int.from_bytes(raw[70:72], 'little')
    if size != 220 or size + extra > len(raw):
        raise PrimarySemanticUnavailable('EnumDisplaySettingsW source input exceeds supported DEVMODEW ABI or buffer bounds')
    return raw, known


def _display_mask(known):
    output = bytearray(known)
    output[168:188] = b'\1' * 20
    return bytes(output)


def _conversion_args(args, codepage):
    return (len(args) == 8 and type(args[0]) is int and args[:2] == (codepage, 0) and isinstance(args[2], bytes) and
        2 <= len(args[2]) <= _LIMIT and len(args[2]) % 2 == 0 and args[2][-2:] == b'\0\0' and
        args[3] == -1 and type(args[4]) is bool and type(args[5]) is int and 0 <= args[5] <= _LIMIT and
        args[4] == (args[5] != 0) and args[6:] == (0, 0))


class WindowsSystemRecordAPIBackend:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_wchar) != 2:
            raise PrimarySemanticUnavailable('system record native observations require Windows Win64')
        self._owner = os.getpid(), threading.get_native_id()
        self._keys, self._sids, self._power = set(), set(), set()
        self._libraries = {}
        self._wlan_path = None
        self._wlan_modules = {}
        self._wlan_seen = set()
        self._wlan_exports = {}
        self._closed = False
        self.cleanup_records = []
        self.kernel = ctypes.WinDLL('kernel32', handle=ctypes.windll.kernel32._handle, use_last_error=True)

    def _check(self):
        if self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('native system record backing requires its creator process and thread')

    def _call(self, library, name, result, types, values):
        self._check()
        if library == 'kernel32':
            dll = self.kernel
        else:
            if library not in self._libraries:
                self._libraries[library] = ctypes.WinDLL(library, use_last_error=True)
            dll = self._libraries[library]
        function = getattr(dll, name)
        function.restype, function.argtypes = result, types
        value = function(*values)
        return value, ctypes.get_last_error() & 0xFFFFFFFF

    @staticmethod
    def _buffer(size):
        return ctypes.create_string_buffer(b'\xCC' * size, size)

    @staticmethod
    def _string_prefix(raw, units=1):
        for offset in range(0, len(raw), units):
            if raw[offset:offset + units] == bytes(units):
                return raw[:offset + units]
        raise PrimarySemanticUnavailable('native system record string lacks its bounded terminator')

    def request(self, name, args):
        self._check()
        p, u, i, q = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint64
        pu = ctypes.POINTER(u)
        if name == 'GetSystemDirectoryW':
            self._wlan_path = None
            if type(args) is not tuple or len(args) != 1 or type(args[0]) is not int or not 0 <= args[0] <= 260:
                raise InputError('system directory requires its bounded UINT character capacity')
            capacity = args[0]
            output = self._buffer(max(2, 2 * capacity))
            value, error = self._call('kernel32', name, u, (p, u), (output, capacity))
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise InputError('system directory result requires its native UINT width')
            raw = b''
            if 0 < value < capacity:
                raw = output.raw[:2 * (value + 1)]
                if raw[-2:] != b'\0\0':
                    raise PrimarySemanticUnavailable('system directory success lacks its actual UTF16 terminator')
            if raw:
                end = raw.find(b'\0')
                if end >= 0:
                    if any(value >= 128 for value in raw[:end]):
                        raise PrimarySemanticUnavailable('WLAN narrow formatter nonASCII locale semantics are unsupported')
                    path = _WLAN_PATTERN.replace('%s', ''.join(chr(value) for value in raw[:end]))
                    if len(path) < 260:
                        self._wlan_path = path.encode('utf-16-le') + b'\0\0'
            return value, raw, error
        if name == 'LoadLibraryExW':
            if (type(args) is not tuple or len(args) != 3 or type(args[0]) is not bytes or
                    self._wlan_path is None or args[0] != self._wlan_path or
                    type(args[1]) is not int or args[1] != 0 or type(args[2]) is not int or args[2] != 0x808):
                raise InputError('WLAN loader requires its same-owner source system-directory construction and fixed flags')
            value, error = self._call('kernel32', name, p, (ctypes.c_wchar_p, p, u),
                (args[0][:-2].decode('utf-16-le'), None, 0x808))
            value = int(value or 0)
            if not 0 <= value <= _MASK:
                raise InputError('WLAN module requires its native pointer width')
            if value:
                self._wlan_modules[value] = self._wlan_modules.get(value, 0) + 1
                self._wlan_seen.add(value)
            return value, b'', error
        if name == 'GetProcAddress':
            if (type(args) is not tuple or len(args) != 2 or type(args[0]) is not int or
                    args[0] not in self._wlan_modules or type(args[1]) is not bytes or args[1] not in _WLAN_NAMES):
                raise InputError('WLAN export requires its live owned module and fixed public symbol')
            value, error = self._call('kernel32', name, p, (p, ctypes.c_char_p), args)
            value = int(value or 0)
            if not 0 <= value <= _MASK:
                raise InputError('WLAN export requires its native pointer width')
            self._wlan_exports[args] = value
            return value, b'', error
        if name == 'FreeLibrary':
            if (type(args) is not tuple or len(args) != 1 or type(args[0]) is not int or
                    args[0] not in self._wlan_modules):
                raise InputError('WLAN release requires its live owned module reference')
            value, error = self._call('kernel32', name, i, (p,), args)
            if value:
                self._wlan_modules[args[0]] -= 1
                if not self._wlan_modules[args[0]]:
                    del self._wlan_modules[args[0]]
                    self._wlan_exports = {key: target for key, target in self._wlan_exports.items() if key[0] != args[0]}
            return value & 0xFFFFFFFF, b'', error
        if name == 'RegOpenKeyExA':
            output = p()
            value, error = self._call('advapi32', name, i, (p, ctypes.c_char_p, u, u, ctypes.POINTER(p)),
                (*args, ctypes.byref(output)))
            if not value:
                self._keys.add(int(output.value or 0))
            return value & 0xFFFFFFFF, ((int(output.value or 0).to_bytes(8, 'little') if not value else b''),), error
        if name == 'RegQueryValueExA':
            handle, key, reserved, capacity = args
            output, kind, length = self._buffer(capacity), u(), u(capacity)
            value, error = self._call('advapi32', name, i, (p, ctypes.c_char_p, p, pu, p, pu),
                (handle, key, None, ctypes.byref(kind), output, ctypes.byref(length)))
            if value == 0 and length.value > capacity:
                raise PrimarySemanticUnavailable('native registry success exceeds its actual output capacity')
            data = output.raw[:length.value] if value == 0 and length.value <= capacity else b''
            effects = (bytes(kind) if value == 0 else b'', data, bytes(length) if value in (0, 234) else b'')
            return value & 0xFFFFFFFF, effects, error
        if name == 'RegCloseKey':
            value, error = self._call('advapi32', name, i, (p,), args)
            if not value:
                self._keys.remove(args[0])
            return value & 0xFFFFFFFF, b'', error
        if name == 'AllocateAndInitializeSid':
            authority = ctypes.create_string_buffer(args[0], 6)
            output = p()
            value, error = self._call('advapi32', name, i, (p, ctypes.c_ubyte, *(u,) * 8, ctypes.POINTER(p)),
                (authority, *args[1:], ctypes.byref(output)))
            if value:
                self._sids.add(int(output.value or 0))
            return value & 0xFFFFFFFF, ((int(output.value or 0).to_bytes(8, 'little') if value else b''),), error
        if name == 'CheckTokenMembership':
            output = i()
            value, error = self._call('advapi32', name, i, (p, p, ctypes.POINTER(i)), (*args, ctypes.byref(output)))
            return value & 0xFFFFFFFF, (bytes(output) if value else b'',), error
        if name == 'FreeSid':
            value, error = self._call('advapi32', name, p, (p,), args)
            if not value:
                self._sids.remove(args[0])
            return int(value or 0), b'', error
        if name in ('GetNativeSystemInfo', 'GetSystemInfo'):
            from .primary_windows_provider_observations import _NativeSystemInfo
            if ctypes.sizeof(_NativeSystemInfo) != 48 or _NativeSystemInfo.processor_count.offset != 32:
                raise PrimarySemanticUnavailable('native SYSTEM_INFO layout does not match source Win64 ABI')
            output = _NativeSystemInfo()
            value, error = self._call('kernel32', name, None, (ctypes.POINTER(_NativeSystemInfo),), (ctypes.byref(output),))
            return value, (_sparse(bytes(output), ((32, 36),) if name == 'GetSystemInfo' else ((0, 2), (32, 36))),), error
        if name == 'EnumDisplaySettingsW':
            raw, known = _display_input(args)
            output = self._buffer(220)
            for index, initialized in enumerate(known):
                if initialized:
                    output[index:index + 1] = raw[index:index + 1]
            value, error = self._call('user32', name, i, (p, u, p), (None, args[1], output))
            return value & 0xFFFFFFFF, ((output.raw, _display_mask(known)),) if value else b'', error
        if name == 'GetSystemMetrics':
            value, error = self._call('user32', name, i, (i,), args)
            return value & 0xFFFFFFFF, b'', error
        if name == 'CallNtPowerInformation':
            output = self._buffer(32)
            value, error = self._call('powrprof', name, i, (i, p, u, p, u),
                (5, None, 0, output, 32))
            return value & 0xFFFFFFFF, (_sparse(output.raw, ((1, 4),)),) if value == 0 else b'', error
        if name == 'GlobalMemoryStatusEx':
            output = self._buffer(64)
            output[0:4] = (64).to_bytes(4, 'little')
            value, error = self._call('kernel32', name, i, (p,), (output,))
            return value & 0xFFFFFFFF, output.raw if value else b'', error
        if name == 'GetTickCount64':
            value, error = self._call('kernel32', name, q, (), ())
            return value, b'', error
        if name in ('GetSystemTimeAsFileTime', 'GetSystemTime', 'GetLocalTime'):
            output = self._buffer(8 if name == 'GetSystemTimeAsFileTime' else 16)
            value, error = self._call('kernel32', name, None, (p,), (output,))
            return value, (output.raw,), error
        if name == '_localtime64_s':
            output, seconds = self._buffer(36), ctypes.c_int64(args[0])
            value, error = self._call('ucrtbase', name, i, (p, ctypes.POINTER(ctypes.c_int64)), (output, ctypes.byref(seconds)))
            return value & 0xFFFFFFFF, (output.raw if not value else b'',), error
        if name == 'GetDynamicTimeZoneInformation':
            output = self._buffer(432)
            value, error = self._call('kernel32', name, u, (p,), (output,))
            effects = b''
            if value != 0xFFFFFFFF:
                prefix = self._string_prefix(output.raw[172:428], 2)
                effects = _sparse(output.raw, ((172, 172 + len(prefix)),))
            return value, (effects,), error
        if name in ('GetSystemDefaultLocaleName', 'GetLocaleInfoEx'):
            capacity = args[-1]
            output = self._buffer(capacity * 2)
            values = (output, capacity) if name == 'GetSystemDefaultLocaleName' else (None, args[1], output, capacity)
            types = (p, i) if name == 'GetSystemDefaultLocaleName' else (p, u, p, i)
            value, error = self._call('kernel32', name, i, types, values)
            if not 0 <= value <= capacity:
                raise PrimarySemanticUnavailable('native locale count exceeds its actual buffer')
            return value, (output.raw[:value * 2] if value else b'',), error
        if name == 'WideCharToMultiByte':
            source = ctypes.create_string_buffer(args[2])
            output = self._buffer(args[5]) if args[4] else None
            value, error = self._call('kernel32', name, i, (u, u, p, i, p, i, p, p),
                (65001, 0, source, -1, output, args[5], None, None))
            if not 0 <= value <= (args[5] if output is not None else _LIMIT):
                raise PrimarySemanticUnavailable('native UTF8 count exceeds its finite source buffer')
            return value, (output.raw[:value] if value else b'',) if output is not None else b'', error
        if name == 'GetVolumeInformationA':
            volume, filesystem = self._buffer(260), self._buffer(260)
            serial, maximum, flags = u(), u(), u()
            value, error = self._call('kernel32', name, i, (ctypes.c_char_p, p, u, pu, pu, pu, p, u),
                (args[0], volume, 260, ctypes.byref(serial), ctypes.byref(maximum), ctypes.byref(flags), filesystem, 260))
            effects = (self._string_prefix(volume.raw), bytes(serial), bytes(maximum), bytes(flags), self._string_prefix(filesystem.raw)) if value else (b'',) * 5
            return value & 0xFFFFFFFF, effects, error
        if name == 'GetDiskFreeSpaceExA':
            total, free = q(), q()
            value, error = self._call('kernel32', name, i, (ctypes.c_char_p, p, ctypes.POINTER(q), ctypes.POINTER(q)),
                (args[0], None, ctypes.byref(total), ctypes.byref(free)))
            return value & 0xFFFFFFFF, (bytes(total), bytes(free)) if value else (b'', b''), error
        if name == 'PowerGetActiveScheme':
            output = p()
            value, error = self._call('powrprof', name, u, (p, ctypes.POINTER(p)), (None, ctypes.byref(output)))
            pointer = int(output.value or 0)
            if not value and pointer:
                self._power.add(pointer)
                raw = ctypes.string_at(pointer, 16)
                return value, (pointer.to_bytes(8, 'little'), ((pointer, raw),)), error
            return value, (b'', ()), error
        if name == 'LocalFree':
            value, error = self._call('kernel32', name, p, (p,), args)
            if not value:
                self._power.remove(args[0])
            return int(value or 0), b'', error
        if name == 'GetSystemFirmwareTable':
            output = self._buffer(args[3]) if args[2] else None
            value, error = self._call('kernel32', name, u, (u, u, p, u), (args[0], args[1], output, args[3]))
            return value, (output.raw[:value] if 0 < value <= args[3] else b'',) if output is not None else b'', error
        raise PrimarySemanticUnavailable('unsupported finite native system record API: ' + name)

    def close(self):
        if self._closed:
            return
        self._check()
        errors = []
        for module, count in tuple(self._wlan_modules.items()):
            for unused in range(count):
                try:
                    result, effects, error = self.request('FreeLibrary', (module,))
                    self.cleanup_records.append({'api': 'FreeLibrary', 'ownership': 'host_after_incomplete_source',
                        'success': bool(result), 'error': error})
                    if not result:
                        raise PrimarySemanticUnavailable('native WLAN module cleanup failed')
                except BaseException as failure:
                    errors.append(failure)
        for name, owned in (('RegCloseKey', self._keys), ('FreeSid', self._sids), ('LocalFree', self._power)):
            for pointer in tuple(owned):
                try:
                    result, effects, error = self.request(name, (pointer,))
                    self.cleanup_records.append({'api': name, 'ownership': 'host_after_incomplete_source', 'result': result, 'error': error})
                    if result:
                        raise PrimarySemanticUnavailable('native system record host cleanup failed: ' + name)
                except BaseException as failure:
                    errors.append(failure)
        if errors:
            raise BaseExceptionGroup('native system record resources retained', errors)
        for name, dll in tuple(self._libraries.items()):
            _ctypes.FreeLibrary(dll._handle)
            del self._libraries[name]
        self._closed = True

    def snapshot(self):
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('native system record snapshot requires its creator identity')
        return {'closed': self._closed, 'registry_handles': len(self._keys), 'SIDs': len(self._sids),
            'power_allocations': len(self._power), 'owned_libraries': len(self._libraries),
            'wlan_module_references': sum(self._wlan_modules.values()), 'wlan_exports': len(self._wlan_exports)}


class WindowsSystemRecordObservations(WorkerObservations):
    def __init__(self, fallback=None, *, backend=None, allow_qqprotect_registry=False, registry_backend=None):
        if type(allow_qqprotect_registry) is not bool or (registry_backend is not None and not allow_qqprotect_registry):
            raise InputError('QQProtect registry backing requires its explicit boolean opt-in')
        self._protection_registry = None
        if allow_qqprotect_registry:
            from .primary_windows_protection_registry import WindowsProtectionRegistryObservations
            self._protection_registry = WindowsProtectionRegistryObservations(allow_qqprotect_registry=True, backend=registry_backend)
        self._identity = os.getpid(), threading.get_native_id()
        self._runtime, self._closed = _UNBOUND, False
        self._fallback, self._backend = fallback, backend
        self._keys, self._sids, self._power = {}, set(), set()
        self._firmware_size = None
        self._memory_failure_error = None
        self.records = []
        image = _image()
        self._queries = {}
        for item in image['registry']:
            path = bytes.fromhex(item['path_hex'])
            self._queries.setdefault((item['root'], path), set()).add((bytes.fromhex(item['key_hex']), item.get('capacity', 4)))
        self._queries[(0xFFFFFFFF80000002, bytes.fromhex(image['mounted_path_hex']))] = {(bytes.fromhex(image['mounted_key_hex']), 32)}
        root_rva = image['volume_root_rva']
        self._volume_root = None
        for segment in image['segments']:
            raw = bytes.fromhex(segment['hex'])
            start = root_rva - segment['rva']
            if 0 <= start < len(raw):
                self._volume_root = raw[start:].split(b'\0', 1)[0] + b'\0'
        if self._volume_root is None:
            raise InputError('fixed system record volume root is not represented by its image')

    def _check_owner(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('system record observations require their owning process and native thread')

    def _check(self, runtime):
        self._check_owner()
        if self._runtime is _UNBOUND:
            self._runtime = runtime
        elif self._runtime is not runtime:
            raise InputError('system record observations require their original runtime')

    def _validate(self, name, args):
        if not isinstance(args, tuple):
            raise InputError('system record API requires tuple arguments')
        valid = False
        if name == 'RegOpenKeyExA':
            valid = len(args) == 4
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            valid = (args[0], args[1]) in self._queries
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            valid = args[2:] == (0, 131353)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'RegQueryValueExA':
            valid = len(args) == 4 and args[0] in self._keys and (args[2] == 0) and ((args[1], args[3]) in self._queries[self._keys[args[0]]])
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'RegCloseKey':
            valid = len(args) == 1 and args[0] in self._keys
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'AllocateAndInitializeSid':
            valid = args == (b'\x00\x00\x00\x00\x00\x05', 2, 32, 544, 0, 0, 0, 0, 0, 0)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'CheckTokenMembership':
            valid = len(args) == 2 and args[0] == 0 and (args[1] in self._sids)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'FreeSid':
            valid = len(args) == 1 and args[0] in self._sids
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name in _VOID or name in ('GetTickCount64', 'GetDynamicTimeZoneInformation'):
            valid = args == ()
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GetSystemMetrics':
            valid = len(args) == 1 and type(args[0]) is int and (args[0] in (0, 1))
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'EnumDisplaySettingsW':
            _display_input(args)
            valid = True
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'CallNtPowerInformation':
            valid = args == (5, 0, 0, 32) and all((type(value) is int for value in args))
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GlobalMemoryStatusEx':
            valid = args == (64,) and type(args[0]) is int
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == '_localtime64_s':
            valid = len(args) == 1 and type(args[0]) is int and (0 < args[0] <= 4294967295)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'LoadLibraryExW':
            valid = len(args) == 3 and type(args[0]) is bytes and (type(args[1]) is int) and (args[1] == 0) and (type(args[2]) is int) and (args[2] == 2056)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GetProcAddress':
            valid = len(args) == 2 and type(args[0]) is int and (type(args[1]) is bytes) and (args[1] in _WLAN_NAMES)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'FreeLibrary':
            valid = len(args) == 1 and type(args[0]) is int
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GetSystemDirectoryW':
            valid = len(args) == 1 and type(args[0]) is int and (args == (260,))
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GetSystemDefaultLocaleName':
            valid = args == (85,)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GetLocaleInfoEx':
            valid = args == (0, 4098, 64)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'WideCharToMultiByte':
            valid = _conversion_args(args, 65001)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GetVolumeInformationA':
            valid = args == (self._volume_root, True, 260, True, True, True, True, 260)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GetDiskFreeSpaceExA':
            valid = args == (self._volume_root, False, True, True)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'PowerGetActiveScheme':
            valid = args == (0,)
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'LocalFree':
            valid = len(args) == 1 and args[0] in self._power
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        elif name == 'GetSystemFirmwareTable':
            valid = len(args) == 4 and args[:2] == (1381190978, 0) and (type(args[2]) is bool) and (type(args[3]) is int) and (args[2:] == (False, 0) or (args[2] and 0 < args[3] <= _LIMIT and (args[3] == self._firmware_size)))
            if not valid:
                raise InputError('system record API is outside its fixed read-only source contract: ' + name)
            return
        raise InputError('system record API is outside its fixed read-only source contract: ' + name)

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if self._protection_registry is not None and self._protection_registry.handles(name, arguments):
            result, effects = self._protection_registry.take(runtime, name, arguments)
            if name in ('RegOpenKeyExA', 'RegCreateKeyExA') and result == 0 and int.from_bytes(effects, 'little') in self._keys:
                raise InputError('QQProtect HKEY aliases a read-only source-owned registry handle')
            return result, effects
        pending_error = self._memory_failure_error
        self._memory_failure_error = None
        if name == 'GetLastError' and pending_error is not None:
            if type(arguments) is not tuple or arguments:
                raise InputError('memory status last-error requires its immediate no-argument read')
            self.records.append({'api': name, 'status': 'observed', 'result': pending_error, 'error': pending_error,
                'effect_sha256': hashlib.sha256(repr(self._summary(b'')).encode()).hexdigest()})
            return pending_error, b''
        if name in ('GetProcAddress', 'FreeLibrary') and (self._backend is None or
                type(arguments) is not tuple or not arguments or type(arguments[0]) is not int or
                arguments[0] not in self._backend._wlan_seen):
            if self._fallback is not None:
                return self._fallback.take(runtime, name, arguments)
            raise PrimarySemanticUnavailable('foreign module observation is unavailable: ' + name)
        if name not in _SURFACE:
            if self._fallback is not None:
                return self._fallback.take(runtime, name, arguments)
            raise PrimarySemanticUnavailable('system record observation is unavailable: ' + name)
        if (name == 'WideCharToMultiByte' and isinstance(arguments, tuple) and _conversion_args(arguments, 0) and
                self._fallback is not None):
            return self._fallback.take(runtime, name, arguments)
        self._validate(name, arguments)
        if self._backend is None:
            self._backend = WindowsSystemRecordAPIBackend()
        result, effects, error = self._backend.request(name, arguments)
        if name == 'WideCharToMultiByte' and arguments[4]:
            if not isinstance(effects, tuple) or len(effects) != 1 or not isinstance(effects[0], bytes):
                raise InputError('native UTF8 fill requires its canonical raw output')
            effects = effects[0]
        if name in _VOID:
            if result is not None:
                raise InputError('native system record void API returned a value: ' + name)
        elif type(result) is not int or not 0 <= result <= (_MASK if name in ('GetTickCount64', 'FreeSid', 'LocalFree', 'LoadLibraryExW', 'GetProcAddress') else 0xFFFFFFFF):
            raise InputError('native system record result exceeds its ABI: ' + name)
        if type(error) is not int or not 0 <= error <= 0xFFFFFFFF:
            raise InputError('native system record last-error must be captured as DWORD')
        if name == 'GetSystemDirectoryW':
            size = 2 * (result + 1) if 0 < result < arguments[0] else 0
            if type(effects) is not bytes or len(effects) != size or size and effects[-2:] != b'\0\0':
                raise InputError('system directory effects require only the successful terminated UTF16 prefix')
        if name in ('GetSystemInfo', 'CallNtPowerInformation', 'EnumDisplaySettingsW'):
            capacity, ranges = {'GetSystemInfo': (48, ((32, 36),)),
                'CallNtPowerInformation': (32, ((1, 4),)),
                'EnumDisplaySettingsW': (220, ((168, 188),))}[name]
            success = name == 'GetSystemInfo' or (result == 0 if name == 'CallNtPowerInformation' else bool(result))
            if success:
                expected_known = (_display_mask(arguments[2][1]) if name == 'EnumDisplaySettingsW' else
                    _sparse(bytes(capacity), ranges)[1])
                if (type(effects) is not tuple or len(effects) != 1 or type(effects[0]) is not tuple or
                        len(effects[0]) != 2 or type(effects[0][0]) is not bytes or len(effects[0][0]) != capacity or
                        type(effects[0][1]) is not bytes or effects[0][1] != expected_known):
                    raise InputError('native cold query requires its exact source-used sparse output: ' + name)
            elif type(effects) is not bytes or effects:
                raise InputError('failed native cold query has no valid output: ' + name)
        elif name == 'GlobalMemoryStatusEx':
            if type(effects) is not bytes or len(effects) != (64 if result else 0):
                raise InputError('native memory status requires its successful full structure or no failure output')
        elif name == 'GetSystemMetrics' and (type(effects) is not bytes or effects):
            raise InputError('native system metric has no output buffer')
        if name == 'GlobalMemoryStatusEx' and result == 0:
            self._memory_failure_error = error
        if name == 'RegOpenKeyExA' and result == 0:
            pointer = self._pointer(effects)
            if pointer in self._keys or (self._protection_registry is not None and
                    self._protection_registry.handles('RegCloseKey', (pointer,))):
                raise InputError('native registry handle aliases another source-owned handle')
            self._keys[pointer] = arguments[:2]
        elif name == 'RegCloseKey' and result == 0:
            del self._keys[arguments[0]]
        elif name == 'AllocateAndInitializeSid' and result:
            self._sids.add(self._pointer(effects))
        elif name == 'FreeSid' and result == 0:
            self._sids.remove(arguments[0])
        elif name == 'PowerGetActiveScheme' and result == 0:
            if not isinstance(effects, tuple) or len(effects) != 2:
                raise InputError('native active power scheme requires its GUID foreign image')
            pointer = self._pointer((effects[0],))
            if (not isinstance(effects[1], tuple) or len(effects[1]) != 1 or
                    not isinstance(effects[1][0], tuple) or len(effects[1][0]) != 2 or
                    effects[1][0][0] != pointer or not isinstance(effects[1][0][1], bytes) or len(effects[1][0][1]) != 16):
                raise InputError('native active power scheme requires exactly its owned GUID16')
            for region in runtime.memory._region_snapshot():
                if pointer < region.address + len(region.data) and region.address < pointer + 16:
                    raise PrimarySemanticUnavailable('native power GUID overlaps existing source memory')
            self._power.add(pointer)
        elif name == 'LocalFree' and result == 0:
            self._power.remove(arguments[0])
        elif name == 'GetSystemFirmwareTable' and not arguments[2]:
            if result > _LIMIT:
                raise PrimarySemanticUnavailable('native SMBIOS table exceeds its supported finite size')
            self._firmware_size = result
        if name in _WLAN_LOADER or name == 'GetSystemDirectoryW':
            if name in _WLAN_LOADER and (type(effects) is not bytes or effects):
                raise InputError('WLAN loader has no output buffer effects')
            self.records.append({'api': name, 'status': 'observed', 'success': bool(result), 'error': error})
            return result, effects
        self.records.append({'api': name, 'status': 'observed', 'result': None if name == 'GetTickCount64' else result if name not in ('FreeSid', 'LocalFree') else int(bool(result)), 'error': error,
            'effect_sha256': hashlib.sha256(repr(self._summary(effects)).encode()).hexdigest()})
        return result, effects

    @staticmethod
    def _pointer(effects):
        if not isinstance(effects, tuple) or len(effects) != 1 or not isinstance(effects[0], bytes) or len(effects[0]) != 8:
            raise InputError('native resource requires its exact pointer-width output')
        pointer = int.from_bytes(effects[0], 'little')
        if not 0 < pointer <= _MASK - 16:
            raise InputError('native resource returned an invalid pointer')
        return pointer

    @staticmethod
    def _summary(effects):
        if isinstance(effects, bytes):
            return len(effects), hashlib.sha256(effects).hexdigest()
        if isinstance(effects, tuple):
            return tuple(WindowsSystemRecordObservations._summary(value) for value in effects)
        return 'opaque'

    def close(self):
        if self._closed:
            return
        self._check_owner()
        if self._protection_registry is not None:
            self._protection_registry.close()
        if self._backend is not None:
            self._backend.close()
        self._closed = True

    def snapshot(self):
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('system record snapshot requires its owner process and thread')
        return {'closed': self._closed, 'source_registry_handles': len(self._keys), 'source_SIDs': len(self._sids),
            'protection_registry': None if self._protection_registry is None else self._protection_registry.snapshot(),
            'source_power_allocations': len(self._power), 'records': tuple(self.records),
            'backend': self._backend.snapshot() if self._backend is not None and hasattr(self._backend, 'snapshot') else None,
            'host_cleanup': () if self._backend is None else tuple(self._backend.cleanup_records)}
