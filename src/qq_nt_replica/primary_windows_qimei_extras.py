import ctypes
import os
from threading import get_ident

from .primary_qimei_extra_sources import ADVERTISING_KEY, EDGE_PROFILES_KEY, HKCU
from .primary_qimei_observations import QimeiApiReply
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError
from .primary_qimei_storage import StorageBuffer


class WindowsQimeiExtraObservations:
    def __init__(self, api=None):
        if ctypes.sizeof(ctypes.c_void_p) != 8 or (api is None and os.name != 'nt'):
            raise QimeiRequestError('source extra API backend requires Windows x64')
        self._thread = get_ident()
        self._closed = False
        self._handles = {}
        self._version = None
        self._calls = {}
        if api is None:
            groups = {name: ctypes.WinDLL(name, use_last_error=True) for name in ('kernel32', 'advapi32', 'user32', 'version')}
            names = {'RegOpenKeyExA': 'advapi32', 'RegQueryValueExA': 'advapi32', 'RegEnumKeyExA': 'advapi32', 'RegCloseKey': 'advapi32',
                     'GetModuleHandleA': 'kernel32', 'GetModuleFileNameA': 'kernel32', 'WideCharToMultiByte': 'kernel32',
                     'EnumDisplayDevicesW': 'user32', 'GetFileVersionInfoSizeA': 'version', 'GetFileVersionInfoA': 'version', 'VerQueryValueA': 'version'}
            self._api = {name: getattr(groups[group], name) for name, group in names.items()}
        else:
            names = ('RegOpenKeyExA', 'RegQueryValueExA', 'RegEnumKeyExA', 'RegCloseKey', 'GetModuleHandleA', 'GetModuleFileNameA',
                     'WideCharToMultiByte', 'EnumDisplayDevicesW', 'GetFileVersionInfoSizeA', 'GetFileVersionInfoA', 'VerQueryValueA')
            self._api = {name: getattr(api, name) for name in names}
        pointer, dword, integer = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        signatures = {
            'RegOpenKeyExA': (integer, (pointer, ctypes.c_char_p, dword, dword, pointer)),
            'RegQueryValueExA': (integer, (pointer, ctypes.c_char_p, pointer, pointer, pointer, pointer)),
            'RegEnumKeyExA': (integer, (pointer, dword, pointer, pointer, pointer, pointer, pointer, pointer)),
            'RegCloseKey': (integer, (pointer,)), 'GetModuleHandleA': (pointer, (ctypes.c_char_p,)),
            'GetModuleFileNameA': (dword, (pointer, pointer, dword)),
            'WideCharToMultiByte': (integer, (dword, dword, pointer, integer, pointer, integer, pointer, pointer)),
            'EnumDisplayDevicesW': (integer, (pointer, dword, pointer, dword)),
            'GetFileVersionInfoSizeA': (dword, (ctypes.c_char_p, pointer)),
            'GetFileVersionInfoA': (integer, (ctypes.c_char_p, dword, dword, pointer)),
            'VerQueryValueA': (integer, (pointer, ctypes.c_char_p, pointer, pointer)),
        }
        for name, (result, arguments) in signatures.items():
            self._api[name].restype = result
            self._api[name].argtypes = arguments

    def _check(self):
        if self._closed or self._thread != get_ident():
            raise QimeiRequestError('extra API backend is closed or used from another thread')

    def _buffer(self, value):
        if not isinstance(value, StorageBuffer) or len(value.data) > 1 << 20:
            raise QimeiRequestBoundary('extra API buffer leaves bounded backing')
        result = (ctypes.c_ubyte * len(value.data))()
        for index, byte in enumerate(value.data):
            if value.known[index]:
                result[index] = byte
        return result

    def _reply(self, result, outputs=None, *, width=32):
        return QimeiApiReply((result or 0) & ((1 << width) - 1),
                             tuple((name, 0, bytes(value)) for name, value in ({} if outputs is None else outputs).items()))

    def _known_handle(self, handle):
        if handle not in self._handles:
            raise QimeiRequestBoundary('registry handle does not belong to extra API backend')
        return self._handles[handle]

    def read(self, namespace, name, *args):
        self._check()
        if namespace != 'qimei-api' or name not in self._api:
            raise QimeiRequestBoundary('unsupported extra raw API')
        self._calls[name] = self._calls.get(name, 0) + 1
        function = self._api[name]
        if name == 'RegOpenKeyExA':
            root, path, reserved, access, target = args
            allowed = path == ADVERTISING_KEY or path == EDGE_PROFILES_KEY or path.startswith(EDGE_PROFILES_KEY + b'\\')
            if root != HKCU or not allowed or reserved != 0 or access not in (0x101, 0x108) or len(target.data) != 8:
                raise QimeiRequestBoundary('registry open leaves source read-only extra paths')
            data = self._buffer(target)
            result = function(root, path, reserved, access, data)
            handle = int.from_bytes(bytes(data), 'little')
            if handle:
                self._handles[handle] = path
            return self._reply(result, {'handle': data})
        if name == 'RegCloseKey':
            handle, = args
            self._known_handle(handle)
            result = function(handle)
            if result == 0:
                del self._handles[handle]
            return self._reply(result)
        if name == 'RegQueryValueExA':
            handle, key, reserved, type_pointer, target, size = args
            path = self._known_handle(handle)
            if reserved != 0 or type_pointer is not None or key != (b'id' if path == ADVERTISING_KEY else b'MUID') or len(size.data) != 4:
                raise QimeiRequestBoundary('registry query leaves source String contract')
            size_buffer = self._buffer(size)
            data = None if target is None else self._buffer(target)
            if data is not None and int.from_bytes(size.read(), 'little') > len(target.data):
                raise QimeiRequestBoundary('registry API capacity exceeds actual allocation')
            result = function(handle, key, None, None, data, size_buffer)
            outputs = {'size': size_buffer}
            if data is not None:
                outputs['data'] = data
            return self._reply(result, outputs)
        if name == 'RegEnumKeyExA':
            handle, index, target, size, reserved, class_pointer, class_length, last_write = args
            if self._known_handle(handle) != EDGE_PROFILES_KEY or reserved != 0 or any(value is not None for value in (class_pointer, class_length, last_write)):
                raise QimeiRequestBoundary('registry enumeration leaves source subkey contract')
            if len(size.data) != 4 or int.from_bytes(size.read(), 'little') > len(target.data):
                raise QimeiRequestBoundary('registry enumeration capacity exceeds actual allocation')
            data, size_buffer = self._buffer(target), self._buffer(size)
            result = function(handle, index, data, size_buffer, None, None, None, None)
            return self._reply(result, {'data': data, 'size': size_buffer})
        if name == 'GetModuleHandleA':
            if args != (b'qimei.dll',):
                raise QimeiRequestBoundary('module query leaves source qimei.dll')
            return self._reply(function(*args), width=64)
        if name == 'GetModuleFileNameA':
            handle, target, count = args
            if count != 260 or len(target.data) != 260:
                raise QimeiRequestBoundary('source module path capacity mismatch')
            data = self._buffer(target)
            return self._reply(function(handle, data, count), {'data': data})
        if name == 'EnumDisplayDevicesW':
            device, index, target, flags = args
            if device is not None or index != 0 or flags != 0 or len(target.data) != 0x348 or target.read(0, 4) != (0x348).to_bytes(4, 'little'):
                raise QimeiRequestBoundary('display query leaves source first-device contract')
            data = self._buffer(target)
            return self._reply(function(None, index, data, flags), {'data': data})
        if name == 'WideCharToMultiByte':
            codepage, flags, wide, count, target, capacity, default, used_default = args
            if codepage != 0 or flags != 0 or count != -1 or default is not None or used_default is not None or not isinstance(wide, bytes) or len(wide) % 2:
                raise QimeiRequestBoundary('wide conversion leaves source CP_ACP contract')
            if (target is None and capacity != 0) or capacity < 0 or (target is not None and capacity > len(target.data)):
                raise QimeiRequestBoundary('ANSI conversion capacity exceeds backing')
            source = ctypes.create_string_buffer(wide)
            data = None if target is None else self._buffer(target)
            result = function(codepage, flags, source, count, data, capacity, None, None)
            return self._reply(result, {} if data is None else {'data': data})
        if name == 'GetFileVersionInfoSizeA':
            path, reserved = args
            if not isinstance(path, bytes) or reserved is not None:
                raise QimeiRequestBoundary('invalid source version size query')
            return self._reply(function(path, None))
        if name == 'GetFileVersionInfoA':
            path, reserved, count, target = args
            if not isinstance(path, bytes) or reserved != 0 or count != len(target.data):
                raise QimeiRequestBoundary('invalid source version data query')
            data = self._buffer(target)
            result = function(path, 0, count, data)
            self._version = data
            return self._reply(result, {'data': data})
        data, key, pointer, length = args
        if self._version is None or data.read() != bytes(self._version) or len(pointer.data) != 8 or len(length.data) != 4:
            raise QimeiRequestBoundary('version query does not match owned raw block')
        if key != b'\\VarFileInfo\\Translation' and not (key.startswith(b'\\StringFileInfo\\') and key.endswith(b'\\FileVersion')):
            raise QimeiRequestBoundary('version query leaves source translation/FileVersion contract')
        address, count = self._buffer(pointer), self._buffer(length)
        result = function(self._version, key, address, count)
        return self._reply(result, {'data': self._version, 'pointer': address, 'length': count})

    def read_memory(self, pointer, length=None):
        self._check()
        if self._version is None:
            raise QimeiRequestBoundary('no owned version resource block')
        offset = pointer - ctypes.addressof(self._version)
        size = len(self._version) - offset if length is None else length
        if offset < 0 or size < 0 or offset + size > len(self._version):
            raise QimeiRequestBoundary('version API returned pointer outside owned block')
        return StorageBuffer(bytes(self._version)[offset:offset + size])

    def release_version_buffer(self):
        self._check()
        self._version = None

    def metadata(self):
        self._check()
        return {'API_counts': dict(self._calls), 'registry_handles': len(self._handles), 'version_buffers': int(self._version is not None)}

    def close(self):
        if self._closed:
            return
        self._check()
        failures = 0
        for handle in tuple(self._handles):
            if self._api['RegCloseKey'](handle) == 0:
                del self._handles[handle]
            else:
                failures += 1
        self._version = None
        if failures:
            raise QimeiRequestBoundary('extra backend could not close all owned registry handles')
        self._closed = True
