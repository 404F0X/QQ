from dataclasses import dataclass, field

from .primary_qimei_extras import produce_request_extras
from .primary_qimei_observations import QimeiApiReply
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer, _signed
from .primary_qimei_storage import StorageBuffer


ADVERTISING_KEY = b'Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo'
EDGE_PROFILES_KEY = b'SOFTWARE\\Microsoft\\Edge\\Profiles'
HKCU = 0xFFFFFFFF80000001


def _cstring(buffer, offset=0):
    result = bytearray()
    while offset < len(buffer.data):
        byte = buffer.read(offset, 1)[0]
        if byte == 0:
            return bytes(result)
        result.append(byte)
        offset += 1
    raise QimeiRequestBoundary('source C string exceeds known backing')


def _wide_cstring(buffer, offset=0):
    result = bytearray()
    while offset + 2 <= len(buffer.data):
        unit = buffer.read(offset, 2)
        if unit == b'\0\0':
            return bytes(result)
        result += unit
        offset += 2
    raise QimeiRequestBoundary('source wide C string exceeds known backing')


@dataclass(frozen=True)
class SourceText:
    accepted: bool
    value: bytes = field(repr=False)


class QimeiExtraSources:
    def __init__(self, observations):
        self.observations = observations

    def _api(self, name, args, outputs=None, *, width=32):
        reply = self.observations.read('qimei-api', name, *args)
        if not isinstance(reply, QimeiApiReply):
            raise QimeiRequestError('explicit raw extra-source API reply required')
        return reply.result, reply.apply({} if outputs is None else outputs, width=width)

    def registry_value(self, path, name, data):
        path, name = _bytes(path), _bytes(name)
        if not isinstance(data, StorageBuffer):
            raise QimeiRequestError('source registry buffer backing required')
        capacity = len(data.data)
        if capacity > 0x7FFFFFFF:
            raise QimeiRequestBoundary('source registry clear size exceeds known backing')
        handle = StorageBuffer(bytes(8))
        status, output = self._api('RegOpenKeyExA', (HKCU, path, 0, 0x101, handle), {'handle': handle})
        handle_value = int.from_bytes(output['handle'].read(), 'little')
        result = 1
        if status == 0:
            size = StorageBuffer(capacity.to_bytes(4, 'little'))
            status, output = self._api('RegQueryValueExA', (handle_value, name, 0, None, None, size), {'size': size})
            size = output['size']
            result = 2
            if status == 0:
                result = 3
                if _signed(int.from_bytes(size.read(), 'little'), 32) <= capacity:
                    data = StorageBuffer(bytes(capacity))
                    status, output = self._api('RegQueryValueExA', (handle_value, name, 0, None, data, size), {'data': data, 'size': size})
                    data = output['data']
                    result = 0 if status == 0 else 4
        if handle_value:
            self._api('RegCloseKey', (handle_value,))
        return result, data

    def registry_child(self, path, index, data):
        path = _bytes(path)
        if not isinstance(data, StorageBuffer):
            raise QimeiRequestError('source registry enumeration buffer backing required')
        capacity = len(data.data)
        if capacity > 0xFFFFFFFF:
            raise QimeiRequestBoundary('source registry enumeration capacity exceeds DWORD')
        handle = StorageBuffer(bytes(8))
        status, output = self._api('RegOpenKeyExA', (HKCU, path, 0, 0x108, handle), {'handle': handle})
        handle_value = int.from_bytes(output['handle'].read(), 'little')
        result = 1
        if status == 0:
            size = StorageBuffer(capacity.to_bytes(4, 'little'))
            status, output = self._api('RegEnumKeyExA', (handle_value, _integer(index) & 0xFFFFFFFF, data, size, 0, None, None, None),
                                       {'data': data, 'size': size})
            data = output['data']
            result = 0 if status == 0 else 2
        if handle_value:
            self._api('RegCloseKey', (handle_value,))
        return result, data

    def advertising_id(self, initial=b''):
        value = _bytes(initial)
        status, data = self.registry_value(ADVERTISING_KEY, b'id', StorageBuffer(bytes(260)))
        if status == 0:
            value = _cstring(data)
        return SourceText(bool(value), value)

    def edge_id(self, initial=b''):
        value = _bytes(initial)
        identifiers, index = [], 0
        while True:
            status, child = self.registry_child(EDGE_PROFILES_KEY, index, StorageBuffer(bytes(260)))
            if status != 0:
                break
            path = EDGE_PROFILES_KEY + b'\\' + _cstring(child)
            status, data = self.registry_value(path, b'MUID', StorageBuffer(bytes(260)))
            if status == 0 and data.read(0, 1) != b'\0':
                identifiers.append(_cstring(data))
            index = (index + 1) & 0xFFFFFFFF
            if index == 0:
                raise QimeiRequestBoundary('source registry enumeration wraps its DWORD index')
        if identifiers:
            value = b'#'.join(identifiers)
        return SourceText(bool(value), value)

    def wide_to_ansi(self, value):
        value = _bytes(value)
        if len(value) % 2:
            raise QimeiRequestBoundary('incomplete source UTF16 unit')
        wide = _wide_cstring(StorageBuffer(value + b'\0\0')) + b'\0\0'
        count, unused = self._api('WideCharToMultiByte', (0, 0, wide, -1, None, 0, None, None))
        allocation = _signed(count + 1, 32)
        if allocation <= 0 or allocation > 1 << 20:
            raise QimeiRequestBoundary('source ANSI allocation length leaves known domain')
        data = StorageBuffer(bytes(allocation))
        unused, output = self._api('WideCharToMultiByte', (0, 0, wide, -1, data, _signed(count, 32), None, None), {'data': data})
        return _cstring(output['data'])

    def gpu_name(self, initial=b''):
        value = _bytes(initial)
        data = StorageBuffer.unknown(0x348).write(0, (0x348).to_bytes(4, 'little'))
        status, output = self._api('EnumDisplayDevicesW', (None, 0, data, 0), {'data': data})
        if status == 0:
            return SourceText(False, value)
        wide = _wide_cstring(output['data'], 0x44)
        value = self.wide_to_ansi(wide)
        return SourceText(bool(value), value)

    def _pointer(self, pointer, length=None):
        if pointer == 0:
            raise QimeiRequestBoundary('source consumed a NULL version resource pointer')
        reader = getattr(self.observations, 'read_memory', None)
        if not callable(reader):
            raise QimeiRequestBoundary('raw version resource pointer backing required')
        data = reader(pointer, length)
        if not isinstance(data, StorageBuffer):
            raise QimeiRequestError('explicit version pointer buffer required')
        return data

    def version_string(self, path, key=b'FileVersion'):
        path, key = _bytes(path).split(b'\0', 1)[0], _bytes(key).split(b'\0', 1)[0]
        count, unused = self._api('GetFileVersionInfoSizeA', (path, None))
        if _signed(count, 32) <= 0:
            return b''
        if count > 1 << 20:
            raise QimeiRequestBoundary('version resource allocation exceeds bounded backing')
        data = StorageBuffer.unknown(count)
        value = b''
        try:
            status, output = self._api('GetFileVersionInfoA', (path, 0, count, data), {'data': data})
            data = output['data']
            if status:
                pointer, length = StorageBuffer(bytes(8)), StorageBuffer(bytes(4))
                status, output = self._api('VerQueryValueA', (data, b'\\VarFileInfo\\Translation', pointer, length), {'data': data, 'pointer': pointer, 'length': length})
                data = output['data']
                if status:
                    address = int.from_bytes(output['pointer'].read(), 'little')
                    word = int.from_bytes(self._pointer(address, 4).read(0, 4), 'little')
                    rotated = ((word << 16) | (word >> 16)) & 0xFFFFFFFF
                    query = b'\\StringFileInfo\\' + ('%08x' % rotated).encode('ascii') + b'\\' + key
                    pointer, length = StorageBuffer(bytes(8)), StorageBuffer(bytes(4))
                    unused, output = self._api('VerQueryValueA', (data, query, pointer, length), {'data': data, 'pointer': pointer, 'length': length})
                    address = int.from_bytes(output['pointer'].read(), 'little')
                    if address:
                        value = _cstring(self._pointer(address))
        finally:
            release = getattr(self.observations, 'release_version_buffer', None)
            if callable(release):
                release()
        return value

    def module_version(self):
        module, unused = self._api('GetModuleHandleA', (b'qimei.dll',), width=64)
        if not module:
            return b''
        return self.module_handle_version(module)

    def module_handle_version(self, module):
        module = _integer(module) & 0xFFFFFFFFFFFFFFFF
        data = StorageBuffer(bytes(260))
        count, output = self._api('GetModuleFileNameA', (module, data, 260), {'data': data})
        if not count:
            return b''
        path = _cstring(output['data'])
        if not path:
            return b''
        return self.version_string(path)

    def populate(self, request, settings, *, settings_dependencies=None):
        def accepted(producer):
            result = producer()
            return result.value if result.accepted else b''
        return produce_request_extras(request, settings, module_version=self.module_version,
                                      advid=lambda: accepted(self.advertising_id), edgeid=lambda: accepted(self.edge_id),
                                      gpudn=lambda: accepted(self.gpu_name), settings_dependencies=settings_dependencies)
