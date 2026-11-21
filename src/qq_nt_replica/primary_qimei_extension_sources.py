import struct

from .primary_qimei_extra_sources import HKCU, QimeiExtraSources, _cstring
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer
from .primary_qimei_request_producer import RequestSourceReply
from .primary_qimei_storage import StorageBuffer
from .primary_qimei_system_sources import HKLM, WINDOWS_KEY, QimeiSystemSources


CRYPTOGRAPHY_KEY = b'SOFTWARE\\Microsoft\\Cryptography'
SQM_KEY = b'SOFTWARE\\Microsoft\\SQMClient'
EDGE_MACHINE_KEY = b'SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate'
EDGE_USER_KEY = b'Software\\Microsoft\\EdgeUpdate'
IDENTITY_VALUES = ((WINDOWS_KEY, b'ProductId'), (CRYPTOGRAPHY_KEY, b'MachineGuid'), (SQM_KEY, b'MachineId'))
EDGE_VALUES = (b'old-uid', b'uid', b'uid-create-time')
HARDWARE_CONFIG_KEY = b'SYSTEM\\HardwareConfig'
HARDWARE_CURRENT_KEY = HARDWARE_CONFIG_KEY + b'\\Current'
HARDWARE_VALUES = (b'BIOSVendor', b'BIOSVersion', b'BIOSReleaseDate')
STAT_ROOTS = (b'C:\\Windows\\SysWOW64', b'C:\\Windows\\System32', b'C:\\Program Files')


def brace_identity(value):
    value = _bytes(value).split(b'\0', 1)[0]
    left, right = value.find(b'{'), value.find(b'}')
    if left < 0 or right < 0:
        return value
    start = left + 1
    count = (right - left - 1) & 0xFFFFFFFFFFFFFFFF
    return value[start:start + min(count, len(value) - start)]


class QimeiExtensionSources:
    def __init__(self, observations):
        self.observations = observations

    _api = QimeiExtraSources._api

    def _identity(self, index, initial):
        initial = _bytes(initial)
        path, name = IDENTITY_VALUES[index]
        status, data = QimeiSystemSources(self.observations).registry_value(path, name, StorageBuffer(bytes(260)))
        value = initial
        if status == 0:
            value = _cstring(data)
            if index == 2:
                value = brace_identity(value)
        return RequestSourceReply(status, (value,))

    def extension_92f6c(self, initial=b''):
        return self._identity(0, initial)

    def extension_9335e(self, initial=b''):
        return self._identity(1, initial)

    def extension_93721(self, initial=b''):
        return self._identity(2, initial)

    def local_timestamp(self, seconds):
        seconds = _integer(seconds) & 0xFFFFFFFF
        data = StorageBuffer(b'\xff' * 36)
        status, output = self._api('_localtime64_s', (data, seconds), {'data': data})
        if status != 0:
            raise QimeiRequestBoundary('source80588 failed localtime CRT domain is unverified')
        second, minute, hour, day, month, year, weekday, yearday, daylight = struct.unpack('<9i', output['data'].read())
        if not (0 <= second <= 60 and 0 <= minute <= 59 and 0 <= hour <= 23 and 1 <= day <= 31 and 0 <= month <= 11
                and 0 <= year <= 8099 and 0 <= weekday <= 6 and 0 <= yearday <= 365 and daylight >= -1):
            raise QimeiRequestBoundary('source80588 strftime calendar leaves verified CRT domain')
        return ('%04d-%02d-%02d %02d:%02d:%02d' % (year + 1900, month + 1, day, hour, minute, second)).encode('ascii')

    def extension_95cfb(self, initial=(b'', b'', b'')):
        if type(initial) is not tuple or len(initial) != 3:
            raise QimeiRequestError('source Edge identity requires three Strings')
        values = [_bytes(value) for value in initial]
        registry = QimeiSystemSources(self.observations)
        for index, name in enumerate(EDGE_VALUES):
            capacity = 4 if index == 2 else 260
            data = StorageBuffer(bytes(capacity))
            status, data = registry.registry_value(EDGE_MACHINE_KEY, name, data, root=HKLM)
            if status != 0:
                status, data = registry.registry_value(EDGE_USER_KEY, name, data, root=HKCU)
            if status == 0:
                values[index] = self.local_timestamp(int.from_bytes(data.read(), 'little')) if index == 2 else brace_identity(_cstring(data))
        return RequestSourceReply(int(any(values)), tuple(values))

    def _firmware_strings(self, initial):
        values = list(initial)
        module, unused = self._api('LoadLibraryA', (b'kernel32.dll',), width=64)
        procedure = 0
        try:
            if module:
                procedure, unused = self._api('GetProcAddress', (module, b'GetSystemFirmwareTable'), width=64)
            if not procedure:
                return 4, values
            size, unused = self._api('GetSystemFirmwareTable', (procedure, 0x52534D42, 0, None, 0))
            if size == 0:
                return 1, values
            if size < 8 or size > 1 << 20:
                raise QimeiRequestBoundary('source SMBIOS size leaves bounded allocation')
            data = StorageBuffer.unknown(size)
            count, output = self._api('GetSystemFirmwareTable', (procedure, 0x52534D42, 0, data, size), {'data': data})
            if count == 0:
                return 2, values
            data = output['data']
            if int.from_bytes(data.read(4, 4), 'little') != size - 8:
                return 3, values
            version = int.from_bytes(data.read(1, 2), 'big', signed=True)
            position, bios_seen = 8, False
            while position < size:
                kind, length = data.read(position, 2)
                if length < 4 or position + length > size:
                    raise QimeiRequestBoundary('source SMBIOS header leaves bounded record')
                strings, cursor = [], position + length
                while True:
                    if cursor + 1 >= size:
                        raise QimeiRequestBoundary('source SMBIOS strings lack double terminator')
                    if data.read(cursor, 2) == b'\0\0':
                        end = cursor + 2
                        break
                    value = bytearray()
                    while cursor < size and data.read(cursor, 1) != b'\0':
                        byte = data.read(cursor, 1)[0]
                        value.append(byte if 0x20 <= byte <= 0x7E else ord('.'))
                        cursor += 1
                    if cursor >= size:
                        raise QimeiRequestBoundary('source SMBIOS String lacks bounded terminator')
                    strings.append(bytes(value))
                    if cursor + 1 < size and data.read(cursor + 1, 1) == b'\0':
                        end = cursor + 2
                        break
                    cursor += 1

                def field(offset):
                    if offset >= length:
                        raise QimeiRequestBoundary('source SMBIOS indexed field leaves record')
                    index = data.read(position + offset, 1)[0]
                    return b'Not Specified' if index == 0 else strings[index - 1] if index <= len(strings) else b'BAD_INDEX'

                if kind == 0 and not bios_seen:
                    values[:3] = [field(offset) for offset in (4, 5, 8)]
                    bios_seen = True
                if kind == 1:
                    values[3], values[5] = field(7), field(0x1A)
                    if length < 24:
                        raise QimeiRequestBoundary('source SMBIOS UUID leaves record')
                    uuid = data.read(position + 8, 16)
                    if uuid not in (bytes(16), b'\xff' * 16):
                        order = (3, 2, 1, 0, 5, 4, 7, 6, *range(8, 16)) if version >= 0x206 else tuple(range(16))
                        text = bytes(uuid[index] for index in order).hex().upper().encode('ascii')
                        values[4] = (b'' if version >= 0x206 else b'-') + b'-'.join((text[:8], text[8:12], text[12:16], text[16:20], text[20:]))
                    else:
                        values[4] = b''
                    return 0, values
                position = end
            return 0, values
        finally:
            if module:
                self._api('FreeLibrary', (module,))

    def extension_93ade(self, initial=(b'', b'', b'', b'', b'')):
        if type(initial) is not tuple or len(initial) != 5:
            raise QimeiRequestError('source firmware identity requires five Strings')
        initial = tuple(_bytes(value) for value in initial)
        reply = self.firmware_strings(initial + (b'',))
        status, values = reply.result, list(reply.values)
        if status != 0:
            registry = QimeiSystemSources(self.observations)
            status, data = registry.registry_value(HARDWARE_CONFIG_KEY, b'LastConfig', StorageBuffer(bytes(260)))
            if status != 0:
                return RequestSourceReply(status, tuple(values[:5]))
            values[4] = brace_identity(_cstring(data))
            for index, name in enumerate(HARDWARE_VALUES):
                unused, data = registry.registry_value(HARDWARE_CURRENT_KEY, name, StorageBuffer(bytes(260)))
                values[index] = _cstring(data)
        return RequestSourceReply(status, tuple(values[:5]))

    def firmware_strings(self, initial=(b'', b'', b'', b'', b'', b'')):
        if type(initial) is not tuple or len(initial) != 6:
            raise QimeiRequestError('source SMBIOS getter requires six Strings')
        status, values = self._firmware_strings(tuple(_bytes(value) for value in initial))
        return RequestSourceReply(status, tuple(values))

    def extension_7ad98(self, initial=b''):
        value = bytearray(_bytes(initial))
        handle, unused = self._api('OpenEventLogA', (None, b'System'), width=64)
        if not handle:
            return RequestSourceReply(0, (bytes(value),))
        data, count = StorageBuffer(bytes(4096)), 0
        try:
            for batch in range(1024):
                read, needed = StorageBuffer(bytes(4)), StorageBuffer(bytes(4))
                status, output = self._api('ReadEventLogA', (handle, 5, 0, data, 4096, read, needed),
                                           {'data': data, 'read': read, 'needed': needed})
                if not status:
                    break
                data = output['data']
                size = int.from_bytes(output['read'].read(), 'little')
                if not 0 < size <= 4096:
                    raise QimeiRequestBoundary('source event read has no bounded progress')
                position = 0
                while position < size:
                    if position + 24 > size:
                        raise QimeiRequestBoundary('source event record header leaves batch')
                    length = int.from_bytes(data.read(position, 4), 'little')
                    if length < 24 or position + length > size:
                        raise QimeiRequestBoundary('source event Length leaves bounded batch')
                    event_id = int.from_bytes(data.read(position + 0x14, 2), 'little', signed=True)
                    seconds = int.from_bytes(data.read(position + 0x0C, 4), 'little')
                    part = str(event_id).encode('ascii') + b',' + self.local_timestamp(seconds) + b';'
                    if len(part) >= 64 or len(value) + len(part) > 1 << 20:
                        raise QimeiRequestBoundary('source event formatting leaves bounded String')
                    value += part
                    count += 1
                    if count == 6:
                        return RequestSourceReply(int(bool(value)), (bytes(value),))
                    position += length
            else:
                raise QimeiRequestBoundary('source event batches exceed bounded progress domain')
            return RequestSourceReply(int(bool(value)), (bytes(value),))
        finally:
            self._api('CloseEventLog', (handle,))

    def extension_8a29b(self):
        if not hasattr(self, '_extension_wow64'):
            self._extension_wow64 = QimeiSystemSources(self.observations)
        selected = STAT_ROOTS[0 if self._extension_wow64.wow64() else 1]
        paths = STAT_ROOTS + tuple(selected + b'\\' + name for name in (b'kernel32.dll', b'user32.dll', b'ntdll.dll'))
        result = bytearray()
        for index, path in enumerate(paths, 1):
            data = StorageBuffer.unknown(56)
            status, output = self._api('_stat64', (path, data), {'data': data})
            value = int.from_bytes(output['data'].read(0x30, 8), 'little') if status == 0 else 0
            result += b'k' + str(index).encode('ascii') + b':' + str(value).encode('ascii') + b';'
        return bytes(result)
