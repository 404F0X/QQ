from dataclasses import dataclass, field
import struct
from threading import RLock

from .primary_qimei_extra_sources import QimeiExtraSources, SourceText, _cstring, _wide_cstring
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer, _signed
from .primary_qimei_storage import StorageBuffer


HKLM = 0xFFFFFFFF80000002
PROCESSOR_KEY = b'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'
PROCESSOR_VALUES = (b'PROCESSOR_ARCHITECTURE', b'PROCESSOR_IDENTIFIER', b'PROCESSOR_LEVEL', b'PROCESSOR_REVISION')
WINDOWS_KEY = b'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
BIOS_KEY = b'HARDWARE\\DESCRIPTION\\System\\BIOS'
BIOS_VALUES = (b'SystemManufacturer', b'SystemProductName', b'BIOSVendor', b'BIOSVersion', b'BIOSReleaseDate')
KEYBOARD_KEY = b'SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\'
COMPATIBILITY_KEY = WINDOWS_KEY + b'\\AppCompatFlags\\Layers'
BOOT_MANAGER = b'{9dea862c-5cdd-4e70-acc1-f32b344d4795}'


@dataclass(frozen=True)
class SourceStrings:
    accepted: bool
    values: tuple[bytes, ...] = field(repr=False)


@dataclass(frozen=True)
class SourceNumbers:
    accepted: bool
    values: tuple[int, ...] = field(repr=False)


class QimeiSystemSources:
    def __init__(self, observations):
        self.observations = observations
        self._wow64 = 0
        self._wow64_initialized = False
        self._lock = RLock()

    _api = QimeiExtraSources._api
    wide_to_ansi = QimeiExtraSources.wide_to_ansi

    def registry_value(self, path, name, data, *, root=HKLM):
        path, name = _bytes(path), _bytes(name)
        if not isinstance(data, StorageBuffer):
            raise QimeiRequestError('source registry buffer backing required')
        capacity = len(data.data)
        if capacity > 0x7FFFFFFF:
            raise QimeiRequestBoundary('source registry clear exceeds bounded backing')
        handle = StorageBuffer(bytes(8))
        status, output = self._api('RegOpenKeyExA', (root, path, 0, 0x101, handle), {'handle': handle})
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

    def wow64(self):
        with self._lock:
            if not self._wow64_initialized:
                process, unused = self._api('GetCurrentProcess', (), width=64)
                module, unused = self._api('GetModuleHandleA', (b'kernel32',), width=64)
                procedure, unused = self._api('GetProcAddress', (module, b'IsWow64Process'), width=64)
                if procedure:
                    value = StorageBuffer(self._wow64.to_bytes(4, 'little'))
                    unused, output = self._api('IsWow64Process', (procedure, process, value), {'value': value})
                    self._wow64 = int.from_bytes(output['value'].read(), 'little')
                self._wow64_initialized = True
            return self._wow64

    def is_admin(self):
        result, unused = self._api('IsUserAnAdmin', ())
        return result

    def machine_names(self, initial=(b'', b'')):
        values = [_bytes(value) for value in initial]
        if len(values) != 2:
            raise QimeiRequestError('source machine names require two Strings')
        for index, name in enumerate(('GetComputerNameA', 'GetUserNameA')):
            data, size = StorageBuffer(bytes(260)), StorageBuffer((260).to_bytes(4, 'little'))
            status, output = self._api(name, (data, size), {'data': data, 'size': size})
            if status:
                values[index] = _cstring(output['data'])
        return SourceStrings(any(values), tuple(values))

    def _registry_strings(self, path, names, initial):
        values = [_bytes(value) for value in initial]
        if len(values) != len(names):
            raise QimeiRequestError('source registry String group has wrong arity')
        for index, name in enumerate(names):
            status, data = self.registry_value(path, name, StorageBuffer(bytes(260)))
            if status == 0:
                values[index] = _cstring(data)
        return SourceStrings(any(values), tuple(values))

    def processor_info(self, initial=(b'', b'', b'', b'')):
        return self._registry_strings(PROCESSOR_KEY, PROCESSOR_VALUES, initial)

    def bios_info(self, initial=(b'', b'', b'', b'', b'')):
        return self._registry_strings(BIOS_KEY, BIOS_VALUES, initial)

    def install_date(self, seconds):
        seconds = _integer(seconds) & 0xFFFFFFFF
        data = StorageBuffer.unknown(36)
        unused, output = self._api('_localtime64_s', (data, seconds), {'data': data})
        second, minute, hour, day, month, year, weekday, yearday, daylight = struct.unpack('<9i', output['data'].read())
        if not (0 <= second <= 60 and 0 <= minute <= 59 and 0 <= hour <= 23 and 1 <= day <= 31 and 0 <= month <= 11
                and 0 <= year <= 8099 and 0 <= weekday <= 6 and 0 <= yearday <= 365 and daylight >= -1):
            raise QimeiRequestBoundary('source strftime calendar leaves verified domain')
        return ('%04d-%02d-%02d %02d:%02d:%02d' % (year + 1900, month + 1, day, hour, minute, second)).encode('ascii')

    def windows_info(self, initial=(b'', b'', b'')):
        values = [_bytes(value) for value in initial]
        if len(values) != 3:
            raise QimeiRequestError('source Windows group requires three Strings')
        status, data = self.registry_value(WINDOWS_KEY, b'ProductName', StorageBuffer(bytes(260)))
        if status == 0:
            values[0] = _cstring(data)
        numbers = []
        for name in (b'CurrentMajorVersionNumber', b'CurrentMinorVersionNumber'):
            unused, data = self.registry_value(WINDOWS_KEY, name, StorageBuffer(bytes(4)))
            numbers.append(_signed(int.from_bytes(data.read(), 'little'), 32))
        unused, data = self.registry_value(WINDOWS_KEY, b'CurrentBuild', StorageBuffer(bytes(260)))
        values[1] = str(numbers[0]).encode('ascii') + b'.' + str(numbers[1]).encode('ascii') + b'.' + _cstring(data)
        if len(values[1]) >= 260:
            raise QimeiRequestBoundary('source Windows version formatting exceeds bounded buffer')
        status, data = self.registry_value(WINDOWS_KEY, b'InstallDate', StorageBuffer(bytes(4)))
        if status == 0:
            values[2] = self.install_date(int.from_bytes(data.read(), 'little'))
        return SourceStrings(any(values), tuple(values))

    def boot_descriptions(self):
        def path(identifier, element, suffix=b''):
            value = b'BCD00000000\\Objects\\' + identifier + suffix + b'\\Elements\\' + str(element).encode('ascii')
            if len(value) >= 260:
                raise QimeiRequestBoundary('source BCD formatting exceeds bounded buffer')
            return value
        data = StorageBuffer(bytes(260))
        status, data = self.registry_value(path(BOOT_MANAGER, 0xB71B04), b'Element', data)
        if status != 0 or _cstring(data) != b'Windows Boot Manager':
            return b''
        status, data = self.registry_value(path(BOOT_MANAGER, 0x16E3601), b'Element', StorageBuffer(bytes(260)))
        if status != 0:
            return b''
        identifiers = _cstring(data).split(b'}')
        if identifiers and identifiers[-1] == b'':
            identifiers.pop()
        value = bytearray()
        for identifier in identifiers:
            if not identifier:
                continue
            status, data = self.registry_value(path(identifier, 0xB71B04, b'}'), b'Element', StorageBuffer(bytes(260)))
            if status == 0:
                value += _cstring(data) + b';'
        return bytes(value)

    def keyboard_layouts(self, initial=b''):
        value = _bytes(initial)
        count, unused = self._api('GetKeyboardLayoutList', (0, None))
        count = _signed(count, 32)
        if count <= 0:
            return SourceText(False, value)
        if count > (1 << 20) // 8:
            raise QimeiRequestBoundary('keyboard layout allocation exceeds bounded backing')
        heap, unused = self._api('GetProcessHeap', (), width=64)
        pointer, unused = self._api('HeapAlloc', (heap, 8, count * 8), width=64)
        if not pointer:
            return SourceText(False, value)
        data = StorageBuffer(bytes(count * 8))
        try:
            returned, output = self._api('GetKeyboardLayoutList', (count, pointer, data), {'data': data})
            returned = _signed(returned, 32)
            for index in range(max(returned, 0)):
                language = int.from_bytes(output['data'].read(index * 8, 2), 'little')
                path = KEYBOARD_KEY + ('%08x' % language).encode('ascii')
                status, name = self.registry_value(path, b'Layout Text', StorageBuffer(bytes(260)))
                if status == 0:
                    value += _cstring(name) + b';'
        finally:
            heap, unused = self._api('GetProcessHeap', (), width=64)
            self._api('HeapFree', (heap, 0, pointer))
        return SourceText(bool(value), value)

    def timezone_name(self, initial=b''):
        value = _bytes(initial)
        data = StorageBuffer.unknown(172)
        status, output = self._api('GetTimeZoneInformation', (data,), {'data': data})
        if status in (0, 1, 2):
            offset = 4 if status in (0, 1) else 88
            value = self.wide_to_ansi(_wide_cstring(output['data'], offset))
        return SourceText(bool(value), value)

    def memory_info(self, initial=(0, 0)):
        values = tuple(_integer(value) & 0xFFFFFFFFFFFFFFFF for value in initial)
        if len(values) != 2:
            raise QimeiRequestError('source memory group requires two QWORDs')
        data = StorageBuffer(bytes(64)).write(0, (64).to_bytes(4, 'little'))
        status, output = self._api('GlobalMemoryStatusEx', (data,), {'data': data})
        if status:
            values = (int.from_bytes(output['data'].read(8, 8), 'little'), int.from_bytes(output['data'].read(40, 8), 'little'))
        return SourceNumbers(bool(status & 0xFFFFFFFF), values)

    def process_id(self):
        value, unused = self._api('GetCurrentProcessId', ())
        return value

    def executable_path(self, initial=b''):
        value = _bytes(initial)
        data = StorageBuffer(bytes(260))
        count, output = self._api('GetModuleFileNameA', (0, data, 260), {'data': data})
        if count:
            value = _cstring(output['data'])
        return SourceText(bool(value), value)

    def compatibility_flags(self, path, initial=b''):
        value = _bytes(initial)
        status, data = self.registry_value(COMPATIBILITY_KEY, _bytes(path).split(b'\0', 1)[0], StorageBuffer(bytes(260)), root=0xFFFFFFFF80000001)
        if status == 0:
            value = _cstring(data)
        return SourceText(bool(value), value)

    def request_version(self):
        return 2

    def memory_status(self):
        data=StorageBuffer(bytes(64)).write(0,(64).to_bytes(4,'little'))
        status,out=self._api('GlobalMemoryStatusEx',(data,),{'data':data})
        values=(0,)*7
        if status:
            d=out['data'];values=(int.from_bytes(d.read(4,4),'little'),)+tuple(int.from_bytes(d.read(o,8),'little') for o in (8,16,24,32,40,48))
        return SourceNumbers(bool(status),values)
    def cursor_position(self):
        data=StorageBuffer(bytes(8));status,out=self._api('GetCursorPos',(data,),{'data':data})
        return SourceNumbers(bool(status),tuple(int.from_bytes(out['data'].read(o,4),'little') for o in (0,4)) if status else (0,0))
    def os_classification(self):
        from .primary_windows_qimei_config import classify_version
        data=StorageBuffer(bytes(148)).write(0,(148).to_bytes(4,'little'))
        unused,out=self._api('GetVersionExA',(data,),{'data':data})
        major,minor,build=(int.from_bytes(out['data'].read(o,4),'little') for o in (4,8,12))
        if (major,minor)==(6,2):
            module,_=self._api('GetModuleHandleA',(b'ntdll.dll',),width=64)
            proc,_=self._api('GetProcAddress',(module,b'RtlGetNtVersionNumbers'),width=64)
            if proc:
                a,b,c=(StorageBuffer(v.to_bytes(4,'little')) for v in (major,minor,build))
                unused,out=self._api('RtlGetNtVersionNumbers',(proc,a,b,c),{'major':a,'minor':b,'build':c})
                major,minor,build=(int.from_bytes(out[k].read(),'little') for k in ('major','minor','build'));build&=0xFFFF
        return classify_version(major,minor,build)
    def architecture(self):
        from .primary_windows_qimei_config import architecture_class
        data=StorageBuffer(bytes(48));unused,out=self._api('GetNativeSystemInfo',(data,),{'data':data})
        return architecture_class(int.from_bytes(out['data'].read(0,2),'little'))
