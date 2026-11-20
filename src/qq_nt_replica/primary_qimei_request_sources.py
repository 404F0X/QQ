from dataclasses import dataclass, field

from .primary_qimei_extra_sources import QimeiExtraSources, _cstring, _wide_cstring
from .primary_qimei_extension_sources import QimeiExtensionSources
from .primary_qimei_records import StartupState, Store
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer, _signed
from .primary_qimei_request_producer import RequestSourceReply
from .primary_qimei_storage import NtStorageProbe, StorageBuffer


SETUP_LIBRARY = b'SETUPAPI.dll'
DISK_CLASS = bytes.fromhex('67e9364d25e3ce11bfc108002be10318')
COMPUTER_CLASS = bytes.fromhex('66e9364d25e3ce11bfc108002be10318')
DEVICE_PROPERTY = bytes.fromhex('2663da83a69788409453a1923f573b2965000000')
SETUP_EXPORTS = (b'SetupDiGetClassDevsW', b'SetupDiEnumDeviceInfo', b'SetupDiDestroyDeviceInfoList')


def mode0_record_payload(store):
    if not isinstance(store, Store) or store.mode != 0:
        raise QimeiRequestBoundary('mode0 source record store required')
    result = bytearray()
    with store._lock:
        for row in store.vector():
            capacity = _signed(_integer(row.capacity), 32)
            if capacity < 0 or capacity > 1 << 20 or len(result) + capacity > 1 << 20:
                raise QimeiRequestBoundary('source record resize exceeds bounded backing')
            value = _bytes(row.value)
            result += value[:capacity].ljust(capacity, b'\0')
    return bytes(result)


@dataclass
class QimeiMode0RecordWriter:
    write_payload: object = field(repr=False)

    def __call__(self, store):
        payload = mode0_record_payload(store)
        if not payload:
            return False
        if not callable(self.write_payload):
            raise QimeiRequestBoundary('complete source9EEF9 payload encryption/file/ACL writer required')
        result = _integer(self.write_payload(store.read_path(), payload)) & 0xFFFFFFFF
        return result == 0


class QimeiRequestSources:
    def __init__(self, observations, *, startup=None, write_main=None, storage_observations=None, adapter_sources=None, extension_observations=None):
        if startup is not None and not isinstance(startup, StartupState):
            raise QimeiRequestError('live source startup state required')
        self.observations, self.startup, self.write_main = observations, startup, write_main
        self.storage_observations = storage_observations
        self.adapter_sources = adapter_sources
        self.extension_sources = QimeiExtensionSources(observations if extension_observations is None else extension_observations)

    def primary_adapter(self):
        if self.adapter_sources is None:
            raise QimeiRequestBoundary('unimplemented source request producer: primary_adapter requires live adapter source')
        return self.adapter_sources.primary_adapter()

    def extension_7f67a(self):
        if self.adapter_sources is None:
            raise QimeiRequestBoundary('unimplemented source request producer: extension_7f67a requires live adapter source')
        return self.adapter_sources.extension_7f67a()

    def extension_92f6c(self):
        return self.extension_sources.extension_92f6c()

    def extension_9335e(self):
        return self.extension_sources.extension_9335e()

    def extension_93721(self):
        return self.extension_sources.extension_93721()

    def extension_95cfb(self):
        return self.extension_sources.extension_95cfb()

    def extension_93ade(self):
        return self.extension_sources.extension_93ade()

    def extension_7ad98(self):
        return self.extension_sources.extension_7ad98()

    def extension_8a29b(self):
        return self.extension_sources.extension_8a29b()

    _api = QimeiExtraSources._api
    wide_to_ansi = QimeiExtraSources.wide_to_ansi

    def _cpuid(self, leaf):
        data = StorageBuffer.unknown(16)
        unused, output = self._api('CPUID', (leaf, 0, data), {'data': data})
        return tuple(int.from_bytes(output['data'].read(index, 4), 'little') for index in range(0, 16, 4))

    def extension_7b1cb(self):
        brand = bytearray()
        for leaf in range(0x80000002, 0x80000005):
            for value in self._cpuid(leaf):
                brand += value.to_bytes(4, 'little')
        first = bytes(brand).split(b'\0', 1)[0]
        if not brand[0]:
            first = b''
        eax, ebx, ecx, edx = self._cpuid(1)
        second = (edx.to_bytes(4, 'big') + eax.to_bytes(4, 'big')).hex().upper().encode('ascii')
        return RequestSourceReply(int(bool(first or second)), (first, second))

    def extension_898d4(self):
        mask, unused = self._api('GetLogicalDrives', ())
        total = 0
        for letter in range(ord('C'), ord('Z') + 1):
            if not mask & (1 << ((letter - 1) & 31)):
                continue
            path = bytes((letter, ord(':'), ord('\\')))
            kind, unused = self._api('GetDriveTypeA', (path,))
            if ((kind - 3) & 0xFFFFFFFF) >= 2:
                continue
            sectors, size, free, clusters = (StorageBuffer(bytes(4)) for index in range(4))
            status, output = self._api('GetDiskFreeSpaceA', (path, sectors, size, free, clusters),
                                      {'sectors': sectors, 'size': size, 'free': free, 'clusters': clusters})
            if status:
                values = [int.from_bytes(output[name].read(), 'little') for name in ('sectors', 'size', 'clusters')]
                total = (total + values[0] * values[1] * values[2]) & 0xFFFFFFFFFFFFFFFF
        return total

    def _load(self, name):
        module, unused = self._api('LoadLibraryA', (SETUP_LIBRARY,), width=64)
        procedure = 0
        if module:
            procedure, unused = self._api('GetProcAddress', (module, name), width=64)
        return module, procedure

    def _free(self, module):
        if module:
            self._api('FreeLibrary', (module,))

    def _disk_property(self, device_set, info):
        module, procedure = self._load(b'SetupDiGetDeviceRegistryPropertyW')
        try:
            if not procedure:
                return b''
            data = StorageBuffer(bytes(8192))
            status, output = self._api('SetupDiGetDeviceRegistryPropertyW', (procedure, device_set, info, 12, None, data, 8192, None),
                                      {'info': info, 'data': data})
            if not status:
                return b''
            return self.wide_to_ansi(_wide_cstring(output['data']))
        finally:
            self._free(module)

    def _computer_property(self, device_set, info):
        module, procedure = self._load(b'SetupDiGetDevicePropertyW')
        try:
            if not procedure:
                return b''
            data, kind, required = StorageBuffer(bytes(4096)), StorageBuffer(bytes(4)), StorageBuffer(bytes(4))
            status, output = self._api('SetupDiGetDevicePropertyW', (procedure, device_set, info, DEVICE_PROPERTY, kind, data, 4096, required, 0),
                                      {'info': info, 'data': data, 'type': kind, 'required': required})
            value = int.from_bytes(output['data'].read(0, 8), 'little') if status else 0
            return str(value).encode('ascii')
        finally:
            self._free(module)

    def _devices(self, class_guid, callback, count):
        class_guid, count = _bytes(class_guid), _signed(_integer(count), 32)
        if len(class_guid) != 16:
            raise QimeiRequestError('source setup class GUID requires sixteen bytes')
        libraries, targets = [], []
        values = set()
        try:
            for name in SETUP_EXPORTS:
                module, target = self._load(name)
                libraries.append(module)
                targets.append(target)
            if not all(targets):
                return ()
            device_set, unused = self._api('SetupDiGetClassDevsW', (targets[0], class_guid, None, None, 10), width=64)
            if not device_set:
                return ()
            try:
                for index in range(10):
                    info = StorageBuffer(bytes(32)).write(0, (32).to_bytes(4, 'little'))
                    status, output = self._api('SetupDiEnumDeviceInfo', (targets[1], device_set, index, info), {'info': info})
                    if not status:
                        break
                    value = _bytes(callback(device_set, output['info']))
                    if value:
                        values.add(value)
                    if count != -1 and len(values) == count:
                        break
            finally:
                self._api('SetupDiDestroyDeviceInfoList', (targets[2], device_set))
            return tuple(sorted(values))
        finally:
            for module in reversed(libraries):
                self._free(module)

    def extension_89b97(self):
        values = self._devices(DISK_CLASS, self._disk_property, -1)
        return next((value for value in values if b'USB' not in value), b'')

    def extension_89d6a(self):
        values = self._devices(COMPUTER_CLASS, self._computer_property, 1)
        if not values:
            return 0
        value = values[0].split(b'\0', 1)[0]
        index = 0
        while index < len(value) and value[index] in b' \t\n\r\v\f':
            index += 1
        negative = index < len(value) and value[index] == ord('-')
        if index < len(value) and value[index] in b'+-':
            index += 1
        start, result = index, 0
        while index < len(value) and ord('0') <= value[index] <= ord('9'):
            result = result * 10 + value[index] - ord('0')
            if result > 0xFFFFFFFFFFFFFFFF:
                return 0xFFFFFFFFFFFFFFFF
            index += 1
        return (-result if negative else result) & 0xFFFFFFFFFFFFFFFF if index != start else 0

    def storage_device(self):
        if self.storage_observations is None:
            raise QimeiRequestBoundary('raw NT storage observations required')
        probe = NtStorageProbe(swap_serial=False)
        result = probe.produce(self.storage_observations)
        values = tuple(probe.outputs)
        if any(value is None for value in values):
            raise QimeiRequestBoundary('unknown source NT storage String output')
        return RequestSourceReply(int(result is not None), values)

    def identity_3fb10(self):
        if self.startup is None:
            raise QimeiRequestBoundary('live startup identity store required')
        return self.startup.identity1.get(2)

    def identity_3fafa(self):
        if self.startup is None:
            raise QimeiRequestBoundary('live startup main store required')
        value = self.startup.main.get(0)
        if len(value) != 16 or not any(value):
            value = bytes(16)
            initialized, unused = self._api('CoInitialize', (None,))
            try:
                data = StorageBuffer.unknown(16)
                result, output = self._api('CoCreateGuid', (data,), {'data': data})
                if result == 0:
                    value = output['data'].read()
            finally:
                if not initialized & 0x80000000:
                    self._api('CoUninitialize', ())
            self.startup.main.set(0, value)
            if not callable(self.write_main):
                raise QimeiRequestBoundary('source identity update requires complete main-store persistence')
            self.write_main(self.startup.main)
        return value.hex().upper().encode('ascii')
