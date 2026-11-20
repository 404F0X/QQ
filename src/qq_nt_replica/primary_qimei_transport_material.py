from dataclasses import dataclass
from threading import RLock

from .primary_qimei_extra_sources import QimeiExtraSources, _cstring
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer, _signed, _varint
from .primary_qimei_storage import StorageBuffer
from .primary_qimei_transport_random import QimeiTransportRandom
from .primary_qimei_system_sources import WINDOWS_KEY


MODEL_KEYS = (b'SYSTEM\\HardwareConfig\\Current', b'HARDWARE\\DESCRIPTION\\System\\BIOS')


@dataclass(frozen=True)
class QimeiTransportMaterial:
    fields: tuple

    def serialize(self):
        if len(self.fields) != 13:
            raise QimeiRequestError('transport material requires thirteen fields')
        result = bytearray()
        for number, value in enumerate(self.fields, 1):
            if number in (1, 3, 13):
                value = _integer(value)
                value = (_signed(value, 32) & 0xFFFFFFFFFFFFFFFF) if number == 13 else value & 0xFFFFFFFF
                result += _varint(number << 3) + _varint(value)
            else:
                value = _bytes(value)
                result += _varint((number << 3) | 2) + _varint(len(value)) + value
        return bytes(result)


class QimeiTransportGlobals:
    _api = QimeiExtraSources._api

    def __init__(self, observations, *, random=None):
        self.observations = observations
        self.random = QimeiTransportRandom(observations) if random is None else random
        self._lock = RLock()
        self._manager = self._config = b''
        self._model = None

    def manager(self):
        with self._lock:
            if not self._manager:
                random = self.random.random_bytes(8)
                data = StorageBuffer(bytes(8))
                unused, output = self._api('GetSystemTimeAsFileTime', (data,), {'data': data})
                delta = _signed(int.from_bytes(output['data'].read(), 'little') - 116444736000000000, 64)
                milliseconds = abs(delta) // 10000 * (-1 if delta < 0 else 1)
                self._manager = str(milliseconds).encode('ascii') + random.hex().encode('ascii')
            return self._manager

    def model(self, extension, system, settings):
        with self._lock:
            if self._model is None:
                value = extension.firmware_strings().values[5] if settings.flag(9) else b''
                if not value:
                    for name in (b'SystemFamily', b'SystemVersion'):
                        for path in MODEL_KEYS:
                            status, data = system.registry_value(path, name, StorageBuffer(bytes(260)))
                            if status == 0:
                                value = _cstring(data)
                                if value:
                                    break
                        if value:
                            break
                self._model = _bytes(value)
            return self._model

    def config(self):
        with self._lock:
            if not self._config:
                data = StorageBuffer(bytes(261))
                status, output = self._api('SHGetFolderPathA', (0, 0x801A, 0, 0, data), {'data': data})
                if _signed(status, 32) < 0 or status == 1:
                    raise QimeiRequestBoundary('AA02C config1 generator is not implemented')
                path = _cstring(output['data']) + b'\\Tencent\\beacon\\GlobalMgr.db'
                data = StorageBuffer(bytes(33))
                unused, output = self._api('GetPrivateProfileStringA', (b'Profile', b'config1', None, data, 33, path), {'data': data})
                value = _cstring(output['data'])
                if len(value) != 32:
                    raise QimeiRequestBoundary('AA02C config1 generator is not implemented')
                if any(byte not in b'0123456789abcdefABCDEF' for byte in value):
                    raise QimeiRequestBoundary('config1 invalid hexadecimal requires source CRT scanf semantics')
                self._config = bytes.fromhex(value.decode('ascii')).hex().encode('ascii')
            return self._config


class QimeiTransportMaterialProducer:
    def __init__(self, *, globals, system, extras, extension, adapter, sdk, startup, settings, convert_ansi):
        self.globals, self.system, self.extras = globals, system, extras
        self.extension, self.adapter, self.sdk = extension, adapter, sdk
        self.startup, self.settings, self.convert_ansi = startup, settings, convert_ansi
        self._lock = RLock()
        self._backend = None

    def _windows(self):
        status, data = self.system.registry_value(WINDOWS_KEY, b'ProductName', StorageBuffer(bytes(260)))
        product = _cstring(data) if status == 0 else b''
        numbers = []
        for name in (b'CurrentMajorVersionNumber', b'CurrentMinorVersionNumber'):
            unused, data = self.system.registry_value(WINDOWS_KEY, name, StorageBuffer(bytes(4)))
            numbers.append(_signed(int.from_bytes(data.read(), 'little'), 32))
        unused, data = self.system.registry_value(WINDOWS_KEY, b'CurrentBuild', StorageBuffer(bytes(260)))
        level = str(numbers[0]).encode('ascii') + b'.' + str(numbers[1]).encode('ascii') + b'.' + _cstring(data)
        if len(level) >= 260:
            raise QimeiRequestBoundary('Windows level formatting exceeds source buffer')
        return b'Windows ' + product + b',level ' + level

    def produce(self, owner, mode, sequence):
        owner, mode, sequence = _bytes(owner), _integer(mode) & 0xFFFFFFFF, _signed(sequence, 32)
        with self._lock:
            if self._backend is None:
                path = self.system.executable_path().value
                basename = path.rsplit(b'\\', 1)[-1]
                version = self.extras.version_string(path)
                windows = self._windows()
                model = self.globals.model(self.extension, self.system, self.settings)
                network = b'net_' + str(self.adapter.refresh().adapter_type & 0xFFFFFFFF).encode('ascii')
                self._backend = basename, version, windows, model, network
            basename, version, windows, model, network = self._backend
            manager = self.globals.manager()
            third = _bytes(self.sdk.get(owner).third) or version
            startup = _bytes(self.startup.main.get(1))
            config = self.globals.config()
            return QimeiTransportMaterial((mode, manager, 3, owner, b'5.1.3.16.1', third, windows, model,
                                           startup[:-1] if startup else b'', config, self.convert_ansi(basename), network, sequence))
