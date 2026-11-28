from dataclasses import dataclass, field

from .primary_qimei_context import ContextObservationError
from .primary_qimei_storage import StorageBuffer


CLASSIFIER_RULES = (
    (b'SYSTEM\\CurrentControlSet\\iCafe8', b'Admin'),
    (b'SOFTWARE\\EYOOCLIENTSTATUS', b'SuperLogin'),
    (b'SYSTEM\\CurrentControlSet', b'diskless'),
    (b'SYSTEMnVos', b'SupperMode'),
    (b'SYSTEM\\CurrentControlSet', b'superadmin'),
)

NETWORK_KEY = b'System\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}'


@dataclass(frozen=True)
class QimeiApiReply:
    result: int
    writes: tuple = field(default=(), repr=False)

    def apply(self, outputs, *, width=32):
        if type(self.result) is not int or not 0 <= self.result < 1 << width or type(self.writes) is not tuple:
            raise ContextObservationError('invalid Qimei raw API result')
        updated = dict(outputs)
        for row in self.writes:
            if type(row) is not tuple or len(row) != 3 or row[0] not in updated or updated[row[0]] is None:
                raise ContextObservationError('invalid Qimei raw API output span')
            name, offset, data = row
            updated[name] = updated[name].write(offset, data)
        return updated


class RegistryDwordProbe:
    def __init__(self):
        self.handle = 0
        self.output = StorageBuffer(b'\xFF' * 4)
        self.phase = 'new'
        self.complete = self.failed = False
        self.status = None

    def _api(self, observations, name, args, outputs):
        reply = observations.read('qimei-api', name, *args)
        if not isinstance(reply, QimeiApiReply):
            raise ContextObservationError('Qimei registry API requires an explicit raw reply')
        return reply.result, reply.apply(outputs)

    def produce(self, observations, path, name):
        if self.phase != 'new' or self.failed:
            raise ContextObservationError('Qimei registry probe cannot replay an entry')
        if (path, name) not in CLASSIFIER_RULES:
            raise ContextObservationError('Qimei classifier query leaves the fixed source rules')
        try:
            self.phase = 'open'
            handle = StorageBuffer(bytes(8))
            status, output = self._api(observations, 'RegOpenKeyExA',
                (0xFFFFFFFF80000002, path, 0, 0x101, handle), {'handle': handle})
            self.handle = int.from_bytes(output['handle'].read(), 'little')
            self.status = 1
            if status == 0:
                self.phase = 'size'
                size = StorageBuffer((4).to_bytes(4, 'little'))
                status, output = self._api(observations, 'RegQueryValueExA',
                    (self.handle, name, 0, None, None, size), {'size': size, 'data': None, 'type': None})
                size = output['size']
                self.status = 2
                if status == 0:
                    length = int.from_bytes(size.read(), 'little', signed=True)
                    self.status = 3
                    if length <= 4:
                        self.phase = 'value'
                        self.output = StorageBuffer(bytes(4))
                        status, output = self._api(observations, 'RegQueryValueExA',
                            (self.handle, name, 0, None, self.output, size),
                            {'size': size, 'data': self.output, 'type': None})
                        self.output = output['data']
                        self.status = 0 if status == 0 else 4
            if self.handle != 0:
                self.phase = 'close'
                self._api(observations, 'RegCloseKey', (self.handle,), {})
                self.handle = 0
            self.phase, self.complete = 'complete', True
            return self.status, int.from_bytes(self.output.read(), 'little')
        except BaseException:
            self.failed = True
            raise


class QimeiClassifierObservations:
    def __init__(self, observations):
        self.observations = observations
        self.probes = []
        self.values = {}
        self.drive_phase = 'new'
        self.drive_letter = None
        self.drive_failed = False

    @property
    def consumed(self):
        return self.observations.consumed

    def read(self, *key):
        if key[:1] != ('classifier',):
            return self.observations.read(*key)
        if len(key) != 3 or type(key[1]) is not int or not 0 <= key[1] < len(CLASSIFIER_RULES):
            raise ContextObservationError('invalid Qimei classifier observation')
        index, field_name = key[1:]
        if field_name == 'status':
            if any(probe.failed for probe in self.probes):
                raise ContextObservationError('failed raw classifier observation cannot be replayed')
            probe = RegistryDwordProbe()
            self.probes.append(probe)
            self.values.pop(index, None)
            status, value = probe.produce(self.observations, *CLASSIFIER_RULES[index])
            if status == 0:
                self.values[index] = value
            return status
        if field_name == 'value' and index in self.values:
            return self.values[index]
        raise ContextObservationError('classifier DWORD has not been produced successfully')

    def read_classifier_fallback(self):
        if self.drive_failed:
            raise ContextObservationError('failed drive classifier cannot replay observations')
        try:
            for letter in range(ord('C'), ord('Z') + 1):
                self.drive_phase, self.drive_letter = 'type', letter
                path = bytes((letter, ord(':')))
                reply = self.observations.read('qimei-api', 'GetDriveTypeA', path)
                if not isinstance(reply, QimeiApiReply):
                    raise ContextObservationError('drive type requires an explicit raw API reply')
                reply.apply({})
                if ((reply.result & 0xFFFFFFFE) - 2) & 0xFFFFFFFC:
                    continue
                self.drive_phase = 'mapping'
                buffer = StorageBuffer(bytes(260))
                reply = self.observations.read('qimei-api', 'QueryDosDeviceA', path, buffer, 260)
                if not isinstance(reply, QimeiApiReply):
                    raise ContextObservationError('drive mapping requires an explicit raw API reply')
                output = reply.apply({'data': buffer})['data']
                if reply.result != 0:
                    data = output.read()
                    end = data.find(b'\0')
                    if end < 0:
                        raise ContextObservationError('drive classifier mapping reads beyond declared bytes')
                    if b'Harddisk' in data[:end]:
                        self.drive_phase = 'complete'
                        return 0
            self.drive_phase = 'complete'
            return 11
        except BaseException:
            self.drive_failed = True
            raise


@dataclass(frozen=True)
class QimeiAdapterReply:
    result: int
    base: int = field(repr=False)
    output: StorageBuffer = field(repr=False)
    size: StorageBuffer = field(repr=False)

    def __post_init__(self):
        if (type(self.result) is not int or not 0 <= self.result < 1 << 32
                or type(self.base) is not int or not 0 < self.base < (1 << 64) - 11264
                or not isinstance(self.output, StorageBuffer) or len(self.output.data) != 11264
                or not isinstance(self.size, StorageBuffer) or len(self.size.data) != 4):
            raise ContextObservationError('invalid raw adapter API observation')


def _cstring(buffer, offset=0, limit=None):
    limit = len(buffer.data) - offset if limit is None else limit
    output = bytearray()
    for index in range(limit):
        byte = buffer.read(offset + index, 1)[0]
        if byte == 0:
            return bytes(output)
        output.append(byte)
    raise ContextObservationError('source CString continues beyond declared bytes')


class QimeiSelectorObservations:
    def __init__(self, observations):
        self.observations = observations
        self.adapter_phase = 'new'
        self.module = self.target = None
        self.adapters = None
        self.registry = {}
        self.registry_handles = []
        self.selected_effects = None
        self.enum_output = None
        self.astat_outputs = {}
        self.failed = False

    @property
    def consumed(self):
        return self.observations.consumed

    def _api(self, name, args, outputs=None, *, width=32):
        reply = self.observations.read('qimei-api', name, *args)
        if not isinstance(reply, QimeiApiReply):
            raise ContextObservationError('selector API requires an explicit raw reply')
        return reply.result, reply.apply(outputs or {}, width=width)

    def _release_module(self):
        if self.module is not None:
            self._api('FreeLibrary', (self.module,))
            self.module = None

    def _adapter_status(self):
        if self.adapter_phase != 'new':
            raise ContextObservationError('adapter source entry cannot be replayed')
        factory = getattr(self.observations, 'adapter_query_buffer', None)
        if factory is not None and not callable(factory):
            raise ContextObservationError('adapter query buffer factory must be callable')
        data = StorageBuffer.unknown(11264) if factory is None else factory()
        if (not isinstance(data, StorageBuffer) or len(data.data) != 11264
                or any(data.known) and not all(data.known)):
            raise ContextObservationError('adapter query requires a complete known or unknown fixed buffer')
        self.adapter_phase = 'library'
        directory = StorageBuffer(bytes(520))
        unused, outputs = self._api('GetSystemDirectoryW', (directory, 260), {'data': directory})
        directory = outputs['data']
        suffix = 'iphlpapi.dll'.encode('utf-16le') + bytes(2)
        unused, outputs = self._api('PathAppendW', (directory, suffix), {'data': directory})
        raw = outputs['data'].read()
        end = next((i for i in range(0, 520, 2) if raw[i:i + 2] == bytes(2)), None)
        if end is None:
            raise ContextObservationError('selector library path is not terminated')
        module, unused = self._api('LoadLibraryW', (raw[:end + 2],), width=64)
        if module == 0:
            self.adapter_phase = 'unavailable'
            return -1
        self.module = module
        self.target, unused = self._api('GetProcAddress', (module, b'GetAdaptersInfo'), width=64)
        if self.target == 0:
            self._release_module()
            self.adapter_phase = 'unavailable'
            return -1
        self.adapter_phase = 'query'
        reply = self.observations.read('qimei-api', 'GetAdaptersInfo', self.target,
                                       data, StorageBuffer((11264).to_bytes(4, 'little')))
        if not isinstance(reply, QimeiAdapterReply):
            raise ContextObservationError('GetAdaptersInfo requires raw bounded output and its base address')
        self.adapters = reply
        if reply.result != 0:
            self._release_module()
            self.adapter_phase = 'failed-query'
        else:
            self.adapter_phase = 'nodes'
        return reply.result

    def _node(self, node, offset, length):
        if self.adapters is None or self.adapters.result != 0 or type(node) is not int:
            raise ContextObservationError('adapter node is unavailable')
        start = node - self.adapters.base
        if not 0 <= start <= 11264 - 704:
            raise ContextObservationError('adapter Next pointer leaves its declared allocation')
        return self.adapters.output.read(start + offset, length)

    def _name(self, node):
        self._node(node, 0, 1)
        return _cstring(self.adapters.output, node - self.adapters.base + 12, 260)

    def _open(self, parent, name):
        handle = StorageBuffer(bytes(8))
        status, outputs = self._api('RegOpenKeyExA', (parent, name, 0, 0x20019, handle), {'handle': handle})
        value = int.from_bytes(outputs['handle'].read(), 'little')
        if status == 0:
            self.registry_handles.append(value)
        return status, value

    def _close(self, handle):
        self._api('RegCloseKey', (handle,))
        self.registry_handles.remove(handle)

    def _adapter_registry(self, node):
        self.adapter_phase = 'registry'
        adapter_name = self._name(node)
        child_name = adapter_name + b'\\Connection'
        if len(child_name) >= 259:
            raise ContextObservationError('adapter connection formatting exceeds declared source domain')
        status, parent = self._open(0xFFFFFFFF80000002, NETWORK_KEY)
        result = {'status': status, 'subtype': None, 'pnp': None}
        if status != 0:
            return result
        status, child = self._open(parent, child_name)
        result['status'] = status
        if status == 0:
            size = StorageBuffer((4).to_bytes(4, 'little'))
            value_type = StorageBuffer((4).to_bytes(4, 'little'))
            data = StorageBuffer(bytes(4))
            status, outputs = self._api('RegQueryValueExA',
                (child, b'MediaSubType', 0, value_type, data, size), {'type': value_type, 'data': data, 'size': size})
            result['status'] = status
            if status == 0:
                result['subtype'] = int.from_bytes(outputs['data'].read(), 'little')
                data = StorageBuffer(bytes(260))
                size, value_type = StorageBuffer((259).to_bytes(4, 'little')), StorageBuffer((1).to_bytes(4, 'little'))
                status, outputs = self._api('RegQueryValueExA',
                    (child, b'PnpInstanceID', 0, value_type, data, size), {'type': value_type, 'data': data, 'size': size})
                result.update(status=status, pnp=outputs['data'])
            self._close(child)
        self._close(parent)
        self.adapter_phase = 'nodes'
        return result

    def _netbios(self, command, lana=0):
        ncb = bytearray(96)
        ncb[0], ncb[64] = command, lana
        output = None
        if command == 0x37:
            output = StorageBuffer.unknown(256)
            ncb[16:18] = (256).to_bytes(2, 'little')
        elif command == 0x33:
            output = StorageBuffer(bytes(600))
            ncb[16:18] = (600).to_bytes(2, 'little')
            ncb[18:20] = b'*\0'
        elif command != 0x32:
            raise ContextObservationError('unsupported source NetBIOS command')
        ncb = StorageBuffer(bytes(ncb))
        status, outputs = self._api('Netbios', (ncb, output), {'ncb': ncb, 'data': output}, width=8)
        return status, outputs['data']

    def read(self, *key):
        if not key or key[0] not in ('adapters', 'adapter', 'netbios'):
            return self.observations.read(*key)
        if self.failed:
            raise ContextObservationError('failed raw selector entry cannot be replayed')
        try:
            return self._read(key)
        except BaseException:
            self.failed = True
            raise

    def _read(self, key):
        if key == ('adapters', 'status', 11264):
            return self._adapter_status()
        if key == ('adapters', 'head'):
            if self.adapters is None or self.adapters.result != 0:
                raise ContextObservationError('successful adapter buffer has not been produced')
            return self.adapters.base
        if len(key) == 3 and key[0] == 'adapter':
            node, name = key[1:]
            if name == 'type':
                return int.from_bytes(self._node(node, 420, 4), 'little')
            if name == 'registry-status':
                if node not in self.registry:
                    self.registry[node] = self._adapter_registry(node)
                return self.registry[node]['status']
            if name in ('subtype', 'pnp-instance'):
                if node not in self.registry or self.registry[node]['status'] != 0:
                    raise ContextObservationError('adapter registry classification is unavailable')
                value = self.registry[node]['subtype' if name == 'subtype' else 'pnp']
                if value is None:
                    raise ContextObservationError('adapter registry field was not consumed by source')
                return value.read(0, 3) if name == 'pnp-instance' else value
            if name == 'address':
                value = self._node(node, 408, 6)
                raw = self.adapters.output
                ip = _cstring(raw, node - self.adapters.base + 448)
                index = int.from_bytes(self._node(node, 416, 4), 'little')
                kind = int.from_bytes(self._node(node, 420, 4), 'little')
                self.selected_effects = {'ip': ip, 'index': index, 'type': kind}
                return value
            if name == 'selected-effects':
                if self.selected_effects is None:
                    raise ContextObservationError('selected adapter fields have not been produced')
                return self.selected_effects
            if name == 'next':
                pointer = int.from_bytes(self._node(node, 0, 8), 'little')
                if pointer == 0:
                    self._release_module()
                    self.adapter_phase = 'complete'
                return pointer
        if key == ('netbios', 'enum-status'):
            if self.enum_output is not None:
                raise ContextObservationError('source NetBIOS enumeration cannot replay an entry')
            status, self.enum_output = self._netbios(0x37)
            return status
        if key == ('netbios', 'lanas') and self.enum_output is not None:
            length = self.enum_output.read(0, 1)[0]
            return self.enum_output.read(1, length)
        if len(key) == 3 and key[0] == 'netbios' and type(key[1]) is int and 0 <= key[1] < 256:
            lana, name = key[1:]
            if name == 'reset-status':
                return self._netbios(0x32, lana)[0]
            if name == 'astat-status':
                status, self.astat_outputs[lana] = self._netbios(0x33, lana)
                return status
            if name == 'address' and lana in self.astat_outputs:
                return self.astat_outputs[lana].read(0, 6)
        raise ContextObservationError('unsupported raw selector consumer')
