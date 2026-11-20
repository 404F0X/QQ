from dataclasses import dataclass, field
from threading import RLock

from .primary_qimei_context import QimeiSelectorState
from .primary_qimei_observations import QimeiSelectorObservations
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer
from .primary_qimei_storage import StorageBuffer
from .primary_qimei_system_sources import QimeiSystemSources
from .primary_qimei_extra_sources import _cstring


INTERFACES_KEY = b'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces'


@dataclass
class QimeiAdapterState:
    selector: QimeiSelectorState = field(default_factory=QimeiSelectorState, repr=False)
    ip: bytes = field(default=b'', repr=False)
    index: int = 0
    adapter_type: int = 0
    _lock: object = field(default_factory=RLock, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.selector, QimeiSelectorState):
            raise QimeiRequestError('live source adapter selector required')
        _bytes(self.ip)
        if any(not 0 <= _integer(value) <= 0xFFFFFFFF for value in (self.index, self.adapter_type)):
            raise QimeiRequestError('source adapter index/type require raw DWORDs')


@dataclass(frozen=True)
class AdapterLookup:
    accepted: bool
    record: StorageBuffer | None = field(default=None, repr=False)


def format_address(value):
    value = _bytes(value)
    if len(value) != 6:
        raise QimeiRequestError('source adapter formatter requires exactly six bytes')
    return value.hex().encode('ascii')


class QimeiAdapterSources:
    def __init__(self, observations, *, state=None):
        self.observations = observations
        self.state = QimeiAdapterState() if state is None else state
        if not isinstance(self.state, QimeiAdapterState):
            raise QimeiRequestError('live source adapter state required')

    def _nodes(self, probe):
        node, visited = probe.adapters.base, set()
        while node:
            if node in visited:
                raise QimeiRequestBoundary('cyclic source adapter Next chain')
            visited.add(node)
            probe._node(node, 0, 1)
            yield node
            node = int.from_bytes(probe._node(node, 0, 8), 'little')

    def lookup_index(self, index):
        index = _integer(index) & 0xFFFFFFFF
        probe = QimeiSelectorObservations(self.observations)
        try:
            if probe._adapter_status() != 0:
                return AdapterLookup(False)
            for node in self._nodes(probe):
                if int.from_bytes(probe._node(node, 416, 4), 'little') == index:
                    start = node - probe.adapters.base
                    raw = probe.adapters.output
                    return AdapterLookup(True, StorageBuffer(raw.data[start:start + 704], raw.known[start:start + 704]))
            return AdapterLookup(False)
        finally:
            if probe.module is not None:
                probe._release_module()

    def refresh(self):
        state = self.state
        with state._lock:
            selected = state.selector.selected6
            if selected is None or not isinstance(selected, bytes) or len(selected) != 6:
                raise QimeiRequestBoundary('source adapter selected address is unknown or malformed')
            if any(selected):
                return state
            observations = QimeiSelectorObservations(self.observations)
            state.selector.select(observations)
            if observations.selected_effects is not None:
                effects = observations.selected_effects
                state.ip, state.index, state.adapter_type = effects['ip'], effects['index'], effects['type']
            if state.ip == b'0.0.0.0':
                found = self.lookup_index(state.index)
                if found.accepted:
                    path = INTERFACES_KEY + b'\\' + _cstring(found.record, 12)
                    system = QimeiSystemSources(self.observations)
                    status, output = system.registry_value(path, b'DhcpIPAddress', StorageBuffer(bytes(260)))
                    if status != 0:
                        unused, output = system.registry_value(path, b'IPAddress', StorageBuffer(bytes(260)))
                    value = _cstring(output)
                    if value:
                        state.ip = value
            return state

    def primary_adapter(self):
        state = self.refresh()
        return format_address(state.selector.selected6), state.ip

    def extension_7f67a(self):
        probe = QimeiSelectorObservations(self.observations)
        result = bytearray()
        try:
            if probe._adapter_status() != 0:
                return bytes(result)
            for node in self._nodes(probe):
                raw = probe.adapters.output
                description = _cstring(raw, node - probe.adapters.base + 272)
                kind = int.from_bytes(probe._node(node, 420, 4), 'little')
                address = probe._node(node, 408, 6)
                result += description + b',' + str(kind).encode('ascii') + b',' + format_address(address) + b','
            return bytes(result)
        finally:
            if probe.module is not None:
                probe._release_module()
