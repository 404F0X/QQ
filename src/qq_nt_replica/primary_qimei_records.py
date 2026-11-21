from dataclasses import dataclass, field
from threading import RLock

from .primary_qimei_cache import CacheRecords, QimeiCacheCodec, QimeiCacheError
from .primary_qimei_context import ContextObservations, QimeiContextProducer, QimeiSelectorState
from .primary_qimei_identity_parser import parse_identity


class RecordObservationError(QimeiCacheError):
    pass


def _bytes(value):
    if not isinstance(value, bytes):
        raise RecordObservationError('explicit readable bytes required')
    return value


def _integer(value):
    if type(value) is not int:
        raise RecordObservationError('explicit integer required')
    return value


def _boolean(value):
    if type(value) is not bool:
        raise RecordObservationError('explicit source boolean required')
    return value


@dataclass
class Record:
    id: int
    capacity: int
    value: bytes | None = field(repr=False)

    def __post_init__(self):
        if not -(1 << 31) <= _integer(self.id) < 1 << 31:
            raise RecordObservationError('record id must be signed DWORD')
        if not -(1 << 31) <= _integer(self.capacity) < 1 << 32:
            raise RecordObservationError('record capacity requires DWORD bits')
        self.capacity &= 0xFFFFFFFF
        if self.value is not None:
            _bytes(self.value)


@dataclass(frozen=True)
class DecodedPayload:
    status: int
    payload: bytes | None = field(repr=False)


class RecordObservations(ContextObservations):
    def __init__(self, values, *, codec=None, context_producer=None, context_observations=None):
        super().__init__(values)
        if context_producer is not None and not isinstance(context_producer, QimeiContextProducer):
            raise RecordObservationError('context producer required')
        self.codec = codec
        self.context_producer = context_producer if context_producer is not None else QimeiContextProducer()
        self.context_observations = context_observations if context_observations is not None else self

    def read(self, *key):
        value = super().read(*key)
        return value() if callable(value) else value

    def identity_projection(self, name, payload):
        if ('parse', name, payload) in self.values:
            return _LegacyIdentityProjection(self, name, payload)
        return parse_identity(payload)

    def decode_payload(self, name, path, capacity):
        if ('decode', name, path, capacity) in self.values:
            return self.read('decode', name, path, capacity)
        ciphertext = _bytes(self.read('ciphertext', name, path))
        if not ciphertext:
            return DecodedPayload(2, None)
        if self.codec is None:
            self.codec = QimeiCacheCodec()
        context = self.context_producer.produce(self.context_observations)
        decoded = self.codec.decode_payload(ciphertext, capacity=capacity, context=context)
        if decoded.accepted is None:
            raise RecordObservationError(decoded.status)
        return DecodedPayload(decoded.source_code, decoded.payload)


class _LegacyIdentityProjection:
    def __init__(self, observations, name, payload):
        self.observations = observations
        self.name = name
        self.accepted = _boolean(observations.read('parse', name, payload))

    def query(self, key):
        return _bytes(self.observations.read('query', self.name, key))


def _identity_projection(observations, name, payload):
    if isinstance(observations, RecordObservations):
        return observations.identity_projection(name, payload)
    return parse_identity(payload)


def _decode_payload(observations, name, path, capacity):
    if isinstance(observations, RecordObservations):
        return observations.decode_payload(name, path, capacity)
    return observations.read('decode', name, path, capacity)


@dataclass
class Store:
    name: str
    mode: int | None
    path: bytes | None = field(repr=False)
    records: list[Record] | None = field(repr=False)
    _lock: object = field(default_factory=RLock, repr=False, compare=False)

    def vector(self):
        if self.records is None:
            raise RecordObservationError('unknown record vector')
        return self.records

    def append(self, id, capacity, observe):
        records = self.vector()
        record = Record(id, capacity, b'')
        observe('append', self, record)
        records.append(record)

    def update(self, index, value, observe):
        record = self.vector()[index]
        value = _bytes(value)
        observe('update', self, record)
        record.value = value

    def get(self, id):
        with self._lock:
            record = next((r for r in self.vector() if r.id == id), None)
            return b'' if record is None else _bytes(record.value)

    def set(self, id, value, observe=lambda *args: None):
        value = _bytes(value)
        with self._lock:
            for index, record in enumerate(self.vector()):
                capacity = record.capacity
                if capacity & 0x80000000:
                    capacity += (1 << 64) - (1 << 32)
                if record.id == id and len(value) <= capacity:
                    self.update(index, value, observe)
                    break

    def clear(self, observe):
        with self._lock:
            for record in self.vector():
                observe('clear', self, record)
                record.value = b''

    def apply_decoded(self, decoded, observations, observe):
        if not isinstance(decoded, DecodedPayload):
            raise RecordObservationError('explicit decoded source result required')
        if _integer(decoded.status) != 0:
            return False
        payload = _bytes(decoded.payload)
        if not payload:
            return False
        if self.mode == 0:
            total = self.capacity_sum()
            if total <= 0:
                return False
            return self._apply_mode0(payload, total, observe)
        if self.mode != 1:
            raise RecordObservationError('unknown store mode')
        parsed = _identity_projection(observations, self.name, payload)
        if not parsed.accepted:
            return False
        return self._apply_parsed(parsed, observe)

    def _apply_mode0(self, payload, total, observe):
        payload = payload[:total]
        with self._lock:
            offset = 0
            for index, record in enumerate(self.vector()):
                capacity = record.capacity & 0xFFFFFFFF
                if capacity & 0x80000000:
                    raise QimeiCacheError('source String length exceeds max_size')
                following = offset + capacity
                if following > len(payload):
                    break
                self.update(index, payload[offset:following], observe)
                offset = following
        return True

    def _apply_parsed(self, parsed, observe):
        with self._lock:
            for index, record in enumerate(self.vector()):
                value = _bytes(parsed.query(str(record.id).encode('ascii')))
                if value and len(value) <= record.capacity:
                    self.update(index, value, observe)
        return True

    def capacity_sum(self):
        with self._lock:
            total = 0
            for record in self.vector():
                total = (total + record.capacity) & 0xFFFFFFFF
            return total - (1 << 32) if total & 0x80000000 else total

    def _read_mode0(self, observations, observe):
        total = self.capacity_sum()
        if total <= 0:
            return False
        if not _boolean(observations.read('allocate', self.name, total)):
            return False
        try:
            path = self.read_path()
            decoded = _decode_payload(observations, self.name, path, total)
            if not isinstance(decoded, DecodedPayload):
                raise RecordObservationError('explicit decoded source result required')
            if _integer(decoded.status) != 0:
                return False
            payload = _bytes(decoded.payload)
            return self._apply_mode0(payload, total, observe) if payload else False
        finally:
            observe('free-buffer', self, None)

    def read_path(self):
        names = {'main': b'Global.db', 'identity1': b'Configv2.ini', 'identity0': b'Config.ini'}
        if self.name not in names:
            raise RecordObservationError('unknown source store path virtual')
        return (_bytes(self.path) + b'\\' + names[self.name]).split(b'\0', 1)[0]

    def read(self, observations, observe=lambda *args: None):
        if self.mode == 0:
            return self._read_mode0(observations, observe)
        if self.mode != 1:
            raise RecordObservationError('unknown store read mode')
        path = self.read_path()
        if not _boolean(observations.read('open', self.name, path)):
            return False
        length = _integer(observations.read('file-length', self.name, path))
        observe('close-file', self, None)
        if not -(1 << 31) <= length < 1 << 31:
            raise RecordObservationError('source file length requires signed EAX')
        if length <= 0:
            return False
        if not _boolean(observations.read('allocate', self.name, length)):
            return False
        try:
            decoded = _decode_payload(observations, self.name, path, length)
            if not isinstance(decoded, DecodedPayload):
                raise RecordObservationError('explicit decoded source result required')
            if _integer(decoded.status) != 0:
                return False
            payload = _bytes(decoded.payload)
            if not payload:
                return False
            parsed = _identity_projection(observations, self.name, payload)
        finally:
            observe('free-buffer', self, None)
        return self._apply_parsed(parsed, observe) if parsed.accepted else False

    def read_codec(self, codec, ciphertext, *, context=None, selected6=None, observe=lambda *args: None):
        records = self.vector()
        if self.mode != 0 or [(r.id, r.capacity) for r in records] != [(0, 16), (1, 37)]:
            raise RecordObservationError('fixed codec requires canonical ordered 16/37 records')
        result = codec.read(ciphertext, context=context, selected6=selected6, previous=CacheRecords())
        with self._lock:
            for index in result.updated_records:
                self.update(index, result.records.record0 if index == 0 else result.records.record1, observe)
        return result

    def profile_records(self):
        records = self.vector()
        first = next((r for r in records if r.id == 0), None)
        second = next((r for r in records if r.id == 1), None)
        a = first.value if first is not None else None
        b = second.value if second is not None else None
        return CacheRecords(a if a is not None and len(a) == 16 else None,
                            b if b is not None and len(b) == 37 else None)


@dataclass
class StartupState:
    main: Store
    identity1: Store
    identity0: Store
    enabled: int | None
    identity_mode: int | None
    record1_capacity: int | None
    identity_capacity: int | None
    once: int | None
    _lock: object = field(default_factory=RLock, repr=False, compare=False)

    @classmethod
    def cold(cls):
        return cls(Store('main', 0, b'', []), Store('identity1', 1, b'', []),
                   Store('identity0', 0, b'', []), 1, 1, 37, 32, 0)

    def start(self, observations, *, selector, selector_observations=None,
              reader=None, observe=lambda *args: None):
        with self._lock:
            if _integer(self.once) != 0:
                return None
            base = _bytes(observations.read('base-path'))
            mode = _integer(self.identity_mode)
            identity = self.identity1 if mode == 1 else self.identity0 if mode == 0 else None
            consume = reader if reader is not None else lambda store: store.read(observations, observe)
            if identity is not None:
                observe('path', identity, None)
                identity.path = base
                rows = ((0, 12), (1, self.identity_capacity), (2, 56)) if mode == 1 else ((0, 6),)
                for id, capacity in rows:
                    identity.append(id, capacity, observe)
                _boolean(consume(identity))
                logical = identity.get(0)
                value = logical if mode == 1 else logical.hex().encode('ascii')
            else:
                value = b''
            if isinstance(selector, QimeiSelectorState):
                selected = selector.select(selector_observations if selector_observations is not None else ContextObservations({}))
            elif callable(selector):
                selected = selector()
            else:
                raise RecordObservationError('independent selector or explicit source callback required')
            selected = _bytes(selected)
            if len(selected) != 6:
                raise RecordObservationError('selected address must have exactly six bytes')
            changed = False
            if value:
                prefix = value[:12]
                if len(value) < 12:
                    prefix = _bytes(observations.read('identity-prefix', identity.name))
                    if len(prefix) != 12 or not prefix.startswith(value) or prefix[len(value)] != 0:
                        raise RecordObservationError('twelve readable identity temporary bytes required')
                changed = prefix != selected.hex().encode('ascii')
            if changed:
                identity.clear(observe)
            observe('path', self.main, None)
            self.main.path = base
            self.main.append(0, 16, observe)
            self.main.append(1, _integer(self.record1_capacity), observe)
            if not changed:
                _boolean(consume(self.main))
            self.once = 1
            return not changed
