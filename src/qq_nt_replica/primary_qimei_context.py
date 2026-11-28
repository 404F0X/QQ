from dataclasses import dataclass, field
from threading import RLock

from .primary_qimei_cache import QimeiCacheError


COMPILED_SELECTED6 = bytes.fromhex('1a2b3c4d5e6f')
STORAGE_MODELS = (b'Virtual SCSI Harddisk', b'vDisk', b'NxDDisk', b'Virtual IDE Disk', b'CCBoot iSCSI')


class ContextObservationError(QimeiCacheError):
    pass


class ContextObservations:
    def __init__(self, values):
        self.values = values
        self.consumed = []

    def read(self, *key):
        self.consumed.append(key)
        if key not in self.values or self.values[key] is None:
            raise ContextObservationError(f'unknown observation: {key!r}')
        value = self.values[key]
        if isinstance(value, BaseException):
            raise value
        return value


def _integer(value):
    if type(value) is not int:
        raise ContextObservationError('integer observation required')
    return value


def _bytes(value):
    if not isinstance(value, bytes):
        raise ContextObservationError('byte observation required')
    return value


def _six(value):
    value = _bytes(value)
    if len(value) < 6:
        raise ContextObservationError('six readable address bytes required')
    return value[:6]


def classify(observations):
    for index, expected in enumerate((0, 0, 1, 0, 0)):
        status = _integer(observations.read('classifier', index, 'status'))
        if status == 0 and _integer(observations.read('classifier', index, 'value')) == expected:
            return index + 1
    fallback = getattr(observations, 'read_classifier_fallback', None)
    if fallback is None:
        return 0
    value = _integer(fallback())
    if value not in (0, 11):
        raise ContextObservationError('invalid source drive classifier result')
    return value


def ata_strings(raw):
    raw = _bytes(raw)
    if len(raw) < 94:
        raise ContextObservationError('ATA identity words through 46 required')
    return tuple(b''.join(raw[2 * i:2 * i + 2][::-1] for i in range(first, last + 1)).rstrip(b' ')
                 for first, last in ((10, 19), (27, 46), (23, 26)))


def storage_gate(observations):
    success = observations.read('storage', 'success')
    if type(success) is not bool:
        raise ContextObservationError('boolean storage success observation required')
    if not success:
        return False
    kind = observations.read('storage', 'format')
    if kind == 'ata':
        outputs = ata_strings(observations.read('storage', 'ata'))
    elif kind == 'normalized':
        outputs = None
    else:
        raise ContextObservationError('unsupported storage observation format')
    first = outputs[0] if outputs is not None else _bytes(observations.read('storage', 0))
    if not first:
        second = outputs[1] if outputs is not None else _bytes(observations.read('storage', 1))
        if not second:
            third = outputs[2] if outputs is not None else _bytes(observations.read('storage', 2))
            if not third:
                return True
    else:
        second = outputs[1] if outputs is not None else _bytes(observations.read('storage', 1))
    return second in STORAGE_MODELS


@dataclass
class QimeiSelectorState:
    selected6: bytes | None = field(default=bytes(6), repr=False)
    selected_effects: dict | None = field(default=None, init=False, repr=False)
    _lock: object = field(default_factory=RLock, repr=False, compare=False)

    def select(self, observations):
        with self._lock:
            if self.selected6 is None:
                raise ContextObservationError('unknown selector state')
            if len(_bytes(self.selected6)) != 6:
                raise ContextObservationError('selector state must contain six bytes')
            if any(self.selected6):
                return self.selected6
            rank = 3
            status = _integer(observations.read('adapters', 'status', 11264))
            if status == 0:
                node = observations.read('adapters', 'head')
                visited = set()
                while node != 0:
                    if node in visited:
                        raise ContextObservationError('cyclic adapter Next chain')
                    visited.add(node)
                    query_status = _integer(observations.read('adapter', node, 'registry-status'))
                    candidate = 3
                    if query_status == 0:
                        subtype = _integer(observations.read('adapter', node, 'subtype'))
                        if subtype == 1:
                            prefix = _bytes(observations.read('adapter', node, 'pnp-instance'))
                            candidate = 0 if prefix[:3].lower() == b'pci' else 2
                        elif subtype == 2:
                            candidate = 1
                    choose = not any(self.selected6)
                    if not choose:
                        adapter_type = _integer(observations.read('adapter', node, 'type'))
                        choose = adapter_type in (6, 23) and rank > candidate
                    if choose:
                        address = _six(observations.read('adapter', node, 'address'))
                        effects = observations.read('adapter', node, 'selected-effects')
                        # Keep the same selection's compound result beyond this IO observation.
                        self.selected6, self.selected_effects = address, effects
                        rank = candidate
                    node = observations.read('adapter', node, 'next')
            if any(self.selected6):
                return self.selected6
            enum_status = _integer(observations.read('netbios', 'enum-status'))
            if enum_status == 0:
                lanas = observations.read('netbios', 'lanas')
                if not isinstance(lanas, bytes):
                    raise ContextObservationError('ordered LANA bytes required')
                for lana in reversed(lanas):
                    if _integer(observations.read('netbios', lana, 'reset-status')) != 0:
                        continue
                    if _integer(observations.read('netbios', lana, 'astat-status')) != 0:
                        continue
                    self.selected6 = _six(observations.read('netbios', lana, 'address'))
                    if any(self.selected6):
                        return self.selected6
            self.selected6 = COMPILED_SELECTED6
            return self.selected6


@dataclass
class QimeiContextProducer:
    context: bytes | None = field(default=b'', repr=False)
    initialized: bool | None = False
    selector: QimeiSelectorState = field(default_factory=QimeiSelectorState)
    _lock: object = field(default_factory=RLock, repr=False, compare=False)

    def produce(self, observations):
        with self._lock:
            if type(self.initialized) is not bool:
                raise ContextObservationError('unknown context once state')
            if not self.initialized:
                category = classify(observations)
                if category in (1, 2, 3) or storage_gate(observations):
                    self.context = self.selector.select(observations).hex().encode('ascii')
                self.initialized = True
            if self.context is None:
                raise ContextObservationError('unknown context at consumer')
            return _bytes(self.context)

    def key(self, constants, observations):
        return constants.key(context=self.produce(observations))

    def read_cache(self, codec, ciphertext, observations, *, previous=None):
        return codec.read(ciphertext, context=self.produce(observations), previous=previous)

    def encode_records(self, codec, record0, record1, observations):
        return codec.encode_records(record0, record1, context=self.produce(observations))
