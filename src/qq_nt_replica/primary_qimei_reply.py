from dataclasses import dataclass, field

from .primary_qimei_context import ContextObservations, QimeiSelectorState
from .primary_qimei_records import RecordObservationError, StartupState


class QimeiReplyError(RecordObservationError):
    pass


class QimeiReplyBoundary(QimeiReplyError):
    def __init__(self, message, cursor, slots):
        super().__init__(message)
        self.cursor = cursor
        self.slots = tuple(slots)


def _bytes(value):
    if not isinstance(value, bytes):
        raise QimeiReplyError('explicit reply bytes required')
    return value


def _integer(value):
    if type(value) is not int:
        raise QimeiReplyError('explicit source integer required')
    return value


def _allocation(allocate, kind, index, size):
    result = True if allocate is None else allocate(kind, index, size)
    if type(result) is not bool:
        raise QimeiReplyError('explicit allocation boolean required')
    return result


@dataclass(frozen=True)
class ReplySlot:
    tag: int = 0
    data: bytes | None = field(default=None, repr=False)

    @property
    def cstr(self):
        return b'' if self.data is None else self.data.split(b'\0', 1)[0]


@dataclass(frozen=True)
class ParsedReply:
    accepted: bool
    slots: tuple[ReplySlot, ...]
    cursor: int


def _varint(payload, cursor, limit):
    value = 0
    for index in range(10):
        if cursor >= limit:
            return False, value, cursor
        byte = payload[cursor]
        cursor += 1
        value = (value | ((byte & 0x7F) << (index * 7))) & 0xFFFFFFFFFFFFFFFF
        if byte < 0x80:
            return True, value, cursor
    return False, value, cursor


def parse_reply(payload, *, allocate=None, count=3):
    payload = _bytes(payload)
    count = _integer(count)
    if not 0 < count < 0x80000000:
        raise QimeiReplyError('positive signed32 scanner slot count required')
    slots = [ReplySlot() for _ in range(count)]
    cursor = 0
    limit = len(payload) & 0xFFFFFFFF
    visited = set()
    while cursor < limit:
        if cursor in visited:
            raise QimeiReplyBoundary('nonterminating source scanner cycle', cursor, slots)
        visited.add(cursor)
        valid, tag, cursor = _varint(payload, cursor, limit)
        if not valid:
            break
        number, wire = (tag >> 3) & 0xFFFFFFFF, tag & 7
        if number > len(slots):
            break
        if wire not in (0, 1, 2):
            return ParsedReply(False, tuple(slots), cursor)
        valid, value, cursor = _varint(payload, cursor, limit)
        if not valid:
            continue
        if wire == 2:
            length = value & 0xFFFFFFFF
            following = (cursor + length) & 0xFFFFFFFF
            if following > limit:
                continue
            data = payload[cursor:cursor + length]
            cursor = following
            slot_tag = 1
        else:
            size = 4 if wire == 0 else 8
            data = (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
            slot_tag = 4 if wire == 0 else 5
        if number == 0:
            raise QimeiReplyBoundary('source field zero writes before slot array', cursor, slots)
        index = number - 1
        old = slots[index].data
        slots[index] = ReplySlot(slot_tag, old)
        if old is None and 0 < len(data) < 0x80000000:
            if _allocation(allocate, 'slot', index, len(data) + 1):
                slots[index] = ReplySlot(slot_tag, data)
    return ParsedReply(True, tuple(slots), cursor)


@dataclass
class QimeiReplyState:
    qimei: bytes = field(default=b'', repr=False)
    field2: bytes = field(default=b'', repr=False)
    field3: bytes = field(default=b'', repr=False)
    success: bool = False
    error: bytes = field(default=b'', repr=False)

    def decode(self, payload, *, allocate=None, observe=lambda *args: None):
        payload = _bytes(payload)
        if not payload or not _allocation(allocate, 'slots', None, 49):
            return None
        parsed = parse_reply(payload, allocate=allocate)
        if parsed.accepted:
            for index, name in enumerate(('qimei', 'field2', 'field3')):
                value = parsed.slots[index].cstr
                observe('reply-field', self, index, value)
                setattr(self, name, value)
            if self.qimei:
                self.success = True
        return parsed

    def receive(self, decoded_body, *, result_code, http_status, server_code,
                allocate=None, observe=lambda *args: None):
        http_status = _integer(http_status) & 0xFFFFFFFFFFFFFFFF
        if http_status != 200:
            key, value = b'net', http_status
        elif _integer(server_code) & 0xFFFFFFFFFFFFFFFF:
            key, value = b'sever', server_code & 0xFFFFFFFFFFFFFFFF
        else:
            key, value = b'local', _integer(result_code) & 0xFFFFFFFF
        if value:
            signed = value - (1 << 64) if value & (1 << 63) else value
            error = b'{"' + key + b'":"' + str(signed).encode('ascii') + b'"}'
            observe('reply-error', self, key, error)
            self.error = error
            return None
        return self.decode(decoded_body, allocate=allocate, observe=observe)


def _select(selector, observations):
    if isinstance(selector, QimeiSelectorState):
        selected = selector.select(observations if observations is not None else ContextObservations({}))
    elif callable(selector):
        selected = selector()
    else:
        raise QimeiReplyError('independent selector or explicit source callback required')
    if len(_bytes(selected)) != 6:
        raise QimeiReplyError('selected address must have exactly six bytes')
    return selected.hex().encode('ascii')


def commit_server_reply(startup, reply, *, selector, persist,
                        selector_observations=None, observe=lambda *args: None):
    if not isinstance(startup, StartupState) or not isinstance(reply, QimeiReplyState):
        raise QimeiReplyError('explicit startup and reply state required')
    qimei = _bytes(reply.qimei)
    if not qimei:
        return False
    startup.main.set(1, qimei + b'\0', observe)
    persist(startup.main)
    selected = _select(selector, selector_observations)
    startup.identity1.set(0, selected, observe)
    startup.identity1.set(1, _bytes(reply.field2), observe)
    persist(startup.identity1)
    selected = _select(selector, selector_observations)
    startup.identity1.set(0, selected, observe)
    startup.identity1.set(2, _bytes(reply.field3), observe)
    persist(startup.identity1)
    return True
