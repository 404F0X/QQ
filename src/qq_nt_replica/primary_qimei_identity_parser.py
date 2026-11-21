from dataclasses import dataclass, field


_SPACE = b'\t\n\r '
_ESCAPES = {34: 34, 47: 47, 92: 92, 98: 8, 102: 12, 110: 10, 114: 13, 116: 9}


class _Invalid(Exception):
    pass


@dataclass(frozen=True)
class IdentityProjection:
    accepted: bool
    slots: dict[bytes, bytes] = field(default_factory=dict, repr=False)

    def query(self, key):
        if not isinstance(key, bytes):
            raise TypeError('identity key must be bytes')
        return self.slots.get(key, b'') if self.accepted else b''


class _Parser:
    def __init__(self, payload, first, last):
        self.payload = payload
        self.position = first
        self.last = last

    def space(self):
        while self.position < self.last and self.payload[self.position] in _SPACE:
            self.position += 1

    def string(self):
        self.space()
        if self.position >= self.last or self.payload[self.position] != 34:
            raise _Invalid
        self.position += 1
        result = bytearray()
        escaped = False
        while self.position <= self.last:
            value = self.payload[self.position]
            self.position += 1
            if value == 92:
                if escaped:
                    result.append(92)
                    escaped = False
                else:
                    escaped = True
            elif escaped:
                if value == 117:
                    if self.position + 4 > self.last:
                        raise _Invalid
                    digits = self.payload[self.position:self.position + 4]
                    if any(v not in b'0123456789abcdefABCDEF' for v in digits):
                        raise _Invalid
                    result.append(int(digits[2:], 16))
                    self.position += 4
                elif value in _ESCAPES:
                    result.append(_ESCAPES[value])
                escaped = False
            elif value == 34:
                return bytes(result)
            else:
                result.append(value)
        raise _Invalid

    def value(self):
        self.space()
        if self.position > self.last:
            raise _Invalid
        value = self.payload[self.position]
        if value in (91, 123):
            self.container()
            return b''
        if value == 34:
            return self.string()
        first = self.position
        while self.position <= self.last and self.payload[self.position] not in b',]}':
            self.position += 1
        token = self.payload[first:self.position].strip(_SPACE)
        if not token:
            raise _Invalid
        return token

    def container(self):
        opening = self.payload[self.position]
        closing = 125 if opening == 123 else 93
        self.position += 1
        slots = {}
        while True:
            self.space()
            if self.position > self.last:
                return slots
            if self.payload[self.position] == closing:
                self.position += 1
                return slots
            if opening == 123:
                key = self.string()
                if not key:
                    raise _Invalid
                self.space()
                if self.position > self.last or self.payload[self.position] != 58:
                    raise _Invalid
                self.position += 1
                value = self.value()
                slots.setdefault(key, value)
            else:
                self.value()
            self.space()
            if self.position <= self.last and self.payload[self.position] == 44:
                self.position += 1


def parse_identity(payload):
    if not isinstance(payload, bytes):
        raise TypeError('identity payload must be bytes')
    first = 0
    last = len(payload) - 1
    while first <= last and payload[first] in _SPACE:
        first += 1
    while last >= first and payload[last] in _SPACE:
        last -= 1
    if first >= last or (payload[first], payload[last]) not in ((123, 125), (91, 93)):
        return IdentityProjection(False)
    parser = _Parser(payload, first, last)
    try:
        slots = parser.container()
    except _Invalid:
        return IdentityProjection(False)
    return IdentityProjection(True, slots if payload[first] == 123 else {})
