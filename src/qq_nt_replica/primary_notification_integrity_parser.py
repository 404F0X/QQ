from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


class ManifestParseError(ValueError):
    pass


class _Reader:
    def __init__(self, value):
        self.value = value.split(b'\0', 1)[0]
        self.position = 0

    def _space(self):
        while self.position < len(self.value):
            if self.value[self.position] in b'\t\n\r ':
                self.position += 1
            elif self.value.startswith(b'//', self.position):
                self.position += 2
                while self.position < len(self.value) and self.value[self.position] not in (10, 13):
                    self.position += 1
            elif self.value.startswith(b'/*', self.position):
                end = self.value.find(b'*/', self.position + 2)
                if end < 0:
                    raise ManifestParseError('unterminated comment')
                self.position = end + 2
            else:
                break

    def _hex4(self):
        raw = self.value[self.position:self.position + 4]
        if len(raw) != 4 or any(value not in b'0123456789abcdefABCDEF' for value in raw):
            raise ManifestParseError('invalid unicode escape')
        self.position += 4
        return int(raw, 16)

    def _string(self):
        if self.value[self.position:self.position + 1] != b'"':
            raise ManifestParseError('expected String token')
        self.position += 1
        result = bytearray()
        escapes = {34: 34, 47: 47, 92: 92, 98: 8, 102: 12, 110: 10, 114: 13, 116: 9}
        while self.position < len(self.value):
            value = self.value[self.position]
            self.position += 1
            if value == 34:
                return bytes(result)
            if value != 92:
                result.append(value)
                continue
            if self.position == len(self.value):
                raise ManifestParseError('incomplete escape')
            value = self.value[self.position]
            self.position += 1
            if value in escapes:
                result.append(escapes[value])
            elif value == 117:
                point = self._hex4()
                if 0xD800 <= point <= 0xDBFF:
                    if self.value[self.position:self.position + 2] != b'\\u':
                        raise ManifestParseError('high surrogate lacks second unicode escape')
                    self.position += 2
                    point = 0x10000 + ((point & 0x3FF) << 10) + (self._hex4() & 0x3FF)
                if point < 0x80:
                    result.append(point)
                elif point < 0x800:
                    result.extend((0xC0 | point >> 6, 0x80 | point & 63))
                elif point < 0x10000:
                    result.extend((0xE0 | point >> 12, 0x80 | point >> 6 & 63, 0x80 | point & 63))
                else:
                    result.extend((0xF0 | point >> 18, 0x80 | point >> 12 & 63,
                                   0x80 | point >> 6 & 63, 0x80 | point & 63))
            else:
                raise ManifestParseError('invalid escape')
        raise ManifestParseError('unterminated String token')

    def _value(self):
        self._space()
        start = self.value[self.position:self.position + 1]
        if start == b'"':
            return self._string()
        for token, value in ((b'null', None), (b'true', True), (b'false', False)):
            if self.value.startswith(token, self.position):
                self.position += len(token)
                return value
        if start in (b'{', b'[') or start and start[0] in b'-0123456789':
            raise PrimarySemanticUnavailable('notification JsonCpp nested Value/number/real domain is not implemented')
        raise ManifestParseError('invalid Value token')

    def parse(self):
        self._space()
        if self.value.startswith(b'null', self.position):
            return None
        start = self.value[self.position:self.position + 1]
        if start != b'{':
            if start == b'"':
                self._string()
                raise PrimarySemanticUnavailable('notification JsonCpp nonobject root/asString exception domain is not implemented')
            if self.value.startswith((b'true', b'false'), self.position) or start == b'[' or start and start[0] in b'-0123456789':
                raise PrimarySemanticUnavailable('notification JsonCpp nonobject root/asString exception domain is not implemented')
            raise ManifestParseError('invalid root token')
        self.position += 1
        result = {}
        first, previous = True, b''
        while True:
            self._space()
            if self.value[self.position:self.position + 1] == b'}':
                if not first and previous:
                    raise ManifestParseError('trailing comma after nonempty member name')
                self.position += 1
                return result
            key = self._string()
            self._space()
            if self.value[self.position:self.position + 1] != b':':
                raise ManifestParseError('missing member separator')
            self.position += 1
            result[key] = self._value()
            previous, first = key, False
            self._space()
            end = self.value[self.position:self.position + 1]
            if end == b'}':
                self.position += 1
                return result
            if end != b',':
                raise ManifestParseError('missing object separator')
            self.position += 1


def parse_manifest(value):
    if not isinstance(value, bytes):
        raise InputError('notification manifest parser requires raw file bytes')
    if len(value) > 1 << 20:
        raise PrimaryProgramLimit('notification manifest exceeds its source file reader limit')
    try:
        return True, _Reader(value).parse()
    except ManifestParseError:
        return False, None


def field_string(value, name):
    if not isinstance(name, bytes) or value is not None and not isinstance(value, dict):
        raise InputError('notification manifest lookup requires its supported root and byte key')
    field = b'' if value is None else value.get(name, b'')
    if field is None:
        return b''
    if isinstance(field, bytes):
        return field
    if type(field) is bool:
        return b'true' if field else b'false'
    raise PrimarySemanticUnavailable('notification JsonCpp asString conversion domain is not implemented')
