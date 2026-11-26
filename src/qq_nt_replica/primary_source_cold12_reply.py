"""Finite selected-12 source decoder; parsing never authorizes runtime admission."""
from dataclasses import dataclass

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_sso_tea import tea_decrypt, _decrypt_attempt
from .primary_source_cold12 import SourceType1ReplyInputs, _project_peer


class _Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, count):
        end = self.offset + count
        if end > len(self.data):
            raise InputError('COLD12_REPLY_TRUNCATED')
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def word(self):
        return int.from_bytes(self.take(4), 'big')

    def string(self):
        length = self.word()
        if length < 4:
            raise InputError('COLD12_REPLY_L32_LENGTH')
        return self.take(length - 4)


@dataclass(frozen=True, repr=False)
class Cold12Reply:
    version: int
    encryption: int
    flag: int
    routing: bytes
    wire_sequence: int
    status: int
    first_string: bytes
    command: bytes
    third_string: bytes
    compression: int
    extension: tuple
    header_word: int
    payload: bytes


def _extension(raw):
    # 3E54707 accepts empty directly. The other supported domain is the
    # attested positive getter path, not arbitrary protobuf or arbitrary 20B.
    if not raw:
        return ()

    def fields(data, schema):
        reader = _Reader(data)
        values = {}
        while reader.offset < len(data):
            first = reader.take(1)[0]
            tag = first
            if first & 128:
                second = reader.take(1)[0]
                if second & 128 or second == 0:
                    raise PrimarySemanticUnavailable('cold12 extension tag outside canonical positive domain')
                tag = (first & 127) | second << 7
            number, wire = tag >> 3, tag & 7
            if number not in schema or number in values or wire != schema[number]:
                raise PrimarySemanticUnavailable('cold12 extension shape/getter outside positive domain')
            value = reader.take(1)[0]
            if value & 128:
                raise PrimarySemanticUnavailable('cold12 extension multibyte value/length outside positive domain')
            values[number] = reader.take(value) if wire == 2 else value
        if values.keys() != schema.keys():
            raise PrimarySemanticUnavailable('cold12 extension presence outside positive domain')
        return values

    top = fields(raw, {9: 0, 21: 0, 22: 2, 25: 0, 27: 0})
    child = fields(top[22], {1: 0, 2: 0, 3: 2})
    if child[3] != b'':
        raise PrimarySemanticUnavailable('cold12 nested bytes outside present-empty positive domain')
    top[22] = tuple(sorted(child.items()))
    return tuple(sorted(top.items()))


def decode_source_cold12_reply(frame, *, type1=None):
    """Decode exactly one prefix-inclusive frame in the proven finite domain.

    InputError denotes malformed supported framing; SemanticUnavailable denotes
    an unsupported source branch. Neither result authenticates SDK material.
    """
    if type1 is not None and type(type1) is not SourceType1ReplyInputs:
        raise InputError('type1 reply inputs required')
    if type(frame) is not bytes:
        raise InputError('COLD12_REPLY_IMMUTABLE_BYTES_REQUIRED')
    outer = _Reader(frame)
    if outer.word() != len(frame):
        raise InputError('COLD12_REPLY_COMPLETE_FRAME_REQUIRED')
    version = outer.word()
    if version != 12:
        raise PrimarySemanticUnavailable('cold12 reply received version is not selected12')
    encryption, flag = outer.take(2)
    routing = outer.string()
    body = frame[outer.offset:]
    if not body:
        raise InputError('COLD12_REPLY_EMPTY_BODY')
    if encryption == 2:
        body = tea_decrypt(body, bytes(16))
    elif encryption == 1:
        if type1 is None or routing != type1.routing_key:
            raise InputError('type1 current snapshot and received routing required')
        ok, count, accepted = _decrypt_attempt(body, _project_peer(type1.current, routing).key78, len(body))
        if not ok and type1.previous is not None:
            ok, count, accepted = _decrypt_attempt(body, _project_peer(type1.previous, routing).key78, count)
        if not ok or not accepted:
            raise InputError('type1 reply decrypt rejected')
        body = accepted
    elif encryption != 0:
        raise PrimarySemanticUnavailable('cold12 reply encryption requires unsupported peer/mode')
    reader = _Reader(body)
    head_length = reader.word()
    if head_length < 5:
        raise InputError('COLD12_REPLY_HEAD_LENGTH')
    head = _Reader(reader.take(head_length - 4))
    sequence, status = head.word(), head.word()
    if status & 0x80000000:
        status -= 1 << 32
    first, command, third = head.string(), head.string(), head.string()
    compression, extension = head.word(), head.string()
    # Source ignores the final read's BOOL. Do not guess its output on failure.
    if len(head.data) - head.offset < 4:
        raise PrimarySemanticUnavailable('cold12 unchecked final header DWORD output is unavailable')
    header_word = head.word()
    ext = _extension(extension)
    if command == b'GrayUinPro.Check' and len(body) - reader.offset >= 5:
        reader.take(4)
    payload = reader.string()
    if compression != 0:
        raise PrimarySemanticUnavailable('cold12 compression flags outside uncompressed positive domain')
    return Cold12Reply(version, encryption, flag, routing, sequence, status,
                       first, command, third, compression, ext, header_word, payload)
