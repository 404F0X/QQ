from dataclasses import dataclass
import struct
import zlib

from .errors import InputError
from .primary_sso_reserved import NativeReserveInputs, build_native_reserved_field, build_reserved_field, _text
from .primary_sso_tea import tea_encrypt, tea_decrypt, _bytes


@dataclass(frozen=True, repr=False)
class PacketContext:
    uin: str
    uid: str
    d2: bytes
    d2_key: bytes
    tgt: bytes
    guid: bytes
    app_id: int
    sub_app_id: int
    build_ver: str


@dataclass(frozen=True)
class SsoProfile:
    protocol_version: int
    reserve_variant: str
    head_field8: int | None = None
    head_field12: int | None = None
    fixed_header: bytes | None = None
    head_version: str | None = None
    native_reserve: NativeReserveInputs | None = None


@dataclass(frozen=True, repr=False)
class SsoPacket:
    seq: int
    command: str
    payload: bytes
    ret_code: int | None = None
    extra_message: str | None = None


def _integer(value, bits):
    if type(value) is not int or not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        raise InputError('SSO_SIGNED_INTEGER_RANGE')
    return value.to_bytes(bits // 8, 'big', signed=True)


def _prefixed(data, bits=32):
    return _integer(len(data) + bits // 8, bits) + data


def _reserve(profile, ctx, command, signature, timestamp_seconds, trace_nibbles):
    if profile.reserve_variant == 'native_ff2' or profile.native_reserve is not None:
        if profile.reserve_variant != 'native_ff2':
            raise InputError('SSO_NATIVE_RESERVE_PROFILE')
        return build_native_reserved_field(profile.native_reserve, signature=signature)
    return build_reserved_field(profile.reserve_variant, uid=ctx.uid, signature=signature,
        guid_hex=_bytes(ctx.guid).hex(), command=command, timestamp_seconds=timestamp_seconds,
        trace_nibbles=trace_nibbles)


def _encrypt(body, ctx, encrypt_type, tea_padding):
    if type(encrypt_type) is not int or encrypt_type not in (0, 1, 2):
        raise InputError('SSO_ENCRYPT_TYPE')
    if encrypt_type:
        return tea_encrypt(body, ctx.d2_key if encrypt_type == 1 else bytes(16), random_padding=tea_padding)
    return body


def build_service_packet(seq, command, ctx, payload, *, profile, encrypt_type, signature,
                         timestamp_seconds=None, trace_nibbles=None, tea_padding):
    reserve = _reserve(profile, ctx, command, signature, timestamp_seconds, trace_nibbles)
    fixed = b'\x02' + bytes(11) if profile.fixed_header is None else _bytes(profile.fixed_header)
    head = b''.join((
        _integer(seq, 32),
        _integer(ctx.sub_app_id if profile.head_field8 is None else profile.head_field8, 32),
        _integer(2052 if profile.head_field12 is None else profile.head_field12, 32),
        fixed, _prefixed(_bytes(ctx.tgt)), _prefixed(_text(command)), _prefixed(b''),
        _prefixed(_bytes(ctx.guid).hex().encode('ascii')), _prefixed(b''),
        _prefixed(_text(ctx.build_ver if profile.head_version is None else profile.head_version), 16),
        _prefixed(reserve)))
    body = _encrypt(_prefixed(head) + _prefixed(_bytes(payload)), ctx, encrypt_type, tea_padding)
    d2 = _bytes(ctx.d2) if encrypt_type == 1 else b''
    inner = (_integer(profile.protocol_version, 32) + bytes((encrypt_type,)) + _prefixed(d2)
        + b'\0' + _prefixed(_text(ctx.uin)) + body)
    return _prefixed(inner)


def build_service_packet13(seq, command, ctx, payload, *, profile, encrypt_type,
                           timestamp_seconds=None, trace_nibbles=None, tea_padding):
    reserve = _reserve(profile, ctx, command, None, timestamp_seconds, trace_nibbles)
    head = _prefixed(_text(command)) + _prefixed(b'') + _prefixed(reserve)
    body = _encrypt(_prefixed(head) + _prefixed(_bytes(payload)), ctx, encrypt_type, tea_padding)
    inner = _integer(13, 32) + bytes((encrypt_type,)) + _integer(seq, 32) + b'\0' + _prefixed(_text(ctx.uin)) + body
    return _prefixed(inner)


def _read(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise InputError('SSO_HEADER_BOUNDS')
    return struct.unpack_from('>i', data, offset)[0]


def _subarray(data, start, end=None):
    length = len(data)
    start = max(length + start, 0) if start < 0 else min(start, length)
    if end is None:
        end = length
    end = max(length + end, 0) if end < 0 else min(end, length)
    return data[start:max(start, end)]


def parse_sso_frame12(data):
    data = _bytes(data)
    if len(data) < 4:
        return None
    head_end = _read(data, 0)
    if head_end > len(data):
        return None
    seq, ret_code = _read(data, 4), _read(data, 8)
    offset = 12
    if offset + 4 > head_end:
        return None
    extra_length = _read(data, offset)
    offset += 4
    extra = ''
    if extra_length > 4:
        extra = _subarray(data, offset, offset + extra_length - 4).decode('utf-8', 'replace')
        offset += extra_length - 4
    if offset + 4 > head_end:
        return None
    command_length = _read(data, offset)
    offset += 4
    command = _subarray(data, offset, offset + command_length - 4).decode('utf-8', 'replace')
    offset = head_end
    if offset + 4 > len(data):
        return None
    body_length = _read(data, offset)
    offset += 4
    payload = _subarray(data, offset, offset + body_length - 4)
    if len(payload) >= 2 and payload[0] == 0x78 and payload[1] in (1, 0x9C, 0xDA):
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            pass
    return SsoPacket(seq, command, payload, ret_code, extra)


def parse_sso_frame13(data, seq):
    data = _bytes(data)
    if len(data) < 4:
        return None
    head_end = _read(data, 0)
    if 8 > head_end:
        return None
    command_length = _read(data, 4)
    command = _subarray(data, 8, 8 + command_length - 4).decode('utf-8', 'replace')
    if head_end + 4 > len(data):
        return None
    body_length = _read(data, head_end)
    return SsoPacket(seq, command, _subarray(data, head_end + 4, head_end + body_length))


def parse_service_packet(frame, d2_key):
    frame = _bytes(frame)
    _read(frame, 0)
    if len(frame) < 5:
        raise InputError('SSO_HEADER_BOUNDS')
    encrypt_type = frame[4]
    uin_length = _read(frame, 6)
    offset = 10 + max(uin_length - 4, 0)
    encrypted = _subarray(frame, offset)
    if encrypt_type in (1, 2):
        try:
            body = tea_decrypt(encrypted, d2_key if encrypt_type == 1 else bytes(16))
        except InputError:
            return None
    else:
        body = encrypted
    return parse_sso_frame12(body)


def split_frames(buffer):
    buffer = _bytes(buffer)
    frames = []
    offset = 0
    while len(buffer) - offset >= 4:
        length = struct.unpack_from('>I', buffer, offset)[0]
        if length > 64 * 1024 * 1024:
            raise InputError('SSO_FRAME_TOO_LARGE')
        if length < 4:
            raise InputError('SSO_FRAME_LENGTH_UNSUPPORTED')
        if len(buffer) - offset < length:
            break
        frames.append(buffer[offset + 4:offset + length])
        offset += length
    return tuple(frames), buffer[offset:]
