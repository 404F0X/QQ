"""Unsigned outbound primitives for the request's fixed field keys."""

from .errors import InputError, LibraryLimitError

INT32_MAX = (1 << 31) - 1
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1


def require_uint(value: int, bits: int, name: str) -> None:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise InputError(f"{name} must be an unsigned {bits}-bit integer")


def require_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise InputError(f"{name} must be bytes")


def check_length(length: int, name: str) -> None:
    if length > INT32_MAX:
        raise LibraryLimitError(
            f"{name} exceeds this Python library's INT32_MAX support domain; "
            "native overflow/failure behavior is not modeled"
        )


def encode_u64(value: int) -> bytes:
    require_uint(value, 64, "value")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_u32(value: int) -> bytes:
    require_uint(value, 32, "value")
    return encode_u64(value)


def _tag(key: int, kind: int) -> bytes:
    require_uint(key, 29, "field key")
    if key == 0:
        raise InputError("outbound field key must be nonzero")
    return encode_u32((key << 3) | kind)


def bytes_field(key: int, value: bytes) -> bytes:
    require_bytes(value, "field value")
    check_length(len(value), "bytes field")
    return message(_tag(key, 2), encode_u32(len(value)), value)


def u32_field(key: int, value: int) -> bytes:
    return _tag(key, 0) + encode_u32(value)


def u64_field(key: int, value: int) -> bytes:
    return _tag(key, 0) + encode_u64(value)


def message(*parts: bytes) -> bytes:
    check_length(sum(map(len, parts)), "message")
    return b"".join(parts)
