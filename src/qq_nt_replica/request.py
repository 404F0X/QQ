"""Conditional QQ52230 Easy/Auth request wire builders.

All producer values are supplied by the caller. These functions do not produce
signatures, device data, keys, authentication material, or transport frames.
"""

from dataclasses import dataclass

from .errors import InputError
from .wire import bytes_field, check_length, message, require_bytes, require_uint
from .wire import u32_field, u64_field

EASY_SELECTOR = "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin"
AUTH_SELECTOR = "trpc.login.ecdh.EcdhService.SsoNTLoginAuthCodeLogin"


@dataclass(frozen=True)
class FinalX:
    s0: bytes
    s20: bytes
    s38: bytes
    s70: bytes
    s90: bytes
    v58: bytes
    v1a8: bytes
    x18: int
    x1c: int
    x50: int
    x1d8: int
    x88: int

    def __post_init__(self) -> None:
        for name in ("s0", "s20", "s38", "s70", "s90", "v58", "v1a8"):
            value = getattr(self, name)
            require_bytes(value, name)
            check_length(len(value), name)
        for name in ("x18", "x1c", "x50", "x1d8"):
            require_uint(getattr(self, name), 32, name)
        require_uint(self.x88, 64, "x88")


@dataclass(frozen=True)
class LoginRecord:
    byte_b8: int
    bytes_a0: bytes
    byte_1e8: int
    bytes_1d0: bytes

    def __post_init__(self) -> None:
        require_uint(self.byte_b8, 8, "byte_b8")
        require_uint(self.byte_1e8, 8, "byte_1e8")
        for name in ("bytes_a0", "bytes_1d0"):
            value = getattr(self, name)
            require_bytes(value, name)
            check_length(len(value), name)


@dataclass(frozen=True)
class RequestResult:
    kind: str | None
    selector: str | None
    payload: bytes | None
    notice: int | None
    builder_al: int | None


def build_common(x: FinalX) -> bytes:
    if not isinstance(x, FinalX):
        raise InputError("x must be FinalX")
    child1 = message(
        bytes_field(1, x.s0),
        u32_field(2, x.x1c) if x.x18 == 3 else b"",
    )
    child2 = message(
        bytes_field(1, x.s20), bytes_field(2, x.s38),
        u32_field(3, x.x50), bytes_field(4, x.v58),
    )
    child3 = message(
        bytes_field(1, x.s70), u64_field(2, x.x88), bytes_field(3, x.s90),
    )
    return message(
        bytes_field(1, child1), bytes_field(2, child2), bytes_field(3, child3),
        bytes_field(5, bytes_field(1, x.v1a8)) if x.v1a8 else b"",
        bytes_field(7, u32_field(1, x.x1d8)),
    )


def build_easy(x: FinalX, material: bytes) -> RequestResult:
    require_bytes(material, "Easy material")
    common = build_common(x)
    if not material:
        return RequestResult("easy", EASY_SELECTOR, None, 1, 0)
    payload = message(bytes_field(1, common), bytes_field(2, bytes_field(1, material)))
    return RequestResult("easy", EASY_SELECTOR, payload, None, 1)


def build_auth(x: FinalX, material: bytes) -> RequestResult:
    require_bytes(material, "Auth material")
    # Auth's empty-material gate precedes common construction; Easy's does not.
    if not material:
        return RequestResult("auth", AUTH_SELECTOR, None, 1, 0)
    common = build_common(x)
    body = message(bytes_field(1, material), u32_field(2, 3))
    payload = message(bytes_field(1, common), bytes_field(2, body))
    return RequestResult("auth", AUTH_SELECTOR, payload, None, 1)


def build_request(x: FinalX, record: LoginRecord) -> RequestResult:
    if not isinstance(x, FinalX) or not isinstance(record, LoginRecord):
        raise InputError("build_request requires FinalX and LoginRecord")
    if record.byte_b8 != 0:
        return build_easy(x, record.bytes_a0)
    if record.byte_1e8 != 0 and record.bytes_1d0:
        return build_auth(x, record.bytes_1d0)
    return RequestResult(None, None, None, 3, None)
