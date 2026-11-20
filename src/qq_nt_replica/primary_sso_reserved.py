from dataclasses import dataclass

from .errors import InputError
from .wire import bytes_field, message, u32_field
from .primary_sso_tea import _bytes


@dataclass(frozen=True, repr=False)
class SignatureBytes:
    sign: bytes
    token: bytes
    extra: bytes

    @classmethod
    def from_primary_result(cls, result):
        from .primary_signature_result import PrimarySignatureResult

        if not isinstance(result, PrimarySignatureResult):
            raise InputError('SSO_PRIMARY_SIGNATURE_RESULT')
        if not (result.sign or result.extra or result.token):
            return None
        return cls(sign=result.sign, token=result.extra, extra=result.token)


def _text(value):
    if not isinstance(value, str):
        raise InputError('SSO_TEXT_REQUIRED')
    try:
        return value.encode('utf-8')
    except UnicodeError:
        raise InputError('SSO_TEXT_UNICODE') from None


@dataclass(frozen=True, repr=False)
class NativeReserveRecord:
    name: bytes
    value: bytes


@dataclass(frozen=True, repr=False)
class NativeReserveInputs:
    field12: bytes = b''
    a13: bytes | None = None
    b13: bytes | None = None
    field15: bytes | None = None
    field16: bytes | None = None
    field21: bool | None = None
    records23: tuple[NativeReserveRecord, ...] = ()
    field26: int | None = None
    field32: bytes = b''


def build_native_reserved_field(inputs, *, signature=None):
    if not isinstance(inputs, NativeReserveInputs):
        raise InputError('SSO_NATIVE_RESERVE_INPUTS')
    if signature is not None and not isinstance(signature, SignatureBytes):
        raise InputError('SSO_SIGNATURE_BYTES')
    if inputs.field21 is not None and type(inputs.field21) is not bool:
        raise InputError('SSO_NATIVE_FIELD21')
    if inputs.field26 is not None and (
            type(inputs.field26) is not int or not 0 <= inputs.field26 < 1 << 32):
        raise InputError('SSO_NATIVE_FIELD26')
    if not isinstance(inputs.records23, tuple) or any(
            not isinstance(record, NativeReserveRecord) for record in inputs.records23):
        raise InputError('SSO_NATIVE_RECORDS23')
    field12, field32 = _bytes(inputs.field12), _bytes(inputs.field32)
    a13, b13, field15, field16 = (
        None if value is None else _bytes(value)
        for value in (inputs.a13, inputs.b13, inputs.field15, inputs.field16))
    records = tuple((_bytes(record.name), _bytes(record.value)) for record in inputs.records23)
    parts = [bytes_field(12, field12)] if field12 else []
    field13 = b13 if b13 is not None else a13
    serialize = field13 is not None
    for number, value in ((13, field13), (15, field15), (16, field16)):
        if value is not None:
            parts.append(bytes_field(number, value))
            serialize = True
    if inputs.field21 is True:
        parts.append(u32_field(21, 32))
        serialize = True
    for name, value in records:
        parts.append(bytes_field(23, bytes_field(1, name) + bytes_field(2, value)))
    if signature is not None:
        child = b''.join(bytes_field(number, value) for number, raw in enumerate(
            (signature.sign, signature.token, signature.extra), 1) if (value := _bytes(raw)))
        if child:
            parts.append(bytes_field(24, child))
            serialize = True
    if inputs.field26 is not None:
        parts.append(u32_field(26, inputs.field26))
        serialize = True
    if field32:
        parts.append(bytes_field(32, field32))
        serialize = True
    return message(*parts) if serialize else b''


def _string(number, value):
    return bytes_field(number, _text(value))


def _trace(nibbles, version, flags):
    if len(_bytes(nibbles)) != 48 or any(value > 15 for value in nibbles):
        raise InputError('SSO_TRACE_ENTROPY')
    text = ''.join('0123456789abcdef'[value] for value in nibbles)
    return f'{version}-{text[:32]}-{text[32:]}-{flags}'


def build_reserved_field(variant, *, uid, signature, guid_hex, command, timestamp_seconds, trace_nibbles, qimei36=''):
    if variant not in ('nt', 'linux', 'macos', 'watch'):
        raise InputError('SSO_RESERVE_VARIANT')
    for value in (uid, guid_hex, command, qimei36):
        _text(value)
    if type(timestamp_seconds) is not int or not 0 <= timestamp_seconds <= (1 << 53) - 1:
        raise InputError('SSO_TIMESTAMP_SECONDS')
    if signature is not None and not isinstance(signature, SignatureBytes):
        raise InputError('SSO_SIGNATURE_BYTES')
    parts = []
    if variant == 'macos':
        parts.append(u32_field(9, 1))
    identifier = qimei36 if variant == 'watch' else guid_hex
    if identifier or variant == 'macos':
        parts.append(_string(12, identifier))
    no_trace = variant == 'linux' and ('.o3.' in command or command == 'ConfigPushSvc.PushResp')
    if variant in ('nt', 'linux') and not no_trace:
        parts.append(bytes_field(13, b'\0'))
    if variant == 'macos':
        parts.append(u32_field(14, 1))
    if not no_trace:
        flags = '00' if variant == 'linux' and not command.startswith('wtlogin.') else '01'
        parts.append(_string(15, _trace(trace_nibbles, '01' if variant == 'watch' else '00', flags)))
    if uid and not (variant == 'linux' and 'SsoEstablishShareKey' in command):
        parts.append(_string(16, uid))
    if variant == 'macos':
        parts.extend(u32_field(number, value) for number, value in ((18, 0), (19, 1), (20, 1), (21, 2)))
    if variant == 'watch':
        parts.append(u32_field(21, 32))
    else:
        parts.append(bytes_field(23, _string(1, 'client_conn_seq') + _string(2, str(timestamp_seconds))))
    if signature is not None:
        sec = []
        for number, value in enumerate((signature.sign, signature.token, signature.extra), 1):
            if _bytes(value):
                sec.append(bytes_field(number, value))
        parts.append(bytes_field(24, b''.join(sec)))
    parts.append(u32_field(26, 100 if variant in ('macos', 'watch') else 101))
    if variant == 'macos':
        parts.extend((u32_field(28, 3), u32_field(34, 1)))
    return b''.join(parts)
