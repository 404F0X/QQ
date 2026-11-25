"""Fixed52230 fresh cold/type2 byte encoding; no send, native admission or profile defaults."""
from dataclasses import dataclass
from .errors import InputError
from .primary_sso_tea import tea_encrypt
from .primary_sso_reserved import NativeReserveInputs, NativeReserveRecord, SignatureBytes, build_native_reserved_field
from .primary_source_cold12_counter import SourceCounter

_COMMANDS = (b'EcdhAccess.SsoEstablishShareKey', b'EcdhAccess.SsoSecureAccess')


def _uint(value, bits):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise InputError('source cold12 requires an unsigned%d value' % bits)
    return value.to_bytes(bits // 8, 'big')


def _bytes(value):
    if type(value) is not bytes:
        raise InputError('source cold12 requires immutable byte strings')
    return value


def _length(value, bits=32):
    return _uint(len(value) + bits // 8, bits) + value


@dataclass(frozen=True, repr=False)
class SourceCold12Reserve:
    context13: bytes | None
    field16: bytes | None
    field21: bool | None
    records23: tuple[NativeReserveRecord, ...]
    field26: int | None
    field32: bytes


@dataclass(frozen=True, repr=False)
class SourceCold12Options:
    dword0: int
    string8: bytes
    string20: bytes
    reserve: SourceCold12Reserve


@dataclass(frozen=True, repr=False)
class SourceCold12Request:
    command: bytes
    body: bytes
    wire_sequence: int
    routing: bytes


class SourceCold12Encoder:
    def __init__(self, inputs, *, routing_number, own_inputs):
        _uint(routing_number, 64)
        if type(own_inputs) is not bool:
            raise InputError('source input ownership must be explicit')
        self.inputs, self._owned, self._closed = inputs, own_inputs, False
        self.routing = str(routing_number).encode('ascii') if routing_number else b''
        try:
            self.counter = SourceCounter(inputs.entropy4)
        except BaseException:
            if own_inputs:
                inputs.close()
            raise

    def _check(self):
        if self._closed:
            raise InputError('source cold12 encoder is closed')

    def prepare(self, command, body):
        self._check()
        _bytes(command); _bytes(body)
        if command not in _COMMANDS:
            raise InputError('source cold12 supports only proven cold type2 commands')
        _uint(len(body) + 4, 32)
        # This allocation occurs before the caller signs; no rollback/re-sign/retry.
        return SourceCold12Request(command, body, self.counter.next(), self.routing)

    def encode_signed(self, request, *, options, signature_result):
        self._check()
        if type(request) is not SourceCold12Request or request.command not in _COMMANDS:
            raise InputError('source cold12 request data required')
        if type(options) is not SourceCold12Options or type(options.reserve) is not SourceCold12Reserve:
            raise InputError('complete explicit source options/reserve required')
        r = options.reserve
        for value in (options.string8, options.string20, r.field32, request.command, request.body, request.routing):
            _bytes(value)
        for value in (r.context13, r.field16):
            if value is not None: _bytes(value)
        signature = SignatureBytes.from_primary_result(signature_result)
        reserve = build_native_reserved_field(NativeReserveInputs(
            field12=options.string20, a13=r.context13, b13=None, field15=None,
            field16=r.field16, field21=r.field21, records23=r.records23,
            field26=r.field26, field32=r.field32), signature=signature)
        # Validate all sizes before entropy/host observations.
        parts = (_uint(request.wire_sequence, 32), _uint(options.dword0, 32), _uint(2052, 32),
                 bytes(12), _length(b''), _length(request.command), _length(b''),
                 _length(options.string20), _length(b''), _length(options.string8, 16), _length(reserve))
        head_size = 4 + sum(map(len, parts))
        _uint(head_size, 32)
        plain_size = head_size + 4 + len(request.body)
        encrypted_size = plain_size + 10 + (-(plain_size + 10) & 7)
        outer = _uint(12, 32) + b'\x02' + _length(b'') + b'\0' + _length(request.routing)
        total = _uint(4 + len(outer) + encrypted_size, 32)
        marker = self.inputs.host_marker()
        marker_byte = _uint(marker, 8)
        mixed = bytes(10) + marker_byte + b'\0'
        parts = parts[:3] + (mixed,) + parts[4:]
        plain = _uint(head_size, 32) + b''.join(parts) + _length(request.body)
        count = 10 - ((len(plain) + 1) & 7)
        entropy = self.inputs.padding_bytes(count)
        return total + outer + tea_encrypt(plain, bytes(16), random_padding=entropy)

    def close(self):
        if not self._closed:
            if self._owned: self.inputs.close()
            self._closed = True
