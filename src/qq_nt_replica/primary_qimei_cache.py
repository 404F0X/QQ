import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .primary_request_encoder import _aes_block, _image, _xtime, _xor


DLL_SHA256 = 'a6100bce0de79ea52fe80a85acce2c24c615306fd3c2dedd119b51b0f26ebcc6'
DEFAULT_DLL = Path('D:/QQ/versions/9.9.33-52230/resources/app/win64/qimei.dll')


class QimeiCacheError(ValueError):
    pass


def _bytes(value):
    if not isinstance(value, bytes):
        raise QimeiCacheError('explicit byte input required')
    return value


def _digest(value):
    return {'length': None if value is None else len(value),
            'sha256': None if value is None else hashlib.sha256(value).hexdigest()}


def _decrypt_block(block, key, box):
    expanded = list(key)
    rcon = 1
    while len(expanded) < 176:
        word = expanded[-4:]
        if len(expanded) % 16 == 0:
            word = [box[word[1]] ^ rcon, box[word[2]], box[word[3]], box[word[0]]]
            rcon = _xtime(rcon)
        for item in word:
            expanded.append(item ^ expanded[-16])
    inverse = [0] * 256
    for index, value in enumerate(box):
        inverse[value] = index
    state = list(block)
    for round_number in range(10, 0, -1):
        state = [item ^ expanded[16 * round_number + i] for i, item in enumerate(state)]
        if round_number != 10:
            for col in range(0, 16, 4):
                a, b, c, d = state[col:col + 4]
                u, v = _xtime(_xtime(a ^ c)), _xtime(_xtime(b ^ d))
                a, b, c, d = a ^ u, b ^ v, c ^ u, d ^ v
                total = a ^ b ^ c ^ d
                state[col:col + 4] = [a ^ total ^ _xtime(a ^ b), b ^ total ^ _xtime(b ^ c),
                                      c ^ total ^ _xtime(c ^ d), d ^ total ^ _xtime(d ^ a)]
        state = [inverse[state[((column - row) % 4) * 4 + row]]
                 for column in range(4) for row in range(4)]
    return bytes(value ^ expanded[i] for i, value in enumerate(state))


def _cbc(value, key, iv, *, decrypt=False):
    if len(_bytes(key)) != 16 or len(_bytes(iv)) != 16 or len(_bytes(value)) % 16:
        raise QimeiCacheError('CBC requires AES128 key, IV and complete blocks')
    box = bytes.fromhex(_image()['aes_sbox_hex'])
    result = bytearray()
    previous = iv
    for offset in range(0, len(value), 16):
        block = value[offset:offset + 16]
        if decrypt:
            result.extend(_xor(_decrypt_block(block, key, box), previous))
            previous = block
        else:
            previous = _aes_block(_xor(block, previous), key, box)
            result.extend(previous)
    return bytes(result)


@dataclass(frozen=True)
class QimeiCacheConstants:
    magic: bytes = field(repr=False)
    fallback_immediate: bytes = field(repr=False)

    @classmethod
    def from_dll_bytes(cls, raw):
        if hashlib.sha256(_bytes(raw)).hexdigest() != DLL_SHA256:
            raise QimeiCacheError('fixed qimei DLL identity mismatch')
        magic, fallback = raw[0x9E3AF:0x9E3B3], raw[0x9E4EC:0x9E4F0]
        if (hashlib.sha256(magic).hexdigest() != '0ff347e4d3968c05385f66b7f031a9f2729f09fdca7917c740affeee2807f07a'
                or hashlib.sha256(fallback).hexdigest() != '9e816084c4fc4ceec2a2841cb46cb4f353f8bb8e7472588991aa6757bc853d0b'):
            raise QimeiCacheError('fixed qimei constants mismatch')
        return cls(magic, fallback)

    @classmethod
    def from_dll(cls, path=DEFAULT_DLL):
        return cls.from_dll_bytes(Path(path).read_bytes())

    def metadata(self):
        return {'source_sha256': DLL_SHA256,
                'magic': dict(_digest(self.magic), source_offset=0x9E3AF),
                'fallback_immediate': dict(_digest(self.fallback_immediate), source_offset=0x9E4EC)}

    def key(self, *, context=None, selected6=None):
        if (context is None) == (selected6 is None):
            raise QimeiCacheError('provide exactly one explicit context or SDK-selected six bytes')
        if selected6 is not None:
            if len(_bytes(selected6)) != 6:
                raise QimeiCacheError('SDK-selected input must contain six bytes')
            context = selected6.hex().encode('ascii')
        context = _bytes(context).split(b'\0', 1)[0]
        if not context:
            context = str(int.from_bytes(self.fallback_immediate, 'little', signed=False)).encode('ascii')
        return context[:15].ljust(16, b'\0')


@dataclass(frozen=True)
class CacheRecords:
    record0: bytes | None = field(default=None, repr=False)
    record1: bytes | None = field(default=None, repr=False)

    def __post_init__(self):
        for value, size in ((self.record0, 16), (self.record1, 37)):
            if value is not None and len(_bytes(value)) != size:
                raise QimeiCacheError('known previous record requires its complete logical capacity')

    def metadata(self):
        return {'record0': _digest(self.record0), 'record1': _digest(self.record1)}


@dataclass(frozen=True)
class EncodedCache:
    value: bytes = field(repr=False)

    def metadata(self):
        return _digest(self.value)


@dataclass(frozen=True)
class PayloadDecodeResult:
    status: str
    source_code: int | None
    accepted: bool | None
    payload_length: int | None
    payload: bytes | None = field(repr=False)

    @property
    def copied_length(self):
        return 0 if self.payload is None else len(self.payload)

    def metadata(self):
        return {'status': self.status, 'source_code': self.source_code, 'accepted': self.accepted,
                'payload_length': self.payload_length, 'copied_length': self.copied_length,
                'payload': _digest(self.payload)}


@dataclass(frozen=True)
class CacheReadResult:
    status: str
    source_code: int | None
    accepted: bool | None
    payload_length: int | None
    copied_length: int
    updated_records: tuple[int, ...]
    records: CacheRecords

    def metadata(self):
        return {'status': self.status, 'source_code': self.source_code, 'accepted': self.accepted,
                'payload_length': self.payload_length, 'copied_length': self.copied_length,
                'updated_records': list(self.updated_records), 'records': self.records.metadata()}


class QimeiCacheCodec:
    def __init__(self, dll_path=DEFAULT_DLL):
        self.constants = QimeiCacheConstants.from_dll(dll_path)

    def encode_payload(self, payload, *, context=None, selected6=None):
        payload = _bytes(payload)
        if len(payload) > 0xFFFFFFFF:
            raise QimeiCacheError('cache payload exceeds source DWORD length')
        key = self.constants.key(context=context, selected6=selected6)
        plain = self.constants.magic + len(payload).to_bytes(4, 'little') + payload
        padding = 16 - len(plain) % 16
        return EncodedCache(_cbc(plain + bytes([padding]) * padding, key, key))

    def encode_records(self, record0, record1, *, context=None, selected6=None):
        payload = _bytes(record0)[:16].ljust(16, b'\0') + _bytes(record1)[:37].ljust(37, b'\0')
        return self.encode_payload(payload, context=context, selected6=selected6)

    def decode_payload(self, ciphertext, *, capacity, context=None, selected6=None):
        ciphertext = _bytes(ciphertext)
        if type(capacity) is not int or not -(1 << 31) <= capacity < 1 << 32:
            raise QimeiCacheError('payload capacity requires DWORD bits')
        capacity &= 0xFFFFFFFF
        capacity = capacity - (1 << 32) if capacity & 0x80000000 else capacity
        key = self.constants.key(context=context, selected6=selected6)

        def fail(code, status):
            return PayloadDecodeResult(status, code, False, None, None)

        if not ciphertext:
            return fail(2, 'empty-ciphertext')
        if len(ciphertext) % 16:
            return fail(3, 'decrypt-or-padding-failed')
        plain = _cbc(ciphertext, key, key, decrypt=True)
        padding = plain[-1]
        if not 1 <= padding <= 16 or plain[-padding:] != bytes([padding]) * padding:
            return fail(3, 'decrypt-or-padding-failed')
        plain = plain[:-padding]
        if not plain:
            return fail(3, 'nonpositive-plaintext')
        if len(plain) < 8:
            return PayloadDecodeResult('source-undefined-short-header', None, None, None, None)
        if plain[:4] != self.constants.magic:
            return fail(4, 'magic-mismatch')
        length = int.from_bytes(plain[4:8], 'little')
        if length != len(plain) - 8:
            return fail(5, 'declared-length-mismatch')
        copied = min(length, capacity)
        if copied < 0:
            return PayloadDecodeResult('source-undefined-negative-copy', None, None, length, None)
        if copied == 0:
            return PayloadDecodeResult('empty-payload', 0, False, length, b'')
        return PayloadDecodeResult('accepted-payload', 0, True, length, plain[8:8 + copied])

    def read(self, ciphertext, *, context=None, selected6=None, previous=None):
        ciphertext = _bytes(ciphertext)
        previous = CacheRecords() if previous is None else previous
        if not isinstance(previous, CacheRecords):
            raise QimeiCacheError('previous state must be explicit cache records')
        decoded = self.decode_payload(ciphertext, capacity=53, context=context, selected6=selected6)
        if not decoded.accepted:
            return CacheReadResult(decoded.status, decoded.source_code, decoded.accepted,
                                   decoded.payload_length, 0, (), previous)
        copied = decoded.copied_length
        record0, record1 = previous.record0, previous.record1
        updated = []
        if copied >= 16:
            record0 = decoded.payload[:16]
            updated.append(0)
        if copied >= 53:
            record1 = decoded.payload[16:53]
            updated.append(1)
        return CacheReadResult('accepted-partial-records' if copied < 53 else 'accepted-records',
                               0, True, decoded.payload_length, copied, tuple(updated), CacheRecords(record0, record1))
