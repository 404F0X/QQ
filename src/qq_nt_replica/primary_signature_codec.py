from collections.abc import Callable

from .errors import InputError


_MODULI = (7292899946213130749, 8427298902244416217)


def _exact_bytes(value, length, name):
    if not isinstance(value, bytes) or len(value) != length:
        raise InputError(f'{name} must be exactly {length} bytes')
    return value


def _transpose(block):
    result = bytearray(16)
    for index, value in enumerate(block):
        result[((index & 12) >> 2) | ((index & 3) << 2)] = value
    return bytes(result)


def _crc16(raw):
    crc = 0xFFFF
    for value in raw:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xFFFF
    return crc


def _initial_iv(seed8):
    key = (seed8[0] * seed8[4]) & 0x7F
    return seed8 + bytes(key ^ seed8[7 - index] for index in range(8))


def _cbc_blocks(payload75, seed8, tail3_provider, m16callable):
    previous = _initial_iv(seed8)
    for offset in range(0, 80, 16):
        block = payload75[offset:offset + 16]
        if offset == 64:
            block += _exact_bytes(tail3_provider(), 3, 'tail3') + b'\x05\x05'
        mixed = bytes(left ^ right for left, right in zip(block, previous))
        transformed = _exact_bytes(m16callable(_transpose(mixed)), 16, 'M16 result')
        previous = _transpose(transformed)
        yield previous


def _seed_footer(seed8):
    output = bytearray()
    for index, modulus in enumerate(_MODULI):
        tagged = b'\x5A' + seed8[index * 4:index * 4 + 4]
        value = int.from_bytes(tagged + _crc16(tagged).to_bytes(2, 'big'), 'big')
        output.extend((value * value % modulus).to_bytes(8, 'big'))
    return bytes(output)


def _xor_outer(output):
    accumulator = 0
    for index in range(96):
        position = 47 - index // 2 if index % 2 == 0 else 48 + index // 2
        accumulator ^= output[position]
        output[position] = accumulator
        yield position, accumulator


def encode_primary_signature(payload75: bytes, seed8: bytes, tail3: bytes,
        m16callable: Callable[[bytes], bytes]) -> bytes:
    payload75 = _exact_bytes(payload75, 75, 'payload75')
    seed8 = _exact_bytes(seed8, 8, 'seed8')
    tail3 = _exact_bytes(tail3, 3, 'tail3')
    if not callable(m16callable):
        raise InputError('m16callable must be a callable accepting a 16-byte block')
    output = bytearray(b''.join(_cbc_blocks(payload75, seed8, lambda: tail3, m16callable)))
    output.extend(_seed_footer(seed8))
    for _ in _xor_outer(output):
        pass
    return bytes(output)
