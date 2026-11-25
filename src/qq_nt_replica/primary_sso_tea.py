import struct

from .errors import InputError


MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9


def _bytes(value):
    if not isinstance(value, bytes):
        raise InputError('SSO_BYTES_REQUIRED')
    return value


def _key(value):
    if len(_bytes(value)) != 16:
        raise InputError('SSO_TEA_KEY_LENGTH')
    return struct.unpack('>4I', value)


def _mix(value, total, left, right):
    return (((value << 4) + left) ^ ((value + total) & MASK) ^ ((value >> 5) + right)) & MASK


def _block(hi, lo, key, decrypt=False):
    total = (DELTA * 16) & MASK if decrypt else 0
    for _ in range(16):
        if decrypt:
            lo = (lo - _mix(hi, total, key[2], key[3])) & MASK
            hi = (hi - _mix(lo, total, key[0], key[1])) & MASK
            total = (total - DELTA) & MASK
        else:
            total = (total + DELTA) & MASK
            hi = (hi + _mix(lo, total, key[0], key[1])) & MASK
            lo = (lo + _mix(hi, total, key[2], key[3])) & MASK
    return hi, lo


def tea_encrypt(data, key, *, random_padding):
    words = _key(key)
    data = _bytes(data)
    fill = 10 - ((len(data) + 1) & 7)
    if len(_bytes(random_padding)) != fill:
        raise InputError('SSO_TEA_ENTROPY_LENGTH')
    plain = bytearray(random_padding + data + bytes(7))
    plain[0] = (random_padding[0] & 0xF8) | ((fill - 3) & 7)
    output = bytearray()
    last_hi = last_lo = previous_hi = previous_lo = 0
    for offset in range(0, len(plain), 8):
        hi, lo = struct.unpack_from('>2I', plain, offset)
        hi, lo = hi ^ last_hi, lo ^ last_lo
        cipher_hi, cipher_lo = _block(hi, lo, words)
        last_hi, last_lo = cipher_hi ^ previous_hi, cipher_lo ^ previous_lo
        previous_hi, previous_lo = hi, lo
        output.extend(struct.pack('>2I', last_hi, last_lo))
    return bytes(output)


def tea_decrypt(data, key):
    words = _key(key)
    data = _bytes(data)
    if len(data) < 16 or len(data) % 8:
        raise InputError('SSO_TEA_DATA_LENGTH')
    plain = bytearray()
    last_hi = last_lo = previous_hi = previous_lo = 0
    for offset in range(0, len(data), 8):
        hi, lo = struct.unpack_from('>2I', data, offset)
        last_hi, last_lo = _block(last_hi ^ hi, last_lo ^ lo, words, True)
        plain.extend(struct.pack('>2I', last_hi ^ previous_hi, last_lo ^ previous_lo))
        previous_hi, previous_lo = hi, lo
    start, end = (plain[0] & 7) + 3, len(data) - 7
    if start >= end:
        raise InputError('SSO_TEA_PADDING')
    return bytes(plain[start:end])
