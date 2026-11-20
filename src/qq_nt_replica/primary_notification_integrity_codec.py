import hashlib
import hmac
from pathlib import Path

from .errors import InputError


_KEY_SHA256 = '1aa99e89c071cd65d4191b584b3a94141c7618821a57d26542fd406ad7374f69'
_ALPHABET = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
_VALUES = {value: index for index, value in enumerate(_ALPHABET)}


def decoded_length(length):
    if type(length) is not int or not 0 <= length <= (1 << 64) - 1:
        raise InputError('Base64 input length requires an unsigned size_t')
    return None if length & 3 else 3 * (length // 4)


def decode_base64(value, output):
    if not isinstance(value, bytes) or not isinstance(output, bytearray):
        raise InputError('Base64 requires exact input bytes and mutable output storage')
    upper = decoded_length(len(value))
    if upper is None or len(output) < upper:
        return False, 0
    written = 0
    for offset in range(0, len(value), 4):
        a, b, c, d = value[offset:offset + 4]
        if a not in _VALUES or b not in _VALUES:
            return False, 0
        first, second = _VALUES[a], _VALUES[b]
        if c == 61:
            if d != 61:
                return False, 0
            block = bytes([(first << 2) | (second >> 4)])
        elif c in _VALUES:
            third = _VALUES[c]
            if d == 61:
                block = bytes([(first << 2) | (second >> 4), ((second << 4) | (third >> 2)) & 255])
            elif d in _VALUES:
                block = bytes([(first << 2) | (second >> 4), ((second << 4) | (third >> 2)) & 255,
                               ((third << 6) | _VALUES[d]) & 255])
            else:
                return False, 0
        else:
            return False, 0
        output[written:written + len(block)] = block
        written += len(block)
        if len(block) != 3 and offset + 4 != len(value):
            return False, 0
    return True, written


def decode_signature(value):
    if not isinstance(value, bytes):
        raise InputError('manifest signature requires its length-preserving String bytes')
    if not 1 <= len(value) <= 65536:
        return None
    upper = decoded_length(len(value))
    if upper is None or not 1 <= upper <= 65536:
        return None
    output = bytearray(upper)
    successful, ignored = decode_base64(value, output)
    if not successful:
        return None
    size = upper
    while size > 256 and not output[size - 1]:
        size -= 1
    return bytes(output[:size])


def public_key():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'notification-integrity-spki.der').read_bytes()
    if len(raw) != 294 or hashlib.sha256(raw).hexdigest() != _KEY_SHA256:
        raise InputError('notification integrity public key differs from its fixed source')
    if raw[:33] != bytes.fromhex('30820122300d06092a864886f70d01010105000382010f003082010a0282010100'):
        raise InputError('notification integrity SPKI header differs from its fixed source')
    modulus = int.from_bytes(raw[33:289], 'big')
    if raw[289:] != b'\x02\x03\x01\0\x01' or modulus.bit_length() != 2048:
        raise InputError('notification integrity RSA parameters differ from their source domain')
    return raw, modulus, 65537


def _mgf1(seed, size):
    return b''.join(hashlib.sha256(seed + counter.to_bytes(4, 'big')).digest()
                    for counter in range((size + 31) // 32))[:size]


def verify_encoded_message(message_hash, encoded):
    if not isinstance(message_hash, bytes) or len(message_hash) != 32 or not isinstance(encoded, bytes):
        raise InputError('PSS requires its SHA256 message hash and exact encoded bytes')
    if len(encoded) != 256 or encoded[-1] != 0xBC or encoded[0] & 0x80:
        return False
    masked, digest = encoded[:223], encoded[223:255]
    data = bytearray(left ^ right for left, right in zip(masked, _mgf1(digest, 223)))
    data[0] &= 0x7F
    if data[:190] != bytes(190) or data[190] != 1:
        return False
    expected = hashlib.sha256(bytes(8) + message_hash + data[191:]).digest()
    return hmac.compare_digest(digest, expected)


def verify_signature(signature, file_digest_hex):
    if (not isinstance(signature, bytes) or not isinstance(file_digest_hex, bytes) or
            len(file_digest_hex) != 64 or any(value not in b'0123456789abcdef' for value in file_digest_hex)):
        raise InputError('manifest PSS requires actual signature bytes and lowercase SHA256 ASCII hex')
    if len(signature) != 256:
        return False
    ignored, modulus, exponent = public_key()
    integer = int.from_bytes(signature, 'big')
    if integer >= modulus:
        return False
    encoded = pow(integer, exponent, modulus).to_bytes(256, 'big')
    return verify_encoded_message(hashlib.sha256(file_digest_hex).digest(), encoded)
