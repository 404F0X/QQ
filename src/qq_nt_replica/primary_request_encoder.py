from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import time

from .errors import InputError
from .primary_request_random import RequestRandom, _system_word, _word, device_random_bytes
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .wire import bytes_field, message, require_bytes, require_uint, u64_field


_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_IMAGE_SHA256 = '54ed76c2f9dfb385f50563a4454ada0de69ff089c3303a260dbed4c590de0355'


def _image():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/request-encoder-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed request encoder image identity mismatch')
    return json.loads(raw)


def _bytes(value, count, name):
    if not isinstance(value, bytes) or len(value) != count:
        raise InputError(name + ' requires exactly ' + str(count) + ' bytes')
    return value


def _scale(point, z):
    x, y = point
    return x * z * z % _P, y * z * z * z % _P


def _initial_double(point, z):
    x, y = _scale(point, z)
    yy = y * y % _P
    s = x * yy % _P
    m = 3 * (x * x - pow(z, 4, _P)) * ((_P + 1) // 2) % _P
    xx = (m * m - 2 * s) % _P
    zz = y * z % _P
    return [_scale(point, zz), (xx, (m * (s - xx) - yy * yy) % _P)]


def _add_coz(left, right, *, conjugate=False):
    x1, y1 = left
    x2, y2 = right
    d = (x2 - x1) % _P
    a, b = x1 * d * d % _P, x2 * d * d % _P
    c = y1 * (b - a) % _P
    delta = (y2 - y1) % _P
    plus = (delta * delta - a - b) % _P
    summed = plus, ((a - plus) * delta - c) % _P
    if not conjugate:
        return (a, c), summed
    total = (y2 + y1) % _P
    minus = (total * total - a - b) % _P
    return (minus, ((minus - a) * total - c) % _P), summed


def _point_multiply(scalar, point, blinding=1):
    points = _initial_double(point, blinding)
    for bit in range(scalar.bit_length() - 2, 0, -1):
        alternate = 1 ^ ((scalar >> bit) & 1)
        points[1 - alternate], points[alternate] = _add_coz(points[1 - alternate], points[alternate], conjugate=True)
        points[alternate], points[1 - alternate] = _add_coz(points[alternate], points[1 - alternate])
    alternate = 1 ^ (scalar & 1)
    points[1 - alternate], points[alternate] = _add_coz(points[1 - alternate], points[alternate], conjugate=True)
    z = (points[1][0] - points[0][0]) * points[1 - alternate][1] * point[0] % _P
    z = pow(z, _P - 2, _P) * point[1] * points[1 - alternate][0] % _P
    points[alternate], points[1 - alternate] = _add_coz(points[alternate], points[1 - alternate])
    return _scale(points[0], z)


def _decode_point(value):
    if value[0] not in (2, 3):
        raise PrimarySemanticUnavailable('request peer point prefix is outside the recovered compressed-point path')
    x = int.from_bytes(value[1:], 'big')
    square = (x * x * x - 3 * x + _B) % _P
    y = pow(square, (_P + 1) // 4, _P)
    if x >= _P or y * y % _P != square:
        raise PrimarySemanticUnavailable('request peer point is outside the recovered valid-point path')
    if y & 1 != value[0] & 1:
        y = _P - y
    return x, y


@dataclass(frozen=True)
class RequestKeyMaterial:
    encoded_peer: bytes
    public_key: bytes
    peer_key: bytes
    shared_x: bytes
    key: bytes


def _request_key(shared_x):
    extracted = hmac.digest(bytes(32), shared_x, 'sha256')
    return hmac.digest(extracted, b'\x01', 'sha256')


def derive_request_material(private_entropy, blinding_entropy, *, encoded_peer=None):
    _bytes(private_entropy, 32, 'request private entropy')
    _bytes(blinding_entropy, 32, 'request projective blinding entropy')
    image = _image()
    encoded_peer = bytes.fromhex(image['encoded_peer_hex']) if encoded_peer is None else encoded_peer
    _bytes(encoded_peer, 33, 'encoded request peer')
    mask = bytes.fromhex(image['peer_mask_hex'])
    rotated = encoded_peer[25:] + encoded_peer[:25]
    peer = bytes(byte ^ mask[index & 7] for index, byte in enumerate(rotated))
    scalar = int.from_bytes(private_entropy, 'little')
    if scalar == 0:
        raise PrimarySemanticUnavailable('request scalar retry/exhaustion requires its original CAPI event sequence')
    scalar %= _N
    raw_base = bytes.fromhex(image['curve_base_hex'])
    base = tuple(int.from_bytes(raw_base[index:index + 32], 'little') for index in (0, 32))
    public = _point_multiply(scalar, base)
    if public == (0, 0):
        raise PrimarySemanticUnavailable('request public point retry/exhaustion requires its original CAPI event sequence')
    shared = _point_multiply(scalar, _decode_point(peer), int.from_bytes(blinding_entropy, 'little'))
    shared_x = shared[0].to_bytes(32, 'big')
    key = _request_key(shared_x)
    return RequestKeyMaterial(encoded_peer, bytes([2 | (public[1] & 1)]) + public[0].to_bytes(32, 'big'),
                              peer, shared_x, key)


def _xtime(value):
    return ((value << 1) ^ (0x11B if value & 128 else 0)) & 255


def _aes_block(value, key, box):
    expanded = list(key)
    rounds = len(key) // 4 + 6
    rcon = 1
    while len(expanded) < 16 * (rounds + 1):
        word = expanded[-4:]
        if len(expanded) % len(key) == 0:
            word = [box[word[1]] ^ rcon, box[word[2]], box[word[3]], box[word[0]]]
            rcon = _xtime(rcon)
        elif len(key) == 32 and len(expanded) % 32 == 16:
            word = [box[item] for item in word]
        for item in word:
            expanded.append(item ^ expanded[-len(key)])
    state = [item ^ expanded[index] for index, item in enumerate(value)]
    for round_number in range(1, rounds + 1):
        state = [box[state[((column + row) % 4) * 4 + row]]
                 for column in range(4) for row in range(4)]
        if round_number != rounds:
            for column in range(0, 16, 4):
                a, b, c, d = state[column:column + 4]
                total = a ^ b ^ c ^ d
                state[column:column + 4] = [a ^ total ^ _xtime(a ^ b), b ^ total ^ _xtime(b ^ c),
                                            c ^ total ^ _xtime(c ^ d), d ^ total ^ _xtime(d ^ a)]
        state = [item ^ expanded[16 * round_number + index] for index, item in enumerate(state)]
    return bytes(state)


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _ghash_multiply(left, right):
    result = 0
    for bit in range(127, -1, -1):
        if left >> bit & 1:
            result ^= right
        right = (right >> 1) ^ (0xE1000000000000000000000000000000 if right & 1 else 0)
    return result


def encrypt_request_body(plain, key, nonce):
    require_bytes(plain, 'request plaintext')
    _bytes(key, 32, 'request AES256 key')
    _bytes(nonce, 12, 'request GCM nonce')
    if len(plain) > 0xFFFFFFFE0:
        raise PrimaryProgramLimit('request GCM plaintext exceeds original counter domain')
    box = bytes.fromhex(_image()['aes_sbox_hex'])
    hash_key = int.from_bytes(_aes_block(bytes(16), key, box), 'big')
    counter = nonce + b'\0\0\0\x01'
    ciphertext = bytearray()
    for offset in range(0, len(plain), 16):
        block = nonce + ((2 + offset // 16) & 0xFFFFFFFF).to_bytes(4, 'big')
        ciphertext.extend(_xor(plain[offset:offset + 16], _aes_block(block, key, box)))
    accumulator = 0
    for offset in range(0, len(ciphertext), 16):
        block = bytes(ciphertext[offset:offset + 16]).ljust(16, b'\0')
        accumulator = _ghash_multiply(accumulator ^ int.from_bytes(block, 'big'), hash_key)
    accumulator = _ghash_multiply(accumulator ^ (len(ciphertext) * 8), hash_key)
    tag = _xor(accumulator.to_bytes(16, 'big'), _aes_block(counter, key, box))
    return nonce + bytes(ciphertext) + tag


def request_fingerprint(digest, nonce):
    _bytes(digest, 32, 'request ciphertext digest')
    _bytes(nonce, 16, 'request fingerprint nonce')
    image = _image()
    box, key = bytes.fromhex(image['aes_sbox_hex']), bytes.fromhex(image['fingerprint_key_hex'])
    counter = int.from_bytes(nonce, 'big')
    result = bytearray(nonce)
    for offset in range(0, len(digest), 16):
        block = ((counter + offset // 16) & ((1 << 128) - 1)).to_bytes(16, 'big')
        result.extend(_xor(digest[offset:offset + 16], _aes_block(block, key, box)))
    return bytes(result)


@dataclass(frozen=True)
class EncodedMaterialRequest:
    wire: bytes
    plain: bytes
    ciphertext: bytes
    digest: bytes
    fingerprint: bytes


def _request_plain(tag, payload, material, device_random, message_id):
    require_bytes(tag, 'request operation tag')
    require_bytes(payload, 'request payload')
    if not isinstance(material, RequestKeyMaterial):
        raise InputError('request requires derived key material')
    _bytes(material.public_key, 33, 'request public key')
    _bytes(material.encoded_peer, 33, 'encoded request peer')
    _bytes(material.key, 32, 'request key')
    _bytes(device_random, 32, 'request device random')
    require_uint(message_id, 64, 'request message identifier')
    return message(u64_field(1, message_id) if message_id else b'',
                   bytes_field(2, payload) if payload else b'', bytes_field(3, device_random))


def _encode_material_request(tag, payload, material, device_random, message_id, nonce, fingerprint_nonce,
                             public_key_flag=1):
    require_uint(public_key_flag, 8, 'request public key flag')
    plain = _request_plain(tag, payload, material, device_random, message_id)
    ciphertext = encrypt_request_body(plain, material.key, nonce())
    digest = hashlib.sha256(ciphertext).digest()
    fingerprint = request_fingerprint(digest, fingerprint_nonce())
    wire = message(bytes_field(1, tag) if tag else b'', bytes_field(2, material.public_key),
                   u64_field(3, 1) if public_key_flag != 1 else b'',
                   bytes_field(4, material.encoded_peer.hex().encode('ascii')), bytes_field(5, ciphertext),
                   bytes_field(6, device_random), bytes_field(7, fingerprint), u64_field(8, 3))
    return EncodedMaterialRequest(wire, plain, ciphertext, digest, fingerprint)


def encode_material_request(tag, payload, material, device_random, message_id, nonce, fingerprint_nonce):
    return _encode_material_request(tag, payload, material, device_random, message_id,
                                    lambda: nonce, lambda: fingerprint_nonce)


def encode_material_request_with_random(tag, payload, material, device_random, message_id, random):
    if not isinstance(random, RequestRandom):
        raise InputError('request encoding requires current RequestRandom state')
    return _encode_material_request(tag, payload, material, device_random, message_id,
                                    lambda: random.draw_bytes(12), lambda: random.draw_bytes(16))


def encode_cached_material_request(tag, payload, material, device_random, message_id, random, *,
                                   payload_mode=0, public_key_flag=1):
    require_uint(payload_mode, 8, 'request payload mode')
    require_uint(public_key_flag, 8, 'request public key flag')
    if not isinstance(random, RequestRandom):
        raise InputError('cached request encoding requires current RequestRandom state')
    if payload_mode == 0:
        return _encode_material_request(tag, payload, material, device_random, message_id,
                                        lambda: random.draw_bytes(12), lambda: random.draw_bytes(16),
                                        public_key_flag)
    require_bytes(tag, 'request operation tag')
    require_bytes(payload, 'request payload')
    if not isinstance(material, RequestKeyMaterial):
        raise InputError('request requires derived key material')
    _bytes(material.key, 32, 'request key')
    _bytes(device_random, 32, 'request device random')
    ciphertext = encrypt_request_body(payload, material.key, random.draw_bytes(12))
    wire = message(bytes_field(1, tag) if tag else b'', bytes_field(2, ciphertext), bytes_field(3, device_random))
    return EncodedMaterialRequest(wire, payload, ciphertext, hashlib.sha256(ciphertext).digest(), b'')


@dataclass(frozen=True)
class FreshMaterialRequest:
    request: EncodedMaterialRequest
    material: RequestKeyMaterial
    device_random: bytes
    message_id: int
    random: RequestRandom


def encode_fresh_material_request(tag, payload, private_entropy, blinding_entropy, *,
                                  random=None, clock_ns=time.perf_counter_ns, random_word=_system_word):
    require_bytes(tag, 'request operation tag')
    require_bytes(payload, 'request payload')
    if random is not None and not isinstance(random, RequestRandom):
        raise InputError('fresh material request requires current RequestRandom state')
    material = derive_request_material(private_entropy, blinding_entropy)
    device_random = device_random_bytes(32, clock_ns=clock_ns, random_word=random_word)
    if random is None:
        random = RequestRandom(_word(random_word))
    message_id = int.from_bytes(random.draw_bytes(8), 'little')
    request = encode_material_request_with_random(tag, payload, material, device_random, message_id, random)
    return FreshMaterialRequest(request, material, device_random, message_id, random)
