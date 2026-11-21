import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass, field

from .primary_qimei_cache import _cbc
from .primary_qimei_envelope import QimeiEnvelopeConfiguration
from .primary_qimei_extras import QimeiRequestExtras
from .primary_qimei_request import QimeiRequestBoundary, _bytes, _integer
from .primary_qimei_transport_random import QimeiTransportRandom


PUBLIC_KEY_B64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApLEpcsiHA/PE4MKl7WS7r11RijhytmEQH8jaY3nKhvq/KC29yEpJVAu+/asRp9mpoxCAiaTxJynVZMw5amwe24ff0Eau/MLCcfG9jFq8fp0LJwXmKtJuwha2hVr6zhW1+Q1h8f3T9hu+QMZTRxqQnIY1mjqDY1/ARAK2hMzS+uoB+COosppWgFxOcQhzkjcM7Oa0RO+rSaatWsgBrKspVEXFMYfHS+awD8qGXZyyOVaiDNvXgLfPecJerKCOFdujwR3isgtEEe8yyRryUm1FZgdIi8e+t23Lp0XDDB6LCox7DWLKmRjQ5K/5R7+HmSwNLANkw6yTUuLtYcoMY2nOUwIDAQAB'
DEFAULT_K = bytes.fromhex('a7aff789b8ec69e1454f2689fbb89bdf')
DEFAULT_IV = bytes.fromhex('353c9fc8b84b5882b00591dae8e81cc4')
SIGN_F = bytes.fromhex('b435b4069b69ad11ed309651f7dbfa2d')
SIGN_NONCE = bytes.fromhex('a3a244ef7fe5a465')


def _chacha20(key, nonce, data, counter=0):
    state = list(struct.unpack('<4I', b'expand 32-byte k') + struct.unpack('<8I', key) + (counter & 0xffffffff, counter >> 32) + struct.unpack('<2I', nonce))
    result = bytearray()
    for offset in range(0, len(data), 64):
        words = state.copy()
        def quarter(a, b, c, d):
            for x, y, z, shift in ((a, b, d, 16), (c, d, b, 12), (a, b, d, 8), (c, d, b, 7)):
                words[x] = (words[x] + words[y]) & 0xffffffff
                value = words[z] ^ words[x]
                words[z] = ((value << shift) | (value >> (32 - shift))) & 0xffffffff
        for unused in range(10):
            for indices in ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)):
                quarter(*indices)
        stream = struct.pack('<16I', *((a + b) & 0xffffffff for a, b in zip(words, state)))
        result.extend(a ^ b for a, b in zip(data[offset:offset + 64], stream))
        state[12] = (state[12] + 1) & 0xffffffff
        if state[12] == 0:
            state[13] = (state[13] + 1) & 0xffffffff
    return bytes(result)


class QimeiCrtRandom:
    def __init__(self, initial_state):
        self.state = _integer(initial_state) & 0xffffffff

    def rand(self):
        self.state = (self.state * 214013 + 2531011) & 0xffffffff
        return (self.state >> 16) & 32767


def _rsa_key(material, crt):
    der = base64.b64decode(PUBLIC_KEY_B64)
    modulus_raw = der[32:289]
    modulus_bytes = modulus_raw[1:] if modulus_raw[:1] == b'\0' else modulus_raw
    width = len(modulus_bytes)
    modulus = int.from_bytes(modulus_bytes, 'big')
    padding = bytearray()
    while len(padding) < width - 3 - len(material):
        value = crt.rand() & 255
        if value:
            padding.append(value)
    block = b'\0\x02' + padding + b'\0' + material
    return base64.b64encode(pow(int.from_bytes(block, 'big'), 65537, modulus).to_bytes(width, 'big'))


def _clock(clock):
    value = _integer(clock())
    if not 0 <= value < 1 << 63:
        raise QimeiRequestBoundary('negative or out-of-range signed Unix100ns clock')
    return value


def _sign(mode, key, params, time, nonce, clock, configuration):
    digest = hashlib.md5(str(mode).encode('ascii') + key + params + time + nonce).digest()
    microsecond = (_clock(clock) % 10000000) // 10
    cipher = _chacha20(struct.pack('<I', microsecond) + bytes(28), SIGN_NONCE, digest)
    p = bytearray.fromhex('2800472b002c4c4b')
    p[1], p[4] = cipher[5], digest[4]
    q = digest[:4] + bytes([microsecond >> 24]) + bytes(3) + cipher[1:5] + struct.pack('<I', 0x12345678)
    version = _integer(configuration.device_version) & 0xffffffff
    prefix = _bytes(configuration.device_prefix)
    if version and len(prefix) < 8:
        raise QimeiRequestBoundary('device prefix requires eight source bytes')
    text = prefix[:8] + p if version else SIGN_F + p
    h = hashlib.md5(text).digest()
    x = bytes(h[i] ^ p[i % 8] ^ q[i] for i in range(16))
    body = struct.pack('<I', 0x1085434c) + bytes([digest[4], cipher[5]]) + struct.pack('>I', microsecond) + x
    return (body + struct.pack('>I', version) + struct.pack('<I', _integer(configuration.key_id) & 0xffffffff)).hex().encode('ascii')


@dataclass(frozen=True)
class QimeiTransportRequest:
    body: bytes
    key: bytes = field(repr=False)
    iv: bytes = field(repr=False)


class QimeiTransportCodec:
    def __init__(self, observations, *, crt_initial_state, clock):
        self.random = QimeiTransportRandom(observations)
        self.crt = QimeiCrtRandom(crt_initial_state)
        self.clock = clock

    def encode(self, plaintext, *, mode=1, long_names=True, extra, configuration=None, sign_enabled=True):
        plaintext = _bytes(plaintext)
        mode = _integer(mode) & 255
        configuration = QimeiEnvelopeConfiguration() if configuration is None else configuration
        if not isinstance(configuration, QimeiEnvelopeConfiguration):
            raise QimeiRequestBoundary('explicit envelope configuration required')
        if not isinstance(extra, QimeiRequestExtras):
            raise QimeiRequestBoundary('explicit source String extra map required')
        key, iv, wrapped = DEFAULT_K, DEFAULT_IV, b''
        if mode == 1:
            key, iv = self.random.random_bytes(16), self.random.random_bytes(16)
            if len(key) != 16 or len(iv) != 16:
                raise QimeiRequestBoundary('failed random allocation outside normal RSA domain')
            wrapped = _rsa_key(key + iv, self.crt)
        padding = 16 - len(plaintext) % 16
        params = base64.b64encode(_cbc(plaintext + bytes([padding]) * padding, key, iv))
        nonce_raw = self.random.random_bytes(8)
        if len(nonce_raw) != 8:
            raise QimeiRequestBoundary('failed nonce allocation outside normal domain')
        nonce = nonce_raw.hex().encode('ascii')
        time = str(_clock(self.clock) // 10000).encode('ascii')
        sign = _sign(mode, wrapped, params, time, nonce, self.clock, configuration) if sign_enabled else b''
        names = (b'crypt',b'key',b'params',b'time',b'nonce',b'sign',b'extra') if long_names else (b'cpt',b'ky',b'pms',b'tm',b'nn',b'sn',b'ext')
        copied = QimeiRequestExtras(dict(extra.values))
        if long_names and copied.values and b'crypt' not in copied.values:
            copied.put(b'crypt', str(mode).encode('ascii'))
        outer = QimeiRequestExtras()
        for name, value in zip(names, (str(mode).encode('ascii'), wrapped, params, time, nonce, sign, copied.encode())):
            if name == names[1] and mode != 1:
                continue
            if name == names[6] and not copied.values:
                continue
            outer.put(name, value)
        return QimeiTransportRequest(outer.encode(), key, iv)


class _Number(str):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise QimeiRequestBoundary('duplicate reply JSON keys outside proven domain')
        result[key] = value
    return result


def _reply_map(body):
    try:
        parsed = json.loads(body, parse_int=_Number, parse_float=_Number, object_pairs_hook=_object,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except QimeiRequestBoundary:
        raise
    except (ValueError, UnicodeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    if any(not isinstance(value, str) for value in parsed.values()):
        raise QimeiRequestBoundary('composite, bool and null reply values outside proven domain')
    return parsed


def _base64_loose(value):
    try:
        raw = value.encode('ascii')
    except UnicodeError:
        raise QimeiRequestBoundary('non-ASCII reply base64 outside proven domain') from None
    if b'=' in raw.rstrip(b'=') or len(raw) - len(raw.rstrip(b'=')) > 2:
        raise QimeiRequestBoundary('interior or excessive base64 padding outside proven domain')
    raw += b'=' * (-len(raw) % 4)
    if len(raw) - len(raw.rstrip(b'=')) > 2:
        raise QimeiRequestBoundary('incomplete base64 single sextet outside proven domain')
    alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    reverse = {byte: i for i, byte in enumerate(alphabet)}
    result = bytearray()
    for offset in range(0, len(raw), 4):
        block = raw[offset:offset + 4]
        bits = 0
        for byte in block:
            bits = (bits << 6) | reverse.get(byte, 0)
        result.extend(bits.to_bytes(3, 'big')[:3 - block.count(b'=')])
    return bytes(result)


@dataclass(frozen=True)
class QimeiTransportResponse:
    result_code: int
    server_code: int
    body: bytes = field(repr=False)

    def receive(self, reply, *, http_status=200, **kwargs):
        return reply.receive(self.body, result_code=self.result_code, server_code=self.server_code,
                             http_status=http_status, **kwargs)


def decode_transport_reply(request, body, *, send_success=True):
    if request is None:
        return None
    body = _bytes(body)
    if not send_success:
        return QimeiTransportResponse(8, 0, body)
    if not request.key:
        return QimeiTransportResponse(2, 0, body)
    parsed = _reply_map(body)
    if 'code' not in parsed or 'data' not in parsed:
        return QimeiTransportResponse(5, 0, body)
    if parsed['code'] != '0':
        match = re.match(r'^[\t\n\v\f\r ]*([+-]?[0-9]+)', parsed['code'])
        code = int(match[1]) if match else 0
        if not -(1 << 31) <= code < 1 << 31:
            raise QimeiRequestBoundary('overflowing CRT atoi outside proven domain')
        return QimeiTransportResponse(6, code, body)
    decoded = _base64_loose(parsed['data'])
    if not decoded or len(decoded) % 16:
        return QimeiTransportResponse(7, 0, body)
    if len(request.key) != 16 or len(request.iv) != 16:
        raise QimeiRequestBoundary('saved response AES materials outside proven domain')
    plain = _cbc(decoded, request.key, request.iv, decrypt=True)
    padding = plain[-1]
    if not 1 <= padding <= 16 or plain[-padding:] != bytes([padding]) * padding:
        return QimeiTransportResponse(7, 0, body)
    return QimeiTransportResponse(0, 0, plain[:-padding])
