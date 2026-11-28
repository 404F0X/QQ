import hashlib
from dataclasses import dataclass, field

from .primary_qimei_cache import _cbc
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer, _varint


SOURCE_SHA256 = 'a6100bce0de79ea52fe80a85acce2c24c615306fd3c2dedd119b51b0f26ebcc6'
DEVICE_BITMAP = b'/qilogo.bmp'
KEY_BITMAP = b'/qllogo.bmp'


class QimeiEnvelopeError(QimeiRequestError):
    pass


class QimeiEnvelopeBoundary(QimeiRequestBoundary):
    pass


def _compiled(value):
    text = bytes(item ^ (index + 1) ^ 0x31 ^ 32 for index, item in enumerate(bytes.fromhex(value)))
    return bytes.fromhex(text.decode('ascii'))


def envelope_plaintext(field1, field2):
    field1, field2 = _bytes(field1), _bytes(field2)
    return b'\x0a' + _varint(len(field1)) + field1 + b'\x12' + _varint(len(field2)) + field2


def _bitmap_payload(raw, version):
    if len(raw) < 54 or raw[:2] != b'BM' or int.from_bytes(raw[28:30], 'little') != 24:
        return None
    offset = int.from_bytes(raw[10:14], 'little')
    pixels = (int.from_bytes(raw[18:22], 'little') * int.from_bytes(raw[22:26], 'little')) & 0xFFFFFFFF
    if len(raw) < (3 * pixels + offset) & 0xFFFFFFFF:
        return None

    def hidden(start, length):
        end = offset + start + length * 8
        if end > len(raw):
            raise QimeiEnvelopeBoundary('source bitmap bit extraction exceeds known file backing')
        result = bytearray()
        for index in range(offset + start, end, 8):
            value = 0
            for item in raw[index:index + 8]:
                value = (value << 1) | (item & 1)
            result.append(value)
        return bytes(result)

    encoded_version = hidden(0, 4)
    length = hidden(32, 1)[0]
    if not length or ((pixels - 5) & 0xFFFFFFFF) < length:
        return None
    payload = hidden(40, length)
    return payload if encoded_version == version else None


@dataclass
class QimeiEnvelopeConfiguration:
    device_version: int = 0
    device_prefix: bytes = field(default=bytes(8), repr=False)
    device_blob: bytes = field(default=b'', repr=False)
    key_id: int = 1
    key_override: bytes = field(default=b'', repr=False)

    def refresh(self, read_file):
        first = _bytes(read_file(DEVICE_BITMAP))
        if len(first) < 4:
            return 'device-unavailable', 'key-unread'
        version = first[-4:]
        if int.from_bytes(version, 'little') == (_integer(self.device_version) & 0xFFFFFFFF):
            device_status = 'device-same-version'
        else:
            payload = _bitmap_payload(first, version)
            device_status = 'device-rejected'
            if payload is not None:
                self.device_version = int.from_bytes(version, 'little')
                self.device_prefix = payload[:8].ljust(8, b'\0')
                self.device_blob = payload
                device_status = 'device-updated'
        second = _bytes(read_file(KEY_BITMAP))
        if len(second) < 4:
            return device_status, 'key-unavailable'
        version = second[-4:]
        if int.from_bytes(version, 'little') == (_integer(self.key_id) & 0xFFFFFFFF):
            return device_status, 'key-same-version'
        payload = _bitmap_payload(second, version)
        if payload is None:
            return device_status, 'key-rejected'
        self.key_id = int.from_bytes(version, 'little')
        self.key_override = payload[:16].ljust(16, b'\0')
        return device_status, 'key-updated'

    def metadata(self):
        return {'device_version': _integer(self.device_version) & 0xFFFFFFFF,
                'device_blob_length': len(_bytes(self.device_blob)),
                'device_blob_sha256': hashlib.sha256(self.device_blob).hexdigest(),
                'key_id': _integer(self.key_id) & 0xFFFFFFFF,
                'key_override_length': len(_bytes(self.key_override))}


class QimeiEnvelopeCodec:
    def __init__(self):
        self.iv = _compiled('522b2027252e20205b292d5c242f2f384436313646363530494f4f3a3d4d4d72')
        self.fallback_key = _compiled('56552a252627262a5e2d2d5b292a5c443841373631463f3e4a3b3b4f383a3775')

    def encode(self, field1, field2, *, configuration=None):
        configuration = QimeiEnvelopeConfiguration() if configuration is None else configuration
        if not isinstance(configuration, QimeiEnvelopeConfiguration):
            raise QimeiEnvelopeError('explicit source envelope configuration required')
        key = _bytes(configuration.key_override)
        if key and len(key) < 16:
            raise QimeiEnvelopeBoundary('override key requires its complete sixteen-byte source backing')
        key = key[:16] if key else self.fallback_key
        plain = envelope_plaintext(field1, field2)
        padding = 16 - len(plain) % 16
        ciphertext = _cbc(plain + bytes([padding]) * padding, key, self.iv)
        header = b'\x03' + (_integer(configuration.key_id) & 0xFFFFFFFF).to_bytes(4, 'big')
        return header + ciphertext
