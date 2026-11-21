from dataclasses import dataclass

from .errors import InputError
from .primary_vm import PrimaryProgramLimit
from .wire import bytes_field


@dataclass(frozen=True)
class PrimarySignatureResult:
    sign: bytes
    extra: bytes
    token: bytes

    def __post_init__(self):
        if any(not isinstance(value, bytes) for value in (self.sign, self.extra, self.token)):
            raise InputError('primary signature result requires three raw byte strings')

    def encode_field24(self):
        return encode_signature_field24(self)


def encode_signature_field24(result):
    if not isinstance(result, PrimarySignatureResult):
        raise InputError('signature field24 requires a PrimarySignatureResult')
    child = b''.join(bytes_field(number, value)
                     for number, value in ((1, result.sign), (2, result.extra), (3, result.token))
                     if value)
    return bytes_field(24, child) if child else b''


def caller_result(sign, extra, token):
    result = PrimarySignatureResult(sign, extra, token)
    if any(len(value) > 255 for value in (extra, token, sign)):
        raise PrimaryProgramLimit('BA22B0 result exceeds the nonoverlapping 255-byte caller slot domain')
    return result
