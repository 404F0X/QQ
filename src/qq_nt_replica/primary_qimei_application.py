from dataclasses import dataclass, field

from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes
from .primary_qimei_sdk import QimeiSdkContexts


APPLICATION_OWNER = b'0WIN053OA34CY6NK'


def decode_machine_guid(plaintext):
    plaintext = _bytes(plaintext)
    if len(plaintext) < 4 or int.from_bytes(plaintext[:4], 'big') != 20:
        raise QimeiRequestBoundary('Registry20 typed GUID requires big-endian total length20')
    if len(plaintext) < 20:
        raise QimeiRequestBoundary('Registry20 typed GUID requires all sixteen payload bytes')
    return bytes(value ^ 0xEF for value in plaintext[4:20])


@dataclass(frozen=True)
class QimeiApplication:
    guid: bytes = field(repr=False)

    def __post_init__(self):
        if len(_bytes(self.guid)) != 16:
            raise QimeiRequestError('explicit sixteen-byte application GUID required')

    @classmethod
    def from_registry20_plaintext(cls, plaintext):
        return cls(decode_machine_guid(plaintext))

    def configure(self, contexts):
        if not isinstance(contexts, QimeiSdkContexts):
            raise QimeiRequestError('explicit SDK context collection required')
        context = contexts.get(APPLICATION_OWNER)
        context.configure(b'', b'{"GUID":"' + self.guid.hex().encode('ascii') + b'"}', b'', 1)
        return context
