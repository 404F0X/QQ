from dataclasses import dataclass, field

from .primary_qimei_envelope import QimeiEnvelopeCodec, QimeiEnvelopeConfiguration
from .primary_qimei_extras import QimeiRequestExtras
from .primary_qimei_reply import QimeiReplyState
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer
from .primary_qimei_request_producer import QimeiRequestProducer
from .primary_qimei_transport_codec import QimeiTransportCodec, QimeiTransportRequest, decode_transport_reply
from .primary_qimei_transport_material import QimeiTransportMaterialProducer


@dataclass(frozen=True)
class QimeiHttpRequest:
    body: bytes = field(repr=False)
    url: bytes = b'https://snowflake.qq.com/ola/v2'
    method: bytes = b'POST'
    http_version: bytes = b'HTTP/1.1'
    headers: tuple = ((b'Content-Type', b'application/json'),
                      (b'User-Agent', b'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'))

    @property
    def body_length(self):
        return len(self.body)


@dataclass(frozen=True)
class PreparedQimeiRequest:
    http: QimeiHttpRequest
    transport_request: QimeiTransportRequest = field(repr=False)
    owner: bytes = field(repr=False)
    logical_mode: int
    sequence: int

    def receive(self, body, reply, *, send_success, http_status, allocate=None, observe=lambda *args: None):
        if type(send_success) is not bool or not isinstance(reply, QimeiReplyState):
            raise QimeiRequestError('explicit send success and existing reply state required')
        http_status = _integer(http_status)
        response = decode_transport_reply(self.transport_request, _bytes(body), send_success=send_success)
        return response.receive(reply, http_status=http_status, allocate=allocate, observe=observe)


class QimeiRequestPipeline:
    def __init__(self, request_producer, material_producer, *, envelope, configuration, transport, convert_ansi, sign_enabled):
        if not isinstance(request_producer, QimeiRequestProducer) or not isinstance(material_producer, QimeiTransportMaterialProducer):
            raise QimeiRequestBoundary('explicit device and material source producers required')
        if not isinstance(envelope, QimeiEnvelopeCodec) or not isinstance(configuration, QimeiEnvelopeConfiguration):
            raise QimeiRequestBoundary('explicit envelope codec and configuration required')
        if not isinstance(transport, QimeiTransportCodec) or not callable(convert_ansi) or type(sign_enabled) is not bool:
            raise QimeiRequestBoundary('explicit transport, ANSI conversion and independent signature gate required')
        self.request_producer, self.material_producer = request_producer, material_producer
        self.envelope, self.configuration, self.transport = envelope, configuration, transport
        self.convert_ansi, self.sign_enabled = convert_ansi, sign_enabled

    def prepare(self, owner, logical_mode, sequence, *, extra=None):
        owner = _bytes(owner)
        if owner != self.request_producer.owner:
            raise QimeiRequestError('request owner does not match device producer owner')
        logical_mode, sequence = _integer(logical_mode) & 0xFFFFFFFF, _integer(sequence) & 0xFFFFFFFF
        if extra is not None and not isinstance(extra, QimeiRequestExtras):
            raise QimeiRequestError('explicit external String extra map required')
        if type(self.sign_enabled) is not bool:
            raise QimeiRequestError('explicit independent signature gate required')
        external = {} if extra is None else {_bytes(key): _bytes(value) for key, value in extra.values.items()}
        effective = QimeiRequestExtras(external if external else {b'app_key': owner})
        device = self.request_producer.populate().encode(convert_ansi=self.convert_ansi)
        header = self.material_producer.produce(owner, logical_mode, sequence).serialize()
        envelope = self.envelope.encode(header, device, configuration=self.configuration)
        request = self.transport.encode(envelope, mode=1 if logical_mode in (1, 2) else 2,
                                        long_names=bool(external), extra=effective,
                                        configuration=self.configuration, sign_enabled=self.sign_enabled)
        if len(request.body) >= 1 << 32:
            raise QimeiRequestBoundary('HTTP body length exceeds source DWORD domain')
        return PreparedQimeiRequest(QimeiHttpRequest(request.body), request, owner, logical_mode, sequence)
