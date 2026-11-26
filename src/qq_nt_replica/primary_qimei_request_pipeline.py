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
        return encode_payload(owner, logical_mode, sequence, device,
            material_producer=self.material_producer,envelope=self.envelope,
            configuration=self.configuration,transport=self.transport,
            sign_enabled=self.sign_enabled,extra=QimeiRequestExtras(external))


    def run_cold_material_job(self, binding, *, startup, dispatch, reply,
                              source_clock,
                              selector, persist, selector_observations=None,
                              allocate=None, observe=lambda *args: None):
        """One synchronous attempt; caller owns borrowed resources and persistence.

        Only the cold main-empty Source gate is supported. No scheduler, retry,
        cancellation, full a2 or getter-ready claim follows from this operation.
        """
        from .primary_qimei_application_binding import ApplicationBinding
        from .primary_qimei_records import StartupState
        from .primary_qimei_dispatch import QimeiSourceDispatch
        from .primary_qimei_beacon import QimeiBeacon
        from .primary_qimei_reply import commit_server_reply
        producer, material = self.request_producer, self.material_producer
        if (not isinstance(binding, ApplicationBinding)
                or not isinstance(startup, StartupState)
                or not isinstance(dispatch, QimeiSourceDispatch)
                or not isinstance(reply, QimeiReplyState)
                or binding.context.owner != binding.owner
                or producer.owner != binding.owner
                or producer.settings is not binding.settings
                or producer.sdk_contexts.contexts.get(binding.owner) is not binding.context
                or material.sdk is not binding.context
                or material.settings is not binding.settings
                or material.startup is not startup
                or material.system is not producer.system
                or material.extras is not producer.extras
                or material.extension is not producer.extensions
                or dispatch.material_producer is not material
                or dispatch.envelope is not self.envelope
                or dispatch.configuration is not self.configuration
                or dispatch.transport is not self.transport
                or type(self.sign_enabled) is not bool
                or dispatch.sign_enabled is not self.sign_enabled):
            raise QimeiRequestBoundary('cold job requires original same-owner pipeline bindings')
        if (startup.once != 1 or startup.identity_mode != 1
                or [(r.id,r.capacity) for r in startup.main.vector()] != [(0,16),(1,37)]
                or [(r.id,r.capacity) for r in startup.identity1.vector()] != [(0,12),(1,32),(2,56)]
                or startup.main.get(1).split(b'\0',1)[0]
                or reply.success or reply.qimei or reply.field2 or reply.field3 or reply.error):
            raise QimeiRequestBoundary('cold job requires completed startup, empty main and unfinished reply')
        if (not isinstance(material.globals.beacon,QimeiBeacon)
                or not callable(source_clock)
                or not callable(persist)):
            raise QimeiRequestBoundary('explicit beacon, Source clock/timestamp and authorized persistence required')
        material.globals.refresh_config()
        # 50D00 -> A3F9A refreshes this exact settings record before QWORD+1.
        binding.settings.refresh(**producer.settings_dependencies)
        timestamp = int.from_bytes(binding.settings.record[1:9], 'little')
        now = _integer(source_clock())
        elapsed = ((now & 0xffffffffffffffff) - (timestamp & 0xffffffffffffffff)) & 0xffffffffffffffff
        if elapsed < 86400 and startup.main.get(1).split(b'\0',1)[0]:
            raise QimeiRequestBoundary('cold material readiness gate no longer holds')
        payload = producer.populate().encode(convert_ansi=self.convert_ansi)
        def complete(body, local_code, status, server_code, original):
            parsed = original.receive(body,result_code=local_code,http_status=status,
                server_code=server_code,allocate=allocate,observe=observe)
            if parsed is not None and parsed.accepted and original.qimei:
                commit_server_reply(startup,original,selector=selector,persist=persist,
                    selector_observations=selector_observations,observe=observe)
        dispatch.dispatch(binding.owner,1,payload,complete,reply)  # 972D4 request_object+8; not retry budget3.
        return reply


def encode_payload(owner,logical_mode,sequence,payload,*,material_producer,envelope,
                   configuration,transport,sign_enabled,extra=None):
    """Common post-payload65B74 encoding; does not invoke a device producer."""
    owner,payload=_bytes(owner),_bytes(payload)
    logical_mode,sequence=_integer(logical_mode)&0xFFFFFFFF,_integer(sequence)
    if extra is not None and not isinstance(extra,QimeiRequestExtras):
        raise QimeiRequestError('explicit external String extra map required')
    if type(sign_enabled)is not bool:raise QimeiRequestError('explicit independent signature gate required')
    external={} if extra is None else {_bytes(k):_bytes(v) for k,v in extra.values.items()}
    effective=QimeiRequestExtras(external if external else {b'app_key':owner})
    header=material_producer.produce(owner,logical_mode,sequence).serialize()
    encoded=envelope.encode(header,payload,configuration=configuration)
    request=transport.encode(encoded,mode=1 if logical_mode in (1,2) else 2,
        long_names=bool(external),extra=effective,configuration=configuration,sign_enabled=sign_enabled)
    if len(request.body)>=1<<32:raise QimeiRequestBoundary('HTTP body length exceeds source DWORD domain')
    return PreparedQimeiRequest(QimeiHttpRequest(request.body),request,owner,logical_mode,sequence)
