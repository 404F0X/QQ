"""61D22 post-payload trunk; real WinINet/libcurl carrier remains unimplemented."""
from abc import ABC,abstractmethod
from dataclasses import dataclass,field
from threading import RLock
from .primary_qimei_request import QimeiRequestBoundary,_bytes,_integer
from .primary_qimei_request_pipeline import encode_payload
from .primary_qimei_transport_codec import decode_transport_reply

@dataclass(frozen=True)
class CarrierOutcome:
    body:bytes=field(repr=False)
    source_status:int
    def __post_init__(self):
        _bytes(self.body);_integer(self.source_status)

class QimeiCarrierPort(ABC):
    """Explicit source A3352 port, not http.client or HTTP-status equivalence."""
    @abstractmethod
    def perform(self,encoded_http_request):raise NotImplementedError

class QimeiDispatchState:
    def __init__(self,initial_sequence):
        self.sequence=_integer(initial_sequence)&0xFFFFFFFFFFFFFFFF
        self.pending={}
        self.lock=RLock()

@dataclass
class _Pending:
    prepared:object=field(repr=False)
    completion:object=field(repr=False)
    context:object=field(repr=False)

class QimeiSourceDispatch:
    def __init__(self,module_state,material_producer,*,envelope,configuration,transport,
                 carrier,sign_enabled):
        if not isinstance(module_state,QimeiDispatchState):raise QimeiRequestBoundary('explicit shared dispatcher state required')
        self.state,self.material_producer=module_state,material_producer
        self.envelope,self.configuration,self.transport=envelope,configuration,transport
        self.carrier,self.sign_enabled=carrier,sign_enabled
    def dispatch(self,owner,kind,payload,completion,user_context,*,io=None):
        carrier = self.carrier if io is None else io.carrier
        if not isinstance(carrier,QimeiCarrierPort):
            raise QimeiRequestBoundary('real default carrier backend is unimplemented; explicit source carrier required')
        if not callable(completion):raise QimeiRequestBoundary('source completion required')
        owner,kind,payload=_bytes(owner),_integer(kind)&0xFFFFFFFF,_bytes(payload)
        with self.state.lock:
            old=self.state.sequence;self.state.sequence=(old+1)&0xFFFFFFFFFFFFFFFF
        sequence=old&0xFFFFFFFF
        signed=sequence-(1<<32) if sequence&0x80000000 else sequence
        prepared=encode_payload(owner,kind,signed,payload,material_producer=self.material_producer,
            envelope=self.envelope,configuration=self.configuration,transport=self.transport,
            sign_enabled=self.sign_enabled, **({} if io is None else dict(io=io)))
        record=_Pending(prepared,completion,user_context)
        with self.state.lock:
            if sequence in self.state.pending:raise QimeiRequestBoundary('pending sequence collision outside recovered finite domain')
            self.state.pending[sequence]=record
            # Synchronous outer provider: retain this exact record/key/IV/context.
            outcome=carrier.perform(prepared.http)
            if not isinstance(outcome,CarrierOutcome):raise QimeiRequestBoundary('owned source carrier outcome required')
            success=bool(outcome.body)
            status=200 if success else outcome.source_status
            decoded=decode_transport_reply(record.prepared.transport_request,outcome.body,send_success=success)
            if decoded is None:raise QimeiRequestBoundary('matching encoded request unavailable')
            record.completion(decoded.body,decoded.result_code,status,decoded.server_code,record.context)
            # Only normal cleanup is recovered. Exceptions retain pending evidence.
            del self.state.pending[sequence]
