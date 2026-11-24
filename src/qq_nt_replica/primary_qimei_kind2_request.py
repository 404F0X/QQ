"""Finite 51F84 constructor and 53D22 payload stage; finite attempt1 component; full52359/provider bindings not supplied."""
from .primary_qimei_request import QimeiRequestBoundary,QimeiRequestState,RequestSlot,serialize_slots,_signed,_integer


class QimeiKind2Request:
    kind=2
    count=48
    response_count=1
    def __init__(self,owner,payload_producer,*,convert_ansi,allocate_slots,dispatch,module_state,clock_milliseconds,allocate_response):
        if type(owner) is not bytes or not owner or b'\0' in owner:
            raise QimeiRequestBoundary('source owner C string required')
        if not callable(getattr(payload_producer,'populate',None)) or not callable(allocate_slots) or not callable(convert_ansi):
            raise QimeiRequestBoundary('actual payload/slot allocation/ANSI dependencies required')
        self.owner=memoryview(owner).tobytes()
        self.payload_producer=payload_producer
        self.convert_ansi,self.allocate_slots=convert_ansi,allocate_slots
        if not callable(getattr(dispatch,'dispatch',None)) or not all(callable(v) for v in (clock_milliseconds,allocate_response)):
            raise QimeiRequestBoundary('source dispatch, millisecond clock and response allocation dependencies required')
        self.dispatch,self.module_state,self.clock_milliseconds=dispatch,module_state,clock_milliseconds
        from .primary_qimei_request_state import QimeiModuleRequestState
        if not isinstance(module_state,QimeiModuleRequestState):raise QimeiRequestBoundary('explicit shared module state required')
        self.payload_duration=0
        self.dispatch_duration=0
        self.allocate_response=allocate_response
        self.response_count=1
        self.error=b''
        self.success=False
    def produce_payload(self):
        accepted=self.allocate_slots(768)
        if type(accepted) is not bool:
            raise QimeiRequestBoundary('explicit ordinary allocation success/NULL boolean required')
        if not accepted:return b''
        state=QimeiRequestState([RequestSlot() for _ in range(48)])
        self.payload_producer.populate(self.owner,state)
        return serialize_slots(state.slots,count=48,convert_ansi=self.convert_ansi)
    def consume_response(self,body):
        """52D66 constant TRUE; no main-Qimei fields or settings installation."""
        return True

    def decode(self,body,*,allocate=None,observe=None):
        from .primary_qimei_reply import parse_reply,_allocation,_bytes
        body=_bytes(body)
        if not body or not _allocation(self.allocate_response,'slots',None,17):return None
        parsed=parse_reply(body,count=self.response_count,allocate=self.allocate_response)
        if parsed.accepted and self.consume_response(parsed.slots):self.success=True
        return parsed

    def receive(self,body,*,result_code,http_status,server_code):
        from .primary_qimei_reply import QimeiReplyState
        return QimeiReplyState.receive(self,body,result_code=result_code,http_status=http_status,server_code=server_code)

    def run(self,attempt_limit=1):
        limit=_signed(attempt_limit,32)
        if limit>1:
            raise QimeiRequestBoundary('generic retry/sleep domain beyond actual kind2 attempt1 is not implemented')
        t0=_integer(self.clock_milliseconds())&0xFFFFFFFFFFFFFFFF
        payload=self.produce_payload()
        t1=_integer(self.clock_milliseconds())&0xFFFFFFFFFFFFFFFF
        if limit>0:
            self.dispatch.dispatch(self.owner,self.kind,payload,source_completion,self)
            if self.success:self.module_state.publish(self.kind)
        t2=_integer(self.clock_milliseconds())&0xFFFFFFFFFFFFFFFF
        if t1>t0:self.payload_duration=(t1-t0)&0xFFFFFFFF
        if t2>t1:self.dispatch_duration=(t2-t1)&0xFFFFFFFF
        return self.success


def source_completion(body,result_code,http_status,server_code,user_context):
    """620A1: NULL context does not forward; dispatch return is not success."""
    if user_context is not None:
        return user_context.receive(body,result_code=result_code,http_status=http_status,server_code=server_code)
