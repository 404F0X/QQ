"""540D4 status request group; Source business component, not full a2."""
from .primary_qimei_kind2_request import QimeiKind2Request, source_completion
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestState, RequestSlot, _signed


def status_value(subtype, status):
    if type(subtype) is not int or subtype not in (1, 2, 3):
        raise QimeiRequestBoundary('Source status subtype1/2/3 required')
    if subtype == 2:
        if status is not None:
            raise QimeiRequestBoundary('542E3 supplies its own constant status String')
        return b'0'
    return str(_signed(status, 32)).encode('ascii')


class QimeiStatusRequest(QimeiKind2Request):
    """Reuse the one-slot52D66 response and common request error semantics."""
    kind = 7
    count = 4

    def __init__(self, owner, subtype, value, *, adapter, dispatch, module_state,
                 clock_milliseconds, convert_ansi, io):
        super().__init__(owner, self, convert_ansi=convert_ansi,
            allocate_slots=lambda size: True, dispatch=dispatch, module_state=module_state,
            clock_milliseconds=clock_milliseconds, allocate_response=lambda *args: True)
        self.subtype, self.value, self.adapter, self.io = subtype, value, adapter, io

    def populate(self, owner, state):
        state.set_u32(1, self.subtype)
        state.set_u64(2, self.clock_milliseconds())
        state.set_string(3, self.adapter.refresh().ip)
        state.set_string(4, self.value)

    def produce_payload(self):
        state = QimeiRequestState([RequestSlot() for unused in range(self.count)])
        self.populate(self.owner, state)
        return state.encode(convert_ansi=self.convert_ansi)

    def run(self):
        # Source53DDE attempt1. Normal failure is observable on this request and
        # returns to its caller; no new retry or success-dependent continuation.
        t0 = self.clock_milliseconds() & 0xffffffffffffffff
        payload = self.produce_payload()
        t1 = self.clock_milliseconds() & 0xffffffffffffffff
        self.dispatch.dispatch(self.owner, self.kind, payload, source_completion, self, io=self.io)
        if self.success:
            self.module_state.publish(self.kind)
        t2 = self.clock_milliseconds() & 0xffffffffffffffff
        if t1 > t0:
            self.payload_duration = (t1 - t0) & 0xffffffff
        if t2 > t1:
            self.dispatch_duration = (t2 - t1) & 0xffffffff
        return self.success


def conditional_kind7(owner, settings, subtype, status=None, *, settings_dependencies,
                      adapter, dispatch, module_state, clock_milliseconds, convert_ansi, io):
    """54211/542E3/54411: None means gate skipped, otherwise retain actual result."""
    value = status_value(subtype, status)
    if not settings.flag(13, group=0, **settings_dependencies) & (1 << (subtype - 1)):
        return None
    request = QimeiStatusRequest(owner, subtype, value, adapter=adapter, dispatch=dispatch,
        module_state=module_state, clock_milliseconds=clock_milliseconds,
        convert_ansi=convert_ansi, io=io)
    request.run()
    return request
