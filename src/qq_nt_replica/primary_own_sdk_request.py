"""Independent cold request state; never a native receiver or pending admission."""
import os
import threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_request_material import RequestMaterialState
from .primary_request_transport import _COMMANDS
from .primary_sdk_request import encode_record_request, finish_record_request
from .primary_logger import _String, feature
from .primary_worker_consumer import _logger

class OwnColdSdkRequestOwner:
    def __init__(self, runtime, *, request_capi, clock_inputs, random_environment,
                 state17_owner=None, transport_context=None):
        if set(clock_inputs) != {'wall_seconds','monotonic_ns','clock_ns'} or any(not callable(v) for v in clock_inputs.values()):
            raise InputError('explicit actual request clock interfaces required')
        if request_capi is None:
            raise InputError('explicit request CAPI interface required')
        # This component may attach only to the actually cold SDK cache. Never reset it.
        metadata=_String.read(runtime,runtime.image_base+0x6751840+24).value()
        if metadata:raise PrimarySemanticUnavailable('own cold request requires actual empty SDK metadata cache')
        if runtime.request_transport is not None and transport_context is None:
            raise InputError('configured transport requires its explicit accepted own context')
        self.runtime=runtime;self.capi=request_capi;self.clocks=dict(clock_inputs)
        self.environment=random_environment;self.state17_owner=state17_owner
        self.transport_context=transport_context;self.material=RequestMaterialState()
        self.sequence=1;self.flags=0;self.closed=False;self._pending=[];self._completion=None
        self.creator=(os.getpid(),threading.get_native_id())
        self._tag=bytes.fromhex('4d4c5c7b4146494d');self._encoded=True

    def _check(self):
        if self.closed or self.creator!=(os.getpid(),threading.get_native_id()):
            raise InputError('own request requires its open creator process/native thread')

    def create_device_request(self, records):
        self._check();runtime=self.runtime
        bound=bytes(_String.read(runtime,runtime.image_base+0x6751840+48).value())
        feature46=feature(runtime,_logger(runtime),46)
        metadata=_String.read(runtime,runtime.image_base+0x6751840+24).value()
        if self._encoded:
            self._tag=bytes(b^0x23^(i+1)^8 for i,b in enumerate(self._tag)).split(b'\0',1)[0]
            self._encoded=False
        cipher=None
        if feature46==1:
            if self.state17_owner is None:raise PrimarySemanticUnavailable('feature46 requires current own state17 producer')
            from .primary_crt_stdio_options import read_options
            cipher=dict(state17=self.state17_owner(),process_id=self.creator[0],wall_seconds=self.clocks['wall_seconds'](),
                formatter_options=read_options(runtime))
        from .primary_request_fingerprint import source_request_fingerprint
        stage=encode_record_request(records,metadata,feature46=feature46,tag=self._tag,material_state=self.material,
            cipher_inputs=cipher,
            encoding_inputs=dict(self.clocks,random_word=lambda:int.from_bytes(self.environment.random_bytes(4),'little'),capi=self.capi,
                fingerprint_operation=lambda digest,nonce:source_request_fingerprint(runtime,digest,nonce)))
        binding=runtime.request_transport
        first=None if binding is None else binding.type(self.transport_context)
        if first in (None,0):a2=bool(self.flags&1)
        else:
            second=binding.type(self.transport_context)
            a2=second==1
        sequence=self.sequence
        request=finish_record_request(stage,sdk_sequence=sequence,a2=a2,commands=_COMMANDS)
        self.sequence=(sequence+1)&((1<<64)-1)
        self._pending.append((request,bound))
        return request

    def check_device_request(self, request):
        """Reject inadmissible originals without consuming or mutating the owner."""
        self._check()
        if not any(original is request for original, bound in self._pending):
            raise InputError('response requires its outstanding original Own request')

    def _take(self, request):
        self.check_device_request(request)
        for index, (original, bound) in enumerate(self._pending):
            if original is request:
                self._pending.pop(index)
                return bound
        raise InputError('response requires its outstanding original Own request')

    def cancel_device_request(self, request):
        self._take(request)
        return None  # Local cancellation only; no external transport abort claim.

    def complete_device_request(self, request, responsebody, *, transport_status):
        if type(responsebody) is not bytes or type(transport_status) is not int or not 0 <= transport_status <= 0xFFFFFFFF:
            raise InputError('response requires immutable bytes and explicit transport DWORD status')
        if self._completion is not None:
            raise InputError('Own response completion cannot reenter')
        bound = self._take(request)
        self._completion = (request, bound)
        try:
            from .primary_own_sdk_response import _complete
            return _complete(self, request, bound, responsebody, transport_status)
        finally:
            self._completion = None

    def close(self):
        self._check();self.closed=True;self._pending.clear()
        # CAPI, clocks and observation ports are borrowed, not closed here.
