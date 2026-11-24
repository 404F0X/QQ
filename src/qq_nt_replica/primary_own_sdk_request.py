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
        self.sequence=1;self.flags=0;self.closed=False
        self.creator=(os.getpid(),threading.get_native_id())
        self._tag=bytes.fromhex('4d4c5c7b4146494d');self._encoded=True

    def _check(self):
        if self.closed or self.creator!=(os.getpid(),threading.get_native_id()):
            raise InputError('own request requires its open creator process/native thread')

    def create_device_request(self, records):
        self._check();runtime=self.runtime
        feature46=feature(runtime,_logger(runtime),46)
        metadata=_String.read(runtime,runtime.image_base+0x6751840+24).value()
        if self._encoded:
            self._tag=bytes(b^0x23^(i+1)^8 for i,b in enumerate(self._tag)).split(b'\0',1)[0]
            self._encoded=False
        cipher=None
        if feature46==1:
            if self.state17_owner is None:raise PrimarySemanticUnavailable('feature46 requires current own state17 producer')
            cipher=dict(state17=self.state17_owner(),process_id=self.creator[0],wall_seconds=self.clocks['wall_seconds'](),
                formatter_options=runtime.memory.load(runtime.image_base+0x6749CC0,8))
        stage=encode_record_request(records,metadata,feature46=feature46,tag=self._tag,material_state=self.material,
            cipher_inputs=cipher,
            encoding_inputs=dict(self.clocks,random_word=lambda:int.from_bytes(self.environment.random_bytes(4),'little'),capi=self.capi))
        binding=runtime.request_transport
        first=None if binding is None else binding.type(self.transport_context)
        if first in (None,0):a2=bool(self.flags&1)
        else:
            second=binding.type(self.transport_context)
            a2=second==1
        sequence=self.sequence;self.sequence=(sequence+1)&((1<<64)-1)
        return finish_record_request(stage,sdk_sequence=sequence,a2=a2,commands=_COMMANDS)

    def close(self):
        self._check();self.closed=True
        # CAPI, clocks and observation ports are borrowed, not closed here.
