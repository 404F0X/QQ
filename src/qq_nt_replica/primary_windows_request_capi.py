"""Factory-owned finite request CAPI capability; not a Device/Notify issuer."""
import ctypes
from dataclasses import dataclass
import os
import sys
from threading import get_native_id

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .wire import require_uint


_OWNERS = {}
_RUNTIMES = {}
_HISTORY = {}
_PHYSICAL = {}
_TOKEN = object()


def _frame(code):
    frame=sys._getframe(1)
    while frame is not None:
        if frame.f_code is code:return frame
        frame=frame.f_back
    return None


@dataclass(frozen=True,eq=False)
class _History:
    provider: object
    claim: object
    producer: object
    owner: object
    source: object
    lease: object
    thread: int
    generation: int
    regions: tuple


def bind(owner):
    from .primary_windows_signer import WindowsSigner
    from .primary_client_configuration_scope import _OWNERS as clients
    from .primary_client_configuration_startup import require_request_stage
    caller=sys._getframe(1)
    runtime=owner._signer.runtime
    if (caller.f_code is not WindowsSigner._initialize_crt.__code__ or caller.f_locals.get('self') is not owner or
            owner in _OWNERS or runtime in _RUNTIMES or runtime.request_capi is not None):
        raise InputError('request CAPI binding requires its fresh actual factory stage')
    stage=require_request_stage(runtime)
    original=clients[owner]
    provider=_Provider(owner,original,stage,_TOKEN)
    _OWNERS[owner]=provider;_RUNTIMES[runtime]=provider
    owner._owned_request_capi=provider
    runtime.request_capi=provider
    return provider


def completed_audit(claim):
    from .primary_request_audit_scope import client_handoff_audit
    source=sys._getframe(1)
    if source.f_code is not client_handoff_audit.__wrapped__.__code__ or source.f_locals.get('claim') is not claim:
        raise InputError('request CAPI history requires actual normal audit completion')
    provider=_RUNTIMES.get(claim.runtime)
    if provider is None:return
    provider.validate();claim.require()
    if (claim.stage!='complete' or not claim.status_completed or not claim.status_wrapper_seen or
            not claim.material_wrapper_completed or claim.material_wrapper is not None or
            id(claim.producer) in _HISTORY):
        raise InputError('request CAPI audit history is incomplete or repeated')
    history=_History(provider,claim,claim.producer,claim.owner,claim.source,claim.owner.lease,
                     get_native_id(),claim.runtime._main_generation,
                     ((claim.producer['frame'],claim.producer['region'],0x110),
                      (claim.source.f_locals['frame'],claim.handoff_region,0x178)))
    _HISTORY[id(claim.producer)]=history


def begin(capi):
    provider=_RUNTIMES.get(capi.runtime)
    if provider is None:return None  # Existing non-factory engineering domains are unchanged.
    from .primary_request_entry import _Capi,produce
    caller=sys._getframe(1)
    if caller.f_code is not _Capi.__init__.__code__ or caller.f_back.f_code is not produce.__code__:
        raise InputError('request CAPI ticket must originate in actual material production')
    try:return provider.begin(capi)
    except BaseException as error:provider.fail(error);raise


def check_use(capi,operation,phase,buffer=None,handle=_TOKEN):
    from .primary_request_entry import _Capi
    from .primary_request_capi import _generate
    caller=sys._getframe(1)
    if caller.f_code is not getattr(_Capi,operation).__code__ or caller.f_back.f_code is not _generate.__code__:
        raise InputError('request CAPI adapter requires the immediate actual source helper')
    try:capi.ticket.check(phase,buffer,handle)
    except BaseException as error:capi.ticket.provider.fail(error);raise


def end(ticket):
    if ticket is None:return
    from .primary_request_entry import produce
    if _frame(produce.__code__) is not ticket.source:
        raise InputError('request CAPI ticket retirement lost actual source frame')
    ticket.active=False  # Host qualification only; never release a source handle here.


def preflight(owner):
    provider=_OWNERS.get(owner)
    if provider is None:
        if getattr(owner,'_owned_request_capi',None) is not None:
            raise InputError('request CAPI original owner registry is missing')
        return
    provider.validate()
    if (provider.first_error is not None or any(t.active for t in provider.tickets) or
            any(row.get('live') or not row.get('recorded') for row in provider.handles) or
            any(not row.get('recorded') for row in provider.operations)):
        error=PrimarySemanticUnavailable('request CAPI retains original handle/buffer/operation dependencies')
        if provider.first_error is not None:raise error from provider.first_error
        raise error


def close(owner):
    preflight(owner)
    provider=_OWNERS.get(owner)
    if provider is None or provider.closed:return
    if provider.physical is not None:
        try:provider.physical.close()
        except BaseException as error:provider.fail(error);raise
    provider.closed=True


class _Ticket:
    def __init__(self,provider,capi,history,source,encoder,state,region):
        self.provider,self.capi,self.history=provider,capi,history
        self.source,self.encoder,self.state,self.region=source,encoder,state,region
        self.frame=capi.frame;self.active=True;self.current=None;self.buffers={}
        self.storage={}
        self.regions=history.regions+((self.frame,region,0x4D8),state.f_locals['self'].frame_region)

    def check(self,phase=None,buffer=None,handle=_TOKEN):
        from .primary_client_configuration_scope import require_owner
        from .primary_request_entry import produce,encode,_MaterialState
        from .primary_request_capi import _generate,derive_request_shared_with_capi,RequestCapiBuffer
        p=self.provider;p.validate();h=self.history;r=p.runtime
        if (not self.active or not any(t is self for t in p.tickets) or self.capi.ticket is not self or
                self.capi.runtime is not r or self.capi.frame!=self.frame or
                _HISTORY.get(id(h.producer)) is not h or h.provider is not p or h.claim.active or
                get_native_id()!=h.thread or r._main_generation!=h.generation or
                h.owner.serial is not h.claim.serial or
                require_owner(r,'client_loop') is not h.owner or h.owner.producer is not h.producer or
                h.owner.lease is not h.lease or not h.lease.active or h.lease.suspended or
                _frame(produce.__code__) is not self.source or _frame(encode.__code__) is not self.encoder or
                _frame(_MaterialState.produce.__code__) is not self.state or
                self.source.f_locals.get('service') is not self.capi or
                self.source.f_locals.get('runtime') is not r or self.source.f_locals.get('frame')!=self.frame or
                self.encoder.f_locals.get('runtime') is not r or
                self.encoder.f_locals.get('state') is not self.state.f_locals.get('self') or
                self.state.f_locals['self'].runtime is not r or
                self.state.f_locals['self'].frame!=self.encoder.f_locals.get('frame')):
            raise InputError('request CAPI original material ticket/history/frame/lease changed')
        actual,offset=r.memory._span(self.frame,0x4D8)
        if actual is not self.region or offset or actual.address!=self.frame or len(actual.data)!=0x4D8:
            raise InputError('request CAPI original material backing changed')
        for address,region,size in self.regions:
            actual,offset=r.memory._span(address,size)
            if actual is not region or offset or region.address!=address or len(region.data)!=size:
                raise InputError('request CAPI original producer/handoff/encoder backing changed')
        if phase is not None:
            helper=_frame(_generate.__code__);derive=_frame(derive_request_shared_with_capi.__code__)
            if (phase not in ('private','blinding') or helper is None or derive is None or
                    helper.f_back is not derive or helper.f_locals.get('capi') is not self.capi or
                    helper.f_locals.get('phase')!=phase or derive.f_locals.get('capi') is not self.capi):
                raise InputError('request CAPI requires its actual private/blinding source call')
            actual_buffer=helper.f_locals.get('buffer')
            if (type(actual_buffer) is not RequestCapiBuffer or buffer is not None and buffer is not actual_buffer or
                    len(actual_buffer._data)!=32 or len(actual_buffer._known)!=32):
                raise InputError('request CAPI original output buffer identity/extent changed')
            previous=self.buffers.setdefault(phase,actual_buffer)
            if previous is not actual_buffer:raise InputError('request CAPI phase buffer was replaced')
            data,mask=self.storage.setdefault(phase,(actual_buffer._data,actual_buffer._known))
            if actual_buffer._data is not data or actual_buffer._known is not mask:
                raise InputError('request CAPI original buffer storage/knownmask replaced')
            if handle is not _TOKEN and (self.current is None or self.current['phase']!=phase or
                    self.current['handle']!=handle or not self.current.get('live')):
                raise InputError('request CAPI handle differs from original acquisition')
            return actual_buffer


class _Provider:
    def __init__(self,owner,original,stage,token):
        if token is not _TOKEN:raise InputError('request CAPI provider requires factory issuer')
        self.owner,self.original,self.stage=owner,original,stage
        self.image,self.service,self.runtime,self.registrar,self.signer,_=original
        self.memory,self.base,self.epoch=self.runtime.memory,self.runtime.image_base,self.image.epoch
        self.issuer=self.runtime._primary_allocator_issuer;self.allocator_epoch=self.issuer.epoch
        self.kernel=self.service._kernel
        self.pid=os.getpid();self.tickets=[];self.operations=[];self.handles=[]
        self.physical=None;self.first_error=None;self.closed=False

    def validate(self):
        from .primary_client_configuration_scope import _OWNERS as clients
        from .primary_client_configuration_startup import require_request_stage
        o=self.owner;r=self.runtime
        if (_OWNERS.get(o) is not self or _RUNTIMES.get(r) is not self or
                getattr(o,'_owned_request_capi',None) is not self or r.request_capi is not self or
                clients.get(o) is not self.original or o._signer is not self.signer or o._threads is not self.service or
                o._registrar is not self.registrar or self.signer.runtime is not r or r.memory is not self.memory or
                self.service._kernel is not self.kernel or
                r.image_base!=self.base or self.image.epoch is not self.epoch or os.getpid()!=self.pid or
                r._primary_allocator_issuer is not self.issuer or self.issuer.epoch is not self.allocator_epoch or
                require_request_stage(r) is not self.stage):
            raise InputError('request CAPI original factory owner/runtime/image/allocator registry changed')
        self.image.validate(r)
        issued=_PHYSICAL.get(self)
        if issued is None:
            if self.physical is not None:raise InputError('request CAPI physical adapter is unissued')
        else:
            if self.physical is not issued[0]:raise InputError('request CAPI original physical adapter replaced')
            if issued[1] is not None:self.physical.validate_binding()
        if self.closed:raise InputError('request CAPI provider is terminal')

    def fail(self,error):
        if self.first_error is None:self.first_error=error

    def begin(self,capi):
        from .primary_client_configuration_scope import require_owner
        from .primary_request_entry import _Capi,produce,encode,_MaterialState
        self.validate();owner=require_owner(self.runtime,'client_loop');producer=owner.producer
        history=_HISTORY.get(id(producer));source=_frame(produce.__code__)
        encoder=_frame(encode.__code__);state=_frame(_MaterialState.produce.__code__)
        if (type(capi) is not _Capi or source is None or sys._getframe(2).f_code is not _Capi.__init__.__code__ or
                source.f_locals.get('runtime') is not self.runtime or source.f_locals.get('frame')!=capi.frame or
                history is None or history.producer is not producer or history.owner is not owner or
                history.provider is not self or history.claim.active or encoder is None or state is None or
                type(state.f_locals.get('self')) is not _MaterialState or
                any(t.history is history for t in self.tickets)):
            raise InputError('request CAPI requires its unique actual producer/audit/material chain')
        region,offset=self.memory._span(capi.frame,0x4D8)
        if offset or region.address!=capi.frame or len(region.data)!=0x4D8:
            raise InputError('request CAPI requires exact4D8 material source region')
        ticket=_Ticket(self,capi,history,source,encoder,state,region)
        self.tickets.append(ticket)
        return ticket

    def _ticket(self,operation,phase,handle=None,buffer=None):
        from .primary_request_entry import _Capi
        caller=sys._getframe(3)
        if caller.f_code is not getattr(_Capi,operation).__code__:
            raise InputError('request CAPI operation is private to actual source adapter')
        capi=caller.f_locals.get('self');ticket=getattr(capi,'ticket',None)
        if type(ticket) is not _Ticket or ticket.provider is not self:raise InputError('request CAPI ticket is unissued')
        ticket.check(phase,buffer)
        if self.first_error is not None:raise self.first_error
        if operation=='acquire':
            if ticket.current is not None:raise InputError('request CAPI prior acquisition has not returned through release')
        elif (ticket.current is None or ticket.current['phase']!=phase or ticket.current['handle']!=handle or
                not ticket.current.get('live')):
            raise InputError('request CAPI phase/handle differs from its actual acquisition')
        return ticket

    def _record(self,row):
        self.validate()
        row['ticket'].check(row['phase'],row.get('buffer'))
        row['recorded']=True

    def _call(self,operation,phase,handle=None,buffer=None):
        ticket=self._ticket(operation,phase,handle,buffer)
        row=dict(operation=operation,phase=phase,ticket=ticket,buffer=buffer,entered=False,returned=False,recorded=False,
                 handle=handle,result=None,output_slot=ctypes.c_size_t() if operation=='acquire' else None)
        self.operations.append(row)
        try:
            if self.physical is None:self.physical=_Physical(self)
            row['entered']=True
            result=self.physical.call(row)
            require_uint(result,32,'request CAPI actual result')
            row['result'],row['returned']=result,True
            if operation=='acquire':
                row['handle']=row['output_slot'].value
                if result:
                    row['live']=True;self.handles.append(row);ticket.current=row
            self._record(row)
            if operation=='release':
                if result:ticket.current['live']=False
                ticket.current=None
            return (result,row['handle']) if operation=='acquire' else result
        except BaseException as error:
            self.fail(error);raise

    def acquire(self,phase):return self._call('acquire',phase)
    def generate(self,phase,handle,buffer):return self._call('generate',phase,handle,buffer)
    def release(self,phase,handle):return self._call('release',phase,handle)


class _Physical:
    """Owns one LoadLibrary reference; source HCRYPTPROV ownership is separate."""
    def __init__(self,provider):
        if sys._getframe(1).f_code is not _Provider._call.__code__:
            raise InputError('request CAPI DLL resolution requires an authorized first operation')
        self.provider=provider;self.library=None;self.freed=False
        # Publish partial loader ownership before resolving individual symbols.
        provider.physical=self
        if provider in _PHYSICAL:raise InputError('request CAPI physical adapter cannot reload/adopt')
        _PHYSICAL[provider]=(self,None)
        self.library=ctypes.WinDLL('advapi32.dll',use_last_error=True)
        self.acquire=self.library.CryptAcquireContextW
        self.acquire.argtypes=(ctypes.POINTER(ctypes.c_size_t),ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32)
        self.acquire.restype=ctypes.c_int32
        self.generate=self.library.CryptGenRandom
        self.generate.argtypes=(ctypes.c_size_t,ctypes.c_uint32,ctypes.POINTER(ctypes.c_ubyte));self.generate.restype=ctypes.c_int32
        self.release=self.library.CryptReleaseContext
        self.release.argtypes=(ctypes.c_size_t,ctypes.c_uint32);self.release.restype=ctypes.c_int32
        signatures=tuple((tuple(fn.argtypes),fn.restype) for fn in (self.acquire,self.generate,self.release))
        _PHYSICAL[provider]=(self,(self.library,self.library._handle,self.acquire,self.generate,self.release,signatures))

    def validate_binding(self):
        issued=_PHYSICAL.get(self.provider)
        if issued is None or issued[0] is not self or issued[1] is None:
            raise InputError('request CAPI physical binding is incomplete or unissued')
        library,handle,acquire,generate,release,signatures=issued[1]
        functions=(self.acquire,self.generate,self.release)
        if (self.library is not library or self.library._handle!=handle or self.acquire is not acquire or
                self.generate is not generate or self.release is not release or
                any(tuple(fn.argtypes)!=args or fn.restype is not result for fn,(args,result) in zip(functions,signatures))):
            raise InputError('request CAPI original DLL reference/function/ABI changed')

    def call(self,row):
        self.validate_binding()
        caller=sys._getframe(1)
        if (caller.f_code is not _Provider._call.__code__ or caller.f_locals.get('self') is not self.provider or
                caller.f_locals.get('row') is not row or self.provider.operations[-1] is not row or
                not row['entered'] or row['returned']):
            raise InputError('request CAPI physical call lacks its original current operation')
        operation=row['operation']
        if operation=='acquire':
            return self.acquire(ctypes.byref(row['output_slot']),None,None,1,0xF0000000)&0xFFFFFFFF
        if operation=='release':return self.release(row['handle'],0)&0xFFFFFFFF
        buffer=row['buffer'];native=(ctypes.c_ubyte*32).from_buffer(buffer._data)
        row['native_buffer']=native
        result=self.generate(row['handle'],32,native)&0xFFFFFFFF
        if result:buffer._known[:]=b'\x01'*32
        return result

    def close(self):
        self.validate_binding()
        if self.freed:raise InputError('request CAPI DLL reference already retired')
        # This host-owned reference is not a source CryptReleaseContext call.
        kernel=self.provider.kernel  # Borrow the original factory's existing reference.
        free=kernel.FreeLibrary;free.argtypes=(ctypes.c_void_p,);free.restype=ctypes.c_int32
        if not free(self.library._handle):raise PrimarySemanticUnavailable('request CAPI owned DLL reference release failed')
        self.freed=True
