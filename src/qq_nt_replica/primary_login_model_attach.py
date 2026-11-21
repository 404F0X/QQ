"""Restricted MODEL C6 static constructor phase, never an original QQ epoch."""
import os,sys,threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke

_BIRTHS={}
_PHASES={}


def install_fresh_image(signer):
    from .primary_signer import PrimarySigner
    f=sys._getframe(1)
    if type(signer) is not PrimarySigner or f.f_code is not PrimarySigner._initialize_image.__code__ or f.f_locals.get('self') is not signer:
        raise InputError('Login birth requires original image installer')
    memory=signer.memory;key=id(memory)
    if key in _BIRTHS:raise InputError('Login image cannot be adopted/reset')
    records=[]
    for rva,size in ((0x6752b68,8),(0x674c6f0,24),(0x674c708,4),(0x674c748,24),(0x674c760,4),(0x6753528,8),(0x6753530,0xa8),(0x67535d8,4)):
        address=signer.image_base+rva
        memory.map(address,bytearray(size),name='fixed virtual-tail MODEL Login birth',initialized=True)
        region,offset=memory._span(address,size);records.append((address,region,offset,size))
    _BIRTHS[key]=(memory,signer.image_base,tuple(records))


def validate_birth(runtime):
    record=_BIRTHS.get(id(runtime.memory))
    if record is None or record[0] is not runtime.memory or record[1]!=runtime.image_base:
        raise InputError('Login MODEL birth missing')
    for address,region,offset,size in record[2]:
        actual,current=runtime.memory._span(address,size)
        if actual is not region or current!=offset:raise InputError('Login birth backing changed')


def _run_login_model_attach(owner):
    from .primary_windows_signer import WindowsSigner,open_windows_signer
    from .primary_windows_allocator_issuer import WindowsAllocatorIssuer
    f=sys._getframe(1)
    if type(owner) is not WindowsSigner or f.f_code is not WindowsSigner._initialize_crt.__code__ or f.f_locals.get('self') is not owner:
        raise InputError('C6 MODEL phase requires actual CRT factory point')
    caller=f;factory=False
    while caller is not None:
        if caller.f_code is open_windows_signer.__code__ and caller.f_locals.get('owner') is owner:factory=True
        caller=caller.f_back
    r=owner._signer.runtime;validate_birth(r)
    issuer=getattr(r,'_primary_allocator_issuer',None)
    if (not factory or owner._state!='constructing' or owner._pid!=os.getpid() or owner._thread!=threading.get_native_id() or
            owner._threads._runtime is not r or type(issuer) is not WindowsAllocatorIssuer or issuer.owner is not owner or
            not f.f_locals.get('crt_thread') or f.f_locals['crt_thread']!=r.crt_thread_address):
        raise InputError('C6 MODEL phase lost its actual owner/CRT binding')
    issuer.validate()
    key=id(r);record=_PHASES.get(key)
    if record is not None:
        if record['state']=='complete':return require_complete(r)
        raise PrimarySemanticUnavailable('C6 MODEL phase unavailable; no reentry/retry')
    record=dict(runtime=r,owner=owner,issuer=issuer,epoch=issuer.epoch,state='running',pointer=None,region=None,failure=None)
    _PHASES[key]=record
    try:
        pointer=_invoke(r,0xB75000,24);record['pointer']=pointer
        record['region']=r.memory._span(pointer,24)[0]
        _invoke(r,0x6270,pointer)
        r.memory.store(r.image_base+0x6752b68,pointer,8,source='C6F302.MODEL_static_publish')
        record['state']='complete'
        return pointer
    except BaseException as error:
        record['failure']=error;record['state']='failed';raise


def require_complete(runtime):
    validate_birth(runtime);record=_PHASES.get(id(runtime))
    if record is None or record['runtime'] is not runtime or record['state']!='complete':
        raise PrimarySemanticUnavailable('C6 MODEL process-attach constructor has not completed')
    issuer=getattr(runtime,'_primary_allocator_issuer',None)
    if issuer is not record['issuer'] or issuer.epoch is not record['epoch']:
        raise InputError('C6 MODEL allocator epoch changed')
    pointer=record['pointer'];actual,offset=runtime.memory._span(pointer,24)
    allocation=runtime._custom_allocator_backend.records.get(pointer)
    if (offset or actual is not record['region'] or allocation is None or allocation[0] is not actual or
            runtime.memory.load(runtime.image_base+0x6752b68,8)!=pointer):
        raise InputError('C6 MODEL target allocation changed')
    return pointer


def retire_terminal(owner):
    from .primary_windows_signer import WindowsSigner
    f=sys._getframe(1)
    if f.f_code is not WindowsSigner._release_resources.__code__ or f.f_locals.get('self') is not owner or owner._state!='closing' or owner._busy:
        raise InputError('C6 host retirement requires terminal owner cleanup')
    record=_PHASES.get(id(owner._signer.runtime))
    if record is not None:
        if record['owner'] is not owner or record['state']=='running' or record['issuer'].source._borrow is not None:
            raise InputError('C6 MODEL phase is not quiescent')
        record['state']='terminal'
