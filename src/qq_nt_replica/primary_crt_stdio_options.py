"""Limited MODEL stdio-options projection; not complete source CRT initialization."""
import os,sys,threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
_BIRTHS={}
_PHASES={}


def install_fresh_image(signer):
    from .primary_signer import PrimarySigner
    f=sys._getframe(1)
    if type(signer) is not PrimarySigner or f.f_code is not PrimarySigner._initialize_image.__code__ or f.f_locals.get('self') is not signer:
        raise InputError('stdio birth requires original image installer')
    m=signer.memory;key=id(m)
    if key in _BIRTHS:raise InputError('stdio birth cannot reset/adopt')
    address=signer.image_base+0x6749cc0
    m.map(address,bytearray(8),name='fixed PE zero-tail MODEL stdio options birth',initialized=True)
    region,offset=m._span(address,8)
    _BIRTHS[key]=(m,signer.image_base,region,offset)


def _birth(runtime):
    b=_BIRTHS.get(id(runtime.memory))
    if b is None or b[0] is not runtime.memory or b[1]!=runtime.image_base:raise InputError('stdio birth missing')
    region,offset=runtime.memory._span(runtime.image_base+0x6749cc0,8)
    if region is not b[2] or offset!=b[3]:raise InputError('stdio backing changed')
    return b


def run_model_stage(owner):
    from .primary_windows_signer import WindowsSigner,open_windows_signer
    from .primary_windows_allocator_issuer import WindowsAllocatorIssuer
    f=sys._getframe(1)
    if type(owner) is not WindowsSigner or f.f_code is not WindowsSigner._initialize_crt.__code__ or f.f_locals.get('self') is not owner:
        raise InputError('stdio projection requires actual factory CRT stage')
    caller=f;factory=False
    while caller:
        if caller.f_code is open_windows_signer.__code__ and caller.f_locals.get('owner') is owner:factory=True
        caller=caller.f_back
    r=owner.signer.runtime;b=_birth(r);issuer=getattr(r,'_primary_allocator_issuer',None)
    if (not factory or owner._state!='constructing' or owner._pid!=os.getpid() or owner._thread!=threading.get_native_id() or
            owner._threads._runtime is not r or type(issuer) is not WindowsAllocatorIssuer or issuer.owner is not owner or
            not f.f_locals.get('crt_thread') or f.f_locals['crt_thread']!=r.crt_thread_address):
        raise InputError('stdio factory/thread/CRT identity mismatch')
    issuer.validate()
    if id(r) in _PHASES:raise PrimarySemanticUnavailable('stdio MODEL phase cannot retry/reenter')
    from .primary_module_sync import backend
    mode=backend(r)
    record=dict(mode=mode,runtime=r,owner=owner,issuer=issuer,epoch=issuer.epoch,birth=b,state='running',failure=None)
    _PHASES[id(r)]=record
    try:
        address=r.image_base+0x6749cc0
        value=r.memory.load(address,8)
        r.memory.store(address,value|0x24,8,source='3E6BA7C.MODEL_stdio_OR24')
        record['state']='complete'
    except BaseException as error:record['state']='failed';record['failure']=error;raise


def read_options(runtime):
    b=_birth(runtime);record=_PHASES.get(id(runtime))
    if record is None or record['runtime'] is not runtime or record['state']!='complete':
        raise PrimarySemanticUnavailable('stdio MODEL options phase not complete')
    from .primary_module_sync import backend
    if backend(runtime)!=record['mode'] or record['owner']._state not in ('constructing','open','closing') or record['owner']._pid!=os.getpid() or record['owner']._thread!=threading.get_native_id():
        raise InputError('stdio mode/owner thread changed')
    issuer=getattr(runtime,'_primary_allocator_issuer',None)
    if issuer is not record['issuer'] or issuer.epoch is not record['epoch'] or record['birth'] is not b:
        raise InputError('stdio options epoch changed')
    return runtime.memory.load(runtime.image_base+0x6749cc0,8)


def retire_terminal(owner):
    from .primary_windows_signer import WindowsSigner
    f=sys._getframe(1)
    if f.f_code is not WindowsSigner._release_resources.__code__ or f.f_locals.get('self') is not owner or owner._state!='closing' or owner._busy:
        raise InputError('stdio retirement requires terminal owner')
    record=_PHASES.get(id(owner.signer.runtime))
    if record:
        if record['owner'] is not owner or record['state']=='running' or record['issuer'].source._borrow is not None:raise InputError('stdio stage not quiescent')
        record['state']='terminal'
