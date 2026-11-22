"""Source MSF selection to its actual unavailable MMKV open boundary."""
import sys
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_logger import _String
from .primary_worker_response import _frame
from .primary_shared_locale import resolve_current_module_tls
from .primary_nt_wrapper_owner import acquire as acquire_nt,release as release_nt

_BIRTHS={}


def install_fresh_image(signer):
    from .primary_signer import PrimarySigner
    caller=sys._getframe(1)
    if type(signer) is not PrimarySigner or caller.f_code is not PrimarySigner._initialize_image.__code__ or caller.f_locals.get('self') is not signer:
        raise InputError('MSF selector cells require original model image installer')
    key=id(signer.memory)
    if key in _BIRTHS:raise InputError('MSF selector cannot adopt/reset existing image')
    rows=[]
    for rva,size in ((0x674d420,1),(0x674d424,4)):
        address=signer.image_base+rva
        signer.memory.map(address,bytearray(size),name='fixed PE virtual-tail MODEL selector birth',initialized=True)
        region,offset=signer.memory._span(address,size);rows.append((address,region,offset,size))
    _BIRTHS[key]=(signer.memory,signer.image_base,tuple(rows))


def _validate(runtime):
    birth=_BIRTHS.get(id(runtime.memory))
    if birth is None or birth[0] is not runtime.memory or birth[1]!=runtime.image_base:
        raise InputError('MSF selector missing original model-loader birth')
    for address,region,offset,size in birth[2]:
        actual,current=runtime.memory._span(address,size)
        if actual is not region or current!=offset:raise InputError('MSF selector backing changed')


def _mmkv_open(runtime,identifier,mode,key,path,extra):
    if (mode,key,path,extra)!=(2,0,0,0) or _String.read(runtime,identifier).value()!=b'nt_mmkv_msf_united_config':
        raise InputError('64C9E MMKV source argument mismatch')
    runtime.events.append(('source.mmkv_open',0xB99200,identifier,mode,key,path,extra))
    from .primary_mmkv_open import open_mmkv
    return open_mmkv(runtime,identifier,mode,key,path,extra)


def _callback_7510f1(runtime,closure,frame):
    memory=runtime.memory
    if closure!=frame+0x30 or memory.load(closure,8)!=frame+0x38 or memory.load(frame+0x38,8)!=frame+0x2f:
        raise InputError('7503EA synchronous closure pointer chain changed')
    runtime.events.append(('source.callback',0x7510F1,closure))
    # Entry overwrites RCX for5B11A before reading the incoming marker byte.
    obj,control=acquire_nt(runtime)
    local=None;values=[]
    try:
        local,unused=_frame(runtime,0x50,'7510F1 owned String locals')
        for offset,value in ((0,b'nt_mmkv_msf_united_config'),(0x18,b''),(0x30,b'')):
            string=_String.construct(runtime,value);values.append(string);string.write_to(local+offset)
        alias=obj+8
        target=memory.load(memory.load(alias,8)+0x30,8)
        if target!=runtime.image_base+0x64c9e:raise InputError('NT misc MMKV interface target mismatch')
        # 64C9E calls B99200 before entering its later custom atomic map lock.
        return _mmkv_open(runtime,local,2,0,0,0)
    finally:
        # Host abort cleanup of known owned temporaries, not original EH proof.
        for value in reversed(values):value.destroy()
        if local is not None:runtime.memory.unmap(local)
        release_nt(runtime,obj,control)


def _preinitialize(runtime):
    memory=runtime.memory
    if memory.load(runtime.image_base+0x674d418,8)==(1<<64)-1:return
    frame,unused=_frame(runtime,0x40,'7503EA synchronous closure')
    memory.store(frame+0x38,frame+0x2f,8,source='7503EA.marker_pointer')
    memory.store(frame+0x30,frame+0x38,8,source='7503EA.closure_pointer')
    from .primary_module_sync import selector_once
    try:
        return selector_once(runtime,lambda:_callback_7510f1(runtime,frame+0x30,frame))
    finally:memory.unmap(frame)


def select(runtime):
    _validate(runtime);receipt=resolve_current_module_tls(runtime)
    memory,base=runtime.memory,runtime.image_base;guard=base+0x674d424
    if memory.load(guard,4,signed=True)>memory.load(receipt.epoch_address,4,signed=True):
        runtime._locale_thread_header(guard)
        if memory.load(guard,4,signed=True)==-1:
            _preinitialize(runtime)
            raise PrimarySemanticUnavailable('65240 MMKV lookup/decode after preinit unavailable')
    return bool(memory.load(base+0x674d420,1))


def initialize_login_msf(runtime,login_object):
    if runtime.memory.load(login_object+0x90,8):return
    # 72DE38 factory must return before self90/98 or29D9E can be written.
    select(runtime)
    raise PrimarySemanticUnavailable('72DE38 selected MSF factory construction unavailable')
