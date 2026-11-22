"""Source MSF selection to its actual unavailable MMKV open boundary."""
import sys
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_logger import _String
from .primary_worker_response import _frame
from .primary_worker_consumer import _invoke
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



def _nt_mmkv_method(runtime,interface,identifier,path,crypt):
    from .primary_native_logger import nt_file_basename,nt_misc_mmkv
    from .primary_mmkv_host_init import construct_nt_empty_byte_path,construct_nt_empty_wide_path
    memory=runtime.memory;pending=runtime._mmkv_caller_pending
    frame,unused=_frame(runtime,0x90,'64C9E owning copies, span, byte/wide paths and guard')
    pending.update(interface=interface,method_frame=frame,id_copy=frame,span=frame+0x18,crypt_copy=frame+0x28,path_copy=frame+0x40,wide=frame+0x58,bytepath=frame+0x70,guard=frame+0x88)
    for callsite,destination,source in ((0x64cd9,frame+0x28,crypt),(0x64ce8,frame+0x40,path),(0x64cf7,frame,identifier)):
        runtime.events.append(('source.75B810',callsite,destination,source));_invoke(runtime,0x75b810,destination,source)
    file=nt_file_basename(runtime)
    nt_misc_mmkv(runtime,file,frame,frame+0x40,frame+0x28)
    if not _String.read(runtime,identifier).value():raise PrimarySemanticUnavailable('64D4F empty MMKV identifier branch unavailable')
    value=_String.read(runtime,path);tag=value.get(0,1)
    memory.store(frame+0x18,value.get(16,8) if tag&1 else path+1,8,source='64D94.original_R8_span_pointer')
    memory.store(frame+0x20,value.get(8,8) if tag&1 else tag>>1,8,source='64D94.original_R8_span_length')
    construct_nt_empty_byte_path(runtime,frame+0x70,frame+0x18)
    construct_nt_empty_wide_path(runtime,frame+0x58,frame+0x70)
    pending['phase']='open'
    try:raw=_mmkv_open(runtime,identifier,2,0 if not _String.read(runtime,crypt).value() else crypt,0 if not value.value() else frame+0x58,0)
    except BaseException:
        pending['phase']='open_incomplete'
        raise
    pending['phase']='caller_guard'
    pending.update(raw=raw,lock=interface+0x3b0)
    from .primary_windows_mmkv_host_init import for_runtime
    session=for_runtime(runtime)._WindowsMMKVHost__open;session['caller']=pending;session['boundary']=0xd3de50
    memory.store(frame+0x88,interface+0x3b0,8,source='64E04.caller_guard_pointer')
    from .primary_nt_misc_map import bind
    bound=bind(runtime,pending);runtime._nt_misc_record=bound
    bound.acquire();bound.publish(identifier,raw)
    bound.release()
    pending['released_guard_value']=memory.load(pending['guard'],8)
    from .primary_mmkv_host_init import destroy_wide_root
    for site,address,kind in ((0x64e2f,frame+0x58,'wide'),(0x64e38,frame+0x70,'byte'),(0x64e41,path,'R8'),(0x64e4a,crypt,'R9')):
        runtime.events.append(('source.NT_normal_dtor',site,address))
        if kind=='wide':destroy_wide_root(runtime,address)
        else:_String.read(runtime,address).destroy()
    pending['method_consumed']=True
    memory.unmap(frame);pending['method_finished']=True
    runtime.events.append(('source.64C9E.return',raw))
    return raw

def _callback_7510f1(runtime,closure,frame):
    memory=runtime.memory
    if closure!=frame+0x30 or memory.load(closure,8)!=frame+0x38 or memory.load(frame+0x38,8)!=frame+0x2f:
        raise InputError('7503EA synchronous closure pointer chain changed')
    runtime.events.append(('source.callback',0x7510F1,closure))
    pending=dict(phase='callback_entered',callback_frame=frame,nt_pair=None)
    runtime._mmkv_caller_pending=pending
    obj,control=acquire_nt(runtime);pending['nt_pair']=(obj,control)
    local,unused=_frame(runtime,0x50,'7510F1 owned String locals');pending['locals']=local
    for offset,value in ((0,b'nt_mmkv_msf_united_config'),(0x18,b''),(0x30,b'')):
        _String.construct(runtime,value).write_to(local+offset)
    alias=obj+8
    target=memory.load(memory.load(alias,8)+0x30,8)
    if target!=runtime.image_base+0x64c9e:raise InputError('NT misc MMKV interface target mismatch')
    pending['phase']='nt_method'
    _nt_mmkv_method(runtime,alias,local,local+0x18,local+0x30)
    runtime.events.append(('source.callback_normal_dtor',0x75116f,local))
    _String.read(runtime,local).destroy();pending['callback_id_consumed']=True
    release_nt(runtime,obj,control);pending['callback_pair_consumed']=True
    memory.unmap(local);pending['callback_finished']=True
    history=getattr(runtime,'_nt_callback_history',None)
    if history is None:history=[];runtime._nt_callback_history=history
    history.append(pending);runtime._mmkv_caller_pending=None
    runtime.events.append(('source.7510F1.return',0x751188))


def _preinitialize(runtime):
    memory=runtime.memory
    if memory.load(runtime.image_base+0x674d418,8)==(1<<64)-1:return
    frame,unused=_frame(runtime,0x40,'7503EA synchronous closure')
    memory.store(frame+0x38,frame+0x2f,8,source='7503EA.marker_pointer')
    memory.store(frame+0x30,frame+0x38,8,source='7503EA.closure_pointer')
    from .primary_module_sync import selector_once
    try:selector_once(runtime,lambda:_callback_7510f1(runtime,frame+0x30,frame))
    except BaseException as error:
        runtime._selector_once_failure=(error,memory.load(runtime.image_base+0x674d418,8))
        raise
    runtime._nt_callback_history[-1]['once_finished']=True
    memory.unmap(frame);runtime._nt_callback_history[-1]['closure_frame_finished']=True
    runtime.events.append(('source.7503EA.return',0x7507bc))


def _config_prepare(runtime):
    memory=runtime.memory
    frame,unused=_frame(runtime,0x60,'750756 config output/key/id/new NT pair')
    pending=dict(frame=frame,output=frame,key=frame+0x18,identifier=frame+0x30)
    runtime._selector_config_pending=pending
    _invoke(runtime,0x6270,frame)
    obj,control=acquire_nt(runtime);pending['nt_pair']=(obj,control)
    memory.store(frame+0x48,obj,8,source='7507C9.new_NT_object');memory.store(frame+0x50,control,8,source='7507C9.new_NT_control')
    for site,address,literal,rva in ((0x7507dd,frame+0x18,b'107775_switch',0x3f71a2a),(0x7507ed,frame+0x30,b'nt_mmkv_msf_united_config',0x3f71a10)):
        runtime.events.append(('source.330E',site,address,runtime.image_base+rva,len(literal)))
        _String.construct(runtime,literal).write_to(address)
    alias=obj+8;target=memory.load(memory.load(alias,8)+0x38,8)
    pending.update(alias=alias,target=target)
    runtime.events.append(('source.unavailable',target-runtime.image_base,0x750808,alias,frame+0x30,frame+0x18,frame))
    from .primary_windows_mmkv_host_init import for_runtime
    for_runtime(runtime)._WindowsMMKVHost__open['boundary']=target-runtime.image_base
    raise PrimarySemanticUnavailable('750808 actual NT config target '+hex(target-runtime.image_base)+' unavailable')


def select(runtime):
    _validate(runtime);receipt=resolve_current_module_tls(runtime)
    memory,base=runtime.memory,runtime.image_base;guard=base+0x674d424
    if memory.load(guard,4,signed=True)>memory.load(receipt.epoch_address,4,signed=True):
        runtime._locale_thread_header(guard)
        if memory.load(guard,4,signed=True)==-1:
            _preinitialize(runtime)
            _config_prepare(runtime)
    return bool(memory.load(base+0x674d420,1))


def initialize_login_msf(runtime,login_object):
    if runtime.memory.load(login_object+0x90,8):return
    # 72DE38 factory must return before self90/98 or29D9E can be written.
    select(runtime)
    raise PrimarySemanticUnavailable('72DE38 selected MSF factory construction unavailable')
