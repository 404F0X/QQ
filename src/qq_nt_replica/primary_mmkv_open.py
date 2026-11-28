"""Connected finite cold B99200 open through ordinary empty load and publication."""
import ctypes as C
import sys
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_logger import _String
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
from .primary_mmkv_file import wide,append,WidePath,File40,FileLock,emit,_TOKEN


def _converted(r,port,identifier):
    raw=identifier.value()
    if raw!=b'nt_mmkv_msf_united_config':raise PrimarySemanticUnavailable('other MMKV id conversion/blacklist branches unavailable')
    source=C.create_string_buffer(raw+b'\0');session=port._WindowsMMKVHost__open
    session['buffers'].append(source)
    types=(C.c_uint32,C.c_uint32,C.c_void_p,C.c_int32,C.c_void_p,C.c_int32)
    n,_=port._file_call('MultiByteToWideChar',C.c_int32,types,(65001,0,C.addressof(source),-1,0,0))
    pointer=_invoke(r,0xB758C4,2*n if n>=0 else (1<<64)-1)
    pin,view=r.memory._pin_native_span(pointer,2*n,port);native=(C.c_uint16*n).from_buffer(view)
    session['buffers'].append((pin,view,native,pointer))
    written,_=port._file_call('MultiByteToWideChar',C.c_int32,types,(65001,0,C.addressof(source),-1,C.addressof(native),n))
    if written>0:r.memory.write(pointer,bytes(view[:min(written,n)*2]),source='MultiByteToWideChar.actual_prefix')
    end=0
    while r.memory.load(pointer+end,2):end+=2
    rawwide=r.memory.read(pointer,end)
    output,_=_frame(r,24,'30EDD4 independent converted wide')
    converted=wide(r,output,rawwide)
    r.memory._unpin_native_span(pin,port);view.release();session['buffers'].pop();session['buffers'].pop()
    _invoke(r,0xB758ED,pointer)
    return converted


def _path(r,port,address,identifier,crc=False):
    root=r.image_base+0x6751398
    value=WidePath(r,root,_TOKEN);raw=value.raw[:-2]
    result=wide(r,address,raw+b'\\\0',((value.length+1)|7)+1)
    converted=_converted(r,port,identifier)
    result=append(r,result,converted.raw[:-2])
    converted.destroy();r.memory.unmap(converted.address)
    if crc:result=append(r,result,b'.\0c\0r\0c\0')
    return result


def _parent(r,port,parent,identifier):
    if sys._getframe(1).f_code is not open_mmkv.__code__:raise InputError('parent constructor requires actual cold MMKV miss')
    m=r.memory;b=r.image_base;session=port._WindowsMMKVHost__open
    if session['parent']!=parent:raise InputError('parent constructor allocation identity changed')
    _invoke(r,0x6270,parent)
    identifier.clone().write_to(parent+0x18)
    main=_path(r,port,parent+0x30,identifier);crc=_path(r,port,parent+0x48,identifier,True)
    session['paths']=[main,crc]
    m.write(parent+0x60,bytes(16),source='B986E3.zero16')
    first=_invoke(r,0xB75000,0x40);temporary,_=_frame(r,24,'B98700 copied main path temporary')
    copy=wide(r,temporary,main.raw[:-2]);file1=File40(r,port,first,copy)
    m.unmap(temporary);m.store(parent+0x70,first,8,source='B98719.publish_first_file')
    second=_invoke(r,0xB75000,0x40);temporary,_=_frame(r,24,'B98730 copied crc path temporary')
    copy=wide(r,temporary,crc.raw[:-2]);file2=File40(r,port,second,copy)
    m.unmap(temporary);m.store(parent+0x90,second,8,source='B9874E.publish_second_file')
    data=_invoke(r,0xB75000,0x70)
    m.store(data,0,8,source='B9875A.shared_data_zero');m.store(data+4,1,4,source='B98760.shared_data_count');m.write(data+8,bytes(0x68),source='B98770.shared_data_rest')
    m.store(parent+0x98,data,8,source='B98780.shared_data_publish');m.store(parent+0xa0,0,8,source='B98788.fieldA0')
    lock=_invoke(r,0xB75000,0x28);m.write(lock,bytes(0x28),source='1BD90A0.zero_CS');m.store(parent+0xa8,lock,8,source='B98790.parent_CS')
    state=_invoke(r,0xB75000,0x38);m.store(parent+0xb0,state,8,source='B987A0.parent_lock_state')
    guard=FileLock(r,port,file2.load(0x18),0,state)
    for off,kind in ((0xb8,0),(0xc0,1)):
        wrapper=_invoke(r,0xB75000,0x10)
        m.store(wrapper,state,8,source='B98E2C.state');m.store(wrapper+8,kind,4,source='B98E2C.type');m.store(wrapper+0xc,1,1,source='B98E2C.enabled')
        m.store(parent+off,wrapper,8,source='B98830.wrapper_publish')
    for off,size,value in ((0xc8,1,0),(0xcc,4,0),(0xd0,1,0),(0xd1,1,1)):
        m.store(parent+off,value,size,source='B98850.source_flags')
    m.write(parent+0x78,bytes(16),source='B98870.zero16')
    cache=_invoke(r,0xB75000,0x28);m.write(cache,bytes(32),source='B98880.cache_zero');m.store(cache+32,0x3f800000,4,source='B98888.load_factor');m.store(parent+0x60,cache,8,source='B98890.cache_publish')
    m.store(parent+0x88,1,2,source='B98900.field88');m.store(parent+0x8c,0,4,source='B98908.field8C')
    pin,view=m._pin_native_span(lock,40,port);native=(C.c_ubyte*40).from_buffer(view);session['buffers'].append((pin,view,native,lock))
    result,error=port._file_call('InitializeCriticalSectionAndSpinCount',C.c_int32,(C.c_void_p,C.c_uint32),(C.addressof(native),0x400),error=True)
    m._record_native_write(pin,port,source='1BD90BC.actual_CS')
    if not result:emit(r,'cs_error',error)
    for off in (0xb8,0xc0):m.store(m.load(parent+off,8)+0xc,m.load(parent+0xd1,1),1,source='B98948.copy_enabled')
    guard.acquire() # shared type0 ordinary FALSE ignored
    from .primary_mmkv_load import load
    session['outer_guard']=guard
    load(r,port,parent,guard)
    guard.release()
    r.events.append(('source.parent_return',0xb9898f,parent))
    return parent


def open_mmkv(runtime,identifier,mode,key,path,extra):
    if (mode,key,path,extra)!=(2,0,0,0):raise PrimarySemanticUnavailable('other MMKV open domain unavailable')
    from .primary_windows_mmkv_host_init import for_runtime
    from .primary_mmkv_host_init import _validate
    _validate(runtime);port=for_runtime(runtime)
    session=dict(runtime=runtime,global_lock='not_entered',parent=None,files=[],locks=[],paths=[],buffers=[],boundary=None)
    port._begin_open(session)
    try:
        guard,_=_frame(runtime,8,'B995F0 global CS guard')
        runtime.memory.store(guard,0,8,source='B995F0.guard_zero')
        runtime.memory.store(guard,runtime.memory.load(runtime.image_base+0x6751390,8),8,source='B995F0.guard_publish')
        session['global_guard']=guard;port._enter_global()
        local,_=_frame(runtime,32,'B996A0 owned NULL-root MMKV key')
        source=_String.read(runtime,identifier);owned=source.clone();owned.write_to(local);session['key']=local
        cache=runtime.memory.load(runtime.image_base+0x6751388,8)
        _invoke(runtime,0x8ed82,cache,local+24,local)
        if runtime.memory.load(cache+8,8) or runtime.memory.load(local+24,8):
            raise PrimarySemanticUnavailable('noncold MMKV lookup branch outside finite connected prefix')
        parent=_invoke(runtime,0xB75000,0xd8);session['parent']=parent
        _parent(runtime,port,parent,source)
        _invoke(runtime,0x75cec0,parent,local)
        from .primary_mmkv_map import emplace
        slot=emplace(runtime,cache,local)
        runtime.memory.store(slot,parent,8,source='B9938A.cache_value_publish')
        _String.read(runtime,local).destroy();runtime.memory.unmap(local)
        port._leave_global()
        runtime.memory.store(guard,0,8,source='B99399.global_guard_clear');runtime.memory.unmap(guard)
        runtime.events.append(('source.mmkv_return',parent))
        return parent
    except BaseException as error:
        session.setdefault('failure',error)
        raise
