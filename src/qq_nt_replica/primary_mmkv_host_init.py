"""Finite source ASCII wide-root construction; no MMKV success or host IO."""
from .primary_worker_consumer import _invoke
from .primary_vm import PrimarySemanticUnavailable
from .primary_logger import _String
from .errors import InputError


def construct_wide_root(runtime, output, source):
    """D36138 -> D44D1B -> D4511C, fresh disjoint source ASCII domain."""
    memory=runtime.memory
    source_address=source
    source=_String.read(runtime,source_address)
    data=source.value();size=len(data)
    if source_address<output+24 and output<source_address+24:
        raise PrimarySemanticUnavailable('D4511C aliased String object unsupported')
    _invoke(runtime,0x6270,output)
    if any(byte>=128 for byte in data):
        raise PrimarySemanticUnavailable('D44D1B non-ASCII conversion branch unavailable')
    if not 10<size:
        raise PrimarySemanticUnavailable('D4511C short-root branch outside current finite domain')
    # The source is an independent String; reject overlap rather than invent alias handling.
    if source.get(0,1)&1:
        begin=source.get(16,8)
        if begin<output+24 and output<begin+size:
            raise PrimarySemanticUnavailable('D4511C aliased byte-path branch unavailable')
    capacity=(max(size,20)|7)+1
    pointer=_invoke(runtime,0xB75000,2*capacity)
    memory.store(output+16,pointer,8,source='75D3B0.publish_buffer')
    memory.store(output,capacity|1,8,source='75D3B0.publish_capacity')
    for index,byte in enumerate(data):
        memory.store(pointer+2*index,byte,2,source='D4511C.ASCII_word')
    memory.store(pointer+2*size,0,2,source='D4511C.terminator')
    memory.store(output+8,size,8,source='D4511C.length')
    if size>=200:
        raise PrimarySemanticUnavailable('D36138 extended-path prefix branch unavailable after conversion')
    return output


def copy_wide_root_fresh(runtime, destination, source):
    """75DF80 fresh short-empty -> long owning copy, separate allocation."""
    memory=runtime.memory
    if destination==source:return destination
    if memory.load(destination,1)&1 or memory.load(destination,1)>>1:
        raise PrimarySemanticUnavailable('75DF80 non-fresh destination branch unavailable')
    if not memory.load(source,1)&1:
        raise PrimarySemanticUnavailable('75DF80 short-source branch outside current finite domain')
    size=memory.load(source+8,8);old=memory.load(source+16,8)
    if not 10<size<200:raise PrimarySemanticUnavailable('75DF80 root length outside finite domain')
    payload=memory.read(old,2*size)
    capacity=(max(size,20)|7)+1
    pointer=_invoke(runtime,0xB75000,2*capacity)
    memory.write(pointer,payload,source='75DF80.copy_words')
    memory.store(destination+16,pointer,8,source='75DF80.publish_buffer')
    memory.store(destination,capacity|1,8,source='75DF80.publish_capacity')
    memory.store(destination+8,size,8,source='75DF80.publish_length')
    memory.store(pointer+2*size,0,2,source='75DF80.terminator')
    return destination


def destroy_wide_root(runtime, address):
    if runtime.memory.load(address,1)&1:
        _invoke(runtime,0xB75029,runtime.memory.load(address+16,8))


_BIRTHS={}


def install_fresh_image(signer):
    import sys
    from .primary_signer import PrimarySigner
    from .primary_memory import PrimaryMemoryLimit
    f=sys._getframe(1)
    if type(signer) is not PrimarySigner or f.f_code is not PrimarySigner._initialize_image.__code__ or f.f_locals.get('self') is not signer:
        raise InputError('MMKV cells require original MODEL image installer')
    if id(signer.memory) in _BIRTHS:raise InputError('MMKV birth cannot be adopted/reset')
    records=[]
    for rva,size,known in ((0x6751388,8,True),(0x6751390,8,True),(0x6751398,24,True),(0x67513c8,4,True),(0x6188c48,4,False),(0x677bc70,8,True)):
        address=signer.image_base+rva
        try:region,offset=signer.memory._span(address,size)
        except PrimaryMemoryLimit:
            signer.memory.map(address,bytearray(size),name='source MMKV MODEL image cell',initialized=known)
            region,offset=signer.memory._span(address,size)
        records.append((address,region,offset,size))
    _BIRTHS[id(signer.memory)]=(signer.memory,signer.image_base,tuple(records))


def _validate(runtime):
    record=_BIRTHS.get(id(runtime.memory))
    if record is None or record[0] is not runtime.memory or record[1]!=runtime.image_base:
        raise InputError('MMKV birth identity missing')
    for address,region,offset,size in record[2]:
        actual,current=runtime.memory._span(address,size)
        if actual is not region or current!=offset:raise InputError('MMKV image cell backing changed')


def _stdio_options(runtime):
    runtime.events.append(('source.input.unavailable',0x6749cc0,8,'3E6EE80'))
    raise PrimarySemanticUnavailable('3E6EE80 full u64 source stdio options6749CC0 current-epoch input unavailable')


def _log(runtime,level,file,function,line,template,arguments):
    from .primary_worker_response import _frame
    if runtime.memory.load(runtime.image_base+0x6188c48,4,signed=True)>level:return
    runtime.events.append(('1BDF22C.arguments',level,file,function,line,template,arguments))
    _frame(runtime,16,'7017B4 initial stdio output buffer')
    _stdio_options(runtime)


def _version_log(runtime,page_size):
    _log(runtime,1,b'MMKV.cpp',b'initialize',0xae,b'version %s, page size %d, arch %s',(b'v1.3.2',page_size,b'x86_64'))


def _initialize_cache(runtime):
    import struct
    from .primary_windows_mmkv_host_init import for_runtime
    memory=runtime.memory;base=runtime.image_base
    cache=_invoke(runtime,0xB75000,40)
    memory.write(cache,bytes(32),source='B99489.cache_zero20')
    memory.write(cache+32,struct.pack('<f',1.0),source='B99489.load_factor')
    memory.store(base+0x6751388,cache,8,source='B99489.publish_cache')
    lock=_invoke(runtime,0xB75000,40)
    memory.write(lock,bytes(40),source='B99489.lock_zero28')
    memory.store(base+0x6751390,lock,8,source='B99489.publish_lock')
    port=for_runtime(runtime);port._issue_lock(lock)
    result,error=port.initialize_lock()
    if not result:
        _log(runtime,3,b'ThreadLock_Win32.cpp',b'initialize',0x29,b'fail to init critical section:%d',(error&0xffffffff,))
    page=port.page_size()
    _version_log(runtime,page)


def initialize(runtime,wide_root):
    _validate(runtime);memory=runtime.memory;base=runtime.image_base
    # B9955C stores its source level/handler before independent once initialization.
    memory.store(base+0x6188c48,1,4,source='B9955C.level')
    memory.store(base+0x677bc70,0,8,source='B9955C.handler')
    flag=base+0x67513c8;state=memory.load(flag,4)
    if state==0:
        memory.store(flag,1,4,source='1BD91CC.single_creator_compare_exchange')
        _initialize_cache(runtime)
        memory.store(flag,2,4,source='1BD910A.normal_complete')
    elif state==1:
        raise PrimarySemanticUnavailable('1BD91D8 Sleep(1) in-progress MMKV initializer unavailable')
    elif state!=2:
        raise PrimarySemanticUnavailable('1BD910A unexpected once-state branch unavailable')
    copy_wide_root_fresh(runtime,base+0x6751398,wide_root)
    raise PrimarySemanticUnavailable('1BD8F45 source directory traversal requires additional scoped source host ports')


def initialize_login_root(runtime,common_path):
    import re
    from .primary_worker_response import _frame
    from .primary_native_logger import _append
    raw=common_path.value()
    if re.fullmatch(rb'[A-Za-z]:\\[A-Za-z0-9_-]+(?:\\[A-Za-z0-9_-]+)*',raw) is None:
        raise PrimarySemanticUnavailable('D34792 byte-path normalization outside finite domain')
    frame,unused=_frame(runtime,120,'Login byte paths and owned wide root')
    base=_String.construct(runtime,raw);base.write_to(frame)
    component=_String.construct(runtime,b'mmkv');component.write_to(frame+24)
    joined=base.clone();joined.write_to(frame+48)
    # Finite D355D8 makes no mutation; D353DC copies base, inserts separator, appends component.
    _append(joined,frame+48,b'\\',literal=False)
    _append(joined,frame+48,component.value(),literal=False)
    moved=_String(runtime,joined.header,joined.known);moved.write_to(frame+72)
    _String.construct(runtime,b'').write_to(frame+48)
    component.destroy();base.destroy()
    construct_wide_root(runtime,frame+96,frame+72)
    initialize(runtime,frame+96)
    destroy_wide_root(runtime,frame+96);moved.destroy();runtime.memory.unmap(frame)
