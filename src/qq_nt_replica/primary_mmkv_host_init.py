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
    address=signer.image_base+0x67513b0
    signer.memory.map(address,bytearray(8),name='fixed PE virtual-tail MODEL MMKV page birth',initialized=True)
    region,offset=signer.memory._span(address,8);records.append((address,region,offset,8))
    image=signer._shared_locale_image
    _BIRTHS[id(signer.memory)]=(signer.memory,signer.image_base,tuple(records),image,image.epoch)


def _validate(runtime):
    record=_BIRTHS.get(id(runtime.memory))
    if record is None or record[0] is not runtime.memory or record[1]!=runtime.image_base:
        raise InputError('MMKV birth identity missing')
    image,epoch=record[3:]
    if (getattr(runtime,'_shared_locale_source',None) is not image or
            getattr(runtime,'_shared_locale_source_epoch',None) is not epoch or image.epoch is not epoch or
            image.signer._shared_locale_image is not image):
        raise InputError('MMKV fixed image source/epoch changed')
    image.validate_image(runtime)
    for address,region,offset,size in record[2]:
        actual,current=runtime.memory._span(address,size)
        if actual is not region or current!=offset:raise InputError('MMKV image cell backing changed')
    address,region,offset,size=record[2][-1]
    if region.address!=address or offset or len(region.data)!=8:
        raise InputError('MMKV page birth exact region changed')


def _log(runtime,level,file,function,line,template,arguments):
    from .primary_mmkv_log import log
    return log(runtime,level,file,function,line,template,arguments)


def _version_log(runtime,page_size):
    _log(runtime,1,b'MMKV.cpp',b'initialize',0xae,b'version %s, page size %d, arch %s',(b'v1.3.2',page_size,b'x86_64'))


def _initialize_cache(runtime):
    _validate(runtime)
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
    _validate(runtime)
    page=page&0xffffffff
    memory.store(base+0x67513b0,page,8,source='B994E8.publish_page_size')
    _version_log(runtime,page)


_WIDE_TOKEN=object()


class _WideArgument:
    def __init__(self,runtime,address,token):
        if token is not _WIDE_TOKEN or address!=runtime.image_base+0x6751398:
            raise InputError('wide argument requires original MMKV global root')
        _validate(runtime)
        self.runtime=runtime;self.memory=runtime.memory;self.base=runtime.image_base
        self.source=runtime._shared_locale_source;self.epoch=runtime._shared_locale_source_epoch
        self.address=address;self.region,self.offset=self.memory._span(address,24)
        self.header=self.memory.read(address,24)
        if self.header[0]&1:
            self.length=self.memory.load(address+8,8);self.pointer=self.memory.load(address+16,8)
            self.allocation=runtime._custom_allocator_backend.records.get(self.pointer)
            if self.allocation is None:raise InputError('MMKV wide root lacks its owning allocation')
        else:
            self.length=self.header[0]>>1;self.pointer=address+2;self.allocation=None
            if self.length>10:raise InputError('MMKV short wide root overflow')
        if not 0<self.length<200:raise PrimarySemanticUnavailable('MMKV wide length outside finite domain')
        self.backing,self.start=self.memory._span(self.pointer,2*(self.length+1))
        self.raw=self.memory.read(self.pointer,2*(self.length+1))
        if self.raw[-2:]!=bytes(2):raise InputError('MMKV wide root lacks terminator')
        self.validate(runtime)

    def validate(self,runtime):
        if (runtime is not self.runtime or runtime.memory is not self.memory or runtime.image_base!=self.base or
                runtime._shared_locale_source is not self.source or runtime._shared_locale_source_epoch is not self.epoch):
            raise InputError('MMKV wide argument image changed')
        self.source.validate_image(runtime)
        region,offset=self.memory._span(self.address,24);backing,start=self.memory._span(self.pointer,len(self.raw))
        if (region is not self.region or offset!=self.offset or backing is not self.backing or start!=self.start or
                self.memory.read(self.address,24)!=self.header or self.memory.read(self.pointer,len(self.raw))!=self.raw):
            raise InputError('MMKV wide argument backing/lifetime changed')
        if self.allocation is not None:
            record=runtime._custom_allocator_backend.records.get(self.pointer)
            if record is not self.allocation or record[0] is not backing or record[1]<len(self.raw) or start:
                raise InputError('MMKV wide owning allocation changed')


class _DirectoryWork:
    def __init__(self,root,pointer,size):
        self.root=root;self.runtime=root.runtime;self.pointer=pointer;self.size=size
        self.region,self.offset=root.memory._span(pointer,size)
        if (self.offset or self.runtime.allocations.get(pointer)!=size or self.region is root.backing or
                pointer<root.pointer+len(root.raw) and root.pointer<pointer+size):
            raise InputError('MMKV duplicate requires normal CRT allocation')


def _directory(runtime,root):
    import re
    from .primary_windows_mmkv_host_init import for_runtime
    root.validate(runtime)
    text=root.raw[:-2].decode('utf-16-le')
    if not 10<root.length<200 or re.fullmatch(r'[A-Za-z]:\\[A-Za-z0-9_-]+(?:\\[A-Za-z0-9_-]+)*',text) is None:
        raise PrimarySemanticUnavailable('1BD8F45 path outside finite ASCII drive domain')
    port=for_runtime(runtime);port._prepare_directory(root)
    try:
        size=len(root.raw)
        pointer=_invoke(runtime,0x3E97020,size)
        if not pointer:raise PrimarySemanticUnavailable('3E90050 CRT duplicate NULL/OOM unsupported')
        work=_DirectoryWork(root,pointer,size);port._issue_directory(work)
        memory=runtime.memory
        memory.write(pointer,root.raw,source='3E90050.duplicate_UTF16_with_NUL')
        cursor=pointer
        while True:
            while memory.load(cursor,2)==0x5c:cursor+=2
            end=cursor
            while memory.load(end,2) not in (0,0x5c):end+=2
            done=memory.load(end,2)==0
            memory.store(end,0,2,source='1BD8FD2.temporary_NUL')
            attrs,error=port._directory_step(work)
            if error is not None:
                _log(runtime,3,b'MemoryFile_Win32.cpp',b'mkPath',0x102,b'fail to create dir:%ls, %d',(root,error))
                result=False;break
            if attrs!=0xffffffff and not attrs&0x10:
                _log(runtime,3,b'MemoryFile_Win32.cpp',b'mkPath',0x107,b'%ls attribute:%d not a directry',(root,attrs))
                result=False;break
            cursor=end
            memory.store(cursor,0x5c,2,source='1BD8FE3.write_backslash_even_final_NUL')
            if done:result=True;break
        port._finish_directory(work)
        return result
    except BaseException as error:
        port._directory_failed(error);raise



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
    root=_WideArgument(runtime,base+0x6751398,_WIDE_TOKEN)
    _directory(runtime,root) # ordinary BOOL is ignored by the source caller
    _log(runtime,1,b'MMKV.cpp',b'initializeMMKV',0xe9,b'root dir: %ls',(root,))


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
