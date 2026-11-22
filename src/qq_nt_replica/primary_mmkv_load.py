"""Finite source metadata/header and ordinary zero-length MMKV load."""
from dataclasses import dataclass
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_mmkv_file import Unsigned64

LOGS={
 'invalid_main':(3,b'MMKV_IO.cpp',b'loadFromFile',0x50,b'file [%s] not valid',('path_bytes',)),
 'invalid_meta':(3,b'MMKV_IO.cpp',b'loadMetaInfoAndCheck',0xc0,b'file [%s] not valid',('path_bytes',)),
 'length_mismatch':(2,b'MMKV_IO.cpp',b'readActualSize',0x1cc,b'[%s] actual size %u, meta actual size %u',('identifier','uint','uint')),
 'loading':(1,b'MMKV_IO.cpp',b'loadFromFile',0x57,b'loading [%s] with %zu actual size, file size %zu, InterProcess %d, meta info version:%u',('identifier','size','size','int','uint')),
 'loaded':(1,b'MMKV_IO.cpp',b'loadFromFile',0x88,b'loaded [%s] with %zu key-values',('identifier','size')),
}

@dataclass(frozen=True)
class Unsigned32:
    value:int


class PathCString:
    """Source%s borrows actual UTF16 File40 backing without conversion."""
    def __init__(self,path):
        self.path=path;self.pointer=path.pointer;self.raw=path.raw

    def validate(self,r):
        from .primary_windows_mmkv_host_init import for_runtime
        self.path.validate(r);session=for_runtime(r)._WindowsMMKVHost__open
        if session is None or not (any(x is self.path for x in session['paths']) or any(x.path is self.path for x in session['files'])):raise InputError('path CString requires actual parent or File40 owner')


class Identifier:
    """Borrow the actual constructor-owned parent identifier through stdio."""
    def __init__(self,r,parent):
        from .primary_logger import _String
        from .primary_windows_mmkv_host_init import for_runtime
        self.runtime=r;self.memory=r.memory;self.parent=parent;self.address=parent+0x18
        session=for_runtime(r)._WindowsMMKVHost__open
        if session is None or session['parent']!=parent:raise InputError('identifier requires actual parent')
        self.image=r._shared_locale_source;self.epoch=r._shared_locale_source_epoch
        self.region,self.offset=r.memory._span(self.address,24);self.header=r.memory.read(self.address,24)
        value=_String.read(r,self.address);self.length=len(value.value())
        self.pointer=value.get(16,8) if value.get(0,1)&1 else self.address+1
        self.raw=r.memory.read(self.pointer,self.length+1);self.backing,self.start=r.memory._span(self.pointer,len(self.raw))
        self.allocation=r._custom_allocator_backend.records.get(self.pointer) if value.get(0,1)&1 else None
        if value.get(0,1)&1 and self.allocation is None:raise InputError('identifier lacks original owning allocation')
        self.validate(r)

    def validate(self,r):
        if r is not self.runtime or r.memory is not self.memory or r._shared_locale_source is not self.image or r._shared_locale_source_epoch is not self.epoch:raise InputError('identifier source identity changed')
        self.image.validate_image(r)
        region,offset=r.memory._span(self.address,24);backing,start=r.memory._span(self.pointer,len(self.raw))
        if region is not self.region or offset!=self.offset or backing is not self.backing or start!=self.start or r.memory.read(self.address,24)!=self.header or r.memory.read(self.pointer,len(self.raw))!=self.raw or self.raw[-1:]!=b'\0':raise InputError('borrowed identifier lifetime changed')
        if self.allocation is not None and r._custom_allocator_backend.records.get(self.pointer) is not self.allocation:raise InputError('identifier allocation changed')


def unavailable(r,site,target,reason):
    from .primary_windows_mmkv_host_init import for_runtime
    session=for_runtime(r)._WindowsMMKVHost__open;session['boundary']=target
    r.events.append(('source.unavailable',target,site,session['parent']))
    raise PrimarySemanticUnavailable(reason)


def valid(file):
    return file.load(0x18)!=(1<<64)-1 and file.load(0x38)!=0 and file.load(0x28)!=0 and file.load(0x30)!=0


def log(r,key,*args):
    from .primary_mmkv_host_init import _log
    level,file,function,line,template,types=LOGS[key]
    return _log(r,level,file,function,line,template,args)


def metadata(r,port,parent):
    m=r.memory;session=port._WindowsMMKVHost__open;crc=session['files'][1];meta=m.load(parent+0x98,8)
    if not valid(crc):crc.reload()
    if not valid(crc):
        log(r,'invalid_meta',PathCString(crc.path))
        return
    m.copy_disjoint(meta,crc.load(0x30),0x70,label='1BDA25E.actual_Meta70_copy')
    version=m.load(meta+4,4);flags=m.load(meta+0x68,8)
    if version>=6:
        m.store(meta+4,3,4,source='1BD9A98.version3');m.store(meta+0x68,0,8,source='1BD9AA6.flags0')
        m.copy_disjoint(crc.load(0x30),meta,0x70,label='1BDA37C.actual_Meta70_writeback')
    elif version>=4:
        m.store(parent+0xc8,flags&1,1,source='1BD9AD5.flags_bit0')
        if flags&2 and m.load(parent+0xd0,1):raise PrimarySemanticUnavailable('metadata flags transition log outside finite transcript')
    elif flags:
        m.store(meta+0x68,0,8,source='1BD9B36.flags0')
        m.copy_disjoint(crc.load(0x30),meta,0x70,label='1BDA37C.actual_Meta70_writeback')


def crc_zero(r,seed,pointer,length):
    # The fixed source zero path still requires a real non-NULL pointer argument.
    r.events.append(('source.crc',0x1bdf3e0,seed,pointer,length))
    if seed!=0 or not pointer or length:unavailable(r,0xb99a16,0x1bdf3e0,'1BDF3E0 nonzero CRC domain unavailable')
    return 0


def header(r,port,parent):
    m=r.memory;main,crc=port._WindowsMMKVHost__open['files'];meta=m.load(parent+0x98,8)
    size=main.load(0x38);pointer=main.load(0x30)
    old=m.load(pointer,4);version=m.load(meta+4,4)
    selected=old
    if version>=3:
        selected=m.load(meta+0x1c,4)
        if selected!=old:
            log(r,'length_mismatch',Identifier(r,parent),Unsigned32(old),Unsigned32(selected))
            selected=m.load(meta+0x1c,4)
    m.store(parent+0x78,selected,8,source='1BD9BDB.selected_length_before_bounds')
    if not (selected<size and selected+4<=size):unavailable(r,0x1bd9c66,0x1bda3ca,'1BDA3CA bounds recovery unavailable')
    digest=m.load(meta,4)
    value=_invoke(r,0x1bdf3e0,0,pointer+4,selected)
    m.store(parent+0x8c,value,4,source='B99A1B.actual_CRC_result')
    if value!=digest:unavailable(r,0x1bd9ca9,0x1bda3ca,'1BDA3CA CRC recovery unavailable')
    return selected


def writeback(r,port,parent):
    m=r.memory;main,crc=port._WindowsMMKVHost__open['files'];meta=m.load(parent+0x98,8)
    m.store(parent+0x78,0,8,source='1BDB38E.actualSize0');m.store(main.load(0x30),0,4,source='1BDB38E.main_header0')
    if not valid(crc):return
    m.store(parent+0x78,0,8,source='1BD9F4E.actualSize0');m.store(meta+0x1c,0,4,source='1BD9F4E.meta_size0')
    m.store(parent+0x8c,0,4,source='1BD9F4E.CRC0');m.store(meta,0,4,source='1BD9F4E.meta_CRC0')
    if not m.load(meta+4,4):m.store(meta+4,1,4,source='1BD9F4E.version1')
    if m.load(meta+4,4)<4:
        m.store(meta+0x68,0,8,source='1BD9F4E.flags0');m.store(meta+4,4,4,source='1BD9F4E.version4')
    m.copy_disjoint(crc.load(0x30),meta,0x70,label='1BDA37C.actual_Meta70_writeback')


def load(r,port,parent,outer):
    m=r.memory;session=port._WindowsMMKVHost__open;main,crc=session['files']
    metadata(r,port,parent)
    if m.load(parent+0xa0,8):unavailable(r,0x1bd957c,None,'crypto loader outside finite empty domain')
    if not valid(main):main.reload()
    if not valid(main):
        log(r,'invalid_main',PathCString(session['paths'][0]))
        m.store(parent+0x88,0,1,source='1BD98ED.loaded_byte0')
        return
    length=header(r,port,parent)
    meta=m.load(parent+0x98,8)
    log(r,'loading',Identifier(r,parent),Unsigned64(m.load(parent+0x78,8)),Unsigned64(main.load(0x38)),m.load(parent+0xd1,1),Unsigned32(m.load(meta+4,4)))
    inner=outer.shared_guard(m.load(parent+0xc0,8));session['inner_guard']=inner;inner.acquire()
    descriptor=_invoke(r,0xb75000,0x18)
    for off,value in ((0,main.load(0x30)+4),(8,(main.load(0x38)-4)&((1<<64)-1)),(0x10,0)):m.store(descriptor+off,value,8,source='1BDF4D4.borrowed_descriptor')
    m.store(parent+0x80,descriptor,8,source='1BD96F0.descriptor_publish')
    if length:unavailable(r,0x1bd96f7,None,'nonempty decoder unavailable')
    writeback(r,port,parent);inner.release()
    container=m.load(parent+(0x68 if m.load(parent+0xa0,8) else 0x60),8)
    log(r,'loaded',Identifier(r,parent),Unsigned64(m.load(container+0x18,8)))
    m.store(parent+0x88,0,1,source='1BD98ED.loaded_byte0')
