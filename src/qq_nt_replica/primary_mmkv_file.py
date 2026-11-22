"""Finite source File40 lifecycle; loader/EH/outer object deletion are unavailable."""
import ctypes as C
import sys
from dataclasses import dataclass
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
_MASK=(1<<64)-1
_TOKEN=object()
LOGS={
 'open_error':(3,b'MemoryFile_Win32.cpp',b'open',0x49,b'fail to open:[%ls], %d',('wide','int')),
 'open_ok':(1,b'MemoryFile_Win32.cpp',b'open',0x4c,b'open fd[%p], %ls',('ptr','wide')),
 'closing':(1,b'MemoryFile_Win32.cpp',b'close',0x52,b'closing fd[%p], %ls',('ptr','wide')),
 'close_error':(3,b'MemoryFile_Win32.cpp',b'close',0x56,b'fail to close [%ls], %d',('wide','int')),
 'unmap_error':(3,b'MemoryFile_Win32.cpp',b'truncate',0x7a,b'fail to munmap [%ls], %d',('wide','int')),
 'resize_error':(3,b'MemoryFile_Win32.cpp',b'truncate',0x84,b'fail to truncate [%ls] to size %zu',('wide','size')),
 'zero_error':(3,b'MemoryFile_Win32.cpp',b'truncate',0x8b,b'fail to zeroFile [%ls] to size %zu',('wide','size')),
 'truncate_error':(3,b'MemoryFile_Win32.cpp',b'ftruncate',0x156,b'fail to SetEndOfFile:%d',('int',)),
 'seek_error':(3,b'MemoryFile_Win32.cpp',b'ftruncate',0x159,b'fail to SetFilePointer:%d',('int',)),
 'mapping_error':(3,b'MemoryFile_Win32.cpp',b'mmap',0xad,b'fail to CreateFileMapping [%ls], %d',('wide','int')),
 'view_error':(3,b'MemoryFile_Win32.cpp',b'mmap',0xb2,b'fail to mmap [%ls], %d',('wide','int')),
 'zero_seek_error':(3,b'MemoryFile_Win32.cpp',b'zeroFillFile',0x138,b'fail to lseek fd[%p], error:%d',('ptr','int')),
 'write_error':(3,b'MemoryFile_Win32.cpp',b'zeroFillFile',0x140,b'fail to write fd[%p], error:%d',('ptr','int')),
 'tail_error':(3,b'MemoryFile_Win32.cpp',b'zeroFillFile',0x148,b'fail to write fd[%p], error:%d',('ptr','int')),
 'upgrade_unlock_error':(3,b'InterProcessLock_Win32.cpp',b'platformLock',0x37,b'fail to try unlock first fd=%p, error:%d',('ptr','int')),
 'recover_lock_error':(3,b'InterProcessLock_Win32.cpp',b'platformLock',0x49,b'fail to recover shared-lock fd=%p, error:%d',('ptr','int')),
 'downgrade_error':(3,b'InterProcessLock_Win32.cpp',b'platformUnLock',0x5c,b'fail to roll back to shared-lock, error:%d',('int',)),
 'lock_error':(3,b'InterProcessLock_Win32.cpp',b'platformLock',0x42,b'fail to lock fd=%p, error:%d',('ptr','int')),
 'unlock_error':(3,b'InterProcessLock_Win32.cpp',b'platformUnLock',0x63,b'fail to unlock fd=%p, error:%d',('ptr','int')),
 'cs_error':(3,b'ThreadLock_Win32.cpp',b'initialize',0x29,b'fail to init critical section:%d',('int',)),
}


@dataclass(frozen=True)
class Pointer64:
    value:int


@dataclass(frozen=True)
class Unsigned64:
    value:int


def emit(r,key,*args):
    from .primary_mmkv_host_init import _log
    level,file,function,line,template,types=LOGS[key]
    return _log(r,level,file,function,line,template,args)


class WidePath:
    def __init__(self,r,address,token):
        if token is not _TOKEN:raise InputError('owning path requires source producer')
        self.runtime=r;self.memory=r.memory;self.address=address;self.image=r._shared_locale_source;self.epoch=r._shared_locale_source_epoch
        self.region,self.offset=r.memory._span(address,24);self.header=r.memory.read(address,24)
        self.length=r.memory.load(address+8,8) if self.header[0]&1 else self.header[0]>>1
        self.pointer=r.memory.load(address+16,8) if self.header[0]&1 else address+2
        self.raw=r.memory.read(self.pointer,2*(self.length+1));self.backing,self.start=r.memory._span(self.pointer,len(self.raw))
        self.allocation=r._custom_allocator_backend.records.get(self.pointer) if self.header[0]&1 else None
        if self.raw[-2:]!=bytes(2):raise InputError('source owning path lacks NUL')
        self.validate(r)

    def validate(self,r):
        if r is not self.runtime or r.memory is not self.memory or r._shared_locale_source is not self.image or r._shared_locale_source_epoch is not self.epoch:raise InputError('owning path source epoch changed')
        self.image.validate_image(r)
        actual,offset=r.memory._span(self.address,24);backing,start=r.memory._span(self.pointer,len(self.raw))
        if actual is not self.region or offset!=self.offset or backing is not self.backing or start!=self.start or r.memory.read(self.address,24)!=self.header or r.memory.read(self.pointer,len(self.raw))!=self.raw:raise InputError('owning path lifetime changed')
        if self.allocation is not None and r._custom_allocator_backend.records.get(self.pointer) is not self.allocation:raise InputError('owning path allocation changed')

    def validate_log(self,r):
        from .primary_windows_mmkv_host_init import for_runtime
        self.validate(r);session=for_runtime(r)._WindowsMMKVHost__open
        if session is None or not any(item.path is self for item in session['files']):
            raise InputError('file log requires its own actual File40 path')

    def destroy(self):
        self.validate(self.runtime)
        if self.allocation is not None:_invoke(self.runtime,0xB75029,self.pointer)


def wide(r,address,raw,capacity=None):
    if len(raw)%2:raise InputError('odd UTF16 path')
    n=len(raw)//2;m=r.memory
    if n<=10:
        m.write(address,bytes((n*2,0))+raw+bytes(22-len(raw)),source='75D940.short_wide')
    else:
        count=capacity if capacity is not None else (n|7)+1
        pointer=_invoke(r,0xB75000,count*2)
        m.write(pointer,raw+bytes(2),source='75D940.owning_wide_copy')
        for off,value in ((0,count|1),(8,n),(16,pointer)):m.store(address+off,value,8,source='75D940.wide_publish')
    return WidePath(r,address,_TOKEN)


def append(r,value,raw):
    value.validate(r);m=r.memory;n=value.length+len(raw)//2
    cap=(m.load(value.address,8)&~1)-1 if value.allocation is not None else 10
    if n>cap:
        count=(max(n,2*cap)|7)+1;pointer=_invoke(r,0xB75000,count*2)
        m.write(pointer,value.raw[:-2]+raw+bytes(2),source='75D130.grow_copy_before_free')
        if value.allocation is not None:_invoke(r,0xB75029,value.pointer)
        for off,word in ((16,pointer),(0,count|1),(8,n)):m.store(value.address+off,word,8,source='75D130.publish_after_old_free')
    else:
        m.write(value.pointer+value.length*2,raw+bytes(2),source='75D940.append')
        m.store(value.address+8,n,8,source='75D940.length')
    return WidePath(r,value.address,_TOKEN)


class FileLock:
    def __init__(self,r,port,handle,kind,address=None):
        from .primary_mmkv_open import _parent
        caller=sys._getframe(1)
        if caller.f_code not in (File40.reload.__code__,_parent.__code__) or kind not in (0,1):
            raise InputError('file lock state requires actual constructor source')
        port._check(None)
        self.r=r;self.port=port;self.handle=handle;self.kind=kind;self.address=address
        if address is None:self.address,_=_frame(r,0x38,'878A source file lock state')
        r.memory.store(self.address,handle,8,source='B98DA0.saved_HANDLE')
        r.memory.write(self.address+8,bytes(0x30),source='B98DA0.fresh_lock_counters_OVERLAPPED')
        self.token,self.view=r.memory._pin_native_span(self.address+0x18,32,port)
        self.native=(C.c_ubyte*32).from_buffer(self.view);self.guard='published';self.root=self;self.pinned=True
        port._WindowsMMKVHost__open['locks'].append(self)

    def shared_guard(self,wrapper):
        from .primary_mmkv_load import load
        if sys._getframe(1).f_code is not load.__code__:raise InputError('shared guard requires actual loader')
        m=self.r.memory
        if m.load(wrapper,8)!=self.address or m.load(wrapper+8,4)!=1 or m.load(wrapper+0xc,1)!=1:raise InputError('shared guard wrapper identity changed')
        self.r.memory._validate_native_pin(self.token,self.port)
        other=object.__new__(FileLock)
        for name in ('r','port','handle','address','token','view','native','root'):setattr(other,name,getattr(self,name))
        other.kind=1;other.guard='published'
        self.port._WindowsMMKVHost__open['locks'].append(other)
        return other

    def _lock(self,flags):
        result,error=self.port._file_call('LockFileEx',C.c_int32,(C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_void_p),(self.handle,flags,0,1,0,C.addressof(self.native)),error=True)
        self.r.memory._record_native_write(self.token,self.port,source='LockFileEx.actual_OVERLAPPED')
        return result,error

    def _unlock(self):
        result,error=self.port._file_call('UnlockFileEx',C.c_int32,(C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_void_p),(self.handle,0,1,0,C.addressof(self.native)),error=True)
        self.r.memory._record_native_write(self.token,self.port,source='UnlockFileEx.actual_OVERLAPPED')
        return result,error

    def acquire(self):
        self.port._check(None);self.r.memory._validate_native_pin(self.token,self.port)
        if self.handle==_MASK:return False
        off=8 if self.kind==0 else 0x10;m=self.r.memory
        if m.load(self.address+off,8):m.store(self.address+off,(m.load(self.address+off,8)+1)&_MASK,8,source='1BE1FBC.recursive');return True
        shared=self.kind==1 and bool(m.load(self.address+8,8))
        if shared:
            result,error=self._unlock()
            if not result and error!=0x9e:emit(self.r,'upgrade_unlock_error',Pointer64(self.handle),error)
        result,error=self._lock(0 if self.kind==0 else 2)
        if result:m.store(self.address+off,1,8,source='1BE1FBC.lock_count')
        else:
            emit(self.r,'lock_error',Pointer64(self.handle),error)
            if shared:
                recovered,last=self._lock(0)
                if not recovered:emit(self.r,'recover_lock_error',Pointer64(self.handle),last)
        return bool(result)

    def release(self):
        self.port._check(None);self.r.memory._validate_native_pin(self.token,self.port)
        m=self.r.memory;off=8 if self.kind==0 else 0x10;n=m.load(self.address+off,8)
        if n:
            if n>1:m.store(self.address+off,n-1,8,source='1BE203E.recursive_release')
            elif self.kind==0 and m.load(self.address+0x10,8):m.store(self.address+8,0,8,source='1BE203E.shared_decrement_while_exclusive')
            else:
                if self.kind==1 and m.load(self.address+8,8):
                    result,error=self._lock(0)
                    if not result:emit(self.r,'downgrade_error',error)
                result,error=self._unlock()
                if result or error==0x9e:m.store(self.address+off,0,8,source='1BE203E.unlock_count')
                else:emit(self.r,'unlock_error',Pointer64(self.handle),error)
        self.guard=None
        others=self.port._WindowsMMKVHost__open['locks']
        if not m.load(self.address+8,8) and not m.load(self.address+0x10,8) and not any(x.root is self.root and x.guard is not None for x in others):
            self.r.memory._unpin_native_span(self.token,self.port);self.view.release();self.root.pinned=False


class File40:
    def __init__(self,r,port,address,path):
        from .primary_mmkv_open import _parent
        if sys._getframe(1).f_code is not _parent.__code__:raise InputError('File40 requires actual parent constructor')
        port._check(None)
        self.r=r;self.port=port;self.address=address;self.scratch=[];self.native_extent=None
        self.allocation=r._custom_allocator_backend.records.get(address)
        if self.allocation is None or self.allocation[1]!=0x40:raise InputError('File40 requires actual upper40h allocation')
        path.validate(r);m=r.memory
        m.write(address,path.header,source='1BD8398.move_owning_path')
        m.write(path.address,bytes(24),source='1BD8398.clear_moved_path')
        self.path=WidePath(r,address,_TOKEN)
        m.store(address+0x18,_MASK,8,source='1BD8398.invalid_HANDLE');m.store(address+0x20,7,4,source='1BD8398.flags7')
        port._WindowsMMKVHost__open['files'].append(self)
        self.open()
        m.write(address+0x28,bytes(24),source='1BD86C8.zero_mapping_view_size')
        self.reload()

    def _check(self):
        self.port._check(None);self.path.validate(self.r)
        if self.r._custom_allocator_backend.records.get(self.address) is not self.allocation:
            raise InputError('File40 owning allocation changed')
        region,offset=self.r.memory._span(self.address,0x40)
        if region is not self.allocation[0] or offset:raise InputError('File40 backing changed')

    def load(self,off):return self.r.memory.load(self.address+off,8)
    def store(self,off,value):self.r.memory.store(self.address+off,value,8,source='File40.source_field')

    def open(self):
        self._check()
        if self.load(0x18)!=_MASK:return True
        self.path.validate(self.r)
        token,view=self.r.memory._pin_native_span(self.path.pointer,len(self.path.raw),self.port)
        native=(C.c_uint16*(len(self.path.raw)//2)).from_buffer(view);self.scratch.append((token,view,native))
        value,error=self.port._file_call('CreateFileW',C.c_void_p,(C.c_void_p,C.c_uint32,C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_void_p),(C.addressof(native),0xc0000000,7,0,4,0x80,0),publish=lambda value:self.store(0x18,(value or 0)&_MASK),error=lambda value:(value or 0)&_MASK==_MASK)
        self.r.memory._unpin_native_span(token,self.port);view.release();self.scratch.pop()
        if self.load(0x18)==_MASK:emit(self.r,'open_error',self.path,error);return False
        emit(self.r,'open_ok',Pointer64(self.load(0x18)),self.path);return True

    def close_file(self):
        self._check()
        handle=self.load(0x18)
        if handle==_MASK:return
        emit(self.r,'closing',Pointer64(handle),self.path)
        result,error=self.port._file_call('CloseHandle',C.c_int32,(C.c_void_p,),(handle,),error=True)
        if result:self.store(0x18,_MASK)
        else:emit(self.r,'close_error',self.path,error)

    def clear(self):
        self._check()
        if self.load(0x30):self.port._unmap_view(self.load(0x30));self.store(0x30,0)
        if self.load(0x28):self.port._file_call('CloseHandle',C.c_int32,(C.c_void_p,),(self.load(0x28),));self.store(0x28,0)
        self.close_file()

    def map(self):
        self._check()
        mapping,error=self.port._file_call('CreateFileMappingW',C.c_void_p,(C.c_void_p,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_void_p),(self.load(0x18),0,4,0,0,0),publish=lambda value:self.store(0x28,value or 0),error=True)
        if not mapping:emit(self.r,'mapping_error',self.path,error);return False
        pointer,error=self.port._map_view(mapping,self.native_extent);self.store(0x30,pointer)
        if not pointer:emit(self.r,'view_error',self.path,error);return False
        return True

    def truncate(self,target):
        self._check()
        result,error=self.port._file_call('SetFilePointerEx',C.c_int32,(C.c_void_p,C.c_int64,C.c_void_p,C.c_uint32),(self.load(0x18),target,0,0),error=True)
        if not result:emit(self.r,'seek_error',error);return False
        self.native_extent=None
        result,error=self.port._file_call('SetEndOfFile',C.c_int32,(C.c_void_p,),(self.load(0x18),),error=True)
        if not result:emit(self.r,'truncate_error',error);return False
        self.native_extent=target
        return True

    def zero(self,old,target):
        self._check()
        result,error=self.port._file_call('SetFilePointerEx',C.c_int32,(C.c_void_p,C.c_int64,C.c_void_p,C.c_uint32),(self.load(0x18),old,0,0),error=True)
        if not result:emit(self.r,'zero_seek_error',Pointer64(self.load(0x18)),error);return False
        left=target-old;zero=C.create_string_buffer(bytes(4096));written=C.c_uint32();self.scratch.extend((zero,written))
        while left:
            amount=min(left,4096)
            result,error=self.port._file_call('WriteFile',C.c_int32,(C.c_void_p,C.c_void_p,C.c_uint32,C.c_void_p,C.c_void_p),(self.load(0x18),C.addressof(zero),amount,C.addressof(written),0),error=True)
            if not result:emit(self.r,'tail_error' if left<4096 else 'write_error',Pointer64(self.load(0x18)),error);return False
            if left<4096:break # source tail ignores bytesWritten
            left-=written.value
        return True

    def resize(self,target):
        self._check()
        if self.load(0x18)==_MASK:return False
        old=self.load(0x38);target&=_MASK
        if old==target:return True
        self.store(0x38,target)
        from .primary_mmkv_host_init import _validate
        _validate(self.r);page=self.r.memory.load(self.r.image_base+0x67513b0,8)
        if not page:raise PrimarySemanticUnavailable('File40 resize division zero after raw target publication')
        if page>target or target%page:
            target=(((target//page)+1)*page)&_MASK
            self.store(0x38,target)
        if self.load(0x30):
            result,error=self.port._unmap_view(self.load(0x30));self.store(0x30,0)
            if not result:emit(self.r,'unmap_error',self.path,error)
        if self.load(0x28):self.port._file_call('CloseHandle',C.c_int32,(C.c_void_p,),(self.load(0x28),));self.store(0x28,0)
        truncated=self.truncate(target)
        filled=truncated and (target<=old or self.zero(old,target))
        if not filled:
            emit(self.r,'resize_error' if not truncated else 'zero_error',self.path,Unsigned64(self.load(0x38)))
            self.store(0x38,old);self.map();return False
        if not self.map():self.clear();return False
        return True

    def reload(self):
        self._check()
        self.open()
        if self.load(0x18)==_MASK:return
        state=FileLock(self.r,self.port,self.load(0x18),1);state.acquire() # ordinary BOOL ignored
        size=C.c_uint64();self.scratch.append(size)
        result,_=self.port._file_call('GetFileSizeEx',C.c_int32,(C.c_void_p,C.c_void_p),(self.load(0x18),C.addressof(size)))
        if result:self.native_extent=size.value;self.store(0x38,size.value)
        from .primary_mmkv_host_init import _validate
        _validate(self.r);page=self.r.memory.load(self.r.image_base+0x67513b0,8)
        if not page:raise PrimarySemanticUnavailable('File40 page division zero outside finite domain')
        value=self.load(0x38)
        if value>=page and value%page==0:
            if not self.map():self.clear()
        else:self.resize(max(page,(value//page+1)*page))
        state.release() # normal source position only; no exception finally

    def destroy(self):
        self.clear();self.close_file();self.path.destroy() # no outer40h delete proved
