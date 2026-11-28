"""Own key25 entry with explicit storage ownership and complete CAPI priority."""
import ctypes as C
import hashlib
import os,threading,sys
from pathlib import Path
from .errors import InputError
from .primary_device import CapiObservation
from .primary_windows_capi import CapiCreationDisabled

class WindowsKey25Capi:
    def __init__(self,*,allow_creation=False,backend=None):
        if type(allow_creation)is not bool:raise InputError('explicit CAPI creation permission required')
        self.allow_creation=allow_creation;self.backend=backend;self.handles=[];self.failed_handles=[];self.owns_backend=backend is None;self.closed=False;self.owner=(os.getpid(),threading.get_ident())
    def capi_public_key(self):
        if self.closed or self.owner!=(os.getpid(),threading.get_ident()):raise InputError('CAPI requires open creator process/thread')
        from .primary_windows_capi import _WindowsAPIs
        from .primary_windows import _PublicKeyInfo
        if self.backend is None:self.backend=_WindowsAPIs()
        api=self.backend;method=6
        version=C.create_string_buffer(284)
        for offset,value in ((0,284),(4,5),(8,1)):C.c_uint32.from_buffer(version,offset).value=value
        mask=api.VerSetConditionMask(0,2,3);mask=api.VerSetConditionMask(mask,1,3)
        if not api.VerifyVersionInfoW(version,3,mask):return CapiObservation(None,2)
        def failure(code):return CapiObservation(None,code,api.last_error())
        def handle(name,*args):
            out=C.c_void_p()
            ok=getattr(api,name)(*args,C.byref(out))
            if ok:self.handles.append((out.value,'CryptReleaseContext' if name=='CryptAcquireContextA' else 'CryptDestroyHash' if name=='CryptCreateHash' else 'CryptDestroyKey'))
            return ok,out.value
        def release(value):
            item=next(item for item in self.handles if item[0]==value)
            ok=getattr(api,item[1])(value,0) if item[1]=='CryptReleaseContext' else getattr(api,item[1])(value)
            self.handles.remove(item)
            if not ok:
                self.failed_handles.append(item);raise OSError('CAPI owned handle cleanup failed')
        try:
            provider=C.c_void_p()
            if not api.CryptAcquireContextA(C.byref(provider),b'mWOLCtkGwuHtk',None,24,0x60):
                error=api.last_error();hr=error if not error or error&0x80000000 else (error&65535)|0x80070000
                if hr!=0x80090016:return CapiObservation(None,3,error)
                if not self.allow_creation:raise CapiCreationDisabled(error)
                method=5
                if not api.CryptAcquireContextA(C.byref(provider),b'mWOLCtkGwuHtk',None,24,0x68):return failure(4)
                self.handles.append((provider.value,'CryptReleaseContext'))
                ok,generated=handle('CryptGenKey',provider.value,2,0x08000000)
                if not ok:return failure(5)
                sd=C.create_string_buffer(40)
                for code,name,args in ((6,'InitializeSecurityDescriptor',(sd,1)),(7,'SetSecurityDescriptorDacl',(sd,1,None,0)),(8,'CryptSetProvParam',(provider.value,8,sd,4))):
                    if not getattr(api,name)(*args):return failure(code)
            else:self.handles.append((provider.value,'CryptReleaseContext'))
            ok,key=handle('CryptGetUserKey',provider.value,2)
            if not ok:return failure(9)
            size=C.c_uint32()
            if not api.CryptExportPublicKeyInfo(provider.value,2,0x10001,None,C.byref(size)):return failure(10)
            if not 48<=size.value<=1<<20:raise InputError('CAPI export exceeds finite backing')
            exported=C.create_string_buffer(size.value);capacity=size.value
            if not api.CryptExportPublicKeyInfo(provider.value,2,0x10001,exported,C.byref(size)):return failure(10)
            if not 48<=size.value<=capacity:raise InputError('CAPI export size changed outside backing')
            info=_PublicKeyInfo.from_buffer(exported);start=C.addressof(exported)
            if info.key.size and (not info.key.data or not start<=info.key.data<=start+size.value or info.key.size>start+size.value-info.key.data):raise InputError('CAPI bits outside actual owned export')
            bits=C.string_at(info.key.data,info.key.size) if info.key.size else b'';release(key)
            ok,digest=handle('CryptCreateHash',provider.value,0x800C,None,0)
            if not ok:return failure(11)
            data=C.create_string_buffer(bits)
            if not api.CryptHashData(digest,data,len(bits),0):return failure(12)
            output=C.create_string_buffer(32);count=C.c_uint32(32)
            if not api.CryptGetHashParam(digest,2,output,C.byref(count),0) or count.value!=32:return failure(13)
            if output.raw!=hashlib.sha256(bits).digest():raise InputError('CAPI digest disagrees with shared material computation')
            return CapiObservation(bits,0,method=method)
        finally:
            errors=[]
            for value,kind in tuple(reversed(self.handles)):
                try:release(value)
                except BaseException as error:errors.append(error)
            if errors:
                original=sys.exception()
                raise BaseExceptionGroup('CAPI cleanup failed',([original] if original is not None else [])+errors)
    def close(self):
        if self.closed:return
        if self.owner!=(os.getpid(),threading.get_ident()):raise InputError('CAPI close requires creator')
        if self.handles or self.failed_handles:raise InputError('CAPI cleanup remains unresolved')
        if self.owns_backend and self.backend is not None:
            import _ctypes
            for library in reversed(self.backend.libraries):_ctypes.FreeLibrary(library._handle)
            self.backend=None
        self.closed=True

class _Source:
    def __init__(self,source,capi):self.source=source;self.capi=capi
    def __getattr__(self,name):return getattr(self.source,name)
    def capi_public_key(self):return self.capi.capi_public_key()

def produce_device_value(*,storage_root,environment,source=None,capi=None,allow_creation=False,storage_factory=None):
    """Complete own producer, storage_root/xfolder is explicit and not SHFolder."""
    from .primary_windows import WindowsDeviceSource
    from .primary_device_storage import DirectoryCheckpointStorage
    from .primary_device_provider import produce_observed_device_value
    root=Path(storage_root)
    if not root.is_absolute():raise InputError('own storage root must be explicit absolute path')
    native=WindowsDeviceSource() if source is None else source
    crypto=WindowsKey25Capi(allow_creation=allow_creation) if capi is None else capi
    try:
        storage=(DirectoryCheckpointStorage if storage_factory is None else storage_factory)(root)
        def checkpoint_storage():
            try:storage.ensure_directory()
            except OSError as error:return None,(0x17<<32)|((getattr(error,'winerror',None) or error.errno or 0)&0xFFFFFFFF)
            return storage,None
        return produce_observed_device_value(_Source(native,crypto),environment,checkpoint_storage)
    finally:
        try:crypto.close()
        finally:
            if source is None:native.close()

class WindowsDeviceValueEnvironment:
    """Lazy exact CRT time and DWORD rand_s; no random/clock approximation."""
    def __init__(self):self.clock=None;self.library=None;self.random=None
    def time_seconds(self):
        from .primary_windows_device_time import WindowsDeviceTimeBackend
        if self.clock is None:self.clock=WindowsDeviceTimeBackend()
        status,raw=self.clock.read_timeb()
        if status!=0 or len(raw)!=14:raise InputError('source CRT time failed or incomplete')
        return int.from_bytes(raw[:8],'little')
    def random_bytes(self,size):
        if size!=4:raise InputError('source random requests one DWORD')
        if self.library is None:
            self.library=C.CDLL('ucrtbase.dll',winmode=0x800);self.random=self.library.rand_s;self.random.argtypes=(C.POINTER(C.c_uint32),);self.random.restype=C.c_int32
        output=C.c_uint32()
        if self.random(C.byref(output))!=0:raise InputError('source rand_s failed; exception continuation unavailable')
        return output.value.to_bytes(4,'little')
    def close(self):
        if self.clock is not None:self.clock.close();self.clock=None
        if self.library is not None:
            import _ctypes
            _ctypes.FreeLibrary(self.library._handle);self.random=None;self.library=None
