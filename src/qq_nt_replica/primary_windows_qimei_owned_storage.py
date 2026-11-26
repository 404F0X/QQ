"""Own-only Qimei byte persistence; no QQ-directory discovery or native import I/O."""
import os
from pathlib import Path
import threading
from .primary_qimei_request import QimeiRequestBoundary

class OwnQimeiBeaconBackend:
    """Explicit dedicated root; caller owns handles and must close each issued token.

    Root and files must not be symlinks/junctions. This finite implementation
    rejects substituted roots on each operation; hostile concurrent path swaps
    require an OS handle-relative backend and are outside this adapter's domain.
    """
    def __init__(self, runtime, epoch, current_epoch, *, permit, root, profile_port=None):
        self.binding=(runtime,epoch,current_epoch,permit,os.getpid(),threading.get_native_id())
        self.root=Path(root)
        if not self.root.is_absolute(): raise QimeiRequestBoundary('absolute dedicated Own root required')
        self.handles={}
        self.audit=[]
        self.profile_port=profile_port if profile_port is not None else NativeOwnedProfilePort(self.check)
    def check(self):
        runtime,epoch,current,permit,pid,thread=self.binding
        if (not permit(runtime,epoch) or current(runtime) is not epoch or
                pid!=os.getpid() or thread!=threading.get_native_id()):
            raise QimeiRequestBoundary('Own storage epoch unavailable')
    def _path(self,name):
        self.check()
        root=self.root
        if root.resolve()!=root or root.is_symlink() or (hasattr(root,'is_junction') and root.is_junction()):
            raise QimeiRequestBoundary('Own storage root substitution')
        if name not in ('RanMgr.db','GlobalMgr.db'): raise QimeiRequestBoundary('unbound Own file')
        path=root/name
        if path.resolve().parent!=root or path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):
            raise QimeiRequestBoundary('Own file substitution')
        if path.exists() and path.stat().st_nlink!=1: raise QimeiRequestBoundary('Own beacon hardlink rejected')
        return path
    def read_outer(self):
        return self.profile_port.string(self._path('GlobalMgr.db'),b'config1')
    def close_native(self):
        self.check()
        if self.handles: raise QimeiRequestBoundary('outstanding Own beacon handles')
        self.profile_port.close()
    def open_main(self):
        path=self._path('RanMgr.db')
        try: self.root.mkdir(parents=False,exist_ok=True)
        except OSError as exc:
            self.audit.append(('directory-error',exc.errno)); return None,b'',3
        self._path('RanMgr.db')
        try:
            stream=path.open('r+b'); status=0x50
        except FileNotFoundError:
            try: stream=path.open('w+b'); status=0
            except OSError as exc:
                self.audit.append(('open-error',exc.errno)); return None,b'',0x65f
        except OSError as exc:
            self.audit.append(('open-error',exc.errno)); return None,b'',0x65f
        token=object(); self.handles[token]=stream
        return token,path,status
    def read_config(self,path):
        if path!=self._path('RanMgr.db'): raise QimeiRequestBoundary('unbound Own profile')
        values=tuple(self.profile_port.string(path,b'config'+str(n).encode()) for n in range(1,5))
        return (*values,self.profile_port.integer(path))
    def persist(self,token,path,raw,digests):
        if path!=self._path('RanMgr.db') or token not in self.handles:
            raise QimeiRequestBoundary('foreign Own beacon handle')
        stream=self.handles[token]
        text=b'[Profile]\r\n'+b''.join(b'config'+str(n).encode()+b'='+v+b'\r\n' for n,v in enumerate((raw.hex().encode(),*digests,b'1'),1))
        stream.seek(0); stream.truncate()
        try:
            count=stream.write(text); stream.flush()
            self.audit.append(('write',count,len(text)))
            if count!=len(text): raise OSError('short Own beacon write')
        except BaseException as exc:
            self.audit.append(('write-failure',type(exc).__name__))
            raise
    def close(self,token):
        self.check()
        if token not in self.handles: raise QimeiRequestBoundary('foreign/closed Own beacon handle')
        stream=self.handles[token]
        try: stream.close()
        except BaseException as exc:
            self.audit.append(('close-failure',type(exc).__name__)); raise
        else:
            del self.handles[token]; self.audit.append(('close',True))

class OwnQimeiMainWriterObservations(OwnQimeiBeaconBackend):
    """Finite writer observations with exact logical path to Own file binding.

    Caller closes native ports explicitly after final writer use. Failed FILE
    close remains resource debt; Source writer itself ignores fclose status.
    """
    def __init__(self,*args,logical_main_path,acl_port=None,**kwargs):
        super().__init__(*args,**kwargs)
        if type(logical_main_path) is not bytes or not logical_main_path:
            raise QimeiRequestBoundary('exact logical main path required')
        self.logical_main_path=logical_main_path
        self.acl_port=acl_port if acl_port is not None else NativeOwnedAclPort(self.check)
        self.allocations={}; self.streams={}; self.serial=0
    def _token(self):
        self.serial+=1
        return self.serial
    def _main(self,path):
        if path!=self.logical_main_path: raise QimeiRequestBoundary('unbound logical main path')
        self.check()
        root=self.root
        if root.resolve()!=root: raise QimeiRequestBoundary('Own root substitution')
        physical=root/'QimeiMain.cache'
        if physical.resolve().parent!=root or physical.is_symlink():
            raise QimeiRequestBoundary('Own main substitution')
        if physical.exists() and physical.stat().st_nlink!=1: raise QimeiRequestBoundary('Own main hardlink rejected')
        return physical
    def read(self,channel,name,*args):
        from .primary_qimei_observations import QimeiApiReply
        self.check()
        if channel!='qimei-api': raise QimeiRequestBoundary('unbound storage channel')
        if name in ('calloc','malloc'):
            length=args[0]*args[1] if name=='calloc' else args[0]
            if not 0<=length<=1<<20: raise QimeiRequestBoundary('allocation exceeds writer domain')
            token=self._token(); self.allocations[token]=bytearray(length)
            return QimeiApiReply(token)
        if name=='free':
            if args[0] not in self.allocations: raise QimeiRequestBoundary('foreign writer allocation')
            del self.allocations[args[0]]; return QimeiApiReply(0)
        if name=='fopen':
            path,mode=args
            if mode!=b'wb': raise QimeiRequestBoundary('unbound writer mode')
            physical=self._main(path)
            self.root.mkdir(parents=False,exist_ok=True); self._main(path)
            try: stream=physical.open('wb')
            except OSError as exc:
                self.audit.append(('open-error',exc.errno)); return QimeiApiReply(0)
            token=self._token(); self.streams[token]=stream; return QimeiApiReply(token)
        if name=='fwrite':
            data,size,count,token=args
            if size!=1 or token not in self.streams: raise QimeiRequestBoundary('unbound writer stream')
            try: written=self.streams[token].write(data[:count])
            except OSError as exc:
                self.audit.append(('write-error',exc.errno)); return QimeiApiReply(0)
            self.audit.append(('write',written,count)); return QimeiApiReply(written)
        if name=='fclose':
            token,=args
            if token not in self.streams: raise QimeiRequestBoundary('foreign writer stream')
            try: self.streams[token].close()
            except OSError as exc:
                self.audit.append(('close-error',exc.errno)); return QimeiApiReply(0xffffffff)
            del self.streams[token]; self.audit.append(('close',True)); return QimeiApiReply(0)
        if name=='_access':
            path,mode=args
            if mode!=0: raise QimeiRequestBoundary('unbound access mode')
            return QimeiApiReply(0 if self._main(path).exists() else 0xffffffff)
        # ACL path conversion is delegated only after binding the logical path;
        # every subsequent path argument must reference the physical Own file.
        physical=self._main(self.logical_main_path)
        if name=='MultiByteToWideChar' and args[2]!=self.logical_main_path:
            raise QimeiRequestBoundary('unbound ACL ANSI path')
        if name in ('GetFileSecurityW','SetFileSecurityW') and args[0]!=str(physical).encode('utf-16le'):
            raise QimeiRequestBoundary('unbound ACL wide path')
        if any(byte>=128 for byte in os.fsencode(physical)):
            raise QimeiRequestBoundary('Own ANSI path locale unavailable')
        mapped=tuple(os.fsencode(physical) if arg==self.logical_main_path else arg for arg in args)
        return self.acl_port.read(channel,name,*mapped)

    def read_memory(self,pointer,length=None):
        self.check()
        return self.acl_port.read_memory(pointer,length)
    def close_native(self):
        self.check()
        if self.streams or self.allocations: raise QimeiRequestBoundary('outstanding writer resources')
        self.acl_port.close()
        super().close_native()

# Explicit Win64 ABI for the finite QimeiMainWriter ACL branch.
import ctypes as C
from .primary_qimei_storage import StorageBuffer
from .primary_qimei_observations import QimeiApiReply
P,U,I,W=C.c_void_p,C.c_uint32,C.c_int32,C.c_uint16
ACL_ABI={
 'SHELL32.ordinal680':('shell32',I,()),
 'NetWkstaUserGetInfo':('netapi32',U,(P,U,P)),
 'NetApiBufferFree':('netapi32',U,(P,)),
 'MultiByteToWideChar':('kernel32',I,(U,U,C.c_char_p,I,P,I)),
 'SetLastError':('kernel32',None,(U,)), 'GetLastError':('kernel32',U,()),
 'GetProcessHeap':('kernel32',P,()), 'HeapAlloc':('kernel32',P,(P,U,C.c_size_t)),
 'HeapFree':('kernel32',I,(P,U,P)),
 'LookupAccountNameW':('advapi32',I,(P,P,P,P,P,P,P)),
 'GetFileSecurityW':('advapi32',I,(P,U,P,U,P)),
 'InitializeSecurityDescriptor':('advapi32',I,(P,U)),
 'GetSecurityDescriptorDacl':('advapi32',I,(P,P,P,P)),
 'GetAclInformation':('advapi32',I,(P,P,U,U)),
 'GetLengthSid':('advapi32',U,(P,)), 'InitializeAcl':('advapi32',I,(P,U,U)),
 'GetAce':('advapi32',I,(P,U,P)), 'EqualSid':('advapi32',I,(P,P)),
 'AddAce':('advapi32',I,(P,U,U,P,U)), 'AddAccessAllowedAceEx':('advapi32',I,(P,U,U,U,P)),
 'SetSecurityDescriptorDacl':('advapi32',I,(P,I,P,I)),
 'GetSecurityDescriptorControl':('advapi32',I,(P,P,P)),
 'SetSecurityDescriptorControl':('advapi32',I,(P,W,W)),
 'SetFileSecurityW':('advapi32',I,(P,U,P)),
}
OUTPUTS={'NetWkstaUserGetInfo':{2:'buffer'},'MultiByteToWideChar':{4:'data'},
 'LookupAccountNameW':{3:'size',5:'domain_size',6:'sid_use'},'GetFileSecurityW':{4:'needed'},
 'InitializeSecurityDescriptor':{0:'sd'},'GetSecurityDescriptorDacl':{1:'present',2:'acl',3:'defaulted'},
 'GetAclInformation':{1:'info'},'GetAce':{2:'ace'},'SetSecurityDescriptorDacl':{0:'sd'},
 'GetSecurityDescriptorControl':{1:'control',2:'revision'},'SetSecurityDescriptorControl':{0:'sd'}}

class NativeOwnedAclPort:
    """Lazy per-instance native references; owner must close after writer calls.

    Native heap/net buffers are tracked until successful frees; module unload is
    refused while debt remains. Scripted _invoke doubles need no native loading.
    """
    def __init__(self,check):
        self.check_scope=check; self.libraries={}; self.allocations={}; self.net=set(); self.regions={}; self.closed=False
    def _invoke(self,name,args):
        dll,result,types=ACL_ABI[name]
        if os.name!='nt' or C.sizeof(P)!=8: raise QimeiRequestBoundary('Windows x64 ACL required')
        if dll not in self.libraries: self.libraries[dll]=C.WinDLL(dll,use_last_error=True)
        fn=self.libraries[dll][680] if name=='SHELL32.ordinal680' else getattr(self.libraries[dll],name)
        fn.restype,fn.argtypes=result,types
        return fn(*args)
    def read(self,channel,name,*args):
        self.check_scope()
        if self.closed or channel!='qimei-api' or name not in ACL_ABI: raise QimeiRequestBoundary('unbound ACL operation')
        backing={}; converted=[]
        for index,value in enumerate(args):
            if isinstance(value,StorageBuffer):
                buf=C.create_string_buffer(value.read(),len(value.data)); backing[index]=buf; converted.append(buf)
            elif type(value) is bytes:
                converted.append(C.create_string_buffer(value+b'\0\0'))
            else: converted.append(value)
        result=self._invoke(name,converted)
        result=0 if result is None else result
        if name=='HeapAlloc' and result:self.allocations[result]=args[2]
        if name=='HeapFree' and result:
            self.allocations.pop(args[2],None); self.regions.clear()
        if name=='NetWkstaUserGetInfo':
            pointer=int.from_bytes(backing[2].raw,'little')
            if pointer:self.net.add(pointer)
        if name=='NetApiBufferFree' and result==0:
            self.net.discard(args[0]); self.regions.clear()
        if name=='GetAce' and result:
            pointer=int.from_bytes(backing[2].raw,'little')
            if pointer:
                length=int.from_bytes(C.string_at(pointer,4)[2:4],'little'); self.regions[pointer]=length
        writes=tuple((key,0,backing[index].raw) for index,key in OUTPUTS.get(name,{}).items() if index in backing)
        return QimeiApiReply(int(result)&((1<<64)-1 if ACL_ABI[name][1] is P else 0xffffffff),writes)
    def read_memory(self,pointer,length=None):
        self.check_scope()
        if self.closed: raise QimeiRequestBoundary('closed ACL port')
        if pointer in self.net:
            user=int.from_bytes(C.string_at(pointer,8),'little')
            if user:
                data=C.wstring_at(user).encode('utf-16le')+b'\0\0'
                self.regions[user]=data
            return StorageBuffer(C.string_at(pointer,8))
        for base,size in (*self.allocations.items(),*self.regions.items()):
            if isinstance(size,bytes):
                if pointer==base:return StorageBuffer(size if length is None else size[:length])
            elif length is not None and base<=pointer and pointer+length<=base+size:
                return StorageBuffer(C.string_at(pointer,length))
        raise QimeiRequestBoundary('unowned ACL pointer')
    def _release(self,handle):
        from _ctypes import FreeLibrary
        FreeLibrary(handle)
    def close(self):
        self.check_scope()
        if self.closed:return
        if self.allocations or self.net: raise QimeiRequestBoundary('outstanding ACL native allocation debt')
        for dll in tuple(self.libraries):
            self._release(self.libraries[dll]._handle); del self.libraries[dll]
        self.closed=True

def _profile_ansi_path(path):
    # Win32 A APIs consume process ACP, unlike os.fsencode's Windows UTF-8.
    # Reject best-fit substitutions as well as unrepresentable characters.
    text=os.fspath(path)
    if type(text) is not str or '\0' in text:
        raise QimeiRequestBoundary('Own profile requires a NUL-free text path')
    try:
        encoded=text.encode('mbcs',errors='strict')
        if encoded.decode('mbcs',errors='strict')!=text:
            raise UnicodeError('non-lossless ACP path')
    except (UnicodeError,LookupError) as exc:
        raise QimeiRequestBoundary('Own profile path is not losslessly representable in Windows ACP') from exc
    return encoded


class NativeOwnedProfilePort:
    def __init__(self,check): self.check_scope=check; self.library=None; self.closed=False
    def _call(self,name,result,types,*args):
        self.check_scope()
        if self.closed: raise QimeiRequestBoundary('closed profile port')
        if os.name!='nt': raise QimeiRequestBoundary('Windows profile API required')
        if self.library is None:self.library=C.WinDLL('kernel32',use_last_error=True)
        fn=getattr(self.library,name); fn.restype,fn.argtypes=result,types
        return fn(*args)
    def string(self,path,key):
        target=C.create_string_buffer(33)
        self._call('GetPrivateProfileStringA',U,(C.c_char_p,C.c_char_p,C.c_char_p,P,U,C.c_char_p),b'Profile',key,None,target,33,_profile_ansi_path(path))
        return target.value
    def integer(self,path):
        return self._call('GetPrivateProfileIntA',U,(C.c_char_p,C.c_char_p,I,C.c_char_p),b'Profile',b'config5',0,_profile_ansi_path(path))
    def close(self):
        self.check_scope()
        if self.closed:return
        if self.library is not None:
            from _ctypes import FreeLibrary
            FreeLibrary(self.library._handle); self.library=None
        self.closed=True


def create_owned_qimei_main_writer(runtime,epoch,current_epoch,*,permit,root,logical_main_path,codec,context=None,context_observations,acl_port=None):
    from .primary_qimei_main_writer import QimeiMainWriter
    backend=OwnQimeiMainWriterObservations(runtime,epoch,current_epoch,permit=permit,root=root,logical_main_path=logical_main_path,acl_port=acl_port)
    return QimeiMainWriter(backend,codec=codec,context=context,context_observations=context_observations)


def create_owned_qimei_beacon(runtime,epoch,current_epoch,*,permit,root,producer,profile_port=None):
    from .primary_qimei_beacon import QimeiBeacon
    backend=OwnQimeiBeaconBackend(runtime,epoch,current_epoch,permit=permit,root=root,profile_port=profile_port)
    return QimeiBeacon(producer,backend)
