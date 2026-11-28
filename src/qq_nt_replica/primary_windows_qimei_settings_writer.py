"""Lazy, explicitly scoped CRT settings file ports and same-file Windows DACL."""
import ctypes as C
from dataclasses import dataclass, replace
from .primary_windows_qimei_config import WindowsQimeiConfigSources
from .primary_qimei_request import QimeiRequestBoundary


@dataclass(frozen=True)
class _File:
    raw: int
    path: bytes
    closed: bool = False


@dataclass(frozen=True)
class _UnfreedNetApi:
    raw: int
    status: int
    operation: str


class WindowsQimeiSettingsWriterBackend(WindowsQimeiConfigSources):
    def __init__(self,runtime,epoch,current_epoch,*,path,permit):
        if type(path) is not bytes or not path or b'\0' in path:
            raise QimeiRequestBoundary('explicit owned ANSI settings path required')
        super().__init__(runtime,epoch,current_epoch,
            permit=lambda actual_runtime,actual_epoch: callable(permit) and permit(actual_runtime,actual_epoch,path,'settings-file-write-and-dacl'))
        self.__path=path
        self.__files={}
        self.acl_results=[]
        self.__failed_allocations=[]
        self.__unfreed_netapi=[]

    def validate_path(self,path):
        self._check()
        if path != self.__path:
            raise QimeiRequestBoundary('settings path is outside owned file scope')

    def close(self):
        if (any(not record.closed for record in self.__files.values()) or
                self.__failed_allocations or self.__unfreed_netapi):
            raise QimeiRequestBoundary('settings writer retains native cleanup debt')
        super().close()

    def _api(self,dll,name,result,types,*args):
        return self._call(dll,name,result,types,*args)

    def open_file(self,path):
        self.validate_path(path)
        raw=self._api('ucrtbase','fopen',C.c_void_p,(C.c_char_p,C.c_char_p),path,b'wb')
        if not raw:return None
        token=object();self.__files[token]=_File(raw,path)
        return token

    def _file(self,token):
        self._check()
        record=self.__files.get(token)
        if record is None or record.closed:
            raise QimeiRequestBoundary('foreign or closed settings FILE')
        self.validate_path(record.path)
        return record

    def write_file(self,token,data):
        record=self._file(token)
        return self._api('ucrtbase','fwrite',C.c_size_t,(C.c_void_p,C.c_size_t,C.c_size_t,C.c_void_p),data,1,len(data),record.raw)

    def close_file(self,token):
        record=self._file(token)
        result=self._api('ucrtbase','fclose',C.c_int32,(C.c_void_p,),record.raw)
        self.__files[token]=replace(record,closed=True)
        return result

    def path_exists(self,path):
        self.validate_path(path)
        return self._api('ucrtbase','_access',C.c_int32,(C.c_char_p,C.c_int32),path,0)==0

    def is_admin(self):
        return bool(self._api('shell32','IsUserAnAdmin',C.c_int32,()))

    def _wide(self,path):
        self.validate_path(path)
        args=(C.c_uint32,C.c_uint32,C.c_char_p,C.c_int32,C.c_void_p,C.c_int32)
        count=self._api('kernel32','MultiByteToWideChar',C.c_int32,args,0,0,path,-1,None,0)
        if not count:return None
        output=C.create_unicode_buffer(count)
        if not self._api('kernel32','MultiByteToWideChar',C.c_int32,args,0,0,path,-1,output,count):return None
        return output

    def grant_same_file_access(self,path):
        self.validate_path(path)
        # Buffers never escape this operation; public callers hold no raw authority.
        p=C.c_void_p;u=C.c_uint32;i=C.c_int32
        api=lambda name,types,*args:self._api('advapi32',name,i,types,*args)
        allocations=[]
        heap=self._api('kernel32','GetProcessHeap',p,())
        def allocate(size):
            raw=self._api('kernel32','HeapAlloc',p,(p,u,C.c_size_t),heap,8,size)
            if not raw:return None
            allocations.append(raw)
            return (C.c_char*size).from_address(raw)
        try:
            userbuf=p()
            status=self._api('netapi32','NetWkstaUserGetInfo',u,(C.c_wchar_p,u,C.POINTER(p)),None,1,C.byref(userbuf))
            username=''
            if status==0 and userbuf.value:
                try:
                    username=C.wstring_at(C.cast(userbuf,C.POINTER(p))[0])
                finally:
                    free_status=self._api('netapi32','NetApiBufferFree',u,(p,),userbuf)
                    if free_status:
                        self.__unfreed_netapi.append(_UnfreedNetApi(userbuf.value,free_status,'NetApiBufferFree'))
                        self.acl_results.append(('NetApiBufferFree_failed',free_status))
            if status != 0 and userbuf.value:
                self.__unfreed_netapi.append(_UnfreedNetApi(userbuf.value,status,'NetWkstaUserGetInfo'))
                self.acl_results.append(('source_unfreed_netapi',status))
            wide=self._wide(path)
            if not username or wide is None:
                self.acl_results.append(1);return 1
            sid_size=u();domain_size=u();use=u()
            lookup=(C.c_wchar_p,C.c_wchar_p,p,C.POINTER(u),p,C.POINTER(u),C.POINTER(u))
            result=api('LookupAccountNameW',lookup,None,username,None,C.byref(sid_size),None,C.byref(domain_size),C.byref(use))
            if result or C.get_last_error()!=122:
                self.acl_results.append(1);return 1
            sid=allocate(sid_size.value);domain=allocate(2*domain_size.value)
            if sid is None or domain is None:
                self.acl_results.append(1);return 1
            if not api('LookupAccountNameW',lookup,None,username,sid,C.byref(sid_size),domain,C.byref(domain_size),C.byref(use)):
                self.acl_results.append(1);return 1
            size=u();security=(C.c_wchar_p,u,p,u,C.POINTER(u))
            result=api('GetFileSecurityW',security,wide,4,None,0,C.byref(size))
            if result or C.get_last_error()!=122:
                self.acl_results.append(1);return 1
            old=allocate(size.value)
            if old is None:
                self.acl_results.append(1);return 1
            if not api('GetFileSecurityW',security,wide,4,old,size,C.byref(size)):
                self.acl_results.append(1);return 1
            new=allocate(40);present=i();defaulted=i();oldacl=p()
            if new is None:
                self.acl_results.append(1);return 1
            if not api('InitializeSecurityDescriptor',(p,u),new,1) or not api('GetSecurityDescriptorDacl',(p,C.POINTER(i),C.POINTER(p),C.POINTER(i)),old,C.byref(present),C.byref(oldacl),C.byref(defaulted)):
                self.acl_results.append(1);return 1
            info=(u*3)()
            if oldacl.value and not api('GetAclInformation',(p,p,u,u),oldacl,info,C.sizeof(info),2):
                self.acl_results.append(1);return 1
            length=self._api('advapi32','GetLengthSid',u,(p,),sid)
            acl=allocate((info[1] if oldacl.value else 8)+length+8)
            if acl is None:
                self.acl_results.append(1);return 1
            if not api('InitializeAcl',(p,u,u),acl,C.sizeof(acl),2):
                self.acl_results.append(1);return 1
            index=0;ok=True
            while oldacl.value and index<info[0]:
                ace=p()
                if not api('GetAce',(p,u,C.POINTER(p)),oldacl,index,C.byref(ace)):break
                head=C.string_at(ace,4)
                if head[1]&0x10:break
                if not api('EqualSid',(p,p),sid,ace.value+8):
                    if not api('AddAce',(p,u,u,p,u),acl,2,0xffffffff,ace,int.from_bytes(head[2:4],'little')):
                        ok=False;break
                index+=1
            if ok:ok=bool(api('AddAccessAllowedAceEx',(p,u,u,u,p),acl,2,3,0x10000000,sid))
            while ok and oldacl.value and index<info[0]:
                ace=p()
                if not api('GetAce',(p,u,C.POINTER(p)),oldacl,index,C.byref(ace)):
                    ok=False;break
                head=C.string_at(ace,4)
                ok=bool(api('AddAce',(p,u,u,p,u),acl,2,0xffffffff,ace,int.from_bytes(head[2:4],'little')))
                index+=1
            if ok:ok=bool(api('SetSecurityDescriptorDacl',(p,i,p,i),new,1,acl,0))
            control=C.c_uint16();revision=u()
            if ok:ok=bool(api('GetSecurityDescriptorControl',(p,C.POINTER(C.c_uint16),C.POINTER(u)),old,C.byref(control),C.byref(revision)))
            status=0 if ok else 1
            if ok:
                mask=0x500 if control.value&0x400 else 0x1000 if control.value&0x1000 else 0
                if mask:
                    ok=bool(api('SetSecurityDescriptorControl',(p,C.c_uint16,C.c_uint16),new,mask,mask))
                    if not ok:status=2
            if ok:
                ok=bool(api('SetFileSecurityW',(C.c_wchar_p,u,p),wide,4,new))
                if not ok:status=3
            self.acl_results.append(status)
            return status
        finally:
            errors=[]
            for raw in reversed(allocations):
                if not self._api('kernel32','HeapFree',i,(p,u,p),heap,0,raw):
                    errors.append(raw)
            if errors:
                self.__failed_allocations.extend((heap,raw) for raw in errors)
                self.acl_results.append(('HeapFree_failed',len(errors)))


def create_windows_qimei_settings_writer(runtime,epoch,current_epoch,*,path,permit,codec,context_producer,observations,attempted=None):
    from .primary_qimei_settings_writer import QimeiSettingsWriter
    backend=WindowsQimeiSettingsWriterBackend(runtime,epoch,current_epoch,path=path,permit=permit)
    return QimeiSettingsWriter(backend,codec,context_producer,observations,attempted=attempted)
