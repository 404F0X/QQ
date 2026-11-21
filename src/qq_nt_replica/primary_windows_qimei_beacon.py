"""Dedicated lazy, scoped NORMAL beacon ANSI file/profile ports."""
import ctypes as C
from dataclasses import dataclass,replace
from .primary_windows_qimei_config import WindowsQimeiConfigSources
from .primary_qimei_request import QimeiRequestBoundary


@dataclass(frozen=True)
class _Handle:
    raw:int
    path:bytes
    closed:bool=False


class WindowsQimeiBeaconBackend(WindowsQimeiConfigSources):
    def __init__(self,runtime,epoch,current_epoch,*,permit):
        super().__init__(runtime,epoch,current_epoch,permit=permit)
        self.__handles={};self.__paths=set();self.__active=False

    def check(self):self._check()
    def __api(self,name,result,types,*args):
        self.check()
        if self.__active:raise QimeiRequestBoundary('beacon native borrow already active')
        self.__active=True
        try:return self._call('shell32' if name=='SHGetFolderPathA' else 'kernel32',name,result,types,*args)
        finally:self.__active=False
    def folder(self):
        data=C.create_string_buffer(261)
        status=self.__api('SHGetFolderPathA',C.c_int32,(C.c_void_p,C.c_int32,C.c_void_p,C.c_uint32,C.c_void_p),None,0x801a,None,0,data)
        return status,data.value
    def error(self):return self.__api('GetLastError',C.c_uint32,())
    def _open(self,path,mode):
        if path not in self.__paths:raise QimeiRequestBoundary('unissued beacon path')
        raw=self.__api('CreateFileA',C.c_void_p,(C.c_char_p,C.c_uint32,C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_void_p),path,0xc0000000,3,None,mode,0x80,None)
        if raw==C.c_void_p(-1).value:return None
        token=object();self.__handles[token]=_Handle(raw or 0,path);return token
    def _record(self,token):
        self.check();record=self.__handles.get(token)
        if record is None or record.closed:raise QimeiRequestBoundary('foreign/closed beacon handle')
        return record
    def close(self,token):
        record=self._record(token)
        result=self.__api('CloseHandle',C.c_int32,(C.c_void_p,),record.raw)
        if result:self.__handles[token]=replace(record,closed=True)
        return result
    def open_main(self):
        status,base=self.folder()
        if status<0:return None,b'',3
        for part in (b'Tencent',b'qimei'):
            base+=b'\\'+part
            if not self.__api('CreateDirectoryA',C.c_int32,(C.c_char_p,C.c_void_p),base,None):
                if self.error()!=183 and self.error()!=5:return None,b'',3
        path=base+b'\\RanMgr.db';self.__paths.add(path)
        token=self._open(path,3)
        if token is not None:return token,path,0x50
        if self.error()!=2:return None,b'',0x65f
        token=self._open(path,2)
        return (token,path,0) if token is not None else (None,b'',0x65f)
    def _ini(self,path,key):
        target=C.create_string_buffer(33)
        self.__api('GetPrivateProfileStringA',C.c_uint32,(C.c_char_p,C.c_char_p,C.c_char_p,C.c_void_p,C.c_uint32,C.c_char_p),b'Profile',key,None,target,33,path)
        return target.value
    def read_config(self,path):
        self.check()
        if path not in self.__paths:raise QimeiRequestBoundary('unissued beacon profile path')
        values=[self._ini(path,key) for key in (b'config1',b'config2',b'config3',b'config4')]
        flag=self.__api('GetPrivateProfileIntA',C.c_uint32,(C.c_char_p,C.c_char_p,C.c_int32,C.c_char_p),b'Profile',b'config5',0,path)
        return (*values,flag)
    def persist(self,original,path,raw,digests):
        record=self._record(original)
        if path!=record.path:raise QimeiRequestBoundary('beacon save path/handle mismatch')
        current=original;reopened=False
        position=self.__api('SetFilePointer',C.c_uint32,(C.c_void_p,C.c_int32,C.c_void_p,C.c_uint32),record.raw,0,None,0)
        if position!=0xffffffff:self.__api('SetEndOfFile',C.c_int32,(C.c_void_p,),record.raw)
        high=C.c_uint32()
        low=self.__api('GetFileSize',C.c_uint32,(C.c_void_p,C.POINTER(C.c_uint32)),record.raw,C.byref(high))
        if low|high.value:current=self._open(path,2);reopened=True
        text=b'[Profile]\r\n'+b''.join(b'config'+str(index).encode()+b'='+value+b'\r\n' for index,value in enumerate((raw.hex().encode(),*digests,b'1'),1))
        written=C.c_uint32()
        actual=C.c_void_p(-1).value if current is None else self._record(current).raw
        try:self.__api('WriteFile',C.c_int32,(C.c_void_p,C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32),C.c_void_p),actual,text,len(text),C.byref(written),None)
        finally:
            if reopened and current is not None:self.close(current)
    def read_outer(self):
        status,base=self.folder()
        if status<0 or status==1:return None
        path=base+b'\\Tencent\\beacon\\GlobalMgr.db'
        return self._ini(path,b'config1')


_sessions={}

def create_windows_qimei_beacon(runtime,epoch,current_epoch,*,permit,selector,selector_observations,storage_observations,cpu_observations):
    from .primary_qimei_beacon import QimeiBeacon,QimeiBeaconInputProducer
    key=(id(runtime),id(epoch))
    if key in _sessions:
        bound_runtime,bound_epoch,beacon=_sessions[key]
        if bound_runtime is not runtime or bound_epoch is not epoch:raise QimeiRequestBoundary('beacon session identity mismatch')
        beacon.backend.check()
        return beacon
    beacon=QimeiBeacon(QimeiBeaconInputProducer(selector,selector_observations,storage_observations,cpu_observations),
        WindowsQimeiBeaconBackend(runtime,epoch,current_epoch,permit=permit))
    _sessions[key]=(runtime,epoch,beacon)
    return beacon
