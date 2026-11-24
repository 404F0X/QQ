"""Lazy three-API observations for source QimeiSettings initialization only."""
import ctypes as C
import os
from .primary_qimei_observations import QimeiApiReply
from .primary_qimei_request import QimeiRequestBoundary,_bytes,_integer
from .primary_qimei_storage import StorageBuffer
_SIGNATURES={
 'SHGetSpecialFolderPathA':('shell32',C.c_int32,(C.c_void_p,C.c_void_p,C.c_int32,C.c_int32)),
 'PathIsDirectoryA':('shlwapi',C.c_int32,(C.c_char_p,)),
 'CreateDirectoryA':('kernel32',C.c_int32,(C.c_char_p,C.c_void_p)),
}
class WindowsQimeiSettingsObservations:
    def __init__(self,*,api=None):
        self._injected=api;self._libraries={};self._functions={}
    def _load(self):
        if self._functions:return
        if self._injected is None:
            if os.name!='nt' or C.sizeof(C.c_void_p)!=8:
                raise QimeiRequestBoundary('settings initialization APIs require Windows AMD64')
            libraries={n:C.WinDLL(n,use_last_error=True) for n in ('shell32','shlwapi','kernel32')}
            functions={name:getattr(libraries[library],name) for name,(library,_,__) in _SIGNATURES.items()}
        else:
            libraries={};functions={name:getattr(self._injected,name) for name in _SIGNATURES}
        for name,(_,result,args) in _SIGNATURES.items():
            functions[name].restype,functions[name].argtypes=result,args
        self._libraries,self._functions=libraries,functions
    def read(self,namespace,name,*args):
        if namespace!='qimei-api' or name not in _SIGNATURES:
            raise QimeiRequestBoundary('unsupported settings initialization observation')
        if name=='SHGetSpecialFolderPathA':
            if len(args)!=4:raise QimeiRequestBoundary('settings special folder ABI required')
            hwnd,source,identifier,create=args
            if (type(hwnd)is not int or hwnd!=0 or type(identifier)is not int or identifier not in (0x23,0x1A)
                    or type(create)is not int or create!=1 or not isinstance(source,StorageBuffer) or len(source.data)!=260):
                raise QimeiRequestBoundary('settings special folder source buffer/flags required')
            data=C.create_string_buffer(source.read(),260)
            self._load();result=self._functions[name](hwnd,data,identifier,create)
            return QimeiApiReply(_integer(result)&0xFFFFFFFF,(('data',0,data.raw),))
        if len(args)!=(1 if name=='PathIsDirectoryA' else 2):
            raise QimeiRequestBoundary('settings directory ABI required')
        path=_bytes(args[0])
        if b'\0' in path:raise QimeiRequestBoundary('settings directory path requires CString payload')
        if name=='CreateDirectoryA' and (type(args[1])is not int or args[1]!=0):
            raise QimeiRequestBoundary('settings directory NULL attributes required')
        self._load();result=self._functions[name](*args)
        return QimeiApiReply(_integer(result)&0xFFFFFFFF)
