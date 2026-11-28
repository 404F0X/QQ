"""Lazy system-only Windows AMD64 port for finite Qimei module treeA."""
import ctypes as C
import os
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
_SIGNATURES={
 'GetCurrentProcessId':('kernel32',C.c_uint32,()),
 'OpenProcess':('kernel32',C.c_void_p,(C.c_uint32,C.c_int32,C.c_uint32)),
 'CloseHandle':('kernel32',C.c_int32,(C.c_void_p,)),
 'EnumProcessModules':('psapi',C.c_int32,(C.c_void_p,C.c_void_p,C.c_uint32,C.c_void_p)),
 'GetModuleFileNameExA':('psapi',C.c_uint32,(C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint32)),
 'GetModuleFileNameA':('kernel32',C.c_uint32,(C.c_void_p,C.c_void_p,C.c_uint32)),
}
class WindowsQimeiModuleTreePort:
    def __init__(self):self._libraries={};self._functions={}
    def _load(self):
        if self._functions:return
        if os.name!='nt' or C.sizeof(C.c_void_p)!=8:
            raise PrimarySemanticUnavailable('Qimei module tree requires Windows AMD64')
        libraries={name:C.WinDLL(name,use_last_error=True) for name in ('kernel32','psapi')}
        functions={}
        for name,(library,result,args) in _SIGNATURES.items():
            fn=getattr(libraries[library],name);fn.restype=result;fn.argtypes=args;functions[name]=fn
        self._libraries,self._functions=libraries,functions
    def call(self,name,*args):
        if name not in _SIGNATURES:raise InputError('unsupported Qimei module API')
        self._load()
        converted=[(C.c_ubyte*len(v)).from_buffer(v) if type(v) is bytearray else v for v in args]
        result=self._functions[name](*converted)
        return 0 if name=='OpenProcess' and result is None else result
