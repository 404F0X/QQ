"""Lazy system A-API port, no target wrapper/DLL execution."""
import ctypes as C
import os
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
_SIGNATURES={
'SHGetSpecialFolderPathA':('shell32',C.c_int32,(C.c_void_p,C.c_void_p,C.c_int32,C.c_int32)),
'GetPrivateProfileStringA':('kernel32',C.c_uint32,(C.c_char_p,C.c_char_p,C.c_char_p,C.c_void_p,C.c_uint32,C.c_char_p)),
'PathFileExistsA':('shlwapi',C.c_int32,(C.c_char_p,))}
class WindowsMachineGuidLegacyPathPort:
    def __init__(self):self._libraries={};self._functions={}
    def _load(self):
        if self._functions:return
        if os.name!='nt' or C.sizeof(C.c_void_p)!=8:raise PrimarySemanticUnavailable('legacy path APIs require Windows AMD64')
        libraries={name:C.WinDLL(name,use_last_error=True) for name in ('shell32','kernel32','shlwapi')};functions={}
        for name,(library,result,args) in _SIGNATURES.items():
            fn=getattr(libraries[library],name);fn.restype=result;fn.argtypes=args;functions[name]=fn
        self._libraries,self._functions=libraries,functions
    def call(self,name,*args):
        if name not in _SIGNATURES:raise InputError('unsupported legacy path API')
        self._load()
        buffers=[(C.c_ubyte*len(v)).from_buffer(v) if type(v)is bytearray else v for v in args]
        return self._functions[name](*buffers)
