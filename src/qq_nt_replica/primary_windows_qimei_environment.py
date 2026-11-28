"""Lazy source file/redirection APIs plus existing owned leaf1 CPUID port."""
import ctypes as C,os,threading
from .primary_qimei_request import QimeiRequestBoundary,_integer
from .primary_qimei_storage import StorageBuffer
class WindowsQimeiEnvironment:
    def __init__(self,*,api=None,cpu_observations=None):
        self._api=api;self._cpu=cpu_observations;self._owns_cpu=cpu_observations is None
        self._owner=os.getpid(),threading.get_ident();self.closed=False;self.cleanup_failed=False
        self._functions={};self._libraries={};self._module=None;self._procedure=None
        self._debug_functions={};self._owned_refs=[];self.release_uncertain=False
    def _check(self):
        if self.closed or self.cleanup_failed or self._owner!=(os.getpid(),threading.get_ident()):raise QimeiRequestBoundary('environment backend requires open creator process/thread')
    def _load(self):
        self._check()
        if self._functions:return
        signatures={'GetModuleHandleA':(C.c_void_p,(C.c_char_p,)),'GetProcAddress':(C.c_void_p,(C.c_void_p,C.c_char_p)),'PathFileExistsA':(C.c_int32,(C.c_char_p,))}
        if self._api is None:
            if os.name!='nt' or C.sizeof(C.c_void_p)!=8:raise QimeiRequestBoundary('environment APIs require Windows AMD64')
            self._libraries={n:C.WinDLL(n,use_last_error=True) for n in ('kernel32','shlwapi')}
            functions={n:getattr(self._libraries['shlwapi' if n=='PathFileExistsA' else 'kernel32'],n) for n in signatures}
        else:functions={n:getattr(self._api,n) for n in signatures}
        for n,(result,args) in signatures.items():functions[n].restype=result;functions[n].argtypes=args
        self._functions=functions
    def resolve_redirection(self):
        self._load();self._module=self._functions['GetModuleHandleA'](b'kernel32') or 0
        self._procedure=self._functions['GetProcAddress'](self._module,b'Wow64EnableWow64FsRedirection') or 0
        return self._procedure
    def redirect(self,pointer,enabled):
        self._check()
        if not pointer or pointer!=self._procedure or self._module is None or type(enabled)is not bool:raise QimeiRequestBoundary('redirection requires own fixed lookup and BOOL argument')
        return C.WINFUNCTYPE(C.c_int32,C.c_int32)(pointer)(int(enabled))
    def path_exists(self,path):
        self._load()
        if type(path)is not bytes or b'\0'in path:raise QimeiRequestBoundary('source narrow path required')
        return _integer(self._functions['PathFileExistsA'](path))&0xFFFFFFFF
    def cpuid_leaf1(self):
        self._check()
        if self._cpu is None:
            from .primary_windows_qimei_request_sources import WindowsQimeiRequestObservations
            self._cpu=WindowsQimeiRequestObservations()
        data=StorageBuffer.unknown(16)
        reply=self._cpu.read('qimei-api','CPUID',1,0,data)
        output=reply.apply({'data':data})['data'].read()
        return tuple(int.from_bytes(output[i:i+4],'little') for i in range(0,16,4))
    def close(self):
        if self.closed:return
        self._check()
        try:
            for handle in tuple(self._owned_refs):self._release(handle)
            if self._cpu is not None and self._owns_cpu:self._cpu.close()
            if self.release_uncertain:raise QimeiRequestBoundary('owned module release outcome unknown')
        except BaseException:self.cleanup_failed=True;raise
        self.closed=True

    def _load_debug(self):
        self._check()
        if self._debug_functions:return
        signatures={'LoadLibraryA':(C.c_void_p,(C.c_char_p,)),
                    'GetProcAddress':(C.c_void_p,(C.c_void_p,C.c_char_p)),
                    'FreeLibrary':(C.c_int32,(C.c_void_p,)),
                    'GetCurrentProcess':(C.c_void_p,()),'GetCurrentThread':(C.c_void_p,()),
                    'GetThreadContext':(C.c_int32,(C.c_void_p,C.c_void_p))}
        if self._api is None:
            if os.name!='nt' or C.sizeof(C.c_void_p)!=8:raise QimeiRequestBoundary('debugger APIs require Windows AMD64')
            if 'kernel32' not in self._libraries:self._libraries['kernel32']=C.WinDLL('kernel32',use_last_error=True)
            api=self._libraries['kernel32']
        else:api=self._api
        for name,(result,args) in signatures.items():
            function=getattr(api,name);function.restype=result;function.argtypes=args;self._debug_functions[name]=function
    def _owned_export(self,module,name):
        self._load_debug()
        handle=self._debug_functions['LoadLibraryA'](module) or 0
        if not handle:return 0,0
        self._owned_refs.append(handle)
        return handle,self._debug_functions['GetProcAddress'](handle,name) or 0
    def _release(self,handle):
        if handle:
            # Source ignores BOOL. Keep uncertainty distinct from a source failure.
            if not self._debug_functions['FreeLibrary'](handle):self.release_uncertain=True
            self._owned_refs.remove(handle)
    def debugger_present(self):
        handle,pointer=self._owned_export(b'kernel32.dll',b'IsDebuggerPresent')
        value=C.WINFUNCTYPE(C.c_int32)(pointer)() if pointer else None
        self._release(handle)
        return value
    def remote_debugger(self):
        handle,pointer=self._owned_export(b'kernel32.dll',b'CheckRemoteDebuggerPresent')
        value=None
        if pointer:
            output=C.c_uint32(0)
            C.WINFUNCTYPE(C.c_int32,C.c_void_p,C.POINTER(C.c_uint32))(pointer)(self._debug_functions['GetCurrentProcess'](),C.byref(output))
            value=output.value
        self._release(handle)
        return value
    def kernel_debugger(self):
        handle,pointer=self._owned_export(b'ntdll.dll',b'NtQuerySystemInformation')
        value=None
        if pointer:
            output=(C.c_ubyte*2)();length=C.c_uint32(0)
            status=C.WINFUNCTYPE(C.c_int32,C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32))(pointer)(0x23,C.cast(output,C.c_void_p),2,C.byref(length))
            value=status,bytes(output)
        self._release(handle)
        return value
    def debug_registers(self):
        self._load_debug()
        backing=C.create_string_buffer(0x4D0+15)
        address=(C.addressof(backing)+15)&~15
        C.c_uint32.from_address(address+0x30).value=0x10001F
        accepted=self._debug_functions['GetThreadContext'](self._debug_functions['GetCurrentThread'](),C.c_void_p(address))
        return accepted,tuple(C.c_uint64.from_address(address+offset).value for offset in (0x48,0x50,0x58,0x60))
