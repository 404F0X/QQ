"""Independent cold material16/seed8 birth; no SDK singleton or warm-state claim."""
import ctypes as C
import os
import sys
import threading
from .errors import InputError
from .primary_sign import filetime_seconds,qpc_nanoseconds

_MASK32=(1<<32)-1

def mix_bytes(raw,seed,*,add_index):
    result=bytearray(raw)
    for i in range(len(result)):
        mask=seed^((i*7+5)&255) if add_index else seed^((i*7)&255)
        result[i]^=mask
        seed=(seed*13+17)&255
    return bytes(result)

def produce_device_mix(port):
    """One owned cold birth. The returned bytes outlive all three allocations."""
    owned=[]
    def allocate(size):
        pointer=port.allocate(size)
        if type(pointer)is not int or pointer==0:raise InputError('cold allocation failed')
        owned.append(pointer);return pointer
    def release(pointer):
        owned.remove(pointer);port.free(pointer)
    try:
        container=allocate(1328)
        state=((container&_MASK32)^(filetime_seconds(port.filetime())&_MASK32))&_MASK32
        salt=bytearray()
        for _ in range(64):
            state=(state*1103515245+12345)&_MASK32;salt.append(((state>>16)|1)&255)
        start=port.steady()
        random=allocate(48);port.write(random,bytes(48))
        for i in range(12):port.random4(random+i*4)
        mix=allocate(16);output=bytearray(16)
        for i in range(3):
            block=port.read(random+i*16,16);port.write(mix,block)
            for j,value in enumerate(block):output[j]^=value
        clockmix=b''.join((port.steady()&_MASK32).to_bytes(4,'little') for _ in range(4))
        port.write(mix,clockmix)
        for i,value in enumerate(clockmix):output[i]^=value
        delta=((port.steady()-start)&_MASK32).to_bytes(4,'little');port.write(mix,delta)
        for i,value in enumerate(delta):output[i]^=value
        release(mix);release(random)
        material=mix_bytes(mix_bytes(bytes(output),salt[5],add_index=True),salt[0],add_index=False)
        result=material+bytes([salt[0]])
        release(container)
        return result
    finally:
        # Host resource policy, not a claim of original CRT/EH unwinding.
        cleanup=[]
        for pointer in tuple(reversed(owned)):
            try:port.free(pointer)
            except BaseException as error:cleanup.append(error)
        if cleanup:
            original=sys.exception()
            if original is not None:raise BaseExceptionGroup('cold producer and cleanup failed',[original,*cleanup])
            raise BaseExceptionGroup('cold producer cleanup failed',cleanup)

class WindowsDeviceMixPort:
    """Lazy fixed Windows APIs, creator-owned heap pointers and cold QPF domain."""
    def __init__(self):
        self.owner=(os.getpid(),threading.get_ident());self.closed=False;self.allocations={};self.frequency=None;self.failed_frees=set();self.api={};self.libraries={};self.heap=None
    def _load(self):
        if self.closed or self.owner!=(os.getpid(),threading.get_ident()):raise InputError('cold port requires open creator process/thread')
        if self.api:return
        if os.name!='nt' or C.sizeof(C.c_void_p)!=8:raise InputError('cold port requires Windows AMD64')
        self.libraries={n:C.WinDLL(n,use_last_error=True) for n in ('kernel32','advapi32')}
        specs={'GetProcessHeap':(C.c_void_p,()),'HeapAlloc':(C.c_void_p,(C.c_void_p,C.c_uint32,C.c_size_t)),'HeapFree':(C.c_int32,(C.c_void_p,C.c_uint32,C.c_void_p)),'GetSystemTimeAsFileTime':(None,(C.POINTER(C.c_uint64),)),'QueryPerformanceFrequency':(C.c_int32,(C.POINTER(C.c_int64),)),'QueryPerformanceCounter':(C.c_int32,(C.POINTER(C.c_int64),)),'SystemFunction036':(C.c_ubyte,(C.c_void_p,C.c_uint32))}
        for name,(result,args) in specs.items():
            f=getattr(self.libraries['advapi32' if name=='SystemFunction036' else 'kernel32'],name);f.restype=result;f.argtypes=args;self.api[name]=f
        self.heap=self.api['GetProcessHeap']()
        if not self.heap:raise OSError('GetProcessHeap failed')
    def allocate(self,size):
        self._load();pointer=self.api['HeapAlloc'](self.heap,0,size)
        if not pointer:raise MemoryError('HeapAlloc failed')
        self.allocations[pointer]=size;return pointer
    def _span(self,pointer,size):
        self._load()
        if not any(p<=pointer and pointer+size<=p+n for p,n in self.allocations.items()):raise InputError('cold buffer requires actual owned span')
    def read(self,pointer,size):self._span(pointer,size);return C.string_at(pointer,size)
    def write(self,pointer,data):self._span(pointer,len(data));C.memmove(pointer,data,len(data))
    def free(self,pointer):
        self._load()
        if pointer not in self.allocations:raise InputError('cold free requires owned allocation')
        if pointer in self.failed_frees:raise OSError('previous HeapFree failed; ownership outcome unknown')
        if not self.api['HeapFree'](self.heap,0,pointer):
            self.failed_frees.add(pointer);raise OSError('HeapFree failed')
        del self.allocations[pointer]
    def random4(self,pointer):
        self._span(pointer,4)
        if not self.api['SystemFunction036'](pointer,4):raise OSError('SystemFunction036 failed')
    def filetime(self):
        self._load();value=C.c_uint64();self.api['GetSystemTimeAsFileTime'](C.byref(value));return value.value
    def steady(self):
        self._load()
        if self.frequency is None:
            frequency=C.c_int64()
            if not self.api['QueryPerformanceFrequency'](C.byref(frequency)) or frequency.value<=0:raise OSError('QueryPerformanceFrequency failed')
            self.frequency=frequency.value
        value=C.c_int64()
        if not self.api['QueryPerformanceCounter'](C.byref(value)):raise OSError('QueryPerformanceCounter failed')
        return qpc_nanoseconds(value.value&((1<<64)-1),self.frequency)
    def close(self):
        if self.closed:return
        self._load()
        for pointer in tuple(reversed(self.allocations)):self.free(pointer)
        if self.libraries:
            import _ctypes
            self.api.clear()
            for name,library in tuple(self.libraries.items()):
                _ctypes.FreeLibrary(library._handle)
                del self.libraries[name]
        self.closed=True
