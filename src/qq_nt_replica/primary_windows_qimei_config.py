"""Source config observations; lazy Windows ports, never query at construction."""
import ctypes as C
import os
import threading
from .primary_qimei_request import QimeiRequestBoundary


def classify_version(major, minor, build):
    major, minor, build = (v & 0xffffffff for v in (major, minor, build))
    signed = lambda v: v if v < 0x80000000 else v - 0x100000000
    if major == 5:
        return 1 if minor == 1 else 2 if minor != 0 else 0
    if major == 6:
        return minor + 3 if minor < 3 else 6
    if major == 10:
        thresholds = (14393,15063,16299,17134,17763,18362,18363,19041,22000,22621,22631)
        values = (7,9,10,11,12,13,14,15,16,17,18,19)
        return values[sum(signed(build) >= threshold for threshold in thresholds)]
    return 20 if signed(major) >= 7 else 0


def architecture_class(value):
    return {0:0,9:1,6:2,12:3}.get(value,4)


class _Version(C.Structure):
    _fields_ = [('size',C.c_uint32),('major',C.c_uint32),('minor',C.c_uint32),
                ('build',C.c_uint32),('platform',C.c_uint32),('text',C.c_char*128)]


class WindowsQimeiConfigSources:
    def __init__(self, runtime, epoch, current_epoch, *, permit):
        self.__binding = (runtime,epoch,current_epoch,permit,os.getpid(),threading.get_native_id())
        self.__libraries = {}
        self.__wow64 = None
        self.__closed = False

    def _check(self):
        runtime,epoch,current,permit,pid,thread = self.__binding
        if (self.__closed or not callable(permit) or not permit(runtime,epoch) or current(runtime) is not epoch or
                pid != os.getpid() or thread != threading.get_native_id()):
            raise QimeiRequestBoundary('config platform observation scope unavailable')

    def _call(self, library, name, result, types, *args):
        self._check()
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise QimeiRequestBoundary('Windows x64 config API unavailable')
        if library not in self.__libraries:
            self.__libraries[library] = C.WinDLL(library,use_last_error=True)
        fn = getattr(self.__libraries[library],name)
        fn.restype,fn.argtypes = result,types
        return fn(*args)

    def os_classification(self):
        output = _Version();output.size = C.sizeof(output)
        self._call('kernel32','GetVersionExA',C.c_int32,(C.POINTER(_Version),),C.byref(output))
        major,minor,build = output.major,output.minor,output.build
        if (major,minor) == (6,2):
            module = self._call('kernel32','GetModuleHandleA',C.c_void_p,(C.c_char_p,),b'ntdll.dll')
            proc = self._call('kernel32','GetProcAddress',C.c_void_p,(C.c_void_p,C.c_char_p),module,b'RtlGetNtVersionNumbers')
            if proc:
                a,b,c = C.c_uint32(major),C.c_uint32(minor),C.c_uint32(build)
                self._invoke_version(proc,a,b,c)
                major,minor,build = a.value,b.value,c.value & 0xffff
        return classify_version(major,minor,build)

    def _invoke_version(self, proc, major, minor, build):
        self._check()
        C.WINFUNCTYPE(None,*([C.POINTER(C.c_uint32)]*3))(proc)(C.byref(major),C.byref(minor),C.byref(build))

    def architecture(self):
        output = (C.c_uint64*6)()
        self._call('kernel32','GetNativeSystemInfo',None,(C.c_void_p,),C.byref(output))
        return architecture_class(output[0] & 0xffff)

    def wow64(self):
        self._check()
        if self.__wow64 is None:
            process = self._call('kernel32','GetCurrentProcess',C.c_void_p,())
            output = C.c_int32()
            self._call('kernel32','IsWow64Process',C.c_int32,(C.c_void_p,C.POINTER(C.c_int32)),process,C.byref(output))
            self.__wow64 = output.value & 0xffffffff
        return self.__wow64

    def clock(self):
        local = (C.c_uint16*8)()
        self._call('kernel32','GetLocalTime',None,(C.c_void_p,),C.byref(local))
        year,month,week,day,hour,minute,second,millis = local
        tm = (C.c_int32*9)(second,minute,hour,day,month-1,year-1900,0,0,0)
        return self._call('ucrtbase','_mktime64',C.c_int64,(C.c_void_p,),C.byref(tm))

    def clock_milliseconds(self):
        local = (C.c_uint16*8)()
        self._call('kernel32','GetLocalTime',None,(C.c_void_p,),C.byref(local))
        year,month,week,day,hour,minute,second,millis = local
        tm = (C.c_int32*9)(second,minute,hour,day,month-1,year-1900,0,0,0)
        seconds = self._call('ucrtbase','_mktime64',C.c_int64,(C.c_void_p,),C.byref(tm))
        return (seconds*1000+millis)&0xFFFFFFFFFFFFFFFF

    def close(self):
        if self.__closed:
            return
        self._check()
        from _ctypes import FreeLibrary
        for name, library in tuple(self.__libraries.items()):
            FreeLibrary(library._handle)
            del self.__libraries[name]
        self.__closed = True
