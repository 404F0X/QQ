"""Lazy ANSI Windows metadata port for Source QQ kind13; no file-content reads."""
import ctypes as C
import os
import threading

from .primary_qimei_observations import QimeiApiReply
from .primary_qimei_request import QimeiRequestBoundary
from .primary_qimei_storage import StorageBuffer


_SIGNATURES = {
    'SHGetSpecialFolderPathA': ('shell32', C.c_int32, (C.c_void_p, C.c_void_p, C.c_int32, C.c_int32)),
    '_access': ('ucrtbase', C.c_int32, (C.c_char_p, C.c_int32)),
    '_stat64': ('ucrtbase', C.c_int32, (C.c_char_p, C.c_void_p)),
    'FindFirstFileA': ('kernel32', C.c_void_p, (C.c_char_p, C.c_void_p)),
    'FindNextFileA': ('kernel32', C.c_int32, (C.c_void_p, C.c_void_p)),
    'FindClose': ('kernel32', C.c_int32, (C.c_void_p,)),
    '_localtime64_s': ('ucrtbase', C.c_int32, (C.c_void_p, C.c_void_p)),
}


class WindowsQimeiReportObservations:
    def __init__(self, *, api=None):
        self._injected, self._libraries, self._functions = api, {}, {}
        self._thread, self._closed, self._handles = threading.get_ident(), False, set()

    def _check(self):
        if self._closed or threading.get_ident() != self._thread:
            raise QimeiRequestBoundary('QQ metadata port requires its live constructing thread')

    def _load(self):
        if self._functions:
            return
        if self._injected is None:
            if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
                raise QimeiRequestBoundary('QQ metadata APIs require Windows AMD64')
            self._libraries = {name: (C.CDLL if name == 'ucrtbase' else C.WinDLL)(name)
                               for name in ('shell32', 'kernel32', 'ucrtbase')}
        for name, (library, result, args) in _SIGNATURES.items():
            function = getattr(self._injected if self._injected is not None else self._libraries[library], name)
            function.restype, function.argtypes = result, args
            self._functions[name] = function

    def read(self, namespace, name, *args):
        self._check()
        if namespace != 'qimei-api' or name not in _SIGNATURES:
            raise QimeiRequestBoundary('unsupported QQ metadata observation')
        outputs = {}
        def buffer(value, size):
            if not isinstance(value, StorageBuffer) or len(value.data) != size:
                raise QimeiRequestBoundary('QQ metadata raw buffer ABI required')
            data = C.create_string_buffer(value.read(), size)
            outputs['data'] = data
            return data
        if name == 'SHGetSpecialFolderPathA':
            hwnd, data, identifier, create = args
            if hwnd != 0 or identifier not in (0x1A, 5) or create != 1:
                raise QimeiRequestBoundary('QQ metadata Source folder flags required')
            call = (hwnd, buffer(data, 260), identifier, create)
        elif name == '_access':
            path, mode = args
            if mode != 0:
                raise QimeiRequestBoundary('QQ metadata access mode0 required')
            call = (path, mode)
        elif name in ('_stat64', 'FindFirstFileA'):
            path, data = args
            call = (path, buffer(data, 56 if name == '_stat64' else 320))
        elif name == '_localtime64_s':
            data, seconds = args
            timestamp = C.c_int64(seconds)
            call = (buffer(data, 36), C.byref(timestamp))
        else:
            handle = args[0]
            if handle not in self._handles:
                raise QimeiRequestBoundary('QQ enumeration requires an owned find handle')
            call = (handle, buffer(args[1], 320)) if name == 'FindNextFileA' else (handle,)
        self._load()
        result = self._functions[name](*call)
        result = int(result or 0)
        if name == 'FindFirstFileA':
            result &= 0xFFFFFFFFFFFFFFFF
            if result != 0xFFFFFFFFFFFFFFFF:
                self._handles.add(result)
        elif name == 'FindClose' and result:
            self._handles.remove(args[0])
        return QimeiApiReply(result & (0xFFFFFFFFFFFFFFFF if name == 'FindFirstFileA' else 0xFFFFFFFF),
            tuple((key, 0, value.raw) for key, value in outputs.items()))

    def close(self):
        if self._closed:
            return
        self._check()
        for handle in tuple(self._handles):
            self.read('qimei-api', 'FindClose', handle)
        if self._handles:
            raise QimeiRequestBoundary('QQ find-handle cleanup debt retained')
        self._closed = True
