"""Lazy Windows AMD64 Toolhelp/ACP port for the finite Qimei treeB producer."""
import ctypes as C
import os
from .primary_vm import PrimarySemanticUnavailable
from .errors import InputError

_SIGNATURES = {
    'CreateToolhelp32Snapshot': (C.c_void_p, (C.c_uint32, C.c_uint32)),
    'Process32FirstW': (C.c_int32, (C.c_void_p, C.c_void_p)),
    'Process32NextW': (C.c_int32, (C.c_void_p, C.c_void_p)),
    'CloseHandle': (C.c_int32, (C.c_void_p,)),
    'WideCharToMultiByte': (C.c_int32, (C.c_uint32, C.c_uint32, C.c_void_p,
        C.c_int32, C.c_void_p, C.c_int32, C.c_void_p, C.c_void_p)),
}


class WindowsQimeiProcessTreePort:
    def __init__(self):
        self._library = None
        self._functions = {}

    def _load(self):
        if self._library is not None:
            return
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise PrimarySemanticUnavailable('Qimei process tree requires Windows AMD64')
        library = C.WinDLL('kernel32', use_last_error=True)
        functions = {}
        for name, (result, arguments) in _SIGNATURES.items():
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            functions[name] = function
        self._library, self._functions = library, functions

    def call(self, name, *arguments):
        if name not in _SIGNATURES:
            raise InputError('unsupported Qimei process tree API')
        self._load()
        if name in ('Process32FirstW', 'Process32NextW'):
            handle, entry = arguments
            buffer = (C.c_ubyte * len(entry)).from_buffer(entry)
            return self._functions[name](handle, buffer)
        if name == 'WideCharToMultiByte':
            cp, flags, wide, length, destination, capacity, default, used = arguments
            source = C.create_string_buffer(wide)
            output = None if destination is None else (C.c_ubyte * len(destination)).from_buffer(destination)
            return self._functions[name](cp, flags, source, length, output, capacity, default, used)
        result = self._functions[name](*arguments)
        return 0 if name == 'CreateToolhelp32Snapshot' and result is None else result
