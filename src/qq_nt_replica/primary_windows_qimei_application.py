import ctypes
import os
from pathlib import PureWindowsPath
from threading import get_ident

from .primary_qimei_application import QimeiApplication
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError


class DataBlob(ctypes.Structure):
    _fields_ = [('cbData', ctypes.c_uint32), ('pbData', ctypes.c_void_p)]


class WindowsQimeiApplicationReader:
    def __init__(self, msf_path, *, source_binding, api=None):
        if not isinstance(msf_path, str) or '\0' in msf_path or not isinstance(source_binding, str) or not source_binding.strip():
            raise QimeiRequestError('explicit source-bound local MSF directory required')
        path = PureWindowsPath(msf_path)
        if not path.is_absolute() or len(path.drive) != 2 or path.drive[1] != ':' or '..' in path.parts:
            raise QimeiRequestBoundary('MSF directory must be an absolute local drive path without traversal')
        if ctypes.sizeof(ctypes.c_void_p) != 8 or api is None and os.name != 'nt':
            raise QimeiRequestError('Registry20 reader requires Windows x64 or explicit fake ABI')
        self._path = str(path / 'Registry20')
        self._source_binding = source_binding
        self._thread, self._used, self._closed = get_ident(), False, False
        self._handle, self._allocations = None, set()
        self._read_length = 0
        if api is None:
            kernel, crypt = ctypes.WinDLL('kernel32', use_last_error=True), ctypes.WinDLL('crypt32', use_last_error=True)
            self._api = {name: getattr(crypt if name == 'CryptUnprotectData' else kernel, name) for name in
                         ('CreateFileW', 'GetFileSizeEx', 'ReadFile', 'CloseHandle', 'CryptUnprotectData', 'LocalFree')}
        else:
            self._api = {name: getattr(api, name) for name in
                         ('CreateFileW', 'GetFileSizeEx', 'ReadFile', 'CloseHandle', 'CryptUnprotectData', 'LocalFree')}
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        signatures = {
            'CreateFileW': (p, (ctypes.c_wchar_p, u, u, p, u, u, p)),
            'GetFileSizeEx': (i, (p, ctypes.POINTER(ctypes.c_int64))),
            'ReadFile': (i, (p, p, u, ctypes.POINTER(u), p)),
            'CloseHandle': (i, (p,)),
            'CryptUnprotectData': (i, (ctypes.POINTER(DataBlob), ctypes.POINTER(p), p, p, p, u, ctypes.POINTER(DataBlob))),
            'LocalFree': (p, (p,))
        }
        for name, (result, arguments) in signatures.items():
            self._api[name].restype, self._api[name].argtypes = result, arguments

    def _check(self):
        if self._thread != get_ident():
            raise QimeiRequestError('Registry20 reader requires its creator thread')

    def read(self):
        self._check()
        if self._used or self._closed:
            raise QimeiRequestBoundary('Registry20 reader entry cannot be replayed')
        self._used = True
        try:
            handle = self._api['CreateFileW'](self._path, 0x80000000, 7, None, 3, 0x80, None)
            if handle == ctypes.c_void_p(-1).value or handle is None:
                raise QimeiRequestBoundary('Registry20 existing file open failed')
            self._handle = handle
            size = ctypes.c_int64()
            if not self._api['GetFileSizeEx'](handle, ctypes.byref(size)):
                raise QimeiRequestBoundary('Registry20 file size query failed')
            if not 0 < size.value < 1 << 31:
                raise QimeiRequestBoundary('Registry20 file size leaves positive signed32 domain')
            selected = min(size.value, 4096)
            data, count = ctypes.create_string_buffer(selected), ctypes.c_uint32()
            if not self._api['ReadFile'](handle, data, selected, ctypes.byref(count), None) or count.value != selected:
                raise QimeiRequestBoundary('Registry20 requires complete source-selected read backing')
            self._read_length = selected
            source = DataBlob(selected, ctypes.cast(data, ctypes.c_void_p))
            output, description = DataBlob(), ctypes.c_void_p()
            try:
                success = self._api['CryptUnprotectData'](ctypes.byref(source), ctypes.byref(description), None, None, None, 1, ctypes.byref(output))
            finally:
                self._allocations.update(pointer for pointer in (description.value, output.pbData) if pointer)
            if not success:
                raise QimeiRequestBoundary('Registry20 DPAPI failed')
            if not output.pbData or not 20 <= output.cbData <= 4096:
                raise QimeiRequestBoundary('Registry20 DPAPI output leaves bounded typed GUID domain')
            plaintext = ctypes.string_at(output.pbData, output.cbData)
            return QimeiApplication.from_registry20_plaintext(plaintext)
        finally:
            self.close()

    def metadata(self):
        return {'used': self._used, 'closed': self._closed, 'file_handles': int(self._handle is not None),
                'local_allocations': len(self._allocations), 'selected_read_length': self._read_length}

    def close(self):
        self._check()
        if self._closed:
            return
        if self._handle is not None and self._api['CloseHandle'](self._handle):
            self._handle = None
        for pointer in tuple(self._allocations):
            if not self._api['LocalFree'](pointer):
                self._allocations.remove(pointer)
        if self._handle is not None or self._allocations:
            raise QimeiRequestBoundary('Registry20 reader retains owned file or DPAPI outputs')
        self._closed = True
