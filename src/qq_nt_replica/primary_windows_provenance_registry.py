import _ctypes
import ctypes
import os
import threading

from .errors import InputError
from .primary_device_identifiers import _key
from .primary_device_provenance import _image
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_ROOT = 0xFFFFFFFF80000001
_SUBKEY = _key('registry_subkey')
_VALUE = _key('registry_name')
_DELETE_VALUE = bytes.fromhex(_image()['delete_name_hex'])
_LIMIT = 1 << 20
_UNBOUND = object()
_HANDLE_APIS = {'RegQueryValueExA', 'RegDeleteValueA', 'RegSetValueExA', 'RegCloseKey'}


class WindowsProvenanceRegistryAPIBackend:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise PrimarySemanticUnavailable('provenance registry observations require Windows Win64')
        self._owner = os.getpid(), threading.get_native_id()
        self._closed = False
        self._handles = {}
        self.cleanup_records = []
        self._dll = ctypes.WinDLL('advapi32', use_last_error=True)

    def _check(self):
        if self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('provenance registry backend requires its open creator process and thread')

    def owns(self, handle):
        self._check()
        return type(handle) is int and handle in self._handles

    def _handle(self, handle, mode=None):
        if (type(handle) is not int or handle not in self._handles or
                mode is not None and any(value != mode for value in self._handles[handle])):
            raise InputError('provenance registry operation requires its personally acquired HKEY and source access domain')

    def _call(self, name, types, values):
        self._check()
        function = getattr(self._dll, name)
        function.restype, function.argtypes = ctypes.c_int32, types
        value = function(*values)
        if type(value) is not int:
            raise InputError('provenance registry status requires its native LONG result')
        return value & 0xFFFFFFFF

    def request(self, name, args):
        self._check()
        if type(args) is not tuple:
            raise InputError('provenance registry operations require their source tuple')
        p, u = ctypes.c_void_p, ctypes.c_uint32
        if name == 'RegOpenKeyExA':
            if (len(args) != 4 or type(args[0]) is not int or args[0] != _ROOT or type(args[1]) is not bytes or
                    args[1] != _SUBKEY or type(args[2]) is not int or args[2] != 0 or
                    type(args[3]) is not int or args[3] not in (2, 0x20019)):
                raise InputError('provenance registry open is outside its fixed source domain')
            mode = 'DELETE' if args[3] == 2 else 'READ'
            output = p()
            result = self._call(name, (p, ctypes.c_char_p, u, u, ctypes.POINTER(p)), (*args, ctypes.byref(output)))
            raw = b''
            if result == 0:
                handle = int(output.value or 0)
                if not handle:
                    raise PrimarySemanticUnavailable('successful provenance open lacks its actual HKEY')
                self._handles.setdefault(handle, []).append(mode)
                raw = handle.to_bytes(8, 'little')
            return result, raw
        if name == 'RegCreateKeyExA':
            if (len(args) != 8 or type(args[0]) is not int or args[0] != _ROOT or type(args[1]) is not bytes or
                    args[1] != _SUBKEY or any(type(value) is not int for value in args[2:]) or
                    args[2:] != (0, 0, 0, 0x20006, 0, 0)):
                raise InputError('provenance registry creation is outside its fixed source domain')
            output = p()
            result = self._call(name, (p, ctypes.c_char_p, u, p, u, u, p, ctypes.POINTER(p), p),
                (args[0], args[1], 0, None, 0, 0x20006, None, ctypes.byref(output), None))
            raw = b''
            if result == 0:
                handle = int(output.value or 0)
                if not handle:
                    raise PrimarySemanticUnavailable('successful provenance creation lacks its actual HKEY')
                self._handles.setdefault(handle, []).append('WRITE')
                raw = handle.to_bytes(8, 'little')
            return result, raw
        if name == 'RegQueryValueExA':
            if (len(args) != 5 or type(args[1]) is not bytes or args[1] != _VALUE or
                    any(type(value) is not int for value in args[2:]) or args[2:] != (0, 0, 256)):
                raise InputError('provenance registry query requires its fixed value, NULL type and capacity')
            self._handle(args[0], 'READ')
            output = ctypes.create_string_buffer(b'\xCC' * 256, 256)
            length = u(256)
            result = self._call(name, (p, ctypes.c_char_p, p, p, p, ctypes.POINTER(u)),
                (args[0], args[1], None, None, output, ctypes.byref(length)))
            if result == 0 and length.value > 256:
                raise PrimarySemanticUnavailable('successful provenance query exceeds its actual output capacity')
            return result, (output.raw[:length.value] if result == 0 else b'', length.value)
        if name == 'RegDeleteValueA':
            if len(args) != 2 or type(args[1]) is not bytes or args[1] != _DELETE_VALUE:
                raise InputError('provenance registry delete requires its fixed value name')
            self._handle(args[0], 'DELETE')
            return self._call(name, (p, ctypes.c_char_p), args), b''
        if name == 'RegSetValueExA':
            if (len(args) != 5 or type(args[1]) is not bytes or args[1] != _VALUE or
                    type(args[2]) is not int or args[2] != 0 or type(args[3]) is not int or args[3] != 1 or
                    type(args[4]) is not bytes or len(args[4]) > _LIMIT):
                raise InputError('provenance registry write requires its fixed REG_SZ source buffer')
            self._handle(args[0], 'WRITE')
            raw = args[4]
            output = ctypes.create_string_buffer(raw, len(raw)) if raw else None
            return self._call(name, (p, ctypes.c_char_p, u, u, p, u),
                (args[0], args[1], 0, 1, output, len(raw))), b''
        if name == 'RegCloseKey':
            if len(args) != 1:
                raise InputError('provenance registry close requires exactly one acquired HKEY')
            self._handle(args[0])
            result = self._call(name, (p,), args)
            if result == 0:
                self._handles[args[0]].pop()
                if not self._handles[args[0]]:
                    del self._handles[args[0]]
            return result, b''
        raise PrimarySemanticUnavailable('unsupported finite provenance registry operation: ' + name)

    def close(self):
        if self._closed:
            return
        self._check()
        errors = []
        for handle, modes in tuple(self._handles.items()):
            for unused in tuple(modes):
                try:
                    result, effects = self.request('RegCloseKey', (handle,))
                    self.cleanup_records.append(dict(api='RegCloseKey', success=result == 0))
                    if result:
                        raise PrimarySemanticUnavailable('provenance registry owner close retained its HKEY')
                except BaseException as error:
                    errors.append(error)
        if errors:
            raise BaseExceptionGroup('provenance registry resources retained', errors)
        _ctypes.FreeLibrary(self._dll._handle)
        self._dll = None
        self._closed = True

    def snapshot(self):
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('provenance registry snapshot requires its creator identity')
        return dict(closed=self._closed, HKEYs=len(self._handles), references=sum(map(len, self._handles.values())),
            libraryRetained=self._dll is not None)


class WindowsProvenanceRegistryObservations(WorkerObservations):
    def __init__(self, fallback=None, *, backend=None):
        self._owner = os.getpid(), threading.get_native_id()
        self._runtime, self._closed = _UNBOUND, False
        self._fallback, self._backend = fallback, backend
        self.records = []

    def _check(self, runtime):
        if self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('provenance registry observations require their open creator identity')
        if self._runtime is _UNBOUND:
            self._runtime = runtime
        elif self._runtime is not runtime:
            raise InputError('provenance registry observations require their unique runtime')

    def take(self, runtime, name, args):
        self._check(runtime)
        selected = (name in ('RegOpenKeyExA', 'RegCreateKeyExA') and type(args) is tuple and len(args) >= 2 and
            type(args[0]) is int and args[0] == _ROOT and type(args[1]) is bytes and args[1] == _SUBKEY)
        if name in _HANDLE_APIS and self._backend is not None and type(args) is tuple and args:
            selected = self._backend.owns(args[0])
        if not selected:
            if self._fallback is None:
                raise PrimarySemanticUnavailable('provenance registry observation is outside its fixed source domain: ' + name)
            return self._fallback.take(runtime, name, args)
        if self._backend is None:
            self._backend = WindowsProvenanceRegistryAPIBackend()
        result, effects = self._backend.request(name, args)
        self.records.append(dict(api=name, status='observed', success=result == 0))
        return result, effects

    def close(self):
        if self._closed:
            return
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('provenance registry close requires its creator identity')
        if self._backend is not None:
            self._backend.close()
        self._closed = True

    def snapshot(self):
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('provenance registry snapshot requires its creator identity')
        return dict(closed=self._closed, backend=None if self._backend is None else self._backend.snapshot(),
            records=tuple(self.records), cleanup=() if self._backend is None else tuple(self._backend.cleanup_records))
