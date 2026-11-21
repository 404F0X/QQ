import ctypes
import os
import threading

from .errors import InputError
from .primary_windows_system_records import WindowsSystemRecordAPIBackend
from .primary_worker import WorkerObservations


_ROOT = 0xFFFFFFFF80000001
_PATH = b'SOFTWARE\\Tencent\\QQProtect'
_READ, _DELETE, _WRITE = 0x20019, 2, 0x20006
_MASK = (1 << 64) - 1
_LIMIT = 1 << 20
_NAMES = frozenset(('RegOpenKeyExA', 'RegQueryValueExA', 'RegDeleteValueA',
    'RegCreateKeyExA', 'RegSetValueExA', 'RegCloseKey'))


def _validate(name, args, handles, *, native=False):
    valid = type(args) is tuple
    if valid and name == 'RegOpenKeyExA':
        valid = (len(args) == 4 and type(args[0]) is int and args[:2] == (_ROOT, _PATH) and
            type(args[1]) is bytes and type(args[2]) is int and args[2] == 0 and
            type(args[3]) is int and args[3] in (_READ, _DELETE))
    elif valid and name == 'RegCreateKeyExA':
        valid = (args == (_ROOT, _PATH, 0, 0, 0, _WRITE, 0, 0) and
            all(type(value) is int for index, value in enumerate(args) if index != 1) and type(args[1]) is bytes)
    elif valid and name in ('RegDeleteValueA', 'RegSetValueExA', 'RegQueryValueExA', 'RegCloseKey'):
        valid = len(args) > 0 and type(args[0]) is int and args[0] in handles
        if valid and name == 'RegCloseKey':
            valid = len(args) == 1
        elif valid and name == 'RegDeleteValueA':
            valid = args[1:] == (b'installStatus',) and type(args[1]) is bytes and handles[args[0]] == _DELETE
        elif valid and name == 'RegQueryValueExA':
            valid = (args[1:] == ((b'installFlag', 0, 256) if native else (b'installFlag', 0, 0, 256)) and
                type(args[1]) is bytes and all(type(value) is int for value in args[2:]) and handles[args[0]] == _READ)
        elif valid:
            valid = (len(args) == 5 and args[1:4] == (b'installFlag', 0, 1) and type(args[1]) is bytes and
                type(args[2]) is int and type(args[3]) is int and handles[args[0]] == _WRITE and
                type(args[4]) is bytes and 1 <= len(args[4]) <= _LIMIT and args[4][-1:] == b'\0')
    else:
        valid = False
    if not valid:
        raise InputError('registry API is outside its explicitly enabled QQProtect source contract: ' + name)


def _status(result, error):
    if type(result) is not int or not 0 <= result <= 0xFFFFFFFF or type(error) is not int or not 0 <= error <= 0xFFFFFFFF:
        raise InputError('QQProtect registry requires unsigned LSTATUS and captured DWORD last-error')


def _handle(effects):
    if type(effects) is not tuple or len(effects) != 1 or type(effects[0]) is not bytes or len(effects[0]) != 8:
        raise InputError('QQProtect registry requires its exact Win64 HKEY output')
    pointer = int.from_bytes(effects[0], 'little')
    if not 0 < pointer <= _MASK or pointer == _ROOT:
        raise InputError('QQProtect registry returned an invalid owned HKEY')
    return pointer


class WindowsProtectionRegistryAPIBackend(WindowsSystemRecordAPIBackend):
    def __init__(self, *, allow_qqprotect_registry=False):
        if allow_qqprotect_registry is not True:
            raise InputError('QQProtect registry native backing requires explicit scoped opt-in')
        super().__init__()
        self._protection_handles = {}

    def request(self, name, args):
        self._check()
        _validate(name, args, self._protection_handles, native=True)
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        if name == 'RegCreateKeyExA':
            output = p()
            value, error = self._call('advapi32', name, i, (p, ctypes.c_char_p, u, p, u, u, p, ctypes.POINTER(p), p),
                (*args[:7], ctypes.byref(output), args[7]))
            result, effects = value & 0xFFFFFFFF, ((int(output.value or 0).to_bytes(8, 'little') if not value else b''),)
            if not result:
                self._keys.add(int(output.value or 0))
        elif name == 'RegSetValueExA':
            data = ctypes.create_string_buffer(args[4], len(args[4]))
            value, error = self._call('advapi32', name, i, (p, ctypes.c_char_p, u, u, p, u),
                (*args[:4], data, len(args[4])))
            result, effects = value & 0xFFFFFFFF, b''
        elif name == 'RegDeleteValueA':
            value, error = self._call('advapi32', name, i, (p, ctypes.c_char_p), args)
            result, effects = value & 0xFFFFFFFF, b''
        elif name == 'RegQueryValueExA':
            handle, key, reserved, capacity = args
            output, length = self._buffer(capacity), u(capacity)
            value, error = self._call('advapi32', name, i, (p, ctypes.c_char_p, p, p, p, ctypes.POINTER(u)),
                (handle, key, None, None, output, ctypes.byref(length)))
            result = value & 0xFFFFFFFF
            if result == 0 and length.value > capacity:
                raise InputError('QQProtect registry query success exceeds its actual native buffer')
            effects = (b'', output.raw[:length.value] if result == 0 else b'', bytes(length) if result in (0, 234) else b'')
        else:
            result, effects, error = super().request(name, args)
        _status(result, error)
        if name in ('RegOpenKeyExA', 'RegCreateKeyExA') and result == 0:
            handle = _handle(effects)
            if handle in self._protection_handles:
                raise InputError('QQProtect native HKEY aliases another owned handle')
            self._protection_handles[handle] = args[3] if name == 'RegOpenKeyExA' else _WRITE
        elif name == 'RegCloseKey' and result == 0:
            del self._protection_handles[args[0]]
        return result, effects, error


class WindowsProtectionRegistryObservations(WorkerObservations):
    def __init__(self, *, allow_qqprotect_registry=False, backend=None):
        if allow_qqprotect_registry is not True:
            raise InputError('QQProtect registry observations require explicit scoped opt-in')
        self._identity = os.getpid(), threading.get_native_id()
        self._runtime = None
        self._bound = self._closed = False
        self._backend = backend
        self._handles = {}
        self.records = []

    def handles(self, name, args):
        if name in ('RegCreateKeyExA', 'RegSetValueExA', 'RegDeleteValueA'):
            return True
        if name == 'RegOpenKeyExA':
            return type(args) is tuple and len(args) >= 2 and args[0:2] == (_ROOT, _PATH)
        return name in _NAMES and type(args) is tuple and len(args) > 0 and type(args[0]) is int and args[0] in self._handles

    def _check(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('QQProtect registry observations require their creator process and native thread')

    def take(self, runtime, name, arguments):
        self._check()
        if self._bound and self._runtime is not runtime:
            raise InputError('QQProtect registry observations require their original runtime')
        _validate(name, arguments, self._handles)
        self._runtime, self._bound = runtime, True
        if self._backend is None:
            self._backend = WindowsProtectionRegistryAPIBackend(allow_qqprotect_registry=True)
        native_args = (arguments[0], arguments[1], arguments[2], arguments[4]) if name == 'RegQueryValueExA' else arguments
        result, effects, error = self._backend.request(name, native_args)
        _status(result, error)
        if name in ('RegOpenKeyExA', 'RegCreateKeyExA'):
            if result == 0:
                handle = _handle(effects)
                if handle in self._handles:
                    raise InputError('QQProtect HKEY aliases another source-owned handle')
                self._handles[handle] = arguments[3] if name == 'RegOpenKeyExA' else _WRITE
                effects = effects[0]
            elif effects != (b'',):
                raise InputError('failed QQProtect registry opening has no valid HKEY output')
            else:
                effects = b''
        elif name == 'RegQueryValueExA':
            if type(effects) is not tuple or len(effects) != 3 or any(type(value) is not bytes for value in effects):
                raise InputError('QQProtect query requires raw type, buffer and DWORD length outputs')
            kind, data, length = effects
            if kind:
                raise InputError('QQProtect source query has a NULL type output pointer')
            if result == 0:
                if len(length) != 4 or len(data) != int.from_bytes(length, 'little') or len(data) > 256:
                    raise InputError('QQProtect query success exceeds its exact source output bounds')
            elif result == 234:
                if kind or data or len(length) != 4:
                    raise InputError('QQProtect query size failure requires only its DWORD length output')
            elif effects != (b'', b'', b''):
                raise InputError('failed QQProtect query has no valid output effects')
            effects = data, int.from_bytes(length, 'little') if length else 256
        else:
            if type(effects) is not bytes or effects:
                raise InputError('QQProtect mutation or close has no output buffer')
            if name == 'RegCloseKey' and result == 0:
                del self._handles[arguments[0]]
        self.records.append({'api': name, 'status': 'observed', 'result': result, 'error': error})
        return result, effects

    def close(self):
        if self._closed:
            return
        self._check()
        if self._backend is not None:
            self._backend.close()
        self._handles.clear()
        self._closed = True

    def snapshot(self):
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('QQProtect registry snapshot requires its creator identity')
        return {'closed': self._closed, 'source_registry_handles': len(self._handles),
            'records': tuple(self.records),
            'backend': self._backend.snapshot() if self._backend is not None and hasattr(self._backend, 'snapshot') else None}
