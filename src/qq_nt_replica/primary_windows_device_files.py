import ctypes
import os
from pathlib import Path
import threading

from .errors import CapabilityUnavailable, InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_MASK = (1 << 64) - 1
_COUNTS = {'GetFileAttributesA': 1, 'CreateDirectoryA': 1, 'CreateFileA': 5,
           'GetFileSize': 1, 'ReadFile': 2, 'WriteFile': 2, 'CloseHandle': 1,
           'GetLastError': 0, 'CryptAcquireContextW': 4, 'CryptGenRandom': 2,
           'CryptReleaseContext': 2}


class _WindowsAPIs:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable('device file observations require Windows x64')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        p, u, b = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        pu, pp = ctypes.POINTER(u), ctypes.POINTER(p)
        signatures = (
            (kernel, 'GetFileAttributesA', u, (ctypes.c_char_p,)),
            (kernel, 'CreateDirectoryA', b, (ctypes.c_char_p, p)),
            (kernel, 'CreateFileA', p, (ctypes.c_char_p, u, u, p, u, u, p)),
            (kernel, 'GetFileSize', u, (p, pu)),
            (kernel, 'ReadFile', b, (p, p, u, pu, p)),
            (kernel, 'WriteFile', b, (p, p, u, pu, p)),
            (kernel, 'CloseHandle', b, (p,)),
            (advapi, 'CryptAcquireContextW', b, (pp, ctypes.c_wchar_p, ctypes.c_wchar_p, u, u)),
            (advapi, 'CryptGenRandom', b, (p, u, p)),
            (advapi, 'CryptReleaseContext', b, (p, u)),
        )
        self.libraries = kernel, advapi
        for library, name, result, arguments in signatures:
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            setattr(self, name, function)

    def last_error(self):
        return ctypes.get_last_error()

    def decode_ansi(self, raw):
        text = raw.decode('mbcs', 'strict')
        if text.encode('mbcs', 'strict') != raw:
            raise InputError('device path is not an exact Windows ACP roundtrip')
        return text


def _integer(value, width=32):
    value = getattr(value, 'value', value)
    if type(value) is not int:
        raise InputError('device API requires an integer native result')
    return value & ((1 << width) - 1)


class WindowsDeviceFileObservations(WorkerObservations):
    def __init__(self, storage_root, fallback, *, backend=None):
        root = Path(storage_root)
        if not root.is_absolute() or not root.is_dir():
            raise InputError('device storage requires an existing absolute owned parent')
        if root.is_symlink() or getattr(root.lstat(), 'st_file_attributes', 0) & 0x400:
            raise InputError('device storage parent cannot be a reparse point')
        self.root = root.resolve(strict=True)
        self.directory = self.root / 'xfolder'
        self._paths = {self.directory: 'directory', self.directory / 'checkpoint.dat': 'checkpoint',
                       self.directory / 'profile.dat2': 'profile'}
        self._backend = backend
        self._fallback = WorkerObservations(fallback) if callable(fallback) else fallback
        if self._fallback is not None and not isinstance(self._fallback, WorkerObservations):
            raise InputError('device fallback requires WorkerObservations')
        self._runtime = None
        self._identity = (os.getpid(), threading.get_native_id())
        self._closed = False
        self._request_active = False
        self._close_requested = False
        self._handles = {}
        self._last_error = None
        self.records = []
        self.cleanup_records = []

    @property
    def pending_handles(self):
        return tuple(self._handles)

    def _check(self, runtime):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('device observations require their live owning process and thread')
        if self._runtime is None:
            self._runtime = runtime
        elif self._runtime is not runtime:
            raise InputError('device observations require their owning runtime')

    def _api(self):
        if self._backend is None:
            self._backend = _WindowsAPIs()
        return self._backend

    def _call(self, name, *args, width=32):
        api = self._api()
        try:
            value = getattr(api, name)(*args)
            error = api.last_error()
            self._last_error = _integer(error)
            return _integer(value, width)
        except BaseException as error:
            if name in ('CreateFileA', 'CryptAcquireContextW'):
                self.cleanup_records.append({'api': name, 'completion': 'unknown', 'error': type(error).__name__})
            raise

    def _record(self, runtime, name, result, effects, *, count=0, role=None):
        row = {'api': name, 'result': result, 'last_error': self._last_error, 'count': count}
        if role is not None:
            row['role'] = role
        self.records.append(row)
        runtime.events.append(('windows.device_files', name, result, count, self._last_error))
        return result, effects

    def _path(self, raw):
        if not isinstance(raw, bytes) or not raw.endswith(b'\0') or b'\0' in raw[:-1]:
            raise InputError('device path requires one terminated ANSI string')
        try:
            text = self._api().decode_ansi(raw[:-1])
        except (UnicodeError, ValueError) as error:
            raise InputError('device path is not valid Windows ACP') from error
        candidate = Path(text)
        if (not candidate.is_absolute() or '..' in candidate.parts or
                text.startswith(('\\\\', '\\\\?')) or ':' in text[2:]):
            raise InputError('device path must stay inside its owned storage')
        canonical = candidate.resolve(strict=False)
        if canonical not in self._paths or candidate != canonical:
            raise InputError('device path is outside its exact owned file set')
        for part in (self.root, self.directory, canonical):
            try:
                status = part.lstat()
            except FileNotFoundError:
                continue
            if part.is_symlink() or getattr(status, 'st_file_attributes', 0) & 0x400:
                raise InputError('device paths cannot traverse reparse points')
        return self._paths[canonical]

    def _handle(self, kind, handle):
        if type(handle) is not int or (kind, handle) not in self._handles:
            raise InputError('device API requires its own acquired handle')
        state = self._handles[kind, handle]
        if state['release_attempted']:
            raise InputError('device handle has an unresolved release attempt')
        return state

    def _acquired(self, kind, handle, role=None, access=None):
        if not handle or handle == _MASK or (kind, handle) in self._handles:
            raise PrimarySemanticUnavailable('device API returned a null or duplicate successful handle')
        self._handles[kind, handle] = {'role': role, 'access': access, 'release_attempted': False}

    def take(self, runtime, name, arguments):
        if self._request_active:
            raise InputError('device observations cannot serve a reentrant request')
        self._request_active = True
        failed = False
        try:
            return self._take_request(runtime, name, arguments)
        except BaseException:
            failed = True
            raise
        finally:
            self._request_active = False
            if self._close_requested:
                self.close()
                if not failed:
                    raise InputError('device observations closed during an active request')

    def _take_request(self, runtime, name, arguments):
        self._check(runtime)
        active = bool(getattr(runtime, '_device_core_active', False))
        if name not in _COUNTS or name == 'GetLastError' and not active:
            if self._fallback is None:
                raise PrimarySemanticUnavailable('device observations have no fallback for ' + name)
            return self._fallback.take(runtime, name, arguments)
        if not active:
            raise InputError('device APIs require the active native device domain')
        if not isinstance(arguments, tuple) or len(arguments) != _COUNTS[name]:
            raise InputError('device API requires its canonical argument tuple: ' + name)
        args = arguments
        if name == 'GetLastError':
            if self._last_error is None:
                raise PrimarySemanticUnavailable('device domain has no immediate last-error observation')
            return self._record(runtime, name, self._last_error, b'')
        if name in ('GetFileAttributesA', 'CreateDirectoryA', 'CreateFileA'):
            role = self._path(args[0])
            if name == 'GetFileAttributesA':
                return self._record(runtime, name, self._call(name, args[0]), b'', role=role)
            if name == 'CreateDirectoryA':
                if role != 'directory':
                    raise InputError('device directory creation requires xfolder')
                return self._record(runtime, name, self._call(name, args[0], None), b'', role=role)
            expected = {(0x80000000, 1, 3, 2)}
            expected.add((0x40000000, 0, 1 if role == 'profile' else 2, 2))
            if role == 'directory' or args[1:] not in expected or any(type(value) is not int for value in args[1:]):
                raise InputError('device open arguments differ from source-owned file modes')
            value = self._call(name, args[0], args[1], args[2], None, args[3], args[4], None, width=64)
            if value != _MASK:
                self._acquired('file', value, role, args[1])
            return self._record(runtime, name, value, b'', role=role)
        if name in ('GetFileSize', 'ReadFile', 'WriteFile', 'CloseHandle'):
            state = self._handle('file', args[0])
            role = state['role']
            capacity = 50 if role == 'profile' else 1028
            if name == 'GetFileSize':
                return self._record(runtime, name, self._call(name, args[0], None), b'', role=role)
            if name == 'CloseHandle':
                return self._release(runtime, name, 'file', args[0])
            count = ctypes.c_uint32()
            if name == 'ReadFile':
                if type(args[1]) is not int or args[1] != capacity or state['access'] != 0x80000000:
                    raise InputError('device read requires its source record capacity and read handle')
                buffer = ctypes.create_string_buffer(capacity)
                result = self._call(name, args[0], buffer, capacity, ctypes.byref(count), None)
                if count.value > capacity:
                    self._record(runtime, name, result, None, count=count.value, role=role)
                    raise PrimarySemanticUnavailable('device ReadFile count exceeds its host buffer')
                if not result and count.value:
                    self._record(runtime, name, result, None, count=count.value, role=role)
                    raise PrimarySemanticUnavailable('failed device ReadFile has no proven valid partial output span')
                return self._record(runtime, name, result, (buffer.raw[:count.value], count.value), count=count.value, role=role)
            if not isinstance(args[1], bytes) or len(args[1]) != capacity or state['access'] != 0x40000000:
                raise InputError('device write requires its exact source record and write handle')
            buffer = ctypes.create_string_buffer(args[1], capacity)
            result = self._call(name, args[0], buffer, capacity, ctypes.byref(count), None)
            if count.value > capacity:
                self._record(runtime, name, result, None, count=count.value, role=role)
                raise PrimarySemanticUnavailable('device WriteFile count exceeds its input length')
            return self._record(runtime, name, result, count.value, count=count.value, role=role)
        if name == 'CryptAcquireContextW':
            if args != (0, 0, 1, 0xF0000040) or any(type(value) is not int for value in args):
                raise InputError('device entropy requires ephemeral verify-context silent acquisition')
            handle = ctypes.c_void_p()
            result = self._call(name, ctypes.byref(handle), None, None, 1, 0xF0000040)
            if result:
                self._acquired('provider', handle.value)
            effects = handle.value.to_bytes(8, 'little') if result else b''
            return self._record(runtime, name, result, effects)
        if name == 'CryptGenRandom':
            self._handle('provider', args[0])
            if type(args[1]) is not int or args[1] != 16:
                raise InputError('device entropy requests exactly sixteen bytes')
            buffer = ctypes.create_string_buffer(16)
            result = self._call(name, args[0], 16, buffer)
            return self._record(runtime, name, result, buffer.raw if result else b'', count=16 if result else 0)
        if name == 'CryptReleaseContext':
            if type(args[1]) is not int or args[1] != 0:
                raise InputError('device entropy release requires flags zero')
            self._handle('provider', args[0])
            return self._release(runtime, name, 'provider', args[0])
        raise InputError('unsupported owned device API')

    def _release(self, runtime, name, kind, handle):
        state = self._handles[kind, handle]
        state['release_attempted'] = True
        result = self._call(name, handle, 0) if kind == 'provider' else self._call(name, handle)
        if result:
            del self._handles[kind, handle]
        return self._record(runtime, name, result, b'')

    def close(self):
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('device cleanup requires its owning process and thread')
        if self._request_active:
            self._close_requested = True
            return
        if self._closed:
            return
        self._closed = True
        for (kind, handle), state in tuple(self._handles.items()):
            if state['release_attempted']:
                self.cleanup_records.append({'kind': kind, 'status': 'unresolved_prior_release'})
                continue
            state['release_attempted'] = True
            name = 'CloseHandle' if kind == 'file' else 'CryptReleaseContext'
            try:
                result = self._call(name, handle) if kind == 'file' else self._call(name, handle, 0)
            except BaseException as error:
                self.cleanup_records.append({'kind': kind, 'error': type(error).__name__})
            else:
                self.cleanup_records.append({'kind': kind, 'result': result, 'last_error': self._last_error})
                if result:
                    del self._handles[kind, handle]
