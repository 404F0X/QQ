import _ctypes
import ctypes
import os
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows_crt_environment import _preserve_last_error
from .primary_worker import WorkerObservations


class _Timeb64(ctypes.Structure):
    _fields_ = [('time', ctypes.c_int64), ('millitm', ctypes.c_uint16),
                ('timezone', ctypes.c_int16), ('dstflag', ctypes.c_int16)]


class WindowsDeviceTimeBackend:
    @_preserve_last_error
    def __init__(self):
        self._identity = os.getpid(), threading.get_native_id()
        self._closed = False
        self._active = False
        self._library = self._function = None
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise PrimarySemanticUnavailable('device CRT time requires Windows x64')
        if (ctypes.sizeof(_Timeb64), ctypes.alignment(_Timeb64), _Timeb64.time.offset,
                _Timeb64.millitm.offset, _Timeb64.timezone.offset, _Timeb64.dstflag.offset) != (16, 8, 0, 8, 10, 12):
            raise PrimarySemanticUnavailable('device CRT time native __timeb64 ABI mismatch')
        try:
            self._library = ctypes.CDLL('ucrtbase.dll', winmode=0x800)
            self._function = self._library._ftime64_s
            self._function.restype = ctypes.c_int32
            self._function.argtypes = (ctypes.POINTER(_Timeb64),)
        except BaseException:
            self.close()
            raise

    def _check(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('device CRT time backend requires its live owning process and native thread')

    @_preserve_last_error
    def read_timeb(self):
        self._check()
        if self._active:
            raise InputError('device CRT time backend cannot serve a reentrant request')
        self._active = True
        try:
            output = _Timeb64()
            result = self._function(ctypes.byref(output))
            if type(result) is not int or not -(1 << 31) <= result < 1 << 31:
                raise PrimarySemanticUnavailable('device CRT time requires its native errno_t result')
            return result, ctypes.string_at(ctypes.byref(output), 14) if result == 0 else b''
        finally:
            self._active = False

    @_preserve_last_error
    def close(self):
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('device CRT time backend close requires its owning process and native thread')
        if self._closed:
            return
        if self._active:
            raise InputError('device CRT time backend cannot close during a request')
        if self._library is not None:
            _ctypes.FreeLibrary(self._library._handle)
            self._function = self._library = None
        self._closed = True


class WindowsDeviceTimeObservations(WorkerObservations):
    def __init__(self, *, backend=None):
        self._identity = os.getpid(), threading.get_native_id()
        self._runtime = None
        self._backend = backend
        self._closed = self._active = False
        self.records = []

    def _check(self, runtime):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('device CRT time requires its live owning process and native thread')
        if runtime is None:
            raise InputError('device CRT time requires an owning runtime')
        if self._runtime is None:
            self._runtime = runtime
        elif self._runtime is not runtime:
            raise InputError('device CRT time requires its owning runtime')

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if name != '_ftime64_s':
            raise PrimarySemanticUnavailable('unsupported device CRT time observation: ' + name)
        if type(arguments) is not tuple or arguments != ():
            raise InputError('device CRT time requires its empty source argument tuple')
        if self._active:
            raise InputError('device CRT time cannot serve a reentrant request')
        self._active = True
        try:
            if self._backend is None:
                self._backend = WindowsDeviceTimeBackend()
            result, effects = self._backend.read_timeb()
            if (type(result) is not int or not -(1 << 31) <= result < 1 << 31 or
                    type(effects) is not bytes or len(effects) != (14 if result == 0 else 0)):
                raise PrimarySemanticUnavailable('device CRT time requires native status and only valid __timeb64 fields')
        except BaseException as error:
            self.records.append({'api': name, 'status': type(error).__name__})
            raise
        finally:
            self._active = False
        self.records.append({'api': name, 'status': 'observed' if result == 0 else 'failed',
                             'result': result, 'effect_bytes': len(effects)})
        runtime.events.append(('worker.API', name, arguments, result, effects))
        return result, effects

    def close(self):
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('device CRT time close requires its owning process and native thread')
        if self._closed:
            return
        if self._active:
            raise InputError('device CRT time cannot close during a request')
        if self._backend is not None:
            self._backend.close()
        self._closed = True
