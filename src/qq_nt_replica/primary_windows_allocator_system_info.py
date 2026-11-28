import ctypes as C
import hashlib
import os
import struct
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows_crt_environment import _preserve_last_error


ALLOCATOR_SYSTEM_INFO_ROLE = 'allocator-page-granularity-v1'


class _SystemInfo(C.Structure):
    _fields_ = [('architecture', C.c_uint16), ('reserved', C.c_uint16), ('page_size', C.c_uint32),
                ('minimum_address', C.c_void_p), ('maximum_address', C.c_void_p), ('processor_mask', C.c_uint64),
                ('processor_count', C.c_uint32), ('processor_type', C.c_uint32), ('allocation_granularity', C.c_uint32),
                ('processor_level', C.c_uint16), ('processor_revision', C.c_uint16)]


def _validate_layout():
    expected = (0, 2, 4, 8, 16, 24, 32, 36, 40, 44, 46)
    if (C.sizeof(C.c_void_p), C.sizeof(_SystemInfo), C.alignment(_SystemInfo)) != (8, 48, 8) or tuple(getattr(_SystemInfo, name).offset for name, kind in _SystemInfo._fields_) != expected:
        raise PrimarySemanticUnavailable('allocator system info ABI unavailable')


def _request(session, identity, role, error):
    if (type(session) is not str or not 1 <= len(session) <= 128 or
            identity != (os.getpid(), threading.get_native_id()) or role != ALLOCATOR_SYSTEM_INFO_ROLE or
            type(error) is not int or not 0 <= error <= 0xFFFFFFFF):
        raise InputError('allocator system info requires its live owner, fixed role and known error')


class _AllocatorSystemInfoResult:
    __slots__ = ('_identity', '_session', '_effects', '_error', '_closed', '_used')

    def __init__(self, identity, session, effects, error):
        if type(effects) is not bytearray or len(effects) != 8 or type(error) is not int or not 0 <= error <= 0xFFFFFFFF:
            raise PrimarySemanticUnavailable('allocator system info sparse shape unavailable')
        self._identity, self._session, self._effects, self._error = identity, session, effects, error
        self._closed, self._used = False, False

    def __repr__(self):
        return '<private sparse allocator system info>'

    def safe_summary(self):
        page, granularity = struct.unpack('<II', self._effects)
        return dict(api='GetSystemInfo', role=ALLOCATOR_SYSTEM_INFO_ROLE, calls=1,
                    result_kind='void', native_structure_length=48, known_offsets=((4, 4), (40, 4)),
                    observed_length=8, observed_sha256=hashlib.sha256(self._effects).hexdigest(),
                    status='observed-supported-geometry' if (page, granularity) == (4096, 65536) else 'observed-unsupported-geometry')

    def _take(self, session, identity):
        if self._closed or self._used or session != self._session or identity != self._identity or identity != (os.getpid(), threading.get_native_id()):
            raise InputError('allocator system info requires its unused source owner')
        self._used = True
        return None, self._effects, self._error

    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('allocator system info close requires its owner')
        self._effects[:] = bytes(len(self._effects))
        self._effects.clear()
        self._session = self._error = None
        self._closed = True


class WindowsAllocatorSystemInfoBackend:
    @_preserve_last_error
    def __init__(self):
        _validate_layout()
        if os.name != 'nt':
            raise PrimarySemanticUnavailable('allocator system info requires Windows')
        self._identity = os.getpid(), threading.get_native_id()
        self._closed, self._calls = False, 0
        self._kernel = C.WinDLL('kernel32', handle=C.windll.kernel32._handle, use_last_error=True)
        self._bind(self._kernel)
        self._get_error, self._set_error = C.get_last_error, C.set_last_error

    @staticmethod
    def _bind(kernel):
        kernel.GetSystemInfo.argtypes, kernel.GetSystemInfo.restype = (C.POINTER(_SystemInfo),), None

    def current_identity(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('allocator system info backend requires its live owner')
        return self._identity

    @_preserve_last_error
    def capture(self, session, identity, role, last_error_before):
        _validate_layout()
        _request(session, identity, role, last_error_before)
        if self.current_identity() != identity or self._calls:
            raise InputError('allocator system info allows one observation')
        self._calls += 1
        buffer = _SystemInfo()
        saved = self._get_error()
        try:
            self._set_error(last_error_before)
            result = self._kernel.GetSystemInfo(C.byref(buffer))
            error = self._get_error() & 0xFFFFFFFF
            if result is not None or self.current_identity() != identity:
                raise PrimarySemanticUnavailable('allocator system info void or owner mismatch')
            effects = bytearray(struct.pack('<II', buffer.page_size, buffer.allocation_granularity))
            return _AllocatorSystemInfoResult(identity, session, effects, error)
        except BaseException:
            raise PrimarySemanticUnavailable('allocator system info capture unavailable') from None
        finally:
            C.memset(C.addressof(buffer), 0, C.sizeof(buffer))
            self._set_error(saved)

    @_preserve_last_error
    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('allocator system info backend close requires its owner')
        self._closed, self._kernel = True, None
        self._get_error = self._set_error = None


class WindowsAllocatorSystemInfoObservations:
    def __init__(self, session, *, backend=None, owner_identity=None):
        identity = os.getpid(), threading.get_native_id()
        if type(session) is not str or not 1 <= len(session) <= 128 or owner_identity is not None and owner_identity != identity:
            raise InputError('allocator system info requires a bounded source session and current owner')
        self._session, self._identity, self._backend = session, identity, backend
        self._closed, self._calls, self._result = False, 0, None
        self.records = []

    def __repr__(self):
        return '<private allocator system info observations>'

    def observe_allocator_system_info(self, session, identity, role, source_last_error_before):
        _request(session, identity, role, source_last_error_before)
        if self._closed or self._calls or session != self._session or identity != self._identity:
            raise InputError('allocator system info requires its unused source session')
        self._calls += 1
        try:
            if self._backend is None:
                self._backend = WindowsAllocatorSystemInfoBackend()
            if self._backend.current_identity() != identity:
                raise InputError('allocator system info backend owner mismatch')
            self._result = self._backend.capture(session, identity, role, source_last_error_before)
            if (type(self._result) is not _AllocatorSystemInfoResult or self._result._identity != identity or
                    self._result._session != session or self._backend.current_identity() != identity):
                raise InputError('allocator system info result owner mismatch')
            self.records.append(self._result.safe_summary())
            return self._result
        except BaseException:
            self.records.append(dict(api='GetSystemInfo', role=ALLOCATOR_SYSTEM_INFO_ROLE, status='unavailable'))
            raise PrimarySemanticUnavailable('allocator system info observation unavailable') from None

    def safe_summary(self):
        return dict(api='GetSystemInfo', role=ALLOCATOR_SYSTEM_INFO_ROLE, calls=self._calls, closed=self._closed,
                    scope='source-only-not-shared-model-input', model_allocator_input_alignment=False,
                    records=[dict(row) for row in self.records])

    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('allocator system info close requires its owner')
        failed = False
        for value in (self._result, self._backend):
            try:
                if value is not None:
                    value.close()
            except BaseException:
                failed = True
        self._result = self._backend = self._session = None
        self._closed = True
        if failed:
            raise PrimarySemanticUnavailable('allocator system info cleanup unavailable') from None
