import ctypes as C
import hashlib
import os
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows_crt_environment import _preserve_last_error


ALLOCATOR_ENVIRONMENT_NAME = b'TCMALLOC_MAX_TOTAL_THREAD_CACHE_BYTES'
ALLOCATOR_ENVIRONMENT_CAPACITY = 1023
ALLOCATOR_ENVIRONMENT_ROLE = 'allocator-thread-cache-first-fixed-site-v1'
ALLOCATOR_ENVIRONMENT_ROLES = {
    ALLOCATOR_ENVIRONMENT_ROLE: (ALLOCATOR_ENVIRONMENT_NAME, 0x489ACA2, 0x1B38073, 0x1B38067, 0x1B3806E),
    'allocator-transfer-num-obj': (b'TCMALLOC_TRANSFER_NUM_OBJ', 0x489EA51, 0x1B3BE0B, 0x1B3BDFF, 0x1B3BE06),
    'allocator-aggressive-decommit': (b'TCMALLOC_AGGRESSIVE_DECOMMIT', 0x489A115, 0x1B38E9F, 0x1B38E93, 0x1B38E9A),
}


def _failure():
    return PrimarySemanticUnavailable('fixed allocator environment observation unavailable')


def _request(session, identity, role, preimage, last_error):
    if (type(session) is not str or not 1 <= len(session) <= 128 or
            identity != (os.getpid(), threading.get_native_id()) or
            type(role) is not str or role not in ALLOCATOR_ENVIRONMENT_ROLES or type(preimage) not in (bytes, bytearray) or
            len(preimage) != ALLOCATOR_ENVIRONMENT_CAPACITY or
            type(last_error) is not int or not 0 <= last_error <= 0xFFFFFFFF):
        raise InputError('fixed allocator environment requires its live owner, site and exact known preimage')


class _AllocatorEnvironmentResult:
    __slots__ = ('_identity', '_session', '_postimage', '_count', '_error', '_closed', '_used', '_role')

    def __init__(self, identity, session, count, error, postimage, role=ALLOCATOR_ENVIRONMENT_ROLE):
        if (type(count) is not int or not 0 <= count <= 0xFFFFFFFF or
                type(error) is not int or not 0 <= error <= 0xFFFFFFFF or
                type(postimage) is not bytearray or len(postimage) != ALLOCATOR_ENVIRONMENT_CAPACITY):
            raise _failure()
        if role not in ALLOCATOR_ENVIRONMENT_ROLES:
            raise _failure()
        self._role = role
        self._identity, self._session = identity, session
        self._count, self._error, self._postimage = count, error, postimage
        self._closed, self._used = False, False

    def __repr__(self):
        return '<private fixed allocator environment result>'

    def safe_summary(self):
        n = self._count
        status = ('TRUNCATED_OR_INSUFFICIENT_CAPACITY' if n >= ALLOCATOR_ENVIRONMENT_CAPACITY else
                  'zero-not-found' if n == 0 and self._error == 203 else
                  'zero-other-empty-unresolved' if n == 0 else
                  'fit' if self._postimage[n] == 0 and 0 not in self._postimage[:n] else 'invalid-fit-shape')
        return dict(api='GetEnvironmentVariableA', role=self._role,
                    name_literal_sha256=hashlib.sha256(ALLOCATOR_ENVIRONMENT_ROLES[self._role][0] + b'\0').hexdigest(),
                    capacity=ALLOCATOR_ENVIRONMENT_CAPACITY, returned_count=n, status=status,
                    observed_length=len(self._postimage), observed_sha256=hashlib.sha256(self._postimage).hexdigest())

    def _take(self, session, identity):
        if self._closed or self._used or session != self._session or identity != self._identity or identity != (os.getpid(), threading.get_native_id()):
            raise InputError('fixed allocator environment result requires its unused live owner')
        self._used = True
        return self._count, self._error, self._postimage

    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('fixed allocator environment close requires its owner')
        self._postimage[:] = bytes(len(self._postimage))
        self._postimage.clear()
        self._count = self._error = self._session = None
        self._closed = True


class WindowsAllocatorEnvironmentBackend:
    @_preserve_last_error
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise _failure()
        self._identity = os.getpid(), threading.get_native_id()
        self._closed, self._calls, self._roles = False, 0, set()
        self._kernel = C.WinDLL('kernel32', handle=C.windll.kernel32._handle, use_last_error=True)
        self._bind(self._kernel)
        process, native = C.c_uint16(), C.c_uint16()
        if not self._kernel.IsWow64Process2(self._kernel.GetCurrentProcess(), C.byref(process), C.byref(native)) or (process.value, native.value) != (0, 0x8664):
            raise _failure()
        self._get_error, self._set_error = C.get_last_error, C.set_last_error
        self.current_identity()

    @staticmethod
    def _bind(kernel):
        for name, result, arguments in (
                ('GetEnvironmentVariableA', C.c_uint32, (C.c_char_p, C.c_void_p, C.c_uint32)),
                ('GetCurrentProcess', C.c_void_p, ()),
                ('GetCurrentProcessId', C.c_uint32, ()),
                ('GetCurrentThreadId', C.c_uint32, ()),
                ('IsWow64Process2', C.c_int32, (C.c_void_p, C.POINTER(C.c_uint16), C.POINTER(C.c_uint16)))):
            function = getattr(kernel, name)
            function.restype, function.argtypes = result, arguments

    @_preserve_last_error
    def current_identity(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('fixed allocator environment backend requires its live owner')
        if (int(self._kernel.GetCurrentProcessId()), int(self._kernel.GetCurrentThreadId())) != self._identity:
            raise _failure()
        return self._identity

    @_preserve_last_error
    def capture(self, session, identity, role, preimage, last_error):
        _request(session, identity, role, preimage, last_error)
        if self.current_identity() != identity or role in self._roles or self._calls >= 3:
            raise InputError('fixed allocator environment allows one native call')
        self._calls += 1
        self._roles.add(role)
        buffer = C.create_string_buffer(bytes(preimage), ALLOCATOR_ENVIRONMENT_CAPACITY)
        saved = self._get_error()
        try:
            self._set_error(last_error)
            count = int(self._kernel.GetEnvironmentVariableA(ALLOCATOR_ENVIRONMENT_ROLES[role][0], C.addressof(buffer), ALLOCATOR_ENVIRONMENT_CAPACITY))
            error = self._get_error() & 0xFFFFFFFF
            postimage = bytearray(buffer.raw)
            if self.current_identity() != identity:
                postimage[:] = bytes(len(postimage))
                postimage.clear()
                raise _failure()
            return _AllocatorEnvironmentResult(identity, session, count, error, postimage, role)
        except BaseException:
            raise _failure() from None
        finally:
            C.memset(C.addressof(buffer), 0, ALLOCATOR_ENVIRONMENT_CAPACITY)
            self._set_error(saved)

    @_preserve_last_error
    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('fixed allocator environment backend close requires its owner')
        self._closed, self._kernel = True, None
        self._get_error = self._set_error = None


class WindowsAllocatorEnvironmentObservations:
    def __init__(self, session, *, backend=None, owner_identity=None):
        identity = os.getpid(), threading.get_native_id()
        if type(session) is not str or not 1 <= len(session) <= 128 or owner_identity is not None and owner_identity != identity:
            raise InputError('fixed allocator environment requires its current owner and session')
        self._identity, self._session, self._backend = identity, session, backend
        self._closed, self._calls, self._result = False, 0, None
        self._roles, self._results = set(), []
        self.records = []

    def __repr__(self):
        return '<private fixed allocator environment observations>'

    def observe_allocator_environment(self, session, identity, site_role, preimage1023, last_error_before):
        _request(session, identity, site_role, preimage1023, last_error_before)
        if self._closed or site_role in self._roles or self._calls >= 3 or session != self._session or identity != self._identity:
            raise InputError('fixed allocator environment requires its unused source session')
        self._calls += 1
        self._roles.add(site_role)
        try:
            if self._backend is None:
                self._backend = WindowsAllocatorEnvironmentBackend()
            if self._backend.current_identity() != identity:
                raise _failure()
            self._result = self._backend.capture(session, identity, site_role, preimage1023, last_error_before)
            self._results.append(self._result)
            if (type(self._result) is not _AllocatorEnvironmentResult or self._result._identity != identity or
                    self._result._session != session or self._result._role != site_role or self._backend.current_identity() != identity):
                raise _failure()
            self.records.append(self._result.safe_summary())
            return self._result
        except BaseException:
            self.records.append(dict(api='GetEnvironmentVariableA', role=site_role, status='unavailable'))
            raise _failure() from None

    def safe_summary(self):
        return dict(api='GetEnvironmentVariableA', calls=self._calls, role_counts={role: int(role in self._roles) for role in ALLOCATOR_ENVIRONMENT_ROLES},
                    closed=self._closed, scope='source-only-not-shared-model-input', model_allocator_input_alignment=False,
                    records=[dict(row) for row in self.records])

    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('fixed allocator environment observation close requires its owner')
        failed = False
        for value in (*self._results, self._backend):
            try:
                if value is not None:
                    value.close()
            except BaseException:
                failed = True
        self._results.clear()
        self._result = self._backend = self._session = None
        self._closed = True
        if failed:
            raise _failure() from None
