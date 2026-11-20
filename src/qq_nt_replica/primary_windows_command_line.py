import ctypes as C
import hashlib
import os
import threading
import sys

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows_crt_environment import _MemoryBasicInformation, _preserve_last_error


SUPPORTED_STRING_CAP = 0x20000
_MAX_USER = 0x7FFFFFFFFFFF
_ROLE = 'owned-process-command-line-A'


def _failure(reason):
    return PrimarySemanticUnavailable('command line observation unavailable: ' + reason)


class _CommandLineBorrow:
    __slots__ = ('_identity', '_session', '_raw', '_logical', '_pointer', '_closed', '_used')

    def __init__(self, identity, session, pointer, raw, logical):
        if (type(pointer) is not int or not 0x10000 <= pointer <= _MAX_USER or
                not isinstance(raw, bytearray) or type(logical) is not int or
                not 1 <= logical <= SUPPORTED_STRING_CAP or len(raw) < logical or
                raw[logical - 1] != 0 or 0 in raw[:logical - 1] or
                len(raw) - logical > min(15, 4096 - ((pointer + logical - 1) & 4095) - 1)):
            raise _failure('borrow-shape')
        self._identity, self._session = identity, session
        self._pointer, self._raw, self._logical = pointer, raw, logical
        self._closed, self._used = False, False

    def __repr__(self):
        return '<private owned-process command-line borrow>'

    def _guest_material(self, session, identity):
        if self._closed or self._used or session != self._session or identity != self._identity or identity != (os.getpid(), threading.get_native_id()):
            raise InputError('command line borrow requires its unused live source owner and session')
        self._used = True
        return self._raw, self._logical, self._pointer & 4095

    def _file_material(self, session, identity, runtime, owner):
        frame = sys._getframe(1)
        if (frame.f_code is not capture_file_selector.__code__ or
                frame.f_locals.get('borrow') is not self or frame.f_locals.get('owner') is not owner):
            raise InputError('file command-line pointer borrow requires its original bounded capture consumer')
        owner.source.require_capture(runtime, owner)
        raw, logical, _ = self._guest_material(session, identity)
        return self._pointer, raw, logical

    def _early_material(self,session,identity,runtime,owner):
        frame=sys._getframe(1)
        if frame.f_code is not capture_early_allocator.__code__ or frame.f_locals.get('borrow') is not self:
            raise InputError('early allocator pointer requires its original private capture consumer')
        owner.source.require_capture(runtime,owner)
        raw,logical,_=self._guest_material(session,identity)
        return self._pointer,raw,logical

    def safe_summary(self):
        return dict(api='GetCommandLineA', role=_ROLE, logical_length=self._logical,
                    logical_sha256=hashlib.sha256(self._raw[:self._logical]).hexdigest(),
                    observed_tail_length=max(0, len(self._raw) - self._logical),
                    observed_sha256=hashlib.sha256(self._raw).hexdigest(), closed=self._closed)

    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('command line borrow close requires its creating owner')
        self._raw[:] = bytes(len(self._raw))
        self._raw.clear()
        self._pointer = None
        self._session = None
        self._closed = True


class WindowsCommandLineBackend:
    @_preserve_last_error
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8 or (C.sizeof(_MemoryBasicInformation), _MemoryBasicInformation.size.offset) != (48, 24):
            raise _failure('native-AMD64-ABI')
        self._identity = os.getpid(), threading.get_native_id()
        self._closed, self._calls = False, 0
        self._kernel = C.WinDLL('kernel32', handle=C.windll.kernel32._handle, use_last_error=True)
        self._bind(self._kernel)
        self._process = int(self._kernel.GetCurrentProcess() or 0) & ((1 << 64) - 1)
        if self._process != (1 << 64) - 1:
            raise _failure('current-process-handle')
        process, native = C.c_uint16(), C.c_uint16()
        if not self._kernel.IsWow64Process2(self._process, C.byref(process), C.byref(native)) or (process.value, native.value) != (0, 0x8664):
            raise _failure('native-architecture')
        self.current_identity()

    @staticmethod
    def _bind(kernel):
        for name, result, arguments in (
                ('GetCommandLineA', C.c_void_p, ()),
                ('GetCurrentProcess', C.c_void_p, ()),
                ('GetCurrentProcessId', C.c_uint32, ()),
                ('GetCurrentThreadId', C.c_uint32, ()),
                ('IsWow64Process2', C.c_int32, (C.c_void_p, C.POINTER(C.c_uint16), C.POINTER(C.c_uint16))),
                ('VirtualQuery', C.c_size_t, (C.c_void_p, C.POINTER(_MemoryBasicInformation), C.c_size_t)),
                ('ReadProcessMemory', C.c_int32, (C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)))):
            function = getattr(kernel, name)
            function.restype, function.argtypes = result, arguments

    @_preserve_last_error
    def current_identity(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('command line backend requires its live creating owner')
        actual = int(self._kernel.GetCurrentProcessId()), int(self._kernel.GetCurrentThreadId())
        if actual != self._identity:
            raise _failure('native-owner')
        return actual

    def _query(self, address, allocation):
        self.current_identity()
        if type(address) is not int or not 0x10000 <= address <= _MAX_USER:
            raise _failure('address-range')
        info = _MemoryBasicInformation()
        if self._kernel.VirtualQuery(address, C.byref(info), C.sizeof(info)) != C.sizeof(info):
            raise _failure('query-partial')
        base, size, identity = int(info.base or 0), int(info.size), int(info.allocation_base or 0)
        if (not 0x10000 <= base <= address or size <= 0 or base + size > _MAX_USER + 1 or
                not address < base + size or not 0x10000 <= identity <= base or
                info.state != 0x1000 or info.protect & 0x100 or info.protect & 0xFF not in (2, 4, 8, 0x20, 0x40, 0x80) or
                allocation is not None and identity != allocation):
            raise _failure('mapping-or-allocation')
        return base + size, identity

    def _read(self, address, size):
        if type(size) is not int or not 1 <= size <= 16 or not 0x10000 <= address <= _MAX_USER - size + 1:
            raise _failure('read-range')
        buffer, count = C.create_string_buffer(size), C.c_size_t()
        if not self._kernel.ReadProcessMemory(self._process, address, buffer, size, C.byref(count)) or count.value != size:
            raise _failure('read-partial')
        return buffer.raw

    @_preserve_last_error
    def capture(self, session, identity):
        if self.current_identity() != identity or self._calls:
            raise InputError('command line native observation requires one matching source owner call')
        self._calls += 1
        pointer = self._kernel.GetCommandLineA()
        if type(pointer) is not int or not 0x10000 <= pointer <= _MAX_USER:
            raise _failure('null-or-invalid-result')
        raw, allocation, logical = bytearray(), None, None
        try:
            while logical is None:
                if len(raw) >= SUPPORTED_STRING_CAP:
                    raise _failure('supported-cap-without-NUL')
                address = pointer + len(raw)
                end, allocation = self._query(address, allocation)
                size = min(16, end - address, 4096 - (address & 4095), SUPPORTED_STRING_CAP - len(raw))
                if size <= 0:
                    raise _failure('supported-cap-without-NUL')
                chunk = self._read(address, size)
                raw.extend(chunk)
                position = chunk.find(b'\0')
                if position >= 0:
                    logical = len(raw) - len(chunk) + position + 1
            page_end = ((pointer + logical - 1) & ~4095) + 4096
            extent = logical + min(15, page_end - pointer - logical)
            while len(raw) < extent:
                address = pointer + len(raw)
                end, allocation = self._query(address, allocation)
                size = min(16, end - address, extent - len(raw), 4096 - (address & 4095))
                if size <= 0:
                    raise _failure('tail-range')
                raw.extend(self._read(address, size))
            del raw[extent:]
            if self.current_identity() != identity:
                raise _failure('owner-changed')
            return _CommandLineBorrow(identity, session, pointer, raw, logical)
        except BaseException:
            raw[:] = bytes(len(raw))
            raw.clear()
            raise _failure('native-capture') from None

    @_preserve_last_error
    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('command line backend close requires its creating owner')
        self._closed = True
        self._process = None
        self._kernel = None


class WindowsCommandLineObservations:
    def __init__(self, session, *, backend=None, owner_identity=None):
        identity = os.getpid(), threading.get_native_id()
        if type(session) is not str or not 1 <= len(session) <= 128 or owner_identity is not None and owner_identity != identity:
            raise InputError('command line observation requires a bounded session and current source owner')
        self._session, self._identity, self._backend = session, identity, backend
        self._closed, self._calls, self._borrow = False, 0, None
        self.records = []

    def __repr__(self):
        return '<private owned-process command-line observations>'

    def observe(self, session, identity):
        if self._closed or self._calls or session != self._session or identity != self._identity or identity != (os.getpid(), threading.get_native_id()):
            raise InputError('command line observation requires its unused live source owner and session')
        self._calls += 1
        try:
            if self._backend is None:
                self._backend = WindowsCommandLineBackend()
            if self._backend.current_identity() != self._identity:
                raise _failure('backend-owner')
            self._borrow = self._backend.capture(self._session, self._identity)
            if (type(self._borrow) is not _CommandLineBorrow or
                    self._borrow._identity != self._identity or self._borrow._session != self._session or
                    self._backend.current_identity() != self._identity):
                raise _failure('backend-result')
            self.records.append(dict(status='observed', **self._borrow.safe_summary()))
            return self._borrow
        except BaseException:
            self.records.append(dict(api='GetCommandLineA', role=_ROLE, status='unavailable'))
            raise _failure('capture') from None

    def safe_summary(self):
        return dict(api='GetCommandLineA', role=_ROLE, calls=self._calls, closed=self._closed,
                    scope='source-only-environment-input-not-model-Tape', records=[dict(row) for row in self.records])

    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('command line observation close requires its creating owner')
        failed = False
        try:
            if self._borrow is not None:
                self._borrow.close()
        except BaseException:
            failed = True
        try:
            if self._backend is not None:
                self._backend.close()
        except BaseException:
            failed = True
        finally:
            self._borrow = None
            self._backend = None
            self._session = None
            self._closed = True
        if failed:
            raise _failure('cleanup') from None


class _FileCommandLineAlias:
    def __init__(self, service, runtime, owner, pointer, raw, logical):
        frame = sys._getframe(1)
        if frame.f_code is not capture_file_selector.__code__:
            raise InputError('file alias requires its independently captured source input')
        self.parent, self.service, self.runtime, self.owner = runtime.notification_parent_observations, service, runtime, owner
        self.pointer, self.raw, self.logical = pointer, raw, logical
        self.epoch, self.identity = owner.source.epoch, (os.getpid(), threading.get_ident(), threading.get_native_id())
        self.region, self.closed = None, False
        self.region = self.validate(runtime, owner, raw, logical)

    def validate(self, runtime, owner, raw, logical):
        if (self.closed or self.runtime is not runtime or self.owner is not owner or self.raw is not raw or
                self.logical != logical or self.epoch is not owner.source.epoch or
                self.identity != (os.getpid(), threading.get_ident(), threading.get_native_id())):
            raise InputError('file command-line alias lifetime/thread/epoch changed')
        region = self.parent._file_selector_alias_region(runtime, self.service, owner, self, raw, logical)
        if self.region is not None and region is not self.region:
            raise InputError('file command-line alias region was replaced')
        return region

    def close_refs(self):
        self.closed = True
        self.parent = self.service = self.runtime = self.owner = self.raw = self.region = self.epoch = None
        self.pointer = None


def capture_file_selector(service, runtime, owner):
    """Lazy bounded capture; no generic observation records or content hashes."""
    from .primary_windows_notification_integrity import WindowsNotificationIntegrityService
    frame = sys._getframe(1)
    if (type(service) is not WindowsNotificationIntegrityService or
            frame.f_code is not WindowsNotificationIntegrityService.take.__code__ or
            frame.f_locals.get('self') is not service or frame.f_locals.get('runtime') is not runtime or
            frame.f_locals.get('name') != 'GetCommandLineA' or frame.f_locals.get('arguments') != () or
            getattr(service, '_selector_owner', None) is not owner or owner.origin != 'windows'):
        raise InputError('file command-line capture requires its actual finite service source call')
    service._check(runtime)
    from .primary_windows_notification_parent import WindowsNotificationParentObservations
    from .primary_windows_notification_environment import _ParentEnvironment
    parent = getattr(runtime, 'notification_parent_observations', None)
    if (type(parent) is not WindowsNotificationParentObservations or
            type(service.observer) is not _ParentEnvironment or parent.runtime is not runtime or
            service.observer._runtime is not runtime or service.observer.parent is not parent.parent or
            service.observer.owner is not parent.owner):
        raise InputError('selector capture lacks its actual matching facade and installed parent source')
    parent._installed(runtime)
    parent._parent_source()
    owner.source.require_capture(runtime, owner)
    session, identity = 'file-selector-capture', (os.getpid(), threading.get_native_id())
    backend = WindowsCommandLineBackend()
    borrow = None
    alias = None
    transferred = False
    try:
        borrow = backend.capture(session, identity)
        pointer, raw, logical = borrow._file_material(session, identity, runtime, owner)
        if any(type(entry) is tuple and len(entry) == 2 and entry[0] == pointer for entry in parent.regions):
            alias = _FileCommandLineAlias(service, runtime, owner, pointer, raw, logical)
        def release():
            try:
                borrow.close()
            finally:
                backend.close()
        owner.source.accept_input(runtime, owner, pointer, raw, logical, release, alias)
        transferred = True
        return pointer
    finally:
        if not transferred:
            if alias is not None:
                alias.close_refs()
            try:
                if borrow is not None:
                    borrow.close()
            finally:
                backend.close()


def capture_early_allocator(issuer,owner):
    """One private native borrow, no public summary/hash observation."""
    from .primary_windows_allocator_issuer import WindowsAllocatorIssuer
    frame=sys._getframe(1)
    if type(issuer) is not WindowsAllocatorIssuer or frame.f_code is not WindowsAllocatorIssuer.capture.__code__ or frame.f_locals.get('self') is not issuer:
        raise InputError('early capture requires its original source issuer')
    issuer.validate();issuer.source.require_capture(issuer.runtime,owner)
    session=object();identity=(os.getpid(),threading.get_native_id())
    backend=WindowsCommandLineBackend();borrow=None;transferred=False
    try:
        borrow=backend.capture(session,identity)
        pointer,raw,logical=borrow._early_material(session,identity,issuer.runtime,owner)
        def release():
            try:borrow.close()
            finally:backend.close()
        transferred=True
        return pointer,raw,logical,release
    finally:
        if not transferred:
            try:
                if borrow is not None:borrow.close()
            finally:backend.close()
