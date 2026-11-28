from collections.abc import Mapping
import ctypes as C
from dataclasses import dataclass
import hashlib
import ntpath
import os
from pathlib import PureWindowsPath
import secrets
import struct
import threading
from types import MappingProxyType

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


WRAPPER_PATH = 'D:/QQ/versions/9.9.33-52230/resources/app/wrapper.node'
WRAPPER_SHA256 = '63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'
IMAGE_SIZE = 0x7419000
GUEST_BASE = 0x180000000
LOADER_EVIDENCE_SHA256 = '14fb3fc70983c85d1a67d27ee657ceec396d4d011bcf05dce5449aac15ae31e9'
LOADER_HASHES = (
    ('ntdll.dll', '651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c'),
    ('kernelbase.dll', '5c29b73622ce0976e1ada566f31f2197ba0f8beaea89c3ec033366126172c3d0'),
    ('kernel32.dll', 'e132eba4166256e2f414b91fe7d5386590bc5ea8626aee5af9c9738383cf2ae1'))
LOADER_9974_EVIDENCE_SHA256 = '758bd9e47077c7ccc81c874583ce219123dc722fcf781c5c75e10933ff851f39'
LOADER_9974_HASHES = (
    ('ntdll.dll', 'a0f81bf5c610c0ff0a550adc020a58446f214790c748057bb575042e972e6a34'),
    ('kernelbase.dll', '9eb6768c3020992f8f616f7edfead6254dd6d4c6042d1468d790ec3004cb4bbc'),
    ('kernel32.dll', '970e5e15eed7d53c8b88e06ddc71884c31804f1cb5286abf01fbce39b7f0e29f'))
LOADER_PROFILES = MappingProxyType({
    '10.0.26100.9711': (LOADER_HASHES, LOADER_EVIDENCE_SHA256),
    '10.0.26100.9974': (LOADER_9974_HASHES, LOADER_9974_EVIDENCE_SHA256)})
_MODULE_LOCK = threading.Lock()


@dataclass(frozen=True)
class OwnImageModuleSpec:
    schema_version: int = 1
    role: str = 'wrapper-own-image'
    path: str = WRAPPER_PATH
    sha256: str = WRAPPER_SHA256
    size_of_image: int = IMAGE_SIZE
    guest_base: int = GUEST_BASE
    rva: int = 0
    windows_version: str = '10.0.26100.9711'
    loader_evidence_sha256: str = LOADER_EVIDENCE_SHA256
    loader_pe_sha256: tuple = LOADER_HASHES

    @staticmethod
    def for_loader_profile(label):
        if type(label) is not str or label not in LOADER_PROFILES:
            raise InputError('own-image loader profile is not a reviewed curated selection')
        hashes, evidence = LOADER_PROFILES[label]
        return OwnImageModuleSpec(windows_version=label, loader_pe_sha256=hashes,
                                  loader_evidence_sha256=evidence)

    def __post_init__(self):
        expected = (1, 'wrapper-own-image', WRAPPER_PATH, WRAPPER_SHA256, IMAGE_SIZE, GUEST_BASE, 0)
        actual = tuple(getattr(self, key) for key in self.__dataclass_fields__)[:7]
        profile = (self.windows_version, self.loader_pe_sha256, self.loader_evidence_sha256)
        admitted = tuple((label, hashes, evidence) for label, (hashes, evidence) in LOADER_PROFILES.items())
        if (actual != expected or profile not in admitted or
                type(self.windows_version) is not str or type(self.loader_evidence_sha256) is not str or
                type(self.loader_pe_sha256) is not tuple or
                any(type(row) is not tuple or len(row) != 2 or
                    any(type(value) is not str for value in row) for row in self.loader_pe_sha256) or
                any(type(getattr(self, key)) is not int for key in
                    ('schema_version', 'size_of_image', 'guest_base', 'rva'))):
            raise InputError('own-image specification must match the fixed admitted image and loader evidence')


def _freeze_capability(value, api):
    def keys(item, expected):
        if not isinstance(item, Mapping) or set(item) != set(expected):
            raise InputError('own-image capability fields differ from schema1')
    def integer(item, minimum, maximum):
        return type(item) is int and minimum <= item <= maximum
    def hexvalue(item, length):
        return type(item) is str and len(item) == length and all(c in '0123456789abcdef' for c in item)
    keys(value, ('schema_version', 'kind', 'api', 'logical_role', 'guest_identity', 'native_identity', 'owner', 'load'))
    guest, native, owner, load = (value[key] for key in ('guest_identity', 'native_identity', 'owner', 'load'))
    keys(guest, ('base', 'rva', 'sha256', 'size_of_image'))
    keys(native, ('hmodule', 'image_base', 'size_of_image', 'file_id', 'file_sha256'))
    keys(native['file_id'], ('volume_serial', 'file_id'))
    keys(owner, ('process_id', 'thread_id', 'session_id', 'runtime_binding'))
    keys(load, ('flags', 'hfile', 'reference_kind', 'state', 'fresh_not_reused', 'loader_evidence_sha256'))
    if (type(value['schema_version']) is not int or value['schema_version'] != 1 or
            value['kind'] != 'native-ownimage-relocation' or value['api'] != api or
            value['logical_role'] != 'wrapper-own-image' or
            guest != dict(base=GUEST_BASE, rva=0, sha256=WRAPPER_SHA256, size_of_image=IMAGE_SIZE) or
            any(type(guest[key]) is not int for key in ('base', 'rva', 'size_of_image')) or
            not integer(native['hmodule'], 1, (1 << 64) - 1) or
            type(native['image_base']) is not int or native['image_base'] != native['hmodule'] or
            type(native['size_of_image']) is not int or native['size_of_image'] != IMAGE_SIZE or
            native['file_sha256'] != WRAPPER_SHA256 or
            not integer(native['file_id']['volume_serial'], 0, (1 << 64) - 1) or
            not hexvalue(native['file_id']['file_id'], 32) or
            not integer(owner['process_id'], 1, 0xFFFFFFFF) or not integer(owner['thread_id'], 1, 0xFFFFFFFF) or
            not hexvalue(owner['session_id'], 32) or not hexvalue(owner['runtime_binding'], 32) or
            type(load['flags']) is not int or load['flags'] != 1 or type(load['hfile']) is not int or load['hfile'] != 0 or
            load['reference_kind'] != 'one owned LoadLibraryExW reference' or load['state'] != 'open' or
            load['fresh_not_reused'] is not True or load['loader_evidence_sha256'] not in
            tuple(evidence for hashes, evidence in LOADER_PROFILES.values())):
        raise InputError('own-image capability identity is outside the fixed admitted domain')
    def freeze(item):
        return MappingProxyType({key: freeze(data) for key, data in item.items()}) if isinstance(item, Mapping) else item
    return freeze(value)


def freeze_capability(value):
    return _freeze_capability(value, 'GetModuleFileNameA')


def freeze_w_capability(value):
    return _freeze_capability(value, 'GetModuleFileNameW')


validate_snapshot = freeze_capability
validate_w_snapshot = freeze_w_capability


class _ModuleInformation(C.Structure):
    _fields_ = [('base', C.c_void_p), ('size', C.c_uint32), ('entry', C.c_void_p)]


class _NativeBackend:
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise PrimarySemanticUnavailable('own-image native mapping requires Windows AMD64')
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.files = set()
        self.failed_file_closes = set()

    def _call(self, name, result, types, *arguments):
        function = getattr(self.kernel, name)
        function.restype, function.argtypes = result, types
        return function(*arguments)

    def _require(self, result, operation):
        if not result:
            raise PrimarySemanticUnavailable('own-image native metadata operation failed: ' + operation)
        return result

    def _path(self, handle):
        buffer = C.create_unicode_buffer(32768)
        length = self._call('GetFinalPathNameByHandleW', C.c_uint32,
                            (C.c_void_p, C.c_void_p, C.c_uint32, C.c_uint32), handle, buffer, len(buffer), 0)
        if not 0 < length < len(buffer):
            raise PrimarySemanticUnavailable('own-image final file path is unavailable or truncated')
        path = buffer.value
        return path[4:] if path.startswith('\\\\?\\') else path

    def _identity(self, handle):
        buffer = (C.c_ubyte * 24)()
        self._require(self._call('GetFileInformationByHandleEx', C.c_int32,
                                (C.c_void_p, C.c_int, C.c_void_p, C.c_uint32), handle, 18, buffer, 24), 'FileIdInfo')
        raw = bytes(buffer)
        return {'volume_serial': int.from_bytes(raw[:8], 'little'), 'file_id': raw[8:].hex()}

    def open_file(self, path, *, pinned):
        if pinned:
            for candidate in (PureWindowsPath(path), *PureWindowsPath(path).parents):
                attributes = self._call('GetFileAttributesW', C.c_uint32, (C.c_wchar_p,), str(candidate))
                if attributes == 0xFFFFFFFF or attributes & 0x400:
                    raise PrimarySemanticUnavailable('own-image pinned path is unavailable or traverses a reparse point')
        handle = self._call('CreateFileW', C.c_void_p,
                            (C.c_wchar_p, C.c_uint32, C.c_uint32, C.c_void_p, C.c_uint32, C.c_uint32, C.c_void_p),
                            str(path), 0x80000000 if pinned else 0x80, 1 if pinned else 7, None, 3, 0x200000, None)
        if not handle or handle == C.c_void_p(-1).value:
            raise PrimarySemanticUnavailable('own-image stable file open failed')
        self.files.add(handle)
        return handle

    def inspect_file(self, handle):
        size = C.c_int64()
        self._require(self._call('GetFileSizeEx', C.c_int32, (C.c_void_p, C.c_void_p), handle, C.byref(size)), 'file size')
        if not 0 < size.value <= 1 << 30:
            raise PrimarySemanticUnavailable('own-image file size is outside the bounded metadata domain')
        digest, total, header = hashlib.sha256(), 0, b''
        buffer, read = C.create_string_buffer(1 << 20), C.c_uint32()
        while total < size.value:
            count = min(len(buffer), size.value - total)
            self._require(self._call('ReadFile', C.c_int32,
                                    (C.c_void_p, C.c_void_p, C.c_uint32, C.c_void_p, C.c_void_p),
                                    handle, buffer, count, C.byref(read), None), 'stable file read')
            if not 0 < read.value <= count:
                raise PrimarySemanticUnavailable('own-image stable file read was incomplete')
            raw = buffer.raw[:read.value]
            digest.update(raw)
            header = (header + raw)[:4096]
            total += read.value
        return {'sha256': digest.hexdigest(), 'file_id': self._identity(handle),
                'path': self._path(handle), 'header': header, 'length': total}

    def close_file(self, handle):
        if handle in self.failed_file_closes:
            return False
        success = bool(self._call('CloseHandle', C.c_int32, (C.c_void_p,), handle))
        if success:
            self.files.remove(handle)
        else:
            self.failed_file_closes.add(handle)
        return success

    def _module_path(self, handle):
        buffer = C.create_unicode_buffer(32768)
        count = self._call('K32GetModuleFileNameExW', C.c_uint32,
                           (C.c_void_p, C.c_void_p, C.c_void_p, C.c_uint32), C.c_void_p(-1), handle, buffer, len(buffer))
        if not 0 < count < len(buffer):
            raise PrimarySemanticUnavailable('own-image registered module path is unavailable or truncated')
        return buffer.value

    def check_environment(self, spec):
        directory = C.create_unicode_buffer(32768)
        length = self._call('GetSystemDirectoryW', C.c_uint32, (C.c_void_p, C.c_uint32), directory, len(directory))
        if not 0 < length < len(directory):
            raise PrimarySemanticUnavailable('own-image Windows system directory is unavailable')
        for name, digest in spec.loader_pe_sha256:
            module = self._call('GetModuleHandleW', C.c_void_p, (C.c_wchar_p,), name)
            self._require(module, 'pinned loader module')
            path = ntpath.join(directory.value, name)
            if ntpath.normcase(self._module_path(module)) != ntpath.normcase(path):
                raise PrimarySemanticUnavailable('own-image loaded Windows module path differs from pinned system file')
            handle = self.open_file(path, pinned=True)
            try:
                if self.inspect_file(handle)['sha256'] != digest:
                    raise PrimarySemanticUnavailable('own-image Windows loader file hash differs from pinned evidence')
            finally:
                if not self.close_file(handle):
                    raise PrimarySemanticUnavailable('own-image loader evidence file close failed')

    def modules(self):
        handles, required = (C.c_void_p * 4096)(), C.c_uint32()
        self._require(self._call('K32EnumProcessModulesEx', C.c_int32,
                                (C.c_void_p, C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32),
                                C.c_void_p(-1), handles, C.sizeof(handles), C.byref(required), 3), 'module enumeration')
        if required.value > C.sizeof(handles) or required.value % C.sizeof(C.c_void_p):
            raise PrimarySemanticUnavailable('own-image module enumeration is incomplete')
        rows = []
        for module in handles[:required.value // C.sizeof(C.c_void_p)]:
            if not module:
                raise PrimarySemanticUnavailable('own-image module enumeration contains an invalid handle')
            path = self._module_path(module)
            handle = self.open_file(path, pinned=False)
            try:
                rows.append({'hmodule': module, 'name': ntpath.basename(path).lower(), 'file_id': self._identity(handle)})
            finally:
                if not self.close_file(handle):
                    raise PrimarySemanticUnavailable('own-image enumerated module file close failed')
        return tuple(rows)

    def load(self):
        return int(self._call('LoadLibraryExW', C.c_void_p,
                              (C.c_wchar_p, C.c_void_p, C.c_uint32), WRAPPER_PATH, None, 1) or 0)

    def mapping(self, handle):
        info, read, header = _ModuleInformation(), C.c_size_t(), C.create_string_buffer(4096)
        self._require(self._call('K32GetModuleInformation', C.c_int32,
                                (C.c_void_p, C.c_void_p, C.c_void_p, C.c_uint32),
                                C.c_void_p(-1), handle, C.byref(info), C.sizeof(info)), 'registered image metadata')
        self._require(self._call('ReadProcessMemory', C.c_int32,
                                (C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p),
                                C.c_void_p(-1), handle, header, 4096, C.byref(read)), 'registered PE header')
        if read.value != 4096:
            raise PrimarySemanticUnavailable('own-image mapped PE header read is incomplete')
        path = self._module_path(handle)
        file = self.open_file(path, pinned=False)
        try:
            return {'base': info.base, 'size_of_image': info.size, 'header': header.raw,
                    'path': self._path(file), 'file_id': self._identity(file)}
        finally:
            if not self.close_file(file):
                raise PrimarySemanticUnavailable('own-image mapped identity file close failed')

    def release(self, handle):
        return bool(self._call('FreeLibrary', C.c_int32, (C.c_void_p,), handle))


def _image_size(header):
    if len(header) != 4096 or header[:2] != b'MZ':
        raise PrimarySemanticUnavailable('own-image PE header identity is invalid')
    offset = struct.unpack_from('<I', header, 0x3C)[0]
    if not 0x40 <= offset <= len(header) - 0x100 or header[offset:offset + 4] != b'PE\0\0':
        raise PrimarySemanticUnavailable('own-image PE header offset is outside its bounded metadata')
    if (struct.unpack_from('<H', header, offset + 4)[0] != 0x8664 or
            not struct.unpack_from('<H', header, offset + 22)[0] & 0x2000 or
            struct.unpack_from('<H', header, offset + 24)[0] != 0x20B):
        raise PrimarySemanticUnavailable('own-image requires the fixed AMD64 DLL image')
    return struct.unpack_from('<I', header, offset + 24 + 56)[0]


def _headers_size(header):
    _image_size(header)
    offset = struct.unpack_from('<I', header, 0x3C)[0]
    size = struct.unpack_from('<I', header, offset + 24 + 60)[0]
    if not offset + 24 + 0x70 <= size <= len(header):
        raise PrimarySemanticUnavailable('own-image PE SizeOfHeaders is outside its bounded metadata')
    return size


def _loaded_header_expected(pinned, actual_base):
    span = _headers_size(pinned)
    field = struct.unpack_from('<I', pinned, 0x3C)[0] + 24 + 24
    if (span != 0x400 or field != 0xA8 or not 0 <= field <= span - 8 or
            type(actual_base) is not int or not 0 < actual_base < 1 << 64):
        raise PrimarySemanticUnavailable('own-image loaded header transformation requires the fixed ImageBase span and owned base')
    expected = bytearray(pinned[:span])
    expected[field:field + 8] = actual_base.to_bytes(8, 'little')
    return bytes(expected)


class _NotificationLoadedView:
    def __init__(self, provider, runtime, owner):
        self.provider, self.runtime, self.owner = provider, runtime, owner
        self.session, self.binding = provider._session, provider._binding
        self.module, self.identity = provider._hmodule, provider._pinned
        self.closed = False

    def check(self, runtime):
        provider = self.provider
        if (self.closed or runtime is not self.runtime or not self.owner.valid() or
                provider._state != 'open' or provider._released or provider._runtime is not runtime or
                provider._session != self.session or provider._binding != self.binding or
                provider._hmodule != self.module or provider._pinned is not self.identity or
                provider._owner[0] != os.getpid()):
            raise PrimarySemanticUnavailable('notification borrowed image view is stale')

    def source_address(self, runtime, rva):
        self.check(runtime)
        if rva != 0x3E91B50:
            raise InputError('notification image view only relocates its fixed critical pointer')
        return self.module + rva

    def filename_w_relocation(self, runtime, arguments, capability):
        import sys
        from .primary_windows_notification_integrity import WindowsNotificationIntegrityService
        self.check(runtime)
        claim = runtime._primary_direct_scope.require_parent_phase()
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not WindowsNotificationIntegrityService.module_api.__code__:
            frame = frame.f_back
        service = None if frame is None else frame.f_locals.get('self')
        if (claim.owner is not self.owner or capability is not self or
                type(arguments) is not tuple or arguments != (GUEST_BASE, 260) or
                any(type(value) is not int for value in arguments) or
                type(service) is not WindowsNotificationIntegrityService or service._active != 0x35B3FE0 or
                service._stage != 'filename' or service.observer._provider is not self or
                frame.f_locals.get('runtime') is not runtime or frame.f_locals.get('name') != 'GetModuleFileNameW' or
                frame.f_locals.get('arguments') != arguments):
            raise InputError('notification filename relocation requires its live parent and fixed W source ABI')
        return (self.module, 260), self

    def close(self):
        self.closed = True
        self.provider = self.runtime = self.owner = self.identity = None
        self.module = self.session = self.binding = None


class _ConstructorLoadedView:
    def __init__(self, provider, runtime, owner, capability):
        self.provider, self.runtime, self.owner = provider, runtime, owner
        self.capability = freeze_w_capability(capability)
        self.session, self.binding = provider._session, provider._binding
        self.module, self.identity = provider._hmodule, provider._pinned
        self.spec = provider.spec
        self.closed = False
        self.check(runtime)

    def check(self, runtime):
        provider, capability = self.provider, self.capability
        if (self.closed or runtime is not self.runtime or not self.owner.valid() or
                runtime._primary_direct_scope.require_constructor_phase().owner is not self.owner or
                provider._state != 'open' or provider._released or provider._runtime is not runtime or
                provider._session != self.session or provider._binding != self.binding or
                provider._hmodule != self.module or provider._pinned is not self.identity or
                provider.spec is not self.spec or type(self.spec) is not OwnImageModuleSpec or
                provider._owner[0] != os.getpid() or runtime.image_base != GUEST_BASE or
                capability['native_identity']['hmodule'] != self.module or
                capability['native_identity']['file_id'] != self.identity['file_id'] or
                self.identity['sha256'] != WRAPPER_SHA256 or
                ntpath.normcase(self.identity['path']) != ntpath.normcase(provider.spec.path) or
                capability['owner']['process_id'] != provider._owner[0] or
                capability['owner']['thread_id'] != provider._owner[1] or
                capability['owner']['session_id'] != self.session or
                capability['owner']['runtime_binding'] != self.binding):
            raise PrimarySemanticUnavailable('notification constructor borrowed W view is stale')

    def filename_w_relocation(self, runtime, arguments, capability):
        import sys
        from .primary_notification_environment import _observe
        self.check(runtime)
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not _observe.__code__:
            frame = frame.f_back
        if (capability is not self or type(arguments) is not tuple or arguments != (GUEST_BASE, 260) or
                any(type(value) is not int for value in arguments) or frame is None or
                frame.f_locals.get('runtime') is not runtime or frame.f_locals.get('name') != 'GetModuleFileNameW' or
                frame.f_locals.get('arguments') != arguments):
            raise InputError('notification constructor W relocation requires its exact source arguments')
        return (self.module, 260), self

    def close(self):
        self.closed = True
        self.provider = self.runtime = self.owner = self.identity = self.capability = None
        self.spec = None
        self.module = self.session = self.binding = None


class _ModuleCollectorLoadedView:
    def __init__(self, provider, runtime, owner, capability):
        from .primary_notification_modules import require_claim
        self.provider, self.runtime, self.owner = provider, runtime, owner
        self.claim = require_claim(runtime)
        self.capability = freeze_capability(capability)
        self.session, self.binding = provider._session, provider._binding
        self.module, self.identity, self.spec = provider._hmodule, provider._pinned, provider.spec
        self.worker = os.getpid(), threading.get_native_id()
        self.closed = False
        self.check(runtime)

    def check(self, runtime):
        from .primary_notification_modules import require_claim
        provider, capability = self.provider, self.capability
        if (self.closed or runtime is not self.runtime or self.worker != (os.getpid(), threading.get_native_id()) or
                require_claim(runtime) is not self.claim or self.claim.owner is not self.owner or not self.owner.valid() or
                provider._state != 'open' or provider._released or provider._runtime is not runtime or
                provider._session != self.session or provider._binding != self.binding or
                provider._hmodule != self.module or provider._pinned is not self.identity or
                provider.spec is not self.spec or type(self.spec) is not OwnImageModuleSpec or runtime.image_base != GUEST_BASE or
                provider._owner[0] != os.getpid() or capability['owner']['process_id'] != provider._owner[0] or
                capability['owner']['thread_id'] != provider._owner[1] or capability['owner']['session_id'] != self.session or
                capability['owner']['runtime_binding'] != self.binding or capability['native_identity']['hmodule'] != self.module or
                capability['native_identity']['file_id'] != self.identity['file_id'] or self.identity['sha256'] != WRAPPER_SHA256 or
                ntpath.normcase(self.identity['path']) != ntpath.normcase(self.spec.path)):
            raise PrimarySemanticUnavailable('module collector borrowed A view is stale or foreign')

    def filename_a_relocation(self, runtime, arguments, capability):
        import sys
        from .primary_notification_modules import _observe
        from .primary_windows_notification_modules import WindowsModuleCollectorObservations
        self.check(runtime)
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not _observe.__code__:
            frame = frame.f_back
        facade = runtime.__dict__.get('notification_module_observations')
        if (capability is not self or type(arguments) is not tuple or arguments != (GUEST_BASE, 260) or
                any(type(value) is not int for value in arguments) or frame is None or
                frame.f_locals.get('runtime') is not runtime or frame.f_locals.get('name') != 'GetModuleFileNameA' or
                frame.f_locals.get('arguments') != arguments or type(facade) is not WindowsModuleCollectorObservations or
                facade is not self.claim.facade or facade.view is not self or self not in self.provider._module_views):
            raise InputError('module filename relocation requires its exact collector A source frame')
        return (self.module, 260), self

    def close(self):
        if self.closed:
            return
        if self.worker != (os.getpid(), threading.get_native_id()) or self not in self.provider._module_views:
            raise InputError('module borrowed A view cleanup identity changed')
        self.provider._module_views.remove(self)
        self.closed = True
        self.provider = self.runtime = self.owner = self.identity = self.spec = self.capability = self.claim = None
        self.module = self.session = self.binding = None


class WindowsOwnImageModule:
    def __init__(self, spec, *, backend=None):
        if type(spec) is not OwnImageModuleSpec:
            raise InputError('own-image requires its immutable fixed specification')
        spec.__post_init__()
        self.spec, self._backend = spec, backend
        self._owner = os.getpid(), threading.get_native_id()
        self._runtime = self._file = self._hmodule = self._pinned = None
        self._session = secrets.token_hex(16)
        self._binding = None
        self._state = 'new'
        self._locked = self._released = False
        self._failure = None
        self._postload_diagnostics = None
        self._module_views = set()

    def _check_owner(self):
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('own-image requires its creating process and native thread')

    def module_collector_view(self, runtime, owner, capability):
        from .primary_notification_modules import require_claim
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        claim = require_claim(runtime)
        if (type(owner) is not _NotificationWorkerOwner or claim.owner is not owner or not owner.valid() or
                owner.runtime is not runtime or capability is None):
            raise PrimarySemanticUnavailable('module view requires its actual collector and explicit A authority')
        view = _ModuleCollectorLoadedView(self, runtime, owner, capability)
        self._module_views.add(view)
        return view

    def notification_view(self, runtime, owner):
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        if (type(owner) is not _NotificationWorkerOwner or not owner.valid() or owner.runtime is not runtime or
                os.getpid() != self._owner[0] or self._state != 'open' or self._runtime is not runtime or
                self._released or not self._hmodule or self._pinned is None):
            raise PrimarySemanticUnavailable('notification loaded view requires its real owner and open owned image')
        return _NotificationLoadedView(self, runtime, owner)

    def constructor_view(self, runtime, owner, capability):
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        if (type(owner) is not _NotificationWorkerOwner or not owner.valid() or owner.runtime is not runtime or
                runtime._primary_direct_scope.require_constructor_phase().owner is not owner or capability is None):
            raise PrimarySemanticUnavailable('constructor loaded view requires its actual phase and W authority')
        return _ConstructorLoadedView(self, runtime, owner, capability)

    def _matching(self, rows):
        return [row for row in rows if row['name'] == 'wrapper.node' or
                row['file_id'] == self._pinned['file_id']]

    def acquire(self):
        self._check_owner()
        if self._state != 'new' or not _MODULE_LOCK.acquire(blocking=False):
            raise InputError('own-image acquisition requires one fresh exclusive owner')
        self._locked, self._state = True, 'acquiring'
        if self._backend is None:
            self._backend = _NativeBackend()
        self._backend.check_environment(self.spec)
        self._file = self._backend.open_file(self.spec.path, pinned=True)
        self._pinned = self._backend.inspect_file(self._file)
        if (self._pinned['sha256'] != self.spec.sha256 or _image_size(self._pinned['header']) != IMAGE_SIZE or
                not _headers_size(self._pinned['header']) or
                ntpath.normcase(self._pinned['path']) != ntpath.normcase(self.spec.path)):
            raise PrimarySemanticUnavailable('own-image pinned file identity differs from fixed image')
        if self._matching(self._backend.modules()):
            raise PrimarySemanticUnavailable('own-image requires absence of same basename and same-file aliases')
        self._hmodule = self._backend.load()
        if type(self._hmodule) is not int or not 0 < self._hmodule < 1 << 64:
            self._hmodule = None
            raise PrimarySemanticUnavailable('own-image LoadLibraryExW did not return a registered image')
        mapped = self._backend.mapping(self._hmodule)
        matches = self._matching(self._backend.modules())
        self._validate_postload(mapped, matches)
        self._state = 'open'

    def _validate_postload(self, mapped, matches):
        names = ('P1_owned_base', 'P2_module_image_size', 'P3_header_image_size',
                 'P4_header_span_size', 'P5_header_bytes', 'P6_file_identity',
                 'P7_normalized_path', 'P8_single_matching_module', 'P9_owned_module_match')
        details = {}
        self._postload_diagnostics = dict(predicates=dict.fromkeys(names, 'not_evaluated'),
                                         first_failed_predicate=None, details=details)
        def header_equal():
            actual = mapped['header'][:_headers_size(mapped['header'])]
            expected = self._pinned['header'][:_headers_size(self._pinned['header'])]
            transformed = _loaded_header_expected(self._pinned['header'], self._hmodule)
            equal = actual == expected
            if not equal:
                details.update(compared_length=len(actual), expected_length=len(expected),
                    first_mismatch_offset=next((index for index, pair in enumerate(zip(actual, expected))
                                                if pair[0] != pair[1]), min(len(actual), len(expected))),
                    mapped_header_sha256=hashlib.sha256(actual).hexdigest(),
                    pinned_header_sha256=hashlib.sha256(expected).hexdigest(),
                    imagebase_equals_owned=actual[0xA8:0xB0] == transformed[0xA8:0xB0],
                    expected_transformed_header_sha256=hashlib.sha256(transformed).hexdigest(),
                    first_transformed_mismatch_offset=next((index for index, pair in enumerate(zip(actual, transformed))
                                                            if pair[0] != pair[1]), None))
            return equal or actual == transformed
        def single_match():
            details['matching_module_count'] = len(matches)
            return len(matches) == 1
        checks = (lambda: mapped['base'] == self._hmodule,
                  lambda: mapped['size_of_image'] == IMAGE_SIZE,
                  lambda: _image_size(mapped['header']) == IMAGE_SIZE,
                  lambda: _headers_size(mapped['header']) == _headers_size(self._pinned['header']),
                  header_equal,
                  lambda: mapped['file_id'] == self._pinned['file_id'],
                  lambda: ntpath.normcase(mapped['path']) == ntpath.normcase(self.spec.path),
                  single_match, lambda: matches[0]['hmodule'] == self._hmodule)
        for name, check in zip(names, checks):
            try:
                passed = check()
            except BaseException:
                self._postload_diagnostics['predicates'][name] = 'error'
                self._postload_diagnostics['first_failed_predicate'] = name
                raise
            self._postload_diagnostics['predicates'][name] = 'passed' if passed else 'failed'
            if not passed:
                self._postload_diagnostics['first_failed_predicate'] = name
                raise PrimarySemanticUnavailable('own-image registered mapping identity or fresh ownership is ambiguous')

    def bind(self, runtime):
        self._check_owner()
        if self._state != 'open' or self._runtime is not None or runtime.image_base != GUEST_BASE:
            raise InputError('own-image requires one exact fixed-image runtime binding')
        self._runtime, self._binding = runtime, secrets.token_hex(16)

    def capability_snapshot(self):
        return self._capability_snapshot('GetModuleFileNameA')

    def capability_w_snapshot(self):
        return self._capability_snapshot('GetModuleFileNameW')

    def _capability_snapshot(self, api):
        self._check_owner()
        if self._state != 'open' or self._runtime is None:
            raise InputError('own-image capability requires its open bound runtime')
        return _freeze_capability(dict(schema_version=1, kind='native-ownimage-relocation', api=api,
            logical_role='wrapper-own-image', guest_identity=dict(base=GUEST_BASE, rva=0, sha256=WRAPPER_SHA256, size_of_image=IMAGE_SIZE),
            native_identity=dict(hmodule=self._hmodule, image_base=self._hmodule, size_of_image=IMAGE_SIZE,
                                 file_id=self._pinned['file_id'], file_sha256=WRAPPER_SHA256),
            owner=dict(process_id=self._owner[0], thread_id=self._owner[1], session_id=self._session, runtime_binding=self._binding),
            load=dict(flags=1, hfile=0, reference_kind='one owned LoadLibraryExW reference', state='open',
                      fresh_not_reused=True, loader_evidence_sha256=self.spec.loader_evidence_sha256)), api)

    def filename_relocation(self, runtime, arguments):
        self._check_owner()
        if (runtime is not self._runtime or self._state != 'open' or
                type(arguments) is not tuple or len(arguments) != 2 or
                any(type(value) is not int for value in arguments) or arguments != (GUEST_BASE, 260)):
            raise InputError('own-image filename relocation requires exact runtime, RVA0 and capacity260')
        return (self._hmodule, 260), self.capability_snapshot()

    def filename_w_relocation(self, runtime, arguments, capability):
        self._check_owner()
        if (runtime is not self._runtime or self._state != 'open' or
                type(arguments) is not tuple or len(arguments) != 2 or
                any(type(value) is not int for value in arguments) or arguments != (GUEST_BASE, 260)):
            raise InputError('own-image W filename relocation requires exact runtime, RVA0 and capacity260')
        current = self.capability_w_snapshot()
        if freeze_w_capability(capability) != current:
            raise InputError('own-image W relocation requires its live provider-issued capability')
        return (self._hmodule, 260), current

    def close(self):
        self._check_owner()
        if self._state == 'closed':
            return
        if self._failure is not None:
            raise self._failure
        if self._module_views:
            raise PrimarySemanticUnavailable('own-image retains active module collector views')
        self._state = 'closing'
        try:
            if self._hmodule is not None and not self._released:
                try:
                    success = self._backend.release(self._hmodule)
                except BaseException:
                    self._state = 'release_unknown'
                    raise
                if success is not True:
                    self._state = 'release_failed'
                    raise PrimarySemanticUnavailable('own-image owned reference release returned false')
                self._released = True
                self._session = self._binding = None
                if self._matching(self._backend.modules()):
                    self._state = 'exclusion_failed'
                    raise PrimarySemanticUnavailable('own-image owned reference released but mapping absence is not confirmed')
            if self._file is not None:
                try:
                    file_closed = self._backend.close_file(self._file)
                except BaseException:
                    self._state = 'file_close_unknown'
                    raise
                if file_closed is not True:
                    self._state = 'file_close_failed'
                    raise PrimarySemanticUnavailable('own-image pinned file close returned false')
                self._file = None
            if self._backend is not None and self._backend.files:
                self._state = 'file_close_failed'
                raise PrimarySemanticUnavailable('own-image auxiliary file cleanup remains unresolved')
        except BaseException as error:
            self._failure = error
            raise
        self._runtime = self._hmodule = self._pinned = self._session = self._binding = None
        self._state = 'closed'
        if self._locked:
            self._locked = False
            _MODULE_LOCK.release()

    @property
    def diagnostics(self):
        return {'state': self._state,
                'reference_owned': None if self._state == 'release_unknown' else self._hmodule is not None and not self._released,
                'owned_reference_released': self._released,
                'file_pinned': None if self._state == 'file_close_unknown' else self._file is not None,
                'pending_native_files': 0 if self._backend is None else len(self._backend.files),
                'runtime_bound': self._runtime is not None, 'session_active': self._session is not None,
                'closed': self._state == 'closed',
                'postload_identity': None if self._postload_diagnostics is None else
                    dict(self._postload_diagnostics, predicates=dict(self._postload_diagnostics['predicates']),
                         details=dict(self._postload_diagnostics['details']))}
