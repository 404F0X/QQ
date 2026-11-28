from dataclasses import dataclass
import hashlib
import threading
import os
import sys

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable
from .primary_vm import PrimaryProgramLimit
from .primary_sdk import assign_string
from .primary_logger import log
from .primary_worker_response import _frame
from .primary_worker_consumer import _invoke


_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20
_IMPORTS = {'CreateFileW': 0x490FC40, 'GetFileSizeEx': 0x490FE80,
            'GetLastError': 0x490FEA8, 'ReadFile': 0x4910288,
            'CloseHandle': 0x490FBD8, 'GetCommandLineA': 0x490FDA0}
_COUNTS = {'CreateFileW': 7, 'GetFileSizeEx': 2, 'GetLastError': 0,
           'ReadFile': 5, 'CloseHandle': 1, 'GetCommandLineA': 0}
_OUTPUTS = {'CreateFileW': (), 'GetFileSizeEx': ('size',),
            'GetLastError': (), 'ReadFile': ('data', 'count'), 'CloseHandle': (), 'GetCommandLineA': ()}


@dataclass(frozen=True)
class FileApiWrite:
    buffer: str
    offset: int
    data: bytes

    def __post_init__(self):
        if self.buffer not in ('size', 'data', 'count') or type(self.offset) is not int or self.offset < 0 or type(self.data) is not bytes:
            raise InputError('file API write requires a named output, nonnegative offset and raw bytes')


@dataclass(frozen=True)
class FileApiReply:
    result: int
    writes: tuple

    def __post_init__(self):
        if type(self.result) is not int or not 0 <= self.result <= _MASK64:
            raise InputError('file API result requires an explicit unsigned64 integer')
        if type(self.writes) is not tuple or not all(isinstance(write, FileApiWrite) for write in self.writes):
            raise InputError('file API reply requires ordered typed raw writes')


@dataclass(frozen=True)
class FileApiObservation:
    name: str
    arguments: tuple
    reply: FileApiReply

    def __post_init__(self):
        if self.name not in _COUNTS or type(self.arguments) is not tuple or len(self.arguments) != _COUNTS[self.name]:
            raise InputError('file API observation requires its exact named argument tuple')
        if any(type(value) is not int or not 0 <= value <= _MASK64 for value in self.arguments):
            raise InputError('file API arguments require actual unsigned64 integers')
        if not isinstance(self.reply, FileApiReply):
            raise InputError('file API observation requires its typed raw reply')
        if self.name not in ('CreateFileW', 'GetCommandLineA') and self.reply.result > 0xFFFFFFFF:
            raise InputError('file API BOOL/error result requires an explicit DWORD')
        if any(write.buffer not in _OUTPUTS[self.name] for write in self.reply.writes):
            raise InputError('file API reply writes an output not present in the source call')


class FileObservations:
    def __init__(self, observations):
        self.observations = tuple(observations)
        if not all(isinstance(item, FileApiObservation) for item in self.observations):
            raise InputError('typed ordered file API observations required')
        self.position = 0

    def take(self, runtime, name, arguments):
        if self.position == len(self.observations):
            raise UnknownMemory('missing file API observation: ' + name)
        item = self.observations[self.position]
        if (item.name, item.arguments) != (name, arguments):
            raise InputError('file API observation differs from the actual ordered call')
        self.position += 1
        return item.reply


def install_observations(runtime, observations):
    if not isinstance(observations, FileObservations):
        raise InputError('typed file API stream required')
    runtime.notification_file_observations = observations


def _api(runtime, name, arguments, outputs):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('file API current import is not bound: ' + name)
    observer = getattr(runtime, 'notification_file_observations', None)
    if not isinstance(observer, FileObservations):
        raise UnknownMemory('missing typed file API observations')
    reply = observer.take(runtime, name, arguments)
    FileApiObservation(name, arguments, reply)
    for write in reply.writes:
        pointer, capacity = outputs[write.buffer]
        if write.offset > capacity or len(write.data) > capacity - write.offset:
            raise InputError('file API write leaves its actual output buffer')
        if write.data:
            runtime.memory.write(pointer + write.offset, write.data, source='35A6B90.raw_' + name)
    return reply.result


@dataclass(frozen=True)
class FileSelectorMaterial:
    initial_state: bytes
    command_line_pointer: int
    command_line_bytes: bytes
    source_kind: str
    source_identity: str
    input_sha256: str

    def __post_init__(self):
        if type(self.initial_state) is not bytes or len(self.initial_state) != 2 or self.initial_state[0] != 0:
            raise InputError('file selector requires explicit cold checked/selected bytes')
        if type(self.command_line_pointer) is not int or not 0 < self.command_line_pointer <= _MASK64:
            raise InputError('file selector requires the actual raw command-line pointer')
        if type(self.command_line_bytes) is not bytes or not 0 < len(self.command_line_bytes) <= _LIMIT or b'\0' not in self.command_line_bytes:
            raise InputError('file selector requires bounded raw command-line bytes including NUL')
        if self.source_kind not in ('captured-raw-input', 'synthetic-test-input') or type(self.source_identity) is not str or not self.source_identity:
            raise InputError('file selector requires explicit raw input provenance')
        payload = self.initial_state + self.command_line_pointer.to_bytes(8, 'little') + self.command_line_bytes
        if type(self.input_sha256) is not str or hashlib.sha256(payload).hexdigest() != self.input_sha256:
            raise InputError('file selector input binding does not match its actual raw material')


class _FileAllocatorOwner:
    def __init__(self, runtime, epoch, material):
        self.runtime = runtime
        self.image_base = runtime.image_base
        self.epoch = epoch
        self.thread = threading.get_ident()
        self.material = material
        self.heap = runtime.memory.load(self.image_base + 0x6D8EC90, 8)
        if not self.heap:
            raise InputError('file allocator requires its actual nonzero initialized heap handle')
        self.phase = 'cold'
        self.cache = material.initial_state
        self.live = {}

    def validate(self, runtime):
        if self.phase == 'poisoned':
            raise PrimarySemanticUnavailable('file allocator owner is poisoned by failed initialization or binding')
        if runtime is not self.runtime or runtime.image_base != self.image_base or threading.get_ident() != self.thread:
            raise InputError('file allocator requires its original runtime/image/creation thread')
        if getattr(runtime, 'notification_file_allocator_owner', None) is not self or getattr(runtime, 'notification_file_allocator_epoch', None) != self.epoch:
            self.phase = 'poisoned'
            raise InputError('file allocator owner/cache epoch was replaced')
        if runtime.memory.load(self.image_base + 0x6D8EC90, 8) != self.heap:
            self.phase = 'poisoned'
            raise InputError('file allocator heap differs from its witnessed epoch')
        if runtime.memory.read(self.image_base + 0x6750E80, 2) != self.cache:
            self.phase = 'poisoned'
            raise InputError('file allocator cache changed outside its completed source initialization')

    def select(self, runtime):
        self.validate(runtime)
        if self.phase == 'cold':
            memory = runtime.memory
            memory.store(self.image_base + 0x6750E80, 1, 1, source='B75780.selector_checked_before_raw_call')
            self.cache = bytes((1, self.cache[1]))
            self.phase = 'initializing'
            try:
                pointer = _api(runtime, 'GetCommandLineA', (), {})
                self.validate(runtime)
                if pointer != self.material.command_line_pointer:
                    raise InputError('GetCommandLineA pointer differs from its bound raw material')
                pattern = b'--notcmalloc'
                if memory.read(self.image_base + 0x485330A, len(pattern) + 1) != pattern + b'\0':
                    raise InputError('B7578D selector literal does not match its fixed source')
                length = self.material.command_line_bytes.index(0)
                raw = memory.read(pointer, length + 1)
                if raw != self.material.command_line_bytes[:length + 1]:
                    raise InputError('GetCommandLineA memory differs from its witnessed bytes')
                if pattern in raw[:-1]:
                    memory.store(self.image_base + 0x6750E81, 1, 1, source='B757A1.selector_substring_hit')
                self.cache = memory.read(self.image_base + 0x6750E80, 2)
                self.phase = 'complete'
            except BaseException:
                self.phase = 'poisoned'
                raise
        elif self.phase != 'complete':
            self.phase = 'poisoned'
            raise PrimarySemanticUnavailable('file allocator initialization is incomplete/reentrant')
        self.validate(runtime)
        if not self.cache[1]:
            raise PrimarySemanticUnavailable('B75726 custom cache allocator remains unsupported in this witnessed epoch')


def install_allocator_material(runtime, epoch, material):
    if getattr(runtime, '_primary_allocator_selector', None) is not None:
        raise InputError('fresh shared runtime requires its shared selector source, not an independent cold witness')
    if type(epoch) is not str or not epoch or not isinstance(material, FileSelectorMaterial):
        raise InputError('file allocator requires an explicit epoch and typed source material')
    if hasattr(runtime, 'notification_file_allocator_owner') or hasattr(runtime, 'notification_file_allocator_epoch'):
        raise InputError('file allocator epoch cannot be rebound or reset')
    if runtime.memory.read(runtime.image_base + 0x6750E80, 2) != material.initial_state:
        raise InputError('file allocator raw initial state differs from its explicit source material')
    owner = _FileAllocatorOwner(runtime, epoch, material)
    runtime.notification_file_allocator_epoch = epoch
    runtime.notification_file_allocator_owner = owner
    return owner


class _SharedFileAllocatorOwner(_FileAllocatorOwner):
    def __init__(self, runtime, source, observer, origin, material=None, alias=None):
        self.runtime, self.source, self.observer = runtime, source, observer
        self.image_base, self.epoch = runtime.image_base, source.epoch
        self.identity = os.getpid(), threading.get_ident(), threading.get_native_id()
        self.thread, self.origin = threading.get_ident(), origin
        self.heap = runtime.memory.load(self.image_base + 0x6D8EC90, 8)
        if not self.heap:
            raise InputError('shared file allocator needs its source guest heap identity')
        self.live, self._model_material, self._model_alias = {}, material, alias

    def validate(self, runtime):
        self.source.require_owner(runtime, self)
        if (runtime is not self.runtime or runtime.image_base != self.image_base or
                self.epoch is not self.source.epoch or self.heap != self.source.heap or
                self.identity != (os.getpid(), threading.get_ident(), threading.get_native_id()) or
                getattr(runtime, 'notification_file_observations', None) is not self.observer or
                runtime.memory.load(self.image_base + 0x6D8EC90, 8) != self.heap):
            raise InputError('shared file allocation owner/thread/heap/source changed')
        if self.origin == 'windows':
            self.observer._check(runtime)

    def select(self, runtime):
        self.validate(runtime)
        self.source.select(runtime, self)
        self.validate(runtime)

    def _command_line(self):
        self.source.require_capture(self.runtime, self)
        pointer = _api(self.runtime, 'GetCommandLineA', (), {})
        if self.origin == 'synthetic':
            material = self._model_material
            if material is None or pointer != material.command_line_pointer:
                raise InputError('shared model selector API differs from its explicit material')
            raw = bytearray(material.command_line_bytes)
            def release():
                raw[:] = bytes(len(raw)); raw.clear(); self._model_material = None
                if self._model_alias is not None:
                    self._model_alias.close_refs(); self._model_alias = None
            try:
                self.source.accept_input(self.runtime, self, pointer, raw, raw.index(0) + 1, release, self._model_alias)
            except BaseException:
                release()
                raise
        return pointer


def install_shared_model_allocator(runtime, material=None, *, alias=None):
    """Explicit synthetic model domain; never a captured Windows source grant."""
    from .primary_allocator_selector import _SharedSelector, ModelCommandLineAlias
    from .primary_windows_notification_integrity import WindowsNotificationIntegrityService
    source = getattr(runtime, '_primary_allocator_selector', None)
    observer = getattr(runtime, 'notification_file_observations', None)
    if type(source) is not _SharedSelector or not isinstance(observer, FileObservations) or isinstance(observer, WindowsNotificationIntegrityService):
        raise InputError('shared model selector needs its actual fresh runtime and typed synthetic API stream')
    source.validate(runtime)
    if source.phase == 'fresh':
        if not isinstance(material, FileSelectorMaterial) or material.source_kind != 'synthetic-test-input' or material.initial_state != source.cache:
            raise InputError('shared model cold input must be explicit synthetic material')
        if alias is not None and (type(alias) is not ModelCommandLineAlias or alias.runtime is not runtime or alias.source is not source):
            raise InputError('model selector alias must belong to its explicit current source')
    elif source.phase != 'complete' or material is not None or alias is not None:
        raise InputError('shared model warm owner needs completed same-source provenance only')
    owner = _SharedFileAllocatorOwner(runtime, source, observer, 'synthetic', material, alias)
    source.register(owner, 'synthetic')
    return owner


def _install_shared_file_allocator(runtime, service):
    from .primary_allocator_selector import _SharedSelector
    from .primary_windows_notification_integrity import WindowsNotificationIntegrityService
    from .primary_windows_notification_parent import WindowsNotificationParentObservations
    from .primary_windows_notification_environment import _ParentEnvironment
    frame = sys._getframe(1)
    if (type(service) is not WindowsNotificationIntegrityService or
            type(service.observer) is not _ParentEnvironment or
            frame.f_code is not WindowsNotificationIntegrityService.begin.__code__ or
            frame.f_locals.get('self') is not service or frame.f_locals.get('runtime') is not runtime):
        raise InputError('shared Windows file owner requires its original actual service begin')
    service._check(runtime)
    parent = getattr(runtime, 'notification_parent_observations', None)
    if (type(parent) is not WindowsNotificationParentObservations or
            parent.runtime is not runtime or service.observer._runtime is not runtime or
            service.observer.parent is not parent.parent or service.observer.owner is not parent.owner):
        raise InputError('file facade and installed parent do not share their actual runtime/environment/owner')
    parent._installed(runtime)
    parent._parent_source()
    source = getattr(runtime, '_primary_allocator_selector', None)
    if type(source) is not _SharedSelector:
        raise UnknownMemory('Windows file allocator lacks a fresh source-produced selector epoch')
    source.validate(runtime)
    source.require_origin(runtime, 'windows')
    matches = [owner for owner, entry in source._owners.items() if entry[1] is service]
    if matches:
        if len(matches) != 1:
            raise InputError('shared file source has ambiguous allocation ownership')
        matches[0].validate(runtime)
        return matches[0]
    owner = _SharedFileAllocatorOwner(runtime, source, service, 'windows')
    source.register(owner, 'windows')
    return owner


def _allocator_owner(runtime):
    source = getattr(runtime, '_primary_allocator_selector', None)
    if source is not None:
        from .primary_allocator_selector import _SharedSelector
        if type(source) is not _SharedSelector:
            raise InputError('shared selector source was replaced')
        owner = source.owner_for(runtime, getattr(runtime, 'notification_file_observations', None))
        owner.validate(runtime)
        source.require_origin(runtime, owner.origin)
        return owner
    owner = getattr(runtime, 'notification_file_allocator_owner', None)
    if not isinstance(owner, _FileAllocatorOwner):
        raise UnknownMemory('file allocator requires a completed same-epoch source initialization witness')
    owner.select(runtime)
    return owner


def _allocate_buffer(runtime, size, *, mode=1):
    if type(size) is not int or not 1 <= size <= _LIMIT + 1 or mode not in (0,1):
        raise InputError('file allocation requires its bounded source size and mode')
    owner = _allocator_owner(runtime)
    pointer = _invoke(runtime, 0xB7593F if mode else 0xB75000, size)
    backend = runtime._custom_allocator_backend
    record = backend.records.get(pointer)
    if record is None or record[1] != size:
        raise PrimarySemanticUnavailable('file upper allocation did not return its owned live storage')
    region, offset = runtime.memory._span(pointer, size)
    if offset or pointer in owner.live:
        raise InputError('file upper allocation overlaps witnessed ownership')
    owner.live[pointer] = (region, size, owner.heap, owner.epoch, mode)
    owner.validate(runtime)
    return pointer


def _free_buffer(runtime, pointer):
    owner = _allocator_owner(runtime)
    if type(pointer) is not int or not 0 <= pointer <= _MASK64:
        raise InputError('file upper free requires an unsigned64 pointer')
    if not pointer:
        return None
    allocation = owner.live.get(pointer)
    if allocation is None or allocation[2:4] != (owner.heap, owner.epoch):
        raise InputError('file upper free requires its same-epoch live allocation')
    region, size = allocation[:2]
    actual, offset = runtime.memory._span(pointer, size)
    if actual is not region or offset:
        raise InputError('file free storage identity/liveness differs from its allocation')
    _invoke(runtime, 0xB758ED if allocation[4] else 0xB75029, pointer)
    del owner.live[pointer]
    owner.validate(runtime)


def _decode_local(runtime, frame, flag, counter, encoded, key):
    memory = runtime.memory
    memory.store(frame + flag, 1, 1, source='35A6B90.literal_flag')
    memory.store(frame + flag + 1, key, 1, source='35A6B90.literal_key')
    for index, byte in enumerate(encoded + b'\0\0'):
        memory.store(frame + flag + 2 + index, byte, 1, source='35A6B90.literal_encoded')
    memory.store(frame + counter, 0, 8, source='35A6B90.literal_counter')
    for index in range(len(encoded)):
        memory.store(frame + flag + 2 + index, encoded[index] ^ key ^ (index + 1) ^ len(encoded), 1, source='35A6B90.literal_decoded')
        memory.store(frame + counter, index + 1, 8, source='35A6B90.literal_counter')
    memory.store(frame + flag + 2 + len(encoded), 0, 1, source='35A6B90.literal_NUL')
    memory.store(frame + flag + 3 + len(encoded), 0, 1, source='35A6B90.literal_NUL')
    memory.store(frame + flag, 0, 1, source='35A6B90.literal_ready')
    return frame + flag + 2


def _failure_log(runtime, frame, line, value):
    encoded, key = _LOG_TEMPLATES[line]
    template = _decode_local(runtime, frame, 0x138, 0xA8, encoded, key)
    source = _decode_local(runtime, frame, 0xA8, 0x40, _LOG_SOURCE, 0x1B)
    runtime.memory.store(frame + 0x20, 1, 4, source='35A6B90.log_severity')
    runtime.memory.store(frame + 0x28, value, 8 if line in (0x62, 0x6C) else 4, source='35A6B90.log_argument')
    return log(runtime, source, line, template, runtime.image_base + 0x48972C7, 1, value)


def read_file(runtime, filename, destination):
    if any(type(value) is not int or not 0 <= value <= _MASK64 for value in (filename, destination)):
        raise InputError('35A6B90 requires actual unsigned64 filename and destination pointers')
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x178, '35A6B90.file_reader_frame')
    memory.store(frame + 0x90, destination, 8, source='35A6BA3.destination')
    memory.store(frame + 0x88, filename, 8, source='35A6BBD.filename')
    if not filename:
        memory.unmap(frame)
        return 0
    for offset, value, width in ((0x30, 0, 8), (0x28, 0x80, 4), (0x20, 3, 4)):
        memory.store(frame + offset, value, width, source='35A6D42.create_arguments')
    handle = _api(runtime, 'CreateFileW', (filename, 0x80000000, 1, 0, 3, 0x80, 0), {})
    memory.store(frame + 0x48, handle, 8, source='35A6D77.handle')
    if handle == _MASK64:
        error = _api(runtime, 'GetLastError', (), {})
        _failure_log(runtime, frame, 0x52, error)
        memory.unmap(frame)
        return 0
    size_pointer = frame + 0xA0
    memory.store(frame + 0x78, size_pointer, 8, source='35A75B1.size_alias')
    if not _api(runtime, 'GetFileSizeEx', (handle, size_pointer), {'size': (size_pointer, 8)}):
        error = _api(runtime, 'GetLastError', (), {})
        _failure_log(runtime, frame, 0x59, error)
        _api(runtime, 'CloseHandle', (handle,), {})
        memory.unmap(frame)
        return 0
    memory.store(frame + 0x60, size_pointer, 8, source='35A6DC5.size_pointer')
    size = memory.load(size_pointer, 8)
    memory.store(frame + 0x68, size, 8, source='35A6DD2.file_size')
    if size > _LIMIT:
        _failure_log(runtime, frame, 0x62, size)
        _api(runtime, 'CloseHandle', (handle,), {})
        memory.unmap(frame)
        return 0
    buffer = _allocate_buffer(runtime, size + 1)
    memory.store(frame + 0x58, buffer, 8, source='35A9214.buffer')
    if not buffer:
        _failure_log(runtime, frame, 0x6C, size)
        _api(runtime, 'CloseHandle', (handle,), {})
        memory.unmap(frame)
        return 0
    count_pointer = frame + 0x9C
    memory.store(frame + 0x80, count_pointer, 8, source='35A9239.count_alias')
    memory.store(frame + 0x20, 0, 8, source='35A925B.synchronous_read')
    success = _api(runtime, 'ReadFile', (handle, buffer, size, count_pointer, 0), {'data': (buffer, size), 'count': (count_pointer, 4)})
    if not success:
        error = _api(runtime, 'GetLastError', (), {})
        _failure_log(runtime, frame, 0x74, error)
        _free_buffer(runtime, buffer)
        _api(runtime, 'CloseHandle', (handle,), {})
        memory.unmap(frame)
        return 0
    count = memory.load(count_pointer, 4)
    if count > size:
        raise InputError('ReadFile actual count exceeds the requested source buffer')
    memory.store(buffer + count, 0, 1, source='35A75E6.read_terminator')
    assign_string(runtime, destination, buffer, count)
    _free_buffer(runtime, buffer)
    _api(runtime, 'CloseHandle', (handle,), {})
    memory.unmap(frame)
    return 1


def invoke(runtime, rva, values):
    if rva == 0x35A6B90 and len(values) == 2:
        return read_file(runtime, *values)
    if rva == 0x35A92F0 and len(values) == 2:
        return file_sha256(runtime, *values)
    raise InputError('file reader source interface argument count mismatch')


_LOG_SOURCE = bytes.fromhex('cfa4c3fcfcecf4e4e6cae0ffe3f9e0fcecedead4f9a7b3b6b1e4b0b4b6b7b5ddd9888bdd888883878d808781d2d1d7c99bcbcccdcfc8f7d4c9c7d3c6ced0ceaf8189b6b6bdb5aca789babeb2a2b7b0b4b592ada9baaf97b5b4b6b5afb5a7a088a28b8b9195a6b89c90959cbea5bb9d9888899d819d93b79280948e8688879143686a7674377978')
_LOG_TEMPLATES = {
    0x52: (bytes.fromhex('72565f5d55571249531f51495d551a434d4b4301574a56450c6c5c4c495f4f537d7b733f3056606f736d24393d7f'), 27),
    0x6c: (bytes.fromhex('785c55575f5d18435915555f5e5e534e5a480c464f4447555f0904504b5b45223b71707f'), 27),
    0x59: (bytes.fromhex('7e5a5351595b1e455f13555040175040444e0a5e45554b0f006650574b551c393d7f'), 27),
    0x62: (bytes.fromhex('406c6866227269756b2d637e7e2967713667757d75742a3f3b71707f'), 27),
    0x74: (bytes.fromhex('42666f6d65672279632f7c6c696f2a737d7b733f3056606f736d24393d7f'), 27),
}


def _digest_facet(runtime, implementation, identifier):
    memory = runtime.memory
    index = memory.load(runtime.image_base + identifier + 8, 4)
    begin = memory.load(implementation + 0x10, 8)
    end = memory.load(implementation + 0x18, 8)
    if not index or begin > end or (end - begin) % 8 or index > (end - begin) // 8:
        raise PrimarySemanticUnavailable('digest locale facet ID/table requires an already resolved actual entry')
    pointer = memory.load(begin + (index - 1) * 8, 8)
    if not pointer:
        raise PrimarySemanticUnavailable('digest locale requires its actual nonnull facet entry')
    return pointer


def _digest_method(runtime, facet, offset, expected):
    vtable = runtime.memory.load(facet, 8)
    if runtime.memory.load(vtable + offset, 8) != runtime.image_base + expected:
        raise PrimarySemanticUnavailable('digest locale consumes an unsupported custom facet method')


def format_digest_bytes(runtime, digest, locale_implementation, flags, state, fill, width, exception_mask):
    if type(digest) is not bytes or len(digest) != 32:
        raise InputError('digest formatter requires the actual 32 digest bytes')
    values = (locale_implementation, flags, state, fill, width, exception_mask)
    if any(type(value) is not int or not 0 <= value <= _MASK64 for value in values) or not locale_implementation:
        raise InputError('digest formatter requires explicit initialized locale and stream state integers')
    if (flags, state, fill, width, exception_mask) != (0x1008, 0, 0x30, 2, 0):
        raise PrimarySemanticUnavailable('digest formatter supports only its source-closed good finite output domain')
    num_put = _digest_facet(runtime, locale_implementation, 0x674DCD0)
    ctype = _digest_facet(runtime, locale_implementation, 0x674DE30)
    numpunct = _digest_facet(runtime, locale_implementation, 0x674DEA0)
    for facet, offset, target in ((num_put, 0x30, 0x76EA30), (ctype, 0x30, 0x7824C0),
                                  (ctype, 0x38, 0x7824B0), (numpunct, 0x18, 0x784A60),
                                  (numpunct, 0x20, 0x784A80)):
        _digest_method(runtime, facet, offset, target)
    from .primary_logger import _String
    grouping = _String.read(runtime, numpunct + 0x18).value()
    separator = runtime.memory.load(numpunct + 0x11, 1)
    if grouping:
        raise PrimarySemanticUnavailable('digest formatter requires actual empty grouping')
    output = bytearray()
    alphabet = b'0123456789abcdef'
    for value in digest:
        digits = bytes((alphabet[value],)) if value < 16 else bytes((alphabet[value >> 4], alphabet[value & 15]))
        output.extend(b'0' * (2 - len(digits)))
        output.extend(digits)
    return bytes(output)


@dataclass(frozen=True)
class FileDigestLocaleMaterial:
    tls_base: int
    epoch_value: int
    tls_epoch: int
    tls_index: int | None
    shared_wrapper: int
    implementation: int
    source_kind: str
    source_identity: str
    input_sha256: str

    def __post_init__(self):
        values = (self.tls_base, self.epoch_value, self.tls_epoch, self.shared_wrapper, self.implementation)
        if any(type(value) is not int or not 0 <= value <= _MASK64 for value in values):
            raise InputError('file digest locale requires actual raw unsigned fields')
        if not self.tls_base or not self.shared_wrapper or not self.implementation or any(value > 0xFFFFFFFF for value in values[1:3]):
            raise InputError('file digest locale raw pointers/epochs/ID widths are invalid')
        if self.tls_index is not None and (type(self.tls_index) is not int or not 0 <= self.tls_index <= 0xFFFFFFFF):
            raise InputError('file digest locale raw TLS index must be uint32 or explicitly unobserved')
        if self.source_kind not in ('captured-raw-input', 'synthetic-test-input') or type(self.source_identity) is not str or not self.source_identity:
            raise InputError('file digest locale requires explicit raw provenance')
        encoded = (self.tls_base.to_bytes(8, 'little') + self.epoch_value.to_bytes(8, 'little') +
                   self.tls_epoch.to_bytes(8, 'little') +
                   (b'UNOBSERVED' if self.tls_index is None else self.tls_index.to_bytes(8, 'little')) +
                   self.shared_wrapper.to_bytes(8, 'little') + self.implementation.to_bytes(8, 'little'))
        if hashlib.sha256(encoded).hexdigest() != self.input_sha256:
            raise InputError('file digest locale input binding mismatch')


class _FileDigestLocaleOwner:
    def __init__(self, runtime, epoch, material, source_view=None):
        self.runtime = runtime
        self.base = runtime.image_base
        self.epoch = epoch
        self.material = material
        self.source_view = source_view
        self._source_view_identity = source_view
        self.thread = threading.get_ident()
        self.allocator = _allocator_owner(runtime)
        if self.allocator.epoch is not epoch and self.allocator.epoch != epoch:
            raise InputError('file digest locale allocator epoch differs from its owner')
        self.references = runtime.memory.load(material.implementation + 8, 4)
        self.snapshot = self.capture(runtime)
        self.wrappers = set()

    def capture(self, runtime):
        memory = runtime.memory
        material = self.material
        if self.source_view is not self._source_view_identity:
            raise InputError('file digest locale source view identity changed')
        if self.source_view is not None:
            from .primary_shared_locale import ProducedSharedLocale
            if type(self.source_view) is not ProducedSharedLocale:
                raise InputError('file digest requires its exact sealed locale source view')
            self.source_view.validate(runtime)
            if (self.source_view.shared_wrapper != material.shared_wrapper or
                    self.source_view.implementation != material.implementation or
                    self.source_view.source_kind != self.source_view.capability.source_kind or
                    self.source_view.source_kind != material.source_kind or
                    self.source_view.source_identity != material.source_identity):
                raise InputError('file digest locale source view differs from its material')
        elif material.source_kind != 'synthetic-test-input':
            raise InputError('raw locale material cannot establish captured source provenance')
        signed = lambda value: value if value < 0x80000000 else value - (1 << 32)
        if self.source_view is not None:
            from .primary_shared_locale import resolve_current_module_tls
            receipt = resolve_current_module_tls(runtime)
            if material.tls_index is not None or receipt.native_index != 'UNOBSERVED':
                raise InputError('sealed locale requires an explicitly unobserved native TLS index')
            if ((material.source_kind == 'synthetic-test-input') !=
                    (receipt.origin == 'synthetic-test-input')):
                raise InputError('file digest locale TLS association origin differs from its producer')
            if (memory.load(self.base + 0x674DE10, 8), memory.load(material.shared_wrapper, 8)) != (material.shared_wrapper, material.implementation):
                raise InputError('file digest shared locale wrapper changed')
            epoch_value = memory.load(self.base + 0x674DE18, 4)
            tls_epoch = memory.load(receipt.epoch_address, 4)
        else:
            if runtime.tls_base_address != material.tls_base:
                raise InputError('file digest locale TLS base differs from its raw witness')
            if (memory.load(self.base + 0x674DE10, 8), memory.load(material.shared_wrapper, 8),
                    memory.load(self.base + 0x674DE18, 4), memory.load(material.tls_base + 0xA8, 4),
                    memory.load(self.base + 0x6755690, 4)) != (material.shared_wrapper, material.implementation, material.epoch_value, material.tls_epoch, material.tls_index):
                raise InputError('file digest shared locale/epoch raw fields differ from their bound material')
            epoch_value, tls_epoch = material.epoch_value, material.tls_epoch
        if signed(epoch_value) >= -1 or signed(epoch_value) > signed(tls_epoch):
            raise PrimarySemanticUnavailable('file digest shared locale requires already completed source initialization')
        rows = [memory.load(material.implementation + offset, 8) for offset in (0x10, 0x18)]
        for identifier, methods in ((0x674DCD0, ((0x30, 0x76EA30),)), (0x674DE30, ((0x30, 0x7824C0), (0x38, 0x7824B0))), (0x674DEA0, ((0x18, 0x784A60), (0x20, 0x784A80)))):
            facet = _digest_facet(runtime, material.implementation, identifier)
            rows.extend((memory.load(self.base + identifier + 8, 4), facet, memory.load(facet, 8)))
            for offset, target in methods:
                _digest_method(runtime, facet, offset, target)
                rows.append(memory.load(memory.load(facet, 8) + offset, 8))
            if identifier == 0x674DEA0:
                from .primary_logger import _String
                grouping = _String.read(runtime, facet + 0x18)
                if grouping.value():
                    raise PrimarySemanticUnavailable('file digest grouping must actually be empty')
                rows.extend((memory.load(facet + 0x11, 1), bytes(grouping.header), bytes(grouping.known)))
        return tuple(rows)

    def validate(self, runtime):
        if runtime is not self.runtime or runtime.image_base != self.base or threading.get_ident() != self.thread:
            raise InputError('file digest locale runtime/image/creation-thread mismatch')
        if (getattr(runtime, 'notification_file_digest_locale_owner', None) is not self or
                _allocator_owner(runtime) is not self.allocator or self.allocator.epoch != self.epoch):
            raise InputError('file digest locale shared cache epoch/owner changed')
        self.allocator.validate(runtime)
        if self.capture(runtime) != self.snapshot or runtime.memory.load(self.material.implementation + 8, 4) != self.references:
            raise InputError('file digest locale/facet/reference state changed outside its owned lifecycle')
        if any(runtime.memory.load(wrapper, 8) != self.material.implementation for wrapper in self.wrappers):
            raise InputError('file digest stream-held locale implementation differs from its raw witness')

    def acquire(self, runtime, wrapper):
        self.validate(runtime)
        if wrapper in self.wrappers or self.references == 0xFFFFFFFF:
            raise PrimarySemanticUnavailable('file digest locale duplicate wrapper/reference overflow')
        previous = self.references
        returned = _invoke(runtime, 0x781270, wrapper)
        self.references = runtime.memory.load(self.material.implementation + 8, 4)
        if (returned != wrapper or runtime.memory.load(wrapper, 8) != self.material.implementation or
                self.references != previous + 1):
            raise InputError('file digest actual locale copy returned inconsistent wrapper/reference state')
        self.wrappers.add(wrapper)

    def release(self, runtime, wrapper):
        self.validate(runtime)
        if wrapper not in self.wrappers or runtime.memory.load(wrapper, 8) != self.material.implementation:
            raise InputError('file digest locale release requires its actual owned wrapper')
        previous = self.references
        self.references = (previous - 1) & 0xFFFFFFFF
        runtime.memory.store(self.material.implementation + 8, self.references, 4, source='7664F0.locale_reference_decrement')
        self.wrappers.remove(wrapper)
        if previous == 0:
            raise PrimarySemanticUnavailable('file digest last-owner locale virtual destruction is unsupported')


def install_digest_locale_material(runtime, epoch, material, *, source_view=None):
    if not isinstance(material, FileDigestLocaleMaterial):
        raise InputError('file digest locale requires its typed material')
    allocator = _allocator_owner(runtime)
    if source_view is None and (type(epoch) is not str or not epoch or material.source_kind != 'synthetic-test-input' or material.tls_index is None):
        raise InputError('raw locale installation is restricted to explicit synthetic string epochs')
    if hasattr(runtime, 'notification_file_digest_locale_owner') or epoch != allocator.epoch:
        raise InputError('file digest locale must bind once to the existing actual allocator epoch')
    owner = _FileDigestLocaleOwner(runtime, epoch, material, source_view)
    runtime.notification_file_digest_locale_owner = owner
    owner.validate(runtime)
    return owner


def _produced_digest_locale_owner(runtime):
    owner = getattr(runtime, 'notification_file_digest_locale_owner', None)
    if owner is not None:
        if type(owner) is not _FileDigestLocaleOwner:
            raise InputError('file digest locale owner was replaced')
        owner.validate(runtime)
        return owner
    from .primary_shared_locale import prepare_shared_locale
    view = prepare_shared_locale(runtime)
    view.validate(runtime)
    memory, base = runtime.memory, runtime.image_base
    from .primary_shared_locale import resolve_current_module_tls
    receipt = resolve_current_module_tls(runtime)
    values = (receipt.tls_base, memory.load(base + 0x674DE18, 4),
              memory.load(receipt.epoch_address, 4), None, view.shared_wrapper, view.implementation)
    encoded = b''.join(b'UNOBSERVED' if value is None else value.to_bytes(8, 'little') for value in values)
    material = FileDigestLocaleMaterial(*values, view.source_kind, view.source_identity,
        hashlib.sha256(encoded).hexdigest())
    return install_digest_locale_material(runtime, _allocator_owner(runtime).epoch, material, source_view=view)


def _digest_string_resize(runtime, string, target):
    memory = runtime.memory
    tag = memory.load(string, 1)
    length = memory.load(string + 8, 8) if tag & 1 else tag >> 1
    pointer = memory.load(string + 16, 8) if tag & 1 else string + 1
    capacity = (memory.load(string, 8) & ~1) - 1 if tag & 1 else 22
    if not 0 <= length <= capacity <= _LIMIT or not 0 <= target <= _LIMIT:
        raise PrimaryProgramLimit('digest stream String resize exceeds its bounded source domain')
    if target > capacity:
        physical = (max(2 * capacity, target) | 15) + 1
        destination = _allocate_buffer(runtime, physical, mode=0)
        if length:
            memory.copy_disjoint(destination, pointer, length, label='75C7E9.growth_copy')
        if capacity != 22:
            _free_buffer(runtime, pointer)
        memory.store(string + 16, destination, 8, source='75C7FC.growth_pointer')
        memory.store(string, physical | 1, 8, source='75C804.growth_capacity')
        pointer = destination
    if target > length:
        memory.write(pointer + length, bytes(target - length), source='75C820.resize_fill')
    if memory.load(string, 1) & 1:
        memory.store(string + 8, target, 8, source='75D121.resize_length')
    else:
        memory.store(string, target * 2, 1, source='75D0FF.resize_short_length')
    memory.store(pointer + target, 0, 1, source='75D125.resize_NUL')


def _digest_stream_write(runtime, buffer, data):
    memory = runtime.memory
    vtable = memory.load(buffer, 8)
    if (memory.load(vtable + 0x58, 8), memory.load(vtable + 0x60, 8)) != (runtime.image_base + 0x760A30, runtime.image_base + 0x40098):
        raise PrimarySemanticUnavailable('digest stream current virtual write/overflow targets are not source-bound')
    for value in data:
        current, end = (memory.load(buffer + offset, 8) for offset in (0x30, 0x38))
        if current == end:
            if not memory.load(buffer + 0x60, 1) & 0x10:
                raise PrimarySemanticUnavailable('digest stream overflow output mode is disabled')
            old_begin = memory.load(buffer + 0x28, 8)
            old_high = memory.load(buffer + 0x58, 8)
            get_offset = memory.load(buffer + 0x18, 8) - memory.load(buffer + 0x10, 8)
            string = buffer + 0x40
            tag = memory.load(string, 1)
            length = memory.load(string + 8, 8) if tag & 1 else tag >> 1
            capacity = (memory.load(string, 8) & ~1) - 1 if tag & 1 else 22
            if length == capacity:
                _digest_string_resize(runtime, string, length + 1)
            else:
                _invoke(runtime, 0x75C610, string, 0)
            capacity = (memory.load(string, 8) & ~1) - 1 if memory.load(string, 1) & 1 else 22
            _digest_string_resize(runtime, string, capacity)
            tag = memory.load(string, 1)
            begin = memory.load(string + 16, 8) if tag & 1 else string + 1
            length = memory.load(string + 8, 8) if tag & 1 else tag >> 1
            current = begin + current - old_begin
            for offset, pointer in ((0x28, begin), (0x38, begin + length), (0x30, current), (0x58, begin + old_high - old_begin)):
                memory.store(buffer + offset, pointer, 8, source='40098.rebind_stream_range')
            high = max(current + 1, memory.load(buffer + 0x58, 8))
            memory.store(buffer + 0x58, high, 8, source='40098.overflow_highwater')
            if memory.load(buffer + 0x60, 1) & 8:
                for offset, pointer in ((0x10, begin), (0x18, begin + get_offset), (0x20, high)):
                    memory.store(buffer + offset, pointer, 8, source='40098.rebind_get_range')
        memory.store(current, value, 1, source='760A30.stream_character')
        memory.store(buffer + 0x30, current + 1, 8, source='760A30.stream_current')


def _digest_stream_result(runtime, rbp, result):
    memory = runtime.memory
    owner = _produced_digest_locale_owner(runtime)
    owner.validate(runtime)
    buffer, ios = rbp + 0x60, rbp + 0xC8
    if memory.load(runtime.image_base + 0x3EBE4F0, 4, signed=True) != 0x70:
        raise PrimarySemanticUnavailable('file digest source virtual-base offset is not bound')
    memory.store(rbp + 0x58, runtime.image_base + 0x3EBE4EC, 8, source='35A943B.stream_virtual_base_table')
    memory.store(ios, runtime.image_base + 0x3EBE6E8, 8, source='35A9451.ios_vtable')
    for offset, value, size in ((0x28, buffer, 8), (0x20, 0, 4), (0x24, 0, 4), (8, 0x1002, 4), (0x18, 0, 8), (0x10, 6, 8)):
        memory.store(ios + offset, value, size, source='760720.ios_initialization')
    for offset in range(0x38, 0x88, 0x10):
        memory.write(ios + offset, bytes(16), source='760720.ios_source_zero_fields')
    owner.acquire(runtime, ios + 0x30)
    memory.store(ios + 0x88, 0, 8, source='35A9460.source_tail')
    memory.store(ios + 0x90, 0xFFFFFFFF, 4, source='35A946B.fill_uninitialized')
    memory.store(ios, runtime.image_base + 0x3EBE500, 8, source='35A9484.derived_ios_vtable')
    memory.store(buffer, runtime.image_base + 0x3F729A8, 8, source='7608D0.base_streambuf_vtable')
    owner.acquire(runtime, buffer + 8)
    memory.write(buffer + 0x10, bytes(0x30), source='7608D0.streambuf_source_zero_fields')
    memory.store(buffer, runtime.image_base + 0x3EBE718, 8, source='35A9498.derived_streambuf_vtable')
    memory.write(buffer + 0x40, bytes(32), source='35A949F.empty_streambuf_string')
    memory.store(buffer + 0x60, 0x10, 4, source='35A94AD.stream_mode')
    memory.store(ios + 8, (memory.load(ios + 8, 4) & 0xFFFFFFB5) | 8, 4, source='35A94CD.hex_flags')
    owner.acquire(runtime, rbp + 0x168)
    _digest_method(runtime, _digest_facet(runtime, owner.material.implementation, 0x674DE30), 0x38, 0x7824B0)
    owner.release(runtime, rbp + 0x168)
    memory.store(ios + 0x90, 0x20, 4, source='35A952A.identity_space_fill')
    memory.store(ios + 0x90, 0x30, 4, source='35A9530.zero_fill')
    digest = memory.read(rbp - 0x40, 32)
    for index in range(32):
        owner.validate(runtime)
        memory.store(ios + 0x18, 2, 8, source='35A9558.byte_width')
        encoded = format_digest_bytes(runtime, digest, owner.material.implementation, memory.load(ios + 8, 4), memory.load(ios + 0x20, 4), memory.load(ios + 0x90, 4), memory.load(ios + 0x18, 8), memory.load(ios + 0x24, 4))[index * 2:index * 2 + 2]
        _digest_stream_write(runtime, buffer, encoded)
        memory.store(ios + 0x18, 0, 8, source='69850.success_width_reset')
    begin = memory.load(buffer + 0x28, 8)
    end = max(memory.load(buffer + 0x58, 8), memory.load(buffer + 0x30, 8))
    if end - begin != 64:
        raise PrimarySemanticUnavailable('digest stream produced an unsupported incomplete byte range')
    if result < end and begin < result + 24:
        raise PrimarySemanticUnavailable('digest constructor result header overlaps its copied stream range')
    payload = _allocate_buffer(runtime, 80, mode=0)
    owner.validate(runtime)
    memory.store(result + 16, payload, 8, source='40479.result_pointer')
    memory.store(result, 81, 8, source='40438.result_capacity')
    memory.store(result + 8, 64, 8, source='40438.result_length')
    for index in range(64):
        memory.store(payload + index, memory.load(begin + index, 1), 1, source='40494.result_independent_copy')
    memory.store(payload + 64, 0, 1, source='40438.result_NUL')
    memory.store(ios, runtime.image_base + 0x3EBE500, 8, source='35A959A.destruct_ios_vtable')
    memory.store(buffer, runtime.image_base + 0x3EBE718, 8, source='35A95AA.destruct_streambuf_vtable')
    if memory.load(buffer + 0x40, 1) & 1:
        _free_buffer(runtime, memory.load(buffer + 0x50, 8))
    memory.store(buffer, runtime.image_base + 0x3F729A8, 8, source='760870.base_streambuf_vtable')
    owner.release(runtime, buffer + 8)
    if any(memory.load(ios + offset, 8) for offset in (0x38, 0x40, 0x58, 0x70)):
        raise PrimarySemanticUnavailable('file digest nonempty callback/ios-owned arrays require their actual source destruction')
    owner.release(runtime, ios + 0x30)
    return result


def file_sha256(runtime, result, filename):
    if any(type(value) is not int or not 0 < value <= _MASK64 for value in (result, filename)):
        raise InputError('35A92F0 requires actual constructor-result and WideString24 pointers')
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x220, '35A92F0.file_sha_frame')
    memory.store(rbp + 0x198, _MASK64 - 1, 8, source='35A9309.frame_sentinel')
    pointer = memory.load(filename + 16, 8) if memory.load(filename, 1) & 1 else filename + 2
    for offset, value, size in ((0x30, 0, 8), (0x28, 0x80, 4), (0x20, 3, 4)):
        memory.store(frame + offset, value, size, source='35A9326.create_arguments')
    handle = _api(runtime, 'CreateFileW', (pointer, 0x80000000, 1, 0, 3, 0x80, 0), {})
    if handle == _MASK64:
        error = _api(runtime, 'GetLastError', (), {})
        template = _decode_local(runtime, rbp, -0x18, 0x58, _LOG_TEMPLATES[0x52][0], 0x1B)
        source = _decode_local(runtime, rbp, 0x58, 0x160, _LOG_SOURCE, 0x1B)
        memory.store(frame + 0x28, error, 4, source='35A9AF1.log_error_argument')
        memory.store(frame + 0x20, 1, 4, source='35A9AF5.log_severity')
        log(runtime, source, 0xA2, template, runtime.image_base + 0x48972C7, 1, error)
        memory.write(result, bytes(16), source='35AA0E6.failed_constructor_head')
        memory.store(result + 16, 0, 8, source='35AA0EA.failed_constructor_tail')
        memory.unmap(frame)
        return result
    memory.write(rbp - 0x30, bytes(16), source='35A9366.digest_zero_high')
    memory.write(rbp - 0x40, bytes(16), source='35A936A.digest_zero_low')
    for name, slot in (('SHA256_Init', 0x490FA40), ('SHA256_Update', 0x490FA48), ('SHA256_Final', 0x490FA38)):
        target = runtime.worker_imports.get(name)
        if target is None or memory.load(runtime.image_base + slot, 8) != target:
            raise PrimarySemanticUnavailable('file digest actual crypto import is not bound: ' + name)
    digest = hashlib.sha256()
    scratch = _allocate_buffer(runtime, _LIMIT)
    for iteration in range(65536):
        memory.store(frame + 0x20, 0, 8, source='35A9394.synchronous_read')
        success = _api(runtime, 'ReadFile', (handle, scratch, _LIMIT, rbp + 0x160, 0), {'data': (scratch, _LIMIT), 'count': (rbp + 0x160, 4)})
        if not success:
            break
        count = memory.load(rbp + 0x160, 4)
        if count > _LIMIT:
            raise InputError('file digest ReadFile count exceeds its actual chunk capacity')
        if not count:
            break
        digest.update(memory.read(scratch, count))
    else:
        raise PrimaryProgramLimit('file digest offline read-operation budget exhausted without EOF')
    memory.write(rbp - 0x40, digest.digest(), source='35A941E.actual_SHA256_final')
    _api(runtime, 'CloseHandle', (handle,), {})
    _free_buffer(runtime, scratch)
    _digest_stream_result(runtime, rbp, result)
    memory.unmap(frame)
    return result
