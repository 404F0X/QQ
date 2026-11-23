import os
import sys
from contextlib import contextmanager
from threading import get_ident, get_native_id

from .errors import InputError
from .primary_device_system import system_version
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker import _WideString, _units, lower_unit, path_name
from .primary_worker_response import _frame


_LIMIT = 1 << 20
_IMPORTS = {
    'GetModuleFileNameW': 0x490FEF0,
    'PathRemoveFileSpecW': 0x4910AE8,
    'GetUserDefaultLangID': 0x4910010,
    'GetFileVersionInfoSizeW': 0x490F060,
    'GetFileVersionInfoW': 0x490F068,
    'VerQueryValueW': 0x490F070,
}
_FACTORY = object()


class _ConstructorClaim:
    def __init__(self, runtime, address, source, factory):
        if factory is not _FACTORY:
            raise InputError('constructor claim requires its original source factory')
        self.runtime, self.address, self.source = runtime, address, source
        self.scope = runtime.__dict__.get('_primary_direct_scope')
        self.owner = getattr(self.scope, 'notification_owner', None)
        self.thread, self.native_thread, self.process = get_ident(), get_native_id(), os.getpid()
        self.generation, self.active = runtime._main_generation, True
        self.serial = None if self.owner is None else self.owner.serial
        self.lease = None if self.owner is None else self.owner.lease
        if type(address) is not int or runtime.allocations.get(address) != 0xE0:
            raise InputError('constructor requires its exact live E0 allocation')
        self.region, offset = runtime.memory._span(address, 0xE0)
        if self.region.address != address or offset or len(self.region.data) != 0xE0:
            raise InputError('constructor requires its exact live E0 allocation')

    def valid(self):
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        runtime, owner = self.runtime, self.owner
        return (self.active and self.process == os.getpid() and self.thread == get_ident() and
                self.native_thread == get_native_id() and self.generation == runtime._main_generation and
                frame is not None and frame.f_code is construct.__code__ and
                frame.f_locals.get('runtime') is runtime and frame.f_locals.get('address') == self.address and
                runtime.__dict__.get('_notification_constructor_claim') is self and
                runtime.__dict__.get('_primary_direct_scope') is self.scope and owner is not None and
                self.scope.notification_owner is owner and owner.valid() and owner.serial == self.serial and
                owner.lease is self.lease and runtime.allocations.get(self.address) == 0xE0 and
                any(region is self.region for region in runtime.memory._region_snapshot()) and
                runtime.locks.get(runtime.image_base + 0x677CEA0) == 1 and
                runtime.memory.load(runtime.image_base + 0x677CEC0, 8) == 0)


@contextmanager
def _constructor_phase(runtime, address):
    if runtime.primary_backend != 'direct':
        yield
        return
    from .primary_direct_scopes import PrimaryDirectScope
    from .primary_sign import PrimaryRuntime
    from .primary_windows_notification_environment import WindowsNotificationEnvironmentObservations
    if runtime.__dict__.get('_notification_constructor_claim') is not None:
        raise InputError('notification constructor does not permit nested or replayed phases')
    claim = _ConstructorClaim(runtime, address, sys._getframe(2), _FACTORY)
    environment = None
    had, prior = 'notification_environment_observations' in runtime.__dict__, runtime.__dict__.get('notification_environment_observations')
    runtime._notification_constructor_claim = claim
    try:
        if type(claim.scope) is not PrimaryDirectScope or claim.scope.require_constructor_phase() is not claim:
            raise PrimarySemanticUnavailable('notification constructor requires its actual direct worker scope')
        caller = sys._getframe(1)
        while caller is not None and caller.f_code is not PrimaryRuntime.invoke.__code__:
            caller = caller.f_back
        if (caller is None or caller.f_locals.get('self') is not runtime or caller.f_locals.get('rva') != 0x2E02AE0 or
                len(caller.f_locals['cells']) != 1 or caller.f_locals['arg'](0) != address):
            raise InputError('notification constructor requires its actual routed source entry and owner')
        if type(prior) is not WindowsNotificationEnvironmentObservations:
            raise InputError('notification constructor requires its bound Windows environment')
        environment = prior.constructor_environment(runtime, claim.owner)
        runtime.notification_environment_observations = environment
        yield claim
        if not claim.valid():
            raise InputError('notification constructor lost its actual owner before completion')
    finally:
        primary, failures = sys.exception(), []
        if environment is not None:
            if runtime.__dict__.get('notification_environment_observations') is not environment:
                failures.append(InputError('notification constructor observer was replaced'))
            if had:
                runtime.notification_environment_observations = prior
            else:
                runtime.__dict__.pop('notification_environment_observations', None)
            try:
                prior.release_constructor_environment(environment)
            except BaseException as error:
                failures.append(error)
        claim.active, claim.source = False, None
        if runtime.__dict__.get('_notification_constructor_claim') is not claim:
            failures.append(InputError('notification constructor claim was replaced'))
        runtime.__dict__.pop('_notification_constructor_claim', None)
        for error in failures:
            if primary is not None:
                primary.add_note('notification constructor cleanup failed: ' + type(error).__name__ + ': ' + str(error))
            else:
                primary = error
        if failures and sys.exception() is None:
            raise primary


def _observe(runtime, name, arguments):
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
        raise PrimarySemanticUnavailable('notification environment current import is not bound: ' + name)
    observer = getattr(runtime, 'notification_environment_observations', None)
    if observer is None:
        observer = runtime.worker_observations
    if observer is None:
        raise UnknownMemory('missing notification environment raw API observation: ' + name)
    return observer.take(runtime, name, arguments)


def _cleanup(actions):
    primary, failures = sys.exception(), []
    for release in actions:
        try:
            release()
        except BaseException as error:
            failures.append(error)
    for error in failures:
        if primary is not None:
            primary.add_note('notification environment cleanup failed: ' + type(error).__name__ + ': ' + str(error))
        else:
            primary = error
    if failures and sys.exception() is None:
        raise primary


def _free_resource(runtime, buffer, registered=True):
    try:
        observer = getattr(runtime, 'notification_environment_observations', None)
        if observer is not None and registered:
            observer.release_version_resource(runtime, buffer)
    finally:
        _cleanup((lambda: runtime._free_allocation(buffer),))


def _destroy_metadata(runtime, record):
    try:
        _free_resource(runtime, runtime.memory.load(record, 8))
    finally:
        _cleanup((lambda: runtime._free_allocation(record),))


def _output(runtime, address, raw, capacity):
    if not isinstance(raw, bytes) or len(raw) > capacity:
        raise InputError('notification environment raw output exceeds its actual buffer')
    if raw:
        runtime.memory.write(address, raw, source='notification_environment.raw_API_output')


def _terminated(runtime, address, capacity=260):
    for index in range(capacity):
        if runtime.memory.load(address + index * 2, 2) == 0:
            return runtime.memory.read(address, index * 2)
    raise PrimaryProgramLimit('notification environment wide string has no known bounded terminator')


def _filename(runtime, module, local):
    runtime.memory.write(local, bytes(520), source='notification_environment.zero_filename_local')
    result, raw = _observe(runtime, 'GetModuleFileNameW', (module, 260))
    _output(runtime, local, raw, 520)
    return result & 0xFFFFFFFF


def directory(runtime, destination):
    frame, local = _frame(runtime, 0x458, '35A2C90.directory_frame')
    try:
        _filename(runtime, runtime.image_base, frame + 0x20)
        ignored, raw = _observe(runtime, 'PathRemoveFileSpecW', (runtime.memory.read(frame + 0x20, 520),))
        _output(runtime, frame + 0x20, raw, 520)
        _WideString(runtime, address=destination).assign(_terminated(runtime, frame + 0x20))
        return 1
    finally:
        runtime.memory.unmap(frame)


def _query(runtime, buffer, size, query, pointer, length):
    memory = runtime.memory
    memory.store(pointer, 0, 8, source='notification_environment.initial_query_pointer')
    result, effects = _observe(runtime, 'VerQueryValueW', (buffer, query))
    if not isinstance(effects, tuple) or len(effects) != 3:
        raise InputError('notification version query requires raw pointer, length and resource images')
    raw_pointer, raw_length, images = effects
    _output(runtime, pointer, raw_pointer, 8)
    _output(runtime, length, raw_length, 4)
    if not isinstance(images, tuple) or len(images) > 32:
        raise InputError('notification version query requires bounded resource-owned images')
    for image in images:
        if not isinstance(image, tuple) or len(image) != 2:
            raise InputError('notification version image requires a guest address and bytes')
        address, raw = image
        if type(address) is not int or not isinstance(raw, bytes) or not raw or not buffer <= address < buffer + size or len(raw) > buffer + size - address:
            raise InputError('notification version query image leaves its resource owner')
        memory.write(address, raw, source='notification_environment.resource_query_image')
    return result & 0xFFFFFFFF


def _borrowed(runtime, buffer, size, pointer, count):
    if not buffer <= pointer < buffer + size or count > buffer + size - pointer:
        raise PrimaryProgramLimit('notification version borrowed pointer leaves its resource owner')
    return runtime.memory.read(pointer, count)


def metadata(runtime, source):
    memory = runtime.memory
    frame, local = _frame(runtime, 0x58, '35A2E20.metadata_frame')
    buffer = record = 0
    registered = False
    try:
        path = _WideString(runtime, address=source).value() + b'\0\0'
        size, raw = _observe(runtime, 'GetFileVersionInfoSizeW', (path,))
        _output(runtime, frame + 0x34, raw, 4)
        size &= 0xFFFFFFFF
        if not size:
            return 0
        if size > _LIMIT:
            raise PrimaryProgramLimit('notification version resource exceeds the offline domain')
        buffer = runtime._operator_new(size)
        memory.write(buffer, bytes(size), source='35A2E20.zero_version_resource')
        observer = getattr(runtime, 'notification_environment_observations', None)
        if observer is not None:
            observer.register_version_resource(runtime, buffer, size)
            registered = True
        result, raw = _observe(runtime, 'GetFileVersionInfoW', (path, memory.load(frame + 0x34, 4), size, True))
        _output(runtime, buffer, raw, size)
        if not result & 0xFFFFFFFF:
            return 0
        pointer, length = frame + 0x48, frame + 0x30
        if not _query(runtime, buffer, size, '\\VarFileInfo\\Translation'.encode('utf-16-le') + b'\0\0', pointer, length):
            return 0
        translation = memory.load(pointer, 8)
        if not translation:
            return 0
        record = runtime._operator_new(48)
        first = _borrowed(runtime, buffer, size, translation, 4)
        for offset, value in ((0, buffer), (8, buffer + size), (16, buffer + size), (24, buffer)):
            memory.store(record + offset, value, 8, source='35A2E20.metadata_resource')
        memory.write(record + 32, first, source='35A2E20.metadata_translation')
        result = _query(runtime, buffer, size, b'\\\0\0\0', pointer, length)
        root = memory.load(pointer, 8) if result else 0
        if root:
            _borrowed(runtime, buffer, size, root, 0)
        memory.store(record + 40, root, 8, source='35A2E20.metadata_root')
        output, record, buffer = record, 0, 0
        return output
    finally:
        cleanup = ([lambda: _free_resource(runtime, buffer, registered)] if buffer else [])
        if record:
            cleanup.append(lambda: runtime._free_allocation(record))
        cleanup.append(lambda: memory.unmap(frame))
        _cleanup(cleanup)


def file_version(runtime, record, destination):
    memory = runtime.memory
    frame, local = _frame(runtime, 0x268, '35A3060.version_frame')
    try:
        language, codepage = memory.load(record + 32, 2), memory.load(record + 34, 2)
        languages = []
        for index in range(2):
            value, effects = _observe(runtime, 'GetUserDefaultLangID', ())
            if effects not in (None, b''):
                raise InputError('notification language query has no output buffers')
            languages.append(value & 0xFFFF)
        buffer = memory.load(record + 24, 8)
        size = memory.load(record + 16, 8) - buffer
        for lang, page in ((language, codepage), (languages[0], codepage), (language, 1252), (languages[1], 1252)):
            query = ('\\StringFileInfo\\%04x%04x\\FileVersion' % (lang, page)).encode('utf-16-le') + b'\0\0'
            if len(query) > 520:
                raise PrimaryProgramLimit('notification localized query exceeds its source buffer')
            memory.write(frame + 0x50, query, source='35A3060.localized_query')
            if _query(runtime, buffer, size, query, frame + 0x48, frame + 0x44):
                pointer = memory.load(frame + 0x48, 8)
                if pointer:
                    units = memory.load(frame + 0x44, 4)
                    if units:
                        if units - 1 > _LIMIT:
                            raise PrimaryProgramLimit('notification version string exceeds the offline domain')
                        raw = _borrowed(runtime, buffer, size, pointer, (units - 1) * 2)
                        _WideString(runtime, address=destination).assign(raw)
                        return True
        return False
    finally:
        memory.unmap(frame)


def _append(value, raw):
    if not raw:
        return
    added, length = len(_units(raw)), value.size()
    long = value.get(0, 1) & 1
    capacity = (value.get(0, 8) & ~1) - 1 if long else 10
    if length + added > _LIMIT:
        raise PrimaryProgramLimit('notification appended string exceeds the offline domain')
    if length + added > capacity:
        count = (max(capacity * 2, length + added) | 7) + 1
        pointer = value.runtime._operator_new(count * 2)
        value._payload(value.value() + raw, pointer, '75D940.append_growth_payload')
        if long:
            value.runtime._free_allocation(value.get(16, 8))
        value.set(16, pointer, 8, '75D940.append_pointer')
        value.set(0, count | 1, 8, '75D940.append_capacity')
        value.set(8, length + added, 8, '75D940.append_length')
    else:
        pointer = value.get(16, 8) if long else value.address + 2
        value.runtime.memory.write(pointer + length * 2, raw + b'\0\0', source='75D940.append_units_and_NUL')
        value.set(8 if long else 0, length + added if long else (length + added) * 2,
                  8 if long else 1, '75D940.append_length')


def _copy(runtime, destination, source):
    current = _WideString(runtime, address=destination)
    value = _WideString(runtime, address=source)
    if not current.get(0, 1) & 1 and not value.get(0, 1) & 1:
        value.write_header(destination)
    else:
        current.assign(value.value())


def construct(runtime, address):
    with _constructor_phase(runtime, address):
        return _construct(runtime, address)


def _construct(runtime, address):
    memory = runtime.memory
    memory._span(address, 0xE0)
    frame, rbp = _frame(runtime, 0x4E0, '2E02AE0.environment_frame')
    temporaries = []
    record = 0
    initialized = completed = False
    try:
        system_version(runtime, address + 0x10)
        memory.store(address, 0, 1, source='2E02AE0.flag')
        memory.write(address + 0x34, bytes(0xAC), source='2E02AE0.zero_vectors')
        initialized = True
        for offset in (0x68, 0x38, 0x50, 0x98):
            _WideString(runtime, address=address + offset).assign(b'')
        memory.store(address + 4, 0, 4, source='2E02AE0.flags')
        _WideString(runtime, address=address + 0xB0).assign(b'')
        memory.store(address + 8, 0x01010101, 4, source='2E02AE0.flags')
        service = _WideString(runtime, address=address + 0xC8)
        service.assign('Service Pack '.encode('utf-16-le'))
        memory.store(address + 12, 0, 1, source='2E02AE0.flag')
        memory.store(address + 0x34, memory.load(address + 0x10, 4), 4, source='2E02AE0.classification_copy')
        number = _WideString.construct(runtime, str(memory.load(address + 0x28, 4, signed=True)).encode('utf-16-le'))
        temporaries.append(number)
        _append(service, number.value())
        if _filename(runtime, 0, rbp + 0x1B0):
            _WideString(runtime, address=address + 0x68).assign(_terminated(runtime, rbp + 0x1B0))
        if _filename(runtime, runtime.image_base, rbp - 0x60):
            _WideString(runtime, address=address + 0x38).assign(_terminated(runtime, rbp - 0x60))
        directory(runtime, address + 0xB0)
        temporary = rbp + 0x3E0
        memory.write(temporary, bytes(24), source='2E02AE0.zero_basename_temporary')
        basename = _WideString(runtime, address=temporary)
        temporaries.append(basename)
        path_input = _WideString.construct(runtime, _WideString(runtime, address=address + 0x68).value())
        try:
            path_input.write_header(rbp + 0x420)
            path_name(runtime, rbp + 0x420, temporary, 0)
        finally:
            path_input.destroy()
        pointer = basename.get(16, 8) if basename.get(0, 1) & 1 else temporary + 2
        for index in range(basename.size()):
            unit = lower_unit(runtime, memory.load(pointer + index * 2, 2))
            memory.store(pointer + index * 2, unit, 2, source='2E02AE0.lower_basename_unit')
        _copy(runtime, address + 0x80, temporary)
        record = metadata(runtime, address + 0x68)
        if record:
            version = rbp + 0x420
            memory.write(version, bytes(24), source='35A2FF0.zero_version_temporary')
            try:
                file_version(runtime, record, version)
            except BaseException:
                _cleanup((_WideString(runtime, address=version).destroy,))
                raise
            _WideString(runtime, address=version).write_header(address + 0x98)
            buffer = memory.load(record, 8)
            memory.store(record + 8, buffer, 8, source='2E02AE0.release_resource_end')
            released_record, record = record, 0
            _destroy_metadata(runtime, released_record)
        completed = True
        return address
    finally:
        primary, failures = sys.exception(), []
        cleanup = ([lambda: _destroy_metadata(runtime, record)] if record else [])
        cleanup += [value.destroy for value in reversed(temporaries)]
        if initialized and not completed:
            cleanup += [_WideString(runtime, address=address + offset).destroy
                        for offset in (0x38, 0x50, 0x68, 0x80, 0x98, 0xB0, 0xC8)]
        cleanup.append(lambda: memory.unmap(frame))
        for release in cleanup:
            try:
                release()
            except BaseException as error:
                failures.append(error)
        for error in failures:
            if primary is not None:
                primary.add_note('notification constructor source cleanup failed: ' + type(error).__name__ + ': ' + str(error))
            else:
                primary = error
        if failures and sys.exception() is None:
            raise primary


def invoke(runtime, rva, values):
    if rva == 0x2E02AE0 and len(values) == 1:
        return construct(runtime, values[0])
    raise InputError('notification environment source entry argument count mismatch')
