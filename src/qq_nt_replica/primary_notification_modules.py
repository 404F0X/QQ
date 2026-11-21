from contextlib import contextmanager, ExitStack
import os
import sys
from threading import get_ident, get_native_id

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_IMPORTS = {'GetCurrentProcess': 0x490FDE0, 'GetVersionExW': 0x4910028,
    'GetModuleFileNameA': 0x490FEE8, 'PathRemoveFileSpecA': 0x4910AE0,
    'K32EnumProcessModules': 0x4910140, 'K32GetModuleFileNameExA': 0x4910148,
    'PathFindFileNameA': 0x4910AB0}
_FACTORY = object()


def require_claim(runtime):
    from .primary_direct_scopes import PrimaryDirectScope
    scope = runtime.__dict__.get('_primary_direct_scope')
    if type(scope) is not PrimaryDirectScope:
        raise PrimarySemanticUnavailable('module collector requires its original direct scope')
    return scope.require_module_collector_phase()


class _ModuleCollectorClaim:
    def __init__(self, runtime, source, factory):
        from .primary_direct_scopes import PrimaryDirectScope
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        if factory is not _FACTORY or source.f_code is not collect.__code__ or source.f_locals.get('runtime') is not runtime:
            raise InputError('module collector requires its canonical source factory')
        self.runtime, self.source = runtime, source
        self.scope = runtime.__dict__.get('_primary_direct_scope')
        self.owner = getattr(self.scope, 'notification_owner', None)
        if (type(self.scope) is not PrimaryDirectScope or type(self.owner) is not _NotificationWorkerOwner or
                self.scope.runtime is not runtime or runtime.__dict__.get('_primary_notification_worker_owner') is not self.owner or
                not self.scope._valid_notification()):
            raise PrimarySemanticUnavailable('module collector requires its real active notification worker owner')
        self.identity = os.getpid(), get_ident(), get_native_id()
        self.generation, self.serial, self.lease = runtime._main_generation, self.owner.serial, self.owner.lease
        self.frame = source.f_locals.get('frame')
        if type(self.frame) is not int:
            raise InputError('module collector requires its independent original stack frame')
        self.region, offset = runtime.memory._span(self.frame, 0x2738)
        if self.region.address != self.frame or offset or len(self.region.data) != 0x2738:
            raise InputError('module collector stack allocation identity differs')
        from .primary_device_notification_worker import _first_prefix
        prefix = source.f_back
        while prefix is not None and prefix.f_code is not _first_prefix.__code__:
            prefix = prefix.f_back
        if prefix is None or prefix.f_locals.get('runtime') is not runtime:
            raise InputError('module collector requires its real retained first-prefix ancestor')
        self.prefix = prefix
        self.prefix_address = prefix.f_locals.get('frame')
        self.prefix_region, offset = runtime.memory._span(self.prefix_address, 0x148)
        if self.prefix_region.address != self.prefix_address or offset or len(self.prefix_region.data) != 0x148:
            raise InputError('module collector prefix retained frame differs')
        self.active, self.facade = True, None

    def valid(self):
        from .primary_device_notification_worker import _first_prefix
        from .primary_sign import PrimaryRuntime
        frame, invoke, prefix = sys._getframe(1), None, None
        found = False
        while frame is not None:
            if frame is self.source:
                found = True
            if (found and invoke is None and frame.f_code is PrimaryRuntime.invoke.__code__ and
                    frame.f_locals.get('self') is self.runtime and frame.f_locals.get('rva') == 0x1D20B30):
                invoke = frame
            if found and frame.f_code is _first_prefix.__code__ and frame.f_locals.get('runtime') is self.runtime:
                prefix = frame
                break
            frame = frame.f_back
        runtime, scope, owner = self.runtime, self.scope, self.owner
        return (self.active and found and self.identity == (os.getpid(), get_ident(), get_native_id()) and
                self.source.f_code is collect.__code__ and self.source.f_locals.get('runtime') is runtime and
                self.source.f_locals.get('frame') == self.frame and invoke is not None and prefix is not None and
                invoke.f_locals.get('self') is runtime and invoke.f_locals.get('rva') == 0x1D20B30 and
                type(invoke.f_locals.get('cells')) is tuple and invoke.f_locals.get('cells') == () and
                prefix is self.prefix and prefix.f_locals.get('frame') == self.prefix_address and
                any(region is self.prefix_region for region in runtime.memory._regions) and
                any(region is self.region for region in runtime.memory._regions) and
                runtime.__dict__.get('_primary_direct_scope') is scope and scope.notification_owner is owner and
                runtime.__dict__.get('_primary_notification_worker_owner') is owner and owner.runtime is runtime and
                scope._valid_notification() and owner.serial == self.serial and owner.lease is self.lease and
                self.lease.active and not self.lease.suspended and not self.lease.closing and
                runtime._main_generation == self.generation and runtime._active_main is None and
                runtime.__dict__.get('_notification_module_collector_claim') is self and
                runtime.__dict__.get('notification_module_observations') is self.facade and
                runtime.__dict__.get('_notification_parent_claim') is None and
                runtime.__dict__.get('_notification_constructor_claim') is None)


@contextmanager
def _collector_phase(runtime):
    if (runtime.primary_backend != 'direct' or runtime.__dict__.get('_notification_module_collector_claim') is not None or
            runtime.__dict__.get('notification_module_observations') is not None or
            runtime.__dict__.get('_notification_parent_claim') is not None or
            runtime.__dict__.get('_notification_constructor_claim') is not None):
        raise PrimarySemanticUnavailable('module collector requires its separate nonnested notification source window')
    claim = _ModuleCollectorClaim(runtime, sys._getframe(2), _FACTORY)
    runtime._notification_module_collector_claim = claim
    try:
        if require_claim(runtime) is not claim:
            raise InputError('module collector lost its initial source claim')
        yield claim
        if not claim.valid():
            raise InputError('module collector source claim expired before completion')
    finally:
        primary, failures = sys.exception(), []
        claim.active, claim.source = False, None
        if runtime.__dict__.get('_notification_module_collector_claim') is claim:
            runtime.__dict__.pop('_notification_module_collector_claim')
        else:
            failures.append(InputError('module collector claim was substituted during cleanup'))
        claim.runtime = claim.scope = claim.owner = claim.lease = claim.facade = None
        claim.prefix = claim.region = claim.prefix_region = None
        if failures:
            raise BaseExceptionGroup('module collector claim cleanup failed', ([primary] if primary is not None else []) + failures)


@contextmanager
def _module_environment(runtime):
    from .primary_windows_notification_environment import WindowsNotificationEnvironmentObservations
    claim = require_claim(runtime)
    prior = runtime.__dict__.get('notification_environment_observations')
    if type(prior) is not WindowsNotificationEnvironmentObservations or claim.source.f_locals.get('gate') != 1:
        raise PrimarySemanticUnavailable('module collector requires its enabled feature and original bound environment')
    environment = None
    had, previous = 'notification_module_observations' in runtime.__dict__, runtime.__dict__.get('notification_module_observations')
    try:
        environment = prior.module_collector_environment(runtime, claim.owner)
        claim.facade = environment
        runtime.notification_module_observations = environment
        environment.check(runtime)
        yield environment
    finally:
        primary, failures = sys.exception(), []
        if environment is not None:
            if runtime.__dict__.get('notification_module_observations') is environment:
                if had:
                    runtime.notification_module_observations = previous
                else:
                    runtime.__dict__.pop('notification_module_observations')
            else:
                failures.append(InputError('module collector observation slot was substituted'))
            claim.facade = None
            try:
                prior.release_module_collector_environment(environment)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise BaseExceptionGroup('module collector environment cleanup failed', ([primary] if primary is not None else []) + failures)


def _observe(runtime, name, arguments, address=0, index=None):
    claim = require_claim(runtime)
    if (name not in _IMPORTS or type(arguments) is not tuple or
            runtime.worker_imports.get(name) is None or
            runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != runtime.worker_imports[name] or
            runtime.__dict__.get('notification_module_observations') is not claim.facade or claim.facade is None):
        raise PrimarySemanticUnavailable('module collector API requires its finite current source IAT and facade')
    return claim.facade.take(runtime, name, arguments, address, index)


def invoke_api(runtime, name, values):
    claim = require_claim(runtime)
    arities = {'GetCurrentProcess': 0, 'GetVersionExW': 1, 'GetModuleFileNameA': 3,
        'PathRemoveFileSpecA': 1, 'K32EnumProcessModules': 4, 'K32GetModuleFileNameExA': 4,
        'PathFindFileNameA': 1}
    if name not in arities or type(values) is not tuple or len(values) != arities[name] or any(type(value) is not int for value in values):
        raise InputError('module collector physical API argument shape differs')
    if name == 'GetCurrentProcess':
        return _observe(runtime, name, ())
    if name == 'GetVersionExW':
        return _observe(runtime, name, (284,), values[0])
    if name == 'GetModuleFileNameA':
        module, address, capacity = values
        return _observe(runtime, name, (module, capacity), address)
    if name in ('PathRemoveFileSpecA', 'PathFindFileNameA'):
        return _observe(runtime, name, () if name == 'PathRemoveFileSpecA' else values, values[0])
    if name == 'K32EnumProcessModules':
        process, address, capacity, needed = values
        if not claim.frame <= needed <= claim.frame + 0x2738 - 4:
            raise InputError('module needed DWORD leaves its actual collector frame')
        result, count = _observe(runtime, name, (process, capacity), address)
        runtime.memory.store(needed, count, 4, source='notification_modules.actual_needed_DWORD')
        return result
    process, module, address, capacity = values
    return _observe(runtime, name, (process, module, capacity), address,
        claim.source.f_locals.get('module_index'))


def invoke_thunk(runtime, rva, values):
    name = {0x3EB5EA0: 'K32EnumProcessModules', 0x3EB5EB0: 'K32GetModuleFileNameExA'}.get(rva)
    if name is None:
        raise InputError('module collector thunk is outside its exact source set')
    require_claim(runtime)
    if runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != runtime.worker_imports.get(name):
        raise PrimarySemanticUnavailable('module collector thunk current IAT differs')
    return invoke_api(runtime, name, values)


def collect(runtime):
    from .primary_notification_vectors import _feature
    from .primary_worker_response import _frame
    frame, rbp = _frame(runtime, 0x2738, '1D20B30.module_collector_frame')
    try:
        with _collector_phase(runtime):
            gate = _feature(runtime, 10)
            if gate != 1:
                _collector_log(runtime, 169, b'report process modules: switch off.')
                return 0
            with _module_environment(runtime):
                process = invoke_api(runtime, 'GetCurrentProcess', ())
                if not process:
                    _collector_log(runtime, 175, b'report process modules: open failed.')
                    return 0
                memory = runtime.memory
                memory.write(rbp + 0x2294, bytes(280), source='1D20BCA.version_tail_zero')
                memory.store(rbp + 0x2290, 284, 4, source='1D20BCF.version_size')
                invoke_api(runtime, 'GetVersionExW', (rbp + 0x2290,))
                with ExitStack() as owned:
                    _version_string(runtime, rbp)
                    owned.callback(_destroy_string, runtime, rbp + 0x2240)
                    _parent_record(runtime, rbp, owned)
                    directories = rbp + 0x2260
                    memory.write(directories, bytes(32), source='1D20E88.empty_directory_set')
                    memory.store(directories + 32, 0x3F800000, 4, source='1D20E96.directory_load_factor')
                    owned.callback(_destroy_directories, runtime, directories)
                    _directory_candidates(runtime, rbp, directories)
                    invoke_thunk(runtime, 0x3EB5EA0, (process, rbp - 0x40, 8192, rbp + 0x245C))
                    count = memory.load(rbp + 0x245C, 4) >> 3
                    memory.store(rbp + 0x2570, count, 4, source='1D20FF9.module_count')
                    memory.store(rbp + 0x2220, process, 8, source='1D21009.module_process')
                    for module_index in range(count):
                        if module_index >= 8192 // 8:
                            raise PrimaryProgramLimit('module enumeration needed exceeds its available initialized handle prefix')
                        handle = memory.load(rbp - 0x40 + module_index * 8, 8)
                        result = invoke_thunk(runtime, 0x3EB5EB0, (process, handle, rbp + 0x2460, 260))
                        if not result & 0xFFFFFFFF:
                            continue
                        buffer = _SourceBuffer(runtime, rbp + 0x2460, 260)
                        try:
                            raw = buffer.cstring()[:-1]
                        finally:
                            buffer.close()
                        from .primary_logger import _String
                        from .primary_notification_vectors import _lower_string
                        path = _String.construct(runtime, raw)
                        path.write_to(rbp + 0x25E8)
                        try:
                            _lower_string(runtime, path)
                            path.write_to(rbp + 0x25E8)
                            if _module_allowed(runtime, rbp, directories):
                                _append_module(runtime, rbp)
                        finally:
                            _destroy_string(runtime, rbp + 0x25E8)
                    from .primary_notification_module_records import _record_range
                    from .primary_worker_consumer import _invoke
                    begin, end, records, capacity = _record_range(runtime, rbp + 0x2438)
                    _collector_log(runtime, 284, b'report process modules: num %d.', records)
                    if not records:
                        return 1
                    _invoke(runtime, 0x1D24140, rbp + 0x23B0, rbp + 0x2590)
                    owned.callback(_destroy_string, runtime, rbp + 0x2590)
                    if not memory.load(runtime.image_base + 0x6751B30, 4) & 1:
                        raise PrimarySemanticUnavailable('1D237AD collector receiver cold initializer requires its original writes and registration')
                    pointer, length = _prepare_module_handoff(runtime, rbp)
                    _invoke(runtime, 0x1CE6920, runtime.image_base + 0x6751AB8, rbp + 0x2228,
                        pointer, length, rbp + 0x21E0, rbp + 0x2460, 1)
                    for offset in (0x2478, 0x2460, 0x2578, 0x25E8):
                        _destroy_string(runtime, rbp + offset)
                    return 1
    finally:
        runtime.memory.unmap(frame)


def _destroy_string(runtime, address):
    from .primary_logger import _String
    _String.read(runtime, address).destroy()


def _collector_log(runtime, line, template, *arguments):
    from .primary_logger import log
    source = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\platforms\\Windows\\libsecxx\\envinfo\\enummodules.cpp'
    return log(runtime, source, line, template, b'[FGESDK]', 1, *arguments)


def _version_string(runtime, rbp):
    from .primary_logger import _String
    from .primary_worker_consumer import _append
    memory = runtime.memory
    with ExitStack() as owned:
        for offset, field in ((-0x40, 12), (0x2460, 8), (0x2590, 4)):
            _String.construct(runtime, str(memory.load(rbp + 0x2290 + field, 4)).encode('ascii')).write_to(rbp + offset)
            owned.callback(_destroy_string, runtime, rbp + offset)
        for source, destination, suffix in ((0x2590, 0x23B0, b'.'),
                (0x23B0, 0x1FC0, _String.read(runtime, rbp + 0x2460).value()),
                (0x1FC0, 0x20D0, b'.'), (0x20D0, 0x2240, _String.read(runtime, rbp - 0x40).value())):
            value = _String.read(runtime, rbp + source)
            _append(value, suffix)
            value.write_to(rbp + source)
            value.write_to(rbp + destination)
            memory.write(rbp + source, bytes(24), source='1D20C41.version_temporary_moved')
            if destination != 0x2240:
                owned.callback(_destroy_string, runtime, rbp + destination)


def _parent_record(runtime, rbp, owned):
    from .primary_logger import _String
    from .primary_worker_consumer import _invoke
    memory, base, parent = runtime.memory, runtime.image_base, rbp + 0x23B0
    memory.store(parent, base + 0x414BA28, 8, source='1D20D74.parent_vtable')
    for offset in (8, 0x18, 0x28, 0x38):
        memory.write(parent + offset, bytes(16), source='1D20D7E.parent_fields_zero')
    memory.store(parent + 0x48, 0, 8, source='1D20D9A.parent_field_zero')
    for offset in (0x58, 0x68, 0x78, 0x88):
        memory.write(parent + offset, bytes(16), source='1D20DA5.parent_tail_zero')
    memory.store(parent + 0x98, 0, 8, source='1D20DC1.parent_vector_zero')
    owned.callback(_destroy_parent, runtime, parent)
    for offset, field, frontier in ((8, 0xE0, '1D23552'), (0x20, 0x48, '1D23619')):
        if not memory.load(base + 0x6751800, 4) & 1:
            raise PrimarySemanticUnavailable(frontier + ' collector configuration cold initializer requires its original writes and registration')
        view = _invoke(runtime, 0x1BB9250, base + 0x67516B0)
        _String.read(runtime, view + field).clone().write_to(parent + offset)
    _String.construct(runtime, b'').write_to(parent + 0x38)
    memory.store(parent + 0x50, 3, 4, source='1D20E42.parent_kind')
    _String.read(runtime, rbp + 0x2240).clone().write_to(parent + 0x58)
    if not memory.load(base + 0x6751800, 4) & 1:
        raise PrimarySemanticUnavailable('1D236E3 collector configuration cold initializer requires its original writes and registration')
    view = _invoke(runtime, 0x1BB9250, base + 0x67516B0)
    _String.read(runtime, view + 0x78).clone().write_to(parent + 0x70)


def _directory_candidates(runtime, rbp, directories):
    from .primary_worker_consumer import _invoke
    for address, capacity, module, removals in ((rbp + 0x20D0, 261, 0, (1,)),
            (rbp + 0x1FC0, 260, runtime.image_base, (1, 2, 2))):
        runtime.memory.write(address, bytes(capacity), source='1D20EB2.filename_buffer_zero')
        invoke_api(runtime, 'GetModuleFileNameA', (module, address, capacity))
        for count in removals:
            for ignored in range(count):
                invoke_api(runtime, 'PathRemoveFileSpecA', (address,))
            buffer = _SourceBuffer(runtime, address, capacity)
            try:
                if len(buffer.cstring()) - 1 >= 6:
                    _invoke(runtime, 0x1D209F0, address, directories)
            finally:
                buffer.close()


def _destroy_directories(runtime, address):
    from .primary_logger import _String
    memory = runtime.memory
    current = memory.load(address + 16, 8)
    visited = set()
    while current:
        if current in visited or len(visited) >= 4096:
            raise PrimaryProgramLimit('module directory destruction exceeds its bounded original chain')
        visited.add(current)
        following = memory.load(current, 8)
        _String.read(runtime, current + 16).destroy()
        runtime._free_allocation(current)
        current = following
    buckets = memory.load(address, 8)
    memory.store(address, 0, 8, source='1D2331F.directory_buckets_clear')
    if buckets:
        runtime._free_allocation(buckets)


def _destroy_parent(runtime, parent):
    from .primary_logger import _String
    from .primary_notification_module_records import _record_range
    memory = runtime.memory
    memory.store(parent, runtime.image_base + 0x414BA28, 8, source='1D2333B.parent_destroy_vtable')
    begin, end, count, capacity = _record_range(runtime, parent + 0x88)
    for record in range(end - 0x58, begin - 1, -0x58):
        memory.store(record, runtime.image_base + 0x414BA98, 8, source='1D233AF.child_destroy_vtable')
        for offset in (0x40, 0x20, 8):
            _String.read(runtime, record + offset).destroy()
    memory.store(parent + 0x90, begin, 8, source='1D233ED.child_vector_end')
    if begin:
        runtime._free_allocation(begin)
    for offset in (0x70, 0x58, 0x38, 0x20, 8):
        _String.read(runtime, parent + offset).destroy()


def _module_allowed(runtime, rbp, directories):
    from .primary_logger import _String
    from .primary_notification_vectors import _contains, _lower_string
    from .primary_worker_consumer import _invoke
    path = rbp + 0x25E8
    value = _String.read(runtime, path).value()
    for literal in (b'\\temp\\', b'bot', b'\\tmp\\'):
        if _contains(value, literal):
            return True
    with ExitStack() as owned:
        _String.read(runtime, path).clone().write_to(rbp + 0x2208)
        owned.callback(_destroy_string, runtime, rbp + 0x2208)
        lowered = _String.read(runtime, rbp + 0x2208).clone()
        lowered.write_to(rbp + 0x2590)
        owned.callback(_destroy_string, runtime, rbp + 0x2590)
        _lower_string(runtime, lowered)
        lowered.write_to(rbp + 0x2590)
        value = lowered.value()
        admitted = False
        for literal in (b'liteloader', b'llone', b'lltwo', b'napcat', b'llrobot', b'qqbot', b'llbot'):
            if _contains(value, literal):
                admitted = True
                break
    if admitted:
        return True
    if _invoke(runtime, 0x1D1F8D0, path) & 255:
        return False
    return not _invoke(runtime, 0x1D20720, path, directories) & 255


def _append_module(runtime, rbp):
    from .primary_logger import _String, _cstring
    from .primary_notification_module_records import _record_range
    from .primary_worker_consumer import _invoke
    memory, record, vector = runtime.memory, rbp + 0x2590, rbp + 0x2438
    _invoke(runtime, 0x1D24080, record)
    try:
        _destroy_string(runtime, record + 0x40)
        _String.construct(runtime, _cstring(runtime, rbp + 0x2460)).write_to(record + 0x40)
        alias = invoke_api(runtime, 'PathFindFileNameA', (rbp + 0x2460,))
        if alias:
            _destroy_string(runtime, record + 0x20)
            _String.construct(runtime, _cstring(runtime, alias)).write_to(record + 0x20)
        begin, end, count, capacity = _record_range(runtime, vector, True)
        if count < capacity:
            _invoke(runtime, 0x1D27430, end, record)
            memory.store(vector + 8, end + 0x58, 8, source='1D2164D.module_vector_end')
        else:
            _invoke(runtime, 0x1D271F0, vector, record)
    finally:
        memory.store(record, runtime.image_base + 0x414BA98, 8, source='1D2167A.temporary_record_vtable')
        for offset in (0x40, 0x20, 8):
            _destroy_string(runtime, record + offset)


def _prepare_module_handoff(runtime, rbp):
    from .primary_logger import _String
    memory, base = runtime.memory, runtime.image_base
    memory.write(rbp + 0x25E8, bytes(2), source='1D22C75.empty_metadata_second')
    memory.write(rbp + 0x2578, bytes(2), source='1D22C7E.empty_metadata_first')
    memory.write(rbp + 0x2460, bytes(48), source='1D22C8A.empty_metadata_storage')
    _String.read(runtime, rbp + 0x2578).clone().write_to(rbp + 0x2460)
    _String.read(runtime, rbp + 0x25E8).clone().write_to(rbp + 0x2478)
    memory.store(rbp + 0x21E8, base + 0x414BB08, 8, source='1D22CCF.inline_module_callback')
    serialized = _String.read(runtime, rbp + 0x2590)
    long = serialized.get(0, 1) & 1
    count = serialized.get(8, 4) if long else serialized.get(0, 1) >> 1
    pointer = serialized.get(16, 8) if long else rbp + 0x2591
    memory.store(rbp + 0x2200, rbp + 0x21E8, 8, source='1D22D03.inline_module_callback_pointer')
    tag = _String.construct(runtime, b'ReportDylib')
    tag.write_to(rbp + 0x2228)
    return pointer, count


def _insert_directory(runtime, path, directories):
    from .primary_logger import _String, _cstring
    from .primary_notification_vectors import _lower_string
    from .primary_worker_consumer import _invoke
    from .primary_worker_response import _frame
    if not runtime.memory.load(path, 1):
        return None
    frame, ignored = _frame(runtime, 0x58, '1D209F0.directory_insert_frame')
    try:
        value = _String.construct(runtime, _cstring(runtime, path))
        value.write_to(frame + 0x38)
        try:
            _lower_string(runtime, value)
            value.write_to(frame + 0x38)
            _invoke(runtime, 0x92FC4, directories, frame + 0x28, frame + 0x38, frame + 0x38)
        finally:
            value.destroy()
    finally:
        runtime.memory.unmap(frame)
    return None


def _path_set_excluded(runtime, path, directories):
    from .primary_logger import _String, _cstring
    from .primary_notification_vectors import _contains
    from .primary_worker_consumer import _invoke
    from .primary_worker_response import _frame
    frame, ignored = _frame(runtime, 0x58, '1D20720.path_set_frame')
    try:
        value = _String.read(runtime, path)
        pointer = value.get(16, 8) if value.get(0, 1) & 1 else path + 1
        basename = invoke_api(runtime, 'PathFindFileNameA', (pointer,))
        current, visited = runtime.memory.load(directories + 16, 8), set()
        while current:
            if current in visited or len(visited) >= 4096:
                raise PrimaryProgramLimit('module path-set traversal exceeds its bounded original chain')
            visited.add(current)
            key = _String.read(runtime, current + 16).value()
            if not key or _contains(value.value(), key):
                temporary = _String.construct(runtime, _cstring(runtime, basename))
                temporary.write_to(frame + 0x28)
                try:
                    _invoke(runtime, 0x8ED82, runtime.image_base + 0x677DF20, frame + 0x40, frame + 0x28)
                    node = runtime.memory.load(frame + 0x40, 8)
                finally:
                    temporary.destroy()
                if node:
                    return 1
                runtime.memory.write(frame + 0x2A, b'api-ms-win\0\0', source='1D20990.api_set_literal')
                if _invoke(runtime, 0x3E6D7B0, basename, frame + 0x2A):
                    return 1
            current = runtime.memory.load(current, 8)
        return 0
    finally:
        runtime.memory.unmap(frame)


def _substring(runtime, haystack, needle):
    from .primary_logger import _cstring
    if not runtime.memory.load(needle, 1):
        return haystack
    first, second = _cstring(runtime, haystack) + b'\0', _cstring(runtime, needle) + b'\0'

    def vector(pointer):
        return pointer & 0xFFF <= 0xFF0

    def backed(pointer):
        runtime.memory._span(pointer, 16)
        guard = getattr(runtime.memory, '_consumed_mgf_guard', None)
        if guard is not None:
            guard.guard_overlap(pointer, 16)

    def matches(start):
        offset = 0
        while True:
            width = 16 if vector(haystack + start + offset) and vector(needle + offset) else 1
            if width == 16:
                backed(haystack + start + offset)
                backed(needle + offset)
            for index in range(width):
                if second[offset + index] == 0:
                    return True
                if first[start + offset + index] != second[offset + index]:
                    return False
            offset += width

    start, first_result = 0, -1
    while True:
        if vector(haystack + start):
            backed(haystack + start)
            stop = min(start + 16, len(first))
            candidate = next((index for index in range(start, stop) if first[index] in (0, second[0])), None)
            if candidate is None:
                start += 16
                continue
            start = candidate
        if not first[start]:
            break
        if first[start] == second[0] and matches(start):
            first_result = start
            break
        start += 1

    if vector(needle):
        backed(needle)
    start, second_result = 0, -1
    while True:
        if vector(haystack + start):
            backed(haystack + start)
            candidate = None
            for index in range(16):
                partial = True
                for offset in range(min(16 - index, len(second) - 1)):
                    position = start + index + offset
                    if position >= len(first) or first[position] != second[offset]:
                        partial = False
                        break
                if partial:
                    candidate = start + index
                    break
            if candidate is None:
                if len(first) <= start + 16:
                    break
                start += 16
                continue
            start = candidate
        if not first[start]:
            break
        if first[start] == second[0] and matches(start):
            second_result = start
            break
        start += 1
    if first_result != second_result:
        raise InputError('module substring source branches disagree within the admitted buffer domain')
    return haystack + first_result if first_result >= 0 else 0


def invoke_helper(runtime, rva, values):
    from .primary_worker_consumer import _invoke
    definitions = {0x1D209F0: (_insert_directory, _directory_candidates),
        0x1D20720: (_path_set_excluded, _module_allowed), 0x3E6D7B0: (_substring, _path_set_excluded)}
    if rva not in definitions or type(values) is not tuple or len(values) != 2 or any(type(value) is not int for value in values):
        raise InputError('module helper requires its exact two physical pointer arguments')
    claim = require_claim(runtime)
    caller = sys._getframe(1)
    while caller is not None and caller.f_code is not _invoke.__code__:
        caller = caller.f_back
    expected = definitions[rva][1]
    if (caller is None or caller.f_locals.get('runtime') is not runtime or caller.f_locals.get('rva') != rva or
            caller.f_locals.get('values') != values or caller.f_back is None or caller.f_back.f_code is not expected.__code__ or
            caller.f_back.f_locals.get('runtime') is not runtime or not claim.valid()):
        raise InputError('module helper requires its canonical collector source callsite')
    source = caller.f_back.f_locals
    if rva == 0x3E6D7B0:
        from .primary_logger import _String, _cstring
        frame, value, pointer = source.get('frame'), source.get('value'), source.get('pointer')
        if (type(frame) is not int or type(value) is not _String or value.runtime is not runtime or
                pointer != (value.get(16, 8) if value.get(0, 1) & 1 else source.get('path') + 1) or
                values != (source.get('basename'), frame + 0x2A) or
                runtime.memory.read(values[1], 12) != b'api-ms-win\0\0' or
                not pointer <= values[0] <= pointer + len(_cstring(runtime, pointer)) or
                value.value() != _String.read(runtime, source.get('path')).value()):
            raise InputError('module substring requires its live original basename alias and source literal')
        for pointer in values:
            length = len(_cstring(runtime, pointer)) + 1
            region, offset = runtime.memory._span(pointer, length)
            home, ignored = runtime.memory._span(frame, 16)
            if (pointer < frame + 16 and frame < pointer + length or
                    region is not home and region.data.obj is home.data.obj):
                raise InputError('module substring input aliases its private source save home')
    elif rva == 0x1D209F0:
        if values != (source.get('address'), source.get('directories')):
            raise InputError('module directory helper leaves its source candidate and set')
    elif values != (source.get('path'), source.get('directories')):
        raise InputError('module exclusion helper leaves its source path and set')
    return definitions[rva][0](runtime, *values)


class _SourceBuffer:
    def __init__(self, runtime, address, capacity):
        if type(address) is not int or type(capacity) is not int or not 0 < capacity <= 8192:
            raise InputError('module source buffer requires its finite actual span')
        self.runtime, self.address, self.capacity = runtime, address, capacity
        self.region, self.offset = runtime.memory._span(address, capacity)
        self.closed = False

    def check(self):
        if self.closed or not any(region is self.region for region in self.runtime.memory._regions):
            raise InputError('module source buffer allocation generation expired')
        region, offset = self.runtime.memory._span(self.address, self.capacity)
        if region is not self.region or offset != self.offset:
            raise InputError('module source buffer was substituted')

    def initial(self):
        self.check()
        start, stop = self.offset, self.offset + self.capacity
        return bytes(self.region.data[start:stop]), bytes(self.region.initialized[start:stop])

    def apply(self, effects):
        self.check()
        if type(effects) is not tuple or len(effects) != 2:
            raise InputError('module source effects require bytes and justified knownness')
        raw, mask = effects
        if (type(raw) is not bytes or type(mask) is not bytes or len(raw) != self.capacity or
                len(mask) != self.capacity or any(value not in (0, 1) for value in mask)):
            raise InputError('module effects leave their actual source buffer')
        initial, known = self.initial()
        if any(before and not after for before, after in zip(known, mask)):
            raise InputError('module effects cannot discard source initialized bytes')
        index = 0
        while index < self.capacity:
            if not mask[index]:
                index += 1
                continue
            stop = index + 1
            while stop < self.capacity and mask[stop]:
                stop += 1
            self.runtime.memory.write(self.address + index, raw[index:stop], source='notification_modules.actual_API_effect')
            index = stop

    def cstring(self):
        self.check()
        for index in range(self.capacity):
            if self.runtime.memory.load(self.address + index, 1) == 0:
                return self.runtime.memory.read(self.address, index + 1)
        raise PrimaryProgramLimit('module source CString lacks its bounded known terminator')

    def close(self):
        self.closed = True
        self.runtime = self.region = None


class _SourceAlias:
    def __init__(self, buffer, offset):
        raw = buffer.cstring()
        if type(offset) is not int or not 0 <= offset < len(raw):
            raise InputError('module path alias leaves its actual CString including terminator')
        self.buffer, self.offset, self.preimage = buffer, offset, raw
        self.closed = False

    def pointer(self):
        if self.closed or self.buffer.cstring() != self.preimage:
            raise InputError('module path alias source lifetime or bytes changed')
        return self.buffer.address + self.offset

    def close(self):
        self.closed = True
        self.buffer = self.preimage = None
        self.offset = None


class _Enumeration:
    def __init__(self, process, result, effects, output):
        if type(process) is not int or not process or type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
            raise InputError('module enumeration requires source scalar widths')
        if not result:
            raise PrimarySemanticUnavailable('failed module enumeration has unavailable needed output')
        if (type(effects) is not tuple or len(effects) != 2 or type(effects[0]) is not int or
                not 0 <= effects[0] <= 0xFFFFFFFF or effects[0] % 8 or type(effects[1]) is not bytes or
                len(effects[1]) != min(effects[0], 8192) or output.capacity != 8192):
            raise InputError('module enumeration requires the actual needed and ordered handle prefix')
        self.process, self.needed, self.output = process, effects[0], output
        self.handles = tuple(int.from_bytes(effects[1][index:index + 8], 'little') for index in range(0, len(effects[1]), 8))
        self.index = 0
        self.closed = False
        if effects[1]:
            output.runtime.memory.write(output.address, effects[1], source='notification_modules.actual_enumerated_handles')

    def current(self, index, handle):
        if self.closed or type(index) is not int or index != self.index or not 0 <= index < self.needed // 8:
            raise InputError('module enumeration loop slot is stale or out of order')
        self.output.check()
        if index >= len(self.handles):
            raise PrimaryProgramLimit('module enumeration needed exceeds available initialized handle prefix')
        if type(handle) is not int or handle != self.handles[index] or self.output.runtime.memory.load(self.output.address + index * 8, 8) != handle:
            raise InputError('module request differs from its exact current enumeration generation')
        return handle

    def advance(self):
        if self.closed:
            raise InputError('module enumeration was revoked')
        self.index += 1

    def close(self):
        self.closed = True
        self.output = None
        self.handles = ()
        self.process = None
