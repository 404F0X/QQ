import sys
from contextlib import contextmanager
from threading import get_ident

from .errors import InputError
from .primary_logger import _String, _cstring
from .primary_notification_json import COMPACT_ALLOC_CELL, COMPACT_FREE_CELL, DEFAULT_FREE_RVA, DEFAULT_MALLOC_RVA
from .primary_notification_json import compact, destroy
from .primary_notification_vectors import _api, _contains, _feature
from .primary_device_refresh import _StringVector, format_networks
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _invoke
from .primary_worker_response import _frame


_LIMIT = 1 << 20
_KEYWORDS = tuple(bytes.fromhex(raw) for raw in (
    'e8818ae5a4a9', 'e885bee8aeaf', 'e5b7a5e585b7', 'e4baa4e58f8b', 'e69c80e696b0e78988'))
_FACTORY = object()


class _ParentClaim:
    def __init__(self, runtime, output, source, factory):
        if factory is not _FACTORY:
            raise InputError('parent claim requires its original source factory')
        self.runtime, self.output, self.source = runtime, output, source
        self.thread, self.generation, self.active = get_ident(), runtime._main_generation, True
        self.owner = getattr(getattr(runtime, '_primary_direct_scope', None), 'notification_owner', None)

    def valid(self):
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        return (self.active and self.thread == get_ident() and self.generation == self.runtime._main_generation and
                frame is not None and frame.f_code is produce_parent.__code__ and
                frame.f_locals.get('runtime') is self.runtime and frame.f_locals.get('output') == self.output and
                self.runtime.__dict__.get('_notification_parent_claim') is self and
                (self.owner is None or self.owner.valid()))


@contextmanager
def _parent_phase(runtime, output):
    if runtime.__dict__.get('_notification_parent_claim') is not None:
        raise InputError('notification parent does not permit nested or replayed phases')
    claim = _ParentClaim(runtime, output, sys._getframe(2), _FACTORY)
    scope = runtime.__dict__.get('_primary_direct_scope')
    service = environment = None
    slots = {}
    runtime._notification_parent_claim = claim
    try:
        if runtime.primary_backend == 'direct':
            from .primary_direct_scopes import PrimaryDirectScope
            from .primary_sign import PrimaryRuntime
            from .primary_windows_notification_environment import WindowsNotificationEnvironmentObservations
            if type(scope) is not PrimaryDirectScope or scope.require_parent_phase() is not claim:
                raise PrimarySemanticUnavailable('notification parent requires its actual direct worker scope')
            caller = sys._getframe(1)
            while caller is not None and caller.f_code is not PrimaryRuntime.invoke.__code__:
                caller = caller.f_back
            if caller is None or caller.f_locals.get('self') is not runtime or caller.f_locals.get('rva') != 0x2E031A0:
                raise InputError('notification parent requires its actual routed source entry')
            parent = getattr(runtime, 'notification_environment_observations', None)
            if type(parent) is not WindowsNotificationEnvironmentObservations:
                raise InputError('notification parent requires its bound Windows environment')
            service = parent.notification_parent_service(runtime, claim.owner)
            environment = parent.parent_environment(runtime, claim.owner)
            for name, value in (('worker_observations', service.conversions),
                                ('notification_environment_observations', environment)):
                slots[name] = (name in runtime.__dict__, runtime.__dict__.get(name), value)
                runtime.__dict__[name] = value
            with service.parent_scope(runtime, claim.owner):
                yield claim
        else:
            if not claim.valid():
                raise InputError('notification parent lost its exact source frame')
            yield claim
    finally:
        primary, failures = sys.exception(), []
        for name, (had, prior, value) in reversed(tuple(slots.items())):
            if runtime.__dict__.get(name) is value:
                if had:
                    runtime.__dict__[name] = prior
                else:
                    runtime.__dict__.pop(name)
            else:
                failures.append(InputError('notification parent observer was replaced'))
        for resource in (environment, service):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    failures.append(error)
        claim.active = False
        claim.source = None
        if runtime.__dict__.get('_notification_parent_claim') is claim:
            runtime.__dict__.pop('_notification_parent_claim')
        else:
            failures.append(InputError('notification parent claim was replaced'))
        for error in failures:
            if primary is not None:
                primary.add_note('notification parent cleanup failed: ' + type(error).__name__)
            else:
                primary = error
        if failures and sys.exception() is None:
            raise primary


def render_vector(runtime, output, vector):
    return format_networks(runtime, output, vector)


def quote_command(runtime, output, source):
    value = _String(runtime, bytes(24), bytes((1,)) * 24)
    for byte in _String.read(runtime, source).value():
        _append(value, b'\\"' if byte == 34 else bytes((byte,)))
    value.write_to(output)
    return output


def _allocate(runtime, size):
    if not 0 < size <= _LIMIT:
        raise PrimaryProgramLimit('parent JSON allocation exceeds its bounded source domain')
    target = runtime.memory.load(runtime.image_base + COMPACT_ALLOC_CELL, 8)
    if target != runtime.image_base + DEFAULT_MALLOC_RVA:
        raise PrimarySemanticUnavailable('parent JSON malloc hook is outside the default CRT domain')
    return runtime._allocate(size, False, nullable=True)


def _release(runtime, pointer):
    if runtime.memory.load(runtime.image_base + COMPACT_FREE_CELL, 8) != runtime.image_base + DEFAULT_FREE_RVA:
        raise PrimarySemanticUnavailable('parent JSON free hook is outside the default CRT domain')
    runtime._free_allocation(pointer)


def _node(runtime, tag):
    address = _allocate(runtime, 64)
    if address:
        runtime.memory.write(address, bytes(64), source='2E031A0.zero_JSON_node')
        runtime.memory.store(address + 24, tag & 0xFFFFFFFF, 4, source='2E031A0.JSON_type')
    return address


def _copy_cstring(runtime, raw):
    value = raw.split(b'\0', 1)[0]
    address = _allocate(runtime, len(value) + 1)
    if address:
        runtime.memory.write(address, value + b'\0', source='2E031A0.JSON_CString')
    return address


def _link(runtime, parent, child):
    memory = runtime.memory
    current = memory.load(parent + 16, 8)
    if not current:
        memory.store(parent + 16, child, 8, source='2E031A0.JSON_first_child')
        return
    for ignored in range(4096):
        following = memory.load(current, 8)
        if not following:
            memory.store(current, child, 8, source='2E031A0.JSON_next')
            memory.store(child + 8, current, 8, source='2E031A0.JSON_previous')
            return
        current = following
    raise PrimaryProgramLimit('parent JSON child traversal exceeds the bounded source domain')


def _field(runtime, parent, key, raw=None, tag=4):
    node = _node(runtime, tag)
    if node:
        if raw is not None:
            runtime.memory.store(node + 32, _copy_cstring(runtime, raw), 8, source='2E031A0.JSON_value')
        old_key = runtime.memory.load(node + 56, 8)
        if old_key:
            _release(runtime, old_key)
        runtime.memory.store(node + 56, _copy_cstring(runtime, key), 8, source='2E031A0.JSON_key')
        _link(runtime, parent, node)
    return node


def _map_field(runtime, root, key, mapping):
    parent = _node(runtime, 6)
    if not parent:
        return
    node = runtime.memory.load(mapping + 16, 8)
    for ignored in range(4096):
        if not node:
            break
        _field(runtime, parent, _String.read(runtime, node + 16).value(), _String.read(runtime, node + 40).value())
        node = runtime.memory.load(node, 8)
    else:
        raise PrimaryProgramLimit('parent map traversal exceeds the bounded source domain')
    runtime.memory.store(parent + 56, _copy_cstring(runtime, key), 8, source='2E031A0.JSON_map_key')
    _link(runtime, root, parent)


def _empty_map(runtime, address):
    runtime.memory.write(address, bytes(32), source='2E031A0.empty_map')
    runtime.memory.store(address + 32, 0x3F800000, 4, source='2E031A0.map_load_factor')


def _destroy_map(runtime, address):
    from .primary_worker_consumer import _invoke
    memory = runtime.memory
    node = memory.load(address + 16, 8)
    for ignored in range(4096):
        if not node:
            break
        following = memory.load(node, 8)
        _String.read(runtime, node + 40).destroy()
        _String.read(runtime, node + 16).destroy()
        _invoke(runtime, 0xB75029, node)
        node = following
    else:
        raise PrimaryProgramLimit('parent map cleanup exceeds the bounded source domain')
    buckets = memory.load(address, 8)
    if buckets:
        runtime._free_allocation(buckets)
    memory.store(address, 0, 8, source='2E031A0.clear_map_buckets')


def _destroy_vector(runtime, address):
    target = _StringVector(runtime, address)
    if target.begin:
        for pointer in range(target.end - 24, target.begin - 1, -24):
            _String.read(runtime, pointer).destroy()
        runtime.memory.store(address + 8, target.begin, 8, source='2E031A0.clear_vector_end')
        runtime._free_allocation(target.begin)


def optional_fields(runtime, command):
    if _feature(runtime, 22) != 1:
        return False
    memory = runtime.memory
    address = runtime.image_base + 0x6751D70
    owner = memory.load(address, 8)
    if not owner:
        owner = runtime._operator_new(72)
        for offset in (0x38, 0x28, 0x18):
            memory.write(owner + offset, bytes(16), source='2E03F95.zero_state_block')
        memory.store(owner, 0xA00000014, 8, source='2E03FAE.state_limits')
        memory.store(owner + 8, 0, 1, source='2E03FB1.initial_active')
        memory.store(owner + 12, 3, 4, source='2E03FB5.initial_threshold')
        memory.store(owner + 16, 0, 2, source='2E03FBC.initial_status_WORD')
        memory.store(owner + 18, 0, 1, source='2E03FC2.initial_status_BYTE')
        memory.store(address, owner, 8, source='2E03FC6.publish_state')
    flag10 = memory.load(owner + 16, 1)
    flag12 = memory.load(owner + 18, 1)
    flag11 = memory.load(owner + 17, 1)
    if flag10 & 1 or flag11 or flag12:
        return True
    for keyword in _KEYWORDS:
        if _contains(command, keyword):
            return True
    return False


def produce_parent(runtime, output):
    with _parent_phase(runtime, output):
        return _produce_parent(runtime, output)


def _produce_parent(runtime, output):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x388, '2E031A0.parent_frame')
    serialized = rbp + 0x170
    memory.write(serialized, bytes(24), source='2E031D8.empty_serialized_result')
    try:
        root = _node(runtime, 6)
        if not root:
            memory.store(output, 0, 2, source='2E03292.empty_result_WORD')
            return output
        accounts, integrity, hooks, material = rbp + 0x2B0, rbp + 0x230, rbp + 0xB8, rbp + 0xE0
        memory.write(accounts, bytes(24), source='2E03225.empty_accounts')
        _invoke(runtime, 0x35A3D90, accounts)
        render_vector(runtime, rbp + 0x108, accounts)
        command_pointer = _api(runtime, 'GetCommandLineA', ())
        command = _cstring(runtime, command_pointer)
        _String.construct(runtime, command).write_to(rbp + 0x218)
        _field(runtime, root, b'1', _String.read(runtime, rbp + 0x108).value())
        quote_command(runtime, rbp + 0x258, rbp + 0x218)
        _field(runtime, root, b'8', _String.read(runtime, rbp + 0x258).value())
        _String.read(runtime, rbp + 0x258).destroy()
        _empty_map(runtime, integrity)
        _invoke(runtime, 0x35AA260, integrity)
        status = _invoke(runtime, 0x35B3FE0, integrity)
        _field(runtime, root, b'7', tag=status & 255)
        _map_field(runtime, root, _String.read(runtime, base + 0x6D865B8).value(), integrity)
        for rva, address, key in ((0x2DF8200, hooks, 0x6D86588), (0x2E01C70, material, 0x6D865E8)):
            _empty_map(runtime, address)
            _invoke(runtime, rva, address)
            _map_field(runtime, root, _String.read(runtime, base + key).value(), address)
        windows = rbp + 0x150
        memory.write(windows, bytes(24), source='2E03BC3.empty_window_vector')
        _invoke(runtime, 0x1D0ED90, windows)
        render_vector(runtime, rbp + 0x120, windows)
        _field(runtime, root, _String.read(runtime, base + 0x6D865D0).value(), _String.read(runtime, rbp + 0x120).value())
        _invoke(runtime, 0x35BF640, rbp + 0x138)
        _field(runtime, root, _String.read(runtime, base + 0x6D86600).value(), _String.read(runtime, rbp + 0x138).value())
        cwd = rbp - 0x50
        memory.write(cwd, bytes(260), source='2E03E17.zero_directory_buffer')
        _api(runtime, 'GetCurrentDirectoryA', (260, cwd), ((cwd, 260),))
        _field(runtime, root, _String.read(runtime, base + 0x6D86618).value(), _cstring(runtime, cwd))
        if optional_fields(runtime, command):
            for rva, vector, rendered, key in ((0x35CC6B0, rbp + 0x1E0, rbp + 0x190, b'3'),
                                               (0x1D0EAC0, rbp + 0x1C0, rbp + 0x1A8, b'5')):
                memory.write(vector, bytes(24), source='2E0484E.empty_optional_vector')
                _invoke(runtime, rva, vector)
                render_vector(runtime, rendered, vector)
                _field(runtime, root, key, _String.read(runtime, rendered).value())
            for rendered, vector in ((rbp + 0x1A8, rbp + 0x1C0), (rbp + 0x190, rbp + 0x1E0)):
                _String.read(runtime, rendered).destroy()
                _destroy_vector(runtime, vector)
        printed = compact(runtime, root, 0, 0, 0)
        if printed:
            _String.construct(runtime, _cstring(runtime, printed)).write_to(serialized)
            runtime._free_allocation(printed)
            destroy(runtime, root)
            value = _String.read(runtime, serialized)
            for index, byte in enumerate(value.value()):
                if byte == 124:
                    if value.get(0, 1) & 1:
                        memory.store(value.get(16, 8) + index, 32, 1, source='2E031A0.replace_serialized_pipe')
                    else:
                        value.set(index + 1, b' ')
            value.write_to(output)
            memory.write(serialized, bytes(24), source='2E04E16.clear_moved_result')
        else:
            memory.store(output, 0, 2, source='2E04B95.empty_result_WORD')
        _String.read(runtime, rbp + 0x138).destroy()
        _String.read(runtime, rbp + 0x120).destroy()
        _destroy_vector(runtime, windows)
        for address in (material, hooks, integrity):
            _destroy_map(runtime, address)
        _String.read(runtime, rbp + 0x218).destroy()
        _String.read(runtime, rbp + 0x108).destroy()
        _destroy_vector(runtime, accounts)
        _String.read(runtime, serialized).destroy()
        return output
    finally:
        memory.unmap(frame)


def invoke(runtime, rva, values):
    entries = {0x2E031A0: (produce_parent, 1), 0x2E09B80: (render_vector, 2), 0x2E09EF0: (quote_command, 2)}
    if rva not in entries or len(values) != entries[rva][1]:
        raise InputError('notification parent source entry or logical ABI mismatch')
    return entries[rva][0](runtime, *values)
