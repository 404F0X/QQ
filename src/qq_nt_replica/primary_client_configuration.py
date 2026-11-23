import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .errors import InputError
from .primary_feature_config import _bounds, construct, destroy
from .primary_logger import _String, log
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _invoke, _zero_string
from .primary_worker_response import _frame


_VTABLE = 0x414ABD8
_ASSET_SHA256 = '08123309a36c97c639aa72918ad861901cc5fa6dff650c6c318331895e7ea39e'
_FILE = rb'R:\devops\workspace\p-824b74756ad64e12838601ccde6ecefb\platforms\Windows\..\..\base\include\base/config/dynamic_config_manager.h'
_LIMIT = 1 << 20


def install_image(signer):
    from .primary_client_configuration_scope import premap
    base = signer.image_base
    table = b''.join((base + rva).to_bytes(8, 'little') for rva in
                     (0x142A0, 0x1C513C0, 0x1C513E0, 0x28F0, 0x1FE0, 0x1C51410))
    constructor_table = b''.join((base + rva).to_bytes(8, 'little') for rva in
                                (0x142A0, 0x1C41AE0, 0x1C41AF0, 0x28F0, 0x1FE0, 0x1C41B10))
    return premap(signer, ((_VTABLE, table, True), (0x414A2C8, constructor_table, True),
        (0x677DDB0, bytes(0x78), False), (0x6751690, bytes(8), False),
        (0x6751DC0, bytes(8), False), (0x677CE90, bytes(8), False), (0x677CEA8, bytes(8), False)))


def _fixed_globals():
    raw = (Path(__file__).with_name('data') / 'primary_client_configuration/qq52230-fixed-globals.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _ASSET_SHA256:
        raise InputError('fixed client configuration globals identity mismatch')
    return json.loads(raw)


def _nodes(runtime, address):
    pointer = runtime.memory.load(address + 16, 8)
    for _ in range(_LIMIT):
        if not pointer:
            return
        yield pointer
        pointer = runtime.memory.load(pointer, 8)
    raise PrimaryProgramLimit('client configuration set chain exceeds the bounded source domain')


def destroy_set(runtime, address):
    memory = runtime.memory
    for pointer in list(_nodes(runtime, address)):
        _String.read(runtime, pointer + 16).destroy()
        runtime._free_allocation(pointer)
    buckets = memory.load(address, 8)
    memory.store(address, 0, 8, source='1C52109.configuration_set_bucket_clear')
    if buckets:
        runtime._free_allocation(buckets)


def copy_set(runtime, destination, source):
    memory = runtime.memory
    memory.write(destination, bytes(32), source='3DEB6.configuration_set_copy_empty')
    memory.copy_disjoint(destination + 32, source + 32, 4, label='3DEC6.configuration_set_copy_load_factor')
    _invoke(runtime, 0x3CC9A, destination, memory.load(source + 8, 8))
    frame, _ = _frame(runtime, 16, '293AD0.configuration_set_copy_result')
    for node in _nodes(runtime, source):
        _invoke(runtime, 0x92FAA, destination, frame, node + 16)
    memory.unmap(frame)
    return destination


def initialize_component_globals(runtime):
    memory, base = runtime.memory, runtime.image_base
    if memory.load(base + 0x677DDD0 + 32, 4) or memory.load(base + 0x677DDF8 + 32, 4):
        raise PrimarySemanticUnavailable('client configuration globals require their fresh component construction precondition')
    data = _fixed_globals()
    key = bytes.fromhex(data['key_hex'])
    memory.store(base + 0x677DDB8, len(key) * 2, 1, source='1D118FA.configuration_key_length')
    memory.write(base + 0x677DDB9, key + b'\0', source='1D11908.configuration_key_literal')
    for name, target in (('first_set268', base + 0x677DDD0), ('second_set124', base + 0x677DDF8)):
        rows = data[name]
        frame, _ = _frame(runtime, len(rows) * 24 + 16, 'configuration_global_literal_array')
        for index, row in enumerate(rows):
            header = bytearray.fromhex(row['header24_hex'])
            if row['allocation_size'] is not None:
                pointer = runtime._operator_new(row['allocation_size'])
                memory.write(pointer, bytes.fromhex(row['value_hex']) + b'\0', source='configuration_fixed_literal_buffer')
                header[16:24] = pointer.to_bytes(8, 'little')
            _String(runtime, header, bytes.fromhex(row['header_knownmask24_hex'])).write_to(frame + index * 24)
        pair = frame + len(rows) * 24
        memory.store(pair, frame, 8, source='configuration_literal_array_begin')
        memory.store(pair + 8, len(rows), 8, source='configuration_literal_array_count')
        _invoke(runtime, 0x1224BDC, target, pair)
        for index in range(len(rows) - 1, -1, -1):
            _String.read(runtime, frame + index * 24).destroy()
        memory.unmap(frame)
    runtime.events.append(('configuration.component_globals_constructed', 268, 124))


def _insert(runtime, target, value, output):
    return _invoke(runtime, 0x92FC4, target, output, value, value)


def initialize_persisted_union(runtime):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 64, 'BE35C0.configuration_persisted_union_component')
    _invoke(runtime, 0x1BE5B70, frame, base + 0x677DDB8)
    stored = _String.read(runtime, frame)
    raw = stored.value()
    if raw:
        tokens = raw.split(b',')
        if raw.endswith(b','):
            tokens.pop()
        for token in tokens:
            item = _String.construct(runtime, token)
            item.write_to(frame + 24)
            _insert(runtime, base + 0x677DDF8, frame + 24, frame + 48)
            item.destroy()
    for node in _nodes(runtime, base + 0x677DDD0):
        _insert(runtime, base + 0x677DDF8, node + 16, frame + 48)
    stored.destroy()
    memory.unmap(frame)


@dataclass(frozen=True)
class ClientConfigurationNotificationBinding:
    target: int
    callback: object

    def __post_init__(self):
        if type(self.target) is not int or not 0 < self.target < 1 << 64 or not callable(self.callback):
            raise InputError('client configuration notification requires an actual target and callable')


def notify_adapter(runtime, pointers, count):
    memory, base = runtime.memory, runtime.image_base
    target = memory.load(base + 0x6751690, 8)
    if not target or not pointers or not count:
        return None
    if not 0 <= count < 1 << 64:
        raise InputError('client configuration notification count requires unsigned64')
    frame, _ = _frame(runtime, 0x1068, 'BBDB00.configuration_notification_adapter_frame')
    packed = frame + 0xB8
    memory.store(packed, count & 0xFFFF, 2, source='BBDB47.configuration_notification_count')
    log(runtime, rb'R:\devops\workspace\p-824b74756ad64e12838601ccde6ecefb\platforms\Windows\libsecxx\FGESDKNt.cpp',
        0x103, b'cwlun :%d', base + 0x48972C7, 1, count)
    memory.copy_disjoint(packed + 8, pointers, min(count, 500) * 8,
                         label='BBDF55.configuration_notification_pointer_copy')
    target = memory.load(base + 0x6751690, 8)
    binding = getattr(runtime, 'client_configuration_notification', None)
    if not isinstance(binding, ClientConfigurationNotificationBinding) or binding.target != target:
        raise PrimarySemanticUnavailable('BBDF62 configuration notification host target is not bound')
    runtime.events.append(('configuration.notification_host_call', target, packed, count, min(count, 500)))
    binding.callback(runtime, packed)
    memory.unmap(frame)
    return None


def _first_vector(runtime, aggregate, frame):
    memory, base = runtime.memory, runtime.image_base
    begin, end, _ = _bounds(runtime, aggregate + 8, 24)
    joined = _zero_string(runtime)
    for pointer in range(begin, end, 24):
        item = _String.read(runtime, pointer).clone()
        _append(item, b',')
        _append(joined, item.value())
        item.destroy()
    if joined.value():
        trimmed = _String.construct(runtime, joined.value()[:-1])
        joined.destroy()
        joined = trimmed
    joined.write_to(frame)
    _invoke(runtime, 0x1BE5B30, base + 0x677DDB8, frame)
    for pointer in range(begin, end, 24):
        _insert(runtime, base + 0x677DDF8, pointer, frame + 24)
    joined.destroy()
    if begin == end or not memory.load(base + 0x677DE20, 8):
        return
    guard = memory.load(base + 0x677DDB0, 8)
    if guard != (1 << 64) - 1:
        if guard:
            raise PrimarySemanticUnavailable('configuration union once guard is already in progress')
        memory.store(base + 0x677DDB0, 1, 8, source='75B0E0.configuration_union_once_claim')
        initialize_persisted_union(runtime)
        memory.store(base + 0x677DDB0, (1 << 64) - 1, 8, source='75B0E0.configuration_union_once_complete')
    copy_set(runtime, frame, base + 0x677DDF8)
    size = memory.load(frame + 24, 8)
    array = _invoke(runtime, 0x3E97020, 8 * (size + (end - begin) // 24))
    for pointer in range(begin, end, 24):
        _insert(runtime, frame, pointer, frame + 40)
    count = 0
    for node in _nodes(runtime, frame):
        text = _String.read(runtime, node + 16)
        pointer = text.get(16, 8) if text.get(0, 1) & 1 else node + 17
        memory.store(array + count * 8, pointer, 8, source='1C520C4.configuration_notification_pointer')
        count += 1
    target = memory.load(base + 0x677DE20, 8)
    _invoke(runtime, target - base, array, memory.load(frame + 24, 8))
    _invoke(runtime, 0x3E94F90, array)
    destroy_set(runtime, frame)


def produce(runtime, owner):
    from .primary_client_configuration_scope import require_producer_entry
    require_producer_entry(runtime, owner)
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x110, '1C50FE0.configuration_producer_frame')
    from .primary_client_configuration_scope import producing
    with producing(runtime, owner, frame, rbp):
        previous = memory.load(owner + 9, 1)
        runtime.events.append(('configuration.inflight_compare_exchange', owner + 9, previous, 0, 1))
        if previous:
            memory.unmap(frame)
            return None
        memory.store(owner + 9, 1, 1, source='1C5100B.configuration_inflight_claim')
        for offset in (-0x20, -8, 0x10):
            memory.store(rbp + offset, 0, 2, source='1C51016.configuration_empty_string')
        memory.write(rbp + 0x40, bytes(48), source='1C5103A.configuration_empty_metadata')
        for source, destination in ((rbp + 0x10, rbp + 0x40), (rbp - 8, rbp + 0x58)):
            _invoke(runtime, 0x75CEC0, destination, source)
        carrier = rbp - 0x48
        memory.store(carrier + 8, base + _VTABLE, 8, source='1C5106E.configuration_inline_callback_vtable')
        memory.store(carrier + 16, owner, 8, source='1C51072.configuration_inline_callback_owner')
        memory.store(carrier + 32, carrier + 8, 8, source='1C51076.configuration_inline_callback_active')
        _String.construct(runtime, b'GetSecConf').write_to(rbp + 0x28)
        _invoke(runtime, 0x1CE6920, _invoke(runtime, 0xBA21A0), rbp + 0x28, rbp - 0x1F, 0,
                carrier, rbp + 0x40, 1)
        for offset in (0x58, 0x40, 0x10, -8, -0x20):
            _String.read(runtime, rbp + offset).destroy()
        memory.unmap(frame)
        return None


def loop(runtime, owner):
    from .primary_client_configuration_scope import require_owner, validate_owner
    current = require_owner(runtime, 'client_loop')
    validate_owner(runtime, owner)
    if current.row['task'] != owner:
        raise InputError('configuration loop owner differs from its actual thread capture')
    memory = runtime.memory
    while not memory.load(owner + 24, 1) & 1:
        if memory.load(owner + 4, 4, signed=True) > memory.load(owner, 1):
            return None
        _invoke(runtime, 0x1C50FE0, owner)
        seconds = (memory.load(owner + 4, 4) * 60 + 60) & 0xFFFFFFFF
        signed = seconds - (1 << 32) if seconds >> 31 else seconds
        if signed > 0:
            _invoke(runtime, 0x760050, signed * 1000000000)
        previous = memory.load(owner + 4, 4)
        memory.store(owner + 4, (previous + 1) & 0xFFFFFFFF, 4, source='1C50F90.configuration_count_lock_add')
    return None


def duration_sleep(runtime, duration):
    from .primary_client_configuration_scope import require_owner
    require_owner(runtime)
    duration &= (1 << 64) - 1
    if duration >> 63 or duration == 0:
        return None
    return _invoke(runtime, 0x787A70, duration)


def millisecond_sleep(runtime, duration):
    from .primary_client_configuration_scope import require_owner
    require_owner(runtime)
    duration &= (1 << 64) - 1
    return _host(runtime, 'Sleep', ((duration + 999999) // 1000000) & 0xFFFFFFFF)


def respond(runtime, capture, pointer, count, success, extra):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x158, '1C514B0.configuration_callback_frame')
    owner = memory.load(capture, 8)
    if not success & 255 or not pointer or not count & 0xFFFFFFFF:
        log(runtime, _FILE, 0x24, b'get SecConfig failed', base + 0x48972C7, 2)
        memory.store(owner + 9, 0, 1, source='1C51934.configuration_failure_clear_inflight')
        memory.unmap(frame)
        return None
    memory.store(owner + 24, 1, 1, source='1C514F4.configuration_completed')
    memory.store(owner + 9, 0, 1, source='1C514F9.configuration_success_clear_inflight')
    aggregate, raw_string = rbp - 72, rbp + 48
    construct(runtime, aggregate)
    _String.construct(runtime, memory.read(pointer, count & 0xFFFFFFFF)).write_to(raw_string)
    status = _invoke(runtime, 0x1C52510, aggregate, raw_string)
    _String.read(runtime, raw_string).destroy()
    if status == 0x100:
        from .primary_worker_loop import _ensure_logger
        _ensure_logger(runtime)
        _invoke(runtime, 0x1BE39B0, memory.load(base + 0x67516A8, 8), aggregate + 32)
        _first_vector(runtime, aggregate, rbp + 48)
    else:
        log(runtime, _FILE, 0x36, b'deserialize SecConfigResponse response failed', base + 0x48972C7, 2)
    destroy(runtime, aggregate)
    memory.unmap(frame)
    runtime.events.append(('configuration.response_parsed', owner, status))
    return None


def _host(runtime, name, *arguments):
    slots = {'GetTickCount': 0x490FFE8, 'Sleep': 0x4910368, 'CloseHandle': 0x490FBD8}
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + slots[name], 8) != target:
        raise PrimarySemanticUnavailable('configuration creator current host import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('configuration creator requires declared host observations: ' + name)
    result, effects = runtime.worker_observations.take(runtime, name, arguments)
    if effects not in ((), b''):
        raise InputError('configuration creator host call has no output-buffer effects: ' + name)
    if name == 'Sleep':
        if result is not None:
            raise InputError('Sleep requires its void result')
    elif type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
        raise InputError('configuration creator host call requires a DWORD result: ' + name)
    return result


def create_startup(runtime):
    base = runtime.image_base
    handle = _invoke(runtime, runtime.memory.load(base + 0x490FC80, 8) - base,
                     0, 0, base + 0x1C22D90, 0, 0, 0)
    runtime.memory.store(base + 0x677CE90, handle, 8, source='1C22D79.configuration_startup_handle')
    return _host(runtime, 'CloseHandle', handle)


def finish_local_thread(runtime, thread):
    if not _invoke(runtime, 0x787920, thread) & 255:
        runtime.events.append(('configuration.thread_terminate', thread, runtime.memory.load(thread, 8)))
        raise PrimarySemanticUnavailable('759C40 nonempty thread destructor terminates; normal continuation is unavailable')
    return None


def start_owner(runtime, owner):
    from .primary_client_configuration_scope import require_owner, validate_owner
    current = require_owner(runtime, 'client_startup')
    if validate_owner(runtime, owner)[2] is not current.row:
        raise InputError('client start owner belongs to another startup row')
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0xE8, '1C29F90.configuration_owner_start_frame')
    log(runtime, _FILE, 0x67, b'UpdateConfiguration start', base + 0x48972C7, 2)
    previous = memory.load(owner + 8, 1)
    runtime.events.append(('configuration.started_compare_exchange', owner + 8, previous, 0, 1))
    if not previous:
        memory.store(owner + 8, 1, 1, source='1C2A322.configuration_started_claim')
        memory.store(rbp + 0x40, owner, 8, source='1C2A329.configuration_thread_borrowed_owner')
        memory.store(rbp - 0x50, base + 0x1C50F70, 8, source='1C2A32D.configuration_thread_function')
        _invoke(runtime, 0xBD4FA0, rbp - 0x48, rbp - 0x50, rbp + 0x40)
        if not _invoke(runtime, 0x787920, owner + 16) & 255:
            runtime.events.append(('configuration.thread_terminate', owner + 16, memory.load(owner + 16, 8)))
            raise PrimarySemanticUnavailable('759C40 already owned configuration thread terminates')
        memory.store(owner + 16, memory.load(rbp - 0x48, 8), 8, source='1C2A35D.configuration_thread_handle_publish')
        memory.store(rbp - 0x48, 0, 8, source='1C2A360.configuration_local_handle_clear')
        _invoke(runtime, 0x75FF40, rbp - 0x48)
    memory.unmap(frame)
    return None


def startup_entry(runtime, delay):
    from .primary_client_configuration_scope import require_owner, register_owner, image_for
    require_owner(runtime, 'client_startup')
    image_for(runtime)
    from .primary_provider_init import _state
    from .primary_feature_notifications import _logger

    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x108, '1C22D90.configuration_startup_thread_frame')
    before = _host(runtime, 'GetTickCount')
    _host(runtime, 'Sleep', delay & 0xFFFFFFFF)
    source_file = rb'R:\devops\workspace\p-824b74756ad64e12838601ccde6ecefb\platforms\Windows\libsecxx\envinfo\O3CheckEntry.cpp'
    for attempt in range(30):
        if memory.load(_state(runtime) + 2, 1):
            break
        log(runtime, source_file, 0x114, b'not ready: %d', base + 0x48972C7, 1, attempt)
        _host(runtime, 'Sleep', 100)
    guard = base + 0x677CEA8
    if memory.load(guard, 8) != (1 << 64) - 1:
        if memory.load(guard, 8):
            raise PrimarySemanticUnavailable('configuration startup notification once is already in progress')
        memory.store(guard, 1, 8, source='75B0E0.configuration_startup_once_claim')
        _invoke(runtime, 0x1C2A3B0)
        memory.store(guard, (1 << 64) - 1, 8, source='75B0E0.configuration_startup_once_complete')
    _invoke(runtime, 0x1C1B430)
    carrier = rbp - 0x48
    memory.store(carrier + 8, base + 0x414A2C8, 8, source='1C23221.configuration_change_vtable')
    memory.store(carrier + 32, carrier + 8, 8, source='1C2322C.configuration_change_active')
    _invoke(runtime, 0x1BE3FF0, _logger(runtime), carrier)
    owner = memory.load(base + 0x6751DC0, 8)
    if not owner:
        owner = runtime._operator_new(32)
        register_owner(runtime, owner)
        for offset, value, width in ((0, 5, 1), (4, 0, 4), (8, 0, 2), (16, 0, 8), (24, 0, 1)):
            memory.store(owner + offset, value, width, source='1C23252.configuration_owner_construct')
        memory.store(base + 0x6751DC0, owner, 8, source='1C2326E.configuration_owner_publish')
    from .primary_client_configuration_scope import validate_owner
    validate_owner(runtime, owner)
    _invoke(runtime, 0x1C29F90, owner)
    after = _host(runtime, 'GetTickCount')
    log(runtime, source_file, 0x12C, b'thread2=%u', base + 0x48972C7, 1, (after - before) & 0xFFFFFFFF)
    memory.unmap(frame)
    return 1


def invoke(runtime, rva, values):
    if rva == 0x1C22D50 and not values:
        return create_startup(runtime)
    if rva in (0x1C22D90, 0x1C29F90, 0x75FF40) and len(values) == 1:
        return {0x1C22D90: startup_entry, 0x1C29F90: start_owner, 0x75FF40: finish_local_thread}[rva](runtime, values[0])
    if rva in (0x1C41AE0, 0x1C41AF0) and len(values) == (2 if rva == 0x1C41AE0 else 1):
        destination = values[1] if rva == 0x1C41AE0 else runtime._operator_new(16)
        table = runtime.image_base + 0x414A2C8
        runtime.memory.store(destination, table, 8, source='1C41AE7.configuration_change_clone')
        return table if rva == 0x1C41AE0 else destination
    if rva == 0x1C50F70 and len(values) == 1:
        return loop(runtime, values[0])
    if rva in (0x760050, 0x787A70) and len(values) == 1:
        return (duration_sleep if rva == 0x760050 else millisecond_sleep)(runtime, values[0])
    if rva == 0x1C41B10:
        raise PrimarySemanticUnavailable('queued configuration retry or feature callback continuation is not implemented')
    if rva == 0x1C50FE0 and len(values) == 1:
        return produce(runtime, values[0])
    if rva == 0x1C513C0 and len(values) == 2:
        source, destination = values
        runtime.memory.store(destination, runtime.image_base + _VTABLE, 8, source='1C513C7.configuration_inline_clone_vtable')
        owner = runtime.memory.load(source + 8, 8)
        runtime.memory.store(destination + 8, owner, 8, source='1C513CE.configuration_inline_clone_owner')
        from .primary_client_configuration_scope import remember_clone
        remember_clone(runtime, source, destination, owner)
        return owner
    if rva == 0x1C513E0 and len(values) == 1:
        result = runtime._operator_new(16)
        invoke(runtime, 0x1C513C0, (values[0], result))
        return result
    if rva == 0x1C51410 and len(values) == 5:
        function, pointer, count, success, extra = values
        return respond(runtime, function + 8, runtime.memory.load(pointer, 8), runtime.memory.load(count, 4),
                       runtime.memory.load(success, 1), runtime.memory.load(extra, 4))
    if rva == 0x1C514B0 and len(values) == 5:
        return respond(runtime, *values)
    if rva == 0xBE35C0 and len(values) == 1:
        return initialize_persisted_union(runtime)
    if rva == 0xBBDB00 and len(values) == 2:
        return notify_adapter(runtime, *values)
    raise InputError('client configuration entry argument count mismatch')
