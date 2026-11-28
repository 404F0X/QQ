import base64
import binascii
from dataclasses import dataclass

from .errors import InputError
from .primary_logger import _String, feature, log
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed
from .primary_worker_consumer import _append, _invoke
from .primary_worker_response import _frame


_U64 = (1 << 64) - 1
_LIMIT = 4096
_KEY = b'HighReliabilityReporterCache'
_INITIAL = bytes.fromhex('01310b5c5f0e0f0c0a03050407000001315b5e5d4905471a085541554d51540f6c5a4c52484f166a45586650425c4245000001314450445c4045000001315d555d55545c54684450445c404500000131485e4d52675e425057424254000001314d5d4b57594562545a5c54000001315f4a4c604c584c5c40450000013148515e50604e58425c4245000001315f574e605a5848565145000001314b5d61504b545654405e595f00000131585a5c4c5f645e504052554500000131585749476058584656534500000131525b4e464a4a7858485e43734e464a535a000001314c525758465050540000013131313131313131313131313131313131313131313131313131310b0f0f0b0b37373b3b3f3f3b3b37372b2b2f2f2b2b37373b3b3f7476747a7c7e7c7a7476651e0000')
_FILE = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\channel\\src\\reporter\\high_reliability_reporter.cpp'


@dataclass(frozen=True)
class HighReliabilitySleepBoundary:
    task: int
    iteration: int
    nanoseconds: int


def _map_image(memory, address, raw, *, writable=False):
    cursor, end = address, address + len(raw)
    while cursor < end:
        region = next((item for item in memory._region_snapshot()
                       if item.address <= cursor < item.address + len(item.data)), None)
        if region is not None:
            cursor = min(end, region.address + len(region.data))
            continue
        following = min((item.address for item in memory._region_snapshot() if item.address > cursor), default=end)
        count = min(end, following) - cursor
        fragment = raw[cursor - address:cursor - address + count]
        memory.map(cursor, bytearray(fragment) if writable else fragment,
                   name='fixed high reliability source image', initialized=True)
        cursor += count


def install_image(memory, image_base):
    _map_image(memory, image_base + 0x677CCB8, bytes(8), writable=True)
    _map_image(memory, image_base + 0x6D862D0, bytes(len(_INITIAL)), writable=True)
    tables = {0x436EC18: (0x142A0, 0x2DF1450, 0x2DF1470, 0x28F0, 0x1FE0, 0x2DF14A0),
              0x436EBC8: (0x142A0, 0x2DF0A10, 0x2DF0A20, 0x28F0, 0x1FE0, 0x2DF0A40),
              0x4149058: (0x1C018C0, 0x776860, 0x5C7470, 0x63EC0, 0xBCD880),
              0x41490E8: (0x142A0, 0x1C02370, 0x1C02390, 0x28F0, 0x1FE0, 0xB8F200)}
    for rva, values in tables.items():
        _map_image(memory, image_base + rva,
                   b''.join((image_base + value).to_bytes(8, 'little') for value in values))


def initialize(runtime):
    install_image(runtime.memory, runtime.image_base)
    for index, byte in enumerate(_INITIAL):
        runtime.memory.store(runtime.image_base + 0x6D862D0 + index, byte, 1,
                             source='2DF2230.high_reliability_module_initializer')
    runtime.events.append(('high_reliability.module_initialized',))


def _alphabet(runtime):
    memory, pointer = runtime.memory, runtime.image_base + 0x6D863B8
    if memory.load(pointer, 1) & 1:
        for index in range(64):
            memory.store(pointer + index + 2,
                         memory.load(pointer + index + 2, 1) ^ (index + 1) ^ memory.load(pointer + 1, 1) ^ 64,
                         1, source='high_reliability.alphabet_decode')
        memory.store(pointer + 66, 0, 1, source='high_reliability.alphabet_terminator')
        memory.store(pointer + 67, 0, 1, source='high_reliability.alphabet_terminator')
        memory.store(pointer, 0, 1, source='high_reliability.alphabet_decoded')
    value = memory.read(pointer + 2, 64)
    if value != b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/':
        raise PrimarySemanticUnavailable('high reliability cache requires its actual reporter module initializer')
    return value


def _empty(runtime, address, full=False):
    runtime.memory.write(address, bytes(24) if full else bytes(2),
                         source='high_reliability.empty_string')


def construct_event(runtime, event):
    memory, base = runtime.memory, runtime.image_base
    _String.construct(runtime, b'sec_init').write_to(event + 8)
    for offset in range(0x20, 0xC8, 24):
        _empty(runtime, event + offset)
    memory.write(event + 0xC8, bytes(24), source='1BF7BE7.sec_init_empty_vector')
    memory.store(event, base + 0x4149058, 8, source='1BF7BF9.sec_init_event_vtable')
    _empty(runtime, event + 0xE0, True)
    return event


def copy_event(runtime, destination, source):
    from .primary_source_postfetch import copy_base_record
    copy_base_record(runtime, destination, source)
    runtime.memory.store(destination, runtime.image_base + 0x4149058, 8,
                         source='high_reliability.sec_init_copy_vtable')
    _String.read(runtime, source + 0xE0).clone().write_to(destination + 0xE0)
    return destination


def destroy_event(runtime, event):
    from .primary_task_exit import destroy_base_record
    runtime.memory.store(event, runtime.image_base + 0x4149058, 8,
                         source='high_reliability.sec_init_destroy_vtable')
    _String.read(runtime, event + 0xE0).destroy()
    destroy_base_record(runtime, event)


def _vector(runtime, vector):
    memory = runtime.memory
    first, last, capacity = (memory.load(vector + offset, 8) for offset in (0, 8, 16))
    if not first <= last <= capacity or (last - first) % 0xF8 or (capacity - first) % 0xF8:
        raise InputError('high reliability cache vector has an invalid source layout')
    if (capacity - first) // 0xF8 > _LIMIT:
        raise PrimaryProgramLimit('high reliability cache vector exceeds its bounded normal domain')
    return first, last, capacity


def destroy_vector(runtime, vector):
    first, last, _ = _vector(runtime, vector)
    for pointer in range(last - 0xF8, first - 1, -0xF8):
        destroy_event(runtime, pointer)
    if first:
        runtime._free_allocation(first)


def _append_event(runtime, vector, event):
    memory = runtime.memory
    first, last, capacity = _vector(runtime, vector)
    if last < capacity:
        copy_event(runtime, last, event)
        memory.store(vector + 8, last + 0xF8, 8, source='high_reliability.vector_end')
        return
    count, old_capacity = (last - first) // 0xF8, (capacity - first) // 0xF8
    enlarged = max(count + 1, old_capacity * 2)
    if enlarged > _LIMIT:
        raise PrimaryProgramLimit('high reliability cache growth exceeds its bounded normal domain')
    pointer = runtime._operator_new(enlarged * 0xF8)
    copy_event(runtime, pointer + count * 0xF8, event)
    for index in range(count - 1, -1, -1):
        _move_event(runtime, pointer + index * 0xF8, first + index * 0xF8)
    if first:
        for index in range(count - 1, -1, -1):
            destroy_event(runtime, first + index * 0xF8)
        runtime._free_allocation(first)
    for offset, value in ((0, pointer), (8, pointer + (count + 1) * 0xF8), (16, pointer + enlarged * 0xF8)):
        memory.store(vector + offset, value, 8, source='high_reliability.vector_growth')


def _move_event(runtime, destination, source):
    memory = runtime.memory
    memory.store(destination, runtime.image_base + 0x4149058, 8,
                 source='high_reliability.sec_init_move_vtable')
    for offset in (*range(8, 0xC8, 24), 0xE0):
        _String.read(runtime, source + offset).write_to(destination + offset)
        _empty(runtime, source + offset, True)
    for offset in (0xC8, 0xD0, 0xD8):
        memory.store(destination + offset, memory.load(source + offset, 8), 8,
                     source='high_reliability.sec_init_move_vector')
    memory.write(source + 0xC8, bytes(24), source='high_reliability.sec_init_moved_vector')


def _erase_prefix(runtime, vector, count):
    memory = runtime.memory
    first, last, _ = _vector(runtime, vector)
    length = (last - first) // 0xF8
    if not 0 <= count <= length:
        raise InputError('high reliability cache erase is outside its vector')
    for index in range(count):
        destroy_event(runtime, first + index * 0xF8)
    for index in range(count, length):
        _move_event(runtime, first + (index - count) * 0xF8, first + index * 0xF8)
    for index in range(max(count, length - count), length):
        destroy_event(runtime, first + index * 0xF8)
    memory.store(vector + 8, last - count * 0xF8, 8, source='high_reliability.cache_erase_end')


def format_cache(runtime, output, vector):
    _alphabet(runtime)
    first, last, _ = _vector(runtime, vector)
    result = _String(runtime, bytes(24), bytes([1]) * 24)
    runtime.memory.write(output, bytes(24), source='2DEFA30.cache_output_zero')
    for event in range(first, last, 0xF8):
        frame, _ = _frame(runtime, 0xF8, '2DEFA30.cache_record_copy')
        copy_event(runtime, frame, event)
        for byte in base64.b64encode(_String.read(runtime, frame + 0xE0).value()) + b' ':
            _append(result, bytes([byte]))
        destroy_event(runtime, frame)
        runtime.memory.unmap(frame)
    result.write_to(output)
    return output


def parse_cache(runtime, output, source):
    from .primary_device_identifiers import ensure_classic_locale
    _alphabet(runtime)
    memory = runtime.memory
    raw = _String.read(runtime, source).value()
    memory.write(output, bytes(24), source='2DEED00.cache_vector_zero')
    ensure_classic_locale(runtime)
    tokens = raw.split(b' ')
    if tokens and tokens[-1] == b'':
        tokens.pop()
    for token in tokens:
        try:
            value = base64.b64decode(token, validate=True)
        except binascii.Error as error:
            raise PrimarySemanticUnavailable('high reliability noncanonical cache token requires its source stream policy') from error
        if base64.b64encode(value) != token:
            raise PrimarySemanticUnavailable('high reliability noncanonical cache token requires its source stream policy')
        frame, _ = _frame(runtime, 0xF8, '2DEED00.cache_parsed_record')
        construct_event(runtime, frame)
        _String.read(runtime, frame + 0xE0).destroy()
        _String.construct(runtime, value).write_to(frame + 0xE0)
        _append_event(runtime, output, frame)
        destroy_event(runtime, frame)
        memory.unmap(frame)
    return output


def construct_task(runtime, task, function, period):
    memory = runtime.memory
    memory.store(task, 0, 8, source='1C0223B.periodic_thread_handle')
    memory.store(task + 8, 0, 1, source='1C02242.periodic_thread_started')
    active = memory.load(function + 32, 8)
    if active:
        if active != function + 8 or memory.load(active, 8) != runtime.image_base + 0x41490E8:
            raise PrimarySemanticUnavailable('periodic task requires its actual high reliability inline function')
        for offset in (0, 8, 16):
            memory.store(task + 24 + offset, memory.load(active + offset, 8), 8,
                         source='1C02286.periodic_function_clone')
        memory.store(task + 48, task + 24, 8, source='1C02278.periodic_function_owner')
    else:
        memory.store(task + 48, 0, 8, source='1C02272.periodic_empty_function')
    memory.store(task + 56, period & 0xFFFFFFFF, 8, source='1C02293.periodic_milliseconds')
    _invoke(runtime, 0x75B000, task + 64)
    memory.store(task + 104, 0, 8, source='1C022A4.periodic_count')
    return task


def construct(runtime, owner):
    install_image(runtime.memory, runtime.image_base)
    memory, base = runtime.memory, runtime.image_base
    _String.construct(runtime, _KEY).write_to(owner)
    memory.write(owner + 24, bytes(32), source='1C01FA6.high_reliability_fields')
    memory.store(owner + 56, 0, 8, source='1C01FAE.high_reliability_map_size')
    memory.store(owner + 64, 0x3F800000, 4, source='1C01FB6.high_reliability_maxload')
    memory.store(owner + 72, 0, 8, source='1C01FBD.high_reliability_sequence')
    _invoke(runtime, 0x75B000, owner + 80)
    _invoke(runtime, 0x75B000, owner + 120)
    memory.store(owner + 160, 0, 8, source='1C01FEB.high_reliability_last_time')
    memory.store(owner + 168, 0, 1, source='1C01FF6.high_reliability_attempted')
    frame, _ = _frame(runtime, 40, '1C01F50.periodic_function_frame')
    memory.store(frame + 8, base + 0x41490E8, 8, source='1C02008.periodic_function_vtable')
    memory.store(frame + 16, base + 0x2DEDFA0, 8, source='1C02013.periodic_function_pointer')
    memory.store(frame + 24, owner, 8, source='1C02017.periodic_function_receiver')
    memory.store(frame + 32, frame + 8, 8, source='1C0201B.periodic_inline_owner')
    task = runtime._operator_new(0x70)
    construct_task(runtime, task, frame, 60000)
    memory.store(owner + 24, task, 8, source='1C02066.high_reliability_task')
    memory.unmap(frame)
    return owner


def _nodes(runtime, table):
    memory = runtime.memory
    node, seen = memory.load(table + 16, 8), set()
    while node:
        if node in seen or len(seen) >= _LIMIT:
            raise PrimaryProgramLimit('high reliability map traversal exceeds its bounded normal domain')
        seen.add(node)
        yield node
        node = memory.load(node, 8)


def insert(runtime, table, output, key_pointer, pair, *, copy=False):
    from .primary_sdk_records import _find, _index, _needed, _single, _unsigned_single, rehash
    import struct
    memory = runtime.memory
    key, count = memory.load(key_pointer, 8), memory.load(table + 8, 8)
    node = _find(runtime, table, key, count)
    if node:
        memory.store(output, node, 8, source='2DF1D40.existing_node')
        memory.store(output + 8, 0, 1, source='2DF1D40.duplicate')
        return output
    node = runtime._operator_new(0x110)
    memory.store(node + 16, memory.load(pair, 8), 8, source='2DF1D40.node_key')
    if copy:
        copy_event(runtime, node + 24, pair + 8)
    else:
        _move_event(runtime, node + 24, pair + 8)
    memory.store(node + 8, key, 8, source='2DF1D40.node_hash')
    memory.store(node, 0, 8, source='2DF1D40.node_next')
    size = memory.load(table + 24, 8) + 1
    factor = struct.unpack('<f', memory.read(table + 32, 4))[0]
    if not count or _unsigned_single(size) > _single(_unsigned_single(count) * factor):
        rehash(runtime, table, max((count * 2) | int(count < 3 or bool(count & (count - 1))),
                                   _needed(runtime, table, size)))
        count = memory.load(table + 8, 8)
    bucket = _index(key, count)
    predecessor = memory.load(memory.load(table, 8) + bucket * 8, 8)
    if predecessor:
        memory.store(node, memory.load(predecessor, 8), 8, source='2DF1D40.bucket_next')
        memory.store(predecessor, node, 8, source='2DF1D40.bucket_insert')
    else:
        previous = memory.load(table + 16, 8)
        memory.store(node, previous, 8, source='2DF1D40.head_next')
        memory.store(table + 16, node, 8, source='2DF1D40.head_insert')
        memory.store(memory.load(table, 8) + bucket * 8, table + 16, 8, source='2DF1D40.head_bucket')
        if previous:
            memory.store(memory.load(table, 8) + _index(memory.load(previous + 8, 8), count) * 8,
                         node, 8, source='2DF1D40.previous_head_bucket')
    memory.store(table + 24, size, 8, source='2DF1D40.map_size')
    memory.store(output, node, 8, source='2DF1D40.inserted_node')
    memory.store(output + 8, 1, 1, source='2DF1D40.inserted')
    return output


def persist(runtime, owner, event):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x138, '2DECDE0.cache_persist_frame')
    log(runtime, _FILE, 0x5E, b'HighReliabilityReporter saveToDisk', runtime.image_base + 0x48972C7, 2)
    _invoke(runtime, 0x75B070, owner + 80)
    _invoke(runtime, 0x1BE5B70, frame, owner)
    memory.write(frame + 24, bytes(24), source='2DECDE0.empty_cache_vector')
    if _String.read(runtime, frame).value():
        parse_cache(runtime, frame + 24, frame)
    first, last, _ = _vector(runtime, frame + 24)
    if (last - first) // 0xF8 >= 10:
        _erase_prefix(runtime, frame + 24, 1)
    _append_event(runtime, frame + 24, event)
    format_cache(runtime, frame + 48, frame + 24)
    _invoke(runtime, 0x1BE5B30, owner, frame + 48)
    _String.read(runtime, frame + 48).destroy()
    destroy_vector(runtime, frame + 24)
    _String.read(runtime, frame).destroy()
    _invoke(runtime, 0x75B0A0, owner + 80)
    memory.unmap(frame)


def reload(runtime, owner):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x170, '2DED550.cache_reload_frame')
    log(runtime, _FILE, 0x81, b'HighReliabilityReporter loadFromDisk', runtime.image_base + 0x48972C7, 2)
    _invoke(runtime, 0x75B070, owner + 80)
    _invoke(runtime, 0x1BE5B70, frame, owner)
    memory.write(frame + 24, bytes(24), source='2DED550.empty_cache_vector')
    if _String.read(runtime, frame).value():
        parse_cache(runtime, frame + 24, frame)
    first, last, _ = _vector(runtime, frame + 24)
    count = (last - first) // 0xF8
    if count >= 11:
        _erase_prefix(runtime, frame + 24, count - 10)
    first, last, _ = _vector(runtime, frame + 24)
    for event in range(first, last, 0xF8):
        sequence = memory.load(owner + 72, 8)
        memory.store(frame + 72, sequence, 8, source='2DED550.reload_sequence')
        copy_event(runtime, frame + 80, event)
        insert(runtime, owner + 32, frame + 0x128, frame + 72, frame + 72)
        memory.store(owner + 72, (sequence + 1) & _U64, 8, source='2DEDC92.next_sequence')
        destroy_event(runtime, frame + 80)
    destroy_vector(runtime, frame + 24)
    _String.read(runtime, frame).destroy()
    _invoke(runtime, 0x75B0A0, owner + 80)
    memory.unmap(frame)


def ensure_task(runtime, task):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x50, '2DF0870.periodic_start_frame')
    _invoke(runtime, 0x75B070, task + 64)
    memory.store(task + 104, 0, 8, source='2DF0895.periodic_count_reset')
    if not memory.load(task + 8, 1) & 1:
        memory.store(frame + 24, task, 8, source='2DF08A4.periodic_thread_argument')
        memory.store(frame + 32, base + 0x2DF0960, 8, source='2DF08AF.periodic_thread_function')
        _invoke(runtime, 0xBD4FA0, frame + 40, frame + 32, frame + 24)
        if not _invoke(runtime, 0x787920, task) & 255:
            raise PrimarySemanticUnavailable('2DF0902 high reliability thread start requires original terminate path')
        memory.store(task, memory.load(frame + 40, 8), 8, source='2DF08D8.periodic_thread_handle')
        memory.store(frame + 40, 0, 8, source='2DF08DB.periodic_thread_moved_handle')
        memory.store(task + 8, 1, 1, source='2DF08EE.periodic_thread_started')
        runtime.events.append(('high_reliability.thread_pending', task, base + 0x2DF0960))
    _invoke(runtime, 0x75B0A0, task + 64)
    memory.unmap(frame)


def _callback(runtime, descriptor, receiver=None, sequence=0):
    memory, base = runtime.memory, runtime.image_base
    memory.store(descriptor + 8, base + (0x436EBC8 if receiver is None else 0x436EC18), 8,
                 source='high_reliability.callback_vtable')
    if receiver is not None:
        memory.store(descriptor + 16, receiver, 8, source='high_reliability.callback_receiver')
        memory.store(descriptor + 24, sequence, 8, source='high_reliability.callback_sequence')
    memory.store(descriptor + 32, descriptor + 8, 8, source='high_reliability.callback_inline')


def admit(runtime, owner, event):
    from .primary_worker_response import _image, _owner
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0xA0, '2DEC280.high_reliability_admission_frame')
    log(runtime, _FILE, 0x13, b'HighReliabilityReporter report', base + 0x48972C7, 2)
    _invoke(runtime, 0x75B070, owner + 120)
    if memory.load(owner + 168, 1):
        _invoke(runtime, 0x759B30, frame)
        if signed(memory.load(frame, 8) - memory.load(owner + 160, 8), 64) < 86400000000000:
            _invoke(runtime, 0x75B0A0, owner + 120)
            memory.unmap(frame)
            runtime.events.append(('high_reliability.throttled', owner))
            return None
    log(runtime, _FILE, 0x1D, b'HighReliabilityReporter report once doing', base + 0x48972C7, 2)
    memory.store(owner + 168, 1, 1, source='2DECA00.high_reliability_attempted')
    _invoke(runtime, 0x759B30, frame)
    memory.store(owner + 160, memory.load(frame, 8), 8, source='2DECA14.high_reliability_last')
    _owner(runtime, _image())
    _callback(runtime, frame + 8)
    memory.write(frame + 48, bytes(48), source='2DEC280.immediate_metadata_zero')
    for offset in (48, 72):
        _empty(runtime, frame + offset)
    _invoke(runtime, 0x1BF0AD0, base + 0x67519B8, event, frame + 48, frame + 8, 0)
    for offset in (72, 48):
        _String.read(runtime, frame + offset).destroy()
    persist(runtime, owner, event)
    reload(runtime, owner)
    published = memory.load(base + 0x677CCB8, 8)
    if not published:
        published = runtime._operator_new(0xB0)
        construct(runtime, published)
        memory.store(base + 0x677CCB8, published, 8, source='2DEC280.high_reliability_global_publish')
    ensure_task(runtime, memory.load(published + 24, 8))
    _invoke(runtime, 0x75B0A0, owner + 120)
    memory.unmap(frame)


def produce_event(runtime, event, vector, *, frame=None):
    from .primary_sec_init import produce
    construct_event(runtime, event)
    if frame is None:
        frame = runtime._next(runtime._frames, 'VM frame', 'sec-init')
    local, _ = _frame(runtime, 24, '1BF7C39.sec_init_owning_output')
    produce(runtime, local, vector, frame=frame)
    _String.read(runtime, event + 0xE0).destroy()
    _String.read(runtime, local).write_to(event + 0xE0)
    runtime.memory.unmap(local)
    return event


def produce_and_admit(runtime, vector, *, frame=None):
    memory, base = runtime.memory, runtime.image_base
    local, _ = _frame(runtime, 0xF8, '1BF7B54.sec_init_event_frame')
    produce_event(runtime, local, vector, frame=frame)
    owner = memory.load(base + 0x677CCB8, 8)
    if not owner:
        owner = runtime._operator_new(0xB0)
        construct(runtime, owner)
        memory.store(base + 0x677CCB8, owner, 8, source='1BF7C95.high_reliability_publish')
    admit(runtime, owner, local)
    destroy_event(runtime, local)
    memory.unmap(local)
    return owner


def destroy_callback(runtime, descriptor, descriptor_offset=8):
    memory, base = runtime.memory, runtime.image_base
    active = memory.load(descriptor + descriptor_offset + 24, 8)
    if not active:
        return
    table = memory.load(active, 8)
    if table not in (base + 0x436EBC8, base + 0x436EC18):
        raise PrimarySemanticUnavailable('high reliability callback requires its actual source vtable')
    inline = active == descriptor + descriptor_offset
    target = memory.load(table + (24 if inline else 32), 8)
    if target != base + (0x28F0 if inline else 0x1FE0):
        raise PrimarySemanticUnavailable('high reliability callback current destructor differs from source')
    _invoke(runtime, target - base, active)


def clone_callback(runtime, source, destination):
    memory, base = runtime.memory, runtime.image_base
    active = memory.load(source + 32, 8)
    if not active:
        memory.store(destination + 32, 0, 8, source='1BF0F36.empty_callback_clone')
        return
    table = memory.load(active, 8)
    if table not in (base + 0x436EBC8, base + 0x436EC18):
        raise PrimarySemanticUnavailable('high reliability callback clone requires its source vtable')
    inline = active == source + 8
    expected = (0x2DF0A10 if inline else 0x2DF0A20) if table == base + 0x436EBC8 else (0x2DF1450 if inline else 0x2DF1470)
    target = memory.load(table + (8 if inline else 16), 8)
    if target != base + expected:
        raise PrimarySemanticUnavailable('high reliability callback current clone target differs from source')
    if inline:
        _invoke(runtime, expected, active, destination + 8)
        copied = destination + 8
    else:
        copied = _invoke(runtime, expected, active)
    memory.store(destination + 32, copied, 8, source='1BF0F48.callback_clone_owner')


def submit(runtime, owner, event, metadata, function, force):
    from .primary_caller_diagnostics import _Strings
    from .primary_pending_reports import command
    from .primary_request_direct import _command
    from .primary_request_submit import _clone_row, _destroy_row
    from .primary_worker_loop import _initialize
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x200, '1BF0AD0.generic_event_frame')
    if not memory.load(owner, 1) & 1:
        memory.store(frame + 16, 0xFFFFFFFF, 4, source='1BF0B00.disabled_error')
        memory.store(frame + 12, 0, 1, source='1BF0B0A.disabled_success')
        memory.store(frame + 8, 0, 4, source='1BF0B11.disabled_reply_length')
        memory.store(frame, 0, 8, source='1BF0B1B.disabled_reply_pointer')
        active = memory.load(function + 32, 8)
        if not active:
            raise PrimarySemanticUnavailable('1BF1071 empty callback requires original 002374 bad_function_call and unwind')
        target = memory.load(memory.load(active, 8) + 40, 8)
        _invoke(runtime, target - base, active, frame, frame + 8, frame + 12, frame + 16)
        destroy_callback(runtime, function)
        memory.unmap(frame)
        return None
    table = memory.load(event, 8)
    if table != base + 0x4149058:
        raise PrimarySemanticUnavailable('generic event wrapper requires a supported source event vtable')
    if (memory.load(table, 8), memory.load(table + 32, 8)) != (base + 0x1C018C0, base + 0xBCD880):
        raise PrimarySemanticUnavailable('sec-init generic wrapper virtual methods differ from source')
    packet, row, output = frame, frame + 96, frame + 160
    memory.write(packet, bytes(89), source='1BF0B70.generic_packet_fields')
    memory.store(packet, base + 0x3FD73B8, 8, source='1BF0B65.generic_packet_vtable')
    memory.store(packet + 56, base + 0x3FD7428, 8, source='1BF0B7F.generic_packet_nested')
    memory.store(packet + 88, 1, 1, source='1BF0B96.generic_packet_force_fields')
    _initialize(runtime, 0)
    config = base + 0x67516B0
    current = _String.read(runtime, config + 8).clone()
    if not current.value():
        current.destroy()
        current = _String.construct(runtime, b'0')
    current.write_to(packet + 64)
    _invoke(runtime, 0x1C018C0, event, packet + 8)
    memory.write(row, bytes(56), source='1BF0C52.generic_row_fields')
    memory.store(row, base + 0x3FD7498, 8, source='1BF0C44.generic_row_vtable')
    columns = _Strings(runtime)
    for offset in (0x40, 0xA0, 0x70, 0x58):
        _initialize(runtime, 0)
        columns.push(_String.read(runtime, config + offset), clone=True)
    columns.push(_String.read(runtime, event + 8), clone=True)
    _String.read(runtime, event + 0xE0).clone().write_to(row + 32)
    for index in range(columns.count):
        item = columns.at(index)
        if not item.value():
            _append(item, b' ')
            item.write_to(columns.begin + index * 24)
    for offset, value in ((8, columns.begin), (16, columns.begin + columns.count * 24),
                          (24, columns.begin + columns.capacity * 24)):
        memory.store(row + offset, value, 8, source='1BF0C71.generic_row_columns')
    rows = runtime._operator_new(56)
    _clone_row(runtime, rows, row)
    for offset, value in ((32, rows), (40, rows + 56), (48, rows + 56)):
        memory.store(packet + offset, value, 8, source='1BF0DA3.generic_packet_rows')
    _invoke(runtime, 0xBE1730, packet, output)
    serialized = _String.read(runtime, output)
    pointer = serialized.get(16, 8) if serialized.get(0, 1) & 1 else output + 1
    gate = _invoke(runtime, 0xBA21A0)
    if force & 255:
        copied = frame + 208
        clone_callback(runtime, function, copied)
        command(runtime, frame + 256)
        _invoke(runtime, 0x1CE6920, gate, frame + 256, pointer, len(serialized.value()), copied, metadata, 1)
    else:
        _String.construct(runtime, _command(runtime)).write_to(frame + 256)
        _invoke(runtime, 0x1CE2C50, gate, frame + 256, pointer, len(serialized.value()), metadata, 0)
    serialized.destroy()
    _String.read(runtime, row + 32).destroy()
    columns.destroy()
    _destroy_row(runtime, rows)
    runtime._free_allocation(rows)
    _String.read(runtime, packet + 8).destroy()
    _String.read(runtime, packet + 64).destroy()
    destroy_callback(runtime, function)
    runtime.events.append(('high_reliability.generic_submitted', owner, event, force & 255))
    memory.unmap(frame)


def erase(runtime, owner, sequence):
    from .primary_sdk_records import _index
    memory = runtime.memory
    table = owner + 32
    previous, selected = table + 16, 0
    for node in _nodes(runtime, table):
        if memory.load(node + 16, 8) == sequence:
            selected = node
            break
        previous = node
    if not selected:
        return
    memory.store(previous, memory.load(selected, 8), 8, source='2DF1B90.erase_node')
    count, buckets = memory.load(table + 8, 8), memory.load(table, 8)
    for index in range(count):
        memory.store(buckets + 8 * index, 0, 8, source='2DF1B90.bucket_predecessor_reset')
    predecessor = table + 16
    previous_bucket = None
    for node in _nodes(runtime, table):
        bucket = _index(memory.load(node + 8, 8), count)
        if bucket != previous_bucket:
            memory.store(buckets + 8 * bucket, predecessor, 8, source='2DF1B90.bucket_predecessor')
        predecessor, previous_bucket = node, bucket
    memory.store(table + 24, memory.load(table + 24, 8) - 1, 8, source='2DF1B90.map_count')
    destroy_event(runtime, selected + 24)
    runtime._free_allocation(selected)


def complete(runtime, owner, sequence):
    memory = runtime.memory
    frame, _ = _frame(runtime, 72, '2DF02A0.replay_success_frame')
    _invoke(runtime, 0x75B070, owner + 80)
    erase(runtime, owner, sequence)
    memory.write(frame, bytes(24), source='2DF02A0.remaining_vector')
    for node in _nodes(runtime, owner + 32):
        _append_event(runtime, frame, node + 24)
    _invoke(runtime, 0x75B0A0, owner + 80)
    first, last, _ = _vector(runtime, frame)
    if first == last:
        _empty(runtime, frame + 24)
    else:
        format_cache(runtime, frame + 24, frame)
    _invoke(runtime, 0x1BE5B30, owner, frame + 24)
    _String.read(runtime, frame + 24).destroy()
    destroy_vector(runtime, frame)
    memory.unmap(frame)


def replay(runtime, owner):
    from .primary_sdk_records import rehash
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x2D0, '2DEDFA0.replay_frame')
    log(runtime, _FILE, 0x33, b'HighReliabilityReporter doReportTask', runtime.image_base + 0x48972C7, 2)
    _invoke(runtime, 0x75B070, owner + 80)
    snapshot = frame + 40
    memory.write(snapshot, bytes(32), source='2DEEBF0.snapshot_map_zero')
    memory.store(snapshot + 32, memory.load(owner + 64, 4), 4, source='2DEEBF0.snapshot_maxload')
    rehash(runtime, snapshot, memory.load(owner + 40, 8))
    for node in _nodes(runtime, owner + 32):
        insert(runtime, snapshot, frame + 128, node + 16, node + 16, copy=True)
    _invoke(runtime, 0x75B0A0, owner + 80)
    from .primary_worker_response import _image, _owner
    for copied in _nodes(runtime, snapshot):
        first, second = frame + 144, frame + 392
        copy_event(runtime, first, copied + 24)
        copy_event(runtime, second, first)
        _owner(runtime, _image())
        _callback(runtime, frame, owner, memory.load(copied + 16, 8))
        memory.write(frame + 80, bytes(48), source='2DEDFA0.retry_metadata_zero')
        for offset in (80, 104):
            _empty(runtime, frame + offset)
        _invoke(runtime, 0x1BF0AD0, runtime.image_base + 0x67519B8, second, frame + 80, frame, 1)
        for offset in (104, 80):
            _String.read(runtime, frame + offset).destroy()
        destroy_event(runtime, second)
        destroy_event(runtime, first)
    for copied in tuple(_nodes(runtime, snapshot)):
        destroy_event(runtime, copied + 24)
        runtime._free_allocation(copied)
    buckets = memory.load(snapshot, 8)
    memory.store(snapshot, 0, 8, source='2DEEBF0.snapshot_buckets_reset')
    if buckets:
        runtime._free_allocation(buckets)
    memory.unmap(frame)


def run_iteration(runtime, task):
    memory, base = runtime.memory, runtime.image_base
    active = memory.load(task + 48, 8)
    if not active or memory.load(active, 8) != base + 0x41490E8:
        raise PrimarySemanticUnavailable('periodic iteration requires its actual current inline task function')
    if memory.load(active + 8, 8) != base + 0x2DEDFA0:
        raise PrimarySemanticUnavailable('periodic iteration current function differs from source')
    replay(runtime, memory.load(active + 16, 8))
    count = memory.load(task + 104, 8)
    memory.store(task + 104, (count + 1) & _U64, 8, source='2DF0960.periodic_iteration_count')
    milliseconds = signed(memory.load(task + 56, 8) + (count % 33) ** 2 * 1000, 64)
    if milliseconds <= 0:
        raise PrimarySemanticUnavailable('periodic iteration has no positive bounded sleep boundary')
    nanoseconds = min((1 << 63) - 1, milliseconds * 1000000)
    boundary = HighReliabilitySleepBoundary(task, count, nanoseconds)
    runtime.events.append(('high_reliability.sleep_boundary', task, count, nanoseconds, base + 0x760050))
    return boundary


def notify(runtime, first, second):
    from .primary_caller_diagnostics import _Strings
    from .primary_feature_notifications import _logger
    memory, base = runtime.memory, runtime.image_base
    observed = int(feature(runtime, _logger(runtime), 38) == 1)
    log(runtime, b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\core\\fekitcore_bridge.cc',
        0x1B6, b'switch status: %d', base + 0x48972C7, 2, observed)
    if feature(runtime, _logger(runtime), 38) != 1:
        return None
    _invoke(runtime, 0x1BF63F0)
    local, _ = _frame(runtime, 0x138, '1BF7670.sec_init_notification_frame')
    values = _Strings(runtime)
    values.push(_String.read(runtime, first), clone=True)
    values.push(_String.read(runtime, second), clone=True)
    for offset, value in ((0, values.begin), (8, values.begin + values.count * 24),
                          (16, values.begin + values.capacity * 24)):
        memory.store(local + offset, value, 8, source='1BF7B03.sec_init_inputs')
    event = local + 32
    produce_event(runtime, event, local)
    owner = memory.load(base + 0x677CCB8, 8)
    if not owner:
        owner = runtime._operator_new(0xB0)
        construct(runtime, owner)
        memory.store(base + 0x677CCB8, owner, 8, source='1BF7C95.high_reliability_publish')
    admit(runtime, owner, event)
    if feature(runtime, _logger(runtime), 42) == 1:
        from .primary_super_reporter import submit_joint
        submit_joint(runtime, event)
    destroy_event(runtime, event)
    values.destroy()
    memory.unmap(local)
    return None


def invoke(runtime, rva, values):
    if rva == 0xB8F200:
        if not values:
            raise InputError('periodic task invocation requires its actual active function')
        active = values[0]
        target = runtime.memory.load(active + 8, 8)
        receiver = runtime.memory.load(active + 16, 8)
        return _invoke(runtime, target - runtime.image_base, receiver, *values[1:])
    entries = {0x2DF2230: (initialize, 0), 0x1C01F50: (construct, 1),
               0x1C02220: (construct_task, 3), 0x2DEC280: (admit, 2),
               0x2DECDE0: (persist, 2), 0x2DED550: (reload, 1),
               0x2DF0870: (ensure_task, 1), 0x2DF1D40: (insert, 4),
               0x1BF0AD0: (submit, 5), 0x2DF02A0: (complete, 2),
               0x2DEDFA0: (replay, 1), 0x1BF7670: (notify, 2)}
    if rva in entries:
        function, count = entries[rva]
        if len(values) != count:
            raise InputError('high reliability source entry argument count mismatch')
        return function(runtime, *values)
    if rva in (0x2DEFA30, 0x2DEED00) and len(values) == 3:
        return (format_cache if rva == 0x2DEFA30 else parse_cache)(runtime, values[1], values[2])
    if rva == 0x787920 and len(values) == 1:
        return int(runtime.memory.load(values[0], 8) == 0)
    if rva in (0x2DF1450, 0x2DF1470, 0x2DF0A10, 0x2DF0A20):
        captured = rva in (0x2DF1450, 0x2DF1470)
        heap = rva in (0x2DF1470, 0x2DF0A20)
        if len(values) != (1 if heap else 2):
            raise InputError('high reliability callback clone argument count mismatch')
        destination = runtime._operator_new(24 if captured else 16) if heap else values[1]
        table = runtime.image_base + (0x436EC18 if captured else 0x436EBC8)
        runtime.memory.store(destination, table, 8, source='high_reliability.callback_clone_vtable')
        if captured:
            runtime.memory.write(destination + 8, runtime.memory.read(values[0] + 8, 16),
                                 source='high_reliability.callback_clone_capture')
        return destination if heap else table
    if rva == 0xBCD880 and len(values) == 2:
        _String.read(runtime, values[0] + 0xE0).clone().write_to(values[1])
        return values[1]
    if rva == 0x776860 and len(values) == 2:
        _empty(runtime, values[1], True)
        return values[1]
    if rva == 0x2DF14A0 and len(values) == 5:
        active, reply, count, success, error = values
        if runtime.memory.load(success, 1):
            return complete(runtime, runtime.memory.load(active + 8, 8), runtime.memory.load(active + 16, 8))
        return None
    if rva == 0x2DF0A40 and len(values) == 5:
        log(runtime, _FILE, 0x24, b'HighReliabilityReporter Early report succ: %d',
            runtime.image_base + 0x48972C7, 2, runtime.memory.load(values[3], 1))
        return None
    raise InputError('unsupported high reliability source entry')
