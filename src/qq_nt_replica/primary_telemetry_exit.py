from .primary_feature_notifications import release_owner
from .primary_logger import _String
from .primary_provider_init import _mutex
from .primary_task_exit import destroy_base_record
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_tasks import _observe


def _vector(runtime, header, stride, destroy):
    memory = runtime.memory
    begin = memory.load(header, 8)
    if not begin:
        return
    end = memory.load(header + 8, 8)
    if end < begin or (end - begin) % stride:
        raise PrimaryProgramLimit('telemetry exit vector has an invalid source layout')
    if end != begin:
        memory._span(begin, end - begin)
    cursor = end
    while cursor != begin:
        cursor -= stride
        destroy(runtime, cursor)
    memory.store(header + 8, begin, 8, source='telemetry_exit.vector_end_reset')
    runtime._free_allocation(begin)


def _record68(runtime, record):
    for offset in (0x30, 0x18, 0):
        _String.read(runtime, record + offset).destroy()


def _record_f8(runtime, record):
    runtime.memory.store(record, runtime.image_base + 0x3FD6BA8, 8,
                         source='BCD380.telemetry_record_vtable')
    _String.read(runtime, record + 0xE0).destroy()
    destroy_base_record(runtime, record)


def destroy_embedded(runtime, owner):
    memory = runtime.memory
    memory.store(owner, runtime.image_base + 0x3FD6B68, 8,
                 source='BCD6A0.telemetry_base_vtable')
    _mutex(runtime, owner + 0x10, True)
    if memory.load(owner + 8, 1):
        result, effects = _observe(runtime, 'WakeConditionVariable', owner + 0x28)
        if result is not None or effects != ():
            raise PrimarySemanticUnavailable('telemetry condition wake requires a void result and no concurrent effects')
        memory.store(owner + 8, 0, 1, source='BCD6A0.telemetry_stop_flag')
    _mutex(runtime, owner + 0x10, False)
    _String.read(runtime, owner + 0x38).destroy()
    release_owner(runtime, owner + 0x20)


def destroy_telemetry(runtime):
    memory, owner = runtime.memory, runtime.image_base + 0x67519B8
    node = memory.load(owner + 0xD8, 8)
    seen = set()
    while node:
        if node in seen or len(seen) >= 100000:
            raise PrimaryProgramLimit('telemetry owned list does not terminate')
        seen.add(node)
        following = memory.load(node, 8)
        _String.read(runtime, node + 0x18).destroy()
        runtime._free_allocation(node)
        node = following
    raw = memory.load(owner + 0xC8, 8)
    memory.store(owner + 0xC8, 0, 8, source='BCD380.telemetry_raw_clear')
    if raw:
        runtime._free_allocation(raw)
    if memory.load(owner + 0xC0, 8):
        sentinel = owner + 0xB0
        tail = memory.load(owner + 0xB0, 8)
        first = memory.load(owner + 0xB8, 8)
        following = memory.load(tail + 8, 8)
        before = memory.load(first, 8)
        memory.store(before + 8, following, 8, source='BCD380.telemetry_list_detach_next')
        before = memory.load(first, 8)
        following = memory.load(tail + 8, 8)
        memory.store(following, before, 8, source='BCD380.telemetry_list_detach_previous')
        memory.store(owner + 0xC0, 0, 8, source='BCD380.telemetry_list_count_clear')
        node = first
        seen = set()
        while node != sentinel:
            if node in seen or len(seen) >= 100000:
                raise PrimaryProgramLimit('telemetry control list does not reach its sentinel')
            seen.add(node)
            following = memory.load(node + 8, 8)
            release_owner(runtime, node + 0x10)
            runtime._free_allocation(node)
            node = following
    memory.store(owner + 0x20, runtime.image_base + 0x3FD6AA8, 8,
                 source='BCD380.telemetry_owner_vtable')
    _vector(runtime, owner + 0x88, 0x68, _record68)
    destroy_embedded(runtime, owner + 0x20)
    _vector(runtime, owner + 8, 0xF8, _record_f8)
