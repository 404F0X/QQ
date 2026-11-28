from .errors import InputError
from .primary_logger import _String, _srw
from .primary_request_audit import _copy
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _invoke
from .primary_worker_response import _frame
from .primary_worker_tasks import _observe
from .wire import encode_u64


def _columns(runtime, record):
    from .primary_caller_diagnostics import _columns as read
    return read(runtime, record + 8)


def _write(runtime, address, values):
    from .primary_caller_online import _write_columns
    _write_columns(runtime, address + 8, values)


def _destroy(runtime, record):
    from .primary_caller_online import _destroy_columns
    _destroy_columns(runtime, record + 8)


def _clone(runtime, destination, source):
    runtime.memory.store(destination, runtime.memory.load(source, 4), 4, source='caller.online_queue_record_time')
    _write(runtime, destination, _columns(runtime, source).clone())
    runtime.memory.store(destination + 32, runtime.memory.load(source + 32, 4), 4,
                         source='caller.online_queue_record_state')


def serialize(runtime, record, output):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0xC8, '1CFFE20.caller_online_queue_serialize_frame')
    memory.write(output, bytes(24), source='1CFFE4C.online_queue_serialized_empty')
    result = _String(runtime, bytes(24), bytes([1]) * 24)

    def integer(key, value):
        if value:
            for byte in encode_u64(key << 3) + encode_u64(value & ((1 << 64) - 1)):
                _append(result, bytes([byte]))

    integer(1, memory.load(record, 4, signed=True))
    values = _columns(runtime, record)
    for index in range(values.count):
        first = values.at(index).clone()
        second = first.clone()
        raw = bytes(byte ^ 255 for byte in second.value())
        if second.get(0, 1) & 1:
            memory.write(second.get(16, 8), raw + b'\0', source='1D0019B.online_queue_inverted_column')
        else:
            second.set(1, raw + b'\0')
        if raw:
            for byte in encode_u64(18) + encode_u64(len(raw)):
                _append(result, bytes([byte]))
            _append(result, raw)
        second.destroy()
        first.destroy()
    integer(3, memory.load(record + 32, 4, signed=True))
    result.write_to(output)
    memory.unmap(frame)
    return output


def persist(runtime, manager, record):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x58, '1CFFCF0.caller_online_queue_persist_frame')
    rbp = frame + 0x50
    key = _String.read(runtime, manager).clone()
    _append(key, str(memory.load(record, 4, signed=True)).encode('ascii'))
    serialize(runtime, record, rbp - 0x18)
    value = _String.read(runtime, rbp - 0x18)
    backend = memory.load(base + 0x677BE78, 8)
    if backend:
        raise PrimarySemanticUnavailable('caller online queue persistence requires its actual nonnull storage interface')
    runtime.events.append(('caller.online_queue_persist', key.value(), value.value(), backend))
    value.destroy()
    key.destroy()
    memory.unmap(frame)


def restore(runtime, manager):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x178, '1CFBA20.caller_online_queue_restore_frame')
    if memory.load(base + 0x677BE28, 8):
        raise PrimarySemanticUnavailable('caller online queue restore requires its actual nonnull storage enumeration interface')
    memory.store(rbp, rbp + 8, 8, source='1BE5C1A.empty_online_queue_storage_begin')
    memory.write(rbp + 8, bytes(16), source='1BE5C16.empty_online_queue_storage_tree')
    runtime.events.append(('caller.online_queue_restored', manager, 0))
    memory.unmap(frame)


def append_node(runtime, head, record):
    memory = runtime.memory
    node = runtime._operator_new(56)
    memory.store(node, 0, 8, source='1CFFBA9.online_queue_node_initial_previous')
    _clone(runtime, node + 16, record)
    memory.store(node + 8, head, 8, source='1CFFC5C.online_queue_node_next')
    previous = memory.load(head, 8)
    memory.store(node, previous, 8, source='1CFFC63.online_queue_node_previous')
    memory.store(previous + 8, node, 8, source='1CFFC66.online_queue_previous_next')
    memory.store(head, node, 8, source='1CFFC6A.online_queue_previous')
    memory.store(head + 16, memory.load(head + 16, 8) + 1, 8, source='1CFFC6D.online_queue_count')


def _initialize_list(runtime, head):
    for offset, value in ((0, head), (8, head), (16, 0)):
        runtime.memory.store(head + offset, value, 8, source='caller.online_record_list_initialization')


def _nodes(runtime, head):
    count = runtime.memory.load(head + 16, 8)
    if count > 4096:
        raise PrimaryProgramLimit('caller online record list exceeds its bounded domain')
    node = runtime.memory.load(head + 8, 8)
    for _ in range(count):
        if node == head:
            raise PrimarySemanticUnavailable('caller online record list ends before its actual count')
        yield node
        node = runtime.memory.load(node + 8, 8)
    if node != head:
        raise PrimarySemanticUnavailable('caller online record list does not end at its actual sentinel')


def _clone_list(runtime, destination, source):
    _initialize_list(runtime, destination)
    for node in _nodes(runtime, source):
        append_node(runtime, destination, node + 16)


def clear(runtime, head):
    memory = runtime.memory
    nodes = list(_nodes(runtime, head))
    if not nodes:
        return
    first, last = nodes[0], nodes[-1]
    following, previous = memory.load(last + 8, 8), memory.load(first, 8)
    memory.store(previous + 8, following, 8, source='BD4913.online_record_list_unlink_next')
    memory.store(following, previous, 8, source='BD491E.online_record_list_unlink_previous')
    memory.store(head + 16, 0, 8, source='BD4921.online_record_list_empty_count')
    for node in nodes:
        _destroy(runtime, node + 16)
        runtime._free_allocation(node)


def _move_list(runtime, destination, source):
    memory = runtime.memory
    _initialize_list(runtime, destination)
    count = memory.load(source + 16, 8)
    if count:
        first, last = memory.load(source + 8, 8), memory.load(source, 8)
        memory.store(last + 8, destination, 8, source='1D01CD1.online_callback_list_next')
        memory.store(first, destination, 8, source='1D01CD9.online_callback_list_previous')
        memory.store(destination, last, 8, source='1D01CDC.online_callback_list_last')
        memory.store(destination + 8, first, 8, source='1D01CE0.online_callback_list_first')
        memory.store(destination + 16, count, 8, source='1D01CEB.online_callback_list_count')
        memory.store(source + 16, 0, 8, source='1D01CEF.online_callback_source_empty_count')


def callback_copy(runtime, source, destination=None):
    memory, base = runtime.memory, runtime.image_base
    heap = destination is None
    frame, _ = _frame(runtime, 0x40 if heap else 0x30, '1D028D0.online_queue_callback_copy_frame' if heap
                       else '1D02830.online_queue_callback_copy_frame')
    if heap:
        destination = runtime._operator_new(48)
    memory.store(destination, base + 0x414B5E8, 8, source='1D028F8.online_queue_callback_vtable')
    memory.store(destination + 8, memory.load(source + 8, 8), 8, source='1D028FF.online_queue_callback_manager')
    _clone_list(runtime, destination + 16, source + 16)
    memory.unmap(frame)
    return destination if heap else None


def consume(runtime, manager, head):
    from .primary_caller_diagnostics import _cache_append, submit_cached
    from .primary_caller_online import _destroy_record, _write_columns
    from .primary_worker_response import _image as response_image, _owner
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x218, '1D019D0.caller_online_consume_frame')
    cache, record = rbp + 0x110, rbp - 0x30
    memory.write(cache, bytes(24), source='1D01A00.online_consumer_local_cache')
    if not memory.load(head + 16, 8):
        memory.unmap(frame)
        return
    for node in _nodes(runtime, head):
        first = _String.construct(runtime, b'event')
        first.set(16, bytes(8))
        first.write_to(record + 8)
        for offset in range(32, 200, 24):
            _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(record + offset)
        memory.write(record + 200, bytes(48), source='1D01AB4.online_consumer_record_vectors')
        memory.store(record, base + 0x414B558, 8, source='1D01ACE.online_consumer_record_vtable')
        _write_columns(runtime, record + 224, _columns(runtime, node + 16).clone())
        _cache_append(runtime, cache, record)
        _destroy_record(runtime, record)
    first_list, second_list = rbp + 0x158, rbp + 0x138
    memory.store(first_list - 8, manager, 8, source='1D01BA8.online_consumer_first_manager')
    _clone_list(runtime, first_list, head)
    _owner(runtime, response_image())
    memory.store(second_list - 8, manager, 8, source='1D01C15.online_consumer_second_manager')
    _clone_list(runtime, second_list, first_list)
    function = rbp - 0x58
    memory.store(function + 32, 0, 8, source='1D01C62.online_consumer_empty_callback')
    captured = runtime._operator_new(48)
    memory.store(captured, base + 0x414B5E8, 8, source='1D01C7B.online_consumer_callback_vtable')
    memory.store(captured + 8, manager, 8, source='1D01C85.online_consumer_callback_manager')
    _move_list(runtime, captured + 16, second_list)
    memory.store(function + 32, captured, 8, source='1D01CFA.online_consumer_callback_owner')
    for address in (rbp + 0xD0, rbp + 0xE8):
        _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(address)
    metadata = rbp - 0x30
    memory.write(metadata, bytes(48), source='1D01D13.online_consumer_metadata')
    _String.read(runtime, rbp + 0xE8).clone().write_to(metadata)
    _String.read(runtime, rbp + 0xD0).clone().write_to(metadata + 24)
    submit_cached(runtime, base + 0x67519B8, cache, metadata, function)
    for address in (metadata + 24, metadata, rbp + 0xE8, rbp + 0xD0):
        _String.read(runtime, address).destroy()
    clear(runtime, first_list)
    begin, end = (memory.load(cache + offset, 8) for offset in (0, 8))
    for address in reversed(range(begin, end, 248)):
        _destroy_record(runtime, address)
    if begin:
        memory.store(cache + 8, begin, 8, source='1D01F14.online_consumer_cache_empty_end')
        runtime._free_allocation(begin)
    runtime.events.append(('caller.online_queue_consumed', manager, memory.load(head + 16, 8)))
    memory.unmap(frame)


def push(runtime, head, record, notify):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x118, '1CFF2C0.caller_online_queue_push_frame')
    if not memory.load(head + 45, 1) & 1:
        raise PrimarySemanticUnavailable('caller online disabled queue diagnostics are not implemented')
    _srw(runtime, head + 24, True)
    capacity = memory.load(head + 40, 4, signed=True) & ((1 << 64) - 1)
    if memory.load(head + 16, 8) >= capacity:
        raise PrimarySemanticUnavailable('caller online full queue diagnostics are not implemented')
    append_node(runtime, head, record)
    if notify:
        result, effects = _observe(runtime, 'WakeConditionVariable', head + 32)
        if result is not None or effects != ():
            raise PrimarySemanticUnavailable('caller online queue wake requires actual concurrent effects')
    _srw(runtime, head + 24, False)
    _destroy(runtime, record)
    memory.unmap(frame)


def relay(runtime, head, record, notify):
    frame, _ = _frame(runtime, 0x60, '1CFEF20.caller_online_queue_relay_frame' if not notify
                         else '1CFF0F0.caller_online_queue_relay_frame')
    temporary = frame + 0x20
    _clone(runtime, temporary, record)
    push(runtime, head, temporary, notify)
    _destroy(runtime, record)
    runtime.memory.unmap(frame)


def admit(runtime, task, record):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x90, '1CFEC10.caller_online_queue_admit_frame')
    previous = memory.load(task + 0xF8, 1)
    if not previous:
        memory.store(task + 0xF8, 1, 1, source='1CFEC38.online_task_start_claim')
        _invoke(runtime, 0xBD49E0, task)
    notify = memory.load(task + 0xD8, 4) != 1
    temporary = rbp - (0x30 if notify else 0x58)
    _clone(runtime, temporary, record)
    relay(runtime, task + 96, temporary, notify)
    _destroy(runtime, record)
    memory.unmap(frame)


def enqueue(runtime, manager, scene, event, columns):
    from .primary_caller_diagnostics import _Strings, _columns as read_columns
    from .primary_caller_online import _destroy_columns, scene_value
    from .primary_logger import _cstring
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0xB8, '1CFC560.caller_online_queue_record_frame')
    record = rbp - 0x10
    memory.write(record + 8, bytes(28), source='1CFC593.online_queue_record_initialization')
    _invoke(runtime, 0x759A80, rbp + 0x18)
    microseconds = memory.load(rbp + 0x18, 8, signed=True)
    high = microseconds * 0x20C49BA5E353F7CF >> 64
    milliseconds = ((high & ((1 << 64) - 1)) >> 7) + ((high & ((1 << 64) - 1)) >> 63)
    memory.store(record, milliseconds & 0xFFFFFFFF, 4, source='1CFC5BF.online_queue_record_time')
    values = _Strings(runtime)
    values.push(_String.construct(runtime, _cstring(runtime, scene)))
    values.push(_String.construct(runtime, _cstring(runtime, scene_value(runtime, manager, scene, True))))
    values.push(_String.construct(runtime, _cstring(runtime, scene_value(runtime, manager, scene))))
    values.push(_String.construct(runtime, _cstring(runtime, event)))
    values.extend(read_columns(runtime, columns))
    if values.count == 4:
        values.push(_String.construct(runtime, b'-1'))
    if values.count >= 5:
        _invoke(runtime, 0x759A80, rbp - 0x20)
        _invoke(runtime, 0x1CF5CB0, rbp + 0x18, rbp - 0x20)
        current = _String.read(runtime, rbp + 0x18)
        if values.count >= 6:
            values.insert(5, current)
        else:
            values.push(current)
    if _cstring(runtime, event) == _String.read(runtime, manager + 0x48).value():
        values.push(_String.construct(runtime, b'-1'))
    _write(runtime, record, values)
    persist(runtime, manager, record)
    argument = rbp - 0x48
    memory.store(argument, memory.load(record, 4), 4, source='1CFCA44.online_queue_record_move_time')
    _copy(runtime, record + 8, argument + 8, 24)
    memory.write(record + 8, bytes(24), source='1CFCA5E.online_queue_record_moved_empty')
    memory.store(argument + 32, memory.load(record + 32, 4), 4, source='1CFCA6C.online_queue_record_move_state')
    admit(runtime, memory.load(manager + 0xC0, 8), argument)
    _destroy(runtime, record)
    _destroy_columns(runtime, columns)
    runtime.events.append(('caller.online_queued', manager))
    memory.unmap(frame)


def invoke(runtime, rva, values):
    handlers = {0x1CFC560: (enqueue, 4), 0x1CFBA20: (restore, 1), 0x1CFFCF0: (persist, 2),
                0x1CFFE20: (serialize, 2), 0x1CFEC10: (admit, 2), 0x1CFF2C0: (push, 3),
                0x1CFFB80: (append_node, 2), 0x1D019D0: (consume, 2), 0xBD48F0: (clear, 1),
                0x1D02830: (callback_copy, 2), 0x1D028D0: (callback_copy, 1)}
    if rva in (0x1D02990, 0x1D029A0, 0x1D027F0) and len(values) == (2 if rva == 0x1D027F0 else 1):
        if rva == 0x1D027F0:
            runtime.memory.store(values[0], runtime.image_base + 0x414B5E8, 8, source='1D02807.online_callback_destroy_vtable')
        clear(runtime, values[0] + 16)
        if rva == 0x1D029A0 or rva == 0x1D027F0 and values[1] & 1:
            runtime._free_allocation(values[0])
        return values[0] if rva == 0x1D027F0 else None
    if rva in (0x1CFEF20, 0x1CFF0F0) and len(values) == 2:
        return relay(runtime, *values, notify=rva == 0x1CFF0F0)
    handler, count = handlers[rva]
    if len(values) != count:
        raise InputError('caller online queue native argument count mismatch')
    return handler(runtime, *values)
