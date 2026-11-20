import re

from .errors import InputError
from .primary_cocos import next_mt, seed_mt
from .primary_device_refresh import _logger
from .primary_logger import _cstring, _String, feature, log
from .primary_request_audit import _copy
from .primary_request_transport import _Map
from .primary_vm import PrimarySemanticUnavailable, signed
from .primary_worker_consumer import _append, _invoke
from .primary_worker_response import _frame, _image as _response_image, _owner


_VTABLE = 0x414B698
_SOURCE = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\platforms\\Windows\\..\\..\\channel\\include\\reporter/ui_reporter.h'


def _virtual(runtime, active, offset, *arguments):
    target = runtime.memory.load(runtime.memory.load(active, 8) + offset, 8) - runtime.image_base
    if target not in (0x1D040D0, 0x1D040F0, 0x28F0, 0x1FE0):
        raise PrimarySemanticUnavailable('caller online manager function target is not bound')
    if target in (0x1D040D0, 0x1D040F0):
        return _invoke(runtime, target, active, *arguments)
    if target == 0x1FE0:
        runtime._free_allocation(active)


def _destroy(runtime, function):
    active = runtime.memory.load(function + 32, 8)
    if active:
        _virtual(runtime, active, 24 if active == function + 8 else 32)


def set_consumer(runtime, task, function):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x60, '1D026F0.caller_online_consumer_frame')
    temporary = frame + 0x60 - 0x38
    active = memory.load(function + 32, 8)
    if not active:
        memory.store(temporary + 24, 0, 8, source='1D0272F.empty_online_consumer')
    elif active == function + 8:
        memory.store(temporary + 24, temporary, 8, source='1D02735.inline_online_consumer')
        _virtual(runtime, active, 8, temporary)
    else:
        memory.store(temporary + 24, _virtual(runtime, active, 16), 8, source='1D0272F.copied_online_consumer')
    _invoke(runtime, 0xBED870, temporary, task + 0xA0)
    active = memory.load(temporary + 24, 8)
    if active:
        _virtual(runtime, active, 24 if active == temporary else 32)
    _destroy(runtime, function)
    memory.unmap(frame)


def construct(runtime, manager):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0xD8, '1D00FC0.caller_online_manager_frame')
    for offset, value in enumerate((b'uiReport_', b'begin', b'end', b'0x0105', b'LoginPageShow', b'LoginPageEnd')):
        _String.construct(runtime, value).write_to(manager + offset * 24)
    for offset in (0x90, 0xA8):
        memory.store(manager + offset, manager + offset + 8, 8, source='1D0162D.online_map_begin')
        memory.write(manager + offset + 8, bytes(16), source='1D01621.online_map_root_count')
    for offset, width in ((0xC0, 8), (0xC8, 1), (0xCC, 4)):
        memory.store(manager + offset, 0, width, source='1D01659.online_manager_state')
    task = runtime._operator_new(256)
    _invoke(runtime, 0xBD4710, task, base + 0x47A926A, 1)
    memory.store(task + 0xC4, 0xA00000005, 8, source='1D016A8.online_task_timing')
    memory.store(manager + 0xC0, task, 8, source='1D016B3.online_task_publish')
    function = runtime._operator_new(32)
    for offset, value in ((0, base + _VTABLE), (8, base + 0x1D019D0), (16, manager)):
        memory.store(function + offset, value, 8, source='1D016C4.online_consumer_capture')
    copied = _invoke(runtime, 0x1D040F0, function)
    memory.store(rbp - 0x38, copied, 8, source='1D016E9.online_consumer_owner')
    set_consumer(runtime, task, rbp - 0x58)
    _virtual(runtime, function, 32)
    runtime.events.append(('caller.online_manager_constructed', manager, task))
    memory.unmap(frame)
    return manager


def _node(runtime, table, key):
    current = table.find(key.value())
    if current:
        return current, False
    current = runtime._operator_new(80)
    key.write_to(current + 32)
    runtime.memory.write(current + 56, bytes(24), source='1CFA698.online_map_value_empty')
    table.insert_node(key.value(), current)
    return current, True


def _assign_text(runtime, address, raw):
    current = _String.read(runtime, address)
    long = current.get(0, 1) & 1
    capacity = (current.get(0, 8) & ~1) - 1 if long else 22
    if len(raw) > capacity:
        physical = (max(2 * capacity, len(raw)) | 15) + 1
        from .primary_worker_consumer import _invoke
        pointer = _invoke(runtime, 0xB75000, physical)
        runtime.memory.write(pointer, raw + b'\0', source='75CD00.online_map_value_growth')
        current.destroy()
        current.set(0, (physical | 1).to_bytes(8, 'little'))
        current.set(8, len(raw).to_bytes(8, 'little'))
        current.set(16, pointer.to_bytes(8, 'little'))
    elif long:
        runtime.memory.write(current.get(16, 8), raw + b'\0', source='75CD00.online_map_value_payload')
        current.set(8, len(raw).to_bytes(8, 'little'))
    else:
        current.set(0, bytes([len(raw) * 2]))
        current.set(1, raw + b'\0')
    current.write_to(address)


def register_scene(runtime, manager, scene, correlation):
    scene, correlation = _cstring(runtime, scene), _cstring(runtime, correlation)
    for offset, raw in ((0x90, b'0'), (0xA8, correlation)):
        key = _String.construct(runtime, scene)
        node, moved = _node(runtime, _Map(runtime, manager + offset, True), key)
        _assign_text(runtime, node + 56, raw)
        if not moved:
            key.destroy()


def _find(runtime, manager, scene, offset):
    key = _String.construct(runtime, scene)
    node = _Map(runtime, manager + offset, True).find(scene)
    key.destroy()
    return node


def _value_node(runtime, manager, scene, offset):
    key = _String.construct(runtime, scene)
    node, moved = _node(runtime, _Map(runtime, manager + offset, True), key)
    if not moved:
        key.destroy()
    return node


def scene_value(runtime, manager, scene, counter=False):
    scene = _cstring(runtime, scene)
    offset = 0x90 if counter else 0xA8
    if not _find(runtime, manager, scene, offset):
        return runtime.image_base + 0x48B0A37
    node = _value_node(runtime, manager, scene, offset)
    if counter:
        current = _String.read(runtime, node + 56).clone()
        match = re.match(rb'[\x09-\x0d ]*([+-]?\d+)', current.value())
        number = int(match.group(1)) if match else 0
        if not -(1 << 31) <= number < 1 << 31:
            raise PrimarySemanticUnavailable('caller online counter requires actual CRT overflow and errno effects')
        updated = _String.construct(runtime, str(signed(number + 1, 32)).encode('ascii'))
        node = _value_node(runtime, manager, scene, offset)
        _String.read(runtime, node + 56).destroy()
        updated.write_to(node + 56)
        node = _value_node(runtime, manager, scene, offset)
        current.destroy()
    value = _String.read(runtime, node + 56)
    return value.get(16, 8) if value.get(0, 1) & 1 else node + 57


def erase_scene(runtime, manager, scene):
    scene = _cstring(runtime, scene)
    for offset in (0x90, 0xA8):
        key = _String.construct(runtime, scene)
        table = _Map(runtime, manager + offset, True)
        node = table.find(scene)
        if node:
            table.erase(node)
            for value_offset in (56, 32):
                _String.read(runtime, node + value_offset).destroy()
            runtime._free_allocation(node)
        key.destroy()


def correlation(runtime, manager, output):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x148, '1CFA8C0.caller_online_correlation_frame')
    guard = base + 0x677D2B8
    state = memory.load(guard, 4)
    if not state & 1:
        memory.store(guard, state | 1, 4, source='1CFAA0E.correlation_device_guard')
        _String.construct(runtime, b'/dev/urandom').write_to(rbp - 0x60)
        _invoke(runtime, 0x7602D0, base + 0x677D2B4, rbp - 0x60)
        _String.read(runtime, rbp - 0x60).destroy()
        _invoke(runtime, 0x3E680B4, base + 0x1CFD300)
        state = memory.load(guard, 4)
    generator = base + 0x677D2C0
    if not state & 2:
        memory.store(guard, state | 2, 4, source='1CFAA6D.correlation_mt_guard')
        seed = _invoke(runtime, 0x7603B0, base + 0x677D2B4)
        seed_mt(memory, generator, seed)
    ios = rbp + 0x20
    for offset in (0x38, 0x40, 0x58, 0x70):
        memory.store(ios + offset, 0, 8, source='760754.correlation_stream_owned_storage')
    stream = _String(runtime, bytes(24), bytes([1]) * 24)
    digits = b'0123456789abcdef'
    for index in range(32):
        value = next_mt(memory, generator) & 15
        if index in (8, 12, 16, 20):
            _append(stream, b'-')
        _append(stream, digits[value:value + 1])
    result = _String.construct(runtime, stream.value())
    result.write_to(output)
    stream.destroy()
    for offset in (0x38, 0x40, 0x58, 0x70):
        _invoke(runtime, 0x3E94F90, memory.load(ios + offset, 8))
    runtime.events.append(('caller.online_correlation', result.value()))
    memory.unmap(frame)
    return output


def _write_columns(runtime, address, values):
    for offset, value in ((0, values.begin), (8, values.begin + values.count * 24),
                          (16, values.begin + values.capacity * 24)):
        runtime.memory.store(address + offset, value, 8, source='caller.online_columns')


def _destroy_columns(runtime, address):
    from .primary_caller_diagnostics import _columns
    values = _columns(runtime, address)
    if values.begin:
        runtime.memory.store(address + 8, values.begin, 8, source='caller.online_columns_destroy_end')
    values.destroy()


def _destroy_record(runtime, address):
    runtime.memory.store(address, runtime.image_base + 0x414B558, 8, source='1CFB24C.online_record_vtable')
    _destroy_columns(runtime, address + 224)
    _invoke(runtime, 0xBCD740, address)


def direct(runtime, manager, scene, event, columns):
    from .primary_caller_diagnostics import _Strings, _cache_append, _columns, submit_cached
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x1E8, '1CFAC00.caller_online_direct_frame')
    cache, record = rbp + 0x100, rbp - 0x30
    memory.write(cache, bytes(24), source='1CFAC39.online_local_cache')
    first = _String.construct(runtime, b'event')
    first.set(16, bytes(8))
    first.write_to(record + 8)
    for offset in range(32, 200, 24):
        _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(record + offset)
    memory.write(record + 200, bytes(48), source='1CFAC91.online_record_vectors')
    memory.store(record, base + 0x414B558, 8, source='1CFACAA.online_record_vtable')
    values = _Strings(runtime)
    values.push(_String.construct(runtime, _cstring(runtime, scene)))
    values.push(_String.construct(runtime, _cstring(runtime, scene_value(runtime, manager, scene, True))))
    values.push(_String.construct(runtime, _cstring(runtime, scene_value(runtime, manager, scene))))
    values.push(_String.construct(runtime, _cstring(runtime, event)))
    values.extend(_columns(runtime, columns))
    _invoke(runtime, 0x759A80, rbp + 0xE0)
    _invoke(runtime, 0x1CF5CB0, rbp + 0x120, rbp + 0xE0)
    current = _String.read(runtime, rbp + 0x120)
    if values.count >= 6:
        values.insert(5, current)
    else:
        values.push(current)
    _write_columns(runtime, record + 224, values)
    _cache_append(runtime, cache, record)
    _owner(runtime, _response_image())
    metadata, callback = rbp + 0x120, rbp - 0x58
    memory.write(metadata, bytes(48), source='1CFB1A6.online_direct_metadata')
    memory.store(callback + 32, 0, 8, source='1CFB18C.online_direct_callback')
    submit_cached(runtime, base + 0x67519B8, cache, metadata, callback)
    _destroy_record(runtime, record)
    begin, end = (memory.load(cache + offset, 8) for offset in (0, 8))
    for address in reversed(range(begin, end, 248)):
        _destroy_record(runtime, address)
    if begin:
        memory.store(cache + 8, begin, 8, source='1CFB374.online_local_cache_destroy_end')
        runtime._free_allocation(begin)
    _destroy_columns(runtime, columns)
    runtime.events.append(('caller.online_direct', manager))
    memory.unmap(frame)


def receive(runtime, manager, scene, event, columns):
    from .primary_caller_diagnostics import _columns
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x130, '1CF9D70.caller_online_receive_frame')
    event_text = _cstring(runtime, event)
    if event_text in (_String.read(runtime, manager + 0x18).value(), _String.read(runtime, manager + 0x60).value()):
        correlation(runtime, manager, rbp + 8)
        current = _String.read(runtime, rbp + 8)
        register_scene(runtime, manager, scene, current.value())
        current.destroy()
    if feature(runtime, _logger(runtime), 16) == 1:
        from .primary_caller_queue import enqueue, restore
        if not memory.load(manager + 0xC8, 1):
            memory.store(manager + 0xC8, 1, 1, source='1CF9E3C.online_manager_start_claim')
            _invoke(runtime, 0xBD49E0, memory.load(manager + 0xC0, 8))
            restore(runtime, manager)
        forwarded = _columns(runtime, columns).clone()
        _write_columns(runtime, rbp - 0x30, forwarded)
        enqueue(runtime, manager, scene, event, rbp - 0x30)
    else:
        log(runtime, _SOURCE, 58, b'QSec_Channel NewThread Deny!', b'[FGESDK]', 1)
        forwarded = _columns(runtime, columns).clone()
        _write_columns(runtime, rbp - 0x50, forwarded)
        direct(runtime, manager, scene, event, rbp - 0x50)
    if event_text in (_String.read(runtime, manager + 0x30).value(), _String.read(runtime, manager + 0x78).value()):
        scene_value(runtime, manager, scene)
        erase_scene(runtime, manager, scene)
    _destroy_columns(runtime, columns)
    runtime.events.append(('caller.online_received', manager, event_text))
    memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva == 0x1CF9D70 and len(values) == 4:
        return receive(runtime, *values)
    if rva == 0x1CFAC00 and len(values) == 4:
        return direct(runtime, *values)
    if rva == 0x1CFA8C0 and len(values) == 2:
        return correlation(runtime, *values)
    if rva == 0x1CFD300 and not values:
        return _invoke(runtime, 0x28F0, runtime.image_base + 0x677D2B4)
    if rva == 0x1D00FC0 and len(values) == 1:
        return construct(runtime, values[0])
    if rva == 0x1D026F0 and len(values) == 2:
        return set_consumer(runtime, *values)
    if rva in (0x1D040D0, 0x1D040F0) and len(values) == (2 if rva == 0x1D040D0 else 1):
        output = values[1] if rva == 0x1D040D0 else runtime._operator_new(32)
        runtime.memory.store(output, runtime.image_base + _VTABLE, 8, source='1D04102.online_consumer_vtable')
        _copy(runtime, values[0] + 8, output + 8, 16)
        return output if rva == 0x1D040F0 else None
    if rva == 0x1CFA5C0 and len(values) == 3:
        return register_scene(runtime, *values)
    if rva in (0x1CFD070, 0x1CFD310) and len(values) == 2:
        return scene_value(runtime, *values, counter=rva == 0x1CFD310)
    if rva == 0x1CFCE60 and len(values) == 2:
        return erase_scene(runtime, *values)
    raise InputError('caller online entry argument count mismatch')
