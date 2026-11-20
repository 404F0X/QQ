from .errors import InputError
from .primary_logger import _String, log
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed


_MASK64 = (1 << 64) - 1
_STRINGS = (*range(8, 0xC8, 24), *range(0xE0, 0x170, 24))


def copy_base_record(runtime, destination, source):
    memory, base = runtime.memory, runtime.image_base
    memory.store(destination, base + 0x3FD6C78, 8, source='BD3F17.telemetry_base_vtable')
    for offset in range(8, 0xC8, 24):
        _String.read(runtime, source + offset).clone().write_to(destination + offset)
    memory.write(destination + 0xC8, bytes(24), source='BD3FD6.empty_telemetry_vector')
    first, last = memory.load(source + 0xC8, 8), memory.load(source + 0xD0, 8)
    width = (last - first) & _MASK64
    if width % 24 or width > 24 * 100000:
        raise PrimaryProgramLimit('BD3EF0 telemetry vector exceeds the bounded source layout')
    if width:
        pointer = runtime._operator_new(width)
        for offset, value in ((0xC8, pointer), (0xD0, pointer), (0xD8, pointer + width)):
            memory.store(destination + offset, value, 8, source='BD4030.telemetry_vector_allocation')
        for offset in range(0, width, 24):
            _String.read(runtime, first + offset).clone().write_to(pointer + offset)
        memory.store(destination + 0xD0, pointer + width, 8, source='BD4081.telemetry_vector_end')
    return destination


def copy_record(runtime, destination, source):
    copy_base_record(runtime, destination, source)
    runtime.memory.store(destination, runtime.image_base + 0x3FD6EB8, 8,
                         source='BD38B6.telemetry_derived_vtable')
    for offset in range(0xE0, 0x170, 24):
        _String.read(runtime, source + offset).clone().write_to(destination + offset)
    runtime.events.append(('BD3890.source_telemetry_record_copy', destination, source))
    return destination


def copy_functor(runtime, source, destination=None):
    allocated = destination is None
    if allocated:
        destination = runtime._operator_new(0x180)
    runtime.memory.store(destination, runtime.image_base + 0x3FD6F48, 8,
                         source='BD4367.telemetry_functor_vtable')
    result = copy_record(runtime, destination + 8, source + 8)
    runtime.events.append(('BD4340.source_telemetry_functor_copy' if allocated else
                           'BD4320.source_telemetry_functor_copy', destination, source))
    return destination if allocated else result


def destroy_functor(runtime, pointer, release):
    from .primary_task_exit import destroy_record

    runtime.memory.store(pointer, runtime.image_base + 0x3FD6F48, 8,
                         source='BD42F2.telemetry_functor_vtable')
    destroy_record(runtime, pointer + 8)
    if release:
        runtime._free_allocation(pointer)
    return pointer


def forced_value(runtime, owner, output):
    from .primary_device_native import refresh
    from .primary_device_records import _image

    refresh(runtime, owner)
    value = _String.read(runtime, owner)
    item = _image()['cached_getter_log']
    log(runtime, bytes.fromhex(item['source_file_hex']), 0x26, b'gx: %s',
        bytes.fromhex(item['tag_hex']), 1, value.value())
    _String.read(runtime, owner).clone().write_to(output)
    return output


def device_value(runtime, receiver, output):
    from .primary_device_records import _locked_singleton

    owner = _locked_singleton(runtime, 0x6751838, 0x67516A0, 32, 0x1BE5CD0)
    return forced_value(runtime, owner, output)


def _device(runtime, owner):
    from .primary_sdk import _add_owner

    device, control = runtime.memory.load(owner, 8), runtime.memory.load(owner + 8, 8)
    if control:
        _add_owner(runtime, control)
    runtime.events.append(('source_postfetch.device', device, control))
    return device, control


def _target(runtime, device, offset, expected):
    if not device:
        raise PrimarySemanticUnavailable('BD0A00 current device is null before virtual dereference')
    target = runtime.memory.load(runtime.memory.load(device, 8) + offset, 8)
    if target != runtime.image_base + expected:
        raise PrimarySemanticUnavailable('BD0A00 current device virtual target is not bound: ' + hex(offset))
    return expected


def _state(runtime, owner, field, value):
    if owner == runtime.image_base + 0x6751840 and runtime.provider_material is not None:
        setattr(runtime.provider_material, field, value)


def _move_record(runtime, destination, source):
    memory = runtime.memory
    for offset in _STRINGS:
        _String.read(runtime, source + offset).write_to(destination + offset)
        memory.write(source + offset, bytes(24), source='BD247B.moved_telemetry_string')
    memory.copy_disjoint(destination + 0xC8, source + 0xC8, 24,
                         label='BD2587.moved_telemetry_vector')
    memory.write(source + 0xC8, bytes(24), source='BD25A3.moved_telemetry_vector_empty')
    memory.store(destination, runtime.image_base + 0x3FD6EB8, 8,
                 source='BD25B5.telemetry_derived_vtable')


def _enqueue_record(runtime, record, temporary):
    from .primary_task_exit import destroy_record
    from .primary_worker_tasks import _Function, _enqueue, provider_task

    task = provider_task(runtime)
    copy_record(runtime, temporary, record)
    pointer = runtime._operator_new(0x180)
    runtime.memory.store(pointer, runtime.image_base + 0x3FD6F48, 8,
                         source='BD2468.telemetry_functor_vtable')
    _move_record(runtime, pointer + 8, temporary)
    destroy_record(runtime, temporary)
    _enqueue(runtime, task, _Function(pointer + 8, pointer, 0x3FD6F48))
    destroy_record(runtime, record)


def _report(runtime, owner, record, temporary, success):
    from .primary_material import _move_provider_string
    from .primary_sdk import _release_owner
    from .primary_worker_tasks import _invoke

    memory, base = runtime.memory, runtime.image_base
    _String.construct(runtime, b'xwid').write_to(record + 8)
    for offset in range(32, 0xC8, 24):
        _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(record + offset)
    memory.write(record + 0xC8, bytes(24), source='BD21E2.telemetry_record_empty_vector')
    memory.store(record, base + 0x3FD6EB8, 8, source='BD21FB.telemetry_record_vtable')
    memory.write(record + 0xE0, bytes(144), source='BD2202.telemetry_record_empty_columns')
    device, control = _device(runtime, owner)
    result = _invoke(runtime, _target(runtime, device, 0x18, 0x63EC0), device)
    if type(result) is not int:
        raise PrimarySemanticUnavailable('BD0A00 device slot18 requires its observed QWORD result')
    _String.construct(runtime, str(signed(result, 64)).encode('ascii')).write_to(record + 0xE0)
    _release_owner(runtime, control)
    _String.construct(runtime, str(memory.load(owner + 0x108, 8, signed=True)).encode('ascii')).write_to(record + 0xF8)
    _String.construct(runtime, b'1' if memory.load(owner + 0x14A, 1) else b'0').write_to(record + 0x110)
    _String.construct(runtime, str(memory.load(owner + 0x110, 8, signed=True)).encode('ascii')).write_to(record + 0x128)
    _String.construct(runtime, b'1' if success else b'0').write_to(record + 0x140)
    device, control = _device(runtime, owner)
    _invoke(runtime, _target(runtime, device, 0x28, 0xBEE240), device, temporary)
    _move_provider_string(runtime, record + 0x158, temporary)
    _release_owner(runtime, control)
    _enqueue_record(runtime, record, temporary)


def refresh(runtime, capture):
    from .primary_material import _caller_message
    from .primary_sdk import _release_owner
    from .primary_tokens import provider_token
    from .primary_worker_response import _assign, _frame
    from .primary_worker_tasks import _invoke

    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x3E8, 'BD0A00.provider_postfetch_frame')
    owner = memory.load(capture, 8)
    now = _invoke(runtime, 0x3E8ED3C, 0)
    _invoke(runtime, 0x759B30, rbp - 0x48)
    device, control = _device(runtime, owner)
    output = rbp - 0x20
    _invoke(runtime, _target(runtime, device, 0, 0xBEDB20), device, output)
    _release_owner(runtime, control)
    value = _String.read(runtime, output)
    raw = value.value()
    _caller_message(runtime, 0x288, b'xw L2ID real length:%d', 1, len(raw))
    _invoke(runtime, 0x759B30, rbp + 0x1B0)
    elapsed = signed((memory.load(rbp + 0x1B0, 8) - memory.load(rbp - 0x48, 8)) & _MASK64, 64)
    duration = (abs(elapsed) // 1000000) * (-1 if elapsed < 0 else 1)
    memory.store(owner + 0x108, duration & _MASK64, 8, source='BD0FA9.provider_refresh_duration')
    _state(runtime, owner, 'refresh_duration_ms', duration)
    token_value = None
    if raw:
        token = provider_token(runtime, raw)
        token_value = _String.construct(runtime, token)
        token_value.write_to(rbp + 0x180)
        runtime.publish_provider_token(token, caller='postfetch')
        _assign(runtime, owner + 0x70, value)
        _state(runtime, owner, 'value', _String.read(runtime, owner + 0x70).value())
        runtime.events.append(('BD1B0A.source_provider_raw_commit',))
        _assign(runtime, owner + 0x88, token_value)
        _state(runtime, owner, 'token', _String.read(runtime, owner + 0x88).value())
        runtime.events.append(('BD1B1D.source_provider_token_commit',))
        memory.store(owner + 0xA8, now, 8, source='BD1B22.provider_refresh_timestamp')
        _state(runtime, owner, 'timestamp', signed(now, 64))
        runtime.events.append(('BD1B22.source_provider_time_commit', now))
    else:
        _caller_message(runtime, 0x293, b'createXwId error', 1)
    device, control = _device(runtime, owner)
    _release_owner(runtime, control)
    if not device:
        _caller_message(runtime, 0x2C3, b'getDevice error!', 2)
    elif memory.load(owner + 0x148, 1):
        memory.store(owner + 0x148, 0, 1, source='BD1B63.provider_report_once_clear')
        _state(runtime, owner, 'postfetch_report_once', False)
        _report(runtime, owner, rbp + 0x1B0, rbp, bool(raw))
    if token_value is not None:
        token_value.destroy()
    memory.store(owner + 0xA0, 0, 1, source='BD31BA.provider_refresh_attempt_exchange')
    _state(runtime, owner, 'attempted', False)
    runtime.events.append(('BD31BA.source_provider_refresh_release',))
    value.destroy()
    memory.unmap(frame)
    return None


def consume_record(runtime, record):
    from .primary_worker_response import _assign, _frame, _image, _owner
    from .primary_worker_tasks import _invoke

    _owner(runtime, _image())
    frame, rbp = _frame(runtime, 0x98, 'BD4460.provider_telemetry_frame')
    for offset in (-0x50, -0x38):
        _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(rbp + offset)
    runtime.memory.write(rbp - 0x20, bytes(48), source='BD4499.telemetry_empty_columns')
    _assign(runtime, rbp - 0x20, _String.read(runtime, rbp - 0x38))
    _assign(runtime, rbp - 8, _String.read(runtime, rbp - 0x50))
    result = _invoke(runtime, 0x1BEFC10, runtime.image_base + 0x67519B8, record, rbp - 0x20, 0, 10000, 0)
    for offset in (-8, -0x20, -0x38, -0x50):
        _String.read(runtime, rbp + offset).destroy()
    runtime.memory.unmap(frame)
    return result


def invoke(runtime, rva, values):
    if rva == 0xBD0A00 and len(values) == 1:
        return refresh(runtime, values[0])
    if rva == 0xBEDB20 and len(values) == 2:
        return device_value(runtime, *values)
    if rva == 0x1BE5CE0 and len(values) == 2:
        return forced_value(runtime, *values)
    if rva == 0xBD3EF0 and len(values) == 2:
        return copy_base_record(runtime, *values)
    if rva == 0xBD3890 and len(values) == 2:
        return copy_record(runtime, *values)
    if rva == 0xBD4460 and len(values) == 1:
        return consume_record(runtime, values[0])
    if rva == 0xBEE240 and len(values) == 2:
        runtime.memory.store(values[1], 4, 1, source='BEE243.device_secondary_string_length')
        runtime.memory.write(values[1] + 1, b'-1\0', source='BEE246.device_secondary_string')
        return values[1]
    raise InputError('source provider postfetch interface argument count mismatch')
