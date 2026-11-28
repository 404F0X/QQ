import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _String, _decode, _srw, feature, log
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = 'aa288adb5d8d13688c856324e00373a7c6a53ba2d981cf8c3c262ef37609ca6f'
_IMPORTS = {'SleepConditionVariableSRW': 0x4910370, 'WakeAllConditionVariable': 0x4910450,
            'GetLastError': 0x490FEA8}
_OFFSETS = (*range(0, 216, 24), 224)
_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/notification-thread-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed notification thread image identity mismatch')
    return json.loads(raw)


def install_image(memory, image_base):
    for segment in _image()['segments']:
        memory.map(image_base + segment['rva'], bytearray.fromhex(segment['hex']),
                   name='fixed notification thread source image', initialized=True)


def _api(runtime, name, arguments):
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
        raise PrimarySemanticUnavailable('notification current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing notification system observation: ' + name)
    result, effects = runtime.worker_observations.take(runtime, name, arguments)
    if not isinstance(effects, tuple):
        raise InputError('notification scheduling observation requires an ordered tuple of memory effects')
    for effect in effects:
        if (not isinstance(effect, tuple) or len(effect) != 2 or type(effect[0]) is not int or
                not 0 <= effect[0] <= _MASK64 or not isinstance(effect[1], bytes)):
            raise InputError('notification scheduling effect requires an unsigned address and raw bytes')
        runtime.memory.write(effect[0], effect[1], source=name + '.observed_memory_effect')
    return result


def _dword_api(runtime, name, arguments):
    result = _api(runtime, name, arguments)
    if type(result) is not int or result > 0xFFFFFFFF:
        raise InputError('notification system observation requires a DWORD result: ' + name)
    return result


def _divide(value, divisor):
    return value // divisor if value >= 0 else -((-value) // divisor)


def _saturate(value):
    return min((1 << 63) - 1, max(-(1 << 63), value))


def wait_absolute(runtime, condition, owner, deadline):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x40, 'D45AF0.notification_absolute_wait_frame')
    rbp = frame + 0x40
    if not memory.load(owner + 8, 1):
        raise PrimarySemanticUnavailable('75FE90 notification condition wait requires an owned mutex')
    value = min(signed(deadline, 64), 0x59682F000000E941)
    seconds = _divide(value, 1000000000)
    nanoseconds = signed(value - seconds * 1000000000, 32)
    memory.store(rbp - 0x18, seconds, 8, source='D45B3A.notification_deadline_seconds')
    memory.store(rbp - 0x10, nanoseconds, 4, source='D45B47.notification_deadline_nanoseconds')
    mutex = memory.load(owner, 8)
    clock, _ = _frame(runtime, 0x38, '787860.notification_condition_clock_frame')
    _invoke(runtime, 0x759A80, clock + 0x28)
    deadline_us = _divide(signed(seconds * 1000000000 + nanoseconds, 64), 1000)
    delta = signed(deadline_us - memory.load(clock + 0x28, 8), 64)
    timeout = 0 if delta < 1000 else (delta // 1000) & 0xFFFFFFFF
    result = _dword_api(runtime, 'SleepConditionVariableSRW', (condition, mutex, timeout, 0))
    error = 0
    if not result:
        error = _dword_api(runtime, 'GetLastError', ())
        if error == 1460:
            error = 138
    memory.unmap(clock)
    if error not in (0, 138):
        raise PrimarySemanticUnavailable('75FE90 notification condition wait requires its original exception: ' + str(error))
    memory.unmap(frame)


def wait_for(runtime, condition, owner, milliseconds):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x38, '104D10E.notification_relative_wait_frame')
    duration = memory.load(milliseconds, 8, signed=True)
    if duration <= 0:
        memory.unmap(frame)
        return 1
    _invoke(runtime, 0x759B30, frame + 0x30)
    _invoke(runtime, 0x759A80, frame + 0x28)
    system_ns = _saturate(memory.load(frame + 0x28, 8, signed=True) * 1000)
    duration_ns = _saturate(memory.load(milliseconds, 8, signed=True) * 1000000)
    memory.store(frame + 0x20, duration_ns, 8, source='104D66E.notification_duration_nanoseconds')
    remaining = signed(((1 << 63) - 1) ^ (duration_ns & _MASK64), 64)
    deadline = (1 << 63) - 1 if system_ns > remaining else signed(system_ns + duration_ns, 64)
    wait_absolute(runtime, condition, owner, deadline)
    _invoke(runtime, 0x759B30, frame + 0x20)
    elapsed = signed(memory.load(frame + 0x20, 8) - memory.load(frame + 0x30, 8), 64)
    required = signed(memory.load(milliseconds, 8) * 1000000, 64)
    result = int(elapsed >= required)
    memory.unmap(frame)
    return result


def copy_context(runtime, output, context):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x70, '1BEE6A0.notification_context_copy_frame')
    for offset in _OFFSETS:
        if offset == 224:
            memory.copy_disjoint(output + 216, context + 216, 8,
                                 label='1BEE6A0.notification_context_scalar')
        _String.read(runtime, context + offset).clone().write_to(output + offset)
    runtime.events.append(('notification.context_copy', output, context))
    memory.unmap(frame)
    return output


def destroy_context(runtime, context):
    for offset in reversed(_OFFSETS):
        _String.read(runtime, context + offset).destroy()


def advance(runtime, manager):
    from .primary_feature_notifications import _logger
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x48, '1C2D200.notification_iteration_frame')
    previous = memory.load(manager, 4)
    current = (previous + 1) & 0xFFFFFFFF
    memory.store(manager, current, 4, source='1C2D221.notification_iteration_counter')
    if (not previous or current == 2) and feature(runtime, _logger(runtime), 4) == 1:
        raise PrimarySemanticUnavailable('1C2D200 enabled notification service monitor requires its source producer and handlers')
    memory.unmap(frame)


def task(runtime, manager):
    from .primary_feature_notifications import _logger
    from .primary_sdk_collection import _copy, _destroy, _virtual
    from .primary_sdk_records import destroy_map
    from .primary_worker_loop import _initialize
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x3E8, '1C2A9E0.notification_periodic_task_frame')
    image = _image()
    source, tag = _decode(image['literals']['file']), bytes.fromhex(image['tag_hex'])
    log(runtime, source, 121, _decode(image['literals']['task']), tag, 1)
    memory.write(rbp + 0x108, b'\x02' + b'0\0', source='1C2B0BD.notification_initial_value')
    log(runtime, source, 123, _decode(image['literals']['number']), tag, 1, 123)
    _initialize(runtime, 1)
    copy_context(runtime, rbp + 0x1C0, base + 0x67516D8)
    if feature(runtime, _logger(runtime), 38) == 1:
        _invoke(runtime, 0x1BF7670, rbp + 0x208, rbp + 0x1F0)
    collection = memory.load(base + 0x6751D80, 8)
    if not collection:
        collection = runtime._operator_new(80)
        memory.store(collection + 72, 0, 8, source='1C2B935.notification_collection_owner')
        memory.store(collection + 32, 0, 8, source='1C2B93D.notification_collection_callback')
        memory.store(base + 0x6751D80, collection, 8, source='1C2B945.notification_collection_publish')
    active = memory.load(collection + 72, 8)
    if active:
        _copy(runtime, active, collection + 48, rbp + 0x188)
        copied = memory.load(rbp + 0x1A0, 8)
        if copied:
            _virtual(runtime, copied, 40, rbp + 0x140)
            _destroy(runtime, rbp + 0x188)
        else:
            memory.write(rbp + 0x140, bytes(32), source='1C2B94F.notification_empty_collection')
            memory.store(rbp + 0x160, 0x3F800000, 4, source='1C2B95D.notification_collection_max_load')
    else:
        memory.write(rbp + 0x140, bytes(32), source='1C2B94F.notification_empty_collection')
        memory.store(rbp + 0x160, 0x3F800000, 4, source='1C2B95D.notification_collection_max_load')
    destroy_context(runtime, rbp + 0x1C0)
    log(runtime, source, 125, _decode(image['literals']['number']), tag, 1, 125)
    node = memory.load(rbp + 0x150, 8)
    for _ in range(_LIMIT):
        if not node:
            break
        if memory.load(node + 16, 8) != 1:
            from .primary_sdk_events import emit

            emit(runtime, rbp, node)
        node = memory.load(node, 8)
    else:
        raise PrimaryProgramLimit('SDK notification record traversal exceeds the bounded execution domain')
    advance(runtime, manager)
    destroy_map(runtime, rbp + 0x140)
    _String.read(runtime, rbp + 0x108).destroy()
    memory.unmap(frame)


def _callback(runtime, manager, offset):
    active = runtime.memory.load(manager + 56, 8)
    if active:
        target = runtime.memory.load(runtime.memory.load(active, 8) + offset, 8) - runtime.image_base
        raise PrimarySemanticUnavailable('notification lifecycle current callback is not implemented: ' + hex(target))


def run(runtime, argument):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x48, '1C2A860.notification_thread_loop_frame')
    rbp = frame + 0x40
    manager = memory.load(argument, 8)
    memory.store(rbp - 8, manager + 48, 8, source='1C2A880.notification_callback_mutex')
    _srw(runtime, manager + 48, True)
    _callback(runtime, manager, 0)
    _srw(runtime, memory.load(rbp - 8, 8), False)
    task(runtime, manager)
    iterations = 0
    while memory.load(manager + 4, 1):
        if iterations >= _LIMIT:
            raise PrimaryProgramLimit('notification thread loop exceeds its bounded execution domain')
        iterations += 1
        memory.store(rbp - 0x18, manager + 40, 8, source='1C2A8C6.notification_wait_mutex')
        memory.store(rbp - 0x10, 1, 1, source='1C2A8CA.notification_wait_owned')
        _srw(runtime, manager + 40, True)
        memory.store(rbp - 0x20, (memory.load(manager + 16, 4) * 1000) & 0xFFFFFFFF, 8,
                     source='1C2A8DD.notification_wait_milliseconds')
        wait_for(runtime, manager + 32, rbp - 0x18, rbp - 0x20)
        if memory.load(manager + 4, 1):
            task(runtime, manager)
        if memory.load(rbp - 0x10, 1):
            _srw(runtime, memory.load(rbp - 0x18, 8), False)
    _srw(runtime, memory.load(rbp - 8, 8), True)
    _callback(runtime, manager, 8)
    _srw(runtime, memory.load(rbp - 8, 8), False)
    memory.unmap(frame)


def complete(runtime, state):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x40, 'D46840.notification_completion_frame')
    _srw(runtime, state + 32, True)
    if memory.load(state + 48, 1) & 1 or memory.load(state + 16, 8):
        raise PrimarySemanticUnavailable('D46900 notification shared state is already satisfied or has an exception')
    memory.write(frame + 0x20, bytes(16), source='759D10.notification_empty_exception')
    memory.store(state + 48, memory.load(state + 48, 1) | 5, 1, source='D46894.notification_completed')
    result = _api(runtime, 'WakeAllConditionVariable', (state + 40,))
    if result is not None:
        raise InputError('WakeAllConditionVariable has a void result')
    _srw(runtime, state + 32, False)
    memory.unmap(frame)


def entry(runtime, state):
    frame, _ = _frame(runtime, 0x48, '1C2A7E0.notification_thread_entry_frame')
    runtime.memory.store(frame + 0x38, state, 8, source='1C2A7F3.notification_thread_state_owner')
    run(runtime, state + 56)
    complete(runtime, runtime.memory.load(frame + 0x38, 8))
    runtime.memory.unmap(frame)


def wait_ready(runtime, state):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x30, 'D46AA0.notification_destruction_wait_frame')
    memory.store(frame + 0x20, state + 32, 8, source='D46AAE.notification_completion_mutex')
    memory.store(frame + 0x28, 1, 1, source='D46AB3.notification_completion_mutex_owned')
    _srw(runtime, state + 32, True)
    flags = memory.load(state + 48, 4)
    if not flags & 4 and flags & 8:
        memory.store(state + 48, flags & ~8, 4, source='D46B0E.notification_deferred_claim')
        _srw(runtime, state + 32, False)
        target = memory.load(memory.load(state, 8) + 16, 8) - runtime.image_base
        memory.unmap(frame)
        if target == 0x1BF50C0:
            from .primary_pending_thread import entry as pending_entry

            return pending_entry(runtime, state)
        if target != 0x1C2A7E0:
            raise PrimarySemanticUnavailable('notification current deferred body is not implemented: ' + hex(target))
        return entry(runtime, state)
    iterations = 0
    while not memory.load(state + 48, 1) & 4:
        if iterations >= _LIMIT:
            raise PrimaryProgramLimit('notification shared-state wait exceeds its bounded execution domain')
        iterations += 1
        if not memory.load(frame + 0x28, 1):
            raise PrimarySemanticUnavailable('75FE90 notification completion wait requires an owned mutex')
        _dword_api(runtime, 'SleepConditionVariableSRW',
                   (state + 40, memory.load(frame + 0x20, 8), 0xFFFFFFFF, 0))
    if memory.load(frame + 0x28, 1):
        _srw(runtime, memory.load(frame + 0x20, 8), False)
    memory.unmap(frame)


def destroy_state(runtime, state):
    memory = runtime.memory
    wait_ready(runtime, state)
    target = memory.load(memory.load(state, 8), 8) - runtime.image_base
    if target == 0x1BF4FE0:
        from .primary_pending_thread import delete

        return delete(runtime, state, 1)
    if target != 0xD46CC0:
        raise PrimarySemanticUnavailable('notification current deleting destructor is not implemented: ' + hex(target))
    memory.store(state, runtime.image_base + 0x3FF03A8, 8, source='D46CD2.notification_base_vtable')
    if memory.load(state + 24, 8):
        raise PrimarySemanticUnavailable('3E69794 notification exception control destruction requires its current virtual lifecycle')
    runtime._free_allocation(state)


def invoke(runtime, rva, values):
    runtime.events.append(('notification.thread_entry', rva, values))
    if rva == 0x1C2A9E0 and len(values) == 1:
        return task(runtime, *values)
    if rva == 0x1C2D200 and len(values) == 1:
        return advance(runtime, *values)
    if rva == 0x1BEE6A0 and len(values) == 2:
        return copy_context(runtime, *values)
    if rva == 0xBA1A90 and len(values) == 1:
        return destroy_context(runtime, *values)
    if rva == 0x1C2A860 and len(values) == 1:
        return run(runtime, *values)
    if rva == 0x1C2A7E0 and len(values) == 1:
        return entry(runtime, *values)
    if rva == 0xD46840 and len(values) == 1:
        return complete(runtime, *values)
    if rva == 0x104D10E and len(values) == 3:
        return wait_for(runtime, *values)
    if rva == 0xD45AF0 and len(values) == 3:
        return wait_absolute(runtime, *values)
    if rva == 0x1BF5070 and len(values) == 1:
        return destroy_state(runtime, *values)
    if rva == 0xD46AA0 and len(values) == 1:
        return wait_ready(runtime, *values)
    raise InputError('unsupported notification thread entry or argument count')
