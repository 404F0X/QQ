import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _srw, construct, feature
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _frame
from .primary_worker_tasks import _observe


_IMAGE_SHA256 = '716311b804e2ced94de34a9ce5018e4c4e6290d2d6d5813ec10a0dbf05b433ec'
_VTABLE = 0x41494A8
_MAXIMUM = 0x555555555555555
_LIMIT = 1 << 20


def install_image(memory, image_base):
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/feature-notification-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed feature notification image identity mismatch')
    image = json.loads(raw)
    for segment in image['segments']:
        data = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            value = int.from_bytes(data[offset:offset + 8], 'little') - image['image_base'] + image_base
            data[offset:offset + 8] = value.to_bytes(8, 'little')
        memory.map(image_base + segment['rva'], data, name='fixed feature notification source image', initialized=True)


def _virtual(runtime, active, offset, *arguments):
    target = runtime.memory.load(runtime.memory.load(active, 8) + offset, 8) - runtime.image_base
    if target in (0x1C41AE0, 0x1C41AF0, 0x1C41B10):
        from .primary_client_configuration import invoke as invoke_configuration
        return invoke_configuration(runtime, target, (active, *arguments))
    if target not in (0x1C2A440, 0x1C2A450, 0x1C2A470, 0x28F0, 0x1FE0):
        raise PrimarySemanticUnavailable('feature notification current virtual function is not implemented')
    return invoke(runtime, target, (active, *arguments))


def _copy(runtime, source, source_inline, destination, slot):
    if not source:
        runtime.memory.store(slot, 0, 8, source='feature.notification_empty_copy')
    elif source == source_inline:
        runtime.memory.store(slot, destination, 8, source='feature.notification_inline_owner')
        _virtual(runtime, source, 8, destination)
    else:
        copied = _virtual(runtime, source, 16)
        runtime.memory.store(slot, copied, 8, source='feature.notification_heap_owner')
    return runtime.memory.load(slot, 8)


def _destroy(runtime, active, inline):
    if active:
        _virtual(runtime, active, 24 if active == inline else 32)


def _record(runtime, source, destination):
    runtime.memory.store(destination, runtime.memory.load(source, 4), 4, source='feature.notification_record_id')
    _copy(runtime, runtime.memory.load(source + 40, 8), source + 16, destination + 16, destination + 40)


def _bounds(runtime, vector):
    begin, end, capacity = (runtime.memory.load(vector + offset, 8) for offset in (0, 8, 16))
    if not begin <= end <= capacity or (end - begin) % 48 or (capacity - begin) % 48:
        raise PrimaryProgramLimit('feature notification vector is outside its ordered source layout')
    count, available = (end - begin) // 48, (capacity - begin) // 48
    if count > _LIMIT or available > _LIMIT:
        raise PrimaryProgramLimit('feature notification vector exceeds the bounded execution domain')
    return begin, end, capacity, count, available


def grow(runtime, vector, record):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x38, '1BE5250.notification_growth_frame')
    begin, end, _, count, capacity = _bounds(runtime, vector)
    if count + 1 > _MAXIMUM:
        raise PrimarySemanticUnavailable('notification vector length failure requires its original exception path')
    enlarged = min(_MAXIMUM, max(count + 1, capacity * 2))
    if enlarged > _LIMIT:
        raise PrimaryProgramLimit('notification vector growth exceeds the bounded execution domain')
    destination = runtime._operator_new(enlarged * 48)
    _record(runtime, record, destination + count * 48)
    for index in range(count - 1, -1, -1):
        source, target = begin + index * 48, destination + index * 48
        memory.store(target, memory.load(source, 4), 4, source='1BE53A9.notification_move_id')
        active = memory.load(source + 40, 8)
        if active and active != source + 16:
            memory.store(target + 40, active, 8, source='1BE53C8.notification_move_heap')
            memory.store(source + 40, 0, 8, source='1BE53CD.notification_moved_owner')
        else:
            _copy(runtime, active, source + 16, target + 16, target + 40)
    for offset, value in ((0, destination), (8, destination + (count + 1) * 48), (16, destination + enlarged * 48)):
        memory.store(vector + offset, value, 8, source='1BE5404.notification_vector_publish')
    for index in range(count - 1, -1, -1):
        source = begin + index * 48
        _destroy(runtime, memory.load(source + 40, 8), source + 16)
    if begin:
        runtime._free_allocation(begin)
    memory.unmap(frame)


def register(runtime, logger, function):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x78, '1BE3FF0.notification_registration_frame')
    rbp = frame + 0x70
    _srw(runtime, logger + 112, True)
    identifier = memory.load(logger + 56, 4)
    memory.store(rbp - 0x50, identifier, 4, source='1BE401B.notification_identifier')
    _copy(runtime, memory.load(function + 32, 8), function + 8, rbp - 0x40, rbp - 0x28)
    _, end, capacity, _, _ = _bounds(runtime, logger + 88)
    if end == capacity:
        invoke(runtime, 0x1BE5250, (logger + 88, rbp - 0x50))
    else:
        _record(runtime, rbp - 0x50, end)
        memory.store(logger + 96, end + 48, 8, source='1BE40BF.notification_append')
    memory.store(logger + 56, (identifier + 1) & 0xFFFFFFFF, 4, source='1BE40C3.notification_counter')
    _destroy(runtime, memory.load(rbp - 0x28, 8), rbp - 0x40)
    _srw(runtime, logger + 112, False)
    _destroy(runtime, memory.load(function + 32, 8), function + 8)
    memory.unmap(frame)
    return identifier


def _logger(runtime):
    memory, base = runtime.memory, runtime.image_base
    pointer = memory.load(base + 0x67516A8, 8)
    if not pointer:
        pointer = runtime._operator_new(120)
        construct(runtime, pointer)
        memory.store(base + 0x67516A8, pointer, 8, source='feature.notification_logger_publish')
    return pointer


def register_worker(runtime):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x60, '1C2A3B0.notification_wrapper_frame')
    logger = _logger(runtime)
    memory.store(frame + 0x30, runtime.image_base + _VTABLE, 8, source='1C2A3FA.notification_source_vtable')
    memory.store(frame + 0x48, frame + 0x30, 8, source='1C2A3FE.notification_source_owner')
    result = register(runtime, logger, frame + 0x28)
    memory.unmap(frame)
    return result


def start_manager(runtime, manager):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x40, '1C2A5C0.notification_manager_start_frame')
    _srw(runtime, manager + 8, True)
    if not memory.load(manager + 4, 1):
        memory.store(manager + 4, 1, 1, source='1C2A5ED.notification_manager_claim')
        memory.store(frame + 0x20, manager + 8, 8, source='1C2A5E9.notification_manager_lock_owner')
        memory.store(frame + 0x28, manager, 8, source='1C2A5F1.notification_manager_argument')
        invoke(runtime, 0x1C2A6A0, (frame + 0x30, frame + 0x28))
        state = memory.load(frame + 0x30, 8)
        memory.store(frame + 0x30, 0, 8, source='1C2A606.notification_local_owner_transfer')
        memory.store(frame + 0x28, memory.load(manager + 24, 8), 8, source='1C2A616.notification_previous_owner')
        memory.store(manager + 24, state, 8, source='1C2A61A.notification_shared_state_publish')
        release_owner(runtime, frame + 0x28)
        release_owner(runtime, frame + 0x30)
    _srw(runtime, manager + 8, False)
    memory.unmap(frame)


def release_owner(runtime, owner):
    memory = runtime.memory
    state = memory.load(owner, 8)
    if state:
        count = memory.load(state + 8, 4)
        memory.store(state + 8, (count - 1) & 0xFFFFFFFF, 4, source='D46BD0.notification_reference_release')
        if not count:
            target = memory.load(memory.load(state, 8) + 8, 8) - runtime.image_base
            if target != 0x1BF5070:
                raise PrimarySemanticUnavailable('notification current shared-state destructor is not implemented: ' + hex(target))
            from .primary_notification_thread import destroy_state
            destroy_state(runtime, state)


def acquire_owner(runtime, output, state):
    memory = runtime.memory
    memory.store(output, state, 8, source='D46B5B.notification_future_owner')
    _srw(runtime, state + 32, True)
    flags = memory.load(state + 48, 4)
    if flags & 2:
        raise PrimarySemanticUnavailable('D46B98 notification future already retrieved requires its original exception')
    memory.store(state + 8, (memory.load(state + 8, 4) + 1) & 0xFFFFFFFF, 4, source='D46B71.notification_reference_acquire')
    memory.store(state + 48, flags | 2, 4, source='D46B78.notification_future_retrieved')
    _srw(runtime, state + 32, False)
    return output


def _handle_result(runtime, name, slot, arguments):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + slot, 8) != expected:
        raise PrimarySemanticUnavailable('notification current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing notification system observation: ' + name)
    result, effects = runtime.worker_observations.take(runtime, name, arguments)
    if result > 0xFFFFFFFF or effects != b'':
        raise InputError('notification system observation requires a DWORD result and no memory outputs: ' + name)
    return result


def _detach(runtime, thread):
    memory = runtime.memory
    handle = memory.load(thread, 8)
    if not handle:
        raise PrimarySemanticUnavailable('75FFFA empty notification thread requires its original invalid-argument exception')
    result = _handle_result(runtime, 'CloseHandle', 0x490FBD8, (handle,))
    if not result:
        error = _handle_result(runtime, 'GetLastError', 0x490FEA8, ())
        if error:
            raise PrimarySemanticUnavailable('75FE90 failed notification thread detach requires its original exception: ' + str(error))
    memory.store(thread, 0, 8, source='75FFED.notification_detached_thread')


def construct_thread(runtime, output, function, argument):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x40, 'BD4FA0.notification_thread_tuple_frame')
    holder = runtime._operator_new(8)
    memory.store(frame + 0x30, holder, 8, source='BD4FCA.notification_thread_holder_temporary')
    state = runtime._operator_new(48)
    memory.write(state, bytes(48), source='760232.notification_thread_state_zero')
    memory.store(holder, state, 8, source='760240.notification_thread_state_owner')
    memory.store(frame + 0x28, holder, 8, source='BD4FDA.notification_thread_holder_owner')
    control = runtime._operator_new(24)
    for offset, value in ((0, holder), (8, memory.load(function, 8)), (16, memory.load(argument, 8))):
        memory.store(control + offset, value, 8, source='BD4FA0.notification_thread_tuple')
    memory.store(frame + 0x30, control, 8, source='BD5003.notification_thread_tuple_owner')
    start = runtime._operator_new(16)
    memory.store(start, base + 0xBD55C0, 8, source='78794A.notification_thread_callback')
    memory.store(start + 8, control, 8, source='78794D.notification_thread_argument')
    context = runtime._allocate(40, True)
    memory.store(context, base + 0x7879A0, 8, source='3E817D5.notification_CRT_callback')
    memory.store(context + 8, start, 8, source='3E817DB.notification_CRT_argument')
    result, module = _observe(runtime, 'GetModuleHandleExW', 4, base + 0x7879A0)
    if (result > 0xFFFFFFFF or result and module is None or
            module is not None and (type(module) is not int or not 0 <= module < 1 << 64)):
        raise InputError('notification module observation requires a DWORD result and optional module handle')
    if module is not None:
        memory.store(context + 24, module, 8, source='GetModuleHandleExW.notification_module')
    handle, identifier = _observe(runtime, 'CreateThread', 0, 0, base + 0x3E81800, context, 0)
    if not handle:
        raise PrimarySemanticUnavailable('3E8172E failed notification thread creation requires its original CRT cleanup and error path')
    if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
        raise InputError('notification thread creation requires an observed DWORD thread id')
    memory.store(output, handle, 8, source='787975.notification_thread_handle')
    runtime.events.append(('feature.notification_thread_created', output, handle, context))
    memory.unmap(frame)
    return output


def construct_shared_state(runtime, output, argument):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x48, '1C2A6A0.notification_shared_constructor_frame')
    state = runtime._operator_new(64)
    memory.store(state + 8, 0, 4, source='1C2A6C8.notification_initial_reference')
    memory.store(state, base + 0x3FF03A8, 8, source='1C2A6D6.notification_initial_shared_vtable')
    memory.write(state + 16, bytes(16), source='3E6924C.notification_exception_owner_zero')
    memory.write(state + 32, bytes(16), source='1C2A6E6.notification_shared_synchronization_zero')
    memory.store(state + 48, 0, 4, source='1C2A6EA.notification_shared_flags')
    memory.store(state, base + 0x4149558, 8, source='1C2A6F9.notification_worker_shared_vtable')
    memory.store(state + 56, memory.load(argument, 8), 8, source='1C2A703.notification_manager_capture')
    memory.store(frame + 0x38, state, 8, source='1C2A707.notification_shared_temporary')
    memory.store(frame + 0x20, state, 8, source='1C2A70B.notification_shared_thread_argument')
    memory.store(frame + 0x28, base + 0x36E0, 8, source='1C2A712.notification_virtual_thread_entry')
    construct_thread(runtime, frame + 0x30, frame + 0x28, frame + 0x20)
    _detach(runtime, frame + 0x30)
    if memory.load(frame + 0x30, 8):
        raise PrimarySemanticUnavailable('75FF61 notification joinable-thread destruction requires termination')
    acquire_owner(runtime, output, state)
    release_owner(runtime, frame + 0x38)
    memory.unmap(frame)
    return output


def worker_changed(runtime):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x30, '1C2A4F0.notification_worker_change_frame')
    if feature(runtime, _logger(runtime), 8) != 1:
        memory.unmap(frame)
        return
    manager = memory.load(base + 0x677CEC8, 8)
    if not manager:
        manager = runtime._operator_new(64)
        for offset, value, size in ((0, 0, 4), (8, 0, 8), (20, 0, 1), (4, 0, 1),
                                    (24, 0, 8), (32, 0, 8), (40, 0, 8), (48, 0, 8),
                                    (56, 0, 8), (16, 7200, 4)):
            memory.store(manager + offset, value, size, source='1C2A4F0.notification_manager_construct')
        memory.store(base + 0x677CEC8, manager, 8, source='1C2A587.notification_manager_publish')
    memory.unmap(frame)
    invoke(runtime, 0x1C2A5C0, (manager,))


def notify(runtime, logger, rbp):
    memory = runtime.memory
    memory.store(rbp + 0xF8, logger + 112, 8, source='1CDBF80.notification_lock_owner')
    _srw(runtime, logger + 112, True)
    begin, end = memory.load(logger + 88, 8), memory.load(logger + 96, 8)
    for _ in range(_LIMIT):
        if begin == end:
            _srw(runtime, logger + 112, False)
            return
        memory.store(rbp + 0x148, memory.load(begin, 4), 4, source='1CDBFB0.notification_current_id')
        active = memory.load(begin + 40, 8)
        if not active:
            raise PrimarySemanticUnavailable('1CDCD48 empty notification requires the original bad-function-call exception')
        copied = _copy(runtime, active, begin + 16, rbp + 0x158, rbp + 0x170)
        if not copied:
            raise PrimarySemanticUnavailable('1CDCD53 empty notification clone requires its original exception')
        _virtual(runtime, copied, 40)
        _destroy(runtime, memory.load(rbp + 0x170, 8), rbp + 0x158)
        begin = (begin + 48) & ((1 << 64) - 1)
    raise PrimaryProgramLimit('response feature notification traversal exceeds the bounded execution domain')


def invoke(runtime, rva, values):
    runtime.events.append(('feature.notification_entry', rva, values))
    if rva == 0x1C2A3B0 and not values:
        return register_worker(runtime)
    if rva == 0x1BE3FF0 and len(values) == 2:
        return register(runtime, *values)
    if rva == 0x1BE5250 and len(values) == 2:
        return grow(runtime, *values)
    if rva == 0x1C2A440 and len(values) == 2:
        runtime.memory.store(values[1], runtime.image_base + _VTABLE, 8, source='1C2A447.notification_inline_clone')
        return runtime.image_base + _VTABLE
    if rva == 0x1C2A450 and len(values) == 1:
        result = runtime._operator_new(16)
        runtime.memory.store(result, runtime.image_base + _VTABLE, 8, source='1C2A465.notification_heap_clone')
        return result
    if rva == 0x1C2A470 and len(values) == 1:
        return invoke(runtime, 0x1C2A4F0, (values[0] + 8,))
    if rva == 0x1C2A4F0 and len(values) <= 1:
        return worker_changed(runtime)
    if rva == 0x1C2A5C0 and len(values) == 1:
        return start_manager(runtime, *values)
    if rva == 0x1C2A6A0 and len(values) == 2:
        return construct_shared_state(runtime, *values)
    if rva == 0xBD4FA0 and len(values) == 3:
        return construct_thread(runtime, *values)
    if rva == 0xD46B40 and len(values) == 2:
        return acquire_owner(runtime, *values)
    if rva == 0xD46BD0 and len(values) == 1:
        return release_owner(runtime, *values)
    if rva == 0x28F0 and len(values) == 1:
        return None
    if rva == 0x1FE0 and len(values) == 1:
        runtime._free_allocation(values[0])
        return None
    raise InputError('unsupported feature notification entry or argument count')
