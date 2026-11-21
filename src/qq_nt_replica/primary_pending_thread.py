from .errors import InputError
from .primary_feature_notifications import _detach, acquire_owner, release_owner
from .primary_logger import _String, _srw
from .primary_notification_thread import complete, wait_absolute, _saturate
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
from .primary_worker_tasks import _observe


_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20


def install_image(memory, base):
    from .primary_thread_dispatch import install_image as install_dispatch_image

    install_dispatch_image(memory, base)
    memory.map(base + 0x4148D68,
        bytearray(b''.join((base + rva).to_bytes(8, 'little') for rva in (0x1BF4FE0, 0x1BF5070, 0x1BF50C0))),
        name='fixed pending async state virtual table', initialized=True)


def start_thread(runtime, output, control):
    memory, base = runtime.memory, runtime.image_base
    start = runtime._operator_new(16)
    memory.store(start, base + 0xBD55C0, 8, source='78794A.pending_thread_callback')
    memory.store(start + 8, control, 8, source='78794D.pending_thread_argument')
    context = runtime._allocate(40, True)
    memory.store(context, base + 0x7879A0, 8, source='3E817D5.pending_CRT_callback')
    memory.store(context + 8, start, 8, source='3E817DB.pending_CRT_argument')
    result, module = _observe(runtime, 'GetModuleHandleExW', 4, base + 0x7879A0)
    if (type(result) is not int or not 0 <= result <= 0xFFFFFFFF or result and module is None or
            module is not None and (type(module) is not int or not 0 <= module <= _MASK64)):
        raise InputError('pending thread module observation requires a DWORD result and optional module handle')
    if module is not None:
        memory.store(context + 24, module, 8, source='GetModuleHandleExW.pending_module')
    handle, identifier = _observe(runtime, 'CreateThread', 0, 0, base + 0x3E81800, context, 0)
    if not handle:
        raise PrimarySemanticUnavailable('3E8172E failed pending thread creation requires its original CRT cleanup and error path')
    if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
        raise InputError('pending thread creation requires an observed DWORD thread id')
    memory.store(output, handle, 8, source='787975.pending_thread_handle')
    runtime.events.append(('request.pending_thread_created', output, handle, context))


def wait_nanoseconds(runtime, condition, owner, duration_pointer):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x30, 'BD5420.pending_future_duration_frame')
    duration = memory.load(duration_pointer, 8, signed=True)
    if duration <= 0:
        memory.unmap(frame)
        return 1
    _invoke(runtime, 0x759B30, frame + 0x28)
    _invoke(runtime, 0x759A80, frame + 0x20)
    system = _saturate(memory.load(frame + 0x20, 8, signed=True) * 1000)
    duration = memory.load(duration_pointer, 8, signed=True)
    deadline = _saturate(system + duration)
    wait_absolute(runtime, condition, owner, deadline)
    _invoke(runtime, 0x759B30, frame + 0x20)
    elapsed = signed(memory.load(frame + 0x20, 8) - memory.load(frame + 0x28, 8), 64)
    result = int(elapsed >= memory.load(duration_pointer, 8, signed=True))
    memory.unmap(frame)
    return result


def ready(runtime, state, deadline):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x58, '1BF51B0.pending_future_ready_frame')
    rbp = frame + 0x50
    memory.store(rbp - 0x18, state + 32, 8, source='1BF51D7.pending_future_mutex')
    memory.store(rbp - 0x10, 1, 1, source='1BF51DB.pending_future_mutex_owned')
    _srw(runtime, state + 32, True)
    flags = memory.load(state + 48, 4)
    if flags & 8:
        result = 2
    else:
        for _ in range(_LIMIT):
            flags = memory.load(state + 48, 4)
            if flags & 4:
                break
            _invoke(runtime, 0x759B30, rbp - 8)
            if memory.load(rbp - 8, 8, signed=True) >= memory.load(deadline, 8, signed=True):
                flags = memory.load(state + 48, 4)
                break
            _invoke(runtime, 0x759B30, rbp - 0x20)
            limit = memory.load(deadline, 8, signed=True)
            if memory.load(rbp - 0x20, 8, signed=True) < limit:
                _invoke(runtime, 0x759B30, rbp - 0x28)
                duration = signed(limit - memory.load(rbp - 0x28, 8, signed=True), 64)
                memory.store(rbp - 8, duration, 8, source='1BF5246.pending_future_wait_duration')
                wait_nanoseconds(runtime, state + 40, rbp - 0x18, rbp - 8)
                _invoke(runtime, 0x759B30, rbp - 8)
        else:
            raise PrimaryProgramLimit('pending future readiness wait exceeds the bounded execution domain')
        result = int(not flags & 4)
    if memory.load(rbp - 0x10, 1):
        _srw(runtime, memory.load(rbp - 0x18, 8), False)
    memory.unmap(frame)
    return result


def prune(runtime, owner, rbp):
    memory = runtime.memory
    sentinel = owner + 176
    current = memory.load(sentinel + 8, 8)
    for _ in range(_LIMIT):
        if current == sentinel or not memory.load(owner + 192, 8):
            return
        state = memory.load(current + 16, 8)
        if state:
            _invoke(runtime, 0x759B30, rbp + 0x98)
            memory.store(rbp + 0xE8, memory.load(rbp + 0x98, 8), 8,
                         source='1BF294C.pending_future_poll_deadline')
            if ready(runtime, state, rbp + 0xE8):
                current = memory.load(current + 8, 8)
                continue
        following, previous = memory.load(current, 8), memory.load(current + 8, 8)
        memory.store(following + 8, previous, 8, source='1BF28FB.pending_future_unlink_previous')
        memory.store(previous, following, 8, source='1BF2906.pending_future_unlink_next')
        memory.store(owner + 192, (memory.load(owner + 192, 8) - 1) & _MASK64, 8,
                     source='1BF2909.pending_future_count_remove')
        release_owner(runtime, current + 16)
        runtime._free_allocation(current)
        current = previous
    raise PrimaryProgramLimit('pending future pruning exceeds the bounded execution domain')


def construct(runtime, owner, payload, columns, rbp):
    memory, base = runtime.memory, runtime.image_base
    sources = (payload, columns, columns + 24)
    for offset in (0x38, 0x98, 0xE8):
        targets = tuple(rbp + offset + index * 24 for index in range(3))
        for source, target in zip(sources, targets):
            _String.read(runtime, source).clone().write_to(target)
        sources = targets
    state = runtime._operator_new(128)
    memory.store(state + 8, 0, 4, source='1BF26B6.pending_async_initial_reference')
    memory.store(state, base + 0x3FF03A8, 8, source='1BF26C4.pending_async_base_vtable')
    memory.write(state + 16, bytes(16), source='759D10.pending_async_empty_exception')
    memory.write(state + 32, bytes(16), source='1BF26DA.pending_async_synchronization_zero')
    memory.store(state + 48, 0, 4, source='1BF26DE.pending_async_flags_zero')
    memory.store(state, base + 0x4148D68, 8, source='1BF26EC.pending_async_vtable')
    memory.store(rbp + 0x148, state, 8, source='1BF2701.pending_async_local_owner')
    for source, offset in zip(sources, (56, 80, 104)):
        _String.read(runtime, source).clone().write_to(state + offset)
    holder = runtime._operator_new(8)
    memory.store(rbp + 0x140, holder, 8, source='1BF2745.pending_thread_holder_temporary')
    thread_state = runtime._operator_new(48)
    memory.write(thread_state, bytes(48), source='760232.pending_thread_state_zero')
    memory.store(holder, thread_state, 8, source='760240.pending_thread_state_owner')
    memory.store(rbp + 0xE0, holder, 8, source='1BF275B.pending_thread_holder_owner')
    control = runtime._operator_new(24)
    for offset, value in ((0, holder), (8, base + 0x36E0), (16, state)):
        memory.store(control + offset, value, 8, source='1BF276F.pending_thread_tuple')
    memory.store(rbp + 0x140, control, 8, source='1BF2796.pending_thread_tuple_owner')
    start_thread(runtime, rbp + 0x138, control)
    _detach(runtime, rbp + 0x138)
    if memory.load(rbp + 0x138, 8):
        raise PrimarySemanticUnavailable('75FF61 pending joinable-thread destruction requires termination')
    acquire_owner(runtime, rbp + 0x138, state)
    release_owner(runtime, rbp + 0x148)
    for offset in (0x118, 0x100, 0xE8, 0xC8, 0xB0, 0x98, 0x68, 0x50, 0x38):
        _String.read(runtime, rbp + offset).destroy()
    node = runtime._operator_new(24)
    memory.store(node + 16, memory.load(rbp + 0x138, 8), 8, source='1BF287B.pending_future_state_transfer')
    memory.store(rbp + 0x138, 0, 8, source='1BF287F.pending_future_local_owner_clear')
    sentinel = owner + 176
    previous = memory.load(sentinel, 8)
    memory.store(node + 8, sentinel, 8, source='1BF288A.pending_future_previous')
    memory.store(node, previous, 8, source='1BF2896.pending_future_next')
    memory.store(previous + 8, node, 8, source='1BF2899.pending_future_old_head_previous')
    memory.store(sentinel, node, 8, source='1BF289D.pending_future_head')
    count = (memory.load(owner + 192, 8) + 1) & _MASK64
    memory.store(owner + 192, count, 8, source='1BF28B1.pending_future_count')
    if count >= 101:
        prune(runtime, owner, rbp)
    release_owner(runtime, rbp + 0x138)
    runtime.events.append(('request.pending_async_constructed', state, node))


def entry(runtime, state):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0xA0, '1BF50C0.pending_async_body_frame')
    memory.store(rbp + 16, state, 8, source='1BF50DD.pending_async_body_state')
    gate = _invoke(runtime, 0xBA21A0)
    memory.store(rbp - 32, 0, 8, source='1BF50E9.pending_async_empty_callback')
    payload = _String.read(runtime, state + 56)
    header = payload.get(0, 1)
    pointer, count = (payload.get(16, 8), payload.get(8, 4)) if header & 1 else (state + 57, header >> 1)
    _invoke(runtime, 0x1BF13C0, rbp - 8)
    _invoke(runtime, 0x1CE6920, gate, rbp - 8, pointer, count, rbp - 64, state + 80, 1)
    complete(runtime, memory.load(rbp + 16, 8))
    memory.unmap(frame)


def delete(runtime, state, flag):
    memory, base = runtime.memory, runtime.image_base
    memory.store(state, base + 0x4148D68, 8, source='1BF4FF2.pending_async_destructor_vtable')
    for offset in (104, 80, 56):
        _String.read(runtime, state + offset).destroy()
    memory.store(state, base + 0x3FF03A8, 8, source='1BF5017.pending_async_base_destructor_vtable')
    if memory.load(state + 24, 8):
        raise PrimarySemanticUnavailable('3E69794 pending async exception control requires its actual virtual destruction')
    if flag & 0xFFFFFFFF:
        runtime._free_allocation(state)
    return state


def invoke(runtime, rva, values):
    if rva == 0x1BF50C0 and len(values) == 1:
        return entry(runtime, *values)
    if rva == 0x1BF4FE0 and len(values) == 2:
        return delete(runtime, *values)
    if rva == 0x1BF51B0 and len(values) == 2:
        return ready(runtime, *values)
    if rva == 0xBD5420 and len(values) == 3:
        return wait_nanoseconds(runtime, *values)
    raise InputError('unsupported pending async entry or argument count')
