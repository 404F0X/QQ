from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from .errors import InputError
from .primary_logger import _cstring, _srw, feature
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable


_MASK64 = (1 << 64) - 1
_IMAGE_SHA256 = '730dc926e7de325f9c1b192048f3295dbfbcc2e4842e10ee9e7ace59b57c1f14'
_IMPORTS = {'GetModuleHandleExW': 0x490FF08, 'CreateThread': 0x490FC80,
            'GetThreadId': 0x490FFD8, 'WakeConditionVariable': 0x4910458}


def install_image(memory, image_base):
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'worker-task-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed worker task image identity mismatch')
    image = json.loads(raw)
    for segment in image['segments']:
        data = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            value = int.from_bytes(data[offset:offset + 8], 'little')
            data[offset:offset + 8] = ((value - image['image_base'] + image_base) & _MASK64).to_bytes(8, 'little')
        memory.map(image_base + segment['rva'], data, name='fixed worker task source image', initialized=True)
    for region in (image['provider_zero_fill'], image['zero_fill']):
        memory.map(image_base + region['rva'], bytearray(region['size']), name='fixed worker task PE zero fill', initialized=True)


def _invoke(runtime, rva, *values):
    vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    return runtime.invoke(vm, rva, tuple(range(len(values))))


def _observe(runtime, name, *values):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('worker task current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing worker task system observations: ' + name)
    return runtime.worker_observations.take(runtime, name, values)


def construct(runtime, pointer, name, mode):
    memory = runtime.memory
    value = _cstring(runtime, name)
    if len(value) <= 22:
        memory.store(pointer, len(value) * 2, 1, source='BD4743.task_name_tag')
        target = pointer + 1
    else:
        capacity = (len(value) + 16) & ~15
        target = runtime._operator_new(capacity)
        memory.store(pointer + 16, target, 8, source='BD4766.task_name_pointer')
        memory.store(pointer, capacity | 1, 8, source='BD476E.task_name_capacity')
        memory.store(pointer + 8, len(value), 8, source='BD4771.task_name_length')
    memory.write(target, value + b'\0', source='BD477E.task_name_copy')
    memory.store(pointer + 24, 0, 8, source='BD4788.task_thread')
    memory.store(pointer + 32, 0, 1, source='BD4790.task_running')
    for offset in (0x28, 0x60):
        head = pointer + offset
        memory.store(head, head, 8, source='BD4710.queue_previous')
        memory.store(head + 8, head, 8, source='BD4710.queue_next')
        memory.write(head + 16, bytes(16), source='BD4710.queue_count_and_lock')
        memory.store(head + 32, 0, 8, source='BD4710.queue_condition')
        memory.store(head + 40, 5000, 4, source='BD4710.queue_capacity')
        memory.store(head + 44, 1, 2, source='BD4710.queue_flags')
        memory.store(head + 52, 0, 4, source='BD4710.queue_state')
    for offset, value, width in ((0xB8, 0, 8), (0xC0, 0xA00000000, 8), (0xC8, 3, 4), (0xD0, 0, 8), (0xD8, mode, 4)):
        memory.store(pointer + offset, value, width, source='BD4710.task_metadata')
    memory.write(pointer + 0xE9, bytes(16), source='BD4833.task_synchronization_tail')
    memory.write(pointer + 0xE0, bytes(16), source='BD483A.task_synchronization_head')
    getattr(runtime, 'task_exit_states', {}).pop(pointer, None)
    return pointer


def _start(runtime, task):
    memory, base = runtime.memory, runtime.image_base
    if memory.load(task + 32, 1) & 1:
        return
    _srw(runtime, task + 0xE0, True)
    if not memory.load(task + 32, 1) & 1:
        for offset in (0x20, 0x55, 0x8D):
            memory.store(task + offset, 1, 1, source='BD49E0.running_exchange')
        thread = runtime._operator_new(8)
        holder = runtime._operator_new(8)
        state = runtime._operator_new(48)
        for offset in (0, 16, 32):
            memory.write(state + offset, bytes(16), source='760220.thread_state_zero')
        memory.store(holder, state, 8, source='760240.thread_state_publish')
        control = runtime._operator_new(24)
        for offset, value in ((0, holder), (8, base + 0xBD4B00), (16, task)):
            memory.store(control + offset, value, 8, source='BD4FA0.thread_control')
        start = runtime._operator_new(16)
        memory.store(start, base + 0xBD55C0, 8, source='78794A.thread_callback')
        memory.store(start + 8, control, 8, source='78794D.thread_argument')
        context = runtime._allocate(40, True)
        memory.store(context, base + 0x7879A0, 8, source='3E817D5.CRT_thread_callback')
        memory.store(context + 8, start, 8, source='3E817DB.CRT_thread_argument')
        result, module = _observe(runtime, 'GetModuleHandleExW', 4, base + 0x7879A0)
        if (result > 0xFFFFFFFF or result and module is None or
                module is not None and (type(module) is not int or not 0 <= module <= _MASK64)):
            raise InputError('worker thread module observation requires a DWORD result and optional module handle')
        if module is not None:
            memory.store(context + 24, module, 8, source='GetModuleHandleExW.observed_module')
        handle, identifier = _observe(runtime, 'CreateThread', 0, 0, base + 0x3E81800, context, 0)
        if not handle:
            raise PrimarySemanticUnavailable('3E8172E failed CRT thread creation requires last-error, module and allocation cleanup effects')
        if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
            raise InputError('worker CRT thread creation requires an observed DWORD thread id')
        memory.store(thread, handle, 8, source='787975.thread_handle')
        memory.store(task + 24, thread, 8, source='BD4A5B.task_thread_publish')
        identifier, effects = _observe(runtime, 'GetThreadId', handle)
        if identifier > 0xFFFFFFFF or effects is not None:
            raise InputError('worker thread id requires an observed DWORD and no memory effects')
        memory.store(task + 0xC0, identifier, 4, source='BD4A64.task_thread_id')
        runtime.events.append(('worker.task_thread_created', task, thread, handle, context))
    _srw(runtime, task + 0xE0, False)


@dataclass(frozen=True)
class _Function:
    capture: int | None
    pointer: int = 0
    vtable_rva: int = 0x3FD6FF8


def _slot(runtime, offset, expected, vtable_rva=0x3FD6FF8):
    target = runtime.memory.load(runtime.image_base + vtable_rva + offset, 8)
    if target != runtime.image_base + expected:
        raise PrimarySemanticUnavailable('worker task current function vtable slot is not bound')


def _load_function(runtime, pointer):
    active = runtime.memory.load(pointer + 32, 8)
    if not active:
        return _Function(None)
    vtable_rva = runtime.memory.load(active, 8) - runtime.image_base
    if vtable_rva == 0x436ECF8:
        return _Function(0, 0 if active == pointer + 8 else active, vtable_rva)
    if vtable_rva in (0x4148C38, 0x3FD6F48):
        return _Function(active + 8, 0 if active == pointer + 8 else active, vtable_rva)
    if vtable_rva not in (0x3FD6FF8, 0x3FD6E08):
        raise PrimarySemanticUnavailable('worker task function capture type is not bound')
    return _Function(runtime.memory.load(active + 8, 8), 0 if active == pointer + 8 else active, vtable_rva)


def _copy(runtime, function):
    if function.capture is None:
        return function
    if function.vtable_rva == 0x436ECF8:
        _slot(runtime, 16 if function.pointer else 8,
              0x2DF47E0 if function.pointer else 0x2DF47D0, function.vtable_rva)
        if function.pointer:
            return _Function(0, _invoke(runtime, 0x2DF47E0, function.pointer), function.vtable_rva)
        return function
    if function.vtable_rva == 0x3FD6F48:
        if not function.pointer:
            raise PrimarySemanticUnavailable('provider telemetry oversized inline function capture is unavailable')
        _slot(runtime, 16, 0xBD4340, function.vtable_rva)
        target = _invoke(runtime, 0xBD4340, function.pointer)
        return _Function(target + 8, target, function.vtable_rva)
    if function.vtable_rva == 0x4148C38:
        if not function.pointer:
            raise PrimarySemanticUnavailable('pending report oversized inline function capture remains unavailable')
        _slot(runtime, 16, 0x1BF3DD0, function.vtable_rva)
        target = _invoke(runtime, 0x1BF3DD0, function.pointer)
        return _Function(target + 8, target, function.vtable_rva)
    provider = function.vtable_rva == 0x3FD6E08
    if provider:
        runtime.events.append(('worker.provider_function_copy', function.capture, function.pointer))
    if not function.pointer:
        _slot(runtime, 8, 0xBD0930 if provider else 0xBD6120, function.vtable_rva)
        return function
    _slot(runtime, 16, 0xBD0950 if provider else 0xBD6140, function.vtable_rva)
    target = runtime._operator_new(16)
    runtime.memory.store(target, runtime.image_base + function.vtable_rva, 8, source='worker_task.function_vtable')
    runtime.memory.store(target + 8, function.capture, 8, source='BD6162.function_capture')
    return _Function(function.capture, target, function.vtable_rva)


def _destroy(runtime, function):
    if function.capture is None:
        return
    if function.vtable_rva == 0x3FD6F48:
        rva = 0xBD43C0 if function.pointer else 0xBD43B0
        _slot(runtime, 32 if function.pointer else 24, rva, function.vtable_rva)
        _invoke(runtime, rva, function.pointer or function.capture - 8)
        return
    if function.vtable_rva == 0x4148C38:
        rva = 0x1BF3E90 if function.pointer else 0x1BF3E40
        _slot(runtime, 32 if function.pointer else 24, rva, function.vtable_rva)
        _invoke(runtime, rva, function.pointer or function.capture - 8)
        return
    _slot(runtime, 32 if function.pointer else 24, 0x1FE0 if function.pointer else 0x28F0, function.vtable_rva)
    if function.vtable_rva == 0x3FD6E08:
        runtime.events.append(('worker.provider_function_destroy', function.capture, function.pointer))
    if function.pointer:
        runtime._free_allocation(function.pointer)


def _push(runtime, queue, function, notify):
    memory, base = runtime.memory, runtime.image_base
    if not memory.load(queue + 45, 1) & 1:
        raise PrimarySemanticUnavailable('BD56BD disabled queue reporting remains unavailable')
    _srw(runtime, queue + 24, True)
    count = memory.load(queue + 16, 8)
    capacity = memory.load(queue + 40, 4, signed=True) & _MASK64
    if count >= capacity:
        raise PrimarySemanticUnavailable('BD5A9D queue capacity reporting remains unavailable')
    node = runtime._operator_new(56)
    memory.store(node, 0, 8, source='BD5A65.node_initial_previous')
    if function.capture is None:
        memory.store(node + 48, 0, 8, source='BD5E6E.node_empty_function')
    elif function.pointer:
        copied = _copy(runtime, function)
        memory.store(node + 48, copied.pointer, 8, source='BD5E6E.node_heap_function')
    else:
        memory.store(node + 48, node + 24, 8, source='BD5E7B.node_inline_function')
        _copy(runtime, function)
        memory.store(node + 24, base + function.vtable_rva, 8, source='worker_task.function_vtable')
        if function.vtable_rva != 0x436ECF8:
            memory.store(node + 32, function.capture, 8, source='BD612E.function_capture')
    memory.store(node + 8, queue, 8, source='BD5E89.node_next')
    previous = memory.load(queue, 8)
    memory.store(node, previous, 8, source='BD5E90.node_previous')
    memory.store(previous + 8, node, 8, source='BD5E93.previous_next')
    memory.store(queue, node, 8, source='BD5E97.queue_previous')
    memory.store(queue + 16, count + 1, 8, source='BD5E9A.queue_count')
    if notify:
        result, effects = _observe(runtime, 'WakeConditionVariable', queue + 32)
        if result is not None or effects != ():
            raise PrimarySemanticUnavailable('condition wake with concurrent effects requires actual task scheduling')
    _srw(runtime, queue + 24, False)
    _destroy(runtime, function)
    runtime.events.append(('worker.task_queued', queue, node, function.capture))


def _enqueue(runtime, task, function):
    memory = runtime.memory
    flag = memory.load(task + 0xF8, 1)
    memory.store(task + 0xF8, flag if flag else 1, 1, source='BD07A5.task_start_cmpxchg')
    if not flag:
        _start(runtime, task)
    copied = _copy(runtime, function)
    argument = _copy(runtime, copied)
    _push(runtime, task + 40, argument, True)
    _destroy(runtime, copied)
    _destroy(runtime, function)


def _task(runtime, task_rva, guard_rva, name_rva, callback_rva, source):
    memory, base = runtime.memory, runtime.image_base
    guard = base + guard_rva
    value = memory.load(guard, 4)
    task = base + task_rva
    if not value & 1:
        memory.store(guard, value | 1, 4, source=source)
        construct(runtime, task, base + name_rva, 2)
        _invoke(runtime, 0x3E680B4, base + callback_rva)
    return task


def provider_task(runtime):
    return _task(runtime, 0x6751B50, 0x6751C50, 0x48AF756, 0xBD4700,
                 'BB7671.provider_task_guard_publish')


def device_task(runtime):
    return _task(runtime, 0x6751C58, 0x6751D58, 0x46C7416, 0xBD6110,
                 '1C20C3C.device_task_guard_publish')


def enqueue_device_worker(runtime):
    memory, base = runtime.memory, runtime.image_base
    logger = memory.load(base + 0x67516A8, 8)
    if feature(runtime, logger, 37) != 1:
        from .primary_response_refresh import _synchronous
        return _synchronous(runtime)
    task = device_task(runtime)
    _enqueue(runtime, task, _Function(base + 0x6751840))


def enqueue_provider_worker(runtime):
    task = provider_task(runtime)
    function = _Function(runtime.image_base + 0x6751840, vtable_rva=0x3FD6E08)
    argument = _copy(runtime, function)
    try:
        _enqueue(runtime, task, argument)
    except UnknownMemory as error:
        raise PrimarySemanticUnavailable('provider postfetch enqueue requires its observed native task OS effects') from error
    _destroy(runtime, function)


def invoke(runtime, rva, values):
    if rva in (0xBD5330, 0xBD54F0):
        from .primary_worker_batch import invoke
        return invoke(runtime, rva, values)
    if rva == 0xBD0980 and len(values) == 1:
        return _invoke(runtime, 0xBD0A00, values[0] + 8)
    if rva in (0xBD42E0, 0xBD4320, 0xBD4340, 0xBD43E0):
        from .primary_source_postfetch import copy_functor, destroy_functor
        if rva == 0xBD42E0 and len(values) == 2:
            return destroy_functor(runtime, values[0], values[1] & 0xFFFFFFFF)
        if rva == 0xBD4320 and len(values) == 2:
            return copy_functor(runtime, *values)
        if rva == 0xBD4340 and len(values) == 1:
            return copy_functor(runtime, values[0])
        if rva == 0xBD43E0 and len(values) == 1:
            return _invoke(runtime, 0xBD4460, values[0] + 8)
    if rva == 0xBD4710 and len(values) == 3:
        return construct(runtime, *values)
    if rva == 0xBD49E0 and len(values) == 1:
        return _start(runtime, values[0])
    if rva == 0xBD0780 and len(values) == 2:
        return _enqueue(runtime, values[0], _load_function(runtime, values[1]))
    if rva == 0xBD5690 and len(values) == 3:
        return _push(runtime, values[0], _load_function(runtime, values[1]), values[2] & 255)
    raise InputError('worker task source interface argument count mismatch')
