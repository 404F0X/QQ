from collections import deque

from .errors import InputError
from .primary_logger import _srw
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_tasks import _invoke


def _string(runtime, pointer):
    if runtime.memory.load(pointer, 1) & 1:
        runtime._free_allocation(runtime.memory.load(pointer + 16, 8))


def _vector(runtime, pointer):
    memory = runtime.memory
    begin = memory.load(pointer, 8)
    if not begin:
        return
    current = memory.load(pointer + 8, 8)
    if current < begin or (current - begin) % 24 or current - begin > 24 * 100000:
        raise PrimaryProgramLimit('task string vector is outside the bounded source layout')
    while current != begin:
        current -= 24
        _string(runtime, current)
    target = memory.load(pointer, 8)
    memory.store(pointer + 8, begin, 8, source='task_exit.vector_end_reset')
    runtime._free_allocation(target)


def destroy_base_record(runtime, pointer):
    runtime.memory.store(pointer, runtime.image_base + 0x3FD6C78, 8,
                         source='BCD751.telemetry_base_vtable')
    _vector(runtime, pointer + 0xC8)
    for offset in reversed(range(8, 0xC8, 24)):
        _string(runtime, pointer + offset)


def destroy_record(runtime, pointer):
    runtime.memory.store(pointer, runtime.image_base + 0x3FD6EB8, 8,
                         source='BD3AEF.telemetry_derived_vtable')
    for offset in reversed(range(0xE0, 0x170, 24)):
        _string(runtime, pointer + offset)
    destroy_base_record(runtime, pointer)


def _function(runtime, active, inline):
    if not active:
        return
    table = runtime.memory.load(active, 8)
    target = runtime.memory.load(table + (24 if active == inline else 32), 8)
    _invoke(runtime, target - runtime.image_base, active)


def _detach(runtime, queue):
    memory = runtime.memory
    if not memory.load(queue + 16, 8):
        return None
    previous, first = memory.load(queue, 8), memory.load(queue + 8, 8)
    following = memory.load(previous + 8, 8)
    before = memory.load(first, 8)
    memory.store(before + 8, following, 8, source='task_exit.queue_detach_next')
    before = memory.load(first, 8)
    following = memory.load(previous + 8, 8)
    memory.store(following, before, 8, source='task_exit.queue_detach_previous')
    memory.store(queue + 16, 0, 8, source='task_exit.queue_count_clear')
    runtime.events.append(('task.exit_queue_detached', queue, first))
    return first


def clear_vector_queue(runtime, queue):
    node = _detach(runtime, queue)
    seen = set()
    while node is not None and node != queue:
        if node in seen or len(seen) >= 100000:
            raise PrimaryProgramLimit('task vector queue does not reach its source sentinel')
        seen.add(node)
        following = runtime.memory.load(node + 8, 8)
        _vector(runtime, node + 24)
        runtime._free_allocation(node)
        node = following


def clear_function_queue(runtime, queue):
    node = _detach(runtime, queue)
    seen = set()
    while node is not None and node != queue:
        if node in seen or len(seen) >= 100000:
            raise PrimaryProgramLimit('task function queue does not reach its source sentinel')
        seen.add(node)
        following = runtime.memory.load(node + 8, 8)
        active = runtime.memory.load(node + 48, 8)
        _function(runtime, active, node + 24)
        runtime._free_allocation(node)
        node = following


def _provider_queue(runtime, task):
    queue = task.queues[0]
    if not queue.nodes:
        clear_function_queue(runtime, queue.address)
        queue.count = 0
        return
    if runtime.memory.load(queue.address + 16, 8):
        first = _detach(runtime, queue.address)
        if first != queue.nodes[0][0]:
            raise PrimarySemanticUnavailable('provider queue memory and owned captures disagree')
    else:
        runtime.memory.store(queue.address + 8, queue.address, 8,
                             source='BD6038.provider_queue_detach_next')
        runtime.memory.store(queue.address, queue.address, 8,
                             source='BD6043.provider_queue_detach_previous')
        runtime.memory.store(queue.address + 16, 0, 8,
                             source='BD6046.provider_queue_count_clear')
    task.retired_nodes, queue.nodes = queue.nodes, deque()
    queue.count = 0
    runtime.events.append(('task.exit_queue_detached', queue.address, task.retired_nodes[0][0]))
    while task.retired_nodes:
        node, function = task.retired_nodes[0]
        function.destroy(runtime)
        runtime._free_allocation(node)
        task.retired_nodes.popleft()


def destroy_task(runtime, pointer):
    memory = runtime.memory
    if not hasattr(runtime, 'task_exit_states'):
        runtime.task_exit_states = {}
    if pointer in runtime.task_exit_states:
        raise PrimarySemanticUnavailable('task exit already completed or stopped in an unresolved cleanup')
    if runtime.locks.get(pointer + 0xE0, 0):
        raise PrimarySemanticUnavailable('task exit waits on an owned startup mutex')
    _srw(runtime, pointer + 0xE0, True)
    runtime.task_exit_states[pointer] = 'incomplete'
    logical = runtime.postfetch_task
    if logical is not None and logical.address != pointer:
        logical = None
    if logical is not None:
        logical.closing = True
    for offset, label in ((0x55, 'BD5FD0'), (0x8D, 'BD5FD6'), (0x20, 'BD5FDF')):
        memory.store(pointer + offset, 0, 1, source=label + '.task_flag_clear')
    if logical is not None:
        for queue in logical.queues:
            queue.enabled = 0
    _srw(runtime, pointer + 0xE0, False)
    stop_checkpoint = getattr(runtime, 'worker_stop_checkpoint', None)
    if stop_checkpoint is not None:
        stop_checkpoint(runtime, pointer)
    active = memory.load(pointer + 0xB8, 8)
    _function(runtime, active, pointer + 0xA0)
    if logical is not None and logical.queues[1].nodes:
        raise PrimarySemanticUnavailable('provider secondary queue requires source string-vector ownership')
    clear_vector_queue(runtime, pointer + 0x60)
    if logical is None:
        clear_function_queue(runtime, pointer + 0x28)
    else:
        logical.queues[1].count = 0
        _provider_queue(runtime, logical)
    _string(runtime, pointer)
    runtime.task_exit_states[pointer] = 'complete'
    if logical is not None:
        logical.closing = False
        logical.closed = True
        if logical.batch:
            runtime.events.append(('task.exit_private_batch_retained', pointer, len(logical.batch)))
    runtime.events.append(('BD5FA0.task_destroyed', pointer))


def invoke(runtime, rva, values):
    if rva in (0xBD4700, 0xBD6110) and not values:
        return destroy_task(runtime, runtime.image_base + (0x6751B50 if rva == 0xBD4700 else 0x6751C58))
    if len(values) != 1:
        raise InputError('task exit source interface argument count mismatch')
    if rva == 0xBD5FA0:
        return destroy_task(runtime, values[0])
    if rva in (0xBD43B0, 0xBD43C0):
        destroy_record(runtime, values[0] + 8)
        if rva == 0xBD43C0:
            runtime._free_allocation(values[0])
        return None
    if rva == 0xBD3AE0:
        return destroy_record(runtime, values[0])
    if rva == 0xBCD740:
        return destroy_base_record(runtime, values[0])
    if rva == 0xBD48F0:
        return clear_vector_queue(runtime, values[0])
    raise InputError('unknown task exit source interface')
