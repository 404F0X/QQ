from dataclasses import dataclass

from .errors import InputError
from .primary_logger import _srw
from .primary_task_exit import clear_vector_queue
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed
from .primary_worker_batch import _operation, run_mode2_batch
from .primary_worker_response import _frame
from .primary_worker_tasks import _invoke


@dataclass
class WorkerEntryState:
    task: int
    frame: int = 0
    local_list: int = 0
    phase: str = 'created'
    iterations: int = 0
    mode: int = 0
    active: int = 0
    target: int = 0
    call_pending: bool = False
    failure: BaseException | None = None
    local_initialized: bool = False


def condition_wait(runtime, condition, owner):
    if not runtime.memory.load(owner + 8, 1):
        raise PrimarySemanticUnavailable('75FE90 task condition wait requires an owned mutex')
    mutex = runtime.memory.load(owner, 8)
    return infinite_wait(runtime, condition, mutex)


def infinite_wait(runtime, condition, mutex):
    target = runtime.worker_imports.get('SleepConditionVariableSRW')
    if target is None or runtime.memory.load(runtime.image_base + 0x4910370, 8) != target:
        raise PrimarySemanticUnavailable('task condition wait current import is not bound')
    if not getattr(runtime, '_logger_locks', {}).get(mutex, False):
        raise PrimarySemanticUnavailable('task condition wait requires the currently held source SRW lock')
    raise PrimarySemanticUnavailable('787840 task queue requires actual atomic release/wait/reacquire with timeout FFFFFFFF and flags0')


def _splice_vector(runtime, destination, source):
    memory = runtime.memory
    if memory.load(source + 16, 8):
        last, first = memory.load(source, 8), memory.load(source + 8, 8)
        following, before = memory.load(last + 8, 8), memory.load(first, 8)
        memory.store(before + 8, following, 8, source='task_vector.source_detach_next')
        before, following = memory.load(first, 8), memory.load(last + 8, 8)
        memory.store(following, before, 8, source='task_vector.source_detach_previous')
        previous = memory.load(destination, 8)
        memory.store(previous + 8, first, 8, source='task_vector.destination_previous_next')
        previous = memory.load(destination, 8)
        memory.store(first, previous, 8, source='task_vector.first_previous')
        memory.store(destination, last, 8, source='task_vector.destination_previous')
        memory.store(last + 8, destination, 8, source='task_vector.last_next')
        count = memory.load(source + 16, 8)
        memory.store(destination + 16, memory.load(destination + 16, 8) + count, 8, source='task_vector.destination_count_add')
        memory.store(source + 16, 0, 8, source='task_vector.source_count_clear')


def take_vector_batch(runtime, queue, destination, period=None, threshold=None):
    rva = 0xBD5100 if period is None else 0xBD51D0
    state = _operation(runtime, rva, queue, destination)
    memory = runtime.memory
    try:
        frame, _ = _frame(runtime, 0x58 if period is None else 0xA8, 'task_vector.take_frame')
        owner = frame + (0x28 if period is None else 0x48)
        if period is not None:
            memory.store(frame + 0x60, -2, 8, source='BD51E5.exception_state')
            memory.store(queue + 0x34, threshold, 4, source='BD51F7.vector_threshold')
        memory.store(owner, queue + 24, 8, source='task_vector.mutex_pointer')
        memory.store(owner + 8, 1, 1, source='task_vector.mutex_owned')
        state.phase = 'locking'
        _srw(runtime, queue + 24, True)
        state.lock_acquired = True
        state.phase = 'waiting'
        if period is None:
            while not memory.load(queue + 16, 4):
                condition_wait(runtime, queue + 32, owner)
        else:
            _invoke(runtime, 0x759B30, frame + 0x38)
            deadline = signed(memory.load(frame + 0x38, 8) + signed(period * 1000, 32) * 1000000, 64)
            for _ in range(100000):
                if memory.load(queue + 16, 4):
                    break
                _invoke(runtime, 0x759B30, frame + 0x30)
                if memory.load(frame + 0x30, 8, signed=True) >= deadline:
                    break
                _invoke(runtime, 0x759B30, frame + 0x28)
                memory.store(frame + 0x58, deadline - memory.load(frame + 0x28, 8), 8, source='BD5263.remaining_duration')
                from .primary_pending_thread import wait_nanoseconds
                wait_nanoseconds(runtime, queue + 32, owner, frame + 0x58)
                _invoke(runtime, 0x759B30, frame + 0x58)
                if memory.load(frame + 0x58, 8, signed=True) >= deadline:
                    break
            else:
                raise PrimaryProgramLimit('task vector timed wait exceeds the bounded execution domain')
        if period is None or memory.load(queue + 16, 4):
            state.phase = 'destination_cleanup'
            clear_vector_queue(runtime, destination)
            state.phase = 'moving'
            _splice_vector(runtime, destination, queue)
            state.phase = 'source_cleanup'
            clear_vector_queue(runtime, queue)
            if period is not None:
                memory.store(queue + 0x30, 0, 4, source='BD52E4.vector_pending_count_clear')
        state.phase = 'unlocking'
        if memory.load(owner + 8, 1):
            _srw(runtime, memory.load(owner, 8), False)
            state.lock_acquired = False
        memory.unmap(frame)
        state.phase = 'complete'
        return None
    except BaseException as error:
        state.failure = error
        raise


def _lifecycle(runtime, state, slot):
    memory = runtime.memory
    state.phase = 'start_lock' if slot == 0 else 'stop_lock'
    _srw(runtime, memory.load(state.frame + 0x20, 8), True)
    state.active = memory.load(state.task + 0xF0, 8)
    if state.active:
        state.target = memory.load(memory.load(state.active, 8) + slot, 8)
        state.call_pending = True
        _invoke(runtime, state.target - runtime.image_base, state.active)
        state.call_pending = False
    _srw(runtime, memory.load(state.frame + 0x20, 8), False)


def run(runtime, task):
    if not hasattr(runtime, 'worker_entry_states'):
        runtime.worker_entry_states = {}
    previous = runtime.worker_entry_states.get(task)
    if previous is not None and previous.phase != 'complete':
        raise PrimarySemanticUnavailable('task worker entry retains an unresolved invocation')
    budget = getattr(runtime, 'worker_entry_iteration_budget', 100000)
    if type(budget) is not int or budget <= 0:
        raise InputError('task worker iteration budget must be a positive integer')
    state = WorkerEntryState(task)
    runtime.worker_entry_states[task] = state
    memory = runtime.memory
    try:
        state.frame, _ = _frame(runtime, 0x88, 'BD4B00.worker_entry_frame')
        state.local_list = state.frame + 0x28
        memory.store(state.frame + 0x40, -2, 8, source='BD4B15.exception_state')
        memory.store(state.frame + 0x20, task + 0xE8, 8, source='BD4B27.lifecycle_mutex')
        _lifecycle(runtime, state, 0)
        while True:
            checkpoint = getattr(runtime, 'worker_resident_checkpoint', None)
            if checkpoint is not None:
                checkpoint(runtime, state)
            if not memory.load(task + 32, 1) & 1:
                break
            state.phase = 'loop'
            if state.iterations >= budget:
                state.phase = 'budget_exhausted'
                raise PrimaryProgramLimit('BD4B00 source loop exceeds the bounded execution domain without genuine stop')
            state.iterations += 1
            state.mode = memory.load(task + 0xD8, 4)
            if state.mode == 2:
                state.phase = 'function_batch'
                run_mode2_batch(runtime, task, state.local_list)
                state.local_initialized = True
            elif state.mode < 2:
                local = state.local_list
                memory.store(local, local, 8, source='BD4B7C.local_previous')
                memory.store(local + 8, local, 8, source='BD4B80.local_next')
                memory.store(local + 16, 0, 8, source='BD4B84.local_count')
                state.local_initialized = True
                state.phase = 'vector_batch'
                if state.mode == 0:
                    take_vector_batch(runtime, task + 0x60, local)
                else:
                    period = memory.load(task + 0xC8, 4)
                    threshold = memory.load(task + 0xC4, 4)
                    take_vector_batch(runtime, task + 0x60, local, period, threshold)
                if memory.load(task + 32, 1) & 1:
                    state.active = memory.load(task + 0xB8, 8)
                    count = memory.load(local + 16, 8)
                    if state.active and count:
                        state.target = memory.load(memory.load(state.active, 8) + 40, 8)
                        state.call_pending = True
                        _invoke(runtime, state.target - runtime.image_base, state.active, local)
                        state.call_pending = False
                state.phase = 'vector_cleanup'
                clear_vector_queue(runtime, local)
        _lifecycle(runtime, state, 8)
        memory.unmap(state.frame)
        state.phase = 'complete'
        runtime.events.append(('worker.entry_complete', task, state.iterations))
        return None
    except BaseException as error:
        state.failure = error
        raise


def invoke(runtime, rva, values):
    if rva == 0xBD4B00 and len(values) == 1:
        return run(runtime, values[0])
    if rva in (0xBD5100, 0xBD51D0) and len(values) == (2 if rva == 0xBD5100 else 4):
        return take_vector_batch(runtime, *values)
    if rva == 0xD45A80 and len(values) == 2:
        return condition_wait(runtime, *values)
    if rva == 0x787840 and len(values) == 2:
        return infinite_wait(runtime, *values)
    raise InputError('task worker entry source interface argument count mismatch')
