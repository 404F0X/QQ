from dataclasses import dataclass, field

from .errors import InputError
from .primary_logger import _srw
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_tasks import _invoke


@dataclass
class FunctionListCleanup:
    sentinel: int
    phase: str = 'created'
    first_node: int = 0
    current_node: int = 0
    following_node: int = 0
    active: int = 0
    target: int = 0
    call_pending: bool = False
    destroyed_nodes: list[int] = field(default_factory=list)
    freed_nodes: list[int] = field(default_factory=list)
    failure: BaseException | None = None


@dataclass
class FunctionListTransfer:
    rva: int
    destination: int
    source: int
    phase: str = 'created'
    first_node: int = 0
    last_node: int = 0
    lock_acquired: bool = False
    frame: int = 0
    owner: int = 0
    cleanup: FunctionListCleanup | None = None
    move: 'FunctionListTransfer | None' = None
    failure: BaseException | None = None


@dataclass
class PhysicalWorkerBatch:
    task: int
    local_list: int
    phase: str = 'created'
    current_node: int = 0
    active: int = 0
    target: int = 0
    call_pending: bool = False
    invoked_nodes: list[int] = field(default_factory=list)
    skipped_nodes: list[int] = field(default_factory=list)
    transfer: FunctionListTransfer | None = None
    cleanup: FunctionListCleanup | None = None
    failure: BaseException | None = None


def _detach(runtime, state, prefix):
    memory, sentinel = runtime.memory, state.sentinel
    state.phase = 'detaching'
    if not memory.load(sentinel + 16, 8):
        state.phase = 'complete'
        return
    last = memory.load(sentinel, 8)
    state.first_node = state.current_node = memory.load(sentinel + 8, 8)
    following = memory.load(last + 8, 8)
    before = memory.load(state.first_node, 8)
    memory.store(before + 8, following, 8, source=prefix + '.detach_next')
    before = memory.load(state.first_node, 8)
    following = memory.load(last + 8, 8)
    memory.store(following, before, 8, source=prefix + '.detach_previous')
    memory.store(sentinel + 16, 0, 8, source=prefix + '.count_clear')
    state.phase = 'destroying'


def _clear(runtime, state, prefix):
    try:
        _detach(runtime, state, prefix)
        if state.phase == 'complete':
            return
        seen = set()
        while state.current_node != state.sentinel:
            node = state.current_node
            if node in seen or len(seen) >= 100000:
                raise PrimaryProgramLimit('physical function list does not reach its source sentinel')
            seen.add(node)
            state.following_node = runtime.memory.load(node + 8, 8)
            state.active = runtime.memory.load(node + 48, 8)
            state.target = 0
            state.call_pending = False
            if state.active:
                table = runtime.memory.load(state.active, 8)
                slot = 24 if state.active == node + 24 else 32
                state.target = runtime.memory.load(table + slot, 8)
                state.call_pending = True
                _invoke(runtime, state.target - runtime.image_base, state.active)
                state.call_pending = False
            state.destroyed_nodes.append(node)
            state.phase = 'freeing'
            runtime._free_allocation(node)
            state.freed_nodes.append(node)
            state.current_node = state.following_node
            state.phase = 'destroying'
        state.phase = 'complete'
    except BaseException as error:
        state.failure = error
        raise


def _operation(runtime, rva, first, second):
    if not hasattr(runtime, 'worker_list_operations'):
        runtime.worker_list_operations = {}
    key = rva, first, second
    previous = runtime.worker_list_operations.get(key)
    if previous is not None and previous.phase != 'complete':
        raise PrimarySemanticUnavailable('physical function list operation retains unresolved ownership')
    destination, source = (second, first) if rva in (0xBD5330, 0xBD5100, 0xBD51D0) else (first, second)
    state = FunctionListTransfer(rva, destination, source)
    runtime.worker_list_operations[key] = state
    return state


def _move(runtime, state):
    memory = runtime.memory
    try:
        state.phase = 'destination_cleanup'
        state.cleanup = FunctionListCleanup(state.destination)
        _clear(runtime, state.cleanup, 'BD54F0')
        state.phase = 'splicing'
        if memory.load(state.source + 16, 8):
            state.last_node = last = memory.load(state.source, 8)
            state.first_node = first = memory.load(state.source + 8, 8)
            following = memory.load(last + 8, 8)
            before = memory.load(first, 8)
            memory.store(before + 8, following, 8, source='BD5544.source_detach_next')
            before = memory.load(first, 8)
            following = memory.load(last + 8, 8)
            memory.store(following, before, 8, source='BD554F.source_detach_previous')
            previous = memory.load(state.destination, 8)
            memory.store(previous + 8, first, 8, source='BD5555.destination_previous_next')
            previous = memory.load(state.destination, 8)
            memory.store(first, previous, 8, source='BD555C.first_previous')
            memory.store(state.destination, last, 8, source='BD555F.destination_previous')
            memory.store(last + 8, state.destination, 8, source='BD5562.last_next')
            count = memory.load(state.source + 16, 8)
            memory.store(state.destination + 16, memory.load(state.destination + 16, 8) + count,
                         8, source='BD556A.destination_count_add')
            memory.store(state.source + 16, 0, 8, source='BD556E.source_count_clear')
        state.phase = 'complete'
    except BaseException as error:
        state.failure = error
        raise


def move_function_list(runtime, destination, source):
    state = _operation(runtime, 0xBD54F0, destination, source)
    _move(runtime, state)


def _take(runtime, state):
    try:
        from .primary_worker_response import _frame
        state.frame, _ = _frame(runtime, 0x58, 'BD5330.queue_take_frame')
        state.owner = state.frame + 0x28
        runtime.memory.store(state.owner, state.source + 24, 8, source='BD5343.queue_mutex')
        runtime.memory.store(state.owner + 8, 1, 1, source='BD5348.queue_mutex_owned')
        state.phase = 'locking'
        _srw(runtime, state.source + 24, True)
        state.lock_acquired = True
        state.phase = 'waiting'
        if not runtime.memory.load(state.source + 16, 4):
            from .primary_worker_entry import condition_wait
            while not runtime.memory.load(state.source + 16, 4):
                try:
                    condition_wait(runtime, state.source + 32, state.owner)
                except PrimarySemanticUnavailable as error:
                    raise PrimarySemanticUnavailable('BD5376 physical task queue wait: ' + str(error)) from error
        state.phase = 'moving'
        state.move = _operation(runtime, 0xBD54F0, state.destination, state.source)
        _move(runtime, state.move)
        state.phase = 'source_cleanup'
        state.cleanup = FunctionListCleanup(state.source)
        _clear(runtime, state.cleanup, 'BD5330')
        state.phase = 'unlocking'
        if runtime.memory.load(state.owner + 8, 1):
            _srw(runtime, runtime.memory.load(state.owner, 8), False)
            state.lock_acquired = False
        runtime.memory.unmap(state.frame)
        state.phase = 'complete'
    except BaseException as error:
        state.failure = error
        raise


def take_function_batch(runtime, queue, destination):
    state = _operation(runtime, 0xBD5330, queue, destination)
    _take(runtime, state)


def run_mode2_batch(runtime, task, local_list):
    if not hasattr(runtime, 'worker_batch_states'):
        runtime.worker_batch_states = {}
    previous = runtime.worker_batch_states.get(task)
    if previous is not None and previous.phase not in ('complete', 'not_running'):
        raise PrimarySemanticUnavailable('physical worker batch retains unresolved ownership')
    state = PhysicalWorkerBatch(task, local_list)
    runtime.worker_batch_states[task] = state
    try:
        if not runtime.memory.load(task + 32, 1) & 1:
            state.phase = 'not_running'
            return state
        if runtime.memory.load(task + 0xD8, 4) != 2:
            raise PrimarySemanticUnavailable('physical batch step requires source task mode2')
        if type(local_list) is not int or task <= local_list + 23 and local_list < task + 0x104:
            raise InputError('physical batch requires a separate private List24 address')
        state.phase = 'initializing'
        runtime.memory.store(local_list, local_list, 8, source='BD4BB6.local_previous')
        runtime.memory.store(local_list + 8, local_list, 8, source='BD4BBA.local_next')
        runtime.memory.store(local_list + 16, 0, 8, source='BD4BBE.local_count')
        state.phase = 'transferring'
        state.transfer = _operation(runtime, 0xBD5330, task + 40, local_list)
        _take(runtime, state.transfer)
        state.phase = 'invoking'
        state.current_node = runtime.memory.load(local_list + 8, 8)
        seen = set()
        while state.current_node != local_list:
            node = state.current_node
            if node in seen or len(seen) >= 100000:
                raise PrimaryProgramLimit('physical worker batch does not reach its private sentinel')
            seen.add(node)
            state.active = state.target = 0
            state.call_pending = False
            if runtime.memory.load(task + 32, 1) & 1:
                state.active = runtime.memory.load(node + 48, 8)
                if not state.active:
                    raise PrimarySemanticUnavailable('BD4DB3 bad_function_call in physical worker batch')
                table = runtime.memory.load(state.active, 8)
                state.target = runtime.memory.load(table + 40, 8)
                state.call_pending = True
                from .primary_sign_lifecycle import device_request_call
                with device_request_call(runtime, state):
                    _invoke(runtime, state.target - runtime.image_base, state.active)
                state.call_pending = False
                state.invoked_nodes.append(node)
            else:
                state.skipped_nodes.append(node)
            state.current_node = runtime.memory.load(node + 8, 8)
        state.phase = 'cleanup'
        state.cleanup = FunctionListCleanup(local_list)
        _clear(runtime, state.cleanup, 'BD4C1B')
        state.phase = 'complete'
        runtime.events.append(('worker.physical_batch_complete', task, local_list,
                               tuple(state.invoked_nodes), tuple(state.skipped_nodes)))
        return state
    except BaseException as error:
        state.failure = error
        raise


def invoke(runtime, rva, values):
    if len(values) != 2:
        raise InputError('physical task batch source interface argument count mismatch')
    if rva == 0xBD5330:
        return take_function_batch(runtime, *values)
    if rva == 0xBD54F0:
        return move_function_list(runtime, *values)
    raise InputError('unknown physical task batch source interface')
