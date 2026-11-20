from .errors import InputError
from .primary_logger import _srw
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke


_MASK64 = (1 << 64) - 1
_IMPORTS = {'FlsAlloc': 0x490FD38, 'FlsGetValue': 0x490FD48, 'FlsSetValue': 0x490FD50,
    'GetLastError': 0x490FEA8, 'SetLastError': 0x4910330, 'CloseHandle': 0x490FBD8,
    'ExitThread': 0x490FCE8, 'FreeLibraryAndExitThread': 0x490FD88,
    'WakeAllConditionVariable': 0x4910450,
    'EnterCriticalSection': 0x490FCD0, 'LeaveCriticalSection': 0x4910168}
_VOID = ('SetLastError', 'ExitThread', 'FreeLibraryAndExitThread', 'WakeAllConditionVariable',
    'EnterCriticalSection', 'LeaveCriticalSection')


class ThreadTerminated(Exception):
    def __init__(self, name, arguments):
        self.api = name
        self.arguments = arguments
        super().__init__(name, arguments)


def install_image(memory, base):
    from .primary_crt_thread import install_image as install_crt_image

    install_crt_image(memory, base)
    memory.map(base + 0x674D4E8, bytearray(8), name='fixed thread FLS index and guard zero fill', initialized=True)


def _api(runtime, name, *arguments):
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
        raise PrimarySemanticUnavailable('thread dispatch current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing thread dispatch system observation: ' + name)
    result, effects = runtime.worker_observations.take(runtime, name, arguments)
    if effects not in ((), b''):
        raise InputError('thread dispatch API requires no output-buffer effects: ' + name)
    if name in _VOID:
        if result is not None:
            raise InputError('thread dispatch API requires a void result: ' + name)
    elif type(result) is not int or not 0 <= result <= (_MASK64 if name == 'FlsGetValue' else 0xFFFFFFFF):
        raise InputError('thread dispatch API result is outside its unsigned domain: ' + name)
    return result


def allocate_index(runtime, output, callback):
    index = _api(runtime, 'FlsAlloc', callback)
    if index == 0xFFFFFFFF:
        return _api(runtime, 'GetLastError')
    runtime.memory.store(output, index, 4, source='787AC6.thread_FLS_index')
    return 0


def index(runtime):
    memory, base = runtime.memory, runtime.image_base
    guard = base + 0x674D4EC
    if memory.load(guard, 4, signed=True) > memory.load(runtime.tls_epoch_address, 4, signed=True):
        runtime._thread_header(guard)
        if memory.load(guard, 4, signed=True) == -1:
            construct_index(runtime, base + 0x674D4E8)
            _invoke(runtime, 0x3E680B4, base + 0x28F0)
            runtime._thread_footer(guard)
    return base + 0x674D4E8


def construct_index(runtime, output):
    error = allocate_index(runtime, output, runtime.image_base + 0x760280)
    if error:
        raise PrimarySemanticUnavailable('760131 thread FLS allocation requires its original system-error exception: ' + str(error))
    return output


def set_value(runtime, identifier, value):
    return 0 if _api(runtime, 'FlsSetValue', identifier & 0xFFFFFFFF, value) else _api(runtime, 'GetLastError')


def current(runtime):
    if getattr(runtime, 'crt_startup_observations', None) is not None:
        from .primary_crt_startup import current as source_current
        return runtime._crt_call(source_current)
    return _fallback_current(runtime)


def _fallback_current(runtime):
    memory, base = runtime.memory, runtime.image_base
    direct = memory.load(base + 0x6D8E968, 1)
    if direct:
        raise PrimarySemanticUnavailable('3EA141C current CRT direct FLS getter requires its initialized cached API binding')
    error = _api(runtime, 'GetLastError')
    identifier = memory.load(base + 0x6744470, 4)
    value = 0 if identifier == 0xFFFFFFFF else _api(runtime, 'FlsGetValue', identifier)
    if value == _MASK64:
        value = 0
    elif not value:
        from .primary_crt_thread import create

        value = create(runtime)
    _api(runtime, 'SetLastError', error)
    return value


def require_current(runtime):
    pointer = current(runtime)
    if not pointer:
        raise PrimarySemanticUnavailable('3EA0B43 missing current CRT data requires its original abort')
    return pointer


def virtual_entry(runtime, state):
    target = runtime.memory.load(runtime.memory.load(state, 8) + 16, 8)
    return _invoke(runtime, target - runtime.image_base, state)


def tuple_entry(runtime, control):
    memory, base = runtime.memory, runtime.image_base
    slot = index(runtime)
    holder = memory.load(control, 8)
    memory.store(control, 0, 8, source='BD55E4.thread_holder_transferred_to_FLS')
    set_value(runtime, memory.load(slot, 4), holder)
    target = memory.load(control + 8, 8)
    _invoke(runtime, target - base, memory.load(control + 16, 8))
    holder = memory.load(control, 8)
    memory.store(control, 0, 8, source='BD5604.thread_tuple_holder_clear')
    if holder:
        destroy_holder_state(runtime, holder)
        runtime._free_allocation(holder)
    runtime._free_allocation(control)
    return 0


def adapter(runtime, start):
    memory = runtime.memory
    target, argument = memory.load(start, 8), memory.load(start + 8, 8)
    if start:
        runtime._free_allocation(start)
    previous = getattr(runtime, '_crt_dispatch_active', False)
    runtime._crt_dispatch_active = True
    try:
        return _invoke(runtime, target - runtime.image_base, argument)
    finally:
        runtime._crt_dispatch_active = previous


def satisfy_at_exit(runtime, state):
    memory = runtime.memory
    _srw(runtime, state + 32, True)
    memory.store(state + 48, memory.load(state + 48, 1) | 4, 1, source='D46A75.thread_exit_future_ready')
    _api(runtime, 'WakeAllConditionVariable', state + 40)
    _srw(runtime, state + 32, False)


def _range(begin, end, stride):
    if end < begin or (end - begin) % stride or end - begin > stride * 100000:
        raise PrimaryProgramLimit('thread exit vector is outside its bounded source layout')
    return range(begin, end, stride)


def destroy_state(runtime, state):
    memory = runtime.memory
    for item in _range(memory.load(state + 24, 8), memory.load(state + 32, 8), 16):
        _srw(runtime, memory.load(item + 8, 8), False)
        _api(runtime, 'WakeAllConditionVariable', memory.load(item, 8))
    for item in _range(memory.load(state, 8), memory.load(state + 8, 8), 8):
        active = memory.load(item, 8)
        satisfy_at_exit(runtime, active)
        previous = memory.load(active + 8, 4)
        memory.store(active + 8, (previous - 1) & 0xFFFFFFFF, 4, source='7601B9.thread_exit_owner_release')
        if not previous:
            target = memory.load(memory.load(active, 8) + 8, 8)
            _invoke(runtime, target - runtime.image_base, active)
    pairs = memory.load(state + 24, 8)
    if pairs:
        memory.store(state + 32, pairs, 8, source='7601D3.thread_exit_notification_vector_reset')
        runtime._free_allocation(pairs)
    owners = memory.load(state, 8)
    if owners:
        memory.store(state + 8, owners, 8, source='7601E4.thread_exit_owner_vector_reset')
        runtime._free_allocation(owners)


def destroy_holder_state(runtime, holder):
    state = runtime.memory.load(holder, 8)
    if state:
        destroy_state(runtime, state)
        runtime._free_allocation(state)


def fls_cleanup(runtime, holder):
    if holder:
        destroy_holder_state(runtime, holder)
        runtime._free_allocation(holder)


def terminate(runtime, name, *arguments):
    _api(runtime, name, *arguments)
    raise ThreadTerminated(name, arguments)


def end_thread(runtime, code):
    memory = runtime.memory
    code &= 0xFFFFFFFF
    pointer = current(runtime)
    if pointer:
        context = memory.load(pointer + 0x3C0, 8)
        if context:
            if memory.load(context + 32, 1):
                _invoke(runtime, 0x3EA19A8)
            handle = memory.load(context + 16, 8)
            if handle not in (0, _MASK64):
                _api(runtime, 'CloseHandle', handle)
            module = memory.load(context + 24, 8)
            if module not in (0, _MASK64):
                terminate(runtime, 'FreeLibraryAndExitThread', module, code)
    terminate(runtime, 'ExitThread', code)


def crt_entry(runtime, context):
    if not context:
        terminate(runtime, 'ExitThread', _api(runtime, 'GetLastError'))
    memory, base = runtime.memory, runtime.image_base
    previous = getattr(runtime, '_crt_dispatch_active', False)
    runtime._crt_dispatch_active = True
    try:
        pointer = require_current(runtime)
        memory.store(pointer + 0x3C0, context, 8, source='3E81822.current_CRT_thread_context')
        application = _invoke(runtime, 0x3EA4B68)
        if application == 2:
            result = _invoke(runtime, 0x3EA1958, 1)
            memory.store(context + 32, int(result & 0xFFFFFFFF == 0), 1, source='3E81840.thread_runtime_initialized')
        target = memory.load(context, 8)
        code = _invoke(runtime, target - base, memory.load(context + 8, 8))
        end_thread(runtime, code)
    finally:
        runtime._crt_dispatch_active = previous


def invoke(runtime, rva, values):
    entries = {0x760060: (index, 0), 0x787AB0: (allocate_index, 2), 0x760110: (construct_index, 1),
        0x787AE0: (set_value, 2), 0x36E0: (virtual_entry, 1), 0xBD55C0: (tuple_entry, 1),
        0x7879A0: (adapter, 1), 0x760140: (destroy_state, 1), 0x760250: (destroy_holder_state, 1),
        0x760280: (fls_cleanup, 1), 0xD46A60: (satisfy_at_exit, 1),
        0x3EA0B90: (current, 0), 0x3EA0B30: (require_current, 0),
        0x3E81800: (crt_entry, 1), 0x3E81790: (end_thread, 1), 0x3E81868: (end_thread, 1)}
    entry, count = entries.get(rva, (None, None))
    if entry is None or len(values) != count:
        raise InputError('unsupported thread dispatch entry or argument count')
    return entry(runtime, *values)
