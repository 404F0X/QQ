from dataclasses import dataclass

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_thread_dispatch import _api
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


@dataclass(frozen=True)
class ModuleHandleOutput:
    data: bytes | None

    def __post_init__(self):
        if self.data is not None and (type(self.data) is not bytes or len(self.data) != 8):
            raise InputError('thread module output requires eight explicit bytes or explicit no-write')


def context(runtime, callback, argument):
    pointer = _invoke(runtime, 0x3EA0150, 1, 40)
    _invoke(runtime, 0x3EA01D0, 0)
    if not pointer:
        return 0
    memory, base = runtime.memory, runtime.image_base
    memory.store(pointer, callback, 8, source='3E817D5.CRT_thread_callback')
    memory.store(pointer + 8, argument, 8, source='3E817DB.CRT_thread_argument')
    target = runtime.worker_imports.get('GetModuleHandleExW')
    if target is None or memory.load(base + 0x490FF08, 8) != target:
        raise PrimarySemanticUnavailable('thread creation GetModuleHandleExW current import is not bound')
    if runtime.worker_observations is None:
        raise UnknownMemory('missing thread creation module observation')
    result, output = runtime.worker_observations.take(runtime, 'GetModuleHandleExW', (4, callback, pointer + 24))
    if type(result) is not int or not 0 <= result <= 0xFFFFFFFF or type(output) is not ModuleHandleOutput:
        raise InputError('thread module API requires a DWORD result and typed exact output effect')
    if output.data is not None:
        memory.write(pointer + 24, output.data, source='GetModuleHandleExW.observed_module')
    return pointer


def create(runtime, security, stacksize, callback, argument, flags, caller_tid, *, frame=None):
    if not callback:
        errno = _invoke(runtime, 0x3E84C9C)
        runtime.memory.store(errno, 0x16, 4, source='3E816D5.invalid_callback_errno')
        raise PrimarySemanticUnavailable('3E886D4 invalid-parameter machinery requires its source semantics')
    pointer = context(runtime, callback, argument)
    if not pointer:
        return 0
    owns_frame = frame is None
    if owns_frame:
        frame, unused = _frame(runtime, 0x80, '3E816B0.thread_frame')
    memory, base = runtime.memory, runtime.image_base
    memory.store(frame + 0x50, 0, 4, source='3E816FF.local_thread_id_zero')
    memory.store(frame + 0x28, frame + 0x50, 8, source='3E81708.local_thread_id_pointer')
    memory.store(frame + 0x20, flags, 4, source='3E81719.creation_flags_DWORD')
    raw_flags = memory.load(frame + 0x20, 8)
    target = runtime.create_thread_address
    if target is None or memory.load(base + 0x490FC80, 8) != target:
        raise PrimarySemanticUnavailable('thread creation CreateThread current import is not bound')
    handle = _invoke(runtime, target - base, security, stacksize & 0xFFFFFFFF,
                     base + 0x3E81800, pointer, raw_flags, frame + 0x50)
    if not handle:
        error = _api(runtime, 'GetLastError')
        _invoke(runtime, 0x3E84CE4, error)
        cleanup_context(runtime, pointer)
        if owns_frame:
            memory.unmap(frame)
        return 0
    if caller_tid:
        memory.store(caller_tid, memory.load(frame + 0x50, 4), 4,
                     source='3E81771.caller_thread_id_DWORD')
    runtime.events.append(('CRT.thread_created', pointer, handle))
    if owns_frame:
        memory.unmap(frame)
    return handle


def cleanup_context(runtime, pointer):
    handle = runtime.memory.load(pointer + 16, 8)
    if handle:
        _api(runtime, 'CloseHandle', handle)
    module = runtime.memory.load(pointer + 24, 8)
    if module:
        target = runtime.worker_imports.get('FreeLibrary')
        if target is None or runtime.memory.load(runtime.image_base + 0x490FD80, 8) != target:
            raise PrimarySemanticUnavailable('thread creation FreeLibrary current import is not bound')
        if runtime.worker_observations is None:
            raise UnknownMemory('missing thread creation FreeLibrary observation')
        result, effects = runtime.worker_observations.take(runtime, 'FreeLibrary', (module,))
        if type(result) is not int or not 0 <= result <= 0xFFFFFFFF or effects not in ((), b''):
            raise InputError('FreeLibrary requires a DWORD result and explicit no-output effect')
    _invoke(runtime, 0x3EA01D0, pointer)


def bridge_result(runtime, output, handle):
    runtime.memory.store(output, handle, 8, source='787975.thread_handle')
    return 0 if handle else _api(runtime, 'GetLastError')


def bridge(runtime, output, callback, argument):
    pair = runtime._operator_new(16)
    runtime.memory.store(pair, callback, 8, source='78794A.thread_callback')
    runtime.memory.store(pair + 8, argument, 8, source='78794D.thread_argument')
    frame, unused = _frame(runtime, 0xA0, '787930.thread_frame')
    runtime.memory.store(frame + 0x60, 0, 4, source='78795A.creation_flags_DWORD')
    runtime.memory.store(frame + 0x68, 0, 8, source='787951.optional_caller_tid_pointer')
    handle = create(runtime, 0, 0, runtime.image_base + 0x7879A0, pair,
                    runtime.memory.load(frame + 0x60, 4),
                    runtime.memory.load(frame + 0x68, 8), frame=frame)
    result = bridge_result(runtime, output, handle)
    runtime.memory.unmap(frame)
    return result


def invoke(runtime, rva, values):
    entries = {0x3E816B0: (create, 6), 0x3E8179C: (context, 2), 0x787930: (bridge, 3)}
    function, count = entries[rva]
    if len(values) != count:
        raise InputError('thread creation source ABI argument count mismatch')
    return function(runtime, *values)
