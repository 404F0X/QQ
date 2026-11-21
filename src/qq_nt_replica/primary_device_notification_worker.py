from contextlib import ExitStack

from .errors import InputError
from .primary_device_refresh import _StringVector
from .primary_logger import _String, feature, log
from .primary_memory import PrimaryMemoryLimit
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import _observe
from .primary_worker_loop import _ensure_logger, _initialize, _tick
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_SOURCE_FILE = bytes.fromhex('523a5c6465766f70735c776f726b73706163655c702d38323462373437353661643634653132383338363031636364653665636566625c706c6174666f726d735c57696e646f77735c6c696273656378785c656e76696e666f5c4f33436865636b456e7472792e637070')
_TAG = b'[FGESDK]'


def install_image(memory, image_base):
    for offset, size, name in ((0x677CE8C, 4, 'tick'), (0x677CEA0, 8, 'mutex'),
                               (0x677CEC0, 8, 'environment')):
        address = image_base + offset
        try:
            memory._span(address, size)
        except PrimaryMemoryLimit:
            memory.map(address, bytearray(size), name='fixed device notification fresh PE BSS ' + name, initialized=True)


def _environment(runtime):
    memory, base = runtime.memory, runtime.image_base
    mutex = base + 0x677CEA0
    if runtime.locks.get(mutex, 0):
        raise PrimarySemanticUnavailable('device notification environment waits on its owned mutex')
    runtime.locks[mutex] = 1
    runtime.events.append(('75AF50.lock', mutex))
    try:
        owner = memory.load(base + 0x677CEC0, 8)
        if not owner:
            owner = runtime._operator_new(0xE0)
            try:
                _invoke(runtime, 0x2E02AE0, owner)
            except BaseException:
                runtime._free_allocation(owner)
                raise
            memory.store(base + 0x677CEC0, owner, 8, source='1C21EF1.environment_publish')
        return owner
    finally:
        runtime.locks[mutex] = 0
        runtime.events.append(('75AFC0.unlock', mutex))


def _destroy_vector(runtime, address):
    _StringVector(runtime, address).destroy()


def _first_prefix(runtime):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x148, '1C21700.notification_frame')
    with ExitStack() as retained:
        retained.callback(memory.unmap, frame)
        owner = _environment(runtime)
        with ExitStack() as parent:
            _invoke(runtime, 0x2E031A0, owner, rbp + 0x20)
            parent.callback(_String.read(runtime, rbp + 0x20).destroy)
            _invoke(runtime, 0x2E09690, rbp + 0x40, rbp + 0x20)
            retained.callback(_String.read(runtime, rbp + 0x40).destroy)
        vector, copied = rbp + 0x20, rbp - 0x20
        memory.write(vector, bytes(24), source='1C21F31.empty_retained_vector')
        retained.callback(_destroy_vector, runtime, vector)
        _invoke(runtime, 0x48A5E, vector, rbp + 0x40)
        diagnostic = memory.load(base + 0x6751D88, 8)
        if not diagnostic:
            diagnostic = runtime._operator_new(24)
            memory.write(diagnostic, bytes(24), source='1C21F66.empty_diagnostic_owner')
            memory.store(base + 0x6751D88, diagnostic, 8, source='1C21F71.diagnostic_owner_publish')
        memory.write(copied, bytes(24), source='1C21F7B.empty_copied_vector')
        with ExitStack() as consumed:
            consumed.callback(_destroy_vector, runtime, copied)
            values = _StringVector(runtime, vector)
            size = values.end - values.begin
            if size:
                storage = runtime._operator_new(size)
                for offset, value in ((0, storage), (8, storage), (16, storage + size)):
                    memory.store(copied + offset, value, 8, source='1C21FC4.copied_vector_storage')
                for source in range(values.begin, values.end, 24):
                    destination = memory.load(copied + 8, 8)
                    _String.read(runtime, source).clone().write_to(destination)
                    memory.store(copied + 8, destination + 24, 8, source='1C22000.copied_vector_end')
            event = _String.construct(runtime, b'env')
            event.write_to(rbp - 0x38)
            consumed.callback(event.destroy)
            scene = _String.construct(runtime, b'login')
            scene.write_to(rbp - 0x50)
            consumed.callback(scene.destroy)
            _invoke(runtime, 0x1CF64E0, diagnostic, rbp - 0x50, rbp - 0x38, copied)
            consumed.pop_all()
        _invoke(runtime, 0x1D20B30)
        raise PrimarySemanticUnavailable('1C225D8 device notification next source call 2E09FD0 is not implemented')


def collect(runtime):
    memory, base = runtime.memory, runtime.image_base
    now = _tick(runtime)
    previous = memory.load(base + 0x677CE8C, 4)
    if previous and ((now - previous) & 0xFFFFFFFF) <= 0x36EE7F:
        log(runtime, _SOURCE_FILE, 198, b'frequency limit', _TAG, 1)
        return None
    memory.store(base + 0x677CE8C, now, 4, source='1C21ACF.notification_previous_tick')
    _initialize(runtime, 1)
    view = _invoke(runtime, 0x1BB9250, base + 0x67516B0)
    value = _String.read(runtime, view + 0xE0)
    length = value.get(8, 8) if value.get(0, 1) & 1 else value.get(0, 1) >> 1
    if length <= 2:
        log(runtime, _SOURCE_FILE, 202, b'uin empty', _TAG, 1)
        return None
    _ensure_logger(runtime)
    if feature(runtime, memory.load(base + 0x67516A8, 8), 22) != 1:
        log(runtime, _SOURCE_FILE, 224, b'ced end', _TAG, 1)
        return None
    log(runtime, _SOURCE_FILE, 207, b'ced allow', _TAG, 1)
    return _first_prefix(runtime)


def run(runtime, parameter):
    if type(parameter) is not int or not 0 <= parameter < 1 << 64:
        raise InputError('device notification callback requires its pointer-width source argument')
    before = _tick(runtime)
    result, effects = _observe(runtime, 'Sleep', parameter & 0xFFFFFFFF)
    if result is not None:
        raise InputError('device notification Sleep requires a void result')
    if effects is not None:
        if not isinstance(effects, tuple):
            raise InputError('device notification Sleep requires ordered raw memory effects')
        for effect in effects:
            if (not isinstance(effect, tuple) or len(effect) != 2 or type(effect[0]) is not int or
                    not 0 <= effect[0] < 1 << 64 or not isinstance(effect[1], bytes)):
                raise InputError('device notification Sleep effect requires an address and raw bytes')
            runtime.memory.write(effect[0], effect[1], source='Sleep.observed_memory_effect')
    _invoke(runtime, 0x1C21700)
    after = _tick(runtime)
    log(runtime, _SOURCE_FILE, 234, b'thread5=%u', _TAG, 1, (after - before) & 0xFFFFFFFF)
    return 1


def invoke(runtime, rva, values):
    if rva == 0x1C29910 and len(values) == 1:
        return run(runtime, values[0])
    if rva == 0x1C21700 and not values:
        return collect(runtime)
    if rva == 0x1BB9250 and len(values) == 1:
        return (values[0] + 0x28) & ((1 << 64) - 1)
    raise InputError('device notification source entry argument count mismatch')
