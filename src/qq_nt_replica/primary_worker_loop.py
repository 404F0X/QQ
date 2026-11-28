import hashlib
from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace

from .errors import InputError
from .primary_logger import _decode, _srw, construct, log
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import _observe, construct_context, refresh_context


_MASK64 = (1 << 64) - 1
_IMAGE_SHA256 = 'bdc753f16f405be14eff150e9ee8f5aeb5c5a373546115e3a141a9e399c72661'


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'worker-loop-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed worker loop image identity mismatch')
    return json.loads(raw)


def install_image(memory, image_base):
    region = _image()['zero_fill']
    memory.map(image_base + region['rva'], bytearray(region['size']),
               name='fixed worker shared-state PE zero fill', initialized=True)


def _invoke(runtime, rva, *values):
    vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    return runtime.invoke(vm, rva, tuple(range(len(values))))


def _signed(value):
    value &= _MASK64
    return value - (1 << 64) if value >> 63 else value


def _initialize(runtime, index):
    memory, base = runtime.memory, runtime.image_base
    definition = _image()['initializers'][index]
    guard = base + definition['guard_rva']
    value = memory.load(guard, 4)
    if value & 1:
        return
    memory.store(guard, value | 1, 4, source='1C1BB80.shared_guard_publish')
    for operation in definition['operations']:
        memory.write(base + operation['rva'], bytes.fromhex(operation['hex']),
                     source=f"{operation['instruction_rva']:X}.shared_initializer")
    _invoke(runtime, 0x3E680B4, base + definition['exit_callback_rva'])


def _ensure_logger(runtime):
    memory, base = runtime.memory, runtime.image_base
    pointer = memory.load(base + 0x67516A8, 8)
    if not pointer:
        pointer = runtime._operator_new(120)
        construct(runtime, pointer)
        memory.store(base + 0x67516A8, pointer, 8, source='1C1BD4D.logger_publish')


def _message(runtime, name, line, severity, *arguments):
    image = _image()
    value = image['logs'][name]
    return log(runtime, _decode(value['file']), line, _decode(value['format']),
               bytes.fromhex(image['tag_hex']), severity, *arguments)


def _tick(runtime):
    result, effects = _observe(runtime, 'GetTickCount')
    if result > 0xFFFFFFFF or not (effects is None or type(effects) is bytes and not effects):
        raise InputError('GetTickCount requires an observed DWORD and no output-buffer effects')
    return result


def _sleep(runtime, target):
    expected = runtime.worker_imports.get('Sleep')
    if expected is None or target != expected:
        raise PrimarySemanticUnavailable('worker captured Sleep import is not bound')
    if runtime.worker_observations is None:
        from .primary_memory import UnknownMemory
        raise UnknownMemory('missing SDK worker environment observations: Sleep')
    _, effects = runtime.worker_observations.take(runtime, 'Sleep', (1,))
    if effects is None:
        return
    if not isinstance(effects, tuple):
        raise InputError('Sleep requires an ordered tuple of observed memory effects')
    for effect in effects:
        if (not isinstance(effect, tuple) or len(effect) != 2 or type(effect[0]) is not int or
                not 0 <= effect[0] <= _MASK64 or not isinstance(effect[1], bytes)):
            raise InputError('Sleep effect requires an unsigned address and raw bytes')
        runtime.memory.write(effect[0], effect[1], source='Sleep.observed_memory_effect')


def empty_cache(runtime, pointer):
    value = runtime.memory.load(pointer + 0x20, 4)
    return (value & 0xFFFFFF00) | int(value == 0)


def run(runtime, parameter):
    memory, base = runtime.memory, runtime.image_base
    started = _tick(runtime)
    for rva in (0x1BF75A0, 0x1BF8090):
        for arguments in ((1, 2, 1, 0), (_MASK64 - 3, 0, 3, 1), (0, 0, 2, 1)):
            _invoke(runtime, rva, *arguments)
    context = memory.load(base + 0x677CEF8, 8)
    if not context:
        context = runtime._operator_new(248)
        construct_context(runtime, context)
        memory.store(base + 0x677CEF8, context, 8, source='1C1BC5F.context_publish')
    scope = runtime.__dict__.get('_primary_direct_scope')
    refresh_domain = scope.worker_refresh(context) if scope is not None and scope.worker_owner is not None else nullcontext()
    with refresh_domain:
        refresh_context(runtime, context)
    sleep_target = memory.load(base + 0x4910368, 8)
    count = 0
    while True:
        provider = memory.load(base + 0x677BDD8, 8)
        runtime.events.append(('worker.configuration_poll', count, provider))
        if count >= 10 or provider:
            break
        _sleep(runtime, sleep_target)
        count += 1
    _ensure_logger(runtime)
    _initialize(runtime, 0)
    lock = base + 0x67519A8
    _srw(runtime, lock, True)
    _initialize(runtime, 1)
    if empty_cache(runtime, base + 0x67516B0) & 255:
        _message(runtime, 'empty', 0x104, 2)
    else:
        now = _invoke(runtime, 0x3E8ED3C, 0)
        claimed = memory.load(base + 0x67518A0, 1)
        memory.store(base + 0x67518A0, 1 if not claimed else claimed, 1, source='1C1C29E.claim_cmpxchg')
        if not claimed:
            deferred = False
            retries = memory.load(base + 0x67518A4, 4)
            interval = memory.load(base + 0x6751900, 8)
            threshold = ((1 << (retries % 5)) * interval) & _MASK64
            elapsed = (now - memory.load(base + 0x67518A8, 8)) & _MASK64
            if _signed(elapsed) >= _signed(threshold):
                _message(runtime, 'frequency', 0x10D, 2, 1, 0)
                memory.store(base + 0x67518A8, _invoke(runtime, 0x3E8ED3C, 0), 8,
                             source='1C1C892.refresh_timestamp')
                device = memory.load(base + 0x6751840, 8)
                control = memory.load(base + 0x6751848, 8)
                if control:
                    value = (memory.load(control + 8, 4) + 1) & 0xFFFFFFFF
                    memory.store(control + 8, value, 4, source='1C1C8AC.control_retain')
                    memory.store(control + 8, (value - 1) & 0xFFFFFFFF, 4, source='1C1C8B6.control_release')
                    if value == 0:
                        raise PrimarySemanticUnavailable('1C1C8BF shared-control destructor target/effects are unavailable')
                if device:
                    from .primary_worker_tasks import enqueue_device_worker
                    enqueue_device_worker(runtime)
                    deferred = True
                else:
                    _message(runtime, 'null_device', 0x1CD, 2)
            if not deferred:
                memory.store(base + 0x67518A0, 0, 1, source='1C1CF2D.claim_release')
    _srw(runtime, lock, False)
    elapsed = (_tick(runtime) - started) & 0xFFFFFFFF
    _message(runtime, 'duration', 0x91, 1, elapsed)
    return 0


def invoke(runtime, rva, values):
    if len(values) != 1:
        raise InputError('worker loop source interface takes one argument')
    if rva == 0x1C1BB80:
        return run(runtime, values[0])
    if rva == 0x1BE2F80:
        return empty_cache(runtime, values[0])
    raise InputError('unknown worker loop source interface')
