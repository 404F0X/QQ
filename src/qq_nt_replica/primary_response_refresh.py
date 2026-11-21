from dataclasses import dataclass
from types import SimpleNamespace

from .errors import InputError
from .primary_logger import _String, feature, log, _decode
from .primary_material import _RuntimeResponseMaterial
from .primary_vm import PrimarySemanticUnavailable


_MASK64 = (1 << 64) - 1


def _signed(value):
    value &= _MASK64
    return value - (1 << 64) if value >> 63 else value


def _invoke(runtime, rva, *values):
    vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    return runtime.invoke(vm, rva, tuple(range(len(values))))


def _clock(runtime, now):
    value = _invoke(runtime, 0x3E8ED3C, 0) if now is None else now() if callable(now) else now
    if type(value) is not int or not -(1 << 63) <= value < 1 << 63:
        raise InputError('response refresh requires signed64 Unix seconds')
    runtime.events.append(('response.clock', value))
    return value


@dataclass
class Snapshot:
    expiry: int
    value: _String
    bound: _String

    @classmethod
    def read(cls, runtime, address):
        expiry = runtime.memory.load(address, 8, signed=True)
        value = _String.read(runtime, address + 8)
        bound = _String.read(runtime, address + 32)
        return cls(expiry, value, bound)

    @classmethod
    def capture(cls, runtime, cache):
        expiry = cache.expiry
        if isinstance(cache, _RuntimeResponseMaterial):
            value = _String.read(runtime, cache.address + 24).clone()
            bound = _String.read(runtime, cache.address + 48).clone()
        else:
            value = _String.construct(runtime, cache.value)
            bound = _String.construct(runtime, cache.bound)
        return cls(expiry, value, bound)

    def clone(self):
        return Snapshot(self.expiry, self.value.clone(), self.bound.clone())

    def destroy(self):
        self.bound.destroy()
        self.value.destroy()


def expired(runtime, snapshot, now=None):
    try:
        if not snapshot.value.value():
            return True
        result = snapshot.expiry <= _clock(runtime, now)
        if result:
            _predicate_message(runtime, 0xA4, b'getToken expire')
        return result
    finally:
        snapshot.destroy()


def refresh_needed(runtime, snapshot, now=None):
    try:
        delta = _signed(snapshot.expiry - _clock(runtime, now))
        threshold = runtime.memory.load(runtime.image_base + 0x67518F8, 8, signed=True)
        if delta < threshold:
            _predicate_message(runtime, 0xAE, b'getToken 5 expire')
            return True
        from .primary_worker_loop import _initialize
        _initialize(runtime, 1)
        current = _String.read(runtime, runtime.image_base + 0x67516B8).clone()
        runtime.events.append(('response.bound_getter', runtime.image_base + 0x67516B0))
        try:
            value = current.value()
            return value not in (b'', b'0') and value != snapshot.bound.value()
        finally:
            current.destroy()
    finally:
        snapshot.destroy()


def _predicate_message(runtime, line, message):
    from .primary_worker_loop import _image
    image = _image()
    runtime.events.append(('response.predicate_log', line))
    return log(runtime, _decode(image['logs']['empty']['file']), line, message,
               bytes.fromhex(image['tag_hex']), 1)


def _retain(runtime, control):
    if control:
        count = (runtime.memory.load(control + 8, 4) + 1) & 0xFFFFFFFF
        runtime.memory.store(control + 8, count, 4, source='response_refresh.control_retain')


def _release(runtime, control):
    if control:
        count = runtime.memory.load(control + 8, 4)
        runtime.memory.store(control + 8, (count - 1) & 0xFFFFFFFF, 4,
                             source='response_refresh.control_release')
        if count == 0:
            target = runtime.memory.load(runtime.memory.load(control, 8) + 8, 8)
            _invoke(runtime, target - runtime.image_base, control)
            _invoke(runtime, 0x75AD90, control)


def _synchronous(runtime):
    from .primary_worker_consumer import DeviceRecordsBinding, _destroy_tree, _image, consume_records
    memory, base = runtime.memory, runtime.image_base
    size, frame, initial = runtime._next(runtime._temporaries, 'response refresh private frame', 0x298)
    if size != 0x298 or type(frame) is not int or not 0 < frame <= _MASK64 - size:
        raise InputError('response refresh requires its explicit private frame address and size')
    if initial is not None and (not isinstance(initial, bytes) or len(initial) != size):
        raise InputError('response refresh frame requires complete raw bytes or unknown storage')
    memory.map(frame, bytearray(size) if initial is None else bytearray(initial),
               name='response_refresh.private_frame', initialized=initial is not None)
    rbp = frame + 0x80
    source_map = rbp + 0x80
    memory.store(source_map, source_map + 8, 8, source='response_refresh.records_begin')
    memory.write(source_map + 8, bytes(16), source='response_refresh.records_root_count')
    device, control = memory.load(base + 0x6751840, 8), memory.load(base + 0x6751848, 8)
    _retain(runtime, control)
    target = memory.load(memory.load(device, 8) + 64, 8)
    if target == base + 0xBEE3C0:
        status = _invoke(runtime, 0xBEE3C0, device, source_map)
    else:
        binding = runtime.worker_device_records
        if not isinstance(binding, DeviceRecordsBinding) or binding.address != target:
            raise PrimarySemanticUnavailable('response refresh actual device vtable+40 target and record effects are not bound')
        status = binding.invoke(runtime, device, source_map)
    _release(runtime, control)
    if status:
        image = _image()
        log(runtime, _decode(image['file']), 0x202, _decode(image['device_error']), base + 0x48972C7, 2, status)
    elif memory.load(source_map + 16, 8):
        consume_records(runtime, base + 0x6751840, source_map, rbp, caller='sign')
    memory.store(base + 0x67518A0, 0, 1, source='response_refresh.claim_release')
    _destroy_tree(runtime, source_map)
    memory.unmap(frame)


def refresh(runtime, now=None):
    from .primary_worker_loop import _initialize, _message
    from .primary_worker_consumer import _logger
    memory, base = runtime.memory, runtime.image_base
    lock = base + 0x67519A8
    if runtime.locks.get(lock, 0):
        raise PrimarySemanticUnavailable('response refresh waits on an owned mutex')
    runtime.locks[lock] = 1
    runtime.events.append(('75AF50.lock', lock))
    _initialize(runtime, 1)
    if memory.load(base + 0x67516D0, 4) == 0:
        _message(runtime, 'empty', 0x104, 2)
    else:
        current = _clock(runtime, now)
        busy = memory.load(base + 0x67518A0, 1)
        memory.store(base + 0x67518A0, busy if busy else 1, 1, source='response_refresh.claim_cmpxchg')
        if not busy:
            retries = memory.load(base + 0x67518A4, 4)
            interval = memory.load(base + 0x6751900, 8)
            threshold = _signed((1 << (retries % 5)) * interval)
            elapsed = _signed(current - memory.load(base + 0x67518A8, 8))
            if elapsed < threshold:
                memory.store(base + 0x67518A0, 0, 1, source='response_refresh.backoff_release')
            else:
                _message(runtime, 'frequency', 0x10D, 2, 1, 0)
                memory.store(base + 0x67518A8, _clock(runtime, now), 8, source='response_refresh.timestamp')
                device, control = memory.load(base + 0x6751840, 8), memory.load(base + 0x6751848, 8)
                _retain(runtime, control)
                _release(runtime, control)
                if not device:
                    _message(runtime, 'null_device', 0x1CD, 2)
                    memory.store(base + 0x67518A0, 0, 1, source='response_refresh.null_release')
                elif feature(runtime, _logger(runtime), 0x25) == 1:
                    from .primary_worker_tasks import _Function, _enqueue, device_task
                    _enqueue(runtime, device_task(runtime), _Function(base + 0x6751840))
                else:
                    _synchronous(runtime)
    runtime.locks[lock] = 0
    runtime.events.append(('75AFC0.unlock', lock))


def signing_value(runtime, cache, fallback, features, now=None):
    if features.get(1, 2) != 1:
        _predicate_message(runtime, 0xC2, b'getToken switch is close')
        return fallback
    saved = Snapshot.capture(runtime, cache)
    try:
        if expired(runtime, saved.clone(), now):
            refresh(runtime, now)
            return fallback
        if refresh_needed(runtime, saved.clone(), now):
            refresh(runtime, now)
        return saved.value.value()
    finally:
        saved.destroy()
