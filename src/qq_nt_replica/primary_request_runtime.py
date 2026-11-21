from dataclasses import dataclass

from .errors import InputError
from .primary_cocos import next_mt, seed_mt
from .primary_logger import _String
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
from .wire import check_length, require_uint


_U64 = (1 << 64) - 1


@dataclass(frozen=True)
class RequestEntropyObservation:
    result: int
    output: bytes | None = None

    def __post_init__(self):
        require_uint(self.result, 64, 'request system entropy result')
        if self.output is not None and (not isinstance(self.output, bytes) or len(self.output) > 4):
            raise InputError('request system entropy requires at most four observed output bytes')


def install_image(memory, image_base):
    from .primary_response_diagnostics import install_image as install_diagnostics_image
    from .primary_request_startup import install_image as install_startup_image
    install_diagnostics_image(memory, image_base)
    install_startup_image(memory, image_base)
    memory.map(image_base + 0x677D030, bytearray(24), name='request status tree PE zero fill', initialized=True)
    memory.map(image_base + 0x677D048, bytearray(0x118), name='request encoder PE zero fill', initialized=True)
    memory.map(image_base + 0x677C2CC, bytearray(0x9D4), name='request global MT PE zero fill', initialized=True)
    memory.map(image_base + 0x73940F8, bytearray(8), name='CRT random import PE zero fill', initialized=True)


def _count(count):
    require_uint(count, 64, 'native request random byte count')
    check_length(count, 'native request random byte count')


def _entropy(runtime, destination):
    address = runtime.memory.load(runtime.image_base + 0x73940F8, 8)
    if not address or address == _U64 or address != runtime.worker_imports.get('SystemFunction036'):
        raise PrimarySemanticUnavailable('3EA19EC current SystemFunction036 resolver state remains unavailable')
    observed = runtime._next(runtime._entropy, 'SystemFunction036(4)')
    if isinstance(observed, bytes) and len(observed) == 4:
        observed = RequestEntropyObservation(1, observed)
    if not isinstance(observed, RequestEntropyObservation):
        raise InputError('request system entropy requires raw result and output observations')
    if observed.output:
        runtime.memory.write(destination, observed.output, source='3EA19EC.SystemFunction036_output')
    return observed.result


def random_s(runtime, destination):
    if not destination:
        pointer = _invoke(runtime, 0x3E84C9C)
        runtime.memory.store(pointer, 22, 4, source='3E9902A.random_invalid_argument')
        raise PrimarySemanticUnavailable('3E886D4 random_s invalid-parameter handler remains unavailable')
    runtime.memory.store(destination, 0, 4, source='3E9903C.random_output_zero')
    if _entropy(runtime, destination) & 255:
        return 0
    pointer = _invoke(runtime, 0x3E84C9C)
    runtime.memory.store(pointer, 12, 4, source='3E99052.random_failure_errno')
    return runtime.memory.load(_invoke(runtime, 0x3E84C9C), 4)


def system_word(runtime, receiver):
    frame, _ = _frame(runtime, 0x30, '7603B0.random_device_frame')
    result = random_s(runtime, frame + 0x24)
    if result:
        runtime.events.append(('request.random_device_exception_pending', result))
        raise PrimarySemanticUnavailable('7603EB random-device system_error construction and unwinding remain unavailable')
    value = runtime.memory.load(frame + 0x24, 4)
    runtime.memory.unmap(frame)
    return value


def construct_device(runtime, receiver, token):
    value = _String.read(runtime, token)
    size = value.get(8, 8) if value.get(0, 1) & 1 else value.get(0, 1) >> 1
    if size != 12 or value.value() != b'/dev/urandom':
        raise PrimarySemanticUnavailable('760330 alternate random-device token requires the original exception path')
    return receiver


def clock_bytes(runtime, destination, count):
    _count(count)
    frame, _ = _frame(runtime, 0xA00, '1C54C00.clock_random_frame')
    _invoke(runtime, 0x759B30, frame + 0x28)
    seed_mt(runtime.memory, frame + 0x30, runtime.memory.load(frame + 0x28, 4))
    value = next_mt(runtime.memory, frame + 0x30)
    for index in range(count):
        runtime.memory.store(destination + index, value >> (8 * (index & 3)), 1,
                             source='1C54D24.clock_random_byte')
        if index & 3 == 3:
            value = next_mt(runtime.memory, frame + 0x30)
    runtime.memory.unmap(frame)
    return None


def mixed_bytes(runtime, destination, count):
    _count(count)
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x28, '1C54E10.device_random_frame')
    capacity = (count + 15) & ~15
    first = _frame(runtime, capacity, '1C54E10.first_clock_buffer')[0] if capacity else frame
    clock_bytes(runtime, first, count)
    guard = memory.load(base + 0x677D08C, 4)
    if not guard & 1:
        memory.store(base + 0x677D08C, guard | 1, 4, source='1C55059.random_device_guard')
        _String.construct(runtime, b'/dev/urandom').write_to(frame + 8)
        construct_device(runtime, base + 0x677D088, frame + 8)
        _invoke(runtime, 0x3E680B4, base + 0x1C55120)
    value = system_word(runtime, base + 0x677D088)
    for index in range(count):
        memory.store(destination + index, value >> (8 * (index & 3)), 1,
                     source='1C54EA9.system_random_byte')
        if index & 3 == 3:
            value = system_word(runtime, base + 0x677D088)
    second = _frame(runtime, capacity, '1C54E10.second_clock_buffer')[0] if capacity else frame
    clock_bytes(runtime, second, count)
    for index in range(count):
        value = memory.load(destination + index, 1) ^ memory.load(first + index, 1) ^ memory.load(second + index, 1)
        memory.store(destination + index, value, 1, source='1C5502B.device_random_xor')
    if capacity:
        memory.unmap(second)
        memory.unmap(first)
    memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    if rva == 0x3E9901C and len(values) == 1:
        return random_s(runtime, *values)
    if rva == 0x7603B0 and len(values) == 1:
        return system_word(runtime, *values)
    if rva == 0x7602D0 and len(values) == 2:
        return construct_device(runtime, *values)
    if rva == 0x1C54C00 and len(values) == 2:
        return clock_bytes(runtime, *values)
    if rva == 0x1C54E10 and len(values) == 2:
        return mixed_bytes(runtime, *values)
    if rva == 0x1C55120 and not values:
        return _invoke(runtime, 0x28F0, runtime.image_base + 0x677D088)
    raise InputError('unsupported request random-runtime entry or argument count')
