import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _String, _srw
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_loop import _initialize
from .primary_worker_response import _assign, _frame, _image as _response_image, _owner


_IMAGE_SHA256 = '9c5ce7f6df0f59efc2ff9a6bf5890702115b5514692e2767b8f384fbf4d3d9a9'


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'request-audit-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed request audit image identity mismatch')
    return json.loads(raw)


def install_image(memory, base):
    image = _image()
    for segment in image['segments']:
        raw = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            value = int.from_bytes(raw[offset:offset + 8], 'little')
            raw[offset:offset + 8] = (value - image['image_base'] + base).to_bytes(8, 'little')
        address = base + segment['rva']
        if any(region.address <= address and address + len(raw) <= region.address + len(region.data)
               for region in memory._regions):
            if memory.read(address, len(raw)) != raw:
                raise InputError('request audit image overlaps different source bytes')
        else:
            memory.map(address, raw, name='fixed request audit source image', initialized=True)
    from .primary_request_submit import install_image as install_submit_image
    install_submit_image(memory, base)


def begin(runtime):
    memory, base = runtime.memory, runtime.image_base
    pointer = memory.load(base + 0x6751B38, 8)
    if not pointer:
        pointer = runtime._operator_new(72)
        memory.write(pointer, bytes(72), source='1CE9986.request_log_state_initialization')
        for offset, value, size in ((4, 3, 4), (8, 3, 4), (32, pointer + 40, 8), (56, 1, 1), (64, 2, 2)):
            memory.store(pointer + offset, value, size, source='1CE99A0.request_log_state_defaults')
        memory.store(base + 0x6751B38, pointer, 8, source='1CE99E8.request_log_state_publish')
    memory.store(pointer + 56, 0, 1, source='1CE99F3.request_log_state_success')
    memory.store(pointer + 64, memory.load(pointer + 64, 2) & 0xFFFD, 2,
                 source='1CE99F7.request_log_state_clear_transport_failure')
    from .primary_request_audit_scope import request_audit_begin
    with request_audit_begin(runtime) as claim:
        for rva in (0x1BF75A0, 0x1BF8090):
            if claim is None:
                _invoke(runtime, rva, 1, 9, 1, 1)
            else:
                with claim.step(rva):
                    _invoke(runtime, rva, 1, 9, 1, 1)


def construct(runtime, address):
    memory, base = runtime.memory, runtime.image_base
    memory.store(address, base + 0x4148CD8, 8, source='1CE9C25.request_event_vtable')
    _String.construct(runtime, bytes.fromhex(_image()['event_name_hex'])).write_to(address + 8)
    for offset in range(32, 200, 24):
        _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(address + offset)
    memory.write(address + 200, bytes(192), source='1CE9BD4.request_event_columns_initialization')


def annotate(runtime, event, command_index, tag):
    if command_index is not None:
        _String.construct(runtime, bytes.fromhex(_image()['labels'][command_index]['hex'])).write_to(event + 248)
    _String.construct(runtime, tag).write_to(event + 272)


def _metadata(runtime):
    memory, base = runtime.memory, runtime.image_base
    _initialize(runtime, 1)
    metadata(runtime, base + 0x67516B0, memory.load(base + 0x677DE28, 8), memory.load(base + 0x677DE30, 8))


def metadata(runtime, config, first, second):
    _srw(runtime, config + 0x120, True)
    for offset, callback in ((0x70, first), (0x58, second)):
        if not _String.read(runtime, config + offset).value() and callback:
            raise PrimarySemanticUnavailable('request telemetry metadata callback is not bound')
    _srw(runtime, config + 0x120, False)


def _sample(runtime):
    memory, config = runtime.memory, runtime.image_base + 0x67516B0
    sample = _invoke(runtime, 0x3E98FF0)
    thread = next(event[1] for event in reversed(runtime.events)
                  if event[0] == 'CRT.current_thread.initialized')
    seed = memory.load(thread + 0x28, 4)
    first = _String.read(runtime, config + 8).clone()
    length = len(first.value())
    first.destroy()
    if length >= 5:
        first = _String.read(runtime, config + 8).clone()
        sample ^= int.from_bytes(first.value()[:4], 'little')
        first.destroy()
    second = _String.read(runtime, config + 0x70).value()
    if len(second) >= 5:
        sample ^= int.from_bytes(second[:4], 'little')
    runtime.events.append(('request.audit_sample', seed, sample))
    return sample


def _copy(runtime, source, destination, size):
    memory = runtime.memory
    region, offset = memory._span(source, size)
    raw = bytes(region.data[offset:offset + size])
    known = bytes(region.initialized[offset:offset + size])
    index = 0
    while index < size:
        end = index + 1
        while end < size and known[end] == known[index]:
            end += 1
        if known[index]:
            memory.write(destination + index, raw[index:end], source='1BF3A80.cached_telemetry_move')
        else:
            memory.forget(destination + index, end - index, source='cached_telemetry_unobserved_padding')
        index = end


def _clone_record(runtime, destination, source):
    memory, base = runtime.memory, runtime.image_base
    memory.store(destination, base + 0x3FD6BA8, 8, source='1BEED1A.cached_telemetry_vtable')
    for offset in range(8, 200, 24):
        _String.read(runtime, source + offset).clone().write_to(destination + offset)
    first, last = memory.load(source + 200, 8), memory.load(source + 208, 8)
    if last < first or (last - first) % 24 or last - first > 24 * 4096:
        raise PrimaryProgramLimit('cached telemetry columns exceed the recovered vector domain')
    columns = runtime._operator_new(last - first) if last != first else 0
    for offset in range(0, last - first, 24):
        _String.read(runtime, first + offset).clone().write_to(columns + offset)
    for offset, value in ((200, columns), (208, columns + last - first), (216, columns + last - first)):
        memory.store(destination + offset, value, 8, source='BD3FE8.cached_telemetry_columns')
    _String.read(runtime, source + 224).clone().write_to(destination + 224)


def _append(runtime, owner, record):
    memory, base = runtime.memory, runtime.image_base
    _srw(runtime, base + 0x677C0B0, True)
    first, last, end = (memory.load(owner + offset, 8) for offset in (8, 16, 24))
    if not first <= last <= end or (last - first) % 248 or (end - first) % 248:
        raise PrimarySemanticUnavailable('request telemetry cache has an unobserved vector representation')
    count, capacity = (last - first) // 248, (end - first) // 248
    if count + 1 >= 0x108421084210843:
        raise PrimaryProgramLimit('request telemetry cache exceeds its native vector domain')
    if last == end:
        capacity = max(2 * capacity, count + 1) if capacity < 0x84210842108421 else 0x108421084210842
        if capacity > 4096:
            raise PrimaryProgramLimit('request telemetry cache exceeds the bounded offline allocation domain')
        allocation = runtime._operator_new(capacity * 248)
        _clone_record(runtime, allocation + count * 248, record)
        for index in range(count - 1, -1, -1):
            _copy(runtime, first + index * 248, allocation + index * 248, 248)
            memory.write(first + index * 248 + 8, bytes(240), source='1BF3AA6.moved_telemetry_source_empty')
        if first:
            runtime._free_allocation(first)
        first = allocation
    else:
        _clone_record(runtime, last, record)
    for offset, value in ((8, first), (16, first + (count + 1) * 248), (24, first + capacity * 248)):
        memory.store(owner + offset, value, 8, source='1BF3C2F.telemetry_cache_publish')
    _srw(runtime, base + 0x677C0B0, False)
    runtime.events.append(('request.audit_cached', count + 1, capacity))


def consume(runtime, owner, event, columns, force, divisor, last_flag):
    _metadata(runtime)
    if not force & 255:
        value = _sample(runtime)
        divisor &= 0xFFFFFFFF
        if not divisor:
            raise PrimarySemanticUnavailable('request telemetry unsigned division by zero')
        if value % divisor:
            runtime.events.append(('request.audit_rejected', divisor))
            return 0
    submit_event(runtime, owner, event, columns, last_flag)
    runtime.events.append(('request.audit_accepted', bool(force & 255), divisor & 0xFFFFFFFF, last_flag & 255))
    return 1


def _cost_columns(runtime, event):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x128, 'BCE940.cost_event_columns_frame')
    for index in range(9):
        _String.read(runtime, event + 224 + index * 24).clone().write_to(rbp - 0x58 + index * 24)
    vector = runtime._operator_new(216)
    for index in range(9):
        _String.read(runtime, rbp - 0x58 + index * 24).clone().write_to(vector + index * 24)
    for index in range(8, -1, -1):
        _String.read(runtime, rbp - 0x58 + index * 24).destroy()
    memory.unmap(frame)
    return vector


def submit_event(runtime, owner, event, columns, last_flag):
    memory, base = runtime.memory, runtime.image_base
    if memory.load(owner, 1) & 1:
        from .primary_request_submit import submit as submit_enabled
        submit_enabled(runtime, owner, event, columns, last_flag)
        return
    table = memory.load(event, 8)
    methods = memory.load(table, 8) - base, memory.load(table + 8, 8) - base
    if methods == (0x1BF4C50, 0x1BF4C70):
        column_count,topic = 7,bytes.fromhex(_image()['topic_hex'])
    elif methods == (0x1C018C0, 0x1BF4C70):
        from .primary_sdk_events import _definition

        column_count,topic = 7,bytes.fromhex(_definition()['topic_hex'])
    elif methods == (0xBD3BB0, 0xBD3BD0):
        from .primary_device_records import _image as _device_image
        column_count,topic = 6,bytes.fromhex(_device_image()['failure_topic_hex'])
    elif methods == (0xBCE920, 0xBCE940):
        column_count,topic = 9,b'0b500076578'
    elif table == base + 0x4149058 and methods == (0x1C018C0, 0x776860):
        column_count,topic = 0,None
    else:
        raise PrimarySemanticUnavailable('request telemetry event virtual methods are not bound')
    frame, rbp = _frame(runtime, 0x1B0, '1BEEC40.request_telemetry_cache_frame')
    record = rbp - 72
    memory.write(record, bytes(248), source='1BEEC74.cached_telemetry_initialization')
    memory.store(record, base + 0x3FD6BA8, 8, source='1BEECB9.cached_telemetry_vtable')
    _assign(runtime, record + 8, _String.read(runtime, event + 8))
    width = column_count * 24
    if topic is None:
        _invoke(runtime, methods[1], event, record + 200)
        vector = memory.load(record + 200, 8)
    elif methods == (0xBCE920, 0xBCE940):
        vector = _cost_columns(runtime, event)
    else:
        vector = runtime._operator_new(width)
        for index in range(column_count):
            _String.read(runtime, event + 224 + index * 24).clone().write_to(vector + index * 24)
    for offset, value in ((200, vector), (208, vector + width), (216, vector + width)):
        memory.store(record + offset, value, 8, source='1BF2247.request_telemetry_columns')
    if topic is None:
        _invoke(runtime, methods[0], event, record + 224)
    else:
        _String.construct(runtime, topic).write_to(record + 224)
    _append(runtime, owner, record)
    for offset in list(range(8, 200, 24)) + [224]:
        _String.read(runtime, record + offset).destroy()
    for index in range(column_count):
        _String.read(runtime, vector + index * 24).destroy()
    if vector:
        runtime._free_allocation(vector)
    memory.unmap(frame)


def submit(runtime, event, columns, status, transport_error=None):
    memory, base = runtime.memory, runtime.image_base
    status &= 0xFFFFFFFF
    signed = status - (1 << 32) if status >> 31 else status
    _assign(runtime, event + 224, _String.construct(runtime, str(signed).encode('ascii')))
    if transport_error is not None:
        _assign(runtime, event + 296, _String.construct(runtime, str(transport_error & 0xFFFFFFFF).encode('ascii')))
    for offset in (0, 24):
        _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(columns + offset)
    _owner(runtime, _response_image())
    force = int(status != 0) if transport_error is None else 0
    divisor = 10000 if transport_error is None else 100
    runtime.events.append(('request.audit_submit', signed, transport_error, force, divisor))
    result = consume(runtime, base + 0x67519B8, event, columns, force, divisor, 0)
    for offset in (0, 24):
        _String.read(runtime, columns + offset).destroy()
    return result


def finish_failure(runtime):
    memory = runtime.memory
    pointer = memory.load(runtime.image_base + 0x6751B38, 8)
    memory.store(pointer + 56, 1, 1, source='1CEC464.request_log_transport_failure')
    memory.store(pointer + 64, memory.load(pointer + 64, 2) | 2, 2,
                 source='1CEC468.request_log_transport_failure_bits')


def destroy(runtime, event):
    for offset in list(range(8, 200, 24)) + list(range(224, 392, 24)):
        _String.read(runtime, event + offset).destroy()
