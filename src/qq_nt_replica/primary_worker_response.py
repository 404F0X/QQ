import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _cstring, _decode, _srw, _String, log
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _image as _consumer_image, _invoke, _zero_string


_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20
_IMAGE_SHA256 = '72794746e32e217ef4b0853ad5dc17cf8be1cf47fd8d29a53c17ecc36f081c9d'


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'worker-response-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed worker response image identity mismatch')
    return json.loads(raw)


def install_image(memory, image_base):
    from .primary_signature_encoding import complete_image_segment
    image = _image()
    for segment in image['segments']:
        raw = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            value = int.from_bytes(raw[offset:offset + 8], 'little')
            raw[offset:offset + 8] = ((value - image['image_base'] + image_base) & _MASK64).to_bytes(8, 'little')
        raw = bytearray(complete_image_segment(segment['rva'], bytes(raw)))
        memory.map(image_base + segment['rva'], raw, name='fixed worker response source image', initialized=True)
    memory.map(image_base + 0x6751A00, bytearray(0xB8), name='fixed telemetry owner PE zero fill', initialized=True)
    memory.map(image_base + 0x677DE28, bytearray(16), name='fixed telemetry metadata callback PE zero fill', initialized=True)


def _frame(runtime, size, name):
    observed_size, address, initial = runtime._next(runtime._temporaries, name, size)
    if observed_size != size or type(address) is not int or not 0 < address <= _MASK64 - size:
        raise InputError(name + ' requires its explicit private frame address and size')
    if initial is not None and (not isinstance(initial, bytes) or len(initial) != size):
        raise InputError(name + ' requires complete raw bytes or unknown storage')
    runtime.memory.map(address, bytearray(size) if initial is None else bytearray(initial),
                       name=name, initialized=initial is not None)
    owned = getattr(runtime, '_owned_frame_regions', None)
    if owned is not None:
        from .primary_sign_lifecycle import region_at
        owned.append((address, region_at(runtime.memory, address)))
    return address, address + 0x80


def _assign(runtime, address, value):
    from .primary_worker_consumer import _invoke
    current = _String.read(runtime, address)
    if not current.get(0, 1) & 1 and not value.get(0, 1) & 1:
        value.write_to(address)
        return
    raw = value.value()
    long = current.get(0, 1) & 1
    capacity = (current.get(0, 8) & ~1) - 1 if long else 22
    if len(raw) > capacity:
        physical = (max(2 * capacity, len(raw)) | 15) + 1
        pointer = _invoke(runtime, 0xB75000, physical)
        runtime.memory.write(pointer, raw + b'\0', source='75CFB0.response_assign_growth')
        current.destroy()
        current.set(0, (physical | 1).to_bytes(8, 'little'))
        current.set(8, len(raw).to_bytes(8, 'little'))
        current.set(16, pointer.to_bytes(8, 'little'))
    elif long:
        runtime.memory.write(current.get(16, 8), raw + b'\0', source='75CFB0.response_assign_payload')
        current.set(8, len(raw).to_bytes(8, 'little'))
    else:
        current.set(0, bytes([len(raw) * 2]))
        current.set(1, raw + b'\0')
    current.write_to(address)


def _signed(value):
    value &= _MASK64
    return value - (1 << 64) if value >> 63 else value


def _varint(raw, cursor):
    value = 0
    for index in range(10):
        if cursor == len(raw):
            return False, value, cursor
        byte = raw[cursor]
        cursor += 1
        value = (value | ((byte & 127) << (index * 7))) & _MASK64
        if byte < 128:
            return True, value, cursor
    return False, value, cursor


def _parse(runtime, pointer, size, rbp):
    memory = runtime.memory
    if size > _LIMIT:
        raise PrimaryProgramLimit('device response exceeds the bounded offline domain')
    memory.store(rbp + 0x10, runtime.image_base + 0x3FD7270, 8, source='BDCFAC.response_parser_vtable')
    memory.write(rbp + 0x18, bytes(32), source='BDCFBD.response_parser_fields')
    token = _String.read(runtime, rbp + 0x18)
    source = _String.construct(runtime, memory.read(pointer, size) if size else b'')
    source.write_to(rbp + 0x78)
    copied = source.clone()
    copied.write_to(rbp + 0x98)
    raw, cursor, reason, success = copied.value(), 0, 0x100, True
    steps = 0
    while cursor < len(raw):
        steps += 1
        if steps > _LIMIT:
            raise PrimaryProgramLimit('device response parser exceeds its bounded iteration domain')
        valid, tag, cursor = _varint(raw, cursor)
        if not valid:
            reason, success = 0x102, False
            break
        number = (tag >> 3) & 0xFFFFFFFF
        if number in (1, 2):
            valid, value, cursor = _varint(raw, cursor)
            if not valid:
                reason, success = 0x154 + number, False
                break
            if number == 2:
                memory.store(rbp + 0x30, value, 8, source='BDDE98.response_timestamp')
            else:
                count = value & 0xFFFFFFFF
                end = (cursor + count) & 0xFFFFFFFF
                if end > len(raw):
                    reason, success = 0x155, False
                    break
                _append(token, raw[cursor:cursor + count])
                token.write_to(rbp + 0x18)
                cursor = end
        elif tag & 7 in (0, 2):
            valid, value, cursor = _varint(raw, cursor)
            if not valid:
                cursor = len(raw)
                continue
            if tag & 7 == 2:
                count = value & 0xFFFFFFFF
                end = (cursor + count) & 0xFFFFFFFF
                if end <= len(raw):
                    discarded = _zero_string(runtime)
                    _append(discarded, raw[cursor:cursor + count])
                    discarded.destroy()
                    cursor = end
    copied.destroy()
    source.destroy()
    runtime.events.append(('worker.response_parsed', success, reason, cursor, token.value(),
                           memory.load(rbp + 0x30, 8)))
    return success, reason, token


def format_record(runtime, record, output):
    result = _String.construct(runtime, str(_signed(runtime.memory.load(record, 8))).encode('ascii'))
    separator = _cstring(runtime, runtime.image_base + 0x4698C41)
    _append(result, separator)
    _append(result, _String.read(runtime, record + 8).value())
    _append(result, separator)
    _append(result, _String.read(runtime, record + 32).value())
    result.clone().write_to(output)
    result.destroy()
    return output


def encrypt_record(runtime, output, source):
    value = _String.read(runtime, source)
    raw = value.value()
    if not raw:
        runtime.memory.store(output, 0, 2, source='1BE5885.empty_persistent_record')
        return output
    key = runtime.memory.read(runtime.image_base + 0x4148930, 22)
    state, index = list(range(256)), 0
    for cursor in range(256):
        index = (index + state[cursor] + key[cursor % 22]) & 255
        state[cursor], state[index] = state[index], state[cursor]
    pointer = _invoke(runtime, 0x3E92E00, len(raw), 1)
    result, first, second = bytearray(raw), 0, 0
    for cursor in range(len(raw)):
        first = (first + 1) & 255
        second = (second + state[first]) & 255
        state[first], state[second] = state[second], state[first]
        result[cursor] ^= state[(state[first] + state[second]) & 255]
    data = bytes(result)
    if value.get(0, 1) & 1:
        runtime.memory.write(value.get(16, 8), data, source='1BE58E2.persistent_record_in_place')
    else:
        value.set(1, data)
        value.write_to(source)
    runtime.memory.write(pointer, data, source='1BE58E5.persistent_record_copy')
    encrypted = _String.construct(runtime, data)
    runtime._free_allocation(pointer)
    encrypted.write_to(output)
    runtime.events.append(('worker.persistent_record_encrypted', source, output, data))
    return output


def store_record(runtime, key, value, temporary):
    if not _String.read(runtime, value).value() or not _String.read(runtime, key).value():
        return None
    encrypt_record(runtime, temporary, value)
    provider = runtime.memory.load(runtime.image_base + 0x677BE78, 8)
    if provider and _String.read(runtime, key).value():
        target = runtime.memory.load(runtime.memory.load(provider, 8) + 40, 8)
        runtime.events.append(('worker.persistent_record_pending', provider, target, key, temporary))
        raise PrimarySemanticUnavailable('1BE5A54 persistent configuration provider vtable+28 effects are not bound')
    _String.read(runtime, temporary).destroy()
    return None


def _message(runtime, image, rbp, name, line, severity, *values):
    file = _consumer_image()['file']
    runtime.memory.write(rbp + 0x90, bytes([0, file['seed']]) + _decode(file) + b'\0\0',
                         source='BDCBD4.response_log_file_decode')
    log(runtime, _decode(file), line, _decode(image[name]),
        runtime.image_base + 0x48972C7, severity, *values)


def _owner(runtime, image):
    memory, base = runtime.memory, runtime.image_base
    guard = base + image['owner_guard_rva']
    value = memory.load(guard, 4)
    if not value & 1:
        memory.store(guard, value | 1, 4, source='BCE5C5.telemetry_owner_guard')
        for operation in image['owner_initialization']:
            raw = bytes.fromhex(operation['hex'])
            if operation['relocation']:
                raw = (int.from_bytes(raw, 'little') - image['image_base'] + base).to_bytes(8, 'little')
            address = base + operation['rva']
            boundary = base + 0x6751A00
            if address < boundary < address + len(raw):
                split = boundary - address
                memory.write(address, raw[:split], source='BCE5CB.telemetry_owner_initialization')
                memory.write(boundary, raw[split:], source='BCE5CB.telemetry_owner_initialization')
            else:
                memory.write(address, raw, source='BCE5CB.telemetry_owner_initialization')
        _invoke(runtime, 0x3E680B4, base + image['owner_exit_callback_rva'])


def audit(runtime, record):
    memory, base, image = runtime.memory, runtime.image_base, _image()
    frame, rbp = _frame(runtime, 0x2E8, 'BCDAD0.device_telemetry_frame')
    table = memory.load(record, 8)
    caller = table == base + 0x4148FC8
    virtuals = ((8, 0x1C00FF0), (16, 0x1C010B0), (24, 0x1C014C0)) if caller else (
        (8, 0xBCD160), (16, 0xBCD250), (24, 0x9A3770))
    for offset, target in virtuals:
        if memory.load(table + offset, 8) != base + target:
            raise PrimarySemanticUnavailable('BCDAD0 current device telemetry virtual interface is not bound')
    event = rbp - 0x40
    memory.store(event, base + 0x3FD6CC8, 8, source='BCDB8C.device_telemetry_event_vtable')
    kind = _String.read(runtime, record + 32).clone()
    kind.clone().write_to(event + 8)
    kind.destroy()
    for offset in range(32, 200, 24):
        memory.store(event + offset, 0, 2, source='BCDB49.device_telemetry_empty_field')
    memory.write(event + 200, bytes(240), source='BCDB73.device_telemetry_columns')
    start, end = memory.load(record + 8, 8), memory.load(record + 16, 8)
    duration = _signed(end - start)
    truncate = lambda value: (abs(value) // 1000) * (-1 if value < 0 else 1)
    for offset, value in ((224, truncate(duration)), (248, truncate(_signed(start))), (272, truncate(_signed(end)))):
        _String.construct(runtime, str(value).encode('ascii')).write_to(event + offset)
    _String.construct(runtime, _cstring(runtime, base + 0x4903C10)).write_to(event + 0x128)
    if caller:
        from .primary_caller_audit import columns as caller_columns
        caller_columns(runtime, record, event)
    from .primary_worker_loop import _initialize
    _initialize(runtime, 0)
    config = base + 0x67516B0
    if memory.load(config + 0x100, 4) >= 2:
        memory.store(record + 28, 100, 4, source='BCDD5F.device_telemetry_debug_sample')
        if duration >= 0x989A68:
            raise PrimarySemanticUnavailable('BCDD68 enabled device telemetry duration logging remains unavailable')
    _owner(runtime, image)
    columns = rbp + 0x1D0
    memory.write(columns, bytes(48), source='BCD18C.device_telemetry_metadata')
    for offset in (0, 24):
        _String(runtime, bytes(2) + bytes(22), b'\1\1' + bytes(22)).write_to(columns + offset)
    runtime.events.append(('worker.device_telemetry', event, columns, duration, memory.load(record + 28, 4)))
    sample_divisor = memory.load(record + 28, 4)
    if caller:
        from .primary_caller_audit import divisor as caller_divisor, metadata as caller_metadata
        sample_divisor = caller_divisor(runtime, record, truncate(duration))
        caller_metadata(runtime, record, columns)
    from .primary_request_audit import consume
    consume(runtime, base + 0x67519B8, event, columns, int(not memory.load(record + 24, 1)),
            sample_divisor, 0)
    for offset in (24, 0):
        _String.read(runtime, columns + offset).destroy()
    for offset in list(range(416, 223, -24)) + list(range(176, 7, -24)):
        _String.read(runtime, event + offset).destroy()
    memory.unmap(frame)
    return None


def respond(runtime, capture, pointer, size, success, error):
    memory, base, image = runtime.memory, runtime.image_base, _image()
    frame, rbp = _frame(runtime, 0x1A8, 'BDCAD0.device_response_frame')
    pair = memory.load(capture, 8)
    memory.store(rbp, capture, 8, source='BDCB09.response_capture')
    name = _String.read(runtime, capture + 8).clone()
    name.write_to(rbp - 0x18)
    size, success, error = size & 0xFFFFFFFF, success & 255, error & 0xFFFFFFFF
    _message(runtime, image, rbp, 'response_log', 553, 1, size)
    token = None
    if not success:
        failed = (memory.load(pair + 0x64, 4) + 1) & 0xFFFFFFFF
        memory.store(pair + 0x64, failed, 4, source='BDCFDC.response_transport_failure')
        _message(runtime, image, rbp, 'transport_error', 556, 2, error, failed)
    else:
        parsed, reason, token = _parse(runtime, pointer, size, rbp)
        if not parsed:
            failed = (memory.load(pair + 0x64, 4) + 1) & 0xFFFFFFFF
            memory.store(pair + 0x64, failed, 4, source='BDE241.response_parse_failure')
            _message(runtime, image, rbp, 'parse_error', 569, 2, reason, failed)
        else:
            memory.store(pair + 0x64, 0, 4, source='BDE1E0.response_failure_reset')
            name.clone().write_to(rbp - 0x30)
            token.clone().write_to(rbp - 0x48)
            record = rbp + 0x40
            memory.write(record + 8, bytes(48), source='BE0730.token_record_strings')
            _assign(runtime, record + 8, _String.read(runtime, rbp - 0x48))
            _assign(runtime, record + 32, _String.read(runtime, rbp - 0x30))
            memory.store(record, memory.load(rbp + 0x30, 8), 8, source='BE076D.token_record_timestamp')
            _String.read(runtime, rbp - 0x48).destroy()
            _String.read(runtime, rbp - 0x30).destroy()
            _srw(runtime, pair + 0xE0, True)
            cached = _String.read(runtime, record + 8)
            if cached.value():
                memory.store(pair + 16, memory.load(record, 8), 8, source='BDEC55.token_cache_timestamp')
                _assign(runtime, pair + 24, cached)
                _assign(runtime, pair + 48, _String.read(runtime, record + 32))
                raw = cached.value().split(b'\0', 1)[0]
                _message(runtime, image, rbp, 'success_token', 599, 1, memory.load(record, 8), raw)
                key = _String.construct(runtime, _decode(image['persistent_prefix']))
                _append(key, _String.read(runtime, record + 32).value())
                key.write_to(rbp + 0x90)
                format_record(runtime, record, rbp + 0x78)
                _invoke(runtime, 0x1BE59D0, rbp + 0x90, rbp + 0x78)
                _String.read(runtime, rbp + 0x78).destroy()
                key.destroy()
            else:
                _message(runtime, image, rbp, 'empty_token', 602, 2)
            _srw(runtime, pair + 0xE0, False)
            _String.read(runtime, record + 32).destroy()
            cached.destroy()
            memory.write(rbp + 0x90, bytes(5), source='BDF303.device_auxiliary_empty')
            if token.get(0, 1) & 1:
                auxiliary = memory.read(token.get(16, 8), 4)
            else:
                if not all(token.known[1:5]):
                    raise PrimarySemanticUnavailable('BDF324 short device token padding is unobserved')
                auxiliary = bytes(token.header[1:5])
            memory.write(rbp + 0x90, auxiliary, source='BDF328.device_auxiliary_dword')
            from .primary_tokens import publish_response_token
            publish_response_token(runtime, rbp + 0x90)
    if token is not None:
        token.destroy()
    name.destroy()
    record = rbp + 0x90
    memory.store(record, base + 0x3FD7328, 8, source='BDF8F2.device_cost_vtable')
    _invoke(runtime, 0x759B30, record + 8)
    memory.store(record + 16, 0, 8, source='BDF8B8.device_cost_end')
    memory.store(record + 24, 1, 2, source='BDF8C0.device_cost_report_flags')
    memory.store(record + 28, 10000, 4, source='BDF8C7.device_cost_sample_divisor')
    _String.construct(runtime, _decode(image['telemetry_kind'])).clone().write_to(record + 32)
    memory.store(record + 8, memory.load(capture + 32, 8), 8, source='BDF382.device_cost_original_start')
    memory.store(record + 25, 1, 1, source='BDF38D.device_cost_report_once')
    _invoke(runtime, 0x759B30, rbp + 0x40)
    memory.store(record + 16, memory.load(rbp + 0x40, 8), 8, source='BDF3A4.device_cost_end')
    audit(runtime, record)
    memory.store(record, base + 0x3FD6A28, 8, source='BDF9B7.device_cost_base_vtable')
    _String.read(runtime, record + 32).destroy()
    memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    if rva == 0xBDCAD0 and len(values) == 5:
        return respond(runtime, *values)
    if rva == 0xBDCA30 and len(values) == 5:
        function, data, count, success, error = values
        return respond(runtime, function + 8, runtime.memory.load(data, 8), runtime.memory.load(count, 4),
                       runtime.memory.load(success, 1), runtime.memory.load(error, 4))
    if rva == 0xBE0840 and len(values) == 2:
        return format_record(runtime, *values)
    if rva == 0x1BE5680 and len(values) == 2:
        return encrypt_record(runtime, *values)
    if rva == 0x1BE59D0 and len(values) == 2:
        frame, _ = _frame(runtime, 0x48, '1BE59D0.persistent_record_frame')
        result = store_record(runtime, *values, frame + 0x28)
        runtime.memory.unmap(frame)
        return result
    raise InputError('worker response source interface argument count mismatch')
