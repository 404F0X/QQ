import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_cocos import next_mt, seed_mt
from .primary_logger import _String, _cstring, _format
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
from .wire import require_uint


_STRING_OFFSETS = (*range(0x80, 0x458, 24), *range(0x460, 0x688, 24),
                   *range(0x690, 0x708, 24), 0x710)
_LIMIT = 1 << 20
_IMAGE_SHA256 = 'a5d5e27b06d04a1bbc44e83c18cbc04a4face83d8391af415e61e5876b65e8bc'
_IMPORTS = {'GetSystemTimeAsFileTime': 0x490FFB8,
            'MultiByteToWideChar': 0x49101F0, 'WideCharToMultiByte': 0x4910460}


def install_image(memory, image_base):
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/device-material-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device material image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device material import identity mismatch')
    for segment in image['segments']:
        memory.map(image_base + segment['rva'], bytearray.fromhex(segment['hex']),
                   name='fixed device material formatting image', initialized=True)


def _require_material_import(runtime, name):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('device material current import is not bound: ' + name)


def _terminated(runtime, address, unit):
    value = bytearray()
    for offset in range(0, _LIMIT, unit):
        current = runtime.memory.read(address + offset, unit)
        value.extend(current)
        if current == bytes(unit):
            return bytes(value)
    raise PrimaryProgramLimit('device character conversion input exceeds the bounded offline domain')


def _convert_call(runtime, name, source, destination, capacity):
    _require_material_import(runtime, name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device character conversion OS observations: ' + name)
    wide = name == 'WideCharToMultiByte'
    raw = _terminated(runtime, source, 2 if wide else 1)
    arguments = (65001 if wide else 0, 0, raw, -1, destination is not None, capacity)
    if wide:
        arguments += (0, 0)
    result, output = runtime.worker_observations.take(runtime, name, arguments)
    if not isinstance(output, bytes) or len(output) > capacity * (1 if wide else 2):
        raise InputError('device character conversion requires bounded raw OS output effects')
    if output:
        runtime.memory.write(destination, output, source='2E09690.' + name + '_output')
    result &= 0xFFFFFFFF
    return result if result < 1 << 31 else result - (1 << 32)


def _new_array(runtime, size):
    if not 0 <= size <= _LIMIT:
        raise PrimaryProgramLimit('device conversion array exceeds the bounded offline domain')
    expected, zero, address = runtime._next(runtime._allocations, 'B758C4.array_new', size, False)
    if expected != size or zero is not False:
        raise InputError('device array observation does not match the actual requested size')
    if type(address) is not int or not 0 < address <= (1 << 64) - max(1, size):
        raise PrimaryProgramLimit('device array allocator failure requires its actual handler effects')
    runtime.memory.map(address, bytearray(max(1, size)), name='observed device conversion array', initialized=False)
    if not hasattr(runtime, '_device_arrays'):
        runtime._device_arrays = {}
    runtime._device_arrays[address] = max(1, size)
    runtime.events.append(('device.array_new', size, address))
    return address


def _delete_array(runtime, address):
    allocations = getattr(runtime, '_device_arrays', {})
    if address not in allocations:
        raise PrimaryProgramLimit('device array deletion requires its matching observed allocation')
    runtime.memory.forget(address, allocations.pop(address), source='B758ED.array_delete')
    runtime.memory.unmap(address)
    runtime.events.append(('device.array_delete', address))


def _converted_hardware(runtime, source):
    memory = runtime.memory
    data = memory.load(source + 16, 8) if memory.load(source, 1) & 1 else source + 1
    wide_count = _convert_call(runtime, 'MultiByteToWideChar', data, None, 0)
    wide = _new_array(runtime, 2 * wide_count)
    data = memory.load(source + 16, 8) if memory.load(source, 1) & 1 else source + 1
    _convert_call(runtime, 'MultiByteToWideChar', data, wide, wide_count)
    utf8_count = _convert_call(runtime, 'WideCharToMultiByte', wide, None, 0)
    utf8 = _new_array(runtime, utf8_count)
    _convert_call(runtime, 'WideCharToMultiByte', wide, utf8, utf8_count)
    value = _String.construct(runtime, _terminated(runtime, utf8, 1)[:-1])
    _delete_array(runtime, wide)
    _delete_array(runtime, utf8)
    return value


def convert_hardware(runtime, destination, source):
    _converted_hardware(runtime, source).write_to(destination)
    return destination


def _append_material(runtime, value, suffix):
    previous = value.value()
    long = value.get(0, 1) & 1
    capacity = (value.get(0, 8) & ~1) - 1 if long else 22
    total = len(previous) + len(suffix)
    if total > _LIMIT:
        raise PrimaryProgramLimit('device material String exceeds the bounded offline domain')
    if total <= capacity:
        if suffix:
            value.append(suffix)
        return value
    physical = (max(2 * capacity, total) | 15) + 1
    from .primary_worker_consumer import _invoke
    pointer = _invoke(runtime, 0xB75000, physical)
    runtime.memory.write(pointer, previous, source='75C266.device_material_prefix')
    runtime.memory.write(pointer + len(previous), suffix, source='75C277.device_material_suffix')
    if long:
        value.destroy()
    value.set(16, pointer.to_bytes(8, 'little'))
    value.set(0, (physical | 1).to_bytes(8, 'little'))
    value.set(8, total.to_bytes(8, 'little'))
    runtime.memory.store(pointer + total, 0, 1, source='75C2C6.device_material_nul')
    return value


def generate_material(runtime, destination, source):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0xB00, '35F4E50.device_material_frame')
    _require_material_import(runtime, 'GetSystemTimeAsFileTime')
    timestamp = runtime._next(runtime._filetimes, 'GetSystemTimeAsFileTime')
    require_uint(timestamp, 64, 'device material FILETIME')
    memory.store(rbp + 0x9B0, timestamp, 8, source='35F4E88.observed_FILETIME')
    _String.construct(runtime, b'/dev/urandom').write_to(frame + 0x28)
    _invoke(runtime, 0x7602D0, rbp + 0xA30, frame + 0x28)
    seed = _invoke(runtime, 0x7603B0, rbp + 0xA30)
    seed_mt(memory, frame + 0x28, seed)
    _invoke(runtime, 0x28F0, rbp + 0xA30)
    random = next_mt(memory, frame + 0x28)
    time_text = _format(runtime, _cstring(runtime, base + 0x4898EF2), (timestamp,))
    random_text = _format(runtime, _cstring(runtime, base + 0x4899137), (random,))
    if len(time_text) > 16 or len(random_text) > 16:
        raise PrimarySemanticUnavailable('device material mutated printf formats exceed the original bounded buffers')
    memory.write(rbp + 0x970, time_text + b'\0', source='35F4F82.time_format')
    memory.write(rbp + 0x990, random_text + b'\0', source='35F4F9D.random_format')
    converted = _converted_hardware(runtime, source)
    random_value = _String.construct(runtime, random_text)
    result = _String.construct(runtime, time_text)
    _append_material(runtime, result, _cstring(runtime, base + 0x48C6BA8))
    _append_material(runtime, result, random_value.value())
    _append_material(runtime, result, _cstring(runtime, base + 0x48C6BA8))
    _append_material(runtime, result, converted.value())
    result.write_to(destination)
    random_value.destroy()
    converted.destroy()
    _String.read(runtime, source).destroy()
    memory.unmap(frame)
    return destination


def construct_collector(runtime, address):
    memory = runtime.memory
    for offset in (0x718,):
        memory.write(address + offset, bytes(16), source='2E12327.collector_constructor')
    memory.write(address + 0x728, bytes(8), source='2E1232E.collector_constructor')
    for offset in range(0x18, 0x68, 16):
        memory.write(address + offset, bytes(16), source='2E12339.collector_constructor')
    memory.write(address + 0x68, bytes(8), source='2E1234D.collector_constructor')
    memory.write(address + 0x88, bytes(0x609), source='2E1235D.collector_constructor_memset')
    for offset in (*range(0x698, 0x708, 16), 0x702):
        memory.write(address + offset, bytes(16), source='2E12362.collector_constructor')
    memory.write(address + 0x42A8, b'\0', source='2E1239A.collector_constructor_once')
    memory.write(address, bytes(16), source='2E123A1.collector_constructor')
    memory.write(address + 0x10, bytes(4), source='2E123A4.collector_constructor')
    return address


def _copy_bytes(memory, destination, source, count, label):
    if count:
        memory.copy_disjoint(destination, source, count, label=label)


def assign_string(runtime, destination, source):
    from .primary_worker_consumer import _invoke
    if destination == source:
        return destination
    memory = runtime.memory
    source_tag = memory.load(source, 1)
    destination_long = memory.load(destination, 1) & 1
    if not destination_long and not source_tag & 1:
        _copy_bytes(memory, destination + 16, source + 16, 8, '75CEE7.copy_short_tail')
        _copy_bytes(memory, destination, source, 16, '75CEEE.copy_short_head')
        return destination
    if source_tag & 1:
        size, data = memory.load(source + 8, 8), memory.load(source + 16, 8)
    else:
        size, data = source_tag >> 1, source + 1
    if size > _LIMIT:
        raise PrimaryProgramLimit('collector String assignment exceeds the bounded offline domain')
    if not destination_long:
        if size <= 22:
            memory.store(destination, 2 * size, 1, source='75CF19.assign_short_length')
            _copy_bytes(memory, destination + 1, data, size, '75CF29.assign_short_payload')
            memory.store(destination + 1 + size, 0, 1, source='75CF92.assign_short_nul')
            return destination
        physical = (max(44, size) | 15) + 1
        pointer = _invoke(runtime, 0xB75000, physical)
        _copy_bytes(memory, pointer, data, size, '75CF7E.assign_new_payload')
        memory.store(destination + 16, pointer, 8, source='75CF83.assign_new_pointer')
        memory.store(destination, physical | 1, 8, source='75CF8B.assign_new_capacity')
        memory.store(destination + 8, size, 8, source='75CF8E.assign_new_length')
    else:
        physical = memory.load(destination, 8) & ~1
        pointer = memory.load(destination + 16, 8)
        if size < physical:
            memory.store(destination + 8, size, 8, source='75CFD9.assign_retained_length')
            _copy_bytes(memory, pointer, data, size, '75CFEF.assign_retained_payload')
        else:
            required = max(2 * (physical - 1), size)
            if required > _LIMIT:
                raise PrimaryProgramLimit('collector String growth exceeds the bounded offline domain')
            allocated = (required | 15) + 1
            replacement = _invoke(runtime, 0xB75000, allocated)
            _copy_bytes(memory, replacement, data, size, '75D078.assign_growth_payload')
            _invoke(runtime, 0xB75029, pointer)
            pointer = replacement
            memory.store(destination + 16, pointer, 8, source='75D085.assign_growth_pointer')
            memory.store(destination, allocated | 1, 8, source='75D08D.assign_growth_capacity')
            memory.store(destination + 8, size, 8, source='75D090.assign_growth_length')
    memory.store(pointer + size, 0, 1, source='75D094.assign_payload_nul')
    return destination


def copy_snapshot(runtime, destination, source):
    memory = runtime.memory
    for offset in (0x70, 0x60, 0x50, 0x40):
        _copy_bytes(memory, destination + offset, source + offset, 16, '2E25B80.snapshot_prefix')
    staged = []
    for offset in (0, 0x10, 0x20, 0x30):
        region, position = memory._span(source + offset, 16)
        staged.append((offset, bytes(region.data[position:position + 16]),
                       bytes(region.initialized[position:position + 16])))
    for offset, raw, known in reversed(staged):
        memory.write(destination + offset, raw, source='2E25BAB.snapshot_staged_prefix')
        for index, initialized in enumerate(known):
            if not initialized:
                memory.forget(destination + offset + index, 1, source='2E25BAB.snapshot_unknown_prefix')
    for offset in _STRING_OFFSETS:
        if offset == 0x460:
            _copy_bytes(memory, destination + 0x458, source + 0x458, 8, '2E25ECC.snapshot_dimensions')
        elif offset == 0x690:
            _copy_bytes(memory, destination + 0x688, source + 0x688, 1, '2E2608E.snapshot_battery')
        elif offset == 0x710:
            _copy_bytes(memory, destination + 0x708, source + 0x708, 2, '2E260FA.snapshot_profile_flags')
        assign_string(runtime, destination + offset, source + offset)
    _copy_bytes(memory, destination + 0x728, source + 0x728, 0x3B78, '2E2612B.snapshot_raw_tail')
    return destination


def destroy_snapshot(runtime, address):
    for offset in reversed(_STRING_OFFSETS):
        if runtime.memory.load(address + offset, 1) & 1:
            runtime._free_allocation(runtime.memory.load(address + offset + 16, 8))


def invoke(runtime, rva, values):
    if rva == 0x35F4E50 and len(values) == 2:
        return generate_material(runtime, *values)
    if rva in (0x2E09670, 0x2E09690) and len(values) == 2:
        return convert_hardware(runtime, *values)
    if rva == 0x2E12310 and len(values) == 1:
        return construct_collector(runtime, values[0])
    if rva == 0x2E25B70 and len(values) == 2:
        return copy_snapshot(runtime, *values)
    if rva == 0x1D3CF00 and len(values) == 1:
        return destroy_snapshot(runtime, values[0])
    if rva == 0x75CEC0 and len(values) == 2:
        return assign_string(runtime, *values)
    raise InputError('collector source interface argument count mismatch')
