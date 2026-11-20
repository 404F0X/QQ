import hashlib
import json
from pathlib import Path
from dataclasses import dataclass

from .errors import InputError
from .primary_device_collector import _append_material
from .primary_logger import _cstring, _String
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = '7ba807708e50b721c6ae90c33fb1e147f3418c6c5bd2aa49e7dee53000057187'
_IMPORTS = {'GetWindowsDirectoryA': 0x4910050, 'CreateFileA': 0x490FC28,
            'DeviceIoControl': 0x490FCB8, 'CloseHandle': 0x490FBD8}
_MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class AdapterBufferEffect:
    raw: bytes
    known: bytes
    relocations: tuple


def apply_adapter_buffer(runtime, buffer, capacity, effect, *, source):
    if isinstance(effect, bytes):
        if len(effect) > capacity or effect and not buffer:
            raise InputError('adapter output exceeds its source destination')
        if effect:
            runtime.memory.write(buffer, effect, source=source)
        return
    if (not isinstance(effect, AdapterBufferEffect) or not isinstance(effect.raw, bytes)
            or not isinstance(effect.known, bytes) or len(effect.raw) != len(effect.known)
            or len(effect.raw) > capacity or effect.raw and not buffer
            or any(value not in (0, 1) for value in effect.known) or not isinstance(effect.relocations, tuple)):
        raise InputError('adapter relocation effect requires bounded bytes and explicit known mask')
    raw, slots = bytearray(effect.raw), set()
    for pair in effect.relocations:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise InputError('adapter relocation requires source slot and relative target')
        offset, target = pair
        if (type(offset) is not int or not 0 <= offset <= len(raw) - 8
                or any(slot in slots for slot in range(offset, offset + 8))
                or effect.known[offset:offset + 8] != b'\1' * 8
                or raw[offset:offset + 8] != bytes(8)
                or target is not None and (type(target) is not int or not 0 <= target < len(raw))):
            raise InputError('adapter relocation leaves its original buffer domain')
        slots.update(range(offset, offset + 8))
        pointer = buffer + target if target is not None else 0
        if pointer > _MASK64:
            raise InputError('adapter relocation wraps its source allocation')
        raw[offset:offset + 8] = pointer.to_bytes(8, 'little')
    if raw:
        runtime.memory._span(buffer, len(raw))
    start = 0
    while start < len(raw):
        if not effect.known[start]:
            start += 1
            continue
        end = start + 1
        while end < len(raw) and effect.known[end]:
            end += 1
        runtime.memory.write(buffer + start, bytes(raw[start:end]), source=source)
        start = end


def _image():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/device-hardware-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device hardware image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device hardware import identity mismatch')
    return image


def install_image(memory, image_base):
    image = _image()
    for segment in image['segments']:
        raw = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            pointer = int.from_bytes(raw[offset:offset + 8], 'little')
            raw[offset:offset + 8] = ((pointer - image['image_base'] + image_base) & _MASK64).to_bytes(8, 'little')
        if segment['rva'] == image['ctype_pointer_rva']:
            if memory.read(image_base + segment['rva'], len(raw)) != raw:
                raise InputError('fixed shared CRT classification pointer identity mismatch')
            continue
        memory.map(image_base + segment['rva'], raw, name='fixed device hardware source image', initialized=True)


def _observe(runtime, name, arguments):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('device hardware current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device hardware OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _plain(runtime, name, arguments):
    result, raw = _observe(runtime, name, arguments)
    if raw != b'':
        raise InputError('device hardware operation has no output buffer: ' + name)
    return result


def _cpuid(runtime, leaf):
    if runtime.worker_observations is None:
        raise UnknownMemory('device hardware CPU brand requires CPUID observations')
    ignored, values = runtime.worker_observations.take(runtime, 'CPUID', (leaf, 0))
    if (not isinstance(values, tuple) or len(values) != 4 or
            any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in values)):
        raise InputError('device hardware CPUID requires four explicit DWORD register outputs')
    return b''.join(value.to_bytes(4, 'little') for value in values)


def cpu_brand(runtime, destination):
    frame, ignored = _frame(runtime, 0x70, '1BED570.CPU_brand_frame')
    raw = b''.join(_cpuid(runtime, leaf) for leaf in (0x80000002, 0x80000003, 0x80000004))
    runtime.memory.write(frame + 0x20, raw + b'\0', source='1BED570.CPU_brand_register_bytes')
    runtime.memory.write(destination, b'\x02 \0', source='1BED5EF.default_CPU_brand')
    if raw[0]:
        _invoke(runtime, 0x75BEB0, destination, frame + 0x20, len(_cstring(runtime, frame + 0x20)))
    runtime.memory.unmap(frame)
    return destination


def _alphanumeric(runtime, value):
    image, memory, base = _image(), runtime.memory, runtime.image_base
    if memory.load(base + image['ctype_locale_flag_rva'], 4):
        raise PrimarySemanticUnavailable('device product byte classification requires its actual nondefault CRT locale')
    character = value if value < 128 else value - 256
    if character < -1:
        return False
    table = memory.load(base + image['ctype_pointer_rva'], 8)
    return bool(memory.load(table + 2 * character, 2) & 0x107)


def physical_device(runtime, destination):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x470, '1BED2F0.physical_device_frame')
    memory.write(destination, b'\x02 \0', source='1BED30D.default_physical_device')
    buffer, temporary = rbp - 0x40, rbp + 0x3C8
    memory.write(buffer, bytes(265), source='1BED32C.zero_windows_directory_buffer')
    ignored, raw = _observe(runtime, 'GetWindowsDirectoryA', (260,))
    if not isinstance(raw, bytes) or len(raw) > 260:
        raise InputError('device hardware Windows directory requires bounded raw output effects')
    memory.write(buffer, raw, source='1BED339.GetWindowsDirectoryA_output')
    memory.store(buffer, 34, 1, source='1BED33F.physical_path_String_length')
    memory.copy_disjoint(buffer + 1, runtime.image_base + _image()['physical_path_rva'], 16,
                         label='1BED34A.physical_path_literal')
    memory.store(buffer + 17, 0x65, 2, source='1BED34E.physical_path_suffix')
    _invoke(runtime, 0x75E7B0, temporary, 0)
    path = _String.read(runtime, buffer)
    _append_material(runtime, path, _String.read(runtime, temporary).value()).write_to(buffer)
    _String.read(runtime, temporary).destroy()
    path = _String.read(runtime, buffer).value().split(b'\0', 1)[0]
    handle = _plain(runtime, 'CreateFileA', (path, 0, 3, 0, 3, 0, 0))
    _String.read(runtime, buffer).destroy()
    if ((handle + 1) & _MASK64) < 2:
        memory.unmap(frame)
        return destination
    written, query = rbp + 0x3C4, rbp + 0x3C8
    memory.store(written, 0, 4, source='1BED403.initial_device_bytes_returned')
    memory.write(query, bytes(12), source='1BED40D.storage_property_query')
    memory.write(buffer, bytes(1024), source='1BED42D.zero_device_control_buffer')
    result, effects = _observe(runtime, 'DeviceIoControl', (handle, 0x2D1400, memory.read(query, 12), 1024, 0))
    if (not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], bytes)
            or len(effects[0]) > 1024 or effects[1] is not None
            and (type(effects[1]) is not int or not 0 <= effects[1] <= 0xFFFFFFFF)):
        raise InputError('device control requires bounded raw output and explicit bytes-returned DWORD effects')
    memory.write(buffer, effects[0], source='1BED469.DeviceIoControl_output')
    if effects[1] is not None:
        memory.store(written, effects[1], 4, source='1BED469.bytes_returned_output')
    if result & 0xFFFFFFFF:
        offset = memory.load(buffer + 16, 4)
        value = memory.load(buffer + offset, 1)
        if _alphanumeric(runtime, value):
            _invoke(runtime, 0x75BEB0, destination, buffer + offset, len(_cstring(runtime, buffer + offset)))
    _plain(runtime, 'CloseHandle', (handle,))
    memory.unmap(frame)
    return destination


def _move(runtime, destination, source):
    if runtime.memory.load(destination, 1) & 1:
        runtime._free_allocation(runtime.memory.load(destination + 16, 8))
    runtime.memory.copy_disjoint(destination + 16, source + 16, 8, label='35D5C30.move_hardware_String_tail')
    runtime.memory.copy_disjoint(destination, source, 16, label='35D5C30.move_hardware_String_head')


def concatenate(runtime, destination, first, second):
    prefix, suffix = _String.read(runtime, first).value(), _String.read(runtime, second).value()
    result = _String.construct(runtime, prefix, capacity=len(prefix) + len(suffix))
    _append_material(runtime, result, suffix).write_to(destination)
    return destination


def capture_hardware(runtime, ignored, digest, device, cpu, adapter):
    frame, rbp = _frame(runtime, 0x80, '35D5C30.hardware_material_frame')
    if not digest:
        runtime.memory.unmap(frame)
        return 0
    _invoke(runtime, 0x1BED2F0, rbp - 0x20)
    _move(runtime, device, rbp - 0x20)
    _invoke(runtime, 0x1BED570, rbp - 0x20)
    _move(runtime, cpu, rbp - 0x20)
    runtime.memory.write(rbp - 0x20, bytes(24), source='35D5CAB.initial_adapter_detail_String')
    _invoke(runtime, 0x35D5A80, rbp - 0x40, rbp - 0x20)
    _move(runtime, adapter, rbp - 0x40)
    concatenate(runtime, rbp - 0x58, device, cpu)
    joined = _String.read(runtime, rbp - 0x58)
    _append_material(runtime, joined, _String.read(runtime, adapter).value()).write_to(rbp - 0x58)
    runtime.memory.copy_disjoint(rbp - 0x40, rbp - 0x58, 24, label='35D5D22.move_joined_hardware_String')
    runtime.memory.write(rbp - 0x58, bytes(24), source='35D5D31.clear_moved_hardware_String')
    _String.read(runtime, rbp - 0x58).destroy()
    _invoke(runtime, 0x1D05BC0, rbp - 0x40, digest, 16)
    _String.read(runtime, rbp - 0x40).destroy()
    _String.read(runtime, rbp - 0x20).destroy()
    runtime.memory.unmap(frame)
    return 1


def capture_into_owner(runtime, destination, device, cpu, adapter):
    frame, ignored = _frame(runtime, 0x60, '2E11020.hardware_capture_frame')
    rbp = frame + 0x60
    runtime.memory.write(rbp - 0x20, bytes(24), source='2E11040.empty_hardware_vector')
    runtime.memory.write(rbp - 0x30, bytes(16), source='2E1104C.empty_hardware_digest')
    _invoke(runtime, 0x35D5C30, rbp - 0x20, rbp - 0x30, device, cpu, adapter)
    if not destination:
        raise PrimarySemanticUnavailable('2E11073 null hardware destination requires actual CRT invalid-parameter effects')
    runtime.memory.copy_disjoint(destination, rbp - 0x30, 16, label='2E1106E.owner_hardware_digest')
    first = runtime.memory.load(rbp - 0x20, 8)
    if first:
        last = runtime.memory.load(rbp - 0x18, 8)
        if last < first or (last - first) % 24 or last - first > 1 << 20:
            raise PrimaryProgramLimit('device hardware vector exceeds its bounded source domain')
        for pointer in range(last - 24, first - 1, -24):
            _String.read(runtime, pointer).destroy()
        runtime._free_allocation(first)
    runtime.memory.unmap(frame)
    return 1


def invoke(runtime, rva, values):
    definitions = {0x1BED570: (cpu_brand, 1), 0x1BED2F0: (physical_device, 1),
                   0x35D5C30: (capture_hardware, 5), 0x2E11020: (capture_into_owner, 4),
                   0x37AAE6: (concatenate, 3)}
    function, count = definitions[rva]
    if len(values) != count:
        raise InputError('device hardware source interface argument count mismatch')
    return function(runtime, *values)
