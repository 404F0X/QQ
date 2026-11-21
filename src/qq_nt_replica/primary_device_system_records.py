import hashlib
import json
from pathlib import Path
import struct

from .errors import InputError
from .primary_device_collector import _terminated
from .primary_device_cold import _foreign_output
from .primary_logger import _String
from .primary_memory import PrimaryMemoryLimit, UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = 'aa5ef589f70c79be8f360df3887042d5891b73240f25c28674dd87b8ce2c03b3'
_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/device-system-record-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed system record image identity mismatch')
    return json.loads(raw)


_IMPORTS = _image()['imports']


def install_image(memory, image_base):
    for segment in _image()['segments']:
        address, raw = image_base + segment['rva'], bytes.fromhex(segment['hex'])
        try:
            memory._span(address, len(raw))
        except PrimaryMemoryLimit:
            memory.map(address, bytearray(raw), name='fixed system record image', initialized=True)
        else:
            if memory.read(address, len(raw)) != raw:
                raise InputError('shared system record image identity mismatch')


def _target(runtime, name):
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
        raise PrimarySemanticUnavailable('system record current import is not bound: ' + name)
    return target


def _observe(runtime, name, arguments):
    if name != '_localtime64_s':
        _target(runtime, name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing system record OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _call(runtime, name, arguments, outputs=()):
    result, effects = _observe(runtime, name, arguments)
    if len(outputs) == 1 and isinstance(effects, bytes) and name in ('GetNativeSystemInfo', 'WideCharToMultiByte'):
        effects = (effects,)
    if not outputs:
        if effects != b'':
            raise InputError('system record operation requires empty output effects: ' + name)
        return result
    if not isinstance(effects, tuple) or len(effects) != len(outputs):
        raise InputError('system record operation requires its raw output buffers: ' + name)
    for raw, (address, capacity) in zip(effects, outputs):
        if isinstance(raw, tuple) and len(raw) == 2:
            data, known = raw
            if (not isinstance(data, bytes) or not isinstance(known, bytes) or len(data) != len(known) or
                    len(data) > capacity or any(value not in (0, 1) for value in known) or data and not address):
                raise InputError('system record sparse output exceeds its actual buffer: ' + name)
            start = 0
            while start < len(data):
                if not known[start]:
                    start += 1
                    continue
                end = start + 1
                while end < len(data) and known[end]:
                    end += 1
                runtime.memory.write(address + start, data[start:end], source='system_record.' + name)
                start = end
            continue
        if not isinstance(raw, bytes) or len(raw) > capacity or raw and not address:
            raise InputError('system record output exceeds its actual buffer: ' + name)
        if raw:
            runtime.memory.write(address, raw, source='system_record.' + name)
    return result


def _registry(runtime, root, path, key, destination, capacity, kind):
    memory = runtime.memory
    valid = path is not None and key is not None and (kind != 4 or destination != 0)
    if not valid:
        if kind == 1 and destination and capacity:
            memory.store(destination, 0, 1, source='3C715D0.failed_registry_string')
        return 0
    frame, local = _frame(runtime, 0x50, 'system_record.registry_frame')
    handle, type_pointer, length_pointer = frame + 0x38, frame + 0x34, frame + 0x30
    opened = _call(runtime, 'RegOpenKeyExA', (root, path, 0, 0x20119), ((handle, 8),)) & 0xFFFFFFFF
    success = False
    if not opened:
        memory.store(type_pointer, 0, 4, source='registry.initial_type')
        memory.store(length_pointer, capacity & 0xFFFFFFFF, 4, source='registry.initial_length')
        current = memory.load(handle, 8)
        queried = _call(runtime, 'RegQueryValueExA', (current, key, 0, capacity & 0xFFFFFFFF),
                        ((type_pointer, 4), (destination, capacity & 0xFFFFFFFF), (length_pointer, 4))) & 0xFFFFFFFF
        observed_type = memory.load(type_pointer, 4)
        _call(runtime, 'RegCloseKey', (current,))
        success = queried == 0 and observed_type == kind
    if not success and kind == 1 and destination and capacity:
        memory.store(destination, 0, 1, source='3C715D0.failed_registry_string')
    memory.unmap(frame)
    return int(success)


def registry_string(runtime, root, path, key, destination, capacity):
    if not path or not key:
        return _registry(runtime, root, None, None, destination, capacity, 1)
    return _registry(runtime, root, None if not path else _terminated(runtime, path, 1)[:-1],
                     None if not key else _terminated(runtime, key, 1)[:-1], destination, capacity, 1)


def registry_dword(runtime, root, path, key, destination):
    if not path or not key or not destination:
        return 0
    return _registry(runtime, root, _terminated(runtime, path, 1)[:-1],
                     _terminated(runtime, key, 1)[:-1], destination, 4, 4)


def _copy_value(runtime, destination, capacity, value):
    if not destination or not capacity:
        return None
    if capacity > _LIMIT:
        raise PrimaryProgramLimit('system record bounded copy exceeds the offline domain')
    raw = value.split(b'\0', 1)[0][:capacity - 1]
    runtime.memory.write(destination, raw + bytes(capacity - len(raw)), source='3C71590.bounded_copy')
    return None


def bounded_copy(runtime, destination, capacity, source):
    if not destination or not capacity:
        return None
    if not source:
        runtime.memory.store(destination, 0, 1, source='3C71590.null_source')
        return None
    if capacity > _LIMIT:
        raise PrimaryProgramLimit('system record bounded copy exceeds the offline domain')
    raw = bytearray()
    for offset in range(capacity - 1):
        value = runtime.memory.load(source + offset, 1)
        if not value:
            break
        raw.append(value)
    return _copy_value(runtime, destination, capacity, bytes(raw))


def utf8_string(runtime, destination, source):
    memory = runtime.memory
    if not source or not memory.load(source, 2):
        memory.store(destination, 0, 2, source='3C712C0.empty_String')
        return destination
    raw = _terminated(runtime, source, 2)
    arguments = (65001, 0, raw, -1)
    count = _call(runtime, 'WideCharToMultiByte', (*arguments, False, 0, 0, 0)) & 0xFFFFFFFF
    if count == 0 or count & 0x80000000:
        memory.store(destination, 0, 2, source='3C712C0.failed_String')
        return destination
    if count > _LIMIT:
        raise PrimaryProgramLimit('system record UTF8 output exceeds the offline domain')
    value = _String.construct(runtime, bytes(count))
    value.write_to(destination)
    pointer = value.get(16, 8) if value.get(0, 1) & 1 else destination + 1
    _call(runtime, 'WideCharToMultiByte', (*arguments, True, count, 0, 0), ((pointer, count),))
    value = _String.read(runtime, destination)
    if value.get(0, 1) & 1:
        value.set(8, (count - 1).to_bytes(8, 'little'))
        memory.store(pointer + count - 1, 0, 1, source='3C712C0.resize_terminator')
    else:
        value.set(0, bytes([(count - 1) * 2]))
        value.set(count, b'\0')
    value.write_to(destination)
    return destination


def admin_flag(runtime):
    memory = runtime.memory
    frame, local = _frame(runtime, 0x98, '35EC010.admin_frame')
    sid, member = frame + 0x78, frame + 0x84
    memory.store(sid, 0, 8, source='35EC010.initial_SID')
    memory.store(member, 0, 4, source='35EC010.initial_membership')
    authority = memory.read(runtime.image_base + _image()['authority_rva'], 6)
    allocated = _call(runtime, 'AllocateAndInitializeSid', (authority, 2, 0x20, 0x220, 0, 0, 0, 0, 0, 0), ((sid, 8),))
    _target(runtime, 'CheckTokenMembership')
    free_target = _target(runtime, 'FreeSid')
    if allocated & 0xFFFFFFFF:
        pointer = memory.load(sid, 8)
        _call(runtime, 'CheckTokenMembership', (0, pointer), ((member, 4),))
        _call(runtime, 'FreeSid', (pointer,))
    result = (free_target & 0xFFFFFF00) | int(memory.load(member, 4) != 0)
    memory.unmap(frame)
    return result


def _format_into(runtime, destination, capacity, template, values):
    raw = (template % values).encode('ascii')
    if len(raw) >= capacity:
        raise PrimarySemanticUnavailable('system record snprintf overflow semantics are not recovered')
    runtime.memory.write(destination, raw + b'\0', source='701774.system_record_format')


def mounted_volume(runtime, destination, capacity):
    memory, image = runtime.memory, _image()
    memory.store(destination, 0, 1, source='35EC180.initial_output')
    frame, local = _frame(runtime, 0x88, '35EC180.mounted_frame')
    handle, kind, length, buffer = frame + 0x30, frame + 0x38, frame + 0x3C, frame + 0x40
    opened = _call(runtime, 'RegOpenKeyExA', (0xFFFFFFFF80000002, bytes.fromhex(image['mounted_path_hex']), 0, 0x20119), ((handle, 8),))
    if not opened & 0xFFFFFFFF:
        memory.write(buffer, bytes(32), source='35EC180.initial_buffer')
        memory.store(kind, 0, 4, source='35EC180.initial_type')
        memory.store(length, 32, 4, source='35EC180.initial_length')
        pointer = memory.load(handle, 8)
        queried = _call(runtime, 'RegQueryValueExA', (pointer, bytes.fromhex(image['mounted_key_hex']), 0, 32),
                        ((kind, 4), (buffer, 32), (length, 4)))
        _call(runtime, 'RegCloseKey', (pointer,))
        if not queried & 0xFFFFFFFF and memory.load(length, 4) >= 4:
            _format_into(runtime, destination, capacity, '%02X%02X%02X%02X', tuple(memory.read(buffer, 4)))
    memory.unmap(frame)
    return None


def firmware_uuid(runtime, destination, capacity):
    memory = runtime.memory
    memory.store(destination, 0, 1, source='35EC530.initial_output')
    size = _call(runtime, 'GetSystemFirmwareTable', (0x52534D42, 0, False, 0)) & 0xFFFFFFFF
    if not size:
        return None
    pointer = _invoke(runtime, 0x3E97020, size)
    result = _call(runtime, 'GetSystemFirmwareTable', (0x52534D42, 0, True, size), ((pointer, size),)) & 0xFFFFFFFF
    if result == size and size >= 8:
        end = pointer + 8 + min(memory.load(pointer + 4, 4), size - 8)
        current = pointer + 8
        while current + 4 < end:
            kind, length = memory.load(current, 1), memory.load(current + 1, 1)
            if kind == 127:
                break
            if kind == 1 and length >= 24 and current + 24 <= end:
                value = memory.read(current + 8, 16)
                ordered = bytes(value[index] for index in (3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15)).hex().upper()
                _format_into(runtime, destination, capacity, '%s-%s-%s-%s-%s',
                             (ordered[:8], ordered[8:12], ordered[12:16], ordered[16:20], ordered[20:]))
                break
            following = current + length
            if following > end:
                break
            while following + 1 < end:
                if memory.load(following, 1) == 0 and memory.load(following + 1, 1) == 0:
                    break
                following += 1
            current = following + 2
    _invoke(runtime, 0x3E94F90, pointer)
    return None


def _contract(runtime, item, destination):
    return _registry(runtime, item['root'], bytes.fromhex(item['path_hex']), bytes.fromhex(item['key_hex']),
                     destination, item.get('capacity', 4), 1 if 'capacity' in item else 4)


def _calendar(runtime, source):
    values = struct.unpack('<8H', runtime.memory.read(source, 16))
    return values[0], values[1], values[3], values[4], values[5], values[6], values[7]


def capture(runtime, destination):
    memory, image = runtime.memory, _image()
    frame, rbp = _frame(runtime, 0x648, '35E9640.system_record_frame')
    memory.write(destination, bytes(0x1270), source='35E9640.zero_system_record')
    registry = image['registry']
    for item in registry[:5]:
        _contract(runtime, item, destination + item['owner_offset'])
    server = b'Server' in _terminated(runtime, destination + 0xF0, 1)[:-1] or b'Server' in _terminated(runtime, destination, 1)[:-1]
    memory.store(destination + 0x110, int(server), 1, source='35E9640.server_flag')
    system_info = rbp - 0x30
    _call(runtime, 'GetNativeSystemInfo', (), ((system_info, 48),))
    architecture = memory.load(system_info, 2)
    selected = image['architecture_default_rva']
    if architecture <= 12:
        table = runtime.image_base + image['architecture_table_rva']
        target = image['architecture_table_rva'] + memory.load(table + 4 * architecture, 4, signed=True)
        if str(target) not in image['architecture_branches']:
            raise PrimarySemanticUnavailable('system record current architecture branch is not recovered')
        selected = image['architecture_branches'][str(target)]
    bounded_copy(runtime, destination + 0x111, 32, runtime.image_base + selected)
    memory.store(destination + 0x134, memory.load(system_info + 32, 4), 4, source='35E9640.processor_count')
    memory.store(destination + 0x138, admin_flag(runtime) & 0xFF, 1, source='35E9640.admin_flag')
    ticks = _call(runtime, 'GetTickCount64', ())
    uptime = (((ticks >> 3) * 0x20C49BA5E353F7CF) >> 64) >> 4
    memory.store(destination + 0x148, uptime, 8, source='35E9640.uptime')
    _call(runtime, 'GetSystemTimeAsFileTime', (), ((rbp + 0x238, 8),))
    seconds = ((memory.load(rbp + 0x238, 8) * 0xD6BF94D5E57A42BD) >> 64) >> 23
    memory.store(destination + 0x140, (seconds - uptime + 0xFFFFFFFD49EF6F00) & _MASK64, 8, source='35E9640.boot_time')
    _contract(runtime, registry[5], destination + 0x150)
    installed = memory.load(destination + 0x150, 4)
    if installed:
        _call(runtime, '_localtime64_s', (installed,), ((rbp + 0x240, 36),))
        tm = list(struct.unpack('<9i', memory.read(rbp + 0x240, 36)))
        signed = lambda value: ((value + (1 << 31)) & 0xFFFFFFFF) - (1 << 31)
        _format_into(runtime, destination + 0x154, 32, '%04d-%02d-%02d %02d:%02d:%02d',
                     (signed(tm[5] + 1900), signed(tm[4] + 1), tm[3], tm[2], tm[1], tm[0]))
    calendars = (('GetSystemTime', rbp + 0x408, 0x174), ('GetLocalTime', rbp + 0x418, 0x194))
    for name, local, offset in calendars:
        _call(runtime, name, (), ((local, 16),))
    for name, local, offset in calendars:
        _format_into(runtime, destination + offset, 32, '%04d-%02d-%02dT%02d:%02d:%02d.%03dZ', _calendar(runtime, local))
    zone, string = rbp + 0x240, rbp + 0x1D0
    memory.write(zone, bytes(432), source='35E9640.initial_time_zone')
    status = _call(runtime, 'GetDynamicTimeZoneInformation', (), ((zone, 432),)) & 0xFFFFFFFF
    if status != 0xFFFFFFFF:
        utf8_string(runtime, string, zone + 172)
        value = _String.read(runtime, string)
        bounded_copy(runtime, destination + 0x1B4, 64, value.get(16, 8) if value.get(0, 1) & 1 else string + 1)
        value.destroy()
    for name, local, length, args, offset in (
            ('GetSystemDefaultLocaleName', rbp + 0x80, 170, (85,), 0x1F4),
            ('GetLocaleInfoEx', rbp, 128, (0, 0x1002, 64), 0x234)):
        memory.write(local, bytes(length), source='35E9640.initial_locale')
        _call(runtime, name, args, ((local, length),))
        utf8_string(runtime, string, local)
        value = _String.read(runtime, string)
        bounded_copy(runtime, destination + offset, 64, value.get(16, 8) if value.get(0, 1) & 1 else string + 1)
        value.destroy()
    memory.store(rbp + 0x230, 1, 4, source='35E9640.initial_EnableLUA')
    _contract(runtime, registry[6], rbp + 0x230)
    memory.store(destination + 0x274, int(memory.load(rbp + 0x230, 4) != 0), 1, source='35E9640.EnableLUA')
    root = _terminated(runtime, runtime.image_base + image['volume_root_rva'], 1)
    volume, filesystem = rbp + 0x428, rbp + 0x130
    memory.write(volume, bytes(260), source='35E9640.initial_volume_name')
    memory.write(filesystem, bytes(260), source='35E9640.initial_filesystem_name')
    serial, maximum, flags = rbp + 0x534, rbp + 0x400, rbp + 0x404
    for pointer in (serial, maximum, flags):
        memory.store(pointer, 0, 4, source='35E9640.initial_volume_DWORD')
    _call(runtime, 'GetVolumeInformationA', (root, True, 260, True, True, True, True, 260),
          ((volume, 260), (serial, 4), (maximum, 4), (flags, 4), (filesystem, 260)))
    memory.store(destination + 0x278, memory.load(serial, 4), 4, source='35E9640.volume_serial')
    total, free, scheme = rbp + 0x3F8, rbp + 0x3F0, rbp + 0x420
    for pointer in (total, free, scheme):
        memory.store(pointer, 0, 8, source='35E9640.initial_disk_and_power')
    if _call(runtime, 'GetDiskFreeSpaceExA', (root, False, True, True), ((total, 8), (free, 8))) & 0xFFFFFFFF:
        memory.store(destination + 0x280, memory.load(total, 8), 8, source='35E9640.disk_total')
        memory.store(destination + 0x288, memory.load(free, 8), 8, source='35E9640.disk_free')
    status, effects = _observe(runtime, 'PowerGetActiveScheme', (0,))
    if not isinstance(effects, tuple) or len(effects) != 2:
        raise InputError('system record power scheme requires raw pointer and foreign images')
    pointer_raw, foreign = effects
    if not isinstance(pointer_raw, bytes) or len(pointer_raw) > 8:
        raise InputError('system record power scheme pointer exceeds its output buffer')
    memory.write(scheme, pointer_raw, source='35E9640.power_scheme_pointer')
    pointer = memory.load(scheme, 8)
    _foreign_output(runtime, (pointer, foreign))
    if not status & 0xFFFFFFFF and pointer:
        guid, label = memory.read(pointer, 16), bytes.fromhex(image['custom_power_hex'])
        for rva, raw_label in image['power_labels'].items():
            if guid == memory.read(runtime.image_base + int(rva), 16):
                label = bytes.fromhex(raw_label)
                break
        _copy_value(runtime, destination + 0x290, 512, label)
        released = _call(runtime, 'LocalFree', (pointer,))
        if not released and any(address == pointer for address, raw in foreign):
            memory.unmap(pointer)
    for item in registry[7:]:
        _contract(runtime, item, destination + item['owner_offset'])
    mounted_volume(runtime, destination + 0x854, 16)
    firmware_uuid(runtime, destination + 0x7D4, 64)
    memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    functions = {0x35E9640: (capture, 1), 0x3C715D0: (registry_string, 5), 0x3C716B0: (registry_dword, 4),
                 0x3C71590: (bounded_copy, 3), 0x3C712C0: (utf8_string, 2), 0x35EC010: (admin_flag, 0),
                 0x35EC180: (mounted_volume, 2), 0x35EC530: (firmware_uuid, 2)}
    if rva not in functions or len(values) != functions[rva][1]:
        raise InputError('system record source interface argument count mismatch')
    return functions[rva][0](runtime, *values)
