from .errors import InputError
from .primary_device_collector import _terminated
from .primary_sdk_probes import _IMPORTS, _image, _observe, _plain
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _frame


def _open(runtime, root, path, output, access, target=None):
    result, effects = _observe(runtime, 'RegOpenKeyExW', (root, path, 0, access), target=target)
    if not isinstance(effects, bytes) or len(effects) > 8:
        raise InputError('SDK registry matcher open requires bounded raw handle effects')
    runtime.memory.write(output, effects, source='sdk.registry_matcher_handle_output')
    return not result & 0xFFFFFFFF


def _enumerate(runtime, frame, definition, index, target=None):
    memory = runtime.memory
    buffer = frame + definition['name_buffer_offset']
    memory.write(buffer, bytes(definition['buffer_bytes']), source='sdk.registry_matcher_name_clear')
    capacity = definition['enum_name_capacity']
    memory.store(frame + definition['name_length_offset'], capacity, 4, source='sdk.registry_matcher_name_capacity')
    result, effects = _observe(runtime, 'RegEnumKeyExW',
        (memory.load(frame + definition['parent_handle_offset'], 8), index, buffer, capacity, 0, 0, 0, 0),
        target=target)
    if (not isinstance(effects, tuple) or len(effects) != 2
            or not all(isinstance(value, bytes) for value in effects)
            or len(effects[0]) > 2 * capacity or len(effects[1]) > 4):
        raise InputError('SDK registry enumeration requires bounded raw name and length effects')
    memory.write(buffer, effects[0], source='sdk.registry_matcher_name_output')
    memory.write(frame + definition['name_length_offset'], effects[1], source='sdk.registry_matcher_name_length_output')
    return not result & 0xFFFFFFFF, len(effects[0]) > definition['buffer_bytes']


def match_subkeys(runtime, root, path, value, needle):
    memory, base = runtime.memory, runtime.image_base
    definition = _image()['registry_matcher']
    frame, ignored = _frame(runtime, definition['frame_size'], '1C29DA0.sdk_registry_matcher_frame')
    path_raw = _terminated(runtime, path, 2)[:-2]
    parent = frame + definition['parent_handle_offset']
    present, corrupted = False, False
    if _open(runtime, root, path_raw, parent, definition['access']):
        memory.store(frame + definition['value_pointer_offset'], value, 8, source='sdk.registry_matcher_value_pointer')
        memory.store(frame + definition['needle_pointer_offset'], needle, 8, source='sdk.registry_matcher_needle_pointer')
        ready, corrupted = _enumerate(runtime, frame, definition, 0)
        if ready:
            open_target = memory.load(base + _IMPORTS['RegOpenKeyExW'], 8)
            enum_target = memory.load(base + _IMPORTS['RegEnumKeyExW'], 8)
            index = 1
            while True:
                name = _terminated(runtime, frame + definition['name_buffer_offset'], 2)[:-2]
                child = frame + definition['child_handle_offset']
                if _open(runtime, memory.load(parent, 8), name, child, definition['access'], open_target):
                    buffer = frame + definition['data_buffer_offset']
                    memory.write(buffer, bytes(definition['buffer_bytes']), source='sdk.registry_matcher_data_clear')
                    memory.store(frame + definition['data_length_offset'], definition['buffer_bytes'], 4,
                                 source='sdk.registry_matcher_data_capacity')
                    name = _terminated(runtime, memory.load(frame + definition['value_pointer_offset'], 8), 2)[:-2]
                    result, effects = _observe(runtime, 'RegQueryValueExW',
                        (memory.load(child, 8), name, 0, None, buffer, definition['buffer_bytes']))
                    if (not isinstance(effects, tuple) or len(effects) != 2
                            or not all(isinstance(item, bytes) for item in effects)
                            or len(effects[0]) > definition['buffer_bytes'] or len(effects[1]) > 4):
                        raise InputError('SDK registry matcher query requires bounded raw data and length effects')
                    memory.write(buffer, effects[0], source='sdk.registry_matcher_data_output')
                    memory.write(frame + definition['data_length_offset'], effects[1], source='sdk.registry_matcher_data_length_output')
                    if not result & 0xFFFFFFFF:
                        text = _terminated(runtime, buffer, 2)[:-2]
                        needle_raw = _terminated(runtime, memory.load(frame + definition['needle_pointer_offset'], 8), 2)[:-2]
                        present = bool(_plain(runtime, 'StrStrIW', (text, needle_raw)))
                    _plain(runtime, 'RegCloseKey', (memory.load(child, 8),))
                if present:
                    break
                if index >= 1 << 20:
                    raise PrimaryProgramLimit('SDK registry enumeration exceeds the bounded offline domain')
                ready, overflow = _enumerate(runtime, frame, definition, index, enum_target)
                corrupted |= overflow
                index = (index + 1) & 0xFFFFFFFF
                if not ready:
                    break
        _plain(runtime, 'RegCloseKey', (memory.load(parent, 8),))
    if corrupted:
        raise PrimarySemanticUnavailable('1C29F67 registry enumeration overwrote its stack security-cookie storage')
    memory.unmap(frame)
    return int(present)
