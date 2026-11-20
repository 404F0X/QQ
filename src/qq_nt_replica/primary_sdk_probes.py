from .errors import InputError
from .primary_logger import _decode
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable


_IMPORTS = {'GetModuleHandleW': 0x490FF10, 'GetProcAddress': 0x490FF40,
            'RegOpenKeyW': 0x4910A30, 'RegCloseKey': 0x49109E0, 'PathFileExistsW': 0x4910AA8,
            'RegQueryValueExW': 0x4910A48, 'StrStrIW': 0x4910B28,
            'RegOpenKeyExW': 0x4910A28, 'RegEnumKeyExW': 0x4910A10}


def _image():
    from .primary_sdk_collection import _image as collection_image

    image = collection_image()['environment_probes']
    if image['imports'] != _IMPORTS:
        raise InputError('fixed SDK environment import identity mismatch')
    return image


def _observe(runtime, name, arguments, *, target=None):
    if target is None:
        target = runtime.memory.load(runtime.image_base + _IMPORTS[name], 8)
    if target != runtime.worker_imports.get(name):
        raise PrimarySemanticUnavailable('SDK detector current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing SDK detector OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _plain(runtime, name, arguments, *, target=None):
    result, effects = _observe(runtime, name, arguments, target=target)
    if effects != b'':
        raise InputError('SDK detector API requires empty output effects: ' + name)
    return result


def _literal(runtime, rbp, definition):
    memory = runtime.memory
    address = rbp + definition['marker_offset']
    raw = bytes.fromhex(definition['encrypted_hex'])
    memory.write(address, bytes((1, definition['seed'])) + raw + b'\0\0', source='sdk.detector_encrypted_literal')
    value = _decode(definition)
    memory.store(rbp + definition['counter_offset'], len(value), 8, source='sdk.detector_literal_counter')
    memory.write(address + 2, value, source='sdk.detector_decoded_literal')
    memory.store(address, 0, 1, source='sdk.detector_literal_decoded')
    return value


def _redirection(runtime, rbp, definition, enabled, module_import):
    memory, base = runtime.memory, runtime.image_base
    prefix = 'enable_' if enabled else 'disable_'
    offsets = definition.get('redirection_offsets', {}).get('enable' if enabled else 'disable')
    snapshot, target_offset = ((offsets['snapshot'], offsets['target']) if offsets is not None
                               else (0x298, 0x3B0) if enabled else (0x3B0, 0x408))
    target = memory.load(base + 0x677CEB8, 8)
    memory.store(rbp + snapshot, target, 8, source='sdk.detector_export_snapshot')
    if not target:
        symbol = _literal(runtime, rbp, definition['literals'][prefix + 'symbol']).split(b'\0', 1)[0]
        module = _literal(runtime, rbp, definition['literals'][prefix + 'module'])
        handle = _plain(runtime, 'GetModuleHandleW', (module,), target=module_import)
        target = _plain(runtime, 'GetProcAddress', (handle, symbol))
        memory.store(base + 0x677CEB8, target, 8, source='sdk.detector_export_cache')
    target = memory.load(base + 0x677CEB8, 8)
    memory.store(rbp + target_offset, target, 8, source='sdk.detector_current_export')
    if target:
        if runtime.worker_observations is None:
            raise UnknownMemory('missing SDK detector optional export observations')
        _, effects = runtime.worker_observations.take(runtime, 'Wow64EnableWow64FsRedirection', (target, enabled))
        if effects != b'':
            raise InputError('SDK detector optional redirection export has no output buffer')


def first_detector(runtime, rbp):
    from .primary_sdk_records import destroy_pair, insert

    memory, base = runtime.memory, runtime.image_base
    definition = _image()['first_detector']
    module_import = memory.load(base + _IMPORTS['GetModuleHandleW'], 8)
    _redirection(runtime, rbp, definition, 0, module_import)
    path = _literal(runtime, rbp, definition['literals']['registry'])
    result, effects = _observe(runtime, 'RegOpenKeyW', (0xFFFFFFFF80000002, path))
    if not isinstance(effects, bytes) or len(effects) > 8:
        raise InputError('SDK registry open requires bounded raw handle output effects')
    memory.write(rbp + 0x2F0, effects, source='sdk.detector_registry_handle_output')
    memory.store(rbp + 0x408, result & 0xFFFFFFFF, 4, source='1C03E9C.sdk_registry_status')
    present = not result & 0xFFFFFFFF
    if present:
        _plain(runtime, 'RegCloseKey', (memory.load(rbp + 0x2F0, 8),))
    memory.store(rbp + 0x248, int(present), 1, source='1C03F00.sdk_registry_present')
    _redirection(runtime, rbp, definition, 1, module_import)
    if present:
        pair = rbp + 0x540
        memory.store(pair, definition['key'], 8, source='1C042CA.sdk_registry_record_key')
        memory.write(pair + 8, bytes(144), source='sdk.registry_record_empty_strings')
        insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
        destroy_pair(runtime, pair)
    return module_import


def file_detector(runtime, rbp, module_import):
    from .primary_logger import log
    from .primary_sdk_collection import _image as collection_image
    from .primary_sdk_records import destroy_pair, insert

    memory, base = runtime.memory, runtime.image_base
    definition = _image()['file_detector']
    _redirection(runtime, rbp, definition, 0, module_import)
    present = False
    for group in definition['groups']:
        matched = False
        for index in group['paths']:
            path = _literal(runtime, rbp, definition['paths'][index])
            if _plain(runtime, 'PathFileExistsW', (path,)) & 0xFFFFFFFF:
                matched = True
                break
        if matched:
            template = _literal(runtime, rbp, group['template'])
            filename = _literal(runtime, rbp, group['file'])
            log(runtime, filename, group['log_line'], template,
                bytes.fromhex(collection_image()['tag_hex']), 1)
            present = True
    module_import = memory.load(base + _IMPORTS['GetModuleHandleW'], 8)
    _redirection(runtime, rbp, definition, 1, module_import)
    if present:
        pair = rbp + 0x540
        memory.store(pair, definition['key'], 8, source='1C08661.sdk_file_record_key')
        memory.write(pair + 8, bytes(144), source='sdk.file_record_empty_strings')
        insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
        destroy_pair(runtime, pair)
    return module_import


def _registry_present(runtime, rbp, definition, index):
    memory = runtime.memory
    path = _literal(runtime, rbp, definition['registry_paths'][index])
    result, effects = _observe(runtime, 'RegOpenKeyW', (0xFFFFFFFF80000002, path))
    if not isinstance(effects, bytes) or len(effects) > 8:
        raise InputError('SDK registry open requires bounded raw handle output effects')
    handle = rbp + definition['registry_handle_offsets'][index]
    memory.write(handle, effects, source='sdk.detector_registry_handle_output')
    memory.store(rbp + definition['registry_status_offsets'][index], result & 0xFFFFFFFF, 4,
                 source='sdk.detector_registry_status')
    present = not result & 0xFFFFFFFF
    if present:
        _plain(runtime, 'RegCloseKey', (memory.load(handle, 8),))
    return present


def service_detector(runtime, rbp, module_import):
    from .primary_sdk_records import destroy_pair, insert

    memory, base = runtime.memory, runtime.image_base
    definition = _image()['service_detector']
    _redirection(runtime, rbp, definition, 0, module_import)
    present = _registry_present(runtime, rbp, definition, 0)
    memory.store(rbp + 0xA0, int(present), 1, source='1C08E20.sdk_service_first_present')
    if not present:
        present = _registry_present(runtime, rbp, definition, 1)
    module_import = memory.load(base + _IMPORTS['GetModuleHandleW'], 8)
    _redirection(runtime, rbp, definition, 1, module_import)
    if present:
        pair = rbp + 0x540
        memory.store(pair, definition['key'], 8, source='1C0972D.sdk_service_record_key')
        memory.write(pair + 8, bytes(144), source='sdk.service_record_empty_strings')
        insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
        destroy_pair(runtime, pair)
    return module_import


def _query_value(runtime, rbp, definition, handle, name, buffer, query_import):
    memory = runtime.memory
    incoming_size = memory.load(rbp + definition['size_offset'], 4) if buffer is not None else None
    result, effects = _observe(runtime, 'RegQueryValueExW', (handle, name, 0, buffer, incoming_size),
                               target=query_import)
    if (not isinstance(effects, tuple) or len(effects) != 3
            or any(not isinstance(value, bytes) for value in effects)
            or len(effects[0]) > 4 or len(effects[1]) > 4
            or buffer is None and effects[2]
            or buffer is not None and len(effects[2]) > incoming_size):
        raise InputError('SDK registry query requires bounded raw type,size and data output effects')
    memory.write(rbp + definition['type_offset'], effects[0], source='sdk.registry_query_type_output')
    memory.write(rbp + definition['size_offset'], effects[1], source='sdk.registry_query_size_output')
    if buffer is not None:
        memory.write(buffer, effects[2], source='sdk.registry_query_data_output')
    return result


def _registry_value_present(runtime, rbp, definition, query_import):
    from .primary_device_collector import _delete_array, _new_array, _terminated

    memory, base = runtime.memory, runtime.image_base
    needle = _literal(runtime, rbp, definition['needle'])
    name = _literal(runtime, rbp, definition['name'])
    path = _literal(runtime, rbp, definition['path'])
    result, effects = _observe(runtime, 'RegOpenKeyW', (0xFFFFFFFF80000002, path))
    if not isinstance(effects, bytes) or len(effects) > 8:
        raise InputError('SDK registry open requires bounded raw handle output effects')
    memory.write(rbp + definition['handle_offset'], effects, source='sdk.detector_registry_handle_output')
    memory.store(rbp + definition['status_offset'], result & 0xFFFFFFFF, 4,
                 source='sdk.registry_value_open_status')
    if query_import is None:
        query_import = memory.load(base + _IMPORTS['RegQueryValueExW'], 8)
    if result & 0xFFFFFFFF:
        return False, query_import
    present = False
    handle = memory.load(rbp + definition['handle_offset'], 8)
    name = _terminated(runtime, rbp + definition['name']['marker_offset'] + 2, 2)[:-2]
    if not _query_value(runtime, rbp, definition, handle, name, None, query_import) & 0xFFFFFFFF:
        size = (memory.load(rbp + definition['size_offset'], 4) + 1) & 0xFFFFFFFF
        buffer = _new_array(runtime, size)
        memory.store(rbp + definition['buffer_offset'], buffer, 8, source='sdk.registry_value_array')
        memory.write(buffer, bytes(size), source='3EB2680.sdk_registry_value_zero_fill')
        handle = memory.load(rbp + definition['handle_offset'], 8)
        name = _terminated(runtime, rbp + definition['name']['marker_offset'] + 2, 2)[:-2]
        if not _query_value(runtime, rbp, definition, handle, name, buffer, query_import) & 0xFFFFFFFF:
            buffer = memory.load(rbp + definition['buffer_offset'], 8)
            value = _terminated(runtime, buffer, 2)[:-2]
            needle = _terminated(runtime, rbp + definition['needle']['marker_offset'] + 2, 2)[:-2]
            present = bool(_plain(runtime, 'StrStrIW', (value, needle)))
            memory.store(rbp + definition['match_offset'], int(present), 1,
                         source='sdk.registry_value_search_result')
        else:
            memory.store(rbp + definition['match_offset'], 0, 1, source='sdk.registry_value_read_failed')
        _delete_array(runtime, memory.load(rbp + definition['buffer_offset'], 8))
    _plain(runtime, 'RegCloseKey', (memory.load(rbp + definition['handle_offset'], 8),))
    return present, query_import


def value_detector(runtime, rbp, module_import):
    from .primary_sdk_records import destroy_pair, insert

    memory, base = runtime.memory, runtime.image_base
    definition = _image()['value_detector']
    _redirection(runtime, rbp, definition, 0, module_import)
    query_import, present = None, False
    for index, probe in enumerate(definition['probes']):
        present, query_import = _registry_value_present(runtime, rbp, probe, query_import)
        if not index:
            memory.store(rbp + 0x47, int(present), 1, source='1C0A351.sdk_registry_first_value_present')
        if present:
            break
    module_import = memory.load(base + _IMPORTS['GetModuleHandleW'], 8)
    _redirection(runtime, rbp, definition, 1, module_import)
    if present:
        pair = rbp + 0x540
        memory.store(pair, definition['key'], 8, source='1C0D26D.sdk_registry_value_record_key')
        memory.write(pair + 8, bytes(144), source='sdk.registry_value_record_empty_strings')
        insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
        destroy_pair(runtime, pair)
    return module_import


def cpu_detector(runtime, rbp, image_name='cpu_detector'):
    from .primary_device_hardware import _cpuid
    from .primary_sdk_records import destroy_pair, insert

    memory, base = runtime.memory, runtime.image_base
    definition = _image()[image_name]
    if definition.get('capture_cpuid', True):
        raw = _cpuid(runtime, definition['leaf'])
        chunks = [raw[index:index + 4] for index in (4, 8, 12)]
        for offset, chunk in zip((0x88, 0x30, 0), chunks):
            memory.write(rbp + offset, chunk, source='sdk.cpu_register_spill')
    else:
        chunks = [memory.read(rbp + offset, 4) for offset in definition['register_offsets']]
    for offset, chunk in zip((0x3B0, 0x408, 0x478), chunks):
        memory.write(rbp + offset, b'\x08' + chunk + b'\0', source='sdk.cpu_register_inline_string')
    first = chunks[0] + chunks[1]
    memory.write(rbp + 0x3B0, bytes((2 * len(first),)) + first + b'\0', source='sdk.cpu_vendor_first_append')
    memory.copy_disjoint(rbp + 0x2F0, rbp + 0x3B0, 24, label='sdk.cpu_vendor_first_move')
    memory.write(rbp + 0x3B0, bytes(24), source='sdk.cpu_vendor_first_moved_from')
    vendor = first + chunks[2]
    memory.write(rbp + 0x2F0, bytes((2 * len(vendor),)) + vendor + b'\0', source='sdk.cpu_vendor_second_append')
    memory.copy_disjoint(rbp + 0x540, rbp + 0x2F0, 24, label='sdk.cpu_vendor_second_move')
    memory.write(rbp + 0x2F0, bytes(24), source='sdk.cpu_vendor_second_moved_from')
    needle = _literal(runtime, rbp, definition['needle'])
    if 'vendor_pointer_spill_offset' in definition:
        memory.store(rbp + definition['vendor_pointer_spill_offset'], rbp + 0x541, 8,
                     source='1C18958.sdk_cpu_vendor_pointer')
    present = vendor.find(needle) >= 0
    module_import = (memory.load(base + _IMPORTS['GetModuleHandleW'], 8)
                     if definition.get('capture_module_import', True) else None)
    if present:
        pair = rbp + 0x540
        memory.store(pair, definition['key'], 8, source='sdk.cpu_record_key')
        memory.write(pair + 8, bytes(144), source='sdk.cpu_record_empty_strings')
        insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
        destroy_pair(runtime, pair)
    return module_import


def next_file_detector(runtime, rbp, module_import, image_name='next_file_detector'):
    from .primary_sdk_records import destroy_pair, insert

    memory, base = runtime.memory, runtime.image_base
    definition = _image()[image_name]
    _redirection(runtime, rbp, definition, 0, module_import)
    present = False
    for index, path in enumerate(definition['paths']):
        path = _literal(runtime, rbp, path)
        present = bool(_plain(runtime, 'PathFileExistsW', (path,)) & 0xFFFFFFFF)
        if not index:
            memory.store(rbp + definition['first_present_offset'], int(present), 1,
                         source='sdk.file_detector_first_present')
        if present:
            break
    module_import = memory.load(base + _IMPORTS['GetModuleHandleW'], 8)
    _redirection(runtime, rbp, definition, 1, module_import)
    if present:
        pair = rbp + 0x540
        memory.store(pair, definition['key'], 8, source='sdk.file_detector_record_key')
        memory.write(pair + 8, bytes(144), source='sdk.next_file_record_empty_strings')
        insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
        destroy_pair(runtime, pair)
    return module_import


def next_service_detector(runtime, rbp, module_import):
    from .primary_sdk_records import destroy_pair, insert

    memory, base = runtime.memory, runtime.image_base
    definition = _image()['next_service_detector']
    _redirection(runtime, rbp, definition, 0, module_import)
    present = _registry_present(runtime, rbp, definition, 0)
    memory.store(rbp + definition['first_present_offset'], int(present), 1,
                 source='1C0F6E0.sdk_next_service_first_present')
    if not present:
        present = _registry_present(runtime, rbp, definition, 1)
    _redirection(runtime, rbp, definition, 1, module_import)
    if present:
        pair = rbp + 0x540
        memory.store(pair, definition['key'], 8, source='1C0FE9A.sdk_next_service_record_key')
        memory.write(pair + 8, bytes(144), source='sdk.next_service_record_empty_strings')
        insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
        destroy_pair(runtime, pair)
    return module_import


def enumeration_detector(runtime, rbp, module_import, image_name='enumeration_detector'):
    from .primary_sdk_records import destroy_pair, insert
    from .primary_worker_consumer import _invoke

    memory, base = runtime.memory, runtime.image_base
    definition = _image()[image_name]
    _redirection(runtime, rbp, definition, 0, module_import)
    present = False
    for probe in definition['probes']:
        for name in ('needle', 'name', 'path'):
            _literal(runtime, rbp, probe[name])
        present = bool(_invoke(runtime, 0x1C29DA0, 0xFFFFFFFF80000002,
            *(rbp + probe[name]['marker_offset'] + 2 for name in ('path', 'name', 'needle'))))
        if present:
            break
    if definition['reload_enable_module_import']:
        module_import = memory.load(base + _IMPORTS['GetModuleHandleW'], 8)
    _redirection(runtime, rbp, definition, 1, module_import)
    if present:
        pair = rbp + 0x540
        memory.store(pair, definition['key'], 8, source='sdk.enumeration_record_key')
        memory.write(pair + 8, bytes(144), source='sdk.enumeration_record_empty_strings')
        insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
        destroy_pair(runtime, pair)
    return module_import
