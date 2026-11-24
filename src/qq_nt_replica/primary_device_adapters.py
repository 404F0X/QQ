import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_collector import _new_array
from .primary_logger import _cstring, _String, _Tree
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = 'aed2884c3eb5c338a5f0d2dd933a549239819e797792c462e472f1da21dd8abf'
_IMPORTS = {'LoadLibraryA': 0x4910170, 'FreeLibrary': 0x490FD80,
            'GetProcAddress': 0x490FF40, 'GetTickCount': 0x490FFE8}
_RECORD = 0x1C8
_LIMIT = 1 << 20


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/device-adapter-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device adapter image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device adapter imports identity mismatch')
    return image


def install_image(memory, image_base):
    image = _image()
    for segment in image['segments']:
        raw = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            pointer = int.from_bytes(raw[offset:offset + 8], 'little')
            raw[offset:offset + 8] = (pointer - image['image_base'] + image_base).to_bytes(8, 'little')
        if segment['rva'] in (0x6744A10, image['locale_global_rva'], image['wide_ctype_rva']):
            if memory.read(image_base + segment['rva'], len(raw)) != raw:
                raise InputError('fixed shared CRT locale image identity mismatch')
            continue
        memory.map(image_base + segment['rva'], raw, name='fixed device adapter source image', initialized=True)


def _observe(runtime, name, arguments):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('device adapter current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device adapter OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _plain(runtime, name, arguments):
    result, effects = _observe(runtime, name, arguments)
    if effects != b'':
        raise InputError('device adapter operation has no output buffer: ' + name)
    return result


def _error(runtime, owner, bits):
    runtime.memory.store(owner + 0x30, runtime.memory.load(owner + 0x30, 4) | bits, 4,
                         source='1BEACxx.adapter_error_bits')


def _release_library(runtime, owner):
    handle = runtime.memory.load(owner + 8, 8)
    if handle:
        _plain(runtime, 'FreeLibrary', (handle,))
        runtime.memory.store(owner + 8, 0, 8, source='1BEACxx.released_adapter_library')


def _resolve(runtime, owner):
    image, memory = _image(), runtime.memory
    handle = memory.load(owner + 8, 8)
    if not handle:
        handle = _plain(runtime, 'LoadLibraryA', (_cstring(runtime, runtime.image_base + image['library_rva']),))
        memory.store(owner + 8, handle, 8, source='1BEAD1A.current_adapter_library')
        if not handle:
            return 0, 1
    target = _plain(runtime, 'GetProcAddress', (handle, _cstring(runtime, runtime.image_base + image['symbol_rva'])))
    return target, 0 if target else 2


def _adapter_effects(runtime, target, buffer, size_pointer):
    from .primary_device_hardware import AdapterBufferEffect, apply_adapter_buffer
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device adapter GetAdaptersInfo observation')
    size = runtime.memory.load(size_pointer, 4)
    result, effects = runtime.worker_observations.take(runtime, 'GetAdaptersInfo', (target, bool(buffer), size))
    if (not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], (bytes, AdapterBufferEffect))
            or effects[1] is not None
            and (type(effects[1]) is not int or not 0 <= effects[1] <= 0xFFFFFFFF)):
        raise InputError('adapter information requires explicit raw buffer and size DWORD effects')
    physical = runtime.allocations.get(buffer, 0) if buffer else 0
    apply_adapter_buffer(runtime, buffer, min(size, physical, _LIMIT), effects[0], source='1BEACxx.GetAdaptersInfo_output')
    if effects[1] is not None:
        runtime.memory.store(size_pointer, effects[1], 4, source='1BEACxx.GetAdaptersInfo_size')
    return result & 0xFFFFFFFF


def query_size(runtime, owner, destination):
    if not destination:
        _error(runtime, owner, 8)
        return 0
    target, error = _resolve(runtime, owner)
    if error:
        _error(runtime, owner, error | (8 if error == 1 else 0))
        _release_library(runtime, owner)
        return 0
    runtime.memory.store(destination, 0, 4, source='1BEAD35.initial_adapter_size')
    result = _adapter_effects(runtime, target, 0, destination)
    if result != 111:
        _error(runtime, owner, 4)
    _release_library(runtime, owner)
    return int(result == 111)


def fill_buffer(runtime, owner, destination, capacity):
    frame, ignored = _frame(runtime, 0x38, '1BEABF0.adapter_fill_frame')
    pointer = frame + 0x2C
    runtime.memory.store(pointer, capacity, 4, source='1BEAC0B.adapter_fill_capacity')
    target, error = _resolve(runtime, owner)
    if error:
        _error(runtime, owner, 0x81 if error == 1 else 0x100)
        _release_library(runtime, owner)
        runtime.memory.unmap(frame)
        return 0
    result = _adapter_effects(runtime, target, destination, pointer)
    if result:
        _error(runtime, owner, {111: 0x200, 87: 0x400, 232: 0x800, 50: 0x1000}.get(result, 0x2000))
    _release_library(runtime, owner)
    runtime.memory.unmap(frame)
    return int(result == 0)


def initialize_buffer(runtime, owner):
    memory = runtime.memory
    frame, ignored = _frame(runtime, 0x38, '1BEA500.adapter_buffer_frame')
    pointer = frame + 0x2C
    memory.store(owner + 0x30, 0, 4, source='1BEA518.clear_adapter_errors')
    memory.store(pointer, 0, 4, source='1BEA51F.initial_adapter_size')
    previous = memory.load(owner + 0x10, 8)
    if previous:
        runtime._free_allocation(previous)
        memory.store(owner + 0x10, 0, 8, source='1BEA535.release_old_adapter_buffer')
    if not query_size(runtime, owner, pointer):
        _error(runtime, owner, 0x10)
        memory.unmap(frame)
        return 0
    size = memory.load(pointer, 4)
    buffer = _new_array(runtime, size + 0x580)
    runtime.allocations[buffer] = runtime._device_arrays.pop(buffer)
    memory.store(owner + 0x10, buffer, 8, source='1BEA566.adapter_buffer')
    result = fill_buffer(runtime, owner, buffer, size)
    if not result:
        runtime._free_allocation(buffer)
        memory.store(owner + 0x10, 0, 8, source='1BEA592.release_failed_adapter_buffer')
        _error(runtime, owner, 0x40)
    memory.unmap(frame)
    return result


def construct(runtime, owner):
    runtime.memory.store(owner, runtime.image_base + 0x4148998, 8, source='1BE87BA.adapter_vtable')
    runtime.memory.write(owner + 8, bytes(44), source='1BE87C0.empty_adapter_owner')
    return owner


def destroy(runtime, owner):
    memory = runtime.memory
    memory.store(owner, runtime.image_base + 0x4148998, 8, source='1BE87ED.adapter_vtable')
    pointer = memory.load(owner + 0x10, 8)
    if pointer:
        runtime._free_allocation(pointer)
        memory.store(owner + 0x10, 0, 8, source='1BE87FE.release_adapter_buffer')
    _release_library(runtime, owner)
    begin = memory.load(owner + 0x18, 8)
    memory.store(owner + 0x20, begin, 8, source='1BE8829.clear_adapter_records')
    if begin:
        runtime._free_allocation(begin)
    return None


def _append_record(runtime, vector, source):
    memory = runtime.memory
    begin, end, limit = (memory.load(vector + offset, 8) for offset in (0, 8, 16))
    if end < begin or limit < end or (end - begin) % _RECORD or (limit - begin) % _RECORD:
        raise PrimaryProgramLimit('adapter record vector has invalid current bounds')
    if end == limit:
        size, capacity = (end - begin) // _RECORD, (limit - begin) // _RECORD
        capacity = max(size + 1, 2 * capacity)
        if capacity * _RECORD > _LIMIT:
            raise PrimaryProgramLimit('adapter record vector exceeds the bounded offline domain')
        target = runtime._operator_new(capacity * _RECORD)
        memory.copy_disjoint(target + size * _RECORD, source, _RECORD, label='1BEA9EC.new_adapter_record')
        if size:
            memory.copy_disjoint(target, begin, size * _RECORD, label='1BEAA02.move_previous_adapter_records')
        memory.store(vector, target, 8, source='1BEAA18.adapter_begin')
        memory.store(vector + 8, target + (size + 1) * _RECORD, 8, source='1BEAA1C.adapter_end')
        memory.store(vector + 16, target + capacity * _RECORD, 8, source='1BEAA20.adapter_capacity')
        if begin:
            runtime._free_allocation(begin)
    else:
        memory.copy_disjoint(end, source, _RECORD, label='1BEA91F.append_adapter_record')
        memory.store(vector + 8, end + _RECORD, 8, source='1BEA92B.adapter_end')


def parse_buffer(runtime, owner):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x268, '1BEA5C0.adapter_parser_frame')
    pointer, produced, seen = memory.load(owner + 0x10, 8), False, set()
    record = rbp - 0x58
    while pointer:
        if pointer in seen or len(seen) >= 256:
            raise PrimaryProgramLimit('adapter information linked list exceeds its bounded traversal')
        seen.add(pointer)
        name, description = (_String.construct(runtime, _cstring(runtime, pointer + offset)) for offset in (0xC, 0x110))
        kind, node, addresses = memory.load(pointer + 0x1A4, 4), pointer + 0x1B8, set()
        while node:
            if node in addresses or len(addresses) >= 256:
                raise PrimaryProgramLimit('adapter address linked list exceeds its bounded traversal')
            addresses.add(node)
            text = _String.construct(runtime, _cstring(runtime, node + 8))
            memory.write(record, bytes(0x1C0), source='1BEA80D.zero_adapter_record')
            memory.store(record + 0x1C0, kind, 4, source='1BEA818.adapter_type')
            for offset, value, maximum in ((8, name, 256), (0x10C, description, 128)):
                raw = value.value()[:maximum]
                memory.write(record + offset, raw, source='1BEA85D.adapter_record_text')
            count = memory.load(pointer + 0x194, 4, signed=True)
            if count > 0:
                if count > 8:
                    raise PrimarySemanticUnavailable('oversized adapter address writes beyond the recovered eight-byte material field')
                memory.copy_disjoint(record, pointer + 0x198, count, label='1BEA8C9.adapter_address_bytes')
            memory.copy_disjoint(record + 0x190, pointer + 0x1B8, 48, label='1BEA900.adapter_primary_address_record')
            _append_record(runtime, owner + 0x18, record)
            node = memory.load(node, 8)
            text.destroy()
            produced = True
        pointer = memory.load(pointer, 8)
        description.destroy()
        name.destroy()
    memory.unmap(frame)
    return int(produced)


def copy_records(runtime, destination, begin, end):
    memory = runtime.memory
    if end < begin or (end - begin) % _RECORD or end - begin > _LIMIT:
        raise PrimaryProgramLimit('adapter record copy has invalid observed bounds')
    size = end - begin
    first, last, limit = (memory.load(destination + offset, 8) for offset in (0, 8, 16))
    if size > limit - first:
        if first:
            memory.store(destination + 8, first, 8, source='1BED7D4.clear_old_adapter_records')
            runtime._free_allocation(first)
            memory.write(destination, bytes(24), source='1BED7E3.empty_adapter_vector')
            limit = 0
        physical = max(size, 2 * limit)
        first = runtime._operator_new(physical)
        memory.store(destination, first, 8, source='1BED851.adapter_copy_begin')
        memory.store(destination + 16, first + physical, 8, source='1BED857.adapter_copy_capacity')
    if size:
        memory.copy_disjoint(first, begin, size, label='1BED884.copy_adapter_records')
    memory.store(destination + 8, first + size, 8, source='1BED90A.adapter_copy_end')
    return None


def _cache_node(runtime, flags):
    memory, head = runtime.memory, runtime.image_base + 0x677BF68
    tree = _Tree(runtime, head)
    def initialize(node):
        memory.store(node + 32, flags, 4, source='1BE8B44.adapter_cache_flags')
        memory.store(node + 40, 0, 1, source='1BE8B48.adapter_cache_result')
        memory.write(node + 44, bytes(28), source='1BE8B4F.empty_adapter_cache_value')
    return tree.insert(flags, 72, initialize)


def filter_records(runtime, owner):
    memory = runtime.memory
    first, last = memory.load(owner + 0x18, 8), memory.load(owner + 0x20, 8)
    if last - first < 2 * _RECORD:
        return 0
    frame, rbp = _frame(runtime, 0x268, '1BEBD30.adapter_filter_frame')
    vector = rbp + 0x1B0
    memory.write(vector, bytes(24), source='1BEBD94.empty_filtered_adapter_vector')
    for pointer in range(first, last, _RECORD):
        memory.copy_disjoint(rbp - 0x58, pointer, _RECORD, label='1BEBDFC.current_adapter_record')
        description = _String.construct(runtime, _cstring(runtime, rbp + 0xB4))
        raw = description.value()
        if raw and memory.load(runtime.image_base + 0x6D8E630, 4):
            raise PrimarySemanticUnavailable('adapter filtering requires its actual nondefault CRT lowercase locale')
        lowered = raw.lower()
        if description.get(0, 1) & 1:
            memory.write(description.get(16, 8), lowered, source='1BEBEC8.lowercase_adapter_description')
        else:
            description.set(1, lowered + b'\0')
        address = memory.read(rbp - 0x58, 8)
        rejected = (b'vmware' in lowered or b'ppp/slip' in lowered or address[:4] == b'DEST'
                    or address[:3] == b'\0SE' or address == bytes(8) or b'RAS' in address)
        if not rejected:
            _append_record(runtime, vector, rbp - 0x58)
        description.destroy()
    temporary, end = memory.load(vector, 8), memory.load(vector + 8, 8)
    if temporary != end:
        memory.store(owner + 0x20, first, 8, source='1BEC261.clear_unfiltered_adapter_records')
        for pointer in range(temporary, end, _RECORD):
            _append_record(runtime, owner + 0x18, pointer)
    if temporary:
        runtime._free_allocation(temporary)
    result = int(memory.load(owner + 0x20, 8) != memory.load(owner + 0x18, 8))
    memory.unmap(frame)
    return result


def select_record(runtime, owner, normalize):
    memory = runtime.memory
    first, last = memory.load(owner + 0x18, 8), memory.load(owner + 0x20, 8)
    if last - first < 2 * _RECORD:
        return 0
    frame, ignored = _frame(runtime, 0x208, '1BED080.adapter_selection_frame')
    if normalize & 0xFF:
        for pointer in range(first, last, _RECORD):
            memory.copy_disjoint(frame + 0x40, pointer, _RECORD, label='1BED0FA.adapter_selection_record')
            description = _String.construct(runtime, _cstring(runtime, frame + 0x14C))
            raw = description.value()
            if raw and memory.load(runtime.image_base + 0x6D8E630, 4):
                raise PrimarySemanticUnavailable('adapter selection requires its actual nondefault CRT lowercase locale')
            if description.get(0, 1) & 1:
                memory.write(description.get(16, 8), raw.lower(), source='1BED1A9.lowercase_selection_description')
            description.destroy()
    selected = min(range(first, last, _RECORD), key=lambda pointer: memory.read(pointer, 8))
    memory.copy_disjoint(frame + 0x40, selected, _RECORD, label='1BED250.selected_adapter_record')
    memory.store(owner + 0x20, first, 8, source='1BED255.clear_adapter_selection_vector')
    _append_record(runtime, owner + 0x18, frame + 0x40)
    memory.unmap(frame)
    return 1


def enumerate_primary(runtime, owner, flags):
    memory, base = runtime.memory, runtime.image_base
    flags &= 0xFFFFFFFF
    if flags != 3:
        raise PrimarySemanticUnavailable('adapter flags require their additional source filtering paths')
    guard, head = base + 0x677BF80, base + 0x677BF68
    value = memory.load(guard, 4)
    if not value & 1:
        memory.store(guard, value | 1, 4, source='1BE8FE7.adapter_cache_guard')
        memory.write(head + 8, bytes(16), source='1BE8FF0.adapter_cache_root_count')
        memory.store(head, head + 8, 8, source='1BE8FFE.adapter_cache_begin')
        _invoke(runtime, 0x3E680B4, base + 0x1BEA4E0)
    node = next((item for item in _Tree(runtime, head).nodes() if memory.load(item + 32, 4) == flags), 0)
    if node and memory.load(node + 40, 1):
        copy_records(runtime, owner + 0x18, memory.load(node + 48, 8), memory.load(node + 56, 8))
        return 1
    if node:
        now = _plain(runtime, 'GetTickCount', ()) & 0xFFFFFFFF
        if (now - memory.load(node + 44, 4)) & 0xFFFFFFFF <= 0x36EE7F:
            copy_records(runtime, owner + 0x18, memory.load(node + 48, 8), memory.load(node + 56, 8))
            return 0
    result = 1
    if not memory.load(owner + 0x10, 8) and not initialize_buffer(runtime, owner):
        _error(runtime, owner, 0x4000)
        result = 0
    else:
        if parse_buffer(runtime, owner):
            filter_records(runtime, owner)
            select_record(runtime, owner, 1)
        pointer = memory.load(owner + 0x10, 8)
        if pointer:
            runtime._free_allocation(pointer)
            memory.store(owner + 0x10, 0, 8, source='1BE8A26.release_consumed_adapter_buffer')
    node = _cache_node(runtime, flags)
    memory.store(node + 40, result, 1, source='1BE8B93.adapter_cache_result')
    now = _plain(runtime, 'GetTickCount', ()) & 0xFFFFFFFF
    memory.store(node + 44, now, 4, source='1BE8C5B.adapter_cache_tick')
    copy_records(runtime, node + 48, memory.load(owner + 0x18, 8), memory.load(owner + 0x20, 8))
    return result


def collect(runtime, owner, method, flags):
    memory = runtime.memory
    memory.store(owner + 0x20, memory.load(owner + 0x18, 8), 8, source='1BE88AB.clear_adapter_records')
    method &= 0xFFFFFFFF
    if method > 3:
        return 0
    if method == 0:
        if enumerate_primary(runtime, owner, flags):
            return 1
        memory.store(owner + 0x20, memory.load(owner + 0x18, 8), 8, source='1BE88E5.clear_failed_adapter_records')
        return _invoke(runtime, 0x1BE9020, owner, flags)
    if method == 1:
        result = enumerate_primary(runtime, owner, flags)
        if not result:
            memory.store(owner + 0x20, memory.load(owner + 0x18, 8), 8, source='1BE893C.clear_failed_adapter_records')
        return result
    raise PrimarySemanticUnavailable('adapter method requires its actual alternate collector backend')


def _upper(runtime, character):
    image, memory, base = _image(), runtime.memory, runtime.image_base
    if memory.load(base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable('adapter hexadecimal uppercase requires its actual nondefault CRT locale')
    if not 0 <= character < 128:
        raise PrimarySemanticUnavailable('adapter hexadecimal contains a non-ASCII classification input')
    if not memory.load(base + image['wide_ctype_rva'] + 2 * (character + 1), 1) & 2:
        return character
    locale = memory.load(base + image['locale_global_rva'], 8)
    table = memory.load(locale + 0x118, 8)
    return memory.load(table + character, 1)


def adapter_material(runtime, destination, detail):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0xA8, '35D5A80.adapter_material_frame')
    memory.store(destination, 0, 2, source='35D5AA2.empty_adapter_material')
    owner = rbp - 0x58
    construct(runtime, owner)
    if collect(runtime, owner, 0, 3):
        first = memory.load(owner + 0x18, 8)
        if first != memory.load(owner + 0x20, 8):
            memory.store(rbp - 8, 16, 1, source='35D5ADB.raw_adapter_String_length')
            memory.copy_disjoint(rbp - 7, first, 8, label='35D5AE6.raw_adapter_String_bytes')
            memory.store(rbp + 1, 0, 1, source='35D5AEA.raw_adapter_String_nul')
            _invoke(runtime, 0x2E11240, rbp - 0x20, rbp - 7, 8)
            memory.copy_disjoint(destination + 16, rbp - 0x10, 8, label='35D5B05.move_adapter_hex_tail')
            memory.copy_disjoint(destination, rbp - 0x20, 16, label='35D5B0D.move_adapter_hex_head')
            value = _String.read(runtime, destination)
            pointer = value.get(16, 8) if value.get(0, 1) & 1 else destination + 1
            for index in range(len(value.value())):
                memory.store(pointer + index, _upper(runtime, memory.load(pointer + index, 1)), 1,
                             source='35D5B48.uppercase_adapter_hex')
            _invoke(runtime, 0x75BEB0, detail, first + 0x10C, len(_cstring(runtime, first + 0x10C)))
    destroy(runtime, owner)
    memory.unmap(frame)
    return destination


def _destroy_cache_tree(runtime, node):
    if not node:
        return
    memory = runtime.memory
    _destroy_cache_tree(runtime, memory.load(node, 8))
    _destroy_cache_tree(runtime, memory.load(node + 8, 8))
    begin = memory.load(node + 0x30, 8)
    if begin:
        memory.store(node + 0x38, begin, 8, source='1BED730.adapter_cache_end')
        runtime._free_allocation(begin)
    _invoke(runtime, 0xB75029, node)


def destroy_cache(runtime):
    return _destroy_cache_tree(runtime, runtime.memory.load(runtime.image_base + 0x677BF70, 8))


def invoke(runtime, rva, values):
    definitions = {0x1BE87B0: (construct, 1), 0x1BE87D0: (destroy, 1),
                   0x1BE88A0: (collect, 3), 0x1BE8960: (enumerate_primary, 2),
                   0x1BEA500: (initialize_buffer, 1), 0x1BEA5C0: (parse_buffer, 1),
                   0x1BEACF0: (query_size, 2), 0x1BEABF0: (fill_buffer, 3),
                   0x1BEBD30: (filter_records, 1), 0x1BED080: (select_record, 2),
                   0x1BED780: (copy_records, 3), 0x35D5A80: (adapter_material, 2),
                   0x1BEA4E0: (destroy_cache, 0)}
    function, count = definitions[rva]
    if len(values) != count:
        raise InputError('device adapter source interface argument count mismatch')
    return function(runtime, *values)
