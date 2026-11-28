import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_cache import _WideString, _wide_to_ansi
from .primary_device_cold import _com, _foreign_output, _observe as _cold_observe, _plain as _cold_plain, _release
from .primary_device_collector import _terminated
from .primary_device_hardware import _move
from .primary_device_identifiers import _cache_node
from .primary_logger import _cstring, _String, _Tree, log
from .primary_memory import PrimaryMemoryLimit, UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = '34e5da2807e91eb4c4253cd5bf1712c4735e71192d16209c36c7ca4d41d11136'
_IMPORTS = {'VirtualQuery': 0x4910428, 'VariantClear': 0x4910908,
            'MultiByteToWideChar': 0x49101F0, 'WideCharToMultiByte': 0x4910460}
_COLLECTORS = (0x2E15D90, 0x2E18240, 0x2E191B0, 0x2E1A7C0,
               0x2E1D1B0, 0x2E1E160, 0x2E1F6D0, 0x2E20C10)


def _image():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/device-wmi-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device WMI image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device WMI import identity mismatch')
    return image


def install_image(memory, image_base):
    for segment in _image()['segments']:
        address, raw = image_base + segment['rva'], bytes.fromhex(segment['hex'])
        try:
            memory._span(address, len(raw))
        except PrimaryMemoryLimit:
            memory.map(address, bytearray(raw), name='fixed device WMI image', initialized=True)
        else:
            if memory.read(address, len(raw)) != raw:
                raise InputError('shared device WMI image identity mismatch')


def _observe(runtime, name, arguments):
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
        raise PrimarySemanticUnavailable('device WMI current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device WMI OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _output(runtime, destination, raw, capacity, name):
    if not isinstance(raw, bytes) or len(raw) > capacity:
        raise InputError('device WMI requires bounded raw output effects: ' + name)
    runtime.memory.write(destination, raw, source=name)


def _log(runtime, line, *values):
    item = _image()['logs'][str(line)]
    runtime.events.append(('device.WMI_log', line))
    return log(runtime, bytes.fromhex(item['source_file_hex']), line,
               bytes.fromhex(item['template_hex']), bytes.fromhex(item['tag_hex']), item['severity'], *values)


def _allocate_bstr(runtime, raw):
    pointer, effects = _cold_observe(runtime, 'SysAllocString', (raw,))
    if type(pointer) is not int or not 0 <= pointer < 1 << 64 or not isinstance(effects, bytes) or len(effects) > 4096:
        raise InputError('device WMI BSTR requires a bounded pointer and explicit raw character image')
    if pointer:
        if not effects:
            raise UnknownMemory('device WMI successful BSTR allocation requires its actual character bytes')
        runtime.memory.map(pointer, bytearray(effects), name='observed device WMI BSTR', initialized=True)
    return pointer


def _wrapper(runtime):
    pointer = runtime._operator_new(24)
    runtime.memory.store(pointer + 8, 0, 8, source='2E13C70.BSTR_empty_ansi')
    runtime.memory.store(pointer + 16, 1, 4, source='2E13C70.BSTR_reference_count')
    return pointer


def _destroy_bstr(runtime, wrapper):
    memory = runtime.memory
    references = (memory.load(wrapper + 16, 4) - 1) & 0xFFFFFFFF
    memory.store(wrapper + 16, references, 4, source='2E13C70.BSTR_release')
    if references:
        return
    pointer = memory.load(wrapper, 8)
    if pointer:
        _cold_plain(runtime, 'SysFreeString', (pointer,))
        memory.unmap(pointer)
        memory.store(wrapper, 0, 8, source='2E13C70.BSTR_cleared')
    if memory.load(wrapper + 8, 8):
        raise PrimarySemanticUnavailable('device WMI cached ANSI BSTR cleanup requires actual array ownership')
    runtime._free_allocation(wrapper)


def ansi_bstr(runtime, source):
    if not source:
        return 0
    raw = _cstring(runtime, source) + b'\0'
    if len(raw) > 0x7FFFFFFF:
        raise PrimarySemanticUnavailable('3E68580 oversized input requires its actual COM exception effects')
    result, effects = _observe(runtime, 'MultiByteToWideChar', (0, 0, raw, len(raw), False, 0))
    if effects != b'':
        raise InputError('device WMI BSTR size query has no destination effects')
    count = result & 0xFFFFFFFF
    if not 0 < count < 4096:
        raise PrimarySemanticUnavailable('3E68580 failed or heap conversion requires actual CRT/COM effects')
    frame, ignored = _frame(runtime, (2 * count + 15) & ~15, '3E68580.temporary_UTF16')
    result, effects = _observe(runtime, 'MultiByteToWideChar', (0, 0, raw, len(raw), True, count))
    _output(runtime, frame, effects, 2 * count, '3E6867D.UTF16_output')
    if not result & 0xFFFFFFFF:
        raise PrimarySemanticUnavailable('3E68580 failed conversion requires its actual COM exception effects')
    pointer = _allocate_bstr(runtime, _terminated(runtime, frame, 2))
    if not pointer:
        raise PrimarySemanticUnavailable('3E68580 failed BSTR allocation requires its actual COM exception effects')
    runtime.memory.unmap(frame)
    return pointer


def wide_to_ansi(runtime, destination, source):
    runtime.memory.write(destination, bytes(24), source='2E09930.empty_ANSI_String')
    _wide_to_ansi(runtime, source, destination)
    return destination


def _clone_wide(runtime, value):
    if value.get(0, 1) & 1:
        return _WideString.construct(runtime, value.value())
    return _WideString(runtime, value.header, value.known)


def property_list(runtime, destination, descriptor):
    memory = runtime.memory
    memory.store(destination, destination, 8, source='2DEB5E0.property_list_previous')
    memory.store(destination + 8, destination, 8, source='2DEB5E0.property_list_next')
    memory.store(destination + 16, 0, 8, source='2DEB5E0.property_list_size')
    first, count = memory.load(descriptor, 8), memory.load(descriptor + 8, 8)
    if count > 4096:
        raise PrimaryProgramLimit('WMI property list exceeds the bounded offline domain')
    for index in range(count):
        node = runtime._operator_new(40)
        memory.store(node, 0, 8, source='2DEB5E0.initial_property_node')
        _clone_wide(runtime, _WideString.read(runtime, first + 24 * index)).write_to(node + 16)
        previous = memory.load(destination, 8)
        memory.store(node + 8, destination, 8, source='2DEB5E0.property_next')
        memory.store(node, previous, 8, source='2DEB5E0.property_previous')
        memory.store(previous + 8, node, 8, source='2DEB5E0.property_link')
        memory.store(destination, node, 8, source='2DEB5E0.property_tail')
        memory.store(destination + 16, index + 1, 8, source='2DEB5E0.property_count')
    return destination


def _properties(runtime, sentinel):
    node, seen = runtime.memory.load(sentinel + 8, 8), set()
    while node != sentinel:
        if not node or node in seen or len(seen) >= 4096:
            raise PrimaryProgramLimit('WMI property list cycle or traversal bound')
        seen.add(node)
        yield node
        node = runtime.memory.load(node + 8, 8)


def _valid_bstr(runtime, pointer, buffer):
    if pointer < 0x10000:
        return False
    result, effects = _observe(runtime, 'VirtualQuery', (pointer, 48))
    _output(runtime, buffer, effects, 48, '2E13F7C.VirtualQuery_output')
    return bool(result) and not runtime.memory.load(buffer + 36, 1) & 1


def query(runtime, owner, statement, properties, output):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x1A8, '2E13C70.WMI_query_frame')
    services = memory.load(owner, 8)
    if not services:
        memory.unmap(frame)
        return None
    memory.store(rbp, 0, 8, source='2E13CB4.empty_WMI_enumerator')
    statement_wrapper = _wrapper(runtime)
    statement_bstr = _allocate_bstr(runtime, _terminated(runtime, statement, 2))
    memory.store(statement_wrapper, statement_bstr, 8, source='2E13CE9.query_BSTR')
    if not statement_bstr and statement:
        raise PrimarySemanticUnavailable('2E15172 failed query BSTR requires its actual COM exception effects')
    language_wrapper = _wrapper(runtime)
    language_bstr = ansi_bstr(runtime, runtime.image_base + _image()['language_rva'])
    memory.store(language_wrapper, language_bstr, 8, source='2E13D27.language_BSTR')
    result, effects = _com(runtime, services, 0xA0, 'IWbemServices.ExecQuery',
                           (language_bstr, statement_bstr, 0x30, 0))
    enumerator = _foreign_output(runtime, effects)
    memory.store(rbp, enumerator, 8, source='2E13D54.enumerator_output')
    _destroy_bstr(runtime, language_wrapper)
    _destroy_bstr(runtime, statement_wrapper)
    if result & 0x80000000:
        _log(runtime, 115, result & 0xFFFFFFFF)
        memory.unmap(frame)
        return None
    memory.store(rbp + 8, 0, 8, source='2E13D7E.empty_WMI_object')
    memory.store(rbp + 0x3C, 0, 4, source='2E13D86.empty_WMI_count')
    if not enumerator:
        raise PrimarySemanticUnavailable('2E1514D successful null enumerator requires its actual fault semantics')
    ignored, effects = _com(runtime, enumerator, 0x20, 'IEnumWbemClassObject.Next', (0xFFFFFFFF, 1))
    if not isinstance(effects, tuple) or len(effects) != 3:
        raise InputError('WMI Next requires object pointer,raw count and foreign images')
    pointer, count, images = effects
    current = _foreign_output(runtime, (pointer, images))
    memory.store(rbp + 8, current, 8, source='2E13DB5.WMI_object_output')
    _output(runtime, rbp + 0x3C, count, 4, '2E13DB5.WMI_count_output')
    if memory.load(rbp + 0x3C, 4):
        for node in _properties(runtime, properties):
            _clone_wide(runtime, _WideString.read(runtime, node + 16)).write_to(rbp + 0x20)
            wide = _WideString.read(runtime, rbp + 0x20)
            source = memory.load(rbp + 0x30, 8) if memory.load(rbp + 0x20, 1) & 1 else rbp + 0x22
            property_name = _terminated(runtime, source, 2)
            result, effects = _com(runtime, current, 0x20, 'IWbemClassObject.Get', (property_name, 0, 0, 0))
            if not isinstance(effects, tuple) or len(effects) != 2:
                raise InputError('WMI Get requires raw VARIANT bytes and explicit foreign images')
            raw, images = effects
            _foreign_output(runtime, (0, images))
            _output(runtime, rbp - 0x40, raw, 24, '2E13E25.VARIANT_output')
            wide_to_ansi(runtime, rbp - 0x18, rbp + 0x20)
            key = _String.read(runtime, rbp - 0x18)
            target, inserted = _cache_node(runtime, output - 8, key)
            _invoke(runtime, 0x75BEB0, target + 56, runtime.image_base + _image()['empty_rva'], 0)
            if result & 0x80000000:
                _log(runtime, 143, key.value(), result & 0xFFFFFFFF)
            else:
                kind = memory.load(rbp - 0x40, 2)
                pointer = memory.load(rbp - 0x38, 8) if kind == 8 else 0
                if kind == 8 and pointer and _valid_bstr(runtime, pointer, rbp + 0x98):
                    _WideString.construct(runtime, _terminated(runtime, pointer, 2)[:-2]).write_to(rbp + 0x60)
                    wide_to_ansi(runtime, rbp + 0x98, rbp + 0x60)
                    target, inserted = _cache_node(runtime, output - 8, key)
                    _move(runtime, target + 56, rbp + 0x98)
                    memory.store(rbp + 0x98, 0, 2, source='2E14BF5.cleared_moved_String_tag')
                    _WideString.read(runtime, rbp + 0x60).destroy()
                    ignored, effects = _observe(runtime, 'VariantClear', (memory.read(rbp - 0x40, 24),))
                    _output(runtime, rbp - 0x40, effects, 24, '2E14C11.VariantClear_output')
                elif kind in (3, 22, 23):
                    _invoke(runtime, 0x75E7B0, rbp + 0x98, memory.load(rbp - 0x38, 4))
                    target, inserted = _cache_node(runtime, output - 8, key)
                    _move(runtime, target + 56, rbp + 0x98)
                else:
                    _log(runtime, 139, key.value(), kind)
            key.destroy()
            wide.destroy()
        _release(runtime, current)
    _release(runtime, enumerator)
    memory.unmap(frame)
    return None


def _destroy_list(runtime, sentinel):
    nodes = list(_properties(runtime, sentinel))
    if nodes:
        runtime.memory.store(sentinel, sentinel, 8, source='2E17C5B.empty_property_tail')
        runtime.memory.store(sentinel + 8, sentinel, 8, source='2E17C5B.empty_property_head')
        runtime.memory.store(sentinel + 16, 0, 8, source='2E17C5B.empty_property_count')
    for node in nodes:
        _WideString.read(runtime, node + 16).destroy()
        runtime._free_allocation(node)


def _destroy_tree(runtime, node, depth=0):
    if not node:
        return
    if depth > 256:
        raise PrimaryProgramLimit('WMI tree cleanup exceeds its bounded depth')
    _destroy_tree(runtime, runtime.memory.load(node, 8), depth + 1)
    _destroy_tree(runtime, runtime.memory.load(node + 8, 8), depth + 1)
    _String.read(runtime, node + 56).destroy()
    _String.read(runtime, node + 32).destroy()
    runtime._free_allocation(node)


def collect(runtime, entry, owner):
    memory, definition = runtime.memory, _image()['collectors'][str(entry)]
    frame, rbp = _frame(runtime, 0x400, 'WMI.property_collector_' + hex(entry))
    properties, tree, descriptor = frame + 0x10, frame + 0x40, frame + 0x60
    memory.store(tree, tree + 8, 8, source='WMI.empty_result_tree_begin')
    memory.write(tree + 8, bytes(16), source='WMI.empty_result_tree_root_count')
    first = frame + 0x180
    values = []
    for index, raw in enumerate(definition['properties_hex']):
        value = _WideString.construct(runtime, bytes.fromhex(raw))
        value.write_to(first + 24 * index)
        values.append(value)
    memory.store(descriptor, first, 8, source='WMI.property_array_begin')
    memory.store(descriptor + 8, len(values), 8, source='WMI.property_array_count')
    property_list(runtime, properties, descriptor)
    for value in reversed(values):
        value.destroy()
    statement = frame + 0x80
    memory.write(statement, bytes.fromhex(definition['query_hex']), source='WMI.decoded_query_statement')
    query(runtime, owner, statement, properties, tree)
    for item in definition['writes']:
        key = _String.construct(runtime, bytes.fromhex(item['key_hex']))
        node, inserted = _cache_node(runtime, tree - 8, key, move=True)
        if _String.read(runtime, node + 56).value():
            _invoke(runtime, 0x75CEC0, owner + item['offset'], node + 56)
        if not inserted:
            key.destroy()
    _destroy_list(runtime, properties)
    _destroy_tree(runtime, memory.load(tree + 8, 8))
    memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva in _COLLECTORS and len(values) == 1:
        return collect(runtime, rva, values[0])
    definitions = {0x2E13C70: (query, 4), 0x3E68580: (ansi_bstr, 1),
                   0x2E09930: (wide_to_ansi, 2), 0x2DEB5E0: (property_list, 2)}
    function, count = definitions[rva]
    if len(values) != count:
        raise InputError('device WMI source interface argument count mismatch')
    return function(runtime, *values)
