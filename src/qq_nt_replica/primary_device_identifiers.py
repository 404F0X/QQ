from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_collector import assign_string, _delete_array, _new_array, _terminated
from .primary_logger import _cstring, _srw, _String, _Tree, log
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _frame
from .primary_worker_consumer import _invoke


_IMAGE_SHA256 = '0ceeb4e3579286c202c0fefaa13e1698fbcd87a2a5106e196ffab2f1a5b2ead7'
_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20
_IMPORTS = {'SHGetFolderPathW': 0x49107E0, 'PathFileExistsW': 0x4910AA8,
            'RegCreateKeyExA': 0x49109E8, 'RegSetValueExA': 0x4910A50, 'RegCloseKey': 0x49109E0}


def _image():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/device-identifiers-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device identifier image identity mismatch')
    return json.loads(raw)


def install_image(memory, image_base):
    image = _image()
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device identifier import identity mismatch')
    for segment in image['segments']:
        memory.map(image_base + segment['rva'], bytearray.fromhex(segment['hex']),
                   name='fixed device identifier image', initialized=True)


def _observe(runtime, name, arguments):
    from .primary_device_collector import _IMPORTS as conversion_imports

    expected = runtime.worker_imports.get(name)
    slot = (_IMPORTS | conversion_imports)[name]
    if expected is None or runtime.memory.load(runtime.image_base + slot, 8) != expected:
        raise PrimarySemanticUnavailable('device identifier current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device identifier OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _length(runtime, address):
    tag = runtime.memory.load(address, 1)
    return runtime.memory.load(address + 8, 8) if tag & 1 else tag >> 1


def _data(runtime, address):
    return runtime.memory.load(address + 16, 8) if runtime.memory.load(address, 1) & 1 else address + 1


def _key(name):
    return bytes.fromhex(_image()['keys'][name])


def _log(runtime, kind, line, *values):
    item = _image()['logs'][kind + ':' + str(line)]
    runtime.events.append(('device.identifier_log', kind, line))
    return log(runtime, bytes.fromhex(item['source_file_hex']), line,
               bytes.fromhex(item['template_hex']), bytes.fromhex(item['tag_hex']), item['severity'], *values)


@dataclass(frozen=True)
class DeviceConfigurationBinding:
    receiver: int
    target: int
    callback: object

    def __post_init__(self):
        if (type(self.receiver) is not int or not 0 < self.receiver <= _MASK64 or
                type(self.target) is not int or not 0 < self.target <= _MASK64 or not callable(self.callback)):
            raise InputError('device configuration requires its receiver, virtual target and callable effects')

    def write(self, runtime, receiver, target, key, value):
        if receiver != self.receiver or target != self.target:
            raise PrimarySemanticUnavailable('device configuration current provider or virtual target is not bound')
        runtime.events.append(('device.configuration', receiver, target,
                               _String.read(runtime, key).value(), _String.read(runtime, value).value()))
        effects = self.callback(runtime, receiver, key, value)
        if not isinstance(effects, tuple):
            raise InputError('device configuration callback requires explicit memory effects')
        for effect in effects:
            if (not isinstance(effect, tuple) or len(effect) != 2 or type(effect[0]) is not int or
                    not 0 <= effect[0] <= _MASK64 or not isinstance(effect[1], bytes)):
                raise InputError('device configuration effects require an unsigned address and raw bytes')
            runtime.memory.write(effect[0], effect[1], source='1BE5B30.configuration_callback')


def configure(runtime, key, value):
    memory = runtime.memory
    receiver = memory.load(runtime.image_base + 0x677BDB0, 8)
    if not receiver or not _length(runtime, key):
        return None
    target = memory.load(memory.load(receiver, 8) + 40, 8)
    if target == runtime.image_base + 0xBED7B0:
        from .primary_configuration_callbacks import write
        return write(runtime, receiver, target, key, value)
    binding = runtime.device_configuration
    if not isinstance(binding, DeviceConfigurationBinding):
        raise PrimarySemanticUnavailable('1BE5B30 nonnull configuration provider requires its actual callback binding')
    return binding.write(runtime, receiver, target, key, value)


def _configuration_key(runtime, frame, name, value):
    key = _String.construct(runtime, _key(name))
    key.write_to(frame)
    configure(runtime, frame, value)
    _String.read(runtime, frame).destroy()


def digest_string(runtime, source, destination, requested):
    count = _length(runtime, source) & 0xFFFFFFFF
    if count > _LIMIT:
        raise PrimaryProgramLimit('device digest input exceeds the bounded offline domain')
    raw = runtime.memory.read(_data(runtime, source), count) if count else b''
    size = requested & 0xFFFFFFFF
    size = size if 1 <= size <= 16 else 16
    runtime.memory.write(destination, identifier_digest_bytes(raw,size), source='1D05BC0.device_digest')
    return None


def ensure_classic_locale(runtime):
    memory, base = runtime.memory, runtime.image_base
    guard = base + 0x674DDE8
    if memory.load(guard, 4, signed=True) > memory.load(runtime.tls_epoch_address, 4, signed=True):
        runtime._thread_header(guard)
        if memory.load(guard, 4, signed=True) == -1:
            frame, _ = _frame(runtime, 272, '3E824C8.locale_conversion_frame')
            result, output = _observe(runtime, 'MultiByteToWideChar', (0, 0, _cstring(runtime, base + 0x48A38AB) + b'\0', -1, True, 131))
            if not isinstance(output, bytes) or len(output) > 262 or len(output) & 1:
                raise InputError('C CRT locale conversion requires bounded raw UTF16 output effects')
            if output:
                memory.write(frame, output, source='3EA4944.locale_name_output')
            pointer = 0
            if result & 0xFFFFFFFF:
                name = _terminated(runtime, frame, 2)
                if name != b'C\0\0\0':
                    raise PrimarySemanticUnavailable('device hexadecimal conversion requires the actual observed C CRT locale')
                pointer, header = runtime.worker_observations.take(runtime, '_wcreate_locale', (0, name))
                if not isinstance(header, bytes) or len(header) != (16 if pointer else 0):
                    raise InputError('C CRT locale allocation requires its actual handle and raw descriptor')
                if pointer:
                    memory.map(pointer, bytearray(header), name='observed C CRT locale descriptor', initialized=True)
            memory.store(base + 0x674DDD0, pointer, 8, source='D46D1A.C_locale_handle')
            memory.store(base + 0x674DDD8, base + 0x48A38AB, 8, source='D46D1D.C_locale_name')
            memory.store(base + 0x674DDE0, 0, 8, source='D46D21.C_locale_owned_name')
            _invoke(runtime, 0x3E680B4, base + 0x77DFE0)
            runtime._thread_footer(guard)
            memory.unmap(frame)


def destroy_classic_locale(runtime):
    pointer = runtime.memory.load(runtime.image_base + 0x674DDE0, 8)
    if pointer:
        _invoke(runtime, 0x7650D0, pointer)
        _invoke(runtime, 0xB75029, pointer)


def _codecvt_locale(runtime, facet):
    ensure_classic_locale(runtime)
    memory, base = runtime.memory, runtime.image_base
    memory.store(facet + 8, 0xFFFFFFFF, 4, source='782844.codecvt_reference_count')
    memory.copy_disjoint(facet + 16, base + 0x674DDD0, 16, label='769A4E.C_locale_copy')
    memory.store(facet + 32, 0, 8, source='769A51.C_locale_owned_name')


def hex_string(runtime, destination, source, requested):
    count = requested & 0xFFFFFFFF
    if count >= 1 << 30 or count * 2 > _LIMIT:
        raise PrimaryProgramLimit('device hexadecimal output exceeds the bounded offline domain')
    size = count * 2
    wide = None
    if size > 10:
        wide = runtime._operator_new(2 * ((max(20, size) | 7) + 1))
        runtime.memory.write(wide, bytes(2 * (size + 1)), source='2E11140.wide_resize')
    digits = runtime.memory.read(runtime.image_base + 0x436ED70, 32)
    value = bytearray()
    from .primary_device_integrity import _diagnostic, _loaded
    import sys
    current = sys._getframe(1)
    diagnostic = None
    while current is not None:
        if current.f_code is _diagnostic.__code__ and current.f_locals.get('runtime') is runtime:
            diagnostic = current
            break
        current = current.f_back
    loaded = None
    if diagnostic is not None and source == diagnostic.f_locals.get('address') and count == 16:
        loaded = _loaded(runtime, source, 16)
    for index in range(count):
        byte = loaded[index] if loaded is not None else runtime.memory.load(source + index, 1)
        value.extend(digits[2 * (byte >> 4):2 * (byte >> 4) + 2])
        value.extend(digits[2 * (byte & 15):2 * (byte & 15) + 2])
    if wide is not None:
        runtime.memory.write(wide, bytes(value), source='2E11140.wide_hexadecimal')
    facet = runtime._operator_new(48)
    _codecvt_locale(runtime, facet)
    runtime.memory.store(facet, runtime.image_base + 0x3EF7098, 8, source='2E112AF.codecvt_vtable')
    runtime.memory.store(facet + 40, 0x10FFFF, 8, source='2E112A0.codecvt_maxcode')
    converted = bytes(value).decode('utf-16-le').encode('utf-8')
    result = _String.construct(runtime, bytes(size * 2))
    if result.get(0, 1) & 1:
        runtime.memory.write(result.get(16, 8), converted + b'\0', source='50852E.converted_hexadecimal')
        result.set(8, len(converted).to_bytes(8, 'little'))
    else:
        result.set(0, bytes([len(converted) * 2]))
        result.set(1, converted + b'\0')
    result.write_to(destination)
    runtime._free_allocation(facet)
    if wide is not None:
        runtime._free_allocation(wide)
    return destination


def _replace_digest(runtime, destination, source, frame):
    digest_string(runtime, source, frame, 16)
    hex_string(runtime, frame + 24, frame, 16)
    _String.read(runtime, destination).destroy()
    _String.read(runtime, frame + 24).write_to(destination)


def cache_filename(runtime, manager, destination):
    from .primary_device_cache import cache_filename as current_filename

    return current_filename(runtime, manager, destination)


def _empty_cache_document(runtime):
    error = bytes.fromhex(_image()['empty_xml_error_hex'])
    pointer = _new_array(runtime, (len(error) + 27) & ~3)
    runtime.memory.store(pointer, len(error), 8, source='3C74040.empty_document_error_length')
    runtime.memory.store(pointer + 8, len(error), 8, source='3C74048.empty_document_error_capacity')
    runtime.memory.write(pointer + 16, error + b'\0', source='3C74056.empty_document_error')
    _delete_array(runtime, pointer)


def _empty_wide_to_ansi(runtime):
    arguments = (0, 0, b'\0\0', -1, False, 0, 0, 0)
    result, raw = _observe(runtime, 'WideCharToMultiByte', arguments)
    if not isinstance(raw, bytes) or raw:
        raise InputError('device filename size query requires no destination output effects')
    count = result & 0xFFFFFFFF
    if not 0 < count < 1 << 31:
        return _String.construct(runtime, b'')
    pointer = _new_array(runtime, count)
    runtime.memory.write(pointer, bytes(count), source='2E099B0.filename_conversion_zero')
    _, raw = _observe(runtime, 'WideCharToMultiByte', (0, 0, b'\0\0', -1, True, count, 0, 0))
    if not isinstance(raw, bytes) or len(raw) > count:
        raise InputError('device filename conversion requires bounded raw OS output effects')
    runtime.memory.write(pointer, raw, source='2E099DC.filename_conversion_output')
    runtime.memory.store(pointer + count - 1, 0, 1, source='2E099E5.filename_conversion_nul')
    value = _String.construct(runtime, _cstring(runtime, pointer))
    _delete_array(runtime, pointer)
    return value


def construct_cache(runtime, manager):
    from .primary_device_cache import read_file
    from .primary_device_cache_xml import parse

    memory = runtime.memory
    memory.store(manager, 1, 1, source='35F5536.cache_flag')
    memory.write(manager + 16, bytes(16), source='35F5548.cache_root_count')
    memory.store(manager + 8, manager + 16, 8, source='35F5550.cache_begin')
    frame, _ = _frame(runtime, 96, '35F5520.cache_constructor_frame')
    memory.write(frame, bytes(24), source='35F5554.empty_cache_xml')
    read_file(runtime, manager, frame)
    parse(runtime, manager, frame)
    _String.read(runtime, frame).destroy()
    memory.unmap(frame)
    return manager


def _cache(runtime):
    memory, base = runtime.memory, runtime.image_base
    _srw(runtime, base + 0x6D86F58, True)
    manager = memory.load(base + 0x6D86F50, 8)
    if not manager:
        manager = runtime._operator_new(32)
        construct_cache(runtime, manager)
        memory.store(base + 0x6D86F50, manager, 8, source='2E2932D.cache_publish')
    _srw(runtime, base + 0x6D86F58, False)
    return manager


def _cache_node(runtime, manager, key_value, *, move=False):
    memory = runtime.memory
    raw_key = key_value.value()
    tree = _Tree(runtime, manager + 8)
    parent, slot = manager + 16, manager + 16
    node = memory.load(slot, 8)
    for _ in range(4096):
        if not node:
            node = runtime._operator_new(80)
            (key_value if move else key_value.clone()).write_to(node + 32)
            memory.write(node + 56, bytes(24), source='908A6.empty_cache_value')
            memory.write(node, bytes(16), source='42FC.cache_children')
            memory.store(node + 16, parent, 8, source='42FC.cache_parent')
            memory.store(slot, node, 8, source='42FC.cache_link')
            begin = memory.load(manager + 8, 8)
            left = memory.load(begin, 8)
            if left:
                memory.store(manager + 8, left, 8, source='42FC.cache_begin')
            tree.balance(memory.load(manager + 16, 8), node)
            memory.store(manager + 24, (memory.load(manager + 24, 8) + 1) & _MASK64, 8,
                         source='42FC.cache_count')
            return node, True
        present = _String.read(runtime, node + 32).value()
        if raw_key == present:
            return node, False
        parent, slot = node, node + (0 if raw_key < present else 8)
        node = memory.load(slot, 8)
    else:
        raise PrimaryProgramLimit('device cache key tree exceeds its bounded traversal')


def write_cache_string(runtime, manager, key, value):
    _log(runtime, 'secconfig_center.cpp', 142, _data(runtime, key), _data(runtime, value))
    node, _ = _cache_node(runtime, manager, _String.read(runtime, key))
    assign_string(runtime, node + 56, value)
    return None


def write_cache(runtime, manager, key, value):
    frame, _ = _frame(runtime, 32, '35FB2C0.cache_key_frame')
    _String.construct(runtime, _cstring(runtime, key)).write_to(frame)
    write_cache_string(runtime, manager, frame, value)
    _String.read(runtime, frame).destroy()
    runtime.memory.unmap(frame)
    return None


def flush_cache(runtime, manager):
    if not runtime.memory.load(manager, 1):
        return None
    _log(runtime, 'secconfig_center.cpp', 44)
    from .primary_device_cache import _WideString, serialize, write_file

    frame, _ = _frame(runtime, 48, '35F7BE0.cache_flush_frame')
    runtime.memory.write(frame, bytes(48), source='35F7EEF.empty_cache_filename_and_xml')
    cache_filename(runtime, manager, frame)
    if _length(runtime, frame):
        serialize(runtime, manager, frame + 24)
        write_file(runtime, 0, frame, frame + 24)
        _String.read(runtime, frame + 24).destroy()
    _WideString.read(runtime, frame).destroy()
    runtime.memory.unmap(frame)
    return None


def write_registry(runtime, root, subkey, name, value):
    subkey_data = _cstring(runtime, _data(runtime, subkey))
    result, raw = _observe(runtime, 'RegCreateKeyExA', (root, subkey_data, 0, 0, 0, 0x20006, 0, 0))
    if not isinstance(raw, bytes) or len(raw) not in (0, 8):
        raise InputError('device registry creation requires raw optional HKEY output effects')
    if result & 0xFFFFFFFF:
        _log(runtime, 'win_regedit.cpp', 29, result)
        return 0xFFFFFFFF
    if len(raw) != 8:
        raise UnknownMemory('successful device registry creation did not observe its output handle')
    handle = int.from_bytes(raw, 'little')
    count = ((_length(runtime, value) & 0xFFFFFFFF) + 1) & 0xFFFFFFFF
    if count > _LIMIT:
        raise PrimaryProgramLimit('device registry payload exceeds the bounded offline domain')
    data = runtime.memory.read(_data(runtime, value), count) if count else b''
    result, raw = _observe(runtime, 'RegSetValueExA', (handle, _cstring(runtime, _data(runtime, name)), 0, 1, data))
    if not isinstance(raw, bytes) or raw:
        raise InputError('device registry write has no output buffer')
    failed = result & 0xFFFFFFFF
    if failed:
        _log(runtime, 'win_regedit.cpp', 43, result)
    _, raw = _observe(runtime, 'RegCloseKey', (handle,))
    if not isinstance(raw, bytes) or raw:
        raise InputError('device registry close has no output buffer')
    if not failed:
        _log(runtime, 'win_regedit.cpp', 50)
    return 0xFFFFFFFF if failed else 0


def consume_raw(runtime, owner):
    if not _length(runtime, owner + 0x558):
        _log(runtime, 'computer_info.cpp', 623)
        return None
    frame, _ = _frame(runtime, 96, '2E28B80.identifier_frame')
    if not _length(runtime, owner + 0x570):
        assign_string(runtime, owner + 0x570, owner + 0x558)
        _configuration_key(runtime, frame, 'raw_configuration', owner + 0x558)
        _log(runtime, 'computer_info.cpp', 630, _data(runtime, owner + 0x570))
    if not _length(runtime, owner + 0x588):
        assign_string(runtime, owner + 0x588, owner + 0x558)
        manager = _cache(runtime)
        _String.construct(runtime, _key('raw_cache')).write_to(frame)
        write_cache(runtime, manager, _data(runtime, frame), owner + 0x588)
        _String.read(runtime, frame).destroy()
        _log(runtime, 'computer_info.cpp', 637, _data(runtime, owner + 0x588))
    runtime.memory.unmap(frame)
    return None


def consume_digests(runtime, owner):
    if not _length(runtime, owner + 0x558):
        _log(runtime, 'computer_info.cpp', 643)
        return None
    if all(_length(runtime, owner + offset) for offset in (0x5B8, 0x5D0, 0x5E8)):
        return None
    frame, _ = _frame(runtime, 128, '2E297B0.identifier_frame')
    _replace_digest(runtime, owner + 0x5A0, owner + 0x558, frame)
    if not _length(runtime, owner + 0x5B8):
        assign_string(runtime, owner + 0x5B8, owner + 0x5A0)
        _configuration_key(runtime, frame, 'digest_configuration', owner + 0x5B8)
        _log(runtime, 'computer_info.cpp', 659, _data(runtime, owner + 0x5B8))
    if not _length(runtime, owner + 0x5D0):
        assign_string(runtime, owner + 0x5D0, owner + 0x5A0)
        manager = _cache(runtime)
        _String.construct(runtime, _key('digest_cache')).write_to(frame)
        write_cache(runtime, manager, _data(runtime, frame), owner + 0x5D0)
        _String.read(runtime, frame).destroy()
        flush_cache(runtime, _cache(runtime))
        _log(runtime, 'computer_info.cpp', 667, _data(runtime, owner + 0x5D0))
    if not _length(runtime, owner + 0x5E8):
        _replace_digest(runtime, owner + 0x5E8, owner + 0x5A0, frame)
        _String.construct(runtime, _key('registry_name')).write_to(frame)
        _String.construct(runtime, _key('registry_subkey')).write_to(frame + 24)
        write_registry(runtime, 0xFFFFFFFF80000001, frame + 24, frame, owner + 0x5E8)
        _String.read(runtime, frame + 24).destroy()
        _String.read(runtime, frame).destroy()
        _log(runtime, 'computer_info.cpp', 677, _data(runtime, owner + 0x5E8))
    runtime.memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    definitions = {0x2E28B80: (consume_raw, 1), 0x2E297B0: (consume_digests, 1),
                   0x1BE5B30: (configure, 2), 0x1D05BC0: (digest_string, 3),
                   0x77DFE0: (destroy_classic_locale, 0),
                   0x2E11240: (hex_string, 3), 0x35F5520: (construct_cache, 1),
                   0x35FB2C0: (write_cache, 3), 0x35FB3C0: (write_cache_string, 3),
                   0x35F7BE0: (flush_cache, 1), 0x35F7FE0: (cache_filename, 2),
                   0x35F1EB0: (write_registry, 4)}
    function, count = definitions[rva]
    if len(values) != count:
        raise InputError('device identifier source interface argument count mismatch')
    return function(runtime, *values)


def identifier_digest_bytes(raw,size=16):
    if type(raw)is not bytes:raise InputError('identifier digest requires owned bytes')
    size=size&0xFFFFFFFF;size=size if 1<=size<=16 else 16
    return hashlib.md5(raw).digest()[:size]


def identifier_digest_text(raw):
    # Fixed436ED70 UTF16 digits:0123456789ABCDEF; no host locale substitution.
    return identifier_digest_bytes(raw).hex().upper().encode('ascii')
