from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_collector import assign_string, generate_material, _append_material
from .primary_device_identifiers import _cache, _data, _key, _length, consume_raw, consume_digests
from .primary_logger import _cstring, _String, log
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _frame


_IMAGE_SHA256 = '607b5656e93215270c930265f42543cd1659ad0445d93ded02259a860210f241'
_IMPORTS = {'RegOpenKeyExA': 0x4910A20, 'RegQueryValueExA': 0x4910A40,
            'RegCloseKey': 0x49109E0, 'RegDeleteValueA': 0x4910A00}
_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20


def _image():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/device-provenance-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device provenance image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device provenance import identity mismatch')
    return image


def _log(runtime, kind, line, *values):
    item = _image()['logs'][kind + ':' + str(line)]
    runtime.events.append(('device.identifier_log', kind, line))
    return log(runtime, bytes.fromhex(item['source_file_hex']), line,
               bytes.fromhex(item['template_hex']), bytes.fromhex(item['tag_hex']), item['severity'], *values)


def _observe(runtime, name, arguments):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('device provenance current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device provenance OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _plain(runtime, name, arguments):
    result, effects = _observe(runtime, name, arguments)
    if not isinstance(effects, bytes) or effects:
        raise InputError('device provenance operation has no output buffer: ' + name)
    return result & 0xFFFFFFFF


@dataclass(frozen=True)
class DeviceConfigurationReadBinding:
    receiver: int
    target: int
    callback: object

    def __post_init__(self):
        if (type(self.receiver) is not int or not 0 < self.receiver <= _MASK64 or
                type(self.target) is not int or not 0 < self.target <= _MASK64 or not callable(self.callback)):
            raise InputError('device configuration reader requires its receiver, virtual target and callable effects')

    def read(self, runtime, receiver, target, output, key):
        if receiver != self.receiver or target != self.target:
            raise PrimarySemanticUnavailable('device configuration current reader or virtual target is not bound')
        runtime.events.append(('device.configuration_read', receiver, target, _String.read(runtime, key).value()))
        effects = self.callback(runtime, receiver, output, key)
        if not isinstance(effects, tuple):
            raise InputError('device configuration reader requires explicit memory effects')
        for effect in effects:
            if (not isinstance(effect, tuple) or len(effect) != 2 or type(effect[0]) is not int or
                    not 0 <= effect[0] <= _MASK64 or not isinstance(effect[1], bytes)):
                raise InputError('device configuration read effects require an unsigned address and raw bytes')
            runtime.memory.write(effect[0], effect[1], source='1BE5B70.configuration_callback')


def read_configuration(runtime, output, key):
    memory = runtime.memory
    receiver = memory.load(runtime.image_base + 0x677BDD8, 8)
    if not receiver or not _length(runtime, key):
        memory.store(output, 0, 2, source='1BE5B70.empty_configuration_result')
        return output
    target = memory.load(memory.load(receiver, 8) + 40, 8)
    if target == runtime.image_base + 0xBED9B0:
        from .primary_configuration_callbacks import read
        return read(runtime, receiver, target, output, key)
    binding = runtime.device_configuration_read
    if not isinstance(binding, DeviceConfigurationReadBinding):
        raise PrimarySemanticUnavailable('1BE5B70 nonnull configuration reader requires its actual callback binding')
    binding.read(runtime, receiver, target, output, key)
    return output


def read_cache_string(runtime, manager, key, output):
    wanted = _String.read(runtime, key).value()
    node = runtime.memory.load(manager + 16, 8)
    visited = set()
    while node:
        if node in visited or len(visited) >= _LIMIT:
            raise PrimaryProgramLimit('device cache lookup exceeds the bounded physical tree domain')
        visited.add(node)
        found = _String.read(runtime, node + 32).value()
        if wanted == found:
            assign_string(runtime, output, node + 56)
            return 1
        node = runtime.memory.load(node + (0 if wanted < found else 8), 8)
    _log(runtime, 'secconfig_center.cpp', 84, _data(runtime, key))
    return 0


def read_cache(runtime, manager, key, output):
    frame, _ = _frame(runtime, 24, '35FACA0.cache_lookup_key')
    _String.construct(runtime, _cstring(runtime, key)).write_to(frame)
    result = read_cache_string(runtime, manager, frame, output)
    _String.read(runtime, frame).destroy()
    runtime.memory.unmap(frame)
    return result


def _open_registry(runtime, root, subkey, access):
    result, effects = _observe(runtime, 'RegOpenKeyExA', (root, subkey, 0, access))
    if not isinstance(effects, bytes) or len(effects) not in (0, 8):
        raise InputError('device registry opening requires raw optional HKEY output effects')
    if result & 0xFFFFFFFF:
        return result & 0xFFFFFFFF, None
    if len(effects) != 8:
        raise UnknownMemory('successful device registry opening did not observe its output handle')
    return 0, int.from_bytes(effects, 'little')


def read_registry(runtime, root, subkey, name, output):
    result, handle = _open_registry(runtime, root, _cstring(runtime, _data(runtime, subkey)), 0x20019)
    if result:
        _log(runtime, 'win_regedit.cpp', 68, result)
        return 0xFFFFFFFF
    frame, _ = _frame(runtime, 320, '35F3080.registry_query_frame')
    result, effects = _observe(runtime, 'RegQueryValueExA', (handle, _cstring(runtime, _data(runtime, name)), 0, 0, 256))
    if (not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], bytes) or
            len(effects[0]) > 256 or type(effects[1]) is not int or not 0 <= effects[1] < 1 << 32):
        raise InputError('device registry query requires bounded raw buffer and DWORD size effects')
    if effects[0]:
        runtime.memory.write(frame, effects[0], source='35F3080.registry_buffer_output')
    failed = result & 0xFFFFFFFF
    if failed:
        _log(runtime, 'win_regedit.cpp', 85, result)
    _plain(runtime, 'RegCloseKey', (handle,))
    if not failed:
        replacement = _String.construct(runtime, _cstring(runtime, frame))
        _String.read(runtime, output).destroy()
        replacement.write_to(output)
        _log(runtime, 'win_regedit.cpp', 95)
    runtime.memory.unmap(frame)
    return 0xFFFFFFFF if failed else 0


def delete_registry(runtime, root, subkey, name):
    result, handle = _open_registry(runtime, root, _cstring(runtime, subkey), 2)
    if result:
        _log(runtime, 'win_regedit.cpp', 107, subkey, result)
        return 0
    result = _plain(runtime, 'RegDeleteValueA', (handle, _cstring(runtime, name)))
    if result:
        _log(runtime, 'win_regedit.cpp', 114, name, result)
    _plain(runtime, 'RegCloseKey', (handle,))
    return int(not result)


def _configuration_field(runtime, frame, owner, offset, key):
    _String.construct(runtime, _key(key)).write_to(frame)
    read_configuration(runtime, frame + 24, frame)
    _String.read(runtime, owner + offset).destroy()
    _String.read(runtime, frame + 24).write_to(owner + offset)
    runtime.memory.store(frame + 24, 0, 2, source='2E270E0.moved_configuration_result')
    _String.read(runtime, frame).destroy()


def read_persistence(runtime, owner):
    frame, _ = _frame(runtime, 96, '2E270E0.persistence_frame')
    if not _length(runtime, owner + 0x570):
        _configuration_field(runtime, frame, owner, 0x570, 'raw_configuration')
        if not _length(runtime, owner + 0x570):
            _configuration_field(runtime, frame, owner, 0x570, 'raw_configuration')
        _log(runtime, 'computer_info.cpp', 600, _data(runtime, owner + 0x570))
    if not _length(runtime, owner + 0x5B8):
        _configuration_field(runtime, frame, owner, 0x5B8, 'digest_configuration')
        _log(runtime, 'computer_info.cpp', 604, _data(runtime, owner + 0x5B8))
    for offset, key, line in ((0x588, 'raw_cache', 608), (0x5D0, 'digest_cache', 612)):
        if not _length(runtime, owner + offset):
            manager = _cache(runtime)
            runtime.memory.write(frame, _key(key) + b'\0', source='2E270E0.decoded_cache_key')
            read_cache(runtime, manager, frame, owner + offset)
            _log(runtime, 'computer_info.cpp', line, _data(runtime, owner + offset))
    if not _length(runtime, owner + 0x5E8):
        _String.construct(runtime, _key('registry_subkey')).write_to(frame)
        _String.construct(runtime, _key('registry_name')).write_to(frame + 24)
        read_registry(runtime, 0xFFFFFFFF80000001, frame, frame + 24, owner + 0x5E8)
        _String.read(runtime, frame + 24).destroy()
        _String.read(runtime, frame).destroy()
        _log(runtime, 'computer_info.cpp', 617, _data(runtime, owner + 0x5E8))
    runtime.memory.unmap(frame)
    return None


def collect_identifiers(runtime, owner):
    memory, base = runtime.memory, runtime.image_base
    _log(runtime, 'computer_info.cpp', 683)
    frame, _ = _frame(runtime, 128, '2E26140.identifier_collection_frame')
    memory.write(frame, _key('registry_subkey') + b'\0', source='2E26140.decoded_registry_subkey')
    memory.write(frame + 32, bytes.fromhex(_image()['delete_name_hex']) + b'\0', source='2E26140.decoded_registry_delete_name')
    delete_registry(runtime, 0xFFFFFFFF80000001, frame, frame + 32)
    for _ in range(3):
        read_persistence(runtime, owner)
    if not all(_length(runtime, owner + offset) for offset in (0x570, 0x588, 0x5B8, 0x5D0, 0x5E8)):
        prefix = _String.read(runtime, owner + 0x88).value()
        hardware = _String.construct(runtime, prefix, capacity=len(prefix) + 1)
        _append_material(runtime, hardware, memory.read(base + 0x48C6BA8, 1))
        _append_material(runtime, hardware, _String.read(runtime, owner + 0x130).value())
        _append_material(runtime, hardware, _cstring(runtime, base + 0x48C6BA8))
        _append_material(runtime, hardware, _String.read(runtime, owner + 0x268).value())
        _append_material(runtime, hardware, _cstring(runtime, base + 0x48C6BA8))
        _append_material(runtime, hardware, _String.read(runtime, owner + 0x100).value())
        hardware.clone().write_to(frame)
        generate_material(runtime, frame + 24, frame)
        _String.read(runtime, owner + 0x558).destroy()
        _String.read(runtime, frame + 24).write_to(owner + 0x558)
        consume_raw(runtime, owner)
        consume_digests(runtime, owner)
        hardware.destroy()
    _log(runtime, 'computer_info.cpp', 700)
    memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    definitions = {0x1BE5B70: (read_configuration, 2), 0x35FACA0: (read_cache, 3),
                   0x35FADB0: (read_cache_string, 3), 0x35F3080: (read_registry, 4),
                   0x35F41F0: (delete_registry, 3), 0x2E270E0: (read_persistence, 1),
                   0x2E26140: (collect_identifiers, 1)}
    function, count = definitions[rva]
    if len(values) != count:
        raise InputError('device provenance source interface argument count mismatch')
    return function(runtime, *values)
