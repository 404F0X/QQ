import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_collector import _append_material, _terminated
from .primary_device_provenance import collect_identifiers
from .primary_logger import _cstring, _String, construct, feature, log
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _frame


_IMAGE_SHA256 = '65cc25c49da6b89011fa77fa536da6f193469bc7b33c072085df4d6c164702dc'
_IMPORTS = {'GlobalMemoryStatusEx': 0x4910070, 'GetCursorPos': 0x4910580,
            'GetSystemPowerStatus': 0x490FFA8, 'GetLastError': 0x490FEA8,
            'GetSystemDirectoryW': 0x490FF90, 'LoadLibraryExW': 0x4910180,
            'GetProcAddress': 0x490FF40, 'FreeLibrary': 0x490FD80}
_NAMES = ('WlanOpenHandle', 'WlanEnumInterfaces', 'WlanQueryInterface',
          'WlanGetAvailableNetworkList', 'WlanFreeMemory', 'WlanCloseHandle')
_LIMIT = 1 << 20


def _image():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/device-refresh-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device refresh image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device refresh import identity mismatch')
    return image


def install_image(memory, image_base):
    for item in _image()['segments']:
        memory.map(image_base + item['rva'], bytearray.fromhex(item['hex']),
                   name='fixed device refresh image', initialized=True)


def _log(runtime, kind, line, *values):
    item = _image()['logs'][kind + ':' + str(line)]
    runtime.events.append(('device.identifier_log', kind, line))
    return log(runtime, bytes.fromhex(item['source_file_hex']), line,
               bytes.fromhex(item['template_hex']), bytes.fromhex(item['tag_hex']), item['severity'], *values)


def _observe(runtime, name, arguments):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('device refresh current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device refresh OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _no_output(result, effects, name):
    if not isinstance(effects, bytes) or effects:
        raise InputError('device refresh operation has no output buffer: ' + name)
    return result


def _plain(runtime, name, arguments):
    return _no_output(*_observe(runtime, name, arguments), name)


def _dynamic(runtime, targets, name, arguments):
    target = targets[name]
    if not target:
        raise PrimarySemanticUnavailable('device WLAN function target is null: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device WLAN OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, (target, *arguments))


def _dynamic_plain(runtime, targets, name, arguments):
    return _no_output(*_dynamic(runtime, targets, name, arguments), name)


def _load_wlan(runtime, detailed):
    memory, base = runtime.memory, runtime.image_base
    result, raw = _observe(runtime, 'GetSystemDirectoryW', (260,))
    if not isinstance(raw, bytes) or len(raw) > 520 or len(raw) & 1:
        raise InputError('device WLAN system directory requires bounded raw UTF16 effects')
    result &= 0xFFFFFFFF
    if not 1 <= result <= 260:
        _log(runtime, 'wifi_info.cpp', 49 if detailed else 141)
        return None
    if memory.load(base + 0x6749CC0, 8) or memory.load(base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable('device WLAN path requires actual nondefault printf/locale semantics')
    narrow_end = raw.find(b'\0')
    if narrow_end < 0:
        raise UnknownMemory('device WLAN directory lacks its observed narrow formatter terminator')
    pattern = _terminated(runtime, base + 0x4904624, 2)[:-2].decode('utf-16-le')
    if pattern.count('%s') != 1 or pattern.replace('%s', '').find('%') >= 0:
        raise PrimarySemanticUnavailable('device WLAN mutated wide format is not modeled')
    path = pattern.replace('%s', ''.join(chr(value) for value in raw[:narrow_end]))
    if len(path) >= 260:
        raise PrimarySemanticUnavailable('device WLAN wide format overflow requires its actual CRT effects')
    library = _plain(runtime, 'LoadLibraryExW', (path.encode('utf-16-le') + b'\0\0', 0, 0x808))
    if not library:
        _log(runtime, 'wifi_info.cpp', 49 if detailed else 141)
        return None
    targets = {name: _plain(runtime, 'GetProcAddress', (library, name.encode('ascii'))) for name in _NAMES}
    required = _NAMES if detailed else ('WlanOpenHandle', 'WlanEnumInterfaces', 'WlanFreeMemory', 'WlanCloseHandle')
    if any(not targets[name] for name in required):
        _log(runtime, 'wifi_info.cpp', 66 if detailed else 157)
        _plain(runtime, 'FreeLibrary', (library,))
        return None
    return library, targets


def _open_wlan(runtime, targets):
    result, effects = _dynamic(runtime, targets, 'WlanOpenHandle', (2, 0))
    if result & 0xFFFFFFFF:
        return None
    if (not isinstance(effects, tuple) or len(effects) != 2 or type(effects[0]) is not int or
            not 0 <= effects[0] < 1 << 32 or type(effects[1]) is not int or not 0 < effects[1] < 1 << 64):
        raise UnknownMemory('successful WLAN opening requires its actual negotiated version and handle')
    return effects[1]


def _output_buffer(runtime, effects, extent=0):
    if (not isinstance(effects, tuple) or len(effects) != 2 or type(effects[0]) is not int or
            not 0 <= effects[0] < 1 << 64 or not isinstance(effects[1], bytes) or len(effects[1]) > _LIMIT):
        raise InputError('device WLAN query requires actual pointer and bounded raw output bytes')
    pointer, raw = effects
    if not 0 <= extent <= _LIMIT:
        raise PrimaryProgramLimit('device WLAN reported buffer extent exceeds the bounded domain')
    if not pointer:
        if raw:
            raise InputError('device WLAN null output pointer cannot hold output bytes')
        return 0
    buffers = getattr(runtime, '_device_wlan_buffers', None)
    if buffers is None:
        buffers = runtime._device_wlan_buffers = set()
    if pointer in buffers:
        raise PrimarySemanticUnavailable('device WLAN live OS buffer alias requires its actual ownership semantics')
    runtime.memory.map(pointer, bytearray(max(1, len(raw), extent)), name='observed WLAN OS-owned output', initialized=False)
    if raw:
        runtime.memory.write(pointer, raw, source='device.WLAN_output')
    buffers.add(pointer)
    return pointer


def _free_wlan(runtime, targets, pointer):
    _dynamic_plain(runtime, targets, 'WlanFreeMemory', (pointer,))
    buffers = getattr(runtime, '_device_wlan_buffers', set())
    if pointer in buffers:
        buffers.remove(pointer)
        runtime.memory.unmap(pointer)


def has_interfaces(runtime):
    loaded = _load_wlan(runtime, False)
    if loaded is None:
        return 0
    library, targets = loaded
    handle = _open_wlan(runtime, targets)
    present = 0
    if handle is not None:
        result, effects = _dynamic(runtime, targets, 'WlanEnumInterfaces', (handle, 0))
        pointer = _output_buffer(runtime, effects)
        if not result & 0xFFFFFFFF:
            present = int(bool(runtime.memory.load(pointer, 4)))
            _free_wlan(runtime, targets, pointer)
        _dynamic_plain(runtime, targets, 'WlanCloseHandle', (handle, 0))
    _plain(runtime, 'FreeLibrary', (library,))
    return present


class _StringVector:
    def __init__(self, runtime, address):
        self.runtime, self.address = runtime, address
        self.begin, self.end, self.capacity = (runtime.memory.load(address + n, 8) for n in (0, 8, 16))
        if (not 0 <= self.begin <= self.end <= self.capacity or (self.end - self.begin) % 24 or
                (self.capacity - self.begin) % 24 or self.capacity - self.begin > _LIMIT):
            raise PrimaryProgramLimit('device WLAN String vector exceeds its bounded physical domain')

    def append(self, value):
        runtime, memory = self.runtime, self.runtime.memory
        if self.end == self.capacity:
            count = (self.end - self.begin) // 24
            capacity = max(2 * (self.capacity - self.begin) // 24, count + 1)
            if capacity * 24 > _LIMIT:
                raise PrimaryProgramLimit('device WLAN String vector growth exceeds the bounded domain')
            replacement = runtime._operator_new(capacity * 24)
            value.clone().write_to(replacement + count * 24)
            for index in range(count - 1, -1, -1):
                _String.read(runtime, self.begin + 24 * index).write_to(replacement + 24 * index)
            if self.begin:
                runtime._free_allocation(self.begin)
            self.begin, self.end, self.capacity = replacement, replacement + 24 * (count + 1), replacement + 24 * capacity
            memory.store(self.address, self.begin, 8, source='48B6A.WLAN_vector_begin')
            memory.store(self.address + 16, self.capacity, 8, source='48B6A.WLAN_vector_capacity')
        else:
            value.clone().write_to(self.end)
            self.end += 24
        memory.store(self.address + 8, self.end, 8, source='35F0516.WLAN_vector_end')

    def destroy(self):
        for address in range(self.end - 24, self.begin - 1, -24):
            _String.read(self.runtime, address).destroy()
        if self.begin:
            self.runtime._free_allocation(self.begin)


def read_wlan(runtime, output, vector):
    loaded = _load_wlan(runtime, True)
    if loaded is None:
        return 0
    library, targets = loaded
    handle = _open_wlan(runtime, targets)
    if handle is None:
        _plain(runtime, 'FreeLibrary', (library,))
        return 0
    result, effects = _dynamic(runtime, targets, 'WlanEnumInterfaces', (handle, 0))
    interfaces = _output_buffer(runtime, effects)
    succeeded = not result & 0xFFFFFFFF
    if succeeded:
        count = runtime.memory.load(interfaces, 4, signed=True)
        if count > 4096:
            raise PrimaryProgramLimit('device WLAN interface count exceeds the bounded domain')
        values = _StringVector(runtime, vector)
        for index in range(max(0, count)):
            guid = runtime.memory.read(interfaces + 8 + 532 * index, 16)
            status, effects = _dynamic(runtime, targets, 'WlanQueryInterface', (handle, guid, 7, 0, 604, 3))
            if (not isinstance(effects, tuple) or len(effects) != 4 or type(effects[2]) is not int or
                    not 0 <= effects[2] < 1 << 32 or type(effects[3]) is not int or not 0 <= effects[3] < 1 << 32):
                raise InputError('device WLAN connection requires pointer,bytes,size and opcode-type effects')
            connection = _output_buffer(runtime, effects[:2], effects[2])
            if not status & 0xFFFFFFFF and runtime.memory.load(connection, 4) == 1:
                size = runtime.memory.load(connection + 520, 4)
                if size > _LIMIT:
                    raise PrimaryProgramLimit('device WLAN SSID length exceeds the bounded domain')
                replacement = _String.construct(runtime, runtime.memory.read(connection + 524, size) if size else b'')
                _String.read(runtime, output).destroy()
                replacement.write_to(output)
            if connection:
                _free_wlan(runtime, targets, connection)
            status, effects = _dynamic(runtime, targets, 'WlanGetAvailableNetworkList', (handle, guid, 0, 0))
            networks = _output_buffer(runtime, effects)
            if not status & 0xFFFFFFFF:
                available = runtime.memory.load(networks, 4, signed=True)
                if available > 4096:
                    raise PrimaryProgramLimit('device WLAN network count exceeds the bounded domain')
                for position in range(max(0, available)):
                    item = networks + 628 * position
                    size = runtime.memory.load(item + 520, 4)
                    if size > _LIMIT:
                        raise PrimaryProgramLimit('device WLAN available SSID exceeds the bounded domain')
                    value = _String.construct(runtime, runtime.memory.read(item + 524, size) if size else b'')
                    values.append(value)
                    value.destroy()
            if networks:
                _free_wlan(runtime, targets, networks)
        _free_wlan(runtime, targets, interfaces)
    _dynamic_plain(runtime, targets, 'WlanCloseHandle', (handle, 0))
    _plain(runtime, 'FreeLibrary', (library,))
    return int(succeeded)


def format_networks(runtime, output, vector):
    value = _String.construct(runtime, b'[')
    values = _StringVector(runtime, vector)
    for address in range(values.begin, values.end, 24):
        _append_material(runtime, value, _String.read(runtime, address).value())
        if address != values.end - 24:
            _append_material(runtime, value, _cstring(runtime, runtime.image_base + 0x48FE275))
    _append_material(runtime, value, _cstring(runtime, runtime.image_base + 0x489825D))
    raw = value.value()
    data = value.get(16, 8) if value.get(0, 1) & 1 else None
    for index, byte in enumerate(raw):
        if byte == 124:
            if data is None:
                value.set(index + 1, b'-')
            else:
                runtime.memory.store(data + index, 45, 1, source='2E09E9E.WLAN_pipe_replacement')
    value.write_to(output)
    return output


def decimal_string(runtime, output, value, unsigned=False):
    value &= 0xFFFFFFFF
    if not unsigned and value >= 1 << 31:
        value -= 1 << 32
    _String.construct(runtime, str(value).encode('ascii')).write_to(output)
    return output


def _logger(runtime):
    pointer = runtime.memory.load(runtime.image_base + 0x67516A8, 8)
    if not pointer:
        pointer = runtime._operator_new(120)
        construct(runtime, pointer)
        runtime.memory.store(runtime.image_base + 0x67516A8, pointer, 8, source='2E25928.logger_publish')
    return pointer


def refresh(runtime, owner):
    memory = runtime.memory
    frame, _ = _frame(runtime, 128, '2E252A0.dynamic_refresh_frame')
    for name, arguments, size in (('GlobalMemoryStatusEx', (64,), 64), ('GetCursorPos', (), 8), ('GetSystemPowerStatus', (), 12)):
        memory.forget(frame, size, source='2E252A0.OS_output_unobserved')
        if name == 'GlobalMemoryStatusEx':
            memory.store(frame, 64, 4, source='2E252C1.MEMORYSTATUSEX_length')
        result, raw = _observe(runtime, name, arguments)
        if name == 'GetSystemPowerStatus' and not result & 0xFFFFFFFF and raw is None:
            raw = b''
        if not isinstance(raw, bytes) or len(raw) > size:
            raise InputError('device refresh requires bounded raw OS output effects: ' + name)
        if raw:
            memory.write(frame, raw, source='2E252A0.' + name + '_output')
        if result & 0xFFFFFFFF:
            if name == 'GlobalMemoryStatusEx':
                memory.copy_disjoint(owner + 0x10, frame + 4, 4, label='2E252D9.memory_load')
                memory.copy_disjoint(owner + 0x18, frame + 8, 48, label='2E252E0.memory_status')
            elif name == 'GetCursorPos':
                memory.copy_disjoint(owner + 0x4C, frame, 8, label='2E25787.cursor_position')
            else:
                for index in range(6):
                    value = memory.load(frame + index, 1) if index < 4 else memory.load(frame + 4 * (index - 3), 4)
                    decimal_string(runtime, frame + 64, value, index >= 4)
                    _String.read(runtime, owner + 0x600 + 24 * index).destroy()
                    _String.read(runtime, frame + 64).write_to(owner + 0x600 + 24 * index)
                if memory.load(frame + 1, 1) not in (0x80, 0xFF):
                    memory.store(owner + 0x690, 1, 1, source='2E258FB.battery_seen')
        elif name == 'GlobalMemoryStatusEx':
            _log(runtime, 'computer_info.cpp', 325, _plain(runtime, 'GetLastError', ()))
    if feature(runtime, _logger(runtime), 22) == 1:
        memory.store(owner + 0x710, has_interfaces(runtime), 1, source='2E25947.WLAN_interface_flag')
        memory.write(frame, bytes(48), source='2E25950.empty_WLAN_String_and_vector')
        read_wlan(runtime, frame, frame + 24)
        source = _String.read(runtime, frame)
        replacement = source.clone() if source.value() else _String.construct(runtime, b'none')
        _String.read(runtime, owner + 0x6E0).destroy()
        replacement.write_to(owner + 0x6E0)
        if source.value():
            memory.store(owner + 0x711, 1, 1, source='2E259FB.WLAN_connection_seen')
        format_networks(runtime, frame + 48, frame + 24)
        _String.read(runtime, owner + 0x6F8).destroy()
        _String.read(runtime, frame + 48).write_to(owner + 0x6F8)
        _StringVector(runtime, frame + 24).destroy()
        source.destroy()
    collect_identifiers(runtime, owner)
    memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    definitions = {0x2E252A0: (refresh, 1), 0x35F0A70: (has_interfaces, 0), 0x35EF600: (read_wlan, 2),
                   0x2E09B80: (format_networks, 2), 0x75E7B0: (decimal_string, 2),
                   0x75E9F0: (lambda r, out, value: decimal_string(r, out, value, True), 2)}
    function, count = definitions[rva]
    if len(values) != count:
        raise InputError('device refresh source interface argument count mismatch')
    return function(runtime, *values)
