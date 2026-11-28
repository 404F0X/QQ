import hashlib
from contextlib import contextmanager
import json
from pathlib import Path

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_MASK64 = (1 << 64) - 1
_IMAGE_SHA256 = 'a1cc8b949849e81d94e81f0b100afac8a40ace251853bd5795fce211e7181349'
_IMPORTS = {
    'GetTickCount': 0x490FFE8, 'Sleep': 0x4910368,
    'GetCurrentProcess': 0x490FDE0, 'GetCurrentProcessId': 0x490FDE8,
    'GetModuleFileNameA': 0x490FEE8, 'GetModuleFileNameW': 0x490FEF0,
    'GetModuleHandleW': 0x490FF10, 'GetSystemPowerStatus': 0x490FFA8,
    'K32EnumProcessModules': 0x4910140, 'EnumWindows': 0x4910520,
    'GetClassNameW': 0x4910568, 'GetWindowThreadProcessId': 0x4910608,
    'PathRemoveExtensionW': 0x4910AD8, 'PathStripPathA': 0x4910AF0,
    'PathStripPathW': 0x4910AF8,
}


class WorkerObservations:
    def __init__(self, events):
        self._events = events if callable(events) else iter(events)

    def take(self, runtime, name, arguments):
        event = runtime._next(self._events, 'SDK worker ' + name, name, arguments)
        if (not isinstance(event, tuple) or len(event) != 4 or event[0] != name or
                event[1] != arguments or not (event[2] is None and name in ('Sleep', 'WakeConditionVariable', 'WakeAllConditionVariable',
                    'SetLastError', 'ExitThread', 'FreeLibraryAndExitThread', 'EnterCriticalSection', 'LeaveCriticalSection',
                    'RtlCaptureContext')) and
                (type(event[2]) is not int or not 0 <= event[2] <= _MASK64)):
            raise InputError('worker observation requires matching API name/arguments, unsigned result and raw effects')
        runtime.events.append(('worker.API', name, arguments, event[2], event[3]))
        return event[2], event[3]


def install_image(memory, image_base):
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'worker-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed worker image identity mismatch')
    image = json.loads(raw)
    for segment in image['segments']:
        value = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            pointer = int.from_bytes(value[offset:offset + 8], 'little')
            value[offset:offset + 8] = ((pointer - image['image_base'] + image_base) & _MASK64).to_bytes(8, 'little')
        memory.map(image_base + segment['rva'], value, name='fixed worker image', initialized=True)


def _require_import(runtime, name):
    target = runtime.memory.load(runtime.image_base + _IMPORTS[name], 8)
    expected = runtime.worker_imports.get(name)
    if expected is None or target != expected:
        raise PrimarySemanticUnavailable('worker current import is not bound: ' + name)


def _observe(runtime, name, *arguments):
    _require_import(runtime, name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing SDK worker environment observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _units(raw):
    if not isinstance(raw, bytes) or len(raw) & 1:
        raise InputError('worker wide strings require complete UTF16 code units')
    return [int.from_bytes(raw[index:index + 2], 'little') for index in range(0, len(raw), 2)]


def _raw(units):
    return b''.join(value.to_bytes(2, 'little') for value in units)


def _c_wide(raw):
    value = _units(raw)
    if 0 not in value:
        raise PrimaryProgramLimit('worker wide C string leaves the observed buffer')
    return _raw(value[:value.index(0)])


def strip_path(units):
    offset, colons, colon_offset = 0, 0, None
    for index, value in enumerate(units):
        following = units[index + 1] if index + 1 < len(units) else 0
        if value in (47, 92) and following not in (0, 47, 92):
            offset, colons, colon_offset = index + 1, 0, None
        elif value == 58:
            colons += 1
            if colon_offset is None and following not in (0, 47, 92):
                colon_offset = index + 1
    if colons == 1 and colon_offset is not None:
        offset = colon_offset
    return units[offset:]


def remove_extension(units):
    dot = None
    for index, value in enumerate(units):
        if value in (32, 92):
            dot = None
        elif value == 46:
            dot = index
    return units[:dot] if dot is not None else units


class _WideString:
    def __init__(self, runtime, *, address=None, empty=False):
        self.runtime, self.address = runtime, address
        if address is None:
            self.header = bytearray(24)
            self.known = bytearray([int(empty)] * 24)
        else:
            region, offset = runtime.memory._span(address, 24)
            self.header = bytearray(region.data[offset:offset + 24])
            self.known = bytearray(region.initialized[offset:offset + 24])

    def get(self, offset, width):
        if self.address is not None:
            return self.runtime.memory.load(self.address + offset, width)
        if not all(self.known[offset:offset + width]):
            raise UnknownMemory('worker reads an unobserved local wide-string header')
        return int.from_bytes(self.header[offset:offset + width], 'little')

    def set(self, offset, value, width, source):
        data = (value & ((1 << (width * 8)) - 1)).to_bytes(width, 'little')
        self.header[offset:offset + width] = data
        self.known[offset:offset + width] = bytes([1]) * width
        if self.address is not None:
            self.runtime.memory.write(self.address + offset, data, source=source)

    def size(self):
        tag = self.get(0, 1)
        return self.get(8, 8) if tag & 1 else tag >> 1

    def value(self):
        length = self.size()
        if length > 1 << 20:
            raise PrimaryProgramLimit('worker wide-string length exceeds the offline support domain')
        if self.get(0, 1) & 1:
            return self.runtime.memory.read(self.get(16, 8), length * 2)
        if self.address is not None:
            return self.runtime.memory.read(self.address + 2, length * 2)
        if not all(self.known[2:2 + length * 2]):
            raise UnknownMemory('worker reads unobserved local wide-string units')
        return bytes(self.header[2:2 + length * 2])

    def _payload(self, raw, pointer, source):
        data = raw + b'\0\0'
        if pointer is not None:
            self.runtime.memory.write(pointer, data, source=source)
        else:
            self.header[2:2 + len(data)] = data
            self.known[2:2 + len(data)] = bytes([1]) * len(data)
            if self.address is not None:
                self.runtime.memory.write(self.address + 2, data, source=source)

    @classmethod
    def construct(cls, runtime, raw):
        length = len(_units(raw))
        value = cls(runtime)
        if length <= 10:
            value.set(0, length * 2, 1, 'worker.wide.short_tag')
            value._payload(raw, None, 'worker.wide.short_payload')
        else:
            count = (length + 8) & ~7
            pointer = runtime._operator_new(count * 2)
            value.set(16, pointer, 8, 'worker.wide.pointer')
            value.set(0, count | 1, 8, 'worker.wide.capacity')
            value.set(8, length, 8, 'worker.wide.length')
            value._payload(raw, pointer, 'worker.wide.long_payload')
        return value

    def assign(self, raw):
        length = len(_units(raw))
        long = self.get(0, 1) & 1
        capacity = (self.get(0, 8) & ~1) - 1 if long else 10
        if length > capacity:
            maximum = max(capacity * 2, length)
            count = ((maximum | 7) + 1) if maximum >= 11 else 11
            pointer = self.runtime._operator_new(count * 2)
            self._payload(raw, pointer, '75D130.wide_new_payload')
            if capacity != 10:
                self.runtime._free_allocation(self.get(16, 8))
            self.set(16, pointer, 8, '75D245.wide_pointer')
            self.set(0, count | 1, 8, '75D24D.wide_capacity')
            self.set(8, length, 8, '75D256.wide_length')
        else:
            pointer = self.get(16, 8) if long else None
            self._payload(raw, pointer, '75DF53.wide_payload')
            self.set(8 if long else 0, length if long else length * 2,
                     8 if long else 1, '75DF66.wide_length')

    def write_header(self, destination):
        memory = self.runtime.memory
        for start, end in ((16, 24), (0, 16)):
            index = start
            while index < end:
                known = self.known[index]
                stop = index + 1
                while stop < end and self.known[stop] == known:
                    stop += 1
                if known:
                    memory.write(destination + index, bytes(self.header[index:stop]), source='worker.wide_header_copy')
                else:
                    memory.forget(destination + index, stop - index, source='worker.wide_header_unknown_copy')
                index = stop

    def clone_to(self, destination):
        if not self.get(0, 1) & 1:
            self.write_header(destination)
            return
        copy = self.construct(self.runtime, self.value())
        copy.write_header(destination)

    def destroy(self):
        if self.get(0, 1) & 1:
            self.runtime._free_allocation(self.get(16, 8))


def construct_context(runtime, address):
    memory = runtime.memory
    for offset, value, width in ((0, address, 8), (8, address, 8), (16, 0, 8),
                                  (24, address + 24, 8), (32, address + 24, 8)):
        memory.store(address + offset, value, width, source='2DE94F0.context')
    for offset in (*range(0x28, 0xE0, 16), 0xE1):
        memory.write(address + offset, bytes(16), source='2DE94F0.context_zero16')
    memory.store(address + 0xF4, 1, 4, source='2DE94F0.context_enabled')
    return address


def _context(runtime):
    slot = runtime.image_base + 0x677CEF8
    address = runtime.memory.load(slot, 8)
    if not address:
        address = runtime._operator_new(248)
        construct_context(runtime, address)
        runtime.memory.store(slot, address, 8, source='worker.publish_context')
    return address


def _contains(runtime, head, raw):
    memory = runtime.memory
    node = memory.load(head + 8, 8)
    length = len(raw) // 2
    for _ in range(4096):
        if node == head:
            return False
        value = _WideString(runtime, address=node + 16)
        if value.size() == length and value.value() == raw:
            return True
        node = memory.load(node + 8, 8)
    raise PrimaryProgramLimit('worker list traversal exceeds the offline support domain')


def _insert(runtime, head, value, *, move=False):
    memory = runtime.memory
    node = runtime._operator_new(40)
    if move:
        value.write_header(node + 16)
    else:
        memory.store(node, 0, 8, source='worker.new_node_initial')
        value.clone_to(node + 16)
    memory.store(node + 8, head, 8, source='worker.node_previous')
    previous = memory.load(head, 8)
    memory.store(node, previous, 8, source='worker.node_next')
    memory.store(previous + 8, node, 8, source='worker.previous_link')
    memory.store(head, node, 8, source='worker.head_link')
    memory.store(head + 16, memory.load(head + 16, 8) + 1, 8, source='worker.list_count')


def _buffer(payload, size):
    if not isinstance(payload, bytes) or len(payload) > size:
        raise InputError('worker API effects exceed the actual output buffer')
    return payload + bytes(size - len(payload))


def window_callback(runtime, window, process_id):
    _, actual = _observe(runtime, 'GetWindowThreadProcessId', window)
    if actual is None:
        raise UnknownMemory('GetWindowThreadProcessId did not define the compared process ID')
    if type(actual) is not int or not 0 <= actual <= 0xFFFFFFFF:
        raise InputError('window process ID must be a DWORD memory observation')
    if actual != process_id & 0xFFFFFFFF:
        return 1
    _, payload = _observe(runtime, 'GetClassNameW', window, 100)
    if not isinstance(payload, bytes) or len(payload) > 200:
        raise InputError('GetClassNameW effects exceed its100-code-unit capacity')
    value = _c_wide(_buffer(payload, 202))
    if value:
        context = _context(runtime)
        if not _contains(runtime, context, value):
            context = _context(runtime)
            _insert(runtime, context, _WideString.construct(runtime, value), move=True)
    return 1


def _settings(runtime):
    memory, base = runtime.memory, runtime.image_base
    slot = base + 0x6751B38
    pointer = memory.load(slot, 8)
    if not pointer:
        pointer = runtime._operator_new(72)
        for offset in (0, 16, 48, 32):
            memory.write(pointer + offset, bytes(16), source='worker.settings_zero16')
        memory.store(pointer + 64, 0, 8, source='worker.settings_zero8')
        for offset, value, width in ((4, 0x300000003, 8), (12, 0, 1), (13, 0, 4), (20, 0, 4), (24, 0, 1)):
            memory.store(pointer + offset, value, width, source='worker.settings_default')
        memory.write(pointer + 40, bytes(16), source='worker.settings_vector')
        memory.store(pointer + 32, pointer + 40, 8, source='worker.settings_vector_pointer')
        for offset, value, width in ((56, 1, 1), (60, 0, 4), (64, 2, 2), (66, 0, 1)):
            memory.store(pointer + offset, value, width, source='worker.settings_default')
        memory.store(slot, pointer, 8, source='worker.settings_publish')
    return pointer


@contextmanager
def _refresh_status(runtime, vm, values, kind):
    scope = runtime.__dict__.get('_primary_direct_scope')
    if scope is not None and scope.worker_owner is not None:
        domain = scope.refresh_status_operation(vm, values, kind)
        with domain:
            yield scope.refresh_wrapper
    else:
        yield None


def _flag(runtime, bit, mask):
    from types import SimpleNamespace
    memory = runtime.memory
    pointer = _settings(runtime)
    memory.store(pointer + 60, memory.load(pointer + 60, 4) | mask, 4, source='worker.environment_flags')
    values = (1, bit, 1, 0)
    vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    status_domain = _refresh_status(runtime, vm, values, 'flag')
    with status_domain as authorize:
        for rva in (0x1BF75A0, 0x1BF8090):
            if authorize is not None:
                authorize(rva)
            runtime.invoke(vm, rva, (0, 1, 2, 3))


def _temporary_patterns(runtime, values):
    nodes = []
    for raw in values:
        value = _WideString.construct(runtime, raw)
        node = runtime._operator_new(40)
        runtime.memory.store(node, 0, 8, source='2DEB62E.temporary_node')
        value.clone_to(node + 16)
        runtime.memory.forget(node + 8, 8, source='worker.unobserved_stack_sentinel')
        if nodes:
            runtime.memory.store(node, nodes[-1], 8, source='worker.temporary_next')
            runtime.memory.store(nodes[-1] + 8, node, 8, source='worker.temporary_previous')
        else:
            runtime.memory.forget(node, 8, source='worker.unobserved_stack_sentinel')
        nodes.append(node)
        value.destroy()
    return nodes


def classify_environment(runtime, context):
    from .primary_sign import _FOLD
    memory = runtime.memory
    result, payload = _observe(runtime, 'GetModuleFileNameA', 0, 260)
    if result & 0xFFFFFFFF:
        path = _buffer(payload, 260)
        if 0 not in path:
            raise PrimaryProgramLimit('worker ANSI module filename leaves the observed buffer')
        _require_import(runtime, 'PathStripPathA')
        name = strip_path(list(path[:path.index(0)]))
        if any(value >= 128 for value in name):
            raise PrimarySemanticUnavailable('worker ANSI process path needs its native codepage state')
        if memory.load(runtime.image_base + 0x6D8E630, 4):
            raise PrimarySemanticUnavailable('worker process comparison requires the current CRT locale path')
        folded = bytes(_FOLD[value] for value in name)
        if folded == b'qq.exe' and folded == b'ntqq.exe':
            _flag(runtime, 4, 0x10)
    required = _temporary_patterns(runtime, tuple(value.encode('utf-16-le') for value in ('wrapper', 'ffmpeg')))
    unused = _temporary_patterns(runtime, ('qqntopensdk'.encode('utf-16-le'),))
    for node in required:
        if not _contains(runtime, context + 24, _WideString(runtime, address=node + 16).value()):
            _flag(runtime, 5, 0x20)
            break
    if not _contains(runtime, context, 'Base_PowerMessageWindow'.encode('utf-16-le')):
        _flag(runtime, 7, 0x80)
    for nodes in (unused, required):
        for node in nodes:
            _WideString(runtime, address=node + 16).destroy()
            runtime._free_allocation(node)


def lower_unit(runtime, unit):
    unit &= 0xFFFF
    if unit == 0xFFFF:
        return unit
    memory, base = runtime.memory, runtime.image_base
    if memory.load(base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable('worker wide lowering requires current per-thread CRT locale effects')
    locale = memory.load(base + 0x6744B68, 8)
    utf8 = memory.load(locale + 12, 4) == 65001
    if (utf8 and unit < 128) or (not utf8 and unit < 256):
        if memory.load(base + 0x45BB680 + 2 + unit * 2, 1) & 1:
            return memory.load(memory.load(locale + 0x110, 8) + unit, 1)
        return unit
    if not utf8 and memory.load(locale + 0x138, 8) == 0:
        return unit
    raise PrimarySemanticUnavailable('worker wide lowering requires observed LCMapString effects')


def _path_value(runtime, raw, keep_extension):
    units = _units(raw)
    if not keep_extension & 0xFFFFFFFF:
        _require_import(runtime, 'PathRemoveExtensionW')
        units = remove_extension(units)
    _require_import(runtime, 'PathStripPathW')
    return _raw(strip_path(units))


def path_name(runtime, source, output, keep_extension):
    memory = runtime.memory
    tag = memory.load(source, 1)
    pointer = memory.load(source + 16, 8) if tag & 1 else source + 2
    value = []
    for index in range(260):
        unit = memory.load(pointer + index * 2, 2)
        if not unit:
            result = _path_value(runtime, _raw(value), keep_extension)
            _WideString(runtime, address=output).assign(result)
            return 1
        value.append(unit)
    return 0


def probe_module(runtime):
    result, _ = _observe(runtime, 'GetModuleHandleW', 'frida-agent.dll'.encode('utf-16-le'))
    return int(result != 0)


def refresh_context(runtime, context):
    memory, base = runtime.memory, runtime.image_base
    if not memory.load(context + 0xF4, 4):
        return None
    if not memory.load(context + 0x28, 8):
        process, _ = _observe(runtime, 'GetCurrentProcess')
        result, payload = _observe(runtime, 'K32EnumProcessModules', process, 8192)
        if (not isinstance(payload, tuple) or len(payload) != 2 or type(payload[0]) is not int or
                not 0 <= payload[0] <= 0xFFFFFFFF):
            raise InputError('module enumeration requires raw DWORD needed and handle-buffer effects')
        required, handles = payload
        handles = _buffer(handles, 8192)
        output = _WideString(runtime, empty=True)
        if result & 0xFFFFFFFF:
            for index in range(required >> 3):
                if index >= 1024:
                    raise PrimaryProgramLimit('original module enumeration reads beyond its observed8192-byte stack buffer')
                handle = int.from_bytes(handles[index * 8:index * 8 + 8], 'little')
                result, payload = _observe(runtime, 'GetModuleFileNameW', handle, 260)
                if not result & 0xFFFFFFFF:
                    continue
                raw = _c_wide(_buffer(payload, 520))
                incoming = _WideString.construct(runtime, raw)
                if len(raw) // 2 < 260:
                    output.assign(_path_value(runtime, raw, 0))
                    success = True
                else:
                    success = False
                incoming.destroy()
                if not success:
                    continue
                lowered = _raw([lower_unit(runtime, unit) for unit in _units(output.value())])
                output._payload(lowered, output.get(16, 8) if output.get(0, 1) & 1 else None,
                                '2DEA0A8.lowered_module')
                if not _contains(runtime, context + 24, lowered):
                    _insert(runtime, context + 24, output)
        output.destroy()
    process_id, _ = _observe(runtime, 'GetCurrentProcessId')
    _, windows = _observe(runtime, 'EnumWindows', base + 0x2DE9570, process_id & 0xFFFFFFFF)
    if not isinstance(windows, tuple) or any(type(value) is not int or not 0 <= value <= _MASK64 for value in windows):
        raise InputError('EnumWindows requires an observed sequence of window handles')
    for window in windows:
        window_callback(runtime, window, process_id)
    if not memory.load(context + 0xF4, 4):
        return None
    if probe_module(runtime):
        _flag(runtime, 17, 0x200)
    classify_environment(runtime, context)
    result, power = _observe(runtime, 'GetSystemPowerStatus')
    if result & 0xFFFFFFFF:
        if not isinstance(power, bytes) or len(power) > 12:
            raise InputError('power status requires raw effects within the12-byte structure')
        if len(power) < 2:
            raise UnknownMemory('GetSystemPowerStatus did not define BatteryFlag')
        if power[1] not in (0x80, 0xFF):
            values = (1, 23, 1, 0)
            from types import SimpleNamespace
            vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
            status_domain = _refresh_status(runtime, vm, values, 'power')
            with status_domain as authorize:
                for rva in (0x1BF75A0, 0x1BF8090):
                    if authorize is not None:
                        authorize(rva)
                    runtime.invoke(vm, rva, (0, 1, 2, 3))
    pointer = _settings(runtime)
    value = memory.load(pointer, 4)
    from .primary_logger import worker_log
    return worker_log(runtime, value)


def invoke(runtime, rva, values):
    counts = {0x2DE94F0: 1, 0x2DE9570: 2, 0x2DE9910: 1, 0x2DEA400: 1,
              0x2DF5490: 0, 0x2E11410: 3, 0x3E8F070: 1}
    if rva not in counts or len(values) != counts[rva]:
        raise InputError('worker source interface argument count mismatch')
    if rva == 0x2DE94F0:
        return construct_context(runtime, values[0])
    if rva == 0x2DE9570:
        return window_callback(runtime, *values)
    if rva == 0x2DE9910:
        return refresh_context(runtime, values[0])
    if rva == 0x2DEA400:
        return classify_environment(runtime, values[0])
    if rva == 0x2DF5490:
        return probe_module(runtime)
    if rva == 0x2E11410:
        return path_name(runtime, *values)
    return lower_unit(runtime, values[0])
