from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_IMAGE_SHA256 = '3d8c78483f3aa1f462511448c261af60aed331568c7535a99e8f567e12ac7225'
_IMPORTS = {'AcquireSRWLockExclusive': 0x490FBC0, 'ReleaseSRWLockExclusive': 0x4910298}
_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20
_FORMAT = re.compile(rb'%([-+ #0]*)([0-9]*)(?:\.([0-9]+))?(hh|h|ll|l|I64|I32|z|t)?([diuoxXcs%])')


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'logger-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed logger image identity mismatch')
    return json.loads(raw)


def install_image(memory, image_base):
    for segment in _image()['segments']:
        if segment['rva'] == 0x6749CC0:
            if memory.read(image_base + segment['rva'], 8) != bytes.fromhex(segment['hex']):
                raise InputError('shared CRT formatting image identity mismatch')
            continue
        memory.map(image_base + segment['rva'], bytearray.fromhex(segment['hex']),
                   name='fixed logger image', initialized=True)


def _decode(value):
    return bytes(byte ^ value['seed'] ^ (index + 1) ^ value['length']
                 for index, byte in enumerate(bytes.fromhex(value['encrypted_hex'])))


def _cstring(runtime, value):
    if isinstance(value, bytes):
        return value.split(b'\0', 1)[0]
    if type(value) is not int:
        raise InputError('logger C string requires bytes or a current memory pointer')
    raw = bytearray()
    for index in range(_LIMIT):
        byte = runtime.memory.load((value + index) & _MASK64, 1)
        if not byte:
            return bytes(raw)
        raw.append(byte)
    raise PrimaryProgramLimit('logger C string exceeds the bounded offline domain')


def _srw(runtime, pointer, acquire):
    name = 'AcquireSRWLockExclusive' if acquire else 'ReleaseSRWLockExclusive'
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('logger current synchronization import is not bound: ' + name)
    if pointer == runtime.image_base + 0x674D4D0:
        from .primary_module_sync import shared_acquire, shared_release
        (shared_acquire if acquire else shared_release)(runtime)
        runtime.events.append(('logger.' + name, pointer))
        return
    if not hasattr(runtime, '_logger_locks'):
        runtime._logger_locks = {}
    held = runtime._logger_locks.get(pointer, False)
    if acquire:
        if held or runtime.memory.load(pointer, 8):
            raise PrimarySemanticUnavailable('logger SRW contention/reentrancy requires actual thread scheduling')
        runtime._logger_locks[pointer] = True
    else:
        if not held:
            raise PrimarySemanticUnavailable('logger SRW release has no matching acquire')
        runtime._logger_locks[pointer] = False
    runtime.events.append(('logger.' + name, pointer))


class _String:
    def __init__(self, runtime, header=None, known=None):
        self.runtime = runtime
        self.header = bytearray(24) if header is None else bytearray(header)
        self.known = bytearray(24) if known is None else bytearray(known)

    def set(self, offset, value):
        self.header[offset:offset + len(value)] = value
        self.known[offset:offset + len(value)] = b'\1' * len(value)

    def get(self, offset, size):
        if not all(self.known[offset:offset + size]):
            raise UnknownMemory('logger reads an unobserved local string field')
        return int.from_bytes(self.header[offset:offset + size], 'little')

    @classmethod
    def construct(cls, runtime, value, capacity=None, *, _owned=None):
        size = len(value)
        required = size if capacity is None else capacity
        if not size <= required <= _LIMIT:
            raise PrimaryProgramLimit('logger string allocation exceeds the bounded offline domain')
        result = cls(runtime)
        if required <= 22:
            result.set(0, bytes([size * 2]))
            result.set(1, value + b'\0')
        else:
            physical = (required | 15) + 1
            from .primary_worker_consumer import _invoke
            pointer = _invoke(runtime, 0xB75000, physical)
            if _owned is not None:
                from .primary_sign_lifecycle import region_at
                _owned.append((pointer, region_at(runtime.memory, pointer)))
            result.set(0, (physical | 1).to_bytes(8, 'little'))
            result.set(8, size.to_bytes(8, 'little'))
            result.set(16, pointer.to_bytes(8, 'little'))
            runtime.memory.write(pointer, value + b'\0', source='logger.string_payload')
        return result

    @classmethod
    def read(cls, runtime, address):
        region, offset = runtime.memory._span(address, 24)
        return cls(runtime, region.data[offset:offset + 24], region.initialized[offset:offset + 24])

    def value(self):
        if self.get(0, 1) & 1:
            size, pointer = self.get(8, 8), self.get(16, 8)
            if size > _LIMIT:
                raise PrimaryProgramLimit('logger current string exceeds the bounded offline domain')
            return self.runtime.memory.read(pointer, size)
        size = self.get(0, 1) >> 1
        if size > 22 or not all(self.known[1:size + 1]):
            raise UnknownMemory('logger reads an unknown short string')
        return bytes(self.header[1:size + 1])

    def clone(self, *, _owned=None):
        if self.get(0, 1) & 1:
            return self.construct(self.runtime, self.value(), _owned=_owned)
        return _String(self.runtime, self.header, self.known)

    def write_to(self, address):
        offset = 0
        while offset < 24:
            end = offset + 1
            while end < 24 and self.known[end] == self.known[offset]:
                end += 1
            if self.known[offset]:
                self.runtime.memory.write(address + offset, bytes(self.header[offset:end]), source='logger.string_copy')
            else:
                self.runtime.memory.forget(address + offset, end - offset, source='logger.unobserved_string_padding')
            offset = end

    def append(self, value):
        previous = self.value()
        if self.get(0, 1) & 1:
            capacity = (self.get(0, 8) & ~1) - 1
            if len(previous) + len(value) > capacity:
                raise PrimarySemanticUnavailable('logger string append growth is outside the recovered concatenation path')
            pointer = self.get(16, 8)
            self.runtime.memory.write(pointer + len(previous), value + b'\0', source='logger.string_append')
            self.set(8, (len(previous) + len(value)).to_bytes(8, 'little'))
        else:
            if len(previous) + len(value) > 22:
                raise PrimarySemanticUnavailable('logger short append exceeds its recovered preallocated capacity')
            self.set(0, bytes([(len(previous) + len(value)) * 2]))
            self.set(1 + len(previous), value + b'\0')

    @classmethod
    def concat(cls, runtime, first, second):
        result = cls.construct(runtime, first, len(first) + len(second))
        result.append(second)
        return result

    def destroy(self):
        if self.get(0, 1) & 1:
            from .primary_worker_consumer import _invoke
            _invoke(self.runtime, 0xB75029, self.get(16, 8))


class _Tree:
    def __init__(self, runtime, address):
        self.runtime, self.memory, self.address = runtime, runtime.memory, address

    def load(self, pointer, offset=0, size=8):
        return self.memory.load(pointer + offset, size)

    def store(self, pointer, offset, value, size=8):
        self.memory.store(pointer + offset, value, size, source='logger.tree')

    def rotate(self, pointer, left):
        side, other = (8, 0) if left else (0, 8)
        child = self.load(pointer, side)
        moved = self.load(child, other)
        self.store(pointer, side, moved)
        if moved:
            self.store(moved, 16, pointer)
        parent = self.load(pointer, 16)
        self.store(child, 16, parent)
        self.store(parent, 0 if self.load(parent) == pointer else 8, child)
        self.store(child, other, pointer)
        self.store(pointer, 16, child)

    def balance(self, root, node):
        self.store(node, 24, int(node == root), 1)
        for _ in range(4096):
            if node == root:
                return
            parent = self.load(node, 16)
            if self.load(parent, 24, 1):
                return
            grandparent = self.load(parent, 16)
            parent_left = self.load(grandparent) == parent
            uncle = self.load(grandparent, 8 if parent_left else 0)
            if uncle and not self.load(uncle, 24, 1):
                self.store(parent, 24, 1, 1)
                self.store(grandparent, 24, int(grandparent == root), 1)
                self.store(uncle, 24, 1, 1)
                node = grandparent
                continue
            if self.load(parent, 8 if parent_left else 0) == node:
                self.rotate(parent, parent_left)
                parent = self.load(parent, 16)
                grandparent = self.load(parent, 16)
            self.store(parent, 24, 1, 1)
            self.store(grandparent, 24, 0, 1)
            self.rotate(grandparent, not parent_left)
            return
        raise PrimaryProgramLimit('logger red-black tree exceeds its bounded traversal')

    def insert(self, key, size, initialize):
        signed = key if key < 1 << 31 else key - (1 << 32)
        parent, slot = self.address + 8, self.address + 8
        node = self.load(slot)
        for _ in range(4096):
            if not node:
                # Recovered logger nodes and consumer record nodes use this upper pair.
                if size in (72, 40, 64):
                    from .primary_worker_consumer import _invoke
                    node = _invoke(self.runtime, 0xB75000, size)
                else:
                    node = self.runtime._operator_new(size)
                initialize(node)
                self.memory.write(node, bytes(16), source='logger.tree_children')
                self.store(node, 16, parent)
                self.store(slot, 0, node)
                begin = self.load(self.address)
                left = self.load(begin)
                if left:
                    self.store(self.address, 0, left)
                self.balance(self.load(self.address, 8), node)
                self.store(self.address, 16, (self.load(self.address, 16) + 1) & _MASK64)
                return node
            present = self.load(node, 32, 4)
            present = present if present < 1 << 31 else present - (1 << 32)
            if present == signed:
                return node
            parent, slot = node, node + (0 if signed < present else 8)
            node = self.load(slot)
        raise PrimaryProgramLimit('logger red-black tree exceeds its bounded traversal')

    def nodes(self):
        pending, node, seen = [], self.load(self.address, 8), set()
        while pending or node:
            if node:
                if node in seen or len(seen) >= 4096:
                    raise PrimaryProgramLimit('logger tree cycle or traversal bound')
                seen.add(node)
                pending.append(node)
                node = self.load(node)
            else:
                node = pending.pop()
                yield node
                node = self.load(node, 8)


def construct(runtime, pointer):
    memory, data = runtime.memory, _image()
    memory.write(pointer, bytes(24), source='BC2136.logger_string')
    for offset in (24, 64):
        memory.store(pointer + offset, pointer + offset + 8, 8, source='BC2100.tree_begin')
        memory.write(pointer + offset + 8, bytes(16), source='BC2100.tree_root_count')
    memory.store(pointer + 48, 0, 8, source='BC2163.logger_mutex')
    memory.store(pointer + 56, 0, 4, source='BC216B.logger_mutex_aux')
    memory.write(pointer + 88, bytes(32), source='BC2194.logger_tail')
    _srw(runtime, pointer + 48, True)
    prefix = _decode(data['prefix'])
    memory.store(pointer, len(prefix) * 2, 1, source='BC2273.prefix_length')
    memory.write(pointer + 1, prefix + b'\0', source='BC2273.prefix')
    originals, initializers = [], []
    for definition in data['definitions']:
        value = _String.construct(runtime, _decode(definition['name']))
        originals.append(value)
        initializers.append((definition, value.clone()))
    definitions = _Tree(runtime, pointer + 24)
    for definition, value in initializers:
        def initialize(node):
            memory.store(node + 32, definition['id'], 4, source='BCCF36.definition_id')
            value.clone().write_to(node + 40)
            memory.store(node + 64, definition['default'], 4, source='BCCF36.definition_default')
            memory.store(node + 68, definition['override'], 1, source='BCCF36.definition_override')
        definitions.insert(definition['id'], 72, initialize)
    for _, value in reversed(initializers):
        value.destroy()
    for value in reversed(originals):
        value.destroy()
    values = _Tree(runtime, pointer + 64)
    for definition in definitions.nodes():
        key = memory.load(definition + 32, 4)
        name = _String.read(runtime, definition + 40).clone()
        default = memory.load(definition + 64, 4)
        def initialize(node):
            memory.store(node + 32, key, 4, source='BC9DCF.value_id')
            memory.store(node + 36, 0, 4, source='BC9DD2.value_initial')
        node = values.insert(key, 40, initialize)
        memory.store(node + 36, default, 4, source='BC9E17.value_default')
        if memory.load(definition + 68, 1):
            configuration_key = _String.concat(runtime, prefix, name.value())
            provider = memory.load(runtime.image_base + 0x677BDD8, 8)
            if provider:
                from .primary_caller_audit import _atoi
                from .primary_worker_consumer import _invoke
                from .primary_worker_response import _frame
                frame, _ = _frame(runtime, 48, 'BC9E40.logger_configuration_strings')
                configuration_key.write_to(frame)
                _invoke(runtime, 0x1BE5B70, frame + 24, frame)
                configuration_key.destroy()
                value = _String.read(runtime, frame + 24)
                if value.value():
                    observed = _atoi(_cstring(runtime, value.value()))
                    memory.store(node + 36, observed, 4, source='BC9F80.configuration_value')
                value.destroy()
                memory.unmap(frame)
            else:
                configuration_key.destroy()
        name.destroy()
    _srw(runtime, pointer + 48, False)
    return pointer


def feature(runtime, pointer, key):
    memory = runtime.memory
    key &= 0xFFFFFFFF
    signed = key if key < 1 << 31 else key - (1 << 32)
    _srw(runtime, pointer + 48, True)
    node, candidate = memory.load(pointer + 72, 8), pointer + 72
    for _ in range(4096):
        if not node:
            break
        present = memory.load(node + 32, 4)
        present = present if present < 1 << 31 else present - (1 << 32)
        if present >= signed:
            candidate = node
        node = memory.load(node + (8 if present < signed else 0), 8)
    else:
        raise PrimaryProgramLimit('logger feature lookup exceeds its bounded traversal')
    result = 2
    if candidate != pointer + 72 and memory.load(candidate + 32, 4) == key:
        result = memory.load(candidate + 36, 4)
    _srw(runtime, pointer + 48, False)
    return result


def _format(runtime, template, arguments):
    options = runtime.memory.load(runtime.image_base + 0x6749CC0, 8)
    if options not in (0, 0x18, 0x24) or runtime.memory.load(runtime.image_base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable('logger nondefault CRT formatting options or thread locale effects are unavailable')
    if options in (0x18, 0x24) and (not isinstance(template, bytes) or any(byte >= 128 or byte == 0 for byte in template)):
        raise PrimarySemanticUnavailable('logger finite-options requires its finite ASCII narrow template domain')
    if options in (0x18, 0x24) and len(template) > _LIMIT:
        raise PrimaryProgramLimit('logger printf output exceeds the bounded offline domain')
    output, offset, index = bytearray(), 0, 0
    while offset < len(template):
        if template[offset] != 37:
            output.append(template[offset])
            offset += 1
            continue
        match = _FORMAT.match(template, offset)
        if match is None:
            raise PrimarySemanticUnavailable('logger printf conversion requires unrecovered CRT formatting semantics')
        flags, width, precision, length, conversion = match.groups()
        if options in (0x18, 0x24) and (flags or width or precision is not None or length or conversion not in (b'd', b'u', b's')):
            raise PrimarySemanticUnavailable('logger finite-options supports only bare narrow d/u/s conversions')
        width, precision = int(width or b'0'), None if precision is None else int(precision)
        if width > _LIMIT or (precision is not None and precision > _LIMIT):
            raise PrimaryProgramLimit('logger printf field exceeds the bounded offline domain')
        offset = match.end()
        sign = b''
        if conversion == b'%':
            value = b'%'
        else:
            if index == len(arguments):
                raise UnknownMemory('logger printf reads an unobserved variadic argument')
            argument = arguments[index]
            index += 1
            if options in (0x18, 0x24):
                if conversion in (b'd', b'u') and type(argument) is not int:
                    raise UnknownMemory('logger finite-options reads an unobserved integer variadic argument')
                if conversion == b's' and type(argument) is int and argument == 0:
                    raise PrimarySemanticUnavailable('logger finite-options NULL narrow CString is unsupported')
            if conversion == b's' and not length:
                value = _cstring(runtime, argument)
                if precision is not None:
                    value = value[:precision]
            elif conversion == b'c' and not length:
                value = bytes([argument & 255])
            elif conversion in (b'd', b'i', b'u', b'o', b'x', b'X'):
                bits = 64 if length in (b'll', b'I64', b'z', b't') else 8 if length == b'hh' else 16 if length == b'h' else 32
                number = argument & ((1 << bits) - 1)
                if conversion in (b'd', b'i'):
                    number = number if number < 1 << (bits - 1) else number - (1 << bits)
                    sign = b'-' if number < 0 else b'+' if b'+' in flags else b' ' if b' ' in flags else b''
                    number = abs(number)
                value = format(number, 'x' if conversion == b'x' else 'X' if conversion == b'X' else 'o' if conversion == b'o' else 'd').encode('ascii')
                if precision == 0 and not number:
                    value = b''
                if precision is not None:
                    value = value.rjust(precision, b'0')
                if b'#' in flags:
                    if conversion in (b'x', b'X') and number:
                        sign += b'0x' if conversion == b'x' else b'0X'
                    elif conversion == b'o' and not value.startswith(b'0'):
                        value = b'0' + value
            else:
                raise PrimarySemanticUnavailable('logger wide-character printf conversion needs actual locale semantics')
        missing = max(0, width - len(sign) - len(value))
        if b'-' in flags:
            value = sign + value + b' ' * missing
        elif b'0' in flags and precision is None and conversion in (b'd', b'i', b'u', b'o', b'x', b'X'):
            value = sign + b'0' * missing + value
        else:
            value = b' ' * missing + sign + value
        output.extend(value)
        if len(output) > _LIMIT:
            raise PrimaryProgramLimit('logger printf output exceeds the bounded offline domain')
    return bytes(output)


@dataclass(frozen=True)
class LoggerOutput:
    address: int
    callback: object

    def __post_init__(self):
        if type(self.address) is not int or not 0 < self.address <= _MASK64 or not callable(self.callback):
            raise InputError('logger output requires an explicit target address and callable effect provider')

    def emit(self, runtime, value, tag, severity):
        effects = self.callback(value.split(b'\0', 1)[0], tag, severity)
        if not isinstance(effects, tuple):
            raise InputError('logger output must return an explicit tuple of memory effects')
        for effect in effects:
            if (not isinstance(effect, tuple) or len(effect) != 2 or type(effect[0]) is not int or
                    not 0 <= effect[0] <= _MASK64 or not isinstance(effect[1], bytes)):
                raise InputError('logger output effect requires an unsigned address and raw bytes')
            runtime.memory.write(effect[0], effect[1], source='logger.output_callback')


def log(runtime, source_file, line, template, tag, severity, *arguments, feature_key=3):
    memory, base = runtime.memory, runtime.image_base
    pointer = memory.load(base + 0x67516A8, 8)
    if not pointer:
        from .primary_worker_consumer import _invoke
        pointer = _invoke(runtime, 0xB75000, 120)
        construct(runtime, pointer)
        memory.store(base + 0x67516A8, pointer, 8, source='B9F22E.logger_publish')
    if feature(runtime, pointer, feature_key) != 1:
        return None
    source = _cstring(runtime, source_file)
    separator = max(source.rfind(b'/', 1), source.rfind(b'\\', 1))
    if not source:
        location = b'empty'
    elif separator == len(source) - 1:
        location = b'error_filename'
    else:
        filename = source[separator + 1:]
        location = _format(runtime, bytes.fromhex(_image()['worker']['location_format_hex']), (filename, line & 0xFFFFFFFF))
    location_value = _String.construct(runtime, location[:-1] + b'\0\0' if len(location) > 255 else location)
    message = _format(runtime, _cstring(runtime, template), arguments)
    message_value = _String.construct(runtime, message + (b'\0' if len(message) > 255 else b''))
    target = memory.load(base + 0x677BD88, 8)
    if target:
        combined = _String.concat(runtime, location_value.value(), message_value.value())
        output = runtime.logger_output
        if not isinstance(output, LoggerOutput) or output.address != target:
            raise PrimarySemanticUnavailable('B9F507 actual output callback target/effects are not bound')
        severity &= 0xFFFFFFFF
        raw_tag = _cstring(runtime, tag)
        runtime.events.append(('logger.output', target, combined.value(), raw_tag, severity))
        output.emit(runtime, combined.value(), raw_tag, severity)
        combined.destroy()
    location_value.destroy()
    message_value.destroy()
    return None


def worker_log(runtime, value):
    data = _image()['worker']
    return log(runtime, _decode(data['file']), 0xE6, _decode(data['format']),
               bytes.fromhex(data['worker_tag_hex']), 1, value)


def invoke(runtime, rva, values):
    if rva == 0xBC2100 and len(values) == 1:
        return construct(runtime, values[0])
    if rva == 0x1BE3F80 and len(values) == 2:
        return feature(runtime, *values)
    if rva == 0xB9F1D0 and len(values) >= 5:
        return log(runtime, *values)
    if rva == 0x1C56610 and len(values) >= 4:
        return log(runtime, *values[:4], 2, *values[4:], feature_key=5)
    raise InputError('logger source interface argument count mismatch')
