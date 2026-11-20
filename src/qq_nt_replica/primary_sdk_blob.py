import hashlib
import json
from pathlib import Path
from dataclasses import dataclass

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable, PrimaryProgramLimit, signed
from .primary_logger import _String, _cstring, log
from .primary_worker_consumer import _invoke


def application_material32():
    literal = '0xeb1fd6ac257461580dc7438eb099f23aae04ca679f4d88f53072dc56e3bb1129'
    hexadecimal = literal[2:] if literal.startswith('0x') else literal
    output = bytearray(len(hexadecimal) // 2)
    for offset in range(0, len(hexadecimal), 2):
        output[offset // 2] = int(hexadecimal[offset:offset + 2], 16)
    return bytes(output)


@dataclass(frozen=True)
class LoadedModuleImage:
    name: bytes
    guest_base: int
    segments: tuple[tuple[int, bytes], ...]

    def __post_init__(self):
        if not isinstance(self.name, bytes) or not self.name or b'\0' in self.name:
            raise InputError("module image requires its exact nonempty name bytes")
        if type(self.guest_base) is not int or not 0 < self.guest_base < 1 << 64:
            raise InputError("module image requires an unsigned64 nonzero guest base")
        if not isinstance(self.segments, tuple) or not self.segments:
            raise InputError("module image requires explicit known byte segments")
        end = 0
        for offset, raw in self.segments:
            if type(offset) is not int or offset < end or not isinstance(raw, bytes) or not raw:
                raise InputError("module image segments must be nonempty ordered disjoint known bytes")
            end = offset + len(raw)
            if self.guest_base + end > 1 << 64:
                raise InputError("module image segment wraps its guest address")

    @classmethod
    def qq52230(cls, guest_base):
        directory = Path(__file__).with_name('data') / 'primary_sign_qq52230'
        descriptor = (directory / 'qqnt-module-image.json').read_bytes()
        if hashlib.sha256(descriptor).hexdigest() != '92517282048483c7586521ff84ef866284dc5039906d35bded939c7d9dd20f78':
            raise InputError("fixed QQNT module projection identity mismatch")
        image = json.loads(descriptor)
        segments = []
        for row in image['segments']:
            raw = (directory / row['path']).read_bytes()
            if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise InputError("fixed QQNT module segment identity mismatch")
            segments.append((row['rva'], raw + bytes(row['virtual_bytes'] - len(raw))))
        return cls(bytes.fromhex(image['name_hex']), guest_base, tuple(segments))

    def install(self, memory):
        for offset, raw in self.segments:
            memory.map(self.guest_base + offset, raw, name="declared loaded module " + repr(self.name),
                       initialized=True)


class SDKKeyInvalidArgument(PrimarySemanticUnavailable):
    pass


class SDKKeyOutOfRange(PrimarySemanticUnavailable):
    pass


def parse_key(runtime, string, consumed, base):
    if base & 0xFFFFFFFF != 10:
        raise PrimarySemanticUnavailable("75E460 nondecimal base requires its source conversion contract")
    if runtime.memory.load(runtime.image_base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable("75E460 nondefault locale requires actual current locale semantics")
    raw = _String.read(runtime, string).value().split(b'\0', 1)[0]
    errno = _invoke(runtime, 0x3E84C9C)
    saved = runtime.memory.load(errno, 4)
    runtime.memory.store(errno, 0, 4, source='75E460.errno_clear')
    offset = 0
    while offset < len(raw) and raw[offset] in b' \t\n\v\f\r':
        offset += 1
    negative = offset < len(raw) and raw[offset] == 45
    if offset < len(raw) and raw[offset] in (43, 45):
        offset += 1
    begin = offset
    value, overflow = 0, False
    limit = 2147483648 if negative else 2147483647
    while offset < len(raw) and 48 <= raw[offset] <= 57:
        digit = raw[offset] - 48
        if value > (limit - digit) // 10:
            overflow = True
        if not overflow:
            value = value * 10 + digit
        offset += 1
    if overflow:
        runtime.memory.store(errno, 34, 4, source='3E8E8EC.signed32_ERANGE')
    current = runtime.memory.load(errno, 4)
    runtime.memory.store(errno, saved, 4, source='75E460.errno_restore')
    if current == 34:
        raise SDKKeyOutOfRange("75F400 source std::out_of_range boundary")
    if offset == begin:
        raise SDKKeyInvalidArgument("75F540 source std::invalid_argument boundary")
    if consumed:
        runtime.memory.store(consumed, offset, 8, source='75E460.consumed_length')
    return (-value if negative else value) & 0xFFFFFFFF


def locate_blob(runtime):
    from .primary_worker_response import _frame
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 16, '1D29280.module_name_frame')
    try:
        memory.write(frame, b'QQNT.dll\0', source='1D29280.module_name')
        if runtime.module_lookup_address is None:
            raise PrimarySemanticUnavailable("1D29280 requires its real GetModuleHandleA binding")
        module = _invoke(runtime, runtime.module_lookup_address - base, frame)
    finally:
        memory.unmap(frame)
    runtime.events.append(('1D29280.module_lookup', module))
    if not module:
        return 0
    nt = module + memory.load(module + 0x3C, 4, signed=True)
    count = memory.load(nt + 6, 2)
    section = nt + 0x108
    for _ in range(count):
        if _cstring(runtime, section) == b'.data':
            data = module + memory.load(section + 0x0C, 4)
            size = memory.load(section + 0x10, 4)
            limit = signed((size - 0x210) & 0xFFFFFFFF, 32)
            if limit > 1 << 24:
                raise PrimaryProgramLimit("1D29280 data scan exceeds its explicit offline bound")
            for offset in range(max(limit, 0)):
                if (memory.read(data + offset, 16) == b'something magic.' and
                        memory.read(data + offset + 0x200, 16) == b'end magic things'):
                    runtime.events.append(('1D29280.blob_found', module, data + offset + 16))
                    return data + offset + 16
            return 0
        section += 0x28
    return 0



def push_character(runtime, string, character):
    from .primary_worker_consumer import _invoke
    memory = runtime.memory
    long = memory.load(string, 1) & 1
    length = memory.load(string + 8, 8) if long else memory.load(string, 1) >> 1
    capacity = (memory.load(string, 8) & ~1) - 1 if long else 22
    pointer = memory.load(string + 16, 8) if long else string + 1
    if length > capacity or capacity > 1 << 20:
        raise PrimaryProgramLimit("75C610 string is outside its bounded normal growth domain")
    if length == capacity:
        physical = (max(2 * capacity, capacity + 1) | 15) + 1
        destination = _invoke(runtime, 0xB75000, physical)
        memory.write(destination, memory.read(pointer, capacity), source='75C610.growth_copy')
        if long:
            _invoke(runtime, 0xB75029, pointer)
        pointer = destination
        memory.store(string + 16, pointer, 8, source='75C610.growth_pointer')
        memory.store(string, physical | 1, 8, source='75C610.growth_capacity')
        long = True
    if long:
        memory.store(string + 8, length + 1, 8, source='75C610.heap_length')
    else:
        memory.store(string, (length + 1) * 2, 1, source='75C610.short_length')
    memory.write(pointer + length, bytes((character & 255, 0)), source='75C610.character_and_NUL')
    return length


_FILE = bytes.fromhex('523a5c6465766f70735c776f726b73706163655c702d38323462373437353661643634653132383338363031636364653665636566625c706c6174666f726d735c57696e646f77735c6c696273656378785c46474553444b4e742e637070')


def bootstrap_blob(runtime, key_pointer, external_pointer, caller_length):
    from .primary_provider_init import _state
    from .primary_worker_response import _frame
    memory, base = runtime.memory, runtime.image_base
    if memory.load(_state(runtime) + 2, 1):
        log(runtime, _FILE, 0x14D, b'[FGESDK] wb 1', base + 0x48972C7, 1)
        return None
    if not key_pointer:
        return None
    frame, rbp = _frame(runtime, 0xD8, 'BBFC30.module_bootstrap_frame')
    key = rbp - 0x78
    _String.construct(runtime, _cstring(runtime, key_pointer)).write_to(key)

    def finish():
        _String.read(runtime, key).destroy()
        memory.unmap(frame)

    raw_key = _String.read(runtime, key).value()
    if not raw_key:
        log(runtime, _FILE, 0x157, b'[FGESDK] wb v empty', base + 0x48972C7, 1)
        finish()
        return None
    substring = _String.construct(runtime, raw_key[:2])
    log(runtime, _FILE, 0x15A, b'[FGESDK] wb begin %s', base + 0x48972C7, 1, substring.value())
    substring.destroy()
    if not external_pointer:
        log(runtime, _FILE, 0x15C, b'[FGESDK] wb d empty', base + 0x48972C7, 1)
        finish()
        return None
    blob = _invoke(runtime, 0x1D29280)
    if not blob:
        log(runtime, _FILE, 0x162, b'[FGESDK] wb not found', base + 0x48972C7, 1)
        finish()
        return None
    local, _ = _frame(runtime, 496, 'BBFC30.dynamic_cipher_stack')
    _invoke(runtime, 0x3EB1FE0, local, blob, 496)
    number = _invoke(runtime, 0x75E460, key, 0, 10)
    key_bytes = number.to_bytes(4, 'big')
    decoded = bytes(value ^ key_bytes[index & 3] for index, value in enumerate(memory.read(local, 496)))
    memory.write(local, decoded, source='BBFC30.decimal_key_xor')
    if memory.read(local, 16) != b'amgom data known':
        log(runtime, _FILE, 0x16C, b'[FGESDK] wb not match', base + 0x48972C7, 1)
        memory.unmap(local)
        finish()
        return None
    _invoke(runtime, 0x3EB1FE0, base + 0x677DFB0, external_pointer, 32)
    _invoke(runtime, 0x3EB1FE0, base + 0x677DFD0, local + 16, 480)
    hexadecimal = rbp - 0x40
    memory.write(hexadecimal, bytes(16), source='BC1015.hex_string_prefix')
    memory.store(hexadecimal + 16, 0, 8, source='BC101A.hex_string_tail')
    alphabet = b'0123456789abcdef'
    for value in memory.read(base + 0x677DFB0, 512):
        _invoke(runtime, 0x75C610, hexadecimal, alphabet[value >> 4])
        _invoke(runtime, 0x75C610, hexadecimal, alphabet[value & 15])
    log(runtime, _FILE, 0x172, b'wb data %s', base + 0x48972C7, 1,
        _String.read(runtime, hexadecimal).value())
    _String.read(runtime, hexadecimal).destroy()
    runtime.events.append(('BBFC30.core_begin',))
    _invoke(runtime, 0x1D2C850)
    runtime.events.append(('BBFC30.core_return',))
    memory.store(_state(runtime) + 2, 1, 1, source='BC13B7.sdk_ready')
    log(runtime, _FILE, 0x175, b'[FGESDK] wb end', base + 0x48972C7, 1)
    memory.unmap(local)
    finish()
    return None
