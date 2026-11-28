from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from .errors import InputError
from .primary_logger import _cstring, _decode, _String, _Tree, construct, feature, log
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20
_IMAGE_SHA256 = '63129c554676b41596506af3f3f929eddbac1457137d0c2f04ef55dd7601066e'


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'worker-consumer-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed worker consumer image identity mismatch')
    return json.loads(raw)


def install_image(memory, image_base):
    image = _image()
    for segment in image['segments']:
        data = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            value = int.from_bytes(data[offset:offset + 8], 'little')
            data[offset:offset + 8] = ((value - image['image_base'] + image_base) & _MASK64).to_bytes(8, 'little')
        memory.map(image_base + segment['rva'], data, name='fixed worker consumer source image', initialized=True)


@dataclass(frozen=True)
class DeviceRecordsBinding:
    address: int
    callback: object

    def invoke(self, runtime, device, output):
        if type(self.address) is not int or not 0 < self.address <= _MASK64 or not callable(self.callback):
            raise InputError('device records binding requires a resolved callback address and raw observer')
        result = self.callback(device, output)
        if (not isinstance(result, tuple) or len(result) != 2 or type(result[0]) is not int or
                not 0 <= result[0] <= 0xFFFFFFFF or not isinstance(result[1], tuple)):
            raise InputError('device records callback requires a DWORD result and explicit memory effects')
        for effect in result[1]:
            if (not isinstance(effect, tuple) or len(effect) != 2 or type(effect[0]) is not int or
                    not 0 <= effect[0] <= _MASK64 or not isinstance(effect[1], bytes)):
                raise InputError('device records effect requires an unsigned address and raw bytes')
            runtime.memory.write(effect[0], effect[1], source='device.records_callback')
        runtime.events.append(('worker.device_records', self.address, device, output, result[0], result[1]))
        return result[0]


def _invoke(runtime, rva, *values):
    vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    return runtime.invoke(vm, rva, tuple(range(len(values))))


def _zero_string(runtime):
    return _String(runtime, bytes(24), b'\1' * 24)


def _append(value, raw):
    if not raw:
        return
    previous = value.value()
    size = len(previous)
    required = size + len(raw)
    if required > _LIMIT:
        raise PrimaryProgramLimit('device consumer serialized string exceeds the bounded offline domain')
    long = value.get(0, 1) & 1
    capacity = (value.get(0, 8) & ~1) - 1 if long else 22
    if required > capacity:
        physical = (max(2 * capacity, required) | 15) + 1
        pointer = _invoke(value.runtime, 0xB75000, physical)
        value.runtime.memory.write(pointer, previous + raw, source='75C180.consumer_string_growth')
        if long:
            value.destroy()
        value.set(0, (physical | 1).to_bytes(8, 'little'))
        value.set(8, required.to_bytes(8, 'little'))
        value.set(16, pointer.to_bytes(8, 'little'))
        value.runtime.memory.store(pointer + required, 0, 1, source='75C180.consumer_string_terminator')
    else:
        value.append(raw)


def _varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _integer(value, number):
    for byte in _varint(number):
        _append(value, bytes([byte]))


def _field(value, tag, raw):
    _integer(value, tag)
    _integer(value, len(raw))
    _append(value, raw)


def _record(runtime, key, value):
    result = _zero_string(runtime)
    if key:
        _integer(result, 8)
        _integer(result, key)
    raw = value.value()
    if raw:
        _field(result, 18, raw)
    return result


def _destroy_tree(runtime, address):
    tree = _Tree(runtime, address)
    pending = [(tree.load(address, 8), False)]
    visited = set()
    while pending:
        node, ready = pending.pop()
        if not node:
            continue
        if ready:
            _String.read(runtime, node + 40).destroy()
            _invoke(runtime, 0xB75029, node)
        else:
            if node in visited or len(visited) >= 4096:
                raise PrimaryProgramLimit('device consumer tree cycle or traversal bound')
            visited.add(node)
            pending.extend(((node, True), (tree.load(node, 8), False), (tree.load(node), False)))


def _copy_records(runtime, records, address):
    tree = _Tree(runtime, address)
    for key, value in records:
        def initialize(node):
            runtime.memory.store(node + 32, key, 4, source='BDC682.device_record_key')
            value.clone().write_to(node + 40)

        tree.insert(key, 64, initialize)
    return [(tree.load(node, 32, 4), _String.read(runtime, node + 40)) for node in tree.nodes()]


def _vector(runtime, records):
    pointer, capacity, values = 0, 0, []
    table = runtime.image_base + 0x3FD7118
    for key, value in records:
        first = value.clone()
        second = first.clone()
        first.destroy()
        if len(values) == capacity:
            capacity = max(1, capacity * 2)
            target = runtime._operator_new(capacity * 40)
            for index, (old_key, old_value) in enumerate(values):
                runtime.memory.store(target + index * 40, table, 8, source='BDBDA0.record_vtable')
                runtime.memory.store(target + index * 40 + 8, old_key, 4, source='BDBDA4.record_key')
                old_value.write_to(target + index * 40 + 16)
                runtime.memory.write(pointer + index * 40 + 16, bytes(24), source='BDBDBA.moved_record_string')
            if pointer:
                runtime._free_allocation(pointer)
            pointer = target
        destination = pointer + len(values) * 40
        runtime.memory.store(destination, table, 8, source='BD7896.record_vtable')
        runtime.memory.store(destination + 8, key, 4, source='BD789F.record_key')
        second.write_to(destination + 16)
        values.append((key, second))
    return pointer, values


@dataclass(frozen=True)
class DeviceRecord:
    key: int
    value: bytes

    def __post_init__(self):
        if type(self.key) is not int or not 0 <= self.key <= 0xFFFFFFFF or type(self.value) is not bytes:
            raise InputError('device record requires a DWORD key and bytes')


def serialize_device_records(records, metadata, encrypted):
    """BD7FAF shared ordered record envelope, without native admission."""
    if type(records) is not tuple or any(type(row) is not DeviceRecord for row in records):
        raise InputError('ordered typed records tuple required')
    if type(metadata) is not bytes or type(encrypted) is not bytes:
        raise InputError('metadata and encrypted records require bytes')
    output = bytearray()
    def field(tag, raw):
        output.extend(_varint(tag));output.extend(_varint(len(raw)));output.extend(raw)
        if len(output)>_LIMIT:raise PrimaryProgramLimit('device consumer serialized string exceeds the bounded offline domain')
    for row in records:
        raw = _varint(8)+_varint(row.key) if row.key else b''
        if row.value:raw += _varint(18)+_varint(len(row.value))+row.value
        field(10,raw)
    if metadata:field(18,metadata)
    if encrypted:field(26,encrypted)
    return bytes(output)


def _serialize(runtime, records, metadata, encrypted):
    rows=[]
    for key,value in records:
        if runtime.memory.load(runtime.image_base+0x3FD7118,8)!=runtime.image_base+0xBDBE60:
            raise PrimarySemanticUnavailable('BD7FAF current device record serializer is not bound')
        rows.append(DeviceRecord(key,value.value()))
    result=_zero_string(runtime)
    _append(result,serialize_device_records(tuple(rows),metadata.value(),encrypted.value()))
    return result


def _callback(runtime, pair, value, timestamp, clone=False):
    pointer = runtime._operator_new(48)
    runtime.memory.store(pointer, runtime.image_base + 0x3FD7188, 8, source='BD9BBC.consumer_callback_vtable')
    runtime.memory.store(pointer + 8, pair, 8, source='BD9BC6.consumer_callback_pair')
    if clone:
        value = value.clone()
    value.write_to(pointer + 16)
    runtime.memory.store(pointer + 40, timestamp, 8, source='BD9BE7.consumer_callback_time')
    return pointer


def _logger(runtime):
    memory, base = runtime.memory, runtime.image_base
    pointer = memory.load(base + 0x67516A8, 8)
    if not pointer:
        pointer = _invoke(runtime, 0xB75000, 120)
        construct(runtime, pointer)
        memory.store(base + 0x67516A8, pointer, 8, source='BD68AB.logger_publish')
    return pointer


def consume(runtime, capture):
    memory, base = runtime.memory, runtime.image_base
    size, frame, initial = runtime._next(runtime._temporaries, 'device consumer private frame', 0x298)
    if size != 0x298 or type(frame) is not int or not 0 < frame <= _MASK64 - size:
        raise InputError('device consumer requires its explicit private frame address and size')
    if initial is not None and (not isinstance(initial, bytes) or len(initial) != size):
        raise InputError('device consumer frame observation requires complete raw bytes or unknown storage')
    memory.map(frame, bytearray(size) if initial is None else bytearray(initial),
               name='BD61F0.consumer_frame', initialized=initial is not None)
    rbp = frame + 0x80
    pair = memory.load(capture, 8)
    source_map = rbp + 0x80
    memory.store(source_map, source_map + 8, 8, source='BD622A.device_records_begin')
    memory.write(source_map + 8, bytes(16), source='BD6223.device_records_root_count')
    device, control = memory.load(pair, 8), memory.load(pair + 8, 8)
    if control:
        memory.store(control + 8, memory.load(control + 8, 4) + 1, 4, source='BD623D.device_retain')
    target = memory.load(memory.load(device, 8) + 64, 8)
    if target == base + 0xBEE3C0:
        status = _invoke(runtime, 0xBEE3C0, device, source_map)
    else:
        binding = runtime.worker_device_records
        if not isinstance(binding, DeviceRecordsBinding) or binding.address != target:
            raise PrimarySemanticUnavailable('BD6253 actual device vtable+40 target and record effects are not bound')
        status = binding.invoke(runtime, device, source_map)
    if control:
        count = memory.load(control + 8, 4)
        memory.store(control + 8, count - 1, 4, source='BD6269.device_release')
        if not count:
            raise PrimarySemanticUnavailable('BD684C device shared-control destructor effects remain unavailable')
    image = _image()
    if status or not memory.load(source_map + 16, 8):
        if status:
            log(runtime, _decode(image['file']), 0x1ED, _decode(image['device_error']), base + 0x48972C7, 2, status)
        memory.store(pair + 0x60, 0, 1, source='BD6821.device_claim_release')
        _destroy_tree(runtime, source_map)
        memory.unmap(frame)
        return None
    consume_records(runtime, pair, source_map, rbp)
    memory.store(pair + 0x60, 0, 1, source='BD6821.device_claim_release')
    _destroy_tree(runtime, source_map)
    memory.unmap(frame)
    return None


def consume_records(runtime, pair, source_map, rbp, *, caller='worker'):
    if caller not in ('worker', 'sign'):
        raise InputError('device records consumer requires a bound source caller')
    memory, base = runtime.memory, runtime.image_base
    image = _image()
    memory.store(rbp + 0x50, 0, 2, source='BD6873.consumer_output_empty')
    memory.store(rbp, 0, 2, source='BD6879.consumer_encrypted_empty')
    encrypt = feature(runtime, _logger(runtime), 46) == 1
    tree = _Tree(runtime, source_map)
    records = [(tree.load(node, 32, 4), _String.read(runtime, node + 40)) for node in tree.nodes()]
    if encrypt:
        count = memory.load(source_map + 16, 8)
        array = _invoke(runtime, 0x3E92E00, count, 24)
        payloads = []
        for index, (key, source) in enumerate(records):
            value = source.clone()
            raw = value.value()
            destination = array + index * 24
            memory.store(destination, key, 4, source='BD692A.device_record_key')
            memory.store(destination + 16, len(raw), 4, source='BD6950.device_record_length')
            pointer = _invoke(runtime, 0x3E92E00, len(raw) + 1, 1) if raw else 0
            memory.store(destination + 8, pointer, 8, source='BD6963.device_record_payload')
            if raw:
                memory.write(pointer, raw + b'\0', source='BD698A.device_record_payload_copy')
            payloads.append((pointer, len(raw)))
            value.destroy()
        memory.store(rbp + 0x158, 0, 8, source='BD6FD9.device_vm_output')
        memory.store(rbp + 0x98, 0, 4, source='BD6FE4.device_vm_length')
        _invoke(runtime, 0x1BF7620, array, count & 0xFFFFFFFF, rbp + 0x158, rbp + 0x98)
        output, length = memory.load(rbp + 0x158, 8), memory.load(rbp + 0x98, 4)
        encrypted = _zero_string(runtime)
        if output and length:
            encrypted = _String.construct(runtime, memory.read(output, length))
            runtime._free_allocation(output)
        for pointer, length in payloads:
            if pointer and length:
                runtime._free_allocation(pointer)
        runtime._free_allocation(array)
        encrypted.write_to(rbp)
        if caller == 'worker':
            log(runtime, _decode(image['file']), 477, _decode(image['failed']), base + 0x48972C7, 1)
    else:
        encrypted = _String.read(runtime, rbp)
        if caller == 'worker':
            log(runtime, _decode(image['file']), 480, _decode(image['failed']) + b'!', base + 0x48972C7, 1)
    copied = encrypted.clone()
    copied.write_to(rbp - (0x48 if encrypt else 0x30))
    copy_map = rbp + (0x20 if encrypt else 0x40)
    memory.store(copy_map, copy_map + 8, 8, source='BD7592.device_copy_begin')
    memory.write(copy_map + 8, bytes(16), source='BD758E.device_copy_root_count')
    copied_records = _copy_records(runtime, records, copy_map)
    source = _String.read(runtime, pair + 24)
    raw = source.value()
    metadata = _String.construct(runtime, raw, max(44, len(raw))) if len(raw) > 22 else source.clone()
    vector, elements = _vector(runtime, copied_records)
    assigned = _String.construct(runtime, copied.value(), max(44, len(copied.value()))) if len(copied.value()) > 22 else copied.clone()
    serialized = _serialize(runtime, elements, metadata, assigned)
    assigned.destroy()
    metadata.destroy()
    for key, value in reversed(elements):
        value.destroy()
    if vector:
        runtime._free_allocation(vector)
    _destroy_tree(runtime, copy_map)
    copied.destroy()
    serialized.write_to(rbp + 0x50)
    payload = serialized.clone()
    payload.write_to(rbp - 0x18)
    name = _String.read(runtime, pair + 0x48).clone()
    name.write_to(rbp + 0xF0)
    _invoke(runtime, 0x759B30, rbp + 0x188)
    timestamp = memory.load(rbp + 0x188, 8)
    function = _callback(runtime, pair, name.clone(), timestamp)
    memory.store(rbp + 0x178, function, 8, source='BD9BEB.consumer_callback_publish')
    log(runtime, _decode(image['file']), 532, _decode(image['length_log']), base + 0x48972C7, 1, len(payload.value()))
    gate = _invoke(runtime, 0xBA21A0)
    memory.store(rbp + 0x128, 0, 2, source='BDA0D8.consumer_metadata_first')
    memory.store(rbp + 0x140, 0, 2, source='BDA0E1.consumer_metadata_second')
    memory.write(rbp + 0x190, bytes(48), source='BDA0ED.consumer_metadata_empty')
    _String.read(runtime, rbp + 0x140).write_to(rbp + 0x190)
    _String.read(runtime, rbp + 0x128).write_to(rbp + 0x1A8)
    if memory.load(base + 0x3FD7188 + 16, 8) != base + 0xBDC970:
        raise PrimarySemanticUnavailable('BDA14A current device consumer callback clone is not bound')
    clone = _callback(runtime, pair, _String.read(runtime, function + 16), timestamp, clone=True)
    memory.store(rbp + 0xE0, clone, 8, source='BDA151.consumer_callback_argument')
    if memory.load(pair + 0xD0, 1) & 1:
        seed = memory.load(pair + 0xD1, 1)
        raw = memory.read(pair + 0xD2, 8)
        memory.write(pair + 0xD2, bytes(byte ^ seed ^ (index + 1) ^ 8 for index, byte in enumerate(raw)),
                     source='BDA1DE.device_operation_decode')
        memory.store(pair + 0xDA, 0, 2, source='BDA1FD.device_operation_terminators')
        memory.store(pair + 0xD0, 0, 1, source='BDA20B.device_operation_decoded')
    tag = _String.construct(runtime, _cstring(runtime, pair + 0xD2))
    tag.write_to(rbp + 0x110)
    pointer = payload.get(16, 8) if payload.get(0, 1) & 1 else rbp - 0x17
    arguments = (gate, rbp + 0x110, pointer, len(payload.value()) & 0xFFFFFFFF, rbp + 0xC0, rbp + 0x190, 1)
    runtime.events.append(('worker.consumer_handoff', *arguments))
    _invoke(runtime, 0x1CE6920, *arguments)
    for offset in (0x1A8, 0x190, 0x140, 0x128):
        _String.read(runtime, rbp + offset).destroy()
    if memory.load(base + 0x3FD7188 + 32, 8) != base + 0xBDCA00:
        raise PrimarySemanticUnavailable('BDA3AD current device consumer callback destructor is not bound')
    _String.read(runtime, function + 16).destroy()
    runtime._free_allocation(function)
    name.destroy()
    payload.destroy()
    encrypted.destroy()
    serialized.destroy()
    return None


def invoke(runtime, rva, values):
    if rva in (0xBD61F0, 0xBD6170) and len(values) == 1:
        return consume(runtime, values[0] + (8 if rva == 0xBD6170 else 0))
    raise InputError('worker consumer source interface argument count mismatch')
