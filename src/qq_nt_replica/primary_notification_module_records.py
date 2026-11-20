from .errors import InputError
from .primary_logger import _String
from .primary_notification_vectors import _contains
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _field, _invoke, _varint, _zero_string
from .primary_worker_response import _frame


_LIMIT = 1 << 20
_STRIDE = 0x58
_MAX_COUNT = 0x2E8BA2E8BA2E8BA
_FRAGMENTS = (b'\\windows\\system32\\', b'\\windows\\syswow64\\', b'\\windows\\winsxs\\',
    b'\\programdata\\microsoft\\', b'\\safemon\\', b'\\sogouinput\\', b'\\sogoupinyin\\',
    b'\\bonjour\\', b'\\a-volute\\')


def _source_image(runtime):
    memory, base = runtime.memory, runtime.image_base
    for rva, raw in ((0x4903C10, b'\0'), (0x414BA98, (base + 0x1D260D0).to_bytes(8, 'little'))):
        address, offset = base + rva, 0
        while offset < len(raw):
            current = address + offset
            region = next((region for region in memory._regions if region.address <= current < region.address + len(region.data)), None)
            if region is None:
                following = min((region.address for region in memory._regions if current < region.address < address + len(raw)), default=address + len(raw))
                size = following - current
                memory.map(current, raw[offset:offset + size], name='fixed notification record source image', initialized=True)
            else:
                size = min(len(raw) - offset, region.address + len(region.data) - current)
                if memory.read(current, size) != raw[offset:offset + size]:
                    raise InputError('notification record source constant identity mismatch')
            offset += size


def construct_record(runtime, destination):
    _source_image(runtime)
    memory = runtime.memory
    memory.store(destination, runtime.image_base + 0x414BA98, 8, source='1D2409D.record_vtable')
    for offset in (8, 0x20, 0x40):
        memory.write(destination + offset, bytes(24), source='1D240B4.record_string_zero')
    for offset in (8, 0x20):
        _invoke(runtime, 0x75CD00, destination + offset, runtime.image_base + 0x4903C10)
    memory.store(destination + 0x38, 0, 4, source='1D240EF.record_scalar_zero')
    _invoke(runtime, 0x75CD00, destination + 0x40, runtime.image_base + 0x4903C10)
    return destination


def copy_record(runtime, destination, source):
    memory = runtime.memory
    memory.store(destination, runtime.image_base + 0x414BA98, 8, source='1D27451.record_copy_vtable')
    for offset in (8, 0x20):
        _invoke(runtime, 0x75B810, destination + offset, source + offset)
    memory.store(destination + 0x38, memory.load(source + 0x38, 4), 4, source='1D27481.record_scalar_copy')
    _invoke(runtime, 0x75B810, destination + 0x40, source + 0x40)
    return destination


def _record_range(runtime, vector, capacity=False):
    memory = runtime.memory
    begin, end = memory.load(vector, 8), memory.load(vector + 8, 8)
    last = memory.load(vector + 16, 8) if capacity else end
    if not 0 <= begin <= end <= last < 1 << 64 or (end - begin) % _STRIDE or (last - begin) % _STRIDE or not begin and last:
        raise InputError('notification record vector requires its initialized stride88 layout')
    count, allocated = (end - begin) // _STRIDE, (last - begin) // _STRIDE
    return begin, end, count, allocated


def grow_records(runtime, vector, incoming):
    memory = runtime.memory
    begin, end, count, capacity = _record_range(runtime, vector, True)
    if count + 1 >= _MAX_COUNT + 1:
        raise PrimarySemanticUnavailable('1D273DF record vector requires original2C40 length exception')
    new_capacity = max(2 * capacity, count + 1) if capacity < 0x1745D1745D1745D else _MAX_COUNT
    if new_capacity >= _MAX_COUNT + 1:
        raise PrimarySemanticUnavailable('1D273E4 record vector requires original2439 length exception')
    if new_capacity * _STRIDE > _LIMIT:
        raise PrimaryProgramLimit('notification record vector exceeds its bounded normal allocation domain')
    storage = runtime._operator_new(new_capacity * _STRIDE)
    copy_record(runtime, storage + count * _STRIDE, incoming)
    for index in range(count - 1, -1, -1):
        source, destination = begin + index * _STRIDE, storage + index * _STRIDE
        memory.store(destination, runtime.image_base + 0x414BA98, 8, source='1D272E0.record_move_vtable')
        for offset in (8, 0x20):
            _String.read(runtime, source + offset).write_to(destination + offset)
            memory.write(source + offset, bytes(24), source='1D272F4.record_moved_string_zero')
        memory.store(destination + 0x38, memory.load(source + 0x38, 4), 4, source='1D2731F.record_move_scalar')
        _String.read(runtime, source + 0x40).write_to(destination + 0x40)
        memory.write(source + 0x40, bytes(24), source='1D27332.record_moved_string_zero')
    memory.store(vector, storage, 8, source='1D27355.record_vector_begin')
    memory.store(vector + 8, storage + (count + 1) * _STRIDE, 8, source='1D27358.record_vector_end')
    memory.store(vector + 16, storage + new_capacity * _STRIDE, 8, source='1D2735C.record_vector_capacity')
    for source in range(end - _STRIDE, begin - 1, -_STRIDE):
        memory.store(source, runtime.image_base + 0x414BA98, 8, source='1D27388.old_record_vtable')
        for offset in (0x40, 0x20, 8):
            _String.read(runtime, source + offset).destroy()
    if begin:
        runtime._free_allocation(begin)


def _serialize_fields(runtime, record, result, fields):
    for offset, tag, scalar in fields:
        if scalar:
            value = runtime.memory.load(record + offset, 4)
            if value:
                _append(result, _varint(tag))
                _append(result, _varint(value))
        else:
            raw = _String.read(runtime, record + offset).value()
            if raw:
                _field(result, tag, raw)


def serialize_record(runtime, record, output):
    result = _zero_string(runtime)
    result.write_to(output)
    try:
        _serialize_fields(runtime, record, result, ((8, 0x0A, False), (0x20, 0x12, False),
            (0x38, 0x18, True), (0x40, 0x22, False)))
    finally:
        result.write_to(output)
    return output


def serialize_parent(runtime, parent, output):
    result = _zero_string(runtime)
    result.write_to(output)
    try:
        _serialize_fields(runtime, parent, result, ((8, 0x0A, False), (0x20, 0x12, False),
            (0x38, 0x1A, False), (0x50, 0x20, True), (0x58, 0x2A, False), (0x70, 0x32, False)))
        begin, end, count, _ = _record_range(runtime, parent + 0x88)
        if count > _LIMIT // _STRIDE:
            raise PrimaryProgramLimit('notification child serialization exceeds its bounded normal domain')
        if count:
            _source_image(runtime)
        for record in range(begin, end, _STRIDE):
            vtable = runtime.memory.load(record, 8)
            if vtable != runtime.image_base + 0x414BA98 or runtime.memory.load(vtable, 8) != runtime.image_base + 0x1D260D0:
                raise PrimarySemanticUnavailable('notification record child requires exact414BA98 serializer1D260D0')
            frame, _ = _frame(runtime, 24, '1D25B89.notification_child_string')
            runtime.memory.write(frame, bytes(24), source='1D260F3.child_output_zero')
            try:
                _invoke(runtime, 0x1D260D0, record, frame)
                raw = _String.read(runtime, frame).value()
                if raw:
                    _field(result, 0x3A, raw)
            finally:
                try:
                    _String.read(runtime, frame).destroy()
                finally:
                    runtime.memory.unmap(frame)
    finally:
        result.write_to(output)
    return output


def path_fragment(runtime, path):
    value = _String.read(runtime, path).value()
    return any(_contains(value, fragment) for fragment in _FRAGMENTS)


def invoke(runtime, rva, values):
    definitions = {0x1D24080: (construct_record, 1), 0x1D27430: (copy_record, 2),
        0x1D271F0: (grow_records, 2), 0x1D260D0: (serialize_record, 2),
        0x1D24140: (serialize_parent, 2), 0x1D1F8D0: (path_fragment, 1)}
    if rva not in definitions or len(values) != definitions[rva][1]:
        raise InputError('notification module helper native entry argument count mismatch')
    return definitions[rva][0](runtime, *values)
