import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _String
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _invoke, _logger
from .primary_worker_loop import _initialize
from .primary_worker_response import _frame
from .wire import encode_u64


_IMAGE_SHA256 = '4a6d65133c61d0c550dae07c1405740355662be658c1bce790f03012ed30fefd'


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'request-submit-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed request serialization image identity mismatch')
    return json.loads(raw)


def install_image(memory, base):
    image = _image()
    for segment in image['segments']:
        value = int.from_bytes(bytes.fromhex(segment['hex']), 'little') - image['image_base'] + base
        raw = value.to_bytes(8, 'little')
        address = base + segment['rva']
        if any(region.address <= address and address + 8 <= region.address + len(region.data)
               for region in memory._region_snapshot()):
            if memory.read(address, 8) != raw:
                raise InputError('request serialization image overlaps different source bytes')
        else:
            memory.map(address, raw, name='fixed request serialization source image', initialized=True)
    from .primary_request_direct import install_image as install_direct_image
    install_direct_image(memory, base)
    from .primary_pending_reports import install_image as install_pending_image
    install_pending_image(memory, base)


def _vector(runtime, address, width):
    first, last = runtime.memory.load(address, 8), runtime.memory.load(address + 8, 8)
    if last < first or (last - first) % width or last - first > width * 4096:
        raise PrimaryProgramLimit('request serialization vector exceeds the recovered offline domain')
    return range(first, last, width)


def serialize(runtime, rva, address, destination):
    runtime.memory.write(destination, bytes(24), source='request_serializer.output_initialization')
    value = _serialized(runtime, rva, address)
    value.write_to(destination)
    runtime.events.append(('request.serializer', rva, destination, len(value.value())))
    return destination


def _serialized(runtime, rva, address):
    result = _String(runtime, bytes(24), bytes([1]) * 24)

    def field(key, value, force=False):
        if value or force:
            for byte in encode_u64(key * 8 + 2) + encode_u64(len(value)):
                _append(result, bytes([byte]))
            _append(result, value)

    if rva == 0xBE1730:
        memory, base = runtime.memory, runtime.image_base
        force = bool(memory.load(address + 88, 1))
        field(1, _String.read(runtime, address + 8).value(), force)
        for row in _vector(runtime, address + 32, 56):
            if memory.load(memory.load(row, 8), 8) != base + 0xBE2BC0:
                raise PrimarySemanticUnavailable('request row virtual serializer is not bound')
            value = _serialized(runtime, 0xBE2BC0, row)
            field(2, value.value(), force)
            value.destroy()
        if memory.load(memory.load(address + 56, 8), 8) != base + 0xBE2680:
            raise PrimarySemanticUnavailable('request nested virtual serializer is not bound')
        value = _serialized(runtime, 0xBE2680, address + 56)
        field(3, value.value(), force)
        value.destroy()
    elif rva == 0xBE2BC0:
        for pointer in _vector(runtime, address + 8, 24):
            field(1, _String.read(runtime, pointer).value())
        field(2, _String.read(runtime, address + 32).value())
    elif rva == 0xBE2680:
        field(1, _String.read(runtime, address + 8).value())
    else:
        raise InputError('request serializer requires a recovered source entry')
    return result


def _clone_row(runtime, destination, source):
    memory, base = runtime.memory, runtime.image_base
    memory.write(destination, bytes(56), source='BEE650.request_row_initialization')
    memory.store(destination, base + 0x3FD7498, 8, source='BEE65D.request_row_vtable')
    values = list(_vector(runtime, source + 8, 24))
    vector = runtime._operator_new(24 * len(values)) if values else 0
    for index, pointer in enumerate(values):
        _String.read(runtime, pointer).clone().write_to(vector + index * 24)
    for offset, value in ((8, vector), (16, vector + 24 * len(values)), (24, vector + 24 * len(values))):
        memory.store(destination + offset, value, 8, source='BEE6B7.request_row_columns')
    _String.read(runtime, source + 32).clone().write_to(destination + 32)


def _destroy_row(runtime, address):
    memory = runtime.memory
    for pointer in _vector(runtime, address + 8, 24):
        _String.read(runtime, pointer).destroy()
    first = memory.load(address + 8, 8)
    if first:
        runtime._free_allocation(first)
    _String.read(runtime, address + 32).destroy()


def _f8_base_columns(runtime, row, event):
    from .primary_caller_diagnostics import _Strings
    memory, base = runtime.memory, runtime.image_base
    columns = _Strings(runtime)
    sources = [(True, offset) for offset in (0x40, 0xA0)]
    sources += [(False, offset) for offset in (8, 0x20, 0x38, 0x50, 0x68, 0x80)]
    sources += [(True, offset) for offset in (0x70, 0x58)] + [(False, 0xB0)]
    for config, offset in sources:
        if config:
            _initialize(runtime, 0)
        source = base + 0x67516B0 + offset if config else event + offset
        columns.push(_String.read(runtime, source), clone=True)
        for field, value in ((8, columns.begin), (16, columns.begin + columns.count * 24),
                             (24, columns.begin + columns.capacity * 24)):
            memory.store(row + field, value, 8, source='1BEFD50.request_base_columns')


def submit(runtime, owner, event, columns, last_flag):
    memory, base = runtime.memory, runtime.image_base
    table = memory.load(event, 8)
    methods = tuple(memory.load(table + offset, 8) - base for offset in (0, 8, 16))
    if methods == (0x1BF4C50, 0x1BF4C70, 0x63EC0):
        topic = bytes.fromhex(_image()['topic_hex'])
        column_count = 7
    elif methods == (0x1C018C0, 0x1BF4C70, 0x5C7470):
        from .primary_sdk_events import _definition

        topic = bytes.fromhex(_definition()['topic_hex'])
        column_count = 7
    elif methods == (0xBCE920, 0xBCE940, 0x63EC0):
        topic = b'0b500076578'
        column_count = 9
    elif table == base + 0x4149058 and methods == (0x1C018C0, 0x776860, 0x5C7470):
        topic = None
        column_count = 0
    else:
        raise PrimarySemanticUnavailable('enabled request telemetry virtual interface is not bound')
    frame, rbp = _frame(runtime, 0x1B0, '1BEEC40.request_telemetry_cache_frame')
    packet, row = rbp - 72, rbp + 232
    memory.write(packet, bytes(89), source='1BEED5B.request_batch_initialization')
    memory.store(packet, base + 0x3FD73B8, 8, source='1BEED5B.request_batch_vtable')
    memory.store(packet + 56, base + 0x3FD7428, 8, source='1BEED75.request_batch_nested_vtable')
    event_kind = _invoke(runtime, methods[2], event) & 0xFFFFFFFF
    kind = 0
    if event_kind and (event_kind == 2 or _invoke(runtime, 0x1BE3F80, _logger(runtime), 18) == 1):
        _initialize(runtime, 0)
        current = _String.read(runtime, base + 0x67516B8).clone()
        length = len(current.value())
        current.destroy()
        kind = 1
        if length:
            _String.read(runtime, base + 0x67516B8).clone().write_to(packet + 64)
    if topic is None:
        _invoke(runtime, methods[0], event, packet + 8)
    else:
        _String.construct(runtime, topic).write_to(packet + 8)
    width = column_count * 24
    if topic is None:
        _invoke(runtime, methods[1], event, rbp + 208)
        vector = memory.load(rbp + 208, 8)
    elif methods == (0xBCE920, 0xBCE940, 0x63EC0):
        from .primary_request_audit import _cost_columns
        vector = _cost_columns(runtime, event)
    else:
        vector = runtime._operator_new(width)
        for index in range(column_count):
            _String.read(runtime, event + 224 + index * 24).clone().write_to(vector + index * 24)
    for offset, value in ((208, vector), (216, vector + width), (224, vector + width)):
        memory.store(rbp + offset, value, 8, source='1BF4C70.request_event_columns')
    if topic is None:
        memory.write(row, bytes(56), source='1BEEEB8.request_row_initialization')
        memory.store(row, base + 0x3FD7498, 8, source='1BEEEB8.request_row_vtable')
        _f8_base_columns(runtime, row, event)
    else:
        _initialize(runtime, 0)
        config = base + 0x67516B0
        sources = [config + offset for offset in (0x40, 0xA0, 0x70, 0x58)] + [event + 8]
        sources += [vector + index * 24 for index in range(column_count)]
        row_columns = runtime._operator_new(len(sources) * 24)
        for index, source in enumerate(sources):
            value = _String.read(runtime, source)
            copied = value.clone() if value.value() else _String.construct(runtime, b' ')
            copied.write_to(row_columns + index * 24)
        memory.write(row, bytes(56), source='1BEEEB8.request_row_initialization')
        memory.store(row, base + 0x3FD7498, 8, source='1BEEEB8.request_row_vtable')
        row_width = len(sources) * 24
        for offset, value in ((8, row_columns), (16, row_columns + row_width), (24, row_columns + row_width)):
            memory.store(row + offset, value, 8, source='1BEF02D.request_nonempty_columns')
    rows = runtime._operator_new(56)
    _clone_row(runtime, rows, row)
    for offset, value in ((32, rows), (40, rows + 56), (48, rows + 56)):
        memory.store(packet + offset, value, 8, source='1BEF06F.request_batch_rows')
    output = rbp + 176
    _invoke(runtime, 0xBE1730, packet, output)
    runtime.events.append(('request.audit_serialized', output, len(_String.read(runtime, output).value()), owner + 32))
    queued = _invoke(runtime, 0x1D30A90, owner + 32, kind, output, columns)
    if not queued & 255:
        _invoke(runtime, 0x1BF2390, owner, kind, output, columns, 0, last_flag & 255)
    _String.read(runtime, output).destroy()
    for index in range(column_count):
        _String.read(runtime, vector + index * 24).destroy()
    if vector:
        runtime._free_allocation(vector)
    _destroy_row(runtime, row)
    _destroy_row(runtime, rows)
    runtime._free_allocation(rows)
    _String.read(runtime, packet + 8).destroy()
    _String.read(runtime, packet + 64).destroy()
    memory.unmap(frame)


def invoke(runtime, rva, values):
    if len(values) != 2:
        raise InputError('request serializer requires receiver and output String')
    return serialize(runtime, rva, *values)
