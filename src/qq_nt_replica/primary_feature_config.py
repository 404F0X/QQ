from .errors import InputError
from .primary_logger import _String, _Tree
from .primary_provider_init import _mutex
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _invoke, _zero_string
from .primary_worker_response import _frame, _varint


_LIMIT = 1 << 20
_AGGREGATE = 0x414AC88
_RECORD = 0x41488C8


def _bounds(runtime, vector, width):
    begin, end, capacity = (runtime.memory.load(vector + offset, 8) for offset in (0, 8, 16))
    if not begin <= end <= capacity or (end - begin) % width or (capacity - begin) % width:
        raise PrimaryProgramLimit('feature configuration vector is outside its source layout')
    if capacity - begin > _LIMIT:
        raise PrimaryProgramLimit('feature configuration vector exceeds the bounded domain')
    return begin, end, capacity


def construct(runtime, output):
    runtime.memory.store(output, runtime.image_base + _AGGREGATE, 8,
                         source='1C51507.feature_configuration_aggregate_vtable')
    runtime.memory.write(output + 8, bytes(48), source='1C51521.feature_configuration_vectors_zero')
    return output


def _copy_record(runtime, source, output):
    memory = runtime.memory
    memory.store(output, runtime.image_base + _RECORD, 8, source='1C52510.feature_record_copy_vtable')
    _String.read(runtime, source + 8).clone().write_to(output + 8)
    memory.copy_disjoint(output + 32, source + 32, 8, label='1C52510.feature_record_copy_values')


def _push(runtime, vector, source, width):
    memory = runtime.memory
    begin, end, capacity = _bounds(runtime, vector, width)
    if end != capacity:
        if width == 24:
            _String.read(runtime, source).clone().write_to(end)
        else:
            _copy_record(runtime, source, end)
        memory.store(vector + 8, end + width, 8, source='1C52510.feature_vector_append')
        return
    count, available = (end - begin) // width, (capacity - begin) // width
    enlarged = max(count + 1, available * 2)
    if enlarged * width > _LIMIT:
        raise PrimaryProgramLimit('feature configuration vector growth exceeds the bounded domain')
    target = runtime._operator_new(enlarged * width)
    if width == 24:
        _String.read(runtime, source).clone().write_to(target + count * width)
    else:
        _copy_record(runtime, source, target + count * width)
    for index in range(count - 1, -1, -1):
        previous, destination = begin + index * width, target + index * width
        offset = 0 if width == 24 else 8
        if width == 40:
            memory.store(destination, runtime.image_base + _RECORD, 8,
                         source='1C53580.feature_record_move_vtable')
            memory.copy_disjoint(destination + 32, previous + 32, 8,
                                 label='1C53580.feature_record_move_values')
        _String.read(runtime, previous + offset).write_to(destination + offset)
        memory.write(previous + offset, bytes(24), source='1C53580.feature_vector_moved_from')
    for offset, value in ((0, target), (8, target + (count + 1) * width), (16, target + enlarged * width)):
        memory.store(vector + offset, value, 8, source='1C53580.feature_vector_publish')
    for index in range(count - 1, -1, -1):
        _String.read(runtime, begin + index * width + (0 if width == 24 else 8)).destroy()
    if begin:
        runtime._free_allocation(begin)


def destroy(runtime, aggregate):
    memory = runtime.memory
    for offset, width, string_offset in ((32, 40, 8), (8, 24, 0)):
        begin, end, _ = _bounds(runtime, aggregate + offset, width)
        for pointer in range(end - width, begin - width, -width):
            _String.read(runtime, pointer + string_offset).destroy()
        if begin:
            runtime._free_allocation(begin)


def _fields(raw):
    cursor, steps = 0, 0
    while cursor < len(raw):
        steps += 1
        if steps > _LIMIT:
            raise PrimaryProgramLimit('feature configuration parser exceeds the bounded domain')
        valid, tag, cursor = _varint(raw, cursor)
        if not valid:
            raise ValueError('incomplete feature configuration tag')
        wire, number = tag & 7, (tag >> 3) & 0xFFFFFFFF
        if wire not in (0, 2):
            raise PrimarySemanticUnavailable('feature configuration unknown wire type is outside the recovered parser domain')
        valid, value, cursor = _varint(raw, cursor)
        if not valid:
            raise ValueError('incomplete feature configuration value')
        if wire == 2:
            end = cursor + (value & 0xFFFFFFFF)
            if end > len(raw):
                raise ValueError('incomplete feature configuration bytes')
            value, cursor = raw[cursor:end], end
        yield number, wire, value


def parse(runtime, aggregate, source):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0xC8, '1C52510.feature_configuration_parser_frame')
    copied = _String.read(runtime, source).clone()
    copied.write_to(frame + 0x30)
    status = 0x100
    try:
        for number, wire, value in _fields(copied.value()):
            if number not in (1, 2):
                continue
            if wire != 2:
                raise PrimarySemanticUnavailable('feature configuration known field requires its recovered length-delimited input domain')
            if number == 1:
                temporary = _zero_string(runtime)
                _append(temporary, value)
                temporary.write_to(frame)
                _push(runtime, aggregate + 8, frame, 24)
                temporary.destroy()
                continue
            label, key, state = _zero_string(runtime), 0, 0
            try:
                for child, kind, item in _fields(value):
                    if child == 1:
                        if kind != 2:
                            raise PrimarySemanticUnavailable('feature record label requires length-delimited bytes')
                        _append(label, item)
                    elif child in (2, 3):
                        if kind != 0:
                            raise PrimarySemanticUnavailable('feature record scalar requires a varint')
                        if child == 2:
                            key = item & 0xFFFFFFFF
                        else:
                            state = item & 0xFFFFFFFF
                memory.store(frame + 0x60, base + _RECORD, 8, source='1C52510.feature_record_vtable')
                label.write_to(frame + 0x68)
                memory.store(frame + 0x80, key, 4, source='1C52510.feature_record_key')
                memory.store(frame + 0x84, state, 4, source='1C52510.feature_record_state')
                _push(runtime, aggregate + 32, frame + 0x60, 40)
            finally:
                label.destroy()
    except ValueError:
        status = 0x101
    copied.destroy()
    runtime.events.append(('feature_config.parsed', aggregate, status))
    memory.unmap(frame)
    return status


def _find(runtime, owner, key):
    signed = key if key < 1 << 31 else key - (1 << 32)
    memory = runtime.memory
    node = memory.load(owner + 8, 8)
    for _ in range(4096):
        if not node:
            return 0
        current = memory.load(node + 32, 4, signed=True)
        if current == signed:
            return node
        node = memory.load(node + (0 if signed < current else 8), 8)
    raise PrimaryProgramLimit('feature configuration tree lookup exceeds its bound')


def _set(runtime, tree, key, value):
    def initialize(node):
        runtime.memory.store(node + 32, key, 4, source='1BE39B0.feature_value_key')
        runtime.memory.store(node + 36, 0, 4, source='1BE39B0.feature_value_initial')
    node = tree.insert(key, 40, initialize)
    runtime.memory.store(node + 36, value, 4, source='1BE39B0.feature_value_publish')


def bulk(runtime, logger, records):
    from .primary_feature_notifications import _copy, _destroy, _virtual

    memory = runtime.memory
    frame, _ = _frame(runtime, 0x80, '1BE39B0.feature_configuration_bulk_frame')
    _mutex(runtime, logger + 48, True)
    values = _Tree(runtime, logger + 64)
    for key in range(10, 65):
        _set(runtime, values, key, 0)
    begin, end, _ = _bounds(runtime, records, 40)
    for pointer in range(begin, end, 40):
        label = _String.read(runtime, pointer + 8).clone()
        key = memory.load(pointer + 32, 4)
        signed = key if key < 1 << 31 else key - (1 << 32)
        if signed <= 64:
            raw_state = memory.load(pointer + 36, 4)
            value = int(raw_state != 0)
            _set(runtime, values, key, value)
            definition = _find(runtime, logger + 24, key)
            if definition and memory.load(definition + 68, 1):
                _String.construct(runtime, str(raw_state).encode('ascii')).write_to(frame)
                _String.concat(runtime, _String.read(runtime, logger).value(),
                               _String.read(runtime, definition + 40).value()).write_to(frame + 24)
                _invoke(runtime, 0x1BE5B30, frame + 24, frame)
                _String.read(runtime, frame + 24).destroy()
                _String.read(runtime, frame).destroy()
        label.destroy()
    _mutex(runtime, logger + 48, False)
    _mutex(runtime, logger + 112, True)
    begin, end = memory.load(logger + 88, 8), memory.load(logger + 96, 8)
    if end < begin or (end - begin) % 48 or end - begin > _LIMIT:
        raise PrimaryProgramLimit('feature configuration notification vector is outside its source layout')
    for pointer in range(begin, end, 48):
        active = memory.load(pointer + 40, 8)
        if not active:
            raise PrimarySemanticUnavailable('feature configuration empty notification requires its original exception')
        copied = _copy(runtime, active, pointer + 16, frame + 0x40, frame + 0x58)
        _virtual(runtime, copied, 40)
        _destroy(runtime, copied, frame + 0x40)
    _mutex(runtime, logger + 112, False)
    runtime.events.append(('feature_config.applied', logger, (end - begin) // 48))
    memory.unmap(frame)
    return None


def apply_response(runtime, raw):
    from .primary_worker_loop import _ensure_logger

    if not isinstance(raw, bytes):
        raise InputError('feature configuration response requires exact wire bytes')
    frame, _ = _frame(runtime, 80, 'feature_configuration.response_component_frame')
    construct(runtime, frame)
    _String.construct(runtime, raw).write_to(frame + 56)
    status = _invoke(runtime, 0x1C52510, frame, frame + 56)
    if status == 0x100:
        _ensure_logger(runtime)
        _invoke(runtime, 0x1BE39B0, runtime.memory.load(runtime.image_base + 0x67516A8, 8), frame + 32)
    destroy(runtime, frame)
    _String.read(runtime, frame + 56).destroy()
    runtime.memory.unmap(frame)
    return status


def invoke(runtime, rva, arguments):
    definitions = {0x1C52510: (parse, 2), 0x1BE39B0: (bulk, 2)}
    function, count = definitions[rva]
    if len(arguments) != count:
        raise InputError('feature configuration source entry argument count mismatch')
    return function(runtime, *arguments)
