from .errors import InputError
from .primary_logger import _String, _cstring
from .primary_worker_consumer import _invoke
from .primary_worker_response import _image as _response_image, _owner


def _definition():
    from .primary_sdk_collection import _image

    return _image()['positive_event']


def _name(runtime):
    memory = runtime.memory
    definition = _definition()
    marker = runtime.image_base + definition['name_marker_rva']
    count = definition['name_length']
    if memory.load(marker, 1) & 1:
        for index in range(count):
            value = memory.load(marker + index + 2, 1)
            seed = memory.load(marker + 1, 1)
            memory.store(marker + index + 2, value ^ (index + 1) ^ seed ^ count, 1,
                         source='1C2BFB4.sdk_event_name_decode')
        memory.write(marker + count + 2, bytes(2), source='1C2BFD7.sdk_event_name_terminators')
        memory.store(marker, 0, 1, source='1C2BFE5.sdk_event_name_decoded')
    return _cstring(runtime, marker + 2)


def destroy(runtime, event):
    memory = runtime.memory
    memory.store(event, runtime.image_base + _definition()['vtable_rva'], 8,
                 source='1C2D0F8.sdk_event_destructor_vtable')
    for offset in reversed(range(224, 392, 24)):
        _String.read(runtime, event + offset).destroy()
    _invoke(runtime, 0xBCD740, event)


def emit(runtime, rbp, node):
    memory, base = runtime.memory, runtime.image_base
    event, columns = rbp + 0x1C0, rbp + 0x180
    temporary = _String.construct(runtime, _name(runtime))
    temporary.clone().write_to(event + 8)
    for offset in range(32, 200, 24):
        memory.store(event + offset, 0, 2, source='1C2C0B6.sdk_event_empty_field')
    memory.write(event + 200, bytes(24), source='1C2C0F5.sdk_event_base_vector')
    memory.store(event, base + _definition()['vtable_rva'], 8, source='1C2C107.sdk_event_vtable')
    memory.write(event + 224, bytes(168), source='1C2C115.sdk_event_columns_initialization')
    temporary.destroy()
    key = memory.load(node + 16, 8)
    _String.construct(runtime, str(key).encode('ascii')).write_to(event + 224)
    for index in range(6):
        _String.read(runtime, node + 24 + index * 24).clone().write_to(event + 248 + index * 24)
    _owner(runtime, _response_image())
    for offset in (0, 24):
        _String.construct(runtime, b'').write_to(columns + offset)
    runtime.events.append(('sdk.event_submit', event, columns, key))
    _invoke(runtime, 0x1BEFC10, base + 0x67519B8, event, columns, 1, 10, 0)
    for offset in (24, 0):
        _String.read(runtime, columns + offset).destroy()
    destroy(runtime, event)


def invoke(runtime, rva, values):
    definition = _definition()
    if rva == definition['topic_virtual_rva'] and len(values) == 2:
        _String.construct(runtime, bytes.fromhex(definition['topic_hex'])).write_to(values[1])
        return values[1]
    if rva == definition['kind_virtual_rva'] and len(values) == 1:
        return definition['kind']
    if rva == 0x1C2D0F0 and len(values) == 1:
        return destroy(runtime, values[0])
    raise InputError('SDK event native entry argument count mismatch')
