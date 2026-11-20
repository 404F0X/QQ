import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _decode, log
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = '101fa432b4976dd511ff3c4734b089951a7c96e1330cb39cd77f1e9dacc9a406'
_VTABLE = 0x414ACF8


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/sdk-collection-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed SDK collection image identity mismatch')
    return json.loads(raw)


def install_image(memory, base):
    image = _image()
    for segment in image['segments']:
        raw = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            value = int.from_bytes(raw[offset:offset + 8], 'little') - image['image_base'] + base
            raw[offset:offset + 8] = value.to_bytes(8, 'little')
        memory.map(base + segment['rva'], raw, name='fixed SDK collection source image', initialized=True)
    segment = image['startup']['fresh_zero_fill']
    memory.map(base + segment['rva'], bytearray(segment['size']), name='SDK startup PE zero fill', initialized=True)
    segment = image['environment_probes']['optional_export_zero_fill']
    memory.map(base + segment['rva'], bytearray(segment['size']), name='SDK optional export PE zero fill', initialized=True)


def construct(runtime):
    frame, _ = _frame(runtime, 0x28, '1C54180.sdk_startup_frame')
    result = None
    for item in _image()['startup']['operations']:
        if item['kind'] == 'write':
            runtime.memory.write(runtime.image_base + item['rva'], bytes.fromhex(item['hex']),
                                 source=f"{item['source_rva']:X}.sdk_startup_global")
        else:
            result = _invoke(runtime, 0x3E680B4, runtime.image_base + item['callback_rva'])
    runtime.events.append(('sdk.records_startup_constructed',))
    runtime.memory.unmap(frame)
    return result


def _virtual(runtime, active, offset, *arguments):
    memory = runtime.memory
    target = memory.load(memory.load(active, 8) + offset, 8) - runtime.image_base
    if target in (0x1D040D0, 0x1D040F0):
        return _invoke(runtime, target, active, *arguments)
    if target not in (0x142A0, 0x1C540A0, 0x1C540C0, 0x28F0, 0x1FE0, 0x1C540F0):
        raise PrimarySemanticUnavailable('SDK collection current virtual function is not implemented: ' + hex(target))
    runtime.events.append(('sdk.collection_virtual', target, (active, *arguments)))
    if target in (0x28F0, 0x1FE0):
        if target == 0x1FE0:
            runtime._free_allocation(active)
        return None
    return invoke(runtime, target, (active, *arguments))


def _copy(runtime, active, inline, destination):
    if not active:
        runtime.memory.store(destination + 24, 0, 8, source='sdk.collection_empty_copy')
    elif active == inline:
        runtime.memory.store(destination + 24, destination, 8, source='sdk.collection_inline_copy_owner')
        _virtual(runtime, active, 8, destination)
    else:
        copied = _virtual(runtime, active, 16)
        runtime.memory.store(destination + 24, copied, 8, source='sdk.collection_heap_copy_owner')


def _destroy(runtime, inline):
    active = runtime.memory.load(inline + 24, 8)
    if active:
        _virtual(runtime, active, 24 if active == inline else 32)


def swap(runtime, left, right):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x40, 'BED870.sdk_function_swap_frame')
    rbp = frame + 0x40
    if left == right:
        memory.unmap(frame)
        return
    active_left = memory.load(left + 24, 8)
    if active_left != left:
        active_right = memory.load(right + 24, 8)
        if active_right != right:
            memory.store(left + 24, active_right, 8, source='BED8B2.sdk_pointer_swap_left')
            memory.store(right + 24, active_left, 8, source='BED8B6.sdk_pointer_swap_right')
        else:
            _virtual(runtime, active_right, 8, left)
            _destroy(runtime, right)
            memory.store(right + 24, memory.load(left + 24, 8), 8, source='BED870.sdk_right_pointer_transfer')
            memory.store(left + 24, left, 8, source='BED870.sdk_left_inline_owner')
    elif memory.load(right + 24, 8) != right:
        _virtual(runtime, active_left, 8, right)
        _destroy(runtime, left)
        memory.store(left + 24, memory.load(right + 24, 8), 8, source='BED870.sdk_left_pointer_transfer')
        memory.store(right + 24, right, 8, source='BED870.sdk_right_inline_owner')
    else:
        temporary = rbp - 0x20
        _virtual(runtime, active_left, 8, temporary)
        _destroy(runtime, left)
        memory.store(left + 24, 0, 8, source='BED870.sdk_left_owner_reset')
        _virtual(runtime, memory.load(right + 24, 8), 8, left)
        _destroy(runtime, right)
        memory.store(right + 24, 0, 8, source='BED870.sdk_right_owner_reset')
        memory.store(left + 24, left, 8, source='BED870.sdk_left_inline_owner')
        _virtual(runtime, temporary, 8, right)
        _virtual(runtime, temporary, 24)
        memory.store(right + 24, right, 8, source='BED870.sdk_right_inline_owner')
    memory.unmap(frame)


def register(runtime):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x140, '1C1B430.sdk_collection_registration_frame')
    collection = memory.load(base + 0x6751D80, 8)
    if not collection:
        collection = runtime._operator_new(80)
        memory.store(collection + 72, 0, 8, source='1C1B466.sdk_second_empty_owner')
        memory.store(collection + 32, 0, 8, source='1C1B46E.sdk_first_empty_owner')
        memory.store(base + 0x6751D80, collection, 8, source='1C1B476.sdk_collection_publish')
    for offset in (-0x48, -0x20):
        pointer = rbp + offset
        memory.store(pointer, base + _VTABLE, 8, source='1C1B430.sdk_source_vtable')
        memory.store(pointer + 8, base + 0x1C03200, 8, source='1C1B430.sdk_source_callback')
        memory.store(pointer + 24, pointer, 8, source='1C1B430.sdk_source_owner')
    image = _image()
    log(runtime, _decode(image['literals']['file']), 113, _decode(image['literals']['template']),
        bytes.fromhex(image['tag_hex']), 2)
    temporary = rbp + 0x10
    for source, destination in ((rbp - 0x20, collection + 48), (rbp - 0x48, collection + 8)):
        _copy(runtime, memory.load(source + 24, 8), source, temporary)
        swap(runtime, temporary, destination)
        _destroy(runtime, temporary)
    _destroy(runtime, rbp - 0x20)
    _destroy(runtime, rbp - 0x48)
    memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva == 0x1C54180 and not values:
        return construct(runtime)
    if rva == 0x1C1B430 and not values:
        return register(runtime)
    if rva == 0xBED870 and len(values) == 2:
        return swap(runtime, *values)
    memory, base = runtime.memory, runtime.image_base
    if rva in (0x1C540A0, 0x1C540C0):
        if len(values) != (2 if rva == 0x1C540A0 else 1):
            raise InputError('SDK function clone has an invalid argument count')
        output = values[1] if rva == 0x1C540A0 else runtime._operator_new(16)
        memory.store(output, base + _VTABLE, 8, source='sdk.collection_clone_vtable')
        memory.store(output + 8, memory.load(values[0] + 8, 8), 8, source='sdk.collection_clone_callback')
        return memory.load(values[0] + 8, 8) if rva == 0x1C540A0 else output
    if rva == 0x142A0 and len(values) == 2:
        if values[1] & 1:
            runtime._free_allocation(values[0])
        return values[0]
    if rva == 0x1C540F0 and len(values) == 2:
        _invoke(runtime, memory.load(values[0] + 8, 8) - base, values[1])
        return values[1]
    raise InputError('unsupported SDK collection entry or argument count')
