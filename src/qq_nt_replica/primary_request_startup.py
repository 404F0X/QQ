import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _cstring, _String, _Tree
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = 'd440fbbb3bd34e6e927821ae269e0c300a0cd48e473f06fd6e16bda27bdf1e27'


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'request-startup-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed request startup image identity mismatch')
    return json.loads(raw)


def install_image(memory, base):
    memory.map(base + 0x677CF00, bytearray(0x130), name='request startup PE zero fill', initialized=True)


def _locals(runtime, rbp, writes):
    for item in writes:
        runtime.memory.write(rbp + item['offset'], bytes.fromhex(item['hex']),
                             source=f"{item['source_rva']:X}.request_startup_local")


def _command(runtime, rbp, item):
    from .primary_worker_consumer import _invoke
    memory = runtime.memory
    _locals(runtime, rbp, item['writes'])
    if memory.load(rbp - 0x58, 1) & 1:
        memory.store(rbp + 0x68, 0, 8, source='1CF4360.command_decode_index')
        for index in range(item['length']):
            value = memory.load(rbp - 0x56 + index, 1)
            seed = memory.load(rbp - 0x57, 1)
            memory.store(rbp - 0x56 + index, value ^ seed ^ (index + 1) ^ item['length'], 1,
                         source='1CF4360.command_decode')
            memory.store(rbp + 0x68, index + 1, 8, source='1CF4360.command_decode_index')
        memory.write(rbp - 0x56 + item['length'], bytes(2), source='1CF4360.command_terminators')
        memory.store(rbp - 0x58, 0, 1, source='1CF4360.command_decoded')
    value = _cstring(runtime, rbp - 0x56)
    pointer = _invoke(runtime, 0xB75000, (len(value) + 16) & ~15)
    destination = runtime.image_base + item['rva']
    memory.store(destination + 16, pointer, 8, source='1CF4360.command_allocation')
    memory.store(destination, ((len(value) + 16) & ~15) | 1, 8, source='1CF4360.command_capacity')
    memory.store(destination + 8, len(value), 8, source='1CF4360.command_length')
    memory.write(pointer, value + b'\0', source='1CF4360.command_payload')


def construct(runtime):
    memory, base, data = runtime.memory, runtime.image_base, _image()
    frame, rbp = _frame(runtime, 0x100, '1CF4360.request_startup_frame')
    for item in data['global_writes']:
        memory.write(base + item['rva'], bytes.fromhex(item['hex']),
                     source=f"{item['source_rva']:X}.request_startup_global")
    _locals(runtime, rbp, data['local_writes'])
    head = base + 0x677D030
    memory.write(head + 8, bytes(16), source='1CF4C7C.request_status_root_count')
    memory.store(head, head + 8, 8, source='1CF4C91.request_status_begin')
    table = _Tree(runtime, head)
    for offset in data['key_offsets']:
        key = memory.load(rbp + offset, 4)

        def initialize(node):
            memory.store(node + 32, key, 4, source='1CF2FC0.request_status_key')
            _String.read(runtime, rbp + offset + 8).clone().write_to(node + 40)

        node = table.insert(key, 64, initialize)
        memory.store(rbp + 0x68, node, 8, source='1CF2FC0.request_status_emplace_result')
        memory.store(rbp + 0x70, 1, 1, source='1CF3069.request_status_inserted')
    for offset in reversed(data['key_offsets']):
        _String.read(runtime, rbp + offset + 8).destroy()
    callbacks = [base + item['callback_rva'] for item in data['registrations']]
    _invoke(runtime, 0x3E680B4, callbacks[0])
    _invoke(runtime, 0x75B000, base + 0x677D048)
    _invoke(runtime, 0x3E680B4, callbacks[1])
    memory.write(base + 0x677D070, bytes(24), source='1CF4DB2.request_archive_vector')
    _invoke(runtime, 0x3E680B4, callbacks[2])
    for index, item in enumerate(data['commands']):
        _command(runtime, rbp, item)
        result = _invoke(runtime, 0x3E680B4, callbacks[index + 3])
    runtime.events.append(('request.startup_constructed',))
    memory.unmap(frame)
    return result


def _destroy_archive(runtime):
    memory, base = runtime.memory, runtime.image_base
    begin = memory.load(base + 0x677D070, 8)
    if not begin:
        return
    end = memory.load(base + 0x677D078, 8)
    if end < begin or (end - begin) % 192:
        raise PrimarySemanticUnavailable('request archive cleanup requires an aligned forward 192-byte range')
    while end != begin:
        end -= 192
        _String.read(runtime, end).destroy()
    storage = memory.load(base + 0x677D070, 8)
    memory.store(base + 0x677D078, begin, 8, source='1C54B80.archive_end')
    return runtime._free_allocation(storage)


def invoke(runtime, rva, values):
    if values:
        raise InputError('request startup source interface takes no arguments')
    if rva == 0x1CF4360:
        return construct(runtime)
    if rva == 0x1C54B50:
        from .primary_device_records import _destroy_record_tree
        return _destroy_record_tree(runtime, runtime.memory.load(runtime.image_base + 0x677D038, 8))
    if rva == 0x1C54B70:
        return _invoke(runtime, 0x75B030, runtime.image_base + 0x677D048)
    if rva == 0x1C54B80:
        return _destroy_archive(runtime)
    headers = {0x1CE2AF0: 0x677D160, 0x1CE2B10: 0x677D178,
               0x1CE2B30: 0x677D190, 0x1CE2B50: 0x677D1A8}
    if rva in headers:
        return _String.read(runtime, runtime.image_base + headers[rva]).destroy()
    raise InputError('request startup source interface RVA mismatch')
