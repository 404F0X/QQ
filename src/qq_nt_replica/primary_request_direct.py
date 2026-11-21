import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _String, _cstring, feature, log
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke, _logger
from .primary_worker_response import _frame


_IMAGE_SHA256 = '0bd74ac99b91297e15c2e490ab7f7e6db9b141123c349b87bff339f6975a58fe'


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'request-direct-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed direct request image identity mismatch')
    return json.loads(raw)


def install_image(memory, base):
    from .primary_pending_thread import install_image as install_async_image

    install_async_image(memory, base)
    for segment in _image()['segments']:
        memory.map(base + segment['rva'], bytearray(segment['size']),
                   name='fixed reporter command PE zero fill', initialized=True)


def initialize(runtime):
    for item in _image()['initializer_writes']:
        runtime.memory.store(runtime.image_base + item['rva'], item['value'], item['width'],
                             source='1BF5D70.reporter_command_initializer')
    runtime.events.append(('request.reporter_commands_initialized',))
    return 0


def _command(runtime):
    memory, base = runtime.memory, runtime.image_base
    flag, key, pointer = base + 0x677BFD7, base + 0x677BFD8, base + 0x677BFD9
    if memory.load(flag, 1) & 1:
        for index in range(31):
            byte = memory.load(pointer + index, 1)
            seed = memory.load(key, 1)
            memory.store(pointer + index, byte ^ (index + 1) ^ seed ^ 31, 1,
                         source='1BF259B.report_command_byte_decode')
        memory.store(base + 0x677BFF8, 0, 1, source='1BF25B7.report_command_terminator')
        memory.store(base + 0x677BFF9, 0, 1, source='1BF25BE.report_command_terminator')
        memory.store(flag, 0, 1, source='1BF25C5.report_command_decode_flag_clear')
    return _cstring(runtime, pointer)


def submit(runtime, owner, kind, payload, columns, mode, last_flag):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x1D8, '1BF2390.direct_request_frame')
    if kind & 255:
        sequence = _invoke(runtime, 0x1BF33F0, owner, payload, mode & 0xFFFFFFFF)
        if not _invoke(runtime, 0x1BE4230, _logger(runtime), 21) & 255:
            from .primary_pending_thread import construct

            construct(runtime, owner, payload, columns, rbp)
            runtime.memory.unmap(frame)
            return 0
        from .primary_worker_tasks import provider_task

        task = provider_task(runtime)
        _String.read(runtime, payload).clone().write_to(rbp - 32)
        runtime.memory.store(rbp - 8, owner, 8, source='1BF2438.pending_send_owner')
        runtime.memory.store(rbp, sequence, 8, source='1BF243C.pending_send_sequence')
        for offset, source in ((8, columns), (32, columns + 24)):
            _String.read(runtime, source).clone().write_to(rbp + offset)
        runtime.memory.store(rbp - 48, 0, 8, source='1BF245F.pending_send_empty_function')
        active = runtime._operator_new(104)
        runtime.memory.store(active, runtime.image_base + 0x4148C38, 8,
                             source='1BF2478.pending_send_function_vtable')
        _String.read(runtime, rbp - 32).clone().write_to(active + 8)
        runtime.memory.store(active + 32, owner, 8, source='1BF24A4.pending_send_capture_owner')
        runtime.memory.store(active + 40, sequence, 8, source='1BF24A4.pending_send_capture_sequence')
        for offset, source in ((48, rbp + 8), (72, rbp + 32)):
            _String.read(runtime, source).clone().write_to(active + offset)
        runtime.memory.store(rbp - 48, active, 8, source='1BF24D6.pending_send_function_owner')
        for offset in (32, 8, -32):
            _String.read(runtime, rbp + offset).destroy()
        _invoke(runtime, 0xBD0780, task, rbp - 80)
        runtime.memory.unmap(frame)
        return 0
    gate = _invoke(runtime, 0xBA21A0)
    header = memory.load(payload, 1)
    if header & 1:
        count, pointer = memory.load(payload + 8, 4), memory.load(payload + 16, 8)
    else:
        count, pointer = header >> 1, payload + 1
    _String.construct(runtime, _command(runtime)).write_to(rbp + 128)
    _invoke(runtime, 0x1CE2C50, gate, rbp + 128, pointer, count, columns, last_flag & 255)
    memory.unmap(frame)
    return 0


def send(runtime, receiver, command, pointer, count, columns, last_flag):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x140, '1CE2C50.direct_transport_frame')
    count &= 0xFFFFFFFF
    if _invoke(runtime, 0x1BE4230, _logger(runtime), 43) & 255:
        entry = _image()['enhanced_log']
        log(runtime, bytes.fromhex(entry['file_hex']), entry['line'], bytes.fromhex(entry['template_hex']),
            bytes.fromhex(entry['tag_hex']), entry['severity'])
        memory.store(rbp, 0, 8, source='1CE3070.enhanced_empty_callback')
        _String.construct(runtime, memory.read(pointer, count)).write_to(rbp + 72)
        _invoke(runtime, 0x1CE3390, receiver, command, rbp + 72, rbp - 32, columns, 0)
        _String.read(runtime, rbp + 72).destroy()
    else:
        gate = _invoke(runtime, 0xBA21A0)
        if memory.load(gate + 8, 8):
            if not memory.load(base + 0x677D1C0, 8):
                manager = runtime._operator_new(64)
                _invoke(runtime, 0x1CF35E0, manager)
                memory.store(base + 0x677D1C0, manager, 8, source='1CE30E0.direct_cache_publish')
            memory.store(rbp + 72, 0, 2, source='1CE30E7.empty_duplicate_tag')
            suppressed = _invoke(runtime, 0x1CF2D00, columns, command, rbp + 72)
            _String.read(runtime, rbp + 72).destroy()
            if not suppressed & 255:
                gate = _invoke(runtime, 0xBA21A0)
                transport = memory.load(gate + 8, 8)
                alternate = bool(last_flag & 255)
                copied = rbp - (80 if alternate else 56)
                _String.read(runtime, command).clone().write_to(copied)
                slot = 0 if alternate else 8
                target = memory.load(memory.load(transport, 8) + slot, 8)
                binding = runtime.request_transport
                expected = None if binding is None else binding.alternate_send_address if alternate else binding.send_address
                if expected is None or target != expected:
                    raise PrimarySemanticUnavailable(f'direct request requires actual virtual send callback {target:#x}, slot{slot}')
                callback = binding.send_alternate if alternate else binding.send
                callback(runtime, transport, copied, pointer, count, 0)
                runtime.events.append(('request.direct_dispatched', slot, count))
            else:
                runtime.events.append(('request.direct_duplicate_suppressed',))
    _String.read(runtime, command).destroy()
    memory.unmap(frame)
    return 0


def invoke(runtime, rva, values):
    if rva == 0x1BF5D70 and not values:
        return initialize(runtime)
    if rva == 0x1BE4230 and len(values) == 2:
        return int(feature(runtime, values[0], values[1] & 0xFFFFFFFF) == 1)
    if rva == 0x1BF2390 and len(values) == 6:
        return submit(runtime, *values)
    if rva == 0x1CE2C50 and len(values) == 6:
        return send(runtime, *values)
    raise InputError('direct request native entry argument count mismatch')
