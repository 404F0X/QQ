import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_collector import _terminated
from .primary_logger import _String, log
from .primary_memory import PrimaryMemoryLimit, UnknownMemory
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = '041b3e26ca1c03cb451a95a12c594df58f60d5e3f73051ef194e92225158250a'
_IMPORTS = {'GetAdaptersInfo': 0x4910E78}


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/device-adapter-detail-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed adapter detail image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed adapter detail import identity mismatch')
    return image


def install_image(memory, image_base):
    for segment in _image()['segments']:
        address, raw = image_base + segment['rva'], bytes.fromhex(segment['hex'])
        try:
            memory._span(address, len(raw))
        except PrimaryMemoryLimit:
            memory.map(address, bytearray(raw), name='fixed adapter detail image', initialized=True)
        else:
            if memory.read(address, len(raw)) != raw:
                raise InputError('shared adapter detail image identity mismatch')


def _query(runtime, buffer, size_pointer):
    from .primary_device_hardware import AdapterBufferEffect, apply_adapter_buffer
    target = runtime.worker_imports.get('GetAdaptersInfo')
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS['GetAdaptersInfo'], 8) != target:
        raise PrimarySemanticUnavailable('adapter detail current GetAdaptersInfo import is not bound')
    if runtime.worker_observations is None:
        raise UnknownMemory('missing adapter detail GetAdaptersInfo observations')
    capacity = runtime.memory.load(size_pointer, 4)
    result, effects = runtime.worker_observations.take(runtime, 'GetAdaptersInfo', (target, bool(buffer), capacity))
    if not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], (bytes, AdapterBufferEffect)):
        raise InputError('adapter detail query requires raw buffer and explicit size effects')
    raw, updated = effects
    physical = runtime.allocations.get(buffer)
    if physical is None:
        raise InputError('adapter detail output exceeds its actual allocation')
    if updated is not None and (type(updated) is not int or not 0 <= updated <= 0xFFFFFFFF):
        raise InputError('adapter detail size output must be an observed DWORD')
    apply_adapter_buffer(runtime, buffer, min(capacity, physical), raw, source='2E242xx.GetAdaptersInfo_output')
    if updated is not None:
        if type(updated) is not int or not 0 <= updated <= 0xFFFFFFFF:
            raise InputError('adapter detail size output must be an observed DWORD')
        runtime.memory.store(size_pointer, updated, 4, source='2E242xx.GetAdaptersInfo_size')
    return result & 0xFFFFFFFF


def _log_failure(runtime, error):
    item = _image()['logs']['587']
    runtime.events.append(('device.adapter_detail_log', 587))
    return log(runtime, bytes.fromhex(item['source_file_hex']), 587,
               bytes.fromhex(item['template_hex']), bytes.fromhex(item['tag_hex']), item['severity'], error)


def capture(runtime, owner):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x110, '2E24240.adapter_detail_frame')
    size_pointer = rbp - 0x44
    memory.store(size_pointer, 0x2C0, 4, source='2E24267.initial_adapter_buffer_size')
    buffer = _invoke(runtime, 0x3E97020, 0x2C0)
    result = _query(runtime, buffer, size_pointer)
    if result == 111:
        _invoke(runtime, 0x3E94F90, buffer)
        buffer = _invoke(runtime, 0x3E97020, memory.load(size_pointer, 4))
    result = _query(runtime, buffer, size_pointer)
    if result:
        _log_failure(runtime, result)
    else:
        _String.construct(runtime, _terminated(runtime, buffer + 0xC, 1)[:-1]).write_to(rbp + 0x18)
        _String.construct(runtime, _terminated(runtime, buffer + 0x110, 1)[:-1]).write_to(rbp - 0x28)
        memory.write(rbp - 0x40, bytes(24), source='2E24E68.empty_adapter_address_String')
        address_string = _String.read(runtime, rbp - 0x40)
        for index in range(8):
            value = memory.load(buffer + 0x198 + index, 1)
            for nibble in (value >> 4, value & 15):
                character = memory.load(runtime.image_base + _image()['alphabet_rva'] + nibble, 1)
                address_string.append(bytes([character]))
                address_string.write_to(rbp - 0x40)
        for source, field in ((rbp + 0x18, 0x4B0), (rbp - 0x28, 0x4C8), (rbp - 0x40, 0x4E0)):
            if _String.read(runtime, source).value():
                _invoke(runtime, 0x75CEC0, owner + field, source)
        for source in (rbp - 0x40, rbp - 0x28, rbp + 0x18):
            _String.read(runtime, source).destroy()
    _invoke(runtime, 0x3E94F90, buffer)
    memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    if rva != 0x2E24240 or len(values) != 1:
        raise InputError('adapter detail source interface argument count mismatch')
    return capture(runtime, values[0])
