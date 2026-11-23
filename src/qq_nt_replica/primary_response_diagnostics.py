import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _cstring, _decode, _String
from .primary_worker_consumer import _append, _invoke, _zero_string
from .primary_worker_response import _frame


_IMAGE_SHA256 = '6c6c7fa82b30f4f088d86a78e62796763b2c1d556fd9e2861ca0570251fdf25c'
_ALPHABET = 0x677CFE8


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'response-diagnostics-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed response diagnostics image identity mismatch')
    return json.loads(raw)


def install_image(memory, base):
    for segment in _image()['segments']:
        address = base + segment['rva']
        raw = bytes.fromhex(segment['hex'])
        if any(region.address <= address and address + len(raw) <= region.address + len(region.data)
               for region in memory._region_snapshot()):
            if memory.read(address, len(raw)) != raw:
                raise InputError('response diagnostics image overlaps different source bytes')
        else:
            memory.map(address, raw,
                       name='fixed response diagnostics source data', initialized=True)


def _alphabet(runtime):
    memory, pointer = runtime.memory, runtime.image_base + _ALPHABET
    if memory.load(pointer, 1) & 1:
        for index in range(64):
            value = memory.load(pointer + 2 + index, 1) ^ memory.load(pointer + 1, 1) ^ (index + 1) ^ 64
            memory.store(pointer + 2 + index, value, 1, source='1CAC21B.response_alphabet_decode')
        memory.store(pointer + 66, 0, 1, source='1CAC237.response_alphabet_terminator')
        memory.store(pointer + 67, 0, 1, source='1CAC23E.response_alphabet_terminator')
        memory.store(pointer, 0, 1, source='1CAC245.response_alphabet_decoded')
    return _cstring(runtime, pointer + 2)


def _pointer(value, address):
    return value.get(16, 8) if value.get(0, 1) & 1 else address + 1


def encode(runtime, output, source, alphabet):
    result = _zero_string(runtime)
    result.write_to(output)
    frame, _ = _frame(runtime, 0x68, '1CACBB0.response_base64_frame')
    rbp = frame + 0x60
    symbols = _String.read(runtime, alphabet).clone()
    symbols.write_to(rbp - 0x28)
    if not symbols.value():
        symbols.destroy()
        symbols = _String.construct(runtime, _alphabet(runtime))
        symbols.write_to(rbp - 0x28)
    data = _String.read(runtime, source).value()
    for offset in range(0, len(data), 3):
        chunk = data[offset:offset + 3]
        value = int.from_bytes(chunk.ljust(3, b'\0'), 'big')
        for index in range(len(chunk) + 1):
            pointer = _pointer(symbols, rbp - 0x28)
            digit = runtime.memory.load(pointer + ((value >> (18 - 6 * index)) & 63), 1)
            _append(result, bytes([digit]))
            result.write_to(output)
        if len(chunk) < 3:
            _append(result, b'=' * (3 - len(chunk)))
            result.write_to(output)
    symbols.destroy()
    runtime.memory.unmap(frame)
    return output


def _hex(runtime, source, output):
    result = _zero_string(runtime)
    result.write_to(output)
    for index in range(32):
        for shift in (4, 0):
            digit = (runtime.memory.load(source + index, 1) >> shift) & 15
            _append(result, bytes([runtime.memory.load(runtime.image_base + 0x414ADE0 + digit, 1)]))
            result.write_to(output)
    return result


def report(runtime):
    data = _image()
    frame, rbp = _frame(runtime, 0x1A8, '1CABB60.response_error_frame')
    _invoke(runtime, 0xB9F1D0, _decode(data['file']), 0x177, _decode(data['error']),
            runtime.image_base + 0x48972C7, 2)
    material = runtime.image_base + 0x677D0B8
    public_key = _hex(runtime, material + 0x81, rbp + 0x30)
    alphabet = _String.construct(runtime, _alphabet(runtime))
    alphabet.write_to(rbp - 8)
    identifier = _String.construct(runtime, runtime.memory.read(material + 0x30, 32))
    identifier.write_to(rbp - 0x40)
    _invoke(runtime, 0x1CACBB0, rbp - 0x20, rbp - 0x40, rbp - 8)
    encoded = _String.read(runtime, rbp - 0x20)
    shared_key = _hex(runtime, material, rbp + 0x10)
    _invoke(runtime, 0x1C56610, _decode(data['file']), 0x17B, _decode(data['diagnostic']),
            runtime.image_base + 0x48972C7, _pointer(shared_key, rbp + 0x10),
            _pointer(encoded, rbp - 0x20), _pointer(public_key, rbp + 0x30))
    for address in (rbp + 0x10, rbp - 0x20, rbp - 0x40, rbp - 8, rbp + 0x30):
        _String.read(runtime, address).destroy()
    runtime.memory.unmap(frame)
