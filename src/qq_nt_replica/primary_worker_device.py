import hashlib
from pathlib import Path
from types import SimpleNamespace

from .errors import InputError


_DATA = Path(__file__).with_name('data') / 'primary_sign_qq52230'
_HOSTS = ((0x6428A20, 'device-records-hosts.bin', 'd8ebc44f3ececd93ff9528121221305dc853f9d98b9c577ddf8af3631ee658ea'),
          (0x6556FF0, 'device-mix-hosts.bin', '44efb90779ef6d503b095bd9b581893d0226d08f57621c52870eb168740940c4'))


def install_image(memory, image_base):
    for rva, name, expected in _HOSTS:
        raw = (_DATA / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise InputError('fixed device processing host bank identity mismatch: ' + name)
        relocated = b''.join((int.from_bytes(raw[index:index + 8], 'little') - 0x180000000 + image_base).to_bytes(8, 'little')
                             for index in range(0, len(raw), 8))
        memory.map(image_base + rva, bytearray(relocated), name='fixed device records host bank', initialized=True)
    for rva, raw in ((0x4852891, b'%d\0'), (0x4903C0F, b'\0')):
        if memory.read(image_base + rva, len(raw)) != raw:
            raise InputError('shared device records source string identity mismatch')


def _invoke(runtime, rva, *values):
    vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    return runtime.invoke(vm, rva, tuple(range(len(values))))


def invoke(runtime, rva, values):
    if rva in (0x1BF7620, 0x2DE93E0):
        if len(values) != 4:
            raise InputError('device records processing takes input records, DWORD count and two output pointers')
        if rva == 0x1BF7620:
            _invoke(runtime, 0x1BF63F0)
        pointer, count, output, length = values
        return runtime.execute('device-records', (pointer, count & 0xFFFFFFFF, output, length), None)
    if rva == 0x35922AC and len(values) == 2:
        return runtime.execute('device-mix', values, None)
    if rva == 0x2DE942F and len(values) == 1:
        target = runtime.memory.load(runtime.image_base + 0x490FDE8, 8)
        result = _invoke(runtime, target - runtime.image_base)
        runtime.memory.store(values[0], result & 0xFFFFFFFF, 4, source='2DE943D.current_process_id')
        return None
    raise InputError('device records source interface argument count mismatch')
