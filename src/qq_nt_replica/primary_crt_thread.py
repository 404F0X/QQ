import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_thread_dispatch import _api
from .primary_vm import PrimaryProgramLimit, signed
from .primary_worker_consumer import _invoke


_IMAGE_SHA256 = 'f0d18df000d99ab756a6fd5ffe1b917337d0caf32cdbe947cbf01306efcf1451'
_MASK64 = (1 << 64) - 1


def install_image(memory, base):
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/crt-thread-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed CRT thread data image identity mismatch')
    image = json.loads(raw)
    for segment in image['segments']:
        data = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            pointer = int.from_bytes(data[offset:offset + 8], 'little')
            data[offset:offset + 8] = ((pointer - image['image_base'] + base) & _MASK64).to_bytes(8, 'little')
        memory.map(base + segment['rva'], data, name='fixed CRT thread initial data', initialized=True)


def _critical(runtime, identifier, acquire):
    identifier = signed(identifier, 32)
    if not 0 <= identifier < 256:
        raise PrimaryProgramLimit('CRT critical-section index is outside the bounded table domain')
    pointer = runtime.image_base + 0x6D8EA30 + identifier * 40
    held = getattr(runtime, '_crt_locks', {})
    if not acquire and not held.get(pointer, 0):
        raise PrimaryProgramLimit('CRT critical-section release requires its observed acquisition')
    _api(runtime, 'EnterCriticalSection' if acquire else 'LeaveCriticalSection', pointer)
    held[pointer] = held.get(pointer, 0) + (1 if acquire else -1)
    runtime._crt_locks = held


def _change(runtime, pointer, delta):
    previous = runtime.memory.load(pointer, 4)
    runtime.memory.store(pointer, (previous + delta) & 0xFFFFFFFF, 4, source='CRT.thread_shared_reference')
    return previous


def free(runtime, pointer):
    runtime.events.append(('CRT.free.entry', pointer))
    runtime._free_allocation(pointer)


def calloc(runtime, count, width):
    count, width = count & _MASK64, width & _MASK64
    if count and width > (_MASK64 - 31) // count:
        runtime.memory.store(_invoke(runtime, 0x3E84C9C), 12, 4, source='3EA01B7.calloc_overflow_errno')
        return 0
    return runtime._allocate(max(count * width, 1), True)


def time_reference(runtime, pointer, delta):
    if not pointer or pointer == runtime.image_base + 0x45BFC20:
        return 0x7FFFFFFF
    return (_change(runtime, pointer + 0x15C, delta) + delta) & 0xFFFFFFFF


def locale_reference(runtime, locale, delta):
    if not locale and delta < 0:
        return None
    memory, base = runtime.memory, runtime.image_base
    _change(runtime, locale + 16, delta)
    for offset in (0xE0, 0xF0, 0xE8, 0x100):
        pointer = memory.load(locale + offset, 8)
        if pointer:
            _change(runtime, pointer, delta)
    for index in range(6):
        cursor = locale + 0x38 + index * 32
        if memory.load(cursor - 16, 8) != base + 0x6744B78:
            pointer = memory.load(cursor, 8)
            if pointer:
                _change(runtime, pointer, delta)
        if memory.load(cursor - 24, 8):
            pointer = memory.load(cursor - 8, 8)
            if pointer:
                _change(runtime, pointer, delta)
    return time_reference(runtime, memory.load(locale + 0x120, 8), delta)


def free_array(runtime, pointer, count):
    count &= _MASK64
    if count > 100000 or pointer > _MASK64 - count * 8:
        raise PrimaryProgramLimit('CRT string array is outside the bounded memory domain')
    for cursor in range(pointer, pointer + count * 8, 8):
        free(runtime, runtime.memory.load(cursor, 8))


def free_time_contents(runtime, pointer):
    if not pointer:
        return
    for offset, count in ((0, 7), (0x38, 7), (0x70, 12), (0xD0, 12), (0x130, 2)):
        free_array(runtime, pointer + offset, count)
    for offset in (0x140, 0x148, 0x150):
        free(runtime, runtime.memory.load(pointer + offset, 8))
    for offset, count in ((0x160, 7), (0x198, 7), (0x1D0, 12), (0x230, 12), (0x290, 2)):
        free_array(runtime, pointer + offset, count)
    for offset in (0x2A0, 0x2A8, 0x2B0, 0x2B8):
        free(runtime, runtime.memory.load(pointer + offset, 8))


def free_time(runtime, pointer):
    if pointer and pointer != runtime.image_base + 0x45BFC20 and not runtime.memory.load(pointer + 0x15C, 4):
        free_time_contents(runtime, pointer)
        free(runtime, pointer)


def free_lconv_fields(runtime, pointer, offsets):
    if pointer:
        for offset in offsets:
            value = runtime.memory.load(pointer + offset, 8)
            if value != runtime.memory.load(runtime.image_base + 0x67443B0 + offset, 8):
                free(runtime, value)


def free_locale(runtime, locale):
    memory, base = runtime.memory, runtime.image_base
    lconv = memory.load(locale + 0xF8, 8)
    if lconv and lconv != base + 0x67443B0:
        reference = memory.load(locale + 0xE0, 8)
        if reference and not memory.load(reference, 4):
            for offset, fields in ((0xF0, (0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48,
                    0x68, 0x70, 0x78, 0x80, 0x88, 0x90)), (0xE8, (0, 8, 0x10, 0x58, 0x60))):
                pointer = memory.load(locale + offset, 8)
                if pointer and not memory.load(pointer, 4):
                    free(runtime, pointer)
                    free_lconv_fields(runtime, memory.load(locale + 0xF8, 8), fields)
            free(runtime, memory.load(locale + 0xE0, 8))
            free(runtime, memory.load(locale + 0xF8, 8))
    pointer = memory.load(locale + 0x100, 8)
    if pointer and not memory.load(pointer, 4):
        for offset, displacement in ((0x108, 0xFE), (0x110, 0x80), (0x118, 0x80)):
            free(runtime, (memory.load(locale + offset, 8) - displacement) & _MASK64)
        free(runtime, memory.load(locale + 0x100, 8))
    free_time(runtime, memory.load(locale + 0x120, 8))
    for index in range(6):
        cursor = locale + 0x38 + index * 32
        if memory.load(cursor - 16, 8) != base + 0x6744B78:
            pointer = memory.load(cursor, 8)
            if pointer and not memory.load(pointer, 4):
                free(runtime, pointer)
                free(runtime, memory.load(locale + 0x128 + index * 8, 8))
        if memory.load(cursor - 24, 8):
            pointer = memory.load(cursor - 8, 8)
            if pointer and not memory.load(pointer, 4):
                free(runtime, pointer)
    free(runtime, locale)


def assign_locale(runtime, thread, value):
    memory, base = runtime.memory, runtime.image_base
    previous = memory.load(thread + 0x90, 8)
    if previous:
        locale_reference(runtime, previous, -1)
        previous = memory.load(thread + 0x90, 8)
        if previous != memory.load(base + 0x6D8F120, 8) and previous != base + 0x6744A10:
            if not memory.load(previous + 16, 4):
                free_locale(runtime, previous)
    memory.store(thread + 0x90, value, 8, source='3EA0D34.thread_locale_assign')
    if value:
        locale_reference(runtime, value, 1)


def initialize(runtime, thread):
    memory, base = runtime.memory, runtime.image_base
    for offset, value, width in ((0x28, 1, 4), (0, base + 0x45BCD00, 8),
            (0x3A8, 1, 4), (0x88, base + 0x67444D0, 8), (0xBC, 67, 2),
            (0x1C2, 67, 2), (0x3A0, 0, 8)):
        memory.store(thread + offset, value, width, source='3EA0D54.thread_initial_field')
    _critical(runtime, 5, True)
    _change(runtime, memory.load(thread + 0x88, 8), 1)
    _critical(runtime, 5, False)
    _critical(runtime, 4, True)
    assign_locale(runtime, thread, memory.load(base + 0x6D8F120, 8))
    _critical(runtime, 4, False)


def create(runtime):
    memory, base = runtime.memory, runtime.image_base
    error = _api(runtime, 'GetLastError')
    identifier = memory.load(base + 0x6744470, 4)
    if not _api(runtime, 'FlsSetValue', identifier, _MASK64):
        _api(runtime, 'SetLastError', error)
        return 0
    pointer = calloc(runtime, 1, 0x3C8)
    identifier = memory.load(base + 0x6744470, 4)
    if not pointer:
        _api(runtime, 'FlsSetValue', identifier, 0)
        free(runtime, 0)
        _api(runtime, 'SetLastError', error)
        return 0
    if not _api(runtime, 'FlsSetValue', identifier, pointer):
        _api(runtime, 'FlsSetValue', memory.load(base + 0x6744470, 4), 0)
        free(runtime, pointer)
        result = 0
    else:
        initialize(runtime, pointer)
        free(runtime, 0)
        result = pointer
    _api(runtime, 'SetLastError', error)
    return result


def destroy(runtime, thread):
    memory, base = runtime.memory, runtime.image_base
    actions = memory.load(thread, 8)
    if actions != base + 0x45BCD00:
        free(runtime, actions)
    for offset in (0x70, 0x58, 0x60, 0x68, 0x48, 0x50, 0x78, 0x80, 0x3C0):
        free(runtime, memory.load(thread + offset, 8))
    _critical(runtime, 5, True)
    codepage = memory.load(thread + 0x88, 8)
    if codepage and _change(runtime, codepage, -1) == 1 and codepage != base + 0x67444D0:
        free(runtime, codepage)
    _critical(runtime, 5, False)
    _critical(runtime, 4, True)
    assign_locale(runtime, thread, 0)
    _critical(runtime, 4, False)


def cleanup(runtime):
    memory, base = runtime.memory, runtime.image_base
    identifier = memory.load(base + 0x6744470, 4)
    pointer = 0 if identifier == 0xFFFFFFFF else _api(runtime, 'FlsGetValue', identifier)
    identifier = memory.load(base + 0x6744470, 4)
    if pointer:
        _api(runtime, 'FlsSetValue', identifier, 0)
        destroy(runtime, pointer)
        free(runtime, pointer)


def invoke(runtime, rva, values):
    entries = {0x3EA0F1C: (create, 0), 0x3EA0D54: (initialize, 1),
        0x3EA0E24: (destroy, 1), 0x3EA0C20: (cleanup, 0), 0x3EA0CEC: (assign_locale, 2),
        0x3EA0150: (calloc, 2), 0x3EA01D0: (free, 1),
        0x3EA5B28: (lambda r, p: locale_reference(r, p, 1), 1),
        0x3EA5BB4: (lambda r, p: locale_reference(r, p, -1), 1), 0x3EA5C5C: (free_locale, 1),
        0x3EA5DD4: (lambda r, p: time_reference(r, p, 1), 1),
        0x3EA5DFC: (lambda r, p: time_reference(r, p, -1), 1),
        0x3EA5E24: (free_time, 1), 0x3EA564C: (free_time_contents, 1), 0x3EA5A94: (free_array, 2),
        0x3EA5150: (lambda r, p: free_lconv_fields(r, p,
            (0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90)), 1),
        0x3EA5544: (lambda r, p: free_lconv_fields(r, p, (0, 8, 0x10, 0x58, 0x60)), 1),
        0x3EA1FE0: (lambda r, n: _critical(r, n, True), 1),
        0x3EA1FFC: (lambda r, n: _critical(r, n, False), 1)}
    function, count = entries.get(rva, (None, None))
    if function is None or len(values) != count:
        raise InputError('unsupported CRT thread entry or argument count')
    return function(runtime, *values)
