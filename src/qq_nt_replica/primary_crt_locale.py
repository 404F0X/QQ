import hashlib
from pathlib import Path

from .errors import InputError
from .primary_crt_thread import _change, _critical, calloc, free, free_locale, locale_reference
from .primary_vm import PrimarySemanticUnavailable


_TABLE_SHA256 = '911cebc0ead09ffbf31c75f615da1925a004bd5e3b25d9f088f2cb448baba44b'


def _table():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/crt-c-locale-mb.bin').read_bytes()
    if len(raw) != 0x201 or hashlib.sha256(raw).hexdigest() != _TABLE_SHA256:
        raise InputError('fixed C locale multibyte table identity mismatch')
    return raw


def state_prefix(runtime, output=None):
    memory, base = runtime.memory, runtime.image_base
    if memory.load(base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable('C locale producer requires unsupported current-FLS locale refresh when 6D8E630 is nonzero')
    pair = memory.read(base + 0x6744B68, 16)
    if output is not None:
        memory.store(output + 0x18, 0, 1, source='3E759E4.locale_state_not_owned')
        memory.write(output + 8, pair, source='3E759E4.static_locale_pair')
    memory.store(base + 0x6D8F0F0, 0, 4, source='3EA2678.clear_codepage_override')
    return tuple(int.from_bytes(pair[index:index + 8], 'little') for index in (0, 8))


def create_c_locale(runtime, category=0, name=b'C'):
    if category != 0 or name not in (b'C', 'C'):
        raise PrimarySemanticUnavailable('owned C locale producer supports only category 0 and the C name')
    memory, base = runtime.memory, runtime.image_base
    if memory.load(base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable('C locale producer requires unsupported current-FLS locale refresh when 6D8E630 is nonzero')
    table = _table()
    initial = memory.read(base + 0x6744A10, 0x140) + memory.read(base + 0x6744B50, 0x18)
    header = calloc(runtime, 1, 16)
    locale = calloc(runtime, 1, 0x158)
    mb = calloc(runtime, 1, 0x228)
    memory.write(locale, initial, source='3E836E0.static_C_locale_copy')
    memory.store(locale + 0x10, 0, 4, source='3E836E0.clear_copied_reference_count')
    locale_reference(runtime, locale, 1)
    scratch = runtime._allocate(0x6A6, False)
    memory.store(scratch, 1, 4, source='3E8322C.scratch_reference')
    memory.write(scratch + 4, b'C\x00\x00\x00', source='3E8322C.C_all_category_name')
    free(runtime, scratch)
    for offset in (0x20, 0x28, 0x30, 0x38):
        memory.store(locale + offset, 0, 8, source='3E8322C.clear_all_category_owned_name')
    if memory.load(locale + 0xC, 4):
        raise PrimarySemanticUnavailable('static C locale has an unsupported nonzero codepage')
    state_prefix(runtime)
    memory.write(mb + 0x18, table, source='3EA26F8.static_C_mb_tables')
    memory.store(mb, 1, 4, source='3E82688.owned_mb_reference')
    memory.store(header, locale, 8, source='3E82688.owned_locale_pointer')
    memory.store(header + 8, mb, 8, source='3E82688.owned_mb_pointer')
    free(runtime, 0)
    free(runtime, 0)
    free(runtime, 0)
    return header


def free_owned_locale(runtime, header):
    if not header:
        return
    memory, base = runtime.memory, runtime.image_base
    _critical(runtime, 5, True)
    mb = memory.load(header + 8, 8)
    if mb and _change(runtime, mb, -1) == 1 and mb != base + 0x67444D0:
        free(runtime, mb)
    _critical(runtime, 5, False)
    locale = memory.load(header, 8)
    if locale:
        _critical(runtime, 4, True)
        locale_reference(runtime, locale, -1)
        if not memory.load(locale + 0x10, 4) and locale != base + 0x6744A10:
            free_locale(runtime, locale)
        _critical(runtime, 4, False)
    free(runtime, header)


def release_locale(runtime, header):
    if header != runtime.memory.load(runtime.image_base + 0x674DDD0, 8):
        free_owned_locale(runtime, header)


def invoke(runtime, rva, values):
    if rva == 0x3E82540 and len(values) == 1:
        return free_owned_locale(runtime, values[0])
    if rva in (0x3E824C8, 0x3E82688) and len(values) == 2:
        category, pointer = values
        expected = b'C\x00' if rva == 0x3E824C8 else b'C\x00\x00\x00'
        if not pointer or runtime.memory.read(pointer, len(expected)) != expected:
            raise PrimarySemanticUnavailable('owned locale entry supports only the terminated C name')
        return create_c_locale(runtime, category)
    raise InputError('unsupported owned C locale entry or argument count')
