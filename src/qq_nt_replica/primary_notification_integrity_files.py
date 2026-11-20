from .errors import InputError
from .primary_logger import _String, _cstring
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker import _WideString
from .primary_worker_response import _frame
from .primary_worker_consumer import _invoke
from .primary_device_collector import _new_array, _delete_array
from .primary_notification_files import read_file, file_sha256
from .primary_notification_files import _IMPORTS as _FILE_IMPORTS
from .primary_notification_files import _free_buffer
from .primary_notification_map import insert, insert_variant
from .primary_notification_integrity_codec import decode_signature, public_key, verify_signature
from .primary_notification_integrity_parser import parse_manifest, field_string


_IMPORTS = {'GetModuleHandleA': 0x490FEF8, 'GetModuleFileNameW': 0x490FEF0,
            'PathRemoveFileSpecW': 0x4910AE8, 'WideCharToMultiByte': 0x4910460,
            'MultiByteToWideChar': 0x49101F0}
_IMPORTS.update(_FILE_IMPORTS)
_IMPORTS.update({'SHA256_Init': 0x490FA40, 'SHA256_Update': 0x490FA48, 'SHA256_Final': 0x490FA38})
_FIELDS = {0x35AA260: (13,), 0x35B3FE0: (10, 11, 12, 0)}


def _observe(runtime, name, arguments):
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
        raise PrimarySemanticUnavailable('manifest current import is not bound: ' + name)
    observer = getattr(runtime, 'notification_environment_observations', None)
    if observer is None:
        observer = runtime.worker_observations
    if observer is None:
        raise UnknownMemory('missing manifest module/file raw observation: ' + name)
    method = getattr(observer, 'take_integrity', observer.take)
    result, effects = method(runtime, name, arguments)
    if type(result) is not int or not 0 <= result < 1 << 64:
        raise InputError('manifest API requires its observed unsigned scalar')
    return result, effects


def _raw(runtime, address, raw, size):
    if not isinstance(raw, bytes) or len(raw) != size:
        raise InputError('manifest path requires its complete observed buffer image')
    runtime.memory.write(address, raw, source='notification_integrity.raw_path_API_output')


def _wide_cstring(runtime, address):
    for index in range(260):
        if runtime.memory.load(address + 2 * index, 2) == 0:
            return runtime.memory.read(address, 2 * index)
    raise PrimaryProgramLimit('manifest path has no known terminator in its source capacity')


def _convert(runtime, value, *, wide):
    name = 'WideCharToMultiByte' if wide else 'MultiByteToWideChar'
    raw = value + (b'\0\0' if wide else b'\0')
    args = (0, 0, raw, -1, False, 0) + ((0, 0) if wide else ())
    count, output = _observe(runtime, name, args)
    if output not in (b'', None):
        raise InputError('manifest conversion size query has no output buffer')
    count &= 0xFFFFFFFF
    if count == 0 or count & 0x80000000:
        return b''
    size = count if wide else count * 2 + 2
    if size > 1 << 20:
        raise PrimaryProgramLimit('manifest conversion exceeds its source array domain')
    storage = _new_array(runtime, size)
    try:
        runtime.memory.write(storage, bytes(size), source='notification_integrity.zero_conversion_array')
        args = (0, 0, raw, -1, True, count) + ((0, 0) if wide else ())
        ignored, output = _observe(runtime, name, args)
        if not isinstance(output, bytes) or len(output) > count * (1 if wide else 2):
            raise InputError('manifest conversion output exceeds its source array')
        runtime.memory.write(storage, output, source='notification_integrity.raw_conversion_output')
        runtime.memory.store(storage + (count - 1) * (1 if wide else 2), 0, 1 if wide else 2,
                             source='notification_integrity.conversion_terminator')
        return _cstring(runtime, storage) if wide else runtime.memory.read(storage, (count - 1) * 2)
    finally:
        _delete_array(runtime, storage)


def _put(runtime, mapping, key, value, *, variant=0x2E06D10):
    frame, ignored = _frame(runtime, 0x78, 'notification_integrity.map_entry_frame')
    first = _String.construct(runtime, key)
    second = _String.construct(runtime, value) if variant == 0x35BDB80 else None
    try:
        first.write_to(frame + 0x10)
        if second is None:
            if len(value) > 64:
                raise InputError('manifest literal map value leaves its source domain')
            runtime.memory.write(frame + 0x30, value + b'\0', source='notification_integrity.map_literal_value')
        else:
            second.write_to(frame + 0x30)
        if variant == 0x2E06D10:
            insert(runtime, mapping, frame, frame + 0x10, frame + 0x10, frame + 0x30)
        else:
            insert_variant(runtime, variant, mapping, frame, frame + 0x10, frame + 0x10, frame + 0x30)
        first = _String.read(runtime, frame + 0x10)
    finally:
        if second is not None:
            second.destroy()
        first.destroy()
        runtime.memory.unmap(frame)


def _key(runtime):
    memory, base = runtime.memory, runtime.image_base
    guard = memory.load(base + 0x6D88EE0, 4)
    raw, ignored, ignored_exponent = public_key()
    if not guard & 1:
        memory.store(base + 0x6D88EE0, guard | 1, 4, source='35B12F5.integrity_key_guard')
        memory.write(base + 0x6D88EC8, bytes(24), source='35B12FB.integrity_key_zero_vector')
        pointer = runtime._operator_new(len(raw))
        memory.store(base + 0x6D88EC8, pointer, 8, source='35B1317.integrity_key_begin')
        memory.store(base + 0x6D88ED8, pointer + len(raw), 8, source='35B1328.integrity_key_capacity')
        memory.write(pointer, raw, source='35B133F.integrity_key_copy')
        memory.store(base + 0x6D88ED0, pointer + len(raw), 8, source='35B1344.integrity_key_end')
        _invoke(runtime, 0x3E680B4, base + 0x35BDB60)
    pointer = memory.load(base + 0x6D88EC8, 8)
    if (not pointer or memory.load(base + 0x6D88ED0, 8) != pointer + len(raw) or
            memory.load(base + 0x6D88ED8, 8) != pointer + len(raw) or memory.read(pointer, len(raw)) != raw):
        raise PrimarySemanticUnavailable('manifest key guard/vector is incomplete or differs from its source')


def _filename(runtime, directory, name, header):
    raw = directory + b'\\\0' + _convert(runtime, name, wide=False)
    value = _WideString(runtime, address=header)
    value.assign(raw)
    return value


def _narrow_path(runtime, value):
    return _convert(runtime, value.value(), wide=True)


def produce(runtime, rva, mapping):
    if rva not in _FIELDS or type(mapping) is not int or not 0 < mapping < 1 << 64:
        raise InputError('manifest producer requires its exact entry and map pointer')
    memory, base = runtime.memory, runtime.image_base
    if getattr(runtime, 'notification_integrity_initializer_state', None) != (base, 'complete'):
        raise UnknownMemory('manifest producer requires completed normal static initialization')
    observer = getattr(runtime, 'notification_environment_observations', None)
    begin = getattr(observer, 'begin_integrity', None)
    end = getattr(observer, 'end_integrity', None)
    frame, ignored = _frame(runtime, 0x728 if rva == 0x35AA260 else 0x6D8, f'{rva:X}.manifest_frame')
    active = False
    try:
        if begin is not None:
            begin(runtime, rva)
            active = True
        fields = [_String.read(runtime, base + 0x6D88D78 + index * 24).value() for index in _FIELDS[rva]]
        module = base
        failure_key = fields[0] if rva == 0x35AA260 else b'SRSVFW'
        if rva == 0x35AA260:
            module, raw = _observe(runtime, 'GetModuleHandleA', (b'QQNT.dll\0',))
            if raw not in (None, b''):
                raise InputError('manifest module lookup has no output buffer')
            if not module:
                _put(runtime, mapping, failure_key, b'-1', variant=0x35BD530)
                return 0
        memory.write(frame + 0x20, bytes(520), source='notification_integrity.zero_module_path')
        length, raw = _observe(runtime, 'GetModuleFileNameW', (module, 260))
        _raw(runtime, frame + 0x20, raw, 520)
        if not 1 <= length & 0xFFFFFFFF <= 259:
            _put(runtime, mapping, failure_key, b'-2' if rva == 0x35AA260 else b'-1', variant=0x35BD530)
            return 0
        success, raw = _observe(runtime, 'PathRemoveFileSpecW', (memory.read(frame + 0x20, 520),))
        _raw(runtime, frame + 0x20, raw, 520)
        if not success & 0xFFFFFFFF:
            _put(runtime, mapping, failure_key, b'-3', variant=0x35BD530)
            return 0
        directory = _wide_cstring(runtime, frame + 0x20)
        manifest = _String.read(runtime, base + (0x6D88E20 if rva == 0x35AA260 else 0x6D88E38)).value()
        memory.write(frame + 0x240, bytes(24), source='notification_integrity.initial_manifest_path')
        path = _filename(runtime, directory, manifest, frame + 0x240)
        try:
            pointer = path.get(16, 8) if path.get(0, 1) & 1 else frame + 0x242
            memory.write(frame + 0x260, bytes(24), source='notification_integrity.initial_manifest_content')
            try:
                read = read_file(runtime, pointer, frame + 0x260)
                if not read:
                    _put(runtime, mapping, _narrow_path(runtime, path), b'-1')
                    return 0
                content = _String.read(runtime, frame + 0x260).value()
                accepted, root = parse_manifest(content)
                if not accepted:
                    _put(runtime, mapping, _narrow_path(runtime, path), b'-2')
                    return 0
            finally:
                _String.read(runtime, frame + 0x260).destroy()
        finally:
            path.destroy()
        for field in fields:
            encoded = field_string(root, field)
            if not encoded:
                _put(runtime, mapping, field, b'-3')
                return 0
            memory.write(frame + 0x240, bytes(24), source='notification_integrity.initial_target_path')
            target = _filename(runtime, directory, field, frame + 0x240)
            try:
                _key(runtime)
                signature = decode_signature(encoded)
                if signature is None:
                    _put(runtime, mapping, _narrow_path(runtime, target), b'0')
                    continue
                memory.write(frame + 0x280, bytes(24), source='notification_integrity.initial_file_digest')
                try:
                    file_sha256(runtime, frame + 0x280, frame + 0x240)
                    digest = _String.read(runtime, frame + 0x280).value()
                    if not digest:
                        _put(runtime, mapping, _narrow_path(runtime, target), b'0')
                        continue
                    verified = verify_signature(signature, digest)
                    if verified:
                        _put(runtime, mapping, field, b'1', variant=0x35BD530)
                    else:
                        _put(runtime, mapping, _narrow_path(runtime, target), b'0')
                    _put(runtime, mapping, field + b'@h', digest, variant=0x35BDB80)
                finally:
                    digest_string = _String.read(runtime, frame + 0x280)
                    if digest_string.get(0, 1) & 1:
                        _free_buffer(runtime, digest_string.get(16, 8))
            finally:
                target.destroy()
        return 1
    finally:
        try:
            if active and end is not None:
                end(runtime, rva)
        finally:
            memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva == 0x35BDB60 and not values:
        pointer = runtime.memory.load(runtime.image_base + 0x6D88EC8, 8)
        if pointer:
            runtime.memory.store(runtime.image_base + 0x6D88ED0, pointer, 8,
                                 source='35BDB6C.integrity_key_vector_end')
            runtime._free_allocation(pointer)
        return None
    if rva in _FIELDS and len(values) == 1:
        return produce(runtime, rva, values[0])
    raise InputError('manifest producer/callback requires its exact source argument count')
