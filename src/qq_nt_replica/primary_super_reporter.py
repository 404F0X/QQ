from dataclasses import dataclass
import base64
import binascii
import json

from .errors import InputError
from .primary_logger import _String, _cstring, feature, log
from .primary_provider_init import _mutex
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _invoke
from .primary_worker_response import _frame


_U64 = (1 << 64) - 1
_KEY = b'o3sec_super_reporter_seq_content'
_FILE = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\channel\\src\\reporter\\super_reporter_cache.cpp'
_DISPATCH_FILE = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\channel\\src\\reporter\\super_reporter.cpp'
_JOINT_INITIAL = (
    (0x6D86400, bytes.fromhex('0103396e6d3c3d3e383137363500000103696c6f7b3775283a6773677f63663d5e687e607a7d2458776a5462706e7077000001037662766e7277000001036f676f67666e665a7662766e7277000001037a6c7f60556c706265707066000001037f6f79656b775066686e66000001036d787e527e6a7e6e7277000001037a636c62527c6a706e7077000001036d657c52686a7a64637700000103796f536279666466726c6b6d000001036a686e7e6d566c6272606777000001036a657b75526a6a746461770000010360697c7478784a6a7a6c71417c74786168000001037e60656a746262660000')),
    (0x6D864F0, bytes.fromhex('01030303030303030303030303030303030303030303030303030303393d3d3939050509090d0d0909050519191d1d1919050509090d464446484e4c4e484644572c0000')),
)
_WORKER_INITIAL = bytes.fromhex('01162c7b7829282b2d24222320000001167c797a6e22603d2f7266726a7673284b7d6b756f68314d627f4177657b6562000001166377637b6762000001167a727a72737b734f6377637b6762000001166f796a754079657770656573000001166a7a6c707e6245737d7b7300000116786d6b476b7f6b7b6762000001166f76797747697f657b656200000116787069477d7f6f717662000001166c7a46776c73717367797e78000001167f7d7b6b7843797767757262000001167f706e60477f7f6171746200000116757c69616d6d5f7f6f79645469616d747d000001166b75707f617777730000011616161616161616161616161616161616161616161616161616162c28282c2c10101c1c18181c1c10100c0c08080c0c10101c1c185351535d5b595b5d535142390000')
_REGISTRY_INITIAL = bytes.fromhex('010d376063323330363f39383b0000010d67626175397b2634697d69716d68335066706e74732a5679645a6c7e607e790000010d786c78607c790000010d6169616968606854786c78607c790000010d7462716e5b627e6c6b7e7e680000010d7161776b65795e686660680000010d6376705c706470607c790000010d746d626c5c72647e607e790000010d636b725c6664746a6d790000010d77615d6c77686a687c6265630000010d646660706358626c7c6e69790000010d646b757b5c64647a6a6f790000010d6e67727a7676446474627f4f727a766f660000010d706e6b647a6c6c680000')
_JOINT_COMMANDS = (
    b'trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey',
    b'trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess',
    b'trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Access',
    b'trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish',
    b'trpc.o3.report.Report.SsoReport',
)


@dataclass(frozen=True)
class SuperReporterSleepBoundary:
    owner: int
    nanoseconds: int


def install_image(memory, base):
    tables = {0x436ECF8: (0x142A0, 0x2DF47D0, 0x2DF47E0, 0x28F0, 0x1FE0, 0x2DF4800),
              0x433C478: (0x2DE0B40, 0x2DE0B80, 0x2DE0BA0, 0xB95880, 0xBED000, 0x2DE0C10)}
    images = [(0x677C0C8, bytes(16)), (0x6D85F50, bytes(16)),
              (0x677C258, bytes(8)), (0x677CCC0, bytes(16)), (0x46BAA2F, _KEY + b'\0'),
              (0x6D86400, bytes(0x180)), (0x6D85448, bytes(len(_WORKER_INITIAL))),
              (0x6D88320, bytes(272)), (0x6D85574, bytes(0x9D4))]
    images.extend((rva, b''.join((base + item).to_bytes(8, 'little') for item in entries))
                  for rva, entries in tables.items())
    for rva, data in images:
        cursor, end = base + rva, base + rva + len(data)
        while cursor < end:
            region = next((item for item in memory._regions
                           if item.address <= cursor < item.address + len(item.data)), None)
            if region is not None:
                cursor = min(end, region.address + len(region.data))
                continue
            boundary = min((item.address for item in memory._regions if item.address > cursor), default=end)
            size = min(end, boundary) - cursor
            offset = cursor - base - rva
            memory.map(cursor, bytearray(data[offset:offset + size]),
                       name='fixed super reporter source image', initialized=True)
            cursor += size


def initialize_worker_module(runtime):
    install_image(runtime.memory, runtime.image_base)
    runtime.memory.write(runtime.image_base + 0x6D85448, _WORKER_INITIAL,
                         source='2DE0E00.super_reporter_worker_module_initializer')
    runtime.events.append(('super_reporter.worker_module_initialized',))


def initialize_registry_module(runtime):
    install_image(runtime.memory, runtime.image_base)
    runtime.memory.write(runtime.image_base + 0x6D88320, _REGISTRY_INITIAL,
                         source='3591650.super_reporter_registry_module_initializer')
    _invoke(runtime, 0x75B000, runtime.image_base + 0x6D88408)
    result = _invoke(runtime, 0x3E680B4, runtime.image_base + 0x3588A40)
    runtime.events.append(('super_reporter.registry_module_initialized',))
    return result


def initialize_joint_module(runtime):
    memory, base = runtime.memory, runtime.image_base
    install_image(memory, base)
    for rva, data in _JOINT_INITIAL:
        memory.write(base + rva, data, source='2DF48F0.super_reporter_joint_module_initializer')
    _String.construct(runtime, b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/').write_to(
        base + 0x6D86540)
    _invoke(runtime, 0x3E680B4, base + 0x2DF2A70)
    frame, _ = _frame(runtime, 144, '2DF48F0.joint_command_initialization_frame')
    for index, value in enumerate(_JOINT_COMMANDS):
        _String.construct(runtime, value).write_to(frame + index * 24)
    memory.store(frame + 120, frame, 8, source='2DF5308.joint_command_range')
    memory.store(frame + 128, 5, 8, source='2DF530C.joint_command_count')
    _invoke(runtime, 0x1224BDC, base + 0x6D86558, frame + 120)
    for index in range(4, -1, -1):
        _String.read(runtime, frame + index * 24).destroy()
    result = _invoke(runtime, 0x3E680B4, base + 0x2DF2A90)
    memory.unmap(frame)
    runtime.events.append(('super_reporter.joint_module_initialized',))
    return result


def _once(runtime, flag, callback):
    memory, base = runtime.memory, runtime.image_base
    from .primary_module_sync import backend, MODEL_NATIVE, source_once, shared_acquire, shared_release, shared_wake
    if backend(runtime) == MODEL_NATIVE:
        if memory.load(flag, 8) == _U64:
            return
        import sys
        caller = sys._getframe(1)
        bindings = {
            initialize.__code__: (base + 0x677C0C8, 0x1BF37D0, 0x1BF3780),
            _registry.__code__: (base + 0x6D85F50, 0x1BF37D0, 0x2DE0B00),
            _joint_body.__code__: (base + 0x677CCC0, 0x1BF37D0, 0x1C026E0),
            submit_joint.__code__: (base + 0x677C258, 0x1C02430, caller.f_locals.get('source')),
            start.__code__: (caller.f_locals.get('owner'), 0x2DE0D60, caller.f_locals.get('owner')),
        }
        binding = bindings.get(caller.f_code)
        if caller.f_code is invoke.__code__ and caller.f_locals.get('rva') == 0x2DF4800:
            binding = (base + 0x677C0C8, 0x1BF37D0, 0x1BF3780)
        if binding is None or binding[0] != flag or type(binding[2]) is not int:
            raise InputError('super reporter once source callsite/flag binding mismatch')
        _, entry, target = binding
        # These are guest closure cells, never native addresses or origin receipts.
        size = 24 if entry == 0x1BF37D0 else 16
        closure, _ = _frame(runtime, size, 'super_reporter.source_once_closure')
        memory.store(closure, closure + 8, 8, source='super_reporter.once_closure_outer')
        if entry == 0x1BF37D0:
            memory.store(closure + 8, closure + 16, 8, source='super_reporter.once_closure_inner')
            memory.store(closure + 16, base + target, 8, source='super_reporter.once_fixed_target')
        else:
            memory.store(closure + 8, target, 8, source='super_reporter.once_captured_argument')
        def source_callback():
            resolved = memory.load(memory.load(closure, 8), 8)
            if entry == 0x1BF37D0:
                resolved = memory.load(resolved, 8)
                if resolved != base + target:
                    raise InputError('super reporter fixed once thunk target changed')
            elif resolved != target:
                raise InputError('super reporter once captured argument changed')
            raise PrimarySemanticUnavailable('super reporter source callback body unavailable: ' + hex(
                target if entry == 0x1BF37D0 else entry))
        try:
            return source_once(runtime, flag, source_callback)
        finally:
            memory.unmap(closure)
    if memory.load(flag, 8) == _U64:
        return
    shared_acquire(runtime)
    _mutex(runtime, base + 0x674D4D0, True)
    state = memory.load(flag, 8)
    if state == 1:
        runtime.events.append(('super_reporter.once_wait', flag))
        raise PrimarySemanticUnavailable('super reporter once requires actual concurrent initialization completion')
    if state:
        shared_release(runtime)
        _mutex(runtime, base + 0x674D4D0, False)
        return
    memory.store(flag, 1, 8, source='75B0E0.super_reporter_once_claim')
    shared_release(runtime)
    _mutex(runtime, base + 0x674D4D0, False)
    callback()
    shared_acquire(runtime)
    _mutex(runtime, base + 0x674D4D0, True)
    memory.store(flag, _U64, 8, source='75B0E0.super_reporter_once_completed')
    shared_release(runtime)
    _mutex(runtime, base + 0x674D4D0, False)
    shared_wake(runtime)
    runtime.events.append(('super_reporter.once_notify', base + 0x674D4D8, flag))


def construct(runtime):
    install_image(runtime.memory, runtime.image_base)
    pointer = runtime._operator_new(64)
    runtime.memory.write(pointer, bytes(64), source='1BF3793.super_reporter_owner_zero')
    runtime.memory.store(pointer + 16, 60, 4, source='1BF37A7.super_reporter_interval')
    runtime.memory.store(pointer + 56, 0x3F800000, 4, source='1BF37AE.super_reporter_load_factor')
    runtime.memory.store(runtime.image_base + 0x677C0D0, pointer, 8,
                         source='1BF37B5.super_reporter_owner_publish')
    return pointer


def _start(runtime, owner):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x58, '2DE0D60.super_reporter_thread_frame')
    memory.store(frame + 0x28, owner, 8, source='2DE0D7C.super_reporter_thread_argument')
    memory.store(frame + 0x30, base + 0x2DE09F0, 8, source='2DE0D87.super_reporter_thread_function')
    _invoke(runtime, 0xBD4FA0, frame + 0x38, frame + 0x30, frame + 0x28)
    if memory.load(owner + 8, 8):
        raise PrimarySemanticUnavailable('2DE0DCC replacing a joinable super reporter thread requires termination')
    handle = memory.load(frame + 0x38, 8)
    memory.store(owner + 8, handle, 8, source='2DE0DB0.super_reporter_thread_handle_move')
    memory.store(frame + 0x38, 0, 8, source='2DE0DB3.super_reporter_thread_moved_from')
    runtime.events.append(('super_reporter.thread_pending', owner, handle, base + 0x2DE09F0))
    memory.unmap(frame)


def start(runtime, owner):
    _once(runtime, owner, lambda: _start(runtime, owner))
    return None


def initialize(runtime):
    memory, base = runtime.memory, runtime.image_base
    install_image(memory, base)
    _once(runtime, base + 0x677C0C8, lambda: _invoke(runtime, 0x1BF3780))
    owner = memory.load(base + 0x677C0D0, 8)
    if not owner:
        raise PrimarySemanticUnavailable('super reporter initialized once has no actual published owner')
    _invoke(runtime, 0x2DE0A90, owner)
    return owner


def construct_registry(runtime):
    pointer = runtime._operator_new(56)
    memory = runtime.memory
    memory.write(pointer, bytes(32), source='2DE0B11.super_reporter_registry_zero')
    memory.store(pointer + 8, pointer + 16, 8, source='2DE0B1C.super_reporter_registry_active_sentinel')
    memory.write(pointer + 40, bytes(16), source='2DE0B24.super_reporter_registry_pending_zero')
    memory.store(pointer + 32, pointer + 40, 8, source='2DE0B28.super_reporter_registry_pending_sentinel')
    memory.store(runtime.image_base + 0x6D85F58, pointer, 8,
                 source='2DE0B2C.super_reporter_registry_publish')
    return pointer


def _registry(runtime):
    install_image(runtime.memory, runtime.image_base)
    _once(runtime, runtime.image_base + 0x6D85F50, lambda: _invoke(runtime, 0x2DE0B00))
    pointer = runtime.memory.load(runtime.image_base + 0x6D85F58, 8)
    if not pointer:
        raise PrimarySemanticUnavailable('super reporter registry once has no actual published registry')
    return pointer


def safe(runtime, event):
    from .primary_feature_notifications import _logger
    memory, base = runtime.memory, runtime.image_base
    table = memory.load(event, 8)
    if table != base + 0x4149058 or memory.load(table + 16, 8) != base + 0x5C7470:
        raise PrimarySemanticUnavailable('joint reporter requires the actual sec-init event kind virtual')
    return int(feature(runtime, _logger(runtime), 18) == 1)


def _alphabet(runtime, encoded_rva=0x6D864F0):
    memory, base = runtime.memory, runtime.image_base
    pointer = base + encoded_rva
    value = _String.read(runtime, base + 0x6D86540).clone()
    if value.value():
        if value.value() != b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/':
            raise PrimarySemanticUnavailable('super reporter current Base64 alphabet is unsupported')
        return value
    value.destroy()
    if memory.load(pointer, 1) & 1:
        for index in range(64):
            memory.store(pointer + index + 2,
                         memory.load(pointer + index + 2, 1) ^ (index + 1) ^ memory.load(pointer + 1, 1) ^ 64,
                         1, source='super_reporter.alphabet_decode')
        memory.store(pointer + 66, 0, 1, source='super_reporter.alphabet_terminator')
        memory.store(pointer + 67, 0, 1, source='super_reporter.alphabet_terminator')
        memory.store(pointer, 0, 1, source='super_reporter.alphabet_decoded')
    alphabet = memory.read(pointer + 2, 64)
    if alphabet != b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/':
        raise PrimarySemanticUnavailable('super reporter requires its actual Base64 module initializer')
    return _String.construct(runtime, alphabet)


def wrap(runtime, output, event):
    from .primary_caller_diagnostics import _Strings
    from .primary_request_submit import _clone_row, _destroy_row
    from .primary_worker_loop import _initialize
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x100, '2DF37D0.joint_packet_frame')
    packet, row, serialized = frame, frame + 96, frame + 160
    memory.write(packet, bytes(89), source='2DF37D0.joint_packet_fields')
    memory.store(packet, base + 0x3FD73B8, 8, source='2DF3807.joint_packet_vtable')
    memory.store(packet + 56, base + 0x3FD7428, 8, source='2DF3821.joint_nested_vtable')
    memory.store(packet + 88, 1, 1, source='2DF3831.joint_packet_flag')
    if safe(runtime, event):
        _initialize(runtime, 0)
        current = _String.read(runtime, base + 0x67516B8).clone()
        populated = bool(current.value())
        current.destroy()
        if populated:
            _initialize(runtime, 0)
            _String.read(runtime, base + 0x67516B8).clone().write_to(packet + 64)
    if memory.load(event, 8) != base + 0x4149058:
        raise PrimarySemanticUnavailable('joint wrapper requires its actual sec-init derived event')
    _invoke(runtime, 0x1C018C0, event, packet + 8)
    memory.write(row, bytes(56), source='2DF390A.joint_row_fields')
    memory.store(row, base + 0x3FD7498, 8, source='2DF3903.joint_row_vtable')
    columns = _Strings(runtime)
    for offset in (0x40, 0xA0, 0x70, 0x58):
        _initialize(runtime, 0)
        columns.push(_String.read(runtime, base + 0x67516B0 + offset), clone=True)
    columns.push(_String.read(runtime, event + 8), clone=True)
    _invoke(runtime, 0xBCD880, event, row + 32)
    for offset, value in ((8, columns.begin), (16, columns.begin + columns.count * 24),
                          (24, columns.begin + columns.capacity * 24)):
        memory.store(row + offset, value, 8, source='2DF37D0.joint_row_columns')
    rows = runtime._operator_new(56)
    _clone_row(runtime, rows, row)
    for offset, value in ((32, rows), (40, rows + 56), (48, rows + 56)):
        memory.store(packet + offset, value, 8, source='2DF37D0.joint_packet_row_owner')
    _invoke(runtime, 0xBE1730, packet, serialized)
    encoded = _String(runtime, bytes(24), bytes([1]) * 24)
    memory.write(output, bytes(24), source='2DF37D0.joint_base64_empty')
    alphabet = _alphabet(runtime)
    for byte in base64.b64encode(_String.read(runtime, serialized).value()):
        _append(encoded, bytes([byte]))
    alphabet.destroy()
    encoded.write_to(output)
    runtime.events.append(('super_reporter.wrapped', event, _String.read(runtime, serialized).value(), encoded.value()))
    _String.read(runtime, serialized).destroy()
    _String.read(runtime, row + 32).destroy()
    columns.destroy()
    _destroy_row(runtime, rows)
    runtime._free_allocation(rows)
    _String.read(runtime, packet + 8).destroy()
    _String.read(runtime, packet + 64).destroy()
    memory.unmap(frame)
    return output


def _read(runtime, key, output, temporary):
    _String.construct(runtime, key).write_to(temporary)
    _invoke(runtime, 0x1BE5B70, output, temporary)
    _String.read(runtime, temporary).destroy()


def _write(runtime, key, value, temporary):
    _String.construct(runtime, key).write_to(temporary)
    _invoke(runtime, 0x1BE5B30, temporary, value)
    _String.read(runtime, temporary).destroy()


def sequence(runtime, registry, output):
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    previous = memory.load(registry, 8)
    if not previous:
        frame, _ = _frame(runtime, 48, '3589150.sequence_configuration_frame')
        _read(runtime, _KEY, frame + 24, frame)
        tokens = _String.read(runtime, frame + 24).value().split(b'|')
        for token in tokens:
            if token:
                if not token.isdigit() or int(token) >= 1 << 63:
                    raise PrimarySemanticUnavailable('super reporter sequence requires its bounded decimal stream parser')
                previous = max(previous, int(token))
        _String.read(runtime, frame + 24).destroy()
        memory.unmap(frame)
    value = (previous + 1) & _U64
    memory.store(registry, value, 8, source='358930C.super_reporter_next_sequence')
    _String.construct(runtime, str(value).encode('ascii')).write_to(output)
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)
    return output


def append_sequence(runtime, selected):
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    frame, _ = _frame(runtime, 72, '3589490.sequence_append_frame')
    _read(runtime, _KEY, frame + 24, frame)
    suffix = _String.read(runtime, selected).clone()
    _append(suffix, b'|')
    value = _String.read(runtime, frame + 24)
    _append(value, suffix.value())
    value.write_to(frame + 24)
    suffix.destroy()
    _write(runtime, _KEY, frame + 24, frame + 48)
    value.destroy()
    memory.unmap(frame)
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)


def remove_sequence(runtime, registry, selected):
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    frame, _ = _frame(runtime, 72, '358A210.sequence_remove_frame')
    _read(runtime, _KEY, frame + 24, frame)
    configured = _String.read(runtime, frame + 24)
    raw = configured.value()
    if raw:
        tokens = raw.split(b'|')
        if tokens[-1] == b'':
            tokens.pop()
        key = _String.read(runtime, selected).value()
        retained = b''.join(token + b'|' for token in tokens if token != key)
        configured.destroy()
        configured = _String.construct(runtime, retained)
        configured.write_to(frame + 24)
        _write(runtime, _KEY, frame + 24, frame + 48)
    configured.destroy()
    memory.unmap(frame)
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)


def _quote(raw):
    escapes = {8: b'\\b', 9: b'\\t', 10: b'\\n', 12: b'\\f', 13: b'\\r', 34: b'\\"', 92: b'\\\\'}
    return b'"' + b''.join(escapes.get(byte, ('\\u%04x' % byte).encode('ascii') if byte < 32 else bytes([byte]))
                           for byte in raw.split(b'\0', 1)[0]) + b'"'


def persist(runtime, registry, data, level, safe_value, from_sign_cmd):
    memory, base = runtime.memory, runtime.image_base
    if level & 0xFFFFFFFF:
        raise PrimarySemanticUnavailable('super reporter persistence requires the source Low enum domain')
    frame, _ = _frame(runtime, 160, '3588A50.super_reporter_persist_frame')
    sequence(runtime, registry, frame)
    key = b'o3sec_super_reporter_' + _String.read(runtime, frame).value()
    _String.construct(runtime, key).write_to(frame + 24)
    append_sequence(runtime, frame)
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    _String.read(runtime, frame).clone().write_to(frame + 48)
    _String.read(runtime, data).clone().write_to(frame + 72)
    _String.read(runtime, from_sign_cmd).clone().write_to(frame + 96)
    raw = (b'{"seq":' + _quote(_String.read(runtime, frame + 48).value()) + b',"level":"Low","data":' +
           _quote(_String.read(runtime, frame + 72).value()) + b',"safe":' +
           (b'true' if safe_value & 255 else b'false') + b',"from_sign_cmd":' +
           _quote(_String.read(runtime, frame + 96).value()) + b'}')
    _String.construct(runtime, raw).write_to(frame + 120)
    _invoke(runtime, 0x1BE5B30, frame + 24, frame + 120)
    runtime.events.append(('super_reporter.persisted', _String.read(runtime, frame).value(), raw))
    _String.read(runtime, frame + 120).destroy()
    selected = _String.read(runtime, frame)
    pointer = selected.get(16, 8) if selected.get(0, 1) & 1 else frame + 1
    log(runtime, _FILE, 0x2A, b'super_repoter seq: %s saved', base + 0x48972C7, 2, pointer)
    for offset in (96, 72, 48):
        _String.read(runtime, frame + offset).destroy()
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)
    for offset in (24, 0):
        _String.read(runtime, frame + offset).destroy()
    memory.unmap(frame)


def dispatch(runtime, dispatcher, event, from_sign_cmd):
    from .primary_feature_notifications import _logger
    from .primary_worker_tasks import provider_task
    memory, base = runtime.memory, runtime.image_base
    if _hash_find(runtime, base + 0x6D86558, _String.read(runtime, from_sign_cmd).value()):
        return None
    enabled = int(feature(runtime, _logger(runtime), 42) == 1)
    log(runtime, _DISPATCH_FILE, 0x39, b'switch %d, status: %d', base + 0x48972C7, 2, 42, enabled)
    if not enabled:
        from .primary_worker_response import _image as _response_image, _owner
        _owner(runtime, _response_image())
        frame, _ = _frame(runtime, 72, '2DF2C10.disabled_joint_telemetry_frame')
        _String.construct(runtime, b'').write_to(frame)
        memory.write(frame + 24, bytes(48), source='2DF2FEF.disabled_joint_columns_zero')
        _String.read(runtime, from_sign_cmd).clone().write_to(frame + 24)
        _String.read(runtime, frame).clone().write_to(frame + 48)
        _invoke(runtime, 0x1BEFC10, base + 0x67519B8, event, frame + 24, 1, 10, 0)
        for offset in (48, 24, 0):
            _String.read(runtime, frame + offset).destroy()
        memory.unmap(frame)
        return None
    safe_value = safe(runtime, event)
    if memory.load(memory.load(event, 8) + 24, 8) != base + 0x63EC0:
        raise PrimarySemanticUnavailable('joint reporter level virtual is not bound')
    frame, _ = _frame(runtime, 64, '2DF2C10.joint_dispatch_frame')
    _invoke(runtime, 0x1C018C0, event, frame)
    identifier, name = _String.read(runtime, frame), _String.read(runtime, event + 8)
    id_pointer = identifier.get(16, 8) if identifier.get(0, 1) & 1 else frame + 1
    name_pointer = name.get(16, 8) if name.get(0, 1) & 1 else event + 9
    log(runtime, _DISPATCH_FILE, 0x41, b'super_reporter atta: %s, event: %s', base + 0x48972C7, 2,
        id_pointer, name_pointer)
    identifier.destroy()
    wrap(runtime, frame, event)
    persist(runtime, _registry(runtime), frame, 0, safe_value, from_sign_cmd)
    memory.store(frame + 32, base + 0x436ECF8, 8, source='2DF3457.super_reporter_functor_vtable')
    memory.store(frame + 56, frame + 32, 8, source='2DF345B.super_reporter_functor_active')
    _invoke(runtime, 0xBD0780, provider_task(runtime), frame + 24)
    _String.read(runtime, frame).destroy()
    memory.unmap(frame)


def construct_dispatcher(runtime, pointer=None):
    from .primary_feature_notifications import _logger
    if pointer is None:
        pointer = runtime._operator_new(1)
    if feature(runtime, _logger(runtime), 42) == 1:
        initialize(runtime)
    return pointer


def _publish_dispatcher(runtime):
    pointer = construct_dispatcher(runtime)
    runtime.memory.store(runtime.image_base + 0x677CCC8, pointer, 8,
                         source='1C0270D.joint_dispatcher_publish')
    return pointer


def _joint_body(runtime, source):
    from .primary_high_reliability import destroy_event
    memory, base = runtime.memory, runtime.image_base
    install_image(memory, base)

    frame, _ = _frame(runtime, 0x128, '1C02430.joint_event_frame')
    name = _String.construct(runtime, b'sec_init_super_reporter')
    name.clone().write_to(frame + 8)
    for offset in range(0x20, 0xC8, 24):
        memory.write(frame + offset, bytes(2), source='1C02430.joint_empty_string')
    memory.write(frame + 0xC8, bytes(24), source='1C02430.joint_empty_vector')
    memory.store(frame, base + 0x4149058, 8, source='1C02510.joint_event_vtable')
    memory.write(frame + 0xE0, bytes(24), source='1C0251B.joint_payload_empty')
    name.destroy()
    _String.read(runtime, source + 0xE0).clone().write_to(frame + 0xE0)
    _once(runtime, base + 0x677CCC0, lambda: _publish_dispatcher(runtime))
    memory.write(frame + 0xF8, bytes(2), source='1C025A5.joint_from_sign_cmd_empty')
    dispatch(runtime, memory.load(base + 0x677CCC8, 8), frame, frame + 0xF8)
    _String.read(runtime, frame + 0xF8).destroy()
    destroy_event(runtime, frame)
    memory.unmap(frame)


def submit_joint(runtime, source):
    install_image(runtime.memory, runtime.image_base)
    _once(runtime, runtime.image_base + 0x677C258, lambda: _joint_body(runtime, source))


def reset_pending(runtime, registry):
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    from .primary_request_transport import _Map
    pending = _Map(runtime, registry + 32, strings=True)
    for node in tuple(pending.nodes()):
        _erase_key(runtime, registry + 8, _String.read(runtime, node + 32).value())
    for node in reversed(tuple(pending.nodes())):
        _String.read(runtime, node + 32).destroy()
        runtime._free_allocation(node)
    memory.store(registry + 32, registry + 40, 8, source='358B49C.super_reporter_pending_sentinel')
    memory.write(registry + 40, bytes(16), source='358B4A0.super_reporter_pending_reset')
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)


def snapshot(runtime, registry, output):
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    frame, _ = _frame(runtime, 0x40, '358B4F0.super_reporter_configuration_frame')
    _String.construct(runtime, _KEY).write_to(frame)
    _invoke(runtime, 0x1BE5B70, frame + 24, frame)
    _String.read(runtime, frame).destroy()
    memory.write(output, bytes(32), source='358B57D.super_reporter_snapshot_zero')
    memory.store(output + 32, 0x3F800000, 4, source='358B58B.super_reporter_snapshot_load_factor')
    configured = _String.read(runtime, frame + 24)
    if configured.value():
        tokens = configured.value().split(b'|')
        if tokens[-1] == b'':
            tokens.pop()
        if len(tokens) > 4096 or any(not token or b'\0' in token for token in tokens):
            raise PrimarySemanticUnavailable('super reporter nonempty persisted snapshot requires its bounded sequence parser')
        for token in tokens:
            local, _ = _frame(runtime, 112, '358BE17.super_reporter_record_frame')
            _String.construct(runtime, token).write_to(local)
            key = b'o3sec_super_reporter_' + token
            _read(runtime, key, local + 24, local + 48)
            value = _String.read(runtime, local + 24).value()
            if value and not _has_key(runtime, registry + 8, token):
                parsed = _parse(value)
                _snapshot_insert(runtime, output, token, parsed)
                _mark_key(runtime, registry + 8, local)
            _String.read(runtime, local + 24).destroy()
            _String.read(runtime, local).destroy()
            memory.unmap(local)
    else:
        log(runtime, _FILE, 0x59, b'super_repoter disk IO error, key: %s', base + 0x48972C7, 2,
            base + 0x46BAA2F)
    configured.destroy()
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)
    memory.unmap(frame)
    return output


def run_empty_iteration(runtime, owner):
    memory, base = runtime.memory, runtime.image_base
    registry = _registry(runtime)
    _invoke(runtime, 0x358B3F0, registry)
    run_iteration(runtime, owner)
    seconds = memory.load(owner + 16, 4)
    if not seconds:
        raise PrimarySemanticUnavailable('super reporter zero interval repeats without a bounded sleep boundary')
    boundary = SuperReporterSleepBoundary(owner, seconds * 1000000000)
    runtime.events.append(('super_reporter.sleep_boundary', owner, boundary.nanoseconds, base + 0x760050))
    return boundary


def _has_key(runtime, tree, key):
    from .primary_request_transport import _Map
    return bool(_Map(runtime, tree, strings=True).find(key))


def _mark_key(runtime, tree, source):
    from .primary_request_transport import _Map
    selected = _Map(runtime, tree, strings=True)
    key = _String.read(runtime, source).value()
    current = selected.find(key)
    if current:
        return current
    node = runtime._operator_new(56)
    _String.read(runtime, source).clone().write_to(node + 32)
    return selected.insert_node(key, node)


def _erase_key(runtime, tree, key):
    from .primary_request_transport import _Map
    selected = _Map(runtime, tree, strings=True)
    node = selected.find(key)
    if node:
        selected.erase(node)
        _String.read(runtime, node + 32).destroy()
        runtime._free_allocation(node)


def erase_key(runtime, tree, source):
    key = _String.read(runtime, source).value()
    found = _has_key(runtime, tree, key)
    _erase_key(runtime, tree, key)
    return int(found)


def _parse(raw):
    try:
        parsed = json.loads(raw.split(b'\0', 1)[0])
    except (UnicodeError, ValueError) as error:
        raise PrimarySemanticUnavailable('super reporter nonempty persisted snapshot requires canonical source JSON') from error
    if not isinstance(parsed, dict):
        raise PrimarySemanticUnavailable('super reporter JSON record requires an object')
    values = {key.lower(): value for key, value in parsed.items()}
    names = ('seq', 'level', 'data', 'safe', 'from_sign_cmd')
    if set(values) != set(names) or any(not isinstance(values[key], str) for key in names if key != 'safe'):
        raise PrimarySemanticUnavailable('super reporter JSON record field types are outside its supported source domain')
    if type(values['safe']) is not bool:
        raise PrimarySemanticUnavailable('super reporter JSON safe field requires its boolean source domain')
    try:
        seq, data, command = (values[key].encode('utf-8') for key in ('seq', 'data', 'from_sign_cmd'))
    except UnicodeError as error:
        raise PrimarySemanticUnavailable('super reporter JSON strings require valid UTF-8') from error
    return seq, int(values['level'] == 'Low'), data, int(values['safe']), command


def _hash_nodes(runtime, table):
    node, seen = runtime.memory.load(table + 16, 8), set()
    while node:
        if node in seen or len(seen) >= 4096:
            raise PrimaryProgramLimit('super reporter hash map exceeds its bounded normal domain')
        seen.add(node)
        yield node
        node = runtime.memory.load(node, 8)


def _hash_find(runtime, table, key):
    for node in _hash_nodes(runtime, table):
        if _String.read(runtime, node + 16).value() == key:
            return node
    return 0


def _hash_insert(runtime, table, node, key):
    from .primary_request_manager import hash_bytes, rehash
    from .primary_sdk_records import _index, _needed, _single, _unsigned_single
    import struct
    memory = runtime.memory
    hashed = hash_bytes(key)
    memory.store(node + 8, hashed, 8, source='super_reporter.hash_node_hash')
    memory.store(node, 0, 8, source='super_reporter.hash_node_next')
    size, count = memory.load(table + 24, 8) + 1, memory.load(table + 8, 8)
    factor = struct.unpack('<f', memory.read(table + 32, 4))[0]
    if not count or _unsigned_single(size) > _single(_unsigned_single(count) * factor):
        rehash(runtime, table, max((count * 2) | int(count < 3 or bool(count & (count - 1))),
                                   _needed(runtime, table, size)))
        count = memory.load(table + 8, 8)
    bucket = _index(hashed, count)
    predecessor = memory.load(memory.load(table, 8) + bucket * 8, 8)
    if predecessor:
        memory.store(node, memory.load(predecessor, 8), 8, source='super_reporter.hash_bucket_next')
        memory.store(predecessor, node, 8, source='super_reporter.hash_bucket_insert')
    else:
        previous = memory.load(table + 16, 8)
        memory.store(node, previous, 8, source='super_reporter.hash_head_next')
        memory.store(table + 16, node, 8, source='super_reporter.hash_head_insert')
        memory.store(memory.load(table, 8) + bucket * 8, table + 16, 8, source='super_reporter.hash_head_bucket')
        if previous:
            memory.store(memory.load(table, 8) + _index(memory.load(previous + 8, 8), count) * 8,
                         node, 8, source='super_reporter.hash_previous_head_bucket')
    memory.store(table + 24, size, 8, source='super_reporter.hash_count')


def _snapshot_insert(runtime, table, key, parsed):
    if _hash_find(runtime, table, key):
        return
    seq, mode, data, safe_value, command = parsed
    node = runtime._operator_new(128)
    for offset, raw in ((16, key), (40, seq), (72, data), (104, command)):
        temporary = _String.construct(runtime, raw)
        temporary.clone().write_to(node + offset)
        temporary.destroy()
    runtime.memory.store(node + 64, mode, 4, source='3590F92.super_reporter_snapshot_mode')
    runtime.memory.store(node + 96, safe_value, 1, source='3590FAE.super_reporter_snapshot_safe')
    _hash_insert(runtime, table, node, key)


def destroy_snapshot(runtime, table):
    for node in tuple(_hash_nodes(runtime, table)):
        for offset in (104, 72, 40, 16):
            _String.read(runtime, node + offset).destroy()
        runtime._free_allocation(node)
    buckets = runtime.memory.load(table, 8)
    runtime.memory.store(table, 0, 8, source='2DE0950.super_reporter_snapshot_bucket_reset')
    if buckets:
        runtime._free_allocation(buckets)


def _limited(runtime, owner, key):
    memory, base = runtime.memory, runtime.image_base
    _mutex(runtime, base + 0x6D85F48, True)
    table = owner + 24
    node = _hash_find(runtime, table, key)
    if node:
        count = memory.load(node + 40, 4, signed=True)
        count = count + 1 if count < 5 else 5
        memory.store(node + 40, count & 0xFFFFFFFF, 4, source='2DE060E.super_reporter_retry_count')
    else:
        node = runtime._operator_new(48)
        _String.construct(runtime, key).write_to(node + 16)
        memory.store(node + 40, 0, 4, source='2DE0643.super_reporter_first_retry_count')
        _hash_insert(runtime, table, node, key)
        count = 0
    _mutex(runtime, base + 0x6D85F48, False)
    return count >= 5


def _metadata_owner(runtime):
    from .primary_high_reliability import _map_image
    memory, base = runtime.memory, runtime.image_base
    _map_image(memory, base + 0x6751B30, bytes(4), writable=True)
    value = memory.load(base + 0x6751B30, 4)
    if not value & 1:
        memory.store(base + 0x6751B30, value | 1, 4, source='2DE0007.super_reporter_metadata_guard')
        _map_image(memory, base + 0x6751AB8, bytes(120), writable=True)
        memory.write(base + 0x6751AB8, bytes(2), source='2DE000D.super_reporter_metadata_empty')
        memory.write(base + 0x6751AC0, bytes(16), source='2DE0016.super_reporter_metadata_fields')
        memory.write(base + 0x6751AD8, bytes(16), source='2DE001D.super_reporter_metadata_tree')
        memory.store(base + 0x6751AD0, base + 0x6751AD8, 8, source='2DE002B.super_reporter_metadata_sentinel')
        memory.store(base + 0x6751AE8, 1, 8, source='2DE0032.super_reporter_metadata_initial')
        _invoke(runtime, 0x75B000, base + 0x6751AF0)
        memory.write(base + 0x6751B20, bytes(16), source='2DE0049.super_reporter_metadata_pending')
        memory.store(base + 0x6751B18, base + 0x6751B20, 8, source='2DE0057.super_reporter_metadata_pending_sentinel')
        _invoke(runtime, 0x3E680B4, base + 0x1BFEDD6)
    return base + 0x6751AB8


def failure(runtime, registry, key):
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    raw = _String.read(runtime, key).value()
    _erase_key(runtime, registry + 8, raw)
    value = _String.read(runtime, key)
    pointer = value.get(16, 8) if value.get(0, 1) & 1 else key + 1
    log(runtime, _FILE, 0x40, b'super_repoter seq: %s back for retry', base + 0x48972C7, 2, pointer)
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)
    runtime.events.append(('super_reporter.retry_retained', raw))


def success(runtime, registry, key):
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x358A210, registry, key)
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    frame, _ = _frame(runtime, 0x108, '3589D40.super_reporter_success_frame')
    tree = frame + 80
    memory.store(tree, tree + 8, 8, source='3589DA3.super_reporter_delete_tree_begin')
    memory.write(tree + 8, bytes(16), source='3589D9F.super_reporter_delete_tree_empty')
    value = _String.read(runtime, key)
    _String.construct(runtime, b'o3sec_super_reporter_' + value.value()).write_to(frame + 56)
    temporary = _String.read(runtime, frame + 56).clone()
    temporary.write_to(frame + 104)
    _mark_key(runtime, tree, frame + 104)
    temporary.destroy()
    _invoke(runtime, 0x1BE5BC0, tree)
    _invoke(runtime, 0x358ABB0, registry + 8, key)
    pointer = value.get(16, 8) if value.get(0, 1) & 1 else key + 1
    log(runtime, _FILE, 0x3A, b'super_repoter seq: %s deleted', base + 0x48972C7, 2, pointer)
    _erase_key(runtime, tree, b'o3sec_super_reporter_' + value.value())
    _String.read(runtime, frame + 56).destroy()
    memory.unmap(frame)
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)
    runtime.events.append(('super_reporter.completed', value.value()))


def sample(runtime):
    from .primary_cocos import next_mt, seed_mt
    memory, base = runtime.memory, runtime.image_base
    install_image(memory, base)
    frame, _ = _frame(runtime, 0x50, '2DE06D0.super_reporter_sampler_frame')
    guard = base + 0x6D85578
    value = memory.load(guard, 4)
    if not value & 1:
        memory.store(guard, value | 1, 4, source='2DE0823.super_reporter_sampler_device_guard')
        _String.construct(runtime, b'/dev/urandom').write_to(frame + 0x30)
        _invoke(runtime, 0x7602D0, base + 0x6D85574, frame + 0x30)
        _String.read(runtime, frame + 0x30).destroy()
        _invoke(runtime, 0x3E680B4, base + 0x2DE0AF0)
        value = memory.load(guard, 4)
    if not value & 2:
        memory.store(guard, value | 2, 4, source='2DE0882.super_reporter_sampler_seed_guard')
        seed_mt(memory, base + 0x6D85580, _invoke(runtime, 0x7603B0, base + 0x6D85574))
    _invoke(runtime, 0x759A80, frame + 0x30)
    memory.store(frame + 0x28, _invoke(runtime, 0x759B00, frame + 0x30), 8,
                 source='2DE070E.super_reporter_sampler_seconds')
    calendar = _invoke(runtime, 0x3E88BE0, frame + 0x28)
    if not calendar:
        raise PrimarySemanticUnavailable('2DE071E sampler cannot normally dereference a NULL localtime calendar')
    minute = memory.load(calendar + 4, 4, signed=True)
    hour = memory.load(calendar + 8, 4, signed=True)
    threshold = (50 if minute < 4 else 30 if minute < 6 else 0) if hour == 0 else 0
    selected = next_mt(memory, base + 0x6D85580)
    result = int(selected % 100 < threshold)
    runtime.events.append(('super_reporter.sampled', selected, hour, minute, threshold, result))
    memory.unmap(frame)
    return result


def delay(runtime, registry, key):
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x75B070, base + 0x6D88408)
    _mark_key(runtime, registry + 32, key)
    value = _String.read(runtime, key)
    pointer = value.get(16, 8) if value.get(0, 1) & 1 else key + 1
    log(runtime, _FILE, 0x46, b'super_repoter seq: %s delay for retry', base + 0x48972C7, 2, pointer)
    _invoke(runtime, 0x75B0A0, base + 0x6D88408)
    runtime.events.append(('super_reporter.delayed', value.value()))


def move_capture(runtime, key, active):
    captured = runtime._operator_new(40)
    runtime.memory.store(captured, runtime.image_base + 0x433C478, 8,
                         source='2DDFEC7.super_reporter_callback_vtable')
    _String.read(runtime, key).write_to(captured + 8)
    runtime.memory.write(key, bytes(24), source='2DDFEDA.super_reporter_callback_key_moved')
    runtime.memory.store(active, captured, 8, source='2DDFEE6.super_reporter_callback_active')
    return captured


def run_iteration(runtime, owner):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x120, '2DDF700.super_reporter_iteration_frame')
    registry = _registry(runtime)
    snapshot(runtime, registry, frame)
    submitted = 0
    for node in tuple(_hash_nodes(runtime, frame)):
        key = _String.read(runtime, node + 16).clone()
        key.write_to(frame + 40)
        if _limited(runtime, owner, key.value()):
            key.destroy()
            continue
        delayed = not memory.load(node + 64, 4) and bool(_invoke(runtime, 0x2DE06D0) & 255)
        if delayed or submitted >= 10:
            _invoke(runtime, 0x358B020, registry, frame + 40)
            key.destroy()
            continue
        encoded = _String.read(runtime, node + 72).value()
        decoded = _String(runtime, bytes(24), bytes([1]) * 24)
        if encoded:
            alphabet = _alphabet(runtime, 0x6D85530)
            try:
                raw = base64.b64decode(encoded, validate=True)
            except binascii.Error as error:
                raise PrimarySemanticUnavailable('super reporter noncanonical Base64 requires its source decoder policy') from error
            if base64.b64encode(raw) != encoded:
                raise PrimarySemanticUnavailable('super reporter noncanonical Base64 requires its source decoder policy')
            for byte in raw:
                _append(decoded, bytes([byte]))
            alphabet.destroy()
        decoded.write_to(frame + 64)
        key.clone().write_to(frame + 88)
        command = _String.construct(runtime, b'trpc.o3.report.Report.SsoReport')
        if memory.load(node + 96, 1):
            command.destroy()
            command = _String.construct(runtime, b'report')
        command.write_to(frame + 112)
        receiver = _metadata_owner(runtime)
        memory.write(frame + 136, bytes(48), source='2DDFE6E.super_reporter_metadata_zero')
        _String.read(runtime, node + 104).clone().write_to(frame + 136)
        command.clone().write_to(frame + 160)
        move_capture(runtime, frame + 88, frame + 216)
        command.clone().write_to(frame + 224)
        pointer = decoded.get(16, 8) if decoded.get(0, 1) & 1 else frame + 65
        runtime.events.append(('super_reporter.worker_submission', key.value(), decoded.value(), command.value(),
                               memory.load(node + 96, 1)))
        _invoke(runtime, 0x1CE6920, receiver, frame + 224, pointer, len(decoded.value()),
                frame + 184, frame + 136, memory.load(node + 96, 1))
        for offset in (160, 136, 112, 88, 64, 40):
            _String.read(runtime, frame + offset).destroy()
        submitted += 1
    destroy_snapshot(runtime, frame)
    memory.unmap(frame)
    runtime.events.append(('super_reporter.iteration_complete', owner, submitted))
    return submitted


def invoke(runtime, rva, arguments):
    definitions = {0x2DF48F0: (initialize_joint_module, 0), 0x2DE0E00: (initialize_worker_module, 0),
                   0x3591650: (initialize_registry_module, 0),
                   0x1BF3780: (construct, 0), 0x2DE0A90: (start, 1),
                   0x2DE0B00: (construct_registry, 0), 0x358B3F0: (reset_pending, 1),
                   0x358B4F0: (snapshot, 2), 0x1BF2300: (safe, 1),
                   0x2DF2B40: (construct_dispatcher, 1), 0x2DF2C10: (dispatch, 3),
                   0x3588A50: (persist, 5), 0x3589150: (sequence, 2),
                   0x2DDF700: (run_iteration, 1), 0x358AC50: (failure, 2),
                   0x2DE06D0: (sample, 0), 0x358B020: (delay, 2),
                   0x358A210: (remove_sequence, 2), 0x3589D40: (success, 2),
                   0x358ABB0: (erase_key, 2)}
    memory, base = runtime.memory, runtime.image_base
    if rva == 0x6270 and len(arguments) == 1:
        for offset in (0, 8, 16):
            memory.store(arguments[0] + offset, 0, 8, source='006278.default_string_zero')
        return 3
    if rva == 0x75CD00 and len(arguments) == 2:
        from .primary_caller_online import _assign_text
        _assign_text(runtime, arguments[0], _cstring(runtime, arguments[1]))
        return arguments[0]
    if rva == 0x75B810 and len(arguments) == 2:
        value = _String.read(runtime, arguments[1])
        if value.get(0, 1) & 1 and value.get(8, 8) <= 22:
            size = value.get(8, 8)
            memory.store(arguments[0], size * 2, 1, source='75B846.copy_string_short_length')
            memory.copy_disjoint(arguments[0] + 1, value.get(16, 8), size + 1,
                                 label='75B87B.copy_string_payload_and_terminator')
        else:
            value.clone().write_to(arguments[0])
        return arguments[0]
    if rva == 0x2DE0AF0 and not arguments:
        return _invoke(runtime, 0x28F0, base + 0x6D85574)
    if rva == 0x3588A40 and not arguments:
        return _invoke(runtime, 0x75B030, base + 0x6D88408)
    if rva == 0x3589490 and len(arguments) == 2:
        return append_sequence(runtime, arguments[1])
    if rva == 0x2DF37D0 and len(arguments) == 3:
        return wrap(runtime, arguments[1], arguments[2])
    if rva == 0x1C02430 and len(arguments) == 1:
        return _joint_body(runtime, memory.load(memory.load(arguments[0], 8), 8))
    if rva == 0x1C026E0 and len(arguments) == 1:
        return _publish_dispatcher(runtime)
    if rva in (0x2DF47D0, 0x2DF47E0) and len(arguments) == (2 if rva == 0x2DF47D0 else 1):
        destination = arguments[1] if rva == 0x2DF47D0 else runtime._operator_new(16)
        memory.store(destination, base + 0x436ECF8, 8, source='super_reporter.no_capture_functor_clone')
        return base + 0x436ECF8 if rva == 0x2DF47D0 else destination
    if rva == 0x2DF4800 and len(arguments) == 1:
        install_image(memory, base)
        _once(runtime, base + 0x677C0C8, lambda: _invoke(runtime, 0x1BF3780))
        return run_iteration(runtime, memory.load(base + 0x677C0D0, 8))
    if rva in (0x2DE0B80, 0x2DE0BA0) and len(arguments) == (2 if rva == 0x2DE0B80 else 1):
        destination = arguments[1] if rva == 0x2DE0B80 else runtime._operator_new(40)
        memory.store(destination, base + 0x433C478, 8, source='super_reporter.callback_clone_vtable')
        _String.read(runtime, arguments[0] + 8).clone().write_to(destination + 8)
        return destination if rva == 0x2DE0BA0 else None
    if rva in (0x2DE0B40, 0xB95880, 0xBED000) and len(arguments) == (2 if rva == 0x2DE0B40 else 1):
        _String.read(runtime, arguments[0] + 8).destroy()
        if rva == 0xBED000 or rva == 0x2DE0B40 and arguments[1] & 1:
            runtime._free_allocation(arguments[0])
        return arguments[0] if rva == 0x2DE0B40 else None
    if rva == 0x2DE0C10 and len(arguments) == 5:
        if memory.load(arguments[3], 1):
            return _invoke(runtime, 0x3589D40, _registry(runtime), arguments[0] + 8)
        return failure(runtime, _registry(runtime), arguments[0] + 8)
    if rva in (0x1BF37D0, 0x2DE0D60):
        if len(arguments) != 1:
            raise InputError('super reporter once adapter requires its triple-pointer context')
        pointer = arguments[0]
        for _ in range(3):
            pointer = runtime.memory.load(pointer, 8)
        return _invoke(runtime, pointer - runtime.image_base) if rva == 0x1BF37D0 else _start(runtime, pointer)
    function, count = definitions[rva]
    if len(arguments) != count:
        raise InputError('super reporter source entry argument count mismatch')
    return function(runtime, *arguments)
