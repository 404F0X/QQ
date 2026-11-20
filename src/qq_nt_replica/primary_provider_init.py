from dataclasses import dataclass

from .errors import InputError
from .primary_logger import _String, _cstring, feature, log
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _assign, _frame


_VERSION = b'release/nt_win_8.6.3_bf2d9128c_199'
_FILE = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\platforms\\Windows\\libsecxx\\FGESDKNt.cpp'
_CONTROL = (0xBEDAF0, 0x28F0, 0x63EC0, 0x1FE0)
_COST = (0xBCD0B0, 0xBCD160, 0xBCD250, 0x9A3770)
_COST_EVENT = (0xBCE920, 0xBCE940, 0x63EC0, 0x63EC0, 0xBCD9A0)


@dataclass(frozen=True)
class ProviderInitializationMetadata:
    field_08: bytes | None
    field_10: bytes
    field_18: bytes
    field_20: bytes

    def __post_init__(self):
        for offset in (8, 0x10, 0x18, 0x20):
            value = getattr(self, 'field_' + format(offset, '02x'))
            if offset == 8 and value is None:
                continue
            if not isinstance(value, bytes) or b'\0' in value:
                raise InputError('provider initialization metadata requires exact NUL-free bytes at offset ' + hex(offset))


def install_image(memory, base):
    segments = ((0x3FD7808, b''.join((base + rva).to_bytes(8, 'little') for rva in _CONTROL) +
                 bytes(8) + (1).to_bytes(8, 'little')),
                (0x3FD6A28, b''.join((base + rva).to_bytes(8, 'little') for rva in _COST)),
                (0x3FD6CC8, b''.join((base + rva).to_bytes(8, 'little') for rva in _COST_EVENT)),
                (0x48AAD76, _VERSION + b'\0'), (0x4903C10, b'\0'))
    for rva, raw in segments:
        pointer = base + rva
        offset = 0
        while offset < len(raw):
            current = pointer + offset
            present = next((region for region in memory._regions
                            if region.address <= current < region.address + len(region.data)), None)
            if present is not None:
                size = min(len(raw) - offset, present.address + len(present.data) - current)
                if memory.read(current, size) != raw[offset:offset + size]:
                    raise InputError('provider initializer source image overlaps different bytes')
            else:
                boundary = min((region.address for region in memory._regions if region.address > current),
                               default=pointer + len(raw))
                size = min(len(raw) - offset, boundary - current)
                memory.map(current, raw[offset:offset + size], name='fixed provider initializer source image', initialized=True)
            offset += size


def _mutex(runtime, pointer, acquire):
    held = runtime.locks.get(pointer, 0)
    if (acquire and held) or (not acquire and not held):
        raise PrimarySemanticUnavailable('provider initialization mutex requires actual uncontended ownership')
    runtime.locks[pointer] = int(acquire)
    runtime.events.append(('75AF50.lock' if acquire else '75AFC0.unlock', pointer))


def _state(runtime):
    memory, base = runtime.memory, runtime.image_base
    _mutex(runtime, base + 0x6751830, True)
    pointer = memory.load(base + 0x6751828, 8)
    if not pointer:
        pointer = runtime._operator_new(3)
        memory.store(pointer + 2, 0, 1, source='BA0841.sdk_state_tail')
        memory.store(pointer, 0, 2, source='BA0845.sdk_state_prefix')
        memory.store(base + 0x6751828, pointer, 8, source='BA084A.sdk_state_publish')
    _mutex(runtime, base + 0x6751830, False)
    return pointer


def _install_pair(runtime):
    from .primary_sdk import _add_owner, _release_owner

    memory, base = runtime.memory, runtime.image_base
    control = runtime._operator_new(32)
    memory.store(control + 8, 0, 4, source='BA0D0E.device_control_owner_count')
    memory.store(control + 16, 0, 4, source='BA0D15.device_control_weak_count')
    memory.store(control, base + 0x3FD7808, 8, source='BA0D27.device_control_vtable')
    memory.store(control + 24, base + 0x3FD7898, 8, source='BA0D32.device_interface_vtable')
    _add_owner(runtime, control)
    memory.store(base + 0x6751840, control + 24, 8, source='BA0D40.device_publish')
    previous = memory.load(base + 0x6751848, 8)
    memory.store(base + 0x6751848, control, 8, source='BA0D4E.device_control_publish')
    if previous:
        _release_owner(runtime, previous)
    _release_owner(runtime, control)
    runtime.events.append(('provider.initialization_pair', control + 24, control, previous))
    return control


def configure(runtime, config, context):
    memory = runtime.memory
    _mutex(runtime, config + 0x120, True)
    memory.copy_disjoint(config + 0x104, context + 0xDC, 4,
                         label='1BE294E.configuration_context_tail')
    for source, target in ((0x18, 0x40), (0x18, 0x40), (0x78, 0xA0), (0x90, 0xB8),
                           (0xC0, 0xE8), (0, 0x28), (0x30, 0x58)):
        value = _String.read(runtime, context + source)
        if value.value():
            _assign(runtime, config + target, value)
    value = _String.read(runtime, context + 0x48)
    if value.value():
        _assign(runtime, config + 0x70, value)
        _invoke(runtime, 0x1BF63F0)
        pointer = value.get(16, 8) if value.get(0, 1) & 1 else context + 0x49
        length = len(value.value()) & 0xFFFFFFFF
        from .primary_source2581_direct import _source2581_configuration
        with _source2581_configuration(runtime, config, context, pointer, length, 0x2581):
            _invoke(runtime, 0x1BF7520, pointer, length, 0x2581)
        log(runtime, b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\base\\src\\context\\context.cpp',
            0x59, b'doing guid: %s', runtime.image_base + 0x48972C7, 1, pointer)
    for source, target in ((0x60, 0x88), (0xE0, 0x108)):
        value = _String.read(runtime, context + source)
        if value.value():
            _assign(runtime, config + target, value)
    memory.store(config + 0x100, memory.load(context + 0xD8, 4), 4,
                 source='1BE2E28.configuration_context_mode')
    _mutex(runtime, config + 0x120, False)
    _invoke(runtime, 0xBA1A90, context)


def configure_version(runtime, config, value):
    _mutex(runtime, config + 0x120, True)
    _assign(runtime, config + 0xA0, _String.read(runtime, value))
    _mutex(runtime, config + 0x120, False)
    _String.read(runtime, value).destroy()


def initialize_configuration(runtime, owner, context):
    from .primary_worker_loop import _initialize

    memory, config = runtime.memory, runtime.image_base + 0x67516B0
    now = _invoke(runtime, 0x3E8ED3C, 0)
    _invoke(runtime, 0x3E98FD8, now & 0xFFFFFFFF)
    memory.store(owner, 1, 1, source='1BEE46D.telemetry_owner_enabled')
    _initialize(runtime, 1)
    frame, _ = _frame(runtime, 0x138, '1BEE450.configuration_frame')
    copied = frame + 0x40
    _invoke(runtime, 0x1BEE6A0, copied, context)
    _invoke(runtime, 0x1BE2910, config, copied)
    _initialize(runtime, 1)
    _String.construct(runtime, _VERSION, 47).write_to(frame + 0x28)
    _invoke(runtime, 0x1BE2EB0, config, frame + 0x28)
    memory.unmap(frame)


def initialize_services(runtime, owner, context):
    from .primary_worker_loop import _ensure_logger

    _invoke(runtime, 0x1BEE450, owner, context)
    for flag in (0x2A, 0x26):
        _ensure_logger(runtime)
        logger = runtime.memory.load(runtime.image_base + 0x67516A8, 8)
        if _invoke(runtime, 0x1BE4230, logger, flag):
            if flag == 0x2A:
                from .primary_super_reporter import initialize
                initialize(runtime)
                continue
            raise PrimarySemanticUnavailable('provider initialization enabled service branch is not implemented: ' + hex(flag))


def format_version(runtime, output, capacity, template, *arguments):
    from .primary_logger import _format

    raw = _format(runtime, _cstring(runtime, template), arguments)
    if capacity:
        runtime.memory.write(output, raw[:capacity - 1] + b'\0', source='BA1A10.version_format')
    return len(raw)


def initialize(runtime, metadata):
    from .primary_device_records import _locked_singleton
    from .primary_provider_cache import initialize as initialize_cache
    from .primary_worker_loop import _initialize

    if not metadata:
        return None
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x358, 'BA0270.provider_initialization_frame')
    record = rbp + 0x110
    memory.store(record, base + 0x3FD6A28, 8, source='BA03CA.initialization_cost_vtable')
    _invoke(runtime, 0x759B30, record + 8)
    memory.store(record + 16, 0, 8, source='BA03DD.initialization_cost_end')
    memory.store(record + 24, 0, 2, source='BA03E8.initialization_cost_flags')
    memory.store(record + 28, 1, 4, source='BA03F1.initialization_cost_divisor')
    _String.construct(runtime, b'sdk_init').clone().write_to(record + 32)
    log(runtime, _FILE, 0x45, b'init: %s', base + 0x48972C7, 1, base + 0x48AAD76)
    state = _state(runtime)
    if memory.load(state + 1, 1):
        log(runtime, _FILE, 0x48, b'initialized', base + 0x48972C7, 1)
    else:
        owner = _locked_singleton(runtime, 0x6751838, 0x67516A0, 32, 0x1BE5CD0)
        _invoke(runtime, 0x1BE77F0, owner, rbp - 0x48)
        _String.read(runtime, rbp - 0x48).destroy()
        initialize_cache(runtime, 'sdk')
        _install_pair(runtime)
        context = rbp + 0x10
        memory.write(rbp + 0xF0, bytes(16), source='BA0DAB.initialization_context_tail')
        memory.store(rbp + 0x100, 0, 8, source='BA0DB3.initialization_context_tail')
        for offset in range(0x10, 0xE0, 0x10):
            memory.write(rbp + offset, bytes(16), source='BA0DBA.initialization_context_zero')
        memory.write(rbp + 0xDC, bytes(16), source='BA0E0F.initialization_context_zero')
        tail = getattr(runtime, 'provider_initialization_tail', None)
        if tail is not None:
            memory.write(rbp + 0xEC, tail, source='public_provider_initialization.private_stack_input')
        pointer = memory.load(metadata + 0x10, 8)
        _String.construct(runtime, _cstring(runtime, pointer)).write_to(context + 0x18)
        _String.construct(runtime, _VERSION).write_to(context + 0x78)
        _invoke(runtime, 0x1BED570, rbp - 8)
        _invoke(runtime, 0x1BED930, rbp - 0x30)
        memory.write(rbp + 0x150, bytes(0x104), source='BA0E9C.initialization_version_buffer')
        version = b'%d.%d.%d'
        memory.write(rbp - 0x48, version + b'\0', source='BA0EA3.initialization_version_format')
        _invoke(runtime, 0xBA1A10, rbp + 0x150, 0x104, rbp - 0x48,
                memory.load(rbp - 0x28, 4), memory.load(rbp - 0x24, 4), memory.load(rbp - 0x20, 4))
        _assign(runtime, context, _String.read(runtime, rbp - 8))
        _String.construct(runtime, _cstring(runtime, rbp + 0x150)).write_to(context + 0x90)
        for source, destination in ((0x20, 0x48), (0x18, 0xE0)):
            pointer = memory.load(metadata + source, 8)
            _String.construct(runtime, _cstring(runtime, pointer)).write_to(context + destination)
        pointer = memory.load(metadata + 8, 8)
        _String.construct(runtime, _cstring(runtime, pointer if pointer else base + 0x4903C10)).write_to(context + 0x30)
        from .primary_worker_response import _image, _owner
        _owner(runtime, _image())
        _invoke(runtime, 0x1BEE9A0, base + 0x67519B8, context)
        _invoke(runtime, 0x1BF63F0)
        _invoke(runtime, 0x1BF7660)
        for rva in (0x1BF75A0, 0x1BF8090):
            _invoke(runtime, rva, (1 << 64) - 4, 0, 3, 1)
            _invoke(runtime, rva, 0, 0, 2, 1)
        _invoke(runtime, 0x1C1BA80)
        memory.store(record + 25, 1, 1, source='BA1024.initialization_cost_once')
        _invoke(runtime, 0x759B30, rbp - 0x48)
        memory.store(record + 16, memory.load(rbp - 0x48, 8), 8, source='BA1045.initialization_cost_end')
        _invoke(runtime, 0xBCDAD0, record)
        state = _state(runtime)
        memory.store(state + 1, 1, 1, source='BA1097.sdk_state_ready')
        log(runtime, _FILE, 0x6B, b'init end', base + 0x48972C7, 1)
        _String.read(runtime, rbp - 8).destroy()
        _invoke(runtime, 0xBA1A90, context)
    memory.store(record, base + 0x3FD6A28, 8, source='BA13E8.initialization_cost_base_vtable')
    if not memory.load(record + 25, 1):
        memory.store(record + 25, 1, 1, source='BA1409.initialization_cost_once')
        _invoke(runtime, 0x759B30, rbp - 0x48)
        memory.store(record + 16, memory.load(rbp - 0x48, 8), 8, source='BA142A.initialization_cost_end')
        _invoke(runtime, 0xBCDAD0, record)
    _String.read(runtime, record + 32).destroy()
    memory.unmap(frame)
    return None


def initialize_metadata(runtime, metadata, private_context_tail):
    if not isinstance(metadata, ProviderInitializationMetadata):
        raise InputError('provider initialization requires ProviderInitializationMetadata')
    if private_context_tail is not None and (not isinstance(private_context_tail, bytes) or len(private_context_tail) != 4):
        raise InputError('provider initialization requires four private stack bytes or None at context +0xDC')
    memory = runtime.memory
    size = 0x28 + sum(len(value) + 1 for value in
                      (metadata.field_08, metadata.field_10, metadata.field_18, metadata.field_20)
                      if value is not None)
    frame, _ = _frame(runtime, size, 'public provider initialization metadata')
    cursor = frame + 0x28
    for offset in (8, 0x10, 0x18, 0x20):
        value = getattr(metadata, 'field_' + format(offset, '02x'))
        memory.store(frame + offset, cursor if value is not None else 0, 8,
                     source='public_provider_initialization.metadata_pointer')
        if value is not None:
            memory.write(cursor, value + b'\0', source='public_provider_initialization.metadata_bytes')
            cursor += len(value) + 1
    previous = getattr(runtime, 'provider_initialization_tail', None)
    runtime.provider_initialization_tail = private_context_tail
    try:
        return _invoke(runtime, 0xBA0270, frame)
    finally:
        runtime.provider_initialization_tail = previous
        memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva == 0xBA0270 and len(values) == 1:
        return initialize(runtime, *values)
    if rva == 0x1BEE450 and len(values) == 2:
        return initialize_configuration(runtime, *values)
    if rva == 0x1BEE9A0 and len(values) == 2:
        return initialize_services(runtime, *values)
    if rva == 0x1BE2910 and len(values) == 2:
        return configure(runtime, *values)
    if rva == 0x1BE2EB0 and len(values) == 2:
        return configure_version(runtime, *values)
    if rva == 0x1BF7660 and not values:
        runtime.memory.store(runtime.image_base + 0x6D86040, runtime.image_base + 0x63EC0, 8,
                             source='1BF7667.common_control_publish')
        return None
    if rva == 0xBA1A10 and len(values) >= 3:
        return format_version(runtime, *values)
    if rva == 0xBCDAD0 and len(values) == 1:
        from .primary_worker_response import audit
        return audit(runtime, *values)
    raise InputError('provider initializer source interface argument count mismatch')
