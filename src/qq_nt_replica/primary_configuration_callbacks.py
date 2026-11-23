from dataclasses import dataclass

from .errors import InputError
from .primary_logger import _String, _cstring, log
from .primary_memory import PrimaryMemoryLimit
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_MASK64 = (1 << 64) - 1
_TABLES = {0x3FD7748: (0x142A0, 0xBED780, 0xBED790, 0x28F0, 0x1FE0, 0xBED7B0),
           0x3FD77A8: (0x142A0, 0xBED980, 0xBED990, 0x28F0, 0x1FE0, 0xBED9B0)}


@dataclass(frozen=True)
class ConfigurationCallbacks:
    writer_address: int
    reader_address: int
    release_address: int
    writer: object
    reader: object
    release: object

    def __post_init__(self):
        for address, callback in ((self.writer_address, self.writer), (self.reader_address, self.reader),
                                  (self.release_address, self.release)):
            if type(address) is not int or not 0 <= address <= _MASK64 or (address and not callable(callback)):
                raise InputError('configuration callbacks require unsigned C addresses and explicit callable services')
        addresses = [address for address in (self.writer_address, self.reader_address, self.release_address) if address]
        if len(addresses) != len(set(addresses)):
            raise InputError('configuration callback addresses require distinct C service identities')


def install_image(runtime):
    for rva, targets in _TABLES.items():
        raw = b''.join((runtime.image_base + target).to_bytes(8, 'little') for target in targets)
        pointer = runtime.image_base + rva
        try:
            observed = runtime.memory.read(pointer, len(raw))
        except PrimaryMemoryLimit:
            runtime.memory.map(pointer, raw, name='fixed native configuration adapter vtable', initialized=True)
        else:
            if observed != raw:
                raise InputError('fixed configuration adapter vtable identity mismatch')
    for rva in (0x677BD98, 0x677BDC0, 0x677BDE8):
        cursor, end = runtime.image_base + rva, runtime.image_base + rva + 32
        for region in tuple(runtime.memory._region_snapshot()):
            if region.address >= end:
                break
            region_end = region.address + len(region.data)
            if region_end <= cursor:
                continue
            if cursor < region.address:
                runtime.memory.map(cursor, bytearray(region.address - cursor),
                                   name='native configuration PE loader zero fill', initialized=True)
            cursor = max(cursor, min(end, region_end))
        if cursor < end:
            runtime.memory.map(cursor, bytearray(end - cursor), name='native configuration PE loader zero fill', initialized=True)


def _kind(runtime, active):
    table = runtime.memory.load(active, 8) - runtime.image_base
    if table not in _TABLES:
        raise PrimarySemanticUnavailable('configuration adapter current vtable is not a native registered adapter')
    return table


def _virtual(runtime, active, offset, *values):
    target = runtime.memory.load(runtime.memory.load(active, 8) + offset, 8) - runtime.image_base
    return _invoke(runtime, target, active, *values)


def delete_keys(runtime, tree):
    install_image(runtime)
    active = runtime.memory.load(runtime.image_base + 0x677BE00, 8)
    if active and runtime.memory.load(tree + 16, 8):
        _virtual(runtime, active, 40, tree)
    return None


def destroy(runtime, inline):
    active = runtime.memory.load(inline + 24, 8)
    if active:
        _virtual(runtime, active, 24 if active == inline else 32)


def swap(runtime, left, right):
    if left == right:
        return None
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x40, 'BED870.configuration_function_swap_frame')
    active_left, active_right = memory.load(left + 24, 8), memory.load(right + 24, 8)
    if active_left != left:
        if active_right != right:
            memory.store(left + 24, active_right, 8, source='BED8A5.configuration_left_owner')
            memory.store(right + 24, active_left, 8, source='BED8A9.configuration_right_owner')
        else:
            _virtual(runtime, active_right, 8, left)
            destroy(runtime, right)
            memory.store(right + 24, memory.load(left + 24, 8), 8, source='BED8EC.configuration_right_owner')
            memory.store(left + 24, left, 8, source='BED8F4.configuration_left_inline')
    elif active_right != right:
        _virtual(runtime, active_left, 8, right)
        destroy(runtime, left)
        memory.store(left + 24, memory.load(right + 24, 8), 8, source='BED8CB.configuration_left_owner')
        memory.store(right + 24, right, 8, source='BED952.configuration_right_inline')
    else:
        _virtual(runtime, active_left, 8, frame + 32)
        destroy(runtime, left)
        memory.store(left + 24, 0, 8, source='BED90E.configuration_left_reset')
        _virtual(runtime, active_right, 8, left)
        destroy(runtime, right)
        memory.store(right + 24, 0, 8, source='BED92D.configuration_right_reset')
        memory.store(left + 24, left, 8, source='BED935.configuration_left_inline')
        _virtual(runtime, frame + 32, 8, right)
        _virtual(runtime, frame + 32, 24)
        memory.store(right + 24, right, 8, source='BED952.configuration_right_inline')
    memory.unmap(frame)
    return None


def handles_swap(runtime, left, right):
    return any(active and runtime.memory.load(active, 8) - runtime.image_base in _TABLES
               for active in (runtime.memory.load(left + 24, 8), runtime.memory.load(right + 24, 8)))


def _callback(runtime, slot):
    target = runtime.memory.load(runtime.image_base + slot, 8)
    binding = getattr(runtime, '_configuration_c_callbacks', {}).get(target)
    if binding is None:
        raise PrimarySemanticUnavailable('native configuration current C callback is not bound: ' + hex(target))
    return target, binding


def _guard(runtime):
    pointer = runtime.image_base + 0x6751820
    guard = runtime.memory.load(pointer, 4)
    if not guard & 1:
        runtime.memory.store(pointer, guard | 1, 4, source='native_configuration.callback_guard')


def write(runtime, receiver, target, key, value):
    if _kind(runtime, receiver) != 0x3FD7748 or target != runtime.image_base + 0xBED7B0:
        raise PrimarySemanticUnavailable('native configuration writer receiver or virtual target mismatch')
    _guard(runtime)
    key_pointer = runtime.memory.load(key + 16, 8) if runtime.memory.load(key, 1) & 1 else key + 1
    value_pointer = runtime.memory.load(value + 16, 8) if runtime.memory.load(value, 1) & 1 else value + 1
    address, callback = _callback(runtime, 0x6751808)
    runtime.events.append(('configuration.C_writer', address, key_pointer, value_pointer,
                           _cstring(runtime, key_pointer), _cstring(runtime, value_pointer)))
    callback(runtime, key_pointer, value_pointer)
    return None


def read(runtime, receiver, target, output, key):
    if _kind(runtime, receiver) != 0x3FD77A8 or target != runtime.image_base + 0xBED9B0:
        raise PrimarySemanticUnavailable('native configuration reader receiver or virtual target mismatch')
    _guard(runtime)
    key_pointer = runtime.memory.load(key + 16, 8) if runtime.memory.load(key, 1) & 1 else key + 1
    address, callback = _callback(runtime, 0x6751818)
    pointer = callback(runtime, key_pointer)
    if type(pointer) is not int or not 0 <= pointer <= _MASK64:
        raise InputError('native configuration reader must return a current C string pointer or NULL')
    runtime.events.append(('configuration.C_reader', address, key_pointer, _cstring(runtime, key_pointer), pointer))
    if pointer:
        _String.construct(runtime, _cstring(runtime, pointer)).write_to(output)
    else:
        runtime.memory.store(output, 0, 2, source='BEDA1E.configuration_null_result')
    return output


def register_callbacks(runtime, callbacks):
    if not isinstance(callbacks, ConfigurationCallbacks):
        raise InputError('configuration registration requires explicit ConfigurationCallbacks')
    return register(runtime, callbacks.writer_address, callbacks.reader_address, callbacks.release_address,
                    callbacks=callbacks)


def register(runtime, writer, reader, release, *, callbacks=None):
    if any(type(value) is not int or not 0 <= value <= _MASK64 for value in (writer, reader, release)):
        raise InputError('native configuration registration requires three unsigned C function addresses')
    source_file = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\platforms\\Windows\\libsecxx\\FGESDKNt.cpp'
    log(runtime, source_file, 43, b'set persistent proxy', b'[FGESDK]', 1)
    if not all((writer, reader, release)):
        log(runtime, source_file, 45, b'set persistent proxy: input invalid', b'[FGESDK]', 1)
        return None
    install_image(runtime)
    _guard(runtime)
    for slot, value in ((0x6751810, release), (0x6751818, reader), (0x6751808, writer)):
        runtime.memory.store(runtime.image_base + slot, value, 8, source='B9F8D0.configuration_C_address')
    if callbacks is not None:
        bindings = getattr(runtime, '_configuration_c_callbacks', {})
        bindings.update({writer: callbacks.writer, reader: callbacks.reader, release: callbacks.release})
        runtime._configuration_c_callbacks = bindings
    frame, _ = _frame(runtime, 0xC8, 'B9F8D0.configuration_registration_frame')
    temporary = frame + 0x38
    for table, destination in ((0x3FD7748, 0x677BD98), (0x3FD77A8, 0x677BDC0)):
        runtime.memory.store(temporary, runtime.image_base + table, 8, source='B9F8D0.configuration_native_adapter')
        runtime.memory.store(temporary + 24, temporary, 8, source='B9F8D0.configuration_inline_owner')
        _invoke(runtime, 0xBED870, temporary, runtime.image_base + destination)
        destroy(runtime, temporary)
    runtime.memory.unmap(frame)
    runtime.events.append(('configuration.registered', writer, reader, release))
    return None


def invoke(runtime, rva, values):
    if rva == 0x1BE5BC0 and len(values) == 1:
        return delete_keys(runtime, values[0])
    if rva == 0xB9F8D0 and len(values) == 3:
        return register(runtime, *values)
    if rva in (0xBED780, 0xBED790, 0xBED980, 0xBED990):
        heap = rva in (0xBED790, 0xBED990)
        if len(values) != (1 if heap else 2):
            raise InputError('native configuration adapter clone argument count mismatch')
        expected = 0x3FD7748 if rva in (0xBED780, 0xBED790) else 0x3FD77A8
        if _kind(runtime, values[0]) != expected:
            raise PrimarySemanticUnavailable('native configuration clone current adapter mismatch')
        destination = runtime._operator_new(16) if heap else values[1]
        runtime.memory.store(destination, runtime.image_base + expected, 8, source='native_configuration.clone_vtable')
        return destination if heap else None
    if rva == 0xBED7B0 and len(values) == 3:
        return write(runtime, values[0], runtime.image_base + rva, *values[1:])
    if rva == 0xBED9B0 and len(values) == 3:
        return read(runtime, values[0], runtime.image_base + rva, *values[1:])
    raise InputError('native configuration source interface argument count mismatch')
