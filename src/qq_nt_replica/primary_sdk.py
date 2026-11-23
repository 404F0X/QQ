import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_DATA = Path(__file__).with_name("data") / "primary_sign_qq52230"
_MASK64 = (1 << 64) - 1
_MAX_BYTES = 1 << 20
_ASSETS = (
    (0x6556A90, "sdk-transform-p.bin", "251ace984f4801173665bfc747a25dc8bad5b839e3557c9f6e26609d363be66f"),
    (0x6556C90, "sdk-transform-q.bin", "d8c6befb0dd1810ed2c4c9372416f634f7c748cc3cd7c528b9ad361f589fa22f"),
    (0x433B1F8, "sdk-string-vtable.bin", "c8700b27b86b560ea9a4b2fdebb13eb8f09bef1bd0e352180b2ba14fc36d88b6"),
    (0x433B2E8, "sdk-boolean-vtable.bin", "9f94b9cd4b84237ae7a1351d7cfe8c5da2477ab32b2d5389fe41f3b84122f1a1"),
    (0x41486F8, "sdk-receiver-vtable.bin", "b5ff47c83c9093d58be17ff07fb5ac63e91ea4c883033f06454aeada6e84f972"),
    (0x41487B8, "sdk-receiver-control-vtable.bin", "67ddf536f6e9d782f45d019912c8a457dd1ec3bb505ec1ef39637bc32d1cc1f0"),
)


@dataclass(frozen=True)
class NativeByteReturn:
    value: int


def install_image(memory, image_base):
    for rva, name, digest in _ASSETS:
        raw = (_DATA / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise InputError("fixed SDK asset identity mismatch: " + name)
        if "vtable" in name:
            raw = b"".join(((int.from_bytes(raw[i:i + 8], "little") - 0x180000000 + image_base)
                            & _MASK64).to_bytes(8, "little") for i in range(0, len(raw), 8))
        memory.map(image_base + rva, bytearray(raw), name="fixed SDK " + name, initialized=True)


def string_view(memory, address):
    tag = memory.load(address, 1)
    if tag & 1:
        return memory.load(address + 16, 8), memory.load(address + 8, 8)
    return address + 1, tag >> 1


def _copy(memory, destination, source, size, label):
    if size:
        if destination < source + size and source < destination + size:
            raise PrimaryProgramLimit("SDK string copy requires disjoint native memcpy ranges")
        memory.copy_disjoint(destination, source, size, label=label)


def _local_copy(runtime, source, size):
    region, offset = runtime.memory._span(source, size)
    value = bytearray(region.data[offset:offset + size])
    known = bytes(region.initialized[offset:offset + size])
    runtime.events.append(("SDK.local_string_copy", source, size))
    return value, known


def assign_string(runtime, destination, source, size):
    memory = runtime.memory
    tag = memory.load(destination, 1)
    if not 0 <= size <= _MAX_BYTES:
        raise PrimaryProgramLimit("SDK assignment length exceeds the bounded offline domain")
    if tag & 1:
        capacity = memory.load(destination, 8) & ~1
        usable = (capacity - 1) & _MASK64
        pointer = memory.load(destination + 16, 8)
    else:
        usable, pointer = 22, destination + 1
    if size > usable:
        if usable > _MAX_BYTES:
            raise PrimaryProgramLimit("SDK string growth capacity exceeds the bounded offline domain")
        capacity = (max(2 * usable, size) | 15) + 1
        new_pointer = _invoke_values(runtime, runtime.image_base + 0xB75000, (capacity,))
        _copy(memory, new_pointer, source, size, "75BF76.assign_copy")
        if usable != 22:
            _invoke_values(runtime, runtime.image_base + 0xB75029, (pointer,))
        memory.store(destination + 16, new_pointer, 8, source="75BF89.assign_pointer")
        memory.store(destination, capacity | 1, 8, source="75BF91.assign_capacity")
        memory.store(destination + 8, size, 8, source="75BFC6.assign_length")
        pointer = new_pointer
    else:
        _copy(memory, pointer, source, size, "75BFB3.assign_copy")
        if memory.load(destination, 1) & 1:
            memory.store(destination + 8, size, 8, source="75BFC6.assign_length")
        else:
            memory.store(destination, size << 1, 1, source="75BFC2.assign_short_length")
    memory.store(pointer + size, 0, 1, source="75BFCA.assign_terminator")
    return destination


def transform(runtime, source, destination, length, mode):
    memory = runtime.memory
    size = length & 0xFFFFFFFF
    if size >= 0xFFFFFFF0:
        raise PrimarySemanticUnavailable("35863EB native string length exception")
    if size > _MAX_BYTES:
        raise PrimaryProgramLimit("SDK transform length exceeds the bounded signed32 offline domain")
    if not size:
        return None
    first = second = None
    if size > 22:
        capacity = (size + 16) & ~15
        first = runtime._allocate(capacity, False)
        _copy(memory, first, source, size, "3586206.input_copy")
        memory.store(first + size, 0, 1, source="358620F.input_terminator")
        second = runtime._allocate(capacity, False)
        _copy(memory, second, destination, size, "3586234.initial_target_copy")
        memory.store(second + size, 0, 1, source="3586239.target_terminator")
    else:
        input_value, input_known = _local_copy(runtime, source, size)
        output_value, _ = _local_copy(runtime, destination, size)
    table = runtime.image_base + (0x6556A90 if mode & 0xFFFFFFFF == 1 else 0x6556C90)
    for index in range(size):
        if first is None and not input_known[index]:
            raise UnknownMemory(f"SDK transform reads unknown temporary input byte {index}")
        value = memory.load(first + index, 1) if first is not None else input_value[index]
        row = (2 * index) & 30
        high = memory.load(table + 16 * row + (value >> 4), 1)
        low = memory.load(table + 16 * (row + 1) + (value & 15), 1)
        value = ((high << 4) | low) & 255
        if second is None:
            output_value[index] = value
        else:
            memory.store(second + index, value, 1, source="3586362.transformed_byte")
    if second is None:
        memory.write(destination, bytes(output_value), source="3586396.output_copy")
    else:
        _copy(memory, destination, second, size, "3586396.output_copy")
        runtime._free_allocation(second)
        runtime._free_allocation(first)
    return None


def transform_string(runtime, source, destination, mode):
    memory = runtime.memory
    tag = memory.load(source, 1)
    length = memory.load(source + 8, 8) if tag & 1 else tag >> 1
    reserve = ((length + 16) & _MASK64) & ~15
    if not 0 < reserve <= _MAX_BYTES:
        raise PrimaryProgramLimit("SDK full64 stack reservation exceeds the bounded offline domain")
    event = runtime._next(runtime._temporaries, "SDK transform stack", reserve)
    if not isinstance(event, tuple) or len(event) != 3:
        raise InputError("SDK stack event requires size, address and observed initial bytes")
    actual_size, address, initial = event
    if (actual_size != reserve or type(address) is not int or not 0 < address <= _MASK64 - reserve or
            (initial is not None and (not isinstance(initial, bytes) or len(initial) != reserve))):
        raise InputError("SDK stack event does not match the full64 reservation")
    memory.map(address, bytearray(reserve) if initial is None else bytearray(initial),
               name="SDK callback private stack", initialized=initial is not None)
    pointer = memory.load(source + 16, 8) if tag & 1 else source + 1
    transform(runtime, pointer, address, length, mode)
    tag = memory.load(source, 1)
    length = memory.load(source + 8, 8) if tag & 1 else tag >> 1
    assign_string(runtime, destination, address, length)
    memory.forget(address, reserve, source="SDK.callback.stack_lifetime_end")
    if not runtime.retain_frames:
        memory.unmap(address)
    return None


def _clone_table(runtime, table):
    target = runtime.memory.load(table + 8, 8) - runtime.image_base
    if target == 0x2C5CA50:
        return runtime.image_base + 0x433B1F8
    if target == 0x2C5CB20:
        return runtime.image_base + 0x433B2E8
    raise PrimarySemanticUnavailable("SDK functor current clone target is unavailable")


def _destroy(runtime, table, pointer, heap):
    target = runtime.memory.load(table + (32 if heap else 24), 8) - runtime.image_base
    if heap and target == 0x1FE0:
        runtime._free_allocation(pointer)
    elif heap or target != 0x28F0:
        raise PrimarySemanticUnavailable("SDK functor current destruction target is unavailable")


def handles_swap(runtime, left, right):
    memory, base = runtime.memory, runtime.image_base
    return any(active and memory.load(active, 8) in (base+0x433B1F8, base+0x433B2E8)
               for active in (memory.load(left+24, 8), memory.load(right+24, 8)))


def swap(runtime, left, right):
    from .primary_worker_consumer import _invoke
    from .primary_worker_response import _frame
    if left == right:
        return None
    memory = runtime.memory
    frame, unused = _frame(runtime, 0x40, 'BED870 SDK callback swap local')

    def virtual(active, slot, *values):
        table = memory.load(active, 8)
        target = memory.load(table+slot, 8)
        return _invoke(runtime, target-runtime.image_base, active, *values)

    def destroy(inline):
        active = memory.load(inline+24, 8)
        if active:
            virtual(active, 24 if active == inline else 32)

    active_left, active_right = memory.load(left+24, 8), memory.load(right+24, 8)
    if active_left != left:
        if active_right != right:
            memory.store(left+24, active_right, 8, source='BED8A5.SDK_left_owner')
            memory.store(right+24, active_left, 8, source='BED8A9.SDK_right_owner')
        else:
            virtual(active_right, 8, left)
            destroy(right)
            memory.store(right+24, memory.load(left+24, 8), 8, source='BED8EC.SDK_right_owner')
            memory.store(left+24, left, 8, source='BED8F4.SDK_left_inline')
    elif active_right != right:
        virtual(active_left, 8, right)
        destroy(left)
        memory.store(left+24, memory.load(right+24, 8), 8, source='BED8CB.SDK_left_owner')
        memory.store(right+24, right, 8, source='BED952.SDK_right_inline')
    else:
        virtual(active_left, 8, frame+32)
        destroy(left)
        memory.store(left+24, 0, 8, source='BED90E.SDK_left_reset')
        virtual(active_right, 8, left)
        destroy(right)
        memory.store(right+24, 0, 8, source='BED92D.SDK_right_reset')
        memory.store(left+24, left, 8, source='BED935.SDK_left_inline')
        virtual(frame+32, 8, right)
        virtual(frame+32, 24)
        memory.store(right+24, right, 8, source='BED952.SDK_right_inline')
    memory.unmap(frame)


def construct_objects(runtime):
    from .primary_worker_consumer import _invoke
    from .primary_worker_response import _frame
    memory, base = runtime.memory, runtime.image_base
    frame, unused = _frame(runtime, 32, '2C5C7F0 source inline functor temporary')
    for rva, table_rva, function in ((0x6D83BC8, 0x433B1F8, 0x2C5C8F0),
                                     (0x6D83BF0, 0x433B1F8, 0x2C5C9A0),
                                     (0x6D83C18, 0x433B2E8, 0xB8E60)):
        destination, table = base + rva, base + table_rva
        memory.store(frame, table, 8, source='2C5C7F0.temporary_vtable')
        memory.store(frame + 8, base + function, 8, source='2C5C7F0.temporary_capture')
        memory.store(frame + 24, frame, 8, source='2C5C7F0.temporary_inline_owner')
        _invoke(runtime, 0xBED870, frame, destination)
        active = memory.load(frame + 24, 8)
        if active:
            _destroy(runtime, memory.load(active, 8), active, active != frame)
        runtime.events.append(("SDK.object_constructed", destination, base + function))
    memory.unmap(frame)
    return 0


def _invoke_values(runtime, address, values):
    vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    return runtime.invoke(vm, address - runtime.image_base, tuple(range(len(values))))


def receiver_state(runtime):
    memory, base = runtime.memory, runtime.image_base
    gate, guard = base + 0x6751AB8, base + 0x6751B30
    flags = memory.load(guard, 4)
    if not flags & 1:
        memory.store(guard, flags | 1, 4, source="BA21D6.receiver_guard_claim")
        memory.store(gate, 0, 2, source="BA21DC.receiver_flags")
        memory.write(gate + 8, bytes(16), source="BA21E8.receiver_empty")
        memory.write(gate + 0x20, bytes(16), source="BA21EF.receiver_list_empty")
        memory.store(gate + 0x18, gate + 0x20, 8, source="BA21FD.receiver_list_head")
        memory.store(gate + 0x30, 1, 8, source="BA2204.receiver_list_limit")
        _invoke_values(runtime, base + 0x75B000, (gate + 0x38,))
        memory.write(gate + 0x68, bytes(16), source="BA221B.receiver_pending_empty")
        memory.store(gate + 0x60, gate + 0x68, 8, source="BA2229.receiver_pending_head")
        _invoke_values(runtime, base + 0x3E680B4, (base + 0xBCEDF0,))
    return gate


def _add_owner(runtime, control):
    address = control + 8
    value = runtime.memory.load(address, 4)
    runtime.memory.store(address, value + 1, 4, source="receiver.owner_add")


def release_weak(runtime, control):
    memory = runtime.memory
    value = memory.load(control + 16, 4)
    if value:
        memory.store(control + 16, value - 1, 4, source="75AD9C.weak_release")
        return None
    target = memory.load(memory.load(control, 8) + 24, 8)
    return _invoke_values(runtime, target, (control,))


def _release_owner(runtime, control):
    if control:
        memory = runtime.memory
        previous = memory.load(control + 8, 4)
        memory.store(control + 8, previous - 1, 4, source="receiver.owner_release")
        if not previous:
            target = memory.load(memory.load(control, 8) + 8, 8)
            _invoke_values(runtime, target, (control,))
            release_weak(runtime, control)


def destroy_receiver_tree(runtime, header, node, owned_payload):
    if not node:
        return None
    memory = runtime.memory
    destroy_receiver_tree(runtime, header, memory.load(node, 8), owned_payload)
    destroy_receiver_tree(runtime, header, memory.load(node + 8, 8), owned_payload)
    if owned_payload:
        if memory.load(node + 0x20, 1) & 1:
            runtime._free_allocation(memory.load(node + 0x30, 8))
    else:
        _release_owner(runtime, memory.load(node + 0x30, 8))
    runtime._free_allocation(node)
    return None


def destroy_receiver_state(runtime):
    memory, base = runtime.memory, runtime.image_base
    destroy_receiver_tree(runtime, base + 0x6751B18, memory.load(base + 0x6751B20, 8), True)
    _invoke_values(runtime, base + 0x75B030, (base + 0x6751AF0,))
    destroy_receiver_tree(runtime, base + 0x6751AD0, memory.load(base + 0x6751AD8, 8), False)
    _release_owner(runtime, memory.load(base + 0x6751AC8, 8))
    return None


def _assign_receiver(runtime, gate, read_pair):
    memory = runtime.memory
    pointer, control = read_pair(0), read_pair(8)
    if control:
        _add_owner(runtime, control)
    memory.store(gate + 8, pointer, 8, source="1CE2BEA.receiver_pointer")
    previous = memory.load(gate + 16, 8)
    memory.store(gate + 16, control, 8, source="1CE2BF2.receiver_control")
    _release_owner(runtime, previous)
    _release_owner(runtime, read_pair(8))
    return None


def construct_receiver(runtime, context):
    memory, base = runtime.memory, runtime.image_base
    if not memory.load(base + 0x6D83BE0, 8) or not memory.load(base + 0x6D83C08, 8):
        construct_objects(runtime)
    control = runtime._allocate(40, False)
    memory.store(control + 8, 0, 4, source="1BE309D.owner_init")
    memory.store(control + 16, 0, 4, source="1BE30A4.weak_init")
    memory.store(control, base + 0x41487B8, 8, source="1BE30B2.control_vtable")
    memory.store(control + 24, base + 0x41486F8, 8, source="1BE30BC.receiver_vtable")
    memory.store(control + 32, context, 8, source="1BE30C0.receiver_context")
    gate = receiver_state(runtime)
    _add_owner(runtime, control)
    pair = (control + 24, control)
    _assign_receiver(runtime, gate, lambda offset: pair[offset // 8])
    _release_owner(runtime, control)
    return None


def receiver_gate(runtime, flags_address=None):
    memory = runtime.memory
    flags_address = runtime.image_base + 0x6751AB8 if flags_address is None else flags_address

    def call_receiver():
        pointer = memory.load(receiver_state(runtime) + 8, 8)
        if not pointer:
            raise PrimarySemanticUnavailable("native refresh receiver disappeared before virtual call")
        target = memory.load(memory.load(pointer, 8) + 16, 8)
        value = _invoke_values(runtime, target, (pointer,))
        if type(value) is not int:
            raise PrimarySemanticUnavailable("native refresh receiver slot10 needs a known DWORD return")
        return value & 0xFFFFFFFF

    if memory.load(receiver_state(runtime) + 8, 8) and call_receiver() != 0:
        return NativeByteReturn(int(call_receiver() == 1))
    return NativeByteReturn(memory.load(flags_address, 1) & 1)


def bootstrap(runtime):
    memory, base = runtime.memory, runtime.image_base
    initialized = memory.load(base + 0x677CE88, 1)
    target = memory.load(base + 0x490FC80, 8)
    if initialized:
        return None
    first = memory.load(base + 0x6D83BE0, 8)
    memory.store(base + 0x677CE88, 1, 1, source="1C1BB47.bootstrap_claim")
    if not first or not memory.load(base + 0x6D83C08, 8):
        construct_objects(runtime)
    handle = _invoke_values(runtime, target, (0, 0, base + 0x1C1BB80, 0, 0, 0))
    if type(handle) is not int or not 0 <= handle < 1 << 64:
        raise PrimarySemanticUnavailable("SDK bootstrap thread target needs a known pointer-width result")
    memory.store(base + 0x677CE80, handle, 8, source="1C1BB22.thread_handle")
    return None


def _advance_material_key(value, index):
    feedback = ((value >> 7) ^ (value >> 5) ^ (value >> 4) ^ (value >> 3)) & 1
    value = (((value << 1) | feedback) ^ (0x37 + index * 0x9E)) & 255
    value = ((value << 3) | (value >> 5)) & 255
    return value or (index ^ 0xA5)


def _material_keys(seed):
    result = []
    for index in range(32):
        seed = _advance_material_key(seed, index)
        result.append(seed)
    return result


def update_material_control(runtime, value, bit, operation, flag):
    memory, base = runtime.memory, runtime.image_base
    bit, operation, flag = bit & 0xFFFFFFFF, operation & 0xFFFFFFFF, flag & 255
    context = _invoke_values(runtime, base + 0x3591D6C, ())
    _invoke_values(runtime, base + 0x3591E38, (context,))
    seed_address = context + (0x840 if flag else 0x841)
    selectors = context + (0x800 if flag else 0x820)
    keys = _material_keys(memory.load(seed_address, 1))
    decoded = bytearray()
    for index in range(32):
        selector = memory.load(selectors + index, 1)
        decoded.append(memory.load(context + selector * 8 + 3, 1) ^ keys[index])
    if operation in (2, 3):
        current = int.from_bytes(decoded[:8], "little")
        current = current | value if operation == 2 else current & value
        decoded[:8] = (current & _MASK64).to_bytes(8, "little")
    elif operation == 1 and bit <= 255:
        index, mask = bit >> 3, 1 << (bit & 7)
        decoded[index] = decoded[index] | mask if value == 1 else decoded[index] & (mask ^ 255)
    seed = memory.load(seed_address, 1)
    seed = _advance_material_key(seed, seed & 31)
    memory.store(seed_address, seed, 1, source="2DE8E75.material_control_seed")
    keys = _material_keys(seed)
    for index in range(32):
        selector = memory.load(selectors + index, 1)
        record = context + selector * 8
        memory.store(record + 3, keys[index] ^ decoded[index], 1,
                     source="2DE8F10.material_encoded_value" if index == 0 else "2DE8F37.material_encoded_value")
        memory.store(record, keys[index] ^ index, 1,
                     source="2DE8F19.material_encoded_index" if index == 0 else "2DE8F41.material_encoded_index")
        memory.store(record + 4, keys[index] ^ 255, 1,
                     source="2DE8F22.material_key_complement" if index == 0 else "2DE8F4A.material_key_complement")
    noise = memory.load(context + 0x841, 1) ^ memory.load(context + 0x840, 1)
    for index in range(256):
        selected = False
        for position in range(32):
            if memory.load(context + 0x800 + position, 1) == index or memory.load(context + 0x820 + position, 1) == index:
                selected = True
                break
        if selected:
            continue
        noise = _advance_material_key(noise, index)
        record = context + index * 8
        memory.store(record + 3, noise, 1, source="2DE8FC9.material_noise_value")
        memory.store(record, noise ^ index, 1, source="2DE8FD1.material_noise_index")
        memory.store(record + 4, noise ^ 255, 1, source="2DE8FD8.material_noise_complement")
    _invoke_values(runtime, base + 0x3591E46, (context,))
    return None


def invoke(runtime, rva, values):
    memory, base = runtime.memory, runtime.image_base
    if rva == 0x28F0:
        if len(values) not in (0, 1):
            raise InputError('RET callback accepts its zero-argument exit or one-argument functor call')
        return None
    arity = {0x2C5C7F0: 0, 0x1C00BC0: 2, 0x1C00BF0: 2, 0x1C00F90: 0,
             0x2C5CAA0: 3, 0x2C5CB70: 1, 0x2C5C8F0: 2, 0x2C5C9A0: 2,
             0xB8E60: 0, 0x3586170: 4, 0x75BEA0: 3, 0x75BEB0: 3,
             0x2C5CA50: 2, 0x2C5CB20: 2, 0x1BE3060: 1, 0xBA21A0: 0,
             0x1CE2BD0: 2, 0x1CE2B70: 1, 0x75AD90: 1, 0x75B000: 1,
             0x787720: 1, 0x1FE0: 1, 0x63EC0: 1, 0x1C1BA80: 0,
             0x2DE8CAF: 4, 0x2DE8C9D: 0, 0xBCEDF0: 0, 0xBCEE60: 2, 0xBCEED0: 2}
    if len(values) != arity[rva]:
        raise InputError("SDK callback arguments differ from the captured ABI")
    if rva == 0x2C5C7F0:
        return construct_objects(runtime)
    if rva == 0x1C1BA80:
        return bootstrap(runtime)
    if rva == 0x2DE8CAF:
        return update_material_control(runtime, *values)
    if rva == 0x2DE8C9D:
        return base + 0x2DE8CAF
    if rva == 0x1BE3060:
        return construct_receiver(runtime, values[0])
    if rva == 0xBA21A0:
        return receiver_state(runtime)
    if rva == 0xBCEDF0:
        return destroy_receiver_state(runtime)
    if rva in (0xBCEE60, 0xBCEED0):
        return destroy_receiver_tree(runtime, *values, rva == 0xBCEED0)
    if rva == 0x1CE2BD0:
        gate, pair = values
        return _assign_receiver(runtime, gate, lambda offset: memory.load(pair + offset, 8))
    if rva == 0x1CE2B70:
        return receiver_gate(runtime, values[0])
    if rva == 0x75AD90:
        return release_weak(runtime, values[0])
    if rva == 0x1FE0:
        runtime._free_allocation(values[0])
        return None
    if rva == 0x63EC0:
        return 0
    if rva == 0x75B000:
        _invoke_values(runtime, base + 0x787720, values)
        return values[0]
    if rva == 0x787720:
        target = memory.load(base + 0x49100D8, 8)
        if target in (base + 0x75B000, base + 0x787720):
            raise PrimarySemanticUnavailable("cyclic receiver critical-section import")
        _invoke_values(runtime, target, values)
        return 0
    if rva in (0x1C00BC0, 0x1C00BF0, 0x1C00F90):
        slot = {0x1C00BC0: 0x6D83BE0, 0x1C00BF0: 0x6D83C08, 0x1C00F90: 0x6D83C30}[rva]
        pointer = memory.load(base + slot, 8)
        if not pointer:
            raise PrimarySemanticUnavailable("002374 absent SDK callback object exception")
        target = memory.load(memory.load(pointer, 8) + 40, 8)
        return _invoke_values(runtime, target, (pointer, *values))
    if rva in (0x2C5CAA0, 0x2C5CB70):
        target = memory.load(values[0] + 8, 8)
        return _invoke_values(runtime, target, values[1:])
    if rva in (0x2C5C8F0, 0x2C5C9A0):
        return transform_string(runtime, *values, 1 if rva == 0x2C5C8F0 else 2)
    if rva == 0xB8E60:
        return NativeByteReturn(1)
    if rva == 0x3586170:
        return transform(runtime, *values)
    if rva in (0x75BEA0, 0x75BEB0):
        return assign_string(runtime, *values)
    source, destination = values
    memory.store(destination, base + (0x433B1F8 if rva == 0x2C5CA50 else 0x433B2E8),
                 8, source="2C5CA57.clone_vtable")
    memory.store(destination + 8, memory.load(source + 8, 8), 8, source="2C5CA5E.clone_capture")
    return memory.load(source + 8, 8)
