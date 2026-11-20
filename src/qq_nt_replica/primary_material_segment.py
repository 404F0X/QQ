from .primary_material_cipher import _advance, _normal_dispatch
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_ecrypt import _indexed_pointer, _native_call


def _normal_known(vm, compare_globals=False):
    try:
        if compare_globals:
            return _normal_dispatch(vm)
        return vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) != -0x80000000
    except UnknownMemory:
        return False


def _state(vm):
    state = getattr(vm, 'primary_material_segment_state', None)
    if state is None:
        state = {'filler_bytes': 0, 'decoded_bytes': 0, 'mixed_bytes': 0}
        vm.primary_material_segment_state = state
    return state


def _index(vm, source, destination, value):
    vm._write(source, value, 8, 'material_segment.index')
    vm.execute_once(10, (7, 3, source, destination))
    return vm.cells.value(destination)


def fill_primary_material_segment(vm):
    if not _normal_known(vm):
        return False
    vm.pc = 17727
    source = 158 if vm.predecessor == 421 else 2542 if vm.predecessor == 430 else None
    if source is None:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(2541, vm.cells.value(source), 8, 'L9.phi_q')
    index = vm.cells.value(2541) & 0xFFFFFFFF
    state = _state(vm)
    pointer = vm.cells.value(865)
    while index < 32:
        current = (vm.memory.load(pointer, 4) + 0x9E3779B9) & 0xFFFFFFFF
        vm.memory.store(pointer, current, 4, source='material_segment.filler_state')
        value = current ^ (current >> 14)
        value ^= value >> 6
        value = 1 + (((value & 255) * 254) >> 8)
        offset = _index(vm, 2541, 3259, index)
        vm.memory.store(vm.cells.value(122) + offset, value, 1,
                        source='material_segment.first_filler')
        vm.memory.store(vm.cells.value(123) + offset, value, 1,
                        source='material_segment.second_filler')
        state['filler_bytes'] += 1
        index += 1
    vm._write(2541, index, 8, 'material_segment.filler_end')
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 17736, 431, 429, False
    vm.auxiliary = (0, 508215298)
    return True


def decode_primary_material_segment(vm):
    if not _normal_known(vm, compare_globals=True):
        return False
    length = vm.cells.value(2626) & 0xFFFFFFFF
    if length not in (1, 2, 4, 8):
        return False
    state = _state(vm)
    plain, mask, output = (vm.cells.value(cell) for cell in (2629, 70, 2619))
    value = (vm.cells.value(2654) ^ 55) & 255
    value = ((value << 3) | (value >> 5)) & 255
    vm.memory.store(mask, value or 0xA5, 1, source='material_segment.decode_mask')
    for index in range(1, length):
        previous = _index(vm, 2665, 2666, index - 1)
        value = _advance(vm.memory.load(mask + previous, 1), index)
        offset = _index(vm, 2662, 2690, index)
        vm.memory.store(mask + offset, value, 1, source='material_segment.decode_mask')
    for index in range(length):
        offset = _index(vm, 2692, 2695, index)
        value = vm.memory.load(mask + offset, 1)
        value ^= vm.memory.load(plain + offset, 1)
        vm.memory.store(plain + offset, value, 1, source='material_segment.decode_byte')
        state['decoded_bytes'] += 1
    offset = 0
    while offset < (length & ~3):
        value = vm.memory.load(plain + offset, 4)
        vm.memory.store(output + offset, value, 4, source='material_segment.decoded_word')
        offset += 4
    while offset < length:
        value = vm.memory.load(plain + offset, 1)
        vm.memory.store(output + offset, value, 1, source='material_segment.decoded_tail')
        offset += 1
    for pointer in (plain, mask):
        for index in range(8):
            vm.memory.store(pointer + index, 0, 1, source='material_segment.decode_clear')
    vm._write(2726, vm.memory.load(vm.cells.value(33), 8), 8,
              'material_segment.decoded_value')
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 19110, 443, 466, False
    vm.auxiliary = (0, 1435691859)
    return True


def mix_primary_material_segment(vm):
    if not _normal_known(vm, compare_globals=True):
        return False
    state = _state(vm)
    current = vm.cells.value(3139) & 0xFFFFFFFF
    source, target = vm.cells.value(3141), vm.cells.value(3140)
    for index in range(6):
        current = (current * 0x1B873593) & 0xFFFFFFFF
        spread = current ^ (current >> 15)
        offset = _index(vm, 3142, 3153, index) * 4
        value = vm.memory.load(source + offset, 4) ^ spread
        value ^= vm.memory.load(target + offset, 4)
        vm.memory.store(target + offset, value, 4, source='material_segment.mix_word')
        state['mixed_bytes'] += 4
    current = (current * 0x1B873593) & 0xFFFFFFFF
    spread = current ^ (current >> 15)
    value = vm.memory.load(vm.cells.value(3135) + 24, 1) ^ (spread & 255)
    value ^= vm.memory.load(vm.cells.value(2729) + 24, 1)
    vm.memory.store(vm.cells.value(2729) + 24, value, 1,
                    source='material_segment.mix_tail')
    state['mixed_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 22461, 550, 548, False
    vm.auxiliary = (0, 578987237)
    return True


def _copy_field(vm, source, target, size):
    offset = 0
    while offset < size and (size == 2 or (target + offset) & 3):
        value = vm.memory.load(source + offset, 1)
        vm.memory.store(target + offset, value, 1, source='material_segment.field_copy_byte')
        offset += 1
    while offset + 4 <= size:
        value = vm.memory.load(source + offset, 4)
        vm.memory.store(target + offset, value, 4, source='material_segment.field_copy_word')
        offset += 4
    while offset < size:
        value = vm.memory.load(source + offset, 1)
        vm.memory.store(target + offset, value, 1, source='material_segment.field_copy_tail')
        offset += 1


def assemble_primary_material_fields(vm):
    joined = vm.pc == 19119
    if not joined:
        vm.pc = 19119
        source = 2726 if vm.predecessor == 466 else 145 if vm.predecessor in (435, 444) else None
        if source is None:
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        vm._write(2727, vm.cells.value(source), 8, 'L9.phi_q')
    state = _state(vm)
    state['assembled_fields'] = 0
    state['assembled_bytes'] = 0
    value = vm.memory.load(vm.cells.pointer(2727), 1)
    target = vm.cells.value(122) + 1
    vm._write(2729, target, 8, 'material_segment.material_byte_pointer')
    value ^= vm.memory.load(target, 1)
    vm.memory.store(target, value, 1, source='material_segment.material_byte')
    state['assembled_fields'] += 1
    state['assembled_bytes'] += 1
    temporary = vm.cells.value(125)
    target = vm.cells.value(122) + 2
    value = vm.memory.load(target, 2)
    value ^= vm.memory.load(vm.cells.pointer(284), 2)
    vm.memory.store(temporary, value, 2, source='material_segment.first_word')
    _copy_field(vm, temporary, target, 2)
    state['assembled_fields'] += 1
    state['assembled_bytes'] += 2
    source = vm.cells.value(123) + 4
    value = vm.memory.load(vm.cells.value(615), 1)
    target = vm.cells.value(122) + 4
    value ^= vm.memory.load(source, 1)
    vm.memory.store(target, value, 1, source='material_segment.first_control')
    state['assembled_fields'] += 1
    state['assembled_bytes'] += 1
    target = vm.cells.value(122) + 5
    value = vm.memory.load(target, 1)
    value ^= vm.memory.load(vm.cells.pointer(2538), 1) ^ 0xFA
    vm.memory.store(target, value, 1, source='material_segment.second_control')
    state['assembled_fields'] += 1
    state['assembled_bytes'] += 1
    temporary = vm.cells.value(126)
    value = vm.memory.load(vm.cells.value(106) + 36, 2)
    target = vm.cells.value(122) + 6
    value ^= vm.memory.load(target, 2)
    vm.memory.store(temporary, value, 2, source='material_segment.second_word')
    _copy_field(vm, temporary, target, 2)
    state['assembled_fields'] += 1
    state['assembled_bytes'] += 2
    for temporary_cell, offset in ((127, 8), (128, 16)):
        temporary = vm.cells.value(temporary_cell)
        value = vm.memory.load(vm.cells.value(105) + offset - 8, 8)
        target = vm.cells.value(122) + offset
        if offset == 16:
            vm._write(3012, target, 8, 'material_segment.later_checksum_pointer')
        value ^= vm.memory.load(target, 8)
        vm.memory.store(temporary, value, 8, source='material_segment.qword_field')
        _copy_field(vm, temporary, target, 8)
        state['assembled_fields'] += 1
        state['assembled_bytes'] += 8
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 22016, 542, 540, False
    vm.auxiliary = (0, 803405382)
    if joined:
        prepare_primary_material_random_input(vm)
    return True


def prepare_primary_material_random_input(vm):
    _indexed_pointer(vm, 22016, 3103, 9, 14, (145, 145))
    _native_call(vm, 22024, 22033, 121, 157, (3103, 158, 421), 3104)
    _native_call(vm, 22033, 22040, 160, 3106, (3107,), 3105)
    vm.pc = 22045
    vm._write(3108, vm.cells.value(3105) & 0xFFFFFFFF, 8, 'once9.mask_q')
    _native_call(vm, 22045, 22051, 147, 965, (3108,))
    _native_call(vm, 22051, 22057, 129, 3110, (), 3109)
    _indexed_pointer(vm, 22057, 3111, 9, 14, (145, 145))
    _indexed_pointer(vm, 22065, 3112, 54, 3113, (145, 145))
    _format_primary_material_pid(vm)
    _native_call(vm, 22085, 22091, 129, 984, (), 3116)
    _native_call(vm, 22091, 22098, 164, 3118, (3111,), 3117)
    vm.pc = 22103
    vm._write(3119, int(vm.cells.value(3117) > vm.cells.value(421)), 4, 'L31.comparison')
    vm._jump(543 if vm.cells.value(3119) else 544)
    if vm.block == 544:
        _native_call(vm, 22107, 22114, 164, 3118, (3111,), 3120)
        vm._jump(543)
    return True


def _format_primary_material_pid(vm):
    from .primary_sign import _invoke_host

    memory, base = vm.memory, vm.image_base
    vm.pc = 22074
    if memory.load(base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('variadic call current-global alternate route is unavailable')
    vm.pc = 22078
    x = memory.load(base + 0x677E1B4, 4, signed=True)
    y = memory.load(base + 0x677E1B8, 4, signed=True)
    if (((x * x + y * y) & 0xFFFFFFFF) | ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('variadic call F-global alternate route is unavailable')
    vm.pc = 22080
    x = memory.load(base + 0x6D86090, 4)
    y = memory.load(base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('variadic call G-global alternate route is unavailable')
    vm.pc = 22085
    arguments = (3111, 421, 3112, 3109)
    address = vm.cells.value(3115)
    vm.host_calls.append((22073, address, arguments, 162))
    result = _invoke_host(vm, address, arguments, 162, argument_types=(2, 7, 2, 3))
    vm._write(3114, result, 8, 'high.variadic_result_q')


def consume_primary_material_random_byte(vm):
    if not _normal_known(vm, compare_globals=True):
        return False
    vm.pc = 22123
    source = 3120 if vm.predecessor == 544 else 421 if vm.predecessor == 542 else None
    if source is None:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(3121, vm.cells.value(source), 8, 'L9.phi_q')
    state = _state(vm)
    vm.execute_once(10, (7, 3, 3116, 3122))
    random = vm.cells.value(3122)
    length = vm.cells.value(3121)
    if length == 0:
        raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
    index = random % length
    vm._write(3123, index, 8, 'material_segment.random_index')
    value = vm.memory.load(vm.cells.value(14) + (index & 0xFFFFFFFF), 1) & 15
    value |= ((index & 255) << 4) & 255
    target = vm.cells.value(122) + 24
    value ^= vm.memory.load(target, 1)
    vm.memory.store(target, value, 1, source='material_segment.random_nibbles')
    state['randomized_bytes'] = 1
    state['random_index'] = index
    source = vm.cells.value(123) + 1
    vm._write(3135, source, 8, 'material_segment.companion_mix_pointer')
    value = vm.memory.load(vm.cells.value(2614), 1)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value ^= vm.memory.load(vm.cells.pointer(3138), 4)
    vm._write(3139, value, 8, 'material_segment.mix_seed')
    vm._write(3140, vm.cells.value(2729), 8, 'material_segment.mix_target')
    vm._write(3141, source, 8, 'material_segment.mix_source')
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 22232, 545, 543, False
    vm.auxiliary = (0, 19045)
    return True
