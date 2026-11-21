from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, once_index
from .primary_ecrypt import _indexed_pointer, _native_call


def _flag0(vm):
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')


def _class6(vm, word, left=None, right=None):
    vm.pc = word + 1
    flag, typ, source, other, destination = tuple(vm._operand() for _ in range(5))
    vm.auxiliary = (0, vm.program.words[word - 1])
    if flag != 0:
        raise PrimarySemanticUnavailable('material class6 requires fixed flag0 record')
    if left is not None:
        vm._write(source, left, 8, 'material_state.class6_left')
    if right is not None:
        vm._write(other, right, 8, 'material_state.class6_right')
    operands = (typ, source, other, destination)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        vm.execute_typed(operands)
    vm.execute_typed(operands)
    return vm.cells.value(destination)


def _comparison(vm):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')


def _left(vm, value, count, word, *, bits=32):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        operands = tuple(vm.program.words[word + 1:word + 5])
        vm._write(operands[1], value, 8, 'material_state.alternate_shift_source')
        vm.auxiliary = (0, vm.program.words[word - 1])
        vm.pc = word + 5
        vm.execute_typed(operands)
        vm.execute_typed(vm._typed_operands())
        raise PrimarySemanticUnavailable('material initializer current-global shifted-PC route is unavailable')
    return (value & ((1 << bits) - 1)) << count


def _truncate(vm, word):
    vm.pc = word
    if once_index(vm._operand()) != 9:
        raise PrimarySemanticUnavailable('material producer requires fixed once9 record')
    typ = vm._operand()
    current = (vm.pc + 1) & 0xFFFFFFFF
    vm.pc = (current + 1) & 0xFFFFFFFF
    if not 0 <= current < len(vm.program.words):
        raise PrimaryProgramLimit(f'operand read beyond program at word {current}')
    source = vm.program.words[current]
    destination = vm._operand()
    vm.execute_once(9, (typ, 0, source, destination))


def _produce(vm, word, value):
    records = {
        177: (164, 39),
        195: (190, 43),
        214: (209, 47),
        463: (450, 83),
        486: (481, 71),
        512: (507, 94),
        517: (476, 87),
        536: (531, 98),
        643: (621, 112),
        926: (921, 146),
        989: (984, 165),
        1068: (1063, 180),
        1471: (1458, 232),
        1486: (1481, 236),
        1505: (1500, 239),
        1704: (1691, 268),
        1740: (1735, 275),
        1745: (1714, 272),
        1764: (1759, 279),
        1984: (1979, 292),
        2175: (2170, 333),
        2331: (2318, 360),
        2354: (2349, 333),
        2380: (2375, 369),
        2385: (2344, 364),
        2400: (2395, 373),
        2727: (2714, 412),
        2742: (2737, 416),
        2757: (2752, 419),
        2952: (2939, 445),
        2991: (2986, 452),
        2996: (2965, 449),
        3015: (3010, 456),
        3240: (3235, 469),
        3443: (3438, 509),
        3599: (3586, 536),
        3619: (3614, 509),
        3645: (3640, 545),
        3650: (3609, 540),
        3669: (3664, 549),
    }
    producer, source = records[word]
    if word not in (486, 926, 1984, 2175, 2354, 3240, 3443, 3619, 536, 3669):
        vm.pc = producer
        vm._write(source, value, 8, 'material_state.producer_q')
    _truncate(vm, producer)


def _phi(vm, word, predecessor):
    vm.pc = word
    vm._operand()
    destination, count = vm._operand(), vm._operand()
    matched = False
    for _ in range(count):
        source = vm._operand()
        current = vm.pc
        vm.pc = (current + 1) & 0xFFFFFFFF
        if not matched:
            if not 0 <= current < len(vm.program.words):
                raise PrimaryProgramLimit(f'operand read beyond program at word {current}')
            if vm.program.words[current] == predecessor:
                vm._write(destination, vm.cells.value(source), 8, 'material_state.phi_q')
                matched = True


def _select_byte(vm, word):
    vm.pc = word
    vm._operand()
    condition_type, condition, result_type, true, false = tuple(vm._operand() for _ in range(5))
    current = vm.pc
    vm.pc = (current + 1) & 0xFFFFFFFF
    if vm.program.type(condition_type).raw == 0x15:
        raise PrimarySemanticUnavailable('material selected condition requires fixed scalar type')
    destination = vm.program.words[current]
    selected = true if vm.cells.value(condition) else false
    value = vm._signed_cell(selected, result_type)
    vm._write(destination, value, 8, 'material_state.selected_q')
    return value


def _converted(vm, word, source, value, size=8):
    if size == 8:
        _produce(vm, word, value)
    else:
        vm._write(source, value, size, 'material_state.conversion_source')
    return _once10(vm, word)


def _once10(vm, word):
    vm.pc = word
    if once_index(vm._operand()) != 10:
        raise PrimarySemanticUnavailable('material conversion requires fixed once10 record')
    typ = vm._operand()
    current = (vm.pc + 1) & 0xFFFFFFFF
    vm.pc = (current + 1) & 0xFFFFFFFF
    if not 0 <= current < len(vm.program.words):
        raise PrimaryProgramLimit(f'operand read beyond program at word {current}')
    source = vm.program.words[current]
    destination = vm._operand()
    vm.execute_once(10, (typ, 0, source, destination))
    return vm.cells.value(destination)


def _advance(vm, value, index, shifts, *, feedback_guard=False,
             salt_guard=False, fallback_guard=False, salt=None, fallback=None):
    if feedback_guard:
        _flag0(vm)
    feedback = ((value >> 7) ^ (value >> 5) ^ (value >> 4) ^ (value >> 3)) & 1
    value = (_left(vm, value, 1, shifts[0]) | feedback) & 255
    if salt_guard:
        _flag0(vm)
    value ^= (55 + 158 * (index & 255)) & 255 if salt is None else salt
    value = (_left(vm, value, 3, shifts[1]) | (value >> 5)) & 255
    if fallback_guard:
        _flag0(vm)
    return value or (((index & 255) ^ 0xA5) if fallback is None else fallback)


def _advance_material(vm, value, index, shifts, *, feedback_guard=False,
             salt_guard=False, fallback_guard=False, salt=None, fallback=None):
    groups = {
        172: (None, (177, 40), None, None, (195, 44), (214, 48)),
        458: ((380, 69), (463, 84), (486, 89), (512, 95), (517, 88), (536, 99)),
        1466: (None, (1471, 233), None, None, (1486, 237), (1505, 240)),
        1699: (None, (1704, 269), None, (1740, 276), (1745, 273), (1764, 280)),
        2326: ((2256, 331), (2331, 361), (2354, 366), (2380, 370), (2385, 365), (2400, 374)),
        2722: (None, (2727, 413), None, None, (2742, 417), (2757, 420)),
        2947: (None, (2952, 446), None, (2991, 453), (2996, 450), (3015, 457)),
        3594: ((3524, 507), (3599, 537), (3619, 542), (3645, 546), (3650, 541), (3669, 550)),
    }
    carried, feedback_record, index_record, salt_record, advanced_record, salted_record = groups[shifts[0]]
    if carried:
        value = _once10(vm, carried[0])
    if feedback_guard:
        word = {458: 405, 1699: 1643, 2326: 2281, 2722: 2669, 2947: 2912}[shifts[0]]
        if word == 2912:
            feedback = _class6(vm, word, (value >> 7) ^ (value >> 5), value >> 4)
        else:
            feedback = _class6(vm, word, value >> 7, value >> 5) ^ (value >> 4)
        feedback = (feedback ^ (value >> 3)) & 1
    else:
        feedback = ((value >> 7) ^ (value >> 5) ^ (value >> 4) ^ (value >> 3)) & 1
    _produce(vm, feedback_record[0], feedback)
    shifted = _left(vm, value, 1, shifts[0])
    feedback = _once10(vm, feedback_record[0])
    shifted &= 0xFFFFFFFF
    shifted = shifted if shifted < 0x80000000 else shifted - 0x100000000
    _produce(vm, advanced_record[0], shifted | feedback)
    if index_record:
        index_value = _converted(vm, *index_record, None)
    else:
        index_value = index
    salt = 55 + 158 * index_value if salt is None else salt
    if salt_record:
        salt = _converted(vm, *salt_record, salt)
    advanced = _once10(vm, advanced_record[0])
    if salt_guard:
        value = _class6(vm, 525 if shifts[0] == 458 else 3658, advanced, salt)
    else:
        value = advanced ^ salt
    value = _converted(vm, *salted_record, value)
    rotated = _left(vm, value, 3, shifts[1]) | (value >> 5)
    endings = {
        172: (243, 52, 53, 251, 55, None, 256),
        458: (565, 103, 104, 573, 105, (583, 107), 588),
        1466: (1534, 244, 245, 1542, 246, None, 1547),
        1699: (1793, 284, 285, 1801, 286, (1815, 287), 1820),
        2326: (2426, 378, 379, 2434, 380, (2444, 381), 2449),
        2722: (2786, 424, 425, 2794, 426, None, 2799),
        2947: (3044, 461, 462, 3052, 463, (3066, 464), 3071),
        3594: (3698, 554, 555, 3706, 556, (3716, 557), 3721),
    }
    truncate, source, truncated, comparison, condition, fallback_record, select = endings[shifts[0]]
    vm.pc = truncate
    vm._write(source, rotated, 8, 'material_state.rotated_q')
    _truncate(vm, truncate)
    vm.pc = comparison + 5
    nonzero = vm.memory.load(vm.cells.pointer(truncated), 1) != 0
    vm._write(condition, int(nonzero), 4, 'material_state.selected_condition')
    if fallback_guard:
        _class6(vm, 3060, index & 255)
    elif fallback_record:
        vm.pc = fallback_record[0]
        vm._write(fallback_record[1], index_value ^ 0xA5, 8, 'material_state.fallback_q')
    if fallback_record:
        _truncate(vm, fallback_record[0])
    return _select_byte(vm, select)


def _copy(vm, source, destination, size):
    for index in range(size):
        value = vm.memory.load(source + index, 1)
        vm.memory.store(destination + index, value, 1, source='material_state.byte_copy')


def _clear(vm, pointer):
    for index in range(32):
        vm.memory.store(pointer + index, 0, 1, source='material_state.clear_byte')


def _initial_slots(vm, context):
    memory = vm.memory
    for index in range(256):
        _phi(vm, 870, 13 if index == 0 else 18)
        pointer = context + 8 * index
        byte = _converted(vm, 926, 155, None)
        memory.store(pointer, pointer ^ 222 ^ byte, 1, source='material_state.slot_byte0')
        _converted(vm, 989, 166, index * 3)
        second = _class6(vm, 997, (pointer >> 8) ^ 173)
        memory.store(pointer + 1, second, 1,
                     source='material_state.slot_byte1')
        memory.store(pointer + 2, (index * 55) ^ 190, 1,
                     source='material_state.slot_byte2')
        product = _converted(vm, 1068, 181, index * 127)
        memory.store(pointer + 3, pointer ^ 90 ^ product, 1,
                     source='material_state.slot_byte3')
        _class6(vm, 1107, pointer >> 16)
        tail = _class6(vm, 1116)
        memory.store(pointer + 4, tail, 1, source='material_state.slot_byte4')
        fifth = _class6(vm, 1150, index)
        memory.store(pointer + 5, fifth, 1, source='material_state.slot_byte5')
        memory.store(pointer + 6, pointer ^ byte, 1, source='material_state.slot_byte6')
        memory.store(pointer + 7, (pointer >> 24) ^ 254, 1,
                     source='material_state.slot_byte7')
        vm._write(147, index + 1, 8, 'material_state.slot_next_index')


def _mask(vm, pointer, seed, second):
    value = _converted(vm, 2644 if second else 1385, 403 if second else 223, seed, size=4)
    value = _advance_material(vm, value, 0, (2722, 2765) if second else (1466, 1513),
                     feedback_guard=second)
    value = vm.memory.load(vm.cells.pointer(427 if second else 248), 1)
    vm.memory.store(pointer, value, 1, source='material_state.mask_first')
    for index in range(1, 33):
        _phi(vm, 2820 if second else 1568, (48 if index == 1 else 53) if second else (26 if index == 1 else 31))
        current = _once10(vm, 2827 if second else 1575)
        if current >= 32:
            break
        value = vm.memory.load(pointer + current - 1, 1)
        value = _converted(vm, 2871 if second else 1619, 436 if second else 259, value, size=4)
        value = _advance_material(vm, value, current, (2947, 3023) if second else (1699, 1772),
                         feedback_guard=True, fallback_guard=second)
        slot = _once10(vm, 3078 if second else 1827)
        value = vm.memory.load(vm.cells.pointer(466 if second else 289), 1)
        vm.memory.store(pointer + slot, value, 1, source='material_state.mask_byte')
        vm._write(430 if second else 252, index + 1, 8, 'material_state.mask_next_index')


def _selected_slots(vm, context, buffer, mask, second):
    memory = vm.memory
    keys = context + (2080 if second else 2048)
    key_source = 474 if second else 297
    for index in range(32):
        _phi(vm, 3107 if second else 1856, (54 if index == 0 else 56) if second else (32 if index == 0 else 34))
        key = memory.load(keys + index, 1)
        vm._write(key_source, key, 4, 'material_state.selected_key')
        value = memory.load(buffer + index, 1)
        value = _converted(vm, 3156 if second else 1905, 476 if second else 299, value, size=4)
        mask_value = memory.load(mask + index, 1)
        mask_value = _converted(vm, 3173 if second else 1922, 479 if second else 302, mask_value, size=4)
        if second:
            value = _class6(vm, 3182, value, mask_value)
        else:
            value ^= mask_value
        slot = _once10(vm, 3201 if second else 1945)
        pointer = context + 8 * slot
        memory.store(pointer + 3, value, 1, source='material_state.selected_byte3')
        value = memory.load(mask + index, 1)
        value = _converted(vm, 3230 if second else 1974, 487 if second else 310, value, size=4)
        current = _converted(vm, 3240 if second else 1984, 489 if second else 312, None)
        memory.store(pointer, value ^ current, 1, source='material_state.selected_byte0')
        value = memory.load(mask + index, 1)
        value = _converted(vm, 3283 if second else 2023, 495 if second else 318, value, size=4)
        memory.store(pointer + 4, value ^ 255, 1, source='material_state.selected_byte4')
        vm._write(470 if second else 293, index + 1, 8, 'material_state.selected_next_index')


def _unused_slots(vm, context, state, second):
    memory = vm.memory
    updates = 0
    for index in range(256):
        _phi(vm, 3367 if second else 2099, (57 if index == 0 else 59) if second else (35 if index == 0 else 37))
        _phi(vm, 3374 if second else 2106, (57 if index == 0 else 59) if second else (35 if index == 0 else 37))
        selected = False
        for key_index in range(32):
            key = memory.load(context + 2048 + key_index, 1)
            key = _converted(vm, 3433 if second else 2165, 517 if second else 341, key, size=4)
            current = _converted(vm, 3443 if second else 2175, 519 if second else 343, None)
            if not second:
                _comparison(vm)
            if key == current:
                selected = True
                break
            key = memory.load(context + 2080 + key_index, 1)
            key = _converted(vm, 3473 if second else 2205, 523 if second else 347, key, size=4)
            if not second:
                _comparison(vm)
            if key == current:
                selected = True
                break
        if selected:
            _phi(vm, 3832 if second else 2564, 65 if second else 43)
            vm._write(510 if second else 334, index + 1, 8, 'material_state.unused_next_index')
            continue
        state = _advance_material(vm, state, index, (3594, 3677) if second else (2326, 2408),
                         feedback_guard=not second, salt_guard=second)
        pointer = context + 8 * index
        source = 559 if second else 383
        byte = vm.memory.load(vm.cells.pointer(source), 1)
        memory.store(pointer + 3, byte, 1, source='material_state.unused_byte3')
        current = _once10(vm, 3761 if second else 2489)
        memory.store(pointer, current ^ index, 1, source='material_state.unused_byte0')
        current = vm.cells.value(564 if second else 388)
        memory.store(pointer + 4, current ^ 255, 1, source='material_state.unused_byte4')
        updates += 1
        _phi(vm, 3832 if second else 2564, 68 if second else 46)
        vm._write(510 if second else 334, index + 1, 8, 'material_state.unused_next_index')
    return updates


def _initialize(vm):
    for word, typ, destination in ((1, 1, 1), (4, 6, 2), (7, 15, 3),
                                   (10, 24, 4), (13, 6, 5), (16, 6, 6)):
        vm.pc = word + 3
        vm._allocate(typ, destination)
    vm.pc = 24
    vm.cells.copy_q_clear_owned(2, 7)
    _indexed_pointer(vm, 24, 8, 26, 9, (10, 10))
    _native_call(vm, 32, 41, 28, 12, (1, 8, 13), 11)
    vm.pc = 46
    vm.cells.copy_q_clear_owned(3, 14)
    _native_call(vm, 46, 52, 20, 15, (0,))


def _return(vm):
    vm.pc, vm.halted = 3851, True


def run_primary_material_state(vm):
    progress = {'execution': 'source', 'phase': 'running'}
    vm.material_state_core_state = progress
    result = vm.run(max_steps=1_000_000)
    progress['phase'] = 'complete'
    return result
