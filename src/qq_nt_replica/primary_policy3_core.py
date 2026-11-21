from .primary_entry_exit import _host
from .primary_vm import PrimarySemanticUnavailable


def _pointer(vm, pc, destination, base, indices):
    vm.pc = pc
    offset = sum(vm.memory.load(vm.cells.pointer(index), 4) * stride for index, stride in indices)
    vm._write(destination, vm.cells.value(base) + offset, 8, 'high.indexed_pointer_q')


def _copy(vm, pc, source, destination):
    vm.pc = pc
    vm.cells.copy_q_clear_owned(source, destination)


def _load(vm, pc, source, destination, width):
    vm.pc = pc
    value = vm.memory.load(vm.cells.value(source), width)
    vm._write(destination, value, 8 if width == 8 else 4, 'high.load')


def _store(vm, pc, source, destination, width):
    vm.pc = pc
    pointer = vm.cells.value(destination)
    value = vm.memory.load(vm.cells.pointer(source), width)
    vm.memory.store(pointer, value, width, source='high.store')


def _add(vm, pc, typ, left, right, destination):
    vm.pc = pc
    vm._write(destination, vm._signed_cell(left, typ) + vm._signed_cell(right, typ),
              8, 'once1.integer')


def _mask(vm, pc, source, destination, width):
    vm.pc = pc
    vm._write(destination, vm.cells.value(source) & ((1 << (width * 8)) - 1),
              8, 'once9.mask_q')


def _extend(vm, pc, source, destination, width):
    vm.pc = pc
    vm._write(destination, vm.memory.load(vm.cells.pointer(source), width),
              8, 'once10.first_type_zeroextend_or_q')


def _less(vm, pc, left, right, destination):
    vm.pc = pc
    vm._write(destination, int(vm.cells.value(left) < vm.cells.value(right)),
              4, 'once18.unsigned_q')


def _different(vm, pc, left, right, destination, width):
    vm.pc = pc
    vm._write(destination, int(vm.memory.load(vm.cells.pointer(left), width, signed=True) !=
                              vm.memory.load(vm.cells.pointer(right), width, signed=True)),
              4, 'L27.comparison')


def _signed_less(vm, pc, left, right, destination):
    vm.pc = pc
    a = vm.memory.load(vm.cells.pointer(left), 4, signed=True) & ((1 << 64) - 1)
    b = vm.memory.load(vm.cells.pointer(right), 4, signed=True) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    overflow = ((a ^ difference) & (a ^ b)) >> 63
    vm._write(destination, (difference >> 63) | overflow, 4, 'L29.n_or_v_comparison')


def _phi(vm, pc, destination, choices):
    vm.pc = pc
    for predecessor, source in choices:
        if predecessor == vm.predecessor:
            vm._write(destination, vm.cells.value(source), 8, 'L9.phi_q')
            return
    raise PrimarySemanticUnavailable('PHI has no matching original predecessor')


def _aux(vm, pc, value):
    vm.pc = pc
    vm.auxiliary = (0, value)


def _stop(vm, pc):
    vm.pc = pc
    vm.halted = True


def _branch(vm, pc, condition, true, false):
    vm.pc = pc
    vm._jump(true if vm.cells.value(condition) else false)


def _xor(vm, pc, typ, left, right, destination, *, label='L14.binary_q'):
    vm.pc = pc
    vm._write(destination, vm._signed_cell(left, typ) ^ vm._signed_cell(right, typ), 8, label)


def _and(vm, pc, typ, left, right, destination):
    vm.pc = pc
    vm._write(destination, vm._signed_cell(left, typ) & vm._signed_cell(right, typ),
              8, 'L13.binary_q')


def _or(vm, pc, typ, left, right, destination):
    vm.pc = pc
    vm._write(destination, vm._signed_cell(left, typ) | vm._signed_cell(right, typ),
              8, 'L15.binary_q')


def _right(vm, pc, typ, source, count, destination):
    vm.pc = pc
    width = vm.program.size(typ)
    value = vm.memory.load(vm.cells.pointer(source), width)
    shift = vm.memory.load(vm.cells.pointer(count), 1) & (63 if width == 8 else 31)
    vm._write(destination, value >> shift, 8 if width == 8 else 4, 'once8.logical_shift')


def _equal_pointer(vm, word, consumed, left, right, destination):
    vm.pc = word + 1
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = consumed
    vm._write(destination, int(vm.cells.value(left) == vm.cells.value(right)), 4, 'L26.comparison')


def _typed(vm, pc, typ, left, right, destination):
    vm.pc = pc
    vm.execute_typed((typ, left, right, destination))


def _typed_shift(vm, word, typ, left, right, destination, following_type):
    vm.pc = word + 1
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = word + 5
    vm.execute_typed((typ, left, right, destination))
    if extra:
        vm.pc = word + 9
        vm.program.size(following_type)


def _qextend(vm, pc, typ, source, destination):
    vm.pc = pc
    vm.execute_once(10, (typ, 0, source, destination))


def initialize_policy3_state(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_policy3_init_state = {'phase': 'key_words', 'word_stores': 0}
    _pointer(vm, 8, 2, 1, ((3, 1),))
    _copy(vm, 13, 2, 4)
    _load(vm, 17, 4, 5, 4)
    _pointer(vm, 25, 6, 0, ((7, 64), (7, 0)))
    _pointer(vm, 33, 8, 6, ((9, 64), (10, 4)))
    _store(vm, 37, 5, 8, 4)
    state['word_stores'] += 1
    for pc, key_index, key_pointer, copied, loaded, target, state_index in (
            (37, 12, 11, 13, 14, 15, 16),
            (65, 10, 17, 18, 19, 20, 3),
            (93, 16, 21, 22, 23, 24, 12)):
        _pointer(vm, pc + 7, key_pointer, 1, ((key_index, 1),))
        _copy(vm, pc + 12, key_pointer, copied)
        _load(vm, pc + 16, copied, loaded, 4)
        _pointer(vm, pc + 24, target, 6, ((9, 64), (state_index, 4)))
        _store(vm, pc + 28, loaded, target, 4)
        state['word_stores'] += 1
    _copy(vm, 126, 1, 25)
    _load(vm, 130, 25, 26, 4)
    _pointer(vm, 138, 27, 6, ((9, 64), (28, 4)))
    _store(vm, 142, 26, 27, 4)
    state['word_stores'] += 1
    for pc, copied, loaded, target, state_index in (
            (142, 13, 29, 30, 31), (158, 4, 32, 33, 34), (174, 22, 35, 36, 37)):
        _load(vm, pc + 4, copied, loaded, 4)
        _pointer(vm, pc + 12, target, 6, ((9, 64), (state_index, 4)))
        _store(vm, pc + 16, loaded, target, 4)
        state['word_stores'] += 1
    state['phase'] = 'constants'
    for pc, target, index, source in ((190, 38, 9, 39), (202, 40, 41, 42),
                                      (214, 43, 44, 45), (226, 46, 47, 48)):
        _pointer(vm, pc + 8, target, 6, ((9, 64), (index, 4)))
        _store(vm, pc + 12, source, target, 4)
        state['word_stores'] += 1
    _stop(vm, 239)
    state['phase'] = 'halted'
    return True


def crypt_policy3_payload(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_policy3_crypt_state = {'phase': 'length', 'blocks': 0, 'bytes': 0}
    vm.pc = 4
    vm._allocate(9, 5)
    _copy(vm, 9, 5, 6)
    _aux(vm, 13, 2062734708)
    _different(vm, 18, 4, 7, 8, 4)
    _branch(vm, 22, 8, 1, 2)
    if vm.block == 2:
        _pointer(vm, 30, 9, 5, ((10, 64), (10, 1)))
        _pointer(vm, 38, 11, 12, ((10, 2), (10, 1)))
        _host(vm, 38, 47, 14, (9, 11, 10), 15, 13)
        vm._jump(3)
        _stop(vm, 429)
        state['phase'] = 'halted'
        return True
    state['phase'] = 'nonce'
    _copy(vm, 54, 1, 15)
    _load(vm, 58, 15, 16, 4)
    _pointer(vm, 66, 17, 0, ((7, 64), (7, 0)))
    _pointer(vm, 74, 18, 17, ((10, 64), (19, 4)))
    _store(vm, 78, 16, 18, 4)
    _pointer(vm, 86, 20, 17, ((10, 64), (21, 4)))
    _store(vm, 90, 22, 20, 4)
    _pointer(vm, 98, 23, 17, ((10, 64), (24, 4)))
    _store(vm, 102, 7, 23, 4)
    _pointer(vm, 110, 25, 17, ((10, 64), (26, 4)))
    _store(vm, 114, 7, 25, 4)
    vm._jump(4)
    while True:
        state['phase'] = 'block'
        _phi(vm, 123, 27, ((1, 2), (5, 28)))
        _phi(vm, 130, 29, ((1, 3), (5, 30)))
        _phi(vm, 137, 31, ((1, 4), (5, 32)))
        _pointer(vm, 145, 33, 17, ((10, 64), (10, 4)))
        _pointer(vm, 153, 34, 5, ((10, 64), (10, 1)))
        _host(vm, 153, 160, 35, (34, 33), 19)
        state['blocks'] += 1
        _load(vm, 164, 23, 36, 4)
        _aux(vm, 168, 1964957697)
        _add(vm, 173, 1, 36, 37, 38)
        _store(vm, 177, 38, 23, 4)
        _aux(vm, 180, 475200212)
        _different(vm, 185, 38, 7, 39, 4)
        _branch(vm, 189, 39, 6, 7)
        if vm.block == 7:
            _load(vm, 193, 25, 40, 4)
            _aux(vm, 197, 655196162)
            _add(vm, 202, 1, 40, 37, 41)
            _store(vm, 206, 41, 25, 4)
            vm._jump(6)
        vm.pc = 213
        vm._write(43, int(vm.cells.value(31) <= vm.cells.value(42)), 4, 'once19.unsigned_q')
        _branch(vm, 217, 43, 8, 9)
        if vm.block == 8:
            vm._jump(10)
            state['phase'] = 'remainder'
            while True:
                _phi(vm, 226, 44, ((8, 7), (11, 45)))
                _less(vm, 231, 44, 31, 46)
                _branch(vm, 235, 46, 11, 12)
                if vm.block == 12:
                    vm._jump(3)
                    _stop(vm, 429)
                    state['phase'] = 'halted'
                    return True
                _copy(vm, 242, 44, 47)
                _pointer(vm, 249, 48, 27, ((47, 1),))
                _load(vm, 253, 48, 49, 1)
                _extend(vm, 258, 49, 50, 4)
                _pointer(vm, 266, 51, 5, ((10, 64), (47, 1)))
                _load(vm, 270, 51, 52, 1)
                _extend(vm, 275, 52, 53, 4)
                _xor(vm, 280, 1, 50, 53, 54)
                _mask(vm, 285, 54, 55, 1)
                _pointer(vm, 292, 56, 29, ((47, 1),))
                _store(vm, 296, 55, 56, 1)
                state['bytes'] += 1
                _aux(vm, 300, 1363554305)
                _add(vm, 305, 1, 44, 37, 45)
                vm._jump(10)
        vm._jump(13)
        state['phase'] = 'full_block'
        while True:
            _phi(vm, 316, 57, ((9, 7), (14, 58)))
            _aux(vm, 320, 1396853877)
            _signed_less(vm, 325, 57, 42, 59)
            _branch(vm, 329, 59, 14, 5)
            if vm.block == 5:
                break
            _copy(vm, 359, 57, 61)
            _pointer(vm, 366, 62, 27, ((61, 1),))
            _load(vm, 370, 62, 63, 1)
            _extend(vm, 375, 63, 64, 4)
            _pointer(vm, 383, 65, 5, ((10, 64), (61, 1)))
            _load(vm, 387, 65, 66, 1)
            _extend(vm, 392, 66, 67, 4)
            _aux(vm, 396, 10340)
            _xor(vm, 402, 1, 64, 67, 68, label='high.flag1_xor_q')
            _mask(vm, 407, 68, 69, 1)
            _pointer(vm, 414, 70, 29, ((61, 1),))
            _store(vm, 418, 69, 70, 1)
            state['bytes'] += 1
            _aux(vm, 421, 1924096002)
            _add(vm, 426, 1, 57, 37, 58)
            vm._jump(13)
        _aux(vm, 333, 41328)
        vm.pc = 338
        vm.execute_typed((1, 31, 42, 32))
        _pointer(vm, 345, 30, 29, ((60, 1),))
        _pointer(vm, 352, 28, 27, ((60, 1),))
        vm._jump(4)


def publish_policy3_digest(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_policy3_publish_state = {'phase': 'pointers', 'header_bytes': 0,
                                               'digest_bytes': 0}
    _aux(vm, 5, 601027587)
    _equal_pointer(vm, 5, 10, 0, 3, 4)
    _aux(vm, 13, 1330795587)
    _equal_pointer(vm, 13, 18, 2, 3, 5)
    _aux(vm, 21, 30169)
    vm.pc = 26
    vm.execute_typed((6, 4, 5, 6))
    _branch(vm, 30, 6, 1, 2)
    if vm.block == 1:
        _pointer(vm, 38, 7, 8, ((9, 2), (9, 1)))
        _host(vm, 38, 47, 11, (0, 7, 9), 10, 10)
        vm._jump(3)
        _stop(vm, 264)
        state['phase'] = 'halted'
        return True
    state['phase'] = 'header'
    _store(vm, 53, 12, 0, 1)
    state['header_bytes'] += 1
    for pc, target, index, value in ((53, 13, 14, 15), (64, 16, 17, 18), (75, 19, 20, 21)):
        _pointer(vm, pc + 7, target, 0, ((index, 1),))
        _store(vm, pc + 11, value, target, 1)
        state['header_bytes'] += 1
    _and(vm, 91, 3, 1, 22, 23)
    _mask(vm, 96, 23, 24, 1)
    _pointer(vm, 103, 25, 0, ((26, 1),))
    _store(vm, 107, 24, 25, 1)
    state['header_bytes'] += 1
    for pc, count, shifted, masked, byte, target, index in (
            (107, 27, 28, 29, 30, 31, 32), (133, 33, 34, 35, 36, 37, 38)):
        _right(vm, pc + 5, 3, 1, count, shifted)
        _and(vm, pc + 10, 3, shifted, 22, masked)
        _mask(vm, pc + 15, masked, byte, 1)
        _pointer(vm, pc + 22, target, 0, ((index, 1),))
        _store(vm, pc + 26, byte, target, 1)
        state['header_bytes'] += 1
    _right(vm, 164, 3, 1, 39, 40)
    _mask(vm, 169, 40, 41, 1)
    _pointer(vm, 176, 42, 0, ((43, 1),))
    _store(vm, 180, 41, 42, 1)
    state['header_bytes'] += 1
    _host(vm, 180, 189, 45, (0, 46, 47), 12, 44)
    vm._jump(4)
    state['phase'] = 'digest'
    while True:
        _phi(vm, 198, 48, ((2, 49), (5, 50)))
        _aux(vm, 202, 1399991285)
        _signed_less(vm, 207, 48, 51, 52)
        _branch(vm, 211, 52, 5, 6)
        if vm.block == 6:
            vm._jump(3)
            _stop(vm, 264)
            state['phase'] = 'halted'
            return True
        _aux(vm, 217, 1964294660)
        vm.pc = 222
        vm._write(53, vm._signed_cell(48, 3) * vm._signed_cell(27, 3), 8, 'once0.integer')
        _right(vm, 227, 3, 44, 53, 54)
        _and(vm, 232, 3, 54, 22, 55)
        _mask(vm, 237, 55, 56, 1)
        _copy(vm, 242, 48, 57)
        _pointer(vm, 249, 58, 2, ((57, 1),))
        _store(vm, 253, 56, 58, 1)
        state['digest_bytes'] += 1
        _aux(vm, 256, 1825558530)
        _add(vm, 261, 3, 48, 59, 50)
        vm._jump(4)


def assemble_policy3_packet(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_policy3_packet_state = {'phase': 'private_buffers', 'material_calls': 0,
                                              'permuted_bytes': 0}
    for ordinal, (typ, destination) in enumerate(((7, 7), (9, 8), (11, 9), (13, 10),
                                                (15, 11), (18, 12), (20, 13))):
        vm.pc = 4 + 3 * ordinal
        vm._allocate(typ, destination)
    _copy(vm, 27, 7, 14)
    _host(vm, 27, 36, 16, (14, 17, 18), 22, 15)
    _copy(vm, 41, 8, 19)
    _store(vm, 45, 20, 8, 8)
    _host(vm, 45, 52, 22, (8,), 24, 21)
    _pointer(vm, 60, 23, 7, ((20, 32), (24, 1)))
    _store(vm, 64, 25, 23, 1)
    _extend(vm, 69, 0, 26, 4)
    _aux(vm, 73, 22367)
    _typed(vm, 78, 3, 26, 27, 28)
    _aux(vm, 81, 34748)
    _typed_shift(vm, 81, 3, 28, 29, 30, 14940)
    _and(vm, 91, 3, 30, 31, 32)
    _mask(vm, 96, 32, 33, 1)
    _extend(vm, 101, 33, 34, 4)
    _aux(vm, 104, 31295)
    _xor(vm, 110, 3, 35, 34, 36, label='high.flag1_xor_q')
    _mask(vm, 115, 36, 37, 1)
    _pointer(vm, 123, 38, 7, ((20, 32), (39, 1)))
    _store(vm, 127, 37, 38, 1)
    _copy(vm, 132, 9, 40)
    state['phase'] = 'material_fields'
    _host(vm, 132, 141, 41, (25, 17, 42, 9), 26)
    state['material_calls'] += 1
    _host(vm, 141, 148, 44, (9,), 28, 43)
    _host(vm, 148, 157, 41, (45, 17, 46, 9), 26)
    state['material_calls'] += 1
    _host(vm, 157, 164, 44, (9,), 28, 47)
    _host(vm, 164, 173, 41, (45, 46, 48, 9), 26)
    state['material_calls'] += 1
    _host(vm, 173, 180, 44, (9,), 28, 49)
    _copy(vm, 185, 10, 50)
    _and(vm, 190, 9, 51, 47, 52)
    _mask(vm, 195, 52, 53, 2)
    _extend(vm, 200, 53, 54, 4)
    _and(vm, 205, 9, 55, 49, 56)
    _aux(vm, 208, 41380)
    _typed_shift(vm, 208, 9, 56, 57, 58, 329826885)
    _mask(vm, 218, 58, 59, 2)
    _extend(vm, 223, 59, 60, 4)
    _aux(vm, 226, 45296)
    _typed(vm, 231, 3, 54, 60, 61)
    _aux(vm, 234, 54628)
    _typed(vm, 239, 9, 55, 43, 62)
    _aux(vm, 242, 26604)
    _typed_shift(vm, 242, 9, 62, 51, 63, 329826885)
    _mask(vm, 252, 63, 64, 2)
    _extend(vm, 257, 64, 65, 4)
    _aux(vm, 260, 59097)
    _typed(vm, 265, 3, 61, 65, 66)
    _right(vm, 270, 9, 43, 67, 68)
    _aux(vm, 273, 8807)
    _typed(vm, 278, 9, 55, 68, 69)
    _aux(vm, 281, 29830)
    _typed_shift(vm, 281, 9, 69, 70, 71, 329826885)
    _mask(vm, 291, 71, 72, 2)
    _extend(vm, 296, 72, 73, 4)
    _aux(vm, 299, 22009)
    _typed(vm, 304, 3, 66, 73, 74)
    for pc, count, shifted, masked, aux, shift_count, shift_result, narrow, wide, previous, result in (
            (304, 75, 76, 77, 25311, 78, 79, 80, 81, 74, 82),
            (337, 83, 84, 85, 14244, 86, 87, 88, 89, 82, 90),
            (370, 91, 92, 93, 42206, 94, 95, 96, 97, 90, 98)):
        _right(vm, pc + 5, 9, 43, count, shifted)
        _and(vm, pc + 10, 9, 55, shifted, masked)
        _aux(vm, pc + 13, aux)
        _typed_shift(vm, pc + 13, 9, masked, shift_count, shift_result, 329826885)
        _mask(vm, pc + 23, shift_result, narrow, 2)
        _extend(vm, pc + 28, narrow, wide, 4)
        _or(vm, pc + 33, 3, previous, wide, result)
    _right(vm, 408, 9, 43, 99, 100)
    _and(vm, 413, 9, 55, 100, 101)
    _aux(vm, 416, 5863)
    _typed_shift(vm, 416, 9, 101, 67, 102, 329826885)
    _mask(vm, 426, 102, 103, 2)
    _extend(vm, 431, 103, 104, 4)
    _aux(vm, 434, 30424)
    _typed(vm, 439, 3, 98, 104, 105)
    _mask(vm, 444, 105, 106, 2)
    _store(vm, 448, 106, 10, 2)
    state['phase'] = 'input_and_mt'
    _pointer(vm, 456, 107, 7, ((20, 32), (20, 1)))
    _pointer(vm, 463, 108, 107, ((109, 1),))
    _host(vm, 463, 471, 110, (108, 50, 57), 30)
    vm.pc = 476
    vm._write(112, int(vm.cells.value(111) > vm.cells.value(2)), 4, 'L31.comparison')
    vm.pc = 483
    selected = 2 if vm.cells.value(112) else 111
    vm._write(113, vm._signed_cell(selected, 3), 8, 'L7.selected_q')
    _qextend(vm, 488, 9, 113, 114)
    _pointer(vm, 495, 115, 107, ((116, 1),))
    _host(vm, 495, 503, 110, (115, 1, 114), 30)
    _copy(vm, 508, 11, 117)
    _host(vm, 508, 517, 16, (117, 17, 24), 22, 118)
    _pointer(vm, 525, 119, 11, ((20, 12), (20, 4)))
    _load(vm, 529, 8, 120, 8)
    _host(vm, 529, 537, 121, (21, 120, 119), 33)
    _copy(vm, 542, 119, 122)
    _host(vm, 542, 550, 110, (107, 122, 24), 30)
    _host(vm, 550, 558, 110, (5, 122, 24), 30)
    _load(vm, 562, 23, 123, 1)
    _extend(vm, 567, 123, 124, 4)
    _load(vm, 571, 107, 125, 1)
    _extend(vm, 576, 125, 126, 4)
    _xor(vm, 581, 3, 124, 126, 127)
    _mask(vm, 586, 127, 128, 1)
    _pointer(vm, 593, 129, 5, ((24, 1),))
    _store(vm, 597, 128, 129, 1)
    state['phase'] = 'cocos'
    _copy(vm, 602, 12, 130)
    _host(vm, 602, 609, 131, (12, 107), 35)
    _copy(vm, 614, 13, 132)
    _pointer(vm, 622, 133, 13, ((20, 19), (20, 1)))
    _pointer(vm, 629, 134, 107, ((39, 1),))
    _pointer(vm, 636, 135, 107, ((67, 1),))
    _host(vm, 636, 646, 136, (12, 135, 134, 133, 137), 37)
    _pointer(vm, 653, 138, 5, ((39, 1),))
    _host(vm, 653, 661, 110, (138, 133, 51), 30)
    state['phase'] = 'packet_permutation'
    for pc, source_pointer, source_index, loaded, target, target_index in (
            (661, 139, 70, 140, 141, 116), (684, 142, 78, 143, 144, 83),
            (707, 145, 86, 146, 147, 91), (730, 148, 67, 149, 150, 99),
            (753, 151, 152, 153, 154, 155), (776, 156, 116, 157, 158, 159),
            (799, 160, 75, 161, 162, 163), (822, 164, 94, 165, 166, 167)):
        _pointer(vm, pc + 8, source_pointer, 13, ((20, 19), (source_index, 1)))
        _load(vm, pc + 12, source_pointer, loaded, 1)
        _pointer(vm, pc + 19, target, 5, ((target_index, 1),))
        _store(vm, pc + 23, loaded, target, 1)
        state['permuted_bytes'] += 1
    _pointer(vm, 852, 168, 5, ((169, 1),))
    state['phase'] = 'digest'
    _host(vm, 852, 860, 170, (5, 171, 168), 39)
    _store(vm, 864, 172, 6, 4)
    _stop(vm, 865)
    state['phase'] = 'halted'
    return True
