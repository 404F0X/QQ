from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


def _initialize(vm):
    vm.pc = 4
    vm._allocate(6, 2)
    vm.pc = 7
    vm._allocate(6, 3)
    _native_call(vm, 7, 13, 8, 5, (), 4)
    vm.pc = 18
    a, b = vm.cells.value(1), vm.cells.value(6)
    if b == 0:
        raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
    vm._write(7, a // b, 8, 'L18.unsigned_q_division')
    vm.pc = 19
    vm.pc = 22
    vm.auxiliary = (0, 1316864515)
    vm.pc = 27
    vm._write(8, vm._signed_cell(6, 3) * vm._signed_cell(7, 3), 8, 'once0.integer')
    vm.pc = 30
    vm.auxiliary = (0, 1823846915)
    vm.pc = 35
    vm._write(10, vm._signed_cell(8, 3) * vm._signed_cell(9, 3), 8, 'once0.integer')
    _native_call(vm, 35, 42, 10, 12, (10,), 11)
    vm.pc = 47
    vm.cells.copy_q_clear_owned(11, 13)
    _native_call(vm, 47, 56, 12, 15, (11, 16, 10), 14)
    vm.pc = 61
    vm._write(17, vm.cells.value(7) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 64
    vm.auxiliary = (0, 569778692)
    vm.pc = 69
    vm._write(19, vm._signed_cell(17, 6) * vm._signed_cell(18, 6), 8, 'once0.integer')
    _native_call(vm, 69, 76, 14, 20, (13, 19))
    _native_call(vm, 76, 83, 10, 12, (1,), 21)
    vm.pc = 85
    vm._jump(1)


def _round_head(vm):
    vm.pc = 92
    if vm.predecessor == 0:
        value = vm.cells.value(16)
    elif vm.predecessor == 2:
        value = vm.cells.value(23)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(22, value, 8, 'L9.phi_q')
    vm.pc = 93
    vm.pc = 96
    vm.auxiliary = (0, 740455173)
    vm.pc = 101
    a = vm._signed_cell(22, 6) & ((1 << 64) - 1)
    b = vm._signed_cell(18, 6) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(24, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 105
    vm._jump(3 if vm.cells.value(24) != 0 else 4)


def _round_next(vm):
    vm.pc = 252
    vm.pc = 255
    vm.auxiliary = (0, 364408834)
    vm.pc = 260
    vm._write(23, vm._signed_cell(22, 6) + vm._signed_cell(44, 6), 8, 'once1.integer')
    vm.pc = 262
    vm._jump(1)


def _round_start(vm):
    vm.pc = 109
    vm._jump(6)


def _round_done(vm):
    vm.pc = 107
    vm._jump(5)


def _qpc_head(vm):
    vm.pc = 330
    if vm.predecessor == 4:
        value = vm.cells.value(26)
    elif vm.predecessor == 11:
        value = vm.cells.value(58)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(57, value, 8, 'L9.phi_q')
    vm.pc = 335
    vm._write(59, int(vm.cells.value(57) < vm.cells.value(1)), 4, 'once18.unsigned_q')
    vm.pc = 339
    vm._jump(11 if vm.cells.value(59) != 0 else 12)


def _entropy_copy_head(vm):
    vm.pc = 116
    if vm.predecessor == 3:
        value = vm.cells.value(26)
    elif vm.predecessor == 7:
        value = vm.cells.value(27)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(25, value, 8, 'L9.phi_q')
    vm.pc = 123
    if vm.predecessor == 3:
        value = vm.cells.value(16)
    elif vm.predecessor == 7:
        value = vm.cells.value(29)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(28, value, 8, 'L9.phi_q')
    vm.pc = 128
    vm._write(30, int(vm.cells.value(25) < vm.cells.value(1)), 4, 'once18.unsigned_q')
    vm.pc = 132
    vm._jump(7 if vm.cells.value(30) != 0 else 8)


def _entropy_copy(vm):
    vm.pc = 137
    vm.cells.copy_q_clear_owned(2, 31)
    vm.pc = 138
    vm.pc = 141
    vm.auxiliary = (0, 867598852)
    vm.pc = 146
    vm._write(33, vm._signed_cell(22, 6) * vm._signed_cell(32, 6), 8, 'once0.integer')
    vm.pc = 149
    vm.auxiliary = (0, 504659969)
    vm.pc = 154
    vm._write(34, vm._signed_cell(33, 6) + vm._signed_cell(28, 6), 8, 'once1.integer')
    vm.pc = 159
    vm.cells.copy_q_clear_owned(34, 35)
    _indexed_pointer(vm, 159, 36, 6, 13, (35,))
    vm.pc = 170
    value = vm.memory.load(vm.cells.value(36), 4)
    vm._write(37, value, 4, 'high.load')
    vm.pc = 174
    _store_cell(vm, 170, 4, 37, 2)
    _indexed_pointer(vm, 174, 38, 1, 21, (25,))
    vm.pc = 184
    vm.auxiliary = (0, 12664)
    vm.pc = 189
    vm._write(39, vm._signed_cell(1, 3) - vm._signed_cell(25, 3), 8, 'typed.selector0.q')
    vm.pc = 194
    value = int(vm.cells.value(39) > vm.cells.value(6))
    vm._write(40, value, 4, 'L31.comparison')
    vm.pc = 201
    selected = 6 if vm.cells.value(40) != 0 else 39
    vm._write(41, vm._signed_cell(selected, 3), 8, 'L7.selected_q')
    _native_call(vm, 201, 210, 17, 43, (38, 31, 41), 42)
    vm.pc = 213
    vm.auxiliary = (0, 769265666)
    vm.pc = 218
    vm._write(27, vm._signed_cell(25, 3) + vm._signed_cell(6, 3), 8, 'once1.integer')
    vm.pc = 221
    vm.auxiliary = (0, 556847105)
    vm.pc = 226
    vm._write(29, vm._signed_cell(28, 6) + vm._signed_cell(44, 6), 8, 'once1.integer')
    vm.pc = 228
    vm._jump(6)


def _entropy_copy_done(vm):
    vm.pc = 230
    vm._jump(9)


def _entropy_xor_head(vm):
    vm.pc = 237
    if vm.predecessor == 8:
        value = vm.cells.value(16)
    elif vm.predecessor == 10:
        value = vm.cells.value(46)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(45, value, 8, 'L9.phi_q')
    vm.pc = 242
    vm.cells.copy_q_clear_owned(45, 47)
    vm.pc = 247
    vm._write(48, int(vm.cells.value(47) < vm.cells.value(1)), 4, 'once18.unsigned_q')
    vm.pc = 251
    vm._jump(10 if vm.cells.value(48) != 0 else 2)


def _entropy_xor(vm):
    _indexed_pointer(vm, 262, 49, 1, 21, (47,))
    vm.pc = 273
    value = vm.memory.load(vm.cells.value(49), 1)
    vm._write(50, value, 4, 'high.load')
    vm.pc = 278
    value = vm.memory.load(vm.cells.pointer(50), 4)
    vm._write(51, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 278, 52, 1, 0, (47,))
    vm.pc = 289
    value = vm.memory.load(vm.cells.value(52), 1)
    vm._write(53, value, 4, 'high.load')
    vm.pc = 294
    value = vm.memory.load(vm.cells.pointer(53), 4)
    vm._write(54, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 295
    vm.pc = 298
    vm.auxiliary = (0, 26628)
    vm.pc = 304
    vm._write(55, vm._signed_cell(54, 6) ^ vm._signed_cell(51, 6), 8, 'high.flag1_xor_q')
    vm.pc = 309
    vm._write(56, vm.cells.value(55) & 255, 8, 'once9.mask_q')
    vm.pc = 313
    _store_cell(vm, 309, 1, 56, 52)
    vm.pc = 316
    vm.auxiliary = (0, 406880258)
    vm.pc = 321
    vm._write(46, vm._signed_cell(45, 6) + vm._signed_cell(44, 6), 8, 'once1.integer')
    vm.pc = 323
    vm._jump(9)


def _qpc_copy(vm):
    vm.pc = 344
    vm.cells.copy_q_clear_owned(3, 60)
    _native_call(vm, 344, 350, 19, 62, (), 61)
    vm.pc = 354
    _store_cell(vm, 350, 4, 61, 3)
    _indexed_pointer(vm, 354, 63, 1, 21, (57,))
    vm.pc = 362
    vm.pc = 365
    vm.auxiliary = (0, 17515)
    vm.pc = 370
    vm._write(64, vm._signed_cell(1, 3) - vm._signed_cell(57, 3), 8, 'typed.selector0.q')
    vm.pc = 375
    value = int(vm.cells.value(64) > vm.cells.value(6))
    vm._write(65, value, 4, 'L31.comparison')
    vm.pc = 382
    selected = 6 if vm.cells.value(65) != 0 else 64
    vm._write(66, vm._signed_cell(selected, 3), 8, 'L7.selected_q')
    _native_call(vm, 382, 391, 17, 43, (63, 60, 66), 67)
    vm.pc = 394
    vm.auxiliary = (0, 1825964033)
    vm.pc = 399
    vm._write(58, vm._signed_cell(57, 3) + vm._signed_cell(6, 3), 8, 'once1.integer')
    vm.pc = 401
    vm._jump(5)


def _qpc_copy_done(vm):
    vm.pc = 403
    vm._jump(13)


def _qpc_xor_head(vm):
    vm.pc = 410
    if vm.predecessor == 12:
        value = vm.cells.value(16)
    elif vm.predecessor == 14:
        value = vm.cells.value(69)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(68, value, 8, 'L9.phi_q')
    vm.pc = 415
    vm.cells.copy_q_clear_owned(68, 70)
    vm.pc = 420
    vm._write(71, int(vm.cells.value(70) < vm.cells.value(1)), 4, 'once18.unsigned_q')
    vm.pc = 424
    vm._jump(14 if vm.cells.value(71) != 0 else 15)


def _qpc_xor(vm):
    _indexed_pointer(vm, 449, 76, 1, 21, (70,))
    vm.pc = 460
    value = vm.memory.load(vm.cells.value(76), 1)
    vm._write(77, value, 4, 'high.load')
    vm.pc = 465
    value = vm.memory.load(vm.cells.pointer(77), 4)
    vm._write(78, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 465, 79, 1, 0, (70,))
    vm.pc = 476
    value = vm.memory.load(vm.cells.value(79), 1)
    vm._write(80, value, 4, 'high.load')
    vm.pc = 481
    value = vm.memory.load(vm.cells.pointer(80), 4)
    vm._write(81, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 486
    vm._write(82, vm._signed_cell(81, 6) ^ vm._signed_cell(78, 6), 8, 'L14.binary_q')
    vm.pc = 491
    vm._write(83, vm.cells.value(82) & 255, 8, 'once9.mask_q')
    vm.pc = 495
    _store_cell(vm, 491, 1, 83, 79)
    vm.pc = 496
    vm.pc = 499
    vm.auxiliary = (0, 1564540930)
    vm.pc = 504
    vm._write(69, vm._signed_cell(68, 6) + vm._signed_cell(44, 6), 8, 'once1.integer')
    vm.pc = 506
    vm._jump(13)


def _elapsed(vm):
    _native_call(vm, 424, 430, 8, 5, (), 72)
    _native_call(vm, 430, 438, 21, 74, (72, 4), 73)
    vm.pc = 443
    vm.cells.copy_q_clear_owned(21, 75)
    vm.pc = 447
    _store_cell(vm, 443, 4, 73, 75)
    vm.pc = 449
    vm._jump(16)


def _elapsed_xor_head(vm):
    vm.pc = 513
    if vm.predecessor == 15:
        value = vm.cells.value(16)
    elif vm.predecessor == 17:
        value = vm.cells.value(85)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(84, value, 8, 'L9.phi_q')
    vm.pc = 514
    vm.pc = 517
    vm.auxiliary = (0, 902990389)
    vm.pc = 522
    a = vm._signed_cell(84, 6) & ((1 << 64) - 1)
    b = vm._signed_cell(32, 6) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(86, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 526
    vm._jump(17 if vm.cells.value(86) != 0 else 18)


def _elapsed_xor(vm):
    vm.pc = 544
    vm.cells.copy_q_clear_owned(84, 88)
    _indexed_pointer(vm, 544, 89, 1, 21, (88,))
    vm.pc = 555
    value = vm.memory.load(vm.cells.value(89), 1)
    vm._write(90, value, 4, 'high.load')
    vm.pc = 560
    value = vm.memory.load(vm.cells.pointer(90), 4)
    vm._write(91, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 560, 92, 1, 0, (88,))
    vm.pc = 571
    value = vm.memory.load(vm.cells.value(92), 1)
    vm._write(93, value, 4, 'high.load')
    vm.pc = 576
    value = vm.memory.load(vm.cells.pointer(93), 4)
    vm._write(94, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 581
    vm._write(95, vm._signed_cell(94, 6) ^ vm._signed_cell(91, 6), 8, 'L14.binary_q')
    vm.pc = 586
    vm._write(96, vm.cells.value(95) & 255, 8, 'once9.mask_q')
    vm.pc = 590
    _store_cell(vm, 586, 1, 96, 92)
    vm.pc = 591
    vm.pc = 594
    vm.auxiliary = (0, 1928716289)
    vm.pc = 599
    vm._write(85, vm._signed_cell(84, 6) + vm._signed_cell(44, 6), 8, 'once1.integer')
    vm.pc = 601
    vm._jump(16)


def _release(vm):
    _native_call(vm, 526, 532, 23, 87, (21,))
    _native_call(vm, 532, 538, 23, 87, (11,))
    vm.pc = 539
    vm.halted = True


def run_primary_buffer_init(vm):
    _initialize(vm)
    while True:
        _round_head(vm)
        if vm.block == 4:
            break
        _round_start(vm)
        while True:
            _entropy_copy_head(vm)
            if vm.block == 8:
                break
            _entropy_copy(vm)
        _entropy_copy_done(vm)
        while True:
            _entropy_xor_head(vm)
            if vm.block == 2:
                break
            _entropy_xor(vm)
        _round_next(vm)
    _round_done(vm)
    while True:
        _qpc_head(vm)
        if vm.block == 12:
            break
        _qpc_copy(vm)
    _qpc_copy_done(vm)
    while True:
        _qpc_xor_head(vm)
        if vm.block == 15:
            break
        _qpc_xor(vm)
    _elapsed(vm)
    while True:
        _elapsed_xor_head(vm)
        if vm.block == 18:
            break
        _elapsed_xor(vm)
    _release(vm)
    return vm.result
