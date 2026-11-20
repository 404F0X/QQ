from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell
from .primary_vm import PrimarySemanticUnavailable


def _allocate_scratch_and_container(vm):
    vm.pc = 4
    vm._allocate(3, 0)
    _native_call(vm, 4, 12, 30, 2, (3, 4), 1)
    vm.pc = 17
    vm.cells.copy_q_clear_owned(1, 5)
    vm.pc = 18
    vm.pc = 21
    vm.auxiliary = (0, 1278399299)
    vm.pc = 26
    vm._write(7, int(vm._signed_cell(5, 26) == vm._signed_cell(6, 26)), 4, 'once17.integer')
    vm.pc = 30
    vm._jump(1 if vm.cells.value(7) != 0 else 2)


def _null_container(vm):
    vm.pc = 32
    vm._jump(3)


def _initialize_base(vm):
    _native_call(vm, 32, 39, 34, 9, (10,), 8)
    vm.pc = 44
    vm._write(11, vm.cells.value(8) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 49
    vm.cells.copy_q_clear_owned(5, 12)
    vm.pc = 54
    vm._write(13, vm.cells.value(12) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 59
    vm._write(14, vm._signed_cell(11, 0) ^ vm._signed_cell(13, 0), 8, 'L14.binary_q')
    _indexed_pointer(vm, 59, 15, 25, 5, (16, 16))
    _store_cell(vm, 67, 4, 14, 15)
    vm.pc = 76
    vm._write(17, vm.cells.value(14) & 65535, 8, 'once9.mask_q')
    vm.pc = 81
    value = vm.memory.load(vm.cells.pointer(17), 4)
    vm._write(18, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 82
    vm.pc = 85
    vm.auxiliary = (0, 18439)
    vm.pc = 91
    vm._write(20, vm._signed_cell(19, 0) ^ vm._signed_cell(18, 0), 8, 'high.flag1_xor_q')
    vm.pc = 96
    vm._write(21, vm.cells.value(20) & 65535, 8, 'once9.mask_q')
    _indexed_pointer(vm, 96, 22, 25, 5, (16, 23))
    _store_cell(vm, 104, 2, 21, 22)
    vm.pc = 112
    value = vm.memory.load(vm.cells.value(15), 4)
    vm._write(24, value, 4, 'high.load')
    vm.pc = 114
    vm._jump(4)


def _return_container(vm):
    vm.pc = 1521
    if vm.predecessor == 1:
        value = vm.cells.value(6)
    elif vm.predecessor == 43:
        value = vm.cells.value(5)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(243, value, 8, 'L9.phi_q')
    vm.pc = 1524
    vm.result, vm.halted = vm._signed_cell(243, 26) & ((1 << 64) - 1), True


def _salt_head(vm):
    vm.pc = 121
    if vm.predecessor == 2:
        value = vm.cells.value(16)
    elif vm.predecessor == 5:
        value = vm.cells.value(26)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(25, value, 8, 'L9.phi_q')
    vm.pc = 128
    if vm.predecessor == 2:
        value = vm.cells.value(24)
    elif vm.predecessor == 5:
        value = vm.cells.value(28)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(27, value, 8, 'L9.phi_q')
    vm.pc = 129
    vm.pc = 132
    vm.auxiliary = (0, 1703065733)
    vm.pc = 137
    a = vm._signed_cell(25, 0) & ((1 << 64) - 1)
    b = vm._signed_cell(29, 0) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(30, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 141
    vm._jump(5 if vm.cells.value(30) != 0 else 6)


def _salt_byte(vm):
    vm.pc = 204
    vm.pc = 207
    vm.auxiliary = (0, 1116041731)
    vm.pc = 212
    vm._write(45, vm._signed_cell(27, 0) * vm._signed_cell(44, 0), 8, 'once0.integer')
    vm.pc = 215
    vm.auxiliary = (0, 1110347777)
    vm.pc = 220
    vm._write(28, vm._signed_cell(45, 0) + vm._signed_cell(46, 0), 8, 'once1.integer')
    vm.pc = 225
    a = vm.memory.load(vm.cells.pointer(28), 4)
    count = vm.memory.load(vm.cells.pointer(47), 1)
    vm._write(48, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 230
    vm._write(49, vm.cells.value(48) & 255, 8, 'once9.mask_q')
    vm.pc = 235
    value = vm.memory.load(vm.cells.pointer(49), 4)
    vm._write(50, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 240
    vm._write(51, vm._signed_cell(50, 0) | vm._signed_cell(23, 0), 8, 'L15.binary_q')
    vm.pc = 245
    vm._write(52, vm.cells.value(51) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 245, 53, 25, 5, (16, 42))
    vm.pc = 258
    vm.cells.copy_q_clear_owned(25, 54)
    _indexed_pointer(vm, 258, 55, 5, 53, (36, 54))
    _store_cell(vm, 266, 1, 52, 55)
    vm.pc = 273
    vm.auxiliary = (0, 1817710593)
    vm.pc = 278
    vm._write(26, vm._signed_cell(25, 0) + vm._signed_cell(23, 0), 8, 'once1.integer')
    vm.pc = 280
    vm._jump(4)


def _initialize_entropy_and_lock(vm):
    vm.pc = 146
    vm.cells.copy_q_clear_owned(0, 31)
    _native_call(vm, 146, 155, 38, 33, (31, 16, 34), 32)
    _indexed_pointer(vm, 155, 35, 3, 0, (36, 36))
    _native_call(vm, 163, 170, 41, 37, (35, 34))
    _native_call(vm, 170, 176, 43, 38, (5,))
    _native_call(vm, 176, 183, 45, 39, (5, 40))
    _indexed_pointer(vm, 183, 41, 25, 5, (16, 42))
    _indexed_pointer(vm, 191, 43, 5, 41, (36, 36))
    vm.pc = 203
    vm._jump(7 if vm.cells.value(40) != 0 else 8)


def _load_scratch_seed(vm):
    _indexed_pointer(vm, 280, 56, 5, 41, (36, 57))
    vm.pc = 292
    value = vm.memory.load(vm.cells.value(56), 1)
    vm._write(58, value, 4, 'high.load')
    vm.pc = 294
    vm._jump(9)


def _prepare_key_copy(vm):
    _indexed_pointer(vm, 422, 80, 25, 5, (16, 81))
    _indexed_pointer(vm, 430, 82, 3, 80, (36, 36))
    vm.pc = 442
    vm._jump(12 if vm.cells.value(40) != 0 else 13)


def _scratch_head(vm):
    vm.pc = 301
    if vm.predecessor == 7:
        value = vm.cells.value(58)
    elif vm.predecessor == 10:
        value = vm.cells.value(60)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(59, value, 8, 'L9.phi_q')
    vm.pc = 308
    if vm.predecessor == 7:
        value = vm.cells.value(36)
    elif vm.predecessor == 10:
        value = vm.cells.value(62)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(61, value, 8, 'L9.phi_q')
    vm.pc = 313
    vm._write(63, int(vm.cells.value(61) < vm.cells.value(34)), 4, 'once18.unsigned_q')
    vm.pc = 317
    vm._jump(10 if vm.cells.value(63) != 0 else 11)


def _mix_scratch_byte(vm):
    vm.pc = 322
    value = vm.memory.load(vm.cells.pointer(59), 4)
    vm._write(64, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 323
    vm.pc = 326
    vm.auxiliary = (0, 1512866308)
    vm.pc = 331
    vm._write(66, vm._signed_cell(61, 15) * vm._signed_cell(65, 15), 8, 'once0.integer')
    vm.pc = 334
    vm.auxiliary = (0, 814944257)
    vm.pc = 339
    vm._write(67, vm._signed_cell(66, 15) + vm._signed_cell(57, 15), 8, 'once1.integer')
    vm.pc = 344
    vm._write(68, vm.cells.value(67) & 255, 8, 'once9.mask_q')
    vm.pc = 349
    value = vm.memory.load(vm.cells.pointer(68), 4)
    vm._write(69, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 354
    vm._write(70, vm._signed_cell(64, 0) ^ vm._signed_cell(69, 0), 8, 'L14.binary_q')
    _indexed_pointer(vm, 354, 71, 3, 0, (36, 61))
    vm.pc = 366
    value = vm.memory.load(vm.cells.value(71), 1)
    vm._write(72, value, 4, 'high.load')
    vm.pc = 371
    value = vm.memory.load(vm.cells.pointer(72), 4)
    vm._write(73, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 374
    vm.auxiliary = (0, 6735)
    vm.pc = 380
    vm._write(74, vm._signed_cell(73, 0) ^ vm._signed_cell(70, 0), 8, 'high.flag1_xor_q')
    vm.pc = 385
    vm._write(75, vm.cells.value(74) & 255, 8, 'once9.mask_q')
    _store_cell(vm, 385, 1, 75, 71)
    vm.pc = 392
    vm.auxiliary = (0, 1466655236)
    vm.pc = 397
    vm._write(77, vm._signed_cell(64, 0) * vm._signed_cell(76, 0), 8, 'once0.integer')
    vm.pc = 400
    vm.auxiliary = (0, 1163874306)
    vm.pc = 405
    vm._write(79, vm._signed_cell(77, 0) + vm._signed_cell(78, 0), 8, 'once1.integer')
    vm.pc = 410
    vm._write(60, vm.cells.value(79) & 255, 8, 'once9.mask_q')
    vm.pc = 413
    vm.auxiliary = (0, 411004929)
    vm.pc = 418
    vm._write(62, vm._signed_cell(61, 15) + vm._signed_cell(3, 15), 8, 'once1.integer')
    vm.pc = 420
    vm._jump(9)


def _scratch_done(vm):
    vm.pc = 422
    vm._jump(8)


def _key_copy_start(vm):
    vm.pc = 444
    vm._jump(14)


def _key_transform_gate(vm):
    vm.pc = 513
    vm._jump(17 if vm.cells.value(40) != 0 else 18)


def _key_copy_head(vm):
    vm.pc = 451
    if vm.predecessor == 12:
        value = vm.cells.value(35)
    elif vm.predecessor == 15:
        value = vm.cells.value(84)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(83, value, 8, 'L9.phi_q')
    vm.pc = 458
    if vm.predecessor == 12:
        value = vm.cells.value(82)
    elif vm.predecessor == 15:
        value = vm.cells.value(86)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(85, value, 8, 'L9.phi_q')
    vm.pc = 465
    if vm.predecessor == 12:
        value = vm.cells.value(34)
    elif vm.predecessor == 15:
        value = vm.cells.value(88)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(87, value, 8, 'L9.phi_q')
    vm.pc = 466
    vm.pc = 469
    vm.auxiliary = (0, 1622302722)
    vm.pc = 474
    vm._write(88, vm._signed_cell(87, 15) + vm._signed_cell(89, 15), 8, 'once1.integer')
    vm.pc = 479
    vm._write(90, int(vm.cells.value(87) > vm.cells.value(36)), 4, 'L31.comparison')
    vm.pc = 483
    vm._jump(15 if vm.cells.value(90) != 0 else 16)


def _key_copy_byte(vm):
    _indexed_pointer(vm, 483, 84, 2, 83, (23,))
    vm.pc = 494
    value = vm.memory.load(vm.cells.value(83), 1)
    vm._write(91, value, 4, 'high.load')
    _indexed_pointer(vm, 494, 86, 2, 85, (23,))
    _store_cell(vm, 501, 1, 91, 85)
    vm.pc = 507
    vm._jump(14)


def _key_copy_done(vm):
    vm.pc = 509
    vm._jump(13)


def _key_transform_gate_two(vm):
    vm.pc = 517
    vm._jump(19 if vm.cells.value(40) != 0 else 18)


def _prepare_field22(vm):
    _indexed_pointer(vm, 647, 110, 25, 5, (16, 111))
    _indexed_pointer(vm, 655, 112, 4, 110, (36, 36))
    _store_cell(vm, 663, 1, 113, 112)
    vm.pc = 671
    vm._jump(23 if vm.cells.value(40) != 0 else 24)


def _key_seed(vm):
    vm.pc = 521
    value = vm.memory.load(vm.cells.value(43), 1)
    vm._write(92, value, 4, 'high.load')
    vm.pc = 523
    vm._jump(20)


def _key_head(vm):
    vm.pc = 530
    if vm.predecessor == 19:
        value = vm.cells.value(36)
    elif vm.predecessor == 21:
        value = vm.cells.value(94)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(93, value, 8, 'L9.phi_q')
    vm.pc = 537
    if vm.predecessor == 19:
        value = vm.cells.value(92)
    elif vm.predecessor == 21:
        value = vm.cells.value(96)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(95, value, 8, 'L9.phi_q')
    vm.pc = 542
    vm._write(97, int(vm.cells.value(93) < vm.cells.value(34)), 4, 'once18.unsigned_q')
    vm.pc = 546
    vm._jump(21 if vm.cells.value(97) != 0 else 22)


def _mix_key_byte(vm):
    vm.pc = 551
    value = vm.memory.load(vm.cells.pointer(95), 4)
    vm._write(98, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 552
    vm.pc = 555
    vm.auxiliary = (0, 204370436)
    vm.pc = 560
    vm._write(99, vm._signed_cell(93, 15) * vm._signed_cell(65, 15), 8, 'once0.integer')
    vm.pc = 565
    vm._write(100, vm.cells.value(99) & 255, 8, 'once9.mask_q')
    vm.pc = 570
    value = vm.memory.load(vm.cells.pointer(100), 4)
    vm._write(101, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 573
    vm.auxiliary = (0, 56158)
    vm.pc = 579
    vm._write(102, vm._signed_cell(98, 0) ^ vm._signed_cell(101, 0), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 579, 103, 3, 80, (36, 93))
    vm.pc = 591
    value = vm.memory.load(vm.cells.value(103), 1)
    vm._write(104, value, 4, 'high.load')
    vm.pc = 596
    value = vm.memory.load(vm.cells.pointer(104), 4)
    vm._write(105, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 599
    vm.auxiliary = (0, 20054)
    vm.pc = 605
    vm._write(106, vm._signed_cell(105, 0) ^ vm._signed_cell(102, 0), 8, 'high.flag1_xor_q')
    vm.pc = 610
    vm._write(107, vm.cells.value(106) & 255, 8, 'once9.mask_q')
    _store_cell(vm, 610, 1, 107, 103)
    vm.pc = 617
    vm.auxiliary = (0, 614781444)
    vm.pc = 622
    vm._write(108, vm._signed_cell(98, 0) * vm._signed_cell(76, 0), 8, 'once0.integer')
    vm.pc = 625
    vm.auxiliary = (0, 1210048514)
    vm.pc = 630
    vm._write(109, vm._signed_cell(108, 0) + vm._signed_cell(78, 0), 8, 'once1.integer')
    vm.pc = 635
    vm._write(96, vm.cells.value(109) & 255, 8, 'once9.mask_q')
    vm.pc = 638
    vm.auxiliary = (0, 1464307714)
    vm.pc = 643
    vm._write(94, vm._signed_cell(93, 15) + vm._signed_cell(3, 15), 8, 'once1.integer')
    vm.pc = 645
    vm._jump(20)


def _key_done(vm):
    vm.pc = 647
    vm._jump(18)


def _field22_gate(vm):
    vm.pc = 675
    vm._jump(25 if vm.cells.value(40) != 0 else 24)


def _prepare_field23(vm):
    _indexed_pointer(vm, 817, 134, 25, 5, (16, 135))
    _indexed_pointer(vm, 825, 136, 4, 134, (36, 36))
    _store_cell(vm, 833, 1, 137, 136)
    vm.pc = 841
    vm._jump(29 if vm.cells.value(40) != 0 else 30)


def _field22_seed(vm):
    _indexed_pointer(vm, 675, 114, 5, 41, (36, 3))
    vm.pc = 687
    value = vm.memory.load(vm.cells.value(114), 1)
    vm._write(115, value, 4, 'high.load')
    vm.pc = 689
    vm._jump(26)


def _field22_head(vm):
    vm.pc = 696
    if vm.predecessor == 25:
        value = vm.cells.value(36)
    elif vm.predecessor == 27:
        value = vm.cells.value(117)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(116, value, 8, 'L9.phi_q')
    vm.pc = 703
    if vm.predecessor == 25:
        value = vm.cells.value(115)
    elif vm.predecessor == 27:
        value = vm.cells.value(119)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(118, value, 8, 'L9.phi_q')
    vm.pc = 708
    vm._write(120, int(vm.cells.value(116) < vm.cells.value(3)), 4, 'once18.unsigned_q')
    vm.pc = 712
    vm._jump(27 if vm.cells.value(120) != 0 else 28)


def _field22_byte(vm):
    vm.pc = 717
    value = vm.memory.load(vm.cells.pointer(118), 4)
    vm._write(121, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 718
    vm.pc = 721
    vm.auxiliary = (0, 620065283)
    vm.pc = 726
    vm._write(122, vm._signed_cell(116, 15) * vm._signed_cell(65, 15), 8, 'once0.integer')
    vm.pc = 729
    vm.auxiliary = (0, 1460006913)
    vm.pc = 734
    vm._write(123, vm._signed_cell(122, 15) + vm._signed_cell(3, 15), 8, 'once1.integer')
    vm.pc = 739
    vm._write(124, vm.cells.value(123) & 255, 8, 'once9.mask_q')
    vm.pc = 744
    value = vm.memory.load(vm.cells.pointer(124), 4)
    vm._write(125, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 747
    vm.auxiliary = (0, 52333)
    vm.pc = 753
    vm._write(126, vm._signed_cell(121, 0) ^ vm._signed_cell(125, 0), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 753, 127, 4, 110, (36, 116))
    vm.pc = 765
    value = vm.memory.load(vm.cells.value(127), 1)
    vm._write(128, value, 4, 'high.load')
    vm.pc = 770
    value = vm.memory.load(vm.cells.pointer(128), 4)
    vm._write(129, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 775
    vm._write(130, vm._signed_cell(129, 0) ^ vm._signed_cell(126, 0), 8, 'L14.binary_q')
    vm.pc = 780
    vm._write(131, vm.cells.value(130) & 255, 8, 'once9.mask_q')
    _store_cell(vm, 780, 1, 131, 127)
    vm.pc = 787
    vm.auxiliary = (0, 1513533955)
    vm.pc = 792
    vm._write(132, vm._signed_cell(121, 0) * vm._signed_cell(76, 0), 8, 'once0.integer')
    vm.pc = 795
    vm.auxiliary = (0, 558899202)
    vm.pc = 800
    vm._write(133, vm._signed_cell(132, 0) + vm._signed_cell(78, 0), 8, 'once1.integer')
    vm.pc = 805
    vm._write(119, vm.cells.value(133) & 255, 8, 'once9.mask_q')
    vm.pc = 808
    vm.auxiliary = (0, 2078179330)
    vm.pc = 813
    vm._write(117, vm._signed_cell(116, 15) + vm._signed_cell(3, 15), 8, 'once1.integer')
    vm.pc = 815
    vm._jump(26)


def _field22_done(vm):
    vm.pc = 817
    vm._jump(24)


def _field23_gate(vm):
    vm.pc = 845
    vm._jump(31 if vm.cells.value(40) != 0 else 30)


def _prepare_field24(vm):
    _indexed_pointer(vm, 983, 159, 25, 5, (16, 160))
    _indexed_pointer(vm, 991, 161, 4, 159, (36, 36))
    _store_cell(vm, 999, 1, 162, 161)
    vm.pc = 1007
    vm._jump(35 if vm.cells.value(40) != 0 else 36)


def _field23_seed(vm):
    _indexed_pointer(vm, 845, 138, 5, 41, (36, 139))
    vm.pc = 857
    value = vm.memory.load(vm.cells.value(138), 1)
    vm._write(140, value, 4, 'high.load')
    vm.pc = 859
    vm._jump(32)


def _field23_head(vm):
    vm.pc = 866
    if vm.predecessor == 31:
        value = vm.cells.value(36)
    elif vm.predecessor == 33:
        value = vm.cells.value(142)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(141, value, 8, 'L9.phi_q')
    vm.pc = 873
    if vm.predecessor == 31:
        value = vm.cells.value(140)
    elif vm.predecessor == 33:
        value = vm.cells.value(144)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(143, value, 8, 'L9.phi_q')
    vm.pc = 878
    vm._write(145, int(vm.cells.value(141) < vm.cells.value(3)), 4, 'once18.unsigned_q')
    vm.pc = 882
    vm._jump(33 if vm.cells.value(145) != 0 else 34)


def _field23_byte(vm):
    vm.pc = 887
    value = vm.memory.load(vm.cells.pointer(143), 4)
    vm._write(146, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 888
    vm.pc = 891
    vm.auxiliary = (0, 1575412227)
    vm.pc = 896
    vm._write(147, vm._signed_cell(141, 15) * vm._signed_cell(65, 15), 8, 'once0.integer')
    vm.pc = 899
    vm.auxiliary = (0, 1265541122)
    vm.pc = 904
    vm._write(148, vm._signed_cell(147, 15) + vm._signed_cell(139, 15), 8, 'once1.integer')
    vm.pc = 909
    vm._write(149, vm.cells.value(148) & 255, 8, 'once9.mask_q')
    vm.pc = 914
    value = vm.memory.load(vm.cells.pointer(149), 4)
    vm._write(150, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 919
    vm._write(151, vm._signed_cell(146, 0) ^ vm._signed_cell(150, 0), 8, 'L14.binary_q')
    _indexed_pointer(vm, 919, 152, 4, 134, (36, 141))
    vm.pc = 931
    value = vm.memory.load(vm.cells.value(152), 1)
    vm._write(153, value, 4, 'high.load')
    vm.pc = 936
    value = vm.memory.load(vm.cells.pointer(153), 4)
    vm._write(154, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 941
    vm._write(155, vm._signed_cell(154, 0) ^ vm._signed_cell(151, 0), 8, 'L14.binary_q')
    vm.pc = 946
    vm._write(156, vm.cells.value(155) & 255, 8, 'once9.mask_q')
    _store_cell(vm, 946, 1, 156, 152)
    vm.pc = 953
    vm.auxiliary = (0, 1262658051)
    vm.pc = 958
    vm._write(157, vm._signed_cell(146, 0) * vm._signed_cell(76, 0), 8, 'once0.integer')
    vm.pc = 961
    vm.auxiliary = (0, 868597761)
    vm.pc = 966
    vm._write(158, vm._signed_cell(157, 0) + vm._signed_cell(78, 0), 8, 'once1.integer')
    vm.pc = 971
    vm._write(144, vm.cells.value(158) & 255, 8, 'once9.mask_q')
    vm.pc = 974
    vm.auxiliary = (0, 1512173569)
    vm.pc = 979
    vm._write(142, vm._signed_cell(141, 15) + vm._signed_cell(3, 15), 8, 'once1.integer')
    vm.pc = 981
    vm._jump(32)


def _field23_done(vm):
    vm.pc = 983
    vm._jump(30)


def _field24_gate(vm):
    vm.pc = 1011
    vm._jump(37 if vm.cells.value(40) != 0 else 36)


def _publish_container_fields(vm):
    _indexed_pointer(vm, 1157, 184, 25, 5, (16, 76))
    _indexed_pointer(vm, 1165, 185, 16, 184, (36, 36))
    vm.pc = 1178
    vm.cells.copy_q_clear_owned(186, 187)
    _store_cell(vm, 1178, 8, 187, 185)
    _indexed_pointer(vm, 1182, 188, 16, 184, (36, 3))
    vm.pc = 1195
    vm.cells.copy_q_clear_owned(189, 190)
    _store_cell(vm, 1195, 8, 190, 188)
    _indexed_pointer(vm, 1199, 191, 16, 184, (36, 139))
    vm.pc = 1212
    vm.cells.copy_q_clear_owned(192, 193)
    _store_cell(vm, 1212, 8, 193, 191)
    vm.pc = 1220
    value = vm.memory.load(vm.cells.value(15), 4)
    vm._write(194, value, 4, 'high.load')
    _indexed_pointer(vm, 1220, 195, 25, 5, (16, 196))
    _store_cell(vm, 1228, 4, 194, 195)
    vm.pc = 1236
    value = vm.memory.load(vm.cells.value(15), 4)
    vm._write(197, value, 4, 'high.load')
    _indexed_pointer(vm, 1236, 198, 3, 0, (36, 139))
    vm.pc = 1248
    value = vm.memory.load(vm.cells.value(198), 1)
    vm._write(199, value, 4, 'high.load')
    vm.pc = 1253
    value = vm.memory.load(vm.cells.pointer(199), 4)
    vm._write(200, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1258
    vm._write(201, vm._signed_cell(197, 0) ^ vm._signed_cell(200, 0), 8, 'L14.binary_q')
    _indexed_pointer(vm, 1258, 202, 25, 5, (16, 203))
    _store_cell(vm, 1266, 4, 201, 202)
    vm.pc = 1274
    value = vm.memory.load(vm.cells.value(15), 4)
    vm._write(204, value, 4, 'high.load')
    _indexed_pointer(vm, 1274, 205, 3, 0, (36, 3))
    vm.pc = 1286
    value = vm.memory.load(vm.cells.value(205), 1)
    vm._write(206, value, 4, 'high.load')
    vm.pc = 1291
    value = vm.memory.load(vm.cells.pointer(206), 4)
    vm._write(207, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1296
    vm._write(208, vm._signed_cell(204, 0) ^ vm._signed_cell(207, 0), 8, 'L14.binary_q')
    _indexed_pointer(vm, 1296, 209, 25, 5, (16, 47))
    _store_cell(vm, 1304, 4, 208, 209)
    vm.pc = 1312
    value = vm.memory.load(vm.cells.value(15), 4)
    vm._write(210, value, 4, 'high.load')
    vm.pc = 1313
    vm.pc = 1316
    vm.auxiliary = (0, 20775)
    vm.pc = 1321
    vm._write(212, vm._signed_cell(210, 0) & vm._signed_cell(211, 0), 8, 'typed.selector1.q')
    vm.pc = 1326
    vm._write(213, vm.cells.value(212) & 65535, 8, 'once9.mask_q')
    _indexed_pointer(vm, 1326, 214, 25, 5, (16, 78))
    _store_cell(vm, 1334, 2, 213, 214)
    _indexed_pointer(vm, 1338, 215, 25, 5, (16, 216))
    _store_cell(vm, 1346, 4, 16, 215)
    _indexed_pointer(vm, 1350, 217, 25, 5, (16, 218))
    _store_cell(vm, 1358, 4, 16, 217)
    _indexed_pointer(vm, 1362, 219, 25, 5, (16, 220))
    _store_cell(vm, 1370, 1, 221, 219)
    _indexed_pointer(vm, 1374, 222, 25, 5, (16, 223))
    _store_cell(vm, 1382, 1, 224, 222)
    _indexed_pointer(vm, 1386, 225, 25, 5, (16, 226))
    _store_cell(vm, 1394, 1, 224, 225)
    _indexed_pointer(vm, 1398, 227, 25, 5, (16, 228))
    _store_cell(vm, 1406, 1, 224, 227)
    _indexed_pointer(vm, 1410, 229, 25, 5, (16, 230))
    _store_cell(vm, 1418, 1, 224, 229)
    vm.pc = 1424
    vm._jump(41)


def _field24_seed(vm):
    _indexed_pointer(vm, 1011, 163, 5, 41, (36, 164))
    vm.pc = 1023
    value = vm.memory.load(vm.cells.value(163), 1)
    vm._write(165, value, 4, 'high.load')
    vm.pc = 1025
    vm._jump(38)


def _field24_head(vm):
    vm.pc = 1032
    if vm.predecessor == 37:
        value = vm.cells.value(36)
    elif vm.predecessor == 39:
        value = vm.cells.value(167)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(166, value, 8, 'L9.phi_q')
    vm.pc = 1039
    if vm.predecessor == 37:
        value = vm.cells.value(165)
    elif vm.predecessor == 39:
        value = vm.cells.value(169)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(168, value, 8, 'L9.phi_q')
    vm.pc = 1044
    vm._write(170, int(vm.cells.value(166) < vm.cells.value(3)), 4, 'once18.unsigned_q')
    vm.pc = 1048
    vm._jump(39 if vm.cells.value(170) != 0 else 40)


def _field24_byte(vm):
    vm.pc = 1053
    value = vm.memory.load(vm.cells.pointer(168), 4)
    vm._write(171, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1054
    vm.pc = 1057
    vm.auxiliary = (0, 1561465347)
    vm.pc = 1062
    vm._write(172, vm._signed_cell(166, 15) * vm._signed_cell(65, 15), 8, 'once0.integer')
    vm.pc = 1065
    vm.auxiliary = (0, 658829314)
    vm.pc = 1070
    vm._write(173, vm._signed_cell(172, 15) + vm._signed_cell(164, 15), 8, 'once1.integer')
    vm.pc = 1075
    vm._write(174, vm.cells.value(173) & 255, 8, 'once9.mask_q')
    vm.pc = 1080
    value = vm.memory.load(vm.cells.pointer(174), 4)
    vm._write(175, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1083
    vm.auxiliary = (0, 18532)
    vm.pc = 1089
    vm._write(176, vm._signed_cell(171, 0) ^ vm._signed_cell(175, 0), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 1089, 177, 4, 159, (36, 166))
    vm.pc = 1101
    value = vm.memory.load(vm.cells.value(177), 1)
    vm._write(178, value, 4, 'high.load')
    vm.pc = 1106
    value = vm.memory.load(vm.cells.pointer(178), 4)
    vm._write(179, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1109
    vm.auxiliary = (0, 35446)
    vm.pc = 1115
    vm._write(180, vm._signed_cell(179, 0) ^ vm._signed_cell(176, 0), 8, 'high.flag1_xor_q')
    vm.pc = 1120
    vm._write(181, vm.cells.value(180) & 255, 8, 'once9.mask_q')
    _store_cell(vm, 1120, 1, 181, 177)
    vm.pc = 1127
    vm.auxiliary = (0, 1022018052)
    vm.pc = 1132
    vm._write(182, vm._signed_cell(171, 0) * vm._signed_cell(76, 0), 8, 'once0.integer')
    vm.pc = 1135
    vm.auxiliary = (0, 1723604994)
    vm.pc = 1140
    vm._write(183, vm._signed_cell(182, 0) + vm._signed_cell(78, 0), 8, 'once1.integer')
    vm.pc = 1145
    vm._write(169, vm.cells.value(183) & 255, 8, 'once9.mask_q')
    vm.pc = 1148
    vm.auxiliary = (0, 668938242)
    vm.pc = 1153
    vm._write(167, vm._signed_cell(166, 15) + vm._signed_cell(3, 15), 8, 'once1.integer')
    vm.pc = 1155
    vm._jump(38)


def _field24_done(vm):
    vm.pc = 1157
    vm._jump(36)


def _salt_tail_head(vm):
    vm.pc = 1431
    if vm.predecessor == 36:
        value = vm.cells.value(16)
    elif vm.predecessor == 42:
        value = vm.cells.value(232)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(231, value, 8, 'L9.phi_q')
    vm.pc = 1432
    vm.pc = 1435
    vm.auxiliary = (0, 987932677)
    vm.pc = 1440
    a = vm._signed_cell(231, 0) & ((1 << 64) - 1)
    b = vm._signed_cell(230, 0) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(233, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1444
    vm._jump(42 if vm.cells.value(233) != 0 else 43)


def _copy_salt_tail_byte(vm):
    vm.pc = 1454
    vm.pc = 1457
    vm.auxiliary = (0, 870174721)
    vm.pc = 1462
    vm._write(235, vm._signed_cell(231, 0) + vm._signed_cell(226, 0), 8, 'once1.integer')
    vm.pc = 1467
    vm.cells.copy_q_clear_owned(235, 236)
    _indexed_pointer(vm, 1467, 237, 5, 41, (36, 236))
    vm.pc = 1479
    value = vm.memory.load(vm.cells.value(237), 1)
    vm._write(238, value, 4, 'high.load')
    _indexed_pointer(vm, 1479, 239, 25, 5, (16, 240))
    vm.pc = 1492
    vm.cells.copy_q_clear_owned(231, 241)
    _indexed_pointer(vm, 1492, 242, 17, 239, (36, 241))
    _store_cell(vm, 1500, 1, 238, 242)
    vm.pc = 1507
    vm.auxiliary = (0, 771301378)
    vm.pc = 1512
    vm._write(232, vm._signed_cell(231, 0) + vm._signed_cell(23, 0), 8, 'once1.integer')
    vm.pc = 1514
    vm._jump(41)


def _unlock_container(vm):
    _native_call(vm, 1444, 1451, 45, 39, (5, 234))
    vm.pc = 1453
    vm._jump(3)


def run_primary_singleton_init(vm):
    _allocate_scratch_and_container(vm)
    if vm.block == 1:
        _null_container(vm)
        _return_container(vm)
        return vm.result
    _initialize_base(vm)
    while True:
        _salt_head(vm)
        if vm.block == 6:
            break
        _salt_byte(vm)
    _initialize_entropy_and_lock(vm)
    if vm.block == 7:
        _load_scratch_seed(vm)
        while True:
            _scratch_head(vm)
            if vm.block == 11:
                break
            _mix_scratch_byte(vm)
        _scratch_done(vm)
    _prepare_key_copy(vm)
    if vm.block == 12:
        _key_copy_start(vm)
        while True:
            _key_copy_head(vm)
            if vm.block == 16:
                break
            _key_copy_byte(vm)
        _key_copy_done(vm)
    _key_transform_gate(vm)
    if vm.block == 17:
        _key_transform_gate_two(vm)
        if vm.block == 19:
            _key_seed(vm)
            while True:
                _key_head(vm)
                if vm.block == 22:
                    break
                _mix_key_byte(vm)
            _key_done(vm)
    _prepare_field22(vm)
    if vm.block == 23:
        _field22_gate(vm)
        if vm.block == 25:
            _field22_seed(vm)
            while True:
                _field22_head(vm)
                if vm.block == 28:
                    break
                _field22_byte(vm)
            _field22_done(vm)
    _prepare_field23(vm)
    if vm.block == 29:
        _field23_gate(vm)
        if vm.block == 31:
            _field23_seed(vm)
            while True:
                _field23_head(vm)
                if vm.block == 34:
                    break
                _field23_byte(vm)
            _field23_done(vm)
    _prepare_field24(vm)
    if vm.block == 35:
        _field24_gate(vm)
        if vm.block == 37:
            _field24_seed(vm)
            while True:
                _field24_head(vm)
                if vm.block == 40:
                    break
                _field24_byte(vm)
            _field24_done(vm)
    _publish_container_fields(vm)
    while True:
        _salt_tail_head(vm)
        if vm.block == 43:
            break
        _copy_salt_tail_byte(vm)
    _unlock_container(vm)
    _return_container(vm)
    return vm.result
