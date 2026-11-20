from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell
from .primary_vm import PrimarySemanticUnavailable


def _validate_pointers(vm):
    vm.pc = 4
    vm._allocate(3, 4)
    vm.pc = 7
    vm._allocate(30, 5)
    vm.pc = 8
    vm.pc = 11
    vm.auxiliary = (0, 532830308)
    vm.pc = 16
    value = int(vm._signed_cell(0, 26) != vm._signed_cell(6, 26))
    vm._write(7, value, 4, 'L30.comparison')
    vm.pc = 19
    vm.auxiliary = (0, 501367444)
    vm.pc = 24
    value = int(vm._signed_cell(1, 23) != vm._signed_cell(8, 23))
    vm._write(9, value, 4, 'L30.comparison')
    vm.pc = 27
    vm.auxiliary = (0, 46621)
    vm.pc = 32
    vm._write(10, vm._signed_cell(7, 32) & vm._signed_cell(9, 32), 8, 'typed.selector1.q')
    vm.pc = 35
    vm.auxiliary = (0, 52583)
    vm.pc = 41
    vm._write(12, vm._signed_cell(10, 32) ^ vm._signed_cell(11, 32), 8, 'high.flag1_xor_q')
    vm.pc = 44
    vm.auxiliary = (0, 348292228)
    vm.pc = 49
    value = int(vm._signed_cell(2, 0) != vm._signed_cell(13, 0))
    vm._write(14, value, 4, 'L30.comparison')
    vm.pc = 52
    vm.auxiliary = (0, 13283)
    vm.pc = 57
    vm._write(15, vm._signed_cell(12, 32) | vm._signed_cell(14, 32), 8, 'typed.selector2.q')
    vm.pc = 61
    vm._jump(1 if vm.cells.value(15) != 0 else 2)


def _invalid_pointers(vm):
    vm.pc = 63
    vm._jump(3)


def _validate_kind(vm):
    vm.pc = 64
    vm.pc = 67
    vm.auxiliary = (0, 597859604)
    vm.pc = 72
    value = int(vm._signed_cell(3, 0) != vm._signed_cell(16, 0))
    vm._write(17, value, 4, 'L30.comparison')
    vm.pc = 75
    vm.auxiliary = (0, 1257428308)
    vm.pc = 80
    value = int(vm._signed_cell(3, 0) != vm._signed_cell(18, 0))
    vm._write(19, value, 4, 'L30.comparison')
    vm.pc = 85
    vm._write(20, vm._signed_cell(17, 32) & vm._signed_cell(19, 32), 8, 'L13.binary_q')
    vm.pc = 89
    vm._jump(4 if vm.cells.value(20) != 0 else 5)


def _return_result(vm):
    vm.pc = 2130
    if vm.predecessor == 1:
        value = vm.cells.value(169)
    elif vm.predecessor == 4:
        value = vm.cells.value(169)
    elif vm.predecessor == 43:
        value = vm.cells.value(303)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(304, value, 8, 'L9.phi_q')
    vm.pc = 2133
    vm.result, vm.halted = vm._signed_cell(304, 0) & ((1 << 64) - 1), True


def _invalid_kind(vm):
    vm.pc = 91
    vm._jump(3)


def _lock_material(vm):
    _native_call(vm, 91, 98, 34, 21, (0, 11))
    vm.pc = 103
    vm.cells.copy_q_clear_owned(4, 22)
    _indexed_pointer(vm, 103, 23, 3, 4, (24, 24))
    _indexed_pointer(vm, 111, 25, 25, 0, (26, 18))
    _indexed_pointer(vm, 119, 27, 3, 25, (24, 24))
    vm.pc = 131
    vm._jump(6 if vm.cells.value(11) != 0 else 7)


def _copy_start(vm):
    vm.pc = 133
    vm._jump(8)


def _salt_address(vm):
    _indexed_pointer(vm, 198, 38, 25, 0, (26, 39))
    _indexed_pointer(vm, 206, 40, 5, 38, (24, 24))
    vm.pc = 218
    vm._jump(11 if vm.cells.value(11) != 0 else 12)


def _copy_head(vm):
    vm.pc = 140
    if vm.predecessor == 6:
        value = vm.cells.value(27)
    elif vm.predecessor == 9:
        value = vm.cells.value(29)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(28, value, 8, 'L9.phi_q')
    vm.pc = 147
    if vm.predecessor == 6:
        value = vm.cells.value(23)
    elif vm.predecessor == 9:
        value = vm.cells.value(31)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(30, value, 8, 'L9.phi_q')
    vm.pc = 154
    if vm.predecessor == 6:
        value = vm.cells.value(33)
    elif vm.predecessor == 9:
        value = vm.cells.value(34)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(32, value, 8, 'L9.phi_q')
    vm.pc = 155
    vm.pc = 158
    vm.auxiliary = (0, 354484226)
    vm.pc = 163
    vm._write(34, vm._signed_cell(32, 15) + vm._signed_cell(35, 15), 8, 'once1.integer')
    vm.pc = 168
    value = int(vm.cells.value(32) > vm.cells.value(24))
    vm._write(36, value, 4, 'L31.comparison')
    vm.pc = 172
    vm._jump(9 if vm.cells.value(36) != 0 else 10)


def _copy_byte(vm):
    _indexed_pointer(vm, 172, 29, 2, 28, (16,))
    vm.pc = 183
    value = vm.memory.load(vm.cells.value(28), 1)
    vm._write(37, value, 4, 'high.load')
    _indexed_pointer(vm, 183, 31, 2, 30, (16,))
    vm.pc = 194
    _store_cell(vm, 190, 1, 37, 30)
    vm.pc = 196
    vm._jump(8)


def _copy_done(vm):
    vm.pc = 198
    vm._jump(7)


def _salt_seed(vm):
    vm.pc = 222
    value = vm.memory.load(vm.cells.value(40), 1)
    vm._write(41, value, 4, 'high.load')
    vm.pc = 224
    vm._jump(13)


def _expire(vm):
    _indexed_pointer(vm, 348, 63, 3, 4, (24, 64))
    vm.pc = 360
    value = vm.memory.load(vm.cells.value(63), 1)
    vm._write(65, value, 4, 'high.load')
    _native_call(vm, 360, 367, 37, 66, (0, 65))
    vm.pc = 372
    vm.cells.copy_q_clear_owned(5, 67)
    _native_call(vm, 372, 381, 39, 69, (67, 26, 70), 68)
    _indexed_pointer(vm, 381, 71, 30, 5, (24, 24))
    vm.pc = 393
    vm._jump(16 if vm.cells.value(11) != 0 else 17)


def _material_head(vm):
    vm.pc = 231
    if vm.predecessor == 11:
        value = vm.cells.value(41)
    elif vm.predecessor == 14:
        value = vm.cells.value(43)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(42, value, 8, 'L9.phi_q')
    vm.pc = 238
    if vm.predecessor == 11:
        value = vm.cells.value(24)
    elif vm.predecessor == 14:
        value = vm.cells.value(45)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(44, value, 8, 'L9.phi_q')
    vm.pc = 243
    vm._write(46, int(vm.cells.value(44) < vm.cells.value(33)), 4, 'once18.unsigned_q')
    vm.pc = 247
    vm._jump(14 if vm.cells.value(46) != 0 else 15)


def _material_byte(vm):
    vm.pc = 252
    value = vm.memory.load(vm.cells.pointer(42), 4)
    vm._write(47, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 253
    vm.pc = 256
    vm.auxiliary = (0, 1871913475)
    vm.pc = 261
    vm._write(49, vm._signed_cell(44, 15) * vm._signed_cell(48, 15), 8, 'once0.integer')
    vm.pc = 266
    vm._write(50, vm.cells.value(49) & 255, 8, 'once9.mask_q')
    vm.pc = 271
    value = vm.memory.load(vm.cells.pointer(50), 4)
    vm._write(51, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 274
    vm.auxiliary = (0, 39188)
    vm.pc = 280
    vm._write(52, vm._signed_cell(47, 0) ^ vm._signed_cell(51, 0), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 280, 53, 3, 4, (24, 44))
    vm.pc = 292
    value = vm.memory.load(vm.cells.value(53), 1)
    vm._write(54, value, 4, 'high.load')
    vm.pc = 297
    value = vm.memory.load(vm.cells.pointer(54), 4)
    vm._write(55, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 300
    vm.auxiliary = (0, 22637)
    vm.pc = 306
    vm._write(56, vm._signed_cell(55, 0) ^ vm._signed_cell(52, 0), 8, 'high.flag1_xor_q')
    vm.pc = 311
    vm._write(57, vm.cells.value(56) & 255, 8, 'once9.mask_q')
    vm.pc = 315
    _store_cell(vm, 311, 1, 57, 53)
    vm.pc = 318
    vm.auxiliary = (0, 306815492)
    vm.pc = 323
    vm._write(59, vm._signed_cell(47, 0) * vm._signed_cell(58, 0), 8, 'once0.integer')
    vm.pc = 326
    vm.auxiliary = (0, 718753793)
    vm.pc = 331
    vm._write(61, vm._signed_cell(59, 0) + vm._signed_cell(60, 0), 8, 'once1.integer')
    vm.pc = 336
    vm._write(43, vm.cells.value(61) & 255, 8, 'once9.mask_q')
    vm.pc = 339
    vm.auxiliary = (0, 458735618)
    vm.pc = 344
    vm._write(45, vm._signed_cell(44, 15) + vm._signed_cell(62, 15), 8, 'once1.integer')
    vm.pc = 346
    vm._jump(13)


def _material_done(vm):
    vm.pc = 348
    vm._jump(12)


def _clear_start(vm):
    vm.pc = 395
    vm._jump(18)


def _duplicate_start(vm):
    vm.pc = 444
    vm._jump(21)


def _clear_head(vm):
    vm.pc = 402
    if vm.predecessor == 16:
        value = vm.cells.value(71)
    elif vm.predecessor == 19:
        value = vm.cells.value(73)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(72, value, 8, 'L9.phi_q')
    vm.pc = 409
    if vm.predecessor == 16:
        value = vm.cells.value(70)
    elif vm.predecessor == 19:
        value = vm.cells.value(75)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(74, value, 8, 'L9.phi_q')
    vm.pc = 410
    vm.pc = 413
    vm.auxiliary = (0, 1021333506)
    vm.pc = 418
    vm._write(75, vm._signed_cell(74, 15) + vm._signed_cell(35, 15), 8, 'once1.integer')
    vm.pc = 423
    value = int(vm.cells.value(74) > vm.cells.value(24))
    vm._write(76, value, 4, 'L31.comparison')
    vm.pc = 427
    vm._jump(19 if vm.cells.value(76) != 0 else 20)


def _clear_byte(vm):
    _indexed_pointer(vm, 427, 73, 2, 72, (16,))
    vm.pc = 438
    _store_cell(vm, 434, 1, 77, 72)
    vm.pc = 440
    vm._jump(18)


def _clear_done(vm):
    vm.pc = 442
    vm._jump(17)


def _duplicate_head(vm):
    vm.pc = 451
    if vm.predecessor == 17:
        value = vm.cells.value(26)
    elif vm.predecessor == 22:
        value = vm.cells.value(79)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(78, value, 8, 'L9.phi_q')
    vm.pc = 452
    vm.pc = 455
    vm.auxiliary = (0, 483555141)
    vm.pc = 460
    a = vm._signed_cell(78, 0) & ((1 << 64) - 1)
    b = vm._signed_cell(80, 0) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(81, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 464
    vm._jump(23 if vm.cells.value(81) != 0 else 24)


def _duplicate_next(vm):
    vm.pc = 971
    vm.pc = 974
    vm.auxiliary = (0, 1761681410)
    vm.pc = 979
    vm._write(79, vm._signed_cell(78, 0) + vm._signed_cell(16, 0), 8, 'once1.integer')
    vm.pc = 981
    vm._jump(21)


def _inspect_active(vm):
    _indexed_pointer(vm, 466, 82, 25, 0, (26, 83))
    vm.pc = 479
    vm.cells.copy_q_clear_owned(78, 84)
    _indexed_pointer(vm, 479, 85, 8, 82, (24, 84))
    _indexed_pointer(vm, 487, 86, 7, 85, (26, 87))
    vm.pc = 499
    value = vm.memory.load(vm.cells.value(86), 1)
    vm._write(88, value, 4, 'high.load')
    vm.pc = 500
    vm.pc = 503
    vm.auxiliary = (0, 485643316)
    vm.pc = 508
    value = int(vm._signed_cell(88, 2) != vm._signed_cell(77, 2))
    vm._write(89, value, 4, 'L27.comparison')
    vm.pc = 512
    vm._jump(26 if vm.cells.value(89) != 0 else 22)


def _duplicate_done(vm):
    vm.pc = 466
    vm._jump(25)


def _duplicate_result(vm):
    vm.pc = 988
    if vm.predecessor == 41:
        value = vm.cells.value(16)
    elif vm.predecessor == 24:
        value = vm.cells.value(157)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(156, value, 8, 'L9.phi_q')
    vm.pc = 989
    vm.pc = 992
    vm.auxiliary = (0, 1609730563)
    vm.pc = 993
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = 997
    value = int(vm._signed_cell(156, 0) == vm._signed_cell(157, 0))
    vm._write(158, value, 4, 'L26.comparison')
    vm.pc = 1001
    vm._jump(42 if vm.cells.value(158) != 0 else 43)


def _inspect_kind(vm):
    _indexed_pointer(vm, 512, 90, 7, 85, (26, 13))
    vm.pc = 524
    value = vm.memory.load(vm.cells.value(90), 1)
    vm._write(91, value, 4, 'high.load')
    vm.pc = 529
    value = vm.memory.load(vm.cells.pointer(91), 4)
    vm._write(92, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 530
    vm.pc = 533
    vm.auxiliary = (0, 270667891)
    vm.pc = 534
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = 538
    value = int(vm._signed_cell(92, 0) == vm._signed_cell(3, 0))
    vm._write(93, value, 4, 'L26.comparison')
    vm.pc = 542
    vm._jump(27 if vm.cells.value(93) != 0 else 22)


def _token_address(vm):
    _indexed_pointer(vm, 542, 94, 7, 85, (26, 26))
    _indexed_pointer(vm, 550, 95, 6, 94, (24, 24))
    vm.pc = 562
    vm._jump(28 if vm.cells.value(11) != 0 else 29)


def _token_copy_start(vm):
    vm.pc = 564
    vm._jump(30)


def _decode_start(vm):
    _indexed_pointer(vm, 629, 105, 7, 85, (26, 18))
    vm.pc = 641
    value = vm.memory.load(vm.cells.value(105), 1)
    vm._write(106, value, 4, 'high.load')
    vm.pc = 645
    vm._jump(33 if vm.cells.value(11) != 0 else 34)


def _token_copy_head(vm):
    vm.pc = 571
    if vm.predecessor == 28:
        value = vm.cells.value(95)
    elif vm.predecessor == 31:
        value = vm.cells.value(97)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(96, value, 8, 'L9.phi_q')
    vm.pc = 578
    if vm.predecessor == 28:
        value = vm.cells.value(71)
    elif vm.predecessor == 31:
        value = vm.cells.value(99)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(98, value, 8, 'L9.phi_q')
    vm.pc = 585
    if vm.predecessor == 28:
        value = vm.cells.value(101)
    elif vm.predecessor == 31:
        value = vm.cells.value(102)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(100, value, 8, 'L9.phi_q')
    vm.pc = 586
    vm.pc = 589
    vm.auxiliary = (0, 1513410562)
    vm.pc = 594
    vm._write(102, vm._signed_cell(100, 15) + vm._signed_cell(35, 15), 8, 'once1.integer')
    vm.pc = 599
    value = int(vm.cells.value(100) > vm.cells.value(24))
    vm._write(103, value, 4, 'L31.comparison')
    vm.pc = 603
    vm._jump(31 if vm.cells.value(103) != 0 else 32)


def _token_copy_byte(vm):
    _indexed_pointer(vm, 603, 97, 2, 96, (16,))
    vm.pc = 614
    value = vm.memory.load(vm.cells.value(96), 1)
    vm._write(104, value, 4, 'high.load')
    _indexed_pointer(vm, 614, 99, 2, 98, (16,))
    vm.pc = 625
    _store_cell(vm, 621, 1, 104, 98)
    vm.pc = 627
    vm._jump(30)


def _token_copy_done(vm):
    vm.pc = 629
    vm._jump(29)


def _decode_seed(vm):
    vm.pc = 650
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    value = vm.cells.value(106)
    vm._write(107, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 650, 108, 5, 38, (24, 107))
    vm.pc = 662
    value = vm.memory.load(vm.cells.value(108), 1)
    vm._write(109, value, 4, 'high.load')
    vm.pc = 664
    vm._jump(35)


def _compare_first(vm):
    vm.pc = 796
    value = vm.memory.load(vm.cells.value(71), 1)
    vm._write(128, value, 4, 'high.load')
    vm.pc = 801
    value = vm.memory.load(vm.cells.pointer(128), 4)
    vm._write(129, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 805
    value = vm.memory.load(vm.cells.value(1), 1)
    vm._write(130, value, 4, 'high.load')
    vm.pc = 810
    value = vm.memory.load(vm.cells.pointer(130), 4)
    vm._write(131, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 811
    vm.pc = 814
    vm.auxiliary = (0, 2040665715)
    vm.pc = 815
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = 819
    value = int(vm._signed_cell(129, 0) == vm._signed_cell(131, 0))
    vm._write(132, value, 4, 'L26.comparison')
    vm.pc = 823
    vm._jump(38 if vm.cells.value(132) != 0 else 22)


def _decode_head(vm):
    vm.pc = 671
    if vm.predecessor == 33:
        value = vm.cells.value(24)
    elif vm.predecessor == 36:
        value = vm.cells.value(111)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(110, value, 8, 'L9.phi_q')
    vm.pc = 678
    if vm.predecessor == 33:
        value = vm.cells.value(109)
    elif vm.predecessor == 36:
        value = vm.cells.value(113)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(112, value, 8, 'L9.phi_q')
    vm.pc = 683
    vm._write(114, int(vm.cells.value(110) < vm.cells.value(101)), 4, 'once18.unsigned_q')
    vm.pc = 687
    vm._jump(36 if vm.cells.value(114) != 0 else 37)


def _decode_byte(vm):
    vm.pc = 692
    value = vm.memory.load(vm.cells.pointer(112), 4)
    vm._write(115, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 693
    vm.pc = 696
    vm.auxiliary = (0, 255181316)
    vm.pc = 701
    vm._write(116, vm._signed_cell(110, 15) * vm._signed_cell(48, 15), 8, 'once0.integer')
    vm.pc = 704
    vm.auxiliary = (0, 1368326145)
    vm.pc = 709
    vm._write(117, vm._signed_cell(116, 15) + vm._signed_cell(107, 15), 8, 'once1.integer')
    vm.pc = 714
    vm._write(118, vm.cells.value(117) & 255, 8, 'once9.mask_q')
    vm.pc = 719
    value = vm.memory.load(vm.cells.pointer(118), 4)
    vm._write(119, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 722
    vm.auxiliary = (0, 39173)
    vm.pc = 728
    vm._write(120, vm._signed_cell(115, 0) ^ vm._signed_cell(119, 0), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 728, 121, 30, 5, (24, 110))
    vm.pc = 740
    value = vm.memory.load(vm.cells.value(121), 1)
    vm._write(122, value, 4, 'high.load')
    vm.pc = 745
    value = vm.memory.load(vm.cells.pointer(122), 4)
    vm._write(123, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 750
    vm._write(124, vm._signed_cell(123, 0) ^ vm._signed_cell(120, 0), 8, 'L14.binary_q')
    vm.pc = 755
    vm._write(125, vm.cells.value(124) & 255, 8, 'once9.mask_q')
    vm.pc = 759
    _store_cell(vm, 755, 1, 125, 121)
    vm.pc = 762
    vm.auxiliary = (0, 1260270083)
    vm.pc = 767
    vm._write(126, vm._signed_cell(115, 0) * vm._signed_cell(58, 0), 8, 'once0.integer')
    vm.pc = 770
    vm.auxiliary = (0, 615636994)
    vm.pc = 775
    vm._write(127, vm._signed_cell(126, 0) + vm._signed_cell(60, 0), 8, 'once1.integer')
    vm.pc = 780
    vm._write(113, vm.cells.value(127) & 255, 8, 'once9.mask_q')
    vm.pc = 783
    vm.auxiliary = (0, 970977281)
    vm.pc = 788
    vm._write(111, vm._signed_cell(110, 15) + vm._signed_cell(62, 15), 8, 'once1.integer')
    vm.pc = 790
    vm._jump(35)


def _decode_done(vm):
    vm.pc = 792
    vm._jump(34)


def _compare_second(vm):
    _indexed_pointer(vm, 823, 133, 30, 5, (24, 62))
    vm.pc = 835
    value = vm.memory.load(vm.cells.value(133), 1)
    vm._write(134, value, 4, 'high.load')
    vm.pc = 840
    value = vm.memory.load(vm.cells.pointer(134), 4)
    vm._write(135, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 840, 136, 2, 1, (62,))
    vm.pc = 851
    value = vm.memory.load(vm.cells.value(136), 1)
    vm._write(137, value, 4, 'high.load')
    vm.pc = 856
    value = vm.memory.load(vm.cells.pointer(137), 4)
    vm._write(138, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 857
    vm.pc = 860
    vm.auxiliary = (0, 1229105747)
    vm.pc = 865
    vm._write(139, int(vm._signed_cell(135, 0) == vm._signed_cell(138, 0)), 4, 'once17.integer')
    vm.pc = 869
    vm._jump(39 if vm.cells.value(139) != 0 else 22)


def _compare_third(vm):
    _indexed_pointer(vm, 869, 140, 30, 5, (24, 141))
    vm.pc = 881
    value = vm.memory.load(vm.cells.value(140), 1)
    vm._write(142, value, 4, 'high.load')
    vm.pc = 886
    value = vm.memory.load(vm.cells.pointer(142), 4)
    vm._write(143, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 886, 144, 2, 1, (141,))
    vm.pc = 897
    value = vm.memory.load(vm.cells.value(144), 1)
    vm._write(145, value, 4, 'high.load')
    vm.pc = 902
    value = vm.memory.load(vm.cells.pointer(145), 4)
    vm._write(146, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 903
    vm.pc = 906
    vm.auxiliary = (0, 172115619)
    vm.pc = 911
    vm._write(147, int(vm._signed_cell(143, 0) == vm._signed_cell(146, 0)), 4, 'once17.integer')
    vm.pc = 915
    vm._jump(40 if vm.cells.value(147) != 0 else 22)


def _compare_fourth(vm):
    _indexed_pointer(vm, 915, 148, 30, 5, (24, 64))
    vm.pc = 927
    value = vm.memory.load(vm.cells.value(148), 1)
    vm._write(149, value, 4, 'high.load')
    vm.pc = 932
    value = vm.memory.load(vm.cells.pointer(149), 4)
    vm._write(150, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 932, 151, 2, 1, (64,))
    vm.pc = 943
    value = vm.memory.load(vm.cells.value(151), 1)
    vm._write(152, value, 4, 'high.load')
    vm.pc = 948
    value = vm.memory.load(vm.cells.pointer(152), 4)
    vm._write(153, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 949
    vm.pc = 952
    vm.auxiliary = (0, 1125292035)
    vm.pc = 953
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = 957
    value = int(vm._signed_cell(150, 0) == vm._signed_cell(153, 0))
    vm._write(154, value, 4, 'L26.comparison')
    vm.pc = 961
    vm._jump(41 if vm.cells.value(154) != 0 else 22)


def _duplicate_unlock(vm):
    _native_call(vm, 961, 968, 34, 21, (0, 155))
    vm.pc = 970
    vm._jump(25)


def _empty_start(vm):
    vm.pc = 1003
    vm._jump(44)


def _success_result(vm):
    vm.pc = 2119
    if vm.predecessor == 84:
        value = vm.cells.value(26)
    elif vm.predecessor == 25:
        value = vm.cells.value(16)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(303, value, 8, 'L9.phi_q')
    vm.pc = 2121
    vm._jump(3)


def _empty_head(vm):
    vm.pc = 1010
    if vm.predecessor == 42:
        value = vm.cells.value(26)
    elif vm.predecessor == 45:
        value = vm.cells.value(160)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(159, value, 8, 'L9.phi_q')
    vm.pc = 1011
    vm.pc = 1014
    vm.auxiliary = (0, 1751264293)
    vm.pc = 1019
    a = vm._signed_cell(159, 0) & ((1 << 64) - 1)
    b = vm._signed_cell(80, 0) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(161, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1023
    vm._jump(46 if vm.cells.value(161) != 0 else 47)


def _empty_next(vm):
    vm.pc = 1074
    vm.pc = 1077
    vm.auxiliary = (0, 1425641473)
    vm.pc = 1082
    vm._write(160, vm._signed_cell(159, 0) + vm._signed_cell(16, 0), 8, 'once1.integer')
    vm.pc = 1084
    vm._jump(44)


def _inspect_empty(vm):
    _indexed_pointer(vm, 1025, 162, 25, 0, (26, 83))
    vm.pc = 1038
    vm.cells.copy_q_clear_owned(159, 163)
    _indexed_pointer(vm, 1038, 164, 8, 162, (24, 163))
    _indexed_pointer(vm, 1046, 165, 7, 164, (26, 87))
    vm.pc = 1058
    value = vm.memory.load(vm.cells.value(165), 1)
    vm._write(166, value, 4, 'high.load')
    vm.pc = 1059
    vm.pc = 1062
    vm.auxiliary = (0, 1306706388)
    vm.pc = 1067
    value = int(vm._signed_cell(166, 2) != vm._signed_cell(77, 2))
    vm._write(167, value, 4, 'L27.comparison')
    vm.pc = 1071
    vm._jump(45 if vm.cells.value(167) != 0 else 49)


def _empty_done(vm):
    vm.pc = 1025
    vm._jump(48)


def _empty_result(vm):
    vm.pc = 1091
    if vm.predecessor == 49:
        value = vm.cells.value(159)
    elif vm.predecessor == 47:
        value = vm.cells.value(169)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(168, value, 8, 'L9.phi_q')
    vm.pc = 1092
    vm.pc = 1095
    vm.auxiliary = (0, 1456612163)
    vm.pc = 1096
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = 1100
    value = int(vm._signed_cell(168, 0) == vm._signed_cell(169, 0))
    vm._write(170, value, 4, 'L26.comparison')
    vm.pc = 1104
    vm._jump(50 if vm.cells.value(170) != 0 else 51)


def _empty_found(vm):
    vm.pc = 1073
    vm._jump(48)


def _same_kind_start(vm):
    vm.pc = 1106
    vm._jump(52)


def _selected(vm):
    vm.pc = 1495
    if vm.predecessor == 57:
        value = vm.cells.value(218)
    elif vm.predecessor == 48:
        value = vm.cells.value(168)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(219, value, 8, 'L9.phi_q')
    _indexed_pointer(vm, 1495, 220, 25, 0, (26, 83))
    vm.pc = 1508
    vm.cells.copy_q_clear_owned(219, 221)
    _indexed_pointer(vm, 1508, 222, 8, 220, (24, 221))
    _indexed_pointer(vm, 1516, 223, 7, 222, (26, 87))
    vm.pc = 1528
    value = vm.memory.load(vm.cells.value(223), 1)
    vm._write(224, value, 4, 'high.load')
    vm.pc = 1529
    vm.pc = 1532
    vm.auxiliary = (0, 2003970868)
    vm.pc = 1537
    value = int(vm._signed_cell(224, 2) != vm._signed_cell(77, 2))
    vm._write(225, value, 4, 'L30.comparison')
    vm.pc = 1541
    vm._jump(69 if vm.cells.value(225) != 0 else 70)


def _same_kind_head(vm):
    vm.pc = 1113
    if vm.predecessor == 50:
        value = vm.cells.value(168)
    elif vm.predecessor == 53:
        value = vm.cells.value(172)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(171, value, 8, 'L9.phi_q')
    vm.pc = 1120
    if vm.predecessor == 50:
        value = vm.cells.value(169)
    elif vm.predecessor == 53:
        value = vm.cells.value(174)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(173, value, 8, 'L9.phi_q')
    vm.pc = 1127
    if vm.predecessor == 50:
        value = vm.cells.value(26)
    elif vm.predecessor == 53:
        value = vm.cells.value(176)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(175, value, 8, 'L9.phi_q')
    vm.pc = 1128
    vm.pc = 1131
    vm.auxiliary = (0, 745731269)
    vm.pc = 1136
    a = vm._signed_cell(175, 0) & ((1 << 64) - 1)
    b = vm._signed_cell(80, 0) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(177, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1140
    vm._jump(54 if vm.cells.value(177) != 0 else 55)


def _same_kind_next(vm):
    vm.pc = 1294
    if vm.predecessor == 61:
        value = vm.cells.value(195)
    elif vm.predecessor == 58:
        value = vm.cells.value(171)
    elif vm.predecessor == 54:
        value = vm.cells.value(171)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(172, value, 8, 'L9.phi_q')
    vm.pc = 1303
    if vm.predecessor == 61:
        value = vm.cells.value(196)
    elif vm.predecessor == 58:
        value = vm.cells.value(173)
    elif vm.predecessor == 54:
        value = vm.cells.value(173)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(174, value, 8, 'L9.phi_q')
    vm.pc = 1304
    vm.pc = 1307
    vm.auxiliary = (0, 971911169)
    vm.pc = 1312
    vm._write(176, vm._signed_cell(175, 0) + vm._signed_cell(16, 0), 8, 'once1.integer')
    vm.pc = 1314
    vm._jump(52)


def _same_kind_active(vm):
    _indexed_pointer(vm, 1153, 179, 25, 0, (26, 83))
    vm.pc = 1166
    vm.cells.copy_q_clear_owned(175, 180)
    _indexed_pointer(vm, 1166, 181, 8, 179, (24, 180))
    _indexed_pointer(vm, 1174, 182, 7, 181, (26, 87))
    vm.pc = 1186
    value = vm.memory.load(vm.cells.value(182), 1)
    vm._write(183, value, 4, 'high.load')
    vm.pc = 1187
    vm.pc = 1190
    vm.auxiliary = (0, 2009209844)
    vm.pc = 1195
    value = int(vm._signed_cell(183, 2) != vm._signed_cell(77, 2))
    vm._write(184, value, 4, 'L30.comparison')
    vm.pc = 1199
    vm._jump(58 if vm.cells.value(184) != 0 else 53)


def _same_kind_done(vm):
    vm.pc = 1141
    vm.pc = 1144
    vm.auxiliary = (0, 1341271619)
    vm.pc = 1149
    vm._write(178, int(vm._signed_cell(171, 0) == vm._signed_cell(169, 0)), 4, 'once17.integer')
    vm.pc = 1153
    vm._jump(56 if vm.cells.value(178) != 0 else 57)


def _oldest_start(vm):
    vm.pc = 1316
    vm._jump(62)


def _selection_done(vm):
    vm.pc = 1486
    if vm.predecessor == 65:
        value = vm.cells.value(197)
    elif vm.predecessor == 55:
        value = vm.cells.value(171)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(218, value, 8, 'L9.phi_q')
    vm.pc = 1488
    vm._jump(51)


def _same_kind_check(vm):
    _indexed_pointer(vm, 1199, 185, 7, 181, (26, 13))
    vm.pc = 1211
    value = vm.memory.load(vm.cells.value(185), 1)
    vm._write(186, value, 4, 'high.load')
    vm.pc = 1216
    value = vm.memory.load(vm.cells.pointer(186), 4)
    vm._write(187, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1217
    vm.pc = 1220
    vm.auxiliary = (0, 1891817507)
    vm.pc = 1225
    vm._write(188, int(vm._signed_cell(187, 0) == vm._signed_cell(3, 0)), 4, 'once17.integer')
    vm.pc = 1229
    vm._jump(59 if vm.cells.value(188) != 0 else 53)


def _same_kind_time(vm):
    _indexed_pointer(vm, 1229, 189, 7, 181, (26, 16))
    vm.pc = 1241
    value = vm.memory.load(vm.cells.value(189), 4)
    vm._write(190, value, 4, 'high.load')
    _indexed_pointer(vm, 1241, 191, 25, 0, (26, 26))
    vm.pc = 1253
    value = vm.memory.load(vm.cells.value(191), 4)
    vm._write(192, value, 4, 'high.load')
    vm.pc = 1258
    vm._write(193, vm._signed_cell(190, 0) ^ vm._signed_cell(192, 0), 8, 'L14.binary_q')
    vm.pc = 1263
    vm._write(194, int(vm.cells.value(193) < vm.cells.value(173)), 4, 'once18.unsigned_q')
    vm.pc = 1267
    vm._jump(60 if vm.cells.value(194) != 0 else 61)


def _same_kind_choose(vm):
    vm.pc = 1269
    vm._jump(61)


def _same_kind_result(vm):
    vm.pc = 1276
    if vm.predecessor == 60:
        value = vm.cells.value(175)
    elif vm.predecessor == 59:
        value = vm.cells.value(171)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(195, value, 8, 'L9.phi_q')
    vm.pc = 1283
    if vm.predecessor == 60:
        value = vm.cells.value(193)
    elif vm.predecessor == 59:
        value = vm.cells.value(173)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(196, value, 8, 'L9.phi_q')
    vm.pc = 1285
    vm._jump(53)


def _oldest_head(vm):
    vm.pc = 1323
    if vm.predecessor == 56:
        value = vm.cells.value(171)
    elif vm.predecessor == 63:
        value = vm.cells.value(198)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(197, value, 8, 'L9.phi_q')
    vm.pc = 1330
    if vm.predecessor == 56:
        value = vm.cells.value(169)
    elif vm.predecessor == 63:
        value = vm.cells.value(200)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(199, value, 8, 'L9.phi_q')
    vm.pc = 1337
    if vm.predecessor == 56:
        value = vm.cells.value(26)
    elif vm.predecessor == 63:
        value = vm.cells.value(202)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(201, value, 8, 'L9.phi_q')
    vm.pc = 1338
    vm.pc = 1341
    vm.auxiliary = (0, 1962043813)
    vm.pc = 1346
    a = vm._signed_cell(201, 0) & ((1 << 64) - 1)
    b = vm._signed_cell(80, 0) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(203, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1350
    vm._jump(64 if vm.cells.value(203) != 0 else 65)


def _oldest_next(vm):
    vm.pc = 1461
    if vm.predecessor == 68:
        value = vm.cells.value(216)
    elif vm.predecessor == 64:
        value = vm.cells.value(197)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(198, value, 8, 'L9.phi_q')
    vm.pc = 1468
    if vm.predecessor == 68:
        value = vm.cells.value(217)
    elif vm.predecessor == 64:
        value = vm.cells.value(199)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(200, value, 8, 'L9.phi_q')
    vm.pc = 1469
    vm.pc = 1472
    vm.auxiliary = (0, 1314877442)
    vm.pc = 1477
    vm._write(202, vm._signed_cell(201, 0) + vm._signed_cell(16, 0), 8, 'once1.integer')
    vm.pc = 1479
    vm._jump(62)


def _oldest_active(vm):
    _indexed_pointer(vm, 1352, 204, 25, 0, (26, 83))
    vm.pc = 1365
    vm.cells.copy_q_clear_owned(201, 205)
    _indexed_pointer(vm, 1365, 206, 8, 204, (24, 205))
    _indexed_pointer(vm, 1373, 207, 7, 206, (26, 87))
    vm.pc = 1385
    value = vm.memory.load(vm.cells.value(207), 1)
    vm._write(208, value, 4, 'high.load')
    vm.pc = 1386
    vm.pc = 1389
    vm.auxiliary = (0, 1203937700)
    vm.pc = 1394
    value = int(vm._signed_cell(208, 2) != vm._signed_cell(77, 2))
    vm._write(209, value, 4, 'L27.comparison')
    vm.pc = 1398
    vm._jump(66 if vm.cells.value(209) != 0 else 63)


def _oldest_done(vm):
    vm.pc = 1352
    vm._jump(57)


def _oldest_time(vm):
    _indexed_pointer(vm, 1398, 210, 7, 206, (26, 16))
    vm.pc = 1410
    value = vm.memory.load(vm.cells.value(210), 4)
    vm._write(211, value, 4, 'high.load')
    _indexed_pointer(vm, 1410, 212, 25, 0, (26, 26))
    vm.pc = 1422
    value = vm.memory.load(vm.cells.value(212), 4)
    vm._write(213, value, 4, 'high.load')
    vm.pc = 1427
    vm._write(214, vm._signed_cell(211, 0) ^ vm._signed_cell(213, 0), 8, 'L14.binary_q')
    vm.pc = 1432
    vm._write(215, int(vm.cells.value(214) < vm.cells.value(199)), 4, 'once18.unsigned_q')
    vm.pc = 1436
    vm._jump(67 if vm.cells.value(215) != 0 else 68)


def _oldest_choose(vm):
    vm.pc = 1438
    vm._jump(68)


def _oldest_result(vm):
    vm.pc = 1445
    if vm.predecessor == 67:
        value = vm.cells.value(201)
    elif vm.predecessor == 66:
        value = vm.cells.value(197)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(216, value, 8, 'L9.phi_q')
    vm.pc = 1452
    if vm.predecessor == 67:
        value = vm.cells.value(214)
    elif vm.predecessor == 66:
        value = vm.cells.value(199)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(217, value, 8, 'L9.phi_q')
    vm.pc = 1454
    vm._jump(63)


def _decrement(vm):
    _indexed_pointer(vm, 1541, 226, 25, 0, (26, 227))
    vm.pc = 1553
    value = vm.memory.load(vm.cells.value(226), 4)
    vm._write(228, value, 4, 'high.load')
    _indexed_pointer(vm, 1553, 229, 25, 0, (26, 26))
    vm.pc = 1565
    value = vm.memory.load(vm.cells.value(229), 4)
    vm._write(230, value, 4, 'high.load')
    vm.pc = 1566
    vm.pc = 1569
    vm.auxiliary = (0, 48495)
    vm.pc = 1575
    vm._write(231, vm._signed_cell(228, 0) ^ vm._signed_cell(230, 0), 8, 'high.flag1_xor_q')
    vm.pc = 1580
    value = int(vm.cells.value(231) > vm.cells.value(26))
    vm._write(232, value, 4, 'L31.comparison')
    vm.pc = 1584
    vm._jump(71 if vm.cells.value(232) != 0 else 72)


def _clear_selected(vm):
    vm.pc = 1627
    vm.cells.copy_q_clear_owned(222, 237)
    vm.pc = 1631
    vm._jump(73 if vm.cells.value(11) != 0 else 74)


def _count_positive(vm):
    vm.pc = 1585
    vm.pc = 1588
    vm.auxiliary = (0, 1560342529)
    vm.pc = 1593
    vm._write(233, vm._signed_cell(231, 0) + vm._signed_cell(169, 0), 8, 'once1.integer')
    vm.pc = 1595
    vm._jump(72)


def _count_result(vm):
    vm.pc = 1602
    if vm.predecessor == 71:
        value = vm.cells.value(233)
    elif vm.predecessor == 69:
        value = vm.cells.value(231)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(234, value, 8, 'L9.phi_q')
    vm.pc = 1606
    value = vm.memory.load(vm.cells.value(229), 4)
    vm._write(235, value, 4, 'high.load')
    vm.pc = 1607
    vm.pc = 1610
    vm.auxiliary = (0, 39765)
    vm.pc = 1616
    vm._write(236, vm._signed_cell(234, 0) ^ vm._signed_cell(235, 0), 8, 'high.flag1_xor_q')
    vm.pc = 1620
    _store_cell(vm, 1616, 4, 236, 226)
    vm.pc = 1622
    vm._jump(70)


def _zero_start(vm):
    vm.pc = 1633
    vm._jump(75)


def _input_start(vm):
    _indexed_pointer(vm, 1680, 244, 7, 222, (26, 26))
    _indexed_pointer(vm, 1688, 245, 6, 244, (24, 24))
    vm.pc = 1701
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    value = vm.cells.value(2)
    vm._write(246, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1705
    vm._jump(78 if vm.cells.value(9) != 0 else 79)


def _zero_head(vm):
    vm.pc = 1640
    if vm.predecessor == 73:
        value = vm.cells.value(239)
    elif vm.predecessor == 76:
        value = vm.cells.value(240)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(238, value, 8, 'L9.phi_q')
    vm.pc = 1647
    if vm.predecessor == 73:
        value = vm.cells.value(237)
    elif vm.predecessor == 76:
        value = vm.cells.value(242)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(241, value, 8, 'L9.phi_q')
    vm.pc = 1648
    vm.pc = 1651
    vm.auxiliary = (0, 1259286529)
    vm.pc = 1656
    vm._write(240, vm._signed_cell(238, 15) + vm._signed_cell(35, 15), 8, 'once1.integer')
    vm.pc = 1661
    value = int(vm.cells.value(238) > vm.cells.value(24))
    vm._write(243, value, 4, 'L31.comparison')
    vm.pc = 1665
    vm._jump(76 if vm.cells.value(243) != 0 else 77)


def _zero_byte(vm):
    _indexed_pointer(vm, 1665, 242, 2, 241, (16,))
    vm.pc = 1676
    _store_cell(vm, 1672, 1, 77, 241)
    vm.pc = 1678
    vm._jump(75)


def _zero_done(vm):
    vm.pc = 1680
    vm._jump(74)


def _input_copy_start(vm):
    vm.pc = 1707
    vm._jump(80)


def _encode_start(vm):
    _indexed_pointer(vm, 1772, 255, 25, 0, (26, 26))
    vm.pc = 1784
    value = vm.memory.load(vm.cells.value(255), 4)
    vm._write(256, value, 4, 'high.load')
    vm.pc = 1789
    vm._write(257, vm._signed_cell(256, 0) ^ vm._signed_cell(219, 0), 8, 'L14.binary_q')
    vm.pc = 1790
    vm.pc = 1793
    vm.auxiliary = (0, 47735)
    vm.pc = 1799
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    vm._write(258, vm._signed_cell(257, 0) ^ vm._signed_cell(3, 0), 8, 'typed.selector5.q')
    vm.pc = 1804
    vm._write(259, vm.cells.value(258) & 255, 8, 'once9.mask_q')
    vm.pc = 1809
    value = vm.memory.load(vm.cells.pointer(259), 4)
    vm._write(260, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1814
    vm._write(261, vm._signed_cell(260, 0) & vm._signed_cell(80, 0), 8, 'L13.binary_q')
    vm.pc = 1819
    vm._write(262, vm.cells.value(261) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 1819, 263, 7, 222, (26, 18))
    vm.pc = 1831
    _store_cell(vm, 1827, 1, 262, 263)
    vm.pc = 1835
    vm._jump(83 if vm.cells.value(11) != 0 else 84)


def _input_head(vm):
    vm.pc = 1714
    if vm.predecessor == 78:
        value = vm.cells.value(246)
    elif vm.predecessor == 81:
        value = vm.cells.value(248)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(247, value, 8, 'L9.phi_q')
    vm.pc = 1721
    if vm.predecessor == 78:
        value = vm.cells.value(245)
    elif vm.predecessor == 81:
        value = vm.cells.value(250)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(249, value, 8, 'L9.phi_q')
    vm.pc = 1728
    if vm.predecessor == 78:
        value = vm.cells.value(1)
    elif vm.predecessor == 81:
        value = vm.cells.value(252)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(251, value, 8, 'L9.phi_q')
    vm.pc = 1729
    vm.pc = 1732
    vm.auxiliary = (0, 1520234497)
    vm.pc = 1737
    vm._write(248, vm._signed_cell(247, 15) + vm._signed_cell(35, 15), 8, 'once1.integer')
    vm.pc = 1742
    value = int(vm.cells.value(247) > vm.cells.value(24))
    vm._write(253, value, 4, 'L31.comparison')
    vm.pc = 1746
    vm._jump(81 if vm.cells.value(253) != 0 else 82)


def _input_byte(vm):
    _indexed_pointer(vm, 1746, 252, 2, 251, (16,))
    vm.pc = 1757
    value = vm.memory.load(vm.cells.value(251), 1)
    vm._write(254, value, 4, 'high.load')
    _indexed_pointer(vm, 1757, 250, 2, 249, (16,))
    vm.pc = 1768
    _store_cell(vm, 1764, 1, 254, 249)
    vm.pc = 1770
    vm._jump(80)


def _input_done(vm):
    vm.pc = 1772
    vm._jump(79)


def _encode_seed_start(vm):
    vm.pc = 1839
    vm._jump(85 if vm.cells.value(11) != 0 else 84)


def _publish(vm):
    _native_call(vm, 1990, 1997, 46, 286, (287,), 285)
    vm.pc = 2002
    vm._write(288, vm.cells.value(285) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 2006
    value = vm.memory.load(vm.cells.value(255), 4)
    vm._write(289, value, 4, 'high.load')
    vm.pc = 2007
    vm.pc = 2010
    vm.auxiliary = (0, 65053)
    vm.pc = 2016
    vm._write(290, vm._signed_cell(288, 0) ^ vm._signed_cell(289, 0), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 2016, 291, 7, 222, (26, 16))
    vm.pc = 2028
    _store_cell(vm, 2024, 4, 290, 291)
    vm.pc = 2033
    vm._write(292, vm.cells.value(3) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 2033, 293, 7, 222, (26, 13))
    vm.pc = 2045
    _store_cell(vm, 2041, 1, 292, 293)
    vm.pc = 2049
    _store_cell(vm, 2045, 1, 294, 223)
    _indexed_pointer(vm, 2049, 295, 7, 222, (26, 296))
    vm.pc = 2061
    _store_cell(vm, 2057, 1, 77, 295)
    _indexed_pointer(vm, 2061, 297, 25, 0, (26, 227))
    vm.pc = 2073
    value = vm.memory.load(vm.cells.value(297), 4)
    vm._write(298, value, 4, 'high.load')
    vm.pc = 2077
    value = vm.memory.load(vm.cells.value(255), 4)
    vm._write(299, value, 4, 'high.load')
    vm.pc = 2080
    vm.auxiliary = (0, 52046)
    vm.pc = 2086
    vm._write(300, vm._signed_cell(298, 0) ^ vm._signed_cell(299, 0), 8, 'high.flag1_xor_q')
    vm.pc = 2089
    vm.auxiliary = (0, 207425537)
    vm.pc = 2094
    vm._write(301, vm._signed_cell(300, 0) + vm._signed_cell(16, 0), 8, 'once1.integer')
    vm.pc = 2099
    vm._write(302, vm._signed_cell(301, 0) ^ vm._signed_cell(299, 0), 8, 'L14.binary_q')
    vm.pc = 2103
    _store_cell(vm, 2099, 4, 302, 297)
    _native_call(vm, 2103, 2110, 34, 21, (0, 155))
    vm.pc = 2112
    vm._jump(43)


def _encode_seed(vm):
    vm.pc = 1844
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    value = vm.cells.value(262)
    vm._write(264, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 1844, 265, 5, 38, (24, 264))
    vm.pc = 1856
    value = vm.memory.load(vm.cells.value(265), 1)
    vm._write(266, value, 4, 'high.load')
    vm.pc = 1858
    vm._jump(86)


def _encode_head(vm):
    vm.pc = 1865
    if vm.predecessor == 85:
        value = vm.cells.value(24)
    elif vm.predecessor == 87:
        value = vm.cells.value(268)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(267, value, 8, 'L9.phi_q')
    vm.pc = 1872
    if vm.predecessor == 85:
        value = vm.cells.value(266)
    elif vm.predecessor == 87:
        value = vm.cells.value(270)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(269, value, 8, 'L9.phi_q')
    vm.pc = 1877
    vm._write(271, int(vm.cells.value(267) < vm.cells.value(101)), 4, 'once18.unsigned_q')
    vm.pc = 1881
    vm._jump(87 if vm.cells.value(271) != 0 else 88)


def _encode_byte(vm):
    vm.pc = 1886
    value = vm.memory.load(vm.cells.pointer(269), 4)
    vm._write(272, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1887
    vm.pc = 1890
    vm.auxiliary = (0, 1161056771)
    vm.pc = 1895
    vm._write(273, vm._signed_cell(267, 15) * vm._signed_cell(48, 15), 8, 'once0.integer')
    vm.pc = 1898
    vm.auxiliary = (0, 1567567873)
    vm.pc = 1903
    vm._write(274, vm._signed_cell(273, 15) + vm._signed_cell(264, 15), 8, 'once1.integer')
    vm.pc = 1908
    vm._write(275, vm.cells.value(274) & 255, 8, 'once9.mask_q')
    vm.pc = 1913
    value = vm.memory.load(vm.cells.pointer(275), 4)
    vm._write(276, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1916
    vm.auxiliary = (0, 27159)
    vm.pc = 1922
    vm._write(277, vm._signed_cell(272, 0) ^ vm._signed_cell(276, 0), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 1922, 278, 6, 244, (24, 267))
    vm.pc = 1934
    value = vm.memory.load(vm.cells.value(278), 1)
    vm._write(279, value, 4, 'high.load')
    vm.pc = 1939
    value = vm.memory.load(vm.cells.pointer(279), 4)
    vm._write(280, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 1942
    vm.auxiliary = (0, 38989)
    vm.pc = 1948
    vm._write(281, vm._signed_cell(280, 0) ^ vm._signed_cell(277, 0), 8, 'high.flag1_xor_q')
    vm.pc = 1953
    vm._write(282, vm.cells.value(281) & 255, 8, 'once9.mask_q')
    vm.pc = 1957
    _store_cell(vm, 1953, 1, 282, 278)
    vm.pc = 1960
    vm.auxiliary = (0, 1321894403)
    vm.pc = 1965
    vm._write(283, vm._signed_cell(272, 0) * vm._signed_cell(58, 0), 8, 'once0.integer')
    vm.pc = 1968
    vm.auxiliary = (0, 1057017857)
    vm.pc = 1973
    vm._write(284, vm._signed_cell(283, 0) + vm._signed_cell(60, 0), 8, 'once1.integer')
    vm.pc = 1978
    vm._write(270, vm.cells.value(284) & 255, 8, 'once9.mask_q')
    vm.pc = 1981
    vm.auxiliary = (0, 617545729)
    vm.pc = 1986
    vm._write(268, vm._signed_cell(267, 15) + vm._signed_cell(62, 15), 8, 'once1.integer')
    vm.pc = 1988
    vm._jump(86)


def _encode_done(vm):
    vm.pc = 1990
    vm._jump(84)


def _prepare_material(vm):
    _lock_material(vm)
    if vm.block == 6:
        _copy_start(vm)
        while True:
            _copy_head(vm)
            if vm.block == 10:
                break
            _copy_byte(vm)
        _copy_done(vm)
    _salt_address(vm)
    if vm.block == 11:
        _salt_seed(vm)
        while True:
            _material_head(vm)
            if vm.block == 15:
                break
            _material_byte(vm)
        _material_done(vm)
    _expire(vm)
    if vm.block == 16:
        _clear_start(vm)
        while True:
            _clear_head(vm)
            if vm.block == 20:
                break
            _clear_byte(vm)
        _clear_done(vm)
    _duplicate_start(vm)


def _decode_candidate(vm):
    _token_address(vm)
    if vm.block == 28:
        _token_copy_start(vm)
        while True:
            _token_copy_head(vm)
            if vm.block == 32:
                break
            _token_copy_byte(vm)
        _token_copy_done(vm)
    _decode_start(vm)
    if vm.block == 33:
        _decode_seed(vm)
        while True:
            _decode_head(vm)
            if vm.block == 37:
                break
            _decode_byte(vm)
        _decode_done(vm)
    _compare_first(vm)
    if vm.block == 38:
        _compare_second(vm)
    if vm.block == 39:
        _compare_third(vm)
    if vm.block == 40:
        _compare_fourth(vm)


def _find_slot(vm):
    _empty_start(vm)
    while True:
        _empty_head(vm)
        if vm.block == 47:
            _empty_done(vm)
            break
        _inspect_empty(vm)
        if vm.block == 49:
            _empty_found(vm)
            break
        _empty_next(vm)
    _empty_result(vm)
    if vm.block != 50:
        return
    _same_kind_start(vm)
    while True:
        _same_kind_head(vm)
        if vm.block == 55:
            break
        _same_kind_active(vm)
        if vm.block == 58:
            _same_kind_check(vm)
            if vm.block == 59:
                _same_kind_time(vm)
                if vm.block == 60:
                    _same_kind_choose(vm)
                _same_kind_result(vm)
        _same_kind_next(vm)
    _same_kind_done(vm)
    if vm.block == 56:
        _oldest_start(vm)
        while True:
            _oldest_head(vm)
            if vm.block == 65:
                break
            _oldest_active(vm)
            if vm.block == 66:
                _oldest_time(vm)
                if vm.block == 67:
                    _oldest_choose(vm)
                _oldest_result(vm)
            _oldest_next(vm)
        _oldest_done(vm)
    _selection_done(vm)


def _write_token(vm):
    _selected(vm)
    if vm.block == 69:
        _decrement(vm)
        if vm.block == 71:
            _count_positive(vm)
        _count_result(vm)
    _clear_selected(vm)
    if vm.block == 73:
        _zero_start(vm)
        while True:
            _zero_head(vm)
            if vm.block == 77:
                break
            _zero_byte(vm)
        _zero_done(vm)
    _input_start(vm)
    if vm.block == 78:
        _input_copy_start(vm)
        while True:
            _input_head(vm)
            if vm.block == 82:
                break
            _input_byte(vm)
        _input_done(vm)
    _encode_start(vm)
    if vm.block == 83:
        _encode_seed_start(vm)
        if vm.block == 85:
            _encode_seed(vm)
            while True:
                _encode_head(vm)
                if vm.block == 88:
                    break
                _encode_byte(vm)
            _encode_done(vm)
    _publish(vm)


def run_primary_token_setter(vm):
    state = getattr(vm, 'primary_token_setter_state', None)
    if state is None or state.get('phase') == 'complete':
        state = {'execution': 'source', 'phase': 'running', 'retained_steps': 0}
        vm.primary_token_setter_state = state
    initial_steps = len(vm.trace)
    try:
        result = vm.run(max_steps=1_000_000)
    finally:
        state['retained_steps'] += len(vm.trace) - initial_steps
    state['phase'] = 'complete'
    return result
