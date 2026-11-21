from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell
from .primary_vm import PrimarySemanticUnavailable


def _initialize(vm):
    vm.pc = 4
    vm._allocate(31, 2)
    vm.pc = 7
    vm._allocate(31, 3)
    vm.pc = 10
    vm._allocate(31, 4)
    vm.pc = 13
    vm._allocate(33, 5)
    _native_call(vm, 13, 20, 36, 7, (8,), 6)
    vm.pc = 25
    vm._write(9, vm.cells.value(6) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 30
    vm.cells.copy_q_clear_owned(2, 10)
    _native_call(vm, 30, 39, 38, 12, (10, 13, 14), 11)
    vm.pc = 41
    vm._jump(1)


def _collect_head(vm):
    vm.pc = 48
    if vm.predecessor == 0:
        value = vm.cells.value(13)
    elif vm.predecessor == 2:
        value = vm.cells.value(16)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(15, value, 8, 'L9.phi_q')
    vm.pc = 55
    if vm.predecessor == 0:
        value = vm.cells.value(13)
    elif vm.predecessor == 2:
        value = vm.cells.value(18)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(17, value, 8, 'L9.phi_q')
    vm.pc = 56
    vm.pc = 59
    vm.auxiliary = (0, 378729893)
    vm.pc = 64
    a = vm._signed_cell(15, 1) & ((1 << 64) - 1)
    b = vm._signed_cell(19, 1) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(20, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 68
    vm._jump(3 if vm.cells.value(20) != 0 else 4)


def _collect_next(vm):
    vm.pc = 239
    if vm.predecessor == 7:
        value = vm.cells.value(47)
    elif vm.predecessor == 3:
        value = vm.cells.value(17)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(18, value, 8, 'L9.phi_q')
    vm.pc = 240
    vm.pc = 243
    vm.auxiliary = (0, 1978257410)
    vm.pc = 248
    vm._write(16, vm._signed_cell(15, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 250
    vm._jump(1)


def _inspect_slot(vm):
    _indexed_pointer(vm, 81, 22, 26, 0, (13, 23))
    vm.pc = 94
    vm.cells.copy_q_clear_owned(15, 24)
    _indexed_pointer(vm, 94, 25, 9, 22, (26, 24))
    _indexed_pointer(vm, 102, 27, 8, 25, (13, 28))
    vm.pc = 114
    value = vm.memory.load(vm.cells.value(27), 1)
    vm._write(29, value, 4, 'high.load')
    vm.pc = 115
    vm.pc = 118
    vm.auxiliary = (0, 1544733668)
    vm.pc = 123
    value = int(vm._signed_cell(29, 3) != vm._signed_cell(30, 3))
    vm._write(31, value, 4, 'L27.comparison')
    vm.pc = 127
    vm._jump(7 if vm.cells.value(31) != 0 else 2)


def _collected(vm):
    vm.pc = 69
    vm.pc = 72
    vm.auxiliary = (0, 598898787)
    vm.pc = 77
    vm._write(21, int(vm._signed_cell(17, 1) == vm._signed_cell(13, 1)), 4, 'once17.integer')
    vm.pc = 81
    vm._jump(5 if vm.cells.value(21) != 0 else 6)


def _empty(vm):
    vm.pc = 252
    vm._jump(8)


def _sort(vm):
    vm.pc = 257
    vm.cells.copy_q_clear_owned(17, 48)
    _indexed_pointer(vm, 257, 49, 31, 2, (26, 26))
    vm.pc = 270
    vm.cells.copy_q_clear_owned(49, 50)
    _native_call(vm, 270, 279, 47, 51, (50, 48, 52, 53))
    vm.pc = 284
    vm.cells.copy_q_clear_owned(3, 54)
    _native_call(vm, 284, 293, 38, 12, (54, 13, 14), 55)
    vm.pc = 298
    vm.cells.copy_q_clear_owned(4, 56)
    _native_call(vm, 298, 307, 38, 12, (56, 13, 14), 57)
    vm.pc = 309
    vm._jump(9)


def _collect_active(vm):
    vm.pc = 132
    vm.cells.copy_q_clear_owned(17, 32)
    _indexed_pointer(vm, 132, 33, 31, 2, (26, 32))
    _indexed_pointer(vm, 140, 34, 30, 33, (13, 13))
    vm.pc = 152
    _store_cell(vm, 148, 4, 15, 34)
    _indexed_pointer(vm, 152, 35, 8, 25, (13, 36))
    vm.pc = 164
    value = vm.memory.load(vm.cells.value(35), 4)
    vm._write(37, value, 4, 'high.load')
    _indexed_pointer(vm, 164, 38, 26, 0, (13, 13))
    vm.pc = 176
    value = vm.memory.load(vm.cells.value(38), 4)
    vm._write(39, value, 4, 'high.load')
    vm.pc = 177
    vm.pc = 180
    vm.auxiliary = (0, 22613)
    vm.pc = 186
    vm._write(40, vm._signed_cell(37, 1) ^ vm._signed_cell(39, 1), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 186, 41, 30, 33, (13, 36))
    vm.pc = 198
    _store_cell(vm, 194, 4, 40, 41)
    _indexed_pointer(vm, 198, 42, 8, 25, (13, 43))
    vm.pc = 210
    value = vm.memory.load(vm.cells.value(42), 1)
    vm._write(44, value, 4, 'high.load')
    _indexed_pointer(vm, 210, 45, 30, 33, (13, 46))
    vm.pc = 222
    _store_cell(vm, 218, 1, 44, 45)
    vm.pc = 225
    vm.auxiliary = (0, 1416896514)
    vm.pc = 230
    vm._write(47, vm._signed_cell(17, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 232
    vm._jump(2)


def _finish(vm):
    vm.pc = 1166
    vm.halted = True


def _group_head(vm):
    vm.pc = 316
    if vm.predecessor == 6:
        value = vm.cells.value(13)
    elif vm.predecessor == 10:
        value = vm.cells.value(59)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(58, value, 8, 'L9.phi_q')
    vm.pc = 323
    if vm.predecessor == 6:
        value = vm.cells.value(13)
    elif vm.predecessor == 10:
        value = vm.cells.value(61)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(60, value, 8, 'L9.phi_q')
    vm.pc = 330
    if vm.predecessor == 6:
        value = vm.cells.value(13)
    elif vm.predecessor == 10:
        value = vm.cells.value(63)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(62, value, 8, 'L9.phi_q')
    vm.pc = 331
    vm.pc = 334
    vm.auxiliary = (0, 1235402341)
    vm.pc = 339
    a = vm._signed_cell(58, 1) & ((1 << 64) - 1)
    b = vm._signed_cell(17, 1) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(64, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 343
    vm._jump(11 if vm.cells.value(64) != 0 else 12)


def _group_next(vm):
    vm.pc = 495
    if vm.predecessor == 14:
        value = vm.cells.value(60)
    elif vm.predecessor == 15:
        value = vm.cells.value(81)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(61, value, 8, 'L9.phi_q')
    vm.pc = 502
    if vm.predecessor == 14:
        value = vm.cells.value(74)
    elif vm.predecessor == 15:
        value = vm.cells.value(62)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(63, value, 8, 'L9.phi_q')
    vm.pc = 503
    vm.pc = 506
    vm.auxiliary = (0, 1266737153)
    vm.pc = 511
    vm._write(59, vm._signed_cell(58, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 513
    vm._jump(9)


def _inspect_kind(vm):
    vm.pc = 364
    vm.cells.copy_q_clear_owned(58, 68)
    _indexed_pointer(vm, 364, 69, 31, 2, (26, 68))
    _indexed_pointer(vm, 372, 70, 30, 69, (13, 46))
    vm.pc = 384
    value = vm.memory.load(vm.cells.value(70), 1)
    vm._write(71, value, 4, 'high.load')
    vm.pc = 389
    value = vm.memory.load(vm.cells.pointer(71), 4)
    vm._write(72, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 390
    vm.pc = 393
    vm.auxiliary = (0, 1137837683)
    vm.pc = 398
    vm._write(73, int(vm._signed_cell(72, 1) == vm._signed_cell(36, 1)), 4, 'once17.integer')
    vm.pc = 402
    vm._jump(14 if vm.cells.value(73) != 0 else 15)


def _prepare_deletions(vm):
    vm.pc = 348
    vm.cells.copy_q_clear_owned(5, 65)
    _native_call(vm, 348, 357, 38, 12, (65, 13, 67), 66)
    vm.pc = 359
    vm._jump(13)


def _first_head(vm):
    vm.pc = 520
    if vm.predecessor == 12:
        value = vm.cells.value(13)
    elif vm.predecessor == 16:
        value = vm.cells.value(88)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(87, value, 8, 'L9.phi_q')
    vm.pc = 527
    if vm.predecessor == 12:
        value = vm.cells.value(13)
    elif vm.predecessor == 16:
        value = vm.cells.value(90)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(89, value, 8, 'L9.phi_q')
    vm.pc = 534
    if vm.predecessor == 12:
        value = vm.cells.value(13)
    elif vm.predecessor == 16:
        value = vm.cells.value(92)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(91, value, 8, 'L9.phi_q')
    vm.pc = 541
    if vm.predecessor == 12:
        value = vm.cells.value(13)
    elif vm.predecessor == 16:
        value = vm.cells.value(94)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(93, value, 8, 'L9.phi_q')
    vm.pc = 542
    vm.pc = 545
    vm.auxiliary = (0, 1207066133)
    vm.pc = 550
    a = vm._signed_cell(93, 1) & ((1 << 64) - 1)
    b = vm._signed_cell(62, 1) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(95, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 554
    vm._jump(17 if vm.cells.value(95) != 0 else 18)


def _group_first(vm):
    vm.pc = 403
    vm.pc = 406
    vm.auxiliary = (0, 1968824321)
    vm.pc = 411
    vm._write(74, vm._signed_cell(62, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 416
    vm.cells.copy_q_clear_owned(62, 75)
    _indexed_pointer(vm, 416, 76, 31, 3, (26, 75))
    vm.pc = 429
    vm.cells.copy_q_clear_owned(76, 77)
    vm.pc = 434
    vm.cells.copy_q_clear_owned(69, 78)
    _native_call(vm, 434, 443, 49, 80, (77, 78, 52), 79)
    vm.pc = 445
    vm._jump(10)


def _group_other(vm):
    vm.pc = 446
    vm.pc = 449
    vm.auxiliary = (0, 1912954881)
    vm.pc = 454
    vm._write(81, vm._signed_cell(60, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 459
    vm.cells.copy_q_clear_owned(60, 82)
    _indexed_pointer(vm, 459, 83, 31, 4, (26, 82))
    vm.pc = 472
    vm.cells.copy_q_clear_owned(83, 84)
    vm.pc = 477
    vm.cells.copy_q_clear_owned(69, 85)
    _native_call(vm, 477, 486, 49, 80, (84, 85, 52), 86)
    vm.pc = 488
    vm._jump(10)


def _first_next(vm):
    vm.pc = 700
    if vm.predecessor == 22:
        value = vm.cells.value(87)
    elif vm.predecessor == 23:
        value = vm.cells.value(110)
    elif vm.predecessor == 21:
        value = vm.cells.value(87)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(88, value, 8, 'L9.phi_q')
    vm.pc = 709
    if vm.predecessor == 22:
        value = vm.cells.value(109)
    elif vm.predecessor == 23:
        value = vm.cells.value(89)
    elif vm.predecessor == 21:
        value = vm.cells.value(104)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(90, value, 8, 'L9.phi_q')
    vm.pc = 718
    if vm.predecessor == 22:
        value = vm.cells.value(108)
    elif vm.predecessor == 23:
        value = vm.cells.value(91)
    elif vm.predecessor == 21:
        value = vm.cells.value(105)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(92, value, 8, 'L9.phi_q')
    vm.pc = 719
    vm.pc = 722
    vm.auxiliary = (0, 1071104002)
    vm.pc = 727
    vm._write(94, vm._signed_cell(93, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 729
    vm._jump(13)


def _first_age(vm):
    vm.pc = 561
    vm.cells.copy_q_clear_owned(93, 96)
    _indexed_pointer(vm, 561, 97, 31, 3, (26, 96))
    _indexed_pointer(vm, 569, 98, 30, 97, (13, 36))
    vm.pc = 581
    value = vm.memory.load(vm.cells.value(98), 4)
    vm._write(99, value, 4, 'high.load')
    vm.pc = 582
    vm.pc = 585
    vm.auxiliary = (0, 46913)
    vm.pc = 590
    vm._write(100, vm._signed_cell(9, 1) - vm._signed_cell(99, 1), 8, 'typed.selector0.q')
    vm.pc = 595
    vm._write(102, int(vm.cells.value(100) >= vm.cells.value(101)), 4, 'once20.unsigned_q')
    vm.pc = 600
    value = vm.memory.load(vm.cells.pointer(102), 1)
    vm._write(103, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 604
    vm._jump(20 if vm.cells.value(102) != 0 else 21)


def _first_done(vm):
    vm.pc = 556
    vm._jump(19)


def _other_head(vm):
    vm.pc = 736
    if vm.predecessor == 18:
        value = vm.cells.value(87)
    elif vm.predecessor == 24:
        value = vm.cells.value(114)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(113, value, 8, 'L9.phi_q')
    vm.pc = 743
    if vm.predecessor == 18:
        value = vm.cells.value(89)
    elif vm.predecessor == 24:
        value = vm.cells.value(116)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(115, value, 8, 'L9.phi_q')
    vm.pc = 750
    if vm.predecessor == 18:
        value = vm.cells.value(13)
    elif vm.predecessor == 24:
        value = vm.cells.value(118)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(117, value, 8, 'L9.phi_q')
    vm.pc = 757
    if vm.predecessor == 18:
        value = vm.cells.value(13)
    elif vm.predecessor == 24:
        value = vm.cells.value(120)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(119, value, 8, 'L9.phi_q')
    vm.pc = 758
    vm.pc = 761
    vm.auxiliary = (0, 1192387205)
    vm.pc = 766
    a = vm._signed_cell(119, 1) & ((1 << 64) - 1)
    b = vm._signed_cell(60, 1) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(121, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 770
    vm._jump(25 if vm.cells.value(121) != 0 else 26)


def _first_old(vm):
    vm.pc = 624
    vm.pc = 627
    vm.auxiliary = (0, 941773125)
    vm.pc = 632
    a = vm._signed_cell(91, 1) & ((1 << 64) - 1)
    b = vm._signed_cell(46, 1) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(106, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 635
    vm.auxiliary = (0, 4877)
    vm.pc = 640
    vm._write(107, vm._signed_cell(102, 40) & vm._signed_cell(106, 40), 8, 'typed.selector1.q')
    vm.pc = 644
    vm._jump(22 if vm.cells.value(107) != 0 else 23)


def _first_young(vm):
    vm.pc = 605
    vm.pc = 608
    vm.auxiliary = (0, 1513803778)
    vm.pc = 613
    vm._write(104, vm._signed_cell(89, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 616
    vm.auxiliary = (0, 814030849)
    vm.pc = 621
    vm._write(105, vm._signed_cell(91, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 623
    vm._jump(16)


def _first_keep(vm):
    vm.pc = 645
    vm.pc = 648
    vm.auxiliary = (0, 966361089)
    vm.pc = 653
    vm._write(108, vm._signed_cell(91, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 656
    vm.auxiliary = (0, 1719865345)
    vm.pc = 661
    vm._write(109, vm._signed_cell(89, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 663
    vm._jump(16)


def _first_delete(vm):
    vm.pc = 664
    vm.pc = 667
    vm.auxiliary = (0, 205824002)
    vm.pc = 672
    vm._write(110, vm._signed_cell(87, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 677
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    value = vm.cells.value(87)
    vm._write(111, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 677, 112, 33, 5, (26, 111))
    vm.pc = 689
    _store_cell(vm, 685, 4, 99, 112)
    vm.pc = 691
    vm._jump(16)


def _other_next(vm):
    vm.pc = 916
    if vm.predecessor == 30:
        value = vm.cells.value(113)
    elif vm.predecessor == 31:
        value = vm.cells.value(135)
    elif vm.predecessor == 29:
        value = vm.cells.value(113)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(114, value, 8, 'L9.phi_q')
    vm.pc = 925
    if vm.predecessor == 30:
        value = vm.cells.value(134)
    elif vm.predecessor == 31:
        value = vm.cells.value(115)
    elif vm.predecessor == 29:
        value = vm.cells.value(129)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(116, value, 8, 'L9.phi_q')
    vm.pc = 934
    if vm.predecessor == 30:
        value = vm.cells.value(133)
    elif vm.predecessor == 31:
        value = vm.cells.value(117)
    elif vm.predecessor == 29:
        value = vm.cells.value(130)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(118, value, 8, 'L9.phi_q')
    vm.pc = 935
    vm.pc = 938
    vm.auxiliary = (0, 258674690)
    vm.pc = 943
    vm._write(120, vm._signed_cell(119, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 945
    vm._jump(19)


def _other_age(vm):
    vm.pc = 777
    vm.cells.copy_q_clear_owned(119, 122)
    _indexed_pointer(vm, 777, 123, 31, 4, (26, 122))
    _indexed_pointer(vm, 785, 124, 30, 123, (13, 36))
    vm.pc = 797
    value = vm.memory.load(vm.cells.value(124), 4)
    vm._write(125, value, 4, 'high.load')
    vm.pc = 798
    vm.pc = 801
    vm.auxiliary = (0, 38713)
    vm.pc = 806
    vm._write(126, vm._signed_cell(9, 1) - vm._signed_cell(125, 1), 8, 'typed.selector0.q')
    vm.pc = 811
    vm._write(127, int(vm.cells.value(126) >= vm.cells.value(101)), 4, 'once20.unsigned_q')
    vm.pc = 816
    value = vm.memory.load(vm.cells.pointer(127), 1)
    vm._write(128, value, 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 820
    vm._jump(28 if vm.cells.value(127) != 0 else 29)


def _other_done(vm):
    vm.pc = 772
    vm._jump(27)


def _delete_head(vm):
    vm.pc = 952
    if vm.predecessor == 26:
        value = vm.cells.value(13)
    elif vm.predecessor == 32:
        value = vm.cells.value(139)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(138, value, 8, 'L9.phi_q')
    vm.pc = 957
    vm._write(140, int(vm.cells.value(138) < vm.cells.value(113)), 4, 'once18.unsigned_q')
    vm.pc = 961
    vm._jump(33 if vm.cells.value(140) != 0 else 34)


def _other_old(vm):
    vm.pc = 840
    vm.pc = 843
    vm.auxiliary = (0, 1043510549)
    vm.pc = 848
    a = vm._signed_cell(117, 1) & ((1 << 64) - 1)
    b = vm._signed_cell(46, 1) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(131, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 851
    vm.auxiliary = (0, 57615)
    vm.pc = 856
    vm._write(132, vm._signed_cell(127, 40) & vm._signed_cell(131, 40), 8, 'typed.selector1.q')
    vm.pc = 860
    vm._jump(30 if vm.cells.value(132) != 0 else 31)


def _other_young(vm):
    vm.pc = 821
    vm.pc = 824
    vm.auxiliary = (0, 253890561)
    vm.pc = 829
    vm._write(129, vm._signed_cell(115, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 832
    vm.auxiliary = (0, 468566017)
    vm.pc = 837
    vm._write(130, vm._signed_cell(117, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 839
    vm._jump(24)


def _other_keep(vm):
    vm.pc = 861
    vm.pc = 864
    vm.auxiliary = (0, 253276161)
    vm.pc = 869
    vm._write(133, vm._signed_cell(117, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 872
    vm.auxiliary = (0, 1726906370)
    vm.pc = 877
    vm._write(134, vm._signed_cell(115, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 879
    vm._jump(24)


def _other_delete(vm):
    vm.pc = 880
    vm.pc = 883
    vm.auxiliary = (0, 1120776194)
    vm.pc = 888
    vm._write(135, vm._signed_cell(113, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 893
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    value = vm.cells.value(113)
    vm._write(136, value, 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 893, 137, 33, 5, (26, 136))
    vm.pc = 905
    _store_cell(vm, 901, 4, 125, 137)
    vm.pc = 907
    vm._jump(24)


def _delete_next(vm):
    vm.pc = 1155
    vm.pc = 1158
    vm.auxiliary = (0, 462692353)
    vm.pc = 1163
    vm._write(139, vm._signed_cell(138, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 1165
    vm._jump(27)


def _scan_start(vm):
    vm.pc = 999
    vm._jump(35)


def _publish_count(vm):
    _indexed_pointer(vm, 961, 141, 26, 0, (13, 13))
    vm.pc = 973
    value = vm.memory.load(vm.cells.value(141), 4)
    vm._write(142, value, 4, 'high.load')
    vm.pc = 974
    vm.pc = 977
    vm.auxiliary = (0, 56124)
    vm.pc = 983
    vm._write(143, vm._signed_cell(115, 1) ^ vm._signed_cell(142, 1), 8, 'high.flag1_xor_q')
    _indexed_pointer(vm, 983, 144, 26, 0, (13, 145))
    vm.pc = 995
    _store_cell(vm, 991, 4, 143, 144)
    vm.pc = 997
    vm._jump(8)


def _scan_head(vm):
    vm.pc = 1006
    if vm.predecessor == 33:
        value = vm.cells.value(13)
    elif vm.predecessor == 36:
        value = vm.cells.value(147)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(146, value, 8, 'L9.phi_q')
    vm.pc = 1007
    vm.pc = 1010
    vm.auxiliary = (0, 2059587621)
    vm.pc = 1015
    a = vm._signed_cell(146, 1) & ((1 << 64) - 1)
    b = vm._signed_cell(19, 1) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(148, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1019
    vm._jump(37 if vm.cells.value(148) != 0 else 38)


def _scan_next(vm):
    vm.pc = 1144
    vm.pc = 1147
    vm.auxiliary = (0, 1866928130)
    vm.pc = 1152
    vm._write(147, vm._signed_cell(146, 1) + vm._signed_cell(36, 1), 8, 'once1.integer')
    vm.pc = 1154
    vm._jump(35)


def _scan_slot(vm):
    _indexed_pointer(vm, 1021, 149, 26, 0, (13, 23))
    vm.pc = 1034
    vm.cells.copy_q_clear_owned(146, 150)
    _indexed_pointer(vm, 1034, 151, 9, 149, (26, 150))
    _indexed_pointer(vm, 1042, 152, 8, 151, (13, 36))
    vm.pc = 1054
    value = vm.memory.load(vm.cells.value(152), 4)
    vm._write(153, value, 4, 'high.load')
    _indexed_pointer(vm, 1054, 154, 26, 0, (13, 13))
    vm.pc = 1066
    value = vm.memory.load(vm.cells.value(154), 4)
    vm._write(155, value, 4, 'high.load')
    vm.pc = 1067
    vm.pc = 1070
    vm.auxiliary = (0, 31245)
    vm.pc = 1076
    vm._write(156, vm._signed_cell(153, 1) ^ vm._signed_cell(155, 1), 8, 'high.flag1_xor_q')
    vm.pc = 1081
    vm.cells.copy_q_clear_owned(138, 157)
    _indexed_pointer(vm, 1081, 158, 33, 5, (26, 157))
    vm.pc = 1093
    value = vm.memory.load(vm.cells.value(158), 4)
    vm._write(159, value, 4, 'high.load')
    vm.pc = 1096
    vm.auxiliary = (0, 1004689411)
    vm.pc = 1097
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = 1101
    value = int(vm._signed_cell(159, 1) == vm._signed_cell(156, 1))
    vm._write(160, value, 4, 'L26.comparison')
    vm.pc = 1105
    vm._jump(39 if vm.cells.value(160) != 0 else 40)


def _scan_done(vm):
    vm.pc = 1021
    vm._jump(32)


def _clear_slot(vm):
    vm.pc = 1110
    vm.cells.copy_q_clear_owned(151, 161)
    _native_call(vm, 1110, 1119, 38, 12, (161, 13, 52), 162)
    vm.pc = 1121
    vm._jump(41)


def _skip_slot(vm):
    vm.pc = 1123
    vm._jump(41)


def _scan_result(vm):
    vm.pc = 1130
    if vm.predecessor == 39:
        value = vm.cells.value(164)
    elif vm.predecessor == 40:
        value = vm.cells.value(13)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(163, value, 8, 'L9.phi_q')
    vm.pc = 1131
    vm.pc = 1134
    vm.auxiliary = (0, 1806833507)
    vm.pc = 1135
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = 1139
    value = int(vm._signed_cell(163, 1) == vm._signed_cell(13, 1))
    vm._write(165, value, 4, 'L26.comparison')
    vm.pc = 1143
    vm._jump(36 if vm.cells.value(165) != 0 else 32)


def run_primary_token_expire(vm):
    _initialize(vm)
    while True:
        _collect_head(vm)
        if vm.block == 4:
            break
        _inspect_slot(vm)
        if vm.block == 7:
            _collect_active(vm)
        _collect_next(vm)
    _collected(vm)
    if vm.block == 5:
        _empty(vm)
        _finish(vm)
        return vm.result
    _sort(vm)
    while True:
        _group_head(vm)
        if vm.block == 12:
            break
        _inspect_kind(vm)
        if vm.block == 14:
            _group_first(vm)
        else:
            _group_other(vm)
        _group_next(vm)
    _prepare_deletions(vm)
    while True:
        _first_head(vm)
        if vm.block == 18:
            break
        _first_age(vm)
        if vm.block == 21:
            _first_young(vm)
        else:
            _first_old(vm)
            if vm.block == 22:
                _first_keep(vm)
            else:
                _first_delete(vm)
        _first_next(vm)
    _first_done(vm)
    while True:
        _other_head(vm)
        if vm.block == 26:
            break
        _other_age(vm)
        if vm.block == 29:
            _other_young(vm)
        else:
            _other_old(vm)
            if vm.block == 30:
                _other_keep(vm)
            else:
                _other_delete(vm)
        _other_next(vm)
    _other_done(vm)
    while True:
        _delete_head(vm)
        if vm.block == 34:
            break
        _scan_start(vm)
        while True:
            _scan_head(vm)
            if vm.block == 38:
                _scan_done(vm)
                break
            _scan_slot(vm)
            if vm.block == 39:
                _clear_slot(vm)
            else:
                _skip_slot(vm)
            _scan_result(vm)
            if vm.block == 32:
                break
            _scan_next(vm)
        _delete_next(vm)
    _publish_count(vm)
    _finish(vm)
    return vm.result
