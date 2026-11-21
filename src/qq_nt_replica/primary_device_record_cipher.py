from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


def _stage_0(vm):
    vm.pc = 4
    vm._allocate(3, 4)
    vm.pc = 7
    vm._allocate(9, 5)
    vm.pc = 10
    vm._allocate(11, 6)
    vm.pc = 13
    vm._allocate(13, 7)
    vm.pc = 16
    vm._allocate(13, 8)
    vm.pc = 19
    vm._allocate(15, 9)
    vm.pc = 22
    vm._allocate(11, 10)
    vm.pc = 25
    vm._allocate(17, 11)
    vm.pc = 28
    vm._allocate(11, 12)
    vm.pc = 31
    vm._allocate(20, 13)
    vm.pc = 34
    vm._allocate(22, 14)
    vm.pc = 37
    vm._allocate(19, 15)
    vm.pc = 42
    vm.cells.copy_q_clear_owned(4, 16)
    _store_cell(vm, 42, 4, 17, 4)
    _native_call(vm, 46, 52, 25, 18, (4,))
    vm.pc = 57
    vm.cells.copy_q_clear_owned(5, 19)
    _native_call(vm, 57, 66, 28, 21, (19, 22, 23), 20)
    vm.pc = 71
    vm.cells.copy_q_clear_owned(0, 24)
    _indexed_pointer(vm, 71, 25, 9, 5, (26, 26))
    vm.pc = 84
    vm.cells.copy_q_clear_owned(25, 27)
    vm.pc = 89
    vm.cells.copy_q_clear_owned(1, 28)
    vm.pc = 90
    vm.pc = 93
    vm.auxiliary = (0, 1774916099)
    vm.pc = 98
    vm._write(30, vm._signed_cell(28, 27) * vm._signed_cell(29, 27), 8, 'once0.integer')
    vm.pc = 101
    vm.auxiliary = (0, 54831)
    vm.pc = 106
    value = vm._signed_cell(30, 27) & vm._signed_cell(31, 27)
    vm._write(32, value, 8, 'typed.selector1.q')
    vm.pc = 108
    vm._jump(1)


def _stage_1(vm):
    vm.pc = 115
    if vm.predecessor == 0:
        value = vm.cells.value(26)
    elif vm.predecessor == 2:
        value = vm.cells.value(34)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(33, value, 8, 'L9.phi_q')
    vm.pc = 120
    vm._write(35, int(vm.cells.value(33) < vm.cells.value(32)), 4, 'once18.unsigned_q')
    vm.pc = 124
    vm._jump(2 if vm.cells.value(35) != 0 else 3)


def _stage_2(vm):
    _indexed_pointer(vm, 126, 36, 1, 0, (33,))
    vm.pc = 138
    vm.cells.copy_q_clear_owned(36, 37)
    vm.pc = 142
    vm._write(38, vm.memory.load(vm.cells.value(37), 4), 4, 'high.load')
    _indexed_pointer(vm, 142, 39, 1, 27, (33,))
    vm.pc = 154
    vm.cells.copy_q_clear_owned(39, 40)
    _store_cell(vm, 154, 4, 38, 40)
    vm.pc = 159
    vm.pc = 162
    vm.auxiliary = (0, 771203073)
    vm.pc = 167
    vm._write(34, vm._signed_cell(33, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 169
    vm._jump(1)


def _stage_3(vm):
    vm.pc = 126
    vm._jump(4)


def _stage_4(vm):
    vm.pc = 176
    if vm.predecessor == 3:
        value = vm.cells.value(32)
    elif vm.predecessor == 5:
        value = vm.cells.value(43)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(42, value, 8, 'L9.phi_q')
    vm.pc = 181
    vm._write(44, int(vm.cells.value(42) < vm.cells.value(30)), 4, 'once18.unsigned_q')
    vm.pc = 185
    vm._jump(5 if vm.cells.value(44) != 0 else 6)


def _stage_5(vm):
    _indexed_pointer(vm, 232, 54, 1, 0, (42,))
    vm.pc = 243
    vm._write(55, vm.memory.load(vm.cells.value(54), 1), 4, 'high.load')
    _indexed_pointer(vm, 243, 56, 1, 27, (42,))
    _store_cell(vm, 250, 1, 55, 56)
    vm.pc = 255
    vm.pc = 258
    vm.auxiliary = (0, 922509314)
    vm.pc = 263
    vm._write(43, vm._signed_cell(42, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 265
    vm._jump(4)


def _stage_6(vm):
    vm.pc = 190
    vm._write(45, vm.cells.value(30) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 195
    vm.cells.copy_q_clear_owned(6, 46)
    _native_call(vm, 195, 204, 28, 21, (46, 22, 48), 47)
    _native_call(vm, 204, 210, 32, 50, (), 49)
    vm.pc = 215
    vm.cells.copy_q_clear_owned(49, 51)
    _indexed_pointer(vm, 215, 52, 11, 6, (26, 26))
    _native_call(vm, 223, 230, 54, 53, (51, 52))
    vm.pc = 232
    vm._jump(7)


def _stage_7(vm):
    vm.pc = 272
    if vm.predecessor == 6:
        value = vm.cells.value(22)
    elif vm.predecessor == 8:
        value = vm.cells.value(59)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(58, value, 8, 'L9.phi_q')
    vm.pc = 279
    if vm.predecessor == 6:
        value = vm.cells.value(45)
    elif vm.predecessor == 8:
        value = vm.cells.value(61)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(60, value, 8, 'L9.phi_q')
    vm.pc = 280
    vm.pc = 283
    vm.auxiliary = (0, 944939573)
    vm.pc = 288
    a = vm._signed_cell(58, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(1, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(62, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 292
    vm._jump(9 if vm.cells.value(62) != 0 else 10)


def _stage_8(vm):
    vm.pc = 695
    if vm.predecessor == 21:
        value = vm.cells.value(114)
    elif vm.predecessor == 14:
        value = vm.cells.value(60)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(61, value, 8, 'L9.phi_q')
    vm.pc = 696
    vm.pc = 699
    vm.auxiliary = (0, 1462976513)
    vm.pc = 704
    vm._write(59, vm._signed_cell(58, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 706
    vm._jump(7)


def _stage_9(vm):
    vm.pc = 350
    vm.cells.copy_q_clear_owned(58, 73)
    _indexed_pointer(vm, 350, 74, 8, 24, (73,))
    _indexed_pointer(vm, 357, 75, 8, 74, (22, 22))
    vm.pc = 369
    vm._write(76, vm.memory.load(vm.cells.value(75), 4), 4, 'high.load')
    _indexed_pointer(vm, 369, 77, 9, 5, (26, 73))
    _indexed_pointer(vm, 377, 78, 8, 77, (22, 22))
    _store_cell(vm, 385, 4, 76, 78)
    _indexed_pointer(vm, 389, 79, 8, 74, (22, 80))
    vm.pc = 401
    vm._write(81, vm.memory.load(vm.cells.value(79), 4), 4, 'high.load')
    vm.pc = 406
    vm._write(82, int(vm.cells.value(81) > vm.cells.value(22)), 4, 'L31.comparison')
    vm.pc = 410
    vm._jump(13 if vm.cells.value(82) != 0 else 14)


def _stage_10(vm):
    _indexed_pointer(vm, 292, 63, 9, 5, (26, 28))
    _indexed_pointer(vm, 300, 64, 8, 63, (22, 22))
    _store_cell(vm, 308, 4, 65, 64)
    _native_call(vm, 312, 320, 56, 67, (68, 57), 66)
    _indexed_pointer(vm, 320, 69, 8, 63, (22, 70))
    _store_cell(vm, 328, 8, 66, 69)
    vm.pc = 333
    vm.pc = 336
    vm.auxiliary = (0, 2107810948)
    vm.pc = 341
    vm._write(72, int(vm._signed_cell(66, 2) != vm._signed_cell(71, 2)), 4, 'L30.comparison')
    vm.pc = 345
    vm._jump(11 if vm.cells.value(72) != 0 else 12)


def _stage_11(vm):
    _indexed_pointer(vm, 706, 120, 8, 63, (22, 80))
    _store_cell(vm, 714, 4, 121, 120)
    vm.pc = 722
    vm._write(122, vm.memory.load(vm.cells.value(69), 8), 8, 'high.load')
    vm.pc = 724
    vm._jump(22)


def _stage_12(vm):
    _store_cell(vm, 851, 8, 71, 69)
    _indexed_pointer(vm, 855, 139, 8, 63, (22, 80))
    _store_cell(vm, 863, 4, 22, 139)
    vm.pc = 869
    vm._jump(28)


def _stage_13(vm):
    _indexed_pointer(vm, 410, 83, 8, 74, (22, 70))
    vm.pc = 422
    vm._write(84, vm.memory.load(vm.cells.value(83), 8), 8, 'high.load')
    vm.pc = 423
    vm.pc = 426
    vm.auxiliary = (0, 1284699508)
    vm.pc = 431
    vm._write(85, int(vm._signed_cell(84, 2) != vm._signed_cell(71, 2)), 4, 'L27.comparison')
    vm.pc = 435
    vm._jump(15 if vm.cells.value(85) != 0 else 14)


def _stage_14(vm):
    _indexed_pointer(vm, 662, 118, 8, 77, (22, 80))
    _store_cell(vm, 670, 4, 22, 118)
    _indexed_pointer(vm, 674, 119, 8, 77, (22, 70))
    _store_cell(vm, 682, 8, 71, 119)
    vm.pc = 688
    vm._jump(8)


def _stage_15(vm):
    _indexed_pointer(vm, 435, 86, 8, 77, (22, 80))
    _store_cell(vm, 443, 4, 81, 86)
    vm.pc = 451
    vm._write(87, vm.memory.load(vm.cells.value(79), 4), 4, 'high.load')
    vm.pc = 452
    vm.pc = 455
    vm.auxiliary = (0, 1722941441)
    vm.pc = 460
    vm._write(88, vm._signed_cell(87, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 465
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(89, vm.cells.value(88), 8, 'once10.first_type_zeroextend_or_q')
    _native_call(vm, 465, 473, 56, 67, (89, 57), 90)
    _indexed_pointer(vm, 473, 91, 8, 77, (22, 70))
    _store_cell(vm, 481, 8, 90, 91)
    vm.pc = 489
    vm._write(92, vm.memory.load(vm.cells.value(83), 8), 8, 'high.load')
    vm.pc = 493
    vm._write(93, vm.memory.load(vm.cells.value(79), 4), 4, 'high.load')
    vm.pc = 498
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(94, vm.cells.value(93), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 503
    vm._write(95, vm._signed_cell(94, 27) & vm._signed_cell(31, 27), 8, 'L13.binary_q')
    vm.pc = 505
    vm._jump(16)


def _stage_16(vm):
    vm.pc = 512
    if vm.predecessor == 15:
        value = vm.cells.value(26)
    elif vm.predecessor == 17:
        value = vm.cells.value(97)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(96, value, 8, 'L9.phi_q')
    vm.pc = 517
    vm._write(98, int(vm.cells.value(96) < vm.cells.value(95)), 4, 'once18.unsigned_q')
    vm.pc = 521
    vm._jump(17 if vm.cells.value(98) != 0 else 18)


def _stage_17(vm):
    _indexed_pointer(vm, 523, 99, 1, 92, (96,))
    vm.pc = 535
    vm.cells.copy_q_clear_owned(99, 100)
    vm.pc = 539
    vm._write(101, vm.memory.load(vm.cells.value(100), 4), 4, 'high.load')
    _indexed_pointer(vm, 539, 102, 1, 90, (96,))
    vm.pc = 551
    vm.cells.copy_q_clear_owned(102, 103)
    _store_cell(vm, 551, 4, 101, 103)
    vm.pc = 556
    vm.pc = 559
    vm.auxiliary = (0, 1413476354)
    vm.pc = 564
    vm._write(97, vm._signed_cell(96, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 566
    vm._jump(16)


def _stage_18(vm):
    vm.pc = 523
    vm._jump(19)


def _stage_19(vm):
    vm.pc = 573
    if vm.predecessor == 18:
        value = vm.cells.value(95)
    elif vm.predecessor == 20:
        value = vm.cells.value(105)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(104, value, 8, 'L9.phi_q')
    vm.pc = 578
    vm._write(106, int(vm.cells.value(104) < vm.cells.value(94)), 4, 'once18.unsigned_q')
    vm.pc = 582
    vm._jump(20 if vm.cells.value(106) != 0 else 21)


def _stage_20(vm):
    _indexed_pointer(vm, 629, 115, 1, 92, (104,))
    vm.pc = 640
    vm._write(116, vm.memory.load(vm.cells.value(115), 1), 4, 'high.load')
    _indexed_pointer(vm, 640, 117, 1, 90, (104,))
    _store_cell(vm, 647, 1, 116, 117)
    vm.pc = 652
    vm.pc = 655
    vm.auxiliary = (0, 716083201)
    vm.pc = 660
    vm._write(105, vm._signed_cell(104, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 662
    vm._jump(19)


def _stage_21(vm):
    vm.pc = 586
    vm._write(107, vm.memory.load(vm.cells.value(91), 8), 8, 'high.load')
    vm.pc = 590
    vm._write(108, vm.memory.load(vm.cells.value(86), 4), 4, 'high.load')
    vm.pc = 595
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(109, vm.cells.value(108), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 595, 110, 1, 107, (109,))
    _store_cell(vm, 602, 1, 111, 110)
    vm.pc = 610
    vm._write(112, vm.memory.load(vm.cells.value(79), 4), 4, 'high.load')
    vm.pc = 611
    vm.pc = 614
    vm.auxiliary = (0, 1415901185)
    vm.pc = 619
    vm._write(113, vm._signed_cell(112, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 622
    vm.auxiliary = (0, 1010155522)
    vm.pc = 627
    vm._write(114, vm._signed_cell(60, 3) + vm._signed_cell(113, 3), 8, 'once1.integer')
    vm.pc = 629
    vm._jump(8)


def _stage_22(vm):
    vm.pc = 731
    if vm.predecessor == 11:
        value = vm.cells.value(26)
    elif vm.predecessor == 23:
        value = vm.cells.value(124)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(123, value, 8, 'L9.phi_q')
    vm.pc = 736
    vm._write(125, int(vm.cells.value(123) < vm.cells.value(48)), 4, 'once18.unsigned_q')
    vm.pc = 740
    vm._jump(23 if vm.cells.value(125) != 0 else 24)


def _stage_23(vm):
    _indexed_pointer(vm, 742, 126, 1, 52, (123,))
    vm.pc = 754
    vm.cells.copy_q_clear_owned(126, 127)
    vm.pc = 758
    vm._write(128, vm.memory.load(vm.cells.value(127), 4), 4, 'high.load')
    _indexed_pointer(vm, 758, 129, 1, 122, (123,))
    vm.pc = 770
    vm.cells.copy_q_clear_owned(129, 130)
    _store_cell(vm, 770, 4, 128, 130)
    vm.pc = 775
    vm.pc = 778
    vm.auxiliary = (0, 718229505)
    vm.pc = 783
    vm._write(124, vm._signed_cell(123, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 785
    vm._jump(22)


def _stage_24(vm):
    vm.pc = 742
    vm._jump(25)


def _stage_25(vm):
    vm.pc = 792
    if vm.predecessor == 24:
        value = vm.cells.value(48)
    elif vm.predecessor == 26:
        value = vm.cells.value(132)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(131, value, 8, 'L9.phi_q')
    vm.pc = 797
    vm._write(133, int(vm.cells.value(131) < vm.cells.value(48)), 4, 'once18.unsigned_q')
    vm.pc = 801
    vm._jump(26 if vm.cells.value(133) != 0 else 27)


def _stage_26(vm):
    _indexed_pointer(vm, 818, 136, 1, 52, (131,))
    vm.pc = 829
    vm._write(137, vm.memory.load(vm.cells.value(136), 1), 4, 'high.load')
    _indexed_pointer(vm, 829, 138, 1, 122, (131,))
    _store_cell(vm, 836, 1, 137, 138)
    vm.pc = 841
    vm.pc = 844
    vm.auxiliary = (0, 1110220802)
    vm.pc = 849
    vm._write(132, vm._signed_cell(131, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 851
    vm._jump(25)


def _stage_27(vm):
    vm.pc = 805
    vm._write(134, vm.memory.load(vm.cells.value(69), 8), 8, 'high.load')
    _indexed_pointer(vm, 805, 135, 1, 134, (48,))
    _store_cell(vm, 812, 1, 111, 135)
    vm.pc = 818
    vm._jump(28)


def _stage_28(vm):
    vm.pc = 874
    vm.cells.copy_q_clear_owned(60, 140)
    vm.pc = 875
    vm.pc = 878
    vm.auxiliary = (0, 1108295682)
    vm.pc = 883
    vm._write(141, vm._signed_cell(140, 27) + vm._signed_cell(29, 27), 8, 'once1.integer')
    vm.pc = 888
    vm._write(142, vm.cells.value(141) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 893
    vm.cells.copy_q_clear_owned(142, 143)
    vm.pc = 896
    vm.auxiliary = (0, 1475080193)
    vm.pc = 901
    vm._write(144, vm._signed_cell(143, 27) + vm._signed_cell(68, 27), 8, 'once1.integer')
    vm.pc = 906
    vm._write(145, vm.cells.value(144) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 909
    vm.auxiliary = (0, 706347009)
    vm.pc = 914
    vm._write(146, vm._signed_cell(1, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 919
    vm.cells.copy_q_clear_owned(7, 147)
    vm.pc = 924
    vm.cells.copy_q_clear_owned(8, 148)
    vm.pc = 926
    vm._jump(29)


def _stage_29(vm):
    vm.pc = 933
    if vm.predecessor == 28:
        value = vm.cells.value(26)
    elif vm.predecessor == 30:
        value = vm.cells.value(150)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(149, value, 8, 'L9.phi_q')
    vm.pc = 938
    vm._write(152, int(vm.cells.value(149) < vm.cells.value(151)), 4, 'once18.unsigned_q')
    vm.pc = 942
    vm._jump(30 if vm.cells.value(152) != 0 else 31)


def _stage_30(vm):
    vm.pc = 967
    vm._write(158, vm.cells.value(149) & 4294967295, 8, 'once9.mask_q')
    _indexed_pointer(vm, 967, 159, 13, 7, (26, 149))
    _store_cell(vm, 975, 4, 158, 159)
    _indexed_pointer(vm, 979, 160, 13, 8, (26, 149))
    _store_cell(vm, 987, 4, 158, 160)
    vm.pc = 992
    vm.pc = 995
    vm.auxiliary = (0, 211501057)
    vm.pc = 1000
    vm._write(150, vm._signed_cell(149, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 1002
    vm._jump(29)


def _stage_31(vm):
    _native_call(vm, 942, 949, 59, 154, (155,), 153)
    vm.pc = 954
    vm._write(156, vm.cells.value(153) & 4294967295, 8, 'once9.mask_q')
    _native_call(vm, 954, 960, 61, 157, (156,))
    vm.pc = 962
    vm._jump(32)


def _stage_32(vm):
    vm.pc = 1009
    if vm.predecessor == 31:
        value = vm.cells.value(162)
    elif vm.predecessor == 33:
        value = vm.cells.value(163)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(161, value, 8, 'L9.phi_q')
    vm.pc = 1010
    vm.pc = 1013
    vm.auxiliary = (0, 1787995782)
    vm.pc = 1018
    vm._write(164, int(vm._signed_cell(161, 3) > vm._signed_cell(22, 3)), 4, 'L25.comparison')
    vm.pc = 1022
    vm._jump(33 if vm.cells.value(164) != 0 else 34)


def _stage_33(vm):
    _native_call(vm, 1024, 1030, 63, 166, (), 165)
    vm.pc = 1031
    vm.pc = 1034
    vm.auxiliary = (0, 1223335938)
    vm.pc = 1039
    vm._write(167, vm._signed_cell(161, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 1044
    a, b = vm.cells.value(165), vm.cells.value(167)
    if b == 0:
        raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
    vm._write(168, a % b, 8, 'L17.unsigned_q_division')
    vm.pc = 1049
    vm.cells.copy_q_clear_owned(161, 169)
    _indexed_pointer(vm, 1049, 170, 13, 7, (26, 169))
    vm.pc = 1061
    vm._write(171, vm.memory.load(vm.cells.value(170), 4), 4, 'high.load')
    vm.pc = 1066
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(172, vm.cells.value(168), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 1066, 173, 13, 7, (26, 172))
    vm.pc = 1078
    vm._write(174, vm.memory.load(vm.cells.value(173), 4), 4, 'high.load')
    _store_cell(vm, 1078, 4, 174, 170)
    _store_cell(vm, 1082, 4, 171, 173)
    vm.pc = 1089
    vm.auxiliary = (0, 1172103169)
    vm.pc = 1094
    vm._write(163, vm._signed_cell(161, 3) + vm._signed_cell(175, 3), 8, 'once1.integer')
    vm.pc = 1096
    vm._jump(32)


def _stage_34(vm):
    vm.pc = 1024
    vm._jump(35)


def _stage_35(vm):
    vm.pc = 1103
    if vm.predecessor == 34:
        value = vm.cells.value(22)
    elif vm.predecessor == 36:
        value = vm.cells.value(177)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(176, value, 8, 'L9.phi_q')
    vm.pc = 1104
    vm.pc = 1107
    vm.auxiliary = (0, 798162485)
    vm.pc = 1112
    a = vm._signed_cell(176, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(146, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(178, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1116
    vm._jump(37 if vm.cells.value(178) != 0 else 38)


def _stage_36(vm):
    vm.pc = 1270
    vm.pc = 1273
    vm.auxiliary = (0, 1665662977)
    vm.pc = 1278
    vm._write(177, vm._signed_cell(176, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 1280
    vm._jump(35)


def _stage_37(vm):
    vm.pc = 1200
    vm.cells.copy_q_clear_owned(176, 192)
    _indexed_pointer(vm, 1200, 193, 9, 5, (26, 192))
    _indexed_pointer(vm, 1208, 194, 8, 193, (22, 22))
    vm.pc = 1220
    vm._write(195, vm.memory.load(vm.cells.value(194), 4), 4, 'high.load')
    vm.pc = 1225
    vm._write(197, int(vm.cells.value(195) < vm.cells.value(196)), 4, 'once18.unsigned_q')
    vm.pc = 1229
    vm._jump(40 if vm.cells.value(197) != 0 else 36)


def _stage_38(vm):
    vm.pc = 1121
    vm.cells.copy_q_clear_owned(146, 179)
    _indexed_pointer(vm, 1121, 180, 9, 5, (26, 179))
    _indexed_pointer(vm, 1129, 181, 8, 180, (22, 22))
    _store_cell(vm, 1137, 4, 182, 181)
    _native_call(vm, 1141, 1149, 56, 67, (184, 57), 183)
    _indexed_pointer(vm, 1149, 185, 8, 180, (22, 70))
    _store_cell(vm, 1157, 8, 183, 185)
    _indexed_pointer(vm, 1161, 186, 8, 180, (22, 80))
    _store_cell(vm, 1169, 4, 187, 186)
    vm.pc = 1177
    vm._write(188, vm.memory.load(vm.cells.value(185), 8), 8, 'high.load')
    _indexed_pointer(vm, 1177, 189, 1, 188, (190,))
    _store_cell(vm, 1184, 1, 111, 189)
    vm.pc = 1193
    vm.cells.copy_q_clear_owned(9, 191)
    vm.pc = 1195
    vm._jump(39)


def _stage_39(vm):
    vm.pc = 1287
    if vm.predecessor == 38:
        value = vm.cells.value(22)
    elif vm.predecessor == 41:
        value = vm.cells.value(204)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(203, value, 8, 'L9.phi_q')
    vm.pc = 1294
    if vm.predecessor == 38:
        value = vm.cells.value(22)
    elif vm.predecessor == 41:
        value = vm.cells.value(206)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(205, value, 8, 'L9.phi_q')
    vm.pc = 1295
    vm.pc = 1298
    vm.auxiliary = (0, 1804760197)
    vm.pc = 1303
    a = vm._signed_cell(205, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(196, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(207, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1306
    vm.auxiliary = (0, 899845605)
    vm.pc = 1311
    a = vm._signed_cell(203, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(187, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(208, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1318
    selected = 208 if vm.cells.value(207) != 0 else 209
    vm._write(210, vm._signed_cell(selected, 31), 8, 'L7.selected_q')
    vm.pc = 1322
    vm._jump(42 if vm.cells.value(210) != 0 else 43)


def _stage_40(vm):
    vm.pc = 1234
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(198, vm.cells.value(195), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 1234, 199, 13, 7, (26, 198))
    vm.pc = 1246
    vm._write(200, vm.memory.load(vm.cells.value(199), 4), 4, 'high.load')
    _store_cell(vm, 1246, 4, 200, 194)
    vm.pc = 1255
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(201, vm.cells.value(200), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 1255, 202, 13, 8, (26, 201))
    _store_cell(vm, 1263, 4, 195, 202)
    vm.pc = 1269
    vm._jump(36)


def _stage_41(vm):
    vm.pc = 1750
    vm.pc = 1753
    vm.auxiliary = (0, 2080198657)
    vm.pc = 1758
    vm._write(204, vm._signed_cell(203, 3) + vm._signed_cell(276, 3), 8, 'once1.integer')
    vm.pc = 1761
    vm.auxiliary = (0, 705884162)
    vm.pc = 1766
    vm._write(206, vm._signed_cell(205, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 1768
    vm._jump(39)


def _stage_42(vm):
    vm.pc = 1500
    vm.cells.copy_q_clear_owned(205, 238)
    _indexed_pointer(vm, 1500, 239, 13, 8, (26, 238))
    vm.pc = 1512
    vm._write(240, vm.memory.load(vm.cells.value(239), 4), 4, 'high.load')
    vm.pc = 1513
    vm.pc = 1516
    vm.auxiliary = (0, 1380057509)
    vm.pc = 1521
    a = vm._signed_cell(240, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(22, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(241, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 1525
    vm._jump(46 if vm.cells.value(241) != 0 else 47)


def _stage_43(vm):
    vm.pc = 1327
    vm.cells.copy_q_clear_owned(145, 211)
    vm.pc = 1328
    vm.pc = 1331
    vm.auxiliary = (0, 263950337)
    vm.pc = 1336
    vm._write(212, vm._signed_cell(211, 27) + vm._signed_cell(29, 27), 8, 'once1.integer')
    vm.pc = 1341
    vm._write(213, vm.cells.value(212) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 1346
    vm.cells.copy_q_clear_owned(213, 214)
    vm.pc = 1349
    vm.auxiliary = (0, 302161922)
    vm.pc = 1354
    vm._write(215, vm._signed_cell(214, 27) + vm._signed_cell(184, 27), 8, 'once1.integer')
    vm.pc = 1359
    vm._write(216, vm.cells.value(215) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 1362
    vm.auxiliary = (0, 1266335745)
    vm.pc = 1367
    vm._write(217, vm._signed_cell(146, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 1372
    vm.cells.copy_q_clear_owned(10, 218)
    _native_call(vm, 1372, 1381, 28, 21, (218, 22, 48), 219)
    vm.pc = 1385
    vm._write(220, vm.memory.load(vm.cells.value(4), 4), 4, 'high.load')
    _indexed_pointer(vm, 1385, 221, 11, 10, (26, 26))
    _indexed_pointer(vm, 1393, 222, 65, 223, (26, 26))
    vm.pc = 1402
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('variadic call current-global alternate route is unavailable')
    vm.pc = 1406
    x = vm.memory.load(vm.image_base + 0x677E1B4, 4, signed=True)
    y = vm.memory.load(vm.image_base + 0x677E1B8, 4, signed=True)
    if ((((x * x + y * y) & 0xFFFFFFFF) | ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31):
        raise PrimarySemanticUnavailable('variadic call F-global alternate route is unavailable')
    vm.pc = 1408
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('variadic call G-global alternate route is unavailable')
    vm.pc = 1413
    address = vm.cells.value(225)
    vm.host_calls.append((1401, address, (221, 48, 222, 220), 67))
    from .primary_sign import _invoke_host
    result = _invoke_host(vm, address, (221, 48, 222, 220), 67, argument_types=(2, 27, 2, 3))
    vm._write(224, result, 8, 'high.variadic_result_q')
    _native_call(vm, 1413, 1420, 69, 227, (221,), 226)
    vm.pc = 1425
    vm._write(228, vm.cells.value(226) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 1430
    vm.cells.copy_q_clear_owned(217, 229)
    _indexed_pointer(vm, 1430, 230, 9, 5, (26, 229))
    vm.pc = 1443
    vm.cells.copy_q_clear_owned(228, 231)
    _indexed_pointer(vm, 1443, 232, 8, 230, (22, 22))
    _store_cell(vm, 1451, 4, 233, 232)
    vm.pc = 1458
    vm.auxiliary = (0, 1012576258)
    vm.pc = 1463
    vm._write(234, vm._signed_cell(231, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    _native_call(vm, 1463, 1471, 56, 67, (234, 57), 235)
    _indexed_pointer(vm, 1471, 236, 8, 230, (22, 70))
    _store_cell(vm, 1479, 8, 235, 236)
    vm.pc = 1486
    vm.auxiliary = (0, 1605527316)
    vm.pc = 1491
    vm._write(237, int(vm._signed_cell(235, 2) != vm._signed_cell(71, 2)), 4, 'L27.comparison')
    vm.pc = 1495
    vm._jump(44 if vm.cells.value(237) != 0 else 45)


def _stage_44(vm):
    _indexed_pointer(vm, 1801, 280, 8, 230, (22, 80))
    _store_cell(vm, 1809, 4, 228, 280)
    vm.pc = 1817
    vm._write(281, vm.memory.load(vm.cells.value(236), 8), 8, 'high.load')
    vm.pc = 1818
    vm.pc = 1821
    vm.auxiliary = (0, 30302)
    vm.pc = 1826
    value = vm._signed_cell(231, 27) & vm._signed_cell(31, 27)
    vm._write(282, value, 8, 'typed.selector1.q')
    vm.pc = 1828
    vm._jump(55)


def _stage_45(vm):
    _store_cell(vm, 1955, 8, 71, 236)
    _indexed_pointer(vm, 1959, 299, 8, 230, (22, 80))
    _store_cell(vm, 1967, 4, 22, 299)
    vm.pc = 1973
    vm._jump(61)


def _stage_46(vm):
    vm.pc = 1527
    vm._jump(48)


def _stage_47(vm):
    vm.pc = 1528
    vm.pc = 1531
    vm.auxiliary = (0, 1306704358)
    vm.pc = 1536
    vm._write(242, int(vm._signed_cell(240, 3) > vm._signed_cell(182, 3)), 4, 'L25.comparison')
    vm.pc = 1540
    vm._jump(49 if vm.cells.value(242) != 0 else 48)


def _stage_48(vm):
    vm.pc = 1551
    if vm.predecessor == 46:
        value = vm.cells.value(22)
    elif vm.predecessor == 49:
        value = vm.cells.value(182)
    elif vm.predecessor == 47:
        value = vm.cells.value(240)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(243, value, 8, 'L9.phi_q')
    vm.pc = 1556
    a, b = vm._signed_cell(243, 3), vm._signed_cell(244, 3)
    if b == 0 or (a == -(1 << 63) and b == -1):
        raise PrimaryProgramLimit('native IDIV fault lies outside ordinary execution')
    vm._write(245, abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1), 8, 'once6.integer')
    vm.pc = 1561
    a, b = vm._signed_cell(243, 3), vm._signed_cell(244, 3)
    if b == 0 or (a == -(1 << 63) and b == -1):
        raise PrimaryProgramLimit('native signed IDIV64 fault outside ordinary execution')
    quotient = abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)
    vm._write(246, a - quotient * b, 8, 'L16.signed_remainder_q')
    vm.pc = 1566
    a, b = vm._signed_cell(246, 3), vm._signed_cell(247, 3)
    if b == 0 or (a == -(1 << 63) and b == -1):
        raise PrimaryProgramLimit('native IDIV fault lies outside ordinary execution')
    vm._write(248, abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1), 8, 'once6.integer')
    vm.pc = 1571
    a, b = vm._signed_cell(243, 3), vm._signed_cell(247, 3)
    if b == 0 or (a == -(1 << 63) and b == -1):
        raise PrimaryProgramLimit('native signed IDIV64 fault outside ordinary execution')
    quotient = abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)
    vm._write(249, a - quotient * b, 8, 'L16.signed_remainder_q')
    vm.pc = 1572
    vm.pc = 1575
    vm.auxiliary = (0, 1864495105)
    vm.pc = 1580
    vm._write(251, vm._signed_cell(250, 3) + vm._signed_cell(245, 3), 8, 'once1.integer')
    vm.pc = 1585
    vm._write(252, vm.cells.value(251) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 1585, 253, 15, 9, (26, 26))
    _store_cell(vm, 1593, 1, 252, 253)
    vm.pc = 1600
    vm.auxiliary = (0, 1718353921)
    vm.pc = 1605
    vm._write(254, vm._signed_cell(250, 3) + vm._signed_cell(248, 3), 8, 'once1.integer')
    vm.pc = 1610
    vm._write(255, vm.cells.value(254) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 1610, 256, 15, 9, (26, 57))
    _store_cell(vm, 1618, 1, 255, 256)
    vm.pc = 1625
    vm.auxiliary = (0, 906665985)
    vm.pc = 1630
    vm._write(257, vm._signed_cell(250, 3) + vm._signed_cell(249, 3), 8, 'once1.integer')
    vm.pc = 1635
    vm._write(258, vm.cells.value(257) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 1635, 259, 15, 9, (26, 260))
    _store_cell(vm, 1643, 1, 258, 259)
    _indexed_pointer(vm, 1647, 261, 15, 9, (26, 262))
    _store_cell(vm, 1655, 1, 111, 261)
    vm.pc = 1663
    vm._write(263, vm.memory.load(vm.cells.value(185), 8), 8, 'high.load')
    vm.pc = 1668
    vm.cells.copy_q_clear_owned(203, 264)
    _indexed_pointer(vm, 1668, 265, 1, 263, (264,))
    vm.pc = 1677
    vm._jump(50)


def _stage_49(vm):
    vm.pc = 1542
    vm._jump(48)


def _stage_50(vm):
    vm.pc = 1684
    if vm.predecessor == 48:
        value = vm.cells.value(26)
    elif vm.predecessor == 51:
        value = vm.cells.value(267)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(266, value, 8, 'L9.phi_q')
    vm.pc = 1688
    vm._jump(51 if vm.cells.value(209) != 0 else 52)


def _stage_51(vm):
    _indexed_pointer(vm, 1690, 268, 1, 253, (266,))
    vm.pc = 1702
    vm.cells.copy_q_clear_owned(268, 269)
    vm.pc = 1706
    vm._write(270, vm.memory.load(vm.cells.value(269), 4), 4, 'high.load')
    _indexed_pointer(vm, 1706, 271, 1, 265, (266,))
    vm.pc = 1718
    vm.cells.copy_q_clear_owned(271, 272)
    _store_cell(vm, 1718, 4, 270, 272)
    vm.pc = 1723
    vm.pc = 1726
    vm.auxiliary = (0, 1358954498)
    vm.pc = 1731
    vm._write(267, vm._signed_cell(266, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 1733
    vm._jump(50)


def _stage_52(vm):
    vm.pc = 1690
    vm._jump(53)


def _stage_53(vm):
    vm.pc = 1740
    if vm.predecessor == 52:
        value = vm.cells.value(26)
    elif vm.predecessor == 54:
        value = vm.cells.value(274)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(273, value, 8, 'L9.phi_q')
    vm.pc = 1745
    vm._write(275, int(vm.cells.value(273) < vm.cells.value(262)), 4, 'once18.unsigned_q')
    vm.pc = 1749
    vm._jump(54 if vm.cells.value(275) != 0 else 41)


def _stage_54(vm):
    _indexed_pointer(vm, 1768, 277, 1, 253, (273,))
    vm.pc = 1779
    vm._write(278, vm.memory.load(vm.cells.value(277), 1), 4, 'high.load')
    _indexed_pointer(vm, 1779, 279, 1, 265, (273,))
    _store_cell(vm, 1786, 1, 278, 279)
    vm.pc = 1791
    vm.pc = 1794
    vm.auxiliary = (0, 1571516418)
    vm.pc = 1799
    vm._write(274, vm._signed_cell(273, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 1801
    vm._jump(53)


def _stage_55(vm):
    vm.pc = 1835
    if vm.predecessor == 44:
        value = vm.cells.value(26)
    elif vm.predecessor == 56:
        value = vm.cells.value(284)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(283, value, 8, 'L9.phi_q')
    vm.pc = 1840
    vm._write(285, int(vm.cells.value(283) < vm.cells.value(282)), 4, 'once18.unsigned_q')
    vm.pc = 1844
    vm._jump(56 if vm.cells.value(285) != 0 else 57)


def _stage_56(vm):
    _indexed_pointer(vm, 1846, 286, 1, 221, (283,))
    vm.pc = 1858
    vm.cells.copy_q_clear_owned(286, 287)
    vm.pc = 1862
    vm._write(288, vm.memory.load(vm.cells.value(287), 4), 4, 'high.load')
    _indexed_pointer(vm, 1862, 289, 1, 281, (283,))
    vm.pc = 1874
    vm.cells.copy_q_clear_owned(289, 290)
    _store_cell(vm, 1874, 4, 288, 290)
    vm.pc = 1879
    vm.pc = 1882
    vm.auxiliary = (0, 1310879746)
    vm.pc = 1887
    vm._write(284, vm._signed_cell(283, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 1889
    vm._jump(55)


def _stage_57(vm):
    vm.pc = 1846
    vm._jump(58)


def _stage_58(vm):
    vm.pc = 1896
    if vm.predecessor == 57:
        value = vm.cells.value(282)
    elif vm.predecessor == 59:
        value = vm.cells.value(292)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(291, value, 8, 'L9.phi_q')
    vm.pc = 1901
    vm._write(293, int(vm.cells.value(291) < vm.cells.value(231)), 4, 'once18.unsigned_q')
    vm.pc = 1905
    vm._jump(59 if vm.cells.value(293) != 0 else 60)


def _stage_59(vm):
    _indexed_pointer(vm, 1922, 296, 1, 221, (291,))
    vm.pc = 1933
    vm._write(297, vm.memory.load(vm.cells.value(296), 1), 4, 'high.load')
    _indexed_pointer(vm, 1933, 298, 1, 281, (291,))
    _store_cell(vm, 1940, 1, 297, 298)
    vm.pc = 1945
    vm.pc = 1948
    vm.auxiliary = (0, 1827737601)
    vm.pc = 1953
    vm._write(292, vm._signed_cell(291, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 1955
    vm._jump(58)


def _stage_60(vm):
    vm.pc = 1909
    vm._write(294, vm.memory.load(vm.cells.value(236), 8), 8, 'high.load')
    _indexed_pointer(vm, 1909, 295, 1, 294, (231,))
    _store_cell(vm, 1916, 1, 111, 295)
    vm.pc = 1922
    vm._jump(61)


def _stage_61(vm):
    vm.pc = 1978
    vm.cells.copy_q_clear_owned(216, 300)
    vm.pc = 1979
    vm.pc = 1982
    vm.auxiliary = (0, 357232641)
    vm.pc = 1987
    vm._write(301, vm._signed_cell(300, 27) + vm._signed_cell(29, 27), 8, 'once1.integer')
    vm.pc = 1992
    vm._write(302, vm.cells.value(301) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 1995
    vm.auxiliary = (0, 309219330)
    vm.pc = 2000
    vm._write(303, vm._signed_cell(302, 3) + vm._signed_cell(228, 3), 8, 'once1.integer')
    vm.pc = 2003
    vm.auxiliary = (0, 758919169)
    vm.pc = 2008
    vm._write(304, vm._signed_cell(217, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 2011
    vm.auxiliary = (0, 2074219012)
    vm.pc = 2016
    vm._write(305, vm._signed_cell(303, 3) * vm._signed_cell(80, 3), 8, 'once0.integer')
    vm.pc = 2021
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(306, vm.cells.value(305), 8, 'once10.first_type_zeroextend_or_q')
    _native_call(vm, 2021, 2029, 56, 67, (306, 57), 307)
    vm.pc = 2031
    vm._jump(62)


def _stage_62(vm):
    vm.pc = 2038
    if vm.predecessor == 61:
        value = vm.cells.value(22)
    elif vm.predecessor == 63:
        value = vm.cells.value(309)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(308, value, 8, 'L9.phi_q')
    vm.pc = 2045
    if vm.predecessor == 61:
        value = vm.cells.value(22)
    elif vm.predecessor == 63:
        value = vm.cells.value(311)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(310, value, 8, 'L9.phi_q')
    vm.pc = 2046
    vm.pc = 2049
    vm.auxiliary = (0, 378704517)
    vm.pc = 2054
    a = vm._signed_cell(308, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(304, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(312, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 2058
    vm._jump(64 if vm.cells.value(312) != 0 else 65)


def _stage_63(vm):
    vm.pc = 3190
    if vm.predecessor == 67:
        value = vm.cells.value(310)
    elif vm.predecessor == 95:
        value = vm.cells.value(468)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(311, value, 8, 'L9.phi_q')
    vm.pc = 3197
    if vm.predecessor == 67:
        value = vm.cells.value(470)
    elif vm.predecessor == 95:
        value = vm.cells.value(22)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(469, value, 8, 'L9.phi_q')
    vm.pc = 3198
    vm.pc = 3201
    vm.auxiliary = (0, 1164165121)
    vm.pc = 3206
    vm._write(309, vm._signed_cell(308, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 3208
    vm._jump(62)


def _stage_64(vm):
    vm.pc = 2065
    vm.cells.copy_q_clear_owned(11, 313)
    _native_call(vm, 2065, 2074, 28, 21, (313, 22, 315), 314)
    vm.pc = 2079
    vm.cells.copy_q_clear_owned(308, 316)
    _indexed_pointer(vm, 2079, 317, 8, 25, (316,))
    _indexed_pointer(vm, 2086, 318, 8, 317, (22, 80))
    vm.pc = 2098
    vm._write(319, vm.memory.load(vm.cells.value(318), 4), 4, 'high.load')
    vm.pc = 2103
    vm._write(321, int(vm.cells.value(319) > vm.cells.value(320)), 4, 'L31.comparison')
    vm.pc = 2107
    vm._jump(67 if vm.cells.value(321) != 0 else 68)


def _stage_65(vm):
    vm.pc = 2060
    vm._jump(66)


def _stage_66(vm):
    vm.pc = 3215
    if vm.predecessor == 65:
        value = vm.cells.value(22)
    elif vm.predecessor == 109:
        value = vm.cells.value(472)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(471, value, 8, 'L9.phi_q')
    vm.pc = 3216
    vm.pc = 3219
    vm.auxiliary = (0, 1695692533)
    vm.pc = 3224
    a = vm._signed_cell(471, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(304, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(473, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 3228
    vm._jump(110 if vm.cells.value(473) != 0 else 111)


def _stage_67(vm):
    vm.pc = 2109
    vm._jump(63)


def _stage_68(vm):
    _indexed_pointer(vm, 2109, 322, 8, 317, (22, 22))
    vm.pc = 2121
    vm._write(323, vm.memory.load(vm.cells.value(322), 4), 4, 'high.load')
    vm.pc = 2126
    vm._write(324, int(vm.cells.value(323) > vm.cells.value(22)), 4, 'L31.comparison')
    vm.pc = 2130
    vm._jump(69 if vm.cells.value(324) != 0 else 70)


def _stage_69(vm):
    _indexed_pointer(vm, 2130, 325, 17, 11, (26, 26))
    _store_cell(vm, 2138, 1, 326, 325)
    vm.pc = 2146
    vm._write(327, vm.memory.load(vm.cells.value(322), 4), 4, 'high.load')
    _indexed_pointer(vm, 2146, 328, 1, 325, (57,))
    vm.pc = 2154
    vm.pc = 2157
    vm.auxiliary = (0, 277007508)
    vm.pc = 2162
    vm._write(329, int(vm._signed_cell(327, 3) != vm._signed_cell(22, 3)), 4, 'L30.comparison')
    vm.pc = 2166
    vm._jump(71 if vm.cells.value(329) != 0 else 72)


def _stage_70(vm):
    vm.pc = 2353
    if vm.predecessor == 72:
        value = vm.cells.value(355)
    elif vm.predecessor == 68:
        value = vm.cells.value(22)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(356, value, 8, 'L9.phi_q')
    vm.pc = 2357
    vm._write(357, vm.memory.load(vm.cells.value(318), 4), 4, 'high.load')
    vm.pc = 2362
    vm._write(358, int(vm.cells.value(357) > vm.cells.value(22)), 4, 'L31.comparison')
    vm.pc = 2366
    vm._jump(78 if vm.cells.value(358) != 0 else 79)


def _stage_71(vm):
    vm.pc = 2173
    if vm.predecessor == 69:
        value = vm.cells.value(22)
    elif vm.predecessor == 73:
        value = vm.cells.value(331)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(330, value, 8, 'L9.phi_q')
    vm.pc = 2180
    if vm.predecessor == 69:
        value = vm.cells.value(327)
    elif vm.predecessor == 73:
        value = vm.cells.value(333)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(332, value, 8, 'L9.phi_q')
    vm.pc = 2181
    vm.pc = 2184
    vm.auxiliary = (0, 30069)
    vm.pc = 2189
    value = vm._signed_cell(332, 3) & vm._signed_cell(334, 3)
    vm._write(335, value, 8, 'typed.selector1.q')
    vm.pc = 2194
    vm._write(336, int(vm.cells.value(332) > vm.cells.value(334)), 4, 'L31.comparison')
    vm.pc = 2199
    vm._write(337, vm.memory.load(vm.cells.pointer(336), 4), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 2202
    vm.auxiliary = (0, 54684)
    vm.pc = 2203
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 2207
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(337, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(339, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 2211
        raise PrimaryProgramLimit('type index 63330 outside the decoded type vector')
    vm.pc = 2210
    vm.auxiliary = (0, 10114)
    vm.pc = 2215
    value = vm._signed_cell(335, 3) | vm._signed_cell(339, 3)
    vm._write(340, value, 8, 'typed.selector2.q')
    vm.pc = 2220
    vm._write(341, vm.cells.value(340) & 255, 8, 'once9.mask_q')
    vm.pc = 2223
    vm.auxiliary = (0, 720633858)
    vm.pc = 2228
    vm._write(342, vm._signed_cell(330, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 2233
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(343, vm.cells.value(330), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 2233, 344, 1, 328, (343,))
    _store_cell(vm, 2240, 1, 341, 344)
    vm.pc = 2249
    a = vm.memory.load(vm.cells.pointer(332), 4)
    count = vm.memory.load(vm.cells.pointer(338), 1)
    vm._write(333, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 2252
    vm.auxiliary = (0, 370330835)
    vm.pc = 2257
    vm._write(345, int(vm._signed_cell(333, 3) == vm._signed_cell(22, 3)), 4, 'once17.integer')
    vm.pc = 2261
    vm._jump(74 if vm.cells.value(345) != 0 else 75)


def _stage_72(vm):
    vm.pc = 2335
    if vm.predecessor == 73:
        value = vm.cells.value(331)
    elif vm.predecessor == 69:
        value = vm.cells.value(22)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(354, value, 8, 'L9.phi_q')
    vm.pc = 2336
    vm.pc = 2339
    vm.auxiliary = (0, 912883714)
    vm.pc = 2344
    vm._write(355, vm._signed_cell(70, 3) + vm._signed_cell(354, 3), 8, 'once1.integer')
    vm.pc = 2346
    vm._jump(70)


def _stage_73(vm):
    vm.pc = 2310
    if vm.predecessor == 74:
        value = vm.cells.value(342)
    elif vm.predecessor == 76:
        value = vm.cells.value(346)
    elif vm.predecessor == 77:
        value = vm.cells.value(342)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(331, value, 8, 'L9.phi_q')
    vm.pc = 2319
    if vm.predecessor == 74:
        value = vm.cells.value(352)
    elif vm.predecessor == 76:
        value = vm.cells.value(352)
    elif vm.predecessor == 77:
        value = vm.cells.value(22)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(351, value, 8, 'L9.phi_q')
    vm.pc = 2324
    vm._write(353, int(vm.cells.value(351) < vm.cells.value(70)), 4, 'once18.unsigned_q')
    vm.pc = 2328
    vm._jump(71 if vm.cells.value(353) != 0 else 72)


def _stage_74(vm):
    vm.pc = 2263
    vm._jump(73)


def _stage_75(vm):
    vm.pc = 2268
    vm._write(347, int(vm.cells.value(342) >= vm.cells.value(346)), 4, 'once20.unsigned_q')
    vm.pc = 2272
    vm._jump(76 if vm.cells.value(347) != 0 else 77)


def _stage_76(vm):
    vm.pc = 2273
    vm.pc = 2276
    vm.auxiliary = (0, 9774)
    vm.pc = 2281
    value = vm._signed_cell(333, 3) & vm._signed_cell(334, 3)
    vm._write(348, value, 8, 'typed.selector1.q')
    vm.pc = 2286
    vm._write(349, vm.cells.value(348) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 2286, 350, 1, 328, (41,))
    _store_cell(vm, 2293, 1, 349, 350)
    vm.pc = 2299
    vm._jump(73)


def _stage_77(vm):
    vm.pc = 2301
    vm._jump(73)


def _stage_78(vm):
    _indexed_pointer(vm, 2366, 359, 8, 317, (22, 70))
    vm.pc = 2378
    vm._write(360, vm.memory.load(vm.cells.value(359), 8), 8, 'high.load')
    vm.pc = 2379
    vm.pc = 2382
    vm.auxiliary = (0, 1886533412)
    vm.pc = 2387
    vm._write(361, int(vm._signed_cell(360, 2) != vm._signed_cell(71, 2)), 4, 'L30.comparison')
    vm.pc = 2391
    vm._jump(80 if vm.cells.value(361) != 0 else 79)


def _stage_79(vm):
    vm.pc = 2790
    if vm.predecessor == 93:
        value = vm.cells.value(412)
    elif vm.predecessor == 78:
        value = vm.cells.value(356)
    elif vm.predecessor == 70:
        value = vm.cells.value(356)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(416, value, 8, 'L9.phi_q')
    vm.pc = 2795
    vm._write(417, int(vm.cells.value(416) > vm.cells.value(22)), 4, 'L31.comparison')
    vm.pc = 2799
    vm._jump(94 if vm.cells.value(417) != 0 else 95)


def _stage_80(vm):
    vm.pc = 2392
    vm.pc = 2395
    vm.auxiliary = (0, 1613938689)
    vm.pc = 2400
    vm._write(362, vm._signed_cell(356, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 2405
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(363, vm.cells.value(356), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 2405, 364, 17, 11, (26, 363))
    _store_cell(vm, 2413, 1, 365, 364)
    vm.pc = 2421
    vm._write(366, vm.memory.load(vm.cells.value(318), 4), 4, 'high.load')
    _indexed_pointer(vm, 2421, 367, 17, 11, (26, 26))
    vm.pc = 2434
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(368, vm.cells.value(362), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 2434, 369, 1, 367, (368,))
    vm.pc = 2444
    vm.auxiliary = (0, 381854644)
    vm.pc = 2449
    vm._write(370, int(vm._signed_cell(366, 3) != vm._signed_cell(22, 3)), 4, 'L30.comparison')
    vm.pc = 2453
    vm._jump(81 if vm.cells.value(370) != 0 else 82)


def _stage_81(vm):
    vm.pc = 2460
    if vm.predecessor == 80:
        value = vm.cells.value(22)
    elif vm.predecessor == 83:
        value = vm.cells.value(372)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(371, value, 8, 'L9.phi_q')
    vm.pc = 2467
    if vm.predecessor == 80:
        value = vm.cells.value(366)
    elif vm.predecessor == 83:
        value = vm.cells.value(374)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(373, value, 8, 'L9.phi_q')
    vm.pc = 2472
    vm._write(375, vm._signed_cell(373, 3) & vm._signed_cell(334, 3), 8, 'L13.binary_q')
    vm.pc = 2477
    vm._write(376, int(vm.cells.value(373) > vm.cells.value(334)), 4, 'L31.comparison')
    vm.pc = 2482
    vm._write(377, vm.memory.load(vm.cells.pointer(376), 4), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 2483
    vm.pc = 2486
    vm.auxiliary = (0, 10175)
    vm.pc = 2487
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 2491
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(377, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(378, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 2495
        raise PrimaryProgramLimit('type index 45043 outside the decoded type vector')
    vm.pc = 2496
    vm._write(379, vm._signed_cell(375, 3) | vm._signed_cell(378, 3), 8, 'L15.binary_q')
    vm.pc = 2501
    vm._write(380, vm.cells.value(379) & 255, 8, 'once9.mask_q')
    vm.pc = 2504
    vm.auxiliary = (0, 1218244610)
    vm.pc = 2509
    vm._write(381, vm._signed_cell(371, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 2514
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(382, vm.cells.value(371), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 2514, 383, 1, 369, (382,))
    _store_cell(vm, 2521, 1, 380, 383)
    vm.pc = 2530
    a = vm.memory.load(vm.cells.pointer(373), 4)
    count = vm.memory.load(vm.cells.pointer(338), 1)
    vm._write(374, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 2533
    vm.auxiliary = (0, 1686265747)
    vm.pc = 2538
    vm._write(384, int(vm._signed_cell(374, 3) == vm._signed_cell(22, 3)), 4, 'once17.integer')
    vm.pc = 2542
    vm._jump(84 if vm.cells.value(384) != 0 else 85)


def _stage_82(vm):
    vm.pc = 2612
    if vm.predecessor == 83:
        value = vm.cells.value(372)
    elif vm.predecessor == 80:
        value = vm.cells.value(22)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(392, value, 8, 'L9.phi_q')
    vm.pc = 2617
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(393, vm.cells.value(392), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 2617, 394, 1, 369, (393,))
    vm.pc = 2628
    vm._write(395, vm.memory.load(vm.cells.value(359), 8), 8, 'high.load')
    vm.pc = 2632
    vm._write(396, vm.memory.load(vm.cells.value(318), 4), 4, 'high.load')
    vm.pc = 2637
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(397, vm.cells.value(396), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 2638
    vm.pc = 2641
    vm.auxiliary = (0, 51015)
    vm.pc = 2646
    value = vm._signed_cell(397, 27) & vm._signed_cell(31, 27)
    vm._write(398, value, 8, 'typed.selector1.q')
    vm.pc = 2648
    vm._jump(88)


def _stage_83(vm):
    vm.pc = 2587
    if vm.predecessor == 84:
        value = vm.cells.value(381)
    elif vm.predecessor == 86:
        value = vm.cells.value(346)
    elif vm.predecessor == 87:
        value = vm.cells.value(381)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(372, value, 8, 'L9.phi_q')
    vm.pc = 2596
    if vm.predecessor == 84:
        value = vm.cells.value(390)
    elif vm.predecessor == 86:
        value = vm.cells.value(390)
    elif vm.predecessor == 87:
        value = vm.cells.value(22)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(389, value, 8, 'L9.phi_q')
    vm.pc = 2601
    vm._write(391, int(vm.cells.value(389) < vm.cells.value(70)), 4, 'once18.unsigned_q')
    vm.pc = 2605
    vm._jump(81 if vm.cells.value(391) != 0 else 82)


def _stage_84(vm):
    vm.pc = 2544
    vm._jump(83)


def _stage_85(vm):
    vm.pc = 2549
    vm._write(385, int(vm.cells.value(381) >= vm.cells.value(346)), 4, 'once20.unsigned_q')
    vm.pc = 2553
    vm._jump(86 if vm.cells.value(385) != 0 else 87)


def _stage_86(vm):
    vm.pc = 2558
    vm._write(386, vm._signed_cell(374, 3) & vm._signed_cell(334, 3), 8, 'L13.binary_q')
    vm.pc = 2563
    vm._write(387, vm.cells.value(386) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 2563, 388, 1, 369, (41,))
    _store_cell(vm, 2570, 1, 387, 388)
    vm.pc = 2576
    vm._jump(83)


def _stage_87(vm):
    vm.pc = 2578
    vm._jump(83)


def _stage_88(vm):
    vm.pc = 2655
    if vm.predecessor == 82:
        value = vm.cells.value(26)
    elif vm.predecessor == 89:
        value = vm.cells.value(400)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(399, value, 8, 'L9.phi_q')
    vm.pc = 2660
    vm._write(401, int(vm.cells.value(399) < vm.cells.value(398)), 4, 'once18.unsigned_q')
    vm.pc = 2664
    vm._jump(89 if vm.cells.value(401) != 0 else 90)


def _stage_89(vm):
    _indexed_pointer(vm, 2666, 402, 1, 395, (399,))
    vm.pc = 2678
    vm.cells.copy_q_clear_owned(402, 403)
    vm.pc = 2682
    vm._write(404, vm.memory.load(vm.cells.value(403), 4), 4, 'high.load')
    _indexed_pointer(vm, 2682, 405, 1, 394, (399,))
    vm.pc = 2694
    vm.cells.copy_q_clear_owned(405, 406)
    _store_cell(vm, 2694, 4, 404, 406)
    vm.pc = 2699
    vm.pc = 2702
    vm.auxiliary = (0, 818712577)
    vm.pc = 2707
    vm._write(400, vm._signed_cell(399, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 2709
    vm._jump(88)


def _stage_90(vm):
    vm.pc = 2666
    vm._jump(91)


def _stage_91(vm):
    vm.pc = 2716
    if vm.predecessor == 90:
        value = vm.cells.value(398)
    elif vm.predecessor == 92:
        value = vm.cells.value(408)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(407, value, 8, 'L9.phi_q')
    vm.pc = 2721
    vm._write(409, int(vm.cells.value(407) < vm.cells.value(397)), 4, 'once18.unsigned_q')
    vm.pc = 2725
    vm._jump(92 if vm.cells.value(409) != 0 else 93)


def _stage_92(vm):
    _indexed_pointer(vm, 2748, 413, 1, 395, (407,))
    vm.pc = 2759
    vm._write(414, vm.memory.load(vm.cells.value(413), 1), 4, 'high.load')
    _indexed_pointer(vm, 2759, 415, 1, 394, (407,))
    _store_cell(vm, 2766, 1, 414, 415)
    vm.pc = 2771
    vm.pc = 2774
    vm.auxiliary = (0, 1510842370)
    vm.pc = 2779
    vm._write(408, vm._signed_cell(407, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 2781
    vm._jump(91)


def _stage_93(vm):
    vm.pc = 2729
    vm._write(410, vm.memory.load(vm.cells.value(318), 4), 4, 'high.load')
    vm.pc = 2730
    vm.pc = 2733
    vm.auxiliary = (0, 1162301442)
    vm.pc = 2738
    vm._write(411, vm._signed_cell(392, 3) + vm._signed_cell(410, 3), 8, 'once1.integer')
    vm.pc = 2741
    vm.auxiliary = (0, 1070465026)
    vm.pc = 2746
    vm._write(412, vm._signed_cell(362, 3) + vm._signed_cell(411, 3), 8, 'once1.integer')
    vm.pc = 2748
    vm._jump(79)


def _stage_94(vm):
    vm.pc = 2800
    vm.pc = 2803
    vm.auxiliary = (0, 761241602)
    vm.pc = 2808
    vm._write(418, vm._signed_cell(310, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 2813
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(419, vm.cells.value(310), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 2813, 420, 1, 307, (419,))
    _store_cell(vm, 2820, 1, 421, 420)
    vm.pc = 2829
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(422, vm.cells.value(418), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 2829, 423, 1, 307, (422,))
    vm.pc = 2840
    vm._jump(96 if vm.cells.value(424) != 0 else 97)


def _stage_95(vm):
    vm.pc = 3181
    if vm.predecessor == 108:
        value = vm.cells.value(464)
    elif vm.predecessor == 79:
        value = vm.cells.value(310)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(468, value, 8, 'L9.phi_q')
    vm.pc = 3183
    vm._jump(63)


def _stage_96(vm):
    vm.pc = 2847
    if vm.predecessor == 94:
        value = vm.cells.value(22)
    elif vm.predecessor == 98:
        value = vm.cells.value(426)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(425, value, 8, 'L9.phi_q')
    vm.pc = 2854
    if vm.predecessor == 94:
        value = vm.cells.value(416)
    elif vm.predecessor == 98:
        value = vm.cells.value(428)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(427, value, 8, 'L9.phi_q')
    vm.pc = 2855
    vm.pc = 2858
    vm.auxiliary = (0, 34605)
    vm.pc = 2863
    value = vm._signed_cell(427, 3) & vm._signed_cell(334, 3)
    vm._write(429, value, 8, 'typed.selector1.q')
    vm.pc = 2868
    vm._write(430, int(vm.cells.value(427) > vm.cells.value(334)), 4, 'L31.comparison')
    vm.pc = 2873
    vm._write(431, vm.memory.load(vm.cells.pointer(430), 4), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 2876
    vm.auxiliary = (0, 50414)
    vm.pc = 2877
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 2881
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(431, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(432, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 2885
        raise PrimaryProgramLimit('type index 13977 outside the decoded type vector')
    vm.pc = 2884
    vm.auxiliary = (0, 26089)
    vm.pc = 2889
    value = vm._signed_cell(429, 3) | vm._signed_cell(432, 3)
    vm._write(433, value, 8, 'typed.selector2.q')
    vm.pc = 2894
    vm._write(434, vm.cells.value(433) & 255, 8, 'once9.mask_q')
    vm.pc = 2897
    vm.auxiliary = (0, 202858497)
    vm.pc = 2902
    vm._write(435, vm._signed_cell(425, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 2907
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(436, vm.cells.value(425), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 2907, 437, 1, 423, (436,))
    _store_cell(vm, 2914, 1, 434, 437)
    vm.pc = 2923
    a = vm.memory.load(vm.cells.pointer(427), 4)
    count = vm.memory.load(vm.cells.pointer(338), 1)
    vm._write(428, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 2926
    vm.auxiliary = (0, 282242355)
    vm.pc = 2931
    vm._write(438, int(vm._signed_cell(428, 3) == vm._signed_cell(22, 3)), 4, 'once17.integer')
    vm.pc = 2935
    vm._jump(99 if vm.cells.value(438) != 0 else 100)


def _stage_97(vm):
    vm.pc = 3009
    if vm.predecessor == 98:
        value = vm.cells.value(426)
    elif vm.predecessor == 94:
        value = vm.cells.value(22)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(446, value, 8, 'L9.phi_q')
    vm.pc = 3010
    vm.pc = 3013
    vm.auxiliary = (0, 1872666626)
    vm.pc = 3018
    vm._write(447, vm._signed_cell(418, 3) + vm._signed_cell(446, 3), 8, 'once1.integer')
    vm.pc = 3023
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(448, vm.cells.value(447), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 3023, 449, 1, 307, (448,))
    _indexed_pointer(vm, 3030, 450, 17, 11, (26, 26))
    vm.pc = 3043
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(451, vm.cells.value(416), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 3046
    vm.auxiliary = (0, 4612)
    vm.pc = 3051
    value = vm._signed_cell(451, 27) & vm._signed_cell(31, 27)
    vm._write(452, value, 8, 'typed.selector1.q')
    vm.pc = 3053
    vm._jump(103)


def _stage_98(vm):
    vm.pc = 2984
    if vm.predecessor == 99:
        value = vm.cells.value(435)
    elif vm.predecessor == 101:
        value = vm.cells.value(346)
    elif vm.predecessor == 102:
        value = vm.cells.value(435)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(426, value, 8, 'L9.phi_q')
    vm.pc = 2993
    if vm.predecessor == 99:
        value = vm.cells.value(444)
    elif vm.predecessor == 101:
        value = vm.cells.value(444)
    elif vm.predecessor == 102:
        value = vm.cells.value(22)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(443, value, 8, 'L9.phi_q')
    vm.pc = 2998
    vm._write(445, int(vm.cells.value(443) < vm.cells.value(70)), 4, 'once18.unsigned_q')
    vm.pc = 3002
    vm._jump(96 if vm.cells.value(445) != 0 else 97)


def _stage_99(vm):
    vm.pc = 2937
    vm._jump(98)


def _stage_100(vm):
    vm.pc = 2942
    vm._write(439, int(vm.cells.value(435) >= vm.cells.value(346)), 4, 'once20.unsigned_q')
    vm.pc = 2946
    vm._jump(101 if vm.cells.value(439) != 0 else 102)


def _stage_101(vm):
    vm.pc = 2947
    vm.pc = 2950
    vm.auxiliary = (0, 30524)
    vm.pc = 2955
    value = vm._signed_cell(428, 3) & vm._signed_cell(334, 3)
    vm._write(440, value, 8, 'typed.selector1.q')
    vm.pc = 2960
    vm._write(441, vm.cells.value(440) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 2960, 442, 1, 423, (41,))
    _store_cell(vm, 2967, 1, 441, 442)
    vm.pc = 2973
    vm._jump(98)


def _stage_102(vm):
    vm.pc = 2975
    vm._jump(98)


def _stage_103(vm):
    vm.pc = 3060
    if vm.predecessor == 97:
        value = vm.cells.value(26)
    elif vm.predecessor == 104:
        value = vm.cells.value(454)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(453, value, 8, 'L9.phi_q')
    vm.pc = 3065
    vm._write(455, int(vm.cells.value(453) < vm.cells.value(452)), 4, 'once18.unsigned_q')
    vm.pc = 3069
    vm._jump(104 if vm.cells.value(455) != 0 else 105)


def _stage_104(vm):
    _indexed_pointer(vm, 3071, 456, 1, 450, (453,))
    vm.pc = 3083
    vm.cells.copy_q_clear_owned(456, 457)
    vm.pc = 3087
    vm._write(458, vm.memory.load(vm.cells.value(457), 4), 4, 'high.load')
    _indexed_pointer(vm, 3087, 459, 1, 449, (453,))
    vm.pc = 3099
    vm.cells.copy_q_clear_owned(459, 460)
    _store_cell(vm, 3099, 4, 458, 460)
    vm.pc = 3104
    vm.pc = 3107
    vm.auxiliary = (0, 366854146)
    vm.pc = 3112
    vm._write(454, vm._signed_cell(453, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 3114
    vm._jump(103)


def _stage_105(vm):
    vm.pc = 3071
    vm._jump(106)


def _stage_106(vm):
    vm.pc = 3121
    if vm.predecessor == 105:
        value = vm.cells.value(452)
    elif vm.predecessor == 107:
        value = vm.cells.value(462)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(461, value, 8, 'L9.phi_q')
    vm.pc = 3126
    vm._write(463, int(vm.cells.value(461) < vm.cells.value(451)), 4, 'once18.unsigned_q')
    vm.pc = 3130
    vm._jump(107 if vm.cells.value(463) != 0 else 108)


def _stage_107(vm):
    _indexed_pointer(vm, 3141, 465, 1, 450, (461,))
    vm.pc = 3152
    vm._write(466, vm.memory.load(vm.cells.value(465), 1), 4, 'high.load')
    _indexed_pointer(vm, 3152, 467, 1, 449, (461,))
    _store_cell(vm, 3159, 1, 466, 467)
    vm.pc = 3164
    vm.pc = 3167
    vm.auxiliary = (0, 1410629634)
    vm.pc = 3172
    vm._write(462, vm._signed_cell(461, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 3174
    vm._jump(106)


def _stage_108(vm):
    vm.pc = 3131
    vm.pc = 3134
    vm.auxiliary = (0, 2014330881)
    vm.pc = 3139
    vm._write(464, vm._signed_cell(447, 3) + vm._signed_cell(416, 3), 8, 'once1.integer')
    vm.pc = 3141
    vm._jump(95)


def _stage_109(vm):
    vm.pc = 3399
    vm.pc = 3402
    vm.auxiliary = (0, 1416015873)
    vm.pc = 3407
    vm._write(472, vm._signed_cell(471, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 3409
    vm._jump(66)


def _stage_110(vm):
    vm.pc = 3235
    vm.cells.copy_q_clear_owned(471, 474)
    _indexed_pointer(vm, 3235, 475, 9, 5, (26, 474))
    _indexed_pointer(vm, 3243, 476, 8, 475, (22, 22))
    _store_cell(vm, 3251, 4, 22, 476)
    _indexed_pointer(vm, 3255, 477, 8, 475, (22, 70))
    vm.pc = 3267
    vm._write(478, vm.memory.load(vm.cells.value(477), 8), 8, 'high.load')
    vm.pc = 3268
    vm.pc = 3271
    vm.auxiliary = (0, 832702740)
    vm.pc = 3276
    vm._write(479, int(vm._signed_cell(478, 2) != vm._signed_cell(71, 2)), 4, 'L30.comparison')
    vm.pc = 3280
    vm._jump(113 if vm.cells.value(479) != 0 else 109)


def _stage_111(vm):
    vm.pc = 3230
    vm._jump(112)


def _stage_112(vm):
    vm.pc = 3416
    if vm.predecessor == 111:
        value = vm.cells.value(22)
    elif vm.predecessor == 121:
        value = vm.cells.value(496)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(495, value, 8, 'L9.phi_q')
    vm.pc = 3417
    vm.pc = 3420
    vm.auxiliary = (0, 778189781)
    vm.pc = 3425
    a = vm._signed_cell(495, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(304, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(497, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 3429
    vm._jump(122 if vm.cells.value(497) != 0 else 123)


def _stage_113(vm):
    _indexed_pointer(vm, 3280, 480, 8, 475, (22, 80))
    vm.pc = 3292
    vm._write(481, vm.memory.load(vm.cells.value(480), 4), 4, 'high.load')
    vm.pc = 3297
    vm._write(482, int(vm.cells.value(481) > vm.cells.value(22)), 4, 'L31.comparison')
    vm.pc = 3301
    vm._jump(114 if vm.cells.value(482) != 0 else 109)


def _stage_114(vm):
    vm.pc = 3306
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(483, vm.cells.value(481), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 3311
    vm._write(485, vm._signed_cell(483, 27) & vm._signed_cell(484, 27), 8, 'L13.binary_q')
    vm.pc = 3313
    vm._jump(115)


def _stage_115(vm):
    vm.pc = 3320
    if vm.predecessor == 114:
        value = vm.cells.value(26)
    elif vm.predecessor == 116:
        value = vm.cells.value(487)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(486, value, 8, 'L9.phi_q')
    vm.pc = 3325
    vm._write(488, int(vm.cells.value(486) < vm.cells.value(485)), 4, 'once18.unsigned_q')
    vm.pc = 3329
    vm._jump(116 if vm.cells.value(488) != 0 else 117)


def _stage_116(vm):
    _indexed_pointer(vm, 3331, 489, 1, 478, (486,))
    vm.pc = 3343
    vm.cells.copy_q_clear_owned(489, 490)
    _store_cell(vm, 3343, 4, 22, 490)
    vm.pc = 3348
    vm.pc = 3351
    vm.auxiliary = (0, 1060532225)
    vm.pc = 3356
    vm._write(487, vm._signed_cell(486, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 3358
    vm._jump(115)


def _stage_117(vm):
    vm.pc = 3331
    vm._jump(118)


def _stage_118(vm):
    vm.pc = 3365
    if vm.predecessor == 117:
        value = vm.cells.value(485)
    elif vm.predecessor == 119:
        value = vm.cells.value(492)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(491, value, 8, 'L9.phi_q')
    vm.pc = 3370
    vm._write(493, int(vm.cells.value(491) < vm.cells.value(483)), 4, 'once18.unsigned_q')
    vm.pc = 3374
    vm._jump(119 if vm.cells.value(493) != 0 else 120)


def _stage_119(vm):
    _indexed_pointer(vm, 3376, 494, 1, 478, (491,))
    _store_cell(vm, 3383, 1, 111, 494)
    vm.pc = 3388
    vm.pc = 3391
    vm.auxiliary = (0, 1363324929)
    vm.pc = 3396
    vm._write(492, vm._signed_cell(491, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 3398
    vm._jump(118)


def _stage_120(vm):
    vm.pc = 3376
    vm._jump(109)


def _stage_121(vm):
    vm.pc = 3532
    vm.pc = 3535
    vm.auxiliary = (0, 1420595201)
    vm.pc = 3540
    vm._write(496, vm._signed_cell(495, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 3542
    vm._jump(112)


def _stage_122(vm):
    vm.pc = 3490
    vm.cells.copy_q_clear_owned(495, 509)
    _indexed_pointer(vm, 3490, 510, 9, 5, (26, 509))
    _indexed_pointer(vm, 3498, 511, 8, 510, (22, 70))
    vm.pc = 3510
    vm._write(512, vm.memory.load(vm.cells.value(511), 8), 8, 'high.load')
    vm.pc = 3511
    vm.pc = 3514
    vm.auxiliary = (0, 394427348)
    vm.pc = 3519
    vm._write(513, int(vm._signed_cell(512, 2) != vm._signed_cell(71, 2)), 4, 'L30.comparison')
    vm.pc = 3523
    vm._jump(125 if vm.cells.value(513) != 0 else 121)


def _stage_123(vm):
    _native_call(vm, 3429, 3436, 71, 499, (41,), 498)
    vm.pc = 3441
    vm.cells.copy_q_clear_owned(498, 500)
    vm.pc = 3446
    vm._write(501, vm.cells.value(500) & 4294967295, 8, 'once9.mask_q')
    vm.pc = 3450
    vm._write(502, vm.memory.load(vm.cells.value(4), 4), 4, 'high.load')
    vm.pc = 3451
    vm.pc = 3454
    vm.auxiliary = (0, 1219624962)
    vm.pc = 3459
    vm._write(503, vm._signed_cell(501, 3) + vm._signed_cell(502, 3), 8, 'once1.integer')
    vm.pc = 3462
    vm.auxiliary = (0, 5476)
    vm.pc = 3467
    value = vm._signed_cell(503, 3) & vm._signed_cell(504, 3)
    vm._write(505, value, 8, 'typed.selector1.q')
    vm.pc = 3472
    vm._write(506, vm.cells.value(505) & 255, 8, 'once9.mask_q')
    _native_call(vm, 3472, 3478, 73, 507, (498,))
    vm.pc = 3483
    vm.cells.copy_q_clear_owned(12, 508)
    vm.pc = 3485
    vm._jump(124)


def _stage_124(vm):
    vm.pc = 3549
    if vm.predecessor == 123:
        value = vm.cells.value(22)
    elif vm.predecessor == 126:
        value = vm.cells.value(515)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(514, value, 8, 'L9.phi_q')
    vm.pc = 3550
    vm.pc = 3553
    vm.auxiliary = (0, 1601311285)
    vm.pc = 3558
    a = vm._signed_cell(514, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(121, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(516, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 3562
    vm._jump(126 if vm.cells.value(516) != 0 else 127)


def _stage_125(vm):
    _native_call(vm, 3523, 3529, 73, 507, (512,))
    vm.pc = 3531
    vm._jump(121)


def _stage_126(vm):
    vm.pc = 3762
    vm.cells.copy_q_clear_owned(514, 552)
    _indexed_pointer(vm, 3762, 553, 11, 6, (26, 552))
    vm.pc = 3774
    vm._write(554, vm.memory.load(vm.cells.value(553), 1), 4, 'high.load')
    vm.pc = 3779
    vm._write(555, vm.memory.load(vm.cells.pointer(554), 4), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 3784
    vm.cells.copy_q_clear_owned(506, 556)
    vm.pc = 3785
    vm.pc = 3788
    vm.auxiliary = (0, 47421)
    vm.pc = 3794
    vm._write(557, vm._signed_cell(555, 3) ^ vm._signed_cell(556, 3), 8, 'high.flag1_xor_q')
    vm.pc = 3799
    vm._write(558, vm.cells.value(557) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 3799, 559, 11, 12, (26, 552))
    _store_cell(vm, 3807, 1, 558, 559)
    vm.pc = 3814
    vm.auxiliary = (0, 1321172994)
    vm.pc = 3819
    vm._write(515, vm._signed_cell(514, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 3821
    vm._jump(124)


def _stage_127(vm):
    vm.pc = 3567
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(517, vm.cells.value(310), 8, 'once10.first_type_zeroextend_or_q')
    _native_call(vm, 3567, 3574, 71, 499, (517,), 518)
    vm.pc = 3579
    vm.cells.copy_q_clear_owned(13, 519)
    _indexed_pointer(vm, 3579, 520, 20, 13, (22, 22))
    _indexed_pointer(vm, 3587, 521, 19, 520, (26, 57))
    _store_cell(vm, 3595, 4, 522, 521)
    _indexed_pointer(vm, 3599, 523, 19, 520, (26, 260))
    _store_cell(vm, 3607, 4, 524, 523)
    _indexed_pointer(vm, 3611, 525, 19, 520, (26, 262))
    _store_cell(vm, 3619, 4, 526, 525)
    _indexed_pointer(vm, 3623, 527, 19, 520, (26, 41))
    _store_cell(vm, 3631, 4, 528, 527)
    _indexed_pointer(vm, 3635, 529, 19, 520, (26, 530))
    _store_cell(vm, 3643, 4, 531, 529)
    _indexed_pointer(vm, 3647, 532, 19, 520, (26, 533))
    _store_cell(vm, 3655, 4, 524, 532)
    _indexed_pointer(vm, 3659, 534, 19, 520, (26, 535))
    _store_cell(vm, 3667, 4, 522, 534)
    _indexed_pointer(vm, 3671, 536, 19, 520, (26, 537))
    _store_cell(vm, 3679, 4, 528, 536)
    _indexed_pointer(vm, 3683, 538, 19, 520, (26, 26))
    _store_cell(vm, 3691, 4, 539, 538)
    _indexed_pointer(vm, 3695, 540, 19, 520, (26, 541))
    _store_cell(vm, 3703, 4, 542, 540)
    _indexed_pointer(vm, 3707, 543, 19, 520, (26, 544))
    _store_cell(vm, 3715, 4, 545, 543)
    _indexed_pointer(vm, 3719, 546, 19, 520, (26, 547))
    _store_cell(vm, 3727, 4, 548, 546)
    _indexed_pointer(vm, 3731, 549, 11, 12, (26, 26))
    vm.pc = 3744
    vm.cells.copy_q_clear_owned(14, 550)
    vm.pc = 3745
    vm.pc = 3748
    vm.auxiliary = (0, 1651698148)
    vm.pc = 3753
    vm._write(551, int(vm._signed_cell(310, 3) != vm._signed_cell(22, 3)), 4, 'L30.comparison')
    vm.pc = 3757
    vm._jump(128 if vm.cells.value(551) != 0 else 129)


def _stage_128(vm):
    vm.pc = 3853
    vm.cells.copy_q_clear_owned(549, 565)
    vm.pc = 3857
    vm._write(566, vm.memory.load(vm.cells.value(565), 4), 4, 'high.load')
    _indexed_pointer(vm, 3857, 567, 19, 520, (26, 568))
    _store_cell(vm, 3865, 4, 566, 567)
    _indexed_pointer(vm, 3869, 569, 19, 520, (26, 570))
    _store_cell(vm, 3877, 4, 571, 569)
    _indexed_pointer(vm, 3881, 572, 19, 520, (26, 573))
    _store_cell(vm, 3889, 4, 22, 572)
    _indexed_pointer(vm, 3893, 574, 19, 520, (26, 575))
    _store_cell(vm, 3901, 4, 22, 574)
    vm.pc = 3907
    vm._jump(131)


def _stage_129(vm):
    _indexed_pointer(vm, 3821, 560, 22, 14, (26, 26))
    _indexed_pointer(vm, 3829, 561, 75, 562, (26, 26))
    _native_call(vm, 3837, 3846, 77, 564, (560, 561, 26), 563)
    vm.pc = 3848
    vm._jump(130)


def _stage_130(vm):
    vm.pc = 6159
    if vm.predecessor == 151:
        value = vm.cells.value(22)
    elif vm.predecessor == 129:
        value = vm.cells.value(906)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(905, value, 8, 'L9.phi_q')
    vm.pc = 6160
    vm.pc = 6163
    vm.auxiliary = (0, 355524610)
    vm.pc = 6168
    vm._write(907, vm._signed_cell(121, 3) + vm._signed_cell(310, 3), 8, 'once1.integer')
    vm.pc = 6173
    vm.memory.load(vm.image_base + 0x677E1B4, 4)
    vm.memory.load(vm.image_base + 0x677E1B8, 4)
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA1CC')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA241')
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('once10 current-global reload loop at35DA076')
    vm._write(908, vm.cells.value(907), 8, 'once10.first_type_zeroextend_or_q')
    _native_call(vm, 6173, 6180, 71, 499, (908,), 909)
    vm.pc = 6182
    vm._jump(154)


def _stage_131(vm):
    vm.pc = 3914
    if vm.predecessor == 128:
        value = vm.cells.value(307)
    elif vm.predecessor == 132:
        value = vm.cells.value(577)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(576, value, 8, 'L9.phi_q')
    vm.pc = 3921
    if vm.predecessor == 128:
        value = vm.cells.value(518)
    elif vm.predecessor == 132:
        value = vm.cells.value(579)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(578, value, 8, 'L9.phi_q')
    vm.pc = 3928
    if vm.predecessor == 128:
        value = vm.cells.value(310)
    elif vm.predecessor == 132:
        value = vm.cells.value(581)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(580, value, 8, 'L9.phi_q')
    _indexed_pointer(vm, 3928, 582, 22, 14, (26, 26))
    vm.pc = 3941
    vm.cells.copy_q_clear_owned(15, 583)
    _native_call(vm, 3941, 3950, 28, 21, (583, 22, 585), 584)
    vm.pc = 3952
    vm._jump(133)


def _stage_132(vm):
    vm.pc = 6058
    vm.pc = 6061
    vm.auxiliary = (0, 5936)
    vm.pc = 6066
    value = vm._signed_cell(580, 3) - vm._signed_cell(877, 3)
    vm._write(581, value, 8, 'typed.selector0.q')
    _indexed_pointer(vm, 6066, 579, 1, 578, (585,))
    _indexed_pointer(vm, 6073, 577, 1, 576, (585,))
    vm.pc = 6082
    vm._jump(131)


def _stage_133(vm):
    vm.pc = 3959
    if vm.predecessor == 131:
        value = vm.cells.value(22)
    elif vm.predecessor == 134:
        value = vm.cells.value(587)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(586, value, 8, 'L9.phi_q')
    vm.pc = 3960
    vm.pc = 3963
    vm.auxiliary = (0, 1342350069)
    vm.pc = 3968
    a = vm._signed_cell(586, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(121, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(588, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 3972
    vm._jump(134 if vm.cells.value(588) != 0 else 135)


def _stage_134(vm):
    vm.pc = 3979
    vm.cells.copy_q_clear_owned(586, 589)
    _indexed_pointer(vm, 3979, 590, 3, 538, (589,))
    vm.pc = 3990
    vm._write(591, vm.memory.load(vm.cells.value(590), 4), 4, 'high.load')
    _indexed_pointer(vm, 3990, 592, 19, 15, (26, 589))
    _store_cell(vm, 3998, 4, 591, 592)
    vm.pc = 4003
    vm.pc = 4006
    vm.auxiliary = (0, 867377154)
    vm.pc = 4011
    vm._write(587, vm._signed_cell(586, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 4013
    vm._jump(133)


def _stage_135(vm):
    vm.pc = 3974
    vm._jump(136)


def _stage_136(vm):
    vm.pc = 4020
    if vm.predecessor == 135:
        value = vm.cells.value(594)
    elif vm.predecessor == 137:
        value = vm.cells.value(595)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(593, value, 8, 'L9.phi_q')
    vm.pc = 4021
    vm.pc = 4024
    vm.auxiliary = (0, 244509030)
    vm.pc = 4029
    vm._write(596, int(vm._signed_cell(593, 3) > vm._signed_cell(22, 3)), 4, 'L25.comparison')
    vm.pc = 4033
    vm._jump(137 if vm.cells.value(596) != 0 else 138)


def _stage_137(vm):
    _indexed_pointer(vm, 4035, 597, 19, 15, (26, 260))
    vm.pc = 4047
    vm._write(598, vm.memory.load(vm.cells.value(597), 4), 4, 'high.load')
    _indexed_pointer(vm, 4047, 599, 19, 15, (26, 262))
    vm.pc = 4059
    vm._write(600, vm.memory.load(vm.cells.value(599), 4), 4, 'high.load')
    _indexed_pointer(vm, 4059, 601, 19, 15, (26, 26))
    vm.pc = 4071
    vm._write(602, vm.memory.load(vm.cells.value(601), 4), 4, 'high.load')
    vm.pc = 4072
    vm.pc = 4075
    vm.auxiliary = (0, 1323921409)
    vm.pc = 4080
    vm._write(603, vm._signed_cell(600, 3) + vm._signed_cell(602, 3), 8, 'once1.integer')
    vm.pc = 4083
    vm.auxiliary = (0, 38389)
    vm.pc = 4084
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4088
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(603, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(604, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4092
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4093
    a = vm.memory.load(vm.cells.pointer(603), 4)
    count = vm.memory.load(vm.cells.pointer(605), 1)
    vm._write(606, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4096
    vm.auxiliary = (0, 37521)
    vm.pc = 4101
    value = vm._signed_cell(604, 3) | vm._signed_cell(606, 3)
    vm._write(607, value, 8, 'typed.selector2.q')
    vm.pc = 4104
    vm.auxiliary = (0, 15189)
    vm.pc = 4110
    vm._write(608, vm._signed_cell(598, 3) ^ vm._signed_cell(607, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4110, 4, 608, 597)
    _indexed_pointer(vm, 4114, 609, 19, 15, (26, 57))
    vm.pc = 4126
    vm._write(610, vm.memory.load(vm.cells.value(609), 4), 4, 'high.load')
    vm.pc = 4130
    vm._write(611, vm.memory.load(vm.cells.value(599), 4), 4, 'high.load')
    vm.pc = 4133
    vm.auxiliary = (0, 2126508034)
    vm.pc = 4138
    vm._write(612, vm._signed_cell(608, 3) + vm._signed_cell(611, 3), 8, 'once1.integer')
    vm.pc = 4141
    vm.auxiliary = (0, 25845)
    vm.pc = 4142
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4146
    count = vm.memory.load(vm.cells.pointer(613), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(612, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(614, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4150
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4151
    a = vm.memory.load(vm.cells.pointer(612), 4)
    count = vm.memory.load(vm.cells.pointer(615), 1)
    vm._write(616, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4156
    vm._write(617, vm._signed_cell(614, 3) | vm._signed_cell(616, 3), 8, 'L15.binary_q')
    vm.pc = 4159
    vm.auxiliary = (0, 27957)
    vm.pc = 4165
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(610, 3) ^ vm._signed_cell(617, 3)
    vm._write(618, value, 8, 'typed.selector5.q')
    _store_cell(vm, 4165, 4, 618, 609)
    vm.pc = 4173
    vm._write(619, vm.memory.load(vm.cells.value(601), 4), 4, 'high.load')
    vm.pc = 4177
    vm._write(620, vm.memory.load(vm.cells.value(597), 4), 4, 'high.load')
    vm.pc = 4180
    vm.auxiliary = (0, 1822117890)
    vm.pc = 4185
    vm._write(621, vm._signed_cell(618, 3) + vm._signed_cell(620, 3), 8, 'once1.integer')
    vm.pc = 4188
    vm.auxiliary = (0, 5116)
    vm.pc = 4189
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4193
    count = vm.memory.load(vm.cells.pointer(622), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(621, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(623, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4197
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4198
    a = vm.memory.load(vm.cells.pointer(621), 4)
    count = vm.memory.load(vm.cells.pointer(624), 1)
    vm._write(625, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4201
    vm.auxiliary = (0, 25802)
    vm.pc = 4206
    value = vm._signed_cell(623, 3) | vm._signed_cell(625, 3)
    vm._write(626, value, 8, 'typed.selector2.q')
    vm.pc = 4209
    vm.auxiliary = (0, 36469)
    vm.pc = 4215
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(619, 3) ^ vm._signed_cell(626, 3)
    vm._write(627, value, 8, 'typed.selector5.q')
    _store_cell(vm, 4215, 4, 627, 601)
    vm.pc = 4223
    vm._write(628, vm.memory.load(vm.cells.value(599), 4), 4, 'high.load')
    vm.pc = 4227
    vm._write(629, vm.memory.load(vm.cells.value(609), 4), 4, 'high.load')
    vm.pc = 4230
    vm.auxiliary = (0, 1268129793)
    vm.pc = 4235
    vm._write(630, vm._signed_cell(627, 3) + vm._signed_cell(629, 3), 8, 'once1.integer')
    vm.pc = 4238
    vm.auxiliary = (0, 5335)
    vm.pc = 4239
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4243
    count = vm.memory.load(vm.cells.pointer(631), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(630, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(632, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4247
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4248
    a = vm.memory.load(vm.cells.pointer(630), 4)
    count = vm.memory.load(vm.cells.pointer(633), 1)
    vm._write(634, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4251
    vm.auxiliary = (0, 8882)
    vm.pc = 4256
    value = vm._signed_cell(632, 3) | vm._signed_cell(634, 3)
    vm._write(635, value, 8, 'typed.selector2.q')
    vm.pc = 4259
    vm.auxiliary = (0, 23621)
    vm.pc = 4265
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(628, 3) ^ vm._signed_cell(635, 3)
    vm._write(636, value, 8, 'typed.selector5.q')
    _store_cell(vm, 4265, 4, 636, 599)
    _indexed_pointer(vm, 4269, 637, 19, 15, (26, 541))
    vm.pc = 4281
    vm._write(638, vm.memory.load(vm.cells.value(637), 4), 4, 'high.load')
    _indexed_pointer(vm, 4281, 639, 19, 15, (26, 568))
    vm.pc = 4293
    vm._write(640, vm.memory.load(vm.cells.value(639), 4), 4, 'high.load')
    _indexed_pointer(vm, 4293, 641, 19, 15, (26, 570))
    vm.pc = 4305
    vm._write(642, vm.memory.load(vm.cells.value(641), 4), 4, 'high.load')
    vm.pc = 4308
    vm.auxiliary = (0, 1367355393)
    vm.pc = 4313
    vm._write(643, vm._signed_cell(640, 3) + vm._signed_cell(642, 3), 8, 'once1.integer')
    vm.pc = 4316
    vm.auxiliary = (0, 17605)
    vm.pc = 4317
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4321
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(643, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(644, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4325
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4326
    a = vm.memory.load(vm.cells.pointer(643), 4)
    count = vm.memory.load(vm.cells.pointer(605), 1)
    vm._write(645, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4329
    vm.auxiliary = (0, 8657)
    vm.pc = 4334
    value = vm._signed_cell(644, 3) | vm._signed_cell(645, 3)
    vm._write(646, value, 8, 'typed.selector2.q')
    vm.pc = 4337
    vm.auxiliary = (0, 11071)
    vm.pc = 4343
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(638, 3) ^ vm._signed_cell(646, 3)
    vm._write(647, value, 8, 'typed.selector5.q')
    _store_cell(vm, 4343, 4, 647, 637)
    _indexed_pointer(vm, 4347, 648, 19, 15, (26, 41))
    vm.pc = 4359
    vm._write(649, vm.memory.load(vm.cells.value(648), 4), 4, 'high.load')
    vm.pc = 4363
    vm._write(650, vm.memory.load(vm.cells.value(639), 4), 4, 'high.load')
    vm.pc = 4366
    vm.auxiliary = (0, 1863176193)
    vm.pc = 4371
    vm._write(651, vm._signed_cell(647, 3) + vm._signed_cell(650, 3), 8, 'once1.integer')
    vm.pc = 4374
    vm.auxiliary = (0, 41861)
    vm.pc = 4375
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4379
    count = vm.memory.load(vm.cells.pointer(613), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(651, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(652, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4383
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4384
    a = vm.memory.load(vm.cells.pointer(651), 4)
    count = vm.memory.load(vm.cells.pointer(615), 1)
    vm._write(653, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4387
    vm.auxiliary = (0, 8339)
    vm.pc = 4392
    value = vm._signed_cell(652, 3) | vm._signed_cell(653, 3)
    vm._write(654, value, 8, 'typed.selector2.q')
    vm.pc = 4395
    vm.auxiliary = (0, 11621)
    vm.pc = 4401
    vm._write(655, vm._signed_cell(649, 3) ^ vm._signed_cell(654, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4401, 4, 655, 648)
    vm.pc = 4409
    vm._write(656, vm.memory.load(vm.cells.value(641), 4), 4, 'high.load')
    vm.pc = 4413
    vm._write(657, vm.memory.load(vm.cells.value(637), 4), 4, 'high.load')
    vm.pc = 4416
    vm.auxiliary = (0, 1460658177)
    vm.pc = 4421
    vm._write(658, vm._signed_cell(655, 3) + vm._signed_cell(657, 3), 8, 'once1.integer')
    vm.pc = 4424
    vm.auxiliary = (0, 45556)
    vm.pc = 4425
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4429
    count = vm.memory.load(vm.cells.pointer(622), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(658, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(659, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4433
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4434
    a = vm.memory.load(vm.cells.pointer(658), 4)
    count = vm.memory.load(vm.cells.pointer(624), 1)
    vm._write(660, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4439
    vm._write(661, vm._signed_cell(659, 3) | vm._signed_cell(660, 3), 8, 'L15.binary_q')
    vm.pc = 4442
    vm.auxiliary = (0, 15935)
    vm.pc = 4448
    vm._write(662, vm._signed_cell(656, 3) ^ vm._signed_cell(661, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4448, 4, 662, 641)
    vm.pc = 4456
    vm._write(663, vm.memory.load(vm.cells.value(639), 4), 4, 'high.load')
    vm.pc = 4460
    vm._write(664, vm.memory.load(vm.cells.value(648), 4), 4, 'high.load')
    vm.pc = 4463
    vm.auxiliary = (0, 1867735041)
    vm.pc = 4468
    vm._write(665, vm._signed_cell(662, 3) + vm._signed_cell(664, 3), 8, 'once1.integer')
    vm.pc = 4471
    vm.auxiliary = (0, 61902)
    vm.pc = 4472
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4476
    count = vm.memory.load(vm.cells.pointer(631), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(665, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(666, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4480
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4481
    a = vm.memory.load(vm.cells.pointer(665), 4)
    count = vm.memory.load(vm.cells.pointer(633), 1)
    vm._write(667, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4484
    vm.auxiliary = (0, 14256)
    vm.pc = 4489
    value = vm._signed_cell(666, 3) | vm._signed_cell(667, 3)
    vm._write(668, value, 8, 'typed.selector2.q')
    vm.pc = 4492
    vm.auxiliary = (0, 40295)
    vm.pc = 4498
    vm._write(669, vm._signed_cell(663, 3) ^ vm._signed_cell(668, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4498, 4, 669, 639)
    _indexed_pointer(vm, 4502, 670, 19, 15, (26, 573))
    vm.pc = 4514
    vm._write(671, vm.memory.load(vm.cells.value(670), 4), 4, 'high.load')
    _indexed_pointer(vm, 4514, 672, 19, 15, (26, 575))
    vm.pc = 4526
    vm._write(673, vm.memory.load(vm.cells.value(672), 4), 4, 'high.load')
    _indexed_pointer(vm, 4526, 674, 19, 15, (26, 544))
    vm.pc = 4538
    vm._write(675, vm.memory.load(vm.cells.value(674), 4), 4, 'high.load')
    vm.pc = 4541
    vm.auxiliary = (0, 863809538)
    vm.pc = 4546
    vm._write(676, vm._signed_cell(673, 3) + vm._signed_cell(675, 3), 8, 'once1.integer')
    vm.pc = 4549
    vm.auxiliary = (0, 42423)
    vm.pc = 4550
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4554
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(676, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(677, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4558
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4559
    a = vm.memory.load(vm.cells.pointer(676), 4)
    count = vm.memory.load(vm.cells.pointer(605), 1)
    vm._write(678, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4562
    vm.auxiliary = (0, 33419)
    vm.pc = 4567
    value = vm._signed_cell(677, 3) | vm._signed_cell(678, 3)
    vm._write(679, value, 8, 'typed.selector2.q')
    vm.pc = 4570
    vm.auxiliary = (0, 11391)
    vm.pc = 4576
    vm._write(680, vm._signed_cell(671, 3) ^ vm._signed_cell(679, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4576, 4, 680, 670)
    _indexed_pointer(vm, 4580, 681, 19, 15, (26, 530))
    vm.pc = 4592
    vm._write(682, vm.memory.load(vm.cells.value(681), 4), 4, 'high.load')
    vm.pc = 4596
    vm._write(683, vm.memory.load(vm.cells.value(672), 4), 4, 'high.load')
    vm.pc = 4599
    vm.auxiliary = (0, 1219338241)
    vm.pc = 4604
    vm._write(684, vm._signed_cell(680, 3) + vm._signed_cell(683, 3), 8, 'once1.integer')
    vm.pc = 4607
    vm.auxiliary = (0, 20661)
    vm.pc = 4608
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4612
    count = vm.memory.load(vm.cells.pointer(613), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(684, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(685, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4616
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4617
    a = vm.memory.load(vm.cells.pointer(684), 4)
    count = vm.memory.load(vm.cells.pointer(615), 1)
    vm._write(686, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4620
    vm.auxiliary = (0, 46768)
    vm.pc = 4625
    value = vm._signed_cell(685, 3) | vm._signed_cell(686, 3)
    vm._write(687, value, 8, 'typed.selector2.q')
    vm.pc = 4630
    vm._write(688, vm._signed_cell(682, 3) ^ vm._signed_cell(687, 3), 8, 'L14.binary_q')
    _store_cell(vm, 4630, 4, 688, 681)
    vm.pc = 4638
    vm._write(689, vm.memory.load(vm.cells.value(674), 4), 4, 'high.load')
    vm.pc = 4642
    vm._write(690, vm.memory.load(vm.cells.value(670), 4), 4, 'high.load')
    vm.pc = 4645
    vm.auxiliary = (0, 1423384578)
    vm.pc = 4650
    vm._write(691, vm._signed_cell(688, 3) + vm._signed_cell(690, 3), 8, 'once1.integer')
    vm.pc = 4653
    vm.auxiliary = (0, 61575)
    vm.pc = 4654
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4658
    count = vm.memory.load(vm.cells.pointer(622), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(691, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(692, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4662
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4663
    a = vm.memory.load(vm.cells.pointer(691), 4)
    count = vm.memory.load(vm.cells.pointer(624), 1)
    vm._write(693, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4666
    vm.auxiliary = (0, 33995)
    vm.pc = 4671
    value = vm._signed_cell(692, 3) | vm._signed_cell(693, 3)
    vm._write(694, value, 8, 'typed.selector2.q')
    vm.pc = 4674
    vm.auxiliary = (0, 39725)
    vm.pc = 4680
    vm._write(695, vm._signed_cell(689, 3) ^ vm._signed_cell(694, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4680, 4, 695, 674)
    vm.pc = 4688
    vm._write(696, vm.memory.load(vm.cells.value(672), 4), 4, 'high.load')
    vm.pc = 4692
    vm._write(697, vm.memory.load(vm.cells.value(681), 4), 4, 'high.load')
    vm.pc = 4695
    vm.auxiliary = (0, 1418133505)
    vm.pc = 4700
    vm._write(698, vm._signed_cell(695, 3) + vm._signed_cell(697, 3), 8, 'once1.integer')
    vm.pc = 4703
    vm.auxiliary = (0, 22454)
    vm.pc = 4704
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4708
    count = vm.memory.load(vm.cells.pointer(631), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(698, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(699, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4712
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4713
    a = vm.memory.load(vm.cells.pointer(698), 4)
    count = vm.memory.load(vm.cells.pointer(633), 1)
    vm._write(700, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4716
    vm.auxiliary = (0, 37267)
    vm.pc = 4721
    value = vm._signed_cell(699, 3) | vm._signed_cell(700, 3)
    vm._write(701, value, 8, 'typed.selector2.q')
    vm.pc = 4724
    vm.auxiliary = (0, 51548)
    vm.pc = 4730
    vm._write(702, vm._signed_cell(696, 3) ^ vm._signed_cell(701, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4730, 4, 702, 672)
    _indexed_pointer(vm, 4734, 703, 19, 15, (26, 547))
    vm.pc = 4746
    vm._write(704, vm.memory.load(vm.cells.value(703), 4), 4, 'high.load')
    _indexed_pointer(vm, 4746, 705, 19, 15, (26, 533))
    vm.pc = 4758
    vm._write(706, vm.memory.load(vm.cells.value(705), 4), 4, 'high.load')
    _indexed_pointer(vm, 4758, 707, 19, 15, (26, 535))
    vm.pc = 4770
    vm._write(708, vm.memory.load(vm.cells.value(707), 4), 4, 'high.load')
    vm.pc = 4773
    vm.auxiliary = (0, 864743426)
    vm.pc = 4778
    vm._write(709, vm._signed_cell(706, 3) + vm._signed_cell(708, 3), 8, 'once1.integer')
    vm.pc = 4781
    vm.auxiliary = (0, 58501)
    vm.pc = 4782
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4786
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(709, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(710, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4790
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4791
    a = vm.memory.load(vm.cells.pointer(709), 4)
    count = vm.memory.load(vm.cells.pointer(605), 1)
    vm._write(711, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4794
    vm.auxiliary = (0, 26346)
    vm.pc = 4799
    value = vm._signed_cell(710, 3) | vm._signed_cell(711, 3)
    vm._write(712, value, 8, 'typed.selector2.q')
    vm.pc = 4802
    vm.auxiliary = (0, 59717)
    vm.pc = 4808
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(704, 3) ^ vm._signed_cell(712, 3)
    vm._write(713, value, 8, 'typed.selector5.q')
    _store_cell(vm, 4808, 4, 713, 703)
    _indexed_pointer(vm, 4812, 714, 19, 15, (26, 537))
    vm.pc = 4824
    vm._write(715, vm.memory.load(vm.cells.value(714), 4), 4, 'high.load')
    vm.pc = 4828
    vm._write(716, vm.memory.load(vm.cells.value(705), 4), 4, 'high.load')
    vm.pc = 4831
    vm.auxiliary = (0, 1726103553)
    vm.pc = 4836
    vm._write(717, vm._signed_cell(713, 3) + vm._signed_cell(716, 3), 8, 'once1.integer')
    vm.pc = 4839
    vm.auxiliary = (0, 54742)
    vm.pc = 4840
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4844
    count = vm.memory.load(vm.cells.pointer(613), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(717, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(718, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4848
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4849
    a = vm.memory.load(vm.cells.pointer(717), 4)
    count = vm.memory.load(vm.cells.pointer(615), 1)
    vm._write(719, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4854
    vm._write(720, vm._signed_cell(718, 3) | vm._signed_cell(719, 3), 8, 'L15.binary_q')
    vm.pc = 4859
    vm._write(721, vm._signed_cell(715, 3) ^ vm._signed_cell(720, 3), 8, 'L14.binary_q')
    _store_cell(vm, 4859, 4, 721, 714)
    vm.pc = 4867
    vm._write(722, vm.memory.load(vm.cells.value(707), 4), 4, 'high.load')
    vm.pc = 4871
    vm._write(723, vm.memory.load(vm.cells.value(703), 4), 4, 'high.load')
    vm.pc = 4874
    vm.auxiliary = (0, 1171185665)
    vm.pc = 4879
    vm._write(724, vm._signed_cell(721, 3) + vm._signed_cell(723, 3), 8, 'once1.integer')
    vm.pc = 4882
    vm.auxiliary = (0, 41910)
    vm.pc = 4883
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4887
    count = vm.memory.load(vm.cells.pointer(622), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(724, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(725, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4891
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4892
    a = vm.memory.load(vm.cells.pointer(724), 4)
    count = vm.memory.load(vm.cells.pointer(624), 1)
    vm._write(726, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4895
    vm.auxiliary = (0, 13771)
    vm.pc = 4900
    value = vm._signed_cell(725, 3) | vm._signed_cell(726, 3)
    vm._write(727, value, 8, 'typed.selector2.q')
    vm.pc = 4903
    vm.auxiliary = (0, 64021)
    vm.pc = 4909
    vm._write(728, vm._signed_cell(722, 3) ^ vm._signed_cell(727, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4909, 4, 728, 707)
    vm.pc = 4917
    vm._write(729, vm.memory.load(vm.cells.value(705), 4), 4, 'high.load')
    vm.pc = 4921
    vm._write(730, vm.memory.load(vm.cells.value(714), 4), 4, 'high.load')
    vm.pc = 4924
    vm.auxiliary = (0, 1768284162)
    vm.pc = 4929
    vm._write(731, vm._signed_cell(728, 3) + vm._signed_cell(730, 3), 8, 'once1.integer')
    vm.pc = 4932
    vm.auxiliary = (0, 49302)
    vm.pc = 4933
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4937
    count = vm.memory.load(vm.cells.pointer(631), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(731, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(732, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4941
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4942
    a = vm.memory.load(vm.cells.pointer(731), 4)
    count = vm.memory.load(vm.cells.pointer(633), 1)
    vm._write(733, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 4945
    vm.auxiliary = (0, 13305)
    vm.pc = 4950
    value = vm._signed_cell(732, 3) | vm._signed_cell(733, 3)
    vm._write(734, value, 8, 'typed.selector2.q')
    vm.pc = 4953
    vm.auxiliary = (0, 43781)
    vm.pc = 4959
    vm._write(735, vm._signed_cell(729, 3) ^ vm._signed_cell(734, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 4959, 4, 735, 705)
    vm.pc = 4967
    vm._write(736, vm.memory.load(vm.cells.value(641), 4), 4, 'high.load')
    vm.pc = 4971
    vm._write(737, vm.memory.load(vm.cells.value(599), 4), 4, 'high.load')
    vm.pc = 4975
    vm._write(738, vm.memory.load(vm.cells.value(703), 4), 4, 'high.load')
    vm.pc = 4978
    vm.auxiliary = (0, 1515159554)
    vm.pc = 4983
    vm._write(739, vm._signed_cell(737, 3) + vm._signed_cell(738, 3), 8, 'once1.integer')
    vm.pc = 4986
    vm.auxiliary = (0, 42983)
    vm.pc = 4987
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 4991
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(739, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(740, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 4995
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 4996
    a = vm.memory.load(vm.cells.pointer(739), 4)
    count = vm.memory.load(vm.cells.pointer(605), 1)
    vm._write(741, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5001
    vm._write(742, vm._signed_cell(740, 3) | vm._signed_cell(741, 3), 8, 'L15.binary_q')
    vm.pc = 5006
    vm._write(743, vm._signed_cell(736, 3) ^ vm._signed_cell(742, 3), 8, 'L14.binary_q')
    _store_cell(vm, 5006, 4, 743, 641)
    vm.pc = 5014
    vm._write(744, vm.memory.load(vm.cells.value(681), 4), 4, 'high.load')
    vm.pc = 5018
    vm._write(745, vm.memory.load(vm.cells.value(599), 4), 4, 'high.load')
    vm.pc = 5021
    vm.auxiliary = (0, 658034690)
    vm.pc = 5026
    vm._write(746, vm._signed_cell(743, 3) + vm._signed_cell(745, 3), 8, 'once1.integer')
    vm.pc = 5029
    vm.auxiliary = (0, 18150)
    vm.pc = 5030
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5034
    count = vm.memory.load(vm.cells.pointer(613), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(746, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(747, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5038
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5039
    a = vm.memory.load(vm.cells.pointer(746), 4)
    count = vm.memory.load(vm.cells.pointer(615), 1)
    vm._write(748, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5044
    vm._write(749, vm._signed_cell(747, 3) | vm._signed_cell(748, 3), 8, 'L15.binary_q')
    vm.pc = 5049
    vm._write(750, vm._signed_cell(744, 3) ^ vm._signed_cell(749, 3), 8, 'L14.binary_q')
    _store_cell(vm, 5049, 4, 750, 681)
    vm.pc = 5057
    vm._write(751, vm.memory.load(vm.cells.value(703), 4), 4, 'high.load')
    vm.pc = 5061
    vm._write(752, vm.memory.load(vm.cells.value(641), 4), 4, 'high.load')
    vm.pc = 5064
    vm.auxiliary = (0, 1059954690)
    vm.pc = 5069
    vm._write(753, vm._signed_cell(750, 3) + vm._signed_cell(752, 3), 8, 'once1.integer')
    vm.pc = 5072
    vm.auxiliary = (0, 49622)
    vm.pc = 5073
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5077
    count = vm.memory.load(vm.cells.pointer(622), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(753, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(754, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5081
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5082
    a = vm.memory.load(vm.cells.pointer(753), 4)
    count = vm.memory.load(vm.cells.pointer(624), 1)
    vm._write(755, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5085
    vm.auxiliary = (0, 21216)
    vm.pc = 5090
    value = vm._signed_cell(754, 3) | vm._signed_cell(755, 3)
    vm._write(756, value, 8, 'typed.selector2.q')
    vm.pc = 5095
    vm._write(757, vm._signed_cell(751, 3) ^ vm._signed_cell(756, 3), 8, 'L14.binary_q')
    _store_cell(vm, 5095, 4, 757, 703)
    vm.pc = 5103
    vm._write(758, vm.memory.load(vm.cells.value(599), 4), 4, 'high.load')
    vm.pc = 5107
    vm._write(759, vm.memory.load(vm.cells.value(681), 4), 4, 'high.load')
    vm.pc = 5110
    vm.auxiliary = (0, 617947137)
    vm.pc = 5115
    vm._write(760, vm._signed_cell(757, 3) + vm._signed_cell(759, 3), 8, 'once1.integer')
    vm.pc = 5118
    vm.auxiliary = (0, 28837)
    vm.pc = 5119
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5123
    count = vm.memory.load(vm.cells.pointer(631), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(760, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(761, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5127
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5128
    a = vm.memory.load(vm.cells.pointer(760), 4)
    count = vm.memory.load(vm.cells.pointer(633), 1)
    vm._write(762, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5131
    vm.auxiliary = (0, 29161)
    vm.pc = 5136
    value = vm._signed_cell(761, 3) | vm._signed_cell(762, 3)
    vm._write(763, value, 8, 'typed.selector2.q')
    vm.pc = 5139
    vm.auxiliary = (0, 7445)
    vm.pc = 5145
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(758, 3) ^ vm._signed_cell(763, 3)
    vm._write(764, value, 8, 'typed.selector5.q')
    _store_cell(vm, 5145, 4, 764, 599)
    vm.pc = 5153
    vm._write(765, vm.memory.load(vm.cells.value(674), 4), 4, 'high.load')
    vm.pc = 5157
    vm._write(766, vm.memory.load(vm.cells.value(639), 4), 4, 'high.load')
    vm.pc = 5161
    vm._write(767, vm.memory.load(vm.cells.value(597), 4), 4, 'high.load')
    vm.pc = 5164
    vm.auxiliary = (0, 1361887233)
    vm.pc = 5169
    vm._write(768, vm._signed_cell(766, 3) + vm._signed_cell(767, 3), 8, 'once1.integer')
    vm.pc = 5172
    vm.auxiliary = (0, 50910)
    vm.pc = 5173
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5177
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(768, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(769, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5181
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5182
    a = vm.memory.load(vm.cells.pointer(768), 4)
    count = vm.memory.load(vm.cells.pointer(605), 1)
    vm._write(770, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5187
    vm._write(771, vm._signed_cell(769, 3) | vm._signed_cell(770, 3), 8, 'L15.binary_q')
    vm.pc = 5190
    vm.auxiliary = (0, 7551)
    vm.pc = 5196
    vm._write(772, vm._signed_cell(765, 3) ^ vm._signed_cell(771, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 5196, 4, 772, 674)
    vm.pc = 5204
    vm._write(773, vm.memory.load(vm.cells.value(714), 4), 4, 'high.load')
    vm.pc = 5208
    vm._write(774, vm.memory.load(vm.cells.value(639), 4), 4, 'high.load')
    vm.pc = 5211
    vm.auxiliary = (0, 1169010689)
    vm.pc = 5216
    vm._write(775, vm._signed_cell(772, 3) + vm._signed_cell(774, 3), 8, 'once1.integer')
    vm.pc = 5219
    vm.auxiliary = (0, 54236)
    vm.pc = 5220
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5224
    count = vm.memory.load(vm.cells.pointer(613), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(775, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(776, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5228
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5229
    a = vm.memory.load(vm.cells.pointer(775), 4)
    count = vm.memory.load(vm.cells.pointer(615), 1)
    vm._write(777, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5234
    vm._write(778, vm._signed_cell(776, 3) | vm._signed_cell(777, 3), 8, 'L15.binary_q')
    vm.pc = 5237
    vm.auxiliary = (0, 19988)
    vm.pc = 5243
    vm._write(779, vm._signed_cell(773, 3) ^ vm._signed_cell(778, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 5243, 4, 779, 714)
    vm.pc = 5251
    vm._write(780, vm.memory.load(vm.cells.value(597), 4), 4, 'high.load')
    vm.pc = 5255
    vm._write(781, vm.memory.load(vm.cells.value(674), 4), 4, 'high.load')
    vm.pc = 5258
    vm.auxiliary = (0, 1919016961)
    vm.pc = 5263
    vm._write(782, vm._signed_cell(779, 3) + vm._signed_cell(781, 3), 8, 'once1.integer')
    vm.pc = 5266
    vm.auxiliary = (0, 5037)
    vm.pc = 5267
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5271
    count = vm.memory.load(vm.cells.pointer(622), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(782, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(783, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5275
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5276
    a = vm.memory.load(vm.cells.pointer(782), 4)
    count = vm.memory.load(vm.cells.pointer(624), 1)
    vm._write(784, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5279
    vm.auxiliary = (0, 21643)
    vm.pc = 5284
    value = vm._signed_cell(783, 3) | vm._signed_cell(784, 3)
    vm._write(785, value, 8, 'typed.selector2.q')
    vm.pc = 5287
    vm.auxiliary = (0, 12101)
    vm.pc = 5293
    vm._write(786, vm._signed_cell(780, 3) ^ vm._signed_cell(785, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 5293, 4, 786, 597)
    vm.pc = 5301
    vm._write(787, vm.memory.load(vm.cells.value(639), 4), 4, 'high.load')
    vm.pc = 5305
    vm._write(788, vm.memory.load(vm.cells.value(714), 4), 4, 'high.load')
    vm.pc = 5308
    vm.auxiliary = (0, 2079318018)
    vm.pc = 5313
    vm._write(789, vm._signed_cell(786, 3) + vm._signed_cell(788, 3), 8, 'once1.integer')
    vm.pc = 5316
    vm.auxiliary = (0, 18317)
    vm.pc = 5317
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5321
    count = vm.memory.load(vm.cells.pointer(631), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(789, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(790, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5325
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5326
    a = vm.memory.load(vm.cells.pointer(789), 4)
    count = vm.memory.load(vm.cells.pointer(633), 1)
    vm._write(791, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5329
    vm.auxiliary = (0, 62688)
    vm.pc = 5334
    value = vm._signed_cell(790, 3) | vm._signed_cell(791, 3)
    vm._write(792, value, 8, 'typed.selector2.q')
    vm.pc = 5337
    vm.auxiliary = (0, 35149)
    vm.pc = 5343
    vm._write(793, vm._signed_cell(787, 3) ^ vm._signed_cell(792, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 5343, 4, 793, 639)
    vm.pc = 5351
    vm._write(794, vm.memory.load(vm.cells.value(707), 4), 4, 'high.load')
    vm.pc = 5355
    vm._write(795, vm.memory.load(vm.cells.value(672), 4), 4, 'high.load')
    vm.pc = 5359
    vm._write(796, vm.memory.load(vm.cells.value(637), 4), 4, 'high.load')
    vm.pc = 5362
    vm.auxiliary = (0, 1409458177)
    vm.pc = 5367
    vm._write(797, vm._signed_cell(795, 3) + vm._signed_cell(796, 3), 8, 'once1.integer')
    vm.pc = 5370
    vm.auxiliary = (0, 61662)
    vm.pc = 5371
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5375
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(797, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(798, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5379
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5380
    a = vm.memory.load(vm.cells.pointer(797), 4)
    count = vm.memory.load(vm.cells.pointer(605), 1)
    vm._write(799, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5383
    vm.auxiliary = (0, 54688)
    vm.pc = 5388
    value = vm._signed_cell(798, 3) | vm._signed_cell(799, 3)
    vm._write(800, value, 8, 'typed.selector2.q')
    vm.pc = 5391
    vm.auxiliary = (0, 32340)
    vm.pc = 5397
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(794, 3) ^ vm._signed_cell(800, 3)
    vm._write(801, value, 8, 'typed.selector5.q')
    _store_cell(vm, 5397, 4, 801, 707)
    vm.pc = 5405
    vm._write(802, vm.memory.load(vm.cells.value(609), 4), 4, 'high.load')
    vm.pc = 5409
    vm._write(803, vm.memory.load(vm.cells.value(672), 4), 4, 'high.load')
    vm.pc = 5412
    vm.auxiliary = (0, 1413267457)
    vm.pc = 5417
    vm._write(804, vm._signed_cell(801, 3) + vm._signed_cell(803, 3), 8, 'once1.integer')
    vm.pc = 5420
    vm.auxiliary = (0, 50143)
    vm.pc = 5421
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5425
    count = vm.memory.load(vm.cells.pointer(613), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(804, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(805, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5429
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5430
    a = vm.memory.load(vm.cells.pointer(804), 4)
    count = vm.memory.load(vm.cells.pointer(615), 1)
    vm._write(806, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5433
    vm.auxiliary = (0, 34216)
    vm.pc = 5438
    value = vm._signed_cell(805, 3) | vm._signed_cell(806, 3)
    vm._write(807, value, 8, 'typed.selector2.q')
    vm.pc = 5443
    vm._write(808, vm._signed_cell(802, 3) ^ vm._signed_cell(807, 3), 8, 'L14.binary_q')
    _store_cell(vm, 5443, 4, 808, 609)
    vm.pc = 5451
    vm._write(809, vm.memory.load(vm.cells.value(637), 4), 4, 'high.load')
    vm.pc = 5455
    vm._write(810, vm.memory.load(vm.cells.value(707), 4), 4, 'high.load')
    vm.pc = 5458
    vm.auxiliary = (0, 1817321474)
    vm.pc = 5463
    vm._write(811, vm._signed_cell(808, 3) + vm._signed_cell(810, 3), 8, 'once1.integer')
    vm.pc = 5466
    vm.auxiliary = (0, 4255)
    vm.pc = 5467
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5471
    count = vm.memory.load(vm.cells.pointer(622), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(811, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(812, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5475
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5476
    a = vm.memory.load(vm.cells.pointer(811), 4)
    count = vm.memory.load(vm.cells.pointer(624), 1)
    vm._write(813, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5481
    vm._write(814, vm._signed_cell(812, 3) | vm._signed_cell(813, 3), 8, 'L15.binary_q')
    vm.pc = 5486
    vm._write(815, vm._signed_cell(809, 3) ^ vm._signed_cell(814, 3), 8, 'L14.binary_q')
    _store_cell(vm, 5486, 4, 815, 637)
    vm.pc = 5494
    vm._write(816, vm.memory.load(vm.cells.value(672), 4), 4, 'high.load')
    vm.pc = 5498
    vm._write(817, vm.memory.load(vm.cells.value(609), 4), 4, 'high.load')
    vm.pc = 5501
    vm.auxiliary = (0, 566079490)
    vm.pc = 5506
    vm._write(818, vm._signed_cell(815, 3) + vm._signed_cell(817, 3), 8, 'once1.integer')
    vm.pc = 5509
    vm.auxiliary = (0, 46502)
    vm.pc = 5510
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5514
    count = vm.memory.load(vm.cells.pointer(631), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(818, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(819, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5518
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5519
    a = vm.memory.load(vm.cells.pointer(818), 4)
    count = vm.memory.load(vm.cells.pointer(633), 1)
    vm._write(820, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5524
    vm._write(821, vm._signed_cell(819, 3) | vm._signed_cell(820, 3), 8, 'L15.binary_q')
    vm.pc = 5527
    vm.auxiliary = (0, 64605)
    vm.pc = 5533
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(816, 3) ^ vm._signed_cell(821, 3)
    vm._write(822, value, 8, 'typed.selector5.q')
    _store_cell(vm, 5533, 4, 822, 672)
    vm.pc = 5541
    vm._write(823, vm.memory.load(vm.cells.value(601), 4), 4, 'high.load')
    vm.pc = 5545
    vm._write(824, vm.memory.load(vm.cells.value(705), 4), 4, 'high.load')
    vm.pc = 5549
    vm._write(825, vm.memory.load(vm.cells.value(670), 4), 4, 'high.load')
    vm.pc = 5552
    vm.auxiliary = (0, 1010958338)
    vm.pc = 5557
    vm._write(826, vm._signed_cell(824, 3) + vm._signed_cell(825, 3), 8, 'once1.integer')
    vm.pc = 5560
    vm.auxiliary = (0, 62966)
    vm.pc = 5561
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5565
    count = vm.memory.load(vm.cells.pointer(338), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(826, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(827, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5569
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5570
    a = vm.memory.load(vm.cells.pointer(826), 4)
    count = vm.memory.load(vm.cells.pointer(605), 1)
    vm._write(828, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5575
    vm._write(829, vm._signed_cell(827, 3) | vm._signed_cell(828, 3), 8, 'L15.binary_q')
    vm.pc = 5578
    vm.auxiliary = (0, 59684)
    vm.pc = 5584
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')
    value = vm._signed_cell(823, 3) ^ vm._signed_cell(829, 3)
    vm._write(830, value, 8, 'typed.selector5.q')
    _store_cell(vm, 5584, 4, 830, 601)
    vm.pc = 5592
    vm._write(831, vm.memory.load(vm.cells.value(648), 4), 4, 'high.load')
    vm.pc = 5596
    vm._write(832, vm.memory.load(vm.cells.value(705), 4), 4, 'high.load')
    vm.pc = 5599
    vm.auxiliary = (0, 720621569)
    vm.pc = 5604
    vm._write(833, vm._signed_cell(830, 3) + vm._signed_cell(832, 3), 8, 'once1.integer')
    vm.pc = 5607
    vm.auxiliary = (0, 41348)
    vm.pc = 5608
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5612
    count = vm.memory.load(vm.cells.pointer(613), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(833, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(834, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5616
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5617
    a = vm.memory.load(vm.cells.pointer(833), 4)
    count = vm.memory.load(vm.cells.pointer(615), 1)
    vm._write(835, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5620
    vm.auxiliary = (0, 17800)
    vm.pc = 5625
    value = vm._signed_cell(834, 3) | vm._signed_cell(835, 3)
    vm._write(836, value, 8, 'typed.selector2.q')
    vm.pc = 5630
    vm._write(837, vm._signed_cell(831, 3) ^ vm._signed_cell(836, 3), 8, 'L14.binary_q')
    _store_cell(vm, 5630, 4, 837, 648)
    vm.pc = 5638
    vm._write(838, vm.memory.load(vm.cells.value(670), 4), 4, 'high.load')
    vm.pc = 5642
    vm._write(839, vm.memory.load(vm.cells.value(601), 4), 4, 'high.load')
    vm.pc = 5645
    vm.auxiliary = (0, 262467585)
    vm.pc = 5650
    vm._write(840, vm._signed_cell(837, 3) + vm._signed_cell(839, 3), 8, 'once1.integer')
    vm.pc = 5653
    vm.auxiliary = (0, 8588)
    vm.pc = 5654
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5658
    count = vm.memory.load(vm.cells.pointer(622), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(840, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(841, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5662
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5663
    a = vm.memory.load(vm.cells.pointer(840), 4)
    count = vm.memory.load(vm.cells.pointer(624), 1)
    vm._write(842, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5668
    vm._write(843, vm._signed_cell(841, 3) | vm._signed_cell(842, 3), 8, 'L15.binary_q')
    vm.pc = 5673
    vm._write(844, vm._signed_cell(838, 3) ^ vm._signed_cell(843, 3), 8, 'L14.binary_q')
    _store_cell(vm, 5673, 4, 844, 670)
    vm.pc = 5681
    vm._write(845, vm.memory.load(vm.cells.value(705), 4), 4, 'high.load')
    vm.pc = 5685
    vm._write(846, vm.memory.load(vm.cells.value(648), 4), 4, 'high.load')
    vm.pc = 5688
    vm.auxiliary = (0, 1867182082)
    vm.pc = 5693
    vm._write(847, vm._signed_cell(844, 3) + vm._signed_cell(846, 3), 8, 'once1.integer')
    vm.pc = 5696
    vm.auxiliary = (0, 53388)
    vm.pc = 5697
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    vm.pc = 5701
    count = vm.memory.load(vm.cells.pointer(631), 4)
    if count & 0x80000000 or count >= 32:
        value = 0
    else:
        value = vm._signed_cell(847, 3) & 0xFFFFFFFF
        value <<= count
    vm._write(848, value, 4, 'typed.selector3.d')
    if extra:
        vm.pc = 5705
        raise PrimaryProgramLimit('type index 356101540 outside the decoded type vector')
    vm.pc = 5706
    a = vm.memory.load(vm.cells.pointer(847), 4)
    count = vm.memory.load(vm.cells.pointer(633), 1)
    vm._write(849, a >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 5711
    vm._write(850, vm._signed_cell(848, 3) | vm._signed_cell(849, 3), 8, 'L15.binary_q')
    vm.pc = 5714
    vm.auxiliary = (0, 6444)
    vm.pc = 5720
    vm._write(851, vm._signed_cell(845, 3) ^ vm._signed_cell(850, 3), 8, 'high.flag1_xor_q')
    _store_cell(vm, 5720, 4, 851, 705)
    vm.pc = 5727
    vm.auxiliary = (0, 16712)
    vm.pc = 5732
    value = vm._signed_cell(593, 3) - vm._signed_cell(80, 3)
    vm._write(595, value, 8, 'typed.selector0.q')
    vm.pc = 5734
    vm._jump(136)


def _stage_138(vm):
    vm.pc = 4035
    vm._jump(139)


def _stage_139(vm):
    vm.pc = 5741
    if vm.predecessor == 138:
        value = vm.cells.value(22)
    elif vm.predecessor == 140:
        value = vm.cells.value(853)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(852, value, 8, 'L9.phi_q')
    vm.pc = 5742
    vm.pc = 5745
    vm.auxiliary = (0, 522324229)
    vm.pc = 5750
    a = vm._signed_cell(852, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(121, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(854, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 5754
    vm._jump(140 if vm.cells.value(854) != 0 else 141)


def _stage_140(vm):
    vm.pc = 5761
    vm.cells.copy_q_clear_owned(852, 855)
    _indexed_pointer(vm, 5761, 856, 19, 15, (26, 855))
    vm.pc = 5773
    vm._write(857, vm.memory.load(vm.cells.value(856), 4), 4, 'high.load')
    _indexed_pointer(vm, 5773, 858, 3, 538, (855,))
    vm.pc = 5784
    vm._write(859, vm.memory.load(vm.cells.value(858), 4), 4, 'high.load')
    vm.pc = 5785
    vm.pc = 5788
    vm.auxiliary = (0, 1469587458)
    vm.pc = 5793
    vm._write(860, vm._signed_cell(857, 3) + vm._signed_cell(859, 3), 8, 'once1.integer')
    _store_cell(vm, 5793, 4, 860, 856)
    vm.pc = 5800
    vm.auxiliary = (0, 215601153)
    vm.pc = 5805
    vm._write(853, vm._signed_cell(852, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 5807
    vm._jump(139)


def _stage_141(vm):
    vm.pc = 5756
    vm._jump(142)


def _stage_142(vm):
    vm.pc = 5814
    if vm.predecessor == 141:
        value = vm.cells.value(22)
    elif vm.predecessor == 143:
        value = vm.cells.value(862)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(861, value, 8, 'L9.phi_q')
    vm.pc = 5815
    vm.pc = 5818
    vm.auxiliary = (0, 1698859093)
    vm.pc = 5823
    a = vm._signed_cell(861, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(121, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(863, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 5827
    vm._jump(143 if vm.cells.value(863) != 0 else 144)


def _stage_143(vm):
    vm.pc = 5861
    vm.cells.copy_q_clear_owned(861, 867)
    _indexed_pointer(vm, 5861, 868, 19, 15, (26, 867))
    vm.pc = 5873
    vm._write(869, vm.memory.load(vm.cells.value(868), 4), 4, 'high.load')
    vm.pc = 5874
    vm.pc = 5877
    vm.auxiliary = (0, 266994180)
    vm.pc = 5882
    vm._write(871, vm._signed_cell(870, 3) * vm._signed_cell(861, 3), 8, 'once0.integer')
    vm.pc = 5887
    vm.cells.copy_q_clear_owned(871, 872)
    _indexed_pointer(vm, 5887, 873, 1, 582, (872,))
    vm.pc = 5899
    vm.cells.copy_q_clear_owned(873, 874)
    _store_cell(vm, 5899, 4, 869, 874)
    vm.pc = 5906
    vm.auxiliary = (0, 558747649)
    vm.pc = 5911
    vm._write(862, vm._signed_cell(861, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 5913
    vm._jump(142)


def _stage_144(vm):
    vm.pc = 5831
    vm._write(864, vm.memory.load(vm.cells.value(572), 4), 4, 'high.load')
    vm.pc = 5832
    vm.pc = 5835
    vm.auxiliary = (0, 511959042)
    vm.pc = 5840
    vm._write(865, vm._signed_cell(864, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    _store_cell(vm, 5840, 4, 865, 572)
    vm.pc = 5847
    vm.auxiliary = (0, 420647108)
    vm.pc = 5852
    vm._write(866, int(vm._signed_cell(865, 3) != vm._signed_cell(22, 3)), 4, 'L30.comparison')
    vm.pc = 5856
    vm._jump(145 if vm.cells.value(866) != 0 else 146)


def _stage_145(vm):
    vm.pc = 5937
    vm._write(878, int(vm.cells.value(580) <= vm.cells.value(877)), 4, 'once19.unsigned_q')
    vm.pc = 5941
    vm._jump(147 if vm.cells.value(878) != 0 else 148)


def _stage_146(vm):
    vm.pc = 5917
    vm._write(875, vm.memory.load(vm.cells.value(574), 4), 4, 'high.load')
    vm.pc = 5918
    vm.pc = 5921
    vm.auxiliary = (0, 1777152002)
    vm.pc = 5926
    vm._write(876, vm._signed_cell(875, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    _store_cell(vm, 5926, 4, 876, 574)
    vm.pc = 5932
    vm._jump(145)


def _stage_147(vm):
    vm.pc = 5943
    vm._jump(149)


def _stage_148(vm):
    vm.pc = 6037
    vm._jump(152)


def _stage_149(vm):
    vm.pc = 5950
    if vm.predecessor == 147:
        value = vm.cells.value(22)
    elif vm.predecessor == 150:
        value = vm.cells.value(880)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(879, value, 8, 'L9.phi_q')
    vm.pc = 5955
    vm._write(881, int(vm.cells.value(879) < vm.cells.value(580)), 4, 'once18.unsigned_q')
    vm.pc = 5959
    vm._jump(150 if vm.cells.value(881) != 0 else 151)


def _stage_150(vm):
    vm.pc = 5966
    vm.cells.copy_q_clear_owned(879, 882)
    _indexed_pointer(vm, 5966, 883, 1, 576, (882,))
    vm.pc = 5977
    vm._write(884, vm.memory.load(vm.cells.value(883), 1), 4, 'high.load')
    vm.pc = 5982
    vm._write(885, vm.memory.load(vm.cells.pointer(884), 4), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 5982, 886, 22, 14, (26, 882))
    vm.pc = 5994
    vm._write(887, vm.memory.load(vm.cells.value(886), 1), 4, 'high.load')
    vm.pc = 5999
    vm._write(888, vm.memory.load(vm.cells.pointer(887), 4), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 6000
    vm.pc = 6003
    vm.auxiliary = (0, 10591)
    vm.pc = 6009
    vm._write(889, vm._signed_cell(885, 3) ^ vm._signed_cell(888, 3), 8, 'high.flag1_xor_q')
    vm.pc = 6014
    vm._write(890, vm.cells.value(889) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 6014, 891, 1, 578, (882,))
    _store_cell(vm, 6021, 1, 890, 891)
    vm.pc = 6028
    vm.auxiliary = (0, 1975599106)
    vm.pc = 6033
    vm._write(880, vm._signed_cell(879, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 6035
    vm._jump(149)


def _stage_151(vm):
    vm.pc = 5961
    vm._jump(130)


def _stage_152(vm):
    vm.pc = 6044
    if vm.predecessor == 148:
        value = vm.cells.value(22)
    elif vm.predecessor == 153:
        value = vm.cells.value(893)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(892, value, 8, 'L9.phi_q')
    vm.pc = 6045
    vm.pc = 6048
    vm.auxiliary = (0, 475150517)
    vm.pc = 6053
    a = vm._signed_cell(892, 3) & ((1 << 64) - 1)
    b = vm._signed_cell(877, 3) & ((1 << 64) - 1)
    difference = (a - b) & ((1 << 64) - 1)
    value = (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63)
    vm._write(894, value, 4, 'L29.n_or_v_comparison')
    vm.pc = 6057
    vm._jump(153 if vm.cells.value(894) != 0 else 132)


def _stage_153(vm):
    vm.pc = 6087
    vm.cells.copy_q_clear_owned(892, 895)
    _indexed_pointer(vm, 6087, 896, 1, 576, (895,))
    vm.pc = 6098
    vm._write(897, vm.memory.load(vm.cells.value(896), 1), 4, 'high.load')
    vm.pc = 6103
    vm._write(898, vm.memory.load(vm.cells.pointer(897), 4), 8, 'once10.first_type_zeroextend_or_q')
    _indexed_pointer(vm, 6103, 899, 22, 14, (26, 895))
    vm.pc = 6115
    vm._write(900, vm.memory.load(vm.cells.value(899), 1), 4, 'high.load')
    vm.pc = 6120
    vm._write(901, vm.memory.load(vm.cells.pointer(900), 4), 8, 'once10.first_type_zeroextend_or_q')
    vm.pc = 6125
    vm._write(902, vm._signed_cell(898, 3) ^ vm._signed_cell(901, 3), 8, 'L14.binary_q')
    vm.pc = 6130
    vm._write(903, vm.cells.value(902) & 255, 8, 'once9.mask_q')
    _indexed_pointer(vm, 6130, 904, 1, 578, (895,))
    _store_cell(vm, 6137, 1, 903, 904)
    vm.pc = 6142
    vm.pc = 6145
    vm.auxiliary = (0, 1466990594)
    vm.pc = 6150
    vm._write(893, vm._signed_cell(892, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
    vm.pc = 6152
    vm._jump(152)


def _stage_154(vm):
    vm.pc = 6189
    if vm.predecessor == 130:
        value = vm.cells.value(26)
    elif vm.predecessor == 155:
        value = vm.cells.value(911)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(910, value, 8, 'L9.phi_q')
    vm.pc = 6194
    vm._write(912, int(vm.cells.value(910) < vm.cells.value(48)), 4, 'once18.unsigned_q')
    vm.pc = 6198
    vm._jump(155 if vm.cells.value(912) != 0 else 156)


def _stage_155(vm):
    _indexed_pointer(vm, 6200, 913, 1, 549, (910,))
    vm.pc = 6212
    vm.cells.copy_q_clear_owned(913, 914)
    vm.pc = 6216
    vm._write(915, vm.memory.load(vm.cells.value(914), 4), 4, 'high.load')
    _indexed_pointer(vm, 6216, 916, 1, 909, (910,))
    vm.pc = 6228
    vm.cells.copy_q_clear_owned(916, 917)
    _store_cell(vm, 6228, 4, 915, 917)
    vm.pc = 6233
    vm.pc = 6236
    vm.auxiliary = (0, 1625985026)
    vm.pc = 6241
    vm._write(911, vm._signed_cell(910, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 6243
    vm._jump(154)


def _stage_156(vm):
    vm.pc = 6200
    vm._jump(157)


def _stage_157(vm):
    vm.pc = 6250
    if vm.predecessor == 156:
        value = vm.cells.value(48)
    elif vm.predecessor == 158:
        value = vm.cells.value(919)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(918, value, 8, 'L9.phi_q')
    vm.pc = 6255
    vm._write(920, int(vm.cells.value(918) < vm.cells.value(48)), 4, 'once18.unsigned_q')
    vm.pc = 6259
    vm._jump(158 if vm.cells.value(920) != 0 else 159)


def _stage_158(vm):
    _indexed_pointer(vm, 6277, 923, 1, 549, (918,))
    vm.pc = 6288
    vm._write(924, vm.memory.load(vm.cells.value(923), 1), 4, 'high.load')
    _indexed_pointer(vm, 6288, 925, 1, 909, (918,))
    _store_cell(vm, 6295, 1, 924, 925)
    vm.pc = 6300
    vm.pc = 6303
    vm.auxiliary = (0, 1213603841)
    vm.pc = 6308
    vm._write(919, vm._signed_cell(918, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 6310
    vm._jump(157)


def _stage_159(vm):
    _indexed_pointer(vm, 6259, 921, 1, 909, (48,))
    vm.pc = 6267
    vm.pc = 6270
    vm.auxiliary = (0, 24614)
    vm.pc = 6275
    value = vm._signed_cell(517, 27) & vm._signed_cell(31, 27)
    vm._write(922, value, 8, 'typed.selector1.q')
    vm.pc = 6277
    vm._jump(160)


def _stage_160(vm):
    vm.pc = 6317
    if vm.predecessor == 159:
        value = vm.cells.value(26)
    elif vm.predecessor == 161:
        value = vm.cells.value(927)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(926, value, 8, 'L9.phi_q')
    vm.pc = 6322
    vm._write(928, int(vm.cells.value(926) < vm.cells.value(922)), 4, 'once18.unsigned_q')
    vm.pc = 6326
    vm._jump(161 if vm.cells.value(928) != 0 else 162)


def _stage_161(vm):
    _indexed_pointer(vm, 6328, 929, 1, 518, (926,))
    vm.pc = 6340
    vm.cells.copy_q_clear_owned(929, 930)
    vm.pc = 6344
    vm._write(931, vm.memory.load(vm.cells.value(930), 4), 4, 'high.load')
    _indexed_pointer(vm, 6344, 932, 1, 921, (926,))
    vm.pc = 6356
    vm.cells.copy_q_clear_owned(932, 933)
    _store_cell(vm, 6356, 4, 931, 933)
    vm.pc = 6361
    vm.pc = 6364
    vm.auxiliary = (0, 1073246210)
    vm.pc = 6369
    vm._write(927, vm._signed_cell(926, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 6371
    vm._jump(160)


def _stage_162(vm):
    vm.pc = 6328
    vm._jump(163)


def _stage_163(vm):
    vm.pc = 6378
    if vm.predecessor == 162:
        value = vm.cells.value(922)
    elif vm.predecessor == 164:
        value = vm.cells.value(935)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(934, value, 8, 'L9.phi_q')
    vm.pc = 6383
    vm._write(936, int(vm.cells.value(934) < vm.cells.value(517)), 4, 'once18.unsigned_q')
    vm.pc = 6387
    vm._jump(164 if vm.cells.value(936) != 0 else 165)


def _stage_164(vm):
    _indexed_pointer(vm, 6412, 938, 1, 518, (934,))
    vm.pc = 6423
    vm._write(939, vm.memory.load(vm.cells.value(938), 1), 4, 'high.load')
    _indexed_pointer(vm, 6423, 940, 1, 921, (934,))
    _store_cell(vm, 6430, 1, 939, 940)
    vm.pc = 6435
    vm.pc = 6438
    vm.auxiliary = (0, 1120309249)
    vm.pc = 6443
    vm._write(935, vm._signed_cell(934, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 6445
    vm._jump(163)


def _stage_165(vm):
    _store_cell(vm, 6387, 8, 909, 2)
    _native_call(vm, 6391, 6397, 73, 507, (518,))
    _store_cell(vm, 6397, 4, 907, 3)
    vm.pc = 6402
    vm.pc = 6405
    vm.auxiliary = (0, 54286)
    vm.pc = 6410
    value = vm._signed_cell(306, 27) & vm._signed_cell(484, 27)
    vm._write(937, value, 8, 'typed.selector1.q')
    vm.pc = 6412
    vm._jump(166)


def _stage_166(vm):
    vm.pc = 6452
    if vm.predecessor == 165:
        value = vm.cells.value(26)
    elif vm.predecessor == 167:
        value = vm.cells.value(942)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(941, value, 8, 'L9.phi_q')
    vm.pc = 6457
    vm._write(943, int(vm.cells.value(941) < vm.cells.value(937)), 4, 'once18.unsigned_q')
    vm.pc = 6461
    vm._jump(167 if vm.cells.value(943) != 0 else 168)


def _stage_167(vm):
    _indexed_pointer(vm, 6463, 944, 1, 307, (941,))
    vm.pc = 6475
    vm.cells.copy_q_clear_owned(944, 945)
    _store_cell(vm, 6475, 4, 22, 945)
    vm.pc = 6480
    vm.pc = 6483
    vm.auxiliary = (0, 1777577986)
    vm.pc = 6488
    vm._write(942, vm._signed_cell(941, 27) + vm._signed_cell(41, 27), 8, 'once1.integer')
    vm.pc = 6490
    vm._jump(166)


def _stage_168(vm):
    vm.pc = 6463
    vm._jump(169)


def _stage_169(vm):
    vm.pc = 6497
    if vm.predecessor == 168:
        value = vm.cells.value(937)
    elif vm.predecessor == 170:
        value = vm.cells.value(947)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(946, value, 8, 'L9.phi_q')
    vm.pc = 6502
    vm._write(948, int(vm.cells.value(946) < vm.cells.value(306)), 4, 'once18.unsigned_q')
    vm.pc = 6506
    vm._jump(170 if vm.cells.value(948) != 0 else 171)


def _stage_170(vm):
    _indexed_pointer(vm, 6513, 949, 1, 307, (946,))
    _store_cell(vm, 6520, 1, 111, 949)
    vm.pc = 6525
    vm.pc = 6528
    vm.auxiliary = (0, 1625554946)
    vm.pc = 6533
    vm._write(947, vm._signed_cell(946, 27) + vm._signed_cell(57, 27), 8, 'once1.integer')
    vm.pc = 6535
    vm._jump(169)


def _stage_171(vm):
    _native_call(vm, 6506, 6512, 73, 507, (307,))
    vm.pc, vm.halted = 6513, True


def run_primary_device_record_cipher(vm):
    _stage_0(vm)
    while True:
        _stage_1(vm)
        if vm.block == 3:
            break
        _stage_2(vm)
    _stage_3(vm)
    while True:
        _stage_4(vm)
        if vm.block == 6:
            break
        _stage_5(vm)
    _stage_6(vm)
    while True:
        _stage_7(vm)
        if vm.block == 10:
            break
        _stage_9(vm)
        if vm.block == 13:
            _stage_13(vm)
        if vm.block == 15:
            _stage_15(vm)
            while True:
                _stage_16(vm)
                if vm.block == 18:
                    break
                _stage_17(vm)
            _stage_18(vm)
            while True:
                _stage_19(vm)
                if vm.block == 21:
                    break
                _stage_20(vm)
            _stage_21(vm)
        else:
            _stage_14(vm)
        _stage_8(vm)
    _stage_10(vm)
    if vm.block == 11:
        _stage_11(vm)
        while True:
            _stage_22(vm)
            if vm.block == 24:
                break
            _stage_23(vm)
        _stage_24(vm)
        while True:
            _stage_25(vm)
            if vm.block == 27:
                break
            _stage_26(vm)
        _stage_27(vm)
    else:
        _stage_12(vm)
    _stage_28(vm)
    while True:
        _stage_29(vm)
        if vm.block == 31:
            break
        _stage_30(vm)
    _stage_31(vm)
    while True:
        _stage_32(vm)
        if vm.block == 34:
            break
        _stage_33(vm)
    _stage_34(vm)
    while True:
        _stage_35(vm)
        if vm.block == 38:
            break
        _stage_37(vm)
        if vm.block == 40:
            _stage_40(vm)
        _stage_36(vm)
    _stage_38(vm)
    while True:
        _stage_39(vm)
        if vm.block == 43:
            break
        _stage_42(vm)
        if vm.block == 46:
            _stage_46(vm)
        else:
            _stage_47(vm)
            if vm.block == 49:
                _stage_49(vm)
        _stage_48(vm)
        while True:
            _stage_50(vm)
            if vm.block == 52:
                break
            _stage_51(vm)
        _stage_52(vm)
        while True:
            _stage_53(vm)
            if vm.block == 41:
                break
            _stage_54(vm)
        _stage_41(vm)
    _stage_43(vm)
    if vm.block == 44:
        _stage_44(vm)
        while True:
            _stage_55(vm)
            if vm.block == 57:
                break
            _stage_56(vm)
        _stage_57(vm)
        while True:
            _stage_58(vm)
            if vm.block == 60:
                break
            _stage_59(vm)
        _stage_60(vm)
    else:
        _stage_45(vm)
    _stage_61(vm)
    while True:
        _stage_62(vm)
        if vm.block == 65:
            break
        _stage_64(vm)
        if vm.block == 67:
            _stage_67(vm)
        else:
            _stage_68(vm)
            if vm.block == 69:
                _stage_69(vm)
                if vm.block == 71:
                    while True:
                        _stage_71(vm)
                        if vm.block == 74:
                            _stage_74(vm)
                        else:
                            _stage_75(vm)
                            if vm.block == 76:
                                _stage_76(vm)
                            else:
                                _stage_77(vm)
                        _stage_73(vm)
                        if vm.block == 72:
                            break
                _stage_72(vm)
            _stage_70(vm)
            if vm.block == 78:
                _stage_78(vm)
                if vm.block == 80:
                    _stage_80(vm)
                    if vm.block == 81:
                        while True:
                            _stage_81(vm)
                            if vm.block == 84:
                                _stage_84(vm)
                            else:
                                _stage_85(vm)
                                if vm.block == 86:
                                    _stage_86(vm)
                                else:
                                    _stage_87(vm)
                            _stage_83(vm)
                            if vm.block == 82:
                                break
                    _stage_82(vm)
                    while True:
                        _stage_88(vm)
                        if vm.block == 90:
                            break
                        _stage_89(vm)
                    _stage_90(vm)
                    while True:
                        _stage_91(vm)
                        if vm.block == 93:
                            break
                        _stage_92(vm)
                    _stage_93(vm)
            _stage_79(vm)
            if vm.block == 94:
                _stage_94(vm)
                if vm.block == 96:
                    while True:
                        _stage_96(vm)
                        if vm.block == 99:
                            _stage_99(vm)
                        else:
                            _stage_100(vm)
                            if vm.block == 101:
                                _stage_101(vm)
                            else:
                                _stage_102(vm)
                        _stage_98(vm)
                        if vm.block == 97:
                            break
                _stage_97(vm)
                while True:
                    _stage_103(vm)
                    if vm.block == 105:
                        break
                    _stage_104(vm)
                _stage_105(vm)
                while True:
                    _stage_106(vm)
                    if vm.block == 108:
                        break
                    _stage_107(vm)
                _stage_108(vm)
            _stage_95(vm)
        _stage_63(vm)
    _stage_65(vm)
    while True:
        _stage_66(vm)
        if vm.block == 111:
            break
        _stage_110(vm)
        if vm.block == 113:
            _stage_113(vm)
            if vm.block == 114:
                _stage_114(vm)
                while True:
                    _stage_115(vm)
                    if vm.block == 117:
                        break
                    _stage_116(vm)
                _stage_117(vm)
                while True:
                    _stage_118(vm)
                    if vm.block == 120:
                        break
                    _stage_119(vm)
                _stage_120(vm)
        _stage_109(vm)
    _stage_111(vm)
    while True:
        _stage_112(vm)
        if vm.block == 123:
            break
        _stage_122(vm)
        if vm.block == 125:
            _stage_125(vm)
        _stage_121(vm)
    _stage_123(vm)
    while True:
        _stage_124(vm)
        if vm.block == 127:
            break
        _stage_126(vm)
    _stage_127(vm)
    if vm.block == 128:
        _stage_128(vm)
        while True:
            _stage_131(vm)
            while True:
                _stage_133(vm)
                if vm.block == 135:
                    break
                _stage_134(vm)
            _stage_135(vm)
            while True:
                _stage_136(vm)
                if vm.block == 138:
                    break
                _stage_137(vm)
            _stage_138(vm)
            while True:
                _stage_139(vm)
                if vm.block == 141:
                    break
                _stage_140(vm)
            _stage_141(vm)
            while True:
                _stage_142(vm)
                if vm.block == 144:
                    break
                _stage_143(vm)
            _stage_144(vm)
            if vm.block == 146:
                _stage_146(vm)
            _stage_145(vm)
            if vm.block == 147:
                _stage_147(vm)
                while True:
                    _stage_149(vm)
                    if vm.block == 151:
                        break
                    _stage_150(vm)
                _stage_151(vm)
                break
            _stage_148(vm)
            while True:
                _stage_152(vm)
                if vm.block == 132:
                    break
                _stage_153(vm)
            _stage_132(vm)
    else:
        _stage_129(vm)
    _stage_130(vm)
    while True:
        _stage_154(vm)
        if vm.block == 156:
            break
        _stage_155(vm)
    _stage_156(vm)
    while True:
        _stage_157(vm)
        if vm.block == 159:
            break
        _stage_158(vm)
    _stage_159(vm)
    while True:
        _stage_160(vm)
        if vm.block == 162:
            break
        _stage_161(vm)
    _stage_162(vm)
    while True:
        _stage_163(vm)
        if vm.block == 165:
            break
        _stage_164(vm)
    _stage_165(vm)
    while True:
        _stage_166(vm)
        if vm.block == 168:
            break
        _stage_167(vm)
    _stage_168(vm)
    while True:
        _stage_169(vm)
        if vm.block == 171:
            break
        _stage_170(vm)
    _stage_171(vm)
    return vm.result

