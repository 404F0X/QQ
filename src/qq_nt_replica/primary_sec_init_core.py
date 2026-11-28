from .primary_ecrypt import _indexed_pointer, _native_call
from .primary_policy3_core import (
    _add, _and, _aux, _branch, _copy, _extend, _less, _load, _mask,
    _phi, _signed_less, _store, _xor)
from .primary_vm import PrimaryProgramLimit


def _multiply(vm, pc, typ, left, right, destination):
    vm.pc = pc
    value = vm._signed_cell(left, typ) * vm._signed_cell(right, typ)
    vm._write(destination, value, 8, 'once0.integer')


def _unsigned_divide(vm, pc, left, right, destination, remainder=False):
    vm.pc = pc
    a, b = vm.cells.value(left), vm.cells.value(right)
    if b == 0:
        raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
    value = a % b if remainder else a // b
    vm._write(destination, value, 8, 'L17.unsigned_q_division' if remainder else 'L18.unsigned_q_division')


def _signed_divide(vm, pc, typ, left, right, destination):
    vm.pc = pc
    a, b = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    if b == 0 or (a == -(1 << 63) and b == -1):
        raise PrimaryProgramLimit('native IDIV fault lies outside ordinary execution')
    value = abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)
    vm._write(destination, value, 8, 'once6.integer')


def _shift_nibble(vm):
    vm.pc = 426
    count = vm.memory.load(vm.cells.pointer(82), 4)
    value = 0 if count & 0x80000000 or count >= 32 else (vm._signed_cell(81, 7) & 0xFFFFFFFF) >> count
    vm._write(83, value, 4, 'typed.selector4.d')


def run_primary_sec_init(vm):
    vm.pc = 4
    vm._allocate(11, 2)
    vm.pc = 7
    vm._allocate(5, 3)
    vm.pc = 10
    vm._allocate(13, 4)
    vm.pc = 13
    vm._allocate(15, 5)
    vm.pc = 16
    vm._allocate(17, 6)
    vm.pc = 19
    vm._allocate(2, 7)
    vm.pc = 22
    vm._allocate(13, 8)
    vm.pc = 25
    vm._allocate(20, 9)
    vm.pc = 28
    vm._allocate(23, 10)
    _copy(vm, 33, 2, 11)
    _indexed_pointer(vm, 33, 12, 11, 13, (14, 14))
    _native_call(vm, 41, 50, 25, 16, (11, 12, 17), 15)
    _copy(vm, 55, 3, 18)
    _indexed_pointer(vm, 55, 19, 5, 0, (14, 20))
    _load(vm, 67, 19, 21, 8)
    _aux(vm, 71, 1674452993)
    _add(vm, 76, 2, 21, 22, 23)
    _indexed_pointer(vm, 76, 24, 5, 3, (14, 20))
    _store(vm, 88, 23, 24, 8)
    _aux(vm, 91, 355734020)
    _multiply(vm, 96, 2, 25, 23, 26)
    _native_call(vm, 96, 103, 27, 28, (26,), 27)
    _copy(vm, 108, 27, 29)
    _indexed_pointer(vm, 108, 30, 5, 3, (14, 14))
    _store(vm, 120, 29, 30, 8)
    vm._jump(1)
    while True:
        _phi(vm, 129, 31, ((0, 32), (2, 33)))
        _load(vm, 133, 19, 34, 8)
        _less(vm, 138, 31, 34, 35)
        _branch(vm, 142, 35, 2, 3)
        if vm.block == 3:
            break
        _indexed_pointer(vm, 142, 36, 5, 0, (14, 14))
        _load(vm, 154, 36, 37, 8)
        _indexed_pointer(vm, 154, 38, 3, 37, (31,))
        _indexed_pointer(vm, 161, 39, 3, 38, (14, 14))
        _load(vm, 173, 39, 40, 8)
        _load(vm, 177, 30, 41, 8)
        _indexed_pointer(vm, 177, 42, 3, 41, (31,))
        _indexed_pointer(vm, 184, 43, 3, 42, (14, 14))
        _store(vm, 196, 40, 43, 8)
        _load(vm, 200, 36, 44, 8)
        _indexed_pointer(vm, 200, 45, 3, 44, (31,))
        _indexed_pointer(vm, 207, 46, 3, 45, (14, 20))
        _load(vm, 219, 46, 47, 8)
        _load(vm, 223, 30, 48, 8)
        _indexed_pointer(vm, 223, 49, 3, 48, (31,))
        _indexed_pointer(vm, 230, 50, 3, 49, (14, 20))
        _store(vm, 242, 47, 50, 8)
        _aux(vm, 246, 2116689922)
        _add(vm, 251, 2, 31, 51, 33)
        vm._jump(1)
    _copy(vm, 258, 4, 52)
    _native_call(vm, 258, 267, 32, 54, (52, 14, 25), 53)
    _native_call(vm, 267, 273, 34, 56, (), 55)
    _copy(vm, 278, 55, 57)
    _indexed_pointer(vm, 278, 58, 13, 4, (32, 32))
    _native_call(vm, 286, 293, 57, 59, (57, 58), None)
    _copy(vm, 298, 5, 60)
    vm._jump(4)
    while True:
        _phi(vm, 307, 61, ((3, 14), (5, 62)))
        _aux(vm, 311, 1693621909)
        _signed_less(vm, 316, 61, 63, 64)
        _branch(vm, 320, 64, 5, 6)
        if vm.block == 6:
            break
        _copy(vm, 400, 61, 78)
        _indexed_pointer(vm, 400, 79, 13, 4, (32, 78))
        _load(vm, 412, 79, 80, 1)
        _extend(vm, 417, 80, 81, 4)
        _aux(vm, 421, 6489)
        _shift_nibble(vm)
        _aux(vm, 429, 62980)
        vm.pc = 434
        vm._write(85, vm._signed_cell(83, 7) & vm._signed_cell(84, 7), 8, 'typed.selector1.q')
        _copy(vm, 439, 85, 86)
        _indexed_pointer(vm, 439, 87, 11, 2, (32, 86))
        _load(vm, 451, 87, 88, 1)
        _aux(vm, 454, 408543747)
        _multiply(vm, 459, 7, 61, 89, 90)
        _copy(vm, 464, 90, 91)
        _indexed_pointer(vm, 464, 92, 15, 5, (32, 91))
        _store(vm, 476, 88, 92, 1)
        _load(vm, 480, 79, 93, 1)
        _extend(vm, 485, 93, 94, 4)
        _aux(vm, 488, 54071)
        vm.pc = 493
        vm._write(95, vm._signed_cell(94, 7) & vm._signed_cell(84, 7), 8, 'typed.selector1.q')
        _copy(vm, 498, 95, 96)
        _indexed_pointer(vm, 498, 97, 11, 2, (32, 96))
        _load(vm, 510, 97, 98, 1)
        _aux(vm, 513, 516653058)
        _add(vm, 518, 7, 90, 20, 99)
        _copy(vm, 523, 99, 100)
        _indexed_pointer(vm, 523, 101, 15, 5, (32, 100))
        _store(vm, 535, 98, 101, 1)
        _aux(vm, 538, 813907969)
        _add(vm, 543, 7, 61, 20, 62)
        vm._jump(4)
    _indexed_pointer(vm, 320, 65, 15, 5, (32, 32))
    _load(vm, 332, 30, 66, 8)
    _aux(vm, 336, 1262571522)
    _add(vm, 341, 2, 31, 51, 67)
    _indexed_pointer(vm, 341, 68, 3, 66, (31,))
    _indexed_pointer(vm, 348, 69, 3, 68, (32, 14))
    _store(vm, 360, 65, 69, 8)
    _indexed_pointer(vm, 360, 70, 3, 68, (32, 20))
    _store(vm, 372, 71, 70, 8)
    _native_call(vm, 372, 378, 59, 73, (), 72)
    _and(vm, 383, 7, 72, 74, 75)
    _mask(vm, 388, 75, 76, 1)
    _copy(vm, 393, 6, 77)
    vm._jump(7)
    while True:
        _phi(vm, 552, 102, ((6, 20), (8, 103)))
        _unsigned_divide(vm, 557, 72, 102, 104)
        vm.pc = 562
        vm._write(106, int(vm.cells.value(104) >= vm.cells.value(105)), 4, 'once20.unsigned_q')
        _branch(vm, 566, 106, 8, 9)
        if vm.block == 9:
            break
        _aux(vm, 570, 1423241732)
        _multiply(vm, 575, 7, 102, 105, 103)
        vm._jump(7)
    while True:
        _phi(vm, 584, 107, ((7, 102), (10, 108)))
        _phi(vm, 591, 109, ((7, 32), (10, 110)))
        _phi(vm, 598, 111, ((7, 72), (10, 112)))
        _aux(vm, 602, 443679958)
        vm.pc = 607
        vm._write(113, int(vm._signed_cell(107, 7) > vm._signed_cell(14, 7)), 4, 'L25.comparison')
        _branch(vm, 611, 113, 10, 11)
        if vm.block == 11:
            break
        _unsigned_divide(vm, 616, 111, 107, 114)
        _aux(vm, 620, 1009410049)
        _add(vm, 625, 7, 115, 114, 116)
        _mask(vm, 630, 116, 117, 1)
        _indexed_pointer(vm, 630, 118, 17, 6, (32, 109))
        _store(vm, 642, 117, 118, 1)
        _unsigned_divide(vm, 647, 111, 107, 112, True)
        _signed_divide(vm, 652, 7, 107, 105, 108)
        _aux(vm, 655, 1914232833)
        _add(vm, 660, 2, 109, 51, 110)
        vm._jump(9)
    _indexed_pointer(vm, 662, 119, 17, 6, (32, 109))
    _store(vm, 674, 120, 119, 1)
    _indexed_pointer(vm, 674, 121, 17, 6, (32, 32))
    _load(vm, 686, 30, 122, 8)
    _indexed_pointer(vm, 686, 123, 3, 122, (67,))
    _indexed_pointer(vm, 693, 124, 3, 123, (32, 14))
    _store(vm, 705, 121, 124, 8)
    _indexed_pointer(vm, 705, 125, 3, 123, (32, 20))
    _store(vm, 717, 109, 125, 8)
    _copy(vm, 722, 7, 126)
    _native_call(vm, 722, 730, 61, 128, (3, 7), 127)
    _copy(vm, 735, 8, 129)
    vm._jump(12)
    while True:
        _phi(vm, 744, 130, ((11, 14), (13, 131)))
        _aux(vm, 748, 733112405)
        _signed_less(vm, 753, 130, 63, 132)
        _branch(vm, 757, 132, 13, 14)
        if vm.block == 14:
            break
        _copy(vm, 1033, 130, 179)
        _indexed_pointer(vm, 1033, 180, 13, 4, (32, 179))
        _load(vm, 1045, 180, 181, 1)
        _extend(vm, 1050, 181, 182, 4)
        _copy(vm, 1055, 76, 183)
        _xor(vm, 1060, 7, 182, 183, 184)
        _mask(vm, 1065, 184, 185, 1)
        _indexed_pointer(vm, 1065, 186, 13, 8, (32, 179))
        _store(vm, 1077, 185, 186, 1)
        _aux(vm, 1081, 2069319682)
        _add(vm, 1086, 7, 130, 20, 131)
        vm._jump(12)
    _copy(vm, 762, 9, 133)
    _native_call(vm, 762, 771, 32, 54, (133, 14, 135), 134)
    _indexed_pointer(vm, 771, 136, 20, 9, (32, 32))
    _store(vm, 783, 137, 136, 1)
    _indexed_pointer(vm, 783, 138, 20, 9, (32, 51))
    _store(vm, 795, 139, 138, 1)
    _indexed_pointer(vm, 795, 140, 20, 9, (32, 22))
    _store(vm, 807, 141, 140, 1)
    _indexed_pointer(vm, 807, 142, 20, 9, (32, 143))
    _store(vm, 819, 144, 142, 1)
    _indexed_pointer(vm, 819, 145, 20, 9, (32, 146))
    _store(vm, 831, 147, 145, 1)
    _indexed_pointer(vm, 831, 148, 20, 9, (32, 149))
    _store(vm, 843, 150, 148, 1)
    _indexed_pointer(vm, 843, 151, 20, 9, (32, 152))
    _store(vm, 855, 153, 151, 1)
    _indexed_pointer(vm, 855, 154, 20, 9, (32, 155))
    _store(vm, 867, 156, 154, 1)
    _load(vm, 871, 7, 157, 8)
    _native_call(vm, 871, 878, 27, 28, (157,), 158)
    _copy(vm, 883, 10, 159)
    _native_call(vm, 883, 890, 63, 160, (10, 136), None)
    _load(vm, 894, 7, 161, 8)
    _mask(vm, 899, 161, 162, 4)
    _indexed_pointer(vm, 899, 163, 13, 8, (32, 32))
    _native_call(vm, 907, 917, 65, 164, (10, 163, 127, 158, 162), None)
    _load(vm, 921, 7, 165, 8)
    _aux(vm, 925, 1260965890)
    _add(vm, 930, 2, 25, 165, 166)
    _native_call(vm, 930, 937, 27, 28, (166,), 167)
    _native_call(vm, 937, 946, 25, 16, (167, 163, 25), 168)
    _indexed_pointer(vm, 946, 169, 0, 167, (25,))
    _load(vm, 957, 7, 170, 8)
    _native_call(vm, 957, 966, 25, 16, (169, 158, 170), 171)
    _native_call(vm, 966, 972, 67, 172, (127,), None)
    _native_call(vm, 972, 978, 67, 172, (158,), None)
    _load(vm, 982, 30, 173, 8)
    _copy(vm, 987, 173, 174)
    _native_call(vm, 987, 993, 67, 172, (174,), None)
    _indexed_pointer(vm, 993, 175, 5, 0, (14, 14))
    _load(vm, 1005, 175, 176, 8)
    _copy(vm, 1010, 176, 177)
    _native_call(vm, 1010, 1016, 67, 172, (177,), None)
    _mask(vm, 1021, 166, 178, 4)
    _store(vm, 1025, 178, 1, 4)
    vm.pc = 1028
    vm.result = vm._signed_cell(167, 1) & ((1 << 64) - 1)
    vm.halted = True
    return vm.result
