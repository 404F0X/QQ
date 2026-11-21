from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell
from .primary_vm import PrimarySemanticUnavailable


def run_primary_entry_prepare(vm):
    vm.pc = 4
    vm._allocate(4, 0)
    vm.pc = 7
    vm._allocate(6, 1)
    vm.pc = 12
    vm.cells.copy_q_clear_owned(0, 2)
    _native_call(vm, 12, 21, 10, 4, (2, 5, 6), 3)
    for word, destination, index, source in (
            (21, 7, 8, 9), (33, 10, 11, 12), (45, 13, 14, 15),
            (57, 16, 17, 18), (69, 19, 20, 18), (81, 21, 22, 23),
            (93, 24, 25, 15), (105, 26, 27, 18), (117, 28, 29, 18)):
        _indexed_pointer(vm, word, destination, 4, 0, (8, index))
        _store_cell(vm, word + 8, 1, source, destination)
    _native_call(vm, 129, 136, 14, 31, (7,), 30)
    vm.pc = 137
    vm.pc = 140
    vm.auxiliary = (0, 1600295843)
    vm.pc = 145
    vm._write(33, int(vm._signed_cell(30, 13) == vm._signed_cell(32, 13)),
              4, 'once17.integer')
    vm.pc = 149
    vm._jump(1 if vm.cells.value(33) != 0 else 2)
    if vm.block == 1:
        vm.pc = 151
        vm._jump(3)
    else:
        vm.pc = 156
        vm.cells.copy_q_clear_owned(1, 34)
        _native_call(vm, 156, 165, 10, 4, (34, 5, 36), 35)
        for word, destination, index, source in (
                (165, 37, 8, 38), (177, 39, 11, 12), (189, 40, 14, 18),
                (201, 41, 17, 42), (213, 43, 20, 44), (225, 45, 22, 46),
                (237, 47, 25, 12), (249, 48, 27, 49), (261, 50, 29, 51),
                (273, 52, 53, 54), (285, 55, 6, 56), (297, 57, 58, 12),
                (309, 59, 60, 44), (321, 61, 62, 63), (333, 64, 65, 66),
                (345, 67, 68, 69), (357, 70, 71, 44), (369, 72, 73, 63),
                (381, 74, 75, 66), (393, 76, 77, 78), (405, 79, 80, 51),
                (417, 81, 82, 44), (429, 83, 84, 63), (441, 85, 86, 54)):
            _indexed_pointer(vm, word, destination, 6, 1, (8, index))
            _store_cell(vm, word + 8, 1, source, destination)
        _native_call(vm, 453, 461, 19, 88, (30, 37), 87)
        vm.pc = 466
        vm.cells.copy_q_clear_owned(87, 89)
        vm.pc = 468
        vm._jump(3)
    vm.pc = 475
    if vm.predecessor == 1:
        value = vm.cells.value(91)
    elif vm.predecessor == 2:
        value = vm.cells.value(89)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(90, value, 8, 'L9.phi_q')
    vm.pc = 478
    vm.result, vm.halted = vm._signed_cell(90, 1) & ((1 << 64) - 1), True
    return vm.result
