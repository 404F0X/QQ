from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell
from .primary_vm import PrimarySemanticUnavailable


def run_primary_device_mix(vm):
    _native_call(vm, 1, 8, 31, 2, (0, 3))
    _indexed_pointer(vm, 8, 4, 26, 0, (5, 6))
    _indexed_pointer(vm, 16, 7, 4, 4, (8, 8))
    _native_call(vm, 24, 33, 34, 10, (1, 7, 11), 9)
    vm.pc = 37
    vm.auxiliary = (0, 1307718964)
    vm.pc = 42
    value = int(vm._signed_cell(1, 24) != vm._signed_cell(12, 24))
    vm._write(13, value, 4, 'L27.comparison')
    vm.pc = 46
    vm._jump(1 if vm.cells.value(13) else 2)
    if vm.block == 1:
        _indexed_pointer(vm, 46, 14, 26, 0, (5, 15))
        _indexed_pointer(vm, 54, 16, 6, 14, (8, 8))
        vm.pc = 66
        vm._jump(3 if vm.cells.value(3) else 2)
        if vm.block == 3:
            vm.pc = 70
            vm._write(17, vm.memory.load(vm.cells.value(16), 1), 4, 'high.load')
            vm._jump(4)
            while True:
                vm.pc = 79
                if vm.predecessor == 3:
                    selected = 8
                elif vm.predecessor == 5:
                    selected = 19
                else:
                    raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
                vm._write(18, vm.cells.value(selected), 8, 'L9.phi_q')
                vm.pc = 86
                if vm.predecessor == 3:
                    selected = 17
                elif vm.predecessor == 5:
                    selected = 21
                else:
                    raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
                vm._write(20, vm.cells.value(selected), 8, 'L9.phi_q')
                vm.pc = 91
                vm._write(22, int(vm.cells.value(18) < vm.cells.value(11)), 4, 'once18.unsigned_q')
                vm.pc = 95
                vm._jump(5 if vm.cells.value(22) else 6)
                if vm.block == 6:
                    vm._jump(2)
                    break
                vm.pc = 100
                vm._write(23, vm.memory.load(vm.cells.pointer(20), 4), 8, 'once10.first_type_zeroextend_or_q')
                vm.pc = 104
                vm.auxiliary = (0, 1774752259)
                vm.pc = 109
                value = vm._signed_cell(18, 16) * vm._signed_cell(24, 16)
                vm._write(25, value, 8, 'once0.integer')
                vm.pc = 114
                vm._write(26, vm.cells.value(25) & 255, 8, 'once9.mask_q')
                vm.pc = 119
                vm._write(27, vm.memory.load(vm.cells.pointer(26), 4), 8, 'once10.first_type_zeroextend_or_q')
                vm.pc = 122
                vm.auxiliary = (0, 43831)
                vm.pc = 128
                value = vm._signed_cell(23, 1) ^ vm._signed_cell(27, 1)
                vm._write(28, value, 8, 'high.flag1_xor_q')
                _indexed_pointer(vm, 128, 29, 3, 1, (18,))
                vm.pc = 139
                vm._write(30, vm.memory.load(vm.cells.value(29), 1), 4, 'high.load')
                vm.pc = 144
                vm._write(31, vm.memory.load(vm.cells.pointer(30), 4), 8, 'once10.first_type_zeroextend_or_q')
                vm.pc = 147
                vm.auxiliary = (0, 6190)
                vm.pc = 153
                value = vm._signed_cell(31, 1) ^ vm._signed_cell(28, 1)
                vm._write(32, value, 8, 'high.flag1_xor_q')
                vm.pc = 158
                vm._write(33, vm.cells.value(32) & 255, 8, 'once9.mask_q')
                _store_cell(vm, 158, 1, 33, 29)
                vm.pc = 165
                vm.auxiliary = (0, 759448067)
                vm.pc = 170
                value = vm._signed_cell(23, 1) * vm._signed_cell(34, 1)
                vm._write(35, value, 8, 'once0.integer')
                vm.pc = 173
                vm.auxiliary = (0, 308195330)
                vm.pc = 178
                value = vm._signed_cell(35, 1) + vm._signed_cell(36, 1)
                vm._write(37, value, 8, 'once1.integer')
                vm.pc = 183
                vm._write(21, vm.cells.value(37) & 255, 8, 'once9.mask_q')
                vm.pc = 186
                vm.auxiliary = (0, 1568116738)
                vm.pc = 191
                value = vm._signed_cell(18, 16) + vm._signed_cell(38, 16)
                vm._write(19, value, 8, 'once1.integer')
                vm._jump(4)
    _native_call(vm, 195, 202, 31, 2, (0, 39))
    vm.pc = 203
    vm.halted = True
    return vm.result
