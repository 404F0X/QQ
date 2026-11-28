from .primary_ecrypt import _native_call


def run_primary_singleton_destroy(vm):
    vm.pc = 2
    vm.pc = 5
    vm.auxiliary = (0, 835859220)
    vm.pc = 10
    vm._write(2, int(vm._signed_cell(0, 27) != vm._signed_cell(1, 27)), 4, 'L30.comparison')
    vm.pc = 14
    vm._jump(1 if vm.cells.value(2) != 0 else 2)
    if vm.block == 1:
        _native_call(vm, 14, 21, 31, 3, (0, 4))
        vm.pc = 26
        vm.cells.copy_q_clear_owned(0, 5)
        _native_call(vm, 26, 35, 33, 7, (5, 8, 9), 6)
        _native_call(vm, 35, 42, 31, 3, (0, 10))
        _native_call(vm, 42, 48, 28, 11, (0,))
        _native_call(vm, 48, 54, 35, 12, (5,))
        vm.pc = 56
        vm._jump(2)
    vm.pc, vm.halted = 57, True
    return vm.result
