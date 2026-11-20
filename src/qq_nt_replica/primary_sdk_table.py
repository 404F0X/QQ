from .primary_ecrypt import _indexed_pointer, _native_call


def run_primary_sdk_table(vm):
    _indexed_pointer(vm, 1, 0, 5, 1, (2, 2))
    _native_call(vm, 9, 17, 9, 4, (0, 5), 3)
    vm.pc = 21
    vm._jump(1 if vm.cells.value(3) != 0 else 2)
    if vm.block == 2:
        _indexed_pointer(vm, 21, 6, 12, 7, (8, 8, 8))
        _indexed_pointer(vm, 30, 9, 5, 1, (2, 2))
        _native_call(vm, 38, 47, 15, 11, (6, 9, 5), 10)
        _indexed_pointer(vm, 47, 12, 5, 1, (2, 2))
        _native_call(vm, 55, 64, 17, 14, (12, 8, 5), 13)
        vm.pc = 66
        vm._jump(1)
    vm.pc, vm.halted = 67, True
    return vm.result
