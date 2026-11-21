from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


def run_primary_host129_prepare(vm, *, charge=None):
    from .primary_main_material_getter import _equal, _phi
    def tick(word):
        if charge is not None:
            charge(word)
    tick(1)
    vm.pc = 6
    a, b = vm.cells.value(0), vm.cells.value(1)
    if b == 0:
        raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
    vm._write(2, a // b, 8, 'L18.unsigned_q_division')
    tick(6)
    vm.pc = 11
    a, b = vm.cells.value(2), vm.cells.value(3)
    if b == 0:
        raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
    vm._write(4, a % b, 8, 'L17.unsigned_q_division')
    tick(11)
    vm.pc = 12
    tick(12)
    vm.pc = 15
    vm.auxiliary = (0, 1640126707)
    tick(15)
    vm.pc = 16
    _equal(vm, 20, 4, 4, 5, 6)
    tick(20)
    vm.pc = 24
    vm._jump(1 if vm.cells.value(6) != 0 else 2)
    if vm.block == 1:
        tick(24)
        vm.pc = 26
        vm._jump(2)
    tick(26)
    _phi(vm, 26, (7, 2, 1, 1, 5, 0))
    tick(33)
    vm.pc = 38
    a, b = vm.cells.value(0), vm.cells.value(8)
    if b == 0:
        raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
    vm._write(9, a // b, 8, 'L18.unsigned_q_division')
    tick(38)
    vm.pc = 43
    a, b = vm.cells.value(9), vm.cells.value(3)
    if b == 0:
        raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
    vm._write(10, a % b, 8, 'L17.unsigned_q_division')
    tick(43)
    vm.pc = 44
    tick(44)
    vm.pc = 47
    vm.auxiliary = (0, 685926067)
    tick(47)
    vm.pc = 52
    vm._write(12, int(vm._signed_cell(10, 0) == vm._signed_cell(11, 0)), 4, 'once17.integer')
    tick(52)
    vm.pc = 56
    vm._jump(3 if vm.cells.value(12) != 0 else 4)
    if vm.block == 3:
        tick(56)
        vm.pc = 58
        vm._jump(4)
    tick(58)
    _phi(vm, 58, (13, 2, 8, 3, 5, 2))
    tick(65)
    vm.pc = 66
    tick(66)
    vm.pc = 69
    vm.auxiliary = (0, 667398145)
    tick(69)
    vm.pc = 74
    vm._write(14, vm._signed_cell(0, 0) + vm._signed_cell(7, 0), 8, 'once1.integer')
    tick(74)
    vm.pc = 77
    vm.auxiliary = (0, 41576)
    tick(77)
    vm.pc = 82
    vm._write(15, vm._signed_cell(14, 0) - vm._signed_cell(13, 0), 8, 'typed.selector0.q')
    tick(82)
    vm.pc = 85
    vm.result, vm.halted = vm._signed_cell(15, 0) & ((1 << 64) - 1), True
    return vm.result
