from .primary_material_generation import _retained
from .primary_material_prepare import _address, _binary, _equal, _mask, _right
from .primary_material_rounds import _load, _store


_RECIPE = {
    'auxiliary': {225: 447873139, 226: 1024592227, 228: 922419201,
                  236: 689067379, 238: 1083338676, 239: 391283988,
                  241: 1199757043, 243: 2022678530, 247: 1665323010,
                  250: 368472066, 252: 617422849, 254: 1805786899,
                  256: 404434946, 258: 908832770, 262: 210845697,
                  264: 619499521, 267: 53809, 270: 776117027,
                  272: 488794595, 275: 412712962, 278: 7261, 282: 22213},
    'flag0': (),
    'comparisons': (225, 226, 272),
}


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'sign_counter.phi')


def _different(vm, left, right, destination, typ):
    if destination in _RECIPE['auxiliary']:
        vm.auxiliary = (0, _RECIPE['auxiliary'][destination])
    vm._write(destination, int(vm._signed_cell(left, typ) != vm._signed_cell(right, typ)),
              4, 'sign_counter.different')


def _select(vm, condition, true, false, destination):
    selected = true if vm.cells.value(condition) else false
    vm._write(destination, vm._signed_cell(selected, 1), 8, 'sign_counter.selected_byte')


def _fold(vm, source, added, condition, lowered, destination):
    _binary(vm, _RECIPE, source, 242, added, 1, 'add')
    vm._write(condition, int(vm.cells.value(added) < vm.cells.value(244)),
              4, 'sign_counter.uppercase_range')
    _binary(vm, _RECIPE, source, 246, lowered, 1, 'add')
    _select(vm, condition, lowered, source, destination)


def _command_difference(vm, state):
    vm.execute_once(10, (7, 3, 6, 224))
    if not _equal(vm, _RECIPE, 224, 159, 225, 7):
        _phi(vm, 268, 269)
        return
    if _equal(vm, _RECIPE, 224, 145, 226, 7):
        _phi(vm, 268, 158)
        return
    initial = True
    while True:
        _phi(vm, 227, 224 if initial else 228)
        _phi(vm, 229, 5 if initial else 230)
        _phi(vm, 231, 160 if initial else 232)
        _binary(vm, _RECIPE, 227, 233, 228, 7, 'add')
        _load(vm, 229, 234, 1)
        state['compared_bytes'] += 1
        if _equal(vm, _RECIPE, 234, 235, 236, 1):
            break
        _load(vm, 231, 237, 1)
        _different(vm, 237, 235, 238, 1)
        _different(vm, 228, 145, 239, 7)
        _binary(vm, _RECIPE, 238, 239, 240, 98, 'and')
        if not vm.cells.value(240):
            break
        if not _equal(vm, _RECIPE, 234, 237, 241, 1):
            _fold(vm, 234, 243, 245, 247, 248)
            _load(vm, 231, 249, 1)
            _fold(vm, 249, 250, 251, 252, 253)
            if not _equal(vm, _RECIPE, 248, 253, 254, 1):
                break
        _address(vm, 1, 229, 230, 163)
        _address(vm, 1, 231, 232, 163)
        initial = False
    _load(vm, 229, 255, 1)
    _fold(vm, 255, 256, 257, 258, 259)
    vm.cells.copy_q_clear_owned(259, 260)
    _load(vm, 231, 261, 1)
    _fold(vm, 261, 262, 263, 264, 265)
    vm.cells.copy_q_clear_owned(265, 266)
    vm.auxiliary = (0, _RECIPE['auxiliary'][267])
    vm._write(267, vm._signed_cell(260, 3) - vm._signed_cell(266, 3),
              8, 'sign_counter.command_difference')
    _phi(vm, 268, 267)


def advance_primary_sign_counter(vm):
    state = {'phase': 'enter', 'incremented': False, 'compared_bytes': 0,
             'retained_steps': 0}
    vm.primary_sign_counter_state = state
    _retained(vm, 703, 2, vm.predecessor, 1, state)
    state['phase'] = 'decode'
    _address(vm, 117, 148, 217, 145, 218)
    _load(vm, 217, 219, 2)
    _address(vm, 117, 148, 220, 145, 158)
    _load(vm, 220, 221, 4)
    _mask(vm, 221, 222, 2)
    _binary(vm, _RECIPE, 219, 222, 223, 18, 'xor')
    increment = False
    enabled = bool(vm.cells.value(142))
    if enabled:
        state['phase'] = 'command'
        _command_difference(vm, state)
        _equal(vm, _RECIPE, 268, 158, 270, 3, read=False)
        _equal(vm, _RECIPE, 223, 271, 272, 18, read=False)
        vm._write(273, vm._signed_cell(270, 98) | vm._signed_cell(272, 98),
                  8, 'sign_counter.skip_condition')
        increment = not vm.cells.value(273)
    if increment:
        state['phase'] = 'increment'
        _binary(vm, _RECIPE, 223, 274, 275, 18, 'add')
        _load(vm, 220, 276, 4)
        _mask(vm, 276, 277, 2)
        _binary(vm, _RECIPE, 275, 277, 278, 18, 'xor')
        _store(vm, 278, 217, 2)
        state['incremented'] = True
        state['phase'] = 'leave'
        _retained(vm, 1108, 14, 7, 1, state)
        _right(vm, 275, 280, 281, 2)
        vm.auxiliary = (0, _RECIPE['auxiliary'][282])
        first = vm.memory.load(vm.image_base + 0x6D86090, 4)
        second = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
        extra = (((first * first) & 0xFFFFFFFF) | (abs(second) & 0xFFFFFFFF)) >> 31
        vm.execute_typed((18, 275, 280, 282))
        if extra:
            vm.pc = 1128
            vm.execute_typed(tuple(vm._operand() for _ in range(4)))
        vm._write(283, vm._signed_cell(281, 18) | vm._signed_cell(282, 18),
                  8, 'sign_counter.byte_order')
        _phi(vm, 284, 283)
        predecessor = 14
    else:
        state['phase'] = 'leave'
        predecessor = 7 if enabled else 2
        _retained(vm, 1135, 5, predecessor, 1, state)
        _phi(vm, 284, 285)
        predecessor = 5
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 1151, 15, predecessor, False
    state['phase'] = 'complete'
    return True
