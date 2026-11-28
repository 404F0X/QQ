from . import primary_rolling_state
from .primary_material_generation import _retained
from .primary_material_prepare import _address, _binary
from .primary_material_rounds import _less, _load, _store


_RECIPE = {
    'auxiliary': {1546: 1867567106, 1554: 1272631298,
                  1561: 1616556033, 1569: 609857537,
                  1576: 307560449, 1584: 1825923074, 1539: 362516482},
    'flag0': (),
    'comparisons': (),
}
_COPIES = (
    (952, 1544, (1545, 1546, 1547, 1548, 1549, 1550, 1551, 1552,
                 1553, 1554, 1555, 1556, 1557, 1558)),
    (1525, 1559, (1560, 1561, 1562, 1563, 1564, 1565, 1566, 1567,
                  1568, 1569, 1570, 1571, 1572, 1573)),
    (1537, 1574, (1575, 1576, 1577, 1578, 1579, 1580, 1581, 1582,
                  1583, 1584, 1585, 1586, 1587, 1588)),
)


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'rolling_rounds.phi')


def _copy(vm, group, state):
    source, destination, cells = _COPIES[group]
    (index, following, condition, first, first_pointer, value, second, second_pointer,
     byte_index, byte_following, byte_condition, byte_first, byte_value, byte_second) = cells
    initial = True
    while True:
        _phi(vm, index, 145 if initial else following)
        if not _less(vm, index, 172, condition):
            break
        _address(vm, 1, source, first, index)
        vm.cells.copy_q_clear_owned(first, first_pointer)
        _load(vm, first_pointer, value, 4)
        _address(vm, 1, destination, second, index)
        vm.cells.copy_q_clear_owned(second, second_pointer)
        _store(vm, value, second_pointer, 4)
        state['copied_dwords'] += 1
        _binary(vm, _RECIPE, index, 172, following, 7, 'add')
        initial = False
    initial = True
    while True:
        _phi(vm, byte_index, 172 if initial else byte_following)
        if not _less(vm, byte_index, 172, byte_condition):
            break
        _address(vm, 1, source, byte_first, byte_index)
        _load(vm, byte_first, byte_value, 1)
        _address(vm, 1, destination, byte_second, byte_index)
        _store(vm, byte_value, byte_second, 1)
        state['copied_bytes'] += 1
        _binary(vm, _RECIPE, byte_index, 163, byte_following, 7, 'add')
        initial = False


def mix_primary_rolling_rounds(vm):
    vm.primary_rolling_rounds_state = {'phase': 'rounds', 'rounds': 0,
                                     'copied_dwords': 0, 'copied_bytes': 0,
                                     'input_bytes': 0, 'xor_bytes': 0,
                                     'retained_steps': 0}
    state = vm.primary_rolling_rounds_state
    previous = vm.predecessor
    while True:
        if previous not in (220, 229):
            from .primary_vm import PrimarySemanticUnavailable
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        _phi(vm, 1538, 158 if previous == 220 else 1539)
        _store(vm, 1538, 78, 4)
        if not _less(vm, 1538, 1540, 1541):
            break
        state['phase'] = 'clear'
        _address(vm, 56, 91, 1542, 145, 145)
        _retained(vm, 10237, 230, 228, 1, state)
        _address(vm, 56, 91, 1544, 145, 145)
        state['phase'] = 'first'
        _copy(vm, 0, state)
        _address(vm, 56, 91, 1559, 145, 172)
        state['phase'] = 'second'
        _copy(vm, 1, state)
        _address(vm, 1, 1559, 1574, 172)
        state['phase'] = 'counter'
        _copy(vm, 2, state)
        state['phase'] = 'mix'
        primary_rolling_state.mix_primary_rolling_state(vm)
        state['input_bytes'] += vm.primary_rolling_state['input_bytes']
        state['xor_bytes'] += vm.primary_rolling_state['xor_bytes']
        _load(vm, 78, 1606, 4)
        _binary(vm, _RECIPE, 1606, 269, 1539, 3, 'add')
        state['rounds'] += 1
        previous = 229
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 10787, 232, 231, False
    state['phase'] = 'complete'
    return True
