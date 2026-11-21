from .primary_material_generation import _retained
from .primary_material_prepare import _address, _binary, _equal
from .primary_material_rounds import _less, _load, _store
from .primary_vm import PrimarySemanticUnavailable


_RECIPE = {
    'auxiliary': {1714: 420617171, 1713: 1919631362, 1715: 1573580801,
                  1716: 1767518209, 1725: 1181928595, 1722: 469463042,
                  1730: 218258707, 1727: 1862557698, 1733: 17415,
                  1735: 203980801, 1743: 1917743106,
                  1750: 1517875202, 1758: 608456705},
    'flag0': (),
    'comparisons': (1725, 1730),
}


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'message_cipher.phi')


def _clear(vm, pointer, remaining, next_pointer, next_remaining, condition,
           initial_pointer, initial_remaining, state, field, *, following=False,
           remaining_first=False):
    while True:
        assignments = ((pointer, next_pointer if following else initial_pointer),
                       (remaining, next_remaining if following else initial_remaining))
        for destination, source in reversed(assignments) if remaining_first else assignments:
            _phi(vm, destination, source)
        if _equal(vm, _RECIPE, remaining, 145, condition, 7):
            return
        _binary(vm, _RECIPE, remaining, 233, next_remaining, 7, 'add')
        _address(vm, 1, pointer, next_pointer, 163)
        _store(vm, 235, pointer, 1)
        state[field] += 1
        following = True


def _copy(vm, source, destination, cells, initial, limit, step, width, state, field):
    if width == 4:
        index, following, condition, first, first_pointer, value, second, second_pointer = cells
    else:
        index, following, condition, first, value, second = cells
    initial_iteration = True
    while True:
        _phi(vm, index, initial if initial_iteration else following)
        if not _less(vm, index, limit, condition):
            return
        _address(vm, 1, source, first, index)
        if width == 4:
            vm.cells.copy_q_clear_owned(first, first_pointer)
            _load(vm, first_pointer, value, 4)
        else:
            _load(vm, first, value, 1)
        _address(vm, 1, destination, second, index)
        if width == 4:
            vm.cells.copy_q_clear_owned(second, second_pointer)
            _store(vm, value, second_pointer, 4)
        else:
            _store(vm, value, second, 1)
        state[field] += 1
        _binary(vm, _RECIPE, index, step, following, 7, 'add')
        initial_iteration = False


def encrypt_primary_message(vm):
    vm.primary_message_cipher_state = {'phase': 'local_clear', 'local_clear_bytes': 0,
                                       'allocated_buffers': 0, 'buffer_clear_bytes': 0,
                                       'body_dwords': 0, 'body_bytes': 0,
                                       'trailer_dwords': 0, 'trailer_bytes': 0,
                                       'cipher_calls': 0, 'freed_buffers': 0,
                                       'published_qwords': 0, 'retained_steps': 0}
    state = vm.primary_message_cipher_state
    if vm.predecessor not in (272, 276):
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    _clear(vm, 1710, 1712, 1711, 1713, 1714, 1618, 205,
           state, 'local_clear_bytes', following=vm.predecessor == 276)
    state['phase'] = 'allocate'
    _binary(vm, _RECIPE, 2, 360, 1715, 3, 'add')
    _binary(vm, _RECIPE, 2, 391, 1716, 3, 'add')
    vm.execute_once(10, (7, 3, 1716, 1717))
    _retained(vm, 11562, 277, 273, 1, state)
    state['allocated_buffers'] += 1
    _retained(vm, 11569, 277, 273, 1, state)
    state['allocated_buffers'] += 1
    state['phase'] = 'input_clear'
    _clear(vm, 1723, 1721, 1724, 1722, 1725, 1718, 1717,
           state, 'buffer_clear_bytes', remaining_first=True)
    state['phase'] = 'output_clear'
    _clear(vm, 1728, 1726, 1729, 1727, 1730, 1720, 1717,
           state, 'buffer_clear_bytes', remaining_first=True)
    state['phase'] = 'body_copy'
    vm.execute_once(10, (7, 3, 2, 1731))
    _binary(vm, _RECIPE, 1731, 1732, 1733, 7, 'and')
    _copy(vm, 1, 1718, (1734, 1735, 1736, 1737, 1738, 1739, 1740, 1741),
          145, 1733, 172, 4, state, 'body_dwords')
    _copy(vm, 1, 1718, (1742, 1743, 1744, 1745, 1746, 1747),
          1733, 1731, 163, 1, state, 'body_bytes')
    state['phase'] = 'trailer_copy'
    _address(vm, 1, 1718, 1748, 1731)
    _copy(vm, 934, 1748, (1749, 1750, 1751, 1752, 1753, 1754, 1755, 1756),
          145, 172, 172, 4, state, 'trailer_dwords')
    _copy(vm, 934, 1748, (1757, 1758, 1759, 1760, 1761, 1762),
          172, 172, 163, 1, state, 'trailer_bytes')
    state['phase'] = 'cipher'
    _retained(vm, 11919, 293, 291, 1, state)
    state['cipher_calls'] += 1
    state['phase'] = 'release_input'
    _retained(vm, 11930, 293, 291, 1, state)
    state['freed_buffers'] += 1
    state['phase'] = 'release_output'
    _retained(vm, 11936, 293, 291, 1, state)
    state['freed_buffers'] += 1
    state['phase'] = 'publish'
    _store(vm, 1763, 117, 8)
    state['published_qwords'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 11946, 293, 291, False
    state['phase'] = 'complete'
    return True
