from .primary_material_prepare import _address, _binary, _mask, _right
from .primary_material_rounds import _less, _load, _store
from .primary_vm import PrimarySemanticUnavailable


_RECIPE = {
    'auxiliary': {1628: 1970577409, 1624: 1317228546, 1638: 1979367426,
                  1640: 41980, 1646: 756810243, 1647: 39972, 1633: 868249602,
                  1657: 1516290049, 1654: 1973522433, 1668: 2063892482,
                  1669: 18999, 1670: 29430, 1674: 1874645507, 1675: 7452,
                  1662: 771284994, 1677: 519753730, 1685: 1667284993,
                  1616: 1461784577, 1690: 42637, 1693: 4604,
                  1697: 1870327809, 1702: 38458, 1709: 7991},
    'flag0': (1669,),
    'comparisons': (),
}


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'rolling_permutation.phi')


def _left(vm, source, count, destination, typ, word):
    vm.auxiliary = (0, _RECIPE['auxiliary'][destination])
    first = vm.memory.load(vm.image_base + 0x6D86090, 4)
    second = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((first * first) & 0xFFFFFFFF) | (abs(second) & 0xFFFFFFFF)) >> 31
    amount = vm.memory.load(vm.cells.pointer(count), 4)
    value = 0
    if not amount & 0x80000000 and amount < 32:
        value = (vm._signed_cell(source, typ) & 0xFFFFFFFF) << amount
    vm._write(destination, value, 4, 'rolling_permutation.left')
    if extra:
        vm.pc = word + 5
        vm.execute_typed(tuple(vm._operand() for _ in range(4)))


def _rotate(vm, base, cells, offsets, state):
    (first_pointer, first, second_pointer, second, index, following, condition,
     shifted, source_pointer, value, destination_pointer, head_pointer) = cells
    first_offset, second_offset = offsets
    _address(vm, 1, base, first_pointer, first_offset)
    _load(vm, first_pointer, first, 1)
    _address(vm, 1, base, second_pointer, second_offset)
    _load(vm, second_pointer, second, 1)
    initial = True
    while True:
        _phi(vm, index, second_offset if initial else following)
        vm._write(condition, int(vm.cells.value(index) > vm.cells.value(163)),
                  4, 'rolling_permutation.rotate_condition')
        if not vm.cells.value(condition):
            break
        _binary(vm, _RECIPE, index, 1627, shifted, 7, 'add')
        _address(vm, 1, base, source_pointer, shifted)
        _load(vm, source_pointer, value, 1)
        _address(vm, 1, base, destination_pointer, index)
        _store(vm, value, destination_pointer, 1)
        state['rotation_writes'] += 1
        _binary(vm, _RECIPE, index, 233, following, 7, 'add')
        initial = False
    _store(vm, first, base, 1)
    _address(vm, 1, base, head_pointer, 163)
    _store(vm, second, head_pointer, 1)
    state['rotation_writes'] += 2


def _transform(vm, group, state):
    if group == 0:
        base, limit = 1618, 184
        cells = (1632, 1633, 1634, 1635, 1636, 1637, 1638, 1639,
                 1640, 1642, 1643, 1644, 1646, 1647)
        salt, word = 880, 10958
    else:
        base, limit = 1648, 172
        cells = (1661, 1662, 1663, 1664, 1665, 1666, 1668, 1669,
                 1670, 1671, 1672, 1673, 1674, 1675)
        salt, word = 1667, 11168
    (index, following, condition, pointer, value, byte_index, added, mixed,
     left, right, rotated, other_index, product, output) = cells
    initial = True
    while True:
        _phi(vm, index, 145 if initial else following)
        if not _less(vm, index, limit, condition):
            break
        _address(vm, 1, base, pointer, index)
        _load(vm, pointer, value, 1)
        _mask(vm, index, byte_index, 1)
        _binary(vm, _RECIPE, salt, byte_index, added, 1, 'add')
        _binary(vm, _RECIPE, added, value, mixed, 1, 'xor')
        _left(vm, mixed, 497, left, 1, word)
        _right(vm, mixed, 1641, right, 1)
        vm._write(rotated, vm._signed_cell(left, 1) | vm._signed_cell(right, 1),
                  8, 'rolling_permutation.rotated_byte')
        _mask(vm, index, other_index, 1)
        _binary(vm, _RECIPE, other_index, 1645, product, 1, 'mul')
        _binary(vm, _RECIPE, product, rotated, output, 1, 'xor')
        _store(vm, output, pointer, 1)
        state['transformed_bytes'] += 1
        _binary(vm, _RECIPE, index, 163, following, 7, 'add')
        initial = False


def permute_primary_rolling_key(vm):
    vm.primary_rolling_permutation_state = {'phase': 'pairs', 'pair_writes': 0,
                                           'mirror_xors': 0, 'rotation_writes': 0,
                                           'transformed_bytes': 0, 'published_dwords': 0,
                                           'published_bytes': 0, 'retained_steps': 0}
    state = vm.primary_rolling_permutation_state
    previous = vm.predecessor
    while True:
        if previous not in (231, 253):
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        _phi(vm, 1615, 158 if previous == 231 else 1616)
        if not _less(vm, 1615, 149, 1617):
            break
        _binary(vm, _RECIPE, 1615, 269, 1616, 3, 'add')
        _left(vm, 1616, 269, 1690, 3, 11343)
        vm.execute_once(10, (7, 3, 1690, 1691))
        _address(vm, 49, 94, 1692, 145, 1691)
        _left(vm, 1615, 269, 1693, 3, 11364)
        vm.execute_once(10, (7, 3, 1693, 1694))
        _address(vm, 49, 94, 1695, 145, 1694)
        initial = True
        while True:
            _phi(vm, 1696, 145 if initial else 1697)
            if not _less(vm, 1696, 166, 1698):
                break
            _address(vm, 1, 1692, 1699, 1696)
            _load(vm, 1699, 1700, 1)
            _address(vm, 1, 1695, 1701, 1696)
            _store(vm, 1700, 1701, 1)
            state['pair_writes'] += 1
            _binary(vm, _RECIPE, 1696, 163, 1697, 7, 'add')
            initial = False
        vm.auxiliary = (0, _RECIPE['auxiliary'][1702])
        vm._write(1702, vm._signed_cell(476, 3) - vm._signed_cell(1615, 3),
                  8, 'rolling_permutation.mirror_index')
        vm.execute_once(10, (7, 3, 1702, 1703))
        _address(vm, 49, 94, 1704, 145, 1703)
        _load(vm, 1704, 1705, 1)
        vm.execute_once(10, (7, 3, 1615, 1706))
        _address(vm, 49, 94, 1707, 145, 1706)
        _load(vm, 1707, 1708, 1)
        _binary(vm, _RECIPE, 1708, 1705, 1709, 1, 'xor')
        _store(vm, 1709, 1707, 1)
        state['mirror_xors'] += 1
        previous = 253
    state['phase'] = 'first_rotation'
    _address(vm, 49, 94, 1618, 145, 145)
    _rotate(vm, 1618, (1619, 1620, 1621, 1622, 1623, 1624, 1625,
                      1628, 1629, 1630, 1631, 1626), (178, 181), state)
    state['phase'] = 'first_transform'
    _transform(vm, 0, state)
    state['phase'] = 'second_rotation'
    _address(vm, 49, 94, 1648, 145, 172)
    _rotate(vm, 1648, (1649, 1650, 1651, 1652, 1653, 1654, 1655,
                      1657, 1658, 1659, 1660, 1656), (166, 169), state)
    state['phase'] = 'second_transform'
    _transform(vm, 1, state)
    state['phase'] = 'publish'
    initial = True
    while True:
        _phi(vm, 1676, 145 if initial else 1677)
        if not _less(vm, 1676, 184, 1678):
            break
        _address(vm, 1, 1618, 1679, 1676)
        vm.cells.copy_q_clear_owned(1679, 1680)
        _load(vm, 1680, 1681, 4)
        _address(vm, 1, 1523, 1682, 1676)
        vm.cells.copy_q_clear_owned(1682, 1683)
        _store(vm, 1681, 1683, 4)
        state['published_dwords'] += 1
        _binary(vm, _RECIPE, 1676, 172, 1677, 7, 'add')
        initial = False
    initial = True
    while True:
        _phi(vm, 1684, 184 if initial else 1685)
        if not _less(vm, 1684, 184, 1686):
            break
        _address(vm, 1, 1618, 1687, 1684)
        _load(vm, 1687, 1688, 1)
        _address(vm, 1, 1523, 1689, 1684)
        _store(vm, 1688, 1689, 1)
        state['published_bytes'] += 1
        _binary(vm, _RECIPE, 1684, 163, 1685, 7, 'add')
        initial = False
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 11491, 273, 272, False
    state['phase'] = 'complete'
    return True
