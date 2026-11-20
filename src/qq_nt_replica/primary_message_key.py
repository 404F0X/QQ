from .primary_material_prepare import _address, _auxiliary, _binary, _lookup, _mask, _right
from .primary_material_rounds import _less, _load, _store


_RECIPE = {
    'auxiliary': {1768: 61999, 1773: 29462, 1774: 1679987236, 1782: 45828,
                  1783: 2108828548, 1784: 835873446, 1785: 5972, 1789: 913051650,
                  1795: 275935094, 1801: 407375874, 1805: 232944166,
                  1809: 1567203330, 1813: 497165686, 1817: 1111662593,
                  1823: 877841254, 1827: 1776943105, 1831: 783437494,
                  1835: 1061408770, 1839: 245532230, 1845: 322057558,
                  1850: 560697346, 1852: 43869, 1853: 716710404,
                  1855: 31541, 1860: 31831, 1864: 1364340737,
                  1867: 1467158530, 1872: 53532, 1873: 12052,
                  1877: 1935822515, 1881: 51031, 1885: 1225923667,
                  1888: 432165155, 1893: 36708, 1894: 2017550851,
                  1899: 414208515, 1904: 36430, 1905: 558903811,
                  1908: 31333, 1909: 914117123, 1911: 44831,
                  1912: 1072103940, 1915: 43116, 1916: 613728772,
                  1920: 1221493251, 1921: 1694663379, 1923: 534938419,
                  1931: 28180},
    'flag0': (1904, 1908, 1911, 1915),
    'comparisons': (1885, 1888),
    'cells': tuple(range(1866, 1924)),
}


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'message_key.phi')


def _phis(vm, destinations, sources):
    for destination, source in zip(destinations, sources):
        _phi(vm, destination, source)


def _condition(vm, left, right, destination, *, greater=False):
    _auxiliary(vm, _RECIPE, destination)
    first, second = vm._signed_cell(left, 3 if greater else 7), vm._signed_cell(right, 3 if greater else 7)
    value = first > second if greater else first != second
    vm._write(destination, int(value), 4, 'message_key.condition')
    return bool(vm.cells.value(destination))


def _advance(vm, source, destination, source_next, value, destination_next, width, state):
    _address(vm, 3 if width == 4 else 1, source, source_next, 163)
    _load(vm, source, value, width)
    _address(vm, 3 if width == 4 else 1, destination, destination_next, 163)
    _store(vm, value, destination, width)
    state['copied_bytes'] += width


def _copy_key(vm, state):
    _address(vm, 49, 116, 1766, 145, 163)
    vm.cells.copy_q_clear_owned(1766, 1767)
    _binary(vm, _RECIPE, 1767, 169, 1768, 7, 'and')
    _address(vm, 1, 1521, 1769, 163)
    _load(vm, 1521, 1770, 1)
    _address(vm, 1, 1766, 1771, 163)
    _store(vm, 1770, 1766, 1)
    state['copied_bytes'] += 1
    vm.cells.copy_q_clear_owned(1771, 1772)
    _binary(vm, _RECIPE, 1772, 169, 1773, 7, 'and')
    selected = _condition(vm, 1773, 145, 1774)
    if selected:
        _advance(vm, 1769, 1771, 1775, 1776, 1777, 1, state)
    _phis(vm, (1778, 1779, 1780), (328, 1777, 1775) if selected else (476, 1771, 1769))
    vm.cells.copy_q_clear_owned(1779, 1781)
    _binary(vm, _RECIPE, 1781, 169, 1782, 7, 'and')
    _condition(vm, 1782, 145, 1783)
    _condition(vm, 1778, 158, 1784, greater=True)
    _binary(vm, _RECIPE, 1783, 1784, 1785, 98, 'and')
    selected = bool(vm.cells.value(1785))
    if selected:
        _advance(vm, 1780, 1779, 1786, 1787, 1788, 1, state)
        _binary(vm, _RECIPE, 1778, 396, 1789, 3, 'add')
    _phis(vm, (1790, 1791, 1792), (1789, 1788, 1786) if selected else (1778, 1779, 1780))
    vm.cells.copy_q_clear_owned(1791, 1793)
    vm.cells.copy_q_clear_owned(1792, 1794)
    selected = _condition(vm, 1790, 149, 1795, greater=True)
    if selected:
        _address(vm, 1, 1792, 1796, 172)
        vm.cells.copy_q_clear_owned(1796, 1797)
        _load(vm, 1794, 1798, 4)
        _address(vm, 1, 1791, 1799, 172)
        vm.cells.copy_q_clear_owned(1799, 1800)
        _store(vm, 1798, 1793, 4)
        state['copied_bytes'] += 4
        _binary(vm, _RECIPE, 1790, 1034, 1801, 3, 'add')
    _phis(vm, (1802, 1803, 1804), (1801, 1800, 1797) if selected else (1790, 1793, 1794))
    for remaining, destination, source, condition, source_next, value, destination_next, following, outputs in (
            (1802, 1803, 1804, 1805, 1806, 1807, 1808, 1809, (1810, 1811, 1812)),
            (1810, 1811, 1812, 1813, 1814, 1815, 1816, 1817, (1818, 1819, 1820))):
        selected = _condition(vm, remaining, 149, condition, greater=True)
        if selected:
            _advance(vm, source, destination, source_next, value, destination_next, 4, state)
            _binary(vm, _RECIPE, remaining, 1034, following, 3, 'add')
        _phis(vm, outputs, (following, destination_next, source_next) if selected else
              (remaining, destination, source))
    vm.cells.copy_q_clear_owned(1819, 1821)
    vm.cells.copy_q_clear_owned(1820, 1822)
    for remaining, destination, source, condition, source_next, value, destination_next, following, outputs in (
            (1818, 1821, 1822, 1823, 1824, 1825, 1826, 1827, (1828, 1829, 1830)),
            (1828, 1829, 1830, 1831, 1832, 1833, 1834, 1835, (1836, 1837, 1838))):
        selected = _condition(vm, remaining, 158, condition, greater=True)
        if selected:
            _advance(vm, source, destination, source_next, value, destination_next, 1, state)
            _binary(vm, _RECIPE, remaining, 396, following, 3, 'add')
        _phis(vm, outputs, (following, destination_next, source_next) if selected else
              (remaining, destination, source))
    selected = _condition(vm, 1836, 158, 1839, greater=True)
    if selected:
        _advance(vm, 1838, 1837, 1840, 1841, 1842, 1, state)
    _phis(vm, (1843, 1844), (1842, 1840) if selected else (1837, 1838))
    if _condition(vm, 1836, 269, 1845, greater=True):
        _load(vm, 1844, 1846, 1)
        _store(vm, 1846, 1843, 1)
        state['copied_bytes'] += 1


def mix_primary_message_key(vm):
    vm.primary_message_key_state = {'phase': 'copy', 'copied_bytes': 0,
                                    'mixed_bytes': 0, 'lookups': 0,
                                    'integrity_markers': 0, 'material_bytes': 0,
                                    'flag_writes': 0, 'retained_steps': 0}
    state = vm.primary_message_key_state
    _copy_key(vm, state)
    state['phase'] = 'mix'
    _load(vm, 1520, 1847, 1)
    vm.execute_once(10, (3, 1, 1847, 1848))
    initial = True
    while True:
        _phi(vm, 1849, 158 if initial else 1850)
        if not _less(vm, 1849, 502, 1851):
            break
        _binary(vm, _RECIPE, 1849, 1848, 1852, 3, 'xor')
        _binary(vm, _RECIPE, 1852, 867, 1853, 3, 'mul')
        _right(vm, 1853, 375, 1854, 4)
        _binary(vm, _RECIPE, 1853, 1854, 1855, 3, 'xor')
        vm.execute_once(10, (7, 3, 1849, 1856))
        _address(vm, 1, 1766, 1857, 1856)
        _load(vm, 1857, 1858, 1)
        _mask(vm, 1855, 1859, 1)
        _binary(vm, _RECIPE, 1858, 1859, 1860, 1, 'xor')
        _store(vm, 1860, 1857, 1)
        state['mixed_bytes'] += 1
        _binary(vm, _RECIPE, 1849, 269, 1850, 3, 'add')
        initial = False
    state['phase'] = 'material'
    _load(vm, 1520, 1861, 1)
    vm.cells.copy_q_clear_owned(75, 1862)
    _store(vm, 145, 75, 8)
    initial = True
    while True:
        _phi(vm, 1863, 145 if initial else 1864)
        if not _less(vm, 1863, 163, 1865):
            break
        node, missing = _lookup(vm, 0, 1863, 1381, state, recipe=_RECIPE)
        if vm.cells.value(missing):
            _address(vm, 1, 1862, 1928, 1863)
            _store(vm, 235, 1928, 1)
        else:
            _address(vm, 79, node, 1924, 145, 311)
            _load(vm, 1924, 1925, 8)
            _load(vm, 1925, 1926, 1)
            _address(vm, 1, 1862, 1927, 1863)
            _store(vm, 1926, 1927, 1)
        state['material_bytes'] += 1
        _binary(vm, _RECIPE, 1863, 163, 1864, 7, 'add')
        initial = False
    state['phase'] = 'flag'
    _load(vm, 75, 1929, 8)
    _mask(vm, 1929, 1930, 1)
    _binary(vm, _RECIPE, 1861, 1930, 1931, 1, 'xor')
    _binary(vm, _RECIPE, 1931, 369, 1932, 1, 'xor')
    _store(vm, 1932, 1520, 1)
    state['flag_writes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 13743, 326, 318, False
    state['phase'] = 'complete'
    return True
