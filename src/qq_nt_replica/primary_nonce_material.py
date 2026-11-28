from .primary_material_prepare import _address, _binary, _lookup, _mask, _right
from .primary_material_rounds import _less, _load, _store
from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell


_RECIPE = {
    'auxiliary': {1934: 611753986, 1936: 40806, 1938: 35847,
                  1940: 361677315, 1943: 455192577, 1945: 1618374658,
                  1950: 41340, 1951: 14927, 1955: 244513539,
                  1958: 14460, 1963: 2041747091, 1966: 1833065939,
                  1971: 52324, 1972: 1921946115, 1976: 16228,
                  1977: 1416282627, 1983: 871780868, 1986: 43588,
                  1987: 1819419140, 1990: 1011266052, 1993: 19053,
                  1994: 2127249923, 1997: 56693, 1998: 211522052,
                  1999: 854762915, 2001: 1678942771, 930: 1359777794},
    'flag0': (1936, 1938, 1986, 1993),
    'comparisons': (1955, 1966, 2001),
    'cells': tuple(range(1944, 2002)),
}


def refresh_primary_nonce_material(vm):
    vm.primary_nonce_material_state = {'phase': 'refresh', 'rounds': 0, 'lookups': 0,
                                      'integrity_markers': 0, 'published_bytes': 0,
                                      'retained_steps': 0}
    state = vm.primary_nonce_material_state
    initial = True
    while True:
        vm._write(929, vm.cells.value(158 if initial else 930), 8, 'nonce_material.index_phi')
        if not _less(vm, 929, 404, 931):
            break
        _load(vm, 865, 1933, 4)
        _binary(vm, _RECIPE, 1933, 867, 1934, 3, 'add')
        _store(vm, 1934, 865, 4)
        state['rounds'] += 1
        _right(vm, 1934, 504, 1935, 4)
        _binary(vm, _RECIPE, 1934, 1935, 1936, 3, 'xor')
        _right(vm, 1936, 328, 1937, 4)
        _binary(vm, _RECIPE, 1936, 1937, 1938, 3, 'xor')
        _binary(vm, _RECIPE, 1938, 873, 1939, 3, 'and')
        _binary(vm, _RECIPE, 1939, 875, 1940, 3, 'mul')
        _right(vm, 1940, 502, 1941, 4)
        _mask(vm, 1941, 1942, 1)
        _binary(vm, _RECIPE, 1942, 354, 1943, 1, 'add')
        node, missing = _lookup(vm, 0, 929, 1381, state, recipe=_RECIPE)
        if not vm.cells.value(missing):
            _address(vm, 79, node, 2002, 145, 311)
            _load(vm, 2002, 2003, 8)
            _store(vm, 1943, 2003, 1)
            state['published_bytes'] += 1
        _binary(vm, _RECIPE, 929, 269, 930, 3, 'add')
        initial = False
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 5790, 123, 120, False
    state['phase'] = 'complete'
    finish_primary_nonce_material(vm)
    return True


def finish_primary_nonce_material(vm):
    _indexed_pointer(vm, 5790, 932, 49, 113, (145, 145))
    _native_call(vm, 5798, 5807, 121, 157, (932, 158, 205), 933)
    vm.pc = 5812
    vm.cells.copy_q_clear_owned(114, 934)
    vm.pc = 5817
    vm.cells.copy_q_clear_owned(115, 935)
    _store_cell(vm, 5817, 4, 158, 115)
    _native_call(vm, 5821, 5827, 129, 454, (), 936)
