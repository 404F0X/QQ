from .primary_material_generation import _retained
from .primary_material_prepare import _address, _auxiliary, _binary, _equal, _lookup, _mask, _right
from .primary_material_rounds import _less, _load, _store
from .primary_vm import PrimarySemanticUnavailable


_RECIPE = {
    'auxiliary': {2008: 1842492915, 2005: 1272979458, 2016: 1015353345,
                  2021: 58135, 2026: 1801595763, 2029: 51519, 2030: 18030,
                  2034: 1845675139, 2037: 579003731, 2043: 764535300,
                  2047: 19205, 2048: 2018611716, 2053: 48237, 2054: 1067872771,
                  2058: 1017991683, 2061: 1464902147, 2065: 2077073923,
                  2068: 44332, 2069: 667939332, 2070: 1842498771,
                  2072: 1178763139, 2012: 972320770, 2090: 14341,
                  2091: 317301252, 2093: 55375, 2098: 23415, 2088: 608849921,
                  2105: 1269559297, 2111: 23637, 2115: 629323395,
                  2119: 12916, 2123: 186798323, 2126: 1993539491,
                  2132: 2067509764, 2137: 1571947012, 2142: 61044,
                  2143: 1166901764, 2146: 60701, 2147: 409719300,
                  2149: 52756, 2150: 1469616644, 2153: 43301,
                  2154: 858444292, 2157: 7021, 2158: 1421914627,
                  2159: 484630547, 2161: 1131606707, 2102: 1364189186,
                  2169: 52828, 2189: 1553120915, 2194: 363327490,
                  2202: 1115488258, 2211: 32284, 2213: 6710, 2214: 55093,
                  2215: 53484, 2218: 21196, 2221: 648204531,
                  2228: 2021548033, 2236: 7534, 2238: 43829, 2239: 50300,
                  2240: 29124, 2244: 1924674051, 2245: 1209950210,
                  2246: 47229, 2247: 42197, 2249: 58617, 2250: 2037543555,
                  2226: 1267302401, 2264: 44085, 2257: 1170132994,
                  2267: 1274257409, 2275: 1012584450, 2284: 845307619,
                  2281: 2115477505, 2289: 1749196691, 2286: 661942274},
    'flag0': (2047, 2053, 2093, 2146, 2169, 2211),
    'comparisons': (2037, 2070, 2072, 2123, 2126, 2161,
                    2189, 2221, 2250, 2284, 2289),
}
_LOOKUPS = (
    dict(_RECIPE, cells=(2014, 2016, 2017, *range(2018, 2073))),
    dict(_RECIPE, cells=tuple(range(2104, 2162))),
)


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'message_material.phi')


def _zero(vm, cells, remaining, pointer, state, *, following=False, wide=False):
    count, next_count, target, next_target, condition = cells
    while True:
        _phi(vm, count, next_count if following else remaining)
        _phi(vm, target, next_target if following else pointer)
        if _equal(vm, _RECIPE, count, 145, condition, 7):
            return
        _binary(vm, _RECIPE, count, 233, next_count, 7, 'add')
        _address(vm, 1, target, next_target, 163)
        _store(vm, 235, target, 1, wide=wide)
        state['cleared_bytes'] += 1
        following = True


def _read_material(vm, number, state):
    if number == 0:
        index, following, condition, base, output = 2011, 2012, 2013, 2015, 2010
        pointer, value_pointer, value, target, empty_target = 2073, 2074, 2075, 2076, 2077
    else:
        index, following, condition, base, output = 2101, 2102, 2103, 1381, 2100
        pointer, value_pointer, value, target, empty_target = 2162, 2163, 2164, 2165, 2166
    initial = True
    while True:
        _phi(vm, index, 145 if initial else following)
        if not _less(vm, index, 163, condition):
            return
        node, missing = _lookup(vm, 0, index, base, state, recipe=_LOOKUPS[number])
        if vm.cells.value(missing):
            _address(vm, 1, output, empty_target, index)
            _store(vm, 235, empty_target, 1)
        else:
            _address(vm, 79, node, pointer, 145, 311)
            _load(vm, pointer, value_pointer, 8)
            _load(vm, value_pointer, value, 1)
            _address(vm, 1, output, target, index)
            _store(vm, value, target, 1)
        state['material_bytes'] += 1
        _binary(vm, _RECIPE, index, 163, following, 7, 'add')
        initial = False


def _copy(vm, source, destination, cells, start, limit, width, state):
    if width == 4:
        index, following, condition, first, first_pointer, value, second, second_pointer = cells
    else:
        index, following, condition, first, value, second = cells
    initial = True
    while True:
        _phi(vm, index, start if initial else following)
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
        state['copied_bytes'] += width
        _binary(vm, _RECIPE, index, 172 if width == 4 else 163, following, 7, 'add')
        initial = False


def _left(vm, source, count, destination, word):
    _auxiliary(vm, _RECIPE, destination)
    first = vm.memory.load(vm.image_base + 0x6D86090, 4)
    second = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((first * first) & 0xFFFFFFFF) | (abs(second) & 0xFFFFFFFF)) >> 31
    amount = vm.memory.load(vm.cells.pointer(count), 4)
    value = 0
    if not amount & 0x80000000 and amount < 32:
        value = (vm._signed_cell(source, 1) & 0xFFFFFFFF) << amount
    vm._write(destination, value, 4, 'message_material.left')
    if extra:
        vm.pc = word + 5
        vm.execute_typed(tuple(vm._operand() for _ in range(4)))


def _or(vm, left, right, destination):
    _auxiliary(vm, _RECIPE, destination)
    vm._write(destination, vm._signed_cell(left, 1) | vm._signed_cell(right, 1),
              8, 'message_material.or')


def _select(vm, condition, true, false, destination):
    source = true if vm.cells.value(condition) else false
    vm._write(destination, vm._signed_cell(source, 1), 8, 'message_material.select')


def _stream(vm, state):
    _right(vm, 2184, 336, 2207, 1)
    _right(vm, 2184, 1641, 2208, 1)
    _binary(vm, _RECIPE, 2207, 2208, 2209, 1, 'xor')
    _right(vm, 2184, 152, 2210, 1)
    _binary(vm, _RECIPE, 2209, 2210, 2211, 1, 'xor')
    _right(vm, 2184, 497, 2212, 1)
    _binary(vm, _RECIPE, 2211, 2212, 2213, 1, 'xor')
    _binary(vm, _RECIPE, 2213, 354, 2214, 1, 'and')
    _left(vm, 2184, 354, 2215, 15286)
    _or(vm, 2215, 2214, 2216)
    _binary(vm, _RECIPE, 2216, 1645, 2217, 1, 'xor')
    _left(vm, 2217, 497, 2218, 15304)
    _right(vm, 2217, 1641, 2219, 1)
    _or(vm, 2218, 2219, 2220)
    _equal(vm, _RECIPE, 2220, 235, 2221, 1, read=False)
    _select(vm, 2221, 2222, 2220, 2223)
    _address(vm, 41, 70, 2224, 145, 145)
    _store(vm, 2223, 2224, 1)
    state['stream_bytes'] += 1
    initial = True
    while True:
        _phi(vm, 2225, 269 if initial else 2226)
        if not _less(vm, 2225, 2187, 2227):
            return
        _binary(vm, _RECIPE, 2225, 396, 2228, 3, 'add')
        vm.execute_once(10, (7, 3, 2228, 2229))
        _address(vm, 41, 70, 2230, 145, 2229)
        _load(vm, 2230, 2231, 1)
        _right(vm, 2231, 336, 2232, 1)
        _right(vm, 2231, 1641, 2233, 1)
        _binary(vm, _RECIPE, 2232, 2233, 2234, 1, 'xor')
        _right(vm, 2231, 152, 2235, 1)
        _binary(vm, _RECIPE, 2234, 2235, 2236, 1, 'xor')
        _right(vm, 2231, 497, 2237, 1)
        _binary(vm, _RECIPE, 2236, 2237, 2238, 1, 'xor')
        _binary(vm, _RECIPE, 2238, 354, 2239, 1, 'and')
        _left(vm, 2231, 354, 2240, 15444)
        _or(vm, 2240, 2239, 2241)
        _mask(vm, 2225, 2242, 1)
        _binary(vm, _RECIPE, 2242, 2243, 2244, 1, 'mul')
        _binary(vm, _RECIPE, 2244, 1645, 2245, 1, 'add')
        _binary(vm, _RECIPE, 2245, 2241, 2246, 1, 'xor')
        _left(vm, 2246, 497, 2247, 15487)
        _right(vm, 2246, 1641, 2248, 1)
        _or(vm, 2247, 2248, 2249)
        _equal(vm, _RECIPE, 2249, 235, 2250, 1, read=False)
        _mask(vm, 2225, 2251, 1)
        _binary(vm, _RECIPE, 2251, 2222, 2252, 1, 'xor')
        _select(vm, 2250, 2252, 2249, 2253)
        vm.execute_once(10, (7, 3, 2225, 2254))
        _address(vm, 41, 70, 2255, 145, 2254)
        _store(vm, 2253, 2255, 1)
        state['stream_bytes'] += 1
        _binary(vm, _RECIPE, 2225, 269, 2226, 3, 'add')
        initial = False


def _decode_record(vm, state):
    vm.execute_once(10, (7, 1, 2186, 2190))
    _address(vm, 41, 69, 2191, 145, 145)
    _binary(vm, _RECIPE, 2190, 1732, 2192, 7, 'and')
    _copy(vm, 2177, 2191, (2193, 2194, 2195, 2196, 2197, 2198, 2199, 2200),
          145, 2192, 4, state)
    _copy(vm, 2177, 2191, (2201, 2202, 2203, 2204, 2205, 2206),
          2192, 2190, 1, state)
    _stream(vm, state)
    initial = True
    while True:
        _phi(vm, 2256, 158 if initial else 2257)
        if not _less(vm, 2256, 2187, 2258):
            break
        vm.execute_once(10, (7, 3, 2256, 2259))
        _address(vm, 41, 70, 2260, 145, 2259)
        _load(vm, 2260, 2261, 1)
        _address(vm, 41, 69, 2262, 145, 2259)
        _load(vm, 2262, 2263, 1)
        _binary(vm, _RECIPE, 2263, 2261, 2264, 1, 'xor')
        _store(vm, 2264, 2262, 1)
        state['decoded_bytes'] += 1
        _binary(vm, _RECIPE, 2256, 269, 2257, 3, 'add')
        initial = False
    _binary(vm, _RECIPE, 2190, 1732, 2265, 7, 'and')
    _copy(vm, 2191, 2180, (2266, 2267, 2268, 2269, 2270, 2271, 2272, 2273),
          145, 2265, 4, state)
    _copy(vm, 2191, 2180, (2274, 2275, 2276, 2277, 2278, 2279),
          2265, 2190, 1, state)
    _zero(vm, (2280, 2281, 2282, 2283, 2284), 184, 2191, state, wide=True)
    _zero(vm, (2285, 2286, 2287, 2288, 2289), 184, 2224, state)
    _load(vm, 71, 2290, 8)


def produce_primary_message_material(vm):
    vm.primary_message_material_state = {'phase': 'clear', 'cleared_bytes': 0,
                                         'lookups': 0, 'integrity_markers': 0,
                                         'material_bytes': 0, 'header_mixed_bytes': 0,
                                         'copied_bytes': 0, 'stream_bytes': 0,
                                         'decoded_bytes': 0, 'published_qwords': 0,
                                         'retained_steps': 0}
    state = vm.primary_message_material_state
    if vm.predecessor not in (318, 333):
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    _zero(vm, (2004, 2005, 2006, 2007, 2008), 172, 952, state,
          following=vm.predecessor == 333)
    _store(vm, 158, 114, 4)
    vm.cells.copy_q_clear_owned(118, 2009)
    _store(vm, 158, 118, 4)
    vm.cells.copy_q_clear_owned(74, 2010)
    _store(vm, 145, 74, 8)
    state['phase'] = 'header'
    _read_material(vm, 0, state)
    _load(vm, 74, 2078, 8)
    _mask(vm, 2078, 2079, 1)
    vm.cells.copy_q_clear_owned(118, 2080)
    _store(vm, 2079, 2080, 1)
    _address(vm, 1, 2080, 2081, 163)
    _store(vm, 152, 2081, 1)
    _address(vm, 75, 106, 2082, 145, 269)
    _load(vm, 2082, 2083, 1)
    _address(vm, 1, 2080, 2084, 166)
    _store(vm, 2083, 2084, 1)
    _load(vm, 2080, 2085, 1)
    vm.execute_once(10, (3, 1, 2085, 2086))
    initial = True
    while True:
        _phi(vm, 2087, 158 if initial else 2088)
        if not _less(vm, 2087, 311, 2089):
            break
        _binary(vm, _RECIPE, 2087, 2086, 2090, 3, 'xor')
        _binary(vm, _RECIPE, 2090, 867, 2091, 3, 'mul')
        _right(vm, 2091, 375, 2092, 4)
        _binary(vm, _RECIPE, 2091, 2092, 2093, 3, 'xor')
        vm.execute_once(10, (7, 3, 2087, 2094))
        _address(vm, 1, 2081, 2095, 2094)
        _load(vm, 2095, 2096, 1)
        _mask(vm, 2093, 2097, 1)
        _binary(vm, _RECIPE, 2096, 2097, 2098, 1, 'xor')
        _store(vm, 2098, 2095, 1)
        state['header_mixed_bytes'] += 1
        _binary(vm, _RECIPE, 2087, 269, 2088, 3, 'add')
        initial = False
    _load(vm, 2080, 2099, 1)
    vm.cells.copy_q_clear_owned(73, 2100)
    _store(vm, 145, 73, 8)
    _read_material(vm, 1, state)
    _load(vm, 73, 2167, 8)
    _mask(vm, 2167, 2168, 1)
    _binary(vm, _RECIPE, 2099, 2168, 2169, 1, 'xor')
    _binary(vm, _RECIPE, 2169, 2170, 2171, 1, 'xor')
    _store(vm, 2171, 2080, 1)
    state['phase'] = 'record'
    _address(vm, 23, 119, 2172, 145, 145)
    _retained(vm, 14975, 352, 349, 1, state)
    vm.cells.copy_q_clear_owned(120, 2174)
    vm.cells.copy_q_clear_owned(121, 2175)
    _retained(vm, 14994, 352, 349, 1, state)
    vm.cells.copy_q_clear_owned(68, 2177)
    _address(vm, 41, 69, 2178, 145, 145)
    _address(vm, 41, 70, 2179, 145, 145)
    vm.cells.copy_q_clear_owned(71, 2180)
    _store(vm, 145, 71, 8)
    _address(vm, 11, 120, 2181, 145, 158)
    _load(vm, 2181, 2182, 8)
    _store(vm, 2182, 68, 8)
    _address(vm, 11, 120, 2183, 145, 269)
    _load(vm, 2183, 2184, 1)
    _address(vm, 11, 120, 2185, 145, 311)
    _load(vm, 2185, 2186, 1)
    vm.execute_once(10, (3, 1, 2186, 2187))
    allowed = False
    for case in (354, 369, 152, 2188):
        if not allowed and vm.cells.value(2186) == vm.cells.value(case):
            allowed = True
    predecessor, result = 352, 145
    if allowed:
        predecessor = 361
        if not _equal(vm, _RECIPE, 2184, 235, 2189, 1):
            state['phase'] = 'decode'
            _decode_record(vm, state)
            predecessor, result = 383, 2290
    state['phase'] = 'publish'
    _phi(vm, 2291, result)
    _store(vm, 2291, 121, 8)
    state['published_qwords'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 15862, 360, predecessor, False
    state['phase'] = 'complete'
    return True
