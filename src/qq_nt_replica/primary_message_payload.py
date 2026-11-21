from .primary_material_prepare import _address, _auxiliary, _binary, _lookup, _mask, _right
from .primary_material_rounds import _less, _load, _store


_RECIPE = {
    'auxiliary': {2296: 831665092, 2305: 1741824260, 2306: 1441964806,
                  2311: 1868570625, 2317: 1948418516, 2318: 1036172022,
                  2323: 1870458882, 2329: 1737675158, 2335: 2072334337,
                  2339: 853685398, 2343: 1574359042, 2347: 2061692214,
                  2351: 2013319170, 2357: 2062726534, 2361: 2068090882,
                  2365: 187883238, 2369: 1815044098, 2373: 1396891974,
                  2379: 689046598, 2387: 2117242881, 2393: 40772,
                  2397: 527573955, 2400: 16181, 2405: 291635955,
                  2408: 1839361923, 2413: 35933, 2414: 658125316,
                  2418: 31606, 2419: 2129560067, 2424: 28164,
                  2425: 963678724, 2428: 7767, 2429: 1121280515,
                  2432: 860172804, 2435: 44567, 2436: 2128577027,
                  2439: 64596, 2440: 1624916483, 2441: 179444739,
                  2443: 675417187, 2383: 1963515905, 2456: 1367339523,
                  2458: 23093, 2463: 24071, 2453: 1459838978,
                  2470: 1110384642, 2475: 50983, 2480: 1277314419,
                  2484: 32813, 2488: 1489129859, 2491: 2054349923,
                  2497: 1926337027, 2501: 47692, 2502: 1823343108,
                  2507: 19271, 2508: 1610838531, 2511: 27148,
                  2512: 863330820, 2514: 48901, 2515: 2117685763,
                  2519: 2073625092, 2522: 55669, 2523: 1019339267,
                  2524: 186811859, 2526: 898787683, 2467: 1715994625,
                  2534: 27399},
    'flag0': (2393, 2418, 2439, 2458, 2514, 2522),
    'comparisons': (2397, 2405, 2443, 2480, 2488, 2491, 2526),
}
_LOOKUPS = (
    dict(_RECIPE, cells=(2385, 2387, 2388, *range(2389, 2444))),
    dict(_RECIPE, cells=tuple(range(2469, 2527))),
)


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'message_payload.phi')


def _phis(vm, destinations, sources):
    for destination, source in zip(destinations, sources):
        _phi(vm, destination, source)


def _condition(vm, left, right, destination, *, greater=False):
    _auxiliary(vm, _RECIPE, destination)
    typ = 3 if greater else 7
    first, second = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    vm._write(destination, int(first > second if greater else first != second),
              4, 'message_payload.condition')
    return bool(vm.cells.value(destination))


def _advance(vm, source, destination, source_next, value, destination_next, width, state, *, wide=False):
    _address(vm, 3 if width == 4 else 1, source, source_next, 163)
    _load(vm, source, value, width)
    _address(vm, 3 if width == 4 else 1, destination, destination_next, 163)
    _store(vm, value, destination, width, wide=wide)
    state['copied_bytes'] += width


def _copy_word(vm, state):
    _address(vm, 23, 119, 2292, 145, 145)
    _address(vm, 23, 119, 2293, 145, 163)
    vm.cells.copy_q_clear_owned(2293, 2294)
    _binary(vm, _RECIPE, 2294, 169, 2295, 7, 'and')
    selected = _condition(vm, 2295, 145, 2296)
    if selected:
        _advance(vm, 2175, 2293, 2297, 2298, 2299, 1, state, wide=True)
    _phis(vm, (2300, 2301, 2302), (476, 2299, 2297) if selected else (502, 2293, 2175))
    for remaining, destination, source, cast, masked, unaligned, positive, condition, source_next, value, destination_next, following, outputs in (
            (2300, 2301, 2302, 2303, 2304, 2305, 2306, 2307, 2308, 2309, 2310, 2311,
             (2312, 2313, 2314)),
            (2312, 2313, 2314, 2315, 2316, 2317, 2318, 2319, 2320, 2321, 2322, 2323,
             (2324, 2325, 2326))):
        vm.cells.copy_q_clear_owned(destination, cast)
        _binary(vm, _RECIPE, cast, 169, masked, 7, 'and')
        _condition(vm, masked, 145, unaligned)
        _condition(vm, remaining, 158, positive, greater=True)
        _binary(vm, _RECIPE, unaligned, positive, condition, 98, 'and')
        selected = bool(vm.cells.value(condition))
        if selected:
            _advance(vm, source, destination, source_next, value, destination_next, 1, state)
            _binary(vm, _RECIPE, remaining, 396, following, 3, 'add')
        _phis(vm, outputs, (following, destination_next, source_next) if selected else
              (remaining, destination, source))
    vm.cells.copy_q_clear_owned(2325, 2327)
    vm.cells.copy_q_clear_owned(2326, 2328)
    selected = _condition(vm, 2324, 149, 2329, greater=True)
    if selected:
        _address(vm, 1, 2326, 2330, 172)
        vm.cells.copy_q_clear_owned(2330, 2331)
        _load(vm, 2328, 2332, 4)
        _address(vm, 1, 2325, 2333, 172)
        vm.cells.copy_q_clear_owned(2333, 2334)
        _store(vm, 2332, 2327, 4, wide=True)
        state['copied_bytes'] += 4
        _binary(vm, _RECIPE, 2324, 1034, 2335, 3, 'add')
    _phis(vm, (2336, 2337, 2338), (2335, 2334, 2331) if selected else (2324, 2327, 2328))
    for remaining, destination, source, condition, source_next, value, destination_next, following, outputs in (
            (2336, 2337, 2338, 2339, 2340, 2341, 2342, 2343, (2344, 2345, 2346)),
            (2344, 2345, 2346, 2347, 2348, 2349, 2350, 2351, (2352, 2353, 2354))):
        selected = _condition(vm, remaining, 149, condition, greater=True)
        if selected:
            _advance(vm, source, destination, source_next, value, destination_next, 4, state)
            _binary(vm, _RECIPE, remaining, 1034, following, 3, 'add')
        _phis(vm, outputs, (following, destination_next, source_next) if selected else
              (remaining, destination, source))
    vm.cells.copy_q_clear_owned(2353, 2355)
    vm.cells.copy_q_clear_owned(2354, 2356)
    for remaining, destination, source, condition, source_next, value, destination_next, following, outputs in (
            (2352, 2355, 2356, 2357, 2358, 2359, 2360, 2361, (2362, 2363, 2364)),
            (2362, 2363, 2364, 2365, 2366, 2367, 2368, 2369, (2370, 2371, 2372))):
        selected = _condition(vm, remaining, 158, condition, greater=True)
        if selected:
            _advance(vm, source, destination, source_next, value, destination_next, 1, state)
            _binary(vm, _RECIPE, remaining, 396, following, 3, 'add')
        _phis(vm, outputs, (following, destination_next, source_next) if selected else
              (remaining, destination, source))
    selected = _condition(vm, 2370, 158, 2373, greater=True)
    if selected:
        _advance(vm, 2372, 2371, 2374, 2375, 2376, 1, state, wide=True)
    _phis(vm, (2377, 2378), (2376, 2374) if selected else (2371, 2372))
    if _condition(vm, 2370, 269, 2379, greater=True):
        _load(vm, 2378, 2380, 1)
        _store(vm, 2380, 2377, 1)
        state['copied_bytes'] += 1


def _read_material(vm, number, state):
    if number == 0:
        index, following, condition, base, output = 2382, 2383, 2384, 2386, 2381
        pointer, value_pointer, value, target, empty_target = 2444, 2445, 2446, 2447, 2448
    else:
        index, following, condition, base, output = 2466, 2467, 2468, 1381, 2465
        pointer, value_pointer, value, target, empty_target = 2527, 2528, 2529, 2530, 2531
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


def assemble_primary_message_payload(vm):
    vm.primary_message_payload_state = {'phase': 'copy', 'copied_bytes': 0,
                                        'lookups': 0, 'integrity_markers': 0,
                                        'material_bytes': 0, 'mixed_bytes': 0,
                                        'tag_writes': 0, 'retained_steps': 0}
    state = vm.primary_message_payload_state
    _copy_word(vm, state)
    state['phase'] = 'material'
    vm.cells.copy_q_clear_owned(36, 2381)
    _store(vm, 145, 36, 8)
    _read_material(vm, 0, state)
    _load(vm, 36, 2449, 8)
    _mask(vm, 2449, 2450, 1)
    _store(vm, 2450, 2292, 1)
    state['tag_writes'] += 1
    vm.execute_once(10, (3, 1, 2450, 2451))
    state['phase'] = 'mix'
    initial = True
    while True:
        _phi(vm, 2452, 158 if initial else 2453)
        if not _less(vm, 2452, 502, 2454):
            break
        _binary(vm, _RECIPE, 2452, 2451, 2455, 3, 'xor')
        _binary(vm, _RECIPE, 2455, 867, 2456, 3, 'mul')
        _right(vm, 2456, 375, 2457, 4)
        _binary(vm, _RECIPE, 2456, 2457, 2458, 3, 'xor')
        vm.execute_once(10, (7, 3, 2452, 2459))
        _address(vm, 1, 2293, 2460, 2459)
        _load(vm, 2460, 2461, 1)
        _mask(vm, 2458, 2462, 1)
        _binary(vm, _RECIPE, 2461, 2462, 2463, 1, 'xor')
        _store(vm, 2463, 2460, 1)
        state['mixed_bytes'] += 1
        _binary(vm, _RECIPE, 2452, 269, 2453, 3, 'add')
        initial = False
    _load(vm, 2292, 2464, 1)
    vm.cells.copy_q_clear_owned(35, 2465)
    _store(vm, 145, 35, 8)
    _read_material(vm, 1, state)
    state['phase'] = 'tag'
    _load(vm, 35, 2532, 8)
    _mask(vm, 2532, 2533, 1)
    _binary(vm, _RECIPE, 2464, 2533, 2534, 1, 'xor')
    _binary(vm, _RECIPE, 2534, 2535, 2536, 1, 'xor')
    _store(vm, 2536, 2292, 1)
    state['tag_writes'] += 1
    _address(vm, 75, 106, 2537, 145, 502, 145)
    _load(vm, 2537, 2538, 1)
    _address(vm, 9, 122, 2539, 145, 145)
    _address(vm, 9, 123, 2540, 145, 145)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 17720, 429, 421, False
    state['phase'] = 'complete'
    return True
