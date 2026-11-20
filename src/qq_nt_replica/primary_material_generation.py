from .primary_material_rounds import _less, _load, _next, _pointer, _store
from .primary_material_state import _comparison, _flag0
from .primary_rolling_state import _shift


_GROUPS = (
    {'seed': 4375, 'buffer': 4380,
     'deposit': (4381, 4382, 4383, 4387, 4388, 4389, 4390, 4392, 4393),
     'mark': (4394, 4395, 4396, 4397, 4398, 4399),
     'fill': (4400, 4401, 4402, 4403, 4404, 4405, 4406, 4407,
              4408, 4410, 4411, 4412, 4413, 4414),
     'shift_word': 32347, 'memset': (32324, 714, 712),
     'aux': (33935, 1012129794, 556994561, 1891765363, None, None, 519434241),
     'capture': None},
    {'seed': 4180, 'buffer': 4415,
     'deposit': (4416, 4417, 4418, 4421, 4422, 4423, 4424, 4425, 4426),
     'mark': (4427, 4428, 4429, 4430, 4431, 4432),
     'fill': tuple(range(4433, 4447)),
     'shift_word': 32597, 'memset': (32574, 724, 722),
     'aux': (24812, 1366708225, 1215025154, 1909648147, 35847, None, 1620631554),
     'capture': (32548, 720, 717)},
    {'seed': 4248, 'buffer': 4447,
     'deposit': (4448, 4449, 4450, 4453, 4454, 4455, 4456, 4457, 4458),
     'mark': (4459, 4460, 4461, 4462, 4463, 4464),
     'fill': tuple(range(4465, 4479)),
     'shift_word': 32852, 'memset': (32829, 734, 732),
     'aux': (26333, 1778081794, 1123807234, 2099442803, 7438, 57135, 1617063938),
     'capture': (32803, 730, 727)},
)


_SHARED_NATIVE_CALLS = {
    703: (123, 215, (148, 216), None, 710),
    1108: (123, 215, (148, 279), None, 1115),
    1135: (123, 215, (148, 279), None, 1142),
    1160: (125, 288, (102, 279), 287, 1168),
    1243: (121, 157, (297, 158, 208), 298, 1252),
    1260: (127, 301, (299,), 300, 1267),
    1335: (123, 215, (148, 216), None, 1342),
    2353: (129, 454, (), 453, 2359),
    2701: (121, 157, (509, 158, 175), 510, 2710),
    3323: (123, 215, (148, 279), None, 3330),
    3547: (121, 157, (621, 158, 205), 622, 3556),
    3564: (131, 624, (10, 11, 623, 375), None, 3573),
    3591: (121, 157, (299, 158, 205), 627, 3600),
    3608: (121, 157, (628, 158, 196), 629, 3617),
    3757: (121, 157, (645, 158, 193), 646, 3766),
    3886: (133, 659, (647,), 658, 3893),
    3906: (137, 663, (658, 630), 662, 3914),
    3932: (139, 666, (299,), 667, 3939),
    4066: (131, 624, (669, 686, 299, 375), None, 4075),
    4118: (121, 157, (693, 158, 695), 694, 4127),
    4144: (143, 698, (697, 96, 299, 187), None, 4153),
    4343: (121, 157, (727, 158, 729), 728, 4352),
    9571: (121, 157, (1448, 158, 205), 1449, 9580),
    10182: (121, 157, (1533, 158, 205), 1534, 10191),
    10237: (121, 157, (1542, 158, 196), 1543, 10246),
    11562: (152, 1719, (1717,), 1718, 11569),
    11569: (152, 1719, (1717,), 1720, 11576),
    11919: (154, 1764, (1720, 1523, 502, 1718, 1715), 1763, 11930),
    11930: (156, 1765, (1718,), None, 11936),
    11936: (156, 1765, (1720,), None, 11942),
    14975: (121, 157, (2172, 158, 187), 2173, 14984),
    14994: (158, 2176, (235, 502, 502, 120), None, 15003),
    25788: (121, 157, (3637, 158, 3639), 3638, 25797),
    25805: (121, 157, (3640, 158, 190), 3641, 25814),
    25930: (121, 157, (3651, 158, 199), 3652, 25939),
    26091: (121, 157, (3671, 158, 205), 3672, 26100),
    26288: (121, 157, (3693, 158, 199), 3694, 26297),
    26441: (168, 3708, (328, 3635, 27), 3707, 26450),
    26491: (170, 3715, (3710, 3713, 3716), 3714, 26500),
    26513: (172, 3719, (3713,), 3718, 26520),
    26520: (174, 3721, (3718, 3673), 3720, 26528),
    26541: (174, 3721, (3718, 3695), 3723, 26549),
    26562: (174, 3721, (3718, 3642), 3725, 26570),
    26583: (174, 3721, (3718, 3653), 3727, 26591),
    26652: (121, 157, (3732, 158, 3639), 3733, 26661),
    26669: (121, 157, (3734, 158, 199), 3735, 26678),
    26834: (133, 659, (3736,), 3750, 26841),
    26862: (121, 157, (3752, 158, 213), 3753, 26871),
    27099: (137, 663, (3750, 3754), 3776, 27107),
    27142: (170, 3778, (660, 3781, 3716), 3782, 27151),
    27164: (156, 3784, (3781,), None, 27170),
    27178: (121, 157, (3785, 158, 181), 3786, 27187),
    27381: (121, 157, (3806, 158, 193), 3807, 27390),
    27530: (121, 157, (3819, 158, 187), 3820, 27539),
    27647: (174, 3721, (3781, 3787), 3830, 27655),
    27668: (174, 3721, (3781, 3796), 3832, 27676),
    27689: (174, 3721, (3781, 3808), 3834, 27697),
    27710: (174, 3721, (3781, 3821), 3836, 27718),
    27806: (176, 3849, (311, 158), 3848, 27814),
    27849: (178, 3856, (3848, 22), 3855, 27857),
    27870: (139, 3859, (3848,), 3858, 27877),
    27891: (121, 157, (3862, 158, 201), 3863, 27900),
    27998: (180, 3877, (3875, 3864), 3876, 28006),
    28030: (178, 3881, (3848, 22), 3880, 28038),
    28050: (139, 3859, (3848,), 3883, 28057),
    28113: (121, 157, (3890, 158, 213), 3891, 28122),
    28130: (121, 157, (3892, 158, 169), 3893, 28139),
    28387: (121, 157, (3916, 158, 193), 3917, 28396),
    28528: (133, 659, (3918,), 3930, 28535),
    28556: (121, 157, (3932, 158, 196), 3933, 28565),
    28709: (137, 663, (3930, 3934), 3946, 28717),
    28744: (184, 3948, (3894, 3914), 3951, 28752),
    28765: (186, 3955, (3951,), 3954, 28772),
    28812: (121, 157, (3960, 158, 193), 3961, 28821),
    28953: (133, 659, (3962,), 3973, 28960),
    28981: (121, 157, (3975, 158, 196), 3976, 28990),
    29134: (137, 663, (3973, 3977), 3989, 29142),
    29177: (121, 157, (3993, 158, 187), 3994, 29186),
    29302: (121, 157, (4004, 158, 201), 4005, 29311),
    29467: (184, 3991, (3995, 513), 4020, 29475),
    29488: (184, 3991, (4006, 513), 4022, 29496),
    29569: (121, 157, (4033, 158, 3639), 4034, 29578),
    29586: (121, 157, (4035, 158, 199), 4036, 29595),
    29751: (133, 659, (4037,), 4050, 29758),
    29778: (121, 157, (4052, 158, 213), 4053, 29787),
    30015: (137, 663, (4050, 4054), 4073, 30023),
    30063: (170, 4075, (4079, 4077, 3716), 4080, 30072),
    30085: (156, 3784, (4077,), None, 30091),
    30099: (174, 3721, (4077, 4082), 4084, 30107),
    30128: (174, 3721, (4077, 4086), 4088, 30136),
    30157: (174, 3721, (4077, 4090), 4092, 30165),
    31278: (121, 157, (4249, 158, 4251), 4250, 31287),
    31401: (158, 2176, (235, 158, 502, 18), None, 31410),
    34861: (125, 288, (102, 216), 4725, 34869),
    35309: (133, 659, (4787,), 4789, 35316),
    36360: (121, 157, (4934, 158, 193), 4935, 36369),
    36501: (133, 659, (4936,), 4947, 36508),
    36529: (121, 157, (4949, 158, 199), 4950, 36538),
    36694: (137, 663, (4947, 4951), 4964, 36702),
    36720: (200, 4967, (44,), None, 36726),
    36774: (121, 157, (4975, 158, 4251), 4976, 36783),
}


def _retained(vm, word, block, predecessor, count, state):
    from .primary_vm import PrimarySemanticUnavailable

    if not getattr(vm, '_direct_main_bound', False):
        import hashlib

        if hashlib.sha256(vm.program.raw).hexdigest() != '28afc919ac1b8783ecbe6ddea52ebba5ea41492573609fa7cf634467ecaa00b9':
            raise PrimarySemanticUnavailable('direct main state spans require the fixed primary program')
        vm._direct_main_bound = True
    vm.pc, vm.block, vm.predecessor, vm.initial_block = word, block, predecessor, False
    if word in _SHARED_NATIVE_CALLS:
        from .primary_sign import _invoke_host

        signature, callee, arguments, destination, end = _SHARED_NATIVE_CALLS[word]
        vm.pc = end
        address = vm.cells.value(callee)
        vm.host_calls.append((word, address, arguments, signature))
        result = _invoke_host(vm, address, arguments, signature)
        if destination is not None:
            vm._write(destination, result, 8, 'high.native_result_q')
        return
    if word == 4027:
        _context_variadic(vm)
        return
    if word == 32257:
        vm.pc = 32266
        selected = {711: 4374, 680: 145, 689: 145}.get(predecessor)
        if selected is None:
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        vm._write(4375, vm.cells.value(selected), 8, 'L9.phi_q')
        word = 32266
    if word == 32266:
        for site, base, destination in ((32266, 52, 4376), (32274, 53, 4377),
                (32282, 54, 4378), (32290, 55, 4379), (32298, 52, 4380)):
            _initial_pointer(vm, site, base, destination)
        return
    pointers = {32324: (47, 4384), 32548: (53, 4415),
                         32574: (47, 4419), 32803: (54, 4447),
                         32829: (47, 4451), 33062: (55, 4479)}
    if word not in pointers:
        raise PrimarySemanticUnavailable(f'direct main state span at word{word} is unavailable')
    base, destination = pointers[word]
    _initial_pointer(vm, word, base, destination)
    if count == 2:
        from .primary_sign import _invoke_host

        site = word + 8
        vm.pc = site + 9
        address = vm.cells.value(157)
        arguments = (destination, 158, 4386)
        vm.host_calls.append((site, address, arguments, 121))
        result = _invoke_host(vm, address, arguments, 121)
        vm._write(destination + 1, result, 8, 'high.native_result_q')


def _context_variadic(vm):
    from .primary_sign import _invoke_host
    from .primary_vm import PrimarySemanticUnavailable

    memory, base = vm.memory, vm.image_base
    vm.pc = 4028
    if memory.load(base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('variadic call current-global alternate route is unavailable')
    vm.pc = 4032
    x = memory.load(base + 0x677E1B4, 4, signed=True)
    y = memory.load(base + 0x677E1B8, 4, signed=True)
    if (((x * x + y * y) & 0xFFFFFFFF) | ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('variadic call F-global alternate route is unavailable')
    vm.pc = 4034
    x = memory.load(base + 0x6D86090, 4)
    y = memory.load(base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('variadic call G-global alternate route is unavailable')
    vm.pc = 4038
    arguments = (679, 680, 676)
    address = vm.cells.value(683)
    vm.host_calls.append((4027, address, arguments, 141))
    result = _invoke_host(vm, address, arguments, 141, argument_types=(2, 2, 3))
    vm._write(682, result, 8, 'high.variadic_result_q')


def _initial_pointer(vm, word, base, destination):
    vm.pc = word + 7
    first = vm.memory.load(vm.cells.pointer(145), 4)
    vm.pc = word + 8
    second = vm.memory.load(vm.cells.pointer(145), 4)
    vm._write(destination, vm.cells.value(base) + 37 * first + second,
              8, 'high.indexed_pointer_q')


def _buffer_pointer(vm, base, index, destination):
    first = vm.memory.load(vm.cells.pointer(145), 4)
    second = vm.memory.load(vm.cells.pointer(index), 4)
    vm._write(destination, vm.cells.value(base) + 37 * first + second,
              8, 'material_generation.buffer_pointer')


def _produce_group(vm, group, number, state):
    if group['capture'] is not None:
        _retained(vm, *group['capture'], 1, state)
    state['phase'] = 'deposit'
    index, following, condition, shifted, extracted, byte, perm, offset, target = group['deposit']
    initial = True
    while True:
        vm._write(index, vm.cells.value(145 if initial else following),
                  8, 'material_generation.deposit_index')
        if not _less(vm, index, 184, condition):
            break
        vm.auxiliary = (0, group['aux'][0])
        _shift(vm, index, 169, shifted, group['shift_word'], 8)
        seed = vm.memory.load(vm.cells.pointer(group['seed']), 8)
        count = vm.memory.load(vm.cells.pointer(shifted), 1)
        vm._write(extracted, seed >> (count & 63), 8, 'material_generation.seed_shift')
        vm._write(byte, vm.cells.value(extracted) & 255, 8, 'material_generation.seed_byte')
        _pointer(vm, 4391, index, perm, stride=8, array=True)
        _load(vm, perm, offset, 8)
        _pointer(vm, group['buffer'], offset, target)
        _store(vm, byte, target, 1)
        state['selected_bytes'] += 1
        vm.auxiliary = (0, group['aux'][1])
        _next(vm, index, 163, following)
        initial = False
    _retained(vm, *group['memset'], 2, state)
    state['memsets'] += 1
    state['phase'] = 'mark'
    index, following, condition, perm, offset, target = group['mark']
    initial = True
    while True:
        vm._write(index, vm.cells.value(145 if initial else following),
                  8, 'material_generation.mark_index')
        if not _less(vm, index, 184, condition):
            break
        _pointer(vm, 4391, index, perm, stride=8, array=True)
        _load(vm, perm, offset, 8)
        _buffer_pointer(vm, 47, offset, target)
        _store(vm, 354, target, 1)
        state['marked_bytes'] += 1
        vm.auxiliary = (0, group['aux'][2])
        _next(vm, index, 163, following)
        initial = False
    state['phase'] = 'fill'
    (index, following, condition, bitmap_pointer, marked, empty,
     first_pointer, first, second_pointer, second, mixed, byte, value, target) = group['fill']
    initial = True
    while True:
        vm._write(index, vm.cells.value(145 if initial else following),
                  8, 'material_generation.fill_index')
        if not _less(vm, index, 4386, condition):
            break
        _buffer_pointer(vm, 47, index, bitmap_pointer)
        _load(vm, bitmap_pointer, marked, 1)
        vm.auxiliary = (0, group['aux'][3])
        _comparison(vm)
        vm._write(empty, int(vm._signed_cell(marked, 1) == vm._signed_cell(235, 1)),
                  4, 'material_generation.empty_mark')
        if vm.cells.value(empty):
            _pointer(vm, group['buffer'], 203, first_pointer)
            _load(vm, first_pointer, first, 1)
            _pointer(vm, group['buffer'], 4409, second_pointer)
            _load(vm, second_pointer, second, 1)
            if group['aux'][4] is not None:
                vm.auxiliary = (0, group['aux'][4])
            if number == 1:
                _flag0(vm)
            vm._write(mixed, vm._signed_cell(first, 1) ^ vm._signed_cell(second, 1),
                      8, 'material_generation.anchor_xor')
            vm._write(byte, vm.cells.value(index) & 255, 8, 'material_generation.index_byte')
            if group['aux'][5] is not None:
                vm.auxiliary = (0, group['aux'][5])
            vm._write(value, vm._signed_cell(mixed, 1) ^ vm._signed_cell(byte, 1),
                      8, 'material_generation.feedback_byte')
            _pointer(vm, group['buffer'], index, target)
            _store(vm, value, target, 1, wide=number == 1)
            state['filled_bytes'] += 1
            state['filled_by_group'][number] += 1
        vm.auxiliary = (0, group['aux'][6])
        _next(vm, index, 163, following)
        initial = False


def _copy(vm, source, destination, cells, auxiliaries, state):
    (index, following, condition, first_pointer, first_copy, word,
     second_pointer, second_copy, tail, next_tail, tail_condition,
     source_tail, byte, target_tail) = cells
    initial = True
    while True:
        vm._write(index, vm.cells.value(145 if initial else following),
                  8, 'material_generation.copy_index')
        if not _less(vm, index, 4409, condition):
            break
        _pointer(vm, source, index, first_pointer)
        vm.execute_once(15, (4, 2, first_pointer, first_copy))
        state['pointer_copies'] += 1
        _load(vm, first_copy, word, 4)
        _pointer(vm, destination, index, second_pointer)
        vm.execute_once(15, (4, 2, second_pointer, second_copy))
        state['pointer_copies'] += 1
        _store(vm, word, second_copy, 4)
        state['copy_bytes'] += 4
        vm.auxiliary = (0, auxiliaries[0])
        _next(vm, index, 172, following)
        initial = False
    initial = True
    while True:
        vm._write(tail, vm.cells.value(4409 if initial else next_tail),
                  8, 'material_generation.tail_index')
        if not _less(vm, tail, 4386, tail_condition):
            break
        _pointer(vm, source, tail, source_tail)
        _load(vm, source_tail, byte, 1)
        _pointer(vm, destination, tail, target_tail)
        _store(vm, byte, target_tail, 1)
        state['copy_bytes'] += 1
        vm.auxiliary = (0, auxiliaries[1])
        _next(vm, tail, 163, next_tail)
        initial = False


def _combine(vm, source, other, destination, cells, auxiliaries, state, *, xor):
    (index, following, condition, perm, offset, first_pointer,
     first, second_pointer, second, value, target) = cells
    initial = True
    while True:
        vm._write(index, vm.cells.value(145 if initial else following),
                  8, 'material_generation.combine_index')
        if not _less(vm, index, 184, condition):
            break
        _pointer(vm, 4391, index, perm, stride=8, array=True)
        _load(vm, perm, offset, 8)
        _pointer(vm, source, offset, first_pointer)
        _load(vm, first_pointer, first, 1)
        _pointer(vm, other, offset, second_pointer)
        _load(vm, second_pointer, second, 1)
        if xor:
            vm.auxiliary = (0, auxiliaries[0])
            _flag0(vm)
            result = vm._signed_cell(second, 1) ^ vm._signed_cell(first, 1)
        else:
            result = vm._signed_cell(first, 1) | vm._signed_cell(second, 1)
        vm._write(value, result, 8, 'material_generation.selected_result')
        _pointer(vm, destination, offset, target)
        _store(vm, value, target, 1, wide=not xor)
        state['selected_bytes'] += 1
        vm.auxiliary = (0, auxiliaries[1])
        _next(vm, index, 163, following)
        initial = False


def generate_primary_material(vm):
    vm.primary_material_generation_state = {'phase': 'pointers', 'selected_bytes': 0,
                                          'marked_bytes': 0, 'filled_bytes': 0,
                                          'filled_by_group': [0, 0, 0], 'memsets': 0,
                                          'copy_bytes': 0, 'pointer_copies': 0,
                                          'retained_steps': 0}
    state = vm.primary_material_generation_state
    if vm.pc == 32266:
        _retained(vm, 32266, 688, vm.predecessor, 5, state)
    else:
        _retained(vm, 32257, 688, vm.predecessor, 6, state)
    for number, group in enumerate(_GROUPS):
        _produce_group(vm, group, number, state)
    _retained(vm, 33062, 740, 737, 1, state)
    state['phase'] = 'third_copy'
    _copy(vm, 4415, 4479, tuple(range(4480, 4494)), (560185346, 1970573313), state)
    state['phase'] = 'third_selected'
    _combine(vm, 4415, 4447, 4479, tuple(range(4494, 4505)),
             (19582, 1674567682), state, xor=True)
    state['phase'] = 'material_copy'
    _copy(vm, 4380, 4262, tuple(range(4505, 4519)), (1565753345, 1115807745), state)
    state['phase'] = 'material_selected'
    _combine(vm, 4380, 4479, 4262, tuple(range(4519, 4530)),
             (None, 1714073601), state, xor=False)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 33452, 757, 755, False
    state['phase'] = 'complete'
    return True
