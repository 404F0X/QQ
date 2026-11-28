from .primary_material_segment import decode_primary_material_segment
from .primary_material_seed import decode_primary_material_seed
from .primary_material_key import decode_primary_material_key
from .primary_material_state import _comparison
from .primary_material_schedule import (_array_pointer, _clear, _copy, _first_byte,
                                        _following_bytes, _xor)


def _indexed(vm, destination, base, typ, first, second=None):
    end = vm.pc
    vm.pc = end - int(second is not None)
    index = vm.memory.load(vm.cells.pointer(first), 4)
    offset = vm.program.size(typ) * index
    if second is not None:
        vm.pc = end
        index = vm.memory.load(vm.cells.pointer(second), 4)
        delta, typ = vm._indexed_offset(typ, index)
        offset += delta
    vm._write(destination, vm.cells.value(base) + offset, 8, 'record_frame.pointer')


def _load(vm, source, destination, width):
    value = vm.memory.load(vm.cells.value(source), width)
    vm._write(destination, value, 8 if width == 8 else 4, 'record_frame.load')


def _store(vm, source, destination, width, source_width):
    pointer = vm.cells.value(destination)
    value = vm.memory.load(vm.cells.pointer(source), source_width)
    vm.memory.store(pointer, value, width, source='record_frame.store')


def _host(vm, word, arguments):
    address = vm.cells.value(2176)
    vm.host_calls.append((word, address, arguments, 158))
    from .primary_sign import _invoke_host
    _invoke_host(vm, address, arguments, 158)


def _join(vm, end, destination, success, entry, zero, final):
    vm.pc = end
    selected = success if vm.predecessor == final else 145
    if vm.predecessor not in (entry, zero, final):
        from .primary_vm import PrimarySemanticUnavailable
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(destination, vm.cells.value(selected), 8, 'record_frame.phi')


def _shift_feedback(vm):
    vm.pc = 18534
    first = vm.memory.load(vm.image_base + 0x6D86090, 4)
    second = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((first * first) & 0xFFFFFFFF) | (abs(second) & 0xFFFFFFFF)) >> 31
    vm.pc = 18538
    vm.execute_typed((1, 2623, 354, 2653))
    if extra:
        vm.execute_typed(tuple(vm._operand() for _ in range(4)))



def run_primary_segment_record_frame(vm):
    vm.primary_record_frame_state = {'frame': 'segment', 'phase': 'prefix', 'branch': None, 'retained_steps': 0}
    state = vm.primary_record_frame_state
    vm.pc = 18257
    _host(vm, 18248, (354, 158, 269, 124))
    vm.pc = 18262
    vm.execute_once(15, (2, 8, 32, 2616))
    vm.pc = 18270
    _indexed(vm, 2617, 69, 41, 145, 145)
    vm.pc = 18278
    _indexed(vm, 2618, 70, 41, 145, 145)
    vm.pc = 18283
    vm.execute_once(15, (2, 8, 33, 2619))
    vm.pc = 18287
    _store(vm, 145, 33, 8, 8)
    vm.pc = 18295
    _indexed(vm, 2620, 124, 11, 145, 158)
    vm.pc = 18299
    _load(vm, 2620, 2621, 8)
    vm.pc = 18303
    _store(vm, 2621, 32, 8, 8)
    vm.pc = 18311
    _indexed(vm, 2622, 124, 11, 145, 269)
    vm.pc = 18315
    _load(vm, 2622, 2623, 1)
    vm.pc = 18323
    _indexed(vm, 2624, 124, 11, 145, 311)
    vm.pc = 18327
    _load(vm, 2624, 2625, 1)
    vm.pc = 18332
    vm.execute_once(10, (3, 1, 2625, 2626))
    target = 443
    matched = False
    vm.pc = 18338
    if not matched and vm.cells.value(2625) == vm.cells.value(354):
        target, matched = 444, True
    vm.pc = 18340
    if not matched and vm.cells.value(2625) == vm.cells.value(369):
        target, matched = 444, True
    vm.pc = 18342
    if not matched and vm.cells.value(2625) == vm.cells.value(152):
        target, matched = 444, True
    vm.pc = 18344
    if not matched and vm.cells.value(2625) == vm.cells.value(2188):
        target, matched = 444, True
    vm._jump(target)
    if vm.block == 444:
        vm.pc = 18345
        vm.pc = 18348
        vm.auxiliary = (0, 849489891)
        vm.pc = 18349
        _comparison(vm)
        vm.pc = 18353
        vm._write(2627, int(vm._signed_cell(2623, 1) == vm._signed_cell(235, 1)), 4, 'record_frame.equal')
        vm.pc = 18357
        vm._jump(443 if vm.cells.value(2627) else 445)
    if vm.block == 443:
        state['branch'] = 'length_default' if vm.predecessor == 435 else 'seed_zero'
        _join(vm, 19119, 2727, 2726, 435, 444, 466)
        state['phase'] = 'complete'
        return True
    vm.pc = 18362
    vm.execute_once(10, (7, 1, 2625, 2628))
    vm.pc = 18370
    _indexed(vm, 2629, 69, 41, 145, 145)
    vm.pc = 18371
    vm.pc = 18374
    vm.auxiliary = (0, 54317)
    vm.pc = 18379
    vm.execute_typed((7, 2628, 1732, 2630))
    vm.pc = 18381
    vm._jump(446)
    while True:
        vm.pc = 18388
        selected = None
        if vm.predecessor == 445:
            selected = 145
        if vm.predecessor == 447:
            selected = 2632
        vm._write(2631, vm.cells.value(selected), 8, 'record_frame.loop_phi')
        vm.pc = 18393
        vm.execute_once(18, (7, 2631, 2630, 2633))
        vm.pc = 18397
        vm._jump(447 if vm.cells.value(2633) else 448)
        if vm.block != 447:
            break
        vm.pc = 18404
        _indexed(vm, 2634, 2616, 1, 2631)
        vm.pc = 18409
        vm.execute_once(15, (4, 2, 2634, 2635))
        vm.pc = 18413
        _load(vm, 2635, 2636, 4)
        vm.pc = 18420
        _indexed(vm, 2637, 2629, 1, 2631)
        vm.pc = 18425
        vm.execute_once(15, (4, 2, 2637, 2638))
        vm.pc = 18429
        _store(vm, 2636, 2638, 4, 4)
        vm.pc = 18430
        vm.pc = 18433
        vm.auxiliary = (0, 207237122)
        vm.pc = 18438
        vm.execute_once(1, (7, 2631, 172, 2632))
        vm.pc = 18440
        vm._jump(446)
    while True:
        vm.pc = 18447
        selected = None
        if vm.predecessor == 449:
            selected = 2640
        if vm.predecessor == 446:
            selected = 2630
        vm._write(2639, vm.cells.value(selected), 8, 'record_frame.loop_phi')
        vm.pc = 18452
        vm.execute_once(18, (7, 2639, 2628, 2641))
        vm.pc = 18456
        vm._jump(449 if vm.cells.value(2641) else 450)
        if vm.block != 449:
            break
        vm.pc = 18463
        _indexed(vm, 2642, 2616, 1, 2639)
        vm.pc = 18467
        _load(vm, 2642, 2643, 1)
        vm.pc = 18474
        _indexed(vm, 2644, 2629, 1, 2639)
        vm.pc = 18478
        _store(vm, 2643, 2644, 1, 1)
        vm.pc = 18479
        vm.pc = 18482
        vm.auxiliary = (0, 2029510657)
        vm.pc = 18487
        vm.execute_once(1, (7, 2639, 163, 2640))
        vm.pc = 18489
        vm._jump(448)
    vm.pc = 18494
    vm.execute_once(8, (1, 2623, 336, 2645))
    vm.pc = 18499
    vm.execute_once(8, (1, 2623, 1641, 2646))
    vm.pc = 18504
    vm._write(2647, vm._signed_cell(2645, 1) ^ vm._signed_cell(2646, 1), 8, 'record_frame.binary')
    vm.pc = 18509
    vm.execute_once(8, (1, 2623, 152, 2648))
    vm.pc = 18514
    vm._write(2649, vm._signed_cell(2647, 1) ^ vm._signed_cell(2648, 1), 8, 'record_frame.binary')
    vm.pc = 18519
    vm.execute_once(8, (1, 2623, 497, 2650))
    vm.pc = 18524
    vm._write(2651, vm._signed_cell(2649, 1) ^ vm._signed_cell(2650, 1), 8, 'record_frame.binary')
    vm.pc = 18529
    vm._write(2652, vm._signed_cell(2651, 1) & vm._signed_cell(354, 1), 8, 'record_frame.binary')
    vm.pc = 18530
    vm.pc = 18533
    vm.auxiliary = (0, 17085)
    _shift_feedback(vm)
    vm.pc = 18541
    vm.auxiliary = (0, 62930)
    vm.pc = 18546
    vm.execute_typed((1, 2653, 2652, 2654))
    vm.pc = 18549
    vm.auxiliary = (0, 49005)
    state['branch'] = 'present'
    state['phase'] = 'numeric'
    accepted = decode_primary_material_segment(vm)
    if not accepted:
        return False
    _join(vm, 19119, 2727, 2726, 435, 444, 466)
    state['phase'] = 'complete'
    return True


def run_primary_schedule_record_frame(vm):
    vm.primary_record_frame_state = {'frame': 'schedule', 'phase': 'prefix', 'branch': None, 'retained_steps': 0}
    state = vm.primary_record_frame_state
    vm.pc = 31448
    _indexed(vm, 4268, 18, 11, 145, 158)
    vm.pc = 31452
    _load(vm, 4268, 4269, 8)
    vm.pc = 31456
    _store(vm, 4269, 16, 8, 8)
    vm.pc = 31464
    _indexed(vm, 4270, 18, 11, 145, 269)
    vm.pc = 31468
    _load(vm, 4270, 4271, 1)
    vm.pc = 31476
    _indexed(vm, 4272, 18, 11, 145, 311)
    vm.pc = 31480
    _load(vm, 4272, 4273, 1)
    vm.pc = 31485
    vm.execute_once(10, (3, 1, 4273, 4274))
    target = 688
    matched = False
    vm.pc = 31491
    if not matched and vm.cells.value(4273) == vm.cells.value(354):
        target, matched = 689, True
    vm.pc = 31493
    if not matched and vm.cells.value(4273) == vm.cells.value(369):
        target, matched = 689, True
    vm.pc = 31495
    if not matched and vm.cells.value(4273) == vm.cells.value(152):
        target, matched = 689, True
    vm.pc = 31497
    if not matched and vm.cells.value(4273) == vm.cells.value(2188):
        target, matched = 689, True
    vm._jump(target)
    if vm.block == 689:
        vm.pc = 31498
        vm.pc = 31501
        vm.auxiliary = (0, 395503875)
        vm.pc = 31506
        vm.execute_once(17, (1, 4271, 235, 4275))
        vm.pc = 31510
        vm._jump(688 if vm.cells.value(4275) else 690)
    if vm.block == 688:
        state['branch'] = 'length_default' if vm.predecessor == 680 else 'seed_zero'
        _join(vm, 32266, 4375, 4374, 680, 689, 711)
        state['phase'] = 'complete'
        return True
    state['branch'] = 'present'
    state['phase'] = 'numeric'
    _decode_schedule(vm)
    _join(vm, 32266, 4375, 4374, 680, 689, 711)
    state['phase'] = 'complete'
    return True


def run_primary_seed_record_frame(vm):
    vm.primary_record_frame_state = {'frame': 'seed', 'phase': 'prefix', 'branch': None, 'retained_steps': 0}
    state = vm.primary_record_frame_state
    vm.pc = 36934
    _indexed(vm, 4999, 58, 37, 145, 145)
    vm.pc = 36942
    _indexed(vm, 5000, 58, 37, 145, 145)
    vm.pc = 36947
    vm.execute_once(15, (2, 12, 41, 5001))
    vm.pc = 36956
    _host(vm, 36947, (235, 158, 502, 41))
    vm.pc = 36961
    vm.execute_once(15, (2, 8, 39, 5002))
    vm.pc = 36969
    _indexed(vm, 5003, 69, 41, 145, 145)
    vm.pc = 36977
    _indexed(vm, 5004, 70, 41, 145, 145)
    vm.pc = 36982
    vm.execute_once(15, (2, 8, 40, 5005))
    vm.pc = 36986
    _store(vm, 145, 40, 8, 8)
    vm.pc = 36994
    _indexed(vm, 5006, 41, 11, 145, 158)
    vm.pc = 36998
    _load(vm, 5006, 5007, 8)
    vm.pc = 37002
    _store(vm, 5007, 39, 8, 8)
    vm.pc = 37010
    _indexed(vm, 5008, 41, 11, 145, 269)
    vm.pc = 37014
    _load(vm, 5008, 5009, 1)
    vm.pc = 37022
    _indexed(vm, 5010, 41, 11, 145, 311)
    vm.pc = 37026
    _load(vm, 5010, 5011, 1)
    vm.pc = 37031
    vm.execute_once(10, (3, 1, 5011, 5012))
    target = 829
    matched = False
    vm.pc = 37037
    if not matched and vm.cells.value(5011) == vm.cells.value(354):
        target, matched = 830, True
    vm.pc = 37039
    if not matched and vm.cells.value(5011) == vm.cells.value(369):
        target, matched = 830, True
    vm.pc = 37041
    if not matched and vm.cells.value(5011) == vm.cells.value(152):
        target, matched = 830, True
    vm.pc = 37043
    if not matched and vm.cells.value(5011) == vm.cells.value(2188):
        target, matched = 830, True
    vm._jump(target)
    if vm.block == 830:
        vm.pc = 37044
        vm.pc = 37047
        vm.auxiliary = (0, 1044549619)
        vm.pc = 37048
        _comparison(vm)
        vm.pc = 37052
        vm._write(5013, int(vm._signed_cell(5009, 1) == vm._signed_cell(235, 1)), 4, 'record_frame.equal')
        vm.pc = 37056
        vm._jump(829 if vm.cells.value(5013) else 831)
    if vm.block == 829:
        state['branch'] = 'length_default' if vm.predecessor == 826 else 'seed_zero'
        _join(vm, 37823, 5113, 5112, 826, 830, 852)
        state['phase'] = 'complete'
        return True
    state['branch'] = 'present'
    state['phase'] = 'numeric'
    retained_start = len(vm.trace)
    accepted = decode_primary_material_seed(vm)
    if not accepted:
        return False
    state['retained_steps'] = len(vm.trace) - retained_start
    state['phase'] = 'complete'
    return True


def run_primary_key_record_frame(vm):
    vm.primary_record_frame_state = {'frame': 'key', 'phase': 'prefix', 'branch': None, 'retained_steps': 0}
    state = vm.primary_record_frame_state
    vm.pc = 41019
    _load(vm, 46, 5540, 8)
    vm.pc = 41024
    vm.execute_once(15, (2, 40, 57, 5541))
    vm.pc = 41032
    _indexed(vm, 5542, 57, 39, 145, 145)
    vm.pc = 41039
    selected = 4251 if vm.cells.value(5402) else 145
    vm._write(5543, vm._signed_cell(selected, 7), 8, 'record_frame.select')
    vm.pc = 41043
    _store(vm, 5543, 5542, 8, 8)
    vm.pc = 41051
    _indexed(vm, 5544, 57, 39, 145, 163)
    vm.pc = 41058
    selected = 5545 if vm.cells.value(5398) else 145
    vm._write(5546, vm._signed_cell(selected, 7), 8, 'record_frame.select')
    vm.pc = 41062
    _store(vm, 5546, 5544, 8, 8)
    vm.pc = 41070
    _indexed(vm, 5547, 57, 39, 145, 166)
    vm.pc = 41077
    selected = 145 if vm.cells.value(5401) else 5548
    vm._write(5549, vm._signed_cell(selected, 7), 8, 'record_frame.select')
    vm.pc = 41081
    _store(vm, 5549, 5547, 8, 8)
    vm.pc = 41089
    _indexed(vm, 5550, 58, 37, 145, 145)
    vm.pc = 41090
    vm.pc = 41093
    vm.auxiliary = (0, 28943)
    vm.pc = 41098
    vm.execute_typed((7, 5540, 5551, 5552))
    vm.pc = 41101
    vm.auxiliary = (0, 54861)
    vm.pc = 41106
    vm.execute_typed((7, 5471, 5551, 5553))
    vm.pc = 41114
    _indexed(vm, 5554, 58, 37, 145, 145)
    vm.pc = 41119
    vm.execute_once(15, (2, 12, 51, 5555))
    vm.pc = 41128
    _host(vm, 41119, (354, 269, 311, 51))
    vm.pc = 41133
    vm.execute_once(15, (2, 8, 49, 5556))
    vm.pc = 41141
    _indexed(vm, 5557, 69, 41, 145, 145)
    vm.pc = 41149
    _indexed(vm, 5558, 70, 41, 145, 145)
    vm.pc = 41154
    vm.execute_once(15, (2, 8, 50, 5559))
    vm.pc = 41158
    _store(vm, 145, 50, 8, 8)
    vm.pc = 41166
    _indexed(vm, 5560, 51, 11, 145, 158)
    vm.pc = 41170
    _load(vm, 5560, 5561, 8)
    vm.pc = 41174
    _store(vm, 5561, 49, 8, 8)
    vm.pc = 41182
    _indexed(vm, 5562, 51, 11, 145, 269)
    vm.pc = 41186
    _load(vm, 5562, 5563, 1)
    vm.pc = 41194
    _indexed(vm, 5564, 51, 11, 145, 311)
    vm.pc = 41198
    _load(vm, 5564, 5565, 1)
    vm.pc = 41203
    vm.execute_once(10, (3, 1, 5565, 5566))
    target = 948
    matched = False
    vm.pc = 41209
    if not matched and vm.cells.value(5565) == vm.cells.value(354):
        target, matched = 949, True
    vm.pc = 41211
    if not matched and vm.cells.value(5565) == vm.cells.value(369):
        target, matched = 949, True
    vm.pc = 41213
    if not matched and vm.cells.value(5565) == vm.cells.value(152):
        target, matched = 949, True
    vm.pc = 41215
    if not matched and vm.cells.value(5565) == vm.cells.value(2188):
        target, matched = 949, True
    vm._jump(target)
    if vm.block == 949:
        vm.pc = 41216
        vm.pc = 41219
        vm.auxiliary = (0, 177347315)
        vm.pc = 41224
        vm.execute_once(17, (1, 5563, 235, 5567))
        vm.pc = 41228
        vm._jump(948 if vm.cells.value(5567) else 950)
    if vm.block == 948:
        state['branch'] = 'length_default' if vm.predecessor == 940 else 'seed_zero'
        _join(vm, 41978, 5667, 5666, 940, 949, 971)
        state['phase'] = 'complete'
        return True
    state['branch'] = 'present'
    state['phase'] = 'numeric'
    retained_start = len(vm.trace)
    accepted = decode_primary_material_key(vm)
    if not accepted:
        return False
    state['retained_steps'] = len(vm.trace) - retained_start
    state['phase'] = 'complete'
    return True


def _decode_schedule(vm):
    state = getattr(vm, 'primary_material_schedule_state', None)
    if state is None:
        state = dict.fromkeys(('copy_bytes', 'stream_bytes', 'xor_bytes', 'cleared_bytes',
                               'pointer_copies', 'qword_conversions'), 0)
        vm.primary_material_schedule_state = state
    vm.execute_once(10, (7, 1, 4273, 4276))
    state['qword_conversions'] += 1
    _array_pointer(vm, 69, 145, 4277, 8)
    vm._write(4278, vm.cells.value(4276) & vm.cells.value(1732),
              8, 'material_schedule.input_prefix')
    _copy(vm, 4264, 4277, 4279, 4278, (309792770, 555028482), state)
    _first_byte(vm, state)
    _following_bytes(vm, state)
    _xor(vm, state)
    vm._write(4349, vm.cells.value(4276) & vm.cells.value(1732),
              8, 'material_schedule.output_prefix')
    _copy(vm, 4277, 4267, 4350, 4349, (2018189314, 815079425), state, wide_tail=True)
    state['phase'] = 'clear'
    _clear(vm, 4364, 4277, (192048083, 1363480578), state, guarded=False)
    _clear(vm, 4369, 4309, (533888003, 1669632001), state, guarded=True)
    _load(vm, 17, 4374, 8)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 32257, 688, 711, False
    return True
