from .primary_material_generation import _retained
from .primary_material_rounds import _less, _load, _next, _pointer, _store
from .primary_material_state import _comparison, _flag0
from .primary_rolling_state import _shift


def _array_pointer(vm, base, index, destination, size, stride=1):
    first = vm.memory.load(vm.cells.pointer(145), 4)
    second = vm.memory.load(vm.cells.pointer(index), 4)
    vm._write(destination, vm.cells.value(base) + size * first + stride * second,
              8, 'material_schedule.array_pointer')


def _byte_right(vm, source, count, destination):
    value = vm.memory.load(vm.cells.pointer(source), 1)
    amount = vm.memory.load(vm.cells.pointer(count), 1)
    vm._write(destination, value >> (amount & 31), 4, 'material_schedule.byte_right')


def _byte_left(vm, source, count, destination, word):
    first = vm.memory.load(vm.image_base + 0x6D86090, 4)
    second = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((first * first) & 0xFFFFFFFF) | (abs(second) & 0xFFFFFFFF)) >> 31
    amount = vm.memory.load(vm.cells.pointer(count), 4)
    value = 0
    if not amount & 0x80000000 and amount < 32:
        value = vm.memory.load(vm.cells.pointer(source), 1, signed=True) & 0xFFFFFFFF
        value <<= amount
    vm._write(destination, value, 4, 'material_schedule.byte_left')
    if extra:
        vm.pc = word + 5
        vm.execute_typed(tuple(vm._operand() for _ in range(4)))


def _byte_binary(vm, first, second, destination, operation):
    left, right = vm._signed_cell(first, 1), vm._signed_cell(second, 1)
    result = {'xor': lambda: left ^ right, 'and': lambda: left & right,
              'or': lambda: left | right, 'mul': lambda: left * right,
              'add': lambda: left + right}[operation]()
    vm._write(destination, result, 8, 'material_schedule.byte_' + operation)


def _equal(vm, first, second, destination, type_id):
    vm._write(destination, int(vm._signed_cell(first, type_id) == vm._signed_cell(second, type_id)),
              4, 'material_schedule.equal')


def _convert(vm, source, destination, state):
    vm.execute_once(10, (7, 3, source, destination))
    state['qword_conversions'] += 1


def _copy(vm, source, destination, first_cell, prefix, auxiliaries, state, *, wide_tail=False):
    (index, following, condition, source_pointer, source_copy, word,
     target_pointer, target_copy, tail, next_tail, tail_condition,
     tail_source, byte, tail_target) = range(first_cell, first_cell + 14)
    initial = True
    while True:
        vm._write(index, vm.cells.value(145 if initial else following),
                  8, 'material_schedule.copy_index')
        if not _less(vm, index, prefix, condition):
            break
        _pointer(vm, source, index, source_pointer)
        vm.execute_once(15, (4, 2, source_pointer, source_copy))
        state['pointer_copies'] += 1
        _load(vm, source_copy, word, 4)
        _pointer(vm, destination, index, target_pointer)
        vm.execute_once(15, (4, 2, target_pointer, target_copy))
        state['pointer_copies'] += 1
        _store(vm, word, target_copy, 4)
        state['copy_bytes'] += 4
        vm.auxiliary = (0, auxiliaries[0])
        _next(vm, index, 172, following)
        initial = False
    initial = True
    while True:
        vm._write(tail, vm.cells.value(prefix if initial else next_tail),
                  8, 'material_schedule.tail_index')
        if not _less(vm, tail, 4276, tail_condition):
            break
        _pointer(vm, source, tail, tail_source)
        _load(vm, tail_source, byte, 1)
        _pointer(vm, destination, tail, tail_target)
        _store(vm, byte, tail_target, 1, wide=wide_tail)
        state['copy_bytes'] += 1
        vm.auxiliary = (0, auxiliaries[1])
        _next(vm, tail, 163, next_tail)
        initial = False


def _first_byte(vm, state):
    _byte_right(vm, 4271, 336, 4293)
    _byte_right(vm, 4271, 1641, 4294)
    vm.auxiliary = (0, 22900)
    _byte_binary(vm, 4293, 4294, 4295, 'xor')
    _byte_right(vm, 4271, 152, 4296)
    vm.auxiliary = (0, 44861)
    _byte_binary(vm, 4295, 4296, 4297, 'xor')
    _byte_right(vm, 4271, 497, 4298)
    vm.auxiliary = (0, 15206)
    _byte_binary(vm, 4297, 4298, 4299, 'xor')
    _byte_binary(vm, 4299, 354, 4300, 'and')
    vm.auxiliary = (0, 63212)
    _byte_left(vm, 4271, 354, 4301, 31694)
    _byte_binary(vm, 4301, 4300, 4302, 'or')
    vm.auxiliary = (0, 28189)
    _flag0(vm)
    _byte_binary(vm, 4302, 1645, 4303, 'xor')
    vm.auxiliary = (0, 5628)
    _byte_left(vm, 4303, 497, 4304, 31716)
    _byte_right(vm, 4303, 1641, 4305)
    _byte_binary(vm, 4304, 4305, 4306, 'or')
    vm.auxiliary = (0, 2009237939)
    _equal(vm, 4306, 235, 4307, 1)
    zero = bool(vm.cells.value(4307))
    vm._write(4308, vm._signed_cell(2222 if zero else 4306, 1),
              8, 'material_schedule.first_stream_byte')
    _array_pointer(vm, 70, 145, 4309, 8)
    _store(vm, 4308, 4309, 1, wide=True)
    state['stream_bytes'] += 1


def _following_bytes(vm, state):
    initial = True
    while True:
        vm._write(4310, vm.cells.value(269 if initial else 4311),
                  8, 'material_schedule.stream_index')
        if not _less(vm, 4310, 4274, 4312):
            break
        vm.auxiliary = (0, 1366036482)
        vm._write(4313, vm._signed_cell(4310, 3) + vm._signed_cell(396, 3),
                  8, 'material_schedule.previous_index')
        _convert(vm, 4313, 4314, state)
        _array_pointer(vm, 70, 4314, 4315, 8)
        _load(vm, 4315, 4316, 1)
        _byte_right(vm, 4316, 336, 4317)
        _byte_right(vm, 4316, 1641, 4318)
        _byte_binary(vm, 4317, 4318, 4319, 'xor')
        _byte_right(vm, 4316, 152, 4320)
        _byte_binary(vm, 4319, 4320, 4321, 'xor')
        _byte_right(vm, 4316, 497, 4322)
        vm.auxiliary = (0, 60788)
        _byte_binary(vm, 4321, 4322, 4323, 'xor')
        vm.auxiliary = (0, 21310)
        _byte_binary(vm, 4323, 354, 4324, 'and')
        vm.auxiliary = (0, 29614)
        _byte_left(vm, 4316, 354, 4325, 31852)
        vm.auxiliary = (0, 12769)
        _byte_binary(vm, 4325, 4324, 4326, 'or')
        vm._write(4327, vm.cells.value(4310) & 255, 8, 'material_schedule.stream_salt_index')
        vm.auxiliary = (0, 1519366660)
        _byte_binary(vm, 4327, 2243, 4328, 'mul')
        vm.auxiliary = (0, 1966178306)
        _byte_binary(vm, 4328, 1645, 4329, 'add')
        vm.auxiliary = (0, 63796)
        _byte_binary(vm, 4329, 4326, 4330, 'xor')
        vm.auxiliary = (0, 25246)
        _byte_left(vm, 4330, 497, 4331, 31898)
        _byte_right(vm, 4330, 1641, 4332)
        _byte_binary(vm, 4331, 4332, 4333, 'or')
        vm.auxiliary = (0, 1897067107)
        _equal(vm, 4333, 235, 4334, 1)
        vm._write(4335, vm.cells.value(4310) & 255, 8, 'material_schedule.nonzero_index')
        vm.auxiliary = (0, 56092)
        _byte_binary(vm, 4335, 2222, 4336, 'xor')
        zero = bool(vm.cells.value(4334))
        vm._write(4337, vm._signed_cell(4336 if zero else 4333, 1),
                  8, 'material_schedule.next_stream_byte')
        _convert(vm, 4310, 4338, state)
        _array_pointer(vm, 70, 4338, 4339, 8)
        _store(vm, 4337, 4339, 1)
        state['stream_bytes'] += 1
        vm.auxiliary = (0, 604536833)
        vm._write(4311, vm._signed_cell(4310, 3) + vm._signed_cell(269, 3),
                  8, 'material_schedule.next_stream_index')
        initial = False


def _xor(vm, state):
    initial = True
    while True:
        vm._write(4340, vm.cells.value(158 if initial else 4341),
                  8, 'material_schedule.xor_index')
        if not _less(vm, 4340, 4274, 4342):
            break
        _convert(vm, 4340, 4343, state)
        _array_pointer(vm, 70, 4343, 4344, 8)
        _load(vm, 4344, 4345, 1)
        _array_pointer(vm, 69, 4343, 4346, 8)
        _load(vm, 4346, 4347, 1)
        _byte_binary(vm, 4347, 4345, 4348, 'xor')
        _store(vm, 4348, 4346, 1)
        state['xor_bytes'] += 1
        vm.auxiliary = (0, 762638338)
        vm._write(4341, vm._signed_cell(4340, 3) + vm._signed_cell(269, 3),
                  8, 'material_schedule.next_xor_index')
        initial = False


def _clear(vm, first_cell, start, auxiliaries, state, *, guarded):
    count, following, pointer, next_pointer, condition = range(first_cell, first_cell + 5)
    initial = True
    while True:
        vm._write(count, vm.cells.value(184 if initial else following),
                  8, 'material_schedule.clear_count')
        vm._write(pointer, vm.cells.value(start if initial else next_pointer),
                  8, 'material_schedule.clear_pointer')
        vm.auxiliary = (0, auxiliaries[0])
        if guarded:
            _comparison(vm)
        _equal(vm, count, 145, condition, 7)
        if vm.cells.value(condition):
            break
        vm.auxiliary = (0, auxiliaries[1])
        _next(vm, count, 233, following)
        _pointer(vm, pointer, 163, next_pointer)
        _store(vm, 235, pointer, 1, wide=not guarded)
        state['cleared_bytes'] += 1
        initial = False


def prepare_primary_material_schedule(vm):
    vm.primary_material_schedule_state = {'phase': 'keys', 'key_qwords': 0,
                                        'key_memsets': 0, 'material_calls': 0,
                                        'record_bytes': 0, 'output_clear_bytes': 0,
                                        'copy_bytes': 0, 'stream_bytes': 0, 'xor_bytes': 0,
                                        'cleared_bytes': 0, 'pointer_copies': 0,
                                        'qword_conversions': 0, 'retained_steps': 0,
                                        'branch': None}
    state = vm.primary_material_schedule_state
    predecessor = vm.predecessor
    _load(vm, 19, 4248, 8)
    vm.execute_once(15, (2, 36, 45, 4249))
    state['pointer_copies'] += 1
    _retained(vm, 31278, 680, predecessor, 1, state)
    state['key_memsets'] += 1
    for index, source, destination in ((145, 4112, 4252), (163, 4111, 4253),
                                       (166, 4110, 4254), (169, 4108, 4255),
                                       (172, 4109, 4256)):
        _array_pointer(vm, 45, index, destination, 256, 8)
        _store(vm, source, destination, 8)
        state['key_qwords'] += 1
    _array_pointer(vm, 45, 175, 4257, 256, 8)
    vm.auxiliary = (0, 50396)
    _shift(vm, 4106, 4258, 4259, 31359, 8)
    _store(vm, 4259, 4257, 8)
    state['key_qwords'] += 1
    _array_pointer(vm, 45, 178, 4260, 256, 8)
    _store(vm, 4107, 4260, 8)
    state['key_qwords'] += 1
    _array_pointer(vm, 58, 145, 4261, 37)
    _array_pointer(vm, 58, 145, 4262, 37)
    vm.execute_once(15, (2, 12, 18, 4263))
    state['pointer_copies'] += 1
    state['phase'] = 'material'
    _retained(vm, 31401, 680, predecessor, 1, state)
    state['material_calls'] += 1
    vm.execute_once(15, (2, 8, 16, 4264))
    state['pointer_copies'] += 1
    _array_pointer(vm, 69, 145, 4265, 8)
    _array_pointer(vm, 70, 145, 4266, 8)
    vm.execute_once(15, (2, 8, 17, 4267))
    state['pointer_copies'] += 1
    _store(vm, 145, 17, 8)
    state['output_clear_bytes'] = 8
    state['phase'] = 'record'
    from .primary_record_frames import run_primary_schedule_record_frame

    vm.pc, vm.block, vm.predecessor, vm.initial_block = 31440, 680, predecessor, False
    result = run_primary_schedule_record_frame(vm)
    if result:
        state['record_bytes'] = 10
        state['branch'] = vm.primary_record_frame_state['branch']
        state['phase'] = 'complete'
    return result
