from .primary_material_lookup import _index
from .primary_material_state import _comparison, _flag0
from .primary_ecrypt import _indexed_pointer, _store_cell


def _node(vm, key, stage):
    seed = vm.memory.load(vm.cells.value(112) + 34840, 8)
    if stage:
        _flag0(vm)
    source, target = ((5415, 5416), (5484, 5485))[stage]
    index = _index(vm, source, target, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(vm.cells.value(112) + 16 + 8 * index, 8)
    _comparison(vm)
    node = 0
    if bucket:
        source, target = ((5423, 5424), (5492, 5493))[stage]
        index = _index(vm, source, target, (key ^ (seed >> 8)) & 255)
        node = vm.memory.load(bucket + 8 * index, 8)
        if not stage:
            _comparison(vm)
        if node:
            current = vm.memory.load(node + 4, 2)
            if stage:
                _comparison(vm)
            if current != key:
                node = 0
        if node:
            saved = vm.memory.load(node + 24, 4)
            current = vm.memory.load(node, 4)
            checksum = ((current ^ 0x811C9DC5) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(node + 4, 2)
            if not stage:
                _flag0(vm)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            pointer = vm.memory.load(node + 8, 8)
            checksum = ((checksum ^ (pointer & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            if stage:
                _flag0(vm)
            checksum = ((checksum ^ (pointer >> 32)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            _flag0(vm)
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            if stage:
                _comparison(vm)
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='material_words.integrity_marker')
    if stage:
        _comparison(vm)
    return node


def _word(vm, stage, target, state):
    for index in range(2):
        node = _node(vm, (137 if stage == 0 else 109) + index, stage)
        state['lookups'] += 1
        if node:
            pointer = vm.memory.load(node + 8, 8)
            value = vm.memory.load(pointer, 1)
        else:
            value = 0
        vm.memory.store(vm.cells.value(target) + index, value, 1,
                        source='material_words.word_byte')
        state['word_bytes'] += 1


def prepare_primary_material_words(vm):
    vm.primary_material_words_state = {'phase': 'flags', 'flags': 0, 'lookups': 0,
                                      'word_bytes': 0, 'cleared_bytes': 0,
                                      'retained_steps': 0}
    state = vm.primary_material_words_state
    for word, destination, field, value in ((39948, 5389, 391, 5390),
            (39960, 5391, 360, 5392), (39972, 5393, 149, 5394)):
        _indexed_pointer(vm, word, destination, 75, 106, (145, field))
        vm.pc = word + 12
        vm._write(value, vm.memory.load(vm.cells.value(destination), 4), 4, 'high.load')
    vm.auxiliary = (0, 49239)
    value = (vm.memory.load(vm.cells.pointer(5394), 4, signed=True) &
             vm.memory.load(vm.cells.pointer(5395), 4, signed=True))
    vm._write(5396, value, 8, 'material_words.masked_flag')
    vm._write(5398, int(vm.cells.value(5396) > vm.cells.value(5397)), 4,
              'material_words.key_condition')
    state['flags'] += 1
    value = (vm.memory.load(vm.cells.pointer(5392), 4, signed=True) &
             vm.memory.load(vm.cells.pointer(5399), 4, signed=True))
    vm._write(5400, value, 8, 'material_words.masked_flag')
    vm.auxiliary = (0, 1706186115)
    _comparison(vm)
    value = (vm.memory.load(vm.cells.pointer(5400), 4, signed=True) ==
             vm.memory.load(vm.cells.pointer(158), 4, signed=True))
    vm._write(5401, int(value), 4, 'material_words.key_condition')
    state['flags'] += 1
    vm._write(5402, int(vm.cells.value(5390) > vm.cells.value(269)), 4,
              'material_words.key_condition')
    state['flags'] += 1
    state['phase'] = 'first_word'
    vm.pc = 40021
    vm.cells.copy_q_clear_owned(56, 5403)
    _store_cell(vm, 40021, 8, 145, 56)
    state['cleared_bytes'] += 8
    _word(vm, 0, 5403, state)
    vm.pc, vm.block, vm.predecessor = 40513, 929, 926
    vm.auxiliary = (0, 913473537)
    vm.pc = 40517
    vm._write(5471, vm.memory.load(vm.cells.value(56), 8), 8, 'high.load')
    vm.pc = 40522
    vm.cells.copy_q_clear_owned(46, 5472)
    _store_cell(vm, 40522, 8, 145, 46)
    state['cleared_bytes'] += 8
    state['phase'] = 'second_word'
    _word(vm, 1, 5472, state)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 41015, 940, 937, False
    vm.auxiliary = (0, 1917911042)
    state['phase'] = 'complete'
    return True
