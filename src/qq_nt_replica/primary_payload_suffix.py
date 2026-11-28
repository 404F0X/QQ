from .primary_material_lookup import _index
from .primary_material_segment import _copy_field
from .primary_material_state import _comparison, _flag0
from .primary_payload_tail import _clear, _word_sources


def _storage_byte(vm, key, first):
    seed = vm.memory.load(vm.cells.value(112) + 34840, 8)
    source, target = (6959, 6960) if first else (7194, 7195)
    index = _index(vm, source, target, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(vm.cells.value(112) + 16 + 8 * index, 8)
    node = 0
    if bucket:
        if not first:
            _flag0(vm)
        source, target = (6967, 6968) if first else (7202, 7203)
        index = _index(vm, source, target, (key ^ ((seed >> 8) & 0xFFFF)) & 255)
        node = vm.memory.load(bucket + 8 * index, 8)
        if node:
            current = vm.memory.load(node + 4, 2)
            if first:
                _comparison(vm)
            if current != key:
                node = 0
        if node:
            saved = vm.memory.load(node + 24, 4)
            current = vm.memory.load(node, 4)
            checksum = ((current ^ 0x811C9DC5) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(node + 4, 2)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            pointer = vm.memory.load(node + 8, 8)
            checksum = ((checksum ^ (pointer & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (pointer >> 32)) * 0x01000193) & 0xFFFFFFFF
            if not first:
                _flag0(vm)
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            if first:
                _comparison(vm)
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='payload_suffix.integrity_marker')
    if node:
        pointer = vm.memory.load(node + 8, 8)
        return vm.memory.load(pointer, 1)
    return 0


def _word(vm, first, state):
    base, temporary, output, offset = (135, 6947, 133, 59) if first else (133, 7182, 134, 65)
    for index in range(2):
        value = _storage_byte(vm, base + index, first)
        vm.memory.store(vm.cells.value(temporary) + index, value, 1,
                        source='payload_suffix.word_lookup')
        state['lookups'] += 1
    value = vm.memory.load(vm.cells.value(63 if first else 64), 8) & 0xFFFF
    vm.memory.store(vm.cells.value(output), value, 2, source='payload_suffix.word')
    _copy_field(vm, vm.cells.value(6946 if first else 7181), vm.cells.value(103) + offset, 2)
    state['field_bytes'] += 2


def _dword_bytes(vm, source_cell, offset):
    target = vm.cells.value(103) + offset
    source = vm.cells.value(source_cell)
    for index in range(4):
        value = vm.memory.load(source + index, 1)
        vm.memory.store(target + index, value, 1, source='payload_suffix.dword_byte')


def prepare_primary_payload_suffix(vm):
    vm.primary_payload_suffix_state = {'phase': 'first_word', 'lookups': 0,
                                       'field_bytes': 0, 'cleared_bytes': 0}
    state = vm.primary_payload_suffix_state
    _word_sources(vm, 51773, 133, 63, 6946, 6947)
    _word(vm, True, state)
    state['phase'] = 'first_dword'
    _dword_bytes(vm, 1199, 61)
    state['field_bytes'] += 4
    state['phase'] = 'second_word'
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 53571, 1284, 1282, False
    vm.auxiliary = (0, 1559374118)
    _word_sources(vm, 53571, 134, 64, 7181, 7182)
    _word(vm, False, state)
    state['phase'] = 'second_dword'
    _dword_bytes(vm, 1280, 67)
    state['field_bytes'] += 4
    state['phase'] = 'clear'
    _clear(vm, vm.cells.value(1198), 16)
    state['cleared_bytes'] += 16
    state['phase'] = 'control'
    target = vm.cells.value(103) + 14
    value = vm.memory.load(vm.cells.value(1520), 1)
    vm.memory.store(target, value, 1, source='payload_suffix.control_byte')
    state['field_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 56016, 1351, 1349, False
    vm.auxiliary = (0, 1382209382)
    state['phase'] = 'complete'
    return True
