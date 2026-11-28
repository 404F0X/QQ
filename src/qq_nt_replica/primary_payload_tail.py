from .primary_material_lookup import _index
from .primary_material_segment import _copy_field
from .primary_material_state import _comparison, _flag0
from .primary_ecrypt import _store_cell


def _word_sources(vm, word, source, temporary, destination, scratch):
    vm.pc = word + 5
    vm.cells.copy_q_clear_owned(source, destination)
    vm.pc = word + 10
    vm.cells.copy_q_clear_owned(temporary, scratch)
    _store_cell(vm, word + 10, 8, 145, temporary)


def _storage_byte(vm, key):
    seed = vm.memory.load(vm.cells.value(112) + 34840, 8)
    index = _index(vm, 7508, 7509, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(vm.cells.value(112) + 16 + 8 * index, 8)
    node = 0
    if bucket:
        _flag0(vm)
        index = _index(vm, 7516, 7517, (key ^ ((seed >> 8) & 0xFFFF)) & 255)
        node = vm.memory.load(bucket + 8 * index, 8)
        _comparison(vm)
        if node:
            current = vm.memory.load(node + 4, 2)
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
            _flag0(vm)
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            _flag0(vm)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='payload_tail.integrity_marker')
    if node:
        pointer = vm.memory.load(node + 8, 8)
        return vm.memory.load(pointer, 1)
    return 0


def _piece(vm, source, target, offset, width):
    value = vm.memory.load(source + offset, width)
    vm.memory.store(target + offset, value, width, source='payload_tail.field_piece')


def _copy_eight(vm, source, target):
    _piece(vm, source, target, 0, 1)
    offset = 1
    for step in range(2):
        if (target + offset) & 3:
            _piece(vm, source, target, offset, 1)
            offset += 1
    while offset + 4 <= 8:
        _piece(vm, source, target, offset, 4)
        offset += 4
    while offset < 8:
        _piece(vm, source, target, offset, 1)
        offset += 1


def _clear(vm, pointer, size):
    for index in range(size):
        vm.memory.store(pointer + index, 0, 1, source='payload_tail.clear_byte')


def prepare_primary_payload_tail(vm):
    vm.primary_payload_tail_state = {'phase': 'word', 'lookups': 0,
                                     'field_bytes': 0, 'cleared_bytes': 0}
    state = vm.primary_payload_tail_state
    _word_sources(vm, 56016, 135, 65, 7496, 7497)
    for index, key in enumerate((137, 138)):
        value = _storage_byte(vm, key)
        vm.memory.store(vm.cells.value(7497) + index, value, 1,
                        source='payload_tail.word_lookup')
        state['lookups'] += 1
    value = vm.memory.load(vm.cells.value(65), 8) & 0xFFFF
    vm.memory.store(vm.cells.value(135), value, 2, source='payload_tail.word')
    _copy_field(vm, vm.cells.value(7496), vm.cells.value(103) + 15, 2)
    state['field_bytes'] += 2
    state['phase'] = 'first_source'
    _copy_eight(vm, vm.cells.value(1766), vm.cells.value(103) + 17)
    state['field_bytes'] += 8
    state['phase'] = 'first_clear'
    _clear(vm, vm.cells.value(1520), 16)
    state['cleared_bytes'] += 16
    state['phase'] = 'second_source'
    _copy_eight(vm, vm.cells.value(2292), vm.cells.value(103) + 50)
    state['field_bytes'] += 8
    state['phase'] = 'second_clear'
    _clear(vm, vm.cells.value(2292), 8)
    state['cleared_bytes'] += 8
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 58557, 1422, 1420, False
    vm.auxiliary = (0, 1038283683)
    state['phase'] = 'complete'
    return True
