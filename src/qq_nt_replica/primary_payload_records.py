from .primary_material_lookup import _index
from .primary_material_segment import _copy_field
from .primary_material_state import _comparison, _flag0
from .primary_payload_tail import _word_sources
from .primary_ecrypt import _store_cell


def _header_sources(vm):
    vm.pc = 59522
    vm._write(7953, vm.memory.load(vm.cells.value(6224), 1), 4, 'high.load')
    vm.pc = 59527
    vm.cells.copy_q_clear_owned(66, 7954)
    _store_cell(vm, 59527, 8, 145, 66)


def _storage_byte(vm, key, second):
    context = vm.cells.value(112)
    seed = vm.memory.load(context + 34840, 8)
    source, target = (8113, 8114) if second else (7965, 7966)
    index = _index(vm, source, target, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(vm.cells.value(112) + 16 + 8 * index, 8)
    if second:
        _comparison(vm)
    node = 0
    if bucket:
        if second:
            _flag0(vm)
        source, target = (8121, 8122) if second else (7973, 7974)
        index = _index(vm, source, target, (key ^ ((seed >> 8) & 0xFFFF)) & 255)
        node = vm.memory.load(bucket + 8 * index, 8)
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
            if second:
                _flag0(vm)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            pointer = vm.memory.load(node + 8, 8)
            checksum = ((checksum ^ (pointer & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (pointer >> 32)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            if second:
                _flag0(vm)
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            _comparison(vm)
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='payload_records.integrity_marker')
    if not second:
        _comparison(vm)
    if node:
        pointer = vm.memory.load(node + 8, 8)
        return vm.memory.load(pointer, 1)
    return 0


def prepare_primary_payload_records(vm):
    vm.primary_payload_records_state = {'phase': 'header', 'lookups': 0,
                                        'field_bytes': 0, 'cleared_bytes': 0}
    state = vm.primary_payload_records_state
    _header_sources(vm)
    value = _storage_byte(vm, 35, False)
    vm.memory.store(vm.cells.value(7954), value, 1, source='payload_records.header_lookup')
    state['lookups'] += 1
    value = vm.memory.load(vm.cells.value(66), 8) & 255
    _flag0(vm)
    value ^= vm.memory.load(vm.cells.pointer(7953), 1)
    _flag0(vm)
    value ^= 128
    vm.memory.store(vm.cells.value(6224), value, 1, source='payload_records.header')
    _copy_field(vm, vm.cells.value(6224), vm.cells.value(103) + 1, 1)
    state['field_bytes'] += 1
    state['phase'] = 'word'
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 60639, 1474, 1472, False
    vm.auxiliary = (0, 1858228470)
    _word_sources(vm, 60639, 137, 67, 8101, 8102)
    for index, key in enumerate((129, 130)):
        value = _storage_byte(vm, key, True)
        vm.memory.store(vm.cells.value(8102) + index, value, 1,
                        source='payload_records.word_lookup')
        state['lookups'] += 1
    value = vm.memory.load(vm.cells.value(67), 8) & 0xFFFF
    vm.memory.store(vm.cells.value(137), value, 2, source='payload_records.word')
    _copy_field(vm, vm.cells.value(8101), vm.cells.value(103) + 2, 2)
    state['field_bytes'] += 2
    state['phase'] = 'checksum'
    _copy_field(vm, vm.cells.value(7858), vm.cells.value(103) + 4, 4)
    state['field_bytes'] += 4
    state['phase'] = 'clear'
    for cell, size in ((6224, 5), (138, 128)):
        pointer = vm.cells.value(cell)
        if size == 128:
            vm._write(8346, pointer, 8, 'payload_records.output_pointer')
        for index in range(size + 1):
            _comparison(vm)
            if index == size:
                break
            vm.memory.store(pointer + index, 0, 1, source='payload_records.clear_byte')
            state['cleared_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 62616, 1529, 1527, False
    vm.auxiliary = (0, 991080659)
    state['phase'] = 'complete'
    return True
