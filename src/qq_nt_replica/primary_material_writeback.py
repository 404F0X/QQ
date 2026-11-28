from .primary_material_lookup import _index
from .primary_material_state import _comparison, _flag0


def _storage_node(vm, key, stage):
    seed = vm.memory.load(vm.cells.value(112) + 34840, 8)
    source, target = ((5886, 5887), (5954, 5955), (6011, 6012))[stage]
    index = _index(vm, source, target, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(vm.cells.value(112) + 16 + 8 * index, 8)
    if stage == 2:
        _comparison(vm)
    node = 0
    if bucket:
        if stage == 2:
            _flag0(vm)
        source, target = ((5894, 5895), (5962, 5963), (6019, 6020))[stage]
        index = _index(vm, source, target, (key ^ ((seed >> 8) & 0xFFFF)) & 255)
        node = vm.memory.load(bucket + 8 * index, 8)
        if node:
            current = vm.memory.load(node + 4, 2)
            if stage != 2:
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
            if stage == 2:
                _flag0(vm)
            checksum = ((checksum ^ (pointer & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            if stage == 1:
                _flag0(vm)
            checksum = ((checksum ^ (pointer >> 32)) * 0x01000193) & 0xFFFFFFFF
            if stage == 2:
                _flag0(vm)
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            if stage != 1:
                _comparison(vm)
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='material_writeback.integrity_marker')
    if stage == 0:
        _comparison(vm)
    return node


def write_primary_material(vm):
    vm.primary_material_writeback_state = {'phase': 'material', 'lookups': 0,
                                          'material_bytes': 0, 'mixed_pairs': 0,
                                          'mixed_writes': 0}
    state = vm.primary_material_writeback_state
    for index, key in enumerate((137, 138)):
        node = _storage_node(vm, key, 0)
        state['lookups'] += 1
        if node:
            offset = vm.memory.load(vm.cells.value(4391) + 8 * index, 8) & 0xFFFFFFFF
            value = vm.memory.load(vm.cells.value(5554) + offset, 1)
            pointer = vm.memory.load(node + 8, 8)
            vm.memory.store(pointer, value, 1, source='material_writeback.material_byte')
            state['material_bytes'] += 1
    state['phase'] = 'control'
    control = vm.memory.load(vm.cells.value(130), 1)
    vm._write(5943, control, 8, 'material_writeback.control_snapshot')
    state['phase'] = 'mix'
    for index in range(10):
        first = _storage_node(vm, 129 + index, 1)
        state['lookups'] += 1
        second = _storage_node(vm, 101 + index, 2)
        state['lookups'] += 1
        if first and second:
            vm.execute_once(10, (7, 1, 5943, 6064))
            mask = ((index ^ vm.cells.value(6064)) * 0x9E3779B9) & 0xFFFFFFFF
            mask ^= mask >> 16
            pointer = vm.memory.load(second + 8, 8)
            value = vm.memory.load(pointer, 1)
            pointer = vm.memory.load(first + 8, 8)
            current = vm.memory.load(pointer, 1)
            _flag0(vm)
            vm.memory.store(pointer, current ^ value, 1,
                            source='material_writeback.first_mix')
            state['mixed_writes'] += 1
            pointer = vm.memory.load(first + 8, 8)
            current = vm.memory.load(pointer, 1)
            vm.memory.store(pointer, current ^ (mask & 255), 1,
                            source='material_writeback.second_mix')
            state['mixed_writes'] += 1
            state['mixed_pairs'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 45051, 1048, 1045, False
    vm.auxiliary = (0, 764198913)
    state['phase'] = 'complete'
    return True
