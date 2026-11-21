from .primary_material_lookup import _index
from .primary_material_state import _comparison, _flag0


def _node(vm, key):
    seed = vm.memory.load(vm.cells.value(112) + 34840, 8)
    index = _index(vm, 5332, 5333, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(vm.cells.value(112) + 16 + 8 * index, 8)
    _comparison(vm)
    node = 0
    if bucket:
        index = _index(vm, 5340, 5341, (key ^ (seed >> 8)) & 255)
        node = vm.memory.load(bucket + 8 * index, 8)
        if node and vm.memory.load(node + 4, 2) != key:
            node = 0
        if node:
            saved = vm.memory.load(node + 24, 4)
            current = vm.memory.load(node, 4)
            checksum = ((current ^ 0x811C9DC5) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(node + 4, 2)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            pointer = vm.memory.load(node + 8, 8)
            _flag0(vm)
            checksum = ((checksum ^ (pointer & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (pointer >> 32)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            _comparison(vm)
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='material_publish.integrity_marker')
    _comparison(vm)
    return node


def publish_primary_material(vm):
    vm.primary_material_publish_state = {'phase': 'publish', 'lookups': 0,
                                        'material_bytes': 0}
    state = vm.primary_material_publish_state
    for index in range(8):
        node = _node(vm, 129 + index)
        state['lookups'] += 1
        if node:
            offset = vm.memory.load(vm.cells.value(4391) + 8 * index, 8) & 0xFFFFFFFF
            value = vm.memory.load(vm.cells.value(5000) + offset, 1)
            pointer = vm.memory.load(node + 8, 8)
            vm.memory.store(pointer, value, 1, source='material_publish.selected_byte')
            state['material_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 39948, 919, 916, False
    vm.auxiliary = (0, 1863536641)
    state['phase'] = 'complete'
    return True
