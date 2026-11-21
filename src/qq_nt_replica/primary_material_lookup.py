from .primary_material_segment import _state
from .primary_vm import PrimarySemanticUnavailable
from .primary_ecrypt import _store_cell


def _comparison_globals(vm):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')


def _flag0(vm):
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        raise PrimarySemanticUnavailable('high class6 current-global alternate route is unavailable')


def _index(vm, source, target, value):
    vm._write(source, value, 8, 'material_lookup.index')
    vm.execute_once(10, (7, 18, source, target))
    return vm.cells.value(target)


def _storage_byte(vm, key, final):
    context = vm.cells.value(112)
    seed = vm.memory.load(context + 34840, 8)
    source, target = (3187, 3188) if final else (2556, 2557)
    index = _index(vm, source, target, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(context + 16 + 8 * index, 8)
    if not final:
        _comparison_globals(vm)
    node = 0
    if bucket:
        if final:
            _flag0(vm)
        index = (key ^ ((seed >> 8) & 0xFFFF)) & 255
        source, target = (3195, 3196) if final else (2564, 2565)
        index = _index(vm, source, target, index)
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
            checksum = ((checksum ^ (pointer & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (pointer >> 32)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            if not final:
                _flag0(vm)
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            if final:
                _comparison_globals(vm)
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='material_lookup.integrity_marker')
    _comparison_globals(vm)
    if node:
        pointer = vm.memory.load(node + 8, 8)
        return vm.memory.load(pointer, 1)
    return 0


def prepare_primary_material_header(vm):
    vm.pc = 17741
    vm.cells.copy_q_clear_owned(34, 2544)
    _store_cell(vm, 17741, 8, 145, 34)
    state = _state(vm)
    value = _storage_byte(vm, 39, False)
    state['header_lookups'] = state.get('header_lookups', 0) + 1
    vm.memory.store(vm.cells.value(2544), value, 1, source='material_lookup.initial_value')
    value = vm.memory.load(vm.cells.value(34), 8) & 255
    target = vm.cells.value(122)
    vm._write(2614, target, 8, 'material_lookup.header_pointer')
    vm.memory.store(target, value, 1, source='material_lookup.initial_header')
    state['header_bytes'] = state.get('header_bytes', 0) + 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 18248, 435, 432, False
    vm.auxiliary = (0, 212705281)
    return True


def finish_primary_material_header(vm):
    vm.pc = 22465
    vm._write(3175, vm.memory.load(vm.cells.value(2614), 1), 4, 'high.load')
    vm.pc = 22470
    vm.cells.copy_q_clear_owned(13, 3176)
    _store_cell(vm, 22470, 8, 145, 13)
    state = _state(vm)
    value = _storage_byte(vm, 35, True)
    state['header_lookups'] = state.get('header_lookups', 0) + 1
    vm.memory.store(vm.cells.value(3176), value, 1, source='material_lookup.final_value')
    value = vm.memory.load(vm.cells.value(13), 8) & 255
    value ^= vm.memory.load(vm.cells.pointer(3175), 1) ^ 16
    vm.memory.store(vm.cells.value(2614), value, 1, source='material_lookup.final_header')
    state['header_bytes'] = state.get('header_bytes', 0) + 1
    vm._write(3247, vm.cells.value(129), 8, 'material_lookup.next_record_pointer')
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 23109, 562, 554, False
    vm.auxiliary = (0, 27437)
    return True
