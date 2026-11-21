from .primary_material_lookup import _index
from .primary_material_state import _comparison, _flag0
from .primary_payload_tail import _clear, _word_sources


def _storage_byte(vm, key):
    seed = vm.memory.load(vm.cells.value(112) + 34840, 8)
    index = _index(vm, 6382, 6383, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(vm.cells.value(112) + 16 + 8 * index, 8)
    _comparison(vm)
    node = 0
    if bucket:
        index = _index(vm, 6390, 6391, (key ^ ((seed >> 8) & 0xFFFF)) & 255)
        node = vm.memory.load(bucket + 8 * index, 8)
        _comparison(vm)
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
            _flag0(vm)
            checksum = ((checksum ^ (pointer >> 32)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            _comparison(vm)
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='payload_body.integrity_marker')
    if node:
        pointer = vm.memory.load(node + 8, 8)
        return vm.memory.load(pointer, 1)
    return 0


def _piece(vm, source, target, offset, width):
    value = vm.memory.load(source + offset, width)
    vm.memory.store(target + offset, value, width, source='payload_body.field_piece')


def _copy(vm, source, target, size, mandatory):
    offset = 0
    if mandatory:
        _piece(vm, source, target, 0, 1)
        offset = 1
    else:
        if target & 3:
            _piece(vm, source, target, 0, 1)
            offset = 1
    for step in range(2):
        if offset < size and (target + offset) & 3:
            _piece(vm, source, target, offset, 1)
            offset += 1
    while offset + 4 <= size:
        _piece(vm, source, target, offset, 4)
        offset += 4
    while offset < size:
        _piece(vm, source, target, offset, 1)
        offset += 1


def prepare_primary_payload_body(vm):
    vm.primary_payload_body_state = {'phase': 'word', 'lookups': 0,
                                     'field_bytes': 0, 'cleared_bytes': 0}
    state = vm.primary_payload_body_state
    _word_sources(vm, 47211, 132, 62, 6369, 6370)
    for index, key in enumerate((131, 132)):
        value = _storage_byte(vm, key)
        vm.memory.store(vm.cells.value(6370) + index, value, 1,
                        source='payload_body.word_lookup')
        state['lookups'] += 1
    value = vm.memory.load(vm.cells.value(62), 8) & 0xFFFF
    vm.memory.store(vm.cells.value(132), value, 2, source='payload_body.word')
    target = vm.cells.value(103) + 10
    _copy(vm, vm.cells.value(6369), target, 2, True)
    state['field_bytes'] += 2
    state['phase'] = 'small_field'
    target = vm.cells.value(103) + 12
    _copy(vm, vm.cells.value(2081), target, 2, False)
    state['field_bytes'] += 2
    _clear(vm, vm.cells.value(2080), 4)
    state['cleared_bytes'] += 4
    state['phase'] = 'control'
    target = vm.cells.value(103) + 8
    vm._write(6614, target, 8, 'payload_body.front_checksum_pointer')
    _copy(vm, vm.cells.value(130), target, 1, False)
    state['field_bytes'] += 1
    state['phase'] = 'first_material'
    target = vm.cells.value(103) + 25
    _copy(vm, vm.cells.value(2614), target, 16, True)
    state['field_bytes'] += 16
    state['phase'] = 'second_material'
    target = vm.cells.value(103) + 41
    _copy(vm, vm.cells.value(3012), target, 9, True)
    state['field_bytes'] += 9
    state['phase'] = 'clear'
    pointer = vm.cells.value(2614)
    for index in range(33):
        _comparison(vm)
        if index < 32:
            vm.memory.store(pointer + index, 0, 1, source='payload_body.material_clear')
            state['cleared_bytes'] += 1
    state['phase'] = 'last_control'
    target = vm.cells.value(103) + 58
    value = vm.memory.load(vm.cells.value(1198), 1)
    vm.memory.store(target, value, 1, source='payload_body.last_control')
    state['field_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 51773, 1237, 1235, False
    vm.auxiliary = (0, 1948415766)
    state['phase'] = 'complete'
    return True
