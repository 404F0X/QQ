from .primary_material_lookup import _index
from .primary_material_state import _comparison, _flag0
from .primary_ecrypt import _store_cell


def _control_sources(vm):
    vm.pc = 45055
    vm._write(6081, vm.memory.load(vm.cells.value(130), 1), 4, 'high.load')
    vm.pc = 45060
    vm.cells.copy_q_clear_owned(59, 6082)
    _store_cell(vm, 45060, 8, 145, 59)


def _header_sources(vm):
    vm.pc = 45589
    vm.cells.copy_q_clear_owned(131, 6153)
    _store_cell(vm, 45589, 8, 145, 131)
    vm.pc = 45598
    vm.cells.copy_q_clear_owned(60, 6154)
    vm.pc = 45602
    pointer = vm.cells.value(60)
    value = vm.memory.load(vm.cells.pointer(145), 8)
    vm.memory.store(pointer, value, 8, source='L6.store_integer')


def _scalar_sources(vm):
    vm.pc = 46100
    vm.cells.copy_q_clear_owned(131, 6224)
    _store_cell(vm, 46100, 1, 6223, 6224)
    vm.pc = 46109
    vm.cells.copy_q_clear_owned(61, 6225)
    _store_cell(vm, 46109, 8, 145, 61)


def _storage_byte(vm, key, stage):
    seed = vm.memory.load(vm.cells.value(112) + 34840, 8)
    if stage == 2:
        _flag0(vm)
    source, target = ((6093, 6094), (6166, 6167), (6236, 6237))[stage]
    index = _index(vm, source, target, (key >> 8) ^ (seed & 255))
    bucket = vm.memory.load(vm.cells.value(112) + 16 + 8 * index, 8)
    node = 0
    if bucket:
        source, target = ((6101, 6102), (6174, 6175), (6244, 6245))[stage]
        index = _index(vm, source, target, (key ^ ((seed >> 8) & 0xFFFF)) & 255)
        node = vm.memory.load(bucket + 8 * index, 8)
        if node:
            current = vm.memory.load(node + 4, 2)
            if stage == 2:
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
            if stage in (0, 2):
                _flag0(vm)
            checksum = ((checksum ^ (pointer & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (pointer >> 32)) * 0x01000193) & 0xFFFFFFFF
            checksum = ((checksum ^ (seed & 0xFFFFFFFF)) * 0x01000193) & 0xFFFFFFFF
            if stage == 0:
                _flag0(vm)
            checksum = ((checksum ^ (seed >> 32)) * 0x01000193) & 0xFFFFFFFF
            current = vm.memory.load(pointer, 1)
            if stage == 1:
                _flag0(vm)
            checksum = ((checksum ^ current) * 0x01000193) & 0xFFFFFFFF
            if stage in (0, 1):
                _comparison(vm)
            if saved != checksum:
                vm.memory.store(node + 24, 0x00FF012A, 4,
                                source='payload_header.integrity_marker')
    if stage in (0, 1):
        _comparison(vm)
    if node:
        pointer = vm.memory.load(node + 8, 8)
        return vm.memory.load(pointer, 1)
    return 0


def prepare_primary_payload_header(vm):
    vm.primary_payload_header_state = {'phase': 'control', 'lookups': 0,
                                       'control_bytes': 0, 'header_bytes': 0,
                                       'scalar_bytes': 0, 'field_bytes': 0}
    state = vm.primary_payload_header_state
    _control_sources(vm)
    value = _storage_byte(vm, 35, 0)
    vm.memory.store(vm.cells.value(6082), value, 1, source='payload_header.control_lookup')
    state['lookups'] += 1
    value = vm.memory.load(vm.cells.value(59), 8) & 255
    value ^= vm.cells.value(6081) & 255
    _flag0(vm)
    vm.memory.store(vm.cells.value(130), value ^ 32, 1, source='payload_header.control')
    state['control_bytes'] += 1
    state['phase'] = 'header'
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 45584, 1063, 1060, False
    vm.auxiliary = (0, 14862)
    _header_sources(vm)
    value = _storage_byte(vm, 36, 1)
    vm.memory.store(vm.cells.value(6154), value, 1, source='payload_header.header_lookup')
    state['lookups'] += 1
    value = vm.memory.load(vm.cells.value(60), 8) & 255
    vm._write(6223, value, 8, 'payload_header.header_byte')
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 46095, 1074, 1071, False
    vm.auxiliary = (0, 1476374529)
    _scalar_sources(vm)
    state['header_bytes'] += 1
    state['phase'] = 'scalar'
    value = _storage_byte(vm, 35, 2)
    vm.memory.store(vm.cells.value(6225), value, 1, source='payload_header.scalar_lookup')
    state['lookups'] += 1
    value = vm.memory.load(vm.cells.value(61), 8) & 255
    vm.memory.store(vm.cells.value(290), value, 1, source='payload_header.current_scalar_byte')
    state['scalar_bytes'] += 1
    state['phase'] = 'field'
    target = vm.cells.value(103) + 9
    value = vm.memory.load(vm.cells.value(2080), 1)
    vm.memory.store(target, value, 1, source='payload_header.current_field_byte')
    state['field_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 47211, 1109, 1107, False
    vm.auxiliary = (0, 1301418998)
    state['phase'] = 'complete'
    return True
