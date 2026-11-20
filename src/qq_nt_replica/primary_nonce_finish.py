from .primary_material_rounds import _load
from .primary_material_state import _comparison, _flag0
from .primary_vm import PrimarySemanticUnavailable


def _phi(vm, destination, first, previous, second, back, end):
    vm.pc = end
    source = first if vm.predecessor == previous else second if vm.predecessor == back else None
    if source is None:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(destination, vm.cells.value(source), 8, 'nonce_finish.phi')


def _add(vm, typ, first, second, destination, end):
    vm.pc = end
    vm._write(destination, vm._signed_cell(first, typ) + vm._signed_cell(second, typ),
              8, 'nonce_finish.add')


def _store(vm, source, destination, width, end):
    vm.pc = end
    pointer = vm.cells.value(destination)
    value = vm.memory.load(vm.cells.pointer(source), width)
    vm.memory.store(pointer, value, width, source='nonce_finish.store')


def _pointer(vm, typ, base, destination, first, second, end):
    vm.pc = end - 1
    offset = vm.program.size(typ) * vm.memory.load(vm.cells.pointer(first), 4)
    vm.pc = end
    index = vm.memory.load(vm.cells.pointer(second), 4)
    delta, unused = vm._indexed_offset(typ, index)
    vm._write(destination, vm.cells.value(base) + ((offset + delta) & 0xFFFFFFFFFFFFFFFF),
              8, 'nonce_finish.pointer')


def finish_primary_nonce(vm):
    if vm.pc != 6925:
        return False
    state = getattr(vm, 'primary_nonce_state', None)
    if isinstance(state, dict):
        state['phase'] = 'scratch_xor'
    while True:
        _phi(vm, 1088, 145, 149, 1089, 151, 6932)
        vm.pc = 6937
        vm._write(1090, int(vm.cells.value(1088) < vm.cells.value(169)), 4, 'nonce_finish.less')
        vm.pc = 6941
        vm._jump(151 if vm.cells.value(1090) else 152)
        if vm.block == 152:
            break
        vm.pc = 7073
        _pointer(vm, 54, 90, 1110, 145, 1088, 7073)
        vm.pc = 7077
        _load(vm, 1110, 1111, 1)
        vm.pc = 7082
        vm._write(1112, vm._signed_cell(1111, 1) ^ vm._signed_cell(167, 1), 8, 'nonce_finish.xor')
        _store(vm, 1112, 1110, 1, 7086)
        vm.pc = 7090
        vm.auxiliary = (0, 567140353)
        _add(vm, 7, 1088, 163, 1089, 7095)
        vm.pc = 7097
        vm._jump(150)
    vm.pc = 6945
    vm.auxiliary = (0, 1634919763)
    vm.pc = 6946
    _comparison(vm)
    vm.pc = 6950
    vm._write(1091, int(vm._signed_cell(988, 1) == vm._signed_cell(497, 1)), 4, 'nonce_finish.equal')
    vm.pc = 6954
    _load(vm, 114, 1092, 4)
    vm.pc = 6959
    vm._write(1094, vm._signed_cell(1092, 3) & vm._signed_cell(1093, 3), 8, 'nonce_finish.and')
    vm.pc = 6962
    vm.auxiliary = (0, 2117627906)
    _add(vm, 3, 1094, 396, 1095, 6967)
    _store(vm, 1095, 114, 4, 6971)
    vm.pc = 6973
    vm._jump(153)
    if isinstance(state, dict):
        state['phase'] = 'crc'
    while True:
        _phi(vm, 1096, 169, 152, 1097, 154, 6980)
        _phi(vm, 1098, 994, 152, 1099, 154, 6987)
        _phi(vm, 1100, 873, 152, 1101, 154, 6994)
        vm.pc = 6998
        vm.auxiliary = (0, 272772723)
        vm.pc = 7003
        vm._write(1102, int(vm._signed_cell(1096, 7) == vm._signed_cell(145, 7)), 4, 'nonce_finish.equal')
        vm.pc = 7007
        vm._jump(155 if vm.cells.value(1102) else 154)
        if vm.block == 155:
            break
        vm.pc = 7011
        vm.auxiliary = (0, 1110302722)
        _add(vm, 7, 1096, 233, 1097, 7016)
        vm.pc = 7023
        offset = vm.memory.load(vm.cells.pointer(163), 4)
        vm._write(1099, vm.cells.value(1098) + offset, 8, 'nonce_finish.pointer')
        vm.pc = 7027
        _load(vm, 1098, 1103, 1)
        vm.pc = 7032
        vm._write(1104, vm.memory.load(vm.cells.pointer(1103), 4), 8, 'nonce_finish.extend')
        vm.pc = 7035
        vm.auxiliary = (0, 6732)
        vm.pc = 7041
        vm._write(1105, vm._signed_cell(1100, 3) ^ vm._signed_cell(1104, 3), 8, 'nonce_finish.xor')
        vm.pc = 7046
        vm.memory.load(vm.image_base + 0x677E1B4, 4)
        vm.memory.load(vm.image_base + 0x677E1B8, 4)
        for site in ('35DA1CC', '35DA241', '35DA076'):
            if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
                raise PrimarySemanticUnavailable(f'once10 current-global reload loop at{site}')
        vm._write(1106, vm.cells.value(1105), 8, 'nonce_finish.qcopy')
        vm.pc = 7054
        _pointer(vm, 149, 1108, 1107, 145, 1106, 7054)
        vm.pc = 7058
        _load(vm, 1107, 1109, 1)
        vm.pc = 7063
        vm._write(1101, vm.memory.load(vm.cells.pointer(1109), 4), 8, 'nonce_finish.extend')
        vm.pc = 7065
        vm._jump(153)
    vm.pc = 7102
    vm._write(1113, vm.cells.value(1100) & 255, 8, 'nonce_finish.mask')
    vm.pc = 7106
    vm.auxiliary = (0, 52845)
    vm.pc = 7112
    _flag0(vm)
    vm._write(1115, vm._signed_cell(1113, 1) ^ vm._signed_cell(1114, 1), 8, 'nonce_finish.xor')
    vm.pc = 7117
    vm._write(1116, vm.memory.load(vm.cells.pointer(1091), 1), 8, 'nonce_finish.extend')
    vm.pc = 7120
    vm.auxiliary = (0, 1615052802)
    _add(vm, 1, 1115, 1116, 1117, 7125)
    vm.pc = 7132
    offset = vm.memory.load(vm.cells.pointer(169), 4)
    vm._write(1118, vm.cells.value(952) + offset, 8, 'nonce_finish.pointer')
    _store(vm, 1117, 1118, 1, 7136)
    vm.pc = 7143
    offset = vm.memory.load(vm.cells.pointer(163), 4)
    vm._write(1119, vm.cells.value(934) + offset, 8, 'nonce_finish.pointer')
    vm.pc = 7147
    _load(vm, 1119, 1120, 1)
    vm.pc = 7150
    vm.auxiliary = (0, 54647)
    vm.pc = 7155
    vm._write(1122, vm._signed_cell(1120, 1) & vm._signed_cell(1121, 1), 8, 'nonce_finish.and')
    _store(vm, 1122, 1119, 1, 7159)
    if isinstance(state, dict):
        state['phase'] = 'complete'
    return True
