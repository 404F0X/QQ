from .primary_material_state import _comparison, _flag0, _left


def _selected(vm, index):
    return vm.memory.load(vm.cells.value(4391) + 8 * index, 8) & 0xFFFFFFFF


def _copy(vm, source, target):
    for index in range(0, 36, 4):
        value = vm.memory.load(vm.cells.value(source) + index, 4)
        pointer = vm.cells.value(target) + index
        vm.memory.store(pointer, value, 4, source='material_fold.copy_dword')
    value = vm.memory.load(vm.cells.value(source) + 36, 1)
    pointer = vm.cells.value(target) + 36
    vm.memory.store(pointer, value, 1, source='material_fold.copy_tail')


def fold_primary_material(vm):
    vm.primary_material_fold_state = {'phase': 'mark', 'marked_bytes': 0,
                                     'filled_bytes': 0, 'copy_bytes': 0,
                                     'selected_bytes': 0, 'control_rounds': 0,
                                     'round_writes': 0}
    state = vm.primary_material_fold_state
    for index in range(8):
        offset = _selected(vm, index)
        vm.memory.store(vm.cells.value(47) + offset, 1, 1,
                        source='material_fold.bitmap')
        state['marked_bytes'] += 1
    state['phase'] = 'fill'
    for index in range(37):
        marked = vm.memory.load(vm.cells.value(47) + index, 1)
        _comparison(vm)
        if not marked:
            first = vm.memory.load(vm.cells.value(5736) + 15, 1)
            second = vm.memory.load(vm.cells.value(5736) + 36, 1)
            vm.memory.store(vm.cells.value(5736) + index, first ^ second ^ index, 1,
                            source='material_fold.unmarked_byte')
            state['filled_bytes'] += 1
    state['phase'] = 'third_copy'
    vm._write(5768, vm.cells.value(55), 8, 'material_fold.third_pointer')
    _copy(vm, 5704, 5768)
    state['copy_bytes'] += 37
    state['phase'] = 'third_selected'
    for index in range(8):
        offset = _selected(vm, index)
        first = vm.memory.load(vm.cells.value(5704) + offset, 1)
        second = vm.memory.load(vm.cells.value(5736) + offset, 1)
        _flag0(vm)
        vm.memory.store(vm.cells.value(5768) + offset, first ^ second, 1,
                        source='material_fold.third_selected')
        state['selected_bytes'] += 1
    state['phase'] = 'material_copy'
    _copy(vm, 5672, 5554)
    state['copy_bytes'] += 37
    state['phase'] = 'material_selected'
    for index in range(8):
        offset = _selected(vm, index)
        first = vm.memory.load(vm.cells.value(5672) + offset, 1)
        second = vm.memory.load(vm.cells.value(5768) + offset, 1)
        vm.memory.store(vm.cells.value(5554) + offset, first | second, 1,
                        source='material_fold.material_selected')
        state['selected_bytes'] += 1
    for round_index in range(3):
        state['phase'] = 'round_control'
        key = vm.memory.load(vm.cells.value(5542) + 8 * round_index, 8)
        vm.memory.store(vm.cells.value(48), 90, 1, source='material_fold.round_control')
        state['round_writes'] += 1
        for index in range(37):
            value = vm.memory.load(vm.cells.value(5554) + index, 1)
            pointer = vm.cells.value(5554) + index
            vm.memory.store(pointer, value, 1, source='material_fold.round_self')
            control = vm.memory.load(vm.cells.value(48), 1)
            value ^= control
            vm.memory.store(pointer, value, 1, source='material_fold.round_first_xor')
            control = vm.memory.load(vm.cells.value(48), 1)
            vm.memory.store(pointer, value ^ control, 1,
                            source='material_fold.round_second_xor')
            state['round_writes'] += 3
        state['phase'] = 'round_selected'
        for index in range(8):
            count = _left(vm, index, 3, 43497, bits=64)
            key_byte = (key >> (count & 63)) & 255
            offset = _selected(vm, index)
            current = vm.memory.load(vm.cells.value(5554) + offset, 1)
            first = current & (key_byte ^ 255)
            _flag0(vm)
            second = key_byte & (current ^ 255)
            vm.memory.store(vm.cells.value(5554) + offset, first | second, 1,
                            source='material_fold.round_selected')
            state['selected_bytes'] += 1
        state['control_rounds'] += 1
    state['phase'] = 'final_copy'
    _copy(vm, 5554, 5554)
    state['copy_bytes'] += 37
    state['phase'] = 'final_selected'
    for index in range(8):
        offset = _selected(vm, index)
        first = vm.memory.load(vm.cells.value(5554) + offset, 1)
        second = vm.memory.load(vm.cells.value(5736) + offset, 1)
        vm.memory.store(vm.cells.value(5554) + offset, first ^ second, 1,
                        source='material_fold.final_selected')
        state['selected_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 43611, 1029, 1027, False
    vm.auxiliary = (0, 607469569)
    state['phase'] = 'complete'
    return True
