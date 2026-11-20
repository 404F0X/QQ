from .primary_material_fold import _copy, _selected
from .primary_material_state import _flag0, _left


def merge_primary_material(vm):
    vm.primary_material_merge_state = {'phase': 'mark', 'marked_bytes': 0,
                                      'filled_bytes': 0, 'copy_bytes': 0,
                                      'selected_bytes': 0, 'control_rounds': 0,
                                      'round_writes': 0}
    state = vm.primary_material_merge_state
    for index in range(8):
        offset = _selected(vm, index)
        vm.memory.store(vm.cells.value(47) + offset, 1, 1,
                        source='material_merge.bitmap')
        state['marked_bytes'] += 1
    state['phase'] = 'fill'
    for index in range(37):
        marked = vm.memory.load(vm.cells.value(47) + index, 1)
        if not marked:
            first = vm.memory.load(vm.cells.value(5182) + 15, 1)
            second = vm.memory.load(vm.cells.value(5182) + 36, 1)
            _flag0(vm)
            vm.memory.store(vm.cells.value(5182) + index, first ^ second ^ index, 1,
                            source='material_merge.unmarked_byte')
            state['filled_bytes'] += 1
    state['phase'] = 'third_copy'
    vm._write(5214, vm.cells.value(55), 8, 'material_merge.third_pointer')
    _copy(vm, 5150, 5214)
    state['copy_bytes'] += 37
    state['phase'] = 'third_selected'
    for index in range(8):
        offset = _selected(vm, index)
        first = vm.memory.load(vm.cells.value(5150) + offset, 1)
        second = vm.memory.load(vm.cells.value(5182) + offset, 1)
        vm.memory.store(vm.cells.value(5214) + offset, first ^ second, 1,
                        source='material_merge.third_selected')
        state['selected_bytes'] += 1
    state['phase'] = 'material_copy'
    _copy(vm, 5118, 5000)
    state['copy_bytes'] += 37
    state['phase'] = 'material_selected'
    for index in range(8):
        offset = _selected(vm, index)
        first = vm.memory.load(vm.cells.value(5118) + offset, 1)
        second = vm.memory.load(vm.cells.value(5214) + offset, 1)
        vm.memory.store(vm.cells.value(5000) + offset, first | second, 1,
                        source='material_merge.material_selected')
        state['selected_bytes'] += 1
    for round_index in range(6):
        state['phase'] = 'round_control'
        key = vm.memory.load(vm.cells.value(4977) + 8 * round_index, 8)
        vm.memory.store(vm.cells.value(38), 90, 1, source='material_merge.round_control')
        state['round_writes'] += 1
        for index in range(37):
            value = vm.memory.load(vm.cells.value(5000) + index, 1)
            pointer = vm.cells.value(5000) + index
            vm.memory.store(pointer, value, 1, source='material_merge.round_self')
            control = vm.memory.load(vm.cells.value(38), 1)
            value ^= control
            vm.memory.store(pointer, value, 1, source='material_merge.round_first_xor')
            control = vm.memory.load(vm.cells.value(38), 1)
            vm.memory.store(pointer, value ^ control, 1,
                            source='material_merge.round_second_xor')
            state['round_writes'] += 3
        state['phase'] = 'round_selected'
        for index in range(8):
            count = _left(vm, index, 3, 39354, bits=64)
            key_byte = (key >> (count & 63)) & 255
            offset = _selected(vm, index)
            current = vm.memory.load(vm.cells.value(5000) + offset, 1)
            first = current & (key_byte ^ 255)
            second = key_byte & (current ^ 255)
            vm.memory.store(vm.cells.value(5000) + offset, first | second, 1,
                            source='material_merge.round_selected')
            state['selected_bytes'] += 1
        state['control_rounds'] += 1
    state['phase'] = 'final_copy'
    _copy(vm, 5000, 5000)
    state['copy_bytes'] += 37
    state['phase'] = 'final_selected'
    for index in range(8):
        offset = _selected(vm, index)
        first = vm.memory.load(vm.cells.value(5000) + offset, 1)
        second = vm.memory.load(vm.cells.value(5182) + offset, 1)
        vm.memory.store(vm.cells.value(5000) + offset, first ^ second, 1,
                        source='material_merge.final_selected')
        state['selected_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 39468, 910, 908, False
    vm.auxiliary = (0, 1064558593)
    state['phase'] = 'complete'
    return True
