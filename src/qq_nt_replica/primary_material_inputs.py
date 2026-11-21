from .primary_material_producer import (_buffer_pointer, _clear_bitmap, _deposit,
                                        _material_pointers, _selected)
from .primary_material_state import _comparison, _flag0


def _fill(vm, buffer_cell, state, first):
    for index in range(8):
        offset = _selected(vm, index)
        vm.memory.store(vm.cells.value(47) + offset, 1, 1,
                        source='material_inputs.bitmap')
        state['marked_bytes'] += 1
    for index in range(37):
        marked = vm.memory.load(vm.cells.value(47) + index, 1)
        if not first:
            _comparison(vm)
        if not marked:
            left = vm.memory.load(vm.cells.value(buffer_cell) + 15, 1)
            right = vm.memory.load(vm.cells.value(buffer_cell) + 36, 1)
            value = left ^ right
            if first:
                _flag0(vm)
            vm.memory.store(vm.cells.value(buffer_cell) + index, value ^ index, 1,
                            source='material_inputs.feedback_byte')
            state['filled_bytes'] += 1


def prepare_primary_material_inputs(vm):
    vm.primary_material_inputs_state = {'phase': 'pointers', 'selected_bytes': 0,
                                       'marked_bytes': 0, 'filled_bytes': 0,
                                       'memsets': 0, 'retained_steps': 0}
    state = vm.primary_material_inputs_state
    _material_pointers(vm, 37823, 5114)
    state['phase'] = 'base'
    _deposit(vm, 5113, 5118, 37904, state)
    _clear_bitmap(vm, 37881, 855, 853, 1664798721, 5122)
    state['memsets'] += 1
    _fill(vm, 5118, state, False)
    _buffer_pointer(vm, 38114, 861, 858, 2021552129, 53, 5150)
    state['phase'] = 'first'
    _deposit(vm, 4861, 5150, 38163, state)
    _clear_bitmap(vm, 38140, 865, 863, 1163079681, 5154)
    state['memsets'] += 1
    _fill(vm, 5150, state, True)
    _buffer_pointer(vm, 38373, 871, 868, 1058361346, 54, 5182)
    state['phase'] = 'second'
    _deposit(vm, 4929, 5182, 38422, state)
    _clear_bitmap(vm, 38399, 875, 873, 506359810, 5186)
    state['memsets'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 38470, 876, 875, False
    state['phase'] = 'complete'
    return True
