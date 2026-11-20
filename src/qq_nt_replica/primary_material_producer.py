from .primary_material_state import _left
from .primary_ecrypt import _indexed_pointer, _native_call


def _clear_bitmap(vm, word, block, predecessor, auxiliary, destination):
    vm.pc, vm.block, vm.predecessor, vm.initial_block = word, block, predecessor, False
    vm.auxiliary = (0, auxiliary)
    _indexed_pointer(vm, word, destination, 37, 47, (145, 145))
    _native_call(vm, word + 8, word + 17, 121, 157,
                 (destination, 158, 4386), destination + 1)


def _buffer_pointer(vm, word, block, predecessor, auxiliary, base, destination):
    vm.pc, vm.block, vm.predecessor, vm.initial_block = word, block, predecessor, False
    vm.auxiliary = (0, auxiliary)
    _indexed_pointer(vm, word, destination, 37, base, (145, 145))


def _material_pointers(vm, word, destination):
    for ordinal, base in enumerate((52, 53, 54, 55, 52)):
        _indexed_pointer(vm, word + ordinal * 8, destination + ordinal, 37, base, (145, 145))


def _selected(vm, index):
    return vm.memory.load(vm.cells.value(4391) + 8 * index, 8) & 0xFFFFFFFF


def _deposit(vm, key_cell, buffer_cell, shift_word, state):
    for index in range(8):
        count = _left(vm, index, 3, shift_word, bits=64)
        key = vm.cells.value(key_cell)
        value = (key >> (count & 63)) & 255
        offset = _selected(vm, index)
        vm.memory.store(vm.cells.value(buffer_cell) + offset, value, 1,
                        source='material_producer.selected_byte')
        state['selected_bytes'] += 1


def _fill(vm, buffer_cell, state):
    for index in range(8):
        offset = _selected(vm, index)
        vm.memory.store(vm.cells.value(47) + offset, 1, 1,
                        source='material_producer.bitmap')
        state['marked_bytes'] += 1
    for index in range(37):
        if not vm.memory.load(vm.cells.value(47) + index, 1):
            first = vm.memory.load(vm.cells.value(buffer_cell) + 15, 1)
            second = vm.memory.load(vm.cells.value(buffer_cell) + 36, 1)
            vm.memory.store(vm.cells.value(buffer_cell) + index,
                            first ^ second ^ index, 1,
                            source='material_producer.feedback_byte')
            state['filled_bytes'] += 1


def produce_primary_material(vm):
    vm.primary_material_producer_state = {'phase': 'pointers', 'selected_bytes': 0,
                                         'marked_bytes': 0, 'filled_bytes': 0,
                                         'memsets': 0, 'retained_steps': 0}
    state = vm.primary_material_producer_state
    _material_pointers(vm, 41978, 5668)
    state['phase'] = 'base'
    _deposit(vm, 5667, 5672, 42059, state)
    _clear_bitmap(vm, 42036, 974, 972, 963497986, 5676)
    state['memsets'] += 1
    _fill(vm, 5672, state)
    _buffer_pointer(vm, 42265, 980, 977, 1413263361, 53, 5704)
    state['phase'] = 'first'
    _deposit(vm, 5553, 5704, 42314, state)
    _clear_bitmap(vm, 42291, 984, 982, 567377922, 5708)
    state['memsets'] += 1
    _fill(vm, 5704, state)
    _buffer_pointer(vm, 42520, 990, 987, 922370050, 54, 5736)
    state['phase'] = 'second'
    _deposit(vm, 5552, 5736, 42569, state)
    _clear_bitmap(vm, 42546, 994, 992, 2021953537, 5740)
    state['memsets'] += 1
    state['phase'] = 'complete'
    return True
