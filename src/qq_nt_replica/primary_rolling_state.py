from .primary_material_state import _flag0


def _shift(vm, source, count, destination, word, width):
    first = vm.memory.load(vm.image_base + 0x6D86090, 4)
    second = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((first * first) & 0xFFFFFFFF) | (abs(second) & 0xFFFFFFFF)) >> 31
    amount = vm.memory.load(vm.cells.pointer(count), 4)
    value = 0
    if not amount & 0x80000000 and amount < 8 * width:
        value = vm.memory.load(vm.cells.pointer(source), width)
        value <<= amount
    vm._write(destination, value, width, 'rolling_state.left_shift')
    if extra:
        vm.pc = word + 5
        vm.execute_typed(tuple(vm._operand() for _ in range(4)))


def mix_primary_rolling_state(vm):
    vm.primary_rolling_state = {'phase': 'mix', 'input_bytes': 0,
                               'xor_bytes': 0, 'qword_copies': 0,
                               'retained_steps': 0}
    state = vm.primary_rolling_state
    predecessor = 247
    while True:
        vm._write(1589, vm.cells.value(1590 if predecessor == 247 else 1591),
                  8, 'rolling_state.current')
        vm._write(1592, vm.cells.value(145 if predecessor == 247 else 1593),
                  8, 'rolling_state.input_index')
        vm._write(1594, int(vm.cells.value(1592) < vm.cells.value(196)),
                  4, 'rolling_state.input_condition')
        if not vm.cells.value(1594):
            break
        vm.auxiliary = (0, 16615)
        _shift(vm, 1589, 175, 1595, 10628, 8)
        current = vm.memory.load(vm.cells.pointer(1589), 8)
        count = vm.memory.load(vm.cells.pointer(169), 1)
        vm._write(1596, current >> (count & 63), 8, 'rolling_state.right_shift')
        vm.auxiliary = (0, 15884)
        vm._write(1597, vm.cells.value(1595) ^ vm.cells.value(1596),
                  8, 'rolling_state.shift_mix')
        index = vm.memory.load(vm.cells.pointer(1592), 4)
        vm._write(1598, vm.cells.value(1544) + index, 8, 'rolling_state.input_pointer')
        value = vm.memory.load(vm.cells.value(1598), 1)
        vm._write(1599, value, 4, 'rolling_state.input_byte')
        vm.execute_once(10, (7, 1, 1599, 1600))
        state['qword_copies'] += 1
        vm.auxiliary = (0, 60437)
        _flag0(vm)
        vm._write(1601, vm.cells.value(1597) ^ vm.cells.value(1600),
                  8, 'rolling_state.byte_mix')
        vm.auxiliary = (0, 1465262082)
        vm._write(1591, vm._signed_cell(1601, 7) + vm._signed_cell(1602, 7),
                  8, 'rolling_state.increment')
        vm.auxiliary = (0, 315166722)
        vm._write(1593, vm._signed_cell(1592, 7) + vm._signed_cell(163, 7),
                  8, 'rolling_state.next_input')
        state['input_bytes'] += 1
        predecessor = 249
    state['phase'] = 'xor'
    predecessor = 250
    while True:
        vm._write(1603, vm.cells.value(158 if predecessor == 250 else 1604),
                  8, 'rolling_state.output_index')
        vm._write(1605, int(vm.cells.value(1603) < vm.cells.value(502)),
                  4, 'rolling_state.output_condition')
        if not vm.cells.value(1605):
            break
        vm.auxiliary = (0, 25279)
        _shift(vm, 1603, 149, 1607, 10727, 4)
        vm.execute_once(10, (7, 3, 1607, 1608))
        state['qword_copies'] += 1
        current = vm.memory.load(vm.cells.pointer(1589), 8)
        count = vm.memory.load(vm.cells.pointer(1608), 1)
        vm._write(1609, current >> (count & 63), 8, 'rolling_state.output_shift')
        vm.execute_once(10, (7, 3, 1603, 1610))
        state['qword_copies'] += 1
        base_index = vm.memory.load(vm.cells.pointer(145), 4)
        index = vm.memory.load(vm.cells.pointer(1610), 4)
        vm._write(1611, vm.cells.value(94) + 16 * base_index + index,
                  8, 'rolling_state.output_pointer')
        value = vm.memory.load(vm.cells.value(1611), 1)
        vm._write(1612, value, 4, 'rolling_state.output_byte')
        vm._write(1613, vm.cells.value(1609) & 255, 8, 'rolling_state.mask_byte')
        vm.auxiliary = (0, 26751)
        vm._write(1614, vm._signed_cell(1612, 1) ^ vm._signed_cell(1613, 1),
                  8, 'rolling_state.output_xor')
        pointer = vm.cells.value(1611)
        value = vm.memory.load(vm.cells.pointer(1614), 1)
        vm.memory.store(pointer, value, 1, source='rolling_state.output_byte')
        vm.auxiliary = (0, 769765378)
        vm._write(1604, vm._signed_cell(1603, 3) + vm._signed_cell(269, 3),
                  8, 'rolling_state.next_output')
        state['xor_bytes'] += 1
        predecessor = 252
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 10708, 229, 251, False
    state['phase'] = 'complete'
    return True
