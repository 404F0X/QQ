from .primary_material_state import _flag0
from .primary_rolling_state import _shift


def _pointer(vm, base, index, destination, *, stride=1, array=False):
    offset = 0
    if array:
        offset = 64 * vm.memory.load(vm.cells.pointer(145), 4)
    offset += stride * vm.memory.load(vm.cells.pointer(index), 4)
    vm._write(destination, vm.cells.value(base) + offset, 8, 'material_rounds.pointer')


def _load(vm, source, destination, width):
    value = vm.memory.load(vm.cells.value(source), width)
    vm._write(destination, value, 8 if width == 8 else 4, 'material_rounds.load')


def _store(vm, source, destination, width, *, wide=False):
    pointer = vm.cells.value(destination)
    value = vm.memory.load(vm.cells.pointer(source), 4 if wide else width)
    vm.memory.store(pointer, value, width, source='material_rounds.store')


def _next(vm, index, step, destination):
    vm._write(destination, vm._signed_cell(index, 7) + vm._signed_cell(step, 7),
              8, 'material_rounds.next')


def _less(vm, index, limit, destination):
    vm._write(destination, int(vm.cells.value(index) < vm.cells.value(limit)),
              4, 'material_rounds.condition')
    return bool(vm.cells.value(destination))


def fold_primary_material_rounds(vm):
    vm.primary_material_rounds_state = {'phase': 'round_control', 'key_qwords': 0,
                                      'control_rounds': 0, 'round_writes': 0,
                                      'selected_bytes': 0, 'copy_bytes': 0,
                                      'pointer_copies': 0, 'retained_steps': 0}
    state = vm.primary_material_rounds_state
    previous = 757
    while True:
        vm._write(4530, vm.cells.value(145 if previous == 757 else 4531),
                  8, 'material_rounds.round_index')
        if not _less(vm, 4530, 181, 4532):
            break
        state['phase'] = 'round_control'
        _pointer(vm, 4252, 4530, 4558, stride=8)
        _load(vm, 4558, 4559, 8)
        state['key_qwords'] += 1
        _store(vm, 4560, 15, 1)
        state['round_writes'] += 1
        previous_byte = 760
        state['phase'] = 'round_bytes'
        while True:
            vm._write(4561, vm.cells.value(145 if previous_byte == 760 else 4562),
                      8, 'material_rounds.byte_index')
            if not _less(vm, 4561, 4386, 4563):
                break
            _pointer(vm, 4262, 4561, 4564)
            _load(vm, 4564, 4565, 1)
            _pointer(vm, 4262, 4561, 4566)
            _store(vm, 4565, 4566, 1)
            state['round_writes'] += 1
            _load(vm, 15, 4567, 1)
            vm.auxiliary = (0, 6996)
            vm._write(4568, vm._signed_cell(4565, 1) ^ vm._signed_cell(4567, 1),
                      8, 'material_rounds.first_control_xor')
            _store(vm, 4568, 4566, 1)
            state['round_writes'] += 1
            _load(vm, 15, 4569, 1)
            vm._write(4570, vm._signed_cell(4568, 1) ^ vm._signed_cell(4569, 1),
                      8, 'material_rounds.second_control_xor')
            _store(vm, 4570, 4566, 1, wide=True)
            state['round_writes'] += 1
            vm.auxiliary = (0, 1022705666)
            _next(vm, 4561, 163, 4562)
            previous_byte = 771
        state['phase'] = 'round_selected'
        previous_selected = 772
        while True:
            vm._write(4571, vm.cells.value(145 if previous_selected == 772 else 4572),
                      8, 'material_rounds.selected_index')
            if not _less(vm, 4571, 184, 4573):
                break
            vm.auxiliary = (0, 63223)
            _shift(vm, 4571, 169, 4574, 33777, 8)
            key = vm.memory.load(vm.cells.pointer(4559), 8)
            count = vm.memory.load(vm.cells.pointer(4574), 1)
            vm._write(4575, key >> (count & 63), 8, 'material_rounds.key_byte_shift')
            vm._write(4576, vm.cells.value(4575) & 255, 8, 'material_rounds.key_byte')
            _pointer(vm, 4391, 4571, 4577, stride=8, array=True)
            _load(vm, 4577, 4578, 8)
            _pointer(vm, 4262, 4578, 4579)
            _load(vm, 4579, 4580, 1)
            vm._write(4581, vm.cells.value(4575) & 255, 8, 'material_rounds.key_byte_copy')
            vm.auxiliary = (0, 7725)
            vm._write(4583, vm._signed_cell(4581, 1) ^ vm._signed_cell(4582, 1),
                      8, 'material_rounds.key_complement')
            vm.auxiliary = (0, 55127)
            vm._write(4584, vm._signed_cell(4580, 1) & vm._signed_cell(4583, 1),
                      8, 'material_rounds.first_selected_part')
            vm.auxiliary = (0, 36396)
            _flag0(vm)
            vm._write(4585, vm._signed_cell(4580, 1) ^ vm._signed_cell(4582, 1),
                      8, 'material_rounds.current_complement')
            vm._write(4586, vm._signed_cell(4576, 1) & vm._signed_cell(4585, 1),
                      8, 'material_rounds.second_selected_part')
            vm.auxiliary = (0, 25337)
            vm._write(4587, vm._signed_cell(4584, 1) | vm._signed_cell(4586, 1),
                      8, 'material_rounds.selected_mix')
            _pointer(vm, 4262, 4578, 4588)
            _store(vm, 4587, 4588, 1)
            state['selected_bytes'] += 1
            vm.auxiliary = (0, 1419341826)
            _next(vm, 4571, 163, 4572)
            previous_selected = 774
        state['control_rounds'] += 1
        vm.auxiliary = (0, 1713213442)
        _next(vm, 4530, 163, 4531)
        previous = 759
    state['phase'] = 'final_copy'
    previous = 761
    while True:
        vm._write(4533, vm.cells.value(145 if previous == 761 else 4534),
                  8, 'material_rounds.copy_index')
        if not _less(vm, 4533, 4409, 4535):
            break
        _pointer(vm, 4262, 4533, 4536)
        vm.execute_once(15, (4, 2, 4536, 4537))
        state['pointer_copies'] += 1
        _load(vm, 4537, 4538, 4)
        _pointer(vm, 4262, 4533, 4539)
        vm.execute_once(15, (4, 2, 4539, 4540))
        state['pointer_copies'] += 1
        _store(vm, 4538, 4540, 4)
        state['copy_bytes'] += 4
        vm.auxiliary = (0, 463536130)
        _next(vm, 4533, 172, 4534)
        previous = 763
    previous = 762
    while True:
        vm._write(4541, vm.cells.value(4409 if previous == 762 else 4542),
                  8, 'material_rounds.tail_index')
        if not _less(vm, 4541, 4386, 4543):
            break
        _pointer(vm, 4262, 4541, 4544)
        _load(vm, 4544, 4545, 1)
        _pointer(vm, 4262, 4541, 4546)
        _store(vm, 4545, 4546, 1, wide=True)
        state['copy_bytes'] += 1
        vm.auxiliary = (0, 453926913)
        _next(vm, 4541, 163, 4542)
        previous = 765
    state['phase'] = 'final_selected'
    previous = 766
    while True:
        vm._write(4547, vm.cells.value(145 if previous == 766 else 4548),
                  8, 'material_rounds.final_selected_index')
        if not _less(vm, 4547, 184, 4549):
            break
        _pointer(vm, 4391, 4547, 4550, stride=8, array=True)
        _load(vm, 4550, 4551, 8)
        _pointer(vm, 4262, 4551, 4552)
        _load(vm, 4552, 4553, 1)
        _pointer(vm, 4447, 4551, 4554)
        _load(vm, 4554, 4555, 1)
        vm._write(4556, vm._signed_cell(4555, 1) ^ vm._signed_cell(4553, 1),
                  8, 'material_rounds.final_xor')
        _pointer(vm, 4262, 4551, 4557)
        _store(vm, 4556, 4557, 1)
        state['selected_bytes'] += 1
        vm.auxiliary = (0, 960303106)
        _next(vm, 4547, 163, 4548)
        previous = 768
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 33891, 769, 767, False
    state['phase'] = 'complete'
    return True
