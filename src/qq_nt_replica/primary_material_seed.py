from .primary_material_key import _finish_key, _key_pointer
from .primary_material_state import _comparison, _left
from .primary_ecrypt import _indexed_pointer


def _index(vm, value, source, target):
    vm._write(source, value, 8, 'material_seed.current_index')
    vm.execute_once(10, (7, 3, source, target))
    return vm.cells.value(target) & 0xFFFFFFFF


def _copy(vm, source, target, state):
    prefix = vm.cells.value(5014) & 0xFFFFFFFFFFFFFFFC
    for index in range(0, prefix, 4):
        value = vm.memory.load(vm.cells.value(source) + index, 4)
        pointer = vm.cells.value(target) + index
        vm.memory.store(pointer, value, 4, source='material_seed.copy_dword')
        state['copied_bytes'] += 4
    index = prefix
    while index < vm.cells.value(5014):
        value = vm.memory.load(vm.cells.value(source) + index, 1)
        pointer = vm.cells.value(target) + index
        vm.memory.store(pointer, value, 1, source='material_seed.copy_byte')
        state['copied_bytes'] += 1
        index += 1


def _seed_xor(vm, word):
    flag, typ, left, right, destination = tuple(vm.program.words[word + 1:word + 6])
    vm.auxiliary = (0, vm.program.words[word - 1])
    vm.block, vm.predecessor = (836, 834) if word == 37259 else (838, 837)
    vm.initial_block = False
    vm.pc = word + 6
    current = vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True)
    if current == -0x80000000:
        vm.execute_typed((typ, left, right, destination))
    vm.execute_typed((typ, left, right, destination))
    return vm.memory.load(vm.cells.pointer(destination), 1)


def _advance_seed(vm, value, index, shifts, word):
    feedback = ((value >> 7) ^ (value >> 5) ^ (value >> 4) ^ (value >> 3)) & 1
    value = (_left(vm, value, 1, shifts[0]) | feedback) & 255
    feedback_cell = 5040 if word == 37259 else 5064
    vm._write(feedback_cell, value if value < 128 else value - 256, 8,
              'material_seed.feedback')
    if word == 37443:
        vm.pc = 37424
        vm.execute_once(9, (1, 3, 5048, 5065))
        vm.auxiliary = (0, 1476084227)
        vm.pc = 37432
        vm.execute_once(0, (1, 5065, 2243, 5066))
        vm.auxiliary = (0, 917467137)
        vm.pc = 37440
        vm.execute_once(1, (1, 5066, 1645, 5067))
    value = _seed_xor(vm, word)
    value = (_left(vm, value, 3, shifts[1]) | (value >> 5)) & 255
    return value or ((index & 255) ^ 0xA5)


def decode_primary_material_seed(vm, *, max_steps=1_000_000):
    from .errors import InputError
    from .primary_vm import PrimaryProgramLimit

    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')

    state = getattr(vm, 'primary_material_seed_state', None)
    if state is None or state.get('phase') == 'complete':
        state = {'execution': 'source', 'phase': 'running', 'retained_steps': 0}
        vm.primary_material_seed_state = state
    for _ in range(max_steps):
        if vm.pending_once10 is None and vm.pending_once9 is None and vm.pc == 37823:
            state['phase'] = 'complete'
            return True
        initial_steps = len(vm.trace)
        try:
            vm.step()
        finally:
            state['retained_steps'] += len(vm.trace) - initial_steps
    if vm.pending_once10 is None and vm.pending_once9 is None and vm.pc == 37823:
        state['phase'] = 'complete'
        return True
    raise PrimaryProgramLimit(f'Python seed execution limit after{max_steps} instructions at word{vm.pc}')
