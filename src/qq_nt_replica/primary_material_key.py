from .primary_material_state import _advance, _comparison
from .primary_ecrypt import _indexed_pointer


def _key_pointer(vm, word, block, predecessor, auxiliary, destination):
    vm.pc, vm.block, vm.predecessor, vm.initial_block = word, block, predecessor, False
    vm.auxiliary = (0, auxiliary)
    _indexed_pointer(vm, word, destination, 41, 70, (145, 145))


def _finish_key(vm, word, block, predecessor, auxiliary, pointer, loaded, join, destination):
    vm.pc, vm.block, vm.predecessor, vm.initial_block = word, block, predecessor, False
    vm.auxiliary = (0, auxiliary)
    vm.pc = word + 4
    vm._write(loaded, vm.memory.load(vm.cells.value(pointer), 8), 8, 'high.load')
    vm._jump(join)
    vm.pc = word + 15
    vm._write(destination, vm.cells.value(loaded), 8, 'L9.phi_q')


def _index(vm, value, source, target):
    vm._write(source, value, 8, 'material_key.current_index')
    vm.execute_once(10, (7, 3, source, target))
    return vm.cells.value(target) & 0xFFFFFFFF


def _copy(vm, source, target, state):
    prefix = vm.cells.value(5568) & 0xFFFFFFFFFFFFFFFC
    for index in range(0, prefix, 4):
        value = vm.memory.load(vm.cells.value(source) + index, 4)
        pointer = vm.cells.value(target) + index
        vm.memory.store(pointer, value, 4, source='material_key.copy_dword')
        state['copied_bytes'] += 4
    index = prefix
    while index < vm.cells.value(5568):
        value = vm.memory.load(vm.cells.value(source) + index, 1)
        pointer = vm.cells.value(target) + index
        vm.memory.store(pointer, value, 1, source='material_key.copy_byte')
        state['copied_bytes'] += 1
        index += 1


def decode_primary_material_key(vm, *, max_steps=1_000_000):
    from .errors import InputError
    from .primary_vm import PrimaryProgramLimit

    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')

    state = getattr(vm, 'primary_material_key_state', None)
    if state is None or state.get('phase') == 'complete':
        state = {'execution': 'source', 'phase': 'running', 'retained_steps': 0}
        vm.primary_material_key_state = state
    for _ in range(max_steps):
        if vm.pending_once10 is None and vm.pending_once9 is None and vm.pc == 41978:
            state['phase'] = 'complete'
            return True
        initial_steps = len(vm.trace)
        try:
            vm.step()
        finally:
            state['retained_steps'] += len(vm.trace) - initial_steps
    if vm.pending_once10 is None and vm.pending_once9 is None and vm.pc == 41978:
        state['phase'] = 'complete'
        return True
    raise PrimaryProgramLimit(f'Python key execution limit after{max_steps} instructions at word{vm.pc}')
