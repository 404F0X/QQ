def _steps(vm, word, count, state):
    vm.pc = word
    for _ in range(count):
        vm.step()
        state['retained_steps'] += 1


def _choose(vm, condition, yes, no, target, state):
    selected = yes if vm.cells.value(condition) else no
    value = vm.cells.value(selected)
    pointer = vm.cells.value(target)
    vm.memory.store(pointer, value, 8, source='material_context.selected_key')
    state['key_qwords'] += 1


def prepare_primary_material_context(vm):
    from .primary_record_frames import run_primary_key_record_frame

    return run_primary_key_record_frame(vm)
