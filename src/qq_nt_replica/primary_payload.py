from .primary_material_state import _flag0, _left


def _state(vm):
    state = getattr(vm, 'primary_payload_state', None)
    if state is None:
        state = {'front_bytes': 0, 'masked_bytes': 0, 'back_bytes': 0, 'payload_bytes': 0}
        vm.primary_payload_state = state
    return state


def _prepare_pointer(vm):
    vm.pc = 58562
    vm.cells.copy_q_clear_owned(136, 7820)


def _finish_pointers(vm):
    vm.pc = 64020
    vm._write(8539, vm.cells.value(7857) & 255, 8, 'once9.mask_q')
    vm.pc = 64025
    vm.cells.copy_q_clear_owned(80, 8540)


def prepare_primary_payload_checksum(vm):
    _prepare_pointer(vm)
    state = _state(vm)
    state['phase'] = 'front_hash'
    source = vm.cells.value(6614)
    value = 1296417516
    for index in range(63):
        value = (value * 33 + vm.memory.load(source + index, 1)) & 0xFFFFFFFF
        state['front_bytes'] += 1
    value ^= value >> 16
    value = (value * 2246822507) & 0xFFFFFFFF
    value ^= value >> 13
    high = _left(vm, value & 0xFF00, 8, 58709)
    low = _left(vm, value & 255, 24, 58722)
    value = ((value >> 24) | ((value & 0xFF0000) >> 8) | high | low) & 0xFFFFFFFF
    temporary = vm.cells.value(136)
    vm.memory.store(temporary, value, 4, source='payload.front_checksum')
    shifted = _left(vm, value, 1, 58752) & 0xFFFFFFFF
    signed_shifted = shifted if shifted < 0x80000000 else shifted - 0x100000000
    flag = 2 if temporary < vm.cells.value(7853) else 0
    vm._write(7857, signed_shifted + flag, 8, 'payload.front_pointer_flag')
    target = vm.cells.value(6224) + 1
    vm._write(7858, target, 8, 'payload.front_field_pointer')
    state['phase'] = 'front_copy'
    source = vm.cells.value(7820)
    for index in range(4):
        current = vm.memory.load(source + index, 1)
        vm.memory.store(target + index, current, 1, source='payload.front_copy_byte')
    header = vm.memory.load(vm.cells.value(6224), 1)
    state['phase'] = 'front_mask'
    for index in range(4):
        spread = ((index ^ header) * 0x9E3779B9) & 0xFFFFFFFF
        spread ^= spread >> 16
        vm._write(7941, index, 8, 'payload.front_mask_index')
        vm.execute_once(10, (7, 3, 7941, 7948))
        pointer = target + vm.cells.value(7948)
        current = vm.memory.load(pointer, 1) ^ (spread & 255)
        vm.memory.store(pointer, current, 1, source='payload.front_mask_byte')
        state['masked_bytes'] += 1
    state['phase'] = 'front_complete'
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 59518, 1446, 1444, False
    vm.auxiliary = (0, 318242817)
    return True


def finish_primary_payload_checksum(vm):
    _finish_pointers(vm)
    state = _state(vm)
    state['phase'] = 'back_hash'
    source = vm.cells.value(290)
    value = 0x811C9DC5
    for index in range(71):
        current = value ^ vm.memory.load(source + index, 1)
        product = (current * 0x9E3779B1) & 0xFFFFFFFF
        value = ((product << 13) | (product >> 19)) & 0xFFFFFFFF
        state['back_bytes'] += 1
    value ^= value >> 16
    _flag0(vm)
    vm.memory.store(vm.cells.value(80), value, 4, source='payload.back_checksum')
    target = vm.cells.value(81)
    vm._write(8559, target, 8, 'payload.cipher_input_pointer')
    state['phase'] = 'payload_clear'
    for index in range(100):
        vm.memory.store(target + index, 0, 1, source='payload.clear_byte')
    state['phase'] = 'payload_copy'
    for index in range(0, 68, 4):
        current = vm.memory.load(source + index, 4)
        vm.memory.store(target + index, current, 4, source='payload.copy_word')
        state['payload_bytes'] += 4
    for index in range(68, 71):
        current = vm.memory.load(source + index, 1)
        vm.memory.store(target + index, current, 1, source='payload.copy_tail')
        state['payload_bytes'] += 1
    current = vm.memory.load(vm.cells.value(8540), 4)
    vm.memory.store(target + 71, current, 4, source='payload.append_checksum')
    state['payload_bytes'] += 4
    state['phase'] = 'complete'
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 64425, 1592, 1590, False
    vm.auxiliary = (0, 1010561025)
    return True
