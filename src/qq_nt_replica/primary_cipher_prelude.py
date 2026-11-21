from .primary_material_state import _comparison, _left
from .primary_ecrypt import _native_call, _store_cell
from .primary_vm import PrimarySemanticUnavailable


def _padding_conversion(vm):
    vm.pc = 64791
    bits = vm.memory.load(vm.cells.pointer(8638), 4)
    exponent, fraction = (bits >> 23) & 255, bits & 0x7FFFFF
    if exponent == 255:
        raise PrimarySemanticUnavailable('L21 nonfinite CVTTSS2SI exception route is unavailable')
    if exponent < 127:
        value = 0
    else:
        shift = exponent - 150
        mantissa = 0x800000 | fraction
        value = mantissa << shift if shift >= 0 else mantissa >> -shift
        if bits >> 31:
            value = -value
    if not -(1 << 63) <= value < 1 << 63:
        raise PrimarySemanticUnavailable('L21 out-of-range CVTTSS2SI exception route is unavailable')
    vm._write(8641, value & 0xFFFFFFFF, 8, 'L21.float32_i64_low_dword_q')


def _source_padding(vm):
    vm.pc = 64770
    vm.cells.copy_q_clear_owned(84, 8636)
    _native_call(vm, 64770, 64779, 121, 157, (8636, 158, 205), 8637)
    _native_call(vm, 64779, 64786, 203, 8639, (8640,), 8638)
    _padding_conversion(vm)


def _source_clock(vm):
    vm.pc = 64828
    vm.cells.copy_q_clear_owned(85, 8647)
    _store_cell(vm, 64828, 8, 145, 85)
    _native_call(vm, 64832, 64838, 135, 8649, (), 8648)


def _index(vm, value, source, destination):
    vm._write(source, value, 8, 'cipher_prelude.index_source')
    vm.execute_once(10, (7, 3, source, destination))
    return vm.cells.value(destination)


def prepare_primary_cipher(vm):
    vm.primary_cipher_prelude_state = {'phase': 'clear', 'cleared_bytes': 0,
                                       'seed_bytes': 0, 'iv_bytes': 0,
                                       'completed_source_calls': 0}
    state = vm.primary_cipher_prelude_state
    for cell in (94, 82, 83):
        pointer = vm.cells.value(cell)
        if cell == 83:
            vm._write(8611, pointer, 8, 'cipher_prelude.current_iv_pointer')
        for index in range(17):
            _comparison(vm)
            if index == 16:
                break
            vm.memory.store(pointer + index, 0, 1, source='cipher_prelude.clear_byte')
            state['cleared_bytes'] += 1
    state['phase'] = 'seed_copy'
    target = vm.cells.value(8611)
    for index in (0, 4):
        value = vm.memory.load(vm.cells.value(8375) + index, 4)
        vm.memory.store(target + index, value, 4, source='cipher_prelude.seed_word')
        state['seed_bytes'] += 4
    state['phase'] = 'iv'
    for index in range(8):
        offset = _index(vm, 7 - index, 8651, 8652)
        value = vm.memory.load(vm.cells.value(8375) + offset, 1)
        first = vm.memory.load(vm.cells.value(8611), 1)
        second = vm.memory.load(vm.cells.value(83) + 4, 1)
        value ^= (first * second) & 0x7F
        offset = _index(vm, index + 8, 8631, 8662)
        vm.memory.store(vm.cells.value(83) + offset, value, 1, source='cipher_prelude.iv_byte')
        state['iv_bytes'] += 1
    state['phase'] = 'source_memset_ceil_conversion'
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 64765, 1609, 1607, False
    vm.auxiliary = (0, 440572518)
    _source_padding(vm)
    state.update(phase='padding', completed_source_calls=2)
    value = vm.memory.load(vm.cells.pointer(8641), 4, signed=True)
    vm._write(8643, min(value, 256), 8, 'cipher_prelude.block_count')
    shifted = _left(vm, value, 4, 64810) & 0xFFFFFFFF
    shifted = shifted if shifted < 0x80000000 else shifted - 0x100000000
    vm._write(8646, shifted - 75, 8, 'cipher_prelude.padding_bytes')
    state['phase'] = 'source_offset_and_clock'
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 64823, 1609, 1607, False
    vm.auxiliary = (0, 13162)
    _source_clock(vm)
    state.update(phase='complete', completed_source_calls=3)
    return True
