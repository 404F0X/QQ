from .primary_material_state import _comparison, _flag0, _left
from .primary_ecrypt import _indexed_pointer, _native_call, _store_cell


def _source_material(vm):
    vm.pc = 62621
    vm.cells.copy_q_clear_owned(139, 8352)
    _store_cell(vm, 62621, 4, 158, 139)
    _indexed_pointer(vm, 62625, 8353, 94, 140, (145, 145))
    vm.pc = 62638
    vm.cells.copy_q_clear_owned(141, 8354)
    _native_call(vm, 62638, 62644, 129, 454, (), 8355)
    vm.pc = 62649
    vm.execute_once(10, (7, 3, 8355, 8356))


def _index(vm, value, source, destination, source_type):
    vm._write(source, value, 8, 'seed_footer.index_source')
    vm.execute_once(10, (7, source_type, source, destination))
    return vm.cells.value(destination)


def _crc(vm, scratch, second):
    value = 0xFFFF
    for index in range(5):
        offset = _index(vm, index, 8484 if second else 8408,
                        8494 if second else 8418, 3)
        byte = vm.memory.load(scratch + offset, 1)
        shifted = _left(vm, byte, 8, 63680 if second else 63094)
        if second:
            _flag0(vm)
        value ^= shifted
        for bit in range(8):
            first = _left(vm, value, 1, 63742 if second else 63156)
            if not second:
                _flag0(vm)
            alternative = (first ^ 0x1021) & 0xFFFF
            other = _left(vm, value, 1, 63759 if second else 63173)
            value = (alternative if value & 0x8000 else other) & 0xFFFF
    vm.memory.store(scratch + 5, value >> 8, 1, source='seed_footer.crc_high')
    vm.memory.store(scratch + 6, value, 1, source='seed_footer.crc_low')


def _pack(vm, scratch, second):
    value = 0
    for index in range(7):
        shifted = _left(vm, value, 8, 63810 if second else 63224, bits=64)
        offset = _index(vm, index, 8510 if second else 8435,
                        8514 if second else 8439, 3)
        byte = vm.memory.load(scratch + offset, 1)
        byte = _index(vm, byte, 8516 if second else 8441,
                      8517 if second else 8442, 1)
        value = (shifted | byte) & 0xFFFFFFFFFFFFFFFF
    return value


def _square(vm, value, second):
    modulus = 0x74F3C7B3AC515AD9 if second else 0x653595DC947FC1FD
    base, multiplier, result = value, value, 0
    while True:
        base %= modulus
        if second:
            _comparison(vm)
        if multiplier == 0:
            return result
        if not second:
            _comparison(vm)
        if multiplier & 1:
            result = ((result + base) & 0xFFFFFFFFFFFFFFFF) % modulus
        base = _left(vm, base, 1, 63939 if second else 63353, bits=64) & 0xFFFFFFFFFFFFFFFF
        multiplier >>= 1


def produce_primary_seed_footer(vm):
    vm.primary_seed_footer_state = {'phase': 'source_material_call', 'seed_bytes': 0,
                                    'crc_bytes': 0, 'footer_bytes': 0}
    _source_material(vm)
    state = vm.primary_seed_footer_state
    state['phase'] = 'seed_words'
    current = vm.cells.value(8356)
    expanded = (current * 0x41C64E6D + 0x41C67EA6) & 0xFFFFFFFFFFFFFFFF
    seed = vm.cells.value(141)
    vm.memory.store(seed, expanded & 0x24FFFFFF, 4, source='seed_footer.first_seed_word')
    following = (((expanded & 0x7FFFFFFF) * 0x41C64E6D) + 0x3039) & 0xFFFFFFFF
    vm.memory.store(seed + 4, following & 0x24FFFFFF, 4, source='seed_footer.second_seed_word')
    destination = vm.cells.value(140)
    vm._write(8375, destination, 8, 'seed_footer.current_seed_pointer')
    state['phase'] = 'seed_copy'
    for offset in (0, 4):
        value = vm.memory.load(seed + offset, 4)
        vm.memory.store(destination + offset, value, 4, source='seed_footer.seed_word_copy')
        state['seed_bytes'] += 4
    scratch = vm.cells.value(72)
    for second in (False, True):
        state['phase'] = 'second_crc' if second else 'first_crc'
        vm.memory.store(scratch, 0x5A, 1, source='seed_footer.tag_byte')
        value = vm.memory.load(seed + (4 if second else 0), 4)
        vm.memory.store(scratch + 1, value, 4, source='seed_footer.crc_word_copy')
        _crc(vm, scratch, second)
        state['crc_bytes'] += 7
        state['phase'] = 'second_pack' if second else 'first_pack'
        value = _pack(vm, scratch, second)
        state['phase'] = 'second_square' if second else 'first_square'
        value = _square(vm, value, second)
        output = destination + (16 if second else 8)
        state['phase'] = 'second_footer' if second else 'first_footer'
        for index in range(7, -1, -1):
            vm.memory.store(output + index, value, 1, source='seed_footer.footer_reverse_byte')
            value >>= 8
            state['footer_bytes'] += 1
    state['phase'] = 'complete'
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 64015, 1576, 1572, False
    vm.auxiliary = (0, 1754449910)
    return True
