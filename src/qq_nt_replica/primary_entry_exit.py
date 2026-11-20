from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_ALLOCATION_SIZES = (
    8, 8, 32, 1, 8, 8, 16, 8, 8, 14, 304, 14, 19, 8, 9, 8, 260, 10, 13,
    8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 16, 8, 13, 8, 256, 8, 37, 1, 8, 8, 16,
    37, 37, 37, 37, 8, 24, 37, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    7, 8, 8, 8, 4, 4, 4, 8, 4, 100, 16, 16, 16, 8, 4, 8, 8, 8, 3, 12,
    11, 33, 16, 22, 8, 1, 34, 5, 20, 8, 8, 128, 17, 16, 44, 1, 256, 256,
    6176, 4, 34864, 16, 4, 4, 16, 8, 4, 9, 16, 8, 32, 32, 16, 2, 2, 8, 8,
    16, 1, 8, 2, 2, 2, 2, 4, 2, 128, 4, 24, 8,
)

_COMMAND_STORES = (
    (160, 145, 161, 4), (162, 163, 164, 1), (165, 166, 167, 4),
    (168, 169, 170, 1), (171, 172, 173, 1), (174, 175, 176, 1),
    (177, 178, 179, 1), (180, 181, 182, 1), (183, 184, 185, 1),
    (186, 187, 188, 1), (189, 190, 191, 1), (192, 193, 194, 1),
    (195, 196, 197, 1), (198, 199, 179, 1), (200, 201, 173, 1),
    (202, 203, 185, 1), (204, 205, 206, 1), (207, 208, 185, 1),
    (209, 210, 211, 1), (212, 213, 214, 1),
)


def _host(vm, word, consumed, callee, arguments, signature, destination=None):
    from .primary_sign import _invoke_host
    vm.pc = consumed
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    result = _invoke_host(vm, address, arguments, signature)
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _store(vm, source, destination, width, *, source_width=None, label='high.store'):
    pointer = vm.cells.value(destination)
    value = vm.memory.load(vm.cells.pointer(source), source_width or width)
    vm.memory.store(pointer, value, width, source=label)


def _load(vm, source, destination, width):
    value = vm.memory.load(vm.cells.value(source), width)
    vm._write(destination, value, 8 if width == 8 else 4, 'high.load')


def _pointer(vm, base, index, destination, *, array=False):
    offset = 20 * vm.memory.load(vm.cells.pointer(145), 4) if array else 0
    offset += vm.memory.load(vm.cells.pointer(index), 4)
    vm._write(destination, vm.cells.value(base) + offset, 8, 'high.indexed_pointer_q')


def _halt(vm):
    vm._jump(3)
    vm.pc = 66548
    vm.halted = True


def enter_primary(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_entry_state = {'start_word': 1, 'resume_word': 703,
                                      'allocations': 0, 'command_bytes': 0,
                                      'phase': 'allocations'}
    for ordinal, size in enumerate(_ALLOCATION_SIZES):
        vm.pc = 4 + 3 * ordinal
        end = vm.arena_used + size + 1
        if end > vm.arena_size:
            raise PrimaryProgramLimit('native arena use exceeds the explicitly mapped Python arena')
        destination = ordinal + 12
        vm._write(destination, vm.arena_address + vm.arena_used, 8, 'L4.arena_pointer')
        vm.memory.store(vm.cells.pointer(destination) + 16, 0, 1, source='L4.clear_owned')
        vm.arena_used = end
        state['allocations'] += 1
    state['phase'] = 'command_guard'
    _host(vm, 391, 399, 143, (5, 6), 99, 142)
    vm.pc = 404
    vm.cells.copy_q_clear_owned(101, 144)
    vm.pc = 408
    _store(vm, 145, 101, 8)
    state['phase'] = 'singleton'
    _host(vm, 408, 414, 147, (), 101, 146)
    vm.pc = 419
    vm.cells.copy_q_clear_owned(146, 148)
    vm.pc = 423
    vm.auxiliary = (0, 297934115)
    vm.pc = 424
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = 428
    value = int(vm.memory.load(vm.cells.pointer(9), 4, signed=True) ==
                vm.memory.load(vm.cells.pointer(149), 4, signed=True))
    vm._write(150, value, 4, 'L26.comparison')
    vm.pc = 432
    vm._jump(1 if vm.cells.value(150) else 2)
    if vm.block == 1:
        state['phase'] = 'policy3_host'
        _host(vm, 432, 444, 151, (152, 1, 2, 153, 154, 7, 8), 119)
        vm.pc = 446
        _halt(vm)
        state['phase'] = 'policy3_halted'
        return True
    state['phase'] = 'command_buffer'
    vm.pc = 454
    _pointer(vm, 100, 145, 155, array=True)
    _host(vm, 454, 463, 157, (155, 158, 159), 121, 156)
    for ordinal, (destination, index, source, width) in enumerate(_COMMAND_STORES):
        vm.pc = 471 + 12 * ordinal
        _pointer(vm, 100, index, destination, array=True)
        vm.pc += 4
        _store(vm, source, destination, 1, source_width=width,
               label='L6.store_integer' if width == 4 else 'high.store')
        state['command_bytes'] += 1
    vm.pc = 703
    state['phase'] = 'resumed'
    return True


def exit_primary(vm):
    if vm.pc != 66398:
        return False
    state = vm.primary_exit_state = {'start_word': 66398, 'resume_word': 66548,
                                     'dword_stores': 0, 'byte_stores': 0,
                                     'phase': 'tail_guard'}
    vm.pc = 66402
    _store(vm, 8847, 139, 4)
    _host(vm, 66402, 66413, 8860, (5, 6, 8346, 8861, 1, 2), 207)
    vm.pc = 66417
    _load(vm, 139, 8862, 4)
    vm.pc = 66422
    vm.execute_once(10, (7, 3, 8862, 8863))
    vm.pc = 66427
    vm._write(8864, vm.cells.value(8863) & vm.cells.value(1732), 8, 'L13.binary_q')
    vm._jump(1660)
    state['phase'] = 'dword_copy'
    while True:
        vm.pc = 66436
        source = 145 if vm.predecessor == 1659 else 8866 if vm.predecessor == 1661 else None
        if source is None:
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        vm._write(8865, vm.cells.value(source), 8, 'L9.phi_q')
        vm.pc = 66441
        vm._write(8867, int(vm.cells.value(8865) < vm.cells.value(8864)), 4, 'once18.unsigned_q')
        vm.pc = 66445
        vm._jump(1661 if vm.cells.value(8867) else 1662)
        if vm.block == 1662:
            break
        vm.pc = 66452
        _pointer(vm, 8346, 8865, 8868)
        vm.pc = 66457
        vm.cells.copy_q_clear_owned(8868, 8869)
        vm.pc = 66461
        _load(vm, 8869, 8870, 4)
        vm.pc = 66468
        _pointer(vm, 7, 8865, 8871)
        vm.pc = 66473
        vm.cells.copy_q_clear_owned(8871, 8872)
        vm.pc = 66477
        _store(vm, 8870, 8872, 4)
        state['dword_stores'] += 1
        vm.pc = 66481
        vm.auxiliary = (0, 767430658)
        vm.pc = 66486
        vm._write(8866, vm._signed_cell(8865, 7) + vm._signed_cell(172, 7), 8, 'once1.integer')
        vm._jump(1660)
    state['phase'] = 'byte_copy'
    while True:
        vm.pc = 66495
        source = 8874 if vm.predecessor == 1663 else 8864 if vm.predecessor == 1660 else None
        if source is None:
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        vm._write(8873, vm.cells.value(source), 8, 'L9.phi_q')
        vm.pc = 66500
        vm._write(8875, int(vm.cells.value(8873) < vm.cells.value(8863)), 4, 'once18.unsigned_q')
        vm.pc = 66504
        vm._jump(1663 if vm.cells.value(8875) else 1664)
        if vm.block == 1664:
            break
        vm.pc = 66511
        _pointer(vm, 8346, 8873, 8876)
        vm.pc = 66515
        _load(vm, 8876, 8877, 1)
        vm.pc = 66522
        _pointer(vm, 7, 8873, 8878)
        vm.pc = 66526
        _store(vm, 8877, 8878, 1)
        state['byte_stores'] += 1
        vm.pc = 66530
        vm.auxiliary = (0, 1111830530)
        vm.pc = 66535
        vm._write(8874, vm._signed_cell(8873, 7) + vm._signed_cell(163, 7), 8, 'once1.integer')
        vm._jump(1662)
    state['phase'] = 'publish_length'
    vm.pc = 66541
    _load(vm, 139, 8879, 4)
    vm.pc = 66545
    _store(vm, 8879, 8, 4)
    _halt(vm)
    state['phase'] = 'halted'
    return True
