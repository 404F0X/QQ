from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


def _normal_dispatch(vm):
    if vm.memory.load(vm.image_base + 0x677E1BC, 4, signed=True) == -0x80000000:
        return False
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    return not ((((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31)


def _advance(value, index):
    feedback = ((value >> 7) ^ (value >> 5) ^ (value >> 4) ^ (value >> 3)) & 1
    value = (((value << 1) | feedback) ^ ((55 + 158 * index) & 255)) & 255
    value = ((value << 3) | (value >> 5)) & 255
    return value or (index ^ 0xA5)


def _index(vm, source, destination, value, source_type):
    vm._write(source, value, 8, 'material_core.index_source')
    vm.execute_once(10, (1, source_type, source, destination))
    return vm.cells.value(destination)


def _material_bytes(vm):
    if not _normal_dispatch(vm):
        return False
    _control_phi(vm)
    memory = vm.memory
    mask = vm.cells.value(6)
    plain = vm.cells.value(4)
    key = vm.cells.value(57)
    context = vm.cells.value(10)
    state = vm.material_core_state
    state.update(phase='material_mask', mask_bytes=0, table_bytes=0)
    value = _advance(vm.cells.value(63) & 255, 0)
    memory.store(mask, value, 1, source='material_core.mask_byte')
    state['mask_bytes'] = 1
    for index in range(1, 32):
        value = _advance(memory.load(mask + index - 1, 1), index)
        slot = _index(vm, 93, 134, index, 2)
        memory.store(mask + slot, value, 1, source='material_core.mask_byte')
        state['mask_bytes'] += 1
    state['phase'] = 'material_table'
    for index in range(32):
        slot = _index(vm, 136, 139, index, 5)
        key_byte = memory.load(key + slot, 1)
        table_slot = _index(vm, 141, 143, key_byte, 2)
        value = memory.load(context + 8 * table_slot + 3, 1)
        value ^= memory.load(mask + slot, 1)
        memory.store(plain + slot, value, 1, source='material_core.table_byte')
        state['table_bytes'] += 1
    state['phase'] = 'counter_seed'
    counter = memory.load(context + 2114, 1)
    value = _advance((vm.cells.value(5) & 255) ^ counter, counter ^ 0x3C)
    predecessor = 27 if value else 28
    vm._write(200, value or 0xA5, 8, 'material_core.encoding_seed')
    counter = memory.load(context + 2114, 1)
    memory.store(context + 2114, counter + 1, 1, source='material_core.counter_advance')
    state.update(phase='source_unlock_and_copy', numeric_stages=1)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 1270, 29, predecessor, False
    vm.auxiliary = (0, 2118615041)
    return True


def _encode_bytes(vm):
    if vm.material_core_state['numeric_stages'] != 1 or not _normal_dispatch(vm):
        return False
    length = vm.cells.value(3) & 0xFFFFFFFF
    if length not in (1, 2, 4, 8):
        return False
    memory = vm.memory
    mask, payload = vm.cells.value(9), vm.cells.value(7)
    state = vm.material_core_state
    state.update(phase='encoding_mask', encoded_bytes=0)
    value = _advance(vm.cells.value(200) & 255, 0)
    vm._write(243, mask, 8, 'material_core.encoding_mask_pointer')
    memory.store(mask, value, 1, source='material_core.encoding_mask')
    for index in range(1, length):
        previous = _index(vm, 247, 248, index - 1, 5)
        value = _advance(memory.load(mask + previous, 1), index)
        slot = _index(vm, 244, 283, index, 5)
        memory.store(mask + slot, value, 1, source='material_core.encoding_mask')
    state['phase'] = 'encoding_xor'
    for index in range(length):
        slot = _index(vm, 285, 288, index, 5)
        value = memory.load(mask + slot, 1)
        value ^= memory.load(payload + slot, 1)
        memory.store(payload + slot, value, 1, source='material_core.encoding_xor')
        state['encoded_bytes'] += 1
    state.update(phase='source_cleanup_and_publication', numeric_stages=2)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 1953, 43, 41, False
    vm.auxiliary = (0, 907374594)
    return True


def _host(vm, word, consumed, callee, arguments, signature, destination=None):
    from .primary_sign import _invoke_host
    vm.pc = consumed
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    result = _invoke_host(vm, address, arguments, signature)
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _address(vm, consumed, typ, base, destination, *indices):
    vm.pc = consumed
    offset = 0
    for ordinal, cell in enumerate(indices):
        index = vm.memory.load(vm.cells.pointer(cell), 4)
        if ordinal == 0:
            delta = vm.program.size(typ) * index
        else:
            delta, typ = vm._indexed_offset(typ, index)
        offset = (offset + delta) & 0xFFFFFFFFFFFFFFFF
    vm._write(destination, vm.cells.value(base) + offset, 8, 'high.indexed_pointer_q')


def _store(vm, consumed, source, destination, width):
    vm.pc = consumed
    pointer = vm.cells.value(destination)
    value = vm.memory.load(vm.cells.pointer(source), width)
    vm.memory.store(pointer, value, width, source='high.store')


def _load(vm, consumed, source, destination, width):
    vm.pc = consumed
    value = vm.memory.load(vm.cells.value(source), width)
    vm._write(destination, value, 8 if width == 8 else 4, 'high.load')


def _phi(vm, consumed, destination, source):
    vm.pc = consumed
    vm._write(destination, vm.cells.value(source), 8, 'L9.phi_q')


def _add(vm, consumed, typ, left, right, destination):
    vm.pc = consumed
    value = vm._signed_cell(left, typ) + vm._signed_cell(right, typ)
    vm._write(destination, value, 8, 'once1.integer')


def _greater(vm, consumed, left, right, destination):
    vm.pc = consumed
    vm._write(destination, int(vm.cells.value(left) > vm.cells.value(right)), 4, 'L31.comparison')


def _branch(vm, consumed, true, condition, false):
    vm.pc = consumed
    vm._jump(true if vm.cells.value(condition) != 0 else false)


def _halt(vm):
    vm._jump(3)
    vm.pc = 2159
    vm.halted = True


def _clear(vm, *, word, setup, loop, body, exit_block, resume, pointer, next_pointer,
           counter, following, condition, initial_pointer, initial_count, auxiliary,
           counter_first=False):
    vm._jump(loop)
    while True:
        initial = vm.predecessor == setup
        if not initial and vm.predecessor != body:
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        fields = ((counter, initial_count if initial else following),
                  (pointer, initial_pointer if initial else next_pointer)) if counter_first else (
                  (pointer, initial_pointer if initial else next_pointer),
                  (counter, initial_count if initial else following))
        _phi(vm, word + 7, *fields[0])
        _phi(vm, word + 14, *fields[1])
        vm.pc = word + 18
        vm.auxiliary = (0, auxiliary)
        _add(vm, word + 23, 1, counter, 43, following)
        _greater(vm, word + 28, counter, 16, condition)
        _branch(vm, word + 32, body, condition, exit_block)
        if vm.block == exit_block:
            break
        _address(vm, word + 39, 2, pointer, next_pointer, 20)
        _store(vm, word + 43, 21, pointer, 1)
        vm._jump(loop)
    vm._jump(resume)


def _initialize(vm):
    state = vm.material_execution_state
    state['phase'] = 'allocations'
    for ordinal, typ in enumerate((8, 2, 8, 11, 1, 11)):
        vm.pc = 4 + 3 * ordinal
        vm._allocate(typ, 4 + ordinal)
        state['allocations'] += 1
    _host(vm, 19, 25, 11, (), 28, 10)
    for consumed, source, destination in ((30, 4, 12), (35, 6, 13), (40, 7, 14), (45, 8, 15)):
        vm.pc = consumed
        vm.cells.copy_q_clear_owned(source, destination)
    _store(vm, 49, 16, 8, 8)
    _address(vm, 57, 3, 0, 17, 18, 18)
    _store(vm, 61, 16, 17, 8)
    _address(vm, 69, 3, 0, 19, 18, 20)
    _store(vm, 73, 21, 19, 1)
    _address(vm, 81, 3, 0, 22, 18, 23)
    _store(vm, 85, 21, 22, 1)
    for consumed, right, destination, auxiliary, label in (
            (94, 20, 24, 1797394740, 'L30.comparison'),
            (102, 23, 25, 882011796, 'L27.comparison')):
        vm.auxiliary = (0, auxiliary)
        vm.pc = consumed
        vm._write(destination, int(vm._signed_cell(3, 5) != vm._signed_cell(right, 5)), 4, label)
    vm.auxiliary = (0, 12374)
    vm.pc = 110
    vm._write(26, vm._signed_cell(24, 30) & vm._signed_cell(25, 30), 8, 'typed.selector1.q')
    vm.auxiliary = (0, 1607661332)
    vm.pc = 118
    vm._write(28, int(vm._signed_cell(3, 5) != vm._signed_cell(27, 5)), 4, 'L30.comparison')
    vm.pc = 123
    vm._write(29, vm._signed_cell(26, 30) & vm._signed_cell(28, 30), 8, 'L13.binary_q')
    vm.auxiliary = (0, 721604740)
    vm.pc = 131
    vm._write(31, int(vm._signed_cell(3, 5) != vm._signed_cell(30, 5)), 4, 'L27.comparison')
    vm.pc = 136
    vm._write(32, vm._signed_cell(29, 30) & vm._signed_cell(31, 30), 8, 'L13.binary_q')
    _branch(vm, 140, 1, 32, 2)
    if vm.block == 1:
        _halt(vm)
        return
    vm.auxiliary = (0, 1170751490)
    _add(vm, 151, 5, 2, 3, 33)
    _greater(vm, 156, 33, 34, 35)
    _branch(vm, 160, 4, 35, 5)
    if vm.block == 4:
        _halt(vm)
        return
    state['phase'] = 'initial_clear'
    _address(vm, 170, 8, 4, 36, 16, 16)
    _branch(vm, 174, 6, 37, 7)
    if vm.block == 6:
        _clear(vm, word=176, setup=6, loop=8, body=9, exit_block=10, resume=7,
               pointer=38, next_pointer=39, counter=40, following=42, condition=44,
               initial_pointer=36, initial_count=41, auxiliary=1722007554)
    _address(vm, 231, 11, 7, 45, 16, 16)
    _branch(vm, 235, 11, 37, 12)
    if vm.block == 11:
        _clear(vm, word=237, setup=11, loop=13, body=14, exit_block=15, resume=12,
               pointer=46, next_pointer=47, counter=48, following=50, condition=51,
               initial_pointer=45, initial_count=49, auxiliary=1516998657)
    state['phase'] = 'enter'
    _host(vm, 284, 290, 52, (10,), 31)
    vm.auxiliary = (0, 1175613620)
    vm.pc = 299
    vm._write(53, int(vm._signed_cell(1, 2) != vm._signed_cell(21, 2)), 4, 'L27.comparison')
    _address(vm, 307, 26, 10, 54, 18, 20)
    _address(vm, 315, 26, 10, 55, 18, 23)
    vm.pc = 322
    selected = 54 if vm.cells.value(53) != 0 else 55
    vm._write(56, vm._signed_cell(selected, 9), 8, 'L7.selected_q')
    _address(vm, 330, 8, 56, 57, 16, 16)
    _branch(vm, 334, 16, 53, 17)
    if vm.block == 16:
        _address(vm, 342, 26, 10, 58, 18, 59)
        _load(vm, 346, 58, 60, 1)
    else:
        _address(vm, 356, 26, 10, 61, 18, 27)
        _load(vm, 360, 61, 62, 1)
    vm._jump(18)
    state['phase'] = 'numeric_material'


def _control_phi(vm):
    vm.pc = 369
    source = 60 if vm.predecessor == 16 else 62 if vm.predecessor == 17 else None
    if source is None:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(63, vm.cells.value(source), 8, 'L9.phi_q')


def _unlock_and_copy(vm):
    state = vm.material_execution_state
    state['phase'] = 'leave'
    _host(vm, 1270, 1276, 203, (10,), 31)
    vm._jump(30)
    state['phase'] = 'payload_copy'
    while True:
        source = 18 if vm.predecessor == 29 else 205 if vm.predecessor == 31 else None
        if source is None:
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        _phi(vm, 1285, 204, source)
        vm.pc = 1290
        vm._write(206, int(vm.cells.value(204) < vm.cells.value(3)), 4, 'once18.unsigned_q')
        _branch(vm, 1294, 31, 206, 32)
        if vm.block == 32:
            break
        vm.auxiliary = (0, 1677598722)
        _add(vm, 1303, 5, 2, 204, 207)
        vm.pc = 1308
        vm.execute_once(10, (1, 5, 207, 208))
        _address(vm, 1316, 8, 4, 209, 16, 208)
        _load(vm, 1320, 209, 210, 1)
        vm.pc = 1325
        vm.execute_once(10, (1, 5, 204, 211))
        _address(vm, 1333, 11, 7, 212, 16, 211)
        _store(vm, 1337, 210, 212, 1)
        state['copied_bytes'] += 1
        vm.auxiliary = (0, 1060225025)
        _add(vm, 1345, 5, 204, 20, 205)
        vm._jump(30)
    state['phase'] = 'plaintext_clear'
    _branch(vm, 1351, 33, 37, 34)
    if vm.block == 33:
        _clear(vm, word=1353, setup=33, loop=35, body=36, exit_block=37, resume=34,
               pointer=213, next_pointer=214, counter=215, following=216, condition=217,
               initial_pointer=36, initial_count=41, auxiliary=1913020417)
    state['phase'] = 'numeric_encoding'


def _publish(vm):
    state = vm.material_execution_state
    state['phase'] = 'record_copy'
    vm.pc = 1958
    vm.execute_once(10, (1, 5, 3, 297))
    _branch(vm, 1962, 44, 37, 45)
    if vm.block == 44:
        vm._jump(46)
        while True:
            initial = vm.predecessor == 44
            if not initial and vm.predecessor != 47:
                raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
            _phi(vm, 1971, 298, 297 if initial else 299)
            _phi(vm, 1978, 300, 15 if initial else 301)
            _phi(vm, 1985, 302, 45 if initial else 303)
            vm.pc = 1989
            vm.auxiliary = (0, 1110863873)
            _add(vm, 1994, 1, 298, 43, 299)
            _greater(vm, 1999, 298, 16, 304)
            _branch(vm, 2003, 47, 304, 48)
            if vm.block == 48:
                break
            _address(vm, 2010, 2, 302, 303, 20)
            _load(vm, 2014, 302, 305, 1)
            _address(vm, 2021, 2, 300, 301, 20)
            _store(vm, 2025, 305, 300, 1)
            state['copied_bytes'] += 1
            vm._jump(46)
        vm._jump(45)
    state['phase'] = 'mask_clear'
    _branch(vm, 2033, 49, 37, 50)
    if vm.block == 49:
        _clear(vm, word=2035, setup=49, loop=51, body=52, exit_block=53, resume=50,
               pointer=308, next_pointer=309, counter=306, following=307, condition=310,
               initial_pointer=243, initial_count=49, auxiliary=216731649, counter_first=True)
    state['phase'] = 'payload_clear'
    _branch(vm, 2086, 54, 37, 55)
    if vm.block == 54:
        _clear(vm, word=2088, setup=54, loop=56, body=57, exit_block=58, resume=55,
               pointer=313, next_pointer=314, counter=311, following=312, condition=315,
               initial_pointer=45, initial_count=49, auxiliary=255713282, counter_first=True)
    state['phase'] = 'publication'
    _load(vm, 2139, 8, 316, 8)
    _store(vm, 2143, 316, 17, 8)
    _store(vm, 2147, 200, 19, 1)
    vm.pc = 2152
    vm._write(317, vm.cells.value(3) & 255, 8, 'once9.mask_q')
    _store(vm, 2156, 317, 22, 1)
    _halt(vm)
    state['phase'] = 'complete'


def run_primary_material(vm):
    progress = {'execution': 'source', 'phase': 'running'}
    vm.material_core_state = progress
    result = vm.run(max_steps=1_000_000)
    progress['phase'] = 'complete'
    return result
