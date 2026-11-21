from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


def _host(vm, word, consumed, callee, arguments, signature, destination=None):
    from .primary_sign import _invoke_host
    vm.pc = consumed
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    result = _invoke_host(vm, address, arguments, signature)
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _copy(vm, pc, source, destination):
    vm.pc = pc
    vm.cells.copy_q_clear_owned(source, destination)


def _load(vm, pc, source, destination, width, *, host129_counter=False):
    vm.pc = pc
    raw_api = getattr(vm.runtime, '_host129_api_binding', None) if host129_counter else None
    binding = getattr(vm.runtime, '_host129_counter_binding', None) if host129_counter else None
    value = (raw_api.read_counter(vm, pc, source, destination, width) if raw_api is not None else
             vm.memory.load(vm.cells.value(source), width) if binding is None else
             binding.read(vm, pc, source, destination, width))
    vm._write(destination, value, 8 if width == 8 else 4, 'high.load')


def _store(vm, pc, source, destination, width):
    vm.pc = pc
    pointer = vm.cells.value(destination)
    value = vm.memory.load(vm.cells.pointer(source), width)
    vm.memory.store(pointer, value, width, source='high.store')


def _extend(vm, pc, typ, source, destination):
    vm.pc = pc
    vm.execute_once(10, (typ, 0, source, destination))


def _mask(vm, pc, source, destination, width):
    vm.pc = pc
    vm._write(destination, vm.cells.value(source) & ((1 << (width * 8)) - 1),
              8, 'once9.mask_q')


def _add(vm, pc, typ, left, right, destination):
    vm.pc = pc
    vm._write(destination, vm._signed_cell(left, typ) + vm._signed_cell(right, typ),
              8, 'once1.integer')


def _binary(vm, pc, typ, left, right, destination, operation, label):
    vm.pc = pc
    a, b = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    value = a ^ b if operation == 'xor' else a & b if operation == 'and' else a | b
    vm._write(destination, value, 8, label)


def _compare(vm, word, typ, left, right, destination, kind):
    vm.pc = word + 1
    if kind == 26:
        x = vm.memory.load(vm.image_base + 0x6D86090, 4)
        y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
        if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
            raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
    vm.pc = word + 5
    if kind in (18, 31):
        a, b = vm.cells.value(left), vm.cells.value(right)
    else:
        a, b = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    value = int(a < b) if kind == 18 else int(a > b) if kind == 31 else int(a == b) if kind in (17, 26) else int(a != b)
    label = ('once18.unsigned_q' if kind == 18 else 'once17.integer' if kind == 17
             else f'L{kind}.comparison')
    vm._write(destination, value, 4, label)


def _aux(vm, pc, value):
    vm.pc = pc
    vm.auxiliary = (0, value)


def _typed(vm, pc, typ, left, right, destination):
    vm.pc = pc
    vm.execute_typed((typ, left, right, destination))


def _shift(vm, word, typ, left, right, destination, following):
    vm.pc = word + 1
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
    _typed(vm, word + 5, typ, left, right, destination)
    if extra:
        vm.pc = word + 9
        vm.execute_typed(following)


def _phi(vm, pc, destination, choices):
    vm.pc = pc
    for source, predecessor in choices:
        if vm.predecessor == predecessor:
            vm._write(destination, vm.cells.value(source), 8, 'L9.phi_q')
            return
    raise PrimarySemanticUnavailable('PHI has no matching original predecessor')


def _branch(vm, pc, condition, true, false):
    vm.pc = pc
    vm._jump(true if vm.cells.value(condition) else false)


def _pointer(vm, pc, destination, base, indices, *, field_count=None):
    offset = 0
    for ordinal, (index, stride) in enumerate(indices):
        vm.pc = pc - len(indices) + ordinal + 1
        value = vm.memory.load(vm.cells.pointer(index), 4)
        if ordinal and field_count is not None and value >= field_count:
            raise PrimaryProgramLimit('indexed struct traversal reaches native NULL child type')
        offset += value * stride
    vm.pc = pc
    vm._write(destination, vm.cells.value(base) + offset, 8, 'high.indexed_pointer_q')


def _return(vm, pc, typ, source):
    vm.pc = pc
    vm.result = vm._signed_cell(source, typ) & ((1 << 64) - 1)
    vm.halted = True


def run_primary_host129_select(vm, *, charge=None):
    if vm.pc != 1:
        return False
    from .primary_main_material_getter import _equal, _phi as source_phi
    def tick(word):
        if charge is not None:
            charge(word)
    state = vm.primary_host129_select_state = {'phase': 'bit3'}
    for pc, left, right, destination, remainder in ((6, 0, 1, 2, False), (11, 2, 3, 4, True)):
        tick(pc - 5)
        vm.pc = pc
        a, b = vm.cells.value(left), vm.cells.value(right)
        if b == 0:
            raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
        vm._write(destination, a % b if remainder else a // b, 8,
                  'L17.unsigned_q_division' if remainder else 'L18.unsigned_q_division')
    tick(11)
    vm.pc = 12
    tick(12)
    _aux(vm, 15, 1090670019)
    tick(15)
    vm.pc = 16
    _equal(vm, 20, 4, 4, 5, 6)
    tick(20)
    _branch(vm, 24, 6, 1, 2)
    if vm.block == 1:
        tick(24)
        vm._jump(2)
    tick(26)
    source_phi(vm, 26, (7, 2, 1, 1, 5, 0))
    state['phase'] = 'bit5'
    for pc, left, right, destination, remainder in ((38, 0, 8, 9, False), (43, 9, 3, 10, True)):
        tick(pc - 5)
        vm.pc = pc
        a, b = vm.cells.value(left), vm.cells.value(right)
        if b == 0:
            raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
        vm._write(destination, a % b if remainder else a // b, 8,
                  'L17.unsigned_q_division' if remainder else 'L18.unsigned_q_division')
    tick(43)
    vm.pc = 44
    tick(44)
    _aux(vm, 47, 1980917011)
    tick(47)
    _compare(vm, 47, 0, 10, 5, 11, 17)
    tick(52)
    _branch(vm, 56, 11, 3, 4)
    if vm.block == 3:
        tick(56)
        vm.pc = 57
        tick(57)
        _aux(vm, 60, 815489025)
        tick(60)
        _add(vm, 65, 0, 7, 8, 12)
        tick(65)
        vm._jump(4)
    tick(67)
    source_phi(vm, 67, (13, 2, 12, 3, 7, 2))
    tick(74)
    vm.pc = 75
    tick(75)
    _aux(vm, 78, 618319873)
    tick(78)
    _add(vm, 83, 0, 0, 13, 14)
    tick(83)
    _return(vm, 86, 0, 14)
    state['phase'] = 'halted'
    return True


def run_primary_status_audit(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_status_audit_state = {'phase': 'select'}
    _aux(vm, 5, 1548916756)
    _compare(vm, 5, 5, 4, 5, 6, 27)
    _branch(vm, 14, 6, 1, 2)
    if vm.block == 1:
        _pointer(vm, 22, 7, 0, ((8, 32), (9, 8)), field_count=4)
        _load(vm, 26, 7, 10, 8)
        _pointer(vm, 34, 11, 0, ((8, 32), (12, 8)), field_count=4)
        _load(vm, 38, 11, 13, 8)
        _aux(vm, 42, 64628)
        _binary(vm, 48, 1, 10, 13, 14, 'xor', 'high.flag1_xor_q')
        _copy(vm, 53, 14, 15)
    else:
        _pointer(vm, 63, 16, 0, ((8, 32), (8, 8)), field_count=4)
        _load(vm, 67, 16, 17, 8)
        _pointer(vm, 75, 18, 0, ((8, 32), (19, 8)), field_count=4)
        _load(vm, 79, 18, 20, 8)
        _binary(vm, 84, 1, 17, 20, 21, 'xor', 'L14.binary_q')
        _copy(vm, 89, 21, 22)
    vm._jump(3)
    _phi(vm, 98, 23, ((15, 1), (22, 2)))
    _aux(vm, 102, 592590227)
    _compare(vm, 102, 4, 3, 9, 24, 17)
    _branch(vm, 111, 24, 4, 5)
    state['phase'] = 'update'
    if vm.block == 4:
        _aux(vm, 115, 849509923)
        _compare(vm, 115, 1, 1, 25, 26, 17)
        _branch(vm, 124, 26, 6, 7)
        if vm.block == 6:
            _extend(vm, 129, 1, 2, 27)
            _aux(vm, 133, 41373)
            _shift(vm, 133, 1, 25, 27, 28, (0x06410FC7, 1, 23, 29))
            _load(vm, 142, 23, 29, 8)
            _aux(vm, 145, 23623)
            _binary(vm, 151, 1, 28, 30, 31, 'xor', 'high.flag1_xor_q')
            _binary(vm, 156, 1, 29, 31, 32, 'and', 'L13.binary_q')
            _aux(vm, 159, 58297)
            _typed(vm, 164, 1, 28, 32, 33)
            _store(vm, 168, 33, 23, 8)
            vm._jump(7)
    else:
        _aux(vm, 174, 1145217139)
        _compare(vm, 174, 4, 3, 19, 34, 17)
        _branch(vm, 183, 34, 8, 9)
        if vm.block == 8:
            _load(vm, 187, 23, 35, 8)
            _aux(vm, 191, 21746)
            _typed(vm, 196, 1, 35, 1, 36)
            _store(vm, 200, 36, 23, 8)
            vm._jump(7)
        else:
            _aux(vm, 206, 1582462163)
            _compare(vm, 206, 4, 3, 12, 37, 17)
            _branch(vm, 215, 37, 10, 7)
            if vm.block == 10:
                _load(vm, 219, 23, 38, 8)
                _aux(vm, 223, 13084)
                _typed(vm, 228, 1, 38, 1, 39)
                _store(vm, 232, 39, 23, 8)
                vm._jump(7)
    vm.pc = 235
    vm.halted = True
    state['phase'] = 'halted'
    return True


def run_primary_setup(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_setup_state = {'phase': 'initial', 'rounds': 0, 'accepted': 0,
                                    'dedup_reads': 0, 'published': 0}
    for pc, typ, destination in ((4, 4, 0), (7, 3, 1)):
        vm.pc = pc
        vm._allocate(typ, destination)
    _copy(vm, 12, 0, 2)
    _host(vm, 12, 21, 4, (2, 5, 6), 9, 3)
    _load(vm, 25, 7, 8, 2)
    _extend(vm, 30, 7, 8, 9)
    _aux(vm, 34, 988971203)
    _compare(vm, 34, 7, 9, 5, 10, 26)
    _branch(vm, 43, 10, 1, 2)
    if vm.block == 1:
        _copy(vm, 48, 1, 11)
        _aux(vm, 52, 55861)
        _binary(vm, 58, 8, 11, 12, 13, 'xor', 'high.flag1_xor_q')
        _binary(vm, 63, 8, 13, 14, 15, 'or', 'L15.binary_q')
        _mask(vm, 68, 15, 16, 2)
        _store(vm, 72, 16, 7, 2)
        vm._jump(2)
    vm._jump(3)
    while True:
        _phi(vm, 83, 17, ((5, 2), (18, 4)))
        _compare(vm, 83, 7, 17, 19, 20, 18)
        _branch(vm, 92, 20, 5, 6)
        if vm.block == 6:
            vm.pc = 365
            vm.halted = True
            state['phase'] = 'halted'
            return True
        state['phase'] = 'round'
        _load(vm, 96, 7, 21, 2)
        _extend(vm, 101, 7, 21, 22)
        for auxpc, aux, op_pc, left, right, destination in (
                (105, 24393, 110, 22, 23, 24), (113, 47899, 118, 22, 25, 26)):
            _aux(vm, auxpc, aux)
            _typed(vm, op_pc, 7, left, right, destination)
        _aux(vm, 121, 48733)
        _binary(vm, 127, 7, 24, 26, 27, 'xor', 'high.flag1_xor_q')
        _aux(vm, 130, 28266)
        _typed(vm, 135, 7, 22, 28, 29)
        _binary(vm, 140, 7, 27, 29, 30, 'xor', 'L14.binary_q')
        _aux(vm, 143, 44040)
        _typed(vm, 148, 7, 22, 31, 32)
        _aux(vm, 151, 39287)
        _binary(vm, 157, 7, 30, 32, 33, 'xor', 'high.flag1_xor_q')
        _aux(vm, 160, 30054)
        _typed(vm, 165, 7, 33, 34, 35)
        _mask(vm, 170, 35, 36, 2)
        _aux(vm, 173, 10190)
        _shift(vm, 173, 7, 22, 34, 37, (0x157E55C6, 7, 11, 36))
        _extend(vm, 183, 7, 36, 38)
        _binary(vm, 188, 7, 37, 38, 39, 'or', 'L15.binary_q')
        _mask(vm, 193, 39, 40, 2)
        _extend(vm, 198, 7, 40, 41)
        _aux(vm, 201, 1101192179)
        _compare(vm, 201, 7, 41, 5, 42, 26)
        vm.pc = 213
        selected = 43 if vm.cells.value(42) else 40
        vm._write(44, vm._signed_cell(selected, 11), 8, 'L7.selected_q')
        _store(vm, 217, 44, 7, 2)
        _extend(vm, 222, 7, 44, 45)
        _binary(vm, 227, 7, 45, 46, 47, 'and', 'L13.binary_q')
        _mask(vm, 232, 47, 48, 1)
        state['rounds'] += 1
        vm._jump(7)
        state['phase'] = 'dedup'
        while True:
            _phi(vm, 241, 49, ((5, 5), (50, 8)))
            _compare(vm, 241, 7, 49, 17, 51, 18)
            _branch(vm, 250, 51, 9, 10)
            if vm.block == 10:
                break
            _extend(vm, 255, 8, 49, 52)
            _pointer(vm, 263, 53, 0, ((54, 5), (52, 1)))
            _load(vm, 267, 53, 55, 1)
            state['dedup_reads'] += 1
            _extend(vm, 272, 7, 55, 56)
            _extend(vm, 277, 7, 48, 57)
            _aux(vm, 281, 2098344483)
            _compare(vm, 281, 7, 56, 57, 58, 26)
            _branch(vm, 290, 58, 11, 8)
            if vm.block == 11:
                vm._jump(10)
                break
            _aux(vm, 296, 1618567169)
            _add(vm, 301, 7, 49, 34, 50)
            vm._jump(7)
        _phi(vm, 310, 59, ((60, 11), (61, 7)))
        _aux(vm, 314, 1284676420)
        _compare(vm, 314, 3, 59, 61, 62, 27)
        _branch(vm, 323, 62, 4, 12)
        if vm.block == 12:
            _extend(vm, 328, 7, 48, 63)
            _aux(vm, 332, 564682753)
            _add(vm, 337, 7, 17, 34, 64)
            vm._jump(4)
            state['accepted'] += 1
        _phi(vm, 346, 18, ((17, 10), (64, 12)))
        _phi(vm, 353, 65, ((5, 10), (63, 12)))
        state['phase'] = 'publish'
        _host(vm, 353, 362, 66, (14, 65, 34, 61), 14)
        state['published'] += 1
        vm._jump(3)


def run_primary_host129(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_host129_state = {'phase': 'clock', 'counter_updates': 0}
    for pc, destination in ((4, 0), (7, 1), (10, 2)):
        vm.pc = pc
        vm._allocate(3, destination)
    _copy(vm, 15, 0, 3)
    _host(vm, 15, 21, 5, (), 7, 4)
    _store(vm, 25, 4, 0, 8)
    _host(vm, 25, 33, 7, (8, 9), 9, 6)
    _store(vm, 37, 6, 10, 4)
    _host(vm, 37, 43, 5, (), 7, 11)
    _load(vm, 47, 0, 12, 8)
    _compare(vm, 47, 3, 12, 13, 14, 31)
    _branch(vm, 56, 14, 1, 2)
    if vm.block == 1:
        _aux(vm, 60, 1198704132)
        _compare(vm, 60, 3, 12, 11, 15, 30)
        _branch(vm, 69, 15, 3, 2)
    if vm.block == 3:
        state['phase'] = 'changed_clock'
        _copy(vm, 74, 0, 16)
        _aux(vm, 78, 307224577)
        _add(vm, 83, 3, 12, 16, 17)
        _mask(vm, 88, 17, 18, 4)
        _host(vm, 88, 95, 20, (18,), 13, 19)
        vm._jump(4)
    else:
        state['phase'] = 'entropy'
        _copy(vm, 102, 1, 21)
        _host(vm, 102, 108, 23, (), 1, 22)
        _extend(vm, 113, 3, 22, 24)
        _store(vm, 117, 24, 1, 8)
        _copy(vm, 122, 2, 25)
        _host(vm, 122, 128, 23, (), 1, 26)
        _extend(vm, 133, 3, 26, 27)
        _store(vm, 137, 27, 2, 8)
        _load(vm, 141, 1, 28, 8)
        _compare(vm, 141, 3, 28, 13, 29, 31)
        _branch(vm, 150, 29, 5, 6)
        if vm.block == 5:
            _aux(vm, 154, 489825716)
            _compare(vm, 154, 3, 28, 27, 30, 30)
            _branch(vm, 163, 30, 7, 6)
        if vm.block == 7:
            state['phase'] = 'changed_entropy'
            _copy(vm, 168, 0, 31)
            for auxpc, aux, pc, left, right, destination in (
                    (172, 253952001, 177, 28, 31, 32),
                    (185, 1616330753, 190, 32, 33, 34),
                    (198, 304263169, 203, 34, 35, 36)):
                if right in (33, 35):
                    _copy(vm, auxpc - 3, 1 if right == 33 else 2, right)
                _aux(vm, auxpc, aux)
                _add(vm, pc, 3, left, right, destination)
            _mask(vm, 208, 36, 37, 4)
            _host(vm, 208, 215, 39, (37,), 13, 38)
            vm._jump(8)
        else:
            state['phase'] = 'persistent_counter'
            _load(vm, 221, 0, 40, 8)
            _load(vm, 225, 41, 42, 4, host129_counter=True)
            _extend(vm, 230, 3, 42, 43)
            _compare(vm, 230, 3, 40, 43, 44, 18)
            _branch(vm, 239, 44, 9, 10)
            if vm.block == 9:
                _store(vm, 243, 43, 0, 8)
                vm._jump(10)
            for (loadpc, loaded, auxpc, aux, addpc, incremented, storepc,
                 extendpc, widened) in (
                    (249, 46, 253, 1617448961, 258, 48, 262, 267, 49),
                    (287, 52, 290, 669618177, 295, 53, 299, 304, 54)):
                _load(vm, loadpc, 45, loaded, 4, host129_counter=True)
                _aux(vm, auxpc, aux)
                _add(vm, addpc, 0, loaded, 47, incremented)
                _store(vm, storepc, incremented, 45, 4)
                state['counter_updates'] += 1
                _extend(vm, extendpc, 3, loaded, widened)
                if loaded == 46:
                    _load(vm, 271, 0, 50, 8)
                    _aux(vm, 274, 2072670210)
                    _add(vm, 279, 3, 50, 49, 51)
                    _store(vm, 283, 51, 0, 8)
                else:
                    _load(vm, 308, 1, 55, 8)
                    _aux(vm, 311, 1414438913)
                    _add(vm, 316, 3, 55, 54, 56)
                    _store(vm, 320, 56, 1, 8)
            _load(vm, 324, 0, 57, 8)
            _aux(vm, 327, 767135745)
            _add(vm, 332, 3, 57, 56, 58)
            _copy(vm, 337, 0, 59)
            _aux(vm, 340, 1661341698)
            _add(vm, 345, 3, 58, 59, 60)
            _copy(vm, 350, 2, 61)
            _aux(vm, 353, 1867747329)
            _add(vm, 358, 3, 60, 61, 62)
            _load(vm, 362, 41, 63, 4, host129_counter=True)
            _extend(vm, 367, 3, 63, 64)
            _aux(vm, 370, 23389)
            _binary(vm, 376, 3, 62, 64, 65, 'xor', 'high.flag1_xor_q')
            _store(vm, 380, 65, 0, 8)
            _mask(vm, 385, 65, 66, 4)
            _host(vm, 385, 392, 39, (66,), 13, 67)
            vm._jump(8)
        _phi(vm, 401, 68, ((38, 7), (67, 10)))
        vm._jump(4)
    _phi(vm, 410, 69, ((19, 3), (68, 8)))
    _return(vm, 413, 0, 69)
    state['phase'] = 'halted'
    return True
