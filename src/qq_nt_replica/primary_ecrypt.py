from dataclasses import dataclass
from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed


_MASK32 = 0xFFFFFFFF
_MASK64 = (1 << 64) - 1


def _indexed_pointer(vm, word, destination, typ, base, indices):
    offset = 0
    vm.pc = word + 6
    for ordinal, cell in enumerate(indices):
        vm.pc += 1
        index = vm.memory.load(vm.cells.pointer(cell), 4)
        if ordinal == 0:
            offset += vm.program.size(typ) * index
        else:
            delta, typ = vm._indexed_offset(typ, index)
            offset += delta
        offset &= _MASK64
    vm._write(destination, vm.cells.value(base) + offset, 8, 'high.indexed_pointer_q')


def _native_call(vm, word, end, signature, callee, arguments, destination=None):
    from .primary_sign import _invoke_host

    vm.pc = end
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    result = _invoke_host(vm, address, arguments, signature)
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _store_cell(vm, word, width, source, destination):
    vm.pc = word + 4
    pointer = vm.cells.value(destination)
    value = vm.memory.load(vm.cells.pointer(source), width)
    vm.memory.store(pointer, value, width, source='high.store')


def _transform_initialize(vm):
    for word, typ, destination in ((1, 6, 5), (4, 8, 6), (7, 8, 7), (10, 13, 8)):
        vm.pc = word + 3
        vm._allocate(typ, destination)
    vm.pc = 18
    vm.cells.copy_q_clear_owned(5, 9)
    _native_call(vm, 18, 27, 15, 11, (9, 12, 13), 10)
    for word, destination, field, source in ((27, 14, 15, 16), (39, 17, 18, 19),
            (51, 20, 21, 22), (63, 23, 24, 25), (75, 26, 27, 28),
            (87, 29, 30, 31), (99, 32, 33, 34), (111, 35, 36, 37)):
        _indexed_pointer(vm, word, destination, 6, 5, (15, field))
        _store_cell(vm, word + 8, 1, source, destination)
    vm.pc = 128
    vm.cells.copy_q_clear_owned(6, 38)
    _native_call(vm, 128, 137, 15, 11, (38, 12, 40), 39)
    vm.pc = 142
    vm.cells.copy_q_clear_owned(7, 41)
    _native_call(vm, 142, 151, 15, 11, (41, 12, 40), 42)
    vm.pc = 156
    vm._write(44, int(vm.cells.value(2) > vm.cells.value(43)), 4, 'L31.comparison')
    vm.pc = 163
    selected = 43 if vm.cells.value(44) != 0 else 2
    vm._write(45, vm._signed_cell(selected, 3), 8, 'L7.selected_q')
    vm.pc = 168
    vm.execute_once(10, (0, 3, 45, 46))
    _indexed_pointer(vm, 168, 47, 8, 6, (15, 15))
    _native_call(vm, 176, 185, 18, 49, (47, 1, 46), 48)
    vm.pc = 190
    vm.execute_once(10, (0, 3, 2, 50))
    _indexed_pointer(vm, 190, 51, 8, 7, (15, 15))
    _native_call(vm, 198, 207, 18, 49, (51, 14, 50), 52)
    vm.pc = 212
    vm.cells.copy_q_clear_owned(8, 53)
    _native_call(vm, 212, 217, 21, 54, ())
    vm.auxiliary = (0, 1864716290)
    vm.pc = 226
    vm._write(56, vm._signed_cell(2, 3) + vm._signed_cell(55, 3), 8, 'once1.integer')
    vm.pc = 231
    vm._write(58, vm._signed_cell(56, 3) & vm._signed_cell(57, 3), 8, 'L13.binary_q')
    _native_call(vm, 231, 240, 23, 59, (8, 47, 58, 60))
    _native_call(vm, 240, 247, 25, 61, (8, 51))
    _native_call(vm, 247, 257, 27, 62, (12, 8, 3, 0, 4))
    vm._jump(1)


def _converted_index(vm, source, destination, value, *, typ=13, source_type=1):
    vm._write(source, value & _MASK64, 8, 'ecrypt_core.index_source')
    vm.execute_once(10, (typ, source_type, source, destination))
    return vm.cells.value(destination)


def _halt_void(vm, block, target, end):
    vm.block = block
    vm._jump(target)
    vm.pc = end
    vm.halted = True


def _transform_return(vm):
    vm.pc = 390
    vm.result, vm.halted = vm._signed_cell(87, 0) & _MASK64, True


def _hash_alternate_prefix(vm):
    while True:
        for end, destination, first, following in ((266, 63, 0, 64),
                (273, 65, 66, 67), (280, 68, 4, 69)):
            vm.pc = end
            source = first if vm.predecessor == 0 else following if vm.predecessor == 2 else None
            if source is None:
                raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
            vm._write(destination, vm.cells.value(source), 8, 'L9.phi_q')
        vm.auxiliary = (0, 1567367169)
        vm.pc = 289
        vm._write(69, vm._signed_cell(68, 3) + vm._signed_cell(70, 3), 8, 'once1.integer')
        vm.auxiliary = (0, 1830960372)
        vm.pc = 297
        vm._write(71, int(vm._signed_cell(68, 3) != vm._signed_cell(12, 3)), 4, 'L27.comparison')
        vm._jump(2 if vm.cells.value(71) != 0 else 3)
        if vm.block == 3:
            break
        vm.auxiliary = (0, 58847)
        vm.pc = 306
        x = vm.memory.load(vm.image_base + 0x6D86090, 4)
        y = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
        extra = (((x * x) & _MASK32) | (abs(y) & _MASK32)) >> 31
        vm.pc = 310
        count = vm.memory.load(vm.cells.pointer(36), 4)
        value = 0 if count & 0x80000000 or count >= 64 else vm.cells.value(65) << count
        vm._write(72, value, 8, 'typed.selector3.q')
        if extra:
            vm.pc = 314
            vm.program.size(6490)
        vm.auxiliary = (0, 13353)
        vm.pc = 318
        vm._write(73, vm._signed_cell(72, 0) - vm._signed_cell(65, 0), 8, 'typed.selector0.q')
        _indexed_pointer(vm, 318, 64, 1, 63, (74,))
        vm.pc = 329
        vm._write(75, vm.memory.load(vm.cells.value(63), 1), 4, 'high.load')
        vm.pc = 334
        vm.execute_once(10, (0, 1, 75, 76))
        vm.auxiliary = (0, 1571274754)
        vm.pc = 342
        vm._write(67, vm._signed_cell(73, 0) + vm._signed_cell(76, 0), 8, 'once1.integer')
        vm._jump(1)
    vm.pc = 349
    vm.execute_once(8, (0, 65, 77, 78))
    vm.pc = 354
    vm._write(79, vm._signed_cell(65, 0) ^ vm._signed_cell(78, 0), 8, 'L14.binary_q')
    vm.auxiliary = (0, 505061891)
    vm.pc = 363
    vm.execute_once(0, (0, 79, 80, 81))
    vm.pc = 368
    vm.execute_once(8, (0, 81, 82, 83))
    vm.pc = 373
    vm._write(84, vm._signed_cell(81, 0) ^ vm._signed_cell(83, 0), 8, 'L14.binary_q')
    vm.pc = 378
    vm.execute_once(8, (0, 84, 85, 86))
    vm.auxiliary = (0, 35453)
    vm.pc = 387
    vm._write(87, vm._signed_cell(84, 0) ^ vm._signed_cell(86, 0), 8, 'high.flag1_xor_q')
    _transform_return(vm)
    return vm.result


def _key_initialize(vm):
    for word, destination, field, source, width in ((1, 4, 6, 5, 4),
            (13, 7, 8, 2, 4), (25, 9, 10, 11, 1), (37, 12, 13, 5, 4)):
        _indexed_pointer(vm, word, destination, 6, 0, (5, field))
        _store_cell(vm, word + 8, width, source, destination)


def _key_setup(vm):
    _key_initialize(vm)
    memory = vm.memory
    context, key = vm.cells.value(0), vm.cells.value(1)
    state = vm.ecrypt_core_state
    state['phase'] = 'key_words'
    if vm.cells.value(2) & _MASK32 == 128:
        for index in range(4):
            offset = _converted_index(vm, 19, 20, index * 4)
            word = memory.load(key + offset, 4)
            for source, destination, target in ((26, 27, 20 + index),
                    (31, 32, 12 + index), (16, 34, index)):
                slot = _converted_index(vm, source, destination, target)
                memory.store(context + 4 * slot, word, 4, source='ecrypt_core.key_word')
        for index in range(2):
            offset = _converted_index(vm, 42, 43, index * 4)
            word = memory.load(key + 8 + offset, 4)
            for source, destination, target in ((49, 50, 28 + index),
                    (53, 54, 16 + index), (56, 57, 4 + index)):
                slot = _converted_index(vm, source, destination, target)
                memory.store(context + 4 * slot, word, 4, source='ecrypt_core.key_word')
            word = memory.load(key + offset, 4)
            for source, destination, target in ((63, 64, 30 + index),
                    (67, 68, 18 + index), (71, 72, 6 + index)):
                slot = _converted_index(vm, source, destination, target)
                memory.store(context + 4 * slot, word, 4, source='ecrypt_core.key_word')
    else:
        for index in range(8):
            offset = _converted_index(vm, 78, 79, index * 4)
            word = memory.load(key + offset, 4)
            for source, destination, target in ((84, 85, 8 + index),
                    (74, 87, index), (89, 90, 16 + index)):
                slot = _converted_index(vm, source, destination, target)
                memory.store(context + 4 * slot, word, 4, source='ecrypt_core.key_word')
    state.update(phase='backup', copied_words=0)
    for index in range(32):
        slot = _converted_index(vm, 92, 97, index)
        word = memory.load(context + 4 * slot, 4)
        memory.store(context + 140 + 4 * slot, word, 4, source='ecrypt_core.backup_word')
        state['copied_words'] += 1
    _halt_void(vm, 11, 13, 642)


def _stream_bytes(vm):
    from .primary_sign import _invoke_host

    memory = vm.memory
    context, output = vm.cells.value(0), vm.cells.value(1)
    count = vm.cells.value(2) & _MASK32
    state = vm.ecrypt_core_state
    state.update(phase='stream_bytes', emitted_bytes=0, generated_batches=0)
    for index in range(count):
        if index == 1_000_000:
            raise PrimaryProgramLimit('ECRYPT algorithm execution limit after1000000 bytes')
        offset = memory.load(context + 404, 4)
        x = memory.load(vm.image_base + 0x6D86090, 4)
        y = memory.load(vm.image_base + 0x6D86094, 4, signed=True)
        if (((x * x) & _MASK32) | (abs(y) & _MASK32)) >> 31:
            raise PrimarySemanticUnavailable('L26 current-global extra-consumption route is unavailable')
        if offset == 0:
            state['phase'] = 'keystream'
            vm._write(16, context + 276, 8, 'ecrypt_core.keystream_pointer')
            address = vm.cells.value(18)
            vm.host_calls.append((76, address, (0, 16, 19), 9))
            _invoke_host(vm, address, (0, 16, 19), 9)
            state['generated_batches'] += 1
        state['phase'] = 'stream_byte'
        offset = memory.load(context + 404, 4)
        slot = _converted_index(vm, 21, 22, offset, typ=14)
        byte = memory.load(context + 276 + slot, 1)
        memory.store(output + index, byte, 1, source='ecrypt_core.stream_byte')
        offset = memory.load(context + 404, 4)
        memory.store(context + 404, offset % 16, 4, source='ecrypt_core.stream_offset')
        state['emitted_bytes'] += 1
    _halt_void(vm, 1, 4, 142)


def _packet_initialize(vm):
    _native_call(vm, 1, 9, 11, 5, (1, 3, 4))
    vm._jump(1)


def _packet(vm):
    _packet_initialize(vm)
    memory = vm.memory
    source, output = vm.cells.value(2), vm.cells.value(3)
    count = vm.cells.value(4) & _MASK32
    state = vm.ecrypt_core_state
    state.update(phase='packet_xor', mixed_bytes=0)
    for index in range(count):
        if index == 1_000_000:
            raise PrimaryProgramLimit('ECRYPT packet execution limit after1000000 bytes')
        slot = _converted_index(vm, 6, 10, index, typ=14)
        byte = memory.load(source + slot, 1)
        stream = memory.load(output + slot, 1)
        memory.store(output + slot, byte ^ stream, 1, source='ecrypt_core.packet_xor')
        state['mixed_bytes'] += 1
    _halt_void(vm, 1, 3, 94)


def _transform(vm):
    _transform_initialize(vm)
    memory = vm.memory
    output = vm.cells.value(0)
    count = vm.cells.value(4) & _MASK32
    if count:
        x = memory.load(vm.image_base + 0x6D86090, 4)
        y = memory.load(vm.image_base + 0x6D86094, 4, signed=True)
        if (((x * x) & _MASK32) | (abs(y) & _MASK32)) >> 31:
            vm.ecrypt_core_state['phase'] = 'reference_globals'
            return _hash_alternate_prefix(vm)
    state = vm.ecrypt_core_state
    state.update(phase='output_hash', hashed_bytes=0)
    value = 0xD724BFB6D0F8C8D8
    for index in range(count):
        if index == 1_000_000:
            raise PrimaryProgramLimit('ECRYPT hash execution limit after1000000 bytes')
        byte = memory.load(output + index, 1)
        byte = _converted_index(vm, 75, 76, byte, typ=0)
        value = (value * 127 + byte) & _MASK64
        state['hashed_bytes'] += 1
    value ^= value >> 33
    value = (value * 0xAC58456D3ED2E5B9) & _MASK64
    value ^= value >> 31
    value ^= value >> 32
    vm._write(87, value, 8, 'ecrypt_core.hash_result')
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 387, 3, 1, False
    vm.auxiliary = (0, 35453)
    _transform_return(vm)


def run_primary_ecrypt(vm, name, *, max_steps=1_000_000):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    state = getattr(vm, 'ecrypt_core_state', None)
    if state is None or state.get('phase') == 'complete':
        state = {'program': name, 'execution': 'source', 'phase': 'running', 'retained_steps': 0}
        vm.ecrypt_core_state = state
    initial_steps = len(vm.trace)
    try:
        result = vm.run(max_steps=max_steps)
    finally:
        state['retained_steps'] += len(vm.trace) - initial_steps
    state['phase'] = 'complete'
    return result


_IV_SITES = {'M30F4': 'M', 'F2704': 'F', 'F2903': 'F', 'F27D2': 'F',
             'F30B2': 'F', 'G2FC8': 'G', 'G28B3': 'G', 'M261F': 'M',
             'G31A9': 'G', 'M2F52': 'M'}


@dataclass(frozen=True)
class IVSiteObservation:
    site: str
    operands: tuple

    def __post_init__(self):
        if (type(self.site) is not str or self.site not in _IV_SITES or type(self.operands) is not tuple or
                len(self.operands) != (1 if _IV_SITES[self.site] == 'M' else 2) or
                any(type(v) is not int or not 0 <= v <= _MASK32 for v in self.operands)):
            raise InputError('IV observation requires a source site and ordered raw DWORD operands')


@dataclass(frozen=True)
class IVControlPrefix:
    site: str | None
    context: int | None
    selector: int | None
    d: int
    observations: tuple
    partial_operands: tuple
    alternate_delays: int
    delay_increments: int
    delay_comparisons: int
    context_writes: int
    restore_writes: int


class IVControlFailure(PrimarySemanticUnavailable):
    def __init__(self, reason, prefix):
        super().__init__(reason)
        self.reason, self.prefix = reason, prefix


class IVSetupControl:
    def __init__(self, observations=None, *, alternate_budget=4096):
        if (observations is not None and (type(observations) is not tuple or
                any(type(v) is not IVSiteObservation for v in observations)) or
                type(alternate_budget) is not int or not 0 <= alternate_budget <= _MASK32):
            raise InputError('IV control requires immutable raw site observations and a bounded alternate budget')
        self.observations, self.alternate_budget = observations, alternate_budget
        self.used = self.closed = self.failed = False
        self.site = self.context = self.selector = None
        self.d = self.alternate_delays = self.delay_increments = self.delay_comparisons = 0
        self.context_writes = self.restore_writes = 0
        self.reads = []
        self.partial_operands = ()

    def snapshot(self):
        return IVControlPrefix(self.site, self.context, self.selector, self.d, tuple(self.reads), self.partial_operands,
            self.alternate_delays, self.delay_increments, self.delay_comparisons,
            self.context_writes, self.restore_writes)

    def fail(self, reason):
        self.failed = True
        raise IVControlFailure(reason, self.snapshot())

    def begin(self, context):
        if self.used or self.closed or self.failed:
            raise InputError('IV control is one-shot and terminal')
        self.used, self.context = True, context
        low = context & _MASK32
        self.selector = ((((low << 1) | (low >> 31)) & _MASK32) * 0x19660D - 1) & 3

    def observe(self, memory, base, site):
        if not self.used or self.closed or self.failed:
            raise InputError('IV control is not active')
        self.site = site
        kind = _IV_SITES[site]
        if self.observations is None:
            rvas = (0x677E1BC,) if kind == 'M' else ((0x677E1B4, 0x677E1B8) if kind == 'F' else (0x6D86090, 0x6D86094))
            try:
                self.partial_operands = ()
                for rva in rvas:
                    self.partial_operands += (memory.load(base + rva, 4),)
                operands = self.partial_operands
            except Exception as error:
                try:
                    self.fail('IV_CONTROL_MEMORY_READ')
                except IVControlFailure as failure:
                    raise failure from error
            observation = IVSiteObservation(site, operands)
        else:
            index = len(self.reads)
            if index >= len(self.observations):
                self.fail('IV_CONTROL_WITNESS_EXHAUSTED')
            observation = self.observations[index]
            if observation.site != site:
                self.fail('IV_CONTROL_SITE_MISMATCH')
        self.reads.append(observation)
        self.partial_operands = ()
        values = observation.operands
        if kind == 'M':
            return int(values[0] == 0x80000000)
        x, y = values
        ax, ay = abs(signed(x, 32)), abs(signed(y, 32))
        value = (((x * x + y * y) & _MASK32) | ((ax + ay) & _MASK32)) if kind == 'F' else ((x * x) & _MASK32) | (ay & _MASK32)
        return (value >> 31) & 1

    def delay(self):
        self.d = 0
        if self.alternate_delays >= self.alternate_budget:
            self.fail('IV_CONTROL_ALTERNATE_BUDGET')
        self.alternate_delays += 1
        self.d = self.selector + 1
        self.delay_increments += self.d
        self.delay_comparisons += self.selector + 2

    def finish(self):
        if self.failed or self.closed or not self.used:
            raise InputError('IV control is not active')
        if self.observations is not None and len(self.reads) != len(self.observations):
            self.fail('IV_CONTROL_EXTRA_WITNESS')
        self.closed = True


def _substitute(memory, base, value, banks):
    result = 0
    for lane, bank in enumerate(banks):
        result ^= memory.load(base + 0x433C4C0 + bank * 1024 + ((value >> (8 * lane)) & 255) * 4, 4)
    return result


def normal_iv_setup(memory, context, iv, *, image_base, source_vm=None, control=None):
    replay = getattr(memory, '_consumed_mgf_guard', None)
    if control is not None and type(control) is not IVSetupControl:
        raise InputError('IV setup requires IVSetupControl or fresh memory observations')
    if replay is not None and control is not None:
        raise InputError('consumed normal IV cannot use alternate control observations')
    bits = memory.load(context + 0x110, 4)
    if bits not in (128, 256):
        raise PrimaryProgramLimit("ECRYPT IV requires a supported initialized 128/256-bit key")
    ranges = ((context, context + 408), (iv, iv + bits // 8),
              (image_base + 0x433C4C0, image_base + 0x433CCC0))
    if any(a < d and c < b for i, (a, b) in enumerate(ranges) for c, d in ranges[i + 1:]):
        raise PrimaryProgramLimit("ECRYPT IV private context, IV and tables must be disjoint")
    if any(context < image_base + end and image_base + start < context + 408
           for start, end in ((0x677E1B4, 0x677E1C0), (0x6D86090, 0x6D86098))):
        raise PrimaryProgramLimit("ECRYPT IV private context must preserve branch globals")

    if replay is not None:
        for address, end in ranges:
            replay.guard_overlap(address, end - address)
        replay.verify_iv_normal_domain(source_vm, context, iv)
    else:
        control = IVSetupControl() if control is None else control
        control.begin(context)
    if source_vm is not None and replay is None:
        source_vm.iv_setup_control = control

    def observe(site):
        return 0 if replay is not None else control.observe(memory, image_base, site)

    def delay():
        control.delay()

    def write(address, value, width, site):
        memory.store(address, value, width, source=site)
        if replay is None:
            control.context_writes += 1

    def load(index):
        return memory.load(context + 4 * (index & 31), 4)

    def store(index, value, site):
        write(context + 4 * (index & 31), value, 4, site)

    if memory.load(context + 0x10C, 1) == 0:
        if observe('M30F4'):
            delay()
        while observe('F2704'):
            delay()
        for index in range(32):
            def copy_word():
                store(index, memory.load(context + 0x8C + 4 * index, 4), "2DE27CF.restore_key_state")
                if replay is None:
                    control.restore_writes += 1
            if observe('F2903'):
                copy_word()
                delay()
            copy_word()
            while observe('F27D2'):
                copy_word()
                delay()
                copy_word()
    while True:
        bits = memory.load(context + 0x110, 4)
        if bits not in (128, 256):
            raise PrimaryProgramLimit("ECRYPT IV requires a supported initialized 128/256-bit key")
        current_ranges = ((context, context + 408), (iv, iv + bits // 8),
                          (image_base + 0x433C4C0, image_base + 0x433CCC0))
        if any(a < d and c < b for i, (a, b) in enumerate(current_ranges) for c, d in current_ranges[i + 1:]):
            raise PrimaryProgramLimit("ECRYPT IV private context, IV and tables must be disjoint")
        if not observe('F30B2'):
            break
        delay()
    if bits == 128:
        def copy_iv128(index, extra=False):
            value = memory.load(iv + 4 * index, 4)
            sites = ("ECRYPT.128.extra.IV_word", "ECRYPT.128.extra.IV_xor20", "ECRYPT.128.extra.IV_xor28") if extra else ("2DE28A4.IV_word", "2DE28AA.IV_xor", "2DE28B0.IV_xor")
            store(index + 8, value, sites[0])
            store(index + 20, load(index + 20) ^ value, sites[1])
            store(index + 28, load(index + 28) ^ value, sites[2])
        for index in range(4):
            if observe('G2FC8'):
                copy_iv128(index, True)
                delay()
            copy_iv128(index)
            while observe('G28B3'):
                copy_iv128(index, True)
                delay()
                copy_iv128(index)
        while observe('M261F'):
            delay()
        for index in range(2):
            value = memory.load(iv + 8 + 4 * index, 4)
            store(index + 4, load(index + 4) ^ value, "2DE24BF.IV_xor")
            store(index + 12, load(index + 12) ^ value, "2DE24C5.IV_xor")
            store(index + 24, value, "2DE24CB.IV_word")
            value = memory.load(iv + 4 * index, 4)
            store(index + 6, load(index + 6) ^ value, "2DE24D4.IV_xor")
            store(index + 14, load(index + 14) ^ value, "2DE24DA.IV_xor")
            store(index + 26, value, "2DE24E0.IV_word")
    else:
        def copy_iv256(index, extra=False):
            value = memory.load(iv + 4 * index, 4)
            sites = ("2DE303B.IV_xor", "2DE3048.IV_complement", "2DE304E.IV_word") if extra else ("2DE2F3C.IV_xor", "2DE2F49.IV_complement", "2DE2F4F.IV_word")
            store(index + 8, load(index + 8) ^ value, sites[0])
            store(index + 16, ~(load(index + 16) ^ value), sites[1])
            store(index + 24, value, sites[2])
        for index in range(8):
            if observe('G31A9'):
                copy_iv256(index, True)
                delay()
            copy_iv256(index)
            while observe('M2F52'):
                copy_iv256(index, True)
                delay()
                copy_iv256(index)
    f, e = 0x22432775, 0x3C569F6D
    for _ in range(16):
        offset = memory.load(context + 0x88, 4)
        a = load(offset + 24) ^ load(offset + 1) ^ load(offset + 28)
        b = load(offset + 26) ^ load(offset + 2) ^ load(offset + 30)
        c = load(offset + 3) ^ a ^ load(offset + 25) ^ load(offset + 29)
        d = load(offset) ^ b ^ load(offset + 27) ^ load(offset - 1)
        b = (b + c) & _MASK32
        a = (a + (e ^ f)) & _MASK32
        g = e ^ f ^ _substitute(memory, image_base, b, (0, 1, 0, 0))
        f = (f + d) & _MASK32
        c ^= _substitute(memory, image_base, f, (0, 0, 1, 0))
        d ^= _substitute(memory, image_base, a, (1, 0, 0, 0))
        h = f ^ _substitute(memory, image_base, g, (1, 1, 0, 1))
        a ^= _substitute(memory, image_base, c, (0, 1, 1, 1))
        f = (a + d) & _MASK32
        b ^= _substitute(memory, image_base, d, (1, 0, 1, 1))
        write(context + 0x88, offset + 28, 4, "2DE2CD2.state_offset")
        c = (c + h) & _MASK32
        e = (g + b) & _MASK32
        store(offset + 28, a ^ load(offset + 16) ^ e, "2DE2CF4.state_word")
        store(offset + 31, c ^ load(offset + 18), "2DE2D0C.state_word")
        store(offset + 30, b ^ c ^ load(offset + 17), "2DE2D27.state_word")
        store(offset + 29, f ^ load(offset + 19), "2DE2D3F.state_word")
        f ^= h
    write(context + 0x80, f, 4, "2DE32A4.counter_low")
    write(context + 0x84, e, 4, "2DE32AE.counter_high")
    write(context + 0x10C, 0, 1, "2DE32B4.IV_ready")
    if replay is None:
        control.finish()


def normal_keystream(memory, context, output, blocks, *, image_base):
    if type(blocks) is not int or not 0 <= blocks <= _MASK32 or blocks & 15:
        raise PrimaryProgramLimit("ECRYPT keystream requires complete sixteen-pair batches")
    if any(context < image_base + right and image_base + left < context + 136
           for left, right in ((0x433C4C0, 0x433CCC0), (0x6428508, 0x6428528))):
        raise PrimaryProgramLimit("ECRYPT private core state must preserve tables and dispatch")
    if blocks:
        end = output + 8 * blocks
        if end > 1 << 64 or any(output < right and left < end for left, right in
                               ((context, context + 136),
                                (image_base + 0x433C4C0, image_base + 0x433CCC0),
                                (image_base + 0x6428508, image_base + 0x6428528))):
            raise PrimaryProgramLimit("ECRYPT output must preserve core state, tables and dispatch")

    def dispatch(index, target):
        if memory.load(image_base + 0x6428508 + 8 * index, 8) != image_base + target:
            raise PrimarySemanticUnavailable("ECRYPT current dispatch target is unavailable")

    def load(index):
        return memory.load(context + 4 * index, 4)

    high, low = load(32), load(33)
    dispatch(int(blocks != 0), 0x2DE333D if blocks else 0x2DE4B06)
    a_indices = (0, 28, 30, 24, 26, 22, 20, 14, 16, 18, 12, 10, 8, 6, 2, 4)
    x_indices = (9, 7, 5, 3, 2, 31, 29, 27, 25, 23, 21, 19, 17, 15, 13, 11)
    for start in range(0, blocks, 16):
        for lane, (ai, xi) in enumerate(zip(a_indices, x_indices)):
            di = 30 - 2 * lane
            bi = (16 - 2 * lane) & 31
            a0 = load(ai)
            a = a0 ^ load(xi)
            b = (a + load(bi)) & _MASK32
            d = load(bi) ^ load((bi + 3) & 31)
            e = ((low + start + lane) & _MASK32) ^ load(di) ^ high ^ load(di + 1)
            c = (a0 + e) & _MASK32
            f = ((load(di) ^ high) + d) & _MASK32
            e ^= _substitute(memory, image_base, b, (0, 1, 0, 0))
            a ^= _substitute(memory, image_base, f, (0, 0, 1, 0))
            d ^= _substitute(memory, image_base, c, (1, 0, 0, 0))
            f ^= _substitute(memory, image_base, e, (1, 1, 0, 1))
            b ^= _substitute(memory, image_base, d, (1, 0, 1, 1))
            c ^= _substitute(memory, image_base, a, (0, 1, 1, 1))
            value = (a + f) & _MASK32
            destination = di if lane != 15 else 1
            memory.store(context + 4 * destination, value, 4, source="2DE32CF.next_state_even")
            memory.store(context + 4 * (destination + 1), value ^ b, 4,
                         source="2DE32CF.next_state_odd")
            memory.store(output + 8 * (start + lane), ((b + e) & _MASK32) ^ c, 4,
                         source="2DE32CF.keystream_even")
            memory.store(output + 8 * (start + lane) + 4, ((c + d) & _MASK32) ^ f, 4,
                         source="2DE32CF.keystream_odd")
        dispatch(int(start + 16 != blocks), 0x2DE333D if start + 16 != blocks else 0x2DE4B06)
    updated = (low + blocks) & _MASK32
    carry = updated < memory.load(context + 0x84, 4)
    dispatch(2 + int(carry), 0x2DE4B29 if carry else 0x2DE4B31)
    if carry:
        memory.store(context + 0x80, high + 1, 4, source="2DE4B2B.counter_high")
    memory.store(context + 0x84, updated, 4, source="2DE4B31.counter_low")
