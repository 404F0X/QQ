from hashlib import sha256
from threading import get_ident

from .primary_main_mix import MAIN_SHA256
from .errors import InputError
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, signed


CONSUMER_ENTRIES = {31440: (680, 32266, 4375), 36986: (826, 37823, 5113)}
MATERIAL_SHA256 = '8a073659c987221badb188064e18900a68cb35039e55753ed52fa1c51fd44cea'


def _read_pair_control(vm):
    x = signed(vm.memory.load(vm.image_base + 0x677E1B4, 4), 32)
    y = signed(vm.memory.load(vm.image_base + 0x677E1B8, 4), 32)
    return (((x * x + y * y) & 0xFFFFFFFF) | ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31


def _pair_control(vm):
    if _read_pair_control(vm):
        raise PrimarySemanticUnavailable('independent record consumer alternate pair control is unavailable')


def _single_control(vm):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = signed(vm.memory.load(vm.image_base + 0x6D86094, 4), 32)
    if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
        raise PrimarySemanticUnavailable('independent record consumer extra operand control is unavailable')


def _convert(vm, width, source, destination):
    alternate = False
    if width == 1 or width >= 4:
        alternate = _read_pair_control(vm)
    if width >= 4:
        if vm.memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000:
            raise PrimarySemanticUnavailable('independent record consumer mask wait is unavailable')
        if width >= 8:
            vm.memory.load(vm.image_base + 0x677E1BC, 4)
            if vm.memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000:
                raise PrimarySemanticUnavailable('independent record consumer mask wait is unavailable')
    value = vm.memory.load(vm.cells.pointer(source), width)
    vm.memory.store(vm.cells.pointer(destination), value, 8, source='once10.first_type_zeroextend_or_q')
    if width == 1 and alternate:
        value = vm.memory.load(vm.cells.pointer(source), 1)
        vm.memory.store(vm.cells.pointer(destination), value, 8, source='once10.first_type_zeroextend_or_q')


def _equal(vm, consumed, width, left, right, destination):
    _single_control(vm)
    vm.pc = consumed
    a = vm.memory.load(vm.cells.pointer(left), width, signed=True)
    b = vm.memory.load(vm.cells.pointer(right), width, signed=True)
    vm._write(destination, int(a == b), 4, 'L26.comparison')
    _pair_control(vm)


def _pointer(vm, word, typ, base, destination, indices):
    vm.pc = word + 6
    offset = 0
    for ordinal, index_cell in enumerate(indices):
        vm.pc = word + 7 + ordinal
        index = vm.memory.load(vm.cells.pointer(index_cell), 4)
        if ordinal == 0:
            delta = vm.program.size(typ) * index
        else:
            delta, typ = vm._indexed_offset(typ, index)
        offset = (offset + delta) & 0xFFFFFFFFFFFFFFFF
    vm._write(destination, vm.cells.value(base) + offset, 8, 'high.indexed_pointer_q')


def _phi(vm, word, operands):
    destination, count, *pairs = operands
    matched = False
    for ordinal in range(count):
        source, predecessor = pairs[2 * ordinal:2 * ordinal + 2]
        vm.pc = word + 5 + 2 * ordinal
        if not matched and vm.predecessor == predecessor:
            vm._write(destination, vm.cells.value(source), 8, 'L9.phi_q')
            matched = True
    vm.pc = word + 3 + 2 * count


def _switch(vm, word, operands):
    condition, target, count, *pairs = operands
    matched = False
    for ordinal in range(count):
        case, branch = pairs[2 * ordinal:2 * ordinal + 2]
        vm.pc = word + 6 + 2 * ordinal
        if not matched and vm.cells.value(condition) == vm.cells.value(case):
            target, matched = branch, True
    vm._jump(target)


def _provider_host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    expected = {19: 0x3591D6C, 284: 0x3591E38, 1270: 0x3591E46}[word]
    if address != vm.image_base + expected:
        raise PrimarySemanticUnavailable('independent material provider requires its fixed context host binding')
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    result = _invoke_host(vm, address, arguments, signature,
                          argument_types=vm.program.type(signature).parameters[3:])
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _qualify_policy_material_provider(vm, runtime, owner):
    main, stack = owner['vm'], runtime._program_calls
    if (not runtime.primary_core or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            owner.get('thread') != get_ident() or owner.get('generation') != runtime._main_generation or
            runtime._execute_thread != get_ident() or runtime._active_failed or
            getattr(runtime, '_consumed_mgf', None) is not None or
            main.runtime is not runtime or main.memory is not runtime.memory or main.image_base != runtime.image_base or
            sha256(main.program.raw).hexdigest() != MAIN_SHA256 or main.halted or main.abort_reason is not None or
            (main.pc, main.block, main.predecessor, main.initial_block) != (444, 1, 0, False) or
            main.program.words[432:444] != (0x014A3DB9, 119, 0, 151, 0, 152, 1, 2, 153, 154, 7, 8) or
            not main.host_calls or main.host_calls[-1] !=
            (432, runtime.image_base + 0x2DE50A9, (152, 1, 2, 153, 154, 7, 8), 119) or
            tuple(call['name'] for call in stack) != ('main', 'host97', 'material-block') or
            any(call['hosts'] is not None for call in stack) or not runtime.vms or runtime.vms[-1] is not vm):
        raise PrimarySemanticUnavailable('independent policy material provider requires its exact active Main family')
    signature = main.program.type(119)
    if (signature.raw != 21 or signature.parameters != (0, 0, 7, 1, 2, 3, 2, 3, 2, 4) or
            tuple(main.program.size(t) for t in signature.parameters[3:]) != (1, 8, 4, 8, 4, 8, 8) or
            len(stack[1]['arguments']) != 7 or
            any(type(value) is not int or not 0 <= value < 1 << bits for value, bits in
                zip(stack[1]['arguments'], (8, 64, 32, 64, 32, 64, 64)))):
        raise PrimarySemanticUnavailable('independent policy material provider requires its actual root ABI')
    parents = [parent for parent in runtime.vms if parent is not vm and not parent.halted and
               parent.runtime is runtime and parent.memory is runtime.memory and parent.image_base == runtime.image_base and
               sha256(parent.program.raw).hexdigest() == '189a179b4a0d375c4b01ff2af3b77452213c0efe07153cd3910aff34a55b5875']
    if len(parents) != 1:
        raise PrimarySemanticUnavailable('independent policy material provider requires one actual host97 parent')
    parent = parents[0]
    row = {141: (132, (25, 17, 42, 9), (0, 0, 8)),
           157: (148, (45, 17, 46, 9), (1, 0, 1)),
           173: (164, (45, 46, 48, 9), (1, 1, 2))}.get(parent.pc)
    if row is None:
        raise PrimarySemanticUnavailable('independent policy material provider requires an exact host97 source point')
    word, arguments, values = row
    signature = parent.program.type(26)
    child = stack[-1]['arguments']
    if ((parent.block, parent.predecessor, parent.initial_block) != (0, None, True) or parent.abort_reason is not None or
            parent.program.words[word:parent.pc] != (0x014A3DB9, 26, 0, 41, 0, *arguments) or
            getattr(parent, '_primary_policy3_active_call', None) != (word, 41, arguments, 26, None) or
            not parent.host_calls or parent.host_calls[-1] !=
            (word, runtime.image_base + 0x2DE4C3B, arguments, 26) or
            signature.raw != 21 or signature.parameters != (0, 0, 4, 1, 3, 3, 12) or
            tuple(parent.program.size(t) for t in signature.parameters[3:]) != (1, 4, 4, 8) or
            len(child) != 4 or child[1:] != values or type(child[0]) is not int or not 0 < child[0] < 1 << 64 or
            any(getattr(parent, name) is not None for name in ('pending_once10', 'pending_once9', 'pending_l26',
                'pending_variadic', 'pending_native', 'private_iv_native_pending'))):
        raise PrimarySemanticUnavailable('independent policy material provider requires its actual host97 wrapper window')
    region, offset = runtime.memory._span(child[0], 16)
    if offset != 0 or len(region.data) != 16 or region.name != '2DE4C3B explicit private stack initial state':
        raise PrimarySemanticUnavailable('independent policy material provider requires its real private wrapper record')


def execute_primary_main_material_provider(vm, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != MATERIAL_SHA256 or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) != (1, 0, None, True)):
        raise PrimarySemanticUnavailable('independent material provider requires its fixed program entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if type(owner) is dict and type(owner.get('vm')) is PrimaryVM and owner['vm'].pc == 444:
        _qualify_policy_material_provider(vm, runtime, owner)
    else:
        if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
                type(owner) is not dict or owner.get('thread') != get_ident() or
                owner.get('generation') != runtime._main_generation or runtime._active_failed or
                getattr(runtime, '_consumed_mgf', None) is not None or
                type(owner.get('vm')) is not PrimaryVM or owner['vm'].runtime is not runtime or
                owner['vm'].pc not in (15003, 18257, 31410, 36956, 41128) or len(runtime._program_calls) != 2 or
                runtime._program_calls[0]['name'] != 'main' or runtime._program_calls[1]['name'] != 'material-block'):
            raise PrimarySemanticUnavailable('independent material provider requires its current S/A Main owner')
        if owner['vm'].pc in (15003, 18257):
            main = owner['vm']
            word, block, predecessor, host_arguments, child_arguments = {
                15003: (14994, 352, 349, (235, 502, 502, 120), (0, 8, 8)),
                18257: (18248, 435, 432, (354, 158, 269, 124), (1, 0, 1))}[main.pc]
            arguments = runtime._program_calls[1]['arguments']
            signature = main.program.type(158)
            if (main.memory is not runtime.memory or main.image_base != runtime.image_base or
                    sha256(main.program.raw).hexdigest() != MAIN_SHA256 or
                    (main.block, main.predecessor, main.initial_block) != (block, predecessor, False) or
                    runtime._execute_thread != get_ident() or runtime._program_calls[0]['hosts'] is not None or
                    runtime._program_calls[1]['hosts'] is not None or
                    len(arguments) != 4 or arguments[1:] != child_arguments or
                    main.program.words[word:main.pc] != (0x014A3DB9, 158, 0, 2176, 0, *host_arguments) or
                    signature.raw != 21 or signature.parameters != (0, 0, 4, 1, 3, 3, 12) or
                    tuple(main.program.size(t) for t in signature.parameters[3:]) != (1, 4, 4, 8) or
                    not main.host_calls or main.host_calls[-1] !=
                    (word, runtime.image_base + 0x2DE4C3B, host_arguments, 158)):
                raise PrimarySemanticUnavailable('independent material provider requires its exact early Main call and wrapper arguments')
        if owner['vm'].pc == 41128:
            main = owner['vm']
            arguments = runtime._program_calls[1]['arguments']
            if (main.memory is not runtime.memory or sha256(main.program.raw).hexdigest() != MAIN_SHA256 or
                    runtime._execute_thread != get_ident() or runtime._program_calls[1]['hosts'] is not None or
                    len(arguments) != 4 or arguments[1:] != (1, 1, 2) or
                    not main.host_calls or main.host_calls[-1] !=
                    (41119, runtime.image_base + 0x2DE4C3B, (354, 269, 311, 51), 158)):
                raise PrimarySemanticUnavailable('independent material provider requires the exact Main41119 call and wrapper arguments')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent material provider cannot enter a stopped or pending body')
    state = dict(entryWord=1, exitWord=2159, referenceRecordCount=0, completed=False,
                 backend='DIRECT_MATERIAL_BLOCK', contextInitializationBackend='GENERIC_MATERIAL_STATE',
                 traceComplete=False)
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_main_material_provider_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    _material_provider(vm, tick)
    state['completed'] = True
    return vm.result


def execute_primary_main_record_consumer(vm, *, charge=None):
    entry = CONSUMER_ENTRIES.get(vm.pc)
    if type(vm) is not PrimaryVM or entry is None or sha256(vm.program.raw).hexdigest() != MAIN_SHA256:
        raise PrimarySemanticUnavailable('independent record consumer requires its fixed Main entry')
    block, stop, key = entry
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (vm.block != block or vm.initial_block or runtime is None or vm.memory is not runtime.memory or
            vm.image_base != runtime.image_base or type(owner) is not dict or owner.get('vm') is not vm or
            owner.get('thread') != get_ident() or owner.get('generation') != runtime._main_generation or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None):
        raise PrimarySemanticUnavailable('independent record consumer requires the current Main owner without replay')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent record consumer cannot enter a stopped or pending body')
    state = dict(entryWord=vm.pc, exitWord=stop, key=key, referenceRecordCount=0,
                 completed=False, producerBackend='CALLER_MODEL_MATERIAL_RECORD', traceComplete=False)
    vm.primary_main_record_consumer_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if charge is not None:
            charge()
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    if key == 4375:
        _schedule_consumer(vm, tick)
    else:
        _seed_consumer(vm, tick)
    state['completed'] = True
    return state



def _schedule_consumer(vm, tick):
    cells, memory = vm.cells, vm.memory
    while vm.pc != 32266:
        if vm.block == 680:
            tick(31440)
            _pointer(vm, 31440, 11, 18, 4268, (145, 158))
            tick(31448)
            vm.pc = 31452
            value = memory.load(cells.value(4268), 8)
            vm._write(4269, value, 8, 'L5.unsigned_load')
            tick(31452)
            vm.pc = 31456
            pointer = cells.value(16)
            value = memory.load(cells.pointer(4269), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(31456)
            _pointer(vm, 31456, 11, 18, 4270, (145, 269))
            tick(31464)
            vm.pc = 31468
            value = memory.load(cells.value(4270), 1)
            vm._write(4271, value, 4, 'high.load')
            tick(31468)
            _pointer(vm, 31468, 11, 18, 4272, (145, 311))
            tick(31476)
            vm.pc = 31480
            value = memory.load(cells.value(4272), 1)
            vm._write(4273, value, 4, 'high.load')
            tick(31480)
            vm.pc = 31485
            _convert(vm, 4, 4273, 4274)
            tick(31485)
            _switch(vm, 31485, (4273, 688, 4, 354, 689, 369, 689, 152, 689, 2188, 689))
            continue
        if vm.block == 689:
            tick(31497)
            vm.pc = 31498
            tick(31498)
            vm.pc = 31501
            vm.auxiliary = (0, 395503875)
            tick(31501)
            vm.pc = 31506
            vm._write(4275, int(memory.load(cells.pointer(4271), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(31506)
            vm.pc = 31510
            vm._jump(688 if cells.value(4275) != 0 else 690)
            continue
        if vm.block == 690:
            tick(31510)
            vm.pc = 31515
            _convert(vm, 8, 4273, 4276)
            tick(31515)
            _pointer(vm, 31515, 41, 69, 4277, (145, 145))
            tick(31523)
            vm.pc = 31528
            vm._write(4278, memory.load(cells.pointer(4276), 8, signed=True) & memory.load(cells.pointer(1732), 8, signed=True), 8, 'L13.binary_q')
            tick(31528)
            vm.pc = 31530
            vm._jump(691)
            continue
        if vm.block == 691:
            tick(31530)
            _phi(vm, 31530, (4279, 2, 145, 690, 4280, 692))
            tick(31537)
            vm.pc = 31542
            vm._write(4281, int(cells.value(4279) < cells.value(4278)), 4, 'once18.unsigned_q')
            tick(31542)
            vm.pc = 31546
            vm._jump(692 if cells.value(4281) != 0 else 693)
            continue
        if vm.block == 692:
            tick(31546)
            _pointer(vm, 31546, 1, 4264, 4282, (4279,))
            tick(31553)
            vm.pc = 31558
            cells.copy_q_clear_owned(4282, 4283)
            tick(31558)
            vm.pc = 31562
            value = memory.load(cells.value(4283), 4)
            vm._write(4284, value, 4, 'high.load')
            tick(31562)
            _pointer(vm, 31562, 1, 4277, 4285, (4279,))
            tick(31569)
            vm.pc = 31574
            cells.copy_q_clear_owned(4285, 4286)
            tick(31574)
            vm.pc = 31578
            pointer = cells.value(4286)
            value = memory.load(cells.pointer(4284), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(31578)
            vm.pc = 31579
            tick(31579)
            vm.pc = 31582
            vm.auxiliary = (0, 309792770)
            tick(31582)
            vm.pc = 31587
            vm._write(4280, memory.load(cells.pointer(4279), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(31587)
            vm.pc = 31589
            vm._jump(691)
            continue
        if vm.block == 693:
            tick(31589)
            _phi(vm, 31589, (4287, 2, 4288, 694, 4278, 691))
            tick(31596)
            vm.pc = 31601
            vm._write(4289, int(cells.value(4287) < cells.value(4276)), 4, 'once18.unsigned_q')
            tick(31601)
            vm.pc = 31605
            vm._jump(694 if cells.value(4289) != 0 else 695)
            continue
        if vm.block == 694:
            tick(31605)
            _pointer(vm, 31605, 1, 4264, 4290, (4287,))
            tick(31612)
            vm.pc = 31616
            value = memory.load(cells.value(4290), 1)
            vm._write(4291, value, 4, 'high.load')
            tick(31616)
            _pointer(vm, 31616, 1, 4277, 4292, (4287,))
            tick(31623)
            vm.pc = 31627
            pointer = cells.value(4292)
            value = memory.load(cells.pointer(4291), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(31627)
            vm.pc = 31628
            tick(31628)
            vm.pc = 31631
            vm.auxiliary = (0, 555028482)
            tick(31631)
            vm.pc = 31636
            vm._write(4288, memory.load(cells.pointer(4287), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(31636)
            vm.pc = 31638
            vm._jump(693)
            continue
        if vm.block == 695:
            tick(31638)
            vm.pc = 31643
            value = memory.load(cells.pointer(4271), 1)
            count = memory.load(cells.pointer(336), 1)
            vm._write(4293, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31643)
            vm.pc = 31648
            value = memory.load(cells.pointer(4271), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(4294, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31648)
            vm.pc = 31649
            tick(31649)
            vm.pc = 31652
            vm.auxiliary = (0, 22900)
            tick(31652)
            vm.pc = 31658
            vm._write(4295, memory.load(cells.pointer(4293), 1, signed=True) ^ memory.load(cells.pointer(4294), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(31658)
            vm.pc = 31663
            value = memory.load(cells.pointer(4271), 1)
            count = memory.load(cells.pointer(152), 1)
            vm._write(4296, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31663)
            vm.pc = 31666
            vm.auxiliary = (0, 44861)
            tick(31666)
            vm.pc = 31672
            vm._write(4297, memory.load(cells.pointer(4295), 1, signed=True) ^ memory.load(cells.pointer(4296), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(31672)
            vm.pc = 31677
            value = memory.load(cells.pointer(4271), 1)
            count = memory.load(cells.pointer(497), 1)
            vm._write(4298, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31677)
            vm.pc = 31680
            vm.auxiliary = (0, 15206)
            tick(31680)
            vm.pc = 31686
            vm._write(4299, memory.load(cells.pointer(4297), 1, signed=True) ^ memory.load(cells.pointer(4298), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(31686)
            vm.pc = 31691
            vm._write(4300, memory.load(cells.pointer(4299), 1, signed=True) & memory.load(cells.pointer(354), 1, signed=True), 8, 'L13.binary_q')
            tick(31691)
            vm.pc = 31694
            vm.auxiliary = (0, 63212)
            tick(31694)
            _single_control(vm)
            vm.pc = 31699
            count = memory.load(cells.pointer(354), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(4271), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(4301, value, 4, 'typed.selector3.d')
            tick(31699)
            vm.pc = 31704
            vm._write(4302, memory.load(cells.pointer(4301), 1, signed=True) | memory.load(cells.pointer(4300), 1, signed=True), 8, 'L15.binary_q')
            tick(31704)
            vm.pc = 31707
            vm.auxiliary = (0, 28189)
            tick(31707)
            vm.pc = 31713
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(4303, memory.load(cells.pointer(4302), 1, signed=True) ^ memory.load(cells.pointer(1645), 1, signed=True), 8, 'typed.selector5.q')
            tick(31713)
            vm.pc = 31716
            vm.auxiliary = (0, 5628)
            tick(31716)
            _single_control(vm)
            vm.pc = 31721
            count = memory.load(cells.pointer(497), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(4303), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(4304, value, 4, 'typed.selector3.d')
            tick(31721)
            vm.pc = 31726
            value = memory.load(cells.pointer(4303), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(4305, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31726)
            vm.pc = 31731
            vm._write(4306, memory.load(cells.pointer(4304), 1, signed=True) | memory.load(cells.pointer(4305), 1, signed=True), 8, 'L15.binary_q')
            tick(31731)
            vm.pc = 31734
            vm.auxiliary = (0, 2009237939)
            tick(31734)
            vm.pc = 31739
            vm._write(4307, int(memory.load(cells.pointer(4306), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(31739)
            vm.pc = 31746
            selected = 2222 if cells.value(4307) != 0 else 4306
            vm._write(4308, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(31746)
            _pointer(vm, 31746, 41, 70, 4309, (145, 145))
            tick(31754)
            vm.pc = 31758
            pointer = cells.value(4309)
            value = memory.load(cells.pointer(4308), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(31758)
            vm.pc = 31760
            vm._jump(696)
            continue
        if vm.block == 696:
            tick(31760)
            _phi(vm, 31760, (4310, 2, 269, 695, 4311, 697))
            tick(31767)
            vm.pc = 31772
            vm._write(4312, int(cells.value(4310) < cells.value(4274)), 4, 'once18.unsigned_q')
            tick(31772)
            vm.pc = 31776
            vm._jump(697 if cells.value(4312) != 0 else 698)
            continue
        if vm.block == 697:
            tick(31776)
            vm.pc = 31777
            tick(31777)
            vm.pc = 31780
            vm.auxiliary = (0, 1366036482)
            tick(31780)
            vm.pc = 31785
            vm._write(4313, memory.load(cells.pointer(4310), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(31785)
            vm.pc = 31790
            _convert(vm, 8, 4313, 4314)
            tick(31790)
            _pointer(vm, 31790, 41, 70, 4315, (145, 4314))
            tick(31798)
            vm.pc = 31802
            value = memory.load(cells.value(4315), 1)
            vm._write(4316, value, 4, 'high.load')
            tick(31802)
            vm.pc = 31807
            value = memory.load(cells.pointer(4316), 1)
            count = memory.load(cells.pointer(336), 1)
            vm._write(4317, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31807)
            vm.pc = 31812
            value = memory.load(cells.pointer(4316), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(4318, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31812)
            vm.pc = 31817
            vm._write(4319, memory.load(cells.pointer(4317), 1, signed=True) ^ memory.load(cells.pointer(4318), 1, signed=True), 8, 'L14.binary_q')
            tick(31817)
            vm.pc = 31822
            value = memory.load(cells.pointer(4316), 1)
            count = memory.load(cells.pointer(152), 1)
            vm._write(4320, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31822)
            vm.pc = 31827
            vm._write(4321, memory.load(cells.pointer(4319), 1, signed=True) ^ memory.load(cells.pointer(4320), 1, signed=True), 8, 'L14.binary_q')
            tick(31827)
            vm.pc = 31832
            value = memory.load(cells.pointer(4316), 1)
            count = memory.load(cells.pointer(497), 1)
            vm._write(4322, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31832)
            vm.pc = 31835
            vm.auxiliary = (0, 60788)
            tick(31835)
            vm.pc = 31841
            vm._write(4323, memory.load(cells.pointer(4321), 1, signed=True) ^ memory.load(cells.pointer(4322), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(31841)
            vm.pc = 31844
            vm.auxiliary = (0, 21310)
            tick(31844)
            vm.pc = 31849
            vm._write(4324, memory.load(cells.pointer(4323), 1, signed=True) & memory.load(cells.pointer(354), 1, signed=True), 8, 'typed.selector1.q')
            tick(31849)
            vm.pc = 31852
            vm.auxiliary = (0, 29614)
            tick(31852)
            _single_control(vm)
            vm.pc = 31857
            count = memory.load(cells.pointer(354), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(4316), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(4325, value, 4, 'typed.selector3.d')
            tick(31857)
            vm.pc = 31860
            vm.auxiliary = (0, 12769)
            tick(31860)
            vm.pc = 31865
            vm._write(4326, memory.load(cells.pointer(4325), 1, signed=True) | memory.load(cells.pointer(4324), 1, signed=True), 8, 'typed.selector2.q')
            tick(31865)
            vm.pc = 31870
            vm._write(4327, cells.value(4310) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(31870)
            vm.pc = 31873
            vm.auxiliary = (0, 1519366660)
            tick(31873)
            vm.pc = 31878
            vm._write(4328, memory.load(cells.pointer(4327), 1, signed=True) * memory.load(cells.pointer(2243), 1, signed=True), 8, 'once0.integer')
            tick(31878)
            vm.pc = 31881
            vm.auxiliary = (0, 1966178306)
            tick(31881)
            vm.pc = 31886
            vm._write(4329, memory.load(cells.pointer(4328), 1, signed=True) + memory.load(cells.pointer(1645), 1, signed=True), 8, 'once1.integer')
            tick(31886)
            vm.pc = 31889
            vm.auxiliary = (0, 63796)
            tick(31889)
            vm.pc = 31895
            vm._write(4330, memory.load(cells.pointer(4329), 1, signed=True) ^ memory.load(cells.pointer(4326), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(31895)
            vm.pc = 31898
            vm.auxiliary = (0, 25246)
            tick(31898)
            _single_control(vm)
            vm.pc = 31903
            count = memory.load(cells.pointer(497), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(4330), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(4331, value, 4, 'typed.selector3.d')
            tick(31903)
            vm.pc = 31908
            value = memory.load(cells.pointer(4330), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(4332, value >> (count & 31), 4, 'once8.logical_shift')
            tick(31908)
            vm.pc = 31913
            vm._write(4333, memory.load(cells.pointer(4331), 1, signed=True) | memory.load(cells.pointer(4332), 1, signed=True), 8, 'L15.binary_q')
            tick(31913)
            vm.pc = 31916
            vm.auxiliary = (0, 1897067107)
            tick(31916)
            vm.pc = 31921
            vm._write(4334, int(memory.load(cells.pointer(4333), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(31921)
            vm.pc = 31926
            vm._write(4335, cells.value(4310) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(31926)
            vm.pc = 31929
            vm.auxiliary = (0, 56092)
            tick(31929)
            vm.pc = 31935
            vm._write(4336, memory.load(cells.pointer(4335), 1, signed=True) ^ memory.load(cells.pointer(2222), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(31935)
            vm.pc = 31942
            selected = 4336 if cells.value(4334) != 0 else 4333
            vm._write(4337, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(31942)
            vm.pc = 31947
            _convert(vm, 8, 4310, 4338)
            tick(31947)
            _pointer(vm, 31947, 41, 70, 4339, (145, 4338))
            tick(31955)
            vm.pc = 31959
            pointer = cells.value(4339)
            value = memory.load(cells.pointer(4337), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(31959)
            vm.pc = 31962
            vm.auxiliary = (0, 604536833)
            tick(31962)
            vm.pc = 31967
            vm._write(4311, memory.load(cells.pointer(4310), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(31967)
            vm.pc = 31969
            vm._jump(696)
            continue
        if vm.block == 698:
            tick(31969)
            _phi(vm, 31969, (4340, 2, 4341, 699, 158, 696))
            tick(31976)
            vm.pc = 31981
            vm._write(4342, int(cells.value(4340) < cells.value(4274)), 4, 'once18.unsigned_q')
            tick(31981)
            vm.pc = 31985
            vm._jump(699 if cells.value(4342) != 0 else 700)
            continue
        if vm.block == 699:
            tick(31985)
            vm.pc = 31990
            _convert(vm, 8, 4340, 4343)
            tick(31990)
            _pointer(vm, 31990, 41, 70, 4344, (145, 4343))
            tick(31998)
            vm.pc = 32002
            value = memory.load(cells.value(4344), 1)
            vm._write(4345, value, 4, 'high.load')
            tick(32002)
            _pointer(vm, 32002, 41, 69, 4346, (145, 4343))
            tick(32010)
            vm.pc = 32014
            value = memory.load(cells.value(4346), 1)
            vm._write(4347, value, 4, 'high.load')
            tick(32014)
            vm.pc = 32019
            vm._write(4348, memory.load(cells.pointer(4347), 1, signed=True) ^ memory.load(cells.pointer(4345), 1, signed=True), 8, 'L14.binary_q')
            tick(32019)
            vm.pc = 32023
            pointer = cells.value(4346)
            value = memory.load(cells.pointer(4348), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(32023)
            vm.pc = 32024
            tick(32024)
            vm.pc = 32027
            vm.auxiliary = (0, 762638338)
            tick(32027)
            vm.pc = 32032
            vm._write(4341, memory.load(cells.pointer(4340), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(32032)
            vm.pc = 32034
            vm._jump(698)
            continue
        if vm.block == 700:
            tick(32034)
            vm.pc = 32039
            vm._write(4349, memory.load(cells.pointer(4276), 8, signed=True) & memory.load(cells.pointer(1732), 8, signed=True), 8, 'L13.binary_q')
            tick(32039)
            vm.pc = 32041
            vm._jump(701)
            continue
        if vm.block == 701:
            tick(32041)
            _phi(vm, 32041, (4350, 2, 145, 700, 4351, 702))
            tick(32048)
            vm.pc = 32053
            vm._write(4352, int(cells.value(4350) < cells.value(4349)), 4, 'once18.unsigned_q')
            tick(32053)
            vm.pc = 32057
            vm._jump(702 if cells.value(4352) != 0 else 703)
            continue
        if vm.block == 702:
            tick(32057)
            _pointer(vm, 32057, 1, 4277, 4353, (4350,))
            tick(32064)
            vm.pc = 32069
            cells.copy_q_clear_owned(4353, 4354)
            tick(32069)
            vm.pc = 32073
            value = memory.load(cells.value(4354), 4)
            vm._write(4355, value, 4, 'high.load')
            tick(32073)
            _pointer(vm, 32073, 1, 4267, 4356, (4350,))
            tick(32080)
            vm.pc = 32085
            cells.copy_q_clear_owned(4356, 4357)
            tick(32085)
            vm.pc = 32089
            pointer = cells.value(4357)
            value = memory.load(cells.pointer(4355), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(32089)
            vm.pc = 32090
            tick(32090)
            vm.pc = 32093
            vm.auxiliary = (0, 2018189314)
            tick(32093)
            vm.pc = 32098
            vm._write(4351, memory.load(cells.pointer(4350), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(32098)
            vm.pc = 32100
            vm._jump(701)
            continue
        if vm.block == 703:
            tick(32100)
            _phi(vm, 32100, (4358, 2, 4359, 704, 4349, 701))
            tick(32107)
            vm.pc = 32112
            vm._write(4360, int(cells.value(4358) < cells.value(4276)), 4, 'once18.unsigned_q')
            tick(32112)
            vm.pc = 32116
            vm._jump(704 if cells.value(4360) != 0 else 705)
            continue
        if vm.block == 704:
            tick(32116)
            _pointer(vm, 32116, 1, 4277, 4361, (4358,))
            tick(32123)
            vm.pc = 32127
            value = memory.load(cells.value(4361), 1)
            vm._write(4362, value, 4, 'high.load')
            tick(32127)
            _pointer(vm, 32127, 1, 4267, 4363, (4358,))
            tick(32134)
            vm.pc = 32138
            pointer = cells.value(4363)
            value = memory.load(cells.pointer(4362), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(32138)
            vm.pc = 32139
            tick(32139)
            vm.pc = 32142
            vm.auxiliary = (0, 815079425)
            tick(32142)
            vm.pc = 32147
            vm._write(4359, memory.load(cells.pointer(4358), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(32147)
            vm.pc = 32149
            vm._jump(703)
            continue
        if vm.block == 705:
            tick(32149)
            vm.pc = 32151
            vm._jump(706)
            continue
        if vm.block == 706:
            tick(32151)
            _phi(vm, 32151, (4364, 2, 184, 705, 4365, 707))
            tick(32158)
            _phi(vm, 32158, (4366, 2, 4277, 705, 4367, 707))
            tick(32165)
            vm.pc = 32166
            tick(32166)
            vm.pc = 32169
            vm.auxiliary = (0, 192048083)
            tick(32169)
            vm.pc = 32174
            vm._write(4368, int(memory.load(cells.pointer(4364), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(32174)
            vm.pc = 32178
            vm._jump(708 if cells.value(4368) != 0 else 707)
            continue
        if vm.block == 707:
            tick(32178)
            vm.pc = 32179
            tick(32179)
            vm.pc = 32182
            vm.auxiliary = (0, 1363480578)
            tick(32182)
            vm.pc = 32187
            vm._write(4365, memory.load(cells.pointer(4364), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(32187)
            _pointer(vm, 32187, 1, 4366, 4367, (163,))
            tick(32194)
            vm.pc = 32198
            pointer = cells.value(4366)
            value = memory.load(cells.pointer(235), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(32198)
            vm.pc = 32200
            vm._jump(706)
            continue
        if vm.block == 708:
            tick(32200)
            vm.pc = 32202
            vm._jump(709)
            continue
        if vm.block == 709:
            tick(32202)
            _phi(vm, 32202, (4369, 2, 184, 708, 4370, 710))
            tick(32209)
            _phi(vm, 32209, (4371, 2, 4309, 708, 4372, 710))
            tick(32216)
            vm.pc = 32217
            tick(32217)
            vm.pc = 32220
            vm.auxiliary = (0, 533888003)
            tick(32220)
            _equal(vm, 32225, 8, 4369, 145, 4373)
            tick(32225)
            vm.pc = 32229
            vm._jump(711 if cells.value(4373) != 0 else 710)
            continue
        if vm.block == 710:
            tick(32229)
            vm.pc = 32230
            tick(32230)
            vm.pc = 32233
            vm.auxiliary = (0, 1669632001)
            tick(32233)
            vm.pc = 32238
            vm._write(4370, memory.load(cells.pointer(4369), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(32238)
            _pointer(vm, 32238, 1, 4371, 4372, (163,))
            tick(32245)
            vm.pc = 32249
            pointer = cells.value(4371)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(32249)
            vm.pc = 32251
            vm._jump(709)
            continue
        if vm.block == 711:
            tick(32251)
            vm.pc = 32255
            value = memory.load(cells.value(17), 8)
            vm._write(4374, value, 8, 'high.load')
            tick(32255)
            vm.pc = 32257
            vm._jump(688)
            continue
        if vm.block == 688:
            tick(32257)
            _phi(vm, 32257, (4375, 3, 4374, 711, 145, 680, 145, 689))
            continue
        raise PrimarySemanticUnavailable('independent record consumer left its source-bound blocks')


def _seed_consumer(vm, tick):
    cells, memory = vm.cells, vm.memory
    while vm.pc != 37823:
        if vm.block == 826:
            tick(36986)
            _pointer(vm, 36986, 11, 41, 5006, (145, 158))
            tick(36994)
            vm.pc = 36998
            value = memory.load(cells.value(5006), 8)
            vm._write(5007, value, 8, 'L5.unsigned_load')
            tick(36998)
            vm.pc = 37002
            pointer = cells.value(39)
            value = memory.load(cells.pointer(5007), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(37002)
            _pointer(vm, 37002, 11, 41, 5008, (145, 269))
            tick(37010)
            vm.pc = 37014
            value = memory.load(cells.value(5008), 1)
            vm._write(5009, value, 4, 'high.load')
            tick(37014)
            _pointer(vm, 37014, 11, 41, 5010, (145, 311))
            tick(37022)
            vm.pc = 37026
            value = memory.load(cells.value(5010), 1)
            vm._write(5011, value, 4, 'high.load')
            tick(37026)
            vm.pc = 37031
            _convert(vm, 4, 5011, 5012)
            tick(37031)
            _switch(vm, 37031, (5011, 829, 4, 354, 830, 369, 830, 152, 830, 2188, 830))
            continue
        if vm.block == 830:
            tick(37043)
            vm.pc = 37044
            tick(37044)
            vm.pc = 37047
            vm.auxiliary = (0, 1044549619)
            tick(37047)
            _equal(vm, 37052, 1, 5009, 235, 5013)
            tick(37052)
            vm.pc = 37056
            vm._jump(829 if cells.value(5013) != 0 else 831)
            continue
        if vm.block == 831:
            tick(37056)
            vm.pc = 37061
            _convert(vm, 8, 5011, 5014)
            tick(37061)
            _pointer(vm, 37061, 41, 69, 5015, (145, 145))
            tick(37069)
            vm.pc = 37070
            tick(37070)
            vm.pc = 37073
            vm.auxiliary = (0, 49668)
            tick(37073)
            vm.pc = 37078
            vm._write(5016, memory.load(cells.pointer(5014), 8, signed=True) & memory.load(cells.pointer(1732), 8, signed=True), 8, 'typed.selector1.q')
            tick(37078)
            vm.pc = 37080
            vm._jump(832)
            continue
        if vm.block == 832:
            tick(37080)
            _phi(vm, 37080, (5017, 2, 145, 831, 5018, 833))
            tick(37087)
            vm.pc = 37092
            vm._write(5019, int(cells.value(5017) < cells.value(5016)), 4, 'once18.unsigned_q')
            tick(37092)
            vm.pc = 37096
            vm._jump(833 if cells.value(5019) != 0 else 834)
            continue
        if vm.block == 833:
            tick(37096)
            _pointer(vm, 37096, 1, 5002, 5020, (5017,))
            tick(37103)
            vm.pc = 37108
            cells.copy_q_clear_owned(5020, 5021)
            tick(37108)
            vm.pc = 37112
            value = memory.load(cells.value(5021), 4)
            vm._write(5022, value, 4, 'high.load')
            tick(37112)
            _pointer(vm, 37112, 1, 5015, 5023, (5017,))
            tick(37119)
            vm.pc = 37124
            cells.copy_q_clear_owned(5023, 5024)
            tick(37124)
            vm.pc = 37128
            pointer = cells.value(5024)
            value = memory.load(cells.pointer(5022), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(37128)
            vm.pc = 37129
            tick(37129)
            vm.pc = 37132
            vm.auxiliary = (0, 1212162050)
            tick(37132)
            vm.pc = 37137
            vm._write(5018, memory.load(cells.pointer(5017), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(37137)
            vm.pc = 37139
            vm._jump(832)
            continue
        if vm.block == 834:
            tick(37139)
            _phi(vm, 37139, (5025, 2, 5026, 835, 5016, 832))
            tick(37146)
            vm.pc = 37151
            vm._write(5027, int(cells.value(5025) < cells.value(5014)), 4, 'once18.unsigned_q')
            tick(37151)
            vm.pc = 37155
            vm._jump(835 if cells.value(5027) != 0 else 836)
            continue
        if vm.block == 835:
            tick(37155)
            _pointer(vm, 37155, 1, 5002, 5028, (5025,))
            tick(37162)
            vm.pc = 37166
            value = memory.load(cells.value(5028), 1)
            vm._write(5029, value, 4, 'high.load')
            tick(37166)
            _pointer(vm, 37166, 1, 5015, 5030, (5025,))
            tick(37173)
            vm.pc = 37177
            pointer = cells.value(5030)
            value = memory.load(cells.pointer(5029), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37177)
            vm.pc = 37178
            tick(37178)
            vm.pc = 37181
            vm.auxiliary = (0, 908472322)
            tick(37181)
            vm.pc = 37186
            vm._write(5026, memory.load(cells.pointer(5025), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(37186)
            vm.pc = 37188
            vm._jump(834)
            continue
        if vm.block == 836:
            tick(37188)
            vm.pc = 37193
            value = memory.load(cells.pointer(5009), 1)
            count = memory.load(cells.pointer(336), 1)
            vm._write(5031, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37193)
            vm.pc = 37198
            value = memory.load(cells.pointer(5009), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(5032, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37198)
            vm.pc = 37199
            tick(37199)
            vm.pc = 37202
            vm.auxiliary = (0, 43646)
            tick(37202)
            vm.pc = 37208
            vm._write(5033, memory.load(cells.pointer(5031), 1, signed=True) ^ memory.load(cells.pointer(5032), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(37208)
            vm.pc = 37213
            value = memory.load(cells.pointer(5009), 1)
            count = memory.load(cells.pointer(152), 1)
            vm._write(5034, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37213)
            vm.pc = 37218
            vm._write(5035, memory.load(cells.pointer(5033), 1, signed=True) ^ memory.load(cells.pointer(5034), 1, signed=True), 8, 'L14.binary_q')
            tick(37218)
            vm.pc = 37223
            value = memory.load(cells.pointer(5009), 1)
            count = memory.load(cells.pointer(497), 1)
            vm._write(5036, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37223)
            vm.pc = 37226
            vm.auxiliary = (0, 16254)
            tick(37226)
            vm.pc = 37232
            vm._write(5037, memory.load(cells.pointer(5035), 1, signed=True) ^ memory.load(cells.pointer(5036), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(37232)
            vm.pc = 37235
            vm.auxiliary = (0, 37684)
            tick(37235)
            vm.pc = 37240
            vm._write(5038, memory.load(cells.pointer(5037), 1, signed=True) & memory.load(cells.pointer(354), 1, signed=True), 8, 'typed.selector1.q')
            tick(37240)
            vm.pc = 37243
            vm.auxiliary = (0, 62631)
            tick(37243)
            _single_control(vm)
            vm.pc = 37248
            count = memory.load(cells.pointer(354), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(5009), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(5039, value, 4, 'typed.selector3.d')
            tick(37248)
            vm.pc = 37251
            vm.auxiliary = (0, 8881)
            tick(37251)
            vm.pc = 37256
            vm._write(5040, memory.load(cells.pointer(5039), 1, signed=True) | memory.load(cells.pointer(5038), 1, signed=True), 8, 'typed.selector2.q')
            tick(37256)
            vm.pc = 37259
            vm.auxiliary = (0, 36476)
            tick(37259)
            vm.pc = 37265
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5041, memory.load(cells.pointer(5040), 1, signed=True) ^ memory.load(cells.pointer(1645), 1, signed=True), 8, 'typed.selector5.q')
            tick(37265)
            vm.pc = 37268
            vm.auxiliary = (0, 4798)
            tick(37268)
            _single_control(vm)
            vm.pc = 37273
            count = memory.load(cells.pointer(497), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(5041), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(5042, value, 4, 'typed.selector3.d')
            tick(37273)
            vm.pc = 37278
            value = memory.load(cells.pointer(5041), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(5043, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37278)
            vm.pc = 37283
            vm._write(5044, memory.load(cells.pointer(5042), 1, signed=True) | memory.load(cells.pointer(5043), 1, signed=True), 8, 'L15.binary_q')
            tick(37283)
            vm.pc = 37286
            vm.auxiliary = (0, 238165043)
            tick(37286)
            vm.pc = 37291
            vm._write(5045, int(memory.load(cells.pointer(5044), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(37291)
            vm.pc = 37298
            selected = 2222 if cells.value(5045) != 0 else 5044
            vm._write(5046, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(37298)
            _pointer(vm, 37298, 41, 70, 5047, (145, 145))
            tick(37306)
            vm.pc = 37310
            pointer = cells.value(5047)
            value = memory.load(cells.pointer(5046), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37310)
            vm.pc = 37312
            vm._jump(837)
            continue
        if vm.block == 837:
            tick(37312)
            _phi(vm, 37312, (5048, 2, 269, 836, 5049, 838))
            tick(37319)
            vm.pc = 37324
            vm._write(5050, int(cells.value(5048) < cells.value(5012)), 4, 'once18.unsigned_q')
            tick(37324)
            vm.pc = 37328
            vm._jump(838 if cells.value(5050) != 0 else 839)
            continue
        if vm.block == 838:
            tick(37328)
            vm.pc = 37329
            tick(37329)
            vm.pc = 37332
            vm.auxiliary = (0, 252207106)
            tick(37332)
            vm.pc = 37337
            vm._write(5051, memory.load(cells.pointer(5048), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(37337)
            vm.pc = 37342
            _convert(vm, 8, 5051, 5052)
            tick(37342)
            _pointer(vm, 37342, 41, 70, 5053, (145, 5052))
            tick(37350)
            vm.pc = 37354
            value = memory.load(cells.value(5053), 1)
            vm._write(5054, value, 4, 'high.load')
            tick(37354)
            vm.pc = 37359
            value = memory.load(cells.pointer(5054), 1)
            count = memory.load(cells.pointer(336), 1)
            vm._write(5055, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37359)
            vm.pc = 37364
            value = memory.load(cells.pointer(5054), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(5056, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37364)
            vm.pc = 37367
            vm.auxiliary = (0, 7493)
            tick(37367)
            vm.pc = 37373
            vm._write(5057, memory.load(cells.pointer(5055), 1, signed=True) ^ memory.load(cells.pointer(5056), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(37373)
            vm.pc = 37378
            value = memory.load(cells.pointer(5054), 1)
            count = memory.load(cells.pointer(152), 1)
            vm._write(5058, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37378)
            vm.pc = 37381
            vm.auxiliary = (0, 7950)
            tick(37381)
            vm.pc = 37387
            vm._write(5059, memory.load(cells.pointer(5057), 1, signed=True) ^ memory.load(cells.pointer(5058), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(37387)
            vm.pc = 37392
            value = memory.load(cells.pointer(5054), 1)
            count = memory.load(cells.pointer(497), 1)
            vm._write(5060, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37392)
            vm.pc = 37395
            vm.auxiliary = (0, 44054)
            tick(37395)
            vm.pc = 37401
            vm._write(5061, memory.load(cells.pointer(5059), 1, signed=True) ^ memory.load(cells.pointer(5060), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(37401)
            vm.pc = 37406
            vm._write(5062, memory.load(cells.pointer(5061), 1, signed=True) & memory.load(cells.pointer(354), 1, signed=True), 8, 'L13.binary_q')
            tick(37406)
            vm.pc = 37409
            vm.auxiliary = (0, 12710)
            tick(37409)
            _single_control(vm)
            vm.pc = 37414
            count = memory.load(cells.pointer(354), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(5054), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(5063, value, 4, 'typed.selector3.d')
            tick(37414)
            vm.pc = 37419
            vm._write(5064, memory.load(cells.pointer(5063), 1, signed=True) | memory.load(cells.pointer(5062), 1, signed=True), 8, 'L15.binary_q')
            tick(37419)
            vm.pc = 37424
            vm._write(5065, cells.value(5048) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(37424)
            vm.pc = 37427
            vm.auxiliary = (0, 1476084227)
            tick(37427)
            vm.pc = 37432
            vm._write(5066, memory.load(cells.pointer(5065), 1, signed=True) * memory.load(cells.pointer(2243), 1, signed=True), 8, 'once0.integer')
            tick(37432)
            vm.pc = 37435
            vm.auxiliary = (0, 917467137)
            tick(37435)
            vm.pc = 37440
            vm._write(5067, memory.load(cells.pointer(5066), 1, signed=True) + memory.load(cells.pointer(1645), 1, signed=True), 8, 'once1.integer')
            tick(37440)
            vm.pc = 37443
            vm.auxiliary = (0, 15471)
            tick(37443)
            vm.pc = 37449
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5068, memory.load(cells.pointer(5067), 1, signed=True) ^ memory.load(cells.pointer(5064), 1, signed=True), 8, 'typed.selector5.q')
            tick(37449)
            vm.pc = 37452
            vm.auxiliary = (0, 42471)
            tick(37452)
            _single_control(vm)
            vm.pc = 37457
            count = memory.load(cells.pointer(497), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(5068), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(5069, value, 4, 'typed.selector3.d')
            tick(37457)
            vm.pc = 37462
            value = memory.load(cells.pointer(5068), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(5070, value >> (count & 31), 4, 'once8.logical_shift')
            tick(37462)
            vm.pc = 37465
            vm.auxiliary = (0, 34746)
            tick(37465)
            vm.pc = 37470
            vm._write(5071, memory.load(cells.pointer(5069), 1, signed=True) | memory.load(cells.pointer(5070), 1, signed=True), 8, 'typed.selector2.q')
            tick(37470)
            vm.pc = 37473
            vm.auxiliary = (0, 1801634451)
            tick(37473)
            vm.pc = 37478
            vm._write(5072, int(memory.load(cells.pointer(5071), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(37478)
            vm.pc = 37483
            vm._write(5073, cells.value(5048) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(37483)
            vm.pc = 37488
            vm._write(5074, memory.load(cells.pointer(5073), 1, signed=True) ^ memory.load(cells.pointer(2222), 1, signed=True), 8, 'L14.binary_q')
            tick(37488)
            vm.pc = 37495
            selected = 5074 if cells.value(5072) != 0 else 5071
            vm._write(5075, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(37495)
            vm.pc = 37500
            _convert(vm, 8, 5048, 5076)
            tick(37500)
            _pointer(vm, 37500, 41, 70, 5077, (145, 5076))
            tick(37508)
            vm.pc = 37512
            pointer = cells.value(5077)
            value = memory.load(cells.pointer(5075), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37512)
            vm.pc = 37515
            vm.auxiliary = (0, 1612115970)
            tick(37515)
            vm.pc = 37520
            vm._write(5049, memory.load(cells.pointer(5048), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(37520)
            vm.pc = 37522
            vm._jump(837)
            continue
        if vm.block == 839:
            tick(37522)
            _phi(vm, 37522, (5078, 2, 5079, 840, 158, 837))
            tick(37529)
            vm.pc = 37534
            vm._write(5080, int(cells.value(5078) < cells.value(5012)), 4, 'once18.unsigned_q')
            tick(37534)
            vm.pc = 37538
            vm._jump(840 if cells.value(5080) != 0 else 841)
            continue
        if vm.block == 840:
            tick(37538)
            vm.pc = 37543
            _convert(vm, 8, 5078, 5081)
            tick(37543)
            _pointer(vm, 37543, 41, 70, 5082, (145, 5081))
            tick(37551)
            vm.pc = 37555
            value = memory.load(cells.value(5082), 1)
            vm._write(5083, value, 4, 'high.load')
            tick(37555)
            _pointer(vm, 37555, 41, 69, 5084, (145, 5081))
            tick(37563)
            vm.pc = 37567
            value = memory.load(cells.value(5084), 1)
            vm._write(5085, value, 4, 'high.load')
            tick(37567)
            vm.pc = 37572
            vm._write(5086, memory.load(cells.pointer(5085), 1, signed=True) ^ memory.load(cells.pointer(5083), 1, signed=True), 8, 'L14.binary_q')
            tick(37572)
            vm.pc = 37576
            pointer = cells.value(5084)
            value = memory.load(cells.pointer(5086), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37576)
            vm.pc = 37577
            tick(37577)
            vm.pc = 37580
            vm.auxiliary = (0, 1422397441)
            tick(37580)
            vm.pc = 37585
            vm._write(5079, memory.load(cells.pointer(5078), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(37585)
            vm.pc = 37587
            vm._jump(839)
            continue
        if vm.block == 841:
            tick(37587)
            vm.pc = 37588
            tick(37588)
            vm.pc = 37591
            vm.auxiliary = (0, 53596)
            tick(37591)
            vm.pc = 37596
            vm._write(5087, memory.load(cells.pointer(5014), 8, signed=True) & memory.load(cells.pointer(1732), 8, signed=True), 8, 'typed.selector1.q')
            tick(37596)
            vm.pc = 37598
            vm._jump(842)
            continue
        if vm.block == 842:
            tick(37598)
            _phi(vm, 37598, (5088, 2, 145, 841, 5089, 843))
            tick(37605)
            vm.pc = 37610
            vm._write(5090, int(cells.value(5088) < cells.value(5087)), 4, 'once18.unsigned_q')
            tick(37610)
            vm.pc = 37614
            vm._jump(843 if cells.value(5090) != 0 else 844)
            continue
        if vm.block == 843:
            tick(37614)
            _pointer(vm, 37614, 1, 5015, 5091, (5088,))
            tick(37621)
            vm.pc = 37626
            cells.copy_q_clear_owned(5091, 5092)
            tick(37626)
            vm.pc = 37630
            value = memory.load(cells.value(5092), 4)
            vm._write(5093, value, 4, 'high.load')
            tick(37630)
            _pointer(vm, 37630, 1, 5005, 5094, (5088,))
            tick(37637)
            vm.pc = 37642
            cells.copy_q_clear_owned(5094, 5095)
            tick(37642)
            vm.pc = 37646
            pointer = cells.value(5095)
            value = memory.load(cells.pointer(5093), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(37646)
            vm.pc = 37647
            tick(37647)
            vm.pc = 37650
            vm.auxiliary = (0, 817885186)
            tick(37650)
            vm.pc = 37655
            vm._write(5089, memory.load(cells.pointer(5088), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(37655)
            vm.pc = 37657
            vm._jump(842)
            continue
        if vm.block == 844:
            tick(37657)
            _phi(vm, 37657, (5096, 2, 5097, 845, 5087, 842))
            tick(37664)
            vm.pc = 37669
            vm._write(5098, int(cells.value(5096) < cells.value(5014)), 4, 'once18.unsigned_q')
            tick(37669)
            vm.pc = 37673
            vm._jump(845 if cells.value(5098) != 0 else 846)
            continue
        if vm.block == 845:
            tick(37673)
            _pointer(vm, 37673, 1, 5015, 5099, (5096,))
            tick(37680)
            vm.pc = 37684
            value = memory.load(cells.value(5099), 1)
            vm._write(5100, value, 4, 'high.load')
            tick(37684)
            _pointer(vm, 37684, 1, 5005, 5101, (5096,))
            tick(37691)
            vm.pc = 37695
            pointer = cells.value(5101)
            value = memory.load(cells.pointer(5100), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37695)
            vm.pc = 37696
            tick(37696)
            vm.pc = 37699
            vm.auxiliary = (0, 764846081)
            tick(37699)
            vm.pc = 37704
            vm._write(5097, memory.load(cells.pointer(5096), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(37704)
            vm.pc = 37706
            vm._jump(844)
            continue
        if vm.block == 846:
            tick(37706)
            vm.pc = 37708
            vm._jump(847)
            continue
        if vm.block == 847:
            tick(37708)
            _phi(vm, 37708, (5102, 2, 184, 846, 5103, 848))
            tick(37715)
            _phi(vm, 37715, (5104, 2, 5015, 846, 5105, 848))
            tick(37722)
            vm.pc = 37723
            tick(37723)
            vm.pc = 37726
            vm.auxiliary = (0, 1892818995)
            tick(37726)
            vm.pc = 37731
            vm._write(5106, int(memory.load(cells.pointer(5102), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(37731)
            vm.pc = 37735
            vm._jump(849 if cells.value(5106) != 0 else 848)
            continue
        if vm.block == 848:
            tick(37735)
            vm.pc = 37736
            tick(37736)
            vm.pc = 37739
            vm.auxiliary = (0, 1621995522)
            tick(37739)
            vm.pc = 37744
            vm._write(5103, memory.load(cells.pointer(5102), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(37744)
            _pointer(vm, 37744, 1, 5104, 5105, (163,))
            tick(37751)
            vm.pc = 37755
            pointer = cells.value(5104)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37755)
            vm.pc = 37757
            vm._jump(847)
            continue
        if vm.block == 849:
            tick(37757)
            vm.pc = 37759
            vm._jump(850)
            continue
        if vm.block == 850:
            tick(37759)
            _phi(vm, 37759, (5107, 2, 184, 849, 5108, 851))
            tick(37766)
            _phi(vm, 37766, (5109, 2, 5047, 849, 5110, 851))
            tick(37773)
            vm.pc = 37774
            tick(37774)
            vm.pc = 37777
            vm.auxiliary = (0, 1652729811)
            tick(37777)
            _equal(vm, 37782, 8, 5107, 145, 5111)
            tick(37782)
            vm.pc = 37786
            vm._jump(852 if cells.value(5111) != 0 else 851)
            continue
        if vm.block == 851:
            tick(37786)
            vm.pc = 37787
            tick(37787)
            vm.pc = 37790
            vm.auxiliary = (0, 404844545)
            tick(37790)
            vm.pc = 37795
            vm._write(5108, memory.load(cells.pointer(5107), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(37795)
            _pointer(vm, 37795, 1, 5109, 5110, (163,))
            tick(37802)
            vm.pc = 37806
            pointer = cells.value(5109)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37806)
            vm.pc = 37808
            vm._jump(850)
            continue
        if vm.block == 852:
            tick(37808)
            vm.pc = 37812
            value = memory.load(cells.value(40), 8)
            vm._write(5112, value, 8, 'high.load')
            tick(37812)
            vm.pc = 37814
            vm._jump(829)
            continue
        if vm.block == 829:
            tick(37814)
            _phi(vm, 37814, (5113, 3, 5112, 852, 145, 826, 145, 830))
            continue
        raise PrimarySemanticUnavailable('independent record consumer left its source-bound blocks')


def _material_provider(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(8, 4)
            tick(4)
            vm.pc = 7
            vm._allocate(2, 5)
            tick(7)
            vm.pc = 10
            vm._allocate(8, 6)
            tick(10)
            vm.pc = 13
            vm._allocate(11, 7)
            tick(13)
            vm.pc = 16
            vm._allocate(1, 8)
            tick(16)
            vm.pc = 19
            vm._allocate(11, 9)
            tick(19)
            vm.pc = 25
            _provider_host(vm, 19, 11, (), 28, 10)
            tick(25)
            vm.pc = 30
            cells.copy_q_clear_owned(4, 12)
            tick(30)
            vm.pc = 35
            cells.copy_q_clear_owned(6, 13)
            tick(35)
            vm.pc = 40
            cells.copy_q_clear_owned(7, 14)
            tick(40)
            vm.pc = 45
            cells.copy_q_clear_owned(8, 15)
            tick(45)
            vm.pc = 49
            pointer = cells.value(8)
            value = memory.load(cells.pointer(16), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(49)
            _pointer(vm, 49, 3, 0, 17, (18, 18))
            tick(57)
            vm.pc = 61
            pointer = cells.value(17)
            value = memory.load(cells.pointer(16), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(61)
            _pointer(vm, 61, 3, 0, 19, (18, 20))
            tick(69)
            vm.pc = 73
            pointer = cells.value(19)
            value = memory.load(cells.pointer(21), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(73)
            _pointer(vm, 73, 3, 0, 22, (18, 23))
            tick(81)
            vm.pc = 85
            pointer = cells.value(22)
            value = memory.load(cells.pointer(21), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(85)
            vm.pc = 86
            tick(86)
            vm.pc = 89
            vm.auxiliary = (0, 1797394740)
            tick(89)
            vm.pc = 94
            vm._write(24, int(memory.load(cells.pointer(3), 4, signed=True) != memory.load(cells.pointer(20), 4, signed=True)), 4, 'L30.comparison')
            tick(94)
            vm.pc = 97
            vm.auxiliary = (0, 882011796)
            tick(97)
            vm.pc = 102
            vm._write(25, int(memory.load(cells.pointer(3), 4, signed=True) != memory.load(cells.pointer(23), 4, signed=True)), 4, 'L27.comparison')
            tick(102)
            vm.pc = 105
            vm.auxiliary = (0, 12374)
            tick(105)
            vm.pc = 110
            vm._write(26, memory.load(cells.pointer(24), 1, signed=True) & memory.load(cells.pointer(25), 1, signed=True), 8, 'typed.selector1.q')
            tick(110)
            vm.pc = 113
            vm.auxiliary = (0, 1607661332)
            tick(113)
            vm.pc = 118
            vm._write(28, int(memory.load(cells.pointer(3), 4, signed=True) != memory.load(cells.pointer(27), 4, signed=True)), 4, 'L30.comparison')
            tick(118)
            vm.pc = 123
            vm._write(29, memory.load(cells.pointer(26), 1, signed=True) & memory.load(cells.pointer(28), 1, signed=True), 8, 'L13.binary_q')
            tick(123)
            vm.pc = 126
            vm.auxiliary = (0, 721604740)
            tick(126)
            vm.pc = 131
            vm._write(31, int(memory.load(cells.pointer(3), 4, signed=True) != memory.load(cells.pointer(30), 4, signed=True)), 4, 'L27.comparison')
            tick(131)
            vm.pc = 136
            vm._write(32, memory.load(cells.pointer(29), 1, signed=True) & memory.load(cells.pointer(31), 1, signed=True), 8, 'L13.binary_q')
            tick(136)
            vm.pc = 140
            vm._jump(1 if cells.value(32) != 0 else 2)
            continue
        if vm.block == 1:
            tick(140)
            vm.pc = 142
            vm._jump(3)
            continue
        if vm.block == 2:
            tick(142)
            vm.pc = 143
            tick(143)
            vm.pc = 146
            vm.auxiliary = (0, 1170751490)
            tick(146)
            vm.pc = 151
            vm._write(33, memory.load(cells.pointer(2), 4, signed=True) + memory.load(cells.pointer(3), 4, signed=True), 8, 'once1.integer')
            tick(151)
            vm.pc = 156
            vm._write(35, int(cells.value(33) > cells.value(34)), 4, 'L31.comparison')
            tick(156)
            vm.pc = 160
            vm._jump(4 if cells.value(35) != 0 else 5)
            continue
        if vm.block == 4:
            tick(160)
            vm.pc = 162
            vm._jump(3)
            continue
        if vm.block == 5:
            tick(162)
            _pointer(vm, 162, 8, 4, 36, (16, 16))
            tick(170)
            vm.pc = 174
            vm._jump(6 if cells.value(37) != 0 else 7)
            continue
        if vm.block == 6:
            tick(174)
            vm.pc = 176
            vm._jump(8)
            continue
        if vm.block == 8:
            tick(176)
            _phi(vm, 176, (38, 2, 36, 6, 39, 9))
            tick(183)
            _phi(vm, 183, (40, 2, 41, 6, 42, 9))
            tick(190)
            vm.pc = 191
            tick(191)
            vm.pc = 194
            vm.auxiliary = (0, 1722007554)
            tick(194)
            vm.pc = 199
            vm._write(42, memory.load(cells.pointer(40), 8, signed=True) + memory.load(cells.pointer(43), 8, signed=True), 8, 'once1.integer')
            tick(199)
            vm.pc = 204
            vm._write(44, int(cells.value(40) > cells.value(16)), 4, 'L31.comparison')
            tick(204)
            vm.pc = 208
            vm._jump(9 if cells.value(44) != 0 else 10)
            continue
        if vm.block == 9:
            tick(208)
            _pointer(vm, 208, 2, 38, 39, (20,))
            tick(215)
            vm.pc = 219
            pointer = cells.value(38)
            value = memory.load(cells.pointer(21), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(219)
            vm.pc = 221
            vm._jump(8)
            continue
        if vm.block == 10:
            tick(221)
            vm.pc = 223
            vm._jump(7)
            continue
        if vm.block == 7:
            tick(223)
            _pointer(vm, 223, 11, 7, 45, (16, 16))
            tick(231)
            vm.pc = 235
            vm._jump(11 if cells.value(37) != 0 else 12)
            continue
        if vm.block == 11:
            tick(235)
            vm.pc = 237
            vm._jump(13)
            continue
        if vm.block == 13:
            tick(237)
            _phi(vm, 237, (46, 2, 45, 11, 47, 14))
            tick(244)
            _phi(vm, 244, (48, 2, 49, 11, 50, 14))
            tick(251)
            vm.pc = 252
            tick(252)
            vm.pc = 255
            vm.auxiliary = (0, 1516998657)
            tick(255)
            vm.pc = 260
            vm._write(50, memory.load(cells.pointer(48), 8, signed=True) + memory.load(cells.pointer(43), 8, signed=True), 8, 'once1.integer')
            tick(260)
            vm.pc = 265
            vm._write(51, int(cells.value(48) > cells.value(16)), 4, 'L31.comparison')
            tick(265)
            vm.pc = 269
            vm._jump(14 if cells.value(51) != 0 else 15)
            continue
        if vm.block == 14:
            tick(269)
            _pointer(vm, 269, 2, 46, 47, (20,))
            tick(276)
            vm.pc = 280
            pointer = cells.value(46)
            value = memory.load(cells.pointer(21), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(280)
            vm.pc = 282
            vm._jump(13)
            continue
        if vm.block == 15:
            tick(282)
            vm.pc = 284
            vm._jump(12)
            continue
        if vm.block == 12:
            tick(284)
            vm.pc = 290
            _provider_host(vm, 284, 52, (10,), 31, None)
            tick(290)
            vm.pc = 291
            tick(291)
            vm.pc = 294
            vm.auxiliary = (0, 1175613620)
            tick(294)
            vm.pc = 299
            vm._write(53, int(memory.load(cells.pointer(1), 1, signed=True) != memory.load(cells.pointer(21), 1, signed=True)), 4, 'L27.comparison')
            tick(299)
            _pointer(vm, 299, 26, 10, 54, (18, 20))
            tick(307)
            _pointer(vm, 307, 26, 10, 55, (18, 23))
            tick(315)
            vm.pc = 322
            selected = 54 if cells.value(53) != 0 else 55
            vm._write(56, memory.load(cells.pointer(selected), 8, signed=True), 8, 'L7.selected_q')
            tick(322)
            _pointer(vm, 322, 8, 56, 57, (16, 16))
            tick(330)
            vm.pc = 334
            vm._jump(16 if cells.value(53) != 0 else 17)
            continue
        if vm.block == 16:
            tick(334)
            _pointer(vm, 334, 26, 10, 58, (18, 59))
            tick(342)
            vm.pc = 346
            value = memory.load(cells.value(58), 1)
            vm._write(60, value, 4, 'high.load')
            tick(346)
            vm.pc = 348
            vm._jump(18)
            continue
        if vm.block == 17:
            tick(348)
            _pointer(vm, 348, 26, 10, 61, (18, 27))
            tick(356)
            vm.pc = 360
            value = memory.load(cells.value(61), 1)
            vm._write(62, value, 4, 'high.load')
            tick(360)
            vm.pc = 362
            vm._jump(18)
            continue
        if vm.block == 18:
            tick(362)
            _phi(vm, 362, (63, 2, 60, 16, 62, 17))
            tick(369)
            vm.pc = 374
            _convert(vm, 4, 63, 64)
            tick(374)
            vm.pc = 375
            tick(375)
            vm.pc = 378
            vm.auxiliary = (0, 44370)
            tick(378)
            vm.pc = 383
            count = memory.load(cells.pointer(65), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(64), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(66, value, 4, 'typed.selector4.d')
            tick(383)
            vm.pc = 386
            vm.auxiliary = (0, 6264)
            tick(386)
            vm.pc = 391
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(64), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(68, value, 4, 'typed.selector4.d')
            tick(391)
            vm.pc = 394
            vm.auxiliary = (0, 35087)
            tick(394)
            vm.pc = 400
            vm._write(69, memory.load(cells.pointer(66), 4, signed=True) ^ memory.load(cells.pointer(68), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(400)
            vm.pc = 403
            vm.auxiliary = (0, 19520)
            tick(403)
            vm.pc = 408
            count = memory.load(cells.pointer(27), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(64), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(70, value, 4, 'typed.selector4.d')
            tick(408)
            vm.pc = 411
            vm.auxiliary = (0, 59751)
            tick(411)
            vm.pc = 417
            vm._write(71, memory.load(cells.pointer(69), 4, signed=True) ^ memory.load(cells.pointer(70), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(417)
            vm.pc = 420
            vm.auxiliary = (0, 23352)
            tick(420)
            vm.pc = 425
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(64), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(72, value, 4, 'typed.selector4.d')
            tick(425)
            vm.pc = 428
            vm.auxiliary = (0, 18813)
            tick(428)
            vm.pc = 434
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(73, memory.load(cells.pointer(71), 4, signed=True) ^ memory.load(cells.pointer(72), 4, signed=True), 8, 'typed.selector5.q')
            tick(434)
            vm.pc = 437
            vm.auxiliary = (0, 9076)
            tick(437)
            vm.pc = 442
            vm._write(74, memory.load(cells.pointer(73), 4, signed=True) & memory.load(cells.pointer(20), 4, signed=True), 8, 'typed.selector1.q')
            tick(442)
            vm.pc = 447
            vm._write(75, cells.value(74) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(447)
            vm.pc = 450
            vm.auxiliary = (0, 32933)
            tick(450)
            _single_control(vm)
            vm.pc = 455
            count = memory.load(cells.pointer(20), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(64), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(76, value, 4, 'typed.selector3.d')
            tick(455)
            vm.pc = 460
            _convert(vm, 4, 75, 77)
            tick(460)
            vm.pc = 465
            vm._write(78, memory.load(cells.pointer(76), 4, signed=True) | memory.load(cells.pointer(77), 4, signed=True), 8, 'L15.binary_q')
            tick(465)
            vm.pc = 470
            vm._write(79, cells.value(78) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(470)
            vm.pc = 475
            _convert(vm, 4, 79, 80)
            tick(475)
            vm.pc = 478
            vm.auxiliary = (0, 39478)
            tick(478)
            vm.pc = 484
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(82, memory.load(cells.pointer(80), 4, signed=True) ^ memory.load(cells.pointer(81), 4, signed=True), 8, 'typed.selector5.q')
            tick(484)
            vm.pc = 489
            vm._write(83, cells.value(82) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(489)
            vm.pc = 494
            _convert(vm, 4, 83, 84)
            tick(494)
            vm.pc = 497
            vm.auxiliary = (0, 62383)
            tick(497)
            _single_control(vm)
            vm.pc = 502
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(84), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(85, value, 4, 'typed.selector3.d')
            tick(502)
            vm.pc = 505
            vm.auxiliary = (0, 15635)
            tick(505)
            vm.pc = 510
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(84), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(86, value, 4, 'typed.selector4.d')
            tick(510)
            vm.pc = 515
            vm._write(87, memory.load(cells.pointer(85), 4, signed=True) | memory.load(cells.pointer(86), 4, signed=True), 8, 'L15.binary_q')
            tick(515)
            vm.pc = 520
            vm._write(88, cells.value(87) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(520)
            vm.pc = 523
            vm.auxiliary = (0, 1786944292)
            tick(523)
            vm.pc = 528
            vm._write(89, int(memory.load(cells.pointer(88), 1, signed=True) != memory.load(cells.pointer(21), 1, signed=True)), 4, 'L30.comparison')
            tick(528)
            vm.pc = 535
            selected = 88 if cells.value(89) != 0 else 90
            vm._write(91, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(535)
            _pointer(vm, 535, 8, 6, 92, (16, 16))
            tick(543)
            vm.pc = 547
            pointer = cells.value(92)
            value = memory.load(cells.pointer(91), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(547)
            vm.pc = 549
            vm._jump(19)
            continue
        if vm.block == 19:
            tick(549)
            _phi(vm, 549, (93, 2, 94, 18, 95, 20))
            tick(556)
            vm.pc = 561
            _convert(vm, 4, 93, 96)
            tick(561)
            vm.pc = 562
            tick(562)
            vm.pc = 565
            vm.auxiliary = (0, 522352165)
            tick(565)
            vm.pc = 570
            a = memory.load(cells.pointer(96), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(34), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(97, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(570)
            vm.pc = 574
            vm._jump(20 if cells.value(97) != 0 else 21)
            continue
        if vm.block == 20:
            tick(574)
            vm.pc = 575
            tick(575)
            vm.pc = 578
            vm.auxiliary = (0, 24602)
            tick(578)
            vm.pc = 583
            vm._write(98, memory.load(cells.pointer(96), 4, signed=True) - memory.load(cells.pointer(20), 4, signed=True), 8, 'typed.selector0.q')
            tick(583)
            vm.pc = 588
            cells.copy_q_clear_owned(98, 99)
            tick(588)
            _pointer(vm, 588, 8, 6, 100, (16, 99))
            tick(596)
            vm.pc = 600
            value = memory.load(cells.value(100), 1)
            vm._write(101, value, 4, 'high.load')
            tick(600)
            vm.pc = 605
            _convert(vm, 4, 101, 102)
            tick(605)
            vm.pc = 608
            vm.auxiliary = (0, 22867)
            tick(608)
            vm.pc = 613
            count = memory.load(cells.pointer(65), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(102), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(103, value, 4, 'typed.selector4.d')
            tick(613)
            vm.pc = 616
            vm.auxiliary = (0, 55658)
            tick(616)
            vm.pc = 621
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(102), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(104, value, 4, 'typed.selector4.d')
            tick(621)
            vm.pc = 626
            vm._write(105, memory.load(cells.pointer(103), 4, signed=True) ^ memory.load(cells.pointer(104), 4, signed=True), 8, 'L14.binary_q')
            tick(626)
            vm.pc = 629
            vm.auxiliary = (0, 32611)
            tick(629)
            vm.pc = 634
            count = memory.load(cells.pointer(27), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(102), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(106, value, 4, 'typed.selector4.d')
            tick(634)
            vm.pc = 637
            vm.auxiliary = (0, 52591)
            tick(637)
            vm.pc = 643
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(107, memory.load(cells.pointer(105), 4, signed=True) ^ memory.load(cells.pointer(106), 4, signed=True), 8, 'typed.selector5.q')
            tick(643)
            vm.pc = 646
            vm.auxiliary = (0, 23882)
            tick(646)
            vm.pc = 651
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(102), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(108, value, 4, 'typed.selector4.d')
            tick(651)
            vm.pc = 656
            vm._write(109, memory.load(cells.pointer(107), 4, signed=True) ^ memory.load(cells.pointer(108), 4, signed=True), 8, 'L14.binary_q')
            tick(656)
            vm.pc = 661
            vm._write(110, memory.load(cells.pointer(109), 4, signed=True) & memory.load(cells.pointer(20), 4, signed=True), 8, 'L13.binary_q')
            tick(661)
            vm.pc = 666
            vm._write(111, cells.value(110) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(666)
            vm.pc = 669
            vm.auxiliary = (0, 9173)
            tick(669)
            _single_control(vm)
            vm.pc = 674
            count = memory.load(cells.pointer(20), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(102), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(112, value, 4, 'typed.selector3.d')
            tick(674)
            vm.pc = 679
            _convert(vm, 4, 111, 113)
            tick(679)
            vm.pc = 684
            vm._write(114, memory.load(cells.pointer(112), 4, signed=True) | memory.load(cells.pointer(113), 4, signed=True), 8, 'L15.binary_q')
            tick(684)
            vm.pc = 689
            vm._write(115, cells.value(114) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(689)
            vm.pc = 692
            vm.auxiliary = (0, 1008472580)
            tick(692)
            vm.pc = 697
            vm._write(117, memory.load(cells.pointer(96), 4, signed=True) * memory.load(cells.pointer(116), 4, signed=True), 8, 'once0.integer')
            tick(697)
            vm.pc = 700
            vm.auxiliary = (0, 1562222593)
            tick(700)
            vm.pc = 705
            vm._write(118, memory.load(cells.pointer(117), 4, signed=True) + memory.load(cells.pointer(81), 4, signed=True), 8, 'once1.integer')
            tick(705)
            vm.pc = 710
            vm._write(119, cells.value(118) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(710)
            vm.pc = 715
            _convert(vm, 4, 119, 120)
            tick(715)
            vm.pc = 720
            _convert(vm, 4, 115, 121)
            tick(720)
            vm.pc = 723
            vm.auxiliary = (0, 16148)
            tick(723)
            vm.pc = 729
            vm._write(122, memory.load(cells.pointer(121), 4, signed=True) ^ memory.load(cells.pointer(120), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(729)
            vm.pc = 734
            vm._write(123, cells.value(122) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(734)
            vm.pc = 739
            _convert(vm, 4, 123, 124)
            tick(739)
            vm.pc = 742
            vm.auxiliary = (0, 54733)
            tick(742)
            _single_control(vm)
            vm.pc = 747
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(124), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(125, value, 4, 'typed.selector3.d')
            tick(747)
            vm.pc = 750
            vm.auxiliary = (0, 27001)
            tick(750)
            vm.pc = 755
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(124), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(126, value, 4, 'typed.selector4.d')
            tick(755)
            vm.pc = 760
            vm._write(127, memory.load(cells.pointer(125), 4, signed=True) | memory.load(cells.pointer(126), 4, signed=True), 8, 'L15.binary_q')
            tick(760)
            vm.pc = 765
            vm._write(128, cells.value(127) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(765)
            vm.pc = 768
            vm.auxiliary = (0, 1126316180)
            tick(768)
            vm.pc = 773
            vm._write(129, int(memory.load(cells.pointer(128), 1, signed=True) != memory.load(cells.pointer(21), 1, signed=True)), 4, 'L30.comparison')
            tick(773)
            vm.pc = 776
            vm.auxiliary = (0, 6254)
            tick(776)
            vm.pc = 782
            vm._write(131, memory.load(cells.pointer(96), 4, signed=True) ^ memory.load(cells.pointer(130), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(782)
            vm.pc = 787
            vm._write(132, cells.value(131) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(787)
            vm.pc = 794
            selected = 128 if cells.value(129) != 0 else 132
            vm._write(133, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(794)
            vm.pc = 799
            _convert(vm, 8, 93, 134)
            tick(799)
            _pointer(vm, 799, 8, 6, 135, (16, 134))
            tick(807)
            vm.pc = 811
            pointer = cells.value(135)
            value = memory.load(cells.pointer(133), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(811)
            vm.pc = 814
            vm.auxiliary = (0, 2065965057)
            tick(814)
            vm.pc = 819
            vm._write(95, memory.load(cells.pointer(93), 1, signed=True) + memory.load(cells.pointer(94), 1, signed=True), 8, 'once1.integer')
            tick(819)
            vm.pc = 821
            vm._jump(19)
            continue
        if vm.block == 21:
            tick(821)
            vm.pc = 823
            vm._jump(22)
            continue
        if vm.block == 22:
            tick(823)
            _phi(vm, 823, (136, 2, 18, 21, 137, 23))
            tick(830)
            vm.pc = 835
            vm._write(138, int(cells.value(136) < cells.value(34)), 4, 'once18.unsigned_q')
            tick(835)
            vm.pc = 839
            vm._jump(23 if cells.value(138) != 0 else 24)
            continue
        if vm.block == 23:
            tick(839)
            vm.pc = 844
            _convert(vm, 8, 136, 139)
            tick(844)
            _pointer(vm, 844, 2, 57, 140, (139,))
            tick(851)
            vm.pc = 855
            value = memory.load(cells.value(140), 1)
            vm._write(141, value, 4, 'high.load')
            tick(855)
            _pointer(vm, 855, 26, 10, 142, (18, 18))
            tick(863)
            vm.pc = 868
            _convert(vm, 8, 141, 143)
            tick(868)
            _pointer(vm, 868, 17, 142, 144, (16, 143))
            tick(876)
            _pointer(vm, 876, 16, 144, 145, (18, 20))
            tick(884)
            vm.pc = 888
            value = memory.load(cells.value(145), 1)
            vm._write(146, value, 4, 'high.load')
            tick(888)
            vm.pc = 893
            _convert(vm, 4, 146, 147)
            tick(893)
            _pointer(vm, 893, 8, 6, 148, (16, 139))
            tick(901)
            vm.pc = 905
            value = memory.load(cells.value(148), 1)
            vm._write(149, value, 4, 'high.load')
            tick(905)
            vm.pc = 910
            _convert(vm, 4, 149, 150)
            tick(910)
            vm.pc = 911
            tick(911)
            vm.pc = 914
            vm.auxiliary = (0, 43628)
            tick(914)
            vm.pc = 920
            vm._write(151, memory.load(cells.pointer(147), 4, signed=True) ^ memory.load(cells.pointer(150), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(920)
            vm.pc = 925
            vm._write(152, cells.value(151) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(925)
            _pointer(vm, 925, 8, 4, 153, (16, 139))
            tick(933)
            vm.pc = 937
            pointer = cells.value(153)
            value = memory.load(cells.pointer(152), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(937)
            vm.pc = 940
            vm.auxiliary = (0, 517144578)
            tick(940)
            vm.pc = 945
            vm._write(137, memory.load(cells.pointer(136), 4, signed=True) + memory.load(cells.pointer(20), 4, signed=True), 8, 'once1.integer')
            tick(945)
            vm.pc = 947
            vm._jump(22)
            continue
        if vm.block == 24:
            tick(947)
            vm.pc = 952
            cells.copy_q_clear_owned(5, 154)
            tick(952)
            vm.pc = 953
            tick(953)
            vm.pc = 956
            vm.auxiliary = (0, 53877)
            tick(956)
            vm.pc = 961
            vm._write(156, memory.load(cells.pointer(154), 8, signed=True) & memory.load(cells.pointer(155), 8, signed=True), 8, 'typed.selector1.q')
            tick(961)
            vm.pc = 966
            vm._write(157, cells.value(156) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(966)
            _pointer(vm, 966, 26, 10, 158, (18, 67))
            tick(974)
            vm.pc = 978
            value = memory.load(cells.value(158), 1)
            vm._write(159, value, 4, 'high.load')
            tick(978)
            vm.pc = 983
            _convert(vm, 4, 159, 160)
            tick(983)
            vm.pc = 988
            _convert(vm, 4, 157, 161)
            tick(988)
            vm.pc = 991
            vm.auxiliary = (0, 22582)
            tick(991)
            vm.pc = 997
            vm._write(162, memory.load(cells.pointer(161), 4, signed=True) ^ memory.load(cells.pointer(160), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(997)
            vm.pc = 1002
            vm._write(163, cells.value(162) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1002)
            vm.pc = 1007
            _convert(vm, 4, 163, 164)
            tick(1007)
            vm.pc = 1010
            vm.auxiliary = (0, 28179)
            tick(1010)
            vm.pc = 1015
            count = memory.load(cells.pointer(65), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(164), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(165, value, 4, 'typed.selector4.d')
            tick(1015)
            vm.pc = 1018
            vm.auxiliary = (0, 30752)
            tick(1018)
            vm.pc = 1023
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(164), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(166, value, 4, 'typed.selector4.d')
            tick(1023)
            vm.pc = 1028
            vm._write(167, memory.load(cells.pointer(165), 4, signed=True) ^ memory.load(cells.pointer(166), 4, signed=True), 8, 'L14.binary_q')
            tick(1028)
            vm.pc = 1031
            vm.auxiliary = (0, 18795)
            tick(1031)
            vm.pc = 1036
            count = memory.load(cells.pointer(27), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(164), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(168, value, 4, 'typed.selector4.d')
            tick(1036)
            vm.pc = 1039
            vm.auxiliary = (0, 36156)
            tick(1039)
            vm.pc = 1045
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(169, memory.load(cells.pointer(167), 4, signed=True) ^ memory.load(cells.pointer(168), 4, signed=True), 8, 'typed.selector5.q')
            tick(1045)
            vm.pc = 1048
            vm.auxiliary = (0, 59907)
            tick(1048)
            vm.pc = 1053
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(164), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(170, value, 4, 'typed.selector4.d')
            tick(1053)
            vm.pc = 1056
            vm.auxiliary = (0, 22556)
            tick(1056)
            vm.pc = 1062
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(171, memory.load(cells.pointer(169), 4, signed=True) ^ memory.load(cells.pointer(170), 4, signed=True), 8, 'typed.selector5.q')
            tick(1062)
            vm.pc = 1067
            vm._write(172, memory.load(cells.pointer(171), 4, signed=True) & memory.load(cells.pointer(20), 4, signed=True), 8, 'L13.binary_q')
            tick(1067)
            vm.pc = 1072
            vm._write(173, cells.value(172) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1072)
            vm.pc = 1075
            vm.auxiliary = (0, 54941)
            tick(1075)
            _single_control(vm)
            vm.pc = 1080
            count = memory.load(cells.pointer(20), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(164), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(174, value, 4, 'typed.selector3.d')
            tick(1080)
            vm.pc = 1085
            _convert(vm, 4, 173, 175)
            tick(1085)
            vm.pc = 1088
            vm.auxiliary = (0, 21139)
            tick(1088)
            vm.pc = 1093
            vm._write(176, memory.load(cells.pointer(174), 4, signed=True) | memory.load(cells.pointer(175), 4, signed=True), 8, 'typed.selector2.q')
            tick(1093)
            vm.pc = 1098
            vm._write(177, cells.value(176) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1098)
            vm.pc = 1101
            vm.auxiliary = (0, 65069)
            tick(1101)
            vm.pc = 1107
            vm._write(179, memory.load(cells.pointer(160), 4, signed=True) ^ memory.load(cells.pointer(178), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1107)
            vm.pc = 1112
            vm._write(180, cells.value(179) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1112)
            vm.pc = 1117
            _convert(vm, 4, 180, 181)
            tick(1117)
            vm.pc = 1120
            vm.auxiliary = (0, 857055747)
            tick(1120)
            vm.pc = 1125
            vm._write(182, memory.load(cells.pointer(181), 4, signed=True) * memory.load(cells.pointer(116), 4, signed=True), 8, 'once0.integer')
            tick(1125)
            vm.pc = 1128
            vm.auxiliary = (0, 455499777)
            tick(1128)
            vm.pc = 1133
            vm._write(183, memory.load(cells.pointer(182), 4, signed=True) + memory.load(cells.pointer(81), 4, signed=True), 8, 'once1.integer')
            tick(1133)
            vm.pc = 1138
            vm._write(184, cells.value(183) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1138)
            vm.pc = 1143
            _convert(vm, 4, 184, 185)
            tick(1143)
            vm.pc = 1148
            _convert(vm, 4, 177, 186)
            tick(1148)
            vm.pc = 1151
            vm.auxiliary = (0, 47932)
            tick(1151)
            vm.pc = 1157
            vm._write(187, memory.load(cells.pointer(186), 4, signed=True) ^ memory.load(cells.pointer(185), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1157)
            vm.pc = 1162
            vm._write(188, cells.value(187) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1162)
            vm.pc = 1167
            _convert(vm, 4, 188, 189)
            tick(1167)
            vm.pc = 1170
            vm.auxiliary = (0, 55285)
            tick(1170)
            _single_control(vm)
            vm.pc = 1175
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(189), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(190, value, 4, 'typed.selector3.d')
            tick(1175)
            vm.pc = 1178
            vm.auxiliary = (0, 55339)
            tick(1178)
            vm.pc = 1183
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(189), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(191, value, 4, 'typed.selector4.d')
            tick(1183)
            vm.pc = 1188
            vm._write(192, memory.load(cells.pointer(190), 4, signed=True) | memory.load(cells.pointer(191), 4, signed=True), 8, 'L15.binary_q')
            tick(1188)
            vm.pc = 1193
            vm._write(193, cells.value(192) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1193)
            vm.pc = 1196
            vm.auxiliary = (0, 1558344132)
            tick(1196)
            vm.pc = 1201
            vm._write(194, int(memory.load(cells.pointer(193), 1, signed=True) != memory.load(cells.pointer(21), 1, signed=True)), 4, 'L27.comparison')
            tick(1201)
            vm.pc = 1205
            vm._jump(25 if cells.value(194) != 0 else 26)
            continue
        if vm.block == 25:
            tick(1205)
            vm.pc = 1207
            vm._jump(27)
            continue
        if vm.block == 26:
            tick(1207)
            vm.pc = 1212
            vm._write(195, memory.load(cells.pointer(181), 4, signed=True) ^ memory.load(cells.pointer(130), 4, signed=True), 8, 'L14.binary_q')
            tick(1212)
            vm.pc = 1217
            vm._write(196, cells.value(195) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1217)
            vm.pc = 1219
            vm._jump(27)
            continue
        if vm.block == 27:
            tick(1219)
            _phi(vm, 1219, (197, 2, 193, 25, 196, 26))
            tick(1226)
            vm.pc = 1231
            _convert(vm, 4, 197, 198)
            tick(1231)
            vm.pc = 1232
            tick(1232)
            vm.pc = 1235
            vm.auxiliary = (0, 1942156627)
            tick(1235)
            vm.pc = 1240
            vm._write(199, int(memory.load(cells.pointer(198), 4, signed=True) == memory.load(cells.pointer(18), 4, signed=True)), 4, 'once17.integer')
            tick(1240)
            vm.pc = 1244
            vm._jump(28 if cells.value(199) != 0 else 29)
            continue
        if vm.block == 28:
            tick(1244)
            vm.pc = 1246
            vm._jump(29)
            continue
        if vm.block == 29:
            tick(1246)
            _phi(vm, 1246, (200, 2, 90, 28, 197, 27))
            tick(1253)
            vm.pc = 1257
            value = memory.load(cells.value(158), 1)
            vm._write(201, value, 4, 'high.load')
            tick(1257)
            vm.pc = 1258
            tick(1258)
            vm.pc = 1261
            vm.auxiliary = (0, 2118615041)
            tick(1261)
            vm.pc = 1266
            vm._write(202, memory.load(cells.pointer(201), 1, signed=True) + memory.load(cells.pointer(94), 1, signed=True), 8, 'once1.integer')
            tick(1266)
            vm.pc = 1270
            pointer = cells.value(158)
            value = memory.load(cells.pointer(202), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1270)
            vm.pc = 1276
            _provider_host(vm, 1270, 203, (10,), 31, None)
            tick(1276)
            vm.pc = 1278
            vm._jump(30)
            continue
        if vm.block == 30:
            tick(1278)
            _phi(vm, 1278, (204, 2, 18, 29, 205, 31))
            tick(1285)
            vm.pc = 1290
            vm._write(206, int(cells.value(204) < cells.value(3)), 4, 'once18.unsigned_q')
            tick(1290)
            vm.pc = 1294
            vm._jump(31 if cells.value(206) != 0 else 32)
            continue
        if vm.block == 31:
            tick(1294)
            vm.pc = 1295
            tick(1295)
            vm.pc = 1298
            vm.auxiliary = (0, 1677598722)
            tick(1298)
            vm.pc = 1303
            vm._write(207, memory.load(cells.pointer(2), 4, signed=True) + memory.load(cells.pointer(204), 4, signed=True), 8, 'once1.integer')
            tick(1303)
            vm.pc = 1308
            _convert(vm, 8, 207, 208)
            tick(1308)
            _pointer(vm, 1308, 8, 4, 209, (16, 208))
            tick(1316)
            vm.pc = 1320
            value = memory.load(cells.value(209), 1)
            vm._write(210, value, 4, 'high.load')
            tick(1320)
            vm.pc = 1325
            _convert(vm, 8, 204, 211)
            tick(1325)
            _pointer(vm, 1325, 11, 7, 212, (16, 211))
            tick(1333)
            vm.pc = 1337
            pointer = cells.value(212)
            value = memory.load(cells.pointer(210), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1337)
            vm.pc = 1340
            vm.auxiliary = (0, 1060225025)
            tick(1340)
            vm.pc = 1345
            vm._write(205, memory.load(cells.pointer(204), 4, signed=True) + memory.load(cells.pointer(20), 4, signed=True), 8, 'once1.integer')
            tick(1345)
            vm.pc = 1347
            vm._jump(30)
            continue
        if vm.block == 32:
            tick(1347)
            vm.pc = 1351
            vm._jump(33 if cells.value(37) != 0 else 34)
            continue
        if vm.block == 33:
            tick(1351)
            vm.pc = 1353
            vm._jump(35)
            continue
        if vm.block == 35:
            tick(1353)
            _phi(vm, 1353, (213, 2, 36, 33, 214, 36))
            tick(1360)
            _phi(vm, 1360, (215, 2, 41, 33, 216, 36))
            tick(1367)
            vm.pc = 1368
            tick(1368)
            vm.pc = 1371
            vm.auxiliary = (0, 1913020417)
            tick(1371)
            vm.pc = 1376
            vm._write(216, memory.load(cells.pointer(215), 8, signed=True) + memory.load(cells.pointer(43), 8, signed=True), 8, 'once1.integer')
            tick(1376)
            vm.pc = 1381
            vm._write(217, int(cells.value(215) > cells.value(16)), 4, 'L31.comparison')
            tick(1381)
            vm.pc = 1385
            vm._jump(36 if cells.value(217) != 0 else 37)
            continue
        if vm.block == 36:
            tick(1385)
            _pointer(vm, 1385, 2, 213, 214, (20,))
            tick(1392)
            vm.pc = 1396
            pointer = cells.value(213)
            value = memory.load(cells.pointer(21), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1396)
            vm.pc = 1398
            vm._jump(35)
            continue
        if vm.block == 37:
            tick(1398)
            vm.pc = 1400
            vm._jump(34)
            continue
        if vm.block == 34:
            tick(1400)
            vm.pc = 1405
            cells.copy_q_clear_owned(9, 218)
            tick(1405)
            vm.pc = 1410
            _convert(vm, 4, 200, 219)
            tick(1410)
            vm.pc = 1411
            tick(1411)
            vm.pc = 1414
            vm.auxiliary = (0, 15368)
            tick(1414)
            vm.pc = 1419
            count = memory.load(cells.pointer(65), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(219), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(220, value, 4, 'typed.selector4.d')
            tick(1419)
            vm.pc = 1422
            vm.auxiliary = (0, 14675)
            tick(1422)
            vm.pc = 1427
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(219), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(221, value, 4, 'typed.selector4.d')
            tick(1427)
            vm.pc = 1430
            vm.auxiliary = (0, 64300)
            tick(1430)
            vm.pc = 1436
            vm._write(222, memory.load(cells.pointer(220), 4, signed=True) ^ memory.load(cells.pointer(221), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1436)
            vm.pc = 1439
            vm.auxiliary = (0, 12067)
            tick(1439)
            vm.pc = 1444
            count = memory.load(cells.pointer(27), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(219), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(223, value, 4, 'typed.selector4.d')
            tick(1444)
            vm.pc = 1447
            vm.auxiliary = (0, 35932)
            tick(1447)
            vm.pc = 1453
            vm._write(224, memory.load(cells.pointer(222), 4, signed=True) ^ memory.load(cells.pointer(223), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1453)
            vm.pc = 1456
            vm.auxiliary = (0, 11546)
            tick(1456)
            vm.pc = 1461
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(219), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(225, value, 4, 'typed.selector4.d')
            tick(1461)
            vm.pc = 1464
            vm.auxiliary = (0, 22796)
            tick(1464)
            vm.pc = 1470
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(226, memory.load(cells.pointer(224), 4, signed=True) ^ memory.load(cells.pointer(225), 4, signed=True), 8, 'typed.selector5.q')
            tick(1470)
            vm.pc = 1473
            vm.auxiliary = (0, 4726)
            tick(1473)
            vm.pc = 1478
            vm._write(227, memory.load(cells.pointer(226), 4, signed=True) & memory.load(cells.pointer(20), 4, signed=True), 8, 'typed.selector1.q')
            tick(1478)
            vm.pc = 1483
            vm._write(228, cells.value(227) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1483)
            vm.pc = 1486
            vm.auxiliary = (0, 37326)
            tick(1486)
            _single_control(vm)
            vm.pc = 1491
            count = memory.load(cells.pointer(20), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(219), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(229, value, 4, 'typed.selector3.d')
            tick(1491)
            vm.pc = 1496
            _convert(vm, 4, 228, 230)
            tick(1496)
            vm.pc = 1499
            vm.auxiliary = (0, 6041)
            tick(1499)
            vm.pc = 1504
            vm._write(231, memory.load(cells.pointer(229), 4, signed=True) | memory.load(cells.pointer(230), 4, signed=True), 8, 'typed.selector2.q')
            tick(1504)
            vm.pc = 1509
            vm._write(232, cells.value(231) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1509)
            vm.pc = 1514
            _convert(vm, 4, 232, 233)
            tick(1514)
            vm.pc = 1517
            vm.auxiliary = (0, 10324)
            tick(1517)
            vm.pc = 1523
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(234, memory.load(cells.pointer(233), 4, signed=True) ^ memory.load(cells.pointer(81), 4, signed=True), 8, 'typed.selector5.q')
            tick(1523)
            vm.pc = 1528
            vm._write(235, cells.value(234) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1528)
            vm.pc = 1533
            _convert(vm, 4, 235, 236)
            tick(1533)
            vm.pc = 1536
            vm.auxiliary = (0, 41605)
            tick(1536)
            _single_control(vm)
            vm.pc = 1541
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(236), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(237, value, 4, 'typed.selector3.d')
            tick(1541)
            vm.pc = 1544
            vm.auxiliary = (0, 10264)
            tick(1544)
            vm.pc = 1549
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(236), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(238, value, 4, 'typed.selector4.d')
            tick(1549)
            vm.pc = 1554
            vm._write(239, memory.load(cells.pointer(237), 4, signed=True) | memory.load(cells.pointer(238), 4, signed=True), 8, 'L15.binary_q')
            tick(1554)
            vm.pc = 1559
            vm._write(240, cells.value(239) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1559)
            vm.pc = 1562
            vm.auxiliary = (0, 1290956676)
            tick(1562)
            vm.pc = 1567
            vm._write(241, int(memory.load(cells.pointer(240), 1, signed=True) != memory.load(cells.pointer(21), 1, signed=True)), 4, 'L27.comparison')
            tick(1567)
            vm.pc = 1574
            selected = 240 if cells.value(241) != 0 else 90
            vm._write(242, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(1574)
            _pointer(vm, 1574, 11, 9, 243, (16, 16))
            tick(1582)
            vm.pc = 1586
            pointer = cells.value(243)
            value = memory.load(cells.pointer(242), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1586)
            vm.pc = 1588
            vm._jump(38)
            continue
        if vm.block == 38:
            tick(1588)
            _phi(vm, 1588, (244, 2, 20, 34, 245, 39))
            tick(1595)
            vm.pc = 1600
            vm._write(246, int(cells.value(244) < cells.value(3)), 4, 'once18.unsigned_q')
            tick(1600)
            vm.pc = 1604
            vm._jump(39 if cells.value(246) != 0 else 40)
            continue
        if vm.block == 39:
            tick(1604)
            vm.pc = 1605
            tick(1605)
            vm.pc = 1608
            vm.auxiliary = (0, 41586)
            tick(1608)
            vm.pc = 1613
            vm._write(247, memory.load(cells.pointer(244), 4, signed=True) - memory.load(cells.pointer(20), 4, signed=True), 8, 'typed.selector0.q')
            tick(1613)
            vm.pc = 1618
            _convert(vm, 8, 247, 248)
            tick(1618)
            _pointer(vm, 1618, 11, 9, 249, (16, 248))
            tick(1626)
            vm.pc = 1630
            value = memory.load(cells.value(249), 1)
            vm._write(250, value, 4, 'high.load')
            tick(1630)
            vm.pc = 1635
            _convert(vm, 4, 250, 251)
            tick(1635)
            vm.pc = 1638
            vm.auxiliary = (0, 11378)
            tick(1638)
            vm.pc = 1643
            count = memory.load(cells.pointer(65), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(251), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(252, value, 4, 'typed.selector4.d')
            tick(1643)
            vm.pc = 1646
            vm.auxiliary = (0, 31587)
            tick(1646)
            vm.pc = 1651
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(251), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(253, value, 4, 'typed.selector4.d')
            tick(1651)
            vm.pc = 1656
            vm._write(254, memory.load(cells.pointer(252), 4, signed=True) ^ memory.load(cells.pointer(253), 4, signed=True), 8, 'L14.binary_q')
            tick(1656)
            vm.pc = 1659
            vm.auxiliary = (0, 52075)
            tick(1659)
            vm.pc = 1664
            count = memory.load(cells.pointer(27), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(251), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(255, value, 4, 'typed.selector4.d')
            tick(1664)
            vm.pc = 1667
            vm.auxiliary = (0, 31847)
            tick(1667)
            vm.pc = 1673
            vm._write(256, memory.load(cells.pointer(254), 4, signed=True) ^ memory.load(cells.pointer(255), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1673)
            vm.pc = 1676
            vm.auxiliary = (0, 28250)
            tick(1676)
            vm.pc = 1681
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(251), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(257, value, 4, 'typed.selector4.d')
            tick(1681)
            vm.pc = 1684
            vm.auxiliary = (0, 56445)
            tick(1684)
            vm.pc = 1690
            vm._write(258, memory.load(cells.pointer(256), 4, signed=True) ^ memory.load(cells.pointer(257), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1690)
            vm.pc = 1695
            vm._write(259, memory.load(cells.pointer(258), 4, signed=True) & memory.load(cells.pointer(20), 4, signed=True), 8, 'L13.binary_q')
            tick(1695)
            vm.pc = 1700
            vm._write(260, cells.value(259) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1700)
            vm.pc = 1703
            vm.auxiliary = (0, 37580)
            tick(1703)
            _single_control(vm)
            vm.pc = 1708
            count = memory.load(cells.pointer(20), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(251), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(261, value, 4, 'typed.selector3.d')
            tick(1708)
            vm.pc = 1713
            _convert(vm, 4, 260, 262)
            tick(1713)
            vm.pc = 1716
            vm.auxiliary = (0, 13211)
            tick(1716)
            vm.pc = 1721
            vm._write(263, memory.load(cells.pointer(261), 4, signed=True) | memory.load(cells.pointer(262), 4, signed=True), 8, 'typed.selector2.q')
            tick(1721)
            vm.pc = 1726
            vm._write(264, cells.value(263) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1726)
            vm.pc = 1731
            vm._write(265, cells.value(244) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1731)
            vm.pc = 1736
            _convert(vm, 4, 265, 266)
            tick(1736)
            vm.pc = 1739
            vm.auxiliary = (0, 966922755)
            tick(1739)
            vm.pc = 1744
            vm._write(267, memory.load(cells.pointer(266), 4, signed=True) * memory.load(cells.pointer(116), 4, signed=True), 8, 'once0.integer')
            tick(1744)
            vm.pc = 1747
            vm.auxiliary = (0, 1063104514)
            tick(1747)
            vm.pc = 1752
            vm._write(268, memory.load(cells.pointer(267), 4, signed=True) + memory.load(cells.pointer(81), 4, signed=True), 8, 'once1.integer')
            tick(1752)
            vm.pc = 1757
            vm._write(269, cells.value(268) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1757)
            vm.pc = 1762
            _convert(vm, 4, 269, 270)
            tick(1762)
            vm.pc = 1767
            _convert(vm, 4, 264, 271)
            tick(1767)
            vm.pc = 1772
            vm._write(272, memory.load(cells.pointer(271), 4, signed=True) ^ memory.load(cells.pointer(270), 4, signed=True), 8, 'L14.binary_q')
            tick(1772)
            vm.pc = 1777
            vm._write(273, cells.value(272) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1777)
            vm.pc = 1782
            _convert(vm, 4, 273, 274)
            tick(1782)
            vm.pc = 1785
            vm.auxiliary = (0, 53383)
            tick(1785)
            _single_control(vm)
            vm.pc = 1790
            count = memory.load(cells.pointer(59), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(274), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(275, value, 4, 'typed.selector3.d')
            tick(1790)
            vm.pc = 1793
            vm.auxiliary = (0, 12050)
            tick(1793)
            vm.pc = 1798
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(274), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(276, value, 4, 'typed.selector4.d')
            tick(1798)
            vm.pc = 1801
            vm.auxiliary = (0, 21747)
            tick(1801)
            vm.pc = 1806
            vm._write(277, memory.load(cells.pointer(275), 4, signed=True) | memory.load(cells.pointer(276), 4, signed=True), 8, 'typed.selector2.q')
            tick(1806)
            vm.pc = 1811
            vm._write(278, cells.value(277) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1811)
            vm.pc = 1814
            vm.auxiliary = (0, 1851976628)
            tick(1814)
            vm.pc = 1819
            vm._write(279, int(memory.load(cells.pointer(278), 1, signed=True) != memory.load(cells.pointer(21), 1, signed=True)), 4, 'L30.comparison')
            tick(1819)
            vm.pc = 1822
            vm.auxiliary = (0, 49005)
            tick(1822)
            vm.pc = 1828
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(280, memory.load(cells.pointer(266), 4, signed=True) ^ memory.load(cells.pointer(130), 4, signed=True), 8, 'typed.selector5.q')
            tick(1828)
            vm.pc = 1833
            vm._write(281, cells.value(280) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1833)
            vm.pc = 1840
            selected = 278 if cells.value(279) != 0 else 281
            vm._write(282, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(1840)
            vm.pc = 1845
            _convert(vm, 8, 244, 283)
            tick(1845)
            _pointer(vm, 1845, 11, 9, 284, (16, 283))
            tick(1853)
            vm.pc = 1857
            pointer = cells.value(284)
            value = memory.load(cells.pointer(282), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1857)
            vm.pc = 1860
            vm.auxiliary = (0, 1421459458)
            tick(1860)
            vm.pc = 1865
            vm._write(245, memory.load(cells.pointer(244), 4, signed=True) + memory.load(cells.pointer(20), 4, signed=True), 8, 'once1.integer')
            tick(1865)
            vm.pc = 1867
            vm._jump(38)
            continue
        if vm.block == 40:
            tick(1867)
            vm.pc = 1869
            vm._jump(41)
            continue
        if vm.block == 41:
            tick(1869)
            _phi(vm, 1869, (285, 2, 18, 40, 286, 42))
            tick(1876)
            vm.pc = 1881
            vm._write(287, int(cells.value(285) < cells.value(3)), 4, 'once18.unsigned_q')
            tick(1881)
            vm.pc = 1885
            vm._jump(42 if cells.value(287) != 0 else 43)
            continue
        if vm.block == 42:
            tick(1885)
            vm.pc = 1890
            _convert(vm, 8, 285, 288)
            tick(1890)
            _pointer(vm, 1890, 11, 9, 289, (16, 288))
            tick(1898)
            vm.pc = 1902
            value = memory.load(cells.value(289), 1)
            vm._write(290, value, 4, 'high.load')
            tick(1902)
            vm.pc = 1907
            _convert(vm, 4, 290, 291)
            tick(1907)
            _pointer(vm, 1907, 11, 7, 292, (16, 288))
            tick(1915)
            vm.pc = 1919
            value = memory.load(cells.value(292), 1)
            vm._write(293, value, 4, 'high.load')
            tick(1919)
            vm.pc = 1924
            _convert(vm, 4, 293, 294)
            tick(1924)
            vm.pc = 1925
            tick(1925)
            vm.pc = 1928
            vm.auxiliary = (0, 11085)
            tick(1928)
            vm.pc = 1934
            vm._write(295, memory.load(cells.pointer(294), 4, signed=True) ^ memory.load(cells.pointer(291), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1934)
            vm.pc = 1939
            vm._write(296, cells.value(295) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1939)
            vm.pc = 1943
            pointer = cells.value(292)
            value = memory.load(cells.pointer(296), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1943)
            vm.pc = 1946
            vm.auxiliary = (0, 907374594)
            tick(1946)
            vm.pc = 1951
            vm._write(286, memory.load(cells.pointer(285), 4, signed=True) + memory.load(cells.pointer(20), 4, signed=True), 8, 'once1.integer')
            tick(1951)
            vm.pc = 1953
            vm._jump(41)
            continue
        if vm.block == 43:
            tick(1953)
            vm.pc = 1958
            _convert(vm, 8, 3, 297)
            tick(1958)
            vm.pc = 1962
            vm._jump(44 if cells.value(37) != 0 else 45)
            continue
        if vm.block == 44:
            tick(1962)
            vm.pc = 1964
            vm._jump(46)
            continue
        if vm.block == 46:
            tick(1964)
            _phi(vm, 1964, (298, 2, 297, 44, 299, 47))
            tick(1971)
            _phi(vm, 1971, (300, 2, 15, 44, 301, 47))
            tick(1978)
            _phi(vm, 1978, (302, 2, 45, 44, 303, 47))
            tick(1985)
            vm.pc = 1986
            tick(1986)
            vm.pc = 1989
            vm.auxiliary = (0, 1110863873)
            tick(1989)
            vm.pc = 1994
            vm._write(299, memory.load(cells.pointer(298), 8, signed=True) + memory.load(cells.pointer(43), 8, signed=True), 8, 'once1.integer')
            tick(1994)
            vm.pc = 1999
            vm._write(304, int(cells.value(298) > cells.value(16)), 4, 'L31.comparison')
            tick(1999)
            vm.pc = 2003
            vm._jump(47 if cells.value(304) != 0 else 48)
            continue
        if vm.block == 47:
            tick(2003)
            _pointer(vm, 2003, 2, 302, 303, (20,))
            tick(2010)
            vm.pc = 2014
            value = memory.load(cells.value(302), 1)
            vm._write(305, value, 4, 'high.load')
            tick(2014)
            _pointer(vm, 2014, 2, 300, 301, (20,))
            tick(2021)
            vm.pc = 2025
            pointer = cells.value(300)
            value = memory.load(cells.pointer(305), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2025)
            vm.pc = 2027
            vm._jump(46)
            continue
        if vm.block == 48:
            tick(2027)
            vm.pc = 2029
            vm._jump(45)
            continue
        if vm.block == 45:
            tick(2029)
            vm.pc = 2033
            vm._jump(49 if cells.value(37) != 0 else 50)
            continue
        if vm.block == 49:
            tick(2033)
            vm.pc = 2035
            vm._jump(51)
            continue
        if vm.block == 51:
            tick(2035)
            _phi(vm, 2035, (306, 2, 49, 49, 307, 52))
            tick(2042)
            _phi(vm, 2042, (308, 2, 243, 49, 309, 52))
            tick(2049)
            vm.pc = 2050
            tick(2050)
            vm.pc = 2053
            vm.auxiliary = (0, 216731649)
            tick(2053)
            vm.pc = 2058
            vm._write(307, memory.load(cells.pointer(306), 8, signed=True) + memory.load(cells.pointer(43), 8, signed=True), 8, 'once1.integer')
            tick(2058)
            vm.pc = 2063
            vm._write(310, int(cells.value(306) > cells.value(16)), 4, 'L31.comparison')
            tick(2063)
            vm.pc = 2067
            vm._jump(52 if cells.value(310) != 0 else 53)
            continue
        if vm.block == 52:
            tick(2067)
            _pointer(vm, 2067, 2, 308, 309, (20,))
            tick(2074)
            vm.pc = 2078
            pointer = cells.value(308)
            value = memory.load(cells.pointer(21), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2078)
            vm.pc = 2080
            vm._jump(51)
            continue
        if vm.block == 53:
            tick(2080)
            vm.pc = 2082
            vm._jump(50)
            continue
        if vm.block == 50:
            tick(2082)
            vm.pc = 2086
            vm._jump(54 if cells.value(37) != 0 else 55)
            continue
        if vm.block == 54:
            tick(2086)
            vm.pc = 2088
            vm._jump(56)
            continue
        if vm.block == 56:
            tick(2088)
            _phi(vm, 2088, (311, 2, 49, 54, 312, 57))
            tick(2095)
            _phi(vm, 2095, (313, 2, 45, 54, 314, 57))
            tick(2102)
            vm.pc = 2103
            tick(2103)
            vm.pc = 2106
            vm.auxiliary = (0, 255713282)
            tick(2106)
            vm.pc = 2111
            vm._write(312, memory.load(cells.pointer(311), 8, signed=True) + memory.load(cells.pointer(43), 8, signed=True), 8, 'once1.integer')
            tick(2111)
            vm.pc = 2116
            vm._write(315, int(cells.value(311) > cells.value(16)), 4, 'L31.comparison')
            tick(2116)
            vm.pc = 2120
            vm._jump(57 if cells.value(315) != 0 else 58)
            continue
        if vm.block == 57:
            tick(2120)
            _pointer(vm, 2120, 2, 313, 314, (20,))
            tick(2127)
            vm.pc = 2131
            pointer = cells.value(313)
            value = memory.load(cells.pointer(21), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2131)
            vm.pc = 2133
            vm._jump(56)
            continue
        if vm.block == 58:
            tick(2133)
            vm.pc = 2135
            vm._jump(55)
            continue
        if vm.block == 55:
            tick(2135)
            vm.pc = 2139
            value = memory.load(cells.value(8), 8)
            vm._write(316, value, 8, 'high.load')
            tick(2139)
            vm.pc = 2143
            pointer = cells.value(17)
            value = memory.load(cells.pointer(316), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(2143)
            vm.pc = 2147
            pointer = cells.value(19)
            value = memory.load(cells.pointer(200), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2147)
            vm.pc = 2152
            vm._write(317, cells.value(3) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2152)
            vm.pc = 2156
            pointer = cells.value(22)
            value = memory.load(cells.pointer(317), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2156)
            vm.pc = 2158
            vm._jump(3)
            continue
        if vm.block == 3:
            tick(2158)
            vm.pc = 2159
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent material provider left its source-bound blocks')
