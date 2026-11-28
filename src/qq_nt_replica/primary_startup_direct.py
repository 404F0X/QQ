from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_main_material_getter import _convert, _phi, _pointer, _read_pair_control
from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, signed




PROGRAM_SHA256 = {'primary-setup': 'e409888bf8baf3a341cecec5db3566f71d8831433e8c0d93d9208f78025de80f', 'status-audit': '2db8aba84b5b353914b4b88a9c97043fff8700163a0b4c308c8e933431707ffc'}
CHAINS = {'primary-setup': ('main', 'primary-setup'), 'status-audit': ('main', 'primary-setup', 'status-audit')}




def execute_primary_startup(vm, name, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or name not in PROGRAM_SHA256 or
            sha256(vm.program.raw).hexdigest() != PROGRAM_SHA256[name] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) != (1, 0, None, True) or vm.arena_used != 0):
        raise PrimarySemanticUnavailable('independent startup requires its fixed fresh program entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            type(owner) is not dict or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._execute_thread != get_ident() or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            type(owner.get('vm')) is not PrimaryVM or sha256(owner['vm'].program.raw).hexdigest() != MAIN_SHA256 or
            owner['vm'].runtime is not runtime or owner['vm'].memory is not runtime.memory or
            owner['vm'].image_base != runtime.image_base or owner['vm'].halted or
            not runtime.vms or runtime.vms[-1] is not vm or
            tuple(call['name'] for call in runtime._program_calls) != CHAINS[name] or
            any(call['hosts'] is not None and not (call['name'] == 'cocos-init' and call['hosts'] == ())
                for call in runtime._program_calls)):
        raise PrimarySemanticUnavailable('independent startup requires its actual current Main family owner')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, key) is not None for key in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent startup cannot enter a stopped or pending body')
    _parent(vm, name, owner['vm'])
    return _execute_startup_body(vm, name, max_steps=max_steps, execution_report=execution_report)


def _execute_startup_body(vm, name, *, max_steps, execution_report, backend='DIRECT_startup_TYPED_FRAME'):
    state = dict(program=name, backend=backend, referenceRecordCount=0,
                 completed=False, traceComplete=False, completeIndependentMain=False,
                 controlDomain='NONWAITING_ONCE10_WITH_FIXED_FINITE_ALTERNATE_ERRORS')
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_startup_direct_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    BODIES[name](vm, tick)
    state['completed'] = True
    return vm.result


def execute_primary_status_audit_pre_main(vm, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != PROGRAM_SHA256['status-audit'] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used) != (1, 0, None, True, 0)):
        raise PrimarySemanticUnavailable('pre-Main status requires its fixed fresh program entry')
    from .primary_direct_scopes import PrimaryDirectScope
    runtime = vm.runtime
    scope = getattr(runtime, '_primary_direct_scope', None)
    if (type(scope) is not PrimaryDirectScope or scope.runtime is not runtime or
            vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            vm.halted or vm.abort_reason is not None or any(getattr(vm, key) is not None for key in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending'))):
        raise PrimarySemanticUnavailable('pre-Main status requires its actual public scope and live frame')
    scope._authorize_status_vm(vm)
    result = _execute_startup_body(vm, 'status-audit', max_steps=max_steps, execution_report=execution_report,
                                   backend='DIRECT_PRE_MAIN_STATUS_TYPED_FRAME')
    scope._complete_status_vm(vm)
    return result




def _parent(vm, name, main):
    runtime = vm.runtime
    positions = {
        (1168, 15, 14, False): (1160, runtime.image_base + 0x2DE561F, (102, 279), 125),
        (1168, 15, 5, False): (1160, runtime.image_base + 0x2DE561F, (102, 279), 125),
        (34869, 788, 785, False): (34861, runtime.image_base + 0x2DE561F, (102, 216), 125)}
    row = positions.get((main.pc, main.block, main.predecessor, main.initial_block))
    if row is None or not main.host_calls or main.host_calls[-1] != row:
        raise PrimarySemanticUnavailable('independent startup requires its exact executed Main timer host row')
    if name == 'status-audit':
        parents = [p for p in runtime.vms if p is not vm and p.runtime is runtime and not p.halted and
                   sha256(p.program.raw).hexdigest() == PROGRAM_SHA256['primary-setup']]
        if (len(parents) != 1 or (parents[0].pc, parents[0].block, parents[0].initial_block) != (362, 4, False) or
                parents[0].predecessor not in (10, 12) or parents[0].memory is not runtime.memory or
                parents[0].image_base != runtime.image_base or
                not parents[0].host_calls or parents[0].host_calls[-1] !=
                (353, runtime.image_base + 0x2DE8C4C, (14, 65, 34, 61), 14)):
            raise PrimarySemanticUnavailable('independent startup requires its exact executed setup status host row')




def _host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    vm._primary_startup_active_call = (word, callee, arguments, signature, destination)
    try:
        result = _invoke_host(vm, address, arguments, signature,
                              argument_types=vm.program.type(signature).parameters[3:])
    finally:
        vm._primary_startup_active_call = None
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _single(vm):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = signed(vm.memory.load(vm.image_base + 0x6D86094, 4), 32)
    return ((((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31) & 1



def _primary_setup(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(4, 0)
            tick(4)
            vm.pc = 7
            vm._allocate(3, 1)
            tick(7)
            vm.pc = 12
            cells.copy_q_clear_owned(0, 2)
            tick(12)
            vm.pc = 21
            _host(vm, 12, 4, (2, 5, 6), 9, 3)
            tick(21)
            vm.pc = 25
            value = memory.load(cells.value(7), 2)
            vm._write(8, value, 4, 'high.load')
            tick(25)
            vm.pc = 30
            _convert(vm, 4, 8, 9)
            tick(30)
            vm.pc = 31
            tick(31)
            vm.pc = 34
            vm.auxiliary = (0, 988971203)
            tick(34)
            extra = _single(vm)
            vm.pc = 39
            left_pointer = cells.pointer(9)
            right_pointer = cells.pointer(5)
            destination_pointer = cells.pointer(10)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 43
                left_pointer = cells.pointer(1)
                right_pointer = cells.pointer(10)
                destination_pointer = cells.pointer(2)
                width = vm.program.size(31250)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(31250)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 43
                left_pointer = cells.pointer(1)
                right_pointer = cells.pointer(10)
                destination_pointer = cells.pointer(2)
                width = vm.program.size(31250)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(31250)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(39)
            vm.pc = 43
            vm._jump(1 if cells.value(10) != 0 else 2)
            continue
        if vm.block == 1:
            tick(43)
            vm.pc = 48
            cells.copy_q_clear_owned(1, 11)
            tick(48)
            vm.pc = 49
            tick(49)
            vm.pc = 52
            vm.auxiliary = (0, 55861)
            tick(52)
            vm.pc = 58
            vm._write(13, memory.load(cells.pointer(11), 8, signed=True) ^ memory.load(cells.pointer(12), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(58)
            vm.pc = 63
            vm._write(15, memory.load(cells.pointer(13), 8, signed=True) | memory.load(cells.pointer(14), 8, signed=True), 8, 'L15.binary_q')
            tick(63)
            vm.pc = 68
            vm._write(16, cells.value(15) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 72
                width = vm.program.size(218307768)
                vm._write(7, cells.value(16) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(68)
            vm.pc = 72
            pointer = cells.value(7)
            value = memory.load(cells.pointer(16), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(72)
            vm.pc = 74
            vm._jump(2)
            continue
        if vm.block == 2:
            tick(74)
            vm.pc = 76
            vm._jump(3)
            continue
        if vm.block == 3:
            tick(76)
            _phi(vm, 76, (17, 2, 5, 2, 18, 4))
            tick(83)
            vm.pc = 88
            vm._write(20, int(cells.value(17) < cells.value(19)), 4, 'once18.unsigned_q')
            tick(88)
            vm.pc = 92
            vm._jump(5 if cells.value(20) != 0 else 6)
            continue
        if vm.block == 5:
            tick(92)
            vm.pc = 96
            value = memory.load(cells.value(7), 2)
            vm._write(21, value, 4, 'high.load')
            tick(96)
            vm.pc = 101
            _convert(vm, 4, 21, 22)
            tick(101)
            vm.pc = 102
            tick(102)
            vm.pc = 105
            vm.auxiliary = (0, 24393)
            tick(105)
            vm.pc = 110
            count = memory.load(cells.pointer(23), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(22), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(24, value, 4, 'typed.selector4.d')
            tick(110)
            vm.pc = 113
            vm.auxiliary = (0, 47899)
            tick(113)
            vm.pc = 118
            count = memory.load(cells.pointer(25), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(22), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(26, value, 4, 'typed.selector4.d')
            tick(118)
            vm.pc = 121
            vm.auxiliary = (0, 48733)
            tick(121)
            vm.pc = 127
            vm._write(27, memory.load(cells.pointer(24), 4, signed=True) ^ memory.load(cells.pointer(26), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(127)
            vm.pc = 130
            vm.auxiliary = (0, 28266)
            tick(130)
            vm.pc = 135
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(22), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(29, value, 4, 'typed.selector4.d')
            tick(135)
            vm.pc = 140
            vm._write(30, memory.load(cells.pointer(27), 4, signed=True) ^ memory.load(cells.pointer(29), 4, signed=True), 8, 'L14.binary_q')
            tick(140)
            vm.pc = 143
            vm.auxiliary = (0, 44040)
            tick(143)
            vm.pc = 148
            count = memory.load(cells.pointer(31), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(22), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(32, value, 4, 'typed.selector4.d')
            tick(148)
            vm.pc = 151
            vm.auxiliary = (0, 39287)
            tick(151)
            vm.pc = 157
            vm._write(33, memory.load(cells.pointer(30), 4, signed=True) ^ memory.load(cells.pointer(32), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(157)
            vm.pc = 160
            vm.auxiliary = (0, 30054)
            tick(160)
            vm.pc = 165
            vm._write(35, memory.load(cells.pointer(33), 4, signed=True) & memory.load(cells.pointer(34), 4, signed=True), 8, 'typed.selector1.q')
            tick(165)
            vm.pc = 170
            vm._write(36, cells.value(35) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 174
                width = vm.program.size(55622)
                vm._write(100956627, cells.value(10190) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(170)
            vm.pc = 173
            vm.auxiliary = (0, 10190)
            tick(173)
            extra = _single(vm)
            vm.pc = 178
            count = memory.load(cells.pointer(34), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(22), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(37, value, 4, 'typed.selector3.d')
            if extra:
                vm.pc = 179
                vm.program.size(360601030)
            tick(178)
            vm.pc = 183
            _convert(vm, 4, 36, 38)
            tick(183)
            vm.pc = 188
            vm._write(39, memory.load(cells.pointer(37), 4, signed=True) | memory.load(cells.pointer(38), 4, signed=True), 8, 'L15.binary_q')
            tick(188)
            vm.pc = 193
            vm._write(40, cells.value(39) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 197
                width = vm.program.size(360601030)
                vm._write(40, cells.value(11) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(193)
            vm.pc = 198
            _convert(vm, 4, 40, 41)
            tick(198)
            vm.pc = 201
            vm.auxiliary = (0, 1101192179)
            tick(201)
            extra = _single(vm)
            vm.pc = 206
            left_pointer = cells.pointer(41)
            right_pointer = cells.pointer(5)
            destination_pointer = cells.pointer(42)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 210
                left_pointer = cells.pointer(13)
                right_pointer = cells.pointer(42)
                destination_pointer = cells.pointer(11)
                width = vm.program.size(53085)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(53085)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 210
                left_pointer = cells.pointer(13)
                right_pointer = cells.pointer(42)
                destination_pointer = cells.pointer(11)
                width = vm.program.size(53085)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(53085)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(206)
            vm.pc = 213
            selected = 43 if cells.value(42) != 0 else 40
            vm._write(44, memory.load(cells.pointer(selected), 2, signed=True), 8, 'L7.selected_q')
            tick(213)
            vm.pc = 217
            pointer = cells.value(7)
            value = memory.load(cells.pointer(44), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(217)
            vm.pc = 222
            _convert(vm, 4, 44, 45)
            tick(222)
            vm.pc = 227
            vm._write(47, memory.load(cells.pointer(45), 4, signed=True) & memory.load(cells.pointer(46), 4, signed=True), 8, 'L13.binary_q')
            tick(227)
            vm.pc = 232
            vm._write(48, cells.value(47) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 236
                width = vm.program.size(38218)
                vm._write(49, cells.value(57113) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(232)
            vm.pc = 234
            vm._jump(7)
            continue
        if vm.block == 7:
            tick(234)
            _phi(vm, 234, (49, 2, 5, 5, 50, 8))
            tick(241)
            vm.pc = 246
            vm._write(51, int(cells.value(49) < cells.value(17)), 4, 'once18.unsigned_q')
            tick(246)
            vm.pc = 250
            vm._jump(9 if cells.value(51) != 0 else 10)
            continue
        if vm.block == 9:
            tick(250)
            vm.pc = 255
            _convert(vm, 8, 49, 52)
            tick(255)
            _pointer(vm, 255, 4, 0, 53, (54, 52))
            tick(263)
            vm.pc = 267
            value = memory.load(cells.value(53), 1)
            vm._write(55, value, 4, 'high.load')
            tick(267)
            vm.pc = 272
            _convert(vm, 4, 55, 56)
            tick(272)
            vm.pc = 277
            _convert(vm, 4, 48, 57)
            tick(277)
            vm.pc = 278
            tick(278)
            vm.pc = 281
            vm.auxiliary = (0, 2098344483)
            tick(281)
            extra = _single(vm)
            vm.pc = 286
            left_pointer = cells.pointer(56)
            right_pointer = cells.pointer(57)
            destination_pointer = cells.pointer(58)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 290
                left_pointer = cells.pointer(11)
                right_pointer = cells.pointer(58)
                destination_pointer = cells.pointer(8)
                width = vm.program.size(35062)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(35062)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 290
                left_pointer = cells.pointer(11)
                right_pointer = cells.pointer(58)
                destination_pointer = cells.pointer(8)
                width = vm.program.size(35062)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(35062)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(286)
            vm.pc = 290
            vm._jump(11 if cells.value(58) != 0 else 8)
            continue
        if vm.block == 11:
            tick(290)
            vm.pc = 292
            vm._jump(10)
            continue
        if vm.block == 8:
            tick(292)
            vm.pc = 293
            tick(293)
            vm.pc = 296
            vm.auxiliary = (0, 1618567169)
            tick(296)
            vm.pc = 301
            vm._write(50, memory.load(cells.pointer(49), 4, signed=True) + memory.load(cells.pointer(34), 4, signed=True), 8, 'once1.integer')
            tick(301)
            vm.pc = 303
            vm._jump(7)
            continue
        if vm.block == 10:
            tick(303)
            _phi(vm, 303, (59, 2, 60, 11, 61, 7))
            tick(310)
            vm.pc = 311
            tick(311)
            vm.pc = 314
            vm.auxiliary = (0, 1284676420)
            tick(314)
            vm.pc = 319
            vm._write(62, int(memory.load(cells.pointer(59), 1, signed=True) != memory.load(cells.pointer(61), 1, signed=True)), 4, 'L27.comparison')
            tick(319)
            vm.pc = 323
            vm._jump(4 if cells.value(62) != 0 else 12)
            continue
        if vm.block == 12:
            tick(323)
            vm.pc = 328
            _convert(vm, 4, 48, 63)
            tick(328)
            vm.pc = 329
            tick(329)
            vm.pc = 332
            vm.auxiliary = (0, 564682753)
            tick(332)
            vm.pc = 337
            vm._write(64, memory.load(cells.pointer(17), 4, signed=True) + memory.load(cells.pointer(34), 4, signed=True), 8, 'once1.integer')
            tick(337)
            vm.pc = 339
            vm._jump(4)
            continue
        if vm.block == 4:
            tick(339)
            _phi(vm, 339, (18, 2, 17, 10, 64, 12))
            tick(346)
            _phi(vm, 346, (65, 2, 5, 10, 63, 12))
            tick(353)
            vm.pc = 362
            _host(vm, 353, 66, (14, 65, 34, 61), 14, None)
            tick(362)
            vm.pc = 364
            vm._jump(3)
            continue
        if vm.block == 6:
            tick(364)
            vm.pc = 365
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent startup left its fixed source blocks')


def _status_audit(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 2
            tick(2)
            vm.pc = 5
            vm.auxiliary = (0, 1548916756)
            tick(5)
            vm.pc = 10
            vm._write(6, int(memory.load(cells.pointer(4), 1, signed=True) != memory.load(cells.pointer(5), 1, signed=True)), 4, 'L27.comparison')
            tick(10)
            vm.pc = 14
            vm._jump(1 if cells.value(6) != 0 else 2)
            continue
        if vm.block == 1:
            tick(14)
            _pointer(vm, 14, 2, 0, 7, (8, 9))
            tick(22)
            vm.pc = 26
            value = memory.load(cells.value(7), 8)
            vm._write(10, value, 8, 'high.load')
            tick(26)
            _pointer(vm, 26, 2, 0, 11, (8, 12))
            tick(34)
            vm.pc = 38
            value = memory.load(cells.value(11), 8)
            vm._write(13, value, 8, 'high.load')
            tick(38)
            vm.pc = 39
            tick(39)
            vm.pc = 42
            vm.auxiliary = (0, 64628)
            tick(42)
            vm.pc = 48
            vm._write(14, memory.load(cells.pointer(10), 8, signed=True) ^ memory.load(cells.pointer(13), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(48)
            vm.pc = 53
            cells.copy_q_clear_owned(14, 15)
            tick(53)
            vm.pc = 55
            vm._jump(3)
            continue
        if vm.block == 2:
            tick(55)
            _pointer(vm, 55, 2, 0, 16, (8, 8))
            tick(63)
            vm.pc = 67
            value = memory.load(cells.value(16), 8)
            vm._write(17, value, 8, 'high.load')
            tick(67)
            _pointer(vm, 67, 2, 0, 18, (8, 19))
            tick(75)
            vm.pc = 79
            value = memory.load(cells.value(18), 8)
            vm._write(20, value, 8, 'high.load')
            tick(79)
            vm.pc = 84
            vm._write(21, memory.load(cells.pointer(17), 8, signed=True) ^ memory.load(cells.pointer(20), 8, signed=True), 8, 'L14.binary_q')
            tick(84)
            vm.pc = 89
            cells.copy_q_clear_owned(21, 22)
            tick(89)
            vm.pc = 91
            vm._jump(3)
            continue
        if vm.block == 3:
            tick(91)
            _phi(vm, 91, (23, 2, 15, 1, 22, 2))
            tick(98)
            vm.pc = 99
            tick(99)
            vm.pc = 102
            vm.auxiliary = (0, 592590227)
            tick(102)
            vm.pc = 107
            vm._write(24, int(memory.load(cells.pointer(3), 4, signed=True) == memory.load(cells.pointer(9), 4, signed=True)), 4, 'once17.integer')
            tick(107)
            vm.pc = 111
            vm._jump(4 if cells.value(24) != 0 else 5)
            continue
        if vm.block == 4:
            tick(111)
            vm.pc = 112
            tick(112)
            vm.pc = 115
            vm.auxiliary = (0, 849509923)
            tick(115)
            vm.pc = 120
            vm._write(26, int(memory.load(cells.pointer(1), 8, signed=True) == memory.load(cells.pointer(25), 8, signed=True)), 4, 'once17.integer')
            tick(120)
            vm.pc = 124
            vm._jump(6 if cells.value(26) != 0 else 7)
            continue
        if vm.block == 6:
            tick(124)
            vm.pc = 129
            _convert(vm, 8, 2, 27)
            tick(129)
            vm.pc = 130
            tick(130)
            vm.pc = 133
            vm.auxiliary = (0, 41373)
            tick(133)
            extra = _single(vm)
            vm.pc = 138
            count = memory.load(cells.pointer(27), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(25) << count
            vm._write(28, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 139
                vm.program.size(104927175)
            tick(138)
            vm.pc = 142
            value = memory.load(cells.value(23), 8)
            vm._write(29, value, 8, 'high.load')
            tick(142)
            vm.pc = 145
            vm.auxiliary = (0, 23623)
            tick(145)
            vm.pc = 151
            vm._write(31, memory.load(cells.pointer(28), 8, signed=True) ^ memory.load(cells.pointer(30), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(151)
            vm.pc = 156
            vm._write(32, memory.load(cells.pointer(29), 8, signed=True) & memory.load(cells.pointer(31), 8, signed=True), 8, 'L13.binary_q')
            tick(156)
            vm.pc = 159
            vm.auxiliary = (0, 58297)
            tick(159)
            vm.pc = 164
            vm._write(33, memory.load(cells.pointer(28), 8, signed=True) | memory.load(cells.pointer(32), 8, signed=True), 8, 'typed.selector2.q')
            tick(164)
            vm.pc = 168
            pointer = cells.value(23)
            value = memory.load(cells.pointer(33), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(168)
            vm.pc = 170
            vm._jump(7)
            continue
        if vm.block == 5:
            tick(170)
            vm.pc = 171
            tick(171)
            vm.pc = 174
            vm.auxiliary = (0, 1145217139)
            tick(174)
            vm.pc = 179
            vm._write(34, int(memory.load(cells.pointer(3), 4, signed=True) == memory.load(cells.pointer(19), 4, signed=True)), 4, 'once17.integer')
            tick(179)
            vm.pc = 183
            vm._jump(8 if cells.value(34) != 0 else 9)
            continue
        if vm.block == 8:
            tick(183)
            vm.pc = 187
            value = memory.load(cells.value(23), 8)
            vm._write(35, value, 8, 'high.load')
            tick(187)
            vm.pc = 188
            tick(188)
            vm.pc = 191
            vm.auxiliary = (0, 21746)
            tick(191)
            vm.pc = 196
            vm._write(36, memory.load(cells.pointer(35), 8, signed=True) | memory.load(cells.pointer(1), 8, signed=True), 8, 'typed.selector2.q')
            tick(196)
            vm.pc = 200
            pointer = cells.value(23)
            value = memory.load(cells.pointer(36), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(200)
            vm.pc = 202
            vm._jump(7)
            continue
        if vm.block == 9:
            tick(202)
            vm.pc = 203
            tick(203)
            vm.pc = 206
            vm.auxiliary = (0, 1582462163)
            tick(206)
            vm.pc = 211
            vm._write(37, int(memory.load(cells.pointer(3), 4, signed=True) == memory.load(cells.pointer(12), 4, signed=True)), 4, 'once17.integer')
            tick(211)
            vm.pc = 215
            vm._jump(10 if cells.value(37) != 0 else 7)
            continue
        if vm.block == 10:
            tick(215)
            vm.pc = 219
            value = memory.load(cells.value(23), 8)
            vm._write(38, value, 8, 'high.load')
            tick(219)
            vm.pc = 220
            tick(220)
            vm.pc = 223
            vm.auxiliary = (0, 13084)
            tick(223)
            vm.pc = 228
            vm._write(39, memory.load(cells.pointer(38), 8, signed=True) & memory.load(cells.pointer(1), 8, signed=True), 8, 'typed.selector1.q')
            tick(228)
            vm.pc = 232
            pointer = cells.value(23)
            value = memory.load(cells.pointer(39), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(232)
            vm.pc = 234
            vm._jump(7)
            continue
        if vm.block == 7:
            tick(234)
            vm.pc = 235
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent startup left its fixed source blocks')


BODIES = {'primary-setup': _primary_setup, 'status-audit': _status_audit}
