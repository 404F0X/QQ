from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_main_material_getter import (_convert, _equal, _pair_control, _phi,
                                           _pointer, _single_control)
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable


STATE_SHA256 = '633f3a4bc33cc5cef8a916d55dd27835342364835e0a6ba1a496fbfa1658298d'


def _state_host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    expected = {32: 0x3EB1FE0, 46: 0x3591E1C}[word]
    if address != vm.image_base + expected:
        raise PrimarySemanticUnavailable('independent material initializer requires its fixed model host binding')
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    result = _invoke_host(vm, address, arguments, signature,
                          argument_types=vm.program.type(signature).parameters[3:])
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def execute_primary_main_material_state(vm, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != STATE_SHA256 or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) != (1, 0, None, True)):
        raise PrimarySemanticUnavailable('independent material initializer requires its fixed program entry')
    runtime = vm.runtime
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            getattr(runtime, '_consumed_mgf', None) is not None or runtime._active_failed or
            runtime._execute_thread != get_ident() or not runtime._program_calls or
            runtime._program_calls[-1]['name'] != 'material-state' or
            runtime._program_calls[-1]['arguments'] != (runtime.image_base + 0x6D88430,) or
            runtime._program_calls[-1]['hosts'] is not None or not runtime.vms or runtime.vms[-1] is not vm):
        raise PrimarySemanticUnavailable('independent material initializer requires its current fixed-context runtime frame')
    context = runtime.image_base + 0x6D88430
    private_ranges = ((vm.arena_address, vm.arena_size),
                      (vm.cells.address, (vm.program.cell_count + 1) * 24))
    if any(address < context + 2160 and context < address + size for address, size in private_ranges):
        raise PrimarySemanticUnavailable('independent material initializer requires a distinct context and private frame')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent material initializer cannot enter a stopped or pending body')
    state = dict(entryWord=1, exitWord=3851, backend='DIRECT_MATERIAL_STATE',
                 referenceRecordCount=0, completed=False, traceComplete=False)
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_main_material_state_execution = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    _initialize_material_state(vm, tick)
    state['completed'] = True
    return vm.result



def _initialize_material_state(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(1, 1)
            tick(4)
            vm.pc = 7
            vm._allocate(6, 2)
            tick(7)
            vm.pc = 10
            vm._allocate(15, 3)
            tick(10)
            vm.pc = 13
            vm._allocate(24, 4)
            tick(13)
            vm.pc = 16
            vm._allocate(6, 5)
            tick(16)
            vm.pc = 19
            vm._allocate(6, 6)
            tick(19)
            vm.pc = 24
            cells.copy_q_clear_owned(2, 7)
            tick(24)
            _pointer(vm, 24, 26, 9, 8, (10, 10))
            tick(32)
            vm.pc = 41
            _state_host(vm, 32, 12, (1, 8, 13), 28, 11)
            tick(41)
            vm.pc = 46
            cells.copy_q_clear_owned(3, 14)
            tick(46)
            vm.pc = 52
            _state_host(vm, 46, 15, (0,), 20, None)
            tick(52)
            vm.pc = 57
            cells.copy_q_clear_owned(1, 16)
            tick(57)
            vm.pc = 62
            vm._write(18, memory.load(cells.pointer(16), 8, signed=True) & memory.load(cells.pointer(17), 8, signed=True), 8, 'L13.binary_q')
            tick(62)
            vm.pc = 67
            vm._write(19, cells.value(18) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(67)
            vm.pc = 72
            _convert(vm, 4, 19, 20)
            tick(72)
            vm.pc = 73
            tick(73)
            vm.pc = 76
            vm.auxiliary = (0, 621955315)
            tick(76)
            _equal(vm, 81, 4, 20, 21, 22)
            tick(81)
            vm.pc = 88
            selected = 23 if cells.value(22) != 0 else 19
            vm._write(24, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(88)
            _pointer(vm, 88, 18, 0, 25, (21, 26))
            tick(96)
            vm.pc = 100
            pointer = cells.value(25)
            value = memory.load(cells.pointer(24), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(100)
            vm.pc = 105
            _convert(vm, 4, 24, 27)
            tick(105)
            vm.pc = 108
            vm.auxiliary = (0, 23833)
            tick(108)
            vm.pc = 113
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(27), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(29, value, 4, 'typed.selector4.d')
            tick(113)
            vm.pc = 116
            vm.auxiliary = (0, 20233)
            tick(116)
            vm.pc = 121
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(27), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(31, value, 4, 'typed.selector4.d')
            tick(121)
            vm.pc = 126
            vm._write(32, memory.load(cells.pointer(29), 4, signed=True) ^ memory.load(cells.pointer(31), 4, signed=True), 8, 'L14.binary_q')
            tick(126)
            vm.pc = 129
            vm.auxiliary = (0, 64586)
            tick(129)
            vm.pc = 134
            count = memory.load(cells.pointer(33), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(27), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(34, value, 4, 'typed.selector4.d')
            tick(134)
            vm.pc = 139
            vm._write(35, memory.load(cells.pointer(32), 4, signed=True) ^ memory.load(cells.pointer(34), 4, signed=True), 8, 'L14.binary_q')
            tick(139)
            vm.pc = 142
            vm.auxiliary = (0, 23066)
            tick(142)
            vm.pc = 147
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(27), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(36, value, 4, 'typed.selector4.d')
            tick(147)
            vm.pc = 150
            vm.auxiliary = (0, 11615)
            tick(150)
            vm.pc = 156
            vm._write(37, memory.load(cells.pointer(35), 4, signed=True) ^ memory.load(cells.pointer(36), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(156)
            vm.pc = 159
            vm.auxiliary = (0, 13092)
            tick(159)
            vm.pc = 164
            vm._write(39, memory.load(cells.pointer(37), 4, signed=True) & memory.load(cells.pointer(38), 4, signed=True), 8, 'typed.selector1.q')
            tick(164)
            vm.pc = 169
            vm._write(40, cells.value(39) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(169)
            vm.pc = 172
            vm.auxiliary = (0, 50565)
            tick(172)
            _single_control(vm)
            vm.pc = 177
            count = memory.load(cells.pointer(38), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(27), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(41, value, 4, 'typed.selector3.d')
            tick(177)
            vm.pc = 182
            _convert(vm, 4, 40, 42)
            tick(182)
            vm.pc = 185
            vm.auxiliary = (0, 62147)
            tick(185)
            vm.pc = 190
            vm._write(43, memory.load(cells.pointer(41), 4, signed=True) | memory.load(cells.pointer(42), 4, signed=True), 8, 'typed.selector2.q')
            tick(190)
            vm.pc = 195
            vm._write(44, cells.value(43) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(195)
            vm.pc = 200
            _convert(vm, 4, 44, 45)
            tick(200)
            vm.pc = 203
            vm.auxiliary = (0, 10831)
            tick(203)
            vm.pc = 209
            vm._write(47, memory.load(cells.pointer(45), 4, signed=True) ^ memory.load(cells.pointer(46), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(209)
            vm.pc = 214
            vm._write(48, cells.value(47) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(214)
            vm.pc = 219
            _convert(vm, 4, 48, 49)
            tick(219)
            vm.pc = 222
            vm.auxiliary = (0, 29094)
            tick(222)
            _single_control(vm)
            vm.pc = 227
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(49), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(50, value, 4, 'typed.selector3.d')
            tick(227)
            vm.pc = 230
            vm.auxiliary = (0, 55666)
            tick(230)
            vm.pc = 235
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(49), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(51, value, 4, 'typed.selector4.d')
            tick(235)
            vm.pc = 238
            vm.auxiliary = (0, 14282)
            tick(238)
            vm.pc = 243
            vm._write(52, memory.load(cells.pointer(50), 4, signed=True) | memory.load(cells.pointer(51), 4, signed=True), 8, 'typed.selector2.q')
            tick(243)
            vm.pc = 248
            vm._write(53, cells.value(52) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(248)
            vm.pc = 251
            vm.auxiliary = (0, 721608852)
            tick(251)
            vm.pc = 256
            vm._write(55, int(memory.load(cells.pointer(53), 1, signed=True) != memory.load(cells.pointer(54), 1, signed=True)), 4, 'L30.comparison')
            tick(256)
            vm.pc = 263
            selected = 53 if cells.value(55) != 0 else 56
            vm._write(57, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(263)
            _pointer(vm, 263, 18, 0, 58, (21, 33))
            tick(271)
            vm.pc = 275
            pointer = cells.value(58)
            value = memory.load(cells.pointer(57), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(275)
            _pointer(vm, 275, 18, 0, 59, (21, 30))
            tick(283)
            vm.pc = 287
            pointer = cells.value(59)
            value = memory.load(cells.pointer(54), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(287)
            vm.pc = 292
            cells.copy_q_clear_owned(4, 60)
            tick(292)
            vm.pc = 294
            vm._jump(1)
            continue
        if vm.block == 1:
            tick(294)
            _phi(vm, 294, (61, 2, 21, 0, 62, 2))
            tick(301)
            vm.pc = 302
            tick(302)
            vm.pc = 305
            vm.auxiliary = (0, 778180341)
            tick(305)
            vm.pc = 310
            a = memory.load(cells.pointer(61), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(63), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(64, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(310)
            vm.pc = 314
            vm._jump(2 if cells.value(64) != 0 else 3)
            continue
        if vm.block == 2:
            tick(314)
            vm.pc = 319
            vm._write(65, cells.value(61) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(319)
            vm.pc = 324
            cells.copy_q_clear_owned(61, 66)
            tick(324)
            _pointer(vm, 324, 24, 4, 67, (10, 66))
            tick(332)
            vm.pc = 336
            pointer = cells.value(67)
            value = memory.load(cells.pointer(65), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(336)
            vm.pc = 337
            tick(337)
            vm.pc = 340
            vm.auxiliary = (0, 820613122)
            tick(340)
            vm.pc = 345
            vm._write(62, memory.load(cells.pointer(61), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(345)
            vm.pc = 347
            vm._jump(1)
            continue
        if vm.block == 3:
            tick(347)
            vm.pc = 351
            value = memory.load(cells.value(25), 1)
            vm._write(68, value, 4, 'high.load')
            tick(351)
            vm.pc = 353
            vm._jump(4)
            continue
        if vm.block == 4:
            tick(353)
            _phi(vm, 353, (69, 2, 68, 3, 70, 5))
            tick(360)
            _phi(vm, 360, (71, 2, 21, 3, 72, 5))
            tick(367)
            vm.pc = 368
            tick(368)
            vm.pc = 371
            vm.auxiliary = (0, 1959965189)
            tick(371)
            vm.pc = 376
            a = memory.load(cells.pointer(71), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(73), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(74, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(376)
            vm.pc = 380
            vm._jump(5 if cells.value(74) != 0 else 6)
            continue
        if vm.block == 5:
            tick(380)
            vm.pc = 385
            _convert(vm, 4, 69, 75)
            tick(385)
            vm.pc = 386
            tick(386)
            vm.pc = 389
            vm.auxiliary = (0, 52538)
            tick(389)
            vm.pc = 394
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(75), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(76, value, 4, 'typed.selector4.d')
            tick(394)
            vm.pc = 397
            vm.auxiliary = (0, 10763)
            tick(397)
            vm.pc = 402
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(75), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(77, value, 4, 'typed.selector4.d')
            tick(402)
            vm.pc = 405
            vm.auxiliary = (0, 52861)
            tick(405)
            vm.pc = 411
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(78, memory.load(cells.pointer(76), 4, signed=True) ^ memory.load(cells.pointer(77), 4, signed=True), 8, 'typed.selector5.q')
            tick(411)
            vm.pc = 414
            vm.auxiliary = (0, 39987)
            tick(414)
            vm.pc = 419
            count = memory.load(cells.pointer(33), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(75), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(79, value, 4, 'typed.selector4.d')
            tick(419)
            vm.pc = 422
            vm.auxiliary = (0, 40828)
            tick(422)
            vm.pc = 428
            vm._write(80, memory.load(cells.pointer(78), 4, signed=True) ^ memory.load(cells.pointer(79), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(428)
            vm.pc = 431
            vm.auxiliary = (0, 43627)
            tick(431)
            vm.pc = 436
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(75), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(81, value, 4, 'typed.selector4.d')
            tick(436)
            vm.pc = 439
            vm.auxiliary = (0, 38998)
            tick(439)
            vm.pc = 445
            vm._write(82, memory.load(cells.pointer(80), 4, signed=True) ^ memory.load(cells.pointer(81), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(445)
            vm.pc = 450
            vm._write(83, memory.load(cells.pointer(82), 4, signed=True) & memory.load(cells.pointer(38), 4, signed=True), 8, 'L13.binary_q')
            tick(450)
            vm.pc = 455
            vm._write(84, cells.value(83) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(455)
            vm.pc = 458
            vm.auxiliary = (0, 29420)
            tick(458)
            _single_control(vm)
            vm.pc = 463
            count = memory.load(cells.pointer(38), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(75), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(85, value, 4, 'typed.selector3.d')
            tick(463)
            vm.pc = 468
            _convert(vm, 4, 84, 86)
            tick(468)
            vm.pc = 471
            vm.auxiliary = (0, 9441)
            tick(471)
            vm.pc = 476
            vm._write(87, memory.load(cells.pointer(85), 4, signed=True) | memory.load(cells.pointer(86), 4, signed=True), 8, 'typed.selector2.q')
            tick(476)
            vm.pc = 481
            vm._write(88, cells.value(87) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(481)
            vm.pc = 486
            vm._write(89, cells.value(71) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(486)
            vm.pc = 491
            _convert(vm, 4, 89, 90)
            tick(491)
            vm.pc = 494
            vm.auxiliary = (0, 564253188)
            tick(494)
            vm.pc = 499
            vm._write(92, memory.load(cells.pointer(90), 4, signed=True) * memory.load(cells.pointer(91), 4, signed=True), 8, 'once0.integer')
            tick(499)
            vm.pc = 502
            vm.auxiliary = (0, 413466625)
            tick(502)
            vm.pc = 507
            vm._write(94, memory.load(cells.pointer(92), 4, signed=True) + memory.load(cells.pointer(93), 4, signed=True), 8, 'once1.integer')
            tick(507)
            vm.pc = 512
            vm._write(95, cells.value(94) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(512)
            vm.pc = 517
            _convert(vm, 4, 95, 96)
            tick(517)
            vm.pc = 522
            _convert(vm, 4, 88, 97)
            tick(522)
            vm.pc = 525
            vm.auxiliary = (0, 14655)
            tick(525)
            vm.pc = 531
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(98, memory.load(cells.pointer(97), 4, signed=True) ^ memory.load(cells.pointer(96), 4, signed=True), 8, 'typed.selector5.q')
            tick(531)
            vm.pc = 536
            vm._write(99, cells.value(98) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(536)
            vm.pc = 541
            _convert(vm, 4, 99, 100)
            tick(541)
            vm.pc = 544
            vm.auxiliary = (0, 13967)
            tick(544)
            _single_control(vm)
            vm.pc = 549
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(100), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(101, value, 4, 'typed.selector3.d')
            tick(549)
            vm.pc = 552
            vm.auxiliary = (0, 11097)
            tick(552)
            vm.pc = 557
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(100), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(102, value, 4, 'typed.selector4.d')
            tick(557)
            vm.pc = 560
            vm.auxiliary = (0, 42409)
            tick(560)
            vm.pc = 565
            vm._write(103, memory.load(cells.pointer(101), 4, signed=True) | memory.load(cells.pointer(102), 4, signed=True), 8, 'typed.selector2.q')
            tick(565)
            vm.pc = 570
            vm._write(104, cells.value(103) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(570)
            vm.pc = 573
            vm.auxiliary = (0, 550687940)
            tick(573)
            vm.pc = 578
            vm._write(105, int(memory.load(cells.pointer(104), 1, signed=True) != memory.load(cells.pointer(54), 1, signed=True)), 4, 'L27.comparison')
            tick(578)
            vm.pc = 583
            vm._write(107, memory.load(cells.pointer(90), 4, signed=True) ^ memory.load(cells.pointer(106), 4, signed=True), 8, 'L14.binary_q')
            tick(583)
            vm.pc = 588
            vm._write(108, cells.value(107) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(588)
            vm.pc = 595
            selected = 104 if cells.value(105) != 0 else 108
            vm._write(70, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(595)
            vm.pc = 600
            _convert(vm, 4, 70, 109)
            tick(600)
            vm.pc = 603
            vm.auxiliary = (0, 57347)
            tick(603)
            vm.pc = 608
            vm._write(110, memory.load(cells.pointer(63), 4, signed=True) - memory.load(cells.pointer(71), 4, signed=True), 8, 'typed.selector0.q')
            tick(608)
            vm.pc = 613
            a = memory.load(cells.pointer(109), 4, signed=True)
            b = memory.load(cells.pointer(110), 4, signed=True)
            if b == 0 or (a == -(1 << 63) and b == -1):
                raise PrimaryProgramLimit('native signed IDIV64 fault outside ordinary execution')
            quotient = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
            vm._write(111, a - quotient * b, 8, "L16.signed_remainder_q")
            tick(613)
            vm.pc = 616
            vm.auxiliary = (0, 558944258)
            tick(616)
            vm.pc = 621
            vm._write(112, memory.load(cells.pointer(71), 4, signed=True) + memory.load(cells.pointer(111), 4, signed=True), 8, 'once1.integer')
            tick(621)
            vm.pc = 626
            vm._write(113, cells.value(112) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(626)
            vm.pc = 631
            cells.copy_q_clear_owned(71, 114)
            tick(631)
            _pointer(vm, 631, 24, 4, 115, (10, 114))
            tick(639)
            vm.pc = 643
            value = memory.load(cells.value(115), 1)
            vm._write(116, value, 4, 'high.load')
            tick(643)
            vm.pc = 648
            _convert(vm, 8, 113, 117)
            tick(648)
            _pointer(vm, 648, 24, 4, 118, (10, 117))
            tick(656)
            vm.pc = 660
            value = memory.load(cells.value(118), 1)
            vm._write(119, value, 4, 'high.load')
            tick(660)
            vm.pc = 664
            pointer = cells.value(115)
            value = memory.load(cells.pointer(119), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(664)
            vm.pc = 668
            pointer = cells.value(118)
            value = memory.load(cells.pointer(116), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(668)
            vm.pc = 671
            vm.auxiliary = (0, 1323548673)
            tick(671)
            vm.pc = 676
            vm._write(72, memory.load(cells.pointer(71), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(676)
            vm.pc = 678
            vm._jump(4)
            continue
        if vm.block == 6:
            tick(678)
            _pointer(vm, 678, 18, 0, 120, (21, 38))
            tick(686)
            _pointer(vm, 686, 6, 120, 121, (10, 10))
            tick(694)
            _pointer(vm, 694, 24, 4, 122, (10, 10))
            tick(702)
            vm.pc = 706
            vm._jump(7 if cells.value(123) != 0 else 8)
            continue
        if vm.block == 7:
            tick(706)
            vm.pc = 708
            vm._jump(9)
            continue
        if vm.block == 9:
            tick(708)
            _phi(vm, 708, (124, 2, 122, 7, 125, 10))
            tick(715)
            _phi(vm, 715, (126, 2, 121, 7, 127, 10))
            tick(722)
            _phi(vm, 722, (128, 2, 129, 7, 130, 10))
            tick(729)
            vm.pc = 730
            tick(730)
            vm.pc = 733
            vm.auxiliary = (0, 412680194)
            tick(733)
            vm.pc = 738
            vm._write(130, memory.load(cells.pointer(128), 8, signed=True) + memory.load(cells.pointer(131), 8, signed=True), 8, 'once1.integer')
            tick(738)
            vm.pc = 743
            vm._write(132, int(cells.value(128) > cells.value(10)), 4, 'L31.comparison')
            tick(743)
            vm.pc = 747
            vm._jump(10 if cells.value(132) != 0 else 11)
            continue
        if vm.block == 10:
            tick(747)
            _pointer(vm, 747, 1, 124, 125, (38,))
            tick(754)
            vm.pc = 758
            value = memory.load(cells.value(124), 1)
            vm._write(133, value, 4, 'high.load')
            tick(758)
            _pointer(vm, 758, 1, 126, 127, (38,))
            tick(765)
            vm.pc = 769
            pointer = cells.value(126)
            value = memory.load(cells.pointer(133), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(769)
            vm.pc = 771
            vm._jump(9)
            continue
        if vm.block == 11:
            tick(771)
            vm.pc = 773
            vm._jump(8)
            continue
        if vm.block == 8:
            tick(773)
            _pointer(vm, 773, 18, 0, 134, (21, 135))
            tick(781)
            _pointer(vm, 781, 6, 134, 136, (10, 10))
            tick(789)
            _pointer(vm, 789, 24, 4, 137, (10, 129))
            tick(797)
            vm.pc = 801
            vm._jump(12 if cells.value(123) != 0 else 13)
            continue
        if vm.block == 12:
            tick(801)
            vm.pc = 803
            vm._jump(14)
            continue
        if vm.block == 14:
            tick(803)
            _phi(vm, 803, (138, 2, 137, 12, 139, 15))
            tick(810)
            _phi(vm, 810, (140, 2, 136, 12, 141, 15))
            tick(817)
            _phi(vm, 817, (142, 2, 129, 12, 143, 15))
            tick(824)
            vm.pc = 825
            tick(825)
            vm.pc = 828
            vm.auxiliary = (0, 1965412353)
            tick(828)
            vm.pc = 833
            vm._write(143, memory.load(cells.pointer(142), 8, signed=True) + memory.load(cells.pointer(131), 8, signed=True), 8, 'once1.integer')
            tick(833)
            vm.pc = 838
            vm._write(144, int(cells.value(142) > cells.value(10)), 4, 'L31.comparison')
            tick(838)
            vm.pc = 842
            vm._jump(15 if cells.value(144) != 0 else 16)
            continue
        if vm.block == 15:
            tick(842)
            _pointer(vm, 842, 1, 138, 139, (38,))
            tick(849)
            vm.pc = 853
            value = memory.load(cells.value(138), 1)
            vm._write(145, value, 4, 'high.load')
            tick(853)
            _pointer(vm, 853, 1, 140, 141, (38,))
            tick(860)
            vm.pc = 864
            pointer = cells.value(140)
            value = memory.load(cells.pointer(145), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(864)
            vm.pc = 866
            vm._jump(14)
            continue
        if vm.block == 16:
            tick(866)
            vm.pc = 868
            vm._jump(13)
            continue
        if vm.block == 13:
            tick(868)
            vm.pc = 870
            vm._jump(17)
            continue
        if vm.block == 17:
            tick(870)
            _phi(vm, 870, (146, 2, 21, 13, 147, 18))
            tick(877)
            vm.pc = 878
            tick(878)
            vm.pc = 881
            vm.auxiliary = (0, 677538773)
            tick(881)
            vm.pc = 886
            a = memory.load(cells.pointer(146), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(63), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(148, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(886)
            vm.pc = 890
            vm._jump(18 if cells.value(148) != 0 else 19)
            continue
        if vm.block == 18:
            tick(890)
            _pointer(vm, 890, 18, 0, 149, (21, 21))
            tick(898)
            vm.pc = 903
            cells.copy_q_clear_owned(146, 150)
            tick(903)
            _pointer(vm, 903, 5, 149, 151, (10, 150))
            tick(911)
            vm.pc = 916
            cells.copy_q_clear_owned(151, 152)
            tick(916)
            vm.pc = 921
            vm._write(154, memory.load(cells.pointer(152), 8, signed=True) ^ memory.load(cells.pointer(153), 8, signed=True), 8, 'L14.binary_q')
            tick(921)
            vm.pc = 926
            vm._write(155, cells.value(146) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(926)
            vm.pc = 931
            _convert(vm, 8, 155, 156)
            tick(931)
            vm.pc = 936
            vm._write(157, memory.load(cells.pointer(154), 8, signed=True) ^ memory.load(cells.pointer(156), 8, signed=True), 8, 'L14.binary_q')
            tick(936)
            vm.pc = 941
            vm._write(158, cells.value(157) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(941)
            _pointer(vm, 941, 4, 151, 159, (21, 21))
            tick(949)
            _pointer(vm, 949, 2, 159, 160, (10, 10))
            tick(957)
            vm.pc = 961
            pointer = cells.value(160)
            value = memory.load(cells.pointer(158), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(961)
            vm.pc = 966
            value = memory.load(cells.pointer(152), 8)
            count = memory.load(cells.pointer(161), 1)
            vm._write(162, value >> (count & 63), 8, 'once8.logical_shift')
            tick(966)
            vm.pc = 967
            tick(967)
            vm.pc = 970
            vm.auxiliary = (0, 63519)
            tick(970)
            vm.pc = 976
            vm._write(164, memory.load(cells.pointer(162), 8, signed=True) ^ memory.load(cells.pointer(163), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(976)
            vm.pc = 979
            vm.auxiliary = (0, 910799363)
            tick(979)
            vm.pc = 984
            vm._write(165, memory.load(cells.pointer(146), 4, signed=True) * memory.load(cells.pointer(26), 4, signed=True), 8, 'once0.integer')
            tick(984)
            vm.pc = 989
            vm._write(166, cells.value(165) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(989)
            vm.pc = 994
            _convert(vm, 8, 166, 167)
            tick(994)
            vm.pc = 997
            vm.auxiliary = (0, 47677)
            tick(997)
            vm.pc = 1003
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(168, memory.load(cells.pointer(164), 8, signed=True) ^ memory.load(cells.pointer(167), 8, signed=True), 8, 'typed.selector5.q')
            tick(1003)
            vm.pc = 1008
            vm._write(169, cells.value(168) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1008)
            _pointer(vm, 1008, 2, 159, 170, (10, 13))
            tick(1016)
            vm.pc = 1020
            pointer = cells.value(170)
            value = memory.load(cells.pointer(169), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1020)
            vm.pc = 1023
            vm.auxiliary = (0, 1565700611)
            tick(1023)
            vm.pc = 1028
            vm._write(171, memory.load(cells.pointer(146), 4, signed=True) * memory.load(cells.pointer(93), 4, signed=True), 8, 'once0.integer')
            tick(1028)
            vm.pc = 1033
            vm._write(173, memory.load(cells.pointer(171), 4, signed=True) ^ memory.load(cells.pointer(172), 4, signed=True), 8, 'L14.binary_q')
            tick(1033)
            vm.pc = 1038
            vm._write(174, cells.value(173) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1038)
            _pointer(vm, 1038, 2, 159, 175, (10, 176))
            tick(1046)
            vm.pc = 1050
            pointer = cells.value(175)
            value = memory.load(cells.pointer(174), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1050)
            vm.pc = 1055
            vm._write(178, memory.load(cells.pointer(152), 8, signed=True) ^ memory.load(cells.pointer(177), 8, signed=True), 8, 'L14.binary_q')
            tick(1055)
            vm.pc = 1058
            vm.auxiliary = (0, 312832516)
            tick(1058)
            vm.pc = 1063
            vm._write(180, memory.load(cells.pointer(146), 4, signed=True) * memory.load(cells.pointer(179), 4, signed=True), 8, 'once0.integer')
            tick(1063)
            vm.pc = 1068
            vm._write(181, cells.value(180) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1068)
            vm.pc = 1073
            _convert(vm, 8, 181, 182)
            tick(1073)
            vm.pc = 1076
            vm.auxiliary = (0, 40479)
            tick(1076)
            vm.pc = 1082
            vm._write(183, memory.load(cells.pointer(178), 8, signed=True) ^ memory.load(cells.pointer(182), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(1082)
            vm.pc = 1087
            vm._write(184, cells.value(183) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1087)
            _pointer(vm, 1087, 4, 151, 185, (21, 38))
            tick(1095)
            vm.pc = 1099
            pointer = cells.value(185)
            value = memory.load(cells.pointer(184), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1099)
            vm.pc = 1104
            value = memory.load(cells.pointer(152), 8)
            count = memory.load(cells.pointer(186), 1)
            vm._write(187, value >> (count & 63), 8, 'once8.logical_shift')
            tick(1104)
            vm.pc = 1107
            vm.auxiliary = (0, 27916)
            tick(1107)
            vm.pc = 1113
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(189, memory.load(cells.pointer(187), 8, signed=True) ^ memory.load(cells.pointer(188), 8, signed=True), 8, 'typed.selector5.q')
            tick(1113)
            vm.pc = 1116
            vm.auxiliary = (0, 22861)
            tick(1116)
            vm.pc = 1122
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(190, memory.load(cells.pointer(189), 8, signed=True) ^ memory.load(cells.pointer(156), 8, signed=True), 8, 'typed.selector5.q')
            tick(1122)
            vm.pc = 1127
            vm._write(191, cells.value(190) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1127)
            _pointer(vm, 1127, 4, 151, 192, (21, 135))
            tick(1135)
            _pointer(vm, 1135, 3, 192, 193, (10, 10))
            tick(1143)
            vm.pc = 1147
            pointer = cells.value(193)
            value = memory.load(cells.pointer(191), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1147)
            vm.pc = 1150
            vm.auxiliary = (0, 30822)
            tick(1150)
            vm.pc = 1156
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(195, memory.load(cells.pointer(146), 4, signed=True) ^ memory.load(cells.pointer(194), 4, signed=True), 8, 'typed.selector5.q')
            tick(1156)
            vm.pc = 1161
            vm._write(196, cells.value(195) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1161)
            _pointer(vm, 1161, 3, 192, 197, (10, 13))
            tick(1169)
            vm.pc = 1173
            pointer = cells.value(197)
            value = memory.load(cells.pointer(196), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1173)
            vm.pc = 1176
            vm.auxiliary = (0, 36478)
            tick(1176)
            vm.pc = 1182
            vm._write(198, memory.load(cells.pointer(152), 8, signed=True) ^ memory.load(cells.pointer(156), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(1182)
            vm.pc = 1187
            vm._write(199, cells.value(198) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1187)
            _pointer(vm, 1187, 3, 192, 200, (10, 176))
            tick(1195)
            vm.pc = 1199
            pointer = cells.value(200)
            value = memory.load(cells.pointer(199), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1199)
            vm.pc = 1204
            value = memory.load(cells.pointer(152), 8)
            count = memory.load(cells.pointer(201), 1)
            vm._write(202, value >> (count & 63), 8, 'once8.logical_shift')
            tick(1204)
            vm.pc = 1207
            vm.auxiliary = (0, 28477)
            tick(1207)
            vm.pc = 1213
            vm._write(204, memory.load(cells.pointer(202), 8, signed=True) ^ memory.load(cells.pointer(203), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(1213)
            vm.pc = 1218
            vm._write(205, cells.value(204) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1218)
            _pointer(vm, 1218, 3, 192, 206, (10, 207))
            tick(1226)
            vm.pc = 1230
            pointer = cells.value(206)
            value = memory.load(cells.pointer(205), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1230)
            vm.pc = 1233
            vm.auxiliary = (0, 570335233)
            tick(1233)
            vm.pc = 1238
            vm._write(147, memory.load(cells.pointer(146), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(1238)
            vm.pc = 1240
            vm._jump(17)
            continue
        if vm.block == 19:
            tick(1240)
            vm.pc = 1245
            cells.copy_q_clear_owned(5, 208)
            tick(1245)
            _pointer(vm, 1245, 6, 2, 209, (10, 10))
            tick(1253)
            vm.pc = 1257
            vm._jump(20 if cells.value(123) != 0 else 21)
            continue
        if vm.block == 20:
            tick(1257)
            vm.pc = 1259
            vm._jump(22)
            continue
        if vm.block == 22:
            tick(1259)
            _phi(vm, 1259, (210, 2, 209, 20, 211, 23))
            tick(1266)
            _phi(vm, 1266, (212, 2, 129, 20, 213, 23))
            tick(1273)
            vm.pc = 1274
            tick(1274)
            vm.pc = 1277
            vm.auxiliary = (0, 1915613186)
            tick(1277)
            vm.pc = 1282
            vm._write(213, memory.load(cells.pointer(212), 8, signed=True) + memory.load(cells.pointer(131), 8, signed=True), 8, 'once1.integer')
            tick(1282)
            vm.pc = 1287
            vm._write(214, int(cells.value(212) > cells.value(10)), 4, 'L31.comparison')
            tick(1287)
            vm.pc = 1291
            vm._jump(23 if cells.value(214) != 0 else 24)
            continue
        if vm.block == 23:
            tick(1291)
            _pointer(vm, 1291, 1, 210, 211, (38,))
            tick(1298)
            vm.pc = 1302
            pointer = cells.value(210)
            value = memory.load(cells.pointer(54), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1302)
            vm.pc = 1304
            vm._jump(22)
            continue
        if vm.block == 24:
            tick(1304)
            vm.pc = 1306
            vm._jump(21)
            continue
        if vm.block == 21:
            tick(1306)
            vm.pc = 1310
            pointer = cells.value(3)
            value = memory.load(cells.pointer(207), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(1310)
            vm.pc = 1314
            vm._jump(25 if cells.value(123) != 0 else 26)
            continue
        if vm.block == 25:
            tick(1314)
            vm.pc = 1316
            vm._jump(27)
            continue
        if vm.block == 27:
            tick(1316)
            _phi(vm, 1316, (215, 2, 14, 25, 216, 28))
            tick(1323)
            _phi(vm, 1323, (217, 2, 209, 25, 218, 28))
            tick(1330)
            _phi(vm, 1330, (219, 2, 161, 25, 220, 28))
            tick(1337)
            vm.pc = 1338
            tick(1338)
            vm.pc = 1341
            vm.auxiliary = (0, 959315970)
            tick(1341)
            vm.pc = 1346
            vm._write(220, memory.load(cells.pointer(219), 8, signed=True) + memory.load(cells.pointer(131), 8, signed=True), 8, 'once1.integer')
            tick(1346)
            vm.pc = 1351
            vm._write(221, int(cells.value(219) > cells.value(10)), 4, 'L31.comparison')
            tick(1351)
            vm.pc = 1355
            vm._jump(28 if cells.value(221) != 0 else 29)
            continue
        if vm.block == 28:
            tick(1355)
            _pointer(vm, 1355, 1, 215, 216, (38,))
            tick(1362)
            vm.pc = 1366
            value = memory.load(cells.value(215), 1)
            vm._write(222, value, 4, 'high.load')
            tick(1366)
            _pointer(vm, 1366, 1, 217, 218, (38,))
            tick(1373)
            vm.pc = 1377
            pointer = cells.value(217)
            value = memory.load(cells.pointer(222), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1377)
            vm.pc = 1379
            vm._jump(27)
            continue
        if vm.block == 29:
            tick(1379)
            vm.pc = 1381
            vm._jump(26)
            continue
        if vm.block == 26:
            tick(1381)
            vm.pc = 1385
            value = memory.load(cells.value(25), 1)
            vm._write(223, value, 4, 'high.load')
            tick(1385)
            vm.pc = 1390
            _convert(vm, 4, 223, 224)
            tick(1390)
            vm.pc = 1391
            tick(1391)
            vm.pc = 1394
            vm.auxiliary = (0, 35153)
            tick(1394)
            vm.pc = 1399
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(224), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(225, value, 4, 'typed.selector4.d')
            tick(1399)
            vm.pc = 1402
            vm.auxiliary = (0, 65090)
            tick(1402)
            vm.pc = 1407
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(224), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(226, value, 4, 'typed.selector4.d')
            tick(1407)
            vm.pc = 1410
            vm.auxiliary = (0, 7038)
            tick(1410)
            vm.pc = 1416
            vm._write(227, memory.load(cells.pointer(225), 4, signed=True) ^ memory.load(cells.pointer(226), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1416)
            vm.pc = 1419
            vm.auxiliary = (0, 65280)
            tick(1419)
            vm.pc = 1424
            count = memory.load(cells.pointer(33), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(224), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(228, value, 4, 'typed.selector4.d')
            tick(1424)
            vm.pc = 1427
            vm.auxiliary = (0, 23342)
            tick(1427)
            vm.pc = 1433
            vm._write(229, memory.load(cells.pointer(227), 4, signed=True) ^ memory.load(cells.pointer(228), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1433)
            vm.pc = 1436
            vm.auxiliary = (0, 59771)
            tick(1436)
            vm.pc = 1441
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(224), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(230, value, 4, 'typed.selector4.d')
            tick(1441)
            vm.pc = 1444
            vm.auxiliary = (0, 48389)
            tick(1444)
            vm.pc = 1450
            vm._write(231, memory.load(cells.pointer(229), 4, signed=True) ^ memory.load(cells.pointer(230), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1450)
            vm.pc = 1453
            vm.auxiliary = (0, 45605)
            tick(1453)
            vm.pc = 1458
            vm._write(232, memory.load(cells.pointer(231), 4, signed=True) & memory.load(cells.pointer(38), 4, signed=True), 8, 'typed.selector1.q')
            tick(1458)
            vm.pc = 1463
            vm._write(233, cells.value(232) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1463)
            vm.pc = 1466
            vm.auxiliary = (0, 46846)
            tick(1466)
            _single_control(vm)
            vm.pc = 1471
            count = memory.load(cells.pointer(38), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(224), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(234, value, 4, 'typed.selector3.d')
            tick(1471)
            vm.pc = 1476
            _convert(vm, 4, 233, 235)
            tick(1476)
            vm.pc = 1481
            vm._write(236, memory.load(cells.pointer(234), 4, signed=True) | memory.load(cells.pointer(235), 4, signed=True), 8, 'L15.binary_q')
            tick(1481)
            vm.pc = 1486
            vm._write(237, cells.value(236) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1486)
            vm.pc = 1491
            _convert(vm, 4, 237, 238)
            tick(1491)
            vm.pc = 1494
            vm.auxiliary = (0, 16213)
            tick(1494)
            vm.pc = 1500
            vm._write(239, memory.load(cells.pointer(238), 4, signed=True) ^ memory.load(cells.pointer(93), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1500)
            vm.pc = 1505
            vm._write(240, cells.value(239) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1505)
            vm.pc = 1510
            _convert(vm, 4, 240, 241)
            tick(1510)
            vm.pc = 1513
            vm.auxiliary = (0, 13975)
            tick(1513)
            _single_control(vm)
            vm.pc = 1518
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(241), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(242, value, 4, 'typed.selector3.d')
            tick(1518)
            vm.pc = 1521
            vm.auxiliary = (0, 19787)
            tick(1521)
            vm.pc = 1526
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(241), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(243, value, 4, 'typed.selector4.d')
            tick(1526)
            vm.pc = 1529
            vm.auxiliary = (0, 18328)
            tick(1529)
            vm.pc = 1534
            vm._write(244, memory.load(cells.pointer(242), 4, signed=True) | memory.load(cells.pointer(243), 4, signed=True), 8, 'typed.selector2.q')
            tick(1534)
            vm.pc = 1539
            vm._write(245, cells.value(244) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1539)
            vm.pc = 1542
            vm.auxiliary = (0, 542249556)
            tick(1542)
            vm.pc = 1547
            vm._write(246, int(memory.load(cells.pointer(245), 1, signed=True) != memory.load(cells.pointer(54), 1, signed=True)), 4, 'L30.comparison')
            tick(1547)
            vm.pc = 1554
            selected = 245 if cells.value(246) != 0 else 247
            vm._write(248, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(1554)
            _pointer(vm, 1554, 6, 5, 249, (10, 10))
            tick(1562)
            vm.pc = 1566
            pointer = cells.value(249)
            value = memory.load(cells.pointer(248), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1566)
            vm.pc = 1568
            vm._jump(30)
            continue
        if vm.block == 30:
            tick(1568)
            _phi(vm, 1568, (250, 2, 251, 26, 252, 31))
            tick(1575)
            vm.pc = 1580
            _convert(vm, 4, 250, 253)
            tick(1580)
            vm.pc = 1581
            tick(1581)
            vm.pc = 1584
            vm.auxiliary = (0, 1606611973)
            tick(1584)
            vm.pc = 1589
            a = memory.load(cells.pointer(253), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(254), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(255, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(1589)
            vm.pc = 1593
            vm._jump(31 if cells.value(255) != 0 else 32)
            continue
        if vm.block == 31:
            tick(1593)
            vm.pc = 1594
            tick(1594)
            vm.pc = 1597
            vm.auxiliary = (0, 17515)
            tick(1597)
            vm.pc = 1602
            vm._write(256, memory.load(cells.pointer(253), 4, signed=True) - memory.load(cells.pointer(38), 4, signed=True), 8, 'typed.selector0.q')
            tick(1602)
            vm.pc = 1607
            cells.copy_q_clear_owned(256, 257)
            tick(1607)
            _pointer(vm, 1607, 6, 5, 258, (10, 257))
            tick(1615)
            vm.pc = 1619
            value = memory.load(cells.value(258), 1)
            vm._write(259, value, 4, 'high.load')
            tick(1619)
            vm.pc = 1624
            _convert(vm, 4, 259, 260)
            tick(1624)
            vm.pc = 1627
            vm.auxiliary = (0, 64033)
            tick(1627)
            vm.pc = 1632
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(260), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(261, value, 4, 'typed.selector4.d')
            tick(1632)
            vm.pc = 1635
            vm.auxiliary = (0, 56937)
            tick(1635)
            vm.pc = 1640
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(260), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(262, value, 4, 'typed.selector4.d')
            tick(1640)
            vm.pc = 1643
            vm.auxiliary = (0, 40805)
            tick(1643)
            vm.pc = 1649
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(263, memory.load(cells.pointer(261), 4, signed=True) ^ memory.load(cells.pointer(262), 4, signed=True), 8, 'typed.selector5.q')
            tick(1649)
            vm.pc = 1652
            vm.auxiliary = (0, 60753)
            tick(1652)
            vm.pc = 1657
            count = memory.load(cells.pointer(33), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(260), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(264, value, 4, 'typed.selector4.d')
            tick(1657)
            vm.pc = 1660
            vm.auxiliary = (0, 43111)
            tick(1660)
            vm.pc = 1666
            vm._write(265, memory.load(cells.pointer(263), 4, signed=True) ^ memory.load(cells.pointer(264), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1666)
            vm.pc = 1669
            vm.auxiliary = (0, 56577)
            tick(1669)
            vm.pc = 1674
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(260), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(266, value, 4, 'typed.selector4.d')
            tick(1674)
            vm.pc = 1677
            vm.auxiliary = (0, 22886)
            tick(1677)
            vm.pc = 1683
            vm._write(267, memory.load(cells.pointer(265), 4, signed=True) ^ memory.load(cells.pointer(266), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1683)
            vm.pc = 1686
            vm.auxiliary = (0, 5214)
            tick(1686)
            vm.pc = 1691
            vm._write(268, memory.load(cells.pointer(267), 4, signed=True) & memory.load(cells.pointer(38), 4, signed=True), 8, 'typed.selector1.q')
            tick(1691)
            vm.pc = 1696
            vm._write(269, cells.value(268) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1696)
            vm.pc = 1699
            vm.auxiliary = (0, 34527)
            tick(1699)
            _single_control(vm)
            vm.pc = 1704
            count = memory.load(cells.pointer(38), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(260), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(270, value, 4, 'typed.selector3.d')
            tick(1704)
            vm.pc = 1709
            _convert(vm, 4, 269, 271)
            tick(1709)
            vm.pc = 1714
            vm._write(272, memory.load(cells.pointer(270), 4, signed=True) | memory.load(cells.pointer(271), 4, signed=True), 8, 'L15.binary_q')
            tick(1714)
            vm.pc = 1719
            vm._write(273, cells.value(272) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1719)
            vm.pc = 1722
            vm.auxiliary = (0, 1119470083)
            tick(1722)
            vm.pc = 1727
            vm._write(274, memory.load(cells.pointer(253), 4, signed=True) * memory.load(cells.pointer(91), 4, signed=True), 8, 'once0.integer')
            tick(1727)
            vm.pc = 1730
            vm.auxiliary = (0, 2076348417)
            tick(1730)
            vm.pc = 1735
            vm._write(275, memory.load(cells.pointer(274), 4, signed=True) + memory.load(cells.pointer(93), 4, signed=True), 8, 'once1.integer')
            tick(1735)
            vm.pc = 1740
            vm._write(276, cells.value(275) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1740)
            vm.pc = 1745
            _convert(vm, 4, 276, 277)
            tick(1745)
            vm.pc = 1750
            _convert(vm, 4, 273, 278)
            tick(1750)
            vm.pc = 1753
            vm.auxiliary = (0, 55853)
            tick(1753)
            vm.pc = 1759
            vm._write(279, memory.load(cells.pointer(278), 4, signed=True) ^ memory.load(cells.pointer(277), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1759)
            vm.pc = 1764
            vm._write(280, cells.value(279) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1764)
            vm.pc = 1769
            _convert(vm, 4, 280, 281)
            tick(1769)
            vm.pc = 1772
            vm.auxiliary = (0, 17621)
            tick(1772)
            _single_control(vm)
            vm.pc = 1777
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(281), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(282, value, 4, 'typed.selector3.d')
            tick(1777)
            vm.pc = 1780
            vm.auxiliary = (0, 60705)
            tick(1780)
            vm.pc = 1785
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(281), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(283, value, 4, 'typed.selector4.d')
            tick(1785)
            vm.pc = 1788
            vm.auxiliary = (0, 50600)
            tick(1788)
            vm.pc = 1793
            vm._write(284, memory.load(cells.pointer(282), 4, signed=True) | memory.load(cells.pointer(283), 4, signed=True), 8, 'typed.selector2.q')
            tick(1793)
            vm.pc = 1798
            vm._write(285, cells.value(284) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1798)
            vm.pc = 1801
            vm.auxiliary = (0, 1438782660)
            tick(1801)
            vm.pc = 1806
            vm._write(286, int(memory.load(cells.pointer(285), 1, signed=True) != memory.load(cells.pointer(54), 1, signed=True)), 4, 'L30.comparison')
            tick(1806)
            vm.pc = 1809
            vm.auxiliary = (0, 11341)
            tick(1809)
            vm.pc = 1815
            vm._write(287, memory.load(cells.pointer(253), 4, signed=True) ^ memory.load(cells.pointer(106), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1815)
            vm.pc = 1820
            vm._write(288, cells.value(287) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1820)
            vm.pc = 1827
            selected = 285 if cells.value(286) != 0 else 288
            vm._write(289, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(1827)
            vm.pc = 1832
            _convert(vm, 8, 250, 290)
            tick(1832)
            _pointer(vm, 1832, 6, 5, 291, (10, 290))
            tick(1840)
            vm.pc = 1844
            pointer = cells.value(291)
            value = memory.load(cells.pointer(289), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1844)
            vm.pc = 1847
            vm.auxiliary = (0, 655286273)
            tick(1847)
            vm.pc = 1852
            vm._write(252, memory.load(cells.pointer(250), 1, signed=True) + memory.load(cells.pointer(251), 1, signed=True), 8, 'once1.integer')
            tick(1852)
            vm.pc = 1854
            vm._jump(30)
            continue
        if vm.block == 32:
            tick(1854)
            vm.pc = 1856
            vm._jump(33)
            continue
        if vm.block == 33:
            tick(1856)
            _phi(vm, 1856, (292, 2, 21, 32, 293, 34))
            tick(1863)
            vm.pc = 1864
            tick(1864)
            vm.pc = 1867
            vm.auxiliary = (0, 331510661)
            tick(1867)
            vm.pc = 1872
            a = memory.load(cells.pointer(292), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(254), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(294, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(1872)
            vm.pc = 1876
            vm._jump(34 if cells.value(294) != 0 else 35)
            continue
        if vm.block == 34:
            tick(1876)
            vm.pc = 1881
            cells.copy_q_clear_owned(292, 295)
            tick(1881)
            _pointer(vm, 1881, 6, 120, 296, (10, 295))
            tick(1889)
            vm.pc = 1893
            value = memory.load(cells.value(296), 1)
            vm._write(297, value, 4, 'high.load')
            tick(1893)
            _pointer(vm, 1893, 6, 2, 298, (10, 295))
            tick(1901)
            vm.pc = 1905
            value = memory.load(cells.value(298), 1)
            vm._write(299, value, 4, 'high.load')
            tick(1905)
            vm.pc = 1910
            _convert(vm, 4, 299, 300)
            tick(1910)
            _pointer(vm, 1910, 6, 5, 301, (10, 295))
            tick(1918)
            vm.pc = 1922
            value = memory.load(cells.value(301), 1)
            vm._write(302, value, 4, 'high.load')
            tick(1922)
            vm.pc = 1927
            _convert(vm, 4, 302, 303)
            tick(1927)
            vm.pc = 1932
            vm._write(304, memory.load(cells.pointer(300), 4, signed=True) ^ memory.load(cells.pointer(303), 4, signed=True), 8, 'L14.binary_q')
            tick(1932)
            vm.pc = 1937
            vm._write(305, cells.value(304) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1937)
            _pointer(vm, 1937, 18, 0, 306, (21, 21))
            tick(1945)
            vm.pc = 1950
            _convert(vm, 8, 297, 307)
            tick(1950)
            _pointer(vm, 1950, 5, 306, 308, (10, 307))
            tick(1958)
            _pointer(vm, 1958, 4, 308, 309, (21, 38))
            tick(1966)
            vm.pc = 1970
            pointer = cells.value(309)
            value = memory.load(cells.pointer(305), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1970)
            vm.pc = 1974
            value = memory.load(cells.value(301), 1)
            vm._write(310, value, 4, 'high.load')
            tick(1974)
            vm.pc = 1979
            _convert(vm, 4, 310, 311)
            tick(1979)
            vm.pc = 1984
            vm._write(312, cells.value(292) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1984)
            vm.pc = 1989
            _convert(vm, 4, 312, 313)
            tick(1989)
            vm.pc = 1994
            vm._write(314, memory.load(cells.pointer(311), 4, signed=True) ^ memory.load(cells.pointer(313), 4, signed=True), 8, 'L14.binary_q')
            tick(1994)
            vm.pc = 1999
            vm._write(315, cells.value(314) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(1999)
            _pointer(vm, 1999, 4, 308, 316, (21, 21))
            tick(2007)
            _pointer(vm, 2007, 2, 316, 317, (10, 10))
            tick(2015)
            vm.pc = 2019
            pointer = cells.value(317)
            value = memory.load(cells.pointer(315), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2019)
            vm.pc = 2023
            value = memory.load(cells.value(301), 1)
            vm._write(318, value, 4, 'high.load')
            tick(2023)
            vm.pc = 2028
            _convert(vm, 4, 318, 319)
            tick(2028)
            vm.pc = 2033
            vm._write(321, memory.load(cells.pointer(319), 4, signed=True) ^ memory.load(cells.pointer(320), 4, signed=True), 8, 'L14.binary_q')
            tick(2033)
            vm.pc = 2038
            vm._write(322, cells.value(321) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2038)
            _pointer(vm, 2038, 4, 308, 323, (21, 135))
            tick(2046)
            _pointer(vm, 2046, 3, 323, 324, (10, 10))
            tick(2054)
            vm.pc = 2058
            pointer = cells.value(324)
            value = memory.load(cells.pointer(322), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2058)
            vm.pc = 2059
            tick(2059)
            vm.pc = 2062
            vm.auxiliary = (0, 505585665)
            tick(2062)
            vm.pc = 2067
            vm._write(293, memory.load(cells.pointer(292), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(2067)
            vm.pc = 2069
            vm._jump(33)
            continue
        if vm.block == 35:
            tick(2069)
            vm.pc = 2073
            value = memory.load(cells.value(25), 1)
            vm._write(325, value, 4, 'high.load')
            tick(2073)
            vm.pc = 2078
            _convert(vm, 4, 325, 326)
            tick(2078)
            vm.pc = 2082
            value = memory.load(cells.value(58), 1)
            vm._write(327, value, 4, 'high.load')
            tick(2082)
            vm.pc = 2087
            _convert(vm, 4, 327, 328)
            tick(2087)
            vm.pc = 2092
            vm._write(329, memory.load(cells.pointer(326), 4, signed=True) ^ memory.load(cells.pointer(328), 4, signed=True), 8, 'L14.binary_q')
            tick(2092)
            vm.pc = 2097
            vm._write(330, cells.value(329) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2097)
            vm.pc = 2099
            vm._jump(36)
            continue
        if vm.block == 36:
            tick(2099)
            _phi(vm, 2099, (331, 2, 330, 35, 332, 37))
            tick(2106)
            _phi(vm, 2106, (333, 2, 21, 35, 334, 37))
            tick(2113)
            vm.pc = 2114
            tick(2114)
            vm.pc = 2117
            vm.auxiliary = (0, 2005046885)
            tick(2117)
            vm.pc = 2122
            a = memory.load(cells.pointer(333), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(63), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(335, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(2122)
            vm.pc = 2126
            vm._jump(38 if cells.value(335) != 0 else 39)
            continue
        if vm.block == 38:
            tick(2126)
            vm.pc = 2128
            vm._jump(40)
            continue
        if vm.block == 40:
            tick(2128)
            _phi(vm, 2128, (336, 2, 21, 38, 337, 41))
            tick(2135)
            vm.pc = 2136
            tick(2136)
            vm.pc = 2139
            vm.auxiliary = (0, 1278400261)
            tick(2139)
            vm.pc = 2144
            a = memory.load(cells.pointer(336), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(254), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(338, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(2144)
            vm.pc = 2148
            vm._jump(42 if cells.value(338) != 0 else 43)
            continue
        if vm.block == 42:
            tick(2148)
            vm.pc = 2153
            cells.copy_q_clear_owned(336, 339)
            tick(2153)
            _pointer(vm, 2153, 6, 120, 340, (10, 339))
            tick(2161)
            vm.pc = 2165
            value = memory.load(cells.value(340), 1)
            vm._write(341, value, 4, 'high.load')
            tick(2165)
            vm.pc = 2170
            _convert(vm, 4, 341, 342)
            tick(2170)
            vm.pc = 2175
            vm._write(343, cells.value(333) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2175)
            vm.pc = 2180
            _convert(vm, 4, 343, 344)
            tick(2180)
            vm.pc = 2181
            tick(2181)
            vm.pc = 2184
            vm.auxiliary = (0, 824340435)
            tick(2184)
            _equal(vm, 2189, 4, 342, 344, 345)
            tick(2189)
            vm.pc = 2193
            vm._jump(44 if cells.value(345) != 0 else 45)
            continue
        if vm.block == 45:
            tick(2193)
            _pointer(vm, 2193, 6, 134, 346, (10, 339))
            tick(2201)
            vm.pc = 2205
            value = memory.load(cells.value(346), 1)
            vm._write(347, value, 4, 'high.load')
            tick(2205)
            vm.pc = 2210
            _convert(vm, 4, 347, 348)
            tick(2210)
            vm.pc = 2211
            tick(2211)
            vm.pc = 2214
            vm.auxiliary = (0, 749911555)
            tick(2214)
            _equal(vm, 2219, 4, 348, 344, 349)
            tick(2219)
            vm.pc = 2223
            vm._jump(44 if cells.value(349) != 0 else 41)
            continue
        if vm.block == 44:
            tick(2223)
            vm.pc = 2225
            vm._jump(43)
            continue
        if vm.block == 41:
            tick(2225)
            vm.pc = 2226
            tick(2226)
            vm.pc = 2229
            vm.auxiliary = (0, 663592962)
            tick(2229)
            vm.pc = 2234
            vm._write(337, memory.load(cells.pointer(336), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(2234)
            vm.pc = 2236
            vm._jump(40)
            continue
        if vm.block == 43:
            tick(2236)
            _phi(vm, 2236, (350, 2, 38, 44, 21, 40))
            tick(2243)
            vm.pc = 2244
            tick(2244)
            vm.pc = 2247
            vm.auxiliary = (0, 272796900)
            tick(2247)
            vm.pc = 2252
            vm._write(351, int(memory.load(cells.pointer(350), 4, signed=True) != memory.load(cells.pointer(21), 4, signed=True)), 4, 'L30.comparison')
            tick(2252)
            vm.pc = 2256
            vm._jump(37 if cells.value(351) != 0 else 46)
            continue
        if vm.block == 46:
            tick(2256)
            vm.pc = 2261
            _convert(vm, 4, 331, 352)
            tick(2261)
            vm.pc = 2262
            tick(2262)
            vm.pc = 2265
            vm.auxiliary = (0, 22891)
            tick(2265)
            vm.pc = 2270
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(352), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(353, value, 4, 'typed.selector4.d')
            tick(2270)
            vm.pc = 2273
            vm.auxiliary = (0, 14883)
            tick(2273)
            vm.pc = 2278
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(352), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(354, value, 4, 'typed.selector4.d')
            tick(2278)
            vm.pc = 2281
            vm.auxiliary = (0, 12142)
            tick(2281)
            vm.pc = 2287
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(355, memory.load(cells.pointer(353), 4, signed=True) ^ memory.load(cells.pointer(354), 4, signed=True), 8, 'typed.selector5.q')
            tick(2287)
            vm.pc = 2290
            vm.auxiliary = (0, 16243)
            tick(2290)
            vm.pc = 2295
            count = memory.load(cells.pointer(33), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(352), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(356, value, 4, 'typed.selector4.d')
            tick(2295)
            vm.pc = 2300
            vm._write(357, memory.load(cells.pointer(355), 4, signed=True) ^ memory.load(cells.pointer(356), 4, signed=True), 8, 'L14.binary_q')
            tick(2300)
            vm.pc = 2303
            vm.auxiliary = (0, 30833)
            tick(2303)
            vm.pc = 2308
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(352), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(358, value, 4, 'typed.selector4.d')
            tick(2308)
            vm.pc = 2313
            vm._write(359, memory.load(cells.pointer(357), 4, signed=True) ^ memory.load(cells.pointer(358), 4, signed=True), 8, 'L14.binary_q')
            tick(2313)
            vm.pc = 2318
            vm._write(360, memory.load(cells.pointer(359), 4, signed=True) & memory.load(cells.pointer(38), 4, signed=True), 8, 'L13.binary_q')
            tick(2318)
            vm.pc = 2323
            vm._write(361, cells.value(360) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2323)
            vm.pc = 2326
            vm.auxiliary = (0, 16828)
            tick(2326)
            _single_control(vm)
            vm.pc = 2331
            count = memory.load(cells.pointer(38), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(352), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(362, value, 4, 'typed.selector3.d')
            tick(2331)
            vm.pc = 2336
            _convert(vm, 4, 361, 363)
            tick(2336)
            vm.pc = 2339
            vm.auxiliary = (0, 26074)
            tick(2339)
            vm.pc = 2344
            vm._write(364, memory.load(cells.pointer(362), 4, signed=True) | memory.load(cells.pointer(363), 4, signed=True), 8, 'typed.selector2.q')
            tick(2344)
            vm.pc = 2349
            vm._write(365, cells.value(364) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2349)
            vm.pc = 2354
            vm._write(366, cells.value(333) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2354)
            vm.pc = 2359
            _convert(vm, 4, 366, 367)
            tick(2359)
            vm.pc = 2362
            vm.auxiliary = (0, 256291332)
            tick(2362)
            vm.pc = 2367
            vm._write(368, memory.load(cells.pointer(367), 4, signed=True) * memory.load(cells.pointer(91), 4, signed=True), 8, 'once0.integer')
            tick(2367)
            vm.pc = 2370
            vm.auxiliary = (0, 1565626369)
            tick(2370)
            vm.pc = 2375
            vm._write(369, memory.load(cells.pointer(368), 4, signed=True) + memory.load(cells.pointer(93), 4, signed=True), 8, 'once1.integer')
            tick(2375)
            vm.pc = 2380
            vm._write(370, cells.value(369) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2380)
            vm.pc = 2385
            _convert(vm, 4, 370, 371)
            tick(2385)
            vm.pc = 2390
            _convert(vm, 4, 365, 372)
            tick(2390)
            vm.pc = 2395
            vm._write(373, memory.load(cells.pointer(372), 4, signed=True) ^ memory.load(cells.pointer(371), 4, signed=True), 8, 'L14.binary_q')
            tick(2395)
            vm.pc = 2400
            vm._write(374, cells.value(373) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2400)
            vm.pc = 2405
            _convert(vm, 4, 374, 375)
            tick(2405)
            vm.pc = 2408
            vm.auxiliary = (0, 62893)
            tick(2408)
            _single_control(vm)
            vm.pc = 2413
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(375), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(376, value, 4, 'typed.selector3.d')
            tick(2413)
            vm.pc = 2416
            vm.auxiliary = (0, 32297)
            tick(2416)
            vm.pc = 2421
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(375), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(377, value, 4, 'typed.selector4.d')
            tick(2421)
            vm.pc = 2426
            vm._write(378, memory.load(cells.pointer(376), 4, signed=True) | memory.load(cells.pointer(377), 4, signed=True), 8, 'L15.binary_q')
            tick(2426)
            vm.pc = 2431
            vm._write(379, cells.value(378) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2431)
            vm.pc = 2434
            vm.auxiliary = (0, 997353620)
            tick(2434)
            vm.pc = 2439
            vm._write(380, int(memory.load(cells.pointer(379), 1, signed=True) != memory.load(cells.pointer(54), 1, signed=True)), 4, 'L30.comparison')
            tick(2439)
            vm.pc = 2444
            vm._write(381, memory.load(cells.pointer(367), 4, signed=True) ^ memory.load(cells.pointer(106), 4, signed=True), 8, 'L14.binary_q')
            tick(2444)
            vm.pc = 2449
            vm._write(382, cells.value(381) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2449)
            vm.pc = 2456
            selected = 379 if cells.value(380) != 0 else 382
            vm._write(383, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(2456)
            _pointer(vm, 2456, 18, 0, 384, (21, 21))
            tick(2464)
            vm.pc = 2469
            cells.copy_q_clear_owned(333, 385)
            tick(2469)
            _pointer(vm, 2469, 5, 384, 386, (10, 385))
            tick(2477)
            _pointer(vm, 2477, 4, 386, 387, (21, 38))
            tick(2485)
            vm.pc = 2489
            pointer = cells.value(387)
            value = memory.load(cells.pointer(383), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2489)
            vm.pc = 2494
            _convert(vm, 4, 383, 388)
            tick(2494)
            vm.pc = 2497
            vm.auxiliary = (0, 14373)
            tick(2497)
            vm.pc = 2503
            vm._write(389, memory.load(cells.pointer(388), 4, signed=True) ^ memory.load(cells.pointer(367), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(2503)
            vm.pc = 2508
            vm._write(390, cells.value(389) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2508)
            _pointer(vm, 2508, 4, 386, 391, (21, 21))
            tick(2516)
            _pointer(vm, 2516, 2, 391, 392, (10, 10))
            tick(2524)
            vm.pc = 2528
            pointer = cells.value(392)
            value = memory.load(cells.pointer(390), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2528)
            vm.pc = 2531
            vm.auxiliary = (0, 59749)
            tick(2531)
            vm.pc = 2537
            vm._write(393, memory.load(cells.pointer(388), 4, signed=True) ^ memory.load(cells.pointer(320), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(2537)
            vm.pc = 2542
            vm._write(394, cells.value(393) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2542)
            _pointer(vm, 2542, 4, 386, 395, (21, 135))
            tick(2550)
            _pointer(vm, 2550, 3, 395, 396, (10, 10))
            tick(2558)
            vm.pc = 2562
            pointer = cells.value(396)
            value = memory.load(cells.pointer(394), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2562)
            vm.pc = 2564
            vm._jump(37)
            continue
        if vm.block == 37:
            tick(2564)
            _phi(vm, 2564, (332, 2, 331, 43, 383, 46))
            tick(2571)
            vm.pc = 2572
            tick(2572)
            vm.pc = 2575
            vm.auxiliary = (0, 1819398146)
            tick(2575)
            vm.pc = 2580
            vm._write(334, memory.load(cells.pointer(333), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(2580)
            vm.pc = 2582
            vm._jump(36)
            continue
        if vm.block == 39:
            tick(2582)
            vm.pc = 2587
            cells.copy_q_clear_owned(6, 397)
            tick(2587)
            vm.pc = 2591
            vm._jump(47 if cells.value(123) != 0 else 48)
            continue
        if vm.block == 47:
            tick(2591)
            vm.pc = 2593
            vm._jump(49)
            continue
        if vm.block == 49:
            tick(2593)
            _phi(vm, 2593, (398, 2, 129, 47, 399, 50))
            tick(2600)
            _phi(vm, 2600, (400, 2, 209, 47, 401, 50))
            tick(2607)
            vm.pc = 2608
            tick(2608)
            vm.pc = 2611
            vm.auxiliary = (0, 1220857857)
            tick(2611)
            vm.pc = 2616
            vm._write(399, memory.load(cells.pointer(398), 8, signed=True) + memory.load(cells.pointer(131), 8, signed=True), 8, 'once1.integer')
            tick(2616)
            vm.pc = 2621
            vm._write(402, int(cells.value(398) > cells.value(10)), 4, 'L31.comparison')
            tick(2621)
            vm.pc = 2625
            vm._jump(50 if cells.value(402) != 0 else 51)
            continue
        if vm.block == 50:
            tick(2625)
            _pointer(vm, 2625, 1, 400, 401, (38,))
            tick(2632)
            vm.pc = 2636
            pointer = cells.value(400)
            value = memory.load(cells.pointer(54), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2636)
            vm.pc = 2638
            vm._jump(49)
            continue
        if vm.block == 51:
            tick(2638)
            vm.pc = 2640
            vm._jump(48)
            continue
        if vm.block == 48:
            tick(2640)
            vm.pc = 2644
            value = memory.load(cells.value(58), 1)
            vm._write(403, value, 4, 'high.load')
            tick(2644)
            vm.pc = 2649
            _convert(vm, 4, 403, 404)
            tick(2649)
            vm.pc = 2650
            tick(2650)
            vm.pc = 2653
            vm.auxiliary = (0, 64114)
            tick(2653)
            vm.pc = 2658
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(404), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(405, value, 4, 'typed.selector4.d')
            tick(2658)
            vm.pc = 2661
            vm.auxiliary = (0, 43889)
            tick(2661)
            vm.pc = 2666
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(404), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(406, value, 4, 'typed.selector4.d')
            tick(2666)
            vm.pc = 2669
            vm.auxiliary = (0, 53076)
            tick(2669)
            vm.pc = 2675
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(407, memory.load(cells.pointer(405), 4, signed=True) ^ memory.load(cells.pointer(406), 4, signed=True), 8, 'typed.selector5.q')
            tick(2675)
            vm.pc = 2678
            vm.auxiliary = (0, 16130)
            tick(2678)
            vm.pc = 2683
            count = memory.load(cells.pointer(33), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(404), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(408, value, 4, 'typed.selector4.d')
            tick(2683)
            vm.pc = 2686
            vm.auxiliary = (0, 39438)
            tick(2686)
            vm.pc = 2692
            vm._write(409, memory.load(cells.pointer(407), 4, signed=True) ^ memory.load(cells.pointer(408), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(2692)
            vm.pc = 2695
            vm.auxiliary = (0, 10248)
            tick(2695)
            vm.pc = 2700
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(404), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(410, value, 4, 'typed.selector4.d')
            tick(2700)
            vm.pc = 2703
            vm.auxiliary = (0, 48239)
            tick(2703)
            vm.pc = 2709
            vm._write(411, memory.load(cells.pointer(409), 4, signed=True) ^ memory.load(cells.pointer(410), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(2709)
            vm.pc = 2714
            vm._write(412, memory.load(cells.pointer(411), 4, signed=True) & memory.load(cells.pointer(38), 4, signed=True), 8, 'L13.binary_q')
            tick(2714)
            vm.pc = 2719
            vm._write(413, cells.value(412) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2719)
            vm.pc = 2722
            vm.auxiliary = (0, 16780)
            tick(2722)
            _single_control(vm)
            vm.pc = 2727
            count = memory.load(cells.pointer(38), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(404), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(414, value, 4, 'typed.selector3.d')
            tick(2727)
            vm.pc = 2732
            _convert(vm, 4, 413, 415)
            tick(2732)
            vm.pc = 2737
            vm._write(416, memory.load(cells.pointer(414), 4, signed=True) | memory.load(cells.pointer(415), 4, signed=True), 8, 'L15.binary_q')
            tick(2737)
            vm.pc = 2742
            vm._write(417, cells.value(416) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2742)
            vm.pc = 2747
            _convert(vm, 4, 417, 418)
            tick(2747)
            vm.pc = 2752
            vm._write(419, memory.load(cells.pointer(418), 4, signed=True) ^ memory.load(cells.pointer(93), 4, signed=True), 8, 'L14.binary_q')
            tick(2752)
            vm.pc = 2757
            vm._write(420, cells.value(419) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2757)
            vm.pc = 2762
            _convert(vm, 4, 420, 421)
            tick(2762)
            vm.pc = 2765
            vm.auxiliary = (0, 22479)
            tick(2765)
            _single_control(vm)
            vm.pc = 2770
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(421), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(422, value, 4, 'typed.selector3.d')
            tick(2770)
            vm.pc = 2773
            vm.auxiliary = (0, 27194)
            tick(2773)
            vm.pc = 2778
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(421), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(423, value, 4, 'typed.selector4.d')
            tick(2778)
            vm.pc = 2781
            vm.auxiliary = (0, 38113)
            tick(2781)
            vm.pc = 2786
            vm._write(424, memory.load(cells.pointer(422), 4, signed=True) | memory.load(cells.pointer(423), 4, signed=True), 8, 'typed.selector2.q')
            tick(2786)
            vm.pc = 2791
            vm._write(425, cells.value(424) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2791)
            vm.pc = 2794
            vm.auxiliary = (0, 853735060)
            tick(2794)
            vm.pc = 2799
            vm._write(426, int(memory.load(cells.pointer(425), 1, signed=True) != memory.load(cells.pointer(54), 1, signed=True)), 4, 'L30.comparison')
            tick(2799)
            vm.pc = 2806
            selected = 425 if cells.value(426) != 0 else 247
            vm._write(427, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(2806)
            _pointer(vm, 2806, 6, 6, 428, (10, 10))
            tick(2814)
            vm.pc = 2818
            pointer = cells.value(428)
            value = memory.load(cells.pointer(427), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2818)
            vm.pc = 2820
            vm._jump(52)
            continue
        if vm.block == 52:
            tick(2820)
            _phi(vm, 2820, (429, 2, 251, 48, 430, 53))
            tick(2827)
            vm.pc = 2832
            _convert(vm, 4, 429, 431)
            tick(2832)
            vm.pc = 2833
            tick(2833)
            vm.pc = 2836
            vm.auxiliary = (0, 692218549)
            tick(2836)
            vm.pc = 2841
            a = memory.load(cells.pointer(431), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(254), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(432, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(2841)
            vm.pc = 2845
            vm._jump(53 if cells.value(432) != 0 else 54)
            continue
        if vm.block == 53:
            tick(2845)
            vm.pc = 2846
            tick(2846)
            vm.pc = 2849
            vm.auxiliary = (0, 50490)
            tick(2849)
            vm.pc = 2854
            vm._write(433, memory.load(cells.pointer(431), 4, signed=True) - memory.load(cells.pointer(38), 4, signed=True), 8, 'typed.selector0.q')
            tick(2854)
            vm.pc = 2859
            cells.copy_q_clear_owned(433, 434)
            tick(2859)
            _pointer(vm, 2859, 6, 6, 435, (10, 434))
            tick(2867)
            vm.pc = 2871
            value = memory.load(cells.value(435), 1)
            vm._write(436, value, 4, 'high.load')
            tick(2871)
            vm.pc = 2876
            _convert(vm, 4, 436, 437)
            tick(2876)
            vm.pc = 2879
            vm.auxiliary = (0, 10819)
            tick(2879)
            vm.pc = 2884
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(437), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(438, value, 4, 'typed.selector4.d')
            tick(2884)
            vm.pc = 2887
            vm.auxiliary = (0, 27658)
            tick(2887)
            vm.pc = 2892
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(437), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(439, value, 4, 'typed.selector4.d')
            tick(2892)
            vm.pc = 2895
            vm.auxiliary = (0, 28461)
            tick(2895)
            vm.pc = 2901
            vm._write(440, memory.load(cells.pointer(438), 4, signed=True) ^ memory.load(cells.pointer(439), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(2901)
            vm.pc = 2904
            vm.auxiliary = (0, 40747)
            tick(2904)
            vm.pc = 2909
            count = memory.load(cells.pointer(33), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(437), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(441, value, 4, 'typed.selector4.d')
            tick(2909)
            vm.pc = 2912
            vm.auxiliary = (0, 19766)
            tick(2912)
            vm.pc = 2918
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(442, memory.load(cells.pointer(440), 4, signed=True) ^ memory.load(cells.pointer(441), 4, signed=True), 8, 'typed.selector5.q')
            tick(2918)
            vm.pc = 2921
            vm.auxiliary = (0, 59410)
            tick(2921)
            vm.pc = 2926
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(437), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(443, value, 4, 'typed.selector4.d')
            tick(2926)
            vm.pc = 2931
            vm._write(444, memory.load(cells.pointer(442), 4, signed=True) ^ memory.load(cells.pointer(443), 4, signed=True), 8, 'L14.binary_q')
            tick(2931)
            vm.pc = 2934
            vm.auxiliary = (0, 32820)
            tick(2934)
            vm.pc = 2939
            vm._write(445, memory.load(cells.pointer(444), 4, signed=True) & memory.load(cells.pointer(38), 4, signed=True), 8, 'typed.selector1.q')
            tick(2939)
            vm.pc = 2944
            vm._write(446, cells.value(445) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2944)
            vm.pc = 2947
            vm.auxiliary = (0, 42132)
            tick(2947)
            _single_control(vm)
            vm.pc = 2952
            count = memory.load(cells.pointer(38), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(437), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(447, value, 4, 'typed.selector3.d')
            tick(2952)
            vm.pc = 2957
            _convert(vm, 4, 446, 448)
            tick(2957)
            vm.pc = 2960
            vm.auxiliary = (0, 38819)
            tick(2960)
            vm.pc = 2965
            vm._write(449, memory.load(cells.pointer(447), 4, signed=True) | memory.load(cells.pointer(448), 4, signed=True), 8, 'typed.selector2.q')
            tick(2965)
            vm.pc = 2970
            vm._write(450, cells.value(449) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2970)
            vm.pc = 2973
            vm.auxiliary = (0, 1111826948)
            tick(2973)
            vm.pc = 2978
            vm._write(451, memory.load(cells.pointer(431), 4, signed=True) * memory.load(cells.pointer(91), 4, signed=True), 8, 'once0.integer')
            tick(2978)
            vm.pc = 2981
            vm.auxiliary = (0, 1872494593)
            tick(2981)
            vm.pc = 2986
            vm._write(452, memory.load(cells.pointer(451), 4, signed=True) + memory.load(cells.pointer(93), 4, signed=True), 8, 'once1.integer')
            tick(2986)
            vm.pc = 2991
            vm._write(453, cells.value(452) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(2991)
            vm.pc = 2996
            _convert(vm, 4, 453, 454)
            tick(2996)
            vm.pc = 3001
            _convert(vm, 4, 450, 455)
            tick(3001)
            vm.pc = 3004
            vm.auxiliary = (0, 19476)
            tick(3004)
            vm.pc = 3010
            vm._write(456, memory.load(cells.pointer(455), 4, signed=True) ^ memory.load(cells.pointer(454), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(3010)
            vm.pc = 3015
            vm._write(457, cells.value(456) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3015)
            vm.pc = 3020
            _convert(vm, 4, 457, 458)
            tick(3020)
            vm.pc = 3023
            vm.auxiliary = (0, 46231)
            tick(3023)
            _single_control(vm)
            vm.pc = 3028
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(458), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(459, value, 4, 'typed.selector3.d')
            tick(3028)
            vm.pc = 3031
            vm.auxiliary = (0, 56673)
            tick(3031)
            vm.pc = 3036
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(458), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(460, value, 4, 'typed.selector4.d')
            tick(3036)
            vm.pc = 3039
            vm.auxiliary = (0, 25073)
            tick(3039)
            vm.pc = 3044
            vm._write(461, memory.load(cells.pointer(459), 4, signed=True) | memory.load(cells.pointer(460), 4, signed=True), 8, 'typed.selector2.q')
            tick(3044)
            vm.pc = 3049
            vm._write(462, cells.value(461) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3049)
            vm.pc = 3052
            vm.auxiliary = (0, 1444053972)
            tick(3052)
            vm.pc = 3057
            vm._write(463, int(memory.load(cells.pointer(462), 1, signed=True) != memory.load(cells.pointer(54), 1, signed=True)), 4, 'L30.comparison')
            tick(3057)
            vm.pc = 3060
            vm.auxiliary = (0, 6958)
            tick(3060)
            vm.pc = 3066
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(464, memory.load(cells.pointer(431), 4, signed=True) ^ memory.load(cells.pointer(106), 4, signed=True), 8, 'typed.selector5.q')
            tick(3066)
            vm.pc = 3071
            vm._write(465, cells.value(464) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3071)
            vm.pc = 3078
            selected = 462 if cells.value(463) != 0 else 465
            vm._write(466, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(3078)
            vm.pc = 3083
            _convert(vm, 8, 429, 467)
            tick(3083)
            _pointer(vm, 3083, 6, 6, 468, (10, 467))
            tick(3091)
            vm.pc = 3095
            pointer = cells.value(468)
            value = memory.load(cells.pointer(466), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(3095)
            vm.pc = 3098
            vm.auxiliary = (0, 1270878209)
            tick(3098)
            vm.pc = 3103
            vm._write(430, memory.load(cells.pointer(429), 1, signed=True) + memory.load(cells.pointer(251), 1, signed=True), 8, 'once1.integer')
            tick(3103)
            vm.pc = 3105
            vm._jump(52)
            continue
        if vm.block == 54:
            tick(3105)
            vm.pc = 3107
            vm._jump(55)
            continue
        if vm.block == 55:
            tick(3107)
            _phi(vm, 3107, (469, 2, 21, 54, 470, 56))
            tick(3114)
            vm.pc = 3115
            tick(3115)
            vm.pc = 3118
            vm.auxiliary = (0, 800243557)
            tick(3118)
            vm.pc = 3123
            a = memory.load(cells.pointer(469), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(254), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(471, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(3123)
            vm.pc = 3127
            vm._jump(56 if cells.value(471) != 0 else 57)
            continue
        if vm.block == 56:
            tick(3127)
            vm.pc = 3132
            cells.copy_q_clear_owned(469, 472)
            tick(3132)
            _pointer(vm, 3132, 6, 134, 473, (10, 472))
            tick(3140)
            vm.pc = 3144
            value = memory.load(cells.value(473), 1)
            vm._write(474, value, 4, 'high.load')
            tick(3144)
            _pointer(vm, 3144, 6, 2, 475, (10, 472))
            tick(3152)
            vm.pc = 3156
            value = memory.load(cells.value(475), 1)
            vm._write(476, value, 4, 'high.load')
            tick(3156)
            vm.pc = 3161
            _convert(vm, 4, 476, 477)
            tick(3161)
            _pointer(vm, 3161, 6, 6, 478, (10, 472))
            tick(3169)
            vm.pc = 3173
            value = memory.load(cells.value(478), 1)
            vm._write(479, value, 4, 'high.load')
            tick(3173)
            vm.pc = 3178
            _convert(vm, 4, 479, 480)
            tick(3178)
            vm.pc = 3179
            tick(3179)
            vm.pc = 3182
            vm.auxiliary = (0, 10862)
            tick(3182)
            vm.pc = 3188
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(481, memory.load(cells.pointer(477), 4, signed=True) ^ memory.load(cells.pointer(480), 4, signed=True), 8, 'typed.selector5.q')
            tick(3188)
            vm.pc = 3193
            vm._write(482, cells.value(481) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3193)
            _pointer(vm, 3193, 18, 0, 483, (21, 21))
            tick(3201)
            vm.pc = 3206
            _convert(vm, 8, 474, 484)
            tick(3206)
            _pointer(vm, 3206, 5, 483, 485, (10, 484))
            tick(3214)
            _pointer(vm, 3214, 4, 485, 486, (21, 38))
            tick(3222)
            vm.pc = 3226
            pointer = cells.value(486)
            value = memory.load(cells.pointer(482), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(3226)
            vm.pc = 3230
            value = memory.load(cells.value(478), 1)
            vm._write(487, value, 4, 'high.load')
            tick(3230)
            vm.pc = 3235
            _convert(vm, 4, 487, 488)
            tick(3235)
            vm.pc = 3240
            vm._write(489, cells.value(469) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3240)
            vm.pc = 3245
            _convert(vm, 4, 489, 490)
            tick(3245)
            vm.pc = 3248
            vm.auxiliary = (0, 23327)
            tick(3248)
            vm.pc = 3254
            vm._write(491, memory.load(cells.pointer(488), 4, signed=True) ^ memory.load(cells.pointer(490), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(3254)
            vm.pc = 3259
            vm._write(492, cells.value(491) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3259)
            _pointer(vm, 3259, 4, 485, 493, (21, 21))
            tick(3267)
            _pointer(vm, 3267, 2, 493, 494, (10, 10))
            tick(3275)
            vm.pc = 3279
            pointer = cells.value(494)
            value = memory.load(cells.pointer(492), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(3279)
            vm.pc = 3283
            value = memory.load(cells.value(478), 1)
            vm._write(495, value, 4, 'high.load')
            tick(3283)
            vm.pc = 3288
            _convert(vm, 4, 495, 496)
            tick(3288)
            vm.pc = 3291
            vm.auxiliary = (0, 27399)
            tick(3291)
            vm.pc = 3297
            vm._write(497, memory.load(cells.pointer(496), 4, signed=True) ^ memory.load(cells.pointer(320), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(3297)
            vm.pc = 3302
            vm._write(498, cells.value(497) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3302)
            _pointer(vm, 3302, 4, 485, 499, (21, 135))
            tick(3310)
            _pointer(vm, 3310, 3, 499, 500, (10, 10))
            tick(3318)
            vm.pc = 3322
            pointer = cells.value(500)
            value = memory.load(cells.pointer(498), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(3322)
            vm.pc = 3325
            vm.auxiliary = (0, 1864904705)
            tick(3325)
            vm.pc = 3330
            vm._write(470, memory.load(cells.pointer(469), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(3330)
            vm.pc = 3332
            vm._jump(55)
            continue
        if vm.block == 57:
            tick(3332)
            vm.pc = 3336
            value = memory.load(cells.value(25), 1)
            vm._write(501, value, 4, 'high.load')
            tick(3336)
            vm.pc = 3341
            _convert(vm, 4, 501, 502)
            tick(3341)
            vm.pc = 3345
            value = memory.load(cells.value(58), 1)
            vm._write(503, value, 4, 'high.load')
            tick(3345)
            vm.pc = 3350
            _convert(vm, 4, 503, 504)
            tick(3350)
            vm.pc = 3351
            tick(3351)
            vm.pc = 3354
            vm.auxiliary = (0, 23581)
            tick(3354)
            vm.pc = 3360
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(505, memory.load(cells.pointer(502), 4, signed=True) ^ memory.load(cells.pointer(504), 4, signed=True), 8, 'typed.selector5.q')
            tick(3360)
            vm.pc = 3365
            vm._write(506, cells.value(505) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3365)
            vm.pc = 3367
            vm._jump(58)
            continue
        if vm.block == 58:
            tick(3367)
            _phi(vm, 3367, (507, 2, 506, 57, 508, 59))
            tick(3374)
            _phi(vm, 3374, (509, 2, 21, 57, 510, 59))
            tick(3381)
            vm.pc = 3382
            tick(3382)
            vm.pc = 3385
            vm.auxiliary = (0, 432206661)
            tick(3385)
            vm.pc = 3390
            a = memory.load(cells.pointer(509), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(63), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(511, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(3390)
            vm.pc = 3394
            vm._jump(60 if cells.value(511) != 0 else 61)
            continue
        if vm.block == 60:
            tick(3394)
            vm.pc = 3396
            vm._jump(62)
            continue
        if vm.block == 62:
            tick(3396)
            _phi(vm, 3396, (512, 2, 21, 60, 513, 63))
            tick(3403)
            vm.pc = 3404
            tick(3404)
            vm.pc = 3407
            vm.auxiliary = (0, 1897069845)
            tick(3407)
            vm.pc = 3412
            a = memory.load(cells.pointer(512), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(254), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(514, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(3412)
            vm.pc = 3416
            vm._jump(64 if cells.value(514) != 0 else 65)
            continue
        if vm.block == 64:
            tick(3416)
            vm.pc = 3421
            cells.copy_q_clear_owned(512, 515)
            tick(3421)
            _pointer(vm, 3421, 6, 120, 516, (10, 515))
            tick(3429)
            vm.pc = 3433
            value = memory.load(cells.value(516), 1)
            vm._write(517, value, 4, 'high.load')
            tick(3433)
            vm.pc = 3438
            _convert(vm, 4, 517, 518)
            tick(3438)
            vm.pc = 3443
            vm._write(519, cells.value(509) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3443)
            vm.pc = 3448
            _convert(vm, 4, 519, 520)
            tick(3448)
            vm.pc = 3449
            tick(3449)
            vm.pc = 3452
            vm.auxiliary = (0, 803389635)
            tick(3452)
            vm.pc = 3457
            vm._write(521, int(memory.load(cells.pointer(518), 4, signed=True) == memory.load(cells.pointer(520), 4, signed=True)), 4, 'once17.integer')
            tick(3457)
            vm.pc = 3461
            vm._jump(66 if cells.value(521) != 0 else 67)
            continue
        if vm.block == 67:
            tick(3461)
            _pointer(vm, 3461, 6, 134, 522, (10, 515))
            tick(3469)
            vm.pc = 3473
            value = memory.load(cells.value(522), 1)
            vm._write(523, value, 4, 'high.load')
            tick(3473)
            vm.pc = 3478
            _convert(vm, 4, 523, 524)
            tick(3478)
            vm.pc = 3479
            tick(3479)
            vm.pc = 3482
            vm.auxiliary = (0, 1489167555)
            tick(3482)
            vm.pc = 3487
            vm._write(525, int(memory.load(cells.pointer(524), 4, signed=True) == memory.load(cells.pointer(520), 4, signed=True)), 4, 'once17.integer')
            tick(3487)
            vm.pc = 3491
            vm._jump(66 if cells.value(525) != 0 else 63)
            continue
        if vm.block == 66:
            tick(3491)
            vm.pc = 3493
            vm._jump(65)
            continue
        if vm.block == 63:
            tick(3493)
            vm.pc = 3494
            tick(3494)
            vm.pc = 3497
            vm.auxiliary = (0, 1216192513)
            tick(3497)
            vm.pc = 3502
            vm._write(513, memory.load(cells.pointer(512), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(3502)
            vm.pc = 3504
            vm._jump(62)
            continue
        if vm.block == 65:
            tick(3504)
            _phi(vm, 3504, (526, 2, 38, 66, 21, 62))
            tick(3511)
            vm.pc = 3512
            tick(3512)
            vm.pc = 3515
            vm.auxiliary = (0, 1608682164)
            tick(3515)
            vm.pc = 3520
            vm._write(527, int(memory.load(cells.pointer(526), 4, signed=True) != memory.load(cells.pointer(21), 4, signed=True)), 4, 'L30.comparison')
            tick(3520)
            vm.pc = 3524
            vm._jump(59 if cells.value(527) != 0 else 68)
            continue
        if vm.block == 68:
            tick(3524)
            vm.pc = 3529
            _convert(vm, 4, 507, 528)
            tick(3529)
            vm.pc = 3530
            tick(3530)
            vm.pc = 3533
            vm.auxiliary = (0, 35609)
            tick(3533)
            vm.pc = 3538
            count = memory.load(cells.pointer(28), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(528), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(529, value, 4, 'typed.selector4.d')
            tick(3538)
            vm.pc = 3541
            vm.auxiliary = (0, 36122)
            tick(3541)
            vm.pc = 3546
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(528), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(530, value, 4, 'typed.selector4.d')
            tick(3546)
            vm.pc = 3549
            vm.auxiliary = (0, 31596)
            tick(3549)
            vm.pc = 3555
            vm._write(531, memory.load(cells.pointer(529), 4, signed=True) ^ memory.load(cells.pointer(530), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(3555)
            vm.pc = 3558
            vm.auxiliary = (0, 64000)
            tick(3558)
            vm.pc = 3563
            count = memory.load(cells.pointer(33), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(528), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(532, value, 4, 'typed.selector4.d')
            tick(3563)
            vm.pc = 3568
            vm._write(533, memory.load(cells.pointer(531), 4, signed=True) ^ memory.load(cells.pointer(532), 4, signed=True), 8, 'L14.binary_q')
            tick(3568)
            vm.pc = 3571
            vm.auxiliary = (0, 26977)
            tick(3571)
            vm.pc = 3576
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(528), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(534, value, 4, 'typed.selector4.d')
            tick(3576)
            vm.pc = 3581
            vm._write(535, memory.load(cells.pointer(533), 4, signed=True) ^ memory.load(cells.pointer(534), 4, signed=True), 8, 'L14.binary_q')
            tick(3581)
            vm.pc = 3586
            vm._write(536, memory.load(cells.pointer(535), 4, signed=True) & memory.load(cells.pointer(38), 4, signed=True), 8, 'L13.binary_q')
            tick(3586)
            vm.pc = 3591
            vm._write(537, cells.value(536) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3591)
            vm.pc = 3594
            vm.auxiliary = (0, 9398)
            tick(3594)
            _single_control(vm)
            vm.pc = 3599
            count = memory.load(cells.pointer(38), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(528), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(538, value, 4, 'typed.selector3.d')
            tick(3599)
            vm.pc = 3604
            _convert(vm, 4, 537, 539)
            tick(3604)
            vm.pc = 3609
            vm._write(540, memory.load(cells.pointer(538), 4, signed=True) | memory.load(cells.pointer(539), 4, signed=True), 8, 'L15.binary_q')
            tick(3609)
            vm.pc = 3614
            vm._write(541, cells.value(540) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3614)
            vm.pc = 3619
            vm._write(542, cells.value(509) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3619)
            vm.pc = 3624
            _convert(vm, 4, 542, 543)
            tick(3624)
            vm.pc = 3627
            vm.auxiliary = (0, 1977582083)
            tick(3627)
            vm.pc = 3632
            vm._write(544, memory.load(cells.pointer(543), 4, signed=True) * memory.load(cells.pointer(91), 4, signed=True), 8, 'once0.integer')
            tick(3632)
            vm.pc = 3635
            vm.auxiliary = (0, 1218043905)
            tick(3635)
            vm.pc = 3640
            vm._write(545, memory.load(cells.pointer(544), 4, signed=True) + memory.load(cells.pointer(93), 4, signed=True), 8, 'once1.integer')
            tick(3640)
            vm.pc = 3645
            vm._write(546, cells.value(545) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3645)
            vm.pc = 3650
            _convert(vm, 4, 546, 547)
            tick(3650)
            vm.pc = 3655
            _convert(vm, 4, 541, 548)
            tick(3655)
            vm.pc = 3658
            vm.auxiliary = (0, 64004)
            tick(3658)
            vm.pc = 3664
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(549, memory.load(cells.pointer(548), 4, signed=True) ^ memory.load(cells.pointer(547), 4, signed=True), 8, 'typed.selector5.q')
            tick(3664)
            vm.pc = 3669
            vm._write(550, cells.value(549) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3669)
            vm.pc = 3674
            _convert(vm, 4, 550, 551)
            tick(3674)
            vm.pc = 3677
            vm.auxiliary = (0, 42908)
            tick(3677)
            _single_control(vm)
            vm.pc = 3682
            count = memory.load(cells.pointer(26), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(551), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(552, value, 4, 'typed.selector3.d')
            tick(3682)
            vm.pc = 3685
            vm.auxiliary = (0, 19771)
            tick(3685)
            vm.pc = 3690
            count = memory.load(cells.pointer(30), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(551), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(553, value, 4, 'typed.selector4.d')
            tick(3690)
            vm.pc = 3693
            vm.auxiliary = (0, 54691)
            tick(3693)
            vm.pc = 3698
            vm._write(554, memory.load(cells.pointer(552), 4, signed=True) | memory.load(cells.pointer(553), 4, signed=True), 8, 'typed.selector2.q')
            tick(3698)
            vm.pc = 3703
            vm._write(555, cells.value(554) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3703)
            vm.pc = 3706
            vm.auxiliary = (0, 798128020)
            tick(3706)
            vm.pc = 3711
            vm._write(556, int(memory.load(cells.pointer(555), 1, signed=True) != memory.load(cells.pointer(54), 1, signed=True)), 4, 'L27.comparison')
            tick(3711)
            vm.pc = 3716
            vm._write(557, memory.load(cells.pointer(543), 4, signed=True) ^ memory.load(cells.pointer(106), 4, signed=True), 8, 'L14.binary_q')
            tick(3716)
            vm.pc = 3721
            vm._write(558, cells.value(557) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3721)
            vm.pc = 3728
            selected = 555 if cells.value(556) != 0 else 558
            vm._write(559, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(3728)
            _pointer(vm, 3728, 18, 0, 560, (21, 21))
            tick(3736)
            vm.pc = 3741
            cells.copy_q_clear_owned(509, 561)
            tick(3741)
            _pointer(vm, 3741, 5, 560, 562, (10, 561))
            tick(3749)
            _pointer(vm, 3749, 4, 562, 563, (21, 38))
            tick(3757)
            vm.pc = 3761
            pointer = cells.value(563)
            value = memory.load(cells.pointer(559), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(3761)
            vm.pc = 3766
            _convert(vm, 4, 559, 564)
            tick(3766)
            vm.pc = 3769
            vm.auxiliary = (0, 36100)
            tick(3769)
            vm.pc = 3775
            vm._write(565, memory.load(cells.pointer(564), 4, signed=True) ^ memory.load(cells.pointer(543), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(3775)
            vm.pc = 3780
            vm._write(566, cells.value(565) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3780)
            _pointer(vm, 3780, 4, 562, 567, (21, 21))
            tick(3788)
            _pointer(vm, 3788, 2, 567, 568, (10, 10))
            tick(3796)
            vm.pc = 3800
            pointer = cells.value(568)
            value = memory.load(cells.pointer(566), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(3800)
            vm.pc = 3805
            vm._write(569, memory.load(cells.pointer(564), 4, signed=True) ^ memory.load(cells.pointer(320), 4, signed=True), 8, 'L14.binary_q')
            tick(3805)
            vm.pc = 3810
            vm._write(570, cells.value(569) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(3810)
            _pointer(vm, 3810, 4, 562, 571, (21, 135))
            tick(3818)
            _pointer(vm, 3818, 3, 571, 572, (10, 10))
            tick(3826)
            vm.pc = 3830
            pointer = cells.value(572)
            value = memory.load(cells.pointer(570), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(3830)
            vm.pc = 3832
            vm._jump(59)
            continue
        if vm.block == 59:
            tick(3832)
            _phi(vm, 3832, (508, 2, 507, 65, 559, 68))
            tick(3839)
            vm.pc = 3840
            tick(3840)
            vm.pc = 3843
            vm.auxiliary = (0, 2025209858)
            tick(3843)
            vm.pc = 3848
            vm._write(510, memory.load(cells.pointer(509), 4, signed=True) + memory.load(cells.pointer(38), 4, signed=True), 8, 'once1.integer')
            tick(3848)
            vm.pc = 3850
            vm._jump(58)
            continue
        if vm.block == 61:
            tick(3850)
            vm.pc = 3851
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent material initializer left its source-bound blocks')
