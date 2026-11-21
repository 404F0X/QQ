from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_main_material_getter import _convert, _phi, _pointer, _read_pair_control
from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, signed




PROGRAM_SHA256 = {'host97': '189a179b4a0d375c4b01ff2af3b77452213c0efe07153cd3910aff34a55b5875', 'cocos-init': '877181b3d8ae7cc35554d44c68646088f597bd46508d3c7f5679f73c84e6ef8b', 'cocos-crypt': 'aa01fb02ea3db8689cb480cbe69e5050bffc478af8e9b1bdf7740c174af4c2fb', 'cocos-publish': '6b766ef829393fb9b18b00e80ab2dd2f05005f81d3a5ab6c434ad4be386fe9bf'}
CHAINS = {'host97': ('main', 'host97'), 'cocos-init': ('main', 'host97', 'cocos-init'), 'cocos-crypt': ('main', 'host97', 'cocos-crypt'), 'cocos-publish': ('main', 'host97', 'cocos-publish')}




def execute_primary_policy3(vm, name, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or name not in PROGRAM_SHA256 or
            sha256(vm.program.raw).hexdigest() != PROGRAM_SHA256[name] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) != (1, 0, None, True) or vm.arena_used != 0):
        raise PrimarySemanticUnavailable('independent policy3 requires its fixed fresh program entry')
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
        raise PrimarySemanticUnavailable('independent policy3 requires its actual current Main family owner')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, key) is not None for key in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent policy3 cannot enter a stopped or pending body')
    _parent(vm, name, owner['vm'])
    state = dict(program=name, backend='DIRECT_policy3_TYPED_FRAME', referenceRecordCount=0,
                 completed=False, traceComplete=False, completeIndependentMain=False,
                 controlDomain='NONWAITING_ONCE10_WITH_FIXED_FINITE_ALTERNATE_ERRORS')
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_policy3_direct_state = state
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




def _parent(vm, name, main):
    runtime = vm.runtime
    if ((main.pc, main.block, main.predecessor, main.initial_block) != (444, 1, 0, False) or
            not main.host_calls or main.host_calls[-1] !=
            (432, runtime.image_base + 0x2DE50A9, (152, 1, 2, 153, 154, 7, 8), 119)):
        raise PrimarySemanticUnavailable('independent policy3 requires its exact executed Main policy host row')
    if name != 'host97':
        parents = [p for p in runtime.vms if p is not vm and p.runtime is runtime and not p.halted and
                   sha256(p.program.raw).hexdigest() == PROGRAM_SHA256['host97']]
        expected = {
            'cocos-init': (609, (602, runtime.image_base + 0x35A20F0, (12, 107), 35)),
            'cocos-crypt': (646, (636, runtime.image_base + 0x35A211B, (12, 135, 134, 133, 137), 37)),
            'cocos-publish': (860, (852, runtime.image_base + 0x35A261F, (5, 171, 168), 39))}[name]
        if (len(parents) != 1 or (parents[0].pc, parents[0].block, parents[0].predecessor,
                parents[0].initial_block) != (expected[0], 0, None, True) or
                parents[0].memory is not runtime.memory or parents[0].image_base != runtime.image_base or
                not parents[0].host_calls or parents[0].host_calls[-1] != expected[1]):
            raise PrimarySemanticUnavailable('independent policy3 requires its exact executed host97 cocos host row')




def _host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    vm._primary_policy3_active_call = (word, callee, arguments, signature, destination)
    try:
        result = _invoke_host(vm, address, arguments, signature,
                              argument_types=vm.program.type(signature).parameters[3:])
    finally:
        vm._primary_policy3_active_call = None
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _single(vm):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = signed(vm.memory.load(vm.image_base + 0x6D86094, 4), 32)
    return ((((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31) & 1



def _host97(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(7, 7)
            tick(4)
            vm.pc = 7
            vm._allocate(9, 8)
            tick(7)
            vm.pc = 10
            vm._allocate(11, 9)
            tick(10)
            vm.pc = 13
            vm._allocate(13, 10)
            tick(13)
            vm.pc = 16
            vm._allocate(15, 11)
            tick(16)
            vm.pc = 19
            vm._allocate(18, 12)
            tick(19)
            vm.pc = 22
            vm._allocate(20, 13)
            tick(22)
            vm.pc = 27
            cells.copy_q_clear_owned(7, 14)
            tick(27)
            vm.pc = 36
            _host(vm, 27, 16, (14, 17, 18), 22, 15)
            tick(36)
            vm.pc = 41
            cells.copy_q_clear_owned(8, 19)
            tick(41)
            vm.pc = 45
            pointer = cells.value(8)
            value = memory.load(cells.pointer(20), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(45)
            vm.pc = 52
            _host(vm, 45, 22, (8,), 24, 21)
            tick(52)
            _pointer(vm, 52, 7, 7, 23, (20, 24))
            tick(60)
            vm.pc = 64
            pointer = cells.value(23)
            value = memory.load(cells.pointer(25), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(64)
            vm.pc = 69
            _convert(vm, 4, 0, 26)
            tick(69)
            vm.pc = 70
            tick(70)
            vm.pc = 73
            vm.auxiliary = (0, 22367)
            tick(73)
            vm.pc = 78
            vm._write(28, memory.load(cells.pointer(26), 4, signed=True) & memory.load(cells.pointer(27), 4, signed=True), 8, 'typed.selector1.q')
            tick(78)
            vm.pc = 81
            vm.auxiliary = (0, 34748)
            tick(81)
            extra = _single(vm)
            vm.pc = 86
            count = memory.load(cells.pointer(29), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(28), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(30, value, 4, 'typed.selector3.d')
            if extra:
                vm.pc = 87
                vm.program.size(14940)
            tick(86)
            vm.pc = 91
            vm._write(32, memory.load(cells.pointer(30), 4, signed=True) & memory.load(cells.pointer(31), 4, signed=True), 8, 'L13.binary_q')
            tick(91)
            vm.pc = 96
            vm._write(33, cells.value(32) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 100
                width = vm.program.size(360601030)
                vm._write(33, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(96)
            vm.pc = 101
            _convert(vm, 4, 33, 34)
            tick(101)
            vm.pc = 104
            vm.auxiliary = (0, 31295)
            tick(104)
            vm.pc = 110
            vm._write(36, memory.load(cells.pointer(35), 4, signed=True) ^ memory.load(cells.pointer(34), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(110)
            vm.pc = 115
            vm._write(37, cells.value(36) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 119
                width = vm.program.size(252598635)
                vm._write(7, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(115)
            _pointer(vm, 115, 7, 7, 38, (20, 39))
            tick(123)
            vm.pc = 127
            pointer = cells.value(38)
            value = memory.load(cells.pointer(37), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(127)
            vm.pc = 132
            cells.copy_q_clear_owned(9, 40)
            tick(132)
            vm.pc = 141
            _host(vm, 132, 41, (25, 17, 42, 9), 26, None)
            tick(141)
            vm.pc = 148
            _host(vm, 141, 44, (9,), 28, 43)
            tick(148)
            vm.pc = 157
            _host(vm, 148, 41, (45, 17, 46, 9), 26, None)
            tick(157)
            vm.pc = 164
            _host(vm, 157, 44, (9,), 28, 47)
            tick(164)
            vm.pc = 173
            _host(vm, 164, 41, (45, 46, 48, 9), 26, None)
            tick(173)
            vm.pc = 180
            _host(vm, 173, 44, (9,), 28, 49)
            tick(180)
            vm.pc = 185
            cells.copy_q_clear_owned(10, 50)
            tick(185)
            vm.pc = 190
            vm._write(52, memory.load(cells.pointer(51), 8, signed=True) & memory.load(cells.pointer(47), 8, signed=True), 8, 'L13.binary_q')
            tick(190)
            vm.pc = 195
            vm._write(53, cells.value(52) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 199
                width = vm.program.size(360601030)
                vm._write(53, cells.value(13) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(195)
            vm.pc = 200
            _convert(vm, 4, 53, 54)
            tick(200)
            vm.pc = 205
            vm._write(56, memory.load(cells.pointer(55), 8, signed=True) & memory.load(cells.pointer(49), 8, signed=True), 8, 'L13.binary_q')
            tick(205)
            vm.pc = 208
            vm.auxiliary = (0, 41380)
            tick(208)
            extra = _single(vm)
            vm.pc = 213
            count = memory.load(cells.pointer(57), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(56) << count
            vm._write(58, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 214
                vm.program.size(329826885)
            tick(213)
            vm.pc = 218
            vm._write(59, cells.value(58) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 222
                width = vm.program.size(360601030)
                vm._write(59, cells.value(13) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(218)
            vm.pc = 223
            _convert(vm, 4, 59, 60)
            tick(223)
            vm.pc = 226
            vm.auxiliary = (0, 45296)
            tick(226)
            vm.pc = 231
            vm._write(61, memory.load(cells.pointer(54), 4, signed=True) | memory.load(cells.pointer(60), 4, signed=True), 8, 'typed.selector2.q')
            tick(231)
            vm.pc = 234
            vm.auxiliary = (0, 54628)
            tick(234)
            vm.pc = 239
            vm._write(62, memory.load(cells.pointer(55), 8, signed=True) & memory.load(cells.pointer(43), 8, signed=True), 8, 'typed.selector1.q')
            tick(239)
            vm.pc = 242
            vm.auxiliary = (0, 26604)
            tick(242)
            extra = _single(vm)
            vm.pc = 247
            count = memory.load(cells.pointer(51), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(62) << count
            vm._write(63, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 248
                vm.program.size(329826885)
            tick(247)
            vm.pc = 252
            vm._write(64, cells.value(63) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 256
                width = vm.program.size(360601030)
                vm._write(64, cells.value(13) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(252)
            vm.pc = 257
            _convert(vm, 4, 64, 65)
            tick(257)
            vm.pc = 260
            vm.auxiliary = (0, 59097)
            tick(260)
            vm.pc = 265
            vm._write(66, memory.load(cells.pointer(61), 4, signed=True) | memory.load(cells.pointer(65), 4, signed=True), 8, 'typed.selector2.q')
            tick(265)
            vm.pc = 270
            value = memory.load(cells.pointer(43), 8)
            count = memory.load(cells.pointer(67), 1)
            vm._write(68, value >> (count & 63), 8, 'once8.logical_shift')
            tick(270)
            vm.pc = 273
            vm.auxiliary = (0, 8807)
            tick(273)
            vm.pc = 278
            vm._write(69, memory.load(cells.pointer(55), 8, signed=True) & memory.load(cells.pointer(68), 8, signed=True), 8, 'typed.selector1.q')
            tick(278)
            vm.pc = 281
            vm.auxiliary = (0, 29830)
            tick(281)
            extra = _single(vm)
            vm.pc = 286
            count = memory.load(cells.pointer(70), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(69) << count
            vm._write(71, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 287
                vm.program.size(329826885)
            tick(286)
            vm.pc = 291
            vm._write(72, cells.value(71) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 295
                width = vm.program.size(360601030)
                vm._write(72, cells.value(13) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(291)
            vm.pc = 296
            _convert(vm, 4, 72, 73)
            tick(296)
            vm.pc = 299
            vm.auxiliary = (0, 22009)
            tick(299)
            vm.pc = 304
            vm._write(74, memory.load(cells.pointer(66), 4, signed=True) | memory.load(cells.pointer(73), 4, signed=True), 8, 'typed.selector2.q')
            tick(304)
            vm.pc = 309
            value = memory.load(cells.pointer(43), 8)
            count = memory.load(cells.pointer(75), 1)
            vm._write(76, value >> (count & 63), 8, 'once8.logical_shift')
            tick(309)
            vm.pc = 314
            vm._write(77, memory.load(cells.pointer(55), 8, signed=True) & memory.load(cells.pointer(76), 8, signed=True), 8, 'L13.binary_q')
            tick(314)
            vm.pc = 317
            vm.auxiliary = (0, 25311)
            tick(317)
            extra = _single(vm)
            vm.pc = 322
            count = memory.load(cells.pointer(78), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(77) << count
            vm._write(79, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 323
                vm.program.size(329826885)
            tick(322)
            vm.pc = 327
            vm._write(80, cells.value(79) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 331
                width = vm.program.size(360601030)
                vm._write(80, cells.value(13) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(327)
            vm.pc = 332
            _convert(vm, 4, 80, 81)
            tick(332)
            vm.pc = 337
            vm._write(82, memory.load(cells.pointer(74), 4, signed=True) | memory.load(cells.pointer(81), 4, signed=True), 8, 'L15.binary_q')
            tick(337)
            vm.pc = 342
            value = memory.load(cells.pointer(43), 8)
            count = memory.load(cells.pointer(83), 1)
            vm._write(84, value >> (count & 63), 8, 'once8.logical_shift')
            tick(342)
            vm.pc = 347
            vm._write(85, memory.load(cells.pointer(55), 8, signed=True) & memory.load(cells.pointer(84), 8, signed=True), 8, 'L13.binary_q')
            tick(347)
            vm.pc = 350
            vm.auxiliary = (0, 14244)
            tick(350)
            extra = _single(vm)
            vm.pc = 355
            count = memory.load(cells.pointer(86), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(85) << count
            vm._write(87, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 356
                vm.program.size(329826885)
            tick(355)
            vm.pc = 360
            vm._write(88, cells.value(87) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 364
                width = vm.program.size(360601030)
                vm._write(88, cells.value(13) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(360)
            vm.pc = 365
            _convert(vm, 4, 88, 89)
            tick(365)
            vm.pc = 370
            vm._write(90, memory.load(cells.pointer(82), 4, signed=True) | memory.load(cells.pointer(89), 4, signed=True), 8, 'L15.binary_q')
            tick(370)
            vm.pc = 375
            value = memory.load(cells.pointer(43), 8)
            count = memory.load(cells.pointer(91), 1)
            vm._write(92, value >> (count & 63), 8, 'once8.logical_shift')
            tick(375)
            vm.pc = 380
            vm._write(93, memory.load(cells.pointer(55), 8, signed=True) & memory.load(cells.pointer(92), 8, signed=True), 8, 'L13.binary_q')
            tick(380)
            vm.pc = 383
            vm.auxiliary = (0, 42206)
            tick(383)
            extra = _single(vm)
            vm.pc = 388
            count = memory.load(cells.pointer(94), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(93) << count
            vm._write(95, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 389
                vm.program.size(329826885)
            tick(388)
            vm.pc = 393
            vm._write(96, cells.value(95) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 397
                width = vm.program.size(360601030)
                vm._write(96, cells.value(13) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(393)
            vm.pc = 398
            _convert(vm, 4, 96, 97)
            tick(398)
            vm.pc = 403
            vm._write(98, memory.load(cells.pointer(90), 4, signed=True) | memory.load(cells.pointer(97), 4, signed=True), 8, 'L15.binary_q')
            tick(403)
            vm.pc = 408
            value = memory.load(cells.pointer(43), 8)
            count = memory.load(cells.pointer(99), 1)
            vm._write(100, value >> (count & 63), 8, 'once8.logical_shift')
            tick(408)
            vm.pc = 413
            vm._write(101, memory.load(cells.pointer(55), 8, signed=True) & memory.load(cells.pointer(100), 8, signed=True), 8, 'L13.binary_q')
            tick(413)
            vm.pc = 416
            vm.auxiliary = (0, 5863)
            tick(416)
            extra = _single(vm)
            vm.pc = 421
            count = memory.load(cells.pointer(67), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(101) << count
            vm._write(102, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 422
                vm.program.size(329826885)
            tick(421)
            vm.pc = 426
            vm._write(103, cells.value(102) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 430
                width = vm.program.size(360601030)
                vm._write(103, cells.value(13) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(426)
            vm.pc = 431
            _convert(vm, 4, 103, 104)
            tick(431)
            vm.pc = 434
            vm.auxiliary = (0, 30424)
            tick(434)
            vm.pc = 439
            vm._write(105, memory.load(cells.pointer(98), 4, signed=True) | memory.load(cells.pointer(104), 4, signed=True), 8, 'typed.selector2.q')
            tick(439)
            vm.pc = 444
            vm._write(106, cells.value(105) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 448
                width = vm.program.size(218307768)
                vm._write(10, cells.value(106) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(444)
            vm.pc = 448
            pointer = cells.value(10)
            value = memory.load(cells.pointer(106), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(448)
            _pointer(vm, 448, 7, 7, 107, (20, 20))
            tick(456)
            _pointer(vm, 456, 1, 107, 108, (109,))
            tick(463)
            vm.pc = 471
            _host(vm, 463, 110, (108, 50, 57), 30, None)
            tick(471)
            vm.pc = 476
            vm._write(112, int(cells.value(111) > cells.value(2)), 4, 'L31.comparison')
            tick(476)
            vm.pc = 483
            selected = 2 if cells.value(112) != 0 else 111
            vm._write(113, memory.load(cells.pointer(selected), 4, signed=True), 8, 'L7.selected_q')
            tick(483)
            vm.pc = 488
            _convert(vm, 8, 113, 114)
            tick(488)
            _pointer(vm, 488, 1, 107, 115, (116,))
            tick(495)
            vm.pc = 503
            _host(vm, 495, 110, (115, 1, 114), 30, None)
            tick(503)
            vm.pc = 508
            cells.copy_q_clear_owned(11, 117)
            tick(508)
            vm.pc = 517
            _host(vm, 508, 16, (117, 17, 24), 22, 118)
            tick(517)
            _pointer(vm, 517, 15, 11, 119, (20, 20))
            tick(525)
            vm.pc = 529
            value = memory.load(cells.value(8), 8)
            vm._write(120, value, 8, 'high.load')
            tick(529)
            vm.pc = 537
            _host(vm, 529, 121, (21, 120, 119), 33, None)
            tick(537)
            vm.pc = 542
            cells.copy_q_clear_owned(119, 122)
            tick(542)
            vm.pc = 550
            _host(vm, 542, 110, (107, 122, 24), 30, None)
            tick(550)
            vm.pc = 558
            _host(vm, 550, 110, (5, 122, 24), 30, None)
            tick(558)
            vm.pc = 562
            value = memory.load(cells.value(23), 1)
            vm._write(123, value, 4, 'high.load')
            tick(562)
            vm.pc = 567
            _convert(vm, 4, 123, 124)
            tick(567)
            vm.pc = 571
            value = memory.load(cells.value(107), 1)
            vm._write(125, value, 4, 'high.load')
            tick(571)
            vm.pc = 576
            _convert(vm, 4, 125, 126)
            tick(576)
            vm.pc = 581
            vm._write(127, memory.load(cells.pointer(124), 4, signed=True) ^ memory.load(cells.pointer(126), 4, signed=True), 8, 'L14.binary_q')
            tick(581)
            vm.pc = 586
            vm._write(128, cells.value(127) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 590
                width = vm.program.size(252598635)
                vm._write(1, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(586)
            _pointer(vm, 586, 1, 5, 129, (24,))
            tick(593)
            vm.pc = 597
            pointer = cells.value(129)
            value = memory.load(cells.pointer(128), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(597)
            vm.pc = 602
            cells.copy_q_clear_owned(12, 130)
            tick(602)
            vm.pc = 609
            _host(vm, 602, 131, (12, 107), 35, None)
            tick(609)
            vm.pc = 614
            cells.copy_q_clear_owned(13, 132)
            tick(614)
            _pointer(vm, 614, 20, 13, 133, (20, 20))
            tick(622)
            _pointer(vm, 622, 1, 107, 134, (39,))
            tick(629)
            _pointer(vm, 629, 1, 107, 135, (67,))
            tick(636)
            vm.pc = 646
            _host(vm, 636, 136, (12, 135, 134, 133, 137), 37, None)
            tick(646)
            _pointer(vm, 646, 1, 5, 138, (39,))
            tick(653)
            vm.pc = 661
            _host(vm, 653, 110, (138, 133, 51), 30, None)
            tick(661)
            _pointer(vm, 661, 20, 13, 139, (20, 70))
            tick(669)
            vm.pc = 673
            value = memory.load(cells.value(139), 1)
            vm._write(140, value, 4, 'high.load')
            tick(673)
            _pointer(vm, 673, 1, 5, 141, (116,))
            tick(680)
            vm.pc = 684
            pointer = cells.value(141)
            value = memory.load(cells.pointer(140), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(684)
            _pointer(vm, 684, 20, 13, 142, (20, 78))
            tick(692)
            vm.pc = 696
            value = memory.load(cells.value(142), 1)
            vm._write(143, value, 4, 'high.load')
            tick(696)
            _pointer(vm, 696, 1, 5, 144, (83,))
            tick(703)
            vm.pc = 707
            pointer = cells.value(144)
            value = memory.load(cells.pointer(143), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(707)
            _pointer(vm, 707, 20, 13, 145, (20, 86))
            tick(715)
            vm.pc = 719
            value = memory.load(cells.value(145), 1)
            vm._write(146, value, 4, 'high.load')
            tick(719)
            _pointer(vm, 719, 1, 5, 147, (91,))
            tick(726)
            vm.pc = 730
            pointer = cells.value(147)
            value = memory.load(cells.pointer(146), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(730)
            _pointer(vm, 730, 20, 13, 148, (20, 67))
            tick(738)
            vm.pc = 742
            value = memory.load(cells.value(148), 1)
            vm._write(149, value, 4, 'high.load')
            tick(742)
            _pointer(vm, 742, 1, 5, 150, (99,))
            tick(749)
            vm.pc = 753
            pointer = cells.value(150)
            value = memory.load(cells.pointer(149), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(753)
            _pointer(vm, 753, 20, 13, 151, (20, 152))
            tick(761)
            vm.pc = 765
            value = memory.load(cells.value(151), 1)
            vm._write(153, value, 4, 'high.load')
            tick(765)
            _pointer(vm, 765, 1, 5, 154, (155,))
            tick(772)
            vm.pc = 776
            pointer = cells.value(154)
            value = memory.load(cells.pointer(153), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(776)
            _pointer(vm, 776, 20, 13, 156, (20, 116))
            tick(784)
            vm.pc = 788
            value = memory.load(cells.value(156), 1)
            vm._write(157, value, 4, 'high.load')
            tick(788)
            _pointer(vm, 788, 1, 5, 158, (159,))
            tick(795)
            vm.pc = 799
            pointer = cells.value(158)
            value = memory.load(cells.pointer(157), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(799)
            _pointer(vm, 799, 20, 13, 160, (20, 75))
            tick(807)
            vm.pc = 811
            value = memory.load(cells.value(160), 1)
            vm._write(161, value, 4, 'high.load')
            tick(811)
            _pointer(vm, 811, 1, 5, 162, (163,))
            tick(818)
            vm.pc = 822
            pointer = cells.value(162)
            value = memory.load(cells.pointer(161), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(822)
            _pointer(vm, 822, 20, 13, 164, (20, 94))
            tick(830)
            vm.pc = 834
            value = memory.load(cells.value(164), 1)
            vm._write(165, value, 4, 'high.load')
            tick(834)
            _pointer(vm, 834, 1, 5, 166, (167,))
            tick(841)
            vm.pc = 845
            pointer = cells.value(166)
            value = memory.load(cells.pointer(165), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(845)
            _pointer(vm, 845, 1, 5, 168, (169,))
            tick(852)
            vm.pc = 860
            _host(vm, 852, 170, (5, 171, 168), 39, None)
            tick(860)
            vm.pc = 864
            pointer = cells.value(6)
            value = memory.load(cells.pointer(172), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(864)
            vm.pc = 865
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent policy3 left its fixed source blocks')


def _cocos_init(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            _pointer(vm, 1, 5, 1, 2, (3,))
            tick(8)
            vm.pc = 13
            cells.copy_q_clear_owned(2, 4)
            tick(13)
            vm.pc = 17
            value = memory.load(cells.value(4), 4)
            vm._write(5, value, 4, 'high.load')
            tick(17)
            _pointer(vm, 17, 3, 0, 6, (7, 7))
            tick(25)
            _pointer(vm, 25, 2, 6, 8, (9, 10))
            tick(33)
            vm.pc = 37
            pointer = cells.value(8)
            value = memory.load(cells.pointer(5), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(37)
            _pointer(vm, 37, 5, 1, 11, (12,))
            tick(44)
            vm.pc = 49
            cells.copy_q_clear_owned(11, 13)
            tick(49)
            vm.pc = 53
            value = memory.load(cells.value(13), 4)
            vm._write(14, value, 4, 'high.load')
            tick(53)
            _pointer(vm, 53, 2, 6, 15, (9, 16))
            tick(61)
            vm.pc = 65
            pointer = cells.value(15)
            value = memory.load(cells.pointer(14), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(65)
            _pointer(vm, 65, 5, 1, 17, (10,))
            tick(72)
            vm.pc = 77
            cells.copy_q_clear_owned(17, 18)
            tick(77)
            vm.pc = 81
            value = memory.load(cells.value(18), 4)
            vm._write(19, value, 4, 'high.load')
            tick(81)
            _pointer(vm, 81, 2, 6, 20, (9, 3))
            tick(89)
            vm.pc = 93
            pointer = cells.value(20)
            value = memory.load(cells.pointer(19), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(93)
            _pointer(vm, 93, 5, 1, 21, (16,))
            tick(100)
            vm.pc = 105
            cells.copy_q_clear_owned(21, 22)
            tick(105)
            vm.pc = 109
            value = memory.load(cells.value(22), 4)
            vm._write(23, value, 4, 'high.load')
            tick(109)
            _pointer(vm, 109, 2, 6, 24, (9, 12))
            tick(117)
            vm.pc = 121
            pointer = cells.value(24)
            value = memory.load(cells.pointer(23), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(121)
            vm.pc = 126
            cells.copy_q_clear_owned(1, 25)
            tick(126)
            vm.pc = 130
            value = memory.load(cells.value(25), 4)
            vm._write(26, value, 4, 'high.load')
            tick(130)
            _pointer(vm, 130, 2, 6, 27, (9, 28))
            tick(138)
            vm.pc = 142
            pointer = cells.value(27)
            value = memory.load(cells.pointer(26), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(142)
            vm.pc = 146
            value = memory.load(cells.value(13), 4)
            vm._write(29, value, 4, 'high.load')
            tick(146)
            _pointer(vm, 146, 2, 6, 30, (9, 31))
            tick(154)
            vm.pc = 158
            pointer = cells.value(30)
            value = memory.load(cells.pointer(29), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(158)
            vm.pc = 162
            value = memory.load(cells.value(4), 4)
            vm._write(32, value, 4, 'high.load')
            tick(162)
            _pointer(vm, 162, 2, 6, 33, (9, 34))
            tick(170)
            vm.pc = 174
            pointer = cells.value(33)
            value = memory.load(cells.pointer(32), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(174)
            vm.pc = 178
            value = memory.load(cells.value(22), 4)
            vm._write(35, value, 4, 'high.load')
            tick(178)
            _pointer(vm, 178, 2, 6, 36, (9, 37))
            tick(186)
            vm.pc = 190
            pointer = cells.value(36)
            value = memory.load(cells.pointer(35), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(190)
            _pointer(vm, 190, 2, 6, 38, (9, 9))
            tick(198)
            vm.pc = 202
            pointer = cells.value(38)
            value = memory.load(cells.pointer(39), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(202)
            _pointer(vm, 202, 2, 6, 40, (9, 41))
            tick(210)
            vm.pc = 214
            pointer = cells.value(40)
            value = memory.load(cells.pointer(42), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(214)
            _pointer(vm, 214, 2, 6, 43, (9, 44))
            tick(222)
            vm.pc = 226
            pointer = cells.value(43)
            value = memory.load(cells.pointer(45), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(226)
            _pointer(vm, 226, 2, 6, 46, (9, 47))
            tick(234)
            vm.pc = 238
            pointer = cells.value(46)
            value = memory.load(cells.pointer(48), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(238)
            vm.pc = 239
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent policy3 left its fixed source blocks')


def _cocos_crypt(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(9, 5)
            tick(4)
            vm.pc = 9
            cells.copy_q_clear_owned(5, 6)
            tick(9)
            vm.pc = 10
            tick(10)
            vm.pc = 13
            vm.auxiliary = (0, 2062734708)
            tick(13)
            vm.pc = 18
            vm._write(8, int(memory.load(cells.pointer(4), 4, signed=True) != memory.load(cells.pointer(7), 4, signed=True)), 4, 'L27.comparison')
            tick(18)
            vm.pc = 22
            vm._jump(1 if cells.value(8) != 0 else 2)
            continue
        if vm.block == 2:
            tick(22)
            _pointer(vm, 22, 9, 5, 9, (10, 10))
            tick(30)
            _pointer(vm, 30, 13, 12, 11, (10, 10))
            tick(38)
            vm.pc = 47
            _host(vm, 38, 14, (9, 11, 10), 15, 13)
            tick(47)
            vm.pc = 49
            vm._jump(3)
            continue
        if vm.block == 1:
            tick(49)
            vm.pc = 54
            cells.copy_q_clear_owned(1, 15)
            tick(54)
            vm.pc = 58
            value = memory.load(cells.value(15), 4)
            vm._write(16, value, 4, 'high.load')
            tick(58)
            _pointer(vm, 58, 3, 0, 17, (7, 7))
            tick(66)
            _pointer(vm, 66, 2, 17, 18, (10, 19))
            tick(74)
            vm.pc = 78
            pointer = cells.value(18)
            value = memory.load(cells.pointer(16), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(78)
            _pointer(vm, 78, 2, 17, 20, (10, 21))
            tick(86)
            vm.pc = 90
            pointer = cells.value(20)
            value = memory.load(cells.pointer(22), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(90)
            _pointer(vm, 90, 2, 17, 23, (10, 24))
            tick(98)
            vm.pc = 102
            pointer = cells.value(23)
            value = memory.load(cells.pointer(7), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(102)
            _pointer(vm, 102, 2, 17, 25, (10, 26))
            tick(110)
            vm.pc = 114
            pointer = cells.value(25)
            value = memory.load(cells.pointer(7), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(114)
            vm.pc = 116
            vm._jump(4)
            continue
        if vm.block == 4:
            tick(116)
            _phi(vm, 116, (27, 2, 2, 1, 28, 5))
            tick(123)
            _phi(vm, 123, (29, 2, 3, 1, 30, 5))
            tick(130)
            _phi(vm, 130, (31, 2, 4, 1, 32, 5))
            tick(137)
            _pointer(vm, 137, 2, 17, 33, (10, 10))
            tick(145)
            _pointer(vm, 145, 9, 5, 34, (10, 10))
            tick(153)
            vm.pc = 160
            _host(vm, 153, 35, (34, 33), 19, None)
            tick(160)
            vm.pc = 164
            value = memory.load(cells.value(23), 4)
            vm._write(36, value, 4, 'high.load')
            tick(164)
            vm.pc = 165
            tick(165)
            vm.pc = 168
            vm.auxiliary = (0, 1964957697)
            tick(168)
            vm.pc = 173
            vm._write(38, memory.load(cells.pointer(36), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(173)
            vm.pc = 177
            pointer = cells.value(23)
            value = memory.load(cells.pointer(38), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(177)
            vm.pc = 180
            vm.auxiliary = (0, 475200212)
            tick(180)
            vm.pc = 185
            vm._write(39, int(memory.load(cells.pointer(38), 4, signed=True) != memory.load(cells.pointer(7), 4, signed=True)), 4, 'L27.comparison')
            tick(185)
            vm.pc = 189
            vm._jump(6 if cells.value(39) != 0 else 7)
            continue
        if vm.block == 7:
            tick(189)
            vm.pc = 193
            value = memory.load(cells.value(25), 4)
            vm._write(40, value, 4, 'high.load')
            tick(193)
            vm.pc = 194
            tick(194)
            vm.pc = 197
            vm.auxiliary = (0, 655196162)
            tick(197)
            vm.pc = 202
            vm._write(41, memory.load(cells.pointer(40), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(202)
            vm.pc = 206
            pointer = cells.value(25)
            value = memory.load(cells.pointer(41), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(206)
            vm.pc = 208
            vm._jump(6)
            continue
        if vm.block == 6:
            tick(208)
            vm.pc = 213
            vm._write(43, int(cells.value(31) <= cells.value(42)), 4, "once19.unsigned_q")
            tick(213)
            vm.pc = 217
            vm._jump(8 if cells.value(43) != 0 else 9)
            continue
        if vm.block == 8:
            tick(217)
            vm.pc = 219
            vm._jump(10)
            continue
        if vm.block == 10:
            tick(219)
            _phi(vm, 219, (44, 2, 7, 8, 45, 11))
            tick(226)
            vm.pc = 231
            vm._write(46, int(cells.value(44) < cells.value(31)), 4, 'once18.unsigned_q')
            tick(231)
            vm.pc = 235
            vm._jump(11 if cells.value(46) != 0 else 12)
            continue
        if vm.block == 12:
            tick(235)
            vm.pc = 237
            vm._jump(3)
            continue
        if vm.block == 11:
            tick(237)
            vm.pc = 242
            cells.copy_q_clear_owned(44, 47)
            tick(242)
            _pointer(vm, 242, 5, 27, 48, (47,))
            tick(249)
            vm.pc = 253
            value = memory.load(cells.value(48), 1)
            vm._write(49, value, 4, 'high.load')
            tick(253)
            vm.pc = 258
            _convert(vm, 4, 49, 50)
            tick(258)
            _pointer(vm, 258, 9, 5, 51, (10, 47))
            tick(266)
            vm.pc = 270
            value = memory.load(cells.value(51), 1)
            vm._write(52, value, 4, 'high.load')
            tick(270)
            vm.pc = 275
            _convert(vm, 4, 52, 53)
            tick(275)
            vm.pc = 280
            vm._write(54, memory.load(cells.pointer(50), 4, signed=True) ^ memory.load(cells.pointer(53), 4, signed=True), 8, 'L14.binary_q')
            tick(280)
            vm.pc = 285
            vm._write(55, cells.value(54) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 289
                width = vm.program.size(252598635)
                vm._write(5, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(285)
            _pointer(vm, 285, 5, 29, 56, (47,))
            tick(292)
            vm.pc = 296
            pointer = cells.value(56)
            value = memory.load(cells.pointer(55), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(296)
            vm.pc = 297
            tick(297)
            vm.pc = 300
            vm.auxiliary = (0, 1363554305)
            tick(300)
            vm.pc = 305
            vm._write(45, memory.load(cells.pointer(44), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(305)
            vm.pc = 307
            vm._jump(10)
            continue
        if vm.block == 9:
            tick(307)
            vm.pc = 309
            vm._jump(13)
            continue
        if vm.block == 13:
            tick(309)
            _phi(vm, 309, (57, 2, 7, 9, 58, 14))
            tick(316)
            vm.pc = 317
            tick(317)
            vm.pc = 320
            vm.auxiliary = (0, 1396853877)
            tick(320)
            vm.pc = 325
            a = memory.load(cells.pointer(57), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(42), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(59, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(325)
            vm.pc = 329
            vm._jump(14 if cells.value(59) != 0 else 5)
            continue
        if vm.block == 5:
            tick(329)
            vm.pc = 330
            tick(330)
            vm.pc = 333
            vm.auxiliary = (0, 41328)
            tick(333)
            vm.pc = 338
            vm._write(32, memory.load(cells.pointer(31), 4, signed=True) - memory.load(cells.pointer(42), 4, signed=True), 8, 'typed.selector0.q')
            tick(338)
            _pointer(vm, 338, 5, 29, 30, (60,))
            tick(345)
            _pointer(vm, 345, 5, 27, 28, (60,))
            tick(352)
            vm.pc = 354
            vm._jump(4)
            continue
        if vm.block == 14:
            tick(354)
            vm.pc = 359
            cells.copy_q_clear_owned(57, 61)
            tick(359)
            _pointer(vm, 359, 5, 27, 62, (61,))
            tick(366)
            vm.pc = 370
            value = memory.load(cells.value(62), 1)
            vm._write(63, value, 4, 'high.load')
            tick(370)
            vm.pc = 375
            _convert(vm, 4, 63, 64)
            tick(375)
            _pointer(vm, 375, 9, 5, 65, (10, 61))
            tick(383)
            vm.pc = 387
            value = memory.load(cells.value(65), 1)
            vm._write(66, value, 4, 'high.load')
            tick(387)
            vm.pc = 392
            _convert(vm, 4, 66, 67)
            tick(392)
            vm.pc = 393
            tick(393)
            vm.pc = 396
            vm.auxiliary = (0, 10340)
            tick(396)
            vm.pc = 402
            vm._write(68, memory.load(cells.pointer(64), 4, signed=True) ^ memory.load(cells.pointer(67), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(402)
            vm.pc = 407
            vm._write(69, cells.value(68) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 411
                width = vm.program.size(252598635)
                vm._write(5, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(407)
            _pointer(vm, 407, 5, 29, 70, (61,))
            tick(414)
            vm.pc = 418
            pointer = cells.value(70)
            value = memory.load(cells.pointer(69), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(418)
            vm.pc = 421
            vm.auxiliary = (0, 1924096002)
            tick(421)
            vm.pc = 426
            vm._write(58, memory.load(cells.pointer(57), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(426)
            vm.pc = 428
            vm._jump(13)
            continue
        if vm.block == 3:
            tick(428)
            vm.pc = 429
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent policy3 left its fixed source blocks')


def _cocos_publish(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 2
            tick(2)
            vm.pc = 5
            vm.auxiliary = (0, 601027587)
            tick(5)
            extra = _single(vm)
            vm.pc = 10
            left_pointer = cells.pointer(0)
            right_pointer = cells.pointer(3)
            destination_pointer = cells.pointer(4)
            a = memory.load(left_pointer, 8, signed=True)
            b = memory.load(right_pointer, 8, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 14
                left_pointer = cells.pointer(0)
                right_pointer = cells.pointer(1330795587)
                destination_pointer = cells.pointer(27023)
                width = vm.program.size(13790)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(13790)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 14
                left_pointer = cells.pointer(0)
                right_pointer = cells.pointer(1330795587)
                destination_pointer = cells.pointer(27023)
                width = vm.program.size(13790)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(13790)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(10)
            vm.pc = 13
            vm.auxiliary = (0, 1330795587)
            tick(13)
            extra = _single(vm)
            vm.pc = 18
            left_pointer = cells.pointer(2)
            right_pointer = cells.pointer(3)
            destination_pointer = cells.pointer(5)
            a = memory.load(left_pointer, 8, signed=True)
            b = memory.load(right_pointer, 8, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 22
                left_pointer = cells.pointer(0)
                right_pointer = cells.pointer(30169)
                destination_pointer = cells.pointer(184569090)
                width = vm.program.size(13790)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(13790)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 22
                left_pointer = cells.pointer(0)
                right_pointer = cells.pointer(30169)
                destination_pointer = cells.pointer(184569090)
                width = vm.program.size(13790)
                a = memory.load(left_pointer, width if width in (1, 2, 4) else 8, signed=True)
                width = vm.program.size(13790)
                b = memory.load(right_pointer, width if width in (1, 2, 4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(18)
            vm.pc = 21
            vm.auxiliary = (0, 30169)
            tick(21)
            vm.pc = 26
            vm._write(6, memory.load(cells.pointer(4), 1, signed=True) | memory.load(cells.pointer(5), 1, signed=True), 8, 'typed.selector2.q')
            tick(26)
            vm.pc = 30
            vm._jump(1 if cells.value(6) != 0 else 2)
            continue
        if vm.block == 1:
            tick(30)
            _pointer(vm, 30, 7, 8, 7, (9, 9))
            tick(38)
            vm.pc = 47
            _host(vm, 38, 11, (0, 7, 9), 10, 10)
            tick(47)
            vm.pc = 49
            vm._jump(3)
            continue
        if vm.block == 2:
            tick(49)
            vm.pc = 53
            pointer = cells.value(0)
            value = memory.load(cells.pointer(12), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(53)
            _pointer(vm, 53, 1, 0, 13, (14,))
            tick(60)
            vm.pc = 64
            pointer = cells.value(13)
            value = memory.load(cells.pointer(15), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(64)
            _pointer(vm, 64, 1, 0, 16, (17,))
            tick(71)
            vm.pc = 75
            pointer = cells.value(16)
            value = memory.load(cells.pointer(18), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(75)
            _pointer(vm, 75, 1, 0, 19, (20,))
            tick(82)
            vm.pc = 86
            pointer = cells.value(19)
            value = memory.load(cells.pointer(21), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(86)
            vm.pc = 91
            vm._write(23, memory.load(cells.pointer(1), 4, signed=True) & memory.load(cells.pointer(22), 4, signed=True), 8, 'L13.binary_q')
            tick(91)
            vm.pc = 96
            vm._write(24, cells.value(23) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 100
                width = vm.program.size(252598635)
                vm._write(1, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(96)
            _pointer(vm, 96, 1, 0, 25, (26,))
            tick(103)
            vm.pc = 107
            pointer = cells.value(25)
            value = memory.load(cells.pointer(24), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(107)
            vm.pc = 112
            value = memory.load(cells.pointer(1), 4)
            count = memory.load(cells.pointer(27), 1)
            vm._write(28, value >> (count & 31), 4, 'once8.logical_shift')
            tick(112)
            vm.pc = 117
            vm._write(29, memory.load(cells.pointer(28), 4, signed=True) & memory.load(cells.pointer(22), 4, signed=True), 8, 'L13.binary_q')
            tick(117)
            vm.pc = 122
            vm._write(30, cells.value(29) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 126
                width = vm.program.size(252598635)
                vm._write(1, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(122)
            _pointer(vm, 122, 1, 0, 31, (32,))
            tick(129)
            vm.pc = 133
            pointer = cells.value(31)
            value = memory.load(cells.pointer(30), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(133)
            vm.pc = 138
            value = memory.load(cells.pointer(1), 4)
            count = memory.load(cells.pointer(33), 1)
            vm._write(34, value >> (count & 31), 4, 'once8.logical_shift')
            tick(138)
            vm.pc = 143
            vm._write(35, memory.load(cells.pointer(34), 4, signed=True) & memory.load(cells.pointer(22), 4, signed=True), 8, 'L13.binary_q')
            tick(143)
            vm.pc = 148
            vm._write(36, cells.value(35) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 152
                width = vm.program.size(252598635)
                vm._write(1, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(148)
            _pointer(vm, 148, 1, 0, 37, (38,))
            tick(155)
            vm.pc = 159
            pointer = cells.value(37)
            value = memory.load(cells.pointer(36), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(159)
            vm.pc = 164
            value = memory.load(cells.pointer(1), 4)
            count = memory.load(cells.pointer(39), 1)
            vm._write(40, value >> (count & 31), 4, 'once8.logical_shift')
            tick(164)
            vm.pc = 169
            vm._write(41, cells.value(40) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 173
                width = vm.program.size(252598635)
                vm._write(1, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(169)
            _pointer(vm, 169, 1, 0, 42, (43,))
            tick(176)
            vm.pc = 180
            pointer = cells.value(42)
            value = memory.load(cells.pointer(41), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(180)
            vm.pc = 189
            _host(vm, 180, 45, (0, 46, 47), 12, 44)
            tick(189)
            vm.pc = 191
            vm._jump(4)
            continue
        if vm.block == 4:
            tick(191)
            _phi(vm, 191, (48, 2, 49, 2, 50, 5))
            tick(198)
            vm.pc = 199
            tick(199)
            vm.pc = 202
            vm.auxiliary = (0, 1399991285)
            tick(202)
            vm.pc = 207
            a = memory.load(cells.pointer(48), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(51), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(52, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(207)
            vm.pc = 211
            vm._jump(5 if cells.value(52) != 0 else 6)
            continue
        if vm.block == 6:
            tick(211)
            vm.pc = 213
            vm._jump(3)
            continue
        if vm.block == 5:
            tick(213)
            vm.pc = 214
            tick(214)
            vm.pc = 217
            vm.auxiliary = (0, 1964294660)
            tick(217)
            vm.pc = 222
            vm._write(53, memory.load(cells.pointer(48), 4, signed=True) * memory.load(cells.pointer(27), 4, signed=True), 8, 'once0.integer')
            tick(222)
            vm.pc = 227
            value = memory.load(cells.pointer(44), 4)
            count = memory.load(cells.pointer(53), 1)
            vm._write(54, value >> (count & 31), 4, 'once8.logical_shift')
            tick(227)
            vm.pc = 232
            vm._write(55, memory.load(cells.pointer(54), 4, signed=True) & memory.load(cells.pointer(22), 4, signed=True), 8, 'L13.binary_q')
            tick(232)
            vm.pc = 237
            vm._write(56, cells.value(55) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 241
                width = vm.program.size(12261)
                vm._write(48, cells.value(3) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(237)
            vm.pc = 242
            cells.copy_q_clear_owned(48, 57)
            tick(242)
            _pointer(vm, 242, 1, 2, 58, (57,))
            tick(249)
            vm.pc = 253
            pointer = cells.value(58)
            value = memory.load(cells.pointer(56), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(253)
            vm.pc = 256
            vm.auxiliary = (0, 1825558530)
            tick(256)
            vm.pc = 261
            vm._write(50, memory.load(cells.pointer(48), 4, signed=True) + memory.load(cells.pointer(59), 4, signed=True), 8, 'once1.integer')
            tick(261)
            vm.pc = 263
            vm._jump(4)
            continue
        if vm.block == 3:
            tick(263)
            vm.pc = 264
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent policy3 left its fixed source blocks')


BODIES = {'host97': _host97, 'cocos-init': _cocos_init, 'cocos-crypt': _cocos_crypt, 'cocos-publish': _cocos_publish}
