from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_main_material_getter import _convert, _pair_control, _phi, _pointer, _read_pair_control
from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, signed


ECRYPT_SHA256 = {
    'ecrypt-transform': 'f2f9c6021b5cc0c07b746bbe21c5a911a4322c61aa9e3acebbb621f4d01ae89c',
    'ecrypt-keysetup': '87f37c2eab0c576a7ddb07e192b7d765bc9b726dfff6c3707cf9fc280d0e1504',
    'ecrypt-packet': '13c71679754503e1e750498593c617eb29a040a22be333c2ffefb1b081bfecb3',
    'ecrypt-blocks': 'e5b01d30e582e8d2c84c303a4a5a477360ac35f215c259116c5b176d1add18fb',
}
_CHAINS = {
    'ecrypt-transform': ('main', 'ecrypt-transform'),
    'ecrypt-keysetup': ('main', 'ecrypt-transform', 'ecrypt-keysetup'),
    'ecrypt-packet': ('main', 'ecrypt-transform', 'ecrypt-packet'),
    'ecrypt-blocks': ('main', 'ecrypt-transform', 'ecrypt-packet', 'ecrypt-blocks'),
}
_PARENTS = {
    'ecrypt-transform': (11919, 11930, 0x2DE4BF6, (1720, 1523, 502, 1718, 1715), 154),
    'ecrypt-keysetup': (231, 240, 0x2DE2125, (8, 47, 58, 60), 23),
    'ecrypt-packet': (247, 257, 0x2DE4BB7, (12, 8, 3, 0, 4), 27),
    'ecrypt-blocks': (1, 9, 0x2DE4B87, (1, 3, 4), 11),
}


def execute_primary_ecrypt(vm, name, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or name not in ECRYPT_SHA256 or
            sha256(vm.program.raw).hexdigest() != ECRYPT_SHA256[name] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) != (1, 0, None, True) or vm.arena_used != 0):
        raise PrimarySemanticUnavailable('independent ECRYPT requires its fixed fresh program entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            type(owner) is not dict or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._execute_thread != get_ident() or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            type(owner.get('vm')) is not PrimaryVM or sha256(owner['vm'].program.raw).hexdigest() != MAIN_SHA256 or
            owner['vm'].runtime is not runtime or owner['vm'].memory is not runtime.memory or
            owner['vm'].image_base != runtime.image_base or owner['vm'].halted or
            (owner['vm'].pc, owner['vm'].block, owner['vm'].predecessor, owner['vm'].initial_block) !=
            (11930, 293, 291, False) or not runtime.vms or runtime.vms[-1] is not vm or
            tuple(call['name'] for call in runtime._program_calls) != _CHAINS[name] or
            any(call['hosts'] is not None for call in runtime._program_calls)):
        raise PrimarySemanticUnavailable('independent ECRYPT requires its actual current Main family owner')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, key) is not None for key in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent ECRYPT cannot enter a stopped or pending body')
    parent_name = _CHAINS[name][-2]
    parent_hash = MAIN_SHA256 if parent_name == 'main' else ECRYPT_SHA256[parent_name]
    parents = [p for p in runtime.vms if p is not vm and not p.halted and p.runtime is runtime and
               sha256(p.program.raw).hexdigest() == parent_hash]
    word, consumed, rva, arguments, signature = _PARENTS[name]
    if (len(parents) != 1 or parents[0].pc != consumed or not parents[0].host_calls or
            parents[0].host_calls[-1] != (word, runtime.image_base + rva, arguments, signature) or
            not owner['vm'].host_calls or owner['vm'].host_calls[-1] !=
            (11919, runtime.image_base + 0x2DE4BF6, (1720, 1523, 502, 1718, 1715), 154)):
        raise PrimarySemanticUnavailable('independent ECRYPT requires its exact executed parent host row')
    state = dict(program=name, backend='DIRECT_ECRYPT_TYPED_FRAME', referenceRecordCount=0,
                 completed=False, traceComplete=False, completeIndependentMain=False,
                 controlDomain='NONWAITING_ONCE10_WITH_FIXED_FINITE_ALTERNATE_ERRORS')
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_ecrypt_direct_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    {'ecrypt-transform': _transform, 'ecrypt-keysetup': _keysetup,
     'ecrypt-packet': _packet, 'ecrypt-blocks': _blocks}[name](vm, tick)
    state['completed'] = True
    return vm.result


def _host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    vm._primary_ecrypt_active_call = (word, callee, arguments, signature, destination)
    try:
        result = _invoke_host(vm, address, arguments, signature,
                              argument_types=vm.program.type(signature).parameters[3:])
    finally:
        vm._primary_ecrypt_active_call = None
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _single(vm):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = signed(vm.memory.load(vm.image_base + 0x6D86094, 4), 32)
    return ((((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31) & 1


def _blocks_equal(vm):
    extra = _single(vm)
    vm.pc = 56
    a = vm.memory.load(vm.cells.pointer(12), 4, signed=True)
    b = vm.memory.load(vm.cells.pointer(8), 4, signed=True)
    vm._write(13, int(a == b), 4, 'L26.comparison')
    if extra:
        vm.pc = 60
        vm.program.type(0x15C1)
    if _read_pair_control(vm):
        vm.pc = 60
        vm.program.type(0x15C1)



def _transform(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(6, 5)
            tick(4)
            vm.pc = 7
            vm._allocate(8, 6)
            tick(7)
            vm.pc = 10
            vm._allocate(8, 7)
            tick(10)
            vm.pc = 13
            vm._allocate(13, 8)
            tick(13)
            vm.pc = 18
            cells.copy_q_clear_owned(5, 9)
            tick(18)
            vm.pc = 27
            _host(vm, 18, 11, (9, 12, 13), 15, 10)
            tick(27)
            _pointer(vm, 27, 6, 5, 14, (15, 15))
            tick(35)
            vm.pc = 39
            pointer = cells.value(14)
            value = memory.load(cells.pointer(16), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(39)
            _pointer(vm, 39, 6, 5, 17, (15, 18))
            tick(47)
            vm.pc = 51
            pointer = cells.value(17)
            value = memory.load(cells.pointer(19), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51)
            _pointer(vm, 51, 6, 5, 20, (15, 21))
            tick(59)
            vm.pc = 63
            pointer = cells.value(20)
            value = memory.load(cells.pointer(22), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63)
            _pointer(vm, 63, 6, 5, 23, (15, 24))
            tick(71)
            vm.pc = 75
            pointer = cells.value(23)
            value = memory.load(cells.pointer(25), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(75)
            _pointer(vm, 75, 6, 5, 26, (15, 27))
            tick(83)
            vm.pc = 87
            pointer = cells.value(26)
            value = memory.load(cells.pointer(28), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(87)
            _pointer(vm, 87, 6, 5, 29, (15, 30))
            tick(95)
            vm.pc = 99
            pointer = cells.value(29)
            value = memory.load(cells.pointer(31), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(99)
            _pointer(vm, 99, 6, 5, 32, (15, 33))
            tick(107)
            vm.pc = 111
            pointer = cells.value(32)
            value = memory.load(cells.pointer(34), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(111)
            _pointer(vm, 111, 6, 5, 35, (15, 36))
            tick(119)
            vm.pc = 123
            pointer = cells.value(35)
            value = memory.load(cells.pointer(37), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(123)
            vm.pc = 128
            cells.copy_q_clear_owned(6, 38)
            tick(128)
            vm.pc = 137
            _host(vm, 128, 11, (38, 12, 40), 15, 39)
            tick(137)
            vm.pc = 142
            cells.copy_q_clear_owned(7, 41)
            tick(142)
            vm.pc = 151
            _host(vm, 142, 11, (41, 12, 40), 15, 42)
            tick(151)
            vm.pc = 156
            vm._write(44, int(cells.value(2) > cells.value(43)), 4, 'L31.comparison')
            tick(156)
            vm.pc = 163
            selected = 43 if cells.value(44) != 0 else 2
            vm._write(45, memory.load(cells.pointer(selected), 4, signed=True), 8, 'L7.selected_q')
            tick(163)
            vm.pc = 168
            _convert(vm, 8, 45, 46)
            tick(168)
            _pointer(vm, 168, 8, 6, 47, (15, 15))
            tick(176)
            vm.pc = 185
            _host(vm, 176, 49, (47, 1, 46), 18, 48)
            tick(185)
            vm.pc = 190
            _convert(vm, 8, 2, 50)
            tick(190)
            _pointer(vm, 190, 8, 7, 51, (15, 15))
            tick(198)
            vm.pc = 207
            _host(vm, 198, 49, (51, 14, 50), 18, 52)
            tick(207)
            vm.pc = 212
            cells.copy_q_clear_owned(8, 53)
            tick(212)
            vm.pc = 217
            _host(vm, 212, 54, (), 21, None)
            tick(217)
            vm.pc = 218
            tick(218)
            vm.pc = 221
            vm.auxiliary = (0, 1864716290)
            tick(221)
            vm.pc = 226
            vm._write(56, memory.load(cells.pointer(2), 4, signed=True) + memory.load(cells.pointer(55), 4, signed=True), 8, 'once1.integer')
            tick(226)
            vm.pc = 231
            vm._write(58, memory.load(cells.pointer(56), 4, signed=True) & memory.load(cells.pointer(57), 4, signed=True), 8, 'L13.binary_q')
            tick(231)
            vm.pc = 240
            _host(vm, 231, 59, (8, 47, 58, 60), 23, None)
            tick(240)
            vm.pc = 247
            _host(vm, 240, 61, (8, 51), 25, None)
            tick(247)
            vm.pc = 257
            _host(vm, 247, 62, (12, 8, 3, 0, 4), 27, None)
            tick(257)
            vm.pc = 259
            vm._jump(1)
            continue
        if vm.block == 1:
            tick(259)
            _phi(vm, 259, (63, 2, 0, 0, 64, 2))
            tick(266)
            _phi(vm, 266, (65, 2, 66, 0, 67, 2))
            tick(273)
            _phi(vm, 273, (68, 2, 4, 0, 69, 2))
            tick(280)
            vm.pc = 281
            tick(281)
            vm.pc = 284
            vm.auxiliary = (0, 1567367169)
            tick(284)
            vm.pc = 289
            vm._write(69, memory.load(cells.pointer(68), 4, signed=True) + memory.load(cells.pointer(70), 4, signed=True), 8, 'once1.integer')
            tick(289)
            vm.pc = 292
            vm.auxiliary = (0, 1830960372)
            tick(292)
            vm.pc = 297
            vm._write(71, int(memory.load(cells.pointer(68), 4, signed=True) != memory.load(cells.pointer(12), 4, signed=True)), 4, 'L27.comparison')
            tick(297)
            vm.pc = 301
            vm._jump(2 if cells.value(71) != 0 else 3)
            continue
        if vm.block == 2:
            tick(301)
            vm.pc = 302
            tick(302)
            vm.pc = 305
            vm.auxiliary = (0, 58847)
            tick(305)
            extra = _single(vm)
            vm.pc = 310
            count = memory.load(cells.pointer(36), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(65) << count
            vm._write(72, value, 8, "typed.selector3.q")
            if extra:
                vm.pc = 311
                vm.program.type(6490)
            tick(310)
            vm.pc = 313
            vm.auxiliary = (0, 13353)
            tick(313)
            vm.pc = 318
            vm._write(73, memory.load(cells.pointer(72), 8, signed=True) - memory.load(cells.pointer(65), 8, signed=True), 8, 'typed.selector0.q')
            tick(318)
            _pointer(vm, 318, 1, 63, 64, (74,))
            tick(325)
            vm.pc = 329
            value = memory.load(cells.value(63), 1)
            vm._write(75, value, 4, 'high.load')
            tick(329)
            vm.pc = 334
            _convert(vm, 8, 75, 76)
            tick(334)
            vm.pc = 337
            vm.auxiliary = (0, 1571274754)
            tick(337)
            vm.pc = 342
            vm._write(67, memory.load(cells.pointer(73), 8, signed=True) + memory.load(cells.pointer(76), 8, signed=True), 8, 'once1.integer')
            tick(342)
            vm.pc = 344
            vm._jump(1)
            continue
        if vm.block == 3:
            tick(344)
            vm.pc = 349
            value = memory.load(cells.pointer(65), 8)
            count = memory.load(cells.pointer(77), 1)
            vm._write(78, value >> (count & 63), 8, 'once8.logical_shift')
            tick(349)
            vm.pc = 354
            vm._write(79, memory.load(cells.pointer(65), 8, signed=True) ^ memory.load(cells.pointer(78), 8, signed=True), 8, 'L14.binary_q')
            tick(354)
            vm.pc = 355
            tick(355)
            vm.pc = 358
            vm.auxiliary = (0, 505061891)
            tick(358)
            vm.pc = 363
            vm._write(81, memory.load(cells.pointer(79), 8, signed=True) * memory.load(cells.pointer(80), 8, signed=True), 8, 'once0.integer')
            tick(363)
            vm.pc = 368
            value = memory.load(cells.pointer(81), 8)
            count = memory.load(cells.pointer(82), 1)
            vm._write(83, value >> (count & 63), 8, 'once8.logical_shift')
            tick(368)
            vm.pc = 373
            vm._write(84, memory.load(cells.pointer(81), 8, signed=True) ^ memory.load(cells.pointer(83), 8, signed=True), 8, 'L14.binary_q')
            tick(373)
            vm.pc = 378
            value = memory.load(cells.pointer(84), 8)
            count = memory.load(cells.pointer(85), 1)
            vm._write(86, value >> (count & 63), 8, 'once8.logical_shift')
            tick(378)
            vm.pc = 381
            vm.auxiliary = (0, 35453)
            tick(381)
            vm.pc = 387
            vm._write(87, memory.load(cells.pointer(84), 8, signed=True) ^ memory.load(cells.pointer(86), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(387)
            vm.pc = 390
            vm.result = memory.load(cells.pointer(87), 8, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent ECRYPT left its fixed source blocks')


def _keysetup(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            _pointer(vm, 1, 6, 0, 4, (5, 6))
            tick(9)
            vm.pc = 13
            pointer = cells.value(4)
            value = memory.load(cells.pointer(5), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(13)
            _pointer(vm, 13, 6, 0, 7, (5, 8))
            tick(21)
            vm.pc = 25
            pointer = cells.value(7)
            value = memory.load(cells.pointer(2), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(25)
            _pointer(vm, 25, 6, 0, 9, (5, 10))
            tick(33)
            vm.pc = 37
            pointer = cells.value(9)
            value = memory.load(cells.pointer(11), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37)
            _pointer(vm, 37, 6, 0, 12, (5, 13))
            tick(45)
            vm.pc = 49
            pointer = cells.value(12)
            value = memory.load(cells.pointer(5), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(49)
            vm.pc = 50
            tick(50)
            vm.pc = 53
            vm.auxiliary = (0, 2084712675)
            tick(53)
            vm.pc = 58
            vm._write(15, int(memory.load(cells.pointer(2), 4, signed=True) == memory.load(cells.pointer(14), 4, signed=True)), 4, 'once17.integer')
            tick(58)
            vm.pc = 62
            vm._jump(1 if cells.value(15) != 0 else 2)
            continue
        if vm.block == 1:
            tick(62)
            vm.pc = 64
            vm._jump(3)
            continue
        if vm.block == 3:
            tick(64)
            _phi(vm, 64, (16, 2, 5, 1, 17, 4))
            tick(71)
            vm.pc = 76
            vm._write(18, int(cells.value(16) < cells.value(10)), 4, 'once18.unsigned_q')
            tick(76)
            vm.pc = 80
            vm._jump(4 if cells.value(18) != 0 else 5)
            continue
        if vm.block == 4:
            tick(80)
            vm.pc = 81
            tick(81)
            vm.pc = 84
            vm.auxiliary = (0, 1223197188)
            tick(84)
            vm.pc = 89
            vm._write(19, memory.load(cells.pointer(16), 4, signed=True) * memory.load(cells.pointer(10), 4, signed=True), 8, 'once0.integer')
            tick(89)
            vm.pc = 94
            _convert(vm, 8, 19, 20)
            tick(94)
            _pointer(vm, 94, 4, 1, 21, (20,))
            tick(101)
            vm.pc = 106
            cells.copy_q_clear_owned(21, 22)
            tick(106)
            vm.pc = 110
            value = memory.load(cells.value(22), 4)
            vm._write(23, value, 4, 'high.load')
            tick(110)
            _pointer(vm, 110, 6, 0, 24, (5, 5))
            tick(118)
            vm.pc = 121
            vm.auxiliary = (0, 1570750466)
            tick(121)
            vm.pc = 126
            vm._write(26, memory.load(cells.pointer(25), 4, signed=True) + memory.load(cells.pointer(16), 4, signed=True), 8, 'once1.integer')
            tick(126)
            vm.pc = 131
            _convert(vm, 8, 26, 27)
            tick(131)
            _pointer(vm, 131, 2, 24, 28, (29, 27))
            tick(139)
            vm.pc = 143
            pointer = cells.value(28)
            value = memory.load(cells.pointer(23), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(143)
            vm.pc = 146
            vm.auxiliary = (0, 2078023681)
            tick(146)
            vm.pc = 151
            vm._write(31, memory.load(cells.pointer(30), 4, signed=True) + memory.load(cells.pointer(16), 4, signed=True), 8, 'once1.integer')
            tick(151)
            vm.pc = 156
            _convert(vm, 8, 31, 32)
            tick(156)
            _pointer(vm, 156, 2, 24, 33, (29, 32))
            tick(164)
            vm.pc = 168
            pointer = cells.value(33)
            value = memory.load(cells.pointer(23), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(168)
            vm.pc = 173
            _convert(vm, 8, 16, 34)
            tick(173)
            _pointer(vm, 173, 2, 24, 35, (29, 34))
            tick(181)
            vm.pc = 185
            pointer = cells.value(35)
            value = memory.load(cells.pointer(23), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(185)
            vm.pc = 188
            vm.auxiliary = (0, 1513115649)
            tick(188)
            vm.pc = 193
            vm._write(17, memory.load(cells.pointer(16), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(193)
            vm.pc = 195
            vm._jump(3)
            continue
        if vm.block == 5:
            tick(195)
            vm.pc = 197
            vm._jump(6)
            continue
        if vm.block == 6:
            tick(197)
            _phi(vm, 197, (37, 2, 5, 5, 38, 7))
            tick(204)
            vm.pc = 209
            vm._write(39, int(cells.value(37) < cells.value(6)), 4, 'once18.unsigned_q')
            tick(209)
            vm.pc = 213
            vm._jump(7 if cells.value(39) != 0 else 8)
            continue
        if vm.block == 7:
            tick(213)
            _pointer(vm, 213, 4, 1, 40, (41,))
            tick(220)
            vm.pc = 221
            tick(221)
            vm.pc = 224
            vm.auxiliary = (0, 1309610500)
            tick(224)
            vm.pc = 229
            vm._write(42, memory.load(cells.pointer(37), 4, signed=True) * memory.load(cells.pointer(10), 4, signed=True), 8, 'once0.integer')
            tick(229)
            vm.pc = 234
            _convert(vm, 8, 42, 43)
            tick(234)
            _pointer(vm, 234, 4, 40, 44, (43,))
            tick(241)
            vm.pc = 246
            cells.copy_q_clear_owned(44, 45)
            tick(246)
            vm.pc = 250
            value = memory.load(cells.value(45), 4)
            vm._write(46, value, 4, 'high.load')
            tick(250)
            _pointer(vm, 250, 6, 0, 47, (5, 5))
            tick(258)
            vm.pc = 261
            vm.auxiliary = (0, 1314107393)
            tick(261)
            vm.pc = 266
            vm._write(49, memory.load(cells.pointer(48), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(266)
            vm.pc = 271
            _convert(vm, 8, 49, 50)
            tick(271)
            _pointer(vm, 271, 2, 47, 51, (29, 50))
            tick(279)
            vm.pc = 283
            pointer = cells.value(51)
            value = memory.load(cells.pointer(46), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(283)
            vm.pc = 286
            vm.auxiliary = (0, 459472897)
            tick(286)
            vm.pc = 291
            vm._write(53, memory.load(cells.pointer(52), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(291)
            vm.pc = 296
            _convert(vm, 8, 53, 54)
            tick(296)
            _pointer(vm, 296, 2, 47, 55, (29, 54))
            tick(304)
            vm.pc = 308
            pointer = cells.value(55)
            value = memory.load(cells.pointer(46), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(308)
            vm.pc = 311
            vm.auxiliary = (0, 1918906370)
            tick(311)
            vm.pc = 316
            vm._write(56, memory.load(cells.pointer(10), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(316)
            vm.pc = 321
            _convert(vm, 8, 56, 57)
            tick(321)
            _pointer(vm, 321, 2, 47, 58, (29, 57))
            tick(329)
            vm.pc = 333
            pointer = cells.value(58)
            value = memory.load(cells.pointer(46), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(333)
            _pointer(vm, 333, 4, 1, 59, (43,))
            tick(340)
            vm.pc = 345
            cells.copy_q_clear_owned(59, 60)
            tick(345)
            vm.pc = 349
            value = memory.load(cells.value(60), 4)
            vm._write(61, value, 4, 'high.load')
            tick(349)
            vm.pc = 352
            vm.auxiliary = (0, 210472962)
            tick(352)
            vm.pc = 357
            vm._write(63, memory.load(cells.pointer(62), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(357)
            vm.pc = 362
            _convert(vm, 8, 63, 64)
            tick(362)
            _pointer(vm, 362, 2, 47, 65, (29, 64))
            tick(370)
            vm.pc = 374
            pointer = cells.value(65)
            value = memory.load(cells.pointer(61), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(374)
            vm.pc = 377
            vm.auxiliary = (0, 258842625)
            tick(377)
            vm.pc = 382
            vm._write(67, memory.load(cells.pointer(66), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(382)
            vm.pc = 387
            _convert(vm, 8, 67, 68)
            tick(387)
            _pointer(vm, 387, 2, 47, 69, (29, 68))
            tick(395)
            vm.pc = 399
            pointer = cells.value(69)
            value = memory.load(cells.pointer(61), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(399)
            vm.pc = 402
            vm.auxiliary = (0, 1314603010)
            tick(402)
            vm.pc = 407
            vm._write(71, memory.load(cells.pointer(70), 4, signed=True) + memory.load(cells.pointer(37), 4, signed=True), 8, 'once1.integer')
            tick(407)
            vm.pc = 412
            _convert(vm, 8, 71, 72)
            tick(412)
            _pointer(vm, 412, 2, 47, 73, (29, 72))
            tick(420)
            vm.pc = 424
            pointer = cells.value(73)
            value = memory.load(cells.pointer(61), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(424)
            vm.pc = 427
            vm.auxiliary = (0, 659230721)
            tick(427)
            vm.pc = 432
            vm._write(38, memory.load(cells.pointer(37), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(432)
            vm.pc = 434
            vm._jump(6)
            continue
        if vm.block == 2:
            tick(434)
            vm.pc = 436
            vm._jump(9)
            continue
        if vm.block == 9:
            tick(436)
            _phi(vm, 436, (74, 2, 5, 2, 75, 10))
            tick(443)
            vm.pc = 448
            vm._write(77, int(cells.value(74) < cells.value(76)), 4, 'once18.unsigned_q')
            tick(448)
            vm.pc = 452
            vm._jump(10 if cells.value(77) != 0 else 8)
            continue
        if vm.block == 10:
            tick(452)
            vm.pc = 453
            tick(453)
            vm.pc = 456
            vm.auxiliary = (0, 1875231236)
            tick(456)
            vm.pc = 461
            vm._write(78, memory.load(cells.pointer(74), 4, signed=True) * memory.load(cells.pointer(10), 4, signed=True), 8, 'once0.integer')
            tick(461)
            vm.pc = 466
            _convert(vm, 8, 78, 79)
            tick(466)
            _pointer(vm, 466, 4, 1, 80, (79,))
            tick(473)
            vm.pc = 478
            cells.copy_q_clear_owned(80, 81)
            tick(478)
            vm.pc = 482
            value = memory.load(cells.value(81), 4)
            vm._write(82, value, 4, 'high.load')
            tick(482)
            _pointer(vm, 482, 6, 0, 83, (5, 5))
            tick(490)
            vm.pc = 493
            vm.auxiliary = (0, 971726850)
            tick(493)
            vm.pc = 498
            vm._write(84, memory.load(cells.pointer(76), 4, signed=True) + memory.load(cells.pointer(74), 4, signed=True), 8, 'once1.integer')
            tick(498)
            vm.pc = 503
            _convert(vm, 8, 84, 85)
            tick(503)
            _pointer(vm, 503, 2, 83, 86, (29, 85))
            tick(511)
            vm.pc = 515
            pointer = cells.value(86)
            value = memory.load(cells.pointer(82), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(515)
            vm.pc = 520
            _convert(vm, 8, 74, 87)
            tick(520)
            _pointer(vm, 520, 2, 83, 88, (29, 87))
            tick(528)
            vm.pc = 532
            pointer = cells.value(88)
            value = memory.load(cells.pointer(82), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(532)
            vm.pc = 535
            vm.auxiliary = (0, 966352898)
            tick(535)
            vm.pc = 540
            vm._write(89, memory.load(cells.pointer(52), 4, signed=True) + memory.load(cells.pointer(74), 4, signed=True), 8, 'once1.integer')
            tick(540)
            vm.pc = 545
            _convert(vm, 8, 89, 90)
            tick(545)
            _pointer(vm, 545, 2, 83, 91, (29, 90))
            tick(553)
            vm.pc = 557
            pointer = cells.value(91)
            value = memory.load(cells.pointer(82), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(557)
            vm.pc = 560
            vm.auxiliary = (0, 1921081346)
            tick(560)
            vm.pc = 565
            vm._write(75, memory.load(cells.pointer(74), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(565)
            vm.pc = 567
            vm._jump(9)
            continue
        if vm.block == 8:
            tick(567)
            vm.pc = 569
            vm._jump(11)
            continue
        if vm.block == 11:
            tick(569)
            _phi(vm, 569, (92, 2, 5, 8, 93, 12))
            tick(576)
            vm.pc = 581
            vm._write(95, int(cells.value(92) < cells.value(94)), 4, 'once18.unsigned_q')
            tick(581)
            vm.pc = 585
            vm._jump(12 if cells.value(95) != 0 else 13)
            continue
        if vm.block == 12:
            tick(585)
            _pointer(vm, 585, 6, 0, 96, (5, 5))
            tick(593)
            vm.pc = 598
            _convert(vm, 8, 92, 97)
            tick(598)
            _pointer(vm, 598, 2, 96, 98, (29, 97))
            tick(606)
            vm.pc = 610
            value = memory.load(cells.value(98), 4)
            vm._write(99, value, 4, 'high.load')
            tick(610)
            _pointer(vm, 610, 6, 0, 100, (5, 101))
            tick(618)
            _pointer(vm, 618, 2, 100, 102, (29, 97))
            tick(626)
            vm.pc = 630
            pointer = cells.value(102)
            value = memory.load(cells.pointer(99), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(630)
            vm.pc = 631
            tick(631)
            vm.pc = 634
            vm.auxiliary = (0, 558936066)
            tick(634)
            vm.pc = 639
            vm._write(93, memory.load(cells.pointer(92), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(639)
            vm.pc = 641
            vm._jump(11)
            continue
        if vm.block == 13:
            tick(641)
            vm.pc = 642
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent ECRYPT left its fixed source blocks')


def _packet(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 9
            _host(vm, 1, 5, (1, 3, 4), 11, None)
            tick(9)
            vm.pc = 11
            vm._jump(1)
            continue
        if vm.block == 1:
            tick(11)
            _phi(vm, 11, (6, 2, 7, 0, 8, 2))
            tick(18)
            vm.pc = 23
            vm._write(9, int(cells.value(6) < cells.value(4)), 4, 'once18.unsigned_q')
            tick(23)
            vm.pc = 27
            vm._jump(2 if cells.value(9) != 0 else 3)
            continue
        if vm.block == 2:
            tick(27)
            vm.pc = 32
            _convert(vm, 8, 6, 10)
            tick(32)
            _pointer(vm, 32, 4, 2, 11, (10,))
            tick(39)
            vm.pc = 43
            value = memory.load(cells.value(11), 1)
            vm._write(12, value, 4, 'high.load')
            tick(43)
            vm.pc = 48
            _convert(vm, 4, 12, 13)
            tick(48)
            _pointer(vm, 48, 4, 3, 14, (10,))
            tick(55)
            vm.pc = 59
            value = memory.load(cells.value(14), 1)
            vm._write(15, value, 4, 'high.load')
            tick(59)
            vm.pc = 64
            _convert(vm, 4, 15, 16)
            tick(64)
            vm.pc = 65
            tick(65)
            vm.pc = 68
            vm.auxiliary = (0, 23556)
            tick(68)
            vm.pc = 74
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(17, memory.load(cells.pointer(16), 4, signed=True) ^ memory.load(cells.pointer(13), 4, signed=True), 8, 'typed.selector5.q')
            tick(74)
            vm.pc = 79
            vm._write(18, cells.value(17) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 83
                vm.program.type(0x0D031CB8)
            tick(79)
            vm.pc = 83
            pointer = cells.value(14)
            value = memory.load(cells.pointer(18), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(83)
            vm.pc = 86
            vm.auxiliary = (0, 1823952897)
            tick(86)
            vm.pc = 91
            vm._write(8, memory.load(cells.pointer(6), 4, signed=True) + memory.load(cells.pointer(19), 4, signed=True), 8, 'once1.integer')
            tick(91)
            vm.pc = 93
            vm._jump(1)
            continue
        if vm.block == 3:
            tick(93)
            vm.pc = 94
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent ECRYPT left its fixed source blocks')


def _blocks(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 3
            vm._jump(1)
            continue
        if vm.block == 1:
            tick(3)
            _phi(vm, 3, (3, 2, 1, 0, 4, 2))
            tick(10)
            _phi(vm, 10, (5, 2, 2, 0, 6, 2))
            tick(17)
            vm.pc = 18
            tick(18)
            vm.pc = 21
            vm.auxiliary = (0, 417390594)
            tick(21)
            vm.pc = 26
            vm._write(6, memory.load(cells.pointer(5), 4, signed=True) + memory.load(cells.pointer(7), 4, signed=True), 8, 'once1.integer')
            tick(26)
            vm.pc = 31
            vm._write(9, int(cells.value(5) > cells.value(8)), 4, 'L31.comparison')
            tick(31)
            vm.pc = 35
            vm._jump(3 if cells.value(9) != 0 else 4)
            continue
        if vm.block == 3:
            tick(35)
            _pointer(vm, 35, 6, 0, 10, (8, 11))
            tick(43)
            vm.pc = 47
            value = memory.load(cells.value(10), 4)
            vm._write(12, value, 4, 'high.load')
            tick(47)
            vm.pc = 48
            tick(48)
            vm.pc = 51
            vm.auxiliary = (0, 1503835603)
            tick(51)
            _blocks_equal(vm)
            tick(56)
            vm.pc = 60
            vm._jump(5 if cells.value(13) != 0 else 2)
            continue
        if vm.block == 5:
            tick(60)
            _pointer(vm, 60, 6, 0, 14, (8, 15))
            tick(68)
            _pointer(vm, 68, 5, 14, 16, (17, 17))
            tick(76)
            vm.pc = 84
            _host(vm, 76, 18, (0, 16, 19), 9, None)
            tick(84)
            vm.pc = 86
            vm._jump(2)
            continue
        if vm.block == 2:
            tick(86)
            _pointer(vm, 86, 6, 0, 20, (8, 15))
            tick(94)
            vm.pc = 98
            value = memory.load(cells.value(10), 4)
            vm._write(21, value, 4, 'high.load')
            tick(98)
            vm.pc = 103
            _convert(vm, 8, 21, 22)
            tick(103)
            _pointer(vm, 103, 5, 20, 23, (17, 22))
            tick(111)
            vm.pc = 115
            value = memory.load(cells.value(23), 1)
            vm._write(24, value, 4, 'high.load')
            tick(115)
            _pointer(vm, 115, 4, 3, 4, (25,))
            tick(122)
            vm.pc = 126
            pointer = cells.value(3)
            value = memory.load(cells.pointer(24), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(126)
            vm.pc = 130
            value = memory.load(cells.value(10), 4)
            vm._write(26, value, 4, 'high.load')
            tick(130)
            vm.pc = 135
            a, b = cells.value(26), cells.value(19)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(27, a % b, 8, 'L17.unsigned_q_division')
            tick(135)
            vm.pc = 139
            pointer = cells.value(10)
            value = memory.load(cells.pointer(27), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(139)
            vm.pc = 141
            vm._jump(1)
            continue
        if vm.block == 4:
            tick(141)
            vm.pc = 142
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent ECRYPT left its fixed source blocks')
