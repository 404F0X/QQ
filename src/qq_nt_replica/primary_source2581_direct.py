import sys
from contextlib import contextmanager
from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, signed


PROGRAM_SHA256 = {
    'source2581': '5aa7b463d06b2d1d99d228f4d1ff81094e5b6c2fda97683a3cf656699c7f846a',
    'source2581-setter': '3c435a1c8d971af093c2e45eab06b681418b0c9fd6b41ff48272b5fbea243bfc'}
_CLAIM_FACTORY = object()


class _ConfigurationClaim:
    def __init__(self, runtime, scope, owner, source, config, context, pointer, length, key, factory):
        if factory is not _CLAIM_FACTORY:
            raise PrimarySemanticUnavailable('source2581 phase requires its real configure factory')
        self.runtime, self.scope, self.owner, self.source = runtime, scope, owner, source
        self.config, self.context, self.pointer, self.length, self.key = config, context, pointer, length, key
        self.thread = get_ident()
        self.generation = runtime._main_generation
        self.active = True
        self.root = self.root_call = self.child = None
        self.parent_calls = tuple(runtime._program_calls)


def _source_frame(code, runtime, **values):
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is code:
            local = frame.f_locals
            if local.get('self', local.get('runtime')) is runtime and all(local.get(k) == v for k, v in values.items()):
                return frame
        frame = frame.f_back
    return None


@contextmanager
def _source2581_configuration(runtime, config, context, pointer, length, key):
    scope = runtime.__dict__.get('_primary_direct_scope')
    if scope is None:
        yield
        return
    from .primary_direct_scopes import PrimaryDirectScope
    from .primary_provider_init import configure
    from .primary_sign_lifecycle import _PublicDirectOwner
    owner = scope._configuration_owner() if type(scope) is PrimaryDirectScope else None
    source = _source_frame(configure.__code__, runtime, config=config, context=context, pointer=pointer, length=length)
    if (type(scope) is not PrimaryDirectScope or scope.runtime is not runtime or
            owner is None or
            owner.runtime is not runtime or owner.thread != get_ident() or not owner.valid() or
            source is None or key != 0x2581 or type(pointer) is not int or type(length) is not int or
            not 0 <= length <= 0xFFFFFFFF or runtime.locks.get(config + 0x120) != 1 or
            runtime._program_calls or runtime._active_main is not None or
            runtime.__dict__.get('_primary_source2581_claim') is not None):
        raise PrimarySemanticUnavailable('source2581 requires its actual one-use nonempty GUID configure phase')
    scope._require_live()
    claim = _ConfigurationClaim(runtime, scope, owner, source, config, context, pointer, length, key, _CLAIM_FACTORY)
    runtime._primary_source2581_claim = claim
    try:
        yield
        if claim.root is None or not claim.root.halted or claim.root.pc != 113:
            raise PrimarySemanticUnavailable('source2581 configure phase did not complete its actual root')
    finally:
        claim.active = False
        claim.source = None
        if runtime.__dict__.get('_primary_source2581_claim') is claim:
            runtime.__dict__.pop('_primary_source2581_claim')


def _authorize(vm, name):
    from .primary_sign import PrimaryRuntime
    from .primary_provider_init import configure
    from .primary_tokens import dispatch_local
    runtime = vm.runtime
    claim = getattr(runtime, '_primary_source2581_claim', None)
    if (runtime is None or type(claim) is not _ConfigurationClaim or not claim.active or
            claim.runtime is not runtime or claim.thread != get_ident() or
            runtime.__dict__.get('_primary_direct_scope') is not claim.scope or
            claim.scope._configuration_owner() is not claim.owner or
            not claim.owner.valid() or claim.owner.thread != get_ident() or
            runtime._main_generation != claim.generation or runtime._active_main is not None or
            vm.memory is not runtime.memory or vm.image_base != runtime.image_base or runtime._active_failed or
            runtime._execute_thread != get_ident() or getattr(runtime, '_consumed_mgf', None) is not None or
            not runtime.vms or runtime.vms[-1] is not vm or
            _source_frame(configure.__code__, runtime, config=claim.config, context=claim.context,
                          pointer=claim.pointer, length=claim.length) is not claim.source):
        raise PrimarySemanticUnavailable('source2581 reader lost its actual configure/public/thread claim')
    claim.scope._require_live()
    reader = _source_frame(PrimaryRuntime._execute_program.__code__, runtime, name=name)
    dispatch = _source_frame(dispatch_local.__code__, runtime, pointer=claim.pointer, kind=claim.length, key=0x2581)
    if reader is None or reader.f_locals.get('vm') is not vm or dispatch is None:
        raise PrimarySemanticUnavailable('source2581 requires its actual registry dispatch and initialized reader')
    calls = runtime._program_calls
    count = 1 if name == 'source2581' else 2
    if (len(calls) != len(claim.parent_calls) + count or
            any(a is not b for a, b in zip(calls, claim.parent_calls)) or
            tuple(c['name'] for c in calls[-count:]) != ('source2581',) + (() if count == 1 else ('source2581-setter',)) or
            any(c['hosts'] is not None for c in calls[-count:])):
        raise PrimarySemanticUnavailable('source2581 requires its exact current source child stack')
    if name == 'source2581':
        wrapper = _source_frame(PrimaryRuntime.invoke.__code__, runtime, rva=0x35A2B20)
        if (claim.root is not None or calls[-1]['arguments'] !=
                (runtime.image_base + 0x6D88D74, claim.pointer, claim.length) or wrapper is None):
            raise PrimarySemanticUnavailable('source2581 root phase is replayed or has a foreign ABI')
        claim.root, claim.root_call = vm, calls[-1]
    else:
        root = claim.root
        host = _source_frame(_host.__code__, vm.runtime)
        wrapper = _source_frame(PrimaryRuntime.invoke.__code__, runtime, rva=0x3592214)
        if (claim.child is not None or type(root) is not PrimaryVM or root.runtime is not runtime or
                root.memory is not runtime.memory or root.image_base != runtime.image_base or root.halted or
                sha256(root.program.raw).hexdigest() != PROGRAM_SHA256['source2581'] or
                (root.pc, root.block, root.predecessor, root.initial_block) != (108, 1, 0, False) or
                calls[-2] is not claim.root_call or not root.host_calls or root.host_calls[-1] !=
                (99, runtime.image_base + 0x3592214, (11, 13, 26), 41) or
                getattr(root, '_primary_source2581_active_call', None) != (99, 25, (11, 13, 26), 41, 27) or
                host is None or host.f_locals.get('vm') is not root or wrapper is None or
                wrapper.f_locals.get('vm') is not root or wrapper.f_locals.get('cells') != (11, 13, 26) or
                reader.f_locals.get('arguments') != calls[-1]['arguments']):
            raise PrimarySemanticUnavailable('source2581 setter requires its actual one-use root callback and ABI')
        claim.child = vm
    return claim


def execute_primary_source2581(vm, name, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or name not in PROGRAM_SHA256 or
            sha256(vm.program.raw).hexdigest() != PROGRAM_SHA256[name] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used) != (1, 0, None, True, 0) or
            vm.halted or vm.abort_reason is not None or any(getattr(vm, key) is not None for key in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native', 'private_iv_native_pending'))):
        raise PrimarySemanticUnavailable('source2581 requires its fixed fresh nonpending source body')
    _authorize(vm, name)
    state = dict(program=name, backend='DIRECT_SOURCE2581_LITERAL', completed=False,
                 referenceRecordCount=0, traceComplete=False, completeIndependentMain=False,
                 controlDomain='NONWAITING_ONCE10_FIXED_FINITE_ALTERNATE_ERRORS')
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_source2581_direct_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    {'source2581': _source2581, 'source2581-setter': _source2581_setter}[name](vm, tick)
    state['completed'] = True
    return vm.result


def _host(vm, word, callee, arguments, signature, destination):
    runtime = vm.runtime
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    if word == 99 and address != vm.image_base + 0x3592214:
        raise PrimarySemanticUnavailable('source2581 current container callback is unavailable')
    from .primary_sign import _invoke_host
    vm._primary_source2581_active_call = (word, callee, arguments, signature, destination)
    try:
        result = _invoke_host(vm, address, arguments, signature,
                              argument_types=vm.program.type(signature).parameters[3:])
    finally:
        vm._primary_source2581_active_call = None
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')



def _read_pair_control(vm):
    x = signed(vm.memory.load(vm.image_base + 108519860, 4), 32)
    y = signed(vm.memory.load(vm.image_base + 108519864, 4), 32)
    return (x * x + y * y & 4294967295 | abs(x) + abs(y) & 4294967295) >> 31


def _convert(vm, width, source, destination):
    alternate = False
    if width == 1 or width >= 4:
        alternate = _read_pair_control(vm)
    if width >= 4:
        if vm.memory.load(vm.image_base + 108519868, 4) == 2147483648:
            raise PrimarySemanticUnavailable('independent record consumer mask wait is unavailable')
        if width >= 8:
            vm.memory.load(vm.image_base + 108519868, 4)
            if vm.memory.load(vm.image_base + 108519868, 4) == 2147483648:
                raise PrimarySemanticUnavailable('independent record consumer mask wait is unavailable')
    value = vm.memory.load(vm.cells.pointer(source), width)
    vm.memory.store(vm.cells.pointer(destination), value, 8, source='once10.first_type_zeroextend_or_q')
    if width == 1 and alternate:
        value = vm.memory.load(vm.cells.pointer(source), 1)
        vm.memory.store(vm.cells.pointer(destination), value, 8, source='once10.first_type_zeroextend_or_q')


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
        offset = offset + delta & 18446744073709551615
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


def _single(vm):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = signed(vm.memory.load(vm.image_base + 0x6D86094, 4), 32)
    return ((((x*x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31) & 1


def _source2581(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(7, 3)
            tick(4)
            vm.pc = 5
            tick(5)
            vm.pc = 8
            vm.auxiliary = (0, 926034004)
            tick(8)
            vm.pc = 13
            vm._write(5, int(memory.load(cells.pointer(1), 8, signed=True) != memory.load(cells.pointer(4), 8, signed=True)), 4, 'L27.comparison')
            tick(13)
            vm.pc = 18
            vm._write(7, int(cells.value(2) > cells.value(6)), 4, 'L31.comparison')
            tick(18)
            vm.pc = 23
            vm._write(8, memory.load(cells.pointer(5), 1, signed=True) & memory.load(cells.pointer(7), 1, signed=True), 8, 'L13.binary_q')
            tick(23)
            vm.pc = 27
            vm._jump(1 if cells.value(8) != 0 else 2)
            continue
        if vm.block == 1:
            tick(27)
            vm.pc = 33
            _host(vm, 27, 10, (), 10, 9)
            tick(33)
            vm.pc = 38
            cells.copy_q_clear_owned(9, 11)
            tick(38)
            vm.pc = 43
            cells.copy_q_clear_owned(3, 12)
            tick(43)
            _pointer(vm, 43, 7, 3, 13, (14, 14))
            tick(51)
            vm.pc = 60
            _host(vm, 51, 16, (13, 6, 17), 35, 15)
            tick(60)
            vm.pc = 69
            _host(vm, 60, 19, (13, 1, 20), 37, 18)
            tick(69)
            _pointer(vm, 69, 33, 11, 21, (6, 22))
            tick(77)
            _pointer(vm, 77, 25, 21, 23, (14, 14))
            tick(85)
            vm.pc = 89
            value = memory.load(cells.value(23), 8)
            vm._write(24, value, 8, 'high.load')
            tick(89)
            vm.pc = 94
            cells.copy_q_clear_owned(24, 25)
            tick(94)
            vm.pc = 99
            _convert(vm, 8, 2, 26)
            tick(99)
            vm.pc = 108
            _host(vm, 99, 25, (11, 13, 26), 41, 27)
            tick(108)
            vm.pc = 110
            vm._jump(2)
            continue
        if vm.block == 2:
            tick(110)
            vm.pc = 113
            vm.result = memory.load(cells.pointer(28), 1, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('source2581 left its fixed source blocks')


def _source2581_setter(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(12, 3)
            tick(4)
            vm.pc = 7
            vm._allocate(3, 4)
            tick(7)
            vm.pc = 8
            tick(8)
            vm.pc = 11
            vm.auxiliary = (0, 744658564)
            tick(11)
            vm.pc = 16
            vm._write(6, int(memory.load(cells.pointer(0), 8, signed=True) != memory.load(cells.pointer(5), 8, signed=True)), 4, 'L27.comparison')
            tick(16)
            vm.pc = 19
            vm.auxiliary = (0, 530736468)
            tick(19)
            vm.pc = 24
            vm._write(8, int(memory.load(cells.pointer(1), 8, signed=True) != memory.load(cells.pointer(7), 8, signed=True)), 4, 'L27.comparison')
            tick(24)
            vm.pc = 29
            vm._write(9, memory.load(cells.pointer(6), 1, signed=True) & memory.load(cells.pointer(8), 1, signed=True), 8, 'L13.binary_q')
            tick(29)
            vm.pc = 32
            vm.auxiliary = (0, 27700)
            tick(32)
            vm.pc = 38
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(11, memory.load(cells.pointer(9), 1, signed=True) ^ memory.load(cells.pointer(10), 1, signed=True), 8, 'typed.selector5.q')
            tick(38)
            vm.pc = 41
            vm.auxiliary = (0, 380820804)
            tick(41)
            vm.pc = 46
            vm._write(13, int(memory.load(cells.pointer(2), 8, signed=True) != memory.load(cells.pointer(12), 8, signed=True)), 4, 'L30.comparison')
            tick(46)
            vm.pc = 49
            vm.auxiliary = (0, 53697)
            tick(49)
            vm.pc = 54
            vm._write(14, memory.load(cells.pointer(11), 1, signed=True) | memory.load(cells.pointer(13), 1, signed=True), 8, 'typed.selector2.q')
            tick(54)
            vm.pc = 58
            vm._jump(1 if cells.value(14) != 0 else 2)
            continue
        if vm.block == 1:
            tick(58)
            vm.pc = 60
            vm._jump(3)
            continue
        if vm.block == 2:
            tick(60)
            vm.pc = 67
            _host(vm, 60, 15, (0, 10), 33, None)
            tick(67)
            vm.pc = 72
            cells.copy_q_clear_owned(3, 16)
            tick(72)
            vm.pc = 81
            _host(vm, 72, 18, (16, 19, 20), 35, 17)
            tick(81)
            vm.pc = 83
            vm._jump(4)
            continue
        if vm.block == 4:
            tick(83)
            _phi(vm, 83, (21, 2, 19, 2, 22, 5))
            tick(90)
            _phi(vm, 90, (23, 2, 19, 2, 24, 5))
            tick(97)
            vm.pc = 98
            tick(98)
            vm.pc = 101
            vm.auxiliary = (0, 574813525)
            tick(101)
            vm.pc = 106
            a = memory.load(cells.pointer(21), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(25), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(26, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(106)
            vm.pc = 110
            vm._jump(6 if cells.value(26) != 0 else 7)
            continue
        if vm.block == 7:
            tick(110)
            vm.pc = 115
            cells.copy_q_clear_owned(4, 27)
            tick(115)
            _pointer(vm, 115, 3, 4, 28, (29, 29))
            tick(123)
            _pointer(vm, 123, 25, 0, 30, (19, 31))
            tick(131)
            _pointer(vm, 131, 3, 30, 32, (29, 29))
            tick(139)
            vm.pc = 143
            vm._jump(8 if cells.value(10) != 0 else 9)
            continue
        if vm.block == 6:
            tick(143)
            _pointer(vm, 143, 25, 0, 33, (19, 34))
            tick(151)
            vm.pc = 156
            cells.copy_q_clear_owned(21, 35)
            tick(156)
            _pointer(vm, 156, 14, 33, 36, (29, 35))
            tick(164)
            _pointer(vm, 164, 13, 36, 37, (19, 31))
            tick(172)
            vm.pc = 176
            value = memory.load(cells.value(37), 1)
            vm._write(38, value, 4, 'high.load')
            tick(176)
            vm.pc = 177
            tick(177)
            vm.pc = 180
            vm.auxiliary = (0, 1206004452)
            tick(180)
            vm.pc = 185
            vm._write(40, int(memory.load(cells.pointer(38), 1, signed=True) != memory.load(cells.pointer(39), 1, signed=True)), 4, 'L30.comparison')
            tick(185)
            vm.pc = 189
            vm._jump(10 if cells.value(40) != 0 else 5)
            continue
        if vm.block == 10:
            tick(189)
            _pointer(vm, 189, 12, 3, 41, (29, 29))
            tick(197)
            _pointer(vm, 197, 13, 36, 42, (19, 19))
            tick(205)
            _pointer(vm, 205, 12, 42, 43, (29, 29))
            tick(213)
            vm.pc = 217
            vm._jump(11 if cells.value(10) != 0 else 12)
            continue
        if vm.block == 11:
            tick(217)
            vm.pc = 219
            vm._jump(13)
            continue
        if vm.block == 13:
            tick(219)
            _phi(vm, 219, (44, 2, 43, 11, 45, 14))
            tick(226)
            _phi(vm, 226, (46, 2, 41, 11, 47, 14))
            tick(233)
            _phi(vm, 233, (48, 2, 20, 11, 49, 14))
            tick(240)
            vm.pc = 241
            tick(241)
            vm.pc = 244
            vm.auxiliary = (0, 1572192258)
            tick(244)
            vm.pc = 249
            vm._write(49, memory.load(cells.pointer(48), 8, signed=True) + memory.load(cells.pointer(50), 8, signed=True), 8, 'once1.integer')
            tick(249)
            vm.pc = 254
            vm._write(51, int(cells.value(48) > cells.value(29)), 4, 'L31.comparison')
            tick(254)
            vm.pc = 258
            vm._jump(14 if cells.value(51) != 0 else 15)
            continue
        if vm.block == 14:
            tick(258)
            _pointer(vm, 258, 2, 44, 45, (52,))
            tick(265)
            vm.pc = 269
            value = memory.load(cells.value(44), 1)
            vm._write(53, value, 4, 'high.load')
            tick(269)
            _pointer(vm, 269, 2, 46, 47, (52,))
            tick(276)
            vm.pc = 280
            pointer = cells.value(46)
            value = memory.load(cells.pointer(53), 1)
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
            _pointer(vm, 284, 13, 36, 54, (19, 52))
            tick(292)
            vm.pc = 296
            value = memory.load(cells.value(54), 1)
            vm._write(55, value, 4, 'high.load')
            tick(296)
            _pointer(vm, 296, 25, 0, 56, (19, 57))
            tick(304)
            _pointer(vm, 304, 5, 56, 58, (29, 29))
            tick(312)
            vm.pc = 316
            vm._jump(16 if cells.value(10) != 0 else 17)
            continue
        if vm.block == 16:
            tick(316)
            vm.pc = 321
            _convert(vm, 8, 55, 59)
            tick(321)
            _pointer(vm, 321, 5, 56, 60, (29, 59))
            tick(329)
            vm.pc = 333
            value = memory.load(cells.value(60), 1)
            vm._write(61, value, 4, 'high.load')
            tick(333)
            vm.pc = 335
            vm._jump(18)
            continue
        if vm.block == 18:
            tick(335)
            _phi(vm, 335, (62, 2, 61, 16, 63, 19))
            tick(342)
            _phi(vm, 342, (64, 2, 29, 16, 65, 19))
            tick(349)
            vm.pc = 354
            vm._write(66, int(cells.value(64) < cells.value(20)), 4, 'once18.unsigned_q')
            tick(354)
            vm.pc = 358
            vm._jump(19 if cells.value(66) != 0 else 20)
            continue
        if vm.block == 19:
            tick(358)
            vm.pc = 363
            _convert(vm, 4, 62, 67)
            tick(363)
            vm.pc = 364
            tick(364)
            vm.pc = 367
            vm.auxiliary = (0, 518451715)
            tick(367)
            vm.pc = 372
            vm._write(69, memory.load(cells.pointer(64), 8, signed=True) * memory.load(cells.pointer(68), 8, signed=True), 8, 'once0.integer')
            tick(372)
            vm.pc = 375
            vm.auxiliary = (0, 1676644354)
            tick(375)
            vm.pc = 380
            vm._write(70, memory.load(cells.pointer(69), 8, signed=True) + memory.load(cells.pointer(59), 8, signed=True), 8, 'once1.integer')
            tick(380)
            vm.pc = 385
            vm._write(71, cells.value(70) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 389
                width = vm.program.size(360601030)
                vm._write(71, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(385)
            vm.pc = 390
            _convert(vm, 4, 71, 72)
            tick(390)
            vm.pc = 393
            vm.auxiliary = (0, 35701)
            tick(393)
            vm.pc = 399
            vm._write(73, memory.load(cells.pointer(67), 4, signed=True) ^ memory.load(cells.pointer(72), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(399)
            _pointer(vm, 399, 12, 3, 74, (29, 64))
            tick(407)
            vm.pc = 411
            value = memory.load(cells.value(74), 1)
            vm._write(75, value, 4, 'high.load')
            tick(411)
            vm.pc = 416
            _convert(vm, 4, 75, 76)
            tick(416)
            vm.pc = 419
            vm.auxiliary = (0, 27421)
            tick(419)
            vm.pc = 425
            vm._write(77, memory.load(cells.pointer(76), 4, signed=True) ^ memory.load(cells.pointer(73), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(425)
            vm.pc = 430
            vm._write(78, cells.value(77) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 434
                width = vm.program.size(218307768)
                vm._write(74, cells.value(78) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(430)
            vm.pc = 434
            pointer = cells.value(74)
            value = memory.load(cells.pointer(78), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(434)
            vm.pc = 437
            vm.auxiliary = (0, 263905795)
            tick(437)
            vm.pc = 442
            vm._write(80, memory.load(cells.pointer(67), 4, signed=True) * memory.load(cells.pointer(79), 4, signed=True), 8, 'once0.integer')
            tick(442)
            vm.pc = 445
            vm.auxiliary = (0, 669134850)
            tick(445)
            vm.pc = 450
            vm._write(82, memory.load(cells.pointer(80), 4, signed=True) + memory.load(cells.pointer(81), 4, signed=True), 8, 'once1.integer')
            tick(450)
            vm.pc = 455
            vm._write(63, cells.value(82) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 459
                width = vm.program.size(52768)
                vm._write(92657197, cells.value(303587329) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(455)
            vm.pc = 458
            vm.auxiliary = (0, 303587329)
            tick(458)
            vm.pc = 463
            vm._write(65, memory.load(cells.pointer(64), 8, signed=True) + memory.load(cells.pointer(83), 8, signed=True), 8, 'once1.integer')
            tick(463)
            vm.pc = 465
            vm._jump(18)
            continue
        if vm.block == 20:
            tick(465)
            vm.pc = 467
            vm._jump(17)
            continue
        if vm.block == 17:
            tick(467)
            vm.pc = 468
            tick(468)
            vm.pc = 471
            vm.auxiliary = (0, 547513860)
            tick(471)
            vm.pc = 476
            vm._write(84, int(memory.load(cells.pointer(41), 8, signed=True) != memory.load(cells.pointer(1), 8, signed=True)), 4, 'L27.comparison')
            tick(476)
            vm.pc = 480
            vm._jump(21 if cells.value(84) != 0 else 22)
            continue
        if vm.block == 21:
            tick(480)
            vm.pc = 482
            vm._jump(23)
            continue
        if vm.block == 23:
            tick(482)
            _phi(vm, 482, (85, 2, 1, 21, 86, 24))
            tick(489)
            _phi(vm, 489, (87, 2, 41, 21, 88, 24))
            tick(496)
            _phi(vm, 496, (89, 2, 20, 21, 90, 24))
            tick(503)
            vm.pc = 504
            tick(504)
            vm.pc = 507
            vm.auxiliary = (0, 713756674)
            tick(507)
            vm.pc = 512
            vm._write(90, memory.load(cells.pointer(89), 8, signed=True) + memory.load(cells.pointer(50), 8, signed=True), 8, 'once1.integer')
            tick(512)
            vm.pc = 517
            vm._write(91, int(cells.value(89) > cells.value(29)), 4, 'L31.comparison')
            tick(517)
            vm.pc = 521
            vm._jump(25 if cells.value(91) != 0 else 26)
            continue
        if vm.block == 25:
            tick(521)
            vm.pc = 525
            value = memory.load(cells.value(87), 1)
            vm._write(92, value, 4, 'high.load')
            tick(525)
            vm.pc = 530
            _convert(vm, 4, 92, 93)
            tick(530)
            vm.pc = 534
            value = memory.load(cells.value(85), 1)
            vm._write(94, value, 4, 'high.load')
            tick(534)
            vm.pc = 539
            _convert(vm, 4, 94, 95)
            tick(539)
            vm.pc = 540
            tick(540)
            vm.pc = 543
            vm.auxiliary = (0, 1156751940)
            tick(543)
            vm.pc = 548
            vm._write(96, int(memory.load(cells.pointer(93), 4, signed=True) != memory.load(cells.pointer(95), 4, signed=True)), 4, 'L30.comparison')
            tick(548)
            vm.pc = 552
            vm._jump(27 if cells.value(96) != 0 else 24)
            continue
        if vm.block == 27:
            tick(552)
            vm.pc = 553
            tick(553)
            vm.pc = 556
            vm.auxiliary = (0, 54848)
            tick(556)
            vm.pc = 561
            vm._write(97, memory.load(cells.pointer(93), 4, signed=True) - memory.load(cells.pointer(95), 4, signed=True), 8, 'typed.selector0.q')
            tick(561)
            vm.pc = 563
            vm._jump(26)
            continue
        if vm.block == 24:
            tick(563)
            _pointer(vm, 563, 2, 87, 88, (52,))
            tick(570)
            _pointer(vm, 570, 2, 85, 86, (52,))
            tick(577)
            vm.pc = 579
            vm._jump(23)
            continue
        if vm.block == 26:
            tick(579)
            _phi(vm, 579, (98, 2, 97, 27, 19, 23))
            tick(586)
            vm.pc = 588
            vm._jump(22)
            continue
        if vm.block == 22:
            tick(588)
            _phi(vm, 588, (99, 2, 98, 26, 19, 17))
            tick(595)
            vm.pc = 596
            tick(596)
            vm.pc = 599
            vm.auxiliary = (0, 828553315)
            tick(599)
            extra = _single(vm)
            vm.pc = 604
            left_pointer = cells.pointer(99)
            right_pointer = cells.pointer(19)
            destination_pointer = cells.pointer(100)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 608
                left_pointer = cells.pointer(28)
                right_pointer = cells.pointer(100)
                destination_pointer = cells.pointer(29)
                width = vm.program.size(27239)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(27239)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 608
                left_pointer = cells.pointer(28)
                right_pointer = cells.pointer(100)
                destination_pointer = cells.pointer(29)
                width = vm.program.size(27239)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(27239)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(604)
            vm.pc = 608
            vm._jump(28 if cells.value(100) != 0 else 29)
            continue
        if vm.block == 28:
            tick(608)
            vm.pc = 613
            cells.copy_q_clear_owned(36, 101)
            tick(613)
            vm.pc = 617
            vm._jump(30 if cells.value(10) != 0 else 31)
            continue
        if vm.block == 30:
            tick(617)
            vm.pc = 619
            vm._jump(32)
            continue
        if vm.block == 32:
            tick(619)
            _phi(vm, 619, (102, 2, 101, 30, 103, 33))
            tick(626)
            _phi(vm, 626, (104, 2, 105, 30, 106, 33))
            tick(633)
            vm.pc = 634
            tick(634)
            vm.pc = 637
            vm.auxiliary = (0, 1471217666)
            tick(637)
            vm.pc = 642
            vm._write(106, memory.load(cells.pointer(104), 8, signed=True) + memory.load(cells.pointer(50), 8, signed=True), 8, 'once1.integer')
            tick(642)
            vm.pc = 647
            vm._write(107, int(cells.value(104) > cells.value(29)), 4, 'L31.comparison')
            tick(647)
            vm.pc = 651
            vm._jump(33 if cells.value(107) != 0 else 34)
            continue
        if vm.block == 33:
            tick(651)
            _pointer(vm, 651, 2, 102, 103, (52,))
            tick(658)
            vm.pc = 662
            pointer = cells.value(102)
            value = memory.load(cells.pointer(39), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(662)
            vm.pc = 664
            vm._jump(32)
            continue
        if vm.block == 34:
            tick(664)
            vm.pc = 666
            vm._jump(31)
            continue
        if vm.block == 31:
            tick(666)
            vm.pc = 668
            vm._jump(29)
            continue
        if vm.block == 29:
            tick(668)
            _phi(vm, 668, (108, 2, 52, 31, 23, 22))
            tick(675)
            vm.pc = 677
            vm._jump(5)
            continue
        if vm.block == 5:
            tick(677)
            _phi(vm, 677, (24, 2, 108, 29, 23, 6))
            tick(684)
            vm.pc = 685
            tick(685)
            vm.pc = 688
            vm.auxiliary = (0, 211124225)
            tick(688)
            vm.pc = 693
            vm._write(22, memory.load(cells.pointer(21), 4, signed=True) + memory.load(cells.pointer(52), 4, signed=True), 8, 'once1.integer')
            tick(693)
            vm.pc = 695
            vm._jump(4)
            continue
        if vm.block == 8:
            tick(695)
            vm.pc = 697
            vm._jump(35)
            continue
        if vm.block == 35:
            tick(697)
            _phi(vm, 697, (109, 2, 110, 8, 111, 36))
            tick(704)
            _phi(vm, 704, (112, 2, 28, 8, 113, 36))
            tick(711)
            _phi(vm, 711, (114, 2, 32, 8, 115, 36))
            tick(718)
            vm.pc = 719
            tick(719)
            vm.pc = 722
            vm.auxiliary = (0, 317788161)
            tick(722)
            vm.pc = 727
            vm._write(111, memory.load(cells.pointer(109), 8, signed=True) + memory.load(cells.pointer(50), 8, signed=True), 8, 'once1.integer')
            tick(727)
            vm.pc = 732
            vm._write(116, int(cells.value(109) > cells.value(29)), 4, 'L31.comparison')
            tick(732)
            vm.pc = 736
            vm._jump(36 if cells.value(116) != 0 else 37)
            continue
        if vm.block == 36:
            tick(736)
            _pointer(vm, 736, 2, 114, 115, (52,))
            tick(743)
            vm.pc = 747
            value = memory.load(cells.value(114), 1)
            vm._write(117, value, 4, 'high.load')
            tick(747)
            _pointer(vm, 747, 2, 112, 113, (52,))
            tick(754)
            vm.pc = 758
            pointer = cells.value(112)
            value = memory.load(cells.pointer(117), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(758)
            vm.pc = 760
            vm._jump(35)
            continue
        if vm.block == 37:
            tick(760)
            vm.pc = 762
            vm._jump(9)
            continue
        if vm.block == 9:
            tick(762)
            _pointer(vm, 762, 25, 0, 118, (19, 57))
            tick(770)
            _pointer(vm, 770, 5, 118, 119, (29, 29))
            tick(778)
            vm.pc = 782
            vm._jump(38 if cells.value(10) != 0 else 39)
            continue
        if vm.block == 38:
            tick(782)
            vm.pc = 786
            value = memory.load(cells.value(119), 1)
            vm._write(120, value, 4, 'high.load')
            tick(786)
            vm.pc = 788
            vm._jump(40)
            continue
        if vm.block == 40:
            tick(788)
            _phi(vm, 788, (121, 2, 29, 38, 122, 41))
            tick(795)
            _phi(vm, 795, (123, 2, 120, 38, 124, 41))
            tick(802)
            vm.pc = 807
            vm._write(125, int(cells.value(121) < cells.value(110)), 4, 'once18.unsigned_q')
            tick(807)
            vm.pc = 811
            vm._jump(41 if cells.value(125) != 0 else 42)
            continue
        if vm.block == 41:
            tick(811)
            vm.pc = 816
            _convert(vm, 4, 123, 126)
            tick(816)
            vm.pc = 817
            tick(817)
            vm.pc = 820
            vm.auxiliary = (0, 1526465028)
            tick(820)
            vm.pc = 825
            vm._write(127, memory.load(cells.pointer(121), 8, signed=True) * memory.load(cells.pointer(68), 8, signed=True), 8, 'once0.integer')
            tick(825)
            vm.pc = 830
            vm._write(128, cells.value(127) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 834
                width = vm.program.size(360601030)
                vm._write(128, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(830)
            vm.pc = 835
            _convert(vm, 4, 128, 129)
            tick(835)
            vm.pc = 840
            vm._write(130, memory.load(cells.pointer(126), 4, signed=True) ^ memory.load(cells.pointer(129), 4, signed=True), 8, 'L14.binary_q')
            tick(840)
            _pointer(vm, 840, 3, 4, 131, (29, 121))
            tick(848)
            vm.pc = 852
            value = memory.load(cells.value(131), 1)
            vm._write(132, value, 4, 'high.load')
            tick(852)
            vm.pc = 857
            _convert(vm, 4, 132, 133)
            tick(857)
            vm.pc = 860
            vm.auxiliary = (0, 56933)
            tick(860)
            vm.pc = 866
            vm._write(134, memory.load(cells.pointer(133), 4, signed=True) ^ memory.load(cells.pointer(130), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(866)
            vm.pc = 871
            vm._write(135, cells.value(134) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 875
                width = vm.program.size(218307768)
                vm._write(131, cells.value(135) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(871)
            vm.pc = 875
            pointer = cells.value(131)
            value = memory.load(cells.pointer(135), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(875)
            vm.pc = 878
            vm.auxiliary = (0, 906080772)
            tick(878)
            vm.pc = 883
            vm._write(136, memory.load(cells.pointer(126), 4, signed=True) * memory.load(cells.pointer(79), 4, signed=True), 8, 'once0.integer')
            tick(883)
            vm.pc = 886
            vm.auxiliary = (0, 1119236098)
            tick(886)
            vm.pc = 891
            vm._write(137, memory.load(cells.pointer(136), 4, signed=True) + memory.load(cells.pointer(81), 4, signed=True), 8, 'once1.integer')
            tick(891)
            vm.pc = 896
            vm._write(124, cells.value(137) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 900
                width = vm.program.size(16869)
                vm._write(92657197, cells.value(253259778) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(896)
            vm.pc = 899
            vm.auxiliary = (0, 253259778)
            tick(899)
            vm.pc = 904
            vm._write(122, memory.load(cells.pointer(121), 8, signed=True) + memory.load(cells.pointer(83), 8, signed=True), 8, 'once1.integer')
            tick(904)
            vm.pc = 906
            vm._jump(40)
            continue
        if vm.block == 42:
            tick(906)
            vm.pc = 908
            vm._jump(39)
            continue
        if vm.block == 39:
            tick(908)
            _pointer(vm, 908, 25, 0, 138, (19, 139))
            tick(916)
            vm.pc = 920
            value = memory.load(cells.value(138), 4)
            vm._write(140, value, 4, 'high.load')
            tick(920)
            _pointer(vm, 920, 25, 0, 141, (19, 19))
            tick(928)
            vm.pc = 932
            value = memory.load(cells.value(141), 4)
            vm._write(142, value, 4, 'high.load')
            tick(932)
            _pointer(vm, 932, 3, 4, 143, (29, 83))
            tick(940)
            vm.pc = 944
            value = memory.load(cells.value(143), 1)
            vm._write(144, value, 4, 'high.load')
            tick(944)
            vm.pc = 949
            _convert(vm, 4, 144, 145)
            tick(949)
            vm.pc = 950
            tick(950)
            vm.pc = 953
            vm.auxiliary = (0, 40781)
            tick(953)
            vm.pc = 959
            vm._write(146, memory.load(cells.pointer(142), 4, signed=True) ^ memory.load(cells.pointer(145), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(959)
            vm.pc = 962
            vm.auxiliary = (0, 35133)
            tick(962)
            vm.pc = 968
            vm._write(147, memory.load(cells.pointer(140), 4, signed=True) ^ memory.load(cells.pointer(146), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(968)
            _pointer(vm, 968, 25, 0, 148, (19, 149))
            tick(976)
            vm.pc = 980
            value = memory.load(cells.value(148), 1)
            vm._write(150, value, 4, 'high.load')
            tick(980)
            vm.pc = 985
            _convert(vm, 4, 150, 151)
            tick(985)
            vm.pc = 988
            vm.auxiliary = (0, 1970237441)
            tick(988)
            vm.pc = 993
            vm._write(152, memory.load(cells.pointer(151), 4, signed=True) + memory.load(cells.pointer(52), 4, signed=True), 8, 'once1.integer')
            tick(993)
            vm.pc = 998
            a = memory.load(cells.pointer(152), 4, signed=True)
            b = memory.load(cells.pointer(25), 4, signed=True)
            if b == 0 or (a == -(1 << 63) and b == -1):
                raise PrimaryProgramLimit('native signed IDIV64 fault outside ordinary execution')
            quotient = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
            vm._write(153, a - quotient * b, 8, "L16.signed_remainder_q")
            tick(998)
            vm.pc = 1003
            vm._write(154, cells.value(153) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1007
                width = vm.program.size(218307768)
                vm._write(148, cells.value(154) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1003)
            vm.pc = 1007
            pointer = cells.value(148)
            value = memory.load(cells.pointer(154), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1007)
            _pointer(vm, 1007, 25, 0, 155, (19, 34))
            tick(1015)
            vm.pc = 1020
            cells.copy_q_clear_owned(151, 156)
            tick(1020)
            _pointer(vm, 1020, 14, 155, 157, (29, 156))
            tick(1028)
            vm.pc = 1033
            cells.copy_q_clear_owned(157, 158)
            tick(1033)
            vm.pc = 1037
            vm._jump(43 if cells.value(10) != 0 else 44)
            continue
        if vm.block == 43:
            tick(1037)
            vm.pc = 1039
            vm._jump(45)
            continue
        if vm.block == 45:
            tick(1039)
            _phi(vm, 1039, (159, 2, 105, 43, 160, 46))
            tick(1046)
            _phi(vm, 1046, (161, 2, 158, 43, 162, 46))
            tick(1053)
            vm.pc = 1054
            tick(1054)
            vm.pc = 1057
            vm.auxiliary = (0, 1372901377)
            tick(1057)
            vm.pc = 1062
            vm._write(160, memory.load(cells.pointer(159), 8, signed=True) + memory.load(cells.pointer(50), 8, signed=True), 8, 'once1.integer')
            tick(1062)
            vm.pc = 1067
            vm._write(163, int(cells.value(159) > cells.value(29)), 4, 'L31.comparison')
            tick(1067)
            vm.pc = 1071
            vm._jump(46 if cells.value(163) != 0 else 47)
            continue
        if vm.block == 46:
            tick(1071)
            _pointer(vm, 1071, 2, 161, 162, (52,))
            tick(1078)
            vm.pc = 1082
            pointer = cells.value(161)
            value = memory.load(cells.pointer(39), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1082)
            vm.pc = 1084
            vm._jump(45)
            continue
        if vm.block == 47:
            tick(1084)
            vm.pc = 1086
            vm._jump(44)
            continue
        if vm.block == 44:
            tick(1086)
            _pointer(vm, 1086, 13, 157, 164, (19, 19))
            tick(1094)
            _pointer(vm, 1094, 12, 164, 165, (29, 29))
            tick(1102)
            vm.pc = 1106
            vm._jump(48 if cells.value(8) != 0 else 49)
            continue
        if vm.block == 48:
            tick(1106)
            vm.pc = 1108
            vm._jump(50)
            continue
        if vm.block == 50:
            tick(1108)
            _phi(vm, 1108, (166, 2, 2, 48, 167, 51))
            tick(1115)
            _phi(vm, 1115, (168, 2, 165, 48, 169, 51))
            tick(1122)
            _phi(vm, 1122, (170, 2, 1, 48, 171, 51))
            tick(1129)
            vm.pc = 1130
            tick(1130)
            vm.pc = 1133
            vm.auxiliary = (0, 807735298)
            tick(1133)
            vm.pc = 1138
            vm._write(167, memory.load(cells.pointer(166), 8, signed=True) + memory.load(cells.pointer(50), 8, signed=True), 8, 'once1.integer')
            tick(1138)
            vm.pc = 1143
            vm._write(172, int(cells.value(166) > cells.value(29)), 4, 'L31.comparison')
            tick(1143)
            vm.pc = 1147
            vm._jump(51 if cells.value(172) != 0 else 52)
            continue
        if vm.block == 51:
            tick(1147)
            _pointer(vm, 1147, 2, 170, 171, (52,))
            tick(1154)
            vm.pc = 1158
            value = memory.load(cells.value(170), 1)
            vm._write(173, value, 4, 'high.load')
            tick(1158)
            _pointer(vm, 1158, 2, 168, 169, (52,))
            tick(1165)
            vm.pc = 1169
            pointer = cells.value(168)
            value = memory.load(cells.pointer(173), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1169)
            vm.pc = 1171
            vm._jump(50)
            continue
        if vm.block == 52:
            tick(1171)
            vm.pc = 1173
            vm._jump(49)
            continue
        if vm.block == 49:
            tick(1173)
            vm.pc = 1177
            value = memory.load(cells.value(141), 4)
            vm._write(174, value, 4, 'high.load')
            tick(1177)
            vm.pc = 1178
            tick(1178)
            vm.pc = 1181
            vm.auxiliary = (0, 14916)
            tick(1181)
            vm.pc = 1187
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(175, memory.load(cells.pointer(174), 4, signed=True) ^ memory.load(cells.pointer(151), 4, signed=True), 8, 'typed.selector5.q')
            tick(1187)
            vm.pc = 1190
            vm.auxiliary = (0, 19461)
            tick(1190)
            vm.pc = 1196
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(177, memory.load(cells.pointer(175), 4, signed=True) ^ memory.load(cells.pointer(176), 4, signed=True), 8, 'typed.selector5.q')
            tick(1196)
            vm.pc = 1201
            vm._write(178, cells.value(177) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1205
                width = vm.program.size(360601030)
                vm._write(178, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1201)
            vm.pc = 1206
            _convert(vm, 4, 178, 179)
            tick(1206)
            vm.pc = 1211
            vm._write(181, memory.load(cells.pointer(179), 4, signed=True) & memory.load(cells.pointer(180), 4, signed=True), 8, 'L13.binary_q')
            tick(1211)
            vm.pc = 1216
            vm._write(182, cells.value(181) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1220
                width = vm.program.size(252598635)
                vm._write(13, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1216)
            _pointer(vm, 1216, 13, 157, 183, (19, 52))
            tick(1224)
            vm.pc = 1228
            pointer = cells.value(183)
            value = memory.load(cells.pointer(182), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1228)
            vm.pc = 1232
            vm._jump(53 if cells.value(10) != 0 else 54)
            continue
        if vm.block == 53:
            tick(1232)
            vm.pc = 1236
            vm._jump(55 if cells.value(10) != 0 else 54)
            continue
        if vm.block == 55:
            tick(1236)
            vm.pc = 1241
            _convert(vm, 8, 182, 184)
            tick(1241)
            _pointer(vm, 1241, 5, 118, 185, (29, 184))
            tick(1249)
            vm.pc = 1253
            value = memory.load(cells.value(185), 1)
            vm._write(186, value, 4, 'high.load')
            tick(1253)
            vm.pc = 1255
            vm._jump(56)
            continue
        if vm.block == 56:
            tick(1255)
            _phi(vm, 1255, (187, 2, 29, 55, 188, 57))
            tick(1262)
            _phi(vm, 1262, (189, 2, 186, 55, 190, 57))
            tick(1269)
            vm.pc = 1274
            vm._write(191, int(cells.value(187) < cells.value(20)), 4, 'once18.unsigned_q')
            tick(1274)
            vm.pc = 1278
            vm._jump(57 if cells.value(191) != 0 else 58)
            continue
        if vm.block == 57:
            tick(1278)
            vm.pc = 1283
            _convert(vm, 4, 189, 192)
            tick(1283)
            vm.pc = 1284
            tick(1284)
            vm.pc = 1287
            vm.auxiliary = (0, 1059803651)
            tick(1287)
            vm.pc = 1292
            vm._write(193, memory.load(cells.pointer(187), 8, signed=True) * memory.load(cells.pointer(68), 8, signed=True), 8, 'once0.integer')
            tick(1292)
            vm.pc = 1295
            vm.auxiliary = (0, 464621570)
            tick(1295)
            vm.pc = 1300
            vm._write(194, memory.load(cells.pointer(193), 8, signed=True) + memory.load(cells.pointer(184), 8, signed=True), 8, 'once1.integer')
            tick(1300)
            vm.pc = 1305
            vm._write(195, cells.value(194) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1309
                width = vm.program.size(360601030)
                vm._write(195, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1305)
            vm.pc = 1310
            _convert(vm, 4, 195, 196)
            tick(1310)
            vm.pc = 1313
            vm.auxiliary = (0, 64079)
            tick(1313)
            vm.pc = 1319
            vm._write(197, memory.load(cells.pointer(192), 4, signed=True) ^ memory.load(cells.pointer(196), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1319)
            _pointer(vm, 1319, 12, 164, 198, (29, 187))
            tick(1327)
            vm.pc = 1331
            value = memory.load(cells.value(198), 1)
            vm._write(199, value, 4, 'high.load')
            tick(1331)
            vm.pc = 1336
            _convert(vm, 4, 199, 200)
            tick(1336)
            vm.pc = 1339
            vm.auxiliary = (0, 15196)
            tick(1339)
            vm.pc = 1345
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(201, memory.load(cells.pointer(200), 4, signed=True) ^ memory.load(cells.pointer(197), 4, signed=True), 8, 'typed.selector5.q')
            tick(1345)
            vm.pc = 1350
            vm._write(202, cells.value(201) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1354
                width = vm.program.size(218307768)
                vm._write(198, cells.value(202) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1350)
            vm.pc = 1354
            pointer = cells.value(198)
            value = memory.load(cells.pointer(202), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1354)
            vm.pc = 1357
            vm.auxiliary = (0, 866365956)
            tick(1357)
            vm.pc = 1362
            vm._write(203, memory.load(cells.pointer(192), 4, signed=True) * memory.load(cells.pointer(79), 4, signed=True), 8, 'once0.integer')
            tick(1362)
            vm.pc = 1365
            vm.auxiliary = (0, 1022357506)
            tick(1365)
            vm.pc = 1370
            vm._write(204, memory.load(cells.pointer(203), 4, signed=True) + memory.load(cells.pointer(81), 4, signed=True), 8, 'once1.integer')
            tick(1370)
            vm.pc = 1375
            vm._write(190, cells.value(204) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1379
                width = vm.program.size(28373)
                vm._write(92657197, cells.value(1664978945) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1375)
            vm.pc = 1378
            vm.auxiliary = (0, 1664978945)
            tick(1378)
            vm.pc = 1383
            vm._write(188, memory.load(cells.pointer(187), 8, signed=True) + memory.load(cells.pointer(83), 8, signed=True), 8, 'once1.integer')
            tick(1383)
            vm.pc = 1385
            vm._jump(56)
            continue
        if vm.block == 58:
            tick(1385)
            vm.pc = 1387
            vm._jump(54)
            continue
        if vm.block == 54:
            tick(1387)
            _pointer(vm, 1387, 13, 157, 205, (19, 31))
            tick(1395)
            vm.pc = 1399
            pointer = cells.value(205)
            value = memory.load(cells.pointer(206), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1399)
            vm.pc = 1400
            tick(1400)
            vm.pc = 1403
            vm.auxiliary = (0, 1493347827)
            tick(1403)
            vm.pc = 1408
            vm._write(207, int(memory.load(cells.pointer(23), 4, signed=True) == memory.load(cells.pointer(19), 4, signed=True)), 4, 'once17.integer')
            tick(1408)
            vm.pc = 1413
            vm._write(208, int(cells.value(147) < cells.value(25)), 4, 'once18.unsigned_q')
            tick(1413)
            vm.pc = 1416
            vm.auxiliary = (0, 61566)
            tick(1416)
            vm.pc = 1421
            vm._write(209, memory.load(cells.pointer(207), 1, signed=True) & memory.load(cells.pointer(208), 1, signed=True), 8, 'typed.selector1.q')
            tick(1421)
            vm.pc = 1425
            vm._jump(59 if cells.value(209) != 0 else 60)
            continue
        if vm.block == 59:
            tick(1425)
            vm.pc = 1426
            tick(1426)
            vm.pc = 1429
            vm.auxiliary = (0, 1560793089)
            tick(1429)
            vm.pc = 1434
            vm._write(210, memory.load(cells.pointer(147), 4, signed=True) + memory.load(cells.pointer(52), 4, signed=True), 8, 'once1.integer')
            tick(1434)
            vm.pc = 1436
            vm._jump(60)
            continue
        if vm.block == 60:
            tick(1436)
            _phi(vm, 1436, (211, 2, 210, 59, 147, 54))
            tick(1443)
            vm.pc = 1447
            value = memory.load(cells.value(141), 4)
            vm._write(212, value, 4, 'high.load')
            tick(1447)
            vm.pc = 1451
            value = memory.load(cells.value(143), 1)
            vm._write(213, value, 4, 'high.load')
            tick(1451)
            vm.pc = 1456
            _convert(vm, 4, 213, 214)
            tick(1456)
            vm.pc = 1457
            tick(1457)
            vm.pc = 1460
            vm.auxiliary = (0, 55604)
            tick(1460)
            vm.pc = 1466
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(215, memory.load(cells.pointer(212), 4, signed=True) ^ memory.load(cells.pointer(214), 4, signed=True), 8, 'typed.selector5.q')
            tick(1466)
            vm.pc = 1469
            vm.auxiliary = (0, 27508)
            tick(1469)
            vm.pc = 1475
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(216, memory.load(cells.pointer(211), 4, signed=True) ^ memory.load(cells.pointer(215), 4, signed=True), 8, 'typed.selector5.q')
            tick(1475)
            vm.pc = 1479
            pointer = cells.value(138)
            value = memory.load(cells.pointer(216), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(1479)
            vm.pc = 1486
            _host(vm, 1479, 15, (0, 217), 33, None)
            tick(1486)
            vm.pc = 1489
            vm.auxiliary = (0, 2059582980)
            tick(1489)
            vm.pc = 1494
            vm._write(218, int(memory.load(cells.pointer(23), 4, signed=True) != memory.load(cells.pointer(19), 4, signed=True)), 4, 'L27.comparison')
            tick(1494)
            vm.pc = 1501
            selected = 52 if cells.value(218) != 0 else 19
            vm._write(219, memory.load(cells.pointer(selected), 4, signed=True), 8, 'L7.selected_q')
            tick(1501)
            vm.pc = 1503
            vm._jump(3)
            continue
        if vm.block == 3:
            tick(1503)
            _phi(vm, 1503, (220, 2, 221, 1, 219, 60))
            tick(1510)
            vm.pc = 1513
            vm.result = memory.load(cells.pointer(220), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('source2581 left its fixed source blocks')
