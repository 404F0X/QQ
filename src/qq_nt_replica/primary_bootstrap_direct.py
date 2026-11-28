import sys
from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, signed


PROGRAM_SHA256 = '8c1a0793046837e3592811b2f21af762c5e0b57a260b818e05671c0176dc8991'
_HOSTS = (0x3E92E00, 0x35921EC, 0x3EB2680, 0x359205B, 0x3592191, 0x3592178, 0x3592214, 0x3592244, 0x3592274)
BUFFER_SHA256 = 'b400646daeef6a35eb2782e2e677dcd93df186ff97a8fff6bf0f14f2a2557690'
_BUFFER_HOSTS = (0x3592086, 0x3E97020, 0x3EB2680, 0x35920C0, 0x3EB1FE0, 0x3592129, 0x3592161, 0x3E94F90)


def _source_frame(code, runtime, **values):
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is code:
            local = frame.f_locals
            if local.get('self', local.get('runtime')) is runtime and all(local.get(k) == v for k, v in values.items()):
                return frame
        frame = frame.f_back
    return None


def _authorize(vm, name):
    from .primary_caller import prepare
    from .primary_direct_scopes import PrimaryDirectScope
    from .primary_sign import PrimaryRuntime
    from .primary_sign_lifecycle import _PublicDirectOwner
    runtime = vm.runtime
    scope = getattr(runtime, '_primary_direct_scope', None)
    if type(scope) is PrimaryDirectScope and scope.client_owner is not None:
        from .primary_client_configuration_scope import authorize_bootstrap
        authorize_bootstrap(scope, vm, name, backend=True)
        return
    if type(scope) is PrimaryDirectScope and scope.initialization_owner is not None:
        scope._authorize_initialization_bootstrap(vm, name)
        return
    claim = getattr(runtime, '_primary_token_publication_claim', None)
    if type(scope) is PrimaryDirectScope and getattr(claim, 'caller', None) == 'own-response':
        scope._authorize_own_response_bootstrap(vm, name)
        return
    owner = getattr(runtime, '_primary_public_direct_owner', None)
    if (runtime is None or type(scope) is not PrimaryDirectScope or scope.runtime is not runtime or
            type(owner) is not _PublicDirectOwner or scope.public_owner is not owner or
            owner.runtime is not runtime or owner.thread != get_ident() or not owner.valid() or
            vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            runtime._active_main is not None or runtime._active_failed or
            runtime._execute_thread != get_ident() or runtime._execute_depth != (1 if name == 'singleton-init' else 2) or
            getattr(runtime, '_consumed_mgf', None) is not None or not runtime.vms or runtime.vms[-1] is not vm):
        raise PrimarySemanticUnavailable('bootstrap requires its actual public prepare owner and runtime reader')
    caller = scope._require_caller()
    reader = _source_frame(PrimaryRuntime._execute_program.__code__, runtime, name=name)
    preparation = _source_frame(prepare.__code__, runtime, command=caller.command)
    singleton = _source_frame(PrimaryRuntime._singleton.__code__, runtime)
    wrapper = _source_frame(PrimaryRuntime.invoke.__code__, runtime, rva=0x1BF75A0)
    calls = runtime._program_calls
    if (reader is None or reader.f_locals.get('vm') is not vm or preparation is None or singleton is None or
            wrapper is None or getattr(vm, '_primary_bootstrap_used', False)):
        raise PrimarySemanticUnavailable('bootstrap requires its one-use actual prepare singleton reader')
    if name == 'singleton-init':
        if (reader.f_locals.get('arguments') != () or reader.f_locals.get('hosts') != _HOSTS or
                len(calls) != 1 or calls[0] != dict(name=name, arguments=(), hosts=_HOSTS) or
                getattr(caller, '_bootstrap_used', False)):
            raise PrimarySemanticUnavailable('bootstrap requires its one-use actual singleton call and empty ABI')
        caller._bootstrap_used = True
        caller._bootstrap_root, caller._bootstrap_call = vm, calls[0]
    else:
        root = getattr(caller, '_bootstrap_root', None)
        native = _source_frame(_host.__code__, runtime)
        child_wrapper = _source_frame(PrimaryRuntime.invoke.__code__, runtime, rva=0x359205B)
        if (type(root) is not PrimaryVM or root.runtime is not runtime or root.memory is not runtime.memory or
                sha256(root.program.raw).hexdigest() != PROGRAM_SHA256 or
                (root.pc, root.block, root.predecessor, root.initial_block) != (170, 6, 4, False) or root.halted or
                len(runtime.vms) < 2 or runtime.vms[-2] is not root or len(calls) != 2 or
                calls[0] is not getattr(caller, '_bootstrap_call', None) or calls[1]['name'] != name or
                calls[1]['hosts'] != _BUFFER_HOSTS or len(calls[1]['arguments']) != 2 or
                reader.f_locals.get('arguments') != calls[1]['arguments'] or reader.f_locals.get('hosts') != _BUFFER_HOSTS or
                not root.host_calls or root.host_calls[-1] != (163, runtime.image_base + 0x359205B, (35, 34), 41) or
                getattr(root, '_primary_bootstrap_active_call', None) != (163, 37, (35, 34), 41, None) or
                native is None or native.f_locals.get('vm') is not root or child_wrapper is None or
                child_wrapper.f_locals.get('vm') is not root or child_wrapper.f_locals.get('cells') != (35, 34) or
                getattr(root, '_primary_bootstrap_child', None) is not None):
            raise PrimarySemanticUnavailable('buffer-init requires its actual one-use singleton word163 parent and ABI')
        root._primary_bootstrap_child = vm
    vm._primary_bootstrap_used = True


def execute_primary_bootstrap(vm, name, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    hashes = {'singleton-init': PROGRAM_SHA256, 'buffer-init': BUFFER_SHA256}
    if (type(vm) is not PrimaryVM or name not in hashes or
            sha256(vm.program.raw).hexdigest() != hashes[name] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used) != (1, 0, None, True, 0) or
            vm.halted or vm.abort_reason is not None or vm.trace or vm.host_calls or vm.auxiliary is not None or any(getattr(vm, key) is not None for key in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native', 'private_iv_native_pending'))):
        raise PrimarySemanticUnavailable('bootstrap requires its fixed fresh nonpending singleton source')
    _authorize(vm, name)
    state = dict(program=name, backend='DIRECT_BOOTSTRAP_LITERAL', completed=False,
                 referenceRecordCount=0, traceComplete=False, completeIndependentMain=False,
                 controlDomain='NONWAITING_ONCE10_FIXED_FINITE_ONCE9_ALTERNATE_ERRORS')
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_bootstrap_direct_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    {'singleton-init': _singleton_init, 'buffer-init': _buffer_init}[name](vm, tick)
    state['completed'] = True
    return vm.result


def _host(vm, word, callee, arguments, signature, destination):
    runtime = vm.runtime
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    vm._primary_bootstrap_active_call = (word, callee, arguments, signature, destination)
    try:
        result = _invoke_host(vm, address, arguments, signature,
                              argument_types=vm.program.type(signature).parameters[3:])
    finally:
        vm._primary_bootstrap_active_call = None
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


def _singleton_init(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(3, 0)
            tick(4)
            vm.pc = 12
            _host(vm, 4, 2, (3, 4), 30, 1)
            tick(12)
            vm.pc = 17
            cells.copy_q_clear_owned(1, 5)
            tick(17)
            vm.pc = 18
            tick(18)
            vm.pc = 21
            vm.auxiliary = (0, 1278399299)
            tick(21)
            vm.pc = 26
            vm._write(7, int(memory.load(cells.pointer(5), 8, signed=True) == memory.load(cells.pointer(6), 8, signed=True)), 4, 'once17.integer')
            tick(26)
            vm.pc = 30
            vm._jump(1 if cells.value(7) != 0 else 2)
            continue
        if vm.block == 1:
            tick(30)
            vm.pc = 32
            vm._jump(3)
            continue
        if vm.block == 2:
            tick(32)
            vm.pc = 39
            _host(vm, 32, 9, (10,), 34, 8)
            tick(39)
            vm.pc = 44
            vm._write(11, cells.value(8) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 48
                width = vm.program.size(20056)
                vm._write(5, cells.value(26) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(44)
            vm.pc = 49
            cells.copy_q_clear_owned(5, 12)
            tick(49)
            vm.pc = 54
            vm._write(13, cells.value(12) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 58
                width = vm.program.size(9999)
                vm._write(13, cells.value(11) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(54)
            vm.pc = 59
            vm._write(14, memory.load(cells.pointer(11), 4, signed=True) ^ memory.load(cells.pointer(13), 4, signed=True), 8, 'L14.binary_q')
            tick(59)
            _pointer(vm, 59, 25, 5, 15, (16, 16))
            tick(67)
            vm.pc = 71
            pointer = cells.value(15)
            value = memory.load(cells.pointer(14), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(71)
            vm.pc = 76
            vm._write(17, cells.value(14) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 80
                width = vm.program.size(360601030)
                vm._write(17, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(76)
            vm.pc = 81
            _convert(vm, 4, 17, 18)
            tick(81)
            vm.pc = 82
            tick(82)
            vm.pc = 85
            vm.auxiliary = (0, 18439)
            tick(85)
            vm.pc = 91
            vm._write(20, memory.load(cells.pointer(19), 4, signed=True) ^ memory.load(cells.pointer(18), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(91)
            vm.pc = 96
            vm._write(21, cells.value(20) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 100
                width = vm.program.size(252598635)
                vm._write(25, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(96)
            _pointer(vm, 96, 25, 5, 22, (16, 23))
            tick(104)
            vm.pc = 108
            pointer = cells.value(22)
            value = memory.load(cells.pointer(21), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(108)
            vm.pc = 112
            value = memory.load(cells.value(15), 4)
            vm._write(24, value, 4, 'high.load')
            tick(112)
            vm.pc = 114
            vm._jump(4)
            continue
        if vm.block == 4:
            tick(114)
            _phi(vm, 114, (25, 2, 16, 2, 26, 5))
            tick(121)
            _phi(vm, 121, (27, 2, 24, 2, 28, 5))
            tick(128)
            vm.pc = 129
            tick(129)
            vm.pc = 132
            vm.auxiliary = (0, 1703065733)
            tick(132)
            vm.pc = 137
            a = memory.load(cells.pointer(25), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(29), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(30, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(137)
            vm.pc = 141
            vm._jump(5 if cells.value(30) != 0 else 6)
            continue
        if vm.block == 6:
            tick(141)
            vm.pc = 146
            cells.copy_q_clear_owned(0, 31)
            tick(146)
            vm.pc = 155
            _host(vm, 146, 33, (31, 16, 34), 38, 32)
            tick(155)
            _pointer(vm, 155, 3, 0, 35, (36, 36))
            tick(163)
            vm.pc = 170
            _host(vm, 163, 37, (35, 34), 41, None)
            tick(170)
            vm.pc = 176
            _host(vm, 170, 38, (5,), 43, None)
            tick(176)
            vm.pc = 183
            _host(vm, 176, 39, (5, 40), 45, None)
            tick(183)
            _pointer(vm, 183, 25, 5, 41, (16, 42))
            tick(191)
            _pointer(vm, 191, 5, 41, 43, (36, 36))
            tick(199)
            vm.pc = 203
            vm._jump(7 if cells.value(40) != 0 else 8)
            continue
        if vm.block == 5:
            tick(203)
            vm.pc = 204
            tick(204)
            vm.pc = 207
            vm.auxiliary = (0, 1116041731)
            tick(207)
            vm.pc = 212
            vm._write(45, memory.load(cells.pointer(27), 4, signed=True) * memory.load(cells.pointer(44), 4, signed=True), 8, 'once0.integer')
            tick(212)
            vm.pc = 215
            vm.auxiliary = (0, 1110347777)
            tick(215)
            vm.pc = 220
            vm._write(28, memory.load(cells.pointer(45), 4, signed=True) + memory.load(cells.pointer(46), 4, signed=True), 8, 'once1.integer')
            tick(220)
            vm.pc = 225
            value = memory.load(cells.pointer(28), 4)
            count = memory.load(cells.pointer(47), 1)
            vm._write(48, value >> (count & 31), 4, 'once8.logical_shift')
            tick(225)
            vm.pc = 230
            vm._write(49, cells.value(48) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 234
                width = vm.program.size(360601030)
                vm._write(49, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(230)
            vm.pc = 235
            _convert(vm, 4, 49, 50)
            tick(235)
            vm.pc = 240
            vm._write(51, memory.load(cells.pointer(50), 4, signed=True) | memory.load(cells.pointer(23), 4, signed=True), 8, 'L15.binary_q')
            tick(240)
            vm.pc = 245
            vm._write(52, cells.value(51) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 249
                width = vm.program.size(252598635)
                vm._write(25, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(245)
            _pointer(vm, 245, 25, 5, 53, (16, 42))
            tick(253)
            vm.pc = 258
            cells.copy_q_clear_owned(25, 54)
            tick(258)
            _pointer(vm, 258, 5, 53, 55, (36, 54))
            tick(266)
            vm.pc = 270
            pointer = cells.value(55)
            value = memory.load(cells.pointer(52), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(270)
            vm.pc = 273
            vm.auxiliary = (0, 1817710593)
            tick(273)
            vm.pc = 278
            vm._write(26, memory.load(cells.pointer(25), 4, signed=True) + memory.load(cells.pointer(23), 4, signed=True), 8, 'once1.integer')
            tick(278)
            vm.pc = 280
            vm._jump(4)
            continue
        if vm.block == 7:
            tick(280)
            _pointer(vm, 280, 5, 41, 56, (36, 57))
            tick(288)
            vm.pc = 292
            value = memory.load(cells.value(56), 1)
            vm._write(58, value, 4, 'high.load')
            tick(292)
            vm.pc = 294
            vm._jump(9)
            continue
        if vm.block == 9:
            tick(294)
            _phi(vm, 294, (59, 2, 58, 7, 60, 10))
            tick(301)
            _phi(vm, 301, (61, 2, 36, 7, 62, 10))
            tick(308)
            vm.pc = 313
            vm._write(63, int(cells.value(61) < cells.value(34)), 4, 'once18.unsigned_q')
            tick(313)
            vm.pc = 317
            vm._jump(10 if cells.value(63) != 0 else 11)
            continue
        if vm.block == 10:
            tick(317)
            vm.pc = 322
            _convert(vm, 4, 59, 64)
            tick(322)
            vm.pc = 323
            tick(323)
            vm.pc = 326
            vm.auxiliary = (0, 1512866308)
            tick(326)
            vm.pc = 331
            vm._write(66, memory.load(cells.pointer(61), 8, signed=True) * memory.load(cells.pointer(65), 8, signed=True), 8, 'once0.integer')
            tick(331)
            vm.pc = 334
            vm.auxiliary = (0, 814944257)
            tick(334)
            vm.pc = 339
            vm._write(67, memory.load(cells.pointer(66), 8, signed=True) + memory.load(cells.pointer(57), 8, signed=True), 8, 'once1.integer')
            tick(339)
            vm.pc = 344
            vm._write(68, cells.value(67) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 348
                width = vm.program.size(360601030)
                vm._write(68, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(344)
            vm.pc = 349
            _convert(vm, 4, 68, 69)
            tick(349)
            vm.pc = 354
            vm._write(70, memory.load(cells.pointer(64), 4, signed=True) ^ memory.load(cells.pointer(69), 4, signed=True), 8, 'L14.binary_q')
            tick(354)
            _pointer(vm, 354, 3, 0, 71, (36, 61))
            tick(362)
            vm.pc = 366
            value = memory.load(cells.value(71), 1)
            vm._write(72, value, 4, 'high.load')
            tick(366)
            vm.pc = 371
            _convert(vm, 4, 72, 73)
            tick(371)
            vm.pc = 374
            vm.auxiliary = (0, 6735)
            tick(374)
            vm.pc = 380
            vm._write(74, memory.load(cells.pointer(73), 4, signed=True) ^ memory.load(cells.pointer(70), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(380)
            vm.pc = 385
            vm._write(75, cells.value(74) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 389
                width = vm.program.size(218307768)
                vm._write(71, cells.value(75) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(385)
            vm.pc = 389
            pointer = cells.value(71)
            value = memory.load(cells.pointer(75), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(389)
            vm.pc = 392
            vm.auxiliary = (0, 1466655236)
            tick(392)
            vm.pc = 397
            vm._write(77, memory.load(cells.pointer(64), 4, signed=True) * memory.load(cells.pointer(76), 4, signed=True), 8, 'once0.integer')
            tick(397)
            vm.pc = 400
            vm.auxiliary = (0, 1163874306)
            tick(400)
            vm.pc = 405
            vm._write(79, memory.load(cells.pointer(77), 4, signed=True) + memory.load(cells.pointer(78), 4, signed=True), 8, 'once1.integer')
            tick(405)
            vm.pc = 410
            vm._write(60, cells.value(79) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 414
                width = vm.program.size(4861)
                vm._write(92657197, cells.value(411004929) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(410)
            vm.pc = 413
            vm.auxiliary = (0, 411004929)
            tick(413)
            vm.pc = 418
            vm._write(62, memory.load(cells.pointer(61), 8, signed=True) + memory.load(cells.pointer(3), 8, signed=True), 8, 'once1.integer')
            tick(418)
            vm.pc = 420
            vm._jump(9)
            continue
        if vm.block == 11:
            tick(420)
            vm.pc = 422
            vm._jump(8)
            continue
        if vm.block == 8:
            tick(422)
            _pointer(vm, 422, 25, 5, 80, (16, 81))
            tick(430)
            _pointer(vm, 430, 3, 80, 82, (36, 36))
            tick(438)
            vm.pc = 442
            vm._jump(12 if cells.value(40) != 0 else 13)
            continue
        if vm.block == 12:
            tick(442)
            vm.pc = 444
            vm._jump(14)
            continue
        if vm.block == 14:
            tick(444)
            _phi(vm, 444, (83, 2, 35, 12, 84, 15))
            tick(451)
            _phi(vm, 451, (85, 2, 82, 12, 86, 15))
            tick(458)
            _phi(vm, 458, (87, 2, 34, 12, 88, 15))
            tick(465)
            vm.pc = 466
            tick(466)
            vm.pc = 469
            vm.auxiliary = (0, 1622302722)
            tick(469)
            vm.pc = 474
            vm._write(88, memory.load(cells.pointer(87), 8, signed=True) + memory.load(cells.pointer(89), 8, signed=True), 8, 'once1.integer')
            tick(474)
            vm.pc = 479
            vm._write(90, int(cells.value(87) > cells.value(36)), 4, 'L31.comparison')
            tick(479)
            vm.pc = 483
            vm._jump(15 if cells.value(90) != 0 else 16)
            continue
        if vm.block == 15:
            tick(483)
            _pointer(vm, 483, 2, 83, 84, (23,))
            tick(490)
            vm.pc = 494
            value = memory.load(cells.value(83), 1)
            vm._write(91, value, 4, 'high.load')
            tick(494)
            _pointer(vm, 494, 2, 85, 86, (23,))
            tick(501)
            vm.pc = 505
            pointer = cells.value(85)
            value = memory.load(cells.pointer(91), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(505)
            vm.pc = 507
            vm._jump(14)
            continue
        if vm.block == 16:
            tick(507)
            vm.pc = 509
            vm._jump(13)
            continue
        if vm.block == 13:
            tick(509)
            vm.pc = 513
            vm._jump(17 if cells.value(40) != 0 else 18)
            continue
        if vm.block == 17:
            tick(513)
            vm.pc = 517
            vm._jump(19 if cells.value(40) != 0 else 18)
            continue
        if vm.block == 19:
            tick(517)
            vm.pc = 521
            value = memory.load(cells.value(43), 1)
            vm._write(92, value, 4, 'high.load')
            tick(521)
            vm.pc = 523
            vm._jump(20)
            continue
        if vm.block == 20:
            tick(523)
            _phi(vm, 523, (93, 2, 36, 19, 94, 21))
            tick(530)
            _phi(vm, 530, (95, 2, 92, 19, 96, 21))
            tick(537)
            vm.pc = 542
            vm._write(97, int(cells.value(93) < cells.value(34)), 4, 'once18.unsigned_q')
            tick(542)
            vm.pc = 546
            vm._jump(21 if cells.value(97) != 0 else 22)
            continue
        if vm.block == 21:
            tick(546)
            vm.pc = 551
            _convert(vm, 4, 95, 98)
            tick(551)
            vm.pc = 552
            tick(552)
            vm.pc = 555
            vm.auxiliary = (0, 204370436)
            tick(555)
            vm.pc = 560
            vm._write(99, memory.load(cells.pointer(93), 8, signed=True) * memory.load(cells.pointer(65), 8, signed=True), 8, 'once0.integer')
            tick(560)
            vm.pc = 565
            vm._write(100, cells.value(99) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 569
                width = vm.program.size(360601030)
                vm._write(100, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(565)
            vm.pc = 570
            _convert(vm, 4, 100, 101)
            tick(570)
            vm.pc = 573
            vm.auxiliary = (0, 56158)
            tick(573)
            vm.pc = 579
            vm._write(102, memory.load(cells.pointer(98), 4, signed=True) ^ memory.load(cells.pointer(101), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(579)
            _pointer(vm, 579, 3, 80, 103, (36, 93))
            tick(587)
            vm.pc = 591
            value = memory.load(cells.value(103), 1)
            vm._write(104, value, 4, 'high.load')
            tick(591)
            vm.pc = 596
            _convert(vm, 4, 104, 105)
            tick(596)
            vm.pc = 599
            vm.auxiliary = (0, 20054)
            tick(599)
            vm.pc = 605
            vm._write(106, memory.load(cells.pointer(105), 4, signed=True) ^ memory.load(cells.pointer(102), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(605)
            vm.pc = 610
            vm._write(107, cells.value(106) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 614
                width = vm.program.size(218307768)
                vm._write(103, cells.value(107) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(610)
            vm.pc = 614
            pointer = cells.value(103)
            value = memory.load(cells.pointer(107), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(614)
            vm.pc = 617
            vm.auxiliary = (0, 614781444)
            tick(617)
            vm.pc = 622
            vm._write(108, memory.load(cells.pointer(98), 4, signed=True) * memory.load(cells.pointer(76), 4, signed=True), 8, 'once0.integer')
            tick(622)
            vm.pc = 625
            vm.auxiliary = (0, 1210048514)
            tick(625)
            vm.pc = 630
            vm._write(109, memory.load(cells.pointer(108), 4, signed=True) + memory.load(cells.pointer(78), 4, signed=True), 8, 'once1.integer')
            tick(630)
            vm.pc = 635
            vm._write(96, cells.value(109) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 639
                width = vm.program.size(54956)
                vm._write(92657197, cells.value(1464307714) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(635)
            vm.pc = 638
            vm.auxiliary = (0, 1464307714)
            tick(638)
            vm.pc = 643
            vm._write(94, memory.load(cells.pointer(93), 8, signed=True) + memory.load(cells.pointer(3), 8, signed=True), 8, 'once1.integer')
            tick(643)
            vm.pc = 645
            vm._jump(20)
            continue
        if vm.block == 22:
            tick(645)
            vm.pc = 647
            vm._jump(18)
            continue
        if vm.block == 18:
            tick(647)
            _pointer(vm, 647, 25, 5, 110, (16, 111))
            tick(655)
            _pointer(vm, 655, 4, 110, 112, (36, 36))
            tick(663)
            vm.pc = 667
            pointer = cells.value(112)
            value = memory.load(cells.pointer(113), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(667)
            vm.pc = 671
            vm._jump(23 if cells.value(40) != 0 else 24)
            continue
        if vm.block == 23:
            tick(671)
            vm.pc = 675
            vm._jump(25 if cells.value(40) != 0 else 24)
            continue
        if vm.block == 25:
            tick(675)
            _pointer(vm, 675, 5, 41, 114, (36, 3))
            tick(683)
            vm.pc = 687
            value = memory.load(cells.value(114), 1)
            vm._write(115, value, 4, 'high.load')
            tick(687)
            vm.pc = 689
            vm._jump(26)
            continue
        if vm.block == 26:
            tick(689)
            _phi(vm, 689, (116, 2, 36, 25, 117, 27))
            tick(696)
            _phi(vm, 696, (118, 2, 115, 25, 119, 27))
            tick(703)
            vm.pc = 708
            vm._write(120, int(cells.value(116) < cells.value(3)), 4, 'once18.unsigned_q')
            tick(708)
            vm.pc = 712
            vm._jump(27 if cells.value(120) != 0 else 28)
            continue
        if vm.block == 27:
            tick(712)
            vm.pc = 717
            _convert(vm, 4, 118, 121)
            tick(717)
            vm.pc = 718
            tick(718)
            vm.pc = 721
            vm.auxiliary = (0, 620065283)
            tick(721)
            vm.pc = 726
            vm._write(122, memory.load(cells.pointer(116), 8, signed=True) * memory.load(cells.pointer(65), 8, signed=True), 8, 'once0.integer')
            tick(726)
            vm.pc = 729
            vm.auxiliary = (0, 1460006913)
            tick(729)
            vm.pc = 734
            vm._write(123, memory.load(cells.pointer(122), 8, signed=True) + memory.load(cells.pointer(3), 8, signed=True), 8, 'once1.integer')
            tick(734)
            vm.pc = 739
            vm._write(124, cells.value(123) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 743
                width = vm.program.size(360601030)
                vm._write(124, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(739)
            vm.pc = 744
            _convert(vm, 4, 124, 125)
            tick(744)
            vm.pc = 747
            vm.auxiliary = (0, 52333)
            tick(747)
            vm.pc = 753
            vm._write(126, memory.load(cells.pointer(121), 4, signed=True) ^ memory.load(cells.pointer(125), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(753)
            _pointer(vm, 753, 4, 110, 127, (36, 116))
            tick(761)
            vm.pc = 765
            value = memory.load(cells.value(127), 1)
            vm._write(128, value, 4, 'high.load')
            tick(765)
            vm.pc = 770
            _convert(vm, 4, 128, 129)
            tick(770)
            vm.pc = 775
            vm._write(130, memory.load(cells.pointer(129), 4, signed=True) ^ memory.load(cells.pointer(126), 4, signed=True), 8, 'L14.binary_q')
            tick(775)
            vm.pc = 780
            vm._write(131, cells.value(130) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 784
                width = vm.program.size(218307768)
                vm._write(127, cells.value(131) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(780)
            vm.pc = 784
            pointer = cells.value(127)
            value = memory.load(cells.pointer(131), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(784)
            vm.pc = 787
            vm.auxiliary = (0, 1513533955)
            tick(787)
            vm.pc = 792
            vm._write(132, memory.load(cells.pointer(121), 4, signed=True) * memory.load(cells.pointer(76), 4, signed=True), 8, 'once0.integer')
            tick(792)
            vm.pc = 795
            vm.auxiliary = (0, 558899202)
            tick(795)
            vm.pc = 800
            vm._write(133, memory.load(cells.pointer(132), 4, signed=True) + memory.load(cells.pointer(78), 4, signed=True), 8, 'once1.integer')
            tick(800)
            vm.pc = 805
            vm._write(119, cells.value(133) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 809
                width = vm.program.size(61406)
                vm._write(92657197, cells.value(2078179330) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(805)
            vm.pc = 808
            vm.auxiliary = (0, 2078179330)
            tick(808)
            vm.pc = 813
            vm._write(117, memory.load(cells.pointer(116), 8, signed=True) + memory.load(cells.pointer(3), 8, signed=True), 8, 'once1.integer')
            tick(813)
            vm.pc = 815
            vm._jump(26)
            continue
        if vm.block == 28:
            tick(815)
            vm.pc = 817
            vm._jump(24)
            continue
        if vm.block == 24:
            tick(817)
            _pointer(vm, 817, 25, 5, 134, (16, 135))
            tick(825)
            _pointer(vm, 825, 4, 134, 136, (36, 36))
            tick(833)
            vm.pc = 837
            pointer = cells.value(136)
            value = memory.load(cells.pointer(137), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(837)
            vm.pc = 841
            vm._jump(29 if cells.value(40) != 0 else 30)
            continue
        if vm.block == 29:
            tick(841)
            vm.pc = 845
            vm._jump(31 if cells.value(40) != 0 else 30)
            continue
        if vm.block == 31:
            tick(845)
            _pointer(vm, 845, 5, 41, 138, (36, 139))
            tick(853)
            vm.pc = 857
            value = memory.load(cells.value(138), 1)
            vm._write(140, value, 4, 'high.load')
            tick(857)
            vm.pc = 859
            vm._jump(32)
            continue
        if vm.block == 32:
            tick(859)
            _phi(vm, 859, (141, 2, 36, 31, 142, 33))
            tick(866)
            _phi(vm, 866, (143, 2, 140, 31, 144, 33))
            tick(873)
            vm.pc = 878
            vm._write(145, int(cells.value(141) < cells.value(3)), 4, 'once18.unsigned_q')
            tick(878)
            vm.pc = 882
            vm._jump(33 if cells.value(145) != 0 else 34)
            continue
        if vm.block == 33:
            tick(882)
            vm.pc = 887
            _convert(vm, 4, 143, 146)
            tick(887)
            vm.pc = 888
            tick(888)
            vm.pc = 891
            vm.auxiliary = (0, 1575412227)
            tick(891)
            vm.pc = 896
            vm._write(147, memory.load(cells.pointer(141), 8, signed=True) * memory.load(cells.pointer(65), 8, signed=True), 8, 'once0.integer')
            tick(896)
            vm.pc = 899
            vm.auxiliary = (0, 1265541122)
            tick(899)
            vm.pc = 904
            vm._write(148, memory.load(cells.pointer(147), 8, signed=True) + memory.load(cells.pointer(139), 8, signed=True), 8, 'once1.integer')
            tick(904)
            vm.pc = 909
            vm._write(149, cells.value(148) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 913
                width = vm.program.size(360601030)
                vm._write(149, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(909)
            vm.pc = 914
            _convert(vm, 4, 149, 150)
            tick(914)
            vm.pc = 919
            vm._write(151, memory.load(cells.pointer(146), 4, signed=True) ^ memory.load(cells.pointer(150), 4, signed=True), 8, 'L14.binary_q')
            tick(919)
            _pointer(vm, 919, 4, 134, 152, (36, 141))
            tick(927)
            vm.pc = 931
            value = memory.load(cells.value(152), 1)
            vm._write(153, value, 4, 'high.load')
            tick(931)
            vm.pc = 936
            _convert(vm, 4, 153, 154)
            tick(936)
            vm.pc = 941
            vm._write(155, memory.load(cells.pointer(154), 4, signed=True) ^ memory.load(cells.pointer(151), 4, signed=True), 8, 'L14.binary_q')
            tick(941)
            vm.pc = 946
            vm._write(156, cells.value(155) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 950
                width = vm.program.size(218307768)
                vm._write(152, cells.value(156) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(946)
            vm.pc = 950
            pointer = cells.value(152)
            value = memory.load(cells.pointer(156), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(950)
            vm.pc = 953
            vm.auxiliary = (0, 1262658051)
            tick(953)
            vm.pc = 958
            vm._write(157, memory.load(cells.pointer(146), 4, signed=True) * memory.load(cells.pointer(76), 4, signed=True), 8, 'once0.integer')
            tick(958)
            vm.pc = 961
            vm.auxiliary = (0, 868597761)
            tick(961)
            vm.pc = 966
            vm._write(158, memory.load(cells.pointer(157), 4, signed=True) + memory.load(cells.pointer(78), 4, signed=True), 8, 'once1.integer')
            tick(966)
            vm.pc = 971
            vm._write(144, cells.value(158) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 975
                width = vm.program.size(56416)
                vm._write(92657197, cells.value(1512173569) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(971)
            vm.pc = 974
            vm.auxiliary = (0, 1512173569)
            tick(974)
            vm.pc = 979
            vm._write(142, memory.load(cells.pointer(141), 8, signed=True) + memory.load(cells.pointer(3), 8, signed=True), 8, 'once1.integer')
            tick(979)
            vm.pc = 981
            vm._jump(32)
            continue
        if vm.block == 34:
            tick(981)
            vm.pc = 983
            vm._jump(30)
            continue
        if vm.block == 30:
            tick(983)
            _pointer(vm, 983, 25, 5, 159, (16, 160))
            tick(991)
            _pointer(vm, 991, 4, 159, 161, (36, 36))
            tick(999)
            vm.pc = 1003
            pointer = cells.value(161)
            value = memory.load(cells.pointer(162), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1003)
            vm.pc = 1007
            vm._jump(35 if cells.value(40) != 0 else 36)
            continue
        if vm.block == 35:
            tick(1007)
            vm.pc = 1011
            vm._jump(37 if cells.value(40) != 0 else 36)
            continue
        if vm.block == 37:
            tick(1011)
            _pointer(vm, 1011, 5, 41, 163, (36, 164))
            tick(1019)
            vm.pc = 1023
            value = memory.load(cells.value(163), 1)
            vm._write(165, value, 4, 'high.load')
            tick(1023)
            vm.pc = 1025
            vm._jump(38)
            continue
        if vm.block == 38:
            tick(1025)
            _phi(vm, 1025, (166, 2, 36, 37, 167, 39))
            tick(1032)
            _phi(vm, 1032, (168, 2, 165, 37, 169, 39))
            tick(1039)
            vm.pc = 1044
            vm._write(170, int(cells.value(166) < cells.value(3)), 4, 'once18.unsigned_q')
            tick(1044)
            vm.pc = 1048
            vm._jump(39 if cells.value(170) != 0 else 40)
            continue
        if vm.block == 39:
            tick(1048)
            vm.pc = 1053
            _convert(vm, 4, 168, 171)
            tick(1053)
            vm.pc = 1054
            tick(1054)
            vm.pc = 1057
            vm.auxiliary = (0, 1561465347)
            tick(1057)
            vm.pc = 1062
            vm._write(172, memory.load(cells.pointer(166), 8, signed=True) * memory.load(cells.pointer(65), 8, signed=True), 8, 'once0.integer')
            tick(1062)
            vm.pc = 1065
            vm.auxiliary = (0, 658829314)
            tick(1065)
            vm.pc = 1070
            vm._write(173, memory.load(cells.pointer(172), 8, signed=True) + memory.load(cells.pointer(164), 8, signed=True), 8, 'once1.integer')
            tick(1070)
            vm.pc = 1075
            vm._write(174, cells.value(173) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1079
                width = vm.program.size(360601030)
                vm._write(174, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1075)
            vm.pc = 1080
            _convert(vm, 4, 174, 175)
            tick(1080)
            vm.pc = 1083
            vm.auxiliary = (0, 18532)
            tick(1083)
            vm.pc = 1089
            vm._write(176, memory.load(cells.pointer(171), 4, signed=True) ^ memory.load(cells.pointer(175), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1089)
            _pointer(vm, 1089, 4, 159, 177, (36, 166))
            tick(1097)
            vm.pc = 1101
            value = memory.load(cells.value(177), 1)
            vm._write(178, value, 4, 'high.load')
            tick(1101)
            vm.pc = 1106
            _convert(vm, 4, 178, 179)
            tick(1106)
            vm.pc = 1109
            vm.auxiliary = (0, 35446)
            tick(1109)
            vm.pc = 1115
            vm._write(180, memory.load(cells.pointer(179), 4, signed=True) ^ memory.load(cells.pointer(176), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1115)
            vm.pc = 1120
            vm._write(181, cells.value(180) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1124
                width = vm.program.size(218307768)
                vm._write(177, cells.value(181) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1120)
            vm.pc = 1124
            pointer = cells.value(177)
            value = memory.load(cells.pointer(181), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1124)
            vm.pc = 1127
            vm.auxiliary = (0, 1022018052)
            tick(1127)
            vm.pc = 1132
            vm._write(182, memory.load(cells.pointer(171), 4, signed=True) * memory.load(cells.pointer(76), 4, signed=True), 8, 'once0.integer')
            tick(1132)
            vm.pc = 1135
            vm.auxiliary = (0, 1723604994)
            tick(1135)
            vm.pc = 1140
            vm._write(183, memory.load(cells.pointer(182), 4, signed=True) + memory.load(cells.pointer(78), 4, signed=True), 8, 'once1.integer')
            tick(1140)
            vm.pc = 1145
            vm._write(169, cells.value(183) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1149
                width = vm.program.size(52386)
                vm._write(92657197, cells.value(668938242) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1145)
            vm.pc = 1148
            vm.auxiliary = (0, 668938242)
            tick(1148)
            vm.pc = 1153
            vm._write(167, memory.load(cells.pointer(166), 8, signed=True) + memory.load(cells.pointer(3), 8, signed=True), 8, 'once1.integer')
            tick(1153)
            vm.pc = 1155
            vm._jump(38)
            continue
        if vm.block == 40:
            tick(1155)
            vm.pc = 1157
            vm._jump(36)
            continue
        if vm.block == 36:
            tick(1157)
            _pointer(vm, 1157, 25, 5, 184, (16, 76))
            tick(1165)
            _pointer(vm, 1165, 16, 184, 185, (36, 36))
            tick(1173)
            vm.pc = 1178
            cells.copy_q_clear_owned(186, 187)
            tick(1178)
            vm.pc = 1182
            pointer = cells.value(185)
            value = memory.load(cells.pointer(187), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(1182)
            _pointer(vm, 1182, 16, 184, 188, (36, 3))
            tick(1190)
            vm.pc = 1195
            cells.copy_q_clear_owned(189, 190)
            tick(1195)
            vm.pc = 1199
            pointer = cells.value(188)
            value = memory.load(cells.pointer(190), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(1199)
            _pointer(vm, 1199, 16, 184, 191, (36, 139))
            tick(1207)
            vm.pc = 1212
            cells.copy_q_clear_owned(192, 193)
            tick(1212)
            vm.pc = 1216
            pointer = cells.value(191)
            value = memory.load(cells.pointer(193), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(1216)
            vm.pc = 1220
            value = memory.load(cells.value(15), 4)
            vm._write(194, value, 4, 'high.load')
            tick(1220)
            _pointer(vm, 1220, 25, 5, 195, (16, 196))
            tick(1228)
            vm.pc = 1232
            pointer = cells.value(195)
            value = memory.load(cells.pointer(194), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(1232)
            vm.pc = 1236
            value = memory.load(cells.value(15), 4)
            vm._write(197, value, 4, 'high.load')
            tick(1236)
            _pointer(vm, 1236, 3, 0, 198, (36, 139))
            tick(1244)
            vm.pc = 1248
            value = memory.load(cells.value(198), 1)
            vm._write(199, value, 4, 'high.load')
            tick(1248)
            vm.pc = 1253
            _convert(vm, 4, 199, 200)
            tick(1253)
            vm.pc = 1258
            vm._write(201, memory.load(cells.pointer(197), 4, signed=True) ^ memory.load(cells.pointer(200), 4, signed=True), 8, 'L14.binary_q')
            tick(1258)
            _pointer(vm, 1258, 25, 5, 202, (16, 203))
            tick(1266)
            vm.pc = 1270
            pointer = cells.value(202)
            value = memory.load(cells.pointer(201), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(1270)
            vm.pc = 1274
            value = memory.load(cells.value(15), 4)
            vm._write(204, value, 4, 'high.load')
            tick(1274)
            _pointer(vm, 1274, 3, 0, 205, (36, 3))
            tick(1282)
            vm.pc = 1286
            value = memory.load(cells.value(205), 1)
            vm._write(206, value, 4, 'high.load')
            tick(1286)
            vm.pc = 1291
            _convert(vm, 4, 206, 207)
            tick(1291)
            vm.pc = 1296
            vm._write(208, memory.load(cells.pointer(204), 4, signed=True) ^ memory.load(cells.pointer(207), 4, signed=True), 8, 'L14.binary_q')
            tick(1296)
            _pointer(vm, 1296, 25, 5, 209, (16, 47))
            tick(1304)
            vm.pc = 1308
            pointer = cells.value(209)
            value = memory.load(cells.pointer(208), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(1308)
            vm.pc = 1312
            value = memory.load(cells.value(15), 4)
            vm._write(210, value, 4, 'high.load')
            tick(1312)
            vm.pc = 1313
            tick(1313)
            vm.pc = 1316
            vm.auxiliary = (0, 20775)
            tick(1316)
            vm.pc = 1321
            vm._write(212, memory.load(cells.pointer(210), 4, signed=True) & memory.load(cells.pointer(211), 4, signed=True), 8, 'typed.selector1.q')
            tick(1321)
            vm.pc = 1326
            vm._write(213, cells.value(212) & 65535, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1330
                width = vm.program.size(252598635)
                vm._write(25, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1326)
            _pointer(vm, 1326, 25, 5, 214, (16, 78))
            tick(1334)
            vm.pc = 1338
            pointer = cells.value(214)
            value = memory.load(cells.pointer(213), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(1338)
            _pointer(vm, 1338, 25, 5, 215, (16, 216))
            tick(1346)
            vm.pc = 1350
            pointer = cells.value(215)
            value = memory.load(cells.pointer(16), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(1350)
            _pointer(vm, 1350, 25, 5, 217, (16, 218))
            tick(1358)
            vm.pc = 1362
            pointer = cells.value(217)
            value = memory.load(cells.pointer(16), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(1362)
            _pointer(vm, 1362, 25, 5, 219, (16, 220))
            tick(1370)
            vm.pc = 1374
            pointer = cells.value(219)
            value = memory.load(cells.pointer(221), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1374)
            _pointer(vm, 1374, 25, 5, 222, (16, 223))
            tick(1382)
            vm.pc = 1386
            pointer = cells.value(222)
            value = memory.load(cells.pointer(224), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1386)
            _pointer(vm, 1386, 25, 5, 225, (16, 226))
            tick(1394)
            vm.pc = 1398
            pointer = cells.value(225)
            value = memory.load(cells.pointer(224), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1398)
            _pointer(vm, 1398, 25, 5, 227, (16, 228))
            tick(1406)
            vm.pc = 1410
            pointer = cells.value(227)
            value = memory.load(cells.pointer(224), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1410)
            _pointer(vm, 1410, 25, 5, 229, (16, 230))
            tick(1418)
            vm.pc = 1422
            pointer = cells.value(229)
            value = memory.load(cells.pointer(224), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1422)
            vm.pc = 1424
            vm._jump(41)
            continue
        if vm.block == 41:
            tick(1424)
            _phi(vm, 1424, (231, 2, 16, 36, 232, 42))
            tick(1431)
            vm.pc = 1432
            tick(1432)
            vm.pc = 1435
            vm.auxiliary = (0, 987932677)
            tick(1435)
            vm.pc = 1440
            a = memory.load(cells.pointer(231), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(230), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(233, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(1440)
            vm.pc = 1444
            vm._jump(42 if cells.value(233) != 0 else 43)
            continue
        if vm.block == 43:
            tick(1444)
            vm.pc = 1451
            _host(vm, 1444, 39, (5, 234), 45, None)
            tick(1451)
            vm.pc = 1453
            vm._jump(3)
            continue
        if vm.block == 42:
            tick(1453)
            vm.pc = 1454
            tick(1454)
            vm.pc = 1457
            vm.auxiliary = (0, 870174721)
            tick(1457)
            vm.pc = 1462
            vm._write(235, memory.load(cells.pointer(231), 4, signed=True) + memory.load(cells.pointer(226), 4, signed=True), 8, 'once1.integer')
            tick(1462)
            vm.pc = 1467
            cells.copy_q_clear_owned(235, 236)
            tick(1467)
            _pointer(vm, 1467, 5, 41, 237, (36, 236))
            tick(1475)
            vm.pc = 1479
            value = memory.load(cells.value(237), 1)
            vm._write(238, value, 4, 'high.load')
            tick(1479)
            _pointer(vm, 1479, 25, 5, 239, (16, 240))
            tick(1487)
            vm.pc = 1492
            cells.copy_q_clear_owned(231, 241)
            tick(1492)
            _pointer(vm, 1492, 17, 239, 242, (36, 241))
            tick(1500)
            vm.pc = 1504
            pointer = cells.value(242)
            value = memory.load(cells.pointer(238), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1504)
            vm.pc = 1507
            vm.auxiliary = (0, 771301378)
            tick(1507)
            vm.pc = 1512
            vm._write(232, memory.load(cells.pointer(231), 4, signed=True) + memory.load(cells.pointer(23), 4, signed=True), 8, 'once1.integer')
            tick(1512)
            vm.pc = 1514
            vm._jump(41)
            continue
        if vm.block == 3:
            tick(1514)
            _phi(vm, 1514, (243, 2, 6, 1, 5, 43))
            tick(1521)
            vm.pc = 1524
            vm.result = memory.load(cells.pointer(243), 8, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('bootstrap left its fixed source blocks')


def _buffer_init(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(6, 2)
            tick(4)
            vm.pc = 7
            vm._allocate(6, 3)
            tick(7)
            vm.pc = 13
            _host(vm, 7, 5, (), 8, 4)
            tick(13)
            vm.pc = 18
            a = cells.value(1)
            b = cells.value(6)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(7, a // b, 8, "L18.unsigned_q_division")
            tick(18)
            vm.pc = 19
            tick(19)
            vm.pc = 22
            vm.auxiliary = (0, 1316864515)
            tick(22)
            vm.pc = 27
            vm._write(8, memory.load(cells.pointer(6), 8, signed=True) * memory.load(cells.pointer(7), 8, signed=True), 8, 'once0.integer')
            tick(27)
            vm.pc = 30
            vm.auxiliary = (0, 1823846915)
            tick(30)
            vm.pc = 35
            vm._write(10, memory.load(cells.pointer(8), 8, signed=True) * memory.load(cells.pointer(9), 8, signed=True), 8, 'once0.integer')
            tick(35)
            vm.pc = 42
            _host(vm, 35, 12, (10,), 10, 11)
            tick(42)
            vm.pc = 47
            cells.copy_q_clear_owned(11, 13)
            tick(47)
            vm.pc = 56
            _host(vm, 47, 15, (11, 16, 10), 12, 14)
            tick(56)
            vm.pc = 61
            vm._write(17, cells.value(7) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 65
                width = vm.program.size(13790)
                vm._write(85257452, cells.value(569778692) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(61)
            vm.pc = 64
            vm.auxiliary = (0, 569778692)
            tick(64)
            vm.pc = 69
            vm._write(19, memory.load(cells.pointer(17), 4, signed=True) * memory.load(cells.pointer(18), 4, signed=True), 8, 'once0.integer')
            tick(69)
            vm.pc = 76
            _host(vm, 69, 20, (13, 19), 14, None)
            tick(76)
            vm.pc = 83
            _host(vm, 76, 12, (1,), 10, 21)
            tick(83)
            vm.pc = 85
            vm._jump(1)
            continue
        if vm.block == 1:
            tick(85)
            _phi(vm, 85, (22, 2, 16, 0, 23, 2))
            tick(92)
            vm.pc = 93
            tick(93)
            vm.pc = 96
            vm.auxiliary = (0, 740455173)
            tick(96)
            vm.pc = 101
            a = memory.load(cells.pointer(22), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(18), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(24, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(101)
            vm.pc = 105
            vm._jump(3 if cells.value(24) != 0 else 4)
            continue
        if vm.block == 4:
            tick(105)
            vm.pc = 107
            vm._jump(5)
            continue
        if vm.block == 3:
            tick(107)
            vm.pc = 109
            vm._jump(6)
            continue
        if vm.block == 6:
            tick(109)
            _phi(vm, 109, (25, 2, 26, 3, 27, 7))
            tick(116)
            _phi(vm, 116, (28, 2, 16, 3, 29, 7))
            tick(123)
            vm.pc = 128
            vm._write(30, int(cells.value(25) < cells.value(1)), 4, 'once18.unsigned_q')
            tick(128)
            vm.pc = 132
            vm._jump(7 if cells.value(30) != 0 else 8)
            continue
        if vm.block == 7:
            tick(132)
            vm.pc = 137
            cells.copy_q_clear_owned(2, 31)
            tick(137)
            vm.pc = 138
            tick(138)
            vm.pc = 141
            vm.auxiliary = (0, 867598852)
            tick(141)
            vm.pc = 146
            vm._write(33, memory.load(cells.pointer(22), 4, signed=True) * memory.load(cells.pointer(32), 4, signed=True), 8, 'once0.integer')
            tick(146)
            vm.pc = 149
            vm.auxiliary = (0, 504659969)
            tick(149)
            vm.pc = 154
            vm._write(34, memory.load(cells.pointer(33), 4, signed=True) + memory.load(cells.pointer(28), 4, signed=True), 8, 'once1.integer')
            tick(154)
            vm.pc = 159
            cells.copy_q_clear_owned(34, 35)
            tick(159)
            _pointer(vm, 159, 6, 13, 36, (35,))
            tick(166)
            vm.pc = 170
            value = memory.load(cells.value(36), 4)
            vm._write(37, value, 4, 'high.load')
            tick(170)
            vm.pc = 174
            pointer = cells.value(2)
            value = memory.load(cells.pointer(37), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(174)
            _pointer(vm, 174, 1, 21, 38, (25,))
            tick(181)
            vm.pc = 184
            vm.auxiliary = (0, 12664)
            tick(184)
            vm.pc = 189
            vm._write(39, memory.load(cells.pointer(1), 8, signed=True) - memory.load(cells.pointer(25), 8, signed=True), 8, 'typed.selector0.q')
            tick(189)
            vm.pc = 194
            vm._write(40, int(cells.value(39) > cells.value(6)), 4, 'L31.comparison')
            tick(194)
            vm.pc = 201
            selected = 6 if cells.value(40) != 0 else 39
            vm._write(41, memory.load(cells.pointer(selected), 8, signed=True), 8, 'L7.selected_q')
            tick(201)
            vm.pc = 210
            _host(vm, 201, 43, (38, 31, 41), 17, 42)
            tick(210)
            vm.pc = 213
            vm.auxiliary = (0, 769265666)
            tick(213)
            vm.pc = 218
            vm._write(27, memory.load(cells.pointer(25), 8, signed=True) + memory.load(cells.pointer(6), 8, signed=True), 8, 'once1.integer')
            tick(218)
            vm.pc = 221
            vm.auxiliary = (0, 556847105)
            tick(221)
            vm.pc = 226
            vm._write(29, memory.load(cells.pointer(28), 4, signed=True) + memory.load(cells.pointer(44), 4, signed=True), 8, 'once1.integer')
            tick(226)
            vm.pc = 228
            vm._jump(6)
            continue
        if vm.block == 8:
            tick(228)
            vm.pc = 230
            vm._jump(9)
            continue
        if vm.block == 9:
            tick(230)
            _phi(vm, 230, (45, 2, 16, 8, 46, 10))
            tick(237)
            vm.pc = 242
            cells.copy_q_clear_owned(45, 47)
            tick(242)
            vm.pc = 247
            vm._write(48, int(cells.value(47) < cells.value(1)), 4, 'once18.unsigned_q')
            tick(247)
            vm.pc = 251
            vm._jump(10 if cells.value(48) != 0 else 2)
            continue
        if vm.block == 2:
            tick(251)
            vm.pc = 252
            tick(252)
            vm.pc = 255
            vm.auxiliary = (0, 364408834)
            tick(255)
            vm.pc = 260
            vm._write(23, memory.load(cells.pointer(22), 4, signed=True) + memory.load(cells.pointer(44), 4, signed=True), 8, 'once1.integer')
            tick(260)
            vm.pc = 262
            vm._jump(1)
            continue
        if vm.block == 10:
            tick(262)
            _pointer(vm, 262, 1, 21, 49, (47,))
            tick(269)
            vm.pc = 273
            value = memory.load(cells.value(49), 1)
            vm._write(50, value, 4, 'high.load')
            tick(273)
            vm.pc = 278
            _convert(vm, 4, 50, 51)
            tick(278)
            _pointer(vm, 278, 1, 0, 52, (47,))
            tick(285)
            vm.pc = 289
            value = memory.load(cells.value(52), 1)
            vm._write(53, value, 4, 'high.load')
            tick(289)
            vm.pc = 294
            _convert(vm, 4, 53, 54)
            tick(294)
            vm.pc = 295
            tick(295)
            vm.pc = 298
            vm.auxiliary = (0, 26628)
            tick(298)
            vm.pc = 304
            vm._write(55, memory.load(cells.pointer(54), 4, signed=True) ^ memory.load(cells.pointer(51), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(304)
            vm.pc = 309
            vm._write(56, cells.value(55) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 313
                width = vm.program.size(218307768)
                vm._write(52, cells.value(56) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(309)
            vm.pc = 313
            pointer = cells.value(52)
            value = memory.load(cells.pointer(56), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(313)
            vm.pc = 316
            vm.auxiliary = (0, 406880258)
            tick(316)
            vm.pc = 321
            vm._write(46, memory.load(cells.pointer(45), 4, signed=True) + memory.load(cells.pointer(44), 4, signed=True), 8, 'once1.integer')
            tick(321)
            vm.pc = 323
            vm._jump(9)
            continue
        if vm.block == 5:
            tick(323)
            _phi(vm, 323, (57, 2, 26, 4, 58, 11))
            tick(330)
            vm.pc = 335
            vm._write(59, int(cells.value(57) < cells.value(1)), 4, 'once18.unsigned_q')
            tick(335)
            vm.pc = 339
            vm._jump(11 if cells.value(59) != 0 else 12)
            continue
        if vm.block == 11:
            tick(339)
            vm.pc = 344
            cells.copy_q_clear_owned(3, 60)
            tick(344)
            vm.pc = 350
            _host(vm, 344, 62, (), 19, 61)
            tick(350)
            vm.pc = 354
            pointer = cells.value(3)
            value = memory.load(cells.pointer(61), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(354)
            _pointer(vm, 354, 1, 21, 63, (57,))
            tick(361)
            vm.pc = 362
            tick(362)
            vm.pc = 365
            vm.auxiliary = (0, 17515)
            tick(365)
            vm.pc = 370
            vm._write(64, memory.load(cells.pointer(1), 8, signed=True) - memory.load(cells.pointer(57), 8, signed=True), 8, 'typed.selector0.q')
            tick(370)
            vm.pc = 375
            vm._write(65, int(cells.value(64) > cells.value(6)), 4, 'L31.comparison')
            tick(375)
            vm.pc = 382
            selected = 6 if cells.value(65) != 0 else 64
            vm._write(66, memory.load(cells.pointer(selected), 8, signed=True), 8, 'L7.selected_q')
            tick(382)
            vm.pc = 391
            _host(vm, 382, 43, (63, 60, 66), 17, 67)
            tick(391)
            vm.pc = 394
            vm.auxiliary = (0, 1825964033)
            tick(394)
            vm.pc = 399
            vm._write(58, memory.load(cells.pointer(57), 8, signed=True) + memory.load(cells.pointer(6), 8, signed=True), 8, 'once1.integer')
            tick(399)
            vm.pc = 401
            vm._jump(5)
            continue
        if vm.block == 12:
            tick(401)
            vm.pc = 403
            vm._jump(13)
            continue
        if vm.block == 13:
            tick(403)
            _phi(vm, 403, (68, 2, 16, 12, 69, 14))
            tick(410)
            vm.pc = 415
            cells.copy_q_clear_owned(68, 70)
            tick(415)
            vm.pc = 420
            vm._write(71, int(cells.value(70) < cells.value(1)), 4, 'once18.unsigned_q')
            tick(420)
            vm.pc = 424
            vm._jump(14 if cells.value(71) != 0 else 15)
            continue
        if vm.block == 15:
            tick(424)
            vm.pc = 430
            _host(vm, 424, 5, (), 8, 72)
            tick(430)
            vm.pc = 438
            _host(vm, 430, 74, (72, 4), 21, 73)
            tick(438)
            vm.pc = 443
            cells.copy_q_clear_owned(21, 75)
            tick(443)
            vm.pc = 447
            pointer = cells.value(75)
            value = memory.load(cells.pointer(73), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(447)
            vm.pc = 449
            vm._jump(16)
            continue
        if vm.block == 14:
            tick(449)
            _pointer(vm, 449, 1, 21, 76, (70,))
            tick(456)
            vm.pc = 460
            value = memory.load(cells.value(76), 1)
            vm._write(77, value, 4, 'high.load')
            tick(460)
            vm.pc = 465
            _convert(vm, 4, 77, 78)
            tick(465)
            _pointer(vm, 465, 1, 0, 79, (70,))
            tick(472)
            vm.pc = 476
            value = memory.load(cells.value(79), 1)
            vm._write(80, value, 4, 'high.load')
            tick(476)
            vm.pc = 481
            _convert(vm, 4, 80, 81)
            tick(481)
            vm.pc = 486
            vm._write(82, memory.load(cells.pointer(81), 4, signed=True) ^ memory.load(cells.pointer(78), 4, signed=True), 8, 'L14.binary_q')
            tick(486)
            vm.pc = 491
            vm._write(83, cells.value(82) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 495
                width = vm.program.size(218307768)
                vm._write(79, cells.value(83) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(491)
            vm.pc = 495
            pointer = cells.value(79)
            value = memory.load(cells.pointer(83), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(495)
            vm.pc = 496
            tick(496)
            vm.pc = 499
            vm.auxiliary = (0, 1564540930)
            tick(499)
            vm.pc = 504
            vm._write(69, memory.load(cells.pointer(68), 4, signed=True) + memory.load(cells.pointer(44), 4, signed=True), 8, 'once1.integer')
            tick(504)
            vm.pc = 506
            vm._jump(13)
            continue
        if vm.block == 16:
            tick(506)
            _phi(vm, 506, (84, 2, 16, 15, 85, 17))
            tick(513)
            vm.pc = 514
            tick(514)
            vm.pc = 517
            vm.auxiliary = (0, 902990389)
            tick(517)
            vm.pc = 522
            a = memory.load(cells.pointer(84), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(32), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(86, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(522)
            vm.pc = 526
            vm._jump(17 if cells.value(86) != 0 else 18)
            continue
        if vm.block == 18:
            tick(526)
            vm.pc = 532
            _host(vm, 526, 87, (21,), 23, None)
            tick(532)
            vm.pc = 538
            _host(vm, 532, 87, (11,), 23, None)
            tick(538)
            vm.pc = 539
            vm.halted = True
            continue
        if vm.block == 17:
            tick(539)
            vm.pc = 544
            cells.copy_q_clear_owned(84, 88)
            tick(544)
            _pointer(vm, 544, 1, 21, 89, (88,))
            tick(551)
            vm.pc = 555
            value = memory.load(cells.value(89), 1)
            vm._write(90, value, 4, 'high.load')
            tick(555)
            vm.pc = 560
            _convert(vm, 4, 90, 91)
            tick(560)
            _pointer(vm, 560, 1, 0, 92, (88,))
            tick(567)
            vm.pc = 571
            value = memory.load(cells.value(92), 1)
            vm._write(93, value, 4, 'high.load')
            tick(571)
            vm.pc = 576
            _convert(vm, 4, 93, 94)
            tick(576)
            vm.pc = 581
            vm._write(95, memory.load(cells.pointer(94), 4, signed=True) ^ memory.load(cells.pointer(91), 4, signed=True), 8, 'L14.binary_q')
            tick(581)
            vm.pc = 586
            vm._write(96, cells.value(95) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 590
                width = vm.program.size(218307768)
                vm._write(92, cells.value(96) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(586)
            vm.pc = 590
            pointer = cells.value(92)
            value = memory.load(cells.pointer(96), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(590)
            vm.pc = 591
            tick(591)
            vm.pc = 594
            vm.auxiliary = (0, 1928716289)
            tick(594)
            vm.pc = 599
            vm._write(85, memory.load(cells.pointer(84), 4, signed=True) + memory.load(cells.pointer(44), 4, signed=True), 8, 'once1.integer')
            tick(599)
            vm.pc = 601
            vm._jump(16)
            continue
        raise PrimarySemanticUnavailable('bootstrap left its fixed source blocks')
