import sys
from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, signed


PROGRAM_SHA256 = {
    'source2582': 'd8646e3fcada3a9a52c8b6ef36d919b9f4c877938b725d4b9b9071d60db1fbd8',
    'setter3592244': 'a86c9397ee9d51220153a1a18bcb8b7f1a41fdc1af508a2df8289f22e57ceb78'}
_WINDOW_FACTORY = object()


def _source_frame(code, **values):
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is code and all(frame.f_locals.get(key) == value if type(value) in (int, str, tuple)
                                        else frame.f_locals.get(key) is value for key, value in values.items()):
            return frame
        frame = frame.f_back
    return None


class _RootWindow:
    def __init__(self, vm, factory):
        if factory is not _WINDOW_FACTORY:
            raise PrimarySemanticUnavailable('UIN source window requires its actual callback factory')
        self.root, self.runtime, self.thread = vm, vm.runtime, get_ident()
        self.root_call = vm.runtime._program_calls[-1]
        self.nonce, self.active, self.child = object(), True, None


def _require_fresh(vm, name):
    if (type(vm) is not PrimaryVM or name not in PROGRAM_SHA256 or sha256(vm.program.raw).hexdigest() != PROGRAM_SHA256[name] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used) != (1, 0, None, True, 0) or
            vm.halted or vm.abort_reason is not None or vm.trace or vm.host_calls or vm.auxiliary is not None or
            any(getattr(vm, key) is not None for key in ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic',
                                                       'pending_native', 'private_iv_native_pending'))):
        raise PrimarySemanticUnavailable('UIN family requires its fixed fresh nonpending source reader')


def _authorize_setter(vm):
    from .primary_sign import PrimaryRuntime
    runtime = vm.runtime
    root = runtime.vms[-2] if runtime is not None and len(runtime.vms) > 1 else None
    window = getattr(root, '_primary_uin_window', None)
    reader = _source_frame(PrimaryRuntime._execute_program.__code__, self=runtime, name='setter3592244', vm=vm)
    root_reader = _source_frame(PrimaryRuntime._execute_program.__code__, self=runtime, name='source2582', vm=root)
    wrapper = _source_frame(PrimaryRuntime.invoke.__code__, self=runtime, rva=0x35A2B8C)
    invoke = _source_frame(PrimaryRuntime.invoke.__code__, self=runtime, rva=0x3592244, vm=root, cells=(14, 16, 21))
    native = _source_frame(_host.__code__, vm=root, word=115)
    calls = runtime._program_calls if runtime is not None else ()
    if (type(window) is not _RootWindow or not window.active or window.root is not root or window.runtime is not runtime or
            window.thread != get_ident() or window.child is not None or type(root) is not PrimaryVM or root.runtime is not runtime or
            vm.memory is not runtime.memory or vm.image_base != runtime.image_base or runtime.vms[-1] is not vm or
            root.memory is not vm.memory or root.halted or sha256(root.program.raw).hexdigest() != PROGRAM_SHA256['source2582'] or
            (root.pc, root.block, root.predecessor, root.initial_block) != (124, 1, 0, False) or
            getattr(root, '_primary_uin_active_call', None) != (window.nonce, 115, 29, (14, 16, 21), 42, 30) or
            not root.host_calls or root.host_calls[-1] != (115, runtime.image_base + 0x3592244, (14, 16, 21), 42) or
            reader is None or root_reader is None or wrapper is None or invoke is None or native is None or
            len(calls) != 2 or calls[0] is not window.root_call or tuple(row['name'] for row in calls) != ('source2582', 'setter3592244') or
            calls[0]['hosts'] is not None or calls[1]['hosts'] != (0x3592178, 0x3592430, 0x3EB2680) or
            runtime._execute_thread != get_ident() or runtime._execute_depth != 2 or runtime._active_main is not None or
            runtime._active_failed or runtime.__dict__.get('_primary_public_direct_owner') is not None or
            runtime.__dict__.get('_primary_direct_scope') is not None or getattr(runtime, '_consumed_mgf', None) is not None):
        raise PrimarySemanticUnavailable('UIN setter requires its actual one-use root115 wrapper fixture and source ABI; production phase is unavailable')
    window.child = vm
    return window


def execute_primary_uin_family(vm, name, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    _require_fresh(vm, name)
    if name == 'source2582':
        raise PrimarySemanticUnavailable('UIN root public production phase and original object lifetime are not bound')
    _authorize_setter(vm)
    state = dict(program=name, backend='DIRECT_UIN_LITERAL_WRAPPER_FIXTURE', completed=False, referenceRecordCount=0,
                 traceComplete=False, publicUinQualified=False, completeIndependentMain=False, final96Qualified=False)
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_uin_family_direct_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    _setter3592244(vm, tick)
    state['completed'] = True
    return vm.result


def _host(vm, word, callee, arguments, signature, destination):
    from .primary_sign import PrimaryRuntime, _invoke_host
    runtime = vm.runtime
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    window = None
    if sha256(vm.program.raw).hexdigest() == PROGRAM_SHA256['source2582'] and word == 115:
        reader = _source_frame(PrimaryRuntime._execute_program.__code__, self=runtime, name='source2582', vm=vm)
        wrapper = _source_frame(PrimaryRuntime.invoke.__code__, self=runtime, rva=0x35A2B8C)
        if (reader is not None and wrapper is not None and len(runtime._program_calls) == 1 and
                runtime._program_calls[0]['name'] == 'source2582' and runtime._program_calls[0]['hosts'] is None and
                runtime._execute_thread == get_ident() and runtime._execute_depth == 1 and runtime._active_main is None and
                runtime.__dict__.get('_primary_direct_scope') is None and runtime.__dict__.get('_primary_public_direct_owner') is None):
            window = _RootWindow(vm, _WINDOW_FACTORY)
            vm._primary_uin_window = window
            vm._primary_uin_active_call = (window.nonce, word, callee, arguments, signature, destination)
    try:
        result = _invoke_host(vm, address, arguments, signature, argument_types=vm.program.type(signature).parameters[3:])
    finally:
        if window is not None:
            window.active = False
            vm._primary_uin_active_call = None
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


def _source2582(vm, tick):
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
            vm.auxiliary = (0, 1295180100)
            tick(8)
            vm.pc = 13
            vm._write(5, int(memory.load(cells.pointer(1), 8, signed=True) != memory.load(cells.pointer(4), 8, signed=True)), 4, 'L30.comparison')
            tick(13)
            vm.pc = 18
            vm._write(7, int(cells.value(2) > cells.value(6)), 4, 'L31.comparison')
            tick(18)
            vm.pc = 21
            vm.auxiliary = (0, 13110)
            tick(21)
            vm.pc = 26
            vm._write(8, memory.load(cells.pointer(5), 1, signed=True) & memory.load(cells.pointer(7), 1, signed=True), 8, 'typed.selector1.q')
            tick(26)
            vm.pc = 31
            vm._write(10, int(cells.value(2) <= cells.value(9)), 4, "once19.unsigned_q")
            tick(31)
            vm.pc = 34
            vm.auxiliary = (0, 50452)
            tick(34)
            vm.pc = 39
            vm._write(11, memory.load(cells.pointer(8), 1, signed=True) & memory.load(cells.pointer(10), 1, signed=True), 8, 'typed.selector1.q')
            tick(39)
            vm.pc = 43
            vm._jump(1 if cells.value(11) != 0 else 2)
            continue
        if vm.block == 1:
            tick(43)
            vm.pc = 49
            _host(vm, 43, 13, (), 10, 12)
            tick(49)
            vm.pc = 54
            cells.copy_q_clear_owned(12, 14)
            tick(54)
            vm.pc = 59
            cells.copy_q_clear_owned(3, 15)
            tick(59)
            _pointer(vm, 59, 7, 3, 16, (17, 17))
            tick(67)
            vm.pc = 76
            _host(vm, 67, 19, (16, 6, 20), 36, 18)
            tick(76)
            vm.pc = 81
            _convert(vm, 8, 2, 21)
            tick(81)
            vm.pc = 90
            _host(vm, 81, 23, (16, 1, 21), 38, 22)
            tick(90)
            _pointer(vm, 90, 34, 14, 24, (6, 25))
            tick(98)
            _pointer(vm, 98, 26, 24, 26, (17, 27))
            tick(106)
            vm.pc = 110
            value = memory.load(cells.value(26), 8)
            vm._write(28, value, 8, 'high.load')
            tick(110)
            vm.pc = 115
            cells.copy_q_clear_owned(28, 29)
            tick(115)
            vm.pc = 124
            _host(vm, 115, 29, (14, 16, 21), 42, 30)
            tick(124)
            vm.pc = 126
            vm._jump(2)
            continue
        if vm.block == 2:
            tick(126)
            vm.pc = 129
            vm.result = memory.load(cells.pointer(31), 1, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('UIN left its fixed source blocks')


def _setter3592244(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(29, 3)
            tick(4)
            vm.pc = 7
            vm._allocate(3, 4)
            tick(7)
            vm.pc = 8
            tick(8)
            vm.pc = 11
            vm.auxiliary = (0, 1756510755)
            tick(11)
            extra = _single(vm)
            vm.pc = 16
            left_pointer = cells.pointer(0)
            right_pointer = cells.pointer(5)
            destination_pointer = cells.pointer(6)
            a = memory.load(left_pointer, 8, signed=True)
            b = memory.load(right_pointer, 8, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 20
                left_pointer = cells.pointer(0)
                right_pointer = cells.pointer(1547861459)
                destination_pointer = cells.pointer(27023)
                width = vm.program.size(13790)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(13790)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 20
                left_pointer = cells.pointer(0)
                right_pointer = cells.pointer(1547861459)
                destination_pointer = cells.pointer(27023)
                width = vm.program.size(13790)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(13790)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(16)
            vm.pc = 19
            vm.auxiliary = (0, 1547861459)
            tick(19)
            extra = _single(vm)
            vm.pc = 24
            left_pointer = cells.pointer(1)
            right_pointer = cells.pointer(7)
            destination_pointer = cells.pointer(8)
            a = memory.load(left_pointer, 8, signed=True)
            b = memory.load(right_pointer, 8, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 28
                left_pointer = cells.pointer(32)
                right_pointer = cells.pointer(6)
                destination_pointer = cells.pointer(8)
                width = vm.program.size(17497)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(17497)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 28
                left_pointer = cells.pointer(32)
                right_pointer = cells.pointer(6)
                destination_pointer = cells.pointer(8)
                width = vm.program.size(17497)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(17497)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(24)
            vm.pc = 29
            vm._write(9, memory.load(cells.pointer(6), 1, signed=True) | memory.load(cells.pointer(8), 1, signed=True), 8, 'L15.binary_q')
            tick(29)
            vm.pc = 34
            vm._write(11, int(cells.value(2) <= cells.value(10)), 4, "once19.unsigned_q")
            tick(34)
            vm.pc = 39
            vm._write(12, memory.load(cells.pointer(9), 1, signed=True) | memory.load(cells.pointer(11), 1, signed=True), 8, 'L15.binary_q')
            tick(39)
            vm.pc = 44
            vm._write(14, int(cells.value(2) > cells.value(13)), 4, 'L31.comparison')
            tick(44)
            vm.pc = 47
            vm.auxiliary = (0, 29601)
            tick(47)
            vm.pc = 52
            vm._write(15, memory.load(cells.pointer(12), 1, signed=True) | memory.load(cells.pointer(14), 1, signed=True), 8, 'typed.selector2.q')
            tick(52)
            vm.pc = 56
            vm._jump(1 if cells.value(15) != 0 else 2)
            continue
        if vm.block == 1:
            tick(56)
            vm.pc = 58
            vm._jump(3)
            continue
        if vm.block == 2:
            tick(58)
            vm.pc = 65
            _host(vm, 58, 16, (0, 17), 34, None)
            tick(65)
            vm.pc = 71
            _host(vm, 65, 19, (), 36, 18)
            tick(71)
            vm.pc = 72
            tick(72)
            vm.pc = 75
            vm.auxiliary = (0, 49708)
            tick(75)
            vm.pc = 80
            vm._write(21, memory.load(cells.pointer(18), 8, signed=True) & memory.load(cells.pointer(20), 8, signed=True), 8, 'typed.selector1.q')
            tick(80)
            vm.pc = 85
            vm._write(22, cells.value(21) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 89
                width = vm.program.size(360601030)
                vm._write(22, cells.value(0) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(85)
            vm.pc = 90
            _convert(vm, 8, 22, 23)
            tick(90)
            vm.pc = 95
            vm._write(25, int(cells.value(2) > cells.value(24)), 4, 'L31.comparison')
            tick(95)
            vm.pc = 102
            selected = 24 if cells.value(25) != 0 else 2
            vm._write(26, memory.load(cells.pointer(selected), 8, signed=True), 8, 'L7.selected_q')
            tick(102)
            vm.pc = 107
            a = cells.value(23)
            b = cells.value(26)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(27, a % b, 8, "L17.unsigned_q_division")
            tick(107)
            vm.pc = 112
            vm._write(28, cells.value(27) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 116
                width = vm.program.size(893)
                vm._write(100956627, cells.value(29932) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(112)
            vm.pc = 115
            vm.auxiliary = (0, 29932)
            tick(115)
            extra = _single(vm)
            vm.pc = 120
            count = memory.load(cells.pointer(29), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(28), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(30, value, 4, 'typed.selector3.d')
            if extra:
                vm.pc = 121
                vm.program.size(3327)
            tick(120)
            vm.pc = 125
            vm._write(32, memory.load(cells.pointer(30), 4, signed=True) & memory.load(cells.pointer(31), 4, signed=True), 8, 'L13.binary_q')
            tick(125)
            vm.pc = 130
            _convert(vm, 8, 28, 33)
            tick(130)
            _pointer(vm, 130, 2, 1, 34, (33,))
            tick(137)
            vm.pc = 141
            value = memory.load(cells.value(34), 1)
            vm._write(35, value, 4, 'high.load')
            tick(141)
            vm.pc = 146
            _convert(vm, 4, 35, 36)
            tick(146)
            vm.pc = 149
            vm.auxiliary = (0, 63097)
            tick(149)
            vm.pc = 154
            vm._write(38, memory.load(cells.pointer(36), 4, signed=True) - memory.load(cells.pointer(37), 4, signed=True), 8, 'typed.selector0.q')
            tick(154)
            vm.pc = 157
            vm.auxiliary = (0, 8790)
            tick(157)
            vm.pc = 162
            vm._write(40, memory.load(cells.pointer(38), 4, signed=True) & memory.load(cells.pointer(39), 4, signed=True), 8, 'typed.selector1.q')
            tick(162)
            vm.pc = 165
            vm.auxiliary = (0, 38848)
            tick(165)
            vm.pc = 170
            vm._write(41, memory.load(cells.pointer(32), 4, signed=True) | memory.load(cells.pointer(40), 4, signed=True), 8, 'typed.selector2.q')
            tick(170)
            vm.pc = 175
            vm._write(42, cells.value(41) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 179
                width = vm.program.size(360601030)
                vm._write(42, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(175)
            vm.pc = 180
            _convert(vm, 4, 42, 43)
            tick(180)
            vm.pc = 183
            vm.auxiliary = (0, 34902)
            tick(183)
            vm.pc = 189
            vm._write(45, memory.load(cells.pointer(43), 4, signed=True) ^ memory.load(cells.pointer(44), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(189)
            vm.pc = 194
            vm._write(46, cells.value(45) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 198
                width = vm.program.size(252598635)
                vm._write(25, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(194)
            _pointer(vm, 194, 25, 0, 47, (48, 49))
            tick(202)
            _pointer(vm, 202, 4, 47, 50, (10, 10))
            tick(210)
            vm.pc = 214
            pointer = cells.value(50)
            value = memory.load(cells.pointer(46), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(214)
            vm.pc = 218
            vm._jump(4 if cells.value(17) != 0 else 5)
            continue
        if vm.block == 4:
            tick(218)
            _pointer(vm, 218, 25, 0, 51, (48, 52))
            tick(226)
            _pointer(vm, 226, 5, 51, 53, (10, 10))
            tick(234)
            vm.pc = 238
            vm._jump(6 if cells.value(17) != 0 else 5)
            continue
        if vm.block == 6:
            tick(238)
            _pointer(vm, 238, 5, 51, 54, (10, 55))
            tick(246)
            vm.pc = 250
            value = memory.load(cells.value(54), 1)
            vm._write(56, value, 4, 'high.load')
            tick(250)
            vm.pc = 252
            vm._jump(7)
            continue
        if vm.block == 7:
            tick(252)
            _phi(vm, 252, (57, 2, 56, 6, 58, 8))
            tick(259)
            _phi(vm, 259, (59, 2, 10, 6, 60, 8))
            tick(266)
            vm.pc = 271
            vm._write(62, int(cells.value(59) < cells.value(61)), 4, 'once18.unsigned_q')
            tick(271)
            vm.pc = 275
            vm._jump(8 if cells.value(62) != 0 else 9)
            continue
        if vm.block == 8:
            tick(275)
            vm.pc = 280
            _convert(vm, 4, 57, 63)
            tick(280)
            vm.pc = 281
            tick(281)
            vm.pc = 284
            vm.auxiliary = (0, 354456068)
            tick(284)
            vm.pc = 289
            vm._write(65, memory.load(cells.pointer(59), 8, signed=True) * memory.load(cells.pointer(64), 8, signed=True), 8, 'once0.integer')
            tick(289)
            vm.pc = 292
            vm.auxiliary = (0, 262553602)
            tick(292)
            vm.pc = 297
            vm._write(66, memory.load(cells.pointer(65), 8, signed=True) + memory.load(cells.pointer(55), 8, signed=True), 8, 'once1.integer')
            tick(297)
            vm.pc = 302
            vm._write(67, cells.value(66) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 306
                width = vm.program.size(360601030)
                vm._write(67, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(302)
            vm.pc = 307
            _convert(vm, 4, 67, 68)
            tick(307)
            vm.pc = 312
            vm._write(69, memory.load(cells.pointer(63), 4, signed=True) ^ memory.load(cells.pointer(68), 4, signed=True), 8, 'L14.binary_q')
            tick(312)
            _pointer(vm, 312, 4, 47, 70, (10, 59))
            tick(320)
            vm.pc = 324
            value = memory.load(cells.value(70), 1)
            vm._write(71, value, 4, 'high.load')
            tick(324)
            vm.pc = 329
            _convert(vm, 4, 71, 72)
            tick(329)
            vm.pc = 332
            vm.auxiliary = (0, 56663)
            tick(332)
            vm.pc = 338
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(73, memory.load(cells.pointer(72), 4, signed=True) ^ memory.load(cells.pointer(69), 4, signed=True), 8, 'typed.selector5.q')
            tick(338)
            vm.pc = 343
            vm._write(74, cells.value(73) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 347
                width = vm.program.size(218307768)
                vm._write(70, cells.value(74) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(343)
            vm.pc = 347
            pointer = cells.value(70)
            value = memory.load(cells.pointer(74), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(347)
            vm.pc = 350
            vm.auxiliary = (0, 1362010628)
            tick(350)
            vm.pc = 355
            vm._write(76, memory.load(cells.pointer(63), 4, signed=True) * memory.load(cells.pointer(75), 4, signed=True), 8, 'once0.integer')
            tick(355)
            vm.pc = 358
            vm.auxiliary = (0, 2025484289)
            tick(358)
            vm.pc = 363
            vm._write(78, memory.load(cells.pointer(76), 4, signed=True) + memory.load(cells.pointer(77), 4, signed=True), 8, 'once1.integer')
            tick(363)
            vm.pc = 368
            vm._write(58, cells.value(78) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 372
                width = vm.program.size(1699)
                vm._write(92657197, cells.value(1965035522) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(368)
            vm.pc = 371
            vm.auxiliary = (0, 1965035522)
            tick(371)
            vm.pc = 376
            vm._write(60, memory.load(cells.pointer(59), 8, signed=True) + memory.load(cells.pointer(61), 8, signed=True), 8, 'once1.integer')
            tick(376)
            vm.pc = 378
            vm._jump(7)
            continue
        if vm.block == 9:
            tick(378)
            vm.pc = 380
            vm._jump(5)
            continue
        if vm.block == 5:
            tick(380)
            vm.pc = 385
            cells.copy_q_clear_owned(3, 79)
            tick(385)
            vm.pc = 394
            _host(vm, 385, 81, (79, 48, 82), 40, 80)
            tick(394)
            _pointer(vm, 394, 29, 3, 83, (10, 10))
            tick(402)
            vm.pc = 406
            vm._jump(10 if cells.value(17) != 0 else 11)
            continue
        if vm.block == 10:
            tick(406)
            vm.pc = 408
            vm._jump(12)
            continue
        if vm.block == 12:
            tick(408)
            _phi(vm, 408, (84, 2, 83, 10, 85, 13))
            tick(415)
            _phi(vm, 415, (86, 2, 82, 10, 87, 13))
            tick(422)
            vm.pc = 423
            tick(423)
            vm.pc = 426
            vm.auxiliary = (0, 1576243201)
            tick(426)
            vm.pc = 431
            vm._write(87, memory.load(cells.pointer(86), 8, signed=True) + memory.load(cells.pointer(88), 8, signed=True), 8, 'once1.integer')
            tick(431)
            vm.pc = 436
            vm._write(89, int(cells.value(86) > cells.value(10)), 4, 'L31.comparison')
            tick(436)
            vm.pc = 440
            vm._jump(13 if cells.value(89) != 0 else 14)
            continue
        if vm.block == 13:
            tick(440)
            _pointer(vm, 440, 2, 84, 85, (90,))
            tick(447)
            vm.pc = 451
            pointer = cells.value(84)
            value = memory.load(cells.pointer(91), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(451)
            vm.pc = 453
            vm._jump(12)
            continue
        if vm.block == 14:
            tick(453)
            vm.pc = 455
            vm._jump(11)
            continue
        if vm.block == 11:
            tick(455)
            vm.pc = 457
            vm._jump(15)
            continue
        if vm.block == 15:
            tick(457)
            _phi(vm, 457, (92, 2, 48, 11, 93, 16))
            tick(464)
            _phi(vm, 464, (94, 2, 95, 11, 96, 16))
            tick(471)
            vm.pc = 472
            tick(472)
            vm.pc = 475
            vm.auxiliary = (0, 283300085)
            tick(475)
            vm.pc = 480
            a = memory.load(cells.pointer(92), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(97), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(98, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(480)
            vm.pc = 484
            vm._jump(17 if cells.value(98) != 0 else 18)
            continue
        if vm.block == 18:
            tick(484)
            vm.pc = 486
            vm._jump(19)
            continue
        if vm.block == 17:
            tick(486)
            _pointer(vm, 486, 25, 0, 99, (48, 100))
            tick(494)
            vm.pc = 499
            cells.copy_q_clear_owned(92, 101)
            tick(499)
            _pointer(vm, 499, 11, 99, 102, (10, 101))
            tick(507)
            _pointer(vm, 507, 10, 102, 103, (48, 104))
            tick(515)
            vm.pc = 519
            value = memory.load(cells.value(103), 1)
            vm._write(105, value, 4, 'high.load')
            tick(519)
            vm.pc = 520
            tick(520)
            vm.pc = 523
            vm.auxiliary = (0, 537017812)
            tick(523)
            vm.pc = 528
            vm._write(106, int(memory.load(cells.pointer(105), 1, signed=True) != memory.load(cells.pointer(91), 1, signed=True)), 4, 'L30.comparison')
            tick(528)
            vm.pc = 532
            vm._jump(20 if cells.value(106) != 0 else 16)
            continue
        if vm.block == 20:
            tick(532)
            _pointer(vm, 532, 10, 102, 107, (48, 48))
            tick(540)
            _pointer(vm, 540, 9, 107, 108, (10, 10))
            tick(548)
            vm.pc = 552
            vm._jump(21 if cells.value(17) != 0 else 22)
            continue
        if vm.block == 21:
            tick(552)
            vm.pc = 554
            vm._jump(23)
            continue
        if vm.block == 23:
            tick(554)
            _phi(vm, 554, (109, 2, 108, 21, 110, 24))
            tick(561)
            _phi(vm, 561, (111, 2, 83, 21, 112, 24))
            tick(568)
            _phi(vm, 568, (113, 2, 114, 21, 115, 24))
            tick(575)
            vm.pc = 576
            tick(576)
            vm.pc = 579
            vm.auxiliary = (0, 906387458)
            tick(579)
            vm.pc = 584
            vm._write(115, memory.load(cells.pointer(113), 8, signed=True) + memory.load(cells.pointer(88), 8, signed=True), 8, 'once1.integer')
            tick(584)
            vm.pc = 589
            vm._write(116, int(cells.value(113) > cells.value(10)), 4, 'L31.comparison')
            tick(589)
            vm.pc = 593
            vm._jump(24 if cells.value(116) != 0 else 25)
            continue
        if vm.block == 24:
            tick(593)
            _pointer(vm, 593, 2, 109, 110, (90,))
            tick(600)
            vm.pc = 604
            value = memory.load(cells.value(109), 1)
            vm._write(117, value, 4, 'high.load')
            tick(604)
            _pointer(vm, 604, 2, 111, 112, (90,))
            tick(611)
            vm.pc = 615
            pointer = cells.value(111)
            value = memory.load(cells.pointer(117), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(615)
            vm.pc = 617
            vm._jump(23)
            continue
        if vm.block == 25:
            tick(617)
            vm.pc = 619
            vm._jump(22)
            continue
        if vm.block == 22:
            tick(619)
            _pointer(vm, 619, 10, 102, 118, (48, 90))
            tick(627)
            vm.pc = 631
            value = memory.load(cells.value(118), 1)
            vm._write(119, value, 4, 'high.load')
            tick(631)
            _pointer(vm, 631, 25, 0, 120, (48, 52))
            tick(639)
            _pointer(vm, 639, 5, 120, 121, (10, 10))
            tick(647)
            vm.pc = 651
            vm._jump(26 if cells.value(17) != 0 else 27)
            continue
        if vm.block == 26:
            tick(651)
            vm.pc = 656
            _convert(vm, 8, 119, 122)
            tick(656)
            _pointer(vm, 656, 5, 120, 123, (10, 122))
            tick(664)
            vm.pc = 668
            value = memory.load(cells.value(123), 1)
            vm._write(124, value, 4, 'high.load')
            tick(668)
            vm.pc = 670
            vm._jump(28)
            continue
        if vm.block == 28:
            tick(670)
            _phi(vm, 670, (125, 2, 124, 26, 126, 29))
            tick(677)
            _phi(vm, 677, (127, 2, 10, 26, 128, 29))
            tick(684)
            vm.pc = 689
            vm._write(129, int(cells.value(127) < cells.value(114)), 4, 'once18.unsigned_q')
            tick(689)
            vm.pc = 693
            vm._jump(29 if cells.value(129) != 0 else 30)
            continue
        if vm.block == 29:
            tick(693)
            vm.pc = 698
            _convert(vm, 4, 125, 130)
            tick(698)
            vm.pc = 699
            tick(699)
            vm.pc = 702
            vm.auxiliary = (0, 313262595)
            tick(702)
            vm.pc = 707
            vm._write(131, memory.load(cells.pointer(127), 8, signed=True) * memory.load(cells.pointer(64), 8, signed=True), 8, 'once0.integer')
            tick(707)
            vm.pc = 710
            vm.auxiliary = (0, 1122562050)
            tick(710)
            vm.pc = 715
            vm._write(132, memory.load(cells.pointer(131), 8, signed=True) + memory.load(cells.pointer(122), 8, signed=True), 8, 'once1.integer')
            tick(715)
            vm.pc = 720
            vm._write(133, cells.value(132) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 724
                width = vm.program.size(360601030)
                vm._write(133, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(720)
            vm.pc = 725
            _convert(vm, 4, 133, 134)
            tick(725)
            vm.pc = 730
            vm._write(135, memory.load(cells.pointer(130), 4, signed=True) ^ memory.load(cells.pointer(134), 4, signed=True), 8, 'L14.binary_q')
            tick(730)
            _pointer(vm, 730, 29, 3, 136, (10, 127))
            tick(738)
            vm.pc = 742
            value = memory.load(cells.value(136), 1)
            vm._write(137, value, 4, 'high.load')
            tick(742)
            vm.pc = 747
            _convert(vm, 4, 137, 138)
            tick(747)
            vm.pc = 752
            vm._write(139, memory.load(cells.pointer(138), 4, signed=True) ^ memory.load(cells.pointer(135), 4, signed=True), 8, 'L14.binary_q')
            tick(752)
            vm.pc = 757
            vm._write(140, cells.value(139) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 761
                width = vm.program.size(218307768)
                vm._write(136, cells.value(140) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(757)
            vm.pc = 761
            pointer = cells.value(136)
            value = memory.load(cells.pointer(140), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(761)
            vm.pc = 764
            vm.auxiliary = (0, 411861507)
            tick(764)
            vm.pc = 769
            vm._write(141, memory.load(cells.pointer(130), 4, signed=True) * memory.load(cells.pointer(75), 4, signed=True), 8, 'once0.integer')
            tick(769)
            vm.pc = 772
            vm.auxiliary = (0, 510279681)
            tick(772)
            vm.pc = 777
            vm._write(142, memory.load(cells.pointer(141), 4, signed=True) + memory.load(cells.pointer(77), 4, signed=True), 8, 'once1.integer')
            tick(777)
            vm.pc = 782
            vm._write(126, cells.value(142) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 786
                width = vm.program.size(15650)
                vm._write(92657197, cells.value(254193665) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(782)
            vm.pc = 785
            vm.auxiliary = (0, 254193665)
            tick(785)
            vm.pc = 790
            vm._write(128, memory.load(cells.pointer(127), 8, signed=True) + memory.load(cells.pointer(61), 8, signed=True), 8, 'once1.integer')
            tick(790)
            vm.pc = 792
            vm._jump(28)
            continue
        if vm.block == 30:
            tick(792)
            vm.pc = 794
            vm._jump(27)
            continue
        if vm.block == 27:
            tick(794)
            vm.pc = 795
            tick(795)
            vm.pc = 798
            vm.auxiliary = (0, 903019492)
            tick(798)
            vm.pc = 803
            vm._write(143, int(memory.load(cells.pointer(83), 8, signed=True) != memory.load(cells.pointer(1), 8, signed=True)), 4, 'L27.comparison')
            tick(803)
            vm.pc = 808
            vm._write(144, int(cells.value(2) > cells.value(10)), 4, 'L31.comparison')
            tick(808)
            vm.pc = 813
            vm._write(145, memory.load(cells.pointer(143), 1, signed=True) & memory.load(cells.pointer(144), 1, signed=True), 8, 'L13.binary_q')
            tick(813)
            vm.pc = 817
            vm._jump(31 if cells.value(145) != 0 else 32)
            continue
        if vm.block == 31:
            tick(817)
            vm.pc = 819
            vm._jump(33)
            continue
        if vm.block == 33:
            tick(819)
            _phi(vm, 819, (146, 2, 83, 31, 147, 34))
            tick(826)
            _phi(vm, 826, (148, 2, 1, 31, 149, 34))
            tick(833)
            _phi(vm, 833, (150, 2, 2, 31, 151, 34))
            tick(840)
            vm.pc = 841
            tick(841)
            vm.pc = 844
            vm.auxiliary = (0, 713850882)
            tick(844)
            vm.pc = 849
            vm._write(151, memory.load(cells.pointer(150), 8, signed=True) + memory.load(cells.pointer(88), 8, signed=True), 8, 'once1.integer')
            tick(849)
            vm.pc = 854
            vm._write(152, int(cells.value(150) > cells.value(10)), 4, 'L31.comparison')
            tick(854)
            vm.pc = 858
            vm._jump(35 if cells.value(152) != 0 else 36)
            continue
        if vm.block == 35:
            tick(858)
            vm.pc = 862
            value = memory.load(cells.value(146), 1)
            vm._write(153, value, 4, 'high.load')
            tick(862)
            vm.pc = 867
            _convert(vm, 4, 153, 154)
            tick(867)
            vm.pc = 871
            value = memory.load(cells.value(148), 1)
            vm._write(155, value, 4, 'high.load')
            tick(871)
            vm.pc = 876
            _convert(vm, 4, 155, 156)
            tick(876)
            vm.pc = 877
            tick(877)
            vm.pc = 880
            vm.auxiliary = (0, 544388836)
            tick(880)
            vm.pc = 885
            vm._write(157, int(memory.load(cells.pointer(154), 4, signed=True) != memory.load(cells.pointer(156), 4, signed=True)), 4, 'L30.comparison')
            tick(885)
            vm.pc = 889
            vm._jump(37 if cells.value(157) != 0 else 34)
            continue
        if vm.block == 37:
            tick(889)
            vm.pc = 890
            tick(890)
            vm.pc = 893
            vm.auxiliary = (0, 25947)
            tick(893)
            vm.pc = 898
            vm._write(158, memory.load(cells.pointer(154), 4, signed=True) - memory.load(cells.pointer(156), 4, signed=True), 8, 'typed.selector0.q')
            tick(898)
            vm.pc = 900
            vm._jump(36)
            continue
        if vm.block == 34:
            tick(900)
            _pointer(vm, 900, 2, 146, 147, (90,))
            tick(907)
            _pointer(vm, 907, 2, 148, 149, (90,))
            tick(914)
            vm.pc = 916
            vm._jump(33)
            continue
        if vm.block == 36:
            tick(916)
            _phi(vm, 916, (159, 2, 158, 37, 48, 33))
            tick(923)
            vm.pc = 925
            vm._jump(32)
            continue
        if vm.block == 32:
            tick(925)
            _phi(vm, 925, (160, 2, 159, 36, 48, 27))
            tick(932)
            vm.pc = 936
            vm._jump(38 if cells.value(161) != 0 else 39)
            continue
        if vm.block == 38:
            tick(936)
            vm.pc = 938
            vm._jump(40)
            continue
        if vm.block == 39:
            tick(938)
            vm.pc = 940
            vm._jump(41)
            continue
        if vm.block == 41:
            tick(940)
            _phi(vm, 940, (162, 2, 10, 39, 163, 42))
            tick(947)
            _pointer(vm, 947, 2, 83, 164, (162,))
            tick(954)
            vm.pc = 958
            value = memory.load(cells.value(164), 1)
            vm._write(165, value, 4, 'high.load')
            tick(958)
            vm.pc = 963
            cells.copy_q_clear_owned(165, 166)
            tick(963)
            vm.pc = 964
            tick(964)
            vm.pc = 967
            vm.auxiliary = (0, 892520164)
            tick(967)
            vm.pc = 972
            vm._write(167, int(memory.load(cells.pointer(166), 4, signed=True) != memory.load(cells.pointer(48), 4, signed=True)), 4, 'L27.comparison')
            tick(972)
            vm.pc = 976
            vm._jump(42 if cells.value(167) != 0 else 43)
            continue
        if vm.block == 42:
            tick(976)
            vm.pc = 977
            tick(977)
            vm.pc = 980
            vm.auxiliary = (0, 217645057)
            tick(980)
            vm.pc = 985
            vm._write(163, memory.load(cells.pointer(162), 8, signed=True) + memory.load(cells.pointer(61), 8, signed=True), 8, 'once1.integer')
            tick(985)
            vm.pc = 987
            vm._jump(41)
            continue
        if vm.block == 43:
            tick(987)
            vm.pc = 992
            vm._write(168, cells.value(162) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 996
                width = vm.program.size(33004)
                vm._write(169, cells.value(10254) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(992)
            vm.pc = 994
            vm._jump(40)
            continue
        if vm.block == 40:
            tick(994)
            _phi(vm, 994, (169, 2, 48, 38, 168, 43))
            tick(1001)
            vm.pc = 1002
            tick(1002)
            vm.pc = 1005
            vm.auxiliary = (0, 850547747)
            tick(1005)
            vm.pc = 1010
            vm._write(170, int(memory.load(cells.pointer(160), 4, signed=True) == memory.load(cells.pointer(48), 4, signed=True)), 4, 'once17.integer')
            tick(1010)
            vm.pc = 1014
            vm._jump(44 if cells.value(170) != 0 else 45)
            continue
        if vm.block == 44:
            tick(1014)
            vm.pc = 1019
            cells.copy_q_clear_owned(169, 171)
            tick(1019)
            vm.pc = 1020
            tick(1020)
            vm.pc = 1023
            vm.auxiliary = (0, 683823219)
            tick(1023)
            vm.pc = 1028
            vm._write(172, int(memory.load(cells.pointer(171), 8, signed=True) == memory.load(cells.pointer(2), 8, signed=True)), 4, 'once17.integer')
            tick(1028)
            vm.pc = 1032
            vm._jump(46 if cells.value(172) != 0 else 45)
            continue
        if vm.block == 46:
            tick(1032)
            vm.pc = 1039
            _host(vm, 1032, 16, (0, 161), 34, None)
            tick(1039)
            vm.pc = 1041
            vm._jump(47)
            continue
        if vm.block == 45:
            tick(1041)
            vm.pc = 1043
            vm._jump(47)
            continue
        if vm.block == 47:
            tick(1043)
            _phi(vm, 1043, (173, 2, 90, 46, 48, 45))
            tick(1050)
            _phi(vm, 1050, (174, 2, 90, 46, 94, 45))
            tick(1057)
            vm.pc = 1058
            tick(1058)
            vm.pc = 1061
            vm.auxiliary = (0, 1796404467)
            tick(1061)
            vm.pc = 1066
            vm._write(175, int(memory.load(cells.pointer(173), 4, signed=True) == memory.load(cells.pointer(48), 4, signed=True)), 4, 'once17.integer')
            tick(1066)
            vm.pc = 1070
            vm._jump(16 if cells.value(175) != 0 else 19)
            continue
        if vm.block == 16:
            tick(1070)
            _phi(vm, 1070, (96, 2, 174, 47, 94, 17))
            tick(1077)
            vm.pc = 1078
            tick(1078)
            vm.pc = 1081
            vm.auxiliary = (0, 1576099842)
            tick(1081)
            vm.pc = 1086
            vm._write(93, memory.load(cells.pointer(92), 4, signed=True) + memory.load(cells.pointer(90), 4, signed=True), 8, 'once1.integer')
            tick(1086)
            vm.pc = 1088
            vm._jump(15)
            continue
        if vm.block == 19:
            tick(1088)
            _phi(vm, 1088, (176, 2, 173, 47, 177, 18))
            tick(1095)
            _phi(vm, 1095, (178, 2, 174, 47, 94, 18))
            tick(1102)
            vm.pc = 1103
            tick(1103)
            vm.pc = 1106
            vm.auxiliary = (0, 1179830307)
            tick(1106)
            vm.pc = 1111
            vm._write(179, int(memory.load(cells.pointer(176), 4, signed=True) == memory.load(cells.pointer(177), 4, signed=True)), 4, 'once17.integer')
            tick(1111)
            vm.pc = 1115
            vm._jump(48 if cells.value(179) != 0 else 49)
            continue
        if vm.block == 48:
            tick(1115)
            vm.pc = 1120
            cells.copy_q_clear_owned(4, 180)
            tick(1120)
            _pointer(vm, 1120, 3, 4, 181, (10, 10))
            tick(1128)
            _pointer(vm, 1128, 25, 0, 182, (48, 104))
            tick(1136)
            _pointer(vm, 1136, 3, 182, 183, (10, 10))
            tick(1144)
            vm.pc = 1148
            vm._jump(50 if cells.value(17) != 0 else 51)
            continue
        if vm.block == 50:
            tick(1148)
            vm.pc = 1150
            vm._jump(52)
            continue
        if vm.block == 52:
            tick(1150)
            _phi(vm, 1150, (184, 2, 185, 50, 186, 53))
            tick(1157)
            _phi(vm, 1157, (187, 2, 181, 50, 188, 53))
            tick(1164)
            _phi(vm, 1164, (189, 2, 183, 50, 190, 53))
            tick(1171)
            vm.pc = 1172
            tick(1172)
            vm.pc = 1175
            vm.auxiliary = (0, 1718480898)
            tick(1175)
            vm.pc = 1180
            vm._write(186, memory.load(cells.pointer(184), 8, signed=True) + memory.load(cells.pointer(88), 8, signed=True), 8, 'once1.integer')
            tick(1180)
            vm.pc = 1185
            vm._write(191, int(cells.value(184) > cells.value(10)), 4, 'L31.comparison')
            tick(1185)
            vm.pc = 1189
            vm._jump(53 if cells.value(191) != 0 else 54)
            continue
        if vm.block == 53:
            tick(1189)
            _pointer(vm, 1189, 2, 189, 190, (90,))
            tick(1196)
            vm.pc = 1200
            value = memory.load(cells.value(189), 1)
            vm._write(192, value, 4, 'high.load')
            tick(1200)
            _pointer(vm, 1200, 2, 187, 188, (90,))
            tick(1207)
            vm.pc = 1211
            pointer = cells.value(187)
            value = memory.load(cells.pointer(192), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1211)
            vm.pc = 1213
            vm._jump(52)
            continue
        if vm.block == 54:
            tick(1213)
            vm.pc = 1215
            vm._jump(51)
            continue
        if vm.block == 51:
            tick(1215)
            _pointer(vm, 1215, 25, 0, 193, (48, 52))
            tick(1223)
            _pointer(vm, 1223, 5, 193, 194, (10, 10))
            tick(1231)
            vm.pc = 1235
            vm._jump(55 if cells.value(17) != 0 else 56)
            continue
        if vm.block == 55:
            tick(1235)
            vm.pc = 1239
            value = memory.load(cells.value(194), 1)
            vm._write(195, value, 4, 'high.load')
            tick(1239)
            vm.pc = 1241
            vm._jump(57)
            continue
        if vm.block == 57:
            tick(1241)
            _phi(vm, 1241, (196, 2, 10, 55, 197, 58))
            tick(1248)
            _phi(vm, 1248, (198, 2, 195, 55, 199, 58))
            tick(1255)
            vm.pc = 1260
            vm._write(200, int(cells.value(196) < cells.value(185)), 4, 'once18.unsigned_q')
            tick(1260)
            vm.pc = 1264
            vm._jump(58 if cells.value(200) != 0 else 59)
            continue
        if vm.block == 58:
            tick(1264)
            vm.pc = 1269
            _convert(vm, 4, 198, 201)
            tick(1269)
            vm.pc = 1270
            tick(1270)
            vm.pc = 1273
            vm.auxiliary = (0, 972444163)
            tick(1273)
            vm.pc = 1278
            vm._write(202, memory.load(cells.pointer(196), 8, signed=True) * memory.load(cells.pointer(64), 8, signed=True), 8, 'once0.integer')
            tick(1278)
            vm.pc = 1283
            vm._write(203, cells.value(202) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1287
                width = vm.program.size(360601030)
                vm._write(203, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1283)
            vm.pc = 1288
            _convert(vm, 4, 203, 204)
            tick(1288)
            vm.pc = 1293
            vm._write(205, memory.load(cells.pointer(201), 4, signed=True) ^ memory.load(cells.pointer(204), 4, signed=True), 8, 'L14.binary_q')
            tick(1293)
            _pointer(vm, 1293, 3, 4, 206, (10, 196))
            tick(1301)
            vm.pc = 1305
            value = memory.load(cells.value(206), 1)
            vm._write(207, value, 4, 'high.load')
            tick(1305)
            vm.pc = 1310
            _convert(vm, 4, 207, 208)
            tick(1310)
            vm.pc = 1313
            vm.auxiliary = (0, 55406)
            tick(1313)
            vm.pc = 1319
            vm._write(209, memory.load(cells.pointer(208), 4, signed=True) ^ memory.load(cells.pointer(205), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1319)
            vm.pc = 1324
            vm._write(210, cells.value(209) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1328
                width = vm.program.size(218307768)
                vm._write(206, cells.value(210) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1324)
            vm.pc = 1328
            pointer = cells.value(206)
            value = memory.load(cells.pointer(210), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1328)
            vm.pc = 1331
            vm.auxiliary = (0, 1715909124)
            tick(1331)
            vm.pc = 1336
            vm._write(211, memory.load(cells.pointer(201), 4, signed=True) * memory.load(cells.pointer(75), 4, signed=True), 8, 'once0.integer')
            tick(1336)
            vm.pc = 1339
            vm.auxiliary = (0, 958541826)
            tick(1339)
            vm.pc = 1344
            vm._write(212, memory.load(cells.pointer(211), 4, signed=True) + memory.load(cells.pointer(77), 4, signed=True), 8, 'once1.integer')
            tick(1344)
            vm.pc = 1349
            vm._write(199, cells.value(212) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1353
                width = vm.program.size(37413)
                vm._write(92657197, cells.value(1626607618) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1349)
            vm.pc = 1352
            vm.auxiliary = (0, 1626607618)
            tick(1352)
            vm.pc = 1357
            vm._write(197, memory.load(cells.pointer(196), 8, signed=True) + memory.load(cells.pointer(61), 8, signed=True), 8, 'once1.integer')
            tick(1357)
            vm.pc = 1359
            vm._jump(57)
            continue
        if vm.block == 59:
            tick(1359)
            vm.pc = 1361
            vm._jump(56)
            continue
        if vm.block == 56:
            tick(1361)
            _pointer(vm, 1361, 25, 0, 213, (48, 39))
            tick(1369)
            vm.pc = 1373
            value = memory.load(cells.value(213), 4)
            vm._write(214, value, 4, 'high.load')
            tick(1373)
            _pointer(vm, 1373, 25, 0, 215, (48, 48))
            tick(1381)
            vm.pc = 1385
            value = memory.load(cells.value(215), 4)
            vm._write(216, value, 4, 'high.load')
            tick(1385)
            vm.pc = 1386
            tick(1386)
            vm.pc = 1389
            vm.auxiliary = (0, 65284)
            tick(1389)
            vm.pc = 1395
            vm._write(217, memory.load(cells.pointer(214), 4, signed=True) ^ memory.load(cells.pointer(216), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1395)
            _pointer(vm, 1395, 3, 4, 218, (10, 219))
            tick(1403)
            vm.pc = 1407
            value = memory.load(cells.value(218), 1)
            vm._write(220, value, 4, 'high.load')
            tick(1407)
            vm.pc = 1412
            _convert(vm, 4, 220, 221)
            tick(1412)
            vm.pc = 1417
            vm._write(222, memory.load(cells.pointer(217), 4, signed=True) ^ memory.load(cells.pointer(221), 4, signed=True), 8, 'L14.binary_q')
            tick(1417)
            _pointer(vm, 1417, 25, 0, 223, (48, 177))
            tick(1425)
            vm.pc = 1429
            value = memory.load(cells.value(223), 1)
            vm._write(224, value, 4, 'high.load')
            tick(1429)
            vm.pc = 1434
            _convert(vm, 4, 224, 225)
            tick(1434)
            vm.pc = 1437
            vm.auxiliary = (0, 2065965058)
            tick(1437)
            vm.pc = 1442
            vm._write(226, memory.load(cells.pointer(225), 4, signed=True) + memory.load(cells.pointer(90), 4, signed=True), 8, 'once1.integer')
            tick(1442)
            vm.pc = 1447
            a = memory.load(cells.pointer(226), 4, signed=True)
            b = memory.load(cells.pointer(97), 4, signed=True)
            if b == 0 or (a == -(1 << 63) and b == -1):
                raise PrimaryProgramLimit('native signed IDIV64 fault outside ordinary execution')
            quotient = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
            vm._write(227, a - quotient * b, 8, "L16.signed_remainder_q")
            tick(1447)
            vm.pc = 1452
            vm._write(228, cells.value(227) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1456
                width = vm.program.size(218307768)
                vm._write(223, cells.value(228) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1452)
            vm.pc = 1456
            pointer = cells.value(223)
            value = memory.load(cells.pointer(228), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1456)
            _pointer(vm, 1456, 25, 0, 229, (48, 100))
            tick(1464)
            vm.pc = 1469
            cells.copy_q_clear_owned(225, 230)
            tick(1469)
            _pointer(vm, 1469, 11, 229, 231, (10, 230))
            tick(1477)
            vm.pc = 1482
            cells.copy_q_clear_owned(231, 232)
            tick(1482)
            vm.pc = 1486
            vm._jump(60 if cells.value(17) != 0 else 61)
            continue
        if vm.block == 60:
            tick(1486)
            vm.pc = 1488
            vm._jump(62)
            continue
        if vm.block == 62:
            tick(1488)
            _phi(vm, 1488, (233, 2, 234, 60, 235, 63))
            tick(1495)
            _phi(vm, 1495, (236, 2, 232, 60, 237, 63))
            tick(1502)
            vm.pc = 1503
            tick(1503)
            vm.pc = 1506
            vm.auxiliary = (0, 354033665)
            tick(1506)
            vm.pc = 1511
            vm._write(235, memory.load(cells.pointer(233), 8, signed=True) + memory.load(cells.pointer(88), 8, signed=True), 8, 'once1.integer')
            tick(1511)
            vm.pc = 1516
            vm._write(238, int(cells.value(233) > cells.value(10)), 4, 'L31.comparison')
            tick(1516)
            vm.pc = 1520
            vm._jump(63 if cells.value(238) != 0 else 64)
            continue
        if vm.block == 63:
            tick(1520)
            _pointer(vm, 1520, 2, 236, 237, (90,))
            tick(1527)
            vm.pc = 1531
            pointer = cells.value(236)
            value = memory.load(cells.pointer(91), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1531)
            vm.pc = 1533
            vm._jump(62)
            continue
        if vm.block == 64:
            tick(1533)
            vm.pc = 1535
            vm._jump(61)
            continue
        if vm.block == 61:
            tick(1535)
            _pointer(vm, 1535, 10, 231, 239, (48, 48))
            tick(1543)
            _pointer(vm, 1543, 9, 239, 240, (10, 10))
            tick(1551)
            vm.pc = 1552
            tick(1552)
            vm.pc = 1555
            vm.auxiliary = (0, 944958756)
            tick(1555)
            vm.pc = 1560
            vm._write(241, int(memory.load(cells.pointer(1), 8, signed=True) != memory.load(cells.pointer(7), 8, signed=True)), 4, 'L30.comparison')
            tick(1560)
            vm.pc = 1564
            vm._jump(65 if cells.value(241) != 0 else 66)
            continue
        if vm.block == 65:
            tick(1564)
            vm.pc = 1566
            vm._jump(67)
            continue
        if vm.block == 67:
            tick(1566)
            _phi(vm, 1566, (242, 2, 2, 65, 243, 68))
            tick(1573)
            _phi(vm, 1573, (244, 2, 240, 65, 245, 68))
            tick(1580)
            _phi(vm, 1580, (246, 2, 1, 65, 247, 68))
            tick(1587)
            vm.pc = 1588
            tick(1588)
            vm.pc = 1591
            vm.auxiliary = (0, 554942465)
            tick(1591)
            vm.pc = 1596
            vm._write(243, memory.load(cells.pointer(242), 8, signed=True) + memory.load(cells.pointer(88), 8, signed=True), 8, 'once1.integer')
            tick(1596)
            vm.pc = 1601
            vm._write(248, int(cells.value(242) > cells.value(10)), 4, 'L31.comparison')
            tick(1601)
            vm.pc = 1605
            vm._jump(68 if cells.value(248) != 0 else 69)
            continue
        if vm.block == 68:
            tick(1605)
            _pointer(vm, 1605, 2, 246, 247, (90,))
            tick(1612)
            vm.pc = 1616
            value = memory.load(cells.value(246), 1)
            vm._write(249, value, 4, 'high.load')
            tick(1616)
            _pointer(vm, 1616, 2, 244, 245, (90,))
            tick(1623)
            vm.pc = 1627
            pointer = cells.value(244)
            value = memory.load(cells.pointer(249), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1627)
            vm.pc = 1629
            vm._jump(67)
            continue
        if vm.block == 69:
            tick(1629)
            vm.pc = 1631
            vm._jump(66)
            continue
        if vm.block == 66:
            tick(1631)
            vm.pc = 1635
            value = memory.load(cells.value(215), 4)
            vm._write(250, value, 4, 'high.load')
            tick(1635)
            vm.pc = 1636
            tick(1636)
            vm.pc = 1639
            vm.auxiliary = (0, 36181)
            tick(1639)
            vm.pc = 1645
            vm._write(251, memory.load(cells.pointer(250), 4, signed=True) ^ memory.load(cells.pointer(225), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1645)
            vm.pc = 1648
            vm.auxiliary = (0, 26710)
            tick(1648)
            vm.pc = 1654
            vm._write(253, memory.load(cells.pointer(251), 4, signed=True) ^ memory.load(cells.pointer(252), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1654)
            vm.pc = 1659
            vm._write(254, cells.value(253) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1663
                width = vm.program.size(360601030)
                vm._write(254, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1659)
            vm.pc = 1664
            _convert(vm, 4, 254, 255)
            tick(1664)
            vm.pc = 1669
            vm._write(257, memory.load(cells.pointer(255), 4, signed=True) & memory.load(cells.pointer(256), 4, signed=True), 8, 'L13.binary_q')
            tick(1669)
            vm.pc = 1674
            vm._write(258, cells.value(257) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1678
                width = vm.program.size(252598635)
                vm._write(10, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1674)
            _pointer(vm, 1674, 10, 231, 259, (48, 90))
            tick(1682)
            vm.pc = 1686
            pointer = cells.value(259)
            value = memory.load(cells.pointer(258), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1686)
            vm.pc = 1690
            vm._jump(70 if cells.value(17) != 0 else 71)
            continue
        if vm.block == 70:
            tick(1690)
            vm.pc = 1694
            vm._jump(72 if cells.value(17) != 0 else 71)
            continue
        if vm.block == 72:
            tick(1694)
            vm.pc = 1699
            _convert(vm, 8, 258, 260)
            tick(1699)
            _pointer(vm, 1699, 5, 193, 261, (10, 260))
            tick(1707)
            vm.pc = 1711
            value = memory.load(cells.value(261), 1)
            vm._write(262, value, 4, 'high.load')
            tick(1711)
            vm.pc = 1713
            vm._jump(73)
            continue
        if vm.block == 73:
            tick(1713)
            _phi(vm, 1713, (263, 2, 10, 72, 264, 74))
            tick(1720)
            _phi(vm, 1720, (265, 2, 262, 72, 266, 74))
            tick(1727)
            vm.pc = 1732
            vm._write(267, int(cells.value(263) < cells.value(114)), 4, 'once18.unsigned_q')
            tick(1732)
            vm.pc = 1736
            vm._jump(74 if cells.value(267) != 0 else 75)
            continue
        if vm.block == 74:
            tick(1736)
            vm.pc = 1741
            _convert(vm, 4, 265, 268)
            tick(1741)
            vm.pc = 1742
            tick(1742)
            vm.pc = 1745
            vm.auxiliary = (0, 1665712644)
            tick(1745)
            vm.pc = 1750
            vm._write(269, memory.load(cells.pointer(263), 8, signed=True) * memory.load(cells.pointer(64), 8, signed=True), 8, 'once0.integer')
            tick(1750)
            vm.pc = 1753
            vm.auxiliary = (0, 1263390722)
            tick(1753)
            vm.pc = 1758
            vm._write(270, memory.load(cells.pointer(269), 8, signed=True) + memory.load(cells.pointer(260), 8, signed=True), 8, 'once1.integer')
            tick(1758)
            vm.pc = 1763
            vm._write(271, cells.value(270) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1767
                width = vm.program.size(360601030)
                vm._write(271, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1763)
            vm.pc = 1768
            _convert(vm, 4, 271, 272)
            tick(1768)
            vm.pc = 1771
            vm.auxiliary = (0, 30821)
            tick(1771)
            vm.pc = 1777
            vm._write(273, memory.load(cells.pointer(268), 4, signed=True) ^ memory.load(cells.pointer(272), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1777)
            _pointer(vm, 1777, 9, 239, 274, (10, 263))
            tick(1785)
            vm.pc = 1789
            value = memory.load(cells.value(274), 1)
            vm._write(275, value, 4, 'high.load')
            tick(1789)
            vm.pc = 1794
            _convert(vm, 4, 275, 276)
            tick(1794)
            vm.pc = 1797
            vm.auxiliary = (0, 56325)
            tick(1797)
            vm.pc = 1803
            vm._write(277, memory.load(cells.pointer(276), 4, signed=True) ^ memory.load(cells.pointer(273), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1803)
            vm.pc = 1808
            vm._write(278, cells.value(277) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1812
                width = vm.program.size(218307768)
                vm._write(274, cells.value(278) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1808)
            vm.pc = 1812
            pointer = cells.value(274)
            value = memory.load(cells.pointer(278), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1812)
            vm.pc = 1815
            vm.auxiliary = (0, 720212483)
            tick(1815)
            vm.pc = 1820
            vm._write(279, memory.load(cells.pointer(268), 4, signed=True) * memory.load(cells.pointer(75), 4, signed=True), 8, 'once0.integer')
            tick(1820)
            vm.pc = 1823
            vm.auxiliary = (0, 1814941697)
            tick(1823)
            vm.pc = 1828
            vm._write(280, memory.load(cells.pointer(279), 4, signed=True) + memory.load(cells.pointer(77), 4, signed=True), 8, 'once1.integer')
            tick(1828)
            vm.pc = 1833
            vm._write(266, cells.value(280) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1837
                width = vm.program.size(47893)
                vm._write(92657197, cells.value(308994049) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1833)
            vm.pc = 1836
            vm.auxiliary = (0, 308994049)
            tick(1836)
            vm.pc = 1841
            vm._write(264, memory.load(cells.pointer(263), 8, signed=True) + memory.load(cells.pointer(61), 8, signed=True), 8, 'once1.integer')
            tick(1841)
            vm.pc = 1843
            vm._jump(73)
            continue
        if vm.block == 75:
            tick(1843)
            vm.pc = 1845
            vm._jump(71)
            continue
        if vm.block == 71:
            tick(1845)
            _pointer(vm, 1845, 10, 231, 281, (48, 104))
            tick(1853)
            vm.pc = 1857
            pointer = cells.value(281)
            value = memory.load(cells.pointer(282), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1857)
            vm.pc = 1862
            vm._write(283, int(cells.value(222) < cells.value(97)), 4, 'once18.unsigned_q')
            tick(1862)
            vm.pc = 1866
            vm._jump(76 if cells.value(283) != 0 else 77)
            continue
        if vm.block == 76:
            tick(1866)
            vm.pc = 1867
            tick(1867)
            vm.pc = 1870
            vm.auxiliary = (0, 465121282)
            tick(1870)
            vm.pc = 1875
            vm._write(284, memory.load(cells.pointer(222), 4, signed=True) + memory.load(cells.pointer(90), 4, signed=True), 8, 'once1.integer')
            tick(1875)
            vm.pc = 1879
            value = memory.load(cells.value(215), 4)
            vm._write(285, value, 4, 'high.load')
            tick(1879)
            vm.pc = 1883
            value = memory.load(cells.value(218), 1)
            vm._write(286, value, 4, 'high.load')
            tick(1883)
            vm.pc = 1888
            _convert(vm, 4, 286, 287)
            tick(1888)
            vm.pc = 1891
            vm.auxiliary = (0, 19269)
            tick(1891)
            vm.pc = 1897
            vm._write(288, memory.load(cells.pointer(285), 4, signed=True) ^ memory.load(cells.pointer(287), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1897)
            vm.pc = 1902
            vm._write(289, memory.load(cells.pointer(284), 4, signed=True) ^ memory.load(cells.pointer(288), 4, signed=True), 8, 'L14.binary_q')
            tick(1902)
            vm.pc = 1906
            pointer = cells.value(213)
            value = memory.load(cells.pointer(289), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(1906)
            vm.pc = 1908
            vm._jump(77)
            continue
        if vm.block == 77:
            tick(1908)
            vm.pc = 1915
            _host(vm, 1908, 16, (0, 161), 34, None)
            tick(1915)
            vm.pc = 1917
            vm._jump(49)
            continue
        if vm.block == 49:
            tick(1917)
            _phi(vm, 1917, (290, 2, 48, 77, 178, 19))
            tick(1924)
            vm.pc = 1926
            vm._jump(3)
            continue
        if vm.block == 3:
            tick(1926)
            _phi(vm, 1926, (291, 2, 90, 1, 290, 49))
            tick(1933)
            vm.pc = 1936
            vm.result = memory.load(cells.pointer(291), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('UIN left its fixed source blocks')
