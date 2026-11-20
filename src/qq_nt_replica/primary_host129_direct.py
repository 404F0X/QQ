from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_main_mix import MAIN_SHA256
from .primary_main_material_getter import _convert, _pair_control, _phi
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable


HOST129_SHA256 = 'c66f47d8bada528e0b66289d9b18a1c0854ec7522c8344f8cded9c64356b803c'
NUMERIC_SHA256 = {'host129-prepare': '0c413db7cc56ecdbb6f14b0f9e0c63444b06fa7aab13643db353d0f105682540',
                 'host129-select': 'f6fde5d2d386a51ac92f65329d946b0a53adcfdea554d996c6e38082802e33f1'}
MAIN_CALLS = {2359: (2353, 453), 5827: (5821, 936), 62644: (62638, 8355)}


def _qualify(vm, name):
    expected = HOST129_SHA256 if name == 'host129' else NUMERIC_SHA256.get(name)
    if (type(vm) is not PrimaryVM or expected is None or sha256(vm.program.raw).hexdigest() != expected or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.auxiliary) != (1, 0, None, True, None) or
            vm.arena_used != 0 or vm.result is not None or vm.halted or vm.abort_reason is not None or
            any(getattr(vm, key) is not None for key in ('pending_once10', 'pending_once9', 'pending_l26',
                'pending_variadic', 'pending_native', 'private_iv_native_pending'))):
        raise PrimarySemanticUnavailable('direct Host129 family requires its fixed fresh source frame')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or not runtime.primary_core or vm.memory is not runtime.memory or
            vm.image_base != runtime.image_base or type(owner) is not dict or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._execute_thread != get_ident() or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            type(owner.get('vm')) is not PrimaryVM or owner['vm'].runtime is not runtime or
            owner['vm'].memory is not vm.memory or owner['vm'].image_base != vm.image_base or
            sha256(owner['vm'].program.raw).hexdigest() != MAIN_SHA256 or
            not runtime.vms or runtime.vms[-1] is not vm):
        raise PrimarySemanticUnavailable('direct Host129 family requires its live Main owner')
    main, stack = owner['vm'], runtime._program_calls
    selected = MAIN_CALLS.get(main.pc)
    if selected is None:
        raise PrimarySemanticUnavailable('direct Host129 family requires an exact Main source call')
    word, destination = selected
    typ = main.program.type(129)
    if (main.program.words[word:main.pc] != (0x014A3DB9, 129, 0, destination, 454, 0) or
            not main.host_calls or main.host_calls[-1] != (word, vm.image_base + 0x2DE577E, (), 129) or
            typ.raw != 21 or typ.parameters[0] != 0 or typ.parameters[2:] != (0,) or
            main.program.type(typ.parameters[1]).raw != 7 or main.program.size(typ.parameters[1]) != 4 or
            len(stack) != (2 if name == 'host129' else 3) or stack[0]['name'] != 'main' or
            stack[0]['hosts'] is not None or stack[1]['name'] != 'host129' or
            stack[1]['arguments'] != () or stack[1]['hosts'] is not None or stack[-1]['name'] != name or
            stack[-1]['hosts'] is not None or
            getattr(vm, '_primary_host129_reader_arguments', None) != stack[-1]['arguments']):
        raise PrimarySemanticUnavailable('direct Host129 family source stack or ABI differs')
    if name != 'host129':
        parent = runtime.vms[-2]
        active = getattr(parent, '_primary_host129_active_call', None)
        rows = {'host129-prepare': {95: (88, 20, 18, 19, 0x2DE4C87)},
                'host129-select': {215: (208, 39, 37, 38, 0x2DE5A3F),
                                   392: (385, 39, 66, 67, 0x2DE5A3F)}}
        row = rows[name].get(parent.pc)
        if (parent.runtime is not runtime or parent.memory is not vm.memory or
                sha256(parent.program.raw).hexdigest() != HOST129_SHA256 or row is None or
                active != (row[0], row[1], (row[2],), 13, row[3]) or
                parent.program.words[row[0]:parent.pc] != (0x014A3DB9, 13, 0, row[3], row[1], 0, row[2]) or
                not parent.host_calls or parent.host_calls[-1] != (row[0], vm.image_base + row[4], (row[2],), 13) or
                len(stack[-1]['arguments']) != 1 or type(stack[-1]['arguments'][0]) is not int or
                not 0 <= stack[-1]['arguments'][0] <= 0xFFFFFFFF):
            raise PrimarySemanticUnavailable('direct Host129 numeric child requires its actual active source host')
    return runtime, word


def _counter_load(vm, word, source, destination):
    binding = vm.runtime._host129_source_clock_binding
    if binding is not None:
        binding._direct_witness.load_counter(word)
    else:
        from .primary_support_core import _load
        _load(vm, word + 4, source, destination, 4, host129_counter=True)


def _host129_host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    expected = {15: 0x2DE5A2F, 25: 0x2DE5A34, 37: 0x2DE5A2F, 88: 0x2DE4C87,
                102: 0x35924C4, 122: 0x35924C4, 208: 0x2DE5A3F, 385: 0x2DE5A3F}[word]
    if address != vm.image_base + expected:
        raise PrimarySemanticUnavailable('direct Host129 requires its actual fixed source host binding')
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    vm._primary_host129_active_call = (word, callee, arguments, signature, destination)
    try:
        result = _invoke_host(vm, address, arguments, signature,
                              argument_types=vm.program.type(signature).parameters[3:])
    finally:
        vm._primary_host129_active_call = None
    vm._write(destination, result, 8, 'high.native_result_q')


def _execution(vm, name, max_steps, execution_report):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    runtime, caller = _qualify(vm, name)
    state = dict(program=name, mainCallWord=caller, backend='DIRECT_HOST129_FAMILY',
                 referenceRecordCount=0, completed=False, genericReferenceTraceComplete=False)
    if execution_report is not None:
        execution_report.update(state)
        state = execution_report
    def tick(word):
        vm.pc = word
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit('direct Host129 family record budget exhausted')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    return runtime, state, tick


def execute_primary_host129(vm, *, max_steps=1_000_000, execution_report=None):
    runtime, state, tick = _execution(vm, 'host129', max_steps, execution_report)
    vm.primary_host129_direct_state = state
    binding = runtime._host129_source_clock_binding
    original_write = None
    witness = None
    try:
        if binding is not None:
            original_write = runtime._install_source_counter_write(vm)
            witness = binding.begin_direct_vm(vm)
        _host129_body(vm, tick)
        observer = getattr(runtime, '_primary_stage_observer', None)
        if observer is not None:
            observer('host129', (vm.result & 0xFFFFFFFF).to_bytes(4, 'little'), state['mainCallWord'], None, None)
        state['completed'] = True
        if witness is not None:
            state['counterLoads'] = witness.summary()
        return vm.result
    finally:
        if original_write is not None:
            vm._write = original_write


def execute_primary_host129_numeric(vm, name, *, max_steps=1_000_000, execution_report=None):
    runtime, state, tick = _execution(vm, name, max_steps, execution_report)
    if name == 'host129-prepare':
        from .primary_host129_prepare import run_primary_host129_prepare
        run_primary_host129_prepare(vm, charge=tick)
    else:
        from .primary_support_core import run_primary_host129_select
        run_primary_host129_select(vm, charge=tick)
    state['completed'] = True
    return vm.result



def _host129_body(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(3, 0)
            tick(4)
            vm.pc = 7
            vm._allocate(3, 1)
            tick(7)
            vm.pc = 10
            vm._allocate(3, 2)
            tick(10)
            vm.pc = 15
            cells.copy_q_clear_owned(0, 3)
            tick(15)
            vm.pc = 21
            _host129_host(vm, 15, 5, (), 7, 4)
            tick(21)
            vm.pc = 25
            pointer = cells.value(0)
            value = memory.load(cells.pointer(4), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(25)
            vm.pc = 33
            _host129_host(vm, 25, 7, (8, 9), 9, 6)
            tick(33)
            vm.pc = 37
            pointer = cells.value(10)
            value = memory.load(cells.pointer(6), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(37)
            vm.pc = 43
            _host129_host(vm, 37, 5, (), 7, 11)
            tick(43)
            vm.pc = 47
            value = memory.load(cells.value(0), 8)
            vm._write(12, value, 8, 'high.load')
            tick(47)
            vm.pc = 52
            vm._write(14, int(cells.value(12) > cells.value(13)), 4, 'L31.comparison')
            tick(52)
            vm.pc = 56
            vm._jump(1 if cells.value(14) != 0 else 2)
            continue
        if vm.block == 1:
            tick(56)
            vm.pc = 57
            tick(57)
            vm.pc = 60
            vm.auxiliary = (0, 1198704132)
            tick(60)
            vm.pc = 65
            vm._write(15, int(memory.load(cells.pointer(12), 8, signed=True) != memory.load(cells.pointer(11), 8, signed=True)), 4, 'L30.comparison')
            tick(65)
            vm.pc = 69
            vm._jump(3 if cells.value(15) != 0 else 2)
            continue
        if vm.block == 3:
            tick(69)
            vm.pc = 74
            cells.copy_q_clear_owned(0, 16)
            tick(74)
            vm.pc = 75
            tick(75)
            vm.pc = 78
            vm.auxiliary = (0, 307224577)
            tick(78)
            vm.pc = 83
            vm._write(17, memory.load(cells.pointer(12), 8, signed=True) + memory.load(cells.pointer(16), 8, signed=True), 8, 'once1.integer')
            tick(83)
            vm.pc = 88
            vm._write(18, cells.value(17) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(88)
            vm.pc = 95
            _host129_host(vm, 88, 20, (18,), 13, 19)
            tick(95)
            vm.pc = 97
            vm._jump(4)
            continue
        if vm.block == 2:
            tick(97)
            vm.pc = 102
            cells.copy_q_clear_owned(1, 21)
            tick(102)
            vm.pc = 108
            _host129_host(vm, 102, 23, (), 1, 22)
            tick(108)
            vm.pc = 113
            _convert(vm, 8, 22, 24)
            tick(113)
            vm.pc = 117
            pointer = cells.value(1)
            value = memory.load(cells.pointer(24), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(117)
            vm.pc = 122
            cells.copy_q_clear_owned(2, 25)
            tick(122)
            vm.pc = 128
            _host129_host(vm, 122, 23, (), 1, 26)
            tick(128)
            vm.pc = 133
            _convert(vm, 8, 26, 27)
            tick(133)
            vm.pc = 137
            pointer = cells.value(2)
            value = memory.load(cells.pointer(27), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(137)
            vm.pc = 141
            value = memory.load(cells.value(1), 8)
            vm._write(28, value, 8, 'high.load')
            tick(141)
            vm.pc = 146
            vm._write(29, int(cells.value(28) > cells.value(13)), 4, 'L31.comparison')
            tick(146)
            vm.pc = 150
            vm._jump(5 if cells.value(29) != 0 else 6)
            continue
        if vm.block == 5:
            tick(150)
            vm.pc = 151
            tick(151)
            vm.pc = 154
            vm.auxiliary = (0, 489825716)
            tick(154)
            vm.pc = 159
            vm._write(30, int(memory.load(cells.pointer(28), 8, signed=True) != memory.load(cells.pointer(27), 8, signed=True)), 4, 'L30.comparison')
            tick(159)
            vm.pc = 163
            vm._jump(7 if cells.value(30) != 0 else 6)
            continue
        if vm.block == 7:
            tick(163)
            vm.pc = 168
            cells.copy_q_clear_owned(0, 31)
            tick(168)
            vm.pc = 169
            tick(169)
            vm.pc = 172
            vm.auxiliary = (0, 253952001)
            tick(172)
            vm.pc = 177
            vm._write(32, memory.load(cells.pointer(28), 8, signed=True) + memory.load(cells.pointer(31), 8, signed=True), 8, 'once1.integer')
            tick(177)
            vm.pc = 182
            cells.copy_q_clear_owned(1, 33)
            tick(182)
            vm.pc = 185
            vm.auxiliary = (0, 1616330753)
            tick(185)
            vm.pc = 190
            vm._write(34, memory.load(cells.pointer(32), 8, signed=True) + memory.load(cells.pointer(33), 8, signed=True), 8, 'once1.integer')
            tick(190)
            vm.pc = 195
            cells.copy_q_clear_owned(2, 35)
            tick(195)
            vm.pc = 198
            vm.auxiliary = (0, 304263169)
            tick(198)
            vm.pc = 203
            vm._write(36, memory.load(cells.pointer(34), 8, signed=True) + memory.load(cells.pointer(35), 8, signed=True), 8, 'once1.integer')
            tick(203)
            vm.pc = 208
            vm._write(37, cells.value(36) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(208)
            vm.pc = 215
            _host129_host(vm, 208, 39, (37,), 13, 38)
            tick(215)
            vm.pc = 217
            vm._jump(8)
            continue
        if vm.block == 6:
            tick(217)
            vm.pc = 221
            value = memory.load(cells.value(0), 8)
            vm._write(40, value, 8, 'high.load')
            tick(221)
            vm.pc = 225
            _counter_load(vm, 221, 41, 42)
            tick(225)
            vm.pc = 230
            _convert(vm, 8, 42, 43)
            tick(230)
            vm.pc = 235
            vm._write(44, int(cells.value(40) < cells.value(43)), 4, 'once18.unsigned_q')
            tick(235)
            vm.pc = 239
            vm._jump(9 if cells.value(44) != 0 else 10)
            continue
        if vm.block == 9:
            tick(239)
            vm.pc = 243
            pointer = cells.value(0)
            value = memory.load(cells.pointer(43), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(243)
            vm.pc = 245
            vm._jump(10)
            continue
        if vm.block == 10:
            tick(245)
            vm.pc = 249
            _counter_load(vm, 245, 45, 46)
            tick(249)
            vm.pc = 250
            tick(250)
            vm.pc = 253
            vm.auxiliary = (0, 1617448961)
            tick(253)
            vm.pc = 258
            vm._write(48, memory.load(cells.pointer(46), 4, signed=True) + memory.load(cells.pointer(47), 4, signed=True), 8, 'once1.integer')
            tick(258)
            vm.pc = 262
            pointer = cells.value(45)
            value = memory.load(cells.pointer(48), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(262)
            vm.pc = 267
            _convert(vm, 8, 46, 49)
            tick(267)
            vm.pc = 271
            value = memory.load(cells.value(0), 8)
            vm._write(50, value, 8, 'high.load')
            tick(271)
            vm.pc = 274
            vm.auxiliary = (0, 2072670210)
            tick(274)
            vm.pc = 279
            vm._write(51, memory.load(cells.pointer(50), 8, signed=True) + memory.load(cells.pointer(49), 8, signed=True), 8, 'once1.integer')
            tick(279)
            vm.pc = 283
            pointer = cells.value(0)
            value = memory.load(cells.pointer(51), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(283)
            vm.pc = 287
            _counter_load(vm, 283, 45, 52)
            tick(287)
            vm.pc = 290
            vm.auxiliary = (0, 669618177)
            tick(290)
            vm.pc = 295
            vm._write(53, memory.load(cells.pointer(52), 4, signed=True) + memory.load(cells.pointer(47), 4, signed=True), 8, 'once1.integer')
            tick(295)
            vm.pc = 299
            pointer = cells.value(45)
            value = memory.load(cells.pointer(53), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(299)
            vm.pc = 304
            _convert(vm, 8, 52, 54)
            tick(304)
            vm.pc = 308
            value = memory.load(cells.value(1), 8)
            vm._write(55, value, 8, 'high.load')
            tick(308)
            vm.pc = 311
            vm.auxiliary = (0, 1414438913)
            tick(311)
            vm.pc = 316
            vm._write(56, memory.load(cells.pointer(55), 8, signed=True) + memory.load(cells.pointer(54), 8, signed=True), 8, 'once1.integer')
            tick(316)
            vm.pc = 320
            pointer = cells.value(1)
            value = memory.load(cells.pointer(56), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(320)
            vm.pc = 324
            value = memory.load(cells.value(0), 8)
            vm._write(57, value, 8, 'high.load')
            tick(324)
            vm.pc = 327
            vm.auxiliary = (0, 767135745)
            tick(327)
            vm.pc = 332
            vm._write(58, memory.load(cells.pointer(57), 8, signed=True) + memory.load(cells.pointer(56), 8, signed=True), 8, 'once1.integer')
            tick(332)
            vm.pc = 337
            cells.copy_q_clear_owned(0, 59)
            tick(337)
            vm.pc = 340
            vm.auxiliary = (0, 1661341698)
            tick(340)
            vm.pc = 345
            vm._write(60, memory.load(cells.pointer(58), 8, signed=True) + memory.load(cells.pointer(59), 8, signed=True), 8, 'once1.integer')
            tick(345)
            vm.pc = 350
            cells.copy_q_clear_owned(2, 61)
            tick(350)
            vm.pc = 353
            vm.auxiliary = (0, 1867747329)
            tick(353)
            vm.pc = 358
            vm._write(62, memory.load(cells.pointer(60), 8, signed=True) + memory.load(cells.pointer(61), 8, signed=True), 8, 'once1.integer')
            tick(358)
            vm.pc = 362
            _counter_load(vm, 358, 41, 63)
            tick(362)
            vm.pc = 367
            _convert(vm, 8, 63, 64)
            tick(367)
            vm.pc = 370
            vm.auxiliary = (0, 23389)
            tick(370)
            vm.pc = 376
            vm._write(65, memory.load(cells.pointer(62), 8, signed=True) ^ memory.load(cells.pointer(64), 8, signed=True), 8, 'high.flag1_xor_q')
            tick(376)
            vm.pc = 380
            pointer = cells.value(0)
            value = memory.load(cells.pointer(65), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(380)
            vm.pc = 385
            vm._write(66, cells.value(65) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(385)
            vm.pc = 392
            _host129_host(vm, 385, 39, (66,), 13, 67)
            tick(392)
            vm.pc = 394
            vm._jump(8)
            continue
        if vm.block == 8:
            tick(394)
            _phi(vm, 394, (68, 2, 38, 7, 67, 10))
            tick(401)
            vm.pc = 403
            vm._jump(4)
            continue
        if vm.block == 4:
            tick(403)
            _phi(vm, 403, (69, 2, 19, 3, 68, 8))
            tick(410)
            vm.pc = 413
            vm.result = memory.load(cells.pointer(69), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('direct Host129 left its source-bound blocks')
