from hashlib import sha256
from threading import get_ident

from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, PrimaryExecutionPaused, signed


MAIN_SHA256 = '28afc919ac1b8783ecbe6ddea52ebba5ea41492573609fa7cf634467ecaa00b9'
ENTRY = (44933, 1059, 1054, False)
REFERENCE_RECORD_COUNT = 24


def _reject(message):
    raise PrimarySemanticUnavailable(message)


def _read_pair(vm):
    x = signed(vm.memory.load(vm.image_base + 0x677E1B4, 4), 32)
    y = signed(vm.memory.load(vm.image_base + 0x677E1B8, 4), 32)
    return (((x * x + y * y) & 0xFFFFFFFF) | ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31


def _pair(vm):
    if _read_pair(vm):
        group = vm._once9_operands([])
        vm.program.size(group[0])
        _reject('independent Main mix alternate once operands require an unsupported valid type')


def _mask_control(vm):
    if vm.memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000:
        _reject('independent Main mix alternate class6/once10 control is unavailable')


def _node_pointer(vm, base):
    first = vm.memory.load(vm.cells.pointer(145), 4)
    index = vm.memory.load(vm.cells.pointer(311), 4)
    offsets = vm.program.layout(79)[0]
    if index >= len(offsets):
        raise PrimaryProgramLimit('indexed struct traversal reaches native NULL child type')
    pointer = vm.cells.value(base)
    if not pointer:
        _reject('independent Main mix requires selected nonnull loop nodes')
    return pointer + 32 * first + offsets[index]


def execute_primary_main_mix(vm, *, once10_read_budget=1024):
    from .primary_sign_lifecycle import start_execution
    if type(vm) is not PrimaryVM:
        _reject('independent Main mix requires the fixed Main VM')
    if vm.runtime is None:
        _reject('independent Main mix requires the current Main owner without replay')
    return start_execution(vm.runtime, _execute_primary_main_mix(vm), once10_read_budget=once10_read_budget)


def _execute_primary_main_mix(vm):
    if type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != MAIN_SHA256:
        _reject('independent Main mix requires the fixed Main VM')
    if (vm.pc, vm.block, vm.predecessor, vm.initial_block) != ENTRY:
        _reject('independent Main mix requires exact Main44933 entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            type(owner) is not dict or owner.get('vm') is not vm or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._active_failed or
            getattr(runtime, '_consumed_mgf', None) is not None):
        _reject('independent Main mix requires the current Main owner without replay')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        _reject('independent Main mix cannot enter a stopped or pending body')
    cells, memory = vm.cells, vm.memory
    signed = lambda cell, width: memory.load(cells.pointer(cell), width, signed=True)
    write = lambda cell, value, width, source: cells.set_value(cell, value, width=width, source=source)
    session = runtime.__dict__.get('_primary_wait_session')
    if session is None or session.state != 'running' or session.thread != get_ident():
        _reject('independent Main mix requires its retained execution pump')
    vm.pc = 44934
    operands = vm._once9_operands([])
    if operands != (7, 5943, 6064):
        _reject('independent Main mix requires the fixed once10 operands')
    vm._primary_mix_owner = session
    execution = None
    try:
        if vm._start_once10(*operands):
            execution = vm.pending_once10[0]
        while vm.pending_once10 is not None:
            if session.remaining == 0:
                yield session
            session.remaining -= 1
            try:
                vm._resume_once10(1, _main_owner=session)
            except PrimaryExecutionPaused as error:
                if (getattr(error, '_once10_vm', None) is not vm or
                        getattr(error, '_once10_pending', None) is not vm.pending_once10):
                    raise
    finally:
        pending = vm.pending_once10
        if pending is not None and pending[0] is execution:
            vm.pending_once10 = None
            execution.close()
        if getattr(vm, '_primary_mix_owner', None) is session:
            del vm._primary_mix_owner
    vm.pc = 44942
    vm.auxiliary = (0, 56693)
    vm.pc = 44948
    index = signed(5944, 8)
    if not 0 <= index <= 9:
        _reject('independent Main mix requires loop index0..9')
    write(6065, index ^ signed(6064, 8), 8, 'high.flag1_xor_q')
    vm.pc = 44953
    write(6066, cells.value(6065) & 0xFFFFFFFF, 8, 'once9.mask_q')
    _pair(vm)
    vm.pc = 44956
    vm.auxiliary = (0, 1713603076)
    vm.pc = 44961
    write(6067, signed(6066, 4) * signed(867, 4), 8, 'once0.integer')
    vm.pc = 44966
    value = memory.load(cells.pointer(6067), 4)
    count = memory.load(cells.pointer(375), 1)
    write(6068, value >> (count & 31), 4, 'once8.logical_shift')
    vm.pc = 44971
    write(6069, signed(6067, 4) ^ signed(6068, 4), 8, 'L14.binary_q')
    vm.pc = 44979
    write(6070, _node_pointer(vm, 6060), 8, 'high.indexed_pointer_q')
    vm.pc = 44983
    write(6071, memory.load(cells.value(6070), 8), 8, 'high.load')
    vm.pc = 44987
    write(6072, memory.load(cells.value(6071), 1), 4, 'high.load')
    vm.pc = 44995
    write(6073, _node_pointer(vm, 6003), 8, 'high.indexed_pointer_q')
    vm.pc = 44999
    write(6074, memory.load(cells.value(6073), 8), 8, 'high.load')
    vm.pc = 45003
    write(6075, memory.load(cells.value(6074), 1), 4, 'L5.unsigned_load')
    vm.pc = 45006
    vm.auxiliary = (0, 55615)
    vm.pc = 45012
    repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
    for _ in range(repeats):
        write(6076, signed(6075, 1) ^ signed(6072, 1), 8, 'typed.selector5.q')
    vm.pc = 45016
    pointer = cells.value(6074)
    value = memory.load(cells.pointer(6076), 1)
    memory.store(pointer, value, 1, source='high.store')
    vm.pc = 45020
    write(6077, memory.load(cells.value(6073), 8), 8, 'high.load')
    vm.pc = 45024
    write(6078, memory.load(cells.value(6077), 1), 4, 'high.load')
    vm.pc = 45029
    write(6079, cells.value(6069) & 255, 8, 'once9.mask_q')
    _pair(vm)
    vm.pc = 45034
    write(6080, signed(6078, 1) ^ signed(6079, 1), 8, 'L14.binary_q')
    vm.pc = 45038
    pointer = cells.value(6077)
    value = memory.load(cells.pointer(6080), 1)
    memory.store(pointer, value, 1, source='high.store')
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 45040, 1046, 1059, False
    return REFERENCE_RECORD_COUNT
