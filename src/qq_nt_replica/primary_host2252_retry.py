from .primary_core_mg_raw import host_read
from .errors import InputError, LibraryLimitError
from .primary_vm import PrimaryExecutionPaused, PrimaryProgramLimit, PrimarySemanticUnavailable
from . import primary_host2252 as normal


class Stage1ByteRetry:
    def __init__(self, memory, image_base, pointer):
        self.memory = memory
        self.image_base = image_base
        self.pointer = pointer
        self.row_i = 0
        self.phase = 'row_gate'
        self.pending_row = None
        self.pending_m = None
        self.input_byte = None
        self.workspace = bytearray(256)
        self.known = bytearray(256)
        self.store_count = 0
        self.m_read_count = 0
        low = pointer & 0xFFFFFFFF
        self.q = (((((low << 1) | (low >> 31)) & 0xFFFFFFFF) * 0x19660D - 1) & 0xFFFFFFFF) & 3
        self.dummy_increments = 0

    def _commit(self):
        start = 16 * self.row_i
        self.workspace[start:start + 16] = self.pending_row
        self.known[start:start + 16] = b'\x01' * 16
        self.store_count += 1

    def run(self, read_budget):
        if type(read_budget) is not int or read_budget < 1:
            raise InputError('host2252 M-read budget must be a positive integer')
        reads = 0
        while self.phase != 'complete':
            if self.phase in ('row_gate', 'post_row_M_read'):
                if reads == read_budget:
                    raise PrimaryExecutionPaused('host2252 M-read budget exhausted; pending native call may resume')
                reads += 1
                current = host_read(self, 0x677E1BC,
                                    (0x3592D8C if self.phase == 'row_gate' else 0x3592DEB,),
                                    0x3592D98 if self.phase == 'row_gate' else 0x3592DFC, 'stage1.M')
                current = current if current < 0x80000000 else current - (1 << 32)
                self.m_read_count += 1
                if self.phase == 'row_gate':
                    self.phase = 'alternate_input' if current == -0x80000000 else 'normal_input'
                else:
                    self.pending_m = current
                    self.phase = 'normal_row_commit'
            elif self.phase in ('normal_input', 'alternate_input'):
                self.input_byte = self.memory.load(self.pointer + 4 * (self.row_i % 4) + self.row_i // 4, 1)
                self.phase = 'alternate_row_load_commit' if self.phase == 'alternate_input' else 'normal_row_load'
            elif self.phase in ('normal_row_load', 'alternate_row_load_commit'):
                offset = 4096 * self.row_i + 16 * self.input_byte
                self.pending_row = self.memory.read(self.image_base + 0x44B1480 + offset, 16)
                if self.phase == 'alternate_row_load_commit':
                    self._commit()
                    self.phase = 'dummy_delay'
                else:
                    self.phase = 'post_row_M_read'
            elif self.phase == 'normal_row_commit':
                self._commit()
                self.phase = 'alternate_input' if self.pending_m == -0x80000000 else 'advance'
            elif self.phase == 'dummy_delay':
                self.dummy_increments += self.q + 1
                self.phase = 'normal_input'
            elif self.phase == 'advance':
                self.row_i += 1
                self.pending_row = None
                self.pending_m = None
                self.input_byte = None
                self.phase = 'complete' if self.row_i == 16 else 'row_gate'
            else:
                raise InputError('invalid retained host2252 stage1 phase')


def finish_normal(block, tables, stage1):
    block = normal._view(block, 'block', 16, writable=True)
    tables = normal._view(tables, 'tables', normal._SIZE)
    if stage1.phase != 'complete' or not all(stage1.known):
        raise InputError('host2252 reductions require all completed stage1 rows')
    workspace = memoryview(bytearray(stage1.workspace))
    rows = [workspace[16 * i:16 * i + 16] for i in range(16)]
    normal._reduce_rows(tables, rows, 0)
    block[:16] = bytes(rows[0])
    normal._bridge_into(block, tables)
    normal._expand_stage2(block, tables, rows)
    normal._reduce_rows(tables, rows, 15)
    for i in range(16):
        block[i] = rows[0][4 * (i % 4) + i // 4]


_CONTROL_DISPATCH = ((0x65571F8, (0x3592D2F, 0x3592D27)),
                     (0x6557208, (0x3592D27, 0x3592D59)),
                     (0x6557220, (0x3592F71,)))


def install_control_image(memory, image_base):
    planned = [(image_base + rva, b''.join((image_base + target).to_bytes(8, 'little') for target in targets))
               for rva, targets in _CONTROL_DISPATCH]
    for address, data in planned:
        if any(address < region.address + len(region.data) and region.address < address + len(data)
               for region in memory._regions):
            raise PrimaryProgramLimit('host2252 control M dispatch initialization overlaps memory')
    try:
        for address, data in planned:
            memory.map(address, data, name='fixed QQ52230 control M dispatch', initialized=True)
    except BaseException as error:
        for address, data in reversed(planned):
            region = next((r for r in memory._regions if r.address == address and r.data.obj is data), None)
            if region is not None:
                try:
                    memory.unmap(address)
                except BaseException as cleanup_error:
                    error.add_note('host2252 control M initialization cleanup failed: ' + type(cleanup_error).__name__)
        raise
    regions = tuple((address, next(r for r in memory._regions if r.address == address)) for address, data in planned)
    memory._host2252_control_dispatch_regions = regions
    return regions


class ControlM:
    def __init__(self, memory, image_base, pointer):
        from .primary_host2252_g_retry import delay_q
        self.memory, self.image_base, self.pointer = memory, image_base, pointer
        self.q = delay_q(pointer)
        self.phase = 'control_m_read'
        self.pending_m = None
        self.control_m_reads = 0
        self.control_m_increments = 0
        self.counter = 0
        self.owners = {}

    def diagnostics(self):
        return {'phase': self.phase, 'reads': self.control_m_reads,
                'increments': self.control_m_increments, 'counter': self.counter, 'q': self.q}

    def release(self):
        self.memory = None
        self.pending_m = None
        self.owners.clear()

    def _dispatch(self, rva, index, target):
        address = self.image_base + rva + 8 * index
        region, _ = self.memory._span(address, 8)
        expected = next((owner for start, owner in getattr(self.memory, '_host2252_control_dispatch_regions', ())
                         if start == self.image_base + rva), None)
        if (not region.data.readonly or region is not expected or
                any(other is not region and other.data.obj is region.data.obj for other in self.memory._regions)):
            raise PrimarySemanticUnavailable('host2252 control M dispatch requires disjoint readonly owner')
        owner = self.owners.setdefault(rva, region)
        if owner is not region:
            raise PrimarySemanticUnavailable('host2252 control M dispatch owner changed')
        if self.memory.load(address, 8) != self.image_base + target:
            raise PrimarySemanticUnavailable('host2252 control M current dispatch is outside fixed domain')

    def run(self):
        while self.phase != 'complete':
            if self.phase == 'control_m_read':
                self.pending_m = host_read(self, 0x677E1BC, (0x3592946,), 0x3592952, 'control.M')
                if self.pending_m >= 0x80000000:
                    self.pending_m -= 1 << 32
                self.control_m_reads += 1
                self.phase = 'control_m_dispatch'
            elif self.phase == 'control_m_dispatch':
                alternate = self.pending_m == -0x80000000
                self._dispatch(0x65571F8, 0 if alternate else 1, 0x3592D2F if alternate else 0x3592D27)
                self.counter = 0
                self.phase = 'control_m_delay' if alternate else 'control_m_merge'
            elif self.phase == 'control_m_delay':
                while self.counter <= self.q:
                    self._dispatch(0x6557208, 1, 0x3592D59)
                    self.counter += 1
                    self.control_m_increments += 1
                self._dispatch(0x6557208, 0, 0x3592D27)
                self.phase = 'control_m_merge'
            elif self.phase == 'control_m_merge':
                self._dispatch(0x6557220, 0, 0x3592F71)
                self.pending_m = None
                self.phase = 'complete'
            else:
                raise InputError('invalid retained host2252 control M phase')


def _invoke_retry_original(runtime, vm, cells, pointer):
    if runtime.host2252_retry_mode == 'synchronous':
        from threading import get_ident
        owner = runtime._active_main
        if owner is None or owner['vm'] is not vm or owner['thread'] != get_ident():
            raise InputError('synchronous host2252 requires its executing main owner')
    pending = runtime._host2252_pending
    if pending is None:
        pending = {'vm': vm, 'cells': cells, 'pointer': pointer,
                   'stage1': Stage1ByteRetry(runtime.memory, runtime.image_base, pointer), 'phase': 'stage1'}
        runtime._host2252_pending = pending
    if pending['vm'] is not vm or pending['cells'] != cells or pending['pointer'] != pointer:
        raise InputError('resume the exclusive pending host2252 native call')
    if pending['phase'] == 'failed':
        raise PrimarySemanticUnavailable('host2252 normal tail failed; retained partial output cannot be replayed')
    if pending['phase'] == 'stage1':
        if not runtime.host2252_stage1_retry:
            from .primary_host2252_g_retry import normal_stage1
            normal_stage1(pending['stage1'])
        elif runtime.host2252_retry_mode == 'synchronous':
            from threading import get_ident
            owner = runtime._active_main
            if owner is None or owner['vm'] is not vm or owner['thread'] != get_ident():
                raise InputError('synchronous host2252 requires its executing main owner')
            state = pending['stage1']
            before = state.m_read_count
            try:
                if owner['remaining'] == 0:
                    raise PrimaryProgramLimit('host2252 main M-read total budget exhausted')
                state.run(owner['remaining'])
            except PrimaryExecutionPaused as error:
                raise PrimaryProgramLimit('host2252 main M-read total budget exhausted') from error
            finally:
                consumed = state.m_read_count - before
                owner['consumed'] += consumed
                owner['remaining'] -= consumed
        else:
            pending['stage1'].run(runtime.host2252_m_read_budget)
        pending['phase'] = 'control_m' if runtime.host2252_control_m else 'tail_tables'
    if pending['phase'] == 'control_m':
        state = pending.get('control_m')
        if state is None:
            state = ControlM(runtime.memory, runtime.image_base, pointer)
            pending['control_m'] = state
        try:
            state.run()
        except BaseException:
            pending['phase'] = 'failed'
            raise
        pending['phase'] = 'tail_tables'
    if runtime.host2252_final_f_retry:
        from .primary_host2252_f_retry import run_final
        return run_final(runtime, pending)
    if runtime.host2252_stage2_g_retry:
        from .primary_host2252_g_retry import run_stage2
        return run_stage2(runtime, pending)
    tables = runtime.memory.read(runtime.image_base + 0x43FD440, 1196096)
    initial = runtime.memory.read(pointer, 16)
    block = bytearray(initial)
    pending['phase'] = 'failed'
    try:
        finish_normal(block, tables, pending['stage1'])
    except LibraryLimitError:
        if block != initial:
            runtime.memory.write(pointer, bytes(block), source='359253D.normal_partial')
        raise
    runtime.memory.write(pointer, bytes(block), source='359253D.normal_complete')
    pending['phase'] = 'complete'
    if runtime.host2252_retry_mode == 'synchronous':
        from .primary_sign_lifecycle import discard_retry
        discard_retry(runtime)
    else:
        vm.host2252_last_state = pending['stage1']
        runtime._host2252_pending = None
    return None


def invoke_retry(runtime, vm, cells, pointer):
    from .primary_core_f_raw import retry_scope
    with retry_scope(runtime, vm, cells, pointer):
        return _invoke_retry_original(runtime, vm, cells, pointer)
