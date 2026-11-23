from .primary_core_mg_raw import host_read
from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryExecutionPaused, PrimaryProgramLimit, PrimarySemanticUnavailable
from . import primary_host2252 as normal


_DISPATCH = ((0x65572E8, (0x3592B36, 0x3593713)),
             (0x65572F8, (0x3592F1B, 0x359372F)),
             (0x6557308, (0x359372F, 0x3592F64)),
             (0x6557318, (0x35936FF, 0x3592F1B)))


def install_image(memory, image_base):
    planned = [(image_base + rva, b''.join((image_base + target).to_bytes(8, 'little') for target in targets))
               for rva, targets in _DISPATCH]
    for address, data in planned:
        if any(address < region.address + len(region.data) and region.address < address + len(data)
               for region in memory._region_snapshot()):
            raise PrimaryProgramLimit('host2252 F dispatch initialization cannot replace existing memory')
    try:
        for address, data in planned:
            memory.map(address, data, name='fixed QQ52230 final F dispatch', initialized=True)
    except BaseException as error:
        for address, data in reversed(planned):
            region = next((r for r in memory._region_snapshot() if r.address == address and r.data.obj is data), None)
            if region is not None:
                try:
                    memory.unmap(address)
                except BaseException as cleanup_error:
                    error.add_note('host2252 F dispatch initialization cleanup failed: ' + type(cleanup_error).__name__)
        raise
    return tuple((address, next(r for r in memory._region_snapshot() if r.address == address)) for address, data in planned)


def abs_like(value):
    n = (-value) & 0xFFFFFFFF
    return value if n & 0x80000000 else n


def predicate(x, y):
    squares = (x * x + y * y) & 0xFFFFFFFF
    magnitudes = (abs_like(x) + abs_like(y)) & 0xFFFFFFFF
    return ((squares | magnitudes) >> 31) & 1


def delay_q(pointer):
    low = pointer & 0xFFFFFFFF
    rotated = ((low << 1) | (low >> 31)) & 0xFFFFFFFF
    return ((rotated * 0x19660D - 1) & 0xFFFFFFFF) & 3


def reduce_final(workspace, known, tables):
    if len(workspace) != 256 or len(known) != 256 or not all(known):
        raise UnknownMemory('host2252 final reduction requires completed known rows')
    view = memoryview(workspace)
    rows = [view[16 * i:16 * i + 16] for i in range(16)]
    normal._reduce_rows(tables, rows, 15)


class FinalFRetry:
    def __init__(self, memory, image_base, pointer, workspace, known):
        if type(pointer) is not int or not 0 <= pointer <= (1 << 64) - 16:
            raise InputError('host2252 F requires its unsigned guest block pointer')
        self.workspace = normal._view(workspace, 'final workspace', 16)
        self.known = normal._view(known, 'final known mask', 16)
        region, _ = memory._span(pointer, 16)
        if (region.data.readonly or
                pointer < image_base + 0x6D8F1B4 and image_base < pointer + 16 or
                any(r.data.obj is self.workspace.obj or r.data.obj is self.known.obj for r in memory._region_snapshot()) or
                any(r.data.obj is region.data.obj and image_base <= r.address < image_base + 0x6D8F1B4 for r in memory._region_snapshot())):
            raise PrimaryProgramLimit('host2252 F requires disjoint caller, image and private scratch')
        self.memory = memory
        self.image_base = image_base
        self.pointer = pointer
        self.phase = 'final_guard'
        self.i = 0
        self.pending_byte = None
        self.pending_destination = None
        self.pending_x = None
        self.pending_abs_x = None
        self.f = None
        self.q = delay_q(pointer)
        self.delay_counter = 0
        self.dummy_increments = 0
        self.f_read_count = 0
        self.final_m_reads = 0
        self.normal_stores = 0
        self.alternate_stores = 0
        self.source_reads = 0

    def diagnostics(self):
        return {'phase': self.phase, 'byte_index': self.i, 'pending_x': self.pending_x,
                'pending_abs_x': self.pending_abs_x, 'pending_byte': self.pending_byte,
                'pending_destination': self.pending_destination, 'reads': self.f_read_count,
                'final_m_reads': self.final_m_reads, 'normal_stores': self.normal_stores,
                'alternate_stores': self.alternate_stores, 'source_reads': self.source_reads,
                'q': self.q, 'delay_counter': self.delay_counter, 'dummy_increments': self.dummy_increments}

    def release(self):
        self.workspace = None
        self.known = None
        self.pending_byte = None
        self.pending_x = None
        self.pending_abs_x = None

    def _dispatch(self, rva, index, target):
        address = self.image_base + rva + 8 * index
        actual = self.memory.load(address, 8)
        region, _ = self.memory._span(address, 8)
        if any(other is not region and other.data.obj is region.data.obj for other in self.memory._region_snapshot()):
            raise PrimarySemanticUnavailable('host2252 final F dispatch aliases another mapped region')
        if actual != self.image_base + target:
            raise PrimarySemanticUnavailable('host2252 final F current dispatch is outside fixed domain')

    def _read_source(self):
        selector = self.i // 4 + 4 * (self.i % 4)
        if not self.known[selector]:
            raise UnknownMemory('host2252 final scratch byte is unknown')
        value = self.workspace[selector]
        self.source_reads += 1
        self.pending_destination = self.pointer + self.i
        return value

    def run(self, read_budget):
        if type(read_budget) is not int or read_budget < 0:
            raise InputError('host2252 available F reads must be a nonnegative integer')
        reads = 0
        while self.phase != 'complete':
            if self.phase == 'final_guard':
                self._dispatch(0x65572E8, int(self.i < 16), 0x3593713 if self.i < 16 else 0x3592B36)
                self.phase = 'final_M_gate' if self.i < 16 else 'complete'
            elif self.phase == 'final_M_gate':
                value = host_read(self, 0x677E1BC, (0x3593719,), 0x3593725, 'final.M')
                value = value if value < 0x80000000 else value - (1 << 32)
                self.final_m_reads += 1
                alternate = value == -0x80000000
                self._dispatch(0x65572F8, 0 if alternate else 1, 0x3592F1B if alternate else 0x359372F)
                self.phase = 'alternate_byte_load' if alternate else 'normal_byte_load'
            elif self.phase in ('normal_byte_load', 'alternate_byte_load'):
                self.pending_byte = self._read_source()
                self.phase = 'normal_byte_store' if self.phase == 'normal_byte_load' else 'alternate_byte_store'
            elif self.phase in ('normal_byte_store', 'alternate_byte_store'):
                alternate = self.phase == 'alternate_byte_store'
                self.memory.write(self.pending_destination, bytes((self.pending_byte,)),
                                  source='359253D.final_alternate_byte' if alternate else '359253D.final_normal_byte')
                if alternate:
                    self.alternate_stores += 1
                else:
                    self.normal_stores += 1
                self.pending_byte = None
                self.pending_destination = None
                self.phase = 'F_delay' if alternate else 'F_read_x'
            elif self.phase in ('F_read_x', 'F_read_y'):
                if reads == read_budget:
                    raise PrimaryExecutionPaused('host2252 F-read budget exhausted; pending native call may resume')
                offset = 0x677E1B4 if self.phase == 'F_read_x' else 0x677E1B8
                value = host_read(self, offset, (0x359375C, 0x3593769), 0x359377F, 'final.F')
                reads += 1
                self.f_read_count += 1
                if self.phase == 'F_read_x':
                    self.pending_x = value
                    self.pending_abs_x = abs_like(value)
                    self.phase = 'F_read_y'
                else:
                    squares = (self.pending_x * self.pending_x + value * value) & 0xFFFFFFFF
                    magnitudes = (self.pending_abs_x + abs_like(value)) & 0xFFFFFFFF
                    self.f = ((squares | magnitudes) >> 31) & 1
                    self.pending_x = None
                    self.pending_abs_x = None
                    self.phase = 'F_dispatch'
            elif self.phase == 'F_dispatch':
                self._dispatch(0x6557318, self.f, 0x3592F1B if self.f else 0x35936FF)
                self.phase = 'alternate_byte_load' if self.f else 'advance'
            elif self.phase == 'F_delay':
                while self.delay_counter <= self.q:
                    self._dispatch(0x6557308, 1, 0x3592F64)
                    self.delay_counter += 1
                    self.dummy_increments += 1
                self._dispatch(0x6557308, 0, 0x359372F)
                self.delay_counter = 0
                self.phase = 'normal_byte_load'
            elif self.phase == 'advance':
                self.i += 1
                self.phase = 'final_guard'
            else:
                raise InputError('invalid retained host2252 final F phase')


def run_final(runtime, pending):
    from .primary_host2252_g_retry import Stage2GWait
    stage2 = pending.get('stage2_g')
    if stage2 is None:
        stage2 = Stage2GWait(runtime.memory, runtime.image_base, pending['pointer'],
                            check_g=runtime.host2252_stage2_g_retry, defer_final=True,
                            pair_m_retry=runtime.host2252_pair_m_retry)
        pending['stage2_g'] = stage2
    try:
        if stage2.phase == 'prefix':
            stage2.prefix(pending['stage1'])
        if stage2.phase != 'final_ready':
            if runtime.host2252_retry_mode == 'synchronous':
                owner = runtime._active_main
                before = stage2.g_read_count
                before_m = stage2.pair_m_read_count
                try:
                    if runtime.host2252_stage2_g_retry and owner['g_remaining'] == 0:
                        raise PrimaryProgramLimit('host2252 main G-read total budget exhausted')
                    stage2.run(owner['g_remaining'] if runtime.host2252_stage2_g_retry else 1,
                               owner['pair_m_remaining'])
                except PrimaryExecutionPaused as error:
                    raise PrimaryProgramLimit('host2252 main G/pair M-read total budget exhausted') from error
                finally:
                    consumed = stage2.g_read_count - before
                    owner['g_remaining'] -= consumed
                    owner['g_consumed'] += consumed
                    consumed_m = stage2.pair_m_read_count - before_m
                    if stage2.pair_m_retry:
                        owner['pair_m_remaining'] -= consumed_m
                        owner['pair_m_consumed'] += consumed_m
            else:
                stage2.run(runtime.host2252_g_read_budget, runtime.host2252_pair_m_read_budget)
        state = pending.get('final_f')
        if state is None:
            state = FinalFRetry(runtime.memory, runtime.image_base, pending['pointer'], stage2.workspace, stage2.known)
            pending['final_f'] = state
        if runtime.host2252_retry_mode == 'synchronous':
            owner = runtime._active_main
            before = state.f_read_count
            try:
                state.run(owner['f_remaining'])
            except PrimaryExecutionPaused as error:
                raise PrimaryProgramLimit('host2252 main F-read total budget exhausted') from error
            finally:
                consumed = state.f_read_count - before
                owner['f_remaining'] -= consumed
                owner['f_consumed'] += consumed
        else:
            state.run(runtime.host2252_f_read_budget)
    except PrimaryExecutionPaused:
        raise
    except BaseException:
        pending['phase'] = 'failed'
        raise
    pending['phase'] = 'complete'
    if runtime.host2252_retry_mode == 'synchronous':
        from .primary_sign_lifecycle import discard_retry
        discard_retry(runtime)
    else:
        pending['vm'].host2252_last_state = pending['stage1']
        pending['vm'].host2252_last_g_state = stage2
        pending['vm'].host2252_last_f_state = state
        runtime._host2252_pending = None
    return None
