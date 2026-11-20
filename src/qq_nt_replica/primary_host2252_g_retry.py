from .primary_core_mg_raw import host_read
from .errors import InputError, LibraryLimitError
from .primary_vm import PrimaryExecutionPaused, PrimaryProgramLimit, PrimarySemanticUnavailable
from . import primary_host2252 as normal


_DISPATCH = ((0x65572A8, (0x3592BC8, 0x3592C99)),
             (0x65572B8, (0x3592BC8, 0x3592CC2)),
             (0x65572C8, (0x3592C99, 0x3592BED)),
             (0x65572D8, (0x3592A2F, 0x3592BFC)))


def install_image(memory, image_base):
    planned = [(image_base + rva, b''.join((image_base + target).to_bytes(8, 'little') for target in targets))
               for rva, targets in _DISPATCH]
    for address, data in planned:
        if any(address < region.address + len(region.data) and region.address < address + len(data)
               for region in memory._regions):
            raise PrimaryProgramLimit('host2252 G dispatch initialization cannot replace existing memory')
    try:
        for address, data in planned:
            memory.map(address, data, name='fixed QQ52230 pair-head G dispatch', initialized=True)
    except BaseException as error:
        for address, data in reversed(planned):
            region = next((r for r in memory._regions if r.address == address and r.data.obj is data), None)
            if region is not None:
                try:
                    memory.unmap(address)
                except BaseException as cleanup_error:
                    error.add_note('host2252 G dispatch initialization cleanup failed: ' + type(cleanup_error).__name__)
        raise
    regions = tuple((address, next(r for r in memory._regions if r.address == address)) for address, data in planned)
    memory._host2252_g_dispatch_regions = regions
    return regions


def predicate(x, y):
    n = (-y) & 0xFFFFFFFF
    b = y if n & 0x80000000 else n
    return ((((x * x) & 0xFFFFFFFF) | b) >> 31) & 1


def delay_q(pointer):
    low = pointer & 0xFFFFFFFF
    rotated = ((low << 1) | (low >> 31)) & 0xFFFFFFFF
    return ((rotated * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF) & 3


def current_math_tables(memory, base):
    tables = bytearray(normal._SIZE)
    for start, end in ((normal._T, normal._BYTE), (normal._TA, normal._SIZE)):
        tables[start:end] = memory.read(base + 0x43FD440 + start, end - start)
    return tables


def normal_stage1(state):
    while state.row_i < 16:
        i = state.row_i
        value = state.memory.load(state.pointer + 4 * (i % 4) + i // 4, 1)
        state.pending_row = state.memory.read(state.image_base + 0x44B1480 + 4096 * i + 16 * value, 16)
        state._commit()
        state.row_i += 1
    state.pending_row = None
    state.phase = 'complete'


class Stage2GWait:
    def __init__(self, memory, image_base, pointer, *, check_g=True, defer_final=False, pair_m_retry=False):
        if type(pair_m_retry) is not bool or (pair_m_retry and not check_g):
            raise InputError('host2252 pair M retry requires enabled G retry')
        self.pair_m_retry = pair_m_retry
        self.check_g = check_g
        self.defer_final = defer_final
        self.memory = memory
        self.image_base = image_base
        self.pointer = pointer
        self.phase = 'prefix'
        self.group_start = 0
        self.row = 0
        self.lane = 0
        self.selector = None
        self.workspace = bytearray(256)
        self.known = bytearray(256)
        self.block = None
        self.prefix_committed = False
        self.pending_x = None
        self.g = None
        self.q = delay_q(pointer)
        self.dummy_increments = 0
        self.g_read_count = 0
        self.completed_groups = 0
        self.g_checkpoint = 'expansion'
        self.pair_head_counter = 0
        self.pair_tail_counter = 0
        self.pair_head_dispatch_owners = {}
        self.pair_index = 0
        self.pair_m_reads = 0
        self.pair_m_read_count = 0
        self.accepted_pair_m_gates = 0
        self.pair_m_counter = 0
        self.pending_pair_m = None
        self.pair_tables = None
        self.tree_complete = False

    def diagnostics(self):
        return {'phase': self.phase, 'group_start': self.group_start, 'row': self.row,
                'lane': self.lane, 'known_bytes': sum(self.known), 'pending_x': self.pending_x,
                'prefix_committed': self.prefix_committed, 'prefix': bytes(self.block).hex() if self.block is not None else None,
                'reads': self.g_read_count, 'q': self.q, 'dummy_increments': self.dummy_increments,
                'completed_groups': self.completed_groups, 'g_checkpoint': self.g_checkpoint,
                'pair_head_counter': self.pair_head_counter, 'pair_tail_counter': self.pair_tail_counter,
                'pair_index': self.pair_index,
                'pair_m_reads': self.pair_m_reads, 'pair_m_read_count': self.pair_m_read_count,
                'accepted_pair_m_gates': self.accepted_pair_m_gates, 'pair_m_counter': self.pair_m_counter,
                'pending_pair_m': self.pending_pair_m,
                'tree_complete': self.tree_complete}

    def release(self):
        self.workspace = bytearray()
        self.known = bytearray()
        self.block = None
        self.pending_x = None
        self.pair_head_dispatch_owners.clear()
        self.pair_tables = None
        self.pending_pair_m = None

    def _pair_head_dispatch(self, rva, index, target):
        address = self.image_base + rva + 8 * index
        region, _ = self.memory._span(address, 8)
        expected = next((owner for start, owner in getattr(self.memory, '_host2252_g_dispatch_regions', ())
                         if start == self.image_base + rva), None)
        if (not region.data.readonly or
                region is not expected or
                any(other is not region and other.data.obj is region.data.obj for other in self.memory._regions)):
            raise PrimarySemanticUnavailable('host2252 pair-head G dispatch requires disjoint readonly backing')
        owner = self.pair_head_dispatch_owners.setdefault(rva, region)
        if owner is not region:
            raise PrimarySemanticUnavailable('host2252 pair-head G dispatch owner changed')
        if self.memory.load(address, 8) != self.image_base + target:
            raise PrimarySemanticUnavailable('host2252 pair-head G current dispatch is outside fixed domain')

    def prefix(self, stage1):
        if self.phase != 'prefix' or stage1.phase != 'complete' or not all(stage1.known):
            raise InputError('host2252 G prefix requires completed stage1')
        tables = current_math_tables(self.memory, self.image_base)
        workspace = memoryview(bytearray(stage1.workspace))
        rows = [workspace[16 * i:16 * i + 16] for i in range(16)]
        self.block = bytearray(self.memory.read(self.pointer, 16))
        self.phase = 'failed'
        try:
            normal._reduce_rows(tables, rows, 0)
            self.block[:] = rows[0]
            normal._bridge_into(self.block, tables)
        except BaseException:
            self.memory.write(self.pointer, bytes(self.block), source='359253D.normal_partial')
            raise
        self.memory.write(self.pointer, bytes(self.block), source='359253D.g_prefix')
        self.prefix_committed = True
        self.phase = 'g_read_x' if self.check_g else 'expand_group'

    def run(self, read_budget, pair_m_read_budget=4096):
        if type(read_budget) is not int or read_budget < 1:
            raise InputError('host2252 G-read budget must be a positive integer')
        if type(pair_m_read_budget) is not int or pair_m_read_budget < 0:
            raise InputError('host2252 pair M-read allowance must be a nonnegative integer')
        reads = 0
        pair_m_reads = 0
        while self.phase not in ('complete', 'final_ready'):
            if self.phase in ('g_read_x', 'g_read_y', 'pair_head_read_x', 'pair_head_read_y',
                              'pair_tail_read_x', 'pair_tail_read_y'):
                if reads == read_budget:
                    raise PrimaryExecutionPaused('host2252 G-read budget exhausted; pending native call may resume')
                first = self.phase.endswith('_x')
                pair_head = self.phase.startswith('pair_head')
                pair_tail = self.phase.startswith('pair_tail')
                offset = 0x6D86090 if first else 0x6D86094
                posts, classified = (((0x3592C7A, 0x3592C80), 0x3592C8F) if pair_tail else
                                     (((0x35936E0, 0x35936E6), 0x35936F5) if pair_head else
                                      ((0x35936B8, 0x35936BE), 0x35936CD)))
                value = host_read(self, offset, posts, classified, 'stage2.G')
                reads += 1
                self.g_read_count += 1
                if first:
                    self.pending_x = value
                    self.phase = 'pair_tail_read_y' if pair_tail else ('pair_head_read_y' if pair_head else 'g_read_y')
                else:
                    self.g = predicate(self.pending_x, value)
                    self.pending_x = None
                    if pair_tail:
                        self.phase = 'pair_tail_dispatch'
                    elif pair_head:
                        self.phase = 'pair_head_dispatch'
                    elif self.g:
                        self.phase = 'g_delay'
                    elif self.group_start == 16:
                        self.g_checkpoint = 'pair-head'
                        self.phase = 'pair_head_read_x'
                    else:
                        self.phase = 'expand_group'
            elif self.phase == 'pair_head_dispatch':
                self._pair_head_dispatch(0x65572A8, self.g, 0x3592C99 if self.g else 0x3592BC8)
                self.phase = 'pair_head_delay' if self.g else 'pair_m_gate'
            elif self.phase == 'pair_head_delay':
                while self.pair_head_counter <= self.q:
                    self._pair_head_dispatch(0x65572B8, 1, 0x3592CC2)
                    self.pair_head_counter += 1
                    self.dummy_increments += 1
                self._pair_head_dispatch(0x65572B8, 0, 0x3592BC8)
                self.phase = 'pair_m_gate'
            elif self.phase == 'pair_m_gate':
                if self.accepted_pair_m_gates >= 9 or not 0 <= self.pair_index <= 16 or self.pair_index % 2:
                    raise InputError('invalid retained host2252 pair M state')
                if self.pair_m_retry and pair_m_reads == pair_m_read_budget:
                    raise PrimaryExecutionPaused('host2252 pair M-read budget exhausted; pending native call may resume')
                self.pending_pair_m = host_read(self, 0x677E1BC, (0x3592BD7,), 0x3592BE3, 'pair.M')
                if self.pending_pair_m >= 0x80000000:
                    self.pending_pair_m -= 1 << 32
                pair_m_reads += 1
                self.pair_m_read_count += 1
                self.pair_m_reads += 1
                self.phase = 'pair_m_dispatch'
            elif self.phase == 'pair_m_dispatch':
                unsupported = self.pending_pair_m == -0x80000000
                self._pair_head_dispatch(0x65572C8, 0 if unsupported else 1,
                                         0x3592C99 if unsupported else 0x3592BED)
                if unsupported:
                    if not self.pair_m_retry:
                        raise PrimarySemanticUnavailable('host2252 pair M INTMIN domain is unavailable')
                    self.pair_m_counter = 0
                    self.phase = 'pair_m_delay'
                else:
                    self.accepted_pair_m_gates += 1
                    self.phase = 'pair_row_guard'
            elif self.phase == 'pair_m_delay':
                while self.pair_m_counter <= self.q:
                    self._pair_head_dispatch(0x65572B8, 1, 0x3592CC2)
                    self.pair_m_counter += 1
                    self.dummy_increments += 1
                self._pair_head_dispatch(0x65572B8, 0, 0x3592BC8)
                self.pending_pair_m = None
                self.phase = 'pair_m_gate'
            elif self.phase == 'pair_row_guard':
                mixing = self.pair_index < 16
                self._pair_head_dispatch(0x65572D8, int(mixing), 0x3592BFC if mixing else 0x3592A2F)
                self.pending_pair_m = None
                self.phase = 'pair_mix' if mixing else 'tree_tail'
            elif self.phase == 'pair_mix':
                if len(self.known) != 256 or not all(self.known):
                    from .primary_memory import UnknownMemory
                    raise UnknownMemory('host2252 pair reduction requires completed known rows')
                if self.pair_tables is None:
                    self.pair_tables = current_math_tables(self.memory, self.image_base)
                view = memoryview(self.workspace)
                i = self.pair_index
                start = normal._N + 8192 * (15 + i // 2)
                self.phase = 'failed'
                normal._m16.mix_into(self.pair_tables[start:start + 8192], view[16 * i:16 * i + 16],
                                     view[16 * (i + 1):16 * (i + 2)], view[16 * i:16 * i + 16])
                self.pair_index += 2
                self.g_checkpoint = 'pair-tail'
                self.phase = 'pair_tail_read_x'
            elif self.phase == 'pair_tail_dispatch':
                self._pair_head_dispatch(0x65572A8, self.g, 0x3592C99 if self.g else 0x3592BC8)
                if self.g:
                    self.pair_tail_counter = 0
                self.phase = 'pair_tail_delay' if self.g else 'pair_m_gate'
            elif self.phase == 'pair_tail_delay':
                while self.pair_tail_counter <= self.q:
                    self._pair_head_dispatch(0x65572B8, 1, 0x3592CC2)
                    self.pair_tail_counter += 1
                    self.dummy_increments += 1
                self._pair_head_dispatch(0x65572B8, 0, 0x3592BC8)
                self.phase = 'pair_m_gate'
            elif self.phase == 'tree_tail':
                view = memoryview(self.workspace)
                self.phase = 'failed'
                for page, (a, b) in enumerate(normal._TREE, 23):
                    start = normal._N + 8192 * page
                    normal._m16.mix_into(self.pair_tables[start:start + 8192], view[16 * a:16 * a + 16],
                                         view[16 * b:16 * b + 16], view[16 * a:16 * a + 16])
                self.tree_complete = True
                self.phase = 'postexpand_tail'
            elif self.phase == 'g_delay':
                self.dummy_increments += self.q + 1
                self.phase = 'g_read_x'
            elif self.phase == 'expand_group':
                while self.row < self.group_start + 4:
                    if self.selector is None:
                        offset = 4 * (self.group_start // 4) + 16 * (self.row - self.group_start)
                        selector = self.memory.load(self.image_base + 0x43FD440 + offset, 4, signed=True)
                        if not 0 <= selector < 16:
                            raise LibraryLimitError('host2252 current pi selector exceeds 0..15 support domain')
                        self.selector = selector
                    while self.lane < 16:
                        value = self.block[self.selector]
                        address = self.image_base + 0x44B1480 + 0x10000 + 4096 * self.row + 16 * value + self.lane
                        byte = self.memory.load(address, 1)
                        index = 16 * self.row + self.lane
                        self.workspace[index] = byte
                        self.known[index] = 1
                        self.lane += 1
                    self.row += 1
                    self.lane = 0
                    self.selector = None
                self.group_start += 4
                self.completed_groups += 1
                self.phase = 'g_read_x' if self.check_g else ('postexpand_tail' if self.group_start == 16 else 'expand_group')
            elif self.phase == 'postexpand_tail':
                self.phase = 'failed'
                tables = None if self.tree_complete else current_math_tables(self.memory, self.image_base)
                if self.defer_final:
                    if not self.tree_complete:
                        from .primary_host2252_f_retry import reduce_final
                        reduce_final(self.workspace, self.known, tables)
                    self.phase = 'final_ready'
                    continue
                view = memoryview(self.workspace)
                rows = [view[16 * i:16 * i + 16] for i in range(16)]
                if not self.tree_complete:
                    normal._reduce_rows(tables, rows, 15)
                for i in range(16):
                    self.block[i] = rows[0][4 * (i % 4) + i // 4]
                self.memory.write(self.pointer, bytes(self.block), source='359253D.normal_complete')
                self.phase = 'complete'
            else:
                raise InputError('invalid retained host2252 G phase')


def run_stage2(runtime, pending):
    state = pending.get('stage2_g')
    if state is None:
        state = Stage2GWait(runtime.memory, runtime.image_base, pending['pointer'],
                            pair_m_retry=runtime.host2252_pair_m_retry)
        pending['stage2_g'] = state
    try:
        if state.phase == 'prefix':
            state.prefix(pending['stage1'])
        if runtime.host2252_retry_mode == 'synchronous':
            owner = runtime._active_main
            before = state.g_read_count
            before_m = state.pair_m_read_count
            try:
                if owner['g_remaining'] == 0:
                    raise PrimaryProgramLimit('host2252 main G-read total budget exhausted')
                state.run(owner['g_remaining'], owner['pair_m_remaining'])
            except PrimaryExecutionPaused as error:
                raise PrimaryProgramLimit('host2252 main G/pair M-read total budget exhausted') from error
            finally:
                consumed = state.g_read_count - before
                owner['g_remaining'] -= consumed
                owner['g_consumed'] += consumed
                consumed_m = state.pair_m_read_count - before_m
                if state.pair_m_retry:
                    owner['pair_m_remaining'] -= consumed_m
                    owner['pair_m_consumed'] += consumed_m
        else:
            state.run(runtime.host2252_g_read_budget, runtime.host2252_pair_m_read_budget)
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
        pending['vm'].host2252_last_g_state = state
        runtime._host2252_pending = None
    return None
