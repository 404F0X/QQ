from hashlib import sha256
from threading import get_ident

from .local113_episode_validation import integer, keys, overlap, pointer, require
from .primary_sign import PrimaryFrame, arena_reservation, load_program
from .primary_singleton_history import CapturedFrameSource


FRAME_KEYS = 'program siteWord enterSeq leaveSeq wrapperEntryRSP words cellsCount cells arena arenaSize initiallyDefined invocation parent assetId programSha256 readerEntry context evaluatorEntry evaluatorBP backendBP nativeRoot thread contextCells contextWords evaluatorArena'


class PrefixFramePlan:
    @classmethod
    def from_wire(cls, envelope):
        identity, rows = envelope['identity'], envelope['frames']
        require(type(rows) is list and len(rows) in (2, 3), 'FRAME_COUNT')
        result = cls()
        result.identity = dict(identity)
        result.rows, result.sources = [], []
        previous = envelope['mainEntry']['seq']
        for index, row in enumerate(rows):
            keys(row, FRAME_KEYS, 'FRAME_KEYS')
            name = row['program']
            require(name == ('main' if index == 0 else 'host129'), 'FRAME_PROGRAM_ORDER')
            program = load_program(name)
            count, size, defined = (8881, 0xACD0, 44230) if name == 'main' else (71, 32, 28)
            for key in ('cellsCount', 'arenaSize', 'initiallyDefined', 'siteWord', 'invocation', 'parent', 'assetId', 'nativeRoot', 'thread'):
                integer(row[key])
            require((row['cellsCount'], row['arenaSize'], row['initiallyDefined']) == (count, size, defined) and program.cell_count + 1 == count and arena_reservation(program) == defined, 'FRAME_SIZE')
            frame = PrimaryFrame(name, pointer(row['cells']), pointer(row['arena']), size)
            source = CapturedFrameSource(frame, row['invocation'], row['parent'], row['assetId'], row['programSha256'], pointer(row['readerEntry']), pointer(row['context']), pointer(row['evaluatorEntry']), pointer(row['backendBP']), row['nativeRoot'], row['thread'])
            source.__post_init__()
            require(row['programSha256'] == sha256(program.raw).hexdigest() and row['thread'] == identity['thread'] and row['nativeRoot'] == identity['nativeRoot'], 'FRAME_IDENTITY')
            bp = pointer(row['evaluatorBP'])
            require(bp == source.evaluator_entry - 0x118 and pointer(row['contextCells']) == frame.cells and pointer(row['contextWords']) == pointer(row['words']) and pointer(row['evaluatorArena']) == frame.arena and frame.arena + size <= bp - 0x70, 'FRAME_CONTEXT')
            start, end = integer(row['enterSeq'], minimum=1), integer(row['leaveSeq'], minimum=1)
            require(previous < start < end, 'FRAME_SEQUENCE')
            if index == 0:
                require(source.invocation == identity['readerInvocation'] and source.parent == 0 and row['siteWord'] == 0 and pointer(row['wrapperEntryRSP']) == pointer(identity['mainEntryRSP']), 'MAIN_FRAME_PARENT')
            else:
                main = result.sources[0]
                require(source.parent == main.invocation and rows[0]['enterSeq'] < start < end < rows[0]['leaveSeq'], 'HOST_FRAME_PARENT')
                require(not any(overlap(a, n, b, m) for a, n in ((main.frame.cells, 8881 * 24), (main.frame.arena, 0xACD0)) for b, m in ((frame.cells, count * 24), (frame.arena, size))), 'ACTIVE_FRAME_ALIAS')
            require(not overlap(frame.cells, count * 24, frame.arena, size), 'FRAME_SELF_ALIAS')
            result.rows.append(dict(row))
            result.sources.append(source)
            previous = start if index == 0 else end
        require(tuple(r['siteWord'] for r in rows[1:]) in ((5821,), (2353, 5821)), 'PREFIX_SITES')
        result.runtime = None
        result.thread = get_ident()
        result.index = 0
        result.pending = None
        result.active = []
        result.closed = result.finished = False
        return result

    def bind(self, runtime):
        require(self.runtime is None and not self.closed and runtime.__dict__.get('_local113_frame_plan') is None and runtime._main_generation == 0 and get_ident() == self.thread, 'FRAME_BIND_ONCE')
        self.runtime = runtime
        runtime._local113_frame_plan = self

    def next_frame(self, program_name):
        require(not self.closed and not self.finished and get_ident() == self.thread and self.pending is None and self.index < len(self.sources), 'FRAME_EXHAUSTED')
        source = self.sources[self.index]
        require(source.frame.program == program_name, 'FRAME_INVOCATION')
        self.pending = source
        self.index += 1
        return source.frame

    def check_before_map(self, runtime, name, frame):
        require(runtime is self.runtime and get_ident() == self.thread and not self.closed and self.pending is not None and self.pending.frame is frame and frame.program == name, 'FRAME_MAP_OWNER')
        require(runtime._main_generation == self.identity['generation'] and runtime._execute_thread == self.thread, 'FRAME_GENERATION')
        require((name == 'main' and not self.active) or (name == 'host129' and len(self.active) == 1 and self.active[0][0].frame.program == 'main'), 'FRAME_ACTIVE_PARENT')
        for address, width in ((frame.cells, (load_program(name).cell_count + 1) * 24), (frame.arena, frame.arena_size)):
            require(not any(overlap(address, width, region.address, len(region.data)) for region in runtime.memory._region_snapshot()), 'FRAME_SOURCE_ALIAS')

    def attach_vm(self, runtime, name, frame, vm):
        require(runtime is self.runtime and self.pending is not None and self.pending.frame is frame and vm.runtime is runtime, 'FRAME_ATTACH')
        self.active.append((self.pending, vm))
        self.pending = None
        self.match_vm(name, frame, vm)

    def match_vm(self, name, frame, vm):
        require(any(source.frame is frame and actual is vm for source, actual in self.active) and sha256(vm.program.raw).hexdigest() == next(source.program_sha256 for source, actual in self.active if actual is vm) and vm.cells.address == frame.cells and vm.arena_address == frame.arena and vm.arena_size == frame.arena_size and vm.memory is self.runtime.memory, 'ACTUAL_FRAME_MISMATCH')

    def retire_vm(self, runtime, name, frame, vm):
        require(runtime is self.runtime and self.active and self.active[-1][0].frame is frame and self.active[-1][1] is vm, 'FRAME_RETIRE_OWNER')
        self.active.pop()

    def complete_prefix9563(self, runtime, vm, witness):
        from .primary_main_prefix_stop import _require_witness
        _require_witness(runtime, vm, witness)
        require(not self.finished and self.pending is None and self.index == len(self.sources) and len(self.active) == 1 and self.active[0][1] is vm, 'FRAME_PREFIX_INCOMPLETE')
        self.match_vm('main', self.sources[0].frame, vm)
        self.finished = True

    def reserved(self):
        return tuple(span for source in self.sources for span in ((source.frame.cells, (load_program(source.frame.program).cell_count + 1) * 24), (source.frame.arena, source.frame.arena_size)))

    def close(self):
        require(get_ident() == self.thread and not self.active, 'FRAME_CLOSE_ACTIVE')
        self.pending = None
        self.closed = True
