from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_consumed_mgf import SOURCE_SHA256, SourceIdentity
from .primary_host129_inputs import Host129ServiceReturnObservation, Host129TypedReadObservation
from .primary_singleton_history import CapturedFrameSource


SOURCE_SCOPE_A_UNQUALIFIED = 'SOURCE_SCOPE_A_UNQUALIFIED'
_MAIN = '28afc919ac1b8783ecbe6ddea52ebba5ea41492573609fa7cf634467ecaa00b9'
_HOST = 'c66f47d8bada528e0b66289d9b18a1c0854ec7522c8344f8cded9c64356b803c'
_WORDS = (2353, 5821, 62638)
_DESTINATIONS = (453, 936, 8355)
_CLOCK_THUNK = bytes.fromhex('e9fcc97a00')
_CLOCK_THUNK_SOURCE_SHA256 = '58a8247adefbb11582f4114e841a6ce280b7eb237bf42325ad8a73d4d02a0477'


def _fail():
    raise InputError('HOST129_SOURCE_CLOCK_INPUT_MISMATCH')


@dataclass(frozen=True, repr=False)
class Host129SourceCounterEpoch:
    d: int
    c: int
    no_intervening_writers: bool

    def __post_init__(self):
        if (any(type(v) is not int or not 0 <= v < 1 << 32 for v in (self.d, self.c)) or
                self.no_intervening_writers is not True):
            _fail()


@dataclass(frozen=True, repr=False)
class Host129SourceClockGroup:
    main_caller_word: int
    frame_source: CapturedFrameSource
    events: tuple[Host129ServiceReturnObservation, Host129ServiceReturnObservation]

    entropy_events: tuple[Host129ServiceReturnObservation, ...] = ()
    counter_observations: tuple[Host129TypedReadObservation, ...] = ()

    @property
    def persistent(self):
        return bool(self.entropy_events) and (self.entropy_events[0].value == 0 or
                self.entropy_events[0].value == self.entropy_events[1].value)

    def __post_init__(self):
        if (type(self.main_caller_word) is not int or self.main_caller_word not in _WORDS or
                type(self.frame_source) is not CapturedFrameSource or
                self.frame_source.frame.program != 'host129' or type(self.events) is not tuple or
                len(self.events) != 2 or any(type(e) is not Host129ServiceReturnObservation for e in self.events)):
            _fail()
        self.frame_source.__post_init__()
        expected = 2 if self.events[0].value == 0 or self.events[0].value == self.events[1].value else 0
        if (type(self.entropy_events) is not tuple or len(self.entropy_events) != expected or
                any(type(e) is not Host129ServiceReturnObservation for e in self.entropy_events)):
            _fail()
        for index, event in enumerate(self.events + self.entropy_events):
            event.__post_init__()
            if (event.service_kind != (1 if index < 2 else 2) or event.subordinal != index % 2 or
                    (event.invocation, event.parent) != (self.frame_source.invocation, self.frame_source.parent) or
                    event.evaluator_bp != self.frame_source.evaluator_entry - 0x118 or
                    event.context != self.frame_source.context or event.cells != self.frame_source.frame.cells or
                    event.native_root != self.frame_source.native_root or event.native_thread != self.frame_source.native_thread):
                _fail()
        if (type(self.counter_observations) is not tuple or
                len(self.counter_observations) not in ((0, 4) if self.persistent else (0,)) or
                any(type(o) is not Host129TypedReadObservation for o in self.counter_observations)):
            _fail()
        for observation in self.counter_observations:
            observation.__post_init__()


@dataclass(frozen=True, repr=False)
class Host129SourceClockInputs:
    source_identity: SourceIdentity
    process_creation_identity: str
    module_load_generation: str
    native_thread_id: int
    main_frame_source: CapturedFrameSource
    groups: tuple[Host129SourceClockGroup, ...]
    counter_epoch: Host129SourceCounterEpoch | None = None
    _claimed: bool = field(default=False, init=False, compare=False)

    @property
    def scope_label(self):
        return SOURCE_SCOPE_A_UNQUALIFIED

    def __post_init__(self):
        identity, main = self.source_identity, self.main_frame_source
        if (type(identity) is not SourceIdentity or identity.wrapper_sha256 != SOURCE_SHA256 or
                not 1 <= identity.generation <= 8 or identity.main_arguments[0] != 4 or identity.main_arguments[9] != 2 or
                any(type(s) is not str or not s for s in (self.process_creation_identity, self.module_load_generation)) or
                type(self.native_thread_id) is not int or not 0 < self.native_thread_id < 1 << 32 or
                type(main) is not CapturedFrameSource or main.frame.program != 'main' or main.parent != 0 or
                not 1 <= main.native_root <= 8 or main.native_thread != self.native_thread_id or
                main.frame.arena_size != 0xACD0 or type(self.groups) is not tuple or len(self.groups) != 3 or
                any(type(g) is not Host129SourceClockGroup for g in self.groups)):
            _fail()
        if self.counter_epoch is not None:
            if type(self.counter_epoch) is not Host129SourceCounterEpoch:
                _fail()
            self.counter_epoch.__post_init__()
        if identity.generation == 1 and any(g.persistent for g in self.groups) and self.counter_epoch is None:
            _fail()
        main.__post_init__()
        previous_invocation, previous_sequence = main.invocation, 0
        for ordinal, group in enumerate(self.groups):
            group.__post_init__()
            source = group.frame_source
            if (group.main_caller_word != _WORDS[ordinal] or source.parent != main.invocation or
                    source.invocation <= previous_invocation or source.native_root != main.native_root or
                    source.native_thread != self.native_thread_id or source.frame.arena_size != 32 or
                    source.frame.arena != main.frame.arena - 0xA10):
                _fail()
            previous_invocation = source.invocation
            for event in group.events + group.entropy_events:
                if (event.group_ordinal != ordinal or event.ffi_sequence <= previous_sequence or
                        event.actual_callee != identity.image_base + (0x2DE5A2F if event.service_kind == 1 else 0x35924C4) or
                        event.callee_return_address != identity.image_base + 0x3E6AD01):
                    _fail()
                previous_sequence = event.ffi_sequence


class _CounterLoadWitness:
    _sites = ((221, 225, 6, 41, 42, 0x64284D0), (245, 249, 10, 45, 46, 0x6D86054),
              (283, 287, 10, 45, 52, 0x6D86054), (358, 362, 10, 41, 63, 0x64284D0))

    def __init__(self, binding, vm):
        self._binding, self._vm, self._runtime = binding, vm, binding._runtime
        self._owner, self._root, self._child = binding._owner, binding._root, binding._child
        self._group, self._epoch, self._mapping = binding._group, binding._epoch, binding._mapping
        self._inputs, self._index, self._row_index = binding._inputs, binding._index, binding._row_index
        self._generation, self._thread = binding._runtime._main_generation, get_ident()
        self._root_arguments, self._child_arguments = self._root['arguments'], self._child['arguments']
        self._program, self._memory, self._cells = vm.program, vm.memory, vm.cells
        self._frame = (vm.cells.address, vm.arena_address, vm.arena_size)
        self._write = vm._write
        self._expected = 4 if binding._group.persistent else 0
        self._entries = ()
        self._attempting = self._failed = self._consumed = False

    def _valid(self):
        binding, vm, runtime = self._binding, self._vm, self._runtime
        return (binding is not None and not self._failed and not self._consumed and
                binding._direct_witness is self and binding._direct_started and binding._owner_valid() and
                binding._vm is vm and binding._owner is self._owner and binding._root is self._root and
                binding._child is self._child and binding._group is self._group and binding._epoch is self._epoch and
                binding._mapping == self._mapping and binding._inputs is self._inputs and
                binding._index == self._index and binding._row_index == self._row_index and
                runtime._main_generation == self._generation and get_ident() == self._thread and
                len(runtime._program_calls) == 2 and runtime._program_calls[-1] is self._child and
                self._root['name'] == 'main' and self._root['arguments'] == self._root_arguments and self._root['hosts'] is None and
                self._child['name'] == 'host129' and self._child['arguments'] == self._child_arguments == () and self._child['hosts'] is None and
                vm.runtime is runtime and vm.memory is self._memory is runtime.memory and vm.cells is self._cells and
                vm.program is self._program and sha256(vm.program.raw).hexdigest() == _HOST and
                self._frame == (vm.cells.address, vm.arena_address, vm.arena_size) and
                not binding._vm_complete and not binding._reading)

    def load_counter(self, word):
        binding = self._binding
        try:
            if (not self._valid() or self._attempting or len(self._entries) >= self._expected or
                    self._vm._write is not self._write or binding._installed_write != (self._vm, self._write) or
                    binding._counter_index != len(self._entries)):
                _fail()
            ordinal = len(self._entries)
            source_word, pc, block, source, destination, rva = self._sites[ordinal]
            vm = self._vm
            if (word != source_word or vm.pc != pc or vm.block != block or vm.halted or vm.abort_reason is not None or
                    vm.program.words[word:pc] != (104927175, 0, source, destination) or
                    vm.program.size(0) != 4):
                _fail()
            self._attempting = True
            address = vm.cells.value(source)
            value = vm.memory.load(address, 4)
            before = len(vm.memory.writes)
            vm._write(destination, value, 4, 'high.load')
            target = vm.cells.pointer(destination)
            stored = (target, value.to_bytes(4, 'little'), 'high.load')
            if (not self._valid() or vm._write is not self._write or address != vm.image_base + rva or
                    binding._counter_index != ordinal + 1 or len(vm.memory.writes) != before + 1 or
                    vm.memory.writes[before] != stored):
                _fail()
            self._entries += ((word, pc, block, source, destination, address, target, value, before, self._epoch),)
        except BaseException:
            self._failed = True
            if binding is not None:
                binding.close()
            raise
        finally:
            self._attempting = False

    def summary(self):
        return dict(backend='BINDING_EXECUTED_COUNTER_LOADS', expectedCount=self._expected,
                    completedCount=len(self._entries), words=[entry[0] for entry in self._entries],
                    storeIndices=[entry[8] for entry in self._entries], width=4,
                    genericReferenceTraceComplete=False)

    def consume(self):
        if (not self._valid() or self._attempting or len(self._entries) != self._expected or
                self._binding._counter_index != self._expected or
                any(a[8] >= b[8] for a, b in zip(self._entries, self._entries[1:])) or
                any(self._vm.memory.writes[e[8]] != (e[6], e[7].to_bytes(4, 'little'), 'high.load')
                    for e in self._entries)):
            _fail()
        self._consumed = True
        self.release()

    def release(self):
        self._binding = self._vm = self._runtime = self._owner = self._root = self._child = None
        self._group = self._epoch = self._mapping = self._inputs = None
        self._program = self._memory = self._cells = self._write = None
        self._entries = ()


class _SourceHost129ClockBinding:
    def __init__(self, inputs, runtime):
        rows = (inputs,) if type(inputs) is Host129SourceClockInputs else inputs
        if (type(rows) is not tuple or not 1 <= len(rows) <= 8 or
                any(type(row) is not Host129SourceClockInputs or row._claimed or
                    row.source_identity.generation != index + 1 for index, row in enumerate(rows))):
            _fail()
        first = rows[0]
        lineage = (first.process_creation_identity, first.module_load_generation,
                   first.native_thread_id, first.source_identity.image_base)
        for row in rows:
            row.__post_init__()
            if (row.process_creation_identity, row.module_load_generation,
                    row.native_thread_id, row.source_identity.image_base) != lineage:
                _fail()
        if (len({row.source_identity.candidate for row in rows}) != len(rows) or
                len({row.main_frame_source.native_root for row in rows}) != len(rows) or
                any(row.counter_epoch is not None for row in rows[1:]) or
                any(g.persistent for row in rows for g in row.groups) and first.counter_epoch is None or
                any(current.main_frame_source.invocation <= previous.groups[-1].frame_source.invocation
                    for previous, current in zip(rows, rows[1:]))):
            _fail()
        self._rows, self._row_index = rows, 0
        self._epoch, self._persistent_count = first.counter_epoch, 0
        self._inputs, self._runtime, self._thread = first, runtime, get_ident()
        self._root = self._owner = self._main_vm = self._child = self._vm = self._frame = None
        self._group = self._mapping = self._main_mapping = None
        self._index = self._clock_index = self._entropy_index = self._counter_index = 0
        self._reading = self._vm_complete = self._main_complete = False
        self.completed = self.closed = self.finished = self.failed = False
        self._direct_witness = None
        self._direct_started = False
        self._installed_write = None

    def _conflict(self):
        runtime = self._runtime
        return (getattr(runtime, '_consumed_mgf', None) is not None or
                runtime._host129_multicall_binding is not None or any(getattr(runtime, name) is not None for name in
                ('_host129_counter_binding', '_host129_clock_service_binding', '_host129_entropy_service_binding')))

    def _owner_valid(self):
        runtime = self._runtime
        return (get_ident() == self._thread and not self.closed and not self.failed and
                not runtime._active_failed and not self._conflict() and runtime._active_main is self._owner and
                self._owner is not None and self._owner['thread'] == self._thread and
                self._owner['generation'] == self._inputs.source_identity.generation == runtime._main_generation and
                runtime._execute_thread == self._thread and self._owner['vm'] is self._main_vm and
                runtime._program_calls and runtime._program_calls[0] is self._root)

    @contextmanager
    def scope(self, name):
        runtime = self._runtime
        try:
            if self.closed or get_ident() != self._thread or runtime._active_failed:
                _fail()
            if name == 'main':
                if self._row_index >= len(self._rows):
                    _fail()
                self._inputs = self._rows[self._row_index]
                source = self._inputs.source_identity
                stack = runtime._program_calls
                if (self._inputs._claimed or self._root is not None or self.completed or self._conflict() or
                        len(stack) != 1 or stack[0]['arguments'] != source.main_arguments or stack[0]['hosts'] is not None or
                        runtime.image_base != source.image_base or runtime._active_main is None or
                        runtime._active_main['generation'] != source.generation or
                        runtime._main_generation != source.generation or
                        runtime._active_main['thread'] != self._thread):
                    _fail()
                object.__setattr__(self._inputs, '_claimed', True)
                epoch = self._epoch if self._row_index == 0 else None
                if epoch is not None:
                    for rva, value in ((0x64284D0, epoch.d), (0x6D86054, epoch.c)):
                        address = runtime.image_base + rva
                        if any(a < address + 4 and address < a + (len(data) if data is not None else 4)
                               for a, data, _ in runtime.memory.writes):
                            _fail()
                        runtime.memory.store(address, value, 4, source='declared host129 scope A epoch input')
                self._root, self._owner = stack[0], runtime._active_main
                self._index = 0
                self._main_complete = False
            elif name == 'host129':
                if (not self._owner_valid() or self._child is not None or self._index >= 3 or
                        len(runtime._program_calls) != 2 or runtime._program_calls[-1]['arguments'] != () or
                        runtime._program_calls[-1]['hosts'] is not None):
                    _fail()
                if self._index >= len(self._inputs.groups):
                    _fail()
                group = self._inputs.groups[self._index]
                parent, word = self._main_vm, group.main_caller_word
                record = parent.program.words[word:word + 6]
                typ = parent.program.type(129)
                if (parent.pc != word + 6 or record != (0x014A3DB9, 129, 0, _DESTINATIONS[self._index], 454, 0) or
                        not parent.host_calls or parent.host_calls[-1] != (word, runtime.image_base + 0x2DE577E, (), 129) or
                        parent.cells.value(454) != runtime.image_base + 0x2DE577E or typ.raw != 21 or
                        typ.parameters[0] != 0 or typ.parameters[2:] != (0,) or
                        parent.program.type(typ.parameters[1]).raw != 7 or parent.program.size(typ.parameters[1]) != 4):
                    _fail()
                self._child, self._group = runtime._program_calls[-1], group
                self._clock_index = self._entropy_index = self._counter_index = 0
                self._vm_complete = False
                self._direct_witness = None
                self._direct_started = False
                self._installed_write = None
            yield
            if name == 'host129':
                if (not self._owner_valid() or runtime._program_calls[-1] is not self._child or
                        not self._vm_complete or self._clock_index != 2 or self._reading or self._frame is not None):
                    _fail()
                self._index += 1
                self._child = self._group = self._vm = self._mapping = None
                self._direct_started = False
                self._installed_write = None
            if name == 'main':
                if (not self._owner_valid() or len(runtime._program_calls) != 1 or self._child is not None or
                        self._index != 3 or not self._main_complete or self._reading or self._frame is not None):
                    _fail()
                self._persistent_count += sum(g.persistent for g in self._inputs.groups)
                self._row_index += 1
                self.completed = self._row_index == len(self._rows)
                self._root = self._owner = self._main_vm = None
        except BaseException:
            self.close()
            raise

    def check_frame(self, name, frame):
        if name not in ('main', 'host129'):
            return
        source = self._inputs.main_frame_source if name == 'main' else self._group.frame_source
        if (self._frame is not None or frame.program != name or
                (frame.arena, frame.arena_size) != (source.frame.arena, source.frame.arena_size)):
            self.close()
            _fail()
        self._frame = frame

    def attach_vm(self, name, frame, vm):
        if name not in ('main', 'host129'):
            return
        if (self._frame is not frame or vm.runtime is not self._runtime or
                sha256(vm.program.raw).hexdigest() != (_MAIN if name == 'main' else _HOST) or
                vm.cells.address != frame.cells or vm.arena_address != frame.arena):
            self.close()
            _fail()
        self._frame = None
        if name == 'main':
            self._main_vm = vm
            self._main_mapping = (self._inputs.main_frame_source.frame.cells, vm.cells.address)
        else:
            self._vm = vm
            self._mapping = (self._group.frame_source.frame.cells, vm.cells.address)

    def has_child(self):
        return self._child is not None

    def begin_direct_vm(self, vm):
        try:
            if (not self._owner_valid() or self._vm is not vm or self._direct_started or
                    self._direct_witness is not None or self._vm_complete or self._reading or
                    self._clock_index != 0 or self._entropy_index != 0 or self._counter_index != 0 or
                    len(self._runtime._program_calls) != 2 or self._runtime._program_calls[-1] is not self._child or
                    (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used, vm.auxiliary) !=
                    (1, 0, None, True, 0, None) or vm.halted or vm.abort_reason is not None or
                    sha256(vm.program.raw).hexdigest() != _HOST or self._frame is not None or
                    self._mapping != (self._group.frame_source.frame.cells, vm.cells.address) or
                    self._installed_write != (vm, vm._write)):
                _fail()
            self._direct_started = True
            self._direct_witness = _CounterLoadWitness(self, vm)
            return self._direct_witness
        except BaseException:
            self.close()
            raise

    def resolve_clock(self, cif_callee_rva):
        if (cif_callee_rva != 0x2DE5A2F or _CLOCK_THUNK != bytes.fromhex('e9fcc97a00') or
                cif_callee_rva + 5 + int.from_bytes(_CLOCK_THUNK[1:], 'little', signed=True) != 0x3592430):
            self.close()
            _fail()
        return 0x3592430

    def read_clock(self, vm, resolved_entry_rva, cells, argument_types, *, cif_callee_rva):
        try:
            stack = self._runtime._program_calls
            if (not self._owner_valid() or not self._child or len(stack) != 2 or stack[-1] is not self._child or
                    self._reading or self._vm is not vm or self._clock_index >= 2 or self._vm_complete or
                    len(self._group.events) != 2 or resolved_entry_rva != self.resolve_clock(cif_callee_rva) or
                    cells != () or argument_types not in (None, ())):
                _fail()
            self._reading = True
            event = self._group.events[self._clock_index]
            word, pc, destination = ((15, 21, 4), (37, 43, 11))[self._clock_index]
            typ = vm.program.type(7)
            if (vm.pc != pc or vm.program.words[word:pc] != (0x014A3DB9, 7, 0, destination, 5, 0) or
                    sha256(vm.program.raw).hexdigest() != _HOST or
                    not vm.host_calls or vm.host_calls[-1] != (word, self._runtime.image_base + cif_callee_rva, (), 7) or
                    vm.cells.value(5) != event.actual_callee or typ.raw != 21 or
                    vm.cells.value(0) != vm.arena_address or
                    self._runtime.memory.load(self._runtime.image_base + 0x6428970, 8) != event.actual_callee or
                    typ.parameters[0] != 0 or typ.parameters[2:] != (0,) or
                    vm.program.type(typ.parameters[1]).raw != 7 or vm.program.size(typ.parameters[1]) != 8 or
                    self._mapping != (event.cells, vm.cells.address) or
                    event.callee_cell_address - self._mapping[0] != 24 * 5):
                _fail()
            self._clock_index += 1
            return event.value
        except BaseException:
            self.close()
            raise
        finally:
            self._reading = False

    def read_entropy(self, vm, rva, cells, argument_types):
        try:
            stack = self._runtime._program_calls
            if (not self._owner_valid() or self._vm is not vm or self._reading or
                    self._vm_complete or self._clock_index != 2 or self._entropy_index >= len(self._group.entropy_events) or
                    len(stack) != 2 or stack[-1] is not self._child or rva != 0x35924C4 or
                    cells != () or argument_types not in (None, ())):
                _fail()
            event = self._group.entropy_events[self._entropy_index]
            word, pc, destination = ((102, 108, 22), (122, 128, 26))[self._entropy_index]
            typ = vm.program.type(1)
            if (vm.pc != pc or vm.program.words[word:pc] != (0x014A3DB9, 1, 0, destination, 23, 0) or
                    not vm.host_calls or vm.host_calls[-1] != (word, event.actual_callee, (), 1) or
                    vm.cells.value(23) != event.actual_callee or typ.raw != 21 or
                    typ.parameters[0] != 0 or typ.parameters[2:] != (0,) or
                    vm.program.type(typ.parameters[1]).raw != 7 or vm.program.size(typ.parameters[1]) != 4 or
                    self._mapping != (event.cells, vm.cells.address)):
                _fail()
            self._entropy_index += 1
            return event.value
        except BaseException:
            self.close()
            raise

    _roles = ((225, 41, 42, 0x64284D0), (249, 45, 46, 0x6D86054),
              (287, 45, 52, 0x6D86054), (362, 41, 63, 0x64284D0))

    def check_counter_read(self, vm, pc, source, destination, width, value):
        try:
            if (not self._owner_valid() or self._vm is not vm or not self._group.persistent or
                    self._entropy_index != 2 or self._counter_index >= 4 or self._vm_complete or
                    len(self._runtime._program_calls) != 2 or self._runtime._program_calls[-1] is not self._child):
                _fail()
            role = self._roles[self._counter_index]
            if ((pc, source, destination) != role[:3] or width != 4 or
                    vm.cells.value(source) != self._runtime.image_base + role[3]):
                _fail()
            epoch = self._epoch
            prior = self._persistent_count * 2 + sum(g.persistent for g in self._inputs.groups[:self._index]) * 2
            expected = (epoch.d if source == 41 else
                        (epoch.c + prior + (self._counter_index == 2)) & 0xFFFFFFFF)
            if value != expected:
                _fail()
            if self._group.counter_observations:
                o = self._group.counter_observations[self._counter_index]
                f = self._group.frame_source
                if ((o.index, o.invocation, o.parent, o.block, o.word, o.consumed_pc, o.opcode, o.width,
                     o.evaluator_bp, o.context, o.cells, o.source_pointer, o.source_cell, o.destination_cell,
                     o.native_thread, o.native_root, o.value) !=
                    (self._counter_index, f.invocation, f.parent, vm.block, pc - 4, pc,
                     vm.program.words[pc - 4], 4, f.evaluator_entry - 0x118, f.context, f.frame.cells,
                     vm.cells.value(source), f.frame.cells + 24 * source, f.frame.cells + 24 * destination,
                     f.native_thread, f.native_root, value)):
                    _fail()
            self._counter_index += 1
        except BaseException:
            self.close()
            raise

    def complete_vm(self, name, vm):
        if name not in ('main', 'host129'):
            return
        try:
            if not self._owner_valid() or not vm.halted or self._reading:
                _fail()
            if name == 'main':
                if vm is not self._main_vm or self._index != 3 or self._child is not None:
                    _fail()
                self._main_complete = True
                return
            if vm is not self._vm or self._clock_index != 2 or self._vm_complete:
                _fail()
            loads = []
            for pc in (225, 249, 287, 362):
                words = vm.program.words[pc - 4:pc]
                if len(words) != 4 or vm.program.size(words[1]) != 4:
                    _fail()
                loads.append((pc - 4, words[0], words[1:]))
            if self._direct_started:
                if type(self._direct_witness) is not _CounterLoadWitness:
                    _fail()
                actual_loads = self._direct_witness._expected
                self._direct_witness.consume()
                self._direct_witness = None
            else:
                actual_loads = sum((record.word, record.raw_opcode, record.operands) in loads for record in vm.trace)
            if (actual_loads != (4 if self._group.persistent else 0) or
                    self._counter_index != actual_loads or self._entropy_index != len(self._group.entropy_events) or
                    [word for word, _, _, _ in vm.host_calls if word in (102, 122)] !=
                    ([102, 122] if self._group.entropy_events else [])):
                _fail()
            self._vm_complete = True
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._direct_witness is not None:
            self._direct_witness.release()
        self._direct_witness = None
        self._direct_started = False
        self._installed_write = None
        for row in self._rows:
            object.__setattr__(row, '_claimed', True)
        self._rows = ()
        self.closed = self.failed = True
        self._inputs = self._root = self._owner = self._main_vm = self._child = self._vm = None
        self._group = self._frame = self._mapping = self._main_mapping = None
        self._reading = False

    def finish(self):
        runtime = self._runtime
        if (self.closed or self.failed or self.finished or not self.completed or self._index != 3 or self._row_index != len(self._rows) or
                get_ident() != self._thread or self._conflict() or runtime._active_failed or
                runtime._active_main is not None or runtime._program_calls or runtime._execute_thread is not None):
            self.close()
            _fail()
        self.finished = self.closed = True
        self._rows = ()
        self._inputs = None
        self._main_mapping = None
