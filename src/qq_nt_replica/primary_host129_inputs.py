from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field, replace, fields
from threading import get_ident
from struct import Struct

from .errors import InputError
from .primary_memory import PrimaryMemoryLimit


@dataclass(frozen=True, repr=False, slots=True)
class Host129TypedReadObservation:
    index: int
    invocation: int
    parent: int
    block: int
    word: int
    consumed_pc: int
    opcode: int
    width: int
    evaluator_bp: int
    context: int
    cells: int
    source_pointer: int
    source_cell: int
    destination_cell: int
    native_thread: int
    native_root: int
    value: int

    def __post_init__(self):
        values = tuple(getattr(self, row.name) for row in fields(self))
        if (any(type(value) is not int or not 0 <= value < 1 << (32 if index < 8 or index == 16 else 64)
                for index, value in enumerate(values)) or self.index >= 4 or not self.invocation or
                not self.native_thread or not 1 <= self.native_root <= 8):
            raise InputError('typed host129 read requires bounded unsigned wire fields')

    def to_wire(self):
        return Struct('<8I8QI').pack(*(getattr(self, row.name) for row in fields(self)))

    @classmethod
    def from_wire(cls, data):
        if type(data) is not bytes or len(data) != 100:
            raise InputError('typed host129 read requires exact100B wire')
        return cls(*Struct('<8I8QI').unpack(data))


@dataclass(frozen=True, repr=False)
class Host129CounterReads:
    d0: int
    c0: int
    c1: int
    d1: int

    def __post_init__(self):
        if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
               for value in (self.d0, self.c0, self.c1, self.d1)):
            raise InputError('host129 counter inputs require four unsigned32 reads')


@dataclass(frozen=True, repr=False, slots=True)
class Host129ServiceReturnObservation:
    group_ordinal: int
    invocation: int
    parent: int
    service_kind: int
    subordinal: int
    word: int
    consumed_pc: int
    signature_index: int
    callee_cell_index: int
    return_width: int
    ffi_sequence: int
    reserved_zero: int
    native_root: int
    native_thread: int
    evaluator_bp: int
    context: int
    cells: int
    actual_callee: int
    callee_entry_rsp: int
    callee_return_address: int
    callee_cell_address: int
    value: int

    def __post_init__(self):
        values = tuple(getattr(self, row.name) for row in fields(self))
        if (any(type(value) is not int or not 0 <= value < 1 << (32 if index < 12 else 64)
                for index, value in enumerate(values)) or self.group_ordinal >= 3 or
                not self.invocation or self.parent >= self.invocation or self.service_kind not in (1, 2) or
                self.subordinal >= 2 or self.reserved_zero or not self.ffi_sequence or
                not 1 <= self.native_root <= 8 or not self.native_thread or
                not self.actual_callee or not self.callee_entry_rsp or not self.callee_return_address or
                self.callee_cell_address != self.cells + 24 * self.callee_cell_index):
            raise InputError('host129 service return requires authenticated bounded wire fields')
        word, pc = (((15, 21), (37, 43)) if self.service_kind == 1 else
                    ((102, 108), (122, 128)))[self.subordinal]
        if ((self.word, self.consumed_pc, self.signature_index, self.callee_cell_index, self.return_width) !=
                (word, pc, 7 if self.service_kind == 1 else 1, 5 if self.service_kind == 1 else 23,
                 8 if self.service_kind == 1 else 4) or self.service_kind == 2 and self.value >> 32):
            raise InputError('host129 service return consumer ABI mismatch')

    def to_wire(self):
        return Struct('<12I10Q').pack(*(getattr(self, row.name) for row in fields(self)))

    @classmethod
    def from_wire(cls, data):
        if type(data) is not bytes or len(data) != 128:
            raise InputError('host129 service return requires exact128B wire')
        return cls(*Struct('<12I10Q').unpack(data))


@dataclass(frozen=True, repr=False, slots=True)
class Host129InvocationInputs:
    group_ordinal: int
    invocation: int
    parent: int
    frame_source: object
    main_caller_word: int
    main_caller_consumed_pc: int
    counter_reads: object
    clock_returns: object
    entropy_returns: object
    typed_read_count: int

    def __post_init__(self):
        from .primary_singleton_history import CapturedFrameSource
        source = self.frame_source
        if (type(self.group_ordinal) is not int or not 0 <= self.group_ordinal < 3 or
                type(source) is not CapturedFrameSource or source.frame.program != 'host129' or
                (self.invocation, self.parent) != (source.invocation, source.parent) or
                any(type(value) is not int or not 0 <= value < 1 << 32 for value in
                    (self.invocation, self.parent, self.main_caller_word, self.main_caller_consumed_pc)) or
                self.main_caller_consumed_pc != self.main_caller_word + 6 or
                type(self.typed_read_count) is not int or self.typed_read_count not in (0, 4) or
                (type(self.counter_reads) is not Host129CounterReads if self.typed_read_count == 4 else self.counter_reads is not None) or
                type(self.clock_returns) is not Host129ClockServiceReturns or
                type(self.entropy_returns) is not Host129EntropyServiceReturns):
            raise InputError('host129 invocation inputs require an exact matched source group')
        expected = 2 if self.clock_returns.first == 0 or self.clock_returns.first == self.clock_returns.second else 0
        if len(self.entropy_returns.values) != expected:
            raise InputError('host129 invocation entropy count differs from actual clock branch')
        expected_reads = (4 if expected == 2 and (self.entropy_returns.values[0] == 0 or
                         self.entropy_returns.values[0] == self.entropy_returns.values[1]) else 0)
        if self.typed_read_count != expected_reads:
            raise InputError('host129 invocation counter count differs from actual service branch')
        source.__post_init__()
        if self.counter_reads is not None:
            self.counter_reads.__post_init__()
        self.clock_returns.__post_init__()
        self.entropy_returns.__post_init__()
        from .primary_sign import load_program
        record = load_program('main').words[self.main_caller_word:self.main_caller_consumed_pc]
        if (len(record) != 6 or record[:3] != (0x014A3DB9, 129, 0) or record[4:] != (454, 0)):
            raise InputError('host129 invocation main caller is not the actual host129 FFI record')


class _CounterBinding:
    _expected_reads = 4
    _roles = ((225, 41, 42, 0x64284D0), (249, 45, 46, 0x6D86054),
              (287, 45, 52, 0x6D86054), (362, 41, 63, 0x64284D0))

    def __init__(self, reads, runtime):
        if (self._expected_reads == 4 and not isinstance(reads, Host129CounterReads) or
                self._expected_reads == 0 and reads is not None):
            raise InputError('host129 counter inputs require typed raw reads')
        self._reads = reads
        self._vm = None
        self._index = 0
        self._used = False
        self._runtime = runtime
        self._thread = get_ident()
        self._root = None
        self._call = None
        self._root_used = False
        self.normal_completed = False

    @contextmanager
    def scope(self, runtime, name):
        stack = runtime._program_calls
        if runtime is not self._runtime or get_ident() != self._thread or not runtime.primary_core:
            self.close()
            raise InputError('host129 counter input runtime owner mismatch')
        if name == 'main':
            call = stack[-1]
            if (len(stack) != 1 or self._root_used or self._used or
                    type(call['arguments']) is not tuple or len(call['arguments']) != 12 or
                    call['arguments'][0] != 4 or call['hosts'] is not None):
                self.close()
                raise InputError('host129 counter inputs require one normal main root')
            self._root_used = True
            self._root = call
        if name == 'host129':
            if (self._used or len(stack) != 2 or stack[0] is not self._root or
                    stack[0]['name'] != 'main' or stack[-1]['arguments'] != () or
                    stack[-1]['hosts'] is not None):
                self.close()
                raise InputError('host129 counter inputs require the first direct main invocation')
            self._used = True
            self._call = stack[-1]
        try:
            yield
            if name == 'host129' and self._index != self._expected_reads:
                raise InputError('host129 counter input sequence was not consumed')
            if name == 'host129':
                self.normal_completed = True
            if name == 'main' and not self.normal_completed:
                raise InputError('host129 counter input sequence was not consumed')
        except BaseException:
            self.close()
            raise
        finally:
            if name in ('main', 'host129'):
                self.close()

    def close(self):
        self._used = True
        self._reads = None
        self._vm = None
        self._root = None
        self._call = None

    def read(self, vm, pc, source, destination, width):
        stack = self._runtime._program_calls
        if (not self._used or self._reads is None or self._index >= 4 or
                vm.runtime is not self._runtime or get_ident() != self._thread or
                len(stack) != 2 or stack[0] is not self._root or stack[1] is not self._call):
            raise InputError('host129 counter input lifetime is unavailable')
        from .primary_sign import load_program
        if vm.program.raw != load_program('host129').raw:
            raise InputError('host129 counter input program mismatch')
        if self._vm is None:
            self._vm = vm
        role = self._roles[self._index]
        if (self._vm is not vm or (pc, source, destination) != role[:3] or width != 4 or
                vm.cells.value(source) != vm.image_base + role[3]):
            raise InputError('host129 counter input consumer mismatch')
        values = (self._reads.d0, self._reads.c0, self._reads.c1, self._reads.d1)
        value = values[self._index]
        self._index += 1
        return value


class _ZeroCounterBinding(_CounterBinding):
    _expected_reads = 0

    def __init__(self, runtime):
        super().__init__(None, runtime)

    def read(self, vm, pc, source, destination, width):
        raise InputError('host129 authenticated zero-read branch executed an unexpected counter load')


@dataclass(frozen=True, repr=False)
class Host129ClockServiceReturns:
    first: int
    second: int

    def __post_init__(self):
        if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF
               for value in (self.first, self.second)):
            raise InputError('host129 clock service returns require two unsigned64 values')


class _ClockServiceBinding:
    def __init__(self, returns, runtime):
        if not isinstance(returns, Host129ClockServiceReturns):
            raise InputError('host129 clock service requires typed returns')
        self._returns = returns
        self._runtime = runtime
        self._thread = get_ident()
        self._root = None
        self._call = None
        self._vm = None
        self._index = 0
        self._root_used = False
        self._used = False
        self.normal_completed = False

    @contextmanager
    def scope(self, runtime, name):
        stack = runtime._program_calls
        if runtime is not self._runtime or get_ident() != self._thread or not runtime.primary_core:
            self.close()
            raise InputError('host129 clock service runtime owner mismatch')
        if name == 'main':
            call = stack[-1]
            if (len(stack) != 1 or self._root_used or self._used or
                    type(call['arguments']) is not tuple or len(call['arguments']) != 12 or
                    call['arguments'][0] != 4 or call['hosts'] is not None):
                self.close()
                raise InputError('host129 clock service requires one normal main root')
            self._root_used = True
            self._root = call
        if name == 'host129':
            if (self._used or len(stack) != 2 or stack[0] is not self._root or
                    stack[0]['name'] != 'main' or stack[-1]['arguments'] != () or
                    stack[-1]['hosts'] is not None):
                self.close()
                raise InputError('host129 clock service requires the first direct main invocation')
            self._used = True
            self._call = stack[-1]
        try:
            yield
            if name == 'host129' and self._index != 2:
                raise InputError('host129 clock service returns were not consumed')
            if name == 'host129':
                self.normal_completed = True
            if name == 'main' and not self.normal_completed:
                raise InputError('host129 clock service returns were not consumed')
        except BaseException:
            self.close()
            raise
        finally:
            if name in ('main', 'host129'):
                self.close()

    def close(self):
        self._used = True
        self._returns = None
        self._root = None
        self._call = None
        self._vm = None

    def read(self, vm, rva, cells, argument_types):
        stack = self._runtime._program_calls
        try:
            if (self._returns is None or not self._used or self._index >= 2 or
                    vm.runtime is not self._runtime or get_ident() != self._thread or
                    len(stack) != 2 or stack[0] is not self._root or stack[1] is not self._call):
                raise InputError('host129 clock service lifetime is unavailable')
            from .primary_sign import load_program
            if vm.program.raw != load_program('host129').raw:
                raise InputError('host129 clock service program mismatch')
            word, pc = ((15, 21), (37, 43))[self._index]
            if (rva not in (0x3592430, 0x2DE5A2F) or cells != () or
                    argument_types not in (None, ()) or vm.pc != pc or
                    (self._vm is not None and self._vm is not vm) or
                    vm.cells.value(5) != vm.image_base + rva or not vm.host_calls or
                    vm.host_calls[-1] != (word, vm.image_base + rva, (), 7)):
                raise InputError('host129 clock service consumer mismatch')
            self._vm = vm
            value = (self._returns.first, self._returns.second)[self._index]
            self._index += 1
            return value
        except BaseException:
            self.close()
            raise


@dataclass(frozen=True, repr=False)
class Host129EntropyServiceReturns:
    values: tuple[int, ...]

    def __post_init__(self):
        if (type(self.values) is not tuple or len(self.values) not in (0, 2) or
                any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                    for value in self.values)):
            raise InputError('host129 entropy service returns require zero or two unsigned32 values')


class _EntropyServiceBinding:
    def __init__(self, returns, runtime):
        if not isinstance(returns, Host129EntropyServiceReturns):
            raise InputError('host129 entropy service requires typed returns')
        self._returns = returns
        self._runtime = runtime
        self._thread = get_ident()
        self._root = None
        self._call = None
        self._vm = None
        self._clocks = []
        self._clock_pending = None
        self._index = 0
        self._root_used = False
        self._used = False
        self._completed = False
        self.normal_completed = False

    @contextmanager
    def scope(self, runtime, name):
        stack = runtime._program_calls
        if runtime is not self._runtime or get_ident() != self._thread or not runtime.primary_core:
            self.close()
            raise InputError('host129 entropy service runtime owner mismatch')
        if name == 'main':
            call = stack[-1]
            if (len(stack) != 1 or self._root_used or self._used or
                    type(call['arguments']) is not tuple or len(call['arguments']) != 12 or
                    call['arguments'][0] != 4 or call['hosts'] is not None):
                self.close()
                raise InputError('host129 entropy service requires one normal main root')
            self._root_used = True
            self._root = call
        if name == 'host129':
            if (self._used or len(stack) != 2 or stack[0] is not self._root or
                    stack[0]['name'] != 'main' or stack[-1]['arguments'] != () or
                    stack[-1]['hosts'] is not None):
                self.close()
                raise InputError('host129 entropy service requires the first direct main invocation')
            self._used = True
            self._call = stack[-1]
        try:
            yield
            if name == 'host129':
                if (self._returns is None or self._clock_pending is not None or len(self._clocks) != 2 or
                        len(self._returns.values) != self._expected_count() or
                        self._index != self._expected_count()):
                    raise InputError('host129 entropy service returns were not consumed for the clock branch')
                self._completed = True
                self.normal_completed = True
            if name == 'main' and not self._completed:
                raise InputError('host129 entropy service requires a completed host invocation')
        except BaseException:
            self.close()
            raise
        finally:
            if name in ('main', 'host129'):
                self.close()

    def close(self):
        self._used = True
        self._returns = None
        self._root = None
        self._call = None
        self._vm = None
        self._clocks.clear()
        self._clock_pending = None

    def _expected_count(self):
        return 2 if self._clocks[0] == 0 or self._clocks[0] == self._clocks[1] else 0

    def _consumer(self, vm, rva, cells, argument_types, word, pc, callee, signature):
        stack = self._runtime._program_calls
        if (self._returns is None or not self._used or vm.runtime is not self._runtime or
                get_ident() != self._thread or len(stack) != 2 or
                stack[0] is not self._root or stack[1] is not self._call):
            raise InputError('host129 entropy service lifetime is unavailable')
        from .primary_sign import load_program
        if vm.program.raw != load_program('host129').raw:
            raise InputError('host129 entropy service program mismatch')
        if (cells != () or argument_types not in (None, ()) or vm.pc != pc or
                (self._vm is not None and self._vm is not vm) or
                vm.cells.value(callee) != vm.image_base + rva or not vm.host_calls or
                vm.host_calls[-1] != (word, vm.image_base + rva, (), signature)):
            raise InputError('host129 entropy service consumer mismatch')
        self._vm = vm

    def check_clock(self, vm, rva, cells, argument_types):
        try:
            if (rva not in (0x3592430, 0x2DE5A2F) or self._clock_pending is not None or
                    len(self._clocks) >= 2):
                raise InputError('host129 entropy service clock sequence mismatch')
            word, pc = ((15, 21), (37, 43))[len(self._clocks)]
            self._consumer(vm, rva, cells, argument_types, word, pc, 5, 7)
            self._clock_pending = (vm, rva)
        except BaseException:
            self.close()
            raise

    def pending_clock_for(self, vm, rva):
        return (self._clock_pending is not None and self._clock_pending[0] is vm and
                self._clock_pending[1] == rva)

    def clock_return(self, vm, rva, cells, argument_types, value):
        try:
            if (rva not in (0x3592430, 0x2DE5A2F) or len(self._clocks) >= 2 or
                    self._clock_pending is None or self._clock_pending[0] is not vm or
                    self._clock_pending[1] != rva or
                    type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF):
                raise InputError('host129 entropy service clock sequence mismatch')
            word, pc = ((15, 21), (37, 43))[len(self._clocks)]
            self._consumer(vm, rva, cells, argument_types, word, pc, 5, 7)
            self._clocks.append(value)
            self._clock_pending = None
        except BaseException:
            self.close()
            raise

    def read(self, vm, rva, cells, argument_types):
        try:
            if (rva != 0x35924C4 or self._returns is None or len(self._clocks) != 2 or
                    self._expected_count() != 2 or len(self._returns.values) != 2 or self._index >= 2):
                raise InputError('host129 entropy service sequence is unavailable')
            word, pc = ((102, 108), (122, 128))[self._index]
            self._consumer(vm, rva, cells, argument_types, word, pc, 23, 1)
            value = self._returns.values[self._index]
            self._index += 1
            return value
        except BaseException:
            self.close()
            raise


class _MulticallBinding:
    def __init__(self, inputs, runtime, *, normal_three=False):
        if (type(normal_three) is not bool or type(inputs) is not tuple or not 1 <= len(inputs) <= (3 if normal_three else 2) or
                any(type(row) is not Host129InvocationInputs or row.group_ordinal != index
                    for index, row in enumerate(inputs))):
            raise InputError('host129 multicall inputs require contiguous bounded groups')
        if normal_three and (any(row.main_caller_word not in (2353, 5821, 62638) for row in inputs) or
                len({row.main_caller_word for row in inputs}) != len(inputs)):
            raise InputError('host129 normal main requires unique canonical callsites')
        self._inputs = inputs
        self._runtime = runtime
        self._thread = get_ident()
        self._root = None
        self._index = 0
        self._active = None
        self.closed = False

    def enter(self, name):
        runtime = self._runtime
        stack = runtime._program_calls
        replay = getattr(runtime, '_consumed_mgf', None)
        if self.closed or get_ident() != self._thread or replay is None or not stack:
            raise InputError('host129 multicall requires its actual owned replay root')
        if name == 'main':
            if self._root is not None or len(stack) != 1 or stack[0]['arguments'][0] != 4:
                raise InputError('host129 multicall root is unavailable')
            self._root = stack[0]
        if name != 'host129':
            return
        if (self._active is not None or self._index >= len(self._inputs) or len(stack) != 2 or
                stack[0] is not self._root or stack[-1]['arguments'] != () or stack[-1]['hosts'] is not None):
            raise InputError('host129 multicall direct invocation is unavailable')
        item = self._inputs[self._index]
        if (len(replay._calls) != 2 or replay._calls[-1][0] is not stack[-1] or
                (replay._calls[-1][1], replay._calls[0][1]) != (item.invocation, item.parent)):
            raise InputError('host129 multicall reader invocation differs from captured source')
        parent = next((row[0] for row in replay._vms.values() if row[1] is self._root), None)
        if (parent is None or parent.pc != item.main_caller_consumed_pc or not parent.host_calls or
                parent.host_calls[-1] != (item.main_caller_word, runtime.image_base + 0x2DE577E, (), 129)):
            raise InputError('host129 multicall actual main caller differs from captured source')
        names = ('_host129_counter_binding', '_host129_clock_service_binding', '_host129_entropy_service_binding')
        if any(getattr(runtime, key) is not None for key in names):
            raise InputError('host129 multicall cannot replace installed witnesses')
        bindings = ((_CounterBinding(item.counter_reads, runtime) if item.typed_read_count == 4 else _ZeroCounterBinding(runtime)),
                    _ClockServiceBinding(item.clock_returns, runtime),
                    _EntropyServiceBinding(item.entropy_returns, runtime))
        for key, binding in zip(names, bindings):
            binding._root = self._root
            binding._root_used = True
            setattr(runtime, key, binding)
        self._active = (item, bindings)

    def check_frame(self, frame):
        if self._active is None or frame != self._active[0].frame_source.frame:
            raise InputError('host129 multicall actual frame differs from captured source')

    def complete(self, name):
        if name == 'host129':
            if self._active is None or any(not binding.normal_completed for binding in self._active[1]):
                raise InputError('host129 multicall group did not exhaust its witnesses')
            self._active = None
            self._index += 1
        if name == 'main' and (self._active is not None or self._index != len(self._inputs)):
            raise InputError('host129 multicall root did not exhaust all groups')

    def close(self):
        if self._active is not None:
            for binding in self._active[1]:
                binding.close()
        self._active = self._root = None
        self._inputs = ()
        self.closed = True


@dataclass(frozen=True, repr=False)
class Host129ArenaObservation:
    arena: int

    def __post_init__(self):
        if (type(self.arena) is not int or not 0 < self.arena <= (1 << 64) - 32 or
                self.arena % 16):
            raise InputError('host129 arena observation requires an aligned nonwrapping address')


@dataclass(frozen=True, repr=False)
class Host129FrameObservation:
    arena: int
    pointers: tuple[int, int, int] = field(repr=False)

    def __post_init__(self):
        if (type(self.arena) is not int or not 0 < self.arena <= (1 << 64) - 32 or
                self.arena % 16 or type(self.pointers) is not tuple or
                any(type(value) is not int for value in self.pointers) or
                self.pointers != (self.arena, self.arena + 9, self.arena + 18)):
            raise InputError('host129 frame observation has an unsupported allocation layout')


class ObservedHost129AddressSpace:
    def __init__(self, delegate, observation):
        if not isinstance(observation, (Host129ArenaObservation, Host129FrameObservation)):
            raise InputError('host129 frame requires a typed observation')
        self._delegate = delegate
        self._observation = observation
        self._runtime = None
        self._thread = get_ident()
        self._stack = []
        self._root_used = False
        self._used = False
        self._failed = False

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    def bind_runtime(self, runtime):
        if self._runtime is not None or runtime.retain_frames:
            raise InputError('observed host129 frame requires one nonretaining runtime')
        self._runtime = runtime

    @contextmanager
    def program_context(self, name, arguments, hosts):
        if (self._failed or get_ident() != self._thread or self._runtime is None or
                [call['name'] for call in self._runtime._program_calls] != self._stack + [name]):
            raise InputError('observed host129 address owner is unavailable')
        if name == 'main':
            if (self._root_used or self._stack or type(arguments) is not tuple or
                    len(arguments) != 12 or arguments[0] != 4 or hosts is not None):
                raise InputError('observed host129 requires one normal main root')
            self._root_used = True
        if name == 'host129' and (self._stack != ['main'] or self._used or
                                  arguments != () or hosts is not None):
            raise InputError('observed host129 requires its first direct main invocation')
        context = getattr(self._delegate, 'program_context', None)
        self._stack.append(name)
        try:
            with context(name, arguments, hosts) if context else nullcontext():
                yield
            if name == 'main' and not self._used:
                raise InputError('observed host129 frame was not consumed')
        except BaseException:
            self._failed = True
            raise
        finally:
            self._stack.pop()
            if name == 'main':
                self._observation = None

    def frame(self, name):
        if name != 'host129':
            return self._delegate.frame(name)
        if (self._runtime is None or self._failed or get_ident() != self._thread or
                [call['name'] for call in self._runtime._program_calls] != ['main', 'host129'] or
                self._stack != ['main', 'host129'] or self._used or self._observation is None):
            raise InputError('observed host129 frame lifetime is unavailable')
        self._used = True
        frame = replace(self._delegate.frame(name), arena=self._observation.arena, arena_size=32)
        from .primary_sign import load_program, arena_reservation
        program = load_program(name)
        if arena_reservation(program) != 28:
            raise InputError('observed host129 logical arena extent changed')
        spans = ((frame.cells, (program.cell_count + 1) * 24), (frame.arena, 32))
        for address, size in spans:
            if type(address) is not int or not 0 <= address <= (1 << 64) - size:
                raise InputError('observed host129 frame range is invalid')
            if any(address < region.address + len(region.data) and region.address < address + size
                   for region in self._runtime.memory._regions):
                raise PrimaryMemoryLimit('observed host129 frame collides with owned memory')
        if spans[0][0] < spans[1][0] + 32 and spans[1][0] < spans[0][0] + spans[0][1]:
            raise PrimaryMemoryLimit('observed host129 frame ranges overlap')
        return frame
