from dataclasses import dataclass
from threading import get_ident

from .errors import InputError
from .primary_host129_inputs import (
    Host129ClockServiceReturns, Host129CounterReads, Host129EntropyServiceReturns,
    _ClockServiceBinding, _CounterBinding, _EntropyServiceBinding, _ZeroCounterBinding,
)


_SITES = ((2353, 453), (5821, 936), (62638, 8355))
_BINDINGS = ('_host129_counter_binding', '_host129_clock_service_binding', '_host129_entropy_service_binding')


@dataclass(frozen=True, repr=False)
class Host129RawGroup:
    clocks: Host129ClockServiceReturns
    entropy: Host129EntropyServiceReturns
    counter_reads: Host129CounterReads | None

    def __post_init__(self):
        if type(self.clocks) is not Host129ClockServiceReturns or type(self.entropy) is not Host129EntropyServiceReturns:
            raise InputError('RAW3 requires typed clock and conditional entropy inputs')
        self.clocks.__post_init__()
        self.entropy.__post_init__()
        entropy_count = 0 if self.clocks.first and self.clocks.first != self.clocks.second else 2
        if len(self.entropy.values) != entropy_count:
            raise InputError('RAW3 entropy inputs differ from clock branch')
        persistent = entropy_count == 2 and (self.entropy.values[0] == 0 or self.entropy.values[0] == self.entropy.values[1])
        if persistent:
            if type(self.counter_reads) is not Host129CounterReads:
                raise InputError('RAW3 persistent branch requires four independent reads')
            self.counter_reads.__post_init__()
        elif self.counter_reads is not None:
            raise InputError('RAW3 nonpersistent branch requires absent counter reads')


@dataclass(frozen=True, repr=False)
class Host129RawInputs:
    groups: tuple[Host129RawGroup, ...]

    def __post_init__(self):
        if type(self.groups) is not tuple or len(self.groups) != 3 or any(type(g) is not Host129RawGroup for g in self.groups):
            raise InputError('RAW3 requires exactly three ordered groups')
        for group in self.groups:
            group.__post_init__()


class _Raw3Binding:
    def __init__(self, inputs, runtime):
        if type(inputs) is not Host129RawInputs:
            raise InputError('RAW3 requires Host129RawInputs')
        inputs.__post_init__()
        self._inputs = inputs
        self._runtime = runtime
        self._thread = get_ident()
        self._root = self._owner = self._main_vm = self._active = None
        self._index = 0
        self.closed = False
        self.completed = False

    def _check(self):
        runtime = self._runtime
        if (self.closed or get_ident() != self._thread or not runtime.primary_core or
                getattr(runtime, '_consumed_mgf', None) is not None or
                runtime._host129_source_clock_binding is not None or runtime._host129_multicall_binding is not None):
            raise InputError('RAW3 independent runtime owner is unavailable')
        if self._owner is not None and (runtime._active_main is not self._owner or
                self._owner['thread'] != self._thread or self._owner['generation'] != runtime._main_generation):
            raise InputError('RAW3 main generation owner is unavailable')

    def enter(self, name):
        if name not in ('main', 'host129'):
            return
        try:
            self._check()
            runtime = self._runtime
            stack = runtime._program_calls
            if name == 'main':
                if (self._root is not None or len(stack) != 1 or stack[0]['name'] != 'main' or
                        type(stack[0]['arguments']) is not tuple or len(stack[0]['arguments']) != 12 or
                        stack[0]['arguments'][0] != 4 or stack[0]['hosts'] is not None or
                        runtime._active_main is None or runtime._active_main['thread'] != self._thread or
                        any(getattr(runtime, key) is not None for key in _BINDINGS)):
                    raise InputError('RAW3 requires one independent normal main root')
                self._root, self._owner = stack[0], runtime._active_main
                return
            if (self._active is not None or self._index >= 3 or len(stack) != 2 or stack[0] is not self._root or
                    stack[-1]['arguments'] != () or stack[-1]['hosts'] is not None or
                    runtime._active_main is not self._owner or self._main_vm is None or
                    self._owner['vm'] is not self._main_vm or any(getattr(runtime, key) is not None for key in _BINDINGS)):
                raise InputError('RAW3 requires its ordered direct main child')
            from .primary_sign import load_program
            parent = self._main_vm
            word, destination = _SITES[self._index]
            typ = parent.program.type(129)
            if (parent.runtime is not runtime or parent.program.raw != load_program('main').raw or
                    parent.pc != word + 6 or parent.program.words[word:word + 6] !=
                    (0x014A3DB9, 129, 0, destination, 454, 0) or not parent.host_calls or
                    parent.host_calls[-1] != (word, runtime.image_base + 0x2DE577E, (), 129) or
                    parent.cells.value(454) != runtime.image_base + 0x2DE577E or typ.raw != 21 or
                    typ.parameters[0] != 0 or typ.parameters[2:] != (0,) or
                    parent.program.type(typ.parameters[1]).raw != 7 or parent.program.size(typ.parameters[1]) != 4):
                raise InputError('RAW3 actual main caller does not match ordered site')
            group = self._inputs.groups[self._index]
            bindings = ((_ZeroCounterBinding(runtime) if group.counter_reads is None else _CounterBinding(group.counter_reads, runtime)),
                        _ClockServiceBinding(group.clocks, runtime), _EntropyServiceBinding(group.entropy, runtime))
            for key, binding in zip(_BINDINGS, bindings):
                binding._root = self._root
                binding._root_used = True
                setattr(runtime, key, binding)
            self._active = bindings
        except BaseException:
            self.close()
            raise

    def attach_main(self, vm):
        try:
            self._check()
            from .primary_sign import load_program
            if (self._root is None or self._main_vm is not None or self._owner is not self._runtime._active_main or
                    self._owner['vm'] is not vm or vm.runtime is not self._runtime or vm.program.raw != load_program('main').raw):
                raise InputError('RAW3 main VM owner mismatch')
            self._main_vm = vm
        except BaseException:
            self.close()
            raise

    def complete(self, name):
        if name not in ('main', 'host129'):
            return
        self._check()
        if name == 'host129':
            if self._active is None or any(not binding.normal_completed for binding in self._active):
                raise InputError('RAW3 child did not exhaust all inputs')
            self._active = None
            self._index += 1
        elif (self._active is not None or self._index != 3 or self._main_vm is None or
                not self._main_vm.halted or self._runtime._active_main is not self._owner):
            raise InputError('RAW3 main did not finish all three groups')
        else:
            self.completed = True

    def close(self):
        if self._active is not None:
            for key, binding in zip(_BINDINGS, self._active):
                binding.close()
                if getattr(self._runtime, key) is binding:
                    setattr(self._runtime, key, None)
        self._active = self._inputs = self._root = self._owner = self._main_vm = None
        self.closed = True
