from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_consumed_mgf import SOURCE_SHA256, SourceIdentity


_MAIN_SHA256 = '28afc919ac1b8783ecbe6ddea52ebba5ea41492573609fa7cf634467ecaa00b9'
_SITES = {
    1160: (1168, 125, 288, 0x2DE561F, (102, 279), (0x014A3DB9, 125, 0, 287, 288, 0, 102, 279)),
    34861: (34869, 125, 288, 0x2DE561F, (102, 216), (0x014A3DB9, 125, 0, 4725, 288, 0, 102, 216)),
    64832: (64838, 135, 8649, 0x3592430, (), (0x014A3DB9, 135, 0, 8648, 8649, 0)),
    65472: (65478, 135, 8649, 0x3592430, (), (0x014A3DB9, 135, 0, 8733, 8649, 0)),
}


def _fail():
    raise InputError('MAIN_CLOCK_INPUT_MISMATCH')


@dataclass(frozen=True, repr=False)
class MainClockReturnEvent:
    site_word: int
    value_u64: int

    def __post_init__(self):
        if (type(self.site_word) is not int or self.site_word not in _SITES or
                type(self.value_u64) is not int or not 0 <= self.value_u64 < 1 << 64):
            _fail()


@dataclass(frozen=True, repr=False)
class MainClockInvocationInputs:
    source_identity: SourceIdentity
    process_creation_identity: str
    module_load_generation: str
    native_thread_id: int
    reader_invocation: int
    events: tuple[MainClockReturnEvent, ...]
    _claimed: bool = field(default=False, init=False, compare=False)

    def __post_init__(self):
        identity = self.source_identity
        if (type(identity) is not SourceIdentity or identity.wrapper_sha256 != SOURCE_SHA256 or
                any(type(value) is not str or not value for value in
                    (self.process_creation_identity, self.module_load_generation)) or
                any(type(value) is not int or not 0 < value < 1 << 32 for value in
                    (self.native_thread_id, self.reader_invocation)) or
                type(self.events) is not tuple or any(type(value) is not MainClockReturnEvent for value in self.events)):
            _fail()
        policy = identity.main_arguments[9]
        if (policy == 2 and tuple(value.site_word for value in self.events) != tuple(_SITES) or
                policy == 3 and self.events or policy not in (2, 3)):
            _fail()


class _MainClockReturnBinding:
    def __init__(self, rows, runtime, *, _prefix_owner=None):
        generation_start = 1
        if _prefix_owner is not None:
            from .primary_main_prefix_stop import _PrefixOwner
            if (type(_prefix_owner) is not _PrefixOwner or _prefix_owner.runtime is not runtime or
                    runtime.__dict__.get('_main_prefix9563_retired') is not _prefix_owner or
                    _prefix_owner.state != 'retired' or runtime._active_failed or
                    _prefix_owner.clock is not runtime._main_clock_binding or not _prefix_owner.clock.closed):
                _fail()
            generation_start = runtime._main_generation + 1
        if (type(rows) is not tuple or not 1 <= len(rows) <= 8 or
                any(type(row) is not MainClockInvocationInputs or row._claimed or
                    row.source_identity.generation != index + generation_start for index, row in enumerate(rows))):
            _fail()
        first = rows[0]
        lineage = (first.process_creation_identity, first.module_load_generation, first.native_thread_id,
                   first.source_identity.image_base)
        if (len({row.source_identity.candidate for row in rows}) != len(rows) or
                any((row.process_creation_identity, row.module_load_generation, row.native_thread_id,
                     row.source_identity.image_base) != lineage for row in rows)):
            _fail()
        self._rows = rows
        self._runtime = runtime
        self._thread = get_ident()
        self._row_index = self._event_index = 0
        self._row = self._call = self._vm = self._generation = None
        self._reading = False
        self.closed = self.finished = False

    def close(self):
        self.closed = True
        for row in self._rows:
            object.__setattr__(row, '_claimed', True)
        self._rows = ()
        self._row = self._call = self._vm = self._generation = None
        self._reading = False

    @contextmanager
    def scope(self, arguments, hosts):
        runtime = self._runtime
        try:
            owner = runtime._active_main
            stack = runtime._program_calls
            if (self.closed or self.finished or get_ident() != self._thread or runtime._active_failed or
                    self._row is not None or self._row_index >= len(self._rows) or owner is None or
                    len(stack) != 1 or stack[0]['name'] != 'main' or hosts is not None):
                _fail()
            row = self._rows[self._row_index]
            replay = getattr(runtime, '_consumed_mgf', None)
            if (row._claimed or arguments != row.source_identity.main_arguments or
                    runtime.image_base != row.source_identity.image_base or
                    owner['generation'] != row.source_identity.generation or
                    replay is not None and replay._identity != row.source_identity):
                _fail()
            object.__setattr__(row, '_claimed', True)
            self._row, self._call, self._generation = row, stack[0], owner['generation']
            self._event_index = 0
            yield
            prefix = getattr(self, '_prefix_witness', None)
            if prefix is not None:
                from .primary_main_prefix_stop import _require_witness
                owner9563 = _require_witness(runtime, self._vm, prefix)
                if owner9563.state != 'finalized':
                    _fail()
            if (self.closed or self._reading or self._vm is None or
                    (prefix is None and (not self._vm.halted or self._event_index != len(row.events))) or
                    get_ident() != self._thread or
                    runtime._active_main is not owner or owner['vm'] is not self._vm or
                    owner['generation'] != self._generation or runtime._main_generation != self._generation or
                    runtime._execute_thread != self._thread or len(runtime._program_calls) != 1 or
                    runtime._program_calls[0] is not self._call):
                _fail()
            if prefix is None:
                self._row_index += 1
        except BaseException:
            self.close()
            raise
        finally:
            self._row = self._call = self._vm = self._generation = None
            self._reading = False

    def complete_prefix9563(self, vm, witness):
        from .primary_main_prefix_stop import _require_witness
        _require_witness(self._runtime, vm, witness)
        if (self.closed or self.finished or self._reading or self._vm is not vm or self._row is None or
                self._event_index != 1 or self._row.events[0].site_word != 1160 or
                any(event.site_word <= 9563 for event in self._row.events[self._event_index:]) or
                getattr(self, '_prefix_witness', None) is not None):
            _fail()
        self._prefix_witness = witness
        self.prefix_completed = True

    def attach_vm(self, vm):
        if (self.closed or self._row is None or self._vm is not None or
                vm.runtime is not self._runtime or get_ident() != self._thread or
                sha256(vm.program.raw).hexdigest() != _MAIN_SHA256):
            self.close()
            _fail()
        self._vm = vm

    def is_main(self, vm):
        return vm is self._vm or sha256(vm.program.raw).hexdigest() == _MAIN_SHA256

    def read(self, vm, rva, cells, argument_types):
        runtime = self._runtime
        try:
            owner = runtime._active_main
            stack = runtime._program_calls
            if (self.closed or self._row is None or self._reading or vm is not self._vm or
                    vm.runtime is not runtime or get_ident() != self._thread or owner is None or
                    owner['vm'] is not vm or owner['thread'] != self._thread or
                    owner['generation'] != self._generation or runtime._main_generation != self._generation or
                    runtime._execute_thread != self._thread or len(stack) != 1 or stack[0] is not self._call or
                    stack[0]['hosts'] is not None or stack[0]['arguments'] != self._row.source_identity.main_arguments or
                    self._event_index >= len(self._row.events) or rva != 0x3592430 or
                    cells != () or argument_types not in (None, ()) or
                    sha256(vm.program.raw).hexdigest() != _MAIN_SHA256):
                _fail()
            self._reading = True
            event = self._row.events[self._event_index]
            word = event.site_word
            pc, signature, cell, callee, arguments, words = _SITES[word]
            if (vm.pc != pc or tuple(vm.program.words[word:pc]) != words or not vm.host_calls or
                    vm.host_calls[-1] != (word, runtime.image_base + callee, arguments, signature) or
                    vm.cells.value(cell) != runtime.image_base + callee or
                    vm.program.type(125).parameters != (0, 98, 2, 8, 98) or
                    vm.program.type(135).parameters != (0, 7, 0) or
                    vm.program.type(7).raw != 7 or vm.program.size(7) != 8):
                _fail()
            self._event_index += 1
            return event.value_u64
        except BaseException:
            self.close()
            raise
        finally:
            self._reading = False

    def finish(self):
        if (self.closed or self.finished or get_ident() != self._thread or self._runtime._active_failed or
                self._row is not None or self._reading or self._row_index != len(self._rows) or
                self._runtime._active_main is not None or self._runtime._program_calls or
                self._runtime._execute_thread is not None):
            self.close()
            _fail()
        self.finished = True
        self._rows = ()
