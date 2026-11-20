from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import get_ident

from .errors import InputError


_SOURCE = '63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'
_SITES = {
    ('singleton-init', 4): (12, 0x3E92E00, 30, (3, 4)),
    ('singleton-init', 32): (39, 0x35921EC, 34, (10,)),
    ('singleton-init', 163): (170, 0x359205B, 41, (35, 34)),
    ('buffer-init', 7): (13, 0x3592086, 8, ()),
    ('buffer-init', 35): (42, 0x3E97020, 10, (10,)),
    ('buffer-init', 69): (76, 0x35920C0, 14, (13, 19)),
    ('buffer-init', 76): (83, 0x3E97020, 10, (1,)),
    ('buffer-init', 344): (350, 0x3592129, 19, ()),
    ('buffer-init', 424): (430, 0x3592086, 8, ()),
    ('buffer-init', 526): (532, 0x3E94F90, 23, (21,)),
    ('buffer-init', 532): (538, 0x3E94F90, 23, (11,)),
}

_OTHER_SITES = {
    ('singleton-init', 146): (155, 0x3EB2680, 38, (31, 16, 34)),
    ('singleton-init', 170): (176, 0x3592191, 43, (5,)),
    ('singleton-init', 176): (183, 0x3592178, 45, (5, 40)),
    ('singleton-init', 1444): (1451, 0x3592178, 45, (5, 234)),
    ('buffer-init', 47): (56, 0x3EB2680, 12, (11, 16, 10)),
    ('buffer-init', 201): (210, 0x3EB1FE0, 17, (38, 31, 41)),
    ('buffer-init', 382): (391, 0x3EB1FE0, 17, (63, 60, 66)),
    ('buffer-init', 430): (438, 0x3592161, 21, (72, 4)),
}


def _uint(value, width):
    return type(value) is int and 0 <= value < 1 << width


@dataclass(frozen=True, repr=False)
class PendingLineageIdentity:
    source_sha256: str
    process_creation_identity: str
    module_load_generation: str
    native_thread_id: int
    constructor_call_id: str
    container_generation: str

    def __post_init__(self):
        if (self.source_sha256 != _SOURCE or not _uint(self.native_thread_id, 32) or not self.native_thread_id or
                any(type(value) is not str or not value for value in
                    (self.process_creation_identity, self.module_load_generation,
                     self.constructor_call_id, self.container_generation))):
            raise InputError('pending singleton lineage is incomplete or has another source')

    def finalize(self, selected_main_call_id):
        return ProducerIdentity(self.source_sha256, self.process_creation_identity,
                                self.module_load_generation, self.native_thread_id,
                                self.constructor_call_id, selected_main_call_id, self.container_generation)


@dataclass(frozen=True, repr=False)
class ProducerIdentity:
    source_sha256: str
    process_creation_identity: str
    module_load_generation: str
    native_thread_id: int
    constructor_call_id: str
    selected_main_call_id: str
    container_generation: str

    def __post_init__(self):
        if (self.source_sha256 != _SOURCE or not _uint(self.native_thread_id, 32) or
                not self.native_thread_id or any(type(value) is not str or not value for value in
                (self.process_creation_identity, self.module_load_generation, self.constructor_call_id,
                 self.selected_main_call_id, self.container_generation))):
            raise InputError('singleton producer identity is incomplete or has another source')


@dataclass(frozen=True, repr=False)
class ProducerSite:
    program: str
    word: int
    resume_pc: int
    callee_rva: int
    signature: int
    argument_cells: tuple
    occurrence: int
    native_call_id: str

    def __post_init__(self):
        expected = (_SITES.get((self.program, self.word))
                    if type(self.program) is str and type(self.word) is int else None)
        if (any(not _uint(value, 32) for value in
                (self.word, self.resume_pc, self.callee_rva, self.signature)) or
                type(self.program) is not str or
                expected != (self.resume_pc, self.callee_rva, self.signature, self.argument_cells) or
                type(self.argument_cells) is not tuple or any(not _uint(cell, 32) for cell in self.argument_cells) or not _uint(self.occurrence, 32) or
                not self.occurrence or type(self.native_call_id) is not str or not self.native_call_id):
            raise InputError('singleton producer site is outside the fixed source domain')


@dataclass(frozen=True, repr=False)
class ApiEffect:
    sequence: int
    site: ProducerSite
    api: str
    subcall: int
    output_role: str
    result: object
    data: bytes
    write_mask: bytes

    def __post_init__(self):
        width = {'GetSystemTimeAsFileTime': 8, 'QueryPerformanceFrequency': 8,
                 'QueryPerformanceCounter': 8, 'SystemFunction036': 4}.get(self.api) if type(self.api) is str else None
        if (width is None or type(self.data) is not bytes or len(self.data) != width or
                type(self.write_mask) is not bytes or len(self.write_mask) != width or
                any(bit not in (0, 1) for bit in self.write_mask) or
                not _uint(self.subcall, 32) or type(self.output_role) is not str or
                (self.api == 'GetSystemTimeAsFileTime' and self.result is not None) or
                (self.api != 'GetSystemTimeAsFileTime' and not _uint(self.result, 8 if width == 4 else 32))):
            raise InputError('singleton API effect has an invalid typed shape')


@dataclass(frozen=True, repr=False)
class AllocationEffect:
    sequence: int
    site: ProducerSite
    role: str
    requested_size: int
    zero: bool
    outcome: str = 'success'

    def __post_init__(self):
        if (self.role not in ('P', 'buffer-random', 'buffer-mix') or
                not _uint(self.requested_size, 64) or type(self.zero) is not bool or self.outcome != 'success'):
            raise InputError('singleton allocation effect requires source-normal success')


@dataclass(frozen=True, repr=False)
class FreeEffect:
    sequence: int
    site: ProducerSite
    role: str
    outcome: str = 'success'

    def __post_init__(self):
        if self.role not in ('buffer-random', 'buffer-mix') or self.outcome != 'success':
            raise InputError('singleton free effect requires source-normal scratch success')


def _boot_scope(value):
    return type(value) is tuple and len(value) == 2 and all(type(part) is str and part for part in value)


def _epoch(value):
    return type(value) is int and -(1 << 31) <= value <= -2


@dataclass(frozen=True, repr=False)
class SameBootQpfFact:
    boot_scope: tuple
    query_process_identity: str
    query_id: str
    result: int
    data: bytes
    write_mask: bytes
    origin: str = 'independent-same-boot-QPF'
    _claimed: bool = field(default=False, init=False, compare=False)

    def __post_init__(self):
        if (not _boot_scope(self.boot_scope) or self.origin != 'independent-same-boot-QPF' or
                any(type(value) is not str or not value for value in (self.query_process_identity, self.query_id)) or
                not _uint(self.result, 32) or not self.result or type(self.data) is not bytes or len(self.data) != 8 or
                type(self.write_mask) is not bytes or self.write_mask != bytes([1]) * 8 or
                not 0 < int.from_bytes(self.data, 'little') < 1 << 63):
            raise InputError('independent same-boot QPF fact requires successful full positive output')

    def __repr__(self):
        return '<SameBootQpfFact private independent source>'

    def _claim(self):
        if self._claimed:
            raise InputError('independent QPF fact is single use')
        object.__setattr__(self, '_claimed', True)
        data = self.data
        object.__setattr__(self, 'data', None)
        return bytearray(data)


@dataclass(frozen=True, repr=False)
class ConstructorClockBoundary:
    entry_sequence: int
    return_sequence: int
    tls_block: int
    tls_index: int
    guard_before: int
    guard_after: int
    tls_before: int
    tls_after: int
    epoch_before: int
    epoch_after: int
    header_claims: int
    footer_calls: int
    foreign_epoch_writes: int
    reentries: int
    producer_identity: ProducerIdentity

    def __post_init__(self):
        if (type(self.producer_identity) is not ProducerIdentity or not _uint(self.entry_sequence, 64) or not self.entry_sequence or
                not _uint(self.return_sequence, 64) or self.return_sequence <= self.entry_sequence or
                not _uint(self.tls_block, 64) or not 0 < self.tls_block < (1 << 64) - 0xAC or
                not _uint(self.tls_index, 32) or self.guard_before != 0 or
                any(type(value) is not int for value in (self.guard_before, self.header_claims, self.footer_calls,
                                                        self.foreign_epoch_writes, self.reentries)) or
                (self.header_claims, self.footer_calls, self.foreign_epoch_writes, self.reentries) != (1, 1, 0, 0) or
                not _epoch(self.epoch_before) or not _epoch(self.epoch_after) or
                self.epoch_after != self.epoch_before + 1 or not _epoch(self.tls_before) or
                self.tls_before > self.epoch_before or
                self.guard_after != self.epoch_after or self.tls_after != self.epoch_after):
            raise InputError('completed-clock constructor boundary is outside fresh normal source order')


@dataclass(frozen=True, repr=False)
class ClockIntervalWitness:
    entry_sequence: int
    return_sequence: int
    call_depth: int
    entry_count: int
    header_calls: int
    header_returns: int
    wait_count: int
    clock_initializer_claims: int
    reentries: int
    guard_writes: int
    frequency_writes: int
    foreign_tls_writes: int

    def __post_init__(self):
        if (not _uint(self.entry_sequence, 64) or not self.entry_sequence or
                not _uint(self.return_sequence, 64) or self.return_sequence <= self.entry_sequence or
                any(not _uint(getattr(self, name), 32) for name in
                    ('call_depth', 'entry_count', 'header_calls', 'header_returns', 'wait_count',
                     'clock_initializer_claims', 'reentries', 'guard_writes', 'frequency_writes', 'foreign_tls_writes')) or
                (self.call_depth, self.entry_count, self.wait_count, self.clock_initializer_claims,
                 self.reentries, self.guard_writes, self.frequency_writes, self.foreign_tls_writes) !=
                (1, 1, 0, 0, 0, 0, 0, 0) or
                self.header_calls not in (0, 1) or self.header_returns != self.header_calls):
            raise InputError('completed-clock interval lacks exclusive normal completed source admission')


@dataclass(frozen=True, repr=False)
class CompletedWarmClockWitness:
    site: ProducerSite
    native_clock_call_id: str
    local_lifetime_id: str
    native_local_address: int
    tls_block: int
    tls_index: int
    guard_before: int
    guard_after: int
    tls_before: int
    tls_after: int
    epoch_before: int
    epoch_after: int
    frequency_consumed: int
    qpc_effect_sequence: int
    interval: ClockIntervalWitness
    producer_identity: ProducerIdentity
    source_points: tuple = (0x759B38, 0x759B64, 0x759B70, 0x759BBA)

    def __post_init__(self):
        if (type(self.producer_identity) is not ProducerIdentity or type(self.site) is not ProducerSite or self.site.program != 'buffer-init' or
                self.site.word not in (7, 344, 424) or
                any(type(value) is not str or not value for value in (self.native_clock_call_id, self.local_lifetime_id)) or
                not _uint(self.native_local_address, 64) or not 0 < self.native_local_address <= (1 << 64) - 8 or
                not _uint(self.tls_block, 64) or not 0 < self.tls_block < (1 << 64) - 0xAC or
                not _uint(self.tls_index, 32) or type(self.interval) is not ClockIntervalWitness or
                self.source_points != (0x759B38, 0x759B64, 0x759B70, 0x759BBA) or
                not _epoch(self.guard_before) or self.guard_before == -(1 << 31) or
                self.guard_after != self.guard_before or
                any(not _epoch(value) for value in (self.tls_before, self.tls_after, self.epoch_before, self.epoch_after)) or
                self.guard_before > self.epoch_before or self.tls_before > self.epoch_before or
                self.epoch_after != self.epoch_before or
                self.tls_after != (self.epoch_before if self.guard_before > self.tls_before else self.tls_before) or
                self.interval.header_calls != int(self.guard_before > self.tls_before) or
                not _uint(self.frequency_consumed, 64) or not 0 < self.frequency_consumed < 1 << 63 or
                not _uint(self.qpc_effect_sequence, 32) or not self.qpc_effect_sequence):
            raise InputError('completed warm clock state/source/frequency relation is invalid')


class CompletedWarmClockDomain:
    def __init__(self, identity, native_boot_scope, fact, constructor, clocks, *, model_generation, native_image_base):
        expected = ((7, 1), (344, 1), (344, 2), (344, 3), (344, 4), (424, 1))
        if (type(identity) is not ProducerIdentity or not _boot_scope(native_boot_scope) or
                type(fact) is not SameBootQpfFact or fact.boot_scope != native_boot_scope or
                fact.query_process_identity == identity.process_creation_identity or
                type(constructor) is not ConstructorClockBoundary or constructor.producer_identity != identity or type(clocks) is not tuple or len(clocks) != 6 or
                any(type(w) is not CompletedWarmClockWitness for w in clocks) or
                tuple((w.site.word, w.site.occurrence) for w in clocks) != expected or
                not _uint(model_generation, 64) or not _uint(native_image_base, 64) or
                not 0 < native_image_base < (1 << 64) - 0x6D88CCC):
            raise InputError('completed warm clock domain identity/same-boot/source scope is invalid')
        previous_sequence, previous_tls = constructor.entry_sequence, constructor.tls_before
        call_ids, locals_seen = set(), set()
        for witness in clocks:
            if (witness.producer_identity != identity or witness.site.native_call_id != identity.constructor_call_id + '/buffer-init' or
                    witness.native_clock_call_id in call_ids or witness.local_lifetime_id in locals_seen or
                    witness.native_clock_call_id in (fact.query_id, identity.constructor_call_id) or
                    (witness.tls_block, witness.tls_index) != (constructor.tls_block, constructor.tls_index) or
                    witness.tls_before != previous_tls or witness.epoch_before != constructor.epoch_before or
                    witness.interval.entry_sequence <= previous_sequence or
                    witness.interval.return_sequence >= constructor.return_sequence or
                    witness.qpc_effect_sequence <= (clocks[len(call_ids) - 1].qpc_effect_sequence if call_ids else 0) or
                    witness.native_local_address < constructor.tls_block + 0xAC and
                    constructor.tls_block + 0xA8 < witness.native_local_address + 8 or
                    any(witness.native_local_address < native_image_base + rva + width and
                        native_image_base + rva < witness.native_local_address + 8 for rva, width in
                        ((0x674D440, 8), (0x674D448, 4), (0x5EA1C80, 4), (0x6D88CC8, 4)))):
                raise InputError('completed warm clock witness lifetime/lineage order is invalid')
            call_ids.add(witness.native_clock_call_id)
            locals_seen.add(witness.local_lifetime_id)
            previous_sequence, previous_tls = witness.interval.return_sequence, witness.tls_after
        self._identity, self._fact, self._constructor, self._clocks = identity, fact, constructor, clocks
        self.model_generation = model_generation
        self.native_image_base = native_image_base
        self._claimed = False

    def __repr__(self):
        return '<CompletedWarmClockDomain private producer-only>'

    def _claim(self, identity):
        if self._claimed:
            raise InputError('completed warm clock domain is single use')
        self._claimed = True
        if identity != self._identity:
            raise InputError('completed warm clock domain belongs to another producer identity')
        result = self._fact._claim(), self._constructor, self._clocks, self._fact.query_id, self._fact.result
        self._identity = self._fact = self._constructor = self._clocks = None
        return result


class _CompletedWarmClockBinding:
    def __init__(self, domain, producer):
        if type(domain) is not CompletedWarmClockDomain:
            raise InputError('singleton clock domain must be explicitly typed')
        self._data, self._boundary, self._clocks, self._query_id, self._qpf_result = domain._claim(producer._identity)
        self._generation = domain.model_generation
        self._producer = producer
        self._index = 0
        self._clock = None
        self._model_local = None
        self._epoch_start = None
        self.independent_qpf_consumptions = self.native_qpc_consumptions = 0
        self.closed = self.complete = False

    def enter_root(self):
        runtime = self._producer._runtime
        epoch = runtime.memory.load(runtime.image_base + 0x5EA1C80, 4, signed=True)
        tls = runtime.memory.load(runtime.tls_epoch_address, 4, signed=True)
        if (self.closed or runtime._main_generation != self._generation or not _epoch(epoch) or epoch > -4 or
                not _epoch(tls) or tls > epoch):
            raise InputError('completed clock model needs its own legal cold epoch/TLS order')
        self._epoch_start = epoch

    def _actual(self):
        from .primary_sign import load_program
        owner = self._producer
        runtime = owner._runtime
        context = owner._context
        if (self.closed or not owner.active or get_ident() != owner._thread or context is None or
                runtime._main_generation != self._generation or
                runtime._active_main is not None and
                (runtime._active_main['generation'] != self._generation or runtime._active_main['thread'] != get_ident())):
            raise InputError('completed clock lacks actual producer thread/generation')
        vm, site, record, call = context
        if (vm.runtime is not runtime or record is not vm.host_calls[-1] or vm.pc != site.resume_pc or
                call is not runtime._program_calls[-1] or vm.program != load_program(site.program) or
                not owner._root or len(runtime._program_calls) < 2 or runtime._program_calls[-2] is not owner._root):
            raise InputError('completed clock lacks actual nested VM/record/caller lifetime')
        return context

    @contextmanager
    def clock(self, address):
        context = self._actual()
        if self._clock is not None or self._index >= len(self._clocks):
            raise InputError('completed clock witness exhausted or reentered')
        witness = self._clocks[self._index]
        if context[1] != witness.site:
            raise InputError('completed clock source occurrence differs from actual caller')
        frequency = int.from_bytes(self._data, 'little')
        if witness.frequency_consumed != frequency:
            raise InputError('native consumed frequency differs from independent model source')
        self._clock, self._model_local = witness, address
        before = self.native_qpc_consumptions
        try:
            yield
            if self._actual() is not context or self.native_qpc_consumptions != before + 1:
                raise InputError('completed clock QPC/context was not exactly consumed')
            runtime = self._producer._runtime
            if (runtime.memory.load(runtime.image_base + 0x674D440, 8) != witness.frequency_consumed or
                    runtime.memory.load(runtime.image_base + 0x674D448, 4, signed=True) != self._epoch_start + 1 or
                    runtime.memory.load(runtime.image_base + 0x5EA1C80, 4, signed=True) != self._epoch_start + 1):
                raise InputError('model clock frequency/guard did not follow its own source initialization')
            self._index += 1
        finally:
            self._clock = self._model_local = None

    def independent_frequency(self, destination):
        self._actual()
        runtime = self._producer._runtime
        if (self._clock is None or destination != self._model_local or self.independent_qpf_consumptions or
                runtime.memory.load(runtime.image_base + 0x674D448, 4, signed=True) != -1):
            raise InputError('independent QPF fact requires actual first cold source initialization')
        runtime.memory.write(destination, bytes(self._data), source='singleton.clock.independent_qpf_fact')
        self.independent_qpf_consumptions += 1
        runtime.events.append(('IndependentSameBootQPF.consume', self._query_id))
        return self._qpf_result

    def validate_qpc(self, event, destination, data, mask):
        self._actual()
        if (self._clock is None or destination != self._model_local or
                event.sequence != self._clock.qpc_effect_sequence or event.api != 'QueryPerformanceCounter' or
                not event.result or len(data) != 8 or bytes(mask) != bytes([1]) * 8):
            raise InputError('completed warm clock requires the actual successful fully written QPC event')
        self.native_qpc_consumptions += 1

    def finish_root(self):
        runtime = self._producer._runtime
        epoch = self._epoch_start + 2
        if (self._index != 6 or self._clock is not None or self.independent_qpf_consumptions != 1 or
                self.native_qpc_consumptions != 6 or
                runtime.memory.load(runtime.image_base + 0x5EA1C80, 4, signed=True) != epoch or
                runtime.memory.load(runtime.tls_epoch_address, 4, signed=True) != epoch or
                runtime.memory.load(runtime.image_base + 0x6D88CC8, 4, signed=True) != epoch):
            raise InputError('completed clock producer did not finish natural model footer/order')
        self.complete = True

    def close(self):
        if self.closed:
            return
        self.closed = True
        self._data[:] = bytes(len(self._data))
        self._data.clear()
        self._boundary = self._clocks = self._query_id = self._clock = self._model_local = None


class SingletonProducerInputs:
    def __init__(self, identity, events, *, completed_warm_clock_domain=None):
        if (type(identity) is not ProducerIdentity or type(events) is not tuple or
                not 0 < len(events) <= 64 or any(type(e) not in (ApiEffect, AllocationEffect, FreeEffect) for e in events) or
                any(type(e.site) is not ProducerSite or type(e.sequence) is not int or e.sequence != i
                    for i, e in enumerate(events, 1)) or
                sum(len(e.data) for e in events if type(e) is ApiEffect) > 4096):
            raise InputError('singleton producer tape identity/order/budget is invalid')
        if completed_warm_clock_domain is not None and type(completed_warm_clock_domain) is not CompletedWarmClockDomain:
            raise InputError('singleton clock domain must be explicitly typed')
        self._clock_domain = completed_warm_clock_domain
        self._identity = identity
        self._events = events
        self._claimed = False

    def __repr__(self):
        return '<SingletonProducerInputs private>'

    def _claim(self):
        if self._claimed:
            raise InputError('singleton producer tape is single use')
        self._claimed = True
        identity, events, domain = self._identity, self._events, self._clock_domain
        self._identity = self._events = self._clock_domain = None
        return identity, events, domain


class _ProducerBinding:
    def __init__(self, inputs, runtime):
        if type(inputs) is not SingletonProducerInputs:
            raise InputError('singleton producer inputs require a typed private tape')
        self._identity, events, clock_domain = inputs._claim()
        self._clock_domain = None if clock_domain is None else _CompletedWarmClockBinding(clock_domain, self)
        self._events = [(e, bytearray(e.data), bytearray(e.write_mask)) if type(e) is ApiEffect else (e, None, None)
                        for e in events]
        self._runtime = runtime
        self._thread = get_ident()
        self._index = 0
        self._used = False
        self.active = False
        self._root = None
        self._vms = {}
        self._context = None
        self._dispatch = None
        self._registrar = False
        self._occurrences = {}
        self._roles = {}
        self._freed = set()
        self._records = set()
        self.closed = False
        self.complete = False
        self._prefix = ()
        self._container = None
        self._guard = None

    @contextmanager
    def root(self):
        runtime = self._runtime
        if (self._used or get_ident() != self._thread or
                runtime._program_calls and runtime._execute_thread != self._thread):
            self.close()
            raise InputError('singleton producer root owner mismatch')
        self._used = True
        self._prefix = tuple(runtime._program_calls)
        try:
            m, b = runtime.memory, runtime.image_base
            if (m.load(b + 0x6D88CC0, 8) != 0 or m.load(b + 0x6D88CC8, 4) != 0 or
                    m.load(b + 0x674D448, 4) != 0 or m.load(b + 0x674D440, 8) != 0 or
                    m.load(runtime.tls_epoch_address, 4, signed=True) >= 0):
                raise InputError('singleton producer v1 requires fresh constructor and cold clock provenance')
            if self._clock_domain is not None:
                self._clock_domain.enter_root()
            self.active = True
            yield
            if self._index != len(self._events) or self._freed != {'buffer-random', 'buffer-mix'}:
                raise InputError('singleton producer tape was not exactly consumed')
            self._container = self._roles['P'][0]
            self._guard = m.load(b + 0x6D88CC8, 4)
            if m.load(b + 0x6D88CC0, 8) != self._container or self._guard in (0, 0xFFFFFFFF):
                raise InputError('singleton producer final publication mismatch')
            if self._clock_domain is not None:
                self._clock_domain.finish_root()
            self.complete = True
        finally:
            self.close()

    def warm(self):
        runtime = self._runtime
        if (not self.complete or get_ident() != self._thread or
                runtime.memory.load(runtime.image_base + 0x6D88CC0, 8) != self._container or
                runtime.memory.load(runtime.image_base + 0x6D88CC8, 4) != self._guard):
            raise InputError('singleton producer completed lifetime cannot be reused for another constructor')
        return runtime._singleton()

    @contextmanager
    def program(self, name):
        runtime = self._runtime
        if not self.active:
            if name in ('singleton-init', 'buffer-init'):
                self.close()
                raise InputError('singleton producer requires natural singleton root')
            yield
            return
        call = runtime._program_calls[-1]
        if name == 'singleton-init':
            if (self._root is not None or call['arguments'] != () or
                    len(runtime._program_calls) != len(self._prefix) + 1 or
                    any(actual is not previous for actual, previous in zip(runtime._program_calls, self._prefix))):
                raise InputError('singleton producer constructor call mismatch')
            self._root = call
        elif (name != 'buffer-init' or len(runtime._program_calls) < 2 or
                runtime._program_calls[-2] is not self._root or self._context is None or
                self._context[1].word != 163 or self._context[1].program != 'singleton-init' or
                call['arguments'][1:] != (16,) or 'buffer-init' in [row[0] for row in self._vms.values()]):
            raise InputError('singleton producer nested call mismatch')
        yield

    def register_vm(self, vm, name):
        if self.active:
            from .primary_sign import load_program
            if vm.program != load_program(name) or vm.runtime is not self._runtime:
                raise InputError('singleton producer source identity mismatch')
            self._vms[id(vm)] = (name, vm, self._runtime._program_calls[-1])

    @contextmanager
    def host(self, vm, address, cells, signature):
        if not self.active:
            yield
            return
        row = self._vms.get(id(vm))
        if (get_ident() != self._thread or row is None or row[1] is not vm or
                vm.runtime is not self._runtime or row[2] is not self._runtime._program_calls[-1] or
                not vm.host_calls):
            raise InputError('singleton producer actual VM owner mismatch')
        record = vm.host_calls[-1]
        word, actual_address, actual_cells, actual_signature = record
        if (actual_address, actual_cells, actual_signature) != (address, cells, signature):
            raise InputError('singleton producer actual host record mismatch')
        all_expected = (_SITES | _OTHER_SITES).get((row[0], word))
        if all_expected != (vm.pc, address - vm.image_base, signature, cells):
            raise InputError('singleton producer actual source host ABI mismatch')
        previous, dispatch = self._context, self._dispatch
        self._dispatch = (vm, record, vm.pc, row[2])
        expected = _SITES.get((row[0], word))
        if expected is None:
            self._context = None
        else:
            if expected != (vm.pc, address - vm.image_base, signature, cells) or id(record) in self._records:
                raise InputError('singleton producer host site/repeated record mismatch')
            self._records.add(id(record))
            key = (id(vm), word)
            count = self._occurrences.get(key, 0) + 1
            self._occurrences[key] = count
            call_id = self._identity.constructor_call_id + ('/buffer-init' if row[0] == 'buffer-init' else '')
            site = ProducerSite(row[0], word, vm.pc, address - vm.image_base, signature, cells, count, call_id)
            self._context = (vm, site, record, row[2])
        try:
            yield
        finally:
            self._context, self._dispatch = previous, dispatch

    @contextmanager
    def exit_scope(self):
        runtime = self._runtime
        completed = [row for row in self._vms.values() if row[0] == 'singleton-init']
        if (not self.active or get_ident() != self._thread or self._registrar or
                len(completed) != 1 or not completed[0][1].halted or self._dispatch is not None or
                runtime.memory.load(runtime.image_base + 0x6D88CC0, 8) != self._roles['P'][0] or
                len(runtime._program_calls) != len(self._prefix) or
                any(actual is not previous for actual, previous in zip(runtime._program_calls, self._prefix))):
            raise InputError('singleton producer exit registrar lacks completed constructor')
        self._registrar = True
        try:
            yield
        finally:
            self._registrar = False

    def validate_dispatch(self, vm, rva, cells):
        if self.active:
            if (self._registrar and get_ident() == self._thread and rva == 0x3E680B4 and cells == (0,) and
                    vm.cells.value(0) == self._runtime.image_base + 0x35922FD):
                return
            dispatch = self._dispatch
            if (get_ident() != self._thread or dispatch is None or dispatch[0] is not vm or
                    vm.runtime is not self._runtime or not vm.host_calls or
                    dispatch[1] is not vm.host_calls[-1] or dispatch[2] != vm.pc or
                    dispatch[3] is not self._runtime._program_calls[-1] or
                    dispatch[1][1:] != (self._runtime.image_base + rva, cells, dispatch[1][3])):
                raise InputError('singleton producer dispatch lacks authentic host scope')

    def _consume(self, kind):
        from .primary_sign import load_program
        if (not self.active or self.closed or get_ident() != self._thread or self._context is None or
                self._index >= len(self._events)):
            raise InputError('singleton producer effect lifetime/exhaustion mismatch')
        vm, site, record, call = self._context
        if (record is not vm.host_calls[-1] or vm.pc != site.resume_pc or
                call is not self._runtime._program_calls[-1] or vm.runtime is not self._runtime or
                vm.program != load_program(site.program)):
            raise InputError('singleton producer stale effect context')
        event, data, mask = self._events[self._index]
        if type(event) is not kind or event.site != site:
            raise InputError('singleton producer effect order/site mismatch')
        self._index += 1
        return event, data, mask

    def api(self, name, address, role, subcall=0):
        event, data, mask = self._consume(ApiEffect)
        if self._clock_domain is not None and name == 'QueryPerformanceCounter':
            self._clock_domain.validate_qpc(event, address, data, mask)
        if (event.api, event.output_role, event.subcall) != (name, role, subcall):
            raise InputError('singleton producer API role/subcall mismatch')
        for i, bit in enumerate(mask):
            if bit:
                self._runtime.memory.write(address + i, bytes(data[i:i + 1]), source='singleton.producer.raw_effect')
        return event.result

    @contextmanager
    def local(self, size, zero=False):
        runtime = self._runtime
        actual, pointer, initial = runtime._next(runtime._temporaries, 'singleton API local', size)
        if actual != size or not _uint(pointer, 64) or not pointer or pointer + size > 1 << 64 or initial is not None:
            raise InputError('singleton API local requires fresh role storage')
        runtime.memory.map(pointer, bytearray(size), name='singleton API local', initialized=zero)
        region = next(r for r in runtime.memory._regions if r.address == pointer)
        try:
            yield pointer
        finally:
            from .primary_sign_lifecycle import cleanup
            region.data[:] = bytes(size)
            cleanup(runtime, [(pointer, region)])

    def allocate(self, size, zero):
        event, _, _ = self._consume(AllocationEffect)
        expected_role = {('singleton-init', 4): 'P', ('buffer-init', 35): 'buffer-random',
                         ('buffer-init', 76): 'buffer-mix'}.get((event.site.program, event.site.word))
        if event.role != expected_role or event.role in self._roles or (event.requested_size, event.zero) != (size, zero):
            raise InputError('singleton producer allocation role/shape mismatch')
        return event.role

    def allocated(self, role, pointer):
        runtime = self._runtime
        region = next(r for r in runtime.memory._regions if r.address == pointer)
        self._roles[role] = (pointer, region)

    def free(self, pointer):
        event, _, _ = self._consume(FreeEffect)
        expected_role = {526: 'buffer-mix', 532: 'buffer-random'}.get(event.site.word)
        if (event.role != expected_role or event.role in self._freed or event.role not in self._roles or
                self._roles[event.role][0] != pointer):
            raise InputError('singleton producer free role mismatch')
        return event.role

    def freed(self, role):
        self._freed.add(role)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.active = False
        if self._clock_domain is not None:
            self._clock_domain.close()
        from .primary_sign_lifecycle import cleanup
        scratch = [(pointer, region) for role, (pointer, region) in self._roles.items()
                   if role != 'P' and role not in self._freed]
        try:
            cleanup(self._runtime, [], scratch)
        finally:
            for event, data, mask in self._events:
                if data is not None:
                    data[:] = bytes(len(data))
                    mask[:] = bytes(len(mask))
            self._events.clear()
            self._identity = self._root = self._context = self._dispatch = None
            self._vms.clear()
            self._roles.clear()
            self._records.clear()
            self._occurrences.clear()
            self._prefix = ()
