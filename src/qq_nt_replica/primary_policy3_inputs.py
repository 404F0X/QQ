from contextlib import contextmanager
from dataclasses import dataclass
from threading import get_ident

from .errors import InputError
from .primary_singleton_inputs import PendingLineageIdentity


_SITES = {
    45: (52, 0x2DE4E0D, 24, (8,)),
    132: (141, 0x2DE4C3B, 26, (25, 17, 42, 9)),
    148: (157, 0x2DE4C3B, 26, (45, 17, 46, 9)),
    164: (173, 0x2DE4C3B, 26, (45, 46, 48, 9)),
    529: (537, 0x2DE4EB1, 33, (21, 120, 119)),
    852: (860, 0x35A261F, 39, (5, 171, 168)),
}

_HOST_SITES = {
    27: (36, 0x3EB2680, 22, (14, 17, 18), 16, 15),
    45: (*_SITES[45], 22, 21),
    132: (*_SITES[132], 41, None),
    141: (148, 0x2DE50F8, 28, (9,), 44, 43),
    148: (*_SITES[148], 41, None),
    157: (164, 0x2DE50F8, 28, (9,), 44, 47),
    164: (*_SITES[164], 41, None),
    173: (180, 0x2DE50F8, 28, (9,), 44, 49),
    463: (471, 0x2DE6AA0, 30, (108, 50, 57), 110, None),
    495: (503, 0x2DE6AA0, 30, (115, 1, 114), 110, None),
    508: (517, 0x3EB2680, 22, (117, 17, 24), 16, 118),
    529: (*_SITES[529], 121, None),
    542: (550, 0x2DE6AA0, 30, (107, 122, 24), 110, None),
    550: (558, 0x2DE6AA0, 30, (5, 122, 24), 110, None),
    602: (609, 0x35A20F0, 35, (12, 107), 131, None),
    636: (646, 0x35A211B, 37, (12, 135, 134, 133, 137), 136, None),
    653: (661, 0x2DE6AA0, 30, (138, 133, 51), 110, None),
    852: (*_SITES[852], 170, None),
}


def _fail():
    raise InputError('POLICY3_INPUT_DOMAIN_UNKNOWN')


@dataclass(frozen=True, repr=False)
class Policy3Site:
    word: int
    resume_pc: int
    callee_rva: int
    signature: int
    argument_cells: tuple
    occurrence: int = 1

    def __post_init__(self):
        if (type(self.word) is not int or _SITES.get(self.word) !=
                (self.resume_pc, self.callee_rva, self.signature, self.argument_cells) or
                type(self.occurrence) is not int or self.occurrence != 1):
            _fail()


@dataclass(frozen=True, repr=False)
class Policy3FreshWitness:
    lineage: PendingLineageIdentity
    native_tls_block: int
    native_tls_mt_flags: int
    native_tls_mt_pointer: int
    random_device_once: int
    random_device_slot: int
    random_device_guard: int
    exclusive_entry_sequence: int
    exclusive_return_sequence: int
    foreign_writes: int
    concurrent_entries: int

    def __post_init__(self):
        if (type(self.lineage) is not PendingLineageIdentity or
                any(type(value) is not int or not 0 <= value < 1 << 64 for value in
                    (self.native_tls_block, self.native_tls_mt_flags, self.native_tls_mt_pointer,
                     self.exclusive_entry_sequence, self.exclusive_return_sequence)) or
                not self.native_tls_block or self.native_tls_mt_flags & 1 or
                not 0 < self.exclusive_entry_sequence < self.exclusive_return_sequence or
                any(type(value) is not int or value != 0 for value in
                    (self.random_device_once, self.random_device_slot, self.random_device_guard,
                     self.foreign_writes, self.concurrent_entries))):
            _fail()


@dataclass(frozen=True, repr=False)
class Policy3Effect:
    sequence: int
    site: Policy3Site
    kind: str
    local_identity: str
    native_address: int
    arguments: tuple
    initial_bytes: bytes
    initial_knownmask: bytes
    return_value: object
    output_bytes: bytes
    write_mask: bytes

    def __post_init__(self):
        if (type(self.sequence) is not int or not 1 <= self.sequence <= 64 or type(self.site) is not Policy3Site or
                self.kind not in ('clock-local', 'QueryPerformanceFrequency', 'QueryPerformanceCounter',
                                  'GetSystemTimePreciseAsFileTime', 'GetSystemTimeAsFileTime',
                                  'SystemFunction036', 'allocate', 'exit-registration', 'temporary') or
                type(self.local_identity) is not str or not self.local_identity or
                type(self.native_address) is not int or not 0 < self.native_address < 1 << 64 or
                type(self.arguments) is not tuple or any(type(value) is not int or not 0 <= value < 1 << 64 for value in self.arguments) or
                any(type(value) is not bytes for value in
                    (self.initial_bytes, self.initial_knownmask, self.output_bytes, self.write_mask)) or
                len(self.initial_bytes) != len(self.initial_knownmask) or
                len(self.output_bytes) != len(self.write_mask) or
                any(value not in (0, 1) for value in self.initial_knownmask + self.write_mask) or
                len(self.initial_bytes) > 100 or len(self.output_bytes) > 8):
            _fail()


@dataclass(frozen=True, repr=False)
class Policy3ThreadExitRegistration:
    lineage: PendingLineageIdentity
    native_call_id: str
    root_ordinal: int
    call_rva: int
    resume_rva: int
    tls_index: int
    native_tls_block: int
    native_image_base: int
    head_before: int
    head_knownmask: bytes
    callback_rva: int
    return_value: int
    ordered_writes: tuple
    registration_entries: int
    other_registry_accesses: int
    exits: int
    callback_calls: int

    def __post_init__(self):
        if (type(self.lineage) is not PendingLineageIdentity or type(self.native_call_id) is not str or not self.native_call_id or
                type(self.root_ordinal) is not int or self.root_ordinal != 0 or
                (self.call_rva, self.resume_rva, self.callback_rva) != (0x2DE5070, 0x2DE5075, 0x2DE507A) or
                any(type(value) is not int or not 0 <= value < 1 << 32 for value in (self.tls_index,)) or
                any(type(value) is not int or not 0 < value < (1 << 64) - 0xD78 for value in
                    (self.native_tls_block, self.native_image_base)) or
                type(self.head_before) is not int or self.head_before != 0 or
                type(self.head_knownmask) is not bytes or self.head_knownmask != bytes([1]) * 8 or
                type(self.return_value) is not int or self.return_value != 0 or
                type(self.ordered_writes) is not tuple or
                any(type(item) is not tuple or len(item) != 3 or any(type(value) is not int for value in item)
                    for item in self.ordered_writes) or
                type(self.ordered_writes) is not tuple or self.ordered_writes !=
                    ((0xB0, 8, self.native_tls_block + 0xC0), (0xC0, 4, 0),
                     (0xD0, 8, self.native_image_base + 0x2DE507A), (0xC0, 4, 1)) or
                type(self.registration_entries) is not int or self.registration_entries != 1 or
                any(type(value) is not int or value != 0 for value in
                    (self.other_registry_accesses, self.exits, self.callback_calls))):
            _fail()


class Policy3RootInputs:
    def __init__(self, lineage, native_call_id, root_ordinal, fresh_domain_witness, effects,
                 *, thread_exit_registration=None):
        if (type(lineage) is not PendingLineageIdentity or type(native_call_id) is not str or not native_call_id or
                type(root_ordinal) is not int or root_ordinal != 0 or
                type(fresh_domain_witness) is not Policy3FreshWitness or fresh_domain_witness.lineage != lineage or
                type(effects) is not tuple or not 1 <= len(effects) <= 64 or
                any(type(row) is not Policy3Effect or row.sequence != i for i, row in enumerate(effects, 1))):
            _fail()
        if thread_exit_registration is not None:
            row = thread_exit_registration
            if (type(row) is not Policy3ThreadExitRegistration or row.lineage != lineage or
                    row.native_call_id != native_call_id or row.root_ordinal != root_ordinal or
                    row.native_tls_block != fresh_domain_witness.native_tls_block):
                _fail()
        self.lineage = lineage
        self.native_call_id = native_call_id
        self.root_ordinal = root_ordinal
        self.witness = fresh_domain_witness
        self._effects = effects
        self._claimed = False
        self.thread_exit_registration = thread_exit_registration

    def __repr__(self):
        return '<Policy3RootInputs private source effects>'

    def _claim(self):
        if self._claimed:
            _fail()
        self._claimed = True
        effects, self._effects = self._effects, ()
        return effects


class _Policy3Binding:
    def __init__(self, inputs, runtime, descriptor):
        if (type(inputs) is not Policy3RootInputs or inputs.lineage != descriptor.lineage or
                inputs.native_call_id != descriptor.native_call_id or inputs.root_ordinal != descriptor.root_ordinal or
                descriptor.main_arguments[9] != 3 or descriptor.root_ordinal != 0):
            _fail()
        self.runtime = runtime
        self.descriptor = descriptor
        self._effects = inputs._claim()
        self._thread_registration = inputs.thread_exit_registration
        self.thread_registered = False
        self._index = 0
        self._thread = get_ident()
        self._site = self._vm = self._root = None
        self._sites = set()
        self._host_sites = set()
        self._locals = {}
        self._current_clock = None
        self._seen_locals = set()
        self.closed = self.complete = False
        self.active = False
        self.api_counts = {}

    @contextmanager
    def scope(self, name):
        runtime = self.runtime
        if get_ident() != self._thread or self.closed:
            _fail()
        if name != 'main':
            yield
            return
        if (self._root is not None or len(runtime._program_calls) != 1 or
                runtime._program_calls[-1]['arguments'] != self.descriptor.main_arguments or
                runtime._main_generation != self.descriptor.root_ordinal + 1 or runtime.tls_base_address is None):
            _fail()
        memory, base, tls = runtime.memory, runtime.image_base, runtime.tls_base_address
        if (memory.load(base + 0x6D88CA8, 8) != 0 or memory.load(base + 0x6D88CB0, 8) != 0 or
                memory.load(base + 0x6D88CB8, 4) != 0 or memory.load(tls + 0xD70, 4) & 1 or
                memory.load(base + 0x6D88CC0, 8) != 0 or memory.load(base + 0x6D88CC8, 4) != 0):
            _fail()
        self._root = runtime._program_calls[-1]
        self.active = True
        try:
            yield
            if (self._index != len(self._effects) or self._sites != set(_SITES) or self._host_sites != set(_HOST_SITES) or
                    not self.thread_registered or
                    memory.load(base + 0x6D88CA8, 8) != (1 << 64) - 1 or
                    not memory.load(base + 0x6D88CB0, 8) or not memory.load(tls + 0xD70, 4) & 1 or
                    not memory.load(tls + 0xD68, 8)):
                _fail()
            self.complete = True
        finally:
            self.active = False
            self.close()

    @contextmanager
    def host(self, vm, address, cells, signature):
        if not self.active:
            yield
            return
        runtime = self.runtime
        stack = runtime._program_calls
        if get_ident() != self._thread or vm.runtime is not runtime or not stack or stack[0] is not self._root:
            _fail()
        from .primary_sign import load_program
        if vm.program.raw != load_program('host97').raw:
            yield
            return
        word, actual_address, actual_cells, actual_signature = vm.host_calls[-1]
        if (actual_address, actual_cells, actual_signature) != (address, cells, signature):
            _fail()
        if word not in _HOST_SITES:
            _fail()
        expected = _HOST_SITES[word]
        consumed, target, expected_signature, expected_cells, function_cell, destination = expected
        prefix = (0x014A3DB9, expected_signature, 0) + (() if destination is None else (destination,))
        instruction = prefix + (function_cell, 0) + expected_cells
        if (len(stack) != 2 or stack[-1]['name'] != 'host97' or stack[-1]['arguments'][0] !=
                self.descriptor.main_arguments[0] or self._vm not in (None, vm) or word in self._host_sites or
                expected[:4] != (vm.pc, address - vm.image_base, signature, cells) or
                vm.program.words[word:consumed] != instruction or vm.cells.value(function_cell) != address):
            _fail()
        self._vm = vm
        self._host_sites.add(word)
        if word not in _SITES:
            yield
            return
        self._sites.add(word)
        previous = self._site
        self._site = Policy3Site(word, *expected[:4])
        try:
            yield
        finally:
            self._site = previous

    def consume(self, kind, arguments=()):
        runtime = self.runtime
        if (self.closed or not self.active or self._site is None or get_ident() != self._thread or
                not runtime._program_calls or runtime._program_calls[0] is not self._root or
                self._index >= len(self._effects)):
            _fail()
        row = self._effects[self._index]
        if row.site != self._site or row.kind != kind or row.arguments != arguments:
            _fail()
        self._index += 1
        self.api_counts[kind] = self.api_counts.get(kind, 0) + 1
        return row

    @contextmanager
    def clock_local(self):
        if self._index >= len(self._effects):
            _fail()
        arguments = self._effects[self._index].arguments
        if (len(arguments) != 2 or arguments[0] != 8 or not 0 < arguments[1] < 1 << 63):
            _fail()
        row = self.consume('clock-local', arguments)
        if (len(row.initial_bytes) != 8 or any(row.initial_knownmask) or row.output_bytes or
                row.return_value is not None or self._current_clock is not None or row.local_identity in self._seen_locals):
            _fail()
        self._seen_locals.add(row.local_identity)
        before_qpc = self.api_counts.get('QueryPerformanceCounter', 0)
        address = row.native_address
        self.runtime.memory.map(address, bytearray(row.initial_bytes), name='policy3 clock local', initialized=False)
        self._locals[address] = 'policy3 clock local'
        self._current_clock = row.local_identity, address
        try:
            yield address
            if (self.api_counts.get('QueryPerformanceCounter', 0) != before_qpc + 1 or
                    self.runtime.memory.load(self.runtime.image_base + 0x674D440, 8) != arguments[1]):
                _fail()
        finally:
            self._current_clock = None
            self._clear_local(address)

    def api(self, name, destination):
        row = self.consume(name, (8,))
        if (self._current_clock != (row.local_identity, row.native_address) or destination != row.native_address or
                len(row.output_bytes) != 8 or row.write_mask != bytes([1]) * 8 or
                type(row.return_value) is not int or not 0 < row.return_value < 1 << 32 or
                name == 'QueryPerformanceFrequency' and not 0 < int.from_bytes(row.output_bytes, 'little') < 1 << 63):
            _fail()
        region, offset = self.runtime.memory._span(destination, 8)
        if (bytes(region.data[offset:offset + 8]), bytes(region.initialized[offset:offset + 8])) != (row.initial_bytes, row.initial_knownmask):
            _fail()
        self.runtime.memory.write(destination, row.output_bytes, source='policy3.' + name)
        return row.return_value

    def filetime(self):
        if self._index >= len(self._effects):
            _fail()
        name = self._effects[self._index].kind
        if name not in ('GetSystemTimePreciseAsFileTime', 'GetSystemTimeAsFileTime'):
            _fail()
        row = self.consume(name, (8,))
        if (row.initial_bytes != bytes(8) or row.initial_knownmask != bytes(8) or
                len(row.output_bytes) != 8 or row.write_mask != bytes([1]) * 8 or row.return_value is not None):
            _fail()
        return int.from_bytes(row.output_bytes, 'little')

    def entropy(self):
        row = self.consume('SystemFunction036', (4,))
        if (row.initial_bytes != bytes(4) or row.initial_knownmask != bytes([1]) * 4 or
                len(row.output_bytes) != 4 or row.write_mask != bytes([1]) * 4 or
                type(row.return_value) is not int or not 0 < row.return_value < 256):
            _fail()
        return row.output_bytes

    def allocate(self, size, zero):
        if (size, zero) not in ((1, False), (2504, False)):
            _fail()
        row = self.consume('allocate', (size, int(zero)))
        if (type(row.return_value) is not int or row.return_value != row.native_address or
                row.output_bytes or row.initial_bytes):
            _fail()
        return size, zero, row.return_value

    def exit_registration(self, callback):
        row = self.consume('exit-registration', (callback - self.runtime.image_base,))
        if callback != self.runtime.image_base + 0x3591F69 or type(row.return_value) is not int or row.return_value != 0:
            _fail()
        return callback, 0

    def temporary(self, size):
        row = self.consume('temporary', (size,))
        if (size not in (16, 100) or type(row.return_value) is not int or row.return_value != row.native_address or
                len(row.initial_bytes) != size or row.output_bytes):
            _fail()
        self._locals[row.native_address] = 'temporary-pending'
        return size, row.native_address, row.initial_bytes

    def mapped_temporary(self, address, name):
        row = self._effects[self._index - 1]
        if row.kind != 'temporary' or row.native_address != address:
            _fail()
        self._locals[address] = name
        if len(row.initial_bytes) == 16:
            region, offset = self.runtime.memory._span(address, 16)
            region.initialized[offset:offset + 16] = row.initial_knownmask

    def register_thread_exit(self):
        row = self._thread_registration
        runtime = self.runtime
        if (type(row) is not Policy3ThreadExitRegistration or self.thread_registered or
                self._site != Policy3Site(529, *_SITES[529]) or get_ident() != self._thread or
                runtime._program_calls[0] is not self._root or not self.active):
            _fail()
        memory, tls = runtime.memory, runtime.tls_base_address
        if (memory.load(tls + 0xB0, 8) != 0 or not memory.load(tls + 0xD70, 4) & 1 or
                not memory.load(tls + 0xD68, 8)):
            _fail()
        memory.store(tls + 0xB0, tls + 0xC0, 8, source='3E6808B.thread_inline_head')
        memory.store(tls + 0xC0, 0, 4, source='3E6808F.thread_inline_count_zero')
        memory.store(tls + 0xD0, runtime.image_base + 0x2DE507A, 8, source='3E68093.thread_inline_callback')
        memory.store(tls + 0xC0, 1, 4, source='3E68098.thread_inline_count_one')
        self.thread_registered = True
        return 0

    def _clear_local(self, address):
        from .primary_consumed_mgf import _clear_chunks
        name = self._locals.pop(address, None)
        region = next((row for row in self.runtime.memory._regions if row.address == address and row.name == name), None)
        if region is not None:
            _clear_chunks(region.data)
            self.runtime.memory.unmap(address)

    def close(self):
        if self.closed:
            return
        self.closed = True
        for address in tuple(self._locals):
            self._clear_local(address)
        self._effects = ()
        self._thread_registration = None
        self._site = self._vm = self._root = self._current_clock = None
