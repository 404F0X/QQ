from contextlib import contextmanager
from dataclasses import dataclass, replace
from hashlib import sha256
from threading import get_ident
import zlib
import struct

from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


SOURCE_SHA256 = '63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'
_GLOBALS = (0x6D86090, 0x6D86094, 0x677E1B4, 0x677E1B8, 0x677E1BC)
_BUDGET = 262144
_CODEC_RESERVE = 65536
_PACKET_LIMIT = (_BUDGET - _CODEC_RESERVE) // 3


def _u32(value):
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def predicate(kind, values):
    if any(not _u32(value) for value in values):
        raise InputError('consumed predicate requires unsigned DWORD operands')
    if kind == 'M' and len(values) == 1:
        return int(values[0] == 0x80000000)
    if kind not in ('G', 'F') or len(values) != 2:
        raise InputError('consumed predicate family/arity mismatch')
    x, y = values
    ax = x if x == 0x80000000 else abs(x if x < 0x80000000 else x - (1 << 32))
    ay = y if y == 0x80000000 else abs(y if y < 0x80000000 else y - (1 << 32))
    combined = ((x * x) & 0xFFFFFFFF) | ay if kind == 'G' else ((x * x + y * y) & 0xFFFFFFFF) | ((ax + ay) & 0xFFFFFFFF)
    return (combined >> 31) & 1


def representative(kind, bit):
    if kind not in ('M', 'G', 'F') or type(bit) is not int or bit not in (0, 1):
        raise InputError('consumed class must be a semantic bit')
    return {'M': (0x80000000 if bit else 0,),
            'G': (0, 0x80000000 if bit else 0),
            'F': (0x80000000 if bit else 0, 0)}[kind]


@dataclass(frozen=True, repr=False)
class ReaderTranscript:
    program: str
    invocation: int
    parent: int
    source_sha256: str
    context: int
    raw_base: int
    raw_length: int
    requests: int
    observations: bytes
    event_count: int
    mode: str
    final_state: tuple
    initial_state: tuple = (0, 0, 0)

    def __post_init__(self):
        if (type(self.program) is not str or not self.program or
                any(not _u32(value) for value in (self.invocation, self.parent, self.raw_length, self.requests, self.event_count)) or
                not self.invocation or type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(type(value) is not int or not 0 < value < 1 << 64 for value in (self.context, self.raw_base)) or
                self.context + 40 > 1 << 64 or self.raw_base + self.raw_length > 1 << 64 or
                self.context < self.raw_base + self.raw_length and self.raw_base < self.context + 40 or
                not (type(self.observations) is bytes or type(self.observations) is memoryview and self.observations.readonly) or self.mode not in ('raw', 'class') or
                type(self.final_state) is not tuple or len(self.final_state) != 3 or
                any(type(value) is not int or value < 0 for value in self.final_state) or
                self.final_state[0] > self.raw_length or self.final_state[1] >= 1 << 64 or self.final_state[2] > 64 or
                type(self.initial_state) is not tuple or len(self.initial_state) != 3 or
                any(type(value) is not int for value in self.initial_state) or self.initial_state != (0, 0, 0)):
            raise InputError('normal reader transcript identity/state domain is invalid')
        if self.mode == 'class' and (len(self.observations) != (self.event_count + 7) // 8 or
                                    self.event_count % 8 and self.observations[-1] >> (self.event_count % 8)):
            raise InputError('normal reader class tape has noncanonical extent')


@dataclass(frozen=True, repr=False)
class ReaderMetadata:
    program: str
    invocation: int
    parent: int
    source_sha256: str
    context: int
    raw_base: int
    raw_length: int
    requests: int
    observation_bytes: int
    event_count: int
    mode: str
    final_state: tuple
    initial_state: tuple = (0, 0, 0)

    def __post_init__(self):
        if (type(self.program) is not str or not self.program or
                any(not _u32(value) for value in (self.invocation, self.parent, self.raw_length, self.requests, self.event_count)) or
                not self.invocation or type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(type(value) is not int or not 0 < value < 1 << 64 for value in (self.context, self.raw_base)) or
                self.context + 40 > 1 << 64 or self.raw_base + self.raw_length > 1 << 64 or
                self.context < self.raw_base + self.raw_length and self.raw_base < self.context + 40 or
                not _u32(self.observation_bytes) or self.mode not in ('raw', 'class') or
                type(self.final_state) is not tuple or len(self.final_state) != 3 or
                any(type(value) is not int or value < 0 for value in self.final_state) or
                self.final_state[0] > self.raw_length or self.final_state[1] >= 1 << 64 or self.final_state[2] > 64 or
                type(self.initial_state) is not tuple or len(self.initial_state) != 3 or
                any(type(value) is not int for value in self.initial_state) or self.initial_state != (0, 0, 0)):
            raise InputError('normal reader transcript identity/state domain is invalid')
        bits = self.requests * 6
        cursor = min(self.raw_length, ((bits + 63) // 64) * 8)
        available = cursor * 8 - bits
        full, tail = divmod(cursor, 8)
        events = 5 * full + (6 + 2 * tail if tail else 0)
        extent = (events + 7) // 8 if self.mode == 'class' else 36 * full + (32 + 8 * tail if tail else 0)
        if (bits > self.raw_length * 8 or self.event_count != events or self.observation_bytes != extent or
                self.final_state[0] != cursor or self.final_state[2] != available or
                not 0 <= self.final_state[1] < 1 << available):
            raise InputError('streaming reader metadata bitcount/extent/final state is inconsistent')


class _ReaderReceiveLease:
    def __init__(self, owner, metadata):
        self.owner = owner
        self.metadata = metadata
        self.generation = owner._identity.generation
        self.thread = get_ident()
        self.offset = 0
        self.closed = False
        self.reuse_start = None
        self.reuse_span_id = None


@dataclass(frozen=True, repr=False)
class NormalReaderCertificate:
    source_sha256: str
    requests: int
    events: int
    refills: int
    final_state: tuple
    group_sha256: str


class _NormalReader:
    def __init__(self, raw, transcript):
        if (len(raw) != transcript.raw_length or sha256(raw).hexdigest() != transcript.source_sha256 or
                transcript.requests * 6 > len(raw) * 8):
            raise InputError('normal reader raw identity/request extent mismatch')
        self.raw, self.tape = raw, transcript
        self.C = self.V = self.s = 0
        self.index = self.offset = self.refills = self.requests = 0
        self.groups = sha256()

    def observe(self, kind):
        tape = self.tape
        if self.index >= tape.event_count:
            raise InputError('normal reader witness exhausted')
        if tape.mode == 'class':
            bit = (tape.observations[self.index >> 3] >> (self.index & 7)) & 1
            values = representative(kind, bit)
        else:
            width = 4 if kind == 'M' else 8
            if self.offset + width > len(tape.observations):
                raise InputError('normal reader raw witness is incomplete')
            values = tuple(int.from_bytes(tape.observations[self.offset + i:self.offset + i + 4], 'little')
                           for i in range(0, width, 4))
            self.offset += width
        self.index += 1
        if predicate(kind, values):
            raise PrimarySemanticUnavailable('UNSUPPORTED_REFILL_NONNORMAL')

    def refill(self):
        if self.C >= len(self.raw):
            raise PrimarySemanticUnavailable('reader external EOF failure remains unsupported')
        self.observe('G')
        remaining = len(self.raw) - self.C
        if remaining >= 8:
            self.observe('F')
            self.V = int.from_bytes(self.raw[self.C:self.C + 8], 'little')
            self.observe('F')
            k = 8
        else:
            self.observe('M')
            self.V = 0
            self.observe('M')
            k = remaining
            for j in range(k):
                self.observe('M')
                self.V |= self.raw[self.C + j] << (8 * j)
                self.observe('M')
            self.observe('M')
        self.observe('M')
        self.C += k
        self.s = 8 * k
        self.observe('F')
        self.refills += 1

    def six(self):
        old_position = 8 * self.C - self.s
        if self.s >= 6:
            value = self.V & 63
            self.V >>= 6
            self.s -= 6
        else:
            old, count = self.V, self.s
            needed = 6 - count
            self.refill()
            if self.s < needed:
                raise PrimarySemanticUnavailable('reader external short-refill failure remains unsupported')
            value = old | ((self.V & ((1 << needed) - 1)) << count)
            self.V >>= needed
            self.s -= needed
        if (not 0 <= self.s <= 64 or not 0 <= self.V < 1 << self.s or
                self.C > len(self.raw) or 8 * self.C - self.s != old_position + 6):
            raise InputError('normal reader invariant failed')
        start, shift = old_position >> 3, old_position & 7
        reference = (int.from_bytes(self.raw[start:start + 2], 'little') >> shift) & 63
        if value != reference:
            raise InputError('normal reader six-bit producer differs from fixed source bits')
        self.groups.update(bytes((value,)))
        self.requests += 1
        return value


def check_normal_reader(program, transcript):
    if type(transcript) is not ReaderTranscript or program.consumed_bits % 6 or transcript.requests != program.consumed_bits // 6:
        raise InputError('normal reader must cover every actual decoder six-bit request')
    reader = _NormalReader(program.raw, transcript)
    for _ in range(transcript.requests):
        reader.six()
    if (reader.index != transcript.event_count or transcript.mode == 'raw' and reader.offset != len(transcript.observations) or
            (reader.C, reader.V, reader.s) != transcript.final_state):
        raise InputError('normal reader witness/final state was not exactly consumed')
    return NormalReaderCertificate(transcript.source_sha256, reader.requests, reader.index, reader.refills,
                                   (reader.C, reader.V, reader.s), reader.groups.hexdigest())


@dataclass(frozen=True, repr=False)
class CommitReaderTape:
    observations: bytes
    event_count: int
    mode: str

    def __post_init__(self):
        if (type(self.observations) is not bytes or not _u32(self.event_count) or
                self.mode not in ('raw', 'class')):
            raise InputError('commit reader tape shape is invalid')
        if self.mode == 'class' and (len(self.observations) != (self.event_count + 7) // 8 or
                self.event_count % 8 and self.observations[-1] >> (self.event_count % 8)):
            raise InputError('commit reader class tape has noncanonical extent')


@dataclass(frozen=True, repr=False)
class CommitReaderResult:
    raw_sha256: str
    reader_address: int
    initial_state: tuple
    final_state: tuple
    events: int
    observation_bytes: int
    commit_true: int
    refills: int
    requests: int
    delay_increments: int
    g_true: int = 0
    f_full_true: int = 0
    full_loads: int = 0
    m_commit_true: int = 0
    m_tail_exit_true: int = 0
    m_tail_setup_true: int = 0
    m_tail_reclear_true: int = 0
    tail_clears: int = 0
    m_tail_byte_before_true: int = 0
    m_tail_byte_after_true: int = 0
    tail_byte_loads: int = 0


class CommitReaderFailure(InputError):
    def __init__(self, reason, prefix):
        super().__init__(reason)
        self.reason = reason
        self.prefix = prefix


class BoundedCommitReader:
    def __init__(self, raw, *, initial_state, reader_address, tape,
                 event_budget, commit_budget):
        if (type(raw) is not bytes or len(raw) > 0xFFFFFFFF or
                type(initial_state) is not tuple or len(initial_state) != 3 or
                any(type(v) is not int for v in initial_state) or
                not 0 <= initial_state[0] < 1 << 64 or not 0 <= initial_state[2] <= 64 or
                not 0 <= initial_state[1] < 1 << initial_state[2] or
                type(reader_address) is not int or not 0 < reader_address <= (1 << 64) - 40 or
                type(tape) is not CommitReaderTape or not _u32(event_budget) or
                not _u32(commit_budget)):
            raise InputError('commit reader explicit state/input/budget domain is invalid')
        self.raw, self.tape = raw, tape
        self.initial_state, self.reader_address = initial_state, reader_address
        self.C, self.V, self.s = initial_state
        self.event_budget, self.commit_budget = event_budget, commit_budget
        self.index = self.offset = self.commit_true = self.refills = self.requests = 0
        self.delay_increments = self.g_true = self.f_full_true = self.full_loads = self.m_commit_true = self.m_tail_exit_true = 0
        self.m_tail_setup_true = self.m_tail_reclear_true = self.tail_clears = 0
        self.m_tail_byte_before_true = self.m_tail_byte_after_true = self.tail_byte_loads = 0
        low = reader_address & 0xFFFFFFFF
        rotated = ((low << 1) | (low >> 31)) & 0xFFFFFFFF
        self.selector = (rotated * 0x19660D - 1) & 3
        self.failed = False
        self.closed = False
        self.raw_sha256 = sha256(raw).hexdigest()

    def snapshot(self):
        return CommitReaderResult(self.raw_sha256, self.reader_address, self.initial_state,
                                  (self.C, self.V, self.s), self.index, self.offset,
                                  self.commit_true, self.refills, self.requests, self.delay_increments, self.g_true,
                                  self.f_full_true, self.full_loads, self.m_commit_true, self.m_tail_exit_true,
                                  self.m_tail_setup_true, self.m_tail_reclear_true, self.tail_clears,
                                  self.m_tail_byte_before_true, self.m_tail_byte_after_true, self.tail_byte_loads)

    def _fail(self, reason):
        self.failed = True
        raise CommitReaderFailure(reason, self.snapshot())

    def _active(self):
        if self.failed or self.closed:
            raise InputError('commit reader is failed or finished')

    def _observe(self, kind, allow_true=False):
        if self.index >= self.event_budget:
            self._fail('COMMIT_READER_EVENT_BUDGET')
        if self.index >= self.tape.event_count:
            self._fail('COMMIT_READER_WITNESS_EXHAUSTED')
        if self.tape.mode == 'class':
            bit = (self.tape.observations[self.index >> 3] >> (self.index & 7)) & 1
        else:
            width = 4 if kind == 'M' else 8
            if self.offset + width > len(self.tape.observations):
                self._fail('COMMIT_READER_RAW_WITNESS_INCOMPLETE')
            values = tuple(int.from_bytes(self.tape.observations[self.offset + j:self.offset + j + 4],
                                          'little') for j in range(0, width, 4))
            self.offset += width
            bit = predicate(kind, values)
        self.index += 1
        if bit and not allow_true:
            self._fail('UNSUPPORTED_REFILL_NONNORMAL_' + kind)
        return bit

    def _commit(self, n):
        if self.C + n >= 1 << 64:
            self._fail('COMMIT_READER_CURSOR_OVERFLOW')
        self.C += n
        self.s = 8 * n

    def _shared_commit(self, n, m_true):
        if m_true:
            self.m_commit_true += 1
            self._commit(n)
            self.delay_increments += self.selector + 1
        self._commit(n)

    def _full_copy(self):
        self.V = int.from_bytes(self.raw[self.C:self.C + 8], 'little')
        self.full_loads += 1

    def _full_retry(self):
        self.f_full_true += 1
        self._full_copy()
        self.delay_increments += self.selector + 1

    def _tail_clear(self):
        self.V = 0
        self.tail_clears += 1

    def _tail_clear_delay(self):
        self._tail_clear()
        self.delay_increments += self.selector + 1

    def _tail_byte_load(self, j):
        self.V |= self.raw[self.C + j] << (8 * j)
        self.tail_byte_loads += 1

    def _tail_byte_delay(self, j):
        self._tail_byte_load(j)
        self.delay_increments += self.selector + 1

    def refill(self):
        self._active()
        if self.C >= len(self.raw):
            self._fail('UNSUPPORTED_REFILL_EOF')
        if self.C + 8 >= 1 << 64:
            self._fail('COMMIT_READER_CURSOR_OVERFLOW')
        while self._observe('G', True):
            self.g_true += 1
            self.delay_increments += self.selector + 1
        n = min(8, len(self.raw) - self.C)
        if n == 8:
            if self._observe('F', True):
                self._full_retry()
            self._full_copy()
            while self._observe('F', True):
                self._full_retry()
                self._full_copy()
        else:
            if self._observe('M', True):
                self.m_tail_setup_true += 1
                self._tail_clear_delay()
            self._tail_clear()
            while self._observe('M', True):
                self.m_tail_reclear_true += 1
                self._tail_clear_delay()
                self._tail_clear()
            for j in range(n):
                if self._observe('M', True):
                    self.m_tail_byte_before_true += 1
                    self._tail_byte_delay(j)
                self._tail_byte_load(j)
                while self._observe('M', True):
                    self.m_tail_byte_after_true += 1
                    self._tail_byte_delay(j)
                    self._tail_byte_load(j)
            if self._observe('M', True):
                self.m_tail_exit_true += 1
                self.delay_increments += self.selector + 1
        self._shared_commit(n, self._observe('M', True))
        while self._observe('F', True):
            if self.commit_true >= self.commit_budget:
                self._fail('COMMIT_READER_COMMIT_BUDGET')
            self.commit_true += 1
            self._commit(n)
            self.delay_increments += self.selector + 1
            self._commit(n)
        self.refills += 1
        return self.snapshot()

    def six(self):
        self._active()
        if self.s >= 6:
            value = self.V & 63
            self.V >>= 6
            self.s -= 6
        else:
            old, count = self.V, self.s
            needed = 6 - count
            self.refill()
            if self.s < needed:
                self._fail('UNSUPPORTED_REFILL_SHORT')
            value = old | ((self.V & ((1 << needed) - 1)) << count)
            self.V >>= needed
            self.s -= needed
        self.requests += 1
        return value

    def finish(self):
        self._active()
        if self.index != self.tape.event_count or (self.tape.mode == 'raw' and
                self.offset != len(self.tape.observations)):
            self._fail('COMMIT_READER_EXTRA_WITNESS')
        self.closed = True
        return self.snapshot()


@dataclass(frozen=True, repr=False)
class StatefulReaderMetadata:
    program: str
    invocation: int
    parent: int
    source_sha256: str
    context: int
    raw_base: int
    raw_length: int
    requests: int
    observation_bytes: int
    event_count: int
    mode: str
    final_state: tuple
    initial_state: tuple
    event_budget: int
    commit_budget: int

    def __post_init__(self):
        if (type(self.program) is not str or not self.program or
                any(not _u32(v) for v in (self.invocation, self.parent, self.raw_length,
                    self.requests, self.observation_bytes, self.event_count, self.event_budget, self.commit_budget)) or
                not self.invocation or self.parent >= self.invocation or
                type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in self.source_sha256) or
                any(type(v) is not int or not 0 < v < 1 << 64 for v in (self.context, self.raw_base)) or
                self.context + 40 > 1 << 64 or self.raw_base + self.raw_length > 1 << 64 or
                self.context < self.raw_base + self.raw_length and self.raw_base < self.context + 40 or
                self.mode not in ('class', 'raw') or self.event_count > self.event_budget):
            raise InputError('stateful reader identity/extent/budget is invalid')
        for state in (self.initial_state, self.final_state):
            if (type(state) is not tuple or len(state) != 3 or any(type(v) is not int for v in state) or
                    not 0 <= state[0] < 1 << 64 or not 0 <= state[2] <= 64 or
                    not 0 <= state[1] < 1 << state[2]):
                raise InputError('stateful reader explicit state is invalid')
        if self.mode == 'class' and self.observation_bytes != (self.event_count + 7) // 8:
            raise InputError('stateful reader class extent is invalid')


@dataclass(frozen=True, repr=False)
class StatefulReaderTranscript:
    program: str
    invocation: int
    parent: int
    source_sha256: str
    context: int
    raw_base: int
    raw_length: int
    requests: int
    observations: bytes
    event_count: int
    mode: str
    final_state: tuple
    initial_state: tuple
    event_budget: int
    commit_budget: int

    def __post_init__(self):
        if not (type(self.observations) is bytes or
                type(self.observations) is memoryview and self.observations.readonly):
            raise InputError('stateful reader requires owned immutable observations')
        StatefulReaderMetadata(**{name: len(self.observations) if name == 'observation_bytes'
            else getattr(self, name) for name in StatefulReaderMetadata.__dataclass_fields__})
        CommitReaderTape(bytes(self.observations), self.event_count, self.mode)


@dataclass(frozen=True, repr=False)
class StatefulReaderCertificate:
    transcript: StatefulReaderMetadata
    result: CommitReaderResult
    logical_position: int
    groups_sha256: str


def parse_stateful_reader(raw, transcript):
    from .primary_vm import decode_program_stateful
    if (type(transcript) is not StatefulReaderTranscript or type(raw) is not bytes or
            sha256(raw).hexdigest() != transcript.source_sha256 or len(raw) != transcript.raw_length):
        raise InputError('stateful reader fixed raw identity mismatch')
    reader = BoundedCommitReader(raw, initial_state=transcript.initial_state,
        reader_address=transcript.context,
        tape=CommitReaderTape(bytes(transcript.observations), transcript.event_count, transcript.mode),
        event_budget=transcript.event_budget, commit_budget=transcript.commit_budget)
    program, result, digest = decode_program_stateful(raw, reader)
    if result.requests != transcript.requests or result.final_state != transcript.final_state:
        error = CommitReaderFailure('STATEFUL_READER_REQUESTS_OR_FINAL_STATE', result)
        error.logical_position = program.consumed_bits
        raise error
    metadata = StatefulReaderMetadata(**{name: len(transcript.observations) if name == 'observation_bytes'
        else getattr(transcript, name) for name in StatefulReaderMetadata.__dataclass_fields__})
    return program, StatefulReaderCertificate(metadata, result, program.consumed_bits, digest)


@dataclass(frozen=True, repr=False)
class SourceIdentity:
    wrapper_sha256: str
    candidate: str
    generation: int
    main_arguments: tuple
    image_base: int
    other_packet_bytes: int = 0

    def __post_init__(self):
        if (self.wrapper_sha256 != SOURCE_SHA256 or type(self.candidate) is not str or not self.candidate or
                not _u32(self.generation) or not self.generation or not _u32(self.other_packet_bytes) or
                type(self.image_base) is not int or not 0 < self.image_base < (1 << 64) - 0x6D8F1B4 or
                type(self.main_arguments) is not tuple or len(self.main_arguments) != 12 or self.main_arguments[0] != 4 or
                any(type(value) is not int or not 0 <= value < 1 << 64 for value in self.main_arguments)):
            raise InputError('consumed replay source identity is invalid')


@dataclass(frozen=True, repr=False)
class ConsumerKey:
    program: int
    word: int
    opcode: int
    block: int
    pc: int
    family: str
    iteration: int
    slot: int
    post_rva: int
    host: int = 0
    phase: str = ''
    size: int = 0
    getter_post: int = 0
    type_index: int = 0
    getter_ordinal: int = 0
    block_pointer: int = 0
    helper_ordinal: int = 0

    def __post_init__(self):
        if (any(not _u32(value) for value in (self.program, self.word, self.opcode, self.block, self.pc,
                self.iteration, self.slot, self.post_rva, self.host, self.size, self.getter_post, self.type_index, self.getter_ordinal, self.helper_ordinal)) or
                type(self.block_pointer) is not int or not 0 <= self.block_pointer < 1 << 64 or
                type(self.family) is not str or not 0 < len(self.family) <= 48 or
                type(self.phase) is not str or len(self.phase) > 48):
            raise InputError('consumed replay key has an invalid typed shape')


@dataclass(frozen=True, repr=False)
class RawRead:
    key: ConsumerKey
    value: int


@dataclass(frozen=True, repr=False)
class PairedClass:
    key: ConsumerKey
    bit: int
    class_post: int
    ordered_posts: tuple


@dataclass(frozen=True, repr=False)
class ReplayOperand:
    value: int
    origin: str
    evidence: ConsumerKey


_KEY_FIELDS = tuple(ConsumerKey.__dataclass_fields__)
_STRING_FIELDS = (5, 10)


def _varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def pack_consumptions(events):
    compressor = zlib.compressobj()
    output = bytearray(compressor.compress(b'MGF1'))
    dictionary = {}
    previous = [0] * len(_KEY_FIELDS)
    for event in events:
        if type(event) is RawRead and type(event.key) is ConsumerKey and _u32(event.value):
            suffix = b'\x00' + event.value.to_bytes(4, 'little')
        elif (type(event) is PairedClass and type(event.key) is ConsumerKey and
                type(event.bit) is int and event.bit in (0, 1) and _u32(event.class_post) and
                type(event.ordered_posts) is tuple and len(event.ordered_posts) in (1, 2) and
                all(_u32(post) for post in event.ordered_posts)):
            suffix = b'\x01' + bytes((event.bit,)) + _varint(event.class_post) + bytes((len(event.ordered_posts),))
            for post in event.ordered_posts:
                suffix += _varint(post)
        else:
            raise InputError('consumed packet requires typed raw or complete class events')
        values = [getattr(event.key, name) for name in _KEY_FIELDS]
        for index in _STRING_FIELDS:
            value = values[index]
            if value not in dictionary:
                if len(dictionary) == 128:
                    raise InputError('consumed source vocabulary exceeds its bounded domain')
                try:
                    encoded = value.encode('ascii')
                except UnicodeError as error:
                    raise InputError('consumed source vocabulary must be ASCII') from error
                dictionary[value] = len(dictionary) + 1
                output.extend(compressor.compress(b'\xD0' + bytes((len(encoded),)) + encoded))
            values[index] = dictionary[value]
        mask = sum(1 << index for index, value in enumerate(values) if value != previous[index])
        record = bytearray(suffix[:1])
        record.extend(_varint(mask))
        for index, value in enumerate(values):
            if mask & (1 << index):
                delta = value - previous[index]
                record.extend(_varint(2 * delta if delta >= 0 else -2 * delta - 1))
        record.extend(suffix[1:])
        previous = values
        output.extend(compressor.compress(record))
        if len(output) > _PACKET_LIMIT:
            raise InputError('consumed replay packet exceeds total budget')
    output.extend(compressor.flush())
    if len(output) > _PACKET_LIMIT:
        raise InputError('consumed replay packet exceeds total budget')
    return bytes(output)


def _clear_chunks(buffer):
    for offset in range(0, len(buffer), 1024):
        count = min(1024, len(buffer) - offset)
        buffer[offset:offset + count] = bytes(count)


def _owned_peaks(identity, reader_count, reservations, evidence_bytes):
    if (type(identity) is not SourceIdentity or not _u32(reader_count) or
            type(reservations) is not tuple or not 1 <= len(reservations) <= 8 or
            any(type(value) is not int or value <= 0 for value in reservations) or
            type(evidence_bytes) is not int or not 0 < evidence_bytes <= 16384):
        raise InputError('owned capture requires cumulative candidate and actual evidence reservations')
    inputs = sum(identity.main_arguments[i] for i in (2, 4, 6, 11))
    common = (inputs + 65536 + 16384 + 4 * 4096 + 8192 + 256 * reader_count +
              sum(reservations) + evidence_bytes + 2048 + identity.other_packet_bytes)
    capture, replay = common + 2 * inputs + 98304, common + 2 * inputs + 65536
    if max(capture, replay) > _BUDGET:
        raise InputError('owned capture/replay peak exceeds private budget')
    return capture, replay


class _PredictorBanks:
    def __init__(self):
        self.vectors = bytearray(32 * 17 * 8)
        self.mapping = bytearray(129)
        self.count = 0

    def read(self, bank):
        if type(bank) is not int or not 0 <= bank <= self.count or bank >= 32:
            raise InputError('consumed predictor bank is skipped or out of range')
        return struct.unpack_from('<17Q', self.vectors, bank * 136)

    def commit(self, bank, values):
        family = values[5]
        if not 1 <= family <= 128:
            raise InputError('consumed predictor family reference is invalid')
        binding = self.mapping[family]
        if (bank == self.count and binding or
                bank < self.count and binding != bank + 1):
            raise InputError('consumed predictor family bank was rebound or duplicated')
        struct.pack_into('<17Q', self.vectors, bank * 136, *values)
        self.mapping[family] = bank + 1
        if bank == self.count:
            self.count += 1

    def clear(self):
        _clear_chunks(self.vectors)
        _clear_chunks(self.mapping)
        self.vectors.clear()
        self.mapping.clear()
        self.count = 0


def _key_cost(values, previous):
    mask = sum(1 << index for index, value in enumerate(values) if value != previous[index])
    cost = max(1, (mask.bit_length() + 6) // 7)
    for index, value in enumerate(values):
        if mask & (1 << index):
            delta = value - previous[index]
            encoded = 2 * delta if delta >= 0 else -2 * delta - 1
            cost += max(1, (encoded.bit_length() + 6) // 7)
    return cost


_LEASE_KEY = object()
_READER_COUNT_UNSET = object()


class _ReceivedCandidateLease:
    def __init__(self, key, owner):
        if key is not _LEASE_KEY:
            raise InputError('owned lease must originate in the controlled receiver')
        self._owner = owner

    def close(self):
        owner, self._owner = self._owner, None
        if owner is not None:
            owner.close()


class ConsumptionEncoder:
    def __init__(self, source_identity, reader_count=None, *, reader_capacity=None,
                 candidate_reservations, evidence_bytes):
        if reader_count is None:
            if not _u32(reader_capacity):
                raise InputError('owned capacity mode requires a fixed unsigned reader capacity')
            limit = reader_capacity
        else:
            if reader_capacity is not None:
                raise InputError('owned reader count and capacity modes are mutually exclusive')
            limit = reader_count
        self.capture_peak, self.replay_peak = _owned_peaks(
            source_identity, limit, candidate_reservations, evidence_bytes)
        self._identity = source_identity
        self._reader_count = reader_count
        self._reader_capacity = limit
        self.candidate_reservations = candidate_reservations
        self.evidence_bytes = evidence_bytes
        self._initialize(source_identity)

    @classmethod
    def _history_segment(cls, receiver):
        from .primary_singleton_history import RootReceiver
        if type(receiver) is not RootReceiver or receiver.owner._pending is not receiver:
            raise InputError('history segment requires its controlled current receiver')
        instance = cls.__new__(cls)
        instance.capture_peak = receiver.owner.capture_peak
        instance.replay_peak = receiver.owner.replay_peak
        instance._reader_count = None
        instance._reader_capacity = receiver.descriptor.reader_capacity
        instance.candidate_reservations = receiver.owner.candidate_reservations
        instance.evidence_bytes = receiver.owner.evidence_bytes
        instance._initialize(receiver.identity, receiver)
        return instance

    def _initialize(self, source_identity, history=None):
        self._identity = source_identity
        self._history = history
        self._inputs = tuple(bytearray(source_identity.main_arguments[i]) for i in (2, 4, 6, 11))
        self._input_offsets = [0] * 4
        self._reader_slab = bytearray(16384) if history is None else history.owner._readers
        self._encoded = bytearray(65536) if history is None else history.owner._encoded
        self._encoded_base = 0 if history is None else history.owner.encoded_length
        self._readers = []
        self._reader_length = 0 if history is None else history.owner.reader_length
        self.encoded_length = self.event_count = 0
        self._reader_pending = None
        self._receiver_thread = get_ident()
        self._dictionary = {}
        self._banks = _PredictorBanks()
        self._previous = bytearray(136)
        self.family_switches = self.legacy_key_bytes = self.bank_key_bytes = 0
        self.family_count = 0
        self._last_bank = None
        self.closed = self.finished = False
        self._compressor = zlib.compressobj(level=9, wbits=13, memLevel=3, strategy=zlib.Z_DEFAULT_STRATEGY)
        self._append(self._compressor.compress(b'MGF2'))

    def _active(self):
        if self.closed or self.finished:
            raise InputError('owned encoder is no longer the receiver')

    def _append(self, chunk):
        end = self._encoded_base + self.encoded_length + len(chunk)
        if end > len(self._encoded):
            raise InputError('owned compressed slab capacity exceeded')
        self._encoded[self._encoded_base + self.encoded_length:end] = chunk
        self.encoded_length += len(chunk)

    def receive_input(self, index, block):
        self._active()
        try:
            if type(index) is not int or not 0 <= index < 4 or type(block) is not bytes or not 0 < len(block) <= 4096:
                raise InputError('owned input receiver requires one immutable bounded block')
            offset = self._input_offsets[index]
            end = offset + len(block)
            if end > len(self._inputs[index]):
                raise InputError('owned input receiver exceeds declared extent')
            self._inputs[index][offset:end] = block
            self._input_offsets[index] = end
        except BaseException:
            self.close()
            raise

    def begin_reader(self, metadata, reuse_span_id=None):
        self._active()
        try:
            if (get_ident() != self._receiver_thread or type(metadata) not in (ReaderMetadata, StatefulReaderMetadata) or
                    self._reader_pending is not None or len(self._readers) >= self._reader_capacity):
                raise InputError('streaming reader owner/metadata/slab admission failed')
            if (any(row.invocation == metadata.invocation for row in self._readers) or
                    metadata.invocation <= (self._readers[-1].invocation if self._readers else 0) or
                    metadata.parent >= metadata.invocation):
                raise InputError('streaming reader invocation lineage/order is invalid')
            _validate_ranges(self._identity, (metadata,), tuple(len(value) for value in self._inputs))
            if self._history is not None and type(metadata) is StatefulReaderMetadata:
                raise InputError('history reader entrance is normal-only')
            lease = _ReaderReceiveLease(self, metadata)
            if reuse_span_id is not None:
                if self._history is None:
                    raise InputError('reader sharing requires its controlled history owner')
                lease.reuse_start = self._history._reuse_span(metadata, reuse_span_id)
                lease.reuse_span_id = reuse_span_id
            elif self._reader_length + metadata.observation_bytes > len(self._reader_slab):
                raise InputError('streaming reader slab admission failed')
            self._reader_pending = lease
            return lease
        except BaseException:
            self.close()
            raise

    def _check_reader(self, lease):
        self._active()
        if (type(lease) is not _ReaderReceiveLease or lease is not self._reader_pending or
                lease.closed or lease.owner is not self or lease.thread != get_ident() or
                self._receiver_thread != get_ident() or lease.generation != self._identity.generation):
            raise InputError('streaming reader lease owner/thread/generation is invalid')

    def feed_reader(self, lease, offset, block):
        try:
            self._check_reader(lease)
            if (type(offset) is not int or offset != lease.offset or type(block) is not bytes or
                    not 0 < len(block) <= 4096 or offset + len(block) > lease.metadata.observation_bytes):
                raise InputError('streaming reader block offset/extent is invalid')
            start = (self._reader_length if lease.reuse_start is None else lease.reuse_start) + offset
            if lease.reuse_start is None:
                self._reader_slab[start:start + len(block)] = block
            elif memoryview(self._reader_slab)[start:start + len(block)] != block:
                raise InputError('shared reader full certificate block differs')
            lease.offset += len(block)
        except BaseException:
            self.close()
            raise

    def finish_reader(self, lease):
        try:
            self._check_reader(lease)
            metadata = lease.metadata
            if lease.offset != metadata.observation_bytes:
                raise InputError('streaming reader witness is incomplete')
            start = self._reader_length if lease.reuse_start is None else lease.reuse_start
            end = start + lease.offset
            if (metadata.mode == 'class' and metadata.event_count % 8 and
                    self._reader_slab[end - 1] >> (metadata.event_count % 8)):
                raise InputError('streaming reader class padding is noncanonical')
            view = memoryview(self._reader_slab)[start:end].toreadonly()
            row_type = StatefulReaderTranscript if type(metadata) is StatefulReaderMetadata else ReaderTranscript
            fields = {name: getattr(metadata, name) for name in row_type.__dataclass_fields__ if name != 'observations'}
            try:
                row = row_type(observations=view, **fields)
            except BaseException:
                view.release()
                raise
            reference = None
            if self._history is not None:
                try:
                    reference = self._history._commit_reader(metadata, row, start, end, lease.reuse_span_id)
                except BaseException:
                    view.release()
                    raise
            self._readers.append(row)
            if lease.reuse_start is None:
                self._reader_length = end
            lease.owner = lease.metadata = None
            lease.closed = True
            self._reader_pending = None
            return reference
        except BaseException:
            self.close()
            raise

    def add_reader(self, transcript):
        self._active()
        try:
            if self._reader_pending is not None or type(transcript) not in (ReaderTranscript, StatefulReaderTranscript) or type(transcript.observations) is not bytes:
                raise InputError('owned reader receiver requires a typed immutable witness')
            if self._history is not None and type(transcript) is StatefulReaderTranscript:
                raise InputError('history reader entrance is normal-only')
            if (transcript.parent >= transcript.invocation or
                    transcript.invocation <= (self._readers[-1].invocation if self._readers else 0)):
                raise InputError('reader invocation lineage/order is invalid')
            _validate_ranges(self._identity, (transcript,), tuple(len(v) for v in self._inputs))
            end = self._reader_length + len(transcript.observations)
            if len(self._readers) >= self._reader_capacity or end > len(self._reader_slab):
                raise InputError('owned reader slab or metadata capacity exceeded')
            self._reader_slab[self._reader_length:end] = transcript.observations
            view = memoryview(self._reader_slab)[self._reader_length:end].toreadonly()
            self._readers.append(replace(transcript, observations=view))
            self._reader_length = end
        except BaseException:
            self.close()
            raise

    def feed(self, event):
        self._active()
        try:
            self._feed(event)
            self.event_count += 1
        except BaseException:
            self.close()
            raise

    def _feed(self, event):
        if type(event) is RawRead and type(event.key) is ConsumerKey and _u32(event.value):
            suffix = b'\x00' + event.value.to_bytes(4, 'little')
        elif (type(event) is PairedClass and type(event.key) is ConsumerKey and
                type(event.bit) is int and event.bit in (0, 1) and _u32(event.class_post) and
                type(event.ordered_posts) is tuple and len(event.ordered_posts) in (1, 2) and
                all(_u32(post) for post in event.ordered_posts)):
            suffix = b'\x01' + bytes((event.bit,)) + _varint(event.class_post) + bytes((len(event.ordered_posts),))
            for post in event.ordered_posts:
                suffix += _varint(post)
        else:
            raise InputError('consumed packet requires typed raw or complete class events')
        values = [getattr(event.key, name) for name in _KEY_FIELDS]
        for index in _STRING_FIELDS:
            value = values[index]
            if value not in self._dictionary:
                if len(self._dictionary) == 128:
                    raise InputError('consumed source vocabulary exceeds its bounded domain')
                try:
                    encoded = value.encode('ascii')
                except UnicodeError as error:
                    raise InputError('consumed source vocabulary must be ASCII') from error
                self._dictionary[value] = len(self._dictionary) + 1
                self._append(self._compressor.compress(b'\xD0' + bytes((len(encoded),)) + encoded))
            values[index] = self._dictionary[value]
        family = values[5]
        binding = self._banks.mapping[family]
        bank = binding - 1 if binding else self._banks.count
        previous = self._banks.read(bank)
        mask = sum(1 << index for index, value in enumerate(values) if value != previous[index])
        record = bytearray(suffix[:1])
        record.append(bank)
        record.extend(_varint(mask))
        for index, value in enumerate(values):
            if mask & (1 << index):
                delta = value - previous[index]
                record.extend(_varint(2 * delta if delta >= 0 else -2 * delta - 1))
        record.extend(suffix[1:])
        self._append(self._compressor.compress(record))
        self._banks.commit(bank, values)
        legacy = struct.unpack('<17Q', self._previous)
        self.legacy_key_bytes += _key_cost(values, legacy)
        self.bank_key_bytes += 1 + _key_cost(values, previous)
        self.family_switches += int(self._last_bank is not None and self._last_bank != bank)
        self._last_bank = bank
        self.family_count = self._banks.count
        struct.pack_into('<17Q', self._previous, 0, *values)

    def finish_owned(self, *, reader_count=_READER_COUNT_UNSET, acknowledge=None):
        self._active()
        try:
            if self._reader_count is None:
                if not _u32(reader_count) or reader_count > self._reader_capacity:
                    raise InputError('owned capacity finalization requires an explicit actual reader count')
                actual_count = reader_count
            else:
                if reader_count is not _READER_COUNT_UNSET:
                    raise InputError('owned exact finalization does not accept a reader count override')
                actual_count = self._reader_count
            if (self._reader_pending is not None or len(self._readers) != actual_count or
                    self._input_offsets != [len(value) for value in self._inputs]):
                raise InputError('owned receiver input/readers are incomplete')
            self._reader_count = actual_count
            self.finished = True
            self._append(self._compressor.flush())
            self._compressor = None
            self._dictionary.clear()
            _clear_chunks(self._previous)
            self._previous.clear()
            self._banks.clear()
            if acknowledge is not None and acknowledge() is not True:
                raise InputError('owned receiver acknowledgement failed')
            if self.closed:
                raise InputError('owned receiver was closed during acknowledgement')
            if self._history is not None:
                return self._history._finish_segment(self)
            receiver = object.__new__(ConsumptionEncoder)
            receiver.__dict__ = self.__dict__.copy()
            receiver.finished = False
            self._inputs = ()
            self._readers = []
            self._encoded = self._reader_slab = None
            self._identity = None
            self.closed = True
            return _ReceivedCandidateLease(_LEASE_KEY, receiver)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        self._compressor = None
        if self._reader_pending is not None:
            self._reader_pending.owner = self._reader_pending.metadata = None
            self._reader_pending.closed = True
            self._reader_pending = None
        for row in self._readers:
            row.observations.release()
        self._readers.clear()
        if self._history is not None:
            owner, self._history = self._history.owner, None
            for value in self._inputs:
                _clear_chunks(value)
            self._inputs = ()
            self._reader_slab = self._encoded = self._identity = None
            self._dictionary.clear()
            _clear_chunks(self._previous)
            self._previous.clear()
            self._banks.clear()
            owner.close()
            return
        for value in self._inputs:
            _clear_chunks(value)
        _clear_chunks(self._reader_slab)
        _clear_chunks(self._encoded)
        self._inputs = ()
        self._reader_slab = self._encoded = self._identity = None
        self._dictionary.clear()
        _clear_chunks(self._previous)
        self._previous.clear()
        self._banks.clear()


class _EventReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.decoder = zlib.decompressobj()
        self.buffer = bytearray()
        self.tail = b''
        self.dictionary = []
        self.previous = bytearray(136)
        self.banks = _PredictorBanks()
        self.magic = None
        self.closed = self.finished = False
        self.started = False

    def _take(self, count, *, eof=False):
        while len(self.buffer) < count and not self.decoder.eof:
            chunk = self.tail
            if not chunk:
                chunk = bytes(self.data[self.offset:self.offset + 1024])
                self.offset += len(chunk)
            if not chunk:
                raise InputError('consumed packet is truncated')
            try:
                self.buffer.extend(self.decoder.decompress(chunk, 4096 - len(self.buffer)))
            except zlib.error as error:
                raise InputError('consumed packet encoding is invalid') from error
            self.tail = self.decoder.unconsumed_tail
        if self.decoder.eof and (self.decoder.unused_data or self.offset != len(self.data) or self.tail):
            raise InputError('consumed packet has trailing data')
        if len(self.buffer) < count:
            if eof and not self.buffer:
                return None
            raise InputError('consumed packet record is truncated')
        value = bytes(self.buffer[:count])
        del self.buffer[:count]
        return value

    def _integer(self):
        value = 0
        for shift in range(0, 70, 7):
            byte = self._take(1)[0]
            value |= (byte & 127) << shift
            if not byte & 128:
                if shift and byte == 0:
                    raise InputError('consumed integer encoding is noncanonical')
                return value
        raise InputError('consumed integer extent exceeds its typed domain')

    def next(self):
        if self.closed:
            raise InputError('consumed event decoder is closed')
        if self.finished:
            return None
        try:
            return self._next()
        except BaseException:
            self.close()
            raise

    def _next(self):
        if not self.started:
            self.magic = self._take(4)
            if self.magic not in (b'MGF1', b'MGF2'):
                raise InputError('consumed packet codec identity mismatch')
            self.started = True
        while True:
            tag = self._take(1, eof=True)
            if tag is None:
                self.finished = True
                self.banks.clear()
                _clear_chunks(self.previous)
                return None
            if tag != b'\xD0':
                break
            length = self._take(1)[0]
            if length > 48 or len(self.dictionary) == 128:
                raise InputError('consumed source vocabulary exceeds its bounded domain')
            try:
                value = self._take(length).decode('ascii')
            except UnicodeError as error:
                raise InputError('consumed source vocabulary must be ASCII') from error
            if value in self.dictionary:
                raise InputError('consumed source vocabulary is noncanonical')
            self.dictionary.append(value)
        if tag not in (b'\x00', b'\x01'):
            raise InputError('consumed event origin is invalid')
        bank = self._take(1)[0] if self.magic == b'MGF2' else None
        values = list(self.banks.read(bank) if bank is not None else struct.unpack('<17Q', self.previous))
        mask = self._integer()
        if mask >= 1 << len(_KEY_FIELDS):
            raise InputError('consumed key mask exceeds its typed shape')
        for index in range(len(values)):
            if mask & (1 << index):
                delta = self._integer()
                if bank is not None and not delta:
                    raise InputError('consumed predictor key mask redundantly marks unchanged field')
                values[index] += -(delta // 2) - 1 if delta & 1 else delta // 2
        resolved = list(values)
        for index in _STRING_FIELDS:
            if not 1 <= values[index] <= len(self.dictionary):
                raise InputError('consumed source vocabulary reference is invalid')
            resolved[index] = self.dictionary[values[index] - 1]
        key = dict(zip(_KEY_FIELDS, resolved))
        ConsumerKey(**key)
        if tag == b'\x00':
            event = ['raw', key, int.from_bytes(self._take(4), 'little')]
        else:
            bit = self._take(1)[0]
            classified = self._integer()
            count = self._take(1)[0]
            if bit not in (0, 1) or not _u32(classified) or count not in (1, 2):
                raise InputError('consumed class shape is invalid')
            posts = [self._integer() for _ in range(count)]
            if not all(_u32(post) for post in posts):
                raise InputError('consumed class post exceeds DWORD domain')
            event = ['class', key, bit, classified, posts]
        if bank is None:
            struct.pack_into('<17Q', self.previous, 0, *values)
        else:
            self.banks.commit(bank, values)
        return event

    def close(self):
        self.closed = True
        self.decoder = None
        self.banks.clear()
        _clear_chunks(self.buffer)
        self.buffer.clear()
        self.dictionary.clear()
        _clear_chunks(self.previous)
        self.previous.clear()
        self.data = self.decoder = self.tail = None


@dataclass(frozen=True, repr=False)
class TypedConsumption:
    readers: tuple
    consumers: bytes
    source_identity: SourceIdentity


@dataclass(frozen=True)
class Comparison:
    model_count: int
    native_count: int
    equal: bool


def _main96_digest(output):
    try:
        view = memoryview(output)
    except TypeError as error:
        raise InputError('MAIN96 reference requires a contiguous 96-byte view') from error
    if view.ndim != 1 or view.itemsize != 1 or not view.c_contiguous or len(view) != 96:
        raise InputError('MAIN96 reference requires a contiguous 96-byte view')
    digest = sha256(b'MAIN96_V1\x00' + struct.pack('<I', 96))
    digest.update(view)
    return digest.hexdigest()


@dataclass(frozen=True, repr=False)
class Main96DigestReference:
    count: int
    digest: str

    def __post_init__(self):
        if (type(self.count) is not int or self.count != 96 or type(self.digest) is not str or
                len(self.digest) != 64 or any(char not in '0123456789abcdef' for char in self.digest)):
            raise InputError('MAIN96 reference requires count96 and a lowercase SHA256 digest')

    @classmethod
    def from_output(cls, native_output_view):
        return cls(96, _main96_digest(native_output_view))


def _validate_ranges(identity, readers, lengths):
    if any(identity.main_arguments[i] + length > 1 << 64 for i, length in zip((1, 3, 5, 10), lengths)) or identity.main_arguments[7] + 128 > 1 << 64 or identity.main_arguments[8] + 4 > 1 << 64:
        raise InputError('consumed private ranges wrap the address domain')
    for row in readers:
        private_ranges = [(identity.main_arguments[i], identity.main_arguments[i] + length)
                          for i, length in zip((1, 3, 5, 10), lengths) if length]
        private_ranges += [(identity.main_arguments[7], identity.main_arguments[7] + 128),
                           (identity.main_arguments[8], identity.main_arguments[8] + 4)]
        reader_ranges = ((row.context, row.context + 40), (row.raw_base, row.raw_base + row.raw_length))
        globals_ranges = tuple((identity.image_base + rva, identity.image_base + rva + 4) for rva in _GLOBALS)
        if any(a < d and c < b for a, b in reader_ranges for c, d in private_ranges + list(globals_ranges)):
            raise InputError('normal reader context/raw aliases private inputs/output or globals')

class PrivateCoreReplayCapsule:
    @classmethod
    def _borrow_history_segment(cls, lease):
        from .primary_singleton_history import RootCapsuleLease
        if type(lease) is not RootCapsuleLease or lease.closed or lease.owner._borrowed is not lease:
            raise InputError('history capsule requires the current controlled segment lease')
        row = lease.row
        encoded = memoryview(lease.owner._encoded)[row.compressed_start:row.compressed_end].toreadonly()
        capsule = cls._create(row.identity, row.inputs, list(row.readers), encoded, lease.owner.replay_peak)
        capsule._history_lease = lease
        capsule._input_masks = row.masks
        return capsule

    @classmethod
    def take_received_candidate(cls, lease):
        if type(lease) is not _ReceivedCandidateLease or lease._owner is None:
            raise InputError('consumed capsule requires an unused controlled receiver lease')
        owner, lease._owner = lease._owner, None
        try:
            identity = owner._identity
            lengths = tuple(identity.main_arguments[i] for i in (2, 4, 6, 11))
            _validate_ranges(identity, owner._readers, lengths)
            encoded = memoryview(owner._encoded)[:owner.encoded_length].toreadonly()
            instance = cls._create(identity, owner._inputs, owner._readers, encoded,
                                   owner.replay_peak, owner._reader_slab)
            instance.capture_peak = owner.capture_peak
            instance.candidate_reservations = owner.candidate_reservations
            instance.evidence_bytes = owner.evidence_bytes
            instance.encoded_length = owner.encoded_length
            instance.compression_stats = dict(families=owner.family_count, family_switches=owner.family_switches,
                                              legacy_key_bytes=owner.legacy_key_bytes, bank_key_bytes=owner.bank_key_bytes)
            owner._inputs = ()
            owner._readers = []
            owner._encoded = owner._reader_slab = owner._identity = None
            owner.closed = True
            return instance
        except BaseException:
            owner.close()
            raise

    @classmethod
    def from_received_candidate(cls, owned_input_views, typed_consumption, source_identity):
        if (type(source_identity) is not SourceIdentity or type(typed_consumption) is not TypedConsumption or
                typed_consumption.source_identity != source_identity or
                type(typed_consumption.readers) is not tuple or
                any(type(row) not in (ReaderTranscript, StatefulReaderTranscript) for row in typed_consumption.readers) or
                type(typed_consumption.consumers) is not bytes or type(owned_input_views) is not tuple or
                len(owned_input_views) != 4):
            raise InputError('consumed capsule requires private typed candidate inputs')
        lengths = tuple(source_identity.main_arguments[i] for i in (2, 4, 6, 11))
        if any(not isinstance(value, (bytes, bytearray, memoryview)) or len(value) != length
               for value, length in zip(owned_input_views, lengths)):
            raise InputError('consumed candidate owned-view extent mismatch')
        for value in owned_input_views:
            view = memoryview(value)
            if view.ndim != 1 or view.itemsize != 1 or not view.c_contiguous or view.format not in ('B', 'b', 'c'):
                raise InputError('consumed input must be a contiguous byteview')
        budget = (2 * (sum(lengths) + sum(len(row.observations) for row in typed_consumption.readers)) +
                  3 * len(typed_consumption.consumers) + 256 * len(typed_consumption.readers) +
                  source_identity.other_packet_bytes + _CODEC_RESERVE)
        if budget > _BUDGET:
            raise InputError('consumed capsule combined copies/packet budget exceeded')
        _validate_ranges(source_identity, typed_consumption.readers, lengths)
        return cls._create(source_identity, tuple(bytearray(value) for value in owned_input_views),
                           list(typed_consumption.readers), bytearray(typed_consumption.consumers), budget)

    @classmethod
    def _create(cls, source_identity, inputs, readers, encoded, budget, reader_slab=None):
        instance = cls()
        instance._identity = source_identity
        instance._inputs = inputs
        instance._readers = readers
        instance._encoded = encoded
        instance._reader_slab = reader_slab
        instance.budget_bytes = budget
        instance.closed = instance.used = instance.complete = False
        instance._runtime = instance._thread = instance._root = None
        instance._calls = []
        instance._vms = {}
        instance._verified_readers = {}
        instance._stateful_attempts = set()
        instance._stateful_programs = {}
        instance._stateful_failure = None
        instance._iv_pending = None
        instance._iv_ordinal = 0
        instance._ordinal = instance._reader_index = 0
        instance._pair = None
        instance._events = None
        instance._original_guard = None
        instance._history_lease = None
        instance._input_masks = None
        instance.origins = {'RAW_OBSERVED': 0, 'CLASS_REPRESENTATIVE': 0}
        return instance

    def __repr__(self):
        return '<PrivateCoreReplayCapsule private>'

    @contextmanager
    def bind(self, runtime):
        if self.used or self.closed or getattr(runtime, '_consumed_mgf', None) is not None or runtime._program_calls:
            raise InputError('consumed capsule is one-shot and requires an idle runtime')
        if runtime.image_base != self._identity.image_base:
            raise InputError('consumed model image base does not match the source identity')
        if runtime._active_failed:
            raise InputError('consumed replay cannot reuse an incomplete runtime')
        self.used = True
        self._runtime, self._thread = runtime, get_ident()
        self._events = _EventReader(self._encoded)
        self._original_guard = getattr(runtime.memory, '_consumed_mgf_guard', None)
        for rva in _GLOBALS:
            region = next((r for r in runtime.memory._regions if r.address <= runtime.image_base + rva < r.address + len(r.data)), None)
            if region is not None and sum(r.data.obj is region.data.obj for r in runtime.memory._regions) != 1:
                self.close()
                raise InputError('consumed replay rejects pre-existing five-global aliases')
        if self._original_guard is not None:
            self.close()
            raise InputError('consumed capsule memory is already owned')
        runtime._consumed_mgf = self
        runtime.memory._consumed_mgf_guard = self
        try:
            for index, (pointer_index, view) in enumerate(zip((1, 3, 5, 10), self._inputs)):
                if view:
                    pointer = self._identity.main_arguments[pointer_index]
                    self.guard_overlap(pointer, len(view))
                    region, offset = runtime.memory._span(pointer, len(view))
                    mask = None if self._input_masks is None else self._input_masks[index]
                    known = memoryview(region.initialized)[offset:offset + len(view)]
                    if ((not all(known) if mask is None else known != memoryview(mask)) or
                            region.data[offset:offset + len(view)] != memoryview(view)):
                        raise InputError('consumed capsule input mapping does not match the owned candidate')
            yield self
            if not self.complete or self._reader_index != len(self._readers) or self._pair is not None or self._events.next() is not None:
                raise InputError('consumed capsule did not exactly complete its main and evidence')
        finally:
            runtime._consumed_mgf = None
            runtime.memory._consumed_mgf_guard = self._original_guard
            self.close()

    def guard_overlap(self, address, size):
        if self.closed:
            raise InputError('consumed memory guard is closed')
        if type(address) is not int or type(size) is not int or size < 0:
            raise InputError('consumed memory access has an invalid typed extent')
        address &= (1 << 64) - 1
        if not size:
            return
        if any(address < self._runtime.image_base + rva + 4 and self._runtime.image_base + rva < address + size for rva in _GLOBALS):
            raise InputError('unrouted five-global memory access in consumed replay')

    def guard_mapping(self, address, buffer):
        self.guard_overlap(address, len(buffer))
        backing = memoryview(buffer).obj
        for rva in _GLOBALS:
            region = next((r for r in self._runtime.memory._regions if r.address <= self._runtime.image_base + rva < r.address + len(r.data)), None)
            if region is not None and region.data.obj is backing:
                raise InputError('consumed replay cannot introduce a five-global backing alias')

    @contextmanager
    def program_scope(self, runtime, call):
        if runtime is not self._runtime or get_ident() != self._thread or self.closed:
            raise InputError('consumed program owner mismatch')
        self._ordinal += 1
        ordinal = self._ordinal
        if call['name'] == 'main':
            if self._root is not None or len(runtime._program_calls) != 1 or call['arguments'] != self._identity.main_arguments:
                raise InputError('consumed capsule requires its actual normal main root')
            self._root = call
        elif self._root is None or runtime._program_calls[0] is not self._root:
            raise InputError('consumed nested program has no actual main root')
        self._calls.append((call, ordinal))
        if call is self._root:
            self._model_generation = runtime._active_main['generation']
        try:
            yield
            vm = next((row[0] for row in self._vms.values() if row[1] is call), None)
            if vm is None or not vm.halted:
                raise InputError('consumed program did not finish its actual VM')
            if call is self._root:
                self.finish_main(vm)
        finally:
            if self._calls and self._calls[-1][0] is call:
                self._calls.pop()
            elif not self.closed:
                raise InputError('consumed program ownership stack changed')

    def stateful_reader_pending(self):
        return (self._reader_index < len(self._readers) and
                type(self._readers[self._reader_index]) is StatefulReaderTranscript)

    def decode_reader(self, raw, name):
        if (self.closed or get_ident() != self._thread or not self._calls or
                not self.stateful_reader_pending() or
                self._runtime._program_calls[-1] is not self._calls[-1][0]):
            raise InputError('stateful reader lacks actual current program owner')
        call, ordinal = self._calls[-1]
        transcript = self._readers[self._reader_index]
        parent = self._calls[-2][1] if len(self._calls) > 1 else 0
        if (transcript.program, transcript.invocation, transcript.parent) != (name, ordinal, parent):
            raise InputError('stateful reader invocation/parent/order mismatch')
        if id(call) in self._stateful_attempts:
            raise InputError('stateful reader parse is terminal for this call')
        self._stateful_attempts.add(id(call))
        try:
            program, certificate = parse_stateful_reader(raw, transcript)
        except (CommitReaderFailure, PrimaryProgramLimit, PrimarySemanticUnavailable) as error:
            if hasattr(error, 'prefix'):
                self._stateful_failure = (call, ordinal, error.reason, error.prefix, error.logical_position)
            raise
        self._reader_index += 1
        self._verified_readers[id(call)] = (call, ordinal, certificate)
        self._stateful_programs[id(call)] = program
        return program

    def reader_gate(self, program, name):
        if self._reader_index >= len(self._readers) or not self._calls:
            raise InputError('consumed program reader certificate is missing')
        transcript = self._readers[self._reader_index]
        call, ordinal = self._calls[-1]
        parent = self._calls[-2][1] if len(self._calls) > 1 else 0
        if (transcript.program, transcript.invocation, transcript.parent) != (name, ordinal, parent):
            raise InputError('consumed reader invocation/parent/order mismatch')
        certificate = check_normal_reader(program, transcript)
        self._reader_index += 1
        self._verified_readers[id(call)] = (call, ordinal, certificate)
        return certificate

    def attach_vm(self, vm):
        if not self._calls or vm.runtime is not self._runtime or get_ident() != self._thread:
            raise InputError('consumed VM attachment lacks actual program owner')
        call, ordinal = self._calls[-1]
        verified = self._verified_readers.get(id(call))
        if verified is None or verified[0] is not call or verified[1] != ordinal:
            raise InputError('consumed VM has no actual program reader certificate')
        if (type(verified[2]) is StatefulReaderCertificate and
                vm.program is not self._stateful_programs.get(id(call))):
            raise InputError('stateful VM program is not the actual parsed program')
        self._vms[id(vm)] = (vm, call, ordinal, verified[2])

    def begin_record(self, vm, cursor):
        row = self._vms.get(id(vm))
        if (row is None or row[0] is not vm or row[1] is not self._runtime._program_calls[-1] or
                get_ident() != self._thread or vm._mgf_cursor is not None or self._pair is not None):
            raise InputError('consumed record lacks actual VM/call ownership')
        vm._mgf_cursor = cursor
        vm._mgf_iteration = 0
        vm._mgf_getter_ordinal = 0
        vm._mgf_flag = None
        vm._mgf_stage = None

    def finish_record(self, vm, record):
        cursor = vm._mgf_cursor
        if cursor is None or record is not vm.trace[-1] or (record.word, record.raw_opcode) != (cursor[0], cursor[2]) or record.block != vm.block or self._pair is not None:
            raise InputError('consumed completed record identity/pair mismatch')
        vm._mgf_cursor = None

    def read_vm(self, vm, rva, family, posts, class_post, *, size=0, getter=0, type_index=0, getter_ordinal=0):
        row = self._vms.get(id(vm))
        cursor = vm._mgf_cursor
        if (row is None or row[0] is not vm or cursor is None or vm.runtime is not self._runtime or
                get_ident() != self._thread or row[1] is not self._runtime._program_calls[-1]):
            raise InputError('consumed VM read lacks actual inflight cursor')
        expected = (family, tuple(posts), class_post, size, getter, type_index, getter_ordinal)
        if not vm_read(self, vm, rva, family.split('.')[0], verify=expected):
            raise InputError('consumed VM source edge differs from its qualified family')
        if family.startswith('O10') and cursor[0] == 66417:
            pending = vm.pending_once10
            if (cursor[:3] != (66417, 1659, 0x157E55C6) or vm.pc != 66422 or size != 8 or getter != 0x35D9FDA or
                    pending is None or pending[2].operands != (7, None, 8862, 8863)):
                raise InputError('consumed tail O10 requires actual None operand and type8 result')
        return self._read(row[2], cursor, vm.pc, family, rva, posts, class_post, vm,
                          size=size, getter=getter, type_index=type_index, getter_ordinal=getter_ordinal).value

    def _read(self, ordinal, cursor, pc, family, rva, posts, class_post, vm, *, host=0, phase='', size=0, getter=0, type_index=0, getter_ordinal=0, block_pointer=0, helper_ordinal=0):
        kind = family.rsplit('.', 1)[-1]
        if kind not in ('M', 'G', 'F') or rva not in _GLOBALS:
            raise InputError('consumed family is outside the source equivalence domain')
        slot = 0 if kind == 'M' or rva in (0x6D86090, 0x677E1B4) else 1
        if kind == 'M' and rva != 0x677E1BC or kind == 'G' and rva not in _GLOBALS[:2] or kind == 'F' and rva not in _GLOBALS[2:4]:
            raise InputError('consumed load slot does not belong to its predicate')
        if slot == 0:
            vm._mgf_iteration += 1
        key = ConsumerKey(ordinal, cursor[0], cursor[2], cursor[1], pc, family, vm._mgf_iteration,
                          slot, posts[slot], host, phase, size, getter, type_index, getter_ordinal, block_pointer, helper_ordinal)
        if slot == 1 and self._pair is not None:
            first = self._pair[1]
            if (first.program, first.word, first.block, first.opcode, first.pc, first.family, first.iteration, first.host, first.phase, first.size, first.getter_post, first.type_index, first.getter_ordinal, first.block_pointer, first.helper_ordinal) != (key.program, key.word, key.block, key.opcode, key.pc, key.family, key.iteration, key.host, key.phase, key.size, key.getter_post, key.type_index, key.getter_ordinal, key.block_pointer, key.helper_ordinal):
                raise InputError('consumed second operand belongs to another predicate')
        if slot == 1 and self._pair is not None and self._pair[0] == 'class':
            _, first, value = self._pair
            expected = (first.program, first.word, first.opcode, first.block, first.family,
                        first.iteration, first.host, first.phase, first.size, first.getter_post)
            actual = (key.program, key.word, key.opcode, key.block, key.family,
                      key.iteration, key.host, key.phase, key.size, key.getter_post)
            if expected != actual:
                raise InputError('consumed class second edge has another owner/site')
            self._pair = None
            origin = 'CLASS_REPRESENTATIVE'
        else:
            if slot == 0 and self._pair is not None or slot == 1 and self._pair is None:
                raise InputError('consumed predicate pair is incomplete or out of order')
            event = self._events.next()
            if event is None or type(event) is not list or len(event) not in (3, 5):
                raise InputError('consumed predicate evidence exhausted or malformed')
            try:
                actual_key = ConsumerKey(**event[1])
            except (TypeError, ValueError) as error:
                raise InputError('consumed predicate key is malformed') from error
            if actual_key != key:
                raise InputError('consumed predicate key differs from actual consumer')
            if event[0] == 'raw' and len(event) == 3 and _u32(event[2]):
                value = event[2]
                origin = 'RAW_OBSERVED'
                if kind != 'M':
                    self._pair = ('raw', key, None) if slot == 0 else None
            elif event[0] == 'class' and len(event) == 5 and slot == 0:
                if event[3] != class_post or tuple(event[4]) != tuple(posts):
                    raise InputError('consumed class witness lacks ordered producer edges')
                if posts == (0x3592DEB,):
                    raise InputError('source pre-store M requires its raw DWORD')
                values = representative(kind, event[2])
                value = values[0]
                origin = 'CLASS_REPRESENTATIVE'
                if kind != 'M':
                    self._pair = ('class', key, values[1])
            else:
                raise InputError('consumed predicate origin is not qualified')
        self.origins[origin] += 1
        return ReplayOperand(value, origin, key)

    def verify_iv_normal_domain(self, vm, context, iv):
        runtime = self._runtime
        row = self._vms.get(id(vm))
        owner = runtime._active_main
        if (self.closed or get_ident() != self._thread or row is None or row[0] is not vm or
                vm.runtime is not runtime or owner is None or owner['thread'] != get_ident() or
                owner['generation'] != self._model_generation or owner['vm'] is vm or
                not runtime._program_calls or runtime._program_calls[0] is not self._root or
                runtime._program_calls[-1] is not row[1] or row[1]['name'] != 'ecrypt-transform' or
                not isinstance(row[3], NormalReaderCertificate) or vm.private_iv_native_pending is None or
                self._iv_pending is not None):
            raise InputError('private IV domain lacks actual nested reader/root/thread/generation')
        address, cells, signature, argument_types, record = vm.private_iv_native_pending
        cursor = vm._mgf_cursor
        if (cursor is None or cursor[:3] != (240, record.block, 0x014A3DB9) or vm.pc != 247 or
                address != runtime.image_base + 0x2DE215D or signature != 25 or tuple(argument_types) != (14, 2) or
                vm.program.type(25).parameters != (0, 20, 2, 14, 2) or vm.program.type(20).raw != 2 or
                cells != (8, 51) or record.operands != (25, 0, 61, 0, 8, 51) or
                vm.cells.value(61) != address or vm.cells.value(8) != context or vm.cells.value(51) != iv or
                not vm.host_calls or vm.host_calls[-1] != (240, address, cells, 25)):
            raise InputError('private IV domain differs from actual word240/void25 pending call')
        self._iv_ordinal += 1
        invocation = self._iv_ordinal
        self._iv_pending = (vm, record, invocation, context, iv)
        try:
            bits = runtime.memory.load(context + 0x110, 4)
            flag = runtime.memory.load(context + 0x10C, 1)
            if bits not in (128, 256):
                raise PrimaryProgramLimit('private IV domain requires model-derived key bits128/256')
            for phase, kind, posts, classified in iv_normal_sites(flag, bits):
                values = []
                rvas = (0x677E1BC,) if kind == 'M' else ((0x6D86090, 0x6D86094) if kind == 'G' else (0x677E1B4, 0x677E1B8))
                for rva in rvas:
                    values.append(self._read(row[2], cursor, vm.pc, 'ecrypt.iv.' + kind, rva, posts,
                                             classified, vm, host=0x2DE215D, phase=phase, size=bits,
                                             helper_ordinal=invocation).value)
                if predicate(kind, tuple(values)):
                    raise PrimarySemanticUnavailable('UNSUPPORTED_IV_NONNORMAL')
        finally:
            self._iv_pending = None

    def finish_main(self, vm):
        if (self._pair is not None or vm._mgf_cursor is not None or not vm.halted or
                any(getattr(vm, name) is not None for name in ('pending_native', 'private_iv_native_pending', 'pending_l26', 'pending_once9', 'pending_once10', 'pending_variadic')) or
                self._runtime._host2252_pending is not None):
            raise InputError('consumed main has pending source state')
        if self._reader_index != len(self._readers) or self._events.next() is not None:
            raise InputError('consumed completed main has remaining or malformed evidence')
        self.complete = True

    def compare_result(self, model_count, model_output, native_output_view):
        if not self.complete or self.closed or not _u32(model_count) or model_count > 128:
            raise InputError('consumed comparison requires completed actual model output')
        args = self._identity.main_arguments
        memory = self._runtime.memory
        model = memoryview(model_output)
        if model.ndim != 1 or model.itemsize != 1 or not model.c_contiguous or len(model) != model_count:
            raise InputError('consumed comparison model extent is invalid')
        if memory.load(args[8], 4) != model_count or memory.read(args[7], model_count) != model.tobytes():
            raise InputError('consumed comparison input is not actual source model output')
        if type(native_output_view) is Main96DigestReference:
            return Comparison(model_count, native_output_view.count,
                              model_count == native_output_view.count and
                              _main96_digest(model) == native_output_view.digest)
        native = memoryview(native_output_view)
        if native.ndim != 1 or native.itemsize != 1 or not native.c_contiguous or len(native) > 128:
            raise InputError('consumed comparison native output extent is invalid')
        return Comparison(model_count, len(native), model_count == len(native) and model.tobytes() == native.tobytes())

    def close(self, reason=None):
        if self.closed:
            return
        self.closed = True
        if self._events is not None:
            self._events.close()
        if self._history_lease is not None:
            if type(self._encoded) is memoryview:
                self._encoded.release()
            self._readers.clear()
            self._inputs = ()
            self._encoded = bytearray()
            self._events = self._identity = self._root = self._pair = None
            self._vms.clear()
            self._verified_readers.clear()
            self._stateful_attempts.clear()
            self._stateful_programs.clear()
            self._stateful_failure = None
            self._calls.clear()
            self._input_masks = None
            lease, self._history_lease = self._history_lease, None
            lease._released(self.complete)
            return
        for row in self._readers:
            if type(row.observations) is memoryview:
                row.observations.release()
        self._readers.clear()
        if type(self._encoded) is memoryview:
            backing = self._encoded.obj
            self._encoded.release()
            _clear_chunks(backing)
        else:
            _clear_chunks(self._encoded)
            self._encoded.clear()
        if self._reader_slab is not None:
            _clear_chunks(self._reader_slab)
        for view in self._inputs:
            _clear_chunks(view)
        self._inputs = ()
        self._encoded = bytearray()
        self._reader_slab = None
        self._events = self._identity = self._root = self._pair = None
        self._vms.clear()
        self._verified_readers.clear()
        self._stateful_attempts.clear()
        self._stateful_programs.clear()
        self._stateful_failure = None
        self._iv_pending = None
        self._calls.clear()


def vm_read(replay, vm, rva, family, *, verify=None):
    from .primary_vm import once_index
    cursor = vm._mgf_cursor
    if cursor is None:
        raise InputError('consumed VM source family has no inflight cursor')
    raw, low = cursor[2:4]
    generic = ((raw >> 24) & 0xF0) | (raw & 15)
    qualified = ((family == 'L26' and low == 26 and vm.pending_l26 is not None) or
                 (family == 'class3' and low is None and generic == 3 and vm.pc == cursor[0] + 1) or
                 (family == 'class6' and low is None and generic == 6 and vm._mgf_flag == 0) or
                 (family == 'O9' and low is None and vm.pending_once9 is not None and once_index(raw) == 9) or
                 (family == 'O10' and low is None and vm.pending_once10 is not None and once_index(raw) == 10) or
                 (family == 'variadic' and raw == 0x01024A6A and vm.pending_variadic is not None))
    if not qualified:
        raise InputError('consumed VM family does not match actual opcode/pending state')
    kind = 'M' if rva == 0x677E1BC else ('G' if rva in _GLOBALS[:2] else 'F')
    size = getter = 0
    if family == 'class3' and kind == 'G':
        posts, classified = (0x35DC136, 0x35DC13C), 0x35DC14B
    elif family == 'class6' and kind == 'M':
        posts, classified = (0x35DC4DC,), 0x35DC4E8
    elif family == 'L26' and kind == 'G':
        posts, classified = (0x35DF718, 0x35DF71E), 0x35DF72D
    elif family == 'L26' and kind == 'F':
        size = vm._mgf_width
        edges = {1: (0x35DD8DF, 0x35DD8EC, 0x35DD902),
                 2: (0x35DD936, 0x35DD943, 0x35DD959),
                 4: (0x35DD97C, 0x35DD989, 0x35DD99F),
                 8: (0x35DD9BD, 0x35DD9CA, 0x35DD9E0)}
        if size not in edges:
            raise PrimarySemanticUnavailable('consumed L26 width has no qualified source edge')
        x, y, classified = edges[size]
        posts = (x, y)
    elif family == 'variadic':
        stage = vm._mgf_stage
        edges = {
            ('entry', 'M'): ((0x35DD305,), 0x35DD311),
            ('header-nonvoid', 'F'): ((0x35DDB67, 0x35DDB74), 0x35DDB97),
            ('header-void', 'F'): ((0x35DDBAA, 0x35DDBB7), 0x35DDBD4),
            ('callee', 'G'): ((0x35DFF14, 0x35DFF1A), 0x35DFF2C),
            ('prepare-G', 'G'): ((0x35DDD81, 0x35DDD87), 0x35DDD96),
            ('prepare-F', 'F'): ((0x35E017F, 0x35E018C), 0x35E01AE),
            ('postcall', 'M'): ((0x35E03A8,), 0x35E03B4),
            ('store', 'M'): ((0x35DF910,), 0x35DF91C),
        }
        if (stage, kind) not in edges:
            raise PrimarySemanticUnavailable('consumed variadic phase/source edge is unsupported')
        posts, classified = edges[stage, kind]
        family += '.' + stage
    elif family == 'O9' and kind == 'F':
        posts, classified = (0x35D9ABE, 0x35D9ACB), 0x35D9AE1
        size, getter = vm._mgf_width, vm._mgf_getter_post
    elif family == 'O10':
        size = vm._mgf_width
        getter = 0x35D9FDA
        stage = vm._mgf_stage
        if kind == 'F' and size >= 4:
            posts, classified = (0x35D9FF2, 0x35D9FFF), 0x35DA015
        elif kind == 'F' and size == 1:
            posts, classified = (0x35DA049, 0x35DA056), 0x35DA06C
        elif kind == 'M' and stage in ('M1', 'M2', 'M3'):
            post, classified = {'M1': (0x35DA1DA, 0x35DA1E6),
                                'M2': (0x35DA247, 0x35DA253),
                                'M3': (0x35DA084, 0x35DA090)}[stage]
            posts = (post,)
            family += '.' + stage
        else:
            raise PrimarySemanticUnavailable('consumed O10 nonstandard width/source edge is unsupported')
    else:
        raise PrimarySemanticUnavailable('consumed VM family/source edge is unsupported')
    type_index = vm._mgf_type if family == 'O9' else 0
    getter_ordinal = vm._mgf_getter_ordinal if family == 'O9' else 0
    request = (family + '.' + kind, tuple(posts), classified, size, getter, type_index, getter_ordinal)
    if verify is not None:
        return request == verify
    return replay.read_vm(vm, rva, request[0], posts, classified, size=size, getter=getter,
                          type_index=type_index, getter_ordinal=getter_ordinal)


def host_read(state, rva, posts, classified, family):
    replay = getattr(state.memory, '_consumed_mgf_guard', None)
    if replay is None:
        return state.memory.load(state.image_base + rva, 4)
    runtime = replay._runtime
    pending = runtime._host2252_pending
    vm = pending['vm'] if pending is not None else None
    owner = runtime._active_main
    if (pending is None or state not in tuple(pending.values()) or vm is None or owner is None or
            owner['thread'] != get_ident() or replay._thread != get_ident() or owner['vm'] is not vm or
            owner['generation'] != replay._model_generation or pending['pointer'] != state.pointer or
            runtime._program_calls[0] is not replay._root or vm.pending_native is None):
        raise InputError('consumed host read lacks actual pending root/thread/generation/state')
    address, cells, signature, argument_types, record = vm.pending_native
    cursor = vm._mgf_cursor
    if (address != runtime.image_base + 0x359253D or signature != 205 or len(cells) != 1 or
            pending['cells'] != cells or vm.cells.value(cells[0]) != state.pointer or
            cursor is None or (record.word, record.block, record.raw_opcode) != cursor[:3] or
            not vm.host_calls or vm.host_calls[-1] != (record.word, address, cells, signature) or
            runtime._program_calls[-1] is not replay._root):
        raise InputError('consumed host read differs from its actual void205 call')
    if not all(getattr(runtime, name) for name in ('host2252_stage1_retry', 'host2252_control_m',
            'host2252_pair_m_retry', 'host2252_stage2_g_retry', 'host2252_final_f_retry')):
        raise InputError('consumed host2252 requires all source predicate paths enabled')
    row = replay._vms.get(id(vm))
    if row is None or row[0] is not vm:
        raise InputError('consumed host VM was not attached by execute')
    phase = state.phase
    if phase.endswith(('_x', '_y')):
        phase = phase[:-2]
    return replay._read(row[2], cursor, vm.pc, 'host2252.' + family, rva, posts, classified,
                        vm, host=0x359253D, phase=phase, block_pointer=state.pointer).value


def iv_normal_sites(flag, bits):
    if type(flag) is not int or not 0 <= flag <= 255 or bits not in (128, 256):
        raise InputError('private IV source state is invalid')
    sites = {
        'M261F': ('M', (0x2DE2625,), 0x2DE262E),
        'M2F52': ('M', (0x2DE2F58,), 0x2DE2F61),
        'M30F4': ('M', (0x2DE30FA,), 0x2DE3103),
        'F2704': ('F', (0x2DE270A, 0x2DE2717), 0x2DE272A),
        'F27D2': ('F', (0x2DE27D8, 0x2DE27E5), 0x2DE27F8),
        'F2903': ('F', (0x2DE2909, 0x2DE2916), 0x2DE2929),
        'F30B2': ('F', (0x2DE30B8, 0x2DE30C5), 0x2DE30D8),
        'G28B3': ('G', (0x2DE28B9, 0x2DE28BF), 0x2DE28CB),
        'G2FC8': ('G', (0x2DE2FCE, 0x2DE2FD4), 0x2DE2FE0),
        'G31A9': ('G', (0x2DE31AF, 0x2DE31B5), 0x2DE31C1),
    }
    phases = []
    if flag == 0:
        phases = ['M30F4', 'F2704'] + ['F2903', 'F27D2'] * 32
    phases += ['F30B2']
    phases += ['G2FC8', 'G28B3'] * 4 + ['M261F'] if bits == 128 else ['G31A9', 'M2F52'] * 8
    for phase in phases:
        kind, posts, classified = sites[phase]
        yield phase, kind, posts, classified
