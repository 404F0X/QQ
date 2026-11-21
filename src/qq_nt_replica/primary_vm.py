"""The fixed QQ52230 primary program's packed reader and execution state.

The stream is little bit first, with six-bit groups and five payload bits.
This is not LEB128. Native shift masking, duplicate OR bits, trailing bits,
24-byte cells, and partial-width writes are intentional.
"""

from dataclasses import dataclass

from .errors import CapabilityUnavailable, InputError, LibraryLimitError
from .primary_memory import PrimaryCells, PrimaryMemory


class PrimaryProgramLimit(LibraryLimitError):
    """This offline reader cannot represent a native exceptional input."""


class PrimarySemanticUnavailable(CapabilityUnavailable):
    """A needed native semantic has no implemented, source-bound equivalent."""


class PrimaryExecutionPaused(PrimaryProgramLimit):
    pass


class PackedBits:
    def __init__(self, raw: bytes):
        if not isinstance(raw, bytes):
            raise InputError("packed program must be bytes")
        self.raw = raw
        self.position = 0

    def bits(self, count: int) -> int:
        if type(count) is not int or count < 0:
            raise InputError("packed bit count must be a nonnegative integer")
        if self.position + count > 8 * len(self.raw):
            raise PrimaryProgramLimit(
                f"packed program ends at bit {self.position}; native short-read is fatal, not a zero value"
            )
        value = 0
        for bit in range(count):
            cursor = self.position + bit
            value |= ((self.raw[cursor >> 3] >> (cursor & 7)) & 1) << bit
        self.position += count
        return value

    def integer(self, width: int = 32) -> int:
        if width not in (32, 64):
            raise InputError("packed integer width must be 32 or 64")
        value, shift = 0, 0
        while True:
            group = self.bits(6)
            value |= ((group & 31) << (shift & (width - 1))) & ((1 << width) - 1)
            if not group & 32:
                return value
            shift = (shift + 5) & 0xFFFFFFFF


@dataclass(frozen=True)
class VMType:
    raw: int
    parameters: tuple[int, ...] = ()


@dataclass(frozen=True)
class VMConstant:
    cell: int
    code: int
    parameters: tuple[int, ...]
    bit_begin: int
    bit_end: int


@dataclass(frozen=True)
class PackedProgram:
    raw: bytes
    cell_count: int
    constant_cells: tuple[int, ...]
    host_cells: tuple[int, ...]
    types: tuple[VMType, ...]
    constants: tuple[VMConstant, ...]
    entry_type: int
    words: tuple[int, ...]
    jumps: tuple[int, ...]
    descriptor: int
    consumed_bits: int

    def type(self, index: int) -> VMType:
        if not 0 <= index < len(self.types):
            raise PrimaryProgramLimit(f"type index {index} outside the decoded type vector")
        return self.types[index]

    def size(self, index: int) -> int:
        typ = self.type(index)
        if typ.raw == 7:
            bits = typ.parameters[0]
            return 1 if bits < 8 else bits >> 3
        if typ.raw in (8, 0x15):
            return 8
        if typ.raw == 2:
            return 0
        if typ.raw in (3, 4):
            return 4 if typ.raw == 3 else 8
        if typ.raw in (0xB, 0xC):
            size = typ.parameters[0] * self.size(typ.parameters[1])
            if size > 0x7FFFFFFF:
                raise PrimaryProgramLimit("array size exceeds Python's nonwrapping layout support domain")
            return size
        if typ.raw in (6, 0x12, 0x14):
            return self.layout(index)[1]
        raise PrimarySemanticUnavailable(f"size of raw type {typ.raw:#x} is not implemented")

    def alignment(self, index: int) -> int:
        typ = self.type(index)
        if typ.raw in (7, 8, 0x15):
            return self.size(index)  # native v10 tailcalls this type's v20
        if typ.raw in (0xB, 0xC):
            return self.alignment(typ.parameters[1])
        if typ.raw in (6, 0x12, 0x14):
            if typ.parameters[0] == 1:
                return 1
            children = typ.parameters[2:2 + typ.parameters[1]]
            return max((self.alignment(child) for child in children), default=0)
        raise PrimarySemanticUnavailable(f"alignment of raw type {typ.raw:#x} is not implemented")

    def layout(self, index: int) -> tuple[tuple[int, ...], int]:
        """35A17BA normal nonoverflow struct offsets and final aligned size."""
        typ = self.type(index)
        if typ.raw not in (6, 0x12, 0x14):
            raise InputError("layout requires a compiled struct type")
        offsets, size, largest = [], 0, 0
        packed = typ.parameters[0] == 1
        for child in typ.parameters[2:2 + typ.parameters[1]]:
            alignment = 1 if packed else self.alignment(child)
            if alignment < 1 or alignment & (alignment - 1):
                raise PrimaryProgramLimit("zero/non-power-of-two alignment outside Python layout domain")
            size = (size + alignment - 1) & -alignment
            offsets.append(size)
            size += self.size(child)
            largest = max(largest, alignment)
            if size > 0x7FFFFFFF:
                raise PrimaryProgramLimit("struct layout exceeds Python nonwrapping support domain")
        largest = largest or 1
        size = (size + largest - 1) & -largest
        return tuple(offsets), size


def decode_program(raw: bytes) -> PackedProgram:
    """Decode compiled syntax; this does not execute or certify the program."""
    return _decode_program(raw, PackedBits(raw))


def _decode_program(raw, stream):
    integer = stream.integer
    count = integer()
    if not 0 < count <= 0xFFFF:
        raise PrimaryProgramLimit("cell count outside Python's positive normal reader domain")
    constant_cells = tuple(integer() for _ in range(integer()))
    host_cells = tuple(integer() for _ in range(integer()))
    type_count = integer()
    if type_count > 0xFFFF:
        raise PrimaryProgramLimit("type count outside Python normal reader domain")
    types = []
    for _ in range(type_count):
        raw_type = integer()
        fields = []
        if raw_type in (7, 8):
            fields.append(integer())
        elif raw_type == 0x15:
            fields.extend((integer(), integer(), integer()))
            fields.extend(integer() for _ in range(fields[2]))
        elif raw_type in (6, 0x12, 0x14):
            fields.extend((integer(), integer()))
            fields.extend(integer() for _ in range(fields[1]))
            if raw_type != 0x12:
                fields.append(integer())
                fields.extend(integer() for _ in range(fields[-1]))
        elif raw_type in (0xB, 0xC):
            fields.extend((integer(), integer()))
        types.append(VMType(raw_type, tuple(fields)))
    constants = []
    constant_count = integer()
    if constant_count > len(constant_cells):
        raise PrimaryProgramLimit("constant records exceed their mapped cell-index vector")
    for index in range(constant_count):
        begin = stream.position
        code = integer()
        fields = []
        if code == 2:
            fields.append(integer())
        elif code == 4:
            fields.append(integer(64))
        elif code == 6:
            fields.extend((integer(), integer(64)))
        elif code in (5, 7):
            fields.append(integer())
            fields.extend(integer(64) for _ in range(fields[0]))
        elif code in (8, 9):
            fields.append(integer())
            fields.extend(integer() for _ in range(fields[0]))
        elif code in (10, 11, 13, 16):
            fields.extend(integer() for _ in range(3))
        elif code in (14, 15, 17, 19):
            fields.extend(integer() for _ in range(4))
        elif code in (12, 20, 24):
            fields.append(integer())
            if code == 24:
                fields.append(integer(64))
            length = integer()
            fields.append(length)
            fields.extend(integer() for _ in range(length))
        elif code == 21:
            fields.append(integer())
        elif code == 22:
            type_index, length = integer(), integer()
            fields.extend((type_index, length))
            # Element size is resolved only after the complete type vector exists.
            temporary = PackedProgram(raw, count, (), (), tuple(types), (), 0, (), (), 0, 0)
            width = 64 if temporary.size(type_index) not in (1, 2, 4) else 32
            fields.extend(integer(width) for _ in range(length))
        elif code not in (0, 1, 3, 18, 23):
            raise PrimarySemanticUnavailable(f"unknown constant grammar {code} at bit {begin}")
        constants.append(VMConstant(constant_cells[index], code, tuple(fields), begin, stream.position))
    entry_type = integer()
    words = tuple(integer() for _ in range(integer()))
    jumps = tuple(integer() for _ in range(integer()))
    descriptor = integer()
    return PackedProgram(raw, count, constant_cells, host_cells, tuple(types), tuple(constants),
                         entry_type, words, jumps, descriptor, stream.position)


class StatefulPackedBits(PackedBits):
    def __init__(self, reader):
        self.reader = reader
        self.position = 0
        from hashlib import sha256
        self.groups = sha256()

    def bits(self, count):
        if count != 6:
            raise InputError('stateful packed reader requires six-bit requests')
        value = self.reader.six()
        self.position += 6
        self.groups.update(bytes((value,)))
        return value


class StatefulProgramFailure(PrimaryProgramLimit):
    def __init__(self, reason, prefix, logical_position):
        super().__init__(reason)
        self.reason = reason
        self.prefix = prefix
        self.logical_position = logical_position


def decode_program_stateful(raw, reader):
    from .primary_consumed_mgf import BoundedCommitReader, CommitReaderFailure
    if (type(raw) is not bytes or type(reader) is not BoundedCommitReader or reader.raw != raw or
            reader.failed or reader.closed or reader.requests or reader.refills or reader.index or reader.offset or
            (reader.C, reader.V, reader.s) != reader.initial_state):
        raise InputError('stateful decoder requires its fresh actual raw-bound reader')
    stream = StatefulPackedBits(reader)
    try:
        program = _decode_program(raw, stream)
        result = reader.finish()
    except CommitReaderFailure as error:
        error.logical_position = stream.position
        raise
    except (InputError, PrimaryProgramLimit, PrimarySemanticUnavailable) as error:
        reader.failed = True
        raise StatefulProgramFailure(str(error), reader.snapshot(), stream.position) from error
    return program, result, stream.groups.hexdigest()


BASE_OPCODES = (
    0x12F4, 0x14B7, 0x16C8, 0x18A4, 0x1A6E, 0x1D35, 0x20F6, 0x23C5,
    0x27A9, 0x2913, 0x2F19, 0x32E1, 0x35DE, 0x3A5C, 0x3D84, 0x4459,
    0x4752, 0x48AE, 0x4F68, 0x52C9, 0x54D3, 0x58E1, 0x5B04, 0x5E7A,
    0x63F1, 0x67C2, 0x698F, 0x6B19, 0x6D03, 0x6EAF, 0x71B5, 0x749A,
    0x79D2, 0x7A12,
)


def jump_key(seed: int, block: int) -> int:
    value = 0x243F6A88
    for byte in ((seed + block) & 0xFFFFFFFF).to_bytes(4, "big"):
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value & 0xFFFF


def signed(value: int, width: int) -> int:
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


@dataclass(frozen=True)
class VMRecord:
    word: int
    block: int
    raw_opcode: int
    low_index: int | None
    operands: tuple[int | None, ...]


# These are actual 35DB91C/once record grammars, not inferred LLVM names.
_HIGH_ARITIES = {
    0x157E2A3B: 4, 0x157E55C6: 4, 0x13A8C245: 4,
    0x0585D62D: 4, 0x0E0C42B0: 4, 0x1715D75D: 4,
    0x17A2049E: 4, 0x080A22B1: 4, 0x040D3EC6: 5,
    0x06410FC7: 3, 0x0D031CB8: 3,
}
_HIGH_CLASS_ARITIES = {0: 4, 1: 4, 2: 4, 3: 4, 4: 4, 5: 4, 6: 5, 7: 3, 8: 3}
_LOW_ARITIES = {
    0: 0, 3: 2, 4: 2, 5: 3, 6: 3, 7: 6, 11: 0, 12: 2, 13: 4, 14: 4,
    15: 4, 16: 4, 17: 4, 18: 4, 19: 4, 20: 4, 21: 4, 24: 4, 25: 4, 26: 4,
    27: 4, 29: 4, 30: 4, 31: 4, 32: 1, 33: 3,
}


def record_at(program: PackedProgram, word: int, block: int, *, initial: bool = False) -> VMRecord:
    """Read one ordinary record. Unknown grammar fails with its real location."""
    if not 0 <= word < len(program.words):
        raise PrimaryProgramLimit(f"instruction word {word} outside program")
    raw = program.words[word]
    low = None
    if raw < 0x100000:
        opcode = raw ^ (0 if initial else jump_key(program.words[0], block))
        try:
            low = BASE_OPCODES.index(opcode)
        except ValueError as exc:
            raise PrimarySemanticUnavailable(
                f"unbound low opcode {raw:#x} at word {word}, block {block}"
            ) from exc
        if low == 8:
            if word + 3 >= len(program.words):
                raise PrimaryProgramLimit("switch record ends before its pair count")
            arity = 3 + 2 * program.words[word + 3]
        elif low == 9:
            if word + 2 >= len(program.words):
                raise PrimaryProgramLimit("PHI record ends before its pair count")
            arity = 2 + 2 * program.words[word + 2]
        else:
            arity = _LOW_ARITIES.get(low)
    elif raw == 0x0F0E596B:
        # 35E09E0: dest, nominal flag, source type, operand-vector count.
        if word + 4 >= len(program.words):
            raise PrimaryProgramLimit("indexed pointer record ends before its count")
        arity = 4 + program.words[word + 4]
    elif raw == 0x014A3DB9:
        if word + 1 >= len(program.words):
            raise PrimaryProgramLimit("native call ends before its signature")
        typ = program.type(program.words[word + 1])
        if typ.raw == 8:
            typ = program.type(typ.parameters[0])
        if typ.raw != 0x15:
            raise PrimaryProgramLimit("native call signature is not a compiled function type")
        # The result cell is absent for a void signature (35DD271/35DE442).
        arity = 4 + int(program.type(typ.parameters[1]).raw != 2) + typ.parameters[2]
    elif (((raw >> 24) & 0xF0) | (raw & 15)) == 10:
        if word + 2 >= len(program.words):
            raise PrimaryProgramLimit("variadic call ends before its argument count")
        typ = program.type(program.words[word + 1])
        if typ.raw != 0x15 or typ.parameters[0] != 1:
            raise PrimarySemanticUnavailable("variadic call needs an actual variadic function type")
        count, fixed = program.words[word + 2], typ.parameters[2]
        if not fixed <= count <= 0xFFFF:
            raise PrimaryProgramLimit("variadic argument count outside normal Python FFI domain")
        arity = 5 + int(program.type(typ.parameters[1]).raw != 2) + fixed + 2 * (count - fixed)
    else:
        arity = _HIGH_ARITIES.get(raw, _HIGH_CLASS_ARITIES.get(((raw >> 24) & 0xF0) | (raw & 15)))
        if arity is None and 12 <= (((raw >> 24) & 0xF0) | (raw & 15)) <= 32:
            once_index(raw)
            arity = 4
    if arity is None:
        raise PrimarySemanticUnavailable(
            f"record grammar unavailable for {'L' + str(low) if low is not None else hex(raw)} "
            f"at word {word}, block {block}"
        )
    if word + 1 + arity > len(program.words):
        raise PrimaryProgramLimit(f"record at word {word} exceeds program words")
    return VMRecord(word, block, raw, low, program.words[word + 1:word + 1 + arity])


def decode_records(program: PackedProgram) -> tuple[VMRecord, ...]:
    """Decode ordinary static records, retaining original jump-index identity."""
    targets = {}
    for index, target in enumerate(program.jumps):
        if target in targets:
            raise PrimaryProgramLimit("duplicate block starts need an explicit runtime predecessor")
        targets[target] = index
    records, word, block, initial = [], 1, 0, True
    while word < len(program.words):
        if word in targets and word != 1:
            block, initial = targets[word], False
        record = record_at(program, word, block, initial=initial)
        records.append(record)
        word += 1 + len(record.operands)
    return tuple(records)


def once_index(raw: int) -> int:
    """35DC34A encoded high-op validation and actual 21-entry index."""
    middle = (raw >> 4) & 0xFFFFFF
    if not 0x100000 <= middle <= 0x7FFFFF:
        raise PrimarySemanticUnavailable(f"invalid encoded once opcode {raw:#x}")
    a = ((raw >> 7) & 1) | ((raw >> 10) & 2) | ((raw >> 13) & 4)
    b = ((raw >> 9) & 1) | ((raw >> 12) & 2) | ((raw >> 15) & 4)
    if b != a ^ 5:
        raise PrimarySemanticUnavailable(f"encoded once check bits fail for {raw:#x}")
    encoded = a | ((raw >> 16) & 8) | ((raw >> 19) & 16)
    index = (5 * encoded + 125) & 31
    if index >= 21:
        raise PrimarySemanticUnavailable(f"encoded once index {index} outside its 21 entries")
    return index


class PrimaryVM:
    """Source-bound scalar bodies on explicit current memory and actual cells.

    ``step`` is an instruction-body interface. It does not claim to emulate the
    SDK's obfuscated dispatch, current encoded-handler replacement or exception
    wrappers. A missing body stops before inventing a result; committed memory
    and PC remain available. Absolute addresses are explicit because this
    program also computes with pointer values.
    """

    def __init__(self, program: PackedProgram, memory: PrimaryMemory, *, cells_address: int,
                 arena_address: int, arena_size: int, image_base: int = 0x180000000,
                 runtime=None, scalar_sse_state=None):
        if type(arena_size) is not int or not 0 <= arena_size <= 0x7FFFFFFF:
            raise PrimaryProgramLimit("arena size outside Python nonwrapping support domain")
        if type(image_base) is not int or not 0 <= image_base < (1 << 64):
            raise InputError("image base must be unsigned64")
        self.program, self.memory = program, memory
        self.image_base = image_base
        self.runtime = runtime
        from .primary_x86_float import ScalarSSEState
        if scalar_sse_state is not None and type(scalar_sse_state) is not ScalarSSEState:
            raise InputError("VM scalar SSE state requires explicit ScalarSSEState or unknown None")
        self.scalar_sse_state = scalar_sse_state
        self.cells = PrimaryCells(memory, cells_address, program.cell_count + 1)
        self.arena_address, self.arena_size, self.arena_used = arena_address, arena_size, 0
        self.pc, self.block, self.predecessor, self.initial_block = 1, 0, None, True
        self.auxiliary = None
        self.trace = []
        self.host_calls = []
        self.result = None
        self.halted = False
        self.pending_once10 = None
        self.pending_once9 = None
        self.pending_l26 = None
        self.pending_variadic = None
        self.pending_native = None
        self.private_iv_native_pending = None
        self.abort_reason = None
        self.main_owned_allocations = []
        self._mgf_cursor = None
        self._mgf_iteration = 0
        self._mgf_width = 0
        self._mgf_stage = None
        self._mgf_flag = None
        self._mgf_type = 0
        self._mgf_getter_ordinal = 0
        self._mgf_getter_post = 0

    def _mgf_finish(self, record):
        replay = getattr(self.runtime, '_consumed_mgf', None)
        if replay is not None:
            replay.finish_record(self, record)

    def _mgf_load(self, rva, family):
        replay = getattr(self.runtime, '_consumed_mgf', None)
        if replay is None:
            return self.memory.load(self.image_base + rva, 4)
        from .primary_consumed_mgf import vm_read
        return vm_read(replay, self, rva, family)

    def _resume_native(self):
        if type(self.pending_native) is not tuple:
            from .primary_main_rest import _DirectM16Pending
            if type(self.pending_native) is _DirectM16Pending:
                return self.pending_native.resume(self)
        address, arguments, signature, argument_types, record = self.pending_native
        from .primary_sign import _invoke_host
        _invoke_host(self, address, arguments, signature, argument_types=argument_types)
        self.pending_native = None
        self.trace.append(record)
        self._mgf_finish(record)
        return record

    def _l26_compare(self, operands):
        group = tuple(self._operand() for _ in range(4))
        operands.extend(group)
        typ, left, right, destination = group
        left = self.cells.pointer(left)
        right = self.cells.pointer(right)
        destination = self.cells.pointer(destination)
        size = self.program.size(typ)
        self._mgf_width = size
        a = self.memory.load(left, size if size in (1, 2, 4) else 8, signed=True)
        size = self.program.size(typ)
        b = self.memory.load(right, size if size in (1, 2, 4) else 8, signed=True)
        self.memory.store(destination, int(a == b), 4, source="L26.comparison")

    def _l26(self, operands):
        x = yield 0x6D86090
        y = signed((yield 0x6D86094), 32)
        if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
            self._l26_compare(operands)
        while True:
            self._l26_compare(operands)
            x = signed((yield 0x677E1B4), 32)
            y = signed((yield 0x677E1B8), 32)
            if not ((((x * x + y * y) & 0xFFFFFFFF) |
                     ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31):
                return
            self._l26_compare(operands)

    def _resume_l26(self, budget):
        for _ in range(budget):
            execution, address, record, operands = self.pending_l26
            try:
                value = self._mgf_load(address, 'L26')
            except BaseException:
                self.pending_l26 = None
                execution.close()
                raise
            try:
                address = execution.send(value)
            except StopIteration:
                self.pending_l26 = None
                record = VMRecord(*record, tuple(operands))
                self.trace.append(record)
                self._mgf_finish(record)
                return record
            except BaseException:
                self.pending_l26 = None
                execution.close()
                raise
            self.pending_l26 = (execution, address, record, operands)
        raise PrimaryExecutionPaused("L26 global-read budget exhausted; pending body may resume")

    def _variadic_skip(self, count, operands):
        self.pc = (self.pc + count) & 0xFFFFFFFF
        operands.extend((None,) * count)

    def _variadic_return_size(self, result_type):
        if self.program.type(result_type).raw == 7:
            self.program.size(result_type)
        self.program.size(result_type)

    def _variadic_arguments(self, operands, state):
        self._mgf_stage = 'entry'
        if (yield 0x677E1BC) == 0x80000000:
            self._variadic_skip(3, operands)
        signature = self._operand()
        operands.append(signature)
        typ = self.program.type(signature)
        if typ.raw != 0x15 or typ.parameters[0] != 1:
            raise PrimarySemanticUnavailable("variadic call needs an actual variadic function type")
        count = self._operand()
        operands.append(count)
        self._variadic_skip(1, operands)
        result_type, fixed = typ.parameters[1:3]
        destination = destination_index = None
        nonvoid = self.program.type(result_type).raw != 2
        if nonvoid:
            destination_index = self.pc
            self.pc = (self.pc + 1) & 0xFFFFFFFF
        self._mgf_stage = 'header-nonvoid' if nonvoid else 'header-void'
        x = signed((yield 0x677E1B4), 32)
        y = signed((yield 0x677E1B8), 32)
        if nonvoid:
            if not 0 <= destination_index < len(self.program.words):
                raise PrimaryProgramLimit('variadic destination read beyond program')
            destination = self.program.words[destination_index]
            operands.append(destination)
        if (((x * x + y * y) & 0xFFFFFFFF) | ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31:
            self._variadic_skip(2, operands)
            self._variadic_return_size(result_type)
        while True:
            state['phase'] = 'callee'
            callee = self._operand()
            operands.append(callee)
            callee_pointer = self.cells.pointer(callee)
            self._variadic_skip(1, operands)
            if not fixed <= count <= 0xFFFF:
                raise PrimaryProgramLimit("variadic argument count outside normal Python FFI domain")
            self._variadic_return_size(result_type)
            state['callee_reads'] += 1
            self._mgf_stage = 'callee'
            x = yield 0x6D86090
            y = signed((yield 0x6D86094), 32)
            if not ((((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31):
                break
            self._variadic_skip(2, operands)
            self._variadic_return_size(result_type)
        state['phase'] = 'arguments'
        argument_types = list(typ.parameters[3:3 + fixed])
        arguments = []
        for _ in range(fixed):
            argument = self._operand()
            operands.append(argument)
            arguments.append(argument)
        for _ in range(count - fixed):
            argument_type = self._operand()
            operands.append(argument_type)
            actual_type = self.program.type(argument_type)
            argument = self._operand()
            operands.append(argument)
            if actual_type.raw != 8 and not (actual_type.raw == 7 and self.program.size(argument_type) in (4, 8)):
                raise PrimarySemanticUnavailable("variadic tail requires a proved DWORD/QWORD/pointer FFI type")
            argument_types.append(argument_type)
            arguments.append(argument)
        for argument_type in argument_types[:fixed]:
            actual_type = self.program.type(argument_type)
            if actual_type.raw != 8 and not (actual_type.raw == 7 and self.program.size(argument_type) in (1, 2, 4, 8)):
                raise PrimarySemanticUnavailable("variadic fixed argument requires a proved scalar FFI type")
        return signature, result_type, destination, callee_pointer, tuple(argument_types), tuple(arguments)

    def _variadic_prepare(self, result_type, argument_types, state):
        result = self.program.type(result_type)
        if result.raw not in (2, 8) and not (result.raw == 7 and (1 if result.parameters[0] < 8 else result.parameters[0] >> 3) in (1, 2, 4, 8)):
            raise PrimarySemanticUnavailable("variadic result requires a proved scalar FFI type")
        for index in argument_types:
            typ = self.program.type(index)
            if typ.raw != 8 and not (typ.raw == 7 and (1 if typ.parameters[0] < 8 else typ.parameters[0] >> 3) in (1, 2, 4, 8)):
                raise PrimarySemanticUnavailable("variadic preparation requires builtin scalar FFI types")
        state['prepare_calls'] += 1

    def _variadic(self, start, operands, state):
        signature, result_type, destination, callee_pointer, types, arguments = yield from self._variadic_arguments(operands, state)
        state['phase'] = 'prepare'
        self._mgf_stage = 'prepare-G'
        x = yield 0x6D86090
        y = signed((yield 0x6D86094), 32)
        if (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31:
            self._variadic_prepare(result_type, types, state)
        while True:
            self._variadic_prepare(result_type, types, state)
            self._mgf_stage = 'prepare-F'
            x = signed((yield 0x677E1B4), 32)
            y = signed((yield 0x677E1B8), 32)
            if not ((((x * x + y * y) & 0xFFFFFFFF) | ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31):
                break
            self._variadic_prepare(result_type, types, state)
        state['phase'] = 'call'
        address = self.memory.load(callee_pointer, 8)
        self.host_calls.append((start, address, arguments, signature))
        from .primary_sign import _invoke_host
        result = _invoke_host(self, address, arguments, signature, argument_types=types)
        state['phase'] = 'return_wait'
        self._mgf_stage = 'postcall'
        while (yield 0x677E1BC) == 0x80000000:
            pass
        if destination is not None and signed(destination, 32) >= 0:
            state['phase'] = 'store'
            while True:
                self._write(destination, result, 8, "high.variadic_result_q")
                state['return_stores'] += 1
                self._mgf_stage = 'store'
                if (yield 0x677E1BC) != 0x80000000:
                    break
                self._write(destination, result, 8, "high.variadic_result_q")
                state['return_stores'] += 1
        state['phase'] = 'complete'

    def _resume_variadic(self, budget):
        for _ in range(budget):
            execution, address, record, operands = self.pending_variadic
            try:
                value = self._mgf_load(address, 'variadic')
            except BaseException:
                self.pending_variadic = None
                execution.close()
                raise
            try:
                address = execution.send(value)
            except StopIteration:
                self.pending_variadic = None
                record = VMRecord(*record, tuple(operands))
                self.trace.append(record)
                self._mgf_finish(record)
                return record
            except BaseException:
                self.pending_variadic = None
                execution.close()
                raise
            self.pending_variadic = (execution, address, record, operands)
        raise PrimaryExecutionPaused("variadic global-read budget exhausted; pending body may resume")

    def _once9_operands(self, operands):
        typ = self._operand()
        operands.append(typ)
        current = (self.pc + 1) & 0xFFFFFFFF
        self.pc = (current + 1) & 0xFFFFFFFF
        operands.append(None)
        if not 0 <= current < len(self.program.words):
            raise PrimaryProgramLimit(f"operand read beyond program at word {current}")
        source = self.program.words[current]
        operands.append(source)
        destination = self._operand()
        operands.append(destination)
        return typ, source, destination

    def _once9(self, first, operands):
        group = first
        while True:
            for second in (False, True):
                typ, source, destination = group
                cells = self.cells
                size = self.program.size(typ)
                self._mgf_width = size
                self._mgf_type = typ
                self._mgf_getter_ordinal += 1
                self._mgf_getter_post = 0x35D9B3A if second else 0x35D9A94
                mask = (1 << ((8 * size) & 63)) - 1
                value = cells.value(source)
                cells.set_value(destination, value & mask, width=8, source="once9.mask_q")
                if not second:
                    x = signed((yield 0x677E1B4), 32)
                    y = signed((yield 0x677E1B8), 32)
                    if not ((((x*x + y*y) & 0xFFFFFFFF) |
                             ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31):
                        return
                group = self._once9_operands(operands)

    def _start_once9(self, first, operands, record=None):
        execution = self._once9(first, operands)
        address = next(execution)
        self.pending_once9 = (execution, address, record, operands)

    def _resume_once9(self, budget):
        for _ in range(budget):
            execution, address, record, operands = self.pending_once9
            try:
                value = self._mgf_load(address, 'O9')
            except BaseException:
                self.pending_once9 = None
                execution.close()
                raise
            try:
                address = execution.send(value)
            except StopIteration:
                self.pending_once9 = None
                if record is not None:
                    record = VMRecord(*record, tuple(operands))
                    self.trace.append(record)
                    self._mgf_finish(record)
                return record
            except BaseException:
                self.pending_once9 = None
                execution.close()
                raise
            self.pending_once9 = (execution, address, record, operands)
        raise PrimaryExecutionPaused("once9 global-read budget exhausted; pending body may resume")

    def _once10(self, typ, source, destination):
        source = self.cells.pointer(source)
        destination = self.cells.pointer(destination)
        size = self.program.size(typ)
        self._mgf_width = size
        self._mgf_stage = 'F'
        if type(size) is not int or not 0 <= size <= 0x7FFFFFFF:
            raise PrimaryProgramLimit("once10 size outside nonnegative signed32 layout domain")
        if size == 1 or size >= 4:
            x = signed((yield 0x677E1B4), 32)
            y = signed((yield 0x677E1B8), 32)
            alternate = (((x * x + y * y) & 0xFFFFFFFF) |
                         ((abs(x) + abs(y)) & 0xFFFFFFFF)) >> 31
        if size == 1:
            value = self.memory.load(source, 1)
            self.memory.store(destination, value, 8, source="once10.first_type_zeroextend_or_q")
            if alternate:
                value = self.memory.load(source, 1)
                self.memory.store(destination, value, 8, source="once10.first_type_zeroextend_or_q")
            return
        if size >= 4:
            self._mgf_stage = 'M1'
            while (yield 0x677E1BC) == 0x80000000:
                pass
            if size >= 8:
                self._mgf_stage = 'M2'
                yield 0x677E1BC
                self._mgf_stage = 'M3'
                while (yield 0x677E1BC) == 0x80000000:
                    pass
        if size in (2, 4, 8):
            value = self.memory.load(source, size)
            self.memory.store(destination, value, 8, source="once10.first_type_zeroextend_or_q")
            return
        yield 0x6D86090
        yield 0x6D86094
        while True:
            x = yield 0x6D86090
            y = signed((yield 0x6D86094), 32)
            if not ((((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31):
                return

    def _start_once10(self, typ, source, destination, record=None):
        execution = self._once10(typ, source, destination)
        try:
            address = next(execution)
        except StopIteration:
            return False
        self.pending_once10 = (execution, address, record)
        return True

    def _resume_once10(self, budget, *, _main_owner=None):
        dedicated = getattr(self, '_primary_mix_owner', None)
        if dedicated is not None:
            from .primary_sign_lifecycle import require_execution_active
            require_execution_active(self.runtime)
            if _main_owner is not dedicated or self.runtime.__dict__.get('_primary_wait_session') is not dedicated:
                raise InputError('dedicated Main once10 must resume through its retained call')
        if type(budget) is not int or budget < 1:
            raise InputError("once10 global-read budget must be a positive integer")
        for _ in range(budget):
            execution, address, record = self.pending_once10
            try:
                value = self._mgf_load(address, 'O10')
            except BaseException:
                self.pending_once10 = None
                execution.close()
                raise
            try:
                address = execution.send(value)
            except StopIteration:
                self.pending_once10 = None
                if record is not None:
                    self.trace.append(record)
                    self._mgf_finish(record)
                return record
            except BaseException:
                self.pending_once10 = None
                execution.close()
                raise
            self.pending_once10 = (execution, address, record)
        error = PrimaryExecutionPaused("once10 global-read budget exhausted; pending body may resume")
        error._once10_vm = self
        error._once10_pending = self.pending_once10
        raise error

    def initialize(self, arguments: tuple[int, ...], host_values: tuple[int, ...], *,
                   type_addresses: dict[int, int] | None = None) -> None:
        """Ordinary reader construction, exact constant/argument write widths."""
        if self.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + self.abort_reason)
        if self.pending_native is not None:
            raise InputError('resume the pending native call before reinitializing the VM')
        self.memory.initialize_cells(self.cells.address, self.program.cell_count + 1)
        if len(host_values) != len(self.program.host_cells):
            raise InputError("every actual host slot needs its current pointer/address")
        for cell, value in zip(self.program.host_cells, host_values):
            self.cells.set_value(cell, value, width=8, source="reader.host_q")
            self.memory.store(self.cells.pointer(cell) + 16, 0, 1, source="reader.host_owned")
        for constant in self.program.constants:
            destination = self.cells.pointer(constant.cell)
            code, parameters = constant.code, constant.parameters
            if code == 2:
                raw_type = self.program.type(parameters[0]).raw
                value = self.image_base + 0x4903C10 if raw_type == 0xB else 0
                self.memory.store(destination, value, 8, source="constant.typed_zero")
            elif code in (3, 4):
                self.memory.store(destination, 0 if code == 3 else parameters[0], 8,
                                  source="constant.literal_q")
            elif code == 6:
                type_index, value = parameters
                if type_addresses is not None and type_index in type_addresses:
                    self.memory.store(destination + 8, type_addresses[type_index], 8,
                                      source="constant.type_pointer")
                else:
                    self.memory.forget(destination + 8, 8, source="constant.unknown_type_pointer")
                self.memory.store(destination, value, 8, source="constant.typed_literal_q")
            elif code == 21:
                self.memory.store(destination, parameters[0], 4, source="constant.literal_dword")
            else:
                raise PrimarySemanticUnavailable(f"initialization of constant code {code} is unavailable")
        entry = self.program.type(self.program.entry_type)
        if entry.raw != 8:
            raise PrimaryProgramLimit("entry type must be a compiled function pointer")
        signature = self.program.type(entry.parameters[0])
        if signature.raw != 0x15 or len(arguments) != signature.parameters[2]:
            raise InputError("argument count must match the compiled entry signature")
        for ordinal, (value, typ_index) in enumerate(zip(arguments, signature.parameters[3:])):
            typ = self.program.type(typ_index)
            size = self.program.size(typ_index)
            if typ.raw == 7 and size in (1, 2, 4):
                value = signed(value, 32)  # Win64 promoted integer vararg consumer MOVSXD
            elif typ.raw not in (7, 8) or size != 8:
                raise PrimarySemanticUnavailable(f"vararg type {typ_index} is outside scalar/pointer support")
            self.cells.set_value(ordinal, value, width=8, source="reader.argument_q")

    def _operand(self) -> int:
        current = self.pc
        self.pc = (self.pc + 1) & 0xFFFFFFFF
        if not 0 <= current < len(self.program.words):
            raise PrimaryProgramLimit(f"operand read beyond program at word {current}")
        return self.program.words[current]

    def _typed_operands(self, read=None) -> tuple[int, int, int, int]:
        read = self._operand if read is None else read
        typ = read()
        self.program.type(typ)
        return typ, read(), read(), read()

    def _signed_cell(self, index: int, typ: int) -> int:
        size = self.program.size(typ)
        return self.memory.load(self.cells.pointer(index), size if size in (1, 2, 4) else 8,
                                signed=True)

    def _write(self, index: int, value: int, width: int, source: str) -> None:
        self.cells.set_value(index, value, width=width, source=source)

    def _jump(self, target: int) -> None:
        if not 0 <= target < len(self.program.jumps):
            raise PrimaryProgramLimit(f"jump index {target} outside compiled vector")
        self.predecessor, self.block = self.block, target
        self.pc, self.initial_block = self.program.jumps[target], False

    def _allocate(self, typ: int, destination: int) -> None:
        size = self.program.size(typ)
        end = self.arena_used + size + 1
        if end > self.arena_size:
            raise PrimaryProgramLimit("native arena use exceeds the explicitly mapped Python arena")
        address = (self.arena_address + self.arena_used) & ((1 << 64) - 1)
        self._write(destination, address, 8, "L4.arena_pointer")
        self.memory.store(self.cells.pointer(destination) + 16, 0, 1, source="L4.clear_owned")
        self.arena_used = end

    def _indexed_offset(self, typ: int, index: int) -> tuple[int, int]:
        """35DB108 / 35E941A for pointer, array, and normal struct types."""
        item = self.program.type(typ)
        index &= 0xFFFFFFFF
        if item.raw == 8:
            child = item.parameters[0]
            return self.program.size(child) * index, child
        if item.raw in (0xB, 0xC):
            child = item.parameters[1]
            return self.program.size(child) * index, child
        if item.raw in (6, 0x12, 0x14):
            children = item.parameters[2:2 + item.parameters[1]]
            if index >= len(children):
                # Native offset returns0, but a later child lookup returnsNULL.
                raise PrimaryProgramLimit("indexed struct traversal reaches native NULL child type")
            return self.program.layout(typ)[0][index], children[index]
        raise PrimarySemanticUnavailable("indexed offset requires a proved pointer/array/struct path")

    def execute_once(self, index: int, operands: tuple[int, ...], *, once10_read_budget: int = 1024,
                     once9_read_budget: int = 1024) -> None:
        """Integer subsets of actual 21 helpers; no generic opcode renaming."""
        if self.pending_variadic is not None:
            raise InputError("resume the pending variadic body before starting another")
        if self.pending_l26 is not None:
            raise InputError("resume the pending L26 body before starting another")
        if self.pending_once10 is not None:
            raise InputError("resume the pending once10 body before starting another")
        if self.pending_once9 is not None:
            raise InputError("resume the pending once9 body before starting another")
        if self.pending_native is not None:
            raise InputError('resume the pending native call before another body')
        if len(operands) != 4:
            raise InputError("once scalar bodies require their four compiled operands")
        typ, left, right, destination = operands
        if index == 15:
            self.cells.copy_q_clear_owned(right, destination)
            return
        if index == 9:
            if type(once9_read_budget) is not int or once9_read_budget < 1:
                raise InputError("once9 global-read budget must be a positive integer")
            self._start_once9((typ, right, destination), [])
            self._resume_once9(once9_read_budget)
            return
        if index == 10:
            if type(once10_read_budget) is not int or once10_read_budget < 1:
                raise InputError("once10 global-read budget must be a positive integer")
            if self._start_once10(typ, right, destination):
                self._resume_once10(once10_read_budget)
            return
        raw_type = self.program.type(typ).raw
        if raw_type in (3, 4):
            raise PrimarySemanticUnavailable("native SSE float semantics are not implemented")
        if index in (0, 1, 2, 3, 4, 6, 7, 16, 17):
            a = self._signed_cell(left, typ)
            b = self._signed_cell(right, typ)
            if index in (0, 4): value = a * b
            elif index in (1, 2): value = a + b
            elif index == 3: value = a - b
            elif index in (6, 7):
                if b == 0 or (a == -(1 << 63) and b == -1):
                    raise PrimaryProgramLimit("native IDIV fault lies outside ordinary execution")
                quotient = abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)
                value = quotient if index == 6 else a - quotient * b
            elif index == 16: value = int(a <= b)
            else: value = int(a == b)
            self._write(destination, value, 4 if index in (16, 17) else 8, f"once{index}.integer")
        elif index in (5, 18, 19, 20):
            a, b = self.cells.value(left), self.cells.value(right)
            if index == 5:
                if b == 0:
                    raise PrimaryProgramLimit("native DIV fault lies outside ordinary execution")
                value = a // b
            elif index == 18: value = int(a < b)
            elif index == 19: value = int(a <= b)
            else: value = int(a >= b)
            self._write(destination, value, 8 if index == 5 else 4, f"once{index}.unsigned_q")
        elif index == 8:
            size = self.program.size(typ)
            if size not in (1, 2, 4, 8):
                raise PrimarySemanticUnavailable("once8 unsupported-size no-store path is not modeled")
            a = self.memory.load(self.cells.pointer(left), size)
            count = self.memory.load(self.cells.pointer(right), 1)
            self._write(destination, a >> (count & (63 if size == 8 else 31)),
                        8 if size == 8 else 4, "once8.logical_shift")
        else:
            raise PrimarySemanticUnavailable(f"once{index} needs an unimplemented native body/path")

    def execute_typed(self, operands: tuple[int, ...]) -> None:
        """Accepted integer subpaths of the five-argument4527050 consumer."""
        if self.pending_variadic is not None:
            raise InputError("resume the pending variadic body before starting another")
        if self.pending_l26 is not None:
            raise InputError("resume the pending L26 body before starting another")
        if self.pending_once9 is not None:
            raise InputError("resume the pending once9 body before starting another")
        if self.pending_native is not None:
            raise InputError('resume the pending native call before another body')
        if self.auxiliary is None or self.auxiliary[0] != 0:
            raise PrimarySemanticUnavailable("typed consumer needs a proved current flag0 auxiliary")
        typ, left, right, destination = operands
        aux = self.auxiliary[1]
        selector = 4 * ((aux >> 11) & 1) + 2 * ((aux >> 7) & 1) + ((aux >> 2) & 1)
        size = self.program.size(typ)
        if self.program.type(typ).raw != 7:
            raise PrimarySemanticUnavailable("typed integer body requires an actual integer type")
        if selector in (3, 4) and size in (1, 2, 4):
            count = self.memory.load(self.cells.pointer(right), 4)
            if count & 0x80000000 or count >= 32:
                value = 0
            else:
                value = self._signed_cell(left, typ) & 0xFFFFFFFF
                value = value << count if selector == 3 else value >> count
            self._write(destination, value, 4, f"typed.selector{selector}.d")
            return
        if selector == 3 and size == 8:
            count = self.memory.load(self.cells.pointer(right), 4)
            # Native rejects these counts before reading left, unlike x86SHL.
            value = 0 if count & 0x80000000 or count >= 64 else self.cells.value(left) << count
        elif selector == 4 and size == 8:
            count = self.memory.load(self.cells.pointer(right), 4)
            if count & 0x80000000 or count >= 64:
                value = 0
            else:
                value = self.cells.value(left)
                if count and value == 0x8000000000000000:
                    value -= 1
                value >>= count
        elif selector == 0 and size in (1, 2, 4, 8):
            value = self._signed_cell(left, typ) - self._signed_cell(right, typ)
        elif selector == 1 and size in (1, 2, 4, 8):
            value = self._signed_cell(left, typ) & self._signed_cell(right, typ)
        elif selector == 2 and size in (1, 2, 4, 8):
            value = self._signed_cell(left, typ) | self._signed_cell(right, typ)
        elif selector == 5 and size in (1, 2, 4, 8):
            value = self._signed_cell(left, typ) ^ self._signed_cell(right, typ)
        else:
            raise PrimarySemanticUnavailable(f"typed selector{selector}/size{size} path is unavailable")
        self._write(destination, value, 8, f"typed.selector{selector}.q")

    def step(self, *, once10_read_budget: int = 1024, once9_read_budget: int = 1024,
             l26_read_budget: int = 1024, variadic_read_budget: int = 1024) -> VMRecord | None:
        """Execute one supported ordinary body and retain partial PC/writes."""
        if getattr(self, '_primary_mix_owner', None) is not None:
            raise InputError('dedicated Main once10 cannot resume through generic step')
        if self.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + self.abort_reason)
        if type(once10_read_budget) is not int or once10_read_budget < 1:
            raise InputError("once10 global-read budget must be a positive integer")
        if type(once9_read_budget) is not int or once9_read_budget < 1:
            raise InputError("once9 global-read budget must be a positive integer")
        if type(l26_read_budget) is not int or l26_read_budget < 1:
            raise InputError("L26 global-read budget must be a positive integer")
        if type(variadic_read_budget) is not int or variadic_read_budget < 1:
            raise InputError("variadic global-read budget must be a positive integer")
        if self.pending_variadic is not None:
            return self._resume_variadic(variadic_read_budget)
        if self.pending_l26 is not None:
            return self._resume_l26(l26_read_budget)
        if self.pending_once10 is not None:
            return self._resume_once10(once10_read_budget)
        if self.pending_once9 is not None:
            return self._resume_once9(once9_read_budget)
        if self.pending_native is not None:
            return self._resume_native()
        if self.halted:
            raise InputError("primary VM body execution is halted")
        start = self.pc
        # Grammar validation is deliberately not used as a transactional operand pre-read.
        if not 0 <= start < len(self.program.words):
            raise PrimaryProgramLimit("opcode fetch outside program")
        raw = self._operand()
        low = None
        if raw < 0x100000:
            normalized = raw ^ (0 if self.initial_block else jump_key(self.program.words[0], self.block))
            try: low = BASE_OPCODES.index(normalized)
            except ValueError as error:
                raise PrimarySemanticUnavailable(f"unbound opcode at word {start}") from error
        replay = getattr(self.runtime, '_consumed_mgf', None)
        if replay is not None:
            replay.begin_record(self, (start, self.block, raw, low))
        operands = []
        def operand():
            value = self._operand()
            operands.append(value)
            return value
        if low == 0:
            self.halted = True
        elif low == 4:
            self._allocate(operand(), operand())
        elif low == 6:
            typ, source, destination = operand(), operand(), operand()
            size = self.program.size(typ)
            if size not in (1, 2, 4, 8):
                raise PrimarySemanticUnavailable(f"L6/size{size} memory store is unavailable")
            pointer = self.cells.value(destination)
            value = self.memory.load(self.cells.pointer(source), 8 if size == 8 else 4)
            self.memory.store(pointer, value, size, source="L6.store_integer")
        elif low == 5:
            typ, source, destination = operand(), operand(), operand()
            size = self.program.size(typ)
            if size not in (1, 2, 4, 8):
                raise PrimarySemanticUnavailable(f"L5/size{size} memory load is unavailable")
            value = self.memory.load(self.cells.value(source), size)
            self._write(destination, value, 8 if size == 8 else 4, "L5.unsigned_load")
        elif low == 7:
            condition_type, condition, result_type, true, false = tuple(operand() for _ in range(5))
            # The sixth PC commit precedes the first type/tag access (452600C).
            current = self.pc
            self.pc = (current + 1) & 0xFFFFFFFF
            if self.program.type(condition_type).raw == 0x15:
                raise PrimarySemanticUnavailable("L7 condition tag10h error/callback route is unavailable")
            if not 0 <= current < len(self.program.words):
                raise PrimaryProgramLimit("L7 destination operand exceeds program")
            destination = self.program.words[current]
            operands.append(destination)
            selected = true if self.cells.value(condition) != 0 else false
            value = self._signed_cell(selected, result_type)
            self._write(destination, value, 8, "L7.selected_q")
        elif low in (13, 14, 15):
            typ, left, right, destination = tuple(operand() for _ in range(4))
            size = self.program.size(typ)
            if low == 13 and size in (1, 2, 4, 8):
                value = self._signed_cell(left, typ) & self._signed_cell(right, typ)
            elif low == 14 and size in (1, 2, 4, 8):
                value = self._signed_cell(left, typ) ^ self._signed_cell(right, typ)
            elif low == 15 and size in (1, 2, 4, 8):
                value = self._signed_cell(left, typ) | self._signed_cell(right, typ)
            else:
                raise PrimarySemanticUnavailable(f"L{low}/size{size} binary body is unavailable")
            self._write(destination, value, 8, f"L{low}.binary_q")
        elif low == 16:
            typ, left, right, destination = tuple(operand() for _ in range(4))
            if self.program.type(typ).raw in (3, 4):
                raise PrimarySemanticUnavailable("L16 floating remainder is unavailable")
            size = self.program.size(typ)
            if size not in (1, 2, 4, 8):
                raise PrimarySemanticUnavailable(f"L16/size{size} remainder is unavailable")
            a, b = self._signed_cell(left, typ), self._signed_cell(right, typ)
            if b == 0 or (a == -(1 << 63) and b == -1):
                raise PrimaryProgramLimit("native signed IDIV64 fault outside ordinary execution")
            quotient = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
            self._write(destination, a - quotient * b, 8, "L16.signed_remainder_q")
        elif low in (17, 18):
            typ, left, right, destination = tuple(operand() for _ in range(4))
            if self.program.type(typ).raw in (3, 4):
                raise PrimarySemanticUnavailable("L17/18 floating route is unavailable")
            a, b = self.cells.value(left), self.cells.value(right)
            if b == 0:
                raise PrimaryProgramLimit("native unsigned DIV fault outside ordinary execution")
            value = a % b if low == 17 else a // b
            self._write(destination, value, 8, f"L{low}.unsigned_q_division")
        elif low in (19, 20, 24):
            operand(); operand()
            source, destination = operand(), operand()
            self.cells.copy_q_clear_owned(source, destination)
        elif low == 21:
            destination_type, source_type, source, destination = tuple(operand() for _ in range(4))
            if (self.program.type(destination_type).raw != 7 or
                    self.program.size(destination_type) != 4 or
                    self.program.type(source_type).raw != 3):
                raise PrimarySemanticUnavailable("L21 requires the proved float32-to-DWORD route")
            bits = self.memory.load(self.cells.pointer(source), 4)
            from .primary_x86_float import ScalarSSEUnavailable, cvttss2si_i64_low_dword
            try:
                value = cvttss2si_i64_low_dword(bits, self.scalar_sse_state)
            except ScalarSSEUnavailable as error:
                raise PrimarySemanticUnavailable(str(error)) from error
            self._write(destination, value & 0xFFFFFFFF, 8, "L21.float32_i64_low_dword_q")
        elif low == 8:
            condition, default, count = operand(), operand(), operand()
            target, matched = default, False
            for _ in range(count):
                case, branch = operand(), operand()
                if not matched and self.cells.value(condition) == self.cells.value(case):
                    target, matched = branch, True
            self._jump(target)
        elif low == 9:
            destination, count = operand(), operand()
            matched = False
            for _ in range(count):
                source = operand()
                current = self.pc
                self.pc = (current + 1) & 0xFFFFFFFF
                if not matched:
                    if not 0 <= current < len(self.program.words):
                        raise PrimaryProgramLimit(f"operand read beyond program at word {current}")
                    predecessor = self.program.words[current]
                    operands.append(predecessor)
                    if predecessor == self.predecessor:
                        self._write(destination, self.cells.value(source), 8, "L9.phi_q")
                        matched = True
                else:
                    operands.append(None)
        elif low == 11:
            pass
        elif low == 12:
            self.auxiliary = (operand(), operand())
        elif low == 29:
            typ, left, right, destination = tuple(operand() for _ in range(4))
            size = self.program.size(typ)
            if size not in (1, 2, 4, 8):
                raise PrimarySemanticUnavailable(f"L29/size{size} comparison is unavailable")
            a = self._signed_cell(left, typ) & ((1 << 64) - 1)
            b = self._signed_cell(right, typ) & ((1 << 64) - 1)
            difference = (a - b) & ((1 << 64) - 1)
            overflow = ((a ^ difference) & (a ^ b)) >> 63
            value = (difference >> 63) | overflow
            self._write(destination, value, 4, "L29.n_or_v_comparison")
        elif low in (25, 26, 27, 30, 31):
            if low == 26:
                execution = self._l26(operands)
                address = next(execution)
                self.pending_l26 = (execution, address, (start, self.block, raw, low), operands)
                return self._resume_l26(l26_read_budget)
            typ, left, right, destination = operand(), operand(), operand(), operand()
            size = self.program.size(typ)
            if low == 31:
                value = int(self.cells.value(left) > self.cells.value(right))
            else:
                if ((low == 25 and size not in (2, 4)) or
                        (low in (27, 30) and size not in (1, 2, 4, 8))):
                    raise PrimarySemanticUnavailable(f"L{low}/size{size} comparison is unavailable")
                a, b = self._signed_cell(left, typ), self._signed_cell(right, typ)
                value = int(a > b) if low == 25 else int(a == b) if low == 26 else int(a != b)
            self._write(destination, value, 4, f"L{low}.comparison")
        elif low == 32:
            self._jump(operand())
        elif low == 33:
            true, condition, false = operand(), operand(), operand()
            self._jump(true if self.cells.value(condition) != 0 else false)
        elif low == 3:
            typ = operand()
            if self.program.type(typ).raw not in (7, 8):
                raise PrimarySemanticUnavailable("L3 noninteger/nonpointer return is unavailable")
            size = self.program.size(typ)
            if size not in (1, 2, 4, 8):
                raise PrimarySemanticUnavailable(f"L3/size{size} return is unavailable")
            source = operand()
            self.result, self.halted = self._signed_cell(source, typ) & ((1 << 64) - 1), True
        elif low is None and (((raw >> 24) & 0xF0) | (raw & 15)) in (7, 8):
            typ, source, destination = operand(), operand(), operand()
            size = self.program.size(typ)
            if size not in (1, 2, 4, 8):
                raise PrimarySemanticUnavailable("ordinary typed load/store requires scalar width")
            if raw & 15 == 7:
                pointer = self.cells.value(source)
                value = self.memory.load(pointer, size)
                self._write(destination, value, 8 if size == 8 else 4, "high.load")
            else:
                pointer = self.cells.value(destination)
                value = self.memory.load(self.cells.pointer(source), size)
                self.memory.store(pointer, value, size, source="high.store")
        elif low is None and (((raw >> 24) & 0xF0) | (raw & 15)) == 10:
            state = {'phase': 'header', 'abi': 1, 'callee_reads': 0, 'prepare_calls': 0, 'return_stores': 0}
            self.variadic_state = state
            execution = self._variadic(start, operands, state)
            address = next(execution)
            self.pending_variadic = (execution, address, (start, self.block, raw, low), operands)
            return self._resume_variadic(variadic_read_budget)
        elif raw == 0x014A3DB9:
            signature, convention = operand(), operand()
            typ = self.program.type(signature)
            if typ.raw != 0x15 or convention != 0:
                raise PrimarySemanticUnavailable("native call requires a proved scalar signature/convention")
            result_type, count = typ.parameters[1:3]
            destination = operand() if self.program.type(result_type).raw != 2 else None
            callee = operand()
            flag = operand()
            arguments = tuple(operand() for _ in range(count))
            if flag != 0:
                raise PrimarySemanticUnavailable("native call flag route is not implemented")
            address = self.cells.value(callee)
            self.host_calls.append((start, address, arguments, signature))
            if (address == self.image_base + 0x359253D and self.runtime is not None and
                    (getattr(self.runtime, 'host2252_stage1_retry', False) or getattr(self.runtime, 'host2252_stage2_g_retry', False) or getattr(self.runtime, 'host2252_final_f_retry', False) or getattr(self.runtime, 'host2252_control_m', False))):
                if signature != 205 or destination is not None or count != 1:
                    raise PrimarySemanticUnavailable('host2252 retry requires fixed void signature205')
                record = VMRecord(start, self.block, raw, low, tuple(operands))
                self.pending_native = (address, arguments, signature, typ.parameters[3:3 + count], record)
                return self._resume_native()
            from .primary_sign import _invoke_host
            if address == self.image_base + 0x2DE215D and getattr(self.runtime, '_consumed_mgf', None) is not None:
                record = VMRecord(start, self.block, raw, low, tuple(operands))
                if self.private_iv_native_pending is not None:
                    raise InputError('private IV native call is already pending')
                self.private_iv_native_pending = (address, arguments, signature, typ.parameters[3:3 + count], record)
                try:
                    _invoke_host(self, address, arguments, signature, argument_types=typ.parameters[3:3 + count])
                except BaseException as error:
                    self.abort_reason = type(error).__name__
                    raise
                finally:
                    self.private_iv_native_pending = None
                self.trace.append(record)
                self._mgf_finish(record)
                return record
            result = _invoke_host(self, address, arguments, signature,
                                  argument_types=typ.parameters[3:3 + count])
            owner = getattr(self.runtime, '_active_main', None)
            if (owner is not None and owner['vm'] is self and
                    start in (11562, 11569) and self.block == 277 and callee == 1719 and
                    address == self.image_base + 0x3E97020 and
                    signature == 152 and destination == (1718 if start == 11562 else 1720) and
                    arguments == (1717,)):
                from .primary_sign_lifecycle import region_at
                region = region_at(self.memory, result)
                if not result or region is None or result not in self.runtime.allocations:
                    raise PrimaryProgramLimit('approved main temporary allocation lacks its exact owner')
                self.main_owned_allocations.append({'pointer': result, 'region': region,
                                                    'size': self.runtime.allocations[result],
                                                    'generation': owner['generation'], 'word': start,
                                                    'destination': destination})
            if destination is not None:
                # Native result temporary starts at Q0, and the reader copies
                # its complete Q to the result cell (35DE464/35DD79E).
                self._write(destination, result, 8, "high.native_result_q")
        elif raw == 0x0F0E596B:
            destination = operand()
            operand()  # The nominal flag word is skipped by the native body.
            source_type, count = operand(), operand()
            if count == 0:
                raise PrimarySemanticUnavailable("indexed pointer count0 altered-PC route is unavailable")
            # The high body uses a fresh pointer-to-source-type before the
            # index loop. Count includes the first/base-cell operand.
            base_cell = operand()
            current_type, offset = source_type, 0
            for ordinal in range(1, count):
                index_cell = operand()
                index = self.memory.load(self.cells.pointer(index_cell), 4)
                if ordinal == 1:
                    delta = self.program.size(current_type) * index
                else:
                    delta, current_type = self._indexed_offset(current_type, index)
                offset = (offset + delta) & ((1 << 64) - 1)
            # Base Q is read after all index DWORDs/getters, at35E0226/35E0269.
            self._write(destination, self.cells.value(base_cell) + offset, 8, "high.indexed_pointer_q")
        elif low is None and (((raw >> 24) & 0xF0) | (raw & 15)) == 6:
            flag, typ, left, right, destination = tuple(operand() for _ in range(5))
            self._mgf_flag = flag
            if flag == 0:
                current = signed(self._mgf_load(0x677E1BC, 'class6'), 32)
                if current == -0x80000000:
                    self.execute_typed((typ, left, right, destination))
                self.execute_typed((typ, left, right, destination))
            elif flag == 1:
                value = self._signed_cell(left, typ) ^ self._signed_cell(right, typ)
                self._write(destination, value, 8, "high.flag1_xor_q")
            else:
                raise PrimarySemanticUnavailable("high class6 invalid-flag error route is unavailable")
        elif low is None and (((raw >> 24) & 0xF0) | (raw & 15)) == 5:
            self.execute_typed(tuple(operand() for _ in range(4)))
        elif low is None and (((raw >> 24) & 0xF0) | (raw & 15)) in (0, 1, 2, 3):
            generic = ((raw >> 24) & 0xF0) | (raw & 15)
            if generic == 3:
                x = self._mgf_load(0x6D86090, 'class3')
                y = signed(self._mgf_load(0x6D86094, 'class3'), 32)
                extra = (((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31
            else:
                extra = 0
            values = self._typed_operands(operand) if generic == 3 else tuple(operand() for _ in range(4))
            self.execute_typed(values)
            if extra:
                self.execute_typed(self._typed_operands(operand))
        elif low is None and 12 <= (((raw >> 24) & 0xF0) | (raw & 15)) <= 32:
            index = once_index(raw)
            if index == 9:
                first = self._once9_operands(operands)
                self._start_once9(first, operands, (start, self.block, raw, low))
                return self._resume_once9(once9_read_budget)
            elif index == 10:
                typ = operand()
                current = (self.pc + 1) & 0xFFFFFFFF
                self.pc = (current + 1) & 0xFFFFFFFF
                operands.append(None)
                if not 0 <= current < len(self.program.words):
                    raise PrimaryProgramLimit(f"operand read beyond program at word {current}")
                source = self.program.words[current]
                operands.append(source)
                destination = operand()
                record = VMRecord(start, self.block, raw, low, tuple(operands))
                if self._start_once10(typ, source, destination, record):
                    return self._resume_once10(once10_read_budget)
            else:
                values = tuple(operand() for _ in range(4))
                self.execute_once(index, values)
        else:
            raise PrimarySemanticUnavailable(f"body unavailable for opcode {raw:#x} at word {start}")
        record = VMRecord(start, self.block, raw, low, tuple(operands))
        self.trace.append(record)
        self._mgf_finish(record)
        return record

    def run(self, *, max_steps: int) -> int | None:
        """Run proved bodies until actual stop/return; preserve state on failure.

        The explicit bound is a Python execution limit, not a native watchdog.
        Missing host/math/bytes raises at its real use and never returns an
        invented signature or success value.
        """
        if self.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + self.abort_reason)
        if type(max_steps) is not int or max_steps < 1:
            raise InputError("max_steps must be a positive integer")
        for _ in range(max_steps):
            if self.halted:
                return self.result
            self.step()
        if self.halted:
            return self.result
        raise PrimaryProgramLimit(f"Python execution limit after{max_steps} instructions at word{self.pc}")
