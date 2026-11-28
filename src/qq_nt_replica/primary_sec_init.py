import hashlib
from pathlib import Path

from .errors import InputError
from .primary_memory import PrimaryMemoryLimit
from .primary_sign import PrimaryFrame, arena_reservation
from .primary_vm import PrimaryProgramLimit, PrimaryVM, decode_program
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_DATA = Path(__file__).with_name('data') / 'primary_sec_init_qq52230'
_SHA256 = 'a2e41f0459b732d4c96b742e3360d55e8f153e0e14df12119117f333add3265c'
_HOST_SHA256 = '7cc98c943aefcf324621bcb13f5f08959afb1720868804118c4cd62265566931'
_HOSTS = (0x436E0A0, 0x3EB1FE0, 0x3E97020, 0x3EB2680, 0x3592167,
          0x35922AC, 0x3EB5400, 0x2DEC10F, 0x35A20F0, 0x35A211B, 0x3E94F90)
_LIMIT = 1 << 24


def load_program():
    raw = (_DATA / 'producer.bin').read_bytes()
    if len(raw) != 2604 or hashlib.sha256(raw).hexdigest() != _SHA256:
        raise InputError('fixed sec-init producer identity mismatch')
    program = decode_program(raw)
    if (program.cell_count, len(program.words), program.descriptor) != (187, 1088, 0x100900BE):
        raise InputError('fixed sec-init producer layout mismatch')
    return program


def install_image(memory, image_base):
    original = b''.join((0x180000000 + rva).to_bytes(8, 'little') for rva in _HOSTS)
    if hashlib.sha256(original).hexdigest() != _HOST_SHA256:
        raise InputError('fixed sec-init host bank identity mismatch')
    hosts = b''.join((image_base + rva).to_bytes(8, 'little') for rva in _HOSTS)
    for rva, raw in ((0x6428B40, hosts), (0x436E0A0, b'0123456789ABCDEF\0')):
        try:
            current = memory.read(image_base + rva, len(raw))
        except PrimaryMemoryLimit:
            memory.map(image_base + rva, raw, name='fixed sec-init source image', initialized=True)
        else:
            if current != raw:
                raise InputError('sec-init source image conflicts with current memory')


def serialize(runtime, array, output_size):
    memory = runtime.memory
    values, count = memory.load(array, 8), memory.load(array + 8, 8)
    if count > _LIMIT // 16:
        raise PrimaryProgramLimit('sec-init array exceeds the bounded normal domain')
    size = 0
    for index in range(count):
        size += memory.load(values + 16 * index + 8, 8) + 4
        if size > _LIMIT:
            raise PrimaryProgramLimit('sec-init serialized array exceeds the bounded normal domain')
    result = _invoke(runtime, 0x3E97020, size)
    cursor = result
    for index in range(count):
        pair = memory.load(array, 8) + 16 * index
        length = memory.load(pair + 8, 8)
        source = memory.load(pair, 8)
        memory.store(cursor, length & 0xFFFFFFFF, 4, source='2DEC21F.array_length_DWORD')
        _invoke(runtime, 0x3EB1FE0, cursor + 4, source, length)
        cursor += length + 4
    memory.store(output_size, size, 8, source='2DEC25D.array_size_QWORD')
    runtime.events.append(('sec_init.serialize', array, count, size, result))
    return result


class _ExecutionRuntime:
    def __init__(self, runtime):
        self.runtime = runtime

    def __getattr__(self, name):
        return getattr(self.runtime, name)

    def invoke(self, vm, rva, cells, *, argument_types=None):
        if rva == 0x2DEC10F:
            if len(cells) != 2:
                raise InputError('sec-init array serializer takes two pointers')
            return serialize(self.runtime, *(vm.cells.value(cell) for cell in cells))
        if rva == 0x3EB5400:
            if cells:
                raise InputError('sec-init process-id thunk takes no arguments')
            target = self.memory.load(self.image_base + 0x490FDE8, 8)
            return self.runtime.invoke(vm, target - self.image_base, ())
        return self.runtime.invoke(vm, rva, cells, argument_types=argument_types)


def execute(runtime, array, output_length, *, frame):
    program = load_program()
    if not isinstance(frame, PrimaryFrame) or frame.program != 'sec-init':
        raise InputError('sec-init requires its explicit PrimaryFrame')
    reservation = arena_reservation(program)
    if frame.arena_size < reservation:
        raise InputError('sec-init VM frame is shorter than its native reservation')
    memory = runtime.memory
    install_image(memory, runtime.image_base)
    memory.map(frame.cells, bytearray((program.cell_count + 1) * 24),
               name='sec-init cells', initialized=False)
    memory.map(frame.arena, bytearray(frame.arena_size),
               name='sec-init native private arena', initialized=False)
    memory.write(frame.arena, bytes(reservation), source='35DBC95.arena_memset')
    vm = PrimaryVM(program, memory, cells_address=frame.cells, arena_address=frame.arena,
                   arena_size=frame.arena_size, image_base=runtime.image_base,
                   runtime=_ExecutionRuntime(runtime))
    runtime.vms.append(vm)
    bank = runtime.image_base + 0x6428B40
    hosts = tuple(memory.load(bank + 8 * index, 8) for index in range(len(program.host_cells)))
    vm.initialize((array, output_length), hosts)
    if vm.runtime.primary_core:
        from .primary_sec_init_core import run_primary_sec_init
        result = run_primary_sec_init(vm)
    else:
        result = vm.run(max_steps=1_000_000)
    if not runtime.retain_frames:
        memory.unmap(frame.cells)
        memory.unmap(frame.arena)
    return result


def produce(runtime, output, vector, *, frame):
    memory = runtime.memory
    first, last = memory.load(vector, 8), memory.load(vector + 8, 8)
    if last < first or (last - first) % 24 or last - first > _LIMIT:
        raise PrimaryProgramLimit('sec-init borrowed String vector exceeds the normal domain')
    count = (last - first) // 24
    local, ignored = _frame(runtime, 0x48, '2DEBF04.sec_init_frame')
    pairs = _invoke(runtime, 0x3E97020, count * 16)
    array, length = local + 0x30, local + 0x2C
    memory.store(array, pairs, 8, source='2DEBFAD.borrowed_array')
    memory.store(array + 8, count, 8, source='2DEBFA1.borrowed_count')
    for index in range(count):
        string = first + 24 * index
        tag = memory.load(string, 1)
        pointer = memory.load(string + 16, 8) if tag & 1 else string + 1
        size = memory.load(string + 8, 8) if tag & 1 else tag >> 1
        memory.store(pairs + 16 * index, pointer, 8, source='2DEBFE4.borrowed_string_data')
        memory.store(pairs + 16 * index + 8, size, 8, source='2DEC01F.borrowed_string_length')
    memory.store(length, 0, 4, source='2DEC040.initial_output_length')
    raw = execute(runtime, array, length, frame=frame)
    size = memory.load(length, 4)
    if size >= 23:
        capacity = (size + 16) & ~15
        data = runtime._operator_new(capacity)
        memory.store(output + 16, data, 8, source='2DEC097.owning_output_data')
        memory.store(output, capacity | 1, 8, source='2DEC09F.owning_output_capacity')
        memory.store(output + 8, size, 8, source='2DEC0A2.owning_output_length')
    else:
        memory.store(output, size * 2, 1, source='2DEC077.short_output_length')
        data = output + 1
    if size:
        _invoke(runtime, 0x3EB1FE0, data, raw, size)
    memory.store(data + size, 0, 1, source='2DEC0B4.output_terminator')
    _invoke(runtime, 0x3E94F90, raw)
    memory.unmap(local)
    return output


def invoke(runtime, rva, values, *, frame=None):
    if rva == 0x2DEBF04 and len(values) == 2:
        return produce(runtime, *values, frame=frame)
    if rva == 0x2DEC10F and len(values) == 2:
        return serialize(runtime, *values)
    if rva == 0x3EB5400 and not values:
        target = runtime.memory.load(runtime.image_base + 0x490FDE8, 8)
        return _invoke(runtime, target - runtime.image_base)
    raise InputError('sec-init source interface argument count mismatch')
