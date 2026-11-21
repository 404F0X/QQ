from dataclasses import dataclass

from .errors import InputError
from .primary_logger import _String
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _zero_string
from .primary_worker_response import _frame


_IMPORTS = {'SHGetSpecialFolderPathA': 0x49107E8, 'GetPrivateProfileStringA': 0x490FF30}


@dataclass(frozen=True)
class IniRawWrite:
    offset: int
    data: bytes

    def __post_init__(self):
        if type(self.offset) is not int or self.offset < 0 or not isinstance(self.data, bytes):
            raise InputError('INI raw write requires a nonnegative offset and bytes')


@dataclass(frozen=True)
class IniApiReply:
    result: int
    writes: tuple = ()

    def __post_init__(self):
        if type(self.result) is not int or not 0 <= self.result <= 0xFFFFFFFF:
            raise InputError('INI API result requires an explicit DWORD')
        if not isinstance(self.writes, tuple) or not all(isinstance(item, IniRawWrite) for item in self.writes):
            raise InputError('INI API reply requires ordered typed raw writes')


@dataclass(frozen=True)
class IniApiObservation:
    name: str
    arguments: tuple
    reply: IniApiReply

    def __post_init__(self):
        if self.name not in _IMPORTS or not isinstance(self.arguments, tuple) or not isinstance(self.reply, IniApiReply):
            raise InputError('INI observation requires a supported API, exact argument tuple and raw reply')
        if len(self.arguments) != (4 if self.name == 'SHGetSpecialFolderPathA' else 6):
            raise InputError('INI raw API observation argument count mismatch')
        if not all(type(value) is int and 0 <= value < 1 << 64 for value in self.arguments):
            raise InputError('INI raw API arguments require unsigned pointer-width integers')


class IniObservations:
    def __init__(self, observations):
        self.observations = tuple(observations)
        if not all(isinstance(item, IniApiObservation) for item in self.observations):
            raise InputError('typed INI raw API observations required')
        self.position = 0

    def take(self, runtime, name, arguments):
        if self.position == len(self.observations):
            raise UnknownMemory('missing INI raw API observation: ' + name)
        observation = self.observations[self.position]
        if (observation.name, observation.arguments) != (name, arguments):
            raise InputError('INI raw API observation does not match the actual ordered call')
        self.position += 1
        return observation.reply


def install_observations(runtime, observations):
    if not isinstance(observations, IniObservations):
        raise InputError('typed INI observation stream required')
    runtime.notification_ini_observations = observations


def _observe(runtime, name, arguments, buffer, capacity):
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
        raise PrimarySemanticUnavailable('INI current import is not bound: ' + name)
    observer = getattr(runtime, 'notification_ini_observations', None)
    if observer is None:
        raise UnknownMemory('missing INI raw API observations')
    reply = observer.take(runtime, name, arguments)
    if not isinstance(reply, IniApiReply):
        raise InputError('typed INI raw API reply required')
    for write in reply.writes:
        if write.offset > capacity or len(write.data) > capacity - write.offset:
            raise InputError('INI raw API write leaves its output buffer')
        if write.data:
            runtime.memory.write(buffer + write.offset, write.data, source='35A32A0.raw_API_write')
    return reply.result


def _terminated(runtime, pointer, capacity):
    for size in range(capacity):
        if runtime.memory.load(pointer + size, 1) == 0:
            return runtime.memory.read(pointer, size)
    raise PrimaryProgramLimit('INI C string has no known bounded terminator')


def _pointer(value, address):
    return value.get(16, 8) if value.get(0, 1) & 1 else address + 1


def _construct_output(runtime, destination, raw):
    size = len(raw)
    if size < 23:
        runtime.memory.store(destination, size * 2, 1, source='35A34E2.output_short_length')
        pointer = destination + 1
    else:
        physical = (size + 16) & ~15
        pointer = runtime._operator_new(physical)
        runtime.memory.store(destination + 16, pointer, 8, source='35A3506.output_pointer')
        runtime.memory.store(destination, physical | 1, 8, source='35A350E.output_capacity')
        runtime.memory.store(destination + 8, size, 8, source='35A3511.output_length')
    runtime.memory.write(pointer, raw + b'\0', source='35A3522.output_payload_and_NUL')


def ini_value(runtime, out24, ownedProduct24, ownedFilename24, ownedSection24, ownedKey24):
    frame, rbp = _frame(runtime, 0x2C0, '35A32A0.ini_frame')
    memory = runtime.memory
    root, buffer = rbp - 0x50, rbp + 0xC0
    path = _zero_string(runtime)
    suffix = None
    inputs = (ownedProduct24, ownedFilename24, ownedSection24, ownedKey24)
    try:
        result = _observe(runtime, 'SHGetSpecialFolderPathA', (0, root, 0x2E, 0), root, 260)
        if not result:
            memory.store(out24, 0, 2, source='35A3381.false_WORD_only')
        else:
            _append(path, _terminated(runtime, root, 260))
            product = _String.read(runtime, ownedProduct24)
            filename = _String.read(runtime, ownedFilename24)
            suffix = _String.concat(runtime, b'\\Tencent\\', product.value())
            _append(suffix, b'\\')
            _append(suffix, filename.value())
            _append(path, suffix.value())
            suffix.destroy()
            suffix = None
            path.write_to(rbp + 0x200)
            memory.write(buffer, bytes(265), source='35A3461.zero_profile265')
            section, key = _String.read(runtime, ownedSection24), _String.read(runtime, ownedKey24)
            section_pointer, key_pointer = _pointer(section, ownedSection24), _pointer(key, ownedKey24)
            _terminated(runtime, section_pointer, (1 << 20))
            _terminated(runtime, key_pointer, (1 << 20))
            path_pointer = _pointer(path, rbp + 0x200)
            _terminated(runtime, path_pointer, len(path.value()) + 1)
            if memory.read(runtime.image_base + 0x4903C10, 1) != b'\0':
                raise PrimarySemanticUnavailable('INI current default string is not the fixed empty literal')
            _observe(runtime, 'GetPrivateProfileStringA',
                     (section_pointer, key_pointer, runtime.image_base + 0x4903C10, buffer, 260, path_pointer),
                     buffer, 260)
            _construct_output(runtime, out24, _terminated(runtime, buffer, 265))
        path.destroy()
        path = None
        for address in inputs:
            _String.read(runtime, address).destroy()
        return out24
    finally:
        if suffix is not None:
            suffix.destroy()
        if path is not None:
            path.destroy()
        memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva == 0x35A32A0 and len(values) == 5:
        return ini_value(runtime, *values)
    raise InputError('notification INI source entry argument count mismatch')
