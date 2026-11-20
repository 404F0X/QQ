from dataclasses import dataclass

from .errors import InputError
from .primary_logger import _String, _cstring, log
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame, _owner, _image as _response_image


_IMPORTS = {'GetModuleHandleA': 0x490FEF8, 'GetModuleFileNameA': 0x490FEE8,
    'CreateFileA': 0x490FC28, 'ReadFile': 0x4910288, 'SetFilePointer': 0x4910318,
    'IsBadReadPtr': 0x4910110, 'CloseHandle': 0x490FBD8, 'GetProcAddress': 0x490FF40}
_MASK = (1 << 64) - 1
_SOURCE = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\platforms\\Windows\\..\\..\\platforms\\NT\\CheckNTIntegrity\\nt_code_detect.h'
_NAMES = (b'wrapper.node', b'QQNT.dll')


@dataclass(frozen=True)
class IntegrityWrite:
    address: int
    data: bytes

    def __post_init__(self):
        if type(self.address) is not int or not 0 < self.address <= _MASK or not isinstance(self.data, bytes):
            raise InputError('integrity raw write requires an explicit address and bytes')


@dataclass(frozen=True)
class IntegrityObservation:
    name: str
    arguments: tuple
    result: int
    writes: tuple = ()

    def __post_init__(self):
        widths = {'GetModuleHandleA': 64, 'CreateFileA': 64, 'GetProcAddress': 64}
        counts = {'GetModuleHandleA': 1, 'GetModuleFileNameA': 3, 'CreateFileA': 7, 'ReadFile': 5, 'SetFilePointer': 4, 'IsBadReadPtr': 2, 'CloseHandle': 1, 'GetProcAddress': 2}
        if self.name not in _IMPORTS or not isinstance(self.arguments, tuple):
            raise InputError('integrity observation requires a supported API and exact arguments')
        if len(self.arguments) != counts[self.name]:
            raise InputError('integrity API argument count mismatch')
        if any(type(x) is not int or not 0 <= x <= _MASK for x in self.arguments):
            raise InputError('integrity API arguments require unsigned pointer-width values')
        if type(self.result) is not int or not 0 <= self.result < 1 << widths.get(self.name, 32):
            raise InputError('integrity API result width mismatch')
        if not isinstance(self.writes, tuple) or not all(isinstance(x, IntegrityWrite) for x in self.writes):
            raise InputError('integrity API effects require ordered raw writes')


class IntegrityObservations:
    def __init__(self, observations):
        self.observations = tuple(observations)
        if not all(isinstance(x, IntegrityObservation) for x in self.observations):
            raise InputError('typed integrity observations required')
        self.position = 0

    def take(self, runtime, name, arguments):
        if self.position == len(self.observations):
            raise UnknownMemory('missing integrity API observation: ' + name)
        item = self.observations[self.position]
        if (item.name, item.arguments) != (name, arguments):
            raise InputError('integrity API observation does not match its actual call')
        self.position += 1
        return item


def install_observations(runtime, observations):
    if not isinstance(observations, IntegrityObservations):
        raise InputError('typed integrity observations required')
    runtime.device_integrity_observations = observations


def _api(runtime, name, arguments, spans=()):
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
        raise PrimarySemanticUnavailable('integrity current import is not bound: ' + name)
    observer = getattr(runtime, 'device_integrity_observations', None)
    if observer is None:
        raise UnknownMemory('missing integrity API observations')
    reply = observer.take(runtime, name, arguments)
    if not isinstance(reply, IntegrityObservation) or (reply.name, reply.arguments) != (name, arguments):
        raise InputError('integrity API reply identity mismatch')
    for write in reply.writes:
        if not any(begin <= write.address and write.address + len(write.data) <= begin + size for begin, size in spans):
            raise InputError('integrity raw effect leaves its actual output buffer')
        runtime.memory.write(write.address, write.data, source='2DF8D00.raw_API_write')
    runtime.events.append(('integrity.api', name))
    return reply.result


def _loaded(runtime, address, size):
    observer = getattr(runtime, 'device_integrity_observations', None)
    reader = getattr(observer, 'read_loaded', None)
    value = reader(runtime, address, size) if callable(reader) else runtime.memory.read(address, size)
    if not isinstance(value, bytes) or len(value) != size:
        raise UnknownMemory('integrity loaded byte source is incomplete')
    return value


def _loaded_cstring(runtime, address):
    value = bytearray()
    for index in range(1 << 20):
        byte = _loaded(runtime, address + index, 1)[0]
        if not byte:
            return bytes(value)
        value.append(byte)
    raise PrimarySemanticUnavailable('integrity loaded CString exceeds source bound')


def _source_address(runtime, rva):
    observer = getattr(runtime, 'device_integrity_observations', None)
    method = getattr(observer, 'source_address', None)
    return method(runtime, rva) if callable(method) else runtime.image_base + rva


def _log(runtime, line, template, *values):
    return log(runtime, _SOURCE, line, template, runtime.image_base + 0x48972C7, 1, *values)


def _signed32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & (1 << 31) else value


def _append_offset(runtime, vector, value):
    first, count, capacity = vector
    if count == capacity:
        capacity = max(1, capacity * 2)
        new = runtime._operator_new(capacity * 8)
        runtime.memory.store(new + count * 8, value, 8, source='2DF8D00.offset_append')
        if count:
            runtime.memory.copy_disjoint(new, first, count * 8, label='2DF8D00.offset_growth_copy')
        if first:
            runtime._free_allocation(first)
        first = new
    else:
        runtime.memory.store(first + count * 8, value, 8, source='2DF8D00.offset_append')
    return first, count + 1, capacity


def _event_name(runtime):
    qualified = getattr(runtime, 'integrity_env_detect_initialized', None)
    marker = runtime.image_base + 0x6D8677A
    if qualified != (marker, 'declared-source-initializer-2E0930F'):
        raise PrimarySemanticUnavailable('env_detect source initializer lifecycle is not qualified')
    memory = runtime.memory
    if memory.load(marker, 1) & 1:
        if memory.read(marker, 14) != bytes.fromhex('0107696178566c6e7e6067730000'):
            raise PrimarySemanticUnavailable('env_detect compiled marker differs from source initializer')
        for index in range(10):
            memory.store(marker + index + 2, memory.load(marker + index + 2, 1) ^ (index + 1) ^ 7 ^ 10,
                1, source='2E00138.env_detect_decode')
        memory.write(marker + 12, bytes(2), source='2E0015B.env_detect_terminators')
        memory.store(marker, 0, 1, source='2E00169.env_detect_decoded')
    if _cstring(runtime, marker + 2) != b'env_detect':
        raise PrimarySemanticUnavailable('env_detect decoded marker differs from source')
    return b'env_detect'


def initialize_env_detect(runtime):
    marker = runtime.image_base + 0x6D8677A
    if getattr(runtime, 'integrity_env_detect_initialized', None) is not None:
        raise InputError('env_detect initializer lifecycle is already declared')
    for index, value in enumerate(bytes.fromhex('0107696178566c6e7e6067730000')):
        runtime.memory.store(marker + index, value, 1, source=f'{0x2E0930F + 7 * index:X}.declared_source_initializer')
    runtime.integrity_env_detect_initialized = (marker, 'declared-source-initializer-2E0930F')


def _diagnostic(runtime, rbp, name_pointer, raw_offset, index, loaded, difference):
    memory, base = runtime.memory, runtime.image_base
    memory.store(rbp + 0x700, 125, 8, source='2DFFFF8.committed_source_file_decode_counter')
    name = _event_name(runtime)
    event, temporary, columns = rbp + 0x7B0, rbp + 0x720, rbp + 0x720
    _String.construct(runtime, name).write_to(event + 8)
    for offset in range(32, 200, 24):
        memory.store(event + offset, 0, 2, source='2E0022D.event_empty_field')
    memory.write(event + 200, bytes(24), source='2E0026C.event_base_vector')
    memory.store(event, base + 0x41498D8, 8, source='2E00285.event_vtable')
    memory.write(event + 224, bytes(168), source='2E0028C.event_columns')
    _String.construct(runtime, b'1019').write_to(event + 224)
    _String.construct(runtime, _cstring(runtime, name_pointer)).write_to(event + 248)
    _String.construct(runtime, str((raw_offset + index + difference) & 0xFFFFFFFF).encode('ascii')).write_to(event + 272)
    _invoke(runtime, 0x2E11240, temporary, rbp + 0x310 + difference, 16)
    _String.read(runtime, temporary).write_to(event + 296)
    current_module = _api(runtime, 'GetModuleHandleA', (name_pointer,))
    address = (loaded + difference) & _MASK
    _String.construct(runtime, str((address - current_module) & _MASK).encode('ascii')).write_to(event + 320)
    _invoke(runtime, 0x2E11240, temporary, address, 16)
    _String.read(runtime, temporary).write_to(event + 344)
    _owner(runtime, _response_image())
    for offset in (0, 24):
        _String.construct(runtime, b'').write_to(columns + offset)
    runtime.events.append(('integrity.env_detect', event, index, difference))
    _invoke(runtime, 0x1BEFC10, base + 0x67519B8, event, columns, 1, 10, 0)
    for offset in (24, 0):
        _String.read(runtime, columns + offset).destroy()
    _log(runtime, 0x141, b'result: %s, %s, %s, %s, %s',
        *(_String.read(runtime, event + offset).value() for offset in (248, 272, 296, 320, 344)))
    _invoke(runtime, 0x1C2D0F0, event)


def inspect_module(runtime, name_pointer):
    memory, base = runtime.memory, runtime.image_base
    if type(name_pointer) is not int or not 0 < name_pointer <= _MASK:
        raise InputError('integrity module name requires a borrowed pointer-width CString')
    name = _cstring(runtime, name_pointer)
    if name not in _NAMES:
        raise InputError('integrity predicate supports its two source caller CStrings only')
    frame, rbp = _frame(runtime, 0xA18, '2DF8D00.integrity_frame')
    vector, copied, initial, second, handle = (0, 0, 0), 0, 0, 0, 0
    path, dos, nt, section, count, buffer = rbp - 0x30, rbp + 0xE0, rbp + 0x160, rbp + 0x120, rbp + 0x30C, rbp + 0x310
    def finish(status):
        if handle:
            if copied:
                runtime._free_allocation(copied)
            _api(runtime, 'CloseHandle', (handle,))
        if vector[0]:
            runtime._free_allocation(vector[0])
        if initial:
            runtime._free_allocation(initial)
        runtime.events.append(('integrity.normal_return', status))
        return status
    def fail(line, message, *args):
        _log(runtime, line, message, *args)
        return finish(2)
    def read_file(output, size):
        result = _api(runtime, 'ReadFile', (handle, output, size, count, 0), ((output, size), (count, 4)))
        return result != 0 and memory.load(count, 4) == size
    def seek(offset):
        return _api(runtime, 'SetFilePointer', (handle, offset & 0xFFFFFFFF, 0, 0)) != 0xFFFFFFFF
    try:
        memory.write(path, bytes(260), source='2DF8D2D.zero_path260')
        from .primary_worker_loop import _ensure_logger
        from .primary_logger import feature
        _ensure_logger(runtime)
        if feature(runtime, memory.load(base + 0x67516A8, 8), 3) == 1:
            _log(runtime, 0x209, b'%llx, %llx', _source_address(runtime, 0x3E91B50), memory.load(frame + 0x30, 8))
        initial = runtime._operator_new(8)
        memory.store(initial, _source_address(runtime, 0x3E91B50), 8, source='2DF9293.initial_critical_pointer')
        module = _api(runtime, 'GetModuleHandleA', (name_pointer,))
        if not module:
            return fail(0x211, b'module is null: %s', name_pointer)
        if not _api(runtime, 'GetModuleFileNameA', (module, path, 260), ((path, 260),)):
            return fail(0x216, b'get file name failed: %s', name_pointer)
        second = runtime._operator_new(8)
        critical = _source_address(runtime, 0x3E91B50)
        memory.store(second, critical, 8, source='2DF92EC.critical_pointer_copy')
        loaded_nt = (module + int.from_bytes(_loaded(runtime, module + 0x3C, 4), 'little', signed=True)) & _MASK
        table, loaded, ordinal = (loaded_nt + 0x108) & _MASK, 0, 0
        while _signed32(ordinal) < int.from_bytes(_loaded(runtime, loaded_nt + 6, 2), 'little'):
            header = (table + ordinal * 40) & _MASK
            if _loaded_cstring(runtime, header) == b'.text':
                loaded = (module + int.from_bytes(_loaded(runtime, header + 12, 4), 'little')) & _MASK
                if name != b'wrapper.node':
                    break
                if module < critical < ((module + int.from_bytes(_loaded(runtime, header + 16, 4), 'little')) & _MASK):
                    _log(runtime, 0x12A, b'abort ptr: %llx', critical)
                    vector = _append_offset(runtime, vector, (critical - loaded) & _MASK)
            ordinal = (ordinal + 1) & 0xFFFFFFFF
        runtime._free_allocation(second)
        second = 0
        if not loaded:
            return fail(0x21D, b'textAddr null: %s', name_pointer)
        _log(runtime, 0x220, b'offsetFilter: %x', vector[1])
        for position in range(vector[1]):
            _log(runtime, 0x223, b'offsetFilter: %llx', memory.load(vector[0] + position * 8, 8))
        _cstring(runtime, path)
        handle = _api(runtime, 'CreateFileA', (path, 0x80000000, 1, 0, 3, 0x80, 0))
        if not handle:
            return fail(0x228, b'CreateFileA failed')
        if vector[1]:
            copied = runtime._operator_new(vector[1] * 8)
            memory.copy_disjoint(copied, vector[0], vector[1] * 8, label='2DFA811.copy_offsets')
        memory.store(count, 0, 4, source='2DFA820.bytes_read_initial')
        if not read_file(dos, 64):
            return fail(0x1AC, b'ReadFile dosHeader failed')
        if memory.load(dos, 2) != 0x5A4D:
            return fail(0x1B1, b'ReadFile e_magic failed')
        e_lfanew = memory.load(dos + 0x3C, 4)
        if not seek(e_lfanew):
            return fail(0x1B6, b'SetFilePointer e_lfanew failed')
        if not read_file(nt, 264):
            return fail(0x1BD, b'ReadFile IMAGE_NT_HEADERS failed')
        if name == b'wrapper.node':
            _log(runtime, 0x1C3, b'is wrapper')
        table_offset, ordinal = (e_lfanew + 264) & 0xFFFFFFFF, 0
        while (ordinal & 0xFFFF) < memory.load(nt + 6, 2):
            if not seek(table_offset):
                return fail(0x1CC, b'SetFilePointer sectionTableOffset failed')
            if not read_file(section, 40):
                return fail(0x1D1, b'ReadFile IMAGE_SECTION_HEADER failed')
            if _cstring(runtime, section) == b'.text':
                break
            table_offset, ordinal = (table_offset + 40) & 0xFFFFFFFF, (ordinal + 1) & 0xFFFFFFFF
        else:
            return finish(1)
        memory.write(buffer, bytes(1000), source='2DFE8F1.zero_chunk1000')
        raw_offset, size = memory.load(section + 20, 4), memory.load(section + 16, 4)
        if not seek(raw_offset):
            return fail(0x1DA, b'SetFilePointer sectionHeader.PointerToRawData failed')
        index = 0
        while index < ((size - 1000) & 0xFFFFFFFF):
            if _api(runtime, 'IsBadReadPtr', (loaded, 1000)):
                return fail(0x1E1, b'is bad ptr')
            memory.write(buffer, bytes(1000), source='2DFE980.zero_chunk1000')
            if not read_file(buffer, 1000):
                return finish(2)
            end = _signed32(index + 1000) & _MASK
            skip = False
            if name == b'wrapper.node':
                for position in range(vector[1]):
                    value = memory.load(copied + position * 8, 8)
                    if value and (_signed32(index) & _MASK) < value < end:
                        _log(runtime, 0x1EE, b'abort patch: %llx', value)
                        skip = True
                        break
            if not skip:
                if memory.read(buffer, 1000) != _loaded(runtime, loaded, 1000):
                    _log(runtime, 0x1F3, b'abort patch i: %d', index)
                    _log(runtime, 0x1F4, b'abort patch recordOffset + i: %x', (raw_offset + index) & 0xFFFFFFFF)
                    _log(runtime, 0x1F5, b'abort patch textAddr: %llx', loaded)
                    for difference in range(1000):
                        if memory.load(buffer + difference, 1) != _loaded(runtime, loaded + difference, 1)[0]:
                            _diagnostic(runtime, rbp, name_pointer, raw_offset, index, loaded, difference)
                            break
            loaded, index = (loaded + 1000) & _MASK, (index + 1000) & 0xFFFFFFFF
        return finish(1)
    finally:
        memory.unmap(frame)


def inspect_material_module_prefix(runtime, wrapper_name, qqnt_name):
    if (_cstring(runtime, wrapper_name), _cstring(runtime, qqnt_name)) != _NAMES:
        raise InputError('material predicate prefix requires the two source CStrings in order')
    from .primary_worker_loop import _ensure_logger
    from .primary_logger import feature
    _ensure_logger(runtime)
    if feature(runtime, runtime.memory.load(runtime.image_base + 0x67516A8, 8), 39) != 1:
        return None
    first = inspect_module(runtime, wrapper_name)
    second = inspect_module(runtime, qqnt_name)
    return first & 0xFFFFFFFF, second & 0xFFFFFFFF


def invoke(runtime, rva, values):
    if rva == 0x2DF8D00 and len(values) == 1:
        return inspect_module(runtime, values[0])
    raise InputError('module integrity predicate native argument count mismatch')
