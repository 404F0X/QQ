import hashlib

from .errors import CapabilityUnavailable, InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_MASK64 = (1 << 64) - 1
_IMPORTS = {'CreateToolhelp32Snapshot': 0x490FC88, 'Process32First': 0x4910220,
            'Process32Next': 0x4910230, 'CloseHandle': 0x490FBD8}
_THUNKS = {0x3EB5340: 'CreateToolhelp32Snapshot', 0x3EB57E0: 'Process32First',
           0x3EB57F0: 'Process32Next'}
_ANSI_ADAPTERS = {
    'Process32First': (0x310A0, 279, 'd8af33738b3baf6f574e22c793fefee304710049f58fbb1a09889a4d0b448cf7'),
    'Process32Next': (0x181E0, 279, '2de68f1c4410a5e60d06cecc1e473842da9eee3f60583afb7d231aeb1107f597'),
}
_SCALAR_WRITES = ((16, 8), (24, 4), (28, 4), (32, 4), (36, 4), (4, 4), (40, 4), (8, 4))


class ProcessMaterialObservations:
    def __init__(self, events):
        self._events = events if callable(events) else iter(events)

    def take(self, runtime, name, arguments):
        event = runtime._next(self._events, 'main process ' + name, runtime, name, arguments)
        if (not isinstance(event, tuple) or len(event) != 4 or
                event[0] != name or event[1] != arguments or
                type(event[2]) is not int or not 0 <= event[2] <= _MASK64):
            raise InputError('process material observation requires matching API, arguments, unsigned result and raw writes')
        runtime.events.append(('main.process.API', *event))
        return event[2], event[3]


def compare_process_name(runtime, left, right):
    for offset in range(0, 1 << 20, 2):
        second = runtime.memory.load((right + offset) & _MASK64, 2)
        first = runtime.memory.load((left + offset) & _MASK64, 2)
        if first != second:
            return 1 if first > second else 0xFFFFFFFF
        if second == 0:
            return 0
    raise PrimaryProgramLimit('3E9C1D0 wide comparison exceeds the bounded scan domain')


def invoke_process_material(runtime, name, arguments):
    expected = 2 if name != 'CloseHandle' else 1
    if len(arguments) != expected:
        raise InputError(name + ' has an invalid process material argument count')
    if name == 'CreateToolhelp32Snapshot':
        arguments = tuple(value & 0xFFFFFFFF for value in arguments)
    if runtime.process_material is None:
        raise UnknownMemory('missing main process environment observations: ' + name)
    result, effects = runtime.process_material.take(runtime, name, arguments)
    if name != 'CreateToolhelp32Snapshot' and result > 0xFFFFFFFF:
        raise InputError(name + ' requires an explicit BOOL32 result')
    if name in ('CreateToolhelp32Snapshot', 'CloseHandle'):
        if effects != b'':
            raise InputError(name + ' has no process material output buffer')
    else:
        if not isinstance(effects, tuple):
            raise InputError(name + ' requires ordered PROCESSENTRY32 raw writes')
        for effect in effects:
            if (not isinstance(effect, tuple) or len(effect) != 2 or
                    type(effect[0]) is not int or not isinstance(effect[1], bytes) or
                    not 0 <= effect[0] <= 304 or len(effect[1]) > 304 - effect[0]):
                raise InputError(name + ' output write exceeds the fixed PROCESSENTRY32 structure')
            offset, raw = effect
            if raw:
                runtime.memory.write((arguments[1] + offset) & _MASK64, raw,
                                     source='main.process.' + name)
    return result


def resolve_process_thunk(runtime, vm, rva, cells, argument_types=None):
    seen = set()
    while rva in _THUNKS:
        if rva in seen:
            raise PrimarySemanticUnavailable('recursive process material import thunk is unavailable')
        seen.add(rva)
        address = runtime.memory.load(runtime.image_base + _IMPORTS[_THUNKS[rva]], 8)
        rva = address - runtime.image_base
    return runtime.invoke(vm, rva, cells, argument_types=argument_types)


class WindowsProcessMaterialSource:
    def __init__(self, *, raw_outputs=False):
        import ctypes
        import os
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable('process material collection requires Windows x64')
        self._ctypes = ctypes
        self._kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self._functions = {}
        for name in _IMPORTS:
            function = getattr(self._kernel, name)
            function.restype = ctypes.c_void_p if name == 'CreateToolhelp32Snapshot' else ctypes.c_int32
            function.argtypes = ((ctypes.c_uint32, ctypes.c_uint32) if name == 'CreateToolhelp32Snapshot'
                                else (ctypes.c_void_p,) if name == 'CloseHandle'
                                else (ctypes.c_void_p, ctypes.c_void_p))
            self._functions[name] = function
        self._handles = set()
        self.closed = False
        self.raw_outputs = bool(raw_outputs)
        if self.raw_outputs:
            self.sparse_adapter_verified = False
            return
        base = self._kernel._handle
        self.sparse_adapter_verified = all(
            ctypes.cast(self._functions[name], ctypes.c_void_p).value == base + rva and
            hashlib.sha256(ctypes.string_at(base + rva, size)).hexdigest() == expected
            for name, (rva, size, expected) in _ANSI_ADAPTERS.items())
        self._wide = {}
        self._convert = None
        if self.sparse_adapter_verified:
            wide_type = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p,
                                          ctypes.c_void_p, use_last_error=True)
            self._wide = {'Process32First': wide_type(base + 0x311C0),
                          'Process32Next': wide_type(base + 0x18300)}
            convert_type = ctypes.WINFUNCTYPE(
                ctypes.c_int32, ctypes.c_uint32, ctypes.c_uint32,
                ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_int32,
                ctypes.c_void_p, ctypes.c_void_p, use_last_error=True)
            target = int.from_bytes(ctypes.string_at(base + 0x8BF60, 8), 'little')
            if not target:
                self.sparse_adapter_verified = False
            else:
                self._convert = convert_type(target)

    def observations(self):
        return ProcessMaterialObservations(self._event)

    def _event(self, runtime, name, arguments):
        if self.closed:
            raise InputError('Windows process material source is closed')
        if name not in self._functions:
            raise InputError('Windows process material source received an unsupported API')
        function = self._functions[name]
        if name == 'CreateToolhelp32Snapshot':
            result = function(*arguments)
            result = 0 if result is None else result
            if result not in (0, _MASK64):
                self._handles.add(result)
            effects = b''
        elif name == 'CloseHandle':
            if arguments[0] not in self._handles:
                raise InputError('Windows process material source does not own this handle')
            result = function(arguments[0]) & 0xFFFFFFFF
            if result:
                self._handles.remove(arguments[0])
            effects = b''
        else:
            handle, pointer = arguments
            if handle not in self._handles:
                raise InputError('Windows process material source does not own this snapshot')
            if self.raw_outputs:
                result, effects = self._raw_row(runtime, name, arguments)
                return name, arguments, result, effects
            if self.sparse_adapter_verified:
                result, effects = self._ansi_row(runtime, name, arguments)
                return name, arguments, result, effects
            before = runtime.memory.read(pointer, 304)
            if int.from_bytes(before[:4], 'little') != 304:
                raise PrimarySemanticUnavailable('live process material requires the fixed304-byte input structure')
            buffer = self._ctypes.create_string_buffer(before, 304)
            result = function(handle, self._ctypes.addressof(buffer)) & 0xFFFFFFFF
            after = bytes(buffer)
            writes, start = [], None
            for offset in range(305):
                changed = offset < 304 and before[offset] != after[offset]
                if changed and start is None:
                    start = offset
                elif not changed and start is not None:
                    writes.append((start, after[start:offset]))
                    start = None
            effects = tuple(writes)
        return name, arguments, result, effects

    def _raw_row(self, runtime, name, arguments):
        handle, pointer = arguments
        region, offset = runtime.memory._span(pointer, 304)
        if runtime.memory.load(pointer, 4) != 304:
            raise InputError('raw ANSI process source requires the source304-byte dwSize input')
        initial = region.data[offset:offset + 304]
        known = region.initialized[offset:offset + 304]
        before = bytes(value if bit else 0xA5 for value, bit in zip(initial, known))
        output = self._ctypes.create_string_buffer(before, 304)
        result = self._functions[name](handle, self._ctypes.addressof(output)) & 0xFFFFFFFF
        after = output.raw
        writes, start = [], None
        for index in range(305):
            changed = index < 304 and before[index] != after[index]
            if changed and start is None:
                start = index
            elif not changed and start is not None:
                writes.append((start, after[start:index]))
                start = None
        return result, tuple(writes)

    def _ansi_row(self, runtime, name, arguments):
        handle, pointer = arguments
        region, start = runtime.memory._span(pointer, 304)
        size = runtime.memory.load(pointer, 4)
        if size < 304:
            buffer = self._ctypes.create_string_buffer(size.to_bytes(4, 'little') + bytes(300), 304)
            result = self._functions[name](handle, self._ctypes.addressof(buffer)) & 0xFFFFFFFF
            return result, ()
        wide = self._ctypes.create_string_buffer((568).to_bytes(4, 'little') + bytes(564), 568)
        result = self._wide[name](handle, self._ctypes.addressof(wide)) & 0xFFFFFFFF
        known = all(region.initialized[start + 44:start + 304])
        before = bytes(region.data[start + 44:start + 304]) if known else b'\xA5' * 260
        output = self._ctypes.create_string_buffer(before, 260)
        count = self._convert(0, 0x400, self._ctypes.addressof(wide) + 44, -1,
                              self._ctypes.addressof(output), 260, None, None)
        after = bytes(output)
        if count:
            if not 0 < count <= 260:
                raise InputError('WideCharToMultiByte returned an invalid process name byte count')
            effects = [(44, after[:count])]
        elif known:
            effects, beginning = [], None
            for offset in range(261):
                changed = offset < 260 and before[offset] != after[offset]
                if changed and beginning is None:
                    beginning = offset
                elif not changed and beginning is not None:
                    effects.append((44 + beginning, after[beginning:offset]))
                    beginning = None
        else:
            raise UnknownMemory('process ANSI conversion failure needs its observed name-buffer effects')
        raw = bytes(wide)
        effects.extend((offset, raw[offset:offset + width]) for offset, width in _SCALAR_WRITES)
        return result, tuple(effects)

    def close(self):
        if self.closed:
            return
        for handle in tuple(self._handles):
            if not self._functions['CloseHandle'](handle):
                raise self._ctypes.WinError(self._ctypes.get_last_error())
            self._handles.remove(handle)
        if self.raw_outputs:
            free = self._kernel.FreeLibrary
            free.restype, free.argtypes = self._ctypes.c_int32, (self._ctypes.c_void_p,)
            if not free(self._kernel._handle):
                raise self._ctypes.WinError(self._ctypes.get_last_error())
            self._functions.clear()
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()
