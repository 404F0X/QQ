from .errors import InputError
from .primary_logger import _cstring
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_response import _frame


_IMPORTS = {'GetModuleHandleW': 0x490FF10, 'GetProcAddress': 0x490FF40,
            'GetCurrentProcess': 0x490FDE0, 'OpenProcess': 0x4910200,
            'QueryFullProcessImageNameA': 0x4910248, 'CloseHandle': 0x490FBD8}
_EXPORT = bytes.fromhex('774e6a49584c46795f545c465857434146447b5e424d4a5352')
_MODULE = bytes.fromhex('5c3144375235583b5639163f5a3d50234e21')


def _observe(runtime, name, arguments):
    if name != 'NtQueryInformationProcess':
        target = runtime.worker_imports.get(name)
        if target is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != target:
            raise PrimarySemanticUnavailable('parent process current import is not bound: ' + name)
    observer = getattr(runtime, 'notification_environment_observations', None)
    if observer is None:
        observer = runtime.worker_observations
    if observer is None:
        raise UnknownMemory('missing parent process raw API observation: ' + name)
    result, effects = observer.take(runtime, name, arguments)
    if type(result) is not int or not 0 <= result < 1 << 64:
        raise InputError('parent process API requires an unsigned pointer-width result')
    return result, effects


def _decode(runtime, frame, offset, encoded, sites, counter, decode_site, counter_site, end_sites):
    memory = runtime.memory
    raw = bytes([1, 0x21]) + encoded + bytes(2)
    for index, value in enumerate(raw):
        memory.store(frame + offset + index, value, 1, source=f'{sites[index]:X}.parent_stack_literal')
    initial_site = 0x35BF767 if len(encoded) == 25 else 0x35BF8C6
    memory.store(frame + counter, 0, 8, source=f'{initial_site:X}.parent_decode_counter')
    for index in range(len(encoded)):
        value = memory.load(frame + offset + index + 2, 1)
        seed = memory.load(frame + offset + 1, 1)
        memory.store(frame + offset + index + 2, value ^ ((index + 1) & 255) ^ seed ^ len(encoded), 1,
                     source=f'{decode_site:X}.parent_stack_decode')
        memory.store(frame + counter, index + 1, 8, source=f'{counter_site:X}.parent_decode_counter')
    for index, site in enumerate(end_sites[:2]):
        memory.store(frame + offset + len(encoded) + 2 + index, 0, 1,
                     source=f'{site:X}.parent_stack_terminator')
    memory.store(frame + offset, 0, 1, source=f'{end_sites[2]:X}.parent_stack_decoded')
    return memory.read(frame + offset + 2, len(encoded) + (2 if len(encoded) == 18 else 1))


def _output(runtime, address, raw, size):
    if not isinstance(raw, bytes) or len(raw) != size:
        raise InputError('parent process observation requires its complete source output postimage')
    runtime.memory.write(address, raw, source='parent_process.raw_API_postimage')


def parent_image(runtime, destination):
    memory = runtime.memory
    frame, ignored = _frame(runtime, 0x218, '35BF640.parent_process_frame')

    def empty(site):
        memory.store(destination, 0, 2, source=f'{site:X}.parent_empty_string')
        return destination

    try:
        export = _decode(runtime, frame, 0x1D8, _EXPORT,
                         tuple(0x35BF670 + index * 8 for index in range(29)),
                         0x1C0, 0x35BF7C2, 0x35BF7C9, (0x35BF7E3, 0x35BF7EB, 0x35BF7F3))
        module = _decode(runtime, frame, 0x1C0, _MODULE,
                         (0x35BF803, 0x35BF80B) + tuple(0x35BF81B + index * 8 for index in range(20)),
                         0x30, 0x35BF909, 0x35BF910, (0x35BF924, 0x35BF92C, 0x35BF934))
        handle, ignored = _observe(runtime, 'GetModuleHandleW', (module,))
        function, ignored = _observe(runtime, 'GetProcAddress', (handle, export))
        if not function:
            return empty(0x35BFBCB)
        for offset, site in ((0x20, 0x35BFA48), (0x10, 0x35BFA4C), (0, 0x35BFA50)):
            memory.write(frame + 0x190 + offset, bytes(16), source=f'{site:X}.parent_zero_PBI')
        current, ignored = _observe(runtime, 'GetCurrentProcess', ())
        status, raw = _observe(runtime, 'NtQueryInformationProcess',
                               (function, current, 0, memory.read(frame + 0x190, 48), 48, 0))
        _output(runtime, frame + 0x190, raw, 48)
        if status & 0x80000000:
            return empty(0x35BF9F4)
        parent = memory.load(frame + 0x1B8, 8)
        if not parent:
            return empty(0x35BF9F4)
        process, ignored = _observe(runtime, 'OpenProcess', (0x1000, 0, parent))
        if not process:
            return empty(0x35BFB01)
        memory.write(frame + 0x80, bytes(260), source='35BFB28.parent_zero_ANSI_buffer')
        memory.store(frame + 0x7C, 260, 4, source='35BFB37.parent_initial_capacity')
        try:
            result, effects = _observe(runtime, 'QueryFullProcessImageNameA',
                                       (process, 0, memory.read(frame + 0x80, 260), memory.load(frame + 0x7C, 4)))
            if not isinstance(effects, tuple) or len(effects) != 2:
                raise InputError('parent image query requires buffer and capacity postimages')
            _output(runtime, frame + 0x80, effects[0], 260)
            _output(runtime, frame + 0x7C, effects[1], 4)
        finally:
            _observe(runtime, 'CloseHandle', (process,))
        if not result & 0xFFFFFFFF:
            return empty(0x35BFBDB)
        value = _cstring(runtime, frame + 0x80)
        length = len(value)
        if length < 23:
            memory.store(destination, length * 2, 1, source='35BFB9D.parent_short_flag')
            pointer = destination + 1
        else:
            capacity = (length + 16) & ~15
            pointer = runtime._operator_new(capacity)
            memory.store(destination + 16, pointer, 8, source='35BFC2C.parent_long_pointer')
            memory.store(destination, capacity | 1, 8, source='35BFC34.parent_long_capacity')
            memory.store(destination + 8, length, 8, source='35BFC37.parent_long_length')
        if length:
            memory.write(pointer, value, source='35BFC44.parent_string_copy')
        memory.store(pointer + length, 0, 1, source='35BFC49.parent_string_terminator')
        return destination
    finally:
        memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva != 0x35BF640 or len(values) != 1:
        raise InputError('parent image producer requires exactly one output String pointer')
    return parent_image(runtime, values[0])
