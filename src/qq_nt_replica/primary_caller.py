from .errors import InputError
from .primary_logger import log
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations, _flag, _settings
from .primary_worker_consumer import _invoke
from contextlib import nullcontext


_IMPORTS = {'GetModuleHandleA': 0x490FEF8, 'GetProcAddress': 0x490FF40,
            'GetModuleHandleExW': 0x490FF08, 'GetModuleFileNameA': 0x490FEE8,
            'GetLastError': 0x490FEA8, 'PathFindFileNameA': 0x4910AB0,
            'RtlCaptureContext': 0x49102C0, 'RtlLookupFunctionEntry': 0x49102C8,
            'RtlVirtualUnwind': 0x49102E8,
            'GetForegroundWindow': 0x49105A0, 'GetWindowTextA': 0x49105F0,
            'GetClassNameA': 0x4910560, 'GetWindowRect': 0x49105E8,
            'IsWindowVisible': 0x4910628, 'GetWindowThreadProcessId': 0x4910608,
            'GetCurrentProcessId': 0x490FDE8, 'GetCursorPos': 0x4910580}
_MODULES = frozenset((b'wrapper.node', b'ntdll.dll', b'KERNEL32.DLL'))
_SOURCE = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\platforms\\Windows\\libsecxx\\base\\qqprotect_util/CheckCallStack.h'


def install_image(memory, base):
    memory.map(base + 0x6751B40, bytearray(12), name='fixed caller resolver PE zero fill', initialized=True)
    memory.map(base + 0x6751D88, bytearray(8), name='fixed caller diagnostic owner PE zero fill', initialized=True)
    memory.map(base + 0x414B558, b''.join((base + rva).to_bytes(8, 'little')
                                       for rva in (0x1CFA5A0, 0x1BFCA40, 0x375AE0)),
               name='fixed caller diagnostic virtual interface', initialized=True)
    memory.map(base + 0x414B698, b''.join((base + rva).to_bytes(8, 'little')
                                       for rva in (0x142A0, 0x1D040D0, 0x1D040F0, 0x28F0, 0x1FE0, 0x1D04120)),
               name='fixed caller online consumer virtual interface', initialized=True)
    memory.map(base + 0x414B5E8, b''.join((base + rva).to_bytes(8, 'little')
                                       for rva in (0x1D027F0, 0x1D02830, 0x1D028D0, 0x1D02990, 0x1D029A0, 0x1D029C0)),
               name='fixed caller online queue callback virtual interface', initialized=True)
    for rva, raw in ((0x47A926A, b'Finalize\0'), (0x48B0A37, b'-1\0')):
        memory.map(base + rva, raw, name='fixed caller online source literal', initialized=True)
    memory.map(base + 0x677D2B0, bytearray(0x9E0), name='fixed caller online random and manager PE zero fill', initialized=True)
    for rva in (0x677BE28, 0x677BE78):
        if not any(region.address <= base + rva and base + rva + 8 <= region.address + len(region.data)
                   for region in memory._regions):
            memory.map(base + rva, bytearray(8), name='fixed caller online persistence PE zero fill', initialized=True)


def selected(command):
    if not isinstance(command, bytes) or b'\0' in command:
        raise InputError('caller command requires terminated-string contents without NUL')
    if any(value >= 128 for value in command):
        raise PrimarySemanticUnavailable('caller command search requires the actual non-ASCII ANSI locale')
    return b'login' in command.lower() or command == b'MessageSvc.PbSendMsg'


def _api(runtime, observations, name, *arguments):
    if not isinstance(observations, WorkerObservations):
        raise UnknownMemory('missing explicit caller Windows observations: ' + name)
    if name in _IMPORTS:
        expected = runtime.worker_imports.get(name)
        if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
            raise PrimarySemanticUnavailable('caller current import is not bound: ' + name)
    return observations.take(runtime, name, arguments)


def _wrapper_scope(runtime, site, arguments):
    binding = getattr(runtime, '_caller_wrapper_binding', None)
    return nullcontext() if binding is None else binding.scope(runtime, site, arguments)


def _bytes(value, size, name):
    if not isinstance(value, bytes) or len(value) != size:
        raise InputError(name + ' requires its exact raw output bytes')
    return value


def _module_allowed(runtime, filename):
    state = getattr(runtime, 'caller_crt_locale_state', 0)
    if state is None:
        raise PrimarySemanticUnavailable('caller effective source CRT locale state is unknown')
    if type(state) is not int or not 0 <= state <= 0xFFFFFFFF:
        raise InputError('caller source CRT locale state requires a DWORD or explicit unknown')
    if state:
        table = getattr(runtime, 'caller_crt_lower_table', None)
        if table is None:
            raise PrimarySemanticUnavailable('caller non-C source CRT requires its effective 256-byte lower table')
        table = _bytes(table, 256, 'caller source CRT lower table')
    else:
        table = bytes(value + 32 if 65 <= value <= 90 else value for value in range(256))
    return any(filename.translate(table) == value.translate(table) for value in _MODULES)


def _capture_failure(runtime, observations, kind):
    error, effects = _api(runtime, observations, 'GetLastError')
    if effects is not None:
        raise InputError('GetLastError has no output buffer')
    return None, error & 0xFFFFFFFF, kind


def _filename(runtime, observations, address, capacity, unwind=False):
    result, module = _api(runtime, observations, 'GetModuleHandleExW', 6, address)
    if not result & 0xFFFFFFFF:
        return (None, None, 'module') if unwind else _capture_failure(runtime, observations, 'module')
    handle = int.from_bytes(_bytes(module, 8, 'GetModuleHandleExW'), 'little')
    if not handle:
        return (None, None, 'module') if unwind else _capture_failure(runtime, observations, 'module')
    result, path = _api(runtime, observations, 'GetModuleFileNameA', handle, capacity)
    result &= 0xFFFFFFFF
    if not result:
        return (None, None, 'filename') if unwind else _capture_failure(runtime, observations, 'filename')
    if unwind:
        if not result < capacity:
            raise PrimarySemanticUnavailable('caller truncated unwind module filename remains unavailable')
        path = _bytes(path, result + 1, 'GetModuleFileNameA')
        if path[-1] or b'\0' in path[:-1]:
            raise InputError('caller unwind module filename must have exactly one terminating NUL')
        path = path[:-1]
    else:
        if not isinstance(path, bytes) or len(path) > capacity:
            raise InputError('GetModuleFileNameA requires bounded actual output bytes')
        scratch = bytearray(520)
        scratch[:len(path)] = path
        path = bytes(scratch).split(b'\0', 1)[0]
    if any(value >= 128 for value in path):
        offset, effects = _api(runtime, observations, 'PathFindFileNameA', path + b'\0')
        if type(offset) is not int or not 0 <= offset <= len(path) or effects is not None:
            raise InputError('PathFindFileNameA requires an offset into its bounded CString and no effects')
        return path, path[offset:], None
    offset = _ascii_basename_offset(path)
    return path, path[offset:], None


def _ascii_basename_offset(path):
    offset, colons, colon_offset = 0, 0, None
    for index, value in enumerate(path):
        following = path[index + 1] if index + 1 < len(path) else 0
        if value in (47, 92) and following not in (0, 47, 92):
            offset, colons, colon_offset = index + 1, 0, None
        elif value == 58:
            colons += 1
            if colon_offset is None and following not in (0, 47, 92):
                colon_offset = index + 1
    if colons == 1 and colon_offset is not None:
        offset = colon_offset
    return offset


def prepare(runtime, command, observations):
    if not selected(command):
        return False
    scope = getattr(runtime, '_primary_direct_scope', None)
    with scope.caller_prepare(command) if scope is not None else nullcontext():
        memory, base = runtime.memory, runtime.image_base
        settings = _settings(runtime)
        memory.store(settings + 60, memory.load(settings + 60, 4) & 0xFFFFFFFE, 4,
                     source='BA29F2.caller_flags_clear')
        _invoke(runtime, 0x1BF75A0, 0, 0, 1, 0)
        with _wrapper_scope(runtime, 0xBA2A14, (0, 0, 1, 0)):
            _invoke(runtime, 0x1BF8090, 0, 0, 1, 0)
        if not memory.load(base + 0x6751B48, 4):
            module, effects = _api(runtime, observations, 'GetModuleHandleA', b'ntdll.dll')
            if effects is not None:
                raise InputError('caller named module lookup has no output buffer')
            capture = 0
            if module:
                capture, effects = _api(runtime, observations, 'GetProcAddress', module, b'RtlCaptureStackBackTrace')
                if effects is not None:
                    raise InputError('caller named procedure lookup has no output buffer')
                memory.store(base + 0x6751B40, capture, 8, source='BA2C54.caller_capture_export')
            memory.store(base + 0x6751B48, 1, 4, source='BA2AA5.caller_capture_resolved')
        capture = memory.load(base + 0x6751B40, 8)
        capture_valid = True
        filenames = []
        if capture:
            count, frames = _api(runtime, observations, 'RtlCaptureStackBackTrace', capture, 0, 2)
            count &= 0xFFFF
            if count > 2:
                raise InputError('caller stack capture exceeds its two-frame destination')
            frames = _bytes(frames, count * 8, 'RtlCaptureStackBackTrace')
            for index in range(count):
                address = int.from_bytes(frames[index * 8:index * 8 + 8], 'little')
                _, filename, failure = _filename(runtime, observations, address, 519)
                if failure:
                    prefix, line = (b'GMH:', 102) if failure == 'module' else (b'GFN:', 87)
                    error = filename
                    log(runtime, _SOURCE, line, prefix + b' %08x, %d, %d, %d',
                        b'[FGESDK]', 1, address, count, index, error)
                    filename = prefix + str(address & 0xFFFFFFFFFFFFFFFF).encode('ascii') + b',' + str(error).encode('ascii')
                filenames.append(filename)
                if failure or not _module_allowed(runtime, filename):
                    from .primary_caller_diagnostics import _Strings, report
                    from .primary_logger import _String
                    modules = _Strings(runtime)
                    for value in filenames:
                        modules.push(_String.construct(runtime, value))
                    log(runtime, _SOURCE, 110, b'CCS: %d', b'[FGESDK]', 1, 0)
                    owner = memory.load(base + 0x6751D88, 8)
                    if not owner:
                        owner = runtime._operator_new(24)
                        memory.write(owner, bytes(24), source='BA41BF.caller_diagnostic_owner_initialization')
                        memory.store(base + 0x6751D88, owner, 8, source='BA41CA.caller_diagnostic_owner_publish')
                    forwarded = modules.clone()
                    report(runtime, observations, _api, owner, _String.construct(runtime, b'login'),
                           _String.construct(runtime, b'cs3'), forwarded)
                    forwarded.destroy()
                    modules.destroy()
                    capture_valid = False
                    break
        result, context = _api(runtime, observations, 'RtlCaptureContext')
        if result is not None:
            raise InputError('caller context capture is a void Windows service')
        context = _bytes(context, 1232, 'RtlCaptureContext')
        unwind_valid = True
        for index in range(3):
            pc = int.from_bytes(context[248:256], 'little')
            entry, image = _api(runtime, observations, 'RtlLookupFunctionEntry', pc)
            if not entry:
                if image is not None:
                    raise InputError('failed caller function lookup must preserve its unused image-base output')
                break
            image = int.from_bytes(_bytes(image, 8, 'RtlLookupFunctionEntry'), 'little')
            _, context = _api(runtime, observations, 'RtlVirtualUnwind', 0, image, pc, entry, context)
            context = _bytes(context, 1232, 'RtlVirtualUnwind')
            path, filename, failure = _filename(runtime, observations, pc, 260, unwind=True)
            if failure:
                line, template = {
                    'module': (194, b'[CCS] %d: GetModuleHandleEx failed %08x'),
                    'filename': (185, b'[CCS] %d: GetModuleFileNameA failed %08x'),
                }[failure]
                log(runtime, _SOURCE, line, template, b'[FGESDK]', 1, index + 1, pc)
                unwind_valid = False
                break
            if not _module_allowed(runtime, filename):
                log(runtime, _SOURCE, 190, b'[CCS] %d: %08x, %s', b'[FGESDK]', 1, index + 1, pc, path)
                unwind_valid = False
                break
        if not capture_valid:
            with scope.caller_status_transition('capture-invalid') if scope is not None else nullcontext() as status_transition_claim:
                with _wrapper_scope(runtime, 0xBA5D6B, (1, 0, 1, 0)):
                    _flag(runtime, 0, 1)
        if not unwind_valid:
            with scope.caller_status_transition('unwind-invalid') if scope is not None else nullcontext() as status_transition_claim:
                with _wrapper_scope(runtime, 0xBA5E10, (1, 22, 1, 0)):
                    _flag(runtime, 22, 1)
        log(runtime, _SOURCE, 419, b'CCS %d', b'[FGESDK]', 1, int(capture_valid))
        runtime.events.append(('caller.prepare.complete', command, settings))
        return True
