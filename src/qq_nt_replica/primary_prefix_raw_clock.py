from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from hashlib import sha256
import re
from threading import get_ident

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_consumed_mgf import SourceIdentity, SOURCE_SHA256
from .primary_main_clock_inputs import _MainClockReturnBinding, _SITES, _MAIN_SHA256, _fail

PE_SHA256 = '63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'

API = {
    'QPF': ('QueryPerformanceFrequency', 0x4910260, 0x359245A, 8),
    'QPC': ('QueryPerformanceCounter', 0x4910258, 0x3592473, 8),
    'FILETIME': ('GetSystemTimeAsFileTime', 0x490FFB8, 0x359249D, 8),
    'BCrypt': ('BCryptGenRandom', 0x4911180, 0x35924F9, 4),
}

def require(condition, code):
    if not condition:
        raise InputError('HOST129_RAW_API_' + code)

def keys(row, expected, code):
    require(type(row) is dict and set(row) == set(expected.split()), code)

def integer(value, bits=64, minimum=0):
    require(type(value) is int and minimum <= value < 1 << bits, 'INTEGER')
    return value

def pointer(value):
    require(type(value) is str and re.fullmatch(r'0x[0-9a-f]{16}', value) is not None, 'POINTER')
    return int(value, 16)

def hex_bytes(value, size):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', value) is not None, 'HEX')
    return bytes.fromhex(value)

def label(value):
    require(type(value) is str and bool(value), 'LABEL')
    return value

@dataclass(frozen=True, repr=False)
class ClockState:
    guard: bytes
    frequency: bytes

def state(row):
    keys(row, 'guardHex guardKnownMask frequencyHex frequencyKnownMask', 'STATE_KEYS')
    require(row['guardKnownMask'] == 'ff' and row['frequencyKnownMask'] == 'ffffffffffffffff', 'STATE_KNOWN')
    return ClockState(hex_bytes(row['guardHex'], 1), hex_bytes(row['frequencyHex'], 8))

def module(row):
    keys(row, 'name path base size', 'MODULE_KEYS')
    label(row['name'])
    label(row['path'])
    base = pointer(row['base'])
    size = integer(row['size'], 32, 1)
    require(base + size <= 1 << 64, 'MODULE_SPAN')
    return base, size

@dataclass(frozen=True, repr=False)
class APIRow:
    api: str
    name: str
    output: int
    width: int
    status: int | None
    before: bytes
    after: bytes
    initial_known: bytes
    defined_after: bytes
    coverage: str
    enter_seq: int
    leave_seq: int

def api_row(row, service, ordinal, image_base):
    keys(row, 'api ordinal identity iatRva iatTarget returnRva entryRSP arguments outputPointer width enterSeq leaveSeq normalReturn status beforeHex afterHex initialKnownMask definedAfterMask coverage actualWriteMask', 'API_KEYS')
    require(type(row['api']) is str and row['api'] in API, 'API_NAME')
    api = row['api']
    name, iat, ra, width = API[api]
    require(integer(row['ordinal'], 32) == ordinal and row['normalReturn'] is True, 'API_ORDER')
    require(type(row['iatRva']) is int and row['iatRva'] == iat and type(row['returnRva']) is int and row['returnRva'] == ra, 'API_CALLSITE')
    require(type(row['width']) is int and row['width'] == width and pointer(row['entryRSP']) > 0, 'API_ABI')
    identity = row['identity']
    keys(identity, 'exportName sourceModule resolvedAddress resolvedModule', 'API_IDENTITY_KEYS')
    require(identity['exportName'] == name, 'API_EXPORT')
    module(identity['sourceModule'])
    target_base, target_size = module(identity['resolvedModule'])
    target = pointer(identity['resolvedAddress'])
    require(target_base <= target < target_base + target_size and pointer(row['iatTarget']) == target, 'API_TARGET')
    expected_module = 'bcrypt.dll' if api == 'BCrypt' else 'kernel32.dll'
    require(identity['sourceModule']['name'].casefold() == expected_module, 'API_SOURCE_MODULE')
    output = pointer(row['outputPointer'])
    entropy = service['kind'] == 'entropy'
    require((api == 'BCrypt') == entropy, 'API_SERVICE_KIND')
    require(output == (pointer(service['entryRSP']) - (0x1C if entropy else 0x18) if api != 'QPF' else image_base + 0x6D88CD0), 'API_OUTPUT')
    require(type(row['arguments']) is list, 'API_ARGUMENTS')
    arguments = tuple(pointer(item) for item in row['arguments'])
    require(arguments == ((0, output, 4, 2) if entropy else (output,)), 'API_ARGUMENTS')
    status = row['status']
    if api == 'FILETIME':
        require(status is None, 'FILETIME_VOID')
        result, success = None, True
    else:
        keys(status, 'kind rawU32 signedI32', 'STATUS_KEYS')
        result = integer(status['rawU32'], 32)
        signed = result - (1 << 32) if result & (1 << 31) else result
        require(type(status['signedI32']) is int and status['signedI32'] == signed, 'STATUS_SIGN')
        require(status['kind'] == ('NTSTATUS32' if entropy else 'BOOL32'), 'STATUS_KIND')
        success = signed >= 0 if entropy else result != 0
    before, after = hex_bytes(row['beforeHex'], width), hex_bytes(row['afterHex'], width)
    initial, defined = hex_bytes(row['initialKnownMask'], width), hex_bytes(row['definedAfterMask'], width)
    expected_initial = b'\xff' * width if api in ('QPF', 'BCrypt') else bytes(width)
    require(initial == expected_initial and defined == (b'\xff' * width if success else initial), 'API_KNOWNMASK')
    coverage = 'FULL_BY_API_CONTRACT' if success else 'UNKNOWN'
    require(row['coverage'] == coverage and row['actualWriteMask'] is None, 'API_COVERAGE')
    require(not entropy or before == bytes(4), 'BCRYPT_SOURCE_ZERO')
    enter, leave = integer(row['enterSeq']), integer(row['leaveSeq'])
    require(service['enterSeq'] < enter < leave < service['leaveSeq'], 'API_SEQUENCE')
    return APIRow(api, name, output, width, result, before, after, initial, defined, coverage, enter, leave)

@dataclass(frozen=True, repr=False)
class Service:
    kind: str
    ordinal: int
    word: int
    consumed_pc: int
    call_id: str
    entry_rsp: int
    before: ClockState
    after: ClockState
    rows: tuple[APIRow, ...]
    enter_seq: int
    leave_seq: int

class APIEffects:
    def __init__(self):
        self.events = []

    def write(self, memory, row, destination):
        require(type(row) is APIRow and destination == row.output and row.width == 8, 'OUTPUT_CONSUMER')
        region, offset = memory._span(destination, row.width)
        before = bytes(region.data[offset:offset + row.width])
        known = bytes(region.initialized[offset:offset + row.width])
        require(known == bytes(int(bit != 0) for bit in row.initial_known), 'OUTPUT_INITIAL_KNOWN')
        require(all(not bit or current == captured for current, captured, bit in zip(before, row.before, known)), 'OUTPUT_INITIAL_VALUE')
        self.events.append(dict(api=row.api, coverage=row.coverage, actualWriteMask=None, consumed=False))
        if row.coverage == 'FULL_BY_API_CONTRACT':
            memory.write(destination, row.after, source=row.name + '.raw_api_contract_output')
        elif any(bit and current != captured for current, captured, bit in zip(before, row.after, known)):
            raise UnknownMemory('HOST129_RAW_API_FAILED_OUTPUT_CHANGED_WITH_UNKNOWN_WRITES')
        self.events[-1]['consumed'] = True
        return row.status

    def bcrypt(self, row):
        require(type(row) is APIRow and row.api == 'BCrypt' and row.before == bytes(4) and row.initial_known == b'\xff' * 4, 'BCRYPT_CONSUMER')
        self.events.append(dict(api=row.api, coverage=row.coverage, actualWriteMask=None, consumed=True))
        return row.status, row.after if row.coverage == 'FULL_BY_API_CONTRACT' else bytes(4)

_EVENT_KEYS = set(('kind ordinal word consumedPC siteWord strictOrdinal signature calleeRva innerReturnRva callId entryRSP enterSeq leaveSeq normalReturn stateBefore stateAfter apiRows compareOnly').split())
_ROOT_KEYS = set(('schema sourcePeSha256 moduleBase moduleGeneration processCreationIdentity mainEpoch readerInvocation thread mainEntry initialClockState initialSetupState events').split())


@dataclass(frozen=True, repr=False)
class PrefixMain1160Event:
    service: Service
    site_word: int = field(default=1160, init=False)


@dataclass(frozen=True, repr=False, init=False)
class PrefixMain1160RawInputs:
    source_identity: SourceIdentity
    process_creation_identity: str
    module_load_generation: str
    native_thread_id: int
    reader_invocation: int
    initial: ClockState
    setup_guard: bytes
    events: tuple
    _claimed: bool = field(default=False, init=False, compare=False)

    def __init__(self, source_identity, wire):
        require(type(source_identity) is SourceIdentity and source_identity.wrapper_sha256 == SOURCE_SHA256 and
                source_identity.main_arguments[0] == 4 and source_identity.main_arguments[9] == 2, 'PREFIX_SOURCE_IDENTITY')
        require(type(wire) is dict and set(wire) == _ROOT_KEYS and wire['schema'] == 'main-prefix1160-raw-v1' and
                wire['sourcePeSha256'] == PE_SHA256 and pointer(wire['moduleBase']) == source_identity.image_base and
                wire['mainEpoch'] == source_identity.candidate, 'PREFIX_ROOT_IDENTITY')
        for name in ('moduleGeneration', 'processCreationIdentity', 'mainEpoch'):
            label(wire[name])
        thread, reader = integer(wire['thread'], 32, 1), integer(wire['readerInvocation'], 32, 1)
        entry = wire['mainEntry']
        keys(entry, 'entryRSP seq', 'PREFIX_MAIN_ENTRY')
        require(pointer(entry['entryRSP']) > 0 and integer(entry['seq'], 53, 1) > 0, 'PREFIX_MAIN_ENTRY')
        initial = state(wire['initialClockState'])
        keys(wire['initialSetupState'], 'guardHex guardKnownMask', 'PREFIX_SETUP')
        require(wire['initialSetupState'] == {'guardHex': '01', 'guardKnownMask': 'ff'}, 'PREFIX_SETUP_UNSUPPORTED')
        rows = wire['events']
        require(type(rows) is list and len(rows) == 1, 'PREFIX_EXACTLY_ONE_1160_EVENT')
        row = rows[0]
        require(type(row) is dict and set(row) == _EVENT_KEYS, 'PREFIX_EVENT_KEYS')
        values = tuple(row[name] for name in ('ordinal', 'strictOrdinal', 'word', 'siteWord', 'consumedPC', 'signature', 'calleeRva', 'innerReturnRva'))
        require(all(type(value) is int for value in values) and values == (0, 0, 1160, 1160, 1168, 125, 0x2DE561F, 0x2DE565C) and
                row['kind'] == 'clock' and row['normalReturn'] is True and row['callId'] == wire['mainEpoch'] + ':clock:0', 'PREFIX_SOURCE_SITE')
        require(integer(entry['seq'], 53, 1) < integer(row['enterSeq'], 53, 1) < integer(row['leaveSeq'], 53, 1), 'PREFIX_SEQUENCE')
        before, after = state(row['stateBefore']), state(row['stateAfter'])
        require(before == initial and type(row['apiRows']) is list and 1 <= len(row['apiRows']) <= 2, 'PREFIX_STATE_OR_API_COUNT')
        apis = tuple(api_row(value, row, index, source_identity.image_base) for index, value in enumerate(row['apiRows']))
        require(all(a.leave_seq < b.enter_seq for a, b in zip(apis, apis[1:])), 'PREFIX_API_SEQUENCE')
        if before.guard != bytes(1):
            require(tuple(api.api for api in apis) == ('QPC',) and after == before, 'PREFIX_WARM_CLOCK')
        else:
            require(len(apis) == 2 and apis[0].api == 'QPF' and
                    apis[1].api == ('QPC' if apis[0].status != 0 else 'FILETIME') and
                    apis[0].before == before.frequency and after.frequency == apis[0].after and
                    after.guard == bytes([int(apis[0].status != 0)]), 'PREFIX_COLD_CLOCK')
        keys(row['compareOnly'], 'serviceValue', 'PREFIX_COMPARE_ONLY')
        pointer(row['compareOnly']['serviceValue'])
        service = Service('clock', 0, 1160, 1168, row['callId'], pointer(row['entryRSP']), before, after, apis, row['enterSeq'], row['leaveSeq'])
        values = dict(source_identity=source_identity, process_creation_identity=wire['processCreationIdentity'],
            module_load_generation=wire['moduleGeneration'], native_thread_id=thread, reader_invocation=reader,
            initial=initial, setup_guard=b'\x01', events=(PrefixMain1160Event(service),), _claimed=False)
        for name, value in values.items():
            object.__setattr__(self, name, value)


class _MainPrefixRawClockBinding(_MainClockReturnBinding):
    def __init__(self, rows, runtime, *, _prefix_owner=None):
        require(type(rows) is tuple and len(rows) == 1 and type(rows[0]) is PrefixMain1160RawInputs and
                not rows[0]._claimed and rows[0].source_identity.generation == runtime._main_generation + 1 and
                rows[0].source_identity.image_base == runtime.image_base and runtime._active_main is None and
                not runtime._program_calls and not runtime._active_failed, 'PREFIX_RAW_BINDING')
        if runtime._main_generation:
            from .primary_main_prefix_stop import _PrefixOwner
            require(type(_prefix_owner) is _PrefixOwner and _prefix_owner.runtime is runtime and
                runtime.__dict__.get('_main_prefix9563_retired') is _prefix_owner and _prefix_owner.state == 'retired' and
                _prefix_owner.clock is runtime._main_clock_binding and _prefix_owner.clock.closed, 'PREFIX_REBIND_OWNER')
        row = rows[0]
        self._rows, self._runtime, self._thread = rows, runtime, get_ident()
        self._row_index = self._event_index = 0
        self._row = self._call = self._vm = self._generation = None
        self._reading = self.closed = self.finished = False
        self.active = None
        self.api_index = 0
        self.effects = APIEffects()
        self.timeline = []
        self.predicted_value = None
        if runtime._main_generation:
            require(self.clock_state() == row.initial and runtime.memory.read(runtime.image_base + 0x6D8604C, 1) == row.setup_guard, 'PREFIX_CONTINUOUS_INITIAL_STATE')
        else:
            writes = ((0x6D88CD0, row.initial.frequency), (0x6D88CD8, row.initial.guard), (0x6D8604C, row.setup_guard))
            require(all(not runtime.memory._span(runtime.image_base + offset, len(data))[0].data.readonly for offset, data in writes), 'PREFIX_INITIAL_STATE_WRITABLE')
            for offset, data in writes:
                runtime.memory.write(runtime.image_base + offset, data, source='prefix_raw_clock.actual_entry_state')

    def clock_state(self):
        runtime = self._runtime
        return ClockState(runtime.memory.read(runtime.image_base + 0x6D88CD8, 1), runtime.memory.read(runtime.image_base + 0x6D88CD0, 8))

    @contextmanager
    def scope(self, arguments, hosts):
        from .primary_main_prefix_stop import _input_owner
        require(_input_owner(self._runtime) is not None, 'PREFIX_ONLY_ENTRY_REQUIRED')
        require(self.clock_state() == self._rows[0].initial and
                self._runtime.memory.read(self._runtime.image_base + 0x6D8604C, 1) == b'\x01', 'PREFIX_ENTRY_STATE')
        with super().scope(arguments, hosts):
            yield

    def _compute(self, event):
        from .primary_main_prefix_stop import _input_owner
        require(_input_owner(self._runtime) is not None and self.active is None and self._reading and
                self.clock_state() == event.service.before, 'PREFIX_RAW_ACTIVE_OWNER')
        self.active, self.api_index = event.service, 0
        try:
            value = self._runtime._clock_value(api=self.write_to, local=self.local)
            require(self.api_index == len(self.active.rows) and self.clock_state() == self.active.after, 'PREFIX_RAW_COMPLETION')
            self.predicted_value = value
            self.timeline.append(('MAIN', 1160, self.active.enter_seq, self.active.leave_seq, self.active.before, self.active.after))
            return value
        finally:
            self.active = None

    def write_to(self, name, destination):
        from .primary_main_prefix_stop import _input_owner
        require(_input_owner(self._runtime) is not None and self.active is not None and
                self.api_index < len(self.active.rows), 'PREFIX_RAW_API_ACTIVE')
        row = self.active.rows[self.api_index]
        require(row.name == name, 'PREFIX_RAW_API_ORDER')
        value = self.effects.write(self._runtime.memory, row, destination)
        self.api_index += 1
        return value

    def local(self, name):
        require(self.active is not None and self.api_index < len(self.active.rows), 'PREFIX_RAW_LOCAL_ACTIVE')
        row = self.active.rows[self.api_index]
        require(row.name == name and row.api in ('QPC', 'FILETIME') and row.output == self.active.entry_rsp - 0x18, 'PREFIX_RAW_LOCAL_ABI')
        runtime, address = self._runtime, row.output
        require(not any(address < region.address + len(region.data) and region.address < address + 8 for region in runtime.memory._region_snapshot()), 'PREFIX_RAW_LOCAL_OVERLAP')
        runtime.memory.map(address, bytearray(8), name='prefix raw clock private output', initialized=False)
        try:
            self.write_to(name, address)
            return runtime.memory.load(address, 8)
        finally:
            runtime.memory.forget(address, 8, source='prefix_raw_clock.private_output_lifetime_end')
            runtime.memory.unmap(address)

    @contextmanager
    def host_service(self, vm):
        from .primary_main_prefix_stop import _input_owner
        runtime = self._runtime
        source = runtime._host129_api_binding.source
        require(_input_owner(runtime) is not None and not self.closed and self._event_index == 1 and
                self.active is None and source.host_vm is vm and source.service is not None and
                source.main_vm is self._vm and self.timeline and self.timeline[0][0] == 'MAIN', 'PREFIX_HOST_SERVICE_ORDER')
        before = self.clock_state()
        require(before == self.timeline[-1][-1], 'PREFIX_SHARED_CLOCK_STATE_CONTINUITY')
        site, index = source.sites[-1], source.service
        require(site in (2353, 5821), 'PREFIX_HOST_SITE')
        yield
        require(_input_owner(runtime) is not None and source.host_vm is vm and source.service == index, 'PREFIX_HOST_SERVICE_OWNER')
        self.timeline.append(('HOST', site, index, before, self.clock_state()))

    def read(self, vm, rva, cells, argument_types):
        runtime = self._runtime
        try:
            owner = runtime._active_main
            stack = runtime._program_calls
            if (self.closed or self._row is None or self._reading or vm is not self._vm or
                    vm.runtime is not runtime or get_ident() != self._thread or owner is None or
                    owner['vm'] is not vm or owner['thread'] != self._thread or
                    owner['generation'] != self._generation or runtime._main_generation != self._generation or
                    runtime._execute_thread != self._thread or len(stack) != 1 or stack[0] is not self._call or
                    stack[0]['hosts'] is not None or stack[0]['arguments'] != self._row.source_identity.main_arguments or
                    self._event_index >= len(self._row.events) or rva != 0x3592430 or
                    cells != () or argument_types not in (None, ()) or
                    sha256(vm.program.raw).hexdigest() != _MAIN_SHA256):
                _fail()
            self._reading = True
            event = self._row.events[self._event_index]
            word = event.site_word
            pc, signature, cell, callee, arguments, words = _SITES[word]
            if (vm.pc != pc or tuple(vm.program.words[word:pc]) != words or not vm.host_calls or
                    vm.host_calls[-1] != (word, runtime.image_base + callee, arguments, signature) or
                    vm.cells.value(cell) != runtime.image_base + callee or
                    vm.program.type(125).parameters != (0, 98, 2, 8, 98) or
                    vm.program.type(135).parameters != (0, 7, 0) or
                    vm.program.type(7).raw != 7 or vm.program.size(7) != 8):
                _fail()
            self._event_index += 1
            return self._compute(event)
        except BaseException:
            self.close()
            raise
        finally:
            self._reading = False

    def complete_prefix9563(self, vm, witness):
        require(self.active is None and self._event_index == 1 and self.timeline and self.timeline[0][0:2] == ('MAIN', 1160) and
                self.api_index == len(self._row.events[0].service.rows) and self.clock_state() == self.timeline[-1][-1], 'PREFIX_RAW_FINALIZATION')
        super().complete_prefix9563(vm, witness)

    def close(self):
        self.active = None
        super().close()


def bind_clock_inputs(rows, runtime, *, _prefix_owner=None):
    if type(rows) is tuple and len(rows) == 1 and type(rows[0]) is PrefixMain1160RawInputs:
        return _MainPrefixRawClockBinding(rows, runtime, _prefix_owner=_prefix_owner)
    return _MainClockReturnBinding(rows, runtime, _prefix_owner=_prefix_owner)


def host_clock_scope(runtime, vm):
    binding = runtime._main_clock_binding
    return binding.host_service(vm) if type(binding) is _MainPrefixRawClockBinding else nullcontext()
