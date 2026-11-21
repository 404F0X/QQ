from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from threading import get_ident

from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_memory import UnknownMemory


SCHEMA = 'main96-host129-raw-inputs-v1'
SCHEMA_SHA256 = 'c38a62d9327fb8caf68147365380ab59db0de9c97d3bb283e740d35d8237d5ad'
PE_SHA256 = '63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'
SITES = (2353, 5821, 62638)
DOMAINS = (SITES, (5821, 62638))
DESTINATIONS = {2353: 453, 5821: 936, 62638: 8355}
API = {
    'QPF': ('QueryPerformanceFrequency', 0x4910260, 0x359245A, 8),
    'QPC': ('QueryPerformanceCounter', 0x4910258, 0x3592473, 8),
    'FILETIME': ('GetSystemTimeAsFileTime', 0x490FFB8, 0x359249D, 8),
    'BCrypt': ('BCryptGenRandom', 0x4911180, 0x35924F9, 4),
}
ROOT_KEYS = set(('schema sourcePeSha256 moduleBase moduleGeneration processCreationIdentity '
                 'publicCallEpoch mainEpoch readerInvocation thread initialClockState groups complete').split())
IDENTITY_KEYS = tuple(('sourcePeSha256 moduleBase moduleGeneration processCreationIdentity '
                       'publicCallEpoch mainEpoch readerInvocation thread').split())


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


def service_row(row, index, image_base):
    keys(row, 'kind ordinal word consumedPC callId entryRSP enterSeq leaveSeq normalReturn stateBefore stateAfter apiRows compareOnly', 'SERVICE_KEYS')
    kind = 'clock' if index < 2 else 'entropy'
    ordinal = index % 2
    word, pc = ((15, 21), (37, 43), (102, 108), (122, 128))[index]
    require((row['kind'], integer(row['ordinal'], 32), integer(row['word'], 32), integer(row['consumedPC'], 32)) == (kind, ordinal, word, pc), 'SERVICE_ORDER')
    require(row['normalReturn'] is True and integer(row['enterSeq']) < integer(row['leaveSeq']), 'SERVICE_RETURN')
    keys(row['compareOnly'], 'serviceValue', 'COMPARE_KEYS')
    if kind == 'clock':
        pointer(row['compareOnly']['serviceValue'])
    else:
        integer(row['compareOnly']['serviceValue'], 32)
    before, after = state(row['stateBefore']), state(row['stateAfter'])
    require(type(row['apiRows']) is list and 1 <= len(row['apiRows']) <= 2, 'API_COUNT')
    rows = tuple(api_row(item, row, i, image_base) for i, item in enumerate(row['apiRows']))
    require(all(a.leave_seq < b.enter_seq for a, b in zip(rows, rows[1:])), 'API_SEQUENCE')
    if kind == 'entropy':
        require(len(rows) == 1 and rows[0].api == 'BCrypt' and before == after, 'ENTROPY_STATE')
    elif before.guard != b'\0':
        require(tuple(item.api for item in rows) == ('QPC',) and after == before, 'WARM_CLOCK')
    else:
        require(len(rows) == 2 and rows[0].api == 'QPF', 'COLD_CLOCK')
        success = rows[0].status != 0
        require(rows[1].api == ('QPC' if success else 'FILETIME'), 'CLOCK_BRANCH')
        require(rows[0].before == before.frequency, 'QPF_BEFORE')
        require(after.guard == bytes([int(success)]) and after.frequency == rows[0].after, 'CLOCK_AFTER')
    return Service(kind, ordinal, word, pc, label(row['callId']), pointer(row['entryRSP']), before, after, rows, row['enterSeq'], row['leaveSeq'])


@dataclass(frozen=True, repr=False)
class Group:
    site: int
    epoch: str
    arena: int
    services: tuple[Service, ...]
    counter_reads: tuple[int, ...] | None


@dataclass(frozen=True, repr=False)
class RawInputs:
    identity: tuple
    initial_clock: ClockState
    groups: tuple[Group, ...]
    wire_digest: str


def parse_wire(wire, *, expected_identity, source_address_policy):
    require(type(wire) is dict and 'host129RawInputs' in wire, 'MISSING')
    raw = wire['host129RawInputs']
    core = type(expected_identity) is dict and expected_identity.get('callKind') == 'CORE_MAIN_CALL'
    identity_keys = tuple(key for key in IDENTITY_KEYS if key != 'publicCallEpoch') + ('callKind', 'mainEntryRSP') if core else IDENTITY_KEYS
    root_keys = ROOT_KEYS - {'publicCallEpoch'} | {'callKind', 'mainEntryRSP'} if core else ROOT_KEYS
    require(type(raw) is dict and set(raw) == root_keys, 'ROOT_KEYS')
    require(raw['schema'] == SCHEMA and raw['sourcePeSha256'] == PE_SHA256 and raw['complete'] is True, 'ROOT_DOMAIN')
    require(type(expected_identity) is dict and set(expected_identity) == set(identity_keys), 'EXPECTED_IDENTITY')
    require(all(type(raw[key]) is type(expected_identity[key]) and raw[key] == expected_identity[key] for key in identity_keys), 'SOURCE_BINDING')
    if core:
        require(raw['callKind'] == 'CORE_MAIN_CALL' and pointer(raw['mainEntryRSP']) == pointer(wire.get('entryRSP')), 'MAIN_ENTRY_BINDING')
    image_base = pointer(raw['moduleBase'])
    for name in (('moduleGeneration', 'mainEpoch') if core else ('moduleGeneration', 'publicCallEpoch', 'mainEpoch')):
        label(raw[name])
    require(type(raw['processCreationIdentity']) is str and re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', raw['processCreationIdentity']) is not None, 'PROCESS_IDENTITY')
    integer(raw['readerInvocation'], minimum=1)
    integer(raw['thread'], minimum=1)
    require(callable(source_address_policy) and source_address_policy(wire) is True, 'SOURCE_ADDRESS_POLICY')
    require(type(raw['groups']) is list and tuple(row.get('siteWord') for row in raw['groups'] if type(row) is dict) in DOMAINS and all(type(row) is dict for row in raw['groups']) and type(wire.get('host129Groups')) is list and len(wire['host129Groups']) == len(raw['groups']), 'GROUP_COUNT')
    groups = []
    previous = -1
    for index, (row, existing) in enumerate(zip(raw['groups'], wire['host129Groups'])):
        keys(row, 'siteWord hostEpoch strictOrdinal address services apiEventCount normalReturn', 'GROUP_KEYS')
        require(integer(row['siteWord'], 32) in SITES and integer(row['strictOrdinal'], 32) == index and row['normalReturn'] is True, 'GROUP_ORDER')
        require(existing['siteWord'] == row['siteWord'], 'GROUP_BINDING')
        address = row['address']
        keys(address, 'wrapperEntryRSP evaluatorBP context cells arena pointers arenaSize', 'ADDRESS_KEYS')
        for name in ('wrapperEntryRSP', 'evaluatorBP', 'context', 'cells', 'arena'):
            pointer(address[name])
        arena = pointer(address['arena'])
        require(type(address['arenaSize']) is int and address['arenaSize'] == 32 and type(address['pointers']) is list and tuple(pointer(item) for item in address['pointers']) == (arena, arena + 9, arena + 18), 'ADDRESS_LAYOUT')
        require(existing['address'] == address, 'ADDRESS_BINDING')
        require(type(row['services']) is list and len(row['services']) in (2, 4), 'SERVICE_COUNT')
        services = tuple(service_row(item, i, image_base) for i, item in enumerate(row['services']))
        require(all(a.after == b.before for a, b in zip(services, services[1:])), 'STATE_CONTINUITY')
        require(integer(row['apiEventCount'], 32) == sum(len(item.rows) for item in services) <= 6, 'API_COUNT')
        for item in services:
            require(previous < item.enter_seq, 'SERVICE_SEQUENCE')
            previous = item.leave_seq
        counters = existing['counterReads']
        require(counters is None or type(counters) is list and len(counters) == 4, 'COUNTER_COUNT')
        if counters is not None:
            counters = tuple(integer(value, 32) for value in counters)
            require(len(services) == 4, 'COUNTER_BRANCH')
        groups.append(Group(row['siteWord'], label(row['hostEpoch']), arena, services, counters))
    require(len({group.epoch for group in groups}) == len(groups) and len({item.call_id for group in groups for item in group.services}) == sum(len(group.services) for group in groups), 'EPOCH_REUSE')
    initial = state(raw['initialClockState'])
    require(initial == groups[0].services[0].before, 'INITIAL_STATE')
    digest = sha256(json.dumps(wire, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    return RawInputs(tuple(raw[key] for key in identity_keys), initial, tuple(groups), digest)


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


class Host129RawAPIRows:
    def __init__(self, inputs, delegate):
        require(type(inputs) is RawInputs and delegate is not None, 'TYPED_INPUTS')
        self.inputs, self.delegate = inputs, delegate
        self.runtime = self.thread = self.owner = self.main_owner = None
        self.main_vm = self.host_vm = self.service = None
        self.group_index = self.service_index = self.api_index = self.counter_index = 0
        self.initial_bound = self.closed = self.completed = False
        self.main_site_failure = None
        self.effects = APIEffects()

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    def bind(self, runtime):
        require(self.runtime is None and not self.closed, 'BIND_ONCE')
        require(runtime.image_base == pointer(self.inputs.identity[1]), 'IMAGE_BASE')
        self.delegate.bind(runtime)
        self.runtime, self.thread = runtime, get_ident()

    def _live(self, runtime):
        from qq_nt_replica.primary_sign_lifecycle import _PublicDirectOwner
        require(not self.closed and runtime is self.runtime and self.thread == get_ident() and runtime.primary_core and not runtime._active_failed, 'RUNTIME_OWNER')
        require(runtime.raw_core_observations is self, 'RAW_SOURCE_OWNER')
        owner = runtime.__dict__.get('_primary_public_direct_owner')
        require(type(owner) is _PublicDirectOwner and owner.runtime is runtime and owner.thread == self.thread and owner.valid(), 'PUBLIC_OWNER')
        if self.owner is None:
            self.owner = owner
        require(owner is self.owner and runtime._execute_thread == self.thread, 'PUBLIC_EPOCH')
        require(all(getattr(runtime, name) is None for name in ('_host129_raw_binding', '_host129_source_clock_binding', '_host129_multicall_binding', '_host129_counter_binding', '_host129_clock_service_binding', '_host129_entropy_service_binding')), 'COMPETING_BINDING')
        require(getattr(runtime, '_consumed_mgf', None) is None, 'REPLAY_FORBIDDEN')

    def enter_main(self, runtime, vm):
        from qq_nt_replica.primary_vm import PrimaryVM
        from qq_nt_replica.primary_main_mix import MAIN_SHA256
        self._live(runtime)
        owner = runtime._active_main
        require(self.main_owner is None and type(vm) is PrimaryVM and type(owner) is dict and owner.get('vm') is vm and owner.get('thread') == self.thread and owner.get('generation') == runtime._main_generation, 'MAIN_OWNER')
        require(vm.runtime is runtime and vm.memory is runtime.memory and sha256(vm.program.raw).hexdigest() == MAIN_SHA256, 'MAIN_SOURCE')
        require(len(runtime._program_calls) == 1 and runtime._program_calls[0]['name'] == 'main' and runtime._program_calls[0]['hosts'] is None and runtime._program_calls[0]['arguments'][0] == 4, 'MAIN_CALL')
        self.main_owner, self.main_vm = owner, vm

    def _record_main_site_failure(self, group):
        if self.main_site_failure is not None:
            return
        snapshot = dict(status='UNAVAILABLE', groupIndex=None, expectedSite=None,
            actualMainPC=None, firstFailedPredicate='UNKNOWN', lastRowClass='INVALID',
            lastRowPC=None, hostTag='OTHER', arity=None, addressMatch=None)
        try:
            index, site, pc = self.group_index, group.site, self.main_vm.pc
            snapshot['groupIndex'] = index if type(index) is int and 0 <= index < len(self.inputs.groups) else None
            snapshot['expectedSite'] = site if type(site) is int and site in SITES else None
            snapshot['actualMainPC'] = pc if type(pc) is int and 0 <= pc < 1 << 32 else None
            snapshot['firstFailedPredicate'] = 'PC' if pc != site + 6 else 'HOST_ROW'
            rows = self.main_vm.host_calls
            row = rows[-1] if type(rows) is list and rows else None
            if (type(row) is tuple and len(row) == 4 and type(row[0]) is int and
                    type(row[1]) is int and type(row[2]) is tuple and type(row[3]) is int):
                snapshot['lastRowPC'] = row[0] if 0 <= row[0] < 1 << 32 else None
                snapshot['hostTag'] = str(row[3]) if row[3] in (17, 129) else 'OTHER'
                snapshot['arity'] = len(row[2]) if len(row[2]) <= 1024 else None
                snapshot['addressMatch'] = row[1] == self.runtime.image_base + 0x2DE577E
                snapshot['lastRowClass'] = next(('LEGAL_' + str(word) for word in SITES
                    if row == (word, self.runtime.image_base + 0x2DE577E, (), 129)), 'OTHER')
            snapshot['status'] = 'RECORDED'
        except BaseException:
            pass
        self.main_site_failure = snapshot

    def _host(self, runtime, vm):
        self._live(runtime)
        require(self.main_owner is runtime._active_main and self.main_owner['vm'] is self.main_vm and self.main_owner['generation'] == runtime._main_generation and self.group_index < len(self.inputs.groups), 'MAIN_GENERATION')
        require(vm.runtime is runtime and vm.memory is runtime.memory and len(runtime._program_calls) == 2 and [row['name'] for row in runtime._program_calls] == ['main', 'host129'] and runtime._program_calls[-1]['arguments'] == () and runtime._program_calls[-1]['hosts'] is None, 'HOST_OWNER')
        from qq_nt_replica.primary_host129_direct import HOST129_SHA256
        require(sha256(vm.program.raw).hexdigest() == HOST129_SHA256 and vm in runtime.vms, 'HOST_SOURCE')
        group = self.inputs.groups[self.group_index]
        try:
            require(self.main_vm.pc == group.site + 6 and self.main_vm.host_calls[-1] == (group.site, runtime.image_base + 0x2DE577E, (), 129), 'MAIN_SITE')
        except BaseException:
            try:
                self._record_main_site_failure(group)
            except BaseException:
                pass
            raise
        destination = DESTINATIONS[group.site]
        require(self.main_vm.program.words[group.site:group.site + 6] == (0x014A3DB9, 129, 0, destination, 454, 0) and self.main_vm.cells.value(454) == runtime.image_base + 0x2DE577E, 'MAIN_SOURCE_ABI')
        require(vm.arena_address == group.arena and vm.arena_size == 32, 'HOST_ADDRESS')
        if self.host_vm is None:
            self.host_vm = vm
        require(self.host_vm is vm, 'HOST_EPOCH')
        return group

    def _clock_state(self):
        memory, base = self.runtime.memory, self.runtime.image_base
        return ClockState(memory.read(base + 0x6D88CD8, 1), memory.read(base + 0x6D88CD0, 8))

    def _initial_clock(self):
        if self.initial_bound:
            return
        runtime = self.runtime
        expected = self.inputs.initial_clock
        slot, guard = runtime.image_base + 0x6D88CD0, runtime.image_base + 0x6D88CD8
        prior = []
        for entry in runtime.memory.writes:
            address, data, source = entry
            if address >= guard + 1:
                continue
            extent = runtime.memory.write_extent(entry) if data is None else len(data)
            require(type(extent) is int and extent >= 0, 'INITIAL_STATE_WRITE_EXTENT_UNKNOWN')
            if extent and slot < address + extent:
                prior.append(entry)
        if prior:
            allowed = ('3592454.frequency_publish', '359245E.frequency_ready', 'QueryPerformanceFrequency.raw_write', 'QueryPerformanceFrequency.raw_api_contract_output')
            require(all(source in allowed for _, _, source in prior), 'INITIAL_STATE_WRITE_SOURCE')
            require(self._clock_state() == expected, 'INITIAL_STATE_ALREADY_WRITTEN')
        else:
            runtime.memory.write(slot, expected.frequency, source='host129.raw_api_initial_frequency')
            runtime.memory.write(guard, expected.guard, source='host129.raw_api_initial_guard')
        self.initial_bound = True

    @contextmanager
    def host129_service(self, runtime, vm, rva, cells, argument_types):
        try:
            group = self._host(runtime, vm)
            require(self.service is None and self.service_index < len(group.services), 'SERVICE_EXHAUSTED')
            service = group.services[self.service_index]
            expected = (0x35924C4,) if service.kind == 'entropy' else (0x3592430, 0x2DE5A2F)
            callee, signature = (23, 1) if service.kind == 'entropy' else (5, 7)
            require(rva in expected and cells == () and argument_types in (None, ()) and vm.pc == service.consumed_pc and vm.host_calls[-1] == (service.word, runtime.image_base + rva, (), signature) and vm.cells.value(callee) == runtime.image_base + rva, 'SERVICE_CONSUMER')
            self._initial_clock()
            require(self._clock_state() == service.before, 'STATE_BEFORE')
            self.service, self.api_index = service, 0
            yield
            self._host(runtime, vm)
            require(self.api_index == len(service.rows) and self._clock_state() == service.after, 'STATE_AFTER')
            self.service_index += 1
            self.service = None
        except BaseException:
            self.close()
            raise

    def _row(self, runtime, name):
        self._host(runtime, self.host_vm)
        require(self.service is not None and self.api_index < len(self.service.rows), 'API_EXHAUSTED')
        row = self.service.rows[self.api_index]
        require(row.name == name, 'API_CONSUMER_ORDER')
        return row

    def write_to(self, runtime, name, destination, *, purpose):
        if self.service is None:
            if self.host_vm is not None or any(row['name'] == 'host129' for row in runtime._program_calls):
                raise InputError('HOST129_RAW_API_TYPED_SERVICE_HOOK_MISSING')
            return self.delegate.write_to(runtime, name, destination, purpose=purpose)
        try:
            row = self._row(runtime, name)
            result = self.effects.write(runtime.memory, row, destination)
            self.api_index += 1
            return result
        except BaseException:
            self.close()
            raise

    def bcrypt_word(self):
        runtime = self.runtime
        try:
            row = self._row(runtime, 'BCryptGenRandom')
            result = self.effects.bcrypt(row)
            self.api_index += 1
            return result
        except BaseException:
            self.close()
            raise

    def temporary(self, runtime, size, fallback):
        if self.service is None:
            return fallback(size)
        require(size == 8 and self.service.kind == 'clock', 'TEMPORARY_WIDTH')
        require(self.api_index < len(self.service.rows), 'API_EXHAUSTED')
        row = self._row(runtime, self.service.rows[self.api_index].name)
        require(row.api in ('QPC', 'FILETIME'), 'TEMPORARY_API')
        return 8, row.output, None

    def read_counter(self, runtime, vm, pc, source, destination, width):
        group = self._host(runtime, vm)
        roles = ((225, 41, 42, 0x64284D0), (249, 45, 46, 0x6D86054), (287, 45, 52, 0x6D86054), (362, 41, 63, 0x64284D0))
        require(self.service is None and self.service_index == 4 and group.counter_reads is not None and self.counter_index < 4, 'COUNTER_BRANCH')
        role = roles[self.counter_index]
        require((pc, source, destination) == role[:3] and width == 4 and vm.pc == pc and vm.cells.value(source) == runtime.image_base + role[3], 'COUNTER_CONSUMER')
        result = group.counter_reads[self.counter_index]
        self.counter_index += 1
        return result

    def complete_host(self, runtime, vm):
        try:
            group = self._host(runtime, vm)
            require(vm.halted and self.service is None and self.service_index == len(group.services) and self.counter_index == (0 if group.counter_reads is None else 4), 'HOST_COMPLETE')
            self.group_index += 1
            self.host_vm = None
            self.service_index = self.counter_index = 0
        except BaseException:
            self.close()
            raise

    def complete_main(self, runtime, vm):
        self._live(runtime)
        require(vm is self.main_vm and vm.halted and self.group_index == len(self.inputs.groups) and self.host_vm is None, 'MAIN_COMPLETE')
        self.completed = True

    def close(self):
        self.closed = True
        self.service = self.host_vm = None


def prepare(wire, *, expected_identity, source_address_policy, delegate):
    return Host129RawAPIRows(parse_wire(wire, expected_identity=expected_identity, source_address_policy=source_address_policy), delegate)


def attach(runtime, rows):
    from qq_nt_replica.primary_host129_api_inputs import Host129RawAPIInputs
    require(type(rows) is Host129RawAPIRows and runtime.raw_core_observations is rows and rows.runtime is runtime, 'ATTACH_SOURCE')
    inputs = Host129RawAPIInputs(rows)
    runtime.attach_host129_raw_api_inputs(inputs)
    return inputs
