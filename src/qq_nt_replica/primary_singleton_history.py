from dataclasses import dataclass, fields, is_dataclass
from threading import get_ident

from .errors import InputError
from .primary_consumed_mgf import (
    SOURCE_SHA256, SourceIdentity, ConsumptionEncoder, PrivateCoreReplayCapsule,
    Main96DigestReference, _clear_chunks, _validate_ranges,
)
from .primary_singleton_inputs import (
    PendingLineageIdentity, SingletonProducerInputs, ApiEffect, AllocationEffect, FreeEffect,
    CompletedWarmClockDomain,
)


def _fail():
    raise InputError('HISTORY_CLOSURE_UNKNOWN')


def _unsigned(value, bits=64):
    return type(value) is int and 0 <= value < 1 << bits


def _text_bytes(value):
    return sum(1 if ord(char) < 128 else 2 if ord(char) < 2048 else 3 if ord(char) < 65536 else 4 for char in value)


def _wire_size(value):
    if value is None:
        return 1
    if type(value) is bool:
        return 1
    if type(value) is int:
        if not -(1 << 63) <= value < 1 << 64:
            _fail()
        return 8
    if type(value) is str:
        return 4 + _text_bytes(value)
    if type(value) is bytes:
        return 4 + len(value)
    if type(value) is tuple:
        return 4 + sum(_wire_size(item) for item in value)
    if is_dataclass(value):
        return sum(_wire_size(getattr(value, field.name)) for field in fields(value)
                   if (field.name not in ('host129_invocation_count', 'host129_invocations', 'host129_profile') or
                       getattr(value, field.name) is not None) and field.name != 'wire_version')
    if type(value) is CompletedWarmClockDomain:
        return sum(_wire_size(item) for item in value.__dict__.values())
    from .primary_policy3_inputs import Policy3RootInputs
    if type(value) is Policy3RootInputs:
        return sum(_wire_size(item) for item in value.__dict__.values())
    _fail()


@dataclass(frozen=True, repr=False)
class HistoryRange:
    address: int
    length: int
    alias_group: int
    alias_offset: int

    def __post_init__(self):
        if (not all(_unsigned(value) for value in
                    (self.address, self.length, self.alias_group, self.alias_offset)) or
                self.address + self.length > 1 << 64 or self.alias_offset + self.length > 262144):
            _fail()


@dataclass(frozen=True, repr=False)
class RootDescriptor:
    native_call_id: str
    root_ordinal: int
    main_arguments: tuple
    ranges: tuple
    reader_capacity: int
    image_base: int
    lineage: PendingLineageIdentity
    entry_m: int
    counter_reads: object = None
    clock_returns: object = None
    entropy_returns: object = None
    policy3_inputs: object = None
    host129_invocations: object = None
    host129_profile: str | None = None

    def __post_init__(self):
        from .primary_host129_inputs import (
            Host129CounterReads, Host129ClockServiceReturns, Host129EntropyServiceReturns,
        )
        SourceIdentity(SOURCE_SHA256, self.native_call_id, 1, self.main_arguments, self.image_base)
        if self.host129_profile not in (None, 'normal-main-three-call-native-history'):
            _fail()
        if self.host129_invocations is not None:
            from .primary_host129_inputs import Host129InvocationInputs
            if (type(self) is not RootDescriptor or type(self.host129_invocations) is not tuple or
                    not 1 <= len(self.host129_invocations) <= (3 if self.host129_profile else 2) or self.main_arguments[9] == 3 or
                    any(type(row) is not Host129InvocationInputs or row.group_ordinal != index
                        for index, row in enumerate(self.host129_invocations)) or
                    any(value is not None for value in (self.counter_reads, self.clock_returns, self.entropy_returns))):
                _fail()
        if self.host129_profile and self.host129_invocations is not None and (
                any(row.main_caller_word not in (2353, 5821, 62638) for row in self.host129_invocations) or
                len({row.main_caller_word for row in self.host129_invocations}) != len(self.host129_invocations)):
            _fail()
        if (not _unsigned(self.root_ordinal, 32) or self.root_ordinal >= 8 or
                type(self.lineage) is not PendingLineageIdentity or
                not _unsigned(self.entry_m) or not self.entry_m or
                self.main_arguments[8] != self.entry_m + 0x74 or
                self.main_arguments[7] != self.entry_m + 0x78 or
                not _unsigned(self.reader_capacity, 32) or type(self.ranges) is not tuple or
                len(self.ranges) != 6 or any(type(row) is not HistoryRange for row in self.ranges)):
            _fail()
        from .primary_policy3_inputs import Policy3RootInputs
        if self.main_arguments[9] == 3:
            from .primary_policy3_inputs import Policy3ThreadExitRegistration
            if type(self) in (PendingPolicy3RootDescriptor, RootEntry):
                if self.root_ordinal != 0 or any(value is not None for value in
                        (self.policy3_inputs, self.counter_reads, self.clock_returns, self.entropy_returns)):
                    _fail()
            elif (self.root_ordinal != 0 or type(self.policy3_inputs) is not Policy3RootInputs or
                    type(self.policy3_inputs.thread_exit_registration) is not Policy3ThreadExitRegistration or
                    self.policy3_inputs.lineage != self.lineage or
                    self.policy3_inputs.native_call_id != self.native_call_id or
                    self.policy3_inputs.root_ordinal != self.root_ordinal or
                    any(value is not None for value in (self.counter_reads, self.clock_returns, self.entropy_returns))):
                _fail()
        elif self.policy3_inputs is not None or type(self) is PendingPolicy3RootDescriptor:
            _fail()
        if type(self) is RootEntry and any(value is not None for value in
                (self.policy3_inputs, self.counter_reads, self.clock_returns, self.entropy_returns)):
            _fail()
        for row, (pointer, length) in zip(self.ranges, tuple(
                (self.main_arguments[i], self.main_arguments[j]) for i, j in ((1, 2), (3, 4), (5, 6), (10, 11))) +
                ((self.main_arguments[7], 128), (self.main_arguments[8], 4))):
            if row.address != pointer or row.length != length:
                _fail()
        for value, kind in ((self.counter_reads, Host129CounterReads),
                            (self.clock_returns, Host129ClockServiceReturns),
                            (self.entropy_returns, Host129EntropyServiceReturns)):
            if value is not None and type(value) is not kind:
                _fail()
        for i, left in enumerate(self.ranges):
            for right in self.ranges[i + 1:]:
                if left.length and right.length and left.address < right.address + right.length and right.address < left.address + left.length:
                    if (left.alias_group != right.alias_group or
                            left.address - left.alias_offset != right.address - right.alias_offset):
                        _fail()


@dataclass(frozen=True, repr=False)
class PendingPolicy3RootDescriptor(RootDescriptor):
    pass


@dataclass(frozen=True, repr=False)
class RootEntry(RootDescriptor):
    pass


@dataclass(frozen=True, repr=False)
class RootCaptureIdentity:
    generation: int
    native_root: int
    stream_id: int
    ownership_nonce: str

    def __post_init__(self):
        if (any(type(value) is not int or not 0 < value < 1 << 32 for value in
                (self.generation, self.native_root, self.stream_id)) or self.native_root > 8 or
                type(self.ownership_nonce) is not str or len(self.ownership_nonce) != 32 or
                any(char not in '0123456789abcdef' for char in self.ownership_nonce) or
                self.ownership_nonce[:24] != ''.join(format(value, '08x') for value in
                    (self.generation, self.stream_id, self.native_root)) or int(self.ownership_nonce[24:], 16) == 0):
            _fail()


@dataclass(frozen=True, repr=False)
class CapturedFrameSource:
    frame: object
    invocation: int
    parent: int
    asset_id: int
    program_sha256: str
    reader_entry: int
    context: int
    evaluator_entry: int
    backend_bp: int
    native_root: int
    native_thread: int

    def __post_init__(self):
        from .primary_sign import PrimaryFrame, load_program, arena_reservation
        import hashlib
        if (type(self.frame) is not PrimaryFrame or
                any(not _unsigned(value) for value in (self.reader_entry, self.context, self.evaluator_entry,
                    self.backend_bp, self.native_root, self.native_thread)) or
                any(not _unsigned(value, 32) for value in (self.invocation, self.parent, self.asset_id)) or
                not self.invocation or self.parent >= self.invocation or self.asset_id > 65535 or
                not 1 <= self.native_root <= 8 or not self.native_thread or
                self.context != self.reader_entry - 0x170 or self.context != self.backend_bp + 0x2D0 or
                not 0x118 < self.evaluator_entry < self.reader_entry or
                any(not _unsigned(value) or not value for value in (self.frame.cells, self.frame.arena, self.frame.arena_size)) or
                self.frame.cells + 24 * (load_program(self.frame.program).cell_count + 1) > 1 << 64 or
                self.frame.arena + self.frame.arena_size > 1 << 64 or
                self.frame.program in ('main', 'host129') and self.asset_id != {'main': 1, 'host129': 8}[self.frame.program] or
                self.frame.arena + self.frame.arena_size > self.evaluator_entry or
                self.program_sha256 != hashlib.sha256(load_program(self.frame.program).raw).hexdigest() or
                self.frame.arena_size < arena_reservation(load_program(self.frame.program))):
            _fail()


class QualifiedTypedReadCoverage:
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        _fail()

    def _verify(self, receiver, terminal):
        _fail()


@dataclass(frozen=True, repr=False, slots=True)
class MulticallCoverageProof:
    wire: bytes
    header: tuple
    hashes: tuple
    module: tuple
    stages: tuple
    counts: tuple
    serials: tuple
    lease: int
    invocation_count: int
    service_return_count: int
    clock_return_count: int
    entropy_return_count: int
    groups: tuple

    @classmethod
    def from_wire(cls, data):
        from struct import Struct
        if type(data) is not bytes or len(data) not in (472, 520):
            _fail()
        capacity = 3 if len(data) == 520 else 2
        header = Struct('<3I2Q11I').unpack_from(data)
        hashes = tuple(data[72 + 32 * i:104 + 32 * i] for i in range(4))
        module = Struct('<2Q').unpack_from(data, 200)
        stages = tuple(Struct('<BBHII8s').unpack_from(data, 216 + 20 * i) for i in range(5))
        counts = Struct('<5I').unpack_from(data, 316)
        serials = Struct('<4I').unpack_from(data, 336)
        lease = Struct('<Q').unpack_from(data, 352)[0]
        n, services, clocks, entropy = Struct('<4I').unpack_from(data, 360)
        groups = tuple(Struct('<8I2Q').unpack_from(data, 376 + 48 * i) for i in range(capacity))
        if (header[0] != (4 if capacity == 3 else 3) or not 0 <= n <= capacity or header[11] not in tuple(4 * i for i in range(capacity + 1)) or counts != (header[11],) * 5 or
                clocks != 2 * n or entropy not in tuple(2 * i for i in range(n + 1)) or
                services != clocks + entropy or any(header[12:]) or not lease or
                not 0 < serials[0] < serials[1] < serials[2] < serials[3]):
            _fail()
        expected = ((0, 0, 0x35DD0FC, 0x35DD0FC, bytes.fromhex('418D4501')),
                    (1, 1, 0x35DD157, 0x35DD15A, bytes.fromhex('FF5020')),
                    (2, 0, 0x35DD235, 0x35DD235, bytes.fromhex('8B00')),
                    (3, 1, 0x35DD235, 0x35DD237, bytes.fromhex('8B00')),
                    (4, 1, 0x35DD237, 0x35DD23A, bytes.fromhex('418906')))
        for row, (stage, phase, instruction, callout, raw) in zip(stages, expected):
            if (row[0] != stage or row[1] & 1 != phase or row[1] & 0x3E or not row[1] & 0x40 or
                    header[11] and not row[1] & 0x80 or row[2:] != (len(raw), instruction, callout, raw.ljust(8, b'\0'))):
                _fail()
        for index, group in enumerate(groups):
            if index >= n:
                if any(group):
                    _fail()
            elif (group[0] != index or not group[1] or not 0 < group[2] < group[1] or
                    group[4] != group[3] + 6 or group[5] not in (0, 4) or group[6] != 2 or group[7] not in (0, 2) or
                    not group[8] or not group[9] or index and group[1] <= groups[index - 1][1]):
                _fail()
        if capacity == 3 and (any(group[3] not in (2353, 5821, 62638) for group in groups[:n]) or
                len({group[3] for group in groups[:n]}) != n):
            _fail()
        if entropy != sum(group[7] for group in groups[:n]) or header[11] != sum(group[5] for group in groups[:n]):
            _fail()
        return cls(data, header, hashes, module, stages, counts, serials, lease, n, services, clocks, entropy, groups)


class _QualifiedMulticallCoverage:
    __slots__ = ('_receiver', '_terminal', '_proof', '_used')

    def __new__(cls, *args, **kwargs):
        _fail()

    def _verify(self, receiver, terminal):
        if (getattr(receiver, '_multicall_coverage', None) is not self or self._used or
                self._receiver is not receiver or self._terminal is not terminal):
            _fail()
        proof = MulticallCoverageProof.from_wire(self._proof.wire)
        if proof != self._proof:
            _fail()
        self._used = True
        return proof


_SDK_FILE_PINS = {
    '__init__.py': '018e62dbdc3fc6963145cae44f55da9b6d49695fe5416cb13621d368dbff164f',
    '_frida.pyd': 'adb1f3197fe717278a07dd41ca495976a2f8e058b849af726342a5aa9a487222',
    'core.py': 'ef935a023abed0f00cd48d683ed4c349654ed042c190b0ef2c5e4244304d6451',
}
_SDK_BEHAVIORS = ('five-point-order', 'return-gpr', 'synchronous-context',
                  'cached-cross-root-routing', 'follow-before-reader', 'owner-lease-close')


class VerifiedSDKQualification:
    __slots__ = ('_owner', 'evidence_sha256', 'missing', 'behaviors')

    def __new__(cls, *args, **kwargs):
        _fail()


class ActualInstallRecord:
    __slots__ = ('_owner', 'install_epoch', 'module', 'hashes', 'install_done_serial', 'lease')

    def __new__(cls, *args, **kwargs):
        _fail()


class TypedCoverageSessionReceiver:
    def __new__(cls, *args, **kwargs):
        _fail()

    @classmethod
    def _from_owned_session(cls, session, script, *, identity, sdk_pins, agent_source,
                            collector_manifest, site_catalog, qualification_evidence=None):
        from pathlib import Path
        import hashlib
        import json
        sdk = Path('C:/Users/Color_Fox/AppData/Roaming/Python/Python314/site-packages/frida')
        if (type(session).__module__ != 'frida.core' or type(session).__name__ != 'Session' or
                type(script).__module__ != 'frida.core' or type(script).__name__ != 'Script' or
                sdk_pins != _SDK_FILE_PINS or type(agent_source) is not str or
                type(identity) is not dict or set(identity) != {'pid', 'creation_filetime', 'exe_path',
                    'module_path', 'module_base', 'module_size', 'wrapper_sha256', 'session_epoch'} or
                any(not _unsigned(identity[name]) or not identity[name] for name in
                    ('pid', 'creation_filetime', 'module_base', 'module_size', 'session_epoch')) or
                any(type(identity[name]) is not str or not identity[name] for name in ('exe_path', 'module_path'))):
            _fail()
        for name, digest in _SDK_FILE_PINS.items():
            if hashlib.sha256((sdk / name).read_bytes()).hexdigest() != digest:
                _fail()
        if hashlib.sha256(Path(identity['module_path']).read_bytes()).hexdigest() != identity['wrapper_sha256']:
            _fail()
        path = Path(collector_manifest).resolve()
        raw_manifest = path.read_bytes()
        manifest = json.loads(raw_manifest)
        files = manifest.get('files')
        if type(files) is not dict or not files:
            _fail()
        for name, digest in files.items():
            target = (path.parent / name).resolve()
            if (not target.is_relative_to(path.parent) or type(digest) is not str or
                    hashlib.sha256(target.read_bytes()).hexdigest() != digest):
                _fail()
        agent_files = manifest.get('agent_files')
        agent_file = manifest.get('agent_file')
        if agent_file is not None:
            if agent_file not in files or (path.parent / agent_file).read_text(encoding='utf-8-sig') != agent_source:
                _fail()
        elif (type(agent_files) is not list or not agent_files or any(name not in files for name in agent_files) or
                '\n'.join((path.parent / name).read_text(encoding='utf-8-sig') for name in agent_files) != agent_source):
            _fail()
        catalog = Path(site_catalog).resolve()
        if not catalog.is_relative_to(path.parent) or catalog.relative_to(path.parent).as_posix() not in files:
            _fail()
        result = object.__new__(cls)
        result.session, result.script = session, script
        result.identity = dict(identity)
        result.hashes = (bytes.fromhex(identity['wrapper_sha256']), hashlib.sha256(raw_manifest).digest(),
                         hashlib.sha256(catalog.read_bytes()).digest())
        result.agent_sha256 = hashlib.sha256(agent_source.encode('utf-8')).hexdigest()
        result._source_files = {str((path.parent / name).resolve()): digest for name, digest in files.items()}
        result.install = None
        result.closed = False
        result._receivers = {}
        result._history_owner = None
        result._inside_message = False
        result._callback = None
        result.qualification = result._verify_sdk_evidence(qualification_evidence)
        session.on('detached', lambda *args: result.close())
        script.on('destroyed', lambda *args: result.close())
        return result

    def _active(self):
        if self.closed or self.session.is_detached or self.script.is_destroyed:
            self.close()
            _fail()

    def _bind_message_handler(self, handler):
        from pathlib import Path
        import hashlib
        filename = str(Path(handler.__code__.co_filename).resolve())
        if (self._callback is not None or filename not in self._source_files or
                hashlib.sha256(Path(filename).read_bytes()).hexdigest() != self._source_files[filename]):
            _fail()
        self._active()
        def on_message(message, data):
            self._active()
            if type(message) is not dict or message.get('type') == 'error' or self._inside_message:
                self.close()
                _fail()
            self._inside_message = True
            try:
                return handler(message, data)
            except BaseException:
                self.close()
                raise
            finally:
                self._inside_message = False
        self._callback = on_message
        self.script.on('message', on_message)
        return on_message

    def _register_install(self, actual_rpc_result):
        self._active()
        row = actual_rpc_result
        keys = {'schema', 'session_epoch', 'install_epoch', 'module_base', 'module_size',
                'wrapper_sha256', 'collector_manifest_sha256', 'site_catalog_sha256',
                'install_done_serial', 'guards', 'placements', 'codeowner_lease_id'}
        if (self.install is not None or type(row) is not dict or set(row) != keys or row['schema'] != 1 or
                row['session_epoch'] != self.identity['session_epoch'] or
                (row['module_base'], row['module_size']) != (self.identity['module_base'], self.identity['module_size']) or
                (row['wrapper_sha256'], row['collector_manifest_sha256'], row['site_catalog_sha256']) !=
                    tuple(digest.hex() for digest in self.hashes) or
                any(not _unsigned(row[name]) or not row[name] for name in
                    ('install_epoch', 'install_done_serial', 'codeowner_lease_id')) or
                type(row['guards']) is not list or len(row['guards']) != 5 or
                type(row['placements']) is not list or len(row['placements']) != 5):
            self.close()
            _fail()
        for index, (instruction, callout, phase, raw) in enumerate((
                (0x35DD0FC, 0x35DD0FC, 'pre', '418d4501'),
                (0x35DD157, 0x35DD15A, 'post', 'ff5020'),
                (0x35DD235, 0x35DD235, 'pre', '8b00'),
                (0x35DD235, 0x35DD237, 'post', '8b00'),
                (0x35DD237, 0x35DD23A, 'post', '418906'))):
            guard = row['guards'][index]
            placement = row['placements'][index]
            if (type(guard) is not dict or type(placement) is not dict or
                    any(guard.get(name) != value for name, value in
                        (('id', index), ('instruction', instruction), ('phase', phase), ('size', len(raw) // 2), ('bytes', raw))) or
                    guard.get('observed') is not True or
                    any(placement.get(name) != value for name, value in
                        (('id', index), ('instruction', instruction), ('callout', callout), ('phase', phase),
                         ('size', len(raw) // 2), ('bytes', raw))) or placement.get('observed') is not False):
                self.close()
                _fail()
        result = object.__new__(ActualInstallRecord)
        result._owner = self
        result.install_epoch = row['install_epoch']
        result.module = (row['module_base'], row['module_size'])
        result.hashes = self.hashes
        result.install_done_serial = row['install_done_serial']
        result.lease = row['codeowner_lease_id']
        self.install = result
        return result

    def feed_capture(self, receiver, sequence, operation, *payload):
        self._active()
        if (not self._inside_message or self.install is None or type(receiver) is not RootReceiver or
                not receiver.owner.multicall or receiver.descriptor.image_base != self.identity['module_base'] or
                self._history_owner is not None and receiver.owner is not self._history_owner or
                id(receiver) not in self._receivers and len(self._receivers) >= 8):
            self.close()
            _fail()
        self._receivers[id(receiver)] = receiver
        self._history_owner = receiver.owner
        return receiver.receive_capture(sequence, operation, *payload)

    def _mint_for(self, receiver, terminal):
        return verify_and_mint_multicall_coverage(self, self.install, receiver._multicall_proof,
                                                receiver, terminal, self.qualification)

    def _verify_sdk_evidence(self, evidence_path):
        from pathlib import Path
        import hashlib
        import json
        missing = list(_SDK_BEHAVIORS)
        digest = None
        if evidence_path is not None:
            path = Path(evidence_path)
            raw = path.read_bytes()
            report = json.loads(raw)
            if (report.get('schema') != 1 or report.get('contract') != 'R1317-own-SDK-multicall-coverage-qualification' or
                    report.get('sdk_version') != '17.9.3' or report.get('sdk_file_pins') != _SDK_FILE_PINS or
                    report.get('runtime') != 'qjs' or report.get('os_abi') != 'windows-x64' or
                    report.get('agent_sha256') != self.agent_sha256 or
                    report.get('collector_manifest_sha256') != self.hashes[1].hex() or
                    report.get('site_catalog_sha256') != self.hashes[2].hex()):
                _fail()
            bindings = report.get('execution_bindings')
            if (type(bindings) is not dict or bindings.get('exit_code') != 0 or
                    type(bindings.get('command')) is not str or not bindings['command'] or
                    type(bindings.get('files')) is not dict or not bindings['files']):
                _fail()
            for name, pin in bindings['files'].items():
                target = (path.parent / name).resolve()
                if not target.is_relative_to(path.parent.resolve()) or hashlib.sha256(target.read_bytes()).hexdigest() != pin:
                    _fail()
            observations = report.get('observations')
            if type(observations) is not dict:
                _fail()
            stages = observations.get('five-point-order')
            if (type(stages) is list and len(stages) == 5 and
                    [row.get('stage') for row in stages] == list(range(5)) and
                    [row.get('phase') for row in stages] == ['pre', 'post', 'pre', 'post', 'post'] and
                    all(type(row.get('serial')) is int and row['serial'] > 0 for row in stages) and
                    all(left['serial'] < right['serial'] for left, right in zip(stages, stages[1:]))):
                missing.remove('five-point-order')
            gpr = observations.get('return-gpr')
            if (type(gpr) is dict and type(gpr.get('before')) is int and
                    gpr['before'] == 0xFEDCBA9876543210 and gpr.get('after') == gpr['before']):
                missing.remove('return-gpr')
            context = observations.get('synchronous-context')
            if (type(context) is dict and all(type(context.get(key)) is int for key in ('enter', 'read', 'return')) and
                    0 < context['enter'] < context['read'] < context['return'] and
                    type(context.get('before')) is str and len(context['before']) == 32 and
                    context.get('after') == context['before']):
                missing.remove('synchronous-context')
            routes = observations.get('cached-cross-root-routing')
            if (type(routes) is list and len(routes) == 2 and
                    [row.get('root') for row in routes] == [1, 2] and
                    type(routes[0].get('block')) is int and routes[0]['block'] > 0 and
                    routes[1].get('block') == routes[0]['block'] and
                    all(row.get('delivered_root') == row['root'] for row in routes) and
                    all(type(row.get('serial')) is int for row in routes) and
                    0 < routes[0]['serial'] < routes[1]['serial']):
                missing.remove('cached-cross-root-routing')
            follow = observations.get('follow-before-reader')
            if (type(follow) is dict and type(follow.get('follow')) is int and follow['follow'] > 0 and
                    type(follow.get('readers')) is list and len(follow['readers']) == 2 and
                    all(type(serial) is int and serial > follow['follow'] for serial in follow['readers'])):
                missing.remove('follow-before-reader')
            close = observations.get('owner-lease-close')
            if (type(close) is dict and all(type(close.get(key)) is int for key in
                    ('retain', 'last_access', 'release', 'drain', 'unload', 'owners', 'pending')) and
                    0 < close['retain'] < close['last_access'] < close['release'] < close['drain'] < close['unload'] and
                    close['owners'] == close['pending'] == 0):
                missing.remove('owner-lease-close')
            digest = hashlib.sha256(raw).hexdigest()
        result = object.__new__(VerifiedSDKQualification)
        result._owner = self
        result.evidence_sha256 = digest
        result.missing = tuple(missing)
        result.behaviors = tuple(name for name in _SDK_BEHAVIORS if name not in missing)
        return result

    def close(self):
        self.closed = True
        self._inside_message = False
        for receiver in tuple(self._receivers.values()):
            receiver.close()
        self._receivers.clear()


def verify_and_mint_multicall_coverage(bound_live_session, actual_install_record, parsed_schema3_proof,
                                     receiver, NHB4_terminal, verified_sdk_qualification):
    session = bound_live_session
    if type(session) is not TypedCoverageSessionReceiver:
        _fail()
    session._active()
    install, proof, qualification = actual_install_record, parsed_schema3_proof, verified_sdk_qualification
    if (not session._inside_message or type(install) is not ActualInstallRecord or install is not session.install or
            install._owner is not session or type(qualification) is not VerifiedSDKQualification or
            qualification is not session.qualification or qualification._owner is not session or qualification.missing or
            type(proof) is not MulticallCoverageProof or type(receiver) is not RootReceiver or
            session._receivers.get(id(receiver)) is not receiver or not receiver.owner.multicall or
            receiver.closed or receiver._multicall_coverage is not None or
            proof.header[0] != (4 if receiver.owner.normal_three else 3) or
            NHB4_terminal.wire_version != (5 if receiver.owner.normal_three else 4) or
            receiver._multicall_proof is not proof or receiver._capture_barrier is not NHB4_terminal or
            MulticallCoverageProof.from_wire(proof.wire) != proof or
            proof.header[1] != install.install_epoch or proof.module != install.module or
            proof.hashes != install.hashes + (bytes.fromhex(qualification.evidence_sha256),) or
            proof.serials[0] != install.install_done_serial or proof.lease != install.lease or
            proof.header[10] + 2 != NHB4_terminal.last_sequence or
            proof.header[11] != NHB4_terminal.typed_host129_read_count or
            proof.invocation_count != NHB4_terminal.host129_invocation_count):
        _fail()
    result = object.__new__(_QualifiedMulticallCoverage)
    result._receiver, result._terminal, result._proof, result._used = receiver, NHB4_terminal, proof, False
    receiver._multicall_coverage = result
    return result


@dataclass(frozen=True, repr=False)
class RootSourceSummary:
    reader_count: int
    event_count: int
    flags: int
    output_count: int
    native_root: int
    constructor_records_completed: int

    def __post_init__(self):
        if (any(not _unsigned(getattr(self, field.name), 32) for field in fields(self)) or
                self.flags != 63 or self.output_count > 128 or not 1 <= self.native_root <= 8 or
                self.constructor_records_completed not in (0, 19)):
            _fail()


@dataclass(frozen=True, repr=False)
class RootStreamTerminal:
    identity: RootCaptureIdentity
    last_sequence: int
    event_count: int
    reader_count: int
    frame_count: int
    effect_count: int
    policy_effect_count: int
    environment_count: int
    output_count: int
    native_thread_id: int
    entry_serial: int
    source_summary_sequence: int
    registration_count: int
    constructor_records_completed: int
    producer_count: int = 0
    producer_effect_count: int = 0
    producer_stream: object = None
    typed_host129_read_count: int | None = None
    host129_invocation_count: int | None = None
    wire_version: int = 4

    def __post_init__(self):
        if (type(self.wire_version) is not int or self.wire_version not in (4, 5) or
                type(self.identity) is not RootCaptureIdentity or
                any(not _unsigned(getattr(self, name), 32) for name in
                    ('last_sequence', 'event_count', 'reader_count', 'frame_count', 'effect_count',
                     'policy_effect_count', 'environment_count', 'output_count', 'producer_count', 'producer_effect_count')) or
                any(not _unsigned(getattr(self, name), 32) for name in
                    ('native_thread_id', 'entry_serial', 'source_summary_sequence', 'registration_count', 'constructor_records_completed')) or
                self.typed_host129_read_count is not None and (not _unsigned(self.typed_host129_read_count, 32) or self.typed_host129_read_count not in ((0, 4, 8, 12) if self.wire_version == 5 else (0, 4, 8))) or
                self.host129_invocation_count is not None and (type(self.host129_invocation_count) is not int or
                    not 0 <= self.host129_invocation_count <= (3 if self.wire_version == 5 else 2) or self.typed_host129_read_count not in ((0, 4, 8, 12) if self.wire_version == 5 else (0, 4, 8)) or
                    self.typed_host129_read_count > 4 * self.host129_invocation_count) or
                self.host129_invocation_count is None and (self.typed_host129_read_count in (8, 12) or self.wire_version == 5) or
                not self.last_sequence or self.frame_count > 64 or self.policy_effect_count > 64 or
                self.environment_count > 64 or self.producer_count > 64 or self.producer_effect_count > 64 or
                not self.native_thread_id or self.entry_serial != int(self.identity.ownership_nonce[24:], 16) or
                not 0 < self.source_summary_sequence < self.last_sequence or self.registration_count > 1 or
                self.constructor_records_completed not in (0, 19) or self.output_count > 128 or self.producer_stream is not None):
            _fail()


@dataclass(frozen=True, repr=False, init=False)
class RootSealReceipt:
    identity: RootCaptureIdentity
    native_call_id: str
    root_ordinal: int
    terminal: RootStreamTerminal

    def __init__(self, *args, **kwargs):
        _fail()

    @classmethod
    def _postcommit(cls, receiver):
        owner = receiver.owner
        if (type(receiver) is not RootReceiver or not receiver._finishing_capture or
                owner._awaiting_release is not receiver or
                not receiver.closed or receiver._segment is None or not owner._roots or
                owner._roots[-1] is not receiver._segment or owner._pending is not None or
                owner.closed or type(receiver._stream_terminal) is not RootStreamTerminal or
                type(receiver._segment.descriptor) is not RootDescriptor):
            _fail()
        if receiver._receipt is None:
            row = object.__new__(cls)
            for name, value in (('identity', receiver._capture_identity),
                                ('native_call_id', receiver.descriptor.native_call_id),
                                ('root_ordinal', receiver.descriptor.root_ordinal),
                                ('terminal', receiver._stream_terminal)):
                object.__setattr__(row, name, value)
            receiver._receipt = row
        return receiver._receipt


@dataclass(frozen=True, repr=False)
class RootReleaseConfirmation:
    identity: RootCaptureIdentity
    native_call_id: str
    root_ordinal: int
    last_sequence: int
    root_payload_users: int
    root_payload_bytes: int
    typed_host129_read_count: int | None = None
    host129_invocation_count: int | None = None
    wire_version: int = 4

    def __post_init__(self):
        if (type(self.wire_version) is not int or self.wire_version not in (4, 5) or
                type(self.identity) is not RootCaptureIdentity or type(self.native_call_id) is not str or
                not self.native_call_id or type(self.root_ordinal) is not int or
                self.root_ordinal != self.identity.native_root - 1 or
                not _unsigned(self.last_sequence, 32) or not self.last_sequence or
                self.typed_host129_read_count is not None and (not _unsigned(self.typed_host129_read_count, 32) or self.typed_host129_read_count not in ((0, 4, 8, 12) if self.wire_version == 5 else (0, 4, 8))) or
                self.host129_invocation_count is not None and (type(self.host129_invocation_count) is not int or
                    not 0 <= self.host129_invocation_count <= (3 if self.wire_version == 5 else 2) or self.typed_host129_read_count not in ((0, 4, 8, 12) if self.wire_version == 5 else (0, 4, 8)) or
                    self.typed_host129_read_count > 4 * self.host129_invocation_count) or
                self.host129_invocation_count is None and (self.typed_host129_read_count in (8, 12) or self.wire_version == 5) or
                any(type(value) is not int or value != 0 for value in
                    (self.root_payload_users, self.root_payload_bytes))):
            _fail()


@dataclass(frozen=True, repr=False)
class RootTerminal:
    native_call_id: str
    root_ordinal: int
    normal_return: bool
    output_count: int
    native_output: bytes | Main96DigestReference
    remaining_callbacks: int = 0

    def __post_init__(self):
        if (type(self.native_call_id) is not str or not self.native_call_id or
                not _unsigned(self.root_ordinal, 32) or type(self.normal_return) is not bool or
                not self.normal_return or not _unsigned(self.output_count, 32) or self.output_count > 128 or
                not (type(self.native_output) is bytes and len(self.native_output) == self.output_count or
                     type(self.native_output) is Main96DigestReference and self.native_output.count == self.output_count) or
                type(self.remaining_callbacks) is not int or self.remaining_callbacks != 0):
            _fail()


@dataclass(frozen=True, repr=False)
class HistoryClosure:
    lineage: PendingLineageIdentity
    root_call_ids: tuple
    selected_main_call_id: str
    capture_stopped: bool
    native_continued: bool
    transport_terminal: bool
    foreign_writes: int
    setters: int
    destructors: int
    expiry_calls: int
    reentries: int
    concurrent_calls: int
    missing_roots: int

    def __post_init__(self):
        if (type(self.lineage) is not PendingLineageIdentity or type(self.root_call_ids) is not tuple or
                not 1 <= len(self.root_call_ids) <= 8 or
                any(type(value) is not str or not value for value in self.root_call_ids) or
                len(set(self.root_call_ids)) != len(self.root_call_ids) or
                self.selected_main_call_id != self.root_call_ids[-1] or
                any(type(value) is not bool or not value for value in
                    (self.capture_stopped, self.native_continued, self.transport_terminal)) or
                any(type(value) is not int or value != 0 for value in
                    (self.foreign_writes, self.setters, self.destructors, self.expiry_calls,
                     self.reentries, self.concurrent_calls, self.missing_roots))):
            _fail()


class _Segment:
    pass


@dataclass(frozen=True, repr=False)
class ReaderReference:
    span_id: int
    metadata: object


def _reader_key(metadata):
    return tuple(getattr(metadata, key) for key in
                 ('program', 'source_sha256', 'raw_length', 'mode', 'requests',
                  'event_count', 'observation_bytes', 'initial_state', 'final_state'))


@dataclass(frozen=True, repr=False)
class RootEnvironmentEffect:
    sequence: int
    name: str
    arguments: tuple
    value: object

    def __post_init__(self):
        if (type(self.sequence) is not int or not 1 <= self.sequence <= 64 or
                type(self.name) is not str or not self.name or self.name == 'VM frame' or
                type(self.arguments) is not tuple):
            _fail()
        _wire_size(self.arguments)
        _wire_size(self.value)


class RootReceiver:
    def __init__(self, owner, descriptor):
        self.owner = owner
        self.descriptor = descriptor
        self.identity = SourceIdentity(SOURCE_SHA256, descriptor.native_call_id,
                                       descriptor.root_ordinal + 1, descriptor.main_arguments, descriptor.image_base)
        self.closed = False
        self.encoder = None
        self.masks = tuple(bytearray(row.length) for row in descriptor.ranges[:4])
        self.outputs = tuple(bytearray(row.length) for row in descriptor.ranges[4:])
        self.output_masks = tuple(bytearray(row.length) for row in descriptor.ranges[4:])
        self.offsets = [0] * 6
        self._segment = None
        self.frames = []
        self.environment = []
        self.reader_references = []
        self._new_spans = []
        self._policy3_effects = []
        self._policy3_registration = None
        self._capture_identity = self._stream_terminal = self._receipt = self._release = None
        self._capture_sequence = self._producer_wire_count = self._producer_effect_count = 0
        self._source_summary = self._capture_barrier = None
        self._source_summary_sequence = 0
        self._dispatching_capture = self._finishing_capture = False
        self._frame_sources = {}
        self._source_readers = set()
        self._typed_reads = []
        self._typed_reservation = 0
        self._host129_groups = []
        self._service_returns = []
        self._multicall_coverage = None
        self._multicall_proof = None

    def _active(self):
        try:
            self.owner._active()
            if (self.closed or self.owner._pending is not self or self._segment is not None or
                    self._capture_identity is not None and not self._dispatching_capture):
                _fail()
        except BaseException:
            self.owner.close()
            raise

    def receive_range(self, index, offset, data, mask):
        try:
            self._active()
            if (type(index) is not int or not 0 <= index < 6 or type(offset) is not int or
                    offset != self.offsets[index] or type(data) is not bytes or type(mask) is not bytes or
                    not 0 < len(data) <= 4096 or len(mask) != len(data) or
                    any(value not in (0, 1) for value in mask) or
                    offset + len(data) > self.descriptor.ranges[index].length):
                _fail()
            if index < 4:
                self.encoder.receive_input(index, data)
                target = self.masks[index]
            else:
                target = self.output_masks[index - 4]
                self.outputs[index - 4][offset:offset + len(data)] = data
            target[offset:offset + len(data)] = mask
            self.offsets[index] += len(data)
        except BaseException:
            self.owner.close()
            raise

    def receive_frame(self, frame):
        from .primary_sign import PrimaryFrame, load_program, arena_reservation
        try:
            self._active()
            source = frame if type(frame) is CapturedFrameSource else None
            if self.owner.mode == 'typed-native-history':
                if source is None or self._capture_identity is None:
                    _fail()
                source.__post_init__()
                frame = source.frame
                if (source.invocation != len(self.frames) + 1 or
                        source.native_root != self._capture_identity.native_root or
                        source.native_thread != self.owner.lineage.native_thread_id):
                    _fail()
                if frame.program in ('main', 'host129'):
                    if frame.program in self._frame_sources and not (self.owner.multicall and frame.program == 'host129'):
                        _fail()
                    if frame.program == 'main':
                        if source.parent != 0 or source.invocation != 1 or self.frames:
                            _fail()
                    elif ('main' not in self._frame_sources or
                            source.parent != self._frame_sources['main'].invocation):
                        _fail()
                    if frame.program == 'host129':
                        if self.owner.multicall:
                            if len(self._host129_groups) >= self.owner.host129_capacity:
                                _fail()
                            if self._host129_groups:
                                self._complete_host129_group(self._host129_groups[-1])
                            self.owner._charge_e(26624)
                            self._host129_groups.append({'source': source, 'reads': [], 'services': []})
                        else:
                            self._start_typed_reads()
            elif source is not None:
                _fail()
            if (type(frame) is not PrimaryFrame or len(self.frames) >= 64 or
                    not self.frames and frame.program != 'main' or
                    any(not _unsigned(value) for value in (frame.cells, frame.arena, frame.arena_size)) or
                    not frame.cells or not frame.arena or frame.arena_size < arena_reservation(load_program(frame.program))):
                _fail()
            self.owner._charge_e(2 * _wire_size(frame))
            self.frames.append(frame)
            if source is not None and frame.program in ('main', 'host129'):
                self._frame_sources[frame.program] = source
        except BaseException:
            self.owner.close()
            raise

    def receive_environment(self, event):
        try:
            self._active()
            if type(event) is not RootEnvironmentEffect or event.sequence != len(self.environment) + 1:
                _fail()
            self.owner._charge_e(2 * _wire_size(event))
            self.environment.append(event)
        except BaseException:
            self.owner.close()
            raise

    def _match_source_reader(self, metadata):
        from .primary_sign import load_program
        if self.owner.mode != 'typed-native-history' or metadata.program not in ('main', 'host129'):
            return
        source = self._frame_sources.get(metadata.program)
        if (source is None or (metadata.invocation, metadata.parent, metadata.source_sha256, metadata.context, metadata.raw_base, metadata.raw_length) !=
                (source.invocation, source.parent, source.program_sha256, source.context,
                 self.descriptor.image_base + {'main': 0x4346B30, 'host129': 0x43463D4}[metadata.program],
                 len(load_program(metadata.program).raw))):
            _fail()

    def begin_reader(self, metadata, reuse_span_id=None):
        try:
            self._active()
            self._match_source_reader(metadata)
            return self.encoder.begin_reader(metadata, reuse_span_id=reuse_span_id)
        except BaseException:
            self.owner.close()
            raise

    def _start_typed_reads(self):
        if self.owner.multicall:
            if not self._host129_groups:
                _fail()
            return
        if self._typed_reservation == 512:
            self.owner._charge_e(12800)
            self._typed_reservation = 13312
        elif self._typed_reservation != 13312:
            _fail()

    def receive_typed_host129_read(self, observation):
        from .primary_host129_inputs import Host129TypedReadObservation
        try:
            self._active()
            if (self.owner.mode != 'typed-native-history' or self._capture_identity is None or
                    type(observation) is not Host129TypedReadObservation or
                    len(self._typed_reads) >= (4 * self.owner.host129_capacity if self.owner.multicall else 4)):
                _fail()
            observation.__post_init__()
            self._start_typed_reads()
            source = self._frame_sources.get('host129')
            rows = ((221, 225, 41, 42, 0x64284D0, 6), (245, 249, 45, 46, 0x6D86054, 10),
                    (283, 287, 45, 52, 0x6D86054, 10), (358, 362, 41, 63, 0x64284D0, 10))
            reads = self._host129_groups[-1]['reads'] if self.owner.multicall else self._typed_reads
            if len(reads) >= 4:
                _fail()
            if self.owner.multicall:
                services = self._host129_groups[-1]['services']
                if (len(services) != 4 or [row.service_kind for row in services] != [1, 1, 2, 2] or
                        services[2].value != 0 and services[2].value != services[3].value):
                    _fail()
            word, pc, src, dst, rva, block = rows[len(reads)]
            if (source is None or observation.index != len(reads) or
                    (observation.invocation, observation.parent, observation.evaluator_bp,
                     observation.context, observation.cells, observation.native_root, observation.native_thread) !=
                    (source.invocation, source.parent, source.evaluator_entry - 0x118,
                     source.context, source.frame.cells, source.native_root, source.native_thread) or
                    (observation.word, observation.consumed_pc, observation.opcode, observation.width, observation.block) !=
                    (word, pc, 0x06410FC7, 4, block) or
                    (observation.source_pointer, observation.source_cell, observation.destination_cell) !=
                    (self.descriptor.image_base + rva, source.frame.cells + 24 * src, source.frame.cells + 24 * dst)):
                _fail()
            self._typed_reads.append(observation)
            if self.owner.multicall:
                reads.append(observation)
        except BaseException:
            self.owner.close()
            raise

    def _complete_host129_group(self, group):
        services = group['services']
        clocks = [row.value for row in services if row.service_kind == 1]
        entropies = [row.value for row in services if row.service_kind == 2]
        if (len(clocks) != 2 or
                len(entropies) != (2 if clocks[0] == 0 or clocks[0] == clocks[1] else 0) or
                group['source'].invocation not in self._source_readers):
            _fail()
        expected = 4 if entropies and (entropies[0] == 0 or entropies[0] == entropies[1]) else 0
        if len(group['reads']) != expected:
            _fail()

    def receive_host129_service_return(self, observation):
        from .primary_host129_inputs import Host129ServiceReturnObservation
        try:
            self._active()
            if (not self.owner.multicall or type(observation) is not Host129ServiceReturnObservation or
                    not self._host129_groups or observation.group_ordinal != len(self._host129_groups) - 1):
                _fail()
            observation.__post_init__()
            group = self._host129_groups[-1]
            source = group['source']
            services = group['services']
            index = len(services)
            if (group['reads'] or index >= 4 or (observation.service_kind, observation.subordinal) !=
                    ((1, index) if index < 2 else (2, index - 2)) or
                    (observation.invocation, observation.parent, observation.evaluator_bp, observation.context,
                     observation.cells, observation.native_root, observation.native_thread) !=
                    (source.invocation, source.parent, source.evaluator_entry - 0x118, source.context,
                     source.frame.cells, source.native_root, source.native_thread) or
                    observation.actual_callee - self.descriptor.image_base not in
                    ((0x3592430, 0x2DE5A2F) if observation.service_kind == 1 else (0x35924C4,)) or
                    self._service_returns and observation.ffi_sequence <= self._service_returns[-1].ffi_sequence or
                    index >= 2 and services[0].value != 0 and services[0].value != services[1].value):
                _fail()
            group['services'].append(observation)
            self._service_returns.append(observation)
        except BaseException:
            self.owner.close()
            raise

    def _reuse_span(self, metadata, span_id):
        if type(span_id) is not int or span_id not in self.owner._spans:
            _fail()
        key, start, end = self.owner._spans[span_id]
        if key != _reader_key(metadata) or end - start != metadata.observation_bytes:
            _fail()
        return start

    def _commit_reader(self, metadata, row, start, end, span_id):
        from .primary_sign import load_program
        from .primary_consumed_mgf import check_normal_reader
        check_normal_reader(load_program(metadata.program), row)
        self._match_source_reader(metadata)
        if self.owner.mode == 'typed-native-history' and metadata.program in self._frame_sources:
            self._source_readers.add(metadata.invocation if self.owner.multicall and metadata.program == 'host129' else metadata.program)
        self.owner._charge_e(48)
        if span_id is None:
            self.owner._charge_e(192)
            span_id = self.owner._next_span
            self.owner._next_span += 1
            self._new_spans.append((span_id, (_reader_key(metadata), start, end)))
        reference = ReaderReference(span_id, metadata)
        self.reader_references.append(reference)
        return reference

    def feed_reader(self, lease, offset, block):
        self._active()
        return self.encoder.feed_reader(lease, offset, block)

    def finish_reader(self, lease):
        self._active()
        return self.encoder.finish_reader(lease)

    def feed(self, event):
        self._active()
        return self.encoder.feed(event)

    def _finish_segment(self, encoder):
        if encoder is not self.encoder or self.owner._pending is not self:
            _fail()
        row = _Segment()
        row.descriptor = self.descriptor
        row.identity = self.identity
        row.inputs, row.masks = encoder._inputs, self.masks
        row.outputs, row.output_masks = self.outputs, self.output_masks
        row.readers = encoder._readers
        row.compressed_start = encoder._encoded_base
        row.compressed_end = row.compressed_start + encoder.encoded_length
        row.reader_end = encoder._reader_length
        row.events = encoder.event_count
        row.reader_references = tuple(self.reader_references)
        self.reader_references.clear()
        row.frames = tuple(self.frames)
        row.environment = tuple(self.environment)
        self.frames.clear()
        self.environment.clear()
        self._segment = row
        encoder._inputs, encoder._readers = (), []
        encoder._encoded = encoder._reader_slab = encoder._identity = encoder._history = None
        encoder.closed = True
        return row

    def receive_policy3_effect(self, effect):
        from .primary_policy3_inputs import Policy3Effect
        try:
            self._active()
            if (type(self.descriptor) is not PendingPolicy3RootDescriptor or type(effect) is not Policy3Effect or
                    len(self._policy3_effects) >= 64 or effect.sequence != len(self._policy3_effects) + 1):
                _fail()
            self.owner._charge_e(2 * _wire_size(effect))
            self._policy3_effects.append(effect)
        except BaseException:
            self.owner.close()
            raise

    def receive_policy3_registration(self, registration):
        from .primary_policy3_inputs import Policy3ThreadExitRegistration
        try:
            self._active()
            if (type(self.descriptor) is not PendingPolicy3RootDescriptor or
                    type(registration) is not Policy3ThreadExitRegistration or self._policy3_registration is not None or
                    (registration.lineage, registration.native_call_id, registration.root_ordinal) !=
                    (self.descriptor.lineage, self.descriptor.native_call_id, self.descriptor.root_ordinal)):
                _fail()
            self.owner._charge_e(2 * _wire_size(registration))
            self._policy3_registration = registration
        except BaseException:
            self.owner.close()
            raise

    def _freeze_policy3(self, witness):
        from .primary_policy3_inputs import Policy3FreshWitness, Policy3RootInputs
        if type(self.descriptor) is not PendingPolicy3RootDescriptor:
            if witness is not None:
                _fail()
            return
        if (type(witness) is not Policy3FreshWitness or not self._policy3_effects or
                self._policy3_registration is None or witness.lineage != self.descriptor.lineage):
            _fail()
        expected = ((45, 'clock-local'), (45, 'QueryPerformanceCounter'), (45, 'FILETIME'),
                    (45, 'exit-registration'), (45, 'allocate'), (45, 'SystemFunction036'),
                    (132, 'temporary'), (148, 'temporary'), (164, 'temporary'),
                    (529, 'clock-local'), (529, 'QueryPerformanceCounter'), (529, 'allocate'),
                    (852, 'temporary'))
        actual = tuple((row.site.word, 'FILETIME' if row.kind in
                        ('GetSystemTimePreciseAsFileTime', 'GetSystemTimeAsFileTime') else row.kind)
                       for row in self._policy3_effects)
        if actual != expected:
            _fail()
        self.owner._charge_e(2 * _wire_size(witness))
        inputs = Policy3RootInputs(self.descriptor.lineage, self.descriptor.native_call_id,
                                  self.descriptor.root_ordinal, witness, tuple(self._policy3_effects),
                                  thread_exit_registration=self._policy3_registration)
        values = {field.name: getattr(self.descriptor, field.name) for field in fields(RootDescriptor)}
        values['policy3_inputs'] = inputs
        self.descriptor = RootDescriptor(**values)
        self._policy3_effects.clear()
        self._policy3_registration = None

    def finish_root(self, terminal, *, reader_count, acknowledge=None, policy3_witness=None):
        try:
            self._active()
            if self._capture_identity is not None and (not self._finishing_capture or acknowledge is not None):
                _fail()
            if (type(terminal) is not RootTerminal or
                    (terminal.native_call_id, terminal.root_ordinal) !=
                    (self.descriptor.native_call_id, self.descriptor.root_ordinal) or
                    self.offsets != [row.length for row in self.descriptor.ranges]):
                _fail()
            self._freeze_policy3(policy3_witness)
            reference = terminal.native_output
            self.owner._charge_e(64 + 2 * (_wire_size(reference) if type(reference) is Main96DigestReference else len(reference)))
            row = self.encoder.finish_owned(reader_count=reader_count)
            row.terminal = _Segment()
            row.terminal.output_count = terminal.output_count
            row.native_output = reference if type(reference) is Main96DigestReference else bytearray(reference)
            self.owner._check_aliases(row)
            if acknowledge is not None and acknowledge() is not True:
                _fail()
            if self.owner.closed:
                _fail()
            self.owner.encoded_length = row.compressed_end
            self.owner.reader_length = row.reader_end
            self.owner._roots.append(row)
            self.owner._spans.update(self._new_spans)
            self._new_spans.clear()
            self.owner._pending = None
            self.closed = True
            self._typed_reads.clear()
            self._host129_groups.clear()
            self._service_returns.clear()
            self._frame_sources.clear()
            self._source_readers.clear()
            return terminal.output_count
        except BaseException:
            self.owner.close()
            raise

    def close(self):
        self.owner.close()

    def receive_capture(self, sequence, operation, *payload):
        try:
            if (self._capture_identity is None or self._dispatching_capture or
                    self._capture_barrier is not None or
                    self._multicall_proof is not None and operation != 'barrier' or
                    not _unsigned(sequence, 32) or sequence != self._capture_sequence + 1):
                _fail()
            self._dispatching_capture = True
            self._active()
            methods = {'range': self.receive_range, 'frame': self.receive_frame,
                       'environment': self.receive_environment, 'event': self.feed,
                       'reader-begin': self.begin_reader, 'reader-block': self.feed_reader,
                       'reader-finish': self.finish_reader, 'policy3-effect': self.receive_policy3_effect,
                       'policy3-registration': self.receive_policy3_registration,
                       'typed-host129-read': self.receive_typed_host129_read,
                       'host129-service-return': self.receive_host129_service_return}
            if operation == 'coverage-proof':
                if (not self.owner.multicall or len(payload) != 1 or
                        type(payload[0]) is not MulticallCoverageProof or self._source_summary is None or
                        self._source_summary_sequence != sequence - 1):
                    _fail()
                proof = MulticallCoverageProof.from_wire(payload[0].wire)
                identity = self._capture_identity
                if (proof != payload[0] or proof.header[0] != (4 if self.owner.normal_three else 3) or proof.header[2:8] != (identity.generation, identity.native_root,
                        self.owner.lineage.native_thread_id, identity.stream_id,
                        int(identity.ownership_nonce[24:], 16), 1) or
                        proof.header[8:11] != (sequence - 1, 1, sequence - 1) or
                        proof.header[11] != len(self._typed_reads) or
                        proof.invocation_count != len(self._host129_groups) or
                        proof.service_return_count != len(self._service_returns)):
                    _fail()
                self._multicall_proof = payload[0]
                result = None
            elif operation == 'source-summary':
                if (len(payload) != 1 or type(payload[0]) is not RootSourceSummary or self._source_summary is not None or
                        payload[0].native_root != self._capture_identity.native_root):
                    _fail()
                self.owner._charge_e(2 * _wire_size(payload[0]))
                self._source_summary = payload[0]
                self._source_summary_sequence = sequence
                result = None
            elif operation == 'barrier':
                if (len(payload) != 1 or type(payload[0]) is not RootStreamTerminal or self._source_summary is None or
                        payload[0].wire_version != (5 if self.owner.normal_three else 4) or
                        payload[0].last_sequence != sequence or payload[0].identity != self._capture_identity or
                        payload[0].native_thread_id != self.owner.lineage.native_thread_id or
                        payload[0].source_summary_sequence != self._source_summary_sequence):
                    _fail()
                if (self.owner.multicall and payload[0].host129_invocation_count != len(self._host129_groups) or
                        not self.owner.multicall and payload[0].host129_invocation_count is not None):
                    _fail()
                if self.owner.multicall and (self._multicall_proof is None or
                        payload[0].typed_host129_read_count != self._multicall_proof.header[11]):
                    _fail()
                self.owner._charge_e(2 * _wire_size(payload[0]))
                self._capture_barrier = payload[0]
                result = None
            elif operation == 'events':
                if len(payload) != 1 or type(payload[0]) is not tuple or not 1 <= len(payload[0]) <= 20:
                    _fail()
                for event in payload[0]:
                    self.feed(event)
                result = None
            elif operation == 'producer':
                from .primary_singleton_inputs import ApiEffect, AllocationEffect, FreeEffect
                producer_rows = (payload[0],) if len(payload) == 1 and type(payload[0]) in (ApiEffect, AllocationEffect, FreeEffect) else payload[0] if len(payload) == 1 else ()
                if (type(producer_rows) is not tuple or not 1 <= len(producer_rows) <= 64 or
                        _wire_size(producer_rows) > 4096 or self._producer_wire_count >= 64):
                    _fail()
                for event in producer_rows:
                    self.owner.receive_producer(event)
                self._producer_wire_count += 1
                self._producer_effect_count += len(producer_rows)
                result = None
            elif type(operation) is str and operation in methods:
                result = methods[operation](*payload)
            else:
                _fail()
            self._capture_sequence = sequence
            return result
        except BaseException:
            self.owner.close()
            raise
        finally:
            self._dispatching_capture = False

    def _multicall_inputs(self, terminal, stream_terminal, coverage, policy3_witness):
        from .primary_host129_inputs import (
            Host129InvocationInputs, Host129CounterReads, Host129ClockServiceReturns, Host129EntropyServiceReturns,
        )
        if (type(coverage) is not _QualifiedMulticallCoverage or 'main' not in self._source_readers or
                stream_terminal.host129_invocation_count != len(self._host129_groups) or
                stream_terminal.typed_host129_read_count != len(self._typed_reads)):
            _fail()
        proof = coverage._verify(self, stream_terminal)
        if (proof.invocation_count != len(self._host129_groups) or
                proof.service_return_count != len(self._service_returns)):
            _fail()
        if not self._host129_groups:
            if (self.descriptor.root_ordinal != 0 or self.descriptor.main_arguments[9] != 3 or
                    terminal.output_count != 28 or self._typed_reads or self._service_returns or
                    type(self.descriptor) is not PendingPolicy3RootDescriptor):
                _fail()
            self._freeze_policy3(policy3_witness)
            return None
        if self.descriptor.main_arguments[9] == 3:
            _fail()
        rows = []
        for index, group in enumerate(self._host129_groups):
            self._complete_host129_group(group)
            source = group['source']
            clocks = tuple(row.value for row in group['services'] if row.service_kind == 1)
            entropy = tuple(row.value for row in group['services'] if row.service_kind == 2)
            summary = proof.groups[index]
            if summary != (index, source.invocation, source.parent, summary[3], summary[4], len(group['reads']), 2,
                           len(entropy), source.evaluator_entry - 0x118, source.frame.cells):
                _fail()
            rows.append(Host129InvocationInputs(index, source.invocation, source.parent, source, summary[3], summary[4],
                Host129CounterReads(*(row.value for row in group['reads'])) if group['reads'] else None,
                Host129ClockServiceReturns(*clocks), Host129EntropyServiceReturns(entropy), len(group['reads'])))
        return tuple(rows)

    def _typed_counter_inputs(self, terminal, stream_terminal, coverage, policy3_witness):
        from .primary_host129_inputs import Host129CounterReads
        if (type(coverage) is not QualifiedTypedReadCoverage or
                type(stream_terminal.typed_host129_read_count) is not int or
                stream_terminal.typed_host129_read_count != len(self._typed_reads) or
                self.descriptor.main_arguments[0] != 4 or 'main' not in self._source_readers):
            _fail()
        coverage._verify(self, stream_terminal)
        if stream_terminal.typed_host129_read_count == 4:
            if (self._typed_reservation != 13312 or 'host129' not in self._source_readers or
                    'host129' not in self._frame_sources or self.descriptor.main_arguments[9] == 3):
                _fail()
            return Host129CounterReads(*(row.value for row in self._typed_reads))
        if (self._typed_reservation != 512 or self.descriptor.root_ordinal != 0 or
                self.descriptor.main_arguments[9] != 3 or terminal.output_count != 28 or
                'host129' in self._frame_sources or self._typed_reads or
                type(self.descriptor) is not PendingPolicy3RootDescriptor):
            _fail()
        self._freeze_policy3(policy3_witness)
        return None

    def finish_capture(self, terminal, stream_terminal, *, policy3_witness=None,
                       counter_reads=None, clock_returns=None, entropy_returns=None, typed_read_coverage=None):
        try:
            if self._capture_identity is None or self._dispatching_capture:
                _fail()
            self._dispatching_capture = self._finishing_capture = True
            self._active()
            policies = len(self._policy3_effects)
            registrations = int(self._policy3_registration is not None)
            if (type(stream_terminal) is not RootStreamTerminal or type(terminal) is not RootTerminal or
                    self._capture_barrier is None or stream_terminal != self._capture_barrier or self._source_summary is None or
                    stream_terminal.identity != self._capture_identity or
                    stream_terminal.last_sequence != self._capture_sequence or
                    not stream_terminal.event_count or not stream_terminal.reader_count or not stream_terminal.frame_count or
                    (self._source_summary.reader_count, self._source_summary.event_count, self._source_summary.output_count,
                     self._source_summary.constructor_records_completed) !=
                    (stream_terminal.reader_count, stream_terminal.event_count, terminal.output_count,
                     stream_terminal.constructor_records_completed) or
                    stream_terminal.registration_count != registrations or
                    stream_terminal.constructor_records_completed != (19 if self._producer_effect_count else 0) or
                    (stream_terminal.event_count, stream_terminal.reader_count, stream_terminal.frame_count,
                     stream_terminal.effect_count, stream_terminal.policy_effect_count, stream_terminal.environment_count,
                     stream_terminal.output_count, stream_terminal.producer_count, stream_terminal.producer_effect_count) !=
                    (self.encoder.event_count, len(self.encoder._readers), len(self.frames),
                     policies + registrations + len(self.environment) + self._producer_effect_count,
                     policies, len(self.environment), terminal.output_count, self._producer_wire_count, self._producer_effect_count)):
                _fail()
            if counter_reads is not None:
                _fail()
            invocations = None
            if self.owner.mode == 'typed-native-history':
                if self.owner.multicall:
                    if clock_returns is not None or entropy_returns is not None:
                        _fail()
                    invocations = self._multicall_inputs(terminal, stream_terminal, typed_read_coverage, policy3_witness)
                else:
                    counter_reads = self._typed_counter_inputs(terminal, stream_terminal, typed_read_coverage, policy3_witness)
                if self.descriptor.main_arguments[9] == 3:
                    policy3_witness = None
            elif (typed_read_coverage is not None or stream_terminal.typed_host129_read_count is not None or
                    stream_terminal.host129_invocation_count is not None):
                _fail()
            if self.descriptor.main_arguments[9] == 3:
                if any(value is not None for value in (counter_reads, clock_returns, entropy_returns)):
                    _fail()
            else:
                values = {field.name: getattr(self.descriptor, field.name) for field in fields(RootDescriptor)}
                values.update(counter_reads=counter_reads, clock_returns=clock_returns, entropy_returns=entropy_returns,
                              host129_invocations=invocations,
                              host129_profile=self.owner.evidence_profile if self.owner.normal_three else None)
                self.owner._charge_e(2 * sum(_wire_size(value) for value in ((clock_returns, entropy_returns) if self.owner.mode == 'typed-native-history' else (counter_reads, clock_returns, entropy_returns))))
                self.descriptor = RootDescriptor(**values)
            self._stream_terminal = stream_terminal
            self.finish_root(terminal, reader_count=stream_terminal.reader_count, policy3_witness=policy3_witness)
            self.owner._awaiting_release = self
            return RootSealReceipt._postcommit(self)
        except BaseException:
            self.owner.close()
            raise
        finally:
            self._dispatching_capture = self._finishing_capture = False

    def seal_receipt(self):
        if self._receipt is None:
            _fail()
        return self._receipt

    def confirm_release(self, confirmation):
        try:
            receipt = self.seal_receipt()
            if (type(confirmation) is not RootReleaseConfirmation or
                    (confirmation.identity, confirmation.native_call_id, confirmation.root_ordinal, confirmation.last_sequence,
                     confirmation.typed_host129_read_count, confirmation.host129_invocation_count, confirmation.wire_version) !=
                    (receipt.identity, receipt.native_call_id, receipt.root_ordinal, receipt.terminal.last_sequence,
                     receipt.terminal.typed_host129_read_count, receipt.terminal.host129_invocation_count, receipt.terminal.wire_version)):
                _fail()
            if self._release is not None:
                if confirmation != self._release:
                    _fail()
                return True
            if self.owner.closed or self.owner._awaiting_release is not self:
                _fail()
            self._release = confirmation
            self.owner._awaiting_release = None
            return True
        except BaseException:
            self.owner.close()
            raise


class HistoryArena:
    def __init__(self, lineage, *, input_bytes, output_bytes, reader_capacity,
                 candidate_reservations, evidence_bytes, mode='offline-history',
                 native_root_capacity=None, lineage_reservation=None, additional_native_reservation=None,
                 evidence_profile=None):
        normal_three = type(evidence_profile) is str and evidence_profile == 'normal-main-three-call-native-history'
        multicall = normal_three or evidence_profile == 'multicall-typed-evidence' and type(evidence_profile) is str
        if evidence_profile is not None and not (
                type(evidence_profile) is str and
                (evidence_profile == 'expanded-legacy-evidence' and mode == 'native-history' and evidence_bytes == 65536 or
                 multicall and mode == 'typed-native-history' and evidence_bytes == (262144 if normal_three else 131072))):
            _fail()
        if (type(lineage) is not PendingLineageIdentity or
                any(not _unsigned(value, 32) for value in (input_bytes, output_bytes, reader_capacity, evidence_bytes)) or
                not 0 < evidence_bytes <= 327680 or type(candidate_reservations) is not tuple or
                not 1 <= len(candidate_reservations) <= 8 or
                any(type(value) is not int or not 0 < value <= 262144 for value in candidate_reservations)):
            _fail()
        self.capture_peak = 206848 + 4 * input_bytes + 2 * output_bytes + 256 * reader_capacity + sum(candidate_reservations) + evidence_bytes
        self.replay_peak = self.capture_peak - 32768
        if mode in ('native-history', 'typed-native-history'):
            if (type(native_root_capacity) is not int or not 1 <= native_root_capacity <= 8 or
                    any(not _unsigned(value, 32) for value in (lineage_reservation, additional_native_reservation))):
                _fail()
            self.capture_peak += 16384 + 4064 + 104 + 16 * native_root_capacity + 56 + lineage_reservation + additional_native_reservation
            self.replay_peak = self.capture_peak - 32768
            if mode == 'typed-native-history' and evidence_bytes != (262144 if normal_three else 131072 if multicall else 65536):
                _fail()
            limit = 524288 if normal_three else 393216 if multicall else 327680 if mode == 'typed-native-history' or evidence_profile is not None else 294912
        elif mode == 'offline-history':
            if (evidence_bytes > 16384 or any(value is not None for value in
                    (native_root_capacity, lineage_reservation, additional_native_reservation))):
                _fail()
            limit = 262144
        else:
            _fail()
        if self.capture_peak > limit:
            _fail()
        self.mode = mode
        self.evidence_profile = evidence_profile
        self.multicall = multicall
        self.normal_three = normal_three
        self.host129_capacity = 3 if normal_three else 2
        self.total_cap = limit
        self.native_root_capacity = native_root_capacity
        self.lineage_reservation = lineage_reservation
        self.additional_native_reservation = additional_native_reservation
        self.native_lineage_used = self.additional_native_used = 0
        self.lineage = lineage
        self.input_bytes = input_bytes
        self.output_bytes = output_bytes
        self.reader_capacity = reader_capacity
        self.candidate_reservations = candidate_reservations
        self.evidence_bytes = evidence_bytes
        self._thread = get_ident()
        self._encoded = bytearray(65536)
        self._readers = bytearray(16384)
        self.encoded_length = self.reader_length = self.evidence_used = 0
        self._input_used = self._output_used = self._capacity_used = 0
        self._roots = []
        self._pending = self._borrowed = None
        self._awaiting_release = None
        self._capture_generation = None
        self._capture_serial = 0
        self._capture_streams = set()
        self._producer = None
        self._producer_events = []
        self._spans = {}
        self._next_span = 0
        self._next = 0
        self.closed = self.sealed = self.used = False
        try:
            self._charge_e(128 + sum(_text_bytes(value) for value in
                                     (lineage.source_sha256, lineage.process_creation_identity,
                                      lineage.module_load_generation, lineage.constructor_call_id,
                                      lineage.container_generation)))
            if self.multicall:
                self._charge_e(2048)
        except BaseException:
            self.close()
            raise

    def _active(self):
        if self.closed or self.sealed or self._thread != get_ident():
            _fail()

    def _charge_e(self, size):
        if self.evidence_used + size > self.evidence_bytes:
            _fail()
        self.evidence_used += size

    def find_reader_span(self, metadata):
        self._active()
        from .primary_consumed_mgf import ReaderMetadata
        if type(metadata) is not ReaderMetadata:
            _fail()
        key = _reader_key(metadata)
        return next((span for span, row in self._spans.items() if row[0] == key), None)

    def begin_root(self, descriptor):
        if self.mode != 'offline-history':
            self.close()
            _fail()
        return self._begin_root(descriptor)

    def _begin_root(self, descriptor):
        try:
            self._active()
            if descriptor.host129_invocations is not None or descriptor.host129_profile is not None:
                _fail()
            if (self._pending is not None or self._awaiting_release is not None or
                    type(descriptor) not in (RootDescriptor, PendingPolicy3RootDescriptor) or
                    descriptor.lineage != self.lineage or
                    descriptor.root_ordinal != len(self._roots) or len(self._roots) >= 8 or
                    self.mode in ('native-history', 'typed-native-history') and len(self._roots) >= self.native_root_capacity or
                    any(row.descriptor.native_call_id == descriptor.native_call_id for row in self._roots) or
                    self._roots and self._roots[-1].terminal.output_count == 96):
                _fail()
            inputs = sum(row.length for row in descriptor.ranges[:4])
            outputs = sum(row.length for row in descriptor.ranges[4:])
            if (self._input_used + inputs > self.input_bytes or self._output_used + outputs > self.output_bytes or
                    self._capacity_used + descriptor.reader_capacity > self.reader_capacity):
                _fail()
            if self.mode in ('native-history', 'typed-native-history'):
                charge = 160 + inputs
                if self.native_lineage_used + charge > self.lineage_reservation:
                    _fail()
                self.native_lineage_used += charge
            groups = {}
            for row in descriptor.ranges:
                groups[row.alias_group] = max(groups.get(row.alias_group, 0), row.alias_offset + row.length)
            if sum(groups.values()) > inputs + outputs:
                _fail()
            self._charge_e(512 + _text_bytes(descriptor.native_call_id) + 2 * outputs)
            if descriptor.policy3_inputs is not None:
                self._charge_e(2 * _wire_size(descriptor.policy3_inputs))
            elif type(descriptor) is PendingPolicy3RootDescriptor:
                self._charge_e(2 * (_wire_size(descriptor.lineage) + _wire_size(descriptor.native_call_id) + 8 + 4 + 1))
            self._input_used += inputs
            self._output_used += outputs
            self._capacity_used += descriptor.reader_capacity
            receiver = RootReceiver(self, descriptor)
            self._pending = receiver
            receiver.encoder = ConsumptionEncoder._history_segment(receiver)
            return receiver
        except BaseException:
            self.close()
            raise

    def begin_capture(self, entry, identity, *, header_sequence):
        try:
            self._active()
            if (self.mode not in ('native-history', 'typed-native-history') or type(entry) is not RootEntry or
                    type(identity) is not RootCaptureIdentity or identity.native_root != entry.root_ordinal + 1 or
                    type(header_sequence) is not int or header_sequence != 1 or
                    self._capture_generation not in (None, identity.generation) or
                    identity.stream_id in self._capture_streams or int(identity.ownership_nonce[24:], 16) <= self._capture_serial):
                _fail()
            if self.mode == 'typed-native-history':
                self._charge_e(5120 if self.normal_three else 4608 if self.multicall else 512)
            self._charge_e(512 + 2 * _wire_size(identity) + 2 * _wire_size(entry.native_call_id))
            values = {field.name: getattr(entry, field.name) for field in fields(RootDescriptor)}
            descriptor_type = PendingPolicy3RootDescriptor if entry.main_arguments[9] == 3 else RootDescriptor
            receiver = self._begin_root(descriptor_type(**values))
            receiver._capture_identity = identity
            receiver._typed_reservation = 512 if self.mode == 'typed-native-history' else 0
            receiver._capture_sequence = header_sequence
            self._capture_generation = identity.generation
            self._capture_serial = int(identity.ownership_nonce[24:], 16)
            self._capture_streams.add(identity.stream_id)
            return receiver
        except BaseException:
            self.close()
            raise

    def reserve_additional_native_copy(self, byte_count):
        try:
            self._active()
            if (self.mode not in ('native-history', 'typed-native-history') or not _unsigned(byte_count, 32) or
                    self.additional_native_used + byte_count > self.additional_native_reservation):
                _fail()
            self.additional_native_used += byte_count
        except BaseException:
            self.close()
            raise

    def _check_aliases(self, row):
        values = row.inputs + row.outputs
        masks = row.masks + row.output_masks
        for i, left in enumerate(row.descriptor.ranges):
            for j, right in enumerate(row.descriptor.ranges[:i]):
                if left.alias_group != right.alias_group:
                    continue
                start = max(left.alias_offset, right.alias_offset)
                end = min(left.alias_offset + left.length, right.alias_offset + right.length)
                for index in range(start, end):
                    a, b = index - left.alias_offset, index - right.alias_offset
                    if values[i][a] != values[j][b] or masks[i][a] != masks[j][b]:
                        _fail()

    def receive_producer(self, event):
        try:
            self._active()
            if (type(event) not in (ApiEffect, AllocationEffect, FreeEffect) or
                    len(self._producer_events) >= 64 or event.sequence != len(self._producer_events) + 1 or
                    event.site.native_call_id != self.lineage.constructor_call_id +
                    ('/buffer-init' if event.site.program == 'buffer-init' else '')):
                _fail()
            self._charge_e(64 + 2 * _wire_size(event))
            self._producer_events.append(event)
        except BaseException:
            self.close()
            raise

    def seal(self, selected_call_id, closure, *, producer_events=None, completed_warm_clock_domain=None):
        try:
            self._active()
            if (self._pending is not None or self._awaiting_release is not None or not self._roots or type(closure) is not HistoryClosure or
                    closure.lineage != self.lineage or closure.root_call_ids != tuple(row.descriptor.native_call_id for row in self._roots) or
                    selected_call_id != closure.selected_main_call_id or self._roots[-1].terminal.output_count != 96 or
                    producer_events is not None and (type(producer_events) is not tuple or self._producer_events)):
                _fail()
            if producer_events is not None:
                for event in producer_events:
                    self.receive_producer(event)
            self._charge_e(256 + sum(_text_bytes(value) for value in closure.root_call_ids))
            if completed_warm_clock_domain is not None:
                if type(completed_warm_clock_domain) is not CompletedWarmClockDomain:
                    _fail()
                self._charge_e(2 * _wire_size(completed_warm_clock_domain))
            identity = self.lineage.finalize(selected_call_id)
            self._producer = SingletonProducerInputs(identity, tuple(self._producer_events),
                                                     completed_warm_clock_domain=completed_warm_clock_domain)
            self._producer_events.clear()
            self.sealed = True
            return HistoryLease(self)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self._borrowed is not None:
            lease = self._borrowed
            if lease.capsule is not None and not lease.capsule.closed:
                lease.capsule.close()
            lease.closed = True
            self._borrowed = None
        rows = list(self._roots)
        if self._pending is not None:
            receiver = self._pending
            if receiver._segment is not None:
                rows.append(receiver._segment)
            else:
                if receiver.encoder is not None:
                    receiver.encoder.close()
                for value in receiver.masks + receiver.outputs + receiver.output_masks:
                    _clear_chunks(value)
            receiver.closed = True
            receiver._frame_sources.clear()
            receiver._source_readers.clear()
            receiver._typed_reads.clear()
            receiver._host129_groups.clear()
            receiver._service_returns.clear()
            receiver._policy3_effects.clear()
            receiver._policy3_registration = None
            self._pending = None
        for row in rows:
            for reader in row.readers:
                reader.observations.release()
            row.readers.clear()
            for value in row.inputs + row.masks + row.outputs + row.output_masks:
                _clear_chunks(value)
            row.inputs = row.masks = row.outputs = row.output_masks = ()
            if hasattr(row, 'native_output'):
                if type(row.native_output) is Main96DigestReference:
                    row.native_output = None
                else:
                    _clear_chunks(row.native_output)
            row.terminal = None
        self._roots.clear()
        _clear_chunks(self._readers)
        _clear_chunks(self._encoded)
        self._producer = self.lineage = None
        self._producer_events.clear()
        self._spans.clear()
        self._awaiting_release = None
        self._capture_streams.clear()


class RootCapsuleLease:
    def __init__(self, owner, row):
        self.owner = owner
        self.row = row
        self.capsule = None
        self.closed = False

    def take_capsule(self):
        if self.closed or self.capsule is not None or self.owner._thread != get_ident():
            self.owner.close()
            _fail()
        self.capsule = PrivateCoreReplayCapsule._borrow_history_segment(self)
        return self.capsule

    def _released(self, complete):
        self.closed = True
        self.owner._borrowed = None
        if not complete:
            self.owner.close()

    def close(self):
        if self.closed:
            return
        if self.capsule is not None:
            self.capsule.close()
        else:
            self.closed = True
            self.owner._borrowed = None
            self.owner.close()


class HistoryLease:
    def __init__(self, owner):
        self._owner = owner

    def borrow_next(self):
        owner = self._owner
        if (owner is None or owner.closed or not owner.sealed or owner._thread != get_ident() or
                owner._borrowed is not None or owner._next >= len(owner._roots)):
            if owner is not None:
                owner.close()
            _fail()
        row = owner._roots[owner._next]
        owner._next += 1
        owner._borrowed = RootCapsuleLease(owner, row)
        return owner._borrowed

    def close(self):
        owner, self._owner = self._owner, None
        if owner is not None:
            owner.close()


class _HistoryEnvironmentBinding:
    def __init__(self, row):
        self.row = row
        self.frame_index = self.index = 0
        self.thread = get_ident()

    def read(self, name, arguments):
        if self.thread != get_ident():
            _fail()
        if name == 'VM frame':
            if self.frame_index >= len(self.row.frames):
                _fail()
            frame = self.row.frames[self.frame_index]
            if arguments != (frame.program,):
                _fail()
            self.frame_index += 1
            return frame
        if self.index >= len(self.row.environment):
            _fail()
        event = self.row.environment[self.index]
        if (event.name, event.arguments) != (name, arguments):
            _fail()
        self.index += 1
        return event.value

    def finish(self):
        if self.frame_index != len(self.row.frames) or self.index != len(self.row.environment):
            _fail()


def _map_root(runtime, row):
    memory = runtime.memory
    descriptor = row.descriptor
    for item in descriptor.ranges:
        if not item.length:
            continue
        if (item.address < runtime.image_base + 0x8000000 and runtime.image_base <= item.address + item.length or
                item.address < runtime.tls_epoch_address + 4 and runtime.tls_epoch_address < item.address + item.length or
                any(item.address < pointer + size and pointer < item.address + item.length for pointer, size in runtime.allocations.items())):
            _fail()
        if any(item.address < region.address + len(region.data) and region.address < item.address + item.length
               for region in memory._region_snapshot()):
            _fail()
    backings = {}
    for item in descriptor.ranges:
        size = item.alias_offset + item.length
        if size:
            backings[item.alias_group] = max(backings.get(item.alias_group, 0), size)
    data = {key: bytearray(size) for key, size in backings.items()}
    masks = {key: bytearray(size) for key, size in backings.items()}
    values = row.inputs + row.outputs
    known = row.masks + row.output_masks
    for i, item in enumerate(descriptor.ranges):
        if item.length:
            data[item.alias_group][item.alias_offset:item.alias_offset + item.length] = values[i]
            masks[item.alias_group][item.alias_offset:item.alias_offset + item.length] = known[i]
    intervals = []
    for item in sorted((item for item in descriptor.ranges if item.length), key=lambda item: item.address):
        if intervals and item.address <= intervals[-1][1] and item.alias_group == intervals[-1][2] and item.address - item.alias_offset == intervals[-1][3]:
            intervals[-1][1] = max(intervals[-1][1], item.address + item.length)
        else:
            intervals.append([item.address, item.address + item.length, item.alias_group, item.address - item.alias_offset])
    mapped = []
    try:
        for start, end, group, base in intervals:
            offset = start - base
            memory.map(start, memoryview(data[group])[offset:offset + end - start], name='owned history root', initialized=True)
            mapped.append(start)
        for start, end, group, base in intervals:
            offset = start - base
            region, _ = memory._span(start, end - start)
            region.initialized = memoryview(masks[group])[offset:offset + end - start]
        return mapped, data, masks
    except BaseException:
        for start in mapped:
            memory.unmap(start)
        for value in tuple(data.values()) + tuple(masks.values()):
            _clear_chunks(value)
        raise


def replay_history(runtime, history):
    from .primary_singleton_inputs import _ProducerBinding
    from .primary_host129_inputs import _CounterBinding, _ClockServiceBinding, _EntropyServiceBinding, _MulticallBinding
    from .primary_policy3_inputs import _Policy3Binding
    if type(history) is not HistoryLease or history._owner is None:
        _fail()
    owner = history._owner
    if (owner.closed or owner.used or owner._next != 0 or owner._thread != get_ident() or runtime._program_calls or
            runtime._active_main is not None or runtime._active_failed or runtime._singleton_producer_binding is not None or
            runtime._host129_multicall_binding is not None or
            any(getattr(runtime, name) is not None for name in
                ('_host129_counter_binding', '_host129_clock_service_binding', '_host129_entropy_service_binding'))):
        _fail()
    owner.used = True
    comparisons = []
    try:
        runtime._singleton_producer_binding = _ProducerBinding(owner._producer, runtime)
        owner._producer = None
        for index in range(len(owner._roots)):
            lease = history.borrow_next()
            row = lease.row
            descriptor = row.descriptor
            mapped, data, masks = _map_root(runtime, row)
            try:
                runtime._history_environment = _HistoryEnvironmentBinding(row)
                runtime._policy3_binding = (None if descriptor.policy3_inputs is None else
                                            _Policy3Binding(descriptor.policy3_inputs, runtime, descriptor))
                runtime._host129_multicall_binding = (None if descriptor.host129_invocations is None else
                                                      _MulticallBinding(descriptor.host129_invocations, runtime,
                                                                        normal_three=descriptor.host129_profile is not None))
                for name, value, factory in (
                        ('_host129_counter_binding', descriptor.counter_reads, _CounterBinding),
                        ('_host129_clock_service_binding', descriptor.clock_returns, _ClockServiceBinding),
                        ('_host129_entropy_service_binding', descriptor.entropy_returns, _EntropyServiceBinding)):
                    setattr(runtime, name, None if value is None else factory(value, runtime))
                capsule = lease.take_capsule()
                with capsule.bind(runtime):
                    runtime.execute_main(descriptor.main_arguments)
                    count = runtime.memory.load(descriptor.main_arguments[8], 4)
                    output = runtime.memory.read(descriptor.main_arguments[7], count)
                    comparison = capsule.compare_result(count, output, row.native_output)
                    if not comparison.equal:
                        _fail()
                    comparisons.append(comparison)
                runtime._history_environment.finish()
                if index and not runtime._singleton_producer_binding.complete:
                    _fail()
            finally:
                lease.close()
                multicall = runtime._host129_multicall_binding
                if multicall is not None:
                    multicall.close()
                runtime._host129_multicall_binding = None
                for name in ('_host129_counter_binding', '_host129_clock_service_binding', '_host129_entropy_service_binding'):
                    binding = getattr(runtime, name)
                    if binding is not None:
                        binding.close()
                    setattr(runtime, name, None)
                policy = getattr(runtime, '_policy3_binding', None)
                if policy is not None:
                    policy.close()
                runtime._policy3_binding = None
                runtime._history_environment = None
                for start in mapped:
                    runtime.memory.unmap(start)
                for value in tuple(data.values()) + tuple(masks.values()):
                    _clear_chunks(value)
        if not runtime._singleton_producer_binding.complete:
            _fail()
        return tuple(comparisons)
    except BaseException:
        runtime._active_failed = True
        raise
    finally:
        producer = runtime._singleton_producer_binding
        if producer is not None:
            producer.close()
        history.close()
