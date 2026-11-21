from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
import json

from .local113_episode_validation import integer, keys, label, no_duplicates, pair, pointer, raw, require, sanitized
from .local113_prefix_frames import PrefixFramePlan
from .primary_consumed_mgf import SOURCE_SHA256, SourceIdentity
from .primary_prefix_observed_provider import PrefixObservedProviderInputs, SLOT_KEYS
from .primary_prefix_raw_clock import PrefixMain1160RawInputs
from .primary_singleton_history import RootCaptureIdentity


ROOT_KEYS = 'schema captureMode identity mainEntry frames warmContainer effectiveEnvironment mainClockRawInputs main1160Wrapper providerEpisode hostGroups conditionalIdentities local113Reference terminal'
IDENTITY_KEYS = 'sourcePeSha256 moduleBase moduleGeneration processCreationIdentity mainEpoch generation nativeRoot streamId ownershipNonce thread readerInvocation mainEntryRSP'


@dataclass(repr=False)
class Local113Episode:
    inputs: dict
    reference: bytes
    cleanup: dict
    source_identity: SourceIdentity
    frame_plan: PrefixFramePlan
    clock: PrefixMain1160RawInputs
    provider: PrefixObservedProviderInputs
    capture_identity: RootCaptureIdentity
    diagnostic_only: bool = False
    _claimed: bool = field(default=False, init=False)
    _seal: bytes = field(default=b'', init=False)

    def __post_init__(self):
        self._seal = sha256(json.dumps(self.inputs, sort_keys=True, separators=(',', ':')).encode()).digest()

    def verify_sealed(self):
        require(self._seal == sha256(json.dumps(self.inputs, sort_keys=True, separators=(',', ':')).encode()).digest(), 'POST_SEAL_INPUT_CHANGED')
        rebuilt = PrefixFramePlan.from_wire(self.inputs)
        require(rebuilt.sources == self.frame_plan.sources and rebuilt.rows == self.frame_plan.rows, 'POST_SEAL_FRAME_CHANGED')
        require(PrefixObservedProviderInputs.from_wire(self.source_identity, self.inputs) == self.provider, 'POST_SEAL_PROVIDER_CHANGED')

    def close(self):
        if self.frame_plan is not None and not self.frame_plan.closed:
            self.frame_plan.close()
        self.inputs.clear()
        self.reference = b''
        self._seal = b''
        self.source_identity = self.frame_plan = self.clock = self.provider = self.capture_identity = None


def _validate_cleanup(terminal, diagnostic):
    keys(terminal, 'sealedAt collectionClosed dropped cleanup', 'TERMINAL_KEYS')
    require(type(terminal['sealedAt']) is int and terminal['sealedAt'] == 9563 and terminal['collectionClosed'] is True and type(terminal['dropped']) is int and terminal['dropped'] == 0, 'INCOMPLETE_SEAL')
    cleanup = terminal['cleanup']
    keys(cleanup, 'hooksRestored nativeQuiescent nativeAllocationReleased listenersRemaining', 'CLEANUP_KEYS')
    for name in ('hooksRestored', 'nativeQuiescent', 'nativeAllocationReleased'):
        require(type(cleanup[name]) is bool or cleanup[name] is None or cleanup[name] == 'UNKNOWN', 'CLEANUP_TYPE')
    listeners = cleanup['listenersRemaining']
    require(listeners is None or listeners == 'UNKNOWN' or type(listeners) is int and 0 <= listeners < 1 << 32, 'CLEANUP_LISTENERS')
    require(diagnostic or all(cleanup[k] is True for k in ('hooksRestored', 'nativeQuiescent', 'nativeAllocationReleased')) and type(listeners) is int and listeners == 0, 'NATIVE_CLEANUP_UNQUALIFIED')
    return dict(cleanup)


@sanitized('INPUT_REJECTED')
def parse_local113_episode(wire, *, expected_identity, diagnostic_only=False):
    require(type(diagnostic_only) is bool, 'DIAGNOSTIC_TYPE')
    if type(wire) in (str, bytes, bytearray):
        wire = json.loads(wire, object_pairs_hook=no_duplicates)
    keys(wire, ROOT_KEYS, 'EPISODE_KEYS')
    wire = deepcopy(wire)
    require(wire['schema'] == 'local113-live-episode-v1' and wire['captureMode'] == 'LOCAL113_PREFIX9563', 'EPISODE_SCHEMA')
    identity = wire['identity']
    keys(identity, IDENTITY_KEYS, 'EPISODE_IDENTITY_KEYS')
    keys(expected_identity, IDENTITY_KEYS, 'EXPECTED_IDENTITY_KEYS')
    require(all(type(identity[k]) is type(expected_identity[k]) and identity[k] == expected_identity[k] for k in identity), 'EPISODE_IDENTITY_MISMATCH')
    require(identity['sourcePeSha256'] == SOURCE_SHA256, 'EPISODE_SOURCE_PIN')
    for name in ('moduleGeneration', 'processCreationIdentity', 'mainEpoch'):
        label(identity[name])
    base, rsp = pointer(identity['moduleBase']), pointer(identity['mainEntryRSP'])
    for name in ('generation', 'nativeRoot', 'streamId', 'thread', 'readerInvocation'):
        integer(identity[name], 32, 1)
    capture = RootCaptureIdentity(identity['generation'], identity['nativeRoot'], identity['streamId'], identity['ownershipNonce'])
    capture.__post_init__()
    entry = wire['mainEntry']
    keys(entry, 'seq entryRSP callerReturn actualArguments12 inputs providerPrecall sharedControlReads', 'MAIN_ENTRY_KEYS')
    sequence = integer(entry['seq'], minimum=1)
    control_reads = entry['sharedControlReads']
    require(type(control_reads) is list and len(control_reads) == 2, 'SHARED_CONTROL_COUNT')
    for read, rva in zip(control_reads, (0x677E1B4, 0x677E1B8)):
        keys(read, 'seq address width hex knownMask', 'SHARED_CONTROL_READ_KEYS')
        require(integer(read['seq'], minimum=1) == sequence and pointer(read['address']) == base + rva and type(read['width']) is int and read['width'] == 4 and read['knownMask'] == 'ffffffff', 'SHARED_CONTROL_SOURCE')
        raw(read['hex'], 4)
    require(pointer(entry['entryRSP']) == rsp and pointer(entry['callerReturn']) == base + 0x2DE5B7A, 'MAIN_ENTRY_BINDING')
    args = entry['actualArguments12']
    require(type(args) is list and len(args) == 12, 'ABI12')
    arguments = tuple(pointer(v, True) if i in (1, 3, 5, 7, 8, 10) else integer(v, 53) for i, v in enumerate(args))
    require(arguments[0] == 4 and arguments[9] == 2 and arguments[7:9] == (rsp + 0x78, rsp + 0x74), 'ABI12_OUTPUTS')
    inputs = entry['inputs']
    keys(inputs, 'a b command d policy', 'ABI_INPUT_KEYS')
    require(type(inputs['policy']) is int and inputs['policy'] == 2, 'ABI_POLICY')
    for name, pi, li in (('a', 1, 2), ('b', 3, 4), ('command', 5, 6), ('d', 10, 11)):
        row = inputs[name]
        keys(row, 'pointer length hex', 'ABI_BYTES_KEYS')
        require(pointer(row['pointer'], True) == arguments[pi] and integer(row['length']) == arguments[li] and arguments[li] <= 1 << 20 and len(raw(row['hex'])) == arguments[li], 'ABI_BYTES')
    source = SourceIdentity(SOURCE_SHA256, identity['mainEpoch'], identity['generation'], arguments, base)
    source.__post_init__()
    plan = PrefixFramePlan.from_wire(wire)
    precall = entry['providerPrecall']
    keys(precall, SLOT_KEYS, 'PRECALL_SLOT_KEYS')
    require(integer(precall['seq'], minimum=1) == sequence and pointer(precall['providerPointer'], True) in (0, base + 0x1BFD960) and pointer(precall['md5Pointer'], True) in (0, base + 0x1BFD3D0), 'PRECALL_SLOT')
    guard = raw(precall['guardHex'], 4)
    wrapper = wire['main1160Wrapper']
    keys(wrapper, 'enterSeq leaveSeq sourceWord consumedPC timerAddress flagU8 previousHex timerAfterHex setupBeforeHex setupAfterHex compareOnlyOuterReturnU32', 'MAIN1160_WRAPPER_KEYS')
    require(all(type(wrapper[k]) is int for k in ('sourceWord', 'consumedPC', 'flagU8', 'compareOnlyOuterReturnU32')) and (wrapper['sourceWord'], wrapper['consumedPC'], wrapper['compareOnlyOuterReturnU32']) == (1160, 1168, 0) and 0 <= wrapper['flagU8'] < 256 and raw(wrapper['previousHex'], 8) == bytes(8) and wrapper['setupBeforeHex'] == wrapper['setupAfterHex'] == '01', 'MAIN1160_WRAPPER_DOMAIN')
    pointer(wrapper['timerAddress'])
    raw(wrapper['timerAfterHex'], 8)
    clock_wire = wire['mainClockRawInputs']
    require(clock_wire['mainEntry'] == {'entryRSP': identity['mainEntryRSP'], 'seq': sequence} and all(clock_wire[k] == identity[k] and type(clock_wire[k]) is type(identity[k]) for k in ('sourcePeSha256', 'moduleBase', 'moduleGeneration', 'processCreationIdentity', 'mainEpoch', 'readerInvocation', 'thread')), 'CLOCK_ACTUAL_ENTRY_MISMATCH')
    clock = PrefixMain1160RawInputs(source, clock_wire)
    service = clock.events[0].service
    require(integer(wrapper['enterSeq'], minimum=1) <= service.enter_seq < service.leave_seq <= integer(wrapper['leaveSeq'], minimum=1), 'MAIN1160_WRAPPER_SEQUENCE')
    provider = PrefixObservedProviderInputs.from_wire(source, wire)
    expected_provider = 0 if provider.mode == 'NULL' else base + 0x1BFD960
    require(pointer(precall['providerPointer'], True) == expected_provider and pointer(precall['md5Pointer'], True) == provider.md5_pointer and (provider.mode == 'NULL' or guard[0] & 1), 'PRECALL_PROVIDER_CHANGED')
    require(wrapper['leaveSeq'] < provider.enter_seq < provider.leave_seq, 'MAIN_PROVIDER_ORDER')
    groups = wire['hostGroups']
    require(type(groups) is list and len(groups) == len(plan.sources) - 1, 'HOST_GROUP_COUNT')
    previous = provider.leave_seq
    for row, frame, frow in zip(groups, plan.sources[1:], plan.rows[1:]):
        keys(row, 'siteWord frameInvocation services counterReads compareOnlyReturnU32 enterSeq leaveSeq', 'HOST_GROUP_KEYS')
        require(type(row['siteWord']) is int and row['siteWord'] == frow['siteWord'] and type(row['frameInvocation']) is int and row['frameInvocation'] == frame.invocation and previous < integer(row['enterSeq'], minimum=1) <= frow['enterSeq'] < frow['leaveSeq'] <= integer(row['leaveSeq'], minimum=1), 'HOST_GROUP_FRAME_ORDER')
        integer(row['compareOnlyReturnU32'], 32)
        previous = row['leaveSeq']
    conditionals = wire['conditionalIdentities']
    require(type(conditionals) is list and len(conditionals) <= 1, 'CONDITIONAL_IDENTITIES')
    for row in conditionals:
        keys(row, 'siteWord moduleNameHex moduleHandle exportNameHex exportPointer seq', 'CONDITIONAL_IDENTITY_KEYS')
        require(row['siteWord'] == 3886 and raw(row['moduleNameHex']) and raw(row['exportNameHex']) and provider.leave_seq < integer(row['seq'], minimum=1), 'CONDITIONAL_IDENTITY_SOURCE')
        pointer(row['moduleHandle'], True)
        require(pointer(row['exportPointer'], True) == 0, 'CONDITIONAL_EXPORT_UNSUPPORTED')
    reference = wire['local113Reference']
    keys(reference, 'seq pc length hex', 'LOCAL113_REFERENCE_KEYS')
    require(type(reference['pc']) is int and type(reference['length']) is int and (reference['pc'], reference['length']) == (9563, 16) and previous < integer(reference['seq'], minimum=1) < plan.rows[0]['leaveSeq'], 'LOCAL113_REFERENCE_BOUNDARY')
    private_reference = raw(reference['hex'], 16)
    cleanup = _validate_cleanup(wire['terminal'], diagnostic_only)
    model_inputs = deepcopy(wire)
    model_inputs.pop('local113Reference')
    model_inputs.pop('terminal')
    spans = plan.reserved()
    observed = provider.cache_observations
    if observed is not None:
        for string in (observed['value']['source'], observed['token']['source']):
            source_header = raw(string['headerHex'], 24)
            regions = [(pointer(string['address']), 24)]
            if source_header[0] & 1:
                regions.append((int.from_bytes(source_header[16:], 'little'), len(raw(string['payloadHex']))))
            from .local113_episode_validation import overlap
            require(not any(overlap(address, width, start, size) for address, width in regions for start, size in spans), 'PROVIDER_SOURCE_FRAME_ALIAS')
    return Local113Episode(model_inputs, private_reference, cleanup, source, plan, clock, provider, capture, diagnostic_only)
