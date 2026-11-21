from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import get_ident

from .local113_episode_validation import integer, keys, pair, pointer, raw, require


OP_KEYS = 'enterSeq leaveSeq normalReturn pointer returnAddress entryRSP invocationToken thread parentInvocation'
WARM_KEYS = 'mode callback guardReads cacheLock loggerLookup filetime value timestamp ttl token copies release normalLeave slotReads branchWitness'
STRING_KEYS = 'address headerHex payloadHex'
SLOT_KEYS = 'seq providerPointer md5Pointer guardHex'


def operation(row, identity, address, ra):
    keys(row, OP_KEYS, 'PROVIDER_OPERATION_KEYS')
    enter, leave = pair(row)
    require(pointer(row['pointer']) == address and pointer(row['returnAddress']) == pointer(identity['moduleBase']) + ra and pointer(row['entryRSP']) > 0 and type(row['invocationToken']) is str and 0 < len(row['invocationToken']) <= 256 and integer(row['thread'], 32, 1) == identity['thread'] and integer(row['parentInvocation'], 32, 1) == identity['readerInvocation'], 'PROVIDER_OPERATION_OWNER')
    return enter, leave


def decode_string(row, address):
    keys(row, STRING_KEYS, 'OBSERVED_STRING_KEYS')
    require(pointer(row['address']) == address, 'STRING_SOURCE_ADDRESS')
    header, payload = raw(row['headerHex'], 24), raw(row['payloadHex'])
    if header[0] & 1:
        capacity, size, source = int.from_bytes(header[:8], 'little') & ~1, int.from_bytes(header[8:16], 'little'), int.from_bytes(header[16:], 'little')
        require(0 <= size < capacity <= 1 << 20 and source > 0 and source + size + 1 <= 1 << 64 and len(payload) == size + 1 and payload[-1:] == b'\0', 'OBSERVED_LONG_STRING')
        return payload[:-1]
    size = header[0] >> 1
    require(size <= 22 and header[size + 1:size + 2] == b'\0' and payload == b'', 'OBSERVED_SHORT_STRING')
    return header[1:size + 1]


def slot(row, base, expected_provider, expected_md5):
    keys(row, SLOT_KEYS, 'OBSERVED_SLOT_KEYS')
    require(pointer(row['providerPointer'], True) == expected_provider and pointer(row['md5Pointer'], True) == expected_md5 and raw(row['guardHex'], 4)[0] & 1, 'OBSERVED_SLOT_CHANGED')
    return integer(row['seq'], minimum=1)


def logger_result(row, identity, base):
    keys(row, 'getter pointer pointerRead key root nodes nodesAfter acquire release compareOnlyResultU32', 'LOGGER_KEYS')
    logger = pointer(row['pointer'])
    require(integer(row['key'], 32) == 6, 'LOGGER_KEY')
    ge, gl = operation(row['getter'], identity, logger, 0x1BFD9E7)
    read = row['pointerRead']
    keys(read, 'seq address valueHex knownMask', 'LOGGER_POINTER_READ_KEYS')
    require(integer(read['seq'], minimum=1) <= ge and pointer(read['address']) == base + 0x67516A8 and read['knownMask'] == 'ffffffffffffffff' and int.from_bytes(raw(read['valueHex'], 8), 'little') == logger, 'LOGGER_POINTER_SOURCE')
    ae, al = operation(row['acquire'], identity, logger + 0x30, 0x1BE3F99)
    re, rl = operation(row['release'], identity, logger + 0x30, 0x1BE3FE1)
    require(ge < ae < al < re < rl < gl and row['nodes'] == row['nodesAfter'], 'LOGGER_SNAPSHOT_ORDER')
    nodes = row['nodes']
    require(type(nodes) is list and 1 <= len(nodes) <= 128, 'LOGGER_ROUTE')
    address, candidate, seen = pointer(row['root'], True), None, set()
    for node in nodes:
        keys(node, 'address leftQ rightQ keyI32 valueU32', 'LOGGER_NODE_KEYS')
        require(address != 0 and pointer(node['address']) == address and address not in seen, 'LOGGER_BROKEN_ROUTE')
        seen.add(address)
        key = node['keyI32']
        require(type(key) is int and -(1 << 31) <= key < 1 << 31, 'LOGGER_SIGNED_KEY')
        integer(node['valueU32'], 32)
        left, right = pointer(node['leftQ'], True), pointer(node['rightQ'], True)
        if key < 6:
            address = right
        else:
            candidate, address = node, left
    require(address == 0, 'LOGGER_INCOMPLETE_ROUTE')
    result = candidate['valueU32'] if candidate is not None and candidate['keyI32'] == 6 else 2
    require(integer(row['compareOnlyResultU32'], 32) == result and result == 1, 'UNSUPPORTED_FEATURE6')
    return ge, gl


@dataclass(frozen=True, repr=False)
class PrefixObservedProviderInputs:
    source_identity: object
    identity: dict
    mode: str
    value: bytes
    token: bytes
    timestamp: int
    md5_pointer: int
    enter_seq: int
    leave_seq: int
    wrapper: dict
    cache_observations: dict | None
    _claimed: bool = field(default=False, init=False, compare=False)

    @classmethod
    def from_wire(cls, source_identity, envelope):
        identity, row = envelope['identity'], envelope['providerEpisode']
        base = pointer(identity['moduleBase'])
        effective = envelope['effectiveEnvironment']
        md5 = pointer(effective['md5CallbackPointer'], True)
        require(md5 in (0, base + 0x1BFD3D0), 'OBSERVED_MD5_UNKNOWN')
        require(type(row) is dict and row.get('mode') in ('NULL', 'observed-warm-hit-v1'), 'OBSERVED_PROVIDER_MODE')
        if row['mode'] == 'NULL':
            keys(row, 'mode slotRead md5Read enterSeq leaveSeq', 'NULL_PROVIDER_KEYS')
            enter, leave = integer(row['enterSeq'], minimum=1), integer(row['leaveSeq'], minimum=1)
            for read, rva, value in ((row['slotRead'], 0x6D85FF8, 0), (row['md5Read'], 0x6D85FE8, md5)):
                keys(read, 'seq address valueHex knownMask', 'NULL_SLOT_KEYS')
                require(pointer(read['address']) == base + rva and raw(read['valueHex'], 8) == value.to_bytes(8, 'little') and read['knownMask'] == 'ffffffffffffffff' and enter <= integer(read['seq'], minimum=1) < leave, 'NULL_SLOT')
            return cls(source_identity, dict(identity), row['mode'], b'', b'', 0, md5, enter, leave, dict(envelope['main1160Wrapper']), None)
        keys(row, WARM_KEYS, 'OBSERVED_WARM_KEYS')
        keys(row['branchWitness'], 'source', 'BRANCH_WITNESS_KEYS')
        require(row['branchWitness']['source'] == 'normal-warm-copy-path-v1', 'UNSUPPORTED_BRANCH_WITNESS')
        cb = row['callback']
        keys(cb, OP_KEYS + ' ffiSite destination bp', 'CALLBACK_KEYS')
        op = {k: cb[k] for k in OP_KEYS.split()}
        ce, cl = operation(op, identity, base + 0x1BFD960, 0x2DE572A)
        require(cb['ffiSite'] == 1260 and type(cb['ffiSite']) is int, 'CALLBACK_SITE')
        destination, bp = pointer(cb['destination']), pointer(cb['bp'])
        require(bp == pointer(cb['entryRSP']) - 0x118, 'CALLBACK_BP_RELATION')
        guards = row['guardReads']
        require(type(guards) is list and len(guards) == 3, 'GUARD_READ_COUNT')
        guard_seqs = []
        for index, read in enumerate(guards):
            keys(read, 'seq address valueHex knownMask consumedEaxU32', 'GUARD_READ_KEYS')
            value = int.from_bytes(raw(read['valueHex'], 4), 'little')
            require(pointer(read['address']) == base + 0x67519B0 and read['knownMask'] == 'ffffffff' and value & 1 and (read['consumedEaxU32'] is None if index < 2 else integer(read['consumedEaxU32'], 32) == value), 'GUARD_CONSUMPTION')
            guard_seqs.append(integer(read['seq'], minimum=1))
        require(guards[0]['valueHex'] == envelope['mainEntry']['providerPrecall']['guardHex'] and guard_seqs[0] == envelope['mainEntry']['seq'] < ce <= guard_seqs[1] < guard_seqs[2], 'GUARD_TIMING')
        acquire = operation(row['cacheLock'], identity, base + 0x67518F0, 0x1BFD99D)
        release = operation(row['release'], identity, base + 0x67518F0, 0x1BFF17C)
        le, ll = logger_result(row['loggerLookup'], identity, base)
        require(ce < guard_seqs[2] < acquire[0] < acquire[1] < row['loggerLookup']['pointerRead']['seq'] <= le < ll, 'PROVIDER_LOCK_ORDER')
        ft = row['filetime']
        from .primary_prefix_raw_clock import keys as rawkeys, module
        rawkeys(ft, 'api identity iatRva iatTarget returnRva entryRSP arguments outputPointer width enterSeq leaveSeq normalReturn status afterHex definedAfterMask compareOnlySecondsHex', 'PROVIDER_FILETIME_KEYS')
        fe, fl = pair(ft)
        api = ft['identity']
        rawkeys(api, 'exportName sourceModule resolvedAddress resolvedModule', 'PROVIDER_FILETIME_IDENTITY')
        module(api['sourceModule'])
        resolved_base, resolved_size = module(api['resolvedModule'])
        target = pointer(api['resolvedAddress'])
        output = pointer(ft['outputPointer'])
        require(ft['api'] == 'FILETIME' and api['exportName'] == 'GetSystemTimeAsFileTime' and api['sourceModule']['name'].lower() == 'kernel32.dll' and resolved_base <= target < resolved_base + resolved_size and pointer(ft['iatTarget']) == target and ft['iatRva'] == 0x490FFB8 and ft['returnRva'] == 0x3E8ED56 and ft['width'] == 8 and ft['status'] is None and output == pointer(ft['entryRSP']) + 0x38 and ft['arguments'] == [ft['outputPointer']] and ft['definedAfterMask'] == 'ffffffffffffffff', 'PROVIDER_FILETIME_ABI')
        from .primary_sign import filetime_seconds
        from .primary_vm import signed
        now = filetime_seconds(int.from_bytes(raw(ft['afterHex'], 8), 'little'))
        require(int.from_bytes(raw(ft['compareOnlySecondsHex'], 8), 'little') == now, 'PROVIDER_SECONDS_WITNESS')
        value = row['value']
        keys(value, 'readSeq lengthSeq lengthU64 source adjacentSource', 'VALUE_KEYS')
        predicted = decode_string(value['source'], base + 0x67518B0)
        require(value['source'] == value['adjacentSource'] and predicted and pointer(value['lengthU64'], True) == len(predicted), 'VALUE_ADJACENT_CHANGED')
        ve, vl = integer(value['readSeq'], minimum=1), integer(value['lengthSeq'], minimum=1)
        stamp = row['timestamp']
        keys(stamp, 'seq address rawHex consumedRcxHex adjacentRawHex', 'TIMESTAMP_KEYS')
        timestamp = int.from_bytes(raw(stamp['rawHex'], 8), 'little')
        ts = integer(stamp['seq'], minimum=1)
        require(pointer(stamp['address']) == base + 0x67518E8 and stamp['rawHex'] == stamp['consumedRcxHex'] == stamp['adjacentRawHex'], 'TIMESTAMP_CHANGED')
        ttl = row['ttl']
        previous = ts
        if timestamp == 0:
            require(ttl is None, 'ZERO_TIMESTAMP_TTL')
        else:
            keys(ttl, 'beforeSeq afterSeq address beforeHex afterHex compareOnlyDifferenceHex compareOnlyDifferenceAfterHex', 'TTL_KEYS')
            before, after = integer(ttl['beforeSeq'], minimum=1), integer(ttl['afterSeq'], minimum=1)
            delta = (now - timestamp) & ((1 << 64) - 1)
            threshold = int.from_bytes(raw(ttl['beforeHex'], 8), 'little', signed=True)
            require(pointer(ttl['address']) == base + 0x6751908 and ttl['beforeHex'] == ttl['afterHex'] and int.from_bytes(raw(ttl['compareOnlyDifferenceHex'], 8), 'little') == delta and ttl['compareOnlyDifferenceAfterHex'] == ttl['compareOnlyDifferenceHex'] and signed(delta, 64) <= threshold and ts < before < after, 'UNSUPPORTED_CACHE_MISS_OR_TTL_CHANGED')
            previous = after
        token = row['token']
        keys(token, 'readSeq source adjacentSource', 'TOKEN_KEYS')
        token_bytes = decode_string(token['source'], base + 0x67518C8)
        require(token['source'] == token['adjacentSource'], 'TOKEN_ADJACENT_CHANGED')
        copies = row['copies']
        require(type(copies) is list and len(copies) == 2, 'COPY_COUNT')
        require(ll < fe < fl <= ve < vl < ts, 'PROVIDER_READ_ORDER')
        token_seq = integer(token['readSeq'], minimum=1)
        tokens = {cb['invocationToken'], row['cacheLock']['invocationToken'], row['release']['invocationToken'], row['loggerLookup']['getter']['invocationToken'], row['loggerLookup']['acquire']['invocationToken'], row['loggerLookup']['release']['invocationToken']}
        for index, (copy, source, data, dest, ra) in enumerate(zip(copies, (value['source'], token['source']), (predicted, token_bytes), (bp - 0x10, bp + 8), (0x1BFF160, 0x1BFF170))):
            keys(copy, OP_KEYS + ' source destination initialHex compareOnlyDestination compareOnlyReturn', 'COPY_KEYS')
            span = operation({k: copy[k] for k in OP_KEYS.split()}, identity, dest, ra)
            if index == 1:
                require(previous < token_seq == span[0], 'TOKEN_CONSUMPTION_TIMING')
            require(previous < span[0] < span[1] < release[0] and pointer(copy['destination']) == dest and copy['source'] == source and copy['initialHex'] == '00' * 24 and decode_string(copy['compareOnlyDestination'], dest) == data and pointer(copy['compareOnlyReturn']) == dest and copy['invocationToken'] not in tokens, 'COPY_SOURCE_OR_DESTINATION_CHANGED')
            tokens.add(copy['invocationToken'])
            previous = span[1]
        require(len(tokens) == 8, 'PROVIDER_INVOCATION_REUSED')
        normal = row['normalLeave']
        keys(normal, 'seq destination moveCompleted tokenDestroyed normalReturn', 'PROVIDER_NORMAL_LEAVE_KEYS')
        require(release[1] < integer(normal['seq'], minimum=1) <= cl and pointer(normal['destination']) == destination and normal['moveCompleted'] is True and normal['tokenDestroyed'] is True and normal['normalReturn'] is True, 'PROVIDER_ABNORMAL_LEAVE')
        reads = row['slotReads']
        require(type(reads) is list and len(reads) == 3, 'PROVIDER_SLOT_READ_COUNT')
        times = [slot(read, base, base + 0x1BFD960, md5) for read in reads]
        require(times[0] < ce < cl <= times[1] < times[2], 'PROVIDER_SLOT_READ_ORDER')
        return cls(source_identity, dict(identity), row['mode'], predicted, token_bytes, timestamp, md5, times[0], times[-1], dict(envelope['main1160Wrapper']), row)


class _ObservedProviderBinding:
    def __init__(self, runtime, inputs, retired=None):
        from .primary_sign import PrimaryRuntime
        from .primary_prefix_raw_clock import _MainPrefixRawClockBinding
        require(type(runtime) is PrimaryRuntime and type(inputs) is PrefixObservedProviderInputs and not inputs._claimed and retired is None and runtime._main_generation == 0 and runtime._active_main is None and runtime.__dict__.get('_prefix_provider_binding') is None, 'OBSERVED_PROVIDER_BIND_ONCE')
        clock, raw_binding = runtime._main_clock_binding, runtime._host129_api_binding
        require(type(clock) is _MainPrefixRawClockBinding and clock._rows[0].source_identity == inputs.source_identity and raw_binding.source.observed_counter_inputs.source_identity == inputs.source_identity and runtime._main_environment_binding.identity.source_identity == inputs.source_identity, 'OBSERVED_PROVIDER_LINEAGE')
        require(clock._rows[0].events[0].service.leave_seq < inputs.enter_seq < inputs.leave_seq, 'OBSERVED_PROVIDER_SEQUENCE')
        self.runtime, self.inputs, self.clock, self.raw = runtime, inputs, clock, raw_binding
        self.thread = get_ident()
        self.active = self.closed = self.finished = False
        self.calls = 0
        self.regions, self.temporaries = {}, set()
        self.cursor = 0xF000000000000000
        self.lifecycle = []
        runtime.memory.store(runtime.image_base + 0x6D85FF8, 0 if inputs.mode == 'NULL' else runtime.image_base + 0x1BFD960, 8, source='observed_provider.slot')
        require(runtime.memory.load(runtime.image_base + 0x6D85FE8, 8) == inputs.md5_pointer, 'OBSERVED_MD5_EFFECTIVE_SLOT')
        object.__setattr__(inputs, '_claimed', True)
        runtime._prefix_provider_binding = self

    def preflight(self, arguments):
        require(not self.closed and not self.finished and get_ident() == self.thread and self.inputs.source_identity.main_arguments == arguments and self.runtime.__dict__.get('_prefix_provider_binding') is self, 'OBSERVED_PROVIDER_PREFLIGHT')

    def live(self):
        from .primary_main_prefix_stop import _input_owner
        owner = _input_owner(self.runtime)
        require(owner is not None and owner.provider is self and self.runtime._main_clock_binding is self.clock and self.runtime._host129_api_binding is self.raw and not self.closed and get_ident() == self.thread, 'OBSERVED_PROVIDER_OWNER')
        return owner

    @contextmanager
    def scope(self, vm, cells, argument_types):
        owner = self.live()
        require(not self.active and self.calls == 0 and owner.vm is vm and vm.pc == 1267 and vm.block == 18 and cells == (299,) and argument_types == vm.program.type(127).parameters[3:] and vm.host_calls[-1] == (1260, self.runtime.image_base + 0x2DE5687, (299,), 127), 'OBSERVED_PROVIDER_CALLSITE')
        wrapper = self.inputs.wrapper
        timer = vm.cells.value(102)
        require(timer == pointer(wrapper['timerAddress']) and (vm.cells.value(279) & 255) == wrapper['flagU8'] and self.runtime.memory.read(timer, 8) == raw(wrapper['timerAfterHex'], 8) and int.from_bytes(raw(wrapper['timerAfterHex'], 8), 'little') == self.clock.predicted_value and wrapper['compareOnlyOuterReturnU32'] == 0, 'MAIN1160_WRAPPER_RESULT')
        self.active = True
        try:
            yield
            require(not self.regions and not self.temporaries, 'OBSERVED_PROVIDER_COPY_LEAK')
            self.calls += 1
        finally:
            self.active = False

    def temporary(self, size):
        self.live()
        require(self.active and size == 24, 'OBSERVED_PROVIDER_TEMPORARY')
        address = self._address(size)
        self.temporaries.add(address)
        return size, address, None

    def _address(self, size):
        from .local113_episode_validation import overlap
        address = self.cursor
        self.cursor += (size + 0xFFF) & ~0xFFF
        require(self.cursor < 1 << 64 and not any(overlap(address, size, r.address, len(r.data)) for r in self.runtime.memory._regions), 'MODEL_PRIVATE_ALLOCATOR_ALIAS')
        plan = self.runtime._local113_frame_plan
        require(not any(overlap(address, size, start, width) for start, width in plan.reserved()), 'MODEL_PRIVATE_FRAME_ALIAS')
        return address

    def allocate(self, size, zero=False):
        require(self.active and type(size) is int and 0 < size <= (1 << 20) + 32, 'MODEL_PRIVATE_ALLOCATION')
        address = self._address(size)
        self.runtime.memory.map(address, bytearray(size), name='model-private provider copy', initialized=zero)
        self.regions[address] = size
        self.lifecycle.append('allocate')
        return address

    def free(self, address):
        require(self.active and address in self.regions, 'MODEL_PRIVATE_FREE')
        size = self.regions.pop(address)
        self.runtime.memory.forget(address, size, source='model_private_provider.release')
        self.runtime.memory.unmap(address)
        self.lifecycle.append('free')

    def retire_temporary(self, address):
        require(address in self.temporaries, 'MODEL_PRIVATE_TEMPORARY_OWNER')
        self.temporaries.remove(address)

    def return_string(self, destination):
        from .primary_adapter import string_view, write_string
        self.live()
        require(self.active and self.inputs.mode == 'observed-warm-hit-v1' and destination in self.temporaries, 'OBSERVED_PROVIDER_RETURN')
        token_object = self._address(24)
        self.runtime.memory.map(token_object, bytearray(24), name='model-private token temporary', initialized=True)
        try:
            write_string(self.runtime.memory, destination, self.inputs.value, self.allocate)
            self.lifecycle.append('value_copy')
            write_string(self.runtime.memory, token_object, self.inputs.token, self.allocate)
            self.lifecycle.append('token_copy')
            if self.runtime.memory.load(token_object, 1) & 1:
                self.free(string_view(self.runtime.memory, token_object)[0])
            self.lifecycle.append('token_destroy')
        finally:
            self.runtime.memory.forget(token_object, 24, source='model_private_provider.token_lifetime')
            self.runtime.memory.unmap(token_object)
        return destination

    def complete_prefix9563(self, vm, witness):
        from .primary_main_prefix_stop import _require_witness
        _require_witness(self.runtime, vm, witness)
        self.live()
        require(self.calls == 1 and not self.active and not self.regions and not self.temporaries, 'OBSERVED_PROVIDER_INCOMPLETE')
        self.finished = True

    def close(self):
        require(get_ident() == self.thread and not self.active, 'OBSERVED_PROVIDER_CLOSE_OWNER')
        for address in tuple(self.regions):
            self.runtime.memory.forget(address, self.regions.pop(address), source='model_private_provider.failure_release')
            self.runtime.memory.unmap(address)
        for address in tuple(self.temporaries):
            if any(r.address == address for r in self.runtime.memory._regions):
                self.runtime.memory.forget(address, 24, source='model_private_provider.failure_temporary')
                self.runtime.memory.unmap(address)
            self.temporaries.remove(address)
        self.closed = True


def bind_observed_prefix_provider_inputs(runtime, inputs, *, retired=None):
    return _ObservedProviderBinding(runtime, inputs, retired)
