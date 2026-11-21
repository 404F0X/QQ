from .local113_episode_inputs import Local113Episode, _validate_cleanup
from .local113_episode_projection import project
from .local113_episode_validation import integer, keys, overlap, pointer, raw, require, sanitized
from .primary_host129_inputs import Host129CounterReads
from .primary_host129_api_inputs import Host129RawAPIInputs
from .primary_prefix_observed_provider import bind_observed_prefix_provider_inputs
from .primary_windows_host129_source import ObservedCounterGroup, ObservedCounterInputs, WindowsHost129Source


class _RAMBackend:
    precise_available = False

    def __init__(self, episode):
        self.rows = episode.inputs['conditionalIdentities']
        self.index = 0
        self.closed = False

    def request(self, name, output, count):
        require(False, 'UNOBSERVED_RAW_API')

    def resolve(self, name, arguments):
        require(not self.closed and self.rows and self.index < 2, 'MISSING_CONDITIONAL_IDENTITY')
        row = self.rows[0]
        if self.index == 0:
            require(name == 'GetModuleHandleA' and arguments == (raw(row['moduleNameHex']),), 'CONDITIONAL_MODULE_INPUT')
            result = pointer(row['moduleHandle'], True)
            self.index = 1 if result else 2
        else:
            require(name == 'GetProcAddress' and arguments == (pointer(row['moduleHandle']), raw(row['exportNameHex'])), 'CONDITIONAL_EXPORT_INPUT')
            result = pointer(row['exportPointer'], True)
            self.index = 2
        return result

    def close(self):
        self.closed = True


class _HostTape:
    def __init__(self, episode, adapter):
        self.groups = []
        self.adapter = adapter
        self.effects = adapter.APIEffects()
        self.active = None
        self.row_index = 0
        self.used = []
        state = episode.clock.events[0].service.after
        previous = episode.provider.leave_seq
        call_ids = set()
        for group in episode.inputs['hostGroups']:
            services = group['services']
            require(type(services) is list and len(services) in (2, 4), 'HOST_RAW_SERVICE_COUNT')
            parsed = tuple(adapter.service_row(row, index, episode.source_identity.image_base) for index, row in enumerate(services))
            for service in parsed:
                require(previous < service.enter_seq < service.leave_seq and service.enter_seq > group['enterSeq'] and service.leave_seq < group['leaveSeq'] and service.before.guard == state.guard and service.before.frequency == state.frequency and service.call_id not in call_ids, 'HOST_SHARED_CLOCK_TIMELINE')
                call_ids.add(service.call_id)
                previous, state = service.leave_seq, service.after
            self.groups.append(parsed)
        self.episode = episode

    def current_state(self, runtime):
        return self.adapter.ClockState(runtime.memory.read(runtime.image_base + 0x6D88CD8, 1), runtime.memory.read(runtime.image_base + 0x6D88CD0, 8))

    def start(self, source, index):
        require(self.active is None and source._observed_index < len(self.groups) and index < len(self.groups[source._observed_index]), 'HOST_RAW_SERVICE_EXHAUSTED')
        self.active = self.groups[source._observed_index][index]
        require(self.current_state(source.runtime) == self.active.before, 'HOST_RAW_STATE_BEFORE')
        self.row_index = 0

    def write(self, runtime, name, destination):
        require(self.active is not None and self.row_index < len(self.active.rows), 'HOST_RAW_API_EXHAUSTED')
        row = self.active.rows[self.row_index]
        require(row.name == name, 'HOST_RAW_API_ORDER')
        result = self.effects.write(runtime.memory, row, destination)
        self.row_index += 1
        return result

    def bcrypt(self):
        require(self.active is not None and self.row_index < len(self.active.rows), 'HOST_RAW_ENTROPY_EXHAUSTED')
        row = self.active.rows[self.row_index]
        result = self.effects.bcrypt(row)
        self.row_index += 1
        return result

    def temporary(self):
        require(self.active is not None and self.row_index < len(self.active.rows), 'HOST_RAW_TEMPORARY')
        row = self.active.rows[self.row_index]
        require(row.api in ('QPC', 'FILETIME'), 'HOST_RAW_TEMPORARY_API')
        return 8, row.output, None

    def finish(self, source):
        require(self.active is not None and self.row_index == len(self.active.rows) and self.current_state(source.runtime) == self.active.after, 'HOST_RAW_SERVICE_INCOMPLETE')
        self.used.append(self.active)
        self.active = None

    def complete(self):
        require(self.active is None and len(self.used) == sum(map(len, self.groups)), 'HOST_RAW_INPUTS_UNCONSUMED')


def _counter_inputs(episode):
    groups = []
    for row, source, frame in zip(episode.inputs['hostGroups'], episode.frame_plan.sources[1:], episode.frame_plan.rows[1:]):
        reads = row['counterReads']
        if reads is not None:
            keys(reads, 'schema siteWord consumedPC frameCells destinationCells sourceRvas values bytesRead', 'HOST_COUNTER_KEYS')
            require(reads['schema'] == 'host129-selector-load-results-v1' and reads['siteWord'] == row['siteWord'] and reads['consumedPC'] == 392 and reads['frameCells'] == frame['cells'] and reads['destinationCells'] == [42, 46, 52, 63] and reads['sourceRvas'] == [0x64284D0, 0x6D86054, 0x6D86054, 0x64284D0] and reads['bytesRead'] == 16 and type(reads['values']) is list and len(reads['values']) == 4, 'HOST_COUNTER_BINDING')
            reads = Host129CounterReads(*(integer(value, 32) for value in reads['values']))
        groups.append(ObservedCounterGroup(row['siteWord'], source, reads))
    return ObservedCounterInputs(episode.source_identity, episode.capture_identity, episode.frame_plan.sources[0], tuple(groups))


def _install_abi(memory, abi, reserved):
    targets = tuple((address, data, True) for address, data in abi.inputs) + ((abi.output_pointer, bytes(128), False), (abi.output_length_pointer, bytes(4), False))
    existing = tuple((region.address, len(region.data)) for region in memory._regions) + reserved
    for address, data, _ in targets:
        require(not any(overlap(address, len(data), start, size) for start, size in existing), 'ABI_PRIVATE_ALIAS')
    for address, data, known in targets:
        memory.map(address, bytearray(data), name='local113 observed ABI buffer', initialized=known)


def _calculate(episode, *, model_loader, max_steps):
    require(type(episode) is Local113Episode and not episode._claimed and type(max_steps) is int and max_steps > 0 and model_loader.active, 'EPISODE_SINGLE_USE')
    episode.verify_sealed()
    episode._claimed = True
    helper, adapter = model_loader.source('helper'), model_loader.source('raw')
    wire, identity = episode.inputs, episode.inputs['identity']
    arguments = helper.arguments_from_wire(wire['mainEntry']['actualArguments12'])
    abi = helper.plan_buffers(arguments, {name: raw(wire['mainEntry']['inputs'][name]['hex']) for name in ('a', 'b', 'command', 'd')})
    metadata = dict(mainEpoch=identity['mainEpoch'], thread=identity['thread'], readerInvocation=identity['readerInvocation'], processCreationIdentity=identity['processCreationIdentity'], moduleLoadGeneration=identity['moduleGeneration'], imageBase=episode.source_identity.image_base)
    warm = helper.build_warm_inputs(wire['warmContainer'], identity=episode.source_identity, metadata=metadata)
    envwire = dict(wire)
    envwire['entryRSP'] = wire['mainEntry']['entryRSP']
    envwire['identity'] = dict(identity, context=episode.frame_plan.rows[0]['context'], evaluatorBP=episode.frame_plan.rows[0]['evaluatorBP'])
    effective = helper.build_effective_environment(envwire, identity=episode.source_identity, metadata=metadata)
    require(effective.cursor_function is None, 'UNOBSERVED_CURSOR_API_UNSUPPORTED')
    from .primary_signer import PrimarySigner, SigningEnvironment, SourceAddressSpace
    backend = _RAMBackend(episode)
    counter = _counter_inputs(episode)
    tape = _HostTape(episode, adapter)
    source = WindowsHost129Source(backend=backend, observed_counter_inputs=counter)
    source._episode_tape = tape
    def unavailable(*args, **kwargs):
        require(False, 'UNOBSERVED_ENVIRONMENT_SERVICE')
    environment = SigningEnvironment(cursor=None, process_path=b'local113-model.exe', module_path=b'local113-model.node', stack_modules=(), loaded_modules=(), filetime=unavailable, qpc=unavailable, random_bytes=unavailable, raw_core_observations=None, warm_core_container_inputs=warm, main_environment_inputs=effective)
    addresses = SourceAddressSpace(initial_stack=None, public_entry_rsp=pointer(identity['mainEntryRSP']), singleton_address=warm.identity.container_address)
    def observed_frame(name):
        require(not addresses.failed and addresses._programs and addresses._programs[-1]['name'] == name and addresses._programs[-1]['frame'] is None, 'FRAME_PROGRAM_SCOPE')
        frame = episode.frame_plan.next_frame(name)
        addresses._programs[-1]['frame'] = frame
        return frame
    addresses.frame = observed_frame
    signer = None
    try:
        signer = PrimarySigner(environment, initial_stack=None, addresses=addresses, image_base=episode.source_identity.image_base, main_clock_inputs=(episode.clock,))
        runtime = signer.runtime
        for read in wire['mainEntry']['sharedControlReads']:
            runtime.memory.write(pointer(read['address']), raw(read['hex'], 4), source='local113.true_entry.raw_shared_control')
        episode.frame_plan.bind(runtime)
        environment.raw_core_observations = source
        runtime.raw_core_observations = source
        source.bind(runtime)
        runtime.attach_host129_raw_api_inputs(Host129RawAPIInputs(source))
        _install_abi(runtime.memory, abi, episode.frame_plan.reserved())
        binding = bind_observed_prefix_provider_inputs(runtime, episode.provider)
        result = runtime.execute_main_prefix9563(arguments, max_steps=max_steps)
        tape.complete()
        require(episode.frame_plan.finished and binding.finished and binding.closed and not binding.regions and not binding.temporaries and runtime.vms[0].pc == 9564 and not runtime.vms[0].halted and all(vm.pc != 9571 for vm in runtime.vms), 'PREFIX_MODEL_COMPLETION')
        require((not backend.rows and backend.index == 0) or (backend.rows and backend.index == 2), 'CONDITIONAL_IDENTITY_UNCONSUMED')
        return result
    finally:
        source.close()
        episode.frame_plan.close()
        if signer is not None:
            runtime = signer.runtime
            for region in tuple(runtime.memory._regions):
                if not region.data.readonly:
                    region.data[:] = bytes(len(region.data))
            runtime.memory._regions.clear()
            runtime.memory.writes.clear()
            runtime.memory._write_extents.clear()
            runtime.vms.clear()
            runtime.events.clear()
            runtime.allocations.clear()
            runtime.locks.clear()


@sanitized('MODEL_EXECUTION_REJECTED')
def consume_local113_episode(episode, *, model_loader, max_steps):
    require(type(episode) is Local113Episode and not episode.diagnostic_only, 'STRICT_EPISODE_REQUIRED')
    _validate_cleanup(dict(sealedAt=9563, collectionClosed=True, dropped=0, cleanup=episode.cleanup), False)
    return project(episode, _calculate(episode, model_loader=model_loader, max_steps=max_steps), False)


@sanitized('MODEL_EXECUTION_REJECTED')
def diagnose_local113_episode(episode, *, model_loader, max_steps):
    require(type(episode) is Local113Episode, 'DIAGNOSTIC_EPISODE_REQUIRED')
    return project(episode, _calculate(episode, model_loader=model_loader, max_steps=max_steps), True)
