from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
import os
import sys
from threading import get_ident, get_native_id

from .errors import InputError
from .primary_consumed_mgf import SourceIdentity
from .primary_host129_inputs import Host129CounterReads
from .primary_host129_direct import HOST129_SHA256, MAIN_CALLS
from .primary_host129_api_inputs import Host129RawAPIInputs
from .primary_main_mix import MAIN_SHA256
from .primary_sign import PrimaryFrame, PrimaryRuntime, arena_reservation
from .primary_sign_lifecycle import _PublicDirectOwner, region_at
from .primary_vm import PrimaryVM
from .primary_windows_core_observations import WindowsCoreObservations
from .primary_singleton_history import CapturedFrameSource, RootCaptureIdentity


@dataclass(frozen=True, repr=False)
class ObservedCounterGroup:
    site_word: int
    host_epoch: CapturedFrameSource
    reads: Host129CounterReads | None
    _claimed: bool = field(default=False, init=False, compare=False)

    def __post_init__(self):
        if (type(self.site_word) is not int or self.site_word not in (2353, 5821) or
                type(self.host_epoch) is not CapturedFrameSource or self.host_epoch.frame.program != 'host129' or
                self.reads is not None and type(self.reads) is not Host129CounterReads):
            raise InputError('OBSERVED_COUNTER_GROUP')
        self.host_epoch.__post_init__()
        if self.reads is not None:
            self.reads.__post_init__()


@dataclass(frozen=True, repr=False)
class ObservedCounterInputs:
    source_identity: SourceIdentity
    capture_identity: RootCaptureIdentity
    main_frame_source: CapturedFrameSource
    groups: tuple[ObservedCounterGroup, ...]
    _claimed: bool = field(default=False, init=False, compare=False)

    def __post_init__(self):
        if (type(self.source_identity) is not SourceIdentity or
                type(self.capture_identity) is not RootCaptureIdentity or
                type(self.main_frame_source) is not CapturedFrameSource or
                self.main_frame_source.frame.program != 'main' or type(self.groups) is not tuple or
                not 1 <= len(self.groups) <= 2 or any(type(group) is not ObservedCounterGroup for group in self.groups)):
            raise InputError('OBSERVED_COUNTER_INPUTS')
        self.source_identity.__post_init__()
        self.capture_identity.__post_init__()
        self.main_frame_source.__post_init__()
        main, capture = self.main_frame_source, self.capture_identity
        if (self.source_identity.main_arguments[9] != 2 or
                capture.generation != self.source_identity.generation or main.native_root != capture.native_root or
                tuple(group.site_word for group in self.groups) not in ((5821,), (2353, 5821))):
            raise InputError('OBSERVED_COUNTER_MAIN_EPOCH')
        prior = main.invocation
        for group in self.groups:
            group.__post_init__()
            host = group.host_epoch
            if (host.parent != main.invocation or host.invocation <= prior or
                    (host.native_root, host.native_thread) != (main.native_root, main.native_thread)):
                raise InputError('OBSERVED_COUNTER_HOST_EPOCH')
            prior = host.invocation


class WindowsHost129Source:
    def __init__(self, *, backend=None, tap=None, observed_counter_inputs=None, delegate=None):
        if delegate is not None and (type(delegate) is not WindowsCoreObservations or
                backend is not None or tap is not None or observed_counter_inputs is not None or
                delegate._closed or delegate._owner != (os.getpid(), get_native_id()) or
                delegate.__dict__.get('_episode_tape') is not None):
            raise InputError('borrowed Host129 delegate requires its live normal source owner')
        if observed_counter_inputs is not None:
            if type(observed_counter_inputs) is not ObservedCounterInputs:
                raise InputError('OBSERVED_COUNTER_INPUTS')
            observed_counter_inputs.__post_init__()
            if observed_counter_inputs._claimed or any(group._claimed for group in observed_counter_inputs.groups):
                raise InputError('OBSERVED_COUNTER_REUSED')
        self._owns_delegate = delegate is None
        self.delegate = WindowsCoreObservations(backend=backend, tap=tap) if delegate is None else delegate
        self.observed_counter_inputs = observed_counter_inputs
        self._observed_index = 0
        self._observed_group = self._observed_frame = None
        self.runtime = self.thread = self.owner = self.main_owner = None
        self.main_vm = self.host_vm = self.service = None
        self.identity = os.getpid(), get_native_id()
        self.sites = []
        self.hosts = []
        self.services = []
        self.counters = []
        self.api_count = 0
        self.first_failed_predicate = None
        self.closed = self.completed = self.failed = False

    _predicates = {
        'one inactive original runtime required': 'BIND_RUNTIME',
        'live original runtime required': 'LIVE_RUNTIME',
        'canonical exclusive input binding required': 'EXCLUSIVE_BINDING',
        'competing binding': 'COMPETING_BINDING',
        'actual public owner required': 'PUBLIC_OWNER',
        'public epoch changed': 'PUBLIC_EPOCH',
        'Main generation changed': 'MAIN_GENERATION',
        'actual fixed Main VM required': 'MAIN_IDENTITY',
        'normal Main ABI required': 'MAIN_ABI',
        'Host129 source call required': 'HOST_CALL',
        'Main callsite required': 'MAIN_CALLSITE',
        'Main source ABI required': 'MAIN_SOURCE_ABI',
        'Host129 callsite order': 'CALLSITE_ORDER',
        'Host129 VM reused': 'VM_REUSED',
        'Host129 epoch changed': 'HOST_EPOCH',
        'nested or exhausted service': 'SERVICE_STATE',
        'actual ordered source service required': 'SERVICE_ABI',
        'service API completion required': 'SERVICE_COMPLETION',
        'live core delegate required': 'CORE_DELEGATE',
        'missing Host129 service hook': 'MISSING_HOOK',
        'clock API required': 'CLOCK_API',
        'one actual entropy API required': 'ENTROPY_API',
        'clock temporary required': 'TEMPORARY_REQUEST',
        'actual guest temporary allocator required': 'TEMPORARY_CALLER',
        'temporary tuple required': 'TEMPORARY_TUPLE',
        'eight-byte guest temporary required': 'TEMPORARY_VALUE',
        'private temporary overlaps live guest memory': 'TEMPORARY_OVERLAP',
        'actual counter branch required': 'COUNTER_BRANCH',
        'counter source instruction required': 'COUNTER_INSTRUCTION',
        'Host129 completion required': 'HOST_COMPLETION',
        'complete Main callsite domain required': 'MAIN_COMPLETION',
        'creating process and native thread required': 'CLOSE_THREAD',
    }

    def _require(self, condition, message, predicate=None):
        if condition:
            return
        if self.first_failed_predicate is None:
            self.first_failed_predicate = predicate or self._predicates.get(message, 'SOURCE_CONTRACT')
        error = InputError('Windows Host129 source: ' + message)
        error.firstFailedPredicate = self.first_failed_predicate
        raise error

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    def _normal_live_inputs(self):
        return (self.__dict__.get('_episode_tape') is None and
                self.delegate.__dict__.get('_episode_tape') is None)

    def bind(self, runtime):
        self._require(self.identity == (os.getpid(), get_native_id()) and not self.closed and
            self.runtime is None and type(runtime) is PrimaryRuntime and
            runtime.raw_core_observations is self and runtime._active_main is None and
            not runtime._program_calls and not runtime._execute_depth, 'one inactive original runtime required')
        inputs = self.observed_counter_inputs
        if inputs is not None:
            inputs.__post_init__()
            self._require(not inputs._claimed and not any(group._claimed for group in inputs.groups),
                'fresh observed counter inputs required', 'OBSERVED_COUNTER_REUSED')
            identity = inputs.source_identity
            effective = runtime._main_environment_binding
            self._require(identity.image_base == runtime.image_base and
                identity.generation == runtime._main_generation + 1 and effective is not None and
                inputs.main_frame_source.native_thread == effective.identity.native_thread_id and
                (identity.generation != effective.identity.source_identity.generation or
                 identity == effective.identity.source_identity),
                'matching observed counter source required', 'OBSERVED_COUNTER_SOURCE')
        if self._owns_delegate:
            self.delegate.bind(runtime)
        else:
            self._require(not self.delegate._closed and self.delegate._runtime is runtime and
                self.delegate._owner == self.identity and self.delegate._caller is not None,
                'live core delegate required')
            self._require(self._normal_live_inputs(), 'untaped normal live source required', 'TAPE_DOMAIN')
        self.runtime, self.thread = runtime, get_ident()
        if inputs is not None:
            object.__setattr__(inputs, '_claimed', True)
            for group in inputs.groups:
                object.__setattr__(group, '_claimed', True)

    def _live(self, runtime):
        self._require(not self.closed and not self.failed and not self.completed and runtime is self.runtime and
            self.thread == get_ident() and self.identity == (os.getpid(), get_native_id()) and
            runtime.primary_core and not runtime._active_failed and
            runtime.raw_core_observations is self and runtime._execute_thread == self.thread and
            getattr(runtime, '_consumed_mgf', None) is None, 'live original runtime required')
        binding = runtime._host129_api_binding
        self._require(type(binding) is Host129RawAPIInputs and binding.source is self and binding.runtime is runtime and
            binding.bound and not binding.closed, 'canonical exclusive input binding required')
        self._require(all(getattr(runtime, key) is None for key in ('_host129_raw_binding',
            '_host129_source_clock_binding', '_host129_multicall_binding', '_host129_counter_binding',
            '_host129_clock_service_binding', '_host129_entropy_service_binding')), 'competing binding')
        owner = runtime.__dict__.get('_primary_public_direct_owner')
        from .primary_main_prefix_stop import _input_owner
        prefix = _input_owner(runtime)
        if prefix is not None:
            owner = prefix
        self._require(prefix is not None or type(owner) is _PublicDirectOwner and owner.runtime is runtime and
            owner.thread == self.thread and owner.valid(), 'actual public owner required')
        if self.owner is None:
            self.owner = owner
        self._require(self.owner is owner, 'public epoch changed')
        if self.main_owner is not None:
            self._require(runtime._active_main is self.main_owner and
                self.main_owner.get('generation') == runtime._main_generation and
                self.main_owner.get('thread') == self.thread and self.main_owner.get('vm') is self.main_vm,
                'Main generation changed')

    def enter_main(self, runtime, vm):
        self._live(runtime)
        owner = runtime._active_main
        self._require(self.main_vm is None and type(vm) is PrimaryVM and type(owner) is dict and
            owner.get('vm') is vm and owner.get('thread') == self.thread and
            owner.get('generation') == runtime._main_generation and vm.runtime is runtime and
            vm.memory is runtime.memory and vm.image_base == runtime.image_base and
            sha256(vm.program.raw).hexdigest() == MAIN_SHA256 and any(item is vm for item in runtime.vms),
            'actual fixed Main VM required')
        calls = runtime._program_calls
        self._require(len(calls) == 1 and calls[0]['name'] == 'main' and calls[0]['hosts'] is None and
            len(calls[0]['arguments']) == 12 and calls[0]['arguments'][0] == 4, 'normal Main ABI required')
        inputs = self.observed_counter_inputs
        if inputs is not None:
            identity = inputs.source_identity
            self._require(identity.main_arguments == calls[0]['arguments'] and
                identity.image_base == runtime.image_base and identity.generation == owner['generation'],
                'matching observed counter Main required', 'OBSERVED_COUNTER_MAIN')
            clocks = runtime._main_clock_binding
            self._require(clocks is None or getattr(clocks, '_row', None) is not None and
                clocks._row.source_identity == identity and
                clocks._row.native_thread_id == inputs.main_frame_source.native_thread,
                'matching observed counter Main identity required', 'OBSERVED_COUNTER_MAIN_IDENTITY')
        plan = runtime.__dict__.get('_local113_frame_plan')
        if plan is not None:
            plan.match_vm('main', inputs.main_frame_source.frame, vm)
        self.main_owner, self.main_vm = owner, vm
        self.main_call = calls[0]

    def _frame(self, runtime, vm):
        caller = sys._getframe(1)
        while caller is not None:
            if (caller.f_code is PrimaryRuntime._execute_program.__code__ and
                    caller.f_locals.get('self') is runtime and caller.f_locals.get('vm') is vm):
                break
            caller = caller.f_back
        self._require(caller is not None, 'actual runtime frame required', 'HOST_FRAME_CALLER')
        values = caller.f_locals
        frame, program = values.get('frame'), values.get('program')
        self._require(type(frame) is PrimaryFrame and frame.program == 'host129' and
            values.get('name') == 'host129' and values.get('arguments') == () and values.get('hosts') is None and
            program is vm.program, 'actual runtime frame required', 'HOST_FRAME_BINDING')
        reservation = arena_reservation(program)
        self._require(values.get('reservation') == reservation and type(frame.arena_size) is int and
            frame.arena_size >= reservation and vm.arena_size == frame.arena_size and
            vm.arena_address == frame.arena and vm.cells.address == frame.cells,
            'actual runtime frame required', 'HOST_FRAME_CAPACITY')
        arena, cells = region_at(runtime.memory, frame.arena), region_at(runtime.memory, frame.cells)
        owned = values.get('owned')
        self._require(type(owned) is list and len(owned) == 2 and
            owned[0][0] == frame.cells and owned[0][1] is cells and
            owned[1][0] == frame.arena and owned[1][1] is arena and
            arena is not None and cells is not None and
            arena.address == frame.arena and cells.address == frame.cells and
            len(arena.data) == frame.arena_size and len(cells.data) == (program.cell_count + 1) * 24 and
            arena.name == 'host129 native private arena' and cells.name == 'host129 cells',
            'actual runtime frame required', 'HOST_FRAME_REGIONS')
        self._require(len(arena.initialized) == frame.arena_size and all(arena.initialized[:reservation]) and
            0 <= vm.arena_used <= reservation,
            'actual runtime frame required', 'HOST_FRAME_RESERVATION')
        return frame

    def _host(self, runtime, vm):
        self._live(runtime)
        self._require(self.main_vm is not None, 'actual fixed Host129 VM required', 'HOST_MAIN_VM')
        self._require(type(vm) is PrimaryVM, 'actual fixed Host129 VM required', 'HOST_EXACT_VM')
        self._require(vm.runtime is runtime, 'actual fixed Host129 VM required', 'HOST_RUNTIME')
        self._require(vm.memory is runtime.memory, 'actual fixed Host129 VM required', 'HOST_MEMORY')
        self._require(vm.image_base == runtime.image_base, 'actual fixed Host129 VM required', 'HOST_IMAGE')
        self._require(sha256(vm.program.raw).hexdigest() == HOST129_SHA256,
            'actual fixed Host129 VM required', 'HOST_PROGRAM')
        self._require(any(item is vm for item in runtime.vms), 'actual fixed Host129 VM required', 'HOST_HISTORY')
        frame = self._frame(runtime, vm)
        calls = runtime._program_calls
        self._require(len(calls) == 2 and calls[0] is self.main_call and not self.main_vm.halted and calls[0]['name'] == 'main' and calls[0]['hosts'] is None and
            calls[1] == dict(name='host129', arguments=(), hosts=None) and
            getattr(vm, '_primary_host129_reader_arguments', None) == (), 'Host129 source call required')
        main = self.main_vm
        site = MAIN_CALLS.get(main.pc)
        self._require(site is not None, 'Main callsite required')
        word, destination = site
        self._require(main.program.words[word:main.pc] == (0x014A3DB9, 129, 0, destination, 454, 0) and
            main.cells.value(454) == runtime.image_base + 0x2DE577E and main.host_calls and
            main.host_calls[-1] == (word, runtime.image_base + 0x2DE577E, (), 129), 'Main source ABI required')
        if self.host_vm is None:
            prefix = tuple(self.sites) + (word,)
            self._require(any(domain[:len(prefix)] == prefix for domain in
                ((2353, 5821, 62638), (5821, 62638))), 'Host129 callsite order')
            self._require(not any(prior is vm for prior in self.hosts), 'Host129 VM reused')
            if self.observed_counter_inputs is not None:
                groups = self.observed_counter_inputs.groups
                self._require(self._observed_group is None and self._observed_index < len(groups),
                    'one observed group per Host129 required', 'OBSERVED_COUNTER_GROUP_COUNT')
                group = groups[self._observed_index]
                self._require(group.site_word == word,
                    'matching observed Host129 site required', 'OBSERVED_COUNTER_SITE')
                self._require(group.host_epoch.frame is frame and vm.cells.address == frame.cells and vm.arena_address == frame.arena and vm.arena_size == frame.arena_size, 'observed actual Host129 frame mismatch', 'OBSERVED_ACTUAL_FRAME')
                plan = runtime.__dict__.get('_local113_frame_plan')
                if plan is not None:
                    plan.match_vm('host129', frame, vm)
                self._observed_group, self._observed_frame = group, frame
            self.hosts.append(vm)
            self.host_vm = vm
            self.host_call = calls[-1]
            self.sites.append(word)
        self._require(self.host_vm is vm and calls[-1] is self.host_call, 'Host129 epoch changed')
        if self.observed_counter_inputs is not None:
            self._require(self._observed_group is self.observed_counter_inputs.groups[self._observed_index] and
                self._observed_group.site_word == word and self._observed_frame is frame,
                'matching observed Host129 frame required', 'OBSERVED_COUNTER_FRAME')

    @contextmanager
    def host129_service(self, runtime, vm, rva, cells, argument_types):
        try:
            self._host(runtime, vm)
            self._require(self.service is None and len(self.services) < 4, 'nested or exhausted service')
            index = len(self.services)
            word, pc, callee, signature, destination = (
                (15, 21, 5, 7, 4), (37, 43, 5, 7, 11),
                (102, 108, 23, 1, 22), (122, 128, 23, 1, 26))[index]
            expected = (0x2DE5A2F, 0x3592430) if index < 2 else (0x35924C4,)
            self._require(rva in expected and cells == () and argument_types in (None, ()) and vm.pc == pc and
                vm.cells.value(callee) == runtime.image_base + rva and vm.host_calls and
                vm.host_calls[-1] == (word, runtime.image_base + rva, (), signature) and
                getattr(vm, '_primary_host129_active_call', None) == (word, callee, (), signature, destination) and
                vm.program.words[word:pc] == (0x014A3DB9, signature, 0, destination, callee, 0),
                'actual ordered source service required')
            self.service, self.api_count = index, 0
            tape = self.__dict__.get('_episode_tape')
            if tape is not None:
                tape.start(self, index)
            yield
            if tape is not None:
                tape.finish(self)
            self._host(runtime, vm)
            self._require(self.api_count > 0 and (index < 2 or self.api_count == 1), 'service API completion required')
            self.services.append(word)
            self.service = None
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup:
                error.host129_cleanup_errors = getattr(error, 'host129_cleanup_errors', ()) + (cleanup,)
                error.add_note('Windows Host129 cleanup failed: ' + type(cleanup).__name__)
            raise

    def write_to(self, runtime, name, destination, *, purpose):
        if self.service is None:
            self._require(not self.closed and not self.failed and runtime is self.runtime and self.thread == get_ident(), 'live core delegate required')
            self._require(not any(row['name'] == 'host129' for row in runtime._program_calls), 'missing Host129 service hook')
            return self.delegate.write_to(runtime, name, destination, purpose=purpose)
        self._host(runtime, self.host_vm)
        self._require(self.service < 2 and name in ('QueryPerformanceFrequency', 'QueryPerformanceCounter',
            'GetSystemTimeAsFileTime'), 'clock API required')
        tape = self.__dict__.get('_episode_tape')
        result = (self.delegate.write_to(runtime, name, destination, purpose=purpose) if tape is None else tape.write(runtime, name, destination))
        self.api_count += 1
        return result

    def bcrypt_word(self):
        self._host(self.runtime, self.host_vm)
        self._require(self.service in (2, 3) and self.api_count == 0, 'one actual entropy API required')
        tape = self.__dict__.get('_episode_tape')
        result = self.delegate.bcrypt_word() if tape is None else tape.bcrypt()
        self.api_count += 1
        return result

    def temporary(self, runtime, size, fallback):
        self._host(runtime, self.host_vm)
        self._require(self.service in (0, 1) and size == 8 and callable(fallback), 'clock temporary required')
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not PrimaryRuntime._clock_local.__code__:
            frame = frame.f_back
        self._require(frame is not None and frame.f_locals.get('self') is runtime and
            frame.f_locals.get('fallback') is fallback, 'actual guest temporary allocator required')
        tape = self.__dict__.get('_episode_tape')
        result = fallback(size) if tape is None else tape.temporary()
        self._require(type(result) is tuple and len(result) == 3, 'temporary tuple required')
        count, address, initial = result
        self._require(count == 8 and type(address) is int and 0 < address <= (1 << 64) - 9 and
            (initial is None or type(initial) is bytes and len(initial) == 8), 'eight-byte guest temporary required')
        self._require(not any(address < region.address + len(region.data) and region.address < address + 8
            for region in runtime.memory._region_snapshot()), 'private temporary overlaps live guest memory')
        return result

    def read_counter(self, runtime, vm, pc, source, destination, width):
        self._host(runtime, vm)
        if self.observed_counter_inputs is not None:
            self._require(all(type(value) is int for value in (pc, source, destination, width)),
                'exact observed counter scalar protocol required', 'OBSERVED_COUNTER_SCALAR')
        roles = ((225, 41, 42, 0x64284D0), (249, 45, 46, 0x6D86054),
            (287, 45, 52, 0x6D86054), (362, 41, 63, 0x64284D0))
        self._require(self.service is None and len(self.services) == 4 and len(self.counters) < 4,
            'actual counter branch required')
        expected = roles[len(self.counters)]
        self._require((pc, source, destination) == expected[:3] and width == 4 and vm.pc == pc and
            vm.cells.value(source) == runtime.image_base + expected[3], 'counter source instruction required')
        if self.observed_counter_inputs is None:
            result = runtime.memory.load(vm.cells.value(source), width)
        else:
            reads = self._observed_group.reads
            self._require(type(reads) is Host129CounterReads,
                'four observed persistent loads required', 'OBSERVED_COUNTER_MISSING')
            result = (reads.d0, reads.c0, reads.c1, reads.d1)[len(self.counters)]
        self.counters.append(pc)
        return result

    def complete_host(self, runtime, vm):
        self._host(runtime, vm)
        self._require(vm.halted and self.service is None and len(self.services) in (2, 4) and
            len(self.counters) in (0, 4), 'Host129 completion required')
        if self.observed_counter_inputs is not None:
            expected = 0 if self._observed_group.reads is None else 4
            self._require(len(self.counters) == expected,
                'exact observed counter consumption required', 'OBSERVED_COUNTER_CONSUMPTION')
            self._observed_index += 1
            self._observed_group = self._observed_frame = None
        self.host_vm = None
        self.services.clear()
        self.counters.clear()

    def complete_main(self, runtime, vm):
        self._live(runtime)
        self._require(vm is self.main_vm and vm.halted and any(item is vm for item in runtime.vms) and
            len(runtime._program_calls) == 1 and runtime._program_calls[0] is self.main_call and
            self.host_vm is None and self.service is None and
            tuple(self.sites) in ((2353, 5821, 62638), (5821, 62638)), 'complete Main callsite domain required')
        self.completed = True

    def complete_prefix9563(self, runtime, vm, witness):
        from .primary_main_prefix_stop import _require_witness
        _require_witness(runtime, vm, witness)
        self._live(runtime)
        if self.observed_counter_inputs is not None:
            self._require(self._observed_index == len(self.observed_counter_inputs.groups) and
                self._observed_group is None and self._observed_frame is None,
                'complete observed counter groups required', 'OBSERVED_COUNTER_PREFIX_COMPLETION')
        self._require(vm is self.main_vm and not vm.halted and any(item is vm for item in runtime.vms) and
            len(runtime._program_calls) == 1 and runtime._program_calls[0] is self.main_call and
            self.host_vm is None and self.service is None and not self.services and not self.counters and
            tuple(self.sites) in ((2353, 5821), (5821,)) and len(self.hosts) == len(self.sites) and
            all(type(host) is PrimaryVM and host.runtime is runtime and host.memory is runtime.memory and
                host.halted and host.abort_reason is None and sha256(host.program.raw).hexdigest() == HOST129_SHA256
                for host in self.hosts) and not getattr(self, 'prefix_completed', False),
            'authenticated9563 prefix callsite completion required')
        self.prefix_completed = True

    def close(self):
        self._require(self.identity == (os.getpid(), get_native_id()), 'creating process and native thread required')
        if self.closed and (not self._owns_delegate or self.delegate._closed):
            return
        self.failed = True
        if self.observed_counter_inputs is not None:
            object.__setattr__(self.observed_counter_inputs, '_claimed', True)
            for group in self.observed_counter_inputs.groups:
                object.__setattr__(group, '_claimed', True)
        self.observed_counter_inputs = None
        self._observed_group = self._observed_frame = None
        if self._owns_delegate:
            self.delegate.close()
        self.closed = True
        self.service = self.host_vm = self.main_vm = self.main_owner = self.owner = None


