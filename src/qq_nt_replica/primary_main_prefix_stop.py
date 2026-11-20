from dataclasses import dataclass, field
from hashlib import sha256
import sys
from threading import get_ident

from .errors import InputError
from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM


_FACTORY = object()


@dataclass(frozen=True)
class MainPrefix9563Result:
    local113: bytes
    charged_steps: int
    scope: str = field(default='INDEPENDENT_LOCAL113_PREFIX9563', init=False)
    full_completed: bool = field(default=False, init=False)
    final96_qualified: bool = field(default=False, init=False)


class _PrefixComplete(BaseException):
    def __init__(self, witness):
        self.witness = witness


class _Witness:
    def __init__(self, owner, vm, value, factory):
        if factory is not _FACTORY:
            raise InputError('prefix witness factory required')
        self.owner, self.vm, self.program = owner, vm, vm.program
        self.value = value


class _PrefixOwner:
    def __init__(self, runtime, arguments, budget):
        self.runtime, self.arguments, self.budget = runtime, arguments, budget
        self.thread, self.generation = get_ident(), runtime._main_generation + 1
        self.state, self.witness = 'starting', None
        self.main_owner = self.vm = self.program = self.session = self.driver = None
        self.raw, self.clock = runtime._host129_api_binding, runtime._main_clock_binding
        self.provider = runtime.__dict__.get('_prefix_provider_binding')

    def valid(self):
        runtime = self.runtime
        session = runtime.__dict__.get('_primary_wait_session')
        from .primary_sign_lifecycle import _SignContinuation
        return (get_ident() == self.thread and runtime.__dict__.get('_main_prefix9563_owner') is self and
                not runtime._active_failed and self.state in ('running', 'captured', 'stopped', 'finalized') and
                runtime._execute_thread == self.thread and runtime._main_generation == self.generation and
                type(session) is _SignContinuation and session is self.session and session.executing and
                session.state == 'running' and runtime._active_main is self.main_owner and
                self.main_owner.get('vm') is self.vm and self.main_owner.get('thread') == self.thread and
                self.main_owner.get('generation') == self.generation and self.vm.runtime is runtime and
                self.vm.program is self.program and self.vm.memory is runtime.memory and
                runtime._host129_api_binding is self.raw and runtime._main_clock_binding is self.clock and
                runtime.__dict__.get('_prefix_provider_binding') is self.provider and
                self.driver.installed and not self.driver.closed and self.driver.runtime is runtime and
                runtime.__dict__.get('_run_primary_main') is self.driver.bindings['_run_primary_main'][2])

    def attach(self, vm):
        runtime = self.runtime
        if (self.state != 'starting' or type(vm) is not PrimaryVM or vm.pc != 1 or vm.arena_used or
                vm.halted or sha256(vm.program.raw).hexdigest() != MAIN_SHA256):
            raise InputError('prefix requires fresh fixed Main PC1')
        self.vm, self.program, self.main_owner = vm, vm.program, runtime._active_main
        self.session = runtime.__dict__.get('_primary_wait_session')
        self.state = 'running'
        if not self.valid():
            raise InputError('prefix Main owner identity changed')


def _current(runtime):
    owner = runtime.__dict__.get('_main_prefix9563_owner')
    return owner if type(owner) is _PrefixOwner else None


def _input_owner(runtime):
    owner = _current(runtime)
    if owner is None:
        return None
    if owner.state == 'starting':
        from .primary_sign_lifecycle import _SignContinuation
        session = runtime.__dict__.get('_primary_wait_session')
        if (get_ident() == owner.thread and runtime._main_generation == owner.generation and
                runtime._execute_thread == owner.thread and not runtime._active_failed and
                type(session) is _SignContinuation and session.executing and session.state == 'running' and
                runtime._host129_api_binding is owner.raw and runtime._main_clock_binding is owner.clock):
            return owner
        return None
    return owner if owner.valid() else None


def _capture(vm):
    owner = _current(vm.runtime)
    if owner is None:
        return
    from .primary_main_prefix import _prefix_one
    caller = sys._getframe(1)
    address = vm.cells.value(113)
    if (caller.f_code is not _prefix_one.__code__ or caller.f_locals.get('vm') is not vm or
            not owner.valid() or owner.state != 'running' or owner.vm is not vm or
            vm.pc != 9564 or vm.block != 209 or vm.halted or vm.abort_reason is not None or
            vm.cells.value(1198) != address or not vm.arena_address <= address <= vm.arena_address + vm.arena_size - 16 or
            not vm.memory.writes or vm.memory.writes[-1] != (address, bytes((vm.memory.load(vm.cells.pointer(1447), 1),)), 'high.store') or
            any(getattr(vm, name) is not None for name in ('pending_once9', 'pending_once10', 'pending_native', 'pending_variadic', 'pending_l26', 'private_iv_native_pending'))):
        raise InputError('authenticated9563 post-store boundary required')
    observation = getattr(vm.runtime, '_main_stage_observation', None)
    if observation is not None and observation.status == 'UNQUALIFIED':
        raise InputError('prefix stage observer became unqualified')
    owner.witness = _Witness(owner, vm, vm.memory.read(address, 16), _FACTORY)
    owner.state = 'captured'
    raise _PrefixComplete(owner.witness)


def _require_witness(runtime, vm, witness):
    owner = _current(runtime)
    if (type(witness) is not _Witness or owner is None or owner.witness is not witness or witness.owner is not owner or
            witness.vm is not vm or witness.program is not vm.program or not owner.valid() or
            owner.state not in ('stopped', 'finalized') or vm.pc != 9564 or vm.halted):
        raise InputError('same-owner authenticated9563 completion witness required')
    return owner


def _finalize(runtime, vm, witness):
    owner = _require_witness(runtime, vm, witness)
    if owner.state != 'stopped':
        raise InputError('prefix input finalization cannot repeat')
    owner.raw.complete_prefix9563(vm, witness)
    owner.clock.complete_prefix9563(vm, witness)
    owner.provider.complete_prefix9563(vm, witness)
    frames = runtime.__dict__.get('_local113_frame_plan')
    if frames is not None:
        frames.complete_prefix9563(runtime, vm, witness)
    owner.state = 'finalized'


def _preflight(runtime, arguments, max_steps):
    from .primary_sign import PrimaryRuntime
    from .primary_host129_api_inputs import Host129RawAPIInputs
    from .primary_prefix_raw_clock import _MainPrefixRawClockBinding, bind_clock_inputs
    from .primary_windows_host129_source import WindowsHost129Source
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(runtime) is not PrimaryRuntime or type(arguments) is not tuple or len(arguments) != 12 or
            any(type(v) is not int for v in arguments) or arguments[0] != 4 or arguments[9] != 2 or
            runtime.retain_frames or not runtime.primary_core or runtime.primary_backend != 'reference' or
            runtime._active_failed or runtime._active_main is not None or runtime._execute_depth or runtime._program_calls or
            runtime._execute_thread is not None or runtime.__dict__.get('_primary_wait_session') is not None or
            runtime.__dict__.get('_main_prefix9563_owner') is not None or runtime.__dict__.get('_primary_direct_scope') is not None or
            runtime.__dict__.get('_primary_public_direct_owner') is not None or
            any(getattr(runtime, name, None) is not None for name in ('_consumed_mgf', '_host129_raw_binding',
                '_host129_source_clock_binding', '_host129_multicall_binding', '_host129_counter_binding',
                '_host129_clock_service_binding', '_host129_entropy_service_binding'))):
        raise InputError('prefix requires inactive independent policy2 runtime without competing owners')
    observation = getattr(runtime, '_main_stage_observation', None)
    from .primary_main_stage_observation import MainStageObservation
    if observation is not None and (type(observation) is not MainStageObservation or observation.source_mode != 'live_windows'):
        raise InputError('prefix supports only adapted live_windows observation mode')
    raw, clock = runtime._host129_api_binding, runtime._main_clock_binding
    if (type(raw) is not Host129RawAPIInputs or not raw.owns_source or not raw.bound or raw.closed or raw.failed or
            raw.thread != get_ident() or type(raw.source) is not WindowsHost129Source or
            raw.source.runtime is not runtime or raw.source.closed or raw.source.completed or
            type(clock) is not _MainPrefixRawClockBinding or clock.closed or clock.finished or
            clock._thread != get_ident() or len(clock._rows) != 1 or clock._row_index or
            clock._rows[0].source_identity.main_arguments != arguments or
            clock._rows[0].source_identity.generation != runtime._main_generation + 1 or
            clock._rows[0].source_identity.image_base != runtime.image_base):
        raise InputError('prefix requires fresh adapted WindowsRawAPI and MainClock input bindings')
    from .primary_prefix_provider_inputs import _PrefixProviderBinding
    provider = runtime.__dict__.get('_prefix_provider_binding')
    from .primary_prefix_observed_provider import _ObservedProviderBinding
    if type(provider) not in (_PrefixProviderBinding, _ObservedProviderBinding):
        raise InputError('prefix requires explicit provider and MD5 typed state')
    provider.preflight(arguments)
    for name in ('_run_primary_main', '_run_primary_material', '_try_primary_host129_direct'):
        method = getattr(runtime, name)
        if getattr(method, '__func__', None) is not getattr(PrimaryRuntime, name) or getattr(method, '__self__', None) is not runtime:
            raise InputError('prefix rejects a competing body driver')


def execute_main_prefix9563(runtime, arguments, *, max_steps):
    _preflight(runtime, arguments, max_steps)
    from .primary_direct_main import MainDirectDriver
    from .primary_direct_scopes import Host129DirectScope
    from .primary_sign_lifecycle import start_execution
    owner = _PrefixOwner(runtime, arguments, max_steps)
    runtime._main_prefix9563_owner = owner
    driver, host = MainDirectDriver(runtime), Host129DirectScope(runtime)
    owner.driver = driver
    result = None
    try:
        driver.install()
        host.install()
        witness = start_execution(runtime, runtime._execute_continued('main', arguments, None))
        if (witness is not owner.witness or owner.state != 'finalized' or runtime._active_failed or
                runtime._active_main is not None or runtime._execute_depth or runtime._program_calls or
                runtime.__dict__.get('_primary_wait_session') is not None):
            raise InputError('prefix execution did not retire normally')
        result = MainPrefix9563Result(witness.value, driver.report['chargedRecordCount'])
    finally:
        primary, failures = sys.exception(), []
        for close in (owner.provider.close, owner.clock.close, owner.raw.close, host.close, driver.close):
            try:
                close()
            except BaseException as error:
                failures.append(error)
        owner.state = 'retired'
        if runtime.__dict__.get('_main_prefix9563_owner') is owner:
            runtime.__dict__.pop('_main_prefix9563_owner')
        else:
            failures.append(InputError('prefix owner changed during cleanup'))
        if failures:
            runtime._active_failed = True
            if primary is not None:
                for error in failures:
                    primary.add_note('prefix cleanup failed: ' + type(error).__name__)
            else:
                raise failures[0]
    runtime._main_prefix9563_retired = owner
    return result


def rebind_main_prefix9563_inputs(runtime, host129_inputs, main_clock_inputs, *, provider_inputs=None):
    from .primary_host129_api_inputs import Host129RawAPIInputs
    from .primary_prefix_raw_clock import _MainPrefixRawClockBinding, bind_clock_inputs
    from .primary_windows_host129_source import WindowsHost129Source
    retired = runtime.__dict__.get('_main_prefix9563_retired')
    if (type(retired) is not _PrefixOwner or retired.state != 'retired' or retired.runtime is not runtime or
            retired.raw is not runtime._host129_api_binding or retired.clock is not runtime._main_clock_binding or
            not retired.raw.closed or not retired.clock.closed or runtime._active_failed or runtime._active_main is not None or
            runtime._execute_depth or runtime._program_calls or runtime.__dict__.get('_primary_wait_session') is not None or
            runtime.__dict__.get('_main_prefix9563_owner') is not None or get_ident() != retired.thread or type(host129_inputs) is not Host129RawAPIInputs or
            not host129_inputs.owns_source or host129_inputs.bound or host129_inputs.closed or type(host129_inputs.source) is not WindowsHost129Source or
            host129_inputs.source.closed or host129_inputs.source.runtime is not None):
        raise InputError('fresh bindings require a normally retired prefix execution')
    clock = bind_clock_inputs(main_clock_inputs, runtime, _prefix_owner=retired)
    if type(clock) is not _MainPrefixRawClockBinding:
        raise InputError('fresh prefix requires primitive Main1160 raw clock inputs')
    if (len(clock._rows) != 1 or clock._rows[0].source_identity.generation != runtime._main_generation + 1 or
            clock._rows[0].source_identity.image_base != runtime.image_base):
        raise InputError('fresh clock binding requires next Main generation')
    try:
        runtime.raw_core_observations = host129_inputs.source
        host129_inputs.source.bind(runtime)
        host129_inputs.bind(runtime)
        from .primary_signer import PrimarySigner
        signer = runtime.__dict__.get('_primary_entry_owner')
        if type(signer) is PrimarySigner and signer.runtime is runtime and signer.environment.raw_core_observations is retired.raw.source:
            signer.environment.raw_core_observations = host129_inputs.source
        runtime._host129_api_binding, runtime._main_clock_binding = host129_inputs, clock
        from .primary_prefix_provider_inputs import bind_prefix_provider_inputs
        bind_prefix_provider_inputs(runtime, provider_inputs, retired=retired.provider)
        runtime.__dict__.pop('_main_prefix9563_retired')
    except BaseException as primary:
        runtime._active_failed = True
        for close in (clock.close, host129_inputs.close):
            try:
                close()
            except BaseException as error:
                primary.add_note('prefix fresh binding cleanup failed: ' + type(error).__name__)
        raise


def _close_failure_inputs(runtime, primary):
    for name in ('_host129_api_binding', '_host129_raw_binding', '_host129_source_clock_binding',
                 '_host129_multicall_binding', '_host129_counter_binding', '_host129_clock_service_binding',
                 '_host129_entropy_service_binding'):
        binding = getattr(runtime, name)
        if binding is not None:
            try:
                binding.close()
            except BaseException as error:
                primary.add_note('prefix input cleanup failed: ' + type(error).__name__)


def _cleanup_runtime(runtime, captured):
    primary, failures = sys.exception(), []
    try:
        runtime._program_calls.pop()
        for name in ('_host129_api_binding', '_host129_counter_binding', '_host129_clock_service_binding', '_host129_entropy_service_binding'):
            binding = getattr(runtime, name)
            if binding is not None:
                try:
                    binding.close()
                except BaseException as error:
                    failures.append(error)
    finally:
        for label, used, remaining in (('last_host2252_budget', 'consumed', 'remaining'),
                ('last_host2252_g_budget', 'g_consumed', 'g_remaining'),
                ('last_host2252_f_budget', 'f_consumed', 'f_remaining'),
                ('last_host2252_pair_m_budget', 'pair_m_consumed', 'pair_m_remaining')):
            setattr(runtime, label, dict(consumed=captured[used], remaining=captured[remaining]))
        if runtime._active_main is captured:
            runtime._active_main = None
        runtime._execute_depth -= 1
        if not runtime._execute_depth:
            runtime._execute_thread = None
    if failures:
        runtime._active_failed = True
        if primary is not None:
            for error in failures:
                primary.add_note('prefix runtime cleanup failed: ' + type(error).__name__)
        else:
            raise failures[0]

