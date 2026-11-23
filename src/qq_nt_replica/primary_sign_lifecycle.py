import sys
from contextlib import contextmanager
from threading import get_ident, get_native_id

from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimaryExecutionPaused, PrimarySemanticUnavailable


_PUBLIC_DIRECT_FACTORY = object()
_CLOSE_DIRECT_FACTORY = object()
_PROVIDER_INITIALIZATION_FACTORY = object()
_SDK_WORKER_FACTORY = object()
_SECONDARY_POSTFETCH_FACTORY = object()
_NOTIFICATION_WORKER_FACTORY = object()


class _SignContinuation:
    def __init__(self, runtime, execution, signer, allow_pause=True):
        self.runtime, self.execution, self.signer = runtime, execution, signer
        self.thread = get_ident()
        self.state, self.remaining, self.snapshot = 'running', 0, None
        self.allow_pause = allow_pause
        self.executing = False
        self.scope = self.driver = None

    def retain(self):
        runtime = self.runtime
        owner = runtime._active_main
        vm = owner.get('vm') if type(owner) is dict else None
        if (vm is None or getattr(vm, '_primary_mix_owner', None) is not self or
                vm.pending_once10 is None or vm.pc != 44938):
            raise InputError('continuation yielded outside its owned Main once10 wait')
        chain, current = [], self.execution
        from types import GeneratorType
        while type(current) is GeneratorType:
            chain.append((current, current.gi_code, current.gi_frame, current.gi_yieldfrom))
            current = current.gi_yieldfrom
        self.snapshot = (owner, runtime._main_generation, vm, vm.program, vm.program.words,
                         vm.program.raw, vm.cells, vm.memory, vm.image_base, vm.cells.address,
                         vm.arena_address, vm.arena_size, vm.arena_used, vm.pending_once10,
                         tuple(runtime._program_calls), runtime._execute_depth,
                         runtime.__dict__.get('_primary_direct_scope'),
                         runtime.__dict__.get('_primary_public_direct_owner'),
                         runtime.memory._region_snapshot(), tuple(chain), tuple(owner.items()),
                         tuple((call['name'], call['arguments'], call['hosts']) for call in runtime._program_calls),
                         vm._mgf_stage, vm._mgf_width, vm.trace, tuple(vm.trace))
        self.scope = runtime.__dict__.get('_primary_direct_scope')
        self.driver = self.scope.driver if self.scope is not None else None

    def validate(self, runtime, signer):
        if (runtime is not self.runtime or signer is not self.signer or self.thread != get_ident() or
                self.state != 'paused' or runtime.__dict__.get('_primary_wait_session') is not self):
            raise InputError('continuation requires its original paused owner and thread')
        owner, generation, vm, program, words, raw, cells, memory, base, cells_address, arena, size, used, pending, calls, depth, scope, public, regions, chain, owner_fields, call_fields, stage, width, trace, records = self.snapshot
        if (runtime._active_main is not owner or runtime._main_generation != generation or
                owner.get('generation') != generation or owner.get('thread') != self.thread or
                owner.get('vm') is not vm or runtime._active_failed or runtime._execute_thread != self.thread or
                not runtime.primary_core or getattr(runtime, '_consumed_mgf', None) is not None or
                tuple(owner.items()) != owner_fields or
                vm.runtime is not runtime or vm.program is not program or program.words is not words or
                program.raw is not raw or vm.cells is not cells or vm.memory is not memory or
                memory is not runtime.memory or vm.image_base != base or runtime.image_base != base or
                cells.address != cells_address or vm.arena_address != arena or vm.arena_size != size or
                vm.arena_used != used or (vm.pc, vm.block, vm.predecessor, vm.initial_block) != (44938, 1059, 1054, False) or
                vm.halted or vm.abort_reason is not None or vm.pending_once10 is not pending or
                getattr(vm, '_primary_mix_owner', None) is not self or runtime._execute_depth != depth or
                len(runtime._program_calls) != len(calls) or
                any(a is not b for a, b in zip(runtime._program_calls, calls)) or
                any((call.get('name'), call.get('arguments'), call.get('hosts')) != fields
                    for call, fields in zip(runtime._program_calls, call_fields)) or
                vm._mgf_stage != stage or vm._mgf_width != width or vm.trace is not trace or tuple(trace) != records or
                runtime.__dict__.get('_primary_direct_scope') is not scope or
                runtime.__dict__.get('_primary_public_direct_owner') is not public or
                len(runtime.memory._region_snapshot()) != len(regions) or
                any(a is not b for a, b in zip(runtime.memory._region_snapshot(), regions)) or
                any(g.gi_code is not code or g.gi_frame is not frame or g.gi_yieldfrom is not child
                    for g, code, frame, child in chain)):
            raise InputError('continuation Main identity, frame or pending body changed')
        if signer is not None and (signer.runtime is not runtime or signer._sign_owner != self.thread or signer.failed):
            raise InputError('continuation public owner changed')
        if scope is not None and (not scope.installed or scope.closed or scope.runtime is not runtime or
                                  scope.thread != self.thread or scope.public_owner is not public or
                                  scope is not self.scope or scope.driver is not self.driver or
                                  self.driver is not None and (self.driver.closed or not self.driver.installed or
                                                              self.driver.runtime is not runtime)):
            raise InputError('continuation direct scope changed')
        if public is not None and (not public.active or public.thread != self.thread or
                public.runtime is not runtime or public.signer is not signer or
                signer._public_direct_serial != public.serial):
            raise InputError('continuation public scope changed')


def _retire_execution(session):
    runtime = session.runtime
    if runtime.__dict__.get('_primary_wait_session') is session:
        del runtime._primary_wait_session
    session.snapshot = session.execution = session.signer = session.runtime = None
    session.scope = session.driver = None


def close_retained_execution(runtime, owner):
    session = runtime.__dict__.get('_primary_wait_session')
    if session is None:
        return False
    if type(session) is not _SignContinuation or session.thread != get_ident():
        raise InputError('retained close requires the original owner thread')
    if session.executing and session.state in ('running', 'closing'):
        return False
    if session.state != 'paused' or owner is None or owner is not session.scope and owner is not session.driver:
        raise InputError('retained close requires the captured scope or driver')
    cancel_execution(runtime, session, signer=session.signer)
    return True


def _check_read_budget(budget):
    if type(budget) is not int or budget < 1:
        raise InputError('once10 global-read budget must be a positive integer')


def execution_active(runtime):
    session = runtime.__dict__.get('_primary_wait_session')
    return session is None or (type(session) is _SignContinuation and session.thread == get_ident() and
                               session.executing and session.state in ('running', 'closing'))


def require_execution_active(runtime):
    if not execution_active(runtime):
        raise InputError('runtime has a suspended execution')


def _sync_execution(execution):
    try:
        next(execution)
    except StopIteration as completed:
        return completed.value
    try:
        raise InputError('synchronous caller cannot retain a Main continuation')
    finally:
        execution.close()


def _pump_execution(session, budget):
    _check_read_budget(budget)
    session.remaining, session.state = budget, 'running'
    session.executing = True
    try:
        yielded = next(session.execution)
        if yielded is not session:
            raise InputError('execution yielded a foreign continuation')
        if not session.allow_pause:
            raise PrimarySemanticUnavailable('this synchronous entry cannot retain a Main wait; use sign or sign_result')
        session.retain()
    except StopIteration as completed:
        session.state = 'complete'
        _retire_execution(session)
        return completed.value
    except BaseException as primary:
        session.state = 'closing'
        try:
            session.execution.close()
        except BaseException as error:
            primary.add_note('continuation cleanup failed: ' + type(error).__name__)
        finally:
            session.state = 'failed'
            _retire_execution(session)
        raise
    finally:
        session.executing = False
    session.state = 'paused'
    error = PrimaryExecutionPaused('Main once10 read quantum exhausted; resume the retained public call')
    error.continuation = session
    raise error


def start_execution(runtime, execution, *, signer=None, once10_read_budget=1024):
    _check_read_budget(once10_read_budget)
    if runtime.__dict__.get('_primary_wait_session') is not None:
        execution.close()
        raise InputError('runtime already owns a retained execution')
    session = _SignContinuation(runtime, execution, signer)
    runtime._primary_wait_session = session
    return _pump_execution(session, once10_read_budget)


def synchronous_execution(runtime, execution):
    session = runtime.__dict__.get('_primary_wait_session')
    if session is not None:
        if session.thread != get_ident() or session.state != 'running':
            execution.close()
            raise InputError('runtime has a suspended execution')
        return _sync_execution(execution)
    session = _SignContinuation(runtime, execution, None, allow_pause=False)
    runtime._primary_wait_session = session
    return _pump_execution(session, 1024)


def resume_execution(runtime, continuation, *, signer=None, once10_read_budget=1024):
    _check_read_budget(once10_read_budget)
    if type(continuation) is not _SignContinuation:
        raise InputError('resume requires its opaque continuation')
    continuation.validate(runtime, signer)
    return _pump_execution(continuation, once10_read_budget)


def cancel_execution(runtime, continuation, *, signer=None):
    if type(continuation) is not _SignContinuation:
        raise InputError('cancel requires its opaque continuation')
    continuation.validate(runtime, signer)
    continuation.state = 'closing'
    continuation.executing = True
    try:
        continuation.execution.close()
    finally:
        continuation.state = 'cancelled'
        continuation.executing = False
        _retire_execution(continuation)


def retain_execution(runtime, execution):
    session = runtime.__dict__.get('_primary_wait_session')
    if session is None:
        return start_execution(runtime, execution)
    if type(session) is not _SignContinuation or session.thread != get_ident() or session.state != 'running':
        execution.close()
        raise InputError('runtime has a suspended execution')
    return execution

from .primary_device_request import device_request_call


class _SDKWorkerOwner:
    def __init__(self, service, row, parameter, domain, source, lease, factory):
        if factory is not _SDK_WORKER_FACTORY:
            raise InputError('SDK direct worker requires its actual entry factory')
        self.service, self.runtime, self.row = service, service._runtime, row
        self.parameter, self.domain, self.source, self.lease = parameter, domain, source, lease
        self.thread, self.native_thread = get_ident(), get_native_id()
        self.generation = self.runtime._main_generation
        self.active, self.status_index, self.material_used = True, 0, False
        self.material_reuse = None

    def valid(self):
        from .primary_windows_threads import WindowsSDKThreadService, _LIVE_SERVICES
        from .primary_host_services import _ExecutionLease
        import os
        service, runtime, row = self.service, self.runtime, self.row
        if not self.active or self.thread != get_ident() or self.native_thread != get_native_id():
            return False
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        domain = self.domain.gen
        context = domain.gi_frame
        registrar = service._registrar
        leases = registrar._leases.get(self.native_thread, ())
        return (type(service) is WindowsSDKThreadService and service._runtime is runtime and
                service._owner[0] == os.getpid() and service._owner[1] != self.native_thread and
                service in _LIVE_SERVICES and type(row.get('_callback')) is service._callback_type and
                self.source is frame and frame.f_code is WindowsSDKThreadService._entry.__code__ and
                frame.f_locals.get('self') is service and frame.f_locals.get('row') is row and
                frame.f_locals.get('parameter') is self.parameter and frame.f_locals.get('domain') is self.domain and
                domain.gi_suspended and domain.gi_code is WindowsSDKThreadService._context.__wrapped__.__code__ and
                context is not None and context.f_locals.get('self') is service and
                context.f_locals.get('runtime') is runtime and service._execution.locked() and
                service._execution_tid == self.native_thread and not service._closed and
                service._failure is None and any(item is row for item in service._threads) and
                row.get('_diagnostic_role') == 'bootstrap' and row.get('_kind') is None and
                row.get('state') == 'running' and row.get('callback_thread_id') == self.native_thread and
                row.get('thread_id') == self.native_thread and type(row.get('handle')) is int and row['handle'] > 0 and
                not row.get('handle_closed') and not row.get('source_completed') and row.get('host_failure') is None and
                (self.parameter is None or type(self.parameter) is int and self.parameter == 0) and
                registrar._runtime is runtime and registrar._bound and type(self.lease) is _ExecutionLease and
                self.lease.registrar is registrar and self.lease.thread_id == self.native_thread and
                self.lease.active and not self.lease.suspended and not self.lease.closing and
                bool(leases) and leases[-1] is self.lease and runtime._active_main is None and
                not runtime._active_failed and runtime._main_generation == self.generation and
                runtime.__dict__.get('_primary_sdk_worker_owner') is self and
                all(runtime.__dict__.get(key) is None for key in ('_primary_public_direct_owner',
                    '_primary_close_direct_owner', '_primary_provider_initialization_owner')))


    def failure_observation(self):
        from .primary_windows_threads import WindowsSDKThreadService, _LIVE_SERVICES
        from .primary_host_services import _ExecutionLease
        from inspect import getgeneratorstate
        import os
        service, runtime, row = self.service, self.runtime, self.row
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        generator = self.domain.gen
        context = generator.gi_frame
        registrar = service._registrar
        leases = registrar._leases.get(self.native_thread, ())
        predicates = {
            'THREAD': self.active and self.thread == get_ident() and self.native_thread == get_native_id(),
            'SERVICE': type(service) is WindowsSDKThreadService and service._runtime is runtime and
                service._owner[0] == os.getpid() and service._owner[1] != self.native_thread and
                service in _LIVE_SERVICES and type(row.get('_callback')) is service._callback_type,
            'SOURCE_FRAME': self.source is frame and frame is not None and
                frame.f_code is WindowsSDKThreadService._entry.__code__ and
                frame.f_locals.get('self') is service and frame.f_locals.get('row') is row and
                frame.f_locals.get('parameter') is self.parameter and frame.f_locals.get('domain') is self.domain,
            'CONTEXT_GENERATOR': generator.gi_suspended and
                generator.gi_code is WindowsSDKThreadService._context.__wrapped__.__code__ and
                context is not None and context.f_locals.get('self') is service and context.f_locals.get('runtime') is runtime,
            'EXECUTION': service._execution.locked() and service._execution_tid == self.native_thread and not service._closed,
            'SERVICE_FAILURE': service._failure is None,
            'ROW_MEMBERSHIP': any(item is row for item in service._threads),
            'ROW_IDENTITY': row.get('_diagnostic_role') == 'bootstrap' and row.get('_kind') is None and
                row.get('state') == 'running' and row.get('callback_thread_id') == self.native_thread and
                row.get('thread_id') == self.native_thread and type(row.get('handle')) is int and row['handle'] > 0 and
                not row.get('handle_closed') and not row.get('source_completed') and row.get('host_failure') is None,
            'PARAMETER': self.parameter is None or type(self.parameter) is int and self.parameter == 0,
            'REGISTRAR': registrar._runtime is runtime and registrar._bound and type(self.lease) is _ExecutionLease,
            'LEASE': self.lease.registrar is registrar and self.lease.thread_id == self.native_thread and
                self.lease.active and not self.lease.suspended and not self.lease.closing,
            'LEASE_STACK': bool(leases) and leases[-1] is self.lease,
            'RUNTIME_STATE': runtime._active_main is None and not runtime._active_failed and
                runtime._main_generation == self.generation,
            'OWNER_SLOT': runtime.__dict__.get('_primary_sdk_worker_owner') is self,
            'EXCLUSIVE_OWNERS': all(runtime.__dict__.get(key) is None for key in
                ('_primary_public_direct_owner', '_primary_close_direct_owner', '_primary_provider_initialization_owner')),
        }
        configured = getattr(runtime, 'crt_startup_observations', None) is not None
        native_domain = self.native_thread in service._crt_domains
        branch = 'UNKNOWN'
        if predicates['CONTEXT_GENERATOR']:
            if configured and native_domain and 'saved' not in context.f_locals:
                branch = 'NATIVE_CRT'
            elif not configured and 'saved' in context.f_locals:
                branch = 'LOCAL_CONTEXT'
        return dict(kind='REJECTION_SNAPSHOT', originalFailedPredicate='UNKNOWN',
            snapshotFirstFalseGroup=next((key for key, value in predicates.items() if not value), 'NONE'),
            predicates={key: bool(value) for key, value in predicates.items()}, contextBranch=branch,
            generatorState=getgeneratorstate(generator),
            statusCompleted=self.status_index if type(self.status_index) is int and 0 <= self.status_index <= 3 else 'UNKNOWN',
            nativeCRTConfigured=configured,
            nativeCRTDomainCurrent=native_domain, leaseTopMatches=bool(leases) and leases[-1] is self.lease)

    def refusal(self, message):
        error = InputError(message)
        error.sdkContext = 'UNKNOWN'
        try:
            error.sdkContext = self.failure_observation()
        except BaseException:
            pass
        return error


@contextmanager
def sdk_worker_call(service, row, parameter, domain):
    runtime = service._runtime
    if getattr(runtime, 'primary_backend', 'reference') != 'direct':
        yield
        return
    from .primary_windows_threads import WindowsSDKThreadService
    from .primary_sign import PrimaryRuntime
    from types import GeneratorType
    source = sys._getframe(2)
    if (type(service) is not WindowsSDKThreadService or type(runtime) is not PrimaryRuntime or
            type(getattr(domain, 'gen', None)) is not GeneratorType or
            source.f_code is not WindowsSDKThreadService._entry.__code__ or
            runtime._execute_depth or runtime._program_calls or runtime._active_main is not None or
            runtime.__dict__.get('_primary_sdk_worker_owner') is not None or
            runtime.__dict__.get('_primary_direct_scope') is not None):
        raise InputError('SDK direct worker requires its inactive original bootstrap entry')
    lease = service._registrar.current_lease()
    owner = _SDKWorkerOwner(service, row, parameter, domain, source, lease, _SDK_WORKER_FACTORY)
    runtime._primary_sdk_worker_owner = owner
    scope = None
    report = row.setdefault('direct_scope', {})
    try:
        if not owner.valid():
            raise owner.refusal('SDK direct worker lost its actual native execution context')
        from .primary_direct_scopes import PrimaryDirectScope
        scope = PrimaryDirectScope(runtime, worker_owner=owner, execution_report=report)
        scope.install()
        yield
        if not owner.valid() or owner.status_index != 3:
            raise owner.refusal('SDK direct worker did not complete its ordered bootstrap status calls')
        report['sdkWorker']['completed'] = True
    finally:
        primary, failure = sys.exception(), None
        if scope is not None:
            try:
                scope.close()
            except BaseException as error:
                failure = error
        owner.active = False
        owner.material_reuse = None
        owner.source = owner.domain = None
        if runtime.__dict__.get('_primary_sdk_worker_owner') is owner:
            runtime.__dict__.pop('_primary_sdk_worker_owner')
        elif failure is None:
            failure = InputError('SDK direct worker owner changed before completion')
        if failure is not None:
            if primary is not None:
                primary.add_note('SDK direct worker cleanup failed: ' + type(failure).__name__)
            else:
                raise failure


class _SecondaryPostfetchOwner:
    def __init__(self, service, row, domain, source, lease, serial, factory):
        if factory is not _SECONDARY_POSTFETCH_FACTORY:
            raise InputError('secondary postfetch owner requires its actual entry factory')
        self.service, self.runtime, self.row = service, service._runtime, row
        self.domain, self.source, self.lease = domain, source, lease
        self.thread, self.native_thread = get_ident(), get_native_id()
        self._serial, self.generation, self.active = serial, self.runtime._main_generation, True

    @property
    def serial(self):
        return self._serial

    def valid(self):
        return self._valid(self.generation)

    def _resume(self, service, row, domain, ticket):
        from .primary_windows_threads import WindowsSDKThreadService
        source = sys._getframe(1)
        runtime = self.runtime
        if (source.f_code is not WindowsSDKThreadService.resident_checkpoint.__code__ or
                source.f_locals.get('self') is not service or source.f_locals.get('row') is not row or
                source.f_locals.get('domain') is not domain or source.f_locals.get('ticket') is not ticket or
                service is not self.service or row is not self.row or
                service._crt_domains.get(self.native_thread) is not domain or
                domain['state'].get('_primary_secondary_postfetch_owner') is not self or
                domain['state'].get('_primary_direct_scope') is not runtime.__dict__.get('_primary_direct_scope') or
                self.generation != domain.get('main_generation') or
                type(runtime._main_generation) is not int or runtime._main_generation < self.generation or
                row.get('consumed_ticket') != ticket[0] or row.get('continuation_kind') != ticket[2] or
                not self._valid(runtime._main_generation)):
            raise InputError('secondary postfetch resume lost its paired parked domain and fresh ticket')
        self.generation = runtime._main_generation

    def _valid(self, generation):
        from .primary_windows_threads import WindowsSDKThreadService, _LIVE_SERVICES
        from .primary_host_services import _ExecutionLease
        import os
        service, runtime, row = self.service, self.runtime, self.row
        if not self.active or self.thread != get_ident() or self.native_thread != get_native_id():
            return False
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        generator = self.domain.gen
        context = generator.gi_frame
        registrar = service._registrar
        leases = registrar._leases.get(self.native_thread, ())
        return (type(service) is WindowsSDKThreadService and service._runtime is runtime and
                service._owner[0] == os.getpid() and service._owner[1] != self.native_thread and
                service in _LIVE_SERVICES and frame is not None and frame is self.source and
                frame.f_code is WindowsSDKThreadService._secondary_entry.__code__ and
                frame.f_locals.get('self') is service and frame.f_locals.get('row') is row and
                frame.f_locals.get('domain') is self.domain and generator.gi_suspended and
                generator.gi_code is WindowsSDKThreadService._context.__wrapped__.__code__ and
                context is not None and context.f_locals.get('self') is service and
                context.f_locals.get('runtime') is runtime and service._execution.locked() and
                service._execution_tid == self.native_thread and not service._closed and
                service._failure is None and any(item is row for item in service._threads) and
                any(item is row for item in service._secondary) and row.get('_kind') == 'secondary' and
                row.get('state') == 'running' and row.get('callback_thread_id') == self.native_thread and
                row.get('thread_id') == self.native_thread and type(row.get('handle')) is int and row['handle'] > 0 and
                type(row.get('context')) is int and row['context'] > 0 and
                type(row.get('task')) is int and row['task'] > 0 and
                not row.get('handle_closed') and not row.get('source_completed') and row.get('host_failure') is None and
                row.get('_direct_secondary_serial') == self.serial and type(self.serial) is int and
                type(service._secondary_direct_serial) is int and 0 < self.serial <= service._secondary_direct_serial and
                registrar._runtime is runtime and registrar._bound and type(self.lease) is _ExecutionLease and
                self.lease.registrar is registrar and self.lease.thread_id == self.native_thread and
                self.lease.token is service._close_token and self.lease.active and
                not self.lease.suspended and not self.lease.closing and bool(leases) and leases[-1] is self.lease and
                runtime._active_main is None and not runtime._active_failed and
                runtime._main_generation == generation and
                runtime.__dict__.get('_primary_secondary_postfetch_owner') is self and
                all(runtime.__dict__.get(key) is None for key in ('_primary_public_direct_owner',
                    '_primary_close_direct_owner', '_primary_provider_initialization_owner', '_primary_sdk_worker_owner')))


@contextmanager
def secondary_postfetch_call(service, row, domain):
    runtime = service._runtime
    if getattr(runtime, 'primary_backend', 'reference') != 'direct':
        yield
        return
    from .primary_windows_threads import WindowsSDKThreadService
    from .primary_sign import PrimaryRuntime
    from types import GeneratorType
    source = sys._getframe(2)
    if (type(service) is not WindowsSDKThreadService or type(runtime) is not PrimaryRuntime or
            type(getattr(domain, 'gen', None)) is not GeneratorType or
            source.f_code is not WindowsSDKThreadService._secondary_entry.__code__ or
            runtime._execute_depth or runtime._program_calls or runtime._active_main is not None or
            row.get('_direct_secondary_serial') is not None or
            any(runtime.__dict__.get(key) is not None for key in ('_primary_secondary_postfetch_owner',
                '_primary_public_direct_owner', '_primary_close_direct_owner', '_primary_provider_initialization_owner',
                '_primary_sdk_worker_owner', '_primary_direct_scope'))):
        raise InputError('secondary postfetch requires its inactive original secondary entry')
    lease = service._registrar.current_lease()
    service._secondary_direct_serial += 1
    serial = service._secondary_direct_serial
    row['_direct_secondary_serial'] = serial
    owner = _SecondaryPostfetchOwner(service, row, domain, source, lease, serial, _SECONDARY_POSTFETCH_FACTORY)
    runtime._primary_secondary_postfetch_owner = owner
    scope = None
    report = row.setdefault('direct_scope', {})
    try:
        if not owner.valid():
            raise InputError('secondary postfetch lost its actual native execution context')
        from .primary_direct_scopes import PrimaryDirectScope
        scope = PrimaryDirectScope(runtime, secondary_owner=owner, execution_report=report)
        scope.install()
        yield
        if not owner.valid():
            raise InputError('secondary postfetch lost its execution owner before completion')
    finally:
        primary, failure = sys.exception(), None
        if scope is not None:
            try:
                scope.close()
            except BaseException as error:
                failure = error
        owner.active = False
        owner.source = owner.domain = None
        if runtime.__dict__.get('_primary_secondary_postfetch_owner') is owner:
            runtime.__dict__.pop('_primary_secondary_postfetch_owner')
        elif failure is None:
            failure = InputError('secondary postfetch owner changed before completion')
        if failure is not None:
            if primary is not None:
                primary.add_note('secondary postfetch cleanup failed: ' + type(failure).__name__)
            else:
                raise failure


class _NotificationWorkerOwner:
    def __init__(self, service, row, domain, source, lease, serial, parameter, factory):
        if factory is not _NOTIFICATION_WORKER_FACTORY:
            raise InputError('notification worker owner requires its actual entry factory')
        self.service, self.runtime, self.row = service, service._runtime, row
        self.domain, self.source, self.lease = domain, source, lease
        self.parameter = parameter
        self.thread, self.native_thread = get_ident(), get_native_id()
        self._serial, self.generation, self.active = serial, self.runtime._main_generation, True

    @property
    def serial(self):
        return self._serial

    def valid(self):
        from .primary_windows_threads import WindowsSDKThreadService, _LIVE_SERVICES
        from .primary_host_services import _ExecutionLease
        import os
        service, runtime, row = self.service, self.runtime, self.row
        if not self.active or self.thread != get_ident() or self.native_thread != get_native_id():
            return False
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        generator = self.domain.gen
        context = generator.gi_frame
        registrar = service._registrar
        leases = registrar._leases.get(self.native_thread, ())
        return (type(service) is WindowsSDKThreadService and service._runtime is runtime and
                service._owner[0] == os.getpid() and service._owner[1] != self.native_thread and
                service in _LIVE_SERVICES and frame is not None and frame is self.source and
                frame.f_code is WindowsSDKThreadService._notification_entry.__code__ and
                frame.f_locals.get('self') is service and frame.f_locals.get('row') is row and
                frame.f_locals.get('domain') is self.domain and generator.gi_suspended and
                generator.gi_code is WindowsSDKThreadService._context.__wrapped__.__code__ and
                context is not None and context.f_locals.get('self') is service and
                context.f_locals.get('runtime') is runtime and service._execution.locked() and
                service._execution_tid == self.native_thread and not service._closed and
                service._failure is None and any(item is row for item in service._threads) and
                row.get('_kind') == 'notification' and type(row.get('_callback')) is service._callback_type and
                row.get('declared_parameter') == 3000 and self.parameter == 3000 and
                frame.f_locals.get('argument') == 3000 and frame.f_locals.get('parameter') is self.parameter and
                row.get('state') == 'running' and row.get('callback_thread_id') == self.native_thread and
                row.get('thread_id') == self.native_thread and type(row.get('handle')) is int and row['handle'] > 0 and
                not row.get('handle_closed') and not row.get('source_completed') and row.get('host_failure') is None and
                row.get('_direct_notification_serial') == self.serial == service._notification_direct_serial and
                registrar._runtime is runtime and registrar._bound and type(self.lease) is _ExecutionLease and
                self.lease.registrar is registrar and self.lease.thread_id == self.native_thread and
                self.lease.token is None and self.lease.active and
                not self.lease.suspended and not self.lease.closing and bool(leases) and leases[-1] is self.lease and
                runtime._active_main is None and not runtime._active_failed and
                runtime._main_generation == self.generation and
                runtime.__dict__.get('_primary_notification_worker_owner') is self and
                all(runtime.__dict__.get(key) is None for key in ('_primary_public_direct_owner',
                    '_primary_close_direct_owner', '_primary_provider_initialization_owner', '_primary_sdk_worker_owner',
                    '_primary_secondary_postfetch_owner')))


@contextmanager
def notification_worker_call(service, row, parameter, domain):
    runtime = service._runtime
    if getattr(runtime, 'primary_backend', 'reference') != 'direct':
        yield
        return
    from .primary_windows_threads import WindowsSDKThreadService
    from .primary_sign import PrimaryRuntime
    from .primary_windows_notification_environment import WindowsNotificationEnvironmentObservations
    from types import GeneratorType
    source = sys._getframe(2)
    slots = ('_primary_notification_worker_owner', '_primary_secondary_postfetch_owner', '_primary_sdk_worker_owner',
             '_primary_public_direct_owner', '_primary_close_direct_owner', '_primary_provider_initialization_owner',
             '_primary_direct_scope')
    if (type(service) is not WindowsSDKThreadService or type(runtime) is not PrimaryRuntime or
            source.f_code is not WindowsSDKThreadService._notification_entry.__code__ or
            type(getattr(domain, 'gen', None)) is not GeneratorType or parameter != 3000 or
            runtime._execute_depth or runtime._program_calls or runtime._active_main is not None or
            row.get('_direct_notification_serial') is not None or any(runtime.__dict__.get(k) is not None for k in slots)):
        raise InputError('notification direct worker requires its inactive original source entry')
    lease = service._registrar.current_lease()
    service._notification_direct_serial += 1
    serial = service._notification_direct_serial
    row['_direct_notification_serial'] = serial
    owner = _NotificationWorkerOwner(service, row, domain, source, lease, serial, parameter, _NOTIFICATION_WORKER_FACTORY)
    runtime._primary_notification_worker_owner = owner
    scope = delegate = None
    prior = runtime.__dict__.get('device_integrity_observations')
    had = 'device_integrity_observations' in runtime.__dict__
    parent = getattr(runtime, 'notification_environment_observations', None)
    try:
        if not owner.valid():
            raise InputError('notification direct worker lost its actual execution context')
        if parent is None:
            from .primary_memory import UnknownMemory
            raise UnknownMemory('notification mandatory environment observations are missing')
        if type(parent) is not WindowsNotificationEnvironmentObservations:
            raise InputError('notification mandatory service requires its actual environment parent')
        delegate = parent.notification_mandatory_service(runtime, owner)
        if prior is not None:
            raise InputError('notification mandatory observer refuses a competing source')
        runtime.device_integrity_observations = delegate
        from .primary_direct_scopes import PrimaryDirectScope
        scope = PrimaryDirectScope(runtime, notification_owner=owner, execution_report=row.setdefault('direct_scope', {}))
        scope.install()
        yield
        if not owner.valid():
            raise InputError('notification direct worker lost its owner before completion')
    finally:
        primary, failures = sys.exception(), []
        if scope is not None:
            try:
                scope.close()
            except BaseException as error:
                failures.append(error)
        if delegate is not None:
            try:
                parent.release_notification_mandatory(delegate)
            except BaseException as error:
                failures.append(error)
            if runtime.__dict__.get('device_integrity_observations') is delegate:
                if had:
                    runtime.device_integrity_observations = prior
                else:
                    runtime.__dict__.pop('device_integrity_observations')
            elif prior is None:
                failures.append(InputError('notification mandatory observer was replaced'))
        owner.active = False
        owner.source = owner.domain = None
        if runtime.__dict__.get('_primary_notification_worker_owner') is owner:
            runtime.__dict__.pop('_primary_notification_worker_owner')
        else:
            failures.append(InputError('notification worker owner was replaced'))
        for error in failures:
            if primary is not None:
                primary.add_note('notification worker cleanup failed: ' + type(error).__name__)
            else:
                primary = error
        if failures and sys.exception() is None:
            raise primary


class _CloseDirectOwner:
    def __init__(self, signer, windows, registrar, serial, factory):
        if factory is not _CLOSE_DIRECT_FACTORY:
            raise InputError('direct close owner requires its actual closing factory')
        self.signer, self.runtime, self.windows, self.registrar = signer, signer.runtime, windows, registrar
        self.thread, self.serial, self.active = get_ident(), serial, True

    def valid(self):
        return (self.active and get_ident() == self.thread and self.windows._thread == get_native_id() and
                self.signer.runtime is self.runtime and self.runtime._primary_entry_owner is self.signer and
                self.windows._signer is self.signer and self.windows._registrar is self.registrar and
                self.windows._state == 'closing' and not self.windows._busy and
                self.signer._sign_owner is None and self.runtime._active_main is None and
                self.runtime.__dict__.get('_primary_public_direct_owner') is None and
                self.runtime.__dict__.get('_primary_close_direct_owner') is self and
                self.registrar._runtime is self.runtime and self.registrar._bound)


@contextmanager
def close_call(signer, windows, registrar):
    if getattr(signer, 'primary_backend', 'reference') != 'direct':
        yield
        return
    from .primary_direct_scopes import PrimaryDirectScope, _source_locals
    from .primary_windows_signer import WindowsSigner
    source = _source_locals(WindowsSigner.close.__code__, windows)
    release = _source_locals(WindowsSigner._release_resources.__code__, windows)
    runtime = signer.runtime
    if source is None:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if release is None:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if windows._state != 'closing':
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if windows._busy:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if windows._signer is not signer:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if windows._registrar is not registrar:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if signer._sign_owner is not None:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if runtime._active_main is not None:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if runtime._execute_depth:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if runtime._program_calls:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if runtime.__dict__.get('_primary_direct_scope') is not None:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if runtime.__dict__.get('_primary_public_direct_owner') is not None:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    if runtime.__dict__.get('_primary_close_direct_owner') is not None:
        raise InputError('direct close requires its original inactive Windows owner and registrar')
    signer._public_close_serial += 1
    owner = _CloseDirectOwner(signer, windows, registrar, signer._public_close_serial, _CLOSE_DIRECT_FACTORY)
    runtime._primary_close_direct_owner = owner
    scope = None
    try:
        signer.last_close_report = {}
        scope = PrimaryDirectScope(runtime, close_owner=owner, execution_report=signer.last_close_report)
        scope.install()
        yield
    finally:
        primary = sys.exception()
        try:
            if scope is not None:
                scope.close()
        finally:
            owner.active = False
            if runtime.__dict__.get('_primary_close_direct_owner') is owner:
                runtime.__dict__.pop('_primary_close_direct_owner', None)
            elif primary is not None:
                primary.add_note('direct close owner changed during cleanup')
            else:
                raise InputError('direct close owner changed during cleanup')


def close_program_allowed(runtime, name, arguments, hosts):
    from .primary_direct_scopes import PrimaryDirectScope
    scope = runtime.__dict__.get('_primary_direct_scope')
    return (type(scope) is PrimaryDirectScope and scope.runtime is runtime and
            scope.close_owner is not None and scope.allow_close_program(name, arguments, hosts))


def close_frame_allowed(addresses, name, arguments=None, hosts=None):
    from .primary_sign import PrimaryRuntime
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is PrimaryRuntime._execute_continued.__code__:
            source = frame.f_locals
            runtime = source.get('self')
            owner = getattr(runtime, '_primary_close_direct_owner', None)
            if (type(owner) is _CloseDirectOwner and owner.signer.addresses is addresses and
                    source.get('name') == name and
                    (arguments is None or source.get('arguments') is arguments) and
                    source.get('hosts') is hosts):
                return close_program_allowed(runtime, name, source['arguments'], source['hosts'])
            return False
        frame = frame.f_back
    return False


class _PublicDirectOwner:
    __slots__ = ('_signer', '_runtime', '_thread', '_serial', '_active')

    def __init__(self, signer, serial, factory):
        if factory is not _PUBLIC_DIRECT_FACTORY:
            raise InputError('public direct owner requires its actual call factory')
        self._signer, self._runtime = signer, signer.runtime
        self._thread, self._serial, self._active = get_ident(), serial, True

    @property
    def signer(self):
        return self._signer

    @property
    def runtime(self):
        return self._runtime

    @property
    def thread(self):
        return self._thread

    @property
    def serial(self):
        return self._serial

    @property
    def active(self):
        return self._active

    def valid(self):
        return (self._active and execution_active(self._runtime) and get_ident() == self._thread and self._signer._sign_owner == self._thread and
                self._signer.runtime is self._runtime and self._runtime._primary_entry_owner is self._signer and
                self._runtime.__dict__.get('_primary_public_direct_owner') is self)


class _ProviderInitializationOwner:
    def __init__(self, signer, metadata, tail, serial, source, factory):
        if factory is not _PROVIDER_INITIALIZATION_FACTORY:
            raise InputError('provider initialization requires its actual operation factory')
        self.signer, self.runtime, self.thread = signer, signer.runtime, get_ident()
        self.metadata, self.tail, self.serial, self.source = metadata, tail, serial, source
        self.active, self.status_index, self.material_used = True, 0, False
        self.bootstrap_root = self.bootstrap_call = None
        self.bootstrap_parents = None

    def valid(self):
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        return (self.active and self.thread == get_ident() and frame is self.source and
                self.source.f_locals.get('self') is self.signer and
                self.source.f_locals.get('metadata') is self.metadata and
                self.source.f_locals.get('tail') is self.tail and
                self.signer._sign_owner == self.thread and self.signer.runtime is self.runtime and
                self.runtime._primary_entry_owner is self.signer and
                self.runtime.__dict__.get('_primary_provider_initialization_owner') is self and
                not self.signer.failed and not self.runtime._active_failed)


@contextmanager
def provider_initialization_call(signer, metadata, tail):
    from .primary_signer import PrimarySigner
    source = sys._getframe(2)
    runtime = signer.runtime
    if (source.f_code is not PrimarySigner.initialize_provider.__code__ or
            source.f_locals.get('self') is not signer or source.f_locals.get('metadata') is not metadata or
            source.f_locals.get('tail') is not tail or signer._sign_owner is not None or signer.failed or
            runtime._active_failed or runtime._active_main is not None or runtime._program_calls or
            runtime.__dict__.get('_primary_public_direct_owner') is not None or
            runtime.__dict__.get('_primary_close_direct_owner') is not None or
            runtime.__dict__.get('_primary_provider_initialization_owner') is not None):
        raise InputError('provider initialization requires its inactive original signer operation')
    signer._sign_owner = get_ident()
    serial = getattr(signer, '_provider_initialization_serial', 0) + 1
    signer._provider_initialization_serial = serial
    owner = _ProviderInitializationOwner(signer, metadata, tail, serial, source, _PROVIDER_INITIALIZATION_FACTORY)
    runtime._primary_provider_initialization_owner = owner
    scope = None
    prior_regions = runtime._owned_frame_regions
    runtime._owned_frame_regions = []
    try:
        from .primary_direct_scopes import PrimaryDirectScope
        signer.last_initialization_report = {}
        scope = PrimaryDirectScope(runtime, initialization_owner=owner,
                                   execution_report=signer.last_initialization_report)
        scope.install()
        yield
        scope.report['providerInitialization']['completed'] = True
    except BaseException:
        signer.failed = True
        if hasattr(signer.addresses, 'failed'):
            signer.addresses.failed = True
        raise
    finally:
        primary, failure = sys.exception(), None
        try:
            cleanup(runtime, runtime._owned_frame_regions)
        except BaseException as error:
            failure = error
        runtime._owned_frame_regions = prior_regions
        if scope is not None:
            try:
                scope.close()
            except BaseException as error:
                if failure is None:
                    failure = error
                else:
                    failure.add_note('provider initialization scope cleanup failed: ' + type(error).__name__)
        owner.active, owner.source = False, None
        if runtime.__dict__.get('_primary_provider_initialization_owner') is owner:
            runtime.__dict__.pop('_primary_provider_initialization_owner')
        elif failure is None:
            failure = InputError('provider initialization owner changed before completion')
        signer._sign_owner = None
        if failure is not None:
            signer.failed = True
            if hasattr(signer.addresses, 'failed'):
                signer.addresses.failed = True
            if primary is not None:
                primary.add_note('provider initialization cleanup failed: ' + type(failure).__name__)
            else:
                raise failure


def region_at(memory, address):
    return next((r for r in memory._region_snapshot() if r.address == address), None)


def cleanup(runtime, regions, allocations=()):
    errors = []
    cancellation = None
    for address, region in reversed(regions):
        if region_at(runtime.memory, address) is region:
            try:
                runtime.memory.unmap(address)
            except BaseException as error:
                errors.append(type(error).__name__)
                if not isinstance(error, Exception) and cancellation is None:
                    cancellation = error
    for address, region in reversed(allocations):
        if region_at(runtime.memory, address) is region:
            try:
                runtime.memory.unmap(address)
                runtime.allocations.pop(address, None)
            except BaseException as error:
                errors.append(type(error).__name__)
                if not isinstance(error, Exception) and cancellation is None:
                    cancellation = error
    if errors:
        runtime.cleanup_errors.extend(errors)
        primary = sys.exception()
        if primary is not None:
            primary.add_note('owned signing cleanup failed: ' + ','.join(errors))
        else:
            if cancellation is not None:
                raise cancellation
            raise PrimaryProgramLimit('owned signing cleanup failed: ' + ','.join(errors))


def discard_retry(runtime, vm=None, reason=None):
    pending = runtime._host2252_pending
    if pending is not None:
        state = pending['stage1']
        runtime.host2252_diagnostics.append({'reads': state.m_read_count, 'row': state.row_i,
                                            'phase': state.phase, 'reason': reason})
        control = pending.get('control_m')
        if control is not None:
            runtime.host2252_diagnostics[-1]['control_m'] = control.diagnostics()
            control.release()
        g_state = pending.get('stage2_g')
        if g_state is not None:
            runtime.host2252_diagnostics[-1]['g'] = g_state.diagnostics()
            g_state.release()
        f_state = pending.get('final_f')
        if f_state is not None:
            runtime.host2252_diagnostics[-1]['f'] = f_state.diagnostics()
            f_state.release()
        state.workspace.clear()
        state.known.clear()
        state.pending_row = None
        state.pending_m = None
        state.input_byte = None
        pending['phase'] = 'aborted' if reason else 'complete'
    runtime._host2252_pending = None
    if vm is not None and reason is not None:
        vm.abort_reason = reason
        vm.pending_native = None


@contextmanager
def public_call(signer):
    if signer._sign_owner is not None:
        raise InputError('signer already owns an active public call')
    if signer.failed:
        raise InputError('signer stopped after an incomplete call; inspect retained state')
    signer._sign_owner = get_ident()
    signer._pending_material_completions = 0
    completed = False
    runtime = signer.runtime
    runtime._owned_frame_regions = []
    direct_scope = direct_owner = None
    had_direct_owner = '_primary_public_direct_owner' in runtime.__dict__
    prior_direct_owner = runtime.__dict__.get('_primary_public_direct_owner')
    try:
        if signer.primary_backend == 'direct':
            if runtime.__dict__.get('_primary_public_direct_owner') is not None:
                raise InputError('runtime already owns a public direct call')
            signer._public_direct_serial += 1
            direct_owner = _PublicDirectOwner(signer, signer._public_direct_serial, _PUBLIC_DIRECT_FACTORY)
            runtime._primary_public_direct_owner = direct_owner
            from .primary_direct_scopes import PrimaryDirectScope
            signer.last_direct_report = {}
            direct_scope = PrimaryDirectScope(runtime, public_owner=direct_owner,
                                              execution_report=signer.last_direct_report)
            direct_scope.install()
        yield
        completed = True
    except BaseException:
        signer.failed = True
        if hasattr(signer.addresses, 'failed'):
            signer.addresses.failed = True
        raise
    finally:
        primary = sys.exception()
        final_error = None
        try:
            cleanup(runtime, runtime._owned_frame_regions)
        except BaseException as error:
            signer.failed = True
            if hasattr(signer.addresses, 'failed'):
                signer.addresses.failed = True
            if primary is None:
                final_error = error
            else:
                primary.add_note('public frame cleanup failed: ' + type(error).__name__)
        finally:
            runtime._owned_frame_regions = None
            if direct_scope is not None:
                try:
                    direct_scope.close()
                except BaseException as error:
                    signer.failed = True
                    if hasattr(signer.addresses, 'failed'):
                        signer.addresses.failed = True
                    if primary is not None:
                        primary.add_note('public direct scope cleanup failed: ' + type(error).__name__)
                    elif final_error is None:
                        final_error = error
                    else:
                        final_error.add_note('public direct scope cleanup failed: ' + type(error).__name__)
            if direct_owner is not None:
                direct_owner._active = False
                if runtime.__dict__.get('_primary_public_direct_owner') is direct_owner:
                    if had_direct_owner:
                        runtime._primary_public_direct_owner = prior_direct_owner
                    else:
                        runtime.__dict__.pop('_primary_public_direct_owner')
                else:
                    signer.failed = True
                    if hasattr(signer.addresses, 'failed'):
                        signer.addresses.failed = True
                    error = InputError('public direct owner changed before its call completed')
                    if primary is not None:
                        primary.add_note(str(error))
                    elif final_error is None:
                        final_error = error
                    else:
                        final_error.add_note(str(error))
            if completed and not signer.failed:
                if direct_scope is not None and not signer.retain_diagnostics:
                    runtime.events.clear()
                    runtime.vms.clear()
                    runtime.memory.writes.clear()
                signer.calls += signer._pending_material_completions
            signer._pending_material_completions = 0
            signer._sign_owner = None
        if final_error is not None:
            raise final_error


def release_command(runtime, address, release):
    primary = sys.exception()
    try:
        release(runtime, address)
    except BaseException as error:
        if primary is None:
            raise
        runtime.cleanup_errors.append(type(error).__name__)
        primary.add_note('public command release failed: ' + type(error).__name__)
    finally:
        tracked = getattr(runtime, '_public_command_owned', {}).pop(address, None)
        if tracked is not None:
            cleanup(runtime, *tracked)


def cleanup_main_allocations(runtime, vm):
    errors = []
    cancellation = None
    remaining = []
    owner = runtime._active_main
    for entry in reversed(vm.main_owned_allocations):
        address = entry['pointer']
        region = region_at(runtime.memory, address)
        if (owner is None or owner['vm'] is not vm or owner['generation'] != entry['generation'] or
                region is not entry['region'] or runtime.allocations.get(address) != entry['size']):
            errors.append('main temporary identity or ledger mismatch')
            remaining.append(entry)
            continue
        try:
            runtime.memory.unmap(address)
            runtime.allocations.pop(address)
        except BaseException as error:
            errors.append(type(error).__name__)
            if not isinstance(error, Exception) and cancellation is None:
                cancellation = error
            remaining.append(entry)
    vm.main_owned_allocations[:] = reversed(remaining)
    if errors:
        runtime.cleanup_errors.extend(errors)
        primary = sys.exception()
        if primary is not None:
            primary.add_note('owned main temporary cleanup failed: ' + ','.join(errors))
        else:
            if cancellation is not None:
                raise cancellation
            raise PrimaryProgramLimit('owned main temporary cleanup failed: ' + ','.join(errors))
