from contextlib import contextmanager
from threading import get_ident
from types import SimpleNamespace
import sys

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


_FACTORY = object()
_ARGUMENTS = (1, 9, 1, 1)


class _RequestAuditClaim:
    _arguments = _ARGUMENTS
    _seed_flag = 1

    def __init__(self, scope, source, completion, public, factory):
        if factory is not _FACTORY:
            raise InputError('request audit requires its original source factory')
        self.scope, self.runtime, self.owner = scope, scope.runtime, scope.public_owner
        self.source, self.completion, self.public = source, completion, public
        self.thread, self.generation, self.serial = get_ident(), self.runtime._main_generation, self.owner.serial
        self.active, self.stage, self.status_completed, self.material_used = True, 'created', False, False
        self.write_start = None

    def valid(self):
        from .primary_request_audit import begin
        from .primary_request_transport import _complete
        from .primary_signer import PrimarySigner
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        runtime, scope = self.runtime, self.scope
        current = self.public.f_locals if self.public is not None else {}
        pending = self.completion.f_locals if self.completion is not None else {}
        return (self.active and get_ident() == self.thread and frame is self.source and
            self.source.f_code is begin.__code__ and self.source.f_locals.get('runtime') is runtime and
            self.source.f_back is self.completion and self.completion.f_code is _complete.__code__ and
            self.public.f_code is PrimarySigner.complete_request.__code__ and
            current.get('self') is self.owner.signer and current.get('runtime') is runtime and
            current.get('command_address') == pending.get('command') and
            current.get('pointer') == pending.get('pointer') and
            len(current.get('response', b'')) == pending.get('count') and
            all(current.get(key) == pending.get(key) for key in ('success', 'sequence', 'error')) and
            pending.get('runtime') is runtime and pending.get('consume_command') is False and
            scope._request_audit is self and scope._valid_public() and self.owner.serial == self.serial and
            runtime.__dict__.get('_primary_direct_scope') is scope and runtime._active_main is None and
            runtime._main_generation == self.generation and not runtime._active_failed)

    def require(self):
        if not self.valid():
            raise PrimarySemanticUnavailable('request audit lost its original completion source and public owner')
        return self

    @contextmanager
    def step(self, rva):
        self.require()
        if rva == 0x1BF75A0 and self.stage == 'created':
            self.stage = 'audit'
        elif rva == 0x1BF8090 and self.stage == 'audited' and self.status_completed:
            self.stage = 'update'
            self.write_start = len(self.runtime.memory.writes)
        else:
            raise PrimarySemanticUnavailable('request audit requires its one source75A0 then8090 pair')
        yield
        self.require()
        if self.stage == 'audit':
            if not self.status_completed:
                raise PrimarySemanticUnavailable('request audit did not complete its real status reader')
            self.stage = 'audited'
        elif self.stage == 'update':
            writes = self.runtime.memory.writes[self.write_start:]
            seed = self.runtime.image_base + 0x6D88430 + (0x840 if self._seed_flag else 0x841)
            seed_writes = sum(address == seed and source == '2DE8E75.material_control_seed'
                              for address, raw, source in writes)
            index_writes = sum(source in ('2DE8F19.material_encoded_index', '2DE8F41.material_encoded_index')
                               for address, raw, source in writes)
            if seed_writes not in (0, 1) or index_writes != 32 * seed_writes:
                raise PrimarySemanticUnavailable('request audit lacks its actual encoded material update')
            self.stage = 'complete'

    @contextmanager
    def status_host(self, carrier, cells):
        from .primary_direct_scopes import _StatusHostClaim, _source_locals
        from .primary_sign import PrimaryRuntime
        from .primary_worker_consumer import _invoke
        self.require()
        scope, runtime = self.scope, self.runtime
        source = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x1BF75A0)
        worker = _source_locals(_invoke.__code__, runtime, rva=0x1BF75A0)
        if (self.stage != 'audit' or self.status_completed or scope._status_host is not None or
                runtime._program_calls or type(carrier) is not SimpleNamespace or cells != (0, 1, 2, 3) or
                source is None or source.get('vm') is not carrier or source.get('cells') is not cells or
                worker is None or worker.get('vm') is not carrier or worker.get('values') != self._arguments):
            raise PrimarySemanticUnavailable('request audit status carrier differs from its exact source ABI')
        claim = _StatusHostClaim(self, carrier, cells, self._arguments)
        scope._status_host = claim
        try:
            yield
            self.require()
            if not claim.normal_used or scope._audit is not None:
                raise PrimarySemanticUnavailable('request audit status child did not complete')
            self.status_completed = True
        finally:
            claim.active = False
            if scope._status_host is claim:
                scope._status_host = None

    def authorize_material(self, vm, claim):
        from .primary_direct_scopes import _source_locals
        from .primary_sign import PrimaryRuntime
        from .primary_sdk import update_material_control
        self.require()
        runtime = self.runtime
        update = _source_locals(update_material_control.__code__, runtime)
        source = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x1BF8090)
        if (self.stage != 'update' or not self.status_completed or self.material_used or source is None or
                update is None or tuple(update.get(key) for key in ('value', 'bit', 'operation', 'flag')) != self._arguments or
                claim.get('publicOwner') is not self.scope.public_owner or claim.get('parentCalls') != () or
                len(runtime._program_calls) != 1 or runtime._program_calls[0]['name'] != 'material-state' or
                runtime._program_calls[0]['arguments'] != (runtime.image_base + 0x6D88430,) or
                runtime._execute_depth != 1 or runtime._execute_thread != self.thread):
            raise PrimarySemanticUnavailable('request audit material initializer lacks its real ordered update')
        self.material_used = True


@contextmanager
def request_audit_begin(runtime):
    if getattr(runtime, 'primary_backend', 'reference') != 'direct':
        yield None
        return
    from .primary_request_audit import begin
    from .primary_signer import PrimarySigner
    scope = runtime.__dict__.get('_primary_direct_scope')
    source = sys._getframe(2)
    frame, public = source, None
    while frame is not None:
        if frame.f_code is PrimarySigner.complete_request.__code__:
            public = frame
            break
        frame = frame.f_back
    if (scope is None or not scope._valid_public() or source.f_code is not begin.__code__ or
            public is None or scope._request_audit is not None or scope._caller is not None or
            scope._status_host is not None or scope._audit is not None or runtime._program_calls):
        raise PrimarySemanticUnavailable('request audit requires its actual public completion begin')
    claim = _RequestAuditClaim(scope, source, source.f_back, public, _FACTORY)
    scope._request_audit = claim
    try:
        claim.require()
        yield claim
        claim.require()
        if claim.stage != 'complete' or not claim.status_completed:
            raise PrimarySemanticUnavailable('request audit pair did not finish its original source update')
        scope.report['requestAudit'] = dict(completed=True, publicSerial=claim.serial, materialInitialized=claim.material_used)
    finally:
        claim.active = False
        claim.source = claim.completion = claim.public = None
        if scope._request_audit is claim:
            scope._request_audit = None
        elif sys.exception() is None:
            raise PrimarySemanticUnavailable('request audit claim ownership changed before exit')


class _DeviceHandoffAuditClaim(_RequestAuditClaim):
    _arguments = (1, 61, 1, 0)
    _seed_flag = 0

    def __init__(self, scope, source, factory):
        if factory is not _FACTORY:
            raise InputError('device handoff audit requires its actual source pair')
        self.scope, self.runtime, self.owner = scope, scope.runtime, scope.device_owner
        self.source, self.completion, self.public = source, None, None
        self.thread, self.generation, self.serial = get_ident(), self.runtime._main_generation, self.owner.serial
        self.active, self.stage, self.status_completed, self.material_used = True, 'created', False, False
        self.write_start = None

    def valid(self):
        from .primary_worker_handoff import handoff
        from .primary_worker_consumer import consume_records
        from .primary_sign_lifecycle import region_at
        runtime, scope, source = self.runtime, self.scope, self.source
        frame = sys._getframe(1)
        while frame is not None and frame is not source:
            frame = frame.f_back
        consumer = frame
        while consumer is not None and consumer.f_code is not consume_records.__code__:
            consumer = consumer.f_back
        if (not self.active or frame is None or frame is not source or source.f_code is not handoff.__code__ or
                get_ident() != self.thread or consumer is None or not scope._valid_device() or
                scope.device_owner is not self.owner or not self.owner.valid() or self.owner.serial != self.serial or
                runtime.__dict__.get('_primary_direct_scope') is not scope or scope._request_audit is not self or
                runtime._main_generation != self.generation or runtime._active_main is not None or runtime._active_failed):
            return False
        actual = source.f_locals
        values = consumer.f_locals.get('arguments')
        names = ('receiver', 'tag', 'pointer', 'count', 'function', 'metadata', 'mode')
        region = region_at(runtime.memory, actual.get('frame'))
        return (actual.get('runtime') is runtime and consumer.f_locals.get('runtime') is runtime and
            type(values) is tuple and len(values) == 7 and tuple(actual.get(key) for key in names) == values and
            region is not None and region.name == '1CE6920.device_handoff_frame' and len(region.data) == 0x178 and
            actual.get('rbp') == region.address + 0x80)


@contextmanager
def device_handoff_audit(runtime):
    if getattr(runtime, 'primary_backend', 'reference') != 'direct':
        yield None
        return
    from .primary_worker_handoff import handoff
    scope = runtime.__dict__.get('_primary_direct_scope')
    source = sys._getframe(2)
    if (scope is None or not scope._valid_device() or source.f_code is not handoff.__code__ or
            scope._request_audit is not None or scope._status_host is not None or scope._audit is not None or
            runtime._program_calls):
        raise PrimarySemanticUnavailable('device handoff audit requires its actual running getToken callback')
    claim = _DeviceHandoffAuditClaim(scope, source, _FACTORY)
    scope._request_audit = claim
    try:
        claim.require()
        yield claim
        claim.require()
        if claim.stage != 'complete' or not claim.status_completed:
            raise PrimarySemanticUnavailable('device handoff audit did not complete its original pair')
        scope.report['deviceRequestAudit'] = dict(completed=True, materialInitialized=claim.material_used)
    finally:
        claim.active = False
        claim.source = None
        if scope._request_audit is claim:
            scope._request_audit = None
        elif sys.exception() is None:
            raise PrimarySemanticUnavailable('device handoff audit ownership changed before exit')
