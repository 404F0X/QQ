from contextlib import contextmanager
import os
import sys
from threading import get_ident, get_native_id
from types import SimpleNamespace

from .errors import InputError
from .primary_request_audit_scope import _RequestAuditClaim
from .primary_vm import PrimarySemanticUnavailable


_FACTORY = object()
_NAMES = ('receiver', 'tag', 'pointer', 'count', 'function', 'metadata', 'mode')
_TABLE = (0x142A0, 0x1D27500, 0x1D27510, 0x28F0, 0x1FE0, 0x1D27530)


def _empty_source_metadata(memory, address, parent):
    guard = getattr(memory, '_consumed_mgf_guard', None)
    if guard is not None:
        guard.guard_overlap(address, 48)
    region, ignored = memory._span(address, 48)
    if region is not parent or any(other is not parent and other.data.obj is parent.data.obj for other in memory._regions):
        return False
    return memory.load(address, 2) == 0 and memory.load(address + 24, 2) == 0


def _source_layout(runtime, collector_frame, collector_rbp, arguments, frame, rbp):
    from .primary_logger import _String
    from .primary_sign_lifecycle import region_at
    if (type(arguments) is not tuple or len(arguments) != 7 or any(type(value) is not int for value in arguments) or
            any(type(value) is not int for value in (collector_frame, collector_rbp, frame, rbp))):
        return False
    memory, base = runtime.memory, runtime.image_base
    parent, local = region_at(memory, collector_frame), region_at(memory, frame)
    if (parent is None or parent.address != collector_frame or len(parent.data) != 0x2738 or
            parent.name != '1D20B30.module_collector_frame' or collector_rbp != collector_frame + 0x80 or
            local is None or local.address != frame or len(local.data) != 0x178 or
            local.name != '1CE6920.device_handoff_frame' or rbp != frame + 0x80):
        return False
    receiver, tag, pointer, count, function, metadata, mode = arguments
    if (receiver != base + 0x6751AB8 or tag != collector_rbp + 0x2228 or
            function != collector_rbp + 0x21E0 or metadata != collector_rbp + 0x2460 or mode != 1):
        return False
    serialized = collector_rbp + 0x2590
    long = memory.load(serialized, 1) & 1
    expected_pointer = memory.load(serialized + 16, 8) if long else serialized + 1
    expected_count = memory.load(serialized + 8, 4) if long else memory.load(serialized, 1) >> 1
    active = memory.load(function + 32, 8)
    return (pointer == expected_pointer and count == expected_count and
        active == function + 8 and memory.load(active, 8) == base + 0x414BB08 and
        tuple(memory.load(base + 0x414BB08 + index * 8, 8) for index in range(6)) == tuple(base + rva for rva in _TABLE) and
        _String.read(runtime, tag).value() == b'ReportDylib' and _empty_source_metadata(memory, metadata, parent))


class _NotificationHandoffAuditClaim(_RequestAuditClaim):
    _arguments = (1, 61, 1, 0)
    _seed_flag = 0

    def __init__(self, scope, source, collector, factory):
        if factory is not _FACTORY:
            raise InputError('notification handoff audit requires its canonical factory')
        self.scope, self.runtime, self.owner = scope, scope.runtime, scope.notification_owner
        self.source, self.collector = source, collector
        self.completion = self.public = None
        self.thread, self.native_thread, self.process = get_ident(), get_native_id(), os.getpid()
        self.generation, self.serial, self.lease = self.runtime._main_generation, self.owner.serial, self.owner.lease
        self.active, self.stage, self.status_completed, self.material_used = True, 'created', False, False
        self.write_start = None
        self.status_wrapper_seen = self.material_wrapper_completed = False
        self.material_wrapper = None

    def valid(self):
        from .primary_direct_scopes import PrimaryDirectScope
        from .primary_notification_modules import _ModuleCollectorClaim, collect
        from .primary_sign import PrimaryRuntime
        from .primary_worker_consumer import _invoke
        from .primary_worker_handoff import handoff, invoke
        runtime, scope, source, collector = self.runtime, self.scope, self.source, self.collector
        if (not self.active or self.process != os.getpid() or self.thread != get_ident() or
                self.native_thread != get_native_id() or type(scope) is not PrimaryDirectScope or
                type(collector) is not _ModuleCollectorClaim or source is None or
                source.f_code is not handoff.__code__ or scope._request_audit is not self or
                runtime.__dict__.get('_primary_direct_scope') is not scope or scope.runtime is not runtime or
                scope.notification_owner is not self.owner or collector.owner is not self.owner or
                collector.scope is not scope or collector.runtime is not runtime or
                self.owner.serial != self.serial or self.owner.lease is not self.lease or
                collector.serial != self.serial or collector.lease is not self.lease or
                self.owner.generation != self.generation or collector.generation != self.generation or
                runtime._main_generation != self.generation or runtime._active_main is not None or runtime._active_failed):
            return False
        frame = sys._getframe(1)
        while frame is not None and frame is not source:
            frame = frame.f_back
        if frame is not source or scope.require_module_collector_phase() is not collector:
            return False
        dispatch = source.f_back
        wrapper = None if dispatch is None else dispatch.f_back
        worker = None if wrapper is None else wrapper.f_back
        producer = None if worker is None else worker.f_back
        if (dispatch is None or dispatch.f_code is not invoke.__code__ or wrapper is None or
                wrapper.f_code is not PrimaryRuntime.invoke.__code__ or worker is None or worker.f_code is not _invoke.__code__ or
                producer is not collector.source or producer is None or producer.f_code is not collect.__code__):
            return False
        actual = source.f_locals
        values = tuple(actual.get(key) for key in _NAMES)
        calling, supplied, produced = wrapper.f_locals, worker.f_locals, dispatch.f_locals
        return (actual.get('runtime') is runtime and calling.get('self') is runtime and calling.get('rva') == 0x1CE6920 and
            type(calling.get('cells')) is tuple and calling.get('cells') == tuple(range(7)) and
            supplied.get('runtime') is runtime and supplied.get('rva') == 0x1CE6920 and supplied.get('values') == values and
            supplied.get('vm') is calling.get('vm') and type(calling.get('vm')) is SimpleNamespace and
            produced.get('runtime') is runtime and produced.get('rva') == 0x1CE6920 and produced.get('values') == values and
            collector.handoff_audit_started is True and
            _source_layout(runtime, collector.frame, producer.f_locals.get('rbp'), values, actual.get('frame'), actual.get('rbp')))

    def setting(self, carrier, rva, cells, *, completed):
        from .primary_direct_scopes import _source_locals
        from .primary_sign import PrimaryRuntime
        from .primary_worker_consumer import _invoke
        self.require()
        source = _source_locals(PrimaryRuntime.invoke.__code__, self.runtime, rva=rva)
        worker = _source_locals(_invoke.__code__, self.runtime, rva=rva)
        if (rva not in (0x1BF75A0, 0x1BF8090) or type(completed) is not bool or
                type(carrier) is not SimpleNamespace or type(cells) is not tuple or cells != (0, 1, 2, 3) or
                source is None or worker is None or source.get('vm') is not carrier or source.get('cells') is not cells or
                worker.get('vm') is not carrier or worker.get('values') != self._arguments or
                tuple(carrier.cells.value(index) for index in range(4)) != self._arguments or self.runtime._program_calls):
            raise PrimarySemanticUnavailable('notification handoff wrapper lost its exact source carrier and ABI')
        if rva == 0x1BF75A0:
            if completed or self.stage != 'audit' or self.status_completed or self.status_wrapper_seen:
                raise PrimarySemanticUnavailable('notification handoff status wrapper is stale or repeated')
            self.status_wrapper_seen = True
        elif not completed:
            if self.stage != 'update' or not self.status_completed or self.material_wrapper is not None or self.material_wrapper_completed:
                raise PrimarySemanticUnavailable('notification handoff material wrapper is out of order')
            self.material_wrapper = carrier, cells
        else:
            if (self.stage != 'update' or not self.status_completed or self.material_wrapper is None or
                    self.material_wrapper[0] is not carrier or self.material_wrapper[1] is not cells or self.material_wrapper_completed):
                raise PrimarySemanticUnavailable('notification handoff material completion lost its original wrapper')
            self.material_wrapper_completed = True
            self.material_wrapper = None

    def program(self, name):
        self.require()
        if not ((name == 'status-audit' and self.stage == 'audit' and self.status_wrapper_seen and not self.status_completed) or
                (name == 'material-state' and self.stage == 'update' and self.status_completed and self.material_wrapper is not None)):
            raise PrimarySemanticUnavailable('notification handoff does not authorize this audit program')


@contextmanager
def notification_handoff_audit(runtime):
    from .primary_direct_scopes import PrimaryDirectScope
    from .primary_worker_handoff import handoff
    scope = runtime.__dict__.get('_primary_direct_scope')
    source = sys._getframe(2)
    if (getattr(runtime, 'primary_backend', 'reference') != 'direct' or type(scope) is not PrimaryDirectScope or
            not scope._valid_notification() or source.f_code is not handoff.__code__ or scope._request_audit is not None or
            scope._caller is not None or scope._status_host is not None or scope._audit is not None or runtime._program_calls):
        raise PrimarySemanticUnavailable('notification handoff audit requires its current canonical collector call')
    collector = scope.require_module_collector_phase()
    if getattr(collector, 'handoff_audit_started', False):
        raise PrimarySemanticUnavailable('notification handoff audit cannot consume its collector twice')
    claim = _NotificationHandoffAuditClaim(scope, source, collector, _FACTORY)
    collector.handoff_audit_started = True
    scope._request_audit = claim
    try:
        claim.require()
        yield claim
        claim.require()
        if (claim.stage != 'complete' or not claim.status_completed or not claim.status_wrapper_seen or
                not claim.material_wrapper_completed or claim.material_wrapper is not None):
            raise PrimarySemanticUnavailable('notification handoff audit did not complete its original pair')
        scope.report['notificationHandoffAudit'] = dict(completed=True, materialInitialized=claim.material_used)
    finally:
        claim.active = False
        claim.source = claim.collector = claim.lease = claim.material_wrapper = None
        claim.owner = claim.runtime = claim.scope = None
        if scope._request_audit is claim:
            scope._request_audit = None
        elif sys.exception() is None:
            raise PrimarySemanticUnavailable('notification handoff audit ownership changed before exit')


def handoff_audit(runtime):
    from .primary_request_audit_scope import device_handoff_audit
    scope = runtime.__dict__.get('_primary_direct_scope')
    if getattr(runtime, 'primary_backend', 'reference') == 'direct' and scope is not None and scope.notification_owner is not None:
        return notification_handoff_audit(runtime)
    return device_handoff_audit(runtime)
