from contextlib import contextmanager
from dataclasses import dataclass
from threading import get_ident, get_native_id
from time import monotonic
import os
import sys

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


_FACTORY = object()


@dataclass(frozen=True)
class _DeviceRequestPumpReceipt:
    parked: bool
    batch_completed: bool
    request_ticket: int


@dataclass(frozen=True)
class _DeviceRequestCallbackReceipt:
    sequence: int
    service: object
    runtime: object
    row: object
    pending_node: int
    record: int
    callback: int
    request_ticket: int
    generation: int


@dataclass
class _DeviceDrainGrant:
    ticket: tuple
    entry: object
    parked: tuple
    generation: int
    previous_batch: object
    batch: object = None
    active: bool = False


def _issue_drain(service, row, ticket):
    lease = service._registrar.current_lease()
    if (not service._draining or service._closing or service._closed or service._active_owner or
            not service._execution.locked() or lease.thread_id != service._owner[1] or
            lease.token is not service._close_token or not lease.active or lease.suspended or
            row.get('_device_drain_grant') is not None or _device_row(service) is not row):
        raise PrimarySemanticUnavailable('device drain requires its idle parked execution fence')
    entry = _park(service, row)
    return _DeviceDrainGrant(ticket, entry, service._park_signature(entry), service._runtime._main_generation,
                             getattr(service._runtime, 'worker_batch_states', {}).get(row['task']))


def _drain_entry(service, row, grant, advance):
    runtime = service._runtime
    entry = getattr(runtime, 'worker_entry_states', {}).get(row['task'])
    return (row.get('_device_drain_grant') is grant and entry is grant.entry and entry.failure is None and
            runtime._main_generation == grant.generation and entry.frame == grant.parked[4] and
            entry.local_list == grant.parked[5] and entry.iterations == grant.parked[1] + advance and
            row.get('source_frame') == entry.frame and not service._closed and not service._closing and
            service._failure is None)


def _activate_drain(service, row, ticket):
    grant = row.get('_device_drain_grant')
    if (type(grant) is not _DeviceDrainGrant or grant.active or grant.ticket != ticket or
            ticket[2] != 'drain' or not _drain_entry(service, row, grant, 0)):
        raise PrimarySemanticUnavailable('device drain lost its one fresh parked batch grant')
    grant.active = True


def _drain_callback(service, row, grant, state):
    if (type(grant) is not _DeviceDrainGrant or not grant.active or
            grant.ticket[2] != 'drain' or
            row.get('continuation_kind') != 'drain' or row.get('consumed_ticket') != grant.ticket[0] or
            row.get('thread_id') != grant.ticket[1] or not _drain_entry(service, row, grant, 1) or
            state is grant.previous_batch or grant.batch is not None and grant.batch is not state or
            state.local_list != grant.entry.local_list or state.current_node in state.invoked_nodes):
        return False
    transfer = state.transfer
    return (transfer is not None and transfer.phase == 'complete' and transfer.failure is None and
            transfer.source == state.task + 40 and transfer.destination == state.local_list and
            not transfer.lock_acquired and transfer.cleanup is not None and transfer.cleanup.phase == 'complete' and
            transfer.move is not None and transfer.move.phase == 'complete')


def _finish_drain(service, row, entry, batch):
    grant = row.get('_device_drain_grant')
    if grant is None:
        return
    runtime = service._runtime
    if (type(grant) is not _DeviceDrainGrant or not grant.active or not _drain_entry(service, row, grant, 1) or
            entry is not grant.entry or batch is not grant.batch or batch is grant.previous_batch or
            batch is None or batch.phase != 'complete' or batch.call_pending or batch.failure is not None or
            batch.cleanup is None or batch.cleanup.phase != 'complete' or
            row.get('continuation_kind') != 'drain' or row.get('consumed_ticket') != grant.ticket[0] or
            runtime.__dict__.get('_primary_device_request_owner') is not None or
            runtime.__dict__.get('_primary_direct_scope') is not None):
        raise PrimarySemanticUnavailable('device drain did not finish its one source batch before checkpoint')
    _revoke_drain(row)


def _revoke_drain(row):
    grant = row.pop('_device_drain_grant', None)
    if grant is not None:
        grant.active = False


def _device_row(service):
    runtime = service._runtime
    rows = [row for row in service._secondary if row['task'] == runtime.image_base + 0x6751C58]
    if len(rows) != 1:
        raise PrimarySemanticUnavailable('device request requires one actual source device row')
    row = rows[0]
    launch = row.get('_launch')
    if (not any(item is row for item in service._threads) or row.get('_kind') != 'secondary' or
            row.get('handle', 0) <= 0 or row.get('thread_id', 0) <= 0 or launch is None or
            launch.context != row.get('context') or launch.handle != row['handle'] or
            launch.thread_id != row['thread_id'] or launch.joined or launch.handle_closed or
            row.get('_source_chain', (None,))[0] != row.get('context') or
            row.get('_source_chain', (None,))[-1] != row['task'] or
            row.get('joined') or row.get('handle_closed') or row.get('host_failure') is not None or
            runtime.memory.load(row['task'] + 0xD8, 4) != 2):
        raise PrimarySemanticUnavailable('device request row differs from its source CRT launch chain')
    return row


def _park(service, row):
    runtime = service._runtime
    if service._failure is not None:
        raise service._failure_for_raise()
    entry = getattr(runtime, 'worker_entry_states', {}).get(row['task'])
    witness = row.get('_park_witness')
    leases = service._registrar._leases.get(row['thread_id'], ())
    if (row['state'] != 'parked_at_BD4B60' or row.get('callback_thread_id') != row['thread_id'] or
            not leases or not leases[-1].active or not leases[-1].suspended or
            leases[-1].thread_id != row['thread_id'] or leases[-1].registrar is not service._registrar or
            leases[-1].token is not service._close_token or row['thread_id'] not in service._crt_domains or
            witness is None or entry is None or witness[0] is not entry or entry.failure is not None or
            entry.call_pending or witness[1] != service._park_signature(entry) or
            witness[2] != row.get('consumed_ticket', 0) or row.get('source_frame') != entry.frame or
            row.get('resident_rva') != 0xBD4B60 or row.get('_ticket') is not None or
            not row['_checkpoint'].is_set() or row['_resume'].is_set() or
            runtime.__dict__.get('_primary_device_request_owner') is not None or
            runtime.__dict__.get('_primary_direct_scope') is not None):
        raise PrimarySemanticUnavailable('device request does not own its true source checkpoint')
    return entry


def _pending(service, witness):
    from .primary_request_transport import _Map
    runtime, memory = service._runtime, service._runtime.memory
    gate = runtime.image_base + 0x6751AB8
    signed = witness.sequence - (1 << 64) if witness.sequence >> 63 else witness.sequence
    node = _Map(runtime, gate + 24).find(signed)
    if (node != witness.pending_node or not node or memory.load(node + 48, 8) != witness.record or
            memory.load(node + 40, 8) != witness.record + 24 or
            memory.load(witness.record + 168, 8) != witness.callback or
            memory.load(memory.load(witness.callback, 8) + 40, 8) != runtime.image_base + 0xBDCA30):
        raise PrimarySemanticUnavailable('device request pending record or business callback changed')


def callback_witness(service):
    from .primary_request_transport import RequestTransportBinding, dispatch
    runtime = service._runtime
    owner = runtime.__dict__.get('_primary_device_request_owner')
    scope = runtime.__dict__.get('_primary_direct_scope')
    if (type(owner) is not _DeviceRequestOwner or owner.service is not service or not owner.valid() or
            owner.grant is not None or owner.row.get('continuation_kind') != 'request' or
            scope is None or scope.device_owner is not owner or not scope._valid_device()):
        raise PrimarySemanticUnavailable('outbound device request requires its real running callback owner')
    source, sending = None, None
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is RequestTransportBinding.send.__code__ and frame.f_locals.get('runtime') is runtime:
            sending = frame.f_locals
        if frame.f_code is dispatch.__code__ and frame.f_locals.get('runtime') is runtime:
            source = frame.f_locals
            break
        frame = frame.f_back
    row = owner.row
    if (source is None or sending is None or sending.get('self') is not runtime.request_transport or
            source.get('binding') is not runtime.request_transport or
            sending.get('sequence') != source.get('sequence') or row.get('_outbound_witness') is not None):
        raise PrimarySemanticUnavailable('outbound device request lacks its one actual transport send frame')
    witness = _DeviceRequestCallbackReceipt(source['sequence'], service, runtime, row, source['node'],
        source['record'], runtime.memory.load(source['record'] + 168, 8), row['_request_ticket'], runtime._main_generation)
    _pending(service, witness)
    row['_outbound_witness'] = witness
    return witness


def parked_witness(service):
    service._check_owner()
    runtime = service._runtime
    lease = service._registrar.current_lease()
    if (not service._active_owner or service._execution_tid != service._owner[1] or
            not service._execution.locked() or lease.thread_id != service._owner[1] or
            not lease.active or lease.suspended or service._failure is not None or
            runtime._active_main is not None or runtime._active_failed):
        raise InputError('parked device validation requires its actual owner execution fence')
    row = _device_row(service)
    _park(service, row)
    receipt, witness = row.get('_request_receipt'), row.get('_outbound_witness')
    batch = getattr(runtime, 'worker_batch_states', {}).get(row['task'])
    if (type(receipt) is not _DeviceRequestPumpReceipt or type(witness) is not _DeviceRequestCallbackReceipt or
            witness.service is not service or witness.runtime is not runtime or witness.row is not row or
            witness.generation != runtime._main_generation or
            receipt.request_ticket != witness.request_ticket or witness.request_ticket != row.get('consumed_ticket') or
            batch is None or batch.phase != 'complete' or batch.call_pending or
            batch.invoked_nodes != [row.get('_request_node')] or batch.cleanup is None or batch.cleanup.phase != 'complete' or
            not service._queues_empty(row['task'])):
        raise PrimarySemanticUnavailable('parked device result lost its exact one-batch and outbound witness')
    _pending(service, witness)
    return witness


def _wait_checkpoint(row, deadline, message):
    remaining = deadline - monotonic()
    if remaining <= 0 or not row['_checkpoint'].wait(remaining) or monotonic() >= deadline:
        raise PrimarySemanticUnavailable(message)


def pump(service):
    service._check_owner()
    if (service._active_owner or service._execution.locked() or service._execution_tid is not None or
            service._closed or service._closing or service._draining or service._failure is not None or
            service._gate.is_set() or getattr(service, '_request_pump_row', None) is not None or
            service._registrar._leases.get(service._owner[1])):
        raise InputError('device request pump requires idle owner without an execution lease')
    runtime = service._runtime
    deadline = monotonic() + 60.0
    with service._execution:
        with service._registrar.operation(token=service._close_token):
            row = _device_row(service)
            service._queues_empty(row['task'])
            head = row['task'] + 40
            node = runtime.memory.load(head + 8, 8)
            active = runtime.memory.load(node + 48, 8) if node != head else 0
            if (runtime.memory.load(head + 16, 8) != 1 or runtime.memory.load(row['task'] + 0x70, 8) or
                    not active or runtime.memory.load(active, 8) != runtime.image_base + 0x3FD6FF8 or
                    runtime.memory.load(active + 8, 8) != runtime.image_base + 0x6751840 or
                    runtime.memory.load(runtime.image_base + 0x3FD6FF8 + 40, 8) != runtime.image_base + 0xBD6170 or
                    row.get('_request_ticket') is not None or row.get('_request_started') is not None or
                    row['state'] != 'created_pending'):
                raise PrimarySemanticUnavailable('device pump requires its single original queued getToken callback')
            row['_request_node'], row['_request_active'], row['_request_started'] = node, active, True
            service._request_pump_row = row
    try:
        row['_start_gate'].set()
        _wait_checkpoint(row, deadline, 'device request did not reach its first original checkpoint within its total budget')
        with service._execution:
            with service._registrar.operation(token=service._close_token):
                entry = _park(service, row)
                if entry.iterations != 0 or entry.local_initialized:
                    raise PrimarySemanticUnavailable('device request first checkpoint is not pre-batch')
                if monotonic() >= deadline:
                    raise PrimarySemanticUnavailable('device request total budget expired before its source ticket')
                service._issue_ticket(row, 'request')
                row['_request_ticket'] = row['_ticket'][0]
        _wait_checkpoint(row, deadline, 'device request did not return to its next original checkpoint within its total budget')
        with service._execution:
            with service._registrar.operation(token=service._close_token):
                entry = _park(service, row)
                batch = getattr(runtime, 'worker_batch_states', {}).get(row['task'])
                if (entry.iterations != 1 or not entry.local_initialized or batch is None or
                        batch.phase != 'complete' or batch.call_pending or batch.invoked_nodes != [row['_request_node']] or
                        batch.cleanup is None or batch.cleanup.phase != 'complete' or not service._queues_empty(row['task']) or
                        row.get('consumed_ticket') != row['_request_ticket']):
                    raise PrimarySemanticUnavailable('device request did not finish exactly one source mode2 batch')
                if monotonic() >= deadline:
                    raise PrimarySemanticUnavailable('device request total budget expired before its proved return')
                receipt = _DeviceRequestPumpReceipt(True, True, row['_request_ticket'])
                row['_request_receipt'] = receipt
                return receipt
    except BaseException as failure:
        service._remember_failure(failure, row)
        raise
    finally:
        service._request_pump_row = None


class _DeviceRequestOwner:
    def __init__(self, runtime, service, row, domain, secondary, batch, state, lease, serial, factory):
        if factory is not _FACTORY:
            raise InputError('device request owner requires its original batch callback factory')
        self.runtime, self.service, self.row, self.domain = runtime, service, row, domain
        self.secondary, self.batch, self.state, self.lease = secondary, batch, state, lease
        self.thread, self.native_thread = get_ident(), get_native_id()
        self.serial, self.generation, self.active = serial, runtime._main_generation, True
        self.node, self.function, self.target = state.current_node, state.active, state.target
        self.grant = row.get('_device_drain_grant')

    def valid(self):
        from .primary_windows_threads import WindowsSDKThreadService, _LIVE_SERVICES
        from .primary_host_services import _ExecutionLease
        from .primary_worker_batch import run_mode2_batch, PhysicalWorkerBatch
        runtime, service, row, state = self.runtime, self.service, self.row, self.state
        if not self.active or get_ident() != self.thread or get_native_id() != self.native_thread:
            return False
        frame = sys._getframe(1)
        while frame is not None and frame is not self.batch:
            frame = frame.f_back
        domain = getattr(self.domain, 'gen', None)
        context = None if domain is None else domain.gi_frame
        leases = service._registrar._leases.get(self.native_thread, ())
        memory, base = runtime.memory, runtime.image_base
        return (type(service) is WindowsSDKThreadService and service in _LIVE_SERVICES and
            service._runtime is runtime and service._owner[0] == os.getpid() and service._owner[1] != self.native_thread and
            frame is self.batch and self.batch.f_code is run_mode2_batch.__code__ and
            self.batch.f_locals.get('runtime') is runtime and self.batch.f_locals.get('state') is state and
            type(state) is PhysicalWorkerBatch and state.task == base + 0x6751C58 and
            runtime.worker_batch_states.get(state.task) is state and state.phase == 'invoking' and state.call_pending and
            state.current_node == self.node and state.active == self.function and state.target == self.target and
            ((self.grant is None and row.get('continuation_kind') == 'request' and
              row.get('consumed_ticket') == row.get('_request_ticket') and
              self.node == row.get('_request_node') and self.function == row.get('_request_active')) or
             _drain_callback(service, row, self.grant, state)) and
            state.target == base + 0xBD6170 and memory.load(state.current_node + 48, 8) == state.active and
            memory.load(state.active, 8) == base + 0x3FD6FF8 and
            memory.load(state.active + 8, 8) == base + 0x6751840 and
            memory.load(base + 0x3FD6FF8 + 40, 8) == state.target and
            self.secondary.f_code is WindowsSDKThreadService._secondary_entry.__code__ and
            self.secondary.f_locals.get('self') is service and self.secondary.f_locals.get('row') is row and
            self.secondary.f_locals.get('domain') is self.domain and domain.gi_suspended and
            domain.gi_code is WindowsSDKThreadService._context.__wrapped__.__code__ and context is not None and
            context.f_locals.get('self') is service and context.f_locals.get('runtime') is runtime and
            service._execution.locked() and service._execution_tid == self.native_thread and not service._closed and
            service._failure is None and any(item is row for item in service._threads) and
            any(item is row for item in service._secondary) and row.get('_kind') == 'secondary' and
            row.get('state') == 'running' and row.get('task') == state.task and
            row.get('callback_thread_id') == row.get('thread_id') == self.native_thread and row.get('handle', 0) > 0 and
            row.get('_launch') is not None and row.get('_source_chain', (None,))[0] == row.get('context') and
            row.get('_source_chain', (None,))[-1] == state.task and not row.get('handle_closed') and
            not row.get('source_completed') and row.get('host_failure') is None and
            row.get('_device_direct_serial') == self.serial == service._device_request_serial and
            type(self.lease) is _ExecutionLease and self.lease.registrar is service._registrar and
            self.lease.thread_id == self.native_thread and self.lease.token is service._close_token and
            self.lease.active and not self.lease.suspended and not self.lease.closing and
            bool(leases) and leases[-1] is self.lease and service._registrar._runtime is runtime and
            runtime._active_main is None and not runtime._active_failed and runtime._main_generation == self.generation and
            runtime.__dict__.get('_primary_device_request_owner') is self and
            all(runtime.__dict__.get(key) is None for key in ('_primary_public_direct_owner', '_primary_close_direct_owner',
                '_primary_provider_initialization_owner', '_primary_sdk_worker_owner', '_primary_secondary_postfetch_owner',
                '_primary_notification_worker_owner')))


@contextmanager
def device_request_call(runtime, state):
    if getattr(runtime, 'primary_backend', 'reference') != 'direct' or state.task != runtime.image_base + 0x6751C58:
        yield
        return
    from .primary_worker_batch import run_mode2_batch
    from .primary_windows_threads import WindowsSDKThreadService
    from .primary_direct_scopes import PrimaryDirectScope
    batch = sys._getframe(2)
    source = batch
    while source is not None and source.f_code is not WindowsSDKThreadService._secondary_entry.__code__:
        source = source.f_back
    if (batch.f_code is not run_mode2_batch.__code__ or batch.f_locals.get('runtime') is not runtime or
            batch.f_locals.get('state') is not state or source is None or runtime._execute_depth or
            runtime._program_calls or runtime.__dict__.get('_primary_direct_scope') is not None or
            runtime.__dict__.get('_primary_device_request_owner') is not None):
        raise PrimarySemanticUnavailable('device request requires its actual resolved mode2 callback')
    service, row, domain = (source.f_locals.get(key) for key in ('self', 'row', 'domain'))
    lease = service._registrar.current_lease()
    service._device_request_serial = getattr(service, '_device_request_serial', 0) + 1
    row['_device_direct_serial'] = service._device_request_serial
    owner = _DeviceRequestOwner(runtime, service, row, domain, source, batch, state, lease,
                                service._device_request_serial, _FACTORY)
    runtime._primary_device_request_owner = owner
    scope = None
    try:
        if not owner.valid():
            raise PrimarySemanticUnavailable('device callback owner lost its real task node, thread, control or lease')
        if owner.grant is not None:
            owner.grant.batch = state
        scope = PrimaryDirectScope(runtime, device_owner=owner, execution_report=row.setdefault('device_direct_scope', {}))
        scope.install()
        yield
        if not owner.valid():
            raise PrimarySemanticUnavailable('device callback changed ownership before source return')
    finally:
        primary, failure = sys.exception(), None
        if scope is not None:
            try:
                scope.close()
            except BaseException as error:
                failure = error
        owner.active = False
        owner.secondary = owner.batch = owner.domain = None
        if runtime.__dict__.get('_primary_device_request_owner') is owner:
            runtime.__dict__.pop('_primary_device_request_owner')
        elif failure is None:
            failure = InputError('device callback owner changed before exit')
        if failure is not None:
            if primary is not None:
                primary.add_note('device callback scope cleanup failed: ' + type(failure).__name__)
            else:
                raise failure
