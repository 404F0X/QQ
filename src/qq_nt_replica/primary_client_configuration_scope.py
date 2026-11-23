"""Finite client-configuration source issuer; never a device/notify capability."""
from contextlib import contextmanager
import os
import sys
from threading import get_ident, get_native_id

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


_FACTORY = object()
_IMAGES = {}
_SERVICES = {}
_OWNERS = {}


def _frame(code, runtime):
    frame = sys._getframe(1)
    while frame is not None:
        values = frame.f_locals
        if frame.f_code is code and (values.get('runtime') is runtime or values.get('self') is runtime):
            return frame
        frame = frame.f_back
    return None


class _Image:
    def __init__(self, signer, regions, token):
        if token is not _FACTORY:
            raise InputError('client image requires its original fresh installer')
        self.signer, self.memory, self.base = signer, signer.memory, signer.image_base
        self.regions, self.source, self.epoch = regions, None, None
        self.debts, self.owners, self.rows = [], {}, []
        self.row_receipts = []
        self.receivers = []

    def validate(self, runtime):
        from .primary_shared_locale import _SharedLocaleSource
        signer, source = self.signer, self.source
        if (_IMAGES.get(signer) is not self or getattr(signer, '_client_configuration_image', None) is not self or
                signer.memory is not self.memory or signer.image_base != self.base or signer.runtime is not runtime or
                runtime._primary_entry_owner is not signer or runtime.memory is not self.memory or runtime.image_base != self.base or
                type(source) is not _SharedLocaleSource or signer._shared_locale_image is not source or source.epoch is not self.epoch):
            raise InputError('client configuration original image identity/epoch changed')
        source.validate_image(runtime)
        for address, region, size in self.regions:
            actual, offset = self.memory._span(address, size)
            if actual is not region or offset or region.address != address or len(region.data) != size:
                raise InputError('client configuration exact source backing replaced')
        return self


def premap(signer, spans):
    from .primary_client_configuration import install_image
    from .primary_memory import PrimaryMemoryLimit
    from .primary_signer import PrimarySigner
    source = sys._getframe(1)
    if (type(signer) is not PrimarySigner or source.f_code is not install_image.__code__ or
            source.f_back.f_code is not PrimarySigner._initialize_image.__code__ or source.f_back.f_locals.get('self') is not signer):
        raise InputError('client pre-map requires its actual fixed-source installer')
    if signer in _IMAGES or getattr(signer, '_client_configuration_image', None) is not None:
        raise InputError('client configuration repeated fresh image installation')
    memory, base = signer.memory, signer.image_base
    # Check every interval before publishing even the first mapping.
    for rva, raw, readonly in spans:
        start, end = base + rva, base + rva + len(raw)
        if any(start < region.address + len(region.data) and region.address < end for region in memory._regions):
            raise PrimaryMemoryLimit('client configuration fresh image overlaps existing memory')
    regions = []
    for rva, raw, readonly in spans:
        address = base + rva
        memory.map(address, raw if readonly else bytearray(raw), initialized=True, name='fixed client configuration source image')
        region, offset = memory._span(address, len(raw))
        regions.append((address, region, len(raw)))
    image = _Image(signer, tuple(regions), _FACTORY)
    _IMAGES[signer] = image
    signer._client_configuration_image = image
    return image


def bind_image(signer):
    from .primary_shared_locale import _SharedLocaleSource
    from .primary_signer import PrimarySigner
    image = _IMAGES.get(signer)
    source = getattr(signer, '_shared_locale_image', None)
    if (sys._getframe(1).f_code is not PrimarySigner._initialize_image.__code__ or
            type(image) is not _Image or signer._client_configuration_image is not image or image.source is not None or
            type(source) is not _SharedLocaleSource or source.signer is not signer or source.memory is not image.memory or source.base != image.base):
        raise InputError('client image requires the subsequently born actual shared-locale image')
    image.source, image.epoch = source, source.epoch
    from .primary_client_configuration_startup import bind_image as bind_startup
    bind_startup(signer, image)


def image_for(runtime):
    image = _IMAGES.get(getattr(runtime, '_primary_entry_owner', None))
    if type(image) is not _Image:
        raise InputError('client configuration has no original fresh image receipt')
    return image.validate(runtime)


def bind_service(service):
    from .primary_windows_signer import WindowsSigner
    owner = getattr(service._observer_factory, '__self__', None)
    if type(owner) is not WindowsSigner:
        # Legacy standalone services acquire no client source capability.
        return
    image = image_for(service._runtime)
    if service in _SERVICES:
        raise InputError('client thread service already bound')
    if (owner._threads is not service or
            owner._signer is not image.signer or owner._registrar is not service._registrar):
        raise InputError('client service requires its original Windows factory owner')
    binding = (image, service._runtime, service._registrar, owner)
    _SERVICES[service] = binding
    original = (image, service, service._runtime, service._registrar, image.signer, binding)
    _OWNERS[owner] = original
    owner._client_configuration_close = original
    from .primary_client_configuration_startup import bind_service_kernel
    bind_service_kernel(service)


def preflight_owner(owner):
    from .primary_client_configuration_startup import preflight_srw,preflight_request_stage
    preflight_request_stage(owner)
    preflight_srw(owner)
    original = _OWNERS.get(owner)
    anchor = getattr(owner, '_client_configuration_close', None)
    if original is None and anchor is None:
        return
    if original is None or anchor is not original:
        raise InputError('client close original Windows owner registry/anchor changed')
    image, service, runtime, registrar, signer, binding = original
    if not image.debts:
        return
    if (owner._threads is not service or owner._signer is not signer or signer.runtime is not runtime or
            owner._registrar is not registrar or _SERVICES.get(service) is not binding):
        raise InputError('client close original owner/service/runtime registry changed')
    preflight_close(service)


def preflight_close(service):
    binding = _SERVICES.get(service)
    if binding is None:
        return
    image, runtime, registrar, owner = binding
    if service._runtime is not runtime or service._registrar is not registrar or registrar._runtime is not runtime:
        raise InputError('client close original service/runtime/registrar replaced')
    image.validate(runtime)
    if image.debts:
        raise PrimarySemanticUnavailable('client configuration retains source owner/thread/callback/module dependencies')


def startup_creation(service):
    from .primary_client_configuration import create_startup
    from .primary_sign_lifecycle import _SDKWorkerOwner
    runtime = service._runtime
    image = image_for(runtime)
    from .primary_client_configuration_startup import require_request_stage
    require_request_stage(runtime)
    owner = require_creator(service)
    if (_frame(create_startup.__code__, runtime) is None or _SERVICES.get(service, (None,))[0] is not image):
        raise PrimarySemanticUnavailable('client startup requires its actual SDK creator source and lease')
    receipt = {'image': image, 'service': service, 'creator': owner, 'row': None}
    image.debts.append(('startup', receipt))
    return receipt


def register_owner(runtime, pointer):
    from .primary_client_configuration import startup_entry
    from .primary_sign_lifecycle import region_at
    image = image_for(runtime)
    owner = require_owner(runtime, 'client_startup')
    if _frame(startup_entry.__code__, runtime) is None or pointer in image.owners:
        raise InputError('client owner requires its original startup allocation')
    region = region_at(runtime.memory, pointer)
    if region is None or region.address != pointer or len(region.data) != 32 or runtime.allocations.get(pointer) != 32:
        raise InputError('client owner requires exact source allocation backing')
    receipt = (pointer, region, owner.row)
    image.owners[pointer] = receipt
    image.debts.append(('owner', receipt))


def validate_owner(runtime, pointer):
    image = image_for(runtime)
    receipt = image.owners.get(pointer)
    if receipt is None or not any(kind == 'owner' and issued is receipt for kind, issued in image.debts):
        raise PrimarySemanticUnavailable('client raw owner has no source startup allocation')
    actual, offset = runtime.memory._span(pointer, 32)
    if actual is not receipt[1] or offset or runtime.allocations.get(pointer) != 32:
        raise InputError('client raw owner allocation backing changed')
    return receipt


def secondary_creation(service, context, start, control, pointer):
    from .primary_client_configuration import start_owner
    from .primary_feature_notifications import construct_thread
    runtime = service._runtime
    owner = require_owner(runtime, 'client_startup')
    image = image_for(runtime)
    receipt = validate_owner(runtime, pointer)
    source = _frame(start_owner.__code__, runtime)
    building = _frame(construct_thread.__code__, runtime)
    if (owner.service is not service or source is None or source.f_locals.get('owner') != pointer or building is None or
            runtime.memory.load(control + 8, 8) != runtime.image_base + 0x1C50F70):
        raise PrimarySemanticUnavailable('client thread capture requires its actual startup and BD4FA0 construction')
    regions = []
    for address, size in ((context,40),(start,16),(control,24)):
        region, offset = runtime.memory._span(address,size)
        if offset or region.address != address or len(region.data) != size or runtime.allocations.get(address) != size:
            raise InputError('client thread construction backing differs from its original exact allocation')
        regions.append((address,region,size))
    return {'image': image, 'owner': receipt, 'context': context, 'start': start, 'control': control,
            'regions': tuple(regions), 'row': None}


def entry_preflight(service, row, parameter=None):
    from .primary_windows_threads import WindowsSDKThreadService
    runtime=service._runtime
    image=image_for(runtime)
    source=sys._getframe(1)
    expected=WindowsSDKThreadService._notification_entry if row.get('_kind')=='client_startup' else WindowsSDKThreadService._secondary_entry
    receipt=row.get('_client_receipt')
    binding=_SERVICES.get(service)
    if (source.f_code is not expected.__code__ or source.f_locals.get('self') is not service or
            source.f_locals.get('row') is not row or
            not any(item is row and issued is receipt for item,issued in image.row_receipts) or
            receipt.get('entry_source') is not None or binding is None or binding[0] is not image or
            binding[1] is not runtime or binding[2] is not service._registrar or
            binding[3]._threads is not service or binding[3]._signer is not image.signer or
            row.get('thread_id') != get_native_id() or row.get('callback_thread_id') != get_native_id() or
            service._execution_tid != get_native_id() or not service._execution.locked()):
        raise InputError('client native entry lost its original creation/owner/image/thread receipt')
    lease=service._registrar.current_lease()
    if not lease.active or lease.suspended or lease.registrar is not service._registrar or lease.thread_id != get_native_id():
        raise InputError('client native entry has no actual unsuspended original execution lease')
    if row['_kind']=='client_startup':
        if (parameter not in (None,0) or row.get('declared_parameter') != 0 or
                receipt.get('callback') is not row.get('_callback') or type(row.get('_callback')) is not service._callback_type):
            raise InputError('client startup native parameter differs from its exact NULL source argument')
        return
    if (row.get('_launch') is not receipt.get('launch') or service._worker_bridge is not receipt.get('bridge') or
            receipt['launch'].context != receipt['context'] or receipt['launch'].handle != row.get('handle') or
            receipt['launch'].thread_id != row.get('thread_id')):
        raise InputError('client native entry requires its original personally issued bridge launch instance')
    validate_owner(runtime,row['task'])
    for address,original,size in receipt['regions']:
        actual,offset=runtime.memory._span(address,size)
        if actual is not original or offset or runtime.allocations.get(address) != size:
            raise InputError('client native entry construction backing replaced before source execution')
    if (runtime.memory.load(receipt['context'],8) != runtime.image_base+0x7879A0 or
            runtime.memory.load(receipt['context']+8,8) != receipt['start'] or
            runtime.memory.load(receipt['start'],8) != runtime.image_base+0xBD55C0 or
            runtime.memory.load(receipt['start']+8,8) != receipt['control'] or
            runtime.memory.load(receipt['control']+8,8) != runtime.image_base+0x1C50F70 or
            runtime.memory.load(receipt['control']+16,8) != row['task']):
        raise InputError('client native entry original callback/capture chain changed')


class _ClientOwner:
    def __init__(self, service, row, domain, source, token):
        if token is not _FACTORY:
            raise InputError('client owner requires its original thread entry')
        self.service, self.runtime, self.row, self.domain, self.source = service, service._runtime, row, domain, source
        self.image = image_for(self.runtime)
        self.thread, self.native_thread, self.process = get_ident(), get_native_id(), os.getpid()
        self.lease = service._registrar.current_lease()
        self.generation, self.serial = self.runtime._main_generation, object()
        self.active, self.producer = True, None

    def valid(self):
        from .primary_host_services import _ExecutionLease
        from .primary_windows_threads import WindowsSDKThreadService, _LIVE_SERVICES
        runtime, service, row = self.runtime, self.service, self.row
        if not self.active or (self.thread, self.native_thread, self.process) != (get_ident(), get_native_id(), os.getpid()):
            return False
        self.image.validate(runtime)
        source = self.source
        code = WindowsSDKThreadService._notification_entry.__code__ if row.get('_kind') == 'client_startup' else WindowsSDKThreadService._secondary_entry.__code__
        found = _frame(code, service)
        receipt = row.get('_client_receipt')
        binding = _SERVICES.get(service)
        host = binding[3] if binding is not None else None
        original = _OWNERS.get(host)
        leases = service._registrar._leases.get(self.native_thread, ())
        generator = getattr(self.domain, 'gen', None)
        if (type(service) is not WindowsSDKThreadService or found is not source or source.f_locals.get('row') is not row or
                source.f_locals.get('domain') is not self.domain or service not in _LIVE_SERVICES or
                binding is None or binding[0] is not self.image or binding[1] is not runtime or
                binding[2] is not service._registrar or original is None or original[5] is not binding or
                getattr(host, '_client_configuration_close', None) is not original or
                host._threads is not service or host._signer is not self.image.signer or host._registrar is not binding[2] or
                service._runtime is not runtime or
                service._closed or service._closing or service._failure is not None or service._execution_tid != self.native_thread or
                not service._execution.locked() or row.get('state') != 'running' or
                row.get('thread_id') != self.native_thread or row.get('callback_thread_id') != self.native_thread or
                self.native_thread == service._owner[1] or not any(item is row for item in service._threads) or
                not row.get('handle') or row.get('handle_closed') or row.get('source_completed') or row.get('host_failure') is not None or
                type(receipt) is not dict or receipt.get('image') is not self.image or receipt.get('row') is not row or
                not any(item is row and issued is receipt for item, issued in self.image.row_receipts) or
                generator is None or not generator.gi_suspended or
                generator.gi_code is not WindowsSDKThreadService._context.__wrapped__.__code__ or
                generator.gi_frame is None or generator.gi_frame.f_locals.get('self') is not service or
                type(self.lease) is not _ExecutionLease or self.lease.registrar is not service._registrar or
                self.lease.thread_id != self.native_thread or not self.lease.active or self.lease.suspended or self.lease.closing or
                not leases or leases[-1] is not self.lease or runtime._main_generation != self.generation or
                runtime._active_main is not None or runtime._active_failed or
                runtime.__dict__.get('_primary_client_configuration_owner') is not self):
            return False
        if row['_kind'] == 'client_startup' and (row.get('_callback') is not receipt.get('callback') or
                type(row.get('_callback')) is not service._callback_type or row.get('declared_parameter') != 0):
            return False
        if row['_kind'] == 'client_loop':
            from .primary_client_configuration import loop, invoke as client_invoke
            from .primary_sign import PrimaryRuntime
            from .primary_worker_consumer import _invoke
            from .primary_thread_dispatch import tuple_entry, adapter, crt_entry
            pointer = row['task']
            if validate_owner(runtime, pointer) is not receipt.get('owner'):
                return False
            launch = row.get('_launch')
            if (launch is None or launch is not receipt.get('launch') or service._worker_bridge is not receipt.get('bridge') or
                    launch.context != row['context'] or launch.handle != row['handle'] or
                    launch.thread_id != self.native_thread or launch.joined or launch.handle_closed or
                    row.get('_source_chain') != (receipt['context'], receipt['start'], receipt['control'], pointer)):
                return False
            running = _frame(loop.__code__, runtime)
            if running is not None:
                # adapter has already source-freed start16; use its captured arguments,
                # while context40/control24 remain live throughout the loop call.
                tuple_call, adapt, crt = (_frame(code, runtime) for code in
                    (tuple_entry.__code__,adapter.__code__,crt_entry.__code__))
                dispatch = running.f_back
                wrapper = None if dispatch is None else dispatch.f_back
                worker = None if wrapper is None else wrapper.f_back
                if (tuple_call is None or adapt is None or crt is None or
                        dispatch is None or dispatch.f_code is not client_invoke.__code__ or
                        dispatch.f_locals.get('rva') != 0x1C50F70 or dispatch.f_locals.get('values') != (pointer,) or
                        wrapper is None or wrapper.f_code is not PrimaryRuntime.invoke.__code__ or
                        wrapper.f_locals.get('rva') != 0x1C50F70 or wrapper.f_locals.get('cells') != (0,) or
                        worker is None or worker.f_code is not _invoke.__code__ or worker.f_back is not tuple_call or
                        worker.f_locals.get('values') != (pointer,) or worker.f_locals.get('vm') is not wrapper.f_locals.get('vm') or
                        tuple_call.f_locals.get('control') != receipt['control'] or
                        adapt.f_locals.get('start') != receipt['start'] or
                        adapt.f_locals.get('target') != runtime.image_base + 0xBD55C0 or
                        adapt.f_locals.get('argument') != receipt['control'] or
                        crt.f_locals.get('context') != receipt['context']):
                    return False
                for address, original, size in (receipt['regions'][0],receipt['regions'][2]):
                    current, offset = runtime.memory._span(address,size)
                    if current is not original or offset or runtime.allocations.get(address) != size:
                        return False
                if (runtime.memory.load(receipt['control']+8,8) != runtime.image_base + 0x1C50F70 or
                        runtime.memory.load(receipt['control']+16,8) != pointer):
                    return False
        return True


def require_owner(runtime, kind=None):
    owner = runtime.__dict__.get('_primary_client_configuration_owner')
    if type(owner) is not _ClientOwner or owner.runtime is not runtime or not owner.valid() or kind is not None and owner.row['_kind'] != kind:
        raise PrimarySemanticUnavailable('client configuration requires its original running source thread and active lease')
    return owner


def require_producer_entry(runtime, pointer):
    from .primary_client_configuration import loop
    owner = require_owner(runtime, 'client_loop')
    validate_owner(runtime, pointer)
    source = _frame(loop.__code__, runtime)
    if source is None or source.f_locals.get('owner') != pointer or owner.row['task'] != pointer or owner.producer is not None:
        raise PrimarySemanticUnavailable('client producer requires its actual loop/capture before allocating a frame')
    return owner


@contextmanager
def worker_call(service, row, domain):
    from .primary_direct_scopes import PrimaryDirectScope
    from .primary_windows_threads import WindowsSDKThreadService
    runtime = service._runtime
    source = sys._getframe(2)
    expected = WindowsSDKThreadService._notification_entry if row.get('_kind') == 'client_startup' else WindowsSDKThreadService._secondary_entry
    receipt = row.get('_client_receipt')
    image = image_for(runtime)
    if (source.f_code is not expected.__code__ or runtime.__dict__.get('_primary_direct_scope') is not None or
            not any(item is row and issued is receipt for item, issued in image.row_receipts) or
            receipt.get('entry_source') is not None or
            runtime.__dict__.get('_primary_client_configuration_owner') is not None):
        raise InputError('client scope requires its actual inactive thread entry')
    receipt['entry_source'] = source
    owner = _ClientOwner(service, row, domain, source, _FACTORY)
    runtime._primary_client_configuration_owner = owner
    scope = None
    try:
        if not owner.valid():
            raise InputError('client source thread identity is invalid')
        scope = PrimaryDirectScope(runtime, client_owner=owner, execution_report=row.setdefault('direct_scope', {}))
        scope.install()
        yield owner
        require_owner(runtime)
    finally:
        # Host scope retirement does not consume any source-owned frame/callback.
        primary = sys.exception()
        try:
            if scope is not None:
                scope.close()
        except BaseException as failure:
            if primary is None:
                raise
            primary.add_note('client host scope retirement failed: ' + type(failure).__name__)
        finally:
            owner.active = False
            if runtime.__dict__.get('_primary_client_configuration_owner') is owner:
                runtime.__dict__.pop('_primary_client_configuration_owner')


@contextmanager
def producing(runtime, pointer, frame, rbp):
    from .primary_client_configuration import produce, loop
    owner = require_owner(runtime, 'client_loop')
    validate_owner(runtime, pointer)
    source = sys._getframe(2)
    caller = _frame(loop.__code__, runtime)
    if (source.f_code is not produce.__code__ or source.f_locals.get('owner') != pointer or
            caller is None or caller.f_locals.get('owner') != pointer or owner.row['task'] != pointer or owner.producer is not None):
        raise PrimarySemanticUnavailable('client produce requires its current source loop and exact raw owner')
    region, offset = runtime.memory._span(frame, 0x110)
    if offset or region.address != frame or len(region.data) != 0x110:
        raise InputError('client producer requires exact original frame backing')
    producer = {'source': source, 'frame': frame, 'rbp': rbp, 'region': region, 'owner': owner,
                'claimed': False, 'completed': False, 'audit_completed': False}
    owner.producer = producer
    owner.image.debts.append(('producer', producer))
    try:
        yield producer
        producer['completed'] = True
    finally:
        owner.producer = None


def current_request(runtime):
    owner = runtime.__dict__.get('_primary_client_configuration_owner')
    if owner is None:
        return None
    return require_owner(runtime, 'client_loop')


def transport_type(runtime, transport, target):
    from .primary_worker_consumer import _invoke
    owner = current_request(runtime)
    if owner is None:
        return None
    memory, base = runtime.memory, runtime.image_base
    if (not owner.producer or target != base + 0x63EC0 or
            memory.load(base + 0x6751AB8 + 8, 8) != transport or memory.load(transport, 8) != base + 0x41486F8):
        raise PrimarySemanticUnavailable('client request requires the actual SDK-produced receiver vtable type')
    validate_receiver(runtime, transport)
    return _invoke(runtime, 0x63EC0, transport)


def remember_clone(runtime, source, destination, pointer):
    owner = current_request(runtime)
    if owner is not None:
        if pointer != owner.row['task']:
            raise InputError('client callback clone changed its original raw owner')
        owner.image.debts.append(('callback_clone', (source, destination, pointer)))


def stop_sender(runtime, transport, command, pointer, count, sequence, target):
    owner = current_request(runtime)
    if owner is None:
        return False
    validate_receiver(runtime, transport)
    owner.image.debts.append(('native_sender', (target, transport, command, pointer, count, sequence)))
    runtime.events.append(('configuration.native_sender_unavailable', target, transport, command, pointer, count, sequence))
    raise PrimarySemanticUnavailable(f'client request actual five-argument native sender {target:#x} is unavailable')


def receiver_produced(runtime, context, write_start):
    from .primary_sign import PrimaryRuntime
    image = _IMAGES.get(getattr(runtime, '_primary_entry_owner', None))
    if image is None:
        return
    image.validate(runtime)
    source = sys._getframe(1)
    if source.f_code is not PrimaryRuntime.invoke.__code__ or source.f_locals.get('rva') != 0x1BE3060:
        raise InputError('client receiver receipt requires the real SDK constructor return')
    memory, base = runtime.memory, runtime.image_base
    pointer, control = memory.load(base + 0x6751AC0, 8), memory.load(base + 0x6751AC8, 8)
    region, offset = memory._span(control, 40)
    writes = memory.writes[write_start:]
    if (pointer != control + 24 or region.address != control or offset or len(region.data) != 40 or
            runtime.allocations.get(control) != 40 or memory.load(control, 8) != base + 0x41487B8 or
            memory.load(pointer, 8) != base + 0x41486F8 or memory.load(control + 32, 8) != context or
            not any(address == base + 0x6751AC0 and label == '1CE2BEA.receiver_pointer' for address,raw,label in writes)):
        raise InputError('client SDK receiver source constructor effects differ')
    table = tuple(memory._span(base + 0x41486F8 + index*8, 8) for index in range(3))
    receipt = (pointer, control, region, table, context)
    image.receivers.append(receipt)


def validate_receiver(runtime, pointer):
    image = image_for(runtime)
    memory, base = runtime.memory, runtime.image_base
    control = memory.load(base + 0x6751AC8, 8)
    receipts = [row for row in image.receivers if row[0] == pointer and row[1] == control]
    if len(receipts) != 1:
        raise PrimarySemanticUnavailable('client transport has no unique actual SDK constructor receipt')
    receipt = receipts[0]
    region, offset = memory._span(control, 40)
    table = tuple(memory._span(base + 0x41486F8 + index*8, 8) for index in range(3))
    if (region is not receipt[2] or offset or len(region.data) != 40 or runtime.allocations.get(control) != 40 or
            any(actual is not prior or offset != prior_offset for (actual,offset),(prior,prior_offset) in zip(table,receipt[3])) or
            memory.load(base + 0x6751AC0, 8) != pointer or memory.load(pointer, 8) != base + 0x41486F8 or
            memory.load(control + 32, 8) != receipt[4]):
        raise InputError('client SDK receiver original allocation/vtable backing changed')
    from .primary_client_configuration_startup import require_receiver
    require_receiver(runtime, pointer, receipt)
    return receipt


def retain_domain(service, tid):
    binding = _SERVICES.get(service)
    return binding is not None and bool(binding[0].debts) and any(
        row.get('thread_id') == tid for row in binding[0].rows)


def require_creator(service):
    from .primary_creator_domain import _for_service
    from .primary_client_configuration import create_startup, invoke as client_invoke
    from .primary_sign import PrimaryRuntime
    from .primary_sign_lifecycle import _SDKWorkerOwner
    runtime = service._runtime
    source = _frame(create_startup.__code__, runtime)
    dispatch = None if source is None else source.f_back
    entry = None if dispatch is None else dispatch.f_back
    if (source is None or dispatch is None or dispatch.f_code is not client_invoke.__code__ or
            dispatch.f_locals.get('rva') != 0x1C22D50 or dispatch.f_locals.get('values') != () or
            entry is None or entry.f_code is not PrimaryRuntime.invoke.__code__ or
            entry.f_locals.get('self') is not runtime or entry.f_locals.get('rva') != 0x1C22D50 or
            entry.f_locals.get('cells') != ()):
        raise PrimarySemanticUnavailable('client startup requires its actual selected source entry')
    owner = runtime.__dict__.get('_primary_sdk_worker_owner')
    if type(owner) is _SDKWorkerOwner and owner.service is service and owner.valid():
        return owner
    creator = _for_service(service)
    if creator is None:
        raise PrimarySemanticUnavailable('client startup creator has no original factory execution issuer')
    creator.validate()
    return creator


def normal_cleanup(runtime):
    # Existing engineering domains retain their established cleanup contract.
    # The source client path has no proved EH tail at an unavailable callee.
    return sys.exception() is None or runtime.__dict__.get('_primary_client_configuration_owner') is None


class _ClientCtor:
    def __init__(self, scope, vm, call, registration, singleton, carrier, token):
        if token is not _FACTORY or sys._getframe(1).f_code is not authorize_bootstrap.__code__:
            raise InputError('client constructor requires its actual source root issuer')
        self.scope,self.runtime,self.owner=scope,scope.runtime,scope.client_owner
        self.image=self.owner.image
        self.audit=scope._request_audit
        self.root,self.root_call=vm,call
        self.registration,self.singleton,self.carrier=registration,singleton,carrier
        self.tls=self.runtime.tls_epoch_address
        self.tls_region,self.tls_offset=self.runtime.memory._span(self.tls,4)
        self.root_backend=False
        self.child=self.child_call=None
        self.child_backend=False

    def require(self):
        from .primary_sign import PrimaryRuntime
        from .primary_bootstrap_direct import _source_frame,_HOSTS
        r,s=self.runtime,self.scope
        if (s._client_ctor is not self or s.client_owner is not self.owner or not s._valid_client() or
                self.owner.image is not self.image or s._request_audit is not self.audit or not self.audit.valid() or
                self.audit.stage!='audit' or self.audit.status_completed or not self.audit.status_wrapper_seen or
                s._status_host is not None or s._audit is not None or
                not any(kind=='constructor' and issued is self for kind,issued in self.image.debts) or
                not r._program_calls or r._program_calls[0] is not self.root_call or
                self.root_call != dict(name='singleton-init',arguments=(),hosts=_HOSTS) or
                getattr(self.root,'_primary_client_ctor',None) is not self or
                _source_frame(PrimaryRuntime._register_callback_group.__code__,r) is not self.registration or
                _source_frame(PrimaryRuntime._singleton.__code__,r) is not self.singleton or
                r.tls_epoch_address!=self.tls):
            raise PrimarySemanticUnavailable('client constructor lost its original request/root/thread/source instance')
        region,offset=r.memory._span(self.tls,4)
        if region is not self.tls_region or offset!=self.tls_offset:
            raise InputError('client constructor original TLS epoch backing replaced')
        self.image.validate(r)
        return self


def authorize_bootstrap(scope, vm, name, *, backend):
    """Two independent admission layers for this exact cold registration caller."""
    from hashlib import sha256
    from .primary_vm import PrimaryVM
    from .primary_sign import PrimaryRuntime
    from .primary_request_audit_scope import _ClientHandoffAuditClaim
    from .primary_bootstrap_direct import _source_frame,_host,_HOSTS,_BUFFER_HOSTS,PROGRAM_SHA256,BUFFER_SHA256
    r=scope.runtime
    owner=require_owner(r,'client_loop')
    scope._require_live()
    audit=scope._request_audit
    reader=_source_frame(PrimaryRuntime._execute_program.__code__,r,name=name)
    hashes={'singleton-init':PROGRAM_SHA256,'buffer-init':BUFFER_SHA256}
    if (name not in hashes or type(vm) is not PrimaryVM or scope.client_owner is not owner or
            type(audit) is not _ClientHandoffAuditClaim or not audit.valid() or
            reader is None or reader.f_locals.get('vm') is not vm or
            vm.runtime is not r or vm.memory is not r.memory or vm.image_base!=r.image_base or
            sha256(vm.program.raw).hexdigest()!=hashes[name] or
            (vm.pc,vm.block,vm.predecessor,vm.initial_block,vm.arena_used)!=(1,0,None,True,0) or
            vm.halted or vm.abort_reason is not None or vm.trace or vm.host_calls or vm.auxiliary is not None or
            any(getattr(vm,key) is not None for key in ('pending_once10','pending_once9','pending_l26',
                'pending_variadic','pending_native','private_iv_native_pending')) or
            getattr(vm,'_primary_bootstrap_used',False) or not r.vms or r.vms[-1] is not vm or
            r._execute_thread!=get_ident() or r._execute_depth!=len(r._program_calls)):
        raise PrimarySemanticUnavailable('client bootstrap requires the actual fixed fresh source VM and reader')
    calls=r._program_calls
    if name=='singleton-init':
        registration=_source_frame(PrimaryRuntime._register_callback_group.__code__,r)
        provider=_source_frame(PrimaryRuntime._register_provider_base.__code__,r)
        callback=_source_frame(PrimaryRuntime.invoke.__code__,r,rva=0x2DE5910)
        wrapper=_source_frame(PrimaryRuntime.invoke.__code__,r,rva=0x1BF75A0)
        singleton=_source_frame(PrimaryRuntime._singleton.__code__,r)
        carrier=None if wrapper is None else wrapper.f_locals.get('vm')
        actual={} if registration is None else registration.f_locals
        local={} if singleton is None else singleton.f_locals
        domain=owner.service._crt_domains.get(get_native_id())
        if (audit.stage!='audit' or audit.status_completed or not audit.status_wrapper_seen or
                scope._status_host is not None or scope._audit is not None or
                registration is None or provider is None or callback is None or wrapper is None or singleton is None or
                any(actual.get(key)!=value for key,value in (('lock_rva',0x677C220),('start',0x6D85F60),
                    ('size',72),('pc',0x1BF6463),('slot',None),('target',0x2DE5910),('group',bytes(72)))) or
                actual.get('vm') is not carrier or provider.f_locals.get('vm') is not carrier or
                callback.f_locals.get('vm') is not carrier or callback.f_locals.get('cells')!=() or
                wrapper.f_locals.get('cells')!=(0,1,2,3) or
                tuple(carrier.cells.value(i) for i in range(4))!=(1,61,1,0) or
                r.locks.get(r.image_base+0x677C220)!=1 or
                local.get('guard_address')!=r.image_base+0x6D88CC8 or local.get('slot_address')!=r.image_base+0x6D88CC0 or
                r.memory.load(r.image_base+0x6D88CC8,4,signed=True)!=-1 or
                domain is None or r.tls_epoch_address!=domain['tls']+0xA8 or
                not local['guard']>r.memory.load(r.tls_epoch_address,4,signed=True) or
                len(calls)!=1 or calls[-1]!=dict(name=name,arguments=(),hosts=_HOSTS) or
                reader.f_locals.get('arguments')!=() or reader.f_locals.get('hosts')!=_HOSTS):
            raise PrimarySemanticUnavailable('client cold root lacks its actual zero-group75A0 registration and TLS header decision')
        if not backend:
            if scope._client_ctor is not None or getattr(vm,'_primary_client_ctor',None) is not None:
                raise PrimarySemanticUnavailable('client constructor root cannot be issued twice')
            ctor=_ClientCtor(scope,vm,calls[-1],registration,singleton,carrier,_FACTORY)
            scope._client_ctor=ctor
            vm._primary_client_ctor=ctor
            owner.image.debts.append(('constructor',ctor))
        ctor=scope._client_ctor
        if (type(ctor) is not _ClientCtor or ctor.require() is not ctor or ctor.root is not vm or
                ctor.root_call is not calls[-1] or vm._primary_client_ctor is not ctor or ctor.root_backend):
            raise PrimarySemanticUnavailable('client root requires its original unconsumed constructor receipt')
        if backend:
            ctor.root_backend=True
            vm._primary_bootstrap_used=True
        return
    ctor=scope._client_ctor
    if type(ctor) is not _ClientCtor:
        raise PrimarySemanticUnavailable('client buffer child has no original source constructor root')
    ctor.require()
    root=ctor.root
    native=_source_frame(_host.__code__,r)
    wrapper=_source_frame(PrimaryRuntime.invoke.__code__,r,rva=0x359205B)
    arguments=(root.cells.value(35),root.cells.value(34))
    if (not ctor.root_backend or type(root) is not PrimaryVM or root.runtime is not r or root.memory is not r.memory or
            root.image_base!=r.image_base or sha256(root.program.raw).hexdigest()!=PROGRAM_SHA256 or root.halted or
            (root.pc,root.block,root.predecessor,root.initial_block)!=(170,6,4,False) or
            len(r.vms)<2 or r.vms[-2] is not root or len(calls)!=2 or calls[-2] is not ctor.root_call or
            calls[-1]!=dict(name=name,arguments=arguments,hosts=_BUFFER_HOSTS) or
            reader.f_locals.get('arguments')!=arguments or reader.f_locals.get('hosts')!=_BUFFER_HOSTS or
            root.host_calls[-1:]!=[(163,r.image_base+0x359205B,(35,34),41)] or
            getattr(root,'_primary_bootstrap_active_call',None)!=(163,37,(35,34),41,None) or
            native is None or native.f_locals.get('vm') is not root or wrapper is None or wrapper.f_locals.get('vm') is not root or
            wrapper.f_locals.get('cells')!=(35,34) or
            any(native.f_locals.get(key)!=value for key,value in (('word',163),('callee',37),('arguments',(35,34)),('signature',41),('destination',None))) or
            getattr(root,'_primary_bootstrap_child',None) is not None or ctor.child_backend):
        raise PrimarySemanticUnavailable('client buffer requires the actual unique word163 root/current-cell ABI/parent record')
    if not backend:
        if ctor.child is not None or getattr(vm,'_primary_client_ctor',None) is not None:
            raise PrimarySemanticUnavailable('client constructor child cannot be issued twice')
        ctor.child,ctor.child_call=vm,calls[-1]
        vm._primary_client_ctor=ctor
    if ctor.child is not vm or ctor.child_call is not calls[-1] or getattr(vm,'_primary_client_ctor',None) is not ctor:
        raise PrimarySemanticUnavailable('client child constructor receipt instance changed')
    if backend:
        root._primary_bootstrap_child=vm
        vm._primary_bootstrap_used=True
        ctor.child_backend=True
