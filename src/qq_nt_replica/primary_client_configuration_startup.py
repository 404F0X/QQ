"""Finite selected 72B078 MODEL component; no application-origin capability."""
import os
import sys
from threading import Lock, get_ident, get_native_id

from .errors import InputError
from .primary_logger import _String
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_TOKEN = object()
_IMAGES = {}
_INPUTS = {}
_RECEIVERS = {}
_SRW_PORTS = {}
_KERNELS = {}
_INIT_STAGES = {}
_INIT_ACTIVE = {}
_INIT_ATTEMPTS = {}
_SDK_FILE = rb'R:\devops\workspace\p-824b74756ad64e12838601ccde6ecefb\platforms\Windows\libsecxx\FGESDKNt.cpp'
_SESSION_FILE = rb'..\wrapper\external\msf\msf_security_sign_callback.cc'


def install_fresh_globals(signer):
    from .primary_memory import PrimaryMemoryLimit
    from .primary_signer import PrimarySigner
    caller = sys._getframe(1)
    if (type(signer) is not PrimarySigner or caller.f_code is not PrimarySigner._initialize_image.__code__ or
            caller.f_locals.get('self') is not signer or signer in _IMAGES):
        raise InputError('client startup fresh birth requires its original cold installer')
    memory, base = signer.memory, signer.image_base
    spans = tuple((rva,bytes(size)) for rva,size in
        ((0x674D230,24),(0x674D248,4),(0x674D280,24),(0x674D298,4),
         (0x6D83BC8,24),(0x6D83BF0,24),(0x6D83C18,24)))
    literals = ((0x486ABAA,_SESSION_FILE+b'\0'),(0x4849C07,b'SetSessionId\0'),
                (0x46629B0,b'SetSessionId:{}\0'),(0x3F6DE00,b'MSFSecuritySignCallback\0'),
                (0x45D1E46,b'[{}]->{}\0'),
                (0x4909ED8,(base+0x1CF4360).to_bytes(8,'little')),
                (0x3EB8678,(base+0x45D1E46).to_bytes(8,'little')+(8).to_bytes(8,'little')))
    for rva, raw in spans+literals:
        start, end = base + rva, base + rva + len(raw)
        if any(start < region.address + len(region.data) and region.address < end for region in memory._regions):
            raise PrimaryMemoryLimit('client startup exact fresh cell overlaps existing memory')
    regions = []
    for rva, raw in spans+literals:
        address = base + rva
        memory.map(address,bytearray(raw) if (rva,raw) in spans else raw,initialized=True,
                   name='fixed PE client startup virtual-tail birth' if (rva,raw) in spans else 'fixed PE SetSessionId literal')
        region, offset = memory._span(address, len(raw))
        regions.append((address, region, len(raw)))
    record = dict(signer=signer, memory=memory, base=base, regions=tuple(regions), image=None, atomic=Lock())
    _IMAGES[signer] = record
    signer._client_startup_birth = record


def bind_image(signer, image):
    from .primary_client_configuration_scope import bind_image as bind_client
    caller = sys._getframe(1)
    record = _IMAGES.get(signer)
    if (caller.f_code is not bind_client.__code__ or record is None or
            signer._client_startup_birth is not record or record['image'] is not None or image.signer is not signer):
        raise InputError('client startup source image binding requires its original installer')
    # These regions were already born in their own fixed-image installers.
    regions = list(record['regions'])
    for rva, size in ((0x6D83BE0, 8), (0x6D83C08, 8), (0x6D83C30, 8),
                      (0x6751AB8, 0x7C), (0x67516B0, 848), (0x677CF00,0x130),
                      (0x677D030,24),(0x677D048,0x118),(0x677D160,104)):
        address = record['base'] + rva
        region, offset = record['memory']._span(address, size)
        if offset or region.address != address or len(region.data) != size:
            raise InputError('client startup original fixed-image backing differs')
        regions.append((address, region, size))
    record['regions'], record['image'] = tuple(regions), image


def validate_image(runtime):
    from .primary_client_configuration_scope import image_for
    image = image_for(runtime)
    record = _IMAGES.get(image.signer)
    if (record is None or getattr(image.signer, '_client_startup_birth', None) is not record or
            record['image'] is not image or record['memory'] is not runtime.memory or record['base'] != runtime.image_base):
        raise InputError('client startup original source image/receipt changed')
    for address, region, size in record['regions']:
        actual, offset = runtime.memory._span(address, size)
        if actual is not region or offset or region.address != address or len(region.data) != size:
            raise InputError('client startup original exact backing replaced')
    return image


def bind_service_kernel(service):
    from .primary_client_configuration_scope import bind_service
    source=sys._getframe(1)
    if source.f_code is not bind_service.__code__ or source.f_locals.get('service') is not service or service in _KERNELS:
        raise InputError('SOURCE_SRW kernel binding requires the original factory service bind')
    _KERNELS[service]=service._kernel


def _creator(owner):
    from .primary_client_configuration_scope import _OWNERS, _SERVICES
    from .primary_creator_domain import _for_service, _validate_domain
    original = _OWNERS.get(owner)
    if original is None or getattr(owner, '_client_configuration_close', None) is not original:
        raise InputError('client component requires its original Windows owner')
    image, service, runtime, registrar, signer, binding = original
    if (owner._threads is not service or owner._signer is not signer or owner._registrar is not registrar or
            signer.runtime is not runtime or service._runtime is not runtime or _SERVICES.get(service) is not binding):
        raise InputError('client component original service/runtime registry changed')
    validate_image(runtime)
    creator = _for_service(service)
    if creator is None:
        raise InputError('client component has no original creator issuer')
    creator.validate()
    if creator.domain is None:
        raise InputError('client component requires its actual active creator CRT domain')
    _validate_domain(service, creator.domain['value'])
    return original, creator, registrar.current_lease()


def run_request_model_stage(owner):
    from .primary_windows_signer import WindowsSigner,open_windows_signer
    from .primary_request_startup import _IMAGE_SHA256,_image
    caller=sys._getframe(1)
    if caller.f_code is not WindowsSigner._initialize_crt.__code__ or caller.f_locals.get('self') is not owner:
        raise InputError('request MODEL initializer requires its actual factory CRT point')
    scan=caller;factory=False
    while scan:
        if scan.f_code is open_windows_signer.__code__ and scan.f_locals.get('owner') is owner:factory=True
        scan=scan.f_back
    original,creator,lease=_creator(owner)
    image,service,runtime,registrar,signer,binding=original
    if (not factory or owner._state!='constructing' or owner in _INIT_STAGES or
            _INIT_ATTEMPTS.get(runtime) or image.debts or service._threads or service._secondary):
        raise InputError('request MODEL initializer cannot adopt/repeat/retry a consumer or constructor domain')
    _image()  # Fixed canonical asset digest, not a caller-supplied constructor.
    memory,base=runtime.memory,runtime.image_base
    for rva,size in ((0x677CF00,0x130),(0x677D030,24),(0x677D048,0x118),(0x677D160,104)):
        if memory.read(base+rva,size)!=bytes(size):
            raise InputError('request MODEL initializer requires its original cold image backing')
    target=memory.load(base+0x4909ED8,8)
    if target!=base+0x1CF4360:
        raise InputError('request MODEL initializer fixed source slot/entry changed')
    issuer=runtime._primary_allocator_issuer
    issuer.validate()
    stage=dict(owner=owner,original=original,image=image,runtime=runtime,memory=memory,base=base,
        epoch=image.epoch,issuer=issuer,allocator=runtime._primary_allocator_selector,
        allocator_epoch=issuer.epoch,registrar=registrar,lease=lease,slot=base+0x4909ED8,target=target,
        asset=_IMAGE_SHA256,origin='MODEL_SOURCE_SELECTED_INIT_STAGE',state='running',constructor=None,
        first_error=None,receipt=None,untracked=[])
    _INIT_STAGES[owner]=stage;_INIT_ACTIVE[runtime]=stage
    owner._client_request_initializer=stage
    try:
        result=_invoke(runtime,target-base)
        record=stage['constructor']
        if record is None or not record.get('normal_return') or len(record['registrations'])!=7:
            raise InputError('request MODEL stage lacks the full actual constructor normal return')
        stage['untracked']=[row for row in record['registrations'] if not row.get('returned') or row.get('result')!=0 or row.get('registered_record') is None]
        stage['result']=result
        stage['state']='complete'
        # Identity is separate from equal field values; no public helper can mint it.
        stage['receipt']=object()
        runtime._client_request_init_receipt=stage['receipt']
        runtime.events.append(('request.MODEL_SOURCE_SELECTED_INIT_STAGE',stage['slot'],target))
    except BaseException as error:
        stage['state']='failed';stage['first_error']=error;raise
    finally:
        if _INIT_ACTIVE.get(runtime) is stage:del _INIT_ACTIVE[runtime]


def constructor_enter(runtime):
    from .primary_request_startup import construct
    if sys._getframe(1).f_code is not construct.__code__:
        raise InputError('request constructor journal requires its actual body')
    stage=_INIT_ACTIVE.get(runtime)
    record=dict(registrations=[],normal_return=False,private_stage=stage)
    _INIT_ATTEMPTS.setdefault(runtime,[]).append(record)
    if stage is not None:
        if stage['constructor'] is not None or stage['state']!='running':
            raise InputError('request constructor stage entered twice')
        stage['constructor']=record
    return record


def require_request_stage(runtime):
    from .primary_client_configuration_scope import _OWNERS
    candidates=[stage for owner,stage in _INIT_STAGES.items() if stage['runtime'] is runtime]
    if len(candidates)!=1:raise PrimarySemanticUnavailable('client consumer requires its completed MODEL source-selected request initializer stage')
    stage=candidates[0];owner=stage['owner']
    if (_INIT_STAGES.get(owner) is not stage or getattr(owner,'_client_request_initializer',None) is not stage or
            _OWNERS.get(owner) is not stage['original'] or owner._signer is not stage['image'].signer or
            owner._threads is not stage['original'][1] or owner._registrar is not stage['registrar'] or
            stage['image'].signer.runtime is not runtime or runtime.memory is not stage['memory'] or
            runtime.image_base!=stage['base'] or validate_image(runtime) is not stage['image'] or
            stage['image'].epoch is not stage['epoch'] or runtime._primary_allocator_issuer is not stage['issuer'] or
            runtime._primary_allocator_selector is not stage['allocator'] or stage['issuer'].epoch is not stage['allocator_epoch']):
        raise InputError('request MODEL stage original owner/runtime/image/allocator identity changed')
    if (stage['state']!='complete' or stage['receipt'] is None or
            getattr(runtime,'_client_request_init_receipt',None) is not stage['receipt'] or
            len(_INIT_ATTEMPTS.get(runtime,()))!=1 or _INIT_ATTEMPTS[runtime][0] is not stage['constructor']):
        raise PrimarySemanticUnavailable('request MODEL stage has no unique completed private receipt')
    return stage


def preflight_request_stage(owner):
    stage=_INIT_STAGES.get(owner)
    if stage is None:return
    if getattr(owner,'_client_request_initializer',None) is not stage:
        raise InputError('request MODEL stage original owner anchor changed')
    if stage['state']!='complete' or stage['untracked']:
        error=PrimarySemanticUnavailable('request MODEL initializer retains partial or unregistered source dependencies')
        if stage['first_error'] is not None:raise error from stage['first_error']
        raise error
    require_request_stage(stage['runtime'])


class _OwnedInput:
    def __init__(self, owner, original, creator, lease, token):
        if token is not _TOKEN:
            raise InputError('client owning input is issuer-private')
        self.owner, self.original, self.creator, self.lease = owner, original, creator, lease
        self.thread = os.getpid(), get_ident(), get_native_id()
        self.header = self.region = self.backing = self.snapshot = None
        self.allocations = []
        runtime=original[2]
        self.allocator=runtime._primary_allocator_selector
        self.allocator_epoch=self.allocator.epoch
        self.backend=runtime._custom_allocator_backend
        self.issuer=runtime._primary_allocator_issuer
        self.storage_records=()
        self.used, self.frame = False, None
        self.origin = 'MODEL_COMPONENT'

    def require(self):
        original, creator, lease = _creator(self.owner)
        image, service, runtime, registrar, signer, binding = original
        if (_INPUTS.get(self) is not self.original or original is not self.original or creator is not self.creator or
                lease is not self.lease or self.thread != (os.getpid(), get_ident(), get_native_id()) or
                not any(kind=='component_input' and issued is self for kind,issued in image.debts) or self.origin != 'MODEL_COMPONENT'):
            raise InputError('client owning input original identity/lease changed')
        if (runtime._primary_allocator_selector is not self.allocator or self.allocator.epoch is not self.allocator_epoch or
                runtime._custom_allocator_backend is not self.backend or runtime._primary_allocator_issuer is not self.issuer):
            raise InputError('client owning input original allocator identity/epoch changed')
        self.issuer.validate()
        for pointer,record in self.storage_records:
            if self.backend.records.get(pointer) is not record:
                raise InputError('client owning input original allocation receipt changed')
        if self.header is None or self.snapshot is None:
            raise InputError('client owning input construction did not complete')
        region, offset = runtime.memory._span(self.header, 24)
        if region is not self.region or offset or len(region.data) != 24:
            raise InputError('client owning input header backing replaced')
        pointer, size, payload_region, payload_offset = self.backing
        actual, actual_offset = runtime.memory._span(pointer, size + 1)
        raw, known, payload, payload_known = self.snapshot
        if (actual is not payload_region or actual_offset != payload_offset or bytes(region.data) != raw or
                bytes(region.initialized) != known or
                bytes(actual.data[actual_offset:actual_offset+size+1]) != payload or
                bytes(actual.initialized[actual_offset:actual_offset+size+1]) != payload_known):
            raise InputError('client owning input original bytes/knownness/backing changed')
        return runtime


def _own_client_configuration_input(owner, value):
    if type(value) is not bytes or len(value) > 1 << 20:
        raise InputError('client component requires explicit bounded MODEL bytes')
    original, creator, lease = _creator(owner)
    image, service, runtime, registrar, signer, binding = original
    require_request_stage(runtime)
    receipt = _OwnedInput(owner, original, creator, lease, _TOKEN)
    _INPUTS[receipt] = original
    image.debts.append(('component_input',receipt))  # Anchor before the first allocation or guest write.
    header, unused = _frame(runtime, 24, 'MODEL_COMPONENT owned client startup input')
    receipt.header = header
    receipt.region, offset = runtime.memory._span(header, 24)
    value = _String.construct(runtime, value, _owned=receipt.allocations)
    value.write_to(header)
    receipt.storage_records=tuple((pointer,receipt.backend.records[pointer]) for pointer,region in receipt.allocations)
    pointer, size = (value.get(16, 8), value.get(8, 8)) if value.get(0, 1) & 1 else (header+1, value.get(0, 1)>>1)
    backing, offset = runtime.memory._span(pointer, size + 1)
    receipt.backing = pointer, size, backing, offset
    receipt.snapshot = (bytes(receipt.region.data), bytes(receipt.region.initialized),
                        bytes(backing.data[offset:offset+size+1]), bytes(backing.initialized[offset:offset+size+1]))
    return receipt


def _run_client_configuration_component(owner, owned_input_receipt):
    if type(owned_input_receipt) is not _OwnedInput or owned_input_receipt.owner is not owner:
        raise InputError('client component requires its original issued owning input')
    runtime = owned_input_receipt.require()
    if owned_input_receipt.used:
        raise InputError('client owning input was already consumed by its selected entry')
    owned_input_receipt.used = True
    return _invoke(runtime, 0x72B078, owned_input_receipt.header)


def _selected_input(runtime, pointer):
    caller = sys._getframe(2)
    while caller is not None and caller.f_code is not _run_client_configuration_component.__code__:
        caller = caller.f_back
    receipt = None if caller is None else caller.f_locals.get('owned_input_receipt')
    if type(receipt) is not _OwnedInput or receipt.require() is not runtime or receipt.header != pointer or not receipt.used:
        raise InputError('72B078 requires its actual selected component owning-input handoff')
    return receipt


def getter(runtime, second=False):
    from .primary_shared_locale import resolve_current_module_tls
    validate_image(runtime)
    receipt = resolve_current_module_tls(runtime)
    memory, base = runtime.memory, runtime.image_base
    address, guard = (base+0x674D280, base+0x674D298) if second else (base+0x674D230, base+0x674D248)
    if memory.load(guard, 4, signed=True) > memory.load(receipt.epoch_address, 4, signed=True):
        runtime._locale_thread_header(guard)
        if memory.load(guard, 4, signed=True) == -1:
            if second:
                # 330E's empty literal produces only tag and terminator.
                _String.construct(runtime, b'').write_to(address)
            else:
                _invoke(runtime, 0x6270, address)
            runtime._locale_thread_footer(guard)
    return address


def selected_entry(runtime, pointer):
    receipt = _selected_input(runtime, pointer)
    frame, unused = _frame(runtime, 24, '72B078 source owning log-copy local')
    receipt.frame = dict(address=frame, input=pointer, stage='input_assigned')
    destination = getter(runtime)
    _invoke(runtime, 0x75CEC0, destination, pointer)
    _invoke(runtime, 0x75B810, frame, pointer)
    last = 0
    for index in range(len(_SESSION_FILE)):
        if runtime.memory.load(runtime.image_base+0x486ABAA+index,1)==0x5C:
            last = runtime.image_base+0x486ABAA+index
    runtime.events.append(('source.3E6D680',runtime.image_base+0x486ABAA,0x5C,last))
    basename = last+1 if last else runtime.image_base+0x486ABAA
    receipt.frame['stage'] = '72B0FE 4CC9 log'
    _invoke(runtime,0x4CC9,runtime.image_base+0x3F6DE00,2,basename,0x21,
            runtime.image_base+0x4849C07,runtime.image_base+0x46629B0,frame)
    receipt.frame['stage'] = '72B10A setter'
    _invoke(runtime,0xB9E850,runtime.image_base+0x72B142)
    second = getter(runtime,True)
    data = runtime.memory.load(second+16,8) if runtime.memory.load(second,1)&1 else second+1
    receipt.frame.update(stage='72B127 BBB730',second_global=second,second_data=data,known_low8=1)
    flag=_LowByte(receipt)
    receipt.frame['low8_projection']=flag
    runtime.events.append(('source.72B122.MOV_CL',1,0xFF))
    _invoke(runtime,0xBBB730,flag,data)
    receipt.frame['normal_return']=True
    receipt.frame['stage']='72B141 normal return'
    runtime.memory.unmap(frame)
    return None


def require_receiver(runtime, pointer, constructor_receipt):
    from .primary_client_configuration_scope import _OWNERS
    image = validate_image(runtime)
    row = _RECEIVERS.get(image.signer)
    if (row is None or row[0] is not image or row[1] != pointer or row[2] is not constructor_receipt or
            _INPUTS.get(row[3]) is not row[3].original or _OWNERS.get(row[3].owner) is not row[3].original):
        raise PrimarySemanticUnavailable('client receiver lacks the completed literal 72B103/72B10A source publisher receipt')
    return row


def _issue_receiver(runtime, callback, first_constructor):
    from .primary_client_configuration_scope import image_for
    source = sys._getframe(2)
    while source is not None and source.f_code is not selected_entry.__code__:
        source = source.f_back
    receipt = None if source is None else source.f_locals.get('receipt')
    if type(receipt) is not _OwnedInput or receipt.frame.get('stage') != '72B10A setter':
        return  # A bare constructor/setter never receives literal-source qualification.
    if receipt.require() is not runtime or callback != runtime.image_base+0x72B142:
        raise InputError('client literal receiver source frame/callback changed')
    image = image_for(runtime)
    rows = image.receivers[first_constructor:]
    pointer = runtime.memory.load(runtime.image_base+0x6751AC0,8)
    control = runtime.memory.load(runtime.image_base+0x6751AC8,8)
    if len(rows)!=1 or rows[0][0]!=pointer or rows[0][1]!=control or rows[0][4]!=callback:
        raise InputError('client literal setter did not complete its actual constructor/publisher tail')
    row = (image,pointer,rows[0],receipt)
    _RECEIVERS[image.signer] = row
    image.debts.append(('literal_receiver',row))


def set_callback(runtime, callback):
    image = validate_image(runtime)
    if not callback:
        return None
    first_constructor = len(image.receivers)
    _metadata_cold(runtime)
    config = _invoke(runtime,0x1BB9250,runtime.image_base+0x67516B0)
    tag = runtime.memory.load(config+0xE0,1)
    length = runtime.memory.load(config+0xE8,8) if tag&1 else tag>>1
    _invoke(runtime,0xB9F1D0,_SDK_FILE,0x24,b'set channel proxy: %d',b'[FGESDK]',1,length)
    _invoke(runtime,0x1BE3060,callback)
    _invoke(runtime,0xB9F1D0,_SDK_FILE,0x26,b'set channel proxy end',b'[FGESDK]',1)
    _issue_receiver(runtime,callback,first_constructor)
    return None


def _metadata_cold(runtime):
    memory,base = runtime.memory,runtime.image_base
    flags = memory.load(base+0x6751800,4)
    if flags&1:
        return
    memory.store(base+0x6751800,flags|1,4,source='B9F108.metadata_guard_claim')
    memory.store(base+0x67516B0,0,4,source='B9F10E.metadata_DWORD_zero')
    memory.store(base+0x67516B8,0x3002,2,source='B9F118.metadata_len1_ASCII_zero')
    memory.store(base+0x67516BA,0,1,source='B9F121.metadata_NUL')
    memory.store(base+0x67516D0,0xFFFFFFFF,4,source='B9F128.metadata_minus_one')
    for rva in (0x67516D8,0x67516E8,0x67516F8,0x6751708,0x6751718,0x6751728,
                0x6751738,0x6751748,0x6751758,0x6751768,0x6751778,0x6751788,
                0x6751798,0x67517A4,0x67517E8,0x67517D8,0x67517C8,0x67517B8):
        memory.write(base+rva,bytes(16),source='B9F132.metadata_ordered_zero16')
    memory.store(base+0x67517F8,0,8,source='B9F1B3.metadata_QWORD_zero')
    _invoke(runtime,0x3E680B4,base+0xBCD020)


def compare_cstring(runtime,source,cstring):
    memory=runtime.memory
    # Native 75CB20 obtains the CString length before reading the String shape.
    right_size=_invoke(runtime,0x3EB2C10,cstring)
    if right_size==(1<<64)-1:
        raise PrimarySemanticUnavailable('75CBB6 String/CString length exception tail is unavailable')
    tag=memory.load(source,1)
    left_size=memory.load(source+8,8) if tag&1 else tag>>1
    left=memory.load(source+16,8) if tag&1 else source+1
    count=min(left_size,right_size)
    if count:
        runtime.events.append(('source.unavailable',0x3EB1EE0,0x75CB92,left,cstring,count))
        raise PrimarySemanticUnavailable('75CB92 -> 3EB1EE0 nonzero String/CString comparison needs its exact supported primitive domain')
    return -1 if left_size<right_size else int(left_size>right_size)


def exchange_gate_byte(runtime,address,value):
    image=validate_image(runtime)
    from .primary_client_configuration_scope import _OWNERS
    owners=[owner for owner,original in _OWNERS.items() if original[0] is image]
    if len(owners)!=1:
        raise InputError('SDK gate-byte exchange has no unique original Windows owner')
    _creator(owners[0])
    if type(value) is _LowByte:
        value=value.require(runtime)
    if address!=runtime.image_base+0x6751AB8 or type(value) is not int:
        raise InputError('1CE2BC0 requires its exact SDK gate and known input low byte')
    operation=_IMAGES[image.signer]['atomic']
    if not operation.acquire(False):
        raise PrimarySemanticUnavailable('MODEL gate-byte exchange is already active')
    try:
        # This private mutex only serializes the MODEL memory operation. It is
        # neither the source SRWLOCK nor a hardware memory-ordering claim.
        old=runtime.memory.load(address,1)
        runtime.memory.store(address,value&255,1,source='1CE2BC0.XCHG_BYTE')
        runtime.events.append(('source.1CE2BC0.DL_exchange',address,old,value&255))
    finally:operation.release()
    # XCHG updates DL; the source does not define a business RAX result.
    return None


class _LowByte:
    def __init__(self,receipt):
        source=sys._getframe(1)
        if source.f_code is not selected_entry.__code__ or source.f_locals.get('receipt') is not receipt:
            raise InputError('MOV CL projection requires its actual selected caller')
        self.receipt,self.source=receipt,source

    def require(self,runtime):
        from .primary_client_configuration_scope import _frame as source_frame
        if (self.receipt.require() is not runtime or self.receipt.frame.get('low8_projection') is not self or
                source_frame(selected_entry.__code__,runtime) is not self.source):
            raise InputError('MOV CL original source projection changed')
        return 1  # Exactly CL, never a claim that the source ECX upper24 is zero.


def _status_context(runtime):
    from .primary_client_configuration_scope import _frame as source_frame
    source=source_frame(login_status.__code__,runtime)
    if source is None:
        raise InputError('startup SRW requires its actual BBB730 source frame')
    flag=source.f_locals.get('flag')
    if type(flag) is not _LowByte or flag.require(runtime)!=1:
        raise InputError('startup SRW requires its actual partial-register source input')
    context=flag.receipt.frame.get('bbb')
    if type(context) is not dict or context.get('source') is not source:
        raise InputError('startup SRW source-stage context replaced')
    return context,flag.receipt


def login_status(runtime,flag,uin):
    from .primary_sign import PrimaryRuntime
    from .primary_client_configuration_scope import _frame as source_frame
    validate_image(runtime)
    if type(flag) is not _LowByte:
        raise InputError('BBB730 requires its actual MOV CL source projection')
    low=flag.require(runtime)
    source=sys._getframe()
    dispatch=source.f_back;wrapper=dispatch.f_back;worker=wrapper.f_back
    if (dispatch.f_code is not invoke.__code__ or dispatch.f_locals.get('rva')!=0xBBB730 or
            wrapper.f_code is not PrimaryRuntime.invoke.__code__ or wrapper.f_locals.get('rva')!=0xBBB730 or
            worker.f_code is not _invoke.__code__ or worker.f_back is not flag.source or
            flag.source.f_locals.get('data')!=uin or flag.source.f_locals.get('second')!=runtime.image_base+0x674D280):
        raise InputError('BBB730 source caller/current second-global borrow differs')
    memory,base=runtime.memory,runtime.image_base
    frame,unused=_frame(runtime,0x150,'BBB730 source normal locals and owning copies')
    rbp=frame+0x40
    context=dict(source=source,frame=frame,rbp=rbp,uin=uin,stage='BBBAF4')
    flag.receipt.frame['bbb']=context
    # Fixed decrypted source literals. Keep the unconsumed obfuscation seeds
    # unknown; inputstruct+00 is this earlier scratch, never a new zero field.
    memory.write(rbp+0x3A,b'login status: %s, %d\0\0',source='BBB805.decoded_first_format')
    memory.store(rbp+0x38,0,1,source='BBB80D.format_flag_clear')
    memory.write(rbp+0x62,_SDK_FILE+b'\0\0',source='BBBAC5.decoded_file_CString')
    memory.store(rbp+0x18,len(_SDK_FILE),8,source='BBBA72.completed_file_decode_count')
    memory.store(rbp+0x60,0,1,source='BBBAD3.file_flag_clear')
    _invoke(runtime,0xB9F1D0,rbp+0x62,0xB0,rbp+0x3A,b'[FGESDK]',1,uin,low)
    gate=_invoke(runtime,0xBA21A0)
    _invoke(runtime,0x1CE2BC0,gate,flag)
    if low:
        context['stage']='BBBB19'
        _invoke(runtime,0x75AF50,base+0x6751830)
        pointer=memory.load(base+0x6751828,8)
        if not pointer:
            pointer=_invoke(runtime,0xB75000,3)
            memory.store(pointer+2,0,1,source='BBBB37.state_tail_zero')
            memory.store(pointer,0,2,source='BBBB3B.state_prefix_zero')
            memory.store(base+0x6751828,pointer,8,source='BBBB40.state_pointer_publication')
        context['stage']='BBBB4E'
        _invoke(runtime,0x75AFC0,base+0x6751830)
        memory.store(pointer,1,1,source='BBBB53.state_enabled_after_release')
        memory.store(rbp+0x50,uin,8,source='BBBB56.original_uin_CString')
        for site,cold,offset,destination,slot in (
                (0xBBBB7C,0xBBC3FA,0x48,rbp-0x38,rbp+0x58),
                (0xBBBBBA,0xBBC4C4,0x18,rbp-0x20,rbp+0x48),
                (0xBBBBF8,0xBBC58E,0x30,rbp-8,rbp+0x40)):
            if not memory.load(base+0x6751800,4)&1:
                runtime.events.append(('source.unavailable',None,cold))
                raise PrimarySemanticUnavailable('BBB730 actual cold metadata branch '+hex(cold)+' is unavailable')
            metadata=_invoke(runtime,0x1BB9250,base+0x67516B0)
            _invoke(runtime,0x75B810,destination,metadata+offset)
            value=_String.read(runtime,destination)
            data=value.get(16,8) if value.get(0,1)&1 else destination+1
            memory.store(slot,data,8,source=f'{site:X}.owned_copy_CString_slot')
        context['stage']='BBBC15'
        _invoke(runtime,0xBBA000,rbp+0x38)
        args=tuple(memory.load(rbp+offset,8) for offset in (0x50,0x58,0x48,0x40))
        _invoke(runtime,0xB9F1D0,_SDK_FILE,0xC0,b'login status: %s, %s, %s, %s',b'[FGESDK]',1,*args)
        context['stage']='BBC009'
        _invoke(runtime,0x1C22D50)
        for site,address in ((0xBBC3D3,rbp-8),(0xBBC3E6,rbp-0x20),(0xBBC02C,rbp-0x38)):
            if memory.load(address,1)&1:
                _invoke(runtime,0xB75029,memory.load(address+16,8))
                runtime.events.append(('source.BBB730.normal_long_free',site,address))
    context['stage']='BBC3BB'
    _invoke(runtime,0xB9F1D0,_SDK_FILE,0xC6,b'set login status end',b'[FGESDK]',1)
    context['normal_return']=True
    memory.unmap(frame)
    return None


class _SourceSRW:
    def __init__(self,runtime,context,receipt):
        if sys._getframe(1).f_code is not srw_import.__code__:
            raise InputError('SOURCE_SRW requires its actual source import issuer')
        self.runtime,self.image,self.receipt=runtime,validate_image(runtime),receipt
        original,creator,lease=_creator(receipt.owner)
        self.owner,self.service,self.original=receipt.owner,original[1],original
        self.kernel=_KERNELS.get(self.service)
        if self.kernel is None or self.service._kernel is not self.kernel:
            raise InputError('SOURCE_SRW original factory kernel replaced')
        self.memory,self.base,self.epoch=runtime.memory,runtime.image_base,self.image.epoch
        self.region,self.offset=self.memory._span(self.base+0x6751830,8)
        if self.region.address!=self.base+0x67516B0 or len(self.region.data)!=848 or self.offset!=0x180:
            raise InputError('SOURCE_SRW requires its exact original8 within the fixed848B birth')
        self.pid,self.tid=os.getpid(),get_native_id()
        self.context,self.lease=context,lease
        self.pin=None;self.state='not_entered';self.active=False
        self.failures=[];self.records=[];self.record_debt=False
        self.origin='SOURCE_SRW'

    def identity(self):
        from .primary_client_configuration_scope import _OWNERS
        if (_SRW_PORTS.get(self.owner) is not self or self.owner._threads is not self.service or
                self.owner._signer is not self.image.signer or self.image.signer.runtime is not self.runtime or
                _OWNERS.get(self.owner) is not self.original or self.service._runtime is not self.runtime or
                getattr(self.service,'_client_source_srw',None) is not self or
                getattr(self.runtime,'_client_source_srw',None) is not self or self.origin!='SOURCE_SRW' or
                _KERNELS.get(self.service) is not self.kernel or self.service._kernel is not self.kernel or
                self.memory is not self.runtime.memory or self.runtime.image_base!=self.base or self.image.epoch is not self.epoch):
            raise InputError('SOURCE_SRW original owner/runtime/registry changed')
        validate_image(self.runtime)
        region,offset=self.memory._span(self.base+0x6751830,8)
        if region is not self.region or offset!=self.offset:
            raise InputError('SOURCE_SRW original8 backing replaced')

    def _entered(self,name):
        from .primary_windows_threads import WindowsSDKThreadService
        source=sys._getframe(1)
        if (source.f_code is not WindowsSDKThreadService._client_srw_api.__code__ or
                source.f_locals.get('self') is not self.service or not self.active):
            raise InputError('SOURCE_SRW API-entry recording is private')
        self.records[-1]['entered']=True
        self.state='acquire_unknown' if name=='AcquireSRWLockExclusive' else 'release_unknown'

    def _check(self,context,receipt,acquire):
        self.identity()
        original,creator,lease=_creator(self.owner)
        if (self.pid!=os.getpid() or self.tid!=get_native_id() or lease is not receipt.lease or
                original is not self.original or self.active or self.failures or self.record_debt):
            raise InputError('SOURCE_SRW creator lease/lifetime is not current')
        if context.get('stage')!=('BBBB19' if acquire else 'BBBB4E'):
            raise InputError('SOURCE_SRW source direction/stage differs')
        if acquire:
            if self.state not in ('not_entered','unheld') or self.pin is not None:
                raise PrimarySemanticUnavailable('SOURCE_SRW acquire retains a prior unresolved operation')
            self.context,self.receipt,self.lease=context,receipt,lease
        elif self.state!='held' or context is not self.context or lease is not self.lease:
            raise InputError('SOURCE_SRW release requires its original held source acquire')

    def call(self,context,receipt,acquire):
        if sys._getframe(1).f_code is not srw_import.__code__:
            raise InputError('SOURCE_SRW operation requires its actual source import')
        self._check(context,receipt,acquire)
        name='AcquireSRWLockExclusive' if acquire else 'ReleaseSRWLockExclusive'
        slot=0x490FBC0 if acquire else 0x4910298
        target=self.runtime.worker_imports.get(name)
        if type(target) is not int or self.memory.load(self.base+slot,8)!=target:
            raise InputError('SOURCE_SRW current import target differs')
        if self.pin is None:
            import ctypes
            self.memory.read(self.base+0x6751830,8)
            token,view=self.memory._pin_native_span(self.base+0x6751830,8,self)
            self.pin=(token,view,(ctypes.c_ubyte*8).from_buffer(view))
        token,view,native=self.pin
        self.memory._validate_native_pin(token,self)
        record=dict(name=name,target=target,state_before=self.state,entered=False,returned=False,
                    result=None,recorded=False,lease=self.lease,token=token)
        self.records.append(record);self.active=True
        primary=None
        try:
            try:
                result=self.service._client_srw_api(self.runtime,name,native,self)
                record['returned'],record['result']=True,result
                if result is not None:raise InputError('SOURCE_SRW API requires its actual void return')
                self.state='held' if acquire else 'unheld'
            except BaseException as error:
                primary=error;self.failures.append((name,'api',error))
            if record['entered']:
                try:
                    self.identity()
                    current,issued=_status_context(self.runtime)
                    if current is not context or issued is not receipt or _creator(self.owner)[2] is not self.lease:
                        raise InputError('SOURCE_SRW source identity changed after API return')
                    self.memory._record_native_write(token,self,source=name+'.actual_SOURCE_SRW_backing')
                    record['recorded']=True
                except BaseException as error:
                    self.record_debt=True;self.failures.append((name,'record',error))
                    if primary is None:primary=error
                    else:primary.add_note('SOURCE_SRW write recording also failed: '+type(error).__name__)
            if primary is not None:raise primary
            if not acquire:
                try:
                    self.memory._unpin_native_span(token,self)
                    self.pin=None
                    del native
                    view.release()
                except BaseException as error:
                    self.record_debt=True;self.failures.append((name,'unpin',error));raise
            return 0
        finally:self.active=False


def preflight_srw(owner):
    port=_SRW_PORTS.get(owner)
    if port is None:return
    port.identity()
    if (port.active or port.pin is not None or port.failures or port.record_debt or
            port.state in ('held','acquire_unknown','release_unknown')):
        error=PrimarySemanticUnavailable('SOURCE_SRW retains native/recording dependencies; close cannot retire backing')
        if port.failures:raise error from port.failures[0][2]
        raise error


def srw_import(runtime,address,acquire):
    context,receipt=_status_context(runtime)
    if address!=runtime.image_base+0x6751830:
        raise InputError('SOURCE_SRW import requires its exact source global')
    port=_SRW_PORTS.get(receipt.owner)
    if port is None:
        port=_SourceSRW(runtime,context,receipt)
        _SRW_PORTS[receipt.owner]=port
        port.service._client_source_srw=port
        runtime._client_source_srw=port
        port.image.debts.append(('source_srw',port))
    return port.call(context,receipt,acquire)


def srw_wrapper(runtime,address,acquire):
    result=_invoke(runtime,0x7877A0 if acquire else 0x7877E0,address)
    if acquire and result!=0:
        raise PrimarySemanticUnavailable('75AF6B -> 75FE90 SRW exception primitive unavailable')
    return result


def update_info(runtime,inputs):
    validate_image(runtime)
    memory,base=runtime.memory,runtime.image_base
    if not inputs:
        return None
    uin=memory.load(inputs+0x18,8)
    if not uin:
        return None
    _invoke(runtime,0xB9F1D0,_SDK_FILE,0x8F,b'update info: %s',b'[FGESDK]',1,uin)
    if not memory.load(base+0x6751800,4)&1:
        runtime.events.append(('source.unavailable',None,0xBBB244))
        raise PrimarySemanticUnavailable('BBA460 cold metadata branch BBB244 is unavailable')
    metadata=_invoke(runtime,0x1BB9250,base+0x67516B0)
    compared=_invoke(runtime,0x75CB20,metadata+0xE0,uin)
    if compared&0xFFFFFFFF==0:
        _invoke(runtime,0xB9F1D0,_SDK_FILE,0x92,b'update info repeated',b'[FGESDK]',1)
        runtime.events.append(('source.BBA000.normal_repeated_return',inputs,0xBBB233))
        return None
    raise PrimarySemanticUnavailable('BBA000 nonzero 75CB20 result retains effects; remaining selected business branch is unavailable')


def invoke(runtime, rva, values):
    if rva == 0x72B078 and len(values) == 1:
        return selected_entry(runtime, values[0])
    if rva in (0x72B018, 0x72B5B6) and not values:
        return getter(runtime, rva == 0x72B5B6)
    if rva == 0xB9E850 and len(values)==1:
        return set_callback(runtime,values[0])
    if rva == 0x75CB20 and len(values)==2:
        return compare_cstring(runtime,*values)
    if rva == 0xBBA000 and len(values)==1:
        return update_info(runtime,values[0])
    if rva == 0x1CE2BC0 and len(values)==2:
        return exchange_gate_byte(runtime,*values)
    if rva == 0xBBB730 and len(values)==2:
        return login_status(runtime,*values)
    if rva in (0x75AF50,0x75AFC0) and len(values)==1:
        return srw_wrapper(runtime,values[0],rva==0x75AF50)
    if rva in (0x7877A0,0x7877E0) and len(values)==1:
        return srw_import(runtime,values[0],rva==0x7877A0)
    raise InputError('client configuration selected source entry ABI differs')
