"""Original Login input capability and finite pre-VT80 record, MODEL source only."""
import os,sys,threading,weakref
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_logger import _String
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
_ACTIVE=weakref.WeakKeyDictionary()
_OWNERS={}


class _Input:
    def __setattr__(self,name,value):
        if getattr(self,'_sealed',False) and name!='phase':raise InputError('issued original input receipt fields are immutable')
        object.__setattr__(self,name,value)


def _owner_input(owner):
    row=_OWNERS.get(id(owner))
    if row is None:
        if any(type(q) is _Input and q.owner is owner for q in tuple(_ACTIVE.values())):
            raise InputError('original Login owner debt anchor is missing')
        return None
    # Retain and compare the original instance: an integer id alone carries no authority.
    if type(row) is not tuple or len(row)!=2 or row[0] is not owner or type(row[1]) is not _Input:
        raise InputError('original Login owner debt anchor changed')
    return row[1]


def _optional_init(r,p):
    r.memory.store(p,0,1,source='optional.payload_first_BYTE')
    r.memory.store(p+24,0,1,source='optional.presence_BYTE')


def _optional_copy(r,dst,src):
    m=r.memory;a=m.load(dst+24,1);b=m.load(src+24,1)
    if a not in (0,1) or b not in (0,1):raise PrimarySemanticUnavailable('9970 noncanonical optional presence unavailable')
    if a and not b:
        _String.read(r,dst).destroy();m.store(dst+24,0,1,source='9990.presence_clear')
    elif b:
        _invoke(r,0x75cec0 if a else 0x75b810,dst,src)
        if not a:m.store(dst+24,1,1,source='99AE.presence_engaged')


def _move(r,dst,src):
    _String.read(r,src).write_to(dst);_invoke(r,0x6270,src)
    r.events.append(('source.D56F50.String_MOVE',dst,src))


def _capture(r,address,size):
    region,offset=r.memory._span(address,size)
    return address,size,region,offset,region.data,bytes(region.initialized[offset:offset+size]),bytes(region.data[offset:offset+size])


def _check_span(r,row):
    address,size,region,offset,backing,mask,data=row;actual,current=r.memory._span(address,size)
    if (actual is not region or current!=offset or region.data is not backing or
            bytes(region.initialized[offset:offset+size])!=mask or
            any(known and region.data[offset+i]!=data[i] for i,known in enumerate(mask))):raise InputError('Login original input backing/mask/value changed')


def validate(r,login,receipt):
    if type(receipt) is not _Input or _ACTIVE.get(r) is not receipt:raise InputError('Login input receipt is unissued/copied/retired')
    q=receipt;m=r.memory
    if _owner_input(q.owner) is not q:raise InputError('Login input original owner anchor changed')
    if q.phase not in ('issued','persistent_copied'):raise InputError('Login original converter has not issued its completed input')
    if (q.r is not r or q.login!=login or q.service._LoginService__object!=q.login or q.service._LoginService__control!=q.control or r.memory is not q.memory or r.image_base!=q.base or
            q.owner is not q.service._LoginService__owner or q.owner._signer is not q.signer or q.signer.runtime is not r or q.owner._state!='open' or
            r._shared_locale_source is not q.image or r._shared_locale_source_epoch is not q.image_epoch or
            q.image.epoch is not q.image_epoch or q.image.signer._shared_locale_image is not q.image or
            r._custom_allocator_backend is not q.allocator or q.allocator.source.epoch is not q.allocator_epoch or
            q.allocator.records.get(q.control) is not q.control_record or
            m.load(q.base+0x674c730,8)!=login or m.load(q.base+0x674c738,8)!=q.control or
            login!=q.control+0x18 or os.getpid()!=q.pid or threading.get_native_id()!=q.thread or
            not q.service._LoginService__active or q.service._LoginService__input_receipt is not q):raise InputError('Login input owner/memory/image/allocator/call identity changed')
    frame=sys._getframe(1);active=False
    while frame is not None:
        if frame is q.call:active=True;break
        frame=frame.f_back
    if not active:raise InputError('Login input original source call has ended')
    region,offset=m._span(q.control,0x320)
    if (q.control_record is None or region is not q.control_record[0] or offset or len(region.data)!=0x320 or q.control_record[1]!=0x320 or q.control_record[2] is not q.allocator_epoch):raise InputError('Login original control allocation changed')
    q.image.validate_image(r)
    for row in q.spans:_check_span(r,row)
    return q


def produce(service,value):
    from .primary_outer_init import _LoginService
    caller=sys._getframe(1)
    if caller.f_code is not _LoginService.initConfig.__code__ or caller.f_locals.get('self') is not service:raise InputError('Login input issuer requires original wrapper converter')
    r=service._LoginService__runtime;m=r.memory
    if r in _ACTIVE or _owner_input(service._LoginService__owner) is not None:raise InputError('Login original input cannot be replaced/retried')
    q=_Input();q.r=r;q.memory=m;q.base=r.image_base;q.service=service;q.owner=service._LoginService__owner;q.signer=q.owner._signer
    q.login=service._LoginService__object;q.control=service._LoginService__control;q.call=caller
    q.image=r._shared_locale_source;q.image_epoch=r._shared_locale_source_epoch
    q.allocator=r._custom_allocator_backend;q.allocator_epoch=q.allocator.source.epoch;q.control_record=q.allocator.records.get(q.control)
    q.pid=os.getpid();q.thread=threading.get_native_id();q.spans=[];q.phase='converting';q.weak_mutex=threading.Lock()
    _ACTIVE[r]=q;_OWNERS[id(q.owner)]=(q.owner,q);service._LoginService__input_receipt=q;r._login_input_pending=q
    frame,unused=_frame(r,0x200,'D4F840 properties, independent by-value arguments and original input')
    q.frame=frame;q.input=frame+0xd0;q.optional=frame+0x78;q.arg7=frame+0x98;q.converted_appid=frame+0xb8
    for offset,key in zip((0,24,48,72,96),('commonPath','clientVer','machineId','platVer','hostName')):
        item=value.get(key)
        if type(item) is not str:raise PrimarySemanticUnavailable('public initConfig requires supported explicit String domain: '+key)
        try:raw=item.encode('utf-8')
        except UnicodeEncodeError as error:raise PrimarySemanticUnavailable('unsupported NAPI UTF8 conversion') from error
        _String.construct(r,raw).write_to(frame+offset)
    if not _String.read(r,frame).value() or not _String.read(r,frame+48).value():raise PrimarySemanticUnavailable('empty commonPath/machineId source alternatives unavailable')
    _optional_init(r,q.optional)
    appid=value.get('appid')
    if appid is not None:
        if type(appid) is not str:raise PrimarySemanticUnavailable('present appid conversion outside supported UTF8 String domain')
        try:raw=appid.encode('utf-8')
        except UnicodeEncodeError as error:raise PrimarySemanticUnavailable('unsupported NAPI UTF8 appid conversion') from error
        _String.construct(r,raw).write_to(q.converted_appid)
        _invoke(r,0x75b810,q.optional,q.converted_appid)
        m.store(q.optional+24,1,1,source='D4B334.presence_engaged')
        _String.read(r,q.converted_appid).destroy()
    q.boolean_local=frame+0x171
    m.store(frame+0x178,0,8,source='D4F9D6.property_handle_initial')
    m.store(q.boolean_local,0,1,source='D4F9F7.Boolean_output_initial')
    external=value.get('externalVersion')
    if type(external) is not bool:raise PrimarySemanticUnavailable('externalVersion requires explicit supported known Boolean; no missing default')
    m.store(q.boolean_local,int(external),1,source='D4FA03.known_Boolean_output')
    external_byte=m.load(q.boolean_local,1) # D4FA09 saves the actual output BYTE in R15B.
    _optional_init(r,q.arg7);_optional_copy(r,q.arg7,q.optional)
    q.argument_copies=tuple(frame+0x180+offset for offset in (0,24,48,72,96))
    q.phase='argument_copies'
    for index,site in ((4,0xd4fa2d),(3,0xd4fa3f),(2,0xd4fa4f),(1,0xd4fa5f),(0,0xd4fa6f)):
        q.copy_index=index+1
        r.events.append(('source.D4F840.argument_COPY',site,q.argument_copies[index],frame+24*index))
        _invoke(r,0x75b810,q.argument_copies[index],frame+24*index)
    r.events.append(('source.D4FA97.D56F50',q.input,q.argument_copies,q.arg7,external_byte))
    for index,offset in enumerate((0,24,48,72,96)):_move(r,q.input+offset,q.argument_copies[index])
    _optional_init(r,q.input+0x78)
    if m.load(q.arg7+24,1):
        _move(r,q.input+0x78,q.arg7);m.store(q.input+0x90,1,1,source='1E9BC.target_presence')
    m.store(q.input+0xa0,external_byte,1,source='D5700F.externalVersion')
    # Normal D56F50 and converter tails, never source exception cleanup.
    for address in q.argument_copies:_String.read(r,address).destroy()
    if m.load(q.arg7+24,1):_String.read(r,q.arg7).destroy()
    if m.load(q.optional+24,1):_String.read(r,q.optional).destroy()
    for offset in (96,72,48,24,0):
        r.events.append(('source.D4FAA3.property_dtor',frame+offset))
        _String.read(r,frame+offset).destroy()
    q.phase='issued';q.spans=[_capture(r,q.input,0xa1),_capture(r,q.control,8)]
    for offset in (0,24,48,72,96,0x78):
        if offset==0x78 and not m.load(q.input+0x90,1):continue
        string=_String.read(r,q.input+offset)
        if string.get(0,1)&1:q.spans.append(_capture(r,string.get(16,8),string.get(8,8)+1))
    q.spans=tuple(q.spans);q._sealed=True
    r.events.append(('source.D4F840.original_input',q.input,q.login,q.control))
    return q


def copy_to_login(r,login,receipt):
    q=validate(r,login,receipt)
    for target,source in zip((0x100,0x118,0x130,0x148,0x160),(0,24,48,72,96)):_invoke(r,0x75cec0,login+target,q.input+source)
    _optional_copy(r,login+0x178,q.input+0x78)
    r.memory.store(login+0x1a0,r.memory.load(q.input+0xa0,1),1,source='6C4A78.externalVersion_copy')
    q.phase='persistent_copied';r.events.append(('source.6C4A20.same_input',q.input))


def _empty(r,p):_String.construct(r,b'').write_to(p)


def construct_record(r,p):
    m=r.memory;m.store(p,0,8,source='29D9E.qword0')
    for offset in (8,0x20):_empty(r,p+offset)
    m.store(p+0x38,0,4,source='2FFC4.DWORD')
    for offset in (0x40,0x58,0x70,0x88):_empty(r,p+offset)
    for offset in (0xa0,0xb8):m.store(p+offset,0,1,source='29D9E.optional_BYTE')
    for offset in (0xc8,0xe0,0xf8,0x110,0x128,0x140):_empty(r,p+offset)
    m.store(p+0x158,0,8,source='29D9E.qword158');_empty(r,p+0x160)
    _empty(r,p+0x178);m.store(p+0x190,0,4,source='3ED5A.DWORD190')
    for offset in (0x198,0x1b0):_empty(r,p+offset)
    m.store(p+0x1c8,0xffffffff,4,source='3ED5A.DWORD1C8')
    for offset in (0x1d0,0x1e8,0x200,0x218,0x230,0x248,0x260):_empty(r,p+offset)
    m.store(p+0x278,p+0x280,8,source='3ED5A.container_head');m.write(p+0x280,bytes(16),source='3ED5A.container_empty')
    for offset in (0x290,0x2a8):_empty(r,p+offset)
    for offset in (0x2e0,0x2d0,0x2c0):m.write(p+offset,bytes(16),source='29D9E.zero16_order')
    m.store(p+0x2f0,0,8,source='29D9E.qword2F0')
    for offset in (0x2f8,0x310):_empty(r,p+offset)
    m.store(p+0x328,1,1,source='29D9E.byte328')


def prepare(r,login,receipt):
    q=validate(r,login,receipt)
    from .primary_windows_mmkv_host_init import for_runtime
    port=for_runtime(r);port._check(None)
    p,unused=_frame(r,0x350,'6D4BBC record330 and alias shared pair')
    r._login_msf_record_pending=dict(input=q,record=p,pair=p+0x330,login=login)
    construct_record(r,p)
    for site,destination,source in ((0x6d4c2d,p+0x58,login+0x100),(0x6d4c39,p+0x40,login+0x100),(0x6d4c4c,p+0x140,login+0x130)):
        r.events.append(('source.record_copy',site,destination,source));_invoke(r,0x75cec0,destination,source)
    validate(r,login,receipt)
    if r.memory.load(q.input+0x90,1):_invoke(r,0x75cec0,p+0x2a8,q.input+0x78)
    m=r.memory;z=r._login_msf_record_pending;old=p+0x340;z['old_strong']=old
    obj=m.load(login+0x48,8);m.store(old,obj,8,source='46453.weak_object_first')
    control=m.load(login+0x50,8)
    if obj!=login or control not in (0,q.control):raise InputError('weak upgrade lost original same Login owner/control')
    result=0
    if control:
        expected=m.load(control+8,4)
        while expected!=0xffffffff:
            desired=(expected+1)&0xffffffff
            with q.weak_mutex:
                observed=m.load(control+8,4);success=observed==expected
                if success:m.store(control+8,desired,4,source='75ADC8.MODEL_CMPXCHG_DWORD_success')
            r.events.append(('source.75ADC8.MODEL_CAS',expected,observed,desired,success))
            if success:result=control;break
            expected=observed # CMPXCHG failure updates EAX; source retries with that actual value.
    m.store(old+8,result,8,source='46464.weak_control_result' if control else '46476.NULL_control_zero')
    if not result:
        exception,unused=_frame(r,24,'46481 bad_weak_ptr exception prefix')
        m.store(exception,r.image_base+0x3ebf9b8,8,source='46481.bad_weak_ptr_vptr')
        m.write(exception+8,bytes(16),source='46481.bad_weak_ptr_rest')
        z['exception']=exception;z['target']=r.image_base+0x3e6bb18
        port._WindowsMMKVHost__open['boundary']=0x3e6bb18
        r.events.append(('source.unavailable',0x3e6bb18,0x464b1,exception))
        raise PrimarySemanticUnavailable('464B1 actual bad_weak_ptr throw 3E6BB18 unavailable')
    m.store(z['pair'],obj+0x18 if obj else 0,8,source='6D4CA8.alias18_MOVE')
    m.store(z['pair']+8,result,8,source='6D4CB2.control_MOVE')
    m.write(old,bytes(16),source='6D4CB6.old_strong_moved_empty')
    msf=m.load(login+0x90,8);table=m.load(msf,8);target=m.load(table+0x80,8)
    z.update(args=(msf,z['pair'],p),vtable=table,target=target)
    port._WindowsMMKVHost__open['boundary']=target-r.image_base
    r.events.append(('source.unavailable',target-r.image_base,0x6d4cca,*z['args']))
    raise PrimarySemanticUnavailable('6D4CCA actual VT80 '+hex(target-r.image_base)+' 72EC24 business call unavailable')


def preflight_close(owner):
    # Discover retained debt from the original owner before inspecting any current signer/runtime.
    q=_owner_input(owner);signer=owner._signer
    if q is None:
        if signer is None:return
        if _ACTIVE.get(signer.runtime) is None:return
        raise InputError('Login runtime debt belongs to another original owner')
    r=q.r
    if (_ACTIVE.get(r) is not q or q.owner is not owner or q.signer is not signer or
            signer.runtime is not r or q.service._LoginService__owner is not owner or
            r.memory is not q.memory or r.image_base!=q.base or
            r._shared_locale_source is not q.image or r._shared_locale_source_epoch is not q.image_epoch or
            q.image.epoch is not q.image_epoch or q.image.signer._shared_locale_image is not q.image or
            r._custom_allocator_backend is not q.allocator or q.allocator.source.epoch is not q.allocator_epoch or
            q.allocator.records.get(q.control) is not q.control_record):
        raise InputError('original Login input debt owner/signer/runtime/image/registry changed')
    for span in q.spans:_check_span(r,span)
    raise PrimarySemanticUnavailable('original Login input/record/alias ownership remains pending before source normal VT returns')
