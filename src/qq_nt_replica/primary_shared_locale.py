"""Fixed-profile complete shared-locale normal producer (integration in progress)."""
import threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable,PrimaryProgramLimit
from .primary_worker_consumer import _invoke

# Verified per-function normal CFG, source order: facet, vtable, installer, ID.
FACETS = ((108324872, 66531688, 7858000, 108321936), (108324888, 66531832, 7858320, 108321952), (108324904, 66531384, 7858640, 108322352), (108324936, 66538024, 7858960, 108322336), (108324952, 66538184, 7859280, 108322368), (108324968, 66531480, 7859600, 108322384), (108325008, 66471992, 7859920, 108322400), (108325024, 66538296, 7860240, 108322432), (108325040, 66538408, 7860560, 108322416), (108325056, 66538520, 7860880, 108322448), (108325072, 66531560, 7861200, 108322464), (108325120, 66531624, 7861520, 108322480), (108325168, 66531976, 7861840, 108321968), (108325184, 66532424, 7862160, 108321984), (108325200, 66532744, 7862480, 108322000), (108325216, 66533176, 7862800, 108322016), (108325232, 66534728, 7863120, 108322096), (108325248, 66535032, 7863440, 108322112), (108325264, 66535240, 7863760, 108322128), (108325280, 66535448, 7864080, 108322144), (108325296, 66535656, 7864400, 108322160), (108325312, 66535912, 7864720, 108322176), (108325328, 66536168, 7865040, 108322192), (108325344, 66536424, 7865360, 108322208), (108325360, 66533480, 7865680, 108322032), (108325384, 66533960, 7866000, 108322048), (108325408, 66534344, 7866320, 108322064), (108325448, 66534584, 7866640, 108322080), (108325488, 66536680, 7866960, 108322224), (108325504, 66536936, 7867280, 108322240))


def _change_ref(runtime,pointer,amount,source):
    value=runtime.memory.load(pointer+8,4)
    runtime.memory.store(pointer+8,(value+amount)&0xffffffff,4,source=source)
    return value


def _grow_table(runtime,table,n):
    """786860 appends n slots; slack and copied knownness retain their origin."""
    memory=runtime.memory
    first,end,cap=(memory.load(table+offset,8) for offset in (0,8,16))
    if not first<=end<=cap or (end-first)%8 or (cap-first)%8 or type(n) is not int or n<0:
        raise InputError('shared locale vector has invalid pointer arithmetic')
    oldsize=(end-first)//8;capacity=(cap-first)//8
    if n>(1<<61)-1-oldsize:raise PrimaryProgramLimit('shared locale vector source size overflow')
    if n<=capacity-oldsize:
        if n:memory.write(end,bytes(n*8),source='786860.append_zero_slots')
        memory.store(table+8,end+n*8,8,source='786860.publish_end')
        return
    wanted=oldsize+n;newcap=max(capacity*2,wanted)
    if newcap>1<<20:raise PrimarySemanticUnavailable('shared locale vector huge-cap/failure domain unsupported')
    inline=table+24;flag=table+0x108
    if newcap and newcap<=30 and memory.load(flag,1)==0:
        memory.store(flag,1,1,source='786860.claim_inline')
        destination=inline
    else:destination=_invoke(runtime,0xB75000,newcap*8)
    memory.write(destination+oldsize*8,bytes(n*8),source='786860.append_zero_slots')
    if oldsize:memory.copy_disjoint(destination,first,oldsize*8,label='786860.copy_old_pointer_masks')
    for offset,value in ((0,destination),(8,destination+wanted*8),(16,destination+newcap*8)):
        memory.store(table+offset,value,8,source='786860.publish_vector')
    if first==inline:memory.store(flag,0,1,source='786860.release_old_inline')
    elif first:_invoke(runtime,0xB75029,first)


def _install_facet(runtime,implementation,facet,identifier,capability):
    capability.validate(runtime)
    memory=runtime.memory;base=runtime.image_base
    state=memory.load(base+identifier,8,signed=True)
    if state!=-1:capability.initialize_identifier(runtime,identifier)
    index=memory.load(base+identifier+8,4,signed=True)
    if index<=0:raise PrimarySemanticUnavailable('shared locale nonpositive facet ID unsupported')
    _change_ref(runtime,facet,1,'77E750.increment_new_facet_reference')
    table=implementation+16;first=memory.load(table,8);end=memory.load(table+8,8)
    count=(end-first)//8
    if index>count:_grow_table(runtime,table,index-count)
    first=memory.load(table,8);slot=first+(index-1)*8
    old=memory.load(slot,8)
    if old:
        previous=_change_ref(runtime,old,-1,'77E750.release_old_facet_reference')
        if previous==0:
            raise PrimarySemanticUnavailable('shared locale replaced last-owner facet destructor unsupported')
    memory.store(slot,facet,8,source='77E750.publish_new_facet_last')


_VIEW_FACTORY=object()
_SOURCE_FACTORY=object()


class ProducedSharedLocale:
    """Borrowed provenance of completed source state; reference counts stay live."""
    def __init__(self,runtime,capability,token):
        if token is not _VIEW_FACTORY:raise InputError('shared locale view requires its original producer')
        self.runtime=runtime;self.capability=capability;self.epoch=capability.epoch
        self.thread=threading.get_ident()
        self.source_kind=capability.source_kind
        self.source_identity='qq52230-complete-shared-locale-source'

    def validate(self,runtime):
        if runtime is not self.runtime or self.thread!=threading.get_ident():
            raise InputError('shared locale view runtime/thread changed')
        self.capability.validate(runtime)
        if self.source_kind!=self.capability.source_kind or self.source_identity!='qq52230-complete-shared-locale-source':
            raise InputError('shared locale view provenance differs from its actual source capability')
        if self.capability.epoch is not self.epoch or not self.capability.complete:
            raise InputError('shared locale view is not its completed image epoch')
        return True

    @property
    def shared_wrapper(self):
        self.validate(self.runtime)
        return self.runtime.memory.load(self.runtime.image_base+0x674DE10,8)

    @property
    def implementation(self):
        return self.runtime.memory.load(self.shared_wrapper,8)


def prepare_shared_locale(runtime):
    capability=getattr(runtime,'_shared_locale_source',None)
    if type(capability) is not _SharedLocaleSource:
        raise PrimarySemanticUnavailable('shared locale requires its fresh image source capability')
    capability.prepare_stream_guard(runtime)
    return ProducedSharedLocale(runtime,capability,_VIEW_FACTORY)


def copy_shared_locale(runtime,destination):
    view=prepare_shared_locale(runtime)
    implementation=view.implementation
    runtime.memory.store(destination,implementation,8,source='781270.copy_implementation')
    _change_ref(runtime,implementation,1,'781270.increment_copied_implementation_reference')
    return destination


_SOURCE='63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'
_METHODS=((0x3EBE770,0x760A30),(0x3EBE778,0x40098),(0x3F73068,0x7824C0),(0x3F73070,0x7824B0),(0x3F73100,0x784A60),(0x3F73108,0x784A80),(0x3F735B8,0x76EA30))
_ZERO_SPANS=((0x6D8F0F0,4),(0x674DDF0,16),(0x674DE00,4),(0x674DE08,16),(0x674DE18,4),(0x674DE1C,4),(0x674E808,0x288),(0x674EA90,0x138))


def current_character_table(runtime):
    current=runtime._crt_thread();memory=runtime.memory;base=runtime.image_base
    temporary=memory.load(current+0x90,8)
    if temporary!=memory.load(base+0x6D8F120,8) and not (memory.load(current+0x3A8,4)&memory.load(base+0x6744B80,4)):
        raise PrimarySemanticUnavailable('shared locale current CRT refresh 3EA5E5C unsupported')
    return memory.load(temporary,8)


class _SharedLocaleSource:
    def __init__(self,signer,regions,token):
        import sys
        if token is not _SOURCE_FACTORY or sys._getframe(1).f_code is not install_fresh_image.__code__:
            raise InputError('shared locale image source requires its original fixed-profile constructor')
        self.signer=signer;self.runtime=None;self.memory=signer.memory;self.base=signer.image_base
        self.regions=regions;self.epoch=object();self.complete=False;self.poisoned=False;self.started=False
        self.source_kind=None;self.model_input=None;self.operation=threading.Lock();self.installed=[]

    def validate_image(self,runtime):
        if (runtime is not self.runtime or runtime.memory is not self.memory or
                runtime.image_base!=self.base or getattr(runtime,'_shared_locale_source',None) is not self or
                getattr(runtime,'_shared_locale_source_epoch',None) is not self.epoch or
                self.signer.runtime is not runtime or runtime._primary_entry_owner is not self.signer):
            raise InputError('shared locale source runtime/image/epoch identity changed or failed')
        for address,region,size in self.regions:
            current,offset=self.memory._span(address,size)
            if current is not region or offset:raise InputError('shared locale source region replaced')
    def validate(self,runtime):
        if self.poisoned:raise PrimarySemanticUnavailable('shared locale producer failed and cannot restart')
        self.validate_image(runtime)
        if self.model_input is not None:
            self.model_input.validate(runtime,self)
            resolve_current_module_tls(runtime)
            return
        from .primary_windows_allocator_issuer import WindowsAllocatorIssuer
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        issuer=getattr(runtime,'_primary_allocator_issuer',None)
        owner=getattr(runtime,'_primary_notification_worker_owner',None)
        if type(issuer) is not WindowsAllocatorIssuer or type(owner) is not _NotificationWorkerOwner or not owner.valid():
            raise PrimarySemanticUnavailable('shared locale requires actual current notification CRT source or explicit model inputs')
        issuer.validate()
        service=owner.service;domain=service._crt_domains.get(threading.get_native_id())
        if type(domain) is not dict or domain['tls']!=runtime.tls_base_address or runtime.tls_epoch_address!=domain['tls']+0xA8:
            raise InputError('shared locale current native CRT/TLS domain changed')
        if self.source_kind not in (None,'captured-raw-input'):raise InputError('shared locale model provenance cannot upgrade')
        self.source_kind='captured-raw-input'
        resolve_current_module_tls(runtime)

    def initialize_identifier(self,runtime,identifier):
        from .primary_logger import _srw
        memory=self.memory;base=self.base
        _srw(runtime,base+0x674D4D0,True)
        state=memory.load(base+identifier,8,signed=True)
        if state==1:
            _srw(runtime,base+0x674D4D0,False)
            raise PrimarySemanticUnavailable('shared locale ID condition wait unsupported')
        if state!=0:
            _srw(runtime,base+0x674D4D0,False);return
        memory.store(base+identifier,1,8,source='75B0E0.once_claim')
        _srw(runtime,base+0x674D4D0,False)
        previous=memory.load(base+0x674DE1C,4)
        memory.store(base+0x674DE1C,(previous+1)&0xffffffff,4,source='781620.ID_counter_xadd')
        memory.store(base+identifier+8,(previous+1)&0xffffffff,4,source='781620.publish_ID')
        _srw(runtime,base+0x674D4D0,True)
        memory.store(base+identifier,-1,8,source='75B0E0.once_complete')
        _srw(runtime,base+0x674D4D0,False)
        from .primary_module_sync import shared_wake
        shared_wake(runtime)
        runtime.events.append(('shared_locale.WakeAllConditionVariable.no_waiters',base+0x674D4D8))

    def _guard(self,runtime,rva,construct):
        receipt=resolve_current_module_tls(runtime)
        guard=self.base+rva;memory=self.memory
        if memory.load(guard,4,signed=True)>memory.load(receipt.epoch_address,4,signed=True):
            runtime._locale_thread_header(guard)
            if memory.load(guard,4,signed=True)==-1:
                construct();runtime._locale_thread_footer(guard)

    def holder(self,runtime):
        memory=self.memory;base=self.base;holder=base+0x674DDD0
        def construct():
            header=_invoke(runtime,0x3E824C8,0,base+0x48A38AB)
            memory.store(holder,header,8,source='D46D00.C_core_header')
            memory.store(holder+8,base+0x48A38AB,8,source='D46D00.original_C_name_pointer')
            memory.store(holder+16,0,8,source='D46D00.no_owned_String_container')
            _invoke(runtime,0x3E680B4,base+0x77DFE0)
        self._guard(runtime,0x674DDE8,construct)
        return holder

    def _construct(self,runtime):
        memory=self.memory;base=self.base;impl=base+0x674EA90
        memory.store(impl,base+0x3F73018,8,source='77E010.implementation_vtable')
        memory.store(impl+8,0,4,source='77E010.reference_EDX_minus_one')
        for offset,value in ((16,impl+0x28),(24,impl+0x28),(32,impl+0x118)):
            memory.store(impl+offset,value,8,source='77E010.inline_table_header')
        memory.store(impl+0x118,1,1,source='77E010.inline_active')
        memory.write(impl+0x28,bytes(0xF0),source='77E010.zero_inline_slots')
        memory.store(impl+0x120,2,1,source='77E010.short_C_tag')
        memory.write(impl+0x121,b'C\0',source='77E010.short_C_payload')
        for index,(facet_rva,vtable,installer,identifier) in enumerate(FACETS,1):
            facet=base+facet_rva
            memory.store(facet,base+vtable,8,source='77E010.facet_vtable')
            memory.store(facet+8,0,4,source='77E010.facet_initial_reference')
            if index==3:
                memory.store(facet+16,0,8,source='77E010.ctype_initial_table')
                memory.store(facet+24,0,1,source='77E010.ctype_unowned')
                memory.store(facet+16,current_character_table(runtime),8,source='77E010.current_CRT_character_table')
            if index in (6,27,28):
                if index in (27,28):memory.store(facet,base+0x3F648A8,8,source='77E010.common_base_vtable')
                memory.store(facet+16,self.holder(runtime),8,source='77E010.C_holder')
                memory.store(facet,base+vtable,8,source='77E010.final_facet_vtable')
            if index in (11,12):
                memory.store(facet+16,0x2C2E if index==11 else 0x002C002E,2 if index==11 else 4,source='77E010.decimal_grouping_characters')
                memory.write(facet+24,bytes(16),source='77E010.empty_grouping_String')
                memory.store(facet+40,0,8,source='77E010.empty_grouping_tail')
            if index in (25,26):memory.store(facet+16,base+(0x3F739E8 if index==25 else 0x3F73B68),8,source='77E010.secondary_vtable')
            _install_facet(runtime,impl,facet,identifier,self)
            self.installed.append(installer)
        return impl

    def default_wrapper(self,runtime):
        memory=self.memory;base=self.base
        def construct():
            implementation=self._construct(runtime)
            memory.store(base+0x674DDF0,implementation,8,source='781180.publish_implementation')
            memory.store(base+0x674DDF8,base+0x674DDF0,8,source='781180.publish_wrapper_source')
        self._guard(runtime,0x674DE00,construct)
        implementation=memory.load(memory.load(base+0x674DDF8,8),8)
        memory.store(base+0x674DE08,implementation,8,source='781180.common_copy')
        _change_ref(runtime,implementation,1,'781180.common_reference')
        return base+0x674DE08

    def _claim_fresh_production(self):
        if self.started:return
        for rva,size in _ZERO_SPANS+tuple((identifier,12) for _,_,_,identifier in FACETS):
            if self.memory.read(self.base+rva,size)!=bytes(size):
                raise PrimarySemanticUnavailable('shared locale source changed before its original producer; warm adoption unsupported')
        if self.memory.read(self.base+0x674DDD0,32)!=bytes(32):
            raise PrimarySemanticUnavailable('shared C holder was produced outside current supported source epoch')
        self.started=True

    def prepare_stream_guard(self,runtime):
        self.validate(runtime)
        if not self.operation.acquire(False):raise PrimarySemanticUnavailable('shared locale concurrent/reentrant producer unsupported')
        try:
            self._claim_fresh_production()
            self._guard(runtime,0x674DE18,lambda:self.memory.store(self.base+0x674DE10,self.default_wrapper(runtime),8,source='781270.publish_shared_wrapper'))
            if (self.memory.load(self.base+0x674DE10,8)!=self.base+0x674DE08 or
                    self.memory.load(self.base+0x674DE08,8)!=self.base+0x674EA90 or
                    self.installed!=[row[2] for row in FACETS]):
                raise PrimarySemanticUnavailable('shared locale guards did not execute the complete original producer')
            self.complete=True
        except BaseException:
            self.poisoned=True;raise
        finally:self.operation.release()


def release_C_holder(runtime):
    capability=getattr(runtime,'_shared_locale_source',None)
    if type(capability) is not _SharedLocaleSource:raise InputError('C holder callback lacks its source image')
    capability.validate_image(runtime)
    if runtime.memory.load(runtime.image_base+0x674DDE0,8):
        raise PrimarySemanticUnavailable('77DFE0 nonempty owned String container destructor unsupported')
    return None


def install_fresh_image(signer):
    import sys
    from .primary_signer import PrimarySigner,_SOURCE as profile
    frame=sys._getframe(1)
    if type(signer) is not PrimarySigner or profile!=_SOURCE or frame.f_code is not PrimarySigner._initialize_image.__code__ or frame.f_locals.get('self') is not signer:
        raise InputError('shared locale capability requires original fixed fresh image construction')
    memory=signer.memory;base=signer.image_base;regions=[]
    for rva,raw in ((0x674DDD0,bytes(32)),(0x48A38AB,b'C\0')):
        region,offset=memory._span(base+rva,len(raw))
        if offset or len(region.data)!=len(raw) or region.name!='fixed device identifier image' or memory.read(base+rva,len(raw))!=raw:
            raise InputError('shared locale existing holder/literal original source mismatch')
        regions.append((base+rva,region,len(raw)))
    spans=((0x6755690,4),)+_ZERO_SPANS+tuple((identifier,12) for _,_,_,identifier in FACETS)
    for rva,size in spans:
        memory.map(base+rva,bytearray(size),name='fixed PE shared locale fresh zero span',initialized=True)
        regions.append((base+rva,memory._span(base+rva,size)[0],size))
    memory.map(base+0x3EBE4F0,(0x70).to_bytes(4,'little'),name='fixed PE digest stream virtual base offset',initialized=True)
    regions.append((base+0x3EBE4F0,memory._span(base+0x3EBE4F0,4)[0],4))
    # Fixed .data raw DWORD, not a chosen locale policy or a test flag.
    memory.map(base+0x6744B80,bytearray.fromhex('feffffff'),name='fixed PE CRT locale policy mask',initialized=True)
    regions.append((base+0x6744B80,memory._span(base+0x6744B80,4)[0],4))
    for rva,target in _METHODS:
        memory.map(base+rva,(base+target).to_bytes(8,'little'),name='fixed PE shared locale relocated method',initialized=True)
        regions.append((base+rva,memory._span(base+rva,8)[0],8))
    return _SharedLocaleSource(signer,regions,_SOURCE_FACTORY)


def bind_fresh_runtime(signer):
    import sys
    from .primary_signer import PrimarySigner
    frame=sys._getframe(1)
    if type(signer) is not PrimarySigner or frame.f_code is not PrimarySigner.__init__.__code__ or frame.f_locals.get('self') is not signer:
        raise InputError('shared locale source requires its original runtime binding')
    capability=signer._shared_locale_image
    if capability.runtime is not None:raise InputError('shared locale source cannot be rebound')
    capability.runtime=signer.runtime;signer.runtime._shared_locale_source=capability
    signer.runtime._shared_locale_source_epoch=capability.epoch


def invoke(runtime,rva,values):
    source=getattr(runtime,'_shared_locale_source',None)
    if type(source) is not _SharedLocaleSource:raise PrimarySemanticUnavailable('missing shared locale image source')
    if rva==0x77DFE0 and not values:return release_C_holder(runtime)
    source.validate(runtime)
    if rva==0x781270 and len(values)==1:return copy_shared_locale(runtime,values[0])
    if rva in (0x781180,0x769A10) and not values:
        if not source.operation.acquire(False):raise PrimarySemanticUnavailable('shared locale contended direct producer unsupported')
        try:
            source._claim_fresh_production()
            return source.default_wrapper(runtime) if rva==0x781180 else source.holder(runtime)
        except BaseException:
            source.poisoned=True;raise
        finally:source.operation.release()
    if rva==0x3E6E7F8 and not values:return current_character_table(runtime)
    raise InputError('unsupported shared locale source entry/ABI')


class _ModelCurrentLocaleInput:
    def activate(self):
        return _activate_model_module_tls(self.runtime,self)

    def deactivate(self):
        _invalidate_module_tls(self.runtime)

    def __init__(self,runtime,current_thread,tls_base):
        self.runtime=runtime;self.current_thread=current_thread;self.tls_base=tls_base
        self.thread=threading.get_ident();self.regions=(runtime.memory._span(current_thread,0x3C8)[0],runtime.memory._span(tls_base,0xD78)[0])

    def validate(self,runtime,source):
        from .primary_custom_allocator import ModelAllocatorIssuer
        issuer=getattr(runtime,'_primary_allocator_issuer',None)
        if (runtime is not self.runtime or threading.get_ident()!=self.thread or
                type(issuer) is not ModelAllocatorIssuer or source.source_kind!='synthetic-test-input' or
                issuer.source.origin!='synthetic' or issuer.source.phase!='complete' or
                runtime.crt_thread_address!=self.current_thread or runtime.tls_base_address!=self.tls_base or
                runtime.tls_epoch_address!=self.tls_base+0xA8 or self.tls_base==source.signer.tls_base or
                runtime.allocations.get(self.current_thread,0)<0x3C8 or runtime.allocations.get(self.tls_base,0)<0xD78 or
                getattr(runtime,'crt_startup_observations',None) is not None or getattr(runtime,'_crt_dispatch_active',False)):
            raise InputError('explicit model locale input current CRT/TLS/source identity changed')
        issuer.validate()
        for address,size,region in ((self.current_thread,0x3C8,self.regions[0]),(self.tls_base,0xD78,self.regions[1])):
            current,offset=runtime.memory._span(address,size)
            if current is not region or offset:raise InputError('model locale input region replaced')
        if self.current_thread < self.tls_base+0xD78 and self.tls_base < self.current_thread+0x3C8:
            raise InputError('model current CRT and TLS inputs overlap')
        runtime.memory.read(self.current_thread+0x90,8)
        runtime.memory.read(self.current_thread+0x3A8,4)
        runtime.memory.read(self.tls_base+0xA8,4)
        if runtime.memory.load(self.current_thread,8)!=runtime.image_base+0x45BCD00:
            raise InputError('model locale input lacks actual CRT thread initializer header')


def install_model_shared_locale_source(runtime,*,current_crt_thread,tls_base):
    source=getattr(runtime,'_shared_locale_source',None)
    if type(source) is not _SharedLocaleSource or source.source_kind is not None or source.model_input is not None or source.complete:
        raise InputError('model locale input requires an unused original source image capability')
    if type(current_crt_thread) is not int or type(tls_base) is not int:
        raise InputError('model locale input requires explicit current CRT and separate TLS addresses')
    value=_ModelCurrentLocaleInput(runtime,current_crt_thread,tls_base)
    source.source_kind='synthetic-test-input';source.model_input=value
    try:
        _activate_model_module_tls(runtime,value)
        source.validate(runtime)
    except BaseException:
        source.poisoned=True;raise
    return value


_TLS_RECEIPT_FACTORY=object()


class ModuleTLSReceipt:
    """One active guest-module lookup; never an observed native TLS index."""
    native_index='UNOBSERVED'
    def __init__(self,runtime,source,origin,tls,service,domain,token):
        import os
        if token is not _TLS_RECEIPT_FACTORY:raise InputError('module TLS receipt requires its source activation')
        self.runtime=runtime;self.source=source;self.image_epoch=source.epoch
        self.module_identity=_SOURCE;self.index_field,self.index_offset=runtime.memory._span(runtime.image_base+0x6755690,4)
        self.origin=origin;self.tls_base=tls;self.epoch_address=tls+0xA8
        self.region,self.offset=runtime.memory._span(tls,0xD78)
        self.thread=(os.getpid(),threading.get_ident(),threading.get_native_id())
        self.service=service;self.domain=domain;self.active=True

    def validate(self,runtime,module_identity):
        import os
        source=self.source
        if (not self.active or runtime is not self.runtime or module_identity!=_SOURCE or
                self.module_identity!=_SOURCE or source is not getattr(runtime,'_shared_locale_source',None) or
                self.image_epoch is not source.epoch or self.native_index!='UNOBSERVED' or
                self.thread!=(os.getpid(),threading.get_ident(),threading.get_native_id()) or
                getattr(runtime,'_current_module_tls_receipt',None) is not self):
            raise InputError('guest module TLS activation/module/thread/epoch is stale or foreign')
        source.validate_image(runtime)
        field,offset=runtime.memory._span(runtime.image_base+0x6755690,4)
        region,tls_offset=runtime.memory._span(self.tls_base,0xD78)
        if (field is not self.index_field or offset!=self.index_offset or region is not self.region or
                tls_offset!=self.offset or tls_offset or runtime.tls_base_address!=self.tls_base or
                runtime.tls_epoch_address!=self.epoch_address or self.tls_base==source.signer.tls_base):
            raise InputError('guest module TLS field/region/lookup/current aliases changed')
        if self.origin=='synthetic-test-input':
            if self.domain is not source.model_input:raise InputError('model TLS domain replaced')
            self.domain.validate(runtime,source)
        elif self.origin=='guest-windows-thread-domain':
            from .primary_windows_threads import WindowsSDKThreadService,_LIVE_SERVICES
            service=self.service;domain=self.domain;tid=self.thread[2]
            if (type(service) is not WindowsSDKThreadService or service not in _LIVE_SERVICES or
                    service._runtime is not runtime or service._closed or service._crt_domains.get(tid) is not domain or
                    domain['tls']!=self.tls_base or domain.get('services_closed') is not False):
                raise InputError('guest Windows TLS source service/domain no longer live')
            lease=service._registrar.current_lease()
            if lease.registrar is not service._registrar or not lease.active or lease.suspended or lease.thread_id!=tid:
                raise InputError('guest module TLS has no current execution lease')
        else:raise InputError('unknown guest module TLS provenance')
        return self


def _invalidate_module_tls(runtime,*,domain=None):
    source=getattr(runtime,'_shared_locale_source',None)
    registry=getattr(source,'_registered_module_domains',None)
    if domain is not None and type(registry) is dict:
        entry=registry.get(id(domain))
        if entry is not None and entry[1] is domain:del registry[id(domain)]
    receipt=getattr(runtime,'_current_module_tls_receipt',None)
    if type(receipt) is ModuleTLSReceipt and (domain is None or receipt.domain is domain):
        receipt.active=False
        runtime._current_module_tls_receipt=None


def _activate_native_module_tls(runtime,service,domain):
    import os,sys
    from .primary_windows_threads import WindowsSDKThreadService,_LIVE_SERVICES
    caller=sys._getframe(1);tid=threading.get_native_id()
    allowed=(WindowsSDKThreadService._native_crt_context.__wrapped__.__code__,WindowsSDKThreadService._restore_domain.__code__)
    if (caller.f_code not in allowed or caller.f_locals.get('self') is not service or
            type(service) is not WindowsSDKThreadService or service not in _LIVE_SERVICES or
            service._runtime is not runtime or service._closed or service._owner[0]!=os.getpid() or
            service._crt_domains.get(tid) is not domain or domain['tls']!=runtime.tls_base_address or
            runtime.tls_epoch_address!=domain['tls']+0xA8 or domain.get('services_closed') is not False):
        raise InputError('guest module TLS requires its original native domain create/activation')
    source=getattr(runtime,'_shared_locale_source',None)
    if type(source) is not _SharedLocaleSource:raise InputError('guest module TLS lacks fixed image source')
    source.validate_image(runtime)
    if source.model_input is not None or source.source_kind=='synthetic-test-input':
        raise InputError('synthetic module TLS provenance cannot upgrade through a native domain')
    registry=getattr(source,'_registered_module_domains',None)
    if registry is None:registry={};source._registered_module_domains=registry
    region,offset=runtime.memory._span(domain['tls'],0xD78)
    if offset or runtime.allocations.get(domain['tls'],0)<0xD78:
        raise InputError('module TLS activation is not original live guest storage')
    if caller.f_code is WindowsSDKThreadService._native_crt_context.__wrapped__.__code__:
        if caller.f_locals.get('runtime') is not runtime or caller.f_locals.get('tls')!=domain['tls']:
            raise InputError('module TLS allocation differs from original native context locals')
        registry[id(domain)]=(service,domain,tid,domain['tls'],region,source.epoch)
    else:
        prior=registry.get(id(domain))
        if (prior is None or prior[0] is not service or prior[1] is not domain or prior[2]!=tid or
                prior[3]!=domain['tls'] or prior[4] is not region or prior[5] is not source.epoch):
            raise InputError('cannot reactivate foreign/replaced/unregistered module TLS storage')
    lease=service._registrar.current_lease()
    if not lease.active or lease.suspended or lease.thread_id!=tid:raise InputError('native TLS activation lost original lease')
    _invalidate_module_tls(runtime)
    runtime._current_module_tls_receipt=ModuleTLSReceipt(runtime,source,'guest-windows-thread-domain',domain['tls'],service,domain,_TLS_RECEIPT_FACTORY)
    return runtime._current_module_tls_receipt


def resolve_current_module_tls(runtime,*,module_identity=None):
    expected=_SOURCE if module_identity is None else module_identity
    receipt=getattr(runtime,'_current_module_tls_receipt',None)
    if type(receipt) is not ModuleTLSReceipt:raise InputError('no active fixed guest module TLS association')
    return receipt.validate(runtime,expected)


def _activate_model_module_tls(runtime,model):
    source=getattr(runtime,'_shared_locale_source',None)
    if type(source) is not _SharedLocaleSource or source.model_input is not model:
        raise InputError('model module TLS requires its explicit installed input domain')
    source.validate_image(runtime);model.validate(runtime,source)
    _invalidate_module_tls(runtime)
    runtime._current_module_tls_receipt=ModuleTLSReceipt(runtime,source,'synthetic-test-input',model.tls_base,None,model,_TLS_RECEIPT_FACTORY)
    return runtime._current_module_tls_receipt


def _has_registered_native_module_tls(runtime,service,domain):
    source=getattr(runtime,'_shared_locale_source',None)
    registry=getattr(source,'_registered_module_domains',None)
    prior=None if type(registry) is not dict else registry.get(id(domain))
    return prior is not None and prior[0] is service and prior[1] is domain and prior[2]==threading.get_native_id()
