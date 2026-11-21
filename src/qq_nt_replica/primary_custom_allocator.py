"""Source-bounded upper allocator with independent CUSTOM guest storage.

These are exact fresh PE fields, not a warm-state default or empty hook table.
"""
import sys
import threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable

_SOURCE='63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'
_INITIAL_HOOKS=((0x6181C60,0x1B3AE0E),(0x6181CA8,0x1B3AE3E),(0x6181CF0,0x1B3AE80))
_FRESH_ZERO_FIELDS=((0x6777BB8,8),(0x6777BB0,4),(0x6777C00,4),(0x6D8306C,4))

def install_fresh_image(signer):
    from .primary_signer import PrimarySigner,_SOURCE as profile_source
    frame=sys._getframe(1)
    if (type(signer) is not PrimarySigner or profile_source!=_SOURCE or
            frame.f_code is not PrimarySigner._initialize_image.__code__ or frame.f_locals.get('self') is not signer):
        raise InputError('custom hook source requires its original fresh image initializer')
    for rva,callback in _INITIAL_HOOKS:
        # Count and callback slot are QWORDs; callback is the source DIR64 relocation.
        raw=(1).to_bytes(8,'little')+(signer.image_base+callback).to_bytes(8,'little')
        signer.memory.map(signer.image_base+rva,bytearray(raw),name='fixed source initial custom hook table',initialized=True)
    for rva,size in _FRESH_ZERO_FIELDS:
        signer.memory.map(signer.image_base+rva,bytearray(size),name='fixed source custom virtual-tail field',initialized=True)
    return _HookState(signer.memory,signer.image_base)


class CustomDomainUnsupported(PrimarySemanticUnavailable):
    def __init__(self, reason, mode=None):
        super().__init__('custom allocation domain not implemented: '+reason)
        self.mode, self.reason = mode, reason


class _HookState:
    def __init__(self, memory, base):
        self.memory, self.base = memory, base
        spans=tuple((rva,16) for rva,_ in _INITIAL_HOOKS)+_FRESH_ZERO_FIELDS
        self.regions={rva:(memory._span(base+rva,size)[0],size) for rva,size in spans}
        self.complete=False; self.poisoned=False; self.steps=[]
        self.lock=threading.Lock()

    def _current(self):
        if self.poisoned:raise CustomDomainUnsupported('failed hook initialization')
        for rva,(region,size) in self.regions.items():
            actual,offset=self.memory._span(self.base+rva,size)
            if actual is not region or offset or len(region.data)!=size:raise CustomDomainUnsupported('hook source region replaced')
        if self.memory.load(self.base+0x6D8306C,4)!=0:raise CustomDomainUnsupported('nondefault hook logging level')
        if self.memory.load(self.base+0x6777BB8,8)!=0:raise CustomDomainUnsupported('dynamic free hook table')
        if self.memory.load(self.base+0x6777BB0,4)!=0:raise CustomDomainUnsupported('hook mutex contention/state')

    def before_allocate(self):
        if not self.lock.acquire(False):raise CustomDomainUnsupported('concurrent hook initialization')
        try:
            self._current()
            memory,base=self.memory,self.base
            once=memory.load(base+0x6777C00,4)
            if self.complete:
                if once!=1 or any(memory.load(base+rva,8) or memory.load(base+rva+8,8) for rva,_ in _INITIAL_HOOKS):
                    raise CustomDomainUnsupported('completed hook state changed')
                self.steps.append('B75544.empty_redispatch');return
            if once!=0:raise CustomDomainUnsupported('unproved once state')
            for rva,callback in _INITIAL_HOOKS:
                if (memory.load(base+rva,8),memory.load(base+rva+8,8))!=(1,base+callback):
                    raise CustomDomainUnsupported('nonfresh callback table')
            self.steps.append('B75544.callback')
            memory.store(base+0x6777C00,2,4,source='1B3B373.once_claim');self.steps.append('once2')
            for rva,callback in _INITIAL_HOOKS:
                memory.store(base+0x6777BB0,1,4,source='1B3AD2C.mutex_claim')
                memory.store(base+rva+8,0,8,source='1B3AD2C.remove_matching_callback')
                memory.store(base+rva,0,8,source='1B3AD10.trim_empty_tail')
                memory.store(base+0x6777BB0,0,4,source='1B3AD2C.mutex_release')
                self.steps.append('remove_'+hex(callback))
            memory.store(base+0x6777C00,1,4,source='1B3B373.once_complete')
            self.complete=True;self.steps.extend(('once1','B75544.empty_redispatch'))
        except BaseException:
            self.poisoned=True
            raise
        finally:self.lock.release()

    def before_free(self):
        self._current()
        if not self.complete:raise CustomDomainUnsupported('free before established hook initialization')


class _BoundGuestSupplier:
    def __init__(self, signer):
        self.signer=signer;self.runtime=signer.runtime;self.addresses=signer.addresses
        self.supplier=self.addresses.allocation
        self.validate(self.runtime)

    def validate(self,runtime):
        from .primary_signer import VirtualAddressSpace
        if (runtime is not self.runtime or self.signer.runtime is not runtime or
                runtime._primary_entry_owner is not self.signer or self.signer.addresses is not self.addresses or
                type(self.addresses) is not VirtualAddressSpace):
            raise CustomDomainUnsupported('unsupported guest address source')
        for bound in (self.supplier,runtime._allocations,self.addresses.allocation):
            if (getattr(bound,'__self__',None) is not self.addresses or
                    getattr(bound,'__func__',None) is not VirtualAddressSpace.allocation):
                raise CustomDomainUnsupported('guest address binding changed')
        if (getattr(runtime,'_history_environment',None) is not None or
                getattr(runtime,'_policy3_binding',None) is not None):
            raise CustomDomainUnsupported('history/policy address domain')

    def take(self,runtime,size):
        self.validate(runtime)
        observed,zero,pointer=self.supplier(size,False)
        if observed!=size or zero is not False:raise InputError('custom guest supplier size/knownness mismatch')
        return pointer


class _OwnedStorage:
    """Custom-family opaque storage; never calls or records source lower CRT."""
    def __init__(self,runtime,selector,hooks,supplier):
        self.runtime,self.selector,self.hooks,self.supplier=runtime,selector,hooks,supplier
        self.epoch=selector.epoch;self.base=runtime.image_base;self.live={};self.closed=False;self.source_free_seen=[];self.storage_disposed=[]

    def _validate(self):
        if self.closed:raise InputError('custom storage is retired')
        self.selector.validate(self.runtime)
        if self.selector.epoch is not self.epoch or self.runtime.image_base!=self.base:
            raise InputError('custom storage image epoch changed')
        self.supplier.validate(self.runtime)

    def allocate(self,size,mode,entry):
        self._validate()
        if type(mode) is not int or mode not in (0,1):raise InputError('custom allocation mode must be source0 or1')
        if type(size) is not int or not 1<=size<=0x1000000:
            raise CustomDomainUnsupported('size/OOM/retry/throw policy',mode)
        self.hooks.before_allocate()
        pointer=self.supplier.take(self.runtime,size)
        if type(pointer) is not int or not 0<pointer<=(1<<64)-1-size:
            raise CustomDomainUnsupported('guest address failure/OOM policy',mode)
        try:buffer=bytearray(size)
        except (MemoryError,OverflowError) as error:raise CustomDomainUnsupported('OOM handler/retry/throw',mode) from error
        self.runtime.memory.map(pointer,buffer,name='source custom owned storage',initialized=False)
        region,offset=self.runtime.memory._span(pointer,size)
        if offset or pointer in self.live:raise InputError('custom storage address overlaps live ownership')
        self.live[pointer]=(region,size,self.epoch,threading.get_ident(),entry,mode)
        return pointer

    def free(self,pointer):
        self._validate();self.hooks.before_free()
        if type(pointer) is not int:raise InputError('custom free needs an actual pointer')
        record=self.live.get(pointer)
        if record is None:raise InputError('custom free requires live custom-family ownership')
        region,size,epoch,thread,entry,mode=record
        if epoch is not self.epoch or thread!=threading.get_ident():
            raise CustomDomainUnsupported('unproved cross-thread free transfer',mode)
        actual,offset=self.runtime.memory._span(pointer,size)
        if actual is not region or offset:raise InputError('custom allocation region identity changed')
        self.runtime.memory.forget(pointer,size,source='B74C19.custom_invalidated')
        self.runtime.memory.unmap(pointer);region.data.release();del self.live[pointer]
        self.source_free_seen.append(record)


class _CustomBackend:
    def __init__(self,signer):
        self.runtime=signer.runtime;self.signer=signer
        self.source=self.runtime._primary_allocator_selector
        self.storage=_OwnedStorage(self.runtime,self.source,signer._custom_hook_image,_BoundGuestSupplier(signer))
        self.records={};self.closed=False;self.operation=threading.Lock()

    def dispatch(self,rva,values):
        if not self.operation.acquire(False):
            raise CustomDomainUnsupported('concurrent/reentrant whole upper allocation')
        try:return self._dispatch(rva,values)
        finally:self.operation.release()

    def _dispatch(self,rva,values):
        if self.closed:raise InputError('upper allocator backend is retired')
        if rva not in (0xB75000,0xB75029,0xB7593F,0xB758ED) or len(values)!=1:
            raise InputError('unsupported whole upper allocator entry/ABI')
        issuer=getattr(self.runtime,'_primary_allocator_issuer',None)
        from .primary_windows_allocator_issuer import WindowsAllocatorIssuer
        if type(issuer) not in (ModelAllocatorIssuer, WindowsAllocatorIssuer):raise CustomDomainUnsupported('missing explicit allocator selector issuer')
        crt=issuer.choose(self.runtime)
        from .primary_worker_consumer import _invoke
        if rva in (0xB75000,0xB7593F):
            size=values[0];mode=0 if rva==0xB75000 else 1
            pointer=_invoke(self.runtime,0x3E97020,size) if crt else self.storage.allocate(size,mode,rva)
            if pointer in self.records:raise InputError('upper allocation repeats a live pointer')
            region,offset=self.runtime.memory._span(pointer,size)
            if offset:raise InputError('upper allocation is not an exact storage base')
            self.records[pointer]=(region,size,self.source.epoch,threading.get_ident(),'CRT' if crt else 'CUSTOM')
            return pointer
        pointer=values[0]
        record=self.records.get(pointer)
        if record is None:raise InputError('upper delete requires its actual upper allocation family')
        region,size,epoch,thread,family=record
        if epoch is not self.source.epoch or thread!=threading.get_ident():raise CustomDomainUnsupported('unproved upper free ownership transfer')
        actual,offset=self.runtime.memory._span(pointer,size)
        if actual is not region or offset or (family=='CRT') is not crt:raise InputError('upper free region/selection/family changed')
        if crt:_invoke(self.runtime,0x3E94F90,pointer)
        else:self.storage.free(pointer)
        del self.records[pointer]

    def retire_storage(self):
        if self.closed:raise InputError('custom storage retirement is already complete')
        from .primary_windows_allocator_issuer import WindowsAllocatorIssuer
        frame=sys._getframe(1)
        if frame.f_code not in (WindowsAllocatorIssuer.retire.__code__,dispose_model_allocator.__code__):
            raise InputError('custom storage disposal requires its terminal source/model lifecycle')
        if not self.operation.acquire(False):
            raise CustomDomainUnsupported('custom storage disposal during active upper operation')
        try:
            # Host-model teardown after guest dtors, never reported as source B74C19 frees.
            for pointer,record in tuple(self.storage.live.items()):
                region,size=record[:2]
                actual,offset=self.runtime.memory._span(pointer,size)
                if actual is not region or offset:raise InputError('retired custom storage identity changed')
                self.runtime.memory.forget(pointer,size,source='model.custom_storage_teardown')
                self.runtime.memory.unmap(pointer);region.data.release();del self.storage.live[pointer]
                self.storage.storage_disposed.append(record)
            self.records={pointer:record for pointer,record in self.records.items() if record[4]!='CUSTOM'}
            self.closed=True;self.storage.closed=True
        finally:
            self.operation.release()


def bind_runtime_core(signer):
    from .primary_signer import PrimarySigner
    frame=sys._getframe(1)
    if type(signer) is not PrimarySigner or frame.f_code is not PrimarySigner.__init__.__code__ or frame.f_locals.get('self') is not signer:
        raise InputError('custom core requires the original constructed signer runtime')
    runtime=signer.runtime
    if getattr(runtime,'_custom_allocator_backend',None) is not None:raise InputError('custom core cannot be rebound')
    runtime._custom_allocator_backend=_CustomBackend(signer)


class _AllocatorOwner:
    def __init__(self, issuer):
        from .primary_allocator_selector import _identity
        self.observer=issuer; self.runtime=issuer.runtime; self.source=issuer.source
        self.image_base=self.runtime.image_base; self.epoch=self.source.epoch
        self.heap=self.source.heap; self.origin=issuer.origin; self.identity=_identity()

    def _command_line(self):
        self.source.require_capture(self.runtime,self)
        pointer,raw,logical,release=self.observer.capture(self)
        try:
            self.observer.validate()
            self.source.accept_input(self.runtime,self,pointer,raw,logical,release)
        except BaseException:
            release(); raise
        return pointer


class _Issuer:
    def _owner(self):
        from .primary_allocator_selector import _identity
        self.validate()
        identity=_identity()
        owner=self.owners.get(identity)
        if owner is None:
            owner=_AllocatorOwner(self)
            self.source.register(owner,self.origin)
            self.owners[identity]=owner
        return owner

    def choose(self,runtime):
        if runtime is not self.runtime:raise InputError('allocator issuer has another runtime')
        owner=self._owner()
        result=self.source.choice(runtime,owner)
        self.validate()
        return result

    def validate(self):
        if self.closed or getattr(self.runtime,'_primary_allocator_issuer',None) is not self:
            raise InputError('allocator issuer is not its live installed source')
        self.source.validate(self.runtime)
        if self.source.epoch is not self.epoch:raise InputError('allocator issuer epoch changed')
        if self.source.phase=='complete':self.source.require_origin(self.runtime,self.origin)

    def close(self):
        self.validate()
        if self.source._borrow is not None:raise InputError('allocator issuer still owns a live source borrow')
        self.closed=True;self.owners.clear()


class ModelAllocatorIssuer(_Issuer):
    """Explicit synthetic source input, never a Windows receipt."""
    def __init__(self,runtime,material,supplier):
        if sys._getframe(1).f_code is not install_model_allocator.__code__:
            raise InputError('model allocator issuer requires its explicit installer')
        from .primary_notification_files import FileSelectorMaterial
        if type(material) is not FileSelectorMaterial or material.source_kind!='synthetic-test-input':
            raise InputError('model allocator requires complete explicit synthetic material')
        backend=runtime._custom_allocator_backend
        if (getattr(supplier,'__self__',None) is not backend.storage.supplier.addresses or
                getattr(supplier,'__func__',None) is not backend.storage.supplier.supplier.__func__):
            raise InputError('model custom supplier must be explicitly bound to this actual signer address source')
        backend.storage.supplier.validate(runtime)
        self.runtime=runtime;self.source=runtime._primary_allocator_selector;self.epoch=self.source.epoch
        if self.source.phase!='fresh' or material.initial_state!=self.source.cache:
            raise InputError('model input requires its actual fresh source')
        self.material=material;self.origin='synthetic';self.closed=False;self.owners={};self.calls=0

    def capture(self,owner):
        self.validate();self.source.require_capture(self.runtime,owner)
        if self.material is None or self.calls:raise InputError('model input is one-use')
        self.calls+=1;material=self.material;raw=bytearray(material.command_line_bytes)
        def release():
            raw[:]=bytes(len(raw));raw.clear();self.material=None
        return material.command_line_pointer,raw,raw.index(0)+1,release


def install_model_allocator(runtime,material,*,supplier):
    if getattr(runtime,'_primary_allocator_issuer',None) is not None:
        raise InputError('allocator issuer cannot be rebound')
    issuer=ModelAllocatorIssuer(runtime,material,supplier)
    runtime._primary_allocator_issuer=issuer
    return issuer


def dispose_model_allocator(runtime):
    issuer=getattr(runtime,'_primary_allocator_issuer',None)
    if type(issuer) is not ModelAllocatorIssuer:raise InputError('model disposal cannot retire Windows provenance')
    issuer.validate()
    if (runtime._active_main is not None or runtime._program_calls or
            getattr(runtime,'_primary_provider_initialization_owner',None) is not None or
            getattr(runtime,'_primary_public_direct_owner',None) is not None or
            getattr(runtime,'_primary_close_direct_owner',None) is not None):
        raise InputError('model disposal requires an inactive completed guest operation')
    runtime._custom_allocator_backend.retire_storage()
    issuer.closed=True;issuer.owners.clear();issuer.material=None
