"""Fresh-image B75773 choice shared by upper allocation consumers.

Lower CRT entries do not select; a completed receipt retains its original
model/Windows provenance. Backend capability is checked by whole upper entries.
"""
import os
import sys
import threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable

_FACTORY=object()
_PATTERN=b'--notcmalloc'
_CAP=0x20000

def _identity():return os.getpid(),threading.get_ident(),threading.get_native_id()

def _readonly_alias_region(memory,ledger,pointer,raw,logical):
    """Only the new capture's logical NUL extent matters, never its read tail."""
    if (type(ledger) is not list or type(raw) is not bytearray or type(logical) is not int or
            not 1<=logical<=_CAP or len(raw)<logical or raw[logical-1]!=0 or 0 in raw[:logical-1]):
        raise InputError('selector alias needs its exact logical source CString')
    matches=[item[1] for item in ledger if type(item) is tuple and len(item)==2 and item[0]==pointer]
    if len(matches)!=1:raise InputError('selector alias is absent or ambiguous in the original owner ledger')
    region,offset=memory._span(pointer,logical)
    if region is not matches[0] or offset or len(region.data)!=logical or not region.data.readonly:
        raise InputError('selector alias is not the exact live readonly parent region')
    if memory.read(pointer,logical)!=bytes(raw[:logical]):raise InputError('selector alias differs from the independent logical capture')
    return region

class ModelCommandLineAlias:
    """Explicit controlled-model source window; not a Windows parent capability."""
    def __init__(self,runtime,pointer):
        self.runtime=runtime;self.source=runtime._primary_allocator_selector;self.epoch=self.source.epoch
        self.identity=_identity();self.pointer=pointer;self.region=runtime.memory._span(pointer,1)[0]
        self.ledger=[(pointer,self.region)];self.window_open=True;self.calls=0
    def validate(self,runtime,owner,raw,logical):
        self.calls+=1
        if (not self.window_open or owner.origin!='synthetic' or runtime is not self.runtime or
                owner.source is not self.source or self.source.epoch is not self.epoch or self.identity!=_identity()):
            raise InputError('model selector alias window/thread/epoch is not current')
        self.source.require_owner(runtime,owner)
        region=_readonly_alias_region(runtime.memory,self.ledger,self.pointer,raw,logical)
        if region is not self.region:raise InputError('model selector alias region identity changed')
        return region
    def expire(self):self.window_open=False
    def close_refs(self):
        self.window_open=False;self.runtime=self.source=self.epoch=self.region=self.ledger=None

class _SharedSelector:
    def __init__(self,signer,token):
        if token is not _FACTORY:raise InputError('selector source requires actual fresh image construction')
        self.memory,self.base=signer.memory,signer.image_base
        self.region,offset=self.memory._span(self.base+0x6750E80,2)
        if offset or len(self.region.data)!=2 or self.memory.read(self.base+0x6750E80,2)!=b'\0\0':raise InputError('selector image needs its exact known fresh source region')
        self.heap_region,heap_offset=self.memory._span(self.base+0x6D8EC90,8)
        self.heap=self.memory.load(self.base+0x6D8EC90,8)
        if heap_offset or len(self.heap_region.data)!=8 or not self.heap:raise InputError('selector source lacks its fresh guest heap identity')
        self.epoch=object();self.runtime=None;self.cache=b'\0\0';self.phase='fresh';self.origin=None
        self._owners={};self._lock=threading.Lock();self._active=None;self._borrow=None;self._completed_receipt=None
    def bind(self,runtime):
        if self.runtime is not None or runtime.memory is not self.memory or runtime.image_base!=self.base:raise InputError('selector source cannot be rebound')
        self.runtime=runtime
        runtime._primary_allocator_selector=self;runtime._primary_allocator_selector_epoch=self.epoch
    def _receipt_matches(self,runtime):
        receipt=self._completed_receipt
        return (type(receipt) is tuple and len(receipt)==8 and receipt[0] is runtime and
            receipt[1] is self.memory and receipt[2] is self.region and receipt[3] is self.heap_region and
            receipt[4]==self.heap and receipt[5] is self.epoch and receipt[6]==self.origin and receipt[7]==self.cache)

    def validate(self,runtime):
        if self.phase=='poisoned':raise PrimarySemanticUnavailable('shared selector source failed and cannot be restarted')
        if ((self.phase=='complete' and not self._receipt_matches(runtime)) or
                (self.phase!='complete' and self._completed_receipt is not None) or
                (self.phase=='fresh' and (self.origin is not None or self.cache!=b'\0\0'))):
            self.phase='poisoned';raise InputError('selector phase/origin differs from its source completion receipt')
        if (runtime is not self.runtime or runtime.memory is not self.memory or runtime.image_base!=self.base or getattr(runtime,'_primary_allocator_selector',None) is not self or getattr(runtime,'_primary_allocator_selector_epoch',None) is not self.epoch):raise InputError('selector runtime/image/source epoch identity changed')
        region,offset=self.memory._span(self.base+0x6750E80,2)
        if region is not self.region or offset or len(region.data)!=2 or self.memory.read(self.base+0x6750E80,2)!=self.cache:
            self.phase='poisoned';raise InputError('selector source region/cache changed outside its producer')
        heap_region,heap_offset=self.memory._span(self.base+0x6D8EC90,8)
        if heap_region is not self.heap_region or heap_offset or self.memory.load(self.base+0x6D8EC90,8)!=self.heap:
            self.phase='poisoned';raise InputError('selector source guest heap identity changed')
    def safe_state(self,runtime):
        """Enums and source-identity booleans only; never command-line material."""
        phase=self.phase if self.phase in ('fresh','initializing','complete','poisoned') else 'UNKNOWN'
        origin=self.origin if self.origin in ('synthetic','windows') else 'UNSELECTED'
        complete=phase=='complete' and self._receipt_matches(runtime)
        selection=('CRT' if self.cache[1] else 'CUSTOM') if complete else 'UNKNOWN'
        return dict(phase=phase,origin=origin,selection=selection,
            same_runtime_source=runtime is self.runtime and getattr(runtime,'_primary_allocator_selector',None) is self,
            same_epoch=getattr(runtime,'_primary_allocator_selector_epoch',None) is self.epoch,
            input_consumed=complete,borrow_live=self._borrow is not None)

    def register(self,owner,origin):
        self.validate(owner.runtime)
        from .primary_notification_files import _SharedFileAllocatorOwner,install_shared_model_allocator,_install_shared_file_allocator
        caller=sys._getframe(1)
        from .primary_custom_allocator import _AllocatorOwner, _Issuer
        file_owner = type(owner) is _SharedFileAllocatorOwner and caller.f_code in (install_shared_model_allocator.__code__,_install_shared_file_allocator.__code__)
        upper_owner = type(owner) is _AllocatorOwner and caller.f_code is _Issuer._owner.__code__
        if not (file_owner or upper_owner) or origin not in ('synthetic','windows') or owner in self._owners:raise InputError('selector owner requires its finite source installer')
        if self.phase=='complete' and origin!=self.origin:raise InputError('selector completion cannot cross synthetic/Windows provenance')
        self._owners[owner]=(origin,owner.observer,owner.identity)
    def owner_for(self,runtime,observer):
        self.validate(runtime)
        matches=[owner for owner,entry in self._owners.items() if entry[1] is observer and entry[2]==_identity()]
        if len(matches)!=1:raise InputError('file selector lacks its current thread/source allocation owner')
        return matches[0]
    def require_owner(self,runtime,owner):
        self.validate(runtime);entry=self._owners.get(owner)
        from .primary_custom_allocator import _AllocatorOwner
        installed = (getattr(runtime,'_primary_allocator_issuer',None) is owner.observer if type(owner) is _AllocatorOwner else getattr(runtime,'notification_file_observations',None) is owner.observer)
        if (entry is None or entry[0]!=owner.origin or entry[1] is not owner.observer or
                entry[2]!=_identity() or owner.identity!=entry[2] or owner.source is not self or
                owner.runtime is not runtime or owner.image_base!=self.base or owner.epoch is not self.epoch or
                owner.heap!=self.heap or not installed):
            raise InputError('selector consumer source/thread/image/heap/epoch identity changed')
        if self.phase=='complete' and entry[0]!=self.origin:raise InputError('selector warm receipt has another provenance domain')
        return entry[0]
    def require_origin(self,runtime,origin):
        self.validate(runtime)
        if self.phase!='complete' or origin!=self.origin:raise InputError('selector completion does not authorize that origin domain')
        return bool(self.cache[1])
    def require_capture(self,runtime,owner):
        self.require_owner(runtime,owner)
        if self.phase!='initializing' or self._active is not owner or self.cache[0]!=1 or self._borrow is not None:raise InputError('command line borrow lacks its checked-before-API source call')
    def accept_input(self,runtime,owner,pointer,raw,logical,release,alias=None):
        self.require_capture(runtime,owner)
        from .primary_notification_files import _SharedFileAllocatorOwner
        from .primary_windows_command_line import capture_file_selector,_FileCommandLineAlias
        caller=sys._getframe(1)
        from .primary_custom_allocator import _AllocatorOwner
        expected=(_AllocatorOwner._command_line.__code__ if type(owner) is _AllocatorOwner else _SharedFileAllocatorOwner._command_line.__code__ if self._owners[owner][0]=='synthetic' else capture_file_selector.__code__)
        if caller.f_code is not expected or type(pointer) is not int or not 0<pointer<2**64 or type(raw) is not bytearray or type(logical) is not int or not 1<=logical<=_CAP or len(raw)<logical or raw[logical-1]!=0 or 0 in raw[:logical-1] or not callable(release):raise InputError('selector requires its exact bounded source borrow')
        if alias is not None:
            expected_alias=ModelCommandLineAlias if self._owners[owner][0]=='synthetic' else _FileCommandLineAlias
            if type(alias) is not expected_alias or alias.pointer!=pointer:raise InputError('selector alias belongs to another provenance domain or pointer')
            region=alias.validate(runtime,owner,raw,logical);buffer=None
        else:
            buffer=bytearray(raw[:logical]);self.memory.map(pointer,buffer,name='private source selector command line',initialized=True)
            region,offset=self.memory._span(pointer,logical)
        self._borrow=(pointer,logical,raw,buffer,region,release,alias)
        return pointer
    def _release_input(self):
        borrow=self._borrow;self._borrow=None
        if borrow is None:return
        pointer,logical,raw,buffer,region,release,alias=borrow
        try:
            if alias is not None:
                alias.close_refs()
            else:
                actual,offset=self.memory._span(pointer,logical)
                if actual is not region or offset:raise InputError('selector borrow mapping identity was replaced')
                self.memory.unmap(pointer);region.data.release();buffer[:]=bytes(len(buffer));buffer.clear()
        finally:release()
    def choice(self,runtime,owner):
        origin=self.require_owner(runtime,owner)
        if not self._lock.acquire(False):
            self.phase='poisoned';raise PrimarySemanticUnavailable('concurrent/reentrant shared selector initialization is unsupported')
        try:
            self.validate(runtime)
            if self.phase=='fresh':
                self.origin=origin;self._active=owner;self.phase='initializing'
                try:
                    self.memory.store(self.base+0x6750E80,1,1,source='B75780.shared_checked_before_API');self.cache=bytes((1,self.cache[1]))
                    pointer=owner._command_line()
                    self.require_owner(runtime,owner)
                    if self.phase!='initializing' or self._borrow is None:raise InputError('selector API did not publish its one-use source borrow')
                    observed,logical,raw,buffer,region,release,alias=self._borrow
                    if alias is not None:alias.validate(runtime,owner,raw,logical)
                    actual,offset=self.memory._span(pointer,logical)
                    if pointer!=observed or actual is not region or offset or self.memory.read(pointer,logical)!=bytes(raw[:logical]):raise InputError('selector pointer/bytes differ from its source borrow')
                    if self.memory.read(self.base+0x485330A,len(_PATTERN)+1)!=_PATTERN+b'\0':raise InputError('selector fixed substring literal differs')
                    if _PATTERN in self.memory.read(pointer,logical-1):
                        self.memory.store(self.base+0x6750E81,1,1,source='B757A1.shared_substring_hit');self.cache=bytes((1,1))
                    if alias is not None:alias.validate(runtime,owner,raw,logical)
                    from .primary_custom_allocator import _AllocatorOwner
                    if type(owner) is _AllocatorOwner:owner.observer.validate()
                    self._release_input()
                    raw=buffer=region=release=alias=None
                    self._completed_receipt=(runtime,self.memory,self.region,self.heap_region,self.heap,self.epoch,self.origin,self.cache)
                    self.phase='complete';self._active=None
                except BaseException as primary:
                    self.phase='poisoned'
                    try:self._release_input()
                    except BaseException as cleanup:raise BaseExceptionGroup('selector initialization and borrow cleanup failed',[primary,cleanup])
                    finally:self._active=None
                    raise
            elif self.phase!='complete':
                self.phase='poisoned';raise PrimarySemanticUnavailable('shared selector initialization is incomplete')
            self.require_owner(runtime,owner)
            return bool(self.cache[1])
        finally:self._lock.release()

    def select(self,runtime,owner):
        if not self.choice(runtime,owner):
            raise PrimarySemanticUnavailable('legacy file selector custom allocator remains unsupported')

def create_fresh_image(signer):
    from .primary_signer import PrimarySigner
    frame=sys._getframe(1)
    if type(signer) is not PrimarySigner or frame.f_code is not PrimarySigner._initialize_image.__code__ or frame.f_locals.get('self') is not signer:raise InputError('selector provenance requires the actual fresh image initializer')
    return _SharedSelector(signer,_FACTORY)

def bind_fresh_runtime(signer):
    from .primary_signer import PrimarySigner
    frame=sys._getframe(1)
    if type(signer) is not PrimarySigner or frame.f_code is not PrimarySigner._bind_runtime.__code__ or frame.f_locals.get('self') is not signer:raise InputError('selector binding requires the original runtime construction')
    signer._allocator_selector_image.bind(signer.runtime)
