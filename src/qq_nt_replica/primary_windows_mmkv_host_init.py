"""Lazy scoped MMKV host primitives; no API load at construction/import."""
import os,sys,threading
from dataclasses import dataclass,replace
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable

_PORTS={}


@dataclass(frozen=True)
class _Backing:
    address:int
    region:object
    allocation:object
    token:object
    view:object
    native:object
    initialized:object=None
    raw_result:object=None
    last_error:object=None


@dataclass(frozen=True)
class _ViewIdentity:
    owner:object
    signer:object
    runtime:object
    memory:object
    base:int
    allocator:object
    source:object
    allocator_epoch:object
    allocator_issuer:object
    receipt:object
    module:object
    module_record:object
    module_epoch:object
    image:object
    image_epoch:object
    view:object
    view_owner:object
    guest:int
    length:int
    file_address:int
    file_allocation:object
    raw:int
    native:object
    mapping:int
    token:object
    pid:int
    thread:int


class WindowsMMKVHost:
    def __init__(self,owner,permit):
        if sys._getframe(1).f_code is not bind_windows_mmkv_host.__code__:
            raise InputError('MMKV host requires actual factory binding')
        self.__owner=owner;self.__runtime=owner.signer.runtime;self.__permit=permit
        self.__allocator=self.__runtime._custom_allocator_backend
        self.__epoch=self.__allocator.source.epoch;self.__memory=self.__runtime.memory
        self.__base=self.__runtime.image_base;self.__pid=os.getpid();self.__thread=threading.get_native_id()
        self.__open=None;self.__file_ops=[];self.__file_handles=[];self.__views={};self.__directory=None;self.__origin=None;self.__lock=None;self.__infos={};self.__failures=[]
        self.__active=False;self.__checking=False;self.__terminal=False;self.__kernel=None

    def _check(self,operation,*,terminal=False):
        from .primary_module_sync import _resource,MODEL_NATIVE
        r=self.__runtime;o=self.__owner
        if (self.__terminal or self.__active or self.__checking or self.__pid!=os.getpid() or
                self.__thread!=threading.get_native_id() or o.signer.runtime is not r or
                r.memory is not self.__memory or r.image_base!=self.__base or
                r._custom_allocator_backend is not self.__allocator or self.__allocator.source.epoch is not self.__epoch or
                self.__allocator.closed or self.__failures):
            raise PrimarySemanticUnavailable('MMKV host stale/active/terminal or persistent native failure')
        resource=_resource(r)
        if resource.backend!=MODEL_NATIVE or resource.owner is not o:
            raise InputError('MMKV host requires its immutable actual-factory MODEL_NATIVE birth')
        if terminal:
            if resource.callbacks or self.__allocator.source._borrow is not None:
                raise InputError('MMKV terminal source borrow remains active')
            if o._state!='closing' or o._busy:raise InputError('MMKV terminal owner is not quiescent')
        else:
            if o._state!='open' or o._threads._runtime is not r:
                raise InputError('MMKV source owner/runtime mismatch')
            from .primary_host_services import _ExecutionLease
            lease=o._registrar.current_lease()
            if type(lease) is not _ExecutionLease or not lease.active or lease.suspended or lease.thread_id!=self.__thread:
                raise InputError('MMKV native operation requires its active execution lease')
        if operation is not None:
            self.__checking=True
            try:
                if not self.__permit(o,operation):raise PrimarySemanticUnavailable('MMKV native operation scope denied')
            finally:self.__checking=False

    def _issue_lock(self,pointer):
        from .primary_mmkv_host_init import _initialize_cache
        f=sys._getframe(1)
        if f.f_code is not _initialize_cache.__code__ or f.f_locals.get('runtime') is not self.__runtime or self.__origin is not None:
            raise InputError('MMKV lock origin requires actual B99489 producer')
        self._check(None)
        record=self.__allocator.records.get(pointer)
        if record is None or record[1]!=40 or record[2] is not self.__epoch or record[3]!=threading.get_ident():
            raise InputError('MMKV lock allocation origin mismatch')
        region,offset=self.__memory._span(pointer,40)
        if region is not record[0] or offset or self.__memory.load(self.__base+0x6751390,8)!=pointer:
            raise InputError('MMKV source lock publication mismatch')
        self.__origin=(pointer,record)

    def _api(self,name,result,types,*args):
        import ctypes as C
        if self.__kernel is None:
            if os.name!='nt' or C.sizeof(C.c_void_p)!=8:raise PrimarySemanticUnavailable('MMKV Windows x64 host unavailable')
            self.__kernel=C.WinDLL('kernel32',use_last_error=True)
        fn=getattr(self.__kernel,name);fn.restype=result;fn.argtypes=types
        return fn(*args)

    def _capture(self,backing,operation,call):
        failures=[];result=None
        try:result=call()
        except BaseException as error:failures.append((operation,'api',error))
        try:self.__memory._record_native_write(backing.token,self,source=operation+'.actual_backing')
        except BaseException as error:failures.append((operation,'write_record',error))
        self.__failures.extend(failures)
        if len(failures)>1:raise BaseExceptionGroup('MMKV native operation and write observation failed',[x[2] for x in failures])
        if failures:raise failures[0][2]
        return result

    def initialize_lock(self):
        import ctypes as C
        self._check('InitializeCriticalSectionAndSpinCount')
        if self.__origin is None or self.__lock is not None:raise InputError('MMKV lock absent/already attempted')
        pointer,record=self.__origin
        actual,offset=self.__memory._span(pointer,40)
        if self.__allocator.records.get(pointer) is not record or actual is not record[0] or offset or self.__memory.load(self.__base+0x6751390,8)!=pointer:
            raise InputError('MMKV lock immutable origin changed')
        token,view=self.__memory._pin_native_span(pointer,40,self)
        try:native=(C.c_ubyte*40).from_buffer(view)
        except BaseException:
            self.__memory._unpin_native_span(token,self);view.release();raise
        self.__lock=_Backing(pointer,actual,record,token,view,native)
        self.__active=True
        def call():
            result=self._api('InitializeCriticalSectionAndSpinCount',C.c_int32,(C.c_void_p,C.c_uint32),C.addressof(native),400)
            # No permit/log/observation between source BOOL and immediate last-error.
            error=None
            try:error=0 if result else self._api('GetLastError',C.c_uint32,())
            finally:self.__lock=replace(self.__lock,initialized=bool(result),raw_result=result,last_error=error if not result else None)
            return result,error
        try:return self._capture(self.__lock,'InitializeCriticalSectionAndSpinCount',call)
        finally:self.__active=False

    def page_size(self):
        import ctypes as C
        from .primary_worker_response import _frame
        self._check('GetSystemInfo')
        pointer,unused=_frame(self.__runtime,48,'1BD8ED1 SYSTEM_INFO')
        region,offset=self.__memory._span(pointer,48)
        token,view=self.__memory._pin_native_span(pointer,48,self)
        try:native=(C.c_ubyte*48).from_buffer(view)
        except BaseException:
            self.__memory._unpin_native_span(token,self);view.release();self.__memory.unmap(pointer);raise
        backing=_Backing(pointer,region,None,token,view,native);self.__infos[pointer]=backing
        self.__active=True
        try:
            self._capture(backing,'GetSystemInfo',lambda:self._api('GetSystemInfo',None,(C.c_void_p,),C.addressof(native)))
            result=self.__memory.load(pointer+4,4)
            self.__memory._unpin_native_span(token,self);view.release();self.__memory.unmap(pointer)
            del self.__infos[pointer]
            return result
        finally:self.__active=False

    def _begin_open(self,session):
        from .primary_mmkv_open import open_mmkv
        f=sys._getframe(1)
        if f.f_code is not open_mmkv.__code__ or f.f_locals.get('runtime') is not self.__runtime or self.__open is not None:
            raise InputError('MMKV open requires unique real source entry')
        self._check(None);self.__open=session

    def preflight_close(self):
        # Deliberately side-effect-free, including when an earlier operation is unknown.
        if getattr(self.__runtime,'_mmkv_caller_pending',None) is not None or self.__directory is not None or self.__infos or self.__failures or (self.__open is not None and (self.__open['global_lock']!='not_entered' or self.__open['parent'] is not None or self.__open['files'] or self.__open['buffers'])) or self.__views or self.__file_ops:
            raise PrimarySemanticUnavailable('MMKV connected open has unresolved lock/parent/file/view debt')

    def _file_call(self,operation,result,types,args,*,publish=None,error=False):
        from .primary_mmkv_file import File40,FileLock
        from .primary_mmkv_open import _converted,_parent
        f=sys._getframe(1);caller=f.f_locals.get('self')
        internal=f.f_code in (WindowsMMKVHost._parent_cs.__code__,WindowsMMKVHost._enter_global.__code__,WindowsMMKVHost._leave_global.__code__,WindowsMMKVHost._map_view.__code__,WindowsMMKVHost._unmap_view.__code__) and caller is self
        source=(type(caller) is File40 and caller in self.__open['files'] or type(caller) is FileLock and caller in self.__open['locks']) if self.__open else False
        adapter=f.f_code in (_converted.__code__,_parent.__code__) and f.f_locals.get('r') is self.__runtime
        allowed=('EnterCriticalSection','LeaveCriticalSection','CreateFileW','MultiByteToWideChar','LockFileEx','UnlockFileEx','GetFileSizeEx','SetFilePointerEx','SetEndOfFile','WriteFile','CreateFileMappingW','MapViewOfFile','UnmapViewOfFile','CloseHandle','InitializeCriticalSectionAndSpinCount')
        if not (internal or source or adapter) or operation not in allowed:raise InputError('file API requires its actual connected source caller')
        self._check(operation)
        self.__allocator.source.validate(self.__runtime)
        if self.__open is None:raise InputError('file API lacks connected source session')
        record=dict(operation=operation,state='unknown',result=None,error=None,owner=caller)
        self.__file_ops.append(record);self.__active=True
        try:
            if operation=='EnterCriticalSection' and f.f_code is WindowsMMKVHost._enter_global.__code__:self.__open['global_lock']='enter_unknown'
            if operation=='LeaveCriticalSection' and f.f_code is WindowsMMKVHost._leave_global.__code__:self.__open['global_lock']='leave_unknown'
            value=self._api(operation,result,types,*args)
            record['result']=value
            if publish is not None:publish(value)
            failed=error(value) if callable(error) else error and not value
            last=self._api('GetLastError',__import__('ctypes').c_uint32,()) if failed else None
            record.update(state='returned',result=value,error=last)
            if operation in ('CreateFileW','CreateFileMappingW'):
                handle=value or 0;kind='file' if operation=='CreateFileW' else 'mapping'
                if handle!=(1<<64)-1 and handle!=-1 and (kind=='file' or handle):
                    self.__file_handles.append(dict(handle=handle,kind=kind,owner=caller,state='live'))
            if operation=='CloseHandle':
                for entry in self.__file_handles:
                    if entry['owner'] is caller and entry['handle']==args[0] and entry['state'] in ('live','unreleased'):
                        entry['state']='closed' if value else 'unreleased';break
            return value,last
        except BaseException as failure:self.__failures.append(failure);raise
        finally:self.__active=False

    def _enter_global(self):
        import ctypes as C
        record=self.__lock
        if record is None or not record.initialized:raise PrimarySemanticUnavailable('MMKV global CS not initialized')
        pointer=self.__memory.load(self.__open['global_guard'],8)
        if pointer!=record.address or self.__memory.load(self.__base+0x6751390,8)!=pointer or self.__allocator.records.get(pointer) is not record.allocation:
            raise InputError('global CS guard lost actual initialized backing')
        self.__memory._validate_native_pin(record.token,self)
        self._file_call('EnterCriticalSection',None,(C.c_void_p,),(C.addressof(record.native),))
        self.__open['global_lock']='held'

    def _leave_global(self):
        from .primary_mmkv_open import open_mmkv
        if sys._getframe(1).f_code is not open_mmkv.__code__ or self.__open['global_lock']!='held':raise InputError('MMKV global Leave requires source normal open suffix')
        import ctypes as C
        record=self.__lock
        if self.__memory.load(self.__open['global_guard'],8)!=record.address or self.__memory.load(self.__base+0x6751390,8)!=record.address:raise InputError('global Leave guard identity changed')
        self.__memory._validate_native_pin(record.token,self)
        self._file_call('LeaveCriticalSection',None,(C.c_void_p,),(C.addressof(record.native),))
        self.__open['global_lock']='released'

    def _parent_cs(self,parent,acquire):
        import ctypes as C
        from .primary_nt_config import get_string
        if sys._getframe(1).f_code is not get_string.__code__ or self.__open['parent']!=parent:raise InputError('private CS requires actual getter parent')
        self._check(None);pointer=self.__memory.load(parent+0xa8,8);record=self.__allocator.records.get(pointer)
        matches=[x for x in self.__open['buffers'] if isinstance(x,tuple) and len(x)==4 and x[3]==pointer]
        if len(matches)!=1 or record is None or record[1]!=40 or record[2] is not self.__epoch:raise InputError('private CS original constructor pin missing')
        pin,view,native,address=matches[0];region,offset=self.__memory._span(pointer,40)
        if region is not record[0] or offset:raise InputError('private CS original backing replaced')
        self.__memory._validate_native_pin(pin,self)
        name='EnterCriticalSection' if acquire else 'LeaveCriticalSection'
        self.__open['private_cs']='enter_unknown' if acquire else 'leave_unknown'
        self._file_call(name,None,(C.c_void_p,),(C.addressof(native),))
        self.__open['private_cs']='held' if acquire else 'released'

    def _capture_view_identity(self,memory,address,length,token):
        from .primary_memory import PrimaryMemory
        from .primary_module_sync import _resource,_RESOURCES
        if sys._getframe(1).f_code is not PrimaryMemory._issue_native_view.__code__:
            raise InputError('view identity requires original memory issuance')
        r=self.__runtime;view=self.__views.get(address)
        if memory is not self.__memory or view is None or view['state']!='unissued' or view['size']!=length:
            raise InputError('view identity lacks original pending mapping')
        module=_resource(r);source=self.__allocator.source;image=r._shared_locale_source
        identity=_ViewIdentity(self.__owner,self.__owner._signer,r,memory,self.__base,self.__allocator,
            source,self.__epoch,r._primary_allocator_issuer,source._completed_receipt,module,
            _RESOURCES.get(r),module.epoch,image,r._shared_locale_source_epoch,view,view['owner'],
            address,length,view['owner'].address,view['owner'].allocation,view['raw'],view['native'],view['mapping'],token,self.__pid,self.__thread)
        view['identity']=identity
        return identity

    def _validate_view_identity(self,identity,memory):
        # Guest access checks ownership only: no permit, execution lease or poisoned-state writes.
        from .primary_module_sync import _RESOURCES
        if type(identity) is not _ViewIdentity:raise InputError('foreign native view identity')
        issued=self.__views.get(identity.guest)
        if issued is None or issued.get('identity') is not identity:raise InputError('unissued native view identity')
        i=identity;r=i.runtime;o=i.owner
        if (self.__terminal or self.__owner is not o or self.__runtime is not r or
                self.__memory is not memory or memory is not i.memory or self.__base!=i.base or
                self.__allocator is not i.allocator or self.__epoch is not i.allocator_epoch or
                self.__pid!=i.pid or os.getpid()!=i.pid or self.__thread!=i.thread or
                o._pid!=i.pid or o._thread!=i.thread or o._signer is not i.signer or
                o._state not in ('open','closing','cleanup_failed') or i.signer.runtime is not r or
                r.memory is not memory or r.image_base!=i.base):
            raise InputError('native view owner/runtime/memory identity changed')
        if (r._custom_allocator_backend is not i.allocator or i.allocator.closed or
                i.allocator.runtime is not r or i.allocator.signer is not i.signer or
                i.allocator.source is not i.source or i.source.epoch is not i.allocator_epoch or
                r._primary_allocator_selector is not i.source or r._primary_allocator_selector_epoch is not i.allocator_epoch or
                r._primary_allocator_issuer is not i.allocator_issuer or i.allocator_issuer.closed or
                i.allocator_issuer.epoch is not i.allocator_epoch or i.source.phase!='complete' or
                i.source._completed_receipt is not i.receipt):
            raise InputError('native view allocator identity/epoch changed')
        if (r._shared_locale_source is not i.image or r._shared_locale_source_epoch is not i.image_epoch or
                i.image.epoch is not i.image_epoch or i.signer._shared_locale_image is not i.image or
                _RESOURCES.get(r) is not i.module_record or i.module.epoch is not i.module_epoch or
                i.module.owner is not o or i.module.locale is not i.image or i.module.locale_epoch is not i.image_epoch):
            raise InputError('native view module/image identity/epoch changed')
        i.module.validate(r)
        view=self.__views.get(i.guest)
        if (view is not i.view or view['owner'] is not i.view_owner or view['guest']!=i.guest or view['size']!=i.length or view['raw']!=i.raw or
                view['native'] is not i.native or view['mapping']!=i.mapping or view['token'] is not i.token or
                i.view_owner.r is not r or i.view_owner.port is not self or
                i.view_owner.address!=i.file_address or i.view_owner.allocation is not i.file_allocation or
                r._custom_allocator_backend.records.get(i.file_address) is not i.file_allocation):
            raise InputError('native view original mapping/file ownership changed')
        region,offset=memory._span(i.file_address,0x40)
        if region is not i.file_allocation[0] or offset:
            raise InputError('native view original File40 backing changed')

    def _map_view(self,mapping,size):
        import ctypes as C
        from .primary_mmkv_file import File40
        owner=sys._getframe(1).f_locals.get('self')
        if self.__open is None or type(owner) is not File40 or owner not in self.__open['files'] or owner.load(0x28)!=mapping or owner.native_extent!=size:raise InputError('mapping requires actual File40 producer')
        if size is not None and not 0<=size<=0x1000000:raise PrimarySemanticUnavailable('finite native mapping size unavailable')
        raw,error=self._file_call('MapViewOfFile',C.c_void_p,(C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_size_t),(mapping,0xf001f,0,0,0),publish=lambda raw:owner.store(0x30,0) if not raw else None,error=True)
        if not raw:return 0,error
        if size is None or size==0:
            raise PrimarySemanticUnavailable('successful native mapping extent is unproved; raw view debt retained')
        native=(C.c_ubyte*size).from_address(raw)
        address=self.__allocator.storage.supplier.take(self.__runtime,size)
        # Register host debt before issuing guest access; failed issuance retains native ownership.
        record=dict(raw=raw,native=native,size=size,guest=address,token=None,state='unissued',owner=owner,mapping=mapping)
        self.__views[address]=record
        record['token']=self.__memory._issue_native_view(self,address,native);record['state']='live'
        return address,None

    def _unmap_view(self,address):
        import ctypes as C
        record=self.__views.get(address)
        from .primary_mmkv_file import File40
        owner=sys._getframe(1).f_locals.get('self')
        if record is None or record['state']!='live' or type(owner) is not File40 or record['owner'] is not owner:raise InputError('view lacks live native origin')
        self.__memory._revoke_native_view(self,record['token'],begin=True);record['state']='revoking'
        try:
            result,error=self._file_call('UnmapViewOfFile',C.c_int32,(C.c_void_p,),(record['raw'],),error=True)
            if result:
                self.__memory._revoke_native_view(self,record['token'],success=True);del self.__views[address]
            else:self.__memory._revoke_native_view(self,record['token']);record['state']='unreleased'
            return result,error
        except BaseException:
            record['state']='unknown';raise

    def _prepare_directory(self,root):
        from .primary_mmkv_host_init import _directory
        f=sys._getframe(1)
        if f.f_code is not _directory.__code__ or f.f_locals.get('runtime') is not self.__runtime:
            raise InputError('MMKV directory preparation requires source adapter')
        self._check(None);root.validate(self.__runtime)
        if self.__directory is not None:raise PrimarySemanticUnavailable('MMKV pending directory cannot retry')

    def _directory_failed(self,error):
        if not self.__failures:self.__failures.append(error)

    def _issue_directory(self,work):
        from .primary_mmkv_host_init import _directory,_DirectoryWork
        import ctypes as C
        f=sys._getframe(1)
        if f.f_code is not _directory.__code__ or type(work) is not _DirectoryWork or work.runtime is not self.__runtime or self.__directory is not None:
            raise InputError('MMKV directory requires unique actual duplicate producer')
        self._check(None);work.root.validate(self.__runtime)
        token,view=self.__memory._pin_native_span(work.pointer,work.size,self)
        try:native=(C.c_uint16*(work.size//2)).from_buffer(view)
        except BaseException:self.__memory._unpin_native_span(token,self);view.release();raise
        self.__directory=(work,token,view,native,work.pointer,work.size,work.region,work.root)

    def _directory_record(self,work):
        record=self.__directory
        if record is None or record[0] is not work or (work.pointer!=record[4] or work.size!=record[5] or work.region is not record[6] or work.root is not record[7]):raise InputError('foreign/closed MMKV directory workbuffer')
        work.root.validate(self.__runtime)
        region,offset=self.__memory._span(work.pointer,work.size)
        if region is not work.region or offset or self.__runtime.allocations.get(work.pointer)!=work.size:
            raise InputError('MMKV directory CRT duplicate changed')
        self.__memory._validate_native_pin(record[1],self)
        return record

    def _directory_step(self,work):
        import ctypes as C
        self._check('GetFileAttributesW');record=self._directory_record(work)
        pointer=C.addressof(record[3]);self.__active=True
        try:attrs=self._api('GetFileAttributesW',C.c_uint32,(C.c_void_p,),pointer)&0xffffffff
        except BaseException as error:self.__failures.append(error);raise
        finally:self.__active=False
        if attrs!=0xffffffff:return attrs,None
        self._check('CreateDirectoryW');self._directory_record(work);self.__active=True
        try:
            result=self._api('CreateDirectoryW',C.c_int32,(C.c_void_p,C.c_void_p),pointer,0)
            error=None if result else self._api('GetLastError',C.c_uint32,())&0xffffffff
            return attrs,error
        except BaseException as error:self.__failures.append(error);raise
        finally:self.__active=False

    def _finish_directory(self,work):
        from .primary_worker_consumer import _invoke
        self._check(None);record=self._directory_record(work)
        self.__memory._unpin_native_span(record[1],self);record[2].release()
        try:_invoke(self.__runtime,0x3E94F90,work.pointer)
        except BaseException as error:self.__failures.append(error);raise
        self.__directory=None

    def dispose_terminal(self):
        import ctypes as C
        self.preflight_close()
        self._check(None,terminal=True)
        if self.__directory is not None:raise PrimarySemanticUnavailable('MMKV directory workbuffer remains unresolved')
        if self.__infos:raise PrimarySemanticUnavailable('MMKV SystemInfo borrow remains unresolved')
        record=self.__lock
        if record is not None:
            if record.initialized is None:raise PrimarySemanticUnavailable('MMKV CS initialization outcome unknown')
            if record.initialized:
                self._check('DeleteCriticalSection',terminal=True);self.__active=True
                try:
                    def delete():
                        self._api('DeleteCriticalSection',None,(C.c_void_p,),C.addressof(record.native))
                        self.__lock=replace(record,initialized=False)
                    self._capture(record,'DeleteCriticalSection.host_terminal',delete)
                finally:self.__active=False
            self.__memory._unpin_native_span(record.token,self);record.view.release();self.__lock=None
        self.__terminal=True


def bind_windows_mmkv_host(owner,permit):
    from .primary_windows_signer import WindowsSigner,open_windows_signer
    f=sys._getframe(1)
    if type(owner) is not WindowsSigner or f.f_code is not open_windows_signer.__code__ or f.f_locals.get('owner') is not owner or owner._state!='open' or not callable(permit):
        raise InputError('MMKV host binding requires actual selected factory')
    runtime=owner.signer.runtime
    if runtime in _PORTS:raise InputError('MMKV host cannot rebind/warm-adopt')
    port=WindowsMMKVHost(owner,permit);_PORTS[runtime]=port
    return port


def for_runtime(runtime):
    port=_PORTS.get(runtime)
    if port is None:raise PrimarySemanticUnavailable('MMKV scoped native host is not bound')
    return port


def dispose_terminal(owner):
    port=_PORTS.get(owner.signer.runtime)
    if port is not None:port.dispose_terminal()


def preflight_close(owner):
    if owner._signer is not None:
        port=_PORTS.get(owner._signer.runtime)
        if port is not None:port.preflight_close()
        from .primary_windows_mmkv_stdio import _PORTS as stdio_ports
        stdio=stdio_ports.get(owner._signer.runtime)
        if stdio is not None:stdio.preflight_close()
