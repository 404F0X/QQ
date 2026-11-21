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


class WindowsMMKVHost:
    def __init__(self,owner,permit):
        if sys._getframe(1).f_code is not bind_windows_mmkv_host.__code__:
            raise InputError('MMKV host requires actual factory binding')
        self.__owner=owner;self.__runtime=owner.signer.runtime;self.__permit=permit
        self.__allocator=self.__runtime._custom_allocator_backend
        self.__epoch=self.__allocator.source.epoch;self.__memory=self.__runtime.memory
        self.__base=self.__runtime.image_base;self.__pid=os.getpid();self.__thread=threading.get_native_id()
        self.__origin=None;self.__lock=None;self.__infos={};self.__failures=[]
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

    def dispose_terminal(self):
        import ctypes as C
        self._check(None,terminal=True)
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
