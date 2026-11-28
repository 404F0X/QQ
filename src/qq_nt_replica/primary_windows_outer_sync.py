"""Lazy owned same-backing Windows CS port; no API load before operation."""
import ctypes as C
import os
import threading
from dataclasses import dataclass,replace
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


@dataclass(frozen=True)
class _Resource:
    allocation:int
    allocation_record:tuple
    token:object
    view:object
    native:object
    api_initialized:object=None


class WindowsOuterSync:
    def __init__(self,owner,permit):
        from .primary_windows_signer import WindowsSigner
        from .primary_custom_allocator import _CustomBackend
        if type(owner) is not WindowsSigner or type(getattr(owner.signer.runtime,'_custom_allocator_backend',None)) is not _CustomBackend:
            raise InputError('outer sync requires its actual Windows owner and allocator backend')
        owner._check_owner()
        self.__owner=owner;self.__runtime=owner.signer.runtime;self.__permit=permit
        self.__thread=(os.getpid(),threading.get_native_id());self.__records={}
        self.__allocator=self.__runtime._custom_allocator_backend
        self.__epoch=self.__allocator.source.epoch;self.__base=self.__runtime.image_base
        self.__kernel=None;self.__active=False;self.__terminal=False

    def _check(self,operation):
        owner=self.__owner
        if (self.__terminal or self.__thread!=(os.getpid(),threading.get_native_id()) or
                owner.signer.runtime is not self.__runtime or self.__active or
                self.__runtime._custom_allocator_backend is not self.__allocator or
                self.__allocator.source.epoch is not self.__epoch or self.__runtime.image_base!=self.__base or
                getattr(self.__allocator,'closed',False)):
            raise InputError('outer sync session is stale/terminal/foreign/active')
        self.__allocator.source.validate(self.__runtime)
        if not callable(self.__permit) or not self.__permit(owner,operation):
            raise PrimarySemanticUnavailable('outer sync native operation scope unavailable')

    def _api(self,name,result,types,*args):
        if self.__kernel is None:
            if os.name!='nt' or C.sizeof(C.c_void_p)!=8:raise PrimarySemanticUnavailable('Windows x64 CS port required')
            self.__kernel=C.WinDLL('kernel32',use_last_error=True)
        fn=getattr(self.__kernel,name);fn.restype,fn.argtypes=result,types
        return fn(*args)

    def initialize(self,allocation):
        self._check('InitializeCriticalSectionEx')
        runtime=self.__runtime;memory=runtime.memory
        backend=getattr(runtime,'_custom_allocator_backend',None)
        record=None if backend is None else backend.records.get(allocation)
        if record is None or record[1]!=0x50 or record[2] is not backend.source.epoch or record[3]!=threading.get_ident():
            raise InputError('CS requires actual live50-byte source allocation')
        region,offset=memory._span(allocation,0x50)
        if region is not record[0] or offset or memory.load(runtime.image_base+0x6745268,8)!=allocation:
            raise InputError('CS source allocation/global identity mismatch')
        if allocation in self.__records:raise InputError('CS native backing already issued')
        token,view=memory._pin_native_span(allocation+0x18,40,self)
        try:native=(C.c_ubyte*40).from_buffer(view)
        except BaseException:
            memory._unpin_native_span(token,self);view.release();raise
        resource=_Resource(allocation,record,token,view,native)
        self.__records[allocation]=resource
        self.__active=True
        try:
            try:
                result=self._api('InitializeCriticalSectionEx',C.c_int32,(C.c_void_p,C.c_uint32,C.c_uint32),C.addressof(native),0,0)
                self.__records[allocation]=replace(resource,api_initialized=bool(result))
                # Capture thread error immediately, before any other Windows call.
                error=0 if result else self._api('GetLastError',C.c_uint32,())
            finally:memory._record_native_write(token,self,source='InitializeCriticalSectionEx.actual_backing')
            self.__records[allocation]=replace(resource,api_initialized=bool(result))
            return result,error
        finally:self.__active=False

    def dispose_terminal(self):
        self._check('DeleteCriticalSection')
        if self.__owner._busy or self.__owner._state!='closing':
            raise InputError('outer sync disposal requires the quiescent terminal owner-close phase')
        self.__terminal=True
        for allocation,record in tuple(self.__records.items()):
            runtime=self.__runtime;backend=runtime._custom_allocator_backend
            if backend.records.get(allocation) is not record.allocation_record:
                raise InputError('CS allocation ownership changed before disposal')
            runtime.memory._validate_native_pin(record.token,self)
            if record.api_initialized is None:
                raise PrimarySemanticUnavailable('CS native initialization outcome unknown; backing retained')
            if record.api_initialized:
                self._api('DeleteCriticalSection',None,(C.c_void_p,),C.addressof(record.native))
                runtime.memory._record_native_write(record.token,self,source='host_outer_sync.DeleteCriticalSection')
            runtime.memory._unpin_native_span(record.token,self)
            del self.__records[allocation]
            record.view.release()
        self.__kernel=None


def bind_outer_sync(owner,*,permit):
    from .primary_windows_signer import WindowsSigner
    if type(owner) is not WindowsSigner:raise InputError('CS port requires actual Windows owner')
    owner._check_owner()
    runtime=owner.signer.runtime
    if getattr(runtime,'_outer_sync_port',None) is not None:raise InputError('outer CS port already bound')
    port=WindowsOuterSync(owner,permit);runtime._outer_sync_port=port
    return port
