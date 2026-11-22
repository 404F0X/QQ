"""Independent MODEL system-UCRT provider, lazy and source-call scoped."""
import os,sys,threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
_PORTS={}


class WindowsMMKVStdio:
    def __init__(self,owner,permit):
        if sys._getframe(1).f_code is not bind_windows_mmkv_stdio.__code__:raise InputError('stdio requires factory binding')
        self.__owner=owner;self.__runtime=owner.signer.runtime;self.__permit=permit
        self.__allocator=self.__runtime._custom_allocator_backend;self.__epoch=self.__allocator.source.epoch
        self.__memory=self.__runtime.memory;self.__base=self.__runtime.image_base
        self.__pid=os.getpid();self.__thread=threading.get_native_id()
        self.__library=None;self.__functions=None;self.__stdout=None
        self.__records={};self.__widepins={};self.__pins={};self.__failures=[];self.__active=False;self.__checking=False;self.__terminal=False

    def _check(self,operation=None,terminal=False):
        from .primary_module_sync import _resource,MODEL_NATIVE
        o=self.__owner;r=self.__runtime
        if (self.__terminal or self.__active or self.__checking or self.__failures or self.__pid!=os.getpid() or self.__thread!=threading.get_native_id() or
                o.signer.runtime is not r or r.memory is not self.__memory or r.image_base!=self.__base or r._custom_allocator_backend is not self.__allocator or
                self.__allocator.source.epoch is not self.__epoch or self.__allocator.closed):
            raise PrimarySemanticUnavailable('stdio session stale/active/terminal or sticky failure')
        resource=_resource(r)
        if resource.backend!=MODEL_NATIVE or resource.owner is not o:raise InputError('stdio MODEL_NATIVE factory origin mismatch')
        if terminal:
            if o._state!='closing' or o._busy or resource.callbacks or self.__allocator.source._borrow is not None:raise InputError('stdio terminal owner not quiescent')
        else:
            from .primary_host_services import _ExecutionLease
            lease=o._registrar.current_lease()
            if o._state!='open' or o._threads._runtime is not r or type(lease) is not _ExecutionLease or not lease.active or lease.suspended or lease.thread_id!=self.__thread:
                raise InputError('stdio requires active bound owner lease')
        if operation:
            self.__checking=True
            try:
                if not self.__permit(o,operation):raise PrimarySemanticUnavailable('stdio native operation scope denied')
            finally:self.__checking=False

    def _load(self):
        f=sys._getframe(1)
        if f.f_code not in (WindowsMMKVStdio._format.__code__,WindowsMMKVStdio._output.__code__):raise InputError('stdio loader is source-internal only')
        import ctypes as C
        if self.__library is None:
            if os.name!='nt' or C.sizeof(C.c_void_p)!=8:raise PrimarySemanticUnavailable('Windows x64 system UCRT required')
            library=C.CDLL('ucrtbase.dll',winmode=0x00000800)
            self.__library=library
            functions={name:getattr(library,name) for name in ('__stdio_common_vsprintf','__stdio_common_vfprintf','__acrt_iob_func')}
            functions['__stdio_common_vsprintf'].argtypes=(C.c_uint64,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,C.c_void_p)
            functions['__stdio_common_vfprintf'].argtypes=(C.c_uint64,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p)
            functions['__acrt_iob_func'].argtypes=(C.c_uint,)
            functions['__stdio_common_vsprintf'].restype=C.c_int
            functions['__stdio_common_vfprintf'].restype=C.c_int
            functions['__acrt_iob_func'].restype=C.c_void_p
            self.__library=library;self.__functions=functions
        return self.__functions

    def _begin(self,template,arguments,buffer):
        from .primary_mmkv_log import log
        f=sys._getframe(1)
        if f.f_code is not log.__code__ or f.f_locals.get('runtime') is not self.__runtime:raise InputError('stdio arguments require actual source log producer')
        self._check()
        from .primary_mmkv_host_init import _WideArgument
        from .primary_mmkv_file import WidePath,Pointer64,Unsigned64,LOGS
        wide={b'%ls attribute:%d not a directry':(_WideArgument,int),b'fail to create dir:%ls, %d':(_WideArgument,int),b'root dir: %ls':(_WideArgument,)}
        kinds={'wide':WidePath,'ptr':Pointer64,'size':Unsigned64,'int':int}
        wide.update({entry[4]:tuple(kinds[k] for k in entry[5]) for entry in LOGS.values()})
        if template not in (*wide,b'version %s, page size %d, arch %s',b'fail to init critical section:%d'):raise PrimarySemanticUnavailable('other MMKV printf template unavailable')
        expected=wide.get(template,(bytes,int,bytes) if template.startswith(b'version') else (int,))
        if len(arguments)!=len(expected) or any(type(value) is not kind for value,kind in zip(arguments,expected)):
            raise InputError('fixed MMKV va_list count/type mismatch')
        import ctypes as C
        region,offset=self.__memory._span(buffer,16)
        token=object();owned=[];slots=[];widepins=[]
        self.__widepins[token]=widepins
        for arg in arguments:
            if type(arg) in (_WideArgument,WidePath):
                if type(arg) is WidePath:arg.validate_log(self.__runtime)
                else:arg.validate(self.__runtime)
                pin,view=self.__memory._pin_native_span(arg.pointer,len(arg.raw),self)
                try:native=(C.c_uint16*(len(arg.raw)//2)).from_buffer(view)
                except BaseException as error:
                    self.__memory._unpin_native_span(pin,self);view.release();self.__failures.append(error);raise
                widepins.append((arg,pin,view,native));slots.append(C.addressof(native))
            elif type(arg) is bytes:
                if any(x>=128 for x in arg):raise PrimarySemanticUnavailable('non-ASCII MMKV CString provider unavailable')
                item=C.create_string_buffer(arg+b'\0');owned.append(item);slots.append(C.addressof(item))
            elif type(arg) in (Pointer64,Unsigned64):slots.append(arg.value&0xffffffffffffffff)
            elif type(arg) is int:slots.append(arg&0xffffffff)
            else:raise InputError('unsupported finite va_list argument')
        vector=(C.c_uint64*len(slots))(*slots);fmt=C.create_string_buffer(template+b'\0')
        self.__records[token]=(tuple(owned),vector,fmt,buffer,region,offset)
        self.__widepins[token]=widepins
        return token

    def _validate_wide(self,token):
        for arg,pin,view,native in self.__widepins.get(token,()):
            arg.validate(self.__runtime)
            from .primary_mmkv_file import WidePath
            if type(arg) is WidePath:arg.validate_log(self.__runtime)
            self.__memory._validate_native_pin(pin,self)

    def _format(self,token,buffer,capacity,options):
        from .primary_mmkv_log import _format
        if sys._getframe(1).f_code is not _format.__code__:raise InputError('stdio buffer requires actual7017B4 caller')
        self._check('__stdio_common_vsprintf')
        self._validate_wide(token)
        record=self.__records.get(token)
        if record is None:raise InputError('foreign/closed stdio call token')
        if buffer==record[3]:
            region,offset=self.__memory._span(buffer,capacity)
            if capacity!=16 or region is not record[4] or offset!=record[5]:raise InputError('stdio initial buffer changed')
        elif buffer==record[3]-31:
            region,offset=self.__memory._span(buffer,capacity)
            if not 16<=capacity<=23 or region is not record[4] or offset!=record[5]-31:
                raise InputError('stdio inline message buffer changed')
        else:
            allocation=self.__allocator.records.get(buffer)
            if allocation is None or allocation[1]<capacity or allocation[2] is not self.__epoch or allocation[3]!=threading.get_ident():raise InputError('stdio resized output is not owned allocation')
            region,offset=self.__memory._span(buffer,capacity)
            if offset or region is not allocation[0]:raise InputError('stdio output backing changed')
        import ctypes as C
        pin,view=self.__memory._pin_native_span(buffer,capacity,self)
        try:native=(C.c_ubyte*capacity).from_buffer(view)
        except BaseException:self.__memory._unpin_native_span(pin,self);view.release();raise
        self.__pins[pin]=(view,native);self.__active=True;errors=[];result=None
        try:
            try:result=self._load()['__stdio_common_vsprintf'](options,C.addressof(native),capacity,C.addressof(record[2]),0,C.addressof(record[1]))
            except BaseException as error:errors.append(error)
            try:self.__memory._record_native_write(pin,self,source='system_UCRT.vsprintf.actual_buffer')
            except BaseException as error:errors.append(error)
            if errors:
                self.__failures.extend(errors)
                if len(errors)>1:raise BaseExceptionGroup('stdio native/record failures',errors)
                raise errors[0]
            self.__memory._unpin_native_span(pin,self);view.release();del self.__pins[pin]
            return result
        finally:self.__active=False

    def _output(self,token,options,level,file,line,function,message):
        from .primary_mmkv_log import log
        if sys._getframe(1).f_code is not log.__code__:raise InputError('stdio output requires actual622D94 caller')
        self._check('__stdio_common_vfprintf')
        if token not in self.__records:raise InputError('foreign stdio output token')
        self._validate_wide(token)
        import ctypes as C
        leveltext={1:b'I',3:b'E'}.get(level)
        if leveltext is None:raise PrimarySemanticUnavailable('MMKV level text outside finite domain')
        values=(leveltext,file,line,function,message.value().split(b'\0',1)[0]);owned=[];slots=[]
        for arg in values:
            if type(arg) is int:slots.append(arg&0xffffffff)
            else:
                if any(x>=128 for x in arg):raise PrimarySemanticUnavailable('MMKV stdout non-ASCII unavailable')
                buf=C.create_string_buffer(arg+b'\0');owned.append(buf);slots.append(C.addressof(buf))
        vector=(C.c_uint64*len(slots))(*slots);fmt=C.create_string_buffer(b'[%s] <%s:%d::%s> %s\n\0')
        self.__records[token]=self.__records[token]+(tuple(owned),vector,fmt)
        if self.__stdout is None:self._check('__acrt_iob_func')
        self.__active=True
        try:
            functions=self._load()
            if self.__stdout is None:
                self.__stdout=functions['__acrt_iob_func'](1)
                if not self.__stdout:raise PrimarySemanticUnavailable('system UCRT stdout unavailable')
            return functions['__stdio_common_vfprintf'](options,self.__stdout,C.addressof(fmt),0,C.addressof(vector))
        except BaseException as error:self.__failures.append(error);raise
        finally:self.__active=False

    def _end(self,token):
        from .primary_mmkv_log import log
        if sys._getframe(1).f_code is not log.__code__:raise InputError('stdio call cleanup requires source log')
        self._check()
        if token not in self.__records:raise InputError('stdio call already closed')
        self._validate_wide(token)
        for arg,pin,view,native in self.__widepins.pop(token,()):
            self.__memory._unpin_native_span(pin,self);view.release()
        del self.__records[token]

    def preflight_close(self):
        if self.__records or self.__pins or self.__widepins or self.__failures:
            raise PrimarySemanticUnavailable('stdio live/failed call or borrowed buffer remains')

    def dispose_terminal(self):
        self.preflight_close()
        self._check(terminal=True)
        if self.__records or self.__pins or self.__widepins:raise PrimarySemanticUnavailable('stdio live call/buffer remains')
        self.__terminal=True;self.__stdout=None;self.__functions=None;self.__library=None
        # Borrowed system stdout is never fclose'd; dropping host references is not source teardown.


def bind_windows_mmkv_stdio(owner,permit):
    from .primary_windows_signer import WindowsSigner,open_windows_signer
    f=sys._getframe(1)
    if type(owner) is not WindowsSigner or f.f_code is not open_windows_signer.__code__ or f.f_locals.get('owner') is not owner or owner._state!='open' or not callable(permit):raise InputError('stdio requires actual selected factory')
    runtime=owner.signer.runtime
    if runtime in _PORTS:raise InputError('stdio cannot warm-adopt/rebind')
    port=WindowsMMKVStdio(owner,permit);_PORTS[runtime]=port;return port


def for_runtime(runtime):
    port=_PORTS.get(runtime)
    if port is None:raise PrimarySemanticUnavailable('scoped MMKV stdio provider missing')
    return port


def dispose_terminal(owner):
    port=_PORTS.get(owner.signer.runtime)
    if port is not None:port.dispose_terminal()
