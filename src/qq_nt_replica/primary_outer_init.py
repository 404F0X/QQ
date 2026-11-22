"""Source-aligned public LoginService prefix; inner initialization stays diagnostic."""
from dataclasses import dataclass
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_logger import _String
from .primary_worker_consumer import _invoke


_KEYS=('commonPath','clientVer','machineId','platVer','hostName')


@dataclass(frozen=True)
class _Config:
    strings:tuple
    appid:object
    external_version:bool


def _convert(value):
    if type(value) is not dict:
        raise PrimarySemanticUnavailable('public initConfig non-object/coercion domain unavailable')
    return value



def login_nt_data_path(runtime,source):
    """9AE42A finite drive-absolute ASCII path; independent owned result."""
    raw=source.value()
    import re
    if (any(value>=128 for value in raw) or b'\0' in raw or
            re.fullmatch(rb'[A-Za-z]:\\[A-Za-z0-9_-]+(?:\\[A-Za-z0-9_-]+)*',raw) is None):
        raise PrimarySemanticUnavailable('9AE42A unsupported path normalization/encoding domain')
    return _String.construct(runtime,raw+b'\\nt_data')


def _global_sync(runtime):
    from .primary_login_model_attach import validate_birth
    validate_birth(runtime)
    memory,base=runtime.memory,runtime.image_base
    current=memory.load(base+0x6745268,8)
    if current:return current
    pointer=_invoke(runtime,0xB75000,0x50)
    if not pointer:raise PrimarySemanticUnavailable('5C195E allocation/OOM unavailable')
    for offset in (0x28,0x18,8):memory.write(pointer+offset,bytes(16),source='5C6E10.constructor_zero')
    memory.store(pointer+0x38,0,8,source='5C6E10.field38')
    memory.store(base+0x6745268,pointer,8,source='5C6E10.publish_before_field40')
    memory.store(pointer+0x40,0,8,source='5C6E10.field40')
    from .primary_windows_outer_sync import WindowsOuterSync
    port=getattr(runtime,'_outer_sync_port',None)
    if type(port) is not WindowsOuterSync:raise PrimarySemanticUnavailable('owned InitializeCriticalSectionEx port unavailable')
    result,error=port.initialize(pointer)
    hr=0 if result else ((0x80070000|(error&0xffff)) if 0<error<0x80000000 else error)
    if hr&0x80000000:memory.store(base+0x67451d4,1,1,source='5C6E10.sticky_failure')
    else:memory.store(pointer+8,0x38,4,source='5C6E10.success_status')
    memory.store(pointer,base+0x3f466f8,8,source='5C6CBE.vtable')
    memory.store(base+0x6745280,pointer,8,source='5C6CBE.derived_publish')
    return pointer


def _container(runtime,address):
    runtime.memory.store(address,address+8,8,source='3BA6.head')
    runtime.memory.write(address+8,bytes(16),source='3BA6.empty')


def _install_owner_dispatch(runtime):
    address=runtime.image_base+0x3f655d8+0x20
    expected=runtime.image_base+0x6d3dcc
    from .primary_memory import PrimaryMemoryLimit
    try:observed=runtime.memory.load(address,8)
    except PrimaryMemoryLimit:
        runtime.memory.map(address,expected.to_bytes(8,'little'),name='fixed source LoginService initConfig slot',initialized=True)
    else:
        if observed!=expected:raise InputError('LoginService source virtual target mismatch')


def _construct_owner(runtime):
    memory,base=runtime.memory,runtime.image_base
    _install_owner_dispatch(runtime)
    control=_invoke(runtime,0xB75000,0x320);obj=control+0x18
    memory.store(control,base+0x3f65548,8,source='6E02D2.control_vtable')
    memory.store(control+8,0,4,source='6E02D2.strong_initial')
    memory.store(control+0x10,0,4,source='6E02D2.weak_initial')
    memory.write(obj,bytes(0x308),source='6E03C9.memset_source_object')
    for offset,value in zip(range(0,0x48,8),(0x3f655d8,0x3f65708,0x3f65728,0x3f657a8,0x3f657d8,0x3f657f8,0x3f65808,0x3f65828,0x3f65858)):
        memory.store(obj+offset,base+value,8,source='6E03EC.interface_vtable')
    _container(runtime,obj+0x68);_container(runtime,obj+0xe8)
    for offset in (0x100,0x118,0x130,0x148,0x160,0x1a8,0x1c0,0x1d8,0x1f0,0x210):
        _invoke(runtime,0x6270,obj+offset)
    state=obj+0x270
    memory.store(state,base+0x3fed6a8,8,source='D3024C.base_vtable')
    memory.store(state+0x28,0xffffffff,4,source='D3024C.state28')
    memory.store(state,base+0x3fed718,8,source='D30AC0.derived_vtable')
    memory.store(state+0x88,base+0x236a,8,source='D30AC0.function88')
    memory.store(state+0x80,base+0x2338,8,source='D30AC0.function80')
    from .primary_sdk import _add_owner,_release_owner
    _add_owner(runtime,control)
    memory.store(control+0x10,memory.load(control+0x10,4)+1,4,source='168CE.weak_add')
    memory.store(obj+0x48,obj,8,source='168CE.selfweak_object')
    memory.store(obj+0x50,control,8,source='168CE.selfweak_control')
    _release_owner(runtime,control)
    return obj,control


def _module_pair(runtime):
    from .primary_shared_locale import resolve_current_module_tls
    receipt=resolve_current_module_tls(runtime)
    memory,base=runtime.memory,runtime.image_base;guard=base+0x674c740
    if memory.load(guard,4,signed=True)>memory.load(receipt.epoch_address,4,signed=True):
        runtime._thread_header(guard)
        if memory.load(guard,4,signed=True)==-1:
            obj,control=_construct_owner(runtime)
            memory.store(base+0x674c730,obj,8,source='6D3A08.module_object')
            memory.store(base+0x674c738,control,8,source='6D3A08.module_control')
            runtime._thread_footer(guard)
    return memory.load(base+0x674c730,8),memory.load(base+0x674c738,8),receipt.image_epoch


class _LoginWrapper:
    def __init__(self,service):self.__service=service
    @property
    def state(self):return self.__service.state
    def initConfig(self,*args):return self.__service.initConfig(self,*args)
    def require_ready(self):return self.__service.require_ready()
    def release_wrappers(self):return self.__service.release_wrapper(self)


class _LoginService:
    """Private module singleton backing, never an original SDK/native origin token."""
    def __init__(self,owner):
        self.__owner=owner
        self.__runtime=owner.signer.runtime
        self.__memory=self.__runtime.memory;self.__base=self.__runtime.image_base
        self.__epoch=None
        self.__backings={}
        self.__pending_backings=[]
        self.__object=None
        self.__control=None
        self.__state='UNINITIALIZED'
        self.__failure=None
        self.__active=False

    def select(self):
        if self.__state=='UNAVAILABLE':raise PrimarySemanticUnavailable('outer entry already unavailable')
        self.__state='INITIALIZING'

    def fail(self):self.__state='UNAVAILABLE'

    def acquire_wrapper(self):
        self.__owner._check_owner()
        if self.__state=='UNAVAILABLE':raise PrimarySemanticUnavailable('unavailable source owner cannot resume')
        self.__state='INITIALIZING'
        try:
            backing=_invoke(self.__runtime,0xB75000,0x10)
            if not backing:raise PrimarySemanticUnavailable('Node backing allocation/OOM unavailable')
            self.__pending_backings.append(backing)
            obj,control,epoch=_module_pair(self.__runtime)
            if self.__epoch is not None and self.__epoch is not epoch:raise InputError('outer source image epoch changed')
            self.__epoch=epoch
            from .primary_sdk import _add_owner
            self.__runtime.memory.store(backing,obj,8,source='NodeLogin.wrap_object')
            self.__runtime.memory.store(backing+8,control,8,source='NodeLogin.wrap_control')
            if control:_add_owner(self.__runtime,control)
            self.__pending_backings.remove(backing)
            self.__object,self.__control=obj,control
            wrapper=_LoginWrapper(self)
            self.__backings[wrapper]=(backing,False)
            return wrapper
        except BaseException:
            self.__state='UNAVAILABLE';raise

    def release_wrapper(self,wrapper):
        self.__owner._check_owner()
        if self.__runtime.memory is not self.__memory or self.__runtime.image_base!=self.__base:
            raise InputError('source wrapper memory/image changed')
        from .primary_sdk import _release_owner
        record=self.__backings.get(wrapper)
        if record is None:raise InputError('closed or foreign source wrapper')
        backing,released=record
        if (self.__runtime.memory.load(backing,8)!=self.__object or self.__runtime.memory.load(backing+8,8)!=self.__control):
            raise InputError('wrapped source pair identity changed')
        if not released:
            _release_owner(self.__runtime,self.__control)
            self.__backings[wrapper]=(backing,True)
        _invoke(self.__runtime,0xB75029,backing)
        del self.__backings[wrapper]

    @property
    def state(self):return self.__state

    def initConfig(self,wrapper,*args):
        self.__owner._check_owner()
        if self.__owner._state!='open' or self.__owner.signer.runtime is not self.__runtime:
            raise PrimarySemanticUnavailable('outer source owner closed or runtime changed')
        if len(args)!=1:raise InputError('NodeIKernelLoginService.initConfig requires exactly one argument')
        if self.__state=='UNAVAILABLE' or self.__active:
            raise PrimarySemanticUnavailable('outer prefix unavailable/active; skip-resume is prohibited')
        temporaries=[]
        self.__state='INITIALIZING'
        try:
            from .primary_shared_locale import resolve_current_module_tls
            receipt=resolve_current_module_tls(self.__runtime)
            if receipt.image_epoch is not self.__epoch or self.__runtime.memory is not self.__memory or self.__runtime.image_base!=self.__base:
                raise InputError('initConfig source module epoch changed')
            memory=self.__runtime.memory
            wrapped=self.__backings.get(wrapper)
            if (self.__object is None or wrapped is None or wrapped[1] or
                    memory.load(wrapped[0],8)!=self.__object or memory.load(wrapped[0]+8,8)!=self.__control or
                    memory.load(memory.load(self.__object,8)+0x20,8)!=self.__runtime.image_base+0x6d3dcc):
                raise InputError('initConfig lost its source unwrap/virtual owner identity')
            config=_convert(args[0])
            self.__active=True;self.__state='INITIALIZING'
            from .primary_login_msf_record import produce,copy_to_login
            record_input=produce(self,config)
            _global_sync(self.__runtime)
            copy_to_login(self.__runtime,self.__object,record_input)
            target=self.__object+0x100
            path=login_nt_data_path(self.__runtime,_String.read(self.__runtime,target))
            _String.read(self.__runtime,target).destroy();path.write_to(target)
            from .primary_login_host_init import publish_hostname,msf_directory,publish_msf_directory
            publish_hostname(self.__runtime,_String.read(self.__runtime,self.__object+0x160))
            directory=msf_directory(self.__runtime,_String.read(self.__runtime,target))
            if not directory.value():
                from .primary_native_logger import empty_msf_path
                empty_msf_path(self.__runtime)
            publish_msf_directory(self.__runtime,directory.clone())
            temporaries.append(directory)
            log_values={}
            for offset in (0x148,0x130,0x118,0x100):
                log_values[offset]=_String.read(self.__runtime,self.__object+offset).clone()
            from .primary_native_logger import login_config
            login_config(self.__runtime,*(log_values[offset] for offset in (0x100,0x118,0x130,0x148)))
            from .primary_mmkv_host_init import initialize_login_root
            initialize_login_root(self.__runtime,_String.read(self.__runtime,target))
            from .primary_msf_selection import initialize_login_msf
            initialize_login_msf(self.__runtime,self.__object,record_input)
            raise PrimarySemanticUnavailable('6D4BBC continuation after existing MSF owner unavailable')
        except BaseException as error:
            if self.__state=='INITIALIZING':
                self.__state='UNAVAILABLE';self.__failure=type(error).__name__
            raise
        finally:
            # Host call bookkeeping only; source input/record cleanup follows normal VT return.
            self.__active=False

    def require_ready(self):
        if self.__state!='READY':
            raise PrimarySemanticUnavailable('outer source prefix has not completed; sign/notify/update unavailable')


_services={}

def require_selected_outer_ready(runtime):
    record=_services.get(id(runtime))
    if record is not None and record[0] is runtime and record[1].state!='UNINITIALIZED':
        record[1].require_ready()


def _selected_service(owner):
    from .primary_windows_signer import WindowsSigner
    if type(owner) is not WindowsSigner or owner._state!='open':
        raise InputError('outer entry requires its actual open Windows signer owner')
    owner._check_owner();runtime=owner.signer.runtime
    record=_services.get(id(runtime))
    if record is not None:
        if record[0] is not runtime:raise InputError('outer module identity mismatch')
        return record[1]
    service=_LoginService(owner);_services[id(runtime)]=(runtime,service)
    return service


def select_outer_entry(owner):
    service=_selected_service(owner);service.select();return service


def get_login_service(owner,*constructor_args):
    if constructor_args:raise InputError('NodeIKernelLoginService constructor requires zero arguments')
    return _selected_service(owner).acquire_wrapper()
