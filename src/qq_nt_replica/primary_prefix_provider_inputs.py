from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
import sys
from threading import get_ident

from .errors import InputError
from .primary_consumed_mgf import SourceIdentity, SOURCE_SHA256
from .primary_main_environment_inputs import MainEnvironmentIdentity, QualifiedMD5Callback
from .primary_singleton_history import RootCaptureIdentity, CapturedFrameSource


class ProviderState(Enum):
    NULL='NULL'
    RECOGNIZED_ENABLED='RECOGNIZED_ENABLED'
    UNKNOWN='UNKNOWN'


class MD5State(Enum):
    DISABLED='DISABLED'
    RECOGNIZED_ENABLED='RECOGNIZED_ENABLED'
    UNKNOWN='UNKNOWN'


def require(value,code):
    if not value:
        raise InputError('PREFIX_PROVIDER_'+code)


def uint(value,bits=64):
    return type(value) is int and 0<=value<1<<bits


@dataclass(frozen=True,repr=False)
class ProviderLineage:
    environment_identity: MainEnvironmentIdentity
    capture_identity: RootCaptureIdentity
    main_frame_source: CapturedFrameSource
    main_entry_sequence: int
    enter_sequence: int
    leave_sequence: int

    def __post_init__(self):
        require(type(self.environment_identity) is MainEnvironmentIdentity and type(self.capture_identity) is RootCaptureIdentity and type(self.main_frame_source) is CapturedFrameSource,'LINEAGE_TYPES')
        self.environment_identity.__post_init__()
        self.capture_identity.__post_init__()
        self.main_frame_source.__post_init__()
        identity,root,frame=self.environment_identity,self.capture_identity,self.main_frame_source
        require(identity.source_identity.wrapper_sha256==SOURCE_SHA256 and identity.main_epoch==identity.source_identity.candidate and
            frame.frame.program=='main' and root.generation==identity.source_identity.generation and
            frame.native_root==root.native_root and frame.native_thread==identity.native_thread_id and frame.invocation==identity.reader_invocation,'MAIN_READER_EPOCH')
        require(all(uint(value,53) and value>0 for value in (self.main_entry_sequence,self.enter_sequence,self.leave_sequence)) and
            self.main_entry_sequence<self.enter_sequence<self.leave_sequence,'SEQUENCE')


@dataclass(frozen=True,repr=False)
class HistoricalCacheString:
    header: bytes
    payload: bytes

    def __post_init__(self):
        require(type(self.header) is bytes and len(self.header)==24 and type(self.payload) is bytes and len(self.payload)<=1<<20,'HISTORICAL_STRING')
        if self.header[0]&1:
            capacity=int.from_bytes(self.header[:8],'little')&~1
            size=int.from_bytes(self.header[8:16],'little')
            pointer=int.from_bytes(self.header[16:24],'little')
            require(0<size<capacity<=1<<20 and uint(pointer) and pointer>0 and pointer+size+1<=1<<64 and len(self.payload)==size+1 and self.payload[-1:]==b'\0','HISTORICAL_LONG_STRING')
        else:
            size=self.header[0]>>1
            require(size<=22 and self.header[1+size:2+size]==b'\0' and self.payload==b'','HISTORICAL_SHORT_STRING')

    def value(self):
        return self.payload[:-1] if self.header[0]&1 else self.header[1:1+(self.header[0]>>1)]


@dataclass(frozen=True,repr=False)
class ProviderCacheSnapshot:
    lineage: ProviderLineage
    observed_sequence: int
    constructor_origin: str
    constructor_complete_sequence: int
    guard_u32: int
    mutex_depth_u32: int
    features: tuple
    value: HistoricalCacheString
    token: HistoricalCacheString
    timestamp_u64: int
    ttl_i64: int
    device_u64: int
    control_u64: int
    worker_guard_u32: int
    foreground_u32: int
    attempted: bool
    fetch_once: bool
    marker_u8: int
    secondary_state_u32: int
    duration_ms_i64: int
    refresh_duration_ms_i64: int
    postfetch_report_once: bool
    fetch_receiver_rva: int | None

    def __post_init__(self):
        require(type(self.lineage) is ProviderLineage,'CACHE_LINEAGE')
        require(type(self.constructor_origin) is str and self.constructor_origin in ('caller','callback','sdk','UNINITIALIZED','UNKNOWN') and uint(self.constructor_complete_sequence,53),'CACHE_CONSTRUCTOR_LINEAGE')
        require(uint(self.observed_sequence,53) and 0<self.observed_sequence<self.lineage.main_entry_sequence,'CACHE_BEFORE_CALL_ORIGIN')
        require(all(uint(value,32) for value in (self.guard_u32,self.mutex_depth_u32,self.worker_guard_u32,self.foreground_u32,self.secondary_state_u32)) and
            all(uint(value) for value in (self.timestamp_u64,self.device_u64,self.control_u64)) and uint(self.marker_u8,8),'CACHE_SCALARS')
        require(all(type(value) is int and -(1<<63)<=value<1<<63 for value in (self.ttl_i64,self.duration_ms_i64,self.refresh_duration_ms_i64)) and
            all(type(value) is bool for value in (self.attempted,self.fetch_once,self.postfetch_report_once)),'CACHE_STATE_TYPES')
        require(type(self.features) is tuple and len(self.features)<=128 and
            all(type(row) is tuple and len(row)==2 and type(row[0]) is int and -(1<<31)<=row[0]<1<<31 and uint(row[1],32) for row in self.features) and
            len({row[0] for row in self.features})==len(self.features) and {6,0x37}<=set(dict(self.features)),'FEATURES_EXPLICIT')
        require(type(self.value) is HistoricalCacheString and type(self.token) is HistoricalCacheString,'CACHE_STRINGS')
        require(self.fetch_receiver_rva is None or type(self.fetch_receiver_rva) is int and self.fetch_receiver_rva==0xBEDC00,'UNSUPPORTED_FETCH_RECEIVER')


@dataclass(frozen=True,repr=False)
class ProviderRawFiletime:
    lineage: ProviderLineage
    enter_sequence: int
    leave_sequence: int
    output: bytes
    defined_mask: bytes

    def __post_init__(self):
        require(type(self.lineage) is ProviderLineage and uint(self.enter_sequence,53) and uint(self.leave_sequence,53) and
            self.lineage.enter_sequence<self.enter_sequence<self.leave_sequence<self.lineage.leave_sequence,'FILETIME_SEQUENCE')
        require(type(self.output) is bytes and len(self.output)==8 and type(self.defined_mask) is bytes and self.defined_mask==b'\xff'*8,'FILETIME_RAW_OUTPUT')


@dataclass(frozen=True,repr=False)
class PrefixProviderInputs:
    lineage: ProviderLineage
    provider_state: ProviderState
    provider_pointer_u64: int
    md5_state: MD5State
    md5_callback: QualifiedMD5Callback | None
    cache: ProviderCacheSnapshot | None
    raw_filetimes: tuple
    _claimed: bool=field(default=False,init=False,compare=False)

    def __post_init__(self):
        require(type(self.lineage) is ProviderLineage and type(self.provider_state) is ProviderState and type(self.md5_state) is MD5State and uint(self.provider_pointer_u64),'INPUT_TYPES')
        self.lineage.__post_init__()
        require(self.cache is None or type(self.cache) is ProviderCacheSnapshot and self.cache.lineage==self.lineage,'CACHE_INPUT_LINEAGE')
        require(self.md5_callback is None or type(self.md5_callback) is QualifiedMD5Callback and self.md5_callback.identity==self.lineage.environment_identity,'MD5_INPUT_LINEAGE')
        require(type(self.raw_filetimes) is tuple and len(self.raw_filetimes)<=1 and all(type(row) is ProviderRawFiletime and row.lineage==self.lineage for row in self.raw_filetimes),'RAW_INPUT_SEQUENCE')


class _ProviderEnvironment:
    def __init__(self,binding):
        self.binding=binding

    def filetime(self):
        from .primary_material import ProviderMaterial
        from .primary_sign import PrimaryRuntime
        binding=self.binding
        binding.live()
        frame=sys._getframe(1)
        parent=frame.f_back
        require(binding.active and frame.f_code is ProviderMaterial._read.__code__ and frame.f_locals.get('self') is binding.material and frame.f_locals.get('caller')=='callback' and
            parent is not None and parent.f_code is PrimaryRuntime._return_provider_string.__code__ and parent.f_locals.get('self') is binding.runtime,'FILETIME_CALLER')
        require(binding.clock_index<len(binding.inputs.raw_filetimes),'FILETIME_EXHAUSTED')
        row=binding.inputs.raw_filetimes[binding.clock_index]
        binding.clock_index+=1
        return int.from_bytes(row.output,'little')

    def qpc(self):
        raise InputError('PREFIX_PROVIDER_UNSUPPORTED_COLD_QPC_DEVICE_SOURCE_SEQUENCE')


class _PrefixProviderBinding:
    def __init__(self,inputs,runtime,*,retired=None):
        from .primary_material import ProviderMaterial
        from .primary_sign import PrimaryRuntime
        from .primary_prefix_raw_clock import _MainPrefixRawClockBinding
        require(type(inputs) is PrefixProviderInputs and not inputs._claimed and type(runtime) is PrimaryRuntime and not runtime._active_failed and
            runtime._active_main is None and not runtime._program_calls and not runtime._execute_depth,'ATTACH_CONTEXT')
        inputs.__post_init__()
        source=inputs.lineage.environment_identity.source_identity
        require(source.generation==runtime._main_generation+1 and source.image_base==runtime.image_base,'SOURCE_GENERATION')
        clock=runtime._main_clock_binding
        require(type(clock) is _MainPrefixRawClockBinding and not clock.closed and len(clock._rows)==1,'RAW_CLOCK_BINDING')
        other=clock._rows[0]
        identity=inputs.lineage.environment_identity
        require(other.source_identity==source and (other.process_creation_identity,other.module_load_generation,other.native_thread_id,other.reader_invocation)==
            (identity.process_creation_identity,identity.module_load_generation,identity.native_thread_id,identity.reader_invocation) and
            inputs.lineage.enter_sequence>other.events[0].service.leave_seq,'CLOCK_LINEAGE_SEQUENCE')
        environment=runtime._main_environment_binding
        require(environment is not None and environment.runtime is runtime and environment.thread==get_ident(),'ENVIRONMENT_BINDING')
        prior=environment.identity
        require((prior.process_creation_identity,prior.module_load_generation,prior.native_thread_id)==
            (identity.process_creation_identity,identity.module_load_generation,identity.native_thread_id) and
            (retired is not None or prior==identity),'ENVIRONMENT_LINEAGE')
        raw=runtime._host129_api_binding
        require(raw is not None and raw.source is not None and raw.source.observed_counter_inputs is not None,'COUNTER_LINEAGE_REQUIRED')
        counter=raw.source.observed_counter_inputs
        require(counter.source_identity==source and counter.capture_identity==inputs.lineage.capture_identity and counter.main_frame_source==inputs.lineage.main_frame_source,'COUNTER_FRAME_LINEAGE')
        require(inputs.provider_state is not ProviderState.UNKNOWN and inputs.md5_state is not MD5State.UNKNOWN,'UNKNOWN_SLOT_UNSUPPORTED')
        require(inputs.provider_pointer_u64==(0 if inputs.provider_state is ProviderState.NULL else runtime.image_base+0x1BFD960),'PROVIDER_POINTER_IDENTITY')
        md5=inputs.md5_callback
        require(md5 is None if inputs.md5_state is MD5State.DISABLED else md5 is not None and md5.source_module_base_u64==runtime.image_base,'MD5_EXPLICIT_STATE')
        require(runtime.memory.load(runtime.image_base+0x6D85FE8,8)==(0 if md5 is None else runtime.image_base+0x1BFD3D0),'MD5_EFFECTIVE_SLOT')
        self.runtime,self.inputs,self.thread=runtime,inputs,get_ident()
        self.clock,self.raw=clock,raw
        self.active=self.closed=self.finished=False
        self.calls=self.clock_index=0
        self.material=None
        self.environment=_ProviderEnvironment(self)
        if inputs.provider_state is ProviderState.NULL:
            require(inputs.cache is None and inputs.raw_filetimes==(),'NULL_HAS_NO_PROVIDER_INPUTS')
        else:
            cache=inputs.cache
            require(cache is not None,'CACHE_STATE_REQUIRED')
            require(cache.guard_u32&1==1 and cache.constructor_origin in ('caller','callback','sdk') and 0<cache.constructor_complete_sequence<cache.observed_sequence,'UNSUPPORTED_CACHE_CONSTRUCTOR_REQUIRES_RAW_INITIALIZATION')
            require(cache.mutex_depth_u32==0,'MUTEX_NOT_ACQUIRABLE')
            require(dict(cache.features)[6]==1,'UNSUPPORTED_SWITCH_BRANCH')
            require(len(inputs.raw_filetimes)==1 and cache.value.value()!=b'','UNSUPPORTED_COLD_OWN_PRODUCER_RAW_DEVICE_SOURCE_REQUIRED')
            from .primary_sign import filetime_seconds
            from .primary_vm import signed
            now=filetime_seconds(int.from_bytes(inputs.raw_filetimes[0].output,'little'))
            require(cache.timestamp_u64==0 or signed((now-cache.timestamp_u64)&((1<<64)-1),64)<=cache.ttl_i64,'UNSUPPORTED_CACHE_MISS_RAW_DEVICE_SOURCE_REQUIRED')
            self.material=ProviderMaterial(value=cache.value.value(),token=cache.token.value(),timestamp=cache.timestamp_u64,
                attempted=cache.attempted,fetch_once=cache.fetch_once,marker=cache.marker_u8,secondary_state=cache.secondary_state_u32,
                duration_ms=cache.duration_ms_i64,features=dict(cache.features),refresh_duration_ms=cache.refresh_duration_ms_i64,postfetch_report_once=cache.postfetch_report_once)
        self.material_state=None if self.material is None else {key:(dict(value) if type(value) is dict else value) for key,value in vars(self.material).items()}
        if retired is not None:
            require(type(retired) is _PrefixProviderBinding and retired.closed and retired.finished and retired.runtime is runtime and runtime.__dict__.get('_prefix_provider_binding') is retired,'REBIND_OWNER')
            require(retired.inputs.provider_state is inputs.provider_state and retired.inputs.md5_state is inputs.md5_state,'UNSUPPORTED_REBIND_SLOT_TRANSITION')
            if self.material is not None:
                require(runtime.provider_material is retired.material and vars(self.material)==vars(retired.material),'CACHE_REBIND_CONTINUITY')
                self.material=retired.material
            self.verify_memory(previous=retired)
        else:
            require(runtime.__dict__.get('_prefix_provider_binding') is None and runtime._main_generation==0,'ALREADY_ATTACHED')
            self.install_memory()
        object.__setattr__(inputs,'_claimed',True)
        runtime._prefix_provider_binding=self
        if self.material is not None:
            runtime.provider_material=self.material
            runtime.provider_environment=self.environment

    def memory_rows(self):
        base=self.runtime.image_base
        md5=0 if self.inputs.md5_state is MD5State.DISABLED else base+0x1BFD3D0
        rows=[(base+0x6D85FF8,self.inputs.provider_pointer_u64.to_bytes(8,'little')),(base+0x6D85FE8,md5.to_bytes(8,'little'))]
        cache=self.inputs.cache
        if cache is not None:
            for offset,value,size in ((0x67519B0,cache.guard_u32,4),(0x6751908,cache.ttl_i64&((1<<64)-1),8),
                (0x6751840,cache.device_u64,8),(0x6751848,cache.control_u64,8),(0x67516D0,cache.foreground_u32,4),
                (0x67518E0,int(cache.attempted),1),(0x6751968,int(cache.fetch_once),1),(0x675198A,cache.marker_u8,1),
                (0x67518E8,cache.timestamp_u64,8),(0x6751950,cache.duration_ms_i64&((1<<64)-1),8)):
                rows.append((base+offset,value.to_bytes(size,'little')))
            for offset,string in ((0x67518B0,cache.value),(0x67518C8,cache.token)):
                rows.append((base+offset,string.header))
                if string.header[0]&1:
                    rows.append((int.from_bytes(string.header[16:24],'little'),string.payload))
        return rows

    def install_memory(self):
        memory=self.runtime.memory
        rows=self.memory_rows()
        payloads=[(int.from_bytes(string.header[16:24],'little'),string.payload) for string in (self.inputs.cache.value,self.inputs.cache.token) if string.header[0]&1] if self.inputs.cache is not None else []
        new_rows=[]
        original_regions={id(region) for region in memory._region_snapshot()}
        for index,(address,data) in enumerate(rows):
            require(type(address) is int and 0<=address<(1<<64) and type(data) is bytes and 0<len(data)<=(1<<64)-address,'SNAPSHOT_SPAN')
            require(all(not (address<other+len(raw) and other<address+len(data)) for other,raw in rows[index+1:]),'SNAPSHOT_ALIAS')
            overlaps=[region for region in memory._region_snapshot() if address<region.address+len(region.data) and region.address<address+len(data)]
            if (address,data) in payloads:
                require(not overlaps,'HISTORICAL_BUFFER_OVERLAP')
            if overlaps:
                region,_=memory._span(address,len(data))
                require(not region.data.readonly,'SNAPSHOT_READONLY')
            else:
                new_rows.append((address,data))
        self._memory_commit_started=True
        try:
            for address,data in new_rows:
                memory.map(address,bytearray(len(data)),name='typed pre-call provider snapshot',initialized=False)
            for address,data in rows:
                memory.write(address,data,source='prefix_provider.before_call_state')
            if self.inputs.cache is not None:
                self.runtime.locks[self.runtime.image_base+0x67518F0]=self.inputs.cache.mutex_depth_u32
        except BaseException as error:
            self.runtime._active_failed=True
            for address,_ in reversed(new_rows):
                if any(region.address==address and id(region) not in original_regions for region in memory._region_snapshot()):
                    try:
                        memory.unmap(address)
                    except BaseException:
                        error.add_note('PREFIX_PROVIDER_NEW_MAPPING_CLEANUP_FAILED')
            raise

    def verify_memory(self,*,previous=None):
        if self.material is not None:
            environment=self.environment if previous is None else previous.environment
            require(self.runtime.provider_material is self.material and self.runtime.provider_environment is environment and vars(self.material)==self.material_state,'MATERIAL_OWNER_STATE')
        require(all(self.runtime.memory.read(address,len(data))==data for address,data in self.memory_rows()),'STATE_CONTINUITY')
        if self.inputs.cache is not None:
            require(self.runtime.locks.get(self.runtime.image_base+0x67518F0,0)==self.inputs.cache.mutex_depth_u32,'MUTEX_CONTINUITY')

    def preflight(self,arguments):
        require(not self.closed and not self.finished and self.thread==get_ident() and self.runtime.__dict__.get('_prefix_provider_binding') is self and
            self.inputs.lineage.environment_identity.source_identity.main_arguments==arguments and self.inputs.lineage.environment_identity.source_identity.generation==self.runtime._main_generation+1,'PREFLIGHT_OWNER')
        self.verify_memory()

    def live(self):
        from .primary_main_prefix_stop import _input_owner
        owner=_input_owner(self.runtime)
        require(not self.closed and not self.finished and self.thread==get_ident() and self.runtime.__dict__.get('_prefix_provider_binding') is self and
            owner is not None and owner.provider is self and self.runtime._main_clock_binding is self.clock and self.runtime._host129_api_binding is self.raw,'ACTIVE_OWNER')
        return owner

    @contextmanager
    def scope(self,vm,cells,argument_types):
        owner=self.live()
        source=self.inputs.lineage.environment_identity.source_identity
        require(not self.active and self.calls==0 and owner.vm is vm and vm.runtime is self.runtime and vm.pc==1267 and vm.block==18 and
            sha256(vm.program.raw).hexdigest()==self.inputs.lineage.main_frame_source.program_sha256 and
            cells==(299,) and argument_types==vm.program.type(127).parameters[3:] and vm.host_calls[-1]==(1260,self.runtime.image_base+0x2DE5687,(299,),127) and
            self.runtime._main_generation==source.generation and self.runtime._program_calls[0]['arguments']==source.main_arguments,'CALLSITE')
        self.verify_memory()
        self.active=True
        try:
            yield
            require(self.clock_index==len(self.inputs.raw_filetimes),'RAW_SEQUENCE_INCOMPLETE')
            if self.material is not None:
                require(self.runtime.provider_material is self.material and self.runtime.provider_environment is self.environment,'CALLBACK_OWNER')
            self.verify_memory()
            self.calls+=1
        finally:
            self.active=False

    def complete_prefix9563(self,vm,witness):
        self.live()
        require(self.calls==1 and not self.active and self.clock_index==len(self.inputs.raw_filetimes),'FINALIZATION')
        self.verify_memory()
        self.finished=True

    def close(self):
        require(self.thread==get_ident() and not self.active,'CLOSE_OWNER')
        self.closed=True


def bind_prefix_provider_inputs(runtime,inputs,*,retired=None):
    binding=_PrefixProviderBinding.__new__(_PrefixProviderBinding)
    try:
        binding.__init__(inputs,runtime,retired=retired)
        return binding
    except BaseException:
        if getattr(binding,'_memory_commit_started',False) or runtime.__dict__.get('_main_prefix9563_retired') is not None:
            runtime._active_failed=True
        raise


def provider_scope(runtime,vm,cells,argument_types):
    binding=runtime.__dict__.get('_prefix_provider_binding')
    return nullcontext() if binding is None else binding.scope(vm,cells,argument_types)
