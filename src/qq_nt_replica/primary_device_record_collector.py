"""Independent collector data storage; unknown bytes remain unknown."""
from .errors import InputError
from .primary_memory import PrimaryMemory
from .primary_logger import _String
from .primary_device_collector import construct_collector,copy_snapshot,_STRING_OFFSETS
from .primary_device_records import device_record_values
from .primary_windows_wmi_session import WmiQueryResult

class _DataMemory(PrimaryMemory):
    def __init__(self,owner):super().__init__();self.owner=owner
    def unmap(self,address):
        super().unmap(address);self.owner.buffers.discard(address);self.owner.allocations.pop(address,None)

class _StringStorage:
    """Only owning String buffers, not an SDK runtime or execution identity."""
    def __init__(self):self.buffers=set();self.allocations={};self.memory=_DataMemory(self);self.next=0x100000000;self.image_base=0x180000000;self.events=[]
    def allocate(self,size):
        pointer=self.next;self.next+=max(0x1000,(size+4095)&~4095)
        self.memory.map(pointer,bytearray(size),name='own collector data',initialized=False);self.buffers.add(pointer);self.allocations[pointer]=size;return pointer
    def _operator_new(self,size):return self.allocate(size)
    def _free_allocation(self,pointer):
        if pointer not in self.buffers:raise InputError('String free requires own data allocation')
        self.memory.unmap(pointer);self.buffers.discard(pointer)
    def invoke(self,vm,rva,cells):
        if len(cells)!=1:raise InputError('collector String allocator requires one argument')
        value=vm.cells.value(cells[0])
        if rva==0xB75000:return self.allocate(value)
        if rva==0xB75029:self._free_allocation(value);return None
        raise InputError('collector data storage does not execute source functions')
    def close(self):
        for pointer in tuple(self.buffers):self._free_allocation(pointer)

class DeviceCollectionState:
    def __init__(self):
        self.storage=_StringStorage();self.address=self.storage.allocate(0x42B0)
        construct_collector(self.storage,self.address)
    @property
    def warm(self):return bool(self.storage.memory.load(self.address+0x42A8,1))
    def read(self,offset,size):return self.storage.memory.read(self.address+offset,size)
    def write(self,offset,data):self.storage.memory.write(self.address+offset,data,source='own actual collector output')
    def string(self,offset):return _String.read(self.storage,self.address+offset).value()
    def set_string(self,offset,value):
        if offset-8 not in _STRING_OFFSETS:raise InputError('collector String offset outside source schema')
        if type(value)is not bytes:raise InputError('collector String requires owning bytes')
        old=_String.read(self.storage,self.address+offset);replacement=_String.construct(self.storage,value)
        old.destroy();replacement.write_to(self.address+offset)
    def snapshot(self):
        before=set(self.storage.buffers)
        target=self.storage.allocate(0x42A0)
        try:
            for offset in _STRING_OFFSETS:self.storage.memory.store(target+offset,0,1,source='own snapshot initial short tag')
            copy_snapshot(self.storage,target,self.address+8)
            return DeviceRecordSnapshot(self.storage,target)
        except BaseException:
            for pointer in tuple(self.storage.buffers-before):self.storage._free_allocation(pointer)
            raise
    def close(self):
        if self.address is None:return
        from .primary_device_collector import destroy_snapshot
        destroy_snapshot(self.storage,self.address+8);self.storage._free_allocation(self.address);self.address=None

class DeviceRecordSnapshot:
    def __init__(self,storage,address):self.storage=storage;self.address=address
    def records(self,*,version,device_value,sdk_fields,ansi_to_utf8):
        return device_record_values(self.storage,self.address,version=version,device_value=device_value,sdk_fields=sdk_fields,ansi_to_utf8=ansi_to_utf8)
    def close(self):
        from .primary_device_collector import destroy_snapshot
        if self.address is None:return
        destroy_snapshot(self.storage,self.address);self.storage._free_allocation(self.address);self.address=None


def collect_wmi_fields(state,session):
    """Apply the eight source queries to owned state, never promoting warm here.

    session is the OwnedWmiSession port contract; its owning DTOs are defined by
    that port, not redefined as raw COM pointers or runtime qualifications here.
    """
    from .primary_device_wmi import _COLLECTORS
    for spec_id in _COLLECTORS:
        apply_wmi_result(state,spec_id,session.query_first(spec_id))


def apply_wmi_result(state,spec_id,result):
    from .primary_device_wmi import _image
    from .primary_vm import PrimarySemanticUnavailable
    spec=_image()['collectors'][str(spec_id)]
    if not isinstance(result,WmiQueryResult):raise InputError('owning WMI query DTO required')
    if result.state in ('no_services','exec_failed','no_object'):
        if result.properties:raise InputError('empty WMI result cannot contain property values')
        return
    if result.state!='row' or result.returned_count!=1:raise PrimarySemanticUnavailable('WMI row state/count outside owning port contract')
    expected=tuple(bytes.fromhex(value) for value in spec['properties_hex'])
    if tuple(prop.property_id for prop in result.properties)!=expected:raise InputError('WMI property source order changed')
    values={}
    for prop in result.properties:
        if type(prop.key_ansi)is not bytes or b'\0'in prop.key_ansi:raise InputError('WMI key requires owning ANSI CString')
        if prop.state not in ('get_failed','value','empty','unsupported_type','invalid_bstr'):raise PrimarySemanticUnavailable('WMI property outcome unavailable')
        value=prop.value_ansi
        if type(value)is not bytes or b'\0'in value:raise InputError('WMI value requires owning ANSI CString')
        if prop.state!='value' and value:raise InputError('failed/empty WMI property cannot fabricate bytes')
        values[prop.key_ansi]=value
    for write in spec['writes']:
        value=values.get(bytes.fromhex(write['key_hex']),b'')
        if value:state.set_string(write['offset'],value)


class CollectionOperations:
    """Finite collection calculations on own data and explicit OS/store ports.

    No interpreter, SDK runtime, TLS, source receiver or native IAT qualification.
    """
    def __init__(self,state,port,stores,*,sdk_fields,wmi_factory):
        from .primary_device_records import sdk_field_record_values
        from .primary_logger import _image as logger_image
        sdk_field_record_values(sdk_fields)
        self.state=state;self.data=state.storage;self.port=port;self.stores=stores;self.sdk_fields=dict(sdk_fields);self.wmi_factory=wmi_factory;self.wmi=None;self.last_wmi=None
        self.logger=[];self._feature22=next(x['default'] for x in logger_image()['definitions'] if x['id']==22)
        self.data.worker_observations=port;self.import_handles=[];self.adapter_target=None;self.cleanups=[]
        self._install_constants()
    def require_data(self,data):
        if data is not self.data or type(data)is not _StringStorage:raise InputError('collection operations require their own data storage')
    def _install_constants(self):
        from . import primary_device_cold,primary_device_system,primary_device_system_records,primary_device_process_records,primary_device_hardware,primary_device_adapters,primary_device_adapter_details,primary_device_refresh
        modules=(primary_device_cold,primary_device_system,primary_device_system_records,primary_device_process_records,primary_device_hardware,primary_device_adapters,primary_device_adapter_details,primary_device_refresh)
        values={}
        for module in modules:
            image=module._image()
            for segment in image['segments']:
                rva=segment['rva'];rva=int(rva,16) if type(rva)is str else rva
                raw=bytes.fromhex(segment['hex']);relocated=bytearray(raw)
                for offset in segment.get('relocations',()):relocated[offset:offset+8]=(int.from_bytes(raw[offset:offset+8],'little')-image['image_base']+self.data.image_base).to_bytes(8,'little')
                for i,byte in enumerate(relocated):
                    address=self.data.image_base+rva+i
                    if address in values and values[address]!=byte:raise InputError('collection constant images overlap different bytes')
                    values[address]=byte
        from .primary_signer import _asset
        # Source PE zero-filled data of this NEW independent image, never a warm reset.
        for segment in _asset('runtime-image.json')['segments']:
            rva=int(segment['rva'],16)
            if rva not in (0x6749CC0,0x6D8E630):continue
            for i,byte in enumerate(bytes.fromhex(segment['hex'])):
                address=self.data.image_base+rva+i
                if address in values and values[address]!=byte:raise InputError('fixed formatting data overlap mismatch')
                values[address]=byte
        addresses=sorted(values);i=0
        while i<len(addresses):
            start=addresses[i];end=i+1
            while end<len(addresses) and addresses[end]==addresses[end-1]+1:end+=1
            self.data.memory.map(start,bytearray(values[a] for a in addresses[i:end]),name='fixed collection constants',initialized=True);i=end
        # Own fresh cache guard; enumerate_primary itself constructs its tree.
        if self.data.memory.load(self.data.image_base+0x677BF80,4)!=0:raise InputError('fixed adapter cold cache asset is not fresh')
    def frame(self,size,name):
        pointer=self.data.allocate(size);return pointer,pointer+0x80
    def array(self,size):
        from .primary_vm import PrimaryProgramLimit
        if not 0<=size<=1<<20:raise PrimaryProgramLimit('device conversion array exceeds the bounded offline domain')
        pointer=self.data.allocate(max(size,1))
        if not hasattr(self.data,"_device_arrays"):self.data._device_arrays={}
        self.data._device_arrays[pointer]=max(size,1)
        return pointer
    def observe(self,name,args):return self.port.take(self.data,name,args)
    def plain(self,name,args):
        value,effects=self.observe(name,args)
        if effects not in (None,b''):raise InputError('plain collection API returned unexpected effects: '+name)
        return value
    def dynamic(self,target,name,args):return self.observe(name,((target[name] if type(target)is dict else target),*args))
    def source_log(self,*args):self.logger.append(args)
    def adapter_failure(self,error):self.logger.append(('adapter-detail-failure',error))
    @property
    def feature22(self):return self._feature22
    def feature(self,logger,identifier):
        if identifier!=22:raise InputError('independent collection only consumes source feature22')
        return self.feature22
    def ascii_upper(self,value):
        if not 0<=value<128:raise InputError('adapter hexadecimal byte outside ASCII domain')
        return value-32 if 97<=value<=122 else value
    def format(self,template,values):
        from .primary_logger import _format
        return _format(self.data,template,values)
    def copy_machine_id(self,destination):_String.construct(self.data,self.sdk_fields[0x48]).write_to(destination)
    def open_wmi(self):
        if self.wmi is not None:raise InputError('WMI session already open')
        self.wmi=self.wmi_factory();self.last_wmi=self.wmi
    def close_wmi(self):
        if self.wmi is not None:
            session=self.wmi;self.wmi=None
            session.close()
    def adapter_query(self,buffer,size_pointer):
        from .primary_device_hardware import apply_adapter_buffer
        if self.adapter_target is None:
            module=self.plain('LoadLibraryA',(b'iphlpapi.dll',))
            if not module:raise InputError('independent adapter import module unavailable')
            self.import_handles.append(module);self.adapter_target=self.plain('GetProcAddress',(module,b'GetAdaptersInfo'))
            if not self.adapter_target:raise InputError('independent adapter import unavailable')
        capacity=self.data.memory.load(size_pointer,4)
        result,(effect,updated)=self.observe('GetAdaptersInfo',(self.adapter_target,bool(buffer),capacity))
        apply_adapter_buffer(self.data,buffer,min(capacity,self.data.allocations.get(buffer,0)),effect,source='own adapter detail output')
        if updated is not None:self.data.memory.store(size_pointer,updated,4,source='own adapter size output')
        return result&0xFFFFFFFF
    def identifiers(self,owner):
        from .primary_device_provenance import collect_owned_identifiers
        from .primary_device_collector import generate_material_bytes
        if owner!=self.state.address:raise InputError('identifier owner is not this collector')
        collect_owned_identifiers(self.state,self.stores,generate=lambda raw:generate_material_bytes(raw,filetime=self.port.filetime(),random_device_word=self.port.random_device_word(),ansi_to_utf8=self.port.ansi_to_utf8))
    def invoke(self,rva,*values):
        # Only concrete source collection helpers, not an arbitrary native dispatcher.
        from . import primary_device_system as system,primary_device_hardware as hardware,primary_device_cold as cold,primary_device_system_records as records,primary_device_process_records as process,primary_device_adapters as adapters,primary_device_adapter_details as detail
        from .primary_device_collector import assign_string,copy_snapshot
        from .primary_device_wmi import _COLLECTORS
        if rva in (0x1BE9020,0x1BE9A70):
            from .primary_vm import PrimarySemanticUnavailable
            raise PrimarySemanticUnavailable('independent collection adapter fallback algorithm unavailable: '+hex(rva))
        if rva in _COLLECTORS:
            if self.wmi is None:raise InputError('WMI query outside owning session')
            self._apply_query(rva,self.wmi.query_first(rva));return None
        if rva in (0xB75000,0x3E97020):return self.data.allocate(max(values[0],1))
        if rva==0x3E92E00:
            size=values[0]*values[1];pointer=self.data.allocate(max(size,1));self.data.memory.write(pointer,bytes(size),source='own source calloc output');return pointer
        if rva in (0xB75029,0x3E94F90):self.data._free_allocation(values[0]);return None
        if rva==0x75CEC0:return assign_string(self.data,*values)
        if rva==0x75BEB0:
            destination,pointer,length=values;_String.construct(self.data,self.data.memory.read(pointer,length)).write_to(destination);return destination
        if rva==0x75E7B0:
            destination,value=values;value=((value+(1<<31))&0xFFFFFFFF)-(1<<31);_String.construct(self.data,str(value).encode()).write_to(destination);return destination
        if rva==0x1D05BC0:
            from .primary_device_identifiers import identifier_digest_bytes
            source,destination,count=values;self.data.memory.write(destination,identifier_digest_bytes(_String.read(self.data,source).value(),count),source='shared identifier digest');return None
        if rva==0x2E11240:
            destination,pointer,count=values;_String.construct(self.data,self.data.memory.read(pointer,count).hex().upper().encode()).write_to(destination);return destination
        if rva==0x3E680B4:
            if values!=(self.data.image_base+0x1BEA4E0,):raise InputError('collection cleanup registration outside finite domain')
            self.cleanups.append(0x1BEA4E0);return 0
        if rva==0x3E8ED3C:
            from .primary_sign import filetime_seconds
            result=filetime_seconds(self.port.filetime())
            if values[0]:self.data.memory.store(values[0],result,8,source='own source wall seconds')
            return result
        if rva==0x2E252A0:
            from .primary_device_refresh import refresh
            return refresh(self.data,*values,_operations=self)
        if rva==0x2E25B70:return copy_snapshot(self.data,*values)
        groups=((system,(0x1BED930,0x1BEDC50,0x1BEDD40)),(hardware,(0x1BED570,0x1BED2F0,0x35D5C30,0x2E11020,0x37AAE6)),(cold,(0x1BEE390,0x2E15CA0,0x2E24080)),(records,(0x35E9640,0x3C715D0,0x3C716B0,0x3C71590,0x3C712C0,0x35EC010,0x35EC180,0x35EC530)),(process,(0x35ECC50,0x3C71430,0x35ED8F0,0x35EDA10,0x35EDD40,0x35EE0A0,0x35EDBB0,0x35EE6C0,0x35EDC70,0x35EEAA0,0x35EF450)),(adapters,(0x1BE87B0,0x1BE87D0,0x1BE88A0,0x1BE8960,0x1BEA500,0x1BEA5C0,0x1BEACF0,0x1BEABF0,0x1BEBD30,0x1BED080,0x1BED780,0x35D5A80,0x1BEA4E0)))
        if rva==0x2E24240:return detail.capture(self.data,*values,_operations=self)
        for module,allowed in groups:
            if rva in allowed:return module.invoke(self.data,rva,values,_operations=self)
        raise InputError('helper outside finite collection operations: '+hex(rva))
    def _apply_query(self,spec_id,result):
        # Reuse the same source-order projection without replaying other queries.
        apply_wmi_result(self.state,spec_id,result)
    def close(self):
        failures=[]
        try:self.close_wmi()
        except BaseException as error:failures.append(error)
        while self.cleanups:
            cleanup=self.cleanups.pop()
            try:self.invoke(cleanup)
            except BaseException as error:failures.append(error)
        while self.import_handles:
            handle=self.import_handles.pop()
            try:self.plain('FreeLibrary',(handle,))
            except BaseException as error:failures.append(error)
        if failures:raise BaseExceptionGroup('collection operation cleanup failed',failures)


class IndependentDeviceRecordCollector:
    """One owned cold collector; each collect performs the source refresh."""
    def __init__(self,port,stores,*,sdk_fields,wmi_factory):
        self.state=DeviceCollectionState()
        try:self.operations=CollectionOperations(self.state,port,stores,sdk_fields=sdk_fields,wmi_factory=wmi_factory)
        except BaseException:self.state.storage.close();raise
        self.closed=False
    def _capture_snapshot(self):
        if self.closed:raise InputError('collector is closed')
        from .primary_device_cold import capture_snapshot
        target=self.state.storage.allocate(0x42A0)
        for offset in _STRING_OFFSETS:self.state.storage.memory.store(target+offset,0,1,source='own snapshot String birth')
        try:
            capture_snapshot(self.state.storage,self.state.address,target,_operations=self.operations)
            return DeviceRecordSnapshot(self.state.storage,target)
        except BaseException as original:
            cleanup=[]
            try:self.operations.close_wmi()
            except BaseException as error:cleanup.append(error)
            from .primary_device_collector import destroy_snapshot
            try:
                destroy_snapshot(self.state.storage,target)
                self.state.storage._free_allocation(target)
            except BaseException as error:cleanup.append(error)
            if cleanup:raise BaseExceptionGroup('collection and owned cleanup failed',[original,*cleanup])
            raise
    def collect(self,*,version,device_value,ansi_to_utf8):
        """Return all137 owning typed records, or propagate the first Boundary."""
        from .primary_worker_consumer import DeviceRecord
        if type(version)is not bytes or type(device_value)is not bytes or not callable(ansi_to_utf8):raise InputError('complete records require explicit version/device bytes and ANSI conversion')
        snapshot=self._capture_snapshot()
        try:values=snapshot.records(version=version,device_value=device_value,sdk_fields=self.operations.sdk_fields,ansi_to_utf8=ansi_to_utf8)
        except BaseException as original:
            try:snapshot.close()
            except BaseException as cleanup:raise BaseExceptionGroup('record projection and snapshot cleanup failed',[original,cleanup])
            raise
        else:snapshot.close()
        return tuple(DeviceRecord(key,value) for key,value in values)
    def create_request(self,*,version,device_value,ansi_to_utf8,metadata,**request_inputs):
        from .primary_sdk_request import create_record_request
        records=self.collect(version=version,device_value=device_value,ansi_to_utf8=ansi_to_utf8)
        return create_record_request(records,metadata,**request_inputs)
    def close(self):
        if self.closed:return
        failures=[]
        for cleanup in (self.operations.close,self.state.close,self.state.storage.close):
            try:cleanup()
            except BaseException as error:failures.append(error)
        self.closed=True
        if failures:raise BaseExceptionGroup('collector cleanup failed',failures)
