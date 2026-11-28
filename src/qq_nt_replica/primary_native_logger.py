"""Finite Login D3 gate/ownership; unsupported typed formatting stays explicit."""
from .primary_vm import PrimarySemanticUnavailable
from .primary_login_model_attach import validate_birth
from .primary_logger import _String
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
from .errors import InputError


def enabled(runtime, level):
    from .primary_shared_locale import resolve_current_module_tls
    validate_birth(runtime);receipt=resolve_current_module_tls(runtime)
    memory=runtime.memory;base=runtime.image_base;guard=base+0x67535d8
    if memory.load(guard,4,signed=True)>memory.load(receipt.epoch_address,4,signed=True):
        runtime._locale_thread_header(guard)
        if memory.load(guard,4,signed=True)==-1:
            memory.write(base+0x6753530,bytes(0xa8),source='D3AF48.singleton_zero')
            memory.store(base+0x67535d0,2,4,source='D3AF48.threshold')
            runtime._locale_thread_footer(guard)
    return memory.load(base+0x67535d0,4,signed=True)<=level


def _set(value,address,offset,number,width,source):
    value.set(offset,number.to_bytes(width,'little'))
    value.runtime.memory.store(address+offset,number,width,source=source)


def _append(value,address,data,*,literal):
    r=value.runtime;m=r.memory;old=value.value();size=len(old);required=size+len(data)
    heap=bool(value.get(0,1)&1)
    capacity=(value.get(0,8)&~1)-1 if heap else 22
    if not literal and not data and required<=capacity:return
    if required>=1<<63:raise PrimarySemanticUnavailable('source append overflow branch unavailable')
    if required>capacity:
        maximum=max(2*capacity,required)
        physical=(maximum|15)+1 if maximum>=23 else 23
        pointer=_invoke(r,0xB75000,physical)
        if old:m.write(pointer,old,source='75BAB0.old_prefix' if literal else '75C180.old_prefix')
        if not literal:m.write(pointer+size,data,source='75C180.new_payload')
        if capacity!=22:_invoke(r,0xB75029,value.get(16,8))
        _set(value,address,16,pointer,8,'75BAB0.buffer' if literal else '75C180.buffer')
        _set(value,address,0,physical|1,8,'75BAB0.capacity' if literal else '75C180.capacity')
        heap=True
    else:pointer=value.get(16,8) if heap else address+1
    if literal or required<=capacity:
        m.write(pointer+size,data,source='508834.literal' if literal else '75C180.new_payload')
    if literal:m.store(pointer+required,0,1,source='508834.NUL')
    if heap:_set(value,address,8,required,8,'508834.length' if literal else '75C180.length')
    else:
        _set(value,address,0,required*2,1,'508834.short_length' if literal else '75C180.short_length')
        # Keep host String metadata synchronized with its actual modeled backing.
        value.set(1,m.read(address+1,required)+(b'\0' if literal else b''))
    if not literal:m.store(pointer+required,0,1,source='75C180.NUL')
    if not heap:value.set(1,m.read(address+1,required+1))


def _decimal(runtime,number,buffer,span):
    # D3C279's pair table is fixed source00..99; writes model the actual backward span.
    signed=number&0xffffffff
    if signed&0x80000000:signed-=1<<32
    magnitude=-signed if signed<0 else signed
    end=buffer+33;cursor=end-1
    table=b''.join(bytes((48+i//10,48+i%10)) for i in range(100))
    while magnitude>=100:
        magnitude,remainder=divmod(magnitude,100)
        runtime.memory.store(cursor-1,table[2*remainder],1,source='B1D6C6.first')
        runtime.memory.store(cursor,table[2*remainder+1],1,source='B1D6C6.second')
        cursor-=2
    if magnitude<=9:runtime.memory.store(cursor,48|magnitude,1,source='D3C279.single_digit')
    else:
        cursor-=1
        runtime.memory.store(cursor,table[2*magnitude],1,source='B1D6C6.first')
        runtime.memory.store(cursor+1,table[2*magnitude+1],1,source='B1D6C6.second')
    runtime.memory.store(span,cursor,8,source='D3C279.span_begin')
    runtime.memory.store(span+8,end,8,source='D3C279.span_end')
    if signed<0:
        cursor-=1;runtime.memory.store(cursor,45,1,source='D3C669.minus')
    return runtime.memory.read(cursor,end-cursor)


def _format_fixed(runtime,template,arguments):
    if template not in (b'InitConfig, commonPath: {}, clientVer: {}, machineId: {}, platVer: {}',b'[{}] {}({})::{} {}'):
        raise PrimarySemanticUnavailable('D3BE4F other format/spec branch unavailable')
    count=len(arguments)
    size=40*count+24*count+sum(len(value)+1 for kind,value in arguments if kind=='cstring')+128
    frame,unused=_frame(runtime,size,'D3 fixed typed slots and owned temporaries')
    memory=runtime.memory;locals_base=frame+40*count;cursor=locals_base+24*count
    for index,(kind,value) in enumerate(arguments):
        slot=frame+40*index
        memory.store(slot+24,0,4,source='typed.outer_tag')
        if kind=='integer':
            memory.store(slot+8,value&0xffffffff,4,source='2810.signed_DWORD')
            memory.store(slot+32,4,4,source='2810.inner_tag')
        else:
            if kind=='String':
                source=locals_base+24*index;value.write_to(source)
                pointer=value.get(16,8) if value.get(0,1)&1 else source+1
            elif kind=='cstring':
                pointer=cursor;memory.write(pointer,value+b'\0',source='MODEL fixed-literal borrow')
                cursor+=len(value)+1
            else:raise InputError('unsupported fixed formatter argument tag')
            memory.store(slot+8,pointer,8,source='3028.borrowed_CString')
            memory.store(slot+32,11,4,source='3028.inner_tag')
    temporary=_String.construct(runtime,template)
    output=_String.construct(runtime,b'')
    output_address=frame+size-64;output.write_to(output_address)
    decimal_buffer=frame+size-40
    parts=template.split(b'{}')
    if len(parts)!=count+1:raise InputError('fixed formatter argument count mismatch')
    for index,part in enumerate(parts):
        if part:_append(output,output_address,part,literal=True)
        if index==count:break
        slot=frame+40*index;tag=memory.load(slot+32,4)
        if tag==4:data=_decimal(runtime,memory.load(slot+8,4),decimal_buffer,output_address-16)
        else:
            pointer=memory.load(slot+8,8);data=bytearray()
            while memory.load(pointer+len(data),1):data.append(memory.load(pointer+len(data),1))
            data=bytes(data)
        _append(output,output_address,data,literal=False)
    temporary.destroy()
    for index in reversed(range(count)):
        memory.store(frame+40*index+24,0xffffffff,4,source='2896.tag_after_RET')
    memory.unmap(frame)
    return output



_NT_FORMAT=b'init misc mmkv, id={}, path={} crypt_key={}'
_NT_MISSING=b'get misc mmkv failed,  id={} key:{}'
_NT_FILE=bytes.fromhex('2e2e5c777261707065725c7379735f656e765c656e67696e655c7372635c6e745f777261707065725f656e67696e652e636300')


def nt_file_basename(runtime):
    # Both fixed source search implementations return the last matching byte before NUL.
    last=None
    for index,byte in enumerate(_NT_FILE):
        if not byte:break
        if byte==0x5c:last=index
    result=runtime.image_base+0x486b891+last if last is not None else 0
    runtime.events.append(('source.3E6D680',runtime.image_base+0x486b891,0x5c,result))
    return _NT_FILE[(last+1) if last is not None else 0:-1]


def _nt_format_records(runtime,view,array,count,output_address):
    # A fixed source-literal view and actual40B variants are the formatter inputs.
    memory=runtime.memory
    pointer=memory.load(view,8);length=memory.load(view+8,8)
    choices={(runtime.image_base+0x45d2964,43,3):_NT_FORMAT,(runtime.image_base+0x4604ab6,35,2):_NT_MISSING,
             (runtime.image_base+0x46629B0,15,1):b'SetSessionId:{}',
             (runtime.image_base+0x45D1E46,8,2):b'[{}]->{}'}
    template=choices.get((pointer,length,count))
    if template is None:raise InputError('NT formatter requires exact fixed literal view/count')
    output=_String.construct(runtime,b'');output.write_to(output_address)
    parts=template.split(b'{}')
    for index,part in enumerate(parts):
        if part:_append(output,output_address,part,literal=True)
        if index==count:break
        slot=array+40*index
        if memory.load(slot+0x20,4)!=11:raise InputError('NT formatter requires actual CString variant11')
        pointer=memory.load(slot+8,8);data=bytearray()
        while memory.load(pointer+len(data),1):data.append(memory.load(pointer+len(data),1))
        _append(output,output_address,bytes(data),literal=False)
    return output


def nt_misc_mmkv(runtime,source_file,id_copy,path_copy,crypt_copy):
    memory=runtime.memory;pending=runtime._mmkv_caller_pending
    runtime.events.append(('source.64FBA',2,source_file,0x73c,b'',_NT_FORMAT))
    if enabled(runtime,2):
        frame,unused=_frame(runtime,160,'6E282 native40 argument array and format view')
        view=frame;array=frame+16;output_address=frame+136
        pending['log_frame']=frame;pending['log_array']=array;pending['log_output']=output_address
        memory.store(view,runtime.image_base+0x45d2964,8,source='64FBA.fixed_format_pointer')
        memory.store(view+8,len(_NT_FORMAT),8,source='64FBA.fixed_format_length')
        for index in range(3):
            memory.store(array+40*index+8,0,1,source='6E282.initial_BYTE8')
            memory.store(array+40*index+0x20,0,4,source='6E282.initial_tag0')
        for index,address in enumerate((id_copy,path_copy,crypt_copy)):
            source=_String.read(runtime,address);tag=source.get(0,1)
            pointer=source.get(16,8) if tag&1 else address+1
            length=source.get(8,8) if tag&1 else tag>>1 # 2FEB discards the actual span length.
            slot=array+40*index
            if memory.load(slot+0x20,4)!=0:raise InputError('NT variant initialization changed')
            memory.store(slot+0x20,0xffffffff,4,source='2896.tag0_RET')
            memory.store(slot+8,pointer,8,source='3028.borrowed_CString')
            memory.store(slot+0x20,11,4,source='308A.variant11')
        message=_nt_format_records(runtime,view,array,3,output_address)
        for index in reversed(range(3)):
            if memory.load(array+40*index+0x20,4)!=11:raise InputError('NT CString variant lifetime changed')
            memory.store(array+40*index+0x20,0xffffffff,4,source='2896.variant11_RET')
        _emit_cold(runtime,message,2,0x73c,source_file=source_file,function=b'')
        runtime.events.append(('source.64FBA.message_dtor',output_address))
        message.destroy();memory.unmap(frame);pending['log_frame']=None
    # These are source normal call positions, never exception cleanup.
    for address in (id_copy,path_copy,crypt_copy):
        runtime.events.append(('source.64FBA.copy_dtor',address))
        _String.read(runtime,address).destroy()


def nt_config_missing(runtime,source_file,id_copy,key_copy):
    memory=runtime.memory;pending=runtime._selector_config_pending
    runtime.events.append(('source.62140',4,source_file,0x767,b'',_NT_MISSING))
    if enabled(runtime,4):
        frame,unused=_frame(runtime,120,'450C native40 config argument array and format view')
        view=frame;array=frame+16;output_address=frame+96
        pending['log_frame']=frame;pending['log_array']=array
        memory.store(view,runtime.image_base+0x4604ab6,8,source='62140.fixed_format_pointer')
        memory.store(view+8,35,8,source='62140.fixed_format_length')
        for index in range(2):
            memory.store(array+40*index+8,0,1,source='450C.initial_BYTE8');memory.store(array+40*index+0x20,0,4,source='450C.initial_tag0')
        for index,address in enumerate((id_copy,key_copy)):
            source=_String.read(runtime,address);tag=source.get(0,1)
            pointer=source.get(16,8) if tag&1 else address+1
            length=source.get(8,8) if tag&1 else tag>>1
            memory.store(array+40*index+0x20,0xffffffff,4,source='2896.tag0_RET')
            memory.store(array+40*index+8,pointer,8,source='3028.borrowed_CString');memory.store(array+40*index+0x20,11,4,source='308A.variant11')
        message=_nt_format_records(runtime,view,array,2,output_address)
        for index in reversed(range(2)):memory.store(array+40*index+0x20,0xffffffff,4,source='2896.variant11_RET')
        _emit_cold(runtime,message,4,0x767,source_file=source_file,function=b'')
        message.destroy();memory.unmap(frame);pending['log_frame']=None
    for address in (id_copy,key_copy):
        runtime.events.append(('source.62140.copy_dtor',address));_String.read(runtime,address).destroy()


def _emit_cold(runtime,message,level,line,*,source_file=b'login_service.cc',function=b'initConfig'):
    memory=runtime.memory;base=runtime.image_base
    runtime.events.append(('source.D3A81F',level,source_file,line,function,message.value()))
    if memory.load(base+0x6753528,8):
        raise PrimarySemanticUnavailable('D3AB8F nonempty filter shared-pair predicate unavailable')
    if memory.load(base+0x6753530+0x78,8) or memory.load(base+0x6753530+0x28,8):
        raise PrimarySemanticUnavailable('D3A81F nonempty holder source terminal unavailable')
    if (source_file,function)!=(b'login_service.cc',b'initConfig') and (level,line,source_file,function) not in ((2,0x73c,b'nt_wrapper_engine.cc',b''),(4,0x767,b'nt_wrapper_engine.cc',b''),(2,0x21,b'msf_security_sign_callback.cc',b'SetSessionId')):raise PrimarySemanticUnavailable('D3 source metadata outside finite supported calls')
    output=_format_fixed(runtime,b'[{}] {}({})::{} {}',(('cstring',b'I' if level==2 else b'E'),('cstring',source_file),('integer',line),('cstring',function),('String',message)))
    if memory.load(base+0x6753530,8) or memory.load(base+0x6753530+0x50,8):
        raise PrimarySemanticUnavailable('D3A81F unbound actual output callback unavailable')
    output.destroy()


def login_config(runtime,common_path,client_ver,machine_id,plat_ver):
    values=(common_path,client_ver,machine_id,plat_ver)
    try:
        if enabled(runtime,2):
            message=_format_fixed(runtime,b'InitConfig, commonPath: {}, clientVer: {}, machineId: {}, platVer: {}',tuple(('String',value) for value in values))
            _emit_cold(runtime,message,2,0x129)
            message.destroy()
    finally:
        # Known argument host retirement; no claim about source formatter EH.
        for value in values:value.destroy()


def empty_msf_path(runtime):
    if enabled(runtime,4):
        message=_String.construct(runtime,b' path: get msf save path failed!!!')
        _emit_cold(runtime,message,4,0x122)
        message.destroy()


def session_log(runtime,metadata,level,source_file,line,function,template,owned_copy):
    from .primary_client_configuration_startup import validate_image
    from .primary_logger import _cstring
    validate_image(runtime)
    base,memory=runtime.image_base,runtime.memory
    if (metadata!=base+0x3F6DE00 or level!=2 or line!=0x21 or function!=base+0x4849C07 or
            template!=base+0x46629B0 or _cstring(runtime,source_file)!=b'msf_security_sign_callback.cc' or
            _cstring(runtime,metadata)!=b'MSFSecuritySignCallback' or _cstring(runtime,function)!=b'SetSessionId'):
        raise InputError('4CC9 metadata differs from the finite SetSessionId source call')
    frame,unused=_frame(runtime,0x60,'4CC9 source formatting locals')
    rbp=frame+0x40
    pending=dict(frame=frame,rbp=rbp,metadata=metadata,owned_copy=owned_copy)
    runtime._client_session_log_pending=pending
    memory.store(rbp-0x10,metadata,8,source='4CE8.metadata_CString_pointer')
    if enabled(runtime,level):
        memory.store(rbp-0x28,template,8,source='4CFF.format_pointer')
        length=_invoke(runtime,0x3EB2C10,template)
        memory.store(rbp-0x20,length,8,source='4D07.actual_strlen_length')
        pending.update(stage='4D16',format_view=rbp-0x28)
        _session_one(runtime,rbp-0x40,rbp-0x28,owned_copy,pending)
        pending['stage']='4D2D'
        _session_two(runtime,rbp-0x28,base+0x3EB8678,rbp-0x10,rbp-0x40,pending)
        pending['stage']='4D43'
        _emit_cold(runtime,_String.read(runtime,rbp-0x28),level,line,
                   source_file=_cstring(runtime,source_file),function=_cstring(runtime,function))
        for site,address in ((0x4D4C,rbp-0x28),(0x4D55,rbp-0x40)):
            runtime.events.append(('source.4CC9.normal_dtor',site,address))
            _String.read(runtime,address).destroy()
    runtime.events.append(('source.4CC9.normal_dtor',0x4D5E,owned_copy))
    _String.read(runtime,owned_copy).destroy()
    memory.unmap(frame)
    runtime._client_session_log_pending=None


def _session_one(runtime,output,view,argument,pending):
    memory=runtime.memory
    frame,unused=_frame(runtime,56,'2F11 single borrowed String variant and format view')
    pending['one_adapter']=frame
    memory.store(frame+8,0,1,source='2F11.initial_BYTE8')
    memory.store(frame+0x20,0,4,source='2F11.initial_tag0')
    memory.copy_disjoint(frame+40,view,16,label='2F11.copied_format_view')
    value=_String.read(runtime,argument);tag=value.get(0,1)
    pointer=value.get(16,8) if tag&1 else argument+1
    memory.store(frame+0x20,0xFFFFFFFF,4,source='2896.tag0_RET')
    memory.store(frame+8,pointer,8,source='2F93.borrowed_String_CString')
    memory.store(frame+0x20,11,4,source='2F93.variant11')
    runtime.events.append(('source.2F51.D3BE4F',output,frame+40,frame,1))
    _nt_format_records(runtime,frame+40,frame,1,output)
    memory.store(frame+0x20,0xFFFFFFFF,4,source='2F5A.2896_variant11_RET')
    memory.unmap(frame)
    pending['one_adapter']=None


def _session_two(runtime,output,view,metadata_pointer,first,pending):
    memory=runtime.memory
    frame,unused=_frame(runtime,96,'3A12 two native argument records and copied view')
    pending.update(two_adapter=frame,two_output=output,metadata_pointer=metadata_pointer,first_formatted=first)
    for index in (0,1):
        memory.store(frame+40*index+8,0,1,source='3A12.initial_payload_BYTE')
        memory.store(frame+40*index+0x20,0,4,source='3A12.initial_tag0')
    memory.copy_disjoint(frame+80,view,16,label='3A12.copied_format_view')
    # 3AC2/3AEB/3AFD dereference the metadata CString pointer and use the
    # already recovered 3028 pointer-borrow producer. No String is cloned.
    pointer=memory.load(metadata_pointer,8)
    memory.store(frame+0x20,0xFFFFFFFF,4,source='2896.tag0_RET')
    memory.store(frame+8,pointer,8,source='3028.metadata_CString_pointer')
    memory.store(frame+0x20,11,4,source='308A.metadata_variant11')
    value=_String.read(runtime,first);tag=value.get(0,1)
    pointer=value.get(16,8) if tag&1 else first+1
    memory.store(frame+40+0x20,0xFFFFFFFF,4,source='2896.tag0_RET')
    memory.store(frame+40+8,pointer,8,source='2F93.borrowed_String_CString')
    memory.store(frame+40+0x20,11,4,source='2F93.variant11')
    runtime.events.append(('source.3A60.D3BE4F',output,frame+80,frame,2))
    _nt_format_records(runtime,frame+80,frame,2,output)
    for index in (1,0):
        memory.store(frame+40*index+0x20,0xFFFFFFFF,4,source='3A12.2896_variant11_RET')
    memory.unmap(frame)
    pending['two_adapter']=None
