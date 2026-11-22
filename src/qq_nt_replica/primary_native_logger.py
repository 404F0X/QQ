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
    if count!=3 or memory.load(view,8)!=runtime.image_base+0x45d2964 or memory.load(view+8,8)!=len(_NT_FORMAT):
        raise InputError('NT formatter requires original fixed literal view/count3')
    output=_String.construct(runtime,b'');output.write_to(output_address)
    parts=_NT_FORMAT.split(b'{}')
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


def _emit_cold(runtime,message,level,line,*,source_file=b'login_service.cc',function=b'initConfig'):
    memory=runtime.memory;base=runtime.image_base
    runtime.events.append(('source.D3A81F',level,source_file,line,function,message.value()))
    if memory.load(base+0x6753528,8):
        raise PrimarySemanticUnavailable('D3AB8F nonempty filter shared-pair predicate unavailable')
    if memory.load(base+0x6753530+0x78,8) or memory.load(base+0x6753530+0x28,8):
        raise PrimarySemanticUnavailable('D3A81F nonempty holder source terminal unavailable')
    if (source_file,function)!=(b'login_service.cc',b'initConfig') and (level,line,source_file,function)!=(2,0x73c,b'nt_wrapper_engine.cc',b''):raise PrimarySemanticUnavailable('D3 source metadata outside finite supported calls')
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
