"""Finite source MMKV printf orchestration; system stdio is an explicit provider."""
from .primary_logger import _String
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
from .primary_crt_stdio_options import read_options
from .primary_vm import PrimarySemanticUnavailable


def _format(runtime,port,token,buffer,capacity):
    options=read_options(runtime)
    result=port._format(token,buffer,capacity,options|2)
    if type(result) is not int:raise PrimarySemanticUnavailable('7017B4 provider did not return source int')
    return -1 if result<0 else result


def _resize(runtime,message,address,size):
    if size<0 or size>=1<<63:raise PrimarySemanticUnavailable('75D0F0 unsupported resize/overflow')
    old=message.value();heap=bool(message.get(0,1)&1)
    capacity=(message.get(0,8)&~1)-1 if heap else 22
    memory=runtime.memory
    if size>capacity:
        physical=(max(2*capacity,size)|15)+1
        pointer=_invoke(runtime,0xB75000,physical)
        if old:memory.write(pointer,old,source='75D0F0.old_copy')
        if heap:_invoke(runtime,0xB75029,message.get(16,8))
        message.set(16,pointer.to_bytes(8,'little'));memory.store(address+16,pointer,8,source='75D0F0.buffer')
        message.set(0,(physical|1).to_bytes(8,'little'));memory.store(address,physical|1,8,source='75D0F0.capacity')
        heap=True
    else:pointer=message.get(16,8) if heap else address+1
    if size>len(old):memory.write(pointer+len(old),bytes(size-len(old)),source='75D0F0.fill_zero')
    if heap:
        message.set(8,size.to_bytes(8,'little'));memory.store(address+8,size,8,source='75D0F0.length')
    else:
        message.set(0,bytes((size*2,)));memory.store(address,size*2,1,source='75D0F0.short_length')
    memory.store(pointer+size,0,1,source='75D0F0.NUL')
    if not heap:message.set(1,memory.read(pointer,size+1))
    return pointer


def log(runtime,level,file,function,line,template,arguments):
    if runtime.memory.load(runtime.image_base+0x6188c48,4,signed=True)>level:return
    runtime.events.append(('1BDF22C.arguments',level,file,function,line,template,arguments))
    from .primary_windows_mmkv_stdio import for_runtime
    port=for_runtime(runtime)
    frame,unused=_frame(runtime,64,'1BDF22C message and uninitialized16B buffer')
    memory=runtime.memory;message=_String.construct(runtime,b'');message.write_to(frame)
    buffer=frame+32
    token=port._begin(template,arguments,buffer)
    n=_format(runtime,port,token,buffer,16)
    if 0<=n<16:
        temporary=_String.construct(runtime,memory.read(buffer,n))
        message.destroy();message=_String(runtime,temporary.header,temporary.known)
        message.write_to(frame)
        # 5FE2 transfers ownership; source temporary is now empty before destructor.
        temporary=_String.construct(runtime,b'');temporary.destroy()
    elif n>=16:
        pointer=_resize(runtime,message,frame,n)
        _format(runtime,port,token,pointer,n+1) # same recorded va_list start; result intentionally ignored
        if not message.get(0,1)&1:message.set(1,memory.read(pointer,n+1))
    else:
        from .primary_sdk import assign_string
        assign_string(runtime,frame,0,0)
        message=_String.read(runtime,frame)
    # Ordinary negative assigns empty without reading a NULL/failed output buffer.
    if memory.load(runtime.image_base+0x677bc70,8):
        raise PrimarySemanticUnavailable('1BDF22C nonNULL actual callback binding unavailable')
    options=read_options(runtime)
    port._output(token,options,level,file,line,function,message) # ordinary output status ignored
    message.destroy();port._end(token);memory.unmap(frame)
