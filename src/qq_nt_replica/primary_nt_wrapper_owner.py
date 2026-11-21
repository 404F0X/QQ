"""Fixed-source NT wrapper module owner used by MSF selection, model memory only."""
import sys
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_shared_locale import resolve_current_module_tls
from .primary_sdk import _add_owner,_release_owner
from .primary_logger import _String

_BIRTHS={}
_CELLS=((0x6745648,8),(0x6745650,8),(0x6745658,4))


def install_fresh_image(signer):
    from .primary_signer import PrimarySigner
    frame=sys._getframe(1)
    if type(signer) is not PrimarySigner or frame.f_code is not PrimarySigner._initialize_image.__code__ or frame.f_locals.get('self') is not signer:
        raise InputError('NT selector cells require original model image installer')
    key=id(signer.memory)
    if key in _BIRTHS:raise InputError('NT selector model birth cannot be adopted/reset')
    rows=[]
    for rva,size in _CELLS:
        pointer=signer.image_base+rva
        signer.memory.map(pointer,bytearray(size),name='fixed PE virtual-tail MODEL loader birth',initialized=True)
        region,offset=signer.memory._span(pointer,size);rows.append((pointer,region,offset,size))
    from .primary_memory import PrimaryMemoryLimit
    for slot,target in ((0x3ec64f8+0x30,0x64c9e),(0x3ec64f8+0x38,0x65240)):
        address=signer.image_base+slot;expected=signer.image_base+target
        try:observed=signer.memory.load(address,8)
        except PrimaryMemoryLimit:
            signer.memory.map(address,expected.to_bytes(8,'little'),name='fixed NT interface method slot',initialized=True)
        else:
            if observed!=expected:raise InputError('NT method fixed-source slot mismatch')
    _BIRTHS[key]=(signer.memory,signer.image_base,tuple(rows))


def validate_birth(runtime):
    record=_BIRTHS.get(id(runtime.memory))
    if record is None or record[0] is not runtime.memory or record[1]!=runtime.image_base:
        raise InputError('NT selection lacks original model-loader birth')
    for pointer,region,offset,size in record[2]:
        actual,observed=runtime.memory._span(pointer,size)
        if actual is not region or observed!=offset:raise InputError('NT selection birth backing changed')


def _tree(runtime,pointer):
    runtime.memory.store(pointer,pointer+8,8,source='3BA6.head')
    runtime.memory.write(pointer+8,bytes(16),source='3BA6.empty')


def _construct(runtime):
    memory,base=runtime.memory,runtime.image_base
    obj=_invoke(runtime,0xB75000,0x3d8)
    memory.write(obj,bytes(0x3d8),source='5B656.whole_source_object_zero')
    for offset,table in ((0,0x3ec6488),(8,0x3ec64f8),(0x10,0x3ec6568)):
        memory.store(obj+offset,base+table,8,source='5B780.interface')
    memory.store(obj+0x28,0,1,source='5B780.byte28')
    for offset in (0x30,0x39):memory.write(obj+offset,bytes(16),source='5B780.zero16')
    for offset in (0x50,0x68):_invoke(runtime,0x6270,obj+offset)
    memory.store(obj+0x80,0,4,source='2B174.field80')
    for offset in (0x88,0xa0,0xb8,0xd0,0xe8):_invoke(runtime,0x6270,obj+offset)
    memory.store(obj+0x100,0,1,source='2B174.byte100')
    memory.store(obj+0x104,0,4,source='2B174.field104')
    for offset in (0x108,0x150):memory.store(obj+offset,0,1,source='5B780.optional')
    memory.store(obj+0x160,0,8,source='664B6.field160')
    memory.store(obj+0x168,8,1,source='664B6.literal_size')
    memory.write(obj+0x169,b'null\0',source='664B6.literal_null')
    for offset in (0x180,0x184,0x18c,0x190,0x198,0x19c,0x1a4,0x1a8):
        memory.store(obj+offset,0,1,source='664B6.flag')
    memory.store(obj+0x1b0,0,2,source='664B6.word')
    for offset in (0x1b8,0x1d0,0x1e0,0x1f8,0x208,0x220,0x230,0x248,0x258,0x270):
        memory.store(obj+offset,0,1,source='664FA.optional')
    memory.store(obj+0x280,0,4,source='2FFC4.field')
    for offset in (0x288,0x2a0,0x2b8,0x2d0):_invoke(runtime,0x6270,obj+offset)
    for offset in (0x2e8,0x318):memory.store(obj+offset,0,1,source='5B780.optional')
    memory.store(obj+0x320,0,4,source='5B780.field320')
    for offsets,string in (((0x328,0x338),0x348),((0x370,0x360),0x380)):
        for offset in offsets:memory.write(obj+offset,bytes(16),source='5B780.zero16')
        _invoke(runtime,0x6270,obj+string)
    for offset in (0x3a8,0x398):memory.write(obj+offset,bytes(16),source='5B780.zero16')
    memory.store(obj+0x3b8,0,8,source='5B780.map_lock')
    _tree(runtime,obj+0x3c0)
    control=_invoke(runtime,0xB75000,0x28)
    memory.store(control,base+0x3ec69b8,8,source='5B902.control_vtable')
    memory.store(control+8,0,4,source='5B902.strong')
    memory.store(control+0x10,0,4,source='5B902.weak')
    memory.store(control+0x18,obj,8,source='5B902.control_object')
    _add_owner(runtime,control)
    memory.store(control+0x10,memory.load(control+0x10,4)+1,4,source='168CE.weak_add')
    memory.store(obj+0x18,obj,8,source='168CE.selfweak_object')
    memory.store(obj+0x20,control,8,source='168CE.selfweak_control')
    _release_owner(runtime,control)
    return obj,control


def acquire(runtime):
    validate_birth(runtime);receipt=resolve_current_module_tls(runtime)
    memory,base=runtime.memory,runtime.image_base;guard=base+0x6745658
    if memory.load(guard,4,signed=True)>memory.load(receipt.epoch_address,4,signed=True):
        runtime._locale_thread_header(guard)
        if memory.load(guard,4,signed=True)==-1:
            obj,control=_construct(runtime)
            memory.store(base+0x6745648,obj,8,source='5B656.module_object')
            memory.store(base+0x6745650,control,8,source='5B656.module_control')
            runtime._locale_thread_footer(guard)
    obj=memory.load(base+0x6745648,8);control=memory.load(base+0x6745650,8)
    _add_owner(runtime,control)  # 5B656 getter copy
    _add_owner(runtime,control)  # 5B11A output copy
    _release_owner(runtime,control)  # 5B11A temporary release
    return obj,control


def release(runtime,obj,control):
    validate_birth(runtime)
    if (runtime.memory.load(obj+0x18,8)!=obj or runtime.memory.load(obj+0x20,8)!=control):
        raise InputError('NT strong lease/source selfweak identity changed')
    _release_owner(runtime,control)
