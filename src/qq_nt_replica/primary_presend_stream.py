"""Finite business MODEL of the stateful presend stream; no GS/native frame claim."""
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame

_U32=(1<<32)-1
_U64=(1<<64)-1
_K=(3614090360, 3905402710, 606105819, 3250441966, 4118548399, 1200080426, 2821735955, 4249261313, 1770035416, 2336552879, 4294925233, 2304563134, 1804603682, 4254626195, 2792965006, 1236535329, 4129170786, 3225465664, 643717713, 3921069994, 3593408605, 38016083, 3634488961, 3889429448, 568446438, 3275163606, 4107603335, 1163531501, 2850285829, 4243563512, 1735328473, 2368359562, 4294588738, 2272392833, 1839030562, 4259657740, 2763975236, 1272893353, 4139469664, 3200236656, 681279174, 3936430074, 3572445317, 76029189, 3654602809, 3873151461, 530742520, 3299628645, 4096336452, 1126891415, 2878612391, 4237533241, 1700485571, 2399980690, 4293915773, 2240044497, 1873313359, 4264355552, 2734768916, 1309151649, 4149444226, 3174756917, 718787259, 3951481745)
_S=(7,12,17,22)*4+(5,9,14,20)*4+(4,11,16,23)*4+(6,10,15,21)*4


def _compress_words(state,words):
    a,b,c,d=state
    for i in range(64):
        if i<16:f=(b&c)|(~b&d);g=i
        elif i<32:f=(b&d)|(c&~d);g=(5*i+1)%16
        elif i<48:f=b^c^d;g=(3*i+5)%16
        else:f=c^(b|~d);g=7*i%16
        value=(a+f+_K[i]+words[g])&_U32
        rotated=((value<<_S[i])|(value>>(32-_S[i])))&_U32
        a,d,c,b=d,c,b,(b+rotated)&_U32
    return tuple((x+y)&_U32 for x,y in zip(state,(a,b,c,d)))


def block(runtime,context,pointer):
    m=runtime.memory
    state=tuple(m.load(context+4*i,4) for i in range(4))
    words=tuple(m.load(pointer+4*i,4) for i in range(16))
    result=_compress_words(state,words)
    for i,value in enumerate(result):m.store(context+4*i,value,4,source='1D04820.feedforward')


def _copy(m,destination,source,count,*,fill,index):
    # Same forward BYTE fallback for overlap. The disjoint fill uses single
    # XMMs, while tail32 reads both XMMs before either store.
    disjoint=(destination >= ((source+count)&_U64) or source >= ((destination+count)&_U64))
    position=0
    if disjoint and ((fill and index<=56) or (not fill and count>=8)):
        if fill:
            while position+16<=count:
                value=m.read(source+position,16)
                m.write(destination+position,value,source='stream.copy_XMM')
                position+=16
        else:
            while position+32<=count:
                first=m.read(source+position,16);second=m.read(source+position+16,16)
                m.write(destination+position,first,source='stream.copy_XMM_A')
                m.write(destination+position+16,second,source='stream.copy_XMM_B')
                position+=32
        while position+8<=count:
            value=m.read(source+position,8);m.write(destination+position,value,source='stream.copy_QWORD');position+=8
    while position<count:
        value=m.load(source+position,1);m.store(destination+position,value,1,source='stream.copy_BYTE');position+=1


def _absorb(runtime,context,pointer,count,index):
    need=64-index;used=0
    if count>=need:
        _copy(runtime.memory,context+24+index,pointer,need,fill=True,index=index)
        block(runtime,context,context+24);used=need
        while used+64<=count:
            block(runtime,context,pointer+used);used+=64
        index=0
    remaining=count-used
    if remaining:_copy(runtime.memory,context+24+index,pointer+used,remaining,fill=False,index=index)


def update(runtime,context,pointer,count):
    m=runtime.memory;count&=_U32
    low=m.load(context+16,4);index=(low>>3)&63;total=low+((count<<3)&_U32)
    m.store(context+16,total&_U32,4,source='1D0514C.count_low')
    high=m.load(context+20,4)
    m.store(context+20,(high+(count>>29)+(total>>32))&_U32,4,source='1D05150.count_high')
    _absorb(runtime,context,pointer,count,index)


def final(runtime,output,context):
    from .primary_client_configuration_scope import stream_padding
    m=runtime.memory
    local,unused=_frame(runtime,8,'1D05590.saved_bitcount')
    low=m.load(context+16,4);m.store(local,low,4,source='1D055B8.saved_low')
    high=m.load(context+20,4);m.store(local+4,high,4,source='1D055BF.saved_high')
    index=(low>>3)&63;count=(56-index) if index<56 else (120-index)
    total=low+((count<<3)&_U32)
    m.store(context+16,total&_U32,4,source='1D055F3.count_low')
    m.store(context+20,(high+(count>>29)+(total>>32))&_U32,4,source='1D055F8.count_high')
    padding=stream_padding(runtime)
    _absorb(runtime,context,padding,count,index)
    low=m.load(context+16,4);index=(low>>3)&63
    m.store(context+16,(low+64)&_U32,4,source='1D05819.count_low')
    high=m.load(context+20,4)
    m.store(context+20,(high+int(low>=0xFFFFFFC0))&_U32,4,source='1D0581F.count_high')
    used=0
    if index>=56:
        used=64-index
        _invoke(runtime,0x3EB1FE0,context+24+index,local,used)
        block(runtime,context,context+24);index=0
    if used!=8:_invoke(runtime,0x3EB1FE0,context+24+index,local+used,8-used)
    for i in range(16):m.store(output+i,m.load(context+i,1),1,source='1D05590.output_BYTE')
    for offset in (64,48,32,16,0):m.write(context+offset,bytes(16),source='1D05590.erase_XMM')
    m.store(context+80,0,8,source='1D0590D.erase_QWORD')
    m.unmap(local)


def invoke(runtime,rva,values):
    if rva==0x1D04820 and len(values)==2:return block(runtime,*values)
    if rva==0x1D05120 and len(values)==3:return update(runtime,*values)
    if rva==0x1D05590 and len(values)==2:return final(runtime,*values)
    from .errors import InputError
    raise InputError('unsupported presend stream entry/ABI')
