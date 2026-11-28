"""Finite 35D44F0/35D4630 source model; never an OS environment fallback."""
from contextlib import contextmanager
from dataclasses import dataclass
import os,threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable,PrimaryProgramLimit
from .primary_logger import _String
from .primary_worker_consumer import _invoke
from .primary_sdk import assign_string

NAMES=(b'_PYI_ARCHIVE_FILE',b'_PYI_APPLICATION_HOME_DIR',b'LITELOADERQQNT_PROFILE')
LIMIT=1<<20
@dataclass(frozen=True)
class EnvironmentReply:
    result: int
    after_bytes: bytes=b''
    known_mask: bytes=b''

class ModelEnvironmentValues:
    origin='synthetic-test-input'
    def __init__(self,events):
        self.events=iter(events);self.active=False;self.closed=False;self.pending=None;self.index=0
    def begin(self,runtime,names=NAMES):
        if self.closed or self.active:raise InputError('environment source window unavailable')
        self.runtime=runtime;self.epoch=runtime._primary_allocator_selector_epoch
        self.thread=(os.getpid(),threading.get_native_id());self.active=True;self.index=0;self.names=tuple(names)
        if not self.names or any(n not in NAMES for n in self.names):raise InputError('foreign environment name')
    def check(self,runtime):
        if (not self.active or self.closed or runtime is not self.runtime or
            runtime._primary_allocator_selector_epoch is not self.epoch or
            self.thread!=(os.getpid(),threading.get_native_id())):
            raise InputError('environment source lifetime changed')
    def take(self,runtime,name,phase,capacity,before):
        self.check(runtime)
        if self.index>=len(self.names) or name!=self.names[self.index] or phase not in ('probe','read'):
            raise InputError('environment source name/order changed')
        if phase=='probe':
            if self.pending is not None or capacity or before:raise InputError('environment probe pair changed')
        elif self.pending!=capacity or len(before)!=capacity:
            raise InputError('environment read differs from original probe capacity')
        reply=self._reply(runtime,name,phase,capacity,before)
        _validate_reply(reply,phase,capacity)
        if phase=='probe':
            if reply.result:self.pending=reply.result
            else:self.index+=1
        else:self.pending=None;self.index+=1
        return reply
    def _reply(self,runtime,name,phase,capacity,before):
        try:expected,reply=next(self.events)
        except StopIteration as e:raise InputError('environment observations exhausted') from e
        if expected!=(name,phase,capacity) or type(reply) is not EnvironmentReply:
            raise InputError('environment observation schema/order mismatch')
        return reply
    def end(self,runtime,failed=False):
        try:
            self.check(runtime)
            if not failed and (self.pending is not None or self.index!=len(self.names)):
                raise InputError('environment window ended before all original pairs')
        finally:
            self.active=False;self.closed=True

def _validate_reply(reply,phase,capacity):
    if type(reply.result) is not int or not 0<=reply.result<=0xFFFFFFFF:
        raise InputError('environment API requires DWORD result')
    if phase=='probe':
        if reply.after_bytes or reply.known_mask:raise InputError('NULL probe cannot write output')
        if reply.result>LIMIT:raise PrimaryProgramLimit('environment probe exceeds finite source domain')
    elif (type(reply.after_bytes) is not bytes or type(reply.known_mask) is not bytes or
          len(reply.after_bytes)!=capacity or len(reply.known_mask)!=capacity or
          any(v not in (0,1) for v in reply.known_mask)):
        raise InputError('environment read requires exact postcall bytes and known mask')

@contextmanager
def _window(runtime,names=NAMES):
    import sys
    frame=sys._getframe(1)
    while frame is not None and frame.f_code not in (collect.__code__,invoke.__code__):frame=frame.f_back
    if frame is None or frame.f_locals.get('runtime') is not runtime:
        raise InputError('environment window lacks original finite helper frame')
    service=getattr(runtime,'notification_environment_values_observations',None)
    if service is None:
        facade=getattr(runtime,'notification_parent_observations',None)
        if facade is None:raise PrimarySemanticUnavailable('environment values require actual parent source or explicit model observations')
        service=facade.parent.environment_values_service(runtime,facade)
    elif type(service) is not ModelEnvironmentValues:
        raise InputError('explicit environment observations must remain typed synthetic')
    service.begin(runtime,names)
    failed=True
    try:yield service;failed=False
    finally:
        import sys
        primary=sys.exception()
        try:service.end(runtime,failed=failed)
        except BaseException as cleanup:
            if primary is None:raise
            primary.add_note('environment source window cleanup failed: '+type(cleanup).__name__)

def _observe(runtime,service,name,phase,capacity,before):
    reply=service.take(runtime,name,phase,capacity,before)
    if type(reply) is not EnvironmentReply:raise InputError('environment API returned foreign reply')
    _validate_reply(reply,phase,capacity)
    return reply

def _read_value(runtime,service,output,name_header):
    name=_String.read(runtime,name_header).value()
    if name not in NAMES:raise InputError('environment helper only supports fixed source names')
    n=_observe(runtime,service,name,'probe',0,b'').result
    m=runtime.memory
    if not n:m.store(output,0,2,source='35D4548.probe_zero');return output
    value=_String(runtime)
    if n<23:
        value.set(0,bytes([n*2]));pointer=output+1
    else:
        capacity=(n+16)&~15;pointer=_invoke(runtime,0xB75000,capacity)
        value.set(0,(capacity|1).to_bytes(8,'little'));value.set(8,n.to_bytes(8,'little'));value.set(16,pointer.to_bytes(8,'little'))
    # Local String backing is represented by the destination region until its move.
    m.write(pointer,bytes(n+1),source='35D457F.prezero_and_terminator')
    reply=_observe(runtime,service,name,'read',n,bytes(n))
    for i,(byte,known) in enumerate(zip(reply.after_bytes,reply.known_mask)):
        if known:m.store(pointer+i,byte,1,source='35D45B1.GetEnvironmentVariableA')
        else:m.forget(pointer+i,1,source='35D45B1.unobserved_output')
    # 75D0F0 resize ignores the second API result; shrinking writes the new NUL.
    m.store(pointer+n-1,0,1,source='75D0F0.resize_terminator')
    if n<23:
        region,off=m._span(pointer,n)
        value.set(0,bytes([(n-1)*2]));value.header[1:n+1]=region.data[off:off+n];value.known[1:n+1]=region.initialized[off:off+n]
    else:value.set(8,(n-1).to_bytes(8,'little'))
    value.write_to(output);return output

class _ValueTree:
    def __init__(self,runtime,address):
        self.runtime=runtime;self.m=runtime.memory;self.address=address
        self.put(address,0,address+8);self.put(address,8,0);self.put(address,16,0)
    def get(self,p,o=0,size=8):return self.m.load(p+o,size)
    def put(self,p,o,v,size=8):self.m.store(p+o,v,size,source='environment.value_tree')
    def rotate(self,p,left):
        side,other=(8,0) if left else (0,8);child=self.get(p,side);moved=self.get(child,other)
        self.put(p,side,moved)
        if moved:self.put(moved,16,p)
        parent=self.get(p,16);self.put(child,16,parent)
        self.put(parent,0 if self.get(parent)==p else 8,child)
        self.put(child,other,p);self.put(p,16,child)
    def balance(self,node):
        root=self.get(self.address,8);self.put(node,24,int(node==root),1)
        for _ in range(4):
            if node==root:return
            parent=self.get(node,16)
            if self.get(parent,24,1):return
            grand=self.get(parent,16);left=self.get(grand)==parent;uncle=self.get(grand,8 if left else 0)
            if uncle and not self.get(uncle,24,1):
                self.put(parent,24,1,1);self.put(grand,24,int(grand==root),1);self.put(uncle,24,1,1);node=grand;continue
            if self.get(parent,8 if left else 0)==node:
                self.rotate(parent,left);parent=self.get(parent,16);grand=self.get(parent,16)
            self.put(parent,24,1,1);self.put(grand,24,0,1);self.rotate(grand,not left);return
        raise PrimaryProgramLimit('environment tree balance exceeds three original values')
    def insert(self,value):
        raw=value.value();parent=slot=self.address+8;node=self.get(slot)
        while node:
            present=_String.read(self.runtime,node+32).value()
            if raw==present:return node,False
            parent=node;slot=node+(0 if raw<present else 8);node=self.get(slot)
        if self.get(self.address,16)>=3:raise PrimaryProgramLimit('environment tree exceeds three source values')
        node=_invoke(self.runtime,0xB75000,56)
        value.clone().write_to(node+32)
        self.put(node,0,0);self.put(node,8,0);self.put(node,16,parent);self.put(slot,0,node)
        begin=self.get(self.address);left=self.get(begin)
        if left:self.put(self.address,0,left)
        self.balance(node);self.put(self.address,16,self.get(self.address,16)+1)
        return node,True
    def destroy(self,node=None):
        if node is None:node=self.get(self.address,8)
        if not node:return
        left,right=self.get(node),self.get(node,8)
        if left:self.destroy(left)
        if right:self.destroy(right)
        _String.read(self.runtime,node+32).destroy();_invoke(self.runtime,0xB75029,node)

def collect(runtime,output):
    m=runtime.memory
    # Source locals require independent addressable headers and tree sentinel.
    from .primary_worker_response import _frame
    frame,_=_frame(runtime,0x200,'35D4630.environment_frame')
    tree=_ValueTree(runtime,frame);name_header=frame+32;current=frame+64;temporary=frame+96;literal=frame+128
    try:
        with _window(runtime) as service:
            for index,name in enumerate(NAMES):
                m.write(literal,name+b'\0',source='35D4630.fixed_decoded_environment_name')
                if index==0:_String.construct(runtime,name).write_to(name_header)
                else:assign_string(runtime,name_header,literal,len(name))
                _read_value(runtime,service,temporary,name_header)
                if index:_String.read(runtime,current).destroy()
                _String.read(runtime,temporary).write_to(current)
                value=_String.read(runtime,current)
                if value.value():tree.insert(value)
            if tree.get(tree.address,16):m.store(output,0,2,source='35D4B93.normal_empty_result')
            else:m.write(output,bytes(24),source='35D4BE1.empty_aggregate_move')
            _String.read(runtime,current).destroy();_String.read(runtime,name_header).destroy();tree.destroy()
        return output
    finally:
        m.forget(frame,0x200,source='environment.local_lifetime_end')
        if not runtime.retain_frames:m.unmap(frame)

def invoke(runtime,rva,values):
    if rva==0x35D4630 and len(values)==1:return collect(runtime,values[0])
    if rva==0x35D44F0 and len(values)==2:
        name=_String.read(runtime,values[1]).value()
        with _window(runtime,(name,)) as service:return _read_value(runtime,service,*values)
    raise InputError('environment values helper physical ABI mismatch')
