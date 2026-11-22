"""Narrow owner/epoch-bound MODEL CAS and first cold64B NT misc tree node."""
import os,threading,weakref
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
_RECORDS=weakref.WeakKeyDictionary()
_MASK=(1<<64)-1


class _Bound:
    def __init__(self,r,pending):
        from .primary_windows_mmkv_host_init import for_runtime
        from .primary_module_sync import _resource
        self.r=r;self.pending=pending;self.port=for_runtime(r);self.port._check(None)
        self.owner=self.port._WindowsMMKVHost__owner;self.memory=r.memory;self.base=r.image_base
        self.image=r._shared_locale_source;self.image_epoch=r._shared_locale_source_epoch
        self.module=_resource(r);self.module_epoch=self.module.epoch
        self.allocator=r._custom_allocator_backend;self.epoch=self.allocator.source.epoch
        self.obj,self.control=pending['nt_pair'];self.cell=self.obj+0x3b8;self.tree=self.obj+0x3c0
        self.obj_record=self.allocator.records.get(self.obj);self.control_record=self.allocator.records.get(self.control)
        if self.obj_record is None or self.control_record is None:raise InputError('NT original allocation missing')
        self.obj_backing=self.obj_record[0].data;self.control_backing=self.control_record[0].data
        self.pid=os.getpid();self.thread=threading.get_native_id();self.mutex=threading.Lock();self.expected={};self.operations=[]
        self.check()

    def check(self):
        r=self.r;m=self.memory
        if (r._mmkv_caller_pending is not self.pending or self.port._WindowsMMKVHost__owner is not self.owner or
                self.owner._signer.runtime is not r or r.memory is not m or r.image_base!=self.base or
                r._shared_locale_source is not self.image or r._shared_locale_source_epoch is not self.image_epoch or
                self.image.epoch is not self.image_epoch or self.owner._signer._shared_locale_image is not self.image or
                r._custom_allocator_backend is not self.allocator or self.allocator.source.epoch is not self.epoch or
                self.module.epoch is not self.module_epoch or r._primary_allocator_selector is not self.allocator.source or
                r._primary_allocator_selector_epoch is not self.epoch or os.getpid()!=self.pid or threading.get_native_id()!=self.thread):
            raise InputError('NT MODEL operation identity/epoch changed')
        self.port._check(None);self.module.validate(r)
        obj_region,obj_offset=m._span(self.obj,0x3d8);control_region,control_offset=m._span(self.control,0x28)
        if (self.allocator.records.get(self.obj) is not self.obj_record or not self.obj_record or self.obj_record[1]!=0x3d8 or
                self.allocator.records.get(self.control) is not self.control_record or not self.control_record or self.control_record[1]!=0x28 or
                obj_region is not self.obj_record[0] or obj_offset or obj_region.data is not self.obj_backing or
                control_region is not self.control_record[0] or control_offset or control_region.data is not self.control_backing or
                self.obj_record[2] is not self.epoch or self.control_record[2] is not self.epoch or
                m.load(self.base+0x6745648,8)!=self.obj or m.load(self.base+0x6745650,8)!=self.control or
                self.pending['interface']!=self.obj+8 or m.load(self.pending['guard'],8)!=self.cell):
            raise InputError('NT original owner/control/cell/backing changed')

    def read(self):
        self.check()
        with self.mutex:return self.memory.load(self.cell,8)

    def scratch(self,value):
        self.check();address,unused=_frame(self.r,8,'D3FB3B actual expected QWORD')
        self.memory.store(address,value,8,source='D3FB3B.expected_input');self.expected[address]=(self.memory._span(address,8)[0],self.memory._span(address,8)[0].data)
        return address

    def cas(self,expected,desired,order):
        self.check()
        region,offset=self.memory._span(expected,8);issued=self.expected.get(expected)
        if order not in (2,3) or type(desired) is not int or not 0<=desired<=_MASK or issued is None or region is not issued[0] or region.data is not issued[1] or offset:raise InputError('NT CAS needs original expected cell/order/full64')
        # No guest execution/native call occurs in this operation. This mutex models serialization only.
        with self.mutex:
            observed=self.memory.load(self.cell,8);wanted=self.memory.load(expected,8)
            success=observed==wanted
            if success:self.memory.store(self.cell,desired,8,source='D3FB3B.MODEL_cell_success')
            else:self.memory.store(expected,observed,8,source='D3FB3B.MODEL_expected_failure')
        self.operations.append((order,observed,wanted,desired,success,expected));return success

    def stop(self,site,target,reason):
        self.pending['nt_boundary']=target;self.r.events.append(('source.unavailable',target,site,self.cell))
        raise PrimarySemanticUnavailable(reason)

    def acquire(self):
        state=self.read()
        if state&0x19:self.stop(0xd3de50,0xd3ded1,'D3DED1 NT contended acquire unavailable')
        expected=self.scratch(state)
        if not self.cas(expected,state|8,2):self.stop(0xd3de50,0xd3ded1,'D3DED1 NT failed acquire CAS unavailable')
        self.memory.unmap(expected);del self.expected[expected]

    def slot(self,key):
        self.check();m=self.memory;tree=self.tree
        root=m.load(tree+8,8)
        if root:
            self.pending['nt_compare_args']=(key,root+0x20)
            self.stop(0x422a,0x4075,'422A 4075 noncold NT comparator unavailable')
        begin=m.load(tree,8);count=m.load(tree+0x10,8)
        if begin!=tree+8 or count:raise PrimarySemanticUnavailable('NT sentinel/count outside finite cold attach domain')
        self.r.events.append(('source.call',0x24c0,0x40))
        node=_invoke(self.r,0xb75000,0x40);guard,unused=_frame(self.r,24,'6F490 node construction guard')
        self.pending.update(nt_node=node,nt_node_guard=guard)
        m.store(guard,node,8,source='6F490.guard_node');m.store(guard+8,tree+0x10,8,source='6F490.guard_count');m.store(guard+0x10,0,1,source='6F490.guard_key0')
        _invoke(self.r,0x75b810,node+0x20,key)
        m.store(node+0x38,0,8,source='6F490.value_NULL');m.store(guard+0x10,1,1,source='6F490.guard_key1')
        m.write(node,bytes(16),source='4307.children0');m.store(node+0x10,tree+8,8,source='430B.parent_sentinel')
        m.store(tree+8,node,8,source='430F.root_publish')
        m.load(m.load(tree,8),8)
        m.store(tree,node,8,source='431D.begin_publish')
        if m.load(tree+8,8)!=node:self.stop(0x432a,0x4341,'4341 nonroot NT balancing unavailable')
        m.store(node+0x18,1,1,source='434C.root_black')
        m.store(tree+0x10,m.load(tree+0x10,8)+1,8,source='432F.count_increment')
        m.store(guard,0,8,source='6F45E.guard_clear');m.store(guard,0,8,source='53334.NULL_cleanup')
        m.unmap(guard);return node+0x38

    def publish(self,key,raw):
        slot=self.slot(key)
        self.memory.store(slot,raw,8,source='64E1F.raw_MMkv_publish')
        return slot

    def release(self):
        state=self.read()
        if state!=8:self.stop(0xd3e9ac,0x3eb325e,'3EB325E NT slow release unavailable')
        expected=self.scratch(8)
        if not self.cas(expected,0,3):self.stop(0xd3e9ac,0x3eb325e,'3EB325E NT failed release CAS unavailable')
        self.memory.unmap(expected);del self.expected[expected]


def bind(r,pending):
    record=_RECORDS.get(r)
    if record is None:record=_Bound(r,pending);_RECORDS[r]=record
    elif record.pending is not pending:raise InputError('NT MODEL cannot adopt another pending owner')
    record.check();return record
