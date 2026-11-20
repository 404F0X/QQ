import hashlib
import unittest
import struct
import threading
from unittest.mock import patch
from signature_core import load_core

class PendingOwnerAllocatorChecks(unittest.TestCase):
    def test_existing_model_bootstrap_and_upper_roundtrip(self):
        core=load_core()
        try:
            with core.activate():
                from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
                from qq_nt_replica.primary_notification_files import FileSelectorMaterial
                from qq_nt_replica.primary_custom_allocator import install_model_allocator,dispose_model_allocator,CustomDomainUnsupported
                from qq_nt_replica.primary_worker_consumer import _invoke
                signer=PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/m.exe',module_path=b'C:/explicit/m.dll',stack_modules=()),initial_stack=None,primary_backend='direct')
                runtime=signer.runtime
                raw=b'explicit-model-custom\0';pointer=0x7600000000;initial=bytes(2)
                material=FileSelectorMaterial(initial,pointer,raw,'synthetic-test-input','explicit-model',hashlib.sha256(initial+pointer.to_bytes(8,'little')+raw).hexdigest())
                install_model_allocator(runtime,material,supplier=signer.addresses.allocation)
                from qq_nt_replica import primary_pending_reports as pending
                from qq_nt_replica.primary_logger import _String
                from qq_nt_replica.errors import InputError
                from qq_nt_replica.primary_memory import UnknownMemory
                memory=runtime.memory
                lower_registry=runtime.allocations
                lower_contents=dict(lower_registry)
                def unchanged_lower():
                    self.assertIs(runtime.allocations,lower_registry)
                    self.assertEqual(runtime.allocations,lower_contents)
                def scratch(size):
                    address=signer.addresses.allocation(size,False)[2]
                    memory.map(address,bytearray(size),name='explicit model fixture',initialized=False)
                    return address
                address=scratch(40);memory.write(address,bytes(32)+struct.pack('<f',1.0)+bytes(4),source='explicit model header')
                pair=scratch(40);out=scratch(24)
                nodes={}
                for key in (1,3,5,9,17,2):
                    memory.store(pair,key,8,source='explicit key')
                    _String.construct(runtime,b'model').write_to(pair+8)
                    memory.store(pair+32,0,1,source='explicit mode')
                    pending.insert(runtime,address,out,pair,pair)
                    nodes[key]=memory.load(out,8)
                    self.assertEqual(memory.load(out+8,1),1)
                    self.assertEqual(memory.read(pair+8,24),bytes(24))
                    with self.assertRaises(UnknownMemory):memory.read(nodes[key]+49,1)
                unchanged_lower()
                memory.store(pair,1,8,source='duplicate key')
                before=set(runtime._custom_allocator_backend.records)
                pending.insert(runtime,address,out,pair,pair)
                self.assertEqual(memory.load(out+8,1),0)
                self.assertEqual(set(runtime._custom_allocator_backend.records),before)
                def links():
                    count=memory.load(address+8,8);buckets=memory.load(address,8);node=memory.load(address+16,8);seen=[];pred=address+16;first={}
                    while node:
                        self.assertNotIn(node,seen);seen.append(node)
                        bucket=pending._index(memory.load(node+8,8),count)
                        first.setdefault(bucket,pred)
                        pred,node=node,memory.load(node,8)
                    self.assertEqual(set(seen),set(nodes.values()))
                    for bucket in range(count):self.assertEqual(memory.load(buckets+8*bucket,8),first.get(bucket,0))
                for requested,expected in ((16,16),(9,11),(2,7),(7,7)):
                    pending.rehash(runtime,address,requested)
                    self.assertEqual(memory.load(address+8,8),expected);links()
                # Explicit container input includes a contiguous equal-key run.
                ordered=[];cursor=memory.load(address+16,8)
                while cursor:ordered.append(cursor);cursor=memory.load(cursor,8)
                for node,key in zip(ordered,(1,2,3,3,4,1)):
                    memory.store(node+8,key,8,source='explicit collision hash')
                    memory.store(node+16,key,8,source='explicit collision key')
                pending._rehash(runtime,address,2)
                actual=[];cursor=memory.load(address+16,8)
                while cursor:actual.append(cursor);cursor=memory.load(cursor,8)
                self.assertEqual(actual,[ordered[n] for n in (5,2,3,0,1,4)])
                for key,node in nodes.items():
                    memory.store(node+8,key,8,source='explicit restore hash')
                    memory.store(node+16,key,8,source='explicit restore key')
                pending._rehash(runtime,address,16);links()
                unchanged_lower()
                # The old free observes published pointer, but old count and unknown new cells.
                old_count=memory.load(address+8,8);old=memory.load(address,8);original=pending._invoke
                def fail_free(rt,rva,*args):
                    if rva==0xB75029 and args==(old,):
                        self.assertNotEqual(memory.load(address,8),old)
                        self.assertEqual(memory.load(address+8,8),old_count)
                        with self.assertRaises(UnknownMemory):memory.read(memory.load(address,8),8)
                        raise RuntimeError('explicit oldfree failure')
                    return original(rt,rva,*args)
                with patch.object(pending,'_invoke',side_effect=fail_free):
                    with self.assertRaises(RuntimeError):pending.rehash(runtime,address,32)
                # Deliberately no rollback guarantee. Release new block, restore fixture header to resume.
                orphan=memory.load(address,8);_invoke(runtime,0xB75029,orphan)
                memory.store(address,old,8,source='explicit test resume after observed failure')
                for key in list(nodes):
                    memory.store(pair,key,8,source='erase key');self.assertEqual(pending.erase(runtime,address,pair),1);nodes.pop(key)
                    links()
                self.assertEqual(pending.erase(runtime,address,pair),0)
                pending.rehash(runtime,address,0)
                self.assertEqual(memory.read(address,16),bytes(16))
                self.assertFalse(runtime._custom_allocator_backend.records)
                unchanged_lower()
                # Heap String move/extract retains payload ownership until explicit destroy.
                memory.store(pair,77,8,source='heap key')
                _String.construct(runtime,b'x'*40).write_to(pair+8)
                memory.store(pair+32,0,1,source='heap mode')
                payload=memory.load(pair+24,8)
                pending.insert(runtime,address,out,pair,pair)
                node=memory.load(out,8);self.assertIn(payload,runtime._custom_allocator_backend.records)
                freed=len(runtime._custom_allocator_backend.storage.source_free_seen)
                pending.extract(runtime,address,out,node)
                self.assertEqual(len(runtime._custom_allocator_backend.storage.source_free_seen),freed)
                _String.read(runtime,node+24).destroy();_invoke(runtime,0xB75029,node)
                memory.store(pair,78,8,source='heap erase key');_String.construct(runtime,b'y'*40).write_to(pair+8)
                pending.insert(runtime,address,out,pair,pair)
                before_free=len(runtime._custom_allocator_backend.storage.source_free_seen)
                pending.erase(runtime,address,pair)
                sizes=[record[1] for record in runtime._custom_allocator_backend.storage.source_free_seen[before_free:]]
                self.assertEqual(sizes,[48,56])
                # An extraction handle with ownership false must still release its node.
                memory.store(pair,88,8,source='unowned key');_String.construct(runtime,b'sso').write_to(pair+8)
                pending.insert(runtime,address,out,pair,pair);node=memory.load(out,8)
                actual_extract=pending.extract
                def unowned(rt,table,handle,current):
                    result=actual_extract(rt,table,handle,current)
                    rt.memory.store(handle+16,0,1,source='explicit unowned handle observation')
                    return result
                with patch.object(pending,'extract',side_effect=unowned):self.assertEqual(pending.erase(runtime,address,pair),1)
                self.assertNotIn(node,runtime._custom_allocator_backend.records)
                pending.rehash(runtime,address,0)
                unchanged_lower()
                allocated=_invoke(runtime,0xB75000,56)
                self.assertIn(allocated,runtime._custom_allocator_backend.records)
                errors=[]
                def foreign():
                    try:_invoke(runtime,0xB75029,allocated)
                    except (InputError,CustomDomainUnsupported):errors.append(True)
                worker=threading.Thread(target=foreign);worker.start();worker.join(2)
                self.assertFalse(worker.is_alive());self.assertEqual(errors,[True])
                with self.assertRaises((InputError,CustomDomainUnsupported)):_invoke(runtime,0xB75029,pair)
                _invoke(runtime,0xB75029,allocated)
                with self.assertRaises((InputError,CustomDomainUnsupported)):_invoke(runtime,0xB75029,allocated)
                self.assertNotIn(allocated,runtime._custom_allocator_backend.records)
                # Explicit source-known container helper input, not a registrar/callback proof.
                from qq_nt_replica.primary_telemetry_exit import destroy_telemetry
                owner=runtime.image_base+0x67519B8
                for region in memory._regions:
                    lo=max(owner,region.address);hi=min(owner+0x100,region.address+len(region.data))
                    if hi>lo:memory.write(lo,bytes(hi-lo),source='explicit model telemetry owner')
                memory.write(owner+200,bytes(32)+struct.pack('<f',1.0)+bytes(4),source='explicit owner pending header')
                memory.store(pair,99,8,source='owner pending key');_String.construct(runtime,b'owner').write_to(pair+8)
                pending.insert(runtime,owner+200,out,pair,pair)
                owner_node=memory.load(out,8);owner_bucket=memory.load(owner+200,8)
                destroy_telemetry(runtime)
                unchanged_lower()
                self.assertNotIn(owner_node,runtime._custom_allocator_backend.records)
                self.assertNotIn(owner_bucket,runtime._custom_allocator_backend.records)
                retained=_invoke(runtime,0xB75000,33)
                before_free=len(runtime._custom_allocator_backend.storage.source_free_seen)
                dispose_model_allocator(runtime)
                self.assertEqual(len(runtime._custom_allocator_backend.storage.storage_disposed),1)
                self.assertEqual(len(runtime._custom_allocator_backend.storage.source_free_seen),before_free)
        finally:core.close()


    def test_stale_epoch_is_terminal_on_independent_runtime(self):
        core=load_core()
        try:
            with core.activate():
                from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
                from qq_nt_replica.primary_notification_files import FileSelectorMaterial
                from qq_nt_replica.primary_custom_allocator import install_model_allocator,dispose_model_allocator,CustomDomainUnsupported
                from qq_nt_replica.primary_worker_consumer import _invoke
                signer=PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/m.exe',module_path=b'C:/explicit/m.dll',stack_modules=()),initial_stack=None,primary_backend='direct')
                runtime=signer.runtime
                raw=b'explicit-model-custom\0';pointer=0x7600000000;initial=bytes(2)
                material=FileSelectorMaterial(initial,pointer,raw,'synthetic-test-input','explicit-model',hashlib.sha256(initial+pointer.to_bytes(8,'little')+raw).hexdigest())
                install_model_allocator(runtime,material,supplier=signer.addresses.allocation)
                allocated=_invoke(runtime,0xB75000,56)
                runtime._primary_allocator_selector.epoch=object()
                from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
                from qq_nt_replica.errors import InputError
                with self.assertRaises((InputError,PrimarySemanticUnavailable)):_invoke(runtime,0xB75029,allocated)
                self.assertEqual(runtime._primary_allocator_selector.phase,'poisoned')
                self.assertIn(allocated,runtime._custom_allocator_backend.records)
                self.assertEqual(runtime._custom_allocator_backend.storage.source_free_seen,[])
                # A poisoned source is intentionally not resumed or disposed as source-free.
        finally:core.close()

if __name__=='__main__':unittest.main()
