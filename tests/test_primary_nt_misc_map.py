"""Controlled source NT CAS/tree/callback/once; no actual native DLL/API."""
import unittest
from contextlib import contextmanager
from unittest.mock import patch
from test_primary_mmkv_file import connected


@contextmanager
def paused():
    def instrument(functions,r,calls):
        store=r.memory.store
        def actual(address,value,size,**kw):
            result=store(address,value,size,**kw)
            if kw.get('source')=='64E04.caller_guard_pointer':raise RuntimeError('controlled NT pause')
            return result
        r.memory.store=actual;return functions
    with connected({'expected_type':RuntimeError,'expected_error':'controlled NT pause'},transform=instrument) as (e,port):
        from qq_nt_replica.primary_nt_misc_map import bind
        with e['owner']._registrar.operation():yield e,bind(e['runtime'],e['runtime']._mmkv_caller_pending)


class NTMap(unittest.TestCase):
    def test_continuous_factory_reaches_actual_config_caller(self):
        from qq_nt_replica.primary_logger import _String
        transitions=[];prepared=[]
        def instrument(functions,r,calls):
            class Events(list):
                def append(self,item):
                    if item[0]=='source.7510F1.return':
                        h=r._nt_callback_history[-1];transitions.append(('callback',r.memory.load(h['nt_pair'][1]+8,4)))
                    super().append(item)
            r.events=Events(r.events);store=r.memory.store
            def actual(address,value,size,**kw):
                if kw.get('source')=='7507C9.new_NT_object':transitions.append(('config',r.memory.load(r._selector_config_pending['nt_pair'][1]+8,4)))
                if kw.get('source')=='65274.NT_guard_publish':
                    p=r._selector_config_pending;m=r.memory;region,off=m._span(p['key'],24)
                    prepared.append((m.read(p['output'],24),bytes(region.initialized[off:off+24]),_String.read(r,p['key']).value(),m.load(p['key'],1),_String.read(r,p['identifier']).get(0,8),_String.read(r,p['identifier']).value(),_String.read(r,p['identifier']).get(16,8)))
                return store(address,value,size,**kw)
            r.memory.store=actual;return functions
        with connected(transform=instrument) as (e,port):
            r=e['runtime'];m=r.memory;p=r._selector_config_history[-1];h=r._nt_callback_history[-1];b=r._nt_misc_record
            self.assertEqual(transitions,[('callback',0),('config',1)])
            self.assertTrue(h['method_finished']);self.assertTrue(h['callback_finished']);self.assertTrue(h['once_finished'])
            self.assertIsNone(r._mmkv_caller_pending);self.assertEqual(m.load(r.image_base+0x674d418,8),(1<<64)-1)
            self.assertIsNone(r._selector_config_pending);self.assertTrue(p['caller_consumed']);self.assertEqual(p['target'],r.image_base+0x65240)
            self.assertEqual(prepared[0][:6],(bytes(24),bytes([1])*15+bytes(9),b'107775_switch',0x1a,0x21,b'nt_mmkv_msf_united_config'))
            self.assertEqual(p['nt_pair'],h['nt_pair']);self.assertEqual(m.load(h['lock'],8),0)
            node=m.load(b.tree+8,8);self.assertEqual(m.load(node+0x38,8),h['raw'])
            self.assertNotEqual(prepared[0][6],m.load(node+0x30,8));self.assertEqual(h['released_guard_value'],h['lock'])
            self.assertEqual([(x[0],x[4]) for x in b.operations],[(2,True),(3,True)])
            self.assertEqual(b.expected,{})
            from qq_nt_replica.primary_memory import PrimaryMemoryLimit
            for operation in b.operations:
                with self.assertRaises(PrimaryMemoryLimit):m.read(operation[5],8)
            self.assertNotEqual(m.load(r.image_base+0x674d424,4,signed=True),-1)
            obj=m.load(r.image_base+0x674c730,8);self.assertEqual((m.load(obj+0x90,8),m.load(obj+0x98,8)),r._ordinary_msf_pair_moved)
            self.assertEqual(r.events[-1][1],0x72ec24)
            events=[x[1] for x in r.events if x[0]=='source.NT_normal_dtor'];self.assertEqual(events,[0x64e2f,0x64e38,0x64e41,0x64e4a])

    def test_cas_full64_success_and_real_expected_failure(self):
        with paused() as (e,b):
            m=e['runtime'].memory;big=0x80000000fedcba98;expected=b.scratch(0)
            self.assertTrue(b.cas(expected,big,2));self.assertEqual(m.load(expected,8),0)
            wrong=b.scratch(7);before=len(m.writes);self.assertFalse(b.cas(wrong,0,3))
            self.assertEqual(m.load(wrong,8),big);self.assertEqual(b.read(),big)
            self.assertEqual([w[0] for w in m.writes[before:]],[wrong])
            good=b.scratch(big);self.assertTrue(b.cas(good,0,3));self.assertEqual(m.load(good,8),big)

    def test_acquire_cas_can_fail_after_initial_load_without_retry_or_unlock(self):
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with paused() as (e,b):
            read=b.read;done=[]
            def actual_read():
                value=read()
                if not done:
                    done.append(True);other=b.scratch(value);self.assertTrue(b.cas(other,8,2))
                return value
            with patch.object(b,'read',side_effect=actual_read):
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'failed acquire CAS'):b.acquire()
            failed=b.operations[-1];self.assertFalse(failed[4]);self.assertEqual(e['runtime'].memory.load(failed[5],8),8)
            self.assertEqual(read(),8);self.assertEqual(b.pending['nt_boundary'],0xd3ded1)
            self.assertEqual(e['runtime'].memory.load(b.tree+8,8),0)

    def test_release_cas_failure_retains_guard_and_actual_observed_state(self):
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with paused() as (e,b):
            b.acquire();read=b.read;done=[]
            def actual_read():
                state=read()
                if not done:
                    done.append(True);expected=b.scratch(8);self.assertTrue(b.cas(expected,9,2))
                return state
            with patch.object(b,'read',side_effect=actual_read):
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'failed release CAS'):b.release()
            self.assertEqual(read(),9);self.assertEqual(e['runtime'].memory.load(b.operations[-1][5],8),9)
            self.assertEqual(e['runtime'].memory.load(b.pending['guard'],8),b.cell)

    def test_cas_rejects_epoch_owner_memory_and_region_replacement_without_writes(self):
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_memory import PrimaryMemory
        with paused() as (e,b):
            r=e['runtime'];m=r.memory;expected=b.scratch(0)
            cases=((r,'memory',PrimaryMemory()),(r,'image_base',r.image_base+0x1000),(r,'_shared_locale_source',object()),(r,'_shared_locale_source_epoch',object()),(b.image,'epoch',object()),(b.module,'epoch',object()),(r,'_primary_allocator_selector_epoch',object()),(b.port,'_WindowsMMKVHost__owner',object()),(b.allocator.source,'epoch',object()))
            for obj,name,value in cases:
                before=len(m.writes)
                with self.subTest(name=name),patch.object(obj,name,value):
                    with self.assertRaises(InputError):b.cas(expected,8,2)
                self.assertEqual(len(m.writes),before);self.assertEqual(b.read(),0)
            region,offset=m._span(expected,8);index=next(i for i,x in enumerate(m._regions) if x is region)
            other=type(region)(region.address,memoryview(bytearray(region.data)),bytearray(region.initialized),region.name)
            try:
                m._regions[index]=other
                with self.assertRaises(InputError):b.cas(expected,8,2)
            finally:m._regions[index]=region;other.data.release()
            for address in (b.obj,b.control,expected):
                region,offset=m._span(address,8);old=region.data;replacement=memoryview(bytearray(old));before=len(m.writes)
                try:
                    region.data=replacement
                    with self.assertRaises(InputError):b.cas(expected,8,2)
                    self.assertEqual(len(m.writes),before)
                finally:region.data=old;replacement.release()

    def test_nt64_node_publication_padding_guard_and_noncold_comparator(self):
        from qq_nt_replica.primary_memory import UnknownMemory
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with paused() as (e,b):
            r=e['runtime'];m=r.memory;b.acquire();snap=[];store=m.store
            def observe(address,value,size,**kw):
                result=store(address,value,size,**kw)
                if kw.get('source')=='431D.begin_publish':
                    node=b.pending['nt_node'];self.assertEqual(m.load(b.tree+8,8),node);self.assertEqual(m.load(b.tree,8),node)
                    self.assertEqual(m.load(b.tree+16,8),0)
                    with self.assertRaises(UnknownMemory):m.read(node+0x18,1)
                    snap.append(node)
                return result
            with patch.object(m,'store',side_effect=observe):slot=b.publish(b.pending['locals'],0)
            node=snap[0];self.assertEqual(b.allocator.records[node][1],64)
            self.assertEqual(m.read(node,16),bytes(16));self.assertEqual(m.load(node+0x10,8),b.tree+8)
            self.assertEqual(m.load(node+0x18,1),1)
            with self.assertRaises(UnknownMemory):m.read(node+0x19,7)
            self.assertEqual(m.load(node+0x20,8),0x21);self.assertEqual(m.load(slot,8),0)
            self.assertTrue([w for w in m.writes if w[0]==slot and w[2]=='64E1F.raw_MMkv_publish' and w[1]==bytes(8)])
            self.assertEqual(m.load(b.tree+16,8),1);b.release();self.assertEqual(m.load(b.pending['guard'],8),b.cell)
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'4075'):b.slot(b.pending['locals'])
            self.assertEqual(b.pending['nt_compare_args'],(b.pending['locals'],node+0x20));self.assertEqual(m.load(slot,8),0)

    def test_config_consumes_actual_new_virtual_slot(self):
        reads=[]
        def instrument(functions,r,calls):
            load=r.memory.load
            def actual(address,size,**kw):
                value=load(address,size,**kw)
                if address==r.image_base+0x3ec6530 and hasattr(r,'_selector_config_pending'):
                    self.assertIn('nt_pair',r._selector_config_pending);reads.append((address,value))
                return value
            r.memory.load=actual;return functions
        with connected(transform=instrument) as (e,port):
            r=e['runtime'];self.assertEqual(reads,[(r.image_base+0x3ec6530,r.image_base+0x65240)])
            self.assertTrue([x for x in r.events if x[0]=='source.65240.return']);self.assertTrue(r._selector_config_history[-1]['caller_consumed'])
            self.assertEqual(r.events[-1][1],0x72ec24)

    def test_once_tail_failures_preserve_consumed_callback_and_flag(self):
        for operation,flag in (('AcquireSRWLockExclusive',1),('ReleaseSRWLockExclusive',(1<<64)-1),('WakeAllConditionVariable',(1<<64)-1)):
            calls=[]
            def instrument(functions,r,stdio):
                class Events(list):
                    def append(self,item):
                        if item[0]=='source.7510F1.return':
                            from qq_nt_replica.primary_module_sync import _resource
                            port=_resource(r).port
                            def api(name,pointer):
                                calls.append(name)
                                if name==operation:raise RuntimeError('controlled once tail '+operation)
                            port._api=api
                        super().append(item)
                r.events=Events(r.events);return functions
            with self.subTest(operation=operation),connected({'expected_type':RuntimeError,'expected_error':'controlled once tail'},transform=instrument) as (e,port):
                r=e['runtime'];h=r._nt_callback_history[-1]
                self.assertTrue(h['callback_finished']);self.assertNotIn('once_finished',h)
                self.assertIsNone(r._mmkv_caller_pending);self.assertEqual(r.memory.load(r.image_base+0x674d418,8),flag)
                self.assertEqual(r._selector_once_failure[1],flag);self.assertFalse(hasattr(r,'_selector_config_pending'))
                self.assertEqual(calls[-1],operation)
                with patch.object(e['owner']._threads,'prepare_close',side_effect=AssertionError('dangerous retire')):
                    with self.assertRaises(ExceptionGroup):e['owner'].close()
                self.assertFalse(r._custom_allocator_backend.closed)

    def test_suspended_or_missing_execution_lease_rejects_without_cell_effect(self):
        from qq_nt_replica.errors import InputError
        with paused() as (e,b):
            expected=b.scratch(0);before=len(e['runtime'].memory.writes)
            with e['owner']._registrar.current_lease().suspend():
                with self.assertRaises(InputError):b.cas(expected,8,2)
            self.assertEqual(len(e['runtime'].memory.writes),before);self.assertEqual(b.read(),0)

    def test_changed_actual_root_stops_before_color_count_or_unlock(self):
        from qq_nt_replica.primary_memory import UnknownMemory
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with paused() as (e,b):
            b.acquire();m=e['runtime'].memory;store=m.store
            def changed(address,value,size,**kw):
                result=store(address,value,size,**kw)
                if kw.get('source')=='431D.begin_publish':store(b.tree+8,0,8,source='controlled root change before balance')
                return result
            with patch.object(m,'store',side_effect=changed):
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'nonroot NT balancing'):b.slot(b.pending['locals'])
            node=b.pending['nt_node'];self.assertEqual(m.load(b.tree,8),node);self.assertEqual(m.load(b.tree+16,8),0)
            with self.assertRaises(UnknownMemory):m.read(node+0x18,1)
            self.assertEqual(m.load(b.pending['nt_node_guard'],8),node);self.assertEqual(b.read(),8)

if __name__=='__main__':unittest.main()
