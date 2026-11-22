"""Actual ordinary source constructor/publisher through Login pair move, no native API."""
import unittest
from unittest.mock import patch
from test_primary_mmkv_file import connected


class Ordinary(unittest.TestCase):
    def test_real_config_selects_ctor_masks_timers_and_login_move_before_record(self):
        from qq_nt_replica.primary_memory import UnknownMemory,PrimaryMemoryLimit
        from qq_nt_replica.primary_logger import _String
        captures=[];stages=[]
        def instrument(functions,r,calls):
            m=r.memory;store=m.store;unmap=m.unmap
            def actual(address,value,size,**kw):
                source=kw.get('source','')
                if source=='7377C4.base_vptr' and not stages:captures.append(('stdio',len(calls)))
                result=store(address,value,size,**kw)
                if source in ('7377C4.base_vptr','737938.child_vptr','7378E8.child_vptr','7377C4.interface_vptr','72DF56.final_vptr'):stages.append((source,address,value))
                return result
            def retire(address):
                p=getattr(r,'_ordinary_msf_pending',{})
                if address==p.get('constructor_frame'):
                    captures.append(('move',tuple(bytes(m._span(address+i,24)[0].initialized[m._span(address+i,24)[1]:m._span(address+i,24)[1]+24]) for i in (0,24,48))))
                return unmap(address)
            m.store=actual;m.unmap=retire;return functions
        with connected(transform=instrument) as (e,port):
            r=e['runtime'];m=r.memory;b=r.image_base;p,c=r._ordinary_msf_pair_moved
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0x29d9e)
            self.assertEqual(r._custom_allocator_backend.records[p][1],0x380)
            self.assertEqual([m.load(p+i,8)-b for i in (0,8,0x10,0x18,0x20)],[0x3f6ded8,0x3f6dfd8,0x3f6e1c8,0x3f6e210,0x3f6e228])
            self.assertEqual([v-b for source,address,v in stages if address==p],[0x3f6ea78,0x3f6e668,0x3f6ded8])
            self.assertEqual([v-b for source,address,v in stages if address==p+0x20],[0x3f6ebe0,0x3f6eba8,0x3f6e9b8,0x3f6e228])
            self.assertEqual(captures[1],('move',(bytes([1])*24,)*3))
            self.assertEqual(_String.read(r,p+0x28).value(),b'')
            region,offset=m._span(p+0x28,24);self.assertEqual(bytes(region.initialized[offset:offset+24]),b'\1\1'+bytes(22))
            self.assertEqual(_String.read(r,p+0x298).value(),b'\0')
            self.assertEqual(m.read(p+0x298,3),b'\2\0\0')
            for offset,size in ((0x2a,22),(0x26a,6),(0x271,7),(0x29b,21),(0x2cc,20),(0x2dc,4)):
                with self.assertRaises(UnknownMemory):m.read(p+offset,size)
            for offset,table in ((0xa8,0x3fed6d8),(0x138,0x3fed6d8),(0x2f0,0x3fed718)):
                t=p+offset;self.assertEqual(m.load(t,8),b+table);self.assertEqual(m.load(t+0x28,4),0xffffffff)
                for gap,size in ((0x2c,4),(0x44,4),(0x54,4),(0x64,4),(0x69,23)):
                    with self.assertRaises(UnknownMemory):m.read(t+gap,size)
                self.assertEqual((m.load(t+0x80,8),m.load(t+0x88,8)),(b+0x2338,b+0x236a))
            self.assertEqual((m.load(p+0x40,8),m.load(p+0x48,8)),(p,c))
            self.assertEqual((m.load(c+8,4),m.load(c+0x10,4)),(1,1))
            for offset,size in ((0xc,4),(0x14,4),(0x20,8)):
                with self.assertRaises(UnknownMemory):m.read(c+offset,size)
            login=m.load(b+0x674c730,8);self.assertEqual((m.load(login+0x90,8),m.load(login+0x98,8)),(p,c))
            with self.assertRaises(PrimaryMemoryLimit):m.read(r._ordinary_msf_return_pair,16)
            self.assertEqual(m.load(m.load(p,8)+0x80,8),b+0x72ec24)
            for address in (b+0x3f6df57,b+0x3f6df60):
                with self.assertRaises(PrimaryMemoryLimit):m.read(address,1)
            self.assertEqual([x for x in r.events if x[0]=='source.unavailable'][-1][1],0x29d9e)
            self.assertEqual(captures[0][1],len(e['stdio_calls']))
            self.assertTrue(r._selector_config_history[-1]['caller_consumed'])
            with patch.object(e['owner']._threads,'prepare_close',side_effect=AssertionError('dangerous retirement')):
                with self.assertRaises(ExceptionGroup):e['owner'].close()
            self.assertFalse(r._custom_allocator_backend.closed)

    def test_publisher_partial_failures_do_not_rollback_or_run_footer(self):
        for fail in ('73CFA6.object_publish','73CFA6.control_publish','1687C.selfweak_object'):
            def instrument(functions,r,calls):
                store=r.memory.store
                def actual(address,value,size,**kw):
                    result=store(address,value,size,**kw)
                    if kw.get('source')==fail:raise RuntimeError('controlled publisher stop')
                    return result
                r.memory.store=actual;return functions
            with self.subTest(fail=fail),connected({'expected_type':RuntimeError,'expected_error':'controlled publisher stop'},transform=instrument) as (e,port):
                r=e['runtime'];m=r.memory;b=r.image_base;p=r._ordinary_msf_pending;obj=p['allocation']
                self.assertEqual(m.load(b+0x674d2c0,8),obj);self.assertEqual(m.load(b+0x674d2d0,4,signed=True),-1)
                self.assertNotIn('source.72DE38.return',[x[0] for x in r.events])
                login=m.load(b+0x674c730,8);self.assertEqual(m.read(login+0x90,16),bytes(16))
                if fail=='73CFA6.object_publish':self.assertEqual(m.load(b+0x674d2c8,8),0);self.assertEqual(p['unique'],obj)
                else:
                    self.assertEqual(m.load(b+0x674d2c8,8),p['control'])
                    if fail=='73CFA6.control_publish':self.assertEqual(p['unique'],obj)
                    else:
                        self.assertEqual(p['unique'],0);self.assertEqual(m.load(obj+0x40,8),obj)
                        self.assertEqual(m.load(obj+0x48,8),0);self.assertEqual(m.load(p['control']+8,4),1)
                self.assertEqual(m.load(p['unique_frame'],8),p['unique'])
                self.assertFalse(hasattr(r,'_ordinary_msf_pair_moved'))

    def test_footer_precedes_output_reread_and_warm_getter_only_retains(self):
        from types import SimpleNamespace
        from qq_nt_replica.primary_msf_ordinary import get_pair
        from qq_nt_replica.primary_worker_response import _frame
        from qq_nt_replica.primary_sdk import _release_owner
        marks=[]
        def instrument(functions,r,calls):
            footer=r._locale_thread_footer;store=r.memory.store
            def actual_footer(guard):
                if guard==r.image_base+0x674d2d0:marks.append(('footer',r.memory.load(r.image_base+0x674d2c0,8),r.memory.load(r.image_base+0x674d2c8,8)))
                return footer(guard)
            def actual_store(address,value,size,**kw):
                if kw.get('source')=='72DE9B.output_object':marks.append(('output',value,r.memory.load(r.image_base+0x674d2d0,4,signed=True)))
                return store(address,value,size,**kw)
            r._locale_thread_footer=actual_footer;r.memory.store=actual_store;return functions
        with connected(transform=instrument) as (e,port):
            r=e['runtime'];m=r.memory;obj,control=r._ordinary_msf_pair_moved
            self.assertEqual(marks[0],('footer',obj,control));self.assertEqual(marks[1][:2],('output',obj));self.assertNotEqual(marks[1][2],-1)
            old=len(r._custom_allocator_backend.records);counts=m.load(control+8,4)
            with e['owner']._registrar.operation(),patch('qq_nt_replica.primary_shared_locale.resolve_current_module_tls',return_value=SimpleNamespace(epoch_address=r.tls_epoch_address)):
                output,unused=_frame(r,16,'controlled warm factory output');get_pair(r,output)
                self.assertEqual(m.read(output,16),obj.to_bytes(8,'little')+control.to_bytes(8,'little'))
                self.assertEqual(m.load(control+8,4),counts+1);_release_owner(r,control);m.unmap(output)
            self.assertEqual(len(r._custom_allocator_backend.records),old);self.assertEqual(m.load(control+8,4),counts)

    def test_constructor_and_footer_failures_keep_actual_partial_ownership(self):
        from qq_nt_replica.primary_memory import UnknownMemory
        for stage in ('constructor','footer_before','footer_after'):
            def instrument(functions,r,calls):
                store=r.memory.store
                def actual(address,value,size,**kw):
                    p=getattr(r,'_ordinary_msf_pending',None)
                    footer=address==r.image_base+0x674d2d0 and kw.get('source')=='3E67EA5.guard_publish'
                    if stage=='footer_before' and footer:raise RuntimeError('controlled ordinary '+stage)
                    result=store(address,value,size,**kw)
                    if stage=='footer_after' and footer:raise RuntimeError('controlled ordinary '+stage)
                    if stage=='constructor' and p and address==p['allocation']+0x2f0 and kw.get('source')=='D30896/D30AC0.timer_vptr':raise RuntimeError('controlled ordinary '+stage)
                    return result
                r.memory.store=actual;return functions
            with self.subTest(stage=stage),connected({'expected_type':RuntimeError,'expected_error':'controlled ordinary '+stage},transform=instrument) as (e,port):
                r=e['runtime'];m=r.memory;b=r.image_base;p=r._ordinary_msf_pending
                login=m.load(b+0x674c730,8);self.assertEqual(m.read(login+0x90,16),bytes(16))
                self.assertFalse([x for x in r.events if x[0]=='source.72DE38.return'])
                if stage=='constructor':
                    self.assertEqual(m.read(b+0x674d2c0,16),bytes(16));self.assertEqual(m.load(b+0x674d2d0,4,signed=True),-1)
                    with self.assertRaises(UnknownMemory):m.read(p['allocation']+0x378,8)
                    self.assertTrue(p['base_finished']);self.assertEqual(p['phase'],'constructor')
                else:
                    self.assertEqual((m.load(b+0x674d2c0,8),m.load(b+0x674d2c8,8)),(p['allocation'],p['control']))
                    self.assertEqual((m.load(p['control']+8,4),m.load(p['control']+0x10,4)),(0,1))
                    self.assertEqual(p['phase'],'published')
                    self.assertEqual(m.load(b+0x674d2d0,4,signed=True)==-1,stage=='footer_before')
                self.assertFalse(hasattr(r,'_ordinary_msf_pair_moved'))

if __name__=='__main__':unittest.main()
