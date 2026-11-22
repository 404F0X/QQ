"""Connected factory prefix stops before first loader and retains early close debt."""
import unittest
from unittest.mock import patch
from test_primary_mmkv_file import connected


class OpenChecks(unittest.TestCase):
    def test_actual_prefix_parent_fields_paths_hooks_and_no_publication(self):
        from qq_nt_replica.primary_memory import UnknownMemory
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;session=port._WindowsMMKVHost__open;p=session['parent']
            self.assertEqual(session['global_lock'],'held');self.assertEqual(session['boundary'],0x1bd99a0)
            for off,size in ((0x8a,2),(0xc9,3),(0xd2,6)):
                with self.assertRaises(UnknownMemory):m.read(p+off,size)
            self.assertEqual(m.load(p+0xd1,1),1)
            self.assertEqual(m.read(p,24),bytes(24))
            paths=[x.pointer for x in session['paths']]+[x.path.pointer for x in session['files']]
            self.assertEqual(len(set(paths)),4)
            self.assertTrue(session['paths'][1].raw.endswith(b'.\0c\0r\0c\0\0\0'))
            self.assertEqual(r._primary_allocator_selector.phase,'complete')
            self.assertTrue(r._custom_allocator_backend.storage.hooks.complete)
            self.assertEqual(m.load(m.load(r.image_base+0x6751388,8)+8,8),0)
            obj=m.load(r.image_base+0x674c730,8);self.assertEqual(m.read(obj+0x90,16),bytes(16))

    def test_close_rejects_before_guest_creator_bridge_retirement(self):
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with connected() as (e,port):
            owner=e['owner'];before=list(e['file_api'].calls)
            with patch.object(owner._threads,'prepare_close',side_effect=AssertionError('dangerous retirement')):
                with self.assertRaises(ExceptionGroup):owner.close()
            self.assertEqual(e['file_api'].calls,before)
            self.assertFalse(owner._signer.runtime._custom_allocator_backend.closed)

    def test_two_real_conversions_temp_array_mode0_and_growth_receipts(self):
        with connected() as (e,port):
            r=e['runtime'];calls=[args for name,args in e['file_api'].calls if name=='MultiByteToWideChar']
            self.assertEqual(len(calls),4)
            self.assertEqual([args[5] for args in calls],[0,26,0,26])
            temps=[record for record in r._custom_allocator_backend.storage.source_free_seen if record[4]==0xb758c4]
            self.assertEqual(len(temps),2)
            self.assertEqual([(record[1],record[5]) for record in temps],[(52,0),(52,0)])
            self.assertTrue([x for x in r.memory.writes if x[2]=='75D130.publish_after_old_free'])
            entries=[x for x in r.events if x[0]=='source.mmkv_open']
            self.assertEqual((entries[-1][1],entries[-1][3:]),(0xb99200,(2,0,0,0)))

    def test_real_hash_precedes_real_cold_bucket_count(self):
        trace=[]
        def observe(functions,r,calls):
            invoke=r.invoke;load=r.memory.load
            def actual_invoke(vm,rva,cells):
                if rva==0x3c77e:trace.append('hash')
                return invoke(vm,rva,cells)
            def actual_load(address,width,**kwargs):
                cache=load(r.image_base+0x6751388,8)
                if cache and address==cache+8:trace.append('count')
                return load(address,width,**kwargs)
            r.invoke=actual_invoke;r.memory.load=actual_load
            return functions
        with connected(transform=observe) as (e,port):
            self.assertLess(trace.index('hash'),trace.index('count'))
            r=e['runtime'];session=port._WindowsMMKVHost__open
            self.assertEqual(r.memory.load(session['global_guard'],8),r.memory.load(r.image_base+0x6751390,8))


if __name__=='__main__':unittest.main()
