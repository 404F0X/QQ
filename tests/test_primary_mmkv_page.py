"""Exact cold MODEL page birth and actual producer with synthetic physical APIs."""
from pathlib import Path
import sys,unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'src')]
from test_primary_outer_init import Runtime
import test_primary_login_host_init as host_checks
from qq_nt_replica import primary_mmkv_host_init as subject
from qq_nt_replica.primary_memory import PrimaryMemory,PrimaryMemoryLimit
from qq_nt_replica.errors import InputError


class Page(unittest.TestCase):
    def test_exact_original_cold_birth_and_neighbor_gap(self):
        r=Runtime();m=r.memory;b=r.image_base;p=b+0x67513b0
        subject._validate(r)
        region,offset=m._span(p,8)
        self.assertEqual((region.address,offset,len(region.data)),(p,0,8))
        self.assertEqual(m.read(p,8),bytes(8));self.assertIn('virtual-tail',region.name)
        # The preexisting wide24 ends exactly at P; do not mistake it for a newly mapped gap.
        self.assertEqual(m._span(p-1,1)[0].address,b+0x6751398)
        for address in (p+8,p+15,p+23):
            with self.assertRaises(PrimaryMemoryLimit):m.read(address,1)
        with self.assertRaises(PrimaryMemoryLimit):m.read(p-1,2)
        for address,size in ((p,8),(p-1,2),(p+7,2)):
            with self.assertRaises(PrimaryMemoryLimit):m.map(address,bytearray(size),name='conflict',initialized=True)
        m.store(p,0xabc,8,source='controlled prior production')
        with self.assertRaises(InputError):subject.install_fresh_image(r._primary_entry_owner)
        with self.assertRaises(PrimaryMemoryLimit):r._primary_entry_owner._initialize_image()
        self.assertEqual(m.load(p,8),0xabc)

    def test_preexisting_exact_and_partial_subject_overlap_not_adopted_or_zeroed(self):
        from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
        original=PrimaryMemory.map;p=0x180000000+0x67513b0
        for shift,size in ((0,8),(7,2)):
            saved=[]
            def mapped(m,address,buffer,**kwargs):
                if address==p and not saved:
                    original(m,address+shift,b'\xa5'*size,name='preexisting warm source',initialized=True);saved.append(m)
                return original(m,address,buffer,**kwargs)
            with patch.object(PrimaryMemory,'map',mapped):
                with self.assertRaisesRegex(PrimaryMemoryLimit,'overlapping'):
                    PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/p.exe',module_path=b'C:/explicit/m.dll',stack_modules=()),initial_stack=None,primary_backend='direct')
            self.assertEqual(saved[0].read(p+shift,size),b'\xa5'*size)
        fake=SimpleNamespace(memory=PrimaryMemory(),image_base=0x180000000)
        with self.assertRaises(InputError):subject._initialize_cache(fake)

    def test_consumer_rejects_wrong_memory_base_image_bridge_owner_without_effects(self):
        for field in ('memory','image_base','_shared_locale_source','_shared_locale_source_epoch','_primary_entry_owner'):
            r=Runtime();value=getattr(r,field);m=r.memory;before=list(m.writes);epoch=r._custom_allocator_backend.source.epoch
            replacement=PrimaryMemory() if field=='memory' else (r.image_base+0x1000 if field=='image_base' else object())
            setattr(r,field,replacement)
            with self.assertRaises(InputError):subject._initialize_cache(r)
            self.assertEqual((r.calls,m.writes),([],before));self.assertIs(r._custom_allocator_backend.source.epoch,epoch)
            setattr(r,field,value);subject._validate(r)
        for replace_image in (False,True):
            r=Runtime();source=r._shared_locale_source;before=list(r.memory.writes)
            if replace_image:source.signer._shared_locale_image=object()
            else:source.epoch=object()
            with self.assertRaisesRegex(InputError,'source/epoch'):subject._initialize_cache(r)
            self.assertEqual((r.calls,r.memory.writes),([],before))

    def test_replaced_page_region_rejected_without_reset_or_allocation(self):
        r=Runtime();m=r.memory;p=r.image_base+0x67513b0
        m.unmap(p);m.map(p,(123).to_bytes(8,'little'),name='warm replacement',initialized=True)
        before=list(m.writes)
        with self.assertRaisesRegex(InputError,'backing changed'):subject._initialize_cache(r)
        self.assertEqual(m.load(p,8),123);self.assertEqual((r.calls,m.writes),([],before))

    def test_actual_factory_non4096_high_dword_and_zero_page_published_before_version(self):
        for page in (8192,65536,0x80001000,0xffffffff,0):
            seen=[]
            def observe(functions,r,calls):
                real=functions['__stdio_common_vsprintf']
                def format(*args):
                    import ctypes as C
                    if C.string_at(args[3]).startswith(b'version'):
                        self.assertEqual(r.memory.load(r.image_base+0x67513b0,8),page)
                        seen.append(r.memory.read(r.image_base+0x67513b0,8))
                    return real(*args)
                functions['__stdio_common_vsprintf']=format;return functions
            e=host_checks.AttachPhase()._scoped_native_port_case(directory={},page_size=page,stdio_transform=observe)
            r=e['runtime'];p=r.image_base+0x67513b0
            self.assertTrue(seen);self.assertEqual(seen[0],page.to_bytes(8,'little'))
            writes=[row for row in r.memory.writes if row[2]=='B994E8.publish_page_size']
            self.assertEqual(writes,[(p,page.to_bytes(8,'little'),'B994E8.publish_page_size')])
            self.assertEqual(r.memory.load(r.image_base+0x67513c8,4),2)
            stop=[x for x in r.events if x[0]=='source.unavailable'][-1]
            self.assertEqual((stop[1],stop[3:]),(0xb99200,(2,0,0,0)))
            obj=r.memory.load(r.image_base+0x674c730,8)
            self.assertEqual(r.memory.read(obj+0x90,16),bytes(16))

    def test_api_exception_produces_no_page_or_default(self):
        e=host_checks.AttachPhase()._scoped_native_port_case(failure='page_api')
        r=e['runtime']
        self.assertEqual(r.memory.load(r.image_base+0x67513b0,8),0)
        self.assertFalse([x for x in r.memory.writes if x[2]=='B994E8.publish_page_size'])
        self.assertFalse([x for x in r.events if x[0]=='1BDF22C.arguments'])
        self.assertEqual(r.memory.load(r.image_base+0x67513c8,4),1)

    def test_version_log_exception_retains_real_page_and_once_in_progress(self):
        def fail(functions,r,calls):
            def format(*args):
                self.assertEqual(r.memory.load(r.image_base+0x67513b0,8),0x80002000)
                raise RuntimeError('controlled stdio page-log failure')
            functions['__stdio_common_vsprintf']=format;return functions
        e=host_checks.AttachPhase()._scoped_native_port_case(page_size=0x80002000,stdio_transform=fail,stdio_failure=True)
        r=e['runtime']
        self.assertEqual(r.memory.load(r.image_base+0x67513b0,8),0x80002000)
        self.assertEqual(len([x for x in r.memory.writes if x[2]=='B994E8.publish_page_size']),1)
        self.assertEqual(r.memory.load(r.image_base+0x67513c8,4),1)


if __name__=='__main__':unittest.main()
