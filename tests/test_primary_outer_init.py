"""Controlled source-memory/ABI; no Windows source operation or SDK execution."""
from pathlib import Path
import sys,os,threading,ctypes as C
from types import SimpleNamespace
from unittest.mock import patch
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from qq_nt_replica.primary_memory import PrimaryMemory,UnknownMemory,PrimaryMemoryLimit
from qq_nt_replica.primary_outer_init import get_login_service,_global_sync
from qq_nt_replica.primary_windows_signer import WindowsSigner
from qq_nt_replica.primary_sign import PrimaryRuntime
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_windows_outer_sync import bind_outer_sync,WindowsOuterSync

class Runtime:
    image_base=0x180000000
    _thread_header=PrimaryRuntime._thread_header
    _thread_footer=PrimaryRuntime._thread_footer
    def __new__(cls):
        # Use the original cold installer and its bound fixed-image epoch.
        from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
        signer=PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/p.exe',module_path=b'C:/explicit/m.dll',stack_modules=()),initial_stack=None,primary_backend='direct')
        r=signer.runtime;r.calls=[];r.events=[];r.next=0x7100000000;r.fail_size=None
        from qq_nt_replica.primary_custom_allocator import _CustomBackend
        r.epoch=object();r._custom_allocator_backend=_CustomBackend.__new__(_CustomBackend)
        r._custom_allocator_backend.records={};r._custom_allocator_backend.closed=False
        r._custom_allocator_backend.source=SimpleNamespace(epoch=r.epoch,validate=lambda runtime:None)
        r.invoke=cls.invoke.__get__(r,type(r))
        return r
    def invoke(self,vm,rva,cells):
        args=tuple(vm.cells.value(i) for i in cells);self.calls.append((rva,args))
        if rva in (0x75cec0,0x75b810):return PrimaryRuntime.invoke(self,vm,rva,cells)
        if rva==0x6270:
            for offset in (0,8,16):self.memory.store(args[0]+offset,0,8,source='6270.three_QWORD_zero')
            return 3
        if rva==0xB75029:
            pointer=args[0];record=self._custom_allocator_backend.records[pointer]
            self.memory._assert_no_native_pin(pointer,record[1]);self.memory.unmap(pointer)
            del self._custom_allocator_backend.records[pointer];return
        if rva!=0xB75000:raise AssertionError('unexpected unsupported source call '+hex(rva))
        size=args[0]
        if size==self.fail_size:raise PrimarySemanticUnavailable('controlled source allocation unavailable')
        pointer=self.next;self.next+=0x1000
        self.memory.map(pointer,bytearray(size),name='controlled upper allocation',initialized=False)
        region,offset=self.memory._span(pointer,size)
        self._custom_allocator_backend.records[pointer]=(region,size,self.epoch,threading.get_ident(),'CUSTOM')
        return pointer

class Birth(unittest.TestCase):
    cells=((0x6745268,8),(0x6745280,8),(0x67451d4,1))

    def test_original_cold_exact_regions_gaps_and_no_adoption_reset(self):
        from qq_nt_replica.primary_login_model_attach import validate_birth,install_fresh_image
        r=Runtime();m=r.memory;b=r.image_base
        validate_birth(r)
        for rva,size in self.cells:
            region,offset=m._span(b+rva,size)
            self.assertEqual((region.address,offset,len(region.data)),(b+rva,0,size))
            self.assertEqual(m.read(b+rva,size),bytes(size))
            self.assertIn('raw-backed 00' if size==1 else 'virtual-tail',region.name)
            for address,length in ((b+rva,size),(b+rva-1,2),(b+rva+size-1,2)):
                with self.assertRaises(PrimaryMemoryLimit):m.map(address,bytearray(length),name='conflict',initialized=True)
            for address in (b+rva-1,b+rva+size):
                with self.assertRaises(PrimaryMemoryLimit):m.read(address,1)
        m.store(b+0x6745268,0x1234,8,source='controlled warm publication')
        with self.assertRaises(InputError):install_fresh_image(r._primary_entry_owner)
        with self.assertRaises(PrimaryMemoryLimit):r._primary_entry_owner._initialize_image()
        self.assertEqual(_global_sync(r),0x1234)
        self.assertEqual(m.load(b+0x6745280,8),0)
        # An independently assembled memory cannot adopt mapped warm/cold cells.
        other=SimpleNamespace(memory=PrimaryMemory(),image_base=b)
        for rva,size in self.cells:other.memory.map(b+rva,bytearray(size),name='adopted',initialized=True)
        with self.assertRaises(InputError):_global_sync(other)

    def test_consumer_rejects_replaced_region_memory_base_or_fixed_image_epoch(self):
        from qq_nt_replica.primary_login_model_attach import validate_birth
        for rva,size in self.cells:
            r=Runtime();m=r.memory;address=r.image_base+rva
            m.unmap(address);m.map(address,bytearray(size),name='replacement',initialized=True)
            before=(list(r.calls),list(m.writes))
            with self.assertRaisesRegex(InputError,'backing changed'):_global_sync(r)
            self.assertEqual((r.calls,m.writes),before)
        for field,value in (('memory',PrimaryMemory()),('image_base',0x190000000),('_shared_locale_source_epoch',object()),('_shared_locale_source',object())):
            r=Runtime();old=getattr(r,field);allocator_epoch=r._custom_allocator_backend.source.epoch
            setattr(r,field,value)
            with self.assertRaises(InputError):_global_sync(r)
            self.assertEqual(r.calls,[])
            self.assertIs(r._custom_allocator_backend.source.epoch,allocator_epoch)
            setattr(r,field,old);validate_birth(r)
        r=Runtime();r._shared_locale_source.epoch=object()
        with self.assertRaisesRegex(InputError,'fixed image epoch'):_global_sync(r)

    def test_original_installer_rejects_preexisting_full_and_partial_subject_overlap(self):
        from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
        original=PrimaryMemory.map
        for rva,size in self.cells:
            for shift,length in ((0,size),(-1,2),(size-1,2)):
                inserted=[]
                def mapped(m,address,buffer,**kwargs):
                    if address==0x180000000+rva and not inserted:
                        original(m,address+shift,bytearray(length),name='preexisting owned cell',initialized=True)
                        inserted.append(m)
                    return original(m,address,buffer,**kwargs)
                with patch.object(PrimaryMemory,'map',mapped):
                    with self.assertRaisesRegex(PrimaryMemoryLimit,'overlapping'):
                        PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/p.exe',module_path=b'C:/explicit/m.dll',stack_modules=()),initial_stack=None,primary_backend='direct')
                self.assertEqual(len(inserted),1)

class Prefix(unittest.TestCase):
    def owner(self):
        owner=WindowsSigner.__new__(WindowsSigner);owner._state='open';owner._busy=False
        owner._pid=os.getpid();owner._thread=threading.get_native_id();owner._signer=SimpleNamespace(runtime=Runtime())
        return owner
    def config(self):return dict(commonPath='C:\\data',clientVer='v',machineId='machine',platVer='p',hostName='h',externalVersion=False)
    def tls(self,runtime):
        # Explicit test-only TLS observation boundary, never a genuine receipt claim.
        return patch('qq_nt_replica.primary_shared_locale.resolve_current_module_tls',return_value=SimpleNamespace(epoch_address=runtime.tls_epoch_address,image_epoch=runtime._shared_locale_source_epoch))
    def run_config(self,owner,service,value):
        # Keep these existing CS/setup checks at their controlled next-port boundary.
        with self.tls(owner.signer.runtime),patch('qq_nt_replica.primary_login_host_init.publish_hostname',side_effect=PrimarySemanticUnavailable('controlled hostname publication boundary')):
            return service.initConfig(value)
    def test_real_owner_control_selfweak_and_local_release(self):
        owner=self.owner();r=owner.signer.runtime
        with self.tls(r):service=get_login_service(owner);other=get_login_service(owner)
        self.assertIsNot(service,other)
        obj=r.memory.load(r.image_base+0x674c730,8);control=r.memory.load(r.image_base+0x674c738,8)
        self.assertEqual(obj,control+0x18)
        for offset in (0x0c,0x14):
            with self.assertRaises(UnknownMemory):r.memory.read(control+offset,4)
        self.assertEqual(r.memory.load(obj+0x48,8),obj);self.assertEqual(r.memory.load(obj+0x50,8),control)
        self.assertEqual(r.memory.load(control+8,4),2);self.assertEqual(r.memory.load(control+0x10,4),1)
        self.assertEqual(r.memory.load(obj+0x68,8),obj+0x70)
        self.assertEqual(sum(args==(0x320,) for call,args in r.calls if call==0xB75000),1)
        service.release_wrappers();self.assertEqual(r.memory.load(control+8,4),1)
        other.release_wrappers();self.assertEqual(r.memory.load(control+8,4),0)
        self.assertIn(control,r._custom_allocator_backend.records)
    def test_exact_publish_order_and_missing_port_retains_prefix(self):
        owner=self.owner();r=owner.signer.runtime
        with self.tls(r):service=get_login_service(owner)
        start=len(r.memory.writes)
        with self.assertRaisesRegex(PrimarySemanticUnavailable,'InitializeCriticalSectionEx'):self.run_config(owner,service,self.config())
        pointer=r.memory.load(r.image_base+0x6745268,8)
        events=r.memory.writes[start:]
        global_events=[row for row in events if row[2].startswith('5C6E10.')]
        addresses=[row[0] for row in global_events]
        self.assertEqual(addresses[:6],[pointer+0x28,pointer+0x18,pointer+8,pointer+0x38,r.image_base+0x6745268,pointer+0x40])
        with self.assertRaises(UnknownMemory):r.memory.read(pointer+0x48,8)
        with self.assertRaises(UnknownMemory):r.memory.read(pointer,8)
        self.assertEqual(service.state,'UNAVAILABLE')
        before=list(r.calls)
        with self.assertRaises(PrimarySemanticUnavailable):self.run_config(owner,service,self.config())
        self.assertEqual(before,r.calls)
        for operation in (lambda:owner.sign(b'cmd',b'data'),owner.request_device_refresh_async,owner.pump_device_request,owner.drain):
            with self.assertRaises(PrimarySemanticUnavailable):operation()
        service.release_wrappers()
    def test_temporary_allocation_failure_poisoned_before_global(self):
        owner=self.owner();r=owner.signer.runtime
        with self.tls(r):service=get_login_service(owner)
        config=self.config();config['clientVer']='v'*40;r.fail_size=48
        with self.assertRaises(PrimarySemanticUnavailable):self.run_config(owner,service,config)
        self.assertEqual(service.state,'UNAVAILABLE')
        self.assertEqual(r.memory.load(r.image_base+0x6745268,8),0)
        with self.assertRaises(PrimarySemanticUnavailable):owner.sign(b'a',b'b')
        service.release_wrappers()
        owner=self.owner();r=owner.signer.runtime
        with self.tls(r):service=get_login_service(owner)
        config=self.config();config['appid']=7
        with self.assertRaisesRegex(PrimarySemanticUnavailable,'present appid'):self.run_config(owner,service,config)
        self.assertEqual(r.memory.load(r.image_base+0x6745268,8),0)
        self.assertEqual(service.state,'UNAVAILABLE');service.release_wrappers()
    def test_missing_tls_stops_factory_without_faking_receipt(self):
        owner=self.owner();r=owner.signer.runtime
        with self.assertRaises(InputError):get_login_service(owner)
        self.assertEqual(r.calls,[(0xB75000,(0x10,))])
        with self.assertRaises(PrimarySemanticUnavailable):owner.sign(b'a',b'b')
    def test_native_cs_same_backing_hresult_cleanup_and_new_frontier(self):
        for result,error in ((1,0),(0,5),(0,0),(0,0x80000002),(0,0xffffffff)):
            owner=self.owner();r=owner.signer.runtime;calls=[]
            port=bind_outer_sync(owner,permit=lambda *args:True)
            def api(unused,name,restype,types,*args):
                calls.append(name)
                if name=='InitializeCriticalSectionEx':
                    pointer=r.memory.load(r.image_base+0x6745268,8)
                    self.assertNotEqual(pointer,0)
                    self.assertEqual(r.memory.load(r.image_base+0x6745280,8),0)
                    self.assertEqual(r.memory.load(pointer+0x40,8),0)
                    with self.assertRaises(UnknownMemory):r.memory.read(pointer,8)
                    C.memset(args[0],0x5a,40);return result
                if name=='GetLastError':return error
                return None
            with self.tls(r):service=get_login_service(owner)
            with patch.object(WindowsOuterSync,'_api',api):
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'controlled hostname publication boundary'):self.run_config(owner,service,self.config())
                pointer=r.memory.load(r.image_base+0x6745268,8)
                self.assertEqual(r.memory.read(pointer+0x18,40),b'Z'*40)
                self.assertEqual(r.memory.load(pointer+8,4),0 if not result and error else 0x38)
                self.assertEqual(r.memory.load(r.image_base+0x67451d4,1),int(not result and error!=0))
                self.assertEqual(r.memory.load(r.image_base+0x6745280,8),pointer)
                self.assertEqual(r.memory.load(pointer,8),r.image_base+0x3f466f8)
                with self.assertRaises(UnknownMemory):r.memory.read(pointer+0x48,8)
                before=(list(r.calls),list(calls),list(r.memory.writes))
                self.assertEqual(_global_sync(r),pointer)
                self.assertEqual((r.calls,calls,r.memory.writes),before)
                with self.assertRaises(PrimaryMemoryLimit):r.memory.unmap(pointer)
                with self.assertRaises(PrimaryMemoryLimit):r.memory.forget(pointer,0x50,source='controlled free')
                owner._state='closing';port.dispose_terminal()
            self.assertEqual(calls.count('GetLastError'),int(not result))
            self.assertEqual(calls.count('DeleteCriticalSection'),int(bool(result)))
            r.memory._assert_no_native_pin(pointer,0x50)
            service.release_wrappers()
    def test_success_does_not_clear_existing_sticky_byte(self):
        owner=self.owner();r=owner.signer.runtime;m=r.memory;b=r.image_base
        m.store(b+0x67451d4,1,1,source='controlled prior failure byte')
        port=bind_outer_sync(owner,permit=lambda *args:True)
        with patch.object(WindowsOuterSync,'_api',side_effect=lambda name,*args:1 if name=='InitializeCriticalSectionEx' else None):
            pointer=_global_sync(r)
            self.assertEqual(m.load(pointer+8,4),0x38)
            self.assertEqual(m.load(b+0x67451d4,1),1)
            owner._state='closing';port.dispose_terminal()
        m._assert_no_native_pin(pointer,0x50)

    def test_unsupported_cs_retains_api_effects_early_publish_and_nonretry(self):
        owner=self.owner();r=owner.signer.runtime;m=r.memory;b=r.image_base
        port=bind_outer_sync(owner,permit=lambda *args:True);calls=[]
        def api(unused,name,*args):
            calls.append(name)
            if name=='InitializeCriticalSectionEx':
                C.memset(args[2],0x5b,40)
                raise PrimarySemanticUnavailable('controlled unsupported host')
            raise AssertionError(name)
        with patch.object(WindowsOuterSync,'_api',api):
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'unsupported host'):_global_sync(r)
            pointer=m.load(b+0x6745268,8)
            self.assertEqual(m.read(pointer+0x18,40),b'['*40)
            self.assertEqual(m.load(b+0x6745280,8),0);self.assertEqual(m.load(b+0x67451d4,1),0)
            for offset,size in ((0,8),(0x48,8)):
                with self.assertRaises(UnknownMemory):m.read(pointer+offset,size)
            before=(list(r.calls),list(m.writes));self.assertEqual(_global_sync(r),pointer)
            self.assertEqual((r.calls,m.writes),before);self.assertEqual(calls,['InitializeCriticalSectionEx'])
            owner._state='closing'
            with self.assertRaises(PrimarySemanticUnavailable):port.dispose_terminal()
        # Only synthetic API backing exists; release test-owned pins after retention assertions.
        for record in port._WindowsOuterSync__records.values():
            m._unpin_native_span(record.token,port);record.view.release()
        m._assert_no_native_pin(pointer,0x50)

    def test_allocator_free_and_all_teardown_preflight(self):
        from qq_nt_replica.primary_custom_allocator import _OwnedStorage,_CustomBackend,ModelAllocatorIssuer,dispose_model_allocator
        r=Runtime();epoch=object();hook=[]
        storage=_OwnedStorage.__new__(_OwnedStorage)
        storage.runtime=r;storage.closed=False;storage.epoch=epoch;storage.base=r.image_base
        storage.selector=SimpleNamespace(epoch=epoch,validate=lambda runtime:None)
        storage.supplier=SimpleNamespace(validate=lambda runtime:None)
        storage.hooks=SimpleNamespace(before_free=lambda:hook.append('free'))
        storage.live={};storage.source_free_seen=[];storage.storage_disposed=[]
        for pointer in (100,200):
            r.memory.map(pointer,bytearray(8),name='controlled owned',initialized=True)
            region,offset=r.memory._span(pointer,8)
            storage.live[pointer]=(region,8,epoch,threading.get_ident(),0xB75000,0)
        token,view=r.memory._pin_native_span(200,8,self)
        with self.assertRaises(PrimaryMemoryLimit):storage.free(200)
        self.assertEqual(hook,[])
        backend=_CustomBackend.__new__(_CustomBackend);backend.runtime=r;backend.closed=False
        backend.operation=threading.Lock();backend.storage=storage;backend.records={}
        r._custom_allocator_backend=backend;r._active_main=None;r._program_calls=[]
        issuer=ModelAllocatorIssuer.__new__(ModelAllocatorIssuer);issuer.closed=False;issuer.owners={};issuer.material=None
        r._primary_allocator_issuer=issuer
        with patch.object(ModelAllocatorIssuer,'validate',lambda issuer:None):
            with self.assertRaises(PrimaryMemoryLimit):dispose_model_allocator(r)
            self.assertEqual(set(storage.live),{100,200})
            self.assertEqual(r.memory.read(100,8),bytes(8))
            r.memory._unpin_native_span(token,self);view.release()
            storage.free(100);self.assertEqual(hook,['free'])
            dispose_model_allocator(r)
        self.assertTrue(backend.closed);self.assertFalse(storage.live)
    def test_delete_failure_retains_actual_backing_pin(self):
        owner=self.owner();r=owner.signer.runtime;port=bind_outer_sync(owner,permit=lambda *args:True)
        with self.tls(r):service=get_login_service(owner)
        def api(unused,name,result,types,*args):
            if name=='InitializeCriticalSectionEx':return 1
            if name=='DeleteCriticalSection':raise RuntimeError('controlled delete unavailable')
            raise AssertionError(name)
        with patch.object(WindowsOuterSync,'_api',api):
            with self.assertRaises(PrimarySemanticUnavailable):self.run_config(owner,service,self.config())
            pointer=r.memory.load(r.image_base+0x6745268,8);owner._state='closing'
            with self.assertRaisesRegex(RuntimeError,'delete unavailable'):port.dispose_terminal()
        with self.assertRaises(PrimaryMemoryLimit):r.memory.unmap(pointer)
        service.release_wrappers()
        for record in port._WindowsOuterSync__records.values():
            r.memory._unpin_native_span(record.token,port);record.view.release()
        r.memory._assert_no_native_pin(pointer,0x50)

    def test_selectable_setup_enters_existing_scope_before_owner_and_never_inner(self):
        from contextlib import contextmanager
        from qq_nt_replica.primary_windows_signer_setup import IndependentWindowsSetup
        owner=self.owner();r=owner.signer.runtime;events=[]
        @contextmanager
        def lease():
            events.append('lease')
            try:yield
            finally:events.append('lease_exit')
        @contextmanager
        def native_context():
            events.append('native_context')
            with self.tls(r):
                try:yield
                finally:events.append('native_context_exit')
        owner._threads=SimpleNamespace(before_public_operation=lambda:events.append('before'),after_public_operation=lambda:events.append('after'),_creator_crt_context=native_context)
        owner._registrar=SimpleNamespace(operation=lease)
        setup=IndependentWindowsSetup(owner)
        port=bind_outer_sync(owner,permit=lambda *args:True)
        def api(unused,name,result,types,*args):
            if name=='InitializeCriticalSectionEx':return 1
            return None
        with patch.object(WindowsOuterSync,'_api',api),patch('qq_nt_replica.primary_login_host_init.publish_hostname',side_effect=PrimarySemanticUnavailable('controlled hostname publication boundary')):
            config=self.config();config['externalVersion']=True
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'controlled hostname publication boundary'):setup.prepare_outer_prefix(config)
            owner._state='closing';port.dispose_terminal()
        self.assertEqual(setup.state,'failed')
        self.assertEqual(events,['before','lease','native_context','native_context_exit','lease_exit','after'])
        from qq_nt_replica.primary_logger import _String
        obj=r.memory.load(r.image_base+0x674c730,8)
        self.assertEqual(_String.read(r,obj+0x130).value(),b'machine')
        self.assertEqual(r.memory.load(obj+0x1a0,1),1)
        self.assertNotIn(0xBA0270,[rva for rva,args in r.calls])
        self.assertNotEqual(r.memory.load(r.image_base+0x6745268,8),0)

    def test_unpinned_memory_compatibility(self):
        m=PrimaryMemory();m.map(100,bytearray(8),name='controlled',initialized=False)
        m.write(100,b'12345678',source='ordinary');m.forget(100,8,source='ordinary')
        with self.assertRaises(UnknownMemory):m.read(100,8)
        m.unmap(100)

if __name__=='__main__':unittest.main()
