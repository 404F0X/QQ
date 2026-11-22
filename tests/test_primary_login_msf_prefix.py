"""Controlled finite path checks; not a complete MSF factory test."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from qq_nt_replica.primary_logger import _String
from qq_nt_replica.primary_outer_init import login_nt_data_path
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from test_primary_outer_init import Runtime

class PathChecks(unittest.TestCase):
    def test_independent_owned_heap_path_and_cleanup(self):
        runtime=Runtime();value=_String.construct(runtime,b'C:\\long_component')
        result=login_nt_data_path(runtime,value)
        self.assertEqual(value.value(),b'C:\\long_component')
        self.assertEqual(result.value(),b'C:\\long_component\\nt_data')
        pointer=result.get(16,8)
        self.assertIn(pointer,runtime._custom_allocator_backend.records)
        result.destroy();value.destroy()
        self.assertNotIn(pointer,runtime._custom_allocator_backend.records)
    def test_unsupported_domain_before_result_allocation(self):
        runtime=Runtime()
        for data in (b'C:\\',b'relative',b'C:\\a\\..\\b',b'C:\\a\0x',b'C:\\a\xff'):
            value=_String.construct(runtime,data);before=list(runtime.calls)
            with self.assertRaises(PrimarySemanticUnavailable):login_nt_data_path(runtime,value)
            self.assertEqual(runtime.calls,before);value.destroy()

class SelectionChecks(unittest.TestCase):
    def fixture(self):
        import hashlib
        from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
        from qq_nt_replica.primary_notification_files import FileSelectorMaterial
        from qq_nt_replica.primary_custom_allocator import install_model_allocator
        signer=PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/p.exe',module_path=b'C:/explicit/m.dll',stack_modules=()),initial_stack=None,primary_backend='direct')
        r=signer.runtime
        raw=b'explicit-model-custom\0';pointer=0x7600000000;initial=bytes(2)
        material=FileSelectorMaterial(initial,pointer,raw,'synthetic-test-input','explicit-model',hashlib.sha256(initial+pointer.to_bytes(8,'little')+raw).hexdigest())
        install_model_allocator(r,material,supplier=signer.addresses.allocation)
        return signer

    def test_source_callback_nt_owner_and_mmkv_boundary(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from qq_nt_replica import primary_msf_selection as selection
        from qq_nt_replica.primary_memory import UnknownMemory
        signer=self.fixture();r=signer.runtime;m=r.memory;b=r.image_base
        receipt=SimpleNamespace(epoch_address=r.tls_epoch_address,image_epoch=object())
        with patch('qq_nt_replica.primary_shared_locale.resolve_current_module_tls',return_value=receipt),patch.object(selection,'resolve_current_module_tls',return_value=receipt),patch('qq_nt_replica.primary_nt_wrapper_owner.resolve_current_module_tls',return_value=receipt):
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'scoped native host'):selection.select(r)
        self.assertEqual(m.load(b+0x674d418,8),1)
        obj=m.load(b+0x6745648,8);control=m.load(b+0x6745650,8)
        self.assertEqual(m.load(control+8,4),0)
        self.assertEqual(m.load(control+0x10,4),1)
        self.assertEqual(_String.read(r,obj+0x168).value(),b'null')
        self.assertEqual(m.load(obj+0x3c0,8),obj+0x3c8)
        for offset in (0xc,0x14):
            with self.assertRaises(UnknownMemory):m.read(control+offset,4)
        self.assertEqual([e[1] for e in r.events if e[0]=='source.callback'],[0x7510f1])
        boundary=[e for e in r.events if e[0]=='source.mmkv_open']
        self.assertEqual(len(boundary),1);self.assertEqual(boundary[0][1],0xb99200)
        self.assertEqual(boundary[0][3:],(2,0,0,0))
        self.assertFalse(signer._module_sync_image.held)
        with patch('qq_nt_replica.primary_shared_locale.resolve_current_module_tls',return_value=receipt),patch.object(selection,'resolve_current_module_tls',return_value=receipt):
            with self.assertRaises(PrimarySemanticUnavailable):selection.select(r)
        self.assertEqual(len([e for e in r.events if e[0]=='source.callback']),1)
        from qq_nt_replica.primary_nt_wrapper_owner import install_fresh_image
        from qq_nt_replica.errors import InputError
        with self.assertRaises(InputError):install_fresh_image(signer)
        with self.assertRaises(InputError):selection.install_fresh_image(signer)

    def test_public_prefix_keeps_owned_path_but_never_publishes_msf(self):
        import os,threading
        from types import SimpleNamespace
        from unittest.mock import patch
        from qq_nt_replica.primary_windows_signer import WindowsSigner
        from qq_nt_replica.primary_outer_init import get_login_service
        from qq_nt_replica import primary_msf_selection as selection
        from qq_nt_replica.primary_memory import UnknownMemory
        signer=self.fixture();r=signer.runtime;m=r.memory;b=r.image_base
        # Controlled public-wrapper fixture; no actual Windows factory/native origin.
        owner=WindowsSigner.__new__(WindowsSigner);owner._state='open';owner._busy=False
        owner._pid=os.getpid();owner._thread=threading.get_native_id();owner._signer=signer
        receipt=SimpleNamespace(epoch_address=r.tls_epoch_address,image_epoch=r._shared_locale_source_epoch)
        from qq_nt_replica.primary_windows_outer_sync import bind_outer_sync,WindowsOuterSync
        port=bind_outer_sync(owner,permit=lambda *args:True)
        original=selection._callback_7510f1
        def observe(runtime,closure,frame):
            with self.assertRaises(UnknownMemory):m.read(frame+0x2f,1)
            return original(runtime,closure,frame)
        with patch('qq_nt_replica.primary_shared_locale.resolve_current_module_tls',return_value=receipt),patch.object(selection,'resolve_current_module_tls',return_value=receipt),patch('qq_nt_replica.primary_nt_wrapper_owner.resolve_current_module_tls',return_value=receipt):
            service=get_login_service(owner)
            # CS operation has its own existing same-buffer ABI checks; no native here.
            with patch.object(WindowsOuterSync,'_api',side_effect=lambda name,*args:1 if name=='InitializeCriticalSectionEx' else None),patch.object(selection,'_callback_7510f1',observe):
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'C6 MODEL process-attach'):
                    service.initConfig(dict(commonPath='C:\\data',clientVer='v',machineId='machine',platVer='p',hostName='h'))
            obj=m.load(b+0x674c730,8)
            self.assertEqual(_String.read(r,obj+0x100).value(),b'C:\\data\\nt_data')
            self.assertEqual(m.read(obj+0x90,16),bytes(16))
            self.assertEqual(service.state,'UNAVAILABLE')
            before=len(r.events)
            with self.assertRaises(PrimarySemanticUnavailable):service.initConfig({})
            self.assertEqual(len(r.events),before)
            service.release_wrappers()
        owner._state='closing'
        with patch.object(WindowsOuterSync,'_api',return_value=None):port.dispose_terminal()

if __name__=='__main__':unittest.main()

