"""Admission denials keep original Device/Notify gates and source image facts."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test_primary_client_configuration_request import signer, source_threads


class Admission(unittest.TestCase):
    def test_creator_lease_alone_cannot_issue_a_client_startup_or_loop_claim(self):
        from qq_nt_replica.primary_client_configuration_scope import current_request
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with source_threads() as (owner,r,physical,bridge):
            service=owner._threads; service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with service._native_crt_context():
                        before=list(physical.kernel.calls)
                        with self.assertRaises(PrimarySemanticUnavailable):
                            service.source_start(0,0,r.image_base+0x1C22D90,0,0,0)
                        from qq_nt_replica.primary_client_configuration import create_startup
                        with self.assertRaises(PrimarySemanticUnavailable):create_startup(r)
                        self.assertEqual(service._threads,[])
                        self.assertEqual(physical.kernel.calls,before)
                        with patch.object(r,'_primary_client_configuration_owner',SimpleNamespace(),create=True):
                            with self.assertRaises(PrimarySemanticUnavailable):current_request(r)
            finally:service.after_public_operation()

    def test_new_role_does_not_accept_device_notification_or_arbitrary_owner(self):
        from qq_nt_replica.primary_direct_scopes import PrimaryDirectScope
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        r=signer().runtime
        fake=SimpleNamespace(runtime=r,thread=__import__('threading').get_ident(),valid=lambda:True)
        for field in ('client_owner','device_owner','notification_owner'):
            before=list(r.memory.writes)
            scope=PrimaryDirectScope(r,**{field:fake})
            with self.subTest(field=field),self.assertRaises(PrimarySemanticUnavailable):scope.install()
            self.assertEqual(r.memory.writes,before)
            self.assertIsNone(r.__dict__.get('_primary_direct_scope'))

    def test_handoff_without_the_actual_source_producer_cannot_start_audit(self):
        from qq_nt_replica.primary_request_audit_scope import client_handoff_audit
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        r=signer().runtime;before=list(r.memory.writes)
        with self.assertRaises(PrimarySemanticUnavailable):
            with client_handoff_audit(r):self.fail('raw client audit was admitted')
        self.assertEqual(r.memory.writes,before)
        self.assertIsNone(r.__dict__.get('_primary_direct_scope'))


class NarrowLogger(unittest.TestCase):
    def test_proved_options18_narrow_templates_and_low32_signedness(self):
        from qq_nt_replica.primary_logger import _format
        r=signer().runtime; m=r.memory; b=r.image_base
        rows=((b'%s:%d',(b'file.cc',0xFFFFFFFF),b'file.cc:-1'),
            (b'not ready: %d',(0x80000000,),b'not ready: -2147483648'),
            (b'thread2=%u',(0xFFFFFFFFFFFFFFFF,),b'thread2=4294967295'),
            (b'cwlun :%d',(0x100000001,),b'cwlun :1'),
            (b'UpdateConfiguration start',(),b'UpdateConfiguration start'))
        for options in (0,0x18,0x24):
            m.store(b+0x6749CC0,options,8,source='explicit formatter-only MODEL options')
            for template,args,want in rows:
                with self.subTest(options=options,template=template):self.assertEqual(_format(r,template,args),want)
        m.map(0x7800000000,b'raw\xff\0',name='controlled raw narrow CString',initialized=True)
        self.assertEqual(_format(r,b'%s',(0x7800000000,)),b'raw\xff')

    def test_options18_domain_rejects_unproved_forms_and_keeps_locale_and_unknown_guards(self):
        from qq_nt_replica.primary_logger import _format
        from qq_nt_replica.primary_memory import UnknownMemory,PrimaryMemoryLimit
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable,PrimaryProgramLimit
        r=signer().runtime; m=r.memory; b=r.image_base
        m.store(b+0x6749CC0,0x18,8,source='explicit formatter-only MODEL options')
        for template in (b'%i',b'%c',b'%ls',b'%lld',b'%08u',b'%.2s',b'%*d',b'%f',b'%n',b'%1$d',b'%Fd',b'%%',b'\xff'):
            with self.subTest(template=template),self.assertRaises(PrimarySemanticUnavailable):_format(r,template,(1,))
        with self.assertRaises(PrimarySemanticUnavailable):_format(r,b'%s',(0,))
        with self.assertRaises(UnknownMemory):_format(r,b'%d',())
        with self.assertRaises(UnknownMemory):_format(r,b'%u',(None,))
        with self.assertRaises(PrimaryMemoryLimit):_format(r,b'%s',(0x7800000000,))
        with self.assertRaises(PrimaryProgramLimit):_format(r,b'x'*(1+(1<<20)),())
        m.store(b+0x6D8E630,1,4,source='explicit unsupported locale fixture')
        with self.assertRaises(PrimarySemanticUnavailable):_format(r,b'%d',(1,))
        m.store(b+0x6D8E630,0,4,source='restore formatter fixture locale')
        for options in (1,0x25,0x19):
            m.store(b+0x6749CC0,options,8,source='explicit unsupported options fixture')
            with self.subTest(options=options),self.assertRaises(PrimarySemanticUnavailable):_format(r,b'%d',(1,))
        m.store(b+0x6749CC0,0,8,source='explicit original options0 domain')
        self.assertEqual(_format(r,b'%04x',(15,)),b'000f')


class NativeBoundary(unittest.TestCase):
    def test_constructor_cached_loader_and_direct_accessor_tripwires_reject_before_call(self):
        import ctypes
        from unittest.mock import patch
        calls=[]
        def denied(*a,**kw):calls.append('blocked-before-native');raise AssertionError('controlled native boundary denied')
        class Cached:
            def __getattr__(self,name):return denied()
        with patch.multiple(ctypes,WinDLL=denied,CDLL=denied,OleDLL=denied,PyDLL=denied,GetLastError=denied,
                windll=Cached(),cdll=Cached(),oledll=Cached(),pydll=Cached(),create=True):
            for name in ('WinDLL','CDLL','OleDLL','PyDLL'):
                with self.assertRaises(AssertionError):getattr(ctypes,name)('never-loaded.dll')
            with self.assertRaises(AssertionError):ctypes.GetLastError()
            for name in ('windll','cdll','oledll','pydll'):
                with self.assertRaises(AssertionError):getattr(getattr(ctypes,name),'never_loaded')
        self.assertEqual(calls,['blocked-before-native']*9)

    def test_exact_last_error_metadata_snapshot_restore_and_reject_unknown_cached_address(self):
        import ctypes
        from test_primary_client_configuration_request import controlled_cached_apis
        from qq_nt_replica.primary_windows_crt_environment import _preserve_last_error
        kernel=object();metadata=[]
        private=ctypes.get_last_error()
        try:
            with controlled_cached_apis(kernel,metadata) as (get_error,set_error):
                ctypes.set_last_error(0x4321)
                @_preserve_last_error
                def operation():
                    set_error(0x9876);ctypes.set_last_error(0x8765);return 7
                self.assertEqual(operation(),7)
                self.assertEqual(get_error(),0x1234)
                self.assertEqual(ctypes.get_last_error(),0x4321)
                with self.assertRaises(AssertionError):
                    ctypes.WINFUNCTYPE(None)(('not_a_controlled_API',kernel))
                with self.assertRaises(AssertionError):ctypes.WINFUNCTYPE(None)(0x12345678)
            self.assertEqual([row[0] for row in metadata],['GetLastError','SetLastError','SetLastError','GetLastError'])
        finally:ctypes.set_last_error(private)


class ColdConstructor(unittest.TestCase):
    def test_actual_root_rejects_unissued_vm_and_lease_copies_then_retains_source_on_clock_failure(self):
        from copy import copy
        from test_primary_client_configuration_request import start_component
        from qq_nt_replica.primary_client_configuration_scope import image_for,authorize_bootstrap
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        failure=RuntimeError('controlled constructor FILETIME unavailable');seen=[]
        def clock(r):
            scope=r._primary_direct_scope;ctor=scope._client_ctor
            self.assertTrue(ctor.root_backend)
            self.assertTrue(ctor.root._primary_bootstrap_used)
            before=list(r.memory.writes)
            with self.assertRaises(PrimarySemanticUnavailable):authorize_bootstrap(scope,copy(ctor.root),'singleton-init',backend=True)
            cloned=copy(ctor)
            with patch.object(scope,'_client_ctor',cloned):
                with self.assertRaises(PrimarySemanticUnavailable):cloned.require()
            self.assertEqual(r.memory.writes,before)
            self.assertIs(scope._client_ctor,ctor)
            self.assertTrue(ctor.root_backend)
            seen.append(ctor)
            raise failure
        with source_threads(filetime=clock) as (owner,r,physical,bridge):
            startup=start_component(owner,r);physical.join(startup['source_handle'])
            launch=bridge.launches[0];launch.gate.set()
            with self.assertRaises(RuntimeError) as stopped:physical.join(launch.handle)
            self.assertIs(stopped.exception,failure)
            self.assertEqual(len(seen),1)
            self.assertIn(('constructor',seen[0]),image_for(r).debts)
            self.assertEqual(r.memory.load(r.image_base+0x6D88CC0,8),0)
            self.assertEqual(r.memory.load(r.image_base+0x6D88CC8,4,signed=True),-1)
            self.assertEqual(r.memory.load(r.image_base+0x6D85F60,8),r.image_base+0x1BF81B0)
            self.assertEqual(r.memory.load(r.image_base+0x6D85F78,8),r.image_base+0xB9F1D0)
            self.assertEqual(r.locks[r.image_base+0x677C220],0)

    def test_issued_child_failure_keeps_original_child_and_used_qualifier(self):
        from test_primary_client_configuration_request import start_component
        failure=RuntimeError('controlled child first QPC API unavailable');seen=[]
        def core(r,name,destination,purpose):
            ctor=r._primary_direct_scope._client_ctor
            self.assertIsNotNone(ctor.child)
            self.assertTrue(ctor.child_backend)
            self.assertIs(ctor.root._primary_bootstrap_child,ctor.child)
            self.assertTrue(ctor.child._primary_bootstrap_used)
            self.assertIs(r._program_calls[-2],ctor.root_call)
            self.assertIs(r._program_calls[-1],ctor.child_call)
            self.assertEqual(ctor.child_call['arguments'],(ctor.root.cells.value(35),ctor.root.cells.value(34)))
            seen.append((ctor,ctor.child,ctor.child_call));raise failure
        with source_threads(core_output=core) as (owner,r,physical,bridge):
            startup=start_component(owner,r);physical.join(startup['source_handle'])
            launch=bridge.launches[0];launch.gate.set()
            with self.assertRaises(RuntimeError) as stopped:physical.join(launch.handle)
            self.assertIs(stopped.exception,failure)
            self.assertEqual(len(seen),1)
            ctor,child,call=seen[0]
            self.assertIs(ctor.child,child)
            self.assertIs(ctor.child_call,call)
            self.assertTrue(ctor.root_backend and ctor.child_backend and child._primary_bootstrap_used)
            self.assertIs(ctor.root._primary_bootstrap_child,child)
            self.assertFalse(ctor.root.halted)
            self.assertEqual(r.memory.load(r.image_base+0x6D88CC0,8),0)
            self.assertEqual(r.memory.load(r.image_base+0x6D88CC8,4,signed=True),-1)
            self.assertGreater(len(r.allocations),0)

    def test_equal_parent_record_copy_is_not_adopted_by_real_word163_child(self):
        from test_primary_client_configuration_request import start_component
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        originals=[]
        def clock(r):
            ctor=r._primary_direct_scope._client_ctor
            originals.append(ctor.root_call)
            self.assertIs(r._program_calls[0],ctor.root_call)
            r._program_calls[0]=dict(ctor.root_call)
            self.assertEqual(r._program_calls[0],ctor.root_call)
            self.assertIsNot(r._program_calls[0],ctor.root_call)
            return 116444736000000000
        with source_threads(filetime=clock) as (owner,r,physical,bridge):
            startup=start_component(owner,r);physical.join(startup['source_handle'])
            launch=bridge.launches[0];launch.gate.set()
            with self.assertRaises(PrimarySemanticUnavailable):physical.join(launch.handle)
            self.assertEqual(len(originals),1)
            root=r.vms[0]
            self.assertEqual((root.pc,root.block,root.predecessor),(170,6,4))
            self.assertEqual(root.host_calls[-1],(163,r.image_base+0x359205B,(35,34),41))
            self.assertIsNone(getattr(root,'_primary_bootstrap_child',None))
            self.assertFalse(root._primary_client_ctor.child_backend)
            self.assertEqual(r.memory.load(r.image_base+0x6D88CC0,8),0)
            self.assertEqual(r.memory.load(r.image_base+0x6D88CC8,4,signed=True),-1)
            self.assertEqual(r.locks[r.image_base+0x677C220],0)


if __name__ == '__main__':
    unittest.main()
