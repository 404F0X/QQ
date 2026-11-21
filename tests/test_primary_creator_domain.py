"""Synthetic physical boundaries; creator issuer/receipt/journal guards stay real."""
import sys,ctypes as C,threading,unittest
from pathlib import Path
from contextlib import ExitStack,contextmanager
from unittest.mock import patch
from types import SimpleNamespace
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'src'),str(Path(__file__).resolve().parent)]


class Function:
    def __init__(self,backend,name):self.backend=backend;self.name=name
    def __call__(self,*args):return self.backend.call(self.name,args)


class PhysicalKernel:
    def __init__(self):self.clear_false=False;self.functions={};self.fls={};self.nextslot=3;self.buffers=[];self.calls=[];self._handle=123
    def __getattr__(self,name):return self.functions.setdefault(name,Function(self,name))
    def call(self,name,args):
        self.calls.append((name,args))
        if name=='WaitForSingleObject':return 258
        if name=='FlsAlloc':
            result=self.nextslot;self.nextslot+=1;return result
        if name=='FlsSetValue':
            if getattr(self,'clear_false',False) and not args[1]:return 0
            self.fls[threading.get_native_id(),args[0]]=int(args[1] or 0);return 1
        if name=='FlsGetValue':return self.fls.get((threading.get_native_id(),args[0]),0)
        if name in ('GetCurrentThreadId','GetThreadId'):return threading.get_native_id()
        if name in ('LoadLibraryExW','GetProcAddress','GetLastError'):return 0
        if name=='VirtualAlloc':
            data=C.create_string_buffer(args[1]);self.buffers.append(data);return C.addressof(data)
        if name in ('FlsFree','InitializeCriticalSectionEx','VirtualProtect','VirtualFree','FreeLibrary','CloseHandle'):return 1
        if name in ('EnterCriticalSection','LeaveCriticalSection','DeleteCriticalSection','SetLastError'):return
        raise AssertionError('unexpected physical API '+name)


@contextmanager
def factory(*,fail_initialize=False,captured=None):
    from qq_nt_replica import primary_windows_signer as windows
    from qq_nt_replica.primary_windows_allocator_issuer import WindowsAllocatorIssuer
    from qq_nt_replica import primary_login_model_attach as attach
    from test_primary_outer_init import Runtime
    kernel=PhysicalKernel();owners=[]
    constructors=('WindowsCallerAPIBackend','WindowsCallerBridge','WindowsCallerObservations','WindowsProviderObservations','WindowsWorkerObservations','WindowsDeviceFileObservations','WindowsCoreObservations','WindowsDeviceProcessRecordObservations','WindowsDeviceHardwareObservations','WindowsSystemRecordObservations','WindowsWMIObservations')
    def allocator(owner):
        owners.append(owner)
        if captured is not None:captured.append(owner)
        r=owner._signer.runtime
        issuer=WindowsAllocatorIssuer.__new__(WindowsAllocatorIssuer);issuer.owner=owner;issuer.runtime=r;issuer.epoch=r._primary_allocator_selector.epoch;issuer.source=r._primary_allocator_selector
        r._primary_allocator_issuer=issuer
    def invoke(r,rva,*args):
        if not hasattr(r,'calls'):r.calls=[];r.next=0x7b00000000;r.fail_size=None;r.epoch=r._primary_allocator_selector.epoch
        # Source upper operations only; lower CRT/PTD allocation remains real model allocation.
        from qq_nt_replica.primary_worker_consumer import _invoke
        original=r.invoke;r.invoke=Runtime.invoke.__get__(r,type(r))
        try:return _invoke(r,rva,*args)
        finally:r.invoke=original
    with ExitStack() as stack:
        stack.enter_context(patch.object(C,'WinDLL',return_value=kernel))
        stack.enter_context(patch.object(C,'CDLL',side_effect=AssertionError('no actual DLL')))
        stack.enter_context(patch.object(windows,'_validated_paths',return_value=(Path('controlled.dll'),Path('controlled'))))
        for name in constructors:stack.enter_context(patch.object(windows,name))
        stack.enter_context(patch.object(windows.DeviceFactory,'windows'))
        stack.enter_context(patch.object(windows.WindowsSigner,'_host_environment',return_value=(b'C:/explicit/p.exe',None,())))
        stack.enter_context(patch.object(windows.WindowsSigner,'_initialize_notification_statics'))
        stack.enter_context(patch('qq_nt_replica.primary_windows_allocator_issuer.install_early_allocator',side_effect=allocator))
        stack.enter_context(patch.object(WindowsAllocatorIssuer,'validate'))
        stack.enter_context(patch.object(attach,'_invoke',side_effect=invoke))
        stack.enter_context(patch.object(windows.WindowsSigner,'diagnostics',new=property(lambda actual:{})))
        if fail_initialize:stack.enter_context(patch('qq_nt_replica.primary_crt_thread.initialize',side_effect=RuntimeError('controlled initialize failure')))
        owner=windows.open_windows_signer(bridge_path='controlled.dll',storage_root='controlled',host_profile_string=b'explicit-model-profile',primary_backend='direct')
        windows.WindowsDeviceFileObservations.return_value.pending_handles=0
        windows.WindowsDeviceFileObservations.return_value.cleanup_records=[]
        yield owner,kernel


class CreatorDomain(unittest.TestCase):
    def test_actual_factory_grant_and_complete_ptd_journal(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime,grant
        from qq_nt_replica.errors import InputError
        with factory() as (owner,kernel):
            record=_for_runtime(owner.signer.runtime)
            self.assertIs(record.owner,owner)
            self.assertTrue(record.ptd['initialized'])
            with self.assertRaises(InputError):grant(owner)

    def test_creator_receipt_without_worker_live_and_scope_revocation(self):
        from qq_nt_replica.primary_shared_locale import resolve_current_module_tls
        from qq_nt_replica.primary_windows_threads import _LIVE_SERVICES
        from qq_nt_replica.errors import InputError
        with factory() as (owner,kernel):
            service=owner._threads;r=owner.signer.runtime
            service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with service._native_crt_context():
                        receipt=resolve_current_module_tls(r)
                        self.assertEqual(receipt.origin,'model-windows-creator-domain')
                        self.assertNotIn(service,_LIVE_SERVICES)
                        with owner._registrar.current_lease().suspend():
                            with self.assertRaises(InputError):receipt.validate(r,receipt.module_identity)
                    with self.assertRaises(InputError):receipt.validate(r,receipt.module_identity)
            finally:service.after_public_operation()

    def test_zero_worker_actual_creator_close_cleans_unique_ptd_then_backing(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        from qq_nt_replica.primary_windows_allocator_issuer import WindowsAllocatorIssuer
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with factory() as (owner,kernel):
            service=owner._threads;r=owner.signer.runtime
            service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with service._native_crt_context():pass
            finally:service.after_public_operation()
            record=_for_runtime(r);pointer=record.ptd['pointer'];slot=record.ptd['slot']
            owner._bridge._closed=True;owner._bridge._close_status='unloaded'
            with patch.object(WindowsAllocatorIssuer,'retire'):
                owner.close()
            self.assertEqual(owner._state,'closed')
            self.assertTrue(record.ptd['consumed']);self.assertEqual(record.state,'terminal')
            self.assertNotIn(pointer,r.allocations);self.assertFalse(service._crt_domains)
            self.assertTrue(owner._crt._closed)
            self.assertEqual(sum(name=='FlsSetValue' and args==(slot,None) for name,args in kernel.calls),1)

    def test_clear_false_source_consumes_but_retains_native_chain_no_repeat(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        with factory() as (owner,kernel):
            service=owner._threads;r=owner.signer.runtime
            service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with service._native_crt_context():pass
            finally:service.after_public_operation()
            record=_for_runtime(r);item=record.ptd;pointer=item['pointer'];slot=item['slot']
            kernel.clear_false=True
            with self.assertRaises(ExceptionGroup):owner.close()
            self.assertTrue(item['consumed']);self.assertNotIn(pointer,r.allocations)
            self.assertIn(service._owner[1],service._crt_domains)
            self.assertTrue(owner._crt._values);self.assertFalse(owner._crt._closed)
            self.assertFalse(any(name=='FlsFree' for name,args in kernel.calls))
            calls=len(kernel.calls)
            with self.assertRaises(ExceptionGroup):owner.close()
            self.assertEqual(len(kernel.calls),calls)
            token=next(iter(owner._crt._tokens))
            owner._crt._cleanup_token(token)
            first=owner._crt._callback_failure
            self.assertIsNotNone(first)
            owner._crt._cleanup_token(token)
            self.assertIs(owner._crt._callback_failure,first)
            self.assertEqual(len(kernel.calls),calls)
            self.assertTrue(owner._crt._tokens)

    def test_published_partial_factory_failure_retains_ptd_without_destructor(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        captured=[]
        with self.assertRaises(BaseException):
            with factory(fail_initialize=True,captured=captured):
                self.fail('partial initialization cannot open')
        self.assertEqual(len(captured),1)
        owner=captured[0];r=owner._signer.runtime;record=_for_runtime(r);item=record.ptd
        self.assertEqual(item['state'],'published_partial')
        self.assertFalse(item['initialized']);self.assertFalse(item['consumed'])
        self.assertIn(item['pointer'],r.allocations)
        self.assertTrue(owner._crt._values);self.assertFalse(owner._crt._closed)
        self.assertIn('controlled initialize failure',str(item['failure']))

    def test_services_exit_failure_retains_domain_and_first_error(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        with factory() as (owner,kernel):
            service=owner._threads;r=owner.signer.runtime
            service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with service._native_crt_context():pass
            finally:service.after_public_operation()
            record=_for_runtime(r);domain=record.domain;tls=domain['tls']
            failure=RuntimeError('controlled services exit failure')
            class FailedExit:
                def __exit__(self,*args):raise failure
            domain['value']['services']=FailedExit()
            with self.assertRaises(ExceptionGroup):owner.close()
            self.assertIs(domain['failure'],failure)
            self.assertFalse(domain['services_exit']);self.assertFalse(domain['retired'])
            self.assertIn(tls,r.allocations);self.assertFalse(owner._crt._closed)
            calls=len(kernel.calls)
            with self.assertRaises(ExceptionGroup):owner.close()
            self.assertEqual(len(kernel.calls),calls)

    def test_creator_identity_epoch_thread_and_forged_receipt_rejected(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        from qq_nt_replica.primary_shared_locale import resolve_current_module_tls
        from qq_nt_replica.errors import InputError
        import copy
        with factory() as (owner,kernel):
            r=owner.signer.runtime;record=_for_runtime(r);service=owner._threads
            epoch=r._primary_allocator_selector.epoch
            r._primary_allocator_selector.epoch=object()
            try:
                with self.assertRaises(InputError):record.validate(lease=False)
            finally:r._primary_allocator_selector.epoch=epoch
            errors=[]
            def foreign():
                try:record.validate(lease=False)
                except InputError:errors.append('denied')
            thread=threading.Thread(target=foreign);thread.start();thread.join(2)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,['denied'])
            service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with service._native_crt_context():
                        receipt=resolve_current_module_tls(r);forged=copy.copy(receipt)
                        with self.assertRaises(InputError):forged.validate(r,receipt.module_identity)
            finally:service.after_public_operation()

    def test_active_callback_prevents_zero_worker_cleanup(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        with factory() as (owner,kernel):
            service=owner._threads;r=owner.signer.runtime
            service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with service._native_crt_context():pass
            finally:service.after_public_operation()
            record=_for_runtime(r);owner._crt._callbacks_active=1
            before=len(kernel.calls)
            with self.assertRaises(ExceptionGroup):owner.close()
            self.assertFalse(record.ptd['consumed']);self.assertIn(record.ptd['pointer'],r.allocations)
            self.assertFalse(owner._crt._closed)
            self.assertFalse(any(name=='FlsFree' for name,args in kernel.calls[before:]))

    def test_unknown_services_enter_preserves_chain_without_domain_pop(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        from qq_nt_replica import primary_windows_signer as windows
        with factory() as (owner,kernel):
            service=owner._threads;r=owner.signer.runtime
            service.before_public_operation()
            try:
                with owner._registrar.operation(),patch.object(windows,'WindowsWMIObservations',side_effect=RuntimeError('controlled partial enter')):
                    with self.assertRaisesRegex(RuntimeError,'controlled partial enter'):
                        with service._native_crt_context():self.fail('must not enter')
            finally:service.after_public_operation()
            record=_for_runtime(r)
            self.assertEqual(record.service_phase,'enter_failed_unknown')
            self.assertIsNotNone(record.pending_unpublished)
            prior_events=list(record.events);prior_calls=len(kernel.calls);prior_allocations=dict(r.allocations)
            service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with self.assertRaisesRegex(Exception,'unresolved partial'):
                        with service._native_crt_context():self.fail('retry must not enter')
            finally:service.after_public_operation()
            self.assertEqual(record.events,prior_events);self.assertEqual(len(kernel.calls),prior_calls)
            self.assertEqual(r.allocations,prior_allocations)
            with self.assertRaises(ExceptionGroup):owner.close()
            self.assertFalse(record.ptd['consumed']);self.assertFalse(owner._crt._closed)

    def test_known_unpublished_allocation_failure_can_close_unique_ptd(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        from qq_nt_replica.primary_windows_allocator_issuer import WindowsAllocatorIssuer
        with factory() as (owner,kernel):
            service=owner._threads;r=owner.signer.runtime;allocate=r._allocate
            def fail(size,*args,**kwargs):
                if size==0xd78:raise RuntimeError('controlled unpublished D78 failure')
                return allocate(size,*args,**kwargs)
            service.before_public_operation()
            try:
                with owner._registrar.operation(),patch.object(r,'_allocate',side_effect=fail):
                    with self.assertRaisesRegex(RuntimeError,'controlled unpublished D78 failure'):
                        with service._native_crt_context():self.fail('must not enter')
            finally:service.after_public_operation()
            record=_for_runtime(r);self.assertIsNone(record.domain)
            self.assertEqual(record.service_phase,'exit_confirmed')
            owner._bridge._closed=True;owner._bridge._close_status='unloaded'
            with patch.object(WindowsAllocatorIssuer,'retire'):owner.close()
            self.assertTrue(record.ptd['consumed']);self.assertEqual(record.state,'terminal')

    def test_unjoined_worker_still_blocks_creator_cleanup(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        with factory() as (owner,kernel):
            record=_for_runtime(owner.signer.runtime)
            row=dict(handle=1234,handle_closed=False,thread_id=threading.get_native_id()+1,joined=False,state='running',_kind='sdk')
            owner._threads._threads.append(row)
            with self.assertRaises(ExceptionGroup):owner.close()
            self.assertEqual(row['wait_result'],258);self.assertFalse(row['joined'])
            self.assertFalse(record.ptd['consumed']);self.assertFalse(owner._crt._closed)
            self.assertFalse(any(name=='FlsFree' for name,args in kernel.calls))

    def test_real_registrar_failure_stops_dependent_retirement(self):
        from qq_nt_replica.primary_creator_domain import _for_runtime
        with factory() as (owner,kernel):
            service=owner._threads;r=owner.signer.runtime
            service.before_public_operation()
            try:
                with owner._registrar.operation():
                    with service._native_crt_context():pass
            finally:service.after_public_operation()
            record=_for_runtime(r);failure=RuntimeError('controlled guest callback failure')
            owner._registrar(r.image_base+0x1234)
            def invoke(*args):raise failure
            with patch.object(r,'invoke',side_effect=invoke):
                with self.assertRaises(ExceptionGroup):owner.close()
            self.assertIs(owner._registrar._failure,failure)
            self.assertEqual(owner._registrar.snapshot()['lifecycle'],'cleanup_failed')
            self.assertIs(owner._registrar._runtime,r)
            self.assertFalse(record.ptd['consumed']);self.assertFalse(record.domain['services_exit'])
            self.assertFalse(record.domain['retired']);self.assertFalse(owner._crt._closed)
            self.assertIn(record.ptd['pointer'],r.allocations)
            self.assertFalse(any(name=='FlsFree' for name,args in kernel.calls))

if __name__=='__main__':unittest.main()
