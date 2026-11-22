"""Controlled source map ABI; no process attach or native execution."""
import unittest
from test_primary_outer_init import Runtime
from qq_nt_replica.primary_logger import _String
from qq_nt_replica.primary_memory import UnknownMemory
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from qq_nt_replica.primary_login_host_init import empty_tree,insert_directory,copy_directory_tree,destroy_directory_tree

class DirectoryMap(unittest.TestCase):
    def test_literal_tree_independent_copy_padding_and_cleanup(self):
        r=Runtime();m=r.memory;header=0x7900000000;copy=header+0x100
        for p in (header,copy):m.map(p,bytearray(24),name="controlled map header",initialized=False)
        empty_tree(r,header)
        nodes=[]
        for key,raw in ((6,b'Emoji'),(9,b'Log'),(10,b'msf'),(11,b'Login')):
            value=_String.construct(r,raw);nodes.append(insert_directory(r,header,key,value));value.destroy()
        self.assertEqual(m.load(header+16,8),4)
        self.assertEqual(m.load(m.load(header+8,8)+32,4),9)
        for node in nodes:
            for offset,size in ((25,7),(36,4)):
                with self.assertRaises(UnknownMemory):m.read(node+offset,size)
        copy_directory_tree(r,header,copy)
        self.assertNotEqual(m.load(copy+8,8),m.load(header+8,8))
        destroy_directory_tree(r,copy);destroy_directory_tree(r,header)
        self.assertFalse(r._custom_allocator_backend.records)

class Producers(unittest.TestCase):
    def test_actual_model_birth_hostname_directory_and_no_lazy_target(self):
        from test_primary_login_msf_prefix import SelectionChecks
        from qq_nt_replica.primary_login_host_init import publish_hostname,msf_directory
        from qq_nt_replica.primary_login_model_attach import require_complete
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from unittest.mock import patch
        from types import SimpleNamespace
        signer=SelectionChecks().fixture();r=signer.runtime;m=r.memory;b=r.image_base
        receipt=SimpleNamespace(epoch_address=r.tls_epoch_address)
        with patch('qq_nt_replica.primary_shared_locale.resolve_current_module_tls',return_value=receipt):
            host=_String.construct(r,b'host')
            address=publish_hostname(r,host)
            self.assertEqual(_String.read(r,address).value(),b'host');host.destroy()
            path=_String.construct(r,b'C:\\data\\nt_data')
            result=msf_directory(r,path)
            self.assertEqual(result.value(),b'C:\\data\\nt_data\\msf')
            result.destroy();path.destroy()
        before=set(r._custom_allocator_backend.records)
        with self.assertRaises(PrimarySemanticUnavailable):require_complete(r)
        self.assertEqual(m.load(b+0x6752b68,8),0)
        self.assertEqual(set(r._custom_allocator_backend.records),before)

class AttachPhase(unittest.TestCase):
    def test_failed_ctor_retains_unpublished_allocation(self):
        from unittest.mock import patch
        from contextlib import ExitStack
        from pathlib import Path
        from qq_nt_replica import primary_windows_signer as windows
        from qq_nt_replica.primary_sign import PrimaryRuntime
        from qq_nt_replica.primary_windows_allocator_issuer import WindowsAllocatorIssuer
        from qq_nt_replica import primary_login_model_attach as attach
        from types import SimpleNamespace
        import threading
        constructors=('WindowsCallerAPIBackend','WindowsCallerBridge','WindowsCallerObservations','WindowsProviderObservations','WindowsWorkerObservations','WindowsDeviceFileObservations','WindowsCoreObservations')
        observed=[];owners=[]
        def allocator(owner):
            owners.append(owner)
            r=owner._signer.runtime
            issuer=WindowsAllocatorIssuer.__new__(WindowsAllocatorIssuer)
            issuer.owner=owner;issuer.epoch=object();issuer.source=SimpleNamespace(_borrow=None)
            r._primary_allocator_issuer=issuer
        def crt_thread(r):
            r.crt_thread_address=0x7980000000
            return r.crt_thread_address
        def invoke(r,rva,*args):
            observed.append((rva,args))
            if rva==0xb75000:
                pointer=0x7990000000;r.memory.map(pointer,bytearray(24),name='controlled C6 allocation',initialized=False)
                region,offset=r.memory._span(pointer,24)
                r._custom_allocator_backend.records[pointer]=(region,24,r._primary_allocator_issuer.epoch,threading.get_ident(),'CUSTOM')
                return pointer
            self.assertEqual(rva,0x6270)
            self.assertEqual(r.memory.load(r.image_base+0x6752b68,8),0)
            raise RuntimeError('controlled C6 constructor unavailable')
        with ExitStack() as stack:
            stack.enter_context(patch.object(windows,'_validated_paths',return_value=(Path('controlled.dll'),Path('controlled'))))
            for name in constructors:stack.enter_context(patch.object(windows,name))
            from test_primary_creator_domain import PhysicalKernel
            import ctypes as C
            stack.enter_context(patch.object(C,'WinDLL',return_value=PhysicalKernel()))
            stack.enter_context(patch.object(C,'CDLL',side_effect=AssertionError('no actual DLL')))
            stack.enter_context(patch.object(windows.DeviceFactory,'windows'))
            stack.enter_context(patch.object(windows.WindowsSigner,'_host_environment',return_value=(b'C:/explicit/p.exe',None,())))
            stack.enter_context(patch.object(windows.WindowsSigner,'_initialize_notification_statics'))
            stack.enter_context(patch('qq_nt_replica.primary_windows_allocator_issuer.install_early_allocator',side_effect=allocator))
            stack.enter_context(patch.object(WindowsAllocatorIssuer,'validate'))
            stack.enter_context(patch.object(PrimaryRuntime,'_crt_call',return_value=1))
            stack.enter_context(patch.object(PrimaryRuntime,'_crt_thread',crt_thread))
            stack.enter_context(patch.object(attach,'_invoke',side_effect=invoke))
            stack.enter_context(patch.object(windows.WindowsSigner,'close'))
            stack.enter_context(patch.object(windows.WindowsSigner,'diagnostics',new=property(lambda actual:{})))
            with self.assertRaisesRegex(RuntimeError,'controlled C6 constructor unavailable') as caught:
                windows.open_windows_signer(bridge_path='controlled.dll',storage_root='controlled',host_profile_string=b'explicit-model-profile',primary_backend='direct')
            owner=owners[0];r=owner._signer.runtime
            record=attach._PHASES[id(r)]
            self.assertEqual(r.memory.load(r.image_base+0x6749cc0,8),0x24)
            self.assertEqual(record['state'],'failed')
            self.assertIs(record['failure'],caught.exception)
            self.assertEqual(record['pointer'],0x7990000000)
            self.assertIn(record['pointer'],r._custom_allocator_backend.records)
            self.assertEqual(r.memory.load(r.image_base+0x6752b68,8),0)
            with self.assertRaises(UnknownMemory):r.memory.read(record['pointer'],24)
            with self.assertRaises(PrimarySemanticUnavailable):attach.require_complete(r)

    def _scoped_native_port_case(self,failure=None,stdio_transform=None,stdio_failure=False,stage_failure=None,defer_terminal=False):
        from unittest.mock import patch
        from contextlib import ExitStack
        from pathlib import Path
        from qq_nt_replica import primary_windows_signer as windows
        from qq_nt_replica.primary_sign import PrimaryRuntime
        from qq_nt_replica.primary_windows_allocator_issuer import WindowsAllocatorIssuer
        from qq_nt_replica import primary_login_model_attach as attach
        from types import SimpleNamespace
        import threading
        constructors=('WindowsCallerAPIBackend','WindowsCallerBridge','WindowsCallerObservations','WindowsProviderObservations','WindowsWorkerObservations','WindowsDeviceFileObservations','WindowsCoreObservations')
        observed=[];stage_owners=[]
        def allocator(owner):
            stage_owners.append(owner)
            r=owner._signer.runtime
            issuer=WindowsAllocatorIssuer.__new__(WindowsAllocatorIssuer)
            issuer.owner=owner;issuer.epoch=r._custom_allocator_backend.source.epoch;issuer.source=SimpleNamespace(_borrow=None)
            r._primary_allocator_issuer=issuer
        def crt_thread(r):
            r.crt_thread_address=0x7980000000
            if stage_failure=='thread':raise RuntimeError('controlled stdio prerequisite failure')
            if stage_failure=='write':
                original=r.memory.store
                def store(*args,**kwargs):
                    result=original(*args,**kwargs)
                    if kwargs.get('source')=='3E6BA7C.MODEL_stdio_OR24':raise RuntimeError('controlled stdio OR observation failure')
                    return result
                r.memory.store=store
            return r.crt_thread_address
        def invoke(r,rva,*args):
            observed.append((rva,args))
            if rva==0xb75000:
                pointer=0x7990000000;r.memory.map(pointer,bytearray(24),name='controlled C6 allocation',initialized=False)
                region,offset=r.memory._span(pointer,24)
                r._custom_allocator_backend.records[pointer]=(region,24,r._primary_allocator_issuer.epoch,threading.get_ident(),'CUSTOM')
                return pointer
            self.assertEqual(rva,0x6270)
            self.assertEqual(r.memory.load(r.image_base+0x6752b68,8),0)
            r.memory.store(args[0],0,2,source='controlled6270')
        with ExitStack() as stack:
            stack.enter_context(patch.object(windows,'_validated_paths',return_value=(Path('controlled.dll'),Path('controlled'))))
            for name in constructors:stack.enter_context(patch.object(windows,name))
            from test_primary_creator_domain import PhysicalKernel
            import ctypes as C
            stack.enter_context(patch.object(C,'WinDLL',return_value=PhysicalKernel()))
            stack.enter_context(patch.object(C,'CDLL',side_effect=AssertionError('no actual DLL')))
            stack.enter_context(patch.object(windows.DeviceFactory,'windows'))
            stack.enter_context(patch.object(windows.WindowsSigner,'_host_environment',return_value=(b'C:/explicit/p.exe',None,())))
            stack.enter_context(patch.object(windows.WindowsSigner,'_initialize_notification_statics'))
            stack.enter_context(patch('qq_nt_replica.primary_windows_allocator_issuer.install_early_allocator',side_effect=allocator))
            stack.enter_context(patch.object(WindowsAllocatorIssuer,'validate'))
            stack.enter_context(patch.object(PrimaryRuntime,'_crt_call',return_value=1))
            stack.enter_context(patch.object(PrimaryRuntime,'_crt_thread',crt_thread))
            stack.enter_context(patch.object(attach,'_invoke',side_effect=invoke))
            stack.enter_context(patch('qq_nt_replica.primary_windows_signer_setup.IndependentWindowsSetup'))
            if stage_failure:
                with patch.object(windows.WindowsSigner,'close'),patch.object(windows.WindowsSigner,'diagnostics',new=property(lambda actual:{})):
                    with self.assertRaisesRegex(RuntimeError,'controlled stdio'):
                        windows.open_windows_signer(bridge_path='controlled.dll',storage_root='controlled',host_profile_string=b'explicit-model-profile',primary_backend='direct',outer_login_config={},outer_sync_permit=lambda actual,operation:True)
                r=stage_owners[0].signer.runtime
                from qq_nt_replica import primary_crt_stdio_options as options
                self.assertEqual(observed,[])
                self.assertEqual(r.memory.load(r.image_base+0x6749cc0,8),0 if stage_failure=='thread' else 0x24)
                if stage_failure=='thread':self.assertNotIn(id(r),options._PHASES)
                else:self.assertEqual(options._PHASES[id(r)]['state'],'failed')
                with self.assertRaises(PrimarySemanticUnavailable):options.read_options(r)
                return
            owner=windows.open_windows_signer(bridge_path='controlled.dll',storage_root='controlled',host_profile_string=b'explicit-model-profile',primary_backend='direct',outer_login_config={},outer_sync_permit=lambda actual,operation:True)
            r=owner.signer.runtime;m=r.memory;b=r.image_base
            r.next=0x7b00000000;r.calls=[];r.fail_size=None;r.epoch=r._custom_allocator_backend.source.epoch
            r.invoke=Runtime.invoke.__get__(r,type(r))
            for rva,size in ((0x6745268,8),(0x6745280,8),(0x67451d4,1)):
                m.map(b+rva,bytearray(size),name='controlled prior Login birth',initialized=True)
            from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost,for_runtime
            from qq_nt_replica.primary_outer_init import get_login_service
            import ctypes as C
            calls=[]
            def api(actual,name,result,types,*arguments):
                calls.append(name)
                if name=='InitializeCriticalSectionAndSpinCount':
                    if failure=='init_api':raise RuntimeError('controlled MMKV native failure')
                    self.assertEqual(arguments[1],400);C.memset(arguments[0],0x5a,40);return 0 if failure=='init_false' else 1
                if name=='GetLastError':return 5
                if name=='GetSystemInfo':
                    C.memset(arguments[0],0,48);C.c_uint32.from_address(arguments[0]+4).value=8192;return
                if name=='DeleteCriticalSection':return
                raise AssertionError(name)
            receipt=SimpleNamespace(epoch_address=r.tls_epoch_address,image_epoch=object())
            from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
            from test_primary_mmkv_stdio import fake_ucrt
            stdio_calls=[];stdio_functions=fake_ucrt(stdio_calls)
            if stdio_transform is not None:stdio_functions=stdio_transform(stdio_functions,r,stdio_calls)
            with patch.object(WindowsMMKVStdio,'_load',return_value=stdio_functions),patch.object(WindowsMMKVHost,'_api',api),patch('qq_nt_replica.primary_shared_locale.resolve_current_module_tls',return_value=receipt),owner._registrar.operation():
                service=get_login_service(owner)
                with patch('qq_nt_replica.primary_outer_init._global_sync',return_value=1):
                    with self.assertRaisesRegex(RuntimeError if failure=='init_api' or stdio_failure else PrimarySemanticUnavailable,'controlled MMKV native failure' if failure=='init_api' else ('controlled stdio' if stdio_failure else '1BD8F45')):
                        service.initConfig(dict(commonPath='C:\\data',clientVer='v',machineId='machine',platVer='p',hostName='h'))
                self.assertEqual(calls,['InitializeCriticalSectionAndSpinCount'] if failure=='init_api' else (['InitializeCriticalSectionAndSpinCount','GetLastError','GetSystemInfo'] if failure=='init_false' else ['InitializeCriticalSectionAndSpinCount','GetSystemInfo']))
                lock=m.load(b+0x6751390,8);cache=m.load(b+0x6751388,8)
                self.assertEqual(m.read(lock,40),bytes(40) if failure=='init_api' else b'Z'*40)
                with self.assertRaises(UnknownMemory):m.read(cache+36,4)
                self.assertEqual(m.load(b+0x67513c8,4),1 if failure=='init_api' or stdio_failure else 2)
                obj=m.load(b+0x674c730,8);self.assertEqual(m.read(obj+0x90,16),bytes(16))
                from qq_nt_replica.primary_memory import PrimaryMemoryLimit
                with self.assertRaises(PrimaryMemoryLimit):m.unmap(lock)
                service.release_wrappers()
            if defer_terminal:return dict(runtime=r,stdio_calls=stdio_calls,owner=owner,mmkv_api=api)
            owner._state='closing'
            port=for_runtime(r)
            if stdio_failure:
                from qq_nt_replica.primary_windows_mmkv_stdio import for_runtime as stdio_for_runtime
                stdio_port=stdio_for_runtime(r)
                with self.assertRaises(PrimarySemanticUnavailable):stdio_port.dispose_terminal()
                self.assertTrue(stdio_port._WindowsMMKVStdio__records)
                self.assertTrue(stdio_port._WindowsMMKVStdio__failures)
                # Only private controlled functions ran: release test pins, no production recovery.
                for token,(view,native) in tuple(stdio_port._WindowsMMKVStdio__pins.items()):
                    m._unpin_native_span(token,stdio_port);view.release()
                lock_backing=port._WindowsMMKVHost__lock
                m._unpin_native_span(lock_backing.token,port);lock_backing.view.release()
                return dict(runtime=r,stdio_calls=stdio_calls,owner=owner)
            with patch.object(WindowsMMKVHost,'_api',api):
                if failure=='init_api':
                    with self.assertRaises(PrimarySemanticUnavailable):port.dispose_terminal()
                elif failure=='delete_record':
                    with patch.object(m,'_record_native_write',side_effect=RuntimeError('controlled MMKV write failure')):
                        with self.assertRaisesRegex(RuntimeError,'controlled MMKV write failure'):port.dispose_terminal()
                    with self.assertRaises(PrimarySemanticUnavailable):port.dispose_terminal()
                    self.assertEqual(calls.count('DeleteCriticalSection'),1)
                else:
                    port.dispose_terminal()
                    if failure=='init_false':
                        self.assertNotIn('DeleteCriticalSection',calls)
                        log=[event for event in r.events if event[0]=='1BDF22C.arguments' and event[1]==3][-1]
                        self.assertEqual(log[1:],(3,b'ThreadLock_Win32.cpp',b'initialize',0x29,b'fail to init critical section:%d',(5,)))
                    else:self.assertEqual(calls[-1],'DeleteCriticalSection')
            if failure in ('init_api','delete_record'):
                with self.assertRaises(PrimaryMemoryLimit):m.unmap(lock)
                # Only controlled private API ran; release test-owned view, never a production recovery.
                backing=port._WindowsMMKVHost__lock
                m._unpin_native_span(backing.token,port);backing.view.release()
            m._assert_no_native_pin(lock,40)
            from qq_nt_replica.primary_windows_mmkv_stdio import for_runtime as stdio_for_runtime
            stdio_for_runtime(r).dispose_terminal()
            return dict(runtime=r,stdio_calls=stdio_calls,owner=owner)


    def test_scoped_native_port_same_buffer_options_stop_and_terminal(self):
        self._scoped_native_port_case()

    def test_native_api_and_terminal_record_failures_retain_backing(self):
        for failure in ('init_api','delete_record','init_false'):
            with self.subTest(failure=failure):self._scoped_native_port_case(failure)


    def test_real_factory_crt_call_chain_with_controlled_host_and_allocator(self):
        from unittest.mock import patch
        from contextlib import ExitStack
        from pathlib import Path
        from qq_nt_replica import primary_windows_signer as windows
        from qq_nt_replica.primary_sign import PrimaryRuntime
        from qq_nt_replica.primary_windows_allocator_issuer import WindowsAllocatorIssuer
        from qq_nt_replica import primary_login_model_attach as attach
        from types import SimpleNamespace
        import threading
        constructors=('WindowsCallerAPIBackend','WindowsCallerBridge','WindowsCallerObservations','WindowsProviderObservations','WindowsWorkerObservations','WindowsDeviceFileObservations','WindowsCoreObservations')
        observed=[]
        def allocator(owner):
            r=owner._signer.runtime
            issuer=WindowsAllocatorIssuer.__new__(WindowsAllocatorIssuer)
            issuer.owner=owner;issuer.epoch=object();issuer.source=SimpleNamespace(_borrow=None)
            r._primary_allocator_issuer=issuer
        def crt_thread(r):
            r.crt_thread_address=0x7980000000
            return r.crt_thread_address
        def invoke(r,rva,*args):
            observed.append((rva,args))
            if rva==0xb75000:
                pointer=0x7990000000;r.memory.map(pointer,bytearray(24),name='controlled C6 allocation',initialized=False)
                region,offset=r.memory._span(pointer,24)
                r._custom_allocator_backend.records[pointer]=(region,24,r._primary_allocator_issuer.epoch,threading.get_ident(),'CUSTOM')
                return pointer
            self.assertEqual(rva,0x6270)
            self.assertEqual(r.memory.load(r.image_base+0x6752b68,8),0)
            r.memory.store(args[0],0,2,source='controlled6270')
        with ExitStack() as stack:
            stack.enter_context(patch.object(windows,'_validated_paths',return_value=(Path('controlled.dll'),Path('controlled'))))
            for name in constructors:stack.enter_context(patch.object(windows,name))
            from test_primary_creator_domain import PhysicalKernel
            import ctypes as C
            stack.enter_context(patch.object(C,'WinDLL',return_value=PhysicalKernel()))
            stack.enter_context(patch.object(C,'CDLL',side_effect=AssertionError('no actual DLL')))
            stack.enter_context(patch.object(windows.DeviceFactory,'windows'))
            stack.enter_context(patch.object(windows.WindowsSigner,'_host_environment',return_value=(b'C:/explicit/p.exe',None,())))
            stack.enter_context(patch.object(windows.WindowsSigner,'_initialize_notification_statics'))
            stack.enter_context(patch('qq_nt_replica.primary_windows_allocator_issuer.install_early_allocator',side_effect=allocator))
            stack.enter_context(patch.object(WindowsAllocatorIssuer,'validate'))
            stack.enter_context(patch.object(PrimaryRuntime,'_crt_call',return_value=1))
            stack.enter_context(patch.object(PrimaryRuntime,'_crt_thread',crt_thread))
            stack.enter_context(patch.object(attach,'_invoke',side_effect=invoke))
            owner=windows.open_windows_signer(bridge_path='controlled.dll',storage_root='controlled',host_profile_string=b'explicit-model-profile',primary_backend='direct')
            r=owner.signer.runtime
            self.assertEqual(observed,[(0xb75000,(24,)),(0x6270,(0x7990000000,))])
            self.assertEqual(attach.require_complete(r),0x7990000000)
            with self.assertRaises(UnknownMemory):r.memory.read(0x7990000002,22)
            from qq_nt_replica.errors import InputError
            with self.assertRaises(InputError):attach._run_login_model_attach(owner)
            # Extend through the real public prefix with explicit model source inputs.
            # The allocator/TLS/CS are controlled ports, not Windows execution proof.
            from qq_nt_replica.primary_outer_init import get_login_service
            from types import SimpleNamespace
            r.next=0x7b00000000;r.calls=[];r.fail_size=None;r.epoch=r._primary_allocator_issuer.epoch
            r.invoke=Runtime.invoke.__get__(r,type(r))
            for rva,size in ((0x6745268,8),(0x6745280,8),(0x67451d4,1)):
                r.memory.map(r.image_base+rva,bytearray(size),name='controlled prior Login birth',initialized=True)
            receipt=SimpleNamespace(epoch_address=r.tls_epoch_address,image_epoch=object())
            with patch('qq_nt_replica.primary_shared_locale.resolve_current_module_tls',return_value=receipt):
                service=get_login_service(owner)
                with patch('qq_nt_replica.primary_outer_init._global_sync',return_value=1):
                    with self.assertRaisesRegex(PrimarySemanticUnavailable,'MMKV scoped native host'):
                        service.initConfig(dict(commonPath='C:\\data',clientVer='v',machineId='machine',platVer='p',hostName='h'))
                self.assertEqual(_String.read(r,attach.require_complete(r)).value(),b'C:\\data\\nt_data\\msf')
                self.assertEqual(_String.read(r,r.image_base+0x674c6f0).value(),b'h')
                self.assertEqual(r.memory.load(r.image_base+0x67535d0,4),2)
                obj=r.memory.load(r.image_base+0x674c730,8)
                self.assertEqual(r.memory.read(obj+0x90,16),bytes(16))
                self.assertEqual(service.state,'UNAVAILABLE');service.release_wrappers()


class WideRoot(unittest.TestCase):
    def test_exact_long_root_and_independent_global_copy(self):
        from qq_nt_replica.primary_mmkv_host_init import construct_wide_root,copy_wide_root_fresh,destroy_wide_root
        r=Runtime();m=r.memory;frame=0x7c00000000
        m.map(frame,bytearray(72),name='controlled wide root locals',initialized=False)
        raw=b'C:\\data\\nt_data\\mmkv';value=_String.construct(r,raw);value.write_to(frame)
        start=len(m.writes)
        construct_wide_root(r,frame+24,frame)
        pointer=m.load(frame+40,8);size=len(raw);capacity=(max(size,20)|7)+1
        self.assertEqual(m.load(frame+24,8),capacity|1)
        self.assertEqual(m.read(pointer,2*(size+1)),raw.decode('ascii').encode('utf-16-le')+bytes(2))
        writes=[row[0] for row in m.writes[start:] if len(row[1])==8]
        self.assertLess(writes.index(frame+40),writes.index(frame+24))
        self.assertEqual(writes[-1],frame+32)
        r.memory.store(frame+48,0,2,source='controlled fresh global wide')
        copy_wide_root_fresh(r,frame+48,frame+24)
        second=m.load(frame+64,8);self.assertNotEqual(pointer,second)
        destroy_wide_root(r,frame+24)
        self.assertEqual(m.read(second,2*size),raw.decode('ascii').encode('utf-16-le'))
        destroy_wide_root(r,frame+48);value.destroy()
        self.assertFalse(r._custom_allocator_backend.records)

class FixedFormatting(unittest.TestCase):
    def test_literal_and_cstring_growth_keep_distinct_free_publish_order(self):
        from qq_nt_replica.primary_native_logger import _append
        for literal in (True,False):
            r=Runtime();m=r.memory;address=0x7d00000000
            m.map(address,bytearray(24),name='controlled formatter output',initialized=False)
            value=_String.construct(r,b'A'*47);value.write_to(address)
            old=value.get(16,8);original=r.invoke;observed=[]
            def invoke(vm,rva,cells):
                args=tuple(vm.cells.value(i) for i in cells)
                if rva==0xb75029:
                    self.assertEqual(m.load(address+16,8),old)
                    new=max(r._custom_allocator_backend.records)
                    if literal:
                        with self.assertRaises(UnknownMemory):m.read(new+47,2)
                    else:self.assertEqual(m.read(new+47,2),b'ZZ')
                    observed.append(args)
                return original(vm,rva,cells)
            r.invoke=invoke
            start=len(m.writes);_append(value,address,b'ZZ',literal=literal)
            self.assertEqual(value.value(),b'A'*47+b'ZZ')
            relevant=[row[2] for row in m.writes[start:] if row[2].endswith(('.buffer','.capacity','.length','.NUL'))]
            self.assertEqual(relevant[-2:],['508834.NUL','508834.length'] if literal else ['75C180.length','75C180.NUL'])
            self.assertEqual(observed,[(old,)])
            r.invoke=original;value.destroy()
            self.assertFalse(r._custom_allocator_backend.records)


    def test_both_fixed_templates_growth_decimal_and_cleanup(self):
        from test_primary_login_msf_prefix import SelectionChecks
        from qq_nt_replica.primary_native_logger import _format_fixed
        signer=SelectionChecks().fixture();r=signer.runtime
        raw=b'C:\\long_component\\nt_data'
        value=_String.construct(r,raw)
        output=_format_fixed(r,b'InitConfig, commonPath: {}, clientVer: {}, machineId: {}, platVer: {}',(('String',value),('cstring',b'v'),('cstring',b'm'),('cstring',b'p')))
        self.assertEqual(output.value(),b'InitConfig, commonPath: '+raw+b', clientVer: v, machineId: m, platVer: p')
        outer=_format_fixed(r,b'[{}] {}({})::{} {}',(('cstring',b'I'),('cstring',b'login_service.cc'),('integer',-297),('cstring',b'initConfig'),('String',output)))
        self.assertEqual(outer.value(),b'[I] login_service.cc(-297)::initConfig '+output.value())
        outer.destroy();output.destroy();value.destroy()
        self.assertFalse(r._custom_allocator_backend.records)

if __name__=='__main__':unittest.main()
