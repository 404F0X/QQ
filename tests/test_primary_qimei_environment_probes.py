import unittest,ctypes as C
from types import SimpleNamespace as NS
from unittest.mock import Mock,patch
from qq_nt_replica.primary_qimei_environment_probes import *
from qq_nt_replica.primary_qimei_kind2_payload import populate_flag1_group
from qq_nt_replica.primary_qimei_request import QimeiRequestState,RequestSlot,QimeiRequestBoundary
from qq_nt_replica.primary_qimei_settings import QimeiSettings
from qq_nt_replica.primary_qimei_observations import QimeiApiReply
from qq_nt_replica.primary_windows_qimei_environment import WindowsQimeiEnvironment
class Port:
    def __init__(self,hit=None,resolve=(7,),bit=True):self.hit=hit;self.resolves=list(resolve);self.calls=[];self.bit=bit
    def resolve_redirection(self):self.calls.append('resolve');return self.resolves.pop(0) if len(self.resolves)>1 else self.resolves[0]
    def redirect(self,p,v):self.calls.append(('redirect',p,v));return 0
    def path_exists(self,p):self.calls.append(p);return 256 if p==self.hit else 0
    def cpuid_leaf1(self):self.calls.append('cpu');return (0,0,0x80000000 if self.bit else 0,0)
class Probes(unittest.TestCase):
    def test_all_files_and_registry_order_cache_and_null_retry(self):
        self.assertEqual(len(VMWARE_FILES),12);self.assertTrue(VMWARE_FILES[8].endswith(b'.dl'));self.assertTrue(VMWARE_FILES[9].endswith(b'.dl'))
        for paths,method in ((VMWARE_FILES,'vmware'),(VBOX_FILES,'virtualbox')):
            for index,path in enumerate(paths):
                port=Port(path);system=Mock();probe=QimeiEnvironmentProbes(RedirectionCache(port),system)
                self.assertEqual(getattr(probe,method)(),1);self.assertEqual([x for x in port.calls if type(x)is bytes],list(paths[:index+1]));system.registry_value.assert_not_called()
                self.assertEqual([x[-1] for x in port.calls if type(x)is tuple],[False,True])
        port=Port(resolve=(0,7));system=Mock();system.registry_value.return_value=(1,StorageBuffer(bytes(260)));cache=RedirectionCache(port);probe=QimeiEnvironmentProbes(cache,system)
        self.assertEqual(probe.vmware(),0);self.assertEqual([c.args[:2] for c in system.registry_value.call_args_list],list(REGISTRY_PROBES));probe.virtualbox();self.assertEqual(port.calls.count('resolve'),2)
        self.assertTrue(cache.normal_tail_completed)
    def test_registry_case_boundary_and_no_invented_exception_tail(self):
        for i in range(6):
            port=Port();system=Mock();system.registry_value.side_effect=[(n%4+1,StorageBuffer(bytes(260))) for n in range(i)]+[(0,StorageBuffer(b'xxVMware\0'+bytes(251)))]
            self.assertEqual(QimeiEnvironmentProbes(RedirectionCache(port),system).vmware(),1);self.assertEqual(system.registry_value.call_count,i+1)
        system=Mock();system.registry_value.return_value=(0,StorageBuffer(b'vmware\0'+bytes(253)))
        self.assertEqual(QimeiEnvironmentProbes(RedirectionCache(Port()),system).vmware(),0)
        port=Port();cache=RedirectionCache(port);system.registry_value.return_value=(0,StorageBuffer(b'X'*260))
        with self.assertRaises(QimeiRequestBoundary):QimeiEnvironmentProbes(cache,system).vmware()
        self.assertFalse(cache.normal_tail_completed);self.assertEqual([x[-1] for x in port.calls if type(x)is tuple],[False])
    def test_whole_group_actual_refresh_and_preservation(self):
        for flag in (0,1):
            settings=QimeiSettings();settings.initialize(b'owner',NS(read=lambda *a:QimeiApiReply(0)))
            data=bytearray(0x459);data[0]=3;data[0x25D:0x261]=flag.to_bytes(4,'little')
            read=Mock(return_value=b'cipher');producer=NS(produce=Mock(return_value=b'context'));codec=NS(decode_payload=Mock(return_value=NS(source_code=0,payload=bytes(data))))
            port=Port(hit=VMWARE_FILES[0]);probe=QimeiEnvironmentProbes(RedirectionCache(port),Mock());state=QimeiRequestState([RequestSlot() for _ in range(48)]);state.set_u32(1,9)
            deps=dict(read_file=read,codec=codec,context_producer=producer,observations=object())
            for _ in range(2):populate_flag1_group(b'owner',state,settings,probe,settings_dependencies=deps)
            self.assertEqual(read.call_count,1);self.assertEqual(producer.produce.call_count,1)
            self.assertEqual([i+1 for i,s in enumerate(state.slots) if s.data is not None],[1,25,26,30,31] if flag else [1])
            if flag:self.assertEqual([int.from_bytes(state.slots[i].data,'little') for i in (24,25,29,30)],[3,1,1,0])
            else:self.assertEqual(port.calls,[])
        self.assertEqual(QimeiEnvironmentProbes(RedirectionCache(Port(bit=False)),Mock()).cpuid_pair(),(0,0))
        state=QimeiRequestState([RequestSlot() for _ in range(48)]);probes=NS(cpuid_pair=lambda:(0,0),vmware=lambda:0xFFFF0001,virtualbox=lambda:0x12340000)
        populate_flag1_group(b'o',state,NS(flag=lambda *a,**kw:-1),probes);self.assertEqual(state.slots[29].data,b'\1\0\0\0');self.assertEqual(state.slots[30].data,bytes(4))
    def test_backend_own_fixed_pointer_and_borrowed_cpu(self):
        api=NS(GetModuleHandleA=Mock(return_value=9),GetProcAddress=Mock(return_value=17),PathFileExistsA=Mock(return_value=256));cpu=NS(read=Mock(return_value=QimeiApiReply(0,(('data',0,bytes(16)),))),close=Mock())
        port=WindowsQimeiEnvironment(api=api,cpu_observations=cpu);self.assertEqual(port.resolve_redirection(),17);api.GetProcAddress.assert_called_once_with(9,b'Wow64EnableWow64FsRedirection')
        with patch('ctypes.WINFUNCTYPE',return_value=lambda ptr:lambda enabled:0,create=True):self.assertEqual(port.redirect(17,False),0)
        with self.assertRaises(QimeiRequestBoundary):WindowsQimeiEnvironment(api=api,cpu_observations=cpu).redirect(17,False)
        self.assertEqual(port.cpuid_leaf1(),(0,0,0,0));self.assertEqual(cpu.read.call_args.args[:4],('qimei-api','CPUID',1,0));port.close();cpu.close.assert_not_called()
        with self.assertRaises(QimeiRequestBoundary):port.path_exists(b'x')

    def test_reused_registry_reader_errors_signed_size_and_exact_key_scope(self):
        from qq_nt_replica.primary_qimei_system_sources import QimeiSystemSources,HKLM
        from qq_nt_replica.primary_windows_qimei_system import WindowsQimeiSystemObservations
        for error in (0,1,2,3,4):
            calls=[]
            class Obs:
                def read(self,namespace,name,*args):
                    calls.append(name)
                    if name=='RegOpenKeyExA':
                        selftest.assertEqual(args[0],HKLM);selftest.assertEqual(args[3],0x101)
                        return QimeiApiReply(1 if error==1 else 0,(('handle',0,(1).to_bytes(8,'little')),))
                    if name=='RegCloseKey':return QimeiApiReply(0)
                    selftest.assertIsNone(args[3])
                    if args[4] is None:return QimeiApiReply(2 if error==2 else 0,(('size',0,(261 if error==3 else 8).to_bytes(4,'little')),))
                    return QimeiApiReply(4 if error==4 else 0,(('data',0,b'VMware\0'),))
            selftest=self;system=QimeiSystemSources(Obs());code,data=system.registry_value(SYSTEM_INFORMATION_KEYS[0],b'SystemManufacturer',StorageBuffer(bytes(260)))
            self.assertEqual(code,error);self.assertEqual(calls[-1],'RegCloseKey')
        for key in SYSTEM_INFORMATION_KEYS:
            self.assertTrue(WindowsQimeiSystemObservations._allowed_registry(None,HKLM,key));self.assertTrue(WindowsQimeiSystemObservations._allowed_value(None,key,b'SystemProductName'));self.assertFalse(WindowsQimeiSystemObservations._allowed_value(None,key,b'Unknown'))
    def test_owned_CPU_close_failure_is_not_resource_zero_or_retry(self):
        error=RuntimeError('controlled VirtualFree failure');cpu=NS(read=Mock(return_value=QimeiApiReply(0,(('data',0,bytes(16)),))),close=Mock(side_effect=error))
        port=WindowsQimeiEnvironment()
        with patch('qq_nt_replica.primary_windows_qimei_request_sources.WindowsQimeiRequestObservations',return_value=cpu):self.assertEqual(port.cpuid_leaf1(),(0,0,0,0))
        with self.assertRaises(RuntimeError) as raised:port.close()
        self.assertIs(raised.exception,error);self.assertTrue(port.cleanup_failed)
        with self.assertRaises(QimeiRequestBoundary):port.close()
        self.assertEqual(cpu.close.call_count,1)

    def test_flag2_classifier_priority_full_values_and_independent_flags(self):
        from qq_nt_replica.primary_qimei_kind2_payload import populate_flag2_group
        for local,remote,kernel,registers,expected,count in (
            (256,1,(0,b'\0\0'),(1,(1,0,0,0)),1,1),
            (None,256,(0,b'\0\0'),(1,(1,0,0,0)),2,2),
            (0,None,(0,b'\xff\0'),(1,(1,0,0,0)),3,3),
            (0,0,(-1,b'\0\0'),(256,(0,0,1<<63,0)),6,4),
            (0,0,(0,b'\0\1'),(0,(1,2,3,4)),0,4),
            (None,None,None,(1,(0,0,0,0)),0,4)):
            calls=[]
            def result(name,value):
                def invoke():calls.append(name);return value
                return invoke
            port=NS(debugger_present=result('local',local),remote_debugger=result('remote',remote),kernel_debugger=result('kernel',kernel),debug_registers=result('registers',registers))
            self.assertEqual(QimeiEnvironmentProbes(RedirectionCache(port),Mock()).debugger(),expected);self.assertEqual(len(calls),count)
        settings=NS(flag=Mock(side_effect=[0,0x80000000]));state=QimeiRequestState([RequestSlot() for _ in range(48)]);probe=Mock();probe.debugger.return_value=0xFEDCBA98
        populate_flag1_group(b'o',state,settings,probe);populate_flag2_group(b'o',state,settings,probe)
        self.assertEqual(settings.flag.call_args_list,[unittest.mock.call(1,group=1),unittest.mock.call(2,group=1)])
        self.assertEqual(state.slots[26].data,b'\x98\xba\xdc\xfe');probe.cpuid_pair.assert_not_called()

    def test_debugger_port_ABI_release_order_and_borrowed_cache(self):
        events=[]
        def lookup(handle,name):events.append(('lookup',name));return {b'Wow64EnableWow64FsRedirection':17,b'IsDebuggerPresent':21,b'CheckRemoteDebuggerPresent':22,b'NtQuerySystemInformation':23}[name]
        def free(handle):events.append(('free',handle));return 1
        def context(thread,pointer):
            address=pointer.value;self.assertEqual(address%16,0);self.assertEqual(C.string_at(address,0x30),bytes(0x30));self.assertEqual(C.c_uint32.from_address(address+0x30).value,0x10001F)
            self.assertEqual(C.string_at(address+0x34,0x4D0-0x34),bytes(0x4D0-0x34));C.c_uint64.from_address(address+0x58).value=1<<63;return 256
        api=NS(GetModuleHandleA=Mock(return_value=9),GetProcAddress=Mock(side_effect=lookup),PathFileExistsA=Mock(),LoadLibraryA=Mock(side_effect=lambda name:events.append(('load',name)) or 9),FreeLibrary=Mock(side_effect=free),GetCurrentProcess=Mock(return_value=-1),GetCurrentThread=Mock(return_value=-2),GetThreadContext=Mock(side_effect=context))
        port=WindowsQimeiEnvironment(api=api);self.assertEqual(port.resolve_redirection(),17)
        def prototype(*types):
            def pointer(ptr):
                def invoke(*args):
                    events.append(('call',ptr))
                    if ptr==22:C.cast(args[1],C.POINTER(C.c_uint32))[0]=256;return 0
                    if ptr==23:
                        self.assertEqual(args[0],0x23);self.assertEqual(args[2],2);self.assertEqual(C.string_at(args[1],2),bytes(2));self.assertEqual(C.cast(args[3],C.POINTER(C.c_uint32))[0],0);return -1
                    return 0
                return invoke
            return pointer
        with patch('ctypes.WINFUNCTYPE',side_effect=prototype,create=True):
            self.assertEqual(port.debugger_present(),0);self.assertEqual(port.remote_debugger(),256);self.assertEqual(port.kernel_debugger(),(-1,bytes(2)))
            self.assertEqual(port.debug_registers(),(256,(0,0,1<<63,0)));self.assertEqual(port.redirect(17,True),0)
        self.assertEqual([x[1] for x in events if x[0]=='load'],[b'kernel32.dll',b'kernel32.dll',b'ntdll.dll'])
        for ptr in (21,22,23):self.assertEqual(events[events.index(('call',ptr))+1],('free',9))
        self.assertEqual(port._procedure,17);self.assertEqual(port._owned_refs,[]);port.close()
        # Missing export still releases, NULL module never resolves or releases.
        for handle in (0,9):
            api.LoadLibraryA.return_value=handle;api.LoadLibraryA.side_effect=None;api.GetProcAddress.side_effect=None;api.GetProcAddress.return_value=0;api.FreeLibrary.reset_mock();api.GetProcAddress.reset_mock()
            other=WindowsQimeiEnvironment(api=api);self.assertIsNone(other.debugger_present());self.assertEqual(api.FreeLibrary.call_count,int(bool(handle)));self.assertEqual(api.GetProcAddress.call_count,int(bool(handle)));other.close()

    def test_debugger_exception_preserved_and_host_close_releases_owned_ref(self):
        error=RuntimeError('controlled export exception')
        api=NS(LoadLibraryA=Mock(return_value=5),GetProcAddress=Mock(side_effect=error),FreeLibrary=Mock(return_value=1),GetCurrentProcess=Mock(),GetCurrentThread=Mock(),GetThreadContext=Mock())
        port=WindowsQimeiEnvironment(api=api)
        with self.assertRaises(RuntimeError) as raised:port.debugger_present()
        self.assertIs(raised.exception,error);api.FreeLibrary.assert_not_called();self.assertEqual(port._owned_refs,[5]);port.close();api.FreeLibrary.assert_called_once_with(5)
