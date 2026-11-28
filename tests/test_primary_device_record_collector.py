import unittest
from qq_nt_replica.primary_device_record_collector import DeviceCollectionState
from qq_nt_replica.primary_memory import UnknownMemory
class DataState(unittest.TestCase):
    def test_source_constructor_unknown_tail_and_own_strings(self):
        state=DeviceCollectionState()
        try:
            self.assertFalse(state.warm);self.assertEqual(state.read(0x88,24),bytes(24))
            with self.assertRaises(UnknownMemory):state.read(0x1000,1)
            state.set_string(0x88,b'long-source-value'*8)
            snapshot=state.snapshot()
            try:
                state.set_string(0x88,b'changed')
                state.close() # snapshot owns its copied buffers after owner retirement
                from qq_nt_replica.primary_logger import _String
                self.assertEqual(_String.read(snapshot.storage,snapshot.address+0x80).value(),b'long-source-value'*8)
                with self.assertRaises(UnknownMemory):snapshot.storage.memory.read(snapshot.address+0x1000,1)
            finally:snapshot.close()
        finally:state.close()
        self.assertEqual(state.storage.buffers,set())

    def test_wmi_source_order_mapping_and_empty_retention(self):
        from types import SimpleNamespace as NS
        from qq_nt_replica.primary_device_record_collector import collect_wmi_fields
        from qq_nt_replica.primary_device_wmi import _image,_COLLECTORS
        from qq_nt_replica.primary_windows_wmi_session import WmiQueryResult,WmiPropertyResult
        calls=[];state=DeviceCollectionState();spec=_image()['collectors'][str(_COLLECTORS[0])]
        retained=spec['writes'][0]['offset'];state.set_string(retained,b'prior')
        class Session:
            def query_first(self,identity):
                calls.append(identity)
                if identity!=_COLLECTORS[0]:return WmiQueryResult('no_object',0,1,0,())
                props=[]
                for i,wide in enumerate(spec['properties_hex']):
                    raw=bytes.fromhex(wide);key=raw.decode('utf-16le').encode('ascii')
                    props.append(WmiPropertyResult(raw,key,0,8,'empty' if i==0 else 'value',b'' if i==0 else b'actual-control'))
                return WmiQueryResult('row',0,0,1,tuple(props))
        try:
            collect_wmi_fields(state,Session());self.assertEqual(calls,list(_COLLECTORS));self.assertEqual(state.string(retained),b'prior');self.assertFalse(state.warm)
            self.assertTrue(any(state.string(w['offset'])==b'actual-control' for w in spec['writes'][1:]))
        finally:state.close()

    def test_owned_identifiers_delete_three_read_generate_persist_warm_reuse(self):
        from qq_nt_replica.primary_device_provenance import collect_owned_identifiers
        from qq_nt_replica.primary_device_collector import generate_material_bytes
        from qq_nt_replica.primary_device_identifiers import identifier_digest_text
        calls=[]
        class Stores:
            def __init__(self):self.values={}
            def delete_registry(self,key):calls.append(('delete',key));self.values.pop(('registry',key),None)
            def flush_cache(self):calls.append(('flush',))
            def __getattr__(self,name):
                kind,domain=name.split('_')
                def call(key,*values):
                    calls.append((name,key))
                    if kind=='read':return self.values.get((domain,key))
                    self.values[domain,key]=values[0]
                return call
        stores=Stores();state=DeviceCollectionState();generated=[]
        def generate(raw):
            generated.append(raw)
            return generate_material_bytes(raw,filetime=12345678,random_device_word=42,ansi_to_utf8=lambda value:value)
        try:
            collect_owned_identifiers(state,stores,generate=generate)
            value=state.string(0x558);self.assertTrue(value);self.assertEqual(state.string(0x570),value);self.assertEqual(state.string(0x588),value)
            self.assertEqual(state.string(0x5B8),identifier_digest_text(value));self.assertEqual(state.string(0x5E8),identifier_digest_text(identifier_digest_text(value)))
            self.assertEqual(calls[0][0],'delete');self.assertEqual(sum(c[0]=='read_config' for c in calls),9);self.assertIn(('flush',),calls)
            collect_owned_identifiers(state,stores,generate=generate);self.assertEqual(len(generated),1)
        finally:state.close()

    def test_own_xml_uses_existing_parser_grammar(self):
        from qq_nt_replica.primary_device_cache import serialize_owned_cache_xml
        from qq_nt_replica.primary_device_cache_xml import parse_owned_cache_xml
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        values={b'z':b'a"b&c',b'a':b'line\nfeed'}
        encoded=serialize_owned_cache_xml(values);success,pairs=parse_owned_cache_xml(encoded)
        self.assertTrue(success);self.assertEqual(dict(pairs),values)
        with self.assertRaises(PrimarySemanticUnavailable):parse_owned_cache_xml(b'<!-- comment --><root />')

    def test_own_registry_namespace_is_explicit_not_source_redirect(self):
        from qq_nt_replica.primary_windows_device_collection import OwnIdentifierStores,WindowsOwnIdentifierRegistry
        from qq_nt_replica.errors import InputError
        calls=[]
        class Registry:
            def delete(self,path,key):calls.append((path,key));return True
            def read(self,path,key):calls.append((path,key));return b'value'
        stores=OwnIdentifierStores('G:/controlled-only','sample-state',registry=Registry())
        self.assertTrue(stores.delete_registry(b'installStatus'));self.assertEqual(stores.read_registry(b'installFlag'),b'value')
        self.assertEqual(calls,[(r'Software\404F0X\QQReplica\Signature\sample-state',b'installStatus'),(r'Software\404F0X\QQReplica\Signature\sample-state',b'installFlag')])
        with self.assertRaises(InputError):WindowsOwnIdentifierRegistry()._namespace(r'SOFTWARE\Tencent\QQProtect')

class ControlledCollectionPort:
    """External IO fixture, never substitutes collector/helper mathematics."""
    def __init__(self):self.calls=[]
    def take(self,data,name,args):
        self.calls.append((name,args))
        if name=='AllocateAndInitializeSid':return 0,(b'',)
        if name=='GetTickCount64':return 1000,b''
        if name=='GetSystemTimeAsFileTime':return 0,(self.filetime().to_bytes(8,'little'),)
        if name in ('GetSystemTime','GetLocalTime'):return 0,(bytes(16),)
        if name=='GetDynamicTimeZoneInformation':return 0xFFFFFFFF,(b'',)
        if name in ('GetSystemDefaultLocaleName','GetLocaleInfoEx'):return 0,(b'',)
        if name=='WideCharToMultiByte':return 1,b'\0'
        if name=='GetVolumeInformationA':return 0,(b'',b'',b'',b'',b'')
        if name=='GetDiskFreeSpaceExA':return 0,(b'',b'')
        if name=='PowerGetActiveScheme':return 1,(bytes(8),())
        if name=='GetVolumePathNameA':return 0,(b'',)
        if name=='GetSystemFirmwareTable':return 0,b''
        if name=='GetCurrentProcessId':return 123,b''
        if name=='GetProcessTimes':return 0,(b'',b'',b'',b'')
        if name=='QueryFullProcessImageNameW':return 0,(b'',b'')
        if name=='GetCommandLineW':return 0,()
        if name=='GetCurrentDirectoryW':return 0,b''
        if name=='MultiByteToWideChar':return 1,b'\0\0'
        if name=='GetModuleHandleA':return 0,b''
        if name=='RegOpenKeyExA':return 2,(b'',)
        if name=='GetCurrentProcess':return (1<<64)-1,b''
        if name in ('GetModuleHandleW','LoadLibraryA','LoadLibraryExW'):return 100,b''
        if name=='GetProcAddress':return 101,b''
        if name=='FreeLibrary':return 1,b''
        if name=='IsWow64Process':return 1,bytes(4)
        if name=='GetVersionExW':
            raw=bytearray(284);raw[:4]=(284).to_bytes(4,'little');raw[4:8]=(10).to_bytes(4,'little');raw[12:16]=(19045).to_bytes(4,'little');return 1,bytes(raw)
        if name=='GetProductInfo':return 1,(48).to_bytes(4,'little')
        if name in ('GetComputerNameA','GetUserNameA'):return 1,(b'controlled-name\0',15)
        if name=='GetCurrentHwProfileA':return 0,b''
        if name=='GetNativeSystemInfo':return 0,bytes(48)
        if name=='GetSystemInfo':return 0,bytes(48)
        if name=='GetCursorPos':return 1,bytes(8)
        if name in ('GetKeyboardType','IsDebuggerPresent','GetSystemDefaultLCID','GetSystemMetrics','GetTickCount'):return 0,b''
        if name=='GetLastError':return 5,b''
        if name=='CPUID':return 0,(0,0,0,0)
        if name=='GetWindowsDirectoryA':return 10,b'C:\\Windows\0'
        if name=='CreateFileA':return (1<<64)-1,b''
        if name=='EnumDisplaySettingsW':return 0,b''
        if name=='GlobalMemoryStatusEx':
            raw=bytearray(64);raw[:4]=(64).to_bytes(4,'little');return 1,bytes(raw)
        if name=='GetSystemPowerStatus':return 0,b''
        if name=='GetSystemDirectoryW':return 19,'C:\\Windows\\System32\0'.encode('utf-16le')
        if name=='WlanOpenHandle':return 0,(2,777)
        if name=='WlanEnumInterfaces':
            raw=bytearray(540);raw[:4]=(1).to_bytes(4,'little');return 0,(0x7e00000000,bytes(raw))
        if name=='WlanQueryInterface':
            raw=bytearray(604);raw[:4]=(1).to_bytes(4,'little');raw[520:524]=(3).to_bytes(4,'little');raw[524:527]=b'one';return 0,(0x7e00010000,bytes(raw),604,3)
        if name=='WlanGetAvailableNetworkList':
            raw=bytearray(628);raw[:4]=(1).to_bytes(4,'little');raw[520:524]=(3).to_bytes(4,'little');raw[524:527]=b'one';return 0,(0x7e00020000,bytes(raw))
        if name in ('WlanFreeMemory','WlanCloseHandle'):return 0,b'' 
        if name=='GetAdaptersInfo':
            if not args[1]:return 111,(b'',704)
            raw=bytearray(704);raw[12:17]=b'eth0\0';raw[272:276]=b'NIC\0';raw[404:408]=(6).to_bytes(4,'little');raw[408:414]=bytes([2,3,4,5,6,7]);raw[420:424]=(6).to_bytes(4,'little');raw[448:457]=b'10.0.0.1\0';return 0,(bytes(raw),704)
        if name=='CallNtPowerInformation':return 1,b''
        raise AssertionError('external fixture API not declared: '+name+' '+repr(args))
    def display_environment(self):
        class Environment:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def sample(self,index):return (2,1920,1080) if index==0 else (0,0,0)
        return Environment()
    def filetime(self):return 132000000000000000
    def random_device_word(self):return 42
    def ansi_to_utf8(self,raw):return raw

class CompleteCollection(unittest.TestCase):
    def test_controlled_normal_collection(self):
        from qq_nt_replica.primary_device_record_collector import IndependentDeviceRecordCollector
        from qq_nt_replica.primary_windows_wmi_session import WmiQueryResult
        class Session:
            def query_first(self,identity):
                from qq_nt_replica.primary_device_wmi import _image
                from qq_nt_replica.primary_windows_wmi_session import WmiPropertyResult
                props=[]
                for encoded in _image()['collectors'][str(identity)]['properties_hex']:
                    raw=bytes.fromhex(encoded);key=raw.decode('utf-16le').encode('ascii')
                    props.append(WmiPropertyResult(raw,key,0,8,'value',b'controlled WMI '+key*3))
                return WmiQueryResult('row',0,0,1,tuple(props))
            def close(self):pass
        class Stores:
            def delete_registry(self,key):pass
            def flush_cache(self):return True
            def __getattr__(self,name):return lambda *args: b'controlled-persisted' if name.startswith('read_') else None
        collector=IndependentDeviceRecordCollector(ControlledCollectionPort(),Stores(),sdk_fields={0x30:b'',0x48:b'CONTROLLED',0x78:b'1'},wmi_factory=Session)
        try:
            snapshot=collector._capture_snapshot()
            try:
                ansi_calls=[]
                def convert(raw):ansi_calls.append(raw);return raw.replace(b'controlled',b'converted')
                records=snapshot.records(version=b'1',device_value=b'CONTROLLED-KEY25',sdk_fields=collector.operations.sdk_fields,ansi_to_utf8=convert)
                self.assertTrue(ansi_calls)
                self.assertTrue(any(b'converted' in value for key,value in records))
                self.assertEqual(len(records),137)
                self.assertTrue(collector.state.warm)
                self.assertEqual(collector.operations.feature22,1)
                self.assertEqual(dict(records)[28],b'')
                self.assertEqual(collector.state.string(0x6E0),b'one')
                self.assertEqual(collector.state.string(0x6F8),b'[one]')
                from qq_nt_replica.primary_device_records import _schema
                self.assertEqual([key for key,value in records],[f['key'] for f in _schema()['fields']])
            finally:snapshot.close()
            count=len(collector.operations.port.calls)
            snapshot=collector._capture_snapshot();snapshot.close()
            second=collector.operations.port.calls[count:]
            self.assertEqual([name for name,args in second[:3]],['GlobalMemoryStatusEx','GetCursorPos','GetSystemPowerStatus'])
            self.assertNotIn('GetVersionExW',[name for name,args in second])
            self.assertIn('GetSystemDirectoryW',[name for name,args in second])
            from qq_nt_replica.primary_request_material import RequestMaterial,RequestMaterialState
            from qq_nt_replica.primary_request_random import RequestRandom
            raw=bytearray(168);raw[:32]=bytes(range(32));raw[32:48]=b'\xff'*16;raw[48:80]=bytes(range(32));raw[81]=1;raw[129:162]=b'\x02'+bytes(32)
            material=RequestMaterialState(RequestMaterial(bytes(raw)),random=RequestRandom(123))
            request=collector.create_request(version=b'1',device_value=b'CONTROLLED-KEY25',ansi_to_utf8=lambda raw:raw,metadata=b'controlled-metadata',feature46=0,tag=b'device',material_state=material,sdk_sequence=19,a2=False,commands=(b'a',b'b',b'c',b'd'),encoding_inputs=dict(wall_seconds=lambda:1,monotonic_ns=lambda:1))
            self.assertTrue(request.body);self.assertEqual(request.sdk_sequence,19)
            self.assertIn(b'CONTROLLED-KEY25',request.serialized_records)
            boundary=RuntimeError('controlled ANSI failure')
            def fail_conversion(raw):raise boundary
            with self.assertRaises(RuntimeError) as caught:
                collector.collect(version=b'1',device_value=b'CONTROLLED-KEY25',ansi_to_utf8=fail_conversion)
            self.assertIs(caught.exception,boundary)
        finally:collector.close()
        self.assertFalse(collector.state.storage.buffers)

    def test_unknown_adapter_fallback_is_boundary_not_empty_success(self):
        from qq_nt_replica.primary_device_record_collector import IndependentDeviceRecordCollector
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.primary_windows_wmi_session import WmiQueryResult
        class Port(ControlledCollectionPort):
            def take(self,data,name,args):
                if name=='GetAdaptersInfo':return 50,(b'',0)
                return super().take(data,name,args)
        class Session:
            def query_first(self,identity):return WmiQueryResult('no_object',0,1,0,())
            def close(self):pass
        collector=IndependentDeviceRecordCollector(Port(),None,sdk_fields={0x30:b'',0x48:b'CONTROLLED',0x78:b'1'},wmi_factory=Session)
        try:
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'0x1be9020'):collector._capture_snapshot()
            self.assertFalse(collector.state.warm)
        finally:collector.close()
        self.assertFalse(collector.state.storage.buffers)

    def test_wmi_close_failure_prevents_warm_and_is_not_retried(self):
        from qq_nt_replica.primary_device_record_collector import IndependentDeviceRecordCollector
        from qq_nt_replica.primary_windows_wmi_session import WmiQueryResult
        error=RuntimeError('controlled close failure');calls=[]
        class Session:
            def query_first(self,identity):return WmiQueryResult('no_object',0,1,0,())
            def close(self):calls.append('close');raise error
        collector=IndependentDeviceRecordCollector(ControlledCollectionPort(),None,sdk_fields={0x30:b'',0x48:b'CONTROLLED',0x78:b'1'},wmi_factory=Session)
        try:
            with self.assertRaises(RuntimeError) as caught:collector._capture_snapshot()
            self.assertIs(caught.exception,error);self.assertEqual(calls,['close']);self.assertFalse(collector.state.warm)
        finally:collector.close()
        self.assertEqual(calls,['close']);self.assertFalse(collector.state.storage.buffers)

    def test_legacy_import_guards_are_preserved(self):
        from types import SimpleNamespace
        from qq_nt_replica.primary_memory import PrimaryMemory
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica import primary_device_cold,primary_device_system,primary_device_refresh,primary_device_adapters
        runtime=SimpleNamespace(worker_imports={},memory=PrimaryMemory(),image_base=0x180000000)
        for module in (primary_device_cold,primary_device_system,primary_device_refresh,primary_device_adapters):
            with self.assertRaises(PrimarySemanticUnavailable):module._observe(runtime,'unbound',())

    def test_business_and_cleanup_failures_preserve_both_objects(self):
        from qq_nt_replica.primary_device_record_collector import IndependentDeviceRecordCollector
        primary=RuntimeError('controlled query error');cleanup=OSError('controlled close error');calls=[]
        class Session:
            def query_first(self,identity):raise primary
            def close(self):calls.append('close');raise cleanup
        collector=IndependentDeviceRecordCollector(ControlledCollectionPort(),None,sdk_fields={0x30:b'',0x48:b'CONTROLLED',0x78:b'1'},wmi_factory=Session)
        try:
            with self.assertRaises(BaseExceptionGroup) as caught:collector._capture_snapshot()
            self.assertEqual(caught.exception.exceptions,(primary,cleanup));self.assertFalse(collector.state.warm)
        finally:collector.close()
        self.assertEqual(calls,['close']);self.assertFalse(collector.state.storage.buffers)
