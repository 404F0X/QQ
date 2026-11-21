"""Controlled observations only; no Windows calls or account/file IO."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from qq_nt_replica.primary_windows_qimei_config import classify_version, architecture_class


class ConfigCases(unittest.TestCase):
    def test_source_version_thresholds(self):
        path=Path(__file__).parent/'data/qimei_config_source_cases.json'
        raw=path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'6a85668ff30f0764e6c54ea43d47e2ab1b992e223c2267e9e6230bf0198764b5')
        for case in json.loads(raw)['cases']:
            if case['group']!='windows_version':
                continue
            data=case['input']
            from qq_nt_replica.primary_windows_qimei_config import WindowsQimeiConfigSources,_Version
            class ABI(WindowsQimeiConfigSources):
                def _call(self,library,name,result,types,*args):
                    if name=='GetVersionExA':
                        output=C.cast(args[0],C.POINTER(_Version)).contents
                        output.major,output.minor,output.build=data['initial']
                        return data['get_version_ex_result']
                    if name=='GetModuleHandleA':return 1 if data.get('module_present',True) else 0
                    if name=='GetProcAddress':return 1 if data.get('proc_present',False) else 0
                    raise AssertionError(name)
                def _invoke_version(self,proc,major,minor,build):
                    for key,target in (('major',major),('minor',minor),('build',build)):
                        if key in data.get('rtl_writes',{}):target.value=data['rtl_writes'][key]
            epoch=object();reader=ABI(object(),epoch,lambda runtime:epoch,permit=lambda *args:True)
            with self.subTest(case=case['id']):
                self.assertEqual(reader.os_classification(),case['expected']['classification'])
        for case in json.loads(raw)['cases']:
            if case['group']=='architecture':
                self.assertEqual(architecture_class(case['input']['processor_architecture']),case['expected']['classification'])


class BusinessFlow(unittest.TestCase):
    def test_complete_controlled_request_and_settings_save(self, empty=False):
        import base64
        from types import SimpleNamespace
        from qq_nt_replica.primary_qimei_config_request import QimeiConfigRequest,ConfigHttpResponse
        from qq_nt_replica.primary_qimei_cache import _cbc
        from qq_nt_replica.primary_qimei_envelope import QimeiEnvelopeCodec,QimeiEnvelopeConfiguration
        from qq_nt_replica.primary_qimei_transport_codec import QimeiTransportCodec,DEFAULT_K,DEFAULT_IV
        from qq_nt_replica.primary_qimei_settings import QimeiSettings
        from qq_nt_replica.primary_qimei_transport_material import QimeiTransportMaterial
        events=[]
        codec=QimeiTransportCodec.__new__(QimeiTransportCodec)
        codec.random=SimpleNamespace(random_bytes=lambda count:b'A'*count)
        codec.clock=lambda:133000000000000000
        codec.crt=None
        class Settings(QimeiSettings):
            def refresh(self,**kwargs):events.append('refresh')
        settings=Settings(initialized=1)
        def produce(owner,kind,seq):
            self.assertEqual((owner,kind,seq),(b'owner',4,-1))
            return QimeiTransportMaterial((4,b'm',3,owner,b'v',b't',b'w',b'm',b'',b'c',b'b',b'n',seq))
        def send(request):
            outer=json.loads(request.body)
            self.assertEqual(outer['cpt'],'2')
            self.assertNotIn('ext',outer)
            self.assertNotIn('ky',outer)
            response=b'' if empty else b'\x0a\x03new\x10\x07'
            pad=16-len(response)%16
            body=json.dumps({'code':'0','data':base64.b64encode(_cbc(response+bytes([pad])*pad,DEFAULT_K,DEFAULT_IV)).decode()}).encode()
            events.append('HTTP')
            return ConfigHttpResponse(True,200,body)
        sources=SimpleNamespace(_check=lambda:None,clock=lambda:90000,wow64=lambda:1,
            os_classification=lambda:19,architecture=lambda:1)
        writer=SimpleNamespace(save=lambda path,data:events.append('save') or 0)
        handler=QimeiConfigRequest(b'owner',settings,sources,SimpleNamespace(produce=produce),
            envelope=QimeiEnvelopeCodec(),configuration=QimeiEnvelopeConfiguration(),transport=codec,
            http=SimpleNamespace(send=send),writer=writer,convert_ansi=lambda data:data,
            sign_enabled=False,sequence=0xffffffff)
        if empty:
            before=bytes(settings.record)
            self.assertFalse(handler.run())
            self.assertEqual(bytes(settings.record),before)
            self.assertEqual(settings.dirty,0)
            self.assertEqual(events,['refresh','HTTP'])
            self.assertEqual(handler.sequence,0x100000000)
            return
        self.assertTrue(handler.run())
        self.assertEqual(handler.sequence,0x100000000)
        self.assertEqual(settings.record[17:21],b'new\0')
        self.assertEqual(settings.record[49:53],b'\x07\0\0\0')
        self.assertEqual(settings.dirty,1)
        self.assertEqual(events,['refresh','HTTP','refresh','save'])
        self.assertFalse(handler.run())
        self.assertEqual(handler.sequence,0x100000000)

    def test_valid_empty_decoded_body_skips_consumer(self):
        self.test_complete_controlled_request_and_settings_save(empty=True)

class WriterABI(unittest.TestCase):
    def test_owned_file_and_acl_calls_cleanup_and_flags(self):
        from qq_nt_replica.primary_windows_qimei_settings_writer import WindowsQimeiSettingsWriterBackend
        from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
        from unittest.mock import patch
        epoch=object()
        class ABI(WindowsQimeiSettingsWriterBackend):
            def __init__(self):
                super().__init__(object(),epoch,lambda runtime:epoch,path=b'controlled',permit=lambda *args:True)
                self.calls=[];self.allocations={};self.refs=[];self.fail=None;self.free_status=0
            def _api(self,dll,name,result,types,*args):
                self.calls.append((name,args))
                if name==self.fail:return 0
                def output(ptr,kind,value):C.cast(ptr,C.POINTER(kind))[0]=value
                if name=='GetProcessHeap':return 123
                if name=='HeapAlloc':
                    self.assert_flags=args[1]
                    block=C.create_string_buffer(args[2]);raw=C.addressof(block);self.allocations[raw]=block;return raw
                if name=='HeapFree':self.allocations.pop(args[2]);return 1
                if name=='NetWkstaUserGetInfo':
                    text=C.create_unicode_buffer('controlled-user');info=(C.c_void_p*1)(C.addressof(text));self.refs.extend((text,info))
                    output(args[2],C.c_void_p,C.addressof(info));return 0
                if name=='NetApiBufferFree':return self.free_status
                if name=='MultiByteToWideChar':
                    if args[4] is None:return 11
                    args[4].value='controlled';return 11
                if name=='LookupAccountNameW':
                    if args[2] is None:
                        output(args[3],C.c_uint32,16);output(args[5],C.c_uint32,8);return 0
                    return 1
                if name=='GetFileSecurityW':
                    if args[2] is None:output(args[4],C.c_uint32,40);return 0
                    return 1
                if name=='GetSecurityDescriptorDacl':
                    output(args[1],C.c_int32,1);output(args[2],C.c_void_p,None);return 1
                if name=='GetLengthSid':return 16
                if name=='GetSecurityDescriptorControl':output(args[1],C.c_uint16,0x1400);return 1
                if name=='fopen':return 0x1234567887654321
                if name=='fwrite':return args[2]
                return 1
        backend=ABI()
        with self.assertRaises(QimeiRequestBoundary):backend.open_file(b'other')
        self.assertEqual(backend.calls,[])
        token=backend.open_file(b'controlled')
        self.assertEqual(backend.write_file(token,b'abc'),3)
        backend.close_file(token)
        with self.assertRaises(QimeiRequestBoundary):backend.write_file(token,b'abc')
        with patch('ctypes.get_last_error',create=True,return_value=122):
            self.assertEqual(backend.grant_same_file_access(b'controlled'),0)
        self.assertFalse(backend.allocations)
        calls={name:args for name,args in backend.calls}
        self.assertEqual(calls['AddAccessAllowedAceEx'][1:4],(2,3,0x10000000))
        self.assertEqual(calls['SetSecurityDescriptorControl'][1:],(0x500,0x500))
        self.assertEqual(calls['SetFileSecurityW'][1],4)
        self.assertEqual(backend.assert_flags,8)
        for failure in ('InitializeSecurityDescriptor','AddAccessAllowedAceEx','GetSecurityDescriptorControl','SetSecurityDescriptorControl','SetFileSecurityW'):
            backend=ABI();backend.fail=failure
            with patch('ctypes.get_last_error',create=True,return_value=122):
                self.assertEqual(backend.grant_same_file_access(b'controlled'),{'SetSecurityDescriptorControl':2,'SetFileSecurityW':3}.get(failure,1))
            self.assertFalse(backend.allocations)

        backend=ABI();backend.free_status=5
        with patch('ctypes.get_last_error',create=True,return_value=122):
            self.assertEqual(backend.grant_same_file_access(b'controlled'),0)
        retained=backend._WindowsQimeiSettingsWriterBackend__unfreed_netapi
        self.assertEqual(len(retained),1)
        self.assertEqual(retained[0].status,5)
        frees=[args for name,args in backend.calls if name=='NetApiBufferFree']
        self.assertEqual(len(frees),1)
        self.assertEqual(retained[0].raw,frees[0][0].value)


class NetApiRetention(unittest.TestCase):
    def test_failed_free_retains_pointer_and_status_without_retry(self):
        from qq_nt_replica.primary_windows_qimei_settings_writer import WindowsQimeiSettingsWriterBackend
        epoch=object()
        class ABI(WindowsQimeiSettingsWriterBackend):
            def __init__(self):
                super().__init__(object(),epoch,lambda runtime:epoch,path=b'controlled',permit=lambda *args:True)
                self.text=C.create_unicode_buffer('controlled-user')
                self.info=(C.c_void_p*1)(C.addressof(self.text));self.frees=0
            def _wide(self,path):return None
            def _api(self,dll,name,result,types,*args):
                if name=='GetProcessHeap':return 123
                if name=='NetWkstaUserGetInfo':
                    C.cast(args[2],C.POINTER(C.c_void_p))[0]=C.addressof(self.info);return 0
                if name=='NetApiBufferFree':self.frees+=1;return 5
                raise AssertionError(name)
        backend=ABI();backend.grant_same_file_access(b'controlled')
        retained=backend._WindowsQimeiSettingsWriterBackend__unfreed_netapi
        self.assertEqual(len(retained),1)
        self.assertEqual((retained[0].raw,retained[0].status),(C.addressof(backend.info),5))
        self.assertEqual(backend.frees,1)

class ScannerCases(unittest.TestCase):
    def test_count22_default3_and_missing_slots(self):
        from qq_nt_replica.primary_qimei_reply import parse_reply
        data=bytes([0xb0,1,7])
        original=parse_reply(data)
        config=parse_reply(data,count=22)
        self.assertEqual(len(original.slots),3)
        self.assertEqual(len(config.slots),22)
        self.assertEqual(config.slots[21].tag,4)
        self.assertEqual(config.slots[21].data,b'\x07\0\0\0')
        self.assertTrue(parse_reply(b'',count=22).accepted)

class SettingsFlow(unittest.TestCase):
    def test_refresh_update_clock_save_and_no_rollback(self):
        from qq_nt_replica.primary_qimei_settings import QimeiSettings
        from qq_nt_replica.primary_qimei_reply import ReplySlot
        from types import SimpleNamespace
        events=[]
        class Settings(QimeiSettings):
            def refresh(self,**kwargs):events.append('refresh')
        state=Settings(initialized=1)
        state.record[17:49]=b'T'*32
        state.record[49:561]=b'z'*512
        slots=[ReplySlot(1,b'name')]+[ReplySlot(4,(7).to_bytes(4,'little')),ReplySlot(99)]
        def clock():events.append('clock');return -1
        def save(path,record):
            events.append('save')
            self.assertEqual(record[9:17],b'\xff'*8)
            return 2
        state.update_response(slots,clock=clock,writer=SimpleNamespace(save=save))
        self.assertEqual(events,['refresh','clock','save'])
        self.assertEqual(state.record[49:57],b'\x07\0\0\0zzzz')
        self.assertEqual(state.dirty,0)
        self.assertEqual(state.record[17:49],b'name\0'+b'T'*27)

    def test_file_success_acl_failure_is_still_zero_and_deduplicated(self):
        from qq_nt_replica.primary_qimei_settings_writer import QimeiSettingsWriter
        from qq_nt_replica.primary_qimei_settings import RECORD_SIZE
        from types import SimpleNamespace
        events=[]
        backend=SimpleNamespace(validate_path=lambda path:events.append('validate'),
            open_file=lambda path:object(),write_file=lambda token,data:len(data),
            close_file=lambda token:events.append('close'),path_exists=lambda path:True,
            is_admin=lambda:True,grant_same_file_access=lambda path:events.append('ACL') or False)
        codec=SimpleNamespace(encode_payload=lambda data,context:SimpleNamespace(value=b'encoded'))
        writer=QimeiSettingsWriter(backend,codec,SimpleNamespace(produce=lambda obs:object()),None)
        for unused in range(2):self.assertEqual(writer.save(b'controlled',bytes(RECORD_SIZE)),0)
        self.assertEqual(events.count('ACL'),1)
        self.assertEqual(events.count('close'),2)
        for status in (1,2,3):
            events.clear()
            backend.grant_same_file_access=lambda path,status=status:events.append(status) or status
            writer=QimeiSettingsWriter(backend,codec,SimpleNamespace(produce=lambda obs:object()),None)
            for unused in range(2):self.assertEqual(writer.save(b'controlled',bytes(RECORD_SIZE)),0)
            self.assertEqual(events.count(status),1)


class ControlledConfigSources(unittest.TestCase):
    def test_clock_backing_and_lazy_scope(self):
        from qq_nt_replica.primary_windows_qimei_config import WindowsQimeiConfigSources
        from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
        epoch=object()
        source=WindowsQimeiConfigSources(object(),epoch,lambda runtime:epoch,permit=lambda *args:False)
        with self.assertRaises(QimeiRequestBoundary):source.clock()
        class ABI(WindowsQimeiConfigSources):
            def _call(self,library,name,result,types,*args):
                if name=='GetLocalTime':
                    C.cast(args[0],C.POINTER(C.c_uint16*8)).contents[:]=(2026,7,3,14,15,16,17,999)
                    return None
                self.tm=tuple(C.cast(args[0],C.POINTER(C.c_int32*9)).contents)
                return -1
        source=ABI(object(),epoch,lambda runtime:epoch,permit=lambda *args:True)
        self.assertEqual(source.clock(),-1)
        self.assertEqual(source.tm,(17,16,15,14,6,126,0,0,0))

if __name__=='__main__': unittest.main()
