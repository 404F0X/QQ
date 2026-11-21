"""Controlled normal-input composition; no device/API queries."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from qq_nt_replica.primary_qimei_beacon import QimeiBeaconInputProducer
from qq_nt_replica.primary_qimei_context import QimeiSelectorState
from qq_nt_replica.primary_qimei_observations import QimeiApiReply

class Inputs(unittest.TestCase):
    def test_order_partial_storage_and_brand_only(self):
        order=[]
        class Selector(QimeiSelectorState):
            def select(self,obs):order.append('selector');return b'ABCDEF'
        class Probe:
            def __init__(self,*,swap_serial):
                self.swap=swap_serial;self.outputs=[b'partial',b'',b'']
            def produce(self,obs):
                order.append(('storage',self.swap));return None
        class CPU:
            def read(self,namespace,name,leaf,subleaf,target):
                order.append((name,leaf,subleaf))
                raw=b'controlled-brand' if leaf==0x80000002 else bytes(16)
                return QimeiApiReply(0,(('data',0,raw),))
        with patch('qq_nt_replica.primary_qimei_beacon.NtStorageProbe',Probe):
            result=QimeiBeaconInputProducer(Selector(),object(),object(),CPU()).produce()
        self.assertEqual(result.storage,(b'partial',b'',b''))
        self.assertEqual((result.selector_status,result.storage_status,result.cpu_status),(1,0,1))
        self.assertEqual(result.brand,b'controlled-brand')
        self.assertEqual(order,['selector',('storage',True)]+[('CPUID',leaf,0) for leaf in (0x80000002,0x80000003,0x80000004)])
    def test_selector_exception_is_not_false_fallback(self):
        class Selector(QimeiSelectorState):
            def select(self,obs):raise RuntimeError('controlled unavailable')
        with self.assertRaisesRegex(RuntimeError,'controlled unavailable'):
            QimeiBeaconInputProducer(Selector(),object(),object(),object()).produce()

class Business(unittest.TestCase):
    def test_scan_carry_validation_earlywrite(self):
        import hashlib
        from qq_nt_replica.primary_qimei_beacon import BeaconInputs,validate,scan_pairs
        inputs=BeaconInputs(b'ABCDEF',(b's',b'm',b'f'),b'cpu',1,1,1)
        digest=lambda value:hashlib.md5(value).hexdigest().encode()
        old=(b'12gg'+b'00'*14,digest(b'ABCDEF'.hex().encode()).upper(),digest(b'smf'),digest(b'cpu'),0)
        output=bytearray(16)
        accepted,addcpu,unused=validate(inputs,old,output)
        self.assertFalse(accepted);self.assertFalse(addcpu)
        self.assertEqual(output[:2],b'\x12\x12')
        self.assertEqual(scan_pairs(b'gg'*16),bytes(16))
    def test_validation_accept_empty_and_unavailable_domains(self):
        import hashlib
        from qq_nt_replica.primary_qimei_beacon import BeaconInputs,validate
        from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
        inputs=BeaconInputs(b'ABCDEF',(b'',b'',b''),b'',1,0,0)
        selector=hashlib.md5(b'ABCDEF'.hex().encode()).hexdigest().upper().encode()
        output=bytearray(16)
        self.assertEqual(validate(inputs,(b'A1'*16,selector,b'',b'',1),output)[:2],(True,False))
        self.assertEqual(output,b'\xa1'*16)
        before=bytes(output)
        self.assertFalse(validate(inputs,(b'00'*16,b'',b'',b'',1),output)[0])
        self.assertEqual(output,before)
        with self.assertRaises(QimeiRequestBoundary):validate(inputs,(b'\xff'*32,selector,b'',b'',1),output)
    def test_denied_native_scope_precedes_library_and_stale_epoch(self):
        from qq_nt_replica.primary_windows_qimei_beacon import WindowsQimeiBeaconBackend
        from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
        from unittest.mock import patch
        epoch=object()
        with patch('ctypes.WinDLL',create=True,side_effect=AssertionError('native')):
            backend=WindowsQimeiBeaconBackend(object(),epoch,lambda runtime:epoch,permit=lambda *args:False)
            with self.assertRaises(QimeiRequestBoundary):backend.open_main()
            backend=WindowsQimeiBeaconBackend(object(),epoch,lambda runtime:object(),permit=lambda *args:True)
            with self.assertRaises(QimeiRequestBoundary):backend.read_outer()
    def test_existing_unbound_config_lazy_path_preserved(self):
        from qq_nt_replica.primary_qimei_transport_material import QimeiTransportGlobals
        calls=[]
        class Observations:
            def read(self,namespace,name,*args):
                calls.append(name)
                data=b'C:\\AppData\0' if name=='SHGetFolderPathA' else b'A'*32+b'\0'
                return QimeiApiReply(0,(('data',0,data),))
        globals=QimeiTransportGlobals(Observations())
        self.assertEqual(globals.config(),b'a'*32)
        self.assertEqual(globals.config(),b'a'*32)
        self.assertEqual(calls,['SHGetFolderPathA','GetPrivateProfileStringA'])
    def test_generation_once_refresh_lazy(self):
        from types import SimpleNamespace
        from qq_nt_replica.primary_qimei_beacon import BeaconInputs,QimeiBeacon
        from qq_nt_replica.primary_qimei_transport_material import QimeiTransportGlobals
        events=[]
        class Backend:
            outer=None
            def check(self):pass
            def open_main(self):events.append('open');return object(),b'RanMgr',0
            def persist(self,*args):events.append('persist')
            def close(self,token):events.append('close')
            def read_outer(self):return self.outer
        backend=Backend()
        def produce():events.append('inputs');return BeaconInputs(b'ABCDEF',(b's',b'm',b'f'),b'cpu',1,1,1)
        beacon=QimeiBeacon(SimpleNamespace(produce=produce),backend)
        globals=QimeiTransportGlobals(object(),beacon=beacon)
        first=globals.config()
        self.assertEqual(events,['inputs','open','persist','close'])
        backend.outer=b'A'*32
        self.assertEqual(globals.config(),first)
        self.assertEqual(globals.refresh_config(),b'a'*32)
        backend.outer=None
        self.assertEqual(globals.refresh_config(),first)
        self.assertEqual(events.count('inputs'),1)
    def test_public_operations_cannot_dispatch_arbitrary_native_args(self):
        import ctypes as C
        from qq_nt_replica.primary_windows_qimei_beacon import WindowsQimeiBeaconBackend
        from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
        epoch=object()
        class ABI(WindowsQimeiBeaconBackend):
            def __init__(self):
                super().__init__(object(),epoch,lambda runtime:epoch,permit=lambda *args:True)
                self.calls=[]
            def _call(self,*args):self.calls.append(args);return 1
        backend=ABI()
        for name,args in (('CreateFileA',(b'C:\\outside',)),('WriteFile',(456,b'controlled',10,None,None))):
            with self.subTest(api=name):
                with self.assertRaises(AttributeError):backend.api(name,C.c_int32,(),*args)
                self.assertEqual(backend.calls,[])
        for action in (lambda:backend.close(456),lambda:backend.persist(456,b'C:\\outside',bytes(16),(b'',b'',b'')),lambda:backend.read_config(b'C:\\outside')):
            with self.assertRaises(QimeiRequestBoundary):action()
            self.assertEqual(backend.calls,[])

    def test_windows_two_handles_exactbytes_unchecked_write(self):
        import ctypes as C
        from qq_nt_replica.primary_windows_qimei_beacon import WindowsQimeiBeaconBackend
        epoch=object()
        class ABI(WindowsQimeiBeaconBackend):
            def __init__(self):
                super().__init__(object(),epoch,lambda runtime:epoch,permit=lambda *args:True)
                self.calls=[];self.next=100
            def _call(self,library,name,result,types,*args):
                self.calls.append((name,args))
                if name=='SHGetFolderPathA':args[-1].value=b'C:\\AppData';return 0
                if name=='CreateFileA':self.next+=1;return self.next
                if name=='GetFileSize':return 1
                if name=='WriteFile':return 0
                return 1
        backend=ABI();handle,path,status=backend.open_main()
        self.assertEqual((path,status),(b'C:\\AppData\\Tencent\\qimei\\RanMgr.db',0x50))
        backend.persist(handle,path,bytes(16),(b'a',b'b',b''));backend.close(handle)
        writes=[args for name,args in backend.calls if name=='WriteFile']
        expected=b'[Profile]\r\nconfig1='+b'0'*32+b'\r\nconfig2=a\r\nconfig3=b\r\nconfig4=\r\nconfig5=1\r\n'
        self.assertEqual(writes[0][1:3],(expected,len(expected)))
        self.assertEqual([args[0] for name,args in backend.calls if name=='CloseHandle'],[102,101])
        with self.assertRaises(Exception):backend.close(handle)

if __name__=='__main__':unittest.main()
