import unittest
from qq_nt_replica.primary_windows_device_collection import WindowsDeviceCollectionObservations as Port
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable

class Fake:
    def __init__(self): self.calls=[]; self.closed=False
    def take(self,data,name,args): self.calls.append((data,name,args)); return 17,b'fixture'
    def close(self): self.closed=True
    def snapshot(self): return {'closed':self.closed}
    def cpuid(self,*args): return (1,2,3,4)

class CompositionTests(unittest.TestCase):
    def test_dispatch_lazy_helpers_and_close(self):
        first,second=Fake(),Fake(); sources=[]
        def source(): sources.append(Fake()); return sources[-1]
        p=Port(components=(first,second),source_factory=source,helpers={'filetime':lambda:123,'random_device_word':lambda:42,'ansi_to_utf8':lambda b:b})
        self.assertEqual(sources,[])
        data=object(); self.assertEqual(p.take(data,'fixture',()),(17,b'fixture'))
        self.assertEqual(second.calls,[])
        self.assertEqual(p.filetime(),123); self.assertEqual(p.random_device_word(),42); self.assertEqual(p.ansi_to_utf8(b'a'),b'a')
        self.assertEqual(p.cpuid(0),(1,2,3,4)); self.assertEqual(len(sources),1)
        p.close(); self.assertTrue(first.closed and second.closed and sources[0].closed)
    def test_default_helpers_lazy_and_random_closed(self):
        from unittest.mock import patch
        class Random(Fake):
            def random_bytes(self,size):
                self.calls.append(size); return bytes.fromhex('78563412')
        class Conversion:
            def __call__(self,value): return value+b'-utf8'
        random=Random()
        with patch('qq_nt_replica.primary_device_value_producer.WindowsDeviceValueEnvironment',return_value=random) as rf, patch('qq_nt_replica.primary_qimei_request.WindowsAnsiConversion',side_effect=Conversion) as af:
            p=Port(components=(Fake(),))
            rf.assert_not_called(); af.assert_not_called()
            self.assertEqual(p.random_device_word(),0x12345678)
            self.assertEqual(p.ansi_to_utf8(b'a'),b'a-utf8')
            self.assertEqual(p.random_device_word(),0x12345678)
            self.assertEqual(p.ansi_to_utf8(b'b'),b'b-utf8')
            self.assertEqual(random.calls,[4,4]); rf.assert_called_once(); af.assert_called_once()
            p.close(); self.assertTrue(random.closed)

    def test_existing_conversion_abi_and_filetime_chain(self):
        import ctypes
        from types import SimpleNamespace
        from unittest.mock import patch
        from qq_nt_replica.primary_qimei_request import WindowsAnsiConversion, QimeiRequestBoundary
        calls=[]
        class API:
            def MultiByteToWideChar(self,page,flags,source,length,target,capacity):
                calls.append((page,flags,length,bool(target),capacity))
                if target is not None: ctypes.memmove(target,b'A\0\0\0',4)
                return 2
            def WideCharToMultiByte(self,page,flags,source,length,target,capacity,*tail):
                calls.append((page,flags,length,bool(target),capacity))
                if target is not None: ctypes.memmove(target,b'A\0',2)
                return 2
        converter=WindowsAnsiConversion(API())
        p=Port()
        with patch('qq_nt_replica.primary_qimei_request.WindowsAnsiConversion',return_value=converter):
            self.assertEqual(p.ansi_to_utf8(b'A'),b'A')
        self.assertEqual([c[0] for c in calls],[0,0,65001,65001])
        self.assertTrue(all(c[1:3]==(0,-1) for c in calls))
        class Backend:
            _wlan_seen={}
            def request(self,name,args):
                self.observed=(name,args); return None,(123).to_bytes(8,'little'),0
            def close(self): pass
        backend=Backend(); p._components[2]._backend=backend
        data=SimpleNamespace(events=[])
        p._data=data
        self.assertEqual(p.filetime(),123)
        self.assertEqual(backend.observed,('GetSystemTimeAsFileTime',()))
        p.close()
        class BadAPI(API):
            def MultiByteToWideChar(self,*args): return 0
        with self.assertRaises(QimeiRequestBoundary): WindowsAnsiConversion(BadAPI())(b'A')

    def test_real_chain_cpuid_and_unsupported_are_lazy(self):
        from types import SimpleNamespace
        p=Port(source_factory=Fake)
        data=SimpleNamespace(events=[])
        result,effects=p.take(data,'CPUID',(1,0))
        self.assertEqual(result,0)
        self.assertEqual(effects,(1,2,3,4))
        with self.assertRaises(PrimarySemanticUnavailable):
            p.take(data,'not-a-supported-API',())
        self.assertTrue(all(getattr(c,'backend',getattr(c,'_backend',None)) is None for c in p._components))
        p.close()

    def test_boundary_and_failure_no_retry(self):
        class Failure(Fake):
            def take(self,*args): raise PrimarySemanticUnavailable('actual boundary')
            def close(self): self.calls.append('close'); raise RuntimeError('cleanup')
        f=Failure(); other=Fake(); p=Port(components=(f,other))
        with self.assertRaises(PrimarySemanticUnavailable): p.take(object(),'anything',())
        self.assertEqual(other.calls,[])
        with self.assertRaises(RuntimeError): p.close()
        with self.assertRaises(PrimarySemanticUnavailable): p.close()
        self.assertEqual(f.calls,['close']); self.assertTrue(other.closed)
        self.assertEqual(p.snapshot()['close_failures'],('RuntimeError',))

if __name__=='__main__': unittest.main()
