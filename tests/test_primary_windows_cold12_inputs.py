"""Pure full-path API doubles; never calls the Windows backend."""
import ctypes as C
import unittest
from unittest.mock import patch
from qq_nt_replica.primary_windows_cold12_inputs import WindowsCold12Inputs, _Backend
from qq_nt_replica.errors import InputError


class Backend:
    def __init__(self,versions=((10,0),(10,0)),statuses=(0,0),family_node=None,version_result=1,address4=bytes(4),address6=bytes(15)+b'\x01'):
        self.address4=address4;self.address6=address6
        self.versions=iter(versions);self.statuses=iter(statuses);self.family_node=family_node;self.calls=[];self.closed=False;self.entropy_calls=0;self.version_result=version_result
    def entropy4(self):self.entropy_calls+=1;return (5489).to_bytes(4,'little')
    def call(self,name,result,types,values):
        self.calls.append((name,types,values[:3] if name=='GetAdaptersAddresses' else ()))
        if name=='GetVersionExW':
            self.assert_size=C.c_uint32.from_buffer(values[0]).value
            major,minor=next(self.versions)
            C.c_uint32.from_buffer(values[0],4).value=major;C.c_uint32.from_buffer(values[0],8).value=minor
            return self.version_result
        family,flags,reserved,output,size=values
        assert flags==0x80 and reserved is None
        status=next(self.statuses)
        if status==0x6F:C.cast(size,C.POINTER(C.c_uint32))[0]=20000
        if status:return status
        start=C.addressof(output)
        # Only+D0 selected entry is populated. A same-family distractor at+18 must be ignored.
        C.c_uint64.from_buffer(output,0x18).value=start+0x380
        C.c_uint64.from_buffer(output,0x390).value=start+0x3C0
        C.c_uint16.from_buffer(output,0x3C0).value=family
        C.memmove(start+0x3C0+(4 if family==2 else 8),b'\x01'*(4 if family==2 else 16),4 if family==2 else 16)
        if self.family_node is not False:
            C.c_uint64.from_buffer(output,0xD0).value=start+0x200
            C.c_uint64.from_buffer(output,0x208).value=start+0x380
            C.c_uint64.from_buffer(output,0x210).value=start+0x300
            C.c_uint16.from_buffer(output,0x300).value=family if self.family_node is None else self.family_node
            begin=0x304 if family==2 else 0x308
            C.memmove(start+begin,self.address4 if family==2 else self.address6,4 if family==2 else 16)
        return 0
    def close(self):self.closed=True


class WindowsInputs(unittest.TestCase):
    def test_version_gates_and_borrowed_lifetime(self):
        backend=Backend(versions=((5,1),(5,2)),version_result=0)
        provider=WindowsCold12Inputs(backend=backend)
        self.assertEqual(provider.host_marker(),1)
        self.assertEqual([x[0] for x in backend.calls],['GetVersionExW']*2)
        self.assertEqual(backend.assert_size,0x114)
        provider.close();self.assertFalse(backend.closed)
        with self.assertRaises(InputError):provider.entropy4()

    def test_selected_node_resize_failure_and_ipv6_zero_filter(self):
        cases=[(bytes(16),(0x6F,0,0),None,1),(bytes(15)+b'\x01',(0,0),None,3),
               (bytes(16),(5,5),None,0),(bytes(16),(0,0),False,0),
               (bytes(16),(0,0),99,0),(bytes(16),(0x6F,0x6F,5),None,0)]
        for address6,statuses,node,want in cases:
            with self.subTest(address6=address6,statuses=statuses,node=node):
                backend=Backend(statuses=statuses,family_node=node,address6=address6)
                provider=WindowsCold12Inputs(backend=backend)
                self.assertEqual(provider.host_marker(),want)
                gaa=[x for x in backend.calls if x[0]=='GetAdaptersAddresses']
                self.assertEqual(gaa[0][2],(2,0x80,None));self.assertEqual(gaa[-1][2],(23,0x80,None))
                if statuses==(5,5):self.assertEqual(provider.records,[('GetVersionExW',1),('GetAdaptersAddresses',2,5),('GetVersionExW',1),('GetAdaptersAddresses',23,5)])
                provider.close()

    def test_entropy_word_per_byte_and_independent_padding_seed(self):
        backend=Backend();provider=WindowsCold12Inputs(backend=backend)
        self.assertEqual(provider.entropy4(),(5489).to_bytes(4,'little'))
        self.assertEqual(provider.padding_bytes(3),bytes(v&255 for v in (3499211612,581869302,3890346734)))
        self.assertEqual(provider.padding_bytes(3),bytes(v&255 for v in (3586334585,545404204,4161255391)))
        self.assertEqual(backend.entropy_calls,2)
        provider.close()
        backend=Backend();backend.entropy4=lambda:b'bad'
        with self.assertRaises(InputError):WindowsCold12Inputs(backend=backend).entropy4()
        def entropy_failure():raise OSError('entropy unavailable')
        backend.entropy4=entropy_failure
        with self.assertRaises(OSError):WindowsCold12Inputs(backend=backend).entropy4()

    def test_encoder_with_real_producer_class_and_only_api_doubles(self):
        from qq_nt_replica.primary_source_cold12 import SourceCold12Encoder, SourceCold12Options, SourceCold12Reserve
        from qq_nt_replica.primary_signature_result import PrimarySignatureResult
        from qq_nt_replica.primary_sso_tea import tea_decrypt
        backend=Backend();provider=WindowsCold12Inputs(backend=backend)
        encoder=SourceCold12Encoder(provider,routing_number=0,own_inputs=True)
        try:
            request=encoder.prepare(b'EcdhAccess.SsoSecureAccess',b'MODEL')
            options=SourceCold12Options(123,b'MODEL-8',b'MODEL-20',SourceCold12Reserve(None,None,None,(),None,b''))
            frame=encoder.encode_signed(request,options=options,signature_result=PrimarySignatureResult(b's',b'e',b't'))
            plain=tea_decrypt(frame[18:],bytes(16))
            self.assertEqual(plain[16:28],bytes(10)+b'\x03\0')
            self.assertEqual(plain[-5:],b'MODEL')
            self.assertEqual(backend.entropy_calls,2)
        finally:encoder.close()
        self.assertFalse(backend.closed)  # Windows producer borrowed the raw backend.

    def test_raw_entropy_status_and_invalid_backing_are_errors(self):
        from types import SimpleNamespace as NS
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        raw=object.__new__(_Backend)
        calls=[]
        def request(name,output,count):
            calls.append((name,count));C.memmove(output,b'abcd',4);return 1
        raw.core=NS(request=request)
        self.assertEqual(raw.entropy4(),b'abcd');self.assertEqual(calls,[('SystemFunction036',4)])
        raw.core.request=lambda *args:0
        with self.assertRaises(PrimarySemanticUnavailable):raw.entropy4()
        provider=WindowsCold12Inputs(backend=Backend())
        with self.assertRaises(PrimarySemanticUnavailable):provider._read(C.create_string_buffer(8),1,8)
        provider.close()

    def test_owned_backend_close_and_constructor_failure(self):
        backend=Backend()
        with patch('qq_nt_replica.primary_windows_cold12_inputs._Backend',return_value=backend):
            provider=WindowsCold12Inputs();provider.close();provider.close()
        self.assertTrue(backend.closed)
        core=Backend()
        with patch('qq_nt_replica.primary_windows_core_observations.WindowsCoreAPIBackend',return_value=core),patch('qq_nt_replica.primary_windows_cold12_inputs.C.WinDLL',side_effect=OSError('load failed'),create=True):
            with self.assertRaises(OSError):_Backend()
        self.assertTrue(core.closed)

if __name__=='__main__':unittest.main()
