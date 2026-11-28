import unittest,ctypes as C,hashlib
from types import SimpleNamespace as NS
from qq_nt_replica.primary_device import *
from qq_nt_replica.primary_device_provider import DeviceFactory,produce_observed_device_value
from qq_nt_replica.primary_device_storage import MemoryCheckpointStorage,DirectoryCheckpointStorage,CheckpointRead
from qq_nt_replica.primary_device_value_producer import WindowsKey25Capi
from qq_nt_replica.primary_windows_capi import CapiCreationDisabled
from qq_nt_replica.primary_windows import _PublicKeyInfo
class Source:
    def system_information(self):return 1,None
    def cpuid(self,leaf,subleaf=0):
        return (0,*[int.from_bytes(b'VMwareVMware'[i:i+4],'little') for i in (0,4,8)]) if leaf==0x40000000 else (leaf&0xffffffff,1,2,3)
    def object_names(self):return ('PCI#abc#tail','PCI#abc#duplicate','ignore')
    def displays(self):return (DisplayObservation('123456789\\child',1),DisplayObservation('ignored',8))
    def volume_serial(self):return 123
    def uuid(self):return 1,None
    def capi_public_key(self):return CapiObservation(b'controlled public bits',0)
class Store(DirectoryCheckpointStorage):
    def __init__(self,profile=None):self.inner=MemoryCheckpointStorage(profile=profile);self.created=0
    def ensure_directory(self):pass
    def read(self):return self.inner.read()
    def write_record(self,*args):return self.inner.write_record(*args)
    def read_profile(self,*,random_bytes):
        if self.inner.profile is None:
            self.created+=1;self.inner.profile=encode_profile(device_material(bytes(range(16))),random_bytes)
            return CheckpointRead(self.inner.profile,created=True)
        return self.inner.read_profile()
def environment():return NS(filetime=lambda:116444736010000000,random_bytes=lambda n:bytes(range(n)))
class Backend:
    def __init__(self,missing=False):self.missing=missing;self.calls=[];self.bits=b'controlled key';self.closed=[]
    def VerSetConditionMask(self,mask,kind,condition):return mask+kind
    def VerifyVersionInfoW(self,version,kind,mask):
        assert C.c_uint32.from_buffer(version).value==284 and C.c_uint32.from_buffer(version,4).value==5 and C.c_uint32.from_buffer(version,8).value==1 and kind==3
        return 1
    def last_error(self):return 0x80090016
    def CryptAcquireContextA(self,out,name,provider,kind,flags):
        self.calls.append(('acquire',flags))
        if flags==0x60 and self.missing:return 0
        C.cast(out,C.POINTER(C.c_void_p))[0]=10;return 1
    def CryptGenKey(self,provider,alg,flags,out):self.calls.append(('gen',alg,flags));C.cast(out,C.POINTER(C.c_void_p))[0]=11;return 1
    def CryptGetUserKey(self,provider,alg,out):C.cast(out,C.POINTER(C.c_void_p))[0]=12;return 1
    def InitializeSecurityDescriptor(self,*args):self.calls.append(('sd',));return 1
    def SetSecurityDescriptorDacl(self,*args):self.calls.append(('dacl',args[1:]));return 1
    def CryptSetProvParam(self,*args):self.calls.append(('param',args[1],args[3]));return 1
    def CryptExportPublicKeyInfo(self,provider,key,enc,out,count):
        if out is not None:
            start=C.addressof(out);info=_PublicKeyInfo.from_buffer(out);info.key.size=len(self.bits);info.key.data=start+64;C.memmove(start+64,self.bits,len(self.bits))
        C.cast(count,C.POINTER(C.c_uint32))[0]=128;return 1
    def CryptCreateHash(self,provider,alg,key,flags,out):C.cast(out,C.POINTER(C.c_void_p))[0]=13;return 1
    def CryptHashData(self,handle,data,count,flags):self.actual=C.string_at(data,count);return 1
    def CryptGetHashParam(self,handle,param,out,count,flags):C.memmove(out,hashlib.sha256(self.actual).digest(),32);return 1
    def CryptDestroyKey(self,handle):self.closed.append(handle);return 1
    def CryptDestroyHash(self,handle):self.closed.append(handle);return 1
    def CryptReleaseContext(self,handle,flags):self.closed.append(handle);return 1
class ValueProducer(unittest.TestCase):
    def test_nonempty_names_display_shared_policy_legacy_parity(self):
        a=Store();source=Source();result=produce_observed_device_value(source,environment(),lambda:(a,None))
        self.assertTrue(result.success);self.assertEqual(a.created,0)
        legacy=DeviceFactory(source,Store(),environment())._produce();self.assertEqual(result,legacy)
        record=decode_checkpoint(a.inner.value).record
        self.assertEqual(record[12:16],object_directory_material(source.object_names()).to_bytes(4,'little'))
        self.assertEqual(record[28:32],display_material(source.displays()).to_bytes(4,'little'))
    def test_capi_open_creation_denied_and_real_creation_math(self):
        for missing,allow,method in ((False,False,6),(True,True,5)):
            api=Backend(missing);port=WindowsKey25Capi(backend=api,allow_creation=allow);value=port.capi_public_key();self.assertEqual(value.method,method);self.assertEqual(value.public_key_bits,api.bits);self.assertEqual(port.handles,[])
            self.assertEqual(api.calls[0],('acquire',0x60))
            if missing:self.assertIn(('acquire',0x68),api.calls);self.assertIn(('gen',2,0x08000000),api.calls);self.assertIn(('param',8,4),api.calls)
        api=Backend(True);port=WindowsKey25Capi(backend=api)
        with self.assertRaises(CapiCreationDisabled):port.capi_public_key()
        self.assertEqual(api.calls,[('acquire',0x60)]);self.assertEqual(port.handles,[])
    def test_profile_missing_read_and_corrupt_no_rebuild(self):
        class Fallback(Source):
            def capi_public_key(self):return CapiObservation(None,3,5)
        store=Store();first=produce_observed_device_value(Fallback(),environment(),lambda:(store,None));self.assertTrue(first.success);self.assertEqual(store.created,1);self.assertEqual(len(store.inner.profile),50)
        second=produce_observed_device_value(Fallback(),environment(),lambda:(store,None));self.assertTrue(second.success);self.assertEqual(store.created,1)
        broken=Store(b'x'*50);result=produce_observed_device_value(Fallback(),environment(),lambda:(broken,None));self.assertFalse(result.success);self.assertEqual(broken.created,0)

    def test_version_gate_and_creation_denial_not_profile_fallback(self):
        api=Backend();api.VerifyVersionInfoW=lambda *args:0
        result=WindowsKey25Capi(backend=api).capi_public_key();self.assertEqual(result.error_code,2);self.assertEqual(api.calls,[])
        store=Store();port=WindowsKey25Capi(backend=Backend(True))
        class Denied(Source):
            def capi_public_key(self):return port.capi_public_key()
        with self.assertRaises(CapiCreationDisabled):produce_observed_device_value(Denied(),environment(),lambda:(store,None))
        self.assertEqual(store.created,0);self.assertIsNone(store.inner.profile)

    def test_entry_explicit_store_isolation_and_borrowed_source(self):
        from qq_nt_replica.primary_device_value_producer import produce_device_value
        calls=[];stores={}
        class Crypto:
            def capi_public_key(self):return CapiObservation(b'fixture',0)
            def close(self):calls.append('close')
        def factory(root):
            self.assertEqual(root.name,'case');stores[root]=Store();return stores[root]
        from pathlib import Path
        root=Path('G:/controlled/case')
        result=produce_device_value(storage_root=root,environment=environment(),source=Source(),capi=Crypto(),storage_factory=factory)
        self.assertTrue(result.success);self.assertEqual(list(stores),[root]);self.assertEqual(calls,['close'])
    def test_cleanup_failure_preserves_original_and_no_retry(self):
        api=Backend();api.CryptExportPublicKeyInfo=lambda *args:(_ for _ in ()).throw(ValueError('controlled export'))
        count=[]
        def fail(handle):count.append(handle);return 0
        api.CryptDestroyKey=fail;port=WindowsKey25Capi(backend=api)
        with self.assertRaises(BaseExceptionGroup) as got:port.capi_public_key()
        self.assertIsInstance(got.exception.exceptions[0],ValueError);self.assertEqual(count,[12]);self.assertEqual(port.failed_handles,[(12,'CryptDestroyKey')])

    def test_ucrt_exported_rand_s_binding_without_native_execution(self):
        from qq_nt_replica.primary_device_value_producer import WindowsDeviceValueEnvironment
        from unittest.mock import patch
        calls=[]
        def rand_s(out):calls.append('rand_s');C.cast(out,C.POINTER(C.c_uint32))[0]=0x12345678;return 0
        library=NS(rand_s=rand_s,_handle=123)
        env=WindowsDeviceValueEnvironment()
        with patch('qq_nt_replica.primary_device_value_producer.C.CDLL',return_value=library) as load:
            self.assertEqual(env.random_bytes(4),b'\x78\x56\x34\x12');self.assertEqual(env.random_bytes(4),b'\x78\x56\x34\x12')
            load.assert_called_once_with('ucrtbase.dll',winmode=0x800)
        self.assertEqual(calls,['rand_s','rand_s']);self.assertEqual(rand_s.argtypes,(C.POINTER(C.c_uint32),));self.assertIs(rand_s.restype,C.c_int32)
        with patch('_ctypes.FreeLibrary') as free:env.close();free.assert_called_once_with(123)

    def test_empty_checkpoint_from_failed_write_follows_existing_policy(self):
        store=Store();store.inner.value=b''
        self.assertFalse(decode_checkpoint(store.inner.value).success)
        self.assertEqual(decode_checkpoint(store.inner.value).error_code,0x1A)
        result=produce_observed_device_value(Source(),environment(),lambda:(store,None))
        self.assertTrue(result.success);self.assertEqual(store.created,0);self.assertEqual(store.inner.writes,1);self.assertEqual(len(store.inner.value),1028)
