# Scripted profile API model only; production uses Windows profile APIs.
class ScriptedProfile:
    def string(self,path,key):
        try: rows=path.read_bytes().splitlines()
        except FileNotFoundError:return b''
        return next((row.split(b'=',1)[1][:32] for row in rows if row.startswith(key+b'=')),b'')
    def integer(self,path):return 1
    def close(self):pass

from pathlib import Path
import pytest
from qq_nt_replica.primary_windows_qimei_owned_storage import OwnQimeiBeaconBackend
from qq_nt_replica.primary_qimei_beacon import QimeiBeacon, BeaconInputs
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary

def backend(tmp_path):
    runtime=object(); epoch=object()
    return OwnQimeiBeaconBackend(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/'own',profile_port=ScriptedProfile())
class Producer:
    def __init__(self): self.calls=0
    def produce(self):
        self.calls+=1
        return BeaconInputs(b'123456',(b'disk',),b'cpu',1,1,1)
def test_real_beacon_generate_persist_once(tmp_path):
    port=backend(tmp_path); producer=Producer(); beacon=QimeiBeacon(producer,port)
    raw=beacon.raw()
    assert beacon.raw()==raw and producer.calls==1 and not port.handles
    assert (port.root/'RanMgr.db').read_bytes().startswith(b'[Profile]\r\nconfig1='+raw.hex().encode())
    assert QimeiBeacon(Producer(),port).raw()==raw

def test_outer_valid_and_malformed(tmp_path):
    port=backend(tmp_path); port.root.mkdir()
    path=port.root/'GlobalMgr.db'
    path.write_bytes(b'[Profile]\r\nconfig1='+b'A'*32)
    assert QimeiBeacon(Producer(),port).refresh()==b'a'*32
    path.write_bytes(b'[Profile]\r\nconfig1='+b'z'*32)
    with pytest.raises(QimeiRequestBoundary): QimeiBeacon(Producer(),port).refresh()
def test_epoch(tmp_path):
    port=backend(tmp_path)
    runtime,epoch,_,permit,pid,thread=port.binding
    port.binding=(runtime,epoch,lambda r:None,permit,pid,thread)
    with pytest.raises(QimeiRequestBoundary): port.open_main()
    assert not port.root.exists()

from qq_nt_replica.primary_windows_qimei_owned_storage import OwnQimeiMainWriterObservations, NativeOwnedAclPort, NativeOwnedProfilePort
from qq_nt_replica.primary_qimei_cache import QimeiCacheCodec
from qq_nt_replica.primary_qimei_main_writer import QimeiMainWriter
from qq_nt_replica.primary_qimei_context import QimeiContextProducer
from qq_nt_replica.primary_qimei_observations import QimeiApiReply
import ctypes as C
class AclScript:
    def __init__(self):self.calls=[]
    def read(self,channel,name,*args):
        self.calls.append((name,args))
        if name=='SHELL32.ordinal680':return QimeiApiReply(1)
        if name=='NetWkstaUserGetInfo':return QimeiApiReply(5)
        raise AssertionError(name)
    def close(self):pass

def test_real_writer_codec(tmp_path):
    runtime=object(); epoch=object(); acl=AclScript()
    backend=OwnQimeiMainWriterObservations(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/'own',logical_main_path=b'C:\\source\\cache',acl_port=acl)
    codec=QimeiCacheCodec(); context=QimeiContextProducer(context=b'313233343536',initialized=True)
    writer=QimeiMainWriter(backend,codec=codec,context=context,context_observations=None)
    payload=bytes(range(53))
    assert writer(b'C:\\source\\cache',payload)==0
    encrypted=(backend.root/'QimeiMain.cache').read_bytes()
    decoded=codec.decode_payload(encrypted,capacity=53,context=b'313233343536')
    assert decoded.accepted and decoded.payload==payload
    assert writer.last_acl_code==1 and not backend.streams and not backend.allocations
    assert [name for name,args in acl.calls]==['SHELL32.ordinal680','NetWkstaUserGetInfo']
    with pytest.raises(QimeiRequestBoundary):writer(b'other',payload)
    assert not backend.allocations

class RawAcl(NativeOwnedAclPort):
    def __init__(self):super().__init__(lambda:None); self.calls=[]; self.buf=None
    def _invoke(self,name,args):
        self.calls.append((name,args))
        if name=='SHELL32.ordinal680':return 1
        if name=='NetWkstaUserGetInfo':return 5
        if name=='HeapAlloc':
            self.buf=C.create_string_buffer(args[2]); return C.addressof(self.buf)
        if name=='HeapFree':return 1
        raise AssertionError(name)
def test_native_acl_typed_backing_model():
    from qq_nt_replica.primary_qimei_storage import StorageBuffer
    port=RawAcl()
    reply=port.read('qimei-api','NetWkstaUserGetInfo',None,1,StorageBuffer(bytes(8)))
    assert reply.result==5 and reply.writes==( ('buffer',0,bytes(8)), )
    raw=port.read('qimei-api','HeapAlloc',1,8,16).result
    assert port.read_memory(raw,16).read()==bytes(16)
    with pytest.raises(QimeiRequestBoundary):port.read_memory(raw+16,1)
    port.read('qimei-api','HeapFree',1,0,raw)
    assert not port.allocations

def test_profile_exact_native_arguments_model(tmp_path):
    class Profile(NativeOwnedProfilePort):
        def _call(self,name,result,types,*args):
            self.last=(name,args)
            if name=='GetPrivateProfileStringA':
                C.memmove(args[3],b'abc\0',4);return 3
            return 7
    port=Profile(lambda:None); path=tmp_path/'RanMgr.db'
    assert port.string(path,b'config1')==b'abc'
    assert port.last[1][:3]==(b'Profile',b'config1',None) and port.last[1][4]==33
    assert port.integer(path)==7

def test_writer_short_count_and_close_failure(tmp_path):
    runtime=object();epoch=object()
    backend=OwnQimeiMainWriterObservations(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/'own',logical_main_path=b'logical',acl_port=AclScript())
    token=backend.read('qimei-api','fopen',b'logical',b'wb').result
    real=backend.streams[token]
    class ShortFile:
        def write(self,data):return real.write(data[:2])
        def close(self):raise OSError(5,'scripted close failure')
    backend.streams[token]=ShortFile()
    assert backend.read('qimei-api','fwrite',b'abcdef',1,6,token).result==2
    real.flush()
    assert (backend.root/'QimeiMain.cache').read_bytes()==b'ab'
    assert backend.read('qimei-api','fclose',token).result==0xffffffff
    assert token in backend.streams and backend.audit[-1]==('close-error',5)
    with pytest.raises(QimeiRequestBoundary):backend.close_native()
    backend.streams[token]=real
    assert backend.read('qimei-api','fclose',token).result==0

def test_acl_owned_target_and_typed_factory(tmp_path):
    from qq_nt_replica.primary_windows_qimei_owned_storage import create_owned_qimei_main_writer
    runtime=object();epoch=object();acl=AclScript()
    writer=create_owned_qimei_main_writer(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/'own',logical_main_path=b'logical',codec=QimeiCacheCodec(),context=QimeiContextProducer(context=b'313233343536',initialized=True),context_observations=None,acl_port=acl)
    assert isinstance(writer,QimeiMainWriter)
    class Capture:
        def read(self,channel,name,*args):
            assert name=='MultiByteToWideChar'
            assert args[2]==bytes(str(tmp_path/'own'/'QimeiMain.cache'),'utf-8')
            return QimeiApiReply(0)
    writer.observations.acl_port=Capture()
    writer.observations.read('qimei-api','MultiByteToWideChar',0,0,b'logical',-1,None,0)

def test_root_substitution_rejected(tmp_path):
    port=backend(tmp_path)
    # Lexical parent traversal cannot select a different physical dedicated root.
    port.root=tmp_path/'elsewhere'/'..'/'own'
    with pytest.raises(QimeiRequestBoundary):port.open_main()

def test_acl_module_release_failure_and_debt():
    from types import SimpleNamespace
    class Releaser(RawAcl):
        def __init__(self):super().__init__();self.releases=[];self.fail=True
        def _release(self,handle):
            if self.fail:raise OSError(5,'scripted module release failure')
            self.releases.append(handle)
    port=Releaser();port.libraries={'advapi32':SimpleNamespace(_handle=77)}
    port.allocations[123]=16
    with pytest.raises(QimeiRequestBoundary):port.close()
    port.allocations.clear()
    with pytest.raises(OSError):port.close()
    assert not port.closed and 'advapi32' in port.libraries
    port.fail=False;port.close();port.close()
    assert port.closed and port.releases==[77]
    with pytest.raises(QimeiRequestBoundary):port.read('qimei-api','SHELL32.ordinal680')

def test_real_writer_full_acl_success_chain(tmp_path):
    """MODEL native ABI outputs, REAL writer/codec/files; no native calls."""
    import os
    from qq_nt_replica.primary_windows_qimei_owned_storage import ACL_ABI
    class SuccessfulAcl(NativeOwnedAclPort):
        def __init__(self):
            super().__init__(lambda:None)
            self.calls=[]; self.heap={}; self.frees=[]; self.sec_calls=0; self.lookup_calls=0
            self.username=C.create_unicode_buffer('OwnedModelUser')
            self.userinfo=C.create_string_buffer(8)
            C.memmove(self.userinfo,int(C.addressof(self.username)).to_bytes(8,'little'),8)
            self.security_path=None
        def _invoke(self,name,args):
            assert name in ACL_ABI
            self.calls.append(name)
            def output(target,value,width=4):C.memmove(target,value.to_bytes(width,'little'),width)
            if name=='SHELL32.ordinal680':return 1
            if name=='NetWkstaUserGetInfo':
                output(args[2],C.addressof(self.userinfo),8);return 0
            if name=='NetApiBufferFree':
                assert args[0]==C.addressof(self.userinfo);return 0
            if name=='MultiByteToWideChar':
                path=args[2].value.decode('ascii')
                data=path.encode('utf-16le')+b'\0\0'
                if args[4] is not None:C.memmove(args[4],data,len(data))
                return len(data)//2
            if name=='SetLastError':return None
            if name=='GetLastError':return 122
            if name=='GetProcessHeap':return 1
            if name=='HeapAlloc':
                buf=C.create_string_buffer(args[2]);pointer=C.addressof(buf)
                self.heap[pointer]=buf;return pointer
            if name=='HeapFree':
                assert args[2] in self.heap
                self.frees.append(args[2]);del self.heap[args[2]];return 1
            if name=='LookupAccountNameW':
                self.lookup_calls+=1
                output(args[3],12);output(args[5],4);output(args[6],1)
                if args[2] is None:return 0
                C.memmove(args[2],b'\x01'+bytes(11),12);return 1
            if name=='GetFileSecurityW':
                self.sec_calls+=1;output(args[4],40)
                if args[2] is None:return 0
                C.memmove(args[2],bytes(40),40);return 1
            if name=='GetSecurityDescriptorDacl':
                output(args[1],0);output(args[2],0,8);output(args[3],0);return 1
            if name=='GetLengthSid':return 12
            if name=='GetSecurityDescriptorControl':
                output(args[1],0,2);output(args[2],1);return 1
            if name=='SetFileSecurityW':
                self.security_path=C.wstring_at(args[0]);return 1
            if name in ('InitializeSecurityDescriptor','InitializeAcl','AddAccessAllowedAceEx','SetSecurityDescriptorDacl'):
                return 1
            raise AssertionError(name)
    runtime=object();epoch=object();acl=SuccessfulAcl()
    root=tmp_path/'own'
    from qq_nt_replica.primary_windows_qimei_owned_storage import create_owned_qimei_main_writer
    writer=create_owned_qimei_main_writer(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=root,logical_main_path=b'logical',acl_port=acl,codec=QimeiCacheCodec(),context=QimeiContextProducer(context=b'313233343536',initialized=True),context_observations=None)
    observations=writer.observations
    payload=bytes(range(53))
    assert writer(b'logical',payload)==0 and writer.last_acl_code==0
    assert acl.security_path==str(root/'QimeiMain.cache')
    assert acl.lookup_calls==2 and acl.sec_calls==2
    assert {'SHELL32.ordinal680','NetWkstaUserGetInfo','NetApiBufferFree','MultiByteToWideChar','LookupAccountNameW','GetFileSecurityW','InitializeSecurityDescriptor','GetSecurityDescriptorDacl','GetLengthSid','InitializeAcl','AddAccessAllowedAceEx','SetSecurityDescriptorDacl','GetSecurityDescriptorControl','SetFileSecurityW'}.issubset(acl.calls)
    assert len(acl.frees)==4
    assert not acl.heap and not acl.allocations and not acl.net and not observations.allocations and not observations.streams
    decoded=writer.codec.decode_payload((root/'QimeiMain.cache').read_bytes(),capacity=53,context=b'313233343536')
    assert decoded.accepted and decoded.payload==payload
    acl.close()
    assert acl.closed

def test_profile_acp_physical_path_and_rejection(tmp_path):
    from qq_nt_replica.primary_windows_qimei_owned_storage import _profile_ansi_path
    class Profile(NativeOwnedProfilePort):
        def __init__(self):super().__init__(lambda:None);self.calls=[]
        def _call(self,name,result,types,*args):
            self.calls.append((name,args))
            return 0
    # This is a real dedicated directory; only the native API calls are modeled.
    root=tmp_path/'own-é';root.mkdir()
    path=root/'GlobalMgr.db';path.write_bytes(b'[Profile]\r\nconfig1=abc')
    port=Profile()
    try: encoded=str(path).encode('mbcs',errors='strict')
    except UnicodeError:
        with pytest.raises(QimeiRequestBoundary):port.string(path,b'config1')
        assert not port.calls
    else:
        if encoded.decode('mbcs',errors='strict')!=str(path):
            with pytest.raises(QimeiRequestBoundary):port.string(path,b'config1')
            assert not port.calls
        else:
            port.string(path,b'config1');port.integer(path)
            assert all(args[-1]==encoded for name,args in port.calls)
            assert all(Path(args[-1].decode('mbcs')).resolve()==path.resolve() for name,args in port.calls)
    count=len(port.calls)
    bad=root/('unrepresentable-'+chr(0xd800))
    for method in (lambda:port.string(bad,b'config1'),lambda:port.integer(bad)):
        with pytest.raises(QimeiRequestBoundary):method()
        assert len(port.calls)==count  # failure never becomes a default/missing result
    with pytest.raises(QimeiRequestBoundary):_profile_ansi_path(str(path)+'\0suffix')
