import ctypes as C
import pytest
from qq_nt_replica.primary_qimei_request_pipeline import QimeiHttpRequest
from qq_nt_replica.primary_windows_qimei_carrier import WindowsQimeiCarrier, WinInetFailure, FLAGS, UA
class Port:
    def __init__(self,chunks=(),fail=None): self.chunks=iter(chunks); self.fail=fail; self.calls=[]
    def check(self): pass
    def error(self): return 12345
    def call(self,name,*args):
        self.calls.append((name,args))
        if name==self.fail: return 0
        if name=='InternetReadFile':
            chunk=next(self.chunks,b'')
            if chunk is None: return 0
            C.memmove(args[1],chunk,len(chunk)); C.cast(args[3],C.POINTER(C.c_uint32))[0]=len(chunk)
        return {'InternetOpenA':11,'InternetConnectA':22,'HttpOpenRequestA':33}.get(name,1)
@pytest.mark.parametrize('chunks',[(),(b'non200 body',),(b'a'*4095,b'b')])
def test_clean(chunks):
    port=Port(chunks); carrier=WindowsQimeiCarrier(port); result=carrier.perform(QimeiHttpRequest(b'a\x00b'))
    assert (result.body,result.source_status)==(b''.join(chunks),0)
    assert port.calls[0]==('InternetOpenA',(UA,1,None,None,0))
    assert port.calls[1]==('InternetConnectA',(11,b'snowflake.qq.com',443,None,None,3,0,0))
    assert port.calls[2]==('HttpOpenRequestA',(22,b'POST',b'/ola/v2',b'HTTP/1.1',None,None,FLAGS,0))
    args=port.calls[3][1]
    assert args[:3]==(33,b'Content-Type: application/json',0xffffffff)
    assert C.string_at(args[3],args[4])==b'a\x00b'
    assert [a[0] for n,a in port.calls if n=='InternetCloseHandle']==[33,22,11]
    assert all(a[2]==4095 for n,a in port.calls if n=='InternetReadFile')
    assert sum(n=='HttpSendRequestA' for n,a in port.calls)==1
@pytest.mark.parametrize('phase,closed',[('InternetOpenA',[]),('InternetConnectA',[11]),('HttpOpenRequestA',[22,11]),('HttpSendRequestA',[33,22,11])])
def test_early_failure(phase,closed):
    port=Port(fail=phase)
    with pytest.raises(WinInetFailure) as caught: WindowsQimeiCarrier(port).perform(QimeiHttpRequest(b'x'))
    assert caught.value.error==12345
    assert [a[0] for n,a in port.calls if n=='InternetCloseHandle']==closed

def test_partial_failure():
    port=Port((b'partial',None)); carrier=WindowsQimeiCarrier(port)
    with pytest.raises(WinInetFailure) as caught: carrier.perform(QimeiHttpRequest(b'x'))
    assert caught.value.partial_body==b'partial'
    assert caught.value.send_return_success and caught.value.error==12345
    assert len(caught.value.close_results)==3
    assert not carrier.active

from types import SimpleNamespace
from qq_nt_replica.primary_windows_qimei_carrier import NativeWinInetPort
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary

class Function:
    def __init__(self, value): self.value=value
    def __call__(self,*args): return self.value
class LoaderPort(NativeWinInetPort):
    def __init__(self):
        super().__init__(permit=lambda:True)
        self.loads=0; self.releases=[]; self.release_fail=False
        self.mock=SimpleNamespace(_handle=99,InternetOpenA=Function(11),InternetCloseHandle=Function(1))
    def _load(self): self.loads+=1; return self.mock
    def _release(self,handle):
        if self.release_fail: raise OSError(5,'release failed')
        self.releases.append(handle)
    def error(self): return 12345

def test_module_lazy_and_idempotent_close():
    port=LoaderPort()
    assert port.loads==0
    port.call('InternetOpenA',UA,1,None,None,0)
    assert port.loads==1
    with pytest.raises(QimeiRequestBoundary): port.close()
    port.call('InternetCloseHandle',11)
    port.close(); port.close()
    assert port.releases==[99] and port.closed and port.library is None
    with pytest.raises(QimeiRequestBoundary): port.call('InternetOpenA',UA,1,None,None,0)

def test_release_failure_preserves_module():
    port=LoaderPort(); port.call('InternetOpenA',UA,1,None,None,0); port.call('InternetCloseHandle',11)
    port.release_fail=True
    with pytest.raises(OSError): port.close()
    assert not port.closed and port.library is port.mock
    port.release_fail=False; port.close()
    assert port.releases==[99]

def test_failed_handle_close_blocks_unload():
    port=LoaderPort(); port.call('InternetOpenA',UA,1,None,None,0)
    port.mock.InternetCloseHandle.value=0
    assert port.call('InternetCloseHandle',11)==0 and port.error()==12345
    with pytest.raises(QimeiRequestBoundary): port.close()
    assert port.handles=={11} and port.releases==[]

def test_never_loaded_close():
    port=LoaderPort(); port.close(); port.close()
    assert port.loads==0 and port.releases==[]

def test_send_false_is_remote_unknown():
    port=Port(fail='HttpSendRequestA')
    with pytest.raises(WinInetFailure) as caught: WindowsQimeiCarrier(port).perform(QimeiHttpRequest(b'x'))
    assert caught.value.send_attempted and caught.value.remote_send_unknown
    assert not caught.value.send_return_success

def test_send_call_exception_retains_attempt_and_cause():
    class ThrowPort(Port):
        def call(self,name,*args):
            if name=='HttpSendRequestA': raise OSError('scripted call exception')
            return super().call(name,*args)
    with pytest.raises(WinInetFailure) as caught: WindowsQimeiCarrier(ThrowPort()).perform(QimeiHttpRequest(b'x'))
    assert caught.value.send_attempted and caught.value.remote_send_unknown
    assert isinstance(caught.value.__cause__,OSError)
    assert len(caught.value.close_results)==3
