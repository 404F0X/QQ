import unittest
from qq_nt_replica.primary_device_mix_producer import produce_device_mix,WindowsDeviceMixPort
class Observations:
    def __init__(self,fail=None):self.live={};self.next=0x12345000;self.calls=[];self.entropy=0;self.ticks=iter((100,201,302,403,504,609));self.fail=fail
    def event(self,name,*args):
        self.calls.append((name,*args))
        if self.fail==(name,len([x for x in self.calls if x[0]==name])):raise RuntimeError('controlled failure')
    def allocate(self,n):self.event('alloc',n);p=self.next;self.next+=0x1000;self.live[p]=bytearray(n);return p
    def free(self,p):self.event('free',len(self.live[p]));del self.live[p]
    def locate(self,p,n):
        base=next(b for b,v in self.live.items() if b<=p and p+n<=b+len(v));return self.live[base],p-base
    def write(self,p,data):v,o=self.locate(p,len(data));v[o:o+len(data)]=data
    def read(self,p,n):v,o=self.locate(p,n);return bytes(v[o:o+n])
    def random4(self,p):self.event('rng',4);self.write(p,bytes(range(self.entropy,self.entropy+4)));self.entropy+=4
    def steady(self):self.event('steady');return next(self.ticks)
    def filetime(self):self.event('filetime');return 116444736000000000+10000000*123
class Producer(unittest.TestCase):
    def test_cold_order_math_and_copy(self):
        obs=Observations();result=produce_device_mix(obs)
        self.assertEqual(len(result),17);self.assertEqual(obs.live,{})
        self.assertEqual(obs.calls,[('alloc',1328),('filetime',),('steady',),('alloc',48)]+[('rng',4)]*12+[('alloc',16)]+[('steady',)]*5+[('free',16),('free',48),('free',1328)])
        # Source constants, byte masking, three entropy blocks and little-endian clock words.
        value=0x12345000^123;salt=[]
        for _ in range(64):value=(value*1103515245+12345)&0xffffffff;salt.append(((value>>16)|1)&255)
        raw=bytearray(a^b^c for a,b,c in zip(range(16),range(16,32),range(32,48)))
        clock=b''.join(x.to_bytes(4,'little') for x in (201,302,403,504))
        delta=(609-100).to_bytes(4,'little');left=salt[5];right=salt[0]
        expected=bytearray()
        for i,x in enumerate(raw):
            x^=clock[i]^(delta[i] if i<4 else 0);x^=left^((i*7+5)&255);x^=right^((i*7)&255);expected.append(x);left=(left*13+17)&255;right=(right*13+17)&255
        self.assertEqual(result,bytes(expected)+bytes([salt[0]]))
    def test_failures_cleanup_without_retry(self):
        for where in [('alloc',1),('alloc',2),('alloc',3),('filetime',1),('rng',1),('rng',12),('steady',1),('steady',6)]:
            obs=Observations(where)
            with self.assertRaisesRegex(RuntimeError,'controlled failure'):produce_device_mix(obs)
            self.assertEqual(obs.live,{})
    def test_windows_lazy_and_exact_clock_conversion(self):
        import ctypes as C
        port=WindowsDeviceMixPort();self.assertEqual(port.api,{})
        calls=[]
        def write(name,number):
            def call(p):calls.append(name);C.cast(p,C.POINTER(C.c_int64))[0]=number;return 1
            return call
        port.api={'QueryPerformanceFrequency':write('freq',3000000),'QueryPerformanceCounter':write('counter',123456789)}
        self.assertEqual(port.steady(),41152263000);self.assertEqual(port.steady(),41152263000);self.assertEqual(calls,['freq','counter','counter']);port.close()

    def test_independent_arch_KAT(self):
        obs=Observations();obs.next=0x1020304050607080;obs.ticks=iter((100,101,102,103,104,109))
        obs.filetime=lambda:116444736000000000+0x01020304*10000000
        def rng(pointer):
            obs.write(pointer,(obs.entropy//4).to_bytes(4,'little'));obs.entropy+=4
        obs.random4=rng
        self.assertEqual(produce_device_mix(obs).hex(),'c3410fb908f137290ac1df8964d1575935')
    def test_failed_free_is_not_retried(self):
        obs=Observations(('free',1))
        with self.assertRaisesRegex(RuntimeError,'controlled failure'):produce_device_mix(obs)
        self.assertEqual([x for x in obs.calls if x[0]=='free'],[('free',16),('free',48),('free',1328)])
        self.assertEqual(list(map(len,obs.live.values())),[16])
