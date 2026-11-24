import unittest
from qq_nt_replica.primary_windows_wmi_session import OwnedWmiSession
from qq_nt_replica.primary_device_wmi import _image

class ABI:
    def __init__(self):
        self.serial=100; self.count=1; self.hr=0; self.values=[]; self.releases=[]
    def initialize(self): return 0
    def create(self): return 0, 1
    def allocate(self, raw): self.serial+=1; return self.serial
    def free(self, p): pass
    def connect(self, *args): return 0, 2
    def blanket(self, p): return 0
    def release(self, p): self.releases.append(p); return 0
    def uninitialize(self): pass
    def close(self): pass
    def query(self, *args): return self.hr, 3 if not self.hr else 0
    def next(self,p): return 0x80004005, 4 if self.count else 0, self.count
    def get(self,p,name):
        self.values.append(name[:-2]); return 0, (23).to_bytes(2,'little')+bytes(6)+bytes.fromhex('ffffffff')+bytes(12)
    def convert(self,name,args):
        raw=args[2]
        value=raw.decode('utf-16le').encode('ascii') if name=='WideCharToMultiByte' else raw.decode('ascii').encode('utf-16le')
        return (len(value) if name=='WideCharToMultiByte' else len(value)//2), value if args[4] else b''

class SessionTests(unittest.TestCase):
    def test_row_and_balances(self):
        b=ABI(); s=OwnedWmiSession.open(backend=b); spec=next(iter(_image()['collectors']))
        r=s.query_first(int(spec)); self.assertEqual(r.state,'row'); self.assertEqual(r.next_hresult,0x80004005)
        self.assertEqual(b.values,[bytes.fromhex(p) for p in _image()['collectors'][spec]['properties_hex']])
        self.assertTrue(all(p.value_ansi==b'-1' for p in r.properties)); self.assertEqual(b.releases,[1,4,3])
        s.close(); self.assertEqual(s.snapshot()['interfaces'],0); self.assertEqual(s.snapshot()['com_balances'],0)
    def test_bstr_and_failed_get(self):
        for valid in (True, False):
            b=ABI()
            raw=(8).to_bytes(2,'little')+bytes(6)+(0x20000).to_bytes(8,'little')+bytes(8)
            b.get=lambda *args: (0,raw)
            b.virtual_query=lambda p: (48,bytes(36)+bytes([0 if valid else 1])+bytes(11))
            b.cstring_wide=lambda p: 'fixture\0'.encode('utf-16le')
            def clear(raw):
                if not valid:
                    raise AssertionError('invalid BSTR must never be cleared')
                return 0,bytes(24)
            b.clear=clear
            s=OwnedWmiSession.open(backend=b)
            r=s.query_first(int(next(iter(_image()['collectors']))))
            self.assertTrue(all(p.state==('value' if valid else 'invalid_bstr') for p in r.properties))
            s.close(); self.assertEqual(s.snapshot()['variants'],0 if valid else len(r.properties))
            if not valid:
                self.assertTrue(all(v=='unvalidated' for v in s.snapshot()['variant_states']))
        b=ABI(); b.get=lambda *args: (0x80004005,b'')
        s=OwnedWmiSession.open(backend=b)
        r=s.query_first(int(next(iter(_image()['collectors']))))
        self.assertTrue(all(p.state=='get_failed' and p.key_ansi for p in r.properties)); s.close()

    def test_failed_clear_never_retried(self):
        b=ABI(); calls=[]
        raw=(8).to_bytes(2,'little')+bytes(6)+(0x20000).to_bytes(8,'little')+bytes(8)
        b.get=lambda *args: (0,raw)
        b.virtual_query=lambda p: (48,bytes(48))
        b.cstring_wide=lambda p: 'fixture\0'.encode('utf-16le')
        def clear(raw):
            calls.append(raw)
            return 0x80004005,bytes(24)
        b.clear=clear
        s=OwnedWmiSession.open(backend=b)
        r=s.query_first(int(next(iter(_image()['collectors']))))
        self.assertEqual(len(calls),len(r.properties))
        s.close(); s.close()
        self.assertEqual(len(calls),len(r.properties))
        self.assertEqual(s.snapshot()['variants'],len(r.properties))
        self.assertTrue(all(v=='clear_failed_unknown' for v in s.snapshot()['variant_states']))

    def test_no_services_and_release_exception_balance(self):
        b=ABI(); b.create=lambda: (0x80004005,0)
        s=OwnedWmiSession.open(backend=b)
        self.assertEqual(s.query_first(int(next(iter(_image()['collectors'])))).state,'no_services'); s.close()
        b=ABI(); s=OwnedWmiSession.open(backend=b)
        def fail(p): raise RuntimeError('fixture release failure')
        original=b.release; b.release=fail
        with self.assertRaises(RuntimeError): s.close()
        self.assertFalse(s.closed); self.assertEqual(s.snapshot()['interfaces'],1)
        b.release=original; s.close()

    def test_empty_and_exec_failure(self):
        for count,hr,state in [(0,0,'no_object'),(1,0x80004005,'exec_failed')]:
            b=ABI(); b.count=count; b.hr=hr; s=OwnedWmiSession.open(backend=b)
            self.assertEqual(s.query_first(int(next(iter(_image()['collectors'])))).state,state)
            self.assertEqual(b.values,[]); s.close()

if __name__=='__main__': unittest.main()
