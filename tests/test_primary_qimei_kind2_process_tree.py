import unittest
from unittest.mock import patch
from qq_nt_replica.primary_qimei_kind2_process_tree import enumerate_mode0,produce_process_tree,INVALID_HANDLE_VALUE
from qq_nt_replica.primary_windows_qimei_process_tree import WindowsQimeiProcessTreePort

class Port:
    def __init__(self,names=(),handle=7,count=None,second=1):
        self.names=list(names);self.handle=handle;self.calls=[];self.index=0;self.count=count;self.second=second;self.backings=[]
    def call(self,name,*args):
        self.calls.append((name,args))
        if name=='CreateToolhelp32Snapshot':
            assert args==(2,0);return self.handle
        if name in ('Process32FirstW','Process32NextW'):
            handle,entry=args;assert handle==self.handle
            assert len(entry)==568 and int.from_bytes(entry[:4],'little')==568
            if self.index==len(self.names):return 0
            text=self.names[self.index];self.index+=1
            entry[8:12]=(100+self.index).to_bytes(4,'little');entry[32:36]=(200+self.index).to_bytes(4,'little')
            entry[44:]=bytes(524);raw=text.encode('utf-16-le')+b'\0\0';entry[44:44+len(raw)]=raw
            return 0x100
        if name=='WideCharToMultiByte':
            cp,flags,wide,length,out,cap,default,used=args
            assert (cp,flags,length,default,used)==(0,0,-1,None,None)
            text=wide[:-2].decode('utf-16-le');raw=text.encode('ascii')+b'\0'
            count=len(raw) if self.count is None else self.count
            if out is None:
                assert cap==0;return count
            assert len(out)==count+1 and cap==count and not any(out)
            self.backings.append(out)
            if count:out[:min(cap,len(raw))]=raw[:cap]
            return self.second
        if name=='CloseHandle':return 0
        raise AssertionError('unexpected API')

class TreeB(unittest.TestCase):
    def test_invalid_first_false_and_null_handle(self):
        for handle,expected in ((INVALID_HANDLE_VALUE,['CreateToolhelp32Snapshot']),(-1,['CreateToolhelp32Snapshot']),(0,['CreateToolhelp32Snapshot','Process32FirstW','CloseHandle']),(7,['CreateToolhelp32Snapshot','Process32FirstW','CloseHandle'])):
            p=Port(handle=handle);self.assertEqual(produce_process_tree(p),())
            self.assertEqual([n for n,a in p.calls],expected)
    def test_offsets_full_bool_order_duplicates_case_empty_and_ownership(self):
        p=Port(['z.exe','A.exe','a.exe','A.exe',''])
        result=produce_process_tree(p);self.assertEqual(result,(b'A.exe',b'a.exe',b'z.exe'))
        for out in p.backings:out[:]=b'Q'*len(out)
        self.assertEqual(result,(b'A.exe',b'a.exe',b'z.exe'))
        self.assertEqual(sum(n=='CloseHandle' for n,a in p.calls),1)
        self.assertEqual(sum(n=='Process32NextW' for n,a in p.calls),5)
        rows=enumerate_mode0(Port(['x']))
        self.assertEqual((rows[0].pid,rows[0].parent_pid,rows[0].second),(101,201,b''))
    def test_acp_zero_count_and_ignored_second_false(self):
        for count,want in ((0,()),(None,(b'x',))):
            p=Port(['x'],count=count,second=0);self.assertEqual(produce_process_tree(p),want)
            self.assertEqual(sum(n=='WideCharToMultiByte' for n,a in p.calls),2)
    def test_host_failure_propagates_without_invented_finally(self):
        p=Port(['nonascii汉'])
        with self.assertRaises(UnicodeEncodeError):produce_process_tree(p)
        self.assertNotIn('CloseHandle',[n for n,a in p.calls])
    def test_port_import_and_construction_are_lazy(self):
        with patch('ctypes.WinDLL',side_effect=AssertionError('no native'),create=True):
            self.assertIsNone(WindowsQimeiProcessTreePort()._library)
