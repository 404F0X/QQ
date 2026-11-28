import unittest
from unittest.mock import patch
from qq_nt_replica import primary_qimei_kind2_module_tree as a
from qq_nt_replica.primary_windows_qimei_module_tree import WindowsQimeiModuleTreePort
from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
class Port:
    def __init__(self,paths=(),exe=b'Z:\\host\\app.exe',handle=9,status=256,needed=None):
        self.paths=list(paths);self.exe=exe;self.handle=handle;self.status=status;self.needed=needed;self.calls=[];self.buffers=[]
    def call(self,name,*args):
        self.calls.append(name)
        if name=='GetCurrentProcessId':return 123
        if name=='OpenProcess':assert args==(0x410,0,123);return self.handle
        if name=='EnumProcessModules':
            h,buf,size,needed=args;assert h==self.handle and size==8192 and not any(buf) and not any(needed)
            for i in range(len(self.paths)):buf[i*8:i*8+8]=(i+1).to_bytes(8,'little')
            needed[:]=(len(self.paths)*8 if self.needed is None else self.needed).to_bytes(4,'little');return self.status
        if name in ('GetModuleFileNameExA','GetModuleFileNameA'):
            buf=args[-2];assert len(buf)==260 and not any(buf)
            raw=self.paths[args[1]-1] if name.endswith('ExA') else self.exe
            if raw is None:return 0
            buf[:len(raw)]=raw;self.buffers.append(buf);return len(raw)
        if name=='CloseHandle':return 0
        raise AssertionError(name)
class ModuleTree(unittest.TestCase):
    def test_all_patterns_offset_first_strip_ascii_state(self):
        self.assertEqual(len(a.PATTERNS),43)
        for pattern in a.PATTERNS:
            with self.subTest(pattern=pattern):
                self.assertTrue(a.filter_fixed(b'C'+pattern.upper()+b'x',crt_lowercase_indicator=0))
                self.assertFalse(a.filter_fixed(b'xxC'+pattern+b'x',crt_lowercase_indicator=0))
                self.assertTrue(a.filter_fixed(b'abc?\\C'+pattern+b'x',crt_lowercase_indicator=0))
                self.assertFalse(a.filter_fixed(b'?\\bad?\\C'+pattern+b'x',crt_lowercase_indicator=0))
        self.assertEqual(a._lower(b'AZ\xc0',0),b'az\xc0')
        with self.assertRaises(PrimarySemanticUnavailable):a.filter_fixed(b'a',crt_lowercase_indicator=1)
    def test_second_filter_directory_prefixes_and_failure(self):
        for exe,path,want in ((b'C:\\app\\a.exe',b'c:\\APP\\x',True),(b'C:\\QQ\\bin\\a',b'c:\\qq\\other\\x',True),(b'C:\\sogouinput\\bin\\a',b'c:\\sogouinput\\x',True),(b'C:\\QQ\\bin\\a',b'D:\\qq\\x',False),(None,b'any',True),(b'abc',b'abcd',True)):
            self.assertEqual(a.filter_executable(Port(exe=exe),path,crt_lowercase_indicator=0),want)
    def test_order_copy_filter_order_and_exe_reread(self):
        p=Port([b'C:\\Windows\\System32\\x',b'X:\\z.dll',b'X:\\A.dll',b'X:\\a.dll',b'X:\\A.dll',b''])
        got=a.produce_module_tree(p,crt_lowercase_indicator=0)
        self.assertEqual(got,(b'X:\\A.dll',b'X:\\a.dll',b'X:\\z.dll'))
        self.assertEqual(p.calls.count('GetModuleFileNameA'),4);self.assertEqual(p.calls.count('CloseHandle'),1)
        for buf in p.buffers:buf[:]=b'Q'*len(buf)
        self.assertEqual(got,(b'X:\\A.dll',b'X:\\a.dll',b'X:\\z.dll'))
    def test_api_empty_overflow_unterminated_and_lazy(self):
        for p in (Port(handle=0),Port(status=0)):
            self.assertEqual(a.produce_module_tree(p,crt_lowercase_indicator=0),())
            self.assertEqual(p.calls.count('CloseHandle'),int(p.handle!=0))
        with self.assertRaises(PrimarySemanticUnavailable):a.produce_module_tree(Port(needed=8193),crt_lowercase_indicator=0)
        with self.assertRaises(InputError):a.produce_module_tree(Port([b'x'*260]),crt_lowercase_indicator=0)
        with self.assertRaises(InputError):a.filter_executable(Port(exe=b'x'*260),b'x',crt_lowercase_indicator=0)
        with patch('ctypes.WinDLL',side_effect=AssertionError('no native'),create=True):
            self.assertEqual(WindowsQimeiModuleTreePort()._functions,{})
