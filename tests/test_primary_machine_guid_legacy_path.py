import unittest
from unittest.mock import patch
from qq_nt_replica.primary_machine_guid_legacy_path import select_legacy_path,legacy_import_precheck
from qq_nt_replica.primary_windows_machine_guid_legacy_path import WindowsMachineGuidLegacyPathPort
class Port:
    def __init__(self,first=256,root=b'R:\\Root',personal=b'P:\\Personal',hit=0):self.first=first;self.root=root;self.personal=personal;self.hit=hit;self.calls=[];self.exists=0;self.buffers=[]
    def call(self,name,*args):
        self.calls.append((name,args))
        if name=='SHGetSpecialFolderPathA':
            _,out,csidl,create=args;assert create==0 and not any(out) and len(out)==260
            raw=b'A:\\AppData' if csidl==0x2E else self.personal;out[:len(raw)]=raw;self.buffers.append(out)
            return self.first if csidl==0x2E else 0
        if name=='GetPrivateProfileStringA':
            section,key,default,out,cap,file=args;assert (section,key,default,cap,file)==(b'UserDataSet',b'UserDataSavePath',b'',260,b'A:\\AppData\\Tencent\\QQ\\UserDataInfo.ini');assert len(out)==261 and not any(out)
            out[:len(self.root)]=self.root;self.buffers.append(out);return 0
        if name=='PathFileExistsA':self.exists+=1;return 256 if self.exists==self.hit else 0
        raise AssertionError(name)
class LegacyPath(unittest.TestCase):
    def test_first_failure_stops_and_lazy(self):
        p=Port(first=0);self.assertEqual(select_legacy_path(p),b'');self.assertEqual(len(p.calls),1)
        with patch('ctypes.WinDLL',side_effect=AssertionError('no native'),create=True):self.assertEqual(WindowsMachineGuidLegacyPathPort()._functions,{})
    def test_root_preference_empty_and_owning(self):
        for hit,product in ((1,b'QQ'),(2,b'TIM')):
            p=Port(root=b'',hit=hit);got=select_legacy_path(p);self.assertEqual(got,b'\\All Users\\'+product+b'\\Registry2.0.db');self.assertEqual(p.exists,hit)
            for buf in p.buffers:buf[:]=b'Q'*len(buf)
            self.assertEqual(got,b'\\All Users\\'+product+b'\\Registry2.0.db')
    def test_personal_false_consumed_and_final_tim_no_check(self):
        for hit,product in ((3,b'QQ'),(0,b'TIM')):
            p=Port(hit=hit);got=select_legacy_path(p);self.assertEqual(got,b'P:\\Personal\\Tencent Files\\All Users\\'+product+b'\\Registry2.0.db');self.assertEqual(p.exists,3)
            before=p.exists;self.assertFalse(legacy_import_precheck(p,got));self.assertEqual(p.exists,before+1)
        p=Port(personal=b'');self.assertEqual(select_legacy_path(p),b'\\Tencent Files\\All Users\\TIM\\Registry2.0.db')
