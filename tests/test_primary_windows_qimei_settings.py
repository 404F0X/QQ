import ctypes as C,unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from qq_nt_replica.primary_windows_qimei_settings import WindowsQimeiSettingsObservations
from qq_nt_replica.primary_qimei_settings import QimeiSettings
from qq_nt_replica.primary_qimei_storage import StorageBuffer
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
class SettingsWindows(unittest.TestCase):
    def api(self,folder):return SimpleNamespace(SHGetSpecialFolderPathA=Mock(side_effect=folder),PathIsDirectoryA=Mock(return_value=0),CreateDirectoryA=Mock(return_value=0))
    def test_raw_buffer_bool_dword_and_signatures_lazy(self):
        def folder(hwnd,out,identifier,create):
            self.assertEqual((hwnd,identifier,create),(0,0x23,1));self.assertEqual(out.raw,b'X'*260)
            C.memmove(out,b'F:\\controlled folder\0',21);return -2147483648
        api=self.api(folder)
        with patch('ctypes.WinDLL',side_effect=AssertionError('no native'),create=True):
            self.assertEqual(WindowsQimeiSettingsObservations()._functions,{})
            obs=WindowsQimeiSettingsObservations(api=api)
            source=StorageBuffer(b'X'*260);reply=obs.read('qimei-api','SHGetSpecialFolderPathA',0,source,0x23,1)
            self.assertEqual(reply.result,0x80000000);updated=reply.apply({'data':source})['data'];self.assertEqual(updated.read(0,20),b'F:\\controlled folder')
            self.assertEqual(api.SHGetSpecialFolderPathA.restype,C.c_int32);self.assertEqual(api.SHGetSpecialFolderPathA.argtypes,(C.c_void_p,C.c_void_p,C.c_int32,C.c_int32))
            self.assertEqual(obs.read('qimei-api','PathIsDirectoryA',b'raw path').result,0)
            self.assertEqual(obs.read('qimei-api','CreateDirectoryA',b'raw path',0).result,0)
            api.CreateDirectoryA.assert_called_once_with(b'raw path',0)
    def test_actual_initialize_fallback_and_ignored_mkdir_failures(self):
        def folder(hwnd,out,identifier,create):
            self.assertEqual(create,1)
            if identifier==0x23:C.memmove(out,b'stale\0',6);return 0
            self.assertEqual(out.raw[:6],b'stale\0');C.memmove(out,b'G:\\fixture\0',11);return 256
        api=self.api(folder);obs=WindowsQimeiSettingsObservations(api=api);settings=QimeiSettings()
        self.assertTrue(settings.initialize(b'controlled-owner',obs));self.assertEqual(settings.initialized,1)
        self.assertTrue(settings.path.startswith(b'G:\\fixture\\Tencent\\qimei\\'))
        self.assertEqual([c.args[2] for c in api.SHGetSpecialFolderPathA.call_args_list],[0x23,0x1A])
        self.assertGreater(api.CreateDirectoryA.call_count,0)
    def test_both_folder_false_source_root_relative_and_errors(self):
        api=self.api(lambda *a:0);obs=WindowsQimeiSettingsObservations(api=api);settings=QimeiSettings();settings.initialize(b'owner',obs)
        self.assertTrue(settings.path.startswith(b'\\'));api.PathIsDirectoryA.assert_not_called();api.CreateDirectoryA.assert_not_called()
        with self.assertRaises(QimeiRequestBoundary):obs.read('other','PathIsDirectoryA',b'x')
        error=RuntimeError('controlled API');api.PathIsDirectoryA.side_effect=error
        with self.assertRaises(RuntimeError) as raised:obs.read('qimei-api','PathIsDirectoryA',b'x')
        self.assertIs(raised.exception,error)
