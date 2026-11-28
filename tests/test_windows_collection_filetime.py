import ctypes
import os
import threading
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_windows_system_records import WindowsSystemRecordAPIBackend, WindowsSystemRecordObservations
from qq_nt_replica.primary_windows_device_process_records import WindowsDeviceProcessRecordObservations
from qq_nt_replica.primary_windows_device_collection import WindowsDeviceCollectionObservations

class Filetime(unittest.TestCase):
    def port(self,function):
        backend=object.__new__(WindowsSystemRecordAPIBackend)
        backend._closed=False;backend._owner=(os.getpid(),threading.get_native_id())
        backend.kernel=NS(GetSystemTimeAsFileTime=function)
        backend.close=lambda:None # mock owns no DLLs or native resources
        system=WindowsSystemRecordObservations(backend=backend)
        process=WindowsDeviceProcessRecordObservations(system)
        port=WindowsDeviceCollectionObservations(components=(process,system))
        port._data=NS(events=[])
        return port

    def test_actual_backend_tuple_through_process_system_to_filetime(self):
        expected=0xfedcba9876543210;calls=[]
        class Function:
            def __call__(self,output):
                calls.append((self.restype,self.argtypes))
                ctypes.memmove(output,expected.to_bytes(8,'little'),8)
                return None
        function=Function();port=self.port(function)
        with patch('ctypes.get_last_error',return_value=0):
            self.assertEqual(port.filetime(),expected)
        self.assertEqual(calls,[(None,(ctypes.c_void_p,))])
        port.close()

    def test_ffi_failure_is_original_and_not_default_clock(self):
        error=RuntimeError('ffi')
        class Function:
            def __call__(self,output):raise error
        port=self.port(Function())
        with self.assertRaises(RuntimeError) as caught:port.filetime()
        self.assertIs(caught.exception,error);port.close()

    def test_nonvoid_ffi_return_still_rejected_by_system(self):
        class Function:
            def __call__(self,output):return 1
        port=self.port(Function())
        from qq_nt_replica.errors import InputError
        with patch('ctypes.get_last_error',return_value=0):
            with self.assertRaisesRegex(InputError,'void API returned a value'):port.filetime()
        port.close()
