import ctypes
import unittest
import textwrap
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_windows_device_collection import WindowsDeviceCollectionObservations as Port
from qq_nt_replica.primary_memory import PrimaryMemory

class Cursor(unittest.TestCase):
    def run_cursor(self,result):
        class Function:
            def __call__(self,pointer):
                value=ctypes.cast(pointer,ctypes.POINTER(ctypes.c_int32*2)).contents
                value[0]=-123;value[1]=2147483647
                return result
        function=Function();library=NS(GetCursorPos=function,_handle=987)
        component=NS(close=lambda:None)
        with patch('ctypes.WinDLL',return_value=library) as load,patch('ctypes.set_last_error'),patch('ctypes.get_last_error',return_value=5),patch('_ctypes.FreeLibrary') as free:
            port=Port(components=(component,));load.assert_not_called()
            memory=PrimaryMemory();memory.map(0x1000,bytearray(0x400),name='cursor temp',initialized=False)
            memory.map(0x2000,bytearray(b'Z'*0x100),name='owner',initialized=True)
            data=NS(memory=memory)
            raw=port.take(data,'GetCursorPos',())
            self.assertEqual(raw,(result,(-123).to_bytes(4,'little',signed=True)+(2147483647).to_bytes(4,'little',signed=True) if result else b''))
            self.assertEqual(port._cursor.last_error,5)
            self.assertEqual(ctypes.sizeof(function.argtypes[0]._type_),8)
            # Execute the exact source consumer POINT write/copy statements.
            import qq_nt_replica.primary_device_cold as cold
            source=Path(cold.__file__).read_text(encoding='utf-8')
            begin=source.index("        result, raw = refresh_observe(runtime, 'GetCursorPos'")
            end=source.index("        memory.store(owner + 0x54",begin)
            operations=NS(require_data=lambda r:None,observe=lambda name,args:port.take(data,name,args))
            from qq_nt_replica.primary_device_refresh import _observe
            exec(textwrap.dedent(source[begin:end]),dict(refresh_observe=_observe,runtime=data,_operations=operations,memory=memory,rbp=0x1000,owner=0x2000,InputError=ValueError))
            self.assertEqual(memory.read(0x204c,8),raw[1] if result else b'Z'*8)
            port.close();free.assert_called_once_with(987)
    def test_success_signed_long_point_and_real_consumer_copy(self):self.run_cursor(1)
    def test_false_preserves_owner_no_fake_point(self):self.run_cursor(0)
    def test_ffi_exception_propagates_and_library_closed(self):
        library=NS(GetCursorPos=NS(),_handle=98)
        error=RuntimeError('ffi')
        class Function:
            def __call__(self,pointer):raise error
        library.GetCursorPos=Function()
        with patch('ctypes.WinDLL',return_value=library),patch('ctypes.set_last_error'),patch('_ctypes.FreeLibrary') as free:
            port=Port(components=(NS(close=lambda:None),))
            with self.assertRaises(RuntimeError) as caught:port.take(object(),'GetCursorPos',())
            self.assertIs(caught.exception,error)
            port.close();free.assert_called_once_with(98)
