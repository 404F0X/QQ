import unittest,ctypes as C
from types import SimpleNamespace as NS
from unittest.mock import Mock
from qq_nt_replica.primary_qimei_kind2_payload import populate_local_tail
from qq_nt_replica.primary_qimei_system_sources import QimeiSystemSources
from qq_nt_replica.primary_qimei_observations import QimeiApiReply
from qq_nt_replica.primary_qimei_request import QimeiRequestState,RequestSlot,QimeiRequestBoundary
from qq_nt_replica.primary_qimei_storage import StorageBuffer
from qq_nt_replica.primary_windows_qimei_system import WindowsQimeiSystemObservations
EPOCH=116444736000000000
class Obs:
    def __init__(self,ticks):self.ticks=ticks;self.calls=[]
    def read(self,namespace,name,*args):
        self.calls.append((name,args))
        if name=='GetSystemTimeAsFileTime':
            assert args[0].read()==bytes(8)
            return QimeiApiReply(0,(('data',0,self.ticks.to_bytes(8,'little')),))
        return QimeiApiReply(0xFFFFFFFF if name=='GetKeyboardType' else 0x80000000+args[0])
class Tail(unittest.TestCase):
    def test_whole_tail_order_and_only_four_writes(self):
        obs=Obs(EPOCH+10000000);state=QimeiRequestState([RequestSlot() for _ in range(48)]);state.set_u32(1,9);before=list(state.slots)
        populate_local_tail(state,QimeiSystemSources(obs))
        self.assertEqual([(n,a) for n,a in obs.calls[:3]],[('GetKeyboardType',(0,)),('GetSystemMetrics',(0,)),('GetSystemMetrics',(1,))])
        self.assertEqual([int.from_bytes(s.data,'little') for s in state.slots[20:24]],[0xFFFFFFFF,0x80000000,0x80000001,1])
        self.assertEqual([s.tag for s in state.slots[20:24]],[4,4,4,5])
        for i in list(range(20))+list(range(24,48)):self.assertEqual(state.slots[i],before[i])
    def test_filetime_wrap_truncation_and_cap(self):
        for ticks,want in ((EPOCH,0),(EPOCH-1,0),(EPOCH-9999999,0),(EPOCH-10000001,-1),(EPOCH+9999999,0),(EPOCH+32536799999*10000000,32536799999),(EPOCH+32536800000*10000000,-1),(0,-11644473600),((EPOCH+(1<<63))&((1<<64)-1),-922337203685)):
            self.assertEqual(QimeiSystemSources(Obs(ticks)).request_time(),want&((1<<64)-1))
    def test_actual_port_ABI_copy_and_exception(self):
        api=NS()
        def filetime(buffer):C.memmove(buffer,(EPOCH+1).to_bytes(8,'little'),8)
        names=('RegOpenKeyExA','RegQueryValueExA','RegEnumKeyExA','RegCloseKey','GetModuleHandleA','GetModuleFileNameA','WideCharToMultiByte','EnumDisplayDevicesW','GetFileVersionInfoSizeA','GetFileVersionInfoA','VerQueryValueA','GetCurrentProcess','GetCurrentProcessId','GetProcAddress','GetComputerNameA','GetUserNameA','GetTimeZoneInformation','GlobalMemoryStatusEx','GetKeyboardLayoutList','GetProcessHeap','HeapAlloc','HeapFree','IsUserAnAdmin','_localtime64_s','GetDriveTypeA','QueryDosDeviceA','GetVersionExA','GetNativeSystemInfo','GetCursorPos','GetKeyboardType','GetSystemMetrics','GetSystemTimeAsFileTime')
        for name in names:setattr(api,name,Mock(return_value=-1))
        api.GetSystemTimeAsFileTime.side_effect=filetime
        backend=WindowsQimeiSystemObservations(api);self.assertEqual(QimeiSystemSources(backend).request_time(),0)
        self.assertIsNone(api.GetSystemTimeAsFileTime.restype);self.assertEqual(api.GetKeyboardType.argtypes,(C.c_int32,))
        self.assertEqual(backend.read('qimei-api','GetKeyboardType',0).result,0xFFFFFFFF)
        error=RuntimeError('controlled');api.GetSystemMetrics.side_effect=error
        with self.assertRaises(RuntimeError) as raised:backend.read('qimei-api','GetSystemMetrics',0)
        self.assertIs(raised.exception,error)
        with self.assertRaises(QimeiRequestBoundary):backend.read('qimei-api','GetSystemTimeAsFileTime',StorageBuffer(bytes(7)))
        backend.close()
