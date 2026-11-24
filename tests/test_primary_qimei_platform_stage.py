import ctypes as C,unittest
from types import SimpleNamespace as NS
from unittest.mock import Mock,patch
from qq_nt_replica.primary_qimei_system_sources import QimeiSystemSources
from qq_nt_replica.primary_qimei_observations import QimeiApiReply
from qq_nt_replica.primary_qimei_kind2_payload import populate_platform_stage
from qq_nt_replica.primary_qimei_request import QimeiRequestState,RequestSlot,QimeiRequestBoundary,QimeiRequestError
from qq_nt_replica.primary_windows_qimei_system import WindowsQimeiSystemObservations
from qq_nt_replica.primary_qimei_storage import StorageBuffer
class Obs:
    def __init__(self,fail=False,dynamic=True):self.calls=[];self.fail=fail;self.dynamic=dynamic
    def read(self,space,name,*args):
        self.calls.append(name)
        if name in ('GetComputerNameA','GetUserNameA'):
            return QimeiApiReply(256,(('data',0,(b'N' if name=='GetComputerNameA' else b'')+b'\0'),))
        if name=='GetVersionExA':return QimeiApiReply(0,(('data',4,(6).to_bytes(4,'little')+(2).to_bytes(4,'little')+bytes(4)),))
        if name=='GetModuleHandleA':return QimeiApiReply(7)
        if name=='GetProcAddress':return QimeiApiReply(8 if self.dynamic else 0)
        if name=='RtlGetNtVersionNumbers':return QimeiApiReply(0,tuple((k,0,v.to_bytes(4,'little')) for k,v in zip(('major','minor','build'),(10,0,0xF000585D))))
        if name=='GetNativeSystemInfo':return QimeiApiReply(0,(('data',0,(12).to_bytes(2,'little')),))
        if name=='GlobalMemoryStatusEx':
            assert args[0].read(0,4)==(64).to_bytes(4,'little')
            return QimeiApiReply(0 if self.fail else 256,(('data',4,(0xFFFFFFFF).to_bytes(4,'little')+b''.join(v.to_bytes(8,'little') for v in (1<<40,2<<40,3<<40,4<<40,5<<40,6<<40))),))
        if name=='GetCursorPos':return QimeiApiReply(0 if self.fail else 256,(('data',0,(0xFFFFFFFF).to_bytes(4,'little')+(0x80000000).to_bytes(4,'little')),))
        raise AssertionError(name)
class Platform(unittest.TestCase):
    def test_coherent_stage_48_order_all_widths_and_failures(self):
        for fail in (False,True):
            obs=Obs(fail);state=QimeiRequestState([RequestSlot() for _ in range(48)]);state.set_u32(1,77)
            populate_platform_stage(state,QimeiSystemSources(obs));self.assertEqual(state.slots[0].data,(77).to_bytes(4,'little'))
            self.assertEqual(obs.calls,['GetComputerNameA','GetUserNameA','GetVersionExA','GetModuleHandleA','GetProcAddress','RtlGetNtVersionNumbers','GlobalMemoryStatusEx','GetNativeSystemInfo','GetCursorPos'])
            self.assertEqual(state.slots[3].data,b'N');self.assertEqual(state.slots[4],RequestSlot(1,None));self.assertEqual(int.from_bytes(state.slots[9].data,'little'),18)
            if fail:self.assertTrue(all(state.slots[i]==RequestSlot() for i in list(range(10,17))+[18,19]))
            else:
                self.assertEqual([int.from_bytes(state.slots[i].data,'little') for i in range(10,17)],[0xFFFFFFFF]+[n<<40 for n in range(1,7)])
                self.assertEqual(state.slots[18].data,b'\xff'*4);self.assertEqual(state.slots[19].data,b'\0\0\0\x80')
            converted=[];state.encode(convert_ansi=lambda value:converted.append(value) or value);self.assertEqual(converted,[b'N'])
        self.assertEqual(QimeiSystemSources(Obs(dynamic=False)).os_classification(),5)
    def test_backend_buffers_fixed_owned_proc_and_guards(self):
        api=NS()
        for name in ('RegOpenKeyExA','RegQueryValueExA','RegEnumKeyExA','RegCloseKey','GetModuleHandleA','GetModuleFileNameA','WideCharToMultiByte','EnumDisplayDevicesW','GetFileVersionInfoSizeA','GetFileVersionInfoA','VerQueryValueA','GetCurrentProcess','GetCurrentProcessId','GetProcAddress','GetComputerNameA','GetUserNameA','GetTimeZoneInformation','GlobalMemoryStatusEx','GetKeyboardLayoutList','GetProcessHeap','HeapAlloc','HeapFree','IsUserAnAdmin','_localtime64_s','GetDriveTypeA','QueryDosDeviceA','GetVersionExA','GetNativeSystemInfo','GetCursorPos'):setattr(api,name,Mock(return_value=0))
        backend=WindowsQimeiSystemObservations(api);backend._kernel_module=999;backend._wow64_procedure=888;api.GetModuleHandleA.return_value=44;api.GetProcAddress.return_value=55
        backend.read('qimei-api','GetModuleHandleA',b'ntdll.dll');backend.read('qimei-api','GetProcAddress',44,b'RtlGetNtVersionNumbers')
        self.assertEqual((backend._kernel_module,backend._wow64_procedure),(999,888))
        def version(data):
            ptr=C.cast(data,C.POINTER(C.c_uint32));ptr[1]=10;ptr[2]=0;ptr[3]=22000;return 0
        api.GetVersionExA.side_effect=version
        self.assertEqual(QimeiSystemSources(backend).os_classification(),17)
        for value,want in ((0,0),(9,1),(6,2),(12,3),(99,4)):
            def native(data):C.cast(data,C.POINTER(C.c_uint16))[0]=value
            api.GetNativeSystemInfo.side_effect=native
            self.assertEqual(QimeiSystemSources(backend).architecture(),want)
        targets=[StorageBuffer(bytes(4)) for _ in range(3)]
        def void(a,b,c):a[0]=10;b[0]=0;c[0]=0xF000585D
        with patch('ctypes.WINFUNCTYPE',return_value=lambda proc:void,create=True) as factory:
            reply=backend.read('qimei-api','RtlGetNtVersionNumbers',55,*targets)
            self.assertEqual(reply.apply(dict(zip(('major','minor','build'),targets)))['major'].read(),(10).to_bytes(4,'little'))
            self.assertIsNone(factory.call_args.args[0])
        other=WindowsQimeiSystemObservations(api)
        with self.assertRaises(QimeiRequestBoundary):other.read('qimei-api','RtlGetNtVersionNumbers',55,*targets)
        with self.assertRaises(QimeiRequestBoundary):backend.read('qimei-api','GetVersionExA',StorageBuffer(bytes(147)))
        with patch('qq_nt_replica.primary_windows_qimei_system.os.getpid',return_value=-1):
            with self.assertRaises(QimeiRequestBoundary):backend.read('qimei-api','GetCursorPos',StorageBuffer(bytes(8)))
        with patch('qq_nt_replica.primary_windows_qimei_extras.get_ident',return_value=-1):
            with self.assertRaises(QimeiRequestError):backend.read('qimei-api','GetCursorPos',StorageBuffer(bytes(8)))
        backend.close()
        with self.assertRaises(QimeiRequestError):backend.read('qimei-api','GetCursorPos',StorageBuffer(bytes(8)))

    def test_base_plus_platform_same_system_and_zeroed_names(self):
        from qq_nt_replica.primary_qimei_kind2_payload import populate_base_prefix
        class Combined(Obs):
            def read(self,space,name,*args):
                if name=='GetCurrentProcessId':return QimeiApiReply(99)
                if name=='GetCurrentProcess':return QimeiApiReply(1)
                if name=='GetProcAddress' and args[1]==b'IsWow64Process':return QimeiApiReply(0)
                if name=='IsUserAnAdmin':return QimeiApiReply(256)
                if name=='GetModuleFileNameA':return QimeiApiReply(0)
                if name in ('GetComputerNameA','GetUserNameA'):return QimeiApiReply(256,(('data',0,b'\0'),))
                return super().read(space,name,*args)
        state=QimeiRequestState([RequestSlot() for _ in range(48)]);system=QimeiSystemSources(Combined())
        populate_base_prefix(state,system);prefix=tuple(state.slots)
        populate_platform_stage(state,system)
        self.assertEqual(len(state.slots),48)
        for i in (0,1,2,5,6):self.assertEqual(state.slots[i],prefix[i])
        self.assertEqual(state.slots[3:5],[RequestSlot(),RequestSlot()])
        converted=[];stream=state.encode(convert_ansi=lambda b:converted.append(b) or b)
        self.assertTrue(stream);self.assertEqual(converted,[])
