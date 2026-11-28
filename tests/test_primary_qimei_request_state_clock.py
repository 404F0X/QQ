import unittest,ctypes as C
from unittest.mock import Mock,patch
from test_primary_qimei_kind2_request import Request
from qq_nt_replica.primary_qimei_request_state import QimeiModuleRequestState
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary,QimeiRequestState,RequestSlot
from qq_nt_replica.primary_qimei_kind2_payload import populate_base_prefix
from qq_nt_replica.primary_qimei_extra_sources import SourceText
from qq_nt_replica.primary_windows_qimei_config import WindowsQimeiConfigSources
class StateClock(unittest.TestCase):
    def test_shared_mask_low5_lock_failure(self):
        state=QimeiModuleRequestState(0x80);r=Request().request();other=Request().request();r.module_state=other.module_state=state
        state.publish(34);self.assertEqual(other.module_state.read_mask(),0x84)
        state.publish(0);self.assertEqual(state.read_mask(),0x85)
        mutex=Mock();mutex.acquire.return_value=False;s=QimeiModuleRequestState(9,mutex=mutex)
        with self.assertRaises(QimeiRequestBoundary):s.publish(2)
        self.assertEqual(s._mask,9);mutex.release.assert_not_called()
    def test_three_clock_order_preserve_overflow_and_failure(self):
        for values,want in (([4,4,3],(7,8)),([0,0x100000001,0x200000003],(1,2))):
            r=Request().request();self.assertEqual((r.payload_duration,r.dispatch_duration),(0,0))
            r.payload_duration,r.dispatch_duration=7,8;r.clock_milliseconds=Mock(side_effect=values)
            r.run(0);self.assertEqual((r.payload_duration,r.dispatch_duration),want)
        for fail_at in ('publish','t2'):
            r=Request().request();r.success=True;r.payload_duration,r.dispatch_duration=7,8
            events=[];error=RuntimeError('controlled')
            r.payload_producer.populate.side_effect=lambda *a:events.append('payload')
            r.dispatch.dispatch.side_effect=lambda *a:events.append('dispatch')
            def clock():
                events.append('clock')
                if fail_at=='t2' and events.count('clock')==3:raise error
                return events.count('clock')
            r.clock_milliseconds=clock
            def publish(kind):
                events.append('publish')
                if fail_at=='publish':raise error
            with patch.object(r.module_state,'publish',side_effect=publish):
                with self.assertRaises(RuntimeError) as raised:r.run()
            self.assertIs(raised.exception,error);self.assertEqual((r.payload_duration,r.dispatch_duration),(7,8))
            self.assertEqual(events[:4],['clock','payload','clock','dispatch'])
    def test_millisecond_same_localtime_tm_and_negative_mktime(self):
        calls=[]
        def api(lib,name,result,types,ptr):
            calls.append(name)
            if name=='GetLocalTime':C.cast(ptr,C.POINTER(C.c_uint16*8)).contents[:]=[2026,11,2,24,10,20,30,987];return None
            self.assertEqual(list(C.cast(ptr,C.POINTER(C.c_int32*9)).contents),[30,20,10,24,10,126,0,0,0]);return -1
        fake=Mock();fake._call=api
        self.assertEqual(WindowsQimeiConfigSources.clock_milliseconds(fake),(-13)&((1<<64)-1))
        self.assertEqual(calls,['GetLocalTime','_mktime64'])
    def test_prefix_order_full_dword_conditional_and_host_error(self):
        for exe,compat in ((b'',b''),(b'X',b''),(b'X',b'C')):
            system=Mock();events=[]
            for name,value in (('process_id',0xFFFFFFFF),('wow64',0x100),('is_admin',0x80000000)):
                getattr(system,name).side_effect=lambda name=name,value=value:(events.append(name),value)[1]
            system.executable_path.side_effect=lambda:(events.append('exe'),SourceText(bool(exe),exe))[1]
            system.compatibility_flags.side_effect=lambda path:(events.append('compat'),SourceText(bool(compat),compat))[1]
            state=QimeiRequestState([RequestSlot() for _ in range(48)]);populate_base_prefix(state,system)
            self.assertEqual(events,['process_id','wow64','is_admin','exe']+(['compat'] if exe else []))
            self.assertEqual(state.slots[2].data,b'\x00\x01\x00\x00');self.assertEqual(state.slots[5].data,b'\x00\x00\x00\x80')
            self.assertEqual(state.slots[1].data,exe or None);self.assertEqual(state.slots[6].data,compat or None)
        system=Mock();system.process_id.return_value=1;error=RuntimeError('controlled');system.wow64.side_effect=error
        state=QimeiRequestState([RequestSlot() for _ in range(48)])
        with self.assertRaises(RuntimeError):populate_base_prefix(state,system)
        self.assertEqual(state.slots[0].data,b'\x01\x00\x00\x00');system.is_admin.assert_not_called()
