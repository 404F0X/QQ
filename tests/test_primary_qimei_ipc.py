"""Controlled ABI only: never loads DLLs or invokes Win32."""
import ctypes as C
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from qq_nt_replica.primary_qimei_ipc import QimeiIPCPool, IPCError, object_name, _crypt
from qq_nt_replica.primary_windows_qimei_ipc import WindowsQimeiIPCBackend, create_windows_qimei_ipc

class ABI(WindowsQimeiIPCBackend):
    def __init__(self):
        super().__init__(); self.view=C.create_string_buffer(1024)
        self.calls=[];self.null=set();self.wait_status=258;self.on_wait=None;self.close_fail=False
    def _call(self,name,result,types,args):
        self._check();self.calls.append((name,result,types,args))
        if name in self.null:return 0
        if name=='MapViewOfFile':return C.addressof(self.view)
        if name=='WaitForSingleObject':
            if self.on_wait:self.on_wait()
            return self.wait_status
        if name=='CloseHandle' and self.close_fail:return 0
        if name in ('OpenFileMappingA','OpenEventA'):return 0
        if name=='CreateFileMappingA':return 0x1234567887654321
        if name=='CreateEventA':return 0x8765432112345678
        return 1

class IPCChecks(unittest.TestCase):
    def pool(self):
        runtime=object();epoch=[object()];b=ABI()
        p=QimeiIPCPool(runtime,epoch[0],lambda r:epoch[0],b)
        return p,b,epoch
    def test_source_flow_tail_and_signals(self):
        p,b,e=self.pool();self.assertTrue(p.initialize(b'owner'))
        self.assertEqual(bytes(p.states[b'owner'].cache),bytes(42))
        data=b'A'*36+b'12345';C.memmove(b.view,_crypt(data),41)
        self.assertEqual(p.consume(b'owner'),b'A'*36)
        self.assertIsNone(p.states[b'owner'].event)
        self.assertTrue(p.publish(b'owner',b'B'*36,-1))
        self.assertEqual(_crypt(b.view.raw[:41]),b'B'*36+b'12345')
        self.assertEqual([x[0] for x in b.calls].count('SetEvent'),1)
        p.dispose_terminal();self.assertFalse(b._leases)
    def test_publish_two_signals_and_input_bounds(self):
        p,b,e=self.pool();p.initialize(b'x')
        with self.assertRaises(IPCError):p.publish(b'x',b'x',1)
        self.assertFalse(p.publish(b'x',None,1));self.assertFalse(p.publish(b'x',b'a'*36,37))
        self.assertTrue(p.publish(b'x',b'C'*36,0))
        self.assertEqual(_crypt(b.view.raw[:41]),b'C'*36+bytes(5))
        self.assertEqual([x[0] for x in b.calls][-3:],['SetEvent','SetEvent','CloseHandle'])
        p.dispose_terminal()
    def test_once_wait_reset_all_statuses_and_old_zero(self):
        for status in (0,258,0xFFFFFFFF):
            p,b,e=self.pool();p.initialize(b'x');b.wait_status=status
            def wake():
                with self.assertRaises(IPCError):p.dispose_terminal()
                C.memmove(b.view,_crypt(b'D'*41),41)
            b.on_wait=wake
            self.assertEqual(p.consume(b'x'),b'D'*36)
            names=[x[0] for x in b.calls]
            self.assertEqual(names.count('WaitForSingleObject'),1)
            self.assertIn('ResetEvent',names)
            C.memset(b.view,0,41)
            self.assertEqual(p.consume(b'x'),b'D'*36)
            self.assertEqual([x[0] for x in b.calls].count('WaitForSingleObject'),1)
            p.dispose_terminal()
    def test_partial_failures_event_missing_and_repeat(self):
        p,b,e=self.pool();b.null={'CreateEventA'}
        self.assertTrue(p.initialize(b'x'))
        with patch.object(b,'read_view',wraps=b.read_view) as read:
            self.assertEqual(p.consume(b'x'),b'')
            self.assertEqual(read.call_count,2)
        self.assertIsNone(p.states[b'x'].event_wrapper)
        n=len(b.calls)
        with self.assertRaises(IPCError):p.initialize(b'x')
        self.assertEqual(len(b.calls),n);p.dispose_terminal()
        p,b,e=self.pool();b.null={'MapViewOfFile'}
        self.assertFalse(p.initialize(b'x'));self.assertIsNotNone(p.states[b'x'].mapping)
        self.assertFalse(p.publish(b'x',b'z'*36,1));p.dispose_terminal()
    def test_ownership_epoch_thread_and_disposal_failure(self):
        p,b,e=self.pool();p.initialize(b'x');view=p.states[b'x'].view
        with self.assertRaises(IPCError):b.read_view(b'other',view)
        with patch('threading.get_native_id',return_value=0):
            with self.assertRaises(IPCError):p.consume(b'x')
        old=e[0];e[0]=object()
        with self.assertRaises(IPCError):p.consume(b'x')
        e[0]=old;b.close_fail=True
        with self.assertRaises(ExceptionGroup):p.dispose_terminal()
        self.assertIsNotNone(p.states[b'x'].mapping);self.assertTrue(b._leases)
        with self.assertRaises(IPCError):p.consume(b'x')
        with self.assertRaises(IPCError):b.read_view(b'x',view)
    def test_partial_initialization_order_and_host_read_error(self):
        p,b,e=self.pool()
        def cache_failure(owner):
            self.assertIsNotNone(p.states[owner].event_wrapper)
            self.assertIsNotNone(p.states[owner].event)
            raise MemoryError('cache allocation')
        with patch.object(b,'allocate_cache',side_effect=cache_failure):
            with self.assertRaises(MemoryError):p.initialize(b'x')
        p.dispose_terminal()
        p,b,e=self.pool();p.initialize(b'x');before=bytes(p.states[b'x'].cache)
        with patch.object(b,'read_view',side_effect=RuntimeError('host read')):
            with self.assertRaisesRegex(RuntimeError,'host read'):p.consume(b'x')
        self.assertEqual(bytes(p.states[b'x'].cache),before)
        self.assertIsNotNone(p.states[b'x'].event)
        p.dispose_terminal()
    def test_null_cache_and_preserved_host_error(self):
        p,b,e=self.pool()
        with patch.object(b,'allocate_cache',return_value=None):
            self.assertFalse(p.initialize(b'x'))
        self.assertEqual(p.consume(b'x'),b'');p.dispose_terminal()
        p,b,e=self.pool()
        with patch.object(b,'allocate_cache',side_effect=MemoryError('allocator boundary')):
            with self.assertRaisesRegex(MemoryError,'allocator boundary'):p.initialize(b'x')
        self.assertIsNotNone(p.states[b'x'].mapping)
        self.assertIsNotNone(p.states[b'x'].view)
        p.dispose_terminal()
    def test_source_close_failure_retains_owned_record(self):
        p,b,e=self.pool();p.initialize(b'x');b.close_fail=True
        self.assertTrue(p.publish(b'x',b'a'*36,1))
        self.assertIsNone(p.states[b'x'].event)
        self.assertEqual(len(p._unclosed_consumed_events),1)
        b.close_fail=False;p.dispose_terminal();self.assertFalse(b._leases)
    def test_disabled_and_null_handle_publication(self):
        p,b,e=self.pool();b.null={'CreateEventA'};p.initialize(b'x')
        self.assertTrue(p.publish(b'x',b'a'*36,1))
        self.assertIsNone(p.states[b'x'].event_wrapper)
        self.assertNotIn('SetEvent',[c[0] for c in b.calls]);p.dispose_terminal()
        p,b,e=self.pool();b.null={'MapViewOfFile'};p.initialize(b'x')
        wrapper=p.states[b'x'].event_wrapper;n=len(b.calls)
        self.assertEqual(p.consume(b'x'),b'')
        self.assertFalse(p.publish(b'x',b'a'*36,1))
        self.assertIs(p.states[b'x'].event_wrapper,wrapper)
        self.assertEqual(len(b.calls),n);p.dispose_terminal()

    def test_foreign_backend_and_creator_thread(self):
        p,b,e=self.pool();p.initialize(b'x')
        other,backend,_=self.pool();other.initialize(b'x')
        with self.assertRaises(IPCError):backend.read_view(b'x',p.states[b'x'].view)
        failures=[]
        def foreign():
            try:p.consume(b'x')
            except IPCError as error:failures.append(error)
        t=threading.Thread(target=foreign);t.start();t.join()
        self.assertEqual(len(failures),1)
        p.dispose_terminal();other.dispose_terminal()

    def test_wrapper_construction_failure_keeps_mapping(self):
        p,b,e=self.pool()
        with patch.object(b,'open_event',side_effect=RuntimeError('event constructor')):
            with self.assertRaisesRegex(RuntimeError,'event constructor'):p.initialize(b'x')
        state=p.states[b'x']
        self.assertIsNotNone(state.view);self.assertIsNone(state.event_wrapper)
        self.assertIsNone(state.cache);self.assertFalse(state.enabled)
        p.dispose_terminal();self.assertFalse(b._leases)

    def test_issued_tokens_cannot_be_retargeted(self):
        p,b,e=self.pool();p.initialize(b'x')
        state=p.states[b'x']
        for token,kind in ((state.view,'view'),(state.mapping,'mapping'),(state.event,'event')):
            original=b._raw(b'x',token,kind)
            token.owner=b'other';token.kind='event' if kind!='event' else 'view'
            token.raw=456
            with self.assertRaises(IPCError):b._raw(b'other',token,token.kind)
            with self.assertRaises(IPCError):b._raw(b'x',token,token.kind)
            self.assertEqual(b._raw(b'x',token,kind),original)
        # Inspect the controlled ABI arguments, never dereference a tampered address.
        b.wait_event(b'x',state.event)
        self.assertEqual(b.calls[-1][3][0],0x8765432112345678)
        view=state.view
        p.dispose_terminal()
        self.assertFalse(b._leases)
        self.assertEqual([c[3][0] for c in b.calls if c[0]=='UnmapViewOfFile'],[C.addressof(b.view)])
        with self.assertRaises(IPCError):b._raw(b'x',view,'view')

    def test_factory_is_lazy(self):
        epoch=object()
        with patch('ctypes.WinDLL',create=True,side_effect=AssertionError('native load')):
            pool=create_windows_qimei_ipc(object(),epoch,lambda runtime:epoch)
            self.assertIsNone(pool.backend._kernel)
            pool.dispose_terminal()

    def test_exact_names_crypto_and_abi(self):
        self.assertEqual(object_name(b'owner',b'm'),b'96B5EE981AB70A4A3532C599C08C9DA0')
        p,b,e=self.pool();p.initialize(b'x')
        calls={x[0]:x for x in b.calls}
        self.assertEqual(calls['OpenFileMappingA'][3][:2],(6,0))
        self.assertEqual(calls['CreateFileMappingA'][3][2:5],(4,0,1024))
        self.assertEqual(calls['MapViewOfFile'][3],(0x1234567887654321,6,0,0,1024))
        self.assertEqual(calls['CreateEventA'][3][:3],(None,0,0))
        self.assertEqual(calls['MapViewOfFile'][2][-1],C.c_size_t)
        p.dispose_terminal()

if __name__=='__main__':unittest.main()
