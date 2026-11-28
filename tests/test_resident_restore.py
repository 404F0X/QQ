"""Model governance fixture: no native bridge or SDK execution."""
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from qq_nt_replica.primary_windows_threads import WindowsSDKThreadService, _LIVE_SERVICES
from qq_nt_replica.primary_host_services import GuestExitRegistrar
from qq_nt_replica import primary_shared_locale as tls
from qq_nt_replica.errors import InputError

class ResidentRestoreTests(unittest.TestCase):
    def exercise(self, *, failure=None, nested=False, bad_ticket=False):
        tid = threading.get_native_id()
        region = object()
        class Memory:
            def _span(self, address, size): return region, 0
            def load(self, address, size):
                if address == 0x1000 + 0xD8: return 2
                for offset in (0x28, 0x60):
                    head = 0x1000 + offset
                    if address in (head, head+8): return head
                    if address == head+16: return 0
                raise AssertionError(address)
        runtime = NS(image_base=0, memory=Memory(), allocations={0x2000:0xD78},
                     tls_base_address=0x2000, tls_epoch_address=0x20A8,
                     _main_generation=0, _execute_depth=0, _program_calls=[],
                     _execute_thread=None, _active_main=None)
        service = object.__new__(WindowsSDKThreadService)
        service._runtime=runtime;service._owner=(os.getpid(),tid+1);service._closed=False
        service._execution=threading.Lock();service._execution.acquire();service._execution_tid=tid
        registrar=GuestExitRegistrar();registrar.bind(NS(image_base=0,invoke=lambda:None))
        service._registrar=registrar
        state=NS(task=0x1000,call_pending=False,local_initialized=False,phase='loop',iterations=0,mode=2,frame=1,local_list=0)
        row={'task':state.task,'_checkpoint':threading.Event(),'_resume':threading.Event()}
        service._secondary=[row]
        service._secondary_row=lambda:row
        domain={'tls':0x2000,'services_closed':False,'owner_state':{'tls_base_address':0x3000,'tls_epoch_address':0x30A8}}
        service._crt_domains={tid:domain}
        source=object.__new__(tls._SharedLocaleSource)
        source.epoch=object();source.model_input=None;source.source_kind='fixture-governance-only'
        source._registered_module_domains={id(domain):(service,domain,tid,0x2000,region,source.epoch)}
        runtime._shared_locale_source=source
        _LIVE_SERVICES.add(service)
        continued=[]
        class Resume:
            def clear(self): pass
            def wait(self):
                self_test.assertTrue(service._execution_tid is None)
                self_test.assertFalse(service._execution.locked())
                with self_test.assertRaises(InputError): registrar.current_lease()
                if failure == 'wait': raise RuntimeError('wait failure')
                row['_ticket']=(1,tid+int(bad_ticket),'close')
        self_test=self;row['_resume']=Resume()
        try:
            with patch.object(tls._SharedLocaleSource,'validate_image',side_effect=RuntimeError('restore failure') if failure=='restore' else None):
                with registrar.operation() as outer:
                    from contextlib import nullcontext
                    with registrar.operation() if nested else nullcontext(outer) as lease:
                        try:
                            service.resident_checkpoint(runtime,state)
                            continued.append(registrar.current_lease())
                            self.assertTrue(runtime._current_module_tls_receipt.active)
                            self.assertIs(runtime._current_module_tls_receipt.domain,domain)
                        finally:
                            self.assertIs(registrar.current_lease(),lease)
                            self.assertFalse(outer.suspended)
                            self.assertTrue(service._execution.locked())
                            self.assertEqual(service._execution_tid,tid)
                self.assertEqual(continued,[lease])
                self.assertEqual(row['consumed_ticket'],1)
        finally:
            service._execution.release();_LIVE_SERVICES.discard(service)
            self.assertEqual(registrar._active_operations,0)
            self.assertFalse(registrar._leases)

    def test_resume_callback(self): self.exercise()
    def test_nested_original_stack(self): self.exercise(nested=True)
    def test_restore_error_preserved(self):
        with self.assertRaisesRegex(RuntimeError,'restore failure'): self.exercise(failure='restore')
    def test_wait_error_preserved(self):
        with self.assertRaisesRegex(RuntimeError,'wait failure'): self.exercise(failure='wait')
    def test_wrong_thread_ticket_rejected(self):
        with self.assertRaisesRegex(InputError,'fresh identity-bound'): self.exercise(bad_ticket=True)

if __name__ == '__main__': unittest.main()
