import threading
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_host_services import GuestExitRegistrar, _ExecutionLease
from qq_nt_replica.primary_windows_threads import WindowsSDKThreadService as Service
from qq_nt_replica.primary_windows_signer import WindowsSigner


class CloseLease(unittest.TestCase):
    def registrar(self):
        r = GuestExitRegistrar()
        r.bind(NS(image_base=0, invoke=lambda *a: None))
        r._lifecycle = 'closed'
        return r

    def test_checkpoint_restore_and_failure_debt(self):
        for failure in (None, 'wait', 'join', 'restore', 'both'):
            with self.subTest(failure=failure):
                r = self.registrar()
                lock = threading.Lock()
                lock.acquire()
                row = dict(task=1, joined=False, state='parked_at_BD4B60')
                runtime = NS(locks={}, memory=NS(load=lambda *a: 0))
                s = object.__new__(Service)
                s._registrar, s._execution, s._runtime = r, lock, runtime
                s._secondary, s._owner = [row], (None, threading.get_native_id())
                s._closing, s._active_owner, s._execution_tid = True, True, s._owner[1]
                s._timeout_ms = 1
                s._check_owner = lambda: None
                s._queues_empty = lambda *a: None
                s._save_domain = lambda: 'saved'
                retired = []
                s._retire_joined_domains = lambda: retired.append(True)
                s._secondary_quiescent = lambda row: False
                def waiting(*a):
                    self.assertFalse(lock.locked())
                    self.assertFalse(s._active_owner)
                    self.assertTrue(all(x.suspended for x in r._leases[s._owner[1]]))
                    acquired = []
                    def worker():
                        with r._operation_lock:
                            acquired.append(True)
                    t = threading.Thread(target=worker)
                    t.start(); t.join(1)
                    self.assertFalse(t.is_alive())
                    self.assertEqual(acquired, [True])
                    if failure in ('wait', 'both'): raise ValueError('wait failure')
                    return True
                row['_checkpoint'] = NS(wait=waiting)
                s._issue_ticket = lambda *a: None
                def join(*a, **kw):
                    if failure == 'join': raise ValueError('join failure')
                    row['joined'] = True
                s._join_secondary = join
                restored = []
                def restore(saved):
                    self.assertEqual(saved, 'saved')
                    self.assertTrue(lock.locked())
                    self.assertTrue(s._active_owner)
                    self.assertIs(r.current_lease(), inner)
                    self.assertFalse(outer.suspended)
                    self.assertFalse(inner.suspended)
                    restored.append(True)
                    if failure in ('restore', 'both'): raise RuntimeError('restore failure')
                s._restore_domain = restore
                with _ExecutionLease(r, closing=True) as outer, _ExecutionLease(r, closing=True) as inner:
                    with self.assertRaises(Exception) as caught:
                        s.stop_checkpoint(runtime, 1)
                    self.assertEqual(restored, [True])
                    self.assertEqual(r._active_operations, 0)
                    if failure == 'both':
                        self.assertIsInstance(caught.exception, RuntimeError)
                        self.assertIsInstance(caught.exception.__context__, ValueError)
                    if failure in ('wait', 'join', 'restore', 'both'):
                        self.assertEqual(retired, [])
                    else:
                        self.assertEqual(retired, [True])
                    self.assertNotEqual(row['state'], 'retired')
                lock.release()

    def test_creator_final_restore_uses_live_closing_lease(self):
        from qq_nt_replica import primary_creator_domain as cd, primary_shared_locale as locale
        for failing in (False, True):
            with self.subTest(failing=failing):
                r = self.registrar()
                s = object.__new__(Service)
                s._registrar, s._runtime = r, NS()
                domain = dict(active=False, value={'state': {}}, tls=1)
                owner = NS()
                record = NS(owner=owner, domain=domain, ptd=None, close_lease=None, validate=lambda **kw: None)
                s._save_domain = lambda: {}
                seen = []
                def restore(saved):
                    self.assertIs(r.current_lease(), record.close_lease)
                    self.assertTrue(record.close_lease.active)
                    self.assertFalse(domain['active'])
                    seen.append(True)
                    if failing: raise RuntimeError('restore failure')
                s._restore_domain = restore
                def release(self):
                    with s._creator_closing_context():
                        pass
                def close(self):
                    return self._release_resources()
                # Original close-path frame checks are retained using controlled Python methods.
                with patch.object(WindowsSigner, 'close', close), patch.object(WindowsSigner, '_release_resources', release), patch.object(cd, '_for_service', return_value=record), patch.object(cd, '_safe_restore', side_effect=lambda service, state: state), patch.object(locale, '_invalidate_module_tls'):
                    owner = object.__new__(WindowsSigner)
                    record.owner = owner
                    if failing:
                        with self.assertRaisesRegex(RuntimeError, 'restore failure'): owner.close()
                    else: owner.close()
                self.assertEqual(seen, [True])
                self.assertIsNone(record.close_lease)
                self.assertEqual(r._leases, {})


if __name__ == '__main__':
    unittest.main()
