"""Controlled MODEL birth checks; no actual Windows operations."""
from pathlib import Path
import sys
import unittest
import ctypes as C
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import ExitStack

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from qq_nt_replica.primary_signer import PrimarySigner, SigningEnvironment
from qq_nt_replica import primary_module_sync as sync
from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable


class ModuleSync(unittest.TestCase):
    def signer(self):
        return PrimarySigner(SigningEnvironment(cursor=None, process_path=b'C:/explicit/p.exe',
            module_path=b'C:/explicit/m.dll', stack_modules=()), initial_stack=None, primary_backend='direct')

    def test_model_birth_once_callback_failure_and_no_retry(self):
        signer = self.signer()
        runtime = signer.runtime
        self.assertEqual(sync.backend(runtime), sync.MODEL_ONLY)
        self.assertEqual(signer._module_sync_image.origin, 'MODEL_LOADER_BIRTH')
        flag = runtime.image_base + 0x674D418
        def unavailable():
            self.assertFalse(signer._module_sync_image.held)
            raise PrimarySemanticUnavailable('controlled callback unavailable')
        with self.assertRaisesRegex(PrimarySemanticUnavailable, 'controlled callback'):
            sync.selector_once(runtime, unavailable)
        self.assertEqual(runtime.memory.load(flag, 8), 1)
        with self.assertRaisesRegex(PrimarySemanticUnavailable, '787840'):
            sync.selector_once(runtime, lambda: self.fail('callback retried'))

    def test_normal_once_and_birth_guards(self):
        signer = self.signer()
        runtime = signer.runtime
        called = []
        self.assertEqual(sync.selector_once(runtime, lambda: called.append(1)), 0)
        self.assertEqual(sync.selector_once(runtime, lambda: called.append(2)), 0)
        self.assertEqual(called, [1])
        with self.assertRaises(InputError):
            sync.install_fresh_image(signer)
        with self.assertRaises(InputError):
            sync.bind_fresh_runtime(signer)
        with self.assertRaises(InputError):
            sync._ModuleSync(signer, None)

    def test_backend_mutation_and_region_replacement_rejected(self):
        signer = self.signer()
        resource = signer._module_sync_image
        resource._backend = sync.MODEL_NATIVE
        with self.assertRaises(InputError):
            sync.backend(signer.runtime)
        resource._backend = sync.MODEL_ONLY
        address = signer.image_base + 0x674D4D0
        signer.memory.unmap(address)
        signer.memory.map(address, bytearray(8), name='replacement is not birth', initialized=True)
        with self.assertRaises(InputError):
            sync.shared_acquire(signer.runtime)

    def test_controlled_adapter_same_backing_and_unknown_retention(self):
        # Explicit adapter-only ABI boundary; this does not mint a factory owner.
        from qq_nt_replica.primary_windows_msf_once import WindowsModuleSync
        from qq_nt_replica.primary_memory import PrimaryMemory, PrimaryMemoryLimit
        memory = PrimaryMemory()
        base = 0x180000000
        for rva in (0x674D4D0, 0x674D4D8):
            memory.map(base + rva, bytearray(8), name='controlled ABI cell', initialized=True)
        owner = SimpleNamespace(_state='closing', _busy=False, _check_owner=lambda: None)
        resource = SimpleNamespace(runtime=object(), backend=sync.MODEL_NATIVE, memory=memory,
            base=base, owner=owner, callbacks=0, validate=lambda runtime: None,
            permit=lambda actual, operation: actual is owner)
        with patch.object(sync, '_resource', return_value=resource):
            port = WindowsModuleSync(resource)
        class ControlledFunction:
            def __call__(self, pointer):
                return 123  # The adapter must not consume a void API return.
        for name in ('AcquireSRWLockExclusive', 'ReleaseSRWLockExclusive', 'WakeAllConditionVariable'):
            function = ControlledFunction()
            port.kernel = SimpleNamespace(**{name: function})
            self.assertIsNone(port._api(name, 0x1234))
            self.assertIsNone(function.restype)
            self.assertEqual(function.argtypes, (C.c_void_p,))
        port.kernel = None
        calls = []
        def api(name, pointer):
            calls.append(name)
            (C.c_ubyte * 8).from_address(pointer)[0] = 9 if name.startswith('Acquire') else 0
        with patch.object(port, '_api', side_effect=api):
            self.assertEqual(port.acquire(), 0)
            self.assertEqual(memory.load(base + 0x674D4D0, 8), 9)
            with self.assertRaises(PrimaryMemoryLimit):
                memory.unmap(base + 0x674D4D0)
            self.assertEqual(port.release(), 0)
            self.assertEqual(port.wake(), 0)
            port.dispose_terminal()
        self.assertEqual(calls, ['AcquireSRWLockExclusive', 'ReleaseSRWLockExclusive', 'WakeAllConditionVariable'])
        self.assertFalse(port.records)
        with patch.object(sync, '_resource', return_value=resource):
            unknown = WindowsModuleSync(resource)
        with patch.object(unknown, '_api', side_effect=RuntimeError('controlled unknown API outcome')):
            with self.assertRaises(RuntimeError):
                unknown.acquire()
        self.assertEqual(unknown.state, 'acquire_unknown')
        with self.assertRaises(PrimarySemanticUnavailable):
            unknown.dispose_terminal()
        self.assertTrue(unknown.records)
        # Test-only release after proving the injected call never entered Windows.
        for token, view, native in unknown.records.values():
            memory._unpin_native_span(token, unknown)
            view.release()
        unknown.records.clear()

    def test_locale_logger_and_reporter_share_birth_resource(self):
        from qq_nt_replica.primary_shared_locale import FACETS
        from qq_nt_replica import primary_super_reporter as reporter
        from qq_nt_replica.primary_logger import _srw
        signer = self.signer()
        runtime = signer.runtime
        resource = signer._module_sync_image
        pointer = runtime.image_base + 0x674D4D0
        _srw(runtime, pointer, True)
        self.assertTrue(resource.held)
        with self.assertRaises(PrimarySemanticUnavailable):
            sync.shared_acquire(runtime)
        _srw(runtime, pointer, False)
        identifier = FACETS[0][3]
        signer._shared_locale_image.initialize_identifier(runtime, identifier)
        self.assertFalse(resource.held)
        self.assertEqual(runtime.memory.load(runtime.image_base + identifier, 8), (1 << 64) - 1)
        reporter.install_image(runtime.memory, runtime.image_base)
        flag = runtime.image_base + 0x677C0C8
        called = []
        reporter._once(runtime, flag, lambda: called.append(resource.held))
        self.assertEqual(called, [False])
        self.assertFalse(resource.held)
        self.assertIn(('75AF50.lock', pointer), runtime.events)
        self.assertIn(('super_reporter.once_notify', runtime.image_base + 0x674D4D8, flag), runtime.events)
        runtime.memory.store(runtime.tls_epoch_address, 0, 4, source='controlled portable TLS epoch')
        device = runtime._random_device()
        self.assertEqual(runtime._random_device(), device)
        self.assertFalse(resource.held)
        self.assertEqual(runtime.events.count(('call_once.lock', pointer)), 1)
        self.assertEqual(runtime.events.count(('call_once.unlock', pointer)), 1)

    def test_adapter_unheld_api_and_record_failures_retain_backing(self):
        from qq_nt_replica.primary_windows_msf_once import WindowsModuleSync
        from qq_nt_replica.primary_memory import PrimaryMemory, PrimaryMemoryLimit
        for scenario in ('wake_api', 'wake_record', 'release_record', 'terminal_release_record', 'wake_both'):
            with self.subTest(scenario=scenario):
                memory = PrimaryMemory()
                base = 0x180000000
                for rva in (0x674D4D0, 0x674D4D8):
                    memory.map(base + rva, bytearray(8), name='controlled private-stub cell', initialized=True)
                owner = SimpleNamespace(_state='closing', _busy=False, _check_owner=lambda: None)
                resource = SimpleNamespace(runtime=object(), backend=sync.MODEL_NATIVE, memory=memory,
                    base=base, owner=owner, callbacks=0, validate=lambda runtime: None,
                    permit=lambda actual, operation: actual is owner)
                with patch.object(sync, '_resource', return_value=resource):
                    port = WindowsModuleSync(resource)
                api_error = RuntimeError('controlled native-call failure')
                record_error = ValueError('controlled write-record failure')
                calls = []
                def private_stub(name, pointer):
                    calls.append(name)
                    if scenario in ('wake_api', 'wake_both'):
                        raise api_error
                try:
                    with patch.object(port, '_api', side_effect=private_stub):
                        if scenario in ('release_record', 'terminal_release_record'):
                            port.acquire()
                        with ExitStack() as stack:
                            if scenario in ('wake_record', 'release_record', 'terminal_release_record', 'wake_both'):
                                stack.enter_context(patch.object(memory, '_record_native_write', side_effect=record_error))
                            expected = BaseExceptionGroup if scenario == 'wake_both' else (
                                RuntimeError if scenario == 'wake_api' else ValueError)
                            with self.assertRaises(expected) as failure:
                                operation = port.dispose_terminal if scenario == 'terminal_release_record' else (
                                    port.release if scenario == 'release_record' else port.wake)
                                operation()
                        if scenario == 'wake_both':
                            self.assertEqual(failure.exception.exceptions, (api_error, record_error))
                        else:
                            self.assertIs(failure.exception, api_error if scenario == 'wake_api' else record_error)
                        self.assertEqual(port.state, 'unheld')
                        before = dict(port.records)
                        recorded_failures = tuple(port.failures)
                        self.assertTrue(recorded_failures)
                        call_count = len(calls)
                        for operation in (port.wake, port.dispose_terminal):
                            with self.assertRaises(PrimarySemanticUnavailable):
                                operation()
                        self.assertEqual(len(calls), call_count)
                        self.assertEqual(tuple(port.failures), recorded_failures)
                        self.assertEqual(port.records, before)
                        self.assertFalse(port.closed)
                        self.assertFalse(port.active)
                        for rva in port.records:
                            with self.assertRaises(PrimaryMemoryLimit):
                                memory.unmap(base + rva)
                finally:
                    # Only private_stub ran: no Windows call or unresolved native
                    # resource exists. Test-only pin release is not a port recovery API.
                    for token, view, native in port.records.values():
                        memory._unpin_native_span(token, port)
                        view.release()
                    port.records.clear()

    def test_native_callback_routing_with_model_sync_only(self):
        # Exercise native-branch source ordering with MODEL_ONLY synchronization;
        # this is not a native factory/permit or Windows witness.
        from qq_nt_replica import primary_super_reporter as reporter
        signer = self.signer()
        runtime = signer.runtime
        runtime.memory.store(runtime.tls_epoch_address, 0, 4, source='controlled portable TLS epoch')
        allocations = []
        def invoke(actual, rva, *arguments):
            self.assertIs(actual, runtime)
            self.assertEqual((rva, arguments), (0xB75000, (1,)))
            self.assertFalse(signer._module_sync_image.held)
            address = runtime._allocate(1, False)
            allocations.append(address)
            return address
        with patch.object(sync, 'backend', return_value=sync.MODEL_NATIVE):
            with patch('qq_nt_replica.primary_worker_consumer._invoke', side_effect=invoke):
                with self.assertRaisesRegex(PrimarySemanticUnavailable, 'sourceCD18'):
                    runtime._random_device()
            self.assertEqual(runtime.memory.load(runtime.image_base + 0x6D88CA8, 8), 1)
            self.assertEqual(runtime.memory.load(runtime.image_base + 0x6D88CB0, 8), 0)
            from qq_nt_replica.primary_memory import UnknownMemory
            with self.assertRaises(UnknownMemory):
                runtime.memory.read(allocations[0], 1)
            for operation, target, flag in (
                (lambda: reporter.initialize(runtime), '0x1bf3780', 0x677C0C8),
                (lambda: reporter._registry(runtime), '0x2de0b00', 0x6D85F50),
                (lambda: reporter.submit_joint(runtime, 0x1234), '0x1c02430', 0x677C258),
            ):
                with self.assertRaisesRegex(PrimarySemanticUnavailable, target):
                    operation()
                self.assertEqual(runtime.memory.load(runtime.image_base + flag, 8), 1)
                self.assertFalse(signer._module_sync_image.held)

    def test_authentic_factory_birth_with_all_host_effects_replaced(self):
        from qq_nt_replica import primary_windows_signer as windows
        # Real public factory/WindowsSigner/PrimarySigner/birth code; all host
        # acquisition boundaries are mocks. This proves no actual Windows state.
        constructors = ('WindowsCallerAPIBackend', 'WindowsCallerBridge', 'WindowsSDKThreadService',
            'WindowsCallerObservations', 'WindowsProviderObservations', 'WindowsWorkerObservations',
            'WindowsDeviceFileObservations', 'WindowsCoreObservations')
        with ExitStack() as stack:
            stack.enter_context(patch.object(windows, '_validated_paths', return_value=(Path('controlled.dll'), Path('controlled'))))
            for name in constructors:
                stack.enter_context(patch.object(windows, name))
            windows.WindowsSDKThreadService.return_value.observations.return_value = None
            stack.enter_context(patch.object(windows.DeviceFactory, 'windows'))
            stack.enter_context(patch.object(windows.WindowsSigner, '_host_environment',
                return_value=(b'C:/explicit/p.exe', None, ())))
            stack.enter_context(patch.object(windows.WindowsSigner, '_initialize_notification_statics'))
            stack.enter_context(patch.object(windows.WindowsSigner, '_initialize_crt'))
            stack.enter_context(patch('qq_nt_replica.primary_windows_allocator_issuer.install_early_allocator'))
            stack.enter_context(patch('qq_nt_replica.primary_windows_outer_sync.bind_outer_sync'))
            stack.enter_context(patch('qq_nt_replica.primary_windows_signer_setup.IndependentWindowsSetup'))
            owner = windows.open_windows_signer(bridge_path='controlled.dll', storage_root='controlled',
                host_profile_string=b'explicit-model-profile', primary_backend='direct',
                outer_login_config={}, outer_sync_permit=lambda actual, operation: False)
            resource = owner.signer._module_sync_image
            self.assertIs(resource.owner, owner)
            self.assertTrue(resource.sealed)
            self.assertNotIn(owner, sync._PENDING)
            self.assertEqual(sync.backend(owner.signer.runtime), sync.MODEL_NATIVE)
            self.assertEqual(resource.origin, 'MODEL_LOADER_BIRTH')
            self.assertIsNone(resource.port)
            with self.assertRaises(PrimarySemanticUnavailable):
                sync.shared_acquire(owner.signer.runtime)
            self.assertFalse(resource.port.records)
            owner._state = 'closing'
            sync.dispose_terminal(owner)
            with self.assertRaises(InputError):
                sync.shared_acquire(owner.signer.runtime)


if __name__ == '__main__':
    unittest.main()
