"""MODEL checks for the narrow encoder operation boundary (no Source runtime)."""
import hashlib
import pytest
from qq_nt_replica.primary_request_encoder import RequestKeyMaterial, encode_cached_material_request
from qq_nt_replica.primary_request_random import RequestRandom


def test_operation_receives_entire_ciphertext_digest_and_once_drawn_nonce():
    material = RequestKeyMaterial(bytes(33), bytes(33), b'', b'', bytes(32))
    random = RequestRandom(123)
    reference = RequestRandom(123)
    reference.draw_bytes(12)
    nonce = reference.draw_bytes(16)
    calls = []
    def operation(digest, actual_nonce):
        calls.append((digest, actual_nonce))
        return actual_nonce + bytes(32)
    result = encode_cached_material_request(b't', b'payload', material, bytes(32), 0,
                                            random, fingerprint_operation=operation)
    assert calls == [(hashlib.sha256(result.ciphertext).digest(), nonce)]
    assert result.fingerprint == nonce + bytes(32)
    assert random.draw_bytes(16) == reference.draw_bytes(16)


def test_operation_failure_propagates_and_access_mode_does_not_call_it():
    material = RequestKeyMaterial(bytes(33), bytes(33), b'', b'', bytes(32))
    def failure(*args):
        raise RuntimeError('provider-domain')
    with pytest.raises(RuntimeError, match='provider-domain'):
        encode_cached_material_request(b't', b'p', material, bytes(32), 0,
                                       RequestRandom(123), fingerprint_operation=failure)
    result = encode_cached_material_request(b't', b'p', material, bytes(32), 0,
                                           RequestRandom(123), payload_mode=1,
                                           fingerprint_operation=failure)
    assert result.fingerprint == b''


def model_signer():
    from qq_nt_replica.primary_signer import PrimarySigner, SigningEnvironment
    from qq_nt_replica.primary_custom_allocator import install_model_allocator
    from qq_nt_replica.primary_notification_files import FileSelectorMaterial
    from qq_nt_replica.primary_sdk import construct_objects
    from qq_nt_replica.primary_host_services import GuestExitRegistrar
    registrar = GuestExitRegistrar()
    signer = PrimarySigner(SigningEnvironment(cursor=None, process_path=b'C:/model/p.exe',
        module_path=b'C:/model/m.dll', stack_modules=(), exit_registration=registrar), initial_stack=None,
        primary_backend='reference', retain_diagnostics=True)
    registrar.bind(signer.runtime)
    initial, pointer, raw = bytes(2), 0x7600000000, b'explicit-model-custom\0'
    material = FileSelectorMaterial(initial, pointer, raw, 'synthetic-test-input',
        'explicit-model', hashlib.sha256(initial + pointer.to_bytes(8, 'little') + raw).hexdigest())
    install_model_allocator(signer.runtime, material, supplier=signer.addresses.allocation)
    construct_objects(signer.runtime)
    from qq_nt_replica.primary_worker_consumer import _logger
    from qq_nt_replica.primary_logger import _Tree
    pointer = _logger(signer.runtime)
    for node in _Tree(signer.runtime, pointer + 64).nodes():
        if signer.runtime.memory.load(node + 32, 4) == 46:
            signer.runtime.memory.store(node + 36, 2, 4, source='MODEL configured feature46 disabled')
    return signer


def test_actual_own_create_routes_source_vm_and_preserves_sequence_on_domain_failure():
    from types import SimpleNamespace
    from qq_nt_replica.primary_worker_consumer import DeviceRecord
    from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
    class ModelCapi:
        def acquire(self, phase): return 1, 1
        def generate(self, phase, handle, buffer):
            buffer.write(bytes(range(1, 33)))
            return 1
        def release(self, phase, handle): return 1
    signer = model_signer()
    signer.initialize_own_sdk_request(request_capi=ModelCapi(),
        clock_inputs=dict(wall_seconds=lambda: 1, monotonic_ns=lambda: 1, clock_ns=lambda: 1),
        random_environment=SimpleNamespace(random_bytes=lambda count: b'1234'))
    result = signer.create_own_device_request((DeviceRecord(7, b'value'),))
    assert len(result.encoded.request.fingerprint) == 48
    assert signer._own_sdk_request.sequence == 2
    assert len(signer._own_sdk_request._pending) == 1
    assert any(vm.program.raw == __import__('qq_nt_replica.primary_sign', fromlist=['load_program']).load_program('request-fingerprint').raw for vm in signer.runtime.vms)
    signer.runtime.memory.store(signer.image_base + 0x677E1B4, 1, 4, source='MODEL unsupported current auxiliary')
    with pytest.raises(PrimarySemanticUnavailable):
        signer.create_own_device_request((DeviceRecord(8, b'next'),))
    assert signer._own_sdk_request.sequence == 2
    assert len(signer._own_sdk_request._pending) == 1


def test_current_table_pending_copy_clear_and_retention_without_reseed():
    from qq_nt_replica.primary_request_fingerprint import source_request_fingerprint
    from qq_nt_replica.primary_sign_lifecycle import public_call
    signer = model_signer()
    runtime, base = signer.runtime, signer.image_base
    pending = bytes(range(256)) * 2
    runtime.memory.write(base + 0x677DFB0, pending, source='MODEL decoded SDK pending table')
    with public_call(signer):
        first = source_request_fingerprint(runtime, bytes(range(32)), bytes(range(16)))
    assert runtime.memory.read(base + 0x618CB00, 512) == pending
    assert runtime.memory.read(base + 0x677DFB0, 512) == bytes(512)
    current = bytes(reversed(range(256))) * 2
    runtime.memory.write(base + 0x618CB00, current, source='MODEL current mutable SDK table update')
    with public_call(signer):
        second = source_request_fingerprint(runtime, bytes(range(32)), bytes(range(16)))
    assert runtime.memory.read(base + 0x618CB00, 512) == current
    assert first[:16] == second[:16] == bytes(range(16))
    assert first != second

def test_current_category_true_invokes_boolean_and_updates_actual_latch():
    from qq_nt_replica.primary_request_fingerprint import source_request_fingerprint
    from qq_nt_replica.primary_sign_lifecycle import public_call
    from qq_nt_replica.primary_logger import _Tree
    signer = model_signer()
    runtime, base = signer.runtime, signer.image_base
    with public_call(signer):
        expected = source_request_fingerprint(runtime, bytes(range(32)), bytes(range(16)))
    logger = runtime.memory.load(base + 0x67516A8, 8)
    for node in _Tree(runtime, logger + 64).nodes():
        if runtime.memory.load(node + 32, 4) == 46:
            runtime.memory.store(node + 36, 1, 4, source='MODEL existing config value enabled')
    category = runtime._allocate(40, False)
    runtime.memory.write(category, bytes(16), source='MODEL category leaf links')
    runtime.memory.store(category + 32, 0, 4, source='MODEL category key0')
    runtime.memory.store(category + 36, 46, 4, source='MODEL category feature binding')
    runtime.memory.store(base + 0x677C210, category, 8, source='MODEL current category tree root')
    assert runtime.memory.load(base + 0x677E1B0, 1) == 0
    with public_call(signer):
        actual = source_request_fingerprint(runtime, bytes(range(32)), bytes(range(16)))
    assert runtime.memory.load(base + 0x677E1B0, 1) == 1
    assert actual == expected
