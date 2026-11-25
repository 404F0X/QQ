"""MODEL public-operation ports; actual pure parser and original pending checks."""
import unittest
from dataclasses import replace
from test_primary_source_cold12_binding import ModelOwner, Inputs
from test_primary_source_cold12_reply import frame
from qq_nt_replica.primary_windows_signer import WindowsSigner
from qq_nt_replica.primary_source_cold12_binding import DisabledEnvironment
from qq_nt_replica.primary_own_sdk_response import OwnCompletionResult
from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable


class Owner(ModelOwner):
    receive_own_cold12 = WindowsSigner.receive_own_cold12

    def __init__(self):
        super().__init__()
        self.operations = []
        self.result = OwnCompletionResult('failed', 'sdk_status', 1003, False, None)
        self.error = None
        self.reenter = None

    def complete_own_device_request(self, original, payload, *, transport_status):
        assert not self._busy
        self.operations.append(('complete', original, payload, transport_status))
        self._signer._own_sdk_request._take(original)
        if self.reenter:
            self.reenter()
        if self.error:
            self._state = 'failed'
            raise self.error
        return self.result

    def cancel_own_device_request(self, original):
        assert not self._busy
        self.operations.append(('cancel', original))
        self._signer._own_sdk_request.cancel_device_request(original)
        if self.error:
            self._state = 'failed'
            raise self.error


class Receive(unittest.TestCase):
    def fixture(self):
        owner = Owner()
        owner.bind_own_cold12(Inputs(), own_inputs=False, appid_override=None,
                              env_setting=DisabledEnvironment())
        first, second = owner.request(), owner.request(2)
        encoded = owner.encode_own_cold12(first)
        return owner, first, second, replace(encoded, wire_sequence=0x80000001)

    def wire(self, encoded, **values):
        return frame(sequence=encoded.wire_sequence, command=encoded._request.command,
                     **values)

    def test_success_forwards_exact_original_payload_and_result(self):
        owner, first, second, encoded = self.fixture()
        result = owner.receive_own_cold12(encoded, self.wire(encoded, status=0, payload=b'MODEL-envelope'))
        self.assertIs(result, owner.result)
        self.assertEqual(owner.operations, [('complete', first, b'MODEL-envelope', 0)])
        self.assertEqual([q for q,b in owner._signer._own_sdk_request._pending], [second])
        self.assertEqual(len(owner.signs), 1)
        self.assertFalse(owner._own_cold12._active)

    def test_nonzero_signed_sso_only_cancels_target(self):
        owner, first, second, encoded = self.fixture()
        result = owner.receive_own_cold12(encoded, self.wire(encoded, status=-7))
        self.assertEqual((result.outcome, result.stage, result.code), ('failed', 'sso', -7))
        self.assertEqual(owner.operations, [('cancel', first)])
        self.assertEqual([q for q,b in owner._signer._own_sdk_request._pending], [second])
        self.assertFalse(result.cache_updated); self.assertIsNone(result.publication)

    def test_parse_mismatch_and_foreign_rejections_preserve_pending(self):
        owner, first, second, encoded = self.fixture()
        other, _, _, foreign = self.fixture()
        cases = [(encoded, b'', InputError),
                 (encoded, frame(sequence=2, command=first.command), InputError),
                 (encoded, frame(sequence=encoded.wire_sequence, command=b'wrong'), InputError),
                 (encoded, self.wire(encoded, encryption=1), PrimarySemanticUnavailable),
                 (replace(encoded, sdk_sequence=99), self.wire(encoded), InputError),
                 (replace(encoded, wire_sequence=True), self.wire(encoded), InputError),
                 (foreign, self.wire(foreign), InputError)]
        for data, wire, error in cases:
            with self.assertRaises(error):owner.receive_own_cold12(data, wire)
            self.assertEqual(owner.operations, [])
            self.assertEqual([q for q,b in owner._signer._own_sdk_request._pending], [first, second])
            self.assertEqual(owner._state, 'open');self.assertFalse(owner._signer.failed)
            self.assertFalse(owner._own_cold12._active)
        owner.cancel_own_device_request(first)
        with self.assertRaises(InputError):owner.receive_own_cold12(encoded, self.wire(encoded))
        owner._own_cold12.close()
        with self.assertRaises(InputError):owner.receive_own_cold12(encoded, self.wire(encoded))

    def test_stateful_exceptions_and_reentry_clear_active(self):
        for status in (0, -1):
            owner, first, second, encoded = self.fixture()
            error = RuntimeError('MODEL stateful port failure');owner.error = error
            with self.assertRaises(RuntimeError) as caught:
                owner.receive_own_cold12(encoded, self.wire(encoded, status=status))
            self.assertIs(caught.exception, error)
            self.assertFalse(owner._own_cold12._active)
            self.assertEqual([q for q,b in owner._signer._own_sdk_request._pending], [second])
        owner, first, second, encoded = self.fixture()
        owner.reenter = lambda: owner.receive_own_cold12(encoded, self.wire(encoded, status=0))
        with self.assertRaisesRegex(InputError, 'reenter'):
            owner.receive_own_cold12(encoded, self.wire(encoded, status=0))
        self.assertFalse(owner._own_cold12._active)
        self.assertEqual(len(owner.operations), 1)


if __name__ == '__main__':unittest.main()
