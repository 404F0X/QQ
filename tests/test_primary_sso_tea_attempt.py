"""Synthetic TEA consumer mechanics; these keys carry no issuer provenance."""
import unittest

from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_sso_tea import _decrypt_attempt, tea_decrypt, tea_encrypt


class TeaAttemptTests(unittest.TestCase):
    key = bytes(range(16))
    payload = b'MODEL-PAYLOAD-12345678'
    cipher = bytes.fromhex(
        'c770a0e4f6675b385ba2b940e2d9d09bf4655a32fa378781887e97d3b78dc90b')

    def test_early_failure_preserves_capacity(self):
        for cipher in (b'', bytes(15), bytes(17)):
            self.assertEqual(_decrypt_attempt(cipher, self.key, 99), (False, 99, None))

    def test_capacity_check_precedes_count_publication(self):
        self.assertEqual(_decrypt_attempt(self.cipher, self.key, 21), (False, 21, None))
        self.assertEqual(_decrypt_attempt(self.cipher, self.key, 22),
                         (True, 22, self.payload))

    def test_late_failure_publishes_count_without_plaintext(self):
        self.assertEqual(_decrypt_attempt(self.cipher, bytes([1]) * 16, 32),
                         (False, 15, None))

    def test_shared_count_changes_previous_key_result(self):
        ok, count, accepted = _decrypt_attempt(self.cipher, bytes([1]) * 16, 32)
        self.assertFalse(ok)
        self.assertIsNone(accepted)
        self.assertEqual(_decrypt_attempt(self.cipher, self.key, count), (False, 15, None))
        self.assertEqual(_decrypt_attempt(self.cipher, self.key, 32),
                         (True, 22, self.payload))

    def test_true_empty_is_distinct_from_public_rejection(self):
        cipher = tea_encrypt(b'', self.key, random_padding=bytes(9))
        self.assertEqual(_decrypt_attempt(cipher, self.key, 0), (True, 0, b''))
        with self.assertRaisesRegex(InputError, '^SSO_TEA_PADDING$'):
            tea_decrypt(cipher, self.key)

    def test_invalid_arguments_are_not_primitive_failure(self):
        for key in (b'bad', None):
            with self.assertRaises(InputError):
                _decrypt_attempt(self.cipher, key, 32)
        with self.assertRaises(InputError):
            _decrypt_attempt(None, self.key, 32)
        with self.assertRaises(TypeError):
            _decrypt_attempt(self.cipher, self.key, True)
        with self.assertRaises(ValueError):
            _decrypt_attempt(self.cipher, self.key, -1)
