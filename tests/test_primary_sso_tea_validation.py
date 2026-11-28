"""Public MODEL fixtures captured before the seven-zero-tail fix."""
import unittest

from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_sso_tea import tea_decrypt


class TeaValidationTests(unittest.TestCase):
    def test_controls_and_corrupted_final_blocks(self):
        # Covers all eight pad lengths and both 16/24-byte ciphertexts.
        cases = [
            ('4d', 'a77c08c044d6ab83c0409da8d4bfd3ad'),
            ('4d4f', 'fd6de28f7a2852444f5464c45f1eaaa6'),
            ('4d4f44', '5d3a6dc1c805fbb1ca02b30566b1c8c4'),
            ('4d4f4445', 'b98d055004838169cd0ccfe08f5489e2'),
            ('4d4f44454c', '10b6d4b3e8dec9c14a7985f54811b0c8'),
            ('4d4f44454c2d', '27612e4fa0180104d30dfb7cb9960b09'),
            ('4d4f44454c2d54', 'b1242f342f0c608df24d1da43efe9a26bee31d0755144792'),
            ('4d4f44454c2d5445', '1e651e839f02fcb7417cfe8de08bd323e0f04e5aac2f8292'),
        ]
        for payload, cipher in cases:
            with self.subTest(payload=payload):
                data = bytes.fromhex(cipher)
                self.assertEqual(tea_decrypt(data, bytes(range(16))), bytes.fromhex(payload))
                malformed = data[:-1] + bytes([data[-1] ^ 1])
                with self.assertRaisesRegex(InputError, '^SSO_TEA_PADDING$'):
                    tea_decrypt(malformed, bytes(range(16)))
