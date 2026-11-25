"""MODEL byte parser checks only; no server/authresponse or install claim."""
import unittest
from types import SimpleNamespace as NS
from qq_nt_replica import primary_own_sdk_response as reply
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable

class OwnResponseParsing(unittest.TestCase):
    def test_duplicate_bytes_append_integers_replace_and_modes(self):
        valid, fields = reply._envelope(b'\x0a\x01a\x0a\x01b\x10\x01\x10\x03\x18\x09', 0)
        self.assertTrue(valid); self.assertEqual(fields, {1:b'ab',2:3,3:9})
        self.assertEqual(reply._envelope(b'\x1a\x01d\x20\x07',1),(True,{1:b'',2:0,3:b'd',4:7}))

    def test_bad_tag_does_not_expose_plaintext(self):
        self.assertIsNone(reply._authenticated_plaintext(bytes(29), NS(key=bytes(32))))

    def test_missing_stack_inputs_are_boundaries(self):
        with self.assertRaises(PrimarySemanticUnavailable):reply._establish_fields(b'')
        with self.assertRaises(PrimarySemanticUnavailable):reply._feature_values({})
        self.assertIsNone(reply._feature_values({10:1}))
        features=reply._feature_values({1:1,2:9})
        self.assertEqual((features[1],features[2],features[4],features[9]),(1,2,2,0))

    def test_inner_and_nested_settings_duplicates(self):
        valid, fields, settings=reply._establish_fields(b'\x10\x01\x18\x02\x22\x01x\x22\x01y\x2a\x02\x08\x01\x2a\x02\x10\x00')
        self.assertTrue(valid);self.assertEqual(fields[4],b'xy');self.assertEqual(settings,{1:1,2:0})
        self.assertFalse(reply._envelope(b'\x0a\x05x',0)[0])

if __name__=='__main__':unittest.main()
