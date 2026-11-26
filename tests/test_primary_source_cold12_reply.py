"""Synthetic MODEL source frames, never captured SDK/authentication evidence."""
import unittest
from dataclasses import FrozenInstanceError

from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from qq_nt_replica.primary_sso_tea import tea_encrypt
from qq_nt_replica.primary_source_cold12_reply import decode_source_cold12_reply


def word(value):
    return (value & 0xffffffff).to_bytes(4, 'big')


def string(value):
    return word(len(value) + 4) + value


EXT = b'\x48\x01\xa8\x01\x02\xb2\x01\x06\x08\x03\x10\x04\x1a\x00\xc8\x01\x05\xd8\x01\x06'


def frame(*, encryption=0, command=b'MODEL.command', extension=EXT,
          compression=0, sequence=0x80000001, status=-3, skip=b'', payload=b'MODEL'):
    head = (word(sequence) + word(status) + string(b'not-command') + string(command)
            + string(b'third') + word(compression) + string(extension) + word(7))
    body = word(4 + len(head)) + head + skip + string(payload)
    if encryption == 2:
        body = tea_encrypt(body, bytes(16), random_padding=bytes(10 - ((len(body) + 1) & 7)))
    outer = word(12) + bytes((encryption, 0)) + string(b'route') + body
    return word(4 + len(outer)) + outer


class SourceCold12Reply(unittest.TestCase):
    def test_plain_and_encrypted_fields_and_immutable_output(self):
        for mode in (0, 2):
            with self.subTest(mode=mode):
                result = decode_source_cold12_reply(frame(encryption=mode))
                self.assertEqual((result.version, result.wire_sequence, result.status), (12, 0x80000001, -3))
                self.assertEqual((result.first_string, result.command, result.payload),
                                 (b'not-command', b'MODEL.command', b'MODEL'))
                self.assertEqual(dict(result.extension)[22], ((1, 3), (2, 4), (3, b'')))
                with self.assertRaises(FrozenInstanceError):
                    result.status = 0
        self.assertEqual(decode_source_cold12_reply(frame(status=1003)).status, 1003)

    def test_empty_extension_and_payload_and_grayuin_skip(self):
        result = decode_source_cold12_reply(frame(extension=b'', payload=b''))
        self.assertEqual((result.extension, result.payload), ((), b''))
        result = decode_source_cold12_reply(frame(command=b'GrayUinPro.Check', skip=b'abcd'))
        self.assertEqual(result.payload, b'MODEL')
        # Remaining==4 does not take the GrayUin skip path.
        self.assertEqual(decode_source_cold12_reply(frame(command=b'GrayUinPro.Check', payload=b'')).payload, b'')

    def test_complete_frame_and_supported_truncations_fail(self):
        good = frame()
        for bad in (b'', good[:-1], good + b'x', word(3) + good[4:]):
            with self.subTest(length=len(bad)), self.assertRaises(InputError):
                decode_source_cold12_reply(bad)
        # Rewrite total length so the L32 routing failure is independently reached.
        bad = good[:10] + word(3) + good[14:]
        with self.assertRaisesRegex(InputError, 'L32'):
            decode_source_cold12_reply(bad)
        with self.assertRaises(InputError):
            decode_source_cold12_reply(bytearray(good))

    def test_tea_tail_rejection(self):
        bad = bytearray(frame(encryption=2));bad[-1] ^= 1
        with self.assertRaises(InputError):
            decode_source_cold12_reply(bytes(bad))

    def test_unsupported_branches_do_not_become_plaintext(self):
        for data in (frame(encryption=3), frame(compression=1),
                     frame(extension=b'\x08\x01'), frame(extension=EXT + b'\x48\x01'),
                     frame(extension=EXT.replace(b'\x48\x01', b'\x48\x80\x01'))):
            with self.subTest(data=data[:10]), self.assertRaises(PrimarySemanticUnavailable):
                decode_source_cold12_reply(data)
        bad = bytearray(frame());bad[7] = 11
        with self.assertRaises(PrimarySemanticUnavailable):
            decode_source_cold12_reply(bytes(bad))

    def test_extension_structure_not_private_values(self):
        changed = EXT.replace(b'\x48\x01', b'\x48\x7f')
        self.assertEqual(dict(decode_source_cold12_reply(frame(extension=changed)).extension)[9], 127)
        # A length-six field22 whose bytes are truncated is malformed, not empty.
        with self.assertRaises(InputError):
            decode_source_cold12_reply(frame(extension=b'\xb2\x01\x06\x08'))


if __name__ == '__main__':
    unittest.main()


class Type1ReplyModel(unittest.TestCase):
    def test_current_previous_and_attempt_boundaries(self):
        from unittest.mock import patch
        from qq_nt_replica.primary_source_cold12 import SourceType1StoredPeer, SourceType1ReplyInputs
        peer=SourceType1StoredPeer(b'',b'',bytes(16))
        inputs=SourceType1ReplyInputs(b'route',peer,peer)
        plain=frame()[19:]
        wire=frame(encryption=1)
        target='qq_nt_replica.primary_source_cold12_reply._decrypt_attempt'
        with patch(target,side_effect=[(False,7,None),(True,len(plain),plain)]) as attempt:
            self.assertEqual(decode_source_cold12_reply(wire,type1=inputs).payload,b'MODEL')
            self.assertEqual(attempt.call_args_list[1].args[2],7)
        for outcome in ((True,0,b''),(False,7,None)):
            with patch(target,return_value=outcome) as attempt:
                with self.assertRaises(InputError):decode_source_cold12_reply(wire,type1=inputs)
                self.assertEqual(attempt.call_count,1 if outcome[0] else 2)
        with patch(target,side_effect=RuntimeError('MODEL')) as attempt:
            with self.assertRaises(RuntimeError):decode_source_cold12_reply(wire,type1=inputs)
            self.assertEqual(attempt.call_count,1)
        with self.assertRaises(InputError):decode_source_cold12_reply(wire)
        with self.assertRaises(InputError):SourceType1ReplyInputs(b'route',None,peer)
        with patch(target,return_value=(True,1,b'x')) as attempt:
            with self.assertRaises(InputError):decode_source_cold12_reply(wire,type1=inputs)
            self.assertEqual(attempt.call_count,1)


    def test_actual_model_cipher_rotation_and_received_route(self):
        from qq_nt_replica.primary_source_cold12 import SourceType1StoredPeer, SourceType1ReplyInputs
        from unittest.mock import patch
        previous=SourceType1StoredPeer(b'',b'',bytes(16))
        current=SourceType1StoredPeer(b'',b'',b'k'*16)
        plain=frame()[19:]
        cipher=tea_encrypt(plain,b'\xef'*16,random_padding=bytes(10-((len(plain)+1)&7)))
        outer=word(12)+b'\x01\0'+string(b'route')+cipher
        wire=word(len(outer)+4)+outer
        self.assertEqual(decode_source_cold12_reply(wire,type1=SourceType1ReplyInputs(b'route',previous)).payload,b'MODEL')
        with patch('qq_nt_replica.primary_source_cold12_reply._decrypt_attempt') as attempt:
            with self.assertRaises(InputError):decode_source_cold12_reply(wire,type1=SourceType1ReplyInputs(b'other',current,previous))
            attempt.assert_not_called()
