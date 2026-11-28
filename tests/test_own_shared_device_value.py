import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_signer import PrimarySigner
from qq_nt_replica.primary_windows_signer import WindowsSigner
from qq_nt_replica.primary_device_record_collector import _StringStorage
from qq_nt_replica.primary_logger import _String
from qq_nt_replica.primary_material import caller_device_value
from qq_nt_replica.primary_device_records import cached_value

class SharedValue(unittest.TestCase):
    def test_public_lifecycle_and_same_cached_singleton(self):
        runtime=_StringStorage();owner=runtime.allocate(32)
        _String.construct(runtime,b'shared-own-value').write_to(owner)
        signer=object.__new__(PrimarySigner)
        signer.runtime=runtime;signer._sign_owner=None;signer.failed=False;signer.primary_backend='reference';signer.addresses=NS();signer.calls=0
        calls=[]
        def invoke(r,rva,*args):
            self.assertEqual(rva,0x1BE77F0);self.assertEqual(args[0],owner)
            calls.append(rva);return cached_value(r,*args)
        with patch('qq_nt_replica.primary_device_records._locked_singleton',return_value=owner) as locked,patch('qq_nt_replica.primary_worker_response._frame',side_effect=lambda r,*a:(r.allocate(24),0)),patch('qq_nt_replica.primary_worker_consumer._invoke',side_effect=invoke),patch('qq_nt_replica.primary_device_records.log'),patch('qq_nt_replica.primary_device_native.refresh',side_effect=AssertionError('cache hit must not produce again')):
            first=signer.get_own_device_value()
            second=caller_device_value(runtime) # normal SIGN uses this same helper
            self.assertEqual(first,b'shared-own-value');self.assertEqual(second,first)
            self.assertEqual(locked.call_args.args[1:],(0x6751838,0x67516A0,32,0x1BE5CD0))
        self.assertEqual(len(calls),2);self.assertIsNone(signer._sign_owner)
        self.assertFalse(signer.failed);runtime.close()

    def test_original_failure_marks_public_signer_failed(self):
        signer=object.__new__(PrimarySigner);signer.runtime=_StringStorage()
        signer._sign_owner=None;signer.failed=False;signer.primary_backend='reference';signer.addresses=NS();signer.calls=0
        error=RuntimeError('original boundary')
        with patch('qq_nt_replica.primary_signer.caller_device_value',side_effect=error):
            with self.assertRaises(RuntimeError) as caught:signer.get_own_device_value()
        self.assertIs(caught.exception,error);self.assertTrue(signer.failed);self.assertIsNone(signer._sign_owner)
        signer.runtime.close()

    def test_windows_forwards_through_existing_operation(self):
        owner=object.__new__(WindowsSigner)
        with patch.object(owner,'_operation',return_value=b'value') as operation:
            self.assertEqual(owner.get_own_device_value(),b'value')
            operation.assert_called_once_with('get_own_device_value')
