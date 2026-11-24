import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_own_sdk_request import OwnColdSdkRequestOwner
from qq_nt_replica.primary_worker_consumer import DeviceRecord
from qq_nt_replica.primary_request_transport import _COMMANDS

class Capi:
    def acquire(self,phase):return 1,1
    def generate(self,phase,handle,buffer):buffer.write(bytes(range(1,33)));return 1
    def release(self,phase,handle):return 1

class Requests(unittest.TestCase):
    def component(self,binding=None):
        runtime=NS(image_base=0,request_transport=binding,memory=NS(load=lambda *a:0))
        return OwnColdSdkRequestOwner(runtime,request_capi=Capi(),clock_inputs=dict(wall_seconds=lambda:1,monotonic_ns=lambda:1,clock_ns=lambda:1),random_environment=NS(random_bytes=lambda n:b'1234'))
    def test_real_fresh_encoder_and_dual_type(self):
        for types,a2 in ((None,False),([0],False),([2,1],True),([1,0],False)):
            calls=[];values=iter(types or [])
            binding=None if types is None else NS(type=lambda context:(calls.append(context),next(values))[1])
            with patch('qq_nt_replica.primary_own_sdk_request._String.read',return_value=NS(value=lambda:b'')),patch('qq_nt_replica.primary_own_sdk_request._logger',return_value=1),patch('qq_nt_replica.primary_own_sdk_request.feature',return_value=2):
                if binding is None:component=self.component()
                else:
                    # Explicit binding context; never a fabricated native gate pointer.
                    runtime=NS(image_base=0,request_transport=binding)
                    component=OwnColdSdkRequestOwner(runtime,request_capi=Capi(),clock_inputs=dict(wall_seconds=lambda:1,monotonic_ns=lambda:1,clock_ns=lambda:1),random_environment=NS(random_bytes=lambda n:b'1234'),transport_context='own-context')
                result=component.create_device_request((DeviceRecord(7,b'value'),))
                self.assertEqual(component._tag,b'getToken');self.assertEqual(result.sdk_sequence,1)
                self.assertEqual(result.command,_COMMANDS[2*int(a2)+int(result.encoded.status==0)])
                self.assertTrue(result.body);self.assertEqual(component.sequence,2)
                retained=result.decode_material
                component.material.reset();self.assertEqual(result.decode_material,retained)
                self.assertEqual(len(calls),len(types or []));component.close()
    def test_failed_encoding_does_not_consume_counter(self):
        with patch('qq_nt_replica.primary_own_sdk_request._String.read',return_value=NS(value=lambda:b'')),patch('qq_nt_replica.primary_own_sdk_request._logger',return_value=1),patch('qq_nt_replica.primary_own_sdk_request.feature',return_value=2):
            component=self.component()
            with patch('qq_nt_replica.primary_own_sdk_request.encode_record_request',side_effect=RuntimeError('encode')):
                with self.assertRaisesRegex(RuntimeError,'encode'):component.create_device_request(())
            self.assertEqual(component.sequence,1);component.close()


    def test_type_failure_preserves_encoded_material_without_consuming_counter(self):
        with patch('qq_nt_replica.primary_own_sdk_request._String.read',return_value=NS(value=lambda:b'')),patch('qq_nt_replica.primary_own_sdk_request._logger',return_value=1),patch('qq_nt_replica.primary_own_sdk_request.feature',return_value=2):
            component=self.component()
            before=component.material.current
            def fail(context):
                self.assertIsNot(component.material.current,before)
                self.assertIsNotNone(component.material.random)
                raise RuntimeError('type')
            component.runtime.request_transport=NS(type=fail)
            with self.assertRaisesRegex(RuntimeError,'type'):component.create_device_request((DeviceRecord(7,b'value'),))
            self.assertEqual(component.sequence,1)
            self.assertIsNot(component.material.current,before)
            component.close()

    def test_snapshot_precedes_type_callback_mutation(self):
        with patch('qq_nt_replica.primary_own_sdk_request._String.read',return_value=NS(value=lambda:b'')),patch('qq_nt_replica.primary_own_sdk_request._logger',return_value=1),patch('qq_nt_replica.primary_own_sdk_request.feature',return_value=2):
            component=self.component();captured=[]
            def mutate(context):
                captured.append(component.material.current)
                component.material.reset()
                return 0
            component.runtime.request_transport=NS(type=mutate)
            result=component.create_device_request((DeviceRecord(7,b'value'),))
            self.assertIs(result.decode_material,captured[0])
            self.assertIsNot(result.decode_material,component.material.current)
            self.assertEqual(result.sdk_sequence,1);self.assertEqual(component.sequence,2)
            component.close()
