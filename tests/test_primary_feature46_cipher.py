import unittest
from qq_nt_replica.primary_device_record_adapter import RecordCipherHost
from qq_nt_replica.primary_device_record_cipher import encrypt_device_records
from qq_nt_replica.primary_worker_consumer import DeviceRecord,serialize_device_records
from qq_nt_replica.primary_sdk_request import create_record_request
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from qq_nt_replica.errors import InputError
import test_primary_sdk_request as request_checks

class Cipher(unittest.TestCase):
    inputs=dict(state17=bytes(range(17)),process_id=123,wall_seconds=100,formatter_options=0)
    rows=(DeviceRecord(1,b'controlled'),DeviceRecord(9,b'long'*30),DeviceRecord(0,b''))
    def test_actual_cipher_determinism_inputs_and_cleanup(self):
        host=RecordCipherHost(**self.inputs);output=host.encrypt(self.rows)
        self.assertTrue(output);self.assertEqual(host.owned,{})
        self.assertEqual(output,encrypt_device_records(self.rows,**self.inputs))
        for key,value in (('state17',bytes(range(1,18))),('process_id',124),('wall_seconds',101)):
            self.assertNotEqual(output,encrypt_device_records(self.rows,**dict(self.inputs,**{key:value})))
        self.assertTrue(encrypt_device_records((),**self.inputs))
    def test_actual_ON_request_and_OFF_compatibility(self):
        state=request_checks.Records().state(0)
        args=dict(tag=b'device',sdk_sequence=99,a2=True,commands=(b'a',b'b',b'c',b'd'),encoding_inputs=dict(wall_seconds=lambda:1,monotonic_ns=lambda:1))
        result=create_record_request(self.rows,b'meta',feature46=1,material_state=state,cipher_inputs=self.inputs,**args)
        cipher=encrypt_device_records(self.rows,**self.inputs)
        self.assertEqual(result.serialized_records,serialize_device_records(self.rows,b'meta',cipher));self.assertEqual(result.command,b'd');self.assertEqual(result.sdk_sequence,99);self.assertEqual(result.decode_material,state.current)
        off=create_record_request(self.rows,b'meta',feature46=0,material_state=request_checks.Records().state(0),**args)
        self.assertEqual(off.serialized_records,serialize_device_records(self.rows,b'meta',b''));self.assertNotEqual(off.body,result.body)
    def test_rejection_and_fresh_controls_not_warm_reset(self):
        with self.assertRaises(InputError):encrypt_device_records(self.rows,**dict(self.inputs,state17=b'short'))
        with self.assertRaises(PrimarySemanticUnavailable):encrypt_device_records(self.rows,**dict(self.inputs,formatter_options=18))
        host=RecordCipherHost(**self.inputs);host.memory.store(host.image_base+0x677E1BC,0x80000000,4,source='controlled reload-loop condition')
        with self.assertRaises(PrimarySemanticUnavailable):host.encrypt(self.rows)
        self.assertEqual(host.owned,{})
