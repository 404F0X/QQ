import unittest
from types import SimpleNamespace as NS
from qq_nt_replica.primary_worker_consumer import DeviceRecord,serialize_device_records,_serialize
from qq_nt_replica.primary_sdk_request import create_record_request
from qq_nt_replica.primary_request_material import RequestMaterial,RequestMaterialState
from qq_nt_replica.primary_request_random import RequestRandom
from qq_nt_replica.primary_request_encoder import encode_cached_material_request,RequestKeyMaterial
from qq_nt_replica.primary_memory import PrimaryMemory
from qq_nt_replica.primary_logger import _String
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from qq_nt_replica.errors import InputError
class Records(unittest.TestCase):
    def test_shared_legacy_order_zero_empty_and_cipher(self):
        m=PrimaryMemory();base=0x180000000;m.map(base+0x3FD7118,(base+0xBDBE60).to_bytes(8,'little'),name='controlled serializer',initialized=True)
        r=NS(memory=m,image_base=base)
        rows=(DeviceRecord(0,b''),DeviceRecord(2,b'x'))
        strings=[(x.key,_String.construct(r,x.value)) for x in rows]
        old=_serialize(r,strings,_String.construct(r,b'm'),_String.construct(r,b'e'))
        self.assertEqual(old.value(),serialize_device_records(rows,b'm',b'e'))
        self.assertEqual(old.value(),b'\x0a\x00\x0a\x05\x08\x02\x12\x01x\x12\x01m\x1a\x01e')
    def state(self,mode):
        raw=bytearray(168);raw[:32]=bytes(range(32));raw[32:48]=b'\xff'*16;raw[48:80]=bytes(range(32));raw[80]=mode;raw[81]=1;raw[88:96]=(42).to_bytes(8,'little');raw[129:162]=b'\x02'+bytes(32)
        return RequestMaterialState(RequestMaterial(bytes(raw)),random=RequestRandom(123))
    def test_real_encoder_commands_status_a2_and_decode_snapshot(self):
        for mode in (0,1):
            for a2 in (False,True):
                s=self.state(mode);current=s.current;rows=(DeviceRecord(7,b'value'),)
                result=create_record_request(rows,b'metadata',feature46=0,tag=b'device',material_state=s,sdk_sequence=99,a2=a2,commands=(b'c0',b'c1',b'c2',b'c3'),encoding_inputs=dict(wall_seconds=lambda:1,monotonic_ns=lambda:1))
                expected=encode_cached_material_request(b'device',serialize_device_records(rows,b'metadata',b''),RequestKeyMaterial(s.encoded_peer,current.public_key,current.peer_key,b'',current.key),current.device_random,42,RequestRandom(123),payload_mode=mode,public_key_flag=1)
                self.assertEqual(result.body,expected.wire);self.assertEqual(result.command,(b'c0',b'c1',b'c2',b'c3')[int(a2)*2+int(mode==0)]);self.assertEqual(result.sdk_sequence,99);self.assertEqual(result.decode_material,current);s.reset();self.assertEqual(result.decode_material,current)
    def test_ON_and_bad_input_fail_before_material_mutation(self):
        s=self.state(0);before=s.current
        args=dict(feature46=1,tag=b'd',material_state=s,sdk_sequence=1,a2=False,commands=(b'a',b'b',b'c',b'd'),encoding_inputs={})
        with self.assertRaises(PrimarySemanticUnavailable):create_record_request((),b'',**args)
        self.assertIs(s.current,before)
        args['feature46']=0
        with self.assertRaises(InputError):create_record_request(((1,b'x'),),b'',**args)
        self.assertIs(s.current,before)
