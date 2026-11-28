import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_device_record_adapter import RecordCipherHost
from qq_nt_replica.primary_device_record_cipher import encrypt_device_records
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from qq_nt_replica.primary_worker_consumer import DeviceRecord

class Printf24(unittest.TestCase):
    inputs=dict(state17=bytes(range(17)),process_id=123,wall_seconds=100)
    def test_signed_decimal_finite_domain(self):
        host=RecordCipherHost(**self.inputs,formatter_options=0x24)
        destination=host.allocate(32)
        def invoke(value,capacity=32,fmt=None):
            args=(destination,capacity,fmt or host.image_base+0x4852891,value)
            vm=NS(cells=NS(value=lambda i:args[i]))
            return host.invoke(vm,0x701774,range(4))
        try:
            for value,expected in ((0,b'0'),(0xffffffff,b'-1'),(0x80000000,b'-2147483648'),(0x7fffffff,b'2147483647')):
                self.assertEqual(invoke(value),len(expected));self.assertEqual(host.memory.read(destination,len(expected)+1),expected+b'\0')
            with self.assertRaises(PrimarySemanticUnavailable):invoke(123,3)
            wrong=host.allocate(3);host.memory.write(wrong,b'%s\0',source='test wrong format')
            with self.assertRaises(PrimarySemanticUnavailable):invoke(1,fmt=wrong)
        finally:
            for pointer in tuple(host.owned):host.free(pointer)
        for options in (True,4,0x20,0x25,0x26,1<<64,-1):
            with self.assertRaises(PrimarySemanticUnavailable):RecordCipherHost(**self.inputs,formatter_options=options)

    def test_complete_cipher_matches_existing_zero_mode(self):
        rows=(DeviceRecord(1,b'controlled'),DeviceRecord(9,b'long'*30),DeviceRecord(0,b''))
        baseline=encrypt_device_records(rows,**self.inputs,formatter_options=0)
        self.assertEqual(encrypt_device_records(rows,**self.inputs,formatter_options=0x24),baseline)

    def test_on_request_reads_qualified_current_model_options(self):
        import os,threading
        from qq_nt_replica import primary_crt_stdio_options as options
        from qq_nt_replica.primary_crt_stdio_options import read_options
        from qq_nt_replica.primary_own_sdk_request import OwnColdSdkRequestOwner
        from qq_nt_replica.primary_memory import PrimaryMemory
        from test_primary_own_sdk_request import Capi
        memory=PrimaryMemory();address=0x6749cc0
        memory.map(address,bytearray((0x24).to_bytes(8,'little')),name='controlled qualified stdio stage backing',initialized=True)
        runtime=NS(memory=memory,image_base=0,request_transport=None)
        epoch=object();issuer=NS(epoch=epoch);runtime._primary_allocator_issuer=issuer
        region,offset=memory._span(address,8);birth=(memory,0,region,offset)
        owner=NS(_state='open',_pid=os.getpid(),_thread=threading.get_native_id())
        record=dict(runtime=runtime,state='complete',mode='controlled',owner=owner,issuer=issuer,epoch=epoch,birth=birth)
        observed=[]
        def stop(records,metadata,**kwargs):
            observed.append(kwargs['cipher_inputs']['formatter_options'])
            raise RuntimeError('stop after qualified options')
        with patch.dict(options._BIRTHS,{id(memory):birth}),patch.dict(options._PHASES,{id(runtime):record}),patch('qq_nt_replica.primary_module_sync.backend',return_value='controlled'),patch('qq_nt_replica.primary_own_sdk_request._String.read',return_value=NS(value=lambda:b'')),patch('qq_nt_replica.primary_own_sdk_request._logger',return_value=1),patch('qq_nt_replica.primary_own_sdk_request.feature',return_value=1):
            component=OwnColdSdkRequestOwner(runtime,request_capi=Capi(),clock_inputs=dict(wall_seconds=lambda:1,monotonic_ns=lambda:1,clock_ns=lambda:1),random_environment=NS(random_bytes=lambda n:b'1234'),state17_owner=lambda:bytes(range(17)))
            with patch('qq_nt_replica.primary_own_sdk_request.encode_record_request',side_effect=stop):
                with self.assertRaisesRegex(RuntimeError,'stop after qualified'):component.create_device_request(())
            self.assertEqual(observed,[0x24]);component.close()
