"""Declared MODEL owners/ports only. Never a Windows close/factory or native proof."""
import os
import threading
import unittest
from dataclasses import replace
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_source_cold12_binding import DisabledEnvironment, EnabledEnvironment, fresh_options
from qq_nt_replica.primary_windows_signer import WindowsSigner
from qq_nt_replica.primary_windows_signer_setup import IndependentWindowsSetup
from qq_nt_replica.primary_provider_init import ProviderInitializationMetadata
from qq_nt_replica.primary_own_sdk_request import OwnColdSdkRequestOwner
from qq_nt_replica.primary_sdk_request import SdkRecordRequest
from qq_nt_replica.primary_request_material import RequestMaterial
from qq_nt_replica.primary_signature_result import PrimarySignatureResult
from qq_nt_replica.errors import InputError


class Inputs:
    def __init__(self,fail_close=False):self.seeds=0;self.closes=0;self.fail_close=fail_close
    def entropy4(self):self.seeds+=1;return bytes(4)
    def host_marker(self):return 1
    def padding_bytes(self,n):return bytes(range(n))
    def close(self):
        self.closes+=1
        if self.fail_close:raise OSError('MODEL close failure')


class ModelOwner:
    bind_own_cold12=WindowsSigner.bind_own_cold12
    encode_own_cold12=WindowsSigner.encode_own_cold12
    def __init__(self,machine=b'MODEL-machine'):
        self._own_business_initialized=True;self._own_business_machine_id=machine
        self._state='open';self._busy=False;self._own_cold12=None;self.signs=[];self.fail_sign=False
        component=object.__new__(OwnColdSdkRequestOwner)
        component.runtime=NS();component.closed=False;component.creator=(os.getpid(),threading.get_native_id());component._pending=[]
        self._signer=NS(failed=False,_own_sdk_request=component,runtime=component.runtime)
    def _check_owner(self):pass  # Explicit MODEL creator port; no fake native frame/close context.
    def request(self,seq=1):
        value=SdkRecordRequest(b'trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey',b'MODEL-body',seq,None,RequestMaterial(bytes(168)),b'MODEL')
        self._signer._own_sdk_request._pending.append((value,b'MODEL-bound'))
        return value
    def sign_result(self,command,body):
        assert not self._busy
        self.signs.append((command,body))
        if self.fail_sign:
            self._state='failed';self._signer.failed=True
            raise RuntimeError('MODEL normal SIGN failed')
        return PrimarySignatureResult(b'S',b'E',b'T')


class Binding(unittest.TestCase):
    def bind(self,owner,inputs,owned=False):
        owner.bind_own_cold12(inputs,own_inputs=owned,appid_override=None,env_setting=DisabledEnvironment())
        return owner._own_cold12

    def test_projection_appid_env_truth_table_and_fresh_constants(self):
        for appid,want in ((None,0x20067C69),(0,0x20067C69),(123,123)):
            cases=[(DisabledEnvironment(),None,b''),(EnabledEnvironment('',0,'id',''),None,b''),
                (EnabledEnvironment('host',0,'id',''),None,b''),(EnabledEnvironment('',1,'id',''),None,b''),
                (EnabledEnvironment('host',1,'id',''),b'id',b''),(EnabledEnvironment('',0,'id','canary'),b'id',b'canary'),
                (EnabledEnvironment('host',1,'',''),None,b'')]
            for env,field13,canary in cases:
                value=fresh_options(b'MODEL-machine',appid_override=appid,env_setting=env)
                self.assertEqual((value.dword0,value.string8,value.string20),(want,b'',b'MODEL-machine'))
                self.assertEqual((value.reserve.context13,value.reserve.field32),(field13,canary))
                self.assertEqual((value.reserve.field16,value.reserve.field21,value.reserve.records23,value.reserve.field26),(None,False,(),101))
        for env in (None,EnabledEnvironment('h',-1,'id',''),EnabledEnvironment('h','1','id',''),EnabledEnvironment('h',1,'\ud800','')):
            with self.assertRaises(InputError):fresh_options(b'm',appid_override=None,env_setting=env)
        with self.assertRaises(InputError):fresh_options(b'm',appid_override=True,env_setting=DisabledEnvironment())
        self.assertEqual(fresh_options('\u00e9'.encode('utf-8'),appid_override=None,env_setting=DisabledEnvironment()).string20,'\u00e9'.encode('utf-8'))

    def test_setup_captures_only_successful_installed_identity(self):
        owner=ModelOwner();owner._own_business_machine_id=None;setup=IndependentWindowsSetup(owner)
        config={'uin':0,'machine_id':b'MODEL-original'}
        metadata=ProviderInitializationMetadata(None,b'MODEL-qua',b'0',config['machine_id'])
        installed=[]
        def prepare(value):
            self.assertIsNone(owner._own_business_machine_id);installed.append(value)
        with patch('qq_nt_replica.primary_windows_signer_setup.business_metadata',return_value=metadata),patch.object(setup,'_prepare_provider',side_effect=prepare):
            setup.prepare_business(**config)
        config['machine_id']=b'changed'
        self.assertEqual(owner._own_business_machine_id,installed[0].field_20)
        failed=ModelOwner();failed._own_business_machine_id=None;setup=IndependentWindowsSetup(failed)
        with patch('qq_nt_replica.primary_windows_signer_setup.business_metadata',return_value=metadata),patch.object(setup,'_prepare_provider',side_effect=RuntimeError('setup')):
            with self.assertRaises(RuntimeError):setup.prepare_business(**config)
        self.assertIsNone(failed._own_business_machine_id)

    def test_real_pending_preflight_and_prepare_sign_encode_order(self):
        owner=ModelOwner();inputs=Inputs();binder=self.bind(owner,inputs)
        first=owner.request();second=owner.request(2);order=[]
        prepare,encode=binder.encoder.prepare,binder.encoder.encode_signed
        def prepared(command,body):order.append('prepare');return prepare(command,body)
        def signed(command,body):order.append('sign');return ModelOwner.sign_result(owner,command,body)
        def encoded(request,**kw):
            order.append('encode');self.assertTrue(owner._busy)
            self.assertEqual((request.command,request.body),(first.command,first.body))
            return encode(request,**kw)
        owner.sign_result=signed
        with patch.object(binder.encoder,'prepare',side_effect=prepared),patch.object(binder.encoder,'encode_signed',side_effect=encoded):
            result=owner.encode_own_cold12(first)
        self.assertEqual(order,['prepare','sign','encode']);self.assertEqual(owner.signs,[(first.command,first.body)])
        self.assertEqual(result.sdk_sequence,first.sdk_sequence);self.assertIs(result._request,first);self.assertTrue(result.frame)
        self.assertEqual(len(owner._signer._own_sdk_request._pending),2)
        before=binder.encoder.counter._value
        for invalid in (replace(first),ModelOwner().request()):
            with self.assertRaises(InputError):owner.encode_own_cold12(invalid)
        owner._signer._own_sdk_request.cancel_device_request(first)
        with self.assertRaises(InputError):owner.encode_own_cold12(first)
        self.assertEqual(binder.encoder.counter._value,before);self.assertEqual(len(owner.signs),1)
        owner.encode_own_cold12(second);self.assertEqual(len(owner.signs),2)
        binder.close();self.assertEqual(inputs.closes,0)

    def test_unsupported_identity_config_and_owner_fail_before_counter(self):
        for machine in (b'',b'bad\0value',b'\xff'):
            owner=ModelOwner(machine);inputs=Inputs();request=owner.request()
            with self.assertRaises(InputError):self.bind(owner,inputs,True)
            self.assertEqual(inputs.seeds,0);self.assertEqual(inputs.closes,1)
            self.assertEqual(owner.signs,[]);self.assertEqual(len(owner._signer._own_sdk_request._pending),1)
            self.assertEqual(owner._own_business_machine_id,machine)
        owner=ModelOwner();inputs=Inputs();request=owner.request()
        with self.assertRaises(InputError):owner.bind_own_cold12(inputs,own_inputs=False,appid_override=None,env_setting=None)
        self.assertEqual(inputs.seeds,0);self.assertEqual(inputs.closes,0);self.assertEqual(owner._state,'open')
        self.assertEqual(len(owner._signer._own_sdk_request._pending),1)
        owner=ModelOwner();owner._own_business_initialized=False;inputs=Inputs()
        with self.assertRaises(InputError):self.bind(owner,inputs)
        self.assertEqual(inputs.seeds,0)

    def test_sign_encode_failures_do_not_retry_or_rollback(self):
        for stage in ('sign','encode'):
            owner=ModelOwner();binder=self.bind(owner,Inputs());request=owner.request();before=binder.encoder.counter._value
            if stage=='sign':owner.fail_sign=True
            with patch.object(binder.encoder,'encode_signed',side_effect=RuntimeError('MODEL encode failed')) as encode:
                with self.assertRaises(RuntimeError):owner.encode_own_cold12(request)
            self.assertEqual(binder.encoder.counter._value,(before+1)&0xFFFFFFFF)
            self.assertEqual(len(owner.signs),1);self.assertEqual(encode.call_count,int(stage=='encode'))
            self.assertEqual(len(owner._signer._own_sdk_request._pending),1);self.assertEqual(owner._state,'failed')
            binder.close()

    def test_owned_close_and_creation_cleanup_failure_retains_debt(self):
        owner=ModelOwner();inputs=Inputs();binder=self.bind(owner,inputs,True);binder.close();binder.close();self.assertEqual(inputs.closes,1)
        owner=ModelOwner();inputs=Inputs(True);binder=self.bind(owner,inputs,True)
        with self.assertRaises(OSError):binder.close()
        with self.assertRaises(OSError):binder.close()
        self.assertEqual(inputs.closes,1)
        owner=ModelOwner();inputs=Inputs()
        def seed_failure():raise OSError('MODEL entropy failure')
        inputs.entropy4=seed_failure
        with self.assertRaises(OSError):self.bind(owner,inputs,True)
        self.assertEqual(inputs.closes,1)
        owner=ModelOwner(b'\xff');inputs=Inputs(True)
        with self.assertRaises(BaseExceptionGroup) as error:self.bind(owner,inputs,True)
        self.assertEqual(len(error.exception.exceptions),2);self.assertEqual(owner._state,'failed');self.assertEqual(inputs.closes,1)
        with self.assertRaises(OSError):owner._own_cold12.close()
        self.assertEqual(inputs.closes,1)

if __name__=='__main__':unittest.main()
