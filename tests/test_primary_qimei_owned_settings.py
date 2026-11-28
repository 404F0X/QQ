import hashlib
from pathlib import Path
from unittest.mock import patch
import pytest
from qq_nt_replica.primary_qimei_settings import QimeiSettings,default_flag_arrays,RECORD_SIZE
from qq_nt_replica.primary_qimei_cache import QimeiCacheCodec
from qq_nt_replica.primary_qimei_context import QimeiContextProducer,ContextObservations
from qq_nt_replica.primary_windows_qimei_owned_storage import create_owned_qimei_settings
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary

def factory(tmp_path):
 runtime=object();epoch=object();codec=QimeiCacheCodec();context=QimeiContextProducer(initialized=True,context=b'')
 settings,deps=create_owned_qimei_settings(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/'own',owner=b'owner',codec=codec,context_producer=context,context_observations=ContextObservations({}))
 return settings,deps,codec

def test_missing_uses_real_source_defaults_no_shell(tmp_path):
 with patch('ctypes.WinDLL',side_effect=AssertionError('no native'),create=True):settings,deps,codec=factory(tmp_path)
 first,second=default_flag_arrays()
 assert settings.record[0]==3 and len(settings.record)==RECORD_SIZE
 assert settings.record[0x31:0x31+len(first)]==first and settings.record[0x259:0x259+len(second)]==second
 assert Path(settings.path.decode()).name==hashlib.md5(b'ownerqimei.dll').hexdigest().upper()
 assert settings.refresh(**deps)==2 and settings.initialized==1 and settings.loaded==0
 assert settings.flag(16,**deps)==0
 assert set((tmp_path/'own').iterdir())=={tmp_path/'own'/'settings'}

def test_real_ciphertext_refresh_timestamp_and_flags(tmp_path):
 settings,deps,codec=factory(tmp_path);record=bytearray(settings.record)
 record[1:9]=(123456).to_bytes(8,'little');record[0x31+3*4:0x31+4*4]=(2).to_bytes(4,'little')
 Path(settings.path.decode()).write_bytes(codec.encode_payload(bytes(record),context=b'').value)
 assert settings.refresh(**deps)==0 and settings.loaded==1
 assert int.from_bytes(settings.record[1:9],'little')==123456
 assert settings.flag(3,**deps)==2

def test_bad_cipher_and_permission_never_missing(tmp_path):
 settings,deps,codec=factory(tmp_path);path=Path(settings.path.decode());original=bytes(settings.record);path.write_bytes(b'bad-cipher')
 assert settings.refresh(**deps)!=0 and bytes(settings.record)==original and settings.loaded==0
 real=Path.open
 def denied(self,*args,**kwargs):
  if self==path:raise PermissionError('controlled exact-file failure')
  return real(self,*args,**kwargs)
 with patch.object(Path,'open',denied):
  with pytest.raises(PermissionError):settings.refresh(**deps)
 with pytest.raises(QimeiRequestBoundary):deps['read_file'](b'other')

def test_copy_prefix_and_repeated_initialize():
 settings=QimeiSettings()
 with pytest.raises(QimeiRequestBoundary):settings.initialize_owned_path(path=b'OWN',first=b'abc',first_count=3,second=b'x',second_count=-1)
 assert settings.path==b'OWN' and settings.record[0x31:0x34]==b'abc' and settings.initialized==0
 assert settings.loaded==0 and settings.dirty==0
 assert settings.initialize_owned_path(path=b'OWN2') is True
 before=bytes(settings.record)
 assert settings.initialize_owned_path(path=None,first=None,second=object()) is False
 assert settings.path==b'OWN2' and bytes(settings.record)==before

def test_directory_failure_no_published_initialization(tmp_path):
 runtime=object();epoch=object();codec=QimeiCacheCodec();context=QimeiContextProducer()
 real=Path.mkdir
 def denied(self,*args,**kwargs):
  if self.name=='settings':raise PermissionError('controlled directory refusal')
  return real(self,*args,**kwargs)
 with patch.object(Path,'mkdir',denied),patch.object(QimeiSettings,'initialize_owned_path',side_effect=AssertionError('must not publish')):
  with pytest.raises(PermissionError):create_owned_qimei_settings(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/'own',owner=b'owner',codec=codec,context_producer=context,context_observations=ContextObservations({}))

def test_epoch_refuses_before_directory(tmp_path):
 with pytest.raises(QimeiRequestBoundary):create_owned_qimei_settings(object(),object(),lambda r:None,permit=lambda r,e:True,root=tmp_path/'own',owner=b'owner',codec=QimeiCacheCodec(),context_producer=QimeiContextProducer(),context_observations=None)
 assert not (tmp_path/'own').exists()

def test_owned_factory_real_refresh_real_material_cold_job(tmp_path):
 # Reuse existing full production-factory MODEL API fixture, not mocked produce.
 from test_primary_qimei_cold_material_job import ActualFactoryModel
 from qq_nt_replica.primary_qimei_application_binding import ApplicationBinding
 case=ActualFactoryModel('test_real_factory_and_material_produce_through_retained_reply')
 pipeline,oldbinding,args,apis=case.real_factory()
 settings,deps,codec=factory(tmp_path)
 # Explicit prior MODEL settings snapshot disables optional device groups; it is
 # encrypted then loaded through the original refresh, never a manual ready flag.
 record=bytearray(RECORD_SIZE);record[0]=3;record[1:9]=(5).to_bytes(8,'little')
 Path(settings.path.decode()).write_bytes(codec.encode_payload(bytes(record),context=b'').value)
 pipeline.request_producer.settings=settings;pipeline.request_producer.settings_dependencies=deps
 pipeline.material_producer.settings=settings
 pipeline.material_producer.settings_dependencies=deps
 binding=ApplicationBinding(oldbinding.owner,settings,oldbinding.context,{})
 def clock():
  assert settings.loaded==1 and int.from_bytes(settings.record[1:9],'little')==5
  return 7
 args['source_clock']=clock
 reply=pipeline.run_cold_material_job(binding,**args)
 assert reply is args['reply'] and reply.success
 assert args['startup'].main.get(1)==b'r'*36+b'\0'
 assert args['dispatch'].state.pending=={}
 assert 'CryptGenRandom' in apis.calls
