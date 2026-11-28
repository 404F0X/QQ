"""Fresh-default full Source factory MODEL; API outcomes/entropy/service only scripted."""
import base64,json
from pathlib import Path
import pytest
from test_primary_qimei_cold_material_job import ModelAPIs,Carrier
from qq_nt_replica.primary_qimei_observations import QimeiApiReply
from qq_nt_replica.primary_qimei_cache import QimeiCacheCodec,_cbc
from qq_nt_replica.primary_qimei_context import QimeiContextProducer,ContextObservations
from qq_nt_replica.primary_windows_qimei_owned_storage import create_owned_qimei_settings,OwnQimeiMainWriterObservations
from qq_nt_replica.primary_qimei_main_writer import QimeiMainWriter
from qq_nt_replica.primary_qimei_records import StartupState,Record,RecordObservations,persist_store
from qq_nt_replica.primary_qimei_application_binding import ApplicationBinding

def firmware():
 bios=bytearray(9);bios[0]=0;bios[1]=9;bios[4]=1;bios[5]=2;bios[8]=3
 system=bytearray(27);system[0]=1;system[1]=27;system[7]=1;system[26]=2;system[8:24]=bytes(range(16))
 records=bytes(bios)+b'Vendor\0BIOS\0Date\0\0'+bytes(system)+b'Serial\0ModelSix\0\0'
 return b'\0\x03\0\0'+len(records).to_bytes(4,'little')+records

class DefaultAPIs(ModelAPIs):
 def read(self,ns,name,*args):
  if ns=='storage-api':
   from qq_nt_replica.primary_qimei_storage import StorageApiReply
   self.calls.append(name)
   if name=='GetVersionExW':return StorageApiReply(1,((16,(2).to_bytes(4,'little')),))
   if name=='CreateFileW':return (1<<64)-1 # explicit ordinary failed open, allSource probes
   raise AssertionError(name)
  if name=='GetSystemDirectoryW':return QimeiApiReply(3,(('data',0,'X:\\OS\0'.encode('utf-16le')),))
  if name=='PathAppendW':return QimeiApiReply(1,(('data',0,'X:\\OS\\iphlpapi.dll\0'.encode('utf-16le')),))
  if name=='LoadLibraryW':return QimeiApiReply(1)
  if name=='GetProcAddress' and args[1]==b'GetAdaptersInfo':return QimeiApiReply(0)
  if name=='IsWow64Process':return QimeiApiReply(1)
  if name in ('LoadLibraryA','GetProcAddress','FreeLibrary','GetCurrentProcess','IsUserAnAdmin','GetCurrentProcessId'):
   self.calls.append(name);return QimeiApiReply(1)
  if name=='GetSystemFirmwareTable':
   self.calls.append(name);raw=firmware();return QimeiApiReply(len(raw),() if args[-2] is None else (('data',0,raw),))
  if name=='CPUID':
   self.calls.append(name);return QimeiApiReply(0,(('data',0,b'CPU Model Bytes!'),))
  if name=='SetupDiGetClassDevsW':self.calls.append(name);return QimeiApiReply(0) # explicit no device-set result
  if name=='CoInitialize' or name=='CoUninitialize':self.calls.append(name);return QimeiApiReply(0)
  if name=='CoCreateGuid':self.calls.append(name);return QimeiApiReply(0,(('data',0,bytes(range(16))),))
  if name=='GetDriveTypeA':self.calls.append(name);return QimeiApiReply(3)
  if name=='GetTimeZoneInformation':self.calls.append(name);return QimeiApiReply(0xffffffff)
  if name in ('GetLogicalDrives','GetKeyboardLayoutList','GlobalMemoryStatusEx','GetComputerNameA','GetUserNameA','OpenEventLogA','EnumDisplayDevicesW','QueryDosDeviceA'):
   self.calls.append(name);return QimeiApiReply(0)
  return super().read(ns,name,*args)

class Acl:
 def read(self,ns,name,*args):
  if name=='SHELL32.ordinal680':return QimeiApiReply(1)
  if name=='NetWkstaUserGetInfo':return QimeiApiReply(5)
  raise AssertionError(name)
 def close(self):pass
class Profile:
 def close(self):pass

def full_factory(tmp_path,reply_bad=False,fail_identity=False):
 import test_primary_qimei_cold_material_job as coldtests
 case=coldtests.ActualFactoryModel('test_real_factory_and_material_produce_through_retained_reply')
 p,old,k,_=case.real_factory();api=DefaultAPIs();context=QimeiContextProducer();codec=QimeiCacheCodec();runtime=object();epoch=object()
 from qq_nt_replica.primary_qimei_observations import QimeiClassifierObservations
 from qq_nt_replica.primary_qimei_storage import NtStorageContextObservations
 class ContextPorts:
  def __init__(self):self.classifier=QimeiClassifierObservations(api);self.storage=NtStorageContextObservations(api)
  def read(self,*key):
   return (self.classifier if key[0]=='classifier' else self.storage).read(*key)
  def read_classifier_fallback(self):return self.classifier.read_classifier_fallback()
 context_ports=ContextPorts()
 settings,deps=create_owned_qimei_settings(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/'configuration',owner=old.owner,codec=codec,context_producer=context,context_observations=context_ports)
 assert settings.flag(9,**deps)==1 and settings.loaded==0
 state=StartupState.cold()
 state.start(RecordObservations({('base-path',):b'OWN',('open','identity1',b'OWN\\Configv2.ini'):False,('allocate','main',53):True,('ciphertext','main',b'OWN\\Global.db'):b''}),selector=lambda:b'123456')
 ports={};writers={};persisted=[]
 for store in (state.main,state.identity1):
  port=OwnQimeiMainWriterObservations(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/store.name,logical_main_path=store.read_path(),acl_port=Acl(),profile_port=Profile())
  ports[store.name]=port;writers[store.name]=QimeiMainWriter(port,codec=codec,context=context,context_observations=context_ports)
 def persist(store):
  if fail_identity and store.name=='identity1':raise OSError('controlled identity persistence refusal')
  physical=ports[store.name].root/'QimeiMain.cache'
  def previous(path):
   try:raw=physical.read_bytes()
   except FileNotFoundError:return None
   return codec.decode_payload(raw,capacity=len(raw),context=b'')
  status=persist_store(store,writers[store.name],previous)
  if status is None or status!=0:raise RuntimeError('persist failed')
  persisted.append((store.name,codec.decode_payload(physical.read_bytes(),capacity=2000,context=b'').payload))
 # Replace only observation/input bindings; all original high-level methods stay unchanged.
 producer=p.request_producer;material=p.material_producer
 producer.settings=settings;producer.settings_dependencies=deps;producer.system.observations=api;producer.extras.observations=api
 extension=producer.extensions;extension.observations=api;extension.extension_sources.observations=api;extension.startup=state;extension.write_main=persist;extension.storage_observations=api;extension.adapter_sources.observations=api
 material.settings=settings;material.settings_dependencies=deps;material.startup=state;material.globals.observations=api;material.globals.random.observations=api;p.transport.random.observations=api
 k.update(startup=state,persist=persist);k['dispatch'].carrier=Carrier(lambda http:response(http))
 binding=ApplicationBinding(old.owner,settings,old.context,{})
 captured={}
 def response(http):
  from qq_nt_replica.primary_qimei_dispatch import CarrierOutcome
  prepared=k['dispatch'].state.pending[7].prepared;request=prepared.transport_request
  captured['http']=http.body;captured['prepared']=prepared
  outer=json.loads(http.body);cipher=base64.b64decode(outer.get('pms',outer.get('params')))
  raw=_cbc(cipher,request.key,request.iv,decrypt=True);envelope=raw[:-raw[-1]]
  plain=_cbc(envelope[5:],p.envelope.fallback_key,p.envelope.iv,decrypt=True);captured['plain']=plain[:-plain[-1]]
  payload=b'\x0a\x24'+b'q'*36+b'\x12\x01x\x1a\x01y';padding=16-len(payload)%16
  encoded=_cbc(payload+bytes([padding])*padding,request.key,request.iv,decrypt=False)
  return CarrierOutcome(b'bad' if reply_bad else json.dumps({'code':'0','data':base64.b64encode(encoded).decode()}).encode(),0)
 return p,binding,k,api,ports,persisted,captured

def test_firmware_facade_exact_six_and_five_projection(tmp_path):
 p,b,k,api,ports,persisted,captured=full_factory(tmp_path)
 try:
  six=p.request_producer.extensions.firmware_strings();five=p.request_producer.extensions.extension_93ade()
  assert len(six.values)==6 and len(set(six.values))==6 and six.values[-1]==b'ModelSix'
  assert five.values==six.values[:5]
  reply=p.run_cold_material_job(b,**k)
  assert reply.success and k['dispatch'].state.pending=={}
  assert p.material_producer._backend[3]==b'ModelSix'
  assert b'ModelSix' in captured['plain'] and all(x in captured['plain'] for x in six.values[:5])
  assert persisted[0]==('main',bytes(range(16))+bytes(37))
  assert [n for n,_ in persisted]==['main','main','identity1','identity1']
  assert persisted[1][1]==bytes(range(16))+b'q'*36+b'\0'
  from qq_nt_replica.primary_provider_profile import assemble_provider_profile
  from qq_nt_replica.primary_source_config import SourceProfile,SourceFact
  profile=assemble_provider_profile(SourceProfile((SourceFact('qua','source-default','MODEL',0,b'qua'),),0,0),k['startup'].main.profile_records(),uin=1,machine_id=b'MODEL')
  assert profile.record1==b'q'*36+b'\0'
  assert b.settings.flag(9,**p.request_producer.settings_dependencies)==1
  assert api.calls.count('CoCreateGuid')==1
 finally:
  for port in ports.values():port.close_native()

@pytest.mark.parametrize('bad,partial',[(True,False),(False,True)])
def test_default_bad_reply_and_partial_persistence(tmp_path,bad,partial):
 p,b,k,api,ports,persisted,captured=full_factory(tmp_path,reply_bad=bad,fail_identity=partial)
 try:
  if partial:
   with pytest.raises(OSError):p.run_cold_material_job(b,**k)
   assert k['startup'].main.get(1)==b'q'*36+b'\0' and len(k['dispatch'].state.pending)==1
  else:
   p.run_cold_material_job(b,**k)
   assert k['startup'].main.get(1)==b'' and [n for n,_ in persisted]==['main']
 finally:
  for port in ports.values():port.close_native()


def test_wrong_dependency_object_rejected_before_io(tmp_path):
 from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
 p,b,k,api,ports,persisted,captured=full_factory(tmp_path)
 try:
  p.material_producer.settings_dependencies=dict(p.request_producer.settings_dependencies)
  before=list(api.calls)
  with pytest.raises(QimeiRequestBoundary):p.run_cold_material_job(b,**k)
  assert api.calls==before and persisted==[] and captured=={}
  assert p.material_producer.globals._config==b'' and k['dispatch'].state.sequence==7
 finally:
  for port in ports.values():port.close_native()


def test_later_real_read_error_propagates_same_dict(tmp_path,monkeypatch):
 p,b,k,api,ports,persisted,captured=full_factory(tmp_path)
 deps=p.request_producer.settings_dependencies
 assert p.material_producer.settings_dependencies is deps
 path=Path(b.settings.path.decode());original=Path.open;reads=[]
 def read(self,*args,**kwargs):
  if self==path:
   reads.append(self)
   # Timestamp gets genuine FileNotFoundError from original open; a later flag
   # read gets explicit lowlevel IO failure, not a cached successful default.
   if len(reads)==2:raise PermissionError('controlled later Own read failure')
  return original(self,*args,**kwargs)
 monkeypatch.setattr(Path,'open',read)
 try:
  with pytest.raises(PermissionError):p.run_cold_material_job(b,**k)
  assert len(reads)==2 and b.settings.loaded==0 and b.settings.initialized==1
  assert persisted==[] and captured=={} and k['dispatch'].state.sequence==7
 finally:
  for port in ports.values():port.close_native()
