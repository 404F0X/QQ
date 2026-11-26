"""Composition MODEL: controlled field/envelope ports, original producer/dispatch/reply/AES."""
import unittest,json,base64
from types import SimpleNamespace as NS
from qq_nt_replica.primary_qimei_request_pipeline import QimeiRequestPipeline
from qq_nt_replica.primary_qimei_dispatch import QimeiSourceDispatch,QimeiDispatchState,QimeiCarrierPort,CarrierOutcome
from qq_nt_replica.primary_qimei_request_producer import QimeiRequestProducer
from qq_nt_replica.primary_qimei_transport_material import QimeiTransportGlobals,QimeiTransportMaterialProducer
from qq_nt_replica.primary_qimei_beacon import QimeiBeacon
from qq_nt_replica.primary_qimei_settings import QimeiSettings
from qq_nt_replica.primary_qimei_sdk import QimeiSdkContexts
from qq_nt_replica.primary_qimei_system_sources import QimeiSystemSources
from qq_nt_replica.primary_qimei_application_binding import ApplicationBinding
from qq_nt_replica.primary_qimei_records import StartupState,Record
from qq_nt_replica.primary_qimei_reply import QimeiReplyState
from qq_nt_replica.primary_qimei_cache import _cbc
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
from qq_nt_replica.primary_provider_profile import assemble_provider_profile
from qq_nt_replica.primary_source_config import SourceProfile,SourceFact

class Carrier(QimeiCarrierPort):
 def __init__(self,fn):self.fn=fn
 def perform(self,request):return self.fn(request)

class ColdJob(unittest.TestCase):
 def fixture(self,body=None,status=200,server=0,corrupt=False,failpersist=False):
  events=[];settings=QimeiSettings();contexts=QimeiSdkContexts();sdk=contexts.get(b'owner');sdk.configure(b'',b'config',b'',1)
  startup=StartupState.cold();startup.once=1
  startup.main.records=[Record(0,16,b''),Record(1,37,b'')]
  startup.identity1.records=[Record(0,12,b''),Record(1,32,b''),Record(2,56,b'')]
  binding=ApplicationBinding(b'owner',settings,sdk,{})
  extras=NS(populate=lambda request,*a,**k:request.set_string(50,b'{}'))
  extension=NS(identity_3fafa=lambda:events.append('populate') or b'')
  producer=QimeiRequestProducer(b'owner',settings,contexts,QimeiSystemSources(None),extras,extension)
  class BeaconBackend:
   def check(self):pass
   def read_outer(self):events.append('beacon');return b'a'*32
  globals=QimeiTransportGlobals(None,beacon=QimeiBeacon(None,BeaconBackend()))
  material=QimeiTransportMaterialProducer(globals=globals,system=producer.system,extras=extras,extension=extension,adapter=None,sdk=sdk,startup=startup,settings=settings,convert_ansi=lambda b:b)
  material.produce=lambda owner,kind,sequence:events.append(('material',owner,kind,sequence)) or NS(serialize=lambda:b'header')
  requests=[]
  def encode(value,**kw):
   r=NS(body=b'encoded',key=b'k'*16,iv=b'i'*16);requests.append(r);return r
  pipeline=object.__new__(QimeiRequestPipeline)
  pipeline.request_producer=producer;pipeline.material_producer=material;pipeline.envelope=NS(encode=lambda *a,**k:b'envelope');pipeline.configuration=object();pipeline.transport=NS(encode=encode);pipeline.sign_enabled=False;pipeline.convert_ansi=lambda b:b
  dispatch=QimeiSourceDispatch(QimeiDispatchState(7),material,envelope=pipeline.envelope,configuration=pipeline.configuration,transport=pipeline.transport,carrier=None,sign_enabled=False)
  payload=body if body is not None else b'\x0a\x24'+b'q'*36+b'\x12\x01x\x1a\x01y'
  def perform(http):
   events.append('carrier');self.assertIs(dispatch.state.pending[7].context,reply)
   if status!=200:return CarrierOutcome(b'',status)
   raw=_cbc(payload+bytes([16-len(payload)%16])*(16-len(payload)%16),requests[-1].key,requests[-1].iv,decrypt=False)
   return CarrierOutcome(b'bad' if corrupt else json.dumps({'code':str(server),'data':base64.b64encode(raw).decode()}).encode(),999)
  dispatch.carrier=Carrier(perform);reply=QimeiReplyState()
  def persist(store):
   events.append(('persist',store.name))
   if failpersist and store.name=='identity1':raise RuntimeError('persist identity failed')
  # Timestamp refresh executes on the same real settings; later producer flag reads are no-op refreshes.
  settings.initialized=1;settings.loaded=1
  original=settings.refresh
  def refresh(**kw):events.append('timestamp-refresh');return original(**kw)
  settings.refresh=refresh
  args=dict(startup=startup,dispatch=dispatch,reply=reply,source_clock=lambda:events.append('clock') or 0,selector=lambda:b'123456',persist=persist)
  return pipeline,binding,args,events,requests
 def test_success_original_state_profile_and_order(self):
  p,b,k,e,r=self.fixture();reply=p.run_cold_material_job(b,**k)
  self.assertIs(reply,k['reply']);self.assertTrue(reply.success)
  self.assertEqual(e[:3],['beacon','timestamp-refresh','clock'])
  self.assertEqual([x for x in e if isinstance(x,tuple) and x[0]=='persist'],[('persist','main'),('persist','identity1'),('persist','identity1')])
  self.assertIn(('material',b'owner',1,7),e)
  self.assertEqual(len(r),1);self.assertEqual(k['dispatch'].state.sequence,8);self.assertEqual(k['dispatch'].state.pending,{})
  profile=assemble_provider_profile(SourceProfile((SourceFact('qua','source-default','known',0,b'model'),),0,0),k['startup'].main.profile_records(),uin=1,machine_id=b'model')
  self.assertEqual(profile.record1,b'q'*36+b'\0')
 def test_negative_status_server_local_empty_do_not_commit(self):
  for opts in ({'status':503},{'server':7},{'corrupt':True},{'body':b'\x0a\x00'}):
   with self.subTest(opts=opts):
    p,b,k,e,r=self.fixture(**opts);p.run_cold_material_job(b,**k)
    self.assertFalse(any(isinstance(x,tuple) and x[0]=='persist' for x in e));self.assertEqual(k['startup'].main.get(1),b'')
 def test_persist_exception_retains_prefix_and_pending(self):
  p,b,k,e,r=self.fixture(failpersist=True)
  with self.assertRaises(RuntimeError):p.run_cold_material_job(b,**k)
  self.assertEqual(k['startup'].main.get(1),b'q'*36+b'\0');self.assertEqual(len(k['dispatch'].state.pending),1)
 def test_misbound_or_warm_rejected_before_io(self):
  for change in ('owner','settings','context','once','main'):
   p,b,k,e,r=self.fixture()
   if change=='owner':p.request_producer.owner=b'other'
   elif change=='settings':p.request_producer.settings=QimeiSettings()
   elif change=='context':p.material_producer.sdk=object()
   elif change=='once':k['startup'].once=0
   else:k['startup'].main.records[1].value=b'warm'
   with self.assertRaises(QimeiRequestBoundary):p.run_cold_material_job(b,**k)
   self.assertEqual(e,[]);self.assertEqual(k['dispatch'].state.sequence,7)
 def test_unsigned_clock_and_timestamp_are_not_skipped(self):
  p,b,k,e,r=self.fixture();b.settings.record[1:9]=(3).to_bytes(8,'little');k['source_clock']=lambda:e.append('clock') or -1
  p.run_cold_material_job(b,**k);self.assertEqual(e[:3],['beacon','timestamp-refresh','clock']);self.assertEqual(len(r),1)
