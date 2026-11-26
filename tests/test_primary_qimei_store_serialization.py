import unittest
from qq_nt_replica.primary_qimei_records import Store,Record,StartupState,serialize_store_payload,persist_store,RecordObservationError
from qq_nt_replica.primary_qimei_cache import QimeiCacheCodec,PayloadDecodeResult
from qq_nt_replica.primary_qimei_context import QimeiContextProducer
from qq_nt_replica.primary_qimei_main_writer import QimeiMainWriter
from qq_nt_replica.primary_qimei_observations import QimeiApiReply

class WriterAPIs:
 """MODEL raw allocation/stdio observations; never original files or native APIs."""
 def __init__(self,fail_at=None):self.ciphers=[];self.paths=[];self.fail_at=fail_at
 def read(self,ns,name,*args):
  if name in ('calloc','malloc'):return QimeiApiReply(8)
  if name=='free':return QimeiApiReply(0)
  if name=='fopen':self.paths.append(args[0]);return QimeiApiReply(1)
  if name=='fwrite':
   self.ciphers.append(args[0]);return QimeiApiReply(0 if len(self.ciphers)==self.fail_at else len(args[0]))
  if name=='fclose':return QimeiApiReply(0)
  if name=='_access':return QimeiApiReply(1)
  if name=='CoInitialize':return QimeiApiReply(0)
  if name=='CoCreateGuid':return QimeiApiReply(0,(('data',0,bytes(range(16))),))
  if name=='CoUninitialize':return QimeiApiReply(0)
  raise AssertionError(name)

class Serialization(unittest.TestCase):
 def test_mode0_order_pad_truncate_empty_nul(self):
  store=Store('main',0,b'MODEL',[Record(1,3,b'abcd'),Record(1,4,b'x\0'),Record(0,0,b'ignored')])
  self.assertEqual(serialize_store_payload(store),b'abcx\0\0\0')
  self.assertEqual(store.records[0].value,b'abcd')
  cold=Store('main',0,b'MODEL',[Record(0,16,b''),Record(1,37,b'')])
  self.assertEqual(serialize_store_payload(cold),bytes(53))
 def test_zero_unknown_negative_overflow(self):
  store=Store('main',0,b'MODEL',[])
  self.assertIsNone(serialize_store_payload(store))
  self.assertIsNone(persist_store(store,lambda *a:self.fail('writer invoked'),None))
  for cap,value in ((1,None),(-1,b''),(0x7fffffff,b'')):
   with self.assertRaises(ValueError):serialize_store_payload(Store('main',0,b'MODEL',[Record(0,cap,value)]))
 def test_mode1_merge_duplicates_and_source_escape(self):
  store=Store('identity1',1,b'MODEL',[Record(1,1,b'uncapped'),Record(1,1,b'/"\\\b\t\n\f\r\x01\x1f\xff')])
  payload=serialize_store_payload(store,b'{"0":"old","2":"keep"}')
  self.assertEqual(payload,b'{"0":"old","1":"\\/\\"\\\\\\b\\t\\n\\f\\r\\u0001\\u001F\xff","2":"keep"}')
  self.assertEqual(serialize_store_payload(Store('identity1',1,b'MODEL',[Record(0,0,b'')]),None),b'{"0":""}')
 def test_unsupported_prior_never_default_missing(self):
  store=Store('identity1',1,b'MODEL',[Record(0,12,b'ok')])
  for previous in (b'',b'{',b'{"0":1}',b'{"0":{}}',b'{"9":"x"}',b'{"0":"x\0"}',b'{"0":"\\u0061"}'):
   with self.subTest(previous=previous):
    with self.assertRaises(RecordObservationError):serialize_store_payload(store,previous)
 def test_prior_decode_and_writer_status(self):
  store=Store('identity1',1,b'MODEL',[Record(0,12,b'now')]);codec=QimeiCacheCodec()
  raw=codec.encode_payload(b'{"1":"old"}',context=b'').value
  decoded=codec.decode_payload(raw,capacity=len(raw),context=b'');writes=[]
  self.assertEqual(persist_store(store,lambda path,payload:writes.append((path,payload)) or 17,lambda path:decoded),17)
  self.assertEqual(writes,[(b'MODEL\\Configv2.ini',b'{"0":"now","1":"old"}')])
  bad=PayloadDecodeResult('bad',2,False,None,None)
  with self.assertRaises(RecordObservationError):persist_store(store,lambda *a:self.fail('write'),lambda path:bad)
 def writer(self,apis):
  codec=QimeiCacheCodec()
  return codec,QimeiMainWriter(apis,codec=codec,context=QimeiContextProducer(initialized=True,context=b''))
 def test_first_source_guid_persist_empty_record1(self):
  from qq_nt_replica.primary_qimei_request_sources import QimeiRequestSources
  state=StartupState.cold();state.main.records=[Record(0,16,b''),Record(1,37,b'')]
  apis=WriterAPIs();codec,writer=self.writer(apis)
  def persist(store):
   status=persist_store(store,writer,None)
   if status!=0:raise RuntimeError('persist failed')
  sources=QimeiRequestSources(apis,startup=state,write_main=persist)
  self.assertEqual(sources.identity_3fafa(),bytes(range(16)).hex().upper().encode())
  self.assertEqual(len(apis.ciphers),1)
  decoded=codec.decode_payload(apis.ciphers[0],capacity=100,context=b'')
  self.assertEqual(decoded.payload,bytes(range(16))+bytes(37))
 def test_real_writer_merge_and_partial_commit(self):
  from qq_nt_replica.primary_qimei_reply import QimeiReplyState,commit_server_reply
  state=StartupState.cold();state.main.records=[Record(0,16,b''),Record(1,37,b'')]
  state.identity1.records=[Record(0,12,b''),Record(1,32,b''),Record(2,56,b'')]
  apis=WriterAPIs(fail_at=2);codec,writer=self.writer(apis)
  old=codec.encode_payload(b'{"2":"old"}',context=b'').value
  def persist(store):
   status=persist_store(store,writer,lambda path:codec.decode_payload(old,capacity=len(old),context=b''))
   if status!=0:raise RuntimeError('actual writer status '+str(status))
  with self.assertRaises(RuntimeError):commit_server_reply(state,QimeiReplyState(b'q'*36,b'x',b'y',True),selector=lambda:b'123456',persist=persist)
  self.assertEqual(state.main.get(1),b'q'*36+b'\0')
  self.assertEqual(len(apis.ciphers),2)
  self.assertEqual(codec.decode_payload(apis.ciphers[1],capacity=200,context=b'').payload,b'{"0":"313233343536","1":"x","2":""}')


def test_real_owned_file_codec_first_guid_and_identity_merge(tmp_path):
 from qq_nt_replica.primary_windows_qimei_owned_storage import OwnQimeiMainWriterObservations
 from qq_nt_replica.primary_qimei_request_sources import QimeiRequestSources
 from qq_nt_replica.primary_qimei_reply import QimeiReplyState,commit_server_reply
 class Acl:
  def read(self,ns,name,*args):
   if name=='SHELL32.ordinal680':return QimeiApiReply(1)
   if name=='NetWkstaUserGetInfo':return QimeiApiReply(5)
   raise AssertionError(name)
  def close(self):pass
 class Profile:
  def close(self):pass
 state=StartupState.cold();state.main.records=[Record(0,16,b''),Record(1,37,b'')]
 state.identity1.records=[Record(0,12,b''),Record(1,32,b''),Record(2,56,b'')]
 runtime=object();epoch=object();codec=QimeiCacheCodec();ports={};writers={}
 for store in (state.main,state.identity1):
  port=OwnQimeiMainWriterObservations(runtime,epoch,lambda r:epoch,permit=lambda r,e:True,root=tmp_path/store.name,logical_main_path=store.read_path(),acl_port=Acl(),profile_port=Profile())
  ports[store.name]=port;writers[store.name]=QimeiMainWriter(port,codec=codec,context=QimeiContextProducer(initialized=True,context=b''))
 def persist(store):
  physical=ports[store.name].root/'QimeiMain.cache'
  def old(path):
   try:raw=physical.read_bytes()
   except FileNotFoundError:return None
   return codec.decode_payload(raw,capacity=len(raw),context=b'')
  status=persist_store(store,writers[store.name],old)
  if status is None or status!=0:raise RuntimeError('persistence did not succeed')
 try:
  QimeiRequestSources(WriterAPIs(),startup=state,write_main=persist).identity_3fafa()
  raw=(ports['main'].root/'QimeiMain.cache').read_bytes()
  assert codec.decode_payload(raw,capacity=len(raw),context=b'').payload==bytes(range(16))+bytes(37)
  commit_server_reply(state,QimeiReplyState(b'q'*36,b'x',b'y',True),selector=lambda:b'123456',persist=persist)
  raw=(ports['identity1'].root/'QimeiMain.cache').read_bytes()
  assert codec.decode_payload(raw,capacity=len(raw),context=b'').payload==b'{"0":"313233343536","1":"x","2":"y"}'
 finally:
  for port in ports.values():port.close_native()
 assert all(not p.streams and not p.allocations for p in ports.values())


def test_source_lock_order_and_finite_key_domain():
 class Lock:
  depth=0
  def __enter__(self):self.depth+=1
  def __exit__(self,*args):self.depth-=1
 lock=Lock();store=Store('main',0,b'MODEL',[Record(0,1,b'x')]);store._lock=lock
 def writer(path,payload):
  assert lock.depth==0
  return 19
 assert persist_store(store,writer,None)==19
 store=Store('identity1',1,b'MODEL',[Record(0,0,b'')]);store._lock=lock
 def previous(path):
  assert lock.depth==0
  return None
 def locked_writer(path,payload):
  assert lock.depth==1
  return 23
 assert persist_store(store,locked_writer,previous)==23
 import pytest
 with pytest.raises(RecordObservationError):serialize_store_payload(Store('identity1',1,b'MODEL',[Record(-1,1,b'x')]))
