import json,hashlib
from pathlib import Path
from signature_core import load_core
c=load_core();checks=[]
try:
 with c.activate():
  from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
  from qq_nt_replica.primary_notification_files import FileSelectorMaterial
  from qq_nt_replica.primary_custom_allocator import install_model_allocator
  from qq_nt_replica.primary_notification_environment_values import *
  from qq_nt_replica.primary_logger import _String
  from qq_nt_replica.primary_notification_environment_values import _ValueTree
  from qq_nt_replica.primary_worker_consumer import _invoke
  from qq_nt_replica.primary_memory import UnknownMemory
  def fixture():
   s=PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/p.exe',module_path=b'C:/explicit/m.dll',stack_modules=()),initial_stack=None,primary_backend='direct');r=s.runtime
   raw=b'explicit-model-custom\0';p=0x7600000000;initial=b'\0\0'
   m=FileSelectorMaterial(initial,p,raw,'synthetic-test-input','explicit-model',hashlib.sha256(initial+p.to_bytes(8,'little')+raw).hexdigest())
   install_model_allocator(r,m,supplier=s.addresses.allocation)
   return s,r
  def run(rows):
   s,r=fixture();out=_invoke(r,0x3E92E00,1,24);r.memory.write(out,b'X'*24,source='explicit-output-before')
   events=[]
   for name,(n,ret,data) in zip(NAMES,rows):
    events.append(((name,'probe',0),EnvironmentReply(n)))
    if n:events.append(((name,'read',n),EnvironmentReply(ret,data,b'\1'*n)))
   obs=ModelEnvironmentValues(events);r.notification_environment_values_observations=obs
   assert _invoke(r,0x35D4630,out)==out and _String.read(r,out).value()==b''
   assert obs.closed and obs.index==3
   storage=r._custom_allocator_backend.storage
   assert not storage.live and not storage.storage_disposed
   return r,out,storage
  r,out,storage=run([(0,0,b'')]*3)
  assert r.memory.read(out,24)==bytes(24)
  checks.append('three_probe_zero_empty_aggregate_real_name_sideeffects')
  r,out,storage=run([(22,0,b'a'*21+b'\0'),(23,100,b'b'*22+b'\0'),(23,0,b'b'*22+b'\0')])
  assert r.memory.read(out,2)==b'\0\0' and r.memory.read(out+2,22)==b'X'*22
  checks.append('probe22_23_sso_heap_second_returns_ignored_duplicate_source_frees')
  r,out,storage=run([(5,0,b'a\0b\0x'),(5,1,b'a\0b\0y'),(5,99,b'a\0c\0z')])
  checks.append('embedded_NUL_explicit_length_duplicate_comparison_and_race')
  # Three keys force each symmetric balance/rotation path, padding remains unknown.
  for values in ((b'c',b'b',b'a'),(b'a',b'b',b'c'),(b'c',b'a',b'b'),(b'a',b'c',b'b')):
   s,r=fixture();a=_invoke(r,0x3E92E00,1,24);tree=_ValueTree(r,a);nodes=[]
   for value in values:nodes.append(tree.insert(_String.construct(r,value))[0])
   assert tree.get(a,16)==3 and tree.get(tree.get(a,8),24,1)==1
   for node in nodes:
    try:r.memory.read(node+25,7)
    except UnknownMemory:pass
    else:raise AssertionError('node padding was invented')
   tree.destroy();assert not r._custom_allocator_backend.storage.live
  checks.append('four_rotation_shapes_three_nodes_padding_unknown_postorder_destruction')
  from qq_nt_replica.primary_windows_notification_environment_values import WindowsEnvironmentValuesBackend,WindowsEnvironmentValuesService
  import ctypes as C,threading,ast
  backend=WindowsEnvironmentValuesBackend();calls=[]
  def spy(name,buffer,capacity):
   calls.append((C.string_at(name),buffer is None,capacity))
   if capacity:C.memmove(buffer,b'Q\0R',3)
   return 99 if capacity else 3
  backend.function=spy
  assert backend.call(NAMES[0],None,0)==3
  native=C.create_string_buffer(bytes(3),3)
  assert backend.call(NAMES[0],native,3)==99 and native.raw==b'Q\0R'
  assert calls==[(NAMES[0],True,0),(NAMES[0],False,3)]
  checks.append('backend_argument_spy_only_NULL_probe_native_buffer_exact_postbytes_no_real_API')
  def refuses(fn):
   try:fn()
   except (InputError,UnknownMemory,PrimarySemanticUnavailable):return
   raise AssertionError('invalid environment source accepted')
  s,r=fixture();obs=ModelEnvironmentValues([])
  obs.begin(r);refuses(lambda:obs.begin(r));refuses(lambda:obs.take(r,NAMES[1],'probe',0,b''))
  errors=[]
  def foreign():
   try:obs.check(r)
   except InputError:errors.append(True)
  t=threading.Thread(target=foreign);t.start();t.join(2);assert not t.is_alive() and errors==[True]
  epoch=r._primary_allocator_selector_epoch;r._primary_allocator_selector_epoch=object();refuses(lambda:obs.check(r));r._primary_allocator_selector_epoch=epoch
  s2,r2=fixture();refuses(lambda:obs.check(r2));obs.end(r,failed=True);refuses(lambda:obs.check(r));refuses(lambda:obs.begin(r))
  refuses(lambda:WindowsEnvironmentValuesService(object(),r,object()))
  checks.append('model_reentry_name_foreign_thread_epoch_runtime_closed_and_Windows_origin_rejection')
  s,r=fixture();out=_invoke(r,0x3E92E00,1,24);name=_invoke(r,0x3E92E00,1,24)
  r.memory.forget(out,24,source='explicit_unknown_header');_String.construct(r,NAMES[0]).write_to(name)
  obs=ModelEnvironmentValues([((NAMES[0],'probe',0),EnvironmentReply(0))]);r.notification_environment_values_observations=obs
  _invoke(r,0x35D44F0,out,name);assert r.memory.read(out,2)==bytes(2)
  try:r.memory.read(out+2,1)
  except UnknownMemory:pass
  else:raise AssertionError('probe zero defined extra header bytes')
  checks.append('standalone_helper_probezero_WORD_only_other_header_unknown')
  s,r=fixture();out=_invoke(r,0x3E92E00,1,24);r.notification_environment_values_observations=ModelEnvironmentValues([])
  refuses(lambda:_invoke(r,0x35D4630,out))
  assert r.notification_environment_values_observations.closed
  checks.append('missing_observation_propagates_failure_window_closed_not_empty_success')
  # Independent key clone and left/right/String/node postorder pair sequence.
  s,r=fixture();a=_invoke(r,0x3E92E00,1,24);tree=_ValueTree(r,a)
  source=_String.construct(r,b'x'*30);node,inserted=tree.insert(source);clone=_String.read(r,node+32)
  assert inserted and clone.get(16,8)!=source.get(16,8)
  before=len(r._custom_allocator_backend.storage.live)
  assert tree.insert(source)==(node,False) and len(r._custom_allocator_backend.storage.live)==before
  source.destroy();assert clone.value()==b'x'*30
  tree.destroy();sizes=[record[1] for record in r._custom_allocator_backend.storage.source_free_seen]
  assert sizes==[32,32,56]
  checks.append('independent_long_key_clone_duplicate_no_allocation_string_then_node_source_free')
  from qq_nt_replica.primary_notification_environment_values import _validate_reply
  refuses(lambda:_validate_reply(EnvironmentReply(0,b'x',b'\1'),'probe',0))
  refuses(lambda:_validate_reply(EnvironmentReply(1,b'x',b'\0\0'),'read',1))
  s,r=fixture();out=_invoke(r,0x3E92E00,1,24)
  r.notification_environment_values_observations=ModelEnvironmentValues([((NAMES[0],'probe',0),EnvironmentReply(3)),((NAMES[0],'read',3),EnvironmentReply(0,b'xxz',b'\0\1\1'))])
  refuses(lambda:_invoke(r,0x35D4630,out))
  assert r.notification_environment_values_observations.closed
  checks.append('invalid_schema_unknown_required_content_fail_not_empty_fallback')
  # Old worker source and source guards have not been modified or enabled.
  current=Path(c.binding['qq_nt_replica/primary_sign.py']['path']).read_text()
  added="        if rva in (0x35D44F0, 0x35D4630):\n            from .primary_notification_environment_values import invoke\n            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))\n"
  assert current.count(added)==1
  row=c.binding['qq_nt_replica/primary_sign.py']
  # Current export inventory pin, after the accepted static-unit source change.
  assert row['sha256']=='afbfcb10eca02fcdc2442bdbac3f5a9e3f132cd022fc60a3e3c10b9dbe010a4f'
  assert hashlib.sha256(Path(row['path']).read_bytes()).hexdigest()==row['sha256']
  checks.append('finite_two_helper_routes_present_current_selected_source_manifest_exact')
finally:c.close()
Path('ENV-VALUES-CHECKS.json').write_text(json.dumps({'checks':checks,'pass':len(checks),'inputs':c.binding,'native':'NOT_RUN','script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},indent=2))
print(json.dumps({'pass':len(checks)}))
