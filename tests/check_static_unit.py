import ast,json,hashlib,threading
from pathlib import Path
from unittest.mock import patch
from signature_core import load_core
c=load_core();checks=[]
try:
 with c.activate():
  from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
  from qq_nt_replica import primary_notification_static_initializers as u
  from qq_nt_replica.primary_notification_files import FileSelectorMaterial
  from qq_nt_replica.primary_custom_allocator import install_model_allocator
  from qq_nt_replica.primary_worker_consumer import _invoke
  from qq_nt_replica.primary_host_services import GuestExitRegistrar
  from qq_nt_replica.errors import InputError
  def fixture():
   reg=GuestExitRegistrar();s=PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/m.exe',module_path=b'C:/explicit/m.dll',stack_modules=(),exit_registration=reg),initial_stack=None,primary_backend='direct');reg.bind(s.runtime)
   raw=b'explicit-model-custom\0';p=0x7600000000;zero=bytes(2)
   m=FileSelectorMaterial(zero,p,raw,'synthetic-test-input','explicit-model',hashlib.sha256(zero+p.to_bytes(8,'little')+raw).hexdigest());install_model_allocator(s.runtime,m,supplier=s.addresses.allocation)
   return s,s.runtime,reg
  def reject(fn):
   try:fn()
   except InputError:return
   raise AssertionError('invalid unit accepted')
  s,r,reg=fixture();base=r.image_base;lo=base+0x6D867D8
  assert r.memory.read(lo,232)==bytes(232)
  oldregions=list(r.memory._regions)
  oldflag=[(region,bytes(region.data),bytes(region.initialized)) for region in oldregions if region.address<=base+0x6755698<region.address+len(region.data)]
  with reg.operation():_invoke(r,0x2E07D30)
  calls=[];store=r.memory.store
  def observe(address,value,size,**kw):
   if lo<=address<lo+232:calls.append((address-lo,value,size))
   return store(address,value,size,**kw)
  with patch.object(r.memory,'store',side_effect=observe):
   with reg.operation():assert _invoke(r,0x2E0AB10) is None
  assert calls==[(i,v,1) for i,(_,v) in enumerate(u._unit_plan())]
  assert r.memory.read(lo,232)==bytes(v for _,v in u._unit_plan()) and r._static_unit_2e0ab10.phase=='complete'
  assert [(region,bytes(region.data),bytes(region.initialized)) for region in r.memory._regions if region.address<=base+0x6755698<region.address+len(region.data)]==oldflag
  checks.append('actual_selected_startup_return_then_full232_width1_order_knownness_no_wholeCRTflag')
  raw=r.memory.read(base+0x6D86862,14);assert raw[:2]==b'\1\1'
  payload=raw[2:12];assert bytes(v^((i+1)&255)^1^10 for i,v in enumerate(payload))==b'env_detect'
  checks.append('independent_consumer_XOR_env_detect')
  cross=[]
  def other_thread():
   try:r._static_unit_2e0ab10.validate(r);cross.append(True)
   except BaseException as error:cross.append(type(error).__name__)
  t=threading.Thread(target=other_thread);t.start();t.join(2);assert not t.is_alive() and cross==[True]
  assert all(not (region.address<lo+232 and lo<region.address+len(region.data)) or (region.address==lo and len(region.data)==232) for region in r.memory._regions)
  checks.append('completed_global_receipt_not_constructor_thread_bound_exact_span')
  reject(lambda:u.initialize_static_unit(r));r._main_generation+=1;reject(lambda:u.initialize_static_unit(r))
  checks.append('once_not_reset_by_sign_generation')
  s2,r2,reg2=fixture();unit=r2._static_unit_2e0ab10;reject(lambda:unit.validate(r))
  epoch=r2._primary_allocator_selector_epoch;r2._primary_allocator_selector_epoch=object();reject(lambda:u.initialize_static_unit(r2));r2._primary_allocator_selector_epoch=epoch
  r2._custom_allocator_backend.closed=True;reject(lambda:u.initialize_static_unit(r2));r2._custom_allocator_backend.closed=False
  checks.append('foreign_runtime_stale_epoch_closed_rejected')
  store=r2.memory.store;seen=[]
  def fail(address,value,size,**kw):
   seen.append(address)
   if len(seen)==17:raise RuntimeError('explicit model write failure')
   return store(address,value,size,**kw)
  try:
   with patch.object(r2.memory,'store',side_effect=fail):u.initialize_static_unit(r2)
  except RuntimeError:pass
  else:raise AssertionError('failure swallowed')
  assert unit.phase=='failed' and len(seen)==17;reject(lambda:u.initialize_static_unit(r2))
  checks.append('midwrite_failure_sticky_no_complete_or_retry')
  s3,r3,_=fixture();r3._static_unit_2e0ab10.phase='running';reject(lambda:u.initialize_static_unit(r3))
  checks.append('running_reentry_rejected')
  tree=ast.parse(Path(u.__file__).read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='initialize_supported')
  names=[n.func.id for n in ast.walk(fn) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
  assert names.index('construct')<names.index('initialize_static_unit')<names.index('construct_timezone')
  checks.append('constructor_hook_AST_original_sequence_retained_not_full_Windows_execution')
finally:c.close()
Path('STATIC-UNIT-CHECKS.json').write_text(json.dumps({'pass':len(checks),'checks':checks,'inputs':c.binding,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'Windows':'NOT_RUN'},indent=2))
print(json.dumps({'pass':len(checks)}))
