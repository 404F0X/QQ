"""Controlled Python-thread carrier, not Native CreateThread evidence."""
import ctypes as C
import os,threading
import pytest
from test_primary_qimei_ipc import ABI
from qq_nt_replica.primary_qimei_ipc import QimeiIPCPool,IPCError
from qq_nt_replica.primary_windows_qimei_executor import create_own_qimei_executor
from qq_nt_replica.primary_windows_worker_bridge import WindowsWorkerBridge,WorkerBridgeLaunch,_LaunchRecord

class Launch(WorkerBridgeLaunch):
 def join(self,timeout_ms=10000):
  self.thread.join(timeout_ms/1000)
  if self.thread.is_alive():raise IPCError('timeout')
  self.joined=self.handle_closed=True;self.exit_code=0
  return self.snapshot()
class Bridge(WindowsWorkerBridge):
 def __init__(self,fail_at=None):
  self._owner=(os.getpid(),threading.get_native_id());self._launches={};self.marker=1
  self._callback_type=C.CFUNCTYPE(C.c_uint32,C.c_uint64,C.POINTER(_LaunchRecord));self.fail_at=fail_at
 def _check_owner(self):
  assert self._owner==(os.getpid(),threading.get_native_id())
 def launch(self,dispatch,context,*,module_reference=None,quiescence_check):
  token=len(self._launches)+1;l=Launch(self,token,dispatch,context,None,quiescence_check);self._launches[token]=l
  if token==self.fail_at:return l
  l.handle=token;started=threading.Event();gate=threading.Event()
  def run():
   l.record.state=1;l.record.thread_id=threading.get_native_id();started.set();gate.wait()
   status=l._dispatch(token,C.pointer(l.record));l.record.state=5
  l.thread=threading.Thread(target=run);l.thread.start();started.wait();l.thread_id=l.record.thread_id;gate.set();return l

def setup():
 runtime=object();epoch=[object()];backend=ABI();pool=QimeiIPCPool(runtime,epoch[0],lambda r:epoch[0],backend)
 owner=b'worker-owner';pool.initialize(owner);return pool,owner,epoch

def test_fifo_real_callbacks_owner_scope_and_drain():
 pool,owner,epoch=setup();bridge=Bridge();executor=create_own_qimei_executor(pool,owner,bridge)
 assert create_own_qimei_executor(pool,owner,bridge) is executor
 other_setup=setup()
 sequence=[];entered=threading.Event();leave=threading.Event()
 def body(o):
  entered.set();leave.wait(2)
  with pytest.raises(IPCError):pool.initialize(o)
  with pytest.raises(IPCError):pool.publish(b'wrong',b'x'*36,36)
  with pytest.raises(IPCError):pool.backend.allocate_cache(o)
  other,otherowner,unused=other_setup
  with pytest.raises(IPCError):other.consume(otherowner)
  saved=epoch[0];epoch[0]=object()
  with pytest.raises(IPCError):pool.consume(o)
  epoch[0]=saved
  assert pool.publish(o,b'x'*36,36)
  with pytest.raises(IPCError):pool.consume(o)
  return b'x'*36
 task=executor.submit(owner,body,lambda t:sequence.append(('complete',t.result)),lambda t:sequence.append(('release',t.phase)))
 assert entered.wait(2)
 with pytest.raises(IPCError):pool.dispose_terminal()
 foreign=[]
 def external():
  try:pool.consume(owner)
  except IPCError:foreign.append(True)
 # Unknown caller waits for the Own lock, then must still fail after task scope exits.
 thread=threading.Thread(target=external);thread.start();leave.set();assert task.done.wait(2);thread.join(2)
 assert foreign==[True] and task.result==b'x'*36 and not task.errors
 assert pool.consume(owner)==b'x'*36
 assert task.thread_id!=threading.get_native_id();assert sequence[0][0]=='complete' and sequence[1][0]=='release'
 with pytest.raises(IPCError):executor.submit(b'wrong',lambda o:None,lambda t:None,lambda t:None)
 saved=epoch[0];epoch[0]=object()
 with pytest.raises(IPCError):executor.submit(owner,lambda o:None,lambda t:None,lambda t:None)
 epoch[0]=saved
 executor.shutdown_and_join();assert len(executor._slots)==5
 assert all(s['launch'].retired for s in executor._slots)
 with pytest.raises(IPCError):executor.submit(owner,body,lambda t:None,lambda t:None)
 pool.dispose_terminal();other_setup[0].dispose_terminal();assert not pool.backend._leases

def test_drain_errors_release_and_cleanup_debt():
 pool,owner,epoch=setup();ex=create_own_qimei_executor(pool,owner,Bridge());seen=[]
 def fail(o):raise ValueError('task failure')
 jobs=[ex.submit(owner,fail,lambda t:seen.append('completion'),lambda t:seen.append('release')) for i in range(3)]
 ex.shutdown_and_join();assert all(t.done.is_set() and len(t.errors)==1 for t in jobs);assert seen==['completion','release']*3
 pool.backend.close_fail=True
 with pytest.raises(ExceptionGroup):pool.dispose_terminal()
 pool.backend.close_fail=False;pool.dispose_terminal()
 with pytest.raises(IPCError):pool.consume(owner)

def test_partial_start_not_published_and_timeout_debt():
 pool,owner,epoch=setup()
 with pytest.raises(ExceptionGroup):create_own_qimei_executor(pool,owner,Bridge(fail_at=3))
 ex=pool._executor;assert not ex._published
 assert all(s['launch'].retired for s in ex._slots)
 pool.dispose_terminal()
 pool,owner,epoch=setup();ex=create_own_qimei_executor(pool,owner,Bridge());entered=threading.Event();leave=threading.Event()
 task=ex.submit(owner,lambda o:(entered.set(),leave.wait(2)),lambda t:None,lambda t:None);assert entered.wait(2)
 with pytest.raises(ExceptionGroup):ex.shutdown_and_join(0)
 assert not ex._shutdown and any(not s['launch'].retired for s in ex._slots)
 leave.set();assert task.done.wait(2);ex.shutdown_and_join();pool.dispose_terminal()

def test_fifo_sequence_and_completion_release_failures():
 pool,owner,epoch=setup();ex=create_own_qimei_executor(pool,owner,Bridge());order=[]
 gate=threading.Event();entered=threading.Event()
 first=ex.submit(owner,lambda o:(entered.set(),gate.wait(2)),lambda t:None,lambda t:None)
 assert entered.wait(2)
 # Accepted submissions must return while the first body is still blocked.
 tasks=[ex.submit(owner,lambda o,n=n:order.append(n),lambda t:None,lambda t:None) for n in range(10)]
 assert not first.done.is_set();gate.set();assert first.done.wait(2)
 def error(t):raise RuntimeError('callback failure')
 last=ex.submit(owner,lambda o:17,error,error)
 ex.shutdown_and_join()
 assert order==list(range(10));assert len(last.errors)==2 and last.result==17 and last.done.is_set()
 pool.dispose_terminal()

def test_partial_physical_exception_retains_registered_launch_for_cleanup():
 class RaisingBridge(Bridge):
  def launch(self,*args,**kwargs):
   launch=super().launch(*args,**kwargs)
   if not launch.handle:raise RuntimeError('physical call failed after registration')
   return launch
 pool,owner,epoch=setup()
 with pytest.raises(ExceptionGroup):create_own_qimei_executor(pool,owner,RaisingBridge(fail_at=2))
 assert len(pool._executor._slots)==2
 assert all(s['launch'].retired for s in pool._executor._slots)
 pool.dispose_terminal()

def test_equal_distinct_owner_keys_preserve_capture_and_publish_cleanup():
 pool,owner1,epoch=setup();owner2=bytes(bytearray(owner1));owner3=bytes(bytearray(owner1))
 assert owner1==owner2==owner3 and owner1 is not owner2 and owner2 is not owner3
 bridge=Bridge();ex=create_own_qimei_executor(pool,owner2,bridge)
 try:
  captured=[]
  task=ex.submit(owner2,lambda owner:(captured.append(owner),pool.publish(owner,b'a'*36,36))[1],lambda t:None,lambda t:None)
  assert task.done.wait(2)
  assert not task.errors, {'errors':[str(e) for e in task.errors],'set_events':sum(c[0]=='SetEvent' for c in pool.backend.calls),'event_still_owned':pool.states[owner1].event is not None}
  assert captured[0] is owner2
  assert create_own_qimei_executor(pool,owner3,bridge) is ex
  task2=ex.submit(owner3,lambda owner:(captured.append(owner),pool.publish(owner,b'b'*36,36))[1],lambda t:None,lambda t:None)
  assert task2.done.wait(2) and not task2.errors
  assert captured[-1] is owner3
  assert pool.consume(owner1)==b'b'*36
 finally:
  ex.shutdown_and_join();pool.dispose_terminal()
