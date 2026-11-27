"""Finite Own key1/five-worker adapter; only worker IPC publication is Source-bound."""
from collections import deque
from dataclasses import dataclass, field
import os
import threading
import time
from .primary_qimei_ipc import IPCError, QimeiIPCPool
from .primary_windows_worker_bridge import WindowsWorkerBridge, WorkerBridgeLaunch, NativeWorkerExit

@dataclass
class QimeiExecutorTask:
    owner: bytes
    body: object = field(repr=False)
    completion: object = field(repr=False)
    release: object = field(repr=False)
    phase: str = 'queued'
    result: object = None
    errors: list = field(default_factory=list)
    thread_id: int = 0
    done: object = field(default_factory=threading.Event, repr=False)
    business: str | None = None
    application: object = field(default=None, repr=False)

class OwnQimeiExecutor:
    """Borrow a pool and bridge. FIFO/drain/serialization are explicit Own policies."""
    def __init__(self, pool, owner, bridge):
        if not isinstance(pool,QimeiIPCPool) or not isinstance(bridge,WindowsWorkerBridge):
            raise IPCError('typed IPC pool and real worker bridge required')
        pool._check()
        if type(owner) is not bytes or pool._executor is not None or owner not in pool.states or not pool.states[owner].initialized:
            raise IPCError('one key1 executor requires an initialized IPC owner')
        if pool.identity != bridge._owner:
            raise IPCError('bridge and IPC creator identities differ')
        self.pool,self.owner,self.bridge=pool,owner,bridge
        self.runtime,self.epoch,self.current_epoch=pool.runtime,pool.epoch,pool.current_epoch
        self.backend=pool.backend
        self._condition=threading.Condition();self._queue=deque();self._slots=[]
        self._published=False;self._sealed=False;self._stop=False;self._shutdown=False
        self.failures=[]
        self._module = None
        pool._executor=self
        try:
            for index in range(5):
                slot={'index':index,'launch':None,'current':None,'exited':False}
                self._slots.append(slot)
                try:
                    launch=bridge.launch(self._worker,slot,quiescence_check=lambda s=slot:self._quiet(s))
                except BaseException:
                    # launch can register its backing before a physical call raises.
                    retained=[l for l in bridge._launches.values()
                              if l.context is slot and l.dispatch == self._worker]
                    if len(retained)==1:slot['launch']=retained[0]
                    raise
                slot['launch']=launch
                if not isinstance(launch,WorkerBridgeLaunch) or not launch.handle or launch.failure is not None:
                    raise IPCError('five real worker handles required before publication')
            with self._condition:self._published=True;self._condition.notify_all()
        except BaseException as error:
            self.failures.append(error)
            with self._condition:self._sealed=True;self._stop=True;self._condition.notify_all()
            # The pool retains this unpublished owner and all partial launch debt.
            try:self.shutdown_and_join()
            except BaseException as cleanup:self.failures.append(cleanup)
            raise ExceptionGroup('Own executor partial start failed (pool retains owner)',self.failures)

    def _creator(self):
        if (self.pool.identity!=(os.getpid(),threading.get_native_id()) or
            self.pool.runtime is not self.runtime or self.pool.epoch is not self.epoch or
            self.pool.current_epoch is not self.current_epoch or self.current_epoch(self.runtime) is not self.epoch):
            raise IPCError('executor requires original creator and live borrowed epoch')

    def _quiet(self,slot):
        with self._condition:return slot['exited'] and slot['current'] is None

    def _has_tasks(self):
        with self._condition:return bool(self._queue) or any(s['current'] is not None for s in self._slots)

    def _permits(self,owner=None):
        if (self.pool._executor is not self or self.pool.backend is not self.backend or
            self.pool.runtime is not self.runtime or self.pool.epoch is not self.epoch or
            self.pool.current_epoch is not self.current_epoch or self.current_epoch(self.runtime) is not self.epoch or
            owner is not None and owner != self.owner):return False
        tid=threading.get_native_id()
        with self._condition:
            for slot in self._slots:
                launch=slot['launch'];task=slot['current']
                if (task is not None and task.owner == self.owner and isinstance(launch,WorkerBridgeLaunch) and
                    launch.bridge is self.bridge and self.bridge._launches.get(launch.token) is launch and
                    launch.record.state==1 and launch.record.thread_id==tid and launch.thread_id==tid and
                    not launch.retired and not launch.joined):return True
        return False

    def submit(self,owner,body,completion,release):
        self._creator()
        if type(owner) is not bytes or owner != self.owner or not all(callable(f) for f in (body,completion,release)):
            raise IPCError('matching owner key and complete task callbacks required')
        self.pool._check()
        # Submission never waits for material execution or the Own IPC IO lock.
        with self._condition:
            if not self._published or self._sealed:raise IPCError('executor not published or sealed')
            task=QimeiExecutorTask(owner,body,completion,release)
            self._queue.append(task);self._condition.notify()
            return task

    def _submit_module(self, module, app, business, body):
        """Finite scheduler capability; public submit remains creator-only."""
        if (module is not self._module or module.applications.get(app.appid) is not app
                or business not in ('6B01C', '6A923', '6B0CE')
                or not module._submission_allowed()):
            raise IPCError('module callback/task admission unavailable')
        with self._condition:
            if not self._published or self._sealed:
                raise IPCError('executor sealed')
            task = QimeiExecutorTask(app.appid, body, lambda t: None, lambda t: None,
                                     business=business, application=app)
            self._queue.append(task)
            self._condition.notify()
            return task

    def _permits_operation(self, owner, operation):
        if not self._permits():
            return False
        tid = threading.get_native_id()
        with self._condition:
            for slot in self._slots:
                task = slot['current']
                if task is None or task.thread_id != tid or task.application is None:
                    continue
                if self._module is None or self._module.applications.get(task.owner) is not task.application:
                    return False
                if operation in ('consume', 'event_cleanup'):
                    return task.business == '6B0CE' and owner == task.owner
                if operation == 'counter':
                    return task.business == '6B0CE' and owner == self.pool._counter_owner
                if operation == 'event_cleanup_publish':
                    return task.business == '6A923' and owner == task.owner
        return False

    def _worker(self,slot):
        try:
            while True:
                with self._condition:
                    self._condition.wait_for(lambda:self._stop or self._published and self._queue)
                    if not self._queue and self._stop:break
                    if not self._published:break
                # Acquire before dequeue: invocation order is FIFO even with five waiters.
                # Own serialization is not a claimed Source mutex.
                with self.pool._io_lock:
                    with self._condition:
                        if not self._queue:
                            continue
                        task=self._queue.popleft();slot['current']=task
                    task.thread_id=threading.get_native_id()
                    try:
                        if not self._permits(task.owner):raise IPCError('unvalidated worker task domain')
                        task.phase='invoke';task.result=task.body(task.owner)
                    except BaseException as error:task.errors.append(error)
                    try:task.phase='completion';task.completion(task)
                    except BaseException as error:task.errors.append(error)
                    finally:
                        try:task.phase='release';task.release(task)
                        except BaseException as error:task.errors.append(error)
                    task.phase='failed' if task.errors else 'completed'
                    with self._condition:slot['current']=None;task.done.set();self._condition.notify_all()
        finally:
            with self._condition:slot['exited']=True;self._condition.notify_all()
        return NativeWorkerExit('return',0,0)

    def shutdown_and_join(self,timeout_ms=10000):
        self._creator()
        if type(timeout_ms) is not int or not 0<=timeout_ms<0xFFFFFFFF:raise IPCError('bounded timeout required')
        with self._condition:self._sealed=True;self._stop=True;self._condition.notify_all()
        deadline=time.monotonic()+timeout_ms/1000;errors=[]
        for slot in self._slots:
            launch=slot['launch']
            if launch is None:continue
            try:
                if launch.handle:
                    launch.join(max(0,int((deadline-time.monotonic())*1000)))
                    if not launch.joined or not launch.handle_closed or launch.failure is not None:
                        raise IPCError('native worker join/close/exit remains unproved')
                elif not slot['exited']:
                    if launch.record.thread_id:
                        raise IPCError('callback observed without retained native handle')
                    # No callback and no handle for failed CreateThread.
                    slot['exited']=True
                launch.retire_host_resources()
            except BaseException as error:errors.append(error)
        if self._has_tasks():errors.append(IPCError('accepted task callbacks remain active'))
        if errors:raise ExceptionGroup('Own executor shutdown debt retained',errors)
        self._shutdown=True


def create_own_qimei_executor(pool,owner,bridge):
    existing=pool._executor
    if existing is not None:
        existing._creator()
        if type(owner) is not bytes or existing.owner != owner or existing.bridge is not bridge or not existing._published or existing._sealed:
            raise IPCError('key1 reuse differs or is no longer live')
        return existing
    return OwnQimeiExecutor(pool,owner,bridge)
