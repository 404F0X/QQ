from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock, get_native_id
from types import SimpleNamespace

from .errors import InputError


@dataclass
class _ExitRecord:
    sequence: int
    address: int
    status: str = 'pending'


class _EmptyCells:
    def value(self, index):
        raise InputError('guest exit callback has no argument cells')


class _ExecutionLease:
    def __init__(self, registrar, *, closing=False, token=None):
        self.registrar, self.closing, self.token = registrar, closing, token
        self.thread_id = get_native_id()
        self.active = self.suspended = False

    def __enter__(self):
        owner = self.registrar
        owner._operation_lock.acquire()
        try:
            with owner._lock:
                allowed = owner._lifecycle == 'open' or (
                    owner._lifecycle == 'closing' and self.token is not None and
                    owner._thread_tokens.get(self.thread_id) is self.token)
                if not owner._bound or not (self.closing or allowed):
                    raise InputError('exit owner is not open or authorized for this closing thread')
                owner._leases.setdefault(self.thread_id, []).append(self)
                owner._active_operations += int(not self.closing)
                self.active = True
        except BaseException:
            owner._operation_lock.release()
            raise
        return self

    def __exit__(self, *exception):
        owner = self.registrar
        with owner._lock:
            stack = owner._leases.get(self.thread_id, [])
            if get_native_id() != self.thread_id or not self.active or self.suspended or not stack or stack[-1] is not self:
                raise InputError('exit execution lease requires its active native thread and stack order')
            stack.pop()
            if not stack:
                owner._leases.pop(self.thread_id, None)
            owner._active_operations -= int(not self.closing)
            self.active = False
        owner._operation_lock.release()

    @contextmanager
    def suspend(self):
        owner = self.registrar
        with owner._lock:
            stack = tuple(owner._leases.get(self.thread_id, ()))
            if get_native_id() != self.thread_id or not self.active or self.suspended or not stack or stack[-1] is not self:
                raise InputError('lease suspension requires the current explicit execution lease')
            for lease in stack:
                if not lease.active or lease.suspended:
                    raise InputError('exit execution lease stack is not suspendable')
            for lease in stack:
                lease.suspended = True
                owner._active_operations -= int(not lease.closing)
        for lease in reversed(stack):
            owner._operation_lock.release()
        try:
            yield
        finally:
            for lease in stack:
                owner._operation_lock.acquire()
            with owner._lock:
                if tuple(owner._leases.get(self.thread_id, ())) != stack:
                    raise InputError('suspended exit lease stack changed')
                for lease in stack:
                    lease.suspended = False
                    owner._active_operations += int(not lease.closing)


class GuestExitRegistrar:
    def __init__(self, *, max_callbacks=None):
        if max_callbacks is not None and (type(max_callbacks) is not int or max_callbacks < 0):
            raise InputError('exit callback capacity must be a nonnegative integer or None')
        self._max_callbacks = max_callbacks
        self._lock = RLock()
        self._operation_lock = RLock()
        self._runtime = None
        self._bound = False
        self._lifecycle = 'open'
        self._records = []
        self._failure = None
        self._failure_text = None
        self._active_operations = 0
        self._leases = {}
        self._thread_tokens = {}
        self._fresh_owner = None

    def take_fresh(self, owner):
        with self._operation_lock, self._lock:
            if (owner is None or self._fresh_owner is not None or self._bound or self._runtime is not None or
                    self._lifecycle != 'open' or self._records or self._leases or self._thread_tokens or
                    self._active_operations or self._failure is not None):
                raise InputError('SUPPLIED_REGISTRAR_NOT_FRESH')
            self._fresh_owner = owner

    def abandon_fresh(self, *, owner=None):
        with self._operation_lock, self._lock:
            if (self._fresh_owner is not owner or self._bound or self._runtime is not None or
                    self._lifecycle != 'open' or self._records or self._leases or self._thread_tokens or
                    self._active_operations or self._failure is not None):
                raise InputError('SUPPLIED_REGISTRAR_NOT_FRESH')
            return self.abandon()

    def authorize_thread(self, thread_id, token):
        with self._lock:
            if self._lifecycle != 'open' or type(thread_id) is not int or thread_id <= 0 or token is None:
                raise InputError('exit thread authorization requires an open owner and native identity')
            if thread_id in self._thread_tokens:
                raise InputError('native exit thread was already authorized')
            self._thread_tokens[thread_id] = token

    def retire_thread(self, thread_id, token):
        with self._lock:
            if token is None or self._thread_tokens.get(thread_id) is not token or thread_id in self._leases:
                raise InputError('exit thread retirement requires its token and no active lease')
            del self._thread_tokens[thread_id]

    def current_lease(self):
        with self._lock:
            stack = self._leases.get(get_native_id(), ())
            if not stack or stack[-1].suspended:
                raise InputError('exit registrar has no current execution lease')
            return stack[-1]

    def bind(self, runtime):
        with self._lock:
            if self._bound or self._lifecycle != 'open':
                raise InputError('exit registrar requires one runtime binding while open')
            base = getattr(runtime, 'image_base', None)
            if not callable(getattr(runtime, 'invoke', None)) or type(base) is not int or not 0 <= base < 1 << 64:
                raise InputError('exit registrar requires a guest runtime and image base')
            self._runtime = runtime
            self._bound = True

    def __call__(self, callback):
        if type(callback) is not int or not 0 <= callback < 1 << 64:
            raise InputError('exit callback must be an unsigned64 guest address')
        with self._lock:
            if self._lifecycle != 'open':
                return callback, -1
            if not self._bound:
                raise InputError('exit registrar is not bound')
            if self._max_callbacks is not None and len(self._records) >= self._max_callbacks:
                return callback, -1
            try:
                self._records.append(_ExitRecord(len(self._records), callback))
            except MemoryError:
                return callback, -1
            return callback, 0

    def operation(self, *, token=None):
        return _ExecutionLease(self, token=token)

    def close(self):
        with _ExecutionLease(self, closing=True):
            with self._lock:
                if self._lifecycle == 'closed':
                    return
                if self._lifecycle == 'cleanup_failed':
                    raise self._failure
                if self._lifecycle != 'open' or self._active_operations:
                    raise InputError('exit owner cannot close reentrantly or after abandonment')
                if not self._bound:
                    raise InputError('exit registrar is not bound')
                self._lifecycle = 'closing'
                runtime = self._runtime
            try:
                vm = SimpleNamespace(cells=_EmptyCells())
                for record in reversed(self._records):
                    with self._lock:
                        record.status = 'invoking'
                    try:
                        runtime.invoke(vm, record.address - runtime.image_base, ())
                    except BaseException:
                        with self._lock:
                            record.status = 'failed'
                        raise
                    with self._lock:
                        record.status = 'completed'
            except BaseException as error:
                with self._lock:
                    self._failure = error
                    self._failure_text = repr(error)
                    self._lifecycle = 'cleanup_failed'
                raise
            with self._lock:
                self._lifecycle = 'closed'
                self._runtime = None

    def snapshot(self):
        with self._lock:
            return {
                'lifecycle': self._lifecycle,
                'bound': self._bound,
                'owns_runtime': self._runtime is not None,
                'failure': self._failure_text,
                'records': tuple({'sequence': r.sequence, 'address': r.address, 'status': r.status}
                                 for r in self._records),
            }

    def abandon(self):
        with self._operation_lock:
            with self._lock:
                if self._lifecycle == 'closing' or self._active_operations or self._leases:
                    raise InputError('exit owner cannot abandon an active operation')
                if self._lifecycle != 'closed':
                    self._lifecycle = 'abandoned'
                self._runtime = None
                self._failure = None
                return self.snapshot()
