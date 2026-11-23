from contextlib import contextmanager, nullcontext
import ctypes
import os
import sys
import threading
from types import SimpleNamespace

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_LIVE_SERVICES = set()
_ABSENT = object()
_HOST_FAILURE = 0xE0001025
_EXECUTION_DOMAIN = ('_primary_direct_scope', '_primary_public_direct_owner',
    '_primary_close_direct_owner', '_primary_provider_initialization_owner',
    '_primary_sdk_worker_owner', '_primary_secondary_postfetch_owner',
    '_primary_notification_worker_owner', '_primary_device_request_owner', '_primary_client_configuration_owner',
    '_execute_thread', '_execute_depth', '_program_calls')


class _WorkerServiceObservations(WorkerObservations):
    def __init__(self, service, fallback):
        self.service, self.fallback = service, fallback

    def take(self, runtime, name, arguments):
        if self.service.handles(runtime, name, arguments):
            return self.service.take(runtime, name, arguments)
        return self.fallback.take(runtime, name, arguments)


class WindowsSDKThreadService(WorkerObservations):
    def __init__(self, *, timeout_ms=10000):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise PrimarySemanticUnavailable('SDK native threads require Windows x64')
        if type(timeout_ms) is not int or not 0 <= timeout_ms < 0xFFFFFFFF:
            raise InputError('SDK thread join requires a bounded DWORD timeout')
        self._owner = os.getpid(), threading.get_native_id()
        self._timeout_ms = timeout_ms
        self._wait_failure_details = None
        self._runtime = self._registrar = self._observer_factory = None
        self._gate = threading.Event()
        self._execution = threading.Lock()
        self._active_owner = False
        self._draining = False
        self._closed = False
        self._failure = None
        self._threads = []
        self._crt_domains = {}
        self._secondary = []
        self._secondary_direct_serial = 0
        self._device_request_serial = 0
        self._request_pump_row = None
        self._notification_direct_serial = 0
        self._worker_bridge = None
        self._bridge_capability = None
        self._execution_tid = None
        self._module_pending = {}
        self._closing = False
        self._close_token = object()
        self._holder_slot = None
        self._holder_values = {}
        self._holder_active = set()
        self._holder_failure = None
        self._holder_records = []
        self._holder_errors = {}
        self._ticket_sequence = 0
        self._wake_records = []
        self._kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self._callback_type = ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)
        for name, result, arguments in (
                ('CreateThread', ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_size_t, self._callback_type,
                                                  ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))),
                ('GetCurrentThreadId', ctypes.c_uint32, ()),
                ('GetThreadId', ctypes.c_uint32, (ctypes.c_void_p,)),
                ('WaitForSingleObject', ctypes.c_uint32, (ctypes.c_void_p, ctypes.c_uint32)),
                ('GetExitCodeThread', ctypes.c_int32, (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))),
                ('DuplicateHandle', ctypes.c_int32, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                                     ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32,
                                                     ctypes.c_int32, ctypes.c_uint32)),
                ('CloseHandle', ctypes.c_int32, (ctypes.c_void_p,))):
            function = getattr(self._kernel, name)
            function.restype, function.argtypes = result, arguments
        self._fls_callback_type = ctypes.WINFUNCTYPE(None, ctypes.c_void_p)
        self._holder_callback = self._fls_callback_type(self._holder_cleanup)
        for name, result, arguments in (
                ('FlsAlloc', ctypes.c_uint32, (self._fls_callback_type,)),
                ('FlsGetValue', ctypes.c_void_p, (ctypes.c_uint32,)),
                ('FlsSetValue', ctypes.c_int32, (ctypes.c_uint32, ctypes.c_void_p)),
                ('FlsFree', ctypes.c_int32, (ctypes.c_uint32,))):
            function = getattr(self._kernel, name)
            function.restype, function.argtypes = result, arguments

    def _check_owner(self):
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('SDK thread service requires its creating process and native thread')

    def bind(self, runtime, registrar, observer_factory):
        self._check_owner()
        if self._runtime is not None or self._closed or not callable(observer_factory):
            raise InputError('SDK thread service requires one live runtime and observer factory binding')
        self._runtime, self._registrar, self._observer_factory = runtime, registrar, observer_factory
        registrar.authorize_thread(self._owner[1], self._close_token)
        runtime.worker_resident_checkpoint = self.resident_checkpoint
        runtime.worker_stop_checkpoint = self.stop_checkpoint
        from .primary_client_configuration_scope import bind_service
        bind_service(self)

    def observations(self, fallback):
        return _WorkerServiceObservations(self, fallback)

    def bind_worker_bridge(self, bridge):
        self._check_owner()
        if self._worker_bridge is not None or self._secondary or self._closed:
            raise InputError('secondary bridge requires one fresh owner binding')
        self._worker_bridge = bridge
        self._bridge_capability = bridge.authorize_service(self._bridge_creation_authorized)

    def _bridge_creation_authorized(self):
        tid = threading.get_native_id()
        if os.getpid() != self._owner[0] or self._execution_tid != tid or self._closed:
            return False
        try:
            self._registrar.current_lease()
        except InputError:
            return False
        return tid == self._owner[1] and not self._closing or any(row['callback_thread_id'] == tid and row['state'] == 'running' for row in self._threads)

    def handles(self, runtime, name, arguments):
        if name == 'WakeConditionVariable':
            return True
        if runtime is not self._runtime:
            return False
        if name == 'Sleep':
            return runtime.__dict__.get('_primary_client_configuration_owner') is not None
        if name == 'GetModuleHandleExW':
            return arguments == (4, runtime.image_base + 0x7879A0)
        if name == 'CreateThread':
            return True
        if name == 'CloseHandle':
            return len(arguments) == 1 and any(
                row.get('_kind') in ('notification', 'client_startup') and not row['source_handle_closed'] and
                row['source_handle'] == arguments[0] for row in self._threads)
        if name == 'GetThreadId':
            return any(row['handle'] == arguments[0] for row in self._secondary) if len(arguments) == 1 else False
        if name == 'FlsAlloc':
            return arguments == (runtime.image_base + 0x760280,)
        if name in ('FlsGetValue', 'FlsSetValue'):
            return bool(arguments) and self._holder_slot is not None and arguments[0] == self._holder_slot
        if name in ('ExitThread', 'FreeLibraryAndExitThread'):
            return True
        if name == 'GetLastError':
            return arguments == () and threading.get_native_id() in self._holder_errors
        return False

    def _client_srw_api(self,runtime,name,native,port):
        from .primary_client_configuration_startup import _SourceSRW
        source=sys._getframe(1)
        if (source.f_code is not _SourceSRW.call.__code__ or source.f_locals.get('self') is not port or
                type(port) is not _SourceSRW or port.service is not self or self._runtime is not runtime or
                getattr(self,'_client_source_srw',None) is not port or port.pin is None or port.pin[2] is not native or
                name not in ('AcquireSRWLockExclusive','ReleaseSRWLockExclusive')):
            raise InputError('SOURCE_SRW native ABI requires its original issued port and live pin')
        port.identity()
        function=getattr(self._kernel,name)
        function.restype=None
        function.argtypes=(ctypes.c_void_p,)
        port._entered(name)
        return function(ctypes.c_void_p(ctypes.addressof(native)))

    def _client_sleep(self, runtime, arguments):
        from .primary_client_configuration import _host
        from .primary_client_configuration_scope import require_owner, _frame
        owner = require_owner(runtime)
        if (owner.service is not self or _frame(_host.__code__, runtime) is None or
                len(arguments) != 1 or type(arguments[0]) is not int or not 0 <= arguments[0] <= 0xFFFFFFFF):
            raise InputError('client Sleep requires its exact source import, owner and DWORD duration')
        tid = threading.get_native_id()
        domain = self._crt_domains.get(tid)
        if domain is None:
            raise PrimarySemanticUnavailable('client Sleep requires its retained original CRT/TLS domain')
        lease = self._registrar.current_lease()
        source_state = self._save_domain()
        domain['state'] = source_state
        self._restore_domain(domain['owner_state'])
        owner.row['state'] = 'client_sleeping'
        owner.image.debts.append(('sleep', (owner.row, arguments[0], lease)))
        function = self._kernel.Sleep
        function.restype, function.argtypes = None, (ctypes.c_uint32,)
        try:
            with lease.suspend():
                self._execution_tid = None
                self._execution.release()
                try:
                    result = function(arguments[0])
                    if result is not None:
                        raise InputError('physical client Sleep must return void')
                finally:
                    self._execution.acquire()
                    self._execution_tid = tid
        finally:
            domain['owner_state'] = self._save_domain()
            self._restore_retained_domain(source_state, tid)
            owner.row['state'] = 'running'
        require_owner(runtime)
        self._validate_execution_domain()
        return None, b''

    def _restore_retained_domain(self, state, tid):
        from .primary_client_configuration_scope import retain_domain
        primary = sys.exception()
        try:
            self._restore_domain(state)
        except BaseException as failure:
            if primary is None or not retain_domain(self, tid):
                raise
            primary.add_note('client retained-domain restore failed: ' + type(failure).__name__)

    def _secondary_row(self):
        tid = threading.get_native_id()
        rows = [row for row in self._secondary if row['thread_id'] == tid]
        if len(rows) != 1:
            raise InputError('source secondary operation requires its registered actual native thread')
        return rows[0]

    def _holder_cleanup(self, value):
        tid = threading.get_native_id()
        try:
            if self._holder_values.get(tid) != int(value or 0) or tid in self._holder_active:
                raise InputError('holder FLS callback requires its retained native-thread value')
            self._holder_active.add(tid)
            with self._callback_context(self._runtime, tid, 'holder'):
                vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: int(value or 0)))
                self._runtime.invoke(vm, 0x760280, (0,))
                self._holder_values.pop(tid)
                self._holder_records.append({'thread_id': tid, 'source_callback': 0x760280, 'completed': True})
        except BaseException as error:
            self._holder_failure = error
        finally:
            self._holder_active.discard(tid)

    def _pending_fls(self, tid):
        crt = getattr(self._runtime, 'crt_startup_observations', None)
        return tid in self._holder_values or tid in self._holder_active or (
            crt is not None and tid in crt.snapshot()['pending_thread_ids'])

    def source_start(self, *arguments):
        client = arguments == (0, 0, self._runtime.image_base + 0x1C22D90, 0, 0, 0) if self._runtime is not None else False
        if not client:
            self._check_owner()
        if self._runtime is None or self._closed or self._closing or self._draining:
            raise InputError('SDK source thread creation requires its live bound owner')
        if arguments == (0, 0, self._runtime.image_base + 0x1C1BB80, 0, 0, 0):
            return self.bootstrap_start(*arguments)
        receipt = None
        if client:
            from .primary_client_configuration_scope import startup_creation
            receipt = startup_creation(self)
        expected = (0, 0, self._runtime.image_base + (0x1C22D90 if client else 0x1C29910), 0 if client else 3000, 0, 0)
        if arguments != expected or any(type(value) is not int for value in arguments):
            raise InputError('SDK source thread requires a supported exact six-argument entry')
        row = {'_kind': 'client_startup' if client else 'notification', 'declared_parameter': arguments[3], 'state': 'creating', 'handle': 0, 'thread_id': 0,
               'callback_thread_id': None, 'source_handle': 0, 'source_handle_closed': False,
               'source_close_result': None, 'create_error': 0, 'host_failure': None,
               'source_completed': False, 'signaled': False, 'joined': False,
               'handle_closed': False, 'exit_code': None, 'crt_fls_cleanup': 'not_observed'}
        if client:
            row['_client_receipt'] = receipt
            receipt['row'] = row
            receipt['image'].rows.append(row)
            receipt['image'].row_receipts.append((row, receipt))
        self._threads.append(row)
        callback = self._callback_type(lambda parameter: self._notification_entry(row, parameter))
        row['_callback'] = callback
        if client:
            receipt['callback'] = callback
        identifier = ctypes.c_uint32()
        _LIVE_SERVICES.add(self)
        ctypes.set_last_error(0)
        source = int(self._kernel.CreateThread(None, 0, callback, ctypes.c_void_p(arguments[3]), 0,
                                              ctypes.byref(identifier)) or 0)
        row['source_handle'], row['thread_id'] = source, identifier.value
        if not source:
            row['state'], row['create_error'] = 'create_failed', ctypes.get_last_error()
            return (*arguments, 0)
        row['handle'] = source
        duplicate = ctypes.c_void_p()
        if not self._kernel.DuplicateHandle(ctypes.c_void_p(-1), source, ctypes.c_void_p(-1),
                                            ctypes.byref(duplicate), 0, False, 2):
            row['state'] = 'duplicate_failed'
            self._failure = PrimarySemanticUnavailable('notification join-handle duplication failed: ' +
                                                       str(ctypes.get_last_error()))
            raise self._failure_for_raise()
        row['handle'] = int(duplicate.value or 0)
        if not row['handle'] or row['handle'] == source:
            self._failure = PrimarySemanticUnavailable('notification requires an independent native join handle')
            raise self._failure_for_raise()
        row['state'] = 'created_pending'
        actual = self._kernel.GetThreadId(source)
        if not actual or actual != identifier.value or actual == self._owner[1]:
            self._failure = PrimarySemanticUnavailable('notification native thread identity validation failed')
        return (*arguments, source)

    def bootstrap_start(self, *arguments):
        self._check_owner()
        if self._runtime is None or self._closed or self._draining or self._threads:
            raise InputError('SDK bootstrap creation is unavailable or already attempted')
        expected = (0, 0, self._runtime.image_base + 0x1C1BB80, 0, 0, 0)
        if arguments != expected or any(type(value) is not int for value in arguments):
            raise InputError('SDK bootstrap requires the exact six source CreateThread arguments')
        row = {'_diagnostic_role': 'bootstrap', 'state': 'creating', 'handle': 0, 'thread_id': 0, 'callback_thread_id': None,
               'create_error': 0, 'host_failure': None, 'source_completed': False,
               'signaled': False, 'joined': False, 'handle_closed': False, 'exit_code': None,
               'crt_fls_cleanup': 'not_observed'}
        self._threads.append(row)
        callback = self._callback_type(lambda parameter: self._entry(row, parameter))
        row['_callback'] = callback
        identifier = ctypes.c_uint32()
        _LIVE_SERVICES.add(self)
        ctypes.set_last_error(0)
        handle = self._kernel.CreateThread(None, 0, callback, None, 0, ctypes.byref(identifier))
        error = ctypes.get_last_error()
        row['handle'], row['thread_id'] = int(handle or 0), identifier.value
        if not handle:
            row['state'], row['create_error'] = 'create_failed', error
            _LIVE_SERVICES.discard(self)
            return (*arguments, 0)
        row['state'] = 'created_pending'
        actual = self._kernel.GetThreadId(handle)
        error = ctypes.get_last_error()
        if not actual or actual != identifier.value or actual == self._owner[1]:
            self._failure = PrimarySemanticUnavailable('native SDK thread identity validation failed: ' + str(error))
        return (*arguments, int(handle))

    def take(self, runtime, name, arguments):
        if runtime is not self._runtime or os.getpid() != self._owner[0]:
            raise InputError('SDK thread observation requires its bound runtime and process')
        if not isinstance(arguments, tuple):
            raise InputError('SDK source observation requires tuple arguments')
        if name == 'Sleep':
            return self._client_sleep(runtime, arguments)
        if name == 'WakeConditionVariable':
            return self._wake_condition(runtime, arguments)
        if name == 'GetModuleHandleExW' and arguments == (4, runtime.image_base + 0x7879A0):
            if self._worker_bridge is None:
                raise PrimarySemanticUnavailable('secondary source module requires its owned worker bridge binding')
            tid = threading.get_native_id()
            if tid in self._module_pending:
                raise InputError('source creator retains an unconsumed module lookup')
            with self._worker_bridge.service_creation(self._bridge_capability):
                reference = self._worker_bridge.acquire_worker_reference(runtime.image_base, arguments[1])
            self._module_pending[tid] = reference
            return reference.result, reference.module if reference.result else None
        if name == 'CreateThread':
            return self._create_secondary(arguments)
        if name == 'CloseHandle' and self.handles(runtime, name, arguments):
            client = any(row.get('_kind') == 'client_startup' and row.get('source_handle') == arguments[0] for row in self._threads)
            if client:
                from .primary_client_configuration_scope import require_creator
                require_creator(self)
            else:
                self._check_owner()
            row = next(row for row in self._threads if row.get('_kind') in ('notification', 'client_startup') and
                       not row['source_handle_closed'] and row['source_handle'] == arguments[0])
            result = int(self._kernel.CloseHandle(arguments[0]))
            row['source_close_result'] = result
            if result or not arguments[0]:
                row['source_handle_closed'] = True
            return result, b''
        if name == 'GetThreadId' and len(arguments) == 1:
            for row in self._secondary:
                if row['handle'] == arguments[0]:
                    with self._worker_bridge.service_creation(self._bridge_capability):
                        return row['_launch'].get_thread_id(), None
            raise InputError('source thread ID requires its retained secondary handle')
        if name == 'FlsAlloc' and arguments == (runtime.image_base + 0x760280,):
            if self._holder_slot is not None:
                raise InputError('source holder FLS slot was already allocated')
            result = self._kernel.FlsAlloc(self._holder_callback)
            if result != 0xFFFFFFFF:
                self._holder_slot = result
            else:
                self._holder_errors[threading.get_native_id()] = ctypes.get_last_error()
            return result, b''
        if name in ('FlsGetValue', 'FlsSetValue') and arguments and arguments[0] == self._holder_slot and self._holder_slot is not None:
            self._secondary_row()
            tid = threading.get_native_id()
            if name == 'FlsGetValue' and len(arguments) == 1:
                actual = int(self._kernel.FlsGetValue(self._holder_slot) or 0)
                if actual != self._holder_values.get(tid, 0):
                    raise PrimarySemanticUnavailable('native holder FLS value differs from its source provenance')
                return actual, b''
            if name == 'FlsSetValue' and len(arguments) == 2 and type(arguments[1]) is int and 0 <= arguments[1] < 1 << 64:
                result = self._kernel.FlsSetValue(self._holder_slot, arguments[1])
                if result:
                    if arguments[1]:
                        self._holder_values[tid] = arguments[1]
                    else:
                        self._holder_values.pop(tid, None)
                else:
                    self._holder_errors[tid] = ctypes.get_last_error()
                return result & 0xFFFFFFFF, b''
            raise InputError('holder FLS arguments differ from their finite source ABI')
        if name == 'GetLastError' and arguments == () and threading.get_native_id() in self._holder_errors:
            return self._holder_errors.pop(threading.get_native_id()), b''
        if name in ('ExitThread', 'FreeLibraryAndExitThread'):
            row = self._secondary_row()
            from .primary_windows_worker_bridge import NativeWorkerExit
            if name == 'ExitThread' and len(arguments) == 1:
                module, code = 0, arguments[0]
            elif name == 'FreeLibraryAndExitThread' and len(arguments) == 2:
                module, code = arguments
                reference = row['_reference']
                if reference is None or reference.state != 'acquired' or module != reference.module:
                    raise InputError('source native epilogue requires its personally acquired worker module')
            else:
                raise InputError('source thread exit arguments differ from their ABI')
            if type(code) is not int or not 0 <= code <= 0xFFFFFFFF or row.get('_exit_request') is not None:
                raise InputError('source thread exit requires one exact DWORD request')
            row['_exit_request'] = NativeWorkerExit(name, code, module)
            return None, b''
        raise PrimarySemanticUnavailable('SDK thread source observation is unavailable: ' + name)

    def _save_domain(self):
        return {name: getattr(self._runtime, name, _ABSENT) for name in (
            'worker_observations', 'tls_epoch_address', 'tls_base_address',
            'crt_thread_address', '_crt_dispatch_active', '_filetimes', *_EXECUTION_DOMAIN)}

    def _enter_worker_domain(self):
        runtime = self._runtime
        for name in _EXECUTION_DOMAIN:
            runtime.__dict__.pop(name, None)
        runtime._execute_thread, runtime._execute_depth, runtime._program_calls = None, 0, []

    def _validate_execution_domain(self):
        runtime = self._runtime
        depth, calls = runtime._execute_depth, runtime._program_calls
        if (type(depth) is not int or depth < 0 or type(calls) is not list or len(calls) != depth or
                runtime._execute_thread != (threading.get_ident() if depth else None) or
                runtime._active_main is not None):
            raise InputError('resident execution stack differs from its current native domain')
        scope = runtime.__dict__.get('_primary_direct_scope')
        owners = tuple(runtime.__dict__.get(name) for name in _EXECUTION_DOMAIN[1:9])
        if scope is None:
            if any(owner is not None for owner in owners):
                raise InputError('resident lifecycle owner has no paired direct scope')
            return
        from .primary_direct_scopes import PrimaryDirectScope
        if type(scope) is not PrimaryDirectScope or scope.runtime is not runtime:
            raise InputError('resident execution requires its exact direct scope')
        paired = (scope.public_owner, scope.close_owner, scope.initialization_owner,
                  scope.worker_owner, scope.secondary_owner, scope.notification_owner, scope.device_owner, scope.client_owner)
        if any(owner is not expected for owner, expected in zip(owners, paired)) or sum(owner is not None for owner in owners) != 1:
            raise InputError('resident direct scope and lifecycle owner differ')
        scope._require_live()

    def _create_secondary(self, arguments):
        runtime = self._runtime
        if self._worker_bridge is None or not self._bridge_creation_authorized():
            raise PrimarySemanticUnavailable('secondary creation requires its owned bridge and source creator execution lease')
        if (len(arguments) != 5 or arguments[:3] != (0, 0, runtime.image_base + 0x3E81800) or arguments[4] != 0 or
                any(type(value) is not int for value in arguments)):
            raise InputError('secondary creation requires the exact five source arguments')
        context = arguments[3]
        memory, base = runtime.memory, runtime.image_base
        start = memory.load(context + 8, 8)
        control = memory.load(start + 8, 8)
        task = memory.load(control + 16, 8)
        client = memory.load(control + 8, 8) == base + 0x1C50F70
        client_receipt = None
        if memory.load(context, 8) != base + 0x7879A0 or memory.load(start, 8) != base + 0xBD55C0:
            raise PrimarySemanticUnavailable('secondary creation requires its actual source CRT/control chain')
        if client:
            from .primary_client_configuration_scope import secondary_creation
            client_receipt = secondary_creation(self, context, start, control, task)
        elif (memory.load(control + 8, 8) != base + 0xBD4B00 or memory.load(task + 0xD8, 4) != 2 or
                not memory.load(task + 32, 1) & 1):
            raise PrimarySemanticUnavailable('secondary creation requires the source mode2 worker control chain')
        tid = threading.get_native_id()
        if tid not in self._module_pending:
            raise InputError('secondary creation requires its preceding source module lookup')
        reference = self._module_pending.pop(tid)
        if memory.load(context + 24, 8) != (reference.module if reference.result else 0):
            self._module_pending[tid] = reference
            raise InputError('source CRT context module differs from its acquired worker reference')
        row = {'state': 'created_pending', 'handle': 0, 'thread_id': 0, 'callback_thread_id': None,
               'task': task, 'context': context, 'source_completed': False, 'signaled': False,
               'joined': False, 'handle_closed': False, 'exit_code': None, 'host_failure': None,
               'crt_fls_cleanup': 'not_observed', 'holder_fls_cleanup': 'not_observed',
               '_reference': reference if reference.result else None, '_checkpoint': threading.Event(),
               '_resume': threading.Event(), '_kind': 'client_loop' if client else 'secondary',
               '_source_chain': (context, start, control, task),
               '_start_gate': threading.Event() if task == base + 0x6751C58 else self._gate}
        if client:
            row['_client_receipt'] = client_receipt
            client_receipt['row'] = row
            client_receipt['image'].rows.append(row)
            client_receipt['image'].row_receipts.append((row, client_receipt))
        self._secondary.append(row)
        self._threads.append(row)
        _LIVE_SERVICES.add(self)
        with self._worker_bridge.service_creation(self._bridge_capability):
            launch = self._worker_bridge.launch(lambda ignored: self._secondary_entry(row), context,
                module_reference=row['_reference'], quiescence_check=lambda: self._secondary_quiescent(row))
        row['_launch'] = launch
        if client:
            client_receipt['launch'] = launch
            client_receipt['bridge'] = self._worker_bridge
        row['handle'], row['thread_id'], row['create_error'] = launch.handle, launch.thread_id, launch.creation_error
        if launch.handle:
            self._registrar.authorize_thread(launch.thread_id, self._close_token)
        else:
            row['state'] = 'create_failed_source_cleanup_missing'
            self._failure = PrimarySemanticUnavailable('3E8172E source creation-failure cleanup is unavailable; start16 and source ownership retained')
        return launch.handle, launch.thread_id

    def _secondary_entry(self, row):
        from .primary_thread_dispatch import ThreadTerminated
        try:
            row['callback_thread_id'] = threading.get_native_id()
            row.get('_start_gate', self._gate).wait()
            with self._execution:
                with self._registrar.operation(token=self._close_token):
                    self._execution_tid = threading.get_native_id()
                    row['state'] = 'running'
                    try:
                        if row.get('_kind') == 'client_loop':
                            from .primary_client_configuration_scope import entry_preflight
                            entry_preflight(self, row)
                        domain = self._context()
                        with domain:
                            from .primary_sign_lifecycle import secondary_postfetch_call
                            from .primary_client_configuration_scope import worker_call as client_call
                            with (client_call(self, row, domain) if row['_kind'] == 'client_loop' else
                                  nullcontext() if row['task'] == self._runtime.image_base + 0x6751C58 else
                                  secondary_postfetch_call(self, row, domain)):
                                vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: row['context']))
                                try:
                                    self._runtime.invoke(vm, 0x3E81800, (0,))
                                except ThreadTerminated as signal:
                                    request = row.get('_exit_request')
                                    expected = (request.module, request.code) if request is not None and request.action == 'FreeLibraryAndExitThread' else (() if request is None else (request.code,))
                                    if request is None or signal.api != request.action or signal.arguments != expected:
                                        raise InputError('source terminal signal differs from its validated native exit request')
                                else:
                                    raise PrimarySemanticUnavailable('source CRT secondary entry returned without its terminal signal')
                        row['source_completed'] = True
                        row['state'] = 'source_terminated'
                    finally:
                        self._execution_tid = None
            return row['_exit_request']
        except BaseException as error:
            self._remember_failure(error, row)
            row['host_failure'], row['state'] = type(error).__name__, 'host_failed'
            raise
        finally:
            from .primary_device_request import _revoke_drain
            _revoke_drain(row)
            row['_checkpoint'].set()

    def _wake_condition(self, runtime, arguments):
        tid = threading.get_native_id()
        if (self._closed or self._closing or self._execution_tid != tid or not self._execution.locked() or self._failure is not None or
                self._holder_failure is not None or self._holder_active):
            raise PrimarySemanticUnavailable('condition wake requires live serialized execution without host failure')
        lease = self._registrar.current_lease()
        if (lease.registrar is not self._registrar or lease.thread_id != tid or not lease.active or lease.suspended or
                self._registrar._runtime is not runtime):
            raise InputError('condition wake requires its bound current registrar execution lease')
        current = [row for row in self._threads if row.get('callback_thread_id') == tid and row['state'] == 'running']
        if self._active_owner:
            if tid != self._owner[1] or current:
                raise InputError('condition wake owner identity differs from its explicit execution owner')
        elif len(current) != 1 or current[0]['thread_id'] != tid:
            raise InputError('condition wake requires its unique running bootstrap or secondary identity')
        if len(arguments) != 1 or type(arguments[0]) is not int:
            raise InputError('condition wake requires its exact owned condition address')
        condition = arguments[0]
        owned = [row for row in self._secondary if row['task'] + 0x48 == condition]
        if len(owned) != 1:
            raise PrimarySemanticUnavailable('condition wake does not identify one owned secondary task')
        target = owned[0]
        if (sum(row is target for row in self._threads) != 1 or type(target['handle']) is not int or
                target['handle'] <= 0 or type(target['thread_id']) is not int or target['thread_id'] <= 0 or
                target.get('_launch') is None or target.get('joined') or target.get('handle_closed')):
            raise PrimarySemanticUnavailable('condition wake task has no live successful native creation')
        task, memory = target['task'], runtime.memory
        expected = runtime.worker_imports.get('WakeConditionVariable')
        if type(expected) is not int or not expected or memory.load(runtime.image_base + 0x4910458, 8) != expected:
            raise PrimarySemanticUnavailable('condition wake current import is not bound')
        if memory.load(task + 0xD8, 4) != 2 or memory.load(condition, 8) != 0:
            raise PrimarySemanticUnavailable('condition wake requires its known-zero source mode2 condition')
        if getattr(runtime, '_logger_locks', {}).get(task + 0x40) is not True:
            raise PrimarySemanticUnavailable('condition wake requires its currently held source queue SRW')
        self._queues_empty(task)
        if memory.load(task + 0x38, 8) == 0:
            raise PrimarySemanticUnavailable('condition wake requires a committed nonempty source queue')
        crt = getattr(runtime, 'crt_startup_observations', None)
        if crt is not None:
            snapshot = crt.snapshot()
            if snapshot['callback_failure'] is not None or snapshot['callbacks_active']:
                raise PrimarySemanticUnavailable('condition wake cannot prove CRT callback quiescence')
        states = []
        for row in self._threads:
            if (row.get('host_failure') is not None or not row.get('handle') or not row.get('thread_id') or
                    row.get('callback_thread_id') not in (None, row['thread_id'])):
                raise PrimarySemanticUnavailable('condition wake retains a failed native continuation')
            if current and row is current[0]:
                states.append('current_running')
                continue
            state = row['state']
            if state == 'created_pending':
                if (not row.get('handle') or not row.get('thread_id') or row.get('_ticket') is not None or
                        row.get('_kind') == 'secondary' and row['task'] in getattr(runtime, 'worker_entry_states', {})):
                    raise PrimarySemanticUnavailable('condition wake cannot prove continuation precedes guest entry')
            elif state == 'parked_at_BD4B60':
                witness = row.get('_park_witness')
                entry = getattr(runtime, 'worker_entry_states', {}).get(row.get('task'))
                if (witness is None or witness[0] is not entry or entry is None or entry.failure is not None or
                        entry.call_pending or witness[1] != self._park_signature(entry) or
                        witness[2] != row.get('consumed_ticket', 0) or row.get('resident_rva') != 0xBD4B60 or
                        row.get('source_frame') != entry.frame or row.get('_ticket') is not None or
                        not row['_checkpoint'].is_set() or row['_resume'].is_set()):
                    raise PrimarySemanticUnavailable('condition wake requires its verified unticketed pre-read source park')
            elif state in ('returned', 'joined', 'retired'):
                if not row.get('joined') or not row.get('handle_closed') or not row.get('source_completed'):
                    raise PrimarySemanticUnavailable('condition wake continuation termination is not proved')
            else:
                raise PrimarySemanticUnavailable('condition wake has an unproved running, issued, waiting or unknown continuation')
            states.append(state)
        if not hasattr(self, '_wake_records'):
            self._wake_records = []
        self._wake_records.append({'task': task, 'condition': condition, 'thread_id': tid,
            'continuations': tuple(states), 'reason': 'serialized_no_source_CV_waiter'})
        return None, ()

    @staticmethod
    def _park_signature(state):
        return state.phase, state.iterations, state.mode, state.local_initialized, state.frame, state.local_list

    def _queues_empty(self, task):
        memory = self._runtime.memory
        empty = True
        for offset in (0x28, 0x60):
            head = task + offset
            previous, following, count = (memory.load(head + index * 8, 8) for index in range(3))
            low = memory.load(head + 16, 4)
            if low != count:
                raise PrimarySemanticUnavailable('resident queue DWORD and full count disagree')
            if count > 100000:
                raise PrimarySemanticUnavailable('resident queue exceeds the supported 100000-node validation bound')
            if not count:
                if previous != head or following != head:
                    raise PrimarySemanticUnavailable('resident empty queue has inconsistent sentinel links')
            else:
                if previous == head or following == head or memory.load(previous + 8, 8) != head or memory.load(following, 8) != head:
                    raise PrimarySemanticUnavailable('resident nonempty queue has inconsistent boundary links')
                seen = set()
                cursor, predecessor = following, head
                for index in range(count):
                    if cursor == head:
                        raise PrimarySemanticUnavailable('resident queue reaches its sentinel before its exact count')
                    if cursor in seen:
                        raise PrimarySemanticUnavailable('resident queue contains a non-sentinel cycle')
                    seen.add(cursor)
                    before, after = memory.load(cursor, 8), memory.load(cursor + 8, 8)
                    if before != predecessor or memory.load(after, 8) != cursor:
                        raise PrimarySemanticUnavailable('resident queue has inconsistent internal reciprocal links')
                    predecessor, cursor = cursor, after
                if cursor != head or predecessor != previous:
                    raise PrimarySemanticUnavailable('resident queue node chain differs from its exact count or tail')
                empty = False
        return empty

    def resident_failure_observation(self, runtime, state=None):
        if runtime is not self._runtime:
            raise InputError('resident observation requires its bound runtime')
        logger = getattr(runtime, '_logger_locks', {})
        source = getattr(runtime, 'locks', {})
        categories = {}
        for row in self._secondary[:128]:
            task = row.get('task')
            if type(task) is int:
                for offset, name in ((0xE0, 'TASK_STARTUP'), (0xE8, 'TASK_LIFECYCLE'),
                        (0x40, 'TASK_FUNCTION_QUEUE'), (0x78, 'TASK_VECTOR_QUEUE')):
                    categories[task + offset] = name
        def held(table):
            counts = {}
            for index, (key, value) in enumerate(table.items()):
                if index == 1024:
                    return dict(count='UNKNOWN', categories=counts, truncated=True)
                if value:
                    name = categories.get(key, 'UNKNOWN')
                    counts[name] = counts.get(name, 0) + 1
            return dict(count=sum(counts.values()), categories=counts, truncated=False)
        lease = None
        try:
            lease = self._registrar.current_lease()
        except InputError:
            pass
        tid = threading.get_native_id()
        phase = getattr(state, 'phase', None)
        phases = ('created', 'start_lock', 'stop_lock', 'loop', 'function_batch',
            'vector_batch', 'vector_cleanup', 'budget_exhausted', 'complete')
        return dict(callPending=None if state is None else bool(state.call_pending),
            anyLogger=any(logger.values()), anySource=any(source.values()),
            loggerHeld=held(logger), sourceHeld=held(source),
            phase=phase if phase in phases else 'UNKNOWN', executionLocked=self._execution.locked(),
            executionThreadMatches=self._execution_tid == tid, ownerThread=tid == self._owner[1],
            leaseCurrent=lease is not None and lease.registrar is self._registrar and lease.thread_id == tid,
            leaseActive=lease is not None and lease.active, leaseSuspended=lease is not None and lease.suspended)

    def resident_checkpoint(self, runtime, state):
        if not self._secondary or threading.get_native_id() == self._owner[1]:
            return
        row = self._secondary_row()
        if runtime is not self._runtime or state.task != row['task'] or self._execution_tid != threading.get_native_id():
            raise InputError('resident checkpoint requires the exact worker task and execution domain')
        if runtime.memory.load(state.task + 0xD8, 4) != 2:
            raise PrimarySemanticUnavailable('native resident mode0/1 waiting is unavailable')
        self._queues_empty(state.task)
        if state.call_pending or any(getattr(runtime, '_logger_locks', {}).values()) or any(getattr(runtime, 'locks', {}).values()):
            error = PrimarySemanticUnavailable('resident checkpoint retains a source lock or active callback')
            error.residentRefusal = 'UNKNOWN'
            try:
                row['resident_refusal'] = 'UNKNOWN'
                observation = self.resident_failure_observation(runtime, state)
                row['resident_refusal'] = observation
                error.residentRefusal = observation
            except BaseException:
                pass
            raise error
        batch = getattr(runtime, 'worker_batch_states', {}).get(state.task)
        if batch is not None and (batch.phase != 'complete' or batch.call_pending or batch.cleanup is None or batch.cleanup.phase != 'complete'):
            raise PrimarySemanticUnavailable('resident checkpoint retains private batch ownership')
        for operation in getattr(runtime, 'worker_list_operations', {}).values():
            if (operation.source in (state.task + 0x28, state.task + 0x60, state.local_list) or
                    operation.destination in (state.task + 0x28, state.task + 0x60, state.local_list)) and operation.phase != 'complete':
                raise PrimarySemanticUnavailable('resident checkpoint retains a source list transfer')
        if state.local_initialized:
            local = state.local_list
            if tuple(runtime.memory.load(local + offset, 8) for offset in (0, 8, 16)) != (local, local, 0):
                raise PrimarySemanticUnavailable('resident checkpoint private list is not source-cleaned')
        from .primary_device_request import _finish_drain
        _finish_drain(self, row, state, batch)
        self._validate_execution_domain()
        tid = threading.get_native_id()
        domain = self._crt_domains[tid]
        lease = self._registrar.current_lease()
        domain['state'] = self._save_domain()
        domain['main_generation'] = runtime._main_generation
        self._restore_domain(domain['owner_state'])
        row['_resume'].clear()
        row['state'], row['resident_rva'], row['source_frame'] = 'parked_at_BD4B60', 0xBD4B60, state.frame
        row['_park_witness'] = state, self._park_signature(state), row.get('consumed_ticket', 0)
        with lease.suspend():
            self._execution_tid = None
            self._execution.release()
            row['_checkpoint'].set()
            try:
                row['_resume'].wait()
            finally:
                self._execution.acquire()
                self._execution_tid = tid
        # TLS activation requires the original lease stack to be active again.
        current_owner = self._save_domain()
        domain['owner_state'].clear()
        domain['owner_state'].update(current_owner)
        ticket = row.pop('_ticket', None)
        self._restore_domain(domain['state'])
        if (ticket is None or ticket[1] != tid or ticket[2] not in ('drain', 'close', 'request') or
                ticket[0] <= row.get('consumed_ticket', 0)):
            raise InputError('resident continuation requires one fresh identity-bound service ticket')
        row['consumed_ticket'], row['continuation_kind'] = ticket[0], ticket[2]
        if ticket[2] == 'drain' and row['task'] == runtime.image_base + 0x6751C58:
            from .primary_device_request import _activate_drain
            _activate_drain(self, row, ticket)
        row.pop('_park_witness', None)
        row['state'] = 'running'
        owner = domain['state'].get('_primary_secondary_postfetch_owner', _ABSENT)
        if owner is not _ABSENT and owner is not None:
            from .primary_sign_lifecycle import _SecondaryPostfetchOwner
            if type(owner) is not _SecondaryPostfetchOwner:
                raise InputError('resident continuation lost its exact secondary lifecycle owner')
            owner._resume(self, row, domain, ticket)
        self._validate_execution_domain()

    def _secondary_quiescent(self, row):
        tid = row['thread_id']
        crt = self._runtime.crt_startup_observations.snapshot()
        return (row['joined'] and row['handle_closed'] and tid not in self._crt_domains and
                not self._pending_fls(tid) and not self._holder_active and self._holder_failure is None and
                crt['callback_failure'] is None and not crt['callbacks_active'])

    def _restore_domain(self, domain):
        from .primary_creator_domain import _safe_restore
        domain=_safe_restore(self,domain)
        from .primary_shared_locale import _invalidate_module_tls,_activate_native_module_tls,_has_registered_native_module_tls
        _invalidate_module_tls(self._runtime)
        for name, value in domain.items():
            if value is _ABSENT:
                if hasattr(self._runtime, name):
                    delattr(self._runtime, name)
            else:
                setattr(self._runtime, name, value)

        current=self._crt_domains.get(threading.get_native_id())
        from .primary_creator_domain import _for_service
        creator=_for_service(self)
        if creator is not None and creator.domain is not None and current is creator.domain['value'] and creator.domain['active'] and not creator.ptd['consumed'] and self._runtime.tls_base_address==creator.domain['tls']:
            from .primary_shared_locale import _activate_creator_module_tls
            _activate_creator_module_tls(self._runtime,self,current)
        elif (current is not None and not self._closed and
                _has_registered_native_module_tls(self._runtime,self,current) and
                self._runtime.tls_base_address==current['tls'] and
                self._runtime.tls_epoch_address==current['tls']+0xA8):
            _activate_native_module_tls(self._runtime,self,current)

    def _release_crt_domain(self, tid):
        domain = self._crt_domains[tid]
        from .primary_shared_locale import _invalidate_module_tls
        _invalidate_module_tls(self._runtime,domain=domain)
        domain['services'].__exit__(None, None, None)
        self._runtime._free_allocation(domain['tls'])
        del self._crt_domains[tid]

    @contextmanager
    def crt_callback_context(self, runtime, tid):
        with self._callback_context(runtime, tid, 'crt'):
            yield

    @contextmanager
    def _callback_context(self, runtime, tid, kind):
        if runtime is not self._runtime or tid != threading.get_native_id() or os.getpid() != self._owner[0]:
            raise InputError('CRT callback requires its original native thread and runtime')
        if tid == self._owner[1]:
            from .primary_creator_domain import _close_lease_active
            if _close_lease_active(self):
                yield
                return
            if self._active_owner:
                with self._registrar.operation(token=self._close_token):
                    yield
            else:
                with self._execution:
                    with self._registrar.operation(token=self._close_token):
                        yield
            return
        if tid not in self._crt_domains:
            raise InputError('CRT callback requires its retained original native thread domain')
        with self._execution:
            with self._registrar.operation(token=self._close_token):
                saved = self._save_domain()
                self._restore_domain(self._crt_domains[tid]['state'])
                try:
                    yield
                    domain = self._crt_domains[tid]
                    domain['state'] = self._save_domain()
                    if kind == 'crt':
                        domain['source_fls_completed'] = True
                        for row in self._threads:
                            if row['thread_id'] == tid:
                                row['crt_fls_cleanup'] = 'source_callback_returning'
                    else:
                        domain['holder_fls_completed'] = True
                    crt = runtime.crt_startup_observations.snapshot()
                    other_pending = tid in self._holder_values if kind == 'crt' else tid in crt['pending_thread_ids']
                    from .primary_client_configuration_scope import retain_domain
                    if not other_pending and not retain_domain(self, tid):
                        domain['services'].__exit__(None, None, None)
                        domain['services_closed'] = True
                finally:
                    self._restore_domain(saved)

    @contextmanager
    def _creator_closing_context(self):
        from .primary_creator_domain import _for_service,_safe_restore
        from .primary_host_services import _ExecutionLease
        from .primary_windows_signer import WindowsSigner
        from .primary_shared_locale import _activate_creator_module_tls,_invalidate_module_tls
        import sys
        record=_for_service(self)
        if record is None:raise InputError('creator closing context issuer missing')
        record.validate(lease=False,closing=True)
        f=sys._getframe(1);owner_close=False;release=False
        while f is not None:
            if f.f_code is WindowsSigner.close.__code__ and f.f_locals.get('self') is record.owner:owner_close=True
            if f.f_code is WindowsSigner._release_resources.__code__ and f.f_locals.get('self') is record.owner:release=True
            f=f.f_back
        if not owner_close or not release or getattr(record,'close_lease',None) is not None:
            raise InputError('creator close lease requires original private owner close path')
        saved=self._save_domain();d=record.domain
        try:
            with _ExecutionLease(self._registrar,closing=True) as lease:
                record.close_lease=lease
                if d is not None:
                    d['active']=True
                    values=_safe_restore(self,d['value']['state'])
                    for name,value in values.items():
                        if value is _ABSENT:self._runtime.__dict__.pop(name,None)
                        else:setattr(self._runtime,name,value)
                    if record.ptd is not None and not record.ptd['consumed']:
                        _activate_creator_module_tls(self._runtime,self,d['value'])
                yield
        finally:
            _invalidate_module_tls(self._runtime)
            if d is not None:d['value']['state']=self._save_domain();d['active']=False
            record.close_lease=None
            self._restore_domain(saved)

    @contextmanager
    def _creator_crt_context(self):
        from .primary_creator_domain import _for_service,_register_domain,_associate_ptd
        from .primary_shared_locale import _activate_creator_module_tls,_invalidate_module_tls
        record=_for_service(self)
        if record is None:raise InputError('creator context has no private factory issuer')
        record.validate();runtime=self._runtime;tid=threading.get_native_id()
        if getattr(record,'pending_unpublished',None) is not None:
            raise PrimarySemanticUnavailable('creator retains unresolved partial service effects; retry denied')
        if record.ptd is None or not record.ptd['initialized'] or record.ptd['cleanup'] or record.ptd['consumed']:
            raise PrimarySemanticUnavailable('creator consumer requires complete unconsumed PTD')
        if self._closing or record.domain is not None and record.domain['active']:
            raise InputError('creator public context cannot reenter/close-resume')
        saved=self._save_domain();entered=False;services=None;tls=None;published=False
        try:
            if record.domain is None:
                self._enter_worker_domain()
                services=self._observer_factory();record.service_phase='entering';record.events.append(('services_enter_start',))
                values=services.__enter__();entered=True;record.service_phase='entered';record.events.append(('services_entered',))
                runtime.worker_observations=values['observations'];runtime._filetimes=values['filetime']
                runtime.crt_thread_address=None
                runtime.__dict__.pop('_crt_dispatch_active',None)
                tls=runtime._allocate(0xd78,True);record.events.append(('tls_allocated',tls))
                runtime.tls_base_address= tls;runtime.tls_epoch_address=tls+0xa8;record.events.append(('aliases_published',tls))
                runtime.memory.store(tls+0xa8,0x80000001,4,source='MODEL_creator.initial_TLS_epoch')
                domain={'services':services,'values':values,'tls':tls,'state':self._save_domain(),'owner_state':saved,'services_closed':False,'source_fls_completed':False}
                self._crt_domains[tid]=domain;published=True;record.events.append(('domain_published',tls))
                _register_domain(self,domain);record.events.append(('domain_registered',tls))
            else:
                domain=record.domain['value']
                if record.domain['retired'] or record.domain['failure'] is not None:raise PrimarySemanticUnavailable('creator domain retains failed/retired effects')
                # Alias restoration is authorized only while this genuine context is active.
                for name,value in domain['state'].items():
                    if value is _ABSENT:runtime.__dict__.pop(name,None)
                    else:setattr(runtime,name,value)
            record.domain['active']=True
            runtime._crt_thread()
            _associate_ptd(self);record.events.append(('ptd_borrow_verified',))
            _activate_creator_module_tls(runtime,self,domain);record.events.append(('receipt_published',))
            record.events.append(('consumer_enter',))
            yield
        except BaseException as error:
            if not record.failures:record.failures.append(error)
            if record.domain is not None and record.domain['failure'] is None:record.domain['failure']=error
            raise
        finally:
            _invalidate_module_tls(runtime)
            if record.domain is not None:
                record.domain['value']['state']=self._save_domain();record.domain['active']=False
            elif published:
                record.pending_unpublished=(tls,services,record.failures[0] if record.failures else None)
            elif not entered and getattr(record,'service_phase',None)=='entering':
                record.pending_unpublished=(tls,services,record.failures[0] if record.failures else None)
                record.service_phase='enter_failed_unknown'
            elif entered:
                try:services.__exit__(None,None,None);record.service_phase='exit_confirmed'
                except BaseException as error:
                    record.service_phase='exit_failed'
                    if not record.failures:record.failures.append(error)
                    record.pending_unpublished=(tls,services,error)
                    raise
            try:self._restore_domain(saved)
            except BaseException as error:
                if not record.failures:record.failures.append(error)
                record.pending_unpublished=(tls,services,error)
                raise
            if record.domain is None and not published and tls is not None and getattr(record,'service_phase',None)=='exit_confirmed':
                runtime._free_allocation(tls)

    @contextmanager
    def _native_crt_context(self):
        from .primary_creator_domain import _for_service
        creator=_for_service(self)
        if creator is not None and creator.thread[2]==threading.get_native_id():
            with self._creator_crt_context():yield
            return
        runtime = self._runtime
        tid = threading.get_native_id()
        saved = self._save_domain()
        services = self._observer_factory()
        entered = False
        try:
            self._enter_worker_domain()
            values = services.__enter__()
            entered = True
            runtime.worker_observations = values['observations']
            runtime._filetimes = values['filetime']
            runtime.crt_thread_address = None
            if hasattr(runtime, '_crt_dispatch_active'):
                del runtime._crt_dispatch_active
            tls = runtime._allocate(0xD78, True)
            runtime.tls_base_address, runtime.tls_epoch_address = tls, tls + 0xA8
            runtime.memory.store(tls + 0xA8, 0x80000001, 4, source='native_worker.initial_TLS_epoch')
            self._crt_domains[tid] = {'services': services, 'values': values, 'tls': tls, 'state': self._save_domain(), 'owner_state': saved,
                                      'services_closed': False, 'source_fls_completed': False}
            from .primary_shared_locale import _activate_native_module_tls
            if getattr(runtime,'_shared_locale_source',None) is not None:
                _activate_native_module_tls(runtime,self,self._crt_domains[tid])
            yield
        finally:
            try:
                if tid in self._crt_domains:
                    self._crt_domains[tid]['state'] = self._save_domain()
                    from .primary_client_configuration_scope import retain_domain
                    if not self._pending_fls(tid) and not retain_domain(self, tid):
                        self._release_crt_domain(tid)
                        for row in self._threads:
                            if row['thread_id'] == tid:
                                row['crt_fls_cleanup'] = 'no_thread_value'
                elif entered:
                    services.__exit__(None, None, None)
            finally:
                self._restore_retained_domain(saved, tid)

    @contextmanager
    def _context(self):
        runtime = self._runtime
        if getattr(runtime, 'crt_startup_observations', None) is not None:
            with self._native_crt_context():
                yield
            return
        saved = self._save_domain()
        try:
            self._enter_worker_domain()
            with self._observer_factory() as services:
                runtime.worker_observations = services['observations']
                runtime._filetimes = services['filetime']
                runtime.crt_thread_address = None
                if hasattr(runtime, '_crt_dispatch_active'):
                    del runtime._crt_dispatch_active
                tls = runtime._allocate(0xD78, True)
                runtime.tls_base_address, runtime.tls_epoch_address = tls, tls + 0xA8
                runtime.memory.store(tls + 0xA8, 0x80000001, 4, source='native_worker.initial_TLS_epoch')
                from .primary_thread_dispatch import require_current
                runtime.crt_thread_address = require_current(runtime)
                yield
                from .primary_crt_thread import cleanup
                cleanup(runtime)
                runtime._free_allocation(tls)
        finally:
            self._restore_domain(saved)

    def _entry(self, row, parameter):
        try:
            row['callback_thread_id'] = self._kernel.GetCurrentThreadId()
            self._gate.wait()
            with self._execution:
                with self._registrar.operation():
                    self._execution_tid = threading.get_native_id()
                    row['state'] = 'running'
                    try:
                        domain = self._context()
                        with domain:
                            from .primary_sign_lifecycle import sdk_worker_call
                            with sdk_worker_call(self, row, parameter, domain):
                                vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: 0))
                                result = self._runtime.invoke(vm, 0x1C1BB80, (0,))
                                if type(result) is not int or result != 0:
                                    raise PrimarySemanticUnavailable('SDK bootstrap did not return source DWORD zero')
                    finally:
                        self._execution_tid = None
                    row['source_completed'] = True
                    row['state'] = 'returned'
                    return 0
        except BaseException as error:
            self._remember_failure(error, row)
            row['host_failure'] = type(error).__name__
            row['state'] = 'host_failed'
            return _HOST_FAILURE

    def _notification_entry(self, row, parameter):
        try:
            row['callback_thread_id'] = self._kernel.GetCurrentThreadId()
            self._gate.wait()
            with self._execution:
                with self._registrar.operation():
                    self._execution_tid = threading.get_native_id()
                    row['state'] = 'running'
                    try:
                        if row.get('_kind') == 'client_startup':
                            from .primary_client_configuration_scope import entry_preflight
                            entry_preflight(self, row, parameter)
                        domain = self._context()
                        with domain:
                            argument = int(parameter or 0)
                            row['callback_matches_declared'] = argument == row.get('declared_parameter')
                            client = row.get('_kind') == 'client_startup'
                            if (type(row.get('declared_parameter')) is not int or
                                    row['declared_parameter'] != (0 if client else 3000) or argument != row['declared_parameter']):
                                error = InputError('notification callback parameter differs from its retained source declaration')
                                error.callback_matches_declared = row['callback_matches_declared']
                                raise error
                            from .primary_sign_lifecycle import notification_worker_call
                            from .primary_client_configuration_scope import worker_call as client_call
                            with (client_call(self, row, domain) if client else notification_worker_call(self, row, parameter, domain)):
                                vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: argument))
                                result = self._runtime.invoke(vm, 0x1C22D90 if client else 0x1C29910, (0,))
                                if type(result) is not int or result != 1:
                                    raise PrimarySemanticUnavailable('notification callback did not return source DWORD one')
                    finally:
                        self._execution_tid = None
                    row['source_completed'], row['state'] = True, 'returned'
                    return 1
        except BaseException as error:
            self._remember_failure(error, row)
            row['host_failure'], row['state'] = type(error).__name__, 'host_failed'
            return _HOST_FAILURE

    def _remember_failure(self, error, row):
        from .primary_device_request import _revoke_drain
        for secondary in self._secondary:
            _revoke_drain(secondary)
        if self._failure is None:
            self._failure = error
        row['_host_exception'] = error

    def _failure_for_raise(self):
        errors = [self._failure]
        for row in self._threads[:31]:
            error = row.get('_host_exception')
            if error is not None and not any(error is existing for existing in errors):
                errors.append(error)
        if len(errors) == 1:
            result = self._failure
        else:
            result = BaseExceptionGroup('SDK worker execution failures', errors)
        try:
            result.sdkFailureRowsTruncated = len(self._threads) > 31
        except BaseException:
            pass
        return result

    def pump_device_request(self):
        from .primary_device_request import pump
        return pump(self)

    def validate_device_request_callback(self):
        from .primary_device_request import callback_witness
        return callback_witness(self)

    def validate_device_request_park(self):
        from .primary_device_request import parked_witness
        return parked_witness(self)

    def before_public_operation(self):
        self._check_owner()
        if self._failure is not None:
            raise self._failure_for_raise()
        if self._closed or self._closing or self._draining or self._active_owner:
            raise InputError('SDK execution ownership is unavailable')
        if not self._execution.acquire(blocking=False):
            raise InputError('SDK native worker owns runtime execution')
        self._active_owner = True
        self._execution_tid = threading.get_native_id()

    def after_public_operation(self):
        self._check_owner()
        if not self._active_owner:
            raise InputError('SDK owner operation was not entered')
        self._active_owner = False
        self._execution_tid = None
        self._execution.release()

    def drain(self):
        if self._closing:
            raise InputError('explicit SDK drain is unavailable after close preparation')
        return self._quiesce(consume=True)

    def _quiesce(self, *, consume):
        self._check_owner()
        if self._active_owner:
            raise InputError('SDK owner cannot join while holding execution ownership')
        self._draining = True
        self._gate.set()
        for row in self._secondary:
            row.get('_start_gate', self._gate).set()
        for ordinal, row in enumerate(self._threads):
            if row.get('_kind') in ('secondary', 'client_loop'):
                self._drain_secondary(row, consume=consume)
                continue
            if not row['handle'] or row['handle_closed']:
                continue
            result = self._kernel.WaitForSingleObject(row['handle'], self._timeout_ms)
            error = ctypes.get_last_error()
            if result != 0:
                row['wait_result'], row['wait_error'] = result, error
                if self._wait_failure_details is None:
                    self._wait_failure_details = self._safe_wait_failure(ordinal, row)
                raise PrimarySemanticUnavailable('SDK native worker termination is unproved: ' + str(result))
            row['signaled'] = row['joined'] = True
            code = ctypes.c_uint32()
            if not self._kernel.GetExitCodeThread(row['handle'], ctypes.byref(code)):
                raise PrimarySemanticUnavailable('SDK native worker exit-code observation failed: ' + str(ctypes.get_last_error()))
            row['exit_code'] = code.value
            if not self._kernel.CloseHandle(row['handle']):
                raise PrimarySemanticUnavailable('SDK native thread handle close failed: ' + str(ctypes.get_last_error()))
            row['handle_closed'] = True
            if row.get('_kind') in ('notification', 'client_startup') and not row['source_handle_closed']:
                if row['source_handle'] == row['handle']:
                    row['source_handle_closed'] = True
                elif row['source_handle']:
                    if not self._kernel.CloseHandle(row['source_handle']):
                        raise PrimarySemanticUnavailable('notification retained source handle cleanup failed')
                    row['source_handle_closed'] = True
        crt = getattr(self._runtime, 'crt_startup_observations', None)
        self._retire_joined_domains()
        resident_ids = {row['thread_id'] for row in self._secondary if row['state'] == 'parked_at_BD4B60'}
        from .primary_creator_domain import _closing_ids
        creator_ids=_closing_ids(self) if self._closing else set()
        if crt is not None and (crt.snapshot()['callback_failure'] is not None or
                                crt.snapshot()['callbacks_active'] or set(self._crt_domains) - resident_ids - creator_ids):
            if self._failure is None:
                self._failure = PrimarySemanticUnavailable('native SDK CRT FLS destruction is incomplete; thread domains retained')
            raise self._failure_for_raise()
        if consume and not resident_ids:
            _LIVE_SERVICES.discard(self)
        for row in self._secondary:
            if row['joined'] and not row['_launch'].retired and self._secondary_quiescent(row):
                if row.get('_reference') is not None:
                    row['_launch'].close_host_failure_reference(row['_reference'])
                row['_launch'].retire_host_resources()
                self._registrar.retire_thread(row['thread_id'], self._close_token)
                row['state'] = 'retired'
        self._draining = False
        if consume and self._failure is not None:
            raise self._failure_for_raise()

    def _drain_secondary(self, row, *, consume):
        if row['handle_closed'] or not row['handle']:
            return
        row.get('_start_gate', self._gate).set()
        if not row['_checkpoint'].wait(self._timeout_ms / 1000):
            raise PrimarySemanticUnavailable('secondary has not reached a proved resident checkpoint or native termination')
        if row['state'] == 'parked_at_BD4B60':
            with self._execution:
                with self._registrar.operation(token=self._close_token):
                    empty = self._queues_empty(row['task'])
                    if consume and not empty:
                        self._issue_ticket(row, 'drain')
            if not row['_checkpoint'].wait(self._timeout_ms / 1000):
                raise PrimarySemanticUnavailable('secondary continuation has not returned to its source checkpoint')
        if row['state'] == 'parked_at_BD4B60':
            self._prove_resident(row)
            return
        self._join_secondary(row, report_failure=consume)

    def _prove_resident(self, row):
        code = ctypes.c_uint32()
        if not self._kernel.GetExitCodeThread(row['handle'], ctypes.byref(code)) or code.value != 259:
            raise PrimarySemanticUnavailable('resident secondary native STILL_ACTIVE state is unproved')
        row['native_still_active'] = True

    def _issue_ticket(self, row, kind):
        self._check_owner()
        if not any(candidate is row for candidate in self._secondary) or not row['thread_id']:
            raise InputError('resident ticket requires its registered native worker identity')
        if row['state'] != 'parked_at_BD4B60' or row.get('_ticket') is not None or kind not in ('drain', 'close', 'request'):
            raise InputError('resident continuation requires its parked worker and one explicit ticket')
        if kind == 'close' and not self._closing or kind == 'drain' and self._closing:
            raise InputError('resident continuation kind differs from its service lifecycle')
        if kind == 'request' and (self._closing or self._draining or self._request_pump_row is not row or
                row['task'] != self._runtime.image_base + 0x6751C58 or row.get('_request_ticket') is not None):
            raise InputError('request ticket requires its unique active device pump')
        ticket = self._ticket_sequence + 1, row['thread_id'], kind
        if kind == 'drain' and row['task'] == self._runtime.image_base + 0x6751C58:
            from .primary_device_request import _issue_drain
            row['_device_drain_grant'] = _issue_drain(self, row, ticket)
        self._ticket_sequence += 1
        row['_ticket'] = ticket
        row['state'] = 'continuation_issued'
        row['_checkpoint'].clear()
        row['_resume'].set()

    def _join_secondary(self, row, *, report_failure=True):
        launch = row['_launch']
        launch.join(self._timeout_ms)
        row['signaled'], row['joined'], row['handle_closed'], row['exit_code'] = launch.joined, launch.joined, launch.handle_closed, launch.exit_code
        if launch.failure is not None:
            self._remember_failure(launch.failure, row)
            if report_failure:
                raise self._failure_for_raise()
        row['state'] = 'joined'

    def prepare_close(self):
        from .primary_client_configuration_scope import preflight_close
        preflight_close(self)
        self._check_owner()
        if self._active_owner:
            raise InputError('secondary close preparation requires released owner execution')
        self._closing = True
        self._quiesce(consume=False)
        self._check_teardown_obligations(allow_resident=True,allow_creator=True)

    @contextmanager
    def closing_context(self):
        self._check_owner()
        if not self._closing or self._active_owner:
            raise InputError('secondary closing context requires completed close preparation')
        self._execution.acquire()
        self._active_owner, self._execution_tid = True, threading.get_native_id()
        try:
            from .primary_creator_domain import _for_service
            if _for_service(self) is not None:
                with self._creator_closing_context():yield
            else:yield
        finally:
            self._active_owner, self._execution_tid = False, None
            self._execution.release()

    def stop_checkpoint(self, runtime, task):
        rows = [row for row in self._secondary if row['task'] == task and not row['joined']]
        if not rows:
            return
        self._check_owner()
        if runtime is not self._runtime or not self._closing or not self._active_owner or self._execution_tid != self._owner[1]:
            raise InputError('source task stop requires its current owner closing execution lease')
        if runtime.locks.get(task + 0xE0, 0) or getattr(runtime, '_logger_locks', {}).get(task + 0xE0, False):
            raise PrimarySemanticUnavailable('source task stop checkpoint precedes its genuine mutex unlock')
        if any(runtime.memory.load(task + offset, 1) for offset in (0x20, 0x55, 0x8D)):
            raise PrimarySemanticUnavailable('source task stop checkpoint precedes genuine source flag writes')
        if any(row['state'] != 'parked_at_BD4B60' for row in rows):
            raise PrimarySemanticUnavailable('source task stop requires its retained resident source stack')
        self._queues_empty(task)
        saved = self._save_domain()
        lease = self._registrar.current_lease()
        with lease.suspend():
            self._active_owner, self._execution_tid = False, None
            self._execution.release()
            try:
                for row in rows:
                    self._issue_ticket(row, 'close')
                for row in rows:
                    if not row['_checkpoint'].wait(self._timeout_ms / 1000):
                        raise PrimarySemanticUnavailable('source task shutdown has not returned through its native epilogue')
                    self._join_secondary(row, report_failure=False)
            finally:
                self._execution.acquire()
                self._active_owner, self._execution_tid = True, self._owner[1]
                self._restore_domain(saved)
        self._retire_joined_domains()
        for row in rows:
            if not self._secondary_quiescent(row):
                raise PrimarySemanticUnavailable('source task shutdown retains CRT or holder FLS obligations')
            if row.get('_reference') is not None:
                row['_launch'].close_host_failure_reference(row['_reference'])
            row['_launch'].retire_host_resources()
            self._registrar.retire_thread(row['thread_id'], self._close_token)
            row['state'] = 'retired'

    def _retire_joined_domains(self):
        crt = getattr(self._runtime, 'crt_startup_observations', None)
        if crt is None:
            return
        snapshot = crt.snapshot()
        from .primary_client_configuration_scope import retain_domain
        for tid, domain in tuple(self._crt_domains.items()):
            if retain_domain(self, tid):
                continue
            joined = any(row['thread_id'] == tid and row['joined'] for row in self._threads)
            if (joined and domain['services_closed'] and not self._pending_fls(tid) and
                    not snapshot['callbacks_active'] and snapshot['callback_failure'] is None and
                    self._holder_failure is None and not self._holder_active):
                self._runtime._free_allocation(domain['tls'])
                del self._crt_domains[tid]
                for row in self._threads:
                    if row['thread_id'] == tid:
                        row['crt_fls_cleanup'] = 'completed_after_join'
                        row['holder_fls_cleanup'] = 'completed_after_join' if domain.get('holder_fls_completed') else 'no_thread_value'

    def _check_teardown_obligations(self, *, allow_resident,allow_creator=False):
        resident_ids = {row['thread_id'] for row in self._secondary
                        if allow_resident and row['state'] == 'parked_at_BD4B60'}
        crt = getattr(self._runtime, 'crt_startup_observations', None)
        snapshot = None if crt is None else crt.snapshot()
        from .primary_windows_crt import WindowsCRTObservations
        creator_ids = {self._owner[1]} if (type(crt) is WindowsCRTObservations and
            crt._owner == self._owner and crt._runtime is self._runtime and not crt._closed) else set()
        if allow_creator:
            from .primary_creator_domain import _closing_ids
            creator_ids=_closing_ids(self)
        if (self._active_owner or self._execution.locked() or self._draining or
                any(row['handle'] and row['thread_id'] not in resident_ids and
                    (not row['joined'] or not row['handle_closed']) for row in self._threads) or
                any(row.get('_kind') in ('notification', 'client_startup') and row['source_handle'] and
                    not row['source_handle_closed'] for row in self._threads) or
                any(row['thread_id'] not in resident_ids and not row['_launch'].retired for row in self._secondary) or
                set(self._crt_domains) - resident_ids - (creator_ids if allow_creator else set()) or self._module_pending or
                set(self._holder_values) - resident_ids or self._holder_active or self._holder_failure is not None or
                snapshot is not None and (snapshot['callback_failure'] is not None or snapshot['callbacks_active'] or
                                          set(snapshot['pending_thread_ids']) - resident_ids - creator_ids)):
            raise PrimarySemanticUnavailable('secondary shutdown retains live, failed or unknown source/native obligations')

    def finish_workers(self):
        self._check_owner()
        self._check_teardown_obligations(allow_resident=False,allow_creator=True)

    def finish_close(self):
        self._check_owner()
        self._check_teardown_obligations(allow_resident=False)
        if self._holder_slot is not None:
            result = self._kernel.FlsFree(self._holder_slot)
            error = ctypes.get_last_error()
            self._holder_records.append({'api': 'FlsFree', 'ownership': 'host_after_join', 'result': result, 'error': error})
            if not result:
                raise PrimarySemanticUnavailable('host holder FLS slot release failed: ' + str(error))
            self._holder_slot = None
        if self._worker_bridge is not None:
            self._worker_bridge.close()
        self._closed = True
        _LIVE_SERVICES.discard(self)

    def quiesce_for_close(self):
        self.prepare_close()
        if any(row['state'] == 'parked_at_BD4B60' for row in self._secondary):
            raise PrimarySemanticUnavailable('resident workers require source destructor shutdown before finish_close')
        self.finish_close()

    def _safe_wait_failure(self, ordinal, row):
        roles = ('bootstrap', 'notification', 'secondary')
        states = ('creating', 'create_failed', 'duplicate_failed', 'created_pending',
                  'create_failed_source_cleanup_missing', 'running', 'returned', 'host_failed',
                  'source_terminated', 'parked_at_BD4B60', 'continuation_issued', 'joined', 'retired')
        failures = ('PrimarySemanticUnavailable', 'InputError', 'RuntimeError', 'ValueError',
                    'TypeError', 'AssertionError', 'KeyboardInterrupt', 'SystemExit', 'Exception',
                    'OSError', 'TimeoutError')
        role = row.get('_kind') if row.get('_kind') in ('notification', 'secondary') else row.get('_diagnostic_role')
        state, failure = row.get('state'), row.get('host_failure')
        result = {'ordinal': ordinal, 'role': role if role in roles else 'unknown',
                  'state': state if state in states else 'unknown', 'timeout_ms': self._timeout_ms,
                  'execution_locked': self._execution.locked(), 'owner_active': self._active_owner,
                  'closing': self._closing, 'draining': self._draining,
                  'retained_crt_domains': len(self._crt_domains),
                  'holder_pending_count': len(self._holder_values),
                  'holder_callbacks_active': len(self._holder_active),
                  'pending_source_module_lookups': len(self._module_pending),
                  'host_failure': failure if failure in failures else None if failure is None else 'unknown',
                  'wait_error_status': 'diagnostic-only-stale-or-undefined-for-timeout' if row.get('wait_result') == 258 else 'diagnostic-only'}
        for name in ('source_completed', 'joined', 'signaled', 'handle_closed', 'source_handle_closed'):
            value = row.get(name)
            result[name] = value if type(value) is bool else None
        for name in ('wait_result', 'wait_error'):
            value = row.get(name)
            result[name] = value if type(value) is int and 0 <= value < 1 << 32 else None
        return tuple(result.items())

    def snapshot(self):
        self._check_owner()
        return {'closed': self._closed, 'owner_active': self._active_owner, 'draining': self._draining,
                'threads': [dict({key: value for key, value in row.items() if not key.startswith('_')},
                                 ordinal=index, role=row.get('_kind') if row.get('_kind') in ('notification', 'secondary') else 'bootstrap' if row.get('_diagnostic_role') == 'bootstrap' else 'unknown')
                            for index, row in enumerate(self._threads)],
                'timeout_ms': self._timeout_ms, 'execution_locked': self._execution.locked(),
                'wait_failure': None if self._wait_failure_details is None else dict(self._wait_failure_details),
                'failure_type': None if self._failure is None else type(self._failure).__name__,
                'retained_crt_domains': len(self._crt_domains), 'closing': self._closing,
                'holder_fls': {'slot_allocated': self._holder_slot is not None,
                    'pending_thread_ids': tuple(sorted(set(self._holder_values) | self._holder_active)),
                    'callbacks_active': len(self._holder_active),
                    'failure_type': None if self._holder_failure is None else type(self._holder_failure).__name__,
                    'records': tuple(self._holder_records)},
                'pending_source_module_lookups': len(self._module_pending),
                'condition_wakes': tuple(getattr(self, '_wake_records', ())),
                'worker_bridge': None if self._worker_bridge is None else {'close_status': self._worker_bridge.close_status}}
