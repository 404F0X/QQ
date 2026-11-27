"""Injected Windows APIs/Python threads only; never Native/network evidence."""
import base64
import ctypes as C
import hashlib
import json
import threading
from types import SimpleNamespace as NS

import pytest
from test_primary_qimei_cold_material_job import ActualFactoryModel, ModelAPIs, Carrier
from test_primary_windows_qimei_executor import Bridge
from test_primary_qimei_ipc import ABI
from qq_nt_replica.primary_qimei_ipc import QimeiIPCPool, IPCError, _crypt
from qq_nt_replica.primary_qimei_module_backend import OwnQimeiModuleBackend, QimeiApplicationInputs
from qq_nt_replica.primary_qimei_config_business import conditional_kind3, retained_kind4
from qq_nt_replica.primary_qimei_getter import QimeiGetterOwner
from qq_nt_replica.primary_qimei_context import QimeiSelectorState
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary, QimeiRequestState
from qq_nt_replica.primary_qimei_records import RecordObservations
from qq_nt_replica.primary_qimei_reply import ReplySlot
from qq_nt_replica.primary_qimei_transport_random import QimeiTransportRandom
from qq_nt_replica.primary_qimei_extra_sources import QimeiExtraSources
from qq_nt_replica.primary_qimei_request_sources import QimeiRequestSources
from qq_nt_replica.primary_qimei_system_sources import QimeiSystemSources
from qq_nt_replica.primary_qimei_cache import _cbc
from qq_nt_replica.primary_qimei_settings import QimeiSettings
from qq_nt_replica.primary_windows_qimei_schedule import OwnQimeiSchedule
from qq_nt_replica.primary_windows_signer_setup import business_metadata


class APIs:
    def __init__(self, opens=()):
        self.opens = iter(opens)
        self.calls = []
        self.callbacks = []
        self.delete_error = 997
        self.close_queue_error = 0
        self.create = 55
    def thunk(self, callback):
        return callback
    def close(self):
        self.closed = True
    def image_size(self):
        return 0xffffffff
    def timestamp_ms(self):
        return 12345
    def call(self, name, result, types, *args):
        self.calls.append((name, args))
        if name == 'OpenMutexA':
            return next(self.opens, 0), 2
        if name == 'CreateMutexA':
            return self.create, 5 if not self.create else 0
        if name == 'CreateTimerQueue':
            return 77, 0
        if name == 'CreateTimerQueueTimer':
            C.cast(args[0], C.POINTER(C.c_void_p))[0] = 90 + len(self.callbacks)
            self.callbacks.append(args[2])
        if name == 'DeleteTimerQueueTimer':
            return int(not self.delete_error), self.delete_error
        if name == 'DeleteTimerQueueEx':
            return int(not self.close_queue_error), self.close_queue_error
        return 1, 0


def schedule(api):
    runtime, epoch = object(), object()
    return OwnQimeiSchedule(runtime, epoch, lambda r: epoch, namespace=b'a' * 32, api=api)


def test_coordination_dynamic_and_open_null_create_failure():
    api = APIs([0]); api.create = 0
    s = schedule(api)
    assert s.coordination(b'app') is True
    assert s.coordination(b'other') is True
    assert len([c for c in api.calls if c[0] == 'OpenMutexA']) == 1
    assert s.diagnostics[-1] == ('CreateMutexA', False, 5)
    api = APIs([44, 0]); s = schedule(api)
    assert s.coordination(b'app') is False
    assert s.dynamic50000(b'app') is False
    assert s.dynamic50000(b'app') is True
    assert [c[0] for c in api.calls] == ['OpenMutexA', 'CloseHandle', 'OpenMutexA', 'CreateMutexA']


def test_instance_names_wrap_first_appid_and_cache():
    api = APIs([44, 0]); s = schedule(api)
    assert s.instance_count(b'app') == 2
    names = [c[1][-1] for c in api.calls if c[0] == 'OpenMutexA']
    for index, name in enumerate(names, 1):
        assert name.endswith(hashlib.md5(b'x5sg8bj0app' + str((0xffffffff + index) & 0xffffffff).encode()).hexdigest().upper().encode())
        assert name.startswith(b'Local\\QQReplicaOwnInstance_')
    assert s.instance_count(b'second') == 2
    assert len([c for c in api.calls if c[0] == 'OpenMutexA']) == 2


def test_timer_pending_close_failure_and_backing_retention():
    api = APIs(); s = schedule(api); app = object(); seen = []
    record = s.register(app, 60000, lambda r: (seen.append(r['app']), s.unregister(r)))
    api.callbacks[0](None, 1)
    assert seen == [app] and record['pending']
    assert s.timers[0]['thunk'] is api.callbacks[0]
    assert api.calls[1][1][-3:] == (60000, 60000, 0)
    api.close_queue_error = 5
    with pytest.raises(OSError): s.close_queue()
    assert not s.quiescent and s.timers and s.queue
    api.callbacks[0](None, 1)
    assert len(seen) == 1
    api.close_queue_error = 0; s.close_queue(); s.close_mutexes()
    assert s.quiescent and not s.timers


def test_timer_exception_never_crosses_abi_and_self_wait_rejected():
    api = APIs(); s = schedule(api)
    s.register(object(), 86410000, lambda r: s.close_queue())
    api.callbacks[0](None, 1)
    assert len(s.errors) == 1 and isinstance(s.errors[0], QimeiRequestBoundary)
    assert not s.sealed
    s.close_queue(); s.close_mutexes()


def test_counter_once_encrypted_preserves_qimei_and_failure():
    runtime, epoch = object(), object(); abi = ABI()
    p = QimeiIPCPool(runtime, epoch, lambda r: epoch, abi)
    p._initialize_counter(b'default')
    raw = b'q' * 36 + b'\0' + (7).to_bytes(4, 'little')
    C.memmove(abi.view, _crypt(raw), 41)
    assert p._usage_count() == 8 and p._usage_count() == 8
    assert _crypt(abi.view.raw[:41]) == raw[:37] + (8).to_bytes(4, 'little')
    assert not [c for c in abi.calls if c[0] == 'SetEvent']
    p.dispose_terminal()
    p = QimeiIPCPool(runtime, epoch, lambda r: epoch, ABI()); p._initialize_counter(b'default')
    def fail(*a): raise OSError('write failure')
    p.backend.write_view = fail
    with pytest.raises(OSError): p._usage_count()
    assert not p._counter_once
    p.dispose_terminal()


def test_kind3_exact_slots_producers_on_skip_and_no_install(monkeypatch):
    events = []; cells = []; sends = []
    monkeypatch.setattr(QimeiRequestState, 'encode', lambda self, **k: cells.append(tuple(self.slots)) or b'payload')
    settings = NS(flag=lambda *a, **k: 2)
    dispatch = NS(dispatch=lambda *a, **k: sends.append(a))
    args = dict(settings_dependencies={}, usage_count=lambda: events.append('usage') or 0xffffffff,
                instance_count=lambda owner: events.append('instance') or 2,
                selector=NS(select=lambda o: b'123456'), selector_observations=None,
                request_sources=NS(identity_3fafa=lambda: events.append('identity') or b'A' * 32),
                dispatch=dispatch, convert_ansi=lambda b: b)
    assert not conditional_kind3(b'app', settings, **args)
    assert events == ['usage', 'instance'] and not sends
    args['instance_count'] = lambda owner: 3
    assert conditional_kind3(b'app', settings, **args)
    values = [slot.data for slot in cells[0]]
    assert len(values) == 16
    assert values[:7] == [b'ig', b'313233343536', None, None, b'A' * 32, b'-1', b'3']
    assert values[7:] == [None] * 9
    assert sends[0][1] == 3 and sends[0][3](b'anything', 8, 503, 9, None) is True


class TestBridge(Bridge):
    __test__ = False
    def close(self):
        assert not self._launches
        self.closed = True


def module_fixture(opens=(0,), block=False, io_fail=False):
    case = ActualFactoryModel('test_real_factory_and_material_produce_through_retained_reply')
    pipeline, binding, args, obs = case.real_factory()
    binding.settings.record[0x31:0x35] = (1).to_bytes(4, 'little')
    binding.settings.record[0x61:0x65] = (1).to_bytes(4, 'little')
    runtime, epoch = object(), object(); api = APIs(opens)
    sched = OwnQimeiSchedule(runtime, epoch, lambda r: epoch, namespace=b'b' * 32, api=api)
    pool = QimeiIPCPool(runtime, epoch, lambda r: epoch, ABI()); bridge = TestBridge()
    entered, leave = threading.Event(), threading.Event(); ios = []
    shared_selector = QimeiSelectorState(selected6=b'123456')
    class IO:
        debt = []
        def __init__(self, app):
            self.thread = threading.get_native_id(); self.closed = False
            self.startup = args['startup']; self.settings = binding.settings
            self.settings_dependencies = pipeline.request_producer.settings_dependencies
            self.selector = shared_selector; self.selector_observations = None
            self.convert_ansi = lambda b: b; self.config_sources = NS(_check=lambda: None, clock=lambda: 0)
            self.settings_writer = NS(save=lambda p,r: 0)
            self.request_observations = obs
            self.write_main = lambda store: self.persist(store)
            self.system = pipeline.request_producer.system
            self.extras = pipeline.request_producer.extras
            self.extension = pipeline.request_producer.extensions
            self.adapter = pipeline.material_producer.adapter
            self.classifier_observations = None
            self.beacon_backend = pipeline.material_producer.globals.beacon.backend
            self.beacon_producer = None
            self.random = QimeiTransportRandom(obs); self.clock = lambda: 1000000
            self.globals_api = QimeiExtraSources(obs)._api
            self.persist = args['persist']
            self.carrier = Carrier(self.perform)
            self.bad_code_pointer = lambda p: p == 999
            self.invoke_notification = lambda p, b: None
            ios.append(self)
        def perform(self, http):
            assert self.thread == threading.get_native_id()
            entered.set()
            if block: assert leave.wait(3)
            from qq_nt_replica.primary_qimei_dispatch import CarrierOutcome
            record = next(iter(args['dispatch'].state.pending.values()))
            payload = b'\x0a\x24' + b'r' * 36 + b'\x12\x01x\x1a\x01y'
            request = record.prepared.transport_request
            padding = bytes([16 - len(payload) % 16]) * (16 - len(payload) % 16)
            cipher = _cbc(payload + padding, request.key, request.iv)
            return CarrierOutcome(json.dumps({'code': '0', 'data': base64.b64encode(cipher).decode()}).encode(), 0)
        def close(self):
            assert self.thread == threading.get_native_id()
            if io_fail and self.thread != threading.main_thread().native_id: raise OSError('cleanup failure')
            self.closed = True
    creator_io = IO(None)
    module = OwnQimeiModuleBackend(runtime, epoch, lambda r: epoch,
        startup=args['startup'], sdk=pipeline.request_producer.sdk_contexts,
        settings=binding.settings, pipeline=pipeline, dispatch=args['dispatch'],
        ipc=pool, bridge=bridge, schedule=sched, creator_io=creator_io,
        worker_io_factory=IO, default_counter_owner=b'default')
    inputs = QimeiApplicationInputs(binding.owner, b'', b'config', b'', 1, RecordObservations({}))
    return module, inputs, api, ios, entered, leave


def test_a2_no_material_barrier_same_store_getter_first_metadata():
    m, inputs, api, ios, entered, leave = module_fixture(block=True)
    getter = QimeiGetterOwner()
    try:
        assert getter.initialize(m, inputs) == 0
        assert getter.status == 'INITIALIZED' and entered.wait(2)
        assert not m.tasks[-1].done.is_set()
        assert [t.business for t in m.tasks] == ['6B01C', '6A923']
        leave.set(); assert m.tasks[-1].done.wait(2)
        assert not any(t.errors for t in m.tasks)
        app = m.applications[inputs.appid]
        assert app.startup is m.pipeline.material_producer.startup is m.startup
        assert app.settings is m.settings is m.pipeline.request_producer.settings
        assert getter.get() == b'r' * 36
        metadata = business_metadata(uin=1, machine_id=b'own', qimei_owner=getter)
        assert metadata.field_08 == b'r' * 36
        m.startup.main.set(1, b's\0')
        assert getter.get() == b'r' * 36
        assert m.initialize(inputs) == 0 and m.applications[inputs.appid] is app
        assert len(m.tasks) == 2
        assert all(io.closed for io in ios[1:])
        assert all(io.thread != ios[0].thread for io in ios[1:])
    finally:
        leave.set(); m.close()
    assert m.closed and m.bridge.closed


def test_false_branch_qualified_consume_and_callback_enqueue():
    m, inputs, api, ios, entered, leave = module_fixture(opens=(44, 0))
    try:
        assert m.initialize(inputs) == 0
        assert m.tasks[0].business == '6B0CE' and m.tasks[0].done.wait(2)
        assert not m.tasks[0].errors and m.tasks[0].result == 1
        calls = [c[0] for c in m.ipc.backend.calls]
        assert 'WaitForSingleObject' in calls and 'ResetEvent' in calls
        foreign = []
        def callback():
            with pytest.raises(IPCError): m.executor.submit(inputs.appid, lambda o: None, lambda t: None, lambda t: None)
            api.callbacks[0](None, 1)
            foreign.append(True)
        thread = threading.Thread(target=callback); thread.start(); thread.join(3)
        assert foreign == [True] and not m.schedule.errors
        assert [t.business for t in m.tasks] == ['6B0CE', '6B01C', '6A923']
        assert m.applications[inputs.appid].timestamp == 12345
        assert m.schedule.timers[0]['pending']
    finally:
        m.close()


def test_notification_early_stop_tail_and_exception_does_not_clear():
    m, inputs, api, ios, entered, leave = module_fixture()
    try:
        m.initialize(inputs); assert m.tasks[-1].done.wait(2)
        app = m.applications[inputs.appid]; io = ios[0]; calls = []
        io.invoke_notification = lambda p, b: calls.append(p)
        app.callbacks[:] = [1, None, 3, None, None, None, None, None]
        app.buffer[:] = b'z' * 70
        m._notify(app, io)
        assert calls == [1] and app.callbacks[0] is None and app.callbacks[2] == 3
        assert app.buffer[36] == 0 and app.buffer[38] == 0 and app.buffer[39:] == b'z' * 31
        app.callbacks[:] = [999, 2, None, None, None, None, None, None]
        m._notify(app, io); assert app.callbacks[0] == 999 and calls == [1]
        app.callbacks[0] = 1
        def fail(p, b): raise RuntimeError('callback')
        io.invoke_notification = fail
        with pytest.raises(RuntimeError): m._notify(app, io)
        assert app.callbacks[0] == 1
        m.startup.identity1.set(1, b'')
        with pytest.raises(QimeiRequestBoundary, match='AUX'): m.query(inputs.appid, bytearray(70))
    finally:
        m.close()


def test_worker_cleanup_exception_retains_backing_debt():
    m, inputs, api, ios, entered, leave = module_fixture(io_fail=True)
    m.initialize(inputs)
    assert m.tasks[-1].done.wait(2)
    assert m.io_debt and m.tasks[-1].errors
    with pytest.raises(QimeiRequestBoundary, match='cleanup debt'): m.close()
    assert m.applications and not m.closed and not m.ipc.terminal
    # Fake IO has no real resources; retain diagnostic ownership as required.


def test_kind4_exact_payload_retained_reply_same_settings(monkeypatch):
    cells, sends, saves = [], [], []
    monkeypatch.setattr(QimeiRequestState, 'encode', lambda self, **k: cells.append(tuple(self.slots)) or b'payload')
    settings = QimeiSettings(); settings.initialize_owned_path(path=b'own'); settings.loaded = 1
    settings.record[17:21] = b'old\0'
    settings.record[140:147] = b'tailXYZ'
    sources = NS(_check=lambda: None, clock=lambda: 86400,
                 wow64=lambda: 1, os_classification=lambda: 19, architecture=lambda: 3)
    args = dict(settings_dependencies={}, sources=sources,
                writer=NS(save=lambda path, record: saves.append((path, record)) or 2),
                dispatch=NS(dispatch=lambda *a, **k: sends.append(a)), convert_ansi=lambda b: b)
    assert retained_kind4(b'app', settings, **args)
    assert len(cells[0]) == 5 and cells[0][0].data == b'old'
    assert [int.from_bytes(s.data, 'little') for s in cells[0][1:]] == [1, 2, 19, 3]
    complete = sends[0][3]
    assert not complete(b'\x0a\x03cfg\x10\x04', 0, 503, 0, settings)
    assert not saves
    assert complete(b'\x0a\x03cfg\x10\x04', 0, 200, 0, settings)
    assert sends[0][1] == 4 and sends[0][4] is settings
    assert settings.record[17:21] == b'cfg\0' and settings.flag(0) == 4
    assert settings.record[140:147] == b'tailXYZ' and settings.dirty == 0
    assert len(saves) == 1 and int.from_bytes(settings.record[9:17], 'little') == 86400
    assert not retained_kind4(b'app', settings, **args)


def test_ordinary_first_start_executes_original_store_reader():
    from dataclasses import replace
    from test_qimei_startup_binding import Startup, BASE
    model = Startup(); model.setUp()
    m, inputs, api, ios, entered, leave = module_fixture()
    m.startup.once = 0
    m.startup.main.records.clear(); m.startup.identity1.records.clear()
    main = model.codec.encode_records(b'm' * 16, bytes(37), context=b'').value
    observations = model.obs(main=main)
    observations.values[('base-path',)] = BASE
    inputs = replace(inputs, startup_observations=observations)
    try:
        assert m.initialize(inputs) == 0
        assert m.startup.once == 1 and m.startup.main.get(0) == b'm' * 16
        assert m.startup.main.path == BASE and m.startup.identity1.path == BASE
        assert m.tasks[-1].done.wait(2) and not any(t.errors for t in m.tasks)
        assert m.startup.main.get(1) == b'r' * 36 + b'\0'
    finally:
        m.close()


def test_a2_failure_does_not_publish_getter_ready():
    m, inputs, api, ios, entered, leave = module_fixture()
    m.startup.once = 0
    getter = QimeiGetterOwner()
    try:
        with pytest.raises(Exception): getter.initialize(m, inputs)
        assert getter.status == 'UNINITIALIZED' and getter.get() == b''
        assert not m.applications[inputs.appid].initialized and m.executor is None
    finally:
        m.close()


def test_empty_getter_requeries_and_cstring_truncates_then_caches():
    m, inputs, api, ios, entered, leave = module_fixture(opens=(44,))
    getter = QimeiGetterOwner()
    try:
        getter.initialize(m, inputs); assert m.tasks[0].done.wait(2)
        m.startup.identity1.set(1, b'aux')  # Explicit controlled supported domain.
        assert getter.get() == b''
        m.startup.main.set(1, b'abc\0trailing')
        assert getter.get() == b'abc'
        m.startup.main.set(1, b'other')
        assert getter.get() == b'abc'
    finally:
        m.close()


def test_only_accepted_notification_task_can_use_counter_consume():
    m, inputs, api, ios, entered, leave = module_fixture(opens=(44,))
    try:
        m.initialize(inputs); assert m.tasks[0].done.wait(2)
        def wrong(owner):
            with pytest.raises(IPCError): m.ipc.consume(owner)
            with pytest.raises(IPCError): m.ipc._usage_count()
        task = m.executor.submit(inputs.appid, wrong, lambda t: None, lambda t: None)
        assert task.done.wait(2) and not task.errors
        m.startup.main.set(1, b'q' * 36 + b'\0'); m.startup.identity1.set(1, b'aux')
        # Both producers execute even when the comparison skips the send.
        m.settings.record[0x265:0x269] = (2).to_bytes(4, 'little')
        task = m._submit(m.applications[inputs.appid], '6B0CE')
        assert task.done.wait(2) and not task.errors
        assert m.ipc._counter_once and m.schedule._instance == 1
    finally:
        m.close()


def test_worker_binds_existing_settings_without_creator_guard_bypass(tmp_path):
    from test_primary_qimei_owned_settings import factory
    from qq_nt_replica.primary_windows_qimei_owned_storage import bind_owned_qimei_settings
    settings, creator_dependencies, codec = factory(tmp_path)
    runtime, epoch = object(), object()
    result = []
    def worker():
        dependencies = bind_owned_qimei_settings(settings, runtime, epoch, lambda r: epoch,
            permit=lambda r,e: True, root=tmp_path/'own', owner=b'owner', codec=codec,
            context_producer=creator_dependencies['context_producer'],
            context_observations=creator_dependencies['observations'])
        assert settings.flag(9, **dependencies) == 1
        with pytest.raises(QimeiRequestBoundary): creator_dependencies['read_file'](settings.path)
        result.append(dependencies)
    thread = threading.Thread(target=worker); thread.start(); thread.join(2)
    assert result and not thread.is_alive()
    assert settings.flag(9, **creator_dependencies) == 1
    with pytest.raises(QimeiRequestBoundary): result[0]['read_file'](settings.path)


def test_io_factory_partial_failure_closes_on_constructing_thread(monkeypatch):
    from qq_nt_replica.primary_windows_qimei_module_io import WindowsQimeiModuleIOFactory, WindowsQimeiModuleIO
    factory = object.__new__(WindowsQimeiModuleIOFactory)
    factory.debt = []
    runtime, epoch = object(), object()
    factory.runtime, factory.epoch, factory.current_epoch = runtime, epoch, lambda r: epoch
    factory.permit = lambda r,e: True
    order = []
    class Resource:
        def __init__(self, number): self.number = number; self.thread = threading.get_native_id()
        def close(self):
            assert self.thread == threading.get_native_id()
            order.append(self.number)
    def fail(io, app):
        io._own(Resource(1)); io._own(Resource(2))
        raise ValueError('construct failure')
    monkeypatch.setattr(WindowsQimeiModuleIO, 'initialize', fail)
    with pytest.raises(ValueError): factory(object())
    assert order == [2, 1] and not factory.debt


def test_real_windows_factory_defers_first_metadata_until_construction_hook(monkeypatch):
    import ast
    from pathlib import Path
    import qq_nt_replica.primary_windows_signer as windows
    from qq_nt_replica.primary_windows_signer_setup import IndependentWindowsSetup, BUSINESS_QUA
    from qq_nt_replica.errors import InputError
    m, inputs, api, ios, entered, leave = module_fixture()
    getter = QimeiGetterOwner(); events = []
    config = dict(uin=1, machine_id=b'own', qimei_owner=getter)
    class BeforeConstruction(Exception): pass
    def paths(*args):
        assert getter.status == 'UNINITIALIZED' and not events
        raise BeforeConstruction()
    monkeypatch.setattr(windows, '_validated_paths', paths)
    original = QimeiGetterOwner.get
    def get(owner):
        events.append('metadata-query')
        return original(owner)
    monkeypatch.setattr(QimeiGetterOwner, 'get', get)
    with pytest.raises(BeforeConstruction):
        windows.open_windows_signer(bridge_path='fake', storage_root='fake', host_profile_string=BUSINESS_QUA,
            primary_backend='direct', worker_bridge_path='fake', own_business_config=config)
    assert not events
    # Execute the actual post-construction factory statements against an explicit
    # fake runtime. No Native constructor/SDK/provider implementation is invoked.
    owner = NS(signer=NS(runtime=m.runtime), _independent_setup=None)
    def hook(actual):
        assert actual is owner
        events.append('hook')
        getter.initialize(m, inputs)
        assert m.tasks[-1].done.wait(2) and not any(t.errors for t in m.tasks)
    def prepare(setup, metadata):
        assert metadata.field_08 == b'r' * 36
        events.append('first-provider-init')
    monkeypatch.setattr(IndependentWindowsSetup, '_prepare_provider', prepare)
    tree = ast.parse(Path(windows.__file__).read_text())
    factory = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'open_windows_signer')
    body = next(n for n in factory.body if isinstance(n, ast.Try)).body
    start = next(i for i,n in enumerate(body) if isinstance(n,ast.If) and ast.unparse(n.test) == 'construction_setup is not None')
    namespace = dict(__name__=windows.__name__, __package__=windows.__package__, owner=owner,
        construction_setup=hook, outer_login_config=None, business=True, own_business_config=config,
        independent_provider_metadata=None)
    try:
        exec(compile(ast.fix_missing_locations(ast.Module(body=body[start:-1], type_ignores=[])), windows.__file__, 'exec'), namespace)
        assert events == ['hook', 'metadata-query', 'first-provider-init']
        assert owner._own_business_initialized
        wrong = NS(signer=NS(runtime=object()))
        with pytest.raises(InputError, match='active runtime epoch'):
            IndependentWindowsSetup(wrong).prepare_business(**config)
        assert events == ['hook', 'metadata-query', 'first-provider-init']
    finally:
        m.close()


def test_overlapping_timer_callbacks_only_enqueue_then_shutdown_drains():
    m, inputs, api, ios, entered, leave = module_fixture(block=True)
    try:
        m.initialize(inputs); assert entered.wait(2)
        gate = threading.Barrier(3)
        def callback():
            gate.wait(2); api.callbacks[0](None, 1)
        threads = [threading.Thread(target=callback) for _ in range(2)]
        for thread in threads: thread.start()
        gate.wait(2)
        for thread in threads: thread.join(2)
        assert all(not thread.is_alive() for thread in threads)
        assert len(m.tasks) == 6 and not m.schedule.errors
        assert [t.business for t in m.tasks] == ['6B01C', '6A923'] * 3
    finally:
        leave.set(); m.close()
    assert all(t.done.is_set() and not t.errors for t in m.tasks)


def test_module_partial_worker_start_retains_executor_for_close():
    m, inputs, api, ios, entered, leave = module_fixture()
    m.bridge = TestBridge(fail_at=3)
    with pytest.raises(ExceptionGroup): m.initialize(inputs)
    assert m.executor is m.ipc._executor and m.executor is not None
    assert not m.applications[inputs.appid].initialized
    m.close()
    assert m.closed and m.bridge.closed
