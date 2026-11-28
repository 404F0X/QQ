"""Finite fresh OwnHost a2 -> same-store b/getter composition.

This owns application and callback backing for an epoch. It does not model
Original destruction or cross-restart restoration, and is not full SIGN.
"""
import ctypes as C
import threading
from dataclasses import dataclass, field

from .primary_qimei_application_binding import ApplicationBinding
from .primary_qimei_config_business import conditional_kind3, retained_kind4
from .primary_qimei_records import StartupState, RecordObservations
from .primary_qimei_reply import QimeiReplyState
from .primary_qimei_request import QimeiRequestBoundary
from .primary_qimei_request_state import QimeiModuleRequestState
from .primary_qimei_status_business import conditional_kind7, status_value
from .primary_qimei_report_business import conditional_kind13
from .primary_qimei_sdk import QimeiSdkContexts
from .primary_windows_qimei_executor import create_own_qimei_executor


@dataclass(frozen=True)
class QimeiApplicationInputs:
    appid: bytes
    first: bytes
    second: bytes
    third: bytes
    option: int
    startup_observations: RecordObservations


@dataclass(eq=False)
class CanonicalQimeiApplication:
    appid: bytes
    settings: object
    context: object
    startup: StartupState
    callbacks: list = field(default_factory=lambda: [None] * 8)
    buffer: bytearray = field(default_factory=lambda: bytearray(70))
    timestamp: int = 0
    d8: int = 0
    lock: object = field(default_factory=threading.RLock, repr=False)
    initialized: bool = False


class QimeiDefaultProvider:
    """619C2 finite owner; shared publication owns a separate control reference."""
    def __init__(self, dispatch):
        self.strings = [b''] * 5
        self.a8 = 0
        self.lock = threading.RLock()
        self.dispatcher = dispatch
        self.references = 1

    def retain(self):
        with self.lock:
            self.references += 1

    def release(self):
        with self.lock:
            if self.references <= 0:
                raise QimeiRequestBoundary('provider reference underflow')
            self.references -= 1

    def dispatch(self, *args, **kwargs):
        return self.dispatcher.dispatch(*args, **kwargs)


class OwnQimeiModuleBackend:
    def __init__(self, runtime, epoch, current_epoch, *, startup, sdk, settings,
                 pipeline, dispatch, ipc, bridge, schedule, creator_io,
                 worker_io_factory, default_counter_owner):
        if (not isinstance(startup, StartupState) or not isinstance(sdk, QimeiSdkContexts)
                or ipc.runtime is not runtime or ipc.epoch is not epoch
                or schedule.runtime is not runtime or schedule.epoch is not epoch
                or pipeline.material_producer is not dispatch.material_producer
                or pipeline.material_producer.startup is not startup
                or pipeline.material_producer.sdk is not sdk
                or pipeline.material_producer.settings is not settings
                or pipeline.request_producer.settings is not settings
                or pipeline.request_producer.sdk_contexts is not sdk
                or dispatch.transport is not pipeline.transport
                or dispatch.configuration is not pipeline.configuration
                or dispatch.envelope is not pipeline.envelope
                or not callable(worker_io_factory) or not isinstance(getattr(worker_io_factory, 'debt', None), list)):
            raise QimeiRequestBoundary('one live epoch and same canonical module state required')
        self.runtime, self.epoch, self.current_epoch = runtime, epoch, current_epoch
        self.startup, self.sdk, self.settings = startup, sdk, settings
        self.pipeline, self.dispatch, self.ipc, self.bridge = pipeline, dispatch, ipc, bridge
        self.schedule, self.creator_io, self.worker_io_factory = schedule, creator_io, worker_io_factory
        self.default_counter_owner = default_counter_owner
        self.creator = threading.get_native_id()
        self.lock = threading.RLock()
        self.applications = {}
        self.executor = None
        self.provider = None
        self.provider_pair = None
        self.provider_once = False
        self.sealed = False
        self.closed = False
        self.tasks = []
        self.io_debt = []
        self._callback = threading.local()
        self.request_state = QimeiModuleRequestState(0)

    def _check(self, *, creator=False):
        if (self.closed or self.current_epoch(self.runtime) is not self.epoch
                or creator and threading.get_native_id() != self.creator):
            raise QimeiRequestBoundary('module epoch/thread unavailable')

    def _submission_allowed(self):
        self._check()
        return not self.sealed and (threading.get_native_id() == self.creator or
                                   getattr(self._callback, 'application', None) in self.applications.values())

    def _publish_provider(self):
        with self.lock:
            if self.provider_once:
                return
            provider = QimeiDefaultProvider(self.dispatch)
            provider.retain()
            old = self.provider_pair
            self.provider_pair = (provider, provider)
            self.provider = provider
            if old is not None:
                old[1].release()
            self.provider_once = True

    def initialize(self, inputs):
        self._check(creator=True)
        if (not isinstance(inputs, QimeiApplicationInputs) or type(inputs.appid) is not bytes
                or not inputs.appid or b'\0' in inputs.appid
                or type(inputs.startup_observations) is not RecordObservations
                or inputs.appid != self.pipeline.request_producer.owner):
            raise QimeiRequestBoundary('typed fresh application and original startup inputs required')
        if any(key and key[0] in ('decode', 'parse') for key in inputs.startup_observations.values):
            raise QimeiRequestBoundary('ordinary startup requires raw ciphertext and the original parser')
        with self.lock:
            if self.sealed:
                raise QimeiRequestBoundary('module admission sealed')
            context = self.sdk.get(inputs.appid)
            app = self.applications.get(inputs.appid)
            if app is None:
                app = CanonicalQimeiApplication(inputs.appid, self.settings, context, self.startup)
                self.applications[inputs.appid] = app
            elif app.initialized:
                return 0
            if not self.settings.initialized:
                raise QimeiRequestBoundary('Own settings location must be bound before a2')
            if inputs.appid not in self.ipc.states:
                self.ipc.initialize(inputs.appid)
            if self.ipc._counter_owner is None:
                self.ipc._initialize_counter(self.default_counter_owner)
            context.configure(inputs.first, inputs.second, inputs.third, inputs.option)
            # Own location observations are supplied explicitly. Never invoke
            # Registry20 binding or Original Shell data paths in this host.
            self.startup.start(inputs.startup_observations, selector=self.creator_io.selector,
                               selector_observations=self.creator_io.selector_observations)
            self.pipeline.material_producer.globals.refresh_config(io=self.creator_io)
            self._publish_provider()
            if self.executor is None:
                try:
                    self.executor = create_own_qimei_executor(self.ipc, inputs.appid, self.bridge)
                finally:
                    # Partial native launch debt remains owned by the pool even
                    # when the constructor raises before assignment completes.
                    if self.executor is None:
                        self.executor = self.ipc._executor
                self.executor._module = self
            app.timestamp = self.schedule.timestamp_ms()
            if self.schedule.coordination(inputs.appid):
                self.schedule.register(app, 86410000, lambda record: self._timer(app, record, False))
                self._submit_pair(app)
            else:
                self.schedule.register(app, 60000, lambda record: self._timer(app, record, True))
                self._submit(app, '6B0CE')
            app.initialized = True
            return 0  # Normal ordinary calls completed; no material wait.

    def _timer(self, app, record, polling):
        with self.lock:
            self._check()
            if not self.schedule.callback_admitted(record, app):
                raise QimeiRequestBoundary('timer callback lacks current admitted record')
            if self.sealed:
                return
            self._callback.application = app
            try:
                if polling and self.schedule.dynamic50000(app.appid):
                    return
                app.timestamp = self.schedule.timestamp_ms()
                self._submit_pair(app)
                if polling:
                    self.schedule.unregister(record)
            finally:
                self._callback.application = None

    def _submit_pair(self, app):
        self._submit(app, '6B01C')
        self._submit(app, '6A923')

    def request_status(self, appid, subtype, status=None):
        """Queue the complete Source kind7 group on this module's provider.

        The caller supplies the Source54211/54411 status. This request does not
        complete acquisition, publish material or make a getter ready.
        """
        self._check(creator=True)
        status_value(subtype, status)
        app = self.applications.get(appid)
        if app is None or not app.initialized or self.sealed:
            raise QimeiRequestBoundary('status request requires an admitted canonical application')
        return self._submit(app, ('54211', '542E3', '54411')[subtype - 1], status)

    def request_report(self, appid):
        """Queue Source6BBCE on the admitted owner, without acquisition publication."""
        self._check(creator=True)
        app = self.applications.get(appid)
        if app is None or not app.initialized or self.sealed:
            raise QimeiRequestBoundary('report requires an admitted canonical application')
        return self._submit(app, '6BBCE')

    def _submit(self, app, business, status=None):
        task = self.executor._submit_module(self, app, business,
                                           lambda owner: self._run(app, business, status))
        self.tasks.append(task)
        return task

    def _run(self, app, business, status=None):
        io = self.worker_io_factory(app)
        try:
            self._check()
            if (io.startup is not self.startup or io.settings is not app.settings
                    or io.selector is not self.creator_io.selector
                    or io.settings_dependencies.get('codec') is not self.creator_io.settings_dependencies.get('codec')
                    or io.settings_dependencies.get('context_producer') is not self.creator_io.settings_dependencies.get('context_producer')):
                raise QimeiRequestBoundary('worker IO cannot replace canonical stores/settings')
            if business == '6BBCE':
                return conditional_kind13(app.appid, app.settings,
                    settings_dependencies=io.settings_dependencies, sources=io.report_sources,
                    dispatch=self.provider, io=io)
            if business in ('54211', '542E3', '54411'):
                if (io.adapter.state is not self.creator_io.adapter.state or
                        io.adapter.state.selector is not io.selector):
                    raise QimeiRequestBoundary('status request requires the canonical compound adapter owner')
                return conditional_kind7(app.appid, app.settings,
                    ('54211', '542E3', '54411').index(business) + 1, status,
                    settings_dependencies=io.settings_dependencies, adapter=io.adapter,
                    dispatch=self.provider, module_state=self.request_state,
                    clock_milliseconds=self.schedule.timestamp_ms,
                    convert_ansi=io.convert_ansi, io=io)
            if business == '6B01C':
                return retained_kind4(app.appid, app.settings,
                    settings_dependencies=io.settings_dependencies, sources=io.config_sources,
                    writer=io.settings_writer, dispatch=self.provider,
                    convert_ansi=io.convert_ansi, io=io)
            if business == '6A923':
                value = self.startup.main.get(1).split(b'\0', 1)[0]
                if value:
                    return self.ipc.publish(app.appid, value[:36].ljust(36, b'\0'), len(value))
                self.ipc._event_cleanup(app.appid)
                binding = ApplicationBinding(app.appid, app.settings, app.context, {})
                return self.pipeline.run_cold_material_job(binding, startup=self.startup,
                    dispatch=self.dispatch, reply=QimeiReplyState(), source_clock=io.config_sources.clock,
                    selector=io.selector, selector_observations=io.selector_observations,
                    persist=io.persist, io=io)
            value = self.startup.main.get(1).split(b'\0', 1)[0]
            if value:
                self.ipc._event_cleanup(app.appid)
            else:
                value = self.ipc.consume(app.appid)
            if not value:
                return 1
            conditional_kind3(app.appid, app.settings,
                settings_dependencies=io.settings_dependencies, usage_count=self.ipc._usage_count,
                instance_count=self.schedule.instance_count, selector=io.selector,
                selector_observations=io.selector_observations, request_sources=self.pipeline.request_producer.extensions,
                dispatch=self.provider, convert_ansi=io.convert_ansi, io=io)
            self._notify(app, io)
            return 0
        finally:
            try:
                io.close()
            except BaseException:
                self.io_debt.append(io)
                raise

    def _fill(self, app, out, dependencies):
        with app.settings._lock:
            return self._fill_locked(app, out, dependencies)

    def _fill_locked(self, app, out, dependencies):
        if type(out) is not bytearray or len(out) != 70:
            raise QimeiRequestBoundary('b requires existing 70-byte output backing')
        for flag, offset, length, store in ((0, 0, 36, self.startup.main),
                                           (12, 37, 32, self.startup.identity1)):
            if app.settings.flag(flag, **dependencies):
                value = store.get(1).split(b'\0', 1)[0]
                if offset and not value:
                    raise QimeiRequestBoundary('empty AUX690A5 remains outside fresh supported domain')
                value = value[:length]
                out[offset:offset + len(value) + 1] = value + b'\0'
        return out

    def query(self, appid, out70):
        self._check(creator=True)
        app = self.applications.get(appid)
        if app is None or not app.initialized:
            raise QimeiRequestBoundary('query requires normally initialized canonical application')
        with app.lock:
            self._fill(app, out70, self.creator_io.settings_dependencies)
        return 0

    def _notify(self, app, io):
        with app.lock:
            self._fill(app, app.buffer, io.settings_dependencies)
            if not app.buffer[0]:
                return
            for index, pointer in enumerate(app.callbacks):
                if pointer is None or not pointer or io.bad_code_pointer(pointer) or not app.buffer[0]:
                    break
                io.invoke_notification(pointer, app.buffer)
                app.callbacks[index] = None  # Normal callback return only.

    def close(self):
        self._check(creator=True)
        with self.lock:
            self.sealed = True
        self.schedule.close_queue()
        if self.executor is not None:
            self.executor.shutdown_and_join()
        if self.io_debt or self.worker_io_factory.debt:
            raise QimeiRequestBoundary('worker IO cleanup debt retains module backing')
        self.creator_io.close()
        self.ipc.dispose_terminal()
        self.schedule.close_mutexes()
        self.bridge.close()
        if self.provider_pair is not None:
            self.provider_pair[1].release()
            self.provider_pair = None
        if self.provider is not None:
            self.provider.release()
        self.applications.clear()
        self.closed = True
