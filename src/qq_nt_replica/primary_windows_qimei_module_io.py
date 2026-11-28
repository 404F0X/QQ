"""Worker-local real Windows IO, borrowing the epoch's unique state owners."""
import ctypes as C
import threading

from .primary_qimei_adapter_sources import QimeiAdapterSources, QimeiAdapterState
from .primary_qimei_context import QimeiContextProducer
from .primary_qimei_cache import QimeiCacheCodec
from .primary_qimei_records import StartupState
from .primary_qimei_settings import QimeiSettings
from .primary_qimei_beacon import QimeiBeaconInputProducer
from .primary_qimei_extra_sources import QimeiExtraSources
from .primary_qimei_main_writer import QimeiMainWriter
from .primary_qimei_observations import QimeiClassifierObservations
from .primary_qimei_records import persist_store
from .primary_qimei_request import QimeiRequestBoundary
from .primary_qimei_report_sources import QimeiReportSources
from .primary_qimei_request_sources import QimeiRequestSources
from .primary_qimei_storage import StorageBuffer
from .primary_qimei_system_sources import QimeiSystemSources
from .primary_qimei_transport_random import QimeiTransportRandom
from .primary_windows_qimei_adapter import WindowsQimeiAdapterAPIBackend
from .primary_windows_qimei_carrier import NativeWinInetPort, WindowsQimeiCarrier
from .primary_windows_qimei_config import WindowsQimeiConfigSources
from .primary_windows_qimei_context import WindowsQimeiContextObservations
from .primary_windows_qimei_extensions import WindowsQimeiExtensionObservations
from .primary_windows_qimei_owned_storage import (OwnQimeiBeaconBackend,
    OwnQimeiMainWriterObservations, bind_owned_qimei_settings)
from .primary_windows_qimei_request_sources import WindowsQimeiRequestObservations
from .primary_windows_qimei_report import WindowsQimeiReportObservations
from .primary_windows_qimei_settings_writer import create_windows_qimei_settings_writer
from .primary_windows_qimei_storage import WindowsStorageObservations
from .primary_windows_qimei_transport_material import WindowsQimeiTransportObservations


class WindowsQimeiModuleIOFactory:
    def __init__(self, runtime, epoch, current_epoch, *, permit, root, startup,
                 settings, cache_codec, context_producer, adapter_state, convert_ansi):
        if (not isinstance(context_producer, QimeiContextProducer) or
                not isinstance(cache_codec, QimeiCacheCodec) or
                not isinstance(startup, StartupState) or not isinstance(settings, QimeiSettings) or
                not isinstance(adapter_state, QimeiAdapterState) or
                adapter_state.selector is not context_producer.selector):
            raise QimeiRequestBoundary('IO factory requires the same epoch context/selector/adapter/cache owners')
        self.runtime, self.epoch, self.current_epoch = runtime, epoch, current_epoch
        self.permit, self.root = permit, root
        self.startup, self.settings = startup, settings
        self.cache_codec, self.context_producer = cache_codec, context_producer
        self.adapter_state, self.convert_ansi = adapter_state, convert_ansi
        self.debt = []
        self.settings_acl_cache = set()
        self.store_acl_caches = {'main': set(), 'identity1': set()}

    def __call__(self, app):
        io = object.__new__(WindowsQimeiModuleIO)
        io.resources = []
        io.factory = self
        io.thread = threading.get_native_id()
        io.closed = False
        try:
            io.initialize(app)
            return io
        except BaseException as error:
            try:
                io.close()
            except BaseException as cleanup:
                self.debt.append(io)
                raise ExceptionGroup('IO construction and cleanup failed', [error, cleanup])
            raise


class WindowsQimeiModuleIO:
    def _own(self, resource, close='close'):
        self.resources.append((resource, close))
        return resource

    def check(self):
        f = self.factory
        if (self.closed or threading.get_native_id() != self.thread or
                not f.permit(f.runtime, f.epoch) or f.current_epoch(f.runtime) is not f.epoch):
            raise QimeiRequestBoundary('module IO requires its live constructing thread')

    def initialize(self, app):
        self.check()
        f = self.factory
        self.startup, self.settings, self.convert_ansi = f.startup, f.settings, f.convert_ansi
        self.report_sources = QimeiReportSources(self._own(WindowsQimeiReportObservations()))
        if app.settings is not self.settings or app.startup is not self.startup:
            raise QimeiRequestBoundary('IO application differs from canonical state')
        context = self._own(WindowsQimeiContextObservations(backend=WindowsQimeiAdapterAPIBackend()))
        request = self._own(WindowsQimeiRequestObservations())
        self.request_observations = request
        self.write_main = self._write_main
        extension = self._own(WindowsQimeiExtensionObservations())
        transport = self._own(WindowsQimeiTransportObservations())
        storage = self._own(WindowsStorageObservations())
        self.config_sources = self._own(WindowsQimeiConfigSources(f.runtime, f.epoch, f.current_epoch, permit=f.permit))
        self.selector, self.selector_observations = f.context_producer.selector, context
        self.classifier_observations = QimeiClassifierObservations(request)
        self.adapter = QimeiAdapterSources(context, state=f.adapter_state)
        self.system, self.extras = QimeiSystemSources(request), QimeiExtraSources(transport)
        self.random = QimeiTransportRandom(transport)
        self.globals_api = self.extras._api
        self.transport_observations = transport
        self.beacon_backend = self._own(OwnQimeiBeaconBackend(f.runtime, f.epoch, f.current_epoch,
            permit=f.permit, root=f.root), 'close_native')
        self.beacon_producer = QimeiBeaconInputProducer(self.selector, context, storage, request)
        self.settings_dependencies = bind_owned_qimei_settings(self.settings, f.runtime, f.epoch,
            f.current_epoch, permit=f.permit, root=f.root, owner=app.appid, codec=f.cache_codec,
            context_producer=f.context_producer, context_observations=context)
        self.settings_writer = create_windows_qimei_settings_writer(f.runtime, f.epoch, f.current_epoch,
            path=self.settings.path, permit=self._settings_permit, codec=f.cache_codec,
            context_producer=f.context_producer, observations=context, attempted=f.settings_acl_cache)
        self._own(self.settings_writer.backend)
        self.writers = {}
        self.context_observations = context
        self.extension = QimeiRequestSources(request, startup=self.startup,
            write_main=self._write_main, storage_observations=storage,
            adapter_sources=self.adapter, extension_observations=extension)
        port = self._own(NativeWinInetPort(permit=lambda: f.permit(f.runtime, f.epoch)
            and f.current_epoch(f.runtime) is f.epoch))
        self.carrier = WindowsQimeiCarrier(port)

    def _settings_permit(self, runtime, epoch, path, operation):
        self.check()
        from pathlib import Path
        target = Path(path.decode('ascii'))
        root = Path(self.factory.root)
        for directory in (root, root / 'settings'):
            if (directory.resolve() != directory or directory.is_symlink() or
                    hasattr(directory, 'is_junction') and directory.is_junction()):
                raise QimeiRequestBoundary('Own settings directory substitution')
        if (target.parent != root / 'settings' or target.is_symlink() or
                target.exists() and target.stat().st_nlink != 1):
            raise QimeiRequestBoundary('Own settings write target substitution')
        return (runtime is self.factory.runtime and epoch is self.factory.epoch
                and path == self.settings.path and operation == 'settings-file-write-and-dacl')

    def clock(self):
        self.check()
        data = StorageBuffer(bytes(8))
        unused, outputs = self.globals_api('GetSystemTimeAsFileTime', (data,), {'data': data})
        return int.from_bytes(outputs['data'].read(), 'little') - 116444736000000000

    def _writer(self, store):
        self.check()
        if store is not self.startup.main and store is not self.startup.identity1:
            raise QimeiRequestBoundary('unbound module Store persistence')
        if store.name not in self.writers:
            from pathlib import Path
            f = self.factory
            root = Path(f.root) / store.name
            root.mkdir(exist_ok=True)
            observations = self._own(OwnQimeiMainWriterObservations(f.runtime, f.epoch,
                f.current_epoch, permit=f.permit, root=root,
                logical_main_path=store.read_path()), 'close_native')
            writer = QimeiMainWriter(observations, codec=f.cache_codec, context=f.context_producer,
                                     context_observations=self.context_observations, acl_cache=f.store_acl_caches[store.name])
            self.writers[store.name] = writer, observations
        return self.writers[store.name]

    def persist(self, store):
        writer, observations = self._writer(store)
        def previous(path):
            physical = observations._main(path)
            try:
                raw = physical.read_bytes()
            except FileNotFoundError:
                return None
            f = self.factory
            return f.cache_codec.decode_payload(raw, capacity=1 << 20,
                context=f.context_producer.produce(self.context_observations))
        status = persist_store(store, writer, previous)
        if status != 0:
            raise QimeiRequestBoundary('Store persistence failed with status ' + str(status))
        return True

    def _write_main(self, store):
        return self.persist(store)

    def bad_code_pointer(self, pointer):
        self.check()
        if type(pointer) is not int:
            raise QimeiRequestBoundary('native callback slot requires actual integer pointer')
        return bool(self.config_sources._call('kernel32', 'IsBadCodePtr', C.c_int32, (C.c_void_p,), pointer))

    def invoke_notification(self, pointer, buffer):
        self.check()
        backing = (C.c_ubyte * 70).from_buffer(buffer)
        C.WINFUNCTYPE(None, C.c_void_p)(pointer)(C.addressof(backing))

    def close(self):
        if self.closed:
            return
        self.check()
        errors = []
        for resource, method in reversed(tuple(self.resources)):
            try:
                getattr(resource, method)()
                self.resources.remove((resource, method))
            except BaseException as error:
                errors.append(error)
        if errors:
            raise ExceptionGroup('worker IO cleanup debt', errors)
        self.closed = True
