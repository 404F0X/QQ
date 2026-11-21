from collections import Counter
from contextlib import contextmanager, nullcontext
import copy
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import struct
import threading

from .errors import InputError
from .primary_device_provider import DeviceFactory, DeviceRefreshGate
from .primary_host_services import GuestExitRegistrar
from .primary_signer import CallerProfile, PrimarySigner, SigningEnvironment
from .primary_request_transport import RequestTransportBinding
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows_caller import WindowsCallerAPIBackend, WindowsCallerObservations
from .primary_windows_caller_bridge import WindowsCallerBridge
from .primary_windows_device_files import WindowsDeviceFileObservations
from .primary_windows_device_process_records import WindowsDeviceProcessRecordObservations
from .primary_windows_device_hardware import WindowsDeviceHardwareObservations
from .primary_windows_provider_observations import WindowsProviderObservations
from .primary_windows_worker_observations import WindowsWorkerObservations
from .primary_windows_threads import WindowsSDKThreadService
from .primary_windows_crt import WindowsCRTObservations
from .primary_windows_core_observations import WindowsCoreObservations
from .primary_windows_ownimage import OwnImageModuleSpec, WindowsOwnImageModule
from .primary_windows_notification_environment import WindowsNotificationEnvironmentObservations
from .primary_windows_wmi import WindowsWMIObservations
from .primary_windows_system_records import WindowsSystemRecordObservations
from .primary_windows_worker_bridge import WindowsWorkerBridge
from . import primary_crt_startup


_RETAINED_SUPPLIED_OWNERS = []


def open_supplied_signer(environment, *, registrar, profile, initial_stack, addresses, image_base,
                         provider_material=None, primary_backend='direct', construction_setup=None):
    if (type(environment) is not SigningEnvironment or type(registrar) is not GuestExitRegistrar or
            environment.exit_registration is not registrar or type(profile) is not CallerProfile):
        raise InputError('SUPPLIED_SIGNER_INPUT_IDENTITY')
    if type(primary_backend) is not str or primary_backend not in ('reference', 'direct'):
        raise InputError('primary_backend must be reference or direct')
    if type(profile.host_profile_string) is not bytes:
        raise InputError('SUPPLIED_SIGNER_PROFILE')
    if construction_setup is not None and not callable(construction_setup):
        raise InputError('SUPPLIED_SIGNER_CONSTRUCTION_SETUP')
    owner = object.__new__(WindowsSigner)
    owner._initialize(None, profile.host_profile_string, initial_stack)
    registrar.take_fresh(owner)
    owner._registrar = registrar
    owner._supplied_environment = environment
    try:
        owner._signer = PrimarySigner(environment, initial_stack=initial_stack, addresses=addresses,
            image_base=image_base, profile=profile, provider_material=provider_material,
            primary_backend=primary_backend)
        registrar.bind(owner._signer.runtime)
        owner._initialize_notification_statics()
        if construction_setup is not None:
            construction_setup(owner)
        owner._state = 'open'
        return owner
    except BaseException as original:
        try:
            owner.close()
        except BaseException as cleanup:
            failure = BaseExceptionGroup('Supplied signer construction and cleanup failed', [original, cleanup])
            failure.supplied_signer_owner = owner
            raise failure
        try:
            original.supplied_signer_owner = owner
        except BaseException:
            pass
        raise


def _error_summary(error):
    return {'type': type(error).__name__, 'message_sha256': hashlib.sha256(str(error).encode('utf-8', 'replace')).hexdigest()}


def _nonreparse(path):
    for candidate in (path, *path.parents):
        try:
            information = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(information.st_mode) or getattr(information, 'st_file_attributes', 0) & 0x400:
            raise InputError('Windows signer paths must not traverse reparse points')


def _validated_paths(bridge_path, storage_root, host_profile_string, initial_stack, retain_diagnostics):
    if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise PrimarySemanticUnavailable('Windows signer requires Windows x64')
    if not isinstance(host_profile_string, bytes):
        raise InputError('Windows signer host profile must be explicit bytes')
    if initial_stack is not None and (not isinstance(initial_stack, bytes) or len(initial_stack) != 16):
        raise InputError('Windows signer initial stack must be unknown or an explicit owned16-byte preimage')
    if type(retain_diagnostics) is not bool:
        raise InputError('Windows signer diagnostic retention must be boolean')
    try:
        bridge, storage = Path(bridge_path), Path(storage_root)
    except (TypeError, ValueError) as error:
        raise InputError('Windows signer requires explicit absolute paths') from error
    for path in (bridge, storage):
        if not path.is_absolute() or '..' in path.parts or '\0' in str(path):
            raise InputError('Windows signer requires absolute nontraversing paths')
        _nonreparse(path)
    manifest = Path(str(bridge) + '.manifest.json')
    _nonreparse(manifest)
    if not bridge.is_file() or not manifest.is_file():
        raise InputError('Windows signer requires its existing owned helper DLL and manifest')
    if not storage.parent.is_dir() or storage.exists() and not storage.is_dir():
        raise InputError('Windows signer storage requires an existing parent and directory root')
    if not storage.exists():
        storage.mkdir()
    _nonreparse(storage)
    return bridge, storage


def open_windows_signer(*, bridge_path, storage_root, host_profile_string, initial_stack=None, scalar_sse_state=None,
                        primary_backend='reference', retain_diagnostics=False, worker_bridge_path=None, raw_event_tap=None, ownimage_module=None,
                        notification_environment=False, host2252_stage1_retry=False, host2252_m_read_budget=4096,
                        host2252_stage2_g_retry=False, host2252_g_read_budget=4096,
                    host2252_final_f_retry=False, host2252_f_read_budget=4096,
                    host2252_pair_m_retry=False, host2252_pair_m_read_budget=4096,
                    host2252_control_m=False, independent_provider_metadata=None, common_guid=None,
                    allow_qqprotect_registry=False, allow_capi_creation=False,
                    request_transport=None, construction_setup=None, display_environment='independent_windows', outer_login_config=None, outer_sync_permit=None):
    if outer_login_config is not None and construction_setup is not None:
        raise InputError('source outer entry cannot run an unrelated construction hook first')
    if outer_sync_permit is not None and (outer_login_config is None or not callable(outer_sync_permit)):
        raise InputError('outer native sync permit requires explicit outer selection')
    if outer_login_config is not None and independent_provider_metadata is not None:
        raise InputError('choose source outer prefix or diagnostic inner preparation')
    if type(display_environment) is not str or display_environment not in ('source_frame', 'independent_windows'):
        raise InputError('WINDOWS_DISPLAY_ENVIRONMENT_MODE')
    if request_transport is not None and not isinstance(request_transport, RequestTransportBinding):
        raise InputError('WINDOWS_REQUEST_TRANSPORT_BINDING')
    if construction_setup is not None and not callable(construction_setup):
        raise InputError('WINDOWS_SIGNER_CONSTRUCTION_SETUP')
    if type(allow_capi_creation) is not bool:
        raise InputError('CAPI_CREATION_OPT_IN_BOOL')
    if type(allow_qqprotect_registry) is not bool:
        raise InputError('QQPROTECT_REGISTRY_OPT_IN_BOOL')
    if type(primary_backend) is not str or primary_backend not in ('reference', 'direct'):
        raise InputError('primary_backend must be reference or direct')
    if type(notification_environment) is not bool or notification_environment and ownimage_module is None:
        raise InputError('notification environment W opt-in requires an explicit boolean and owned image specification')
    if ownimage_module is not None and type(ownimage_module) is not OwnImageModuleSpec:
        raise InputError('Windows signer own-image opt-in requires its fixed immutable specification')
    if independent_provider_metadata is not None:
        from .primary_windows_signer_setup import validate_independent
        validate_independent(independent_provider_metadata, host_profile_string, primary_backend, worker_bridge_path)
    bridge, storage = _validated_paths(bridge_path, storage_root, host_profile_string, initial_stack, retain_diagnostics)
    owner = object.__new__(WindowsSigner)
    owner._initialize(storage, host_profile_string, initial_stack)
    owner._allow_qqprotect_registry = allow_qqprotect_registry
    try:
        if ownimage_module is not None:
            owner._ownimage_module = WindowsOwnImageModule(ownimage_module)
            owner._ownimage_module.acquire()
        owner._backend = WindowsCallerAPIBackend()
        owner._bridge = WindowsCallerBridge(bridge)
        owner._backend.bridge = owner._bridge
        owner._bridge_transferred = True
        owner._threads = WindowsSDKThreadService()
        if worker_bridge_path is not None:
            owner._threads.bind_worker_bridge(WindowsWorkerBridge(worker_bridge_path))
        if owner._ownimage_module is None:
            owner._caller = WindowsCallerObservations(owner._threads, backend=owner._backend,
                allow_qqprotect_registry=owner._allow_qqprotect_registry)
        else:
            owner._caller = WindowsCallerObservations(owner._threads, backend=owner._backend,
                                                      ownimage_module=owner._ownimage_module,
                                                      allow_qqprotect_registry=owner._allow_qqprotect_registry)
        owner._provider = WindowsProviderObservations(owner._caller)
        owner._refresh = WindowsWorkerObservations(owner._provider)
        owner._files = WindowsDeviceFileObservations(storage, owner._refresh)
        owner._registrar = GuestExitRegistrar()
        owner._core_observations = WindowsCoreObservations(tap=raw_event_tap)
        process_path, cursor, stack_paths = owner._host_environment()
        environment = SigningEnvironment(cursor=cursor, process_path=process_path, module_path=process_path,
                                         stack_modules=stack_paths, process_id=owner._pid,
                                         filetime=owner._core_observations.filetime,
                                         qpc=owner._core_observations.qpc, random_bytes=owner._core_observations.random_bytes,
                                         bcrypt=owner._core_observations.bcrypt_word,
                                         raw_core_observations=owner._core_observations,
                                         caller_observations=owner._caller,
                                         worker_observations=owner._threads.observations(owner._files), exit_registration=owner._registrar,
                                         sdk_thread_starts=owner._threads.source_start, scalar_sse_state=scalar_sse_state,
                                         common_guid=common_guid, request_transport=request_transport)
        owner._factory = DeviceFactory.windows(environment, storage_root=storage,
                                              enumeration_source='windows', public_key_source='windows',
                                              device_time_source='observed', refresh_observer=None,
                                              refresh_gate=DeviceRefreshGate.native(), allow_capi_creation=allow_capi_creation,
                                              display_environment=display_environment)
        owner._provider.bind_source(owner._factory.source)
        profile = CallerProfile(None, host_profile_string, device_factory=owner._factory)
        from .primary_module_sync import _begin_birth, _seal_birth
        sync_birth = _begin_birth(owner, outer_sync_permit) if outer_sync_permit is not None else None
        owner._signer = PrimarySigner(environment, initial_stack=initial_stack, profile=profile,
                                      primary_backend=primary_backend,
                                      retain_diagnostics=retain_diagnostics,
                                      host2252_stage1_retry=host2252_stage1_retry,
                                      host2252_m_read_budget=host2252_m_read_budget,
                                      host2252_stage2_g_retry=host2252_stage2_g_retry,
                                      host2252_g_read_budget=host2252_g_read_budget,
                                      host2252_final_f_retry=host2252_final_f_retry,
                                      host2252_f_read_budget=host2252_f_read_budget,
                                      host2252_pair_m_retry=host2252_pair_m_retry,
                                      host2252_pair_m_read_budget=host2252_pair_m_read_budget,
                                      host2252_control_m=host2252_control_m,
                                      _module_sync_birth=sync_birth)
        if sync_birth is not None:
            _seal_birth(owner)
        if owner._ownimage_module is not None:
            owner._ownimage_module.bind(owner._signer.runtime)
        if notification_environment:
            owner._notification_environment = WindowsNotificationEnvironmentObservations(
                ownimage_module=owner._ownimage_module, capability=owner._ownimage_module.capability_w_snapshot(),
                module_capability=owner._ownimage_module.capability_snapshot())
            owner._notification_environment.bind(owner._signer.runtime)
            owner._signer.runtime.notification_environment_observations = owner._notification_environment
        owner._registrar.bind(owner._signer.runtime)
        from .primary_windows_allocator_issuer import install_early_allocator
        install_early_allocator(owner)
        owner._initialize_notification_statics()
        owner._threads.bind(owner._signer.runtime, owner._registrar, owner._worker_services)
        owner._initialize_crt()
        if construction_setup is not None:
            construction_setup(owner)
        owner._state = 'open'
        if outer_login_config is not None:
            if outer_sync_permit is not None:
                from .primary_windows_outer_sync import bind_outer_sync
                bind_outer_sync(owner,permit=outer_sync_permit)
            from .primary_windows_signer_setup import IndependentWindowsSetup
            owner._independent_setup = IndependentWindowsSetup(owner)
            owner._independent_setup.prepare_outer_prefix(outer_login_config)
        elif independent_provider_metadata is not None:
            from .primary_windows_signer_setup import IndependentWindowsSetup
            owner._independent_setup = IndependentWindowsSetup(owner)
            owner._independent_setup.prepare(independent_provider_metadata)
        return owner
    except BaseException as original:
        from .primary_module_sync import _cancel_pending_birth
        _cancel_pending_birth(owner)
        try:
            owner.close()
        except BaseException as cleanup:
            failure = BaseExceptionGroup('Windows signer construction and cleanup failed', [original, cleanup])
            failure.windows_signer_diagnostics = owner.diagnostics
            if independent_provider_metadata is not None:
                failure.independent_windows_owner = owner
            failure.add_note('Windows signer storage is retained: ' + str(storage))
            raise failure
        original.windows_signer_diagnostics = owner.diagnostics
        original.add_note('Windows signer storage is retained: ' + str(storage))
        raise


class WindowsSigner:
    def __init__(self):
        raise InputError('Use open_windows_signer to acquire a Windows signer')

    def _initialize(self, storage, host_profile_string, initial_stack):
        self._allow_qqprotect_registry = False
        self._storage_root = storage
        self._profile_hash = hashlib.sha256(host_profile_string).hexdigest()
        self._stack_kind = 'unknown' if initial_stack is None else 'explicit owned16-byte preimage'
        self._pid, self._thread = os.getpid(), threading.get_native_id()
        self._state, self._busy = 'constructing', False
        self._backend = self._bridge = self._caller = self._files = None
        self._provider = None
        self._refresh = self._threads = self._crt = None
        self._core_observations = None
        self._ownimage_module = None
        self._notification_environment = None
        self._registrar = self._factory = self._signer = None
        self._bridge_transferred = False
        self._cleanup_outcomes = []
        self._cleanup_failure = None
        self._operation_failure = None
        self._operation_outcomes = []
        self._successful_operation_result = None
        self._worker_wmi_pending = []
        self._worker_system_records_pending = []
        self._worker_hardware_pending = []
        self._worker_process_records_pending = []
        self._supplied_environment = None
        self._independent_setup = None

    def _initialize_notification_statics(self):
        if self._state != 'constructing':
            raise InputError('notification static initialization requires its constructing owner')
        with self._registrar.operation():
            self._signer.initialize_notification_statics()

    def _initialize_crt(self):
        if self._state != 'constructing' or self._crt is not None:
            raise InputError('Windows signer CRT startup requires its fresh constructing owner')
        runtime = self._signer.runtime
        primary_crt_startup.install_cold_state(runtime.memory, runtime.image_base)
        self._crt = WindowsCRTObservations(callback_context=self._crt_callback_context)
        self._crt.bind(runtime)
        runtime.crt_startup_observations = self._crt
        self._threads.before_public_operation()
        try:
            with self._registrar.operation():
                if runtime._crt_call(primary_crt_startup.initialize) != 1:
                    raise PrimarySemanticUnavailable('Windows signer source CRT process initialization returned false')
                runtime._crt_thread()
        finally:
            self._threads.after_public_operation()

    @contextmanager
    def _crt_callback_context(self, runtime, tid):
        if self._signer is None or runtime is not self._signer.runtime:
            raise InputError('Windows signer CRT callback requires its bound runtime')
        with self._threads.crt_callback_context(runtime, tid):
            previous = runtime.worker_observations
            runtime.worker_observations = self._crt
            try:
                yield
            finally:
                runtime.worker_observations = previous

    @contextmanager
    def _worker_services(self):
        caller = provider = refresh = files = process_records = hardware = system_records = wmi = None
        try:
            caller = WindowsCallerObservations(self._threads,
                allow_qqprotect_registry=self._allow_qqprotect_registry)
            provider = WindowsProviderObservations(caller, source=self._factory.source)
            refresh = WindowsWorkerObservations(provider)
            files = WindowsDeviceFileObservations(self._storage_root, refresh)
            process_records = WindowsDeviceProcessRecordObservations(files)
            hardware = WindowsDeviceHardwareObservations(process_records)
            system_records = WindowsSystemRecordObservations(hardware,
                allow_qqprotect_registry=self._allow_qqprotect_registry)
            wmi = WindowsWMIObservations(system_records)
            wmi.bind(self._signer.runtime)
            yield {'observations': self._threads.observations(wmi), 'filetime': caller.filetime}
        finally:
            errors = []
            if wmi is not None:
                try:
                    wmi.close()
                except BaseException as error:
                    self._worker_wmi_pending.append((wmi, system_records, hardware, process_records, files, refresh, provider, caller))
                    raise BaseExceptionGroup('native worker WMI cleanup retains its observation domain', [error])
            if system_records is not None:
                try:
                    system_records.close()
                except BaseException as error:
                    self._worker_system_records_pending.append((wmi, system_records, hardware, process_records, files, refresh, provider, caller))
                    raise BaseExceptionGroup('native worker system record cleanup retains its observation domain', [error])
            if hardware is not None:
                try:
                    hardware.close()
                except BaseException as error:
                    self._worker_hardware_pending.append((wmi, system_records, hardware, process_records, files, refresh, provider, caller))
                    raise BaseExceptionGroup('native worker hardware cleanup retains its observation domain', [error])
            if process_records is not None:
                try:
                    process_records.close()
                except BaseException as error:
                    self._worker_process_records_pending.append((wmi, system_records, hardware, process_records, files, refresh, provider, caller))
                    raise BaseExceptionGroup('native worker process record cleanup retains its observation domain', [error])
            for resource in (files, refresh, provider, caller):
                if resource is not None:
                    try:
                        resource.close()
                        if resource is files and (files.pending_handles or any(
                                row.get('completion') == 'unknown' for row in files.cleanup_records)):
                            raise PrimarySemanticUnavailable('native worker file cleanup remains unresolved')
                    except BaseException as error:
                        errors.append(error)
            if errors:
                raise BaseExceptionGroup('native worker observation cleanup failed', errors)

    def _check_owner(self):
        if self._pid != os.getpid() or self._thread != threading.get_native_id():
            raise InputError('Windows signer requires its creating process and native thread')

    def _host_environment(self):
        length, raw, _ = self._backend.request('GetModuleFileNameA', (0, 519))
        process_path = self._complete_path(length, raw)
        module, _, _ = self._backend.request('GetModuleHandleA', (b'ntdll.dll',))
        if not module:
            raise PrimarySemanticUnavailable('Windows signer actual ntdll module is unavailable')
        export, _, _ = self._backend.request('GetProcAddress', (module, b'RtlCaptureStackBackTrace'))
        if not export:
            raise PrimarySemanticUnavailable('Windows signer actual stack capture export is unavailable')
        snapshot = self._backend.capture(export)
        if (snapshot.process_id, snapshot.thread_id) != (self._pid, self._thread) or not snapshot.frames:
            raise PrimarySemanticUnavailable('Windows signer actual helper frames are unavailable or foreign')
        stack_paths = []
        for address in snapshot.frames:
            success, handle, _ = self._backend.request('GetModuleHandleExW', (6, address))
            if not success or not isinstance(handle, bytes) or len(handle) != 8:
                raise PrimarySemanticUnavailable('Windows signer actual frame module is unavailable')
            length, raw, _ = self._backend.request('GetModuleFileNameA', (int.from_bytes(handle, 'little'), 519))
            stack_paths.append(self._complete_path(length, raw))
        return process_path, None, tuple(stack_paths)

    @staticmethod
    def _complete_path(length, raw):
        if (type(length) is not int or not 0 < length < 519 or not isinstance(raw, bytes) or
                len(raw) != length + 1 or raw[-1:] != b'\0' or b'\0' in raw[:-1]):
            raise PrimarySemanticUnavailable('Windows signer actual module filename is unavailable or truncated')
        return raw[:-1]

    def _operation(self, method, *arguments, **options):
        self._check_owner()
        from .primary_outer_init import require_selected_outer_ready
        require_selected_outer_ready(self._signer.runtime)
        if self._state != 'open' or self._busy or self._signer.failed:
            raise InputError('Windows signer is unavailable for a new serial signing operation')
        self._busy = True
        events = len(self._signer.runtime.events)
        calls = self._signer.calls
        entered = False
        try:
            if self._threads is not None:
                self._threads.before_public_operation()
                entered = True
            with self._registrar.operation():
                phase = 'initialization' if method.startswith('initialize') else 'core'
                with self._core_observations.phase(phase) if self._core_observations is not None else nullcontext():
                    with self._independent_setup.operation(method) if self._independent_setup is not None else nullcontext():
                        result = getattr(self._signer, method)(*arguments, **options)
            self._operation_outcomes.append({'method': method, 'status': 'completed',
                                             'call_count': self._signer.calls})
            if method in ('sign', 'sign_result'):
                self._successful_operation_result = result
            return result
        except BaseException as error:
            self._operation_failure = error
            if (self._signer.failed or not isinstance(error, InputError) or
                    len(self._signer.runtime.events) != events or self._signer.calls != calls):
                self._state = 'failed'
            raise
        finally:
            if entered:
                self._threads.after_public_operation()
            self._busy = False

    def drain(self):
        self._check_owner()
        from .primary_outer_init import require_selected_outer_ready
        require_selected_outer_ready(self._signer.runtime)
        if self._busy or self._threads is None:
            raise InputError('Windows signer cannot drain during an active operation or without thread service')
        return self._threads.drain()

    def initialize_sdk(self):
        return self._operation('initialize_sdk')

    def initialize_provider(self, metadata, *, private_context_tail):
        return self._operation('initialize_provider', metadata, private_context_tail=private_context_tail)

    def sign(self, command, payload):
        return self._operation('sign', command, payload)

    @property
    def signer(self):
        return self._signer

    def sign_result(self, command, payload, *, now=None):
        return self._operation('sign_result', command, payload, now=now)

    def request_device_refresh_async(self) -> None:
        return self._operation('request_device_refresh_async')

    def pump_device_request(self):
        self._check_owner()
        from .primary_outer_init import require_selected_outer_ready
        require_selected_outer_ready(self._signer.runtime)
        if self._state != 'open' or self._busy or self._signer.failed or self._threads is None:
            raise InputError('device request pump requires its idle open Windows owner')
        return self._threads.pump_device_request()

    def validate_device_request_callback(self):
        if self._threads is None or self._threads._runtime is not self._signer.runtime:
            raise InputError('device request callback lost its owning Windows thread service')
        return self._threads.validate_device_request_callback()

    def validate_device_request_park(self):
        self._check_owner()
        if (self._state != 'open' or not self._busy or self._signer.failed or self._threads is None or
                self._threads._runtime is not self._signer.runtime):
            raise InputError('device request validation requires its open owner fence')
        return self._threads.validate_device_request_park()

    def request_device_refresh(self) -> None:
        return self._operation('request_device_refresh')

    def complete_request(self, command: bytes, response: bytes, *, success: int, sequence: int,
                         error: int = 0) -> str:
        return self._operation('complete_request', command, response, success=success, sequence=sequence, error=error)

    def _release_resources(self):
        errors = []
        def attempt(stage, function):
            try:
                function()
            except BaseException as error:
                errors.append(error)
                self._cleanup_outcomes.append(dict(_error_summary(error), stage=stage, status='failed'))
                return False
            self._cleanup_outcomes.append({'stage': stage, 'status': 'completed'})
            return True
        if self._threads is not None:
            if not attempt('sdk_threads_prepare', self._threads.prepare_close):
                return errors
        if self._worker_wmi_pending:
            def retained_wmi():
                raise PrimarySemanticUnavailable('native worker WMI observation domain cleanup remains unresolved')
            attempt('worker_wmi', retained_wmi)
            return errors
        if self._worker_system_records_pending:
            def retained_system_records():
                raise PrimarySemanticUnavailable('native worker system record observation domain cleanup remains unresolved')
            attempt('worker_system_records', retained_system_records)
            return errors
        if self._worker_hardware_pending:
            def retained_hardware():
                raise PrimarySemanticUnavailable('native worker hardware observation domain cleanup remains unresolved')
            attempt('worker_hardware', retained_hardware)
            return errors
        if self._worker_process_records_pending:
            def retained_process_records():
                raise PrimarySemanticUnavailable('native worker process record observation domain cleanup remains unresolved')
            attempt('worker_process_records', retained_process_records)
            return errors
        if self._registrar is not None:
            def release_guest():
                snapshot = self._registrar.snapshot()
                if snapshot['bound']:
                    from .primary_sign_lifecycle import close_call
                    with close_call(self._signer, self, self._registrar):
                        if self._threads is not None:
                            with self._threads.closing_context():
                                self._registrar.close()
                        else:
                            self._registrar.close()
                elif snapshot['records']:
                    raise PrimarySemanticUnavailable('unbound Windows signer registrar retains unresolved guest callbacks')
                elif self._supplied_environment is not None:
                    self._registrar.abandon_fresh(owner=self)
            attempt('guest_callbacks', release_guest)
        if self._threads is not None:
            if not attempt('sdk_threads_finish', self._threads.finish_close):
                return errors
        if self._crt is not None:
            def release_crt():
                from .primary_crt_thread import cleanup
                runtime = self._signer.runtime
                failures = []
                try:
                    runtime._crt_call(cleanup)
                except BaseException as error:
                    failures.append(error)
                try:
                    self._crt.close()
                except BaseException as error:
                    failures.append(error)
                if len(failures) == 1:
                    raise failures[0]
                if failures:
                    raise BaseExceptionGroup('Windows signer CRT guest and backing cleanup failed', failures)
            attempt('crt_process', release_crt)
        if self._factory is not None:
            attempt('device_source', lambda: self._factory.source.close())
        if self._provider is not None:
            attempt('provider_observations', self._provider.close)
        if self._refresh is not None:
            attempt('refresh_observations', self._refresh.close)
        if self._files is not None:
            def release_files():
                self._files.close()
                if self._files.pending_handles or any(row.get('completion') == 'unknown' for row in self._files.cleanup_records):
                    raise PrimarySemanticUnavailable('Windows signer file cleanup retains pending handles or unknown native completion')
            attempt('device_files', release_files)
        consumers_closed = True
        if self._notification_environment is not None:
            def release_notification_environment():
                self._notification_environment.close()
                if self._signer is not None:
                    self._signer.runtime.notification_environment_observations = None
            consumers_closed = attempt('notification_environment', release_notification_environment)
        if self._independent_setup is not None:
            consumers_closed = attempt('independent_host129_source', self._independent_setup.close) and consumers_closed
        if self._core_observations is not None:
            consumers_closed = attempt('raw_core_observations', self._core_observations.close) and consumers_closed
        if self._caller is not None:
            completed = attempt('caller_and_bridge', self._caller.close)
        elif self._bridge is not None and not self._bridge_transferred:
            completed = attempt('untransferred_bridge', self._bridge.close)
        elif self._backend is not None:
            completed = attempt('backend_and_bridge', self._backend.close)
        else:
            completed = True
        if completed and self._bridge is not None:
            def verify_bridge():
                status = getattr(self._bridge, '_close_status', None)
                if status != 'unloaded' or not getattr(self._bridge, '_closed', False):
                    raise PrimarySemanticUnavailable('Windows signer bridge unload is not confirmed complete')
            completed = attempt('bridge_unload', verify_bridge)
        if self._ownimage_module is not None:
            if consumers_closed and completed:
                attempt('ownimage_module', self._ownimage_module.close)
            else:
                def retain_ownimage():
                    raise PrimarySemanticUnavailable('own-image retained until raw and caller consumers are confirmed closed')
                attempt('ownimage_module', retain_ownimage)
        if self._signer is not None:
            from .primary_module_sync import dispose_terminal as dispose_module_sync
            if errors:return errors
            if not attempt('host_module_sync', lambda: dispose_module_sync(self)):return errors
            port=getattr(self._signer.runtime,'_outer_sync_port',None)
            if port is not None:
                if errors:return errors
                if not attempt('host_outer_sync',port.dispose_terminal):return errors
            issuer=getattr(self._signer.runtime,'_primary_allocator_issuer',None)
            if issuer is not None:
                # Keep capability/storage if guest teardown failed; this is model storage retirement.
                if errors:return errors
                try:
                    issuer.retire()
                except BaseException as error:
                    errors.append(error)
                    self._cleanup_outcomes.append(dict(_error_summary(error),stage='allocator_storage',status='failed'))
                    return errors
                self._cleanup_outcomes.append({'stage':'allocator_storage','status':'completed'})
        return errors

    def close(self):
        self._check_owner()
        if self._state == 'closing':
            raise InputError('Windows signer close is already in progress')
        if self._busy:
            raise InputError('Windows signer cannot close during an active signing operation')
        if self._cleanup_failure is not None:
            raise self._cleanup_failure
        if self._state == 'closed':
            return None
        self._state = 'closing'
        try:
            with self._core_observations.phase('cleanup') if self._core_observations is not None else nullcontext():
                errors = self._release_resources()
        except BaseException as error:
            if self._supplied_environment is not None:
                self._state = 'cleanup_failed'
                self._cleanup_failure = error
                if self not in _RETAINED_SUPPLIED_OWNERS:
                    _RETAINED_SUPPLIED_OWNERS.append(self)
            raise
        if errors:
            self._state = 'cleanup_failed'
            if self._supplied_environment is not None and self not in _RETAINED_SUPPLIED_OWNERS:
                _RETAINED_SUPPLIED_OWNERS.append(self)
            self._cleanup_failure = BaseExceptionGroup('Windows signer cleanup failed', errors)
            self._cleanup_failure.windows_signer_diagnostics = self.diagnostics
            self._cleanup_failure.successful_operation_result = self._successful_operation_result
            raise self._cleanup_failure
        self._state = 'closed'
        return None

    def __enter__(self):
        self._check_owner()
        if self._state != 'open' or self._busy:
            raise InputError('Windows signer context requires an idle open owner')
        return self

    def __exit__(self, exception_type, exception, traceback):
        try:
            self.close()
        except BaseException as cleanup:
            if exception is not None:
                failure = BaseExceptionGroup('Windows signer operation and cleanup failed', [exception, cleanup])
                failure.successful_operation_result = self._successful_operation_result
                failure.windows_signer_diagnostics = self.diagnostics
                raise failure
            raise
        return False

    @property
    def diagnostics(self):
        records = [] if self._caller is None else self._caller.records
        pending = () if self._files is None else self._files.pending_handles
        file_cleanup = [] if self._files is None else self._files.cleanup_records
        registrar = None if self._registrar is None else self._registrar.snapshot()
        if registrar is not None:
            failure = registrar.pop('failure', None)
            registrar['failure_message_sha256'] = None if failure is None else hashlib.sha256(failure.encode('utf-8', 'replace')).hexdigest()
        value = {'state': self._state, 'process_id': self._pid, 'thread_id': self._thread,
                 'calls': 0 if self._signer is None else self._signer.calls,
                 'signer_failed': None if self._signer is None else self._signer.failed,
                 'raw_core_observations': None if self._core_observations is None else self._core_observations.diagnostics,
                 'ownimage_module': None if self._ownimage_module is None else self._ownimage_module.diagnostics,
                 'notification_environment': None if self._notification_environment is None else self._notification_environment.diagnostics,
                 'storage_root': str(self._storage_root), 'host_profile_sha256': self._profile_hash,
                 'initial_stack': self._stack_kind,
                 'caller': {'request_count': len(records), 'api_counts': dict(Counter(row['api'] for row in records)),
                            'status_counts': dict(Counter(row['status'] for row in records)),
                            'capture_sequences': [row['capture_provenance']['sequence'] for row in records if row.get('capture_provenance')]},
                 'registrar': registrar,
                 'files': {'pending_handle_count': len(pending), 'pending_by_kind': dict(Counter(item[0] for item in pending)),
                           'cleanup_records': file_cleanup,
                           'unknown_completion_count': sum(row.get('completion') == 'unknown' for row in file_cleanup)},
                 'bridge': {'closed': None if self._bridge is None else getattr(self._bridge, '_closed', None),
                            'unload_status': None if self._bridge is None else getattr(self._bridge, '_close_status', None)},
                 'cleanup_outcomes': self._cleanup_outcomes,
                 'operation_outcomes': self._operation_outcomes,
                 'sdk_threads': None if self._threads is None else self._threads.snapshot(),
                 'retained_worker_wmi_domains': len(self._worker_wmi_pending),
                 'retained_worker_hardware_domains': len(self._worker_hardware_pending),
                 'retained_worker_process_record_domains': len(self._worker_process_records_pending),
                 'retained_worker_system_record_domains': len(self._worker_system_records_pending),
                 'crt': None if self._crt is None else self._crt.snapshot(),
                 'operation_error': None if self._operation_failure is None else _error_summary(self._operation_failure),
                 'provenance': {'guest': 'fixed-image PrimarySigner and explicit model allocation/frame services',
                                'native': 'actual own-helper Windows caller, creation-disabled device source, owned storage'},
                 'factory_cache_length': 0 if self._factory is None else len(self._factory.cached_value)}
        return copy.deepcopy(value)
