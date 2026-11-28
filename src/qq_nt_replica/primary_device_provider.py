from dataclasses import dataclass, replace

from .errors import InputError
from .primary_device import CapiObservation, checkpoint_hardware_invalidates, checkpoint_needs_update, decode_checkpoint, decode_profile, device_environment_classification, device_public_key_material, encode_device_body, initial_device_profile, invalid_checkpoint_record, mix_device_bytes, new_checkpoint_record
from .primary_device_storage import DirectoryCheckpointStorage
from .primary_sign import filetime_seconds
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows import WindowsDeviceSource, collect_device_environment, collect_device_observations


_UNOBSERVED = object()


class DeviceRefreshGate:
    def __init__(self, flags=0, *, resolve_receiver=None):
        if type(flags) is not int or not 0 <= flags <= 0xFF:
            raise InputError("device refresh gate flags must be an observed byte")
        if resolve_receiver is not None and not callable(resolve_receiver):
            raise InputError("device refresh receiver resolver must be callable or explicitly absent")
        self.flags = flags
        self.resolve_receiver = resolve_receiver
        self._native = False

    @classmethod
    def native(cls):
        gate = cls()
        gate._native = True
        return gate

    def _resolve(self, runtime):
        receiver = None if self.resolve_receiver is None else self.resolve_receiver()
        if receiver is not None and not callable(receiver):
            raise InputError("device refresh receiver must expose its slot10 observation adapter")
        runtime.events.append(("1CE2B70.receiver_resolve", receiver is not None))
        return receiver

    def _call(self, runtime):
        receiver = self._resolve(runtime)
        if receiver is None:
            raise PrimarySemanticUnavailable("device refresh receiver disappeared before its virtual call")
        value = receiver()
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise InputError("device refresh slot10 return must be an observed DWORD")
        runtime.events.append(("1CE2B70.receiver_slot10", value))
        return value

    def allows_refresh(self, runtime):
        if self._native:
            from .primary_sdk import receiver_gate
            return bool(receiver_gate(runtime).value)
        if self._resolve(runtime) is not None and self._call(runtime) != 0:
            return self._call(runtime) == 1
        if type(self.flags) is not int or not 0 <= self.flags <= 0xFF:
            raise InputError("device refresh gate flags must remain an observed byte")
        return bool(self.flags & 1)


@dataclass(frozen=True)
class DeviceResult:
    value: bytes
    success: bool
    secondary: int
    checkpoint_errors: tuple[int, ...] = ()


class DeviceFactory:
    def __init__(self, source, storage, environment, *, close_source=False, injected_material=None,
                 refresh_gate=None, refresh_observer=_UNOBSERVED, public_key_source="observed",
                 device_time_source="observed", enumeration_source="observed", allow_capi_creation=False, display_environment="source_frame", adapter_environment="source_sparse"):
        if refresh_gate is not None and not isinstance(refresh_gate, DeviceRefreshGate):
            raise InputError("device refresh gate must be explicitly bound")
        if refresh_observer is not _UNOBSERVED and refresh_observer is not None and not callable(refresh_observer):
            raise InputError("device refresh observer must be callable or explicitly absent")
        if public_key_source not in ("observed", "raw_os", "windows"):
            raise InputError("device public-key source must be observed, raw_os or windows")
        if type(allow_capi_creation) is not bool:
            raise InputError("device CAPI creation policy must be an explicit boolean")
        self.public_key_source = public_key_source
        self.allow_capi_creation = allow_capi_creation
        if enumeration_source not in ("observed", "raw_os", "windows"):
            raise InputError("device enumeration source must be observed, raw_os or windows")
        self.enumeration_source = enumeration_source
        if device_time_source not in ("observed", "filetime_seconds_projection"):
            raise InputError("device time source must be observed or filetime_seconds_projection")
        self.device_time_source = device_time_source
        self.source = source
        self.storage = storage
        self.environment = environment
        self.close_source = close_source
        self.injected_material = injected_material
        self.cached_value = b""
        self.last_result = None
        self.refresh_gate = refresh_gate
        self.refresh_observer = refresh_observer
        self.failure_reported = False
        self.select_display_environment(display_environment)
        self.select_adapter_environment(adapter_environment)

    @classmethod
    def windows(cls, environment, *, storage_root=None, uuid_observation=None, injected_material=None,
                refresh_gate=None, refresh_observer=_UNOBSERVED, enumeration_source="observed",
                public_key_source="observed", device_time_source="observed", allow_capi_creation=False, display_environment="source_frame", adapter_environment="source_sparse"):
        storage = DirectoryCheckpointStorage(storage_root) if storage_root is not None else None
        return cls(WindowsDeviceSource(uuid_observation=uuid_observation), storage, environment,
                   close_source=True, injected_material=injected_material,
                   refresh_gate=refresh_gate, refresh_observer=refresh_observer,
                   enumeration_source=enumeration_source, public_key_source=public_key_source,
                   device_time_source=device_time_source, allow_capi_creation=allow_capi_creation, display_environment=display_environment, adapter_environment=adapter_environment)

    def select_display_environment(self, mode):
        if mode not in ('source_frame', 'independent_windows') or type(mode) is not str:
            raise InputError('display environment must explicitly select source_frame or independent_windows')
        if self.cached_value or self.last_result is not None:
            raise InputError('display environment must be selected before producing device material')
        self.display_environment = mode

    @property
    def display_qualifications(self):
        if self.display_environment == 'independent_windows':
            from .primary_windows_display_environment import qualification
            return qualification()
        return dict(origin='STRICT_SOURCE_FRAME', original_frame_equivalence='REQUIRES_SOURCE_INPUTS',
            source_request_association='NOT_ASSOCIATED', source_profile_association='NOT_ASSOCIATED',
            same_request_qualification=False, full96_qualification=False)

    def select_adapter_environment(self, mode):
        from .primary_windows_device_hardware import _adapter_mode
        if self.cached_value or self.last_result is not None:
            raise InputError('adapter environment must be selected before producing device material')
        self.adapter_environment = _adapter_mode(mode)

    @property
    def adapter_qualifications(self):
        from .primary_windows_device_hardware import adapter_qualification
        return adapter_qualification(self.adapter_environment)

    def reset(self):
        self.cached_value = b""

    def get(self, runtime=None):
        if (self.enumeration_source, self.public_key_source) == ('raw_os', 'raw_os'):
            from .primary_material import device_factory_value
            return device_factory_value(self, runtime)
        if self.cached_value:
            return self.cached_value
        return self._refresh(runtime)

    def get_for_refresh(self, runtime):
        if (self.enumeration_source, self.public_key_source) == ('raw_os', 'raw_os'):
            from .primary_device_records import _locked_singleton
            from .primary_logger import _String
            from .primary_worker_consumer import _invoke
            if runtime is None or getattr(getattr(runtime, 'provider_profile', None), 'device_factory', None) is not self:
                raise PrimarySemanticUnavailable('native refresh requires its matching caller runtime profile')
            owner = _locked_singleton(runtime, 0x6751838, 0x67516A0, 32, 0x1BE5CD0)
            _invoke(runtime, 0x1BE6150, owner)
            return _String.read(runtime, owner).value()
        if self.cached_value:
            if self.refresh_gate is None:
                raise PrimarySemanticUnavailable("device slot0 refresh needs its1BE6150/1CE2B70 gate binding")
            if not self.refresh_gate.allows_refresh(runtime):
                runtime.events.append(("1BE6A5D.device_cached_refresh_rejected", len(self.cached_value)))
                return self.cached_value
        return self._refresh(runtime)

    def _refresh(self, runtime):
        try:
            result = self._produce()
            self.last_result = result
        finally:
            if self.close_source:
                self.source.close()
        self.cached_value = result.value if result.success else b""
        if runtime is not None:
            runtime.events.append(("1BE6150.device_refresh_publish", result.success, len(self.cached_value)))
        if result.success:
            observer = self.refresh_observer
            if observer is _UNOBSERVED:
                raise PrimarySemanticUnavailable("device refresh cache was published;1BE5B30 observer binding is unobserved")
            if observer is not None:
                observer(b"qq_o_xd", self.cached_value)
            if runtime is not None:
                runtime.events.append(("1BE5B30.device_refresh_observer_return", observer is not None))
        elif not self.failure_reported:
            if runtime is None:
                raise PrimarySemanticUnavailable("device first failure reporting needs its telemetry runtime")
            from .primary_postfetch import ProviderTelemetryRecord
            from .primary_telemetry import ProviderTelemetryState
            if runtime.provider_telemetry is None:
                runtime.provider_telemetry = ProviderTelemetryState()
            runtime.provider_telemetry.consume(runtime, ProviderTelemetryRecord.device_failure(result.secondary),
                                               force=True)
            self.failure_reported = True
            runtime.events.append(("1BE6A37.device_failure_report_commit",))
        return self.cached_value

    def _checkpoint_storage(self):
        storage = self.storage
        if storage is None:
            try:
                storage = DirectoryCheckpointStorage(self.source.common_appdata())
            except OSError as error:
                code = getattr(error, "winerror", None) or error.errno or 0
                return None, (0xE << 32) | (code & 0xFFFFFFFF)
        try:
            storage.ensure_directory()
        except OSError as error:
            code = getattr(error, "winerror", None) or error.errno or 0
            return None, (0x17 << 32) | (code & 0xFFFFFFFF)
        return storage, None

    def _produce(self):
        if self.enumeration_source != "observed" or self.public_key_source != "observed":
            raise PrimarySemanticUnavailable("raw OS device production requires the shared native runtime and ordered API observations")
        return produce_observed_device_value(self.source, self.environment, self._checkpoint_storage,
                                             injected_material=self.injected_material)


def produce_observed_device_value(source, environment, checkpoint_storage, *, injected_material=None):
    """Shared complete observed-input key25 policy, including storage effects."""
    observations = collect_device_observations(source)
    if injected_material is not None:
        observations = replace(observations, injected_material=injected_material)
    hardware = initial_device_profile(observations)
    storage, storage_error = checkpoint_storage()
    read = storage.read() if storage_error is None else None
    decoded = decode_checkpoint(read.value) if read is not None and read.value is not None else None
    record = decoded.record if decoded is not None and decoded.success else None
    flagged = bool(record[81] & 1) if record is not None else False
    errors = []

    def save(value):
        target, error = checkpoint_storage()
        if error is not None:
            errors.append(error >> 32)
            return
        result = target.write_record(value, environment.random_bytes)
        if not result.success:
            errors.append(result.error)

    def acquire():
        capi = source.capi_public_key()
        if not isinstance(capi, CapiObservation):
            raise InputError("device CAPI source must return its structured public-key observation")
        if capi.error_code == 0:
            return device_public_key_material(capi.public_key_bits), capi.method, 0
        target, error = checkpoint_storage()
        if error is not None:
            return None, 0, error
        profile = (target.read_profile(random_bytes=environment.random_bytes)
                   if isinstance(target, DirectoryCheckpointStorage) else target.read_profile())
        if profile.value is None:
            return None, 0, (profile.internal_error << 32) | ((profile.error or 0) & 0xFFFFFFFF)
        material = decode_profile(profile.value)
        if material is None:
            return None, 0, (0x15 << 32) | ((profile.error or 0) & 0xFFFFFFFF)
        return material, 3 if profile.created else 4, capi.error_code

    if record is not None and checkpoint_hardware_invalidates(record, hardware):
        preliminary, method, secondary = acquire()
        if preliminary is not None and mix_device_bytes(preliminary).to_bytes(8, "little") == record[72:80]:
            flagged = True
            record = invalid_checkpoint_record(hardware)
            save(record)
    material, method, secondary = acquire()
    if material is None:
        return DeviceResult(b"", False, secondary, tuple(errors))
    if checkpoint_needs_update(record, hardware, material, flagged=flagged):
        save(new_checkpoint_record(hardware, material, method=method, flagged=flagged))
    classification = device_environment_classification(collect_device_environment(
        source, observations.cpuid[0x40000000]))
    body = bytes([method | (0x80 if flagged else 0), classification]) + material
    clock = getattr(environment, 'time_seconds', None)
    seconds = (clock() if clock is not None else filetime_seconds(environment.filetime())) & 0xFFFFFFFF
    value = encode_device_body(body, seconds, environment.random_bytes)
    return DeviceResult(value, True, secondary, tuple(errors))
