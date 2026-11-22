






import hashlib
import json
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from .errors import InputError, LibraryLimitError
from .primary_vm import PrimarySemanticUnavailable, PrimaryProgramLimit, decode_program, signed
from .primary_memory import UnknownMemory


_DATA = Path(__file__).with_name("data") / "primary_sign_qq52230"
_PROGRAMS = {
    "sdk-table-init": "999cd6aa948d3562adac0b15dcd9985a2edfe600faa4e643e6a8da7ad837e4fa",
    "entry-prepare": "da98f1ee6c39ffa41336ddc19681e0f1aaefbbdfa585ebda02442f3dbe0a5370",
    "main": "28afc919ac1b8783ecbe6ddea52ebba5ea41492573609fa7cf634467ecaa00b9",
    "forward": "669e5e094d7d945c67528128ed3c9899dda6889c86975eac3f930250f7c241fd",
    "singleton-init": "8c1a0793046837e3592811b2f21af762c5e0b57a260b818e05671c0176dc8991",
    "singleton-destroy": "d9a05940328900460d741f9030bcf17c2d0422dbab7cc4d60d398831e4ae55d4",
    "buffer-init": "b400646daeef6a35eb2782e2e677dcd93df186ff97a8fff6bf0f14f2a2557690",
    "primary-setup": "e409888bf8baf3a341cecec5db3566f71d8831433e8c0d93d9208f78025de80f",
    "host97": "189a179b4a0d375c4b01ff2af3b77452213c0efe07153cd3910aff34a55b5875",
    "cocos-init": "877181b3d8ae7cc35554d44c68646088f597bd46508d3c7f5679f73c84e6ef8b",
    "cocos-crypt": "aa01fb02ea3db8689cb480cbe69e5050bffc478af8e9b1bdf7740c174af4c2fb",
    "cocos-publish": "6b766ef829393fb9b18b00e80ab2dd2f05005f81d3a5ab6c434ad4be386fe9bf",
    "status-audit": "2db8aba84b5b353914b4b88a9c97043fff8700163a0b4c308c8e933431707ffc",
    "host129": "c66f47d8bada528e0b66289d9b18a1c0854ec7522c8344f8cded9c64356b803c",
    "host129-prepare": "0c413db7cc56ecdbb6f14b0f9e0c63444b06fa7aab13643db353d0f105682540",
    "host129-select": "f6fde5d2d386a51ac92f65329d946b0a53adcfdea554d996c6e38082802e33f1",
    "ecrypt-transform": "f2f9c6021b5cc0c07b746bbe21c5a911a4322c61aa9e3acebbb621f4d01ae89c",
    "ecrypt-keysetup": "87f37c2eab0c576a7ddb07e192b7d765bc9b726dfff6c3707cf9fc280d0e1504",
    "ecrypt-packet": "13c71679754503e1e750498593c617eb29a040a22be333c2ffefb1b081bfecb3",
    "ecrypt-blocks": "e5b01d30e582e8d2c84c303a4a5a477360ac35f215c259116c5b176d1add18fb",
    "material-block": "8a073659c987221badb188064e18900a68cb35039e55753ed52fa1c51fd44cea",
    "material-state": "633f3a4bc33cc5cef8a916d55dd27835342364835e0a6ba1a496fbfa1658298d",
    "source2581": "5aa7b463d06b2d1d99d228f4d1ff81094e5b6c2fda97683a3cf656699c7f846a",
    "source2581-setter": "3c435a1c8d971af093c2e45eab06b681418b0c9fd6b41ff48272b5fbea243bfc",
    "source2582": "d8646e3fcada3a9a52c8b6ef36d919b9f4c877938b725d4b9b9071d60db1fbd8",
    "setter3592244": "a86c9397ee9d51220153a1a18bcb8b7f1a41fdc1af508a2df8289f22e57ceb78",
    "source2583": "cddde1eb11604d2ed98f936f7e84c33f6442423948fa3f2a480ac1acea9ed490",
    "token-setter": "5fa8d78f68f7fe6d6081d1587f521e6aa2a731d9afa8f2158c21ba9aff6e112a",
    "token-expire": "952cdf6c4d6dcd3595627de08fe71a7a34925ec69a83a7ad996f5e445fa62522",
    "device-records": "9af888fbbf3550c113ef1a0f3ca802cc5dc1c9ae7429e7c091dc225328801fdb",
    "device-mix": "7c2576cda7040248193a52fc8482798b30ba4b325ddb8d416a5840579bca0b60",
}
_HOST_BANKS = {"entry-prepare": 0x6428950,
               "primary-setup": 0x64289C0, "host97": 0x6428900, "host129": 0x6428970,
               "ecrypt-transform": 0x64288D0, "ecrypt-packet": 0x64288C8,
               "ecrypt-blocks": 0x64288C0, "material-block": 0x6556EC0,
               "material-state": 0x6556EA0, "cocos-crypt": 0x655BC20,
               "cocos-publish": 0x655BD30, "source2581": 0x655BD50, "source2583": 0x655BD90,
               "source2581-setter": 0x6556F98,
               "source2582": 0x655BD70,
               "token-setter": 0x6556FD0, "token-expire": 0x6556F20,
               "device-records": 0x6428A20, "device-mix": 0x6556FF0,
               "singleton-destroy": 0x6557000}
_COMMANDS = (
    b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginUnusualDevice",
    b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin",
    b"trpc.login.ecdh.EcdhService.SsoNTLoginTGTExchangeFastLogin",
    b"trpc.login.ecdh.EcdhService.SsoNTLoginEasyLoginUnusualDevice",
    b"trpc.login.ecdh.EcdhService.SsoNTLoginAuthLogin",
    b"trpc.login.ecdh.EcdhService.SsoNTLoginOptimusLogin",
    b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginNewDevice",
    b"trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin",
    b"trpc.login.ecdh.EcdhService.SsoQRLoginScanQr",
    b"wtlogin.exchange_emp", b"wtlogin.qrlogin", b"wtlogin.login",
    b"810_9", b"2088", b"2102",
)
_FOLD = bytes(value + 32 if 65 <= value <= 90 else value for value in range(256))
_MASK64 = (1 << 64) - 1


def install_singleton_destroy_image(memory, image_base):
    hosts = (0x3592178, 0x3EB2680, 0x359219F, 0x3E94F90)
    raw = b''.join((image_base + rva).to_bytes(8, 'little') for rva in hosts)
    first = cursor = image_base + 0x6557000
    while cursor < first + len(raw):
        containing = next((region for region in memory._regions
                           if region.address <= cursor < region.address + len(region.data)), None)
        if containing is not None:
            cursor = min(first + len(raw), containing.address + len(containing.data))
            continue
        end = min([first + len(raw)] + [region.address for region in memory._regions
                                       if region.address > cursor])
        memory.map(cursor, bytearray(raw[cursor - first:end - first]),
                   name='fixed singleton destructor host bank', initialized=True)
        cursor = end


def _install_uin_wrapper_hosts(memory, image_base):
    raw = b''.join((image_base + rva).to_bytes(8, 'little') for rva in (0x3592167, 0x3EB2680, 0x3EB1FE0))
    first = cursor = image_base + 0x655BD70
    while cursor < first + len(raw):
        containing = next((region for region in memory._regions
                           if region.address <= cursor < region.address + len(region.data)), None)
        if containing is not None:
            cursor = min(first + len(raw), containing.address + len(containing.data))
            continue
        end = min([first + len(raw)] + [region.address for region in memory._regions if region.address > cursor])
        memory.map(cursor, bytearray(raw[cursor - first:end - first]), name='fixed UIN wrapper host bank', initialized=True)
        cursor = end


def install_sdk_initializer_image(memory, image_base):
    hosts = (0x677DFB0, 0x1D2CDD4, 0x618CB00, 0x3EB1FE0, 0x3EB2680)
    memory.map(image_base + 0x618CF50,
               b''.join((image_base + rva).to_bytes(8, 'little') for rva in hosts),
               name="fixed SDK initializer host bank", initialized=True)


def filetime_seconds(filetime: int) -> int:

    if type(filetime) is not int or not 0 <= filetime <= _MASK64:
        raise InputError("FILETIME service value must be unsigned64")
    x = signed(filetime + 0xFE624E212AC18000, 64)
    high = (signed(0xD6BF94D5E57A42BD, 64) * x) >> 64
    q0 = signed(high + x, 64) >> 23
    q = signed(q0 + ((q0 & _MASK64) >> 63), 64)
    return -1 if q > 0x793582AFF else q


def qpc_nanoseconds(counter: int, frequency: int) -> int:

    if any(type(value) is not int or not 0 <= value <= _MASK64 for value in (counter, frequency)):
        raise InputError("QPC service values must be unsigned64")

    def divpair(x, f):
        if (x | f) >> 32 == 0:
            if f == 0:
                raise PrimaryProgramLimit("native QPC DIV32 by zero")
            return divmod(x, f)
        x, f = signed(x, 64), signed(f, 64)
        if f == 0 or (x == -(1 << 63) and f == -1):
            raise PrimaryProgramLimit("native QPC IDIV64 fault")
        q = (abs(x) // abs(f)) * (-1 if (x < 0) != (f < 0) else 1)
        return q, x - q * f

    q1, r1 = divpair(counter, frequency)
    part, temporary = (q1 * 1_000_000_000) & _MASK64, (r1 * 1_000_000_000) & _MASK64
    q2, _ = divpair(temporary, frequency)
    return (part + q2) & _MASK64


def arena_reservation(program) -> int:

    descriptor = program.descriptor & 0x0FFFFFFF
    count = (descriptor >> 16) & 0xFFF
    size = descriptor + count - (count << 16) + 1
    if not 0 < size <= 0x7FFFFFFF:
        raise PrimaryProgramLimit("native arena reservation outside Python nonwrapping support")
    return size


def scaled_qpc_nanoseconds(counter: int, frequency: int) -> int:
    if any(type(value) is not int or not 0 <= value <= _MASK64 for value in (counter, frequency)):
        raise InputError("QPC service values must be unsigned64")
    numerator, denominator = signed(counter * 1_000_000_000, 64), signed(frequency, 64)
    if denominator == 0 or (numerator == -(1 << 63) and denominator == -1):
        raise PrimaryProgramLimit("native scaled QPC IDIV64 fault")
    quotient = abs(numerator) // abs(denominator)
    if (numerator < 0) != (denominator < 0):
        quotient = -quotient
    return quotient & _MASK64


@dataclass(frozen=True)
class PrimaryFrame:

    program: str
    cells: int
    arena: int
    arena_size: int


class StacktraceStateDomain(Enum):
    COLD_PE = 'cold-pe'


class PrimaryRuntime:










    def __init__(self, memory, *, filetimes, qpc, entropy, allocations, frames,
                 tls_epoch_address: int, image_base: int, bcrypt=(), crt_thread_address=None,
                 temporaries=(), current_process=None, module_lookup=None,
                 procedure_lookup=None, cursor_position=None, stack_capture=None,
                 module_from_address=None, module_filename=None, path_filename=None,
                 path_strip=None, find_window=None, window_visible=None, host2252_normal=False,
                  retain_frames=True, tls_base_address=None, provider_material=None,
                  provider_environment=None, provider_profile=None, postfetch_start_errors=(),
                   telemetry_metadata_providers=None, postfetch_crt_seed=None,
                   critical_section_init=None, exit_registration=(), create_thread=None,
                   worker_observations=None, worker_imports=None, logger_output=None, worker_device_records=None,
                   request_capi=None, request_transport=None, device_configuration=None, device_configuration_read=None,
                   response_feature_initial=None, module_filename_aliases=(), stderr=None, clock_apis=None,
                    primary_core=False, process_material=None, program_context=None, raw_core_observations=None,
                    host2252_stage1_retry=False, host2252_m_read_budget=1024,
                    host2252_retry_mode='retained', host2252_stage2_g_retry=False, host2252_g_read_budget=4096,
                    host2252_final_f_retry=False, host2252_f_read_budget=4096,
                    host2252_pair_m_retry=False, host2252_pair_m_read_budget=4096,
                    host2252_control_m=False, host129_counter_reads=None,
                    host129_clock_service_returns=None, host129_entropy_service_returns=None,
                    singleton_producer_inputs=None, stacktrace_state_domain=None, main_clock_inputs=None,
                    host129_source_clock_inputs=None, crt_error_storage=None, scalar_sse_state=None, iv_control=None,
                    host129_raw_inputs=None, warm_core_container_inputs=None, main_environment_inputs=None,
                    primary_backend='reference'):
        if type(primary_backend) is not str or primary_backend not in ('reference', 'direct'):
            raise InputError('primary_backend must be reference or direct')
        self.primary_backend = primary_backend
        self.memory, self.image_base = memory, image_base
        _install_uin_wrapper_hosts(memory, image_base)
        from .primary_ecrypt import IVSetupControl
        if iv_control is not None and type(iv_control) is not IVSetupControl:
            raise InputError('runtime IV control requires IVSetupControl or None')
        self.iv_control = iv_control
        from .primary_x86_float import ScalarSSEState
        if scalar_sse_state is not None and type(scalar_sse_state) is not ScalarSSEState:
            raise InputError("runtime scalar SSE state requires explicit ScalarSSEState or unknown None")
        self.scalar_sse_state = scalar_sse_state
        from .primary_crt_error_map import CRTErrorStorage
        if crt_error_storage is not None and type(crt_error_storage) is not CRTErrorStorage:
            raise InputError('CRT error storage requires an explicit source domain')
        self.crt_error_storage = crt_error_storage
        if stacktrace_state_domain is not None and type(stacktrace_state_domain) is not StacktraceStateDomain:
            raise InputError('stacktrace state domain requires an explicit model enum')
        self._singleton_producer_binding = None
        self._host129_multicall_binding = None
        self._host129_api_binding = None
        self._host129_api_attached = False
        self._host129_main_completion = None
        self._host129_retirement = None
        self._host129_public_exit = None
        if host129_raw_inputs is not None and any(value is not None for value in
                (host129_source_clock_inputs, host129_counter_reads, host129_clock_service_returns, host129_entropy_service_returns)):
            raise InputError('RAW3 cannot replace source or legacy host129 inputs')
        from .primary_host129_raw_inputs import _Raw3Binding
        self._host129_raw_binding = None if host129_raw_inputs is None else _Raw3Binding(host129_raw_inputs, self)
        from .primary_host129_source_clock_inputs import _SourceHost129ClockBinding
        if host129_source_clock_inputs is not None and any(value is not None for value in
                (host129_counter_reads, host129_clock_service_returns, host129_entropy_service_returns)):
            raise InputError('HOST129_SOURCE_CLOCK_INPUT_MISMATCH')
        self._host129_source_clock_binding = (None if host129_source_clock_inputs is None else
                                             _SourceHost129ClockBinding(host129_source_clock_inputs, self))
        from .primary_host129_inputs import _ClockServiceBinding, _CounterBinding, _EntropyServiceBinding
        self._host129_counter_binding = (None if host129_counter_reads is None else
                                         _CounterBinding(host129_counter_reads, self))
        self._host129_clock_service_binding = (None if host129_clock_service_returns is None else
                                              _ClockServiceBinding(host129_clock_service_returns, self))
        self._host129_entropy_service_binding = (None if host129_entropy_service_returns is None else
                                                _EntropyServiceBinding(host129_entropy_service_returns, self))
        self.raw_core_observations = raw_core_observations
        if raw_core_observations is not None:
            raw_core_observations.bind(self)
        if program_context is not None and not callable(program_context):
            raise InputError('program address context must be callable or absent')
        self._program_context = program_context
        if (not isinstance(module_filename_aliases, tuple) or
                any(type(address) is not int or not 0 < address <= _MASK64
                    for address in module_filename_aliases)):
            raise InputError("module filename aliases require explicit pointer-width function addresses")
        self.module_filename_aliases = frozenset(module_filename_aliases)
        if response_feature_initial is not None and (not isinstance(response_feature_initial, bytes) or len(response_feature_initial) != 8):
            raise InputError("response feature stack input requires eight explicit bytes or unobserved storage")
        self.response_feature_initial = response_feature_initial
        stream = lambda value: value if callable(value) else iter(value)
        self._filetimes, self._qpc = stream(filetimes), stream(qpc)
        self._clock_apis = None if clock_apis is None else stream(clock_apis)
        self._entropy, self._allocations, self._frames = stream(entropy), stream(allocations), stream(frames)
        self._bcrypt = stream(bcrypt)
        if stderr is not None and not callable(stderr):
            raise InputError("CRT stderr observer must be callable or absent")
        self.stderr = stderr
        self._temporaries = stream(temporaries)
        self._postfetch_start_errors = stream(postfetch_start_errors)
        self._exit_registration = stream(exit_registration)
        self.exit_callbacks = []
        self.thread_starts = []
        from .primary_worker import WorkerObservations
        if worker_observations is not None and not isinstance(worker_observations, WorkerObservations):
            raise InputError('SDK worker requires raw WorkerObservations')
        self.worker_observations = worker_observations
        from .primary_material_process import ProcessMaterialObservations
        if process_material is not None and not isinstance(process_material, ProcessMaterialObservations):
            raise InputError('process material requires explicit ProcessMaterialObservations')
        self.process_material = process_material
        from .primary_logger import LoggerOutput
        if logger_output is not None and not isinstance(logger_output, LoggerOutput):
            raise InputError('logger output requires an explicit LoggerOutput binding')
        self.logger_output = logger_output
        from .primary_worker_consumer import DeviceRecordsBinding
        if worker_device_records is not None and not isinstance(worker_device_records, DeviceRecordsBinding):
            raise InputError('device records require an explicit DeviceRecordsBinding')
        self.worker_device_records = worker_device_records
        from .primary_device_identifiers import DeviceConfigurationBinding
        if device_configuration is not None and not isinstance(device_configuration, DeviceConfigurationBinding):
            raise InputError('device configuration requires an explicit DeviceConfigurationBinding')
        self.device_configuration = device_configuration
        from .primary_device_provenance import DeviceConfigurationReadBinding
        if device_configuration_read is not None and not isinstance(device_configuration_read, DeviceConfigurationReadBinding):
            raise InputError('device configuration reader requires an explicit DeviceConfigurationReadBinding')
        self.device_configuration_read = device_configuration_read
        self.request_capi = request_capi
        from .primary_request_transport import RequestTransportBinding
        if request_transport is not None and not isinstance(request_transport, RequestTransportBinding):
            raise InputError('request transport requires an explicit RequestTransportBinding')
        self.request_transport = request_transport
        self.worker_imports = dict(worker_imports or {})
        if any(not isinstance(name, str) or type(value) is not int or not 0 < value <= _MASK64
               for name, value in self.worker_imports.items()):
            raise InputError('SDK worker imports require explicit resolved function addresses')
        if critical_section_init is not None and (type(critical_section_init) is not int or
                                                  not 0 < critical_section_init <= _MASK64):
            raise InputError("critical-section initialization needs an explicit resolved function address")
        self.critical_section_init_address = critical_section_init
        self.postfetch_task = None
        from .primary_telemetry import TelemetryMetadataProviders
        if (telemetry_metadata_providers is not None and
                not isinstance(telemetry_metadata_providers, TelemetryMetadataProviders)):
            raise InputError("telemetry metadata requires explicit provider bindings")
        if postfetch_crt_seed is not None and (type(postfetch_crt_seed) is not int or
                                              not 0 <= postfetch_crt_seed <= 0xFFFFFFFF):
            raise InputError("postfetch worker CRT seed must be unsigned32 or unobserved")
        self.telemetry_metadata_providers = telemetry_metadata_providers
        self.postfetch_crt_seed = postfetch_crt_seed
        self.provider_telemetry = None
        if type(retain_frames) is not bool:
            raise InputError("VM frame retention must be an explicit boolean")
        self.retain_frames = retain_frames
        if type(host2252_normal) is not bool:
            raise InputError("host2252 normal-domain premise selection must be explicit boolean")
        self.host2252_normal = host2252_normal
        if type(host2252_stage1_retry) is not bool:
            raise InputError('host2252 stage1 retry premise must be explicit boolean')
        if type(host2252_m_read_budget) is not int or host2252_m_read_budget < 1:
            raise InputError('host2252 M-read budget must be a positive integer')
        if type(host2252_control_m) is not bool:
            raise InputError('host2252 control M option must be bool')
        self.host2252_control_m = host2252_control_m
        self.host2252_stage1_retry = host2252_stage1_retry
        self.host2252_m_read_budget = host2252_m_read_budget
        if type(host2252_stage2_g_retry) is not bool:
            raise InputError('host2252 stage2 G retry premise must be explicit boolean')
        if type(host2252_g_read_budget) is not int or host2252_g_read_budget < 1:
            raise InputError('host2252 G-read budget must be a positive integer')
        if type(host2252_pair_m_retry) is not bool:
            raise InputError('host2252 pair M retry option must be bool')
        if type(host2252_pair_m_read_budget) is not int or host2252_pair_m_read_budget < 1:
            raise InputError('host2252 pair M-read budget must be a positive integer')
        if host2252_pair_m_retry and not host2252_stage2_g_retry:
            raise InputError('host2252 pair M retry requires enabled G retry')
        self.host2252_pair_m_retry = host2252_pair_m_retry
        self.host2252_pair_m_read_budget = host2252_pair_m_read_budget
        self.host2252_stage2_g_retry = host2252_stage2_g_retry
        self.host2252_g_read_budget = host2252_g_read_budget
        if type(host2252_final_f_retry) is not bool:
            raise InputError('host2252 final F retry premise must be explicit boolean')
        if type(host2252_f_read_budget) is not int or host2252_f_read_budget < 1:
            raise InputError('host2252 F-read budget must be a positive integer')
        self.host2252_final_f_retry = host2252_final_f_retry
        self.host2252_f_read_budget = host2252_f_read_budget
        self._host2252_pending = None
        if host2252_retry_mode not in ('retained', 'synchronous'):
            raise InputError('host2252 retry mode must be retained or synchronous')
        self.host2252_retry_mode = host2252_retry_mode
        self._active_main = None
        self._execute_thread = None
        self._execute_depth = 0
        self._program_calls = []
        self._main_generation = 0
        self._active_failed = False
        self._owned_frame_regions = None
        self.cleanup_errors = []
        self.host2252_diagnostics = []
        if type(primary_core) is not bool:
            raise InputError("primary core selection must be an explicit boolean")
        self.primary_core = primary_core
        if current_process is not None:
            if (not isinstance(current_process, tuple) or len(current_process) != 2 or
                    type(current_process[0]) is not int or not 0 < current_process[0] < 1 << 64 or
                    type(current_process[1]) is not int or not 0 <= current_process[1] <= 0xFFFFFFFF):
                raise InputError("current process requires an explicit resolved function address and DWORD process ID")
        self.current_process = current_process
        for name, address in (("path_filename", path_filename), ("path_strip", path_strip)):
            if address is not None and (type(address) is not int or not 0 < address <= _MASK64):
                raise InputError(name + " requires an explicit resolved function address")
            setattr(self, name + "_address", address)
        if module_lookup is not None:
            if (not isinstance(module_lookup, tuple) or len(module_lookup) != 2 or
                    type(module_lookup[0]) is not int or not 0 < module_lookup[0] < 1 << 64):
                raise InputError("module lookup requires an explicit resolved function address and event stream")
            self.module_lookup_address, observations = module_lookup
            self._module_handles = stream(observations)
        else:
            self.module_lookup_address = None
        for name, binding in (("procedure_lookup", procedure_lookup), ("cursor_position", cursor_position),
                              ("stack_capture", stack_capture), ("module_from_address", module_from_address),
                              ("module_filename", module_filename), ("find_window", find_window),
                              ("window_visible", window_visible), ("create_thread", create_thread)):
            if binding is None:
                setattr(self, name + "_address", None)
            else:
                if (not isinstance(binding, tuple) or len(binding) != 2 or
                        type(binding[0]) is not int or not 0 < binding[0] < 1 << 64):
                    raise InputError(name + " requires an explicit resolved function address and event stream")
                setattr(self, name + "_address", binding[0])
                setattr(self, "_" + name, stream(binding[1]))
        self.tls_epoch_address = tls_epoch_address
        if tls_base_address is not None and (type(tls_base_address) is not int or
                                             not 0 < tls_base_address <= _MASK64 - 0xD74):
            raise InputError("TLS base must be an explicit nonwrapping address")
        self.tls_base_address = tls_base_address
        self.crt_thread_address = crt_thread_address
        self.provider_material = provider_material
        self.provider_environment = provider_environment
        self.provider_profile = provider_profile
        self.events, self.vms, self.locks, self.allocations = [], [], {}, {}
        if singleton_producer_inputs is not None and warm_core_container_inputs is not None:
            raise InputError('warm core and cold singleton producer inputs are mutually exclusive')
        from .primary_singleton_inputs import _ProducerBinding
        self._singleton_producer_binding = (None if singleton_producer_inputs is None else
                                             _ProducerBinding(singleton_producer_inputs, self))
        from .primary_warm_core_inputs import _WarmCoreBinding
        self._warm_core_binding = (None if warm_core_container_inputs is None else
                                   _WarmCoreBinding(warm_core_container_inputs, self))
        if self._warm_core_binding is not None:
            self.locks[self._warm_core_binding.identity.container_address + 0x508] = 0
        from .primary_prefix_raw_clock import bind_clock_inputs
        self._main_clock_binding = (None if main_clock_inputs is None else
                                    bind_clock_inputs(main_clock_inputs, self))

        if main_environment_inputs is not None and stacktrace_state_domain is not None:
            raise InputError('effective Main environment cannot use cold stacktrace state')
        from .primary_main_environment_inputs import _MainEnvironmentBinding
        self._main_environment_binding = (None if main_environment_inputs is None else
                                          _MainEnvironmentBinding(main_environment_inputs, self))

        if stacktrace_state_domain is StacktraceStateDomain.COLD_PE:
            self.memory.map(self.image_base + 0x6D86014, bytearray(2),
                            name='explicit model cold PE stacktrace count WORD', initialized=True)

    def attach_host129_raw_api_inputs(self, inputs):
        from .primary_host129_api_inputs import Host129RawAPIInputs
        if (type(inputs) is not Host129RawAPIInputs or self._host129_api_attached or
                any(getattr(self, name) is not None for name in ('_host129_raw_binding',
                    '_host129_source_clock_binding', '_host129_multicall_binding', '_host129_counter_binding',
                    '_host129_clock_service_binding', '_host129_entropy_service_binding'))):
            raise InputError('host129 raw API inputs require a single exclusive typed attachment')
        inputs.bind(self)
        self._host129_api_binding = inputs
        self._host129_api_attached = True

    def _host129_api_service(self, vm, rva, cells, argument_types):
        from contextlib import nullcontext
        binding = self._host129_api_binding
        return nullcontext() if binding is None else binding.service(vm, rva, cells, argument_types)

    def _host129_serial_idle(self, setup):
        import os
        from threading import get_ident, get_native_id
        from .primary_windows_signer_setup import IndependentWindowsSetup
        from .primary_windows_host129_source import WindowsHost129Source
        from .primary_windows_core_observations import WindowsCoreObservations
        from .primary_windows_signer import WindowsSigner
        from .primary_main_prefix_stop import _input_owner
        owner = setup.owner if type(setup) is IndependentWindowsSetup else None
        signer = None if owner is None else owner.signer
        delegate = None if owner is None else setup.delegate
        if (type(owner) is not WindowsSigner or owner._independent_setup is not setup or signer.runtime is not self or
                self._primary_entry_owner is not signer or owner._state != 'open' or not owner._busy or
                owner._operation_failure is not None or signer.failed or getattr(signer.addresses, 'failed', False) or
                signer.primary_backend != 'direct' or self.primary_backend != 'direct' or not self.primary_core or
                owner._pid != os.getpid() or owner._thread != get_native_id() or
                owner._threads is None or not owner._threads._active_owner or
                owner._threads._execution_tid != get_native_id() or not owner._threads._execution.locked() or
                type(delegate) is not WindowsCoreObservations or delegate._closed or
                delegate._owner != (os.getpid(), get_native_id()) or delegate._runtime is not self or
                delegate._caller is not owner._caller or type(setup.source) is not WindowsHost129Source or
                setup.source._owns_delegate or setup.source.delegate is not delegate or
                not setup.source._normal_live_inputs() or
                setup.source.runtime is not self or setup.source.thread != get_ident() or
                setup.source.identity != (os.getpid(), get_native_id()) or
                setup.source.observed_counter_inputs is not None or getattr(setup.source, 'prefix_completed', False) or
                self._active_failed or self._active_main is not None or self._execute_depth or
                self._execute_thread is not None or self._program_calls or signer._sign_owner is not None or
                self.__dict__.get('_primary_public_direct_owner') is not None or
                self.__dict__.get('_primary_direct_scope') is not None or
                self.__dict__.get('_primary_wait_session') is not None or
                self.__dict__.get('_consumed_mgf') is not None or self.__dict__.get('_local113_frame_plan') is not None or
                _input_owner(self) is not None or any(getattr(self, key) is not None for key in
                    ('_host129_raw_binding', '_host129_source_clock_binding', '_host129_multicall_binding',
                     '_host129_counter_binding', '_host129_clock_service_binding', '_host129_entropy_service_binding',
                     '_main_environment_binding', '_main_clock_binding'))):
            raise InputError('serial Host129 epochs require their idle normal live Windows owner')
        prior = self._host129_public_exit
        if prior is not None and setup.state != 'signing':
            previous_setup, calls, serial, generation, index, method, outcomes = prior
            allowed = ('complete_request', 'request_device_refresh', 'request_device_refresh_async')
            if (previous_setup is not setup or signer.calls != calls or
                    self._main_generation != generation or owner._operation_outcomes is not outcomes or
                    len(outcomes) <= index or outcomes[index] !=
                    {'method': method, 'status': 'completed', 'call_count': calls} or
                    signer._public_direct_serial != serial + len(outcomes) - index - 1 or
                    any(type(row) is not dict or row.get('method') not in allowed or row !=
                        {'method': row['method'], 'status': 'completed', 'call_count': calls}
                        for row in outcomes[index + 1:])):
                raise InputError('serial Host129 epoch lacks its successful Windows public exit')

    def _require_unused_host129_api_inputs(self, setup, inputs=None):
        import os
        from threading import get_ident, get_native_id
        from .primary_host129_api_inputs import Host129RawAPIInputs
        binding = self._host129_api_binding if inputs is None else inputs
        source = setup.source if inputs is None else inputs.source
        if (type(binding) is not Host129RawAPIInputs or binding.source is not source or
                binding.runtime is not self or not binding.bound or binding.owns_source or
                binding.thread != get_ident() or source.thread != get_ident() or source.runtime is not self or
                source.identity != (os.getpid(), get_native_id()) or source.delegate is not setup.delegate or
                source._owns_delegate or not source._normal_live_inputs() or
                binding.closed or binding.failed or binding.completed or binding.service_active or
                any(value is not None for value in (binding.owner, binding.main_owner, binding.main_vm,
                    source.owner, source.main_owner, source.main_vm, source.host_vm, source.service,
                    source.observed_counter_inputs, source._observed_group, source._observed_frame)) or
                source.closed or source.failed or source.completed or source.first_failed_predicate is not None or
                source.sites or source.hosts or source.services or source.counters or source.api_count or
                source._observed_index or getattr(source, 'prefix_completed', False) or
                getattr(binding, 'prefix_completed', False)):
            raise InputError('serial Host129 epoch requires its genuinely unconsumed input pair')

    def _finish_host129_api_epoch(self, setup):
        from threading import get_ident
        from .primary_sign_lifecycle import _PublicDirectOwner
        from .primary_host129_api_inputs import Host129RawAPIInputs
        self._host129_serial_idle(setup)
        signer, source, binding = setup.owner.signer, setup.source, self._host129_api_binding
        before = setup._epoch_before
        if (setup.state != 'signing' or type(before) is not tuple or len(before) != 4 or
                setup._method not in ('sign', 'sign_result') or
                signer._public_direct_serial != before[1] + 1 or
                len(setup.owner._operation_outcomes) != before[3] or
                self.raw_core_observations is not source or signer.environment.raw_core_observations is not source or
                type(binding) is not Host129RawAPIInputs or binding.source is not source or
                self._host129_retirement is not None):
            raise InputError('serial Host129 epoch lacks its actual public completion')
        if not source.completed and not binding.completed:
            self._require_unused_host129_api_inputs(setup)
            if signer.calls != before[0] or self._main_generation != before[2]:
                raise InputError('unused Host129 public call changed Main completion state')
            consumed = False
        else:
            proof = self._host129_main_completion
            public, main, vm = binding.owner, binding.main_owner, binding.main_vm
            if (proof is None or proof[0] is not binding or proof[1] is not source or
                    proof[2] is not main or proof[3] is not vm or proof[4] != self._main_generation or
                    not source.completed or source.failed or source.closed or
                    source.first_failed_predicate is not None or source.observed_counter_inputs is not None or
                    not binding.completed or not binding.closed or not binding.failed or binding.owns_source or
                    binding.service_active or source.service is not None or source.host_vm is not None or
                    source.main_owner is not main or source.main_vm is not vm or source.owner is not public or
                    type(public) is not _PublicDirectOwner or public.active or public.runtime is not self or
                    public.signer is not signer or public.thread != get_ident() or public.serial != before[1] + 1 or
                    type(main) is not dict or main.get('vm') is not vm or main.get('thread') != get_ident() or
                    main.get('generation') != before[2] + 1 or self._main_generation != before[2] + 1 or
                    vm is None or not vm.halted or vm.abort_reason is not None or
                    signer.calls != before[0] + 1 or getattr(source, 'prefix_completed', False) or
                    getattr(binding, 'prefix_completed', False)):
                raise InputError('serial Host129 retirement requires correct Main and public success')
            self._host129_retirement = (setup, binding, source, source.delegate, main, vm,
                                       self._main_generation, signer.calls, signer._public_direct_serial)
            consumed = True
        self._host129_public_exit = (setup, signer.calls, signer._public_direct_serial, self._main_generation,
                                    before[3], setup._method, setup.owner._operation_outcomes)
        return consumed

    def _handoff_host129_raw_api_inputs(self, setup, inputs):
        from threading import get_ident
        from .primary_host129_api_inputs import Host129RawAPIInputs
        from .primary_windows_host129_source import WindowsHost129Source
        self._host129_serial_idle(setup)
        receipt = self._host129_retirement
        old = self._host129_api_binding
        source = inputs.source if type(inputs) is Host129RawAPIInputs else None
        if (setup.state != 'completed' or receipt is None or receipt[0] is not setup or
                receipt[1] is not old or receipt[2] is not setup.source or receipt[3] is not setup.delegate or
                receipt[6] != self._main_generation or receipt[7] != setup.owner.signer.calls or
                self._host129_public_exit is None or receipt[8] != self._host129_public_exit[2] or
                self._host129_main_completion is None or self._host129_main_completion[:4] !=
                (old, setup.source, receipt[4], receipt[5]) or
                not old.completed or not old.closed or not old.failed or old.source is not setup.source or
                old.runtime is not self or old.thread != get_ident() or old.service_active or
                old.main_owner is not receipt[4] or old.main_vm is not receipt[5] or
                old.owner is None or old.owner.active or old.owner.runtime is not self or
                old.owner.signer is not setup.owner.signer or old.owner.thread != get_ident() or
                old.owner.serial != receipt[8] or receipt[4].get('generation') != receipt[6] or
                receipt[4].get('thread') != get_ident() or receipt[4].get('vm') is not receipt[5] or
                not receipt[5].halted or receipt[5].abort_reason is not None or
                not setup.source.completed or not setup.source.closed or not setup.source.failed or
                setup.source.first_failed_predicate is not None or
                setup.source.host_vm is not None or setup.source.service is not None or
                type(source) is not WindowsHost129Source or source is setup.source or source._owns_delegate or
                not source._normal_live_inputs() or
                source.delegate is not setup.delegate or source.runtime is not self or
                inputs.bound or inputs.closed or inputs.failed or inputs.completed or inputs.owns_source or
                self.raw_core_observations is not source or
                setup.owner.signer.environment.raw_core_observations is not source):
            raise InputError('serial Host129 handoff requires its unique successful retirement')
        try:
            inputs.bind(self)
            self._require_unused_host129_api_inputs(setup, inputs)
        except BaseException:
            inputs.close()
            raise
        self._host129_api_binding = inputs
        self._host129_retirement = None
        self._host129_main_completion = None

    def next_postfetch_start_error(self):
        try:
            error = self._next(self._postfetch_start_errors, "BD4FA0.thread_start_error")
        except UnknownMemory as exc:
            raise PrimarySemanticUnavailable("provider postfetch enqueue needs an observed thread-start result") from exc
        if type(error) is not int or not 0 <= error <= 0xFFFFFFFF:
            raise InputError("postfetch thread-start error must be unsigned32")
        return error

    def _provider_postfetch(self):
        from .primary_postfetch import ProviderPostfetch
        from .primary_worker_tasks import provider_task
        if self.postfetch_task is not None and (self.postfetch_task.closing or self.postfetch_task.closed):
            raise PrimarySemanticUnavailable('provider task is exiting or has been destroyed')
        provider_task(self)
        if self.postfetch_task is None:
            self.postfetch_task = ProviderPostfetch(self)
        return self.postfetch_task

    def schedule_provider_refresh(self, state, *, direct=False, caller=False):
        from .primary_postfetch import ProviderRefresh
        if direct:
            function = ProviderRefresh(state)
            function.invoke(self)
            function.destroy(self)
            return
        if caller:
            from .primary_worker_tasks import enqueue_provider_worker
            return enqueue_provider_worker(self)
        self._provider_postfetch().enqueue(self, state)

    def schedule_provider_telemetry(self, record):
        from .primary_postfetch import ProviderTelemetry
        task = self._provider_postfetch()
        function = ProviderTelemetry.create(self, record)
        task.enqueue_function(self, function)

    def _thread_header(self, guard_address):
        self.events.append(("CRT.AcquireSRWLockExclusive", self.image_base + 0x6755688))
        guard = self.memory.load(guard_address, 4, signed=True)
        if guard == 0:
            self.memory.store(guard_address, -1, 4, source="3E67DD7.guard_claim")
        elif guard == -1:
            raise PrimarySemanticUnavailable("CRT condition-variable wait on an in-progress initializer")
        else:
            epoch = self.memory.load(self.image_base + 0x5EA1C80, 4)
            self.memory.store(self.tls_epoch_address, epoch, 4, source="3E67E20.TLS_epoch")
        self.events.append(("CRT.ReleaseSRWLockExclusive", self.image_base + 0x6755688))

    def _thread_footer(self, guard_address):
        self.events.append(("CRT.AcquireSRWLockExclusive", self.image_base + 0x6755688))
        value = (self.memory.load(self.image_base + 0x5EA1C80, 4) + 1) & 0xFFFFFFFF
        self.memory.store(self.image_base + 0x5EA1C80, value, 4, source="3E67E9F.global_epoch")
        self.memory.store(guard_address, value, 4, source="3E67EA5.guard_publish")
        epoch = self.memory.load(self.image_base + 0x5EA1C80, 4)
        self.memory.store(self.tls_epoch_address, epoch, 4, source="3E67EC0.TLS_epoch")
        self.events.append(("CRT.ReleaseSRWLockExclusive", self.image_base + 0x6755688))
        self.events.append(("CRT.WakeAllConditionVariable", self.image_base + 0x6755680))

    def _locale_thread_header(self, guard_address):
        from .primary_shared_locale import resolve_current_module_tls
        tls_epoch_address=resolve_current_module_tls(self).epoch_address
        self.events.append(("CRT.AcquireSRWLockExclusive", self.image_base + 0x6755688))
        guard = self.memory.load(guard_address, 4, signed=True)
        if guard == 0:
            self.memory.store(guard_address, -1, 4, source="3E67DD7.guard_claim")
        elif guard == -1:
            raise PrimarySemanticUnavailable("CRT condition-variable wait on an in-progress initializer")
        else:
            epoch = self.memory.load(self.image_base + 0x5EA1C80, 4)
            self.memory.store(tls_epoch_address, epoch, 4, source="3E67E20.TLS_epoch")
        self.events.append(("CRT.ReleaseSRWLockExclusive", self.image_base + 0x6755688))

    def _locale_thread_footer(self, guard_address):
        from .primary_shared_locale import resolve_current_module_tls
        tls_epoch_address=resolve_current_module_tls(self).epoch_address
        self.events.append(("CRT.AcquireSRWLockExclusive", self.image_base + 0x6755688))
        value = (self.memory.load(self.image_base + 0x5EA1C80, 4) + 1) & 0xFFFFFFFF
        self.memory.store(self.image_base + 0x5EA1C80, value, 4, source="3E67E9F.global_epoch")
        self.memory.store(guard_address, value, 4, source="3E67EA5.guard_publish")
        epoch = self.memory.load(self.image_base + 0x5EA1C80, 4)
        self.memory.store(tls_epoch_address, epoch, 4, source="3E67EC0.TLS_epoch")
        self.events.append(("CRT.ReleaseSRWLockExclusive", self.image_base + 0x6755688))
        self.events.append(("CRT.WakeAllConditionVariable", self.image_base + 0x6755680))

    def _next(self, stream, name, *arguments):
        policy = getattr(self, '_policy3_binding', None)
        if policy is not None and policy.active and policy._site is not None:
            if name == 'HeapAlloc':
                return policy.allocate(*arguments)
            if name == 'native private temporary':
                return policy.temporary(*arguments)
            if name == 'CRT exit registration':
                return policy.exit_registration(*arguments)
        history = getattr(self, '_history_environment', None)
        if history is not None:
            value = history.read(name, arguments)
            self.events.append((name, value))
            return value
        try:
            value = stream(*arguments) if callable(stream) else next(stream)
        except StopIteration as error:
            raise UnknownMemory(f"missing actual environment event: {name}") from error
        self.events.append((name, value))
        return value

    def _clock_value(self, *, api=None, local=None):
        api = self._clock_api if api is None else api
        local = self._clock_local if local is None else local
        guard, slot = self.image_base + 0x6D88CD8, self.image_base + 0x6D88CD0
        initialized = self.memory.load(guard, 1) != 0
        if self._clock_apis is not None or self.raw_core_observations is not None:
            if not initialized:
                available = api('QueryPerformanceFrequency', slot) != 0
                self.memory.store(guard, int(available), 1, source='359245E.frequency_ready')
                if not available:
                    filetime = local('GetSystemTimeAsFileTime')
                    return (filetime * 100 + 0x5E6684F4B3960000) & _MASK64
            counter = local('QueryPerformanceCounter')
            return scaled_qpc_nanoseconds(counter, self.memory.load(slot, 8))
        counter, frequency = self._next(self._qpc, "QueryPerformanceCounter/Frequency")
        if not initialized:
            self.events.append(("QueryPerformanceFrequency", frequency))
            self.memory.store(slot, frequency, 8, source="3592454.frequency_publish")
            self.memory.store(guard, 1, 1, source="359245E.frequency_ready")
        self.events.append(("QueryPerformanceCounter", counter))
        current_frequency = self.memory.load(slot, 8)
        if frequency != current_frequency:
            raise InputError("QPC environment event frequency differs from current frequency global")
        return scaled_qpc_nanoseconds(counter, current_frequency)

    def _clock_api(self, name, destination):
        producer = self._singleton_producer_binding
        if producer is not None and producer.active:
            if producer._clock_domain is not None and name == 'QueryPerformanceFrequency':
                return producer._clock_domain.independent_frequency(destination)
            return producer.api(name, destination, 'steady-local')
        policy = getattr(self, '_policy3_binding', None)
        if policy is not None and policy.active:
            return policy.api(name, destination)
        if self.raw_core_observations is not None:
            return self.raw_core_observations.write_to(self, name, destination, purpose='source clock output')
        event = self._next(self._clock_apis, name, name, destination)
        if (not isinstance(event, tuple) or len(event) != 4 or
                event[0] != name or event[1] != (destination,)):
            raise InputError('clock API observation must match the actual name/output pointer')
        result, output = event[2:]
        if name == 'GetSystemTimeAsFileTime':
            if result is not None:
                raise InputError('GetSystemTimeAsFileTime has no BOOL result')
        elif type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
            raise InputError('clock API BOOL observation must be a DWORD')
        if output is not None:
            if not isinstance(output, bytes) or len(output) > 8:
                raise InputError('clock API output effects must fit the actual eight bytes')
            self.memory.write(destination, output, source=name + '.raw_output')
        self.events.append((name, result, destination, output))
        return result

    def _clock_local(self, name):
        binding = self._host129_api_binding
        fallback = lambda size: self._next(self._temporaries, 'clock private output', size)
        size, address, initial = (binding.temporary(fallback) if binding is not None and binding.service_active else fallback(8))
        if (size != 8 or type(address) is not int or not 0 < address <= _MASK64 - 8 or
                initial is not None and (not isinstance(initial, bytes) or len(initial) != 8)):
            raise InputError('clock output requires an explicit private eight-byte temporary')
        self.memory.map(address, bytearray(8) if initial is None else bytearray(initial),
                        name='clock private output', initialized=initial is not None)
        try:
            self._clock_api(name, address)
            return self.memory.load(address, 8)
        finally:
            self.memory.forget(address, 8, source='clock.private_output_lifetime_end')
            if not self.retain_frames:
                self.memory.unmap(address)

    def _raw_private_output(self, name, destination, *, publish_on_success):
        size, address, initial = self._next(self._temporaries, 'raw API private output', 8)
        if (size != 8 or type(address) is not int or not 0 < address <= _MASK64 - 8 or
                initial is not None and (not isinstance(initial, bytes) or len(initial) != 8)):
            raise InputError('raw API requires its explicit eight-byte private output')
        if name == 'GetCursorPos':
            initial = bytes(8)
        self.memory.map(address, bytearray(8) if initial is None else bytearray(initial),
                        name='raw API private output', initialized=initial is not None)
        try:
            result = self.raw_core_observations.write_to(self, name, address, purpose='source private output')
            if result or not publish_on_success:
                self.memory.copy_disjoint(destination, address, 8, label=name + '.source_output_publish')
            return result
        finally:
            self.memory.forget(address, 8, source='raw API private output lifetime end')
            if not self.retain_frames:
                self.memory.unmap(address)

    def _raw_steady_time(self):
        from contextlib import contextmanager
        producer = self._singleton_producer_binding

        @contextmanager
        def storage():
            if producer is not None and producer.active:
                with producer.local(8) as address:
                    yield address
                return
            policy = getattr(self, '_policy3_binding', None)
            if policy is not None and policy.active:
                with policy.clock_local() as address:
                    yield address
                return
            size, address, initial = self._next(self._temporaries, 'clock private output', 8)
            if size != 8 or type(address) is not int or not 0 < address <= _MASK64 - 8 or initial is not None:
                raise InputError('raw steady clock requires one fresh unknown eight-byte local')
            self.memory.map(address, bytearray(8), name='clock private output', initialized=False)
            try:
                yield address
            finally:
                self.memory.forget(address, 8, source='clock.private_output_lifetime_end')
                if not self.retain_frames:
                    self.memory.unmap(address)

        from contextlib import nullcontext
        with storage() as address:
            domain = producer._clock_domain if producer is not None and producer.active else None
            with domain.clock(address) if domain is not None else nullcontext():
                guard_address = self.image_base + 0x674D448
                guard = self.memory.load(guard_address, 4, signed=True)
                if guard > self.memory.load(self.tls_epoch_address, 4, signed=True):
                    self._thread_header(guard_address)
                    if self.memory.load(guard_address, 4, signed=True) == -1:
                        self._clock_api('QueryPerformanceFrequency', address)
                        self.memory.copy_disjoint(self.image_base + 0x674D440, address, 8,
                                                  label='QueryPerformanceFrequency.source_output_publish')
                        self._thread_footer(guard_address)
                self._clock_api('QueryPerformanceCounter', address)
                counter = self.memory.load(address, 8)
                frequency = self.memory.load(self.image_base + 0x674D440, 8)
                return qpc_nanoseconds(counter, frequency)

    def _allocate(self, size: int, zero: bool, *, nullable=False) -> int:
        producer = self._singleton_producer_binding
        role = producer.allocate(size, zero) if producer is not None and producer.active else None
        handle = self.memory.load(self.image_base + 0x6D8EC90, 8)
        self.events.append(("HeapAlloc.arguments", handle, 8 if zero else 0, size))
        expected, actual_zero, address = self._next(self._allocations, "HeapAlloc", size, zero)
        if expected != size or actual_zero is not zero:
            raise InputError("allocator event does not match actual requested size/flags")
        if type(address) is int and address == 0 and nullable and role is None:
            self.events.append(("CRT.calloc.NULL", size))
            return 0
        if type(address) is not int or address == 0:
            raise PrimaryProgramLimit("allocation failure/retry lies outside normal runtime domain")
        self.memory.map(address, bytearray(size), name=f"HeapAlloc({size},zero={zero})", initialized=zero)
        self.allocations[address] = size
        if role is not None:
            producer.allocated(role, address)
        return address

    def _crt_call(self, function, *arguments):
        observer = getattr(self, 'crt_startup_observations', None)
        if observer is None:
            return function(self, *arguments)
        previous = self.worker_observations
        self.worker_observations = observer
        try:
            return function(self, *arguments)
        finally:
            self.worker_observations = previous

    def _crt_thread(self):
        if getattr(self, 'crt_startup_observations', None) is not None:
            from .primary_crt_startup import current

            address = self._crt_call(current)
            self.crt_thread_address = address
        elif getattr(self, '_crt_dispatch_active', False):
            from .primary_thread_dispatch import require_current

            address = require_current(self)
        else:
            address = self.crt_thread_address
        if type(address) is not int or not 0 < address < 1 << 64:
            raise UnknownMemory("missing initialized current CRT thread address")
        self.events.append(("CRT.current_thread.initialized", address))
        return address

    def _operator_new(self, size):
        expected, zero, address = self._next(self._allocations, "operator_new", size, False)
        if expected != size or zero is not False:
            raise InputError("operator-new observation does not match the actual requested size")
        if type(address) is not int or not 0 < address <= _MASK64 - size:
            raise PrimaryProgramLimit("operator-new failure/retry needs allocator failure-handler effects")
        self.memory.map(address, bytearray(size), name=f"operator_new({size})", initialized=False)
        self.allocations[address] = size
        return address

    def _material_transform(self, address, length, destination, requested):
        length &= 0xFFFFFFFF
        requested &= 0xFFFFFFFF
        value = self.memory.read(address, length) if length else b""
        digest = hashlib.md5(value).digest()
        count = requested if 1 <= requested <= 16 else 16
        self.memory.write(destination, digest[:count], source="1D05D10.digest_copy")

    def _free_allocation(self, pointer):
        producer = self._singleton_producer_binding
        role = producer.free(pointer) if producer is not None and producer.active else None
        if pointer:
            if pointer not in self.allocations:
                raise PrimaryProgramLimit("free requires this runtime's actual allocation")
            handle = self.memory.load(self.image_base + 0x6D8EC90, 8)
            self.events.append(("HeapFree", handle, 0, pointer))
            from .primary_sign_lifecycle import region_at
            released = region_at(self.memory, pointer)
            self.memory.forget(pointer, self.allocations.pop(pointer), source="HeapFree.invalidated")
            if not self.retain_frames:
                self.memory.unmap(pointer)
            owner = self._active_main
            if owner is not None and owner['vm'] is not None:
                vm = owner['vm']
                vm.main_owned_allocations[:] = [entry for entry in vm.main_owned_allocations
                                                if entry['pointer'] != pointer or entry['region'] is not released]

        if role is not None:
            producer.freed(role)

    def _return_provider_string(self, destination):
        observed = self.__dict__.get('_prefix_provider_binding')
        from .primary_prefix_observed_provider import _ObservedProviderBinding
        if type(observed) is _ObservedProviderBinding:
            return observed.return_string(destination)
        from .primary_adapter import write_string
        from .primary_material import ProviderMaterial
        if not isinstance(self.provider_material, ProviderMaterial):
            raise PrimarySemanticUnavailable("installed material provider has no bound caller state")
        value = self.provider_material._read(self.provider_environment, self.provider_profile, self, caller='callback')[0]
        return write_string(self.memory, destination, value, self._allocate)

    def publish_provider_token(self, token, *, caller="initial"):
        from types import SimpleNamespace
        if not isinstance(token, bytes) or len(token) < 4:
            raise InputError("provider token notification requires at least four source bytes")
        if caller not in ("initial", "postfetch"):
            raise InputError("provider token notification requires an actual supported caller")
        pcs = ("BA9940", "BA9947", "BA9998") if caller == "initial" else ("BD1AC6", "BD1ACA", "BD1AEC")
        size, address, initial = self._next(self._temporaries, "provider token DWORD", 5)
        if (size != 5 or type(address) is not int or not 0 < address <= _MASK64 - 5 or
                (initial is not None and (not isinstance(initial, bytes) or len(initial) != 5))):
            raise InputError("provider token notification needs a private five-byte local")
        self.memory.map(address, bytearray(5), name="provider token local", initialized=False)
        self.memory.store(address + 4, 0, 1, source=pcs[0] + ".token_local_terminator")
        self.memory.store(address, 0, 4, source=pcs[1] + ".token_local_clear")
        self.memory.write(address, token[:4], source=pcs[2] + ".token_local_prefix")
        values = (address, 1, 0x2583)
        vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
        from .primary_token_family_direct import _token_publication
        with _token_publication(self, address, 1, 0x2583, caller, vm):
            self.invoke(vm, 0x1BF7520, (0, 1, 2))
        self.memory.forget(address, 5, source="provider.token_local_lifetime_end")
        if not self.retain_frames:
            self.memory.unmap(address)

    def _register_callback_group(self, vm, lock_rva, start, size, stores):
        lock = self.image_base + lock_rva
        if self.locks.get(lock, 0):
            raise PrimarySemanticUnavailable("callback registration waits on an owned mutex")
        self.locks[lock] = 1
        self.events.append(("75AF50.lock", lock))
        try:
            group = b"".join(self.memory.read(self.image_base + start + offset, 8)
                             for offset in range(0, size, 8))
            if any(group):
                return
            for pc, slot, target in stores:
                if slot is None:
                    self.invoke(vm, target, ())
                else:
                    self.memory.store(self.image_base + slot, self.image_base + target, 8,
                                      source=f"{pc:X}.callback_store")
        finally:
            self.locks[lock] = 0
            self.events.append(("75AFC0.unlock", lock))

    def _register_provider_base(self, vm):
        self._register_callback_group(vm, 0x677C220, 0x6D85F60, 72, (
            (0x1BF644E, 0x6D85F60, 0x1BF81B0),
            (0x1BF645C, 0x6D85F78, 0xB9F1D0),
            (0x1BF6463, None, 0x2DE5910),
            (0x1BF646F, 0x6D85F80, 0x1BF8270),
            (0x1BF647D, 0x6D85F88, 0x1BF9740),
            (0x1BF648B, 0x6D85F90, 0x1BFCB40),
            (0x1BF6499, 0x6D85F98, 0x1BFCCA0),
            (0x1BF64A7, 0x6D85FA0, 0x28F0),
            (0x1BF64B5, 0x6D85F68, 0x1BFD170),
            (0x1BF64C3, 0x6D85F70, 0x1BFD2A0),
            (0x1BF64D1, 0x6D85FE8, 0x1BFD3D0),
            (0x1BF64DF, 0x6D85FF0, 0x1BFD3E0),
            (0x1BF64ED, 0x6D85FF8, 0x1BFD960),
        ))

    def register_provider_callbacks(self, vm=None):
        self._register_provider_base(vm)
        self._register_provider_base(vm)
        self._register_callback_group(vm, 0x677C220, 0x6D85FA8, 16, (
            (0x1BF6588, 0x6D85FA8, 0x1BF80F0),
            (0x1BF6596, 0x6D85FB0, 0x28F0),
        ))
        self._register_callback_group(vm, 0x677C228, 0x6D85FC0, 64, (
            (0x1BF65EF, 0x6D85FC0, 0x1C006E0),
            (0x1BF65FD, 0x6D85FC8, 0x1C007C0),
            (0x1BF660B, 0x6D85FD0, 0x1C00850),
            (0x1BF6619, 0x6D85FD8, 0x1C008E0),
            (0x1BF6627, 0x6D85FE0, 0x1C00970),
            (0x1BF6635, 0x6D85FE8, 0x1BFD3D0),
            (0x1BF6643, 0x6D85FF8, 0x1BFD960),
            (0x1BF6651, 0x6D85FF0, 0x1BFD3E0),
        ))

    def register_sdk_callbacks(self, vm=None):
        self._register_provider_base(vm)
        snapshots = tuple(self.memory.load(self.image_base + slot, 8)
                          for slot in (0x677DF80, 0x677DF88, 0x677DF98))
        lock = self.image_base + 0x677C230
        if self.locks.get(lock, 0):
            raise PrimarySemanticUnavailable("SDK registration waits on an owned mutex")
        self.locks[lock] = 1
        self.events.append(("75AF50.lock", lock))
        try:
            group = self.memory.read(self.image_base + 0x677DF80, 40)
            if any(group) and all(snapshots):
                return
            for source, slot, target in ((0x6D83BE0, 0x677DF80, 0x1C00BC0),
                                         (0x6D83C08, 0x677DF88, 0x1C00BF0),
                                         (None, 0x677DF90, 0x1C00C20),
                                         (0x6D83C30, 0x677DF98, 0x1C00F90)):
                if source is None or self.memory.load(self.image_base + source, 8):
                    self.memory.store(self.image_base + slot, self.image_base + target, 8,
                                      source="1BF6670.SDK_callback_store")
            self.invoke(vm, 0x1D2C850, ())
        finally:
            self.locks[lock] = 0
            self.events.append(("75AFC0.unlock", lock))

    def _initialize_sdk_table(self):
        return self.execute("sdk-table-init", (), None)

    def _sdk_initializer_hosts(self, vm):
        from types import SimpleNamespace
        count = len(vm.program.host_cells)
        capacity = ((count + 16) * 8 + 15) & ~15
        size, address, initial = self._next(self._temporaries, "SDK initializer host scratch", capacity)
        if size != capacity or type(address) is not int or not 0 < address <= _MASK64 - size:
            raise InputError("SDK initializer needs its actual reader stack scratch")
        self.memory.map(address, bytearray(size), name="SDK initializer reader scratch", initialized=False)
        try:
            self.memory.write(address, bytes(count + 16), source="35E46BF.scratch_prefix_clear")
            values = (address, count * 8)
            callback_vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
            self.invoke(callback_vm, 0x1D2C8D0, (0, 1))
            self.events.append(("reader.host_callback", "sdk-table-init", address, count * 8))
            return tuple(self.memory.load(address + index * 8, 8) for index in range(count))
        finally:
            self.memory.forget(address, size, source="reader.host_scratch_lifetime_end")
            if not self.retain_frames:
                self.memory.unmap(address)

    def _random_device(self):
        guard = self.image_base + 0x6D88CB8
        if self.memory.load(guard, 4, signed=True) > self.memory.load(self.tls_epoch_address, 4, signed=True):
            self._thread_header(guard)
            if self.memory.load(guard, 4, signed=True) == -1:
                from .primary_worker_consumer import _invoke
                _invoke(self, 0x3E680B4, self.image_base + 0x3591F69)
                self.events.append(("CRT.atexit", self.image_base + 0x3591F69))
                self._thread_footer(guard)
        once, slot = self.image_base + 0x6D88CA8, self.image_base + 0x6D88CB0
        from .primary_module_sync import backend, MODEL_NATIVE, source_once, shared_acquire, shared_release
        if backend(self) == MODEL_NATIVE:
            from .primary_worker_consumer import _invoke
            def source_callback_3591F77():
                address = _invoke(self, 0xB75000, 1)
                # CD18 has not been source-closed. The allocated byte remains unknown;
                # source3592018 publication occurs only after that constructor returns.
                raise PrimarySemanticUnavailable('sourceCD18 random-device constructor unavailable after B75000(1)')
            source_once(self, once, source_callback_3591F77)
            return self.memory.load(slot, 8)
        if self.memory.load(once, 8) != _MASK64:
            shared_acquire(self)
            self.events.append(("call_once.lock", self.image_base + 0x674D4D0))
            state = self.memory.load(once, 8)
            if state == 1:
                raise PrimarySemanticUnavailable("random device once initialization waits for another thread")
            if state == 0:
                self.memory.store(once, 1, 8, source="75B168.once_claim")
                address = self._allocate(1, False)
                if self.memory.load(slot, 8):
                    raise PrimarySemanticUnavailable("random device initialization replaces an existing object")
                self.memory.store(slot, address, 8, source="359201D.random_device_publish")
                self.memory.store(once, _MASK64, 8, source="75B190.once_publish")
            self.events.append(("call_once.unlock", self.image_base + 0x674D4D0))
            shared_release(self)
        return self.memory.load(slot, 8)

    def _ansi_name(self, pointer):
        raw = bytearray()
        for index in range(0x10000):
            value = self.memory.load(pointer + index, 1)
            if value == 0:
                return bytes(raw)
            raw.append(value)
        raise PrimaryProgramLimit("ANSI name exceeds the bounded Python scan domain")

    def _cursor_value(self, *, discard_failure=False):
        result, x, y = self._next(self._cursor_position, "GetCursorPos")
        if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
            raise InputError("cursor status must be an explicit BOOL32")
        if result == 0:
            if discard_failure:
                return 0, None
            raise PrimarySemanticUnavailable("failed cursor query memory effects are unavailable")
        if any(type(value) is not int or not -(1 << 31) <= value < 1 << 31 for value in (x, y)):
            raise InputError("cursor coordinates must be explicit signed LONG32 values")
        return result, x.to_bytes(4, "little", signed=True) + y.to_bytes(4, "little", signed=True)

    def _path_offset(self, pointer):
        data = self._ansi_name(pointer)
        if any(value >= 128 for value in data):
            raise PrimarySemanticUnavailable("non-ASCII path filename needs the actual ANSI codepage/DBCS state")
        offset, colons, colon_offset = 0, 0, None
        for index, value in enumerate(data):
            next_value = data[index + 1] if index + 1 < len(data) else 0
            if value in (47, 92) and next_value not in (0, 47, 92):
                offset, colons, colon_offset = index + 1, 0, None
            elif value == 58:
                colons += 1
                if colon_offset is None and next_value not in (0, 47, 92):
                    colon_offset = index + 1
        if colons == 1 and colon_offset is not None:
            offset = colon_offset
        return data, offset

    def execute(self, name: str, arguments: tuple[int, ...], hosts: tuple[int, ...] | None):
        from .primary_sign_lifecycle import _sync_execution, start_execution
        execution = self._execute_continued(name, arguments, hosts)
        if name == 'main' and self.__dict__.get('_primary_wait_session') is None:
            return start_execution(self, execution)
        return _sync_execution(execution)

    def _execute_continued(self, name: str, arguments: tuple[int, ...], hosts: tuple[int, ...] | None):
        from threading import get_ident
        from .primary_sign_lifecycle import discard_retry, close_program_allowed
        identity = get_ident()
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self)
        captured_main = None
        if name == 'main' and self._main_environment_binding is not None:
            self._main_environment_binding.enter(arguments, hosts)
        if self._execute_thread is not None and self._execute_thread != identity:
            if self._host129_api_binding is not None:
                self._host129_api_binding.close()
            if self._host129_raw_binding is not None:
                self._host129_raw_binding.close()
            if self._main_clock_binding is not None:
                self._main_clock_binding.close()
            if self._host129_source_clock_binding is not None:
                self._host129_source_clock_binding.close()
            raise InputError('runtime is owned by another executing thread')
        synchronous = (self.host2252_stage1_retry or self.host2252_stage2_g_retry or self.host2252_final_f_retry or self.host2252_control_m) and self.host2252_retry_mode == 'synchronous'
        direct = self.primary_backend == 'direct' or self.__dict__.get('_primary_direct_scope') is not None
        if (direct or synchronous or self._main_environment_binding is not None or self._warm_core_binding is not None or self._main_clock_binding is not None or self._host129_source_clock_binding is not None or self._host129_raw_binding is not None or self._host129_api_binding is not None) and self._active_failed and not close_program_allowed(self, name, arguments, hosts):
            if self._host129_api_binding is not None:
                self._host129_api_binding.close()
            if self._host129_raw_binding is not None:
                self._host129_raw_binding.close()
            if self._main_clock_binding is not None:
                self._main_clock_binding.close()
            if self._host129_source_clock_binding is not None:
                self._host129_source_clock_binding.close()
            raise InputError('active runtime stopped after an incomplete call')
        replay = getattr(self, '_consumed_mgf', None)
        main_owner = (direct or synchronous or replay is not None or self._main_environment_binding is not None or self._warm_core_binding is not None or self._main_clock_binding is not None or
                      self._host129_source_clock_binding is not None or self._host129_raw_binding is not None or self._host129_api_binding is not None) and name == 'main'
        if main_owner and self._active_main is not None:
            if self._host129_api_binding is not None:
                self._host129_api_binding.close()
            if self._host129_raw_binding is not None:
                self._host129_raw_binding.close()
            if self._main_clock_binding is not None:
                self._main_clock_binding.close()
            if self._host129_source_clock_binding is not None:
                self._host129_source_clock_binding.close()
            raise InputError('runtime already owns an active main invocation')
        if main_owner:
            self._main_generation += 1
            self._host129_main_completion = None
            self._active_main = {'thread': identity, 'generation': self._main_generation, 'vm': None,
                                 'remaining': self.host2252_m_read_budget, 'consumed': 0,
                                 'g_remaining': self.host2252_g_read_budget, 'g_consumed': 0,
                                 'f_remaining': self.host2252_f_read_budget, 'f_consumed': 0,
                                 'pair_m_remaining': self.host2252_pair_m_read_budget, 'pair_m_consumed': 0}
        if main_owner:
            captured_main = self._active_main
        self._execute_thread = identity
        self._execute_depth += 1
        self._program_calls.append({'name': name, 'arguments': arguments, 'hosts': hosts})
        multicall = self._host129_multicall_binding
        raw3 = self._host129_raw_binding
        raw_api = self._host129_api_binding
        witness_names = ('_host129_counter_binding', '_host129_clock_service_binding',
                         '_host129_entropy_service_binding')
        witnesses = tuple(getattr(self, key) for key in witness_names)
        normal_return = False
        try:
            from contextlib import ExitStack
            policy = getattr(self, '_policy3_binding', None)
            with ExitStack() as scopes:
                if raw_api is not None:
                    raw_api.enter(name)
                if raw3 is not None:
                    raw3.enter(name)
                    witnesses = tuple(getattr(self, key) for key in witness_names)
                if self._host129_source_clock_binding is not None:
                    scopes.enter_context(self._host129_source_clock_binding.scope(name))
                if name == 'main' and self._main_clock_binding is not None:
                    scopes.enter_context(self._main_clock_binding.scope(arguments, hosts))
                if replay is not None:
                    scopes.enter_context(replay.program_scope(self, self._program_calls[-1]))
                if multicall is not None:
                    multicall.enter(name)
                    witnesses = tuple(getattr(self, key) for key in witness_names)
                for binding in witnesses:
                    if binding is not None:
                        scopes.enter_context(binding.scope(self, name))
                if policy is not None:
                    scopes.enter_context(policy.scope(name))
                if self._singleton_producer_binding is not None:
                    scopes.enter_context(self._singleton_producer_binding.program(name))
                if self._program_context is None:
                    result = yield from self._execute_program(name, arguments, hosts)
                else:
                    with self._program_context(name, arguments, hosts):
                        result = yield from self._execute_program(name, arguments, hosts)
            if name == 'host129' and any(value is not None for value in witnesses):
                if (any(value is not None and not value.normal_completed for value in witnesses) or
                        any(getattr(self, key) is not value for key, value in zip(witness_names, witnesses))):
                    raise InputError('host129 witness group did not complete with its original owners')
                (self._host129_counter_binding, self._host129_clock_service_binding,
                 self._host129_entropy_service_binding) = (None, None, None)
            if multicall is not None:
                multicall.complete(name)
            if raw3 is not None:
                raw3.complete(name)
            normal_return = True
            return result
        except BaseException as error:
            from .primary_main_prefix_stop import _current, _close_failure_inputs
            prefix = _current(self) if main_owner else None
            if prefix is not None:
                _close_failure_inputs(self, error)
                self._active_failed = True
                discard_retry(self, captured_main['vm'], type(error).__name__)
                raise
            if raw_api is not None:
                raw_api.close()
            if raw3 is not None:
                raw3.close()
            if self._host129_source_clock_binding is not None:
                self._host129_source_clock_binding.close()
            if multicall is not None:
                multicall.close()
            for key, value in zip(witness_names, witnesses):
                if value is not None:
                    value.close()
                current = getattr(self, key)
                if current is not None and current is not value:
                    current.close()
            if main_owner:
                self._active_failed = True
                discard_retry(self, captured_main['vm'], type(error).__name__)
            raise
        finally:
            from .primary_main_prefix_stop import _current, _cleanup_runtime
            if main_owner and _current(self) is not None:
                _cleanup_runtime(self, captured_main)
            else:
                self._program_calls.pop()
                if name == 'main' and raw_api is not None:
                    raw_api.close()
                if name == 'main' and raw3 is not None:
                    raw3.close()
                if name == 'main' and multicall is not None:
                    multicall.close()
                    self._host129_multicall_binding = None
                if name == 'main' and self._host129_counter_binding is not None:
                    self._host129_counter_binding.close()
                if name == 'main' and self._host129_clock_service_binding is not None:
                    self._host129_clock_service_binding.close()
                if name == 'main' and self._host129_entropy_service_binding is not None:
                    self._host129_entropy_service_binding.close()
                if main_owner:
                    current = captured_main
                    self.last_host2252_budget = {'consumed': current['consumed'], 'remaining': current['remaining']}
                    self.last_host2252_g_budget = {'consumed': current['g_consumed'], 'remaining': current['g_remaining']}
                    self.last_host2252_f_budget = {'consumed': current['f_consumed'], 'remaining': current['f_remaining']}
                    self.last_host2252_pair_m_budget = {'consumed': current['pair_m_consumed'],
                                                       'remaining': current['pair_m_remaining']}
                    if self._active_main is captured_main:
                        self._active_main = None
                self._execute_depth -= 1
                if not self._execute_depth:
                    self._execute_thread = None
                if (main_owner and normal_return and raw_api is not None and raw_api.completed and
                        raw_api.closed and raw_api.main_owner is captured_main and
                        raw_api.main_vm is captured_main['vm'] and
                        getattr(raw_api.source, '_owns_delegate', True) is False and raw_api.source.completed and
                        not self._active_failed and captured_main['vm'] is not None and
                        captured_main['vm'].halted and captured_main['vm'].abort_reason is None):
                    self._host129_main_completion = (raw_api, raw_api.source, captured_main,
                                                    captured_main['vm'], self._main_generation)

    def _install_source_counter_write(self, vm):
        counter_binding = self._host129_source_clock_binding or self._host129_counter_binding
        original_write = vm._write
        def checked_counter_write(cell, value, width, source):
            if source == 'high.load':
                for pc, source_cell, destination, rva in counter_binding._roles:
                    if vm.pc == pc:
                        if (cell != destination or width != 4 or
                                vm.program.words[pc - 2:pc] != (source_cell, destination) or
                                vm.program.size(vm.program.words[pc - 3]) != 4 or
                                (counter_binding.check_counter_read(vm, pc, source_cell, destination, width, value)
                                 if counter_binding is self._host129_source_clock_binding else
                                 counter_binding.read(vm, pc, source_cell, destination, width) != value)):
                            raise InputError('host129 source counter witness differs from natural read')
                        break
            return original_write(cell, value, width, source)
        vm._write = checked_counter_write
        if counter_binding is self._host129_source_clock_binding:
            counter_binding._installed_write = (vm, checked_counter_write)
        return original_write

    def _execute_program(self, name, arguments, hosts):
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self)
        if self._host2252_pending is not None:
            raise InputError('resume the pending host2252 VM before starting another program')
        from .primary_vm import PrimaryVM
        frame = self._next(self._frames, "VM frame", name)
        if not isinstance(frame, PrimaryFrame) or frame.program != name:
            raise InputError("VM frame event does not match the actual invoked program")
        prefix_frames = self.__dict__.get('_local113_frame_plan')
        if prefix_frames is not None:
            prefix_frames.check_before_map(self, name, frame)
        if self._host129_source_clock_binding is not None:
            self._host129_source_clock_binding.check_frame(name, frame)
        if name == 'host129' and self._host129_multicall_binding is not None:
            self._host129_multicall_binding.check_frame(frame)
        replay = getattr(self, '_consumed_mgf', None)
        if replay is not None and replay.stateful_reader_pending():
            program = load_program(name, reader=replay)
        else:
            program = load_program(name)
            if replay is not None:
                replay.reader_gate(program, name)
        use_core = self.primary_core and replay is None
        reservation = arena_reservation(program)
        if frame.arena_size < reservation:
            raise PrimaryProgramLimit("VM frame is shorter than native arena reservation")
        from .primary_sign_lifecycle import cleanup, cleanup_main_allocations, region_at
        owned = []
        vm = None
        source_counter_write = None
        try:
            self.memory.map(frame.cells, bytearray((program.cell_count + 1) * 24),
                            name=name + " cells", initialized=False)
            owned.append((frame.cells, region_at(self.memory, frame.cells)))
            self.memory.map(frame.arena, bytearray(frame.arena_size),
                            name=name + " native private arena", initialized=False)
            owned.append((frame.arena, region_at(self.memory, frame.arena)))
            self.memory.write(frame.arena, bytes(reservation), source="35DBC95.arena_memset")
            vm = PrimaryVM(program, self.memory, cells_address=frame.cells,
                           arena_address=frame.arena, arena_size=frame.arena_size,
                           image_base=self.image_base, runtime=self, scalar_sse_state=self.scalar_sse_state)
            self.vms.append(vm)
            if prefix_frames is not None:
                prefix_frames.attach_vm(self, name, frame, vm)
            if not use_core and name == 'host129' and self._host129_counter_binding is not None:
                source_counter_write = self._install_source_counter_write(vm)
            if replay is not None:
                replay.attach_vm(vm)
            if self._singleton_producer_binding is not None:
                self._singleton_producer_binding.register_vm(vm, name)
            if name == 'main' and self._active_main is not None:
                self._active_main['vm'] = vm
                if self._host129_raw_binding is not None:
                    self._host129_raw_binding.attach_main(vm)
                if self._main_clock_binding is not None:
                    self._main_clock_binding.attach_vm(vm)
            if self._host129_source_clock_binding is not None:
                self._host129_source_clock_binding.attach_vm(name, frame, vm)
            if self._host129_api_binding is not None:
                self._host129_api_binding.attach_vm(name, vm)
            if name == "sdk-table-init":
                values = self._sdk_initializer_hosts(vm)
            elif name == "main":
                values = host_values(self.memory, image_base=self.image_base)
            elif name in _HOST_BANKS:
                bank = self.image_base + _HOST_BANKS[name]
                values = tuple(self.memory.load(bank + 8 * i, 8) for i in range(len(program.host_cells)))
            else:
                values = tuple(self.image_base + host for host in hosts) if hosts is not None else ()
            vm.initialize(arguments, values)
            direct_scope = self.__dict__.get('_primary_direct_scope')
            if direct_scope is not None:
                from .primary_direct_scopes import PrimaryDirectScope
                if type(direct_scope) is not PrimaryDirectScope or direct_scope.runtime is not self:
                    raise PrimarySemanticUnavailable('direct reader requires its original runtime scope')
                if name in ('host129', 'host129-prepare', 'host129-select'):
                    vm._primary_host129_reader_arguments = tuple(arguments)
                result = direct_scope.execute_program(name, vm)
                if result is NotImplemented:
                    raise PrimarySemanticUnavailable('direct scope did not cover the actual source program: ' + name)
            elif self.primary_backend == 'direct':
                raise PrimarySemanticUnavailable('direct backend requires its installed runtime scope')
            else:
                direct_host129 = NotImplemented
                if use_core and name in ('host129', 'host129-prepare', 'host129-select'):
                    host129_body = self._try_primary_host129_direct
                    if getattr(host129_body, '__func__', None) is not PrimaryRuntime._try_primary_host129_direct:
                        vm._primary_host129_reader_arguments = tuple(arguments)
                    direct_host129 = host129_body(name, vm)
                if direct_host129 is not NotImplemented:
                    result = direct_host129
                elif name == 'main' and use_core:
                    result = self._run_primary_main(vm)
                elif use_core and name in ('ecrypt-transform', 'ecrypt-keysetup', 'ecrypt-packet', 'ecrypt-blocks'):
                    result = self._try_primary_ecrypt_direct(name, vm)
                    if result is NotImplemented:
                        from .primary_ecrypt import run_primary_ecrypt
                        result = run_primary_ecrypt(vm, name)
                elif use_core and name == 'material-block':
                    result = self._run_primary_material(vm)
                elif use_core and name == 'material-state':
                    result = self._run_primary_material_state(vm)
                elif use_core and name == 'source2583':
                    from .primary_source2583 import commit_primary_source2583
                    result = vm.result if commit_primary_source2583(vm) else vm.run(max_steps=1_000_000)
                elif use_core and name == 'token-setter':
                    from .primary_token_setter import run_primary_token_setter
                    result = run_primary_token_setter(vm)
                elif use_core and name == 'token-expire':
                    from .primary_token_expire import run_primary_token_expire
                    result = run_primary_token_expire(vm)
                elif use_core and name == 'buffer-init':
                    from .primary_buffer_init import run_primary_buffer_init
                    result = run_primary_buffer_init(vm)
                elif use_core and name == 'singleton-init':
                    from .primary_singleton_init import run_primary_singleton_init
                    result = run_primary_singleton_init(vm)
                elif use_core and name == 'device-mix':
                    from .primary_device_mix import run_primary_device_mix
                    result = run_primary_device_mix(vm)
                elif use_core and name == 'device-records':
                    from .primary_device_record_cipher import run_primary_device_record_cipher
                    result = run_primary_device_record_cipher(vm)
                elif use_core and name == 'sdk-table-init':
                    from .primary_sdk_table import run_primary_sdk_table
                    result = run_primary_sdk_table(vm)
                elif use_core and name == 'entry-prepare':
                    from .primary_entry_prepare import run_primary_entry_prepare
                    result = run_primary_entry_prepare(vm)
                elif use_core and name == 'host129-prepare':
                    from .primary_host129_prepare import run_primary_host129_prepare
                    result = run_primary_host129_prepare(vm)
                elif use_core and name == 'singleton-destroy':
                    from .primary_singleton_destroy import run_primary_singleton_destroy
                    result = run_primary_singleton_destroy(vm)
                elif use_core and name in ('cocos-init', 'cocos-crypt', 'cocos-publish', 'host97'):
                    result = self._try_primary_startup_direct(name, vm)
                    if result is NotImplemented:
                        from .primary_policy3_core import (initialize_policy3_state, crypt_policy3_payload,
                                                           publish_policy3_digest, assemble_policy3_packet)
                        backend = {'cocos-init': initialize_policy3_state, 'cocos-crypt': crypt_policy3_payload,
                                   'cocos-publish': publish_policy3_digest, 'host97': assemble_policy3_packet}[name]
                        result = vm.result if backend(vm) else vm.run(max_steps=1_000_000)
                elif name == 'host129' and self._host129_source_clock_binding is not None:
                    source_counter_write = self._install_source_counter_write(vm)
                    result = vm.run(max_steps=1_000_000)
                elif use_core and name in ('primary-setup', 'status-audit', 'host129', 'host129-select'):
                    result = self._try_primary_startup_direct(name, vm) if name in ('primary-setup', 'status-audit') else NotImplemented
                    if result is NotImplemented:
                        from .primary_support_core import (run_primary_setup, run_primary_status_audit,
                                                           run_primary_host129, run_primary_host129_select)
                        backend = {'primary-setup': run_primary_setup, 'status-audit': run_primary_status_audit,
                                   'host129': run_primary_host129, 'host129-select': run_primary_host129_select}[name]
                        if backend(vm):
                            result = vm.result
                        else:
                            if name == 'host129' and self._host129_counter_binding is not None:
                                source_counter_write = self._install_source_counter_write(vm)
                            result = vm.run(max_steps=1_000_000)
                else:
                    result = vm.run(max_steps=1_000_000)
            from types import GeneratorType
            if type(result) is GeneratorType:
                from .primary_direct_main import _main_execution
                if name != 'main' or result.gi_code is not _main_execution.__code__:
                    result.close()
                    raise InputError('reader received an unauthorized execution body')
                result = yield from result
            from .primary_main_prefix_stop import _Witness, _finalize
            if name == 'main' and type(result) is _Witness:
                _finalize(self, vm, result)
            else:
                if self._host129_source_clock_binding is not None:
                    self._host129_source_clock_binding.complete_vm(name, vm)
                if self._host129_api_binding is not None:
                    self._host129_api_binding.complete_vm(name, vm)
            return result
        except BaseException as error:
            if self.host2252_retry_mode == 'synchronous' and vm is not None:
                vm.abort_reason = type(error).__name__
                vm.pending_native = None
            raise
        finally:
            if prefix_frames is not None:
                prefix_frames.retire_vm(self, name, frame, vm)
            if vm is not None and source_counter_write is not None:
                vm._write = source_counter_write
            if not self.retain_frames:
                try:
                    cleanup(self, owned)
                finally:
                    if vm is not None:
                        cleanup_main_allocations(self, vm)

    def _try_primary_host129_direct(self, name, vm):
        return NotImplemented

    def _try_primary_ecrypt_direct(self, name, vm):
        return NotImplemented

    def _try_primary_startup_direct(self, name, vm):
        return NotImplemented

    def _run_primary_material(self, vm):
        from .primary_material_cipher import run_primary_material
        return run_primary_material(vm)

    def _run_primary_material_state(self, vm):
        from .primary_material_state import run_primary_material_state
        return run_primary_material_state(vm)

    def _run_primary_main(self, vm, *, max_steps=1_000_000):
        if type(max_steps) is not int or max_steps < 1:
            raise InputError('max_steps must be a positive integer')
        state = getattr(vm, 'primary_main_state', None)
        if state is None or state.get('phase') == 'complete':
            state = {'execution': 'source', 'phase': 'running', 'retained_steps': 0}
            vm.primary_main_state = state
        initial_steps = len(vm.trace)
        try:
            result = vm.run(max_steps=max_steps)
        finally:
            state['retained_steps'] += len(vm.trace) - initial_steps
        state['phase'] = 'complete'
        return result

    def _primary_nonce_seed(self, vm):
        x = self.memory.load(self.image_base + 0x6D86090, 4)
        y = self.memory.load(self.image_base + 0x6D86094, 4, signed=True)
        if ((((x * x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31):
            return False
        seed = vm.cells.value(936) & 0xFFFFFFFF
        seed_pointer = vm.cells.value(114)
        random_pointer = vm.cells.value(115)
        self.memory.store(seed_pointer, int.from_bytes(seed.to_bytes(4, 'little'), 'big'),
                          4, source='primary_nonce.seed_big_endian')
        vm._write(952, random_pointer, 8, 'primary_nonce.random_pointer')
        vm.primary_nonce_state = {'start_word': 5827, 'resume_word': 7159,
                                  'phase': 'first_seed', 'completed_draws': 0}

        def seed_random(value, cell, word):
            vm._write(cell, value, 8, 'primary_nonce.srand_argument')
            address = vm.cells.value(965)
            vm.host_calls.append((word, address, (cell,), 147))
            _invoke_host(vm, address, (cell,), 147)

        def random_byte(cell, word):
            address = vm.cells.value(984)
            vm.host_calls.append((word, address, (), 129))
            result = _invoke_host(vm, address, (), 129)
            vm._write(cell, result, 8, 'primary_nonce.rand_result')
            vm.primary_nonce_state['completed_draws'] += 1
            return result & 255

        seed_random(seed, 964, 5990)
        vm.primary_nonce_state['phase'] = 'first_draws'
        for index in range(3):
            vm._write(966, index, 8, 'primary_nonce.first_draw_index')
            value = random_byte(983, 6102)
            vm.execute_once(10, (7, 3, 966, 986))
            self.memory.store(random_pointer + index, value, 1,
                              source='primary_nonce.first_draw_byte')
        seed = int.from_bytes(self.memory.read(seed_pointer, 4), 'big')
        vm.primary_nonce_state['phase'] = 'second_seed'
        seed_random((seed + 500) & 0xFFFFFFFF, 982, 6094)
        matches = 0
        vm.primary_nonce_state['phase'] = 'comparison_draws'
        for index in range(3):
            vm._write(990, index, 8, 'primary_nonce.comparison_index')
            vm.execute_once(10, (7, 3, 990, 1081))
            previous = self.memory.load(random_pointer + index, 1)
            matches += int(previous == random_byte(1084, 6880))
        vm._write(988, matches, 8, 'primary_nonce.match_count')
        vm.primary_nonce_state.update(phase='source_copy', matches=matches)
        vm.block = 127
        vm._jump(129)
        return True

    def _primary_nonce_checksum(self, vm):
        from .primary_nonce_finish import finish_primary_nonce
        return finish_primary_nonce(vm)

    def _primary_signature_core(self, vm):
        from .primary_signature_codec import _cbc_blocks, _initial_iv, _seed_footer, _transpose, _xor_outer

        if ((vm.cells.value(8643) & 0xFFFFFFFF) != 5 or
                (vm.cells.value(8646) & 0xFFFFFFFF) != 5):
            return False
        payload = self.memory.read(vm.cells.value(81), 75)
        seed = self.memory.read(vm.cells.value(140), 8)
        feedback = vm.cells.value(83)
        if self.memory.read(feedback, 16) != _initial_iv(seed):
            raise PrimarySemanticUnavailable('current main IV differs from its source-bound seed producer')
        output = vm.cells.value(8346)
        block_pointer = vm.cells.value(84)
        mixed_pointer = vm.cells.value(94)
        cipher_pointer = vm.cells.value(82)
        offset_pointer = vm.cells.value(85)
        initial_clock = vm.cells.value(8648)
        clock_address = vm.cells.value(8649)
        vm.primary_core_state = {'start_word': 64838, 'resume_word': 66398,
                                 'phase': 'blocks', 'completed_blocks': 0}

        def tail():
            self.memory.write(mixed_pointer, payload[64:] + bytes(5), source='primary_core.last_block_before_clock')
            vm.primary_core_state['phase'] = 'tail_clock'
            vm.host_calls.append((65472, clock_address, (), 135))
            current = _invoke_host(vm, clock_address, (), 135)
            vm._write(8733, current, 8, 'primary_core.tail_clock_result')
            value = ((current // 1_000_000) % 1_000_000) & 0xFFFFE
            value |= int(current > initial_clock and clock_address < 0x100000000)
            self.memory.store(vm.cells.value(86), value, 4, source='primary_core.tail_clock_word')
            return value.to_bytes(4, 'little')[:3]

        def m16(block):
            vm.primary_core_state['phase'] = 'm16'
            self.memory.write(mixed_pointer, _transpose(block), source='primary_core.CBC_mix')
            self.memory.write(block_pointer, block, source='primary_core.M16_input')
            address = vm.cells.value(8786)
            vm.host_calls.append((65833, address, (84,), 205))
            _invoke_host(vm, address, (84,), 205)
            return self.memory.read(block_pointer, 16)

        for index, cipher in enumerate(_cbc_blocks(payload, seed, tail, m16)):
            self.memory.write(cipher_pointer, cipher, source='primary_core.cipher_transpose')
            self.memory.write(feedback, cipher, source='primary_core.CBC_feedback')
            self.memory.write(output + 16 * index, cipher, source='primary_core.cipher_publish_private')
            self.memory.store(offset_pointer, 16 * (index + 1), 8, source='primary_core.block_offset')
            vm.primary_core_state['completed_blocks'] = index + 1
        vm.primary_core_state['phase'] = 'footer'
        footer = _seed_footer(seed)
        self.memory.write(output + 80, footer, source='primary_core.seed_footer_private')
        packet = bytearray(self.memory.read(output, 96))
        vm.primary_core_state['phase'] = 'outer'
        for position, value in _xor_outer(packet):
            self.memory.store(output + position, value, 1, source='primary_core.outer_xor_private')
        vm._write(8847, len(packet), 8, 'primary_core.completed_length')
        vm.primary_core_state['phase'] = 'complete'
        vm._jump(1659)
        return True

    def execute_main(self, arguments: tuple[int, ...], *, once10_read_budget=1024):







        from .primary_sign_lifecycle import start_execution
        return start_execution(self, self._execute_continued('main', arguments, None), once10_read_budget=once10_read_budget)

    def execute_main_prefix9563(self, arguments, *, max_steps):
        from .primary_main_prefix_stop import execute_main_prefix9563
        return execute_main_prefix9563(self, arguments, max_steps=max_steps)

    def rebind_main_prefix9563_inputs(self, host129_inputs, main_clock_inputs, *, provider_inputs=None):
        from .primary_main_prefix_stop import rebind_main_prefix9563_inputs
        return rebind_main_prefix9563_inputs(self, host129_inputs, main_clock_inputs, provider_inputs=provider_inputs)

    def resume_main(self, continuation, *, once10_read_budget=1024):
        from .primary_sign_lifecycle import resume_execution
        return resume_execution(self, continuation, once10_read_budget=once10_read_budget)

    def cancel_main(self, continuation):
        from .primary_sign_lifecycle import cancel_execution
        return cancel_execution(self, continuation)

    def finish_main_clock_inputs(self):
        if self._main_clock_binding is not None:
            self._main_clock_binding.finish()

    def finish_host129_source_clock_inputs(self):
        if self._host129_source_clock_binding is not None:
            self._host129_source_clock_binding.finish()

    def replay_singleton_history(self, history_lease):
        from .primary_singleton_history import replay_history
        return replay_history(self, history_lease)

    def _capture_stack(self, skip, count, destination, hash_pointer):
        if self.raw_core_observations is not None:
            return self.raw_core_observations.capture_stack(self, skip, count, destination, hash_pointer)
        if hash_pointer:
            raise PrimarySemanticUnavailable("stack capture with a hash destination is unavailable")
        expected_skip, expected_count, frames = self._next(self._stack_capture, "RtlCaptureStackBackTrace", skip, count)
        if (expected_skip, expected_count) != (skip, count):
            raise InputError("stack capture event does not match the actual skip/count arguments")
        if (not isinstance(frames, tuple) or len(frames) > min(count, 0xFFFF) or
                any(type(address) is not int or not 0 <= address <= _MASK64 for address in frames)):
            raise InputError("stack capture requires explicit pointer-width frames within the requested count")
        for index, address in enumerate(frames):
            self.memory.store(destination + 8 * index, address, 8,
                              source="RtlCaptureStackBackTrace.frame")
        return len(frames)

    def execute_primary(self, arguments: tuple[int, ...]):
        from .primary_sign_lifecycle import synchronous_execution
        return synchronous_execution(self, self._execute_primary_continued(arguments))

    def _execute_primary_continued(self, arguments: tuple[int, ...]):
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self)
        if not isinstance(arguments, tuple) or len(arguments) != 12:
            raise InputError("primary bridge requires the actual twelve-argument tuple")
        length = signed(arguments[6], 32)
        command = (self.memory.read(arguments[5], length)
                   if length in (4, 5, 13, 15, 20, 44, 47, 50, 51, 58, 60, 64) else b"")
        selected = command_guard(command, arguments[6])
        self.events.append(("2DE861B.command_guard", selected))
        target = self.memory.load(self.image_base + 0x6428890 + 8 * selected, 8)
        if target != self.image_base + (0x2DE862D if selected else 0x2DE8672):
            raise PrimarySemanticUnavailable("primary bridge current command dispatch is unavailable")
        if selected:
            address = self.execute("entry-prepare", (), None)
            target = self.memory.load(self.image_base + 0x64288A0 + 8 * int(bool(address)), 8)
            if target != self.image_base + (0x2DE8658 if address else 0x2DE8672):
                raise PrimarySemanticUnavailable("primary bridge current preparation dispatch is unavailable")
            if address:
                if address != self.stack_capture_address:
                    raise PrimarySemanticUnavailable("entry preparation returned an unbound stack capture function")
                count = self._capture_stack(0, 4, self.image_base + 0x6D86020, 0)
                self.memory.store(self.image_base + 0x6D86014, count, 2,
                                  source="2DE866B.stack_count")
        return (yield from self._execute_continued('main', (arguments[0] & 255, *arguments[1:]), None))

    def execute_caller_adapter(self, a, b, command, policy, d, *, core, feature_observation=(), borrowed_command=None):
        from .primary_sign_lifecycle import _sync_execution
        return _sync_execution(self._execute_caller_adapter_continued(a, b, command, policy, d, core=core,
                               feature_observation=feature_observation, borrowed_command=borrowed_command))

    def _execute_caller_adapter_continued(self, a, b, command, policy, d, *, core, feature_observation=(), borrowed_command=None):
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self)
        from .primary_command_classification import classify
        if any(not isinstance(value, bytes) for value in (a, b, command, d)):
            raise InputError('caller adapter requires its exact borrowed source bytes')
        if type(policy) is not int or not 0 <= policy <= 0xFFFFFFFF or not callable(core):
            raise InputError('caller adapter requires an unsigned configuration and its primary core')
        if not isinstance(feature_observation, tuple) or len(feature_observation) > 1:
            raise InputError('caller classification accepts zero or one logical feature observation')
        classification = (classify(self, command, observed_feature=feature_observation[0])
                          if feature_observation else classify(self, command))
        if classification == 0:
            return b'QQQQ'
        self.register_provider_callbacks()
        self.register_sdk_callbacks()
        from .primary_caller_audit import _call_continued
        options = {} if borrowed_command is None else {'borrowed_command': borrowed_command}
        return (yield from _call_continued(self, core, a, b, command, d, 3 if classification == 1 else 2, **options))

    def execute_string_adapter(self, sret, a, b, command, policy, d, *, stack_address, output_allocate=None):
        from .primary_sign_lifecycle import synchronous_execution
        return synchronous_execution(self, self._execute_string_adapter_continued(sret, a, b, command, policy, d,
                               stack_address=stack_address, output_allocate=output_allocate))

    def _execute_string_adapter_continued(self, sret, a, b, command, policy, d, *, stack_address, output_allocate=None):
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self)
        from .primary_adapter import string_view, write_string
        self.memory.store(stack_address + 0x6C, 0, 4, source="2DE5A91.length_zero")
        self.memory.write(stack_address + 0x70, bytes(128), source="2DE5A9C.output_zero")
        d_pointer, d_length = string_view(self.memory, d)
        command_pointer, command_length = string_view(self.memory, command)
        b_pointer, b_length = string_view(self.memory, b)
        a_pointer, a_length = string_view(self.memory, a)
        yield from self._execute_primary_continued((4, a_pointer, a_length, b_pointer, b_length,
                              command_pointer, command_length, stack_address + 0x70,
                              stack_address + 0x6C, policy & 0xFFFFFFFF, d_pointer, d_length))
        length = self.memory.load(stack_address + 0x6C, 4)
        if length > 128:
            raise PrimaryProgramLimit("string adapter output exceeds its native 128-byte buffer")
        write_string(self.memory, sret, self.memory.read(stack_address + 0x70, length),
                     self._allocate if output_allocate is None else output_allocate)
        return sret

    def _status_sensor(self):
        slot, mutex = self.image_base + 0x6D861C8, self.image_base + 0x6D861D0
        result = self.memory.load(slot, 8)
        if result:
            return result
        self.events.append(("75AF50.mutex.lock", mutex))
        if self.memory.load(slot, 8) == 0:
            expected, zero, address = self._next(self._allocations, "operator new", 32, False)
            if expected != 32 or zero is not False:
                raise InputError("operator new event does not match actual requested size/flags")
            if type(address) is not int or address == 0:
                raise PrimaryProgramLimit("operator new failure outside normal runtime domain")
            self.memory.map(address, bytearray(32), name="operator new(32)", initialized=False)
            self.allocations[address] = 32
            self.memory.write(address + 16, bytes.fromhex("aa000000000000008c00000000000000"),
                              source="2DE9267.status_tail")
            first = self._allocate(8, True)
            self.memory.store(address + 8, first ^ 0x8C, 8, source="2DE9280.encoded_pointer")
            second = self._allocate(8, True)
            self.memory.store(address, second ^ 0xAA, 8, source="2DE9299.encoded_pointer")
            direct_scope = self.__dict__.get('_primary_direct_scope')
            if direct_scope is None:
                self.execute("status-audit", (address, 3, 0, 2, 1), None)
            else:
                with direct_scope.status_audit('initialize', (address, 3, 0, 2, 1)):
                    self.execute("status-audit", (address, 3, 0, 2, 1), None)
            self.memory.store(slot, address, 8, source="2DE908C.status_publish")
        self.events.append(("75AFC0.mutex.unlock", mutex))
        return self.memory.load(slot, 8)

    def singleton(self) -> int:
        if self._warm_core_binding is not None:
            self._warm_core_binding.validate_getter()
        producer = self._singleton_producer_binding
        if producer is not None:
            if producer.closed:
                return producer.warm()
            with producer.root():
                return self._singleton()
        return self._singleton()

    def _singleton(self) -> int:
        guard_address = self.image_base + 0x6D88CC8
        slot_address = self.image_base + 0x6D88CC0
        guard = self.memory.load(guard_address, 4, signed=True)
        if guard > self.memory.load(self.tls_epoch_address, 4, signed=True):
            self._thread_header(guard_address)
            if self.memory.load(guard_address, 4, signed=True) == -1:
                result = self.execute("singleton-init", (),
                                      (0x3E92E00, 0x35921EC, 0x3EB2680, 0x359205B,
                                       0x3592191, 0x3592178, 0x3592214, 0x3592244, 0x3592274))
                self.memory.store(slot_address, result, 8, source="359240F.singleton_publish")
                from .primary_worker_consumer import _invoke
                from contextlib import nullcontext
                producer = self._singleton_producer_binding
                with producer.exit_scope() if producer is not None and producer.active else nullcontext():
                    _invoke(self, 0x3E680B4, self.image_base + 0x35922FD)
                self._thread_footer(guard_address)
        return self.memory.load(slot_address, 8)

    def _independent_main_timer(self, vm, rva, cells, argument_types):
        from threading import get_ident
        if vm.program.raw != load_program('main').raw:
            return False
        owner = self._active_main
        stack = self._program_calls
        markers = ((1160, 1168, (102, 279)), (34861, 34869, (102, 216)))
        valid = any(vm.pc == pc and vm.host_calls and
                    vm.host_calls[-1] == (word, self.image_base + 0x2DE561F, args, 125)
                    for word, pc, args in markers)
        if (rva != 0x3592430 or cells != () or argument_types not in (None, ()) or
                vm.runtime is not self or owner is None or owner['vm'] is not vm or
                owner['thread'] != get_ident() or owner['generation'] != self._main_generation or
                self._execute_thread != get_ident() or len(stack) != 1 or
                stack[0]['name'] != 'main' or stack[0]['hosts'] is not None or
                len(stack[0]['arguments']) != 12 or stack[0]['arguments'][0] != 4 or
                vm.cells.value(288) != self.image_base + 0x2DE561F or not valid):
            raise InputError('independent main timer source owner mismatch')
        return True

    def invoke(self, vm, rva: int, cells: tuple[int, ...], *, argument_types=None):
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self)
        producer = self._singleton_producer_binding
        if producer is not None:
            producer.validate_dispatch(vm, rva, cells)
        if self._host2252_pending is not None:
            pending = self._host2252_pending
            if rva != 0x359253D or pending['vm'] is not vm or pending['cells'] != cells:
                raise InputError('resume the exclusive pending host2252 native call')
            from .primary_host2252_retry import invoke_retry
            return invoke_retry(self, vm, cells, pending['pointer'])
        common = self.__dict__.get('_common_guid_export')
        if common is not None and self.image_base + rva == common.address:
            return common.invoke(vm, cells, argument_types)
        if self.raw_core_observations is not None:
            self.raw_core_observations.validate_target_use(self, self.image_base + rva)
            self.raw_core_observations.validate_export_abi(self.image_base + rva, vm, cells, argument_types)
        def arg(n):
            return vm.cells.value(cells[n])
        if rva in (0x2DE4CBD, 0x1BFD3E0, 0x1BFD570, 0x3EB2AC0):
            from .primary_signature_encoding import invoke
            return invoke(self, rva, tuple(arg(index) for index in range(len(cells))))
        if rva in (0x3EB5EA0, 0x3EB5EB0):
            from .primary_notification_modules import invoke_thunk
            return invoke_thunk(self, rva, tuple(arg(index) for index in range(len(cells))))
        if self.__dict__.get('_notification_module_collector_claim') is not None:
            from .primary_notification_modules import _IMPORTS as module_imports, invoke_api
            for name in module_imports:
                if self.worker_imports.get(name) == self.image_base + rva:
                    return invoke_api(self, name, tuple(arg(index) for index in range(len(cells))))
        from .primary_material_process import _THUNKS, _IMPORTS as process_imports
        from .primary_material_process import compare_process_name, invoke_process_material, resolve_process_thunk
        if rva in _THUNKS:
            return resolve_process_thunk(self, vm, rva, cells, argument_types)
        if rva == 0x3E9C1D0:
            if len(cells) != 2:
                raise InputError('3E9C1D0 takes two wide-string pointers')
            return compare_process_name(self, arg(0), arg(1))
        for name in process_imports:
            if self.worker_imports.get(name) == rva + self.image_base:
                return invoke_process_material(self, name, tuple(arg(n) for n in range(len(cells))))
        if rva == 0xBA22B0:
            if len(cells) != 5:
                raise InputError('BA22B0 takes command, payload, length, caller DWORD and output')
            owner = getattr(self, '_primary_entry_owner', None)
            if owner is None:
                raise PrimarySemanticUnavailable('BA22B0 requires its actual PrimarySigner owner')
            return owner.invoke_primary_entry(*(arg(index) for index in range(5)))
        if rva == 0xBCD370:
            if cells:
                raise InputError('provider cache exit callback takes no arguments')
            from .primary_provider_cache_destroy import destroy_cache
            return destroy_cache(self)
        if rva == 0xBCD020:
            if cells:
                raise InputError('shared configuration exit callback takes no arguments')
            from .primary_configuration_exit import destroy_configuration
            return destroy_configuration(self)
        if rva == 0xBCD560:
            if cells:
                raise InputError('telemetry exit callback takes no arguments')
            from .primary_telemetry_exit import destroy_telemetry
            return destroy_telemetry(self)
        if rva == 0xBCD270:
            if len(cells) != 1:
                raise InputError('provider cache destructor takes one receiver')
            from .primary_provider_cache_destroy import destroy_cache
            return destroy_cache(self, arg(0))
        if rva == 0x35922FD:
            if cells:
                raise InputError('singleton exit callback takes no arguments')
            return self.execute('singleton-destroy',
                                (self.memory.load(self.image_base + 0x6D88CC0, 8),), None)
        if rva == 0x35923A0:
            if len(cells) != 2:
                raise InputError('singleton destructor host reader takes destination and DWORD byte count')
            count = signed(arg(1), 32)
            if count < 0 or count > 32:
                raise PrimaryProgramLimit('singleton destructor host read exceeds its fixed source bank')
            self.memory.copy_disjoint(arg(0), self.image_base + 0x6557000, count,
                                      label='35923A0.singleton_destroy_hosts')
            return arg(0)
        if rva in (0xB9F8D0, 0xBED780, 0xBED790, 0xBED980, 0xBED990, 0xBED7B0, 0xBED9B0,
                   0x1BE5BC0):
            from .primary_configuration_callbacks import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0xBED870 and len(cells) == 2:
            from .primary_configuration_callbacks import handles_swap, swap
            if handles_swap(self, arg(0), arg(1)):
                return swap(self, arg(0), arg(1))
        if rva in (0xBD0A00, 0xBEDB20, 0x1BE5CE0, 0xBD3EF0, 0xBD3890, 0xBD4460, 0xBEE240):
            from .primary_source_postfetch import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0xBEDC00 and len(cells) == 2:
            from .primary_material import provider_device_getter
            return provider_device_getter(self, arg(0), arg(1))
        if rva in (0x1C54180, 0x1C1B430, 0xBED870, 0x1C540A0, 0x1C540C0,
                   0x142A0, 0x1C540F0):
            from .primary_sdk_collection import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1C018C0, 0x5C7470, 0x1C2D0F0):
            from .primary_sdk_events import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x1C29DA0:
            from .primary_sdk_registry import match_subkeys
            return match_subkeys(self, *(arg(n) for n in range(len(cells))))
        if rva in (0x1C53C90, 0x1C53770, 0x1BF5620, 0x1BF5770, 0x1C1B350,
                   0xBECD60, 0x1C03190, 0x1C03150, 0x1C03170, 0x1C03200):
            from .primary_sdk_records import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1C2A9E0, 0x1C2D200, 0x1BEE6A0, 0xBA1A90, 0x1C2A860,
                   0x1C2A7E0, 0xD46840, 0x104D10E, 0xD45AF0, 0x1BF5070, 0xD46AA0):
            from .primary_notification_thread import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1C29910, 0x1C21700, 0x1BB9250):
            from .primary_device_notification_worker import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x1D20B30:
            if cells:
                raise InputError('module collector requires its original zero logical argument ABI')
            from .primary_notification_modules import collect
            return collect(self)
        if rva in (0x1D209F0, 0x1D20720, 0x3E6D7B0):
            from .primary_notification_modules import invoke_helper
            return invoke_helper(self, rva, tuple(arg(index) for index in range(len(cells))))
        if rva in (0x35D44F0, 0x35D4630):
            from .primary_notification_environment_values import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x2E031A0:
            if len(cells) != 2:
                raise InputError('notification parent requires its physical RCX/RDX ABI')
            from .primary_notification_parent import produce_parent
            return produce_parent(self, arg(1))
        if rva == 0x2E09EF0:
            from .primary_notification_parent import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1D0ED90, 0x1D0EAC0, 0x35CC6B0, 0x1D0EC50, 0x1D0C670,
                   0x1D0C0B0, 0x1D08ED0, 0x1D08CF0, 0x1D05E50, 0x35C0300,
                   0x35CB850, 0x35CC330, 0x2E09810, 0x3E8EDDC):
            if self.primary_backend == 'direct':
                scope = self.__dict__.get('_primary_direct_scope')
                if scope is None:
                    raise PrimarySemanticUnavailable('notification vectors require their actual parent phase')
                scope.require_parent_phase()
            from .primary_notification_vectors import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1D24080, 0x1D27430, 0x1D271F0, 0x1D260D0, 0x1D24140, 0x1D1F8D0):
            from .primary_notification_module_records import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x2DF8D00:
            from .primary_device_integrity import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x35A6B90, 0x35A92F0):
            from .primary_notification_files import invoke
            return invoke(self, rva, tuple(arg(index) for index in range(len(cells))))
        if rva in (0x35AA260, 0x35B3FE0, 0x35BDB60):
            from .primary_notification_integrity_files import invoke
            return invoke(self, rva, tuple(arg(index) for index in range(len(cells))))
        if rva in (0x35A3D90, 0x35A3930, 0x35A6940, 0x35A3730, 0xC8924):
            from .primary_notification_collectors import invoke_accounts
            return invoke_accounts(self, rva, tuple(arg(index) for index in range(len(cells))))
        if rva == 0x35A32A0:
            from .primary_notification_accounts import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1D27F30, 0x1D193B0, 0x1D1F7F0, 0x1D1F860, 0x2E0FE10, 0x35BE420, 0x35C0550, 0x35CB7E0) or rva in range(0x2DF7450, 0x2DF7630, 0x20) or rva in range(0x35A69D0, 0x35A6B90, 0x20):
            from .primary_notification_static_initializers import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x2E0AB10:
            if cells:raise InputError('static unit takes no arguments')
            from .primary_notification_static_initializers import initialize_static_unit
            return initialize_static_unit(self)
        if rva == 0x2E07D30:
            if cells:
                raise InputError('notification startup initializer takes no arguments')
            from .primary_notification_startup import construct
            return construct(self)
        if rva == 0xB9C830:
            if len(cells) != 1:
                raise InputError('JSON destroy takes one node pointer')
            from .primary_notification_json import destroy
            return destroy(self, arg(0))
        if rva == 0x2DF54B0:
            if len(cells) != 4:
                raise InputError('JSON compact takes node, depth, format and printbuffer')
            from .primary_notification_json import compact
            return compact(self, arg(0), arg(1), arg(2), arg(3))
        if rva in (0x35BD530, 0x35BDB80, 0x35BD9E0):
            if len(cells) != 5:
                raise InputError('notification map variant requires its five source arguments')
            from .primary_notification_map import invoke_variants
            return invoke_variants(self, rva, tuple(arg(index) for index in range(5)))
        if rva in (0x2DF7BF0, 0x2DF7630, 0x2DF8200, 0x2E01C70):
            from .primary_notification_mandatory_maps import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x2E07350, 0x2E07AB0, 0x2E074D0, 0x2E077F0):
            from .primary_notification_map import invoke_mandatory
            return invoke_mandatory(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x2E06D10, 0x2E071C0):
            if len(cells) != 5:
                raise InputError('notification map entry takes five arguments')
            from .primary_notification_map import invoke
            return invoke(self, rva, tuple(arg(index) for index in range(5)))
        if rva in (0x1CF64E0, 0x48A5E, 0x2E09A50):
            from .primary_notification_collectors import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x2E0F5F0:
            from .primary_notification_timezone import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x35BF640:
            from .primary_notification_process import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x2E02AE0:
            from .primary_notification_environment import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BF50C0, 0x1BF4FE0, 0x1BF51B0, 0xBD5420):
            from .primary_pending_thread import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x3EA4B68, 0x3EA4C1C, 0x3EA1AA8, 0x3EA1958, 0x3EA19A8):
            from .primary_crt_application import invoke
            return self._crt_call(invoke, rva, tuple(arg(n) for n in range(len(cells))))
        if getattr(self, 'crt_startup_observations', None) is not None and rva in (
                0x3EA1F60, 0x3EA0AC8, 0x3EA1CC0, 0x3EA1FA8, 0x3EA1D04,
                0x3EA141C, 0x3EA140C, 0x3EA0CCC, 0x3EA0B90, 0x3EA0B30, 0x3EA0B0C):
            from .primary_crt_startup import invoke
            if rva == 0x3EA0B30:
                if cells:
                    raise InputError('CRT current thread requires no arguments')
                return self._crt_thread()
            return self._crt_call(invoke, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x3E816B0, 0x3E8179C, 0x787930):
            from .primary_thread_creation import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x760060, 0x787AB0, 0x760110, 0x787AE0, 0x36E0, 0xBD55C0,
                   0x7879A0, 0x760140, 0x760250, 0x760280, 0xD46A60, 0x3EA0B90,
                   0x3EA0B30, 0x3E81800, 0x3E81790, 0x3E81868):
            from .primary_thread_dispatch import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x3EA0F1C, 0x3EA0D54, 0x3EA0E24, 0x3EA0C20, 0x3EA0CEC,
                   0x3EA0150, 0x3EA01D0, 0x3EA5B28, 0x3EA5BB4, 0x3EA5C5C,
                   0x3EA5DD4, 0x3EA5DFC, 0x3EA5E24, 0x3EA564C, 0x3EA5A94,
                   0x3EA5150, 0x3EA5544, 0x3EA1FE0, 0x3EA1FFC):
            from .primary_crt_thread import invoke
            return self._crt_call(invoke, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1C2A3B0, 0x1BE3FF0, 0x1BE5250, 0x1C2A440, 0x1C2A450,
                   0x1C2A470, 0x1C2A4F0, 0x1C2A5C0, 0x1C2A6A0, 0xBD4FA0,
                   0xD46B40, 0xD46BD0):
            from .primary_feature_notifications import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x2C5D590, 0x1BE6150):
            from .primary_device_native import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x3591F69:
            if cells:
                raise InputError('random device exit takes no arguments')
            slot = self.image_base + 0x6D88CB0
            pointer = self.memory.load(slot, 8)
            self.memory.store(slot, 0, 8, source='3592018.random_device_slot_clear')
            if pointer:
                from .primary_worker_consumer import _invoke
                _invoke(self, 0x28F0, pointer)
                self._free_allocation(pointer)
            return None
        if rva in (0xBEE3C0, 0xBEE430, 0x1D332F0, 0x1BE5CD0, 0x1BE77F0, 0x2E11550, 0x1D3D970, 0x1D3DB90, 0x1C298C0):
            from .primary_device_records import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x2E13C70, 0x3E68580, 0x2E09930, 0x2DEB5E0, 0x2E15D90,
                   0x2E18240, 0x2E191B0, 0x2E1A7C0, 0x2E1D1B0, 0x2E1E160,
                   0x2E1F6D0, 0x2E20C10):
            from .primary_device_wmi import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BE87B0, 0x1BE87D0, 0x1BE88A0, 0x1BE8960, 0x1BEA500,
                   0x1BEA5C0, 0x1BEACF0, 0x1BEABF0, 0x1BED780, 0x35D5A80,
                   0x1BEBD30, 0x1BED080, 0x1BEA4E0):
            from .primary_device_adapters import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BED570, 0x1BED2F0, 0x35D5C30, 0x2E11020, 0x37AAE6):
            from .primary_device_hardware import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BED930, 0x1BEDC50, 0x1BEDD40):
            from .primary_device_system import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x2E123C0, 0x2E137F0, 0x1BEE390, 0x2E15CA0, 0x2E24080, 0x2E15490):
            from .primary_device_cold import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x2E24240:
            from .primary_device_adapter_details import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x35E9640, 0x3C715D0, 0x3C716B0, 0x3C71590, 0x3C712C0, 0x35EC010, 0x35EC180, 0x35EC530):
            from .primary_device_system_records import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x35ECC50, 0x3C71430, 0x35ED8F0, 0x35EDA10, 0x35EDD40, 0x35EE0A0, 0x35EDBB0, 0x35EE6C0,
                   0x35EDC70, 0x35EEAA0, 0x35EF450):
            from .primary_device_process_records import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x2E252A0, 0x35F0A70, 0x35EF600, 0x2E09B80, 0x75E7B0, 0x75E9F0):
            from .primary_device_refresh import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BE5B70, 0x35FACA0, 0x35FADB0, 0x35F3080, 0x35F41F0, 0x2E270E0, 0x2E26140):
            from .primary_device_provenance import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x3C71760, 0x3C71980, 0x35F55D0, 0x35F8E10, 0x35F8950, 0x35F78B0):
            from .primary_device_cache import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x3E6E398:
            from .primary_crt_startup import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x781270, 0x781180, 0x769A10, 0x77DFE0, 0x3E6E7F8):
            from .primary_shared_locale import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x3E824C8, 0x3E82688, 0x3E82540):
            from .primary_crt_locale import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x2E28B80, 0x2E297B0, 0x1BE5B30, 0x1D05BC0, 0x2E11240, 0x77DFE0, 0x35F5520,
                   0x35FB2C0, 0x35FB3C0, 0x35F7BE0, 0x35F7FE0, 0x35F1EB0):
            from .primary_device_identifiers import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x1BDF3E0 and len(cells)==3:
            from .primary_mmkv_load import crc_zero
            return crc_zero(self, arg(0), arg(1), arg(2))
        if rva in (0x2E12310, 0x2E25B70, 0x1D3CF00, 0x75CEC0, 0x35F4E50, 0x2E09670, 0x2E09690):
            from .primary_device_collector import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BF33F0, 0x1BF52B0, 0x1BF41E0, 0x1BF3DB0, 0x1BF3DD0,
                   0x1BF3E40, 0x1BF3E90, 0x1BF3D40, 0x1BF13C0, 0x1BF3EE0,
                   0x1BF3530, 0x1BF59E0, 0x1BF5B70, 0x1BF42A0, 0x1BF4300,
                   0x1BF4390, 0x1BF4450, 0x1BF4490, 0x1BF44D0, 0x1BF4B40):
            from .primary_pending_reports import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BF5D70, 0x1BE4230, 0x1BF2390, 0x1CE2C50):
            from .primary_request_direct import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1CF35E0, 0x1224BDC, 0x28B53A, 0x92FAA, 0x92FC4,
                   0x3CC9A, 0x3CDE2, 0x3C77E, 0x3C7D8, 0x3C818, 0x3CFCF, 0x8ED82):
            from .primary_request_manager import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x759A80, 0x759B00, 0x3E88BE0, 0x3E98FD8, 0x3E98FF0, 0x1D31950,
                   0x1D32390, 0x1D31A70, 0x1D320A0, 0x1CF5CB0, 0x1C411C0, 0x1D30A90):
            from .primary_request_delay import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1D00FC0, 0x1D026F0, 0x1D040D0, 0x1D040F0, 0x1CFA5C0,
                   0x1CFD070, 0x1CFD310, 0x1CFCE60, 0x1CFA8C0, 0x1CFD300, 0x1CF9D70, 0x1CFAC00):
            from .primary_caller_online import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1CF5E00, 0x1BF1AB0):
            from .primary_caller_diagnostics import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1CFC560, 0x1CFBA20, 0x1CFFCF0, 0x1CFFE20, 0x1CFEC10,
                   0x1CFEF20, 0x1CFF0F0, 0x1CFF2C0, 0x1CFFB80, 0x1D019D0, 0xBD48F0,
                   0x1D027F0, 0x1D02830, 0x1D028D0, 0x1D02990, 0x1D029A0):
            from .primary_caller_queue import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0xBE1730, 0xBE2680, 0xBE2BC0):
            from .primary_request_submit import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1CF4360, 0x1CE2AF0, 0x1CE2B10, 0x1CE2B30, 0x1CE2B50,
                   0x1C54B50, 0x1C54B70, 0x1C54B80):
            from .primary_request_startup import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1C54C00, 0x1C54E10, 0x7602D0, 0x7603B0, 0x3E9901C, 0x1C55120):
            from .primary_request_runtime import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1CC6E10, 0x1C00F80, 0x1C572E0):
            from .primary_request_entry import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1CACFA0, 0x1CD3CB0, 0x1CB0580, 0x1CABB60, 0x1CACBB0):
            from .primary_request_response import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1CE9930, 0x1CF2D00, 0x1CF4110, 0x75B070, 0x75B0A0,
                   0x1CE3390, 0x1CE82B0, 0x1CE4EF0, 0x1CE6300, 0x1CE6850):
            from .primary_request_transport import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1D27500, 0x1D27510, 0x1D27530):
            from .primary_module_callback import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x1CE6920:
            from .primary_worker_handoff import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0xBDCAD0, 0xBDCA30, 0xBE0840, 0x1BE5680, 0x1BE59D0):
            from .primary_worker_response import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BF7620, 0x2DE93E0, 0x35922AC, 0x2DE942F):
            from .primary_worker_device import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1C1BB80, 0x1BE2F80):
            from .primary_worker_loop import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0xBD4B00, 0xBD5100, 0xBD51D0, 0xD45A80, 0x787840):
            from .primary_worker_entry import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0xBD4710, 0xBD49E0, 0xBD0780, 0xBD5690, 0xBD0980, 0xBD5330, 0xBD54F0,
                   0xBD42E0, 0xBD4320, 0xBD4340, 0xBD43E0):
            from .primary_worker_tasks import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0xBD5FA0, 0xBD4700, 0xBD6110, 0xBD43B0, 0xBD43C0,
                   0xBD3AE0, 0xBCD740, 0xBD48F0):
            from .primary_task_exit import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0xBD61F0, 0xBD6170):
            from .primary_worker_consumer import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0xBC2100, 0x1BE3F80, 0xB9F1D0, 0x1C56610):
            from .primary_logger import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1C50FE0, 0x1C513C0, 0x1C513E0, 0x1C51410, 0x1C514B0, 0xBE35C0, 0xBBDB00,
                   0x1C22D50, 0x1C22D90, 0x1C29F90, 0x75FF40, 0x1C41AE0, 0x1C41AF0, 0x1C41B10, 0x1C50F70):
            from .primary_client_configuration import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1C52510, 0x1BE39B0):
            from .primary_feature_config import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x1BF3780, 0x1BF37D0, 0x2DE0A90, 0x2DE0D60, 0x2DE0B00,
                   0x358B3F0, 0x358B4F0, 0x1C02430, 0x1C026E0, 0x2DF2B40,
                   0x2DF2C10, 0x2DF37D0, 0x1BF2300, 0x3588A50, 0x3589150,
                   0x3589490, 0x2DF47D0, 0x2DF47E0, 0x2DF4800, 0x2DDF700,
                   0x2DE0B40, 0x2DE0B80, 0x2DE0BA0, 0xB95880, 0xBED000,
                   0x2DE0C10, 0x358AC50, 0x2DE0E00, 0x2DF48F0, 0x3591650, 0x3588A40,
                   0x2DE06D0, 0x2DE0AF0, 0x358B020, 0x358A210, 0x3589D40, 0x358ABB0,
                   0x6270, 0x75CD00, 0x75B810):
            from .primary_super_reporter import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x1BF63F0 and not cells:
            return self._register_provider_base(vm)
        if rva in (0x2DF2230, 0x1C01F50, 0x1C02220, 0x2DEC280, 0x2DECDE0,
                   0x2DED550, 0x2DF0870, 0x2DF1D40, 0x2DEFA30, 0x2DEED00,
                   0x1BF0AD0, 0x2DF02A0, 0x2DEDFA0, 0x2DF0A10, 0x2DF0A20,
                   0x2DF0A40, 0x2DF1450, 0x2DF1470, 0x2DF14A0, 0x787920,
                   0x1BF7670, 0x776860, 0xBCD880, 0xB8F200):
            from .primary_high_reliability import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x1BE4230:
            if len(cells) != 2:
                raise InputError('feature boolean lookup requires logger and identifier')
            from .primary_logger import feature
            return int(feature(self, arg(0), arg(1)) == 1)
        if rva in (0x2DE94F0, 0x2DE9570, 0x2DE9910, 0x2DEA400, 0x2DF5490, 0x2E11410, 0x3E8F070):
            from .primary_worker import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva in (0x2C5C7F0, 0x1C00BC0, 0x1C00BF0, 0x1C00F90, 0x2C5CAA0, 0x2C5CB70,
                   0x2C5C8F0, 0x2C5C9A0, 0xB8E60, 0x3586170, 0x75BEA0, 0x75BEB0,
                   0x2C5CA50, 0x2C5CB20, 0x1BE3060, 0xBA21A0, 0x1CE2BD0, 0x1CE2B70,
                   0x75AD90, 0x75B000, 0x787720, 0x28F0, 0x1FE0, 0x63EC0, 0x1C1BA80,
                   0x2DE8CAF, 0x2DE8C9D, 0xBCEDF0, 0xBCEE60, 0xBCEED0):
            from .primary_sdk import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if self.create_thread_address is not None and rva + self.image_base == self.create_thread_address:
            if len(cells) != 6:
                raise InputError("CreateThread takes six arguments")
            arguments = tuple(arg(n) for n in range(6))
            raw_arguments = arguments
            arguments = (*arguments[:4], arguments[4] & 0xFFFFFFFF, arguments[5])
            event = self._next(self._create_thread, "CreateThread", *arguments)
            from .primary_thread_api import RawCreateThreadObservation, apply_observation
            if type(event) is RawCreateThreadObservation:
                return apply_observation(self, event, raw_arguments)
            if arguments[5]:
                raise PrimarySemanticUnavailable("CreateThread nonnull thread-ID output needs explicit memory effects")
            if (not isinstance(event, tuple) or len(event) != 7 or
                    any(type(value) is not int or not 0 <= value <= _MASK64 for value in event) or
                    event[:6] != arguments):
                raise InputError("CreateThread needs matching arguments and an observed pointer-width handle")
            handle = event[6]
            self.thread_starts.append(event)
            self.events.append(("CreateThread.observed", *event))
            return handle
        if self.critical_section_init_address is not None and rva + self.image_base == self.critical_section_init_address:
            if len(cells) != 1:
                raise InputError("InitializeCriticalSection takes one pointer")
            pointer = arg(0)
            if pointer in self.locks:
                raise PrimarySemanticUnavailable("critical section is already initialized in this runtime")
            self.memory.forget(pointer, 40, source="InitializeCriticalSection.opaque_state")
            self.locks[pointer] = 0
            self.events.append(("InitializeCriticalSection", pointer))
            return None
        if rva in (0x75B030, 0x787780):
            if len(cells) != 1:
                raise InputError("critical section destruction takes one pointer")
            if rva == 0x75B030:
                return self.invoke(vm, 0x787780, cells)
            target = self.memory.load(self.image_base + 0x490FCA0, 8)
            if target != self.worker_imports.get("DeleteCriticalSection"):
                raise PrimarySemanticUnavailable("DeleteCriticalSection current import target is not bound")
            self.invoke(vm, target - self.image_base, cells)
            return 0
        if self.worker_imports.get("DeleteCriticalSection") == rva + self.image_base:
            if len(cells) != 1:
                raise InputError("DeleteCriticalSection takes one pointer")
            pointer = arg(0)
            if pointer not in self.locks or self.locks[pointer] != 0:
                raise PrimarySemanticUnavailable("DeleteCriticalSection needs an initialized unowned critical section")
            del self.locks[pointer]
            self.memory.forget(pointer, 40, source="DeleteCriticalSection.opaque_state")
            self.events.append(("DeleteCriticalSection", pointer))
            return None
        if rva == 0x3E680B4:
            if len(cells) != 1:
                raise InputError("CRT exit registration takes one callback")
            callback = arg(0)
            event = self._next(self._exit_registration, "CRT exit registration", callback)
            if (not isinstance(event, tuple) or len(event) != 2 or type(event[0]) is not int or
                    event[0] != callback or type(event[1]) is not int or event[1] not in (0, -1)):
                raise InputError("CRT exit registration requires matching callback and observed0/-1 result")
            if event[1] == 0:
                self.exit_callbacks.append(callback)
            return event[1] & 0xFFFFFFFF
        if rva in (0x1BF6790, 0x1BF6D80):
            from .primary_command_classification import invoke
            return invoke(self, rva, tuple(arg(index) for index in range(len(cells))))
        if rva == 0x1BF63F0:
            self._register_provider_base(vm)
            return None
        if rva == 0x1BF6540:
            self.register_provider_callbacks(vm)
            return None
        if rva == 0x1BF6670:
            self.register_sdk_callbacks(vm)
            return None
        if rva in (0xBA0270, 0xBA1A10, 0x1BEE450, 0x1BEE9A0, 0x1BE2910, 0x1BE2EB0,
                   0x1BF7660, 0xBCDAD0):
            from .primary_provider_init import invoke
            return invoke(self, rva, tuple(arg(index) for index in range(len(cells))))
        if rva == 0x1BEFC10:
            if len(cells) != 6:
                raise InputError('request telemetry entry requires six arguments')
            from .primary_request_audit import consume
            return consume(self, *(arg(index) for index in range(6)))
        if rva == 0x1BEEC40:
            if len(cells) != 4:
                raise InputError('direct request telemetry entry requires four arguments')
            from .primary_request_audit import submit_event
            return submit_event(self, *(arg(index) for index in range(4)))
        if rva == 0x1BE26C0:
            if len(cells) != 3:
                raise InputError('request telemetry metadata entry requires three arguments')
            from .primary_request_audit import metadata
            return metadata(self, *(arg(index) for index in range(3)))
        if rva in (0x1BF75A0, 0x1BF8090):
            if len(cells) != 4:
                raise InputError("SDK material-control wrapper requires value, bit, operation and byte selector")
            direct_scope = self.__dict__.get('_primary_direct_scope')
            if direct_scope is not None and direct_scope.notification_owner is not None and not direct_scope.notification_handoff_setting(vm, rva, cells, completed=False):
                direct_scope.notification_setting(vm, rva, cells, completed=False)
            self._register_provider_base(vm)
            if rva == 0x1BF75A0:
                direct_scope = self.__dict__.get('_primary_direct_scope')
                if direct_scope is None:
                    return self.invoke(vm, 0x2DE8C4C, cells)
                with direct_scope.status_host(vm, cells):
                    return self.invoke(vm, 0x2DE8C4C, cells)
            target = self.invoke(vm, 0x2DE8C9D, ())
            caller_binding = getattr(self, '_caller_wrapper_binding', None)
            caller_scoped = caller_binding is not None and caller_binding.scoped(self)
            if caller_scoped:
                caller_binding.begin_wrapper(self, target, tuple(arg(index) for index in range(4)))
            caller_normal = False
            try:
                first = self.invoke(vm, 0x3E84C9C, ())
                second = self.invoke(vm, 0x3E84C9C, ())
                caller_normal = True
            finally:
                if caller_scoped:
                    caller_binding.end_wrapper(self, caller_normal)
            if not (first ^ second) & 1:
                result = self.invoke(vm, target - self.image_base, cells)
            else:
                result = None
            if direct_scope is not None and direct_scope.notification_owner is not None and not direct_scope.notification_handoff_setting(vm, rva, cells, completed=True):
                direct_scope.notification_setting(vm, rva, cells, completed=True)
            return result
        if rva in (0x3E84CC0, 0x3E84CE4):
            from .primary_crt_error_map import invoke
            return invoke(self, rva, tuple(arg(n) for n in range(len(cells))))
        if rva == 0x3E84C9C:
            if cells:
                raise InputError("initialized CRT pointer query takes no arguments")
            caller_binding = getattr(self, '_caller_wrapper_binding', None)
            if caller_binding is not None and caller_binding.query_active(self):
                return caller_binding.query(self)
            if self.crt_error_storage is not None:
                from .primary_crt_error_map import storage_pointer
                return storage_pointer(self, 0x20)
            pointer = self._crt_thread()
            if pointer > _MASK64 - 0x20:
                raise PrimaryProgramLimit("CRT pointer addition wraps outside the normal initialized domain")
            return pointer + 0x20
        if rva == 0x75C610:
            from .primary_sdk_blob import push_character
            if len(cells) != 2:
                raise InputError("75C610 requires String24 and character")
            return push_character(self, arg(0), arg(1))
        if rva == 0xBBFC30:
            from .primary_sdk_blob import bootstrap_blob
            if len(cells) != 3:
                raise InputError("BBFC30 requires key CString, external32 pointer and caller length")
            return bootstrap_blob(self, arg(0), arg(1), arg(2))
        if rva == 0x1D29280:
            from .primary_sdk_blob import locate_blob
            if cells:
                raise InputError("1D29280 module locator takes no arguments")
            return locate_blob(self)
        if rva == 0x75E460:
            from .primary_sdk_blob import parse_key
            if len(cells) != 3:
                raise InputError("75E460 requires String24, consumed pointer and base")
            return parse_key(self, arg(0), arg(1), arg(2))
        if rva == 0x1D2C850:
            self._initialize_sdk_table()
            return None
        if rva == 0x1D2C8D0:
            destination, count = arg(0), signed(arg(1), 32)
            if count < 0:
                raise PrimaryProgramLimit("SDK host callback signed byte count is outside mapped normal memory")
            self.memory.write(destination, self.memory.read(self.image_base + 0x618CF50, count),
                              source="1D2C8D0.host_bytes_copy")
            return destination
        if rva == 0x1D2CDD4:
            address, count = arg(0), arg(1)
            if self.memory.load(address, 1):
                return 0
            if not count or count > 0x7FFFFFFF:
                raise PrimaryProgramLimit("SDK zero validator length is outside its normal nonempty domain")
            return int(self.memory.read(address, count - 1) == self.memory.read(address + 1, count - 1))
        if rva == 0x2DE5910:
            flag = self.image_base + 0x6D86048
            if self.memory.load(flag, 1) == 0:
                self.memory.store(flag, int(self.singleton() != 0), 1,
                                  source="2DE5928.singleton_ready")
            return None
        if rva in (0x3EB5450, 0x3EB5460):
            slot = 0x490FEF8 if rva == 0x3EB5450 else 0x490FF40
            address = self.memory.load(self.image_base + slot, 8)
            if address in (self.image_base + 0x3EB5450, self.image_base + 0x3EB5460):
                raise PrimarySemanticUnavailable("cyclic current import thunk target")
            return self.invoke(vm, address - self.image_base, cells, argument_types=argument_types)
        if rva == 0x3E8C550:
            if len(cells) != 2:
                raise InputError("compiled path comparison takes two string pointers")
            if self.memory.load(self.image_base + 0x6D8E630, 4) != 0:
                raise PrimarySemanticUnavailable("compiled path comparison locale-dependent route is unavailable")
            left, right = arg(0), arg(1)
            if not left or not right:
                raise PrimarySemanticUnavailable("compiled path comparison null/error route is unavailable")
            for index in range(0x10000):
                first = self.memory.load(left + index, 1)
                second = self.memory.load(right + index, 1)
                if first != second:
                    first, second = _FOLD[first], _FOLD[second]
                difference = first - second
                if difference or first == 0:
                    return difference & 0xFFFFFFFF
            raise PrimaryProgramLimit("compiled path comparison exceeds the bounded Python scan domain")
        if self.current_process is not None and rva + self.image_base == self.current_process[0]:
            if cells:
                raise InputError("GetCurrentProcessId takes no arguments")
            if self.raw_core_observations is not None:
                return self.raw_core_observations.caller_api(self, 'GetCurrentProcessId', ())
            self.events.append(("GetCurrentProcessId", self.current_process[1]))
            return self.current_process[1]
        if rva + self.image_base == self.module_lookup_address:
            if len(cells) != 1:
                raise InputError("GetModuleHandleA takes one pointer argument")
            pointer = arg(0)
            name = self._ansi_name(pointer) if pointer else None
            requested, handle = self._next(self._module_handles, "GetModuleHandleA", name)
            if (requested is not None and (not isinstance(requested, bytes) or b"\0" in requested)):
                raise InputError("module lookup event requires a terminated-name value without its NUL")
            if requested != name:
                error = InputError("module lookup event does not match the actual requested module name")
                error.module_lookup_metadata = {
                    "expected_name_hex_prefix": None if requested is None else requested[:128].hex(),
                    "expected_name_length": None if requested is None else len(requested),
                    "actual_name_hex_prefix": None if name is None else name[:128].hex(),
                    "actual_name_length": None if name is None else len(name),
                    "name_pointer": pointer,
                    "vm_resume_pc": getattr(vm, "pc", None),
                    "event_count_after_read": len(self.events),
                }
                raise error
            if type(handle) is not int or not 0 <= handle < 1 << 64:
                raise InputError("module lookup result must be an explicit pointer-width handle")
            return handle
        if rva + self.image_base == self.module_from_address_address:
            if len(cells) != 3:
                raise InputError("GetModuleHandleExA takes flags, an address/name and an output pointer")
            flags, address = arg(0) & 0xFFFFFFFF, arg(1)
            if self.raw_core_observations is not None:
                return self.raw_core_observations.caller_api(self, 'GetModuleHandleExA', (flags, address), arg(2), 8)
            if flags != 6:
                raise PrimarySemanticUnavailable("module lookup needs the proved FROM_ADDRESS and UNCHANGED_REFCOUNT flags")
            expected_flags, expected_address, result, handle = self._next(
                self._module_from_address, "GetModuleHandleExA", flags, address)
            if (expected_flags, expected_address) != (flags, address):
                raise InputError("module-from-address event does not match the actual flags/address")
            if (type(result) is not int or not 0 <= result <= 0xFFFFFFFF or
                    type(handle) is not int or not 0 <= handle <= _MASK64):
                raise InputError("module-from-address needs explicit BOOL32 and pointer-width handle")
            if result == 0:
                raise PrimarySemanticUnavailable("failed module-from-address output memory effects are unavailable")
            self.memory.store(arg(2), handle, 8, source="GetModuleHandleExA.module")
            return result
        if (rva + self.image_base == self.module_filename_address or
                rva + self.image_base in self.module_filename_aliases):
            if len(cells) != 3:
                raise InputError("GetModuleFileNameA takes a handle, buffer and DWORD capacity")
            module, destination, capacity = arg(0), arg(1), arg(2) & 0xFFFFFFFF
            if self.raw_core_observations is not None:
                return self.raw_core_observations.caller_api(self, 'GetModuleFileNameA', (module, capacity), destination, capacity)
            expected_module, expected_capacity, result, data = self._next(
                self._module_filename, "GetModuleFileNameA", module, capacity)
            if (expected_module, expected_capacity) != (module, capacity):
                raise InputError("module-filename event does not match the actual handle/capacity")
            if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
                raise InputError("module-filename result must be an explicit DWORD")
            if not 0 < result < capacity:
                raise PrimarySemanticUnavailable("failed or truncated module filename memory effects are unavailable")
            if (not isinstance(data, bytes) or len(data) != result + 1 or
                    data[-1] != 0 or b"\0" in data[:-1]):
                raise InputError("successful module filename needs the exact terminated path bytes")
            self.memory.write(destination, data, source="GetModuleFileNameA.path")
            return result
        if rva + self.image_base == self.path_filename_address:
            if len(cells) != 1:
                raise InputError("PathFindFileNameA takes one path pointer")
            pointer = arg(0)
            if self.raw_core_observations is not None:
                return self.raw_core_observations.path_api(self, 'PathFindFileNameA', pointer)
            _, offset = self._path_offset(pointer)
            return pointer + offset
        if rva + self.image_base == self.path_strip_address:
            if len(cells) != 1:
                raise InputError("PathStripPathA takes one writable path pointer")
            pointer = arg(0)
            if self.raw_core_observations is not None:
                return self.raw_core_observations.path_api(self, 'PathStripPathA', pointer)
            data, offset = self._path_offset(pointer)
            if offset:
                self.memory.write(pointer, data[offset:] + b"\0", source="PathStripPathA.filename")
            return None
        if rva + self.image_base == self.find_window_address:
            if len(cells) != 2:
                raise InputError("FindWindowA takes a class and title")
            class_pointer, title_pointer = arg(0), arg(1)
            if 0 < class_pointer <= 0xFFFF:
                raise PrimarySemanticUnavailable("FindWindowA class atom is outside the named support domain")
            class_name = self._ansi_name(class_pointer) if class_pointer else None
            title = self._ansi_name(title_pointer) if title_pointer else None
            if self.raw_core_observations is not None:
                return self.raw_core_observations.find_window(self, class_name, title)
            expected_class, expected_title, handle = self._next(self._find_window, "FindWindowA", class_name, title)
            if (expected_class, expected_title) != (class_name, title):
                raise InputError("window lookup event does not match the actual class/title")
            if type(handle) is not int or not 0 <= handle <= _MASK64:
                raise InputError("window lookup requires an explicit pointer-width handle")
            return handle
        if rva + self.image_base == self.window_visible_address:
            if len(cells) != 1:
                raise InputError("IsWindowVisible takes one window handle")
            if self.raw_core_observations is not None:
                return self.raw_core_observations.caller_api(self, 'IsWindowVisible', (arg(0),))
            expected_handle, result = self._next(self._window_visible, "IsWindowVisible", arg(0))
            if expected_handle != arg(0):
                raise InputError("window visibility event does not match the actual handle")
            if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
                raise InputError("window visibility result must be an explicit BOOL32")
            return result
        if rva + self.image_base == self.procedure_lookup_address:
            if len(cells) != 2:
                raise InputError("GetProcAddress takes two pointer arguments")
            module, pointer = arg(0), arg(1)
            if pointer <= 0xFFFF:
                raise PrimarySemanticUnavailable("ordinal procedure lookup is outside the named support domain")
            name = self._ansi_name(pointer)
            expected_module, expected_name, address = self._next(self._procedure_lookup, "GetProcAddress", module, name)
            if (type(expected_module) is not int or not 0 <= expected_module < 1 << 64 or
                    not isinstance(expected_name, bytes) or b"\0" in expected_name or
                    type(address) is not int or not 0 <= address < 1 << 64):
                raise InputError("procedure lookup needs explicit module/name/address values")
            if (expected_module, expected_name) != (module, name):
                raise InputError("procedure lookup event does not match the actual module and procedure name")
            return address
        if rva + self.image_base == self.cursor_position_address:
            if len(cells) != 1:
                raise InputError("GetCursorPos takes one POINT pointer")
            if self.raw_core_observations is not None:
                return self.raw_core_observations.write_to(self, 'GetCursorPos', arg(0), purpose='source POINT import')
            result, point = self._cursor_value()
            self.memory.write(arg(0), point, source="GetCursorPos.POINT")
            return result
        if rva == 0x2DE52D5:
            slot = self.memory.load(self.image_base + 0x6D86000, 8)
            if slot == 0:
                return None
            if slot != self.cursor_position_address:
                raise PrimarySemanticUnavailable("cursor adapter current function is not explicitly bound")
            if self.raw_core_observations is not None:
                self._raw_private_output('GetCursorPos', arg(0), publish_on_success=True)
                return None
            result, point = self._cursor_value(discard_failure=True)
            if result:
                self.memory.write(arg(0), point, source="2DE5311.POINT_publish")
            return None
        if rva == 0x2DE57A6:
            if len(cells) != 6:
                raise InputError("tail guard requires the actual six-argument binding")
            pointer, length = arg(0), self.memory.load(vm.cells.pointer(cells[1]), 4)
            count = signed(length, 32)
            value = self.memory.read(pointer, count) if count in (4, 5, 13, 15, 20, 44, 47, 50, 51, 58, 60, 64) else b""
            result = command_guard(value, length)
            self.events.append(("2DE57A6.command_guard", result))
            return None
        if rva == 0x2DE4C36:
            sse4 = self.memory.load(self.image_base + 0x62719B8, 4, signed=True) >= 2
            value = self.memory.load(vm.cells.pointer(cells[0]), 4)
            magnitude = value & 0x7FFFFFFF
            if magnitude > 0x7F800000:
                raise PrimarySemanticUnavailable("ceil32 NaN error/quieting route is unavailable")
            if sse4 and 0 < magnitude < 0x00800000:
                raise PrimarySemanticUnavailable("ceil32 SSE4 subnormal input needs explicit MXCSR DAZ state")
            if magnitude >= 0x4B000000 or magnitude == 0:
                return value
            if magnitude < 0x3F800000:
                if value >> 31:
                    return 0x80000000
                return 0x3F800000 if sse4 else self.memory.load(self.image_base + 0x3F34108, 4)
            shift = 150 - (magnitude >> 23)
            truncated = value & ((0xFFFFFFFF << shift) & 0xFFFFFFFF)
            if value >> 31 or value == truncated:
                return truncated
            if not sse4 and self.memory.load(self.image_base + 0x3F34108, 4) != 0x3F800000:
                raise PrimarySemanticUnavailable("ceil32 altered unit constant is unavailable")
            return truncated + (1 << shift)
        if rva == 0x359253D:
            if not self.host2252_normal:
                raise PrimarySemanticUnavailable("host2252 requires explicit conditional-normal dispatch/ABI/lifecycle premises")
            m_full = (self.host2252_stage1_retry and self.host2252_control_m and
                      self.host2252_pair_m_retry and self.host2252_stage2_g_retry and self.host2252_final_f_retry)
            if not m_full:
                m = self.memory.load(self.image_base + 0x677E1BC, 4, signed=True)
            if not self.host2252_stage2_g_retry:
                gx = self.memory.load(self.image_base + 0x6D86090, 4)
                gy = self.memory.load(self.image_base + 0x6D86094, 4, signed=True)
            if not self.host2252_final_f_retry:
                fx = self.memory.load(self.image_base + 0x677E1B4, 4, signed=True)
                fy = self.memory.load(self.image_base + 0x677E1B8, 4, signed=True)
            if ((not m_full and m == -0x80000000) or
                    (not self.host2252_stage2_g_retry and
                     ((((gx * gx) & 0xFFFFFFFF) | (abs(gy) & 0xFFFFFFFF)) >> 31)) or
                    (not self.host2252_final_f_retry and
                     ((((fx * fx + fy * fy) & 0xFFFFFFFF) | ((abs(fx) + abs(fy)) & 0xFFFFFFFF)) >> 31))):
                raise PrimarySemanticUnavailable("host2252 current M/G/F values do not select the accepted normal domain")
            pointer = arg(0)
            region, _ = self.memory._span(pointer, 16)
            if (region.data.readonly or pointer + 16 > 1 << 64 or
                    pointer < self.image_base + 0x6D8F1B4 and self.image_base < pointer + 16 or
                    any(other.data.obj is region.data.obj and self.image_base <= other.address < self.image_base + 0x6D8F1B4
                        for other in self.memory._regions)):
                raise PrimaryProgramLimit("host2252 needs writable private block memory disjoint from image state")
            if self.host2252_stage1_retry or self.host2252_stage2_g_retry or self.host2252_final_f_retry or self.host2252_control_m:
                if len(cells) != 1:
                    raise InputError('host2252 retry requires its single block argument')
                from .primary_host2252_retry import invoke_retry
                return invoke_retry(self, vm, cells, pointer)
            tables = self.memory.read(self.image_base + 0x43FD440, 1196096)
            initial = self.memory.read(pointer, 16)
            block = bytearray(initial)
            from .primary_host2252 import normal_into
            try:
                normal_into(block, tables=tables)
            except LibraryLimitError:
                if block != initial:
                    self.memory.write(pointer, bytes(block), source="359253D.normal_partial")
                raise
            self.memory.write(pointer, bytes(block), source="359253D.normal_complete")
            return None
        if rva == 0x3EB2C10:
            begin = pointer = arg(0)
            while pointer & 7:
                value = self.memory.load(pointer, 1)
                pointer += 1
                if value == 0:
                    return pointer - begin - 1
            for _ in range(0x20000):
                value = self.memory.load(pointer, 8)
                pointer += 8
                marker = ((value + 0x7EFEFEFEFEFEFEFF) & _MASK64) ^ (~value & _MASK64)
                if marker & 0x8101010101010100:
                    value = self.memory.load(pointer - 8, 8)
                    for index in range(8):
                        if (value >> (8 * index)) & 255 == 0:
                            return pointer - begin - 8 + index
            raise PrimaryProgramLimit("native strlen exceeds the bounded Python scan domain")
        if rva == 0x51C872:
            if (len(cells) != 3 or argument_types is None or tuple(argument_types) != (2, 2, 3) or
                    vm.program.type(2).raw != 8 or vm.program.size(2) != 8 or
                    vm.program.type(3).raw != 7 or vm.program.size(3) != 4):
                raise PrimarySemanticUnavailable("byte hex formatter requires two pointers and explicit type3 DWORD tail")
            if self.memory.load(self.image_base + 0x6749CC0, 8) != 0:
                raise PrimarySemanticUnavailable("byte hex formatter nondefault current options are unavailable")
            output, format_address = arg(0), arg(1)
            if self.memory.read(format_address, 5) != b"%02X\0":
                raise PrimarySemanticUnavailable("byte hex formatter only implements the actual %02X format")
            value = self.memory.load(vm.cells.pointer(cells[2]), 4)
            if not 0 <= value <= 255:
                raise PrimarySemanticUnavailable("byte hex formatter requires an unsigned byte promoted to DWORD")
            if output < format_address + 5 and format_address < output + 3:
                raise PrimaryProgramLimit("byte hex formatter requires disjoint format and output bytes")
            digits = b"0123456789ABCDEF"
            result = bytes((digits[value >> 4], digits[value & 15], 0))
            self.memory.write(output, result, source="51C872.hex_u8.full_fit")
            return 2
        if rva == 0x701774:
            if (len(cells) != 4 or argument_types is None or len(argument_types) != 4 or
                    vm.program.type(argument_types[3]).raw != 7 or
                    vm.program.size(argument_types[3]) != 4):
                raise PrimarySemanticUnavailable("integer formatter requires an explicit DWORD variadic tail")
            if self.memory.load(self.image_base + 0x6749CC0, 8) != 0:
                raise PrimarySemanticUnavailable("integer formatter nondefault current options are unavailable")
            output, capacity, format_address = arg(0), arg(1), arg(2)
            if self.memory.read(format_address, 3) != b"%d\0":
                raise PrimarySemanticUnavailable("integer formatter only implements the actual %d format")
            value = signed(self.memory.load(vm.cells.pointer(cells[3]), 4), 32)
            magnitude, digits = abs(value), bytearray()
            while True:
                quotient = (magnitude * 0xCCCCCCCD) >> 35
                digits.append(48 + magnitude - quotient * 10)
                magnitude = quotient
                if magnitude == 0:
                    break
            result = (b"-" if value < 0 else b"") + bytes(reversed(digits))
            if capacity <= len(result):
                raise PrimaryProgramLimit("integer formatter truncation is outside the full-fit support domain")
            if output < format_address + 3 and format_address < output + len(result) + 1:
                raise PrimaryProgramLimit("integer formatter requires disjoint format and output bytes")
            self.memory.write(output, result + b"\0", source="701774.decimal32.full_fit")
            return len(result)
        if rva == 0x2DE4C3B:
            first, second, third, output = arg(0) & 255, arg(1) & 0xFFFFFFFF, arg(2) & 0xFFFFFFFF, arg(3)
            size, temporary, initial = self._next(self._temporaries, "native private temporary", 16)
            if size != 16 or type(temporary) is not int or not 0 < temporary < 1 << 64:
                raise InputError("material wrapper needs an explicit private 16-byte temporary")
            if initial is not None and (not isinstance(initial, bytes) or len(initial) != 16):
                raise InputError("private temporary initial bytes must be absent or exactly 16 bytes")
            self.memory.map(temporary, bytearray(16) if initial is None else bytearray(initial),
                            name="2DE4C3B explicit private stack initial state",
                            initialized=initial is not None)
            policy = getattr(self, '_policy3_binding', None)
            if policy is not None and policy.active:
                policy.mapped_temporary(temporary, '2DE4C3B explicit private stack initial state')
            self.execute("material-block", (temporary, first, second, third), None)
            self.memory.copy_disjoint(output, temporary, 16, label="2DE4C6B.material_publish")
            self.memory.forget(temporary, 16, source="2DE4C82.private_stack_lifetime_end")
            if not self.retain_frames:
                self.memory.unmap(temporary)
            return None
        if rva == 0x2DE50A9:
            return self.execute("host97", (arg(0) & 255, arg(1), arg(2) & 0xFFFFFFFF,
                                           arg(3), arg(4) & 0xFFFFFFFF, arg(5), arg(6)), None)
        if rva == 0x2DE4E0D:
            policy = getattr(self, '_policy3_binding', None)
            if policy is not None and policy.active:
                steady = self._raw_steady_time()
            elif self.raw_core_observations is None:
                counter, frequency = self._next(self._qpc, "QueryPerformanceCounter/Frequency")
                steady = qpc_nanoseconds(counter, frequency)
            else:
                steady = self._raw_steady_time()
            self.memory.store(arg(0), steady, 8, source="2DE4E35.steady_time")
            filetime = (policy.filetime() if policy is not None and policy.active else
                        self._next(self._filetimes, "GetSystemTimePreciseAsFileTime") if self.raw_core_observations is None
                        else self.raw_core_observations.filetime(precise=True))
            if type(filetime) is not int or not 0 <= filetime <= _MASK64:
                raise InputError("precise FILETIME service value must be unsigned64")
            ticks = signed(filetime + 0xFE624E212AC18000, 64)
            high = (ticks * 0x6666666666666667) >> 64
            microseconds = (high >> 2) + ((high & _MASK64) >> 63)
            high = (microseconds * 0x20C49BA5E353F7CF) >> 64
            milliseconds = (high >> 7) + ((high & _MASK64) >> 63)
            device = self._random_device()
            if device:
                raw = (policy.entropy() if policy is not None and policy.active else
                       self._next(self._entropy, "RtlGenRandom") if self.raw_core_observations is None
                       else self.raw_core_observations.entropy_word())
                if not isinstance(raw, bytes) or len(raw) != 4:
                    raise InputError("random device requires four explicit successful entropy bytes")
                random = int.from_bytes(raw, "little")
            else:
                random = milliseconds & 0xFFFFFFFF
            return (milliseconds ^ random) & 0xFFFFFFFF
        if rva == 0x2DE50F8:
            from .primary_cocos import decode_word
            return decode_word(self.memory, arg(0))
        if rva == 0x2DE6AA0:
            output, source, count = arg(0), arg(1), arg(2)
            if count > 0x1000000:
                raise PrimaryProgramLimit("forward DWORD copy exceeds the bounded execution domain")
            whole = count & ~3
            for offset in range(0, whole, 4):
                value = self.memory.load(source + offset, 4)
                self.memory.store(output + offset, value, 4, source="2DE6AB0.forward_dword")
            for offset in range(whole, count):
                value = self.memory.load(source + offset, 1)
                self.memory.store(output + offset, value, 1, source="2DE6AC6.forward_byte")
            return None
        if rva == 0x2DE4EB1:
            from .primary_cocos import seed_mt, next_mt
            tls = self.tls_base_address
            if tls is None:
                raise UnknownMemory("missing actual current TLS base for MT state")
            policy = getattr(self, '_policy3_binding', None)
            if policy is not None and policy.active:
                steady = self._raw_steady_time()
            elif self.raw_core_observations is None:
                counter, frequency = self._next(self._qpc, "QueryPerformanceCounter/Frequency")
                steady = qpc_nanoseconds(counter, frequency)
            else:
                steady = self._raw_steady_time()
            delta = signed(steady - arg(1), 64)
            rounded = float(delta)
            ticks = int(rounded) if -(1 << 63) <= rounded < 1 << 63 else -(1 << 63)
            seed = (ticks ^ arg(0)) & 0xFFFFFFFF
            flags = self.memory.load(tls + 0xD70, 4)
            if not flags & 1:
                self.memory.store(tls + 0xD70, flags | 1, 4, source="2DE500C.MT_tls_claim")
                pointer = self._allocate(2504, False)
                seed_mt(self.memory, pointer, seed)
                self.memory.store(tls + 0xD68, pointer, 8, source="2DE5062.MT_tls_publish")
                if policy is not None and policy.active:
                    policy.register_thread_exit()
                self.events.append(("CRT.thread_atexit", self.image_base + 0x2DE507A))
            pointer = self.memory.load(tls + 0xD68, 8)
            low = seed & 255
            if low == 0:
                seed_mt(self.memory, pointer, seed)
            for index in range(3):
                value = next_mt(self.memory, pointer)
                if 0 < low <= 14:
                    value ^= next_mt(self.memory, pointer)
                elif 14 < low < 240:
                    value ^= 0xCCCCCCCC
                self.memory.store(arg(2) + 4 * index, value, 4, source="2DE4F4E.MT_material")
            return None
        if rva == 0x35A20F0:
            return self.execute("cocos-init", (arg(0), arg(1)), ())
        if rva == 0x35A211B:
            return self.execute("cocos-crypt", (arg(0), arg(1), arg(2), arg(3), arg(4) & 0xFFFFFFFF), None)
        if rva == 0x35A215B:
            from .primary_cocos import core8
            core8(self.memory, arg(0), arg(1))
            return None
        if rva == 0x35A277F:
            from .primary_cocos import hash32
            return hash32(self.memory, arg(0), arg(1), arg(2))
        if rva == 0x35A261F:
            from .primary_cocos import hash32
            source, length, output = arg(0), arg(1) & 0xFFFFFFFF, arg(2)
            if length > 96:
                raise PrimaryProgramLimit("cocos publication input exceeds its 96-byte private payload")
            dispatch = tuple(self.memory.load(self.image_base + 0x655BD18 + 8 * index, 8) for index in range(2))
            if dispatch != (self.image_base + 0x35A26DE, self.image_base + 0x35A26CA):
                raise PrimarySemanticUnavailable("cocos publication current byte-copy dispatch is unavailable")
            size, temporary, initial = self._next(self._temporaries, "native private temporary", 100)
            if size != 100 or type(temporary) is not int or not 0 < temporary <= _MASK64 - 100:
                raise InputError("cocos publication needs an explicit private 100-byte temporary")
            self.memory.map(temporary, bytearray(100), name="35A261F private initialized packet", initialized=True)
            policy = getattr(self, '_policy3_binding', None)
            if policy is not None and policy.active:
                policy.mapped_temporary(temporary, '35A261F private initialized packet')
            self.memory.store(temporary, 0x3D7ACCD4, 4, source="35A26B1.packet_prefix")
            for index in range(length):
                self.memory.store(temporary + 4 + index, self.memory.load(source + index, 1), 1,
                                  source="35A26CD.packet_input")
            digest = hash32(self.memory, temporary, length + 4, 0)
            self.execute("cocos-publish", (temporary, digest, output), None)
            self.memory.forget(temporary, 100, source="35A2722.private_stack_lifetime_end")
            if not self.retain_frames:
                self.memory.unmap(temporary)
            return None
        if rva == 0x3591D31:
            return self.execute("material-block",
                                (arg(0), arg(1) & 255, arg(2) & 0xFFFFFFFF, arg(3) & 0xFFFFFFFF), None)
        if rva == 0x3591D6C:
            guard, context = self.image_base + 0x6D88CA0, self.image_base + 0x6D88430
            current = self.memory.load(guard, 4)
            if current == 0:
                self.memory.store(guard, 1, 4, source="3591D88.initializer_claim")
                state_body = self._run_primary_material_state
                if getattr(state_body, '__func__', None) is PrimaryRuntime._run_primary_material_state:
                    self.execute("material-state", (context,), None)
                else:
                    from threading import get_ident
                    import sys
                    had_claim = '_primary_material_state_claim' in self.__dict__
                    prior_claim = self.__dict__.get('_primary_material_state_claim')
                    if prior_claim is not None:
                        raise PrimarySemanticUnavailable('material initializer already owns an active source claim')
                    claim = dict(runtime=self, thread=get_ident(), generation=self._main_generation,
                                 context=context, guard=guard, writes=self.memory.writes,
                                 writeIndex=len(self.memory.writes) - 1, writeRow=self.memory.writes[-1],
                                 guardRegion=self.memory._span(guard, 4)[0], body=state_body,
                                 parentCalls=tuple(self._program_calls), owner=self._active_main,
                                 vm=None, active=True,
                                 publicOwner=self.__dict__.get('_primary_public_direct_owner'))
                    claim['valid'] = lambda candidate: candidate is claim
                    self._primary_material_state_claim = claim
                    try:
                        self.execute("material-state", (context,), None)
                    finally:
                        primary = sys.exception()
                        owned = self.__dict__.get('_primary_material_state_claim') is claim
                        if owned:
                            if had_claim:
                                self._primary_material_state_claim = prior_claim
                            else:
                                self.__dict__.pop('_primary_material_state_claim', None)
                        claim.clear()
                        if not owned:
                            error = PrimarySemanticUnavailable('material initializer source claim ownership changed')
                            if primary is None:
                                raise error
                            primary.add_note(str(error))
                self.events.append(("MFENCE",))
                self.memory.store(guard, 2, 4, source="3591DB5.initializer_publish")
            elif current == 1:
                raise PrimarySemanticUnavailable("material initializer wait requires concurrent state changes")
            elif current == 2:
                self.events.append(("MFENCE",))
                scope = self.__dict__.get('_primary_direct_scope')
                owner = None if scope is None else scope.worker_owner
                if owner is not None and not owner.material_used and owner.material_reuse is None:
                    scope._authorize_material_reuse(context, guard)
            return context
        if rva == 0x3591E1C:
            pointer = arg(0) + 0x848
            if pointer in self.locks:
                raise PrimaryProgramLimit("duplicate initialization of private critical section")
            self.memory.forget(pointer, 40, source="InitializeCriticalSection.opaque_state")
            self.locks[pointer] = 0
            self.events.append(("InitializeCriticalSection", pointer))
            return None
        if rva in (0x3591E38, 0x3591E46):
            pointer = arg(0) + 0x848
            if pointer not in self.locks:
                raise PrimarySemanticUnavailable("foreign/uninitialized critical section")
            enter = rva == 0x3591E38
            if not enter and self.locks[pointer] == 0:
                raise PrimaryProgramLimit("LeaveCriticalSection without this runtime owning it")
            self.locks[pointer] += 1 if enter else -1
            self.events.append(("EnterCriticalSection" if enter else "LeaveCriticalSection", pointer))
            return None
        if rva == 0x3592167:
            return self.singleton()
        if rva == 0x1BF7520:
            if len(cells) != 3:
                raise InputError("local callback wrapper takes pointer, DWORD type and DWORD key")
            self._register_provider_base(vm)
            self._register_callback_group(vm, 0x677C220, 0x6D85FA8, 16, (
                (0x1BF7568, 0x6D85FA8, 0x1BF80F0),
                (0x1BF7576, 0x6D85FB0, 0x28F0),
            ))
            return self.invoke(vm, 0x2DE8BFB, cells)
        if rva == 0x2DE8BFB:
            if len(cells) != 3:
                raise InputError("local registry dispatch takes pointer, DWORD type and DWORD key")
            from .primary_tokens import dispatch_local
            return dispatch_local(self, arg(0), arg(1), arg(2))
        if rva == 0x35A2B20:
            if len(cells) != 2:
                raise InputError("source2581 wrapper takes pointer and DWORD length")
            return self.execute("source2581", (self.image_base + 0x6D88D74, arg(0), arg(1) & 0xFFFFFFFF), None)
        if rva == 0x3592214:
            if len(cells) != 3:
                raise InputError("source2581 setter takes container, pointer and QWORD length")
            return self.execute("source2581-setter", (arg(0), arg(1), arg(2)), None)
        if rva == 0x3592244:
            if len(cells) != 3:
                raise InputError("source3592244 setter takes container, pointer and QWORD length")
            return self.execute("setter3592244", (arg(0), arg(1), arg(2)),
                                (0x3592178, 0x3592430, 0x3EB2680))
        if rva == 0x35A2B8C:
            if len(cells) != 2:
                raise InputError("source2582 wrapper takes pointer and DWORD length")
            return self.execute("source2582", (self.image_base + 0x6D88D74, arg(0), arg(1) & 0xFFFFFFFF), None)
        if rva == 0x35A2BF0:
            if len(cells) != 2:
                raise InputError("source2583 wrapper takes pointer and DWORD type")
            return self.execute("source2583", (self.image_base + 0x6D88D74, arg(0), arg(1) & 0xFFFFFFFF), None)
        if rva == 0x3592274:
            if len(cells) != 4:
                raise InputError("token setter takes container, pointer, DWORD length and DWORD type")
            return self.execute("token-setter", (arg(0), arg(1), arg(2) & 0xFFFFFFFF, arg(3) & 0xFFFFFFFF), None)
        if rva == 0x35921C2:
            if len(cells) != 2:
                raise InputError("token expiry routine takes container and byte flag")
            return self.execute("token-expire", (arg(0), arg(1) & 255), None)
        if rva == 0x2DE4BF6:
            return self.execute("ecrypt-transform",
                                (arg(0), arg(1), arg(2) & 0xFFFFFFFF, arg(3), arg(4) & 0xFFFFFFFF), None)
        if rva == 0x2DE2125:
            return self.execute("ecrypt-keysetup",
                                (arg(0), arg(1), arg(2) & 0xFFFFFFFF, arg(3) & 0xFFFFFFFF), None)
        if rva == 0x2DE4BB7:
            return self.execute("ecrypt-packet",
                                (arg(0) & 0xFFFFFFFF, arg(1), arg(2), arg(3), arg(4) & 0xFFFFFFFF), None)
        if rva == 0x2DE2124:
            return None
        if rva == 0x2DE215D:
            from .primary_ecrypt import normal_iv_setup
            normal_iv_setup(self.memory, arg(0), arg(1), image_base=self.image_base, source_vm=vm,
                            control=self.iv_control)
            return None
        if rva == 0x2DE4B87:
            return self.execute("ecrypt-blocks", (arg(0), arg(1), arg(2) & 0xFFFFFFFF), None)
        if rva == 0x2DE32CF:
            from .primary_ecrypt import normal_keystream
            normal_keystream(self.memory, arg(0), arg(1), arg(2) & 0xFFFFFFFF,
                             image_base=self.image_base)
            return None
        if rva == 0x2DE6A7F:
            if arg(2) == 0:
                return arg(0)
            return self.invoke(vm, 0x3EB1FE0, cells)
        if rva == 0x2DE577E:
            return self.execute("host129", (), None)
        if rva == 0x2DE4C87:
            if self.__dict__.get('_local113_frame_plan') is not None:
                from .local113_scalar_helpers import execute_prefix_scalar
                return execute_prefix_scalar(self, vm, rva, cells, argument_types)
            return self.execute("host129-prepare", (arg(0) & 0xFFFFFFFF,), None)
        if rva == 0x2DE5A3F:
            if self.__dict__.get('_local113_frame_plan') is not None:
                from .local113_scalar_helpers import execute_prefix_scalar
                return execute_prefix_scalar(self, vm, rva, cells, argument_types)
            return self.execute("host129-select", (arg(0) & 0xFFFFFFFF,), None)
        if rva == 0x2DE5A34:
            left, right = arg(0) & 0xFFFFFFFF, arg(1) & 0xFFFFFFFF
            if right == 0:
                raise PrimaryProgramLimit("native DIV32 fault outside ordinary execution")
            return left // right
        if rva == 0x35924C4:
            with self._host129_api_service(vm, rva, cells, argument_types):
                if self._host129_source_clock_binding is not None and self._host129_source_clock_binding.has_child():
                    return self._host129_source_clock_binding.read_entropy(vm, rva, cells, argument_types)
                if self._host129_entropy_service_binding is not None:
                    return self._host129_entropy_service_binding.read(vm, rva, cells, argument_types)
                status, value = (self._next(self._bcrypt, "BCryptGenRandom(NULL,4,2)")
                                 if self.raw_core_observations is None else self.raw_core_observations.bcrypt_word())
                if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                    raise InputError("BCryptGenRandom status must be unsigned32")
                if signed(status, 32) < 0:
                    message = ("BCryptGenRandom failed: 0x%x\n" % status).encode('ascii')
                    self.events.append(("CRT.stderr.write", message))
                    if self.stderr is not None:
                        self.stderr(message)
                    return 0
                if not isinstance(value, bytes) or len(value) != 4:
                    raise InputError("successful BCryptGenRandom event must supply four exact bytes")
                return int.from_bytes(value, "little")
        if rva == 0x3E98FD8:
            value = arg(0)
            self.memory.store(self._crt_thread() + 0x28, value, 4, source="3E98FE5.thread_random_seed")
            return None
        if rva == 0x3E98FF0:
            slot = self._crt_thread() + 0x28
            value = (self.memory.load(slot, 4) * 0x343FD + 0x269EC3) & 0xFFFFFFFF
            self.memory.store(slot, value, 4, source="3E99006.thread_random_state")
            return (value >> 16) & 0x7FFF
        if rva == 0x2DE5687:
            from .primary_prefix_provider_inputs import provider_scope
            with provider_scope(self, vm, cells, argument_types):
                from .primary_adapter import string_view
                destination = arg(0)
                self.memory.write(destination, b"\x09" * 16, source="2DE56EB.initial_material")
                provider = self.memory.load(self.image_base + 0x6D85FF8, 8)
                temporary = None
                pointer, length = 0, 0
                if provider:
                    if provider != self.image_base + 0x1BFD960:
                        raise PrimarySemanticUnavailable(f"material string provider 0x{provider:x} is unavailable")
                    observed = self.__dict__.get('_prefix_provider_binding')
                    from .primary_prefix_observed_provider import _ObservedProviderBinding
                    size, temporary, initial = (observed.temporary(24) if type(observed) is _ObservedProviderBinding else self._next(self._temporaries, "native provider return string", 24))
                    if size != 24 or type(temporary) is not int or not 0 < temporary <= _MASK64 - 24:
                        raise InputError("material provider needs a private24-byte return string")
                    self.memory.map(temporary, bytearray(24), name="provider return string", initialized=False)
                    self._return_provider_string(temporary)
                    pointer, length = string_view(self.memory, temporary)
                transform = self.memory.load(self.image_base + 0x6D85FE8, 8)
                if transform:
                    if transform != self.image_base + 0x1BFD3D0:
                        raise PrimarySemanticUnavailable(f"material transform 0x{transform:x} is unavailable")
                    self._material_transform(pointer, length, destination, 16)
                if temporary is not None:
                    if self.memory.load(temporary, 1) & 1:
                        if type(observed) is _ObservedProviderBinding:
                            observed.free(pointer)
                        else:
                            self._free_allocation(pointer)
                    self.memory.forget(temporary, 24, source="2DE579A.provider_local_lifetime_end")
                    if not self.retain_frames:
                        self.memory.unmap(temporary)
                    if type(observed) is _ObservedProviderBinding:
                        observed.retire_temporary(temporary)
                return 1
        if rva == 0x1BFD960:
            if len(cells) != 1:
                raise InputError("installed string provider requires its return object")
            return self._return_provider_string(arg(0))
        if rva in (0x1BFD3D0, 0x1D05D10):
            if len(cells) != 4:
                raise InputError("installed MD5 transform requires four arguments")
            self._material_transform(arg(0), arg(1), arg(2), arg(3))
            return None
        if rva == 0x2DE4CAD:
            address = self.memory.load(self.image_base + 0x6D85FE8, 8)
            if address:
                if address != self.image_base + 0x1BFD3D0:
                    raise PrimarySemanticUnavailable(f"material transform 0x{address:x} is unavailable")
                return self.invoke(vm, address - self.image_base, cells, argument_types=argument_types)
            return 0
        if rva == 0x2DE8C4C:
            pointer, value1, value2, flag = arg(0), arg(1) & 0xFFFFFFFF, arg(2) & 0xFFFFFFFF, arg(3) & 255
            sensor = self._status_sensor()
            direct_scope = self.__dict__.get('_primary_direct_scope')
            if direct_scope is None:
                self.execute("status-audit", (sensor, pointer, value1, value2, flag), None)
            else:
                with direct_scope.status_audit('normal', (sensor, pointer, value1, value2, flag)):
                    self.execute("status-audit", (sensor, pointer, value1, value2, flag), None)
            return None
        if rva == 0x2DE561F:
            pointer, flag = arg(0), arg(1) & 255
            guard = self.image_base + 0x6D8604C
            if self.memory.load(guard, 1) == 0:
                self.execute("primary-setup", (), None)
                self.memory.store(guard, 1, 1, source="2DE564D.setup_publish")
            previous = self.memory.load(pointer, 8)
            current = self.invoke(vm, 0x3592430, ())
            if previous and flag:
                elapsed = (current - self.memory.load(pointer, 8)) & _MASK64
                return int(elapsed > 10_000_000_000)
            self.memory.store(pointer, current, 8, source="2DE567A.timer_refresh")
            return 0
        if rva in (0x3592430, 0x2DE5A2F):
            with self._host129_api_service(vm, rva, cells, argument_types):
                if self._main_clock_binding is not None and self._main_clock_binding.is_main(vm):
                    return self._main_clock_binding.read(vm, rva, cells, argument_types)
                if self._host129_source_clock_binding is not None and self._host129_source_clock_binding.has_child():
                    return self._host129_source_clock_binding.read_clock(
                        vm, self._host129_source_clock_binding.resolve_clock(rva), cells, argument_types,
                        cif_callee_rva=rva)
                bound = self._host129_entropy_service_binding is not None or self._host129_clock_service_binding is not None
                independent = bound and self._independent_main_timer(vm, rva, cells, argument_types)
                if not independent and self._host129_entropy_service_binding is not None:
                    self._host129_entropy_service_binding.check_clock(vm, rva, cells, argument_types)
                if not independent and self._host129_clock_service_binding is not None:
                    return self._host129_clock_service_binding.read(vm, rva, cells, argument_types)
                return self._clock_value()
        if rva == 0x3E92E00:
            count, size = arg(0), arg(1)
            if count and 0xFFFFFFFFFFFFFFE0 // count < size:
                raise PrimaryProgramLimit("calloc overflow/CRT failure path outside normal runtime domain")
            return self._allocate(max((count * size) & _MASK64, 1), True, nullable=True)
        if rva in (0xB75000, 0xB75029, 0xB7593F, 0xB758C4, 0xB758ED):
            from .primary_custom_allocator import _CustomBackend
            backend = getattr(self, '_custom_allocator_backend', None)
            if type(backend) is not _CustomBackend:
                raise PrimarySemanticUnavailable('whole upper allocation requires its bound source backend')
            return backend.dispatch(rva, (arg(0),))
        if rva == 0x3E97020:
            size = arg(0)
            if size > 0xFFFFFFFFFFFFFFE0:
                raise PrimaryProgramLimit("malloc overflow/CRT failure path outside normal runtime domain")
            return self._allocate(max(size, 1), False)
        if rva == 0x3E94F90:
            self._free_allocation(arg(0))
            return None
        if rva in (0x35921EC, 0x2DE57A1, 0x3E8ED3C, 0x2DE9317):
            if producer is not None and producer.active:
                with producer.local(8, zero=True) as local:
                    producer.api('GetSystemTimeAsFileTime', local, 'filetime')
                    result = filetime_seconds(self.memory.load(local, 8))
            else:
                result = filetime_seconds(self._next(self._filetimes, "GetSystemTimeAsFileTime"))
            pointer = arg(0)
            if pointer:
                self.memory.store(pointer, result, 8, source=f"{rva:X}.optional_time")
            return result & _MASK64
        if rva in (0x3592086, 0x3592129, 0x759B30):
            if self.raw_core_observations is not None or producer is not None and producer.active:
                result = self._raw_steady_time()
                if rva == 0x759B30:
                    self.memory.store(arg(0), result, 8, source='759BAF.consumer_steady_time')
                    return arg(0)
                return result if rva == 0x3592086 else result & 0xFFFFFFFF
            guard_address = self.image_base + 0x674D448
            guard = self.memory.load(guard_address, 4, signed=True)
            initialize = False
            if guard > self.memory.load(self.tls_epoch_address, 4, signed=True):
                self._thread_header(guard_address)
                initialize = self.memory.load(guard_address, 4, signed=True) == -1
            counter, frequency = self._next(self._qpc, "QueryPerformanceCounter/Frequency")
            if initialize:
                self.events.append(("QueryPerformanceFrequency", frequency))
                self.memory.store(self.image_base + 0x674D440, frequency, 8,
                                  source="759B30.frequency_publish")
                self._thread_footer(guard_address)
            self.events.append(("QueryPerformanceCounter", counter))
            current_frequency = self.memory.load(self.image_base + 0x674D440, 8)
            if frequency != current_frequency:
                raise InputError("QPC environment event frequency differs from current frequency global")
            result = qpc_nanoseconds(counter, frequency)
            if rva == 0x759B30:
                self.memory.store(arg(0), result, 8, source='759BAF.consumer_steady_time')
                return arg(0)
            return result if rva == 0x3592086 else result & 0xFFFFFFFF
        if rva == 0x3592161:
            return (arg(0) - arg(1)) & 0xFFFFFFFF
        if rva == 0x2DE8580:
            destination, size = arg(0), arg(2)
            if size == 0:
                return destination
            return self.invoke(vm, 0x3EB2680, cells)
        if rva == 0x3EB2680:
            destination, fill, size = arg(0), arg(1) & 255, arg(2)
            if size > 0x7FFFFFFF:
                raise PrimaryProgramLimit("Python memset size limit")
            self.memory.write(destination, bytes([fill]) * size, source="native.memset.exclusive")
            return destination
        if rva == 0x3EB1FE0:
            destination, source, size = arg(0), arg(1), arg(2)
            if size > 0x7FFFFFFF:
                raise PrimaryProgramLimit("Python copy size limit")
                                                                            
            if destination < source + size and source < destination + size:
                raise PrimaryProgramLimit("copy's overlapping native order is outside this runtime domain")
            self.memory.write(destination, self.memory.read(source, size), source="native.memcpy.disjoint")
            return destination
        if rva == 0x359205B:
            self.execute("buffer-init", (arg(0), arg(1)),
                         (0x3592086, 0x3E97020, 0x3EB2680, 0x35920C0,
                          0x3EB1FE0, 0x3592129, 0x3592161, 0x3E94F90))
            return None
        if rva == 0x35920C0:
            output = arg(0)
            count = signed(arg(1), 32)
            for index in range(max(count, 0)):
                if producer is not None and producer.active:
                    with producer.local(4, zero=True) as local:
                        result = producer.api('SystemFunction036', local, 'rng-word', index)
                        if not result:
                            raise PrimarySemanticUnavailable('singleton RNG failure needs unsupported CRT/EH semantics')
                        value = self.memory.read(local, 4)
                else:
                    value = (self._next(self._entropy, "SystemFunction036(4)") if self.raw_core_observations is None
                             else self.raw_core_observations.entropy_word())
                if not isinstance(value, bytes) or len(value) != 4:
                    raise InputError("each successful entropy service event must supply four exact bytes")
                self.memory.write(output + 4 * index, value, source="35920C0.random_dword")
            return None
        if rva == 0x3592191:
            pointer = arg(0) + 0x508
            if pointer in self.locks:
                raise PrimaryProgramLimit("duplicate initialization of private critical section")
                                                                           
                                                                           
            self.memory.forget(pointer, 40, source="InitializeCriticalSection.opaque_state")
            self.locks[pointer] = 0
            self.events.append(("InitializeCriticalSection", pointer))
            return None
        if rva == 0x3592178:
            pointer = arg(0) + 0x508
            if pointer not in self.locks:
                raise PrimarySemanticUnavailable("foreign/uninitialized critical section")
            enter = arg(1) & 255
            if not enter and self.locks[pointer] == 0:
                raise PrimaryProgramLimit("LeaveCriticalSection without this runtime owning it")
            self.locks[pointer] += 1 if enter else -1
            self.events.append(("EnterCriticalSection" if enter else "LeaveCriticalSection", pointer))
            return None
        if rva == 0x359219F:
            pointer = arg(0) + 0x508
            if pointer not in self.locks or self.locks[pointer] != 0:
                raise PrimarySemanticUnavailable("DeleteCriticalSection needs an initialized unowned container lock")
            del self.locks[pointer]
            self.memory.forget(pointer, 40, source="DeleteCriticalSection.opaque_state")
            self.events.append(("DeleteCriticalSection", pointer))
            return None
        if rva == 0x35921AD:
            left = self.memory.load(arg(0) + 4, 4)
            right = self.memory.load(arg(1) + 4, 4)
            return -1 if left > right else int(left < right)
        if rva == 0x3E98C40:
            if len(cells) != 4:
                raise InputError("qsort takes base, count, width and comparator")
            from .primary_tokens import sort_expiry
            return sort_expiry(self, arg(0), arg(1), arg(2), arg(3))
        raise PrimarySemanticUnavailable(f"native host RVA{rva:x} has no complete implemented body")


def load_program(name: str = "main", *, reader=None):

    if name not in _PROGRAMS:
        raise InputError("unknown fixed primary program name")
    raw = (_DATA / (name + ".bin")).read_bytes()
    if hashlib.sha256(raw).hexdigest() != _PROGRAMS[name]:
        raise InputError(f"fixed {name} program identity mismatch")
    if reader is not None:
        from .primary_consumed_mgf import PrivateCoreReplayCapsule
        if type(reader) is not PrivateCoreReplayCapsule:
            raise InputError('fixed program requires its actual replay capsule')
        return reader.decode_reader(raw, name)
    return decode_program(raw)


def command_guard(command: bytes, length: int) -> int:







    if not isinstance(command, bytes) or type(length) is not int:
        raise InputError("command guard needs explicit bytes and integer length")
    length = signed(length, 32)
    candidates = tuple(value for value in _COMMANDS if len(value) == length)
    if not candidates:
        return 0
    if len(command) < length:
        raise InputError("command is shorter than the native readable-buffer prerequisite")
    value = command[:length].translate(_FOLD)
    return int(any(value == candidate.translate(_FOLD) for candidate in candidates))


def host_values(memory, *, image_base: int) -> tuple[int, ...]:





    if type(image_base) is not int or not 0 <= image_base <= (1 << 64) - 1:
        raise InputError("image base must be unsigned64")
    mapping = json.loads((_DATA / "main-host-map.json").read_text("utf-8"))
    values = []
    for host in mapping["hosts"]:
        source = host["source"]
        address = (image_base + int(source["rva"], 16)) & ((1 << 64) - 1)
        if source["kind"] == "address":
            value = address
        elif source["kind"] == "LOAD64_CURRENT_MEMORY":
            value = memory.load(address, 8)
        else:
            raise PrimarySemanticUnavailable("unimplemented main host-slot producer")
        values.append(value)
    return tuple(values)


def _invoke_host(vm, address: int, argument_cells: tuple[int, ...], signature: int,
                 *, argument_types=None) -> int:

    image_base = vm.image_base
    if (address == image_base + 0x359253D and vm.runtime is not None and
            (getattr(vm.runtime, 'host2252_stage1_retry', False) or getattr(vm.runtime, 'host2252_stage2_g_retry', False) or getattr(vm.runtime, 'host2252_final_f_retry', False) or getattr(vm.runtime, 'host2252_control_m', False)) and (signature != 205 or len(argument_cells) != 1)):
        raise PrimarySemanticUnavailable('host2252 retry requires fixed void signature205')
    if address == image_base + 0x2DE6AD3:
        if signature != 99 or len(argument_cells) != 2:
            raise PrimarySemanticUnavailable("command host signature differs from the accepted main binding")
        pointer = vm.cells.value(argument_cells[0])
        length = vm.memory.load(vm.cells.pointer(argument_cells[1]), 4)
        n = signed(length, 32)
                                                                               
        data = vm.memory.read(pointer, n) if n in (4, 5, 13, 15, 20, 44, 47, 50, 51, 58, 60, 64) else b""
        return command_guard(data, length)
    if vm.runtime is not None:
        common = vm.runtime.__dict__.get('_common_guid_export')
        if common is not None and address == common.address:
            common.validate(vm, argument_cells, argument_types, signature)
        raw = getattr(vm.runtime, 'raw_core_observations', None)
        row = raw._typed_exports.get(address) if raw is not None else None
        if row is not None:
            result_index = vm.program.type(signature).parameters[1]
            if vm.program.size(result_index) * 8 != row['result_width']:
                raise InputError('dynamic export result width differs from its qualified ABI')
        from contextlib import nullcontext
        producer = getattr(vm.runtime, '_singleton_producer_binding', None)
        policy = getattr(vm.runtime, '_policy3_binding', None)
        with (producer.host(vm, address, argument_cells, signature) if producer is not None else nullcontext(),
              policy.host(vm, address, argument_cells, signature) if policy is not None else nullcontext()):
            result = vm.runtime.invoke(vm, address - image_base, argument_cells,
                                       argument_types=argument_types)
        entropy_binding = getattr(vm.runtime, '_host129_entropy_service_binding', None)
        if (entropy_binding is not None and address - image_base in (0x3592430, 0x2DE5A2F) and
                entropy_binding.pending_clock_for(vm, address - image_base)):
            entropy_binding.clock_return(vm, address - image_base, argument_cells, argument_types, result)
        result_type = vm.program.type(vm.program.type(signature).parameters[1])
        from .primary_sdk import NativeByteReturn
        if isinstance(result, NativeByteReturn):
            if result_type.raw == 2:
                return None
            if result_type.raw == 7 and vm.program.size(vm.program.type(signature).parameters[1]) == 1:
                return signed(result.value, 8) & _MASK64
            raise PrimarySemanticUnavailable("native callback defines only AL; wider return register is unknown")
        if result_type.raw == 7:
            width = vm.program.size(vm.program.type(signature).parameters[1])
            if width in (1, 2, 4, 8):
                return signed(result, 8 * width) & _MASK64
            raise PrimarySemanticUnavailable("native integer return width is unavailable")
        return result
    raise PrimarySemanticUnavailable(
        f"native host 0x{address:x} has no implemented complete source-bound body"
    )
