import hashlib

import json

import os

import secrets

import time

from contextlib import contextmanager

from dataclasses import dataclass, field, replace

from pathlib import Path



from .errors import InputError

from .primary_adapter import string_bytes, string_view, write_string

from .primary_memory import PrimaryMemory, UnknownMemory

from .primary_sign import PrimaryFrame, PrimaryRuntime, arena_reservation, load_program

from .primary_material import ExchangeMaterial, ProviderMaterial, _RuntimeResponseMaterial, caller_context, caller_device_value, caller_empty_body_token, device_factory_value, empty_body_token, payload_token, request_context_digest

from .primary_signature_result import PrimarySignatureResult, caller_result

from .primary_x86_float import ScalarSSEState





_PROVIDER_TAIL_FROM_ENVIRONMENT = object()





_DATA = Path(__file__).with_name("data") / "primary_sign_qq52230"

_SOURCE = "63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0"

_SDK_TABLE = "4d9a6f0c39c655a50cbc0e53d640b515a426c5d26b9aae558032de93baf88f95"

_ASSETS = {"runtime-image.json": "e844089712cb75d370a08339a4f743e451a328b9482b8bf98fa12f5df5d4fed3",

           "caller-commands.json": "a75d1d66712c7c16989f807350b03c322fd48a003a29bd366002db86c737990e"}

_SECURE_COMMANDS = frozenset((b"trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess",

                              b"trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Access",

                              b"trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey",

                              b"trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish"))





def _asset(name):

    raw = (_DATA / name).read_bytes()

    if hashlib.sha256(raw).hexdigest() != _ASSETS[name]:

        raise InputError("fixed caller asset identity mismatch: " + name)

    return json.loads(raw)





def command_classification(command, configuration_value=1):

    if not isinstance(command, bytes):

        raise InputError("command must be its exact source bytes")

    table = _asset("caller-commands.json")

    selected = command in {value.encode("ascii") for value in table["commands"]}

    selected |= command in (b"LightAppSvc.mini_app_userapp.GetDropdownAppList", b"OidbSvcTrpcTcp.0xfd4_1")

    if not selected or configuration_value is None:

        return 2

    if type(configuration_value) is not int or not -(1 << 31) <= configuration_value < 1 << 31:

        raise InputError("configuration ID24 value must be signed32 or absent")

    return configuration_value if configuration_value in (0, 1) else 2





@dataclass

class SigningEnvironment:

    cursor: tuple[int, int] | None

    process_path: bytes

    module_path: bytes

    stack_modules: tuple[bytes, ...]

    loaded_modules: tuple[bytes, ...] = ()

    windows: dict = field(default_factory=dict)

    process_id: int = field(default_factory=os.getpid)

    filetime: object = field(default_factory=lambda: lambda: time.time_ns() // 100 + 116444736000000000)

    qpc: object = field(default_factory=lambda: lambda: (time.perf_counter_ns(), 1_000_000_000))

    random_bytes: object = secrets.token_bytes

    postfetch_start_errors: object = ()

    telemetry_metadata_providers: object = None

    postfetch_crt_seed: int | None = None

    exit_registration: object = ()

    sdk_thread_starts: object = ()

    worker_observations: object = None

    logger_output: object = None

    worker_device_records: object = None

    request_capi: object = None

    request_transport: object = None

    device_configuration: object = None

    device_configuration_read: object = None

    caller_observations: object = None

    provider_initialization_stack_tail: bytes | None = None

    bcrypt: object = None

    stderr: object = None

    module_images: tuple = ()

    clock_apis: object = None

    raw_core_observations: object = None

    singleton_producer_inputs: object = field(default=None, repr=False)

    warm_core_container_inputs: object = field(default=None, repr=False)

    main_environment_inputs: object = field(default=None, repr=False)

    host129_counter_reads: object = None

    host129_clock_service_returns: object = None

    host129_entropy_service_returns: object = None

    host129_raw_inputs: object = field(default=None, repr=False)

    process_material: object = None

    device_hypervisor_key_preimage: bytes | None = None

    device_checkpoint_preimage: bytes | None = None

    device_checkpoint_knownmask: bytes | None = None

    scalar_sse_state: ScalarSSEState | None = None

    common_guid: object = field(default=None, repr=False)





@dataclass

class CallerProfile:

    xfolder_bytes: bytes | None

    host_profile_string: bytes

    empty_body_token: bytes | None = None

    device_factory: object = None



    @classmethod

    def from_windows(cls, host_profile_string, environment, *, storage_root=None, uuid_observation=None):

        from .primary_device_provider import DeviceFactory

        factory = DeviceFactory.windows(environment, storage_root=storage_root, uuid_observation=uuid_observation)

        return cls(None, host_profile_string, device_factory=factory)





class VirtualAddressSpace:

    def __init__(self, *, initial_stack, vm_base=0x7000000000, heap_base=0x7100000000,

                 temporary_base=0x7200000000):

        if initial_stack is not None and (not isinstance(initial_stack, bytes) or len(initial_stack) != 16):

            raise InputError("virtual environment requires a 16-byte initial private stack policy or None")

        self.initial_stack = initial_stack

        self.vm_cursor, self.heap_cursor, self.temporary_cursor = vm_base, heap_base, temporary_base



    def frame(self, name):

        if name == 'sec-init':

            from .primary_sec_init import load_program as load_sec_init

            program = load_sec_init()

        else:

            program = load_program(name)

        cells = self.vm_cursor

        arena = cells + (((program.cell_count + 1) * 24 + 4095) & ~4095)

        size = arena_reservation(program)

        self.vm_cursor = arena + ((size + 4095) & ~4095)

        return PrimaryFrame(name, cells, arena, size)



    def allocation(self, size, zero):

        address = self.heap_cursor

        self.heap_cursor += (size + 4095) & ~4095

        return size, zero, address



    def temporary(self, size):

        address = self.temporary_cursor

        self.temporary_cursor += (size + 4095) & ~4095

        return size, address, self.initial_stack if size == 16 else None





class SourceAddressSpace(VirtualAddressSpace):

    def __init__(self, *, initial_stack, public_entry_rsp, singleton_address, **options):

        if (type(public_entry_rsp) is not int or

                not 0xD268 < public_entry_rsp < (1 << 64) - 0xACD0 or

                public_entry_rsp % 16 != 8):

            raise InputError('source address space requires an aligned public entry RSP')

        if singleton_address is not None:

            if (type(singleton_address) is not int or

                    not 0 < singleton_address <= (1 << 64) - 1328 or

                    singleton_address % 16):

                raise InputError('source address space requires an aligned singleton address')

        super().__init__(initial_stack=initial_stack, **options)

        self.public_entry_rsp = public_entry_rsp

        self.singleton_address = singleton_address

        self.failed = False

        self._programs = []



    @contextmanager

    def program_context(self, name, arguments, hosts):

        from .primary_sign_lifecycle import close_frame_allowed

        if self.failed and not close_frame_allowed(self, name, arguments, hosts):

            raise InputError('source address space stopped after an incomplete program')

        if name == 'main' and (self._programs or type(arguments) is not tuple or len(arguments) != 12 or

                               arguments[0] != 4 or hosts is not None):

            raise InputError('source main stack requires the normal mode4 entry')

        if name == 'host129' and (not self._programs or

                                 self._programs[-1]['name'] != 'main' or

                                 arguments != () or hosts is not None):

            raise InputError('source host129 stack requires its direct main caller')

        current = {'name': name, 'frame': None, 'singleton_allocations': 0}

        self._programs.append(current)

        try:

            yield

            if current['frame'] is None:

                raise InputError('source program did not request its declared frame')

            if name == 'singleton-init' and current['singleton_allocations'] != 1:

                raise InputError('source singleton constructor allocation is incomplete')

        except BaseException:

            self.failed = True

            raise

        finally:

            self._programs.pop()



    def frame(self, name):

        from .primary_sign_lifecycle import close_frame_allowed

        if ((self.failed and not close_frame_allowed(self, name)) or not self._programs or self._programs[-1]['name'] != name or

                self._programs[-1]['frame'] is not None):

            raise InputError('source VM frame requires its active program scope')

        frame = super().frame(name)

        if name == 'main':

            frame = replace(frame, arena=self.public_entry_rsp - 0xC858, arena_size=0xACD0)

        elif name == 'host129':

            frame = replace(frame, arena=self.public_entry_rsp - 0xD268, arena_size=32)

        self._programs[-1]['frame'] = frame

        return frame



    def allocation(self, size, zero):

        if self.failed:

            raise InputError('source address space stopped after an incomplete program')

        event = super().allocation(size, zero)

        if self._programs and self._programs[-1]['name'] == 'singleton-init' and size == 1328:

            current = self._programs[-1]

            if zero is not True or current['singleton_allocations']:

                raise InputError('source singleton requires exactly one zeroed calloc allocation')

            current['singleton_allocations'] += 1

            if self.singleton_address is not None:

                return size, zero, self.singleton_address

        return event





@dataclass(frozen=True)
class _RequestCompletionReceipt:
    serial: int
    sequence: int
    transport_success: bool
    wire_nonempty: bool
    outcome: str | None
    pending_consumed: bool
    decryption_authenticated: bool | None
    verification_performed: bool
    material_accepted: bool | None
    business_success: bool | None
    business_parsed: bool | None
    cache_timestamp_written: bool
    cache_value_touched: bool
    cache_bound_touched: bool
    cache_nonempty: bool | None
    observation_failure_type: str | None = None
    operation_completed: bool = False
    failure_type: str | None = None

    @property
    def cache_mutated(self):
        return self.cache_timestamp_written or self.cache_value_touched or self.cache_bound_touched

    @property
    def verified_cache(self):
        return (self.operation_completed and self.failure_type is None and self.observation_failure_type is None and
                self.outcome == 'dispatched' and self.pending_consumed and self.transport_success and
                self.wire_nonempty and self.decryption_authenticated is True and self.verification_performed and
                self.material_accepted is True and self.business_success is True and self.business_parsed is True and
                self.cache_timestamp_written and self.cache_value_touched and self.cache_bound_touched and
                self.cache_nonempty is True)


def _request_completion_receipt(runtime, serial, sequence, success, wire_nonempty, outcome, event_start, write_start):
    from .primary_logger import _String
    events, writes = runtime.events[event_start:], runtime.memory.writes[write_start:]
    consumed = any(event[0] == 'request.completion_consumed' and event[1] == sequence for event in events)
    decrypt = [event[1] == 0 for event in events if event[0] == 'request.response_decrypt']
    verified = [event for event in events if event[0] == 'request.response_material_verified']
    parsed = [bool(event[1]) for event in events if event[0] == 'worker.response_parsed']
    business = [bool(raw[0]) for address, raw, source in writes if source == 'request.business_success' and len(raw) == 1]
    base = runtime.image_base
    performed = bool(verified and (verified[-1][1] or any(
        address == base + 0x677D108 and source == '1CDC080.response_payload_mode'
        for address, raw, source in writes)))
    timestamp = any(address == base + 0x6751850 and source == 'BDEC55.token_cache_timestamp'
                    for address, raw, source in writes)
    value = any(base + 0x6751858 <= address < base + 0x6751870 and source == 'logger.string_copy'
                for address, raw, source in writes)
    bound = any(base + 0x6751870 <= address < base + 0x6751888 and source == 'logger.string_copy'
                for address, raw, source in writes)
    nonempty, observation_failure = None, None
    if value:
        try:
            nonempty = bool(_String.read(runtime, base + 0x6751858).value())
        except Exception as failure:
            observation_failure = type(failure).__name__
    return _RequestCompletionReceipt(serial, sequence, bool(success), wire_nonempty, outcome, consumed,
        decrypt[-1] if decrypt else None, performed, bool(verified[-1][2]) if verified else None,
        business[-1] if business else None, parsed[-1] if parsed else None, timestamp, value, bound,
        nonempty, observation_failure)


class PrimarySigner:

    def __init__(self, environment, *, initial_stack, addresses=None, image_base=0x180000000,

                 retain_diagnostics=False, profile=None, configuration_value=1, provider_material=None,

                 host2252_stage1_retry=False, host2252_m_read_budget=4096,

                 host2252_stage2_g_retry=False, host2252_g_read_budget=4096,

                    host2252_final_f_retry=False, host2252_f_read_budget=4096,

                    host2252_pair_m_retry=False, host2252_pair_m_read_budget=4096,

                    host2252_control_m=False, main_clock_inputs=None, host129_source_clock_inputs=None,

                    primary_backend='reference', _module_sync_birth=None):

        if type(primary_backend) is not str or primary_backend not in ('reference', 'direct'):

            raise InputError('primary_backend must be reference or direct')

        self.primary_backend = primary_backend

        self._public_direct_serial = 0

        self._public_close_serial = 0

        self.last_direct_report = None

        self.last_close_report = None

        self._request_completion_serial = 0

        self._last_request_completion = None

        if type(host2252_stage1_retry) is not bool:

            raise InputError('host2252 stage1 retry premise must be explicit boolean')

        if type(host2252_m_read_budget) is not int or host2252_m_read_budget < 1:

            raise InputError('host2252 main M-read total budget must be positive integer')

        if type(host2252_stage2_g_retry) is not bool:

            raise InputError('host2252 stage2 G retry premise must be explicit boolean')

        if type(host2252_g_read_budget) is not int or host2252_g_read_budget < 1:

            raise InputError('host2252 main G-read total budget must be positive integer')

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

        if type(host2252_control_m) is not bool:

            raise InputError('host2252 control M option must be bool')

        self.host2252_control_m = host2252_control_m

        self.host2252_stage1_retry = host2252_stage1_retry

        self.host2252_m_read_budget = host2252_m_read_budget

        self._sign_owner = None

        if not isinstance(environment, SigningEnvironment):

            raise InputError("primary signer requires a SigningEnvironment")

        if environment.scalar_sse_state is not None and type(environment.scalar_sse_state) is not ScalarSSEState:

            raise InputError('primary signer requires explicit ScalarSSEState or unknown None')

        self.environment = environment

        self.main_clock_inputs = main_clock_inputs

        self.host129_source_clock_inputs = host129_source_clock_inputs

        self.addresses = addresses or VirtualAddressSpace(initial_stack=initial_stack)

        if self.addresses.initial_stack != initial_stack:

            raise InputError("address space and signer private stack policies differ")

        self.memory, self.image_base = PrimaryMemory(), image_base

        self.retain_diagnostics = retain_diagnostics

        self.workspace_cursor = 0x7300000000

        self.calls = 0

        self.failed = False

        self.profile = profile

        self.configuration_value = configuration_value

        self.exchange = ExchangeMaterial()

        if provider_material is not None and not isinstance(provider_material, ProviderMaterial):

            raise InputError("caller provider state requires ProviderMaterial")

        self.provider_material = provider_material if provider_material is not None else ProviderMaterial()

        self._host_profile_string = b""

        self._empty_body_token = profile.empty_body_token if isinstance(profile, CallerProfile) else None

        self._module_sync_birth = _module_sync_birth
        self._initialize_image()

        from .primary_sdk_blob import LoadedModuleImage

        if not isinstance(environment.module_images, tuple):

            raise InputError("module images must be an explicit tuple")

        names = set()

        for module_image in environment.module_images:

            if not isinstance(module_image, LoadedModuleImage) or module_image.name in names:

                raise InputError("module images require unique declared module names")

            names.add(module_image.name)

            module_image.install(self.memory)

        self._bind_runtime()

        self.response_cache = _RuntimeResponseMaterial(self.runtime)

        self.runtime._primary_entry_owner = self

        from .primary_custom_allocator import bind_runtime_core
        bind_runtime_core(self)
        from .primary_shared_locale import bind_fresh_runtime as bind_shared_locale_runtime
        bind_shared_locale_runtime(self)
        from .primary_module_sync import bind_fresh_runtime as bind_module_sync
        bind_module_sync(self)
        from .primary_notification_static_initializers import bind_static_unit
        bind_static_unit(self)



    def sign(self, command, payload, *, now=None, once10_read_budget=1024):
        return self._start_sign(command, payload, now=now, once10_read_budget=once10_read_budget, result_kind='sign')



    def sign_result(self, command, payload, *, now=None, once10_read_budget=1024):
        return self._start_sign(command, payload, now=now, once10_read_budget=once10_read_budget, result_kind='result')

    def _start_sign(self, command, payload, *, now, once10_read_budget, result_kind):
        from .primary_sign_lifecycle import start_execution
        return start_execution(self.runtime, self._sign_continued(command, payload, now=now,
                               result_kind=result_kind), signer=self, once10_read_budget=once10_read_budget)

    def _sign_continued(self, command, payload, *, now, result_kind):
        from .primary_sign_lifecycle import public_call
        with public_call(self):
            result = yield from self._sign_body(command, payload, now=now)
            if result_kind == 'sign':
                return result.sign
            if result_kind == 'material':
                return result
            return caller_result(result.sign, result.extra, result.token)

    def resume_sign(self, continuation, *, once10_read_budget=1024):
        from .primary_sign_lifecycle import resume_execution
        return resume_execution(self.runtime, continuation, signer=self, once10_read_budget=once10_read_budget)

    def cancel_sign(self, continuation):
        from .primary_sign_lifecycle import cancel_execution
        return cancel_execution(self.runtime, continuation, signer=self)



    def request_device_refresh(self) -> None:
        from .primary_sign_lifecycle import public_call
        from .primary_logger import feature
        from .primary_worker_consumer import _logger
        from .primary_response_refresh import refresh
        from .primary_vm import PrimarySemanticUnavailable
        with public_call(self):
            logger = _logger(self.runtime)
            if feature(self.runtime, logger, 0x25) == 1:
                raise PrimarySemanticUnavailable('foreground device refresh cannot enter the source asynchronous feature0x25 branch')
            return refresh(self.runtime)

    def request_device_refresh_async(self) -> None:
        from .primary_sign_lifecycle import public_call
        from .primary_logger import feature
        from .primary_worker_consumer import _logger
        from .primary_response_refresh import refresh
        from .primary_vm import PrimarySemanticUnavailable
        with public_call(self):
            logger = _logger(self.runtime)
            if feature(self.runtime, logger, 0x25) != 1:
                raise PrimarySemanticUnavailable('asynchronous device refresh requires the source feature0x25 branch')
            return refresh(self.runtime)

    @contextmanager
    def _request_completion_scope(self):
        self._request_completion_serial = getattr(self, '_request_completion_serial', 0) + 1
        try:
            yield
        except BaseException as failure:
            if self._last_request_completion is not None:
                self._last_request_completion = replace(self._last_request_completion, failure_type=type(failure).__name__)
            raise
        else:
            if self._last_request_completion is not None:
                self._last_request_completion = replace(self._last_request_completion, operation_completed=True)

    def complete_request(self, command: bytes, response: bytes, *, success: int, sequence: int,

                         error: int = 0) -> str:

        self._last_request_completion = None

        if not isinstance(command, bytes) or not isinstance(response, bytes):

            raise InputError('request command and response must be bytes')

        for name, value, bits in (('success', success, 8), ('sequence', sequence, 64), ('error', error, 32)):

            if type(value) is not int or not 0 <= value < 1 << bits:

                raise InputError('request completion ' + name + ' must be unsigned' + str(bits))

        if len(command) > 1 << 20 or len(response) > 1 << 20:

            from .primary_vm import PrimaryProgramLimit

            raise PrimaryProgramLimit('request completion input exceeds the bounded offline domain')

        from .primary_sign_lifecycle import public_call, cleanup, region_at

        from .primary_logger import _String

        from .primary_request_transport import _complete

        from .primary_worker_response import _frame

        import sys

        with self._request_completion_scope(), public_call(self):

            runtime, regions, owned, value = self.runtime, [], [], None

            event_start, write_start, outcome = len(runtime.events), len(self.memory.writes), None

            try:

                command_address, _ = _frame(runtime, 24, 'public.request_command')

                regions.append((command_address, region_at(self.memory, command_address)))

                value = _String.construct(runtime, command, _owned=owned)

                value.write_to(command_address)

                pointer, _ = _frame(runtime, max(1, len(response)), 'public.request_response')

                regions.append((pointer, region_at(self.memory, pointer)))

                self.memory.write(pointer, response, source='public.request_response_copy')

                from .primary_sdk import receiver_state

                outcome = _complete(runtime, receiver_state(runtime), command_address, pointer, len(response), success, sequence, error,

                                 consume_command=False)

                return outcome

            finally:

                primary, errors = sys.exception(), []
                self._last_request_completion = _request_completion_receipt(
                    runtime, self._request_completion_serial, sequence, success, bool(response), outcome,
                    event_start, write_start)


                try:

                    if value is not None:

                        if value.get(0, 1) & 1:

                            pointer = value.get(16, 8)

                            if (not owned or region_at(self.memory, pointer) is not owned[0][1] or

                                    pointer not in runtime.allocations):

                                from .primary_vm import PrimaryProgramLimit

                                raise PrimaryProgramLimit('request command backing identity or ledger mismatch')

                        value.destroy()

                except BaseException as failure:

                    errors.append(failure)

                try:

                    cleanup(runtime, regions, owned)

                except BaseException as failure:

                    errors.append(failure)

                if errors:

                    runtime.cleanup_errors.extend(type(failure).__name__ for failure in errors)

                    target = primary if primary is not None else errors[0]

                    for failure in errors:

                        target.add_note('public request cleanup failed: ' + type(failure).__name__)

                    if primary is None:

                        raise target



    def _write_primary_output(self, output, result):

        for offset, value, length_source, copy_source in (

                (0, result.extra, 'BB04EC.primary_extra_length', 'BB0505.primary_extra_copy'),

                (256, result.token, 'BB0528.primary_token_length', 'BB053E.primary_token_copy'),

                (512, result.sign, 'BB0563.primary_sign_length', 'BB057C.primary_sign_copy')):

            self.memory.store(output + offset + 255, len(value) & 255, 1, source=length_source)

            self.memory.write(output + offset, value, source=copy_source)



    def invoke_primary_entry(self, command, payload, length, caller, output):

        from .primary_sign_lifecycle import public_call

        with public_call(self):

            return self._invoke_primary_entry_body(command, payload, length, caller, output)



    def _invoke_primary_entry_body(self, command, payload, length, caller, output):

        from .primary_logger import _cstring, log

        from .primary_vm import PrimarySemanticUnavailable

        if any(type(value) is not int or not 0 <= value < 1 << 64

               for value in (command, payload, length, caller, output)):

            raise InputError('BA22B0 requires five unsigned64 ABI values')

        if not command or not payload or not output:

            log(self.runtime,

                rb'R:\devops\workspace\p-824b74756ad64e12838601ccde6ecefb\platforms\Windows\libsecxx\FGESDKNt.cpp',

                0x7C, b'4761032=input invalid.', self.image_base + 0x48972C7, 1)

            return 1

        selected = _cstring(self.runtime, command)

        count = length & 0xFFFFFFFF

        from .primary_sign_lifecycle import synchronous_execution
        result = synchronous_execution(self.runtime, self._sign_body(selected, self.memory.read(payload, count) if count else b''))

        self._write_primary_output(output, result)

        return 0



    def _caller_host_value(self):

        state = self.memory.load(self.image_base + 0x6751828, 8)

        configured = bool(state and self.memory.load(state + 1, 1))

        if configured:

            from .primary_logger import _String

            from .primary_worker_loop import _initialize

            _initialize(self.runtime, 1)

            self._host_profile_string = _String.read(self.runtime, self.image_base + 0x67516F0).value()

        elif self.profile.host_profile_string:

            self._host_profile_string = self.profile.host_profile_string

        return self._host_profile_string, configured



    def _sign(self, command, payload, *, now=None):
        return self._start_sign(command, payload, now=now, once10_read_budget=1024, result_kind='material')



    def _sign_body(self, command, payload, *, now=None):
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self.runtime)

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        if not isinstance(command, bytes) or not isinstance(payload, bytes) or b"\0" in command:

            raise InputError("command must be NUL-free bytes and payload must be bytes")

        if not isinstance(self.profile, CallerProfile):

            raise InputError("sign requires the host CallerProfile")

        if not isinstance(self.profile.host_profile_string, bytes):

            raise InputError("caller host profile must be raw source bytes")

        if self.profile.device_factory is None and not isinstance(self.profile.xfolder_bytes, bytes):

            raise InputError("caller requires a device factory or an observed source xfolder string")

        if now is not None and (type(now) is not int or not -(1 << 63) <= now < 1 << 63):

            raise InputError("cache selection requires signed64 Unix seconds")

        try:

            from .primary_caller import prepare

            prepare(self.runtime, command, self.environment.caller_observations)

            host_value, configured = self._caller_host_value()

            self.runtime.provider_material = self.provider_material

            self.runtime.provider_profile = self.profile

            device_value, d = self.provider_material.caller_values(self.environment, self.profile, self.runtime)

            from .primary_response_refresh import signing_value

            d = signing_value(self.runtime, self.response_cache, d, self.provider_material.features, now)

            if command in _SECURE_COMMANDS:

                if not payload:

                    token = caller_empty_body_token(self.runtime) if configured else self._empty_body_token

                    if token is None:

                        token = self.refresh_empty_body_token()

                    if not isinstance(token, bytes) or len(token) != 32:

                        raise InputError("initialized empty-body token must contain 32 bytes")

                else:

                    field_number = 6 if command in (

                        b"trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey",

                        b"trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish") else 3

                    token = payload_token(payload, field_number)

            else:

                token = b""

                if (not device_value and (configured or self.profile.device_factory is not None) and

                        (b"login" in command.lower() or command == b"2102") and command != b"wtlogin.trans_emp"):

                    device_value = (caller_device_value(self.runtime) if configured else

                                    device_factory_value(self.profile.device_factory, self.runtime))

            context = caller_context((token, host_value, device_value))

            a = request_context_digest(d, context, payload)

            from .primary_public_entry_tail import prepare as prepare_public, release as release_public

            command_address = prepare_public(self.runtime, command)

            try:

                sign = yield from self.runtime._execute_caller_adapter_continued(

                    a, self.exchange.signing_value(), command, 2, d, core=self._sign_material_continued,

                    feature_observation=() if configured else (self.configuration_value,),

                    borrowed_command=command_address)

            finally:

                from .primary_sign_lifecycle import release_command

                release_command(self.runtime, command_address, release_public)

            return PrimarySignatureResult(sign, d, context)

        except BaseException:

            self.failed = True

            raise



    def refresh_empty_body_token(self):

        self._empty_body_token = empty_body_token(self.environment.qpc, self.environment.random_bytes)

        return self._empty_body_token



    def initialize_application_material(self):

        from .primary_sdk_blob import application_material32

        return self.initialize_module_blob(b'62331990', application_material32())



    def initialize_module_blob(self, key, external32, *, caller_length=32):

        from .primary_worker_response import _frame

        from .primary_worker_consumer import _invoke

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        if key is not None and (not isinstance(key, bytes) or b'\0' in key or len(key) > 1 << 20):

            raise InputError("module key requires bounded NUL-free source bytes or NULL")

        if external32 is not None and (not isinstance(external32, bytes) or len(external32) != 32):

            raise InputError("module initialization requires exactly32 borrowed API bytes or NULL")

        if type(caller_length) is not int or not 0 <= caller_length < 1 << 64:

            raise InputError("module initialization caller length requires unsigned64 ABI bits")

        key_size = len(key) + 1 if key is not None else 0

        external_offset = (key_size + 15) & ~15

        frame, _ = _frame(self.runtime, max(external_offset + 32, 32), 'module initialization caller inputs')

        try:

            key_pointer = frame if key is not None else 0

            external_pointer = frame + external_offset if external32 is not None else 0

            if key is not None:

                self.memory.write(key_pointer, key + b'\0', source='API.module_key_CString')

            if external32 is not None:

                self.memory.write(external_pointer, external32, source='API.module_external32')

            return _invoke(self.runtime, 0xBBFC30, key_pointer, external_pointer, caller_length)

        except BaseException:

            self.failed = True

            raise

        finally:

            self.memory.unmap(frame)



    def initialize_sdk(self):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_sdk import bootstrap

        try:

            return bootstrap(self.runtime)

        except BaseException:

            self.failed = True

            raise



    def initialize_provider(self, metadata, *, private_context_tail=_PROVIDER_TAIL_FROM_ENVIRONMENT):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_provider_init import initialize_metadata

        try:

            if self.primary_backend == 'direct':

                from .primary_sign_lifecycle import provider_initialization_call

                tail = (self.environment.provider_initialization_stack_tail

                        if private_context_tail is _PROVIDER_TAIL_FROM_ENVIRONMENT else private_context_tail)

                with provider_initialization_call(self, metadata, tail):

                    return initialize_metadata(self.runtime, metadata, tail)

            return initialize_metadata(self.runtime, metadata,

                                       self.environment.provider_initialization_stack_tail

                                       if private_context_tail is _PROVIDER_TAIL_FROM_ENVIRONMENT else private_context_tail)

        except BaseException:

            self.failed = True

            raise



    def initialize_notification_statics(self):

        if self.failed:

            raise InputError('signer stopped after an incomplete call; inspect retained state')

        from .primary_notification_static_initializers import initialize_supported

        try:

            return initialize_supported(self.runtime)

        except BaseException:

            self.failed = True

            raise



    def initialize_requests(self):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_request_startup import construct

        try:

            return construct(self.runtime)

        except BaseException:

            self.failed = True

            raise



    def initialize_reporters(self):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_high_reliability import initialize

        try:

            return initialize(self.runtime)

        except BaseException:

            self.failed = True

            raise



    def initialize_super_reporter_worker(self):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_worker_consumer import _invoke

        try:

            return _invoke(self.runtime, 0x2DE0E00)

        except BaseException:

            self.failed = True

            raise



    def initialize_super_reporters(self):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_worker_consumer import _invoke

        try:

            return _invoke(self.runtime, 0x2DF48F0)

        except BaseException:

            self.failed = True

            raise



    def initialize_super_reporter_registry(self):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_worker_consumer import _invoke

        try:

            return _invoke(self.runtime, 0x3591650)

        except BaseException:

            self.failed = True

            raise



    def register_configuration(self, callbacks):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_configuration_callbacks import register_callbacks

        try:

            return register_callbacks(self.runtime, callbacks)

        except BaseException:

            self.failed = True

            raise



    def register_feature_notifications(self):

        if self.failed:

            raise InputError("signer stopped after an incomplete call; inspect retained state")

        from .primary_feature_notifications import register_worker

        try:

            return register_worker(self.runtime)

        except BaseException:

            self.failed = True

            raise



    def reset_empty_body_token(self):

        self._empty_body_token = None



    def _initialize_image(self):

        image = _asset("runtime-image.json")

        if image["source_sha256"] != _SOURCE:

            raise InputError("runtime image source identity mismatch")

        for segment in image["segments"]:

            raw = bytearray.fromhex(segment["hex"])

            for offset in segment["relocations"]:

                value = int.from_bytes(raw[offset:offset + 8], "little") - image["image_base"] + self.image_base

                raw[offset:offset + 8] = value.to_bytes(8, "little")

            if int(segment["rva"],16)==0x6749cc0:
                if raw!=bytes(8) or segment["relocations"]:raise InputError('stdio source birth segment mismatch')
                from .primary_crt_stdio_options import install_fresh_image as install_stdio_options
                install_stdio_options(self)
                continue

            self.memory.map(self.image_base + int(segment["rva"], 16), raw,

                            name="fixed QQ52230 runtime image", initialized=True)

        from .primary_sign import install_singleton_destroy_image

        install_singleton_destroy_image(self.memory, self.image_base)

        # Fixed PE .data virtual tail gives these two selector bytes fresh-image zero.

        for rva, size in ((0x6D85F60, 0x88), (0x677DF80, 40), (0x677DFB0, 512),

                          (0x6D83BE0, 8), (0x6D83C08, 8), (0x6D83C30, 8), (0x6751AB8, 0x7C),

                          (0x677CE80, 9), (0x6750E80, 2)):

            self.memory.map(self.image_base + rva, bytearray(size),

                            name="fixed source fresh-image zero fill", initialized=True)

        from .primary_client_configuration_startup import install_fresh_globals

        install_fresh_globals(self)

        from .primary_command_classification import install_image as install_command_image

        install_command_image(self.memory, self.image_base)

        from .primary_public_entry_tail import install_image as install_public_tail_image

        install_public_tail_image(self.memory, self.image_base)

        from .primary_caller_audit import install_image as install_caller_audit_image

        install_caller_audit_image(self.memory, self.image_base)

        from .primary_sdk import install_image

        install_image(self.memory, self.image_base)

        from .primary_tokens import install_image as install_token_image

        install_token_image(self.memory, self.image_base)

        from .primary_worker import install_image as install_worker_image

        install_worker_image(self.memory, self.image_base)

        from .primary_caller import install_image as install_caller_image

        install_caller_image(self.memory, self.image_base)

        from .primary_logger import install_image as install_logger_image

        install_logger_image(self.memory, self.image_base)

        from .primary_client_configuration import install_image as install_configuration_image

        install_configuration_image(self)

        from .primary_feature_notifications import install_image as install_notification_image

        install_notification_image(self.memory, self.image_base)

        from .primary_notification_thread import install_image as install_notification_thread_image

        install_notification_thread_image(self.memory, self.image_base)

        from .primary_device_notification_worker import install_image as install_device_notification_image

        install_device_notification_image(self.memory, self.image_base)

        from .primary_notification_timezone import install_image as install_timezone_image

        install_timezone_image(self.memory, self.image_base)

        from .primary_notification_static_initializers import install_image as install_notification_statics

        install_notification_statics(self.memory, self.image_base)
        self.memory.map(self.image_base + 0x6D867D8, bytearray(232),
                        name="fixed PE static unit virtual tail", initialized=True)

        from .primary_sdk_collection import install_image as install_sdk_collection_image

        install_sdk_collection_image(self.memory, self.image_base)

        from .primary_worker_loop import install_image as install_worker_loop_image

        install_worker_loop_image(self.memory, self.image_base)

        from .primary_worker_device import install_image as install_device_worker_image

        install_device_worker_image(self.memory, self.image_base)

        from .primary_worker_tasks import install_image as install_worker_task_image

        install_worker_task_image(self.memory, self.image_base)

        from .primary_worker_consumer import install_image as install_worker_consumer_image

        install_worker_consumer_image(self.memory, self.image_base)

        from .primary_worker_response import install_image as install_worker_response_image

        install_worker_response_image(self.memory, self.image_base)

        from .primary_request_runtime import install_image as install_request_runtime_image

        install_request_runtime_image(self.memory, self.image_base)

        from .primary_device_collector import install_image as install_collector_image

        install_collector_image(self.memory, self.image_base)

        from .primary_device_cold import install_image as install_cold_image

        install_cold_image(self.memory, self.image_base)

        from .primary_device_system import install_image as install_system_image

        install_system_image(self.memory, self.image_base)

        from .primary_device_hardware import install_image as install_hardware_image

        install_hardware_image(self.memory, self.image_base)

        from .primary_device_wmi import install_image as install_wmi_image

        install_wmi_image(self.memory, self.image_base)

        from .primary_device_adapter_details import install_image as install_adapter_detail_image

        install_adapter_detail_image(self.memory, self.image_base)

        from .primary_device_system_records import install_image as install_system_record_image

        install_system_record_image(self.memory, self.image_base)

        from .primary_device_adapters import install_image as install_adapter_image

        install_adapter_image(self.memory, self.image_base)

        from .primary_device_identifiers import install_image as install_identifier_image

        install_identifier_image(self.memory, self.image_base)

        from .primary_device_cache import install_image as install_cache_image

        install_cache_image(self.memory, self.image_base)

        from .primary_device_refresh import install_image as install_refresh_image

        install_refresh_image(self.memory, self.image_base)

        from .primary_request_transport import install_image as install_request_transport_image

        install_request_transport_image(self.memory, self.image_base)

        from .primary_device_process_records import install_image as install_process_record_image

        install_process_record_image(self.memory, self.image_base)

        from .primary_device_records import install_image as install_record_producer_image

        install_record_producer_image(self.memory, self.image_base)

        from .primary_signature_encoding import install_image as install_signature_encoding_image

        install_signature_encoding_image(self.memory, self.image_base)

        from .primary_provider_init import install_image as install_provider_initialization_image

        install_provider_initialization_image(self.memory, self.image_base)

        sdk_table = (_DATA / "sdk-initial-table.bin").read_bytes()

        if len(sdk_table) != 512 or hashlib.sha256(sdk_table).hexdigest() != _SDK_TABLE:

            raise InputError("fixed SDK table identity mismatch")

        self.memory.map(self.image_base + 0x618CB00, bytearray(sdk_table),

                        name="fixed compiled SDK table", initialized=True)

        from .primary_sign import install_sdk_initializer_image

        install_sdk_initializer_image(self.memory, self.image_base)

        for rva, filename in ((0x433CCC0, "main-byte-table.bin"),

                              (0x433CDC0, "main-qword-table.bin"),

                              (0x433C4C0, "ecrypt-sboxes.bin"),

                              (0x48B0FA2, "material-state-initial.bin")):

            self.memory.map(self.image_base + rva, (_DATA / filename).read_bytes(),

                            name="fixed QQ52230 computation data", initialized=True)

        from .primary_host2252 import COMPILED_TABLES

        self.memory.map(self.image_base + 0x43FD440, COMPILED_TABLES,

                        name="fixed QQ52230 host2252 banks", initialized=True)

        if self.host2252_control_m:

            from .primary_host2252_retry import install_control_image

            self._host2252_control_dispatch_regions = install_control_image(self.memory, self.image_base)

        if self.host2252_stage2_g_retry:

            from .primary_host2252_g_retry import install_image as install_g_image

            self._host2252_g_dispatch_regions = install_g_image(self.memory, self.image_base)

        if self.host2252_final_f_retry:

            from .primary_host2252_f_retry import install_image

            self._host2252_f_dispatch_regions = install_image(self.memory, self.image_base)

        self.tls_base = 0x7400000000

        self.crt_thread = 0x7400010000

        self.memory.map(self.tls_base, bytearray(0xD78), name="private signer TLS", initialized=True)

        self.memory.map(self.crt_thread, bytearray(0x30), name="private signer CRT state", initialized=False)

        self.memory.store(self.tls_base + 0xA8, 0x80000001, 4, source="virtual_environment.initial_TLS_epoch")

        self.memory.store(self.image_base + 0x5EA1C80, 0x80000001, 4, source="virtual_environment.initial_CRT_epoch")

        self.memory.map(self.image_base + 0x6D8EC90, (0x1122334455667788).to_bytes(8, "little"),

                        name="virtual environment heap handle", initialized=True)



        self.memory.map(self.image_base + 0x485330A, b'--notcmalloc\0',

                        name='fixed source allocator selector literal', initialized=True)

        from .primary_allocator_selector import create_fresh_image

        self._allocator_selector_image = create_fresh_image(self)

        from .primary_custom_allocator import install_fresh_image
        self._custom_hook_image = install_fresh_image(self)

        from .primary_shared_locale import install_fresh_image as install_shared_locale_image
        self._shared_locale_image = install_shared_locale_image(self)
        from .primary_client_configuration_scope import bind_image as bind_client_image
        bind_client_image(self)
        from .primary_module_sync import install_fresh_image as install_module_sync
        self._module_sync_image = install_module_sync(self)
        from .primary_msf_selection import install_fresh_image as install_msf_selection
        from .primary_nt_wrapper_owner import install_fresh_image as install_nt_wrapper_owner
        install_msf_selection(self)
        install_nt_wrapper_owner(self)
        from .primary_login_model_attach import install_fresh_image as install_login_image
        install_login_image(self)
        from .primary_mmkv_host_init import install_fresh_image as install_mmkv_image
        install_mmkv_image(self)


    def _bind_runtime(self):

        env, base = self.environment, self.image_base

        names = ("GetCurrentProcessId", "GetModuleHandleA", "GetProcAddress", "GetCursorPos",

                 "RtlCaptureStackBackTrace", "GetModuleHandleExA", "GetModuleFileNameA",

                    "PathFindFileNameA", "PathStripPathA", "FindWindowA", "IsWindowVisible",

                    "InitializeCriticalSection", "CreateThread", "GetCurrentProcess",

                    "GetModuleFileNameW", "GetModuleHandleW", "GetSystemPowerStatus",

                    "K32EnumProcessModules", "EnumWindows", "GetClassNameW",

                    "GetWindowThreadProcessId", "PathRemoveExtensionW", "PathStripPathW",

                    "AcquireSRWLockExclusive", "ReleaseSRWLockExclusive", "GetTickCount", "Sleep",

                    "GetModuleHandleExW", "GetThreadId", "WakeConditionVariable", "SystemFunction036",

                    "GetSystemTimeAsFileTime", "MultiByteToWideChar", "WideCharToMultiByte",

                    "SHGetFolderPathW", "PathFileExistsW", "RegCreateKeyExA", "RegSetValueExA", "RegCloseKey",

                    "CreateFileW", "ReadFile", "WriteFile", "FlushFileBuffers", "GetFileSize", "CreateDirectoryW",

                    "CloseHandle", "GetLastError", "RegOpenKeyExA", "RegQueryValueExA", "RegDeleteValueA",

                    "GlobalMemoryStatusEx", "GetSystemDirectoryW", "LoadLibraryExW", "FreeLibrary",

                    "CoInitializeEx", "CoCreateInstance", "SysAllocString", "SysFreeString",

                    "CoSetProxyBlanket", "CoUninitialize", "GetNativeSystemInfo", "EnumDisplaySettingsW",

                    "GetSystemMetrics", "GetVersionExW", "GetComputerNameA", "GetUserNameA", "GetCurrentHwProfileA",

                    "GetWindowsDirectoryA", "CreateFileA", "DeviceIoControl", "LoadLibraryA",

                    "GetKeyboardType", "IsDebuggerPresent", "GetSystemDefaultLCID", "GetSystemInfo",

                    "VirtualQuery", "VariantClear", "GetAdaptersInfo")

        from .primary_device_system_records import _IMPORTS as system_record_imports

        names += tuple(name for name in system_record_imports if name not in names)

        from .primary_device_process_records import _IMPORTS as process_record_imports

        names += tuple(name for name in process_record_imports if name not in names)

        from .primary_device_cold import _FINALIZE_IMPORTS as cold_finalize_imports

        names += tuple(name for name in cold_finalize_imports if name not in names)

        from .primary_device_native import _IMPORTS as device_core_imports, _HARDWARE_EXPORTS, _HARDWARE_FLAG

        names += tuple(name for name in device_core_imports if name not in names)

        from .primary_device_hypervisor import _IMPORTS as device_hypervisor_imports

        from .primary_notification_thread import _IMPORTS as notification_thread_imports

        names += tuple(name for name in notification_thread_imports if name not in names)

        from .primary_sdk_probes import _IMPORTS as sdk_probe_imports

        names += tuple(name for name in sdk_probe_imports if name not in names)

        from .primary_thread_dispatch import _IMPORTS as thread_dispatch_imports

        names += tuple(name for name in thread_dispatch_imports if name not in names)

        from .primary_caller import _IMPORTS as caller_imports

        names += tuple(name for name in caller_imports if name not in names)

        names += ("DeleteCriticalSection",)

        from .primary_material_process import _IMPORTS as material_process_imports

        names += tuple(name for name in material_process_imports if name not in names)

        names += tuple(name for name in device_hypervisor_imports if name not in names)

        from .primary_public_entry_tail import _IMPORTS as public_tail_imports

        names += tuple(name for name in public_tail_imports if name not in names)

        from .primary_notification_environment import _IMPORTS as notification_environment_imports

        names += tuple(name for name in notification_environment_imports if name not in names)

        from .primary_notification_accounts import _IMPORTS as notification_ini_imports

        names += tuple(name for name in notification_ini_imports if name not in names)

        from .primary_notification_timezone import _IMPORTS as timezone_imports

        names += tuple(name for name in timezone_imports if name not in names)

        from .primary_notification_process import _IMPORTS as notification_process_imports

        names += tuple(name for name in notification_process_imports if name not in names)

        from .primary_notification_integrity_files import _IMPORTS as notification_integrity_imports

        names += tuple(name for name in notification_integrity_imports if name not in names)

        from .primary_device_integrity import _IMPORTS as integrity_imports

        names += tuple(name for name in integrity_imports if name not in names)

        from .primary_notification_vectors import _IMPORTS as parent_api_descriptors
        from .primary_notification_collectors import _ACCOUNTS_IMPORTS as notification_accounts_imports
        parent_imports = {name: row[0] for name, row in parent_api_descriptors.items()} | notification_accounts_imports
        names += tuple(name for name in parent_imports if name not in names)
        functions = {name: 0x20010000 + 16 * index for index, name in enumerate(names)}

        from .primary_common_guid_export import CommonGuidExport

        common = CommonGuidExport(env.common_guid) if env.common_guid is not None else None

        if common is not None:

            if any(name.lower() == b'common.dll' for name in env.loaded_modules) or any(module.name.lower() == b'common.dll' for module in env.module_images):

                raise InputError('COMMON_GUID_VIRTUAL_MODULE_COLLISION')

            functions['Common.__GetG3Guid'] = 0x20010000 + 16 * len(functions)

        from .primary_notification_modules import _IMPORTS as notification_module_imports
        for name in notification_module_imports:
            if name not in functions:
                functions[name] = 0x20010000 + 16 * len(functions)

        module_names = set(env.loaded_modules) | {b"user32.dll", b"kernel32.dll", b"ntdll.dll"}

        handles = {name: 0x1000000000001000 + 16 * index for index, name in enumerate(sorted(module_names))}

        handles.update({module.name: module.guest_base for module in env.module_images})

        common_handle = 0x1000000000004000 if common is not None else None

        if common is not None and common_handle in handles.values():

            raise InputError('COMMON_GUID_VIRTUAL_HANDLE_COLLISION')

        stack_paths = {base + 0x1000 + 16 * index: path for index, path in enumerate(env.stack_modules)}

        path_handles = {path: 0x1000000000002000 + 16 * index

                        for index, path in enumerate(sorted(set(env.stack_modules) | {env.module_path}))}

        paths = {handle: path for path, handle in path_handles.items()}



        def cursor():

            if env.cursor is None:

                raise UnknownMemory('CURSOR_OBSERVATION_REQUIRED')

            return (1, *env.cursor)



        def module(name):

            if common is not None and type(name) is bytes and name.lower() == b'common.dll':

                return name, common_handle

            if env.raw_core_observations is not None:

                return env.raw_core_observations.module_lookup(name)

            return name, base if name is None else handles.get(name, 0)



        def procedure(handle, name):

            if common is not None and handle == common_handle:

                return handle, name, functions['Common.__GetG3Guid'] if name == b'__GetG3Guid' else 0

            if env.raw_core_observations is not None:

                return env.raw_core_observations.procedure_lookup(handle, name, functions)

            from .primary_core_dynamic_exports import lookup_export

            rows = [lookup_export(alias, name) for alias, value in handles.items() if value == handle]

            identities = {(row['library'], row['export']) for row in rows if row is not None}

            row = next((row for row in rows if row is not None), None) if len(identities) == 1 else None

            return handle, name, functions.get(row['handler_key'], 0) if row and row['supported'] else 0



        def capture(skip, count):

            return skip, count, tuple(stack_paths)[skip:skip + count]



        def from_address(flags, address):

            path = stack_paths.get(address)

            if path is None:

                raise InputError("captured stack address has no supplied module path")

            return flags, address, 1, path_handles[path]



        def filename(handle, capacity):

            path = env.process_path if handle == 0 else env.module_path if handle == base else paths[handle]

            return handle, capacity, len(path), path + b"\0"



        def window(class_name, title):

            return class_name, title, env.windows.get((class_name, title), (0, False))[0]



        def visible(handle):

            values = [int(value[1]) for value in env.windows.values() if value[0] == handle]

            return handle, values[0] if values else 0



        imports = {0x490FDE8: "GetCurrentProcessId", 0x490FEF8: "GetModuleHandleA",

                   0x490FF40: "GetProcAddress", 0x490FF00: "GetModuleHandleExA",

                   0x490FEE8: "GetModuleFileNameA", 0x4910AB0: "PathFindFileNameA",

                   0x4910AF0: "PathStripPathA", 0x4910628: "IsWindowVisible",

                   0x490FBD8: "CloseHandle"}

        imports.update({rva: name for name, rva in public_tail_imports.items()})

        mapping = json.loads((_DATA / "main-host-map.json").read_text("utf-8"))

        for host in mapping["hosts"]:

            source = host["source"]

            if source["kind"] == "LOAD64_CURRENT_MEMORY":

                rva = int(source["rva"], 16)

                value = functions[imports[rva]] if rva in imports else 0

                self.memory.map(base + rva, value.to_bytes(8, "little"),

                                name="virtual environment import", initialized=True)

        for name, rva in public_tail_imports.items():

            address = base + rva

            if not any(region.address <= address and address + 8 <= region.address + len(region.data) for region in self.memory._regions):

                self.memory.map(address, functions[name].to_bytes(8, 'little'), name='public entry raw import', initialized=True)

        self.memory.map(base + 0x49100D8, bytearray(functions["InitializeCriticalSection"].to_bytes(8, "little")),

                        name="receiver InitializeCriticalSection import", initialized=True)

        self.memory.map(base + 0x490FC80, bytearray(functions["CreateThread"].to_bytes(8, "little")),

                        name="SDK bootstrap CreateThread import", initialized=True)

        self.memory.map(base + 0x490FCA0, bytearray(functions["DeleteCriticalSection"].to_bytes(8, "little")),

                        name="DeleteCriticalSection import", initialized=True)

        from .primary_worker import _IMPORTS

        from .primary_logger import _IMPORTS as logger_imports

        from .primary_worker_tasks import _IMPORTS as task_imports

        from .primary_device_collector import _IMPORTS as collector_imports

        from .primary_device_identifiers import _IMPORTS as identifier_imports

        from .primary_device_cache import _IMPORTS as cache_imports

        from .primary_device_provenance import _IMPORTS as provenance_imports

        from .primary_device_refresh import _IMPORTS as refresh_imports

        from .primary_device_cold import _IMPORTS as cold_imports

        from .primary_device_system import _IMPORTS as system_imports

        from .primary_device_hardware import _IMPORTS as hardware_imports

        from .primary_device_adapters import _IMPORTS as adapter_imports

        from .primary_device_wmi import _IMPORTS as wmi_imports

        from .primary_device_adapter_details import _IMPORTS as adapter_detail_imports

        worker_source_imports = (_IMPORTS | logger_imports | task_imports | collector_imports | identifier_imports | cache_imports | provenance_imports | refresh_imports | cold_imports | system_imports | hardware_imports | adapter_imports | wmi_imports | adapter_detail_imports | system_record_imports | process_record_imports | cold_finalize_imports | device_core_imports | device_hypervisor_imports | notification_thread_imports | sdk_probe_imports | thread_dispatch_imports | caller_imports | material_process_imports | notification_environment_imports | notification_ini_imports | timezone_imports | notification_process_imports | notification_integrity_imports | integrity_imports | notification_module_imports)
        for name, rva in parent_imports.items():
            if name in worker_source_imports and worker_source_imports[name] != rva:
                raise InputError('parent import conflicts with its existing source IAT identity')
            if any(slot == rva and symbol != name for symbol, slot in worker_source_imports.items()):
                raise InputError('parent import aliases a different existing source API')
        for name, rva in (worker_source_imports | parent_imports).items():

            if rva not in imports and rva != 0x490FC80 and rva not in {slot for symbol, slot in _HARDWARE_EXPORTS}:

                self.memory.map(base + rva, bytearray(functions[name].to_bytes(8, 'little')),

                                name='SDK worker environment import', initialized=True)

        marker = base + 0x6D8677A

        if not any(region.address <= marker and marker + 14 <= region.address + len(region.data) for region in self.memory._regions):

            self.memory.map(marker, bytearray(14), name='env_detect PE zero fill before declared initializer', initialized=True)

        literal = base + 0x4903C10

        if not any(region.address <= literal < region.address + len(region.data) for region in self.memory._regions):

            self.memory.map(literal, b'\0', name='fixed empty INI default literal', initialized=True)

        if self.memory.read(literal, 1) != b'\0':

            raise InputError('fixed INI default literal mismatch')

        self.memory.map(base + _HARDWARE_FLAG, bytearray(0x48),

                        name='device hardware lookup source BSS', initialized=True)

        self.memory.store(base + 0x73940F8, functions['SystemFunction036'], 8,

                          source='virtual_environment.resolved_SystemFunction036')

        self.runtime = PrimaryRuntime(

            self.memory, image_base=base, tls_base_address=self.tls_base,

            tls_epoch_address=self.tls_base + 0xA8, crt_thread_address=self.crt_thread,

            filetimes=env.filetime, qpc=env.qpc, clock_apis=env.clock_apis, entropy=lambda: env.random_bytes(4),

            bcrypt=env.bcrypt if env.bcrypt is not None else lambda: (0, env.random_bytes(4)),

            stderr=env.stderr, allocations=self.addresses.allocation,

            frames=self.addresses.frame, temporaries=self.addresses.temporary,

            program_context=getattr(self.addresses, 'program_context', None),

            current_process=(functions["GetCurrentProcessId"], env.process_id),

            module_lookup=(functions["GetModuleHandleA"], module),

            procedure_lookup=(functions["GetProcAddress"], procedure),

            cursor_position=(functions["GetCursorPos"], cursor),

            stack_capture=(functions["RtlCaptureStackBackTrace"], capture),

            module_from_address=(functions["GetModuleHandleExA"], from_address),

            module_filename=(functions["GetModuleFileNameA"], filename),

            path_filename=functions["PathFindFileNameA"], path_strip=functions["PathStripPathA"],

            find_window=(functions["FindWindowA"], window),

            window_visible=(functions["IsWindowVisible"], visible),

            provider_material=self.provider_material, provider_environment=env, provider_profile=self.profile,

            postfetch_start_errors=env.postfetch_start_errors,

            telemetry_metadata_providers=env.telemetry_metadata_providers, postfetch_crt_seed=env.postfetch_crt_seed,

             critical_section_init=functions["InitializeCriticalSection"], exit_registration=env.exit_registration,

             create_thread=(functions["CreateThread"], env.sdk_thread_starts),

             worker_observations=env.worker_observations, worker_imports=functions, logger_output=env.logger_output,

             worker_device_records=env.worker_device_records,

             request_capi=env.request_capi, request_transport=env.request_transport,

              device_configuration=env.device_configuration,

              device_configuration_read=env.device_configuration_read,

             response_feature_initial=None if self.addresses.initial_stack is None else self.addresses.initial_stack[:8],

              host2252_normal=True, retain_frames=False, primary_core=True,

              host2252_stage1_retry=self.host2252_stage1_retry,

              host2252_m_read_budget=self.host2252_m_read_budget, host2252_retry_mode='synchronous',

              host2252_stage2_g_retry=self.host2252_stage2_g_retry, host2252_g_read_budget=self.host2252_g_read_budget,

              host2252_final_f_retry=self.host2252_final_f_retry, host2252_f_read_budget=self.host2252_f_read_budget,

              host2252_pair_m_retry=self.host2252_pair_m_retry, host2252_pair_m_read_budget=self.host2252_pair_m_read_budget,

              host2252_control_m=self.host2252_control_m,

              process_material=env.process_material, raw_core_observations=env.raw_core_observations,

              singleton_producer_inputs=env.singleton_producer_inputs,

              warm_core_container_inputs=env.warm_core_container_inputs,

              main_environment_inputs=env.main_environment_inputs,

              host129_counter_reads=env.host129_counter_reads,

              host129_clock_service_returns=env.host129_clock_service_returns,

              host129_entropy_service_returns=env.host129_entropy_service_returns,

              host129_raw_inputs=env.host129_raw_inputs,

              main_clock_inputs=self.main_clock_inputs,

              host129_source_clock_inputs=self.host129_source_clock_inputs,

              scalar_sse_state=env.scalar_sse_state, primary_backend=self.primary_backend)

        from .primary_allocator_selector import bind_fresh_runtime

        bind_fresh_runtime(self)

        if common is not None:

            common.bind(self.runtime, functions['Common.__GetG3Guid'])

        from .primary_host129_inputs import ObservedHost129AddressSpace

        if isinstance(self.addresses, ObservedHost129AddressSpace):

            self.addresses.bind_runtime(self.runtime)

        if env.raw_core_observations is not None:

            env.raw_core_observations.bind_caller(env.caller_observations)

            if env.process_material is None:

                from .primary_material_process import ProcessMaterialObservations

                self.runtime.process_material = ProcessMaterialObservations(env.raw_core_observations.process_event)

        from .primary_device_provider import DeviceFactory, DeviceRefreshGate

        if isinstance(self.profile, CallerProfile) and isinstance(self.profile.device_factory, DeviceFactory):

            if self.profile.device_factory.refresh_gate is None:

                self.profile.device_factory.refresh_gate = DeviceRefreshGate.native()



    def sign_material(self, a, b, command, d, *, policy=2):

        from .primary_sign_lifecycle import public_call

        with public_call(self):

            return self._sign_material(a, b, command, d, policy=policy)



    def _sign_material(self, a, b, command, d, *, policy=2):
        from .primary_sign_lifecycle import synchronous_execution
        return synchronous_execution(self.runtime, self._sign_material_continued(a, b, command, d, policy=policy))

    def _sign_material_continued(self, a, b, command, d, *, policy=2):
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self.runtime)

        from .primary_sign_lifecycle import cleanup, region_at

        from threading import get_ident

        if self._sign_owner != get_ident():

            raise InputError('material execution requires this public call owner')

        if self.failed:

            raise InputError('signer stopped after an incomplete call; inspect retained state')

        if any(not isinstance(value, bytes) for value in (a, b, command, d)):

            raise InputError('signing material, command and payloads must be bytes')

        if type(policy) is not int or not 0 <= policy <= 0xFFFFFFFF:

            raise InputError('signing policy must be unsigned32')

        workspace = self.workspace_cursor

        self.workspace_cursor += 4096

        self.memory.map(workspace, bytearray(4096), name='private string adapter call', initialized=False)

        regions = [(workspace, region_at(self.memory, workspace))]

        owned = []



        def allocate(size, zero):

            pointer = self.runtime._allocate(size, zero)

            owned.append((pointer, region_at(self.memory, pointer)))

            return pointer



        try:

            for offset, value in zip((0, 24, 48, 72), (a, b, command, d)):

                write_string(self.memory, workspace + offset, value, allocate)

            yield from self.runtime._execute_string_adapter_continued(workspace + 96, workspace, workspace + 24,

                                                workspace + 48, policy, workspace + 72,

                                                stack_address=workspace + 256, output_allocate=allocate)

            result = string_bytes(self.memory, workspace + 96)

        finally:

            cleanup(self.runtime, regions, owned)

        self._pending_material_completions += 1

        if not self.retain_diagnostics and self.primary_backend != 'direct':

            self.runtime.events.clear()

            self.runtime.vms.clear()

            self.memory.writes.clear()

        return result

