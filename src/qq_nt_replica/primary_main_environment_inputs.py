from dataclasses import dataclass, field
from threading import get_ident

from .errors import InputError
from .primary_consumed_mgf import SourceIdentity
from .primary_core_dynamic_exports import lookup_export


def _uint(value, bits):
    return type(value) is int and 0 <= value < 1 << bits


@dataclass(frozen=True, repr=False)
class MainEnvironmentIdentity:
    source_identity: SourceIdentity
    process_creation_identity: str
    module_load_generation: str
    native_thread_id: int
    reader_invocation: int
    main_epoch: str
    context_profile_verified: bool
    double_read_equal: bool
    capture_point: str = 'effective-main-evaluator-entry'

    def __post_init__(self):
        if (type(self.source_identity) is not SourceIdentity or
                any(type(v) is not str or not 0 < len(v) <= 256 for v in
                    (self.process_creation_identity, self.module_load_generation, self.main_epoch)) or
                any(not _uint(v, 32) or not v for v in (self.native_thread_id, self.reader_invocation)) or
                self.context_profile_verified is not True or self.double_read_equal is not True or
                self.capture_point != 'effective-main-evaluator-entry'):
            raise InputError('MAIN_ENVIRONMENT_IDENTITY')


@dataclass(frozen=True, repr=False)
class QualifiedCursorFunction:
    identity: MainEnvironmentIdentity
    source_pointer_u64: int
    source_module_handle_u64: int
    library: bytes = b'user32.dll'
    export: bytes = b'GetCursorPos'
    argument_widths: tuple = (64,)
    result_width: int = 32

    def __post_init__(self):
        row = lookup_export('user32.dll', 'GetCursorPos')
        if (type(self.identity) is not MainEnvironmentIdentity or
                any(not _uint(v, 64) or not v for v in
                    (self.source_pointer_u64, self.source_module_handle_u64)) or
                self.source_pointer_u64 == self.source_module_handle_u64 or
                type(self.library) is not bytes or self.library != b'user32.dll' or
                type(self.export) is not bytes or self.export != b'GetCursorPos' or
                type(self.argument_widths) is not tuple or self.argument_widths != row['argument_widths'] or
                any(type(v) is not int for v in self.argument_widths) or
                type(self.result_width) is not int or self.result_width != row['result_width'] or
                not row['supported'] or row['call_path'] != 'nativecall'):
            raise InputError('MAIN_ENVIRONMENT_CURSOR_QUALIFICATION')


@dataclass(frozen=True, repr=False)
class QualifiedMD5Callback:
    identity: MainEnvironmentIdentity
    source_pointer_u64: int
    source_module_base_u64: int
    callback_rva: int = 0x1BFD3D0
    implementation_rva: int = 0x1D05D10

    def __post_init__(self):
        if (type(self.identity) is not MainEnvironmentIdentity or
                not _uint(self.source_module_base_u64, 64) or not self.source_module_base_u64 or
                not _uint(self.source_pointer_u64, 64) or
                type(self.callback_rva) is not int or self.callback_rva != 0x1BFD3D0 or
                type(self.implementation_rva) is not int or self.implementation_rva != 0x1D05D10 or
                self.source_module_base_u64 > (1 << 64) - 1 - self.implementation_rva or
                self.source_pointer_u64 != self.source_module_base_u64 + self.callback_rva):
            raise InputError('MAIN_ENVIRONMENT_MD5_QUALIFICATION')


@dataclass(frozen=True, repr=False)
class MainEnvironmentInputs:
    identity: MainEnvironmentIdentity
    cursor_function: QualifiedCursorFunction | None
    frame_count_u16: int
    frames: tuple[int, ...]
    md5_callback: QualifiedMD5Callback | None
    prng_initial_u32: int
    _claimed: bool = field(default=False, init=False, compare=False)

    def __post_init__(self):
        if (type(self.identity) is not MainEnvironmentIdentity or
                self.cursor_function is not None and
                (type(self.cursor_function) is not QualifiedCursorFunction or
                 self.cursor_function.identity != self.identity) or
                self.md5_callback is not None and
                (type(self.md5_callback) is not QualifiedMD5Callback or
                 self.md5_callback.identity != self.identity) or
                not _uint(self.prng_initial_u32, 32) or
                not _uint(self.frame_count_u16, 16) or self.frame_count_u16 > 4 or
                type(self.frames) is not tuple or len(self.frames) != self.frame_count_u16 or
                any(not _uint(v, 64) for v in self.frames)):
            raise InputError('MAIN_ENVIRONMENT_FIELDS')


class _MainEnvironmentBinding:
    def __init__(self, inputs, runtime):
        if type(inputs) is not MainEnvironmentInputs or inputs._claimed:
            raise InputError('MAIN_ENVIRONMENT_REUSED_OR_UNTYPED')
        identity = inputs.identity
        if identity.source_identity.image_base != runtime.image_base or runtime._program_calls or runtime._main_generation:
            raise InputError('MAIN_ENVIRONMENT_INSTALL_CONTEXT')
        lineage = (identity.process_creation_identity, identity.module_load_generation,
                   identity.native_thread_id, identity.reader_invocation)
        warm = runtime._warm_core_binding
        if warm is not None:
            other = warm.identity
            if (other.source_identity != identity.source_identity or
                    (other.process_creation_identity, other.module_load_generation,
                     other.native_thread_id, other.reader_invocation) != lineage):
                raise InputError('MAIN_ENVIRONMENT_WARM_IDENTITY')
        clocks = runtime._main_clock_binding
        if clocks is not None:
            other = clocks._rows[0]
            if (other.source_identity != identity.source_identity or
                    (other.process_creation_identity, other.module_load_generation,
                     other.native_thread_id, other.reader_invocation) != lineage):
                raise InputError('MAIN_ENVIRONMENT_CLOCK_IDENTITY')
        target = 0
        if inputs.cursor_function is not None:
            target = runtime.cursor_position_address
            if not _uint(target, 64) or not target:
                raise InputError('MAIN_ENVIRONMENT_CURSOR_HANDLER')
            source = inputs.cursor_function
            if (source.source_pointer_u64 == runtime.image_base or
                    source.source_module_handle_u64 == runtime.image_base):
                raise InputError('MAIN_ENVIRONMENT_CURSOR_IDENTITY_COLLISION')
        memory, base = runtime.memory, runtime.image_base
        md5_target = 0 if inputs.md5_callback is None else base + 0x1BFD3D0
        if not _uint(md5_target, 64):
            raise InputError('MAIN_ENVIRONMENT_MD5_HANDLER')
        writes = [(base + 0x6D85FE8, md5_target.to_bytes(8, 'little')),
                  (base + 0x6D86000, target.to_bytes(8, 'little')),
                  (base + 0x6D86010, inputs.prng_initial_u32.to_bytes(4, 'little')),
                  (base + 0x6D86014, inputs.frame_count_u16.to_bytes(2, 'little'))]
        writes.extend((base + 0x6D86020 + 8 * i, value.to_bytes(8, 'little'))
                      for i, value in enumerate(inputs.frames))
        for address, data in writes:
            region, _ = memory._span(address, len(data))
            if region.data.readonly:
                raise InputError('MAIN_ENVIRONMENT_READONLY')
        object.__setattr__(inputs, '_claimed', True)
        self.identity, self.runtime, self.thread = identity, runtime, get_ident()
        self.bound = False
        for address, data in writes:
            memory.write(address, data, source='main_environment.effective_entry_field')

    def enter(self, arguments, hosts):
        runtime = self.runtime
        if get_ident() != self.thread:
            raise InputError('MAIN_ENVIRONMENT_THREAD')
        if not self.bound:
            source = self.identity.source_identity
            if (arguments != source.main_arguments or hosts is not None or
                    runtime._main_generation + 1 != source.generation):
                raise InputError('MAIN_ENVIRONMENT_MAIN_IDENTITY')
            self.bound = True
