from dataclasses import dataclass, field
from threading import get_ident

from .errors import InputError
from .primary_consumed_mgf import SOURCE_SHA256, SourceIdentity


LAYOUT = 'qq-9.9.33-52230-type117-main408-v1'


def _uint(value, bits):
    return type(value) is int and 0 <= value < 1 << bits


def _bytes(value, size):
    return type(value) is bytes and len(value) == size


@dataclass(frozen=True, repr=False)
class WarmCoreIdentity:
    source_identity: SourceIdentity
    process_creation_identity: str
    module_load_generation: str
    native_thread_id: int
    reader_invocation: int
    container_address: int
    layout: str = LAYOUT
    capture_point: str = 'main408-singleton-normal-leave-before414'

    def __post_init__(self):
        if (type(self.source_identity) is not SourceIdentity or
                self.source_identity.wrapper_sha256 != SOURCE_SHA256 or self.layout != LAYOUT or
                self.capture_point != 'main408-singleton-normal-leave-before414' or
                any(type(v) is not str or not v for v in
                    (self.process_creation_identity, self.module_load_generation)) or
                any(not _uint(v, 32) or not v for v in (self.native_thread_id, self.reader_invocation)) or
                not _uint(self.container_address, 64) or not self.container_address or
                self.container_address % 16 or self.container_address + 1328 > 1 << 64):
            raise InputError('warm core identity/layout is invalid')


@dataclass(frozen=True, repr=False)
class TokenEntry:
    encoded4: bytes
    selector_u8: int
    enabled_u8: int

    def __post_init__(self):
        if (not _bytes(self.encoded4, 4) or not _uint(self.selector_u8, 8) or
                not _uint(self.enabled_u8, 8) or self.enabled_u8 and self.selector_u8 >= 64):
            raise InputError('warm token entry domain is invalid')


@dataclass(frozen=True, repr=False)
class GuidEntry:
    encoded33: bytes
    selector_u8: int
    marker_u8: int

    def __post_init__(self):
        if (not _bytes(self.encoded33, 33) or not _uint(self.selector_u8, 8) or
                not _uint(self.marker_u8, 8) or self.marker_u8 and self.selector_u8 >= 64):
            raise InputError('warm GUID entry domain is invalid')


@dataclass(frozen=True, repr=False)
class WarmCoreContainerInputs:
    identity: WarmCoreIdentity
    salt_u32: int
    encoded16: bytes
    field3_u8: int
    field4_u8: int
    field5_u8: int
    table64: bytes
    tokens: tuple[TokenEntry, ...]
    guids: tuple[GuidEntry, ...]
    field12_u8: int
    field14_u32: int
    field15_u32: int
    field16_u32: int
    field17_u16: int
    field19_u8: int
    field22_u64: int
    field23_u64: int
    control_x_u32: int
    control_y_i32: int
    class6_i32: int
    _claimed: bool = field(default=False, init=False, compare=False)

    def __post_init__(self):
        if (type(self.identity) is not WarmCoreIdentity or not _bytes(self.encoded16, 16) or
                not _bytes(self.table64, 64) or type(self.tokens) is not tuple or len(self.tokens) != 50 or
                any(type(v) is not TokenEntry for v in self.tokens) or
                type(self.guids) is not tuple or len(self.guids) != 5 or
                any(type(v) is not GuidEntry for v in self.guids)):
            raise InputError('warm core typed field/record extent is invalid')
        for name, bits in (('salt_u32', 32), ('field3_u8', 8), ('field4_u8', 8), ('field5_u8', 8),
                           ('field12_u8', 8), ('field14_u32', 32), ('field15_u32', 32),
                           ('field16_u32', 32), ('field17_u16', 16), ('field19_u8', 8),
                           ('field22_u64', 64), ('field23_u64', 64), ('control_x_u32', 32)):
            if not _uint(getattr(self, name), bits):
                raise InputError('warm core unsigned field domain is invalid: ' + name)
        if (any(type(v) is not int or not -(1 << 31) <= v < 1 << 31
                for v in (self.control_y_i32, self.class6_i32)) or
                self.class6_i32 == -(1 << 31) or
                (((self.control_x_u32 * self.control_x_u32) & 0xffffffff) |
                 (abs(self.control_y_i32) & 0xffffffff)) >> 31):
            raise InputError('warm core control globals exceed supported normal domain')


class _WarmCoreBinding:
    def __init__(self, inputs, runtime):
        if type(inputs) is not WarmCoreContainerInputs or inputs._claimed:
            raise InputError('warm core inputs require an unused typed snapshot')
        identity = inputs.identity
        if identity.source_identity.image_base != runtime.image_base:
            raise InputError('warm core image identity mismatch')
        m, b, p = runtime.memory, runtime.image_base, identity.container_address
        if m.load(b + 0x6D88CC0, 8) != 0:
            raise InputError('warm core installation requires an unpublished singleton slot')
        ranges = ((b + 0x6D88CC0, 8), (b + 0x6D88CC8, 4), (runtime.tls_epoch_address, 4),
                  (b + 0x5EA1C80, 4), (b + 0x6D86090, 4), (b + 0x6D86094, 4), (b + 0x677E1BC, 4))
        for address, width in ranges:
            region, _ = m._span(address, width)
            if region.data.readonly or address < p + 1328 and p < address + width:
                raise InputError('warm core installation state overlaps or is readonly')
        m.map(p, bytearray(1328), name='typed warm core type117', initialized=False)
        object.__setattr__(inputs, '_claimed', True)
        self.identity, self.runtime, self.thread = identity, runtime, get_ident()
        self.bound = False
        for offset, data in ((6, inputs.encoded16), (25, inputs.table64)):
            m.write(p + offset, data, source='warm_core.typed_field')
        for offset, value, width in ((0, inputs.salt_u32, 4), (22, inputs.field3_u8, 1),
                (23, inputs.field4_u8, 1), (24, inputs.field5_u8, 1), (1193, inputs.field12_u8, 1),
                (1224, inputs.field14_u32, 4), (1228, inputs.field15_u32, 4), (1232, inputs.field16_u32, 4),
                (1236, inputs.field17_u16, 2), (1250, inputs.field19_u8, 1),
                (1264, inputs.field22_u64, 8), (1272, inputs.field23_u64, 8)):
            m.store(p + offset, value, width, source='warm_core.typed_field')
        for i, entry in enumerate(inputs.tokens):
            address = p + 92 + i * 12
            m.write(address, entry.encoded4, source='warm_core.token_encoded')
            m.store(address + 8, entry.selector_u8, 1, source='warm_core.token_selector')
            m.store(address + 9, entry.enabled_u8, 1, source='warm_core.token_enabled')
        for i, entry in enumerate(inputs.guids):
            address = p + 1016 + i * 35
            m.write(address, entry.encoded33, source='warm_core.guid_encoded')
            m.store(address + 33, entry.selector_u8, 1, source='warm_core.guid_selector')
            m.store(address + 34, entry.marker_u8, 1, source='warm_core.guid_marker')
        for rva, value in ((0x6D86090, inputs.control_x_u32), (0x6D86094, inputs.control_y_i32),
                           (0x677E1BC, inputs.class6_i32)):
            m.store(b + rva, value, 4, source='warm_core.typed_control')
        for address in (b + 0x5EA1C80, b + 0x6D88CC8, runtime.tls_epoch_address):
            m.store(address, 0x80000002, 4, source='warm_core.model_completed_CRT_epoch')
        m.store(b + 0x6D88CC0, p, 8, source='warm_core.singleton_publish')

    def validate_getter(self):
        runtime = self.runtime
        if get_ident() != self.thread:
            raise InputError('warm core runtime thread mismatch')
        if not self.bound and runtime._program_calls:
            source = self.identity.source_identity
            call = runtime._program_calls[0]
            if (call['name'] != 'main' or call['arguments'] != source.main_arguments or
                    call['hosts'] is not None or runtime._main_generation != source.generation):
                raise InputError('warm core selected Main identity mismatch')
            self.bound = True
