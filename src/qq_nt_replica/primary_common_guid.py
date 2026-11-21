from dataclasses import dataclass, field
import hashlib

from .errors import InputError
from .primary_memory import PrimaryMemory
from .primary_vm import PrimarySemanticUnavailable


SOURCE_SHA256 = '8cbaf780248b078226e9836fc91e719eb2d7fc3bc9ad2dd88bf387a8e28b0925'
SELECTION_PROVENANCE = frozenset(('source-qualified-17390-mode0-flags3',
                                 'synthetic-17390-mode0-flags3'))
_OWNED = object()


def _integer(value, low, high, field):
    if type(value) is not int or not low <= value <= high:
        raise InputError(field)
    return value


def _boolean(value, field):
    if type(value) is not bool:
        raise InputError(field)
    return value


def _bytes(value, size, field):
    if type(value) is not bytes or len(value) != size:
        raise InputError(field)
    return value


@dataclass(frozen=True)
class DiskPrimitives:
    directory_result: int
    directory_buffer: bytes | None = None
    volume_opened: bool | None = None
    device_number_success: bool | None = None
    device_number_buffer: bytes | None = None
    device_number_returned: int | None = None
    physical_drive_index: int | None = None
    physical_opened: bool | None = None
    descriptor_success: bool | None = None
    descriptor_buffer: bytes | None = None
    descriptor_returned: int | None = None


def disk_material(raw):
    if type(raw) is not DiskPrimitives:
        raise InputError('DISK_RAW_PRIMITIVES')
    _integer(raw.directory_result, 0, 0xFFFFFFFF, 'WINDOWS_DIRECTORY_RESULT')
    directory = _bytes(raw.directory_buffer, 522, 'WINDOWS_DIRECTORY_RAW_261_WCHAR')
    units = tuple(directory[index:index + 2] for index in range(0, 522, 2))
    end = next((index for index, unit in enumerate(units) if unit == b'\0\0'), None)
    if end is None:
        raise PrimarySemanticUnavailable('WINDOWS_DIRECTORY_BOUNDED_CSTRING')
    number = -1
    if end > 1 and _boolean(raw.volume_opened, 'VOLUME_OPEN_OUTCOME'):
        _boolean(raw.device_number_success, 'DEVICE_NUMBER_IOCTL_OUTCOME')
        buffer = _bytes(raw.device_number_buffer, 12, 'DEVICE_NUMBER_RAW_12')
        number = int.from_bytes(buffer[4:8], 'little', signed=True)
    if _integer(raw.physical_drive_index, 0, 0x7FFFFFFF, 'PHYSICAL_DRIVE_INDEX') != max(number, 0):
        raise PrimarySemanticUnavailable('PHYSICAL_DRIVE_OUTCOME_PATH_MISMATCH')
    if not _boolean(raw.physical_opened, 'PHYSICAL_DRIVE_OPEN_OUTCOME'):
        return b' '
    if not _boolean(raw.descriptor_success, 'DESCRIPTOR_IOCTL_OUTCOME'):
        return b' '
    buffer = _bytes(raw.descriptor_buffer, 1024, 'DESCRIPTOR_RAW_1024')
    offset = int.from_bytes(buffer[0x10:0x14], 'little')
    if offset >= len(buffer):
        raise PrimarySemanticUnavailable('DESCRIPTOR_OFFSET_OUTSIDE_BUFFER')
    first = buffer[offset]
    if first >= 128:
        raise PrimarySemanticUnavailable('DISK_CRT_LOCALE_CLASSIFICATION')
    if not (48 <= first <= 57 or 65 <= first <= 90 or 97 <= first <= 122):
        return b' '
    end = buffer.find(b'\0', offset)
    if end < 0:
        raise PrimarySemanticUnavailable('DESCRIPTOR_UNBOUNDED_CSTRING')
    return buffer[offset:end]


def cpu_material(leaves):
    if type(leaves) is not tuple or len(leaves) != 3:
        raise InputError('CPUID_THREE_ORDERED_LEAVES')
    raw = bytearray()
    for leaf in leaves:
        if type(leaf) is not tuple or len(leaf) != 4:
            raise InputError('CPUID_EAX_EBX_ECX_EDX')
        for register in leaf:
            raw.extend(_integer(register, 0, 0xFFFFFFFF, 'CPUID_REGISTER_DWORD').to_bytes(4, 'little'))
    return bytes(raw).split(b'\0', 1)[0] if raw[0] else b' '


@dataclass(frozen=True)
class NetworkPrimitives:
    enumeration_result: int
    selected_prefixes: tuple
    selection_provenance: str


def translate_selected_address(address_length, raw_address, *, selection_provenance):
    if selection_provenance not in SELECTION_PROVENANCE:
        raise PrimarySemanticUnavailable('MAC_MODE0_FLAGS3_SELECTION_UNKNOWN')
    length = _integer(address_length, 0, 8, 'SELECTED_ADAPTER_ADDRESS_LENGTH')
    address = _bytes(raw_address, 8, 'SELECTED_ADAPTER_ADDRESS_RAW_8')
    return address[:length] + bytes(8 - length)


def mac_material(raw):
    from .primary_mac_selector import SelectorNetwork
    if type(raw) is SelectorNetwork:
        return raw.material()
    if type(raw) is not NetworkPrimitives:
        raise InputError('NETWORK_RAW_PRIMITIVES')
    if raw.selection_provenance not in SELECTION_PROVENANCE:
        raise PrimarySemanticUnavailable('MAC_MODE0_FLAGS3_SELECTION_UNKNOWN')
    result = _integer(raw.enumeration_result, -0x80000000, 0x7FFFFFFF, 'NETWORK_ENUMERATION_RESULT')
    if result <= 0:
        return b' '
    if type(raw.selected_prefixes) is not tuple:
        raise InputError('SELECTED_NETWORK_RECORD_VECTOR')
    if not raw.selected_prefixes:
        return b' '
    prefix = _bytes(raw.selected_prefixes[0], 8, 'SELECTED_NETWORK_RECORD_PREFIX_8')
    return prefix.hex().upper().encode('ascii')


@dataclass(frozen=True)
class GuidPrimitives:
    disk: DiskPrimitives
    cpuid_leaves: tuple
    network: NetworkPrimitives


@dataclass(frozen=True)
class GuidPrimitiveSource:
    collect: object = field(repr=False)

    def __post_init__(self):
        if not callable(self.collect):
            raise InputError('COMMON_GUID_PRIMITIVE_SOURCE')


@dataclass(frozen=True)
class CacheProtocol:
    provider_available: bool = True
    acquire_status: int = 0
    group_available: bool = True
    blob_flag: int = 0
    version_read: int | None = None
    length_read: int | None = None
    late_blob_present: bool = True
    data_pointer_present: bool = True


@dataclass(frozen=True)
class CacheWriteOutcome:
    blob_status: int
    version_status: int
    blob_applied: bool
    version_applied: bool


class _OwnedBlob:
    def __init__(self, raw, owner, capability):
        if capability is not _OWNED:
            raise InputError('CACHE_OWN_PRODUCER_REQUIRED')
        self.raw, self.owner = raw, owner


class OwnGuidCache:
    def __init__(self, *, protocol=CacheProtocol(), write_outcome=CacheWriteOutcome(0, 0, True, True)):
        self.protocol, self.write_outcome = protocol, write_outcome
        self._blob, self._version = None, 0
        self.events = []

    def _group(self):
        p = self.protocol
        if type(p) is not CacheProtocol:
            raise InputError('CACHE_PROTOCOL')
        self.events.append('provider')
        if not _boolean(p.provider_available, 'CACHE_PROVIDER_OUTCOME'):
            return False
        self.events.append('acquire_group')
        if _integer(p.acquire_status, -0x80000000, 0x7FFFFFFF, 'CACHE_ACQUIRE_STATUS') < 0:
            return False
        return _boolean(p.group_available, 'CACHE_GROUP_OUTCOME')

    def _read(self):
        group = self._group()
        if not group:
            return None, False
        self.events.append('fetch_blob')
        if self._blob is None:
            return None, True
        if type(self._blob) is not _OwnedBlob or self._blob.owner is not self:
            raise PrimarySemanticUnavailable('CACHE_VALUE_NOT_OWN_PRODUCED')
        p = self.protocol
        self.events.append('blob_flag')
        if _integer(p.blob_flag, 0, 0xFFFFFFFF, 'CACHE_BLOB_FLAG') != 0:
            return None, True
        self.events.append('read_ver')
        version = self._version if p.version_read is None else _integer(p.version_read, 0, 0xFFFFFFFF, 'CACHE_VERSION')
        if version != 2:
            return None, True
        self.events.append('blob_length')
        length = len(self._blob.raw) if p.length_read is None else _integer(p.length_read, 0, 0xFFFFFFFF, 'CACHE_LENGTH')
        if length != 16:
            return None, True
        if not _boolean(p.late_blob_present, 'CACHE_LATE_BLOB_OUTCOME'):
            raise PrimarySemanticUnavailable('CACHE_INVALID_PARAMETER_HANDLER_UNKNOWN')
        self.events.append('blob_data')
        if not _boolean(p.data_pointer_present, 'CACHE_DATA_POINTER_OUTCOME'):
            raise PrimarySemanticUnavailable('CACHE_INVALID_PARAMETER_HANDLER_UNKNOWN')
        return _bytes(self._blob.raw, 16, 'CACHE_OWN_BLOB_16'), True

    def _write(self, raw, group, capability):
        if capability is not _OWNED:
            raise InputError('CACHE_OWN_PRODUCER_REQUIRED')
        self.events.extend(('create_blob', 'set_blob_16'))
        if not group:
            return
        outcome = self.write_outcome
        if type(outcome) is not CacheWriteOutcome:
            raise InputError('CACHE_WRITE_OUTCOME')
        _integer(outcome.blob_status, -0x80000000, 0x7FFFFFFF, 'CACHE_BLOB_WRITE_STATUS')
        _integer(outcome.version_status, -0x80000000, 0x7FFFFFFF, 'CACHE_VERSION_WRITE_STATUS')
        _boolean(outcome.blob_applied, 'CACHE_BLOB_WRITE_EFFECT')
        _boolean(outcome.version_applied, 'CACHE_VERSION_WRITE_EFFECT')
        self.events.append('write_G3')
        if outcome.blob_applied:
            self._blob = _OwnedBlob(raw, self, _OWNED)
        self.events.append('write_ver_2')
        if outcome.version_applied:
            self._version = 2


class CommonG3Guid:
    def __init__(self, *, cache, primitives):
        self.cache, self.primitives = cache, primitives

    def invoke(self, memory, output):
        _integer(output, 0, 0xFFFFFFFFFFFFFFFF, 'COMMON_GUID_OUTPUT_POINTER')
        if output == 0:
            return 0
        if type(memory) is not PrimaryMemory:
            raise InputError('COMMON_GUID_OWN_MEMORY')
        if type(self.cache) is not OwnGuidCache:
            raise PrimarySemanticUnavailable('COMMON_GUID_CACHE_QUALIFICATION_UNKNOWN')
        cached, group = self.cache._read()
        if cached is not None:
            memory.write(output, cached, source='Common.__GetG3Guid.cache_copy_16')
            return 1
        primitives = self.primitives
        if type(primitives) is GuidPrimitiveSource:
            primitives = primitives.collect()
        if type(primitives) is not GuidPrimitives:
            raise PrimarySemanticUnavailable('COMMON_GUID_RAW_PRIMITIVES_UNAVAILABLE')
        digest = hashlib.md5()
        digest.update(disk_material(primitives.disk))
        digest.update(cpu_material(primitives.cpuid_leaves))
        digest.update(mac_material(primitives.network))
        raw = digest.digest()
        memory.write(output, raw, source='Common.__GetG3Guid.md5_final_16')
        self.cache._write(raw, group, _OWNED)
        return 1
