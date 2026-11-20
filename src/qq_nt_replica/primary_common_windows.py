import ctypes
import os
import sysconfig
from dataclasses import dataclass, field
from functools import partial

from .errors import CapabilityUnavailable, InputError
from .primary_common_guid import CommonG3Guid, DiskPrimitives, GuidPrimitives, GuidPrimitiveSource, OwnGuidCache
from .primary_mac_selector import MacSelector, OwnSelectorCache, PartialSelectorRecord, ProcessedStages, PrimitiveTicks, SelectorNetwork, StageResult, StageSource
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows import WindowsDeviceSource
from .primary_windows_device_hardware import _AdapterInfo, _IPAddrString


_MASK = (1 << 64) - 1
_LIMIT = 1 << 20


@dataclass(frozen=True)
class AdapterInfoPrimitives:
    probe_status: int
    requested: int
    fill_status: int | None = None
    returned: int | None = None
    buffer: bytes | None = field(default=None, repr=False)
    address: int | None = field(default=None, repr=False)


class WindowsCommonAPI:
    def __init__(self):
        if os.name != 'nt' or sysconfig.get_platform() != 'win-amd64' or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_wchar) != 2:
            raise CapabilityUnavailable('COMMON_WINDOWS_AMD64_REQUIRED')
        if (ctypes.sizeof(_IPAddrString), ctypes.sizeof(_AdapterInfo), _AdapterInfo.address.offset,
                _AdapterInfo.description.offset, _AdapterInfo.ip.offset, _AdapterInfo.type.offset) != (48, 704, 0x198, 0x110, 0x1b8, 0x1a4):
            raise CapabilityUnavailable('COMMON_ADAPTER_ABI_REQUIRED')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        bind = WindowsDeviceSource._bind
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        self._directory = bind(self.kernel, 'GetWindowsDirectoryW', u, (p, u))
        self._open = bind(self.kernel, 'CreateFileW', p, (ctypes.c_wchar_p, u, u, p, u, u, p))
        self._ioctl = bind(self.kernel, 'DeviceIoControl', i, (p, u, p, u, p, u, ctypes.POINTER(u), p))
        self._close = bind(self.kernel, 'CloseHandle', i, (p,))
        self._handles = set()
        self.closed = False
        self.close_failures = 0

    def _check(self):
        if self.closed:
            raise InputError('COMMON_COLLECTOR_CLOSED')

    def windows_directory(self):
        self._check()
        output = ctypes.create_string_buffer(522)
        result = self._directory(output, 260)
        return int(result), output.raw

    def open_file(self, path):
        self._check()
        handle = int(self._open(path, 0, 3, None, 3, 0, None) or 0) & _MASK
        if handle not in (0, _MASK):
            self._handles.add(handle)
        return handle

    def ioctl(self, handle, code, query, capacity):
        self._check()
        output, returned = ctypes.create_string_buffer(capacity), ctypes.c_uint32()
        argument = ctypes.create_string_buffer(query, len(query)) if query is not None else None
        result = self._ioctl(handle, code, argument, len(query) if query is not None else 0,
            output, capacity, ctypes.byref(returned), None)
        return bool(result), output.raw, returned.value

    def close_handle(self, handle):
        self._check()
        if handle not in self._handles and handle != 0:
            raise InputError('COMMON_HANDLE_NOT_OWNED')
        self._handles.discard(handle)
        if not self._close(handle):
            self.close_failures += 1
            raise CapabilityUnavailable('COMMON_CLOSE_HANDLE_FAILED')

    def brand_leaves(self):
        self._check()
        with WindowsDeviceSource() as source:
            return tuple(source.cpuid(leaf, 0) for leaf in (0x80000002, 0x80000003, 0x80000004))

    def adapter_info(self):
        self._check()
        library = ctypes.WinDLL('iphlpapi', use_last_error=True)
        function = WindowsDeviceSource._bind(library, 'GetAdaptersInfo', ctypes.c_uint32,
            (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)))
        size = ctypes.c_uint32()
        probe = int(function(None, ctypes.byref(size)))
        requested = size.value
        if probe != 111:
            return AdapterInfoPrimitives(probe, requested)
        if not 704 <= requested <= _LIMIT - 0x580:
            raise PrimarySemanticUnavailable('COMMON_ADAPTER_ALLOCATION_DOMAIN')
        output = ctypes.create_string_buffer(requested + 0x580)
        status = int(function(output, ctypes.byref(size)))
        return AdapterInfoPrimitives(probe, requested, status, size.value,
            output.raw if status == 0 else None, ctypes.addressof(output) if status == 0 else None)

    def close(self):
        if self.closed:
            return
        errors = []
        for handle in tuple(self._handles):
            try:
                self.close_handle(handle)
            except Exception as error:
                errors.append(error)
        self.closed = True
        if errors:
            raise CapabilityUnavailable('COMMON_HANDLE_CLEANUP_FAILED') from None

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, kind, value, traceback):
        self.close()


def collect_disk_primitives(api):
    result, directory = api.windows_directory()
    if type(result) is not int or not 0 <= result <= 0xffffffff or type(directory) is not bytes or len(directory) != 522:
        raise PrimarySemanticUnavailable('COMMON_WINDOWS_DIRECTORY_DOMAIN')
    end = next((offset // 2 for offset in range(0, 522, 2) if directory[offset:offset + 2] == b'\0\0'), None)
    if end is None:
        raise PrimarySemanticUnavailable('COMMON_WINDOWS_DIRECTORY_DOMAIN')
    values = {'directory_result': result, 'directory_buffer': directory}
    number = -1
    if end > 1:
        try:
            drive = directory[:4].decode('utf-16le')
        except UnicodeError:
            raise PrimarySemanticUnavailable('COMMON_WINDOWS_DIRECTORY_DOMAIN') from None
        volume = api.open_file('\\\\.\\' + drive)
        values['volume_opened'] = volume != _MASK
        if values['volume_opened']:
            try:
                success, buffer, returned = api.ioctl(volume, 0x2d1080, None, 12)
                values.update(device_number_success=success, device_number_buffer=buffer, device_number_returned=returned)
                if type(buffer) is not bytes or len(buffer) != 12:
                    raise InputError('COMMON_DEVICE_NUMBER_RAW_12')
                number = int.from_bytes(buffer[4:8], 'little', signed=True)
            finally:
                api.close_handle(volume)
    index = max(number, 0)
    values['physical_drive_index'] = index
    physical = api.open_file('\\\\.\\PhysicalDrive' + str(index))
    values['physical_opened'] = physical not in (0, _MASK)
    if values['physical_opened']:
        try:
            success, buffer, returned = api.ioctl(physical, 0x2d1400, bytes(12), 1024)
            values.update(descriptor_success=success, descriptor_buffer=buffer, descriptor_returned=returned)
        finally:
            api.close_handle(physical)
    return DiskPrimitives(**values)


def adapter_stage(raw):
    if type(raw) is not AdapterInfoPrimitives:
        raise InputError('COMMON_ADAPTER_RAW_PRIMITIVES')
    if raw.probe_status != 111 or raw.fill_status != 0:
        return StageResult(0, ())
    data, base = raw.buffer, raw.address
    if type(data) is not bytes or type(base) is not int or not 0 < base < 1 << 64 or not 704 <= len(data) <= _LIMIT:
        raise PrimarySemanticUnavailable('COMMON_ADAPTER_BUFFER_DOMAIN')

    def span(pointer, size):
        offset = pointer - base
        if not 0 <= offset <= len(data) - size:
            raise PrimarySemanticUnavailable('COMMON_ADAPTER_POINTER_DOMAIN')
        return offset

    def pointer(offset):
        return int.from_bytes(data[offset:offset + 8], 'little')

    def text(offset, size):
        end = data.find(b'\0', offset, offset + size)
        if end < 0:
            raise PrimarySemanticUnavailable('COMMON_ADAPTER_TEXT_DOMAIN')
        return data[offset:end]

    current, seen, records = base, set(), []
    while current:
        if current in seen or len(seen) >= 256:
            raise PrimarySemanticUnavailable('COMMON_ADAPTER_CHAIN_DOMAIN')
        seen.add(current)
        offset = span(current, 704)
        name, description = text(offset + 0xc, 260), text(offset + 0x110, 132)
        length = int.from_bytes(data[offset + 0x194:offset + 0x198], 'little', signed=True)
        if length > 8:
            raise PrimarySemanticUnavailable('COMMON_ADAPTER_ADDRESS_DOMAIN')
        node, nodes = current + 0x1b8, set()
        while node:
            if node in nodes or len(nodes) >= 256:
                raise PrimarySemanticUnavailable('COMMON_ADAPTER_IP_CHAIN_DOMAIN')
            nodes.add(node)
            position = span(node, 48)
            text(position + 8, 16)
            record = bytearray(0x190)
            record[8:8 + min(len(name), 256)] = name[:256]
            record[0x10c:0x10c + min(len(description), 128)] = description[:128]
            if length > 0:
                record[:length] = data[offset + 0x198:offset + 0x198 + length]
            kind = data[offset + 0x1a4:offset + 0x1a8]
            records.append(PartialSelectorRecord(((0, bytes(record)), (0x1c0, kind))))
            node = pointer(position)
        current = pointer(offset)
    return StageResult(1, tuple(records))


def _collect_windows_primary():
    with WindowsCommonAPI() as api:
        return adapter_stage(api.adapter_info())


def _read_windows_tick():
    if os.name != 'nt':
        raise CapabilityUnavailable('COMMON_WINDOWS_AMD64_REQUIRED')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    return int(WindowsDeviceSource._bind(kernel, 'GetTickCount', ctypes.c_uint32, ())())


def collect_windows_common_primitives(*, selector_cache=None, full_fallbacks=False):
    if type(full_fallbacks) is not bool:
        raise InputError('COMMON_FULL_FALLBACKS_OPT_IN')
    cache = OwnSelectorCache() if selector_cache is None else selector_cache
    selector = MacSelector(cache=cache)
    with WindowsCommonAPI() as api:
        disk = collect_disk_primitives(api)
        leaves = api.brand_leaves()
    command, netbios = None, None
    if full_fallbacks:
        from .primary_common_fallbacks import collect_windows_command_stage, collect_windows_netbios_stage
        command = StageSource(collect_windows_command_stage)
        netbios = StageSource(collect_windows_netbios_stage)
    network = SelectorNetwork(selector,
        ProcessedStages(StageSource(_collect_windows_primary), command, netbios),
        PrimitiveTicks((), reader=_read_windows_tick))
    return GuidPrimitives(disk, leaves, network)


def collect_windows_common_guid(*, cache=None, selector_cache=None, full_fallbacks=False):
    if type(full_fallbacks) is not bool:
        raise InputError('COMMON_FULL_FALLBACKS_OPT_IN')
    owned = OwnGuidCache() if cache is None else cache
    if type(owned) is not OwnGuidCache:
        raise InputError('COMMON_GUID_OWN_CACHE')
    selection = OwnSelectorCache() if selector_cache is None else selector_cache
    if type(selection) is not OwnSelectorCache:
        raise InputError('MAC_OWN_CACHE')
    return CommonG3Guid(cache=owned, primitives=GuidPrimitiveSource(
        partial(collect_windows_common_primitives, selector_cache=selection, full_fallbacks=full_fallbacks)))
