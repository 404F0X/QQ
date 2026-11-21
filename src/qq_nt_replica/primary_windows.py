import ctypes
import os
from ctypes import wintypes

from .errors import CapabilityUnavailable, InputError
from .primary_device import CapiObservation, DeviceEnvironmentObservations, DeviceObservations, DisplayObservation, RegistryValueObservation


_CPU_LEAVES = (0x80000002, 0x80000003, 0x80000004, 0x80000005, 0, 1, 2, 0x40000000)
_MACHINE_VALUES = ((b"SYSTEM\\CurrentControlSet\\iCafe8", b"Admin"),
                   (b"SOFTWARE\\EYOOCLIENTSTATUS", b"SuperLogin"),
                   (b"SYSTEM\\CurrentControlSet", b"superadmin"),
                   (b"SYSTEM\\nVos", b"SupperMode"))


def collect_device_observations(source, *, enumeration=None):
    native_fields = enumeration is not None and getattr(enumeration, 'raw_fields', False)
    fields = enumeration if native_fields else source
    system_material = None
    if native_fields:
        status, system_material = fields.system_information_material()
        information = None
    else:
        status, information = fields.system_information()
    cpuid = {leaf: fields.cpuid(leaf, 0) for leaf in _CPU_LEAVES}
    names, object_digest = (source.object_names(), None) if enumeration is None else enumeration.object_collection()
    serial = fields.volume_serial()
    uuid_tail = None
    if native_fields:
        uuid_status, uuid_tail = fields.uuid_tail()
        uuid_bytes = None
    else:
        uuid_status, uuid_bytes = fields.uuid()
    displays, display_digest = (source.displays(), None) if enumeration is None else enumeration.display_collection()
    return DeviceObservations(cpuid, status, information, serial, uuid_status, uuid_bytes, names, displays,
                              object_directory_digest=object_digest, display_digest=display_digest,
                              uuid_tail=uuid_tail, system_information_material=system_material)


def collect_device_environment(source, hypervisor_words):
    vendor = b"".join(value.to_bytes(4, "little") for value in hypervisor_words[1:])
    service, vmid, descriptor, disk = False, False, None, False
    values = [None] * 4

    def snapshot():
        return DeviceEnvironmentObservations(vendor, service, vmid, descriptor, tuple(values), disk)

    if vendor == b"Microsoft Hv":
        service = source.service_present()
        if not service:
            vmid = source.registry_value_exists(b"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
                                                b"VirtualMachineId")
            if vmid:
                return snapshot()
    if vendor in (b"VMwareVMware", b"VBoxVBoxVBox") or vendor[:8] == b"KVMKVMKV":
        return snapshot()
    descriptor = source.storage_descriptor()
    if descriptor is not None:
        offset = int.from_bytes(descriptor[16:20], "little")
        if offset < len(descriptor) and b"virtio" in descriptor[offset:].split(b"\0", 1)[0].lower():
            return snapshot()
    if vendor in (b"XenVMMXenVMM", b"Parallels Hv") or vendor[:8] == b"prl hype":
        return snapshot()
    for index, (key, name) in enumerate(_MACHINE_VALUES):
        values[index] = source.registry_value(key, name)
        value = values[index]
        if value.open_status == 0 and value.query_status == 0 and value.data[:4] == bytes(4):
            return snapshot()
    disk = source.registry_key_exists(b"SYSTEM\\CurrentControlSet\\Enum\\vDisk\\Disk0")
    return snapshot()


class _UnicodeString(ctypes.Structure):
    _fields_ = (("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", ctypes.c_void_p))


class _ObjectAttributes(ctypes.Structure):
    _fields_ = (("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
               ("ObjectName", ctypes.POINTER(_UnicodeString)), ("Attributes", wintypes.ULONG),
               ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p))


class _DisplayDevice(ctypes.Structure):
    _fields_ = (("cb", wintypes.DWORD), ("DeviceName", wintypes.WCHAR * 32),
               ("DeviceString", wintypes.WCHAR * 128), ("StateFlags", wintypes.DWORD),
               ("DeviceID", wintypes.WCHAR * 128), ("DeviceKey", wintypes.WCHAR * 128))


class _VersionInfo(ctypes.Structure):
    _fields_ = (("size", wintypes.DWORD), ("major", wintypes.DWORD), ("minor", wintypes.DWORD),
               ("build", wintypes.DWORD), ("platform", wintypes.DWORD), ("service_pack", wintypes.WCHAR * 128),
               ("service_major", wintypes.WORD), ("service_minor", wintypes.WORD), ("suite", wintypes.WORD),
               ("product", wintypes.BYTE), ("reserved", wintypes.BYTE))


class _Blob(ctypes.Structure):
    _fields_ = (("size", wintypes.DWORD), ("data", ctypes.c_void_p))


class _Algorithm(ctypes.Structure):
    _fields_ = (("oid", ctypes.c_void_p), ("parameters", _Blob))


class _BitBlob(ctypes.Structure):
    _fields_ = (("size", wintypes.DWORD), ("data", ctypes.c_void_p), ("unused", wintypes.DWORD))


class _PublicKeyInfo(ctypes.Structure):
    _fields_ = (("algorithm", _Algorithm), ("key", _BitBlob))


class WindowsDeviceSource:
    def __init__(self, *, uuid_observation=None):
        if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable("Windows x64 device observation APIs are required")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.nt = ctypes.WinDLL("ntdll")
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.rpc = ctypes.WinDLL("rpcrt4")
        self.shell = ctypes.WinDLL("shell32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.crypt = ctypes.WinDLL("crypt32", use_last_error=True)
        self.uuid_observation = uuid_observation
        self._code = None
        self._configure()

    @staticmethod
    def _bind(library, name, result, arguments):
        function = getattr(library, name)
        function.restype = result
        function.argtypes = arguments
        return function

    def _configure(self):
        pointer = ctypes.c_void_p
        dword_pointer = ctypes.POINTER(wintypes.DWORD)
        self._alloc = self._bind(self.kernel, "VirtualAlloc", pointer,
                                 (pointer, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD))
        self._protect = self._bind(self.kernel, "VirtualProtect", wintypes.BOOL,
                                   (pointer, ctypes.c_size_t, wintypes.DWORD, dword_pointer))
        self._free = self._bind(self.kernel, "VirtualFree", wintypes.BOOL,
                                (pointer, ctypes.c_size_t, wintypes.DWORD))
        self._flush = self._bind(self.kernel, "FlushInstructionCache", wintypes.BOOL,
                                 (wintypes.HANDLE, pointer, ctypes.c_size_t))
        self._close = self._bind(self.kernel, "CloseHandle", wintypes.BOOL, (wintypes.HANDLE,))
        self._system = self._bind(self.nt, "NtQuerySystemInformation", ctypes.c_long,
                                  (wintypes.ULONG, pointer, wintypes.ULONG, pointer))
        self._open_directory = self._bind(self.nt, "NtOpenDirectoryObject", ctypes.c_long,
                                          (ctypes.POINTER(wintypes.HANDLE), wintypes.ULONG,
                                           ctypes.POINTER(_ObjectAttributes)))
        self._query_directory = self._bind(self.nt, "NtQueryDirectoryObject", ctypes.c_long,
                                           (wintypes.HANDLE, pointer, wintypes.ULONG, ctypes.c_ubyte,
                                            ctypes.c_ubyte, ctypes.POINTER(wintypes.ULONG), pointer))
        self._volume = self._bind(self.kernel, "GetVolumeInformationW", wintypes.BOOL,
                                  (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, dword_pointer,
                                   dword_pointer, dword_pointer, wintypes.LPWSTR, wintypes.DWORD))
        self._uuid = self._bind(self.rpc, "UuidCreateSequential", wintypes.DWORD, (pointer,))
        self._display = self._bind(self.user, "EnumDisplayDevicesW", wintypes.BOOL,
                                   (wintypes.LPCWSTR, wintypes.DWORD,
                                    ctypes.POINTER(_DisplayDevice), wintypes.DWORD))
        self._appdata = self._bind(self.shell, "SHGetSpecialFolderPathA", wintypes.BOOL,
                                   (wintypes.HWND, pointer, ctypes.c_int, wintypes.BOOL))
        self._create_file = self._bind(self.kernel, "CreateFileA", wintypes.HANDLE,
                                       (wintypes.LPCSTR, wintypes.DWORD, wintypes.DWORD, pointer,
                                        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE))
        self._ioctl = self._bind(self.kernel, "DeviceIoControl", wintypes.BOOL,
                                 (wintypes.HANDLE, wintypes.DWORD, pointer, wintypes.DWORD,
                                  pointer, wintypes.DWORD, dword_pointer, pointer))
        self._manager = self._bind(self.advapi, "OpenSCManagerW", wintypes.HANDLE,
                                   (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD))
        self._service = self._bind(self.advapi, "OpenServiceA", wintypes.HANDLE,
                                   (wintypes.HANDLE, wintypes.LPCSTR, wintypes.DWORD))
        self._close_service = self._bind(self.advapi, "CloseServiceHandle", wintypes.BOOL, (wintypes.HANDLE,))
        self._reg_open = self._bind(self.advapi, "RegOpenKeyExA", wintypes.LONG,
                                    (wintypes.HANDLE, wintypes.LPCSTR, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.HANDLE)))
        self._reg_query = self._bind(self.advapi, "RegQueryValueExA", wintypes.LONG,
                                     (wintypes.HANDLE, wintypes.LPCSTR, pointer,
                                      dword_pointer, pointer, dword_pointer))
        self._reg_close = self._bind(self.advapi, "RegCloseKey", wintypes.LONG, (wintypes.HANDLE,))
        self._condition = self._bind(self.kernel, "VerSetConditionMask", ctypes.c_uint64,
                                     (ctypes.c_uint64, wintypes.DWORD, wintypes.BYTE))
        self._verify = self._bind(self.kernel, "VerifyVersionInfoW", wintypes.BOOL,
                                  (ctypes.POINTER(_VersionInfo), wintypes.DWORD, ctypes.c_uint64))
        self._acquire = self._bind(self.advapi, "CryptAcquireContextA", wintypes.BOOL,
                                   (ctypes.POINTER(wintypes.HANDLE), wintypes.LPCSTR, wintypes.LPCSTR,
                                    wintypes.DWORD, wintypes.DWORD))
        self._user_key = self._bind(self.advapi, "CryptGetUserKey", wintypes.BOOL,
                                    (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)))
        self._export = self._bind(self.crypt, "CryptExportPublicKeyInfo", wintypes.BOOL,
                                  (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, pointer, dword_pointer))
        self._create_hash = self._bind(self.advapi, "CryptCreateHash", wintypes.BOOL,
                                       (wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE,
                                        wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)))
        self._hash_data = self._bind(self.advapi, "CryptHashData", wintypes.BOOL,
                                     (wintypes.HANDLE, pointer, wintypes.DWORD, wintypes.DWORD))
        self._hash_param = self._bind(self.advapi, "CryptGetHashParam", wintypes.BOOL,
                                      (wintypes.HANDLE, wintypes.DWORD, pointer, dword_pointer, wintypes.DWORD))
        self._destroy_key = self._bind(self.advapi, "CryptDestroyKey", wintypes.BOOL, (wintypes.HANDLE,))
        self._destroy_hash = self._bind(self.advapi, "CryptDestroyHash", wintypes.BOOL, (wintypes.HANDLE,))
        self._release_crypto = self._bind(self.advapi, "CryptReleaseContext", wintypes.BOOL,
                                          (wintypes.HANDLE, wintypes.DWORD))

    def cpuid(self, leaf, subleaf=0):
        if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in (leaf, subleaf)):
            raise InputError("CPUID inputs must be unsigned DWORDs")
        if self._code is None:
            machine = bytes.fromhex("5389c889d10fa241890041895804418948084189500c5bc3")
            address = self._alloc(None, len(machine), 0x3000, 4)
            if not address:
                raise ctypes.WinError(ctypes.get_last_error())
            ctypes.memmove(address, machine, len(machine))
            previous = wintypes.DWORD()
            if not self._protect(address, len(machine), 0x20, ctypes.byref(previous)):
                error = ctypes.get_last_error()
                self._free(address, 0, 0x8000)
                raise ctypes.WinError(error)
            if not self._flush(wintypes.HANDLE(-1), address, len(machine)):
                error = ctypes.get_last_error()
                self._free(address, 0, 0x8000)
                raise ctypes.WinError(error)
            self._code = address
            self._cpu = ctypes.WINFUNCTYPE(None, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD))(address)
        words = (wintypes.DWORD * 4)()
        self._cpu(leaf, subleaf, words)
        return tuple(words)

    def system_information(self):
        output = ctypes.create_string_buffer(12)
        status = self._system(1, output, 12, None)
        return status, output.raw if status == 0 else None

    def object_names(self):
        path = ctypes.create_unicode_buffer("\\GLOBAL??")
        name = _UnicodeString(len(path.value) * 2, ctypes.sizeof(path), ctypes.addressof(path))
        attributes = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes), None,
                                       ctypes.pointer(name), 0x40, None, None)
        handle = wintypes.HANDLE()
        if self._open_directory(ctypes.byref(handle), 1, ctypes.byref(attributes)) != 0:
            return None
        result, context = [], wintypes.ULONG()
        try:
            for index in range(65536):
                output = ctypes.create_string_buffer(65536)
                status = self._query_directory(handle, output, len(output), 1, int(index == 0),
                                                ctypes.byref(context), None)
                if status & 0xFFFFFFFF == 0x8000001A:
                    return tuple(result)
                if status != 0:
                    return None
                item = _UnicodeString.from_buffer(output)
                if item.Length % 2 or item.Length > item.MaximumLength or not item.Buffer:
                    raise InputError("native directory returned an invalid UTF16 observation")
                result.append(ctypes.string_at(item.Buffer, item.Length).decode("utf-16le", "surrogatepass"))
            raise CapabilityUnavailable("native object directory exceeded the bounded observation limit")
        finally:
            self._close(handle)

    def volume_serial(self):
        serial = wintypes.DWORD()
        return serial.value if self._volume("C:\\", None, 0, ctypes.byref(serial), None, None, None, 0) else None

    def uuid(self):
        if self.uuid_observation is not None:
            return self.uuid_observation
        value = ctypes.create_string_buffer(16)
        status = self._uuid(value)
        return status, value.raw

    def displays(self):
        result = []
        for index in range(4096):
            primary = _DisplayDevice()
            primary.cb = ctypes.sizeof(primary)
            if not self._display(None, index, ctypes.byref(primary), 0):
                return tuple(result)
            for child_index in range(4096):
                child = _DisplayDevice()
                child.cb = ctypes.sizeof(child)
                if not self._display(primary.DeviceName, child_index, ctypes.byref(child), 0):
                    break
                result.append(DisplayObservation(child.DeviceID, child.StateFlags))
            else:
                raise CapabilityUnavailable("native display children exceeded the bounded observation limit")
        raise CapabilityUnavailable("native display enumeration exceeded the bounded observation limit")

    def common_appdata(self):
        output = ctypes.create_string_buffer(260)
        if not self._appdata(None, output, 35, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        return os.fsdecode(output.value)

    def service_present(self):
        manager = self._manager(None, None, 4)
        if not manager:
            return False
        try:
            service = self._service(manager, b"vmbusr", 4)
            if not service:
                return False
            self._close_service(service)
            return True
        finally:
            self._close_service(manager)

    def storage_descriptor(self):
        handle = self._create_file(b"\\\\.\\PhysicalDrive0", 0x100080, 1, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            return None
        try:
            query, output, size = ctypes.create_string_buffer(12), ctypes.create_string_buffer(4096), wintypes.DWORD()
            success = self._ioctl(handle, 0x2D1400, query, 12, output, 4096, ctypes.byref(size), None)
            return output.raw[:size.value] if success and 40 <= size.value <= 4096 else None
        finally:
            self._close(handle)

    def _registry_open(self, key):
        handle = wintypes.HANDLE()
        status = self._reg_open(wintypes.HANDLE(0xFFFFFFFF80000002), key, 0, 0x20119, ctypes.byref(handle))
        return status, handle

    def registry_key_exists(self, key):
        status, handle = self._registry_open(key)
        self._reg_close(handle)
        return status == 0

    def registry_value_exists(self, key, name):
        status, handle = self._registry_open(key)
        if status != 0:
            return False
        try:
            return self._reg_query(handle, name, None, None, None, None) == 0
        finally:
            self._reg_close(handle)

    def registry_value(self, key, name):
        status, handle = self._registry_open(key)
        data, size, value_type = ctypes.create_string_buffer(8), wintypes.DWORD(8), wintypes.DWORD()
        if status != 0:
            return RegistryValueObservation(status, None, 0, data.raw, size.value)
        try:
            queried = self._reg_query(handle, name, None, ctypes.byref(value_type), data, ctypes.byref(size))
            return RegistryValueObservation(status, queried, value_type.value, data.raw, size.value)
        finally:
            self._reg_close(handle)

    def capi_public_key(self):
        version = _VersionInfo()
        version.size, version.major, version.minor = 284, 5, 1
        mask = self._condition(self._condition(0, 2, 3), 1, 3)
        if not self._verify(ctypes.byref(version), 3, mask):
            return CapiObservation(None, 2, ctypes.get_last_error())
        provider, key, digest = wintypes.HANDLE(), wintypes.HANDLE(), wintypes.HANDLE()

        def failure(code):
            return CapiObservation(None, code, ctypes.get_last_error())

        try:
            if not self._acquire(ctypes.byref(provider), b"mWOLCtkGwuHtk", None, 0x18, 0x60):
                return failure(3)
            if not self._user_key(provider, 2, ctypes.byref(key)):
                return failure(9)
            size = wintypes.DWORD()
            if not self._export(provider, 2, 0x10001, None, ctypes.byref(size)):
                return failure(0xA)
            if size.value < ctypes.sizeof(_PublicKeyInfo) or size.value > 1024 * 1024:
                raise CapabilityUnavailable("exported public key structure exceeds the bounded normal observation domain")
            exported = ctypes.create_string_buffer(size.value)
            if not self._export(provider, 2, 0x10001, exported, ctypes.byref(size)):
                return failure(0xA)
            info = _PublicKeyInfo.from_buffer(exported)
            start, end = ctypes.addressof(exported), ctypes.addressof(exported) + len(exported)
            if info.key.size and (not info.key.data or info.key.data < start or info.key.data + info.key.size > end):
                raise InputError("exported public key bits are outside their returned source buffer")
            bits = ctypes.string_at(info.key.data, info.key.size) if info.key.size else b""
            self._destroy_key(key)
            key = wintypes.HANDLE()
            if not self._create_hash(provider, 0x800C, None, 0, ctypes.byref(digest)):
                return failure(0xB)
            data = ctypes.create_string_buffer(bits)
            if not self._hash_data(digest, data, len(bits), 0):
                return failure(0xC)
            value, size = ctypes.create_string_buffer(32), wintypes.DWORD(32)
            if not self._hash_param(digest, 2, value, ctypes.byref(size), 0) or size.value != 32:
                return failure(0xD)
            return CapiObservation(bits, 0)
        finally:
            if key.value:
                self._destroy_key(key)
            if digest.value:
                self._destroy_hash(digest)
            if provider.value:
                self._release_crypto(provider, 0)

    def close(self):
        if self._code is not None:
            address, self._code = self._code, None
            del self._cpu
            if not self._free(address, 0, 0x8000):
                raise ctypes.WinError(ctypes.get_last_error())

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.close()
