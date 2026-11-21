import ctypes
import _ctypes
import os
import sysconfig

from .errors import CapabilityUnavailable, InputError
from .primary_mac_selector import PartialSelectorRecord, StageResult
from .primary_vm import PrimarySemanticUnavailable


_MASK = (1 << 64) - 1


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('descriptor', ctypes.c_void_p), ('inherit', ctypes.c_int32)]


class _StartupInfo(ctypes.Structure):
    _fields_ = [('cb', ctypes.c_uint32), ('reserved', ctypes.c_void_p), ('desktop', ctypes.c_void_p),
        ('title', ctypes.c_void_p), ('x', ctypes.c_uint32), ('y', ctypes.c_uint32),
        ('xsize', ctypes.c_uint32), ('ysize', ctypes.c_uint32), ('xcount', ctypes.c_uint32),
        ('ycount', ctypes.c_uint32), ('fill', ctypes.c_uint32), ('flags', ctypes.c_uint32),
        ('show', ctypes.c_uint16), ('reserved2_size', ctypes.c_uint16), ('reserved2', ctypes.c_void_p),
        ('stdin', ctypes.c_void_p), ('stdout', ctypes.c_void_p), ('stderr', ctypes.c_void_p)]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [('process', ctypes.c_void_p), ('thread', ctypes.c_void_p),
        ('pid', ctypes.c_uint32), ('tid', ctypes.c_uint32)]


def _strtoul_pair(raw):
    if type(raw) is not bytes or len(raw) != 2:
        raise PrimarySemanticUnavailable('COMMON_COMMAND_SUBSTRING_DOMAIN')
    if any(value >= 128 for value in raw):
        raise PrimarySemanticUnavailable('COMMON_COMMAND_CRT_LOCALE_DOMAIN')
    raw = raw.split(b'\0', 1)[0].lstrip(b' \t\n\r\v\f')
    sign = -1 if raw[:1] == b'-' else 1
    if raw[:1] in (b'-', b'+'):
        raw = raw[1:]
    value = 0
    for byte in raw:
        if 48 <= byte <= 57:
            digit = byte - 48
        elif 65 <= byte <= 70:
            digit = byte - 55
        elif 97 <= byte <= 102:
            digit = byte - 87
        else:
            break
        value = value * 16 + digit
    return sign * value & 0xff


def parse_command_stdout(raw):
    if type(raw) is not bytes:
        raise InputError('COMMON_COMMAND_RAW_STDOUT')
    normalized, pending_cr = bytearray(), False
    for byte in raw:
        if byte == 13:
            pending_cr = True
        elif byte == 10:
            normalized.append(10)
            pending_cr = False
        else:
            if pending_cr:
                normalized.append(10)
                pending_cr = False
            normalized.append(byte)
    records, pending = [], b''
    for fragment in bytes(normalized).split(b'\n')[:-1]:
        line = fragment + b'\n'
        colon = line.find(b':')
        if colon <= 0:
            continue
        label = line[:colon + 1].split(b'\0', 1)[0]
        if b'\0' in line[:colon + 1] and ((not pending and b'Description' in label) or
                (pending and b'Physical Address' in label)):
            raise PrimarySemanticUnavailable('COMMON_COMMAND_SUBSTRING_DOMAIN')
        if not pending:
            if b'Description' in label:
                pending = line[colon + 1:]
            continue
        if b'Physical Address' not in label:
            continue
        address = line[colon + 1:]
        if b'\0' in address:
            raise PrimarySemanticUnavailable('COMMON_COMMAND_SUBSTRING_DOMAIN')
        hyphens, start = [], 0
        for index in range(5):
            found = address.find(b'-', start)
            if found < 0:
                break
            hyphens.append(found)
            start = found + 1
        if len(hyphens) != 5:
            pending = b''
            continue
        starts = (hyphens[0] - 2, hyphens[0] + 1, hyphens[1] + 1,
            hyphens[2] + 1, hyphens[3] + 1, hyphens[4] + 1)
        if any(index < 0 or index + 2 > len(address) for index in starts):
            raise PrimarySemanticUnavailable('COMMON_COMMAND_SUBSTRING_DOMAIN')
        record = bytearray(0x1c4)
        record[:6] = bytes(_strtoul_pair(address[index:index + 2]) for index in starts)
        description = pending[:128].split(b'\0', 1)[0]
        record[0x10c:0x10c + len(description)] = description
        records.append(PartialSelectorRecord(((0, bytes(record)),)))
        pending = b''
    return tuple(records)


class WindowsCommonFallbackAPI:
    def __init__(self):
        if os.name != 'nt' or sysconfig.get_platform() != 'win-amd64' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable('COMMON_WINDOWS_AMD64_REQUIRED')
        if (ctypes.sizeof(_SecurityAttributes), ctypes.sizeof(_StartupInfo), ctypes.sizeof(_ProcessInformation)) != (24, 104, 24):
            raise CapabilityUnavailable('COMMON_COMMAND_WIN64_ABI')
        self._libraries, self._functions = {}, {}
        self._handles, self._failed_closes = set(), set()
        self.closed = False

    def _function(self, library, name, result, arguments):
        if self.closed:
            raise InputError('COMMON_FALLBACK_API_CLOSED')
        if library not in self._libraries:
            self._libraries[library] = ctypes.WinDLL(library, use_last_error=True)
        if name not in self._functions:
            function = getattr(self._libraries[library], name)
            function.restype, function.argtypes = result, arguments
            self._functions[name] = function
        return self._functions[name]

    def _own(self, handle):
        value = int(handle or 0) & _MASK
        if value not in (0, _MASK):
            self._handles.add(value)
        return value

    def pipe(self):
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        read, write = p(), p()
        security = _SecurityAttributes(24, None, 1)
        function = self._function('kernel32', 'CreatePipe', i, (ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(_SecurityAttributes), u))
        success = function(ctypes.byref(read), ctypes.byref(write), ctypes.byref(security), 0)
        return bool(success), self._own(read.value), self._own(write.value)

    def duplicate(self, handle):
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        current = self._function('kernel32', 'GetCurrentProcess', p, ())()
        output = p()
        function = self._function('kernel32', 'DuplicateHandle', i, (p, p, p, ctypes.POINTER(p), u, i, u))
        success = function(current, handle, current, ctypes.byref(output), 0, 0, 2)
        return bool(success), self._own(output.value)

    def create_process(self, stdin, stdout):
        startup = _StartupInfo()
        startup.cb, startup.flags = 104, 0x101
        startup.stdin, startup.stdout, startup.stderr = stdin, stdout, stdout
        information = _ProcessInformation()
        command = ctypes.create_unicode_buffer('"ipconfig" /all')
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        function = self._function('kernel32', 'CreateProcessW', i,
            (p, p, p, p, i, u, p, p, ctypes.POINTER(_StartupInfo), ctypes.POINTER(_ProcessInformation)))
        success = function(None, command, None, None, 1, 0, None, None,
            ctypes.byref(startup), ctypes.byref(information))
        return bool(success), self._own(information.process), self._own(information.thread)

    def read(self, handle):
        output, count = ctypes.create_string_buffer(1024), ctypes.c_uint32()
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        function = self._function('kernel32', 'ReadFile', i, (p, p, u, ctypes.POINTER(u), p))
        success = function(handle, output, 1024, ctypes.byref(count), None)
        return bool(success), output.raw, count.value

    def close_handle(self, handle):
        if handle in (0, _MASK):
            return True
        if handle not in self._handles:
            raise InputError('COMMON_FALLBACK_HANDLE_NOT_OWNED')
        function = self._function('kernel32', 'CloseHandle', ctypes.c_int32, (ctypes.c_void_p,))
        self._handles.remove(handle)
        success = bool(function(handle))
        if not success:
            self._failed_closes.add(handle)
        return success

    def netbios(self, command, lana, size):
        ncb = ctypes.create_string_buffer(96)
        output = ctypes.create_string_buffer(size) if size else None
        ncb[0], ncb[64] = bytes((command,)), bytes((lana,))
        if output is not None:
            ctypes.c_uint64.from_buffer(ncb, 8).value = ctypes.addressof(output)
            ctypes.c_uint16.from_buffer(ncb, 16).value = size
        if command == 0x33:
            ncb[18] = b'*'
        function = self._function('netapi32', 'Netbios', ctypes.c_ubyte, (ctypes.c_void_p,))
        return int(function(ncb)), output.raw if output is not None else b''

    def close(self):
        if self.closed:
            return
        for handle in tuple(self._handles):
            self.close_handle(handle)
        if self._failed_closes:
            raise CapabilityUnavailable('COMMON_FALLBACK_CLOSE_FAILED')
        self._functions.clear()
        for library in self._libraries.values():
            _ctypes.FreeLibrary(library._handle)
        self._libraries.clear()
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()


def command_stage(api):
    success, stdout_read, stdout_write = api.pipe()
    if not success:
        return StageResult(0, ())
    success, parent_read = api.duplicate(stdout_read)
    if not success:
        return StageResult(0, ())
    api.close_handle(stdout_read)
    success, stdin_read, stdin_write = api.pipe()
    if not success:
        return StageResult(0, ())
    success, parent_write = api.duplicate(stdin_write)
    if not success:
        return StageResult(0, ())
    api.close_handle(stdin_write)
    success, process, thread = api.create_process(stdin_read, stdout_write)
    if not success:
        return StageResult(0, ())
    api.close_handle(process)
    api.close_handle(thread)
    if not api.close_handle(stdout_write):
        return StageResult(0, ())
    raw = bytearray()
    while True:
        success, buffer, count = api.read(parent_read)
        if not success or count == 0:
            break
        if type(buffer) is not bytes or len(buffer) != 1024 or type(count) is not int or not 0 <= count <= 1024:
            raise InputError('COMMON_COMMAND_READ_PRIMITIVES')
        if len(raw) + count > 1 << 20:
            raise PrimarySemanticUnavailable('COMMON_COMMAND_STDOUT_DOMAIN')
        raw.extend(buffer[:count])
    return StageResult(1, parse_command_stdout(bytes(raw)))


def netbios_stage(api):
    status, enumerated = api.netbios(0x37, 0, 256)
    if status:
        return StageResult(0, ())
    if type(enumerated) is not bytes or len(enumerated) != 256:
        raise InputError('COMMON_NETBIOS_ENUM_RAW_256')
    records = []
    for lana in enumerated[1:1 + enumerated[0]]:
        status, ignored = api.netbios(0x32, lana, 0)
        if status:
            continue
        status, output = api.netbios(0x33, lana, 600)
        if status:
            continue
        if type(output) is not bytes or len(output) != 600:
            raise InputError('COMMON_NETBIOS_ASTAT_RAW_600')
        record = bytearray(0x1c4)
        record[:6] = output[:6]
        records.append(PartialSelectorRecord(((0, bytes(record)),)))
    return StageResult(1, tuple(records))


def collect_windows_command_stage():
    with WindowsCommonFallbackAPI() as api:
        return command_stage(api)


def collect_windows_netbios_stage():
    with WindowsCommonFallbackAPI() as api:
        return netbios_stage(api)
