"""Thin source cold12 Windows inputs. Construction is explicit; imports do not query OS."""
import ctypes as C
import os
from threading import get_ident
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_memory import PrimaryMemory
from .primary_cocos import seed_mt, next_mt


class _Backend:
    def __init__(self):
        from .primary_windows_core_observations import WindowsCoreAPIBackend
        self.core = WindowsCoreAPIBackend()
        try:
            self.iphlpapi = C.WinDLL('iphlpapi', use_last_error=True)
            self.core.modules.append(self.iphlpapi)
        except BaseException:
            self.core.close()
            raise

    def call(self, name, result, arguments, values):
        library = self.iphlpapi if name == 'GetAdaptersAddresses' else self.core.modules[0]
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
        return function(*values)

    def entropy4(self):
        output = C.create_string_buffer(4)
        if not self.core.request('SystemFunction036', output, 4):
            raise PrimarySemanticUnavailable('source four-byte entropy request failed')
        return output.raw

    def close(self):
        self.core.close()


class WindowsCold12Inputs:
    def __init__(self, *, backend=None):
        self._owned = backend is None
        self.backend = _Backend() if backend is None else backend
        self._owner = os.getpid(), get_ident()
        self._closed = False
        self._padding = None
        self.records = []

    def _check(self):
        if self._closed or self._owner != (os.getpid(), get_ident()):
            raise InputError('cold12 Windows inputs require their open creator process/thread')

    def entropy4(self):
        self._check()
        raw = self.backend.entropy4()
        if type(raw) is not bytes or len(raw) != 4:
            raise InputError('source entropy requires exactly four successful bytes')
        return raw

    def padding_bytes(self, count):
        self._check()
        if type(count) is not int or not 3 <= count <= 10:
            raise InputError('source TEA random prefix count must be3..10')
        if self._padding is None:
            raw = self.entropy4()
            memory = PrimaryMemory()
            memory.map(0x1000, bytearray(0x9C8), name='own source padding MT', initialized=True)
            seed_mt(memory, 0x1000, int.from_bytes(raw, 'little'))
            self._padding = memory
        # uniform0..255 consumes one engine word per byte, never pooled word bytes.
        return bytes(next_mt(self._padding, 0x1000) & 255 for unused in range(count))

    def _version_gate(self):
        output = C.create_string_buffer(0x114)
        C.c_uint32.from_buffer(output).value = 0x114
        result = self.backend.call('GetVersionExW', C.c_int32, (C.c_void_p,), (output,))
        self.records.append(('GetVersionExW', result))
        major = C.c_uint32.from_buffer(output, 4).value
        minor = C.c_uint32.from_buffer(output, 8).value
        return major == 5 and minor != 0  # Source does not branch on API BOOL.

    @staticmethod
    def _read(buffer, pointer, size):
        start = C.addressof(buffer)
        if not start <= pointer <= start + C.sizeof(buffer) - size:
            raise PrimarySemanticUnavailable('GAA selected pointer lies outside its owned result buffer')
        return C.string_at(pointer, size)

    def _adapters(self, family):
        size = 0x3A98
        for attempt in range(2):
            if not 0 < size <= 1 << 20:
                raise PrimarySemanticUnavailable('source GAA allocation exceeds bounded input domain')
            output = C.create_string_buffer(size)
            required = C.c_uint32(size)
            status = self.backend.call('GetAdaptersAddresses', C.c_uint32,
                (C.c_uint32, C.c_uint32, C.c_void_p, C.c_void_p, C.POINTER(C.c_uint32)),
                (family, 0x80, None, output, C.byref(required)))
            self.records.append(('GetAdaptersAddresses', family, status))
            if status != 0x6F or attempt:
                break
            size = required.value
        if status:
            return False
        node = C.addressof(output)
        seen = set()
        found = False
        while node:
            if node in seen:
                raise PrimarySemanticUnavailable('GAA source node list is cyclic')
            seen.add(node)
            raw = self._read(output, node, 0xD8)
            selected = int.from_bytes(raw[0xD0:0xD8], 'little')
            if selected:
                entry = self._read(output, selected, 0x18)
                sockaddr = int.from_bytes(entry[0x10:0x18], 'little')
                observed_family = int.from_bytes(self._read(output, sockaddr, 2), 'little')
                if observed_family == family:
                    offset, count = (4, 4) if family == 2 else (8, 16)
                    address = self._read(output, sockaddr + offset, count)
                    # Selected valid binary sockaddr -> source format/parse always succeeds.
                    # IPv4 zero is accepted; IPv6 alone excludes the exact formatted '::'.
                    # This reduction is confined to the proven normal conversion domain.
                    if family == 2 or any(address):
                        found = True
            node = int.from_bytes(raw[8:16], 'little')
        return found

    def host_marker(self):
        self._check()
        first = True if self._version_gate() else self._adapters(2)
        second = False if self._version_gate() else self._adapters(23)
        return int(first) + 2 * int(second)

    def close(self):
        if not self._closed:
            self._check()
            if self._owned:
                self.backend.close()
            self._closed = True
