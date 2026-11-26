"""Finite cold Source hardware branch, fixed C table; CPU source is borrowed."""
import os
import threading

from .primary_device_hardware import AdapterBufferEffect
from .primary_qimei_request import QimeiRequestBoundary
from .primary_qimei_fresh_identity import source_cpu_string


def source_disk_string(raw, written):
    if type(raw) is not bytes or len(raw) != 1024 or not 20 <= written <= 1024:
        raise QimeiRequestBoundary('disk descriptor written bounds unknown')
    offset = int.from_bytes(raw[16:20], 'little')
    if offset >= written:
        raise QimeiRequestBoundary('disk descriptor offset outside written bytes')
    first = raw[offset]
    if first >= 128:
        raise QimeiRequestBoundary('Source signed-char locale branch unsupported')
    # 3E95AA0 fixed C WORD table & 0x107, not Unicode isalnum/isprint.
    if not (48 <= first <= 57 or 65 <= first <= 90 or 97 <= first <= 122):
        return b' '
    end = raw.find(b'\0', offset, written)
    if end < 0:
        raise QimeiRequestBoundary('disk CString terminator outside written bytes')
    return raw[offset:end]


def source_adapter_string(effect):
    if not isinstance(effect, AdapterBufferEffect):
        raise QimeiRequestBoundary('raw adapter effect required')
    raw, known = effect.raw, effect.known
    def read(offset, size):
        if not 0 <= offset <= len(raw) - size or len(known) != len(raw) or known[offset:offset+size] != b'\1' * size:
            raise QimeiRequestBoundary('adapter bytes not API-written')
        return raw[offset:offset+size]
    def text(offset, maximum):
        for i in range(maximum):
            if read(offset+i, 1) == b'\0':
                return
        raise QimeiRequestBoundary('adapter CString lacks bounded terminator')
    if not raw:
        raise QimeiRequestBoundary('empty adapter branch requires unsupported backup')
    # First OS adapter has an embedded first IP node at +0x1B8. The Source
    # appends each node without filtering/sorting, so later nodes cannot win.
    text(12, 260)
    text(272, 132)
    text(448, 16)
    count = int.from_bytes(read(404, 4), 'little')
    if count > 8:
        raise QimeiRequestBoundary('adapter address exceeds Source raw8 domain')
    return (read(408, count) + bytes(8-count)).hex().encode('ascii')



class WindowsFreshIdentityHardware:
    def __init__(self, cpu_source, *, api=None):
        self.cpu_source = cpu_source
        self.api = api
        self._owner = os.getpid(), threading.get_native_id()
        self.closed = False
        self._result = None
        self.failure = None

    def _check(self):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise QimeiRequestBoundary('hardware requires open creator process/thread')

    def strings(self):
        self._check()
        if self.failure is not None:
            raise QimeiRequestBoundary('first hardware attempt failed') from self.failure
        if self._result is not None:
            return self._result
        try:
            if self.api is None:
                from .primary_windows_device_hardware import WindowsDeviceHardwareAPIBackend
                self.api = WindowsDeviceHardwareAPIBackend()
            request = self.api.request
            request('GetWindowsDirectoryA', (260,))
            # C6811B cold empty String length<2 -> -1, C67EC0 clamps to disk0.
            handle, _, _ = request('CreateFileA', (b'\\\\.\\PhysicalDrive0', 0, 3, 0, 3, 0, 0))
            disk = b' '
            if handle not in (0, (1 << 64)-1):
                try:
                    ok, effect, _ = request('DeviceIoControl', (handle, 0x2d1400, bytes(12)))
                    if ok:
                        disk = source_disk_string(*effect)
                finally:
                    ok, _, _ = request('CloseHandle', (handle,))
                    if not ok:
                        raise QimeiRequestBoundary('disk CloseHandle failed')
            cpu = source_cpu_string(tuple(self.cpu_source.cpuid(leaf, 0) for leaf in (0x80000002, 0x80000003, 0x80000004)))
            module, _, _ = request('LoadLibraryA', (b'iphlpapi.dll',))
            if not module:
                raise QimeiRequestBoundary('adapter module load failed')
            try:
                target, _, _ = request('GetProcAddress', (module, b'GetAdaptersInfo'))
                if not target:
                    raise QimeiRequestBoundary('GetAdaptersInfo unavailable')
                status, (_, size), _ = request('GetAdaptersInfo', (target, False, 0))
                if status != 111 or not 704 <= size <= 1 << 20:
                    raise QimeiRequestBoundary('unsupported first adapter status/size')
                status, (effect, written), _ = request('GetAdaptersInfo', (target, True, size))
                if status != 0 or not 704 <= written <= size or len(effect.raw) != written:
                    raise QimeiRequestBoundary('unsupported second adapter status/bounds')
                third = source_adapter_string(effect)
            finally:
                ok, _, _ = request('FreeLibrary', (module,))
                if not ok:
                    raise QimeiRequestBoundary('adapter FreeLibrary failed')
            self._result = disk, cpu, third
            return self._result
        except Exception as error:
            self.failure = error
            raise

    def close(self):
        if self.closed:
            return
        self._check()
        if self.api is not None:
            self.api.close()
        self.closed = True
