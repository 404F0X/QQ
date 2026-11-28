import ctypes
import os
import threading

from .errors import CapabilityUnavailable, InputError
from .primary_device_hypervisor import _IMPORTS, _MACHINE_VALUES
from .primary_vm import PrimarySemanticUnavailable


_MASK = (1 << 64) - 1
_KEYS = {key for key, value in _MACHINE_VALUES} | {
    b'SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters',
    b'SYSTEM\\CurrentControlSet\\Enum\\vDisk\\Disk0'}
_VALUES = {value for key, value in _MACHINE_VALUES} | {b'VirtualMachineId'}


class WindowsHypervisorBackend:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable('raw device classification requires Windows x64')
        self.libraries = {}
        self.closed = False

    def call(self, name, arguments):
        if self.closed:
            raise CapabilityUnavailable('raw device classification backend is closed')
        library = 'kernel32' if name in ('CreateFileA', 'DeviceIoControl', 'CloseHandle') else 'advapi32'
        if library not in self.libraries:
            self.libraries[library] = ctypes.WinDLL(library, use_last_error=True)
        function = getattr(self.libraries[library], name)
        signatures = {
            'OpenSCManagerW': (ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)),
            'OpenServiceA': (ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)),
            'CloseServiceHandle': (ctypes.c_int32, (ctypes.c_void_p,)),
            'RegOpenKeyExA': (ctypes.c_int32, (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)),
            'RegQueryValueExA': (ctypes.c_int32, (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)),
            'RegCloseKey': (ctypes.c_int32, (ctypes.c_void_p,)),
            'CreateFileA': (ctypes.c_void_p, (ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)),
            'DeviceIoControl': (ctypes.c_int32, (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p)),
            'CloseHandle': (ctypes.c_int32, (ctypes.c_void_p,))}
        function.restype, function.argtypes = signatures[name]
        result = function(*arguments)
        return (result or 0) & (_MASK if function.restype is ctypes.c_void_p else 0xFFFFFFFF)

    def close(self):
        if self.closed:
            return
        import _ctypes
        for library in self.libraries.values():
            _ctypes.FreeLibrary(library._handle)
        self.libraries.clear()
        self.closed = True


class WindowsHypervisorObservations:
    def __init__(self, fallback, *, backend=None):
        self.fallback = fallback
        self.backend = backend
        self._own_backend = backend is None
        self.thread = threading.get_ident()
        self.runtime = None
        self.handles = {}
        self.cleanup_events = []
        self.records = []
        self.closed = False

    def _call(self, name, arguments):
        if self.backend is None:
            self.backend = WindowsHypervisorBackend()
        return self.backend.call(name, arguments)

    def _owned(self, handle, kind):
        if self.handles.get(handle) != kind:
            raise PrimarySemanticUnavailable('raw device classification requires its actual owned handle')

    def take(self, runtime, name, arguments):
        result = self._take(runtime, name, arguments)
        if name in _IMPORTS:
            self.records.append((name, result[0]))
        return result

    def _take(self, runtime, name, arguments):
        if self.closed or threading.get_ident() != self.thread:
            raise CapabilityUnavailable('raw device classification observer lifetime or thread mismatch')
        if self.runtime is None:
            self.runtime = runtime
        elif self.runtime is not runtime:
            raise InputError('raw device classification observer runtime mismatch')
        if name not in _IMPORTS:
            if self.fallback is None:
                raise PrimarySemanticUnavailable('raw device classification has no fallback observation')
            return self.fallback.take(runtime, name, arguments)
        if name == 'OpenSCManagerW':
            if arguments != (0, 0, 4):
                raise InputError('raw service manager requires the source access tuple')
            value = self._call(name, arguments)
            if value:
                self.handles[value] = 'manager'
            return value, ()
        if name == 'OpenServiceA':
            handle, service, access = arguments
            self._owned(handle, 'manager')
            if (service, access) != (b'vmbusr\0', 4):
                raise InputError('raw service lookup differs from source')
            value = self._call(name, arguments)
            if value:
                self.handles[value] = 'service'
            return value, ()
        if name in ('CloseServiceHandle', 'CloseHandle', 'RegCloseKey'):
            handle, = arguments
            kind = self.handles.get(handle)
            allowed = {'CloseServiceHandle': ('manager', 'service'), 'CloseHandle': ('disk',), 'RegCloseKey': ('registry',)}[name]
            if kind not in allowed and not (name == 'RegCloseKey' and handle == 0):
                raise PrimarySemanticUnavailable('raw close requires an owned handle or explicit null HKEY')
            result = self._call(name, arguments)
            if (name == 'RegCloseKey' and result == 0) or (name != 'RegCloseKey' and result):
                self.handles.pop(handle, None)
            return result, ()
        if name == 'RegOpenKeyExA':
            root, key, reserved, access, output = arguments
            if root != 0xFFFFFFFF80000002 or key[:-1] not in _KEYS or key[-1:] != b'\0' or (reserved, access) != (0, 0x20119):
                raise InputError('raw registry lookup differs from source')
            region, start = runtime.memory._span(output, 8)
            before = bytes(region.data[start + index] if region.initialized[start + index] else 0xA5 for index in range(8))
            target = ctypes.c_uint64(int.from_bytes(before, 'little'))
            result = self._call(name, (root, key, reserved, access, ctypes.byref(target)))
            if result == 0:
                if not target.value:
                    raise InputError('successful registry open requires an actual handle')
                self.handles[target.value] = 'registry'
                return result, ((output, target.value.to_bytes(8, 'little')),)
            after = target.value.to_bytes(8, 'little')
            return result, tuple((output + index, after[index:index + 1]) for index in range(8) if before[index] != after[index])
        if name == 'RegQueryValueExA':
            handle, key, reserved, kind, data, size = arguments
            self._owned(handle, 'registry')
            if key[:-1] not in _VALUES or key[-1:] != b'\0' or reserved != 0:
                raise InputError('raw registry value lookup differs from source')
            if key == b'VirtualMachineId\0':
                if (kind, data, size) != (0, 0, 0):
                    raise InputError('VMID query requires three null output pointers')
                return self._call(name, arguments), ()
            if not kind or not data or not size or runtime.memory.load(size, 4) != 8:
                raise InputError('machine query requires source type/data/size outputs and size eight')
            for address, width in ((kind, 4), (data, 8), (size, 4)):
                runtime.memory._span(address, width)
            native_kind, native_size = ctypes.c_uint32(), ctypes.c_uint32(8)
            native_data = ctypes.create_string_buffer(8)
            result = self._call(name, (handle, key, 0, ctypes.byref(native_kind), native_data, ctypes.byref(native_size)))
            if result != 0:
                return result, ()
            if native_size.value > 8:
                raise InputError('successful machine query exceeds its source capacity')
            return result, ((kind, native_kind.value.to_bytes(4, 'little')),
                            (size, native_size.value.to_bytes(4, 'little')),
                            (data, native_data.raw[:native_size.value]))
        if name == 'CreateFileA':
            if arguments != (b'\\\\.\\PhysicalDrive0\0', 0x100080, 1, 0, 3, 0, 0):
                raise InputError('raw disk open differs from source')
            result = self._call(name, arguments)
            if result != _MASK:
                self.handles[result] = 'disk'
            return result, ()
        if name == 'DeviceIoControl':
            handle, code, query, query_size, output, capacity, count, overlapped = arguments
            self._owned(handle, 'disk')
            if (code, query_size, capacity, overlapped) != (0x2D1400, 12, 4096, 0) or runtime.memory.read(query, 12) != bytes(12):
                raise InputError('raw storage descriptor query differs from source')
            runtime.memory._span(output, capacity)
            runtime.memory._span(count, 4)
            native_query = ctypes.create_string_buffer(bytes(12), 12)
            native_output = ctypes.create_string_buffer(capacity)
            native_count = ctypes.c_uint32()
            result = self._call(name, (handle, code, native_query, 12, native_output, capacity, ctypes.byref(native_count), 0))
            if not result:
                return result, ()
            if native_count.value > capacity:
                raise InputError('raw storage descriptor output exceeds source capacity')
            return result, ((output, native_output.raw[:native_count.value]),
                            (count, native_count.value.to_bytes(4, 'little')))
        raise PrimarySemanticUnavailable('raw device classification API is unsupported')

    def close(self):
        if self.closed:
            return
        try:
            for handle, kind in list(self.handles.items()):
                name = 'RegCloseKey' if kind == 'registry' else 'CloseHandle' if kind == 'disk' else 'CloseServiceHandle'
                result = self._call(name, (handle,))
                self.cleanup_events.append((name, result))
                if (name == 'RegCloseKey' and result == 0) or (name != 'RegCloseKey' and result):
                    self.handles.pop(handle, None)
            if self.handles:
                raise CapabilityUnavailable('raw classification recovery cleanup did not release all owned handles')
        finally:
            if self._own_backend and self.backend is not None and not self.handles:
                self.backend.close()
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()
