import ctypes
import functools
import hashlib
import os
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


def _preserve_last_error(function):
    @functools.wraps(function)
    def guarded(*arguments, **keywords):
        if os.name != 'nt':
            return function(*arguments, **keywords)
        private = ctypes.get_last_error()
        native = ctypes.GetLastError() & 0xFFFFFFFF
        setter = ctypes.WINFUNCTYPE(None, ctypes.c_uint32)(('SetLastError', ctypes.windll.kernel32))
        try:
            return function(*arguments, **keywords)
        finally:
            setter(native)
            ctypes.set_last_error(private)
    return guarded


class _ProcessBasicInformation(ctypes.Structure):
    _fields_ = [('reserved1', ctypes.c_void_p), ('peb', ctypes.c_void_p),
                ('reserved2', ctypes.c_void_p * 2), ('pid', ctypes.c_size_t),
                ('reserved3', ctypes.c_void_p)]


class _MemoryBasicInformation(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('allocation_base', ctypes.c_void_p),
                ('allocation_protect', ctypes.c_uint32), ('partition', ctypes.c_uint16),
                ('size', ctypes.c_size_t), ('state', ctypes.c_uint32),
                ('protect', ctypes.c_uint32), ('type', ctypes.c_uint32)]


def _pointer(value):
    if type(value) is not int or not 0x10000 <= value <= 0x7FFFFFFFFFFF or value % 8:
        raise PrimarySemanticUnavailable('CRT environment requires a nonnull aligned Win64 user pointer')
    return value


class WindowsCRTEnvironmentBackend:
    @_preserve_last_error
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise PrimarySemanticUnavailable('CRT environment requires native Windows AMD64')
        if (ctypes.sizeof(_ProcessBasicInformation), _ProcessBasicInformation.peb.offset,
                _ProcessBasicInformation.pid.offset, ctypes.sizeof(_MemoryBasicInformation),
                _MemoryBasicInformation.size.offset) != (48, 8, 32, 48, 24):
            raise PrimarySemanticUnavailable('CRT environment native structure ABI mismatch')
        self._identity = os.getpid(), threading.get_native_id()
        self._closed = False
        self.kernel = ctypes.WinDLL('kernel32', handle=ctypes.windll.kernel32._handle, use_last_error=True)
        try:
            for name, result, arguments in (
                    ('GetCurrentProcess', ctypes.c_void_p, ()),
                    ('GetCurrentProcessId', ctypes.c_uint32, ()),
                    ('GetCurrentThreadId', ctypes.c_uint32, ()),
                    ('GetModuleHandleW', ctypes.c_void_p, (ctypes.c_wchar_p,)),
                    ('IsWow64Process2', ctypes.c_int32, (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16))),
                    ('VirtualQuery', ctypes.c_size_t, (ctypes.c_void_p, ctypes.POINTER(_MemoryBasicInformation), ctypes.c_size_t)),
                    ('ReadProcessMemory', ctypes.c_int32, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)))):
                function = getattr(self.kernel, name)
                function.restype, function.argtypes = result, arguments
            self._process = int(self.kernel.GetCurrentProcess() or 0)
            if self._process != (1 << 64) - 1:
                raise PrimarySemanticUnavailable('CRT environment current-process pseudo handle mismatch')
            process_machine, native_machine = ctypes.c_uint16(), ctypes.c_uint16()
            success = self.kernel.IsWow64Process2(self._process, ctypes.byref(process_machine), ctypes.byref(native_machine))
            if not success or (process_machine.value, native_machine.value) != (0, 0x8664):
                raise PrimarySemanticUnavailable('CRT environment requires verified native AMD64 process architecture')
            handle = self.kernel.GetModuleHandleW('ntdll.dll')
            if not handle:
                raise PrimarySemanticUnavailable('CRT environment borrowed ntdll module is unavailable')
            self.ntdll = ctypes.WinDLL('ntdll', handle=handle, use_last_error=True)
            self.ntdll.NtQueryInformationProcess.restype = ctypes.c_int32
            self.ntdll.NtQueryInformationProcess.argtypes = (
                ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_ProcessBasicInformation),
                ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
            self.current_identity()
        except BaseException:
            self.close()
            raise

    @_preserve_last_error
    def current_identity(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('CRT environment backend requires its live creating process and native thread')
        identity = int(self.kernel.GetCurrentProcessId()), int(self.kernel.GetCurrentThreadId())
        if identity != self._identity:
            raise PrimarySemanticUnavailable('CRT environment native identity mismatch')
        return identity

    @_preserve_last_error
    def query_current_peb(self):
        identity = self.current_identity()
        information = _ProcessBasicInformation()
        returned = ctypes.c_uint32()
        status = self.ntdll.NtQueryInformationProcess(self._process, 0, ctypes.byref(information),
                                                     ctypes.sizeof(information), ctypes.byref(returned))
        if status != 0 or returned.value != ctypes.sizeof(information):
            raise PrimarySemanticUnavailable('CRT environment process query failed or returned partial native structure')
        if information.pid != identity[0]:
            raise PrimarySemanticUnavailable('CRT environment process query returned a foreign identity')
        return _pointer(information.peb)

    @_preserve_last_error
    def read_exact(self, address, size):
        self.current_identity()
        if type(address) is not int or type(size) is not int or size not in (4, 8) or not 0x10000 <= address <= 0x7FFFFFFFFFFF - size:
            raise InputError('CRT environment field read exceeds its bounded Win64 source domain')
        information = _MemoryBasicInformation()
        queried = self.kernel.VirtualQuery(address, ctypes.byref(information), ctypes.sizeof(information))
        if queried != ctypes.sizeof(information):
            raise PrimarySemanticUnavailable('CRT environment field mapping query failed or was partial')
        base = int(information.base or 0)
        if (information.state != 0x1000 or information.protect & 0x100 or
                information.protect & 0xFF not in (2, 4, 8, 0x20, 0x40, 0x80) or
                not base <= address or address + size > base + information.size):
            raise PrimarySemanticUnavailable('CRT environment field is outside one committed readable own-process region')
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t()
        success = self.kernel.ReadProcessMemory(self._process, address, buffer, size, ctypes.byref(read))
        if not success or read.value != size:
            raise PrimarySemanticUnavailable('CRT environment native field read failed or was partial')
        return buffer.raw

    @_preserve_last_error
    def close(self):
        if self._closed:
            return
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('CRT environment backend close requires its creating process and native thread')
        self._closed = True


class WindowsCRTEnvironmentObservations:
    @_preserve_last_error
    def __init__(self, *, backend=None):
        self._backend = backend
        self._identity = os.getpid(), threading.get_native_id()
        self._closed = False
        self.records = []

    def _check(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('CRT environment requires its live creating process and native thread')

    @_preserve_last_error
    def read_process_parameters_flags(self):
        self._check()
        try:
            if self._backend is None:
                self._backend = WindowsCRTEnvironmentBackend()
            if self._backend.current_identity() != self._identity:
                raise InputError('CRT environment collector backend identity mismatch')
            peb = _pointer(self._backend.query_current_peb())
            raw = self._backend.read_exact(peb + 0x20, 8)
            if not isinstance(raw, bytes) or len(raw) != 8:
                raise PrimarySemanticUnavailable('CRT environment process-parameters pointer read was partial')
            parameters = _pointer(int.from_bytes(raw, 'little'))
            flags = self._backend.read_exact(parameters + 8, 4)
            if not isinstance(flags, bytes) or len(flags) != 4:
                raise PrimarySemanticUnavailable('CRT environment flags DWORD read was partial')
            if self._backend.current_identity() != self._identity:
                raise InputError('CRT environment collector identity changed during capture')
        except BaseException as error:
            self.records.append({'api': 'CRT.ProcessParametersFlags', 'status': type(error).__name__})
            raise
        self.records.append({'api': 'CRT.ProcessParametersFlags', 'status': 'observed',
                             'read_widths': (8, 4), 'value_sha256': hashlib.sha256(flags).hexdigest()})
        return int.from_bytes(flags, 'little')

    @_preserve_last_error
    def close(self):
        if self._closed:
            return
        self._check()
        if self._backend is not None:
            self._backend.close()
        self._closed = True
