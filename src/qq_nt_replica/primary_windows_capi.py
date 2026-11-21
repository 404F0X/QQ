import ctypes
import os

from .errors import CapabilityUnavailable, InputError
from .primary_device_capi import _IMPORTS
from .primary_vm import PrimarySemanticUnavailable


_SLOTS = dict(_IMPORTS, VerSetConditionMask=0x49103F8, VerifyVersionInfoW=0x4910400)
_LIMIT = 1 << 20


class CapiCreationDisabled(CapabilityUnavailable):
    def __init__(self, last_error):
        super().__init__('Windows CAPI requires container/key creation; creation is disabled')
        self.last_error = last_error


class _WindowsAPIs:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable('Windows x64 CAPI observations are required')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        crypt = ctypes.WinDLL('crypt32', use_last_error=True)
        p, u, b = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        pu, pp = ctypes.POINTER(u), ctypes.POINTER(p)
        signatures = (
            (kernel, 'VerSetConditionMask', ctypes.c_uint64, (ctypes.c_uint64, u, ctypes.c_ubyte)),
            (kernel, 'VerifyVersionInfoW', b, (p, u, ctypes.c_uint64)),
            (advapi, 'CryptAcquireContextA', b, (pp, ctypes.c_char_p, ctypes.c_char_p, u, u)),
            (advapi, 'CryptGetUserKey', b, (p, u, pp)),
            (crypt, 'CryptExportPublicKeyInfo', b, (p, u, u, p, pu)),
            (advapi, 'CryptCreateHash', b, (p, u, p, u, pp)),
            (advapi, 'CryptHashData', b, (p, p, u, u)),
            (advapi, 'CryptGetHashParam', b, (p, u, p, pu, u)),
            (advapi, 'CryptDestroyHash', b, (p,)),
            (advapi, 'CryptDestroyKey', b, (p,)),
            (advapi, 'CryptReleaseContext', b, (p, u)),
            (advapi, 'CryptGenKey', b, (p, u, u, pp)),
            (advapi, 'InitializeSecurityDescriptor', b, (p, u)),
            (advapi, 'SetSecurityDescriptorDacl', b, (p, b, p, b)),
            (advapi, 'CryptSetProvParam', b, (p, u, p, u)),
        )
        self.libraries = kernel, advapi, crypt
        for library, name, result, arguments in signatures:
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            setattr(self, name, function)

    def last_error(self):
        return ctypes.get_last_error()


def _integer(value, width=32):
    value = getattr(value, 'value', value)
    if type(value) is not int:
        raise InputError('Windows CAPI backend requires integer results')
    return value & ((1 << width) - 1)


def _delta(before, after):
    return tuple((index, bytes([right])) for index, (left, right) in enumerate(zip(before, after)) if left != right)


class WindowsCapiObservations:
    def __init__(self, runtime, rbp, *, backend=None, allow_creation=False):
        if type(rbp) is not int or type(allow_creation) is not bool:
            raise InputError('Windows CAPI requires an explicit frame and creation policy')
        self.runtime, self.rbp = runtime, rbp
        self.backend, self.allow_creation = backend, allow_creation
        self.records, self.cleanup_records = [], []
        self._handles = {}
        self._last_error = None
        self._acquisition_error = None
        self._sd = None
        self._previous = None
        self._active = False
        self._closed = False

    @property
    def pending_handles(self):
        return tuple(self._handles)

    @property
    def scratch_count(self):
        return int(self._sd is not None)

    def _api(self):
        if self.backend is None:
            self.backend = _WindowsAPIs()
        return self.backend

    def __enter__(self):
        if self._active or self._closed:
            raise InputError('Windows CAPI observation scope cannot be reused')
        self._previous = self.runtime.worker_observations
        self.runtime.worker_observations = self
        self._active = True
        return self

    def __exit__(self, kind, error, traceback):
        try:
            self.close()
        finally:
            self.runtime.worker_observations = self._previous
            self._active = False
        return False

    def _record(self, name, result, raw, *, count=0):
        record = {'name': name, 'result': result, 'count': count}
        self.records.append(record)
        self.runtime.events.append(('windows.CAPI', name, result, count))
        return result, raw

    def _initial(self, offset, width):
        region, start = self.runtime.memory._span(self.rbp + offset, width)
        return bytes(region.data[start:start + width]), bytes(region.initialized[start:start + width])

    def _require_handle(self, kind, handle):
        if (kind, handle) not in self._handles:
            raise InputError('Windows CAPI requires a handle acquired in this scope')

    def _handle(self, name, args, offset, kind, position):
        before, known = self._initial(offset, 8)
        value = ctypes.c_void_p(int.from_bytes(before, 'little'))
        native_args = list(args)
        native_args.insert(position, ctypes.byref(value))
        try:
            result = _integer(getattr(self._api(), name)(*native_args))
            if name == 'CryptAcquireContextA' and not result:
                self._last_error = _integer(self._api().last_error())
                self._acquisition_error = self._last_error
        except BaseException:
            if value.value and value.value != int.from_bytes(before, 'little'):
                self._handles[kind, value.value] = 'uncertain'
            raise
        after = (value.value or 0).to_bytes(8, 'little')
        if result:
            if not value.value or (kind, value.value) in self._handles:
                raise CapabilityUnavailable('Windows CAPI returned a null or duplicate owned handle')
            self._handles[kind, value.value] = 'owned'
        raw = after if result or all(known) else _delta(before, after)
        return self._record(name, result, raw)

    def take(self, runtime, name, arguments):
        if not self._active or self._closed or runtime is not self.runtime:
            raise InputError('Windows CAPI observations require their active runtime scope')
        if name not in _SLOTS:
            if self._previous is None:
                raise CapabilityUnavailable('Windows CAPI has no fallback observer for this API')
            return self._previous.take(runtime, name, arguments)
        expected = runtime.worker_imports.get(name)
        if expected is None or runtime.memory.load(runtime.image_base + _SLOTS[name], 8) != expected:
            raise PrimarySemanticUnavailable('Windows CAPI current import is not bound: ' + name)
        if not isinstance(arguments, tuple):
            raise InputError('Windows CAPI requires canonical tuple arguments')
        try:
            return self._take(name, arguments)
        except BaseException:
            self.close()
            raise

    def _take(self, name, args):
        if name == 'VerSetConditionMask':
            if len(args) != 3 or args[1:] not in ((2, 3), (1, 3)) or type(args[0]) is not int:
                raise InputError('Windows CAPI version condition arguments differ from source')
            return self._record(name, _integer(self._api().VerSetConditionMask(*args), 64), b'')
        if name == 'VerifyVersionInfoW':
            if len(args) != 3 or not isinstance(args[0], bytes) or len(args[0]) != 284 or args[1] != 3:
                raise InputError('Windows CAPI version verification arguments differ from source')
            version = ctypes.create_string_buffer(args[0], 284)
            return self._record(name, _integer(self._api().VerifyVersionInfoW(version, *args[1:])), b'')
        if name == 'GetLastError':
            if args or self._last_error is None:
                raise InputError('Windows CAPI requires a captured failed-acquisition last error')
            value, self._last_error = self._last_error, None
            return self._record(name, value, b'')
        if name == 'CryptAcquireContextA':
            if args not in ((b'mWOLCtkGwuHtk\0', 0, 24, 0x60), (b'mWOLCtkGwuHtk\0', 0, 24, 0x68)):
                raise InputError('Windows CAPI acquisition arguments differ from source')
            if args[3] == 0x68 and not self.allow_creation:
                raise CapiCreationDisabled(self._acquisition_error)
            return self._handle(name, (args[0], None, *args[2:]), 0x9948, 'provider', 0)
        if name == 'CryptGenKey':
            if not self.allow_creation:
                raise CapiCreationDisabled(self._acquisition_error)
            if len(args) != 3 or args[1:] != (2, 0x08000000):
                raise InputError('Windows CAPI key generation arguments differ from source')
            self._require_handle('provider', args[0])
            return self._handle(name, args, 0x9928, 'key', 3)
        if name == 'CryptGetUserKey':
            if len(args) != 2 or args[1] != 2:
                raise InputError('Windows CAPI user-key arguments differ from source')
            self._require_handle('provider', args[0])
            return self._handle(name, args, 0x98F8, 'key', 2)
        if name == 'CryptCreateHash':
            if len(args) != 4 or args[1:] != (0x800C, 0, 0):
                raise InputError('Windows CAPI hash creation arguments differ from source')
            self._require_handle('provider', args[0])
            return self._handle(name, args, 0x98A8, 'hash', 4)
        if name in ('InitializeSecurityDescriptor', 'SetSecurityDescriptorDacl', 'CryptSetProvParam'):
            return self._security(name, args)
        if name == 'CryptExportPublicKeyInfo':
            return self._export(args)
        if name == 'CryptHashData':
            if len(args) != 3 or not isinstance(args[1], bytes) or len(args[1]) > _LIMIT or args[2] != 0:
                raise InputError('Windows CAPI hash-data arguments differ from source')
            self._require_handle('hash', args[0])
            buffer = ctypes.create_string_buffer(args[1], len(args[1])) if args[1] else None
            return self._record(name, _integer(self._api().CryptHashData(args[0], buffer, len(args[1]), 0)), b'', count=len(args[1]))
        if name == 'CryptGetHashParam':
            if len(args) != 4 or args[1:] != (2, 32, 0):
                raise InputError('Windows CAPI hash output arguments differ from source')
            self._require_handle('hash', args[0])
            buffer, length = ctypes.create_string_buffer(32), ctypes.c_uint32(32)
            result = _integer(self._api().CryptGetHashParam(args[0], 2, buffer, ctypes.byref(length), 0))
            return self._record(name, result, (buffer.raw, length.value), count=length.value)
        if name in ('CryptDestroyHash', 'CryptDestroyKey', 'CryptReleaseContext'):
            kind = {'CryptDestroyHash': 'hash', 'CryptDestroyKey': 'key', 'CryptReleaseContext': 'provider'}[name]
            if len(args) != (2 if kind == 'provider' else 1) or kind == 'provider' and args[1] != 0:
                raise InputError('Windows CAPI cleanup arguments differ from source')
            self._require_handle(kind, args[0])
            result = _integer(getattr(self._api(), name)(*args))
            if result:
                self._handles.pop((kind, args[0]))
            return self._record(name, result, b'')
        raise InputError('Windows CAPI API is unsupported')

    def _security(self, name, args):
        if not self.allow_creation:
            raise CapiCreationDisabled(self._acquisition_error)
        address = self.rbp + 0x9900
        if name == 'InitializeSecurityDescriptor':
            if args != (address, 1) or self._sd is not None:
                raise InputError('Windows CAPI security initialization differs from source')
            before, known = self._initial(0x9900, 40)
            self._sd = ctypes.create_string_buffer(before, 40)
            result = _integer(self._api().InitializeSecurityDescriptor(self._sd, 1))
            raw = ((0, self._sd.raw[:4]), (8, self._sd.raw[8:])) if result else _delta(before, self._sd.raw)
        elif name == 'SetSecurityDescriptorDacl':
            if args != (address, 1, 0, 0) or self._sd is None:
                raise InputError('Windows CAPI security DACL arguments differ from source')
            before = self._sd.raw
            result = _integer(self._api().SetSecurityDescriptorDacl(self._sd, 1, None, 0))
            raw = ((2, self._sd.raw[2:4]), (32, self._sd.raw[32:40])) if result else _delta(before, self._sd.raw)
        else:
            if len(args) != 4 or args[1:] != (8, address, 4) or self._sd is None:
                raise InputError('Windows CAPI security provider arguments differ from source')
            self._require_handle('provider', args[0])
            result = _integer(self._api().CryptSetProvParam(args[0], 8, self._sd, 4))
            raw = b''
        return self._record(name, result, raw)

    def _export(self, args):
        if len(args) != 5 or args[1:3] != (2, 0x10001) or type(args[3]) is not int or type(args[4]) is not int:
            raise InputError('Windows CAPI public-key export arguments differ from source')
        self._require_handle('provider', args[0])
        pointer, capacity = args[3:]
        if not pointer and capacity != 0 or pointer and not 40 <= capacity <= _LIMIT:
            raise InputError('Windows CAPI export requires its bounded size query or buffer')
        initial = self.runtime.memory.read(pointer, capacity) if pointer else b''
        buffer = ctypes.create_string_buffer(initial, capacity) if pointer else None
        length = ctypes.c_uint32(capacity)
        result = _integer(self._api().CryptExportPublicKeyInfo(*args[:3], buffer, ctypes.byref(length)))
        raw = bytearray(buffer.raw) if buffer is not None else bytearray()
        if buffer is not None:
            native = ctypes.addressof(buffer)
            for offset in (0, 16, 32):
                value = int.from_bytes(raw[offset:offset + 8], 'little')
                if native <= value <= native + capacity:
                    raw[offset:offset + 8] = (pointer + value - native).to_bytes(8, 'little')
            if result:
                count = int.from_bytes(raw[24:28], 'little')
                value = int.from_bytes(raw[32:40], 'little')
                if count and (not pointer <= value <= pointer + capacity or count > pointer + capacity - value):
                    raise CapabilityUnavailable('Windows CAPI exported bits leave their returned buffer')
        return self._record('CryptExportPublicKeyInfo', result, (bytes(raw), length.value), count=length.value)

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._sd = None
        for kind in ('hash', 'key', 'provider'):
            for entry in tuple(self._handles):
                if entry[0] != kind:
                    continue
                name = {'hash': 'CryptDestroyHash', 'key': 'CryptDestroyKey', 'provider': 'CryptReleaseContext'}[kind]
                try:
                    result = _integer(getattr(self._api(), name)(entry[1], 0) if kind == 'provider' else getattr(self._api(), name)(entry[1]))
                except BaseException as error:
                    self.cleanup_records.append({'name': name, 'error': type(error).__name__})
                else:
                    self.cleanup_records.append({'name': name, 'result': result})
                    if result:
                        self._handles.pop(entry)
