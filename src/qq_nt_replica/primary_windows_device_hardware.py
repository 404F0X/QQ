import ctypes
import _ctypes
import itertools
import os
import threading
from dataclasses import dataclass

from .errors import InputError
from .primary_device_hardware import AdapterBufferEffect
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_MASK = (1 << 64) - 1
_LIMIT = 1 << 20
_UNBOUND = object()
_TOKENS = itertools.count(1)
_SURFACE = {'GetWindowsDirectoryA', 'CreateFileA', 'DeviceIoControl', 'CloseHandle',
            'LoadLibraryA', 'GetProcAddress', 'FreeLibrary', 'GetAdaptersInfo',
            'GetTickCount', '_wcreate_locale', 'MultiByteToWideChar'}


def _adapter_mode(mode):
    if type(mode) is not str or mode not in ('source_sparse', 'independent_windows'):
        raise InputError('adapter environment must explicitly select source_sparse or independent_windows')
    return mode


def adapter_qualification(mode):
    mode = _adapter_mode(mode)
    if mode == 'independent_windows':
        return dict(origin='INDEPENDENT_WINDOWS_ADAPTER_ENVIRONMENT', postimage_source='CALLER_OWNED_INITIALIZED_BUFFER',
            original_malloc_equivalence='NOT_ESTABLISHED', os_write_set='NOT_INFERRED',
            source_request_association='NOT_ASSOCIATED', source_profile_association='NOT_ASSOCIATED', same_request=False, full96=False)
    return dict(origin='STRICT_SOURCE_SPARSE_ADAPTER_OUTPUT', original_malloc_equivalence='REQUIRES_SOURCE_INPUTS',
        source_request_association='NOT_ASSOCIATED', source_profile_association='NOT_ASSOCIATED', same_request=False, full96=False)


@dataclass(frozen=True)
class _IndependentAdapterEffect(AdapterBufferEffect):
    binding: object


class _IPAddrString(ctypes.Structure):
    _fields_ = [('next', ctypes.c_void_p), ('address', ctypes.c_char * 16),
                ('mask', ctypes.c_char * 16), ('context', ctypes.c_uint32)]


class _AdapterInfo(ctypes.Structure):
    _fields_ = [('next', ctypes.c_void_p), ('combo_index', ctypes.c_uint32),
                ('name', ctypes.c_char * 260), ('description', ctypes.c_char * 132),
                ('address_length', ctypes.c_uint32), ('address', ctypes.c_ubyte * 8),
                ('index', ctypes.c_uint32), ('type', ctypes.c_uint32), ('dhcp', ctypes.c_uint32),
                ('current_ip', ctypes.c_void_p), ('ip', _IPAddrString), ('gateway', _IPAddrString),
                ('dhcp_server', _IPAddrString), ('wins', ctypes.c_int32),
                ('primary_wins', _IPAddrString), ('secondary_wins', _IPAddrString),
                ('lease_obtained', ctypes.c_int64), ('lease_expires', ctypes.c_int64)]


def adapter_buffer_effect(raw, address):
    if not isinstance(raw, bytes) or not 704 <= len(raw) <= _LIMIT:
        raise InputError('adapter native success requires bounded IP_ADAPTER_INFO backing')
    output, known, relocations = bytearray(raw), bytearray(len(raw)), {}

    def span(offset, size):
        if not 0 <= offset <= len(raw) - size:
            raise PrimarySemanticUnavailable('adapter native pointer leaves its original output allocation')

    def mark(offset, size):
        span(offset, size)
        known[offset:offset + size] = b'\1' * size

    def pointer(offset):
        span(offset, 8)
        value = int.from_bytes(raw[offset:offset + 8], 'little')
        target = value - address if value else None
        if target is not None:
            span(target, 1)
        relocations[offset] = target
        output[offset:offset + 8] = bytes(8)
        mark(offset, 8)
        return target

    def text(offset, maximum):
        span(offset, maximum)
        end = raw.find(b'\0', offset, offset + maximum)
        if end < 0:
            raise PrimarySemanticUnavailable('adapter native text lacks its fixed-field terminator')
        mark(offset, end + 1 - offset)

    def ips(first):
        seen, current = set(), first
        while current is not None:
            if current in seen or len(seen) >= 256:
                raise PrimarySemanticUnavailable('adapter native IP chain is cyclic or exceeds its bound')
            seen.add(current)
            span(current, 48)
            following = pointer(current)
            text(current + 8, 16)
            text(current + 24, 16)
            mark(current + 40, 4)
            current = following

    seen, current = set(), 0
    while current is not None:
        if current in seen or len(seen) >= 256:
            raise PrimarySemanticUnavailable('adapter native Next chain is cyclic or exceeds its bound')
        seen.add(current)
        span(current, 704)
        following = pointer(current)
        mark(current + 8, 4)
        text(current + 12, 260)
        text(current + 272, 132)
        mark(current + 404, 4)
        count = int.from_bytes(raw[current + 404:current + 408], 'little')
        if count > 8:
            raise PrimarySemanticUnavailable('adapter native address length exceeds the fixed eight-byte field')
        mark(current + 408, count)
        mark(current + 416, 12)
        ip = pointer(current + 432)
        if ip is not None:
            ips(ip)
        for offset in (440, 488, 536, 592, 640):
            ips(current + offset)
        mark(current + 584, 4)
        mark(current + 688, 16)
        current = following
    return AdapterBufferEffect(bytes(output), bytes(known), tuple(sorted(relocations.items())))


def _independent_adapter_effect(raw, address, binding):
    if binding is None:
        raise InputError('independent adapter effect requires its caller binding')
    effect = adapter_buffer_effect(raw, address)
    known = bytearray(effect.known)
    links = dict(effect.relocations)
    current = 0
    while current is not None:
        known[current + 408:current + 416] = b'\1' * 8
        current = links[current]
    return _IndependentAdapterEffect(effect.raw, bytes(known), effect.relocations, binding)


class WindowsDeviceHardwareAPIBackend:
    def __init__(self, *, adapter_environment='source_sparse'):
        self.adapter_environment = _adapter_mode(adapter_environment)
        self._adapter_binding = object() if self.adapter_environment == 'independent_windows' else None
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise PrimarySemanticUnavailable('native device hardware requires Windows x64')
        if (ctypes.sizeof(_IPAddrString), ctypes.sizeof(_AdapterInfo), _AdapterInfo.address.offset,
                _AdapterInfo.current_ip.offset, _AdapterInfo.ip.offset, _AdapterInfo.secondary_wins.offset) != (48, 704, 408, 432, 440, 640):
            raise PrimarySemanticUnavailable('native adapter layout differs from the fixed Win64 source ABI')
        self._owner = os.getpid(), threading.get_native_id()
        self._libraries, self._source_libraries = {}, {}
        self._handles, self._locales = set(), set()
        self.closed = False
        self.cleanup_records = []
        self.kernel = ctypes.WinDLL('kernel32', handle=ctypes.windll.kernel32._handle, use_last_error=True)

    def _check(self):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('native device hardware requires its open creator process and thread')

    def _call(self, library, name, result, types, values):
        self._check()
        if library == 'kernel32':
            dll = self.kernel
        else:
            if library not in self._libraries:
                self._libraries[library] = ctypes.WinDLL(library, use_last_error=True)
            dll = self._libraries[library]
        function = getattr(dll, name)
        function.restype, function.argtypes = result, types
        value = function(*values)
        return value, ctypes.get_last_error() & 0xFFFFFFFF

    def request(self, name, args):
        self._check()
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        pu = ctypes.POINTER(u)
        if name == 'GetWindowsDirectoryA':
            output = ctypes.create_string_buffer(265)
            value, error = self._call('kernel32', name, u, (p, u), (output, args[0]))
            return value, output.raw[:260], error
        if name == 'CreateFileA':
            value, error = self._call('kernel32', name, p, (ctypes.c_char_p, u, u, p, u, u, p), args)
            value = int(value or 0) & _MASK
            if value not in (0, _MASK):
                self._handles.add(value)
            return value, b'', error
        if name == 'DeviceIoControl':
            output, count = ctypes.create_string_buffer(1024), u()
            query = ctypes.create_string_buffer(args[2], 12)
            value, error = self._call('kernel32', name, i, (p, u, p, u, p, u, pu, p),
                (args[0], args[1], query, 12, output, 1024, ctypes.byref(count), None))
            return value & 0xFFFFFFFF, (output.raw, count.value), error
        if name == 'CloseHandle':
            value, error = self._call('kernel32', name, i, (p,), args)
            if value:
                self._handles.remove(args[0])
            return value & 0xFFFFFFFF, b'', error
        if name == 'LoadLibraryA':
            value, error = self._call('kernel32', name, p, (ctypes.c_char_p,), args)
            value = int(value or 0)
            if value:
                self._source_libraries[value] = self._source_libraries.get(value, 0) + 1
            return value, b'', error
        if name == 'FreeLibrary':
            value, error = self._call('kernel32', name, i, (p,), args)
            if value:
                self._source_libraries[args[0]] -= 1
                if not self._source_libraries[args[0]]:
                    del self._source_libraries[args[0]]
            return value & 0xFFFFFFFF, b'', error
        if name == 'GetProcAddress':
            value, error = self._call('kernel32', name, p, (p, ctypes.c_char_p), args)
            return int(value or 0), b'', error
        if name == 'GetAdaptersInfo':
            target, present, capacity = args
            output = ctypes.create_string_buffer(b'\xCC' * capacity, capacity) if present else None
            count = u(capacity)
            function = ctypes.WINFUNCTYPE(u, p, pu, use_last_error=True)(target) if target else None
            if function is None:
                value, error = self._call('iphlpapi', name, u, (p, pu), (output, ctypes.byref(count)))
            else:
                value = function(output, ctypes.byref(count))
                error = ctypes.get_last_error() & 0xFFFFFFFF
            if value == 0:
                if output is None or not 704 <= count.value <= capacity:
                    raise PrimarySemanticUnavailable('adapter native success has invalid buffer size')
                raw, address = output.raw[:count.value], ctypes.addressof(output)
                effect = (adapter_buffer_effect(raw, address) if self.adapter_environment == 'source_sparse' else
                    _independent_adapter_effect(raw, address, self._adapter_binding))
            else:
                effect = AdapterBufferEffect(b'', b'', ())
            return value, (effect, count.value), error
        if name == 'GetTickCount':
            value, error = self._call('kernel32', name, u, (), ())
            return value, b'', error
        if name == 'MultiByteToWideChar':
            output = ctypes.create_string_buffer(262)
            raw = ctypes.create_string_buffer(args[2])
            value, error = self._call('kernel32', name, i, (u, u, p, i, p, i),
                (0, 0, raw, -1, output, 131))
            return value & 0xFFFFFFFF, output.raw[:2 * value] if value > 0 else b'', error
        if name == '_wcreate_locale':
            value, error = self._call('ucrtbase', name, p, (i, ctypes.c_wchar_p), (0, 'C'))
            value = int(value or 0)
            if value:
                self._locales.add(value)
            return value, ctypes.string_at(value, 16) if value else b'', error
        raise PrimarySemanticUnavailable('unsupported native device hardware operation')

    def close(self):
        if self.closed:
            return
        self._check()
        for handle in tuple(self._handles):
            result, _, error = self.request('CloseHandle', (handle,))
            self.cleanup_records.append(('host.CloseHandle', bool(result), error))
            if not result:
                raise PrimarySemanticUnavailable('host device hardware handle cleanup failed')
        for pointer in tuple(self._locales):
            self._call('ucrtbase', '_free_locale', None, (ctypes.c_void_p,), (pointer,))
            self._locales.remove(pointer)
            self.cleanup_records.append(('host._free_locale', True, 0))
        for handle in tuple(self._source_libraries):
            while handle in self._source_libraries:
                result, _, error = self.request('FreeLibrary', (handle,))
                self.cleanup_records.append(('host.FreeLibrary', bool(result), error))
                if not result:
                    raise PrimarySemanticUnavailable('host adapter library cleanup failed')
        for library, dll in tuple(self._libraries.items()):
            _ctypes.FreeLibrary(dll._handle)
            del self._libraries[library]
        self.closed = True


class WindowsDeviceHardwareObservations(WorkerObservations):
    def __init__(self, fallback=None, *, backend=None, adapter_environment='source_sparse'):
        self.adapter_environment = _adapter_mode(adapter_environment)
        if backend is not None and getattr(backend, 'adapter_environment', 'source_sparse') != self.adapter_environment:
            raise InputError('adapter observations require the selected backend environment')
        self.fallback, self.backend = fallback, backend
        self._owner = os.getpid(), threading.get_native_id()
        self._runtime, self.closed = _UNBOUND, False
        self._handles, self._libraries, self._targets = set(), {}, {}
        self._tokens = {}
        self.records = []

    def _check(self, runtime):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('device hardware observations require their open creator process and thread')
        if self._runtime is not _UNBOUND and self._runtime is not runtime:
            raise InputError('device hardware observations require their unique runtime')
        self._runtime = runtime

    @property
    def adapter_qualifications(self):
        return adapter_qualification(self.adapter_environment)

    def _token(self, pointer):
        if not pointer:
            return 0
        if pointer not in self._tokens:
            memory = getattr(self._runtime, 'memory', None)
            while True:
                token = 0x6E0000000000 + next(_TOKENS) * 0x10000
                if not any(token < region.address + len(region.data) and region.address < token + 0x10000
                           for region in getattr(memory, '_regions', ())):
                    self._tokens[pointer] = token
                    break
        return self._tokens[pointer]

    def _arguments(self, runtime, name, args):
        counts = {'GetWindowsDirectoryA': 1, 'CreateFileA': 7, 'DeviceIoControl': 5, 'CloseHandle': 1,
                  'LoadLibraryA': 1, 'GetProcAddress': 2, 'FreeLibrary': 1, 'GetAdaptersInfo': 3,
                  'GetTickCount': 0, '_wcreate_locale': 2, 'MultiByteToWideChar': 6}
        if not isinstance(args, tuple) or len(args) != counts[name]:
            raise InputError('device hardware observation argument count mismatch')
        valid = True
        if name == 'GetWindowsDirectoryA':
            valid = type(args[0]) is int and args == (260,)
        elif name == 'CreateFileA':
            valid = args == (b'\\\\.\\PhysicalDrive0', 0, 3, 0, 3, 0, 0) and all(type(v) is int for v in args[1:])
        elif name == 'DeviceIoControl':
            valid = type(args[0]) is int and args[0] in self._handles and args[1:] == (0x2D1400, bytes(12), 1024, 0) and all(type(args[o]) is int for o in (1, 3, 4))
        elif name == 'CloseHandle':
            valid = type(args[0]) is int and args[0] in self._handles
        elif name == 'LoadLibraryA':
            valid = args == (b'iphlpapi.dll',)
        elif name == 'GetProcAddress':
            valid = type(args[0]) is int and args[0] in self._libraries and args[1] == b'GetAdaptersInfo'
        elif name == 'FreeLibrary':
            valid = type(args[0]) is int and args[0] in self._libraries
        elif name == 'GetAdaptersInfo':
            target, present, capacity = args
            valid = type(target) is int and type(present) is bool and type(capacity) is int and 0 <= capacity <= _LIMIT and (capacity >= 704 if present else capacity == 0)
            if valid and target not in self._targets:
                valid = target != 0 and target == getattr(runtime, 'worker_imports', {}).get('GetAdaptersInfo')
            if valid:
                return (target if target in self._targets else 0, present, capacity)
        elif name == '_wcreate_locale':
            valid = type(args[0]) is int and args == (0, b'C\0\0\0')
        elif name == 'MultiByteToWideChar':
            valid = args == (0, 0, b'C\0', -1, True, 131) and type(args[4]) is bool
        if not valid:
            raise InputError('device hardware request leaves the finite source allowlist')
        return args

    def take(self, runtime, name, arguments):
        self._check(runtime)
        foreign = False
        if isinstance(arguments, tuple):
            if name == 'CreateFileA' and len(arguments) == 5:
                foreign = True
            elif name in ('CloseHandle', 'FreeLibrary') and len(arguments) == 1:
                domain = self._handles if name == 'CloseHandle' else self._libraries
                foreign = type(arguments[0]) is int and arguments[0] not in domain
            elif name == 'GetProcAddress' and len(arguments) == 2:
                foreign = type(arguments[0]) is int and arguments[0] not in self._libraries and arguments[1] != b'GetAdaptersInfo'
            elif name == 'MultiByteToWideChar' and len(arguments) == 6:
                foreign = arguments != (0, 0, b'C\0', -1, True, 131)
        if name not in _SURFACE or foreign and self.fallback is not None:
            if self.fallback is None:
                raise PrimarySemanticUnavailable('unsupported device hardware observation: ' + name)
            return self.fallback.take(runtime, name, arguments)
        args = self._arguments(runtime, name, arguments)
        if self.backend is None:
            self.backend = WindowsDeviceHardwareAPIBackend(adapter_environment=self.adapter_environment)
        result, effects, error = self.backend.request(name, args)
        width = 64 if name in ('CreateFileA', 'LoadLibraryA', 'GetProcAddress', '_wcreate_locale') else 32
        if type(result) is not int or not 0 <= result < 1 << width:
            raise InputError('device hardware result width differs from its source ABI')
        if type(error) is not int or not 0 <= error <= 0xFFFFFFFF:
            raise InputError('device hardware last error requires actual DWORD bits')
        if name in ('CreateFileA', 'CloseHandle', 'LoadLibraryA', 'FreeLibrary', 'GetProcAddress', 'GetTickCount') and effects != b'':
            raise InputError('device hardware scalar operation has no buffer effects')
        if name in ('GetWindowsDirectoryA', 'MultiByteToWideChar'):
            limit = 260 if name == 'GetWindowsDirectoryA' else 262
            if not isinstance(effects, bytes) or len(effects) > limit or name == 'MultiByteToWideChar' and len(effects) % 2:
                raise InputError('device hardware conversion requires bounded output bytes')
        if name == 'DeviceIoControl':
            if (not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], bytes)
                    or len(effects[0]) > 1024 or type(effects[1]) is not int or not 0 <= effects[1] <= 0xFFFFFFFF):
                raise InputError('device storage query requires bounded output and actual DWORD count')
        if name == 'GetAdaptersInfo':
            if (not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], AdapterBufferEffect)
                    or type(effects[1]) is not int or not 0 <= effects[1] <= 0xFFFFFFFF
                    or result != 0 and effects[0] != AdapterBufferEffect(b'', b'', ())):
                raise InputError('native adapter query requires explicit sparse relocation effects and DWORD size')
        if name == 'GetAdaptersInfo' and result == 0:
            if self.adapter_environment == 'independent_windows':
                if (type(effects[0]) is not _IndependentAdapterEffect or effects[0].binding is not self.backend._adapter_binding or
                        self.backend.adapter_environment != self.adapter_environment):
                    raise InputError('independent adapter output requires the same initialized caller buffer binding')
            elif isinstance(effects[0], _IndependentAdapterEffect):
                raise InputError('strict adapter output must retain its source sparse effect')
        if name == 'CreateFileA' and result not in (0, _MASK):
            self._handles.add(result)
        elif name == 'CloseHandle' and result:
            self._handles.remove(arguments[0])
        elif name == 'LoadLibraryA' and result:
            self._libraries[result] = self._libraries.get(result, 0) + 1
        elif name == 'FreeLibrary' and result:
            self._libraries[arguments[0]] -= 1
            if not self._libraries[arguments[0]]:
                del self._libraries[arguments[0]]
            self._targets = {target: module for target, module in self._targets.items() if module != arguments[0] or arguments[0] in self._libraries}
        elif name == 'GetProcAddress' and result:
            self._targets[result] = arguments[0]
        elif name == '_wcreate_locale':
            if not isinstance(effects, bytes) or len(effects) != (16 if result else 0):
                raise InputError('device C locale requires its exact descriptor16')
            result = self._token(result)
            effects = b''.join(self._token(int.from_bytes(effects[o:o + 8], 'little')).to_bytes(8, 'little') for o in range(0, len(effects), 8))
        self.records.append({'api': name, 'status': 'observed', 'error': error})
        if name == 'GetAdaptersInfo' and self.adapter_environment == 'independent_windows':
            runtime.events.append(('worker.API', name, 'INDEPENDENT_WINDOWS_ADAPTER_ENVIRONMENT'))
        else:
            runtime.events.append(('worker.API', name, arguments, result, effects))
        return result, effects

    def snapshot(self):
        return {'closed': self.closed, 'handles': len(self._handles), 'libraries': len(self._libraries),
                'observations': len(self.records), 'backend_closed': bool(getattr(self.backend, 'closed', False)),
                'native_handles': len(getattr(self.backend, '_handles', ())),
                'native_locales': len(getattr(self.backend, '_locales', ())),
                'native_source_library_references': sum(getattr(self.backend, '_source_libraries', {}).values()),
                'native_host_libraries': len(getattr(self.backend, '_libraries', ())) }

    def close(self):
        if self.closed:
            return
        self._check(self._runtime)
        if self.backend is not None:
            self.backend.close()
        self._handles.clear()
        self._libraries.clear()
        self._targets.clear()
        self._tokens.clear()
        self.closed = True
