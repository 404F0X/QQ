from dataclasses import dataclass
import hashlib
import os
import re
import threading

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations


_MASK = (1 << 64) - 1
_LIMIT = 1 << 20
_EXPORTS = (b'NtQuerySystemInformation', b'LdrLoadDll', b'LdrUnloadDll',
            b'RtlQueryEnvironmentVariable_U', b'LdrGetProcedureAddress',
            b'NtOpenDirectoryObject', b'NtQueryDirectoryObject', b'NtClose')
_APIS = frozenset(('rand_s', '_ftime64_s', 'SHGetSpecialFolderPathA', 'GetFileAttributesA',
    'CreateDirectoryA', 'CreateFileA', 'GetFileSize', 'ReadFile', 'WriteFile', 'CloseHandle',
    'GetLastError', 'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptGenRandom',
    'CryptReleaseContext', 'CryptGenKey', 'InitializeSecurityDescriptor', 'SetSecurityDescriptorDacl',
    'CryptSetProvParam', 'CryptGetUserKey', 'CryptExportPublicKeyInfo', 'CryptDestroyKey',
    'CryptCreateHash', 'CryptHashData', 'CryptGetHashParam', 'CryptDestroyHash',
    'VerSetConditionMask', 'VerifyVersionInfoW', 'GetModuleHandleW', 'GetProcAddress',
    'NtQuerySystemInformation', 'NtOpenDirectoryObject', 'NtQueryDirectoryObject', 'NtClose',
    'CPUID', 'GetVolumeInformationW', 'UuidCreateSequential', 'EnumDisplayDevicesW',
    'OpenSCManagerW', 'OpenServiceA', 'CloseServiceHandle', 'RegOpenKeyExA', 'RegQueryValueExA',
    'RegCloseKey', 'DeviceIoControl'))
_POINTER_RESULTS = frozenset(('GetModuleHandleW', 'GetProcAddress', 'CreateFileA', 'OpenSCManagerW', 'OpenServiceA', 'CPUID'))
_ROLES = frozenset(('HEADER', 'PROFILE_NONCE', 'CHECKPOINT_NONCE', 'TIME', 'DIRECTORY',
                   'CHECKPOINT', 'PROFILE', 'PUBLIC', 'HARDWARE', 'CLASSIFICATION', 'ERROR'))


def _need(value, message):
    if not value:
        raise InputError('device source ' + message)


def _uint(value, width=32):
    _need(type(value) is int and 0 <= value < 1 << width, 'requires an unsigned scalar of its actual width')
    return value


def _identity(value):
    _need(type(value) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]{0,127}', value) is not None,
          'identity must be an opaque semantic reference')
    return value


def _immutable(value):
    if type(value) is tuple:
        _need(len(value) <= 4096, 'tuple exceeds its finite domain')
        return sum(_immutable(item) for item in value)
    _need(value is None or type(value) in (str, int, bool, bytes), 'rows require immutable raw values')
    if type(value) is bytes:
        _need(len(value) <= _LIMIT, 'raw buffer exceeds its supported domain')
        return len(value)
    if type(value) is str:
        _need(len(value) <= 128 and value.isascii(), 'text must be a bounded semantic reference')
    return 0


def require_device_source_binding(runtime):
    observer = getattr(runtime, '_device_source_binding', None)
    if observer is None:
        observer = getattr(runtime, 'device_source_observations', None)
    if observer is not None:
        _need(isinstance(observer, DeviceSourceObservations), 'bound source has the wrong owner type')
        observer.require_route(runtime)
    return observer


def take_device_source_observation(runtime, api, arguments):
    observer = require_device_source_binding(runtime)
    return (observer if observer is not None else runtime.worker_observations).take(runtime, api, arguments)


@dataclass(frozen=True)
class DeviceSourceRow:
    ordinal: int
    api: str
    role: str
    arguments: tuple
    result: int | None
    output: object = b''

    def __post_init__(self):
        _need(type(self.ordinal) is int and 0 <= self.ordinal < 4096, 'ordinal is outside its finite generation')
        _need(self.api in _APIS and self.role in _ROLES and type(self.arguments) is tuple, 'API/role/argument shape is unsupported')
        if self.api in _POINTER_RESULTS:
            _need(self.result is None, 'native pointer/CPUID result must not be injected')
        else:
            _uint(self.result, 64 if self.api == 'VerSetConditionMask' else 32)
        _immutable(self.arguments)
        _immutable(self.output)


@dataclass(frozen=True)
class DeviceSourceInputs:
    generation: str
    source_thread: str
    owner: str
    rows: tuple

    def __post_init__(self):
        for value in (self.generation, self.source_thread, self.owner):
            _identity(value)
        _need(type(self.rows) is tuple and len(self.rows) <= 4096, 'generation requires its finite immutable rows')
        _need(all(isinstance(row, DeviceSourceRow) and row.ordinal == index for index, row in enumerate(self.rows)),
              'rows require contiguous source order')
        _need(sum(_immutable(row.arguments) + _immutable(row.output) for row in self.rows) <= 16 * _LIMIT, 'generation raw input budget exceeded')


class DeviceSourceObservations(WorkerObservations):
    def __init__(self, inputs, delegate=None):
        _need(isinstance(inputs, DeviceSourceInputs), 'requires typed source-only inputs')
        self.inputs = inputs
        self._local_owner = os.getpid(), threading.get_native_id()
        self._runtime = None
        self._cursor = 0
        self._closed = self._failed = False
        self._refs, self._tokens = {}, {}
        self._next_token = 0x7000000000000000
        self._root = None
        self._lookup = 0
        self._rand_counts = dict(HEADER=0, PROFILE_NONCE=0, CHECKPOINT_NONCE=0)
        self._hashes, self._export_sizes = {}, {}
        self._descriptor = None
        self.writes = []
        self._delegates = {}
        self.set_delegate(delegate)

    def _check(self, runtime=None, *, device=True):
        _need(self._local_owner[0] == os.getpid() and not self._closed and
              (not device or self._local_owner[1] == threading.get_native_id()),
              'observer requires its open creating process/device native thread')
        if runtime is not None:
            _need(runtime is self._runtime and getattr(runtime, 'device_source_observations', None) is self,
                  'observer runtime/binding is stale')
        if self._failed:
            raise PrimarySemanticUnavailable('device source observer stopped after an incomplete event')

    def bind(self, runtime, *, generation, source_thread, owner):
        self._check()
        _need(self._runtime is None and getattr(runtime, 'device_source_observations', None) is None and
              getattr(runtime, '_device_source_binding', None) is None,
              'observer requires one fresh runtime binding')
        _need((generation, source_thread, owner) == (self.inputs.generation, self.inputs.source_thread, self.inputs.owner),
              'generation/source-thread/owner binding differs from its source')
        self._runtime = runtime
        runtime.device_source_observations = self
        runtime._device_source_binding = self
        return self

    def require_route(self, runtime):
        try:
            self._check(runtime)
            _need(getattr(runtime, '_device_source_binding', None) is self and
                  getattr(runtime, 'worker_observations', None) is self,
                  'bound source worker routing was replaced')
        except BaseException:
            self._failed = True
            raise

    def set_delegate(self, delegate):
        self._check(device=False)
        _need(delegate is None or delegate is not self and callable(getattr(delegate, 'take', None)), 'delegate is invalid')
        self._delegates[threading.get_native_id()] = delegate
        return self

    def _row(self, api, role, arguments):
        self.require_route(self._runtime)
        if self._cursor >= len(self.inputs.rows):
            raise UnknownMemory('missing actual device source event: ' + api)
        row = self.inputs.rows[self._cursor]
        _need((row.api, row.role, row.arguments) == (api, role, arguments), 'API/role/arguments differ from the next source event')
        self._cursor += 1
        return row

    def _new(self, ref, kind, parent=None, **extra):
        _identity(ref)
        _need(ref not in self._refs, 'opaque reference was reused')
        token = self._next_token
        self._next_token += 16
        self._refs[ref] = token
        self._tokens[token] = dict(ref=ref, kind=kind, parent=parent, live=True, **extra)
        return token

    def _handle(self, token, kinds):
        _uint(token, 64)
        item = self._tokens.get(token)
        _need(item is not None and item['live'] and not item.get('release_attempted') and item['kind'] in kinds, 'foreign/closed/wrong-role handle')
        if item['parent'] is not None:
            _need(self._tokens[item['parent']]['live'] and not self._tokens[item['parent']].get('release_attempted'), 'handle provider lifetime ended')
        return item

    def _ref(self, token, kinds):
        return self._handle(token, kinds)['ref']

    def _retire(self, token, closed):
        self._tokens[token]['release_attempted'] = True
        self._tokens[token]['live'] = not closed

    def _effect(self, pointer, capacity, raw):
        _need(type(raw) is tuple, 'sparse outputs require relative offset/bytes pairs')
        output = []
        for offset, value in raw:
            _need(type(offset) is int and isinstance(value, bytes) and 0 <= offset <= capacity and len(value) <= capacity - offset,
                  'sparse output leaves its actual buffer')
            self._runtime.memory._span(pointer + offset, len(value))
            output.append((pointer + offset, value))
        return tuple(output)

    def _path(self, raw):
        _need(isinstance(raw, bytes) and raw.endswith(b'\0') and b'\0' not in raw[:-1] and self._root is not None,
              'file path lacks its observed raw Shell provenance')
        root = self._root + (b'' if self._root.endswith(b'\\') else b'\\') + b'xfolder'
        paths = {root + b'\0': 'DIRECTORY', root + b'\\checkpoint.dat\0': 'CHECKPOINT', root + b'\\profile.dat2\0': 'PROFILE'}
        _need(raw in paths, 'file path differs from independently derived source root/xfolder/file')
        return paths[raw]

    def device_rand_s(self, runtime, destination, role):
        self.require_route(runtime)
        _need(getattr(runtime, '_device_core_active', False) is True and role in self._rand_counts, 'rand_s leaves its actual device event boundary')
        try:
            index = self._rand_counts[role]
            _need(role != 'HEADER' or index < 5, 'header rand_s count exceeds five')
            row = self._row('rand_s', role, (index,))
            _need(isinstance(row.output, bytes) and len(row.output) == 4, 'rand_s requires all four actually observed output bytes')
            runtime.memory.write(destination, row.output, source='device.source.rand_s.actual_output')
            self._rand_counts[role] = index + 1
            runtime.events.append(('device.source.rand_s', role, index, row.result, row.output))
            return row.result
        except BaseException:
            self._failed = True
            raise

    def take(self, runtime, api, arguments):
        self._check(runtime, device=False)
        if not getattr(runtime, '_device_core_active', False) or api not in _APIS:
            delegate = self._delegates.get(threading.get_native_id())
            if delegate is None:
                raise PrimarySemanticUnavailable('nondevice domain requires its original observation delegate: ' + api)
            return delegate.take(runtime, api, arguments)
        try:
            self.require_route(runtime)
            _need(type(arguments) is tuple and api != 'rand_s', 'device API requires its finite argument boundary')
            return self._take(runtime, api, arguments)
        except BaseException:
            self._failed = True
            raise

    def _take(self, runtime, api, a):
        memory = runtime.memory
        if api == '_ftime64_s':
            row = self._row(api, 'TIME', a)
            _need(a == () and isinstance(row.output, bytes) and len(row.output) <= 14, 'CRT output shape')
            return row.result, row.output
        if api == 'SHGetSpecialFolderPathA':
            _need(a == (0, 35, 1), 'Shell fixed arguments')
            row = self._row(api, 'DIRECTORY', a)
            _need(isinstance(row.output, bytes) and len(row.output) <= 260, 'Shell raw ANSI output')
            if row.result:
                end = row.output.find(b'\0')
                _need(0 < end < 260, 'successful Shell output lacks its known ANSI terminator')
                self._root = row.output[:end]
            return row.result, row.output
        if api in ('GetFileAttributesA', 'CreateDirectoryA'):
            _need(len(a) == 1, 'directory API arguments')
            role = self._path(a[0])
            _need(api != 'CreateDirectoryA' or role == 'DIRECTORY', 'directory creation role')
            row = self._row(api, role, (role,))
            _need(row.output == b'', 'directory scalar output')
            return row.result, b''
        if api == 'CreateFileA' and len(a) == 5:
            role = self._path(a[0])
            _need(role in ('PROFILE', 'CHECKPOINT') and a[1:] in ((0x80000000, 1, 3, 2), (0x40000000, 0, 1, 2), (0x40000000, 0, 2, 2)), 'device file open role/flags')
            _need(a[3] != 1 or role == 'PROFILE', 'CREATE_NEW requires profile')
            row = self._row(api, role, (role,) + a[1:])
            return (_MASK if row.output is None else self._new(row.output, 'file', role=role, access=a[1])), b''
        if api in ('GetFileSize', 'ReadFile', 'WriteFile', 'CloseHandle') and a and a[0] in self._tokens and self._tokens[a[0]]['kind'] == 'file':
            item = self._handle(a[0], ('file',))
            role, ref = item['role'], item['ref']
            if api in ('GetFileSize', 'CloseHandle'):
                _need(len(a) == 1, 'file scalar arguments')
                row = self._row(api, role, (ref,))
                _need(row.output == b'', 'file scalar output')
                if api == 'CloseHandle':
                    self._retire(a[0], row.result != 0)
                return row.result, b''
            _need(len(a) == 2, 'file I/O arguments')
            if api == 'ReadFile':
                _need(item['access'] == 0x80000000 and a[1] == (50 if role == 'PROFILE' else 1028), 'source read role/capacity')
                row = self._row(api, role, (ref, a[1]))
                _need(type(row.output) is tuple and len(row.output) == 2, 'raw read output/count')
                raw, count = row.output
                _need(isinstance(raw, bytes) and type(count) is int and 0 <= count <= len(raw) <= a[1], 'incomplete/out-of-bounds read output')
                return row.result, row.output
            _need(item['access'] == 0x40000000 and isinstance(a[1], bytes) and len(a[1]) == (50 if role == 'PROFILE' else 1028), 'source write role/count')
            row = self._row(api, role, (ref, len(a[1])))
            _need(type(row.output) is int and 0 <= row.output <= len(a[1]), 'write requires its actual DWORD count')
            self.writes.append((role, len(a[1]), hashlib.sha256(a[1]).hexdigest(), row.result, row.output))
            return row.result, row.output
        if api == 'GetLastError':
            row = self._row(api, 'ERROR', a)
            _need(a == () and row.output == b'', 'last error scalar shape')
            return row.result, b''
        if api in ('VerSetConditionMask', 'VerifyVersionInfoW'):
            if api == 'VerSetConditionMask':
                _need(len(a) == 3 and a[1:] in ((2, 3), (1, 3)), 'version condition arguments')
                canonical = a
            else:
                _need(len(a) == 3 and isinstance(a[0], bytes) and len(a[0]) == 284 and a[1] == 3, 'version structure/arguments')
                expected = bytearray(284)
                for offset, value in ((0, 284), (4, 5), (8, 1)):
                    expected[offset:offset + 4] = value.to_bytes(4, 'little')
                _need(a[0] == bytes(expected), 'version source structure differs')
                canonical = (5, 1, 3, a[2])
            row = self._row(api, 'PUBLIC', canonical)
            _need(row.output == b'', 'version scalar output')
            return row.result, b''
        if api.startswith('Crypt') or api in ('InitializeSecurityDescriptor', 'SetSecurityDescriptorDacl'):
            return self._capi(runtime, api, a)
        if api in ('GetModuleHandleW', 'GetProcAddress', 'CPUID', 'NtQuerySystemInformation', 'NtOpenDirectoryObject',
                   'NtQueryDirectoryObject', 'NtClose', 'GetVolumeInformationW', 'UuidCreateSequential', 'EnumDisplayDevicesW'):
            return self._hardware(runtime, api, a)
        return self._classification(runtime, api, a)

    def _capi(self, runtime, api, a):
        role = 'PUBLIC'
        if api in ('CryptAcquireContextA', 'CryptAcquireContextW'):
            if api == 'CryptAcquireContextA':
                _need(a in ((b'mWOLCtkGwuHtk\0', 0, 24, 0x60), (b'mWOLCtkGwuHtk\0', 0, 24, 0x68)), 'public acquire arguments')
            else:
                _need(a == (0, 0, 1, 0xF0000040), 'profile RNG acquire arguments')
                role = 'PROFILE'
            row = self._row(api, role, a)
            if row.result:
                token = self._new(row.output, 'provider', role=role)
                return row.result, token.to_bytes(8, 'little')
            _need(row.output is None or row.output == (), 'failed acquire cannot invent a handle')
            return row.result, b''
        if api in ('InitializeSecurityDescriptor', 'SetSecurityDescriptorDacl'):
            canonical = a[1:]
            _need(canonical == ((1,) if api == 'InitializeSecurityDescriptor' else (1, 0, 0)), 'security descriptor arguments')
            if api == 'InitializeSecurityDescriptor':
                self._descriptor = a[0]
            else:
                _need(a[0] == self._descriptor, 'security descriptor source allocation differs')
            row = self._row(api, role, canonical)
            raw = ((0, row.output),) if isinstance(row.output, bytes) else row.output
            self._effect(a[0], 40, raw)
            return row.result, row.output
        if api == 'CryptDestroyKey':
            _need(len(a) == 1, 'key cleanup argument count')
            ref = self._ref(a[0], ('key', 'generated'))
            row = self._row(api, role, (ref,))
            _need(row.output == b'', 'key cleanup scalar output')
            self._retire(a[0], row.result != 0)
            return row.result, b''
        if api in ('CryptHashData', 'CryptGetHashParam', 'CryptDestroyHash'):
            ref = self._ref(a[0], ('hash',))
            if api == 'CryptHashData':
                _need(len(a) == 3 and isinstance(a[1], bytes) and a[2] == 0, 'HashData actual P bytes/flags')
                row = self._row(api, role, (ref, len(a[1]), 0))
                _need(row.output == b'', 'captured hash output is not an input')
                if row.result:
                    self._hashes[a[0]].update(a[1])
                return row.result, b''
            if api == 'CryptGetHashParam':
                _need(len(a) == 4 and a[1:] == (2, 32, 0), 'GetHashParam source arguments')
                row = self._row(api, role, (ref, 2, 32, 0))
                _need(type(row.output) is tuple and len(row.output) == 1, 'hash output contains only observed length')
                size = row.output[0]
                _need(not row.result or size is not None, 'successful hash output requires its observed DWORD length')
                if size is not None:
                    _uint(size)
                raw = self._hashes[a[0]].digest() if row.result and size == 32 else b''
                return row.result, (raw, size)
            _need(len(a) == 1, 'hash cleanup argument count')
            row = self._row(api, role, (ref,))
            _need(row.output == b'', 'hash cleanup scalar output')
            self._retire(a[0], row.result != 0)
            return row.result, b''
        provider = self._handle(a[0], ('provider',))
        ref, role = provider['ref'], provider['role']
        if api == 'CryptReleaseContext':
            _need(len(a) == 2 and a[1] == 0, 'provider release arguments')
            row = self._row(api, role, (ref, 0))
            _need(row.output == b'', 'provider release scalar output')
            self._retire(a[0], row.result != 0)
            return row.result, b''
        if api == 'CryptGenRandom':
            _need(role == 'PROFILE' and a[1:] == (16,), 'profile material RNG arguments')
            row = self._row(api, role, (ref, 16))
            _need(isinstance(row.output, bytes) and len(row.output) <= 16 and (not row.result or len(row.output) == 16), 'profile material actual output')
            return row.result, row.output
        _need(role == 'PUBLIC', 'public API requires its source public provider')
        if api in ('CryptGenKey', 'CryptGetUserKey', 'CryptCreateHash'):
            tail = {'CryptGenKey': (2, 0x08000000), 'CryptGetUserKey': (2,), 'CryptCreateHash': (0x800C, 0, 0)}[api]
            _need(a[1:] == tail, 'public key/hash arguments')
            row = self._row(api, role, (ref,) + tail)
            if not row.result:
                _need(row.output is None or row.output == (), 'failed key/hash cannot invent output')
                return row.result, ()
            kind = {'CryptGenKey': 'generated', 'CryptGetUserKey': 'key', 'CryptCreateHash': 'hash'}[api]
            token = self._new(row.output, kind, a[0])
            if kind == 'hash':
                self._hashes[token] = hashlib.sha256()
            return row.result, token.to_bytes(8, 'little')
        if api == 'CryptSetProvParam':
            _need(len(a) == 4 and a[1] == 8 and a[2] == self._descriptor and a[3] == 4, 'security provider arguments')
            row = self._row(api, role, (ref, 8, 'SECURITY_DESCRIPTOR', 4))
            _need(row.output == b'', 'provider scalar output')
            return row.result, b''
        _need(api == 'CryptExportPublicKeyInfo' and len(a) == 5 and a[1:3] == (2, 0x10001), 'unsupported CAPI role')
        buffered = a[3] != 0
        row = self._row(api, role, (ref, 2, 0x10001, buffered, a[4]))
        if not buffered:
            _need(a[4] == 0 and type(row.output) is tuple and len(row.output) == 1, 'export size query output')
            size = row.output[0]
            if size is not None:
                _uint(size)
            if row.result:
                _need(type(size) is int and 48 <= size <= _LIMIT, 'public export queried size unsupported')
                self._export_sizes[a[0]] = size
            return row.result, ((), size)
        _need(a[4] == self._export_sizes.get(a[0]), 'public export capacity differs from observed query')
        if not row.result:
            _need(type(row.output) is tuple and len(row.output) == 1, 'failed export requires its observed length only')
            if row.output[0] is not None:
                _uint(row.output[0])
            return row.result, ((), row.output[0])
        _need(type(row.output) is tuple and len(row.output) == 4, 'public bits export fields')
        size, count, offset, bits = row.output
        if size is not None:
            _uint(size)
        _uint(count)
        _need(isinstance(bits, bytes) and len(bits) == count, 'public bits count/bytes differ')
        _need((count == 0 and offset is None) or type(offset) is int and 0 <= offset <= a[4] and count <= a[4] - offset, 'relative public bits leave queried allocation')
        writes = ((24, count.to_bytes(4, 'little')), (32, (0 if offset is None else a[3] + offset).to_bytes(8, 'little')))
        if count:
            _need(offset >= 48, 'public bit bytes overlap source structure fields')
            writes += ((offset, bits),)
        self._effect(a[3], a[4], writes)
        return row.result, (writes, size)

    def _hardware(self, runtime, api, a):
        memory = runtime.memory
        if api == 'CPUID':
            _need(len(a) == 2 and all(type(value) is int for value in a), 'CPUID source operands')
            role = 'CLASSIFICATION' if a == (0x40000000, 0x40000000) else 'HARDWARE'
            _need(role == 'CLASSIFICATION' or a[0] in (0x80000002, 0x80000003, 0x80000004, 0x80000005, 0, 1, 2, 0x40000000) and a[1] == 0, 'CPUID outside source leaves')
            row = self._row(api, role, a)
            _need(type(row.output) is tuple and len(row.output) == 4, 'CPUID actual four registers')
            for word in row.output:
                _uint(word)
            return None, row.output
        if api == 'GetModuleHandleW':
            _need(a == ('ntdll\0'.encode('utf-16-le'),), 'hardware module literal')
            row = self._row(api, 'HARDWARE', ('ntdll',))
            return (0 if row.output is None else self._new(row.output, 'module')), b''
        if api == 'GetProcAddress':
            _need(len(a) == 2 and self._lookup < len(_EXPORTS) and a[1] == _EXPORTS[self._lookup], 'hardware requires all eight source-ordered resolver names')
            ref = self._ref(a[0], ('module',))
            row = self._row(api, 'HARDWARE', (ref, a[1]))
            _need(type(row.output) is bool, 'resolver requires actual return presence')
            self._lookup += 1
            return (self._new('export:' + a[1].decode('ascii'), 'function') if row.output else 0), b''
        if api == 'NtQuerySystemInformation':
            _need(len(a) == 4 and (a[0], a[2], a[3]) == (1, 12, 0), 'system information source arguments')
            row = self._row(api, 'HARDWARE', (1, 12, 0))
            _need(row.result != 0 and row.output == () or row.result == 0 and type(row.output) is tuple and tuple(offset for offset, raw in row.output) == (2, 8) and all(isinstance(raw, bytes) and len(raw) == 4 for offset, raw in row.output), 'system information consumed ranges')
            return row.result, self._effect(a[1], 12, row.output)
        if api == 'GetVolumeInformationW':
            _need(len(a) == 8 and a[1:3] == (0, 0) and a[4:] == (0, 0, 0, 0) and memory.read(a[0], 8) == 'C:\\\0'.encode('utf-16-le'), 'volume source arguments')
            row = self._row(api, 'HARDWARE', ('C:\\',))
            _need(row.output is None and not row.result or isinstance(row.output, bytes) and len(row.output) == 4 and row.result, 'volume actual consumed serial')
            return row.result, () if row.output is None else self._effect(a[3], 4, ((0, row.output),))
        if api == 'UuidCreateSequential':
            _need(len(a) == 1, 'UUID source arguments')
            row = self._row(api, 'HARDWARE', ())
            _need(row.output is None and row.result != 0 or row.result == 0 and isinstance(row.output, bytes) and len(row.output) == 6, 'UUID actual consumed tail')
            return row.result, () if row.output is None else self._effect(a[0], 16, ((10, row.output),))
        if api == 'NtOpenDirectoryObject':
            _need(len(a) == 3 and a[1] == 1, 'NT directory open source arguments')
            attrs = a[2]
            _need(tuple(memory.load(attrs + offset, width) for offset, width in ((0, 4), (8, 8), (24, 4), (32, 8), (40, 8))) == (48, 0, 0, 0, 0), 'NT object attributes shape')
            name = memory.load(attrs + 16, 8)
            _need(memory.load(name, 2) == 18 and memory.load(name + 2, 2) == 20 and memory.read(memory.load(name + 8, 8), 20) == '\\GLOBAL??\0'.encode('utf-16-le'), 'NT directory source name')
            row = self._row(api, 'HARDWARE', (1, '\\GLOBAL??\0'.encode('utf-16-le')))
            if row.output is None:
                return row.result, ()
            _need(not row.result & 0x80000000, 'negative NT open cannot create an observed successful handle')
            token = self._new(row.output, 'directory')
            return row.result, self._effect(a[0], 8, ((0, token.to_bytes(8, 'little')),))
        if api == 'NtClose':
            _need(len(a) == 1, 'NT close source arguments')
            row = self._row(api, 'HARDWARE', (self._ref(a[0], ('directory',)),))
            _need(row.output == b'', 'NT close scalar output')
            self._retire(a[0], not row.result & 0x80000000)
            return row.result, ()
        if api == 'NtQueryDirectoryObject':
            _need(len(a) == 7 and a[2:4] == (4096, 0) and a[4] in (0, 1) and a[6] == 0, 'NT directory query source arguments')
            before = memory.load(a[5], 4)
            row = self._row(api, 'HARDWARE', (self._ref(a[0], ('directory',)), 4096, 0, a[4], before, 0))
            _need(type(row.output) is tuple and len(row.output) == 2, 'NT directory context/records output')
            context, records = row.output
            if row.result & 0x80000000:
                _need(context is None and records == (), 'failed NT query output is not consumed')
                return row.result, ()
            _uint(context)
            _need(type(records) is tuple and len(records) == ((context - before) & 0xFFFFFFFF) and len(records) <= 128, 'NT directory count/context differ')
            writes = []
            for index, record in enumerate(records):
                _need(type(record) is tuple and len(record) == 3, 'NT directory record shape')
                length, offset, raw = record
                _uint(length, 16)
                _need(isinstance(raw, bytes) and len(raw) == (length >> 1) * 2, 'NT directory consumed UTF16 length')
                _need((not raw and offset is None) or type(offset) is int and 0 <= offset <= 4096 and len(raw) <= 4096 - offset, 'NT directory relative name range')
                writes.extend(((index * 32, length.to_bytes(2, 'little')), (index * 32 + 8, (0 if offset is None else a[1] + offset).to_bytes(8, 'little'))))
                if raw:
                    writes.append((offset, raw))
            return row.result, self._effect(a[1], 4096, tuple(writes)) + self._effect(a[5], 4, ((0, context.to_bytes(4, 'little')),))
        _need(api == 'EnumDisplayDevicesW' and len(a) == 4 and a[3] == 0 and memory.load(a[2], 4) == 840, 'display source arguments')
        parent = None
        if a[0]:
            raw = bytearray()
            for index in range(32):
                unit = memory.read(a[0] + index * 2, 2)
                raw.extend(unit)
                if unit == b'\0\0':
                    break
            else:
                raise InputError('device source parent display lacks its source terminator')
            parent = bytes(raw)
        row = self._row(api, 'HARDWARE', (parent, a[1], 840, 0))
        if not row.result:
            _need(row.output is None, 'failed display output is not consumed')
            return row.result, ()
        _need(type(row.output) is tuple and len(row.output) == 3, 'display actual consumed fields')
        name, flags, device_id = row.output
        if parent is None:
            _need(isinstance(name, bytes) and not len(name) & 1 and 2 <= len(name) <= 64 and name.endswith(b'\0\0') and flags is None and device_id is None, 'primary display raw name')
            writes = ((4, name),)
        else:
            _uint(flags)
            _need(name is None, 'child display has no consumed name field')
            writes = ((0x144, flags.to_bytes(4, 'little')),)
            if flags & 1 and not flags & 8:
                _need(isinstance(device_id, bytes) and not len(device_id) & 1 and 2 <= len(device_id) <= 256 and device_id.endswith(b'\0\0'), 'child display consumed ID')
                writes += ((0x148, device_id),)
            else:
                _need(device_id is None, 'unconsumed child ID cannot be input')
        return row.result, self._effect(a[2], 840, writes)

    def _classification(self, runtime, api, a):
        if api == 'RegOpenKeyExA':
            from .primary_device_hypervisor import _MACHINE_VALUES
            names = tuple(key + b'\0' for key, name in _MACHINE_VALUES) + (b'SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters\0', b'SYSTEM\\CurrentControlSet\\Enum\\vDisk\\Disk0\0')
            _need(len(a) == 5 and a[0] == 0xFFFFFFFF80000002 and a[1] in names and a[2:4] == (0, 0x20119), 'classification registry open source role')
            row = self._row(api, 'CLASSIFICATION', a[:4])
            if row.output is None:
                return row.result, ()
            _need(row.result == 0, 'failed registry open must not fabricate HKEY output')
            token = self._new(row.output, 'registry')
            return row.result, self._effect(a[4], 8, ((0, token.to_bytes(8, 'little')),))
        if api == 'RegQueryValueExA':
            _need(len(a) == 6 and a[2] == 0, 'classification registry query source arguments')
            ref = self._ref(a[0], ('registry',))
            enabled = bool(a[3] or a[4] or a[5])
            _need(not enabled or all(a[3:]), 'classification registry output roles')
            canonical = (ref, a[1], 0, enabled, 8 if enabled else 0, runtime.memory.load(a[5], 4) if enabled else 0)
            row = self._row(api, 'CLASSIFICATION', canonical)
            _need(type(row.output) is tuple, 'registry sparse output shape')
            fields = dict(kind=(a[3], 4), data=(a[4], 8), size=(a[5], 4)) if enabled else {}
            effects = []
            for field, offset, raw in row.output:
                _need(field in fields, 'registry output role unsupported')
                pointer, capacity = fields[field]
                effects.extend(self._effect(pointer, capacity, ((offset, raw),)))
            return row.result, tuple(effects)
        if api in ('RegCloseKey', 'CloseServiceHandle', 'CloseHandle'):
            kinds = {'RegCloseKey': ('registry',), 'CloseServiceHandle': ('manager', 'service'), 'CloseHandle': ('disk',)}[api]
            _need(len(a) == 1, 'classification close source arguments')
            row = self._row(api, 'CLASSIFICATION', (self._ref(a[0], kinds),))
            _need(row.output == b'', 'classification close scalar output')
            self._retire(a[0], row.result == 0 if api == 'RegCloseKey' else row.result != 0)
            return row.result, ()
        if api == 'OpenSCManagerW':
            _need(a == (0, 0, 4), 'classification service manager arguments')
            row = self._row(api, 'CLASSIFICATION', a)
            return (0 if row.output is None else self._new(row.output, 'manager')), ()
        if api == 'OpenServiceA':
            _need(len(a) == 3 and a[1:] == (b'vmbusr\0', 4), 'classification service arguments')
            ref = self._ref(a[0], ('manager',))
            row = self._row(api, 'CLASSIFICATION', (ref,) + a[1:])
            return (0 if row.output is None else self._new(row.output, 'service', a[0])), ()
        if api == 'CreateFileA':
            _need(a == (b'\\\\.\\PhysicalDrive0\0', 0x100080, 1, 0, 3, 0, 0), 'classification disk open source arguments')
            row = self._row(api, 'CLASSIFICATION', a)
            return (_MASK if row.output is None else self._new(row.output, 'disk')), ()
        _need(api == 'DeviceIoControl' and len(a) == 8 and a[1] == 0x2D1400 and a[3] == 12 and a[5] == 4096 and a[7] == 0 and runtime.memory.read(a[2], 12) == bytes(12), 'classification storage query arguments')
        ref = self._ref(a[0], ('disk',))
        row = self._row(api, 'CLASSIFICATION', (ref, 0x2D1400, 12, 4096, 0))
        _need(type(row.output) is tuple and len(row.output) == 2, 'storage descriptor sparse output')
        data, count = row.output
        effects = self._effect(a[4], 4096, data)
        if count is not None:
            _uint(count)
            effects += self._effect(a[6], 4, ((0, count.to_bytes(4, 'little')),))
        return row.result, effects

    def assert_consumed(self):
        self._check(self._runtime)
        _need(self._cursor == len(self.inputs.rows), 'unconsumed source events remain')
        live = [item for item in self._tokens.values() if item['live'] and not item.get('release_attempted') and item['kind'] not in ('module', 'function') and
                not (item['kind'] == 'generated' and item['parent'] is not None and self._tokens[item['parent']].get('release_attempted'))]
        _need(not live, 'source handle lifetimes remain incomplete')
        _need(self._rand_counts['HEADER'] in (0, 5) and self._rand_counts['PROFILE_NONCE'] % 3 == 0 and self._rand_counts['CHECKPOINT_NONCE'] % 3 == 0,
              'source rand_s family count is incomplete')

    def close(self):
        _need(self._local_owner == (os.getpid(), threading.get_native_id()), 'close requires its creating process/native thread')
        self._closed = True
        self._delegates.clear()

    @property
    def diagnostics(self):
        return dict(closed=self._closed, failed=self._failed, consumed=self._cursor, total=len(self.inputs.rows),
                    live_references=sum(item['live'] and item['kind'] not in ('module', 'function') for item in self._tokens.values()),
                    unconfirmed_closes=sum(item['live'] and item.get('release_attempted', False) for item in self._tokens.values()),
                    resolver_count=self._lookup, rand_s_counts=dict(self._rand_counts), writes=tuple(self.writes))
