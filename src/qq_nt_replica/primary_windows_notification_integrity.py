import ctypes as C
import hashlib
import os
import threading

from .errors import InputError
from .primary_logger import _cstring
from .primary_memory import UnknownMemory
from .primary_notification_files import FileObservations, FileApiReply, FileApiWrite, FileApiObservation
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20
_SIGNATURES = {
    'GetModuleHandleA': ('kernel32', C.c_void_p, (C.c_void_p,)),
    'GetModuleFileNameW': ('kernel32', C.c_uint32, (C.c_void_p, C.c_void_p, C.c_uint32)),
    'PathRemoveFileSpecW': ('shlwapi', C.c_int32, (C.c_void_p,)),
    'CreateFileW': ('kernel32', C.c_void_p, (C.c_void_p, C.c_uint32, C.c_uint32, C.c_void_p, C.c_uint32, C.c_uint32, C.c_void_p)),
    'GetFileSizeEx': ('kernel32', C.c_int32, (C.c_void_p, C.c_void_p)),
    'ReadFile': ('kernel32', C.c_int32, (C.c_void_p, C.c_void_p, C.c_uint32, C.c_void_p, C.c_void_p)),
    'CloseHandle': ('kernel32', C.c_int32, (C.c_void_p,)),
    'GetLastError': ('kernel32', C.c_uint32, ()),
    'WideCharToMultiByte': ('kernel32', C.c_int32, (C.c_uint32, C.c_uint32, C.c_void_p, C.c_int32, C.c_void_p, C.c_int32, C.c_void_p, C.c_void_p)),
    'MultiByteToWideChar': ('kernel32', C.c_int32, (C.c_uint32, C.c_uint32, C.c_void_p, C.c_int32, C.c_void_p, C.c_int32)),
}


class WindowsNotificationIntegrityAPIBackend:
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise PrimarySemanticUnavailable('manifest observations require Windows AMD64')
        libraries = {name: C.WinDLL(name, use_last_error=True) for name in ('kernel32', 'shlwapi')}
        self._functions = {}
        for name, (library, result, arguments) in _SIGNATURES.items():
            function = getattr(libraries[library], name)
            function.restype, function.argtypes = result, arguments
            self._functions[name] = function
        self.last_error = None

    def call(self, name, *arguments):
        if name not in _SIGNATURES:
            raise InputError('manifest backend supports only its finite source APIs')
        result = self._functions[name](*arguments)
        self.last_error = C.get_last_error()
        return int(result or 0) & (_MASK64 if name in ('GetModuleHandleA', 'CreateFileW') else 0xFFFFFFFF)


def _wcontents(raw):
    if not isinstance(raw, bytes) or len(raw) & 1:
        raise InputError('manifest native path requires exact UTF16 units')
    for offset in range(0, len(raw), 2):
        if raw[offset:offset + 2] == b'\0\0':
            return raw[:offset]
    raise InputError('manifest native path is not terminated')


def _guest_path(runtime, pointer):
    for count in range(1, _LIMIT // 2):
        if runtime.memory.load(pointer + (count - 1) * 2, 2) == 0:
            return runtime.memory.read(pointer, count * 2)
    raise PrimaryProgramLimit('manifest file path exceeds its bounded source String')


class WindowsNotificationIntegrityService(FileObservations):
    def __init__(self, observer, backend=None):
        self.observer, self.backend = observer, backend
        self._owner = os.getpid(), threading.get_native_id()
        self._active = None
        self._module = None
        self._path = None
        self._directory = None
        self._allowed = set()
        self._files = {}
        self._prior = None
        self._installed = False
        self._conversion = None
        self._closed = False
        self.records = []
        self._last_error_pending = False

    def _check(self, runtime):
        if self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('manifest service requires its open creating process/native thread')
        self.observer._check(runtime)

    def begin(self, runtime, rva):
        self._check(runtime)
        if rva not in (0x35AA260, 0x35B3FE0) or self._active is not None or self._files:
            raise InputError('manifest service requires one fresh finite producer role')
        self._active = rva
        self._stage = 'module' if rva == 0x35AA260 else 'filename'
        self._module = self._path = self._directory = self._conversion = None
        self._allowed.clear()
        self._last_error_pending = False
        self._prior = getattr(runtime, 'notification_file_observations', None)
        self._installed = self._prior is None
        if self._installed:
            runtime.notification_file_observations = self
        elif not isinstance(self._prior, FileObservations):
            self._active = None
            raise InputError('manifest existing file source must retain its typed observation contract')
        from .primary_notification_files import _install_shared_file_allocator
        self._selector_owner = _install_shared_file_allocator(runtime, self)

    def end(self, runtime, rva):
        self._check(runtime)
        if rva != self._active:
            raise InputError('manifest service exit differs from its active producer role')
        if self._files:
            raise PrimarySemanticUnavailable('manifest producer left unresolved native file ownership')
        if self._installed:
            if getattr(runtime, 'notification_file_observations', None) is not self:
                raise InputError('manifest file source was replaced during its producer')
            runtime.notification_file_observations = self._prior
        self._active = self._module = self._path = self._directory = self._conversion = None
        self._allowed.clear()
        self._installed = False

    def _call(self, name, arguments, *, pointer=False):
        if self.backend is None:
            self.backend = WindowsNotificationIntegrityAPIBackend()
        result = self.backend.call(name, *arguments)
        if type(result) is not int or not 0 <= result <= (_MASK64 if pointer else 0xFFFFFFFF):
            raise InputError('manifest API backend returned an invalid typed result')
        self.records.append(dict(api=name, role=f'{self._active:X}' if self._active else 'cleanup',
                                 result=int(bool(result)) if pointer else result,
                                 last_error=getattr(self.backend, 'last_error', None)))
        if len(self.records) > 4096:
            self.records.pop(0)
        return result

    def _summary_buffer(self, role, raw, *, defined):
        self.records[-1].setdefault('buffers', []).append(dict(role=role, size=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(), defined_count=defined))

    def module_api(self, runtime, name, arguments):
        self._check(runtime)
        if self._active is None or not isinstance(arguments, tuple):
            raise InputError('manifest module API requires its active exact source role')
        if name == 'GetModuleHandleA':
            if self._stage != 'module' or arguments != (b'QQNT.dll\0',):
                raise InputError('manifest module lookup is limited to genuine QQNT.dll presence')
            raw = C.create_string_buffer(arguments[0], len(arguments[0]))
            result = self._call(name, (raw,), pointer=True)
            self._module = result
            self._stage = 'filename' if result else 'done'
            return result, b''
        if name == 'GetModuleFileNameW':
            if self._stage != 'filename' or len(arguments) != 2 or arguments[1] != 260 or any(type(value) is not int for value in arguments):
                raise InputError('manifest module path requires its observed handle and capacity260')
            module = arguments[0]
            if self._active == 0x35AA260:
                if not self._module or module != self._module:
                    raise InputError('manifest QQNT.dll handle differs from the actual borrowed lookup')
                native = module
            else:
                if module != runtime.image_base or self.observer._capability is None:
                    raise InputError('manifest image-base path requires its genuine owned-image capability')
                native_args, capability = self.observer._provider.filename_w_relocation(runtime, arguments, self.observer._capability)
                native = native_args[0]
            backing = C.create_string_buffer(520)
            result = self._call(name, (native, backing, 260))
            self._summary_buffer('module-path', backing.raw, defined=520)
            self._path = backing.raw
            self._stage = 'directory' if 1 <= result <= 259 else 'done'
            return result, backing.raw
        if name == 'PathRemoveFileSpecW':
            if self._stage != 'directory' or arguments != (self._path,):
                raise InputError('manifest directory must mutate its actual observed module path')
            _wcontents(self._path)
            backing = C.create_string_buffer(self._path, 520)
            result = self._call(name, (backing,))
            self._summary_buffer('directory-in-place', backing.raw, defined=520)
            if result:
                self._directory = _wcontents(backing.raw)
                names = ('version.json', 'QQNT.dll') if self._active == 0x35AA260 else (
                    'application.json', 'wrapper.node', 'application.asar', 'major.node', 'package.json')
                self._allowed = {self._directory + ('\\' + value).encode('utf-16-le') + b'\0\0' for value in names}
                self._allowed.add(self._directory + b'\\\0\0\0')
            self._stage = 'files' if result else 'done'
            return result, backing.raw
        if name not in ('WideCharToMultiByte', 'MultiByteToWideChar') or self._stage != 'files':
            raise InputError('manifest service does not expose an arbitrary API role')
        wide = name == 'WideCharToMultiByte'
        if len(arguments) != (8 if wide else 6):
            raise InputError('manifest conversion requires its exact source ABI tuple')
        page, flags, raw, count, output, capacity = arguments[:6]
        if (type(page) is not int or page != 0 or type(flags) is not int or flags != 0 or count != -1 or
                type(output) is not bool or type(capacity) is not int or not 0 <= capacity <= _LIMIT or
                wide and arguments[6:] != (0, 0)):
            raise InputError('manifest conversion requires source ACP0, flags0, terminated input and no fallback flags')
        if wide:
            if raw not in self._allowed:
                raise InputError('manifest narrow path conversion leaves its actual module directory/files')
        else:
            names = (b'version.json', b'QQNT.dll') if self._active == 0x35AA260 else (
                b'application.json', b'wrapper.node', b'application.asar', b'major.node', b'package.json')
            if raw not in tuple(value + b'\0' for value in names):
                raise InputError('manifest wide conversion requires a finite source field/global name')
        source = C.create_string_buffer(raw, len(raw))
        if not output:
            if capacity or self._conversion is not None:
                raise InputError('manifest conversion size role is stale or mismatched')
            destination = None
        else:
            if self._conversion != (name, raw, capacity) or capacity == 0:
                raise InputError('manifest conversion output role differs from its actual size query')
            destination = C.create_string_buffer(capacity * (1 if wide else 2))
        native = (page, flags, source, -1, destination, capacity) + ((None, None) if wide else ())
        result = self._call(name, native)
        self._conversion = (name, raw, result) if not output and 0 < result < 0x80000000 else None
        if destination is not None:
            self._conversion = None
            self._summary_buffer('conversion', destination.raw, defined=len(destination.raw))
        return result, b'' if destination is None else destination.raw

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if self._stage != 'files' or self._active is None or not self._installed or runtime.notification_file_observations is not self:
            raise InputError('manifest file API requires its original active installed source')
        writes = []
        if name == 'GetCommandLineA':
            if arguments != ():
                raise InputError('file selector command line takes no arguments')
            from .primary_windows_command_line import capture_file_selector
            result = capture_file_selector(self, runtime, self._selector_owner)
        elif name == 'CreateFileW':
            if len(arguments) != 7 or arguments[1:] != (0x80000000, 1, 0, 3, 0x80, 0) or self._files:
                raise InputError('manifest file open requires its one read-only source handle')
            raw = _guest_path(runtime, arguments[0])
            if raw not in self._allowed:
                raise InputError('manifest file open leaves its genuine source module directory')
            backing = C.create_string_buffer(raw, len(raw))
            result = self._call(name, (backing, *arguments[1:]), pointer=True)
            if result != _MASK64:
                if not result:
                    raise PrimarySemanticUnavailable('manifest CreateFileW returned an unexplained NULL handle')
                self._files[result] = dict(reads=0, sized=False)
            self._last_error_pending = result == _MASK64
        elif name == 'GetLastError':
            if arguments or not self._last_error_pending:
                raise InputError('manifest last-error role lacks its actual preceding failed source call')
            result = self._call(name, ())
            self._last_error_pending = False
        else:
            if not arguments or arguments[0] not in self._files:
                raise InputError('manifest file API requires its actual live owned handle')
            handle = arguments[0]
            record = self._files[handle]
            if name == 'GetFileSizeEx':
                if len(arguments) != 2 or record['sized'] or record['reads']:
                    raise InputError('manifest file size requires its fresh manifest-read role')
                record['sized'] = True
                backing = C.create_string_buffer(b'\xA5' * 8, 8)
                result = self._call(name, (handle, backing))
                self._summary_buffer('file-size', backing.raw, defined=8 if result else 0)
                if result:
                    writes.append(FileApiWrite('size', 0, backing.raw))
                self._last_error_pending = not result
            elif name == 'ReadFile':
                if len(arguments) != 5 or arguments[4] != 0 or type(arguments[2]) is not int or not 0 <= arguments[2] <= _LIMIT:
                    raise InputError('manifest file read requires its bounded synchronous source buffer')
                if record['reads'] >= 65536:
                    raise PrimaryProgramLimit('manifest native read call budget exhausted')
                record['reads'] += 1
                capacity = arguments[2]
                backing = C.create_string_buffer(b'\xA5' * capacity, max(1, capacity))
                count = C.create_string_buffer(b'\xA5' * 4, 4)
                result = self._call(name, (handle, backing, capacity, count, None))
                size = int.from_bytes(count.raw, 'little')
                if result and size > capacity:
                    raise InputError('manifest native read count exceeds its actual capacity')
                if result:
                    writes.extend((FileApiWrite('data', 0, backing.raw[:size]), FileApiWrite('count', 0, count.raw)))
                else:
                    for index, value in enumerate(backing.raw[:capacity]):
                        if value != 0xA5:
                            writes.append(FileApiWrite('data', index, bytes([value])))
                    for index, value in enumerate(count.raw):
                        if value != 0xA5:
                            writes.append(FileApiWrite('count', index, bytes([value])))
                self._summary_buffer('read-data', backing.raw[:capacity], defined=size if result else sum(value != 0xA5 for value in backing.raw[:capacity]))
                self._summary_buffer('read-count', count.raw, defined=4 if result else sum(value != 0xA5 for value in count.raw))
                self._last_error_pending = not result
            elif name == 'CloseHandle':
                if len(arguments) != 1:
                    raise InputError('manifest source close requires exactly its owned file handle')
                result = self._call(name, (handle,))
                if result:
                    del self._files[handle]
                self._last_error_pending = False
            else:
                raise InputError('manifest file service does not expose arbitrary filesystem APIs')
        reply = FileApiReply(result, tuple(writes))
        FileApiObservation(name, arguments, reply)
        return reply

    def close(self):
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('manifest cleanup requires its creating process/native thread')
        for handle in tuple(self._files):
            if self._call('CloseHandle', (handle,)):
                del self._files[handle]
        if self._files:
            raise PrimarySemanticUnavailable('manifest native file cleanup retained failed owned handles')
        runtime = self.observer._runtime
        if self._installed:
            if getattr(runtime, 'notification_file_observations', None) is not self:
                raise InputError('manifest file ownership was replaced before cleanup')
            runtime.notification_file_observations = self._prior
        self._active = self._module = self._path = self._directory = self._conversion = None
        self._prior = None
        self._allowed.clear()
        self._closed = True

    @property
    def resource_count(self):
        return len(self._files)
