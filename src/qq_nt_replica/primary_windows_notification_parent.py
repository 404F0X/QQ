from contextlib import contextmanager
import ctypes as C
import os
import sys
import threading

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable


_MASK = (1 << 64) - 1
_LIMIT = 1 << 20
_SIGNATURES = {
    'GetCommandLineA': ('kernel32', C.c_void_p, ()),
    'GetCurrentDirectoryA': ('kernel32', C.c_uint32, (C.c_uint32, C.c_void_p)),
    'EnumWindows': ('user32', C.c_int32, (C.c_void_p, C.c_ssize_t)),
    'GetCurrentProcessId': ('kernel32', C.c_uint32, ()),
    'GetWindowThreadProcessId': ('user32', C.c_uint32, (C.c_void_p, C.c_void_p)),
    'IsWindowVisible': ('user32', C.c_int32, (C.c_void_p,)),
    'GetClassNameA': ('user32', C.c_int32, (C.c_void_p, C.c_void_p, C.c_int32)),
    'GetWindowTextA': ('user32', C.c_int32, (C.c_void_p, C.c_void_p, C.c_int32)),
    'CreateToolhelp32Snapshot': ('kernel32', C.c_void_p, (C.c_uint32, C.c_uint32)),
    'Process32FirstW': ('kernel32', C.c_int32, (C.c_void_p, C.c_void_p)),
    'Process32NextW': ('kernel32', C.c_int32, (C.c_void_p, C.c_void_p)),
    'CloseHandle': ('kernel32', C.c_int32, (C.c_void_p,)),
    'PathRemoveExtensionW': ('shlwapi', None, (C.c_void_p,)),
    'IsDBCSLeadByte': ('kernel32', C.c_int32, (C.c_ubyte,)),
    'MultiByteToWideChar': ('kernel32', C.c_int32, (C.c_uint32, C.c_uint32, C.c_void_p, C.c_int32, C.c_void_p, C.c_int32)),
    'WideCharToMultiByte': ('kernel32', C.c_int32, (C.c_uint32, C.c_uint32, C.c_void_p, C.c_int32, C.c_void_p, C.c_int32, C.c_void_p, C.c_void_p)),
    'FindFirstFileA': ('kernel32', C.c_void_p, (C.c_void_p, C.c_void_p)),
    'FindNextFileA': ('kernel32', C.c_int32, (C.c_void_p, C.c_void_p)),
    'FindClose': ('kernel32', C.c_int32, (C.c_void_p,)),
    'SHGetFolderPathA': ('shell32', C.c_int32, (C.c_void_p, C.c_int32, C.c_void_p, C.c_uint32, C.c_void_p)),
    'SHGetSpecialFolderPathA': ('shell32', C.c_int32, (C.c_void_p, C.c_void_p, C.c_int32, C.c_int32)),
    'GetPrivateProfileStringA': ('kernel32', C.c_uint32, (C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p, C.c_uint32, C.c_void_p)),
}


class WindowsNotificationParentAPIBackend:
    def __init__(self):
        self.functions = None
        self.reader = None
        self.command_pointer = None

    def _resolve(self):
        if self.functions is not None:
            return
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise PrimarySemanticUnavailable('notification parent raw backend requires Windows AMD64')
        libraries = {name: C.WinDLL(name, use_last_error=True) for name in ('kernel32', 'user32', 'shlwapi', 'shell32')}
        functions = {}
        for name, (library, result, arguments) in _SIGNATURES.items():
            function = getattr(libraries[library], name)
            function.restype, function.argtypes = result, arguments
            functions[name] = function
        reader = libraries['kernel32'].ReadProcessMemory
        reader.restype = C.c_int32
        reader.argtypes = (C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p)
        self.functions, self.reader = functions, reader

    def call(self, name, *arguments):
        if name not in _SIGNATURES:
            raise InputError('notification parent backend API is outside its finite domain')
        self._resolve()
        result = self.functions[name](*arguments)
        if name == 'PathRemoveExtensionW':
            return None
        value = int(result or 0) & (_MASK if name in ('GetCommandLineA', 'CreateToolhelp32Snapshot', 'FindFirstFileA') else 0xFFFFFFFF)
        if name == 'GetCommandLineA':
            self.command_pointer = value
        return value

    def enum_windows(self, callback, parameter):
        self._resolve()
        function = C.WINFUNCTYPE(C.c_int32, C.c_void_p, C.c_ssize_t)(callback)
        return self.call('EnumWindows', function, C.c_ssize_t(parameter).value)

    def command_line_bytes(self, address, maximum):
        if type(address) is not int or address == 0 or address != self.command_pointer or not 0 < maximum <= _LIMIT:
            raise InputError('borrowed command line read requires its actual API pointer')
        self._resolve()
        result = bytearray()
        for offset in range(maximum):
            byte, count = C.c_ubyte(), C.c_size_t()
            if address > _MASK - offset or not self.reader(C.c_void_p(-1), address + offset, C.byref(byte), 1, C.byref(count)) or count.value != 1:
                raise PrimarySemanticUnavailable('borrowed command line current-process read failed or was short')
            result.append(byte.value)
            if not byte.value:
                return bytes(result)
        raise PrimarySemanticUnavailable('borrowed command line has no bounded NUL')


class _OutputBuffer:
    def __init__(self, runtime, address, size):
        if type(address) is not int or type(size) is not int or not 0 < size <= _LIMIT:
            raise InputError('parent raw output requires a bounded actual source span')
        region, offset = runtime.memory._span(address, size)
        self.address, self.size = address, size
        self.known = bytes(region.initialized[offset:offset + size])
        self.initial = bytes(region.data[offset + index] if self.known[index] else 0 for index in range(size))
        self.buffer = C.create_string_buffer(self.initial, size)

    def effects(self, defined=()):
        raw = self.buffer.raw
        mask = bytearray(int(self.known[index] or raw[index] != self.initial[index]) for index in range(self.size))
        for offset, size in defined:
            if type(offset) is not int or type(size) is not int or offset < 0 or size < 0 or offset + size > self.size:
                raise InputError('parent raw API-defined write exceeds its actual output span')
            mask[offset:offset + size] = b'\1' * size
        writes, index = [], 0
        while index < self.size:
            if not mask[index]:
                index += 1
                continue
            end = index + 1
            while end < self.size and mask[end]:
                end += 1
            writes.append((self.address + index, raw[index:end]))
            index = end
        return tuple(writes)


def _terminated(raw, unit=1, maximum=None):
    if not isinstance(raw, bytes) or len(raw) % unit:
        raise InputError('parent raw CString requires complete explicit units')
    stop = len(raw) if maximum is None else min(maximum, len(raw))
    for offset in range(0, stop, unit):
        if raw[offset:offset + unit] == bytes(unit):
            return raw[:offset + unit]
    raise UnknownMemory('parent raw API did not establish its bounded CString terminator')


def _guest_cstring(runtime, address, unit=1):
    value = bytearray()
    for offset in range(0, _LIMIT, unit):
        current = runtime.memory.read(address + offset, unit)
        value.extend(current)
        if current == bytes(unit):
            return bytes(value)
    raise PrimarySemanticUnavailable('parent source CString exceeds its finite raw boundary')


def _source(code, runtime, **arguments):
    frame = sys._getframe(1)
    while frame is not None:
        values = frame.f_locals
        if frame.f_code is code and values.get('runtime') is runtime and all(values.get(key) == value for key, value in arguments.items()):
            return frame
        frame = frame.f_back
    return None


from .primary_notification_collectors import AccountsObservations, AccountsApiReply, AccountsApiObservation
from .primary_notification_accounts import IniObservations, IniApiReply, IniRawWrite
from .primary_worker import WorkerObservations


class _AccountsAdapter(AccountsObservations):
    def __init__(self, service):
        super().__init__(())
        self.service = service

    def take(self, runtime, name, arguments):
        return self.service.take_accounts(runtime, name, arguments)


class _IniAdapter(IniObservations):
    def __init__(self, service):
        super().__init__(())
        self.service = service

    def take(self, runtime, name, arguments):
        return self.service.take_ini(runtime, name, arguments)


class _ConversionAdapter(WorkerObservations):
    def __init__(self, service):
        super().__init__(())
        self.service = service

    def take(self, runtime, name, arguments):
        return self.service.take_conversion(runtime, name, arguments)


class WindowsNotificationParentObservations:
    def __init__(self, parent, owner, runtime, *, backend=None):
        self.parent, self.owner, self.runtime = parent, owner, runtime
        self.backend = backend
        self.thread = os.getpid(), threading.get_ident(), threading.get_native_id()
        self.generation = runtime._main_generation
        self.session, self.binding = parent._session, parent._binding
        self.claim, self.view = None, None
        self.closed = self.entered = self.consumed = False
        self.calling = False
        self.snapshots, self.finds, self.regions = {}, {}, []
        self.enumeration, self.window = None, None
        self.command_seen = self.directory_seen = False
        self.queries, self.folder_roots, self.profile_paths = {}, {}, set()
        self.ini_count = 0
        self.ini_pending = None
        self.enumerated = set()
        self.process_seen = False
        self.records = []
        self.accounts, self.ini, self.conversions = _AccountsAdapter(self), _IniAdapter(self), _ConversionAdapter(self)
        self._check(runtime)
        self.view = parent._provider.notification_view(runtime, owner)

    def _check(self, runtime):
        from .primary_direct_scopes import PrimaryDirectScope
        from .primary_notification_parent import _ParentClaim
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        from .primary_windows_notification_environment import WindowsNotificationEnvironmentObservations
        if (self.closed or runtime is not self.runtime or type(self.owner) is not _NotificationWorkerOwner or
                not self.owner.valid() or self.owner.runtime is not runtime or
                self.thread != (os.getpid(), threading.get_ident(), threading.get_native_id()) or
                runtime._main_generation != self.generation or
                type(self.parent) is not WindowsNotificationEnvironmentObservations or self.parent._closed or
                self.parent._runtime is not runtime or self.parent._session != self.session or self.parent._binding != self.binding):
            raise PrimarySemanticUnavailable('parent raw service lost its real notification lifetime')
        scope = runtime.__dict__.get('_primary_direct_scope')
        if type(scope) is not PrimaryDirectScope or scope.notification_owner is not self.owner:
            raise InputError('parent raw service lacks its exact direct scope')
        claim = scope.require_parent_phase()
        if type(claim) is not _ParentClaim or claim.owner is not self.owner or claim.runtime is not runtime or not claim.valid():
            raise InputError('parent raw service lacks its actual source phase')
        if self.claim is None:
            self.claim = claim
        elif self.claim is not claim:
            raise InputError('parent raw service cannot move to another phase')
        if self.view is not None:
            self.view.check(runtime)
        return claim

    def _installed(self, runtime):
        self._check(runtime)
        if self.calling or not self.entered or runtime.__dict__.get('notification_parent_observations') is not self:
            raise InputError('parent raw service is outside its installed source window')

    @contextmanager
    def parent_scope(self, runtime, owner):
        self._check(runtime)
        if owner is not self.owner or self.entered or self.consumed:
            raise InputError('parent raw source window is one use')
        values = {'notification_parent_observations': self,
                  'notification_accounts_observations': self.accounts,
                  'notification_ini_observations': self.ini}
        saved = {name: (name in runtime.__dict__, runtime.__dict__.get(name)) for name in values}
        self.entered = self.consumed = True
        runtime.__dict__.update(values)
        try:
            yield self
        finally:
            primary, failure = sys.exception(), None
            for name, value in values.items():
                if runtime.__dict__.get(name) is value:
                    had, prior = saved[name]
                    if had:
                        runtime.__dict__[name] = prior
                    else:
                        runtime.__dict__.pop(name)
                elif failure is None:
                    failure = InputError('parent raw observer slot was replaced')
            self.entered = False
            if failure is not None:
                if primary is not None:
                    primary.add_note('parent raw restore failed: ' + type(failure).__name__)
                else:
                    raise failure

    def _backend(self):
        if self.backend is None:
            self.backend = WindowsNotificationParentAPIBackend()
        return self.backend

    def _call(self, name, *arguments):
        if self.calling:
            raise InputError('parent raw API does not permit a nested backend call')
        if len(self.records) >= 8192:
            raise PrimarySemanticUnavailable('parent raw API call bound reached')
        self.calling = True
        try:
            result = self._backend().call(name, *arguments)
        finally:
            self.calling = False
        width = 64 if name in ('GetCommandLineA', 'CreateToolhelp32Snapshot', 'FindFirstFileA') else (0 if name == 'PathRemoveExtensionW' else 32)
        if width == 0 and result is not None or width and (type(result) is not int or not 0 <= result < 1 << width):
            raise InputError('parent raw API returned an invalid scalar width')
        self.records.append(dict(api=name, resultWidth=width, completed=True))
        return result

    def _iat(self, runtime, name, table):
        slot = table[name]
        slot = slot[0] if isinstance(slot, tuple) else slot
        target = runtime.worker_imports.get(name)
        if target is None or runtime.memory.load(runtime.image_base + slot, 8) != target:
            raise InputError('parent raw API lost its current IAT identity')

    def _parent_source(self):
        from .primary_notification_parent import _produce_parent
        frame = _source(_produce_parent.__code__, self.runtime, output=self.claim.output)
        if frame is None:
            raise InputError('parent raw API lacks its actual parent producer frame')
        return frame

    def _file_selector_alias_region(self, runtime, service, owner, lease, raw, logical):
        """Readonly proof for this still-installed parent command-line mapping."""
        from .primary_windows_command_line import _FileCommandLineAlias
        from .primary_windows_notification_integrity import WindowsNotificationIntegrityService
        from .primary_windows_notification_environment import _ParentEnvironment
        from .primary_allocator_selector import _readonly_alias_region
        frame = sys._getframe(1)
        if (type(self) is not WindowsNotificationParentObservations or
                type(service) is not WindowsNotificationIntegrityService or
                type(lease) is not _FileCommandLineAlias or
                frame.f_code is not _FileCommandLineAlias.validate.__code__ or
                frame.f_locals.get('self') is not lease or lease.parent is not self or
                lease.service is not service or type(service.observer) is not _ParentEnvironment or
                service.observer._runtime is not runtime or service.observer.parent is not self.parent or
                service.observer.owner is not self.owner or
                service._selector_owner is not owner or owner.observer is not service or
                owner.origin != 'windows' or service._active not in (0x35AA260, 0x35B3FE0) or
                service._stage != 'files' or not service._installed or
                getattr(runtime, 'notification_file_observations', None) is not service):
            raise InputError('selector alias requires its original live parent/file source window')
        self._installed(runtime)
        self._parent_source()
        owner.source.require_owner(runtime, owner)
        if owner.source.phase != 'initializing' or owner.source._active is not owner:
            raise InputError('selector alias lacks its current initializing source consumer')
        return _readonly_alias_region(runtime.memory, self.regions, lease.pointer, raw, logical)

    def _map_command(self, address):
        if not address:
            return
        raw = self._backend().command_line_bytes(address, _LIMIT)
        if not isinstance(raw, bytes) or not raw or len(raw) > _LIMIT or _terminated(raw) != raw or address > _MASK - len(raw):
            raise InputError('parent command line requires its complete bounded raw CString')
        self.runtime.memory.map(address, raw, name='borrowed parent command line', initialized=True)
        region = self.runtime.memory._span(address, len(raw))[0]
        self.regions.append((address, region))

    def _enum(self, callback, vector):
        from . import primary_notification_vectors as vectors
        if len(self.records) >= 8192:
            raise PrimarySemanticUnavailable('parent raw API call bound reached')
        root = self._parent_source().f_locals
        filtered = callback == self.runtime.image_base + 0x1D0C670
        function = vectors.collect_windows if callback == self.runtime.image_base + 0x1D0EC50 else vectors.collect_filtered_windows
        if (callback not in (self.runtime.image_base + 0x1D0EC50, self.runtime.image_base + 0x1D0C670) or
                _source(function.__code__, self.runtime, vector=vector) is None or self.enumeration is not None or
                callback in self.enumerated or not self.command_seen or
                (filtered and (not self.directory_seen or root.get('rva') != 0x1D0EAC0 or root.get('vector') != vector)) or
                (not filtered and (self.directory_seen or root.get('windows') != vector))):
            raise InputError('parent EnumWindows lacks its exact producer callback and vector')
        self.enumerated.add(callback)
        state = dict(callback=callback, vector=vector, failure=None, active=True, calls=0)
        self.enumeration = state
        def bridge(window, parameter):
            if state['failure'] is not None:
                return 0
            try:
                self._installed(self.runtime)
                if (self.enumeration is not state or not state['active'] or self.window is not None or
                        int(parameter) & _MASK != vector or state['calls'] >= 4096):
                    raise InputError('parent window callback identity, LPARAM or lifetime differs')
                state['calls'] += 1
                current = dict(window=int(window or 0) & _MASK, callback=callback, vector=vector, stage=0)
                self.window = current
                try:
                    result = vectors.invoke(self.runtime, callback - self.runtime.image_base, (current['window'], vector))
                    if type(result) is not int or result not in (0, 1):
                        raise InputError('parent window callback did not return a source BOOL')
                    return result
                finally:
                    self.window = None
            except BaseException as error:
                state['failure'] = error
                return 0
        try:
            try:
                result = self._backend().enum_windows(bridge, vector)
            except BaseException as error:
                if state['failure'] is not None:
                    state['failure'].add_note('parent enumeration backend failed: ' + type(error).__name__)
                    raise state['failure']
                raise
            if state['failure'] is not None:
                raise state['failure']
            if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
                raise InputError('parent EnumWindows returned an invalid BOOL width')
            self.records.append(dict(api='EnumWindows', resultWidth=32, completed=True))
            return result
        finally:
            state['active'] = False
            self.enumeration = self.window = None

    def _window_source(self, name, arguments):
        from . import primary_notification_vectors as vectors
        state = self.window
        if state is None or self.enumeration is None or not self.enumeration['active']:
            raise InputError('parent window API is outside its synchronous callback')
        filtered = state['callback'] == self.runtime.image_base + 0x1D0C670
        function = vectors.filtered_window_callback if filtered else vectors.window_callback
        frame = _source(function.__code__, self.runtime, window=state['window'], vector=state['vector'])
        sequence = ('IsWindowVisible', 'GetClassNameA', 'GetWindowTextA') if filtered else (
            'GetCurrentProcessId', 'GetWindowThreadProcessId', 'IsWindowVisible', 'GetWindowTextA', 'GetClassNameA')
        if frame is None or state['stage'] >= len(sequence) or sequence[state['stage']] != name:
            raise InputError('parent window API order differs from its real callback')
        if arguments and arguments[0] != state['window']:
            raise InputError('parent window API changed its borrowed HWND')
        state['stage'] += 1
        return frame

    def take(self, runtime, name, arguments):
        from . import primary_notification_vectors as vectors
        self._installed(runtime)
        if (name not in vectors._IMPORTS or type(arguments) is not tuple or
                _source(vectors._api.__code__, runtime, name=name, arguments=arguments) is None):
            raise InputError('parent raw observation lacks its actual typed API call')
        vectors.ParentObservation(name, arguments, None if vectors._IMPORTS[name][2] == 0 else 0)
        self._iat(runtime, name, vectors._IMPORTS)
        effects = ()
        if name in ('GetCommandLineA', 'GetCurrentDirectoryA'):
            frame = self._parent_source()
            if name == 'GetCommandLineA':
                if self.command_seen or self.directory_seen:
                    raise InputError('parent command line observation is repeated or out of order')
                self.command_seen = True
                result = self._call(name)
                self._map_command(result)
            else:
                if not self.command_seen or self.directory_seen or arguments != (260, frame.f_locals.get('cwd')):
                    raise InputError('parent current directory differs from its source buffer and order')
                self.directory_seen = True
                output = _OutputBuffer(runtime, arguments[1], 260)
                result = self._call(name, 260, output.buffer)
                if 0 < result < 260:
                    if output.buffer.raw[result] != 0:
                        raise InputError('parent current directory lacks its API-defined terminator')
                    effects = output.effects(((0, result + 1),))
                else:
                    effects = output.effects()
        elif name == 'EnumWindows':
            result = self._enum(*arguments)
        elif name in ('GetCurrentProcessId', 'GetWindowThreadProcessId', 'IsWindowVisible', 'GetClassNameA', 'GetWindowTextA'):
            frame = self._window_source(name, arguments)
            if name == 'GetCurrentProcessId':
                result = self._call(name)
            elif name == 'GetWindowThreadProcessId':
                if arguments[1] != frame.f_locals['rbp'] + 0x198:
                    raise InputError('parent window PID output is not its real DWORD local')
                output = _OutputBuffer(runtime, arguments[1], 4)
                result = self._call(name, arguments[0], output.buffer)
                effects = output.effects(((0, 4),) if result else ())
            elif name == 'IsWindowVisible':
                result = self._call(name, arguments[0])
            else:
                target = frame.f_locals.get('kind' if name == 'GetClassNameA' else 'title')
                if arguments[1:] != (target, 256):
                    raise InputError('parent window text/class output leaves its source local')
                output = _OutputBuffer(runtime, target, 256)
                result = self._call(name, arguments[0], output.buffer, 256)
                if result > 255:
                    raise InputError('parent window string result exceeds its source capacity')
                if result and output.buffer.raw[result] != 0:
                    raise InputError('parent window string lacks its API-defined terminator')
                effects = output.effects(((0, result + 1),) if result else ())
        elif name in ('CreateToolhelp32Snapshot', 'Process32FirstW', 'Process32NextW', 'CloseHandle', 'PathRemoveExtensionW'):
            result, effects = self._process_api(name, arguments)
        elif name == 'IsDBCSLeadByte':
            frame = _source(vectors.title_filtered.__code__, runtime)
            if self.window is None or frame is None or arguments != (runtime.memory.load(frame.f_locals['pointer'] + frame.f_locals['index'], 1),):
                raise InputError('parent DBCS query lacks its actual title-filter byte')
            result = self._call(name, *arguments)
        else:
            result, effects = self._vector_conversion(name, arguments)
        return vectors.ParentObservation(name, arguments, result, tuple(vectors.ParentWrite(address, data) for address, data in effects))

    def _process_api(self, name, arguments):
        from . import primary_notification_vectors as vectors
        frame = _source(vectors.collect_processes.__code__, self.runtime)
        root = self._parent_source().f_locals
        if (frame is None or not self.directory_seen or root.get('rva') != 0x35CC6B0 or
                root.get('vector') != frame.f_locals.get('vector')):
            raise InputError('parent process API lacks its original vector producer')
        if name == 'CreateToolhelp32Snapshot':
            if arguments != (2, 0) or self.snapshots or self.process_seen:
                raise InputError('parent snapshot differs from its one source acquisition')
            self.process_seen = True
            result = self._call(name, *arguments)
            if result != _MASK:
                self.snapshots[result] = dict(source=frame, entry=None, first=False, exhausted=False, close_attempted=False)
            return result, ()
        handle = frame.f_locals.get('handle')
        state = self.snapshots.get(handle)
        if state is None or state['source'] is not frame:
            raise InputError('parent process API lacks its owned snapshot')
        if name in ('Process32FirstW', 'Process32NextW'):
            pointer = frame.f_locals.get('entry')
            if arguments != (handle, pointer) or state['exhausted'] or (name == 'Process32FirstW') == state['first']:
                raise InputError('parent process entry order or buffer differs')
            if self.runtime.memory.load(pointer, 4) != 0x238:
                raise InputError('parent process entry dwSize is not source 0x238')
            if state['entry'] is not None and state['entry'] != pointer:
                raise InputError('parent process entry buffer changed')
            state['entry'], state['first'] = pointer, True
            output = _OutputBuffer(self.runtime, pointer, 0x238)
            result = self._call(name, handle, output.buffer)
            state['exhausted'] = not result
            defined = ()
            if result:
                raw = _terminated(output.buffer.raw[44:564], 2)
                defined = ((44, len(raw)),)
            return result, output.effects(defined)
        if name == 'CloseHandle':
            if arguments != (handle,) or state['close_attempted']:
                raise InputError('parent snapshot close is repeated or foreign')
            state['close_attempted'] = True
            result = self._call(name, handle)
            if result:
                del self.snapshots[handle]
            return result, ()
        pointer = frame.f_locals.get('pointer')
        if arguments != (pointer,) or pointer != state['entry'] + 44 or state['exhausted']:
            raise InputError('parent extension removal lacks its observed process name')
        raw = _guest_cstring(self.runtime, pointer, 2)
        if len(raw) > 520:
            raise InputError('parent process name exceeds its source array')
        output = _OutputBuffer(self.runtime, pointer, len(raw))
        result = self._call(name, output.buffer)
        return result, output.effects()

    def _conversion(self, name, raw, codepage, capacity, output=None):
        if name not in ('MultiByteToWideChar', 'WideCharToMultiByte') or codepage not in (0, 65001) or len(raw) > _LIMIT:
            raise InputError('parent conversion leaves its source code pages or finite input')
        unit = 2 if name == 'MultiByteToWideChar' else 1
        input_buffer = C.create_string_buffer(raw, len(raw))
        query = name, raw, codepage
        if output is None:
            if capacity != 0 or query in self.queries:
                raise InputError('parent conversion query is repeated or has an output capacity')
        else:
            if self.queries.pop(query, None) != capacity or not 0 < capacity <= _LIMIT // unit:
                raise InputError('parent conversion fill lacks its exact positive source query')
        arguments = (codepage, 0, input_buffer, -1, None if output is None else output.buffer, capacity)
        if name == 'WideCharToMultiByte':
            arguments += (None, None)
        result = self._call(name, *arguments)
        if output is None:
            signed = C.c_int32(result).value
            if signed > 0:
                self.queries[query] = signed
            return result, ()
        if result > capacity:
            raise InputError('parent conversion returned an oversized character count')
        return result, output.effects(((0, result * unit),) if result else ())

    def _vector_conversion(self, name, arguments):
        from . import primary_notification_vectors as vectors
        runtime = self.runtime
        function = vectors.ansi_to_wide if name == 'MultiByteToWideChar' else vectors._utf8_process_name
        frame = _source(function.__code__, runtime)
        if frame is None or arguments[0] != (0 if name == 'MultiByteToWideChar' else 65001) or arguments[1] != 0 or arguments[3] != 0xFFFFFFFF:
            raise InputError('parent vector conversion lacks its exact ACP/UTF8 source helper')
        if name == 'MultiByteToWideChar':
            if (self.window is None or self.enumeration is None or not self.enumeration['active'] or
                    self.window['callback'] != runtime.image_base + 0x1D0C670 or
                    _source(vectors.filtered_window_callback.__code__, runtime, window=self.window['window'], vector=self.window['vector']) is None):
                raise InputError('parent ACP conversion lacks its real filtered callback')
        elif _source(vectors.collect_processes.__code__, runtime) is None or not self.snapshots:
            raise InputError('parent UTF8 conversion lacks its real active process snapshot')
        if name == 'WideCharToMultiByte' and arguments[6:] != (0, 0):
            raise InputError('parent UTF8 conversion has foreign default-character arguments')
        if arguments[2] != frame.f_locals.get('data'):
            raise InputError('parent vector conversion changed its real source pointer')
        raw = _guest_cstring(runtime, arguments[2], 1 if name == 'MultiByteToWideChar' else 2)
        pointer, capacity = arguments[4:6]
        if not pointer:
            return self._conversion(name, raw, arguments[0], capacity)
        expected = frame.f_locals.get('storage' if name == 'MultiByteToWideChar' else 'destination')
        if pointer != expected or capacity != frame.f_locals.get('count'):
            raise InputError('parent vector conversion output differs from its actual allocation')
        output = _OutputBuffer(runtime, pointer, capacity * (2 if name == 'MultiByteToWideChar' else 1))
        return self._conversion(name, raw, arguments[0], capacity, output)

    def take_ini(self, runtime, name, arguments):
        from . import primary_notification_accounts as ini
        from . import primary_notification_collectors as accounts
        self._installed(runtime)
        if (runtime.__dict__.get('notification_ini_observations') is not self.ini or name not in ini._IMPORTS or
                _source(ini._observe.__code__, runtime, name=name, arguments=arguments) is None):
            raise InputError('parent INI adapter lacks its actual typed source request')
        source = _source(ini.ini_value.__code__, runtime)
        producer = _source(accounts.collect_accounts.__code__, runtime)
        if source is None or producer is None:
            raise InputError('parent INI adapter requires its real accounts producer chain')
        values, caller = source.f_locals, producer.f_locals
        root = self._parent_source().f_locals
        if self.command_seen or root.get('accounts') != caller.get('vector'):
            raise InputError('parent INI adapter is outside the original accounts stage')
        if (caller.get('index') not in (0, 4, 8, 12) or
                any(values.get(name) != caller['rbp'] + caller[offset] for name, offset in
                    (('ownedProduct24', 'product'), ('ownedFilename24', 'filename'), ('ownedSection24', 'section'), ('ownedKey24', 'key')))):
            raise InputError('parent INI inputs differ from their original account literals')
        self._iat(runtime, name, ini._IMPORTS)
        if name == 'SHGetSpecialFolderPathA':
            if arguments != (0, values['root'], 0x2E, 0) or self.ini_count != caller['index'] // 4:
                raise InputError('parent INI shell folder request is repeated or foreign')
            output = _OutputBuffer(runtime, arguments[1], 260)
            result = self._call(name, 0, output.buffer, 0x2E, 0)
            defined = ()
            root = None
            if result:
                root = _terminated(output.buffer.raw)
                defined = ((0, len(root)),)
            self.folder_roots['ini'] = root
            self.ini_pending = source if result else None
            self.ini_count += 1
        else:
            if len(arguments) != 6 or arguments != (values['section_pointer'], values['key_pointer'], runtime.image_base + 0x4903C10,
                                                   values['buffer'], 260, values['path_pointer']):
                raise InputError('parent INI profile ABI differs from its actual source locals')
            root = self.folder_roots.get('ini')
            if root is None or self.ini_pending is not source:
                raise InputError('parent INI path lacks its observed successful shell root')
            self.ini_pending = None
            from .primary_logger import _String
            expected = root[:-1] + b'\\Tencent\\' + _String.read(runtime, values['ownedProduct24']).value() + b'\\' + _String.read(runtime, values['ownedFilename24']).value() + b'\0'
            path, section, item, default = (_guest_cstring(runtime, arguments[index]) for index in (5, 0, 1, 2))
            if path != expected or default != b'\0':
                raise InputError('parent INI path/default differs from its real raw source chain')
            output = _OutputBuffer(runtime, arguments[3], 260)
            result = self._call(name, C.create_string_buffer(section), C.create_string_buffer(item),
                                C.create_string_buffer(default), output.buffer, 260, C.create_string_buffer(path))
            if result >= 260:
                raise InputError('parent INI returned an oversized scalar length')
            if output.buffer.raw[result] != 0:
                raise InputError('parent INI profile lacks its API-defined terminator')
            defined = ((0, result + 1),)
            observed = _terminated(output.buffer.raw)
            if observed != b'\0':
                self.profile_paths.add(observed[:-1])
        reply = IniApiReply(result, tuple(IniRawWrite(address - output.address, raw) for address, raw in output.effects(defined)))
        return reply

    def take_accounts(self, runtime, name, arguments):
        from . import primary_notification_collectors as accounts
        from .primary_logger import _String
        self._installed(runtime)
        if (runtime.__dict__.get('notification_accounts_observations') is not self.accounts or name not in accounts._ACCOUNTS_IMPORTS or
                _source(accounts._accounts_api.__code__, runtime, name=name, arguments=arguments) is None):
            raise InputError('parent accounts adapter lacks its actual typed source request')
        producer = _source(accounts.collect_accounts.__code__, runtime)
        if producer is None:
            raise InputError('parent accounts adapter requires its original producer frame')
        root = self._parent_source().f_locals
        if self.command_seen or root.get('accounts') != producer.f_locals.get('vector'):
            raise InputError('parent accounts adapter is outside the original accounts stage')
        self._iat(runtime, name, accounts._ACCOUNTS_IMPORTS)
        effects = ()
        if name == 'SHGetFolderPathA':
            local = producer.f_locals
            if arguments not in ((0, 0x1A, 0, 0, local.get('root')), (0, 5, 0, 0, local.get('root'))) or self.ini_count != 4:
                raise InputError('parent accounts folder request differs from its source sequence')
            csidl = arguments[1]
            if csidl in self.folder_roots or csidl == 5 and 0x1A not in self.folder_roots:
                raise InputError('parent accounts folder query is repeated or out of order')
            output = _OutputBuffer(runtime, arguments[4], 260)
            result = self._call(name, 0, csidl, 0, 0, output.buffer)
            raw = _terminated(output.buffer.raw) if result == 0 else None
            self.folder_roots[csidl] = raw
            effects = output.effects(((0, len(raw)),) if raw is not None else ())
            origin = output.address
        else:
            source = _source(accounts.enumerate_accounts.__code__, runtime)
            if source is None or source.f_locals.get('vector') != producer.f_locals.get('vector'):
                raise InputError('parent find API lacks its original enumeration frame')
            local = source.f_locals
            if name == 'FindFirstFileA':
                if arguments != (local.get('pattern_pointer'), local.get('find_data')):
                    raise InputError('parent find pattern/output differs from its source locals')
                path = _String.read(runtime, local['path']).value()
                pattern = _guest_cstring(runtime, arguments[0])
                allowed = path in self.profile_paths and local['mode'] == 1
                suffixes = ((0x1A, b'\\Tencent\\QQ\\Misc', 0), (0x1A, b'\\Tencent\\TIM\\Misc', 0),
                            (0x1A, b'\\Tencent\\Users', 1), (0x1A, b'\\QQ\\Crashpad\\log', 1),
                            (5, b'\\Tencent Files', 0))
                allowed = allowed or any(self.folder_roots.get(csidl) is not None and
                    path == self.folder_roots[csidl][:-1] + suffix and local['mode'] == mode for csidl, suffix, mode in suffixes)
                if not allowed or pattern != path + b'\\*\0':
                    raise InputError('parent find path lacks its original shell/profile provenance')
                output = _OutputBuffer(runtime, arguments[1], 320)
                result = self._call(name, C.create_string_buffer(pattern), output.buffer)
                if result != _MASK:
                    if result in self.finds:
                        raise InputError('parent find API aliases an already owned handle')
                    self.finds[result] = dict(source=source, pointer=output.address, exhausted=False, close_attempted=False)
            else:
                handle = local.get('handle')
                state = self.finds.get(handle)
                if state is None or state['source'] is not source or arguments[0] != handle:
                    raise InputError('parent find API lacks its exact owned enumeration')
                if name == 'FindClose':
                    if arguments != (handle,) or state['close_attempted']:
                        raise InputError('parent find close is repeated or foreign')
                    state['close_attempted'] = True
                    result = self._call(name, handle)
                    if result:
                        del self.finds[handle]
                    return AccountsApiReply(result, ())
                if arguments != (handle, state['pointer']) or state['exhausted']:
                    raise InputError('parent next-file request is foreign or follows exhaustion')
                output = _OutputBuffer(runtime, arguments[1], 320)
                result = self._call(name, handle, output.buffer)
                state['exhausted'] = not result
            success = result != _MASK if name == 'FindFirstFileA' else bool(result)
            defined = ()
            if success:
                raw = _terminated(output.buffer.raw[44:304])
                defined = ((0, 4), (44, len(raw)))
            effects, origin = output.effects(defined), output.address
        reply = AccountsApiReply(result, tuple(IniRawWrite(address - origin, raw) for address, raw in effects))
        AccountsApiObservation(name, arguments, reply)
        return reply

    def take_conversion(self, runtime, name, arguments):
        from . import primary_device_cache as cache
        from . import primary_device_collector as collector
        from . import primary_notification_collectors as accounts
        self._installed(runtime)
        if name not in ('MultiByteToWideChar', 'WideCharToMultiByte'):
            raise InputError('parent conversion adapter refuses unrelated worker APIs')
        self._iat(runtime, name, collector._IMPORTS)
        frame = _source(collector._convert_call.__code__, runtime, name=name)
        if frame is not None:
            if _source(accounts.wide_to_utf8.__code__, runtime) is None:
                raise InputError('parent conversion lacks its supported real vector/PPP consumer')
            local = frame.f_locals
            wide = name == 'WideCharToMultiByte'
            raw = _guest_cstring(runtime, local['source'], 2 if wide else 1)
            expected = (65001 if wide else 0, 0, raw, -1, local['destination'] is not None, local['capacity'])
            if wide:
                expected += (0, 0)
            pointer, capacity, codepage = local['destination'], local['capacity'], 65001 if wide else 0
        else:
            frame = _source(cache._wide_to_ansi.__code__, runtime)
            if (frame is None or name != 'WideCharToMultiByte' or
                    _source(cache._observe.__code__, runtime, name=name, arguments=arguments) is None):
                raise InputError('parent ACP conversion lacks its original cache helper frame')
            from . import primary_notification_vectors as vectors
            if _source(vectors.collect_processes.__code__, runtime) is None:
                raise InputError('parent ACP conversion lacks its original process producer')
            local = frame.f_locals
            raw = local['value']
            fill = 'count' in local
            pointer, capacity, codepage = (local.get('pointer'), local['count'], 0) if fill else (None, 0, 0)
            expected = (0, 0, raw, -1, fill, capacity, 0, 0)
        if type(arguments) is not tuple or arguments != expected:
            raise InputError('parent conversion adapter ABI or source bytes differ')
        if pointer is None:
            result, effects = self._conversion(name, raw, codepage, capacity)
            return result, b''
        output = _OutputBuffer(runtime, pointer, capacity * (2 if name == 'MultiByteToWideChar' else 1))
        result, effects = self._conversion(name, raw, codepage, capacity, output)
        contiguous, end = bytearray(), pointer
        for address, data in effects:
            if address != end:
                for address, data in effects:
                    runtime.memory.write(address, data, source='notification.parent_sparse_conversion')
                raise UnknownMemory('typed conversion output has noncontiguous defined failure bytes')
            contiguous.extend(data)
            end += len(data)
        return result, bytes(contiguous)

    @property
    def resource_count(self):
        return len(self.snapshots) + len(self.finds) + len(self.regions) + int(self.enumeration is not None)

    def close(self):
        if self.closed:
            return
        if self.thread != (os.getpid(), threading.get_ident(), threading.get_native_id()) or self.entered or self.enumeration is not None:
            raise PrimarySemanticUnavailable('parent raw close requires its creating worker after the source window')
        failure = None
        for table, name in ((self.snapshots, 'CloseHandle'), (self.finds, 'FindClose')):
            for handle, state in tuple(table.items()):
                try:
                    if state['close_attempted']:
                        raise PrimarySemanticUnavailable('parent owned handle has an unresolved prior close')
                    state['close_attempted'] = True
                    if not self._call(name, handle):
                        raise PrimarySemanticUnavailable('parent owned handle close failed')
                    del table[handle]
                except BaseException as error:
                    state['source'] = None
                    if failure is None:
                        failure = error
        for address, region in tuple(self.regions):
            try:
                current = self.runtime.memory._span(address, len(region.data))[0]
                if current is not region:
                    raise InputError('borrowed parent command mapping was replaced')
                self.runtime.memory.unmap(address)
                self.regions.remove((address, region))
            except BaseException as error:
                if failure is None:
                    failure = error
        if self.view is not None:
            try:
                self.view.close()
            except BaseException as error:
                if failure is None:
                    failure = error
        self.queries.clear()
        self.folder_roots.clear()
        self.profile_paths.clear()
        self.ini_pending = None
        if failure is not None:
            raise failure
        self.closed = True
        self.claim = self.view = self.owner = self.parent = self.runtime = self.backend = None
