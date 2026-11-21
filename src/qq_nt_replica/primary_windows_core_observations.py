from contextlib import contextmanager
import ctypes as C
import hashlib
import os
import threading

from .primary_core_dynamic_exports import lookup_export, logical_identity
from .primary_windows_ownimage import freeze_capability
from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable


class WindowsCoreAPIBackend:
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise PrimarySemanticUnavailable('raw core observations require Windows AMD64')
        self.modules = []
        self.functions = {}
        self.closed = False
        self.precise_available = False
        try:
            for module, definitions in (
                    ('kernel32', (('QueryPerformanceCounter', C.c_int32, (C.c_void_p,)),
                                  ('QueryPerformanceFrequency', C.c_int32, (C.c_void_p,)),
                                  ('GetSystemTimeAsFileTime', None, (C.c_void_p,)))),
                    ('user32', (('GetCursorPos', C.c_int32, (C.c_void_p,)),
                                ('FindWindowA', C.c_void_p, (C.c_char_p, C.c_char_p)))),
                    ('advapi32', (('SystemFunction036', C.c_ubyte, (C.c_void_p, C.c_uint32)),)),
                    ('bcrypt', (('BCryptGenRandom', C.c_int32,
                                 (C.c_void_p, C.c_void_p, C.c_uint32, C.c_uint32)),))):
                library = C.WinDLL(module, use_last_error=True)
                self.modules.append(library)
                if module == 'kernel32':
                    for name, arguments in (('GetModuleHandleA', (C.c_char_p,)),
                                            ('GetProcAddress', (C.c_void_p, C.c_char_p))):
                        resolver = getattr(library, name)
                        resolver.restype, resolver.argtypes = C.c_void_p, arguments
                        self.functions[name] = resolver
                    try:
                        precise = library.GetSystemTimePreciseAsFileTime
                    except AttributeError:
                        precise = None
                    if precise is not None:
                        precise.restype, precise.argtypes = None, (C.c_void_p,)
                        self.functions['GetSystemTimePreciseAsFileTime'] = precise
                        self.precise_available = True
                for name, result, arguments in definitions:
                    function = getattr(library, name)
                    function.restype, function.argtypes = result, arguments
                    self.functions[name] = function
        except BaseException:
            self.close()
            raise

    def request(self, name, output, count):
        if self.closed:
            raise InputError('raw core API backend is closed')
        function = self.functions[name]
        if name == 'SystemFunction036':
            return function(output, count)
        if name == 'BCryptGenRandom':
            return function(None, output, count, 2)
        return function(output)

    def resolve(self, name, arguments):
        if self.closed:
            raise InputError('raw core API backend is closed')
        if name not in ('GetModuleHandleA', 'GetProcAddress', 'FindWindowA'):
            raise InputError('raw entry resolver supports only its two declared APIs')
        return int(self.functions[name](*arguments) or 0)

    def capture_stack(self, output):
        if self.closed:
            raise InputError('raw core API backend is closed')
        function = self.modules[0].RtlCaptureStackBackTrace
        function.restype, function.argtypes = C.c_ushort, (C.c_uint32, C.c_uint32, C.c_void_p, C.c_void_p)
        return int(function(0, 4, output, None))

    def close(self):
        if self.closed:
            return
        if self.modules:
            free = self.modules[0].FreeLibrary
            free.restype, free.argtypes = C.c_int32, (C.c_void_p,)
            while self.modules:
                library = self.modules[-1]
                if not free(library._handle):
                    raise PrimarySemanticUnavailable('raw core system module reference release failed')
                self.modules.pop()
        self.functions.clear()
        self.closed = True


class WindowsCoreObservations:
    def __init__(self, *, backend=None, tap=None):
        if tap is not None and not callable(tap):
            raise InputError('raw core RAM event tap must be callable')
        self._backend, self._tap = backend, tap
        self._owner = os.getpid(), threading.get_native_id()
        self._lock = threading.RLock()
        self._runtime = None
        self._closed = False
        self._sequence = 0
        self._phase = 'initialization'
        self._counts = {}
        self._module_names = {}
        self._opaque_targets = set()
        self._recognized_targets = set()
        self._typed_exports = {}
        self._lookup_diagnostics = []
        self._caller = None
        self._stack_addresses = set()
        self._process_source = None
        self._ownimage_manifest = None

    def bind(self, runtime):
        if self._runtime is not None or self._closed:
            raise InputError('raw core observation requires one live runtime binding')
        self._runtime = runtime

    def bind_caller(self, caller):
        if self._caller is not None or self._closed:
            raise InputError('raw main caller observations require one live binding')
        self._caller = caller

    def ownimage_capability(self):
        if self._closed or self._runtime is None or self._caller is None:
            raise InputError('own-image observation requires its live bound caller')
        getter = getattr(self._caller, 'ownimage_capability', None)
        snapshot = None if getter is None else getter(self._runtime)
        if snapshot is None:
            if self._ownimage_manifest is not None:
                raise InputError('own-image capability changed during capture')
            return None
        snapshot = freeze_capability(snapshot)
        owner = snapshot['owner']
        if ((owner['process_id'], owner['thread_id']) != self._owner or
                self._owner != (os.getpid(), threading.get_native_id()) or
                snapshot['guest_identity']['base'] != self._runtime.image_base):
            raise InputError('own-image capability belongs to another capture owner')
        if self._ownimage_manifest is not None and snapshot != self._ownimage_manifest:
            raise InputError('own-image capability changed during capture')
        self._ownimage_manifest = snapshot
        return snapshot

    def process_event(self, runtime, name, arguments):
        if runtime is not self._runtime:
            raise InputError('raw process observation requires its bound runtime')
        with self._lock:
            if self._closed or self._owner[0] != os.getpid():
                raise InputError('raw core observer is closed or belongs to another process')
            if name not in ('CreateToolhelp32Snapshot', 'Process32First', 'Process32Next', 'CloseHandle'):
                raise InputError('raw main process API is outside its source import set')
            if self._process_source is None:
                from .primary_material_process import WindowsProcessMaterialSource
                self._process_source = WindowsProcessMaterialSource(raw_outputs=True)
            if getattr(self._process_source, 'sparse_adapter_verified', False):
                raise PrimarySemanticUnavailable('raw ANSI process tape cannot use a separate wide-call projection')
            row = name in ('Process32First', 'Process32Next')
            initial = ()
            if row:
                region, offset = runtime.memory._span(arguments[1], 304)
                initial = (('output', bytes(region.data[offset:offset + 304]),
                            bytes(region.initialized[offset:offset + 304])),)
            result, effects = self._process_source.observations().take(runtime, name, arguments)
            writes = tuple(('output', offset, data, b'\1' * len(data)) for offset, data in effects) if row else ()
            self._sequence += 1
            event = {'sequence': self._sequence, 'phase': self._phase,
                     'thread_role': 'caller' if threading.get_native_id() == self._owner[1] else 'sdk_worker',
                     'thread_id': threading.get_native_id(), 'name': name,
                     'arguments': (arguments[0],) if row else arguments,
                     'result': result, 'initial': initial, 'writes': writes,
                     'purpose': 'source main same-call owned process observation'}
            self._counts[name] = self._counts.get(name, 0) + 1
            if self._tap is not None:
                self._tap(event)
            return name, arguments, result, effects

    def path_api(self, runtime, name, pointer):
        if runtime is not self._runtime or self._caller is None:
            raise InputError('raw main path API requires its bound production observer')
        if name not in ('PathFindFileNameA', 'PathStripPathA'):
            raise InputError('raw main path API is outside its source import set')
        with self._lock:
            if self._closed or self._owner[0] != os.getpid():
                raise InputError('raw core observer is closed or belongs to another process')
            initial = runtime._ansi_name(pointer) + b'\0'
            if len(initial) > 520:
                raise PrimarySemanticUnavailable('raw main path exceeds its bounded ANSI domain')
            buffer = C.create_string_buffer(initial, len(initial))
            result, offset = self._caller.core_path_request(runtime, name, buffer)
            raw = buffer.raw
            find = name == 'PathFindFileNameA'
            if find:
                if type(result) is not int or not 0 < result < 1 << 64 or type(offset) is not int or not 0 <= offset < len(initial):
                    raise InputError('raw path filename requires its actual pointer and verified buffer-relative offset')
                if raw != initial:
                    raise PrimarySemanticUnavailable('raw path filename unexpectedly modified its const input')
            elif result is not None or b'\0' not in raw:
                raise InputError('raw path stripping requires its void result and bounded terminated output')
            role = 'input' if find else 'inout'
            writes = bytes(int(value != before) for value, before in zip(raw, initial))
            self._sequence += 1
            event = {'sequence': self._sequence, 'phase': self._phase,
                     'thread_role': 'caller' if threading.get_native_id() == self._owner[1] else 'sdk_worker',
                     'thread_id': threading.get_native_id(), 'name': name,
                     'arguments': (initial,) if find else (), 'result': result,
                     'initial': ((role, initial, b'\1' * len(initial)),),
                     'writes': () if find else ((role, 0, raw, writes),),
                     'purpose': 'source main natural ANSI path API'}
            if find:
                event['logical_result'] = {'role': 'input', 'offset': offset}
            self._counts[name] = self._counts.get(name, 0) + 1
            if self._tap is not None:
                self._tap(event)
            if not find:
                for index, written in enumerate(writes):
                    if written:
                        runtime.memory.write(pointer + index, raw[index:index + 1], source=name + '.raw_write')
            return pointer + offset if find else None

    def caller_api(self, runtime, name, arguments, destination=None, size=0):
        if runtime is not self._runtime or self._caller is None:
            raise InputError('raw main caller API requires its bound production observer')
        if (name == 'GetCurrentProcessId' and (arguments != () or destination is not None or size) or
                name == 'IsWindowVisible' and (len(arguments) != 1 or destination is not None or size) or
                name == 'GetModuleHandleExA' and (len(arguments) != 2 or arguments[0] != 6 or destination is None or size != 8) or
                name == 'GetModuleFileNameA' and (len(arguments) != 2 or destination is None or size != arguments[1]) or
                name not in ('GetCurrentProcessId', 'IsWindowVisible', 'GetModuleHandleExA', 'GetModuleFileNameA')):
            raise InputError('raw main caller API requires its exact source argument and output shape')
        with self._lock:
            if self._closed or self._owner[0] != os.getpid():
                raise InputError('raw core observer is closed or belongs to another process')
            if name == 'GetModuleHandleExA' and arguments[1] not in self._stack_addresses:
                raise PrimarySemanticUnavailable('raw main module lookup requires a same-call captured address')
            if destination is None:
                initial, known, backing, buffer = b'', b'', b'', None
            else:
                if not 0 < size <= 520:
                    raise InputError('raw main caller output exceeds its declared bound')
                region, offset = runtime.memory._span(destination, size)
                initial = bytes(region.data[offset:offset + size])
                known = bytes(region.initialized[offset:offset + size])
                backing = bytes(value if bit else 0xA5 for value, bit in zip(initial, known))
                buffer = C.create_string_buffer(backing, size)
            relocation = None
            if name == 'GetModuleFileNameA':
                ownimage = arguments[0] == runtime.image_base
                expected = None
                if ownimage:
                    if self._phase != 'core' or arguments[1] != 260 or self._owner != (os.getpid(), threading.get_native_id()):
                        raise InputError('own-image filename requires its exact core owner and capacity')
                    expected = self.ownimage_capability()
                    if expected is None:
                        raise PrimarySemanticUnavailable('own-image filename requires its native relocation capability')
                request = getattr(self._caller, 'core_filename_request', None)
                if request is None and ownimage:
                    raise PrimarySemanticUnavailable('own-image filename requires the native relocation adapter')
                if request is None:
                    result = self._caller.core_request(runtime, name, arguments, buffer,
                                                       observed_modules=frozenset(self._module_names))
                else:
                    result, relocation = request(runtime, arguments, buffer, observed_modules=frozenset(self._module_names))
                if ownimage:
                    relocation = freeze_capability(relocation)
                    if relocation != expected:
                        raise InputError('own-image filename returned a different native capability')
                elif relocation is not None:
                    raise InputError('ordinary filename request cannot carry own-image relocation')
            else:
                result = self._caller.core_request(runtime, name, arguments, buffer)
            if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
                raise InputError('raw main caller scalar must preserve its DWORD result')
            raw = b'' if buffer is None else buffer.raw
            if name == 'GetModuleHandleExA' and result:
                handle = int.from_bytes(raw, 'little')
                if self._ownimage_manifest is not None and handle in (runtime.image_base, self._ownimage_manifest['native_identity']['hmodule']):
                    raise PrimarySemanticUnavailable('own-image module cannot enter general observed modules')
                self._module_names.setdefault(handle, set())
            defined = (8 if name == 'GetModuleHandleExA' and result else
                       result + 1 if name == 'GetModuleFileNameA' and 0 < result < size else 0)
            writes = bytes(int(index < defined or value != before)
                           for index, (value, before) in enumerate(zip(raw, backing)))
            self._sequence += 1
            event = {'sequence': self._sequence, 'phase': self._phase,
                     'thread_role': 'caller' if threading.get_native_id() == self._owner[1] else 'sdk_worker',
                     'thread_id': threading.get_native_id(), 'name': name, 'arguments': arguments,
                     'result': result, 'initial': () if not size else (('output', initial, known),),
                     'writes': () if not size else (('output', 0, raw, writes),),
                     'purpose': 'source main natural caller API'}
            if relocation is not None:
                event.update(relocation=relocation, native_arguments=(relocation['native_identity']['hmodule'], arguments[1]),
                             evidence_kind='native_api')
            self._counts[name] = self._counts.get(name, 0) + 1
            if self._tap is not None:
                self._tap(event)
            for index, written in enumerate(writes):
                if written:
                    runtime.memory.write(destination + index, raw[index:index + 1], source=name + '.raw_write')
            return result

    @contextmanager
    def phase(self, phase):
        if phase not in ('initialization', 'core', 'provider', 'cleanup'):
            raise InputError('raw core event phase is outside the declared domain')
        previous, self._phase = self._phase, phase
        try:
            yield self
        finally:
            self._phase = previous

    def observe(self, name, *, initial, knownmask, purpose):
        widths = {'QueryPerformanceCounter': 8, 'QueryPerformanceFrequency': 8,
                  'GetSystemTimeAsFileTime': 8, 'GetSystemTimePreciseAsFileTime': 8,
                  'GetCursorPos': 8, 'BCryptGenRandom': 4}
        if not isinstance(initial, bytes):
            raise InputError('raw core observation initial bytes must be explicit')
        count = len(initial)
        if (not isinstance(initial, bytes) or not isinstance(knownmask, bytes) or
                len(knownmask) != count or any(bit not in (0, 1) for bit in knownmask) or
                name not in (*widths, 'SystemFunction036') or
                name in widths and count != widths[name] or not 0 < count <= 1 << 20):
            raise InputError('raw core observation requires its exact output shape and initialized mask')
        with self._lock:
            if self._closed or self._owner[0] != os.getpid():
                raise InputError('raw core observer is closed or belongs to another process')
            if self._backend is None:
                self._backend = WindowsCoreAPIBackend()
            backing = bytes(value if known else 0xA5 for value, known in zip(initial, knownmask))
            buffer = C.create_string_buffer(backing, count)
            result = self._backend.request(name, buffer, count)
            if name in ('GetSystemTimeAsFileTime', 'GetSystemTimePreciseAsFileTime'):
                if result is not None:
                    raise InputError('raw FILETIME API has a void return')
                success = True
            else:
                if type(result) is not int:
                    raise InputError('raw core API result must be its native integer width')
                result &= 0xFF if name == 'SystemFunction036' else 0xFFFFFFFF
                success = result < 0x80000000 if name == 'BCryptGenRandom' else result != 0
            raw = buffer.raw
            writes = bytes(int(success or current != before) for current, before in zip(raw, backing))
            finalmask = bytes(int(old or written) for old, written in zip(knownmask, writes))
            arguments = ((0, count, 2) if name == 'BCryptGenRandom' else
                         (count,) if name == 'SystemFunction036' else ())
            self._sequence += 1
            event = {'sequence': self._sequence, 'phase': self._phase,
                     'thread_role': 'caller' if threading.get_native_id() == self._owner[1] else 'sdk_worker',
                     'thread_id': threading.get_native_id(), 'name': name, 'arguments': arguments,
                     'result': result, 'initial': (('output', initial, knownmask),),
                     'writes': (('output', 0, raw, writes),), 'purpose': purpose}
            self._counts[name] = self._counts.get(name, 0) + 1
            if self._tap is not None:
                self._tap(event)
            return result, raw, writes, finalmask

    def write_to(self, runtime, name, destination, *, purpose):
        if runtime is not self._runtime:
            raise InputError('raw core effects require their bound runtime')
        size = 8
        region, offset = runtime.memory._span(destination, size)
        initial = bytes(region.data[offset:offset + size])
        known = bytes(region.initialized[offset:offset + size])
        result, raw, writes, _ = self.observe(name, initial=initial, knownmask=known, purpose=purpose)
        for index, written in enumerate(writes):
            if written:
                runtime.memory.write(destination + index, raw[index:index + 1], source=name + '.raw_write')
        return result

    def _resolve(self, name, arguments, *, logical_result):
        with self._lock:
            if self._closed or self._owner[0] != os.getpid():
                raise InputError('raw core observer is closed or belongs to another process')
            if self._backend is None:
                self._backend = WindowsCoreAPIBackend()
            result = self._backend.resolve(name, arguments)
            if type(result) is not int or not 0 <= result < 1 << 64:
                raise InputError('raw resolver result must be its actual pointer-width value')
            self._sequence += 1
            event = {'sequence': self._sequence, 'phase': self._phase,
                     'thread_role': 'caller' if threading.get_native_id() == self._owner[1] else 'sdk_worker',
                     'thread_id': threading.get_native_id(), 'name': name, 'arguments': arguments,
                     'result': result, 'writes': (), 'initial': (),
                     'purpose': 'source entry resolver without native target invocation'}
            if result and logical_result is not None:
                event['logical_result'] = logical_result
            self._counts[name] = self._counts.get(name, 0) + 1
            if self._tap is not None:
                self._tap(event)
            return result

    def module_lookup(self, name):
        if name is not None and (not isinstance(name, bytes) or b'\0' in name or len(name) > 1 << 20):
            raise InputError('raw module query requires NULL or source Cstr bytes without their terminator')
        summary = {'api': 'GetModuleHandleA', 'query_kind': 'null' if name is None else 'cstr',
                   'length': None if name is None else len(name),
                   'sha256': None if name is None else hashlib.sha256(name).hexdigest(),
                   'status': 'requested', 'returned_nonzero': None}
        self._lookup_diagnostics.append(summary)
        try:
            result = self._resolve('GetModuleHandleA', (name,), logical_result=None)
        except BaseException:
            summary['status'] = 'query_or_observer_exception'
            raise
        summary.update(status='returned', returned_nonzero=bool(result))
        if result:
            if self._ownimage_manifest is not None and result in (self._runtime.image_base, self._ownimage_manifest['native_identity']['hmodule']):
                raise PrimarySemanticUnavailable('own-image module cannot enter general observed modules')
            self._module_names.setdefault(result, set()).add(name)
        return name, result

    def procedure_lookup(self, handle, name, dispatch):
        if (type(handle) is not int or not 0 <= handle < 1 << 64 or not isinstance(name, bytes) or
                b'\0' in name or len(name) > 1 << 20):
            raise InputError('raw export query requires its pointer handle and source Cstr export name')
        if handle and handle not in self._module_names:
            raise PrimarySemanticUnavailable('raw export query requires its same-call observed module')
        rows = [lookup_export(alias, name) for alias in self._module_names.get(handle, ())]
        identities = {(row['library'], row['export']) for row in rows if row is not None}
        row = next((row for row in rows if row is not None), None) if len(identities) == 1 else None
        target = dispatch.get(row['handler_key']) if row is not None and row['supported'] else None
        recognized = type(target) is int and 0 < target < 1 << 64
        logical = logical_identity(row) if recognized else None
        summary = {'api': 'GetProcAddress', 'query_kind': 'named_export',
                   'length': len(name), 'sha256': hashlib.sha256(name).hexdigest(),
                   'status': 'requested', 'returned_nonzero': None, 'recognized_dispatch': None}
        self._lookup_diagnostics.append(summary)
        try:
            result = self._resolve('GetProcAddress', (handle, name), logical_result=logical)
        except BaseException:
            summary['status'] = 'query_or_observer_exception'
            raise
        summary.update(status='returned', returned_nonzero=bool(result), recognized_dispatch=bool(result and recognized))
        if not result:
            return handle, name, 0
        if not recognized:
            self._opaque_targets.add(result)
            return handle, name, result
        known_dispatch = {value for value in dispatch.values() if type(value) is int}
        native = None if self._ownimage_manifest is None else self._ownimage_manifest['native_identity']['hmodule']
        if (result == native or target == native or result in self._module_names or result in self._opaque_targets or
                result in self._recognized_targets or result in known_dispatch or
                target in self._module_names or target in self._opaque_targets):
            self._opaque_targets.add(result)
            summary['recognized_dispatch'] = False
            raise PrimarySemanticUnavailable('raw export pointer collides with a module, opaque target or known dispatch')
        previous = self._typed_exports.get(target)
        if previous is not None and previous != row:
            self._opaque_targets.add(target)
            summary['recognized_dispatch'] = False
            raise PrimarySemanticUnavailable('qualified export identities collide at their dispatch target')
        self._typed_exports[target] = row
        self._recognized_targets.add(target)
        return handle, name, target

    def find_window(self, runtime, class_name, title):
        if runtime is not self._runtime:
            raise InputError('raw window lookup requires its bound runtime')
        row = lookup_export('user32.dll', 'FindWindowA')
        if (class_name, title) not in row['argument_domain']:
            raise PrimarySemanticUnavailable('raw window lookup is outside the source argument domain')
        return self._resolve('FindWindowA', (class_name, title), logical_result=None)

    def validate_export_abi(self, address, vm, cells, argument_types):
        row = self._typed_exports.get(address)
        if row is None:
            return
        if row['call_path'] != 'nativecall':
            raise PrimarySemanticUnavailable('dynamic export is available only through its prepare helper')
        if len(cells) != len(row['argument_widths']):
            raise InputError('dynamic export argument count differs from its qualified ABI')
        if argument_types is None:
            raise InputError('dynamic export requires explicit argument ABI')
        if argument_types is not None:
            widths = tuple(vm.program.size(index) * 8 for index in argument_types)
            if widths != row['argument_widths']:
                raise InputError('dynamic export argument widths differ from its qualified ABI')

    def validate_target_use(self, runtime, address):
        if runtime is not self._runtime:
            raise InputError('raw export use requires its bound runtime')
        if self._ownimage_manifest is not None and address == self._ownimage_manifest['native_identity']['hmodule']:
            raise PrimarySemanticUnavailable('own-image native module is unsupported at execution')
        if address in self._module_names:
            raise PrimarySemanticUnavailable('module handle is unsupported at execution')
        if address in self._opaque_targets:
            if address in self._recognized_targets:
                raise PrimarySemanticUnavailable('opaque export target collides with a recognized dispatch; use is ambiguous')
            raise PrimarySemanticUnavailable('opaque export target is unsupported at execution')

    def capture_stack(self, runtime, skip, count, destination, hash_pointer):
        if runtime is not self._runtime or (skip, count, hash_pointer) != (0, 4, 0):
            raise InputError('raw main backtrace requires its bound runtime and exact four-frame ABI')
        with self._lock:
            if self._closed or self._owner[0] != os.getpid():
                raise InputError('raw core observer is closed or belongs to another process')
            if self._backend is None:
                self._backend = WindowsCoreAPIBackend()
            region, offset = runtime.memory._span(destination, 32)
            initial = bytes(region.data[offset:offset + 32])
            known = bytes(region.initialized[offset:offset + 32])
            backing = bytes(value if bit else 0xA5 for value, bit in zip(initial, known))
            buffer = C.create_string_buffer(backing, 32)
            result = self._backend.capture_stack(buffer)
            if type(result) is not int or not 0 <= result <= 4:
                raise InputError('raw main backtrace returned an invalid USHORT frame count')
            raw = buffer.raw
            writes = bytes(int(index < result * 8 or value != before)
                           for index, (value, before) in enumerate(zip(raw, backing)))
            self._sequence += 1
            name = 'RtlCaptureStackBackTrace'
            event = {'sequence': self._sequence, 'phase': self._phase,
                     'thread_role': 'caller' if threading.get_native_id() == self._owner[1] else 'sdk_worker',
                     'thread_id': threading.get_native_id(), 'name': name, 'arguments': (0, 4, False),
                     'result': result, 'initial': (('output', initial, known),),
                     'writes': (('output', 0, raw, writes),),
                     'purpose': 'source main four-frame own-process observation'}
            self._counts[name] = self._counts.get(name, 0) + 1
            self._stack_addresses.update(int.from_bytes(raw[index:index + 8], 'little')
                                         for index in range(0, result * 8, 8))
            if self._tap is not None:
                self._tap(event)
            for index, written in enumerate(writes):
                if written:
                    runtime.memory.write(destination + index, raw[index:index + 1], source=name + '.raw_write')
            return result

    def entropy_word(self):
        result, raw, _, mask = self.observe('SystemFunction036', initial=bytes(4), knownmask=b'\1' * 4,
                                           purpose='source rand_s DWORD output initialized zero')
        if not result:
            raise PrimarySemanticUnavailable('source rand_s SystemFunction036 returned false; errno12 exception continuation')
        if not all(mask):
            raise UnknownMemory('source entropy output retains unknown bytes')
        return raw

    def filetime(self, *, precise=False):
        with self._lock:
            if self._closed or self._owner[0] != os.getpid():
                raise InputError('raw core observer is closed or belongs to another process')
            if precise and self._backend is None:
                self._backend = WindowsCoreAPIBackend()
            name = ('GetSystemTimePreciseAsFileTime' if precise and self._backend.precise_available
                    else 'GetSystemTimeAsFileTime')
            _, raw, _, mask = self.observe(name, initial=bytes(8), knownmask=bytes(8),
                                           purpose='source FILETIME output before scalar projection')
        if not all(mask):
            raise UnknownMemory('FILETIME output retains unknown bytes')
        return int.from_bytes(raw, 'little')

    def bcrypt_word(self):
        result, raw, _, _ = self.observe('BCryptGenRandom', initial=bytes(4), knownmask=b'\1' * 4,
                                         purpose='35924C4 source zero DWORD and signed NTSTATUS')
        return result, raw

    def qpc(self):
        values = []
        for name in ('QueryPerformanceFrequency', 'QueryPerformanceCounter'):
            _, raw, _, mask = self.observe(name, initial=bytes(8), knownmask=bytes(8),
                                            purpose='external scalar environment clock')
            if not all(mask):
                raise UnknownMemory('external scalar QPC requires complete native output')
            values.append(int.from_bytes(raw, 'little'))
        return values[1], values[0]

    def random_bytes(self, count):
        if type(count) is not int or not 0 < count <= 1 << 20:
            raise InputError('external entropy request requires a bounded positive byte count')
        result, raw, _, mask = self.observe('SystemFunction036', initial=bytes(count), knownmask=bytes(count),
                                           purpose='external scalar environment entropy')
        if not result or not all(mask):
            raise PrimarySemanticUnavailable('external entropy API did not produce complete bytes')
        return raw

    @property
    def diagnostics(self):
        return {'closed': self._closed, 'sequence': self._sequence, 'api_counts': dict(self._counts),
                'lookup_diagnostics': [dict(row) for row in self._lookup_diagnostics]}

    def close(self):
        with self._lock:
            if self._closed:
                return
            if self._process_source is not None:
                self._process_source.close()
                self._process_source = None
            if self._backend is not None:
                self._backend.close()
            self._module_names.clear()
            self._opaque_targets.clear()
            self._recognized_targets.clear()
            self._stack_addresses.clear()
            self._ownimage_manifest = None
            self._caller = None
            self._runtime = None
            self._tap = None
            self._closed = True
