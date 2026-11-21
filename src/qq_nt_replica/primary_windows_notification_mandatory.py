import ctypes as C
import os
import sys
import threading

from .errors import InputError
from .primary_device_integrity import IntegrityObservations, IntegrityObservation, IntegrityWrite, _IMPORTS
from .primary_logger import _cstring
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable


_MASK = (1 << 64) - 1
_SIGNATURES = {
    'GetModuleHandleA': (C.c_void_p, (C.c_void_p,)),
    'GetProcAddress': (C.c_void_p, (C.c_void_p, C.c_void_p)),
    'GetModuleFileNameA': (C.c_uint32, (C.c_void_p, C.c_void_p, C.c_uint32)),
    'CreateFileA': (C.c_void_p, (C.c_void_p, C.c_uint32, C.c_uint32, C.c_void_p, C.c_uint32, C.c_uint32, C.c_void_p)),
    'ReadFile': (C.c_int32, (C.c_void_p, C.c_void_p, C.c_uint32, C.c_void_p, C.c_void_p)),
    'SetFilePointer': (C.c_uint32, (C.c_void_p, C.c_int32, C.c_void_p, C.c_uint32)),
    'IsBadReadPtr': (C.c_int32, (C.c_void_p, C.c_size_t)),
    'CloseHandle': (C.c_int32, (C.c_void_p,)),
}


class WindowsNotificationMandatoryAPIBackend:
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise PrimarySemanticUnavailable('mandatory raw service requires Windows AMD64')
        library = C.WinDLL('kernel32', use_last_error=True)
        self.functions = {}
        for name, (result, arguments) in _SIGNATURES.items():
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            self.functions[name] = function
        self.reader = library.ReadProcessMemory
        self.reader.restype = C.c_int32
        self.reader.argtypes = (C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p)

    def call(self, name, *arguments):
        if name not in self.functions:
            raise InputError('mandatory backend API is outside its finite domain')
        result = self.functions[name](*arguments)
        return int(result or 0) & (_MASK if name in ('GetModuleHandleA', 'GetProcAddress', 'CreateFileA') else 0xFFFFFFFF)

    def read_loaded(self, address, size):
        buffer, count = C.create_string_buffer(size), C.c_size_t()
        if not self.reader(C.c_void_p(-1), address, buffer, size, C.byref(count)) or count.value != size:
            raise PrimarySemanticUnavailable('mandatory current-process loaded read failed or was short')
        return buffer.raw


class WindowsNotificationMandatoryService(IntegrityObservations):
    def __init__(self, observer, owner, view, backend=None):
        super().__init__(())
        self.observer, self.owner, self.view, self.backend = observer, owner, view, backend
        self.runtime, self.generation = owner.runtime, owner.runtime._main_generation
        self.thread = os.getpid(), threading.get_ident(), threading.get_native_id()
        self.session, self.binding = observer._session, observer._binding
        self.stack, self.files, self.records = [], {}, []
        self.closed = False
        self.read_count = 0

    def _check(self, runtime, *, active=True):
        if (self.closed or runtime is not self.runtime or not self.owner.valid() or
                self.thread != (os.getpid(), threading.get_ident(), threading.get_native_id()) or
                runtime._main_generation != self.generation or self.observer._closed or
                self.observer._runtime is not runtime or self.observer._session != self.session or
                self.observer._binding != self.binding):
            raise PrimarySemanticUnavailable('mandatory raw service lost its notification lifetime')
        self.view.check(runtime)
        if active:
            from .primary_notification_mandatory_maps import _ProducerClaim
            claim = runtime.__dict__.get('_notification_mandatory_claim')
            if not self.stack or type(claim) is not _ProducerClaim or self.stack[-1]['claim'] is not claim or not claim.valid():
                raise InputError('mandatory raw service requires its exact active producer claim')
        return self.stack[-1] if self.stack else None

    def begin(self, runtime, rva, producer_claim):
        self._check(runtime, active=False)
        from .primary_notification_mandatory_maps import _ProducerClaim
        if (type(producer_claim) is not _ProducerClaim or not producer_claim.valid() or
                producer_claim.runtime is not runtime or producer_claim.owner is not self.owner or producer_claim.rva != rva or
                producer_claim.parent is not (self.stack[-1]['claim'] if self.stack else None)):
            raise InputError('mandatory raw producer entry differs from its source lifetime')
        self.stack.append(dict(claim=producer_claim, rva=rva, module=None, name=None, export=None,
                               path=None, function=None, stage='module', modules=set(), invalid_handle=False))

    def _backend(self):
        if self.backend is None:
            self.backend = WindowsNotificationMandatoryAPIBackend()
        return self.backend

    def _call(self, name, *arguments):
        result = self._backend().call(name, *arguments)
        width = 64 if name in ('GetModuleHandleA', 'GetProcAddress', 'CreateFileA') else 32
        if type(result) is not int or not 0 <= result < 1 << width:
            raise InputError('mandatory raw API returned a scalar with invalid width')
        self.records.append(dict(api=name, resultWidth=width, completed=True))
        if len(self.records) > 8192:
            raise PrimarySemanticUnavailable('mandatory API observation bound reached')
        return result

    def take(self, runtime, name, arguments):
        state = self._check(runtime)
        from .primary_device_integrity import _api
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not _api.__code__:
            frame = frame.f_back
        if frame is None or frame.f_locals.get('runtime') is not runtime or frame.f_locals.get('name') != name or frame.f_locals.get('arguments') != arguments:
            raise InputError('mandatory API observation lacks its actual typed source call')
        if name not in _IMPORTS or runtime.worker_imports.get(name) is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != runtime.worker_imports[name]:
            raise InputError('mandatory raw API lost its current IAT identity')
        writes = []
        if name == 'GetModuleHandleA':
            if len(arguments) != 1:
                raise InputError('mandatory module lookup ABI differs')
            module_name = _cstring(runtime, arguments[0])
            expected = state['claim'].source.f_locals
            allowed = (b'QQNT.dll',) if state['rva'] == 0x2DF7BF0 else ((b'wrapper.node', b'QQNT.dll') if state['rva'] == 0x2E01C70 else (b'Kernel32.dll', b'ntdll.dll'))
            if module_name not in allowed:
                raise InputError('mandatory module lookup leaves its source names')
            if state['rva'] == 0x2DF7630 and (state['stage'] != 'module' or arguments[0] != expected.get('module_name')):
                raise InputError('mandatory detector module lookup is replayed or foreign')
            result = self._call(name, C.create_string_buffer(module_name + b'\0'))
            state.update(module=result, name=module_name, path=None, export=None, function=None, stage='export' if state['rva'] == 0x2DF7630 else 'loaded')
            if result:
                state['modules'].add(result)
        elif name == 'GetProcAddress':
            if state['rva'] != 0x2DF7630 or state['stage'] != 'export' or arguments[0] != state['module'] or arguments[1] != state['claim'].source.f_locals.get('export_name'):
                raise InputError('mandatory export lookup lacks its preceding module observation')
            export = _cstring(runtime, arguments[1])
            from .primary_notification_mandatory_maps import _DETECTORS
            if (state['name'], export) not in tuple((row[0], row[1]) for row in _DETECTORS):
                raise InputError('mandatory export lookup leaves its five source pairs')
            result = self._call(name, arguments[0], C.create_string_buffer(export + b'\0'))
            state.update(export=export, function=result, stage='loaded')
        elif name == 'GetModuleFileNameA':
            if len(arguments) != 3 or arguments[0] != state['module'] or arguments[2] != 260 or state['stage'] != 'loaded':
                raise InputError('mandatory module filename differs from its observed module')
            buffer = C.create_string_buffer(260)
            result = self._call(name, arguments[0], buffer, 260)
            state['path'] = buffer.raw.split(b'\0', 1)[0] if result and b'\0' in buffer.raw else None
            writes.append(IntegrityWrite(arguments[1], buffer.raw))
        elif name == 'CreateFileA':
            if len(arguments) != 7 or state['path'] is None or _cstring(runtime, arguments[0]) != state['path'] or arguments[1:] != (0x80000000, 1, 0, 3, 0x80, 0):
                raise InputError('mandatory disk comparison path differs from its actual module filename')
            result = self._call(name, C.create_string_buffer(state['path'] + b'\0'), *arguments[1:])
            state['invalid_handle'] = result == _MASK
            if result not in (0, _MASK):
                if result in self.files:
                    raise PrimarySemanticUnavailable('mandatory file handle aliases an existing owned handle')
                self.files[result] = state['claim']
        elif name in ('ReadFile', 'SetFilePointer', 'CloseHandle'):
            handle = arguments[0]
            if self.files.get(handle) is not state['claim'] and not (handle == _MASK and state['invalid_handle']):
                raise InputError('mandatory file API lacks its producer-owned handle')
            if name == 'ReadFile':
                if len(arguments) != 5 or arguments[2] not in (40, 64, 264, 1000) or arguments[4] != 0:
                    raise InputError('mandatory file read leaves its exact source spans')
                buffer, count = C.create_string_buffer(arguments[2]), C.c_uint32()
                result = self._call(name, handle, buffer, arguments[2], C.byref(count), None)
                if count.value > arguments[2]:
                    raise InputError('mandatory file read returned an oversized byte count')
                writes.extend((IntegrityWrite(arguments[1], buffer.raw[:count.value]), IntegrityWrite(arguments[3], count.value.to_bytes(4, 'little'))))
            elif name == 'SetFilePointer':
                if len(arguments) != 4 or arguments[2:] != (0, 0):
                    raise InputError('mandatory file seek leaves its source ABI')
                result = self._call(name, handle, C.c_int32(arguments[1]).value, None, 0)
            else:
                result = self._call(name, handle)
                if result:
                    self.files.pop(handle, None)
        elif name == 'IsBadReadPtr':
            if len(arguments) != 2 or arguments[1] != 1000 or not self._in_module(state, arguments[0], 1000):
                raise InputError('mandatory pointer check leaves its observed loaded module')
            result = self._call(name, *arguments)
        else:
            raise InputError('mandatory raw API is outside its finite producer domain')
        return IntegrityObservation(name, arguments, result, tuple(writes))

    def _in_module(self, state, address, size):
        return any(module <= address and address + size <= module + 0x10000000 for module in state['modules'])

    def read_loaded(self, runtime, address, size):
        state = self._check(runtime)
        from .primary_device_integrity import _loaded
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not _loaded.__code__:
            frame = frame.f_back
        if frame is None or frame.f_locals.get('runtime') is not runtime or frame.f_locals.get('address') != address or frame.f_locals.get('size') != size:
            raise InputError('mandatory loaded read lacks its actual source request')
        if type(address) is not int or type(size) is not int or not 0 < size <= 1000 or not 0 <= address <= _MASK - size:
            raise InputError('mandatory loaded read span is invalid')
        if state['stage'] != 'loaded':
            raise InputError('mandatory loaded read precedes its module/export observation')
        if state['rva'] == 0x2DF7630:
            source = state['claim'].source.f_locals
            index, remaining = source.get('index'), source.get('remaining')
            if type(index) is not int or not 0 <= index < remaining or size != 1 or address != (state['function'] + index) & _MASK:
                raise InputError('mandatory detector read differs from its current source byte')
        elif not self._in_module(state, address, size):
            raise PrimarySemanticUnavailable('mandatory loaded read leaves its observed module range')
        if self.read_count >= 1 << 20:
            raise PrimarySemanticUnavailable('mandatory loaded read count bound reached')
        self.read_count += 1
        raw = self._backend().read_loaded(address, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise PrimarySemanticUnavailable('mandatory loaded read was incomplete')
        return raw

    def source_address(self, runtime, rva):
        self._check(runtime)
        if rva != 0x3E91B50:
            raise InputError('mandatory relocation is limited to its source critical pointer')
        return self.view.source_address(runtime, rva)

    def end(self, runtime, rva):
        state = self._check(runtime)
        if state['rva'] != rva:
            raise InputError('mandatory producer exit is out of order')
        failure = None
        for handle, claim in tuple(self.files.items()):
            if claim is state['claim']:
                try:
                    if not self._call('CloseHandle', handle):
                        raise PrimarySemanticUnavailable('mandatory owned comparison file close failed')
                    del self.files[handle]
                except BaseException as error:
                    if failure is None:
                        failure = error
        self.stack.pop()
        state.clear()
        if failure is not None:
            raise failure

    def close(self):
        if self.closed:
            return
        self._check(self.runtime, active=False)
        if self.stack or self.files:
            raise PrimarySemanticUnavailable('mandatory service retains unresolved producer/file resources')
        self.view.close()
        self.owner = self.runtime = self.view = self.observer = self.backend = None
        self.closed = True
