import os
import sys
import threading

from .errors import InputError
from .primary_notification_modules import _Enumeration, _SourceAlias, _SourceBuffer, _observe, require_claim
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows_worker_observations import WindowsWorkerAPIBackend


class WindowsModuleCollectorObservations:
    def __init__(self, parent, runtime, owner, backend=None):
        self.parent, self.runtime, self.owner = parent, runtime, owner
        self.claim = require_claim(runtime)
        self.identity = os.getpid(), threading.get_ident(), threading.get_native_id()
        self.session, self.binding = parent._session, parent._binding
        self.authority = parent._module_capability
        self.chain = runtime.worker_observations
        self.backend = WindowsWorkerAPIBackend() if backend is None else backend
        self.view = parent._provider.module_collector_view(runtime, owner, self.authority)
        self.buffers, self.aliases, self.records = {}, [], []
        self.enumeration = None
        self.closed = False
        self.admitting = True
        self.close_failure = None
        self.process = None
        self.process_seen = self.version_seen = False
        self.filename_stage = 0
        self.path_step = 0
        self.path_buffers = {}

    def check(self, runtime):
        if (self.closed or not self.admitting or runtime is not self.runtime or self.identity != (os.getpid(), threading.get_ident(), threading.get_native_id()) or
                require_claim(runtime) is not self.claim or self.claim.owner is not self.owner or
                self.claim.facade is not self or runtime.__dict__.get('notification_module_observations') is not self or
                self.parent._closed or self.parent._close_failure is not None or self.parent._runtime is not runtime or
                self.parent._session != self.session or self.parent._binding != self.binding or
                self.parent._module_capability is not self.authority or self not in self.parent._module_delegates or
                runtime.worker_observations is not self.chain):
            raise InputError('module collector facade lifetime, chain or slot changed')
        self.view.check(runtime)

    def _source(self, runtime, name, arguments, address, index):
        self.check(runtime)
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not _observe.__code__:
            frame = frame.f_back
        if (frame is None or frame.f_locals.get('runtime') is not runtime or
                frame.f_locals.get('name') != name or frame.f_locals.get('arguments') != arguments or
                frame.f_locals.get('address') != address or frame.f_locals.get('index') != index):
            raise InputError('module collector API requires its exact current source request frame')

    def _buffer(self, address, capacity):
        if not self.claim.frame <= address or address + capacity > self.claim.frame + 0x2738:
            raise InputError('module API buffer leaves its independent source stack frame')
        record = self.buffers.get(address)
        if record is None:
            record = _SourceBuffer(self.runtime, address, capacity)
            self.buffers[address] = record
        elif record.capacity != capacity:
            raise InputError('module API source allocation capacity changed')
        record.check()
        return record

    def take(self, runtime, name, arguments, address, index):
        self._source(runtime, name, arguments, address, index)
        try:
            result = self._take(runtime, name, arguments, address, index)
        except BaseException as error:
            self.records.append(dict(api=name, status='FAILED', errorClass=type(error).__name__, lastError=getattr(self.backend, 'last_error', None)))
            raise
        self.records.append(dict(api=name, status='OBSERVED', lastError=getattr(self.backend, 'last_error', None)))
        return result

    def _take(self, runtime, name, arguments, address, index):
        if type(arguments) is not tuple or any(type(value) is not int for value in arguments):
            raise InputError('module collector API requires exact source scalar arguments')
        if name in ('GetCurrentProcess', 'GetVersionExW', 'K32EnumProcessModules'):
            if self.chain is None or self.chain is not runtime.worker_observations:
                raise PrimarySemanticUnavailable('module collector lacks its original worker observation chain')
            if name == 'GetCurrentProcess':
                if arguments != () or self.process_seen or address or index is not None:
                    raise InputError('module process request is repeated or differs from zero ABI')
                result, effects = self.chain.take(runtime, name, arguments)
                if type(result) is not int or not 0 <= result < 1 << 64 or effects not in (None, b''):
                    raise InputError('module process result differs from source HANDLE ABI')
                self.process_seen, self.process = True, result
                return result
            if not self.process_seen or not self.process:
                raise InputError('module collector process is absent or null')
            if name == 'GetVersionExW':
                if arguments != (284,) or self.version_seen or index is not None:
                    raise InputError('module version requires its one initialized size284 call')
                buffer = self._buffer(address, 284)
                if buffer.initial() != ((284).to_bytes(4, 'little') + bytes(280), b'\1' * 284):
                    raise InputError('module version source preimage differs')
                result, effects = self.chain.take(runtime, name, arguments)
                if type(result) is not int or not 0 <= result <= 0xFFFFFFFF or type(effects) is not bytes or len(effects) != 284:
                    raise InputError('module version requires actual unsigned BOOL and full initialized postimage')
                buffer.apply((effects, b'\1' * 284))
                self.version_seen = True
                return result
            if arguments != (self.process, 8192) or self.enumeration is not None or index is not None or self.path_step != 8:
                raise InputError('module enumeration requires its unique current process and capacity')
            buffer = self._buffer(address, 8192)
            result, effects = self.chain.take(runtime, name, arguments)
            self.enumeration = _Enumeration(self.process, result, effects, buffer)
            return result, self.enumeration.needed
        if not self.version_seen:
            raise InputError('module path API precedes its original process/version prefix')
        if name == 'GetModuleFileNameA':
            expected = ((0, 261), (runtime.image_base, 260))
            if (self.filename_stage >= 2 or self.path_step not in (0, 2) or
                    arguments != expected[self.filename_stage] or any(type(value) is not int for value in arguments) or index is not None):
                raise InputError('module filename role or source capacity differs')
            buffer = self._buffer(address, arguments[1])
            if buffer.initial() != (bytes(arguments[1]), b'\1' * arguments[1]):
                raise InputError('module filename requires its original zero initialized source local')
            actual = arguments
            if self.filename_stage == 1:
                actual, token = self.view.filename_a_relocation(runtime, arguments, self.view)
                if token is not self.view:
                    raise InputError('module filename borrowed authority changed')
            result, effects = self.backend.module_request(name, actual, buffer.initial())
            buffer.apply(effects)
            self.path_buffers[self.filename_stage] = buffer
            self.filename_stage += 1
            self.path_step += 1
            return result
        if name == 'PathRemoveFileSpecA':
            buffer = self.buffers.get(address)
            expected = self.path_buffers.get(0 if self.path_step == 1 else 1)
            if (arguments != () or index is not None or buffer is None or buffer is not expected or
                    self.path_step not in (1, 3, 4, 5, 6, 7)):
                raise InputError('module removal requires its same filename allocation')
            buffer.cstring()
            result, effects = self.backend.module_request(name, (), buffer.initial())
            buffer.apply(effects)
            self.path_step += 1
            return result
        if name == 'K32GetModuleFileNameExA':
            if (type(arguments) is not tuple or len(arguments) != 3 or arguments[0] != self.process or arguments[2] != 260 or
                    self.enumeration is None):
                raise InputError('module path requires its actual current enumeration')
            self.enumeration.current(index, arguments[1])
            buffer = self._buffer(address, 260)
            result, effects = self.backend.module_request(name, arguments, buffer.initial())
            buffer.apply(effects)
            self.enumeration.advance()
            return result
        if name == 'PathFindFileNameA':
            if type(arguments) is not tuple or len(arguments) != 1 or type(arguments[0]) is not int or arguments[0] != address or index is not None:
                raise InputError('module basename requires its actual input CString pointer')
            raw = bytearray()
            for offset in range(520):
                value = runtime.memory.load(address + offset, 1)
                raw.append(value)
                if not value:
                    break
            else:
                raise PrimarySemanticUnavailable('module basename input exceeds its admitted terminated domain')
            buffer = _SourceBuffer(runtime, address, len(raw))
            offset, effects = self.backend.module_request(name, (), buffer.initial())
            if effects != buffer.initial():
                raise InputError('module basename changed its actual input CString')
            alias = _SourceAlias(buffer, offset)
            self.aliases.append(alias)
            return alias.pointer()
        raise PrimarySemanticUnavailable('module collector API is outside its finite source contract')

    def close(self):
        if self.closed:
            return
        if self.close_failure is not None:
            raise self.close_failure
        if self.identity != (os.getpid(), threading.get_ident(), threading.get_native_id()):
            raise InputError('module facade close requires its creating worker thread')
        self.admitting = False
        try:
            for alias in self.aliases:
                alias.buffer.close()
                alias.close()
            for buffer in self.buffers.values():
                buffer.close()
            if self.enumeration is not None:
                self.enumeration.close()
            self.view.close()
        except BaseException as error:
            self.close_failure = error
            raise
        self.closed = True
        self.aliases.clear()
        self.buffers.clear()
        self.path_buffers.clear()
        self.enumeration = self.chain = None
        self.parent = self.runtime = self.owner = self.claim = self.authority = None
        self.session = self.binding = self.backend = None
