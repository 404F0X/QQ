"""Lazy void-ABI SRW/CV adapter over pinned module cells."""
import ctypes as C
import os

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


class WindowsModuleSync:
    def __init__(self, resource):
        from .primary_module_sync import _resource, MODEL_NATIVE
        if _resource(resource.runtime) is not resource or resource.backend != MODEL_NATIVE:
            raise InputError('SRW/CV requires sealed native model birth')
        self.resource = resource
        self.records = {}
        self.state = 'unheld'
        self.active = False
        self.waiters = 0
        self.closed = False
        self.kernel = None
        self.failures = []

    def _check(self, operation):
        resource = self.resource
        resource.validate(resource.runtime)
        if self.closed or self.active:
            raise InputError('SRW/CV adapter closed or active')
        if self.failures:
            raise PrimarySemanticUnavailable('module SRW/CV has unresolved native operation/recording failure') from self.failures[0][2]
        resource.owner._check_owner()
        if resource.owner._state not in ('constructing', 'open', 'closing'):
            raise InputError('SRW/CV owner no longer permits consumer operations')
        if not resource.permit(resource.owner, operation):
            raise PrimarySemanticUnavailable('module SRW/CV operation permit unavailable')

    def _backing(self, rva):
        if rva not in self.records:
            memory = self.resource.memory
            token, view = memory._pin_native_span(self.resource.base + rva, 8, self)
            try:
                native = (C.c_ubyte * 8).from_buffer(view)
            except BaseException:
                memory._unpin_native_span(token, self)
                view.release()
                raise
            self.records[rva] = token, view, native
        record = self.records[rva]
        self.resource.memory._validate_native_pin(record[0], self)
        return record

    def _api(self, name, pointer):
        if self.kernel is None:
            if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
                raise PrimarySemanticUnavailable('module SRW/CV requires Windows x64')
            self.kernel = C.WinDLL('kernel32', use_last_error=True)
        function = getattr(self.kernel, name)
        function.restype = None
        function.argtypes = (C.c_void_p,)
        function(pointer)

    def _call(self, name, rva, *, write_source=None):
        self._check(name)
        token, view, native = self._backing(rva)
        self.active = True
        errors = []
        try:
            if name == 'AcquireSRWLockExclusive':
                self.state = 'acquire_unknown'
            elif name == 'ReleaseSRWLockExclusive':
                self.state = 'release_unknown'
            try:
                self._api(name, C.addressof(native))
                if name == 'AcquireSRWLockExclusive':
                    self.state = 'held'
                elif name == 'ReleaseSRWLockExclusive':
                    self.state = 'unheld'
            except BaseException as error:
                self.failures.append((name, 'api', error))
                errors.append(error)
            finally:
                try:
                    self.resource.memory._record_native_write(token, self,
                        source=write_source or name + '.actual_module_backing')
                except BaseException as error:
                    self.failures.append((name, 'write_record', error))
                    errors.append(error)
        finally:
            self.active = False
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise BaseExceptionGroup('module SRW/CV native operation and recording failed', errors)
        return 0

    def acquire(self):
        if self.state != 'unheld':
            raise PrimarySemanticUnavailable('contended or unknown module SRW unsupported')
        return self._call('AcquireSRWLockExclusive', 0x674D4D0)

    def release(self):
        if self.state != 'held':
            raise InputError('module SRW is not known held')
        return self._call('ReleaseSRWLockExclusive', 0x674D4D0)

    def wake(self):
        return self._call('WakeAllConditionVariable', 0x674D4D8)

    def dispose_terminal(self):
        resource = self.resource
        resource.validate(resource.runtime)
        if (resource.owner._state != 'closing' or resource.owner._busy or self.active or
                resource.callbacks or self.waiters):
            raise InputError('module synchronization consumers are not quiescent')
        if self.failures:
            raise PrimarySemanticUnavailable('module SRW/CV failure unresolved; native backing retained') from self.failures[0][2]
        if self.state in ('acquire_unknown', 'release_unknown'):
            raise PrimarySemanticUnavailable('module SRW outcome unknown; native backing retained')
        for token, view, native in self.records.values():
            resource.memory._validate_native_pin(token, self)
        if self.state == 'held':
            # Host terminal release is not source condition-wait completion.
            self._call('ReleaseSRWLockExclusive', 0x674D4D0,
                write_source='host_terminal.module_sync.ReleaseSRWLockExclusive')
        for rva in tuple(self.records):
            token, view, native = self.records[rva]
            resource.memory._unpin_native_span(token, self)
            del self.records[rva]
            del native
            view.release()
        self.closed = True
        self.kernel = None
