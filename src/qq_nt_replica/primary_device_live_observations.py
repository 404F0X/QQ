import os
import threading

from .errors import InputError
from .primary_device_native import _HARDWARE_FLAG
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows import WindowsDeviceSource
from .primary_worker import WorkerObservations


class WindowsDeviceLiveObservations(WorkerObservations):
    def __init__(self, fallback=None, *, source=None):
        if source is not None and not isinstance(source, WindowsDeviceSource):
            raise InputError('device live observations require a WindowsDeviceSource')
        if fallback is not None and not isinstance(fallback, WorkerObservations):
            raise InputError('device live fallback requires typed worker observations')
        self._source = source
        self._owns_source = source is None
        self._fallback = fallback
        self._owner = os.getpid(), threading.get_native_id()
        self._runtime = None
        self._closed = False
        self.records = []

    def _check(self, runtime):
        if self._closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('device live observations require their open creator process and thread')
        if self._runtime is None:
            self._runtime = runtime
        elif self._runtime is not runtime:
            raise InputError('device live observations require their original runtime')

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if name != 'NtQuerySystemInformation':
            if self._fallback is None:
                raise PrimarySemanticUnavailable('device live API is not supported: ' + name)
            return self._fallback.take(runtime, name, arguments)
        if (type(arguments) is not tuple or len(arguments) != 4 or
                any(type(value) is not int or not 0 <= value < 1 << 64 for value in arguments) or
                arguments[0] != 1 or arguments[2:] != (12, 0)):
            raise InputError('device system information requires source class1/output12/null ReturnLength')
        expected = runtime.worker_imports.get(name)
        actual = runtime.memory.load(runtime.image_base + 0x6D83DE0, 8)
        if not expected or actual != expected or not runtime.memory.load(runtime.image_base + _HARDWARE_FLAG, 1) & 1:
            raise PrimarySemanticUnavailable('device system information source export is not initialized')
        output = arguments[1]
        runtime.memory._span(output, 12)
        if self._source is None:
            self._source = WindowsDeviceSource()
        runtime.memory.forget(output, 12, source='device_live.NtQuerySystemInformation.potential_output')
        status, raw = self._source.system_information()
        if type(status) is not int or not -(1 << 31) <= status < 1 << 31:
            raise InputError('device system information requires the signed32 NTSTATUS result')
        if (status == 0 and (type(raw) is not bytes or len(raw) != 12)) or (status != 0 and raw is not None):
            raise InputError('device system information output knownness differs from the source result')
        effects = ((output, raw),) if status == 0 else ()
        event = name, arguments, status & 0xFFFFFFFF, effects
        self.records.append(event)
        return WorkerObservations((event,)).take(runtime, name, arguments)

    def close(self):
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('device live observations close requires their creator process and thread')
        if self._closed:
            return
        if self._owns_source and self._source is not None:
            self._source.close()
        self._closed = True
