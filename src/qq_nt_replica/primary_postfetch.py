from collections import deque
from dataclasses import dataclass, field

from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed


@dataclass
class ProviderRefresh:
    state: object
    consumed: bool = False

    def clone(self, runtime):
        if self.consumed:
            raise InputError("postfetch functor has already been consumed")
        return ProviderRefresh(self.state)

    def destroy(self, runtime):
        if self.consumed:
            raise InputError("postfetch functor has already been consumed")
        self.consumed = True
        runtime.events.append(("28F0.postfetch_functor_destroy",))

    def invoke(self, runtime):
        if self.consumed:
            raise InputError("postfetch functor has already been consumed")
        self.state.refresh(runtime)


@dataclass(frozen=True)
class ProviderTelemetryRecord:
    strings: tuple[bytes, ...]

    def __post_init__(self):
        if (not isinstance(self.strings, tuple) or len(self.strings) != 14 or
                any(not isinstance(value, bytes) or len(value) >= 23 for value in self.strings)):
            raise InputError("provider telemetry requires its fourteen source short strings")

    @classmethod
    def empty_refresh(cls, state):
        unsigned = lambda value: str(value & 0xFFFFFFFFFFFFFFFF).encode("ascii")
        return cls((b"xwid",) + (b"",) * 7 +
                   (b"0", unsigned(state.refresh_duration_ms), b"1" if state.marker & 0xFF else b"0",
                    unsigned(state.duration_ms), b"0", b"-1"))

    @classmethod
    def nonempty_refresh(cls, state):
        unsigned = lambda value: str(value & 0xFFFFFFFFFFFFFFFF).encode("ascii")
        return cls((b"xwid",) + (b"",) * 7 +
                   (b"0", unsigned(state.refresh_duration_ms), b"1" if state.marker & 0xFF else b"0",
                    unsigned(state.duration_ms), b"1", b"-1"))

    @classmethod
    def device_failure(cls, secondary):
        if type(secondary) is not int or not 0 <= secondary <= 0xFFFFFFFFFFFFFFFF:
            raise InputError("device failure secondary result must be an observed QWORD")
        error = signed(secondary & 0xFFFFFFFF, 32)
        return cls((b"xerr_" + str(error).encode("ascii"),) + (b"",) * 13)

    def copy(self):
        return ProviderTelemetryRecord(tuple(value for value in self.strings))


@dataclass
class ProviderTelemetry:
    record: ProviderTelemetryRecord
    allocation: int
    consumed: bool = False

    @classmethod
    def create(cls, runtime, record):
        copied = record.copy()
        runtime.events.append(("BD3890.telemetry_record_copy",))
        allocation = runtime._allocate(0x180, False)
        runtime.events.append(("BD0A00.telemetry_functor_construct", allocation))
        return cls(copied, allocation)

    def clone(self, runtime):
        if self.consumed:
            raise InputError("postfetch functor has already been consumed")
        allocation = runtime._allocate(0x180, False)
        copied = self.record.copy()
        runtime.events.append(("BD4340.telemetry_functor_clone", allocation))
        return ProviderTelemetry(copied, allocation)

    def destroy(self, runtime):
        if self.consumed:
            raise InputError("postfetch functor has already been consumed")
        self.consumed = True
        runtime.events.append(("BD3AE0.telemetry_record_destroy",))
        runtime._free_allocation(self.allocation)
        runtime.events.append(("BD43C0.telemetry_functor_destroy", self.allocation))

    def invoke(self, runtime):
        if self.consumed:
            raise InputError("postfetch functor has already been consumed")
        runtime.events.append(("BD43E0.telemetry_invoke", self.allocation))
        from .primary_telemetry import ProviderTelemetryState
        if runtime.provider_telemetry is None:
            runtime.provider_telemetry = ProviderTelemetryState()
        runtime.provider_telemetry.consume(runtime, self.record)


@dataclass
class ProviderQueue:
    address: int
    capacity: int = 5000
    enabled: int = 0
    count: int = 0
    nodes: deque = field(default_factory=deque)

    def enqueue(self, runtime, function, *, notify=True):
        if self.enabled & 1 == 0:
            runtime.events.append(("BD5690.queue_disabled", self.address))
            function.destroy(runtime)
            return
        lock = self.address + 0x18
        if runtime.locks.get(lock, 0):
            raise PrimarySemanticUnavailable("provider postfetch enqueue waits on an owned queue mutex")
        runtime.locks[lock] = 1
        runtime.events.append(("75AF50.lock", lock))
        if self.count < (signed(self.capacity & 0xFFFFFFFF, 32) & 0xFFFFFFFFFFFFFFFF):
            node = runtime._allocate(56, False)
            clone = function.clone(runtime)
            self.nodes.append((node, clone))
            self.count = (self.count + 1) & 0xFFFFFFFFFFFFFFFF
            runtime.events.append(("BD5690.queue_append", self.address, node, self.count))
            if notify & 0xFF:
                runtime.events.append(("WakeConditionVariable", self.address + 0x20))
        else:
            runtime.events.append(("BD5690.queue_full", self.address, self.capacity, self.count))
        runtime.locks[lock] = 0
        runtime.events.append(("75AFC0.unlock", lock))
        function.destroy(runtime)

    def take_batch(self, runtime):
        lock = self.address + 0x18
        if runtime.locks.get(lock, 0):
            raise PrimarySemanticUnavailable("provider postfetch worker waits on an owned queue mutex")
        if self.count & 0xFFFFFFFF == 0:
            raise PrimarySemanticUnavailable("provider postfetch worker needs a condition-variable wake")
        runtime.locks[lock] = 1
        runtime.events.append(("75AF50.lock", lock))
        batch, self.nodes = self.nodes, deque()
        self.count = 0
        runtime.events.append(("BD5330.batch_transfer", self.address, len(batch)))
        runtime.locks[lock] = 0
        runtime.events.append(("75AFC0.unlock", lock))
        return batch


class ProviderPostfetch:
    def __init__(self, runtime):
        self.runtime = runtime
        self.address = runtime.image_base + 0x6751B50
        self.mode = runtime.memory.load(self.address + 0xD8, 4)
        self.closing = False
        self.closed = False
        self.start_complete = False
        self.invoke_incomplete = False
        self.queues = (ProviderQueue(self.address + 0x28), ProviderQueue(self.address + 0x60))
        self.batch = deque()
        self.retired_nodes = deque()
        runtime.events.append(("BD4710.postfetch_task_construct", self.address, self.mode))

    @property
    def claimed(self):
        return bool(self.runtime.memory.load(self.address + 0xF8, 1))

    @claimed.setter
    def claimed(self, value):
        self.runtime.memory.store(self.address + 0xF8, int(bool(value)), 1,
                                  source='BD07A5.task_start_claim')

    @property
    def running(self):
        return bool(self.runtime.memory.load(self.address + 0x20, 1) & 1)

    @running.setter
    def running(self, value):
        self.runtime.memory.store(self.address + 0x20, int(bool(value)), 1,
                                  source='BD49E0.task_running')

    def enqueue(self, runtime, state):
        self.enqueue_function(runtime, ProviderRefresh(state))

    def enqueue_function(self, runtime, function):
        if self.closing or self.closed:
            raise PrimarySemanticUnavailable("provider task is exiting or has been destroyed")
        if not self.claimed:
            self.claimed = True
            runtime.events.append(("BD0780.start_claim", self.address + 0xF8))
            lock = self.address + 0xE0
            if runtime.locks.get(lock, 0):
                raise PrimarySemanticUnavailable("provider postfetch startup waits on an owned mutex")
            runtime.locks[lock] = 1
            runtime.events.append(("75AF50.lock", lock))
            self.running = True
            for queue in self.queues:
                queue.enabled = True
                runtime.memory.store(queue.address + 45, 1, 1, source='BD49E0.task_queue_enable')
            runtime.events.append(("BD49E0.enable_before_thread_start", self.address))
            error = runtime.next_postfetch_start_error()
            if error:
                raise PrimaryProgramLimit("provider postfetch thread creation failed before BD502A/INT3")
            self.start_complete = True
            runtime.locks[lock] = 0
            runtime.events.append(("75AFC0.unlock", lock))
        if not self.start_complete:
            raise PrimarySemanticUnavailable("provider postfetch enqueue has an unresolved prior result from thread startup")
        copied = function.clone(runtime)
        argument = copied.clone(runtime)
        self.queues[0].enqueue(runtime, argument)
        copied.destroy(runtime)
        function.destroy(runtime)

    def run_batch(self, runtime):
        if self.closing or self.closed:
            raise PrimarySemanticUnavailable("provider task is exiting or has been destroyed")
        if not self.start_complete:
            raise PrimarySemanticUnavailable("provider postfetch worker has no completed thread startup")
        if self.invoke_incomplete:
            raise PrimarySemanticUnavailable("provider postfetch worker stopped in an incomplete callback")
        if not self.batch:
            self.batch = self.queues[0].take_batch(runtime)
        while self.batch:
            node, function = self.batch[0]
            if self.running:
                self.invoke_incomplete = True
                function.invoke(runtime)
                self.invoke_incomplete = False
            function.destroy(runtime)
            runtime._free_allocation(node)
            self.batch.popleft()
