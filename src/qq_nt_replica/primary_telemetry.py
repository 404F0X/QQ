from dataclasses import dataclass

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


@dataclass(frozen=True)
class TelemetryMetadataProviders:
    first: object
    second: object

    def __post_init__(self):
        for name in ("first", "second"):
            value = getattr(self, name)
            if value is not None and not callable(value):
                if isinstance(value, (str, bytes, bytearray)):
                    raise InputError("metadata providers require streams of C-string observations")
                try:
                    object.__setattr__(self, name, iter(value))
                except TypeError as exc:
                    raise InputError("metadata providers require explicit observation streams") from exc


@dataclass(frozen=True)
class CachedProviderTelemetry:
    strings: tuple[bytes, ...]
    columns: tuple[bytes, ...]
    topic: bytes
    columns_allocation: int


class ProviderTelemetryState:
    def __init__(self):
        self.owner_guard = 0
        self.metadata_guard = 0
        self.enabled = 0
        self.metadata = {}
        self.metadata_allocations = {}
        self.cache = []
        self.cache_allocation = 0
        self.cache_capacity = 0

    def _initialize_owner(self, runtime):
        if self.owner_guard & 1 == 0:
            self.owner_guard |= 1
            runtime.events.append(("BD4540.telemetry_owner_guard_commit", self.owner_guard))
            self.enabled = 0
            self.cache = []
            self.cache_allocation = self.cache_capacity = 0
            runtime.events.append(("BD4460.telemetry_owner_initialize",))

    def _initialize_metadata(self, runtime):
        if self.metadata_guard & 1 == 0:
            self.metadata_guard |= 1
            runtime.events.append(("1BEFC84.telemetry_metadata_guard_commit", self.metadata_guard))
            self.metadata = {0x8: b"0", 0x28: b"", 0x40: b"", 0x58: b"", 0x70: b""}
            self.metadata_allocations = {}
            runtime.events.append(("1BEFC10.telemetry_metadata_initialize",))

    def _query_metadata(self, runtime):
        providers = runtime.telemetry_metadata_providers
        if providers is None:
            raise PrimarySemanticUnavailable("provider telemetry BD4460/1BEFC10 needs observed metadata callback bindings")
        captured = providers.first, providers.second
        lock = runtime.image_base + 0x67517D0
        if runtime.locks.get(lock, 0):
            raise PrimarySemanticUnavailable("provider telemetry metadata waits on an owned mutex")
        runtime.locks[lock] = 1
        runtime.events.append(("75AF50.lock", lock))
        for offset, provider in zip((0x70, 0x58), captured):
            if self.metadata[offset] or provider is None:
                continue
            try:
                observed = provider() if callable(provider) else next(provider)
            except StopIteration as exc:
                raise PrimarySemanticUnavailable("provider telemetry metadata callback has no observed result") from exc
            if observed is None:
                value = b""
            elif isinstance(observed, bytes):
                end = observed.find(b"\0")
                if end < 0:
                    raise PrimarySemanticUnavailable("provider telemetry metadata C-string terminator is unobserved")
                value = observed[:end]
            else:
                raise InputError("metadata callback result must be NULL or observed C-string bytes")
            runtime.events.append(("1BE26C0.metadata_result", offset, observed is not None, len(value)))
            allocation = 0
            if len(value) >= 23:
                allocation = runtime._allocate((len(value) + 16) & ~15, False)
                runtime.memory.write(allocation, value + b"\0", source="1BE26C0.metadata_string_copy")
            previous = self.metadata_allocations.get(offset, 0)
            if previous:
                runtime._free_allocation(previous)
            self.metadata[offset] = value
            self.metadata_allocations[offset] = allocation
            runtime.events.append(("1BE26C0.metadata_publish", offset, len(value)))
        runtime.locks[lock] = 0
        runtime.events.append(("75AFC0.unlock", lock))

    def _clone_sample_string(self, runtime):
        value = self.metadata[0x8]
        allocation = 0
        if len(value) >= 23:
            allocation = runtime._allocate((len(value) + 16) & ~15, False)
            runtime.memory.write(allocation, value + b"\0", source="8234B0.metadata_string_copy")
        return value, allocation

    def _sample(self, runtime):
        seed = runtime.postfetch_crt_seed
        if seed is None:
            raise PrimarySemanticUnavailable("provider telemetry sampling needs its worker CRT random state")
        if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
            raise InputError("postfetch worker CRT seed must be unsigned32")
        seed = (seed * 0x343FD + 0x269EC3) & 0xFFFFFFFF
        runtime.postfetch_crt_seed = seed
        sample = (seed >> 16) & 0x7FFF
        runtime.events.append(("3E99006.postfetch_thread_random_state", seed))
        value, allocation = self._clone_sample_string(runtime)
        length = len(value)
        if allocation:
            runtime._free_allocation(allocation)
        first = 0
        if length >= 5:
            value, allocation = self._clone_sample_string(runtime)
            if len(value) < 4:
                raise UnknownMemory("metadata changed before the sampler DWORD read")
            first = int.from_bytes(value[:4], "little")
            if allocation:
                runtime._free_allocation(allocation)
        value = self.metadata[0x70]
        second = int.from_bytes(value[:4], "little") if len(value) >= 5 else 0
        sample ^= first ^ second
        runtime.events.append(("1BEF7E0.telemetry_sample", sample))
        return sample

    def _append_cache(self, runtime, record):
        columns = tuple(record.strings[8:])
        temporary = runtime._allocate(0x90, False)
        runtime.events.append(("BD3BD0.telemetry_columns", temporary, len(columns)))
        lock = runtime.image_base + 0x677C0B0
        if runtime.locks.get(lock, 0):
            raise PrimarySemanticUnavailable("provider telemetry cache waits on an owned mutex")
        runtime.locks[lock] = 1
        runtime.events.append(("75AF50.lock", lock))
        old_allocation = self.cache_allocation
        allocation, capacity = old_allocation, self.cache_capacity
        growing = len(self.cache) == capacity
        if growing:
            if len(self.cache) + 1 >= 0x108421084210843:
                raise PrimaryProgramLimit("provider telemetry cache exceeds its native vector length domain")
            capacity = (max(2 * capacity, len(self.cache) + 1) if capacity < 0x84210842108421
                        else 0x108421084210842)
            allocation = runtime._allocate(capacity * 0xF8, False)
        column_copy = runtime._allocate(0x90, False)
        copied = CachedProviderTelemetry((record.strings[0],) + (b"",) * 7, tuple(value for value in columns),
                                         b"04d00075584", column_copy)
        self.cache.append(copied)
        self.cache_allocation, self.cache_capacity = allocation, capacity
        runtime.events.append(("1BEEC40.telemetry_cache_commit", allocation, len(self.cache), capacity))
        if growing and old_allocation:
            runtime._free_allocation(old_allocation)
        runtime.locks[lock] = 0
        runtime.events.append(("75AFC0.unlock", lock))
        runtime._free_allocation(temporary)

    def consume(self, runtime, record, *, force=False):
        if type(force) is not bool:
            raise InputError("telemetry force flag must be a boolean")
        self._initialize_owner(runtime)
        self._initialize_metadata(runtime)
        self._query_metadata(runtime)
        if not force and self._sample(runtime) % 10000:
            runtime.events.append(("1BEFC75.telemetry_sample_rejected", 0))
            return
        if self.enabled & 1:
            raise PrimarySemanticUnavailable("active provider telemetry serialization and deferred submission are not implemented")
        self._append_cache(runtime, record)
        runtime.events.append(("1BEFC73.telemetry_accepted_low_byte", 1))
