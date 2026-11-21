from dataclasses import dataclass, field

from .errors import InputError
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable


PREFERRED_EXCLUSIONS = (b'usb', b'wifi', b'wi-fi', b'wireless', bytes.fromhex('e697a0e7babf'), b'bluetooth', bytes.fromhex('e8939de78999'), b'cdma', b'ev-do', b' 3g ', b'gmcc')


def dword(value):
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise InputError('MAC_DWORD')
    return value


@dataclass(frozen=True)
class PartialSelectorRecord:
    fragments: tuple = field(repr=False)

    def __post_init__(self):
        if type(self.fragments) is not tuple:
            raise InputError('MAC_RECORD_KNOWN_FRAGMENTS')
        end = 0
        for fragment in self.fragments:
            if type(fragment) is not tuple or len(fragment) != 2:
                raise InputError('MAC_RECORD_KNOWN_FRAGMENT')
            offset, raw = fragment
            if type(offset) is not int or type(raw) is not bytes or not raw or not end <= offset <= 0x1c8 - len(raw):
                raise InputError('MAC_RECORD_KNOWN_FRAGMENT_SPAN')
            end = offset + len(raw)

    def read(self, offset, size):
        if type(offset) is not int or type(size) is not int or size < 0 or not 0 <= offset <= 0x1c8 - size:
            raise InputError('MAC_RECORD_READ_SPAN')
        output, known = bytearray(size), bytearray(size)
        for start, raw in self.fragments:
            first, last = max(start, offset), min(start + len(raw), offset + size)
            if first < last:
                output[first - offset:last - offset] = raw[first - start:last - start]
                known[first - offset:last - offset] = b'\1' * (last - first)
        if not all(known):
            raise UnknownMemory('MAC_RECORD_UNKNOWN_BYTES')
        return bytes(output)


def record_read(record, offset, size):
    if type(record) is PartialSelectorRecord:
        record.__post_init__()
        return record.read(offset, size)
    if type(record) is not bytes or len(record) != 0x1c8:
        raise InputError('MAC_COMPLETE_RECORD_1C8')
    return record[offset:offset + size]


def record_cstring(record, offset, limit):
    output = bytearray()
    for index in range(limit):
        raw = record_read(record, offset + index, 1)
        if raw == b'\0':
            return bytes(output)
        output.extend(raw)
    raise PrimarySemanticUnavailable('MAC_RECORD_BOUNDED_CSTRING')


def records_checked(records):
    if type(records) is not tuple:
        raise InputError('MAC_COMPLETE_RECORD_TUPLE')
    for record in records:
        text = record_cstring(record, 0x10c, 129)
        if any(value >= 128 for value in text):
            raise PrimarySemanticUnavailable('MAC_NONASCII_CHARLOWERA_UNSUPPORTED')
        record_cstring(record, 0, 0x1c8)
    return records


def description(record):
    return record_cstring(record, 0x10c, 129).lower()


def select_records(records):
    records_checked(records)
    if len(records) < 2:
        return records
    kept = tuple(r for r in records if not any(x in description(r) for x in (b'vmware', b'ppp/slip'))
                 and record_read(r, 0, 4) != b'DEST' and record_read(r, 0, 3) != b'\0SE' and record_read(r, 0, 8) != bytes(8)
                 and b'RAS' not in record_cstring(r, 0, 0x1c8))
    cleaned = kept or records
    if len(cleaned) < 2:
        return cleaned
    preferred = tuple(r for r in cleaned if not any(x in description(r) for x in PREFERRED_EXCLUSIONS))
    return (min(preferred or cleaned, key=lambda r: record_read(r, 0, 8)),)


@dataclass(frozen=True)
class StageResult:
    status: int
    records: tuple

    def __post_init__(self):
        dword(self.status)
        records_checked(self.records)


@dataclass(frozen=True)
class StageSource:
    collect: object = field(repr=False)

    def __post_init__(self):
        if not callable(self.collect):
            raise InputError('MAC_STAGE_SOURCE')


@dataclass(frozen=True)
class ProcessedStages:
    primary: StageResult | StageSource | None
    command: StageResult | StageSource | None
    netbios: StageResult | StageSource | None

    def validate(self):
        for name in ('primary', 'command', 'netbios'):
            result = getattr(self, name)
            if result is None:
                continue
            if type(result) not in (StageResult, StageSource):
                raise InputError('MAC_STAGE_RESULT')
            result.__post_init__()


class PrimitiveTicks:
    def __init__(self, values, *, reader=None):
        if type(values) is not tuple:
            raise InputError('MAC_TICKS_TUPLE')
        for value in values:
            dword(value)
        if reader is not None and (values or not callable(reader)):
            raise InputError('MAC_PRIMITIVE_TICK_READER')
        self.values, self.used, self.events = values, 0, []
        self.reader = reader

    def take(self, stage, purpose):
        if self.reader is not None:
            value = dword(self.reader())
        elif self.used == len(self.values):
            raise PrimarySemanticUnavailable('MAC_PRIMITIVE_TICK_EXHAUSTED')
        else:
            value = self.values[self.used]
        self.used += 1
        self.events.append((stage, purpose, value))
        return value


class OwnSelectorCache:
    def __init__(self):
        self._maps = {stage: {} for stage in ('primary', 'command', 'netbios')}


_PROCESS_CACHE = OwnSelectorCache()


class MacSelector:
    def __init__(self, *, cache=None):
        self.cache = _PROCESS_CACHE if cache is None else cache
        if type(self.cache) is not OwnSelectorCache:
            raise InputError('MAC_OWN_CACHE')
        self.events = []

    def select(self, stages, ticks, *, mode=0, flags=3):
        if type(mode) is not int or mode != 0 or dword(flags) != 3:
            raise PrimarySemanticUnavailable('MAC_ONLY_MODE0_FLAGS3')
        if type(stages) is not ProcessedStages or type(ticks) is not PrimitiveTicks:
            raise InputError('MAC_PROCESSED_STAGE_AND_TICK_PRIMITIVES')
        stages.validate()
        for stage in ('primary', 'command', 'netbios'):
            status, records = self._stage(stage, flags, getattr(stages, stage), ticks)
            if status:
                return 1, records
        return 0, ()

    def _stage(self, stage, flags, result, ticks):
        entries = self.cache._maps[stage]
        previous = entries.get(flags)
        if previous is not None:
            status, stored, records = previous
            if status:
                self.events.append((stage, 'success_hit'))
                return 1, records
            now = ticks.take(stage, 'lookup')
            if ((now - stored) & 0xffffffff) < 3600000:
                self.events.append((stage, 'negative_hit'))
                return 0, records
        self.events.append((stage, 'collect'))
        if result is None:
            raise PrimarySemanticUnavailable('MAC_' + stage.upper() + '_RAW_STAGE_UNAVAILABLE')
        if type(result) is StageSource:
            result = result.collect()
        if type(result) is not StageResult:
            raise InputError('MAC_STAGE_RESULT')
        result.__post_init__()
        records = select_records(result.records) if result.status else result.records
        status = int(bool(result.status))
        stored = ticks.take(stage, 'store')
        entries[flags] = (status, stored, records)
        return status, records


@dataclass(frozen=True)
class SelectorNetwork:
    selector: MacSelector
    stages: ProcessedStages
    ticks: PrimitiveTicks
    mode: int = 0
    flags: int = 3

    def material(self):
        if type(self.selector) is not MacSelector:
            raise InputError('MAC_OWN_SELECTOR')
        status, records = self.selector.select(self.stages, self.ticks, mode=self.mode, flags=self.flags)
        return record_read(records[0], 0, 8).hex().upper().encode('ascii') if status and records else b' '
