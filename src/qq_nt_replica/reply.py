"""Fresh-table model for an already preverified, decrypted handshake inner.

This is not a network response acceptance or cryptographic verification API.
Offsets count inspected bytes in this offline decoder, not a native cursor.
"""

from dataclasses import dataclass

from .errors import CapabilityUnavailable, InputError
from .wire import U32_MAX, U64_MAX, check_length, require_bytes


@dataclass(frozen=True)
class FieldRecord:
    key: int
    wire_kind: int
    value: bytes | int
    start: int
    end: int
    raw: bytes


@dataclass(frozen=True)
class FamilyRun:
    key: int
    family: str
    records: tuple[FieldRecord, ...]

    @property
    def storage_class(self) -> int:
        return {0: 5, 1: 11, 2: 8, 5: 10}[self.records[-1].wire_kind]


@dataclass(frozen=True)
class InnerParseResult:
    raw: bytes
    parse_al: int
    inspected_bytes: int
    ignored_suffix: bytes
    termination_reason: str
    field_start: int | None
    error: str | None
    records: tuple[FieldRecord, ...]
    family_runs: tuple[FamilyRun, ...]

    @property
    def consumed(self) -> int:
        """Alias for inspected_bytes; never a claim about the native cursor."""
        return self.inspected_bytes

    @property
    def current_fields(self) -> tuple[FamilyRun, ...]:
        current = {run.key: run for run in self.family_runs}
        return tuple(current[key] for key in sorted(current))

    def first_bytes(self, key: int) -> bytes:
        for run in self.current_fields:
            if run.key == key and run.family == "bytes":
                return run.records[0].value
        return b""

    def first_numeric(self, key: int) -> int:
        for run in self.current_fields:
            if run.key == key and run.family == "numeric":
                return run.records[0].value
        return 0


@dataclass
class OwnerState:
    o30: bytes
    o48: bytes

    def __post_init__(self) -> None:
        require_bytes(self.o30, "owner.o30")
        require_bytes(self.o48, "owner.o48")


@dataclass(frozen=True)
class PublicationEvent:
    kind: str
    value: bytes | int


@dataclass(frozen=True)
class InnerReplyResult:
    parse: InnerParseResult
    new30: bytes | None
    new48: bytes | None
    q: int | None
    events: tuple[PublicationEvent, ...]


def _read_varint(raw: bytes, offset: int) -> tuple[int, int, str | None]:
    value = 0
    for index in range(10):
        if offset == len(raw):
            return 0, offset, "truncated"
        byte = raw[offset]
        offset += 1
        value = (value | ((byte & 0x7F) << (7 * index))) & U64_MAX
        if byte < 0x80:
            return value, offset, None
    return 0, offset, "overlong"


def parse_preverified_decrypted_inner(raw: bytes) -> InnerParseResult:
    require_bytes(raw, "preverified/decrypted inner")
    check_length(len(raw), "inner input")
    records: list[FieldRecord] = []
    runs: list[FamilyRun] = []
    current: dict[int, int] = {}
    offset = 0

    def finish(al: int, reason: str, start: int | None, error: str | None = None):
        return InnerParseResult(
            raw, al, offset, raw[offset:] if al else b"", reason, start, error,
            tuple(records), tuple(runs),
        )

    if not raw:
        return finish(0, "empty_input", None, "empty input is rejected at the wrapper entry")

    while offset < len(raw):
        start = offset
        tag64, offset, error = _read_varint(raw, offset)
        # Tag primitive failure is normalized to tag zero by the native wrapper.
        # The same primitive's value/length failures below reject the parser.
        if error:
            return finish(1, f"{error}_tag", start)
        tag = tag64 & U32_MAX
        if tag == 0:
            return finish(1, "tag_zero", start)
        key, kind = tag >> 3, tag & 7
        if kind == 4:
            return finish(1, "wire4", start)
        if kind not in (0, 1, 2, 5):
            return finish(0, "invalid_wire_kind", start, f"unsupported wire kind {kind}")

        if kind == 0:
            value, offset, error = _read_varint(raw, offset)
            if error:
                return finish(0, f"{error}_numeric", start, f"{error} numeric varint")
        elif kind in (1, 5):
            width = 8 if kind == 1 else 4
            end = min(len(raw), offset + width)
            if end - offset != width:
                offset = end
                return finish(0, "truncated_fixed", start, f"wire kind {kind} needs {width} bytes")
            value = int.from_bytes(raw[offset:end], "little")
            offset = end
        else:
            length64, offset, error = _read_varint(raw, offset)
            if error:
                return finish(0, f"{error}_length", start, f"{error} length varint")
            length = length64 & U32_MAX
            if length & (1 << 31):
                return finish(0, "negative_length", start, "length low32 has its signed high bit set")
            end = min(len(raw), offset + length)
            if end - offset != length:
                offset = end
                return finish(0, "truncated_bytes", start, "bytes payload is shorter than its length")
            value = raw[offset:end]
            offset = end

        record = FieldRecord(key, kind, value, start, offset, raw[start:offset])
        records.append(record)
        family = "bytes" if kind == 2 else "numeric"
        previous = current.get(key)
        if previous is not None and runs[previous].family == family:
            old = runs[previous]
            runs[previous] = FamilyRun(key, family, old.records + (record,))
        else:
            current[key] = len(runs)
            runs.append(FamilyRun(key, family, (record,)))

    return finish(1, "end_of_input", None)


def apply_preverified_decrypted_inner(raw: bytes, owner: OwnerState) -> InnerReplyResult:
    if not isinstance(owner, OwnerState):
        raise InputError("owner must be OwnerState")
    parsed = parse_preverified_decrypted_inner(raw)
    if not parsed.parse_al:
        return InnerReplyResult(parsed, None, None, None, ())
    new30, new48 = parsed.first_bytes(1), parsed.first_bytes(2)
    bits = parsed.first_numeric(3)
    q = bits if bits < (1 << 63) else bits - (1 << 64)
    events = []
    owner.o30 = new30
    events.append(PublicationEvent("publish30", new30))
    owner.o48 = new48
    events.append(PublicationEvent("publish48", new48))
    if q > 0:
        events.append(PublicationEvent("schedule_intent", q))
    return InnerReplyResult(parsed, new30, new48, q, tuple(events))


def accept_server_handshake(wire: bytes) -> None:
    raise CapabilityUnavailable(
        "Server handshake acceptance is unavailable: primary/status gates, SHA/public-key "
        "verification, ECDSA API semantics, encrypted-envelope acceptance, ECDH, and GCM "
        "are not implemented. Supply only an independently preverified/decrypted inner "
        "to apply_preverified_decrypted_inner."
    )
