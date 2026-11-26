from dataclasses import dataclass, field
import hashlib
from threading import RLock

from .primary_qimei_observations import QimeiApiReply
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer, _signed
from .primary_qimei_storage import StorageBuffer


RECORD_SIZE = 0x459


def default_flag_arrays():
    first, second = [1] * 21, [1] * 15
    for index in (13, 14, 15, 16, 17):
        first[index] = 0
    for index in (0, 3, 10, 13, 14):
        second[index] = 0
    return tuple(b''.join(value.to_bytes(4, 'little') for value in group) for group in (first, second))


def _api(observations, name, args, outputs=None):
    outputs = {} if outputs is None else outputs
    reply = observations.read('qimei-api', name, *args)
    if not isinstance(reply, QimeiApiReply):
        raise QimeiRequestError('explicit raw settings API reply required')
    return reply.result, reply.apply(outputs)


def _cstring(raw):
    position = raw.find(b'\0')
    if position < 0:
        raise QimeiRequestBoundary('source settings path C string exceeds known buffer')
    return raw[:position]


def _directory(path, observations):
    if path == b'.':
        return True
    exists, unused = _api(observations, 'PathIsDirectoryA', (path,))
    if exists:
        return True
    separator = path.rfind(b'\\')
    if separator >= 0 and not _directory(path[:separator], observations):
        return False
    result, unused = _api(observations, 'CreateDirectoryA', (path, 0))
    return result != 0


def settings_path(owner, observations):
    digest = hashlib.md5(_bytes(owner) + b'qimei.dll').hexdigest().upper().encode('ascii')
    buffer = StorageBuffer(bytes(260))
    found = False
    for identifier in (0x23, 0x1A):
        status, output = _api(observations, 'SHGetSpecialFolderPathA', (0, buffer, identifier, 1), {'data': buffer})
        buffer = output['data']
        if status:
            found = True
            break
    base = b''
    if found:
        base = _cstring(buffer.read()) + b'\\Tencent\\qimei'
        exists, unused = _api(observations, 'PathIsDirectoryA', (base,))
        if not exists:
            _directory(base, observations)
    return base + b'\\' + digest


@dataclass
class QimeiSettings:
    record: bytearray = field(default_factory=lambda: bytearray(b'\x03' + bytes(RECORD_SIZE - 1)), repr=False)
    path: bytes = field(default=b'', repr=False)
    initialized: int = 0
    loaded: int = 0
    dirty: int = 0
    _lock: object = field(default_factory=RLock, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.record, bytearray) or len(self.record) != RECORD_SIZE:
            raise QimeiRequestError('complete source settings record required')
        _bytes(self.path)
        for name in ('initialized', 'loaded', 'dirty'):
            setattr(self, name, _integer(getattr(self, name)) & 255)

    def initialize(self, owner, observations, *, first=None, first_count=None, second=None, second_count=None):
        return self._initialize_path(lambda: settings_path(owner, observations),
            first=first, first_count=first_count, second=second, second_count=second_count)

    def initialize_owned_path(self, *, path, first=None, first_count=None, second=None, second_count=None):
        """Own location policy; no claim of Shell folder discovery/creation."""
        def owned_path():
            value = _bytes(path)
            if not value or b'\0' in value:
                raise QimeiRequestBoundary('explicit nonempty Own settings path required')
            return value
        return self._initialize_path(owned_path,first=first,first_count=first_count,
            second=second,second_count=second_count)

    def _initialize_path(self, path_provider, *, first, first_count, second, second_count):
        if self.initialized != 0:
            return False
        if first is None and second is None:
            first, second = default_flag_arrays()
        first, second = _bytes(first), _bytes(second)
        self.path = path_provider()
        for offset, data, count in ((0x31, first, len(first) if first_count is None else first_count),
                                    (0x259, second, len(second) if second_count is None else second_count)):
            length = min(_signed(count, 32), 512)
            if length < 0 or length > len(data):
                raise QimeiRequestBoundary('source settings initialization copy exceeds known input backing')
            self.record[offset:offset + length] = data[:length]
        self.initialized = 1
        return True

    def refresh(self, *, read_file=None, codec=None, context_producer=None, observations=None):
        if not self.initialized & 1:
            return None
        with self._lock:
            if self.loaded != 0 and self.dirty == 0:
                return None
            if read_file is None:
                raise QimeiRequestBoundary('raw encrypted settings file provider required')
            ciphertext = _bytes(read_file(self.path))
            if not ciphertext:
                return 2
            if codec is None or context_producer is None or observations is None:
                raise QimeiRequestBoundary('source settings cipher and context production dependencies required')
            decoded = codec.decode_payload(ciphertext, capacity=RECORD_SIZE, context=context_producer.produce(observations))
            if decoded.source_code is None:
                raise QimeiRequestBoundary('source settings decode reached an undefined memory boundary')
            if decoded.source_code != 0 or not decoded.payload:
                return decoded.source_code
            if decoded.payload[0] == 3:
                self.record[:len(decoded.payload)] = decoded.payload
            self.loaded, self.dirty = 1, 0
            return 0

    def update_response(self, slots, *, clock, writer, **refresh_dependencies):
        """50E1E/A42B8: refresh, prefix update, source time, then persist."""
        return self._update_record(slots, base=9, count=22, clock=clock, writer=writer, **refresh_dependencies)

    def update_kind5_response(self, slots, *, clock, writer, **refresh_dependencies):
        """5127A: update the second record without replacing untouched tails."""
        return self._update_record(slots, base=0x231, count=16, clock=clock, writer=writer, **refresh_dependencies)

    def _update_record(self, slots, *, base, count, clock, writer, **refresh_dependencies):
        self.refresh(**refresh_dependencies)
        if slots is None or not slots:
            return
        from .primary_qimei_reply import ReplySlot
        slots = tuple(slots)
        if len(slots) > count or any(not isinstance(slot, ReplySlot) for slot in slots):
            raise QimeiRequestBoundary('response exceeds typed source record slot count')
        first = slots[0]
        if first.tag == 1 and first.data is not None:
            text = first.cstr[:31]
            self.record[base + 8:base + 9 + len(text)] = text + b'\0'
        flags = bytearray(512)
        length = 0
        for index, slot in enumerate(slots[1:]):
            if slot.tag in (0, 4):
                data = bytes(4) if slot.tag == 0 or slot.data is None else slot.data[:4]
                if len(data) != 4:
                    raise QimeiRequestBoundary('settings DWORD slot backing is shorter than four bytes')
                flags[index * 4:index * 4 + 4] = data
                length += 4
            elif slot.tag == 1:
                length += len(slot.cstr)
            else:
                break
            if length >= 512:
                length = 512
                break
        self.record[base + 40:base + 40 + length] = flags[:length]
        value = _integer(clock())
        if not -(1 << 63) <= value < (1 << 63):
            raise QimeiRequestBoundary('source _mktime64 result must be signed64')
        self.record[base:base + 8] = (value & ((1 << 64) - 1)).to_bytes(8, 'little')
        if self.initialized & 1:
            with self._lock:
                status = writer.save(self.path, bytes(self.record))
                if status == 0:
                    self.dirty = 1

    def flag(self, number, *, group=0, **dependencies):
        if group not in (0, 1) or type(group) is not int:
            raise QimeiRequestError('source settings flag group must be zero or one')
        self.refresh(**dependencies)
        offset = (0x31 if group == 0 else 0x259) + _signed(number, 32) * 4
        if offset < 0 or offset + 4 > len(self.record):
            raise QimeiRequestBoundary('source settings DWORD read exceeds known record backing')
        return int.from_bytes(self.record[offset:offset + 4], 'little')
