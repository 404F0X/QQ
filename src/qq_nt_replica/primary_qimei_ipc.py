"""Finite qimei.dll A4AA8/A4FDA/A54B6 IPC component; facade not connected."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
import threading


class IPCError(RuntimeError):
    pass


def object_name(owner, suffix):
    if type(owner) is not bytes or not owner or b'\0' in owner or suffix not in (b'm', b'e'):
        raise IPCError('IPC names require an owner C string and source suffix')
    return hashlib.md5(owner + b'sdbgnhrwq002' + suffix).hexdigest().upper().encode('ascii')


def _crypt(data):
    key = bytes.fromhex('0df293c75a0331e6')
    box = list(range(256)); j = 0
    for i in range(256):
        j = (j + box[i] + key[i % 8]) % 256
        box[i], box[j] = box[j], box[i]
    i = j = 0; output = bytearray()
    for value in data:
        i = (i + 1) % 256; j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        output.append(value ^ box[(box[i] + box[j]) % 256])
    return bytes(output)


@dataclass
class _State:
    owner: bytes
    mapping: object = None
    view: object = None
    event: object = None
    event_wrapper: object = None
    cache: object = None
    enabled: bool = False
    initialized: bool = False


class QimeiIPCPool:
    """Creator-thread session. current_epoch(runtime) must return the live module epoch."""
    source_pool_finalization = 'unknown'

    def __init__(self, runtime, epoch, current_epoch, backend):
        if epoch is None or not callable(current_epoch):
            raise IPCError('explicit runtime module epoch required')
        self.runtime, self.epoch, self.current_epoch = runtime, epoch, current_epoch
        self.backend = backend
        self.identity = os.getpid(), threading.get_native_id()
        self.states = {}; self.active = 0; self.terminal = False
        self.diagnostics = []
        self._unclosed_consumed_events = []
        backend.bind(self)

    def _check(self):
        if (self.terminal or self.identity != (os.getpid(), threading.get_native_id()) or
                self.current_epoch(self.runtime) is not self.epoch):
            raise IPCError('IPC session is terminal, foreign-thread or stale-epoch')

    @contextmanager
    def _operation(self, owner):
        self._check(); object_name(owner, b'm')
        if self.active:
            raise IPCError('IPC source operation is already active')
        self.active += 1
        try:
            yield
        finally:
            self.active -= 1

    def initialize(self, owner):
        with self._operation(owner):
            if owner in self.states:
                raise IPCError('repeat initialization unsupported before any source IO')
            state = self.states[owner] = _State(owner)
            b = self.backend
            state.mapping = b.open_mapping(owner, object_name(owner, b'm'))
            if state.mapping is None:
                state.mapping = b.create_mapping(owner, object_name(owner, b'm'))
            if state.mapping is not None:
                state.view = b.map_view(owner, state.mapping)
            wrapper = b.allocate_event_wrapper(owner)
            state.event = b.open_event(owner, object_name(owner, b'e'))
            if state.event is None:
                state.event = b.create_event(owner, object_name(owner, b'e'))
            state.event_wrapper = wrapper
            state.cache = b.allocate_cache(owner)
            state.enabled = state.view is not None and state.cache is not None
            state.initialized = True
            return state.enabled

    def _state(self, owner):
        state = self.states.get(owner)
        if state is None or not state.initialized:
            raise IPCError('IPC owner initialization incomplete')
        return state

    def _read(self, state):
        raw = self.backend.read_view(state.owner, state.view)
        if type(raw) is not bytes or len(raw) != 41:
            raise IPCError('IPC view read must preserve exact 41 bytes')
        if any(raw):
            decoded = _crypt(raw)
            state.cache[:41] = decoded
        return True

    def _consume_event(self, state):
        if state.event is not None:
            self.backend.set_event(state.owner, state.event)
            if not self.backend.close_event(state.owner, state.event):
                self._unclosed_consumed_events.append((state.owner, state.event))
            state.event = None
        if state.event_wrapper is not None:
            state.event_wrapper = None
            self.diagnostics.append(('source_event_consumed', state.owner))

    def consume(self, owner):
        with self._operation(owner):
            state = self._state(owner)
            if not state.enabled:
                return b''
            success = self._read(state)
            if not (success and state.cache[0]) and state.event_wrapper is not None:
                if state.event is not None:
                    self.backend.wait_event(owner, state.event)
                    self.backend.reset_event(owner, state.event)
                success = self._read(state)
            result = bytes(state.cache[:36]) if success and state.cache[0] else b''
            self._consume_event(state)
            return result

    def publish(self, owner, backing, signed_length):
        with self._operation(owner):
            if type(signed_length) is not int or not -(1 << 31) <= signed_length < (1 << 31):
                raise IPCError('publish requires a signed32 length')
            if backing is None or signed_length >= 37:
                return False
            state = self._state(owner)
            if not state.enabled:
                return False
            if type(backing) is not bytes or len(backing) < 36:
                raise IPCError('publish requires 36 actually readable bytes')
            state.cache[:36] = backing[:36]
            self.backend.write_view(owner, state.view, _crypt(bytes(state.cache[:41])))
            if state.event is not None:
                self.backend.set_event(owner, state.event)
            self._consume_event(state)
            return state.enabled

    def dispose_terminal(self):
        # Host disposal may retry retained debt, but never resumes Source IO.
        if (self.identity != (os.getpid(), threading.get_native_id()) or
                self.current_epoch(self.runtime) is not self.epoch):
            raise IPCError('IPC cleanup is foreign-thread or stale-epoch')
        if self.active:
            raise IPCError('active IPC operation prevents terminal disposal')
        self.terminal = True
        # Host management only, never a claim about the source pool destructor.
        errors = []
        for state in self.states.values():
            for field, method in (('view', 'unmap_view'), ('mapping', 'close_mapping'), ('event', 'close_event')):
                lease = getattr(state, field)
                if lease is None:
                    continue
                try:
                    if not getattr(self.backend, method)(state.owner, lease):
                        raise IPCError('terminal disposal failed: ' + method)
                    setattr(state, field, None)
                except Exception as error:
                    errors.append(error)
            if state.event is None:
                state.event_wrapper = None
            state.cache = None
        retained = []
        for owner, event in self._unclosed_consumed_events:
            try:
                if not self.backend.close_event(owner, event):
                    raise IPCError('terminal disposal failed: consumed event')
            except Exception as error:
                retained.append((owner, event))
                errors.append(error)
        self._unclosed_consumed_events = retained
        self.diagnostics.append(('host_resources_disposed', not errors))
        if errors:
            raise ExceptionGroup('IPC terminal disposal failures (owned records retained)', errors)
