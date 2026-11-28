from collections import deque
from dataclasses import dataclass
import math
import os
import threading
import time

from .errors import InputError
from .primary_request_transport import RequestTransportBinding, _COMMANDS
from .primary_sdk import construct_receiver
from .primary_sso_codec import PacketContext, SsoProfile, build_service_packet, parse_service_packet, split_frames
from .primary_sso_reserved import SignatureBytes
from .primary_sso_socket import SsoSocket, SsoSocketError


_TIMEOUT, _CLOSED, _IO, _PARSE, _SERVER, _SESSION, _PRE_SEND = range(1, 8)


class SsoTransportError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class SsoEvent:
    kind: str
    sdk_sequence: int | None = None
    wire_sequence: int | None = None
    code: int = 0


@dataclass(repr=False)
class _Request:
    command: bytes
    payload: bytes
    sdk_sequence: int
    wire_sequence: int | None = None
    deadline: float | None = None
    stage: str = 'queued'
    response: bytes = b''
    success: int = 0
    error: int = 0


def _seed(value):
    if type(value) is not int or not 1 <= value <= 0x7FFFFFFF:
        raise InputError('SSO_INITIAL_WIRE_SEQUENCE')
    return value


def _context(value, profile):
    if type(value) is not PacketContext or type(profile) is not SsoProfile or profile.protocol_version != 12:
        raise InputError('SSO_SERVER12_PROFILE_REQUIRED')


class SsoTransport:
    def __init__(self, *, image_base, receiver_context, channel, profile, context, session,
                 initial_wire_sequence, timestamp_seconds, entropy, request_timeout=10.0,
                 clock=time.monotonic, own_channel=False):
        if (type(image_base) is not int or not 0 <= image_base <= (1 << 64) - 0x41486F8 or
                type(receiver_context) is not int or not 0 <= receiver_context < 1 << 64 or
                type(channel) is not SsoSocket or type(own_channel) is not bool or
                not callable(timestamp_seconds) or not callable(entropy) or not callable(clock) or
                type(request_timeout) not in (int, float) or not math.isfinite(request_timeout) or request_timeout <= 0):
            raise InputError('SSO_TRANSPORT_INPUTS')
        _context(context, profile)
        self._identity = os.getpid(), threading.get_native_id()
        self._base, self._receiver_context = image_base, receiver_context
        self._channel, self._own_channel = channel, own_channel
        self._profile, self._context, self._session = profile, context, session
        self._next_wire = _seed(initial_wire_sequence)
        self._timestamp, self._entropy, self._clock = timestamp_seconds, entropy, clock
        self._timeout = float(request_timeout)
        self._owner = self._runtime = self._receiver = None
        self._queue, self._settlements, self._events = deque(), deque(), deque()
        self._pending = {}
        self._lock = threading.RLock()
        self._buffer = b''
        self._closed = self._stepping = self._link_failed = False
        self.binding = RequestTransportBinding(image_base + 0x63EC0, image_base + 0x1BE2F90,
                                               self._type, self._enqueue)
        self._known_streams = []
        self._admit_channel(channel)

    def _admit_channel(self, channel):
        if any(channel._socket is previous for previous in self._known_streams):
            raise InputError('SSO_SOCKET_STREAM_ALREADY_USED')
        channel._claim_transport()
        self._known_streams.append(channel._socket)

    def construction_setup(self, owner):
        from .primary_windows_signer import WindowsSigner
        self._check_thread()
        if (type(owner) is not WindowsSigner or owner._state != 'constructing' or owner._busy or
                self._owner is not None or self._closed or owner.signer.runtime.image_base != self._base or
                owner.signer.runtime.request_transport is not self.binding):
            raise InputError('SSO_CONSTRUCTION_OWNER')
        owner._check_owner()
        runtime = owner.signer.runtime
        if runtime.memory.load(self._base + 0x6751AB8 + 8, 8):
            raise InputError('SSO_RECEIVER_ALREADY_ASSIGNED')
        construct_receiver(runtime, self._receiver_context)
        receiver = runtime.memory.load(self._base + 0x6751AB8 + 8, 8)
        table = runtime.memory.load(receiver, 8)
        if (runtime.memory.load(table + 8, 8) != self.binding.send_address or
                runtime.memory.load(table + 16, 8) != self.binding.type_address):
            raise InputError('SSO_CONSTRUCTED_RECEIVER_TARGETS')
        self._owner, self._runtime, self._receiver = owner, runtime, receiver

    def _check_thread(self):
        if self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('SSO_APPLICATION_OWNER_THREAD')

    def _type(self, receiver):
        if receiver != self._receiver or self._closed:
            raise InputError('SSO_RECEIVER_IDENTITY')
        return 0

    def _enqueue(self, receiver, command, payload, sequence):
        if (not isinstance(command, bytes) or command not in _COMMANDS or not isinstance(payload, bytes) or
                type(sequence) is not int or not 0 <= sequence < 1 << 64):
            raise InputError('SSO_OUTBOUND_REQUEST')
        with self._lock:
            if self._closed or self._owner is None or receiver != self._receiver:
                raise InputError('SSO_OUTBOUND_CLOSED_OR_UNBOUND')
            if any(item.sdk_sequence == sequence for item in (*self._queue, *self._pending.values(), *self._settlements)):
                raise InputError('SSO_SDK_SEQUENCE_COLLISION')
            self._queue.append(_Request(memoryview(command).tobytes(), memoryview(payload).tobytes(), sequence))
        return 'queued'

    def _idle(self, *, workers=True):
        self._check_thread()
        owner = self._owner
        if owner is None:
            raise InputError('SSO_OWNER_UNBOUND')
        owner._check_owner()
        runtime = owner.signer.runtime
        if owner._state != 'open' or owner._busy or owner.signer.failed or runtime is not self._runtime:
            raise InputError('SSO_OWNER_NOT_IDLE')
        if workers and (runtime._active_main is not None or runtime._active_failed or runtime._execute_depth or
                runtime._program_calls or runtime.__dict__.get('_primary_direct_scope') is not None or
                runtime.__dict__.get('_primary_wait_session') is not None):
            raise InputError('SSO_OWNER_NOT_IDLE')
        if workers and owner._threads is not None and (owner._threads._execution.locked() or owner._threads._active_owner):
            raise InputError('SSO_WORKER_NOT_IDLE')

    @property
    def unsettled_count(self):
        with self._lock:
            return len(self._queue) + len(self._pending) + len(self._settlements)

    def take_events(self):
        self._check_thread()
        with self._lock:
            result = tuple(self._events)
            self._events.clear()
            return result

    def _event(self, kind, request=None, code=0):
        with self._lock:
            self._events.append(SsoEvent(kind, None if request is None else request.sdk_sequence,
                None if request is None else request.wire_sequence, code))

    def _fail_all(self, error):
        with self._lock:
            requests = (*self._queue, *self._pending.values())
            self._queue.clear()
            self._pending.clear()
            for request in requests:
                request.stage, request.success, request.error = 'settling', 0, error
                request.response = b''
                self._settlements.append(request)

    def _settle(self):
        while self._settlements:
            self._idle()
            request = self._settlements[0]
            if request.stage != 'settling':
                raise SsoTransportError('SSO_COMPLETION_PREVIOUSLY_FAILED')
            request.stage = 'completing'
            try:
                outcome = self._owner.complete_request(request.command, request.response,
                    success=request.success, sequence=request.sdk_sequence, error=request.error)
            except BaseException:
                request.stage = 'completion_failed'
                raise SsoTransportError('SSO_COMPLETION_FAILED') from None
            if outcome not in ('dispatched', 'no_pending'):
                request.stage = 'completion_failed'
                raise SsoTransportError('SSO_COMPLETION_OUTCOME')
            with self._lock:
                self._settlements.popleft()
            request.stage = 'complete'
            self._event('completed' if outcome == 'dispatched' else 'no_pending', request, request.error)
            request.response = request.payload = b''

    def _link_error(self, code):
        self._link_failed = True
        self._buffer = b''
        self._fail_all(code)
        if self._own_channel:
            self._channel.close()
        self._settle()

    def _random(self, size):
        result = self._entropy(size)
        if not isinstance(result, bytes) or len(result) != size:
            raise InputError('SSO_ENTROPY_RESULT')
        return result

    def _send_one(self):
        self._idle()
        request = self._queue[0]
        if request.stage != 'queued':
            raise SsoTransportError('SSO_REQUEST_PREVIOUSLY_FAILED')
        if self._next_wire > 0x7FFFFFFF:
            raise SsoTransportError('SSO_WIRE_SEQUENCE_EXHAUSTED_REQUIRES_NEW_SOCKET')
        request.wire_sequence = self._next_wire
        self._next_wire += 1
        snapshot = self._session, self._context, self._channel
        request.stage = 'signing'
        try:
            result = self._owner.sign_result(request.command, request.payload)
        except BaseException:
            request.stage = 'sign_failed'
            raise SsoTransportError('SSO_SIGN_FAILED') from None
        if self._owner._threads is not None:
            self._owner.drain()
        self._idle()
        if any(before is not after for before, after in zip(snapshot, (self._session, self._context, self._channel))):
            self._link_error(_SESSION)
            raise SsoTransportError('SSO_SESSION_CHANGED_DURING_SIGN')
        try:
            signature = SignatureBytes.from_primary_result(result)
            command = request.command.decode('ascii')
            encrypted_type = 2 if '.o3.ecdh_access.' in command and 'SsoSecureA2' not in command else (
                1 if self._session is not None else 2)
            timestamp = self._timestamp()
            trace = bytes(value & 15 for value in self._random(48))
            options = dict(profile=self._profile, signature=signature, timestamp_seconds=timestamp,
                           trace_nibbles=trace)
            plain = build_service_packet(request.wire_sequence, command, self._context, request.payload,
                                         encrypt_type=0, tea_padding=b'', **options)
            body_length = len(plain) - 18 - len(self._context.uin.encode('utf-8'))
            padding = self._random(10 - ((body_length + 1) & 7))
            frame = build_service_packet(request.wire_sequence, command, self._context, request.payload,
                                        encrypt_type=encrypted_type, tea_padding=padding, **options)
        except BaseException:
            with self._lock:
                self._queue.popleft()
                request.stage, request.error = 'settling', _PRE_SEND
                self._settlements.append(request)
            self._settle()
            raise SsoTransportError('SSO_PACKET_BUILD_FAILED') from None
        with self._lock:
            self._queue.popleft()
            request.stage, request.deadline = 'pending', self._clock() + self._timeout
            self._pending[request.wire_sequence] = request
        try:
            self._channel.send(frame)
        except (SsoSocketError, InputError):
            self._link_error(_IO)
            raise SsoTransportError('SSO_SEND_FAILED') from None
        self._event('sent', request)

    def _expire(self):
        now = self._clock()
        with self._lock:
            for sequence, request in tuple(self._pending.items()):
                if request.deadline <= now:
                    del self._pending[sequence]
                    request.stage, request.error = 'settling', _TIMEOUT
                    self._settlements.append(request)
                    self._event('timeout', request, _TIMEOUT)

    def _receive(self, timeout):
        try:
            chunk = self._channel.receive(timeout=timeout)
        except (SsoSocketError, InputError):
            self._link_error(_IO)
            raise SsoTransportError('SSO_RECEIVE_FAILED') from None
        if chunk is None:
            return
        self._expire()
        try:
            frames, self._buffer = split_frames(self._buffer + chunk)
            for frame in frames:
                if len(frame) < 5 or int.from_bytes(frame[:4], 'big') != 12 or frame[4] not in (0, 1, 2):
                    raise InputError('SSO_SERVER12_FRAME_REQUIRED')
                packet = parse_service_packet(frame, self._context.d2_key)
                if packet is None:
                    raise InputError('SSO_COMPLETE_FRAME_PARSE_FAILED')
                if packet.ret_code == -10001 and self._session is not None:
                    self._link_error(_SESSION)
                    raise SsoTransportError('SSO_SESSION_EXPIRED')
                with self._lock:
                    request = self._pending.pop(packet.seq, None)
                    if request is None:
                        self._event('unmatched_reply', code=packet.ret_code or 0)
                        continue
                    request.stage = 'settling'
                    request.success = int(not packet.ret_code)
                    request.response = packet.payload if request.success else b''
                    request.error = 0 if request.success else _SERVER
                    self._settlements.append(request)
                    if not request.success:
                        self._event('server_error', request, packet.ret_code)
        except (InputError, ValueError, OverflowError):
            self._link_error(_PARSE)
            raise SsoTransportError('SSO_COMPLETE_FRAME_INVALID') from None

    def step(self, *, max_requests=1, receive_timeout=0.0):
        self._check_thread()
        if (self._closed or self._stepping or type(max_requests) is not int or max_requests < 0 or
                type(receive_timeout) not in (int, float) or not math.isfinite(receive_timeout) or receive_timeout < 0):
            raise InputError('SSO_STEP_STATE')
        self._idle(workers=False)
        self._stepping = True
        try:
            if self._owner._threads is not None:
                self._owner.drain()
            self._idle()
            self._settle()
            if self._link_failed:
                raise SsoTransportError('SSO_CONNECTION_FAILED_REPLACE_SOCKET')
            self._expire()
            self._settle()
            budget = min(max_requests, len(self._queue))
            for _ in range(budget):
                self._send_one()
            self._receive(receive_timeout)
            self._expire()
            self._settle()
            return self.take_events()
        finally:
            self._stepping = False

    def replace_connection(self, channel, *, context, session, initial_wire_sequence, own_channel=False):
        self._check_thread()
        _context(context, self._profile)
        seed = _seed(initial_wire_sequence)
        if (self._closed or self._stepping or type(channel) is not SsoSocket or type(own_channel) is not bool or
                channel._socket is self._channel._socket or channel.closed):
            raise InputError('SSO_REPLACEMENT_CONNECTION')
        self._idle()
        self._admit_channel(channel)
        self._fail_all(_SESSION)
        self._settle()
        if self._own_channel:
            self._channel.close()
        self._channel, self._own_channel = channel, own_channel
        self._context, self._session = context, session
        self._next_wire, self._buffer, self._link_failed = seed, b'', False

    def close(self):
        self._check_thread()
        if self._closed:
            if self.unsettled_count:
                raise SsoTransportError('SSO_CLOSED_WITH_UNSETTLED_REQUESTS')
            return
        if self._stepping:
            raise InputError('SSO_CLOSE_DURING_STEP')
        unavailable = False
        if self._owner is not None:
            try:
                self._idle()
            except InputError:
                if self._owner._busy:
                    raise
                unavailable = True
        with self._lock:
            self._closed = True
        try:
            self._fail_all(_CLOSED)
            if unavailable and self.unsettled_count:
                raise SsoTransportError('SSO_CLOSE_OWNER_UNAVAILABLE')
            self._settle()
        finally:
            if self._own_channel:
                self._channel.close()
        if not self.unsettled_count:
            self._owner = self._runtime = None
