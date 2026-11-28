"""Controlled Own bootstrap: real model request/codec/pending, synthetic IO only."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys
import threading
from types import SimpleNamespace as NS, ModuleType
from unittest.mock import Mock, patch

import pytest
from test_primary_request_fingerprint import model_signer
from test_primary_own_sdk_request import Capi
from test_primary_source_cold12_binding import Inputs
from test_primary_source_cold12_reply import word, string
from qq_nt_replica import primary_authenticated_sdk_session as subject
from qq_nt_replica.primary_windows_signer import WindowsSigner
from qq_nt_replica.primary_signature_result import PrimarySignatureResult
from qq_nt_replica.primary_source_cold12_binding import DisabledEnvironment
from qq_nt_replica.primary_source_cold12 import store_own_type1_peer, _project_peer
from qq_nt_replica.primary_sso_tea import tea_encrypt, tea_decrypt
from qq_nt_replica.primary_worker_consumer import DeviceRecord
from qq_nt_replica.errors import InputError

ROOT = Path(__file__).resolve().parents[1]


class ModelOwner:
    own_business_identity = WindowsSigner.own_business_identity
    initialize_own_sdk_request = WindowsSigner.initialize_own_sdk_request
    set_own_session_id = WindowsSigner.set_own_session_id
    create_own_device_request = WindowsSigner.create_own_device_request
    complete_own_device_request = WindowsSigner.complete_own_device_request
    cancel_own_device_request = WindowsSigner.cancel_own_device_request
    bind_own_cold12 = WindowsSigner.bind_own_cold12
    encode_own_cold12 = WindowsSigner.encode_own_cold12
    receive_own_cold12 = WindowsSigner.receive_own_cold12

    def __init__(self):
        self._pid, self._thread = os.getpid(), threading.get_native_id()
        self._signer = model_signer()
        self._state, self._busy = 'open', False
        self._own_cold12 = None
        self._own_business_initialized = True
        self._own_business_uin = 123456789
        self._own_business_machine_id = bytes(range(16)).hex().encode('ascii')
        self.signs, self.calls, self.closes = [], [], 0

    _check_owner = WindowsSigner._check_owner

    def _operation(self, method, *args, **kwargs):
        self._check_owner()
        assert not self._busy
        self._busy = True
        try:
            self.calls.append((method, args))
            return getattr(self._signer, method)(*args, **kwargs)
        finally:
            self._busy = False

    def sign_result(self, command, body):
        assert not self._busy
        self.signs.append((command, body))
        return PrimarySignatureResult(b'MODEL-sign', b'MODEL-extra', b'MODEL-token')

    def close(self):
        self.closes += 1
        component = getattr(self._signer, '_own_sdk_request', None)
        if component is not None and not component.closed:
            component.close()
        self._state = 'closed'


class Socket:
    def __init__(self):
        self.sent, self.incoming = [], []
        self.closed, self.claims = 0, 0
        self.partial = None
        self.on_send = None
        self.command = None
        self.routing = b'123456789'
        self.wire_delta = 0
        self.status = 0
        self.ping_index_delta = 0
        self.fail_close = False
        self.fail_send = False
        self.empty = False
        self.uin = 123456789
        self.index = 17

    def _claim_transport(self):
        assert self.claims == 0
        self.claims += 1

    def reply(self, sequence, command):
        head = (word(sequence + self.wire_delta) + word(self.status) + string(b'') +
                string(self.command or command) + string(b'') + word(0) + string(b'') + word(0))
        # Real SDK error envelope; no counterfeit authentication/install success.
        plain = word(len(head) + 4) + head + string(b'\x10\xeb\x07')
        encrypted = tea_encrypt(plain, bytes(range(16)),
            random_padding=bytes(10 - ((len(plain) + 1) & 7)))
        outer = word(12) + b'\x01\0' + string(self.routing) + encrypted
        return word(len(outer) + 4) + outer

    def send(self, data):
        if self.on_send:
            self.on_send()
        if self.fail_send:
            raise OSError('MODEL send failure')
        count = min(len(data), self.partial or len(data))
        self.sent.append(data[:count])
        if self.partial:
            return count
        if data[4:8] == bytes.fromhex('01335239'):
            reply = bytearray(data + b'extension')
            reply[:4] = word(len(reply))
            reply[16] = 9  # Source does not require byte16==05 or exactly21B.
            reply[17:21] = word(self.index + self.ping_index_delta)
            self.incoming.extend((bytes(reply[:2]), bytes(reply[2:19]), bytes(reply[19:])))
        else:
            # Extract actual outbound wire sequence after real peer-key decrypt.
            route_offset = 9 + int.from_bytes(data[9:13], 'big') + 1
            cipher_offset = route_offset + int.from_bytes(data[route_offset:route_offset + 4], 'big')
            plain = tea_decrypt(data[cipher_offset:], bytes(range(16)))
            sequence = int.from_bytes(plain[4:8], 'big')
            self.outbound_plain = plain
            self.incoming.extend((self.reply(sequence, self.original.command),))
        return None

    def receive(self, *, timeout):
        if self.empty:
            return b''
        return self.incoming.pop(0) if self.incoming else None

    def close(self):
        self.closed += 1
        if self.fail_close:
            raise OSError('MODEL close debt')


@pytest.fixture(scope='module')
def auth():
    login = Path(os.environ['AUTHENTICATED_LOGIN_ROOT'])
    if 'independent_login_account_registration' not in sys.modules:
        runpy.run_path(str(login / 'G/entry.py'))['load_api']()
    Q, T = sys.modules['independent_qr_login'], sys.modules['independent_login_ticket_exchange']
    device = Q.QrDevice(bytes(range(16)), 'Windows', 'MODEL-device', Q.EcdhKeys.from_private_scalar(1))
    material = T.SessionMaterial(123456789, 'MODEL-uid', b'MODEL-d2', bytes(range(16)),
        b'MODEL-tgt', object(), object(), T.SessionProvenance(None, device, 0))
    return material, Q.DesktopQrProfile.experimental51728()


def session(auth, **overrides):
    owner, channel, inputs = ModelOwner(), Socket(), Inputs()
    options = dict(owner=owner, records=(DeviceRecord(7, b'value'),), session_id='Own local label',
        request_capi=Capi(), clock_inputs=dict(wall_seconds=lambda: 1, monotonic_ns=lambda: 1, clock_ns=lambda: 1),
        random_environment=NS(random_bytes=lambda n: b'1234'), state17_owner=None,
        cold12_inputs=inputs, own_cold12_inputs=True, appid_override=None, env_setting=DisabledEnvironment(),
        connector=lambda **kwargs: channel, ping_index=17, deadline=100., own_owner=False, clock=lambda: 1.)
    options.update(overrides)
    phase = subject.OwnBootstrapSdkSession(*auth, **options)
    original_create = owner.create_own_device_request
    def create(records):
        request = original_create(records)
        channel.original = request
        return request
    owner.create_own_device_request = create
    return phase, owner, channel, inputs


def test_raw_stored_round_trip_and_length_mask():
    raw = (bytes(range(256)) + b'x', b'MODEL-outer', bytes(range(16)))
    stored = store_own_type1_peer(*raw, lookup_key=b'123')
    assert stored.inner18 != raw[0] and stored.key78 != raw[2]
    wire = _project_peer(stored, b'123')
    assert (wire.inner18, wire.outer48, wire.key78) == raw


def test_real_original_chain_one_sign_sdk_error(auth):
    phase, owner, channel, inputs = session(auth)
    result = phase.run()
    assert (result.outcome, result.stage, result.code) == ('failed', 'sdk_status', 2000)  # Source normalizes unknown status-node code.
    component = owner._signer._own_sdk_request
    assert component._session_id == 'Own local label'
    assert component._session_receiver.sender is phase
    assert component._session_receiver.type(None) == 0 and component.flags & 255 == 1
    assert channel.claims == 1 and len(channel.sent) == 2
    assert owner.signs == [(phase._original.command, phase._original.body)]
    assert phase._encoded._request is phase._original
    assert phase._encoded.sdk_sequence == phase._original.sdk_sequence == 1
    assert phase._original.command.endswith((b'SsoSecureA2Access', b'SsoSecureA2Establish'))
    assert component._pending == []
    plain = channel.outbound_plain
    assert bytes(range(16)).hex().encode('ascii') in plain
    assert b'MODEL-tgt' in plain and b'MODEL-d2' in channel.sent[1]
    assert plain[8:12] == word(0x20067c69)
    assert plain[16:28] == bytes(10) + b'\x01\0'
    with pytest.raises(Exception):
        owner.create_own_device_request(())
    phase.close()
    assert channel.closed == inputs.closes == 1 and owner.closes == 0
    assert all(getattr(phase, field) is None for field in
        ('_component', '_original', '_encoded', '_binding', '_carrier', '_owner', '_runtime'))
    receiver = component._session_receiver
    for call, expected in ((phase.check_request, 'SINGLE_ORIGINAL'),
            (lambda: phase.check_binding(component), 'FOREIGN_BINDING'),
            (phase.start, 'SINGLE_USE'),
            (lambda: receiver.send(channel.original), 'ORIGINAL_REQUIRED')):
        with pytest.raises((InputError, subject.AuthenticatedSessionError), match=expected):
            call()
    with pytest.raises(InputError, match='SINGLE_ORIGINAL'):
        owner.create_own_device_request(())
    assert not owner._signer.failed
    assert component._session_id == 'Own local label' and component.flags & 255 == 1
    phase.close()
    assert channel.closed == 1


def test_explicit_profile_config_reaches_same_service_options_and_real_frame(auth):
    phase, owner, channel, inputs = session(auth, bind_profile_appid=True)
    profile = auth[1]
    assert profile.sub_app_id != profile.app_id
    assert phase._cold_config['init_config'] == {'appid': str(profile.sub_app_id)}
    with patch('qq_nt_replica.primary_login_msf_record.prepare') as original_vt80:
        phase.run()
        original_vt80.assert_not_called()
    binding = owner._own_cold12
    service = binding.appid_service
    assert service.binding is binding and service.binding.runtime is owner._signer.runtime
    assert service.appid_string == service.config_2a8 == str(profile.sub_app_id)
    assert binding.options.dword0 == service.current_appid() == profile.sub_app_id
    assert channel.outbound_plain[8:12] == word(binding.options.dword0)
    assert len(owner.signs) == 1 and inputs.seeds == 1
    phase.close()
    assert binding.closed and binding.appid_service is None
    with pytest.raises(InputError, match='idle initialized'):
        service.current_appid()


def test_profile_config_optin_conflict_precedes_connector_sign_and_entropy(auth):
    owner, connector, inputs = ModelOwner(), Mock(), Inputs()
    with pytest.raises(subject.AuthenticatedSessionError, match='APPID_CONFLICT'):
        session(auth, owner=owner, connector=connector, cold12_inputs=inputs,
            bind_profile_appid=True, appid_override=0)
    assert owner.calls == owner.signs == [] and inputs.seeds == 0
    connector.assert_not_called()
    for flag in (None, 0, 1):
        with pytest.raises(subject.AuthenticatedSessionError, match='EXPLICIT_INPUTS'):
            session(auth, bind_profile_appid=flag)
    # Explicit legacy override and default False keep their existing path.
    phase, owner, channel, inputs = session(auth, appid_override=23)
    phase.run()
    assert owner._own_cold12.appid_service is None
    assert channel.outbound_plain[8:12] == word(23)
    phase.close()


@pytest.mark.parametrize('attribute,value,match', [
    ('ping_index_delta', 1, 'PING_MISMATCH'), ('routing', b'foreign', 'UNKNOWN_RECEIVED_ROUTING'),
    ('wire_delta', 1, 'wire sequence'), ('command', b'foreign.command', 'command mismatch'),
    ('empty', True, 'EOF'), ('fail_send', True, 'send failure')])
def test_failures_cancel_only_original_and_preserve_gate(auth, attribute, value, match):
    phase, owner, channel, inputs = session(auth)
    setattr(channel, attribute, value)
    with pytest.raises(Exception, match=match):
        phase.run()
    assert owner._signer._own_sdk_request.flags & 255 == 1
    assert owner._signer._own_sdk_request._session_receiver.sender is phase
    assert owner._signer._own_sdk_request._pending == []
    assert channel.closed == inputs.closes == 1
    assert len(owner.signs) == (0 if attribute in ('ping_index_delta', 'empty', 'fail_send') else 1)


def test_rebind_pending_conflicts_and_gate_upper_bits(auth):
    phase, owner, channel, inputs = session(auth)
    owner.initialize_own_sdk_request(**phase._request_config)
    component = owner._signer._own_sdk_request
    component.flags = 0xabcdef34
    phase._component = component
    phase._state = 'running'
    owner.set_own_session_id('independent SID', sender=phase)
    assert component.flags == 0xabcdef01
    for selection in (False, True, 0):
        with pytest.raises(InputError, match='CONFLICT'):
            owner._signer.create_own_device_request((), external_a2_selection=selection)
    with pytest.raises(InputError, match='CONFLICT'):
        owner.set_own_session_id('again', sender=phase)
    errors = []
    def foreign():
        try: owner.set_own_session_id('thread', sender=phase)
        except Exception as error: errors.append(error)
    thread = threading.Thread(target=foreign)
    thread.start(); thread.join(3)
    assert not thread.is_alive() and len(errors) == 1
    phase.close()


def test_failed_receiver_publication_is_not_bound_success(auth):
    phase, owner, channel, inputs = session(auth)
    with patch('qq_nt_replica.primary_own_sdk_request._SessionReceiver', side_effect=RuntimeError('MODEL receiver failed')):
        with pytest.raises(RuntimeError, match='receiver failed'):
            phase.run()
    component = owner._signer._own_sdk_request
    assert component._session_id == 'Own local label'
    assert component._session_receiver is None and component.flags == 0
    assert component._session_binding_failed
    assert channel.closed == 0 and inputs.closes == 1


def test_identity_and_existing_transport_fail_before_mutation(auth):
    owner = ModelOwner()
    for value in (123, 0):
        owner._own_business_uin = value
        with pytest.raises(Exception, match='OWNER_IDENTITY'):
            session(auth, owner=owner)
    owner._own_business_uin = 123456789
    owner._signer.runtime.request_transport = object()
    with pytest.raises(Exception, match='CONFLICT'):
        session(auth, owner=owner)


def test_carrier_chunks_coalescing_partial_send_busy_and_timeout():
    clock = [1.]
    channel = Socket()
    channel.partial = 3
    carrier = subject._OwnBootstrapCarrier(lambda **kw: channel, uin=123456789,
        ping_index=17, deadline=10., clock=lambda: clock[0])
    ping = bytearray.fromhex('000000150133523900000000044d53460500000000')
    ping[8:12] = word(123456789); ping[17:21] = word(17)
    extra = word(8) + b'data'
    channel.incoming = [bytes(ping[:9]), bytes(ping[9:]) + extra]
    carrier.start()
    assert b''.join(channel.sent) == bytes(ping)
    channel.sent.clear()
    assert carrier.exchange(extra) == extra
    assert b''.join(channel.sent) == extra
    def reenter():
        with pytest.raises(Exception, match='BUSY'):
            carrier.exchange(extra)
        with pytest.raises(Exception, match='BUSY'):
            carrier.close()
    channel.on_send = reenter
    carrier._send(extra)
    channel.on_send = None
    clock[0] = 11.
    with pytest.raises(Exception, match='DEADLINE'):
        carrier._frame()
    carrier.close()


def test_cleanup_debt_prevents_owner_retirement(auth):
    phase, owner, channel, inputs = session(auth, own_owner=True)
    phase.run()
    channel.fail_close = True
    for _ in range(2):
        with pytest.raises(OSError, match='close debt'):
            phase.close()
    assert channel.closed == 1 and inputs.closes == owner.closes == 0
    assert phase._owner is owner
    assert phase._component is owner._signer._own_sdk_request
    assert phase._original is channel.original and phase._encoded is not None
    assert phase._binding is owner._own_cold12 and phase._carrier is not None


def test_duplicate_receive_preserves_no_double_completion(auth):
    phase, owner, channel, inputs = session(auth)
    phase.run()
    encoded = phase._encoded
    with pytest.raises(InputError, match='outstanding original'):
        owner.receive_own_cold12(encoded, channel.reply(encoded.wire_sequence, phase._original.command))
    assert len(owner.signs) == 1 and phase._component._pending == []
    phase.close()


def test_foreign_sender_and_pending_rejected_before_sid(auth):
    phase, owner, channel, inputs = session(auth)
    owner.initialize_own_sdk_request(**phase._request_config)
    component = owner._signer._own_sdk_request
    other, other_owner, other_socket, other_inputs = session(auth)
    other_owner.initialize_own_sdk_request(**other._request_config)
    other._component = other_owner._signer._own_sdk_request
    other._state = 'running'
    with pytest.raises(Exception, match='FOREIGN_BINDING'):
        owner.set_own_session_id('foreign sender', sender=other)
    assert component._session_id is None and component.flags == 0
    request = owner.create_own_device_request((DeviceRecord(7, b'value'),))
    phase._component = component; phase._state = 'running'
    with pytest.raises(Exception, match='CONFLICT'):
        owner.set_own_session_id('pending', sender=phase)
    assert component._session_id is None and component.flags == 0
    owner.cancel_own_device_request(request)
    phase.close(); other.close()


def test_failure_after_original_send_and_timeout_cancel(auth):
    for fault in ('send', 'timeout'):
        now = [1.]
        phase, owner, channel, inputs = session(auth, clock=lambda: now[0])
        carrier = phase._carrier
        count = [0]
        def sending():
            count[0] += 1
            if count[0] == 2:
                if fault == 'send':
                    raise OSError('MODEL original send error')
                now[0] = 101.
        channel.on_send = sending
        with pytest.raises(Exception): phase.run()
        assert len(owner.signs) == 1
        assert owner._signer._own_sdk_request._pending == []
        assert channel.closed == inputs.closes == 1
        assert not carrier._inflight


def test_already_taken_completion_failure_never_double_cancels(auth):
    phase, owner, channel, inputs = session(auth)
    complete = owner.complete_own_device_request
    def taken(*args, **kwargs):
        complete(*args, **kwargs)
        raise RuntimeError('MODEL after actual completion take')
    owner.complete_own_device_request = taken
    with pytest.raises(RuntimeError, match='completion take'): phase.run()
    assert owner._signer._own_sdk_request._pending == []
    assert 'cancel_own_device_request' not in [name for name,args in owner.calls]
    assert channel.closed == inputs.closes == 1


def test_unreturned_pending_is_retained_as_cleanup_debt(auth):
    phase, owner, channel, inputs = session(auth, own_owner=True)
    create = owner.create_own_device_request
    def broken_return(records):
        create(records)
        raise RuntimeError('MODEL request return boundary failed')
    owner.create_own_device_request = broken_return
    with pytest.raises(BaseExceptionGroup) as error: phase.run()
    assert 'UNRETURNED_PENDING' in str(error.value.exceptions[1])
    assert len(phase._component._pending) == 1 and owner.closes == 0
    assert channel.closed == 1 and inputs.closes == 0
    # Controlled model cleanup only, after assertions; production retains debt.
    owner.cancel_own_device_request(phase._component._pending[0][0])
    phase.close()
    assert inputs.closes == owner.closes == 1


def test_input_close_debt_not_retried_or_hidden(auth):
    phase, owner, channel, inputs = session(auth, own_owner=True)
    phase.run()
    inputs.fail_close = True
    for _ in range(2):
        with pytest.raises(OSError, match='close failure'): phase.close()
    assert inputs.closes == channel.closed == 1 and owner.closes == 0
    assert phase._owner is owner
    assert phase._component is owner._signer._own_sdk_request
    assert phase._original is channel.original and phase._encoded is not None
    assert phase._binding is owner._own_cold12 and phase._carrier is not None


def test_owned_success_cleanup_and_borrowed_inputs(auth):
    inputs = Inputs()
    phase, owner, channel, unused = session(auth, own_owner=True, cold12_inputs=inputs,
        own_cold12_inputs=False)
    phase.run(); phase.close()
    assert owner.closes == channel.closed == 1 and inputs.closes == 0


def test_oversized_and_truncated_frames_are_rejected(auth):
    for data in (word(0x500001), word(3), word(100) + b'partial'):
        phase, owner, channel, inputs = session(auth)
        original_receive = channel.receive
        calls = [0]
        def receive(*, timeout):
            calls[0] += 1
            if calls[0] == 1: return data
            return b''
        channel.receive = receive
        with pytest.raises(Exception): phase.run()
        assert owner._signer._own_sdk_request._pending == [] and owner.signs == []
        assert channel.closed == inputs.closes == 1



def test_published_receiver_reentry_rejects_before_second_encode_or_sign(auth):
    phase, owner, channel, inputs = session(auth)
    observed = []

    def reenter_original():
        # The first callback is ping; reproduce reentry only during the first
        # encoded SDK send, exactly as in the independent a2 reproduction.
        if phase._encoded is None:
            return
        channel.on_send = None
        encoded = phase._encoded
        component = owner._signer._own_sdk_request
        counter = owner._own_cold12.encoder.counter
        next_wire = counter._value
        assert phase._state == 'sending' and phase._carrier._inflight
        assert not owner._own_cold12._active and not owner._busy
        assert encoded._request is channel.original
        component.check_device_request(channel.original)
        with pytest.raises(subject.AuthenticatedSessionError, match='OWN_BOOTSTRAP_ORIGINAL_REQUIRED'):
            component._session_receiver.send(channel.original)
        assert phase._encoded is encoded and counter._value == next_wire
        assert len(owner.signs) == 1
        component.check_device_request(channel.original)
        observed.append(encoded)

    channel.on_send = reenter_original
    try:
        result = phase.run()
        assert len(observed) == 1
        first = observed[0]
        assert phase._encoded is first and first._request is channel.original
        assert first.sdk_sequence == channel.original.sdk_sequence == 1
        assert int.from_bytes(channel.outbound_plain[4:8], 'big') == first.wire_sequence
        assert owner._own_cold12.encoder.counter._value == (first.wire_sequence + 1) & 0xffffffff
        assert owner.signs == [(channel.original.command, channel.original.body)]
        assert len(channel.sent) == 2  # Matching ping and the sole SDK frame.
        completions = [args for method,args in owner.calls if method == 'complete_own_device_request']
        assert len(completions) == 1 and completions[0][0] is channel.original
        assert not any(method == 'cancel_own_device_request' for method,args in owner.calls)
        assert owner._signer._own_sdk_request._pending == []
        assert (result.outcome, result.stage, result.code) == ('failed', 'sdk_status', 2000)
        assert not result.cache_updated and result.publication is None
    finally:
        phase.close()
    assert channel.closed == inputs.closes == 1
