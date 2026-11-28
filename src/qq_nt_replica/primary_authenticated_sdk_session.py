"""Finite authenticated application handoff; credentials and signatures stay in RAM."""
from contextlib import contextmanager
from dataclasses import dataclass
import ast
import inspect
import math
import os
import sys
import time


class AuthenticatedSessionError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuthenticatedSdkResult:
    profile: str
    verified_install: bool
    next_sign_consumed: bool


def packet_inputs(material, profile):
    from independent_login_account_registration.registration import require_session
    from independent_qr_login import DesktopQrProfile
    from .primary_sso_codec import PacketContext, SsoProfile

    require_session(material)
    if type(profile) is not DesktopQrProfile:
        raise AuthenticatedSessionError('AUTH_PROFILE_REQUIRED')
    profile.require_experimental51728()
    guid = material.provenance.device.guid
    if type(guid) is not bytes or len(guid) != 16:
        raise AuthenticatedSessionError('AUTH_DEVICE_GUID_REQUIRED')
    context = PacketContext(str(material.uin), material.uid, material.d2, material.d2_key,
        material.tgt, guid, profile.app_id, profile.sub_app_id, profile.head_version)
    wire_profile = SsoProfile(profile.protocol_version, profile.reserve_variant,
        profile.head_field8, profile.head_field12, profile.fixed_header, profile.head_version)
    return context, wire_profile


@contextmanager
def _observe_cache_consumer(runtime, cache, installed):
    """Observe the existing cache-return branch, without changing its decisions."""
    from .primary_response_refresh import signing_value

    observed = {'available': False, 'branch': False, 'returned': False}
    if sys.gettrace() is not None:
        yield observed
        return
    # Bind the cache return statement in the current pinned source, without
    # depending on Python-version-specific LOAD_FAST specializations.
    try:
        source, first_line = inspect.getsourcelines(signing_value)
        lines = {first_line + node.lineno - 1 for node in ast.walk(ast.parse(''.join(source)))
            if isinstance(node, ast.Return) and node.value is not None and
            ast.dump(node.value) == ast.dump(ast.parse('saved.value.value()', mode='eval').body)}
    except Exception:
        lines = set()
    if len(lines) != 1:
        yield observed
        return

    def local(frame, event, value):
        try:
            if frame.f_locals.get('runtime') is runtime and frame.f_locals.get('cache') is cache:
                if event == 'line' and frame.f_lineno in lines:
                    observed['branch'] = True
                if event == 'return' and observed['branch']:
                    observed['returned'] = type(value) is bytes and value == installed
        except Exception:
            observed['available'] = observed['returned'] = False
            return None
        return local

    def trace(frame, event, value):
        if frame.f_code is signing_value.__code__:
            observed['branch'] = observed['returned'] = False
            return local
        return None

    try:
        sys.settrace(trace)
    except Exception:
        yield observed
        return
    observed['available'] = True
    try:
        yield observed
    finally:
        if sys.gettrace() is trace:
            sys.settrace(None)
        else:
            observed['available'] = observed['returned'] = False


class AuthenticatedSdkSession:
    """One new owner/runtime, one refresh, then an observed same-runtime sign.

    A completion event alone never constitutes installation. Close refuses to
    proceed past a transport or owner failure; callers must retain this object.
    """
    def __init__(self, material, profile, *, bridge_path, worker_bridge_path,
                 storage_root, loader_profile, connector, deadline, clock=time.monotonic):
        if (not callable(connector) or not callable(clock) or type(deadline) not in (int, float) or
                not math.isfinite(deadline) or deadline <= clock()):
            raise AuthenticatedSessionError('AUTH_FINITE_DEADLINE')
        self._context, self._wire_profile = packet_inputs(material, profile)
        self._paths = bridge_path, worker_bridge_path, storage_root, loader_profile
        self._deadline, self._clock = deadline, clock
        self._connector = connector
        self._channel = self._transport = self._owner = self._runtime = None
        self._state = 'new'
        self.diagnostic_stage = 'sdk_inputs'

    def __repr__(self):
        return '<AuthenticatedSdkSession private>'

    def __reduce_ex__(self, protocol):
        raise TypeError('AUTH_RAM_ONLY')

    def _live(self):
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise AuthenticatedSessionError('AUTH_SDK_DEADLINE')
        return remaining

    def run(self):
        from .primary_common_windows import collect_windows_common_guid
        from .primary_provider_init import ProviderInitializationMetadata
        from .primary_sso_transport import SsoTransport
        from .primary_windows_ownimage import OwnImageModuleSpec
        from .primary_windows_signer import open_windows_signer

        if self._state != 'new':
            raise AuthenticatedSessionError('AUTH_SINGLE_USE')
        self._state = 'running'
        context, profile = self._context, self._wire_profile
        bridge, worker_bridge, storage, loader_profile = self._paths
        try:
            self.diagnostic_stage = 'sdk_connect'
            self._channel = self._connector(timeout=min(10.0, self._live()))
            self._transport = SsoTransport(image_base=0x180000000, receiver_context=0,
                channel=self._channel, profile=profile, context=context, session=context,
                initial_wire_sequence=1, timestamp_seconds=lambda: int(time.time()),
                entropy=os.urandom, request_timeout=min(10.0, self._live()), own_channel=True)
            metadata = ProviderInitializationMetadata(None, b'V1_WIN_NQ_9.9.33_51728_GW_B',
                context.uin.encode('ascii'), context.guid.hex().encode('ascii'))
            self.diagnostic_stage = 'sdk_factory'
            self._owner = open_windows_signer(bridge_path=bridge, worker_bridge_path=worker_bridge,
                storage_root=storage, host_profile_string=metadata.field_10,
                primary_backend='direct', retain_diagnostics=False,
                independent_provider_metadata=metadata,
                common_guid=collect_windows_common_guid(full_fallbacks=False),
                allow_qqprotect_registry=False, allow_capi_creation=False,
                notification_environment=True,
                ownimage_module=OwnImageModuleSpec.for_loader_profile(loader_profile),
                request_transport=self._transport.binding,
                construction_setup=self._transport.construction_setup)
            self._runtime = self._owner.signer.runtime
            self.diagnostic_stage = 'sdk_refresh'
            if self._owner.device_refresh_is_async():
                self._owner.request_device_refresh_async()
            else:
                self._owner.request_device_refresh()
            return self._receive_and_sign()
        except BaseException as error:
            if self._owner is None:
                self._owner = getattr(error, 'independent_windows_owner', None)
            self._state = 'failed'
            raise

    def _receive_and_sign(self):
        from .primary_signer import _RequestCompletionReceipt

        owner, transport, runtime = self._owner, self._transport, self._runtime
        starting_serial = owner.signer._request_completion_serial
        pending = None
        while True:
            self.diagnostic_stage = 'sdk_completion'
            self._live()
            if owner.signer.runtime is not runtime:
                raise AuthenticatedSessionError('AUTH_RUNTIME_CHANGED')
            if pending is None:
                transport.step(max_requests=0, receive_timeout=0.0)
            if pending is None and transport._queue:
                request = transport._queue[0]
                pending = (request.sdk_sequence, request.command, request.payload)
            events = transport.step(max_requests=1, receive_timeout=min(.1, self._live()))
            receipt = owner.signer._last_request_completion
            if any(event.kind in ('server_error', 'parse_error', 'session_expired') for event in events):
                raise AuthenticatedSessionError('AUTH_SDK_RESPONSE_REJECTED')
            if receipt is None or receipt.serial <= starting_serial:
                continue
            if (type(receipt) is not _RequestCompletionReceipt or pending is None or
                    receipt.sequence != pending[0] or not receipt.verified_cache):
                raise AuthenticatedSessionError('AUTH_INSTALL_NOT_VERIFIED')
            cache = owner.signer.response_cache
            if cache.runtime is not runtime:
                raise AuthenticatedSessionError('AUTH_CACHE_RUNTIME')
            installed = cache.value
            if not installed:
                raise AuthenticatedSessionError('AUTH_INSTALLED_CACHE_EMPTY')
            self.diagnostic_stage = 'sdk_proof'
            with _observe_cache_consumer(runtime, cache, installed) as consumed:
                owner.sign_result(pending[1], pending[2])
            if (owner.signer.runtime is not runtime or not consumed['available'] or not consumed['returned'] or
                    owner.signer._last_request_completion is not receipt):
                raise AuthenticatedSessionError('AUTH_NEXT_SIGN_NOT_PROVED')
            self._state = 'returned'
            return AuthenticatedSdkResult('9.9.33-51728', True, True)

    def close(self):
        if self._state == 'closed':
            return
        if self._transport is not None:
            self.diagnostic_stage = 'sdk_transport_close'
            self._transport.close()
        elif self._channel is not None:
            self.diagnostic_stage = 'sdk_transport_close'
            self._channel.close()
        if self._owner is not None:
            self.diagnostic_stage = 'sdk_owner_close'
            self._owner.close()
        self._context = self._wire_profile = self._transport = self._channel = None
        self._owner = self._runtime = None
        self._state = 'closed'

class _OwnBootstrapCarrier:
    """Single-thread, prefix-inclusive channel; Source matching ping precedes use."""
    _MAX = 0x500000

    def __init__(self, connector, *, uin, ping_index, deadline, clock):
        import threading
        self._thread = (os.getpid(), threading.get_native_id())
        self._connector, self._uin, self._index = connector, uin, ping_index
        self._deadline, self._clock = deadline, clock
        self._channel = None
        self._buffer = bytearray()
        self._published = self._inflight = self._closed = False
        self._close_failure = None

    def _live(self):
        import threading
        if self._thread != (os.getpid(), threading.get_native_id()):
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_THREAD')
        remaining = self._deadline - self._clock()
        if self._closed or remaining <= 0:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_DEADLINE_OR_CLOSED')
        return remaining

    def _send(self, frame):
        self._live()
        if self._channel is None or self._inflight:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_SEND_BUSY_OR_NO_SOCKET')
        self._inflight = True
        try:
            offset = 0
            while offset < len(frame):
                self._live()
                count = self._channel.send(frame[offset:])
                # SsoSocket.send uses sendall and returns None. Injectable raw
                # ports may return the number actually written.
                if count is None:
                    offset = len(frame)
                elif type(count) is int and 0 < count <= len(frame) - offset:
                    offset += count
                else:
                    raise AuthenticatedSessionError('OWN_BOOTSTRAP_PARTIAL_WRITE')
        finally:
            self._inflight = False

    def _frame(self, minimum=4):
        while True:
            remaining = self._live()
            if len(self._buffer) >= 4:
                count = int.from_bytes(self._buffer[:4], 'big')
                if not minimum <= count <= self._MAX:
                    raise AuthenticatedSessionError('OWN_BOOTSTRAP_FRAME_LENGTH')
                if len(self._buffer) >= count:
                    frame = bytes(self._buffer[:count])
                    del self._buffer[:count]
                    return frame
            chunk = self._channel.receive(timeout=min(.1, remaining))
            if chunk is None:
                continue
            if type(chunk) is not bytes or not chunk:
                raise AuthenticatedSessionError('OWN_BOOTSTRAP_EOF_OR_CHUNK')
            self._buffer.extend(chunk)

    def start(self):
        self._live()
        if self._channel is not None:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_CONNECT_ONCE')
        self._channel = self._connector(timeout=min(10., self._live()))
        self._channel._claim_transport()
        ping = bytearray.fromhex('000000150133523900000000044d53460500000000')
        ping[8:12] = (self._uin & 0xffffffff).to_bytes(4, 'big')
        ping[17:21] = self._index.to_bytes(4, 'big')
        self._send(bytes(ping))
        reply = self._frame(21)
        if (reply[4:8] != ping[4:8] or reply[8:12] != ping[8:12] or
                reply[12:16] != ping[12:16] or reply[17:21] != ping[17:21]):
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_PING_MISMATCH')
        self._published = True

    def exchange(self, frame):
        self._live()
        if not self._published:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_MATCHING_PING_REQUIRED')
        if (type(frame) is not bytes or not 4 <= len(frame) <= self._MAX or
                int.from_bytes(frame[:4], 'big') != len(frame)):
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_COMPLETE_FRAME_REQUIRED')
        self._send(frame)
        return self._frame()

    def close(self):
        import threading
        if self._thread != (os.getpid(), threading.get_native_id()) or self._inflight:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_CLOSE_THREAD_OR_BUSY')
        if self._close_failure is not None:
            raise self._close_failure
        if self._closed:
            return
        self._published = False
        try:
            if self._channel is not None:
                self._channel.close()
        except BaseException as error:
            self._close_failure = error
            raise
        self._closed = True
        self._buffer.clear()


class OwnBootstrapSdkSession:
    """Experimental Own 51728 wire candidate / Source 52230 algorithm boundary.

    SID is a local service label, independent of protocol account/routing. No
    ticket TTL, renewal, Native issuer or server acceptance is asserted here.
    The initialized business owner is supplied by the existing Windows factory.
    """
    def __init__(self, material, profile, *, owner, records, session_id,
                 request_capi, clock_inputs, random_environment, state17_owner,
                 cold12_inputs, own_cold12_inputs, appid_override, env_setting,
                 connector, ping_index, deadline, own_owner, clock=time.monotonic, bind_profile_appid=False):
        self._context, self._wire_profile = packet_inputs(material, profile)
        context = self._context
        if type(bind_profile_appid) is not bool:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_EXPLICIT_INPUTS')
        if bind_profile_appid and appid_override is not None:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_APPID_CONFLICT')
        if (not callable(connector) or not callable(clock) or
                type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= clock() or
                type(ping_index) is not int or not 0 <= ping_index < 1 << 32 or
                type(own_owner) is not bool or type(own_cold12_inputs) is not bool):
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_EXPLICIT_INPUTS')
        if type(session_id) is not str or not session_id or '\0' in session_id:
            raise AuthenticatedSessionError('OWN_SESSION_INPUTS')
        session_id.encode('utf-8', errors='strict')
        uin = material.uin
        if type(uin) is not int or not 0 < uin < 1 << 64:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_POSITIVE_UIN')
        identity = owner.own_business_identity()
        if identity != (uin, context.guid.hex().encode('ascii')):
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_OWNER_IDENTITY')
        if (owner._signer.runtime.request_transport is not None or
                getattr(owner._signer, '_own_sdk_request', None) is not None or
                getattr(owner, '_own_cold12', None) is not None):
            raise AuthenticatedSessionError('OWN_SESSION_BINDING_CONFLICT')
        from .primary_source_cold12 import store_own_type1_peer, SourceType1RequestInputs
        key = str(uin).encode('ascii')
        peer = store_own_type1_peer(context.tgt, context.d2, context.d2_key, lookup_key=key)
        self._request_inputs = SourceType1RequestInputs(key, peer)
        self._owner, self._own_owner = owner, own_owner
        self._runtime = owner._signer.runtime
        self._component = None
        self._records, self._session_id = records, session_id
        self._request_config = dict(request_capi=request_capi, clock_inputs=clock_inputs,
            random_environment=random_environment, state17_owner=state17_owner)
        self._cold_config = dict(inputs=cold12_inputs, own_inputs=own_cold12_inputs,
            appid_override=appid_override, env_setting=env_setting)
        if bind_profile_appid:
            self._cold_config['init_config'] = {'appid': str(profile.sub_app_id)}
        self._carrier = _OwnBootstrapCarrier(connector, uin=uin, ping_index=ping_index,
            deadline=deadline, clock=clock)
        self._state = 'new'
        self._original = self._encoded = self._binding = None
        self._bind_attempted = self._unbound_inputs_closed = False
        self._unbound_inputs_failure = None
        self.diagnostic_stage = 'own_bootstrap_inputs'

    def __repr__(self):
        return '<OwnBootstrapSdkSession private>'

    def check_binding(self, component):
        from .errors import InputError
        if self._state != 'running':
            raise InputError('OWN_BOOTSTRAP_FOREIGN_BINDING')
        try:
            self._carrier._live()
        except AuthenticatedSessionError as error:
            raise InputError('OWN_BOOTSTRAP_BINDING_NOT_LIVE') from error
        self._owner._check_owner()
        if (self._state != 'running' or self._component is not component or
                component is not self._owner._signer._own_sdk_request or
                component.runtime is not self._runtime or
                self._owner._signer.runtime is not self._runtime):
            raise InputError('OWN_BOOTSTRAP_FOREIGN_BINDING')

    def check_request(self):
        from .errors import InputError
        if self._state != 'running':
            raise InputError('OWN_BOOTSTRAP_SINGLE_ORIGINAL')
        self._carrier._live()
        if (self._state != 'running' or self._original is not None or
                self._owner._signer.runtime is not self._runtime or
                self._component is not self._owner._signer._own_sdk_request):
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_SINGLE_ORIGINAL')

    def start(self):
        if self._state != 'running':
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_SINGLE_USE')
        self.diagnostic_stage = 'own_bootstrap_ping'
        self._carrier.start()

    def send_original(self, request):
        from .primary_source_cold12 import SourceType1ReplyInputs
        if self._state != 'running' or self._original is not request:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_ORIGINAL_REQUIRED')
        # Hold this original across encode, socket callbacks and reply settlement.
        self._state = 'sending'
        self._carrier._live()
        self.diagnostic_stage = 'own_bootstrap_encode'
        self._encoded = self._owner.encode_own_cold12(request, type1=self._request_inputs)
        self.diagnostic_stage = 'own_bootstrap_exchange'
        frame = self._carrier.exchange(self._encoded.frame)
        # Read actual outer routing before selecting a current peer snapshot.
        # Full decoder and exact command/wire correlation remain authoritative.
        if len(frame) < 14:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_REPLY_OUTER')
        size = int.from_bytes(frame[10:14], 'big')
        if size < 4 or 10 + size > len(frame):
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_REPLY_ROUTING_LENGTH')
        routing = frame[14:10 + size]
        if routing != self._request_inputs.lookup_key:
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_UNKNOWN_RECEIVED_ROUTING')
        reply_inputs = SourceType1ReplyInputs(routing, self._request_inputs.peer, None)
        self.diagnostic_stage = 'own_bootstrap_receive'
        return self._owner.receive_own_cold12(self._encoded, frame, type1=reply_inputs)

    def run(self):
        if self._state != 'new':
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_SINGLE_USE')
        self._state = 'running'
        try:
            self._owner.initialize_own_sdk_request(**self._request_config)
            self._component = self._owner._signer._own_sdk_request
            self._bind_attempted = True
            self._owner.bind_own_cold12(**self._cold_config)
            self._binding = self._owner._own_cold12
            self.diagnostic_stage = 'own_bootstrap_bind'
            self._owner.set_own_session_id(self._session_id, sender=self)
            self.diagnostic_stage = 'own_bootstrap_create'
            self._original = self._owner.create_own_device_request(self._records)
            result = self._component._session_receiver.send(self._original)
            self._state = 'returned' if result.outcome != 'failed' else 'failed'
            return result
        except BaseException as original:
            self._state = 'failed'
            try:
                self.close()
            except BaseException as cleanup:
                raise BaseExceptionGroup('Own bootstrap operation and cleanup failed', [original, cleanup]) from None
            raise

    def close(self):
        if self._state == 'closed':
            return
        self._state = 'stopping'
        self.diagnostic_stage = 'own_bootstrap_carrier_close'
        self._carrier.close()
        if (self._original is None and self._component is not None and
                self._component._pending):
            raise AuthenticatedSessionError('OWN_BOOTSTRAP_UNRETURNED_PENDING')
        if self._original is not None and self._component is not None:
            if any(request is self._original for request, bound in self._component._pending):
                self.diagnostic_stage = 'own_bootstrap_cancel'
                self._owner.cancel_own_device_request(self._original)
        self.diagnostic_stage = 'own_bootstrap_inputs_close'
        # Construction failures may retain a binder with actual cleanup debt.
        binding = self._binding or getattr(self._owner, '_own_cold12', None)
        if binding is not None and binding.component is self._component:
            binding.close()
        if (not self._bind_attempted and self._cold_config['own_inputs'] and
                not self._unbound_inputs_closed):
            if self._unbound_inputs_failure is not None:
                raise self._unbound_inputs_failure
            try:
                self._cold_config['inputs'].close()
            except BaseException as error:
                self._unbound_inputs_failure = error
                raise
            self._unbound_inputs_closed = True
        if self._own_owner:
            self.diagnostic_stage = 'own_bootstrap_owner_close'
            self._owner.close()
        self._context = self._wire_profile = self._request_inputs = None
        self._records = self._request_config = self._cold_config = None
        self._owner = self._runtime = None
        self._component = self._original = self._encoded = self._binding = None
        self._carrier = None
        self._state = 'closed'
