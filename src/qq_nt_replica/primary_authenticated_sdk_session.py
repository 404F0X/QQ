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
