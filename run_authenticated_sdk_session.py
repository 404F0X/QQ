"""Reviewed finite QR -> authenticated SDK application entry. No secret output."""
import argparse
import base64
import contextlib
import hashlib
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import secrets
import socket
import sys
import threading
import time


ROOT = Path(__file__).resolve().parent
CONTRACT = 'MAT-SIGN-AUTHENTICATED-SDK-INTEGRATION/a1'
_RETAINED = []
_STAGE, _FAILURE = 'entry', None
_STAGES = frozenset(('entry', 'inputs', 'login_inputs', 'login_factory', 'login_protocol',
    'login_transport_close', 'login_observer_close', 'login_owner_close',
    'login_activation_exit', 'login_core_close', 'sdk_core', 'sdk_inputs', 'sdk_connect',
    'sdk_factory', 'sdk_refresh', 'sdk_completion', 'sdk_proof', 'sdk_transport_close',
    'sdk_owner_close', 'sdk_activation_exit', 'sdk_core_close'))
_LOGIN_STATES = frozenset(('FAILED', 'QR_ISSUED', 'PHONE_CONFIRMED', 'EXPIRED',
    'CANCELLED', 'UNKNOWN_STATUS', 'LOCAL_EXPIRED', 'POLL_CAP_REACHED',
    'LOGIN_NOT_COMPLETED', 'CREDENTIALS_VALIDATED', 'ONLINE',
    'REGISTRATION_REJECTED', 'ONLINE_OBSERVED_CONNECTION_CLOSED'))


# Fixed public literals from the selected T/Q source contracts; no prefix acceptance.
_QR_FIXED_ERRORS = frozenset((
    'QR_ATTEMPT_INPUT_CHANGED', 'QR_ATTEMPT_TERMINAL', 'QR_BYTES_LENGTH', 'QR_CALLBACK_REQUIRED',
    'QR_DESKTOP_PROFILE_UNSUPPORTED', 'QR_DUPLICATE_TLV', 'QR_ECDH_PEER', 'QR_ECDH_PUBLIC_PREFIX',
    'QR_ECDH_REQUIRED', 'QR_ECDH_SCALAR', 'QR_ENTROPY_PROVIDER', 'QR_EXECUTION_MODE',
    'QR_EXPERIMENT_FETCH_ONLY', 'QR_EXPERIMENT_LIFECYCLE_DEADLINE', 'QR_EXPERIMENT_PROFILE_SOURCE',
    'QR_EXPERIMENT_TRANSPORT_BINDING', 'QR_EXPERIMENT_TRANSPORT_NOT_STARTED', 'QR_HEAD_INTEGER',
    'QR_HEAD_VERSION', 'QR_INITIAL_SEQUENCE', 'QR_INTEGER_RANGE', 'QR_LOCAL_LIFETIME',
    'QR_MONOTONIC_CLOCK', 'QR_POLICY_BOUND', 'QR_POLICY_POLLS', 'QR_POLICY_TIME', 'QR_POLL_CAP',
    'QR_POLL_NOT_DUE', 'QR_PREPARATION_FAILED', 'QR_PREPARE_TIMEOUT', 'QR_REQUEST_INFLIGHT',
    'QR_REQUEST_TIMEOUT', 'QR_RESIDENT_EXPERIMENT_REQUIRED', 'QR_RESPONSE_FAILED',
    'QR_SEQUENCE_EXHAUSTED', 'QR_SIGNING_ASSOCIATION', 'QR_SIGNING_FAILED',
    'QR_SIGN_CALLER_SLOT_LENGTH', 'QR_SIGN_INPUT_REQUIRED', 'QR_SSO_BODY_LENGTH',
    'QR_SSO_COMMAND_LENGTH', 'QR_SSO_COMPRESSION', 'QR_SSO_CORRELATION', 'QR_SSO_DECOMPRESSION_LIMIT',
    'QR_SSO_EXTRA_LENGTH', 'QR_SSO_HEAD_LENGTH', 'QR_SSO_OUTER_FRAME', 'QR_SSO_UIN_LENGTH',
    'QR_STALE_ATTEMPT', 'QR_STALE_REQUEST', 'QR_STATE_TRANSITION', 'QR_TARGET_PROFILE_NOT_QUALIFIED',
    'QR_TEA_LENGTH', 'QR_TEA_PADDING', 'QR_TEXT_ENCODING', 'QR_TEXT_REQUIRED', 'QR_TLV_COUNT',
    'QR_TRAILING_BYTES', 'QR_TRANSPORT_ERROR_KIND', 'QR_TRANS_EMP_APP_ID', 'QR_TRANS_EMP_SUBCOMMAND',
    'QR_TRUNCATED', 'QR_TYPED_INPUT_REQUIRED', 'QR_URL_INVALID', 'QR_URL_REQUIRED',
    'QR_WTLOGIN_COMMAND', 'QR_WTLOGIN_FRAME',
))
_TICKET_FIXED_ERRORS = frozenset((
    'LOGIN_BYTES_LENGTH', 'LOGIN_CANONICAL_UIN_REQUIRED', 'LOGIN_CONFIRMED_POLL_REQUIRED',
    'LOGIN_ERROR_INFO_ENCODING', 'LOGIN_INTEGER_RANGE', 'LOGIN_PROTO_FIELD_LIMIT',
    'LOGIN_PROTO_FIELD_NUMBER', 'LOGIN_PROTO_VARINT_OVERFLOW', 'LOGIN_PROTO_WIRE_UNSUPPORTED',
    'LOGIN_QR_PROFILE_REQUIRED', 'LOGIN_TEXT_ENCODING', 'LOGIN_TEXT_REQUIRED', 'LOGIN_TRAILING_BYTES',
    'LOGIN_TRUNCATED', 'LOGIN_TYPED_INPUT_REQUIRED', 'LOGIN_UID_ENCODING', 'LOGIN_UID_FIELD_AMBIGUOUS',
    'LOGIN_UID_FIELD_REQUIRED', 'LOGIN_UID_REQUIRED', 'LOGIN_WTLOGIN_COMMAND', 'LOGIN_WTLOGIN_FRAME',
))
_TICKET_TLV_ERRORS = frozenset('LOGIN_TLV_' + tag + '_REQUIRED'
    for tag in ('0119', '0143', '0305', '010A', '0543')) | {'LOGIN_TLV_0305_LENGTH'}
_TICKET_SHARED_ERRORS = frozenset('LOGIN_SHARED_' + code for code in (
    'QR_BYTES_LENGTH', 'QR_TEA_LENGTH', 'QR_TEA_PADDING', 'QR_TRUNCATED',
    'QR_TLV_COUNT', 'QR_DUPLICATE_TLV', 'QR_TRAILING_BYTES'))
_SELECTED_LOGIN_ERRORS = (_QR_FIXED_ERRORS | _TICKET_FIXED_ERRORS |
    _TICKET_TLV_ERRORS | _TICKET_SHARED_ERRORS | {'ACCOUNT_' + code for code in _QR_FIXED_ERRORS})


def _remember_failure(error, stage=None):
    global _FAILURE
    if _FAILURE is None:
        kind = type(error).__name__
        allowed = frozenset(('AuthenticatedSessionError', 'EntryError', 'ResidentError',
            'CandidateError', 'QrError', 'InputError', 'StateError', 'LoginDecodeError',
            'PrimarySemanticUnavailable', 'PrimaryMemoryLimit', 'UnknownMemory',
            'SsoTransportError', 'SsoSocketError', 'PermissionError', 'TimeoutError',
            'OSError', 'RuntimeError', 'ValueError', 'TypeError', 'AttributeError',
            'ExceptionGroup', 'BaseExceptionGroup', 'KeyboardInterrupt'))
        selected = _STAGE if stage is None else stage
        _FAILURE = {'stage': selected if type(selected) is str and selected in _STAGES else 'entry',
            'exception_type': kind if kind in allowed else 'OtherError'}
        try:
            # This is an entry boundary/raise site, not a claim about a foreign
            # callee. Never inspect traceback locals, exception args or text.
            traceback = error.__traceback__
            while traceback is not None:
                code = traceback.tb_frame.f_code
                if os.path.normcase(code.co_filename) == os.path.normcase(str(ROOT / Path(__file__).name)):
                    _FAILURE['entry_source'] = {'file': Path(__file__).name,
                        'function': code.co_name, 'line': traceback.tb_lineno}
                traceback = traceback.tb_next
            if type(error) is EntryError:
                state = getattr(error, 'login_state', None)
                if type(state) is str and state in _LOGIN_STATES:
                    _FAILURE['login_state'] = state
        except Exception:
            _FAILURE['source_observation_unavailable'] = True


class EntryError(RuntimeError):
    pass


def _remember_glue_failure(error, glue_api, source_binding, login_root):
    """Project only selected public error semantics; never format an exception."""
    if _FAILURE is None or glue_api is None or source_binding is None:
        return
    try:
        pin = json.loads((login_root / 'G/ENTRY-SOURCE-BINDING.json').read_bytes())['modules'][
            'candidate/independent_login_account_registration/common.py']
        path = Path(pin['path']).resolve()
        base = glue_api.GlueError
        common = sys.modules.get(base.__module__)
        if (common is None or Path(common.__file__).resolve() != path or
                common.GlueError is not base or
                Path(base.__init__.__code__.co_filename).resolve() != path or
                hashlib.sha256(path.read_bytes()).hexdigest() != pin['sha256']):
            return
        kinds = tuple(getattr(common, name) for name in ('GlueError', 'InputError', 'StateError', 'DecodeError'))
        if type(error) not in kinds:
            return
        codes = frozenset(('GLUE_SIGN_PROVIDER_FAILED', 'GLUE_SIGN_ASSOCIATION', 'GLUE_SIGNATURE_REQUIRED',
            'ACCOUNT_CONTINUATION_TERMINAL', 'ACCOUNT_GUARD_FAILED', 'ACCOUNT_STALE_ATTEMPT',
            'ACCOUNT_MONOTONIC_CLOCK', 'ACCOUNT_LOCAL_LIFETIME', 'ACCOUNT_QR_CONTEXT_CHANGED',
            'ACCOUNT_PHASE', 'ACCOUNT_SEQUENCE_REUSE', 'ACCOUNT_STALE_REQUEST', 'ACCOUNT_REQUEST_REQUIRED',
            'ACCOUNT_HTTP_STATUS', 'ACCOUNT_JSON_LIMIT', 'ACCOUNT_JSON_INVALID',
            'ACCOUNT_UIN_EXACT_INTEGER_REQUIRED', 'ACCOUNT_EXPECTED_MISMATCH',
            'ACCOUNT_LOGIN_PREPARATION', 'ACCOUNT_REGISTRATION_PREPARATION',
            'LOGIN_TLV_0143_REQUIRED', 'LOGIN_TLV_0305_REQUIRED', 'LOGIN_TLV_0305_LENGTH',
            'LOGIN_TLV_010A_REQUIRED', 'LOGIN_UID_FIELD_REQUIRED', 'LOGIN_UID_REQUIRED')) | _SELECTED_LOGIN_ERRORS
        names = frozenset(('GlueError', 'InputError', 'StateError', 'DecodeError', 'ResidentError',
            'LoginError', 'LoginInputError', 'LoginDecodeError', 'QrError',
            'PrimarySemanticUnavailable', 'PrimaryProgramLimit', 'PrimaryMemoryLimit', 'UnknownMemory',
            'RuntimeError', 'ValueError', 'TypeError', 'KeyError', 'AttributeError', 'OSError'))
        selected = list(source_binding.values()) + list(source_binding.get('_sources', {}).values())
        trusted = {os.path.normcase(str(Path(row['path']).resolve())) for row in selected
            if isinstance(row, dict) and type(row.get('path')) is str}
        binding = json.loads((login_root / 'G/ENTRY-SOURCE-BINDING.json').read_bytes())
        trusted.update(os.path.normcase(str(Path(row['path']).resolve())) for row in binding['modules'].values())
        chain, seen, current = [], set(), error
        for _ in range(3):
            if current is None or id(current) in seen:
                break
            seen.add(id(current))
            name = type(current).__name__
            record = {'type': name if name in names else 'OtherError'}
            if type(current) in kinds:
                code = current.code
                if type(code) is str and code in codes:
                    record['code'] = code
            sites, traceback = [], current.__traceback__
            while traceback is not None:
                code = traceback.tb_frame.f_code
                if os.path.normcase(code.co_filename) in trusted:
                    sites.append({'file': Path(code.co_filename).name,
                        'function': code.co_name, 'line': traceback.tb_lineno})
                traceback = traceback.tb_next
            if sites:
                record['sites'] = sites[-2:]
            chain.append(record)
            current = current.__context__
        _FAILURE['login_error_chain'] = chain
    except BaseException:
        _FAILURE['glue_observation_unavailable'] = True


class _QrTiming:
    """Optional bounded diagnostic sink; never a business input or authority."""
    labels = frozenset(('login.factory.begin', 'login.factory.end',
        'fetch.prepare.begin', 'fetch.prepare.end', 'poll.prepare.begin', 'poll.prepare.end',
        'qr.sign.begin', 'qr.sign.end', 'fetch.exchange.begin', 'fetch.exchange.end',
        'poll.exchange.begin', 'poll.exchange.end', 'fetch.decode.begin', 'fetch.decode.end',
        'poll.decode.begin', 'poll.decode.end', 'qr.paint.return',
        'session.cleanup.begin', 'session.cleanup.end', 'login.cleanup.begin', 'login.cleanup.end')) | frozenset(
            'state.' + value for value in _LOGIN_STATES | {'CONFIRMED'})

    def __init__(self, path=None, *, stream=None, clock=time.monotonic):
        self.stream, self.clock = stream, clock
        self.owned, self.available, self.index = False, True, None
        try:
            if stream is None:
                self.stream = Path(path).open('x', encoding='utf-8')
                self.owned = True
        except BaseException:
            self.available = False

    def __call__(self, label, index=None):
        if not self.available:
            return
        try:
            if (type(label) is not str or label not in self.labels or
                    index is not None and (type(index) is not int or not 0 <= index <= 8)):
                raise ValueError('invalid timing field')
            if label in ('fetch.prepare.begin', 'poll.prepare.begin'):
                self.index = index
            value = self.clock()
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError('invalid timing clock')
            row = {'label': label, 'monotonic': value}
            if index is not None:
                row['index'] = index
            self.stream.write(json.dumps(row, separators=(',', ':')) + '\n')
            self.stream.flush()
            if label in ('fetch.prepare.end', 'poll.prepare.end'):
                self.index = None
        except BaseException:
            self.available = False

    def policy_event(self, name, **fields):
        # Do not forward Policy payloads, commands, result sizes or exceptions.
        try:
            if self.index is not None and name in ('OP_BEGIN', 'OP_END') and fields.get('stage') == 'SIGN':
                self('qr.sign.begin' if name == 'OP_BEGIN' else 'qr.sign.end', self.index)
        except BaseException:
            self.available = False

    def close(self):
        if self.owned:
            try:
                self.stream.close()
            except BaseException:
                self.available = False


class _Discard(io.TextIOBase):
    def write(self, value):
        return len(value)

    def flush(self):
        pass


@contextlib.contextmanager
def _private_output(path=None):
    # Python redirects do not cover a source CRT writing file descriptors.
    saved = []
    try:
        with open(path if path is not None else os.devnull, 'a', encoding='utf-8') as sink:
            for descriptor in (1, 2):
                saved.append((descriptor, os.dup(descriptor)))
                os.dup2(sink.fileno(), descriptor)
            python_sink = sink if path is not None else _Discard()
            with contextlib.redirect_stdout(python_sink), contextlib.redirect_stderr(python_sink):
                yield
    finally:
        for descriptor, original in reversed(saved):
            os.dup2(original, descriptor)
            os.close(original)


class _NetworkDomain:
    """One installed audit hook; the old worker's permanent hook is never used."""
    def __init__(self, deadline):
        self.deadline = deadline
        self.thread = threading.get_native_id()
        self.stage, self.login = 'closed', None
        self.sdk_socket = None
        self.sdk_dns = self.sdk_connects = 0
        self._sdk_attempted = False
        self._resolving = self._creating = self._connecting = False
        self._sdk_address = self._sdk_spec = None
        self._sdk_operation_deadline = None

    def connect_sdk(self, *, timeout):
        from qq_nt_replica.primary_sso_socket import SsoSocket

        if (threading.get_native_id() != self.thread or self.stage != 'sdk_connect' or
                self._sdk_attempted or type(timeout) not in (int, float) or
                not math.isfinite(timeout) or timeout <= 0 or time.monotonic() >= self.deadline):
            raise PermissionError('AUTH_SDK_CONNECT_SCOPE')
        self._sdk_attempted = True
        self._sdk_operation_deadline = min(self.deadline, time.monotonic() + timeout)
        self._resolving = True
        try:
            addresses = socket.getaddrinfo('msfwifi.3g.qq.com', 8080,
                socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        finally:
            self._resolving = False
        if not addresses or len(addresses[0]) != 5:
            raise PermissionError('AUTH_SDK_RESOLVER_RESULT')
        family, kind, protocol, _, address = addresses[0]
        if (family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or
                protocol != socket.IPPROTO_TCP or type(address) is not tuple or
                len(address) != (2 if family == socket.AF_INET else 4) or
                type(address[0]) is not str or type(address[1]) is not int or address[1] != 8080 or
                ipaddress.ip_address(address[0]).version != (4 if family == socket.AF_INET else 6)):
            raise PermissionError('AUTH_SDK_RESOLVER_RESULT')
        self._sdk_spec, self._sdk_address = (family, kind, protocol), address
        connection = None
        try:
            self._creating = True
            try:
                connection = socket.socket(family, kind, protocol)
            finally:
                self._creating = False
            if connection is not self.sdk_socket:
                raise PermissionError('AUTH_SDK_SOCKET_IDENTITY')
            remaining = self._sdk_operation_deadline - time.monotonic()
            if remaining <= 0:
                raise PermissionError('AUTH_SDK_CONNECT_DEADLINE')
            connection.settimeout(min(timeout, remaining))
            self._connecting = True
            try:
                connection.connect(self._sdk_address)
            finally:
                self._connecting = False
            self.stage = 'sdk_connected'
            return SsoSocket(connection, own_socket=True)
        except BaseException as primary:
            _remember_failure(primary, 'sdk_connect')
            self.stage = 'closed'
            if connection is not None:
                try:
                    connection.close()
                except BaseException as cleanup:
                    _RETAINED.append((connection, self, primary, cleanup))
                    raise BaseExceptionGroup('SDK connection and cleanup failed', [primary, cleanup]) from None
            raise

    def audit(self, event, args):
        if not event.startswith('socket.') or event == 'socket.gethostname':
            return
        if threading.get_native_id() != self.thread or time.monotonic() >= self.deadline:
            raise PermissionError('AUTH_NETWORK_OWNER_OR_DEADLINE')
        if self.stage == 'login' and self.login is not None:
            return self.login.audit(event, args)
        if self.stage != 'sdk_connect':
            raise PermissionError('AUTH_NETWORK_PHASE')
        if self._sdk_operation_deadline is None or time.monotonic() >= self._sdk_operation_deadline:
            raise PermissionError('AUTH_SDK_CONNECT_DEADLINE')
        if event == 'socket.getaddrinfo':
            if (not self._resolving or self.sdk_dns or args !=
                    ('msfwifi.3g.qq.com', 8080, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)):
                raise PermissionError('AUTH_SDK_ENDPOINT')
            self.sdk_dns += 1
            return
        if event == 'socket.__new__':
            if not self._creating or self.sdk_socket is not None or args[1:] != self._sdk_spec:
                raise PermissionError('AUTH_SDK_SINGLE_CONNECTION')
            self.sdk_socket = args[0]
            return
        if event == 'socket.connect':
            if (not self._connecting or args[0] is not self.sdk_socket or self.sdk_connects or
                    not self.sdk_dns or self._sdk_address is None or args[1] != self._sdk_address):
                raise PermissionError('AUTH_SDK_CONNECT')
            self.sdk_connects += 1
            return
        raise PermissionError('AUTH_NETWORK_OPERATION')

    def close_login(self):
        self.login.stop()
        self.login = None
        self.stage = 'closed'


def _checked_inputs(path, login_root):
    document = json.loads(Path(path).read_bytes())
    if (document.get('contract') != CONTRACT or
            Path(document['canonical_root']).resolve() != ROOT or
            Path(document['login_root']).resolve() != login_root or not document.get('files')):
        raise EntryError('AUTH_INPUT_BINDING')
    required = {ROOT / 'run_authenticated_sdk_session.py', ROOT / 'signature_core.py',
        ROOT / 'source-manifest.json', ROOT / 'source-manifest.sha256',
        ROOT / 'src/qq_nt_replica/primary_authenticated_sdk_session.py',
        ROOT / 'trusted_login_capture.py',
        login_root / 'registration_overlay/resident_run.py',
        login_root / 'resident_core_composition.py', login_root / 'mode1_binding.py',
        login_root / 'binding.py'}
    if not required.issubset({Path(row['path']).resolve() for row in document['files']}):
        raise EntryError('AUTH_INPUT_CLOSURE_REQUIRED')
    for row in document['files']:
        source = Path(row['path']).resolve()
        if (not (source.is_relative_to(ROOT) or source.is_relative_to(login_root)) or
                hashlib.sha256(source.read_bytes()).hexdigest() != row['sha256']):
            raise EntryError('AUTH_SOURCE_CHANGED')


def _close_login(transport, signer, owner, activation, core):
    global _STAGE
    # Each normal boundary must return before retiring the next dependency.
    if transport is not None:
        _STAGE = 'login_transport_close'
        transport.close()
    if signer is not None:
        _STAGE = 'login_observer_close'
        signer.close_observer()
    if owner is not None:
        _STAGE = 'login_owner_close'
        owner.close()
    if activation is not None:
        _STAGE = 'login_activation_exit'
        activation.__exit__(None, None, None)
    if core is not None:
        _STAGE = 'login_core_close'
        core.close()


def _prepare_storage_root(storage_root):
    # Each normal factory creates its own leaf; its parent belongs to this entry.
    storage_root.mkdir(exist_ok=True)


def _require_online(result, captured):
    if not result.get('online_observed') or len(captured) != 1:
        error = EntryError('AUTH_ONLINE_REQUIRED')
        state = result.get('state')
        if type(state) is str and state in _LOGIN_STATES:
            error.login_state = state
        raise error


def _login_phase(options, network, notify, sleep, timing=None, local_capture=None):
    global _STAGE
    _STAGE = 'login_inputs'
    import mode1_binding as binding
    from envelope import Envelope, resident_transport
    from https_once import GetFaceOnce
    from network_guard import NetworkGuard
    from resident import Policy
    from resident_core_composition import run_session, login_diagnostics
    from public_events import exception_origin
    from core_result_r10 import CoreObservedSigner

    core = activation = owner = signer = transport = G = None
    captured = []
    guard = NetworkGuard()
    network.login, network.stage = guard, 'login'
    policy = Policy(network.deadline, event=timing.policy_event) if timing is not None else Policy(network.deadline)
    try:
        if timing is not None:
            timing('login.factory.begin')
        Q, T, G, W, adapter = binding.load_all()
        if local_capture is not None:
            local_capture.configure(Q, T, G)
        core = adapter.load_core()
        dependency = json.loads((options.login_root / 'DEPENDENCY-U.json').read_bytes())
        for pin in dependency['sources'].values():
            binding.checked(pin)
        core.binding.update(dependency['sources'])
        ctor_adapter = binding.compose_mode1(core)
        entering = core.activate()
        entering.__enter__()
        activation = entering
        from qq_nt_replica.primary_windows_signer import open_windows_signer
        from qq_nt_replica.primary_windows_ownimage import OwnImageModuleSpec
        from qq_nt_replica.primary_signature_result import PrimarySignatureResult

        identity = adapter.FreshIdentity.create()
        if local_capture is not None:
            local_capture.dto_types.update((type(identity), PrimarySignatureResult))
            local_capture.record('login.identity', identity=identity)
        factory_options = dict(bridge_path=options.bridge, worker_bridge_path=options.worker_bridge,
            ownimage_spec=OwnImageModuleSpec.for_loader_profile(options.loader_profile))
        plan = (adapter.plan_factory(core, identity, **factory_options) if ctor_adapter is None else
            ctor_adapter.plan_factory(adapter, core, identity, **factory_options))
        login_options = dict(plan.options, storage_root=options.storage_root / 'login')
        _STAGE = 'login_factory'
        try:
            owner = policy.operation('FACTORY', 180, lambda: open_windows_signer(**login_options))
        except BaseException as error:
            owner = getattr(error, 'independent_windows_owner', None)
            raise
        if timing is not None:
            timing('login.factory.end')
        device = Q.QrDevice(identity.guid, 'Windows', platform.node(),
            Q.EcdhKeys.from_private_scalar(secrets.randbelow(
                0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D - 1) + 1))
        signer = CoreObservedSigner(Q, G, identity, owner, PrimarySignatureResult, plan.queue, policy, capture=local_capture)
        transport = resident_transport(W, Q, Envelope(Q, G), clock=policy.clock, guard=guard, capture=local_capture)
        guard.begin_startup()

        def capture(material, profile):
            if captured:
                raise EntryError('AUTH_HANDOFF_ONCE')
            captured.append((material, profile))

        _STAGE = 'login_protocol'
        # Match the existing normal resident worker's parser composition.
        diagnostics = []
        with login_diagnostics(G.LoginContinuation, diagnostics, exception_origin):
            if local_capture is not None:
                local_capture.effective_parser(G.LoginContinuation.accept_ticket_exchange)
            try:
                result = run_session(Q, T, G, W, device=device, signer=signer, transport=transport,
                    https=GetFaceOnce(G, guard), confirm_uin=owner.confirm_uin, policy=policy,
                    entropy=os.urandom, unix_seconds=lambda: int(time.time()), notify=notify,
                    system_kernel=platform.version(), sleep=sleep, on_authenticated=capture,
                    timing=timing, capture=local_capture)
            finally:
                if local_capture is not None:
                    local_capture.record('normal.login_diagnostics', records=diagnostics)
        _require_online(result, captured)
    except BaseException as error:
        _remember_failure(error)
        _remember_glue_failure(error, G, core.binding if core is not None else None, options.login_root)
        if local_capture is not None:
            local_capture.exception('login.exception', error)
        captured.clear()
        raise
    finally:
        try:
            if timing is not None:
                timing('login.cleanup.begin')
            _close_login(transport, signer, owner, activation, core)
            if timing is not None:
                timing('login.cleanup.end')
        except BaseException as error:
            _remember_failure(error)
            captured.clear()
            _RETAINED.append((transport, signer, owner, activation, core, guard))
            raise
        network.close_login()
    return captured.pop()


def run(options, notify, sleep=time.sleep, *, timing=None, local_capture=None):
    global _STAGE, _FAILURE
    _STAGE, _FAILURE = 'inputs', None
    if (type(options.timeout) not in (int, float) or not math.isfinite(options.timeout) or
            not 0 < options.timeout <= 900 or not 0 < options.sdk_timeout <= 120):
        raise EntryError('AUTH_TIMEOUT_RANGE')
    options.login_root = options.login_root.resolve()
    _checked_inputs(options.inputs, options.login_root)
    if any(name == 'qq_nt_replica' or name.startswith('qq_nt_replica.') for name in sys.modules):
        raise EntryError('AUTH_FRESH_NAMESPACE_REQUIRED')
    _prepare_storage_root(options.storage_root)
    network = _NetworkDomain(time.monotonic() + options.timeout)
    sys.addaudithook(network.audit)
    sys.path.insert(0, str(options.login_root))
    core = activation = phase = None
    try:
        material, profile = _login_phase(options, network, notify, sleep, timing, local_capture)
        _STAGE = 'sdk_core'
        import signature_core
        if Path(signature_core.__file__).resolve() != ROOT / 'signature_core.py':
            raise EntryError('AUTH_CANONICAL_LOADER_REQUIRED')
        core = signature_core.load_core()
        entering = core.activate()
        entering.__enter__()
        activation = entering
        from qq_nt_replica.primary_authenticated_sdk_session import AuthenticatedSdkSession

        network.stage = 'sdk_connect'
        _STAGE = 'sdk_inputs'
        phase = AuthenticatedSdkSession(material, profile, bridge_path=options.bridge,
            worker_bridge_path=options.worker_bridge, storage_root=options.storage_root / 'sdk',
            loader_profile=options.loader_profile,
            connector=network.connect_sdk,
            deadline=min(network.deadline, time.monotonic() + options.sdk_timeout))
        material = profile = None
        return phase.run()
    except BaseException as error:
        _remember_failure(error, phase.diagnostic_stage if phase is not None else _STAGE)
        raise
    finally:
        network.stage = 'closed'
        try:
            if phase is not None:
                try:
                    phase.close()
                except BaseException as error:
                    _remember_failure(error, phase.diagnostic_stage)
                    raise
            if activation is not None:
                _STAGE = 'sdk_activation_exit'
                activation.__exit__(None, None, None)
            if core is not None:
                _STAGE = 'sdk_core_close'
                core.close()
        except BaseException as error:
            _remember_failure(error)
            _RETAINED.append((phase, activation, core, network))
            raise
        finally:
            sys.path.remove(str(options.login_root))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='execute real login/network only after review')
    for name in ('inputs', 'login-root', 'bridge', 'worker-bridge', 'storage-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--loader-profile', required=True)
    parser.add_argument('--timeout', type=float, default=600)
    parser.add_argument('--sdk-timeout', type=float, default=60)
    parser.add_argument('--qr-timing-events', type=Path, help='owned fixed-label monotonic JSONL diagnostic')
    parser.add_argument('--trusted-capture-root', type=Path, required=True,
        help='authorized private local capture root; contains credentials, never publish')
    options = parser.parse_args(argv)
    if not options.run:
        parser.error('--run is required; this entry has no synthetic success mode')
    import tkinter as tk
    root = tk.Tk()
    root.title('Authenticated QR and SDK session')
    label = tk.Label(root, text='Preparing login')
    label.pack()
    image_label = tk.Label(root)
    image_label.pack()
    cancelled = False
    timing = _QrTiming(options.qr_timing_events) if options.qr_timing_events is not None else None
    attention_job = None
    bell_rung = False

    def clear_attention():
        nonlocal attention_job
        job, attention_job = attention_job, None
        if job is not None:
            try:
                root.after_cancel(job)
            except tk.TclError:
                pass
        try:
            root.attributes('-topmost', False)
        except tk.TclError:
            pass

    def show_attention():
        nonlocal attention_job, bell_rung
        try:
            root.deiconify()
            root.update_idletasks()
            x = max(0, (root.winfo_screenwidth() - root.winfo_reqwidth()) // 2)
            y = max(0, (root.winfo_screenheight() - root.winfo_reqheight()) // 3)
            root.geometry(f'+{x}+{y}')
            root.lift()
            root.attributes('-topmost', True)
            attention_job = root.after(8000, clear_attention)
            if not bell_rung:
                bell_rung = True
                root.bell()
        except tk.TclError:
            clear_attention()

    def cancel():
        nonlocal cancelled
        cancelled = True
        clear_attention()
    root.protocol('WM_DELETE_WINDOW', cancel)

    def pump(*, qr_paint=False):
        root.update()
        if qr_paint and timing is not None:
            timing('qr.paint.return')
        if cancelled:
            raise EntryError('AUTH_CANCELLED')

    def notify(kind, value):
        if kind == 'QR':
            image_label.image = tk.PhotoImage(master=root, data=base64.b64encode(value))
            image_label.configure(image=image_label.image)
            show_attention()
        elif kind == 'STATUS':
            label.configure(text=value)
            if value in ('PHONE_CONFIRMED', 'ONLINE', 'ONLINE_OBSERVED_CONNECTION_CLOSED',
                    'EXPIRED', 'CANCELLED', 'UNKNOWN_STATUS', 'LOCAL_EXPIRED', 'FAILED',
                    'POLL_CAP_REACHED', 'LOGIN_NOT_COMPLETED', 'REGISTRATION_REJECTED'):
                clear_attention()
        pump(qr_paint=kind == 'QR')

    def sleep(seconds):
        pump()
        time.sleep(min(seconds, .1))

    local_capture = None
    try:
        _checked_inputs(options.inputs, options.login_root.resolve())
        from trusted_login_capture import LoginCapture
        local_capture = LoginCapture(options.trusted_capture_root, login_root=options.login_root,
            inputs=options.inputs, parameters={key: str(value) if isinstance(value, Path) else value
                for key, value in vars(options).items()})
        # Source loggers may format private material. Neither stream is a
        # credential transport, including on exceptions or close refusal.
        with _private_output(local_capture.log_path):
            result = run(options, notify, sleep, timing=timing, local_capture=local_capture)
        local_capture.close()
        print(json.dumps(dict(profile=result.profile, verified_install=result.verified_install,
            next_sign_consumed=result.next_sign_consumed, capture_directory=str(local_capture.path),
            capture_available=local_capture.available)))
        return 0
    except BaseException as error:
        _remember_failure(error)
        public = dict(status='AUTHENTICATED_SDK_SESSION_NOT_COMPLETED', **_FAILURE)
        if local_capture is not None:
            local_capture.exception('entry.exception', error)
            local_capture.close()
            public.update(capture_directory=str(local_capture.path), capture_available=local_capture.available)
        if timing is not None:
            public['timing_available'] = timing.available
        print(json.dumps(public), file=sys.stderr)
        return 1
    finally:
        if local_capture is not None:
            local_capture.close()
        clear_attention()
        if timing is not None:
            timing.close()
        root.destroy()


if __name__ == '__main__':
    raise SystemExit(main())
