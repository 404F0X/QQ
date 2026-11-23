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


class _Discard(io.TextIOBase):
    def write(self, value):
        return len(value)

    def flush(self):
        pass


@contextlib.contextmanager
def _private_output():
    # Python redirects do not cover a source CRT writing file descriptors.
    saved = []
    try:
        with open(os.devnull, 'w') as sink:
            for descriptor in (1, 2):
                saved.append((descriptor, os.dup(descriptor)))
                os.dup2(sink.fileno(), descriptor)
            with contextlib.redirect_stdout(_Discard()), contextlib.redirect_stderr(_Discard()):
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


def _login_phase(options, network, notify, sleep):
    global _STAGE
    _STAGE = 'login_inputs'
    import mode1_binding as binding
    from envelope import Envelope, resident_transport
    from https_once import GetFaceOnce
    from network_guard import NetworkGuard
    from resident import Policy
    from resident_core_composition import run_session
    from core_result_r10 import CoreObservedSigner

    core = activation = owner = signer = transport = None
    captured = []
    guard = NetworkGuard()
    network.login, network.stage = guard, 'login'
    policy = Policy(network.deadline)
    try:
        Q, T, G, W, adapter = binding.load_all()
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
        device = Q.QrDevice(identity.guid, 'Windows', platform.node(),
            Q.EcdhKeys.from_private_scalar(secrets.randbelow(
                0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D - 1) + 1))
        signer = CoreObservedSigner(Q, G, identity, owner, PrimarySignatureResult, plan.queue, policy)
        transport = resident_transport(W, Q, Envelope(Q, G), clock=policy.clock, guard=guard)
        guard.begin_startup()

        def capture(material, profile):
            if captured:
                raise EntryError('AUTH_HANDOFF_ONCE')
            captured.append((material, profile))

        _STAGE = 'login_protocol'
        result = run_session(Q, T, G, W, device=device, signer=signer, transport=transport,
            https=GetFaceOnce(G, guard), confirm_uin=owner.confirm_uin, policy=policy,
            entropy=os.urandom, unix_seconds=lambda: int(time.time()), notify=notify,
            system_kernel=platform.version(), sleep=sleep, on_authenticated=capture)
        _require_online(result, captured)
    except BaseException as error:
        _remember_failure(error)
        captured.clear()
        raise
    finally:
        try:
            _close_login(transport, signer, owner, activation, core)
        except BaseException as error:
            _remember_failure(error)
            captured.clear()
            _RETAINED.append((transport, signer, owner, activation, core, guard))
            raise
        network.close_login()
    return captured.pop()


def run(options, notify, sleep=time.sleep):
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
        material, profile = _login_phase(options, network, notify, sleep)
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

    def cancel():
        nonlocal cancelled
        cancelled = True
    root.protocol('WM_DELETE_WINDOW', cancel)

    def pump():
        root.update()
        if cancelled:
            raise EntryError('AUTH_CANCELLED')

    def notify(kind, value):
        if kind == 'QR':
            image_label.image = tk.PhotoImage(master=root, data=base64.b64encode(value))
            image_label.configure(image=image_label.image)
        elif kind == 'STATUS':
            label.configure(text=value)
        pump()

    def sleep(seconds):
        pump()
        time.sleep(min(seconds, .1))

    try:
        # Source loggers may format private material. Neither stream is a
        # credential transport, including on exceptions or close refusal.
        with _private_output():
            result = run(options, notify, sleep)
        print(json.dumps(dict(profile=result.profile, verified_install=result.verified_install,
            next_sign_consumed=result.next_sign_consumed)))
        return 0
    except BaseException as error:
        _remember_failure(error)
        print(json.dumps(dict(status='AUTHENTICATED_SDK_SESSION_NOT_COMPLETED', **_FAILURE)), file=sys.stderr)
        return 1
    finally:
        root.destroy()


if __name__ == '__main__':
    raise SystemExit(main())
