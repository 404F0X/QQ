"""Synthetic handoff/lifecycle checks, never authenticated B acceptance."""
import importlib.util
import ast
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import pickle
import runpy
import sys
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from qq_nt_replica import primary_authenticated_sdk_session as subject
from qq_nt_replica.primary_signer import _RequestCompletionReceipt


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('authenticated_entry_test', ROOT / 'run_authenticated_sdk_session.py')
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


class Timing(unittest.TestCase):
    def test_timing_privacy_and_failure_do_not_change_business(self):
        stream = io.StringIO()
        timing = entry._QrTiming(stream=stream, clock=iter(range(100)).__next__)
        timing('login.factory.begin')
        timing('login.factory.end')
        timing('fetch.prepare.begin', 0)
        timing.policy_event('OP_BEGIN', stage='SIGN', payload='synthetic-secret-payload')
        timing.policy_event('OP_END', stage='SIGN', raw_exception='synthetic-secret-error')
        timing('fetch.prepare.end', 0)
        timing('qr.paint.return')
        timing('state.EXPIRED', 1)
        rows = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual([r['label'] for r in rows], ['login.factory.begin', 'login.factory.end',
            'fetch.prepare.begin', 'qr.sign.begin', 'qr.sign.end', 'fetch.prepare.end',
            'qr.paint.return', 'state.EXPIRED'])
        self.assertTrue(all(set(r) <= {'label', 'monotonic', 'index'} for r in rows))
        self.assertEqual([r['monotonic'] for r in rows], list(range(8)))
        self.assertNotIn('synthetic-secret', stream.getvalue())
        before = stream.getvalue()
        timing.policy_event('OP_BEGIN', stage='SIGN', payload='synthetic-secret-outside-QR')
        self.assertEqual(stream.getvalue(), before)
        timing('synthetic-secret-label')
        self.assertFalse(timing.available)
        timing('fetch.prepare.begin', 0)
        self.assertEqual(stream.getvalue(), before)

        writer = Mock()
        writer.write.side_effect = OSError('synthetic-secret-disk-error')
        broken = entry._QrTiming(stream=writer, clock=lambda: 1.0)
        value = object()
        def business():
            broken('fetch.prepare.begin', 0)
            broken.policy_event('OP_BEGIN', stage='SIGN')
            return value
        self.assertIs(business(), value)
        self.assertFalse(broken.available)
        self.assertEqual(writer.write.call_count, 1)
        primary = ValueError('synthetic-business-first-error')
        try:
            broken('login.cleanup.begin')
            raise primary
        except ValueError as error:
            self.assertIs(error, primary)
        bad_clock = Mock(side_effect=RuntimeError('synthetic-secret-clock'))
        unavailable = entry._QrTiming(stream=io.StringIO(), clock=bad_clock)
        unavailable('fetch.prepare.begin', 0)
        unavailable('fetch.prepare.end', 0)
        self.assertFalse(unavailable.available)
        self.assertEqual(bad_clock.call_count, 1)
        # Execute only the four pinned error class definitions, not the login
        # package or algorithms, in an owned temporary test module.
        import types
        login = Path(os.environ['AUTHENTICATED_LOGIN_ROOT'])
        binding = json.loads((login / 'G/ENTRY-SOURCE-BINDING.json').read_bytes())
        pin = binding['modules']['candidate/independent_login_account_registration/common.py']
        raw = Path(pin['path']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), pin['sha256'])
        source = ast.parse(raw.decode('utf-8'))
        definitions = [node for node in source.body if isinstance(node, ast.ClassDef)
            and node.name in ('GlueError', 'InputError', 'StateError', 'DecodeError')]
        module = types.ModuleType('_controlled_glue_errors')
        module.__file__ = pin['path']
        exec(compile(ast.Module(body=definitions, type_ignores=[]), pin['path'], 'exec'), module.__dict__)
        ticket = types.ModuleType('_controlled_ticket_errors')
        qr = types.ModuleType('_controlled_qr_errors')
        for package, target, names in (
                ('T', ticket, ('LoginError', 'LoginInputError', 'LoginDecodeError')),
                ('Q', qr, ('QrError',))):
            refs = json.loads((login / package / 'ENTRY-SOURCE-BINDING.json').read_bytes())['modules']
            ref = next(v for k, v in refs.items() if k.endswith('/codec.py'))
            payload = Path(ref['path']).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), ref['sha256'])
            defs = [n for n in ast.parse(payload.decode('utf-8')).body
                if isinstance(n, ast.ClassDef) and n.name in names]
            exec(compile(ast.Module(body=defs, type_ignores=[]), ref['path'], 'exec'), target.__dict__)
        previous = entry._FAILURE
        try:
            with patch.dict(sys.modules, {module.__name__: module}):
                api = types.ModuleType('_controlled_actual_G_exports')
                exports = ast.parse((Path(pin['path']).parent / '__init__.py').read_text(encoding='utf-8')).body[0]
                self.assertEqual(exports.module, 'common')
                for name in exports.names:
                    if hasattr(module, name.name):
                        setattr(api, name.asname or name.name, getattr(module, name.name))
                selected = {'test': {'path': str(Path(entry.__file__).parent /
                    'tests/test_primary_authenticated_sdk_session.py')}}
                for public_code in ('LOGIN_WTLOGIN_FRAME', 'LOGIN_WTLOGIN_COMMAND',
                        'LOGIN_TLV_0119_REQUIRED', 'LOGIN_TLV_0543_REQUIRED',
                        'LOGIN_TLV_0305_LENGTH', 'LOGIN_PROTO_VARINT_OVERFLOW',
                        'LOGIN_UID_FIELD_AMBIGUOUS'):
                    try:
                        try:
                            error = ticket.LoginDecodeError(public_code)
                            error.args = ('synthetic-secret-ticket-body',)
                            raise error
                        except ticket.LoginError as error:
                            raise api.StateError(error.code) from None
                    except api.StateError as error:
                        entry._FAILURE = {}
                        entry._remember_glue_failure(error, api, selected, login)
                    actual = entry._FAILURE['login_error_chain']
                    self.assertEqual(actual[0]['code'], public_code)
                    self.assertEqual(actual[1]['type'], 'LoginDecodeError')
                    self.assertNotIn('synthetic-secret', json.dumps(actual))
                try:
                    try:
                        try:
                            error = qr.QrError('QR_TEA_PADDING')
                            error.args = ('synthetic-secret-inner-body',)
                            raise error
                        except qr.QrError as error:
                            raise ticket.LoginDecodeError('LOGIN_SHARED_' + error.code) from None
                    except ticket.LoginError as error:
                        raise api.StateError(error.code) from None
                except module.StateError as error:
                    entry._FAILURE = None
                    entry._remember_failure(error, 'login_protocol')
                    entry._remember_glue_failure(error, api, selected, login)
                chain = entry._FAILURE['login_error_chain']
                self.assertEqual([r['type'] for r in chain], ['StateError', 'LoginDecodeError', 'QrError'])
                self.assertEqual(chain[0]['code'], 'LOGIN_SHARED_QR_TEA_PADDING')
                self.assertTrue(all(len(r.get('sites', [])) <= 2 for r in chain))
                self.assertTrue(all(set(r) <= {'type', 'code', 'sites'} for r in chain))
                self.assertNotIn('synthetic-secret', json.dumps(entry._FAILURE))
                self.assertNotIn(str(login), json.dumps(entry._FAILURE))
                entry._FAILURE = {}
                entry._remember_glue_failure(module.StateError('synthetic-secret-code'), api, selected, login)
                self.assertNotIn('code', entry._FAILURE['login_error_chain'][0])
                self.assertNotIn('synthetic-secret', json.dumps(entry._FAILURE))
        finally:
            entry._FAILURE = previous


class Lifecycle(unittest.TestCase):
    def session(self):
        with patch.object(subject, 'packet_inputs', return_value=(object(), object())):
            return subject.AuthenticatedSdkSession(object(), object(), bridge_path=Path('b'),
                worker_bridge_path=Path('w'), storage_root=Path('s'), loader_profile='explicit',
                connector=lambda **options: self.fail('no physical connector expected here'),
                deadline=time.monotonic() + 10)

    def test_entry_creates_only_parent_required_by_pinned_login_factory(self):
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        login = os.environ.get('AUTHENTICATED_LOGIN_ROOT')
        output = os.environ.get('AUTHENTICATED_TEST_TEMP_ROOT')
        if not login or not output:
            self.skipTest('explicit login source and owned temporary root are required')
        login, output = Path(login), Path(output)
        binding = json.loads((login / 'DEPENDENCY-MATERIAL-CONTROL-RELEASE.json').read_bytes())
        pin = binding['final_map']['qq_nt_replica/primary_windows_signer.py']
        raw = Path(pin['path']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), pin['sha256'])
        parsed = ast.parse(raw.decode('utf-8'))
        functions = [node for node in parsed.body if isinstance(node, ast.FunctionDef)
            and node.name in ('_nonreparse', '_validated_paths')]
        self.assertEqual(len(functions), 2)
        namespace = dict(os=os, ctypes=ctypes, Path=Path, stat=stat,
            InputError=InputError, PrimarySemanticUnavailable=PrimarySemanticUnavailable)
        # Only the pinned pure path validator runs; no factory, DLL or owner.
        exec(compile(ast.Module(body=functions, type_ignores=[]), pin['path'], 'exec'), namespace)
        validate = namespace['_validated_paths']
        bridge = Path(json.loads((login / 'INPUTS.json').read_bytes())['artifacts']['caller_dll']['path'])
        with tempfile.TemporaryDirectory(dir=output) as directory:
            self.assertTrue(Path(directory).resolve().is_relative_to(output.resolve()))
            storage_root = Path(directory) / 'owned-runtime'
            leaf = storage_root / 'login'
            self.assertFalse(storage_root.exists())
            with self.assertRaises(InputError) as failure:
                validate(bridge, leaf, b'synthetic-profile', None, False)
            # The failure is the parent precondition, not a fake helper DLL gate.
            self.assertFalse(leaf.exists())
            entry._prepare_storage_root(storage_root)
            self.assertTrue(storage_root.is_dir())
            self.assertEqual(list(storage_root.iterdir()), [])
            result = validate(bridge, leaf, b'synthetic-profile', None, False)
            self.assertEqual(result, (bridge, leaf))
            self.assertTrue(leaf.is_dir())
            self.assertFalse((storage_root / 'sdk').exists())

    def test_refresh_selector_reads_source_feature_without_changing_guards(self):
        from qq_nt_replica.primary_signer import PrimarySigner
        from qq_nt_replica import primary_sign_lifecycle, primary_logger, primary_worker_consumer
        from contextlib import nullcontext
        signer = SimpleNamespace(runtime=object())
        with patch.object(primary_sign_lifecycle, 'public_call', side_effect=lambda owner: nullcontext()), \
                patch.object(primary_worker_consumer, '_logger', return_value=object()), \
                patch.object(primary_logger, 'feature') as feature:
            for value, expected in ((1, True), (0, False)):
                feature.return_value = value
                self.assertIs(PrimarySigner.device_refresh_is_async(signer), expected)
                feature.assert_called_with(signer.runtime, unittest.mock.ANY, 0x25)
                from qq_nt_replica import primary_response_refresh
                from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
                with patch.object(primary_response_refresh, 'refresh') as refresh:
                    selected = PrimarySigner.request_device_refresh_async if expected else PrimarySigner.request_device_refresh
                    rejected = PrimarySigner.request_device_refresh if expected else PrimarySigner.request_device_refresh_async
                    selected(signer)
                    refresh.assert_called_once_with(signer.runtime)
                    with self.assertRaises(PrimarySemanticUnavailable):
                        rejected(signer)
                    refresh.assert_called_once_with(signer.runtime)

    def test_session_dispatches_existing_api_for_both_source_modes(self):
        run = ast.parse(__import__('inspect').getsource(subject).strip())
        dispatch = next(n for n in ast.walk(run) if isinstance(n, ast.If) and
            isinstance(n.test, ast.Call) and isinstance(n.test.func, ast.Attribute) and
            n.test.func.attr == 'device_refresh_is_async')
        for mode in (False, True):
            owner = Mock()
            owner.device_refresh_is_async.return_value = mode
            exec(compile(ast.Module(body=[dispatch], type_ignores=[]), '<dispatch>', 'exec'),
                {'self': SimpleNamespace(_owner=owner)})
            (owner.request_device_refresh_async if mode else owner.request_device_refresh).assert_called_once_with()
            (owner.request_device_refresh if mode else owner.request_device_refresh_async).assert_not_called()


    def test_private_single_use_and_no_session_serialization(self):
        phase = self.session()
        self.assertEqual(repr(phase), '<AuthenticatedSdkSession private>')
        with self.assertRaises(TypeError):
            pickle.dumps(phase)
        phase.close()
        with self.assertRaises(subject.AuthenticatedSessionError):
            phase.run()
        read, write = os.pipe()
        original = os.dup(1)
        try:
            os.dup2(write, 1)
            with self.assertRaises(ValueError):
                with entry._private_output():
                    print('synthetic-private-python-output')
                    os.write(1, b'synthetic-private-descriptor-output')
                    raise ValueError('controlled private failure')
        finally:
            os.dup2(original, 1)
            os.close(original)
            os.close(write)
        try:
            self.assertEqual(os.read(read, 1024), b'')
        finally:
            os.close(read)
        previous = entry._FAILURE
        try:
            entry._FAILURE = None
            entry._remember_failure(ValueError('synthetic-secret-error-message'), 'sdk_factory')
            entry._remember_failure(RuntimeError('synthetic-close-message'), 'sdk_owner_close')
            self.assertEqual(entry._FAILURE,
                {'stage': 'sdk_factory', 'exception_type': 'ValueError'})
            self.assertNotIn('synthetic-secret', repr(entry._FAILURE))
        finally:
            entry._FAILURE = previous
        try:
            for state in ('POLL_CAP_REACHED', 'REGISTRATION_REJECTED', 'synthetic-secret-state'):
                entry._FAILURE = None
                try:
                    entry._require_online({'state': state, 'private': 'synthetic-secret-result'}, [])
                except entry.EntryError as error:
                    entry._remember_failure(error, 'login_protocol')
                public = entry._FAILURE
                self.assertEqual(public['stage'], 'login_protocol')
                self.assertEqual(public['exception_type'], 'EntryError')
                self.assertEqual(public['entry_source']['file'], 'run_authenticated_sdk_session.py')
                self.assertEqual(public['entry_source']['function'], '_require_online')
                self.assertIs(type(public['entry_source']['line']), int)
                self.assertGreater(public['entry_source']['line'], 0)
                if state == 'synthetic-secret-state':
                    self.assertNotIn('login_state', public)
                else:
                    self.assertEqual(public['login_state'], state)
                encoded = json.dumps(public)
                self.assertNotIn('synthetic-secret', encoded)
                self.assertNotIn(str(ROOT), encoded)
                self.assertNotIn('AUTH_ONLINE_REQUIRED', encoded)
            entry._require_online({'online_observed': True, 'state': 'ONLINE'}, [object()])
        finally:
            entry._FAILURE = previous

    def test_transport_failure_prevents_owner_retirement(self):
        phase = self.session()
        phase._transport, phase._owner = Mock(), Mock()
        phase._transport.close.side_effect = RuntimeError('controlled refusal')
        with self.assertRaises(RuntimeError):
            phase.close()
        phase._owner.close.assert_not_called()
        self.assertIsNotNone(phase._context)

    def test_normal_close_order_and_owner_refusal_retains(self):
        phase = self.session()
        order = []
        phase._transport = SimpleNamespace(close=lambda: order.append('transport'))
        def refuse():
            order.append('owner')
            raise RuntimeError('controlled refusal')
        phase._owner = SimpleNamespace(close=refuse)
        with self.assertRaises(RuntimeError):
            phase.close()
        self.assertEqual(order, ['transport', 'owner'])
        self.assertIsNotNone(phase._owner)
        normal = self.session()
        normal._transport = SimpleNamespace(close=lambda: order.append('transport_normal'))
        normal._owner = SimpleNamespace(close=lambda: order.append('owner_normal'))
        normal.close()
        self.assertIsNone(normal._context)
        self.assertEqual(normal._state, 'closed')
        self.assertEqual(order[-2:], ['transport_normal', 'owner_normal'])

    def test_login_close_failure_keeps_activation_and_core(self):
        owner, activation, core = Mock(), MagicMock(), Mock()
        owner.close.side_effect = RuntimeError('controlled refusal')
        with self.assertRaises(RuntimeError):
            entry._close_login(Mock(), Mock(), owner, activation, core)
        activation.__exit__.assert_not_called()
        core.close.assert_not_called()

    def test_old_guard_is_not_reopened_and_sdk_network_is_finite(self):
        domain = entry._NetworkDomain(time.monotonic() + 10)
        guard = Mock()
        domain.login, domain.stage = guard, 'login'
        domain.audit('socket.connect', ('login',))
        guard.audit.assert_called_once()
        domain.close_login()
        guard.stop.assert_called_once()
        with self.assertRaises(PermissionError):
            domain.audit('socket.connect', ('login',))
        domain.stage = 'sdk_connect'
        with self.assertRaises(PermissionError):
            domain.audit('socket.getaddrinfo', ('arbitrary.invalid', 8080, 0, 0, 0))
        connection = self.connect(domain, ('192.0.2.1', 8080))
        self.assertEqual(domain.stage, 'sdk_connected')
        with self.assertRaises(PermissionError):
            domain.audit('socket.connect', (connection, ('192.0.2.1', 8080)))
        with self.assertRaises(PermissionError):
            domain.connect_sdk(timeout=1)
        self.assertIsNone(domain.login)

    def connect(self, domain, resolved, check_nonresolved=False):
        from qq_nt_replica import primary_sso_socket
        spec = (entry.socket.AF_INET, entry.socket.SOCK_STREAM, entry.socket.IPPROTO_TCP)
        connection, wrapped = Mock(), object()

        def resolve(*args):
            domain.audit('socket.getaddrinfo', args)
            return [(*spec, '', resolved)]

        def create(*args):
            domain.audit('socket.__new__', (connection, *args))
            return connection

        def connect(address):
            if check_nonresolved:
                with self.assertRaises(PermissionError):
                    domain.audit('socket.connect', (connection, ('192.0.2.99', 8080)))
                self.assertEqual(domain.sdk_connects, 0)
            domain.audit('socket.connect', (connection, address))

        connection.connect.side_effect = connect
        with patch.object(entry.socket, 'getaddrinfo', side_effect=resolve) as resolver, \
                patch.object(entry.socket, 'socket', side_effect=create) as constructor, \
                patch.object(primary_sso_socket, 'SsoSocket', return_value=wrapped) as wrapper:
            self.assertIs(domain.connect_sdk(timeout=1), wrapped)
            resolver.assert_called_once_with('msfwifi.3g.qq.com', 8080,
                entry.socket.AF_UNSPEC, entry.socket.SOCK_STREAM, entry.socket.IPPROTO_TCP)
            constructor.assert_called_once_with(*spec)
            connection.connect.assert_called_once_with(resolved)
            wrapper.assert_called_once_with(connection, own_socket=True)
        return connection

    def test_authorized_dns_does_not_authorize_another_address(self):
        domain = entry._NetworkDomain(time.monotonic() + 10)
        domain.stage = 'sdk_connect'
        self.connect(domain, ('192.0.2.1', 8080), check_nonresolved=True)
        self.assertEqual(domain.sdk_connects, 1)

    def test_connect_primary_survives_close_double_fault(self):
        from qq_nt_replica import primary_sso_socket
        domain = entry._NetworkDomain(time.monotonic() + 10)
        domain.stage = 'sdk_connect'
        spec = (entry.socket.AF_INET, entry.socket.SOCK_STREAM, entry.socket.IPPROTO_TCP)
        connection = Mock()
        primary = OSError('synthetic-private-connect-error')
        cleanup = RuntimeError('synthetic-private-close-error')
        previous_failure, retained_start = entry._FAILURE, len(entry._RETAINED)

        def resolve(*args):
            domain.audit('socket.getaddrinfo', args)
            return [(*spec, '', ('192.0.2.1', 8080))]

        def create(*args):
            domain.audit('socket.__new__', (connection, *args))
            return connection

        def connect(address):
            domain.audit('socket.connect', (connection, address))
            raise primary

        def close():
            self.assertEqual(entry._FAILURE['stage'], 'sdk_connect')
            self.assertEqual(entry._FAILURE['exception_type'], 'OSError')
            self.assertEqual(entry._FAILURE['entry_source']['function'], 'connect_sdk')
            raise cleanup

        connection.connect.side_effect, connection.close.side_effect = connect, close
        try:
            entry._FAILURE = None
            with patch.object(entry.socket, 'getaddrinfo', side_effect=resolve), \
                    patch.object(entry.socket, 'socket', side_effect=create), \
                    patch.object(primary_sso_socket, 'SsoSocket') as wrapper:
                with self.assertRaises(BaseExceptionGroup) as failure:
                    domain.connect_sdk(timeout=1)
                self.assertIs(failure.exception.exceptions[0], primary)
                self.assertIs(failure.exception.exceptions[1], cleanup)
                wrapper.assert_not_called()
            connection.close.assert_called_once_with()
            self.assertEqual(domain.stage, 'closed')
            self.assertEqual(domain.sdk_connects, 1)
            self.assertIs(entry._RETAINED[-1][0], connection)
            self.assertIs(entry._RETAINED[-1][1], domain)
            self.assertNotIn('synthetic-private', repr(entry._FAILURE))
            with self.assertRaises(PermissionError):
                domain.connect_sdk(timeout=1)
        finally:
            # Test doubles own no OS handle; retain real failures in production.
            del entry._RETAINED[retained_start:]
            entry._FAILURE = previous_failure

    def test_unverified_completion_is_not_installation(self):
        phase = self.session()
        runtime = object()
        receipt = _RequestCompletionReceipt(1, 7, True, True, 'dispatched', True,
            True, True, True, True, True, False, True, True, True,
            operation_completed=True)
        signer = SimpleNamespace(runtime=runtime, _request_completion_serial=0,
            _last_request_completion=None)
        owner = SimpleNamespace(signer=signer, sign_result=Mock())
        request = SimpleNamespace(sdk_sequence=7, command=b'actual-source-command', payload=b'body')
        def step(**options):
            if options['max_requests']:
                signer._last_request_completion = receipt
            return ()
        phase._owner, phase._runtime = owner, runtime
        phase._transport = SimpleNamespace(_queue=[request], step=step)
        with self.assertRaisesRegex(subject.AuthenticatedSessionError, 'INSTALL_NOT_VERIFIED'):
            phase._receive_and_sign()
        owner.sign_result.assert_not_called()

    def test_actual_cache_return_branch_observed_fallback_does_not_count(self):
        from qq_nt_replica import primary_response_refresh as refresh
        runtime, cache = object(), object()
        saved = SimpleNamespace(value=SimpleNamespace(value=lambda: b'synthetic-installed'),
            clone=lambda: object(), destroy=Mock())
        with patch.object(refresh.Snapshot, 'capture', return_value=saved), \
                patch.object(refresh, 'expired', return_value=False), \
                patch.object(refresh, 'refresh_needed', return_value=False), \
                patch.object(refresh, '_predicate_message'):
            with subject._observe_cache_consumer(runtime, cache, b'synthetic-installed') as observed:
                result = refresh.signing_value(runtime, cache, b'fallback', {1: 1})
            self.assertEqual(result, b'synthetic-installed')
            self.assertTrue(observed['returned'])
            with subject._observe_cache_consumer(runtime, cache, b'synthetic-installed') as observed:
                refresh.signing_value(runtime, cache, b'synthetic-installed', {1: 0})
            self.assertFalse(observed['returned'])
            with patch.object(subject.inspect, 'getsourcelines', side_effect=OSError('controlled observer failure')):
                with subject._observe_cache_consumer(runtime, cache, b'synthetic-installed') as observed:
                    result = refresh.signing_value(runtime, cache, b'fallback', {1: 1})
                self.assertEqual(result, b'synthetic-installed')
                self.assertFalse(observed['available'])
            with subject._observe_cache_consumer(runtime, cache, b'synthetic-installed'):
                with self.assertRaisesRegex(ValueError, 'business failure'):
                    raise ValueError('business failure')

    def test_same_runtime_sign_requires_verified_receipt_and_real_consumer(self):
        phase = self.session()
        runtime = object()
        receipt = _RequestCompletionReceipt(1, 7, True, True, 'dispatched', True,
            True, True, True, True, True, True, True, True, True,
            operation_completed=True)
        cache = SimpleNamespace(runtime=runtime, value=b'synthetic-installed')
        signer = SimpleNamespace(runtime=runtime, _request_completion_serial=0,
            _last_request_completion=None, response_cache=cache)
        request = SimpleNamespace(sdk_sequence=7, command=b'source-command', payload=b'source-body')
        def step(**options):
            if options['max_requests']:
                signer._last_request_completion = receipt
            return ()
        owner = SimpleNamespace(signer=signer, sign_result=Mock())
        phase._owner, phase._runtime = owner, runtime
        phase._transport = SimpleNamespace(_queue=[request], step=step)
        with self.assertRaisesRegex(subject.AuthenticatedSessionError, 'NEXT_SIGN_NOT_PROVED'):
            phase._receive_and_sign()
        owner.sign_result.assert_called_once_with(b'source-command', b'source-body')


class RealInputShape(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        location = os.environ.get('AUTHENTICATED_LOGIN_ROOT')
        if not location:
            raise unittest.SkipTest('explicit pinned login source is required')
        cls.login_root = Path(location)
        cls.G = runpy.run_path(str(cls.login_root / 'G/entry.py'))['load_api']()
        cls.Q = sys.modules['independent_qr_login']
        cls.T = sys.modules['independent_login_ticket_exchange']

    def material(self):
        device = self.Q.QrDevice(bytes(range(16)), 'Windows', 'synthetic-test-device',
            self.Q.EcdhKeys.from_private_scalar(1))
        provenance = self.T.SessionProvenance(None, device, 0)
        return self.T.SessionMaterial(123456789, 'synthetic-uid', b'synthetic-d2',
            bytes(range(16)), b'synthetic-tgt', object(), object(), provenance)

    def test_exact_material_mapping_and_actual_51728_profile(self):
        material = self.material()
        context, profile = subject.packet_inputs(material, self.Q.DesktopQrProfile.experimental51728())
        self.assertEqual(context.uin, str(material.uin))
        self.assertIs(context.d2_key, material.d2_key)
        self.assertIs(context.guid, material.provenance.device.guid)
        self.assertEqual((context.app_id, context.sub_app_id, context.build_ver),
            (1600001604, 537376767, '9.9.33-51728'))
        self.assertEqual((profile.protocol_version, profile.reserve_variant), (12, 'nt'))
        self.assertNotIn('opaque_tlvs', context.__dict__)
        self.assertNotIn('returned_temp_password', context.__dict__)

    def test_foreign_session_bad_key_and_wrong_profile_rejected(self):
        from dataclasses import replace
        material = self.material()
        profile = self.Q.DesktopQrProfile.experimental51728()
        for wrong in (SimpleNamespace(**material.__dict__), replace(material, d2_key=b'bad')):
            with self.assertRaises(Exception):
                subject.packet_inputs(wrong, profile)
        with self.assertRaises(Exception):
            subject.packet_inputs(material, replace(profile, head_version='9.9.33-52230'))


if __name__ == '__main__':
    unittest.main()
