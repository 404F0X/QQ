"""Offline fake-port assembly/WS/profile checks; no target imports or sockets."""
import ast
from contextlib import contextmanager, redirect_stdout
import io
import json
from pathlib import Path, PureWindowsPath
import stat
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

import own_sdk_onebot_bindings as bindings
import run_own_sdk_onebot_candidate as caller
from test_own_sdk_onebot_candidate import Harness, UIN, COMMAND, completion


class PhysicalPath(PureWindowsPath):
    reparse = None
    occupied = False
    escaped = False
    made = []

    def lstat(self):
        if self.name == 'unique-run' and not self.occupied:
            raise FileNotFoundError(str(self))
        return NS(st_mode=stat.S_IFDIR, st_file_attributes=(
            stat.FILE_ATTRIBUTE_REPARSE_POINT if str(self) == self.reparse else 0))

    def resolve(self, strict=False):
        return type(self)('G:/escape') if self.escaped else self

    def mkdir(self):
        self.made.append(str(self))


def config():
    return dict(expected_uin=UIN, machine_id=b'MODEL-own-persistent-machine',
        bridge_path=PhysicalPath('G:/bridge.dll'), worker_bridge_path=PhysicalPath('G:/worker.dll'),
        loader_profile='MODEL-profile', task_root='G:/owned-task', state_id='unique-run',
        run_root=PhysicalPath('G:/owned-task/unique-run'), ws_url='ws://explicit.invalid:23001',
        overall_timeout=10, action_timeout=2, receive_budget=3)


class Socket:
    def __init__(self, replies=()):
        self.replies = iter(replies)
        self.sent, self.timeouts = [], []
        self.closed = False

    def send(self, value): self.sent.append(json.loads(value))
    def recv(self, *, timeout):
        self.timeouts.append(timeout)
        value = next(self.replies)
        if isinstance(value, BaseException): raise value
        return json.dumps(value) if isinstance(value, dict) else value
    def close(self): self.closed = True


def assembly(events, *, fail_collect=False, fail_close=None):
    def resource(name):
        def close():
            events.append('close_' + name)
            if name == fail_close: raise OSError('MODEL cleanup debt')
        return NS(close=close)
    env, mix, port, collector = (resource(n) for n in ('env', 'mix', 'port', 'collector'))
    env.time_seconds = lambda: 10
    env.random_bytes = lambda n: b'MODEL'
    port.ansi_to_utf8 = lambda v: v
    fields = {0x6751708: b'', 0x6751720: b'MODEL-own-persistent-machine', 0x6751750: b'MODEL-version'}
    memory = NS(read=lambda pointer, length: fields[pointer])
    owner = NS(signer=NS(runtime=NS(memory=memory, image_base=0), response_cache=NS(value=b'')),
        get_own_device_value=lambda: b'MODEL-device')
    records = object()
    def collect(**kwargs):
        events.append('collect')
        assert kwargs == dict(version=b'MODEL-version', device_value=b'MODEL-device', ansi_to_utf8=port.ansi_to_utf8)
        if fail_collect: raise ValueError('MODEL collect failure')
        return records
    collector.collect = collect
    registry = NS(read=Mock(return_value=None), write=Mock(return_value=False), delete=Mock(return_value=False))
    def stores(root, state_id, *, registry):
        assert root == config()['run_root'] / 'collector' and state_id == 'unique-run'
        return NS(io_errors=[('MODEL-cache-write', 5)], registry=registry,
            namespace='Software\\404F0X\\QQReplica\\Signature\\' + state_id)
    def make_collector(actual_port, actual_stores, *, sdk_fields, wmi_factory):
        assert actual_port is port and wmi_factory is api.OwnedWmiSession.open
        assert sdk_fields == {0x30: b'', 0x48: b'MODEL-own-persistent-machine', 0x78: b'MODEL-version'}
        return collector
    api = NS(WindowsDeviceValueEnvironment=lambda: env, WindowsDeviceMixPort=lambda: mix,
        produce_device_mix=lambda p: b'MODEL-state17', SystemRequestCapi=lambda: object(),
        WindowsDeviceCollectionObservations=lambda: port, WindowsOwnIdentifierRegistry=lambda: registry,
        OwnIdentifierStores=stores, IndependentDeviceRecordCollector=make_collector,
        OwnedWmiSession=NS(open=lambda: None), string_view=lambda m, a: (a, len(fields[a])))
    return owner, api, records


# Real Python call events with fixture code identities, never SDK implementations.
def selected(runtime, cache, fallback, features, now=None):
    return runtime.selected


def digest(d, context, payload):
    return b'MODEL-digest-return'


class Signer:
    def _sign_body(self, command, payload):
        d = selected(self.runtime, self.runtime.selection_cache, b'fallback', {})
        digest(d, b'MODEL-context', payload)
        if self.runtime.failure: raise self.runtime.failure
        return NS(extra=self.runtime.extra)


class Owner:
    def sign_result(self, command, payload):
        return self.signer._sign_body(command, payload)


class BindingsTests(unittest.TestCase):
    def test_physical_namespace_rejects_escape_existing_and_each_reparse_chain(self):
        with patch.object(bindings, 'Path', PhysicalPath):
            self.assertEqual(bindings.validate_owned_paths('G:/owned-task', 'unique-run'), config()['run_root'])
            for root, state in [('C:/owned-task', 'unique-run'), ('G:/', 'unique-run'),
                    ('G:/owned-task/../other', 'unique-run'), ('G:/owned-task', '../QQ'),
                    ('G:/owned-task', '非ASCII')]:
                with self.assertRaises(ValueError): bindings.validate_owned_paths(root, state)
            for ancestor in ('G:\\', 'G:\\owned-task'):
                with patch.object(PhysicalPath, 'reparse', ancestor):
                    with self.assertRaises(ValueError): bindings.validate_owned_paths('G:/owned-task', 'unique-run')
            for name in ('occupied', 'escaped'):
                with patch.object(PhysicalPath, name, True):
                    with self.assertRaises(ValueError): bindings.validate_owned_paths('G:/owned-task', 'unique-run')

    def test_resource_assembly_actual_fields_and_normal_order_no_capi_close(self):
        events = []
        owner, api, records = assembly(events)
        bundle = bindings.Resources().acquire(owner, api, config())
        self.assertIs(bundle.records, records)
        self.assertEqual(bundle.state17_owner(), b'MODEL-state17')
        self.assertEqual(bundle.clock_inputs['wall_seconds'](), 10)
        self.assertIs(bundle.random_environment, bundle.environment)
        bundle.stores.registry.write(bundle.stores.namespace, b'installFlag', b'MODEL')
        bundle.stores.registry.delete(bundle.stores.namespace, b'installStatus')
        self.assertEqual(bundle.persistence()['registry_calls'], [('write', False), ('delete', False)])
        self.assertEqual(bundle.persistence()['io_errors'], [('MODEL-cache-write', 5)])
        bundle.close()
        self.assertEqual(events, ['collect', 'close_collector', 'close_port', 'close_mix', 'close_env'])

    def test_partial_acquisition_closes_owner_before_backing_and_preserves_debt(self):
        for fail_close in (None, 'collector'):
            with self.subTest(fail_close=fail_close):
                events = []
                owner, api, _ = assembly(events, fail_collect=True, fail_close=fail_close)
                h = Harness()
                h.signer = owner.signer
                h.get_own_device_value = owner.get_own_device_value
                h.close = lambda: events.append('close_owner')
                with self.assertRaises((ValueError, BaseExceptionGroup)) as caught:
                    caller.run_model(h.config, action=h.action, open_windows_signer=h.open,
                        collect_resources=lambda o: bindings.Resources().acquire(o, api, config()), observe_sign=h.observe)
                self.assertEqual(events[:3], ['collect', 'close_owner', 'close_collector'])
                if fail_close:
                    self.assertIsNotNone(caught.exception.sdk_resources.collector)
                    self.assertNotIn('close_port', events)
                else:
                    self.assertEqual(events[-3:], ['close_port', 'close_mix', 'close_env'])

    def test_ws_matching_raw_reply_ignores_push_and_preserves_explicit_empty(self):
        reply = dict(echo='own', status='ok', retcode=0, data={'cmd': 'MODEL', 'hex': ''})
        socket = Socket([{'post_type': 'MODEL-event'}, {'echo': 'unrelated'}, reply])
        connect = Mock(return_value=socket)
        with bindings.WSAction('ws://explicit.invalid', overall_timeout=10, action_timeout=2,
                receive_budget=3, connect=connect, token='MODEL-private-token') as action:
            actual = action(dict(action='send_pb', params={'cmd': 'MODEL', 'hex': '00'}, echo='own'))
        self.assertEqual(actual, reply)
        self.assertEqual(len(socket.sent), 1)
        self.assertTrue(socket.closed)
        self.assertEqual(connect.call_args.kwargs, dict(open_timeout=2, close_timeout=2,
            additional_headers={'Authorization': 'Bearer MODEL-private-token'}))
        self.assertEqual(len(socket.timeouts), 3)
        self.assertTrue(all(0 < t <= 2 for t in socket.timeouts))

    def test_ws_timeout_disconnect_budget_and_api_error_no_resend(self):
        for replies, error in [([TimeoutError('MODEL timeout')], TimeoutError),
                ([''], ConnectionError), ([{'echo': 'other'}], caller.OneBotProtocolError)]:
            socket = Socket(replies)
            with bindings.WSAction('ws://explicit.invalid', overall_timeout=1, action_timeout=1,
                    receive_budget=1, connect=Mock(return_value=socket)) as action:
                with self.assertRaises(error): action(dict(action='send_pb', params={}, echo='own'))
            self.assertEqual(len(socket.sent), 1)
            self.assertTrue(socket.closed)
        socket = Socket([dict(echo='own', status='failed', retcode=1700, message='MODEL raw')])
        with bindings.WSAction('ws://explicit.invalid', overall_timeout=1, action_timeout=1,
                receive_budget=1, connect=Mock(return_value=socket)) as action:
            raw = action(dict(action='send_pb', params={}, echo='own'))
            with self.assertRaises(caller.OneBotAPIError) as caught: caller._action_data(raw, echo='own')
        self.assertIs(caught.exception.response, raw)
        self.assertEqual(caught.exception.retcode, 1700)

    def test_ws_overall_deadline_and_close_failure_propagate(self):
        ticks = iter([0, 2, 2])
        socket = Socket()
        with bindings.WSAction('ws://explicit.invalid', overall_timeout=1, action_timeout=1,
                receive_budget=1, connect=Mock(return_value=socket), clock=lambda: next(ticks)) as action:
            with self.assertRaises(TimeoutError): action(dict(action='MODEL', params={}, echo='own'))
        self.assertEqual(socket.sent, [])
        socket = Socket()
        socket.close = Mock(side_effect=OSError('MODEL close'))
        with self.assertRaises(BaseExceptionGroup) as caught:
            with bindings.WSAction('ws://explicit.invalid', overall_timeout=1, action_timeout=1,
                    receive_budget=1, connect=Mock(return_value=socket)):
                raise ValueError('MODEL operation')
        self.assertEqual(len(caught.exception.exceptions), 2)

    def test_ws_wrong_echo_uses_remaining_message_deadline_and_rejects_late_match(self):
        clock = [0.0]
        socket = Socket([{'echo': 'other1'}, {'echo': 'other2'}, {'echo': 'own'}])
        recv = socket.recv
        def receive(*, timeout):
            reply = recv(timeout=timeout)
            clock[0] += .4
            return reply
        socket.recv = receive
        with bindings.WSAction('ws://explicit.invalid', overall_timeout=2, action_timeout=1,
                receive_budget=3, connect=Mock(return_value=socket), clock=lambda: clock[0]) as action:
            with self.assertRaises(TimeoutError): action(dict(action='MODEL', params={}, echo='own'))
        self.assertEqual(len(socket.sent), 1)
        for actual, expected in zip(socket.timeouts, (1, .6, .2)):
            self.assertAlmostEqual(actual, expected)
        self.assertEqual(len(socket.timeouts), 3)
        self.assertTrue(socket.closed)

    def test_ws_overall_budget_shared_across_actions_and_exact_public_connect_options(self):
        clock = [0.0]
        socket = Socket([{'echo': 'first'}, {'echo': 'second'}])
        recv = socket.recv
        def receive(*, timeout):
            reply = recv(timeout=timeout)
            clock[0] += .6
            return reply
        socket.recv = receive
        def connect(uri, *, additional_headers, open_timeout, close_timeout):
            self.assertEqual(uri, 'ws://explicit.invalid')
            self.assertEqual(additional_headers, {})
            self.assertEqual((open_timeout, close_timeout), (1, 1))
            return socket
        with bindings.WSAction('ws://explicit.invalid', overall_timeout=1, action_timeout=1,
                receive_budget=2, connect=connect, clock=lambda: clock[0]) as action:
            self.assertEqual(action(dict(action='MODEL', params={}, echo='first')), {'echo': 'first'})
            with self.assertRaises(TimeoutError): action(dict(action='MODEL', params={}, echo='second'))
        self.assertEqual(len(socket.sent), 2)  # Two actions; neither is retried.
        self.assertAlmostEqual(socket.timeouts[0], 1)
        self.assertAlmostEqual(socket.timeouts[1], .4)
        self.assertTrue(socket.closed)

    def test_profile_actual_events_filters_same_cache_and_restores_profiler(self):
        for variant in ('positive', 'old_cache', 'selected_mismatch', 'extra_mismatch', 'wrong_cache', 'exception'):
            with self.subTest(variant=variant):
                cache = NS(value=b'MODEL-new')
                runtime = NS(selected=b'MODEL-new', extra=b'MODEL-new', selection_cache=cache, failure=None)
                signer = Signer()
                signer.runtime, signer.response_cache = runtime, cache
                owner = Owner()
                owner.signer = signer
                original = NS(command=COMMAND, body=b'MODEL-body')
                api = NS(signing_value=selected, request_context_digest=digest, PrimarySigner=Signer, WindowsSigner=Owner)
                before = b'MODEL-new' if variant == 'old_cache' else b''
                if variant == 'selected_mismatch': runtime.selected = b'fallback'
                if variant == 'extra_mismatch': runtime.extra = b'other'
                if variant == 'wrong_cache': runtime.selection_cache = NS(value=b'MODEL-new')
                if variant == 'exception': runtime.failure = ValueError('MODEL SIGN failure')
                previous = sys.getprofile()
                sentinel = lambda *args: None
                sys.setprofile(sentinel)
                try:
                    evidence = None
                    try:
                        with bindings.observe_sign(owner, original, completion(), api=api, before=before) as evidence:
                            selected(runtime, cache, b'', {})  # outside signer chain is ignored
                            digest(cache.value, b'', original.body)
                            owner.sign_result(original.command, original.body)
                    except ValueError:
                        self.assertEqual(variant, 'exception')
                    self.assertIs(sys.getprofile(), sentinel)
                    self.assertEqual(evidence['consumption'], 'OBSERVED' if variant == 'positive' else 'UNKNOWN')
                finally:
                    sys.setprofile(previous)

    def test_cli_run_requires_config_and_offline_never_loads_bindings(self):
        with patch.object(bindings, 'run_live', side_effect=AssertionError('no live execution')):
            with patch('sys.stderr', new_callable=io.StringIO):
                with self.assertRaises(SystemExit): caller.main(['--run'])
            raw = json.dumps(dict(echo='record', status='ok', retcode=0, data={'user_id': UIN})).encode()
            with patch.object(Path, 'read_bytes', return_value=raw), redirect_stdout(io.StringIO()):
                self.assertEqual(caller.main(['--metadata-json', 'MODEL.json', '--expected-uin', str(UIN)]), 0)

    def test_deferred_live_assembly_and_factory_failure_core_retention(self):
        for mode in ('normal', 'factory_clean_failure', 'factory_retained_failure'):
            with self.subTest(mode=mode):
                events = []
                resource_owner, api, _ = assembly(events)
                h = Harness()
                h.signer = resource_owner.signer
                h.get_own_device_value = resource_owner.get_own_device_value
                h.result = completion(outcome='failed', cache_updated=False, publication=None)
                close_owner = h.close
                def close():
                    events.append('close_owner')
                    close_owner()
                h.close = close
                failure = OSError('MODEL factory failure')
                if mode == 'factory_retained_failure': failure.independent_windows_owner = h
                api.open_windows_signer = h.open if mode == 'normal' else Mock(side_effect=failure)
                api.OwnImageModuleSpec = NS(for_loader_profile=Mock(return_value=object()))
                @contextmanager
                def active():
                    events.append('core_enter')
                    try: yield
                    finally: events.append('core_exit')
                core = NS(activate=active, close=lambda: events.append('core_close'))
                @contextmanager
                def action(*args, **kwargs):
                    try: yield h.action
                    finally: events.append('ws_close')
                acquire = bindings.Resources.acquire
                def collect(bundle, owner, api, cfg):
                    result = acquire(bundle, owner, api, cfg)
                    h.resources = result
                    return result
                with patch.dict(sys.modules, {'signature_core': NS(load_core=lambda: core)}), \
                        patch.object(bindings, 'WSAction', action), \
                        patch.object(bindings, 'load_source_api', return_value=api), \
                        patch.object(bindings, 'validate_owned_paths', return_value=config()['run_root']), \
                        patch.object(bindings.Resources, 'acquire', collect):
                    if mode == 'normal':
                        result = bindings.run_live(config())
                        self.assertEqual(result.scope, 'OWN_SDK_EXTERNAL_CARRIER_NOT_FULL_GOAL')
                        self.assertEqual(h.events.count('complete'), 1)
                        self.assertEqual(api.OwnImageModuleSpec.for_loader_profile.call_args.args, ('MODEL-profile',))
                        self.assertEqual(events[-8:], ['close_owner', 'close_collector', 'close_port',
                            'close_mix', 'close_env', 'ws_close', 'core_exit', 'core_close'])
                    else:
                        with self.assertRaises(OSError) as caught: bindings.run_live(config())
                        self.assertIs(caught.exception, failure)
                        self.assertIn('ws_close', events)
                        if mode == 'factory_retained_failure':
                            self.assertIs(failure.sdk_core, core)
                            self.assertNotIn('core_exit', events)
                            self.assertNotIn('core_close', events)
                            # Explicitly dispose fixture-only retained context.
                            failure.sdk_activation.__exit__(None, None, None)
                            core.close()
                        else:
                            self.assertEqual(events[-2:], ['core_exit', 'core_close'])

    def test_live_config_has_explicit_inputs_no_material_or_timeout_defaults(self):
        value = config()
        value.pop('machine_id')
        value.pop('run_root')
        value['machine_id_hex'] = b'MODEL-persistent'.hex()
        value['bridge_path'], value['worker_bridge_path'] = 'G:/bridge.dll', 'G:/worker.dll'
        with patch.object(Path, 'read_bytes', return_value=json.dumps(value).encode()), \
                patch.object(bindings, 'validate_owned_paths', return_value=config()['run_root']):
            actual = bindings.read_live_config('MODEL-private.json')
        self.assertEqual(actual['machine_id'], b'MODEL-persistent')
        value.pop('machine_id_hex')
        with patch.object(Path, 'read_bytes', return_value=json.dumps(value).encode()):
            with self.assertRaises(ValueError): bindings.read_live_config('MODEL-private.json')

    def test_deferred_source_bindings_match_static_public_api_and_core(self):
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / 'own_sdk_onebot_bindings.py').read_text(encoding='utf-8'))
        self.assertFalse(any(isinstance(n, (ast.Import, ast.ImportFrom)) and
            ((isinstance(n, ast.ImportFrom) and (n.module or '').startswith('qq_nt_replica')) or
             any(a.name.startswith(('qq_nt_replica', 'websocket', 'signature_core')) for a in n.names))
            for n in tree.body))
        expected = {'primary_device_record_collector.py': {'IndependentDeviceRecordCollector': {'collect', 'close'}},
            'primary_windows_ownimage.py': {'OwnImageModuleSpec': {'for_loader_profile'}},
            'primary_windows_wmi_session.py': {'OwnedWmiSession': {'open'}}}
        for file, classes in expected.items():
            parsed = ast.parse((root / 'src/qq_nt_replica' / file).read_text(encoding='utf-8'))
            for name, methods in classes.items():
                cls = next(n for n in parsed.body if isinstance(n, ast.ClassDef) and n.name == name)
                self.assertTrue(methods <= {n.name for n in cls.body if isinstance(n, ast.FunctionDef)})


if __name__ == '__main__':
    unittest.main()
