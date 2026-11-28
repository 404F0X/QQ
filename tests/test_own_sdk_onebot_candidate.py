"""Pure orchestration MODEL checks; no SDK imports, Native or action transport."""
import ast
from contextlib import contextmanager, redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

import run_own_sdk_onebot_candidate as candidate


UIN = 3932244601
ROOT = Path(__file__).resolve().parents[1]
COMMAND = b'trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey'


def completion(**changes):
    values = dict(outcome='processed', stage='publication', code=None,
        cache_updated=True, publication={'MODEL': 'publication'})
    values.update(changes)
    return NS(**values)


class Harness:
    """Enforce outstanding identity, owner liveness and borrowed backing order."""
    def __init__(self):
        self.events = []
        self.actions = []
        self.config = candidate.ModelConfig(UIN, b'MODEL-own-persistent-machine',
            object(), object(), object(), object())
        self.original = NS(command=COMMAND, body=b'\x0a\x03OWN',
            decode_material=object(), sdk_sequence=1, encoded=object())
        self.decode_material = self.original.decode_material
        self.result = completion()
        self.response_hex, self.expected_body = '0a03415049', b'\x0a\x03API'
        self.completions = []
        self.pending = self.closed = self.observing = False
        self.response_error = self.close_error = self.resource_close_error = None
        self.complete_error = self.cancel_error = self.observer_error = None
        self.sign_error = None
        self.login_data = {'user_id': UIN}
        self.transform_reply = lambda request, reply: reply
        self.resources = NS(records=object(), request_capi=object(),
            clock_inputs={name: (lambda: 1) for name in ('wall_seconds', 'monotonic_ns', 'clock_ns')},
            random_environment=object(), state17_owner=lambda: object(), close=self.close_resources)
        self.factory_calls = []
        self.collect_error = self.initialize_error = None
        self.evidence = {'consumption': 'UNKNOWN'}

    def live(self):
        assert not self.closed

    def open(self, **kwargs):
        self.events.append('factory')
        self.factory_calls.append(kwargs)
        return self

    def collect(self, owner):
        assert owner is self
        self.events.append('collect')
        if self.collect_error:
            raise self.collect_error
        return self.resources

    def own_business_identity(self):
        self.live()
        return UIN, self.config.machine_id

    def initialize_own_sdk_request(self, **kwargs):
        self.live()
        assert kwargs == {name: getattr(self.resources, name) for name in
            ('request_capi', 'clock_inputs', 'random_environment', 'state17_owner')}
        self.events.append('initialize')
        if self.initialize_error:
            raise self.initialize_error

    def create_own_device_request(self, records, *, external_a2_selection):
        self.live()
        assert records is self.resources.records and external_a2_selection is None
        assert not self.pending
        self.pending = True
        self.events.append('original')
        return self.original

    def action(self, request):
        request = json.loads(json.dumps(request))
        self.actions.append(request)
        name = request['action']
        self.events.append(name)
        if name == 'get_login_info':
            assert request['params'] == {} and not self.factory_calls
            data = self.login_data
        else:
            assert name == 'send_pb' and self.pending
            self.live()
            assert request['params'] == {'cmd': 'trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey',
                'hex': self.original.body.hex()}
            assert self.original.command is COMMAND
            assert self.original.decode_material is self.decode_material
            if self.response_error:
                raise self.response_error
            data = {'cmd': request['params']['cmd'], 'hex': self.response_hex}
        reply = self.transform_reply(request, dict(status='ok', retcode=0, data=data, echo=request['echo']))
        self.last_reply = json.loads(json.dumps(reply))
        return self.last_reply

    def complete_own_device_request(self, original, body, *, transport_status):
        self.live()
        assert original is self.original and original.decode_material is self.decode_material
        assert original.command is COMMAND
        assert self.pending and body == self.expected_body and transport_status == 0
        self.completions.append((original, body, transport_status))
        self.events.append('complete')
        self.pending = False
        if self.complete_error:
            raise self.complete_error
        return self.result

    def cancel_own_device_request(self, original):
        self.live()
        assert original is self.original and self.pending
        self.events.append('cancel')
        if self.cancel_error:
            raise self.cancel_error
        self.pending = False

    @contextmanager
    def observe(self, owner, original, result):
        self.live()
        assert owner is self and original is self.original and result is self.result
        assert not self.pending
        self.events.append('observer_enter')
        if self.observer_error:
            raise self.observer_error
        self.observing = True
        try:
            yield self.evidence
        finally:
            self.observing = False
            self.events.append('observer_exit')

    def sign_result(self, command, body):
        self.live()
        assert self.observing and command is COMMAND and body is self.original.body
        self.events.append('sign')
        if self.sign_error:
            raise self.sign_error
        return 'MODEL-local-SIGN'

    def close(self):
        self.events.append('close_owner')
        if self.close_error:
            raise self.close_error
        self.closed = True

    def close_resources(self):
        assert self.closed
        self.events.append('close_resources')
        if self.resource_close_error:
            raise self.resource_close_error

    def run(self):
        return candidate.run_model(self.config, action=self.action,
            open_windows_signer=self.open, collect_resources=self.collect, observe_sign=self.observe)


class OneBotCandidateModelTests(unittest.TestCase):
    def test_reported_zero_missing_wrong_identity_never_opens_owner_or_sends(self):
        # Actual source: A/onebot-metadata-only-20261128/ws-readonly/RESULT.md;
        # only the safe identity/status fields are reproduced, no private reply.
        for data in ({'user_id': 0}, {}, {'user_id': UIN + 1}, {'user_id': str(UIN)}, {'user_id': True}):
            with self.subTest(data=data):
                h = Harness()
                h.login_data = data
                with self.assertRaises(candidate.IdentityBlocked):
                    h.run()
                self.assertEqual(h.events, ['get_login_info'])
                self.assertEqual(h.factory_calls, [])
                self.assertEqual([a['action'] for a in h.actions], ['get_login_info'])

    def test_positive_model_order_exact_public_inputs_original_and_same_owner_sign(self):
        h = Harness()
        result = h.run()
        self.assertEqual(h.events, ['get_login_info', 'factory', 'collect', 'initialize',
            'original', 'send_pb', 'complete', 'observer_enter', 'sign', 'observer_exit',
            'close_owner', 'close_resources'])
        self.assertEqual(h.factory_calls, [dict(bridge_path=h.config.bridge_path,
            worker_bridge_path=h.config.worker_bridge_path, storage_root=h.config.storage_root,
            ownimage_module=h.config.ownimage_module, host_profile_string=candidate.BUSINESS_QUA,
            primary_backend='direct', own_business_config={'uin': UIN, 'machine_id': h.config.machine_id})])
        self.assertEqual(len({a['echo'] for a in h.actions}), 2)
        self.assertIs(result.completion, h.result)
        self.assertIs(result.observation, h.evidence)
        self.assertEqual(result.observation['consumption'], 'UNKNOWN')
        self.assertEqual(result.scope, 'MODEL_ONLY_NOT_BUSINESS_CLOSURE')

    def test_api_error_preserves_raw_codes_and_cancels_original_without_completion(self):
        for failed_action in ('get_login_info', 'send_pb'):
            with self.subTest(action=failed_action):
                h = Harness()
                raw = {}
                def fail(request, reply):
                    if request['action'] == failed_action:
                        reply.update(status='failed', retcode=1400, message='MODEL raw API failure')
                        raw.update(reply)
                        return raw
                    return reply
                h.transform_reply = fail
                with self.assertRaises(candidate.OneBotAPIError) as caught:
                    h.run()
                self.assertIs(caught.exception.response, h.last_reply)
                self.assertEqual(caught.exception.response, raw)
                self.assertEqual((caught.exception.retcode, caught.exception.status, caught.exception.message),
                    (1400, 'failed', 'MODEL raw API failure'))
                self.assertNotIn('complete', h.events)
                self.assertNotIn('sign', h.events)
                if failed_action == 'send_pb':
                    self.assertEqual(h.events[-3:], ['cancel', 'close_owner', 'close_resources'])
                else:
                    self.assertEqual(h.events, ['get_login_info'])

    def test_echo_and_application_body_protocol_errors_cancel_without_synthetic_response(self):
        changes = [lambda r: r.update(echo='unrelated'),
            lambda r: r.update(retcode=True), lambda r: r.pop('data'),
            lambda r: r['data'].pop('cmd'), lambda r: r['data'].update(cmd='wrong'),
            lambda r: r['data'].pop('hex'), lambda r: r['data'].update(hex=None),
            lambda r: r['data'].update(hex=0),
            lambda r: r['data'].update(hex='xz'), lambda r: r['data'].update(hex='00 11')]
        for change in changes:
            with self.subTest(change=change):
                h = Harness()
                def malformed(request, reply):
                    if request['action'] == 'send_pb':
                        change(reply)
                    return reply
                h.transform_reply = malformed
                with self.assertRaises(candidate.OneBotProtocolError):
                    h.run()
                self.assertEqual(h.events[-3:], ['cancel', 'close_owner', 'close_resources'])
                self.assertNotIn('complete', h.events)

    def test_explicit_empty_body_is_completed_once_and_result_controls_sign(self):
        # These outcomes are injected, not a prediction of the real decoder.
        for positive in (False, True):
            with self.subTest(positive=positive):
                h = Harness()
                h.response_hex, h.expected_body = '', b''
                h.result = completion() if positive else completion(
                    outcome='failed', stage='auth', code=2, cache_updated=False, publication=None)
                result = h.run()
                self.assertIs(result.completion, h.result)
                self.assertEqual(h.completions, [(h.original, b'', 0)])
                self.assertEqual(h.events.count('complete'), 1)
                self.assertNotIn('cancel', h.events)
                self.assertEqual(h.events.count('observer_enter'), int(positive))
                self.assertEqual(h.events.count('sign'), int(positive))
                self.assertIs(h.original.command, COMMAND)

    def test_explicit_empty_completion_exception_consumes_without_cancel_or_replay(self):
        h = Harness()
        h.response_hex, h.expected_body = '', b''
        h.complete_error = ValueError('MODEL decoder exception for explicit empty input')
        with self.assertRaises(ValueError) as caught:
            h.run()
        self.assertIs(caught.exception, h.complete_error)
        self.assertEqual(h.completions, [(h.original, b'', 0)])
        self.assertEqual(h.events.count('original'), 1)
        self.assertEqual(h.events.count('complete'), 1)
        self.assertNotIn('cancel', h.events)
        self.assertNotIn('observer_enter', h.events)
        self.assertNotIn('sign', h.events)
        self.assertEqual(h.events[-2:], ['close_owner', 'close_resources'])

    def test_command_text_conversion_is_strict_and_does_not_mutate_original(self):
        h = Harness()
        invalid_command = b'\xffMODEL-invalid-command'
        h.original.command = invalid_command
        with self.assertRaises(UnicodeDecodeError):
            h.run()
        self.assertIs(h.original.command, invalid_command)
        self.assertEqual([a['action'] for a in h.actions], ['get_login_info'])
        self.assertNotIn('complete', h.events)
        self.assertEqual(h.events[-3:], ['cancel', 'close_owner', 'close_resources'])

    def test_login_echo_error_stops_before_factory(self):
        h = Harness()
        h.transform_reply = lambda req, reply: dict(reply, echo='other')
        with self.assertRaises(candidate.OneBotProtocolError):
            h.run()
        self.assertEqual(h.events, ['get_login_info'])

    def test_action_exception_and_failed_cancel_remain_visible(self):
        h = Harness()
        h.response_error = TimeoutError('MODEL action timeout')
        h.cancel_error = OSError('MODEL cancel debt')
        with self.assertRaises(BaseExceptionGroup) as caught:
            h.run()
        self.assertEqual(caught.exception.exceptions, (h.response_error, h.cancel_error))
        self.assertNotIn('complete', h.events)
        self.assertEqual(h.events[-2:], ['close_owner', 'close_resources'])

    def test_only_processed_new_cache_and_publication_enable_observer_and_sign(self):
        negatives = [completion(outcome='failed'), completion(stage='auth'), completion(code=0),
            completion(cache_updated=False), completion(publication=None)]
        for result in negatives:
            with self.subTest(result=result):
                h = Harness()
                h.result = result
                actual = h.run()
                self.assertIs(actual.completion, result)
                self.assertIsNone(actual.sign_result)
                self.assertIsNone(actual.observation)
                self.assertNotIn('observer_enter', h.events)
                self.assertNotIn('sign', h.events)
                self.assertEqual(h.events.count('complete'), 1)
                self.assertNotIn('cancel', h.events)

    def test_consumed_original_not_cancelled_or_replayed_when_decoder_raises(self):
        h = Harness()
        h.complete_error = ValueError('MODEL decoder failure after consume')
        with self.assertRaises(ValueError) as caught:
            h.run()
        self.assertIs(caught.exception, h.complete_error)
        self.assertEqual(h.events.count('original'), 1)
        self.assertEqual(h.events.count('complete'), 1)
        self.assertNotIn('cancel', h.events)
        self.assertNotIn('sign', h.events)

    def test_observer_and_sign_failures_propagate_after_single_completion(self):
        for stage in ('observer_error', 'sign_error'):
            with self.subTest(stage=stage):
                h = Harness()
                failure = RuntimeError('MODEL observation failure')
                setattr(h, stage, failure)
                with self.assertRaises(RuntimeError) as caught:
                    h.run()
                self.assertIs(caught.exception, failure)
                self.assertEqual(h.events.count('complete'), 1)
                self.assertNotIn('cancel', h.events)
                self.assertEqual(h.events[-2:], ['close_owner', 'close_resources'])

    def test_failed_close_retains_owner_backing_and_operation_error(self):
        h = Harness()
        h.close_error = OSError('MODEL owner cleanup debt')
        h.response_error = TimeoutError('MODEL action error')
        with self.assertRaises(BaseExceptionGroup) as caught:
            h.run()
        self.assertEqual(caught.exception.exceptions, (h.response_error, h.close_error))
        self.assertIs(caught.exception.sdk_owner, h)
        self.assertIs(caught.exception.sdk_resources, h.resources)
        self.assertFalse(h.closed)
        self.assertNotIn('close_resources', h.events)

    def test_close_failure_cannot_return_positive_result_or_claim_all_closed(self):
        for field in ('close_error', 'resource_close_error'):
            with self.subTest(field=field):
                h = Harness()
                failure = OSError('MODEL close failure')
                setattr(h, field, failure)
                with self.assertRaises(OSError) as caught:
                    h.run()
                self.assertIs(caught.exception, failure)
                self.assertIs(caught.exception.sdk_resources, h.resources)

    def test_initialization_failure_closes_without_original(self):
        h = Harness()
        h.initialize_error = ValueError('MODEL initialization failure')
        with self.assertRaises(ValueError):
            h.run()
        self.assertNotIn('original', h.events)
        self.assertEqual(h.events[-2:], ['close_owner', 'close_resources'])

    def test_explicit_identity_and_persistent_machine_bytes_required(self):
        for uin in (0, -1, True, '123', 1 << 64):
            with self.assertRaises(ValueError):
                replace(Harness().config, expected_uin=uin)
        for machine in (b'', b'x\0y', 'MODEL-string', None):
            with self.assertRaises(ValueError):
                replace(Harness().config, machine_id=machine)

    def test_cli_only_reads_recorded_metadata_and_never_invokes_model(self):
        for uin, code, status in ((0, 1, 'BLOCKED'), (UIN, 0, 'RECORDED_IDENTITY_MATCH_NOT_EXECUTED')):
            raw = json.dumps(dict(status='ok', retcode=0, data={'user_id': uin}, echo='recorded-model'))
            output = io.StringIO()
            with patch.object(Path, 'read_bytes', return_value=raw.encode()), \
                    patch.object(candidate, 'run_model', side_effect=AssertionError('no model execution')), \
                    redirect_stdout(output):
                actual = candidate.main(['--metadata-json', 'MODEL-reply.json', '--expected-uin', str(UIN)])
            self.assertEqual(actual, code)
            reply = json.loads(output.getvalue())
            self.assertEqual(reply['status'], status)
            self.assertEqual(reply['execution'], 'NOT_EXECUTED')
        with redirect_stdout(io.StringIO()), patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as caught:
                candidate.main(['--metadata-json', 'MODEL', '--expected-uin', str(UIN), '--run'])
        self.assertEqual(caught.exception.code, 2)

    def test_source_public_signature_and_qua_compatibility_without_target_import(self):
        source = ast.parse((ROOT / 'src/qq_nt_replica/primary_windows_signer.py').read_text(encoding='utf-8'))
        factory = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'open_windows_signer')
        self.assertTrue({'bridge_path', 'worker_bridge_path', 'storage_root', 'ownimage_module',
            'host_profile_string', 'primary_backend', 'own_business_config'} <= {a.arg for a in factory.args.kwonlyargs})
        owner = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'WindowsSigner')
        methods = {n.name: n for n in owner.body if isinstance(n, ast.FunctionDef)}
        for name in ('own_business_identity', 'initialize_own_sdk_request', 'create_own_device_request',
                'complete_own_device_request', 'cancel_own_device_request', 'sign_result', 'close'):
            self.assertIn(name, methods)
        create = methods['create_own_device_request']
        self.assertEqual([a.arg for a in create.args.kwonlyargs], ['external_a2_selection'])
        self.assertIsNone(ast.literal_eval(create.args.kw_defaults[0]))
        complete = methods['complete_own_device_request']
        self.assertEqual([a.arg for a in complete.args.args], ['self', 'request', 'responsebody'])
        self.assertEqual([a.arg for a in complete.args.kwonlyargs], ['transport_status'])
        setup = ast.parse((ROOT / 'src/qq_nt_replica/primary_windows_signer_setup.py').read_text(encoding='utf-8'))
        qua = next(n.value for n in setup.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'BUSINESS_QUA' for t in n.targets))
        self.assertEqual(ast.literal_eval(qua), candidate.BUSINESS_QUA)
        request_source = ast.parse((ROOT / 'src/qq_nt_replica/primary_sdk_request.py').read_text(encoding='utf-8'))
        request = next(n for n in request_source.body if isinstance(n, ast.ClassDef) and n.name == 'SdkRecordRequest')
        command = next(n for n in request.body if isinstance(n, ast.AnnAssign) and n.target.id == 'command')
        self.assertEqual(command.annotation.id, 'bytes')
        transport = ast.parse((ROOT / 'src/qq_nt_replica/primary_request_transport.py').read_text(encoding='utf-8'))
        commands = next(n.value for n in transport.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == '_COMMANDS' for t in n.targets))
        self.assertIs(type(COMMAND), bytes)
        self.assertEqual(COMMAND, ast.literal_eval(commands)[1])

    def test_module_has_no_live_import_or_factory_bindings(self):
        tree = ast.parse((ROOT / 'run_own_sdk_onebot_candidate.py').read_text(encoding='utf-8'))
        imports = {n.module if isinstance(n, ast.ImportFrom) else alias.name
            for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
            for alias in (n.names if isinstance(n, ast.Import) else [None])}
        self.assertEqual(imports, {'argparse', 'dataclasses', 'json', 'pathlib', 'typing', 'uuid',
            'own_sdk_onebot_bindings'})
        # Top-level expressions are only docstring, definitions, a literal and
        # the standard __main__ guard; importing cannot enter the model path.
        self.assertFalse(any(isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) for n in tree.body))
        for name in ('action', 'open_windows_signer', 'collect_resources', 'observe_sign'):
            self.assertNotIn(name, vars(candidate))


if __name__ == '__main__':
    unittest.main()
