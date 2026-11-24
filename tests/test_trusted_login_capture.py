"""Synthetic private bundles only; no authentication, network or native APIs."""
import dataclasses
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import trusted_login_capture as subject
import replay_login_capture


LOGIN_ROOT = Path('G:/Hackergame/.codex-workflow/reports/pmhq-analysis-20261010/replica-primary-sign-core-20261019/main96-independent-qr-resident-login-20261119')


@dataclasses.dataclass
class OrdinaryFixture:
    raw: bytes
    fields: tuple


@dataclasses.dataclass
class SignFixture:
    sign: bytes
    extra: bytes
    token: bytes


class TrustedCapture(unittest.TestCase):
    def setUp(self):
        self.deny = patch.multiple(socket, create_connection=self.no_network,
            getaddrinfo=self.no_network)
        self.deny.start()
        subject.CAPTURE_ROOT.mkdir(exist_ok=True)
        self.inputs = Path(tempfile.mkdtemp(prefix='controlled-inputs-', dir=subject.CAPTURE_ROOT)) / 'INPUTS.json'
        self.inputs.write_text('{}', encoding='utf-8')

    def tearDown(self):
        self.deny.stop()

    @staticmethod
    def no_network(*args, **kwargs):
        raise AssertionError('OFFLINE_TEST_NETWORK')

    def capture(self):
        return subject.LoginCapture(subject.CAPTURE_ROOT, login_root=LOGIN_ROOT,
            inputs=self.inputs, parameters={'synthetic_controlled_fixture': True})

    def test_current_source_binding_assembles_original_public_loaders(self):
        path = Path(__file__).resolve().parents[1] / 'run_authenticated_sdk_session.py'
        spec = importlib.util.spec_from_file_location('current_login_entry_test', path)
        entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(entry)
        evidence = subject.CAPTURE_ROOT.parent / 'authenticated-sdk-integration-a1/trusted-capture-a1/source-binding-replan-a1'
        current = evidence / 'INPUTS.json'
        legacy = json.loads((LOGIN_ROOT / 'ENTRY-SOURCE-BINDING.json').read_bytes())
        old_snapshot = (evidence / 'legacy-ENTRY-SOURCE-BINDING.json').read_bytes()
        self.assertTrue((LOGIN_ROOT / 'ENTRY-SOURCE-BINDING.json').read_bytes() == old_snapshot)
        document = entry._checked_inputs(current, LOGIN_ROOT)
        pins = {Path(row['path']).resolve(): row['sha256'] for row in document['files']}
        changed = [name for name, row in legacy['sources'].items()
            if pins[Path(row['path']).resolve()] != row['sha256']]
        self.assertEqual(changed, ['envelope.py'])
        sys.path.insert(0, str(LOGIN_ROOT))
        try:
            import mode1_binding as binding
            with self.assertRaisesRegex(RuntimeError, '^RESIDENT_SOURCE_CHANGED$'):
                binding.checked(legacy['sources']['envelope.py'])
            Q, T, G, W, adapter = entry._load_login_components(LOGIN_ROOT, current)
            self.assertIs(Q, sys.modules['independent_qr_login'])
            self.assertIs(T, sys.modules['independent_login_ticket_exchange'])
            self.assertIs(W._qr_api, Q)
            self.assertIs(G.StateError, sys.modules['independent_login_account_registration.common'].StateError)
            self.assertTrue(adapter.HERE.resolve() == (LOGIN_ROOT / 'adapter').resolve())
            self.assertTrue((LOGIN_ROOT / 'ENTRY-SOURCE-BINDING.json').read_bytes() == old_snapshot)
        finally:
            sys.path.remove(str(LOGIN_ROOT))

    def test_binary_order_alias_and_unavailable_are_explicit(self):
        capture = self.capture()
        capture.dto_types.add(OrdinaryFixture)
        raw = bytes(range(256)) + b'\x00\xff\x00'
        value = OrdinaryFixture(raw, (raw, {9: raw, 1: b'other'}))
        capture.record('fixture', value=value, same=value, unsupported=object())
        capture.close()
        event = json.loads((capture.path / 'events.jsonl').read_text())
        decoded = subject.decode_value(event['values'], capture.path,
            dto_types={__name__ + '.OrdinaryFixture': OrdinaryFixture})
        self.assertIs(decoded['value'], decoded['same'])
        self.assertTrue(decoded['value'].raw == raw)
        self.assertEqual(list(decoded['value'].fields[1]), [9, 1])
        manifest = json.loads((capture.path / 'manifest.json').read_text())
        self.assertTrue(manifest['unserialized'])
        self.assertIn('ticket.response', manifest['not_reached'])
        # Preserve duplicate entries, unknown values, tail, and comparison facts.
        packet = bytes.fromhex('00030001000161000100016299990000') + b'tail'
        view = subject.ordered_tlvs(packet)
        self.assertEqual([r['tag'] for r in view['entries']], [1, 1, 0x9999])
        self.assertFalse(view['entries'][1]['same_value'])
        self.assertTrue(view['tail'] == b'tail')

    def test_capture_failure_keeps_primary_and_restores_profile(self):
        capture = self.capture()
        original_stream = capture._events
        class Failed:
            def write(self, value):
                raise OSError('synthetic private capture failure')
            def close(self):
                pass
        capture._events = Failed()
        primary = RuntimeError('synthetic private original failure')
        previous = sys.getprofile()
        with self.assertRaises(RuntimeError) as caught:
            with capture.ticket_scope():
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertIs(sys.getprofile(), previous)
        self.assertFalse(capture.available)
        capture.close()
        original_stream.close()
        manifest = json.loads((capture.path / 'manifest.json').read_text())
        self.assertEqual(manifest['status'], 'incomplete')
        self.assertTrue(manifest['capture_failures'])

    def test_normal_composition_effective_capture_and_offline_difference(self):
        sys.path.insert(0, str(LOGIN_ROOT))
        try:
            G = runpy.run_path(str(LOGIN_ROOT / 'G/entry.py'))['load_api']()
            Q = sys.modules['independent_qr_login']
            T = sys.modules['independent_login_ticket_exchange']
            from resident_core_composition import login_diagnostics
            from public_events import exception_origin
            capture = self.capture()
            capture.configure(Q, T, G)
            key = bytes(range(16))
            device = Q.QrDevice(bytes(16), 'Windows', 'synthetic', Q.EcdhKeys(b'\x02' + bytes(24), key))
            tickets = T.ConfirmedQrTickets(Q.PollResult(0, 123, key, b'n', b'p'), 123, 'SYNTHETIC')
            nested = Q.tlvs([(0x143, b'synthetic-d2'), (0x305, key),
                (0x10A, b'synthetic-tgt'), (0x543, b'\x4a\x09\x5a\x07\x0a\x05valid'),
                (0x9999, b'first'), (0x9999, b'last')])
            encrypted = Q.tea_encrypt(nested, key, entropy=lambda n: bytes(n))
            outer = Q.tea_encrypt(b'\x00\x09\x00' + Q.tlvs([(0x119, encrypted)]), key, entropy=lambda n: bytes(n))
            payload = bytearray(b'\x02\x00\x00\x00\x00\x08\x10' + bytes(9) + outer + b'\x03')
            payload[1:3] = len(payload).to_bytes(2, 'big')
            target = []
            original = G.LoginContinuation.accept_ticket_exchange
            with login_diagnostics(G.LoginContinuation, target, exception_origin):
                method = G.LoginContinuation.accept_ticket_exchange
                self.assertIs(method.__code__, original.__code__)
                capture.effective_parser(method)
                parser = method.__globals__['parse_login_response']
                with capture.ticket_scope():
                    result = parser(bytes(payload), device=device, tickets=tickets)
                self.assertIs(type(result), T.SessionMaterial)
                self.assertTrue(result.opaque_tlvs[0x9999] == b'last')
            self.assertIs(G.LoginContinuation.accept_ticket_exchange, original)
            capture.close()
            self.assertTrue(capture.available)
            process = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve().parents[1] / 'replay_login_capture.py'), str(capture.path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                output, errors = process.communicate(timeout=30)
            except BaseException:
                process.kill()
                process.wait()
                raise
            (capture.path / 'offline-test-process.json').write_text(json.dumps(
                dict(pid=process.pid, exit_code=process.returncode, joined=True)) + '\n')
            self.assertEqual(process.returncode, 0)
            summary = json.loads(output)
            report = json.loads(Path(summary['report']).read_bytes())
            self.assertTrue(report['offline'])
            self.assertFalse(report['material_B_proof'])
            self.assertEqual(len(report['parser_runs']), 2)
            self.assertEqual(report['parser_runs'][0]['code'], 'LOGIN_SHARED_QR_DUPLICATE_TLV')
            self.assertTrue(report['parser_runs'][1]['returned'])
            inner = [r for r in report['ordered_tlvs'] if r['layer'] == 'ticket.inner0119']
            self.assertTrue(inner)
            self.assertEqual([r['tag'] for r in inner[0]['structure']['entries']][-2:], [0x9999, 0x9999])
        finally:
            sys.path.remove(str(LOGIN_ROOT))

    def test_entry_private_output_keeps_fd_and_python_bytes_off_console(self):
        path = Path(__file__).resolve().parents[1] / 'run_authenticated_sdk_session.py'
        spec = importlib.util.spec_from_file_location('capture_entry_test', path)
        entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(entry)
        capture = self.capture()
        with entry._private_output(capture.log_path):
            print('synthetic private Python log')
            os.write(2, b'synthetic private fd log\n')
        data = capture.log_path.read_bytes()
        self.assertTrue(b'synthetic private Python log' in data)
        self.assertTrue(b'synthetic private fd log' in data)
        capture.close()

    def test_existing_sign_observer_keeps_exact_result_and_primary_exception(self):
        sys.path.insert(0, str(LOGIN_ROOT))
        try:
            from core_result_r10 import CoreObservedSigner
            class Queue(list):
                _items = ()
                def _owner(self):
                    pass
            capture = self.capture()
            capture.dto_types.add(SignFixture)
            result = SignFixture(b'synthetic-sign', b'synthetic-extra', b'synthetic-token')
            request = SimpleNamespace(command=b'wtlogin.login', sequence=4, payload=b'synthetic-payload')
            owner = SimpleNamespace(sign_result=lambda command, payload: result)
            signer = CoreObservedSigner(None, None, None, owner, SignFixture, Queue(), None, capture=capture)
            signer.current_request = request
            self.assertIs(signer.owner.sign_result(request.command, request.payload), result)
            primary = RuntimeError('synthetic original sign exception')
            def fail(command, payload):
                raise primary
            owner.sign_result = fail
            with self.assertRaises(RuntimeError) as caught:
                signer.owner.sign_result(request.command, request.payload)
            self.assertIs(caught.exception, primary)
            signer.close_observer()
            capture.close()
            manifest = json.loads((capture.path / 'manifest.json').read_text())
            self.assertTrue({'sign.input', 'sign.result', 'sign.exception'}.issubset(manifest['observed']))
        finally:
            sys.path.remove(str(LOGIN_ROOT))

    def test_transport_inherited_hooks_keep_heartbeat_and_partial_failure(self):
        sys.path.insert(0, str(LOGIN_ROOT))
        try:
            from envelope import resident_transport
            primary = EOFError('synthetic partial receive')
            class PhysicalBase:
                def __init__(self, **kwargs):
                    self._heartbeat_pending, self._heartbeat_sequence = True, 1
                    self._buffer = bytearray()
                    self.replies = [b'synthetic-heartbeat', b'synthetic-business']
                def _send(self, frame, *args, **kwargs):
                    self.sent = (frame, args, kwargs)
                def _receive(self, *args, **kwargs):
                    if self.replies:
                        return self.replies.pop(0)
                    self._buffer.extend(b'synthetic-partial-frame')
                    raise primary
            capture = self.capture()
            transport = resident_transport(SimpleNamespace(FiniteTcpTransport=PhysicalBase),
                SimpleNamespace(decode_startup_heartbeat=lambda *a, **k: None), None,
                clock=lambda: 0, guard=SimpleNamespace(resolve=self.no_network, socket=self.no_network), capture=capture)
            self.assertTrue(transport.exchange(b'synthetic-request', deadline=5) == b'synthetic-business')
            with self.assertRaises(EOFError) as caught:
                transport._receive(5, 'RESIDENT')
            self.assertIs(caught.exception, primary)
            self.assertFalse(transport.inflight)
            capture.close()
            events = [json.loads(line) for line in (capture.path / 'events.jsonl').read_text().splitlines()]
            received = [subject.decode_value(e['values'], capture.path) for e in events if e['label'] == 'wire.receive.return']
            self.assertEqual(len(received), 2)
            self.assertTrue(received[0]['frame'] == b'synthetic-heartbeat')
            partial = [subject.decode_value(e['values'], capture.path) for e in events if e['label'] == 'wire.receive.partial']
            self.assertTrue(partial[0]['buffer'] == b'synthetic-partial-frame')
        finally:
            sys.path.remove(str(LOGIN_ROOT))


if __name__ == '__main__':
    unittest.main()
