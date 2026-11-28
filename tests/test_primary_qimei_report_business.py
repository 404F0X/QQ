"""Fixed QQ whole report group MODEL: fake OS/transport, real composition/codecs."""
import base64
from dataclasses import replace
import json
import threading
from types import SimpleNamespace as NS

import pytest
from test_primary_qimei_module_backend import module_fixture
from test_primary_windows_qimei_report import Metadata
from qq_nt_replica.primary_qimei_application import APPLICATION_OWNER
from qq_nt_replica.primary_qimei_cache import QimeiCacheCodec, QimeiCacheConstants, _cbc
from qq_nt_replica.primary_qimei_dispatch import CarrierOutcome
from qq_nt_replica.primary_qimei_report_business import conditional_kind13, report_string, report_payload
from qq_nt_replica.primary_qimei_report_sources import QimeiReportValues
from qq_nt_replica.primary_qimei_reply import parse_reply
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary


def fields(payload):
    decoded = parse_reply(payload, count=3)
    assert decoded.accepted
    return tuple(decoded.slots[i].data for i in range(3))


def test_full_six_strings_dil_and_nul_source_json():
    empty = (b'',) * 6
    assert report_string(QimeiReportValues(empty, False)) == b''
    assert report_string(QimeiReportValues(empty, True)) == b'{"1":"","2":"","3":"","4":"","5":"","6":""}'
    strings = (b'a\0"', b'a\0\x01', b'\xff', b'/\n', b'', b'last')
    assert report_string(QimeiReportValues(strings, True)) == b'{"1":"a\0"","2":"a","3":"\xff","4":"\\/\\n","5":"","6":"last"}'
    assert report_string(QimeiReportValues(strings, False)) == b''


@pytest.mark.parametrize('force', [False, True])
@pytest.mark.parametrize('length', [1, 15, 16, 17, 43, 256])
def test_raw_body_exact_inner_aes_pkcs7_ascii_keys(force, length):
    value = b'x' * length
    payload = report_payload(value, force)
    version, encoded, mode = fields(payload)
    assert version == b'1.0' and mode == (b'2' if force else b'1')
    cipher = base64.b64decode(encoded, validate=True)
    assert len(cipher) == 16 * (length // 16 + 1)
    plain = _cbc(cipher, b'18845cac36195f4a', b'2a77ed84a51b0b2e', decrypt=True)
    padding = 16 - length % 16
    assert plain == value + bytes([padding]) * padding
    assert report_payload(b'', True).hex() == '0a03312e3012001a0132'


def fixture(monkeypatch, outcome='success', entries=((b'123', 16),)):
    m, inputs, api, ios, entered, leave = module_fixture(opens=(44,))
    # The existing generic MODEL fixture uses b'owner'; bind its producer and SDK
    # to the real fixed QQ owner before canonical application initialization.
    m.pipeline.request_producer.owner = APPLICATION_OWNER
    inputs = replace(inputs, appid=APPLICATION_OWNER)
    m.initialize(inputs)
    assert m.tasks[0].done.wait(3) and not m.tasks[0].errors and m.tasks[0].result == 1
    md = Metadata(entries)
    io_type, original_init = type(ios[0]), type(ios[0]).__init__
    def initialize(io, app):
        original_init(io, app)
        io.report_sources = md.sources()
    monkeypatch.setattr(io_type, '__init__', initialize)
    original_close = io_type.close
    def close(io):
        if hasattr(io, 'report_sources'):
            io.report_sources.observations.close()
        original_close(io)
    monkeypatch.setattr(io_type, 'close', close)
    codec = object.__new__(QimeiCacheCodec)
    codec.constants = QimeiCacheConstants(b'MDL!', bytes(4))
    context = NS(produce=lambda obs: b'model-cache-context')
    current, refreshes, calls = {'wire': b'', 'outcome': outcome}, [], []
    dependencies = m.creator_io.settings_dependencies
    dependencies.update(read_file=lambda path: refreshes.append(path) or current['wire'],
                        codec=codec, context_producer=context, observations=object())
    def flags(value):
        record = bytearray(m.settings.record)
        record[0x31 + 14 * 4:0x31 + 15 * 4] = value.to_bytes(4, 'little')
        current['wire'] = codec.encode_payload(bytes(record), context=context.produce(None)).value
        m.settings.dirty = 1
    payloads = {}
    original_dispatch = m.dispatch.dispatch
    def dispatch(owner, kind, payload, completion, context, **kwargs):
        assert owner == APPLICATION_OWNER and kind == 13 and context is None
        payloads[m.dispatch.state.sequence & 0xffffffff] = payload
        return original_dispatch(owner, kind, payload, completion, context, **kwargs)
    monkeypatch.setattr(m.dispatch, 'dispatch', dispatch)
    def perform(io, http):
        assert io.thread == threading.get_native_id()
        assert len(m.dispatch.state.pending) == 1
        seq, record = next(iter(m.dispatch.state.pending.items()))
        assert record.context is None and record.prepared.owner == APPLICATION_OWNER
        assert record.prepared.logical_mode == 13
        wire = record.prepared.transport_request
        outer = json.loads(http.body)
        assert outer['cpt'] == '2' and 'ky' not in outer
        plain = _cbc(base64.b64decode(outer['pms']), wire.key, wire.iv, decrypt=True)
        envelope = plain[:-plain[-1]]
        assert envelope[:5] == b'\x03' + m.pipeline.configuration.key_id.to_bytes(4, 'big')
        key = m.pipeline.configuration.key_override or m.pipeline.envelope.fallback_key
        inner = _cbc(envelope[5:], key, m.pipeline.envelope.iv, decrypt=True)
        decoded = parse_reply(inner[:-inner[-1]], count=2)
        assert decoded.accepted and decoded.slots[1].data == payloads[seq]
        version, encoded, mode = fields(payloads[seq])
        if encoded:
            report = _cbc(base64.b64decode(encoded), b'18845cac36195f4a', b'2a77ed84a51b0b2e', decrypt=True)
            assert report[:-report[-1]] == report_string(QimeiReportValues((b'', b'', b'123&2026-01-01 00:00:00', b'', b'', b''), True))
        calls.append((seq, payloads[seq], io, http.body))
        mode = current['outcome']
        if mode == 'raise':
            raise OSError('controlled report carrier failure')
        if mode == 'net':
            return CarrierOutcome(b'', 503)
        if mode == 'local':
            return CarrierOutcome(b'bad-json', 0)
        if mode == 'server':
            return CarrierOutcome(b'{"code":"7","data":""}', 0)
        if mode == 'cipher':
            return CarrierOutcome(b'{"code":"0","data":"AA=="}', 0)
        if mode == 'missingkey':
            record.prepared = replace(record.prepared, transport_request=replace(wire, key=b''))
        payload = b'context0 does not invoke a derived reply parser'
        padding = 16 - len(payload) % 16
        cipher = _cbc(payload + bytes([padding]) * padding, wire.key, wire.iv)
        return CarrierOutcome(json.dumps({'code': '0', 'data': base64.b64encode(cipher).decode()}).encode(), 0)
    monkeypatch.setattr(io_type, 'perform', perform)
    return m, inputs, ios, md, flags, current, refreshes, calls


def wait(task):
    assert task.done.wait(5)
    assert not task.errors, task.errors
    return task.result


@pytest.mark.parametrize('gate', [0, 0xffffffff, 0x80000000, 1, 2, 3])
def test_real_first14_signed_gate_whole_feature(monkeypatch, gate):
    m, inputs, ios, md, flags, current, refreshes, calls = fixture(monkeypatch)
    baseline = m.startup.main.get(1), m.startup.identity1.get(1)
    expected_settings = bytearray(m.settings.record)
    expected_settings[0x31 + 14 * 4:0x31 + 15 * 4] = gate.to_bytes(4, 'little')
    flags(gate)
    try:
        result = wait(m.request_report(inputs.appid))
        assert len(refreshes) >= 1
        if gate in (0, 0xffffffff, 0x80000000):
            assert result is None and not md.calls and not calls
            assert m.dispatch.state.sequence == 7
        else:
            assert result.result_code == 0 and result.status == 200
            assert result.body == b'context0 does not invoke a derived reply parser'
            assert len(calls) == 1 and calls[0][0] == 7
            assert fields(calls[0][1])[2] == (b'2' if gate == 2 else b'1')
            assert 'CryptGenRandom' in calls[0][2].request_observations.calls
            assert m.dispatch.state.sequence == 8 and not m.dispatch.state.pending
        assert m.request_state.read_mask() == 0
        assert (m.startup.main.get(1), m.startup.identity1.get(1)) == baseline
        assert m.settings.record == expected_settings
        assert all(io.closed for io in ios[1:])
    finally:
        m.close()
    assert not m.bridge._launches and all(io.closed for io in ios)


def test_empty_skip_force_and_provider_absent(monkeypatch):
    m, inputs, ios, md, flags, current, refreshes, calls = fixture(monkeypatch, entries=())
    try:
        flags(1)
        assert wait(m.request_report(inputs.appid)) is None and not calls
        flags(2)
        result = wait(m.request_report(inputs.appid))
        assert result.result_code == 0 and calls[0][1].hex() == '0a03312e3012001a0132'
        assert m.dispatch.state.sequence == 8
        # Missing provider has a real code1 outcome and consumes no sequence.
        result = conditional_kind13(inputs.appid, m.settings, settings_dependencies=m.creator_io.settings_dependencies,
            sources=md.sources(), dispatch=None)
        assert result.result_code == 1 and m.dispatch.state.sequence == 8
        md.port.close()
        assert not m.dispatch.state.pending and m.request_state.read_mask() == 0
    finally:
        m.close()


@pytest.mark.parametrize('mode,code,server', [('net', 8, 0), ('local', 5, 0), ('server', 6, 7), ('cipher', 7, 0), ('missingkey', 2, 0)])
def test_common_errors_sequence_and_no_success_publication(monkeypatch, mode, code, server):
    m, inputs, ios, md, flags, current, refreshes, calls = fixture(monkeypatch, mode)
    try:
        flags(1)
        for unused in range(2):
            result = wait(m.request_report(inputs.appid))
            assert (result.result_code, result.server_code) == (code, server)
            assert not m.dispatch.state.pending and m.request_state.read_mask() == 0
        assert [c[0] for c in calls] == [7, 8] and m.dispatch.state.sequence == 9
        assert not m.startup.main.get(1) and all(io.closed for io in ios[1:])
    finally:
        m.close()


def test_owner_admission_exception_retained_pending_and_cleanup(monkeypatch):
    m, inputs, ios, md, flags, current, refreshes, calls = fixture(monkeypatch, 'raise')
    try:
        flags(1)
        with pytest.raises(QimeiRequestBoundary):
            m.request_report(b'other')
        task = m.request_report(inputs.appid)
        assert task.done.wait(3) and task.phase == 'failed'
        assert len(task.errors) == 1 and str(task.errors[0]) == 'controlled report carrier failure'
        assert m.dispatch.state.pending[7].context is None and ios[-1].closed
        assert not md.port._handles and m.request_state.read_mask() == 0
    finally:
        m.close()
    assert m.closed and len(m.dispatch.state.pending) == 1 and not m.bridge._launches


def test_report_task_drain_backing_and_no_ipc_permission(monkeypatch):
    m, inputs, ios, md, flags, current, refreshes, calls = fixture(monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = type(ios[0]).perform
    def blocked(io, http):
        assert not m.executor._permits_operation(inputs.appid, 'consume')
        assert not m.executor._permits_operation(inputs.appid, 'counter')
        entered.set()
        assert release.wait(5)
        return original(io, http)
    monkeypatch.setattr(type(ios[0]), 'perform', blocked)
    launches = [s['launch'] for s in m.executor._slots]
    try:
        flags(2)
        task = m.request_report(inputs.appid)
        assert entered.wait(3)
        with monkeypatch.context() as patch:
            for launch in launches:
                patch.setattr(launch, 'join', lambda timeout_ms=10000, join=launch.join: join(0))
            with pytest.raises(ExceptionGroup, match='shutdown debt retained'):
                m.close()
        assert not m.closed and m.provider_pair and m.applications and not ios[0].closed
        assert m.schedule.quiescent and m.bridge._launches
        with pytest.raises(QimeiRequestBoundary):
            m.request_report(inputs.appid)
        release.set()
        assert wait(task).result_code == 0
        m.close()
        assert not m.bridge._launches and not m.dispatch.state.pending
        assert all(l.joined and l.retired and not l.thread.is_alive() for l in launches)
    finally:
        release.set()
        if not m.closed:
            m.close()
