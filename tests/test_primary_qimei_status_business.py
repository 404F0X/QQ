"""Whole status-group MODEL: real business/codec/pending; controlled IO only."""
import base64
import json
import threading
from types import SimpleNamespace as NS

import pytest
from test_primary_qimei_module_backend import module_fixture
from qq_nt_replica.primary_qimei_cache import QimeiCacheCodec, QimeiCacheConstants, _cbc
from qq_nt_replica.primary_qimei_dispatch import CarrierOutcome
from qq_nt_replica.primary_qimei_reply import parse_reply
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
from qq_nt_replica.primary_windows_qimei_schedule import NativeQimeiScheduleAPI


def cells4(payload, ip):
    # Decode outgoing varints independently: the Source reply scanner projects
    # wire0 to DWORD and must not truncate this request's timestamp64 assertion.
    cursor, fields = 0, {}
    def varint():
        nonlocal cursor
        value, shift = 0, 0
        while True:
            byte = payload[cursor]; cursor += 1
            value |= (byte & 127) << shift
            if byte < 128: return value
            shift += 7
    while cursor < len(payload):
        key, value = varint(), varint()
        assert key >> 3 not in fields
        if key & 7 == 2:
            end = cursor + value
            value = payload[cursor:end]; cursor = end
        else:
            assert key & 7 == 0
        fields[key >> 3] = value
    assert set(fields) == ({1, 2, 3, 4} if ip else {1, 2, 4})
    # Source empty String assignment leaves backing NULL and omits the cell.
    return [fields[1], fields[2], fields.get(3, b''), fields[4]]


def fixture(monkeypatch, outcome='success', ip=b'198.51.100.7'):
    m, inputs, api, ios, entered, leave = module_fixture(opens=(44,))
    m.initialize(inputs)
    assert m.tasks[0].done.wait(3) and not m.tasks[0].errors
    assert m.tasks[0].result == 1 and not entered.is_set()
    adapter = m.creator_io.adapter.state
    adapter.ip = ip
    calls, refreshes = [], []
    # An explicitly controlled cache constant set is sufficient for this MODEL
    # round-trip; no fixed DLL read or Original cache compatibility is claimed.
    codec = object.__new__(QimeiCacheCodec)
    codec.constants = QimeiCacheConstants(b'MDL!', bytes(4))
    context = NS(produce=lambda obs: b'model-cache-context')
    current = {'wire': b'', 'outcome': outcome}
    def read_file(path):
        refreshes.append(path)
        return current['wire']
    dependencies = m.creator_io.settings_dependencies
    dependencies.update(read_file=read_file, codec=codec, context_producer=context,
                        observations=object())
    def flags(value):
        record = bytearray(m.settings.record)
        record[0x31 + 13 * 4:0x31 + 14 * 4] = value.to_bytes(4, 'little')
        current['wire'] = codec.encode_payload(bytes(record), context=context.produce(None)).value
        m.settings.dirty = 1
    payloads = {}
    original_dispatch = m.dispatch.dispatch
    def dispatch(owner, kind, payload, completion, context, **kwargs):
        payloads[m.dispatch.state.sequence & 0xffffffff] = payload
        return original_dispatch(owner, kind, payload, completion, context, **kwargs)
    monkeypatch.setattr(m.dispatch, 'dispatch', dispatch)
    def perform(io, http):
        assert io.thread == threading.get_native_id()
        pending = tuple(m.dispatch.state.pending.items())
        assert len(pending) == 1
        seq, record = pending[0]
        request = record.context
        assert record.prepared.owner == request.owner == inputs.appid
        assert record.prepared.logical_mode == request.kind == 7
        assert request.dispatch is m.provider and request.module_state is m.request_state
        assert request.io is io and io.adapter.state is adapter
        wire = record.prepared.transport_request
        outer = json.loads(http.body)
        plain = _cbc(base64.b64decode(outer['pms']), wire.key, wire.iv, decrypt=True)
        envelope = plain[:-plain[-1]]
        assert envelope[:5] == b'\x03' + m.pipeline.configuration.key_id.to_bytes(4, 'big')
        key = m.pipeline.configuration.key_override or m.pipeline.envelope.fallback_key
        inner = _cbc(envelope[5:], key, m.pipeline.envelope.iv, decrypt=True)
        decoded = parse_reply(inner[:-inner[-1]], count=2)
        assert decoded.accepted and decoded.slots[1].data == payloads[seq]
        cells = cells4(decoded.slots[1].data, ip)
        calls.append((seq, request, cells, http.body, io))
        mode = current['outcome']
        if mode == 'raise':
            raise OSError('controlled carrier failure')
        if mode == 'net':
            return CarrierOutcome(b'', 503)
        if mode == 'local':
            return CarrierOutcome(b'bad-json', 0)
        if mode == 'server':
            return CarrierOutcome(b'{"code":"7","data":""}', 0)
        payload = {'empty': b'', 'malformed': b'\x0b'}.get(mode, b'\x08\x01')
        padding = bytes([16 - len(payload) % 16]) * (16 - len(payload) % 16)
        cipher = _cbc(payload + padding, wire.key, wire.iv)
        return CarrierOutcome(json.dumps({'code': '0', 'data': base64.b64encode(cipher).decode()}).encode(), 0)
    monkeypatch.setattr(type(ios[0]), 'perform', perform)
    return m, inputs, api, ios, calls, refreshes, flags, current


def wait(task):
    assert task.done.wait(5), 'controlled status task did not terminate'
    assert not task.errors, task.errors
    return task.result


@pytest.mark.parametrize('subtype,status,text', [(1, 0xffffffff, b'-1'), (2, None, b'0'), (3, 2, b'2')])
def test_all_subtypes_refresh_gate_and_exact_real_dispatch(monkeypatch, subtype, status, text):
    m, inputs, api, ios, calls, refreshes, flags, current = fixture(monkeypatch)
    app = m.applications[inputs.appid]
    initial = bytes(m.startup.main.get(1)), bytes(m.startup.identity1.get(1))
    initial_settings = bytes(m.settings.record)
    try:
        adapter_reads = []
        original_refresh = m.creator_io.adapter.refresh
        def refresh_adapter():
            adapter_reads.append(threading.get_native_id())
            return original_refresh()
        monkeypatch.setattr(m.creator_io.adapter, 'refresh', refresh_adapter)
        # Source clock implementation with controlled API, not a wall-clock guess.
        calendar_calls = []
        def calendar(name, result, types, *args):
            import ctypes as C
            calendar_calls.append(name)
            if name == 'GetLocalTime':
                p = C.cast(args[0], C.POINTER(C.c_uint16))
                for i, value in enumerate((2026, 11, 6, 28, 9, 8, 7, 654)):
                    p[i] = value
                return None, 0
            assert name == '_mktime64'
            tm = C.cast(args[0], C.POINTER(C.c_int32))
            assert tuple(tm[:9]) == (7, 8, 9, 28, 10, 126, 0, 0, 0)
            return 1234567890, 0
        clock_api = NativeQimeiScheduleAPI(lambda: None)
        monkeypatch.setattr(clock_api, 'call', calendar)
        monkeypatch.setattr(api, 'timestamp_ms', clock_api.timestamp_ms)
        seq = m.dispatch.state.sequence
        # Other bits enabled: wrong subtype must cause no clock/selector/send.
        flags(7 ^ (1 << (subtype - 1)))
        task = m.request_status(inputs.appid, subtype, status)
        assert wait(task) is None and task.application is app
        assert m.dispatch.state.sequence == seq and not calls
        assert m.pipeline.material_producer._backend is None
        assert not calendar_calls
        assert not adapter_reads
        assert len(refreshes) == 1
        flags(1 << (subtype - 1))
        result = wait(m.request_status(inputs.appid, subtype, status))
        assert result.success and not result.error
        assert calendar_calls == ['GetLocalTime', '_mktime64'] * 4
        assert adapter_reads  # Payload and real material share this same adapter.
        assert len(refreshes) == 2 and len(calls) == 1
        assert m.dispatch.state.sequence == seq + 1 and not m.dispatch.state.pending
        seq_seen, sent, cells, body, io = calls[0]
        assert seq_seen == seq and sent is result and io.closed
        assert cells == [subtype, 1234567890654, b'198.51.100.7', text]
        assert m.request_state.read_mask() == 1 << 7
        assert m.pipeline.material_producer._backend is not None and json.loads(body)
        assert 'CryptGenRandom' in io.request_observations.calls
        assert (m.startup.main.get(1), m.startup.identity1.get(1)) == initial
        # Refresh changes only the controlled FIRST flag13, never kind7 response.
        expected = bytearray(initial_settings)
        expected[0x31 + 13 * 4:0x31 + 14 * 4] = (1 << (subtype - 1)).to_bytes(4, 'little')
        assert m.settings.record == expected
    finally:
        m.close()
    assert all(io.closed for io in ios) and not m.bridge._launches


@pytest.mark.parametrize('mode,error', [('net', b'{"net":"503"}'), ('server', b'{"sever":"7"}'),
    ('local', b'{"local":"5"}'), ('empty', b''), ('malformed', b'')])
def test_normal_failures_continue_without_publication_or_retry(monkeypatch, mode, error):
    m, inputs, api, ios, calls, refreshes, flags, current = fixture(monkeypatch, mode)
    try:
        flags(7)
        for subtype, status in ((1, 1), (2, None), (3, 0)):
            result = wait(m.request_status(inputs.appid, subtype, status))
            assert not result.success and result.error == error
            assert not m.dispatch.state.pending and m.request_state.read_mask() == 0
        assert len(calls) == 3 and m.dispatch.state.sequence == 10
        assert not m.startup.main.get(1) and all(io.closed for io in ios[1:])
    finally:
        m.close()


def test_same_owner_sequence_config_and_legal_empty_ip(monkeypatch):
    m, inputs, api, ios, calls, refreshes, flags, current = fixture(monkeypatch, ip=b'')
    try:
        flags(7)
        m.pipeline.configuration.key_override = b'k' * 16
        for subtype, status in ((1, 0), (2, None), (3, 0xffffffff)):
            assert wait(m.request_status(inputs.appid, subtype, status)).success
        assert [c[0] for c in calls] == [7, 8, 9]
        assert all(c[2][2] == b'' for c in calls)
        assert len({id(c[1].module_state) for c in calls}) == 1
        assert m.request_state.read_mask() == 128 and not m.dispatch.state.pending
        with pytest.raises(QimeiRequestBoundary): m.request_status(b'other', 1, 0)
        with pytest.raises(QimeiRequestBoundary): m.request_status(inputs.appid, 2, 0)
        assert len(calls) == 3
    finally:
        m.close()
    with pytest.raises(QimeiRequestBoundary): m.request_status(inputs.appid, 1, 0)


def test_carrier_exception_keeps_matching_pending_and_real_error(monkeypatch):
    m, inputs, api, ios, calls, refreshes, flags, current = fixture(monkeypatch, 'raise')
    try:
        flags(7)
        task = m.request_status(inputs.appid, 2)
        assert task.done.wait(3) and task.phase == 'failed'
        assert len(task.errors) == 1 and str(task.errors[0]) == 'controlled carrier failure'
        record = m.dispatch.state.pending[7]
        assert record.context is calls[0][1] and not record.context.success
        assert m.request_state.read_mask() == 0 and ios[-1].closed
    finally:
        m.close()
    assert m.closed and len(m.dispatch.state.pending) == 1
    # Pending is retained diagnostic evidence by the existing dispatcher policy;
    # no carrier handle, worker or active request remains in this MODEL.


def test_status_task_drains_after_failed_join_with_all_backing_retained(monkeypatch):
    m, inputs, api, ios, calls, refreshes, flags, current = fixture(monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = type(ios[0]).perform
    def blocked(io, http):
        entered.set()
        assert release.wait(5)
        assert m.schedule.quiescent and not m.schedule.retired
        return original(io, http)
    monkeypatch.setattr(type(ios[0]), 'perform', blocked)
    launches = [s['launch'] for s in m.executor._slots]
    try:
        flags(4)
        task = m.request_status(inputs.appid, 3, 1)
        assert entered.wait(3)
        with monkeypatch.context() as patch:
            for launch in launches:
                patch.setattr(launch, 'join', lambda timeout_ms=10000, join=launch.join: join(0))
            with pytest.raises(ExceptionGroup, match='shutdown debt retained'): m.close()
        assert not m.closed and m.applications and m.provider_pair and not ios[0].closed
        assert m.schedule.quiescent and not m.schedule.retired and m.bridge._launches
        assert not task.done.is_set() and task.application is m.applications[inputs.appid]
        release.set()
        assert wait(task).success
        m.close()
        assert m.closed and m.schedule.retired and m.bridge.closed and not m.bridge._launches
        assert all(io.closed for io in ios) and not m.dispatch.state.pending
        assert all(l.joined and l.handle_closed and l.retired and not l.thread.is_alive() for l in launches)
    finally:
        release.set()
        if not m.closed: m.close()
