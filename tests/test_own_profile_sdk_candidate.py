"""CURRENT phase wiring with existing model SDK; no native producers or network."""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch
import runpy

import run_own_profile_sdk_candidate as candidate
from test_primary_own_bootstrap_sdk_session import auth, ModelOwner, Socket, Inputs
from test_primary_own_sdk_request import Capi
from qq_nt_replica.primary_logger import _String
from qq_nt_replica.primary_worker_consumer import DeviceRecord


def test_current_phase_profile_reaches_real_service_options_and_frame(auth, tmp_path):
    material, profile = auth
    owner, channel, cold = ModelOwner(), Socket(), Inputs()
    owner.signer = owner._signer
    owner.get_own_device_value = Mock(return_value=b'MODEL-device-value')
    runtime = owner.signer.runtime
    identity = material.provenance.device.guid.hex().encode('ascii')
    metadata = {runtime.image_base + 0x67516B0 + offset: value for offset, value in
        ((0x58, b''), (0x70, identity), (0xA0, b'MODEL-version'))}
    metadata[runtime.image_base + 0x6751840 + 24] = b''
    read_string = _String.read

    def read(actual_runtime, address):
        if actual_runtime is runtime and address in metadata:
            return NS(value=lambda: metadata[address])
        return read_string(actual_runtime, address)

    environment = NS(time_seconds=lambda: 1, random_bytes=lambda n: b'1234', close=Mock())
    mix, port = NS(close=Mock()), NS(ansi_to_utf8=lambda value: value, close=Mock())
    collector = NS(collect=Mock(return_value=(DeviceRecord(7, b'MODEL-record'),) * 137), close=Mock())
    capture = NS(available=True, dto_types=set(), record=Mock(), exception=Mock())
    original_create = owner.create_own_device_request

    def create(records):
        channel.original = original_create(records)
        return channel.original

    owner.create_own_device_request = create
    patches = {
        'primary_windows_signer.open_windows_signer': lambda **kwargs: owner,
        'primary_device_value_producer.WindowsDeviceValueEnvironment': lambda: environment,
        'primary_device_mix_producer.WindowsDeviceMixPort': lambda: mix,
        'primary_device_mix_producer.produce_device_mix': lambda port: None,
        'primary_request_capi.SystemRequestCapi': Capi,
        'primary_windows_device_collection.WindowsDeviceCollectionObservations': lambda: port,
        'primary_windows_device_collection.OwnIdentifierStores': lambda *a, **kw: object(),
        'primary_windows_device_collection.WindowsOwnIdentifierRegistry': lambda: object(),
        'primary_device_record_collector.IndependentDeviceRecordCollector': lambda *a, **kw: collector,
        'primary_windows_cold12_inputs.WindowsCold12Inputs': lambda: cold,
    }
    phase = candidate.CurrentProfilePhase(material, profile,
        policy={'session_id': 'MODEL-current', 'state_id': 'MODEL_current', 'ping_index': channel.index},
        capture=capture, bridge_path=Path('MODEL-bridge'), worker_bridge_path=Path('MODEL-worker'),
        storage_root=tmp_path, loader_profile='10.0.26100.9974', connector=lambda **kw: channel,
        deadline=candidate.time.monotonic() + 30)
    with ExitStack() as stack:
        for name, value in patches.items():
            stack.enter_context(patch('qq_nt_replica.' + name, value))
        stack.enter_context(patch.object(_String, 'read', side_effect=read))
        result = phase.run()
        binding = phase.session._binding
        assert binding.appid_service.dword_2c8 == profile.sub_app_id
        assert binding.appid_service.appid_string == str(profile.sub_app_id)
        assert int.from_bytes(channel.outbound_plain[8:12], 'big') == profile.sub_app_id
        assert (result.outcome, result.stage, result.code) == ('failed', 'sdk_status', 2000)
        assert len(owner.signs) == 1  # Negative reply never opens subsequent SIGN.
        assert any(call.args[0] == 'own_bootstrap.subsequent_sign_skipped'
            for call in capture.record.call_args_list)
        phase.close()
    assert channel.closed == owner.closes == cold.closes == 1
    assert not phase.resources and phase.owner is phase.session is phase.capi is None
    for resource in (environment, mix, port, collector):
        resource.close.assert_called_once_with()


def test_reconstruction_reads_explicit_capture_without_historical_rebinding(tmp_path):
    import hashlib
    import json
    import sys
    from types import ModuleType
    root = tmp_path / 'current-capture'
    root.mkdir()
    events = b'{}\n'
    (root / 'events.jsonl').write_bytes(events)
    (root / 'blob-00001-0001.bin').write_bytes(b'MODEL-explicit-current-bytes')
    document = {'login_entry': {'path': 'MODEL-login-entry'}, 'capture_root': str(root),
        'events_sha256': hashlib.sha256(events).hexdigest()}
    Q, Ticket, G = ModuleType('Q'), ModuleType('T'), NS()
    reconstruct = Mock(side_effect=lambda saved, manifest, q, ticket, g, reader:
        (reader('blob-00001-0001.bin'), (q, ticket, g)))
    with patch.dict(sys.modules, independent_qr_login=Q, independent_login_ticket_exchange=Ticket), \
            patch.object(runpy, 'run_path', return_value={'load_api': lambda: G}), \
            patch.object(candidate.sys, 'modules', {key: value for key, value in sys.modules.items()
                if key != 'qq_nt_replica' and not key.startswith('qq_nt_replica.')}):
        result = candidate.reconstruct_inputs(document, {'reconstruct': reconstruct})
    assert result == (b'MODEL-explicit-current-bytes', (Q, Ticket, G))
    reconstruct.assert_called_once()
    assert reconstruct.call_args.args[:2] == ([json.loads(events)], document)
