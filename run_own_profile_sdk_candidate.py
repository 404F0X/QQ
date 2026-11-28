"""CURRENT profile-bound Own SDK candidate; Native execution needs separate GO.

The channel/phase is promoted from the immutable historical preparation driver.
DTO reconstruction and transaction orchestration remain imported dependencies.
No credentials or default captured materials are included in this entry.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import runpy
import sys
import time

ROOT = Path(__file__).resolve().parent
RETAINED = []


class CapturedChannel:
    """Observe existing carrier chunks; no framing, SIGN or routing here."""
    def __init__(self, channel, capture):
        self.channel, self.capture = channel, capture

    def _claim_transport(self):
        return self.channel._claim_transport()

    def send(self, data):
        self.capture.record('own_bootstrap.send_attempt', data=data)
        if not self.capture.available:
            raise RuntimeError('OWN_PREPARATION_CAPTURE_UNAVAILABLE')
        result = self.channel.send(data)
        self.capture.record('own_bootstrap.send_return', count=result)
        return result

    def receive(self, *, timeout):
        data = self.channel.receive(timeout=timeout)
        if data is not None:
            self.capture.record('own_bootstrap.received_chunk', data=data)
            if not self.capture.available:
                raise RuntimeError('OWN_PREPARATION_CAPTURE_UNAVAILABLE')
        return data

    def close(self):
        return self.channel.close()


class CurrentProfilePhase:
    def __init__(self, material, profile, *, policy, capture, **paths):
        self.material, self.profile = material, profile
        self.policy, self.capture, self.paths = policy, capture, paths
        self.owner = self.session = self.capi = None
        self.resources = []
        self.diagnostic_stage = 'own_preparation_factory'
        self.started = False

    def run(self):
        if self.started:
            raise RuntimeError('OWN_PREPARATION_SINGLE_USE')
        self.started = True
        from qq_nt_replica.primary_authenticated_sdk_session import OwnBootstrapSdkSession, packet_inputs
        from qq_nt_replica.primary_windows_signer import open_windows_signer
        from qq_nt_replica.primary_windows_signer_setup import BUSINESS_QUA
        from qq_nt_replica.primary_windows_ownimage import OwnImageModuleSpec
        from qq_nt_replica.primary_device_value_producer import WindowsDeviceValueEnvironment
        from qq_nt_replica.primary_device_mix_producer import WindowsDeviceMixPort, produce_device_mix
        from qq_nt_replica.primary_request_capi import SystemRequestCapi
        from qq_nt_replica.primary_logger import _String
        from qq_nt_replica.primary_device_record_collector import IndependentDeviceRecordCollector
        from qq_nt_replica.primary_windows_device_collection import (
            WindowsDeviceCollectionObservations, OwnIdentifierStores, WindowsOwnIdentifierRegistry)
        from qq_nt_replica.primary_windows_wmi_session import OwnedWmiSession
        from qq_nt_replica.primary_source_cold12_binding import DisabledEnvironment
        from qq_nt_replica.primary_windows_cold12_inputs import WindowsCold12Inputs

        context, unused_profile = packet_inputs(self.material, self.profile)
        identity = context.guid.hex().encode('ascii')
        self.diagnostic_stage = 'own_business_factory'
        try:
            self.owner = open_windows_signer(
                bridge_path=self.paths['bridge_path'], worker_bridge_path=self.paths['worker_bridge_path'],
                storage_root=self.paths['storage_root'], host_profile_string=BUSINESS_QUA,
                primary_backend='direct',
                ownimage_module=OwnImageModuleSpec.for_loader_profile(self.paths['loader_profile']),
                own_business_config={'uin': self.material.uin, 'machine_id': identity})
        except BaseException as error:
            self.owner = getattr(error, 'independent_windows_owner', None)
            raise
        runtime = self.owner.signer.runtime
        fields = {key: _String.read(runtime, runtime.image_base + 0x67516B0 + offset).value()
                  for key, offset in ((0x30, 0x58), (0x48, 0x70), (0x78, 0xA0))}
        if self.owner.own_business_identity() != (self.material.uin, identity) or fields[0x48] != identity:
            raise RuntimeError('OWN_PREPARATION_ACTUAL_IDENTITY')
        # Observe the existing cold getter domain; never clear an initialized value.
        if fields[0x30] != b'' or not fields[0x78]:
            raise RuntimeError('OWN_PREPARATION_UNEXPECTED_COLD_METADATA')
        self.diagnostic_stage = 'own_records_and_request_inputs'
        environment = WindowsDeviceValueEnvironment(); self.resources.append(environment)
        value = self.owner.get_own_device_value()
        mix = WindowsDeviceMixPort(); self.resources.append(mix)
        state17 = produce_device_mix(mix)
        self.capi = SystemRequestCapi()
        port = WindowsDeviceCollectionObservations(); self.resources.append(port)
        stores = OwnIdentifierStores(self.paths['storage_root'] / 'collector', self.policy['state_id'],
            registry=WindowsOwnIdentifierRegistry())
        collector = IndependentDeviceRecordCollector(port, stores, sdk_fields=fields,
            wmi_factory=OwnedWmiSession.open)
        self.resources.append(collector)
        records = collector.collect(version=fields[0x78], device_value=value, ansi_to_utf8=port.ansi_to_utf8)
        if len(records) != 137:
            raise RuntimeError('OWN_PREPARATION_REAL_RECORD_COUNT')
        cold_inputs = WindowsCold12Inputs(); self.resources.append(cold_inputs)
        def connector(*, timeout):
            return CapturedChannel(self.paths['connector'](timeout=timeout), self.capture)
        self.session = OwnBootstrapSdkSession(self.material, self.profile, owner=self.owner,
            records=records, session_id=self.policy['session_id'], request_capi=self.capi,
            clock_inputs={'wall_seconds': environment.time_seconds,
                'monotonic_ns': time.perf_counter_ns, 'clock_ns': time.perf_counter_ns},
            random_environment=environment, state17_owner=lambda: state17,
            cold12_inputs=cold_inputs, own_cold12_inputs=False,
            appid_override=None, env_setting=DisabledEnvironment(), connector=connector,
            ping_index=self.policy['ping_index'], deadline=self.paths['deadline'], own_owner=False,
            bind_profile_appid=True)
        self.material = self.profile = None
        self.diagnostic_stage = 'own_bootstrap_transaction'
        before = _String.read(runtime, runtime.image_base + 0x6751840 + 24).value()
        self.capture.record('own_bootstrap.cache_before_transaction', value=before)
        result = self.session.run()
        # Persist achieved reply facts before any optional observation can fail.
        self.capture.record('own_bootstrap.completion_before_observation',
            outcome=result.outcome, stage=result.stage, code=result.code,
            cache_updated=result.cache_updated, publication_present=result.publication is not None)
        encoded = self.session._encoded
        if encoded is not None:
            self.capture.dto_types.add(type(encoded.signature_result))
            self.capture.record('own_bootstrap.original_request_SIGNonce',
                signature_result=encoded.signature_result, frame=encoded.frame,
                wire_sequence=encoded.wire_sequence, sdk_sequence=encoded.sdk_sequence)
        if not (result.outcome == 'processed' and result.stage == 'publication' and
                result.code is None and result.publication is not None and result.cache_updated):
            self.capture.record('own_bootstrap.subsequent_sign_skipped',
                reason='positive_publication_conditions_not_met', consumption='UNKNOWN')
            return result
        self.diagnostic_stage = 'own_bootstrap_subsequent_sign_observation'
        self.capture.dto_types.add(type(result.publication))
        self.capture.record('own_bootstrap.achieved_publication', publication=result.publication)
        selection, digests, order = [], [], []
        returned, followup, after = False, None, None
        try:
            after = _String.read(runtime, runtime.image_base + 0x6751840 + 24).value()
            self.capture.record('own_bootstrap.cache_after_publication', value=after)
            if not after:
                self.capture.record('own_bootstrap.subsequent_sign_skipped',
                    reason='actual_cache_empty', consumption='UNKNOWN')
                return result
            if not self.capture.available:
                raise RuntimeError('OWN_PREPARATION_CAPTURE_UNAVAILABLE')
            import qq_nt_replica.primary_response_refresh as refresh
            import qq_nt_replica.primary_signer as signer_module
            original_select = refresh.signing_value
            original_digest = signer_module.request_context_digest
            def select(*args, **kwargs):
                value = original_select(*args, **kwargs)
                selection.append(value); order.append(('selected', value))
                return value
            def digest(value, context, payload):
                digests.append(value); order.append(('digest_input', value, context, payload))
                return original_digest(value, context, payload)
            refresh.signing_value = select
            signer_module.request_context_digest = digest
            try:
                original = self.session._original
                self.capture.record('own_bootstrap.subsequent_sign_enter',
                    command=original.command, body=original.body)
                # One deliberate local SIGN; no new SDK request, retry or send.
                followup = self.owner.sign_result(original.command, original.body)
                returned = True
                self.capture.dto_types.add(type(followup))
            finally:
                refresh.signing_value = original_select
                signer_module.request_context_digest = original_digest
        except BaseException as error:
            self.capture.exception('own_bootstrap.subsequent_sign_observation_failure', error)
            raise
        finally:
            observed = (returned and after != before and bool(selection) and bool(digests)
                and selection[-1] == after and digests[-1] == after and self.capture.available)
            self.capture.record('own_bootstrap.subsequent_sign_evidence',
                before=before, installed=after, selections=selection, digest_inputs=digests,
                ordered_calls=order, sign_returned=returned, signature_result=followup,
                consumption='OBSERVED' if observed else 'UNKNOWN',
                distinction='subsequent local SIGN; original request signature recorded separately')
        return result

    def close(self):
        # Stop at failed cleanup, retaining the actual backing for diagnosis.
        self.diagnostic_stage = 'own_preparation_close'
        if self.session is not None:
            self.session.close()
            self.session = None
        if self.owner is not None:
            self.owner.close()
            self.owner = None
        while self.resources:
            self.resources[-1].close()
            self.resources.pop()
        # SystemRequestCapi has no close API. Its provider handles are released by
        # existing request operations; its DLL mapping lives until this process exits.
        self.capi = self.material = self.profile = None


def require(condition):
    if not condition:
        raise ValueError('CURRENT_SDK_INPUT_OR_SOURCE_BINDING')


def checked_bytes(path, digest):
    raw = Path(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest)
    return raw


def load_inputs(path):
    """Explicit provenance/configuration, never an Auth validity certificate."""
    document = json.loads(Path(path).read_bytes())
    checked_bytes(ROOT / 'source-manifest.json', document['source_manifest_sha256'])
    required = {'run_own_profile_sdk_candidate.py', 'signature_core.py',
        'run_authenticated_sdk_session.py', 'trusted_login_capture.py'}
    require(set(document['current_files']) == required)
    for name in required:
        checked_bytes(ROOT / name, document['current_files'][name])
    for name in ('dto_helper', 'login_entry'):
        row = document[name]
        checked_bytes(row['path'], row['sha256'])
    timeout = document['sdk_timeout']
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 120)
    policy = document['policy']
    require(set(policy) == {'session_id', 'state_id', 'ping_index'})
    require(all(type(policy[key]) is str and policy[key] and '\0' not in policy[key]
        for key in ('session_id', 'state_id')))
    require(type(policy['ping_index']) is int and 0 <= policy['ping_index'] < 1 << 32)
    return document


def reconstruct_inputs(document, helpers):
    """Use the existing exact DTO schema with an explicit current blob reader.

    The helper's historical T is used only for its lexical basename check when
    reader is supplied. No bytes are read there and no helper globals change.
    Event 72 correlates the saved attempt; it never represents a live callback.
    """
    require(not any(n == 'qq_nt_replica' or n.startswith('qq_nt_replica.') for n in sys.modules))
    G = runpy.run_path(document['login_entry']['path'])['load_api']()
    Q, Ticket = sys.modules['independent_qr_login'], sys.modules['independent_login_ticket_exchange']
    capture_root = Path(document['capture_root']).resolve()
    raw = checked_bytes(capture_root / 'events.jsonl', document['events_sha256'])
    saved = [json.loads(line) for line in raw.decode('utf-8').splitlines()]

    def reader(name):
        path = (capture_root / name).resolve()
        require(path.parent == capture_root)
        return path.read_bytes()

    return helpers['reconstruct'](saved, document, Q, Ticket, G, reader=reader)


def packet_admission(material, profile):
    from qq_nt_replica import primary_authenticated_sdk_session as sdk
    require(Path(sdk.__file__).resolve() == ROOT / 'src/qq_nt_replica/primary_authenticated_sdk_session.py')
    return sdk.packet_inputs(material, profile)


def run_candidate(inputs, *, execute=False):
    """Pure admission by default; an explicit execute requests one transaction.

    Callers must separately obtain execution authorization. Local admission
    cannot establish current server validity, cross-build or Native eligibility.
    """
    require(type(execute) is bool)
    document = load_inputs(inputs)
    helpers = runpy.run_path(document['dto_helper']['path'])
    material, profile = reconstruct_inputs(document, helpers)
    core_api = runpy.run_path(str(ROOT / 'signature_core.py'))
    if not execute:
        core = core_api['load_core']()
        try:
            with core.activate():
                packet_admission(material, profile)
        finally:
            core.close()
        return {'status': 'CURRENT_TYPED_ADMISSION_ONLY', 'actual_sdk': 'NOT_RUN',
            'current_validity': 'UNKNOWN'}

    entry = runpy.run_path(str(ROOT / 'run_authenticated_sdk_session.py'))
    capture_api = runpy.run_path(str(ROOT / 'trusted_login_capture.py'))
    storage = Path(document['storage_root']).resolve()
    require(not storage.exists())
    capture = capture_api['LoginCapture'](document['output_capture_root'],
        login_root=Path(document['login_entry']['path']).resolve().parent.parent,
        inputs=inputs, parameters={'contract': 'SDK-CURRENT-PROFILE-CALLER/a1',
            'source_capture': str(Path(document['capture_root']).resolve()),
            'current_validity': 'UNKNOWN', 'bind_profile_appid': True, **document['policy']})
    try:
        with entry['_private_output'](capture.log_path):
            require(capture.available)
            network = entry['_NetworkDomain'](time.monotonic() + document['sdk_timeout'])
            require(network.login is None)
            sys.addaudithook(network.audit)
            entry['_prepare_storage_root'](storage)
            paths = {key: Path(document[key]) for key in ('bridge_path', 'worker_bridge_path')}
            paths.update(storage_root=storage / 'sdk', loader_profile=document['loader_profile'])
            result = helpers['run_sdk'](material, profile, load_core=core_api['load_core'],
                admit=packet_admission, phase_factory=CurrentProfilePhase, network=network,
                capture=capture, policy=document['policy'], paths=paths)
        return {'status': 'CURRENT_SDK_COMPLETION_RETURNED', 'outcome': result.outcome,
            'stage': result.stage, 'code': result.code, 'cache_updated': result.cache_updated,
            'current_validity': 'UNKNOWN', 'capture_available': capture.available,
            'capture_directory': str(capture.path)}
    except BaseException as error:
        capture.exception('current.entry_failure', error)
        raise
    finally:
        if helpers['RETAINED']:
            RETAINED.append(helpers)
        capture.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True,
        help='explicit private input/source binding JSON; no sample or default material')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--admit', action='store_true', help='pure typed admission; no Native or network')
    mode.add_argument('--run', action='store_true', help='one actual SDK transaction; requires separate GO')
    options = parser.parse_args(argv)
    try:
        result = run_candidate(options.inputs, execute=options.run)
        print(json.dumps(result))
        return 1 if result.get('outcome') == 'failed' else 0
    except BaseException as error:
        print(json.dumps({'status': 'CURRENT_SDK_NOT_COMPLETED', 'error_type': type(error).__name__,
            'current_validity': 'UNKNOWN', 'cleanup_debt': bool(RETAINED)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

