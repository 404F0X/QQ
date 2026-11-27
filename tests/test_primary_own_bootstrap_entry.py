"""Natural entry capture/ONLINE/cleanup with finite login and Own IO dependencies."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys
from types import ModuleType, SimpleNamespace as NS
from unittest.mock import Mock, patch
import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(**fields):
    result = ModuleType('controlled_dependency')
    result.__dict__.update(fields)
    return result


@pytest.mark.parametrize('callbacks,online,expected', [(1, True, None), (0, True, 'ONLINE_REQUIRED'),
    (2, True, 'HANDOFF_ONCE'), (1, False, 'ONLINE_REQUIRED')])
def test_natural_entry_handoff(callbacks, online, expected, tmp_path):
    assert not any(n == 'qq_nt_replica' or n.startswith('qq_nt_replica.') for n in sys.modules)
    spec = importlib.util.spec_from_file_location('controlled_natural_entry', ROOT / 'run_authenticated_sdk_session.py')
    entry = importlib.util.module_from_spec(spec); spec.loader.exec_module(entry)
    login = Path(os.environ['AUTHENTICATED_LOGIN_ROOT'])
    G = sys.modules.get('independent_login_account_registration') or runpy.run_path(str(login / 'G/entry.py'))['load_api']()
    Q, T = sys.modules['independent_qr_login'], sys.modules['independent_login_ticket_exchange']
    device = Q.QrDevice(bytes(range(16)), 'Windows', 'MODEL-device', Q.EcdhKeys.from_private_scalar(1))
    material = T.SessionMaterial(123456789, 'MODEL-uid', b'MODEL-d2', bytes(range(16)),
        b'MODEL-tgt', object(), object(), T.SessionProvenance(None, device, 0))
    profile = Q.DesktopQrProfile.experimental51728()
    order, phases, cores = [], [], []
    login_owner = NS(confirm_uin=Mock(), close=lambda: order.append('login_owner_closed'))

    class Core:
        def __init__(self): self.binding = {}; self.created = []
        @contextlib.contextmanager
        def activate(self):
            previous = set(sys.modules)
            try:
                from qq_nt_replica import primary_windows_signer
                with patch.object(primary_windows_signer, 'open_windows_signer', return_value=login_owner):
                    yield self
            finally:
                for name in list(sys.modules):
                    if name not in previous and (name == 'qq_nt_replica' or name.startswith('qq_nt_replica.')):
                        self.created.append(name)
                        del sys.modules[name]
        def close(self): order.append('core_closed')
    def load_core():
        value = Core(); cores.append(value); return value
    adapter = NS(load_core=load_core, FreshIdentity=NS(create=lambda: NS(guid=bytes(range(16)))),
        plan_factory=lambda *a, **kw: NS(options={}, queue=object()))
    def resident(**kwargs):
        for _ in range(callbacks):
            kwargs['on_authenticated'](material, profile)
        return {'online_observed': online, 'state': 'ONLINE' if online else 'FAILED'}
    def run_session(*args, **kwargs): return resident(**kwargs)
    dependencies = {
        'mode1_binding': module(checked=lambda pin: None, compose_mode1=lambda core: None),
        'envelope': module(Envelope=lambda *a: object(), resident_transport=lambda *a, **kw:
            NS(close=lambda: order.append('login_transport_closed'))),
        'https_once': module(GetFaceOnce=lambda *a: object()),
        'network_guard': module(NetworkGuard=lambda: NS(stop=lambda: order.append('login_guard_stopped'), begin_startup=lambda: None)),
        'resident': module(Policy=lambda deadline: NS(clock=entry.time.monotonic, operation=lambda name, duration, operation: operation())),
        'resident_core_composition': module(run_session=run_session,
            login_diagnostics=lambda *a: contextlib.nullcontext()),
        'public_events': module(exception_origin=lambda *a: None),
        'core_result_r10': module(CoreObservedSigner=lambda *a, **kw:
            NS(close_observer=lambda: order.append('observer_closed'))),
        'signature_core': module(__file__=str(ROOT/'signature_core.py'), load_core=load_core),
    }
    options = NS(timeout=30, sdk_timeout=10, login_root=tmp_path/'login', inputs=tmp_path/'inputs.json',
        storage_root=tmp_path/'storage', bridge=Path('controlled-bridge'), worker_bridge=Path('controlled-worker'),
        loader_profile='10.0.26100.9974')
    options.login_root.mkdir()
    (options.login_root/'DEPENDENCY-U.json').write_text(json.dumps({'sources': {}}))
    def factory(actual_material, actual_profile, **kwargs):
        assert actual_material is material and actual_profile is profile
        assert 'login_guard_stopped' in order and 'login_owner_closed' in order
        assert kwargs['connector'].__self__.stage == 'sdk_connect'
        from test_primary_own_bootstrap_sdk_session import session
        phase, owner, channel, inputs = session((actual_material, actual_profile),
            connector=kwargs['connector'], deadline=kwargs['deadline'], clock=entry.time.monotonic)
        phases.append((phase, owner, channel, inputs))
        return phase
    def connect(network, *, timeout): return phases[0][2]
    try:
        with patch.dict(sys.modules, dependencies), patch.object(entry, '_checked_inputs'), \
                patch.object(entry, '_load_login_components', return_value=(Q,T,G,object(),adapter)), \
                patch.object(entry._NetworkDomain, 'connect_sdk', connect), patch.object(entry.sys, 'addaudithook'):
            if expected:
                with pytest.raises(entry.EntryError, match=expected):
                    entry.run(options, lambda *a: None, own_bootstrap_factory=factory)
                assert phases == []
            else:
                result = entry.run(options, lambda *a: None, own_bootstrap_factory=factory)
                assert (result.outcome,result.stage,result.code) == ('failed','sdk_status',2000)
                phase, owner, channel, inputs = phases[0]
                assert phase._state == 'closed' and channel.closed == inputs.closes == 1
                assert len(owner.signs) == 1
                assert all(getattr(phase, field) is None for field in
                    ('_component', '_original', '_encoded', '_binding', '_carrier'))
            assert order[:4] == ['login_transport_closed','observer_closed','login_owner_closed','core_closed']
            assert 'login_guard_stopped' in order
    finally:
        # The finite test helper module imports model classes from this one
        # activation and must not be reused with a later namespace.
        for name in ('test_primary_own_bootstrap_sdk_session','test_primary_own_sdk_request',
                'test_primary_source_cold12_binding','test_primary_source_cold12_reply',
                'test_primary_request_fingerprint'):
            sys.modules.pop(name, None)
