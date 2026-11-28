"""Deferred public Own SDK/OneBot bindings. Importing does no live work.

Execution requires a separately authorized --run and an explicit private config.
Native is an opaque external carrier; no Own MSF or original SIGN usage claim.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import math
from pathlib import Path
import stat
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlsplit


def validate_owned_paths(task_root, state_id):
    """Read only the selected path chain. Never follow a reparse point to create."""
    root = Path(task_root)
    if (not root.is_absolute() or root.drive.upper() != 'G:' or root == Path(root.anchor)
            or '..' in root.parts or type(state_id) is not str or not state_id
            or any(not (c.isascii() and (c.isalnum() or c in '_-')) for c in state_id)):
        raise ValueError('explicit owned absolute G task directory and unique ASCII state_id required')
    for path in reversed((root, *root.parents)):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError('owned task ancestor must be a physical directory without reparse points')
    resolved = root.resolve(strict=True)
    if resolved != root:
        raise ValueError('owned task root must use its final resolved path')
    run_root = root / state_id
    try:
        run_root.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError('run namespace must be fresh')
    return run_root


def read_live_config(path):
    """No Native, sockets or persistence; only the explicitly supplied config."""
    value = json.loads(Path(path).read_bytes())
    required = {'expected_uin', 'machine_id_hex', 'bridge_path', 'worker_bridge_path',
        'loader_profile', 'task_root', 'state_id', 'ws_url', 'overall_timeout',
        'action_timeout', 'receive_budget'}
    if type(value) is not dict or set(value) - required - {'token_file'} or not required <= set(value):
        raise ValueError('explicit live configuration fields required')
    from run_own_sdk_onebot_candidate import ModelConfig
    machine = bytes.fromhex(value['machine_id_hex'])
    ModelConfig(value['expected_uin'], machine, None, None, None, None)
    for name in ('overall_timeout', 'action_timeout'):
        number = value[name]
        if type(number) not in (int, float) or not math.isfinite(number) or not 0 < number <= 120:
            raise ValueError('finite positive timeout up to 120 seconds required')
    if type(value['receive_budget']) is not int or not 0 < value['receive_budget'] <= 4096:
        raise ValueError('finite receive budget required')
    url = urlsplit(value['ws_url'])
    if url.scheme not in ('ws', 'wss') or not url.hostname or url.username or url.password or url.fragment or url.query:
        raise ValueError('explicit WS endpoint without embedded credentials required')
    for name in ('bridge_path', 'worker_bridge_path'):
        value[name] = Path(value[name])
        if not value[name].is_absolute():
            raise ValueError('absolute bridge paths required')
    value['machine_id'] = machine
    value['run_root'] = validate_owned_paths(value['task_root'], value['state_id'])
    return value


class WSAction:
    """One connection with shared whole-message waiting deadlines, no resend.

    Public recv(timeout) bounds message waiting across control/partial frames.
    send and the library's final receiver join aren't absolute wall-time bounds;
    an authorized execution needs a separate external process budget.
    """
    def __init__(self, url, *, overall_timeout, action_timeout, receive_budget,
                 token=None, connect=None, clock=time.monotonic):
        self.url, self.overall_timeout = url, overall_timeout
        self.action_timeout, self.receive_budget = action_timeout, receive_budget
        self.token, self.connect, self.clock = token, connect, clock
        self.socket = None

    def __enter__(self):
        if self.connect is None:
            from websockets.sync.client import connect
            self.connect = connect
        self.deadline = self.clock() + self.overall_timeout
        headers = {}
        if self.token is not None:
            if not self.token or '\r' in self.token or '\n' in self.token:
                raise ValueError('invalid private token')
            headers['Authorization'] = 'Bearer ' + self.token
        self.socket = self.connect(self.url,
            open_timeout=min(self.overall_timeout, self.action_timeout),
            close_timeout=min(3, self.action_timeout), additional_headers=headers)
        return self

    def __call__(self, request):
        from run_own_sdk_onebot_candidate import OneBotProtocolError
        deadline = min(self.deadline, self.clock() + self.action_timeout)
        def remaining():
            seconds = deadline - self.clock()
            if seconds <= 0:
                raise TimeoutError('OneBot action deadline exceeded; send state may be unknown')
            return seconds
        remaining()
        self.socket.send(json.dumps(request))
        for _ in range(self.receive_budget):
            raw = self.socket.recv(timeout=remaining())
            if raw in ('', b''):
                raise ConnectionError('OneBot disconnected; send state may be unknown')
            reply = json.loads(raw)
            remaining()  # Never accept a reply that arrived after the deadline.
            if type(reply) is dict and reply.get('echo') == request['echo']:
                return reply
        raise OneBotProtocolError('OneBot receive budget exhausted')

    def __exit__(self, kind, error, traceback):
        try:
            self.socket.close()
        except BaseException as cleanup:
            cleanup.onebot_action = self
            if error is not None:
                failure = BaseExceptionGroup('OneBot operation and close failed', [error, cleanup])
                failure.onebot_action = self
                raise failure
            raise
        self.socket = None
        return False


def load_source_api():
    """Called only inside the maintained isolated core activation."""
    from qq_nt_replica.primary_windows_signer import open_windows_signer, WindowsSigner
    from qq_nt_replica.primary_windows_ownimage import OwnImageModuleSpec
    from qq_nt_replica.primary_device_value_producer import WindowsDeviceValueEnvironment
    from qq_nt_replica.primary_device_mix_producer import WindowsDeviceMixPort, produce_device_mix
    from qq_nt_replica.primary_request_capi import SystemRequestCapi
    from qq_nt_replica.primary_windows_device_collection import (
        WindowsDeviceCollectionObservations, OwnIdentifierStores, WindowsOwnIdentifierRegistry)
    from qq_nt_replica.primary_device_record_collector import IndependentDeviceRecordCollector
    from qq_nt_replica.primary_windows_wmi_session import OwnedWmiSession
    from qq_nt_replica.primary_sdk import string_view
    from qq_nt_replica.primary_response_refresh import signing_value
    from qq_nt_replica.primary_material import request_context_digest
    from qq_nt_replica.primary_signer import PrimarySigner
    return SimpleNamespace(**locals())


class Resources:
    """One owner-backed bundle with normal ordered close and visible partial debt."""
    def __init__(self):
        self.environment = self.mix = self.port = self.collector = self.stores = None

    def acquire(self, owner, api, config):
        try:
            runtime = owner.signer.runtime
            fields = {}
            for key, offset in ((0x30, 0x58), (0x48, 0x70), (0x78, 0xA0)):
                pointer, length = api.string_view(runtime.memory, runtime.image_base + 0x67516B0 + offset)
                fields[key] = runtime.memory.read(pointer, length)
            self.before = owner.signer.response_cache.value
            self.environment = api.WindowsDeviceValueEnvironment()
            value = owner.get_own_device_value()
            self.mix = api.WindowsDeviceMixPort()
            self.state17 = api.produce_device_mix(self.mix)
            self.request_capi = api.SystemRequestCapi()
            self.port = api.WindowsDeviceCollectionObservations()
            self.stores = api.OwnIdentifierStores(config['run_root'] / 'collector',
                config['state_id'], registry=RegistryObservations(api.WindowsOwnIdentifierRegistry()))
            self.collector = api.IndependentDeviceRecordCollector(self.port, self.stores,
                sdk_fields=fields, wmi_factory=api.OwnedWmiSession.open)
            self.records = self.collector.collect(version=fields[0x78], device_value=value,
                ansi_to_utf8=self.port.ansi_to_utf8)
            self.clock_inputs = dict(wall_seconds=self.environment.time_seconds,
                monotonic_ns=time.perf_counter_ns, clock_ns=time.perf_counter_ns)
            self.random_environment = self.environment
            self.state17_owner = lambda: self.state17
            return self
        except BaseException as error:
            # Shared controller must close owner before these partial inputs.
            error.sdk_resources = self
            raise

    def close(self):
        for name in ('collector', 'port', 'mix', 'environment'):
            resource = getattr(self, name)
            if resource is not None:
                resource.close()
                setattr(self, name, None)
        # CAPI has no close API. Keep its normal process-lifetime semantics.

    def persistence(self):
        return {'io_errors': [] if self.stores is None else list(self.stores.io_errors),
            'registry_calls': [] if self.stores is None else list(self.stores.registry.calls),
            'persistence_complete': 'UNKNOWN',
            'namespace': None if self.stores is None else self.stores.namespace}


class RegistryObservations:
    """Delegate only the owned provider API; preserve False without a new gate."""
    def __init__(self, provider):
        self.provider, self.calls = provider, []

    def read(self, path, name):
        return self.provider.read(path, name)

    def write(self, path, name, value):
        result = self.provider.write(path, name, value)
        self.calls.append(('write', result))
        return result

    def delete(self, path, name):
        result = self.provider.delete(path, name)
        self.calls.append(('delete', result))
        return result


@contextmanager
def observe_sign(owner, original, completion, *, api, before):
    """Observe actual Python call identities without replacing SDK functions."""
    signer = owner.signer
    runtime, cache = signer.runtime, signer.response_cache
    installed = cache.value
    evidence = dict(consumption='UNKNOWN', before=before, installed=installed, events=[],
        sign_returned=False, sign_extra=None)
    select_code = api.signing_value.__code__
    digest_code = api.request_context_digest.__code__
    body_code = api.PrimarySigner._sign_body.__code__
    sign_code = api.WindowsSigner.sign_result.__code__
    def chain(frame):
        body = public = False
        cursor = frame.f_back
        while cursor is not None:
            local = cursor.f_locals
            if cursor.f_code is body_code and local.get('self') is signer:
                body = (local.get('command') == original.command and local.get('payload') == original.body)
            if cursor.f_code is sign_code and local.get('self') is owner:
                public = (local.get('command') == original.command and local.get('payload') == original.body)
            cursor = cursor.f_back
        return body and public
    def profile(frame, event, value):
        local = frame.f_locals
        if (frame.f_code is select_code and event == 'return' and chain(frame)
                and local.get('runtime') is runtime and local.get('cache') is cache):
            evidence['events'].append(('selected', value))
        elif (frame.f_code is digest_code and chain(frame)
                and local.get('payload') == original.body):
            if event == 'call':
                evidence['events'].append(('digest_input', local.get('d')))
            elif event == 'return':
                evidence['events'].append(('digest_return', value))
        elif (frame.f_code is sign_code and event == 'return' and local.get('self') is owner
                and local.get('command') == original.command and local.get('payload') == original.body):
            if value is not None:
                evidence['sign_returned'] = True
                evidence['sign_extra'] = getattr(value, 'extra', None)
    previous = sys.getprofile()
    sys.setprofile(profile)
    normal = False
    try:
        yield evidence
        normal = True
    finally:
        sys.setprofile(previous)
        evidence['after'] = cache.value
        events = evidence['events']
        if (normal and evidence['sign_returned'] and type(installed) is bytes and installed
                and installed != before and evidence['after'] == installed
                and evidence['sign_extra'] == installed
                and len(events) == 3 and [e[0] for e in events] ==
                    ['selected', 'digest_input', 'digest_return']
                and events[0][1] == installed and events[1][1] == installed
                and type(events[2][1]) is bytes):
            evidence['consumption'] = 'OBSERVED'


def run_live(config):
    """Actual deferred entry. Requires separate execution GO; never called by tests."""
    from signature_core import load_core
    from run_own_sdk_onebot_candidate import ModelConfig, run_model
    # Recheck physical containment immediately before any namespace creation.
    run_root = validate_owned_paths(config['task_root'], config['state_id'])
    if run_root != config['run_root']:
        raise ValueError('owned run path changed')
    token = None
    if config.get('token_file'):
        token = Path(config['token_file']).read_text(encoding='utf-8').strip()
    core = activation = None
    active = False
    resources = Resources()
    debt = False
    try:
        with WSAction(config['ws_url'], overall_timeout=config['overall_timeout'],
                action_timeout=config['action_timeout'], receive_budget=config['receive_budget'], token=token) as action:
            core = load_core()
            activation = core.activate()
            activation.__enter__()
            active = True
            api = load_source_api()
            model = ModelConfig(config['expected_uin'], config['machine_id'],
                config['bridge_path'], config['worker_bridge_path'], run_root / 'sdk',
                api.OwnImageModuleSpec.for_loader_profile(config['loader_profile']))
            def factory(**kwargs):
                validate_owned_paths(config['task_root'], config['state_id'])
                run_root.mkdir()
                return api.open_windows_signer(**kwargs)
            try:
                result = run_model(model, action=action, open_windows_signer=factory,
                    collect_resources=lambda owner: resources.acquire(owner, api, config),
                    observe_sign=lambda owner, original, completion: observe_sign(
                        owner, original, completion, api=api, before=resources.before))
            except BaseException as error:
                debt = hasattr(error, 'sdk_owner') or hasattr(error, 'independent_windows_owner')
                if debt:
                    error.sdk_core, error.sdk_activation = core, activation
                error.own_run_root = run_root
                error.own_persistence = resources.persistence()
                raise
            result = replace(result, scope='OWN_SDK_EXTERNAL_CARRIER_NOT_FULL_GOAL',
                persistence=resources.persistence())
            return result
    finally:
        if not debt:
            if active:
                activation.__exit__(None, None, None)
            if core is not None:
                core.close()
