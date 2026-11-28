"""Injection-only OneBot/Own SDK MODEL candidate, never a live driver.

The CLI inspects a recorded get_login_info reply only. Matching identity does
not authorize execution or establish online status, Native behavior or SDK
acceptance. There are no default SDK, resource, observer or action bindings.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Callable, Mapping, Protocol
from uuid import uuid4


# Literal compatibility is checked against Source without importing its runtime.
BUSINESS_QUA = b'V1_WIN_NQ_9.9.33_52230_GW_B'


class OneBotProtocolError(ValueError):
    pass


class OneBotAPIError(RuntimeError):
    """Retain the action error as received; retcode is never an SSO code."""
    def __init__(self, response):
        super().__init__('OneBot action failed')
        self.response = response
        self.status = response.get('status')
        self.retcode = response.get('retcode')
        self.message = response.get('message')


class IdentityBlocked(ValueError):
    def __init__(self, expected, actual):
        super().__init__('recorded/reported OneBot identity does not match')
        self.expected, self.actual = expected, actual


def _positive_uin(value):
    if type(value) is not int or not 0 < value < 1 << 64:
        raise ValueError('explicit positive uint64 expected UIN required')


def _action_data(response, *, echo):
    if type(response) is not dict or response.get('echo') != echo:
        raise OneBotProtocolError('matching action echo required')
    if type(response.get('status')) is not str or type(response.get('retcode')) is not int:
        raise OneBotProtocolError('explicit action status and integer retcode required')
    if response['status'] != 'ok' or response['retcode'] != 0:
        raise OneBotAPIError(response)
    if type(response.get('data')) is not dict:
        raise OneBotProtocolError('action data object required')
    return response['data']


def _identity(data, expected_uin):
    actual = data.get('user_id')
    if type(actual) is not int or actual <= 0 or actual != expected_uin:
        raise IdentityBlocked(expected_uin, actual)
    return actual


def _call(action, name, params):
    # One correlated action reply, not a wire sequence or a transport receipt.
    echo = str(uuid4())
    return _action_data(action({'action': name, 'params': params, 'echo': echo}), echo=echo)


@dataclass(frozen=True)
class ModelConfig:
    expected_uin: int
    machine_id: bytes
    bridge_path: object
    worker_bridge_path: object
    storage_root: object
    ownimage_module: object

    def __post_init__(self):
        _positive_uin(self.expected_uin)
        if type(self.machine_id) is not bytes or not self.machine_id or b'\0' in self.machine_id:
            raise ValueError('explicit own persistent machine_id bytes required')


class RequestResources(Protocol):
    """Borrowed public inputs, supplied and owned by an injected resource bundle.

    The provider collects actual records from this owner in a future authorized
    binding; it must clean up partial acquisition itself. close() releases its
    normal resources, preserving its own debt on failure. No records are made
    here and no SDK flags, private owner state or call windows are changed.
    """
    records: object
    request_capi: object
    clock_inputs: Mapping[str, Callable]
    random_environment: object
    state17_owner: Callable

    def close(self): ...


@dataclass(frozen=True)
class ModelResult:
    completion: object
    sign_result: object
    observation: object
    scope: str = 'MODEL_ONLY_NOT_BUSINESS_CLOSURE'


def _close(owner, resources, operation_error):
    # Retire the consumer before its borrowed backing. Stop on failed close;
    # exception references retain the actual debt, without a cleanup registry.
    try:
        owner.close()
        if resources is not None:
            resources.close()
    except BaseException as cleanup:
        failure = cleanup if operation_error is None else BaseExceptionGroup(
            'MODEL operation and cleanup failed', [operation_error, cleanup])
        failure.sdk_owner = owner
        failure.sdk_resources = resources
        raise failure


def run_model(config, *, action, open_windows_signer, collect_resources, observe_sign):
    """Finite MODEL orchestration using explicitly injected ports only.

    action accepts a standard action/params/echo object and returns its single
    correlated reply on the same injected connection. It owns timeouts/closure;
    this caller neither opens nor retries a connection. All ports are model
    bindings under this contract; passing live bindings is not authorized.

    observe_sign(owner, original, completion) is an existing-style observation
    context around ONE owner.sign_result call. Its evidence must distinguish
    cache selection and digest consumption; its return is never promoted here
    into an OBSERVED claim. Resources and owner remain on the calling thread.
    """
    _identity(_call(action, 'get_login_info', {}), config.expected_uin)
    # Identity gate precedes factory, collection, initialization and send_pb.
    owner = open_windows_signer(bridge_path=config.bridge_path,
        worker_bridge_path=config.worker_bridge_path, storage_root=config.storage_root,
        ownimage_module=config.ownimage_module, host_profile_string=BUSINESS_QUA,
        primary_backend='direct', own_business_config={
            'uin': config.expected_uin, 'machine_id': config.machine_id})
    resources = None
    operation_error = None
    try:
        if owner.own_business_identity() != (config.expected_uin, config.machine_id):
            raise ValueError('public owner identity mismatch')
        resources = collect_resources(owner)
        owner.initialize_own_sdk_request(request_capi=resources.request_capi,
            clock_inputs=resources.clock_inputs, random_environment=resources.random_environment,
            state17_owner=resources.state17_owner)
        original = owner.create_own_device_request(resources.records, external_a2_selection=None)
        try:
            # Only the OneBot JSON boundary uses text; the original stays bytes.
            command = original.command.decode('ascii', errors='strict')
            data = _call(action, 'send_pb', {'cmd': command, 'hex': original.body.hex()})
            if data.get('cmd') != command or type(data.get('hex')) is not str:
                raise OneBotProtocolError('send_pb command and application body hex required')
            try:
                body = bytes.fromhex(data['hex'])
            except ValueError as error:
                raise OneBotProtocolError('invalid application body hex') from error
            if len(body) * 2 != len(data['hex']):
                raise OneBotProtocolError('application body hex pairs required')
        except BaseException as error:
            try:
                owner.cancel_own_device_request(original)
            except BaseException as cancel:
                raise BaseExceptionGroup('action and original cancellation failed', [error, cancel])
            raise
        # Public completion consumes the original, including decoder failures.
        # Never cancel, replay or rebuild it after entering completion.
        completion = owner.complete_own_device_request(original, body, transport_status=0)
        followup = observation = None
        if (completion.outcome == 'processed' and completion.stage == 'publication'
                and completion.code is None and completion.cache_updated is True
                and completion.publication is not None):
            with observe_sign(owner, original, completion) as observation:
                followup = owner.sign_result(original.command, original.body)
        return ModelResult(completion, followup, observation)
    except BaseException as error:
        operation_error = error
        raise
    finally:
        _close(owner, resources, operation_error)


def inspect_recorded_metadata(response, *, expected_uin):
    """Offline identity check; cannot prove an independent/live correlation."""
    _positive_uin(expected_uin)
    if type(response) is not dict or type(response.get('echo')) is not str or not response['echo']:
        raise OneBotProtocolError('recorded action reply with echo required')
    data = _action_data(response, echo=response['echo'])
    _identity(data, expected_uin)
    return {'status': 'RECORDED_IDENTITY_MATCH_NOT_EXECUTED', 'execution': 'NOT_EXECUTED',
        'online': 'UNKNOWN', 'native_behavior': 'UNKNOWN', 'business_closure': 'UNPROVED'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata-json', type=Path, required=True,
        help='recorded get_login_info action reply; offline inspection only')
    parser.add_argument('--expected-uin', type=int, required=True)
    options = parser.parse_args(argv)
    try:
        result = inspect_recorded_metadata(json.loads(options.metadata_json.read_bytes()),
            expected_uin=options.expected_uin)
    except (ValueError, OSError, OneBotAPIError) as error:
        # Never print the raw reply, nickname, body, or API error message.
        print(json.dumps({'status': 'BLOCKED', 'execution': 'NOT_EXECUTED',
            'error_type': type(error).__name__}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
