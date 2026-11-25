"""Fresh same-owner cold12 options and serial SIGN/frame orchestration; never send."""
from dataclasses import dataclass, field
from .errors import InputError
from .primary_source_cold12 import SourceCold12Encoder, SourceCold12Options, SourceCold12Reserve
from .primary_signature_result import PrimarySignatureResult


@dataclass(frozen=True)
class DisabledEnvironment:
    pass


@dataclass(frozen=True, repr=False)
class EnabledEnvironment:
    host: str
    port: int
    sso_env_id: str
    canary: str


def _text(value):
    if type(value) is not str:
        raise InputError('cold12 environment requires text')
    try:return value.encode('utf-8', errors='strict')
    except UnicodeError:raise InputError('cold12 environment requires strict UTF8 text') from None


def fresh_options(machine_id, *, appid_override, env_setting):
    if type(machine_id) is not bytes or not machine_id or b'\0' in machine_id:
        raise InputError('cold12 binding requires installed nonempty NUL-free machine identity')
    try:
        if machine_id.decode('utf-8', errors='strict').encode('utf-8') != machine_id:
            raise UnicodeError()
    except UnicodeError:
        raise InputError('installed machine identity has no supported strict Node UTF8 projection') from None
    if appid_override is not None and (type(appid_override) is not int or not 0 <= appid_override < 1 << 32):
        raise InputError('cold12 appid override requires uint32 or None')
    context13, canary = None, b''
    if type(env_setting) is EnabledEnvironment:
        host, env_id, value = (_text(v) for v in (env_setting.host, env_setting.sso_env_id, env_setting.canary))
        if type(env_setting.port) is not int or not 0 <= env_setting.port < 1 << 32:
            raise InputError('cold12 environment port requires a numeric DWORD')
        if (host and env_setting.port != 0) or value:
            context13, canary = env_id or None, value
    elif type(env_setting) is not DisabledEnvironment:
        raise InputError('cold12 environment must be explicitly enabled or disabled')
    return SourceCold12Options(appid_override or 0x20067C69, b'', machine_id,
        SourceCold12Reserve(context13, None, False, (), 101, canary))


@dataclass(frozen=True, repr=False)
class EncodedOwnCold12:
    frame: bytes
    wire_sequence: int
    sdk_sequence: int
    signature_result: PrimarySignatureResult
    _request: object = field(repr=False, compare=False)


class FreshCold12Binding:
    def __init__(self, owner, inputs, *, own_inputs, appid_override, env_setting):
        if type(own_inputs) is not bool:
            raise InputError('cold12 input ownership requires bool')
        self.owner, self.inputs, self.own_inputs = owner, inputs, own_inputs
        self.encoder = None
        self.closed, self._active, self._close_failure = False, False, None
        self.signer = owner._signer
        self.component = getattr(self.signer, '_own_sdk_request', None)
        self.runtime = self.signer.runtime
        try:
            self._check()
            self.options = fresh_options(getattr(owner, '_own_business_machine_id', None),
                appid_override=appid_override, env_setting=env_setting)
            owner._busy = True
            try:
                # Binding owns the input lifetime; encoder always borrows it to avoid duplicate cleanup.
                self.encoder = SourceCold12Encoder(inputs, routing_number=0, own_inputs=False)
            finally:owner._busy = False
            self._check()
        except BaseException as original:
            try:self.close()
            except BaseException as cleanup:
                owner._own_cold12 = self  # Retain actual failed cleanup debt, never retry its port close.
                owner._state = 'failed'
                raise BaseExceptionGroup('cold12 binding construction and cleanup failed', [original, cleanup])
            raise

    def _check(self):
        owner = self.owner
        owner._check_owner()
        if (self.closed or owner._state != 'open' or owner._busy or self.signer is not owner._signer or
                self.signer.failed or not getattr(owner, '_own_business_initialized', False) or
                self.signer.runtime is not self.runtime or self.component is None or self.component.runtime is not self.runtime or
                self.component is not getattr(self.signer, '_own_sdk_request', None)):
            raise InputError('cold12 binding requires its idle initialized business owner and SDK component')

    def encode(self, request):
        self._check()
        if self._active:
            raise InputError('cold12 encoding cannot reenter')
        self.component.check_device_request(request)
        self._active = True
        try:
            prepared = self.encoder.prepare(request.command, request.body)
            self._check();self.component.check_device_request(request)
            result = self.owner.sign_result(request.command, request.body)
            self._check();self.component.check_device_request(request)
            self.owner._busy = True
            try:frame = self.encoder.encode_signed(prepared, options=self.options, signature_result=result)
            except BaseException as error:
                self.owner._operation_failure = error
                self.owner._state = 'failed'
                raise
            finally:self.owner._busy = False
            return EncodedOwnCold12(frame, prepared.wire_sequence, request.sdk_sequence, result, request)
        finally:self._active = False

    def receive(self, encoded, frame):
        from .primary_source_cold12_reply import decode_source_cold12_reply
        from .primary_own_sdk_response import OwnCompletionResult
        self._check()
        if self._active:
            raise InputError('cold12 receiving cannot reenter')
        if type(encoded) is not EncodedOwnCold12:
            raise InputError('cold12 receiving requires encoded request data')
        request = encoded._request
        self.component.check_device_request(request)
        if (type(encoded.wire_sequence) is not int or not 0 <= encoded.wire_sequence < 1 << 32 or
                type(encoded.sdk_sequence) is not int or encoded.sdk_sequence != request.sdk_sequence):
            raise InputError('cold12 encoded request sequence mismatch')
        self._active = True
        try:
            reply = decode_source_cold12_reply(frame)
            if reply.wire_sequence != encoded.wire_sequence or reply.command != request.command:
                raise InputError('cold12 reply wire sequence or command mismatch')
            self._check()
            self.component.check_device_request(request)
            if reply.status:
                self.owner.cancel_own_device_request(request)
                return OwnCompletionResult('failed', 'sso', reply.status, False, None)
            return self.owner.complete_own_device_request(request, reply.payload, transport_status=0)
        finally:
            self._active = False

    def close(self):
        if self.closed:return
        if self._close_failure is not None:raise self._close_failure
        try:
            if self.encoder is not None:self.encoder.close()
            if self.own_inputs:self.inputs.close()
        except BaseException as error:
            self._close_failure = error
            raise
        self.closed = True
