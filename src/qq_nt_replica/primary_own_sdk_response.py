"""Own response byte parsing. Parsing alone never authorizes installation."""
from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _varint
from .primary_request_response import decrypt_request_body

_LIMIT = 1 << 20


def _fields(raw, strings, integers, initial=None, messages=None):
    """The finite 1CD3CB0 parser domain: bytes append and integers replace."""
    if type(raw) is not bytes:
        raise InputError('response body requires immutable bytes')
    if len(raw) > _LIMIT:
        raise PrimaryProgramLimit('response parser exceeds the bounded offline domain')
    values = {} if initial is None else dict(initial)
    messages = {} if messages is None else messages
    values.update({key: b'' for key in strings})
    cursor = steps = 0
    while cursor < len(raw):
        steps += 1
        if steps > _LIMIT:
            raise PrimaryProgramLimit('response parser exceeds the bounded offline domain')
        valid, tag, cursor = _varint(raw, cursor)
        if not valid:
            return False, values
        number = (tag >> 3) & 0xFFFFFFFF
        if number in strings or number in integers or number in messages:
            valid, value, cursor = _varint(raw, cursor)
            if not valid:
                return False, values
            if number in strings or number in messages:
                end = (cursor + (value & 0xFFFFFFFF)) & 0xFFFFFFFF
                if end > len(raw):
                    return False, values
                if number in messages:
                    if end == cursor or not messages[number](raw[cursor:end]):
                        return False, values
                else:
                    values[number] += raw[cursor:end]
                cursor = end
            else:
                values[number] = value & ((1 << integers[number]) - 1)
        elif tag & 7 in (0, 2):
            valid, value, cursor = _varint(raw, cursor)
            if not valid:
                return False, values
            if tag & 7 == 2:
                end = (cursor + (value & 0xFFFFFFFF)) & 0xFFFFFFFF
                if end <= len(raw):
                    cursor = end
    return True, values


def _envelope(raw, mode):
    if type(mode) is not int or mode not in (0, 1):
        raise InputError('response mode requires zero or one')
    return _fields(raw, (1, 3) if mode else (1,),
                   {2: 32, (4 if mode else 3): 64}, {2: 0})


def _authenticated_plaintext(ciphertext, snapshot):
    # The decrypt primitive returns plaintext even on bad tag; never expose it then.
    code, plaintext = decrypt_request_body(ciphertext, snapshot.key)
    return None if code else plaintext


def _establish_fields(plaintext):
    settings = {}
    def parse_settings(raw):
        valid, fields = _fields(raw, (), {key: 32 for key in range(1, 11)}, settings)
        if valid:
            settings.update(fields)
        return valid
    valid, fields = _fields(plaintext, (1, 4), {2: 64, 3: 64}, messages={5: parse_settings})
    if valid and 2 not in fields:
        raise PrimarySemanticUnavailable('mode0 response identifier requires uninitialized source stack input')
    return valid, fields, settings


def _feature_values(settings):
    if settings.get(10, 0) != 0:
        return None
    if any(key not in settings for key in (1, 2)):
        raise PrimarySemanticUnavailable('mode0 response features1/2 require explicit source stack input')
    return {key: value if value in (0, 1) else 2
            for key in range(1, 10)
            for value in (settings.get(key, 2 if key == 4 else 0),)}


def _decode(owner, request, response):
    from .primary_request_material import RequestMaterial
    from .primary_request_response import verify_material_signature, _features
    from .primary_worker_response import _frame
    runtime = owner.runtime
    snapshot = request.decode_material
    mode = request.encoded.status
    valid, outer = _envelope(response, mode)
    if not valid:
        return mode, None
    if outer[2]:
        from .primary_request_response import error_message
        from .primary_logger import _String
        frame, rbp = _frame(runtime, 0x338, 'Own.response_status_frame')
        try:
            error_message(runtime, rbp + 0x148, outer[2], rbp + 0x140)
            code = runtime.memory.load(rbp + 0x140, 4)
            _String.read(runtime, rbp + 0x148).destroy()
            if code != 1003 and snapshot.device_random == owner.material.current.device_random:
                owner.material.reset()
            return code, None
        finally:
            runtime.memory.unmap(frame)
    if not outer[1]:
        return 0, b''
    plain = _authenticated_plaintext(outer[1], snapshot)
    if plain is None:
        return 2, None
    if mode:
        return 0, plain
    valid, fields, settings = _establish_fields(plain)
    if not valid:
        return 5, None
    archived = snapshot.device_random != owner.material.current.device_random
    def verify():
        if len(fields[1]) < 64:
            raise PrimarySemanticUnavailable('mode0 verification requires complete source signature storage')
        return verify_material_signature(fields[1][:64], fields[2], snapshot.message_id, snapshot.peer_key)
    if archived:
        return (0, fields[4]) if verify() else (3, None)
    if 3 not in fields:
        raise PrimarySemanticUnavailable('mode0 current response deadline requires uninitialized source stack input')
    raw = bytearray(owner.material.current.raw)
    raw[32:40] = fields[3].to_bytes(8, 'little')
    nanos = owner.clocks['monotonic_ns']()
    if type(nanos) is not int or not -(1 << 63) <= nanos < (1 << 63):
        raise InputError('response monotonic clock requires signed64 input')
    seconds = abs(nanos) // 1000000000 * (-1 if nanos < 0 else 1)
    raw[40:48] = ((seconds + 60) & ((1 << 64) - 1)).to_bytes(8, 'little')
    owner.material.current = RequestMaterial(bytes(raw))
    values = _feature_values(settings)
    frame, rbp = _frame(runtime, 0x338, 'Own.response_features_frame')
    try:
        _features(runtime, values, rbp)
    finally:
        runtime.memory.unmap(frame)
    current = owner.material.current
    if current.payload_mode != 1:
        accepted = verify()
        raw = bytearray(current.raw); raw[80] = int(accepted)
        owner.material.current = RequestMaterial(bytes(raw))
    else:
        accepted = True
    return (0, fields[4]) if accepted else (3, None)


def _complete(owner, request, bound, responsebody, transport_status):
    from .primary_worker_response import _frame, _parse, _apply_parsed_cache, _image
    from .primary_logger import _String
    from .primary_tokens import publish_own_response_token
    runtime = owner.runtime
    memory = runtime.memory
    pair = runtime.image_base + 0x6751840
    if transport_status:
        memory.store(pair + 0x64, (memory.load(pair + 0x64, 4) + 1) & 0xFFFFFFFF, 4, source='Own.response_transport_failure')
        return None
    code, payload = _decode(owner, request, responsebody)
    if code or payload is None:
        memory.store(pair + 0x64, (memory.load(pair + 0x64, 4) + 1) & 0xFFFFFFFF, 4, source='Own.response_decode_failure')
        return None
    frame, rbp = _frame(runtime, 0x1A8, 'Own.device_response_frame')
    pointer = None
    token = name = None
    try:
        pointer = runtime._operator_new(max(len(payload), 1))
        memory.write(pointer, payload, source='Own.authenticated_response_payload')
        parsed, reason, token = _parse(runtime, pointer, len(payload), rbp)
        if not parsed:
            memory.store(pair + 0x64, (memory.load(pair + 0x64, 4) + 1) & 0xFFFFFFFF, 4, source='Own.response_parse_failure')
            return None
        name = _String.construct(runtime, bound)
        _apply_parsed_cache(runtime, pair, name, token, rbp, _image())
        # Only the token parser's zero-initialized 32B storage justifies padding.
        auxiliary = token.value()[:4].ljust(4, b'\0') + b'\0'
        memory.write(rbp + 0x90, auxiliary, source='Own.device_auxiliary')
        result = publish_own_response_token(runtime, rbp + 0x90)
        result['cache_updated'] = bool(token.value())
        return result
    finally:
        if token is not None: token.destroy()
        if name is not None: name.destroy()
        if pointer is not None: runtime._free_allocation(pointer)
        memory.unmap(frame)
