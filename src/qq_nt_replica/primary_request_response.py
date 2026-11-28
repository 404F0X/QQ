import hashlib
import hmac

from .errors import InputError
from .primary_logger import _String, _Tree, _srw, construct, feature
from .primary_request_encoder import _B, _N, _P, _aes_block, _bytes, _ghash_multiply, _image, _xor
from .primary_request_entry import _MaterialState
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _invoke, _zero_string
from .primary_worker_response import _frame, _varint
from .wire import require_bytes, require_uint


_U64 = (1 << 64) - 1
_LIMIT = 1 << 20


def decrypt_request_body(ciphertext, key):
    require_bytes(ciphertext, 'response ciphertext')
    _bytes(key, 32, 'response AES256 key')
    if len(ciphertext) > _LIMIT:
        raise PrimaryProgramLimit('response ciphertext exceeds the bounded offline domain')
    if len(ciphertext) <= 28:
        return 0xFFFFFFFF, None
    nonce, body, received = ciphertext[:12], ciphertext[12:-16], ciphertext[-16:]
    box = bytes.fromhex(_image()['aes_sbox_hex'])
    hash_key = int.from_bytes(_aes_block(bytes(16), key, box), 'big')
    plain, accumulator = bytearray(), 0
    for offset in range(0, len(body), 16):
        block = body[offset:offset + 16]
        counter = nonce + (2 + offset // 16).to_bytes(4, 'big')
        plain.extend(_xor(block, _aes_block(counter, key, box)))
        accumulator = _ghash_multiply(accumulator ^ int.from_bytes(block.ljust(16, b'\0'), 'big'), hash_key)
    accumulator = _ghash_multiply(accumulator ^ (len(body) * 8), hash_key)
    calculated = _xor(accumulator.to_bytes(16, 'big'), _aes_block(nonce + b'\0\0\0\x01', key, box))
    return (0 if hmac.compare_digest(received, calculated) else 0xFFFFFFFF), bytes(plain)


def _double(point):
    x, y = point
    if not y:
        return 0, 0
    slope = (3 * x * x - 3) * pow(2 * y, -1, _P) % _P
    xx = (slope * slope - 2 * x) % _P
    return xx, (slope * (x - xx) - y) % _P


def _add(left, right):
    x, y = left
    u, v = right
    if x == u:
        return 0, 0
    slope = (v - y) * pow(u - x, -1, _P) % _P
    xx = (slope * slope - x - u) % _P
    return xx, (slope * (x - xx) - y) % _P


def _verification_point(value):
    x = int.from_bytes(value[1:], 'big')
    y = pow((x * x * x - 3 * x + _B) % _P, (_P + 1) // 4, _P)
    if y & 1 != value[0] & 1:
        y = _P - y
    return x, y


def verify_material_signature(signature, response_id, current_id, public_key):
    _bytes(signature, 64, 'response material signature')
    _bytes(public_key, 33, 'response material public key')
    require_uint(response_id, 64, 'response material identifier')
    require_uint(current_id, 64, 'current material identifier')
    public = _verification_point(public_key)
    r, s = (int.from_bytes(signature[offset:offset + 32], 'big') for offset in (0, 32))
    if not 0 < r < _N or not 0 < s < _N:
        return False
    digest = hashlib.sha256(public_key + current_id.to_bytes(8, 'big') + response_id.to_bytes(8, 'big')).digest()
    inverse = pow(s, -1, _N)
    first, second = int.from_bytes(digest, 'big') * inverse % _N, r * inverse % _N
    raw_base = bytes.fromhex(_image()['curve_base_hex'])
    generator = tuple(int.from_bytes(raw_base[offset:offset + 32], 'little') for offset in (0, 32))
    points = (None, generator, public, _add(generator, public))
    bit = max(first.bit_length(), second.bit_length()) - 1
    if bit < 0:
        return False
    result = points[((first >> bit) & 1) | (((second >> bit) & 1) << 1)]
    for bit in range(bit - 1, -1, -1):
        result = _double(result)
        selected = ((first >> bit) & 1) | (((second >> bit) & 1) << 1)
        if selected:
            result = _add(result, points[selected])
    return result[0] % _N == r


def _pointer(value, address):
    return value.get(16, 8) if value.get(0, 1) & 1 else address + 1


def decrypt(runtime, source, output, count, key):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x3D8, '1CACFA0.response_decrypt_frame')
    raw = _String.read(runtime, source).value()
    if len(raw) <= 28:
        runtime.events.append(('request.response_decrypt', 0xFFFFFFFF, len(raw), None))
        memory.unmap(frame)
        return 0xFFFFFFFF
    if len(raw) > _LIMIT:
        raise PrimaryProgramLimit('response ciphertext exceeds the bounded offline domain')
    size = len(raw) - 28
    memory.store(count, size, 8, source='1CACFFA.response_plaintext_count')
    copied = runtime._allocate(size, False)
    result = runtime._allocate(size, False)
    memory.store(output, result, 8, source='1CAD013.response_plaintext_pointer')
    whole = runtime._allocate(len(raw), False)
    memory.write(whole, raw, source='1CAD5AE.response_ciphertext_copy')
    memory.write(copied, raw[12:-16], source='1CAD5C6.response_body_copy')
    key_value = _String.read(runtime, key)
    status, plain = decrypt_request_body(raw, memory.read(_pointer(key_value, key), 32))
    memory.write(result, plain, source='1CACFA0.response_plaintext')
    runtime._free_allocation(copied)
    runtime._free_allocation(whole)
    runtime.events.append(('request.response_decrypt', status, len(raw), result))
    memory.unmap(frame)
    return status


def _parse(runtime, raw, strings, integers, initial, *, messages=None):
    values, cursor, steps = dict(initial), 0, 0
    messages = {} if messages is None else messages
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
                    _append(strings[number], raw[cursor:end])
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


def _features(runtime, settings, rbp):
    from .primary_material import ProviderMaterial

    memory, base = runtime.memory, runtime.image_base
    pointer = memory.load(base + 0x67516A8, 8)
    if not pointer:
        pointer = runtime._operator_new(120)
        construct(runtime, pointer)
        memory.store(base + 0x67516A8, pointer, 8, source='1CDA9DE.response_logger_publish')
    if settings is None:
        return
    tree = _Tree(runtime, pointer + 64)
    for key in range(1, 10):
        value = settings.get(key, 2 if key == 4 else 0)
        value = value if value in (0, 1) else 2
        _srw(runtime, pointer + 48, True)

        def initialize(node):
            memory.store(node + 32, key, 4, source='1BE3961.response_feature_key')
            memory.store(node + 36, 0, 4, source='1BE3964.response_feature_initial')

        node = tree.insert(key, 40, initialize)
        memory.store(node + 36, value, 4, source='1BE399E.response_feature_value')
        if isinstance(runtime.provider_material, ProviderMaterial):
            runtime.provider_material.set_feature(key, value)
        _srw(runtime, pointer + 48, False)
    persisted = _String.construct(runtime, str(feature(runtime, pointer, 6)).encode('ascii'))
    persisted.write_to(rbp + 0x148)
    sentinel = pointer + 32
    node, candidate = memory.load(sentinel, 8), sentinel
    for _ in range(4096):
        if not node:
            break
        key = memory.load(node + 32, 4, signed=True)
        if key >= 6:
            candidate, node = node, memory.load(node, 8)
        else:
            node = memory.load(node + 8, 8)
    else:
        raise PrimaryProgramLimit('response configuration name lookup exceeds its bounded tree')
    if candidate != sentinel and memory.load(candidate + 32, 4, signed=True) >= 7:
        candidate = sentinel
    prefix = _String.read(runtime, pointer).value()
    name = _String.read(runtime, candidate + 40).value()
    _String.concat(runtime, prefix, name).write_to(rbp + 0x100)
    _invoke(runtime, 0x1BE5B30, rbp + 0x100, rbp + 0x148)
    _String.read(runtime, rbp + 0x100).destroy()
    _String.read(runtime, rbp + 0x148).destroy()
    from .primary_feature_notifications import notify
    notify(runtime, pointer, rbp)


def _status_node(runtime, code):
    memory, base = runtime.memory, runtime.image_base
    sentinel = base + 0x677D038
    node, candidate = memory.load(sentinel, 8), sentinel
    for _ in range(4096):
        if not node:
            if candidate != sentinel and memory.load(candidate + 32, 4) == code:
                return candidate
            return None
        if memory.load(node + 32, 4) < code:
            node = memory.load(node + 8, 8)
        else:
            candidate, node = node, memory.load(node, 8)
    raise PrimaryProgramLimit('response status tree exceeds the bounded traversal domain')


def error_message(runtime, output, code, status):
    code &= 0xFFFFFFFF
    runtime.memory.store(status, code, 4, source='1CABB8C.response_server_status')
    node = _status_node(runtime, code)
    if node is None:
        code = 2000
        runtime.memory.store(status, code, 4, source='1CABBDA.response_unknown_server_status')
        node = _status_node(runtime, code)
    elif code == 1002:
        from .primary_response_diagnostics import report
        report(runtime)
        code = runtime.memory.load(status, 4)
    node = _status_node(runtime, code)
    source = runtime.image_base + 0x677D060 if node is None else node + 40
    _String.read(runtime, source).clone().write_to(output)
    return output


def respond(runtime, output, source, mode, metadata, status, extra_output=0):
    memory, base = runtime.memory, runtime.image_base
    lock = base + 0x677D048
    if lock not in runtime.locks:
        raise PrimarySemanticUnavailable('1CD3CB0 requires the initialized request critical section')
    runtime.locks[lock] += 1
    runtime.events.append(('EnterCriticalSection', lock))
    frame, rbp = _frame(runtime, 0x338, '1CD3CB0.response_consumer_frame')
    memory.store(status, 0, 4, source='1CD3D11.response_status')
    cipher, details = _zero_string(runtime), _zero_string(runtime)
    locals = [cipher, details]

    def finish(code, value=None):
        memory.store(status, code, 4, source='request.response_status')
        (value if value is not None else _zero_string(runtime)).write_to(output)
        for local in reversed(locals):
            local.destroy()
        runtime.locks[lock] -= 1
        runtime.events.append(('LeaveCriticalSection', lock))
        memory.unmap(frame)
        return output

    if mode & 0xFFFFFFFF not in (0, 1):
        raise PrimarySemanticUnavailable('response mode is outside the recovered mode0/mode1 domain')
    valid, outer = _parse(runtime, _String.read(runtime, source).value(),
                          {1: cipher, **({3: details} if mode else {})},
                          {2: 32, **({4: 64} if mode else {3: 64})}, {2: 0})
    if not valid:
        return finish(mode & 0xFFFFFFFF)
    extra = outer.get(4 if mode else 3, 0)
    if extra_output and extra:
        memory.store(extra_output, extra, 8, source='request.response_timed_seconds')
        return finish(0)
    metadata_value = _String.read(runtime, metadata)
    archived = memory.read(_pointer(metadata_value, metadata), 32) != memory.read(base + 0x677D0E8, 32)
    state = _MaterialState(runtime, frame)
    if outer[2]:
        error_message(runtime, rbp + 0x148, outer[2], status)
        error_value = _String.read(runtime, rbp + 0x148)
        locals.append(error_value)
        code = memory.load(status, 4)
        if code != 1003 and not archived:
            state.reset()
        return finish(code)
    if not cipher.value():
        return finish(0)
    material, found = state.lookup(metadata_value.value()) if archived else (state.current, True)
    if not found:
        return finish(2)
    cipher.write_to(rbp)
    memory.store(rbp + 0x20, 0, 8, source='1CD8B3B.response_decrypt_output')
    key = _String.construct(runtime, material.key)
    locals.append(key)
    key.write_to(rbp + 0x40)
    code = decrypt(runtime, rbp, rbp + 0x20, rbp - 0x28, rbp + 0x40)
    if code:
        return finish(2)
    pointer, count = memory.load(rbp + 0x20, 8), memory.load(rbp - 0x28, 8)
    plain = _String.construct(runtime, memory.read(pointer, count))
    locals.append(plain)
    if mode:
        runtime._free_allocation(pointer)
        locals.remove(plain)
        return finish(0, plain)
    signature, payload = (_zero_string(runtime) for _ in range(2))
    locals.extend((signature, payload))
    settings = {}

    def parse_settings(raw):
        valid, values = _parse(runtime, raw, {}, {key: 32 for key in range(1, 11)}, settings)
        if valid:
            settings.update(values)
        return valid

    valid, inner = _parse(runtime, plain.value(), {1: signature, 4: payload}, {2: 64, 3: 64}, {},
                          messages={5: parse_settings})
    if not valid:
        return finish(5)
    signature.write_to(rbp + 0x88)
    for number, offset in ((2, 0xA0), (3, 0xA8)):
        if number in inner:
            memory.store(rbp + offset, inner[number], 8, source='request.response_material_field')
    response_id = memory.load(rbp + 0xA0, 8)

    def verify():
        return verify_material_signature(memory.read(_pointer(signature, rbp + 0x88), 64),
                                         response_id, material.message_id, material.peer_key)

    if archived:
        accepted = verify()
        runtime._free_allocation(pointer)
        if not accepted:
            return finish(3)
    else:
        memory.store(base + 0x677D0D8, memory.load(rbp + 0xA8, 8), 8, source='1CDA96E.response_wall_deadline')
        _invoke(runtime, 0x759B30, rbp + 0x148)
        nanoseconds = memory.load(rbp + 0x148, 8, signed=True)
        seconds = abs(nanoseconds) // 1000000000 * (-1 if nanoseconds < 0 else 1)
        memory.store(base + 0x677D0E0, (seconds + 60) & _U64, 8, source='1CDA9A4.response_monotonic_deadline')
        apply_settings = settings.get(10, 0) == 0
        if apply_settings:
            for key in (1, 2):
                if key not in settings:
                    address = rbp + 0xCC + key * 4
                    if runtime.response_feature_initial is not None:
                        region, offset = memory._span(address, 4)
                        for index in range(4):
                            if not region.initialized[offset + index]:
                                value = runtime.response_feature_initial[(key - 1) * 4 + index]
                                memory.store(address + index, value, 1, source='explicit response feature stack policy')
                    settings[key] = memory.load(address, 4)
        _features(runtime, settings if apply_settings else None, rbp)
        material = state.current
        if material.payload_mode != 1:
            accepted = verify()
            memory.store(base + 0x677D108, int(accepted), 1, source='1CDC080.response_payload_mode')
        else:
            accepted = True
        runtime._free_allocation(pointer)
    runtime.events.append(('request.response_material_verified', archived, accepted, response_id))
    locals.remove(payload)
    return finish(0 if accepted else 3, payload)


def invoke(runtime, rva, values):
    if rva == 0x1CACBB0 and len(values) == 3:
        from .primary_response_diagnostics import encode
        return encode(runtime, *values)
    if rva == 0x1CACFA0 and len(values) == 4:
        return decrypt(runtime, *values)
    if rva == 0x1CD3CB0 and len(values) in (5, 6):
        return respond(runtime, *values)
    if rva == 0x1CB0580 and len(values) == 4:
        signature, response_id, current_id, public_key = values
        return int(verify_material_signature(runtime.memory.read(signature, 64), response_id, current_id,
                                             runtime.memory.read(public_key, 33)))
    if rva == 0x1CABB60 and len(values) == 3:
        return error_message(runtime, *values)
    raise InputError('unsupported response material entry or argument count')
