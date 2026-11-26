import hmac

from .errors import InputError
from .primary_cocos import next_mt, seed_mt
from .primary_logger import _String, log
from .primary_request_capi import derive_request_shared_with_capi
from .primary_request_encoder import RequestKeyMaterial, _image, encode_cached_material_request
from .primary_request_material import MaterialStateRequest, RequestMaterial, RequestMaterialCacheEntry, RequestMaterialState
from .primary_request_random import RequestRandom
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _field, _integer, _invoke, _zero_string
from .primary_worker_response import _assign, _frame, _image as _response_image, _owner


def _signed(value):
    return value - (1 << 64) if value >> 63 else value


class _Random(RequestRandom):
    def __init__(self, runtime, token):
        self.runtime, self.token = runtime, token

    def snapshot(self):
        return self.runtime.memory.read(self.runtime.image_base + 0x677C2D8, 2504)

    def draw_bytes(self, count):
        runtime, memory, base = self.runtime, self.runtime.memory, self.runtime.image_base
        guard = memory.load(base + 0x677C2D0, 4)
        if not guard & 1:
            memory.store(base + 0x677C2D0, guard | 1, 4, source='1CA8A7C.request_random_device_guard')
            _String.construct(runtime, b'/dev/urandom').write_to(self.token)
            _invoke(runtime, 0x7602D0, base + 0x677C2CC, self.token)
            _invoke(runtime, 0x3E680B4, base + 0x1C00F80)
            guard = memory.load(base + 0x677C2D0, 4)
        if not guard & 2:
            memory.store(base + 0x677C2D0, guard | 2, 4, source='1CA8AF7.request_mt_guard')
            seed = _invoke(runtime, 0x7603B0, base + 0x677C2CC)
            seed_mt(memory, base + 0x677C2D8, seed)
        value = next_mt(memory, base + 0x677C2D8)
        output = bytearray()
        for index in range(count):
            output.append((value >> (8 * (index & 3))) & 255)
            if index & 3 == 3:
                value = next_mt(memory, base + 0x677C2D8)
        return bytes(output)


class _Capi:
    def __init__(self, runtime, frame):
        self.runtime, self.frame = runtime, frame
        self.buffers = {}
        from .primary_windows_request_capi import begin
        self.ticket=begin(self)

    def acquire(self, phase):
        if self.ticket is not None:
            from .primary_windows_request_capi import check_use
            check_use(self,'acquire',phase)
        if self.runtime.request_capi is None:
            raise PrimarySemanticUnavailable('1C572E0 requires the actual CAPI service binding')
        return self.runtime.request_capi.acquire(phase)

    def generate(self, phase, handle, buffer):
        if self.ticket is not None:
            from .primary_windows_request_capi import check_use
            check_use(self,'generate',phase,buffer,handle)
        self.buffers[phase] = buffer
        address = self.frame + (0x50 if phase == 'private' else 0x30)
        region, offset = self.runtime.memory._span(address, 32)
        for index in range(32):
            if region.initialized[offset + index] and not buffer._known[index]:
                buffer._data[index] = region.data[offset + index]
                buffer._known[index] = 1
        try:
            return self.runtime.request_capi.generate(phase, handle, buffer)
        finally:
            primary=__import__('sys').exception()
            try:self.sync()
            except BaseException as failure:
                if primary is None:raise
                primary.add_note('request CAPI known-byte sync also failed: '+type(failure).__name__)

    def release(self, phase, handle):
        if self.ticket is not None:
            from .primary_windows_request_capi import check_use
            check_use(self,'release',phase,handle=handle)
        return self.runtime.request_capi.release(phase, handle)

    def scratch(self, offset):
        region, start = self.runtime.memory._span(self.frame + offset, 32)
        if all(region.initialized[start:start + 32]):
            return bytes(region.data[start:start + 32])
        return None

    def sync(self):
        if self.ticket is not None:self.ticket.check()
        for phase, buffer in self.buffers.items():
            address = self.frame + (0x50 if phase == 'private' else 0x30)
            cursor = 0
            while cursor < 32:
                end = cursor + 1
                while end < 32 and buffer._known[end] == buffer._known[cursor]:
                    end += 1
                if buffer._known[cursor]:
                    self.runtime.memory.write(address + cursor, bytes(buffer._data[cursor:end]), source='request.CAPI_buffer')
                cursor = end


def _hmac(runtime, rbp, key, message):
    memory, base = runtime.memory, runtime.image_base
    memory.store(rbp + 0x130, base + 0x414AE10, 8, source='request.hkdf_descriptor')
    memory.store(rbp + 0x60, 0, 8, source='request.hkdf_pads_initial')
    context = _invoke(runtime, 0x3E92E00, 1, 108)
    memory.store(rbp + 0x1B0, context, 8, source='request.hkdf_context')
    pads = 0
    result = None
    if context:
        pads = _invoke(runtime, 0x3E92E00, 2, 64)
        memory.store(rbp + 0x60, pads, 8, source='request.hkdf_pads')
        if pads:
            normalized = key.ljust(64, b'\0')
            memory.write(pads, bytes(value ^ 0x36 for value in normalized) +
                         bytes(value ^ 0x5C for value in normalized), source='request.hkdf_hmac_pads')
            result = hmac.digest(key, message, 'sha256')
        memory.write(context, bytes(108), source='request.hkdf_context_scrub')
        _invoke(runtime, 0x3E94F90, context)
    if pads:
        memory.write(pads, bytes(128), source='request.hkdf_pads_scrub')
        _invoke(runtime, 0x3E94F90, pads)
    for offset in (0x130, 0x1B0, 0x60):
        memory.store(rbp + offset, 0, 8, source='request.hkdf_ownership_clear')
    return result


def _hkdf(runtime, rbp, shared_x):
    extracted = _hmac(runtime, rbp, bytes(32), shared_x)
    result = None if extracted is None else _hmac(runtime, rbp, extracted, b'\1')
    for offset in (0xB0, 0x10):
        runtime.memory.write(rbp + offset, bytes(32), source='request.hkdf_local_scrub')
    return result


def _hex_string(runtime, value, address):
    from .primary_worker_consumer import _invoke
    result = _String(runtime, bytes(24), b'\1' * 24)
    result.write_to(address)
    for byte in value.hex().encode('ascii'):
        previous = result.value()
        capacity = (result.get(0, 8) & ~1) - 1 if result.get(0, 1) & 1 else 22
        if len(previous) == capacity:
            physical = (max(2 * capacity, capacity + 1) | 15) + 1
            pointer = _invoke(runtime, 0xB75000, physical)
            runtime.memory.write(pointer, previous + bytes([byte, 0]), source='75C6AC.request_hex_growth')
            result.destroy()
            result = _String(runtime)
            result.set(0, (physical | 1).to_bytes(8, 'little'))
            result.set(8, (len(previous) + 1).to_bytes(8, 'little'))
            result.set(16, pointer.to_bytes(8, 'little'))
        else:
            result.append(bytes([byte]))
        result.write_to(address)
    return result


def produce(runtime):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x4D8, '1C572E0.material_producer_frame')
    empty = memory.load(base + 0x677D0B8, 1) == 0 and not any(memory.read(base + 0x677D0B8, 168))
    deadline = memory.load(base + 0x677D0D8, 8)
    now = _invoke(runtime, 0x3E8ED3C, 0)
    if not empty and deadline >= now:
        memory.unmap(frame)
        return None
    encoded_peer = bytes.fromhex(_image()['encoded_peer_hex'])
    memory.write(base + 0x677D090, encoded_peer, source='1C55130.request_encoded_peer')
    mask = bytes.fromhex(_image()['peer_mask_hex'])
    rotated = encoded_peer[25:] + encoded_peer[:25]
    peer = bytes(byte ^ mask[index & 7] for index, byte in enumerate(rotated))
    memory.write(base + 0x677D118, peer, source='1C571A0.request_peer')
    service = _Capi(runtime, frame)
    try:
        material = derive_request_shared_with_capi(service, encoded_peer=encoded_peer,
                                                     previous_public_key=memory.read(base + 0x677D139, 33),
                                                     private_scratch=service.scratch(0x50),
                                                     blinding_scratch=service.scratch(0x30),
                                                     public_key_written=lambda value: memory.write(base + 0x677D139, value,
                                                                                                   source='request.public_key'))
    finally:
        primary=__import__('sys').exception()
        try:service.sync()
        except BaseException as failure:
            if primary is None:raise
            primary.add_note('request CAPI known-byte sync also failed: '+type(failure).__name__)
        finally:
            from .primary_windows_request_capi import end
            end(service.ticket)
    memory.write(base + 0x677D0B8, material.shared_x, source='1C91EF5.request_shared_x')
    _invoke(runtime, 0x1C54E10, base + 0x677D0E8, 32)
    memory.write(base + 0x677D110, _Random(runtime, frame + 0x258).draw_bytes(8), source='request.message_id')
    memory.write(base + 0x677D0D8, b'\xff' * 16, source='1C92273.request_deadlines')
    key = _hkdf(runtime, rbp, material.shared_x)
    source_file = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\platforms\\Windows\\..\\..\\channel\\include\\crypt\\o3_channel_encrypt.h'
    if key is None:
        log(runtime, source_file, 0x122, b'hkdf failed', b'[FGESDK]', 2)
        shared_hex = _hex_string(runtime, memory.read(base + 0x677D0B8, 32), rbp + 0xB0)
        log(runtime, source_file, 0x124, b'hkdf failed, share_key_before:%s', b'[FGESDK]', 2,
            shared_hex.value(), feature_key=5)
        shared_hex.destroy()
        succeeded = 0
    else:
        memory.write(base + 0x677D0B8, key, source='1CA6727.request_key')
        succeeded = 1
    memory.store(base + 0x677D109, succeeded, 1, source='1CA6CE0.request_flag81')
    log(runtime, source_file, 0x12B, b'gen new channel', b'[FGESDK]', 2)
    memory.unmap(frame)
    return None


class _MaterialState(RequestMaterialState):
    def __init__(self, runtime, frame):
        self.runtime, self.frame = runtime, frame
        region,offset=runtime.memory._span(frame,0x448)
        if offset or region.address!=frame or len(region.data)!=0x448:
            raise InputError('request encoder requires its exact original frame')
        self.frame_region=(frame,region,0x448)
        self.random = _Random(runtime, frame + 0x258)
        self.encoded_peer = runtime.memory.read(runtime.image_base + 0x677D090, 33)
        self.cache = []
        begin, end, capacity = self.vector()
        for pointer in range(begin, end, 192):
            self.cache.append(RequestMaterialCacheEntry(_String.read(runtime, pointer).value(),
                                                        RequestMaterial(runtime.memory.read(pointer + 24, 168))))

    @property
    def current(self):
        return RequestMaterial(self.runtime.memory.read(self.runtime.image_base + 0x677D0B8, 168))

    @current.setter
    def current(self, value):
        self.runtime.memory.write(self.runtime.image_base + 0x677D0B8, value.raw, source='request.material_state')

    def vector(self):
        memory, base = self.runtime.memory, self.runtime.image_base
        begin, end, capacity = (memory.load(base + rva, 8) for rva in (0x677D070, 0x677D078, 0x677D080))
        if (not begin <= end <= capacity or (end - begin) % 192 or (capacity - begin) % 192 or
                (capacity - begin) // 192 > 4096):
            raise PrimaryProgramLimit('request material cache vector is outside its bounded valid domain')
        return begin, end, capacity

    def remember(self, key, material):
        runtime, memory, base = self.runtime, self.runtime.memory, self.runtime.image_base
        begin, end, capacity = self.vector()
        count = (end - begin) // 192
        if count == 50:
            _String.read(runtime, end - 192).destroy()
            end -= 192
            memory.store(base + 0x677D078, end, 8, source='request.cache_pop_back')
            count -= 1
        value = _String.construct(runtime, key)
        if end == capacity:
            old_capacity = (capacity - begin) // 192
            new_capacity = max(old_capacity * 2, count + 1)
            allocated = runtime._operator_new(new_capacity * 192)
            for index in range(count):
                self.move(begin + index * 192, allocated + (index + 1) * 192)
            if begin:
                runtime._free_allocation(begin)
            begin, end, capacity = allocated, allocated + count * 192, allocated + new_capacity * 192
            memory.store(base + 0x677D070, begin, 8, source='request.cache_new_begin')
            memory.store(base + 0x677D080, capacity, 8, source='request.cache_new_capacity')
        else:
            for index in range(count - 1, -1, -1):
                self.move(begin + index * 192, begin + (index + 1) * 192)
        value.write_to(begin)
        memory.write(begin + 24, material.raw, source='request.cache_material')
        memory.store(base + 0x677D078, end + 192, 8, source='request.cache_new_end')
        super().remember(key, material)

    def move(self, source, destination):
        _String.read(self.runtime, source).write_to(destination)
        self.runtime.memory.write(destination + 24, self.runtime.memory.read(source + 24, 168), source='request.cache_move_material')

    def produce(self):
        self.encoded_peer = bytes.fromhex(_image()['encoded_peer_hex'])
        return _invoke(self.runtime, 0x1C572E0)


def _serialize(runtime, tag, result, state):
    value = _zero_string(runtime)
    if tag:
        _field(value, 10, tag)
    if state.current.payload_mode:
        _field(value, 18, result.request.ciphertext)
        _field(value, 26, state.current.device_random)
    else:
        current = state.current
        _field(value, 18, current.public_key)
        if current.public_key_flag != 1:
            _integer(value, 24)
            _integer(value, 1)
        _field(value, 34, state.encoded_peer.hex().encode('ascii'))
        _field(value, 42, result.request.ciphertext)
        _field(value, 50, current.device_random)
        _field(value, 58, result.request.fingerprint)
        _integer(value, 64)
        _integer(value, 3)
    if value.value() != result.request.wire:
        raise InputError('request runtime serialization differs from its computed field encoding')
    return value


def _clock_mismatch(runtime, eligibility, material):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x240, '1CAB2B0.clock_mismatch_frame')
    event, columns = rbp - 0x48, rbp + 0x170
    memory.store(event, base + 0x4148CD8, 8, source='1CAB546.clock_mismatch_event_vtable')
    _String.construct(runtime, b'channel_analyze').write_to(event + 8)
    for offset in range(32, 200, 24):
        _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(event + offset)
    memory.write(event + 200, bytes(192), source='1CAB54A.clock_mismatch_event_columns')
    memory.write(columns, bytes(48), source='1CAB7C4.clock_mismatch_empty_columns')
    try:
        _String.construct(runtime, b'expire').write_to(event + 224)
        for offset, value in ((296, eligibility.wall_now), (320, material.wall_deadline),
                              (344, _signed(eligibility.monotonic_now)), (368, material.monotonic_deadline)):
            _String.construct(runtime, str(value).encode('ascii')).write_to(event + offset)
        _owner(runtime, _response_image())
        _invoke(runtime, 0x1BEFC10, base + 0x67519B8, event, columns, 1, 10, 0)
    finally:
        for offset in (24, 0):
            _String.read(runtime, columns + offset).destroy()
        _invoke(runtime, 0x1BF4B40, event)
        memory.unmap(frame)


def encode(runtime, output, payload, tag, status, metadata, extra_status):
    memory, base = runtime.memory, runtime.image_base
    lock = base + 0x677D048
    if lock not in runtime.locks:
        raise PrimarySemanticUnavailable('1CC6E10 requires the initialized request critical section')
    runtime.locks[lock] += 1
    runtime.events.append(('EnterCriticalSection', lock))
    frame, _ = _frame(runtime, 0x448, '1CC6E10.request_encoder_frame')
    _assign(runtime, metadata, _zero_string(runtime))
    memory.store(extra_status, 0, 4, source='1CC6E77.request_extra_status')
    memory.store(status, 1, 4, source='1CC6E7D.request_initial_status')
    state = _MaterialState(runtime, frame)

    def wall():
        return _signed(_invoke(runtime, 0x3E8ED3C, 0))

    def monotonic():
        _invoke(runtime, 0x759B30, frame + 0x28)
        return memory.load(frame + 0x28, 8, signed=True)

    tag_bytes, payload_bytes = _String.read(runtime, tag).value(), _String.read(runtime, payload).value()
    regenerated = state.current.empty
    if not regenerated:
        eligibility = state.eligibility(wall(), monotonic())
        if eligibility.report_clock_mismatch:
            _clock_mismatch(runtime, eligibility, state.current)
        if eligibility.refresh:
            state.reset()
            regenerated = True
    if regenerated:
        state.produce()
    current = state.current
    result_status = int(current.payload_mode != 0)
    memory.store(status, result_status, 4, source='request.encoded_status')
    material = RequestKeyMaterial(state.encoded_peer, current.public_key, current.peer_key, b'', current.key)
    from .primary_request_fingerprint import source_request_fingerprint
    request = encode_cached_material_request(tag_bytes, payload_bytes, material, current.device_random,
                                             current.message_id, state.random, payload_mode=current.payload_mode,
                                             public_key_flag=current.public_key_flag,
                                             fingerprint_operation=lambda digest, nonce: source_request_fingerprint(runtime, digest, nonce))
    result = MaterialStateRequest(request, result_status, current.device_random, 0, regenerated)
    metadata_value = _String.construct(runtime, result.metadata)
    _assign(runtime, metadata, metadata_value)
    metadata_value.destroy()
    packet = _serialize(runtime, tag_bytes, result, state)
    packet.write_to(output)
    runtime.events.append(('request.encoder_complete', len(result.request.wire), result.status, result.regenerated))
    runtime.locks[lock] -= 1
    runtime.events.append(('LeaveCriticalSection', lock))
    memory.unmap(frame)
    return output


def invoke(runtime, rva, values):
    if rva == 0x1C572E0 and not values:
        return produce(runtime)
    if rva == 0x1CC6E10 and len(values) == 6:
        return encode(runtime, *values)
    if rva == 0x1C00F80 and not values:
        return _invoke(runtime, 0x28F0, runtime.image_base + 0x677C2CC)
    raise InputError('unsupported request encoder entry or argument count')
