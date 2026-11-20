from dataclasses import dataclass, field
import base64
import hashlib

from .errors import InputError


def device_factory_value(factory, runtime):
    from .primary_device_provider import DeviceFactory
    if isinstance(factory, DeviceFactory) and (factory.enumeration_source, factory.public_key_source) in (('windows', 'windows'), ('raw_os', 'raw_os')):
        from .primary_vm import PrimarySemanticUnavailable
        if runtime is None or getattr(getattr(runtime, 'provider_profile', None), 'device_factory', None) is not factory:
            raise PrimarySemanticUnavailable('native device factory requires its matching caller runtime profile')
        return caller_device_value(runtime)
    return factory.get(runtime) if isinstance(factory, DeviceFactory) else factory.get()


def caller_device_value(runtime):
    from .primary_device_records import _locked_singleton
    from .primary_logger import _String
    from .primary_worker_consumer import _invoke
    from .primary_worker_response import _frame
    owner = _locked_singleton(runtime, 0x6751838, 0x67516A0, 32, 0x1BE5CD0)
    output, _ = _frame(runtime, 24, 'caller_context.independent_string')
    _invoke(runtime, 0x1BE77F0, owner, output)
    value = _String.read(runtime, output)
    result = value.value()
    value.destroy()
    runtime.memory.unmap(output)
    return result


def caller_empty_body_token(runtime):
    from .primary_worker_consumer import _invoke
    memory, base = runtime.memory, runtime.image_base
    _invoke(runtime, 0x75B070, base + 0x677D048)
    material = memory.read(base + 0x677D0B8, 168)
    if not any(material):
        _invoke(runtime, 0x1C572E0)
    token = memory.read(base + 0x677D0E8, 32)
    _invoke(runtime, 0x75B0A0, base + 0x677D048)
    return token


def _caller_message(runtime, line, message, severity, *arguments):
    from .primary_logger import _decode, log
    from .primary_worker_loop import _image
    image = _image()
    return log(runtime, _decode(image['logs']['empty']['file']), line, message,
               bytes.fromhex(image['tag_hex']), severity, *arguments)


def _caller_device(runtime):
    from .primary_vm import PrimarySemanticUnavailable
    memory, base = runtime.memory, runtime.image_base
    device = memory.load(base + 0x6751840, 8)
    control = memory.load(base + 0x6751848, 8)
    if control:
        count = (memory.load(control + 8, 4) + 1) & 0xFFFFFFFF
        memory.store(control + 8, count, 4, source='caller_provider.control_retain')
        count = memory.load(control + 8, 4)
        memory.store(control + 8, (count - 1) & 0xFFFFFFFF, 4,
                     source='caller_provider.control_release')
        if count == 0:
            raise PrimarySemanticUnavailable('caller provider shared-control virtual destructor and 75AD90 effects are unavailable')
    runtime.events.append(('caller_provider.device', device, control))
    return device


def provider_device_getter(runtime, receiver, output):
    from .primary_device_records import _image, _locked_singleton, cached_value
    from .primary_logger import log
    owner = _locked_singleton(runtime, 0x6751838, 0x67516A0, 32, 0x1BE5CD0)
    item = _image()['cached_getter_log']
    log(runtime, bytes.fromhex(item['source_file_hex']), 0x33, b'get x from fc.',
        bytes.fromhex(item['tag_hex']), 1)
    return cached_value(runtime, owner, output)


def _move_provider_string(runtime, destination, source):
    from .primary_logger import _String
    memory = runtime.memory
    _String.read(runtime, destination).destroy()
    memory.copy_disjoint(destination + 16, source + 16, 8, label='caller_provider.string_move_pointer')
    memory.copy_disjoint(destination, source, 16, label='caller_provider.string_move_header')
    memory.store(source, 0, 2, source='caller_provider.moved_string_empty')


def _caller_produce(runtime, material):
    from .primary_logger import _String
    from .primary_sdk import _add_owner, _invoke_values, _release_owner
    from .primary_vm import PrimarySemanticUnavailable
    from .primary_worker_response import _frame
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 24, 'caller_provider.private_string')
    receiver = memory.load(base + 0x6751840, 8)
    control = memory.load(base + 0x6751848, 8)
    if control:
        _add_owner(runtime, control)
    runtime.events.append(('caller_provider.production_device', receiver, control))
    if not receiver:
        raise PrimarySemanticUnavailable('caller provider third device is null before virtual slot10 dereference')
    target = memory.load(memory.load(receiver, 8) + 16, 8)
    if target != base + 0xBEDC00:
        raise PrimarySemanticUnavailable('caller provider third device virtual slot10 target is unavailable')
    _invoke_values(runtime, target, (receiver, frame))
    value = _String.read(runtime, frame).value()
    _move_provider_string(runtime, base + 0x67518B0, frame)
    material.value = value
    runtime.events.append(('caller_provider.raw_commit', len(value)))
    _release_owner(runtime, control)
    memory.unmap(frame)
    return value


@dataclass
class ProviderMaterial:
    value: bytes = b""
    token: bytes = b""
    timestamp: int = 0
    attempted: bool = False
    fetch_once: bool = True
    marker: int = 0
    secondary_state: int = 0xFFFFFFFF
    duration_ms: int = 0
    features: dict = field(default_factory=lambda: {1: 1, 6: 1, 0x37: 0})
    refresh_duration_ms: int = 0
    postfetch_report_once: bool = True

    def set_feature(self, key, value):
        if (type(key) is not int or not -(1 << 31) <= key < 1 << 31 or
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF):
            raise InputError("provider feature requires signed32 key and unsigned32 raw value")
        self.features[key] = value

    def update_switch(self, state):
        if type(state) is not int or not 0 <= state <= 0xFFFFFFFF:
            raise InputError("provider Switch state must be unsigned32")
        self.features[6] = state if state in (0, 1) else 2

    def update_secconf(self, records):
        records = tuple(records)
        for record in records:
            if (not isinstance(record, tuple) or len(record) != 2 or type(record[0]) is not int or
                    not -(1 << 31) <= record[0] < 1 << 31 or type(record[1]) is not int or
                    not 0 <= record[1] <= 0xFFFFFFFF):
                raise InputError("SecConf records require signed32 keys and unsigned32 states")
        for key in range(0xA, 0x41):
            self.features[key] = 0
        for key, state in records:
            if key <= 0x40:
                self.features[key] = int(state != 0)

    def read(self, environment, profile, runtime, features=None):
        return self._read(environment, profile, runtime, features)[0]

    def caller_values(self, environment, profile, runtime):
        return self._read(environment, profile, runtime, caller='caller')

    def _read(self, environment, profile, runtime, features=None, *, caller=False):
        from .primary_sign import filetime_seconds, qpc_nanoseconds
        from .primary_vm import PrimarySemanticUnavailable, signed
        if caller:
            from .primary_provider_cache import initialize
            origin = 'caller' if caller is True else caller
            initialize(runtime, origin)
            if getattr(runtime, 'provider_cache_seed_pending', False):
                runtime.events.append(('provider_cache.seed_binding', origin, len(self.value), len(self.token),
                                       self.timestamp, self.attempted, self.fetch_once, self.marker, self.duration_ms))
                runtime.provider_cache_seed_pending = False
        features = self.features if features is None else features
        lock = runtime.image_base + 0x67518F0
        if runtime.locks.get(lock, 0):
            raise PrimarySemanticUnavailable("material provider waits on an owned mutex")
        runtime.locks[lock] = 1
        runtime.events.append(("75AF50.lock", lock))
        try:
            if features.get(6, 2) != 1:
                if caller:
                    _caller_message(runtime, 0x2AC, b'getXwId but switch is close', 1)
                return b"", b""
            if environment is None:
                raise PrimarySemanticUnavailable("material provider has no bound clock environment")
            now = filetime_seconds(environment.filetime())
            if caller:
                runtime.events.append(('caller_provider.clock', now))
            delta = signed((now - self.timestamp) & 0xFFFFFFFFFFFFFFFF, 64)
            if self.value and (self.timestamp == 0 or delta <= (
                    runtime.memory.load(runtime.image_base + 0x6751908, 8, signed=True) if caller else 14400)):
                return self.value, self.token
            if caller:
                if not _caller_device(runtime):
                    _caller_message(runtime, 0x2B2, b'getXwId but mDevice is null', 2)
                    return self.value, self.token
                _caller_message(runtime, 0x2B4, b'xwid empty or expired !', 2)
                from .primary_worker_loop import _initialize
                _initialize(runtime, 1)
                if runtime.memory.load(runtime.image_base + 0x67516D0, 4) == 0:
                    _caller_message(runtime, 0x264, b'app background!', 2)
                    return self.value, self.token
                if self.attempted & 1:
                    return self.value, self.token
                if not _caller_device(runtime):
                    _caller_message(runtime, 0x26C, b'getDevice error!', 2)
                    return self.value, self.token
            if (not caller and (profile is None or self.secondary_state & 0xFFFFFFFF == 0)) or self.attempted & 1:
                return self.value, self.token
            if caller:
                _caller_message(runtime, 0x26F, b's c n x', 1)
            self.attempted = True
            if caller:
                runtime.memory.store(runtime.image_base + 0x67518E0, 1, 1, source='caller_provider.attempted_commit')
            if self.fetch_once:
                started = qpc_nanoseconds(*environment.qpc())
                self.value = (_caller_produce(runtime, self) if caller else
                              device_factory_value(profile.device_factory, runtime) if profile.device_factory is not None
                              else profile.xfolder_bytes)
                if not isinstance(self.value, bytes):
                    raise InputError("material provider must return observed source bytes")
                if caller:
                    _caller_message(runtime, 0x274, b'xw L2ID from file:%d', 1, len(self.value))
                finished = qpc_nanoseconds(*environment.qpc())
                elapsed = signed((finished - started) & 0xFFFFFFFFFFFFFFFF, 64)
                self.duration_ms = (abs(elapsed) // 1000000) * (-1 if elapsed < 0 else 1)
                if caller:
                    runtime.memory.store(runtime.image_base + 0x6751950, self.duration_ms, 8,
                                         source='caller_provider.duration_commit')
                if self.value:
                    from .primary_tokens import provider_token
                    token = provider_token(runtime, self.value)
                    runtime.publish_provider_token(token)
                    self.token = token
                    if caller:
                        from .primary_logger import _String
                        from .primary_worker_response import _frame
                        frame, _ = _frame(runtime, 24, 'caller_provider.private_token')
                        _String.construct(runtime, token).write_to(frame)
                        _move_provider_string(runtime, runtime.image_base + 0x67518C8, frame)
                        runtime.memory.unmap(frame)
                    self.timestamp = filetime_seconds(environment.filetime())
                    self.marker = 1
                    if caller:
                        runtime.memory.store(runtime.image_base + 0x67518E8, self.timestamp, 8,
                                             source='caller_provider.timestamp_commit')
                        runtime.memory.store(runtime.image_base + 0x675198A, 1, 1,
                                             source='caller_provider.marker_commit')
                else:
                    self.marker = 0
                    if caller:
                        runtime.memory.store(runtime.image_base + 0x675198A, 0, 1,
                                             source='caller_provider.marker_commit')
                        _caller_message(runtime, 0x27E, b'getXwIdFromFileCache empty', 2)
                self.fetch_once = False
                if caller:
                    runtime.memory.store(runtime.image_base + 0x6751968, 0, 1,
                                         source='caller_provider.fetch_once_commit')
            route = "direct" if (self.marker == 0 and not self.value and features.get(0x37) == 1) else "enqueue"
            runtime.schedule_provider_refresh(self, direct=route == "direct", caller=bool(caller))
            return self.value, self.token
        finally:
            runtime.locks[lock] = 0
            runtime.events.append(("75AFC0.unlock", lock))

    def refresh(self, runtime):
        from .primary_sign import filetime_seconds, qpc_nanoseconds
        from .primary_vm import PrimarySemanticUnavailable, signed
        environment, profile = runtime.provider_environment, runtime.provider_profile
        if environment is None or profile is None:
            raise PrimarySemanticUnavailable("provider postfetch direct/worker needs its live provider binding")
        now = filetime_seconds(environment.filetime())
        started = qpc_nanoseconds(*environment.qpc())
        if profile.device_factory is not None:
            getter = getattr(profile.device_factory, "get_for_refresh", None)
            if not callable(getter):
                raise PrimarySemanticUnavailable("provider postfetch forced getter BEDB20/1BE6150 binding is unavailable")
            value = getter(runtime)
        else:
            value = profile.xfolder_bytes
        if not isinstance(value, bytes):
            raise InputError("provider postfetch getter requires observed source bytes")
        finished = qpc_nanoseconds(*environment.qpc())
        elapsed = signed((finished - started) & 0xFFFFFFFFFFFFFFFF, 64)
        self.refresh_duration_ms = (abs(elapsed) // 1000000) * (-1 if elapsed < 0 else 1)
        runtime.events.append(("BD0A00.provider_observation", len(value), now, self.refresh_duration_ms))
        if value:
            from .primary_tokens import provider_token
            token = provider_token(runtime, value)
            runtime.publish_provider_token(token, caller="postfetch")
            self.value = value
            runtime.events.append(("BD1B0A.provider_raw_commit",))
            self.token = token
            runtime.events.append(("BD1B1D.provider_token_commit",))
            self.timestamp = now
            runtime.events.append(("BD1B22.provider_time_commit", now))
        if self.postfetch_report_once:
            self.postfetch_report_once = False
            from .primary_postfetch import ProviderTelemetryRecord
            record = ProviderTelemetryRecord.nonempty_refresh(self) if value else ProviderTelemetryRecord.empty_refresh(self)
            runtime.schedule_provider_telemetry(record)
        self.attempted = False
        runtime.events.append(("BD31BA.provider_refresh_release",))


def caller_context(fields):
    if not isinstance(fields, tuple) or len(fields) != 3 or any(not isinstance(v, bytes) for v in fields):
        raise InputError("caller context requires its three source byte strings")
    result = bytearray()
    for tag, value in zip((10, 18, 26), fields):
        if not value:
            continue
        result.append(tag)
        length = len(value)
        while length >= 128:
            result.append((length & 127) | 128)
            length >>= 7
        result.append(length)
        result.extend(value)
    return bytes(result)


def device_digest(value):
    if not isinstance(value, bytes):
        raise InputError("WinDevice xfolder value must be bytes")
    return base64.b64encode(hashlib.md5(value).digest()[:9])


def request_digest(d, fields, payload):
    return request_context_digest(d, caller_context(fields), payload)


def request_context_digest(d, context, payload):
    if any(not isinstance(value, bytes) for value in (d, context, payload)):
        raise InputError("request digest requires source bytes")
    data = d + context + payload
    if len(data) > 0xFFFFFFFF:
        raise InputError("request digest exceeds its source DWORD length domain")
    return hashlib.md5(data).digest()


def payload_token(payload, field_number):
    if not isinstance(payload, bytes) or field_number not in (3, 6):
        raise InputError("secure token extraction requires source payload bytes and field3 or field6")
    offset = 0
    result = bytearray()

    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset == len(payload):
                return value, False
            byte = payload[offset]
            offset += 1
            value = (value | ((byte & 127) << shift)) & 0xFFFFFFFFFFFFFFFF
            if byte < 128:
                return value, True
        offset = len(payload)
        return value, False

    while offset < len(payload):
        tag, ok = varint()
        if not ok:
            return b""
        if tag & 0x7FFFFFFF8 == field_number << 3:
            length, ok = varint()
            if length > 0xFFFFFFFF - offset:
                raise InputError("secure token offset and length exceed the supported nonwrapping DWORD domain")
            if not ok or length > len(payload) - offset:
                return b""
            result.extend(payload[offset:offset + length])
            offset += length
        elif tag & 7 == 0:
            varint()
        elif tag & 7 == 2:
            length, ok = varint()
            if length > 0xFFFFFFFF - offset:
                raise InputError("secure token offset and length exceed the supported nonwrapping DWORD domain")
            if ok and length <= len(payload) - offset:
                offset += length
    return bytes(result)


def empty_body_token(qpc, random_bytes):
    from .primary_cocos import seed_mt, next_mt
    from .primary_memory import PrimaryMemory
    from .primary_sign import qpc_nanoseconds
    memory = PrimaryMemory()
    memory.map(0x1000, bytearray(2504), name="private empty-body MT state", initialized=False)

    def mt_bytes():
        counter, frequency = qpc()
        seed_mt(memory, 0x1000, qpc_nanoseconds(counter, frequency) & 0xFFFFFFFF)
        words = [next_mt(memory, 0x1000) for _ in range(9)]
        return b"".join(word.to_bytes(4, "little") for word in words[:8])

    first = mt_bytes()
    random_words = [random_bytes(4) for _ in range(9)]
    if any(not isinstance(value, bytes) or len(value) != 4 for value in random_words):
        raise InputError("empty-body rand_s provider must produce nine exact successful DWORDs")
    random = b"".join(random_words[:8])
    second = mt_bytes()
    return bytes(a ^ b ^ c for a, b, c in zip(first, random, second))


@dataclass
class ExchangeMaterial:
    version: int = 0
    prefix: bytes = bytes(8)
    value: bytes = b""

    def update(self, packet):
        if not isinstance(packet, bytes) or len(packet) < 6:
            raise InputError("exchange material needs BE32 version and BE16 image length")
        version = int.from_bytes(packet[:4], "big")
        length = int.from_bytes(packet[4:6], "big")
        if length + 6 > len(packet):
            raise InputError("exchange material image is truncated")
        image = packet[6:6 + length]
        if len(image) < 54 or image[:2] != b"BM" or int.from_bytes(image[28:30], "little") != 24:
            raise InputError("exchange material needs a readable 24-bit BMP carrier")
        offset = int.from_bytes(image[10:14], "little")
        width = int.from_bytes(image[18:22], "little")
        height = int.from_bytes(image[22:26], "little")
        area = (width * height) & 0xFFFFFFFF
        if ((offset + 3 * area) & 0xFFFFFFFF) > length or offset + 40 > length:
            raise InputError("exchange material carrier is outside its readable image")

        def extract(count):
            if offset + 8 * count > length:
                raise InputError("exchange material bits extend beyond their readable carrier")
            return bytes(sum((image[offset + 8 * j + k] & 1) << (7 - k) for k in range(8))
                         for j in range(count))

        header = extract(5)
        count = header[4]
        if int.from_bytes(header[:4], "little") != version or not count or count > ((area - 5) & 0xFFFFFFFF):
            raise InputError("exchange material embedded version or length is invalid")
        value = extract(5 + count)[5:]
        if version == self.version:
            return False
        self.version = version
        self.prefix = value[:8] + self.prefix[min(len(value), 8):]
        self.value = value
        return True

    def signing_value(self):
        return self.prefix if self.version else b""


@dataclass
class ResponseMaterial:
    expiry: int = 0
    value: bytes = b""
    bound: bytes = b""
    retries: int = 0

    def valid(self, now):
        return bool(self.value) and self.expiry > now

    def signing_value(self, fallback, now, features):
        if features.get(1, 2) != 1:
            return fallback
        snapshot = ResponseMaterial(expiry=self.expiry, value=self.value, bound=self.bound)
        if not snapshot.value:
            return fallback
        current = now() if callable(now) else now
        return snapshot.value if snapshot.expiry > current else fallback

    def refresh_needed(self, now, bound, threshold=300):
        delta = (self.expiry - now) & 0xFFFFFFFFFFFFFFFF
        if delta >= 1 << 63:
            delta -= 1 << 64
        return delta < threshold or (bound not in (b"", b"0") and bound != self.bound)

    def update(self, value, expiry=0, bound=b"", *, accepted=True):
        if not accepted:
            self.retries += 1
            return False
        if (not isinstance(value, bytes) or not isinstance(bound, bytes) or
                type(expiry) is not int or not -(1 << 63) <= expiry < 1 << 63):
            raise InputError("response material requires bytes, signed expiry and bound bytes")
        self.retries = 0
        if not value:
            return False
        self.expiry, self.value, self.bound = expiry, value, bound
        return True


class _RuntimeResponseMaterial(ResponseMaterial):
    def __init__(self, runtime):
        self.runtime = runtime
        self.address = runtime.image_base + 0x6751840

    @property
    def expiry(self):
        return self.runtime.memory.load(self.address + 16, 8, signed=True)

    @expiry.setter
    def expiry(self, value):
        if type(value) is not int or not -(1 << 63) <= value < 1 << 63:
            raise InputError('response material expiry must be signed64')
        from .primary_provider_cache import initialize
        initialize(self.runtime)
        self.runtime.memory.store(self.address + 16, value, 8, source='response_material.expiry')

    def _read_string(self, offset):
        from .primary_logger import _String
        return _String.read(self.runtime, self.address + offset).value()

    def _write_string(self, offset, value):
        from .primary_logger import _String
        from .primary_worker_response import _assign
        if not isinstance(value, bytes):
            raise InputError('response material strings must be bytes')
        from .primary_provider_cache import initialize
        initialize(self.runtime)
        temporary = _String.construct(self.runtime, value)
        try:
            _assign(self.runtime, self.address + offset, temporary)
        finally:
            temporary.destroy()

    @property
    def value(self):
        return self._read_string(24)

    @value.setter
    def value(self, value):
        self._write_string(24, value)

    @property
    def bound(self):
        return self._read_string(48)

    @bound.setter
    def bound(self, value):
        self._write_string(48, value)

    @property
    def retries(self):
        return self.runtime.memory.load(self.address + 100, 4)

    @retries.setter
    def retries(self, value):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise InputError('response material retries must be unsigned32')
        from .primary_provider_cache import initialize
        initialize(self.runtime)
        self.runtime.memory.store(self.address + 100, value, 4, source='response_material.failure_count')

    def update(self, value, expiry=0, bound=b'', *, accepted=True):
        from .primary_provider_cache import initialize
        initialize(self.runtime)
        if not accepted:
            self.retries = (self.retries + 1) & 0xFFFFFFFF
            return False
        return super().update(value, expiry, bound, accepted=accepted)
