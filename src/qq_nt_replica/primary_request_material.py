from dataclasses import dataclass
import time

from .errors import InputError
from .primary_request_encoder import RequestKeyMaterial, EncodedMaterialRequest, _bytes, _image, derive_request_material, encode_cached_material_request
from .primary_request_random import RequestRandom, _system_word, _word, device_random_bytes
from .primary_request_capi import SystemRequestCapi, derive_request_material_with_capi
from .primary_vm import PrimarySemanticUnavailable
from .wire import require_bytes


_U64 = (1 << 64) - 1


def _clock(value, name):
    if type(value) is not int or not -(1 << 63) <= value < (1 << 63):
        raise InputError(name + ' requires a signed 64-bit clock value')
    return value


def _wall_seconds():
    return time.time_ns() // 1000000000


@dataclass(frozen=True)
class RequestMaterial:
    raw: bytes

    def __post_init__(self):
        _bytes(self.raw, 168, 'request material state')

    @property
    def empty(self):
        return not any(self.raw)

    @property
    def key(self):
        return self.raw[:32]

    @property
    def wall_deadline(self):
        return int.from_bytes(self.raw[32:40], 'little')

    @property
    def monotonic_deadline(self):
        return int.from_bytes(self.raw[40:48], 'little')

    @property
    def device_random(self):
        return self.raw[48:80]

    @property
    def payload_mode(self):
        return self.raw[80]

    @property
    def public_key_flag(self):
        return self.raw[81]

    @property
    def message_id(self):
        return int.from_bytes(self.raw[88:96], 'little')

    @property
    def peer_key(self):
        return self.raw[96:129]

    @property
    def public_key(self):
        return self.raw[129:162]


@dataclass(frozen=True)
class RequestMaterialCacheEntry:
    key: bytes
    material: RequestMaterial

    def __post_init__(self):
        require_bytes(self.key, 'request material cache key')
        if not isinstance(self.material, RequestMaterial):
            raise InputError('request material cache requires a complete material state')


@dataclass(frozen=True)
class RequestMaterialEligibility:
    wall_now: int
    monotonic_now: int
    wall_expired: bool
    monotonic_expired: bool

    @property
    def refresh(self):
        return self.wall_expired and self.monotonic_expired

    @property
    def report_clock_mismatch(self):
        return self.wall_expired and not self.monotonic_expired


@dataclass(frozen=True)
class MaterialStateRequest:
    request: EncodedMaterialRequest
    status: int
    metadata: bytes
    extra_status: int
    regenerated: bool


class RequestMaterialState:
    def __init__(self, material=None, *, random=None, cache=(), encoded_peer=None):
        self.current = RequestMaterial(bytes(168)) if material is None else material
        if not isinstance(self.current, RequestMaterial):
            raise InputError('request material state requires a complete material snapshot')
        if random is not None and not isinstance(random, RequestRandom):
            raise InputError('request material state requires current RequestRandom state')
        self.random = random
        self.cache = list(cache)
        if any(not isinstance(entry, RequestMaterialCacheEntry) for entry in self.cache):
            raise InputError('request material cache requires complete entries')
        self.encoded_peer = bytes.fromhex(_image()['encoded_peer_hex']) if encoded_peer is None else encoded_peer
        _bytes(self.encoded_peer, 33, 'encoded request peer')

    def remember(self, key, material):
        entry = RequestMaterialCacheEntry(key, material)
        if len(self.cache) == 50:
            self.cache.pop()
        self.cache.insert(0, entry)

    def reset(self):
        if self.current.empty:
            return False
        self.remember(self.current.device_random, self.current)
        self.current = RequestMaterial(bytes(168))
        return True

    def lookup(self, key):
        require_bytes(key, 'request material lookup key')
        for entry in self.cache:
            if entry.key == key:
                return entry.material, True
        return self.current, False

    def eligibility(self, wall_seconds, monotonic_ns):
        wall = _clock(wall_seconds, 'request wall clock') & _U64
        nanoseconds = _clock(monotonic_ns, 'request monotonic clock')
        seconds = abs(nanoseconds) // 1000000000
        seconds = (-seconds if nanoseconds < 0 else seconds) & _U64
        return RequestMaterialEligibility(wall, seconds, self.current.wall_deadline < wall,
                                           self.current.monotonic_deadline < seconds)

    def _produce(self, private_entropy, blinding_entropy, clock_ns, random_word, capi, private_scratch, blinding_scratch):
        image = _image()
        self.encoded_peer = bytes.fromhex(image['encoded_peer_hex'])
        mask = bytes.fromhex(image['peer_mask_hex'])
        rotated = self.encoded_peer[25:] + self.encoded_peer[:25]
        peer = bytes(byte ^ mask[index & 7] for index, byte in enumerate(rotated))
        raw = bytearray(self.current.raw)
        raw[96:129] = peer
        self.current = RequestMaterial(bytes(raw))

        def publish_public(value):
            raw[129:162] = value
            self.current = RequestMaterial(bytes(raw))

        if capi is None:
            if private_entropy is None or blinding_entropy is None:
                raise PrimarySemanticUnavailable('request material production requires original CAPI entropy observations')
            material = derive_request_material(private_entropy, blinding_entropy, encoded_peer=self.encoded_peer)
        else:
            material = derive_request_material_with_capi(capi, encoded_peer=self.encoded_peer,
                                                         previous_public_key=self.current.public_key,
                                                         private_scratch=private_scratch, blinding_scratch=blinding_scratch,
                                                         public_key_written=publish_public)
        raw[129:162] = material.public_key
        self.current = RequestMaterial(bytes(raw))
        raw[48:80] = device_random_bytes(32, clock_ns=clock_ns, random_word=random_word)
        self.current = RequestMaterial(bytes(raw))
        if self.random is None:
            self.random = RequestRandom(_word(random_word))
        raw[88:96] = self.random.draw_bytes(8)
        raw[32:48] = b'\xff' * 16
        raw[:32] = material.key
        raw[81] = 1
        self.current = RequestMaterial(bytes(raw))

    def encode(self, tag, payload, *, private_entropy=None, blinding_entropy=None,
               wall_seconds=_wall_seconds, monotonic_ns=time.perf_counter_ns,
               clock_ns=time.perf_counter_ns, random_word=_system_word, clock_mismatch=None,
               capi=None, private_scratch=None, blinding_scratch=None):
        require_bytes(tag, 'request operation tag')
        require_bytes(payload, 'request payload')
        if capi is not None and (private_entropy is not None or blinding_entropy is not None):
            raise InputError('request material accepts a CAPI provider or direct entropy inputs')
        regenerated = self.current.empty
        if not regenerated:
            eligibility = self.eligibility(wall_seconds(), monotonic_ns())
            if eligibility.report_clock_mismatch:
                if clock_mismatch is None:
                    raise PrimarySemanticUnavailable('request clock mismatch requires the original telemetry reporting path')
                clock_mismatch(eligibility)
            if eligibility.refresh:
                self.reset()
                regenerated = True
        if regenerated:
            _clock(wall_seconds(), 'request producer wall clock')
            self._produce(private_entropy, blinding_entropy, clock_ns, random_word, capi, private_scratch, blinding_scratch)
        elif self.random is None:
            raise PrimarySemanticUnavailable('cached request requires its existing original MT state')
        current = self.current
        material = RequestKeyMaterial(self.encoded_peer, current.public_key, current.peer_key, b'', current.key)
        request = encode_cached_material_request(tag, payload, material, current.device_random,
                                                 current.message_id, self.random,
                                                 payload_mode=current.payload_mode,
                                                 public_key_flag=current.public_key_flag)
        return MaterialStateRequest(request, int(current.payload_mode != 0), current.device_random, 0, regenerated)

    def encode_with_capi(self, tag, payload, *, capi=None, **inputs):
        return self.encode(tag, payload, capi=SystemRequestCapi() if capi is None else capi, **inputs)
