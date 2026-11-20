import ctypes
from dataclasses import dataclass
import os

from .errors import InputError
from .primary_request_encoder import RequestKeyMaterial, _N, _bytes, _decode_point, _image, _point_multiply, _request_key
from .primary_vm import PrimarySemanticUnavailable
from .wire import require_uint


class RequestCapiBuffer:
    def __init__(self, initial=None):
        if initial is not None:
            _bytes(initial, 32, 'original request CAPI scratch')
        self._data = bytearray(bytes(32) if initial is None else initial)
        self._known = bytearray([initial is not None] * 32)

    def write(self, value):
        if not isinstance(value, bytes) or len(value) > 32:
            raise InputError('request CAPI write requires at most32 bytes')
        self._data[:len(value)] = value
        self._known[:len(value)] = b'\x01' * len(value)

    def value(self):
        if not all(self._known):
            raise PrimarySemanticUnavailable('request CAPI buffer contains unknown original caller scratch bytes')
        return bytes(self._data)


@dataclass(frozen=True)
class RequestCapiObservation:
    operation: str
    phase: str
    result: int
    output: bytes | None = None
    handle: int | None = None

    def __post_init__(self):
        if self.operation not in ('acquire', 'generate', 'release') or self.phase not in ('private', 'blinding'):
            raise InputError('request CAPI observation has an invalid operation or phase')
        require_uint(self.result, 32, 'request CAPI result')
        if self.handle is not None:
            require_uint(self.handle, 64, 'request CAPI provider handle')
        if self.output is not None and (self.operation != 'generate' or not isinstance(self.output, bytes) or len(self.output) > 32):
            raise InputError('request CAPI output requires a generate observation of at most32 bytes')


class RequestCapiReplay:
    def __init__(self, observations):
        self.observations = tuple(observations)
        if any(not isinstance(observation, RequestCapiObservation) for observation in self.observations):
            raise InputError('request CAPI replay requires typed observations')
        self.consumed = 0

    def _next(self, operation, phase):
        if self.consumed == len(self.observations):
            raise PrimarySemanticUnavailable('original request CAPI observation sequence is exhausted')
        observation = self.observations[self.consumed]
        if (observation.operation, observation.phase) != (operation, phase):
            raise PrimarySemanticUnavailable('original request CAPI observation does not match the next source call')
        self.consumed += 1
        return observation

    def acquire(self, phase):
        observation = self._next('acquire', phase)
        if observation.result and observation.handle is None:
            raise PrimarySemanticUnavailable('successful original request CAPI acquisition has no observed handle')
        return observation.result, observation.handle

    def generate(self, phase, handle, buffer):
        observation = self._next('generate', phase)
        if observation.handle is not None and observation.handle != handle:
            raise PrimarySemanticUnavailable('original request CAPI generate handle does not match acquisition')
        if observation.output is not None:
            buffer.write(observation.output)
        return observation.result

    def release(self, phase, handle):
        observation = self._next('release', phase)
        if observation.handle is not None and observation.handle != handle:
            raise PrimarySemanticUnavailable('original request CAPI release handle does not match acquisition')
        return observation.result


class SystemRequestCapi:
    def __init__(self):
        if os.name != 'nt':
            raise PrimarySemanticUnavailable('the recovered request CAPI provider requires Windows')
        self._library = ctypes.WinDLL('advapi32.dll', use_last_error=True)
        self._acquire = self._library.CryptAcquireContextW
        self._acquire.argtypes = (ctypes.POINTER(ctypes.c_size_t), ctypes.c_wchar_p, ctypes.c_wchar_p,
                                  ctypes.c_uint32, ctypes.c_uint32)
        self._acquire.restype = ctypes.c_int32
        self._generate = self._library.CryptGenRandom
        self._generate.argtypes = (ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte))
        self._generate.restype = ctypes.c_int32
        self._release = self._library.CryptReleaseContext
        self._release.argtypes = (ctypes.c_size_t, ctypes.c_uint32)
        self._release.restype = ctypes.c_int32
        self.calls = []

    def acquire(self, phase):
        handle = ctypes.c_size_t()
        result = self._acquire(ctypes.byref(handle), None, None, 1, 0xF0000000) & 0xFFFFFFFF
        self.calls.append(('acquire', phase, result))
        return result, handle.value

    def generate(self, phase, handle, buffer):
        native = (ctypes.c_ubyte * 32).from_buffer(buffer._data)
        result = self._generate(handle, 32, native) & 0xFFFFFFFF
        if result:
            buffer._known[:] = b'\x01' * 32
        self.calls.append(('generate', phase, result))
        return result

    def release(self, phase, handle):
        result = self._release(handle, 0) & 0xFFFFFFFF
        self.calls.append(('release', phase, result))
        return result


def _generate(capi, phase, buffer):
    result, handle = capi.acquire(phase)
    require_uint(result, 32, 'request CAPI acquisition result')
    if not result:
        return False
    require_uint(handle, 64, 'request CAPI provider handle')
    generated = capi.generate(phase, handle, buffer)
    require_uint(generated, 32, 'request CAPI generation result')
    released = capi.release(phase, handle)
    require_uint(released, 32, 'request CAPI release result')
    return True


@dataclass(frozen=True)
class RequestSharedMaterial:
    encoded_peer: bytes
    public_key: bytes
    peer_key: bytes
    shared_x: bytes


def derive_request_shared_with_capi(capi, *, encoded_peer=None, previous_public_key=bytes(33),
                                      private_scratch=None, blinding_scratch=None, public_key_written=None):
    _bytes(previous_public_key, 33, 'previous original request public key')
    image = _image()
    encoded_peer = bytes.fromhex(image['encoded_peer_hex']) if encoded_peer is None else encoded_peer
    _bytes(encoded_peer, 33, 'encoded request peer')
    mask = bytes.fromhex(image['peer_mask_hex'])
    rotated = encoded_peer[25:] + encoded_peer[:25]
    peer = bytes(byte ^ mask[index & 7] for index, byte in enumerate(rotated))
    decoded_peer = _decode_point(peer)
    raw_base = bytes.fromhex(image['curve_base_hex'])
    base = tuple(int.from_bytes(raw_base[index:index + 32], 'little') for index in (0, 32))
    private = RequestCapiBuffer(private_scratch)
    blinding = RequestCapiBuffer(blinding_scratch)
    public_key, scalar = previous_public_key, 0
    for attempt in range(17):
        if not _generate(capi, 'private', private) or attempt == 16:
            scalar = 0
            break
        scalar = int.from_bytes(private.value(), 'little')
        if scalar == 0:
            continue
        scalar %= _N
        private.write(scalar.to_bytes(32, 'little'))
        public = _point_multiply(scalar, base)
        if public == (0, 0):
            scalar = 0
            continue
        public_key = bytes([2 | (public[1] & 1)]) + public[0].to_bytes(32, 'big')
        if public_key_written is not None:
            public_key_written(public_key)
        break
    shared_x = bytes(32)
    if _generate(capi, 'blinding', blinding):
        shared = _point_multiply(scalar, decoded_peer, int.from_bytes(blinding.value(), 'little'))
        shared_x = shared[0].to_bytes(32, 'big')
    return RequestSharedMaterial(encoded_peer, public_key, peer, shared_x)


def derive_request_material_with_capi(capi, *, encoded_peer=None, previous_public_key=bytes(33),
                                      private_scratch=None, blinding_scratch=None, public_key_written=None):
    material = derive_request_shared_with_capi(
        capi, encoded_peer=encoded_peer, previous_public_key=previous_public_key,
        private_scratch=private_scratch, blinding_scratch=blinding_scratch, public_key_written=public_key_written)
    return RequestKeyMaterial(material.encoded_peer, material.public_key, material.peer_key, material.shared_x,
                              _request_key(material.shared_x))
