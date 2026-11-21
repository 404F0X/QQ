import secrets
import time

from .errors import InputError
from .primary_cocos import next_mt, seed_mt
from .primary_memory import PrimaryMemory
from .wire import check_length, require_uint


class RequestRandom:
    def __init__(self, seed):
        require_uint(seed, 32, 'request MT seed')
        self._state = bytearray(2504)
        self._memory = PrimaryMemory()
        self._memory.map(0x1000, self._state, name='request MT state', initialized=False)
        seed_mt(self._memory, 0x1000, seed)
        self._memory.writes.clear()

    @classmethod
    def from_snapshot(cls, state):
        if not isinstance(state, bytes) or len(state) != 2504:
            raise InputError('request MT snapshot requires exactly 2504 bytes')
        if int.from_bytes(state[-8:], 'little') >= 624:
            raise InputError('request MT snapshot index must be below 624')
        instance = cls.__new__(cls)
        instance._state = bytearray(state)
        instance._memory = PrimaryMemory()
        instance._memory.map(0x1000, instance._state, name='request MT state', initialized=True)
        return instance

    def snapshot(self):
        return bytes(self._state)

    def draw_bytes(self, count):
        require_uint(count, 64, 'request random byte count')
        check_length(count, 'request random byte count')
        value = next_mt(self._memory, 0x1000)
        output = bytearray()
        for index in range(count):
            output.append((value >> (8 * (index & 3))) & 255)
            if index & 3 == 3:
                value = next_mt(self._memory, 0x1000)
        self._memory.writes.clear()
        return bytes(output)


def _system_word():
    return int.from_bytes(secrets.token_bytes(4), 'little')


def _word(source):
    value = source()
    require_uint(value, 32, 'request system random word')
    return value


def clock_random_bytes(count, clock_ns):
    require_uint(clock_ns, 64, 'request clock nanoseconds')
    return RequestRandom(clock_ns & 0xFFFFFFFF).draw_bytes(count)


def device_random_bytes(count, *, clock_ns=time.perf_counter_ns, random_word=_system_word):
    require_uint(count, 64, 'device random byte count')
    check_length(count, 'device random byte count')
    first = clock_random_bytes(count, clock_ns())
    value = _word(random_word)
    output = bytearray()
    for index in range(count):
        output.append((value >> (8 * (index & 3))) & 255)
        if index & 3 == 3:
            value = _word(random_word)
    second = clock_random_bytes(count, clock_ns())
    return bytes(a ^ b ^ c for a, b, c in zip(first, output, second))
