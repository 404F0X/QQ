"""Owned source DWORD counter: successful four-byte entropy, local MT, old-value add."""
from threading import Lock
from .errors import InputError
from .primary_memory import PrimaryMemory
from .primary_cocos import seed_mt, next_mt


class SourceCounter:
    def __init__(self, entropy4):
        raw = entropy4()
        if type(raw) is not bytes or len(raw) != 4:
            raise InputError('source counter requires one successful four-byte entropy input')
        memory = PrimaryMemory()
        memory.map(0x1000, bytearray(0x9C8), name='own source counter MT', initialized=True)
        seed_mt(memory, 0x1000, int.from_bytes(raw, 'little'))
        while True:
            value = next_mt(memory, 0x1000) & 0xFFFFFF
            if value < 10_000_000:
                break
        self._value = value + 1
        self._lock = Lock()

    def next(self):
        with self._lock:
            old = self._value
            self._value = (old + 1) & 0xFFFFFFFF
            return old
