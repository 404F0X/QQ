import ctypes
from dataclasses import dataclass, field
from functools import lru_cache
import os

from .primary_qimei_reply import QimeiReplyError


class QimeiRequestError(QimeiReplyError):
    pass


class QimeiRequestBoundary(QimeiRequestError):
    def __init__(self, message, slot_index=None, partial=b''):
        super().__init__(message)
        self.slot_index = slot_index
        self.partial = partial


def _bytes(value):
    if not isinstance(value, bytes):
        raise QimeiRequestError('explicit source bytes required')
    return value


def _integer(value):
    if type(value) is not int:
        raise QimeiRequestError('explicit source integer required')
    return value


def _signed(value, width):
    value = _integer(value) & ((1 << width) - 1)
    return value - (1 << width) if value & (1 << (width - 1)) else value


def _varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


class WindowsAnsiConversion:
    def __init__(self, api=None):
        if api is not None:
            self.multi = api.MultiByteToWideChar
            self.wide = api.WideCharToMultiByte
            return
        if os.name != 'nt':
            raise QimeiRequestError('source CP_ACP conversion requires Windows or an explicit conversion boundary')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.multi = kernel.MultiByteToWideChar
        self.multi.argtypes = (ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
        self.multi.restype = ctypes.c_int
        self.wide = kernel.WideCharToMultiByte
        self.wide.argtypes = (ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_int,
                              ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        self.wide.restype = ctypes.c_int

    def __call__(self, value):
        source = ctypes.create_string_buffer(_bytes(value).split(b'\0', 1)[0] + b'\0')
        count = self.multi(0, 0, source, -1, None, 0)
        if count < 0 or count >= 0x7FFFFFFF:
            raise QimeiRequestBoundary('source wide allocation length is outside the defined conversion domain')
        wide = ctypes.create_string_buffer((count + 1) * 2)
        converted = self.multi(0, 0, source, -1, wide, count)
        if count == 0 or converted == 0:
            raise QimeiRequestBoundary('source conversion may read an undefined wide buffer')
        length = self.wide(65001, 0, wide, -1, None, 0, None, None)
        if length < 0 or length >= 0x7FFFFFFF:
            raise QimeiRequestBoundary('source UTF8 allocation length is outside the defined conversion domain')
        target = ctypes.create_string_buffer(length + 1)
        self.wide(65001, 0, wide, -1, target, length, None, None)
        return target.raw.split(b'\0', 1)[0]


@lru_cache(maxsize=1)
def _windows_conversion():
    return WindowsAnsiConversion()


@dataclass(frozen=True)
class RequestSlot:
    tag: int | None = 0
    data: bytes | None = field(default=None, repr=False)


def serialize_slots(slots, *, count=None, convert_ansi=None):
    count = _signed(len(slots) if count is None else count, 32)
    result = bytearray()
    for index in range(max(count, 0)):
        if index >= len(slots):
            raise QimeiRequestBoundary('source slot read exceeds known vector backing', index, bytes(result))
        slot = slots[index]
        if not isinstance(slot, RequestSlot):
            raise QimeiRequestBoundary('unknown source slot', index, bytes(result))
        if slot.data is None:
            continue
        data = _bytes(slot.data)
        tag = _integer(slot.tag) & 0xFFFFFFFF
        if tag == 1:
            converter = _windows_conversion() if convert_ansi is None else convert_ansi
            try:
                value = _bytes(converter(data.split(b'\0', 1)[0])).split(b'\0', 1)[0]
            except QimeiRequestBoundary as error:
                error.slot_index = index
                error.partial = bytes(result)
                raise
            result += _varint((index + 1) * 8 + 2)
            result += _varint(len(value))
            result += value
        elif tag in (4, 5):
            width = 4 if tag == 4 else 8
            backing = data + b'\0'
            if len(backing) < width:
                raise QimeiRequestBoundary('numeric source read exceeds known allocation', index, bytes(result))
            result += _varint((index + 1) * 8)
            result += _varint(int.from_bytes(backing[:width], 'little'))
        else:
            break
    return bytes(result)


@dataclass
class QimeiRequestState:
    slots: list[RequestSlot] = field(default_factory=lambda: [RequestSlot() for _ in range(51)], repr=False)

    def _assign(self, number, tag, data, allocate):
        index = _integer(number) - 1
        if not 0 <= index < len(self.slots):
            raise QimeiRequestBoundary('source slot assignment exceeds vector backing', index)
        previous = self.slots[index].data
        self.slots[index] = RequestSlot(tag, previous)
        if previous is None and 0 < len(data) < 0x80000000:
            accepted = True if allocate is None else allocate(index, len(data) + 1)
            if type(accepted) is not bool:
                raise QimeiRequestError('explicit allocation boolean required')
            if accepted:
                self.slots[index] = RequestSlot(tag, data)

    def set_string(self, number, value, *, allocate=None):
        self._assign(number, 1, _bytes(value), allocate)

    def set_u32(self, number, value, *, allocate=None):
        self._assign(number, 4, (_integer(value) & 0xFFFFFFFF).to_bytes(4, 'little'), allocate)

    def set_u64(self, number, value, *, allocate=None):
        self._assign(number, 5, (_integer(value) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'), allocate)

    def set_decimal32(self, number, value, *, allocate=None):
        self._assign(number, 1, str(_signed(value, 32)).encode('ascii'), allocate)

    def set_decimal64(self, number, value, *, allocate=None):
        self._assign(number, 1, str(_integer(value) & 0xFFFFFFFFFFFFFFFF).encode('ascii'), allocate)

    def encode(self, *, convert_ansi=None):
        return serialize_slots(self.slots, convert_ansi=convert_ansi)
