from enum import Enum
import threading

from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke


_PAIRS = ((1, 22), (2, 2), (3, 2), (4, 24), (5, 13), (6, 9),
    (7, 12), (8, 12), (9, 12), (10, 7), (11, 8), (12, 22), (13, 22),
    (15, 2), (16, 13), (17, 18), (18, 2), (33, 13), (53, 2), (65, 13),
    (67, 2), (80, 17), (82, 13), (83, 13), (87, 22), (89, 11),
    (108, 13), (109, 32), (112, 28), (114, 9), (128, 10), (129, 10),
    (130, 9), (131, 22), (132, 13), (145, 41), (158, 13), (161, 2),
    (164, 11), (167, 13), (183, 17), (206, 2), (215, 11), (1113, 42), (1816, 12))


class CRTErrorStorage(Enum):
    NORMAL_NULL_PROVIDER = 'source-normal-null-provider-return'


def mapped_errno(error):
    if type(error) is not int:
        raise InputError('DOS error must have integer register bits')
    error &= 0xFFFFFFFF
    for key, value in _PAIRS:
        if error == key:
            return value
    if ((error - 19) & 0xFFFFFFFF) <= 17:
        return 13
    return 8 if ((error - 188) & 0xFFFFFFFF) <= 14 else 22


def storage_pointer(runtime, offset):
    thread = threading.get_ident()
    previous = getattr(runtime, '_crt_error_storage_thread', thread)
    if previous != thread:
        raise PrimarySemanticUnavailable('CRT error storage requires the same established execution thread')
    runtime._crt_error_storage_thread = thread
    if runtime.crt_error_storage is CRTErrorStorage.NORMAL_NULL_PROVIDER:
        return runtime.image_base + (0x6744278 if offset == 0x20 else 0x674427C)
    provider = runtime._crt_thread()
    if provider > (1 << 64) - 1 - offset:
        raise PrimaryProgramLimit('CRT error storage pointer addition wraps')
    return provider + offset


def set_error(runtime, error):
    if type(error) is not int:
        raise InputError('DOS error must have integer register bits')
    error &= 0xFFFFFFFF
    doserrno = _invoke(runtime, 0x3E84CC0)
    runtime.memory.store(doserrno, error, 4, source='3E84CF3.original_doserrno_DWORD')
    value = mapped_errno(error)
    errno = _invoke(runtime, 0x3E84C9C)
    if errno != doserrno - 4:
        raise PrimarySemanticUnavailable('CRT error provider identity changed between ordered getters')
    runtime.memory.store(errno, value, 4, source='3E84D01.mapped_errno_DWORD')
    return errno


def invoke(runtime, rva, values):
    if rva == 0x3E84CC0 and not values:
        return storage_pointer(runtime, 0x24)
    if rva == 0x3E84CE4 and len(values) == 1:
        return set_error(runtime, values[0])
    raise InputError('CRT error mapper ABI argument count mismatch')
