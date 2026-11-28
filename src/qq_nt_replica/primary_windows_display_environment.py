import ctypes
import _ctypes
import os
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


ORIGIN = 'INDEPENDENT_WINDOWS_DISPLAY_ENVIRONMENT'


def qualification():
    return dict(origin=ORIGIN, original_frame_equivalence='NOT_ESTABLISHED',
        source_request_association='NOT_ASSOCIATED', source_profile_association='NOT_ASSOCIATED',
        same_request_qualification=False, full96_qualification=False)


class _Point(ctypes.Structure):
    _fields_ = (('x', ctypes.c_int32), ('y', ctypes.c_int32))


class _Display(ctypes.Structure):
    _fields_ = (('dmPosition', _Point), ('dmDisplayOrientation', ctypes.c_uint32),
        ('dmDisplayFixedOutput', ctypes.c_uint32))


class _Printer(ctypes.Structure):
    _fields_ = tuple((name, ctypes.c_int16) for name in ('dmOrientation', 'dmPaperSize', 'dmPaperLength',
        'dmPaperWidth', 'dmScale', 'dmCopies', 'dmDefaultSource', 'dmPrintQuality'))


class _ModeUnion(ctypes.Union):
    _fields_ = (('display', _Display), ('printer', _Printer))


class DEVMODEW(ctypes.Structure):
    _fields_ = (('dmDeviceName', ctypes.c_uint16 * 32), ('dmSpecVersion', ctypes.c_uint16),
        ('dmDriverVersion', ctypes.c_uint16), ('dmSize', ctypes.c_uint16), ('dmDriverExtra', ctypes.c_uint16),
        ('dmFields', ctypes.c_uint32), ('mode', _ModeUnion), ('dmColor', ctypes.c_int16),
        ('dmDuplex', ctypes.c_int16), ('dmYResolution', ctypes.c_int16), ('dmTTOption', ctypes.c_int16),
        ('dmCollate', ctypes.c_int16), ('dmFormName', ctypes.c_uint16 * 32), ('dmLogPixels', ctypes.c_uint16),
        ('dmBitsPerPel', ctypes.c_uint32), ('dmPelsWidth', ctypes.c_uint32), ('dmPelsHeight', ctypes.c_uint32),
        ('dmDisplayFlags', ctypes.c_uint32), ('dmDisplayFrequency', ctypes.c_uint32), ('dmICMMethod', ctypes.c_uint32),
        ('dmICMIntent', ctypes.c_uint32), ('dmMediaType', ctypes.c_uint32), ('dmDitherType', ctypes.c_uint32),
        ('dmReserved1', ctypes.c_uint32), ('dmReserved2', ctypes.c_uint32), ('dmPanningWidth', ctypes.c_uint32),
        ('dmPanningHeight', ctypes.c_uint32))


def _owned_mode():
    if (ctypes.sizeof(DEVMODEW) != 220 or DEVMODEW.dmSize.offset != 68 or
            DEVMODEW.dmDriverExtra.offset != 70 or DEVMODEW.dmPelsWidth.offset != 172 or
            DEVMODEW.dmPelsHeight.offset != 176):
        raise PrimarySemanticUnavailable('independent display environment requires the declared Windows DEVMODEW ABI')
    buffer = DEVMODEW()
    buffer.dmSize = ctypes.sizeof(DEVMODEW)
    buffer.dmDriverExtra = 0
    return buffer


def _sample(function, buffer, index):
    if type(buffer) is not DEVMODEW or type(index) is not int or not 0 <= index < 4096:
        raise InputError('independent display environment requires its owned typed buffer and bounded mode index')
    result = function(None, index, ctypes.byref(buffer))
    if type(result) is not int or not -(1 << 31) <= result < 1 << 31:
        raise InputError('independent display environment requires an actual BOOL32 result')
    if not result:
        return 0, None, None
    return result & 0xFFFFFFFF, int(buffer.dmPelsWidth), int(buffer.dmPelsHeight)


class WindowsDisplayEnvironment:
    def __init__(self):
        self._identity = os.getpid(), threading.get_native_id()
        self._buffer = _owned_mode()
        self._library = self._function = None
        self._next = 0
        self._ended = self._closed = False

    @property
    def qualifications(self):
        return qualification()

    def _check(self):
        if self._closed or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('independent display environment requires its owning process and thread')

    def __enter__(self):
        self._check()
        if self._library is not None:
            raise InputError('independent display environment opens once')
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_wchar) != 2:
            raise PrimarySemanticUnavailable('independent display environment requires Windows Win64')
        self._library = ctypes.WinDLL('user32', use_last_error=False)
        try:
            self._function = self._library.EnumDisplaySettingsW
            self._function.restype = ctypes.c_int32
            self._function.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(DEVMODEW))
        except BaseException:
            self.close()
            raise
        return self

    def sample(self, index):
        self._check()
        if self._function is None or self._ended or type(index) is not int or index != self._next:
            raise InputError('independent display enumeration requires the next index in its original open sequence')
        observation = _sample(self._function, self._buffer, index)
        self._next += 1
        self._ended = not observation[0]
        return observation

    def close(self):
        if self._closed:
            return
        self._check()
        if self._library is not None:
            _ctypes.FreeLibrary(self._library._handle)
            self._library = self._function = None
        self._buffer = None
        self._closed = True

    def __exit__(self, error_type, error, traceback):
        self.close()
        return False
