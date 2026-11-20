from .errors import CapabilityUnavailable, InputError, LibraryLimitError


class ScalarSSEUnavailable(CapabilityUnavailable):
    pass


class ScalarSSETrap(LibraryLimitError):
    def __init__(self, exception, mxcsr, operation='CVTTSS2SI'):
        self.exception = exception
        self.mxcsr = mxcsr
        self.operation = operation
        super().__init__(f'{operation} unmasked {exception}; destination not committed')


class ScalarSSEState:
    def __init__(self, mxcsr):
        self.mxcsr = mxcsr

    @property
    def mxcsr(self):
        return self._mxcsr

    @mxcsr.setter
    def mxcsr(self, value):
        if type(value) is not int or not 0 <= value <= 0xFFFF:
            raise InputError('scalar SSE state requires explicit nonreserved MXCSR bits')
        self._mxcsr = value


def cvttss2si_i64_low_dword(bits, state=None):
    if type(bits) is not int or not 0 <= bits <= 0xFFFFFFFF:
        raise InputError('CVTTSS2SI source requires unsigned32 encoding')
    if state is not None and type(state) is not ScalarSSEState:
        raise InputError('CVTTSS2SI requires explicit ScalarSSEState or unknown None')
    exponent, fraction = (bits >> 23) & 255, bits & 0x7FFFFF
    if exponent == 0 and fraction:
        if state is None:
            raise ScalarSSEUnavailable('CVTTSS2SI subnormal input requires explicit MXCSR DAZ')
        if state.mxcsr & 0x40:
            return 0
    flag = 0
    if exponent == 255:
        flag, value = 1, -(1 << 63)
    else:
        mantissa = fraction | (0x800000 if exponent else 0)
        shift = (exponent if exponent else 1) - 150
        if shift >= 0:
            value = mantissa << shift
        else:
            value, remainder = divmod(mantissa, 1 << -shift)
            if remainder:
                flag = 0x20
        if bits >> 31:
            value = -value
        if not -(1 << 63) <= value < (1 << 63):
            flag, value = 1, -(1 << 63)
    if flag:
        if state is None:
            raise ScalarSSEUnavailable('CVTTSS2SI exception requires explicit MXCSR mask/status')
        state.mxcsr |= flag
        if not state.mxcsr & (flag << 7):
            raise ScalarSSETrap('invalid' if flag == 1 else 'precision', state.mxcsr)
    return value & 0xFFFFFFFF


from dataclasses import dataclass
from enum import Enum


class _Ceil32Route(Enum):
    FALLBACK = 'fallback'
    ROUNDSS = 'roundss'


@dataclass(frozen=True)
class Ceil32Predicate:
    sf: int
    of: int

    def __post_init__(self):
        if any(type(value) is not int or value not in (0, 1) for value in (self.sf, self.of)):
            raise InputError('ceil32 predicate requires original SF and OF bits')


def ceil32_bits(bits, *, cpu_selector, state=None, unit_bits=None):
    if type(bits) is not int or not 0 <= bits <= 0xFFFFFFFF:
        raise InputError('ceil32 source requires unsigned32 encoding')
    if cpu_selector is None:
        raise ScalarSSEUnavailable('ceil32 requires an explicit signed32 CPU selector')
    if type(cpu_selector) is not int or not -(1 << 31) <= cpu_selector < (1 << 31):
        raise InputError('ceil32 CPU selector requires signed32 encoding')
    route = _Ceil32Route.ROUNDSS if cpu_selector >= 2 else _Ceil32Route.FALLBACK
    return _ceil32_route_bits(bits, route=route, state=state, unit_bits=unit_bits)


def ceil32_from_predicate(bits, predicate, *, state=None, unit_bits=None):
    if type(predicate) is not Ceil32Predicate:
        raise InputError('ceil32 observation requires Ceil32Predicate')
    route = _Ceil32Route.ROUNDSS if predicate.sf == predicate.of else _Ceil32Route.FALLBACK
    return _ceil32_route_bits(bits, route=route, state=state, unit_bits=unit_bits)


def _ceil32_route_bits(bits, *, route, state=None, unit_bits=None):
    if type(bits) is not int or not 0 <= bits <= 0xFFFFFFFF:
        raise InputError('ceil32 source requires unsigned32 encoding')
    if type(route) is not _Ceil32Route:
        raise InputError('ceil32 route requires a source-qualified enum')
    if state is not None and type(state) is not ScalarSSEState:
        raise InputError('ceil32 requires explicit ScalarSSEState or unknown None')
    if unit_bits is not None and (type(unit_bits) is not int or not 0 <= unit_bits <= 0xFFFFFFFF):
        raise InputError('ceil32 unit requires unsigned32 encoding or unknown None')
    magnitude = bits & 0x7FFFFFFF
    roundss = route is _Ceil32Route.ROUNDSS
    if magnitude > 0x7F800000:
        if roundss and not bits & 0x00400000:
            if state is None:
                raise ScalarSSEUnavailable('ceil32 ROUNDSS signaling NaN requires explicit MXCSR mask/status')
            state.mxcsr |= 1
            if not state.mxcsr & 0x80:
                raise ScalarSSETrap('invalid', state.mxcsr, operation='ROUNDSS')
        return bits | 0x00400000
    if roundss and 0 < magnitude < 0x00800000:
        if state is None:
            raise ScalarSSEUnavailable('ceil32 ROUNDSS subnormal requires explicit MXCSR DAZ')
        if state.mxcsr & 0x40:
            return bits & 0x80000000
    if magnitude >= 0x4B000000 or magnitude == 0:
        return bits
    if magnitude < 0x3F800000:
        if bits >> 31:
            return 0x80000000
        if roundss:
            return 0x3F800000
        if unit_bits is None:
            raise ScalarSSEUnavailable('ceil32 fallback requires explicit unit bits')
        return unit_bits
    shift = 150 - (magnitude >> 23)
    truncated = bits & ((0xFFFFFFFF << shift) & 0xFFFFFFFF)
    if bits >> 31 or bits == truncated:
        return truncated
    if not roundss:
        if unit_bits is None:
            raise ScalarSSEUnavailable('ceil32 fallback increment requires explicit unit bits')
        if unit_bits != 0x3F800000:
            raise ScalarSSEUnavailable('ceil32 altered unit constant is unavailable')
    return truncated + (1 << shift)
