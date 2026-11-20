import re
from functools import wraps


class EpisodeError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise EpisodeError(code)


def keys(row, names, code='KEYSET'):
    require(type(row) is dict and set(row) == set(names.split()), code)
    return row


def integer(value, bits=53, minimum=0):
    require(type(value) is int and minimum <= value < 1 << bits, 'INTEGER')
    return value


def pointer(value, zero=False):
    require(type(value) is str and re.fullmatch(r'0x[0-9a-f]{16}', value) is not None, 'POINTER')
    result = int(value, 16)
    require(zero or result > 0, 'NULL_POINTER')
    return result


def raw(value, size=None):
    require(type(value) is str and len(value) % 2 == 0 and len(value) <= 2 * ((1 << 20) + 1) and re.fullmatch('[0-9a-f]*', value) is not None, 'HEX')
    result = bytes.fromhex(value)
    require(size is None or len(result) == size, 'HEX_SIZE')
    return result


def overlap(a, n, b, m):
    return bool(n and m and a < b + m and b < a + n)


def pair(row):
    enter, leave = integer(row['enterSeq'], minimum=1), integer(row['leaveSeq'], minimum=1)
    require(enter < leave and row['normalReturn'] is True, 'EVENT_PAIR')
    return enter, leave


def label(value):
    require(type(value) is str and 0 < len(value) <= 256, 'LABEL')
    return value


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_KEY')
        result[key] = value
    return result


def sanitized(code):
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except EpisodeError:
                raise
            except Exception:
                raise EpisodeError(code) from None
        return call
    return decorate
