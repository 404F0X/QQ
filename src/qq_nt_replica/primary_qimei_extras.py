from dataclasses import dataclass, field

from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, QimeiRequestState, _bytes
from .primary_qimei_settings import QimeiSettings


_ESCAPES = {8: b'\\b', 9: b'\\t', 10: b'\\n', 12: b'\\f', 13: b'\\r',
            34: b'\\"', 47: b'\\/', 92: b'\\\\'}


def escape_string(value):
    value = _bytes(value)
    prefix = value.split(b'\0', 1)[0]
    if not any(byte in _ESCAPES for byte in prefix) and not any(1 <= byte <= 31 for byte in value):
        return value
    result = bytearray()
    for byte in prefix:
        if byte in _ESCAPES:
            result += _ESCAPES[byte]
        elif 1 <= byte <= 31:
            result += ('\\u%04X' % byte).encode('ascii')
        else:
            result.append(byte)
    return bytes(result)


@dataclass
class QimeiRequestExtras:
    values: dict[bytes, bytes] = field(default_factory=dict, repr=False)

    def put(self, key, value):
        self.values[_bytes(key)] = _bytes(value)

    def encode(self):
        return b'{' + b','.join(b'"' + escape_string(key) + b'":"' + escape_string(self.values[key]) + b'"'
                                 for key in sorted(self.values)) + b'}'

    def write_request_field(self, request):
        if not isinstance(request, QimeiRequestState):
            raise QimeiRequestError('source request slot state required')
        request.set_string(50, self.encode())


def produce_request_extras(request, settings, *, module_version, advid=None, edgeid=None, gpudn=None, settings_dependencies=None):
    if not isinstance(request, QimeiRequestState) or not isinstance(settings, QimeiSettings):
        raise QimeiRequestError('source request and settings state required')
    if not callable(module_version):
        raise QimeiRequestBoundary('source qimei.dll module version producer required')
    extras = QimeiRequestExtras()
    extras.put(b'ov', _bytes(module_version()))
    dependencies = {} if settings_dependencies is None else settings_dependencies
    for number, key, producer in ((19, b'advid', advid), (10, b'edgeid', edgeid), (20, b'gpudn', gpudn)):
        if settings.flag(number, **dependencies) != 0:
            if not callable(producer):
                raise QimeiRequestBoundary('source ' + key.decode('ascii') + ' producer required')
            value = _bytes(producer())
            if value:
                extras.put(key, value)
    extras.write_request_field(request)
    return extras
