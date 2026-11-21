from dataclasses import dataclass, field
from threading import RLock

from .primary_qimei_request import QimeiRequestError, QimeiRequestState, _bytes, _integer


@dataclass
class QimeiSdkContext:
    owner: bytes = field(repr=False)
    first: bytes = field(default=b'', repr=False)
    second: bytes = field(default=b'', repr=False)
    third: bytes = field(default=b'', repr=False)
    option: int | None = None

    def __post_init__(self):
        for value in (self.owner, self.first, self.second, self.third):
            _bytes(value)
        if self.option is not None:
            self.option = _integer(self.option) & 255

    def configure(self, first, second, third, option):
        self.first = b'' if first is None else _bytes(first).split(b'\0', 1)[0]
        self.second = b'' if second is None else _bytes(second).split(b'\0', 1)[0]
        self.third = b'' if third is None else _bytes(third).split(b'\0', 1)[0]
        self.option = _integer(option) & 255

    def strings(self):
        return _bytes(self.first), _bytes(self.second), _bytes(self.third)

    def option_byte(self):
        if self.option is None:
            raise QimeiRequestError('SDK option byte is not initialized by its constructor')
        return _integer(self.option) & 255

    def write_request_fields(self, request):
        if not isinstance(request, QimeiRequestState):
            raise QimeiRequestError('source request slot state required')
        request.set_string(46, _bytes(self.first))
        request.set_string(47, _bytes(self.second))


class QimeiSdkContexts:
    def __init__(self):
        self.contexts = {}
        self._lock = RLock()

    def get(self, owner):
        owner = _bytes(owner)
        with self._lock:
            if owner not in self.contexts:
                self.contexts[owner] = QimeiSdkContext(owner)
            return self.contexts[owner]
