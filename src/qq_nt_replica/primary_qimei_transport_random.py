from .primary_qimei_extra_sources import QimeiExtraSources
from .primary_qimei_request import QimeiRequestBoundary, _signed
from .primary_qimei_storage import StorageBuffer


class QimeiTransportRandom:
    _api = QimeiExtraSources._api

    def __init__(self, observations):
        self.observations = observations

    def random_bytes(self, n):
        n = _signed(n, 32)
        if n <= 0:
            return b''
        if n > 1 << 20:
            raise QimeiRequestBoundary('random allocation leaves bounded source domain')
        blocks = n // 32 + 1
        pointer, unused = self._api('calloc', (1, blocks * 32), width=64)
        if not pointer:
            return b''
        result = bytearray(blocks * 32)
        try:
            for index in range(blocks):
                handle = StorageBuffer(bytes(8))
                status, output = self._api('CryptAcquireContextW', (handle, None, None, 1, 0xF0000000), {'handle': handle})
                if status:
                    provider = int.from_bytes(output['handle'].read(), 'little')
                    try:
                        data = StorageBuffer(bytes(32))
                        unused, output = self._api('CryptGenRandom', (provider, 32, data), {'data': data})
                        result[index * 32:(index + 1) * 32] = output['data'].read()
                    finally:
                        self._api('CryptReleaseContext', (provider, 0))
            return bytes(result[:n])
        finally:
            self._api('free', (pointer,))
