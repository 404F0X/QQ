"""Source6BBCE fixed QQ owner: numeric directory names and mtime metadata only."""
from dataclasses import dataclass

from .primary_qimei_application import APPLICATION_OWNER
from .primary_qimei_extra_sources import QimeiExtraSources, _cstring
from .primary_qimei_extension_sources import QimeiExtensionSources
from .primary_qimei_request import QimeiRequestBoundary, _bytes
from .primary_qimei_storage import StorageBuffer


@dataclass(frozen=True)
class QimeiReportValues:
    values: tuple[bytes, bytes, bytes, bytes, bytes, bytes]
    available: bool


class QimeiReportSources:
    def __init__(self, observations):
        self.observations = observations

    _api = QimeiExtraSources._api
    local_timestamp = QimeiExtensionSources.local_timestamp

    def _folder(self, identifier):
        data = StorageBuffer(bytes(260))
        ok, output = self._api('SHGetSpecialFolderPathA', (0, data, identifier, 1), {'data': data})
        return _cstring(output['data']) if ok else b''

    def collect(self, owner):
        if _bytes(owner) != APPLICATION_OWNER:
            raise QimeiRequestBoundary('kind13 collection supports only the fixed QQ owner')
        self._folder(0x1A)  # Source common call creates the folder even in QQ case6.
        root = self._folder(5) + b'\\Tencent Files'
        times = {}
        access, unused = self._api('_access', (root, 0))
        if access == 0:
            data = StorageBuffer(bytes(320))
            handle, output = self._api('FindFirstFileA', (root + b'/*', data), {'data': data}, width=64)
            if handle != 0xFFFFFFFFFFFFFFFF:
                try:
                    while True:
                        entry = output['data']
                        name = _cstring(entry, 44)
                        attributes = int.from_bytes(entry.read(0, 4), 'little')
                        if (name not in (b'.', b'..') and attributes & 0x10
                                and name and all(48 <= byte <= 57 for byte in name)):
                            path = root + b'\\' + name
                            timestamp = 0
                            for suffix in (b'\\nt_qq\\nt_db', b'\\QQGuild\\nt_db'):
                                candidate = path + suffix
                                status, unused = self._api('_access', (candidate, 0))
                                if status == 0:
                                    stat = StorageBuffer(bytes(56))
                                    status, result = self._api('_stat64', (candidate, stat), {'data': stat})
                                    if status == 0:
                                        timestamp = int.from_bytes(result['data'].read(0x28, 8), 'little')
                                    break
                            times.setdefault(timestamp, name)
                        status, output = self._api('FindNextFileA', (handle, data), {'data': data})
                        if not status:
                            break
                finally:
                    self._api('FindClose', (handle,))
        value = b'#'.join(times[timestamp] + b'&' + self.local_timestamp(timestamp & 0xFFFFFFFF)
                          for timestamp in sorted(times, reverse=True)[:10])
        return QimeiReportValues((b'', b'', value, b'', b'', b''), bool(times))
