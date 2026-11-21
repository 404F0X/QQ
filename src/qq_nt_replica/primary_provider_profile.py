import hashlib
from dataclasses import dataclass, field

from .primary_provider_init import ProviderInitializationMetadata
from .primary_qimei_cache import CacheReadResult, CacheRecords
from .primary_source_config import SourceFact, SourceProfile


class ProviderProfileError(ValueError):
    pass


class ProviderProfileUnavailable(ProviderProfileError):
    pass


def _cstr(value):
    return value.split(b'\0', 1)[0]


def _summary(value):
    return {'length': None if value is None else len(value),
            'sha256': None if value is None else hashlib.sha256(value).hexdigest()}


@dataclass(frozen=True)
class ProviderMetadataProfile:
    qua_raw: bytes = field(repr=False)
    qua_source_offset: int | None
    uin: int = field(repr=False)
    machine_id: bytes = field(repr=False)
    record1: bytes | None = field(repr=False)
    cache_read_accepted: bool | None
    record1_updated_this_read: bool | None

    def __post_init__(self):
        if type(self.uin) is not int or not 0 <= self.uin < 1 << 64:
            raise ProviderProfileError('uin requires an explicit unsigned 64-bit integer')
        if not isinstance(self.machine_id, bytes) or not isinstance(self.qua_raw, bytes):
            raise ProviderProfileError('machine_id and source QUA require explicit bytes')
        if self.record1 is not None and (not isinstance(self.record1, bytes) or len(self.record1) != 37):
            raise ProviderProfileError('cache record1 requires exactly 37 known logical bytes or unknown')
        if self.qua_source_offset is not None and (type(self.qua_source_offset) is not int or self.qua_source_offset < 0):
            raise ProviderProfileError('source offset requires a nonnegative integer or unknown')
        for value in (self.cache_read_accepted, self.record1_updated_this_read):
            if value is not None and type(value) is not bool:
                raise ProviderProfileError('cache observations require bool or unknown')
        if self.record1_updated_this_read is True and (self.record1 is None or self.cache_read_accepted is not True):
            raise ProviderProfileError('record1 update requires known bytes and an accepted read')

    @property
    def qimei_status(self):
        if self.record1 is None:
            return 'unknown-record1'
        return 'sdk-export-success' if self.record1[0] else 'sdk-export-return1-wrapper-empty-cache'

    @property
    def qimei(self):
        return None if self.record1 is None else _cstr(self.record1[:-1][:36])

    def to_initialization_metadata(self):
        if self.record1 is None:
            raise ProviderProfileUnavailable('Qimei record1 is unknown; initialization metadata unavailable')
        return ProviderInitializationMetadata(self.qimei, _cstr(self.qua_raw),
                                              str(self.uin).encode('ascii'), _cstr(self.machine_id))

    def metadata(self):
        freshness = ('unknown' if self.record1 is None else 'updated-this-read'
                     if self.record1_updated_this_read is True else 'known-state-not-updated-this-read'
                     if self.record1_updated_this_read is False else 'known-state-update-unobserved')
        return {'status': 'explicit-profile; effective-runtime-unverified',
                'qimei_scope': 'initial-empty-wrapper-cache; existing-nonempty-cache-hit-not-modeled',
                'initialization_metadata_available': self.record1 is not None,
                'cache': {'accepted': self.cache_read_accepted, 'record1_updated_this_read': self.record1_updated_this_read,
                          'record1_state': freshness, 'record1': _summary(self.record1)},
                'fields': [dict(_summary(self.qimei), field='field_08', config_offset=0x58,
                                provenance='SDK-produced-cache-record1', status=self.qimei_status,
                                sdk_export_return=None if self.record1 is None else 0 if self.record1[0] else 1),
                           dict(_summary(_cstr(self.qua_raw)), field='field_10', config_offset=0x40,
                                provenance='source-default', status='effective-runtime-unresolved',
                                source_offset=self.qua_source_offset, raw=_summary(self.qua_raw)),
                           dict(_summary(str(self.uin).encode('ascii')), field='field_18', config_offset=0x108,
                                provenance='explicit-caller-uin', status='unsigned64-ascii'),
                           dict(_summary(_cstr(self.machine_id)), field='field_20', config_offset=0x70,
                                provenance='explicit-caller-machine-id', status='cstring-boundary-only',
                                raw=_summary(self.machine_id))]}


def assemble_provider_profile(source_profile, cache, *, uin, machine_id):
    if not isinstance(source_profile, SourceProfile):
        raise ProviderProfileError('source profile requires the explicit static SourceProfile')
    candidates = [fact for fact in source_profile.facts if isinstance(fact, SourceFact) and fact.name == 'qua']
    if len(candidates) != 1 or candidates[0].provenance != 'source-default':
        raise ProviderProfileError('source profile requires exactly one source-default QUA fact')
    qua = candidates[0]
    if qua.value is None:
        raise ProviderProfileUnavailable('source-default QUA is unknown')
    if isinstance(cache, CacheReadResult):
        records = cache.records
        accepted = cache.accepted
        updated = 1 in cache.updated_records
    elif isinstance(cache, CacheRecords):
        records, accepted, updated = cache, None, None
    else:
        raise ProviderProfileError('cache input requires explicit CacheRecords or CacheReadResult')
    if not isinstance(records, CacheRecords):
        raise ProviderProfileError('cache result requires explicit current records')
    return ProviderMetadataProfile(qua.value, qua.source_offset, uin, machine_id,
                                   records.record1, accepted, updated)
