"""Finite public-commonPath -> typed Registry20 -> same-owner QQ binding.

This projection supports ASCII drive paths with alnum/_/- components only;
it does not claim to restrict the original public NAPI input domain.
"""
from collections.abc import MutableMapping
from dataclasses import dataclass,field
import re
from .primary_qimei_application import APPLICATION_OWNER,QimeiApplication
from .primary_qimei_sdk import QimeiSdkContexts
from .primary_qimei_settings import QimeiSettings
from .primary_qimei_request import QimeiRequestBoundary
from .primary_windows_qimei_application import WindowsQimeiApplicationReader

_SOURCE = 'public initConfig.commonPath D4F840 -> 6D3DCC/6D3E23 nt_data -> selector10 msf -> C6CFC4; explanation only, not observed input provenance'
_METADATA = ('used','closed','file_handles','local_allocations','selected_read_length')


def derive_application_msf_path(common_path):
    if type(common_path) is not str or re.fullmatch(r'[A-Za-z]:\\(?:[A-Za-z0-9_-]+\\)*[A-Za-z0-9_-]+',common_path) is None:
        raise QimeiRequestBoundary('commonPath outside finite ASCII drive-absolute component domain')
    return common_path+'\\nt_data\\msf'


@dataclass(frozen=True,repr=False)
class ApplicationBinding:
    owner: bytes = field(repr=False)
    settings: object = field(repr=False)
    context: object = field(repr=False)
    reader_metadata: dict = field(repr=False)
    def __repr__(self):return '<ApplicationBinding private>'


def bind_application(common_path,*,contexts,settings_by_owner,settings_observations,
                     reader_factory=WindowsQimeiApplicationReader):
    msf=derive_application_msf_path(common_path)
    if (not isinstance(contexts,QimeiSdkContexts) or not isinstance(settings_by_owner,MutableMapping)
            or not callable(getattr(settings_observations,'read',None)) or not callable(reader_factory)):
        raise QimeiRequestBoundary('explicit contexts, caller settings pool, observations and reader factory required')
    reader=reader_factory(msf,source_binding=_SOURCE)
    application=reader.read()
    if not isinstance(application,QimeiApplication):
        raise QimeiRequestBoundary('typed QimeiApplication reader result required')
    if APPLICATION_OWNER not in settings_by_owner:
        settings_by_owner[APPLICATION_OWNER]=QimeiSettings()
    settings=settings_by_owner[APPLICATION_OWNER]
    if not isinstance(settings,QimeiSettings):
        raise QimeiRequestBoundary('typed same-owner settings required')
    settings.initialize(APPLICATION_OWNER,settings_observations)
    context=application.configure(contexts)
    metadata=reader.metadata()
    safe={key:metadata[key] for key in _METADATA if key in metadata and type(metadata[key]) in (bool,int)}
    return ApplicationBinding(APPLICATION_OWNER,settings,context,safe)
