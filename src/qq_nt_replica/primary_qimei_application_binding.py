"""Finite public-commonPath -> typed Registry20 -> same-owner QQ binding.

This projection supports ASCII drive paths with alnum/_/- components and internal ASCII spaces only;
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
    if type(common_path) is not str or re.fullmatch(r'[A-Za-z]:\\[A-Za-z0-9_-]+(?: +[A-Za-z0-9_-]+)*(?:\\[A-Za-z0-9_-]+(?: +[A-Za-z0-9_-]+)*)*',common_path) is None:
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


@dataclass(repr=False)
class StartupCallbackState:
    """Caller-shared strong reference (85820); caller owns serial access/lifetime."""
    callback: object = None


@dataclass(frozen=True, repr=False)
class ApplicationStartup:
    binding: ApplicationBinding
    identity_unchanged: bool | None
    profile: object


def start_application(binding, *, startup, callback_state, callback, arg7,
                      observations, folder_observations, selector, source_profile, uin, machine_id,
                      selector_observations=None, observe=lambda *args: None):
    """Finite cold mode1 startup stage; never full a2, getter-ready or issuance.

    Share startup, observations/context, selector and callback_state across appids.
    arg7 is solely a NULL gate. The boolean reports identity comparison, not restore.
    """
    from .primary_qimei_records import StartupState, RecordObservations
    from .primary_qimei_sdk import QimeiSdkContext
    from .primary_qimei_settings import _api, _cstring, _directory
    from .primary_qimei_storage import StorageBuffer
    from .primary_provider_profile import assemble_provider_profile
    if (not isinstance(binding, ApplicationBinding)
            or not isinstance(binding.context, QimeiSdkContext)
            or binding.context.owner != binding.owner
            or not isinstance(startup, StartupState)
            or not isinstance(callback_state, StartupCallbackState)
            or type(observations) is not RecordObservations):
        raise QimeiRequestBoundary('original binding and caller-shared startup inputs required')
    if binding.owner == b'0WIN05FCO3RZL3EQ':
        raise QimeiRequestBoundary('special appid early-exit configuration is outside this stage')
    if any(key and key[0] in ('decode', 'parse') for key in observations.values):
        raise QimeiRequestBoundary('startup requires raw ciphertext and original identity parser')
    if callback_state.callback is None and callback is not None:
        callback_state.callback = callback
    unchanged = None
    if arg7 is not None:
        # StartupState checks once before requesting this path; repeat calls do no I/O.
        def base():
            buffer = StorageBuffer(bytes(260))
            for identifier in (0x23, 0x1A):
                status, outputs = _api(folder_observations, 'SHGetSpecialFolderPathA',
                    (0, buffer, identifier, 1), {'data': buffer})
                buffer = outputs['data']
                if status:
                    path = _cstring(buffer.read()) + b'\\Tencent\\qimei'
                    exists, unused = _api(folder_observations, 'PathIsDirectoryA', (path,))
                    if not exists:
                        _directory(path, folder_observations)
                    return path
            return b''
        # A scoped observation entry preserves the original shared producer/codec.
        missing = object()
        previous = observations.values.get(('base-path',), missing)
        observations.values[('base-path',)] = base
        try:
            unchanged = startup.start(observations, selector=selector,
                selector_observations=selector_observations, observe=observe)
        finally:
            if previous is missing:
                del observations.values[('base-path',)]
            else:
                observations.values[('base-path',)] = previous
    profile = assemble_provider_profile(source_profile, startup.main.profile_records(),
                                        uin=uin, machine_id=machine_id)
    return ApplicationStartup(binding, unchanged, profile)
