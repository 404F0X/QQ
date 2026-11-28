"""Birth-owned synchronization for the independent fixed-image model.

MODEL_LOADER_BIRTH never asserts an original QQ runtime epoch.
"""
import os
import sys
import threading
import weakref

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable

MODEL_ONLY = 'MODEL_ONLY'
MODEL_NATIVE = 'MODEL_NATIVE'
_PENDING = {}
_RESOURCES = weakref.WeakKeyDictionary()
_CELLS = (0x674D418, 0x674D4D0, 0x674D4D8)


def _thread():
    return os.getpid(), threading.get_native_id()


def _begin_birth(owner, permit):
    from .primary_windows_signer import WindowsSigner, open_windows_signer
    frame = sys._getframe(1)
    if (frame.f_code is not open_windows_signer.__code__ or
            frame.f_locals.get('owner') is not owner or type(owner) is not WindowsSigner or
            owner._state != 'constructing' or owner._signer is not None or not callable(permit)):
        raise InputError('module sync birth requires its authentic pending factory')
    if owner in _PENDING:
        raise InputError('duplicate module sync birth')
    session = object()
    _PENDING[owner] = (session, _thread(), owner._profile_hash, permit)
    return session


def _cancel_pending_birth(owner):
    from .primary_windows_signer import open_windows_signer
    if sys._getframe(1).f_code is not open_windows_signer.__code__:
        raise InputError('pending birth cancellation requires factory failure path')
    _PENDING.pop(owner, None)


class _ModuleSync:
    def __init__(self, signer, session):
        if sys._getframe(1).f_code is not install_fresh_image.__code__:
            raise InputError('module sync resource requires fresh installer')
        self.signer = signer
        self.memory, self.base = signer.memory, signer.image_base
        self.locale = signer._shared_locale_image
        self.locale_epoch = self.locale.epoch
        self.epoch = object()
        self.thread = _thread()
        self.runtime = self.owner = self.port = None
        self.sealed = False
        self.terminal = False
        self.held = False
        self.callbacks = 0
        self.origin = 'MODEL_LOADER_BIRTH'
        self._backend = MODEL_ONLY
        self.permit = None
        self.owner_profile = None
        if session is not None:
            matches = [(owner, record) for owner, record in _PENDING.items() if record[0] is session]
            if len(matches) != 1:
                raise InputError('module sync birth session missing or consumed')
            owner, record = matches[0]
            import hashlib
            if (record[1] != self.thread or owner._signer is not None or
                    hashlib.sha256(signer.profile.host_profile_string).hexdigest() != record[2]):
                raise InputError('module sync birth owner/profile/thread mismatch')
            del _PENDING[owner]
            self.owner, self.permit, self._backend = owner, record[3], MODEL_NATIVE
            self.owner_profile = record[2]
        self.regions = []
        for rva in _CELLS:
            address = self.base + rva
            self.memory.map(address, bytearray(8), name='fixed PE MODEL loader birth sync cell', initialized=True)
            self.regions.append((address, self.memory._span(address, 8)[0]))

    @property
    def backend(self):
        return self._backend

    def validate(self, runtime):
        record = _RESOURCES.get(runtime)
        if (self.terminal or record is None or record[0]() is not self or record[1] != self.backend or
                record[2] is not self.epoch or self.origin != 'MODEL_LOADER_BIRTH' or self.runtime is not runtime or
                self.signer.runtime is not runtime or runtime.memory is not self.memory or
                runtime.image_base != self.base or self.thread != _thread()):
            raise InputError('module synchronization birth/runtime identity changed')
        if (getattr(runtime, '_shared_locale_source', None) is not self.locale or
                self.locale.epoch is not self.locale_epoch):
            raise InputError('module synchronization locale source epoch changed')
        self.locale.validate_image(runtime)
        for address, region in self.regions:
            current, offset = self.memory._span(address, 8)
            if current is not region or offset:
                raise InputError('module synchronization birth backing replaced')
        if self.backend == MODEL_NATIVE and (not self.sealed or self.owner._signer is not self.signer):
            raise PrimarySemanticUnavailable('module synchronization factory seal pending')
        if self.backend == MODEL_NATIVE:
            import hashlib
            if (self.owner._profile_hash != self.owner_profile or
                    hashlib.sha256(self.signer.profile.host_profile_string).hexdigest() != self.owner_profile):
                raise InputError('module synchronization owner fixed profile changed')


def install_fresh_image(signer):
    from .primary_signer import PrimarySigner
    frame = sys._getframe(1)
    if (type(signer) is not PrimarySigner or frame.f_code is not PrimarySigner._initialize_image.__code__ or
            frame.f_locals.get('self') is not signer or hasattr(signer, '_module_sync_image')):
        raise InputError('module sync requires original fresh image installer')
    return _ModuleSync(signer, signer._module_sync_birth)


def bind_fresh_runtime(signer):
    from .primary_signer import PrimarySigner
    frame = sys._getframe(1)
    resource = signer._module_sync_image
    if (frame.f_code is not PrimarySigner.__init__.__code__ or frame.f_locals.get('self') is not signer or
            resource.runtime is not None or signer.runtime in _RESOURCES):
        raise InputError('module synchronization cannot be rebound')
    resource.runtime = signer.runtime
    _RESOURCES[signer.runtime] = (weakref.ref(resource), resource.backend, resource.epoch)


def _seal_birth(owner):
    from .primary_windows_signer import open_windows_signer
    if sys._getframe(1).f_code is not open_windows_signer.__code__:
        raise InputError('module synchronization seal requires actual factory')
    resource = owner._signer._module_sync_image
    if resource.owner is not owner or resource.sealed or resource.thread != _thread():
        raise InputError('module synchronization seal mismatch')
    resource.sealed = True
    resource.validate(owner._signer.runtime)


def _resource(runtime):
    record = _RESOURCES.get(runtime)
    resource = None if record is None else record[0]()
    if type(resource) is not _ModuleSync:
        raise PrimarySemanticUnavailable('missing module synchronization birth')
    resource.validate(runtime)
    return resource


def backend(runtime):
    return _resource(runtime).backend


def _native(resource):
    if resource.port is None:
        from .primary_windows_msf_once import WindowsModuleSync
        resource.port = WindowsModuleSync(resource)
    return resource.port


def dispose_terminal(owner):
    from .primary_windows_signer import WindowsSigner
    if type(owner) is not WindowsSigner or owner._state != 'closing' or owner._busy:
        raise InputError('module synchronization requires terminal owner cleanup')
    resource = _resource(owner._signer.runtime)
    if resource.callbacks:
        raise InputError('module synchronization callback remains active')
    if resource.port is not None:
        resource.port.dispose_terminal()
    resource.terminal = True


def shared_acquire(runtime):
    resource = _resource(runtime)
    if resource.backend == MODEL_NATIVE:
        return _native(resource).acquire()
    if resource.held or runtime.memory.load(resource.base + 0x674D4D0, 8):
        raise PrimarySemanticUnavailable('source787840 contended SRW unsupported')
    resource.held = True
    return 0


def shared_release(runtime):
    resource = _resource(runtime)
    if resource.backend == MODEL_NATIVE:
        return _native(resource).release()
    if not resource.held:
        raise InputError('module SRW release without acquisition')
    resource.held = False
    return 0


def shared_wake(runtime):
    resource = _resource(runtime)
    if resource.backend == MODEL_NATIVE:
        return _native(resource).wake()
    return 0


def source_once(runtime, flag, callback):
    resource = _resource(runtime)
    if runtime.memory.load(flag, 8) == (1 << 64) - 1:
        return 0
    shared_acquire(runtime)
    state = runtime.memory.load(flag, 8)
    if state == 1:
        raise PrimarySemanticUnavailable('source787840 condition wait unsupported')
    if state:
        shared_release(runtime)
        return 0
    runtime.memory.store(flag, 1, 8, source='75B0E0.once_claim')
    shared_release(runtime)
    resource.callbacks += 1
    try:
        callback()
    finally:
        resource.callbacks -= 1
    shared_acquire(runtime)
    runtime.memory.store(flag, (1 << 64) - 1, 8, source='75B0E0.once_complete')
    shared_release(runtime)
    shared_wake(runtime)
    return 0


def selector_once(runtime, callback):
    return source_once(runtime, _resource(runtime).base + 0x674D418, callback)
