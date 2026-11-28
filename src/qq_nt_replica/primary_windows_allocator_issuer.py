"""Finite early Windows allocation issuer; installation never captures input."""
import os
import sys
import threading
from .errors import InputError
from .primary_custom_allocator import _Issuer


def _frame(code, owner):
    frame=sys._getframe(1)
    while frame is not None:
        if frame.f_code is code and frame.f_locals.get('self') is owner:return frame
        frame=frame.f_back
    return None


class WindowsAllocatorIssuer(_Issuer):
    def __init__(self,owner):
        if sys._getframe(1).f_code is not install_early_allocator.__code__:
            raise InputError('Windows allocator issuer requires its original finite factory installer')
        self.owner=owner;self.signer=owner._signer;self.runtime=self.signer.runtime
        self.source=self.runtime._primary_allocator_selector;self.epoch=self.source.epoch
        self.registrar=owner._registrar;self.threads=owner._threads
        self.origin='windows';self.closed=False;self.owners={};self.calls=0;self.bound_seen=False

    def validate(self):
        super().validate()
        from .primary_host_services import GuestExitRegistrar,_ExecutionLease
        from .primary_windows_signer import WindowsSigner
        from .primary_windows_threads import WindowsSDKThreadService
        owner=self.owner
        if (type(owner) is not WindowsSigner or owner._signer is not self.signer or
                self.signer.runtime is not self.runtime or self.runtime._primary_entry_owner is not self.signer or
                owner._pid!=os.getpid() or owner._registrar is not self.registrar or
                type(self.registrar) is not GuestExitRegistrar or owner._threads is not self.threads or
                type(self.threads) is not WindowsSDKThreadService or
                self.registrar._runtime is not self.runtime or owner._state not in ('constructing','open','failed','closing')):
            raise InputError('early allocator issuer lost its actual Windows owner')
        lease=self.registrar.current_lease()
        if (type(lease) is not _ExecutionLease or lease.registrar is not self.registrar or
                not lease.active or lease.suspended or lease.thread_id!=threading.get_native_id()):
            raise InputError('Windows allocation requires its current real execution lease')
        if self.threads._runtime is self.runtime:
            self.bound_seen=True
        else:
            self._require_unbound_domain(lease)
        if self.source.phase in ('fresh','initializing'):self._first_domain()

    def _require_unbound_domain(self,lease):
        from .primary_windows_signer import WindowsSigner,open_windows_signer
        from .primary_signer import PrimarySigner
        from .primary_host_services import GuestExitRegistrar
        from .primary_sign_lifecycle import _CloseDirectOwner
        from . import primary_notification_static_initializers as statics
        owner=self.owner;threads=self.threads;tid=threading.get_native_id()
        if (self.bound_seen or threads._runtime is not None or threads._registrar is not None or
                threads._observer_factory is not None or threads._closed or threads._threads or
                threads._secondary or threads._crt_domains or threads._owner!=(os.getpid(),tid) or
                owner._thread!=tid):
            raise InputError('unbound allocation requires its original never-bound thread service')
        if owner._state=='closing':
            close=getattr(self.runtime,'_primary_close_direct_owner',None)
            if (self.source.phase!='complete' or not lease.closing or
                    self.registrar._lifecycle!='closing' or not self.registrar._bound or
                    not threads._closing or not threads._active_owner or
                    threads._execution_tid!=tid or not threads._execution.locked() or
                    type(close) is not _CloseDirectOwner or close.runtime is not self.runtime or
                    close.signer is not self.signer or close.windows is not owner or
                    close.registrar is not self.registrar or not close.valid() or
                    _frame(WindowsSigner.close.__code__,owner) is None or
                    _frame(WindowsSigner._release_resources.__code__,owner) is None or
                    _frame(GuestExitRegistrar.close.__code__,self.registrar) is None):
                raise InputError('never-bound rollback requires its original warm closing source domain')
            self.source.require_origin(self.runtime,'windows')
            return
        if (owner._state!='constructing' or lease.closing or threads._closing or
                threads._active_owner or threads._execution_tid is not None):
            raise InputError('unbound static allocation requires its inactive constructing source owner')
        common=((PrimarySigner.initialize_notification_statics.__code__,'self',self.signer),
                (WindowsSigner._initialize_notification_statics.__code__,'self',owner),
                (open_windows_signer.__code__,'owner',owner))
        if self.source.phase in ('fresh','initializing'):
            expected=((statics._construct_module_strings.__code__,'runtime',self.runtime),
                      (statics.construct_module_startup.__code__,'runtime',self.runtime))+common
        elif self.source.phase=='complete':
            self.source.require_origin(self.runtime,'windows')
            expected=((statics.initialize_supported.__code__,'runtime',self.runtime),)+common
        else:raise InputError('unbound source phase is unsupported')
        frame=sys._getframe(1)
        for code,key,value in expected:
            while frame is not None and frame.f_code is not code:frame=frame.f_back
            if frame is None or frame.f_locals.get(key) is not value:
                raise InputError('unbound allocation lacks its exact ordered original static source chain')
            frame=frame.f_back

    def _first_domain(self):
        from .primary_windows_signer import WindowsSigner,open_windows_signer
        from .primary_signer import PrimarySigner
        from .primary_sign_lifecycle import _ProviderInitializationOwner
        owner=self.owner
        if self.threads._runtime is None:
            self._require_unbound_domain(self.registrar.current_lease());return
        crt=_frame(WindowsSigner._initialize_crt.__code__,owner)
        frame=sys._getframe(1);factory=False
        while frame is not None:
            if frame.f_code is open_windows_signer.__code__ and frame.f_locals.get('owner') is owner:factory=True
            frame=frame.f_back
        if (crt is not None and factory and owner._state=='constructing' and
                owner._thread==threading.get_native_id()):return
        provider=getattr(self.runtime,'_primary_provider_initialization_owner',None)
        if (type(provider) is _ProviderInitializationOwner and provider.signer is self.signer and
                provider.runtime is self.runtime and provider.valid() and
                _frame(PrimarySigner.initialize_provider.__code__,self.signer) is not None and
                _frame(WindowsSigner._operation.__code__,owner) is not None):return
        raise InputError('first upper selection is outside proved CRT/provider initialization domains')

    def capture(self,consumer):
        self.validate();self._first_domain();self.source.require_capture(self.runtime,consumer)
        if self.calls:raise InputError('Windows selector command-line input is one-use')
        self.calls+=1
        from .primary_windows_command_line import capture_early_allocator
        return capture_early_allocator(self,consumer)

    def retire(self):
        from .primary_windows_signer import WindowsSigner
        frame=sys._getframe(1)
        if (frame.f_code is not WindowsSigner._release_resources.__code__ or
                frame.f_locals.get('self') is not self.owner or self.source._borrow is not None):
            raise InputError('early allocator retirement requires completed owner guest cleanup')
        self.runtime._custom_allocator_backend.retire_storage()
        self.closed=True;self.owners.clear()


def install_early_allocator(owner):
    from .primary_windows_signer import WindowsSigner,open_windows_signer
    frame=sys._getframe(1)
    if (type(owner) is not WindowsSigner or frame.f_code is not open_windows_signer.__code__ or
            frame.f_locals.get('owner') is not owner or owner._state!='constructing' or
            owner._crt is not None or owner._threads is None or owner._registrar is None):
        raise InputError('early allocator capability requires its original post-registrar pre-static factory point')
    runtime=owner._signer.runtime
    from .primary_windows_threads import WindowsSDKThreadService
    from .primary_host_services import GuestExitRegistrar
    if (type(owner._threads) is not WindowsSDKThreadService or owner._threads._runtime is not None or owner._threads._registrar is not None or
            owner._threads._observer_factory is not None or owner._threads._closed or
            owner._threads._threads or owner._threads._secondary or
            type(owner._registrar) is not GuestExitRegistrar or owner._registrar._runtime is not runtime or
            owner._pid!=os.getpid() or owner._thread!=threading.get_native_id()):
        raise InputError('early allocator installation requires actual bound owner services')
    if getattr(runtime,'_primary_allocator_issuer',None) is not None:raise InputError('allocator issuer cannot be rebound')
    issuer=WindowsAllocatorIssuer(owner)
    runtime._primary_allocator_issuer=issuer
    return issuer
