"""GetEnvironmentVariableA delegate restricted to its actual parent helper window."""
import ctypes as C
import os,sys,threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_notification_environment_values import ModelEnvironmentValues,EnvironmentReply,NAMES

class WindowsEnvironmentValuesBackend:
    def __init__(self):self.function=None
    def call(self,name,buffer,capacity):
        if self.function is None:
            if os.name!='nt' or C.sizeof(C.c_void_p)!=8:raise PrimarySemanticUnavailable('GetEnvironmentVariableA requires Windows AMD64')
            f=C.WinDLL('kernel32',use_last_error=False).GetEnvironmentVariableA
            f.restype=C.c_uint32;f.argtypes=(C.c_void_p,C.c_void_p,C.c_uint32);self.function=f
        native_name=C.create_string_buffer(name+b'\0')
        return int(self.function(native_name,buffer,capacity))

class WindowsEnvironmentValuesService(ModelEnvironmentValues):
    origin='windows-parent-api'
    def __init__(self,parent,runtime,facade,backend=None):
        from .primary_windows_notification_environment import WindowsNotificationEnvironmentObservations
        from .primary_windows_notification_parent import WindowsNotificationParentObservations
        if type(parent) is not WindowsNotificationEnvironmentObservations or type(facade) is not WindowsNotificationParentObservations:
            raise InputError('environment delegate requires original parent and facade types')
        super().__init__(())
        self.parent=parent;self.facade=facade;self.bound_runtime=runtime;self.owner=facade.owner
        self.session=parent._session;self.binding=parent._binding
        self.bound_epoch=runtime._primary_allocator_selector_epoch
        self.backend=WindowsEnvironmentValuesBackend() if backend is None else backend
        self._guard(runtime)
    def _guard(self,runtime):
        if (runtime is not self.bound_runtime or runtime._primary_allocator_selector_epoch is not self.bound_epoch or self.parent._session!=self.session or
            self.parent._binding!=self.binding or self.facade.parent is not self.parent):
            raise InputError('environment delegate parent session changed')
        self.parent._parent_check(runtime,self.owner);self.facade._installed(runtime)
    def begin(self,runtime,names=NAMES):
        from .primary_notification_environment_values import _window
        frame=sys._getframe(1)
        if (frame.f_code is not _window.__wrapped__.__code__ or frame.f_locals.get('runtime') is not runtime or
            frame.f_locals.get('service') is not self):raise InputError('environment begin lacks exact helper window')
        self._guard(runtime);super().begin(runtime,names)
    def check(self,runtime):
        super().check(runtime);self._guard(runtime)
    def take(self,runtime,name,phase,capacity,before):
        from .primary_notification_environment_values import _observe
        frame=sys._getframe(1)
        if (frame.f_code is not _observe.__code__ or frame.f_locals.get('runtime') is not runtime or
            frame.f_locals.get('service') is not self or frame.f_locals.get('name')!=name or
            frame.f_locals.get('phase')!=phase or frame.f_locals.get('capacity')!=capacity or frame.f_locals.get('before')!=before):
            raise InputError('environment take lacks exact helper arguments')
        return super().take(runtime,name,phase,capacity,before)
    def _reply(self,runtime,name,phase,capacity,before):
        frame=sys._getframe(1)
        if frame.f_code is not ModelEnvironmentValues.take.__code__ or frame.f_locals.get('self') is not self:
            raise InputError('environment backend requires its validated source pair')
        self.check(runtime)
        if phase=='probe':return EnvironmentReply(self.backend.call(name,None,0))
        if before!=bytes(capacity):raise InputError('native environment read requires original fully known source prezero')
        native=C.create_string_buffer(before,capacity)
        result=self.backend.call(name,native,capacity)
        # Every input byte was source-defined; preserve actual postcall buffer, not result-length slicing.
        after=bytes(native.raw);return EnvironmentReply(result,after,b'\1'*capacity)
    def end(self,runtime,failed=False):
        from .primary_notification_environment_values import _window
        frame=sys._getframe(1)
        if frame.f_code is not _window.__wrapped__.__code__:raise InputError('environment end lacks original window')
        super().end(runtime,failed=failed)
