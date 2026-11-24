"""Own explicitly uninitialized Qimei owner; initialized backend is unavailable."""
from .primary_vm import PrimarySemanticUnavailable

class QimeiGetterOwner:
    __slots__=('_ready','_module','_cache')
    def __init__(self):self._ready=0;self._module=None;self._cache=b'\0' # logical NUL at source cache+70, not a native layout
    @property
    def status(self):return 'UNINITIALIZED' if not self._ready and self._module is None and not any(self._cache) else 'UNSUPPORTED_INITIALIZED_OR_RESTORED'
    def get(self):
        if self.status!='UNINITIALIZED':raise PrimarySemanticUnavailable('initialized/restored Qimei query requires the unimplemented a2/b backend')
        return bytes(self._cache[:36].split(b'\0',1)[0])
    def initialize(self,*args,**kwargs):raise PrimarySemanticUnavailable('Qimei a2 initialization is not implemented')
    def restore(self,*args,**kwargs):raise PrimarySemanticUnavailable('Qimei restored/module lifecycle is not implemented')
