"""Wrapper cache over the same initialized Own module (internal b70)."""
from .primary_vm import PrimarySemanticUnavailable

class QimeiGetterOwner:
    __slots__ = ('_ready', '_module', '_cache', '_appid')
    def __init__(self):
        self._ready, self._module, self._cache, self._appid = 0, None, bytearray(70), None
    @property
    def status(self):
        return 'INITIALIZED' if self._ready else 'UNINITIALIZED'
    def initialize(self, module=None, inputs=None):
        from .primary_qimei_module_backend import OwnQimeiModuleBackend
        if self._ready or self._module is not None or not isinstance(module, OwnQimeiModuleBackend):
            raise PrimarySemanticUnavailable('one normally initialized Own module required')
        result = module.initialize(inputs)
        if result == 0:
            self._module, self._appid, self._ready = module, inputs.appid, 1
        return result
    def get(self):
        if self._ready:
            if self._module is None or self._appid is None:
                raise PrimarySemanticUnavailable('Qimei ready state lacks its initialized module')
            self._module._check(creator=True)
            if not self._cache[0]:
                self._module.query(self._appid, self._cache)
        return bytes(self._cache[:36]).split(b'\0', 1)[0]
    def restore(self, *args, **kwargs):
        raise PrimarySemanticUnavailable('Qimei cross-restart restoration remains unsupported')
