from contextlib import contextmanager, nullcontext
from threading import get_ident

from .errors import InputError


class Host129RawAPIInputs:
    def __init__(self, source, *, owns_source=True):
        names = ('enter_main', 'host129_service', 'temporary', 'read_counter', 'complete_host', 'complete_main', 'close')
        if source is None or any(not callable(getattr(source, name, None)) for name in names):
            raise InputError('host129 raw API inputs require their typed source callbacks')
        self.source = source
        if type(owns_source) is not bool:
            raise InputError('host129 raw API input source ownership must be explicit boolean')
        self.owns_source = owns_source
        self.runtime = self.thread = self.owner = self.main_owner = self.main_vm = None
        self.bound = self.closed = self.completed = self.service_active = self.failed = False

    def bind(self, runtime):
        from .primary_sign import PrimaryRuntime
        if (self.bound or self.closed or type(runtime) is not PrimaryRuntime or
                runtime.raw_core_observations is not self.source or getattr(self.source, 'runtime', None) is not runtime or
                runtime._active_main is not None or runtime._execute_depth or runtime._program_calls):
            raise InputError('host129 raw API inputs require one inactive original runtime binding')
        self.runtime, self.thread, self.bound = runtime, get_ident(), True

    def _live(self):
        from .primary_sign_lifecycle import _PublicDirectOwner
        runtime = self.runtime
        owner = None if runtime is None else runtime.__dict__.get('_primary_public_direct_owner')
        from .primary_main_prefix_stop import _input_owner
        prefix = None if runtime is None else _input_owner(runtime)
        if prefix is not None:
            owner = prefix
        if (not self.bound or self.closed or self.failed or get_ident() != self.thread or not runtime.primary_core or
                runtime._active_failed or runtime._execute_thread != self.thread or
                runtime._host129_api_binding is not self or runtime.raw_core_observations is not self.source or
                (prefix is None and (type(owner) is not _PublicDirectOwner or owner.runtime is not runtime or not owner.valid())) or
                getattr(runtime, '_consumed_mgf', None) is not None or
                any(getattr(runtime, name) is not None for name in ('_host129_raw_binding',
                    '_host129_source_clock_binding', '_host129_multicall_binding', '_host129_counter_binding',
                    '_host129_clock_service_binding', '_host129_entropy_service_binding'))):
            raise InputError('host129 raw API inputs lost their original public runtime owner')
        if self.owner is None:
            self.owner = owner
        if owner is not self.owner:
            raise InputError('host129 raw API inputs cannot cross public call epochs')
        if self.main_owner is not None and (runtime._active_main is not self.main_owner or
                self.main_owner['thread'] != self.thread or self.main_owner['generation'] != runtime._main_generation):
            raise InputError('host129 raw API inputs lost their Main generation')

    def enter(self, name):
        if name not in ('main', 'host129'):
            return
        try:
            self._live()
            if name == 'main':
                runtime = self.runtime
                if (self.main_owner is not None or len(runtime._program_calls) != 1 or
                        runtime._program_calls[0]['name'] != 'main' or runtime._program_calls[0]['hosts'] is not None or
                        len(runtime._program_calls[0]['arguments']) != 12 or runtime._program_calls[0]['arguments'][0] != 4 or
                        type(runtime._active_main) is not dict or runtime._active_main['vm'] is not None):
                    raise InputError('host129 raw API inputs require one actual normal Main entry')
                self.main_owner = runtime._active_main
        except BaseException as error:
            self._close_after_failure(error)
            raise

    def attach_vm(self, name, vm):
        if name != 'main':
            return
        try:
            self._live()
            if self.main_vm is not None or self.main_owner['vm'] is not vm:
                raise InputError('host129 raw API inputs require their original Main VM')
            self.source.enter_main(self.runtime, vm)
            self.main_vm = vm
        except BaseException as error:
            self._close_after_failure(error)
            raise

    def service(self, vm, rva, cells, argument_types):
        stack = self.runtime._program_calls
        if not stack or stack[-1]['name'] != 'host129':
            return nullcontext()
        return self._service(vm, rva, cells, argument_types)

    @contextmanager
    def _service(self, vm, rva, cells, argument_types):
        try:
            self._live()
            if self.service_active:
                raise InputError('host129 raw API service cannot nest')
            self.service_active = True
            from .primary_prefix_raw_clock import host_clock_scope
            with self.source.host129_service(self.runtime, vm, rva, cells, argument_types):
                with host_clock_scope(self.runtime, vm):
                    yield
            self._live()
        except BaseException as error:
            self._close_after_failure(error)
            raise
        finally:
            self.service_active = False

    def temporary(self, fallback):
        try:
            self._live()
            if not self.service_active:
                raise InputError('host129 raw API temporary requires its active service')
            return self.source.temporary(self.runtime, 8, fallback)
        except BaseException as error:
            self._close_after_failure(error)
            raise

    def read_counter(self, vm, pc, source, destination, width):
        try:
            self._live()
            return self.source.read_counter(self.runtime, vm, pc, source, destination, width)
        except BaseException as error:
            self._close_after_failure(error)
            raise

    def complete_vm(self, name, vm):
        if name not in ('main', 'host129'):
            return
        try:
            self._live()
            if name == 'host129':
                self.source.complete_host(self.runtime, vm)
            else:
                self.source.complete_main(self.runtime, vm)
                self.completed = True
        except BaseException as error:
            self._close_after_failure(error)
            raise

    def complete_prefix9563(self, vm, witness):
        from .primary_main_prefix_stop import _require_witness
        _require_witness(self.runtime, vm, witness)
        self._live()
        if self.service_active or vm is not self.main_vm or getattr(self, 'prefix_completed', False):
            raise InputError('raw API prefix has unfinished or repeated completion')
        self.source.complete_prefix9563(self.runtime, vm, witness)
        self.prefix_completed = True

    def _close_after_failure(self, error):
        try:
            self.close()
        except BaseException as cleanup:
            error.host129_cleanup_errors = getattr(error, 'host129_cleanup_errors', ()) + (cleanup,)
            error.add_note('Host129 input cleanup failed: ' + type(cleanup).__name__)

    def close(self):
        self.failed = True
        if not self.closed:
            self.service_active = False
            if self.owns_source:
                self.source.close()
            self.closed = True
