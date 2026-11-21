from contextlib import contextmanager

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_host129_api_inputs import Host129RawAPIInputs
from .primary_provider_init import ProviderInitializationMetadata
from .primary_windows_host129_source import WindowsHost129Source
from .primary_windows_core_observations import WindowsCoreObservations


def validate_independent(metadata, host_profile_string, primary_backend, worker_bridge_path):
    if metadata is None:
        return
    if type(metadata) is not ProviderInitializationMetadata or metadata.field_10 != host_profile_string:
        raise InputError('independent Windows setup requires typed matching provider metadata')
    if primary_backend != 'direct' or worker_bridge_path is None:
        raise InputError('independent Windows setup requires direct backend and owned worker bridge')


class IndependentWindowsSetup:
    def __init__(self, owner):
        self.owner = owner
        self.source = None
        self.delegate = None
        self._epoch_before = None
        self._method = None
        self.state = 'preparing'
        self.bootstrap_state = 'not_observed'

    def prepare(self, metadata):
        """Diagnostic direct-inner initialization; does not execute source outer init."""
        owner = self.owner
        if self.state != 'preparing' or owner._state != 'open' or owner._busy:
            raise InputError('independent Windows setup requires its idle newly constructed owner')
        try:
            owner.initialize_provider(metadata, private_context_tail=None)
            threads = owner._threads
            if threads._failure is not None:
                raise threads._failure
            snapshot = threads.snapshot()
            rows = [row for row in snapshot['threads'] if row['role'] == 'bootstrap']
            runtime = owner.signer.runtime
            if (snapshot['closed'] or snapshot['draining'] or snapshot['execution_locked'] or
                    len(rows) != 1 or rows[0]['state'] != 'created_pending' or
                    rows[0]['host_failure'] is not None or not rows[0]['handle'] or
                    not rows[0]['thread_id'] or rows[0]['source_completed'] or
                    runtime.memory.load(runtime.image_base + 0x677CE88, 1) != 1 or
                    runtime.memory.load(runtime.image_base + 0x677CE80, 8) != rows[0]['handle']):
                raise PrimarySemanticUnavailable('independent Windows setup requires its actual pending SDK bootstrap')
            self.bootstrap_state = 'created_pending'
            runtime, environment = owner.signer.runtime, owner.signer.environment
            self.delegate = WindowsCoreObservations()
            self.delegate.bind(runtime)
            self.delegate.bind_caller(owner._caller)
            source = self.source = WindowsHost129Source(delegate=self.delegate)
            prior = runtime.raw_core_observations
            runtime.raw_core_observations = source
            try:
                source.bind(runtime)
                runtime.attach_host129_raw_api_inputs(Host129RawAPIInputs(source, owns_source=False))
            finally:
                runtime.raw_core_observations = prior
            self.state = 'ready'
        except BaseException:
            self.state = 'failed'
            raise

    def prepare_outer_prefix(self, *arguments):
        """Explicit reached source prefix; never aliases diagnostic prepare()."""
        from .primary_outer_init import get_login_service,select_outer_entry
        if self.state != 'preparing' or self.owner._state != 'open' or self.owner._busy:
            raise InputError('outer prefix requires its idle newly constructed owner')
        self.state = 'preparing_outer'
        owner=self.owner
        selected=select_outer_entry(owner)
        entered=False
        try:
            owner._threads.before_public_operation();entered=True
            with owner._registrar.operation():
                # Owner-thread _crt_callback_context only supplies a lease; this
                # existing issuer also activates validated guest module TLS.
                with owner._threads._native_crt_context():
                    service=get_login_service(owner)
                    try:return service.initConfig(*arguments)
                    finally:service.release_wrappers()
        except BaseException:
            selected.fail();raise
        finally:
            try:
                if entered:owner._threads.after_public_operation()
            finally:self.state = 'failed'

    @contextmanager
    def operation(self, method):
        if method not in ('sign', 'sign_result'):
            yield
            return
        if self.state not in ('ready', 'completed'):
            raise InputError('independent Windows signer requires a clean serial public epoch')
        owner = self.owner
        runtime, environment = owner.signer.runtime, owner.signer.environment
        previous = runtime.raw_core_observations, environment.raw_core_observations
        if any(value is not owner._core_observations for value in previous):
            raise InputError('independent Windows signer core binding changed')
        source = self.source
        try:
            runtime._host129_serial_idle(self)
            if self.state == 'completed':
                source = WindowsHost129Source(delegate=self.delegate)
                runtime.raw_core_observations = environment.raw_core_observations = source
                try:
                    source.bind(runtime)
                    runtime._handoff_host129_raw_api_inputs(self, Host129RawAPIInputs(source, owns_source=False))
                except BaseException:
                    source.close()
                    raise
                self.source = source
            else:
                runtime._require_unused_host129_api_inputs(self)
                runtime.raw_core_observations = environment.raw_core_observations = source
            self._epoch_before = (owner.signer.calls, owner.signer._public_direct_serial,
                                  runtime._main_generation, len(owner._operation_outcomes))
            self._method = method
            with self.delegate._lock:
                self.delegate._stack_addresses.clear()
            self.state = 'signing'
            with source.phase('core'):
                yield
            consumed = runtime._finish_host129_api_epoch(self)
            if consumed:
                source.close()
            self.state = 'completed' if consumed else 'ready'
        except BaseException:
            self.state = 'failed'
            runtime._host129_retirement = None
            raise
        finally:
            self._epoch_before = None
            self._method = None
            competing = runtime.raw_core_observations is not source or environment.raw_core_observations is not source
            if runtime.raw_core_observations is source:
                runtime.raw_core_observations = previous[0]
            if environment.raw_core_observations is source:
                environment.raw_core_observations = previous[1]
            if competing:
                self.state = 'failed'
                runtime._host129_retirement = None
                error = InputError('independent Windows source binding changed during operation')
                import sys
                primary = sys.exception()
                if primary is None:
                    raise error
                primary.add_note(str(error))

    def close(self):
        try:
            if self.source is not None:
                self.source.close()
        finally:
            if self.delegate is not None:
                self.delegate.close()
