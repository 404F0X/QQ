from hashlib import sha256
import os
from threading import get_ident, get_native_id
from types import CodeType, FunctionType

from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM


class MainStageObservation:
    def __init__(self, runtime, callback, *, source_mode='raw_replay'):
        from .primary_sign import PrimaryRuntime
        if (type(runtime) is not PrimaryRuntime or not callable(callback) or
                source_mode not in ('raw_replay', 'live_windows')):
            raise ValueError('STAGE_MODEL_IDENTITY')
        self.runtime, self.callback = runtime, callback
        self.thread = get_ident()
        self.active = False
        self.status = 'NOT_OBSERVED'
        self.binding = self.owner = self.public = self.vm = self.program = None
        self.generation = None
        self.index = 0
        self.sites = None
        self.source_mode = source_mode
        self.source = self.scope = self.driver = self.body = None

    def __enter__(self):
        if self.active or self.thread != get_ident() or getattr(self.runtime, '_main_stage_observation', None) is not None:
            raise ValueError('STAGE_MODEL_IDENTITY')
        self.runtime._main_stage_observation = self
        self.active = True
        return self

    def __exit__(self, kind, error, trace):
        if getattr(self.runtime, '_main_stage_observation', None) is self:
            del self.runtime._main_stage_observation
        else:
            self.status = 'UNQUALIFIED'
        self.active = False
        self.callback = self.binding = self.owner = self.public = self.vm = self.program = self.runtime = None
        self.source = self.scope = self.driver = self.body = None

    def _live_windows(self, runtime, public, source, vm, word):
        from .primary_direct_main import MainDirectDriver
        from .primary_direct_scopes import PrimaryDirectScope
        from .primary_host129_direct import HOST129_SHA256
        from .primary_windows_core_observations import WindowsCoreObservations
        from .primary_windows_host129_source import WindowsHost129Source
        from .primary_main_prefix_stop import _input_owner
        prefix = _input_owner(runtime)
        scope = runtime.__dict__.get('_primary_direct_scope') if prefix is None else prefix
        driver = getattr(scope, 'driver', None)
        body = runtime.__dict__.get('_run_primary_main')
        code = next(item for item in MainDirectDriver.install.__code__.co_consts
                    if type(item) is CodeType and item.co_name == 'run')
        if ((prefix is None and (type(scope) is not PrimaryDirectScope or scope.runtime is not runtime or
                not scope.installed or scope.closed or scope.thread != self.thread or
                scope.public_owner is not public or any(owner is not None for owner in
                    (scope.close_owner, scope.initialization_owner, scope.worker_owner)))) or
                (prefix is not None and (not prefix.valid() or public is not prefix or prefix.vm is not vm or
                    prefix.program is not vm.program or prefix.state != 'running')) or
                type(driver) is not MainDirectDriver or driver.runtime is not runtime or
                not driver.installed or driver.closed or driver.thread != self.thread or
                type(body) is not FunctionType or body.__code__ is not code or
                body.__globals__ is not MainDirectDriver.install.__globals__ or
                driver.bindings.get('_run_primary_main', (None, None, None))[2] is not body or
                not driver.report['entered'] or driver.report['exit'] != 'RAISED' or
                type(source) is not WindowsHost129Source or source.runtime is not runtime or
                source.thread != self.thread or source.identity != (os.getpid(), get_native_id()) or
                source.owner is not public or source.failed or source.completed or
                type(source.delegate) is not WindowsCoreObservations or source.delegate._runtime is not runtime or
                source.delegate._closed or source.delegate._owner != source.identity or
                source.main_call is not runtime._program_calls[0] or
                any(getattr(runtime, name, None) is not None for name in ('_consumed_mgf', '_host129_raw_binding',
                    '_host129_source_clock_binding', '_host129_multicall_binding', '_host129_counter_binding',
                    '_host129_clock_service_binding', '_host129_entropy_service_binding'))):
            raise ValueError('STAGE_MODEL_IDENTITY')
        closure = dict(zip(body.__code__.co_freevars, (cell.cell_contents for cell in body.__closure__)))
        if (set(closure) != {'runtime', 'report', 'thread'} or closure['runtime'] is not runtime or
                closure['report'] is not driver.report or closure['thread'] != self.thread):
            raise ValueError('STAGE_MODEL_IDENTITY')
        seen = tuple(source.sites)
        sites = (2353, 5821, 62638) if seen[:1] == (2353,) else (5821, 62638)
        order = sites[:-1] + (9563, sites[-1])
        consumed = tuple(site for site in order[:self.index + 1] if site != 9563)
        if (self.index >= len(order) or order[self.index] != word or seen != consumed or
                type(source.hosts) is not list or len(source.hosts) != len(seen) or
                len({id(host) for host in source.hosts}) != len(seen) or
                any(type(host) is not PrimaryVM or host is vm or host.runtime is not runtime or
                    host.memory is not runtime.memory or host.image_base != runtime.image_base or not host.halted or
                    not any(item is host for item in runtime.vms) or
                    sha256(host.program.raw).hexdigest() != HOST129_SHA256 for host in source.hosts)):
            raise ValueError('STAGE_MODEL_ORDER')
        if self.scope is None:
            self.scope, self.driver, self.body = scope, driver, body
        if self.scope is not scope or self.driver is not driver or self.body is not body:
            raise ValueError('STAGE_MODEL_IDENTITY')
        return sites

    def observe(self, vm, word):
        from .primary_main_prefix_stop import _input_owner
        prefix = _input_owner(self.runtime)
        value = None
        try:
            from .primary_sign import PrimaryRuntime
            from .primary_sign_lifecycle import _PublicDirectOwner
            from .primary_host129_api_inputs import Host129RawAPIInputs
            runtime = self.runtime
            owner = runtime._active_main
            public = getattr(runtime, '_primary_public_direct_owner', None) if prefix is None else prefix
            binding = getattr(runtime, '_host129_api_binding', None)
            stack = runtime._program_calls
            if (not self.active or self.status == 'UNQUALIFIED' or self.thread != get_ident() or
                    getattr(runtime, '_main_stage_observation', None) is not self or
                    type(vm) is not PrimaryVM or vm.runtime is not runtime or vm.memory is not runtime.memory or
                    vm.image_base != runtime.image_base or sha256(vm.program.raw).hexdigest() != MAIN_SHA256 or
                    type(owner) is not dict or owner.get('vm') is not vm or owner.get('thread') != self.thread or
                    owner.get('generation') != runtime._main_generation or runtime._execute_thread != self.thread or
                    runtime._active_failed or (prefix is None and (type(public) is not _PublicDirectOwner or public.runtime is not runtime or
                    not public.valid())) or (prefix is not None and not prefix.valid()) or type(binding) is not Host129RawAPIInputs or binding.runtime is not runtime or
                    binding.main_owner is not owner or binding.main_vm is not vm or binding.owner is not public or
                    not binding.bound or binding.closed or binding.failed or binding.service_active or
                    binding.thread != self.thread or runtime.raw_core_observations is not binding.source or
                    len(stack) != 1 or stack[0]['name'] != 'main' or stack[0]['hosts'] is not None or
                    len(stack[0]['arguments']) != 12 or stack[0]['arguments'][0] != 4 or
                    any(getattr(vm, name) is not None for name in ('pending_once9', 'pending_once10',
                        'pending_native', 'pending_variadic', 'pending_l26', 'private_iv_native_pending'))):
                raise ValueError('STAGE_MODEL_IDENTITY')
            source = binding.source
            if self.source_mode == 'live_windows':
                sites = self._live_windows(runtime, public, source, vm, word)
            else:
                if getattr(runtime._run_primary_main, '__func__', None) is not PrimaryRuntime._run_primary_main:
                    raise ValueError('STAGE_MODEL_IDENTITY')
                sites = tuple(group.site for group in source.inputs.groups)
                if source.group_index != sum(site <= word for site in sites):
                    raise ValueError('STAGE_MODEL_ORDER')
            if sites not in ((5821, 62638), (2353, 5821, 62638)):
                raise ValueError('STAGE_MODEL_ORDER')
            order = sites[:-1] + (9563, sites[-1])
            if self.vm is None:
                self.vm, self.program, self.owner, self.public, self.binding = vm, vm.program, owner, public, binding
                self.generation, self.sites = runtime._main_generation, sites
                self.source = source
            if (self.vm is not vm or self.program is not vm.program or self.owner is not owner or
                    self.public is not public or self.binding is not binding or self.generation != runtime._main_generation or
                    self.source is not source or self.sites != sites or self.index >= len(order) or order[self.index] != word or
                    source.main_vm is not vm or source.main_owner is not owner or source.host_vm is not None or
                    source.service is not None or source.closed):
                raise ValueError('STAGE_MODEL_ORDER')
            if word == 9563:
                address = vm.cells.value(113)
                if (vm.pc != 9563 or vm.block != 209 or vm.cells.value(1198) != address or
                        not vm.arena_address <= address <= vm.arena_address + vm.arena_size - 16 or
                        vm.memory.load(address, 1) != vm.memory.load(vm.cells.pointer(1447), 1)):
                    raise ValueError('STAGE_MODEL_READ')
                stage = 'LOCAL113_16'
                value = bytearray(vm.memory.read(address, 16))
            else:
                cell = {2353: 453, 5821: 936, 62638: 8355}[word]
                if ((vm.pc, vm.block) != {2353: (2359, 54), 5821: (5827, 123), 62638: (62644, 1529)}[word] or
                        vm.host_calls[-1] != (word, runtime.image_base + 0x2DE577E, (), 129) or
                        vm.cells.value(454) != runtime.image_base + 0x2DE577E):
                    raise ValueError('STAGE_MODEL_IDENTITY')
                stage = 'HOST129_' + str(word)
                value = bytearray((vm.cells.value(cell) & 0xffffffff).to_bytes(4, 'little'))
            self.callback(stage, value)
            self.index += 1
            self.status = 'OBSERVED'
        except BaseException:
            self.status = 'UNQUALIFIED'
            if prefix is not None:
                raise
        finally:
            if value is not None:
                value[:] = bytes(len(value))


def observe_main_stage(vm, word):
    from .primary_main_prefix_stop import _input_owner
    prefix = _input_owner(vm.runtime)
    try:
        observation = getattr(vm.runtime, '_main_stage_observation', None)
        if type(observation) is MainStageObservation:
            observation.observe(vm, word)
    except BaseException:
        if prefix is not None:
            raise
