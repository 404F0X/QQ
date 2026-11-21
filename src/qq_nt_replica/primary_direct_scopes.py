import sys
from contextlib import contextmanager
from hashlib import sha256
from threading import get_ident
from types import SimpleNamespace

from .errors import InputError
from .primary_direct_main import MainDirectDriver
from .primary_ecrypt_direct import execute_primary_ecrypt
from .primary_host129_direct import MAIN_CALLS, execute_primary_host129, execute_primary_host129_numeric
from .primary_main_material_state import execute_primary_main_material_state
from .primary_policy3_direct import execute_primary_policy3
from .primary_sign import PrimaryRuntime, _PROGRAMS
from .primary_startup_direct import execute_primary_startup, execute_primary_status_audit_pre_main
from .primary_vm import PrimaryVM, PrimarySemanticUnavailable


def _source_locals(code, runtime, **values):
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is code:
            current = frame.f_locals
            if current.get('self', current.get('runtime')) is runtime and all(current.get(k) == v for k, v in values.items()):
                return current
        frame = frame.f_back
    return None


class _PreparationClaim:
    def __init__(self, owner, command):
        self.owner, self.command = owner, command
        self.active = True
        self.host_used = False
        self.status_transitions = []


class _StatusHostClaim:
    def __init__(self, caller, carrier, cells, arguments=(0, 0, 1, 0)):
        self.caller, self.carrier, self.cells = caller, carrier, cells
        self.arguments = arguments
        self.active = True
        self.initialize_used = self.normal_used = False


class _StatusAuditClaim:
    def __init__(self, host, phase, arguments):
        self.host, self.phase, self.arguments = host, phase, arguments
        self.active = True
        self.vm = self.call = None
        self.completed = False


class _CallerStatusTransition:
    def __init__(self, caller, phase, bit):
        self.caller, self.phase, self.bit = caller, phase, bit
        self.active, self.used = True, False

class Host129DirectScope:

    def __init__(self, runtime, *, execution_report=None):
        self.runtime, self.thread = (runtime, get_ident())
        self.installed = self.closed = False
        self.current = self.body = self.prior = None
        self.had = False
        self.report = dict(backend='INSTANCE_DIRECT_HOST129_FAMILY', status='NOT_ENTERED', semanticSegments=[], referenceRecordCount=0, numericRecordCount=0, genericReferenceTraceComplete=False, completeIndependentMain=False, scopeRestored=True)
        if execution_report is not None:
            execution_report.update(self.report)
            self.report = execution_report

    def install(self):
        runtime = self.runtime
        original = runtime._try_primary_host129_direct
        if self.installed or self.closed or get_ident() != self.thread or (not runtime.primary_core) or (getattr(runtime, '_consumed_mgf', None) is not None) or (getattr(original, '__func__', None) is not PrimaryRuntime._try_primary_host129_direct) or (getattr(original, '__self__', None) is not runtime):
            raise PrimarySemanticUnavailable('direct Host129 scope rejects replay or competing instance body')
        self.had = '_try_primary_host129_direct' in runtime.__dict__
        self.prior = runtime.__dict__.get('_try_primary_host129_direct')

        def body(name, vm):
            owner = runtime._active_main
            main = owner.get('vm') if type(owner) is dict else None
            if name == 'host129':
                if main is None or main.pc not in MAIN_CALLS:
                    return NotImplemented
                if self.current is not None:
                    raise PrimarySemanticUnavailable('direct Host129 scope already owns an active family')
            elif name not in ('host129-prepare', 'host129-select') or self.current is None:
                return NotImplemented
            if get_ident() != self.thread or runtime._execute_thread != self.thread or runtime.__dict__.get('_try_primary_host129_direct') is not body or (vm.runtime is not runtime) or (vm.memory is not runtime.memory):
                raise PrimarySemanticUnavailable('direct Host129 scope owner or executing instance changed')
            if name != 'host129' and (len(runtime.vms) < 2 or runtime.vms[-2] is not self.current):
                raise PrimarySemanticUnavailable('direct Host129 numeric child has no current family parent')
            segment = dict(program=name, completed=False, referenceRecordCount=0)
            self.report['semanticSegments'].append(segment)
            self.report['status'] = 'DIRECT_INCOMPLETE'
            if name == 'host129':
                self.current = vm
            try:
                if name == 'host129':
                    return execute_primary_host129(vm, execution_report=segment)
                return execute_primary_host129_numeric(vm, name, execution_report=segment)
            finally:
                field = 'referenceRecordCount' if name == 'host129' else 'numericRecordCount'
                self.report[field] += segment['referenceRecordCount']
                if name == 'host129':
                    self.current = None
                if all((item['completed'] for item in self.report['semanticSegments'])):
                    self.report['status'] = 'DIRECT_EXECUTED'
        self.body = body
        runtime._try_primary_host129_direct = body
        self.installed = True
        self.report['scopeRestored'] = False
        return self

    def close(self):
        if self.closed:
            return self.report
        if self.installed:
            source_binding = self.runtime._host129_source_clock_binding
            if source_binding is not None and source_binding.failed and self.report['semanticSegments']:
                self.report['status'] = 'DIRECT_INCOMPLETE'
            if get_ident() != self.thread or self.runtime.__dict__.get('_try_primary_host129_direct') is not self.body:
                self.report['scopeRestored'] = False
                raise PrimarySemanticUnavailable('direct Host129 instance body ownership changed during scope')
            if self.had:
                self.runtime._try_primary_host129_direct = self.prior
            else:
                self.runtime.__dict__.pop('_try_primary_host129_direct', None)
            self.report['scopeRestored'] = True
        self.closed = True
        self.runtime = self.current = self.body = self.prior = None
        return self.report

class MaterialStateScope:

    def __init__(self, runtime, *, public_scope=None):
        self.runtime = runtime
        self.public_scope = public_scope
        self.thread = get_ident()
        self.installed = False
        self.closed = False
        self.prior = None
        self.body = None
        self.had = False
        self.first_event = len(runtime.events)
        self.report = dict(backend='INSTANCE_DIRECT_MATERIAL_STATE', status='NOT_ENTERED', semanticSegments=[], chargedRecordCount=0, warmReuseCount=0, genericReferenceTraceComplete=False, completeIndependentMain=False, scopeRestored=True)

    def install(self):
        runtime = self.runtime
        original = runtime._run_primary_material_state
        if self.installed or self.closed or get_ident() != self.thread or (not runtime.primary_core) or (getattr(runtime, '_consumed_mgf', None) is not None) or (getattr(original, '__func__', None) is not PrimaryRuntime._run_primary_material_state) or (getattr(original, '__self__', None) is not runtime):
            raise PrimarySemanticUnavailable('independent material initializer rejects replay or a competing body scope')
        self.prior = runtime.__dict__.get('_run_primary_material_state')
        self.had = '_run_primary_material_state' in runtime.__dict__

        def run(vm):
            stack = runtime._program_calls
            if get_ident() != self.thread or runtime._execute_thread != self.thread or type(vm) is not PrimaryVM or (vm.runtime is not runtime) or (vm.memory is not runtime.memory) or runtime._active_failed or (getattr(runtime, '_consumed_mgf', None) is not None) or (not stack) or (stack[-1]['name'] != 'material-state') or (stack[-1]['arguments'] != (runtime.image_base + 114852912,)) or (stack[-1]['hosts'] is not None) or (not runtime.vms) or (runtime.vms[-1] is not vm):
                raise PrimarySemanticUnavailable('independent material initializer requires its current runtime and source frame')
            claim = runtime.__dict__.get('_primary_material_state_claim')
            if type(claim) is not dict or not callable(claim.get('valid')) or (not claim['valid'](claim)) or (claim.get('runtime') is not runtime) or (claim.get('thread') != self.thread) or (claim.get('generation') != runtime._main_generation) or (not claim.get('active')) or (claim.get('context') != runtime.image_base + 114852912) or (claim.get('guard') != runtime.image_base + 114855072) or (claim.get('body') is not run) or (runtime.__dict__.get('_run_primary_material_state') is not run) or (claim.get('owner') is not runtime._active_main) or (claim.get('vm') is not None) or (type(claim.get('parentCalls')) is not tuple) or (len(stack) != len(claim['parentCalls']) + 1) or any((a is not b for a, b in zip(stack[:-1], claim['parentCalls']))) or (claim.get('writes') is not runtime.memory.writes) or (type(claim.get('writeIndex')) is not int) or (not 0 <= claim['writeIndex'] < len(runtime.memory.writes)) or (runtime.memory.writes[claim['writeIndex']] is not claim.get('writeRow')) or (claim['writeRow'] != (claim['guard'], b'\x01\x00\x00\x00', '3591D88.initializer_claim')) or (not any((region is claim.get('guardRegion') for region in runtime.memory._regions))) or ((vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used) != (1, 0, None, True, 0)):
                raise PrimarySemanticUnavailable('independent material initializer requires its actual live source claim')
            region, guard = (claim['guardRegion'], claim['guard'])
            for address, data, source in runtime.memory.writes[claim['writeIndex'] + 1:]:
                if data is not None and address < guard + 4 and (guard < address + len(data)) or (data is None and region.address <= address < region.address + len(region.data) and (address < guard + 4)):
                    raise PrimarySemanticUnavailable('independent material initializer source claim was overwritten')
            source = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x3591D6C)
            if source is None or source.get('claim') is not claim:
                raise PrimarySemanticUnavailable('material initializer claim lacks its actual source invocation')
            if claim['owner'] is None:
                if self.public_scope is None:
                    raise PrimarySemanticUnavailable('pre-Main material initializer requires a public caller claim')
                self.public_scope._authorize_material_state(vm, claim)
            claim['vm'] = vm
            segment = dict(completed=False, referenceRecordCount=0)
            self.report['semanticSegments'].append(segment)
            self.report['status'] = 'DIRECT_INCOMPLETE'
            try:
                return execute_primary_main_material_state(vm, execution_report=segment)
            finally:
                self.report['chargedRecordCount'] += segment['referenceRecordCount']
                self.report['status'] = 'DIRECT_EXECUTED' if all((item['completed'] for item in self.report['semanticSegments'])) else 'DIRECT_INCOMPLETE'
        self.body = run
        runtime._run_primary_material_state = run
        self.installed = True
        self.report['scopeRestored'] = False
        return self

    def close(self):
        if self.closed:
            return self.report
        if self.installed:
            if self.runtime.__dict__.get('_run_primary_material_state') is not self.body:
                self.report['scopeRestored'] = False
                raise PrimarySemanticUnavailable('independent material initializer body ownership changed during scope')
            if self.had:
                self.runtime._run_primary_material_state = self.prior
            else:
                self.runtime.__dict__.pop('_run_primary_material_state', None)
            self.report['scopeRestored'] = self.runtime.__dict__.get('_run_primary_material_state') is self.prior if self.had else '_run_primary_material_state' not in self.runtime.__dict__
            fences = sum((event == ('MFENCE',) for event in self.runtime.events[self.first_event:]))
            completed = sum((item['completed'] for item in self.report['semanticSegments']))
            self.report['warmReuseCount'] = max(0, fences - completed)
            if not self.report['semanticSegments'] and self.report['warmReuseCount']:
                self.report['status'] = 'WARM_CONTEXT_REUSED'
            self.installed = False
        self.closed = True
        self.runtime = None
        self.body = None
        self.prior = None
        self.public_scope = None
        return self.report

_PARENT_CALLS = {'ecrypt-keysetup': ('ecrypt-transform', 240, (231, 59, (8, 47, 58, 60), 23, None), 48111909), 'ecrypt-packet': ('ecrypt-transform', 257, (247, 62, (12, 8, 3, 0, 4), 27, None), 48122807), 'ecrypt-blocks': ('ecrypt-packet', 9, (1, 5, (1, 3, 4), 11, None), 48122759)}

class EcryptDirectScope:

    def __init__(self, runtime, *, execution_report=None):
        self.runtime, self.thread = (runtime, get_ident())
        self.installed = self.closed = self.had = False
        self.body = self.prior = None
        self.active = []
        self.report = dict(backend='INSTANCE_DIRECT_ECRYPT_FAMILY', status='NOT_ENTERED', entered=False, semanticSegments=[], referenceRecordCount=0, completedProgramCount=0, genericReferenceTraceComplete=False, completeIndependentMain=False, final96Qualified=False, controlDomain='NONWAITING_ONCE10_WITH_FIXED_FINITE_ALTERNATE_ERRORS', scopeRestored=True, restoreError=None)
        if execution_report is not None:
            execution_report.update(self.report)
            self.report = execution_report

    def install(self):
        if self.installed or self.closed or get_ident() != self.thread:
            raise PrimarySemanticUnavailable('direct ECRYPT scope cannot be installed in its current state or thread')
        runtime = self.runtime
        original = runtime._try_primary_ecrypt_direct
        if not runtime.primary_core or getattr(runtime, '_consumed_mgf', None) is not None or getattr(original, '__func__', None) is not PrimaryRuntime._try_primary_ecrypt_direct or (getattr(original, '__self__', None) is not runtime):
            raise PrimarySemanticUnavailable('direct ECRYPT scope rejects replay or a competing instance body')
        self.had = '_try_primary_ecrypt_direct' in runtime.__dict__
        self.prior = runtime.__dict__.get('_try_primary_ecrypt_direct')

        def body(name, vm):
            owner = runtime._active_main
            main = owner.get('vm') if type(owner) is dict else None
            if name == 'ecrypt-transform':
                if main is None or main.pc != 11930:
                    return NotImplemented
                parent_name, parent, parent_word = ('main', main, 11919)
            elif name in _PARENT_CALLS and self.active:
                parent_name, parent = self.active[-1]
                parent_word = _PARENT_CALLS[name][2][0]
            else:
                return NotImplemented
            segment = dict(program=name, parentProgram=parent_name, parentWord=parent_word, completed=False, referenceRecordCount=0)
            self.report['entered'] = True
            self.report['status'] = 'DIRECT_INCOMPLETE'
            self.report['semanticSegments'].append(segment)
            state = {}
            pushed = False
            try:
                if get_ident() != self.thread or runtime._execute_thread != self.thread or runtime.__dict__.get('_try_primary_ecrypt_direct') is not body or (vm.runtime is not runtime) or (vm.memory is not runtime.memory):
                    raise PrimarySemanticUnavailable('direct ECRYPT executing instance or owner changed')
                if name == 'ecrypt-transform':
                    if self.active:
                        raise PrimarySemanticUnavailable('direct ECRYPT scope already owns an active family')
                else:
                    expected_name, consumed, marker, rva = _PARENT_CALLS[name]
                    if parent_name != expected_name or parent.pc != consumed or getattr(parent, '_primary_ecrypt_active_call', None) != marker or (not parent.host_calls) or (parent.host_calls[-1] != (marker[0], runtime.image_base + rva, marker[2], marker[3])):
                        raise PrimarySemanticUnavailable('direct ECRYPT child is outside its actual parent host window')
                self.active.append((name, vm))
                pushed = True
                return execute_primary_ecrypt(vm, name, execution_report=state)
            except BaseException as error:
                segment['error'] = type(error).__name__
                raise
            finally:
                if pushed:
                    self.active.pop()
                segment.update(state)
                self.report['referenceRecordCount'] += segment['referenceRecordCount']
                self.report['completedProgramCount'] = sum((item['completed'] for item in self.report['semanticSegments']))
                if all((item['completed'] for item in self.report['semanticSegments'])):
                    self.report['status'] = 'DIRECT_EXECUTED'
        self.body = body
        runtime._try_primary_ecrypt_direct = body
        self.installed = True
        self.report['scopeRestored'] = False
        return self

    def close(self):
        if self.closed:
            return self.report
        if self.installed:
            primary = sys.exception()
            if self.report['entered'] and (primary is not None or self.runtime._active_failed):
                self.report['status'] = 'DIRECT_INCOMPLETE'
                self.report['lifecycleError'] = type(primary).__name__ if primary is not None else 'ACTIVE_RUNTIME_FAILED'
            if get_ident() != self.thread or self.active or self.runtime.__dict__.get('_try_primary_ecrypt_direct') is not self.body:
                self.report['scopeRestored'] = False
                self.report['restoreError'] = 'ECRYPT_SCOPE_OWNERSHIP_CHANGED'
                error = PrimarySemanticUnavailable('direct ECRYPT instance body ownership changed during scope')
                if primary is not None:
                    primary.add_note(str(error))
                    return self.report
                raise error
            if self.had:
                self.runtime._try_primary_ecrypt_direct = self.prior
            else:
                self.runtime.__dict__.pop('_try_primary_ecrypt_direct', None)
            self.report['scopeRestored'] = True
        self.installed = False
        self.closed = True
        self.runtime = self.body = self.prior = None
        self.active.clear()
        return self.report

_CHILD_CALLS = {'status-audit': ('primary-setup', 362, '_primary_startup_active_call', (353, 66, (14, 65, 34, 61), 14, None), 48139340), 'cocos-init': ('host97', 609, '_primary_policy3_active_call', (602, 131, (12, 107), 35, None), 56238320), 'cocos-crypt': ('host97', 646, '_primary_policy3_active_call', (636, 136, (12, 135, 134, 133, 137), 37, None), 56238363), 'cocos-publish': ('host97', 860, '_primary_policy3_active_call', (852, 170, (5, 171, 168), 39, None), 56239647)}

_ARGUMENT_COUNTS = {'primary-setup': 0, 'status-audit': 5, 'host97': 7, 'cocos-init': 2, 'cocos-crypt': 5, 'cocos-publish': 3}

class StartupPolicyDirectScope:

    def __init__(self, runtime, *, execution_report=None):
        self.runtime, self.thread = (runtime, get_ident())
        self.installed = self.closed = self.had = False
        self.body = self.prior = self.family = None
        self.active = []
        self.report = dict(backend='INSTANCE_DIRECT_STARTUP_POLICY3_FAMILIES', status='NOT_ENTERED', entered=False, semanticSegments=[], referenceRecordCount=0, completedProgramCount=0, genericReferenceTraceComplete=False, completeIndependentMain=False, final96Qualified=False, providerCoverage='EXTERNAL_OWNER_ROUTE_NOT_QUALIFIED_BY_THIS_SCOPE', controlDomain='NONWAITING_ONCE10_WITH_FIXED_FINITE_ALTERNATE_ERRORS', scopeRestored=True, restoreError=None)
        if execution_report is not None:
            execution_report.update(self.report)
            self.report = execution_report

    def install(self):
        if self.installed or self.closed or get_ident() != self.thread:
            raise PrimarySemanticUnavailable('direct startup scope cannot be installed in its current state or thread')
        runtime = self.runtime
        original = runtime._try_primary_startup_direct
        if not runtime.primary_core or getattr(runtime, '_consumed_mgf', None) is not None or getattr(original, '__func__', None) is not PrimaryRuntime._try_primary_startup_direct or (getattr(original, '__self__', None) is not runtime):
            raise PrimarySemanticUnavailable('direct startup scope rejects replay or a competing instance body')
        self.had = '_try_primary_startup_direct' in runtime.__dict__
        self.prior = runtime.__dict__.get('_try_primary_startup_direct')

        def body(name, vm):
            owner = runtime._active_main
            main = owner.get('vm') if type(owner) is dict else None
            if name in ('primary-setup', 'host97'):
                selected = main is not None and (main.pc in (1168, 34869) if name == 'primary-setup' else main.pc == 444)
                if not selected:
                    return NotImplemented
                parent_name, parent = ('main', main)
                parent_word = (1160 if main.pc == 1168 else 34861) if name == 'primary-setup' else 432
            elif name in _CHILD_CALLS and self.active:
                parent_name, parent = self.active[-1]
                parent_word = _CHILD_CALLS[name][3][0]
            else:
                return NotImplemented
            segment = dict(program=name, parentProgram=parent_name, parentWord=parent_word, completed=False, referenceRecordCount=0)
            self.report['entered'] = True
            self.report['status'] = 'DIRECT_INCOMPLETE'
            self.report['semanticSegments'].append(segment)
            state = {}
            pushed = root = False
            try:
                calls = runtime._program_calls
                if get_ident() != self.thread or runtime._execute_thread != self.thread or runtime.__dict__.get('_try_primary_startup_direct') is not body or (vm.runtime is not runtime) or (vm.memory is not runtime.memory) or (not calls) or (calls[-1]['name'] != name) or (len(calls[-1]['arguments']) != _ARGUMENT_COUNTS[name]) or (calls[-1]['hosts'] != (() if name == 'cocos-init' else None)):
                    raise PrimarySemanticUnavailable('direct startup executing instance, owner or reader ABI changed')
                if name in ('primary-setup', 'host97'):
                    if self.active or self.family is not None:
                        raise PrimarySemanticUnavailable('direct startup scope already owns an active family')
                    self.family = (owner, main, calls[0], runtime._main_generation)
                    root = True
                else:
                    if self.family is None or owner is not self.family[0] or main is not self.family[1] or (calls[0] is not self.family[2]) or (runtime._main_generation != self.family[3]):
                        raise PrimarySemanticUnavailable('direct startup child lost its selected Main family')
                    expected_name, consumed, attribute, marker, rva = _CHILD_CALLS[name]
                    if parent_name != expected_name or parent.pc != consumed or getattr(parent, attribute, None) != marker or (not parent.host_calls) or (parent.host_calls[-1] != (marker[0], runtime.image_base + rva, marker[2], marker[3])):
                        raise PrimarySemanticUnavailable('direct startup child is outside its actual parent host window')
                self.active.append((name, vm))
                pushed = True
                execute = execute_primary_startup if name in ('primary-setup', 'status-audit') else execute_primary_policy3
                return execute(vm, name, execution_report=state)
            except BaseException as error:
                segment['error'] = type(error).__name__
                raise
            finally:
                if pushed:
                    self.active.pop()
                if root:
                    self.family = None
                segment.update(state)
                self.report['referenceRecordCount'] += segment['referenceRecordCount']
                self.report['completedProgramCount'] = sum((item['completed'] for item in self.report['semanticSegments']))
                if all((item['completed'] for item in self.report['semanticSegments'])):
                    self.report['status'] = 'DIRECT_EXECUTED'
        self.body = body
        runtime._try_primary_startup_direct = body
        self.installed = True
        self.report['scopeRestored'] = False
        return self

    def close(self):
        if self.closed:
            return self.report
        if self.installed:
            primary = sys.exception()
            if self.report['entered'] and (primary is not None or self.runtime._active_failed):
                self.report['status'] = 'DIRECT_INCOMPLETE'
                self.report['lifecycleError'] = type(primary).__name__ if primary is not None else 'ACTIVE_RUNTIME_FAILED'
            if get_ident() != self.thread or self.active or self.family is not None or (self.runtime.__dict__.get('_try_primary_startup_direct') is not self.body):
                self.report['scopeRestored'] = False
                self.report['restoreError'] = 'STARTUP_SCOPE_OWNERSHIP_CHANGED'
                error = PrimarySemanticUnavailable('direct startup instance body ownership changed during scope')
                if primary is not None:
                    primary.add_note(str(error))
                    return self.report
                raise error
            if self.had:
                self.runtime._try_primary_startup_direct = self.prior
            else:
                self.runtime.__dict__.pop('_try_primary_startup_direct', None)
            self.report['scopeRestored'] = True
        self.installed = False
        self.closed = True
        self.runtime = self.body = self.prior = self.family = None
        self.active.clear()
        return self.report


class PrimaryDirectScope:
    def __init__(self, runtime, *, public_owner=None, close_owner=None, initialization_owner=None, worker_owner=None, secondary_owner=None, notification_owner=None, device_owner=None, execution_report=None):
        self.runtime, self.public_owner, self.thread = runtime, public_owner, get_ident()
        self.close_owner = close_owner
        self.initialization_owner = initialization_owner
        self.worker_owner = worker_owner
        self.secondary_owner = secondary_owner
        self.notification_owner = notification_owner
        self.device_owner = device_owner
        self._request_audit = None
        self.installed = self.closed = self.had = False
        self.prior = None
        self.driver = None
        self.children = []
        self._caller = self._status_host = self._audit = None
        self._status_transition = None
        self._caller_used = False
        self._refresh = self._refresh_operation = None
        self._refresh_used = False
        self._material_reuse = None
        self.report = dict(backend='PRODUCT_INSTANCE_DIRECT_SCOPES', mainDriver={},
                           publicPreparation=dict(status='NOT_ENTERED', completed=False),
                           preMainStatus=dict(status='NOT_ENTERED', semanticSegments=[], referenceRecordCount=0),
                           materialState={}, auxiliaryPrograms=[], scopeRestored=True,
                           completeIndependentMain=False, final96Qualified=False)
        if execution_report is not None:
            execution_report.clear()
            execution_report.update(self.report)
            self.report = execution_report

    def _valid_public(self):
        from .primary_sign_lifecycle import _PublicDirectOwner
        owner = self.public_owner
        return (type(owner) is _PublicDirectOwner and owner.runtime is self.runtime and
                owner.thread == self.thread == get_ident() and owner.valid())

    def _valid_close(self):
        from .primary_sign_lifecycle import _CloseDirectOwner
        owner = self.close_owner
        return (type(owner) is _CloseDirectOwner and owner.runtime is self.runtime and
                owner.thread == self.thread == get_ident() and owner.valid())

    def _valid_initialization(self):
        from .primary_sign_lifecycle import _ProviderInitializationOwner
        owner = self.initialization_owner
        return (type(owner) is _ProviderInitializationOwner and owner.runtime is self.runtime and
                owner.thread == self.thread == get_ident() and owner.valid())

    def _valid_worker(self):
        from .primary_sign_lifecycle import _SDKWorkerOwner
        owner = self.worker_owner
        return (type(owner) is _SDKWorkerOwner and owner.runtime is self.runtime and
                owner.thread == self.thread == get_ident() and owner.valid())

    def _valid_secondary(self):
        from .primary_sign_lifecycle import _SecondaryPostfetchOwner
        owner = self.secondary_owner
        return (type(owner) is _SecondaryPostfetchOwner and owner.runtime is self.runtime and
                owner.thread == self.thread == get_ident() and owner.valid())

    def _valid_device(self):
        from .primary_device_request import _DeviceRequestOwner
        owner = self.device_owner
        return (type(owner) is _DeviceRequestOwner and owner.runtime is self.runtime and
                owner.thread == self.thread == get_ident() and owner.valid())

    def _valid_notification(self):
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        owner = self.notification_owner
        return (type(owner) is _NotificationWorkerOwner and owner.runtime is self.runtime and
                owner.thread == self.thread == get_ident() and owner.valid())

    def notification_handoff_setting(self, carrier, rva, cells, *, completed):
        from .primary_notification_handoff_audit import _NotificationHandoffAuditClaim
        claim = self._request_audit
        if type(claim) is not _NotificationHandoffAuditClaim:
            return False
        claim.setting(carrier, rva, cells, completed=completed)
        return True

    def _notification_handoff_program(self, name):
        from .primary_notification_handoff_audit import _NotificationHandoffAuditClaim
        claim = self._request_audit
        if type(claim) is not _NotificationHandoffAuditClaim:
            return False
        claim.program(name)
        return True

    def _notification_claim(self):
        self._require_live()
        from .primary_notification_mandatory_maps import _ProducerClaim, material_map
        claim = self.runtime.__dict__.get('_notification_mandatory_claim')
        if (type(claim) is not _ProducerClaim or not claim.valid() or claim.owner is not self.notification_owner or
                claim.rva != 0x2E01C70 or claim.source.f_code is not material_map.__code__):
            raise PrimarySemanticUnavailable('notification setting lacks its actual material producer')
        local = claim.source.f_locals
        if local.get('gate') != 1 or local.get('logged') is not True or local.get('output') != claim.output:
            raise PrimarySemanticUnavailable('notification setting precedes its full predicate results and logs')
        wrapper, qqnt = local.get('wrapper_result'), local.get('qqnt_result')
        if any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in (wrapper, qqnt)):
            raise InputError('notification predicates require complete source DWORD results')
        bits = ((19,) if qqnt == 0 else ()) + ((20,) if wrapper == 0 else ())
        if claim.setting_index >= len(bits) or local.get('bit') != bits[claim.setting_index]:
            raise PrimarySemanticUnavailable('notification setting bit is stale, repeated or out of source order')
        return claim, local, bits[claim.setting_index]

    def require_module_collector_phase(self):
        self._require_live()
        from .primary_notification_modules import _ModuleCollectorClaim
        claim = self.runtime.__dict__.get('_notification_module_collector_claim')
        if (not self._valid_notification() or type(claim) is not _ModuleCollectorClaim or
                claim.runtime is not self.runtime or claim.scope is not self or
                claim.owner is not self.notification_owner or not claim.valid()):
            raise PrimarySemanticUnavailable('module collector requires its exact independent notification source phase')
        return claim

    def require_parent_phase(self):
        self._require_live()
        from .primary_notification_parent import _ParentClaim
        claim = self.runtime.__dict__.get('_notification_parent_claim')
        if (not self._valid_notification() or type(claim) is not _ParentClaim or not claim.valid() or
                claim.owner is not self.notification_owner or claim.runtime is not self.runtime):
            raise PrimarySemanticUnavailable('notification API requires its actual live parent phase')
        return claim

    def require_constructor_phase(self):
        self._require_live()
        from .primary_notification_environment import _ConstructorClaim
        claim = self.runtime.__dict__.get('_notification_constructor_claim')
        if (not self._valid_notification() or type(claim) is not _ConstructorClaim or not claim.valid() or
                claim.owner is not self.notification_owner or claim.runtime is not self.runtime):
            raise PrimarySemanticUnavailable('notification API requires its actual live constructor phase')
        return claim

    def notification_setting(self, carrier, rva, cells, *, completed):
        from .primary_worker_consumer import _invoke
        claim, local, bit = self._notification_claim()
        runtime = self.runtime
        source = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=rva)
        worker = _source_locals(_invoke.__code__, runtime, rva=rva)
        expected_rva = 0x1BF75A0 if claim.setting_stage == 'audit' else 0x1BF8090
        if (rva != expected_rva or local.get('setting_rva') != rva or source is None or worker is None or
                type(carrier) is not SimpleNamespace or cells != (0, 1, 2, 3) or source.get('vm') is not carrier or
                source.get('cells') is not cells or worker.get('vm') is not carrier or
                worker.get('values') != (1, bit, 1, 0) or runtime._program_calls or
                tuple(carrier.cells.value(i) for i in range(4)) != (1, bit, 1, 0)):
            raise PrimarySemanticUnavailable('notification setting requires its exact ordered source carrier and ABI')
        if completed:
            if rva != 0x1BF8090 or claim.setting_stage != 'update':
                raise PrimarySemanticUnavailable('notification update completion is out of order')
            claim.setting_index += 1
            claim.setting_stage = 'audit'
        return claim

    @contextmanager
    def _notification_status_host(self, carrier, cells):
        caller = self.notification_setting(carrier, 0x1BF75A0, cells, completed=False)
        if self._status_host is not None or self._audit is not None:
            raise PrimarySemanticUnavailable('notification status host is already active')
        bit = caller.source.f_locals['bit']
        claim = _StatusHostClaim(caller, carrier, cells, (1, bit, 1, 0))
        self._status_host = claim
        try:
            yield
            self._notification_claim()
            if not claim.normal_used or self._audit is not None:
                raise PrimarySemanticUnavailable('notification status host did not finish its actual audit')
            caller.setting_stage = 'update'
        finally:
            claim.active = False
            if self._status_host is claim:
                self._status_host = None

    def _require_worker(self):
        if self._refresh is not None:
            return self._require_refresh()
        self._require_live()
        from .primary_worker_loop import run, _invoke
        runtime = self.runtime
        phase = _source_locals(run.__code__, runtime)
        source = _source_locals(_invoke.__code__, runtime)
        bootstrap = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x1C1BB80)
        if (not self._valid_worker() or phase is None or phase.get('parameter') != 0 or
                source is None or bootstrap is None or bootstrap.get('cells') != (0,) or
                bootstrap.get('vm') is not self.worker_owner.source.f_locals.get('vm') or
                runtime._active_main is not None or runtime._active_failed):
            raise PrimarySemanticUnavailable('SDK direct scope requires its actual live bootstrap source chain')
        return self.worker_owner, phase, source

    def _require_refresh(self, *, operation=True):
        self._require_live()
        from .primary_worker_loop import run
        from .primary_worker import refresh_context, classify_environment, _flag, _refresh_status
        from types import GeneratorType
        runtime, claim = self.runtime, self._refresh
        phase = _source_locals(run.__code__, runtime)
        bootstrap = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x1C1BB80)
        owner = self.worker_owner
        domain = None if phase is None else getattr(phase.get('refresh_domain'), 'gen', None)
        domain_frame = None if type(domain) is not GeneratorType else domain.gi_frame
        if (claim is None or not claim.active or not self._valid_worker() or owner.status_index != 3 or
                not self._worker_material_ready(owner) or phase is None or phase.get('parameter') != 0 or
                phase.get('context') != claim.context or
                runtime.memory.load(runtime.image_base + 0x677CEF8, 8) != claim.context or
                runtime.memory.load(runtime.image_base + 0x6D88CA0, 4) != 2 or
                bootstrap is None or bootstrap.get('cells') != (0,) or
                bootstrap.get('vm') is not owner.source.f_locals.get('vm') or
                type(domain) is not GeneratorType or domain.gi_code is not type(self).worker_refresh.__wrapped__.__code__ or
                domain_frame is None or domain_frame.f_locals.get('self') is not self or
                domain_frame.f_locals.get('claim') is not claim or
                runtime._active_main is not None or runtime._active_failed):
            raise PrimarySemanticUnavailable('SDK refresh requires its original initialized worker context')
        if not operation:
            return owner, phase, None
        refresh = _source_locals(refresh_context.__code__, runtime, context=claim.context)
        current = self._refresh_operation
        if current is None or not current.active or refresh is None:
            raise PrimarySemanticUnavailable('SDK refresh requires its current source operation')
        source = refresh if current.kind == 'power' else _source_locals(_flag.__code__, runtime)
        classification = _source_locals(classify_environment.__code__, runtime, context=claim.context)
        allowed = {4: 0x10, 5: 0x20, 7: 0x80, 17: 0x200}
        if (source is None or source.get('vm') is not current.carrier or
                source.get('values') is not current.values or
                any(type(current.carrier.cells.value(i)) is not int or
                    current.carrier.cells.value(i) != current.values[i] for i in range(4))):
            raise PrimarySemanticUnavailable('SDK refresh lost its original carrier or values')
        status_domain = getattr(source.get('status_domain'), 'gen', None)
        status_frame = None if type(status_domain) is not GeneratorType else status_domain.gi_frame
        operation_domain = None if status_frame is None else getattr(status_frame.f_locals.get('domain'), 'gen', None)
        operation_frame = None if type(operation_domain) is not GeneratorType else operation_domain.gi_frame
        if (type(status_domain) is not GeneratorType or status_domain.gi_code is not _refresh_status.__wrapped__.__code__ or
                status_frame is None or status_frame.f_locals.get('runtime') is not runtime or
                status_frame.f_locals.get('vm') is not current.carrier or
                type(operation_domain) is not GeneratorType or
                operation_domain.gi_code is not type(self).refresh_status_operation.__wrapped__.__code__ or
                operation_frame is None or operation_frame.f_locals.get('self') is not self or
                operation_frame.f_locals.get('claim') is not current):
            raise PrimarySemanticUnavailable('SDK refresh lost its original operation lifetime')
        if current.kind == 'flag':
            bit = source.get('bit')
            if (type(bit) is not int or bit not in allowed or source.get('mask') != allowed[bit] or
                    current.values != (1, bit, 1, 0) or
                    (bit == 17 and classification is not None) or
                    (bit != 17 and classification is None)):
                raise PrimarySemanticUnavailable('SDK refresh flag is outside its source classification')
        elif current.kind == 'power':
            power, result = refresh.get('power'), refresh.get('result')
            if (classification is not None or current.values != (1, 23, 1, 0) or
                    type(result) is not int or not result & 0xFFFFFFFF or type(power) is not bytes or
                    not 2 <= len(power) <= 12 or power[1] in (0x80, 0xFF)):
                raise PrimarySemanticUnavailable('SDK refresh power status lacks its actual supported observation')
        else:
            raise PrimarySemanticUnavailable('unknown SDK refresh source operation')
        return owner, phase, source

    @contextmanager
    def worker_refresh(self, context):
        self._require_live()
        if (self.worker_owner is None or self._refresh_used or self._refresh is not None or
                type(context) is not int or
                self._status_host is not None or self._audit is not None or self.runtime._program_calls):
            raise PrimarySemanticUnavailable('SDK refresh requires one unused worker phase')
        claim = SimpleNamespace(context=context, active=True)
        self._refresh, self._refresh_used = claim, True
        try:
            self._require_refresh(operation=False)
            yield
            self._require_refresh(operation=False)
            if self._refresh_operation is not None or self._status_host is not None or self._audit is not None:
                raise PrimarySemanticUnavailable('SDK refresh retained an active child')
        finally:
            self._revoke_refresh('_refresh', claim)

    def _revoke_refresh(self, slot, claim):
        claim.active = False
        if getattr(self, slot) is claim:
            setattr(self, slot, None)
            return
        error = PrimarySemanticUnavailable('SDK refresh claim ownership changed during execution')
        primary = sys.exception()
        if primary is not None:
            primary.add_note(str(error))
        else:
            raise error

    @contextmanager
    def refresh_status_operation(self, carrier, values, kind):
        if (self._refresh_operation is not None or type(carrier) is not SimpleNamespace or
                type(values) is not tuple or len(values) != 4 or any(type(v) is not int for v in values)):
            raise PrimarySemanticUnavailable('SDK refresh operation rejects nesting or foreign ABI')
        claim = SimpleNamespace(carrier=carrier, values=values, kind=kind, active=True, status_completed=False)
        self._refresh_operation = claim
        try:
            self._require_refresh()
            yield
            _, _, source = self._require_refresh()
            if not claim.status_completed or source.get('rva') != 0x1BF8090:
                raise PrimarySemanticUnavailable('SDK refresh operation did not complete its ordered wrappers')
        finally:
            self._revoke_refresh('_refresh_operation', claim)

    @contextmanager
    def _refresh_status_host(self, carrier, cells):
        owner, _, worker = self._require_refresh()
        operation = self._refresh_operation
        source = _source_locals(PrimaryRuntime.invoke.__code__, self.runtime, rva=0x1BF75A0)
        if (operation.status_completed or worker.get('rva') != 0x1BF75A0 or
                carrier is not operation.carrier or type(cells) is not tuple or cells != (0, 1, 2, 3) or
                source is None or source.get('vm') is not carrier or source.get('cells') is not cells or
                self._status_host is not None or self.runtime._program_calls):
            raise PrimarySemanticUnavailable('SDK refresh status requires its original one-use wrapper')
        claim = _StatusHostClaim(owner, carrier, cells, operation.values)
        self._status_host = claim
        try:
            yield
            self._require_refresh()
            if not claim.normal_used or self._audit is not None:
                raise PrimarySemanticUnavailable('SDK refresh status did not complete its actual audit child')
            operation.status_completed = True
        finally:
            claim.active = False
            if self._status_host is claim:
                self._status_host = None

    def refresh_wrapper(self, rva):
        _, _, source = self._require_refresh()
        operation = self._refresh_operation
        if (rva not in (0x1BF75A0, 0x1BF8090) or source.get('rva') != rva or
                operation.status_completed is not (rva == 0x1BF8090)):
            raise PrimarySemanticUnavailable('SDK refresh wrappers are out of source order')

    @contextmanager
    def _worker_status_host(self, carrier, cells):
        owner, phase, worker = self._require_worker()
        source = _source_locals(PrimaryRuntime.invoke.__code__, self.runtime, rva=0x1BF75A0)
        expected = ((1, 2, 1, 0), ((1 << 64) - 4, 0, 3, 1), (0, 0, 2, 1))
        if (owner.status_index >= 3 or phase.get('rva') != 0x1BF75A0 or
                phase.get('arguments') != expected[owner.status_index] or
                worker.get('rva') != 0x1BF75A0 or worker.get('values') != expected[owner.status_index] or
                self._status_host is not None or self.runtime._program_calls or type(carrier) is not SimpleNamespace or
                cells != (0, 1, 2, 3) or source is None or source.get('vm') is not carrier or
                source.get('cells') is not cells or worker.get('vm') is not carrier):
            raise PrimarySemanticUnavailable('SDK status requires its original ordered worker carrier and ABI')
        claim = _StatusHostClaim(owner, carrier, cells, expected[owner.status_index])
        self._status_host = claim
        try:
            yield
            self._require_worker()
            if not claim.normal_used or self._audit is not None:
                raise PrimarySemanticUnavailable('SDK status did not complete its actual audit child')
            owner.status_index += 1
            self.report['sdkWorker']['statusCompleted'] = owner.status_index
        finally:
            claim.active = False
            if self._status_host is claim:
                self._status_host = None

    def _require_initialization(self):
        self._require_live()
        from .primary_provider_init import initialize, initialize_metadata
        owner, runtime = self.initialization_owner, self.runtime
        source = _source_locals(initialize_metadata.__code__, runtime)
        phase = _source_locals(initialize.__code__, runtime)
        if (not self._valid_initialization() or source is None or source.get('metadata') is not owner.metadata or
                source.get('private_context_tail') is not owner.tail or phase is None or
                not phase.get('metadata') or runtime._active_main is not None or runtime._active_failed):
            raise PrimarySemanticUnavailable('provider initialization lost its original metadata operation and phase')
        return owner

    def _configuration_owner(self):
        if self.initialization_owner is not None:
            from .primary_provider_init import initialize, initialize_services, initialize_configuration, configure
            owner = self._require_initialization()
            runtime = self.runtime
            root = _source_locals(initialize.__code__, runtime)
            services = _source_locals(initialize_services.__code__, runtime)
            configuration = _source_locals(initialize_configuration.__code__, runtime)
            source = _source_locals(configure.__code__, runtime)
            if (services is None or configuration is None or source is None or
                    services.get('context') != root.get('context') or
                    configuration.get('context') != root.get('context') or
                    source.get('config') != runtime.image_base + 0x67516B0 or
                    source.get('context') != configuration.get('copied')):
                raise PrimarySemanticUnavailable('provider GUID configuration requires its original nested source contexts')
            return owner
        return self.public_owner if self._valid_public() else None

    def _status_owner(self):
        if self._request_audit is not None:
            return self._request_audit.require()
        if self.notification_owner is not None:
            return self._notification_claim()[0]
        if self.worker_owner is not None:
            return self._require_worker()[0]
        if self.initialization_owner is not None:
            return self._require_initialization()
        return self._require_caller()

    @contextmanager
    def _initialization_status_host(self, carrier, cells):
        from .primary_provider_init import initialize
        from .primary_worker_consumer import _invoke
        owner = self._require_initialization()
        phase = _source_locals(initialize.__code__, self.runtime)
        source = _source_locals(PrimaryRuntime.invoke.__code__, self.runtime, rva=0x1BF75A0)
        worker = _source_locals(_invoke.__code__, self.runtime, rva=0x1BF75A0)
        expected = (((1 << 64) - 4, 0, 3, 1), (0, 0, 2, 1))
        if (owner.status_index >= 2 or phase.get('rva') != 0x1BF75A0 or self._status_host is not None or
                self.runtime._program_calls or type(carrier) is not SimpleNamespace or cells != (0, 1, 2, 3) or
                source is None or source.get('vm') is not carrier or source.get('cells') is not cells or
                worker is None or worker.get('vm') is not carrier or worker.get('values') != expected[owner.status_index]):
            raise PrimarySemanticUnavailable('provider status requires its original ordered initialization carrier')
        claim = _StatusHostClaim(owner, carrier, cells, expected[owner.status_index])
        self._status_host = claim
        try:
            yield
            self._require_initialization()
            if not claim.normal_used or self._audit is not None:
                raise PrimarySemanticUnavailable('provider status initialization did not complete its actual audit')
            owner.status_index += 1
        finally:
            claim.active = False
            if self._status_host is claim:
                self._status_host = None

    def _authorize_initialization_bootstrap(self, vm, name):
        from .primary_bootstrap_direct import _HOSTS, _BUFFER_HOSTS, PROGRAM_SHA256, _host
        from .primary_source2581_direct import _ConfigurationClaim, _host as guid_host, PROGRAM_SHA256 as guid_hashes
        owner, runtime = self._require_initialization(), self.runtime
        reader = _source_locals(PrimaryRuntime._execute_program.__code__, runtime, name=name)
        singleton = _source_locals(PrimaryRuntime._singleton.__code__, runtime)
        calls = runtime._program_calls
        if (reader is None or reader.get('vm') is not vm or singleton is None or vm.runtime is not runtime or
                vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
                runtime._execute_thread != self.thread or runtime._execute_depth != len(calls) or
                not runtime.vms or runtime.vms[-1] is not vm or getattr(vm, '_primary_bootstrap_used', False)):
            raise PrimarySemanticUnavailable('provider bootstrap requires its actual fresh singleton reader')
        if name == 'singleton-init':
            parents = tuple(calls[:-1])
            if parents:
                claim = runtime.__dict__.get('_primary_source2581_claim')
                root = getattr(claim, 'root', None)
                host = _source_locals(guid_host.__code__, runtime)
                wrapper = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x3592167)
                valid = (type(claim) is _ConfigurationClaim and claim.owner is owner and claim.active and
                         claim.scope is self and type(root) is PrimaryVM and root.runtime is runtime and
                         sha256(root.program.raw).hexdigest() == guid_hashes['source2581'] and not root.halted and
                         (root.pc, root.block, root.predecessor, root.initial_block) == (33, 1, 0, False) and
                         len(parents) == 1 and parents[0] is claim.root_call and
                         getattr(root, '_primary_source2581_active_call', None) == (27, 10, (), 10, 9) and
                         root.host_calls[-1:] == [(27, runtime.image_base + 0x3592167, (), 10)] and
                         host is not None and host.get('vm') is root and wrapper is not None and wrapper.get('vm') is root)
            else:
                from .primary_provider_init import configure, initialize
                from .primary_worker_consumer import _invoke as source_invoke
                host = self._status_host
                wrapper = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x1BF75A0)
                status = (type(host) is _StatusHostClaim and host.active and host.caller is owner and
                          wrapper is not None and wrapper.get('vm') is host.carrier)
                registration = _source_locals(PrimaryRuntime._register_callback_group.__code__, runtime)
                provider = _source_locals(PrimaryRuntime._register_provider_base.__code__, runtime)
                configure_source = _source_locals(configure.__code__, runtime)
                callback = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x2DE5910)
                register_call = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x1BF63F0)
                registration_matches = (registration is not None and provider is not None and
                              callback is not None and register_call is not None and
                              registration.get('lock_rva') == 0x677C220 and registration.get('start') == 0x6D85F60 and
                              registration.get('size') == 72 and registration.get('pc') == 0x1BF6463 and
                              registration.get('slot') is None and registration.get('target') == 0x2DE5910 and
                              registration.get('group') == bytes(72) and
                              registration.get('vm') is provider.get('vm') is callback.get('vm') is register_call.get('vm') and
                              callback.get('cells') == () and register_call.get('cells') == () and
                              runtime.locks.get(runtime.image_base + 0x677C220) == 1)
                registered = registration_matches and configure_source is not None
                if registered:
                    registered = self._configuration_owner() is owner
                # The original initializer registers again after its configure call has returned.
                first_registration = False
                if registration_matches and configure_source is None:
                    frame = sys._getframe(1)
                    while frame is not None:
                        current = frame.f_locals
                        if (frame.f_code is PrimaryRuntime.invoke.__code__ and current.get('self') is runtime and
                                current.get('rva') == 0x1BF63F0 and current.get('vm') is register_call.get('vm')):
                            source = frame.f_back
                            root = None if source is None else source.f_back
                            first_registration = (source is not None and source.f_code is source_invoke.__code__ and
                                source.f_locals.get('runtime') is runtime and source.f_locals.get('rva') == 0x1BF63F0 and
                                source.f_locals.get('vm') is register_call.get('vm') and
                                type(source.f_locals.get('values')) is tuple and source.f_locals.get('values') == () and
                                root is not None and root.f_code is initialize.__code__ and
                                root.f_locals.get('runtime') is runtime and bool(root.f_locals.get('metadata')))
                            break
                        frame = frame.f_back
                valid = status or registered or first_registration
            if (not valid or owner.bootstrap_root is not None or calls[-1] != dict(name=name, arguments=(), hosts=_HOSTS) or
                    reader.get('arguments') != () or reader.get('hosts') != _HOSTS):
                raise PrimarySemanticUnavailable('provider singleton requires its one-use GUID or status source callback')
            owner.bootstrap_root, owner.bootstrap_call, owner.bootstrap_parents = vm, calls[-1], parents
        else:
            root = owner.bootstrap_root
            native = _source_locals(_host.__code__, runtime)
            wrapper = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x359205B)
            parents = owner.bootstrap_parents
            if (name != 'buffer-init' or type(root) is not PrimaryVM or root.runtime is not runtime or root.halted or
                    sha256(root.program.raw).hexdigest() != PROGRAM_SHA256 or
                    (root.pc, root.block, root.predecessor, root.initial_block) != (170, 6, 4, False) or
                    parents is None or len(calls) != len(parents) + 2 or
                    any(a is not b for a, b in zip(calls, parents)) or calls[-2] is not owner.bootstrap_call or
                    calls[-1]['name'] != name or calls[-1]['hosts'] != _BUFFER_HOSTS or
                    len(calls[-1]['arguments']) != 2 or reader.get('arguments') != calls[-1]['arguments'] or
                    reader.get('hosts') != _BUFFER_HOSTS or len(runtime.vms) < 2 or runtime.vms[-2] is not root or
                    root.host_calls[-1:] != [(163, runtime.image_base + 0x359205B, (35, 34), 41)] or
                    getattr(root, '_primary_bootstrap_active_call', None) != (163, 37, (35, 34), 41, None) or
                    native is None or native.get('vm') is not root or wrapper is None or wrapper.get('vm') is not root or
                    wrapper.get('cells') != (35, 34) or getattr(root, '_primary_bootstrap_child', None) is not None):
                raise PrimarySemanticUnavailable('provider buffer requires its actual one-use singleton word163 child')
            root._primary_bootstrap_child = vm
        vm._primary_bootstrap_used = True

    def _require_live(self):
        from .primary_sign_lifecycle import require_execution_active
        require_execution_active(self.runtime)
        if (not self.installed or self.closed or get_ident() != self.thread or
                self.runtime.__dict__.get('_primary_direct_scope') is not self or
                getattr(self.runtime, '_consumed_mgf', None) is not None or
                self.public_owner is not None and not self._valid_public() or
                self.close_owner is not None and not self._valid_close() or
                self.initialization_owner is not None and not self._valid_initialization() or
                self.worker_owner is not None and not self._valid_worker() or
                self.secondary_owner is not None and not self._valid_secondary() or
                self.notification_owner is not None and not self._valid_notification() or
                self.device_owner is not None and not self._valid_device()):
            raise PrimarySemanticUnavailable('direct scope lost its actual instance, thread or public owner')

    def install(self):
        if self.installed or self.closed or get_ident() != self.thread:
            raise PrimarySemanticUnavailable('direct scope cannot be installed in its current state or thread')
        runtime = self.runtime
        if (getattr(runtime, '_primary_direct_scope', None) is not None or not runtime.primary_core or
                getattr(runtime, '_consumed_mgf', None) is not None or
                self.public_owner is not None and not self._valid_public() or
                self.close_owner is not None and (self.public_owner is not None or not self._valid_close()) or
                self.initialization_owner is not None and (self.public_owner is not None or self.close_owner is not None or
                                                           not self._valid_initialization()) or
                self.worker_owner is not None and (self.public_owner is not None or self.close_owner is not None or
                    self.initialization_owner is not None or not self._valid_worker()) or
                self.secondary_owner is not None and (self.public_owner is not None or self.close_owner is not None or
                    self.initialization_owner is not None or self.worker_owner is not None or not self._valid_secondary()) or
                self.notification_owner is not None and (any(owner is not None for owner in (self.public_owner,
                    self.close_owner, self.initialization_owner, self.worker_owner, self.secondary_owner)) or
                    not self._valid_notification()) or
                self.device_owner is not None and (any(owner is not None for owner in (self.public_owner, self.close_owner,
                    self.initialization_owner, self.worker_owner, self.secondary_owner, self.notification_owner)) or
                    not self._valid_device())):
            raise PrimarySemanticUnavailable('direct scope rejects replay, a competing scope or invalid public owner')
        self.had = '_primary_direct_scope' in runtime.__dict__
        self.prior = runtime.__dict__.get('_primary_direct_scope')
        runtime._primary_direct_scope = self
        self.installed = True
        self.report['scopeRestored'] = False
        if self.device_owner is not None:
            self.report['deviceRequest'] = dict(serial=self.device_owner.serial, deviceProgramsOnly=True)
            return self
        if self.notification_owner is not None:
            self.report['notificationWorker'] = dict(serial=self.notification_owner.serial, materialOnly=True)
            try:
                material = MaterialStateScope(runtime, public_scope=self)
                self.children.append(material)
                self.report['materialState'] = material.report
                material.install()
            except BaseException:
                self.close()
                raise
            return self
        if self.secondary_owner is not None:
            self.report['secondaryPostfetch'] = dict(serial=self.secondary_owner.serial, tokenProgramsOnly=True)
            return self
        if self.worker_owner is not None:
            self.report['sdkWorker'] = dict(completed=False, statusCompleted=0, materialClaimed=False, materialInitialized=False,
                                          materialReused=False)
            try:
                material = MaterialStateScope(runtime, public_scope=self)
                self.children.append(material)
                self.report['materialState'] = material.report
                material.install()
            except BaseException as primary:
                try:
                    self.close()
                except BaseException as error:
                    primary.add_note('SDK material scope setup cleanup failed: ' + type(error).__name__)
                raise
            return self
        if self.close_owner is not None:
            self.report['closePrograms'] = []
            return self
        if self.initialization_owner is not None:
            self.report['providerInitialization'] = dict(completed=False, serial=self.initialization_owner.serial)
            try:
                material = MaterialStateScope(runtime, public_scope=self)
                self.children.append(material)
                self.report['materialState'] = material.report
                material.install()
            except BaseException:
                self.close()
                raise
            return self
        try:
            self.driver = MainDirectDriver(runtime, execution_report=self.report['mainDriver'])
            self.driver.install()
            material = MaterialStateScope(runtime, public_scope=self)
            self.children.append(material)
            self.report['materialState'] = material.report
            material.install()
            for cls, field in ((Host129DirectScope, 'host129Family'), (EcryptDirectScope, 'ecryptFamily'),
                               (StartupPolicyDirectScope, 'startupPolicyFamily')):
                child = cls(runtime, execution_report=self.driver.report[field])
                self.children.append(child)
                child.install()
        except BaseException:
            self.close()
            raise
        return self

    def _require_caller(self):
        self._require_live()
        caller = self._caller
        runtime = self.runtime
        if (not self._valid_public() or type(caller) is not _PreparationClaim or not caller.active or
                caller.owner is not self.public_owner or runtime._active_main is not None):
            raise PrimarySemanticUnavailable('pre-Main direct execution lacks its actual public caller window')
        return caller

    @contextmanager
    def caller_prepare(self, command):
        self._require_live()
        from .primary_caller import prepare
        source = _source_locals(prepare.__code__, self.runtime)
        runtime = self.runtime
        if (not self._valid_public() or self._caller_used or self._caller is not None or
                source is None or source.get('command') is not command or
                runtime._active_main is not None or runtime._program_calls or runtime._execute_depth or
                runtime._execute_thread is not None):
            raise PrimarySemanticUnavailable('pre-Main caller claim requires its real selected public prepare')
        claim = _PreparationClaim(self.public_owner, command)
        self._caller, self._caller_used = claim, True
        report = self.report['publicPreparation']
        report.update(status='INCOMPLETE', completed=False, publicSerial=self.public_owner.serial)
        try:
            yield
            self._require_caller()
            source = _source_locals(prepare.__code__, runtime)
            expected = tuple(phase for phase, field in (('capture-invalid', 'capture_valid'),
                             ('unwind-invalid', 'unwind_valid')) if source is not None and source.get(field) is False)
            if (source is None or not claim.host_used or self._status_host is not None or self._audit is not None or
                    self._status_transition is not None or tuple(claim.status_transitions) != expected):
                raise PrimarySemanticUnavailable('pre-Main caller did not complete its actual status host')
            report.update(status='PREPARED', completed=True)
        finally:
            claim.active = False
            if self._caller is claim:
                self._caller = None

    @contextmanager
    def caller_status_transition(self, phase):
        caller = self._require_caller()
        from .primary_caller import prepare
        source = _source_locals(prepare.__code__, self.runtime)
        if phase == 'capture-invalid':
            field, bit, previous = 'capture_valid', 0, ()
        elif phase == 'unwind-invalid':
            field, bit = 'unwind_valid', 22
            previous = ('capture-invalid',) if source is not None and source.get('capture_valid') is False else ()
        else:
            raise PrimarySemanticUnavailable('unknown caller status transition')
        if (source is None or source.get('scope') is not self or source.get('command') is not caller.command or
                source.get(field) is not False or not caller.host_used or tuple(caller.status_transitions) != previous or
                self._status_transition is not None or self._status_host is not None or self._audit is not None or
                self.runtime._program_calls or self.runtime._execute_depth):
            raise PrimarySemanticUnavailable('caller status transition requires its actual ordered source result')
        claim = _CallerStatusTransition(caller, phase, bit)
        self._status_transition = claim
        caller.status_transitions.append(phase)
        segment = dict(phase=phase, bit=bit, arguments=(1, bit, 1, 0), completed=False)
        self.report['publicPreparation'].setdefault('statusTransitions', []).append(segment)
        try:
            yield claim
            self._require_caller()
            if not claim.used or self._status_host is not None or self._audit is not None:
                raise PrimarySemanticUnavailable('caller status transition did not complete its one actual status host')
            segment['completed'] = True
            key = 'captureInvalidStatusCompleted' if phase == 'capture-invalid' else 'unwindInvalidStatusCompleted'
            self.report['publicPreparation'][key] = True
        finally:
            claim.active = False
            if self._status_transition is claim:
                self._status_transition = None

    @contextmanager
    def status_host(self, carrier, cells):
        if self._request_audit is not None:
            with self._request_audit.status_host(carrier, cells):
                yield
            return
        if self.notification_owner is not None:
            with self._notification_status_host(carrier, cells):
                yield
            return
        if self.worker_owner is not None:
            if self._refresh is not None:
                with self._refresh_status_host(carrier, cells):
                    yield
                return
            with self._worker_status_host(carrier, cells):
                yield
            return
        if self.initialization_owner is not None:
            with self._initialization_status_host(carrier, cells):
                yield
            return
        if self.runtime._active_main is not None and self._caller is None:
            yield
            return
        caller = self._require_caller()
        from .primary_worker_consumer import _invoke
        source = _source_locals(PrimaryRuntime.invoke.__code__, self.runtime, rva=0x1BF75A0)
        worker = _source_locals(_invoke.__code__, self.runtime, rva=0x1BF75A0)
        invalid = self._status_transition
        arguments = (0, 0, 1, 0)
        if invalid is not None:
            if type(invalid) is not _CallerStatusTransition:
                raise PrimarySemanticUnavailable('caller status transition has a foreign claim type')
            from .primary_caller import prepare
            from .primary_worker import _flag
            current = _source_locals(prepare.__code__, self.runtime)
            flagged = _source_locals(_flag.__code__, self.runtime)
            field = 'capture_valid' if invalid.phase == 'capture-invalid' else 'unwind_valid'
            if (not invalid.active or invalid.used or
                    (invalid.phase, invalid.bit) not in (('capture-invalid', 0), ('unwind-invalid', 22)) or
                    invalid.caller is not caller or current is None or current.get('scope') is not self or
                    current.get('status_transition_claim') is not invalid or current.get(field) is not False or
                    current.get('command') is not caller.command or flagged is None or
                    flagged.get('vm') is not carrier or flagged.get('bit') != invalid.bit or flagged.get('mask') != 1 or
                    flagged.get('values') != (1, invalid.bit, 1, 0)):
                raise PrimarySemanticUnavailable('caller status carrier lacks its original finite phase claim')
            arguments, worker = (1, invalid.bit, 1, 0), flagged
        if ((caller.host_used and invalid is None) or self._status_host is not None or self.runtime._program_calls or
                cells != (0, 1, 2, 3) or type(carrier) is not SimpleNamespace or source is None or
                source.get('vm') is not carrier or source.get('cells') is not cells or worker is None or
                worker.get('vm') is not carrier or worker.get('values') != arguments):
            raise PrimarySemanticUnavailable('pre-Main status host requires its real caller carrier and ABI')
        if invalid is not None:
            invalid.used = True
        claim = _StatusHostClaim(caller, carrier, cells, arguments)
        self._status_host, caller.host_used = claim, True
        try:
            yield
            self._require_caller()
            if not claim.normal_used or self._audit is not None:
                raise PrimarySemanticUnavailable('pre-Main status host did not complete its normal audit')
        finally:
            claim.active = False
            if self._status_host is claim:
                self._status_host = None

    @contextmanager
    def status_audit(self, phase, arguments):
        if self.runtime._active_main is not None and self._caller is None:
            yield
            return
        caller = self._status_owner()
        host = self._status_host
        if (type(host) is not _StatusHostClaim or not host.active or host.caller is not caller or
                self._audit is not None or self.runtime._program_calls or type(arguments) is not tuple or
                len(arguments) != 5 or any(type(value) is not int for value in arguments)):
            raise PrimarySemanticUnavailable('pre-Main status audit lacks its real current host window')
        runtime = self.runtime
        if phase == 'initialize':
            source = _source_locals(PrimaryRuntime._status_sensor.__code__, runtime)
            if (host.initialize_used or host.normal_used or source is None or
                    arguments != (source.get('address'), 3, 0, 2, 1)):
                raise PrimarySemanticUnavailable('pre-Main status initialization claim is stale or foreign')
            host.initialize_used = True
        elif phase == 'normal':
            source = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x2DE8C4C)
            if (host.normal_used or source is None or source.get('vm') is not host.carrier or
                    source.get('cells') is not host.cells or arguments[1:] != host.arguments or
                    arguments != tuple(source.get(key) for key in ('sensor', 'pointer', 'value1', 'value2', 'flag'))):
                raise PrimarySemanticUnavailable('pre-Main normal status claim is stale or has a foreign ABI')
            host.normal_used = True
        else:
            raise PrimarySemanticUnavailable('unknown pre-Main status phase')
        claim = _StatusAuditClaim(host, phase, arguments)
        self._audit = claim
        try:
            yield
            self._status_owner()
            if claim.vm is None or not claim.completed:
                raise PrimarySemanticUnavailable('pre-Main status claim did not complete its one actual child')
        finally:
            claim.active = False
            if self._audit is claim:
                self._audit = None

    def _authorize_status_vm(self, vm):
        self._status_owner()
        runtime, claim = self.runtime, self._audit
        if (self._refresh is not None or self.notification_owner is not None or self._request_audit is not None) and (type(vm) is not PrimaryVM or vm.runtime is not runtime or
                vm.memory is not runtime.memory or vm.image_base != runtime.image_base):
            raise PrimarySemanticUnavailable('SDK refresh status VM lost its original runtime memory')
        calls = runtime._program_calls
        source = _source_locals(PrimaryRuntime._execute_program.__code__, runtime, name='status-audit')
        if (type(claim) is not _StatusAuditClaim or not claim.active or claim.vm is not None or
                claim.host is not self._status_host or not claim.host.active or
                len(calls) != 1 or calls[0]['name'] != 'status-audit' or
                calls[0]['arguments'] != claim.arguments or calls[0]['hosts'] is not None or
                runtime._execute_thread != self.thread or runtime._execute_depth != 1 or
                runtime._active_failed or not runtime.vms or runtime.vms[-1] is not vm or
                source is None or source.get('vm') is not vm):
            raise PrimarySemanticUnavailable('pre-Main status reader does not own the current one-use claim')
        claim.vm, claim.call = vm, calls[0]

    def _complete_status_vm(self, vm):
        if self._refresh is not None:
            self._require_refresh()
            if (type(vm) is not PrimaryVM or vm.runtime is not self.runtime or
                    vm.memory is not self.runtime.memory or vm.image_base != self.runtime.image_base):
                raise PrimarySemanticUnavailable('SDK refresh completion lost its original status VM')
        claim = self._audit
        if (type(claim) is not _StatusAuditClaim or not claim.active or claim.vm is not vm or
                self.runtime._program_calls != [claim.call] or not vm.halted or vm.pc != 235):
            raise PrimarySemanticUnavailable('pre-Main status completion lost its actual child')
        claim.completed = True

    def _worker_material_ready(self, owner):
        if owner.material_used:
            return True
        proof, runtime = self._material_reuse, self.runtime
        if (type(proof) is not SimpleNamespace or owner.material_reuse is not proof or not proof.active or
                proof.owner is not owner or proof.thread != self.thread or
                proof.generation != runtime._main_generation or proof.source is not owner.source or
                proof.bootstrap_vm is not owner.source.f_locals.get('vm') or
                proof.context != runtime.image_base + 0x6D88430 or proof.guard != runtime.image_base + 0x6D88CA0 or
                runtime.memory._span(proof.guard, 4)[0] is not proof.guard_region or
                runtime.memory._span(proof.context, 0x848)[0] is not proof.context_region or
                proof.writes is not runtime.memory.writes or not 0 < proof.write_boundary <= len(proof.writes) or
                proof.writes[proof.write_boundary - 1] is not proof.write_row):
            return False
        frame = sys._getframe(1)
        while frame is not None and frame is not proof.worker_frame:
            frame = frame.f_back
        if frame is None:
            return False
        for address, data, source in proof.writes[proof.write_boundary:]:
            if (data is not None and address < proof.guard + 4 and proof.guard < address + len(data) or
                    data is None and proof.guard_region.address <= address < proof.guard_region.address + len(proof.guard_region.data)
                    and address < proof.guard + 4):
                return False
        return runtime.memory.load(proof.guard, 4) == 2

    def _authorize_material_reuse(self, context, guard):
        from .primary_sdk import update_material_control, _invoke_values
        from .primary_worker_loop import run
        owner, phase, source = self._require_worker()
        runtime = self.runtime
        warm = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x3591D6C)
        update = _source_locals(update_material_control.__code__, runtime)
        dispatch = _source_locals(_invoke_values.__code__, runtime, address=runtime.image_base + 0x3591D6C)
        values = None if update is None else tuple(update.get(key) for key in ('value', 'bit', 'operation', 'flag'))
        if (owner.material_used or owner.material_reuse is not None or self._material_reuse is not None or
                owner.status_index != 3 or phase.get('rva') != 0x1BF8090 or source.get('rva') != 0x1BF8090 or
                phase.get('arguments') != values or source.get('values') != values or
                warm is None or warm.get('current') != 2 or warm.get('context') != context or warm.get('guard') != guard or
                warm.get('cells') != () or dispatch is None or dispatch.get('values') != () or
                dispatch.get('vm') is not warm.get('vm') or update is None or runtime._program_calls or
                context != runtime.image_base + 0x6D88430 or guard != runtime.image_base + 0x6D88CA0 or
                runtime.memory.load(guard, 4) != 2):
            raise PrimarySemanticUnavailable('SDK warm material reuse requires its actual worker updater source chain')
        if values != (1, 2, 1, 0):
            return
        frame = sys._getframe(1)
        while frame is not None and not (frame.f_code is run.__code__ and frame.f_locals.get('runtime') is runtime):
            frame = frame.f_back
        proof = SimpleNamespace(owner=owner, source=owner.source, bootstrap_vm=owner.source.f_locals.get('vm'),
            thread=self.thread, generation=runtime._main_generation, context=context, guard=guard, worker_frame=frame,
            guard_region=runtime.memory._span(guard, 4)[0], context_region=runtime.memory._span(context, 0x848)[0],
            writes=runtime.memory.writes, write_boundary=len(runtime.memory.writes), write_row=runtime.memory.writes[-1],
            active=True)
        self._material_reuse = owner.material_reuse = proof
        self.report['sdkWorker']['materialReused'] = True

    def _authorize_material_state(self, vm, claim):
        if self._request_audit is not None:
            self._request_audit.authorize_material(vm, claim)
            return
        if self.notification_owner is not None:
            from .primary_sdk import update_material_control
            producer, phase, bit = self._notification_claim()
            update = _source_locals(update_material_control.__code__, self.runtime)
            source = _source_locals(PrimaryRuntime.invoke.__code__, self.runtime, rva=0x1BF8090)
            calls = self.runtime._program_calls
            if (producer.material_used or producer.setting_stage != 'update' or phase.get('setting_rva') != 0x1BF8090 or
                    source is None or update is None or
                    tuple(update.get(k) for k in ('value', 'bit', 'operation', 'flag')) != (1, bit, 1, 0) or
                    claim.get('parentCalls') != () or len(calls) != 1 or calls[0]['name'] != 'material-state' or
                    calls[0]['arguments'] != (self.runtime.image_base + 0x6D88430,) or
                    self.runtime._execute_depth != 1 or self.runtime._execute_thread != self.thread):
                raise PrimarySemanticUnavailable('notification material initializer lacks its real ordered updater')
            producer.material_used = True
            return
        if self.worker_owner is not None:
            from .primary_sdk import update_material_control
            owner, phase, source = self._require_worker()
            runtime = self.runtime
            update = _source_locals(update_material_control.__code__, runtime)
            calls = runtime._program_calls
            expected = (1, 2, 1, 0)
            if (owner.material_used or owner.status_index != 3 or phase.get('rva') != 0x1BF8090 or
                    phase.get('arguments') != expected or source.get('rva') != 0x1BF8090 or
                    source.get('values') != expected or update is None or
                    tuple(update.get(k) for k in ('value', 'bit', 'operation', 'flag')) != expected or
                    claim.get('parentCalls') != () or len(calls) != 1 or calls[0]['name'] != 'material-state' or
                    runtime._execute_depth != 1 or runtime._execute_thread != self.thread):
                raise PrimarySemanticUnavailable('SDK material state requires its first actual worker updater claim')
            owner.material_used = True
            self.report['sdkWorker']['materialClaimed'] = True
            return
        if self.initialization_owner is not None:
            from .primary_provider_init import initialize
            from .primary_sdk import update_material_control
            owner = self._require_initialization()
            phase = _source_locals(initialize.__code__, self.runtime)
            update = _source_locals(update_material_control.__code__, self.runtime)
            calls = self.runtime._program_calls
            if (owner.material_used or owner.status_index != 2 or phase.get('rva') != 0x1BF8090 or
                    update is None or tuple(update.get(k) for k in ('value', 'bit', 'operation', 'flag')) !=
                    ((1 << 64) - 4, 0, 3, 1) or claim.get('parentCalls') != () or len(calls) != 1 or
                    calls[0]['name'] != 'material-state' or self.runtime._execute_depth != 1 or
                    self.runtime._execute_thread != self.thread):
                raise PrimarySemanticUnavailable('provider material state requires its original first updater claim')
            owner.material_used = True
            return
        self._require_caller()
        runtime = self.runtime
        if (claim.get('publicOwner') is not self.public_owner or claim.get('parentCalls') != () or
                len(runtime._program_calls) != 1 or runtime._program_calls[0]['name'] != 'material-state' or
                runtime._execute_depth != 1 or runtime._execute_thread != self.thread):
            raise PrimarySemanticUnavailable('pre-Main material state lacks its original public source claim')

    def execute_program(self, name, vm):
        self._require_live()
        runtime = self.runtime
        source = _source_locals(PrimaryRuntime._execute_program.__code__, runtime, name=name)
        if source is None or source.get('vm') is not vm:
            raise PrimarySemanticUnavailable('direct dispatch requires the actual initialized runtime reader')
        if self.notification_owner is not None and not self._notification_handoff_program(name):
            self._notification_claim()
            if name not in ('status-audit', 'material-state'):
                raise PrimarySemanticUnavailable('notification worker does not authorize this program: ' + name)
        if self.device_owner is not None:
            from .primary_request_audit_scope import _DeviceHandoffAuditClaim
            handoff_audit = type(self._request_audit) is _DeviceHandoffAuditClaim
            if (not self._valid_device() or (name not in ('device-records', 'device-mix') and
                    (name not in ('status-audit', 'material-state') or not handoff_audit or
                     not self._request_audit.valid()))):
                raise PrimarySemanticUnavailable('device callback does not authorize this program: ' + name)
        if self.secondary_owner is not None and name not in ('source2583', 'token-setter', 'token-expire'):
            raise PrimarySemanticUnavailable('secondary postfetch does not authorize this program: ' + name)
        if self.worker_owner is not None:
            self._require_worker()
            if name not in ('status-audit', 'material-state'):
                raise PrimarySemanticUnavailable('SDK direct worker does not authorize this program: ' + name)
        if self.initialization_owner is not None:
            self._require_initialization()
            if name not in ('source2581', 'source2581-setter', 'singleton-init', 'buffer-init', 'status-audit', 'material-state'):
                raise PrimarySemanticUnavailable('provider initialization does not authorize this program: ' + name)
        if self.close_owner is not None:
            calls = runtime._program_calls
            if (not self.allow_close_program(name, calls[-1]['arguments'] if calls else None,
                                             calls[-1]['hosts'] if calls else None) or
                    type(vm) is not PrimaryVM or vm.runtime is not runtime or vm.memory is not runtime.memory or
                    vm.image_base != runtime.image_base or sha256(vm.program.raw).hexdigest() != _PROGRAMS['singleton-destroy'] or
                    (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used) != (1, 0, None, True, 0) or
                    runtime._execute_thread != self.thread or runtime._execute_depth != 1 or
                    not runtime.vms or runtime.vms[-1] is not vm or vm.halted or vm.abort_reason is not None or
                    any(getattr(vm, key) is not None for key in ('pending_once10', 'pending_once9', 'pending_l26',
                        'pending_variadic', 'pending_native', 'private_iv_native_pending'))):
                raise PrimarySemanticUnavailable('direct close reader lacks its original invoking exit record')
            from .primary_singleton_destroy import run_primary_singleton_destroy
            segment = dict(program=name, backend='EXISTING_DIRECT_SINGLETON_DESTROY', completed=False,
                           referenceRecordCount=None, publicCloseSerial=self.close_owner.serial)
            self.report['closePrograms'].append(segment)
            result = run_primary_singleton_destroy(vm)
            segment['completed'] = True
            return result
        if name == 'main':
            return runtime._run_primary_main(vm)
        if name == 'material-block':
            return runtime._run_primary_material(vm)
        if name == 'material-state':
            result = runtime._run_primary_material_state(vm)
            if self.worker_owner is not None:
                self.report['sdkWorker']['materialInitialized'] = True
            return result
        if name == 'status-audit' and runtime._active_main is None:
            report = self.report['preMainStatus']
            claim = self._audit
            segment = dict(program=name, phase=getattr(claim, 'phase', None), completed=False, referenceRecordCount=0)
            report['semanticSegments'].append(segment)
            report['status'] = 'DIRECT_INCOMPLETE'
            try:
                return execute_primary_status_audit_pre_main(vm, execution_report=segment)
            finally:
                segment['phase'] = getattr(claim, 'phase', None)
                report['referenceRecordCount'] += segment['referenceRecordCount']
                if all(item['completed'] for item in report['semanticSegments']):
                    report['status'] = 'DIRECT_EXECUTED'
        if name in ('host129', 'host129-prepare', 'host129-select'):
            return runtime._try_primary_host129_direct(name, vm)
        if name in ('ecrypt-transform', 'ecrypt-keysetup', 'ecrypt-packet', 'ecrypt-blocks'):
            return runtime._try_primary_ecrypt_direct(name, vm)
        if name in ('primary-setup', 'status-audit', 'host97', 'cocos-init', 'cocos-crypt', 'cocos-publish'):
            return runtime._try_primary_startup_direct(name, vm)
        if name in ('entry-prepare', 'sdk-table-init'):
            from .primary_entry_direct import execute_primary_entry
            segment = dict(program=name, completed=False, referenceRecordCount=0)
            self.report.setdefault('entryPrograms', []).append(segment)
            return execute_primary_entry(vm, name, execution_report=segment)
        if name in ('singleton-init', 'buffer-init'):
            from .primary_bootstrap_direct import execute_primary_bootstrap
            segment = dict(program=name, completed=False, referenceRecordCount=0)
            self.report.setdefault('bootstrapPrograms', []).append(segment)
            return execute_primary_bootstrap(vm, name, execution_report=segment)
        if name in ('source2583', 'token-setter', 'token-expire'):
            segment = dict(program=name, completed=False, referenceRecordCount=0)
            self.report.setdefault('tokenFamilyPrograms', []).append(segment)
            try:
                from .primary_token_family_direct import execute_primary_token_family
            except ModuleNotFoundError as error:
                if error.name != __package__ + '.primary_token_family_direct':
                    raise
                raise PrimarySemanticUnavailable('direct token family implementation is unavailable') from error
            return execute_primary_token_family(vm, name, execution_report=segment)
        if name in ('source2581', 'source2581-setter'):
            from .primary_source2581_direct import execute_primary_source2581
            segment = dict(program=name, completed=False, referenceRecordCount=0)
            self.report.setdefault('source2581Programs', []).append(segment)
            return execute_primary_source2581(vm, name, execution_report=segment)
        return self._auxiliary_program(name, vm)

    def allow_close_program(self, name, arguments, hosts):
        from .primary_sign_lifecycle import _sync_execution
        if (not self.installed or self.closed or not self._valid_close() or name != 'singleton-destroy' or
                type(arguments) is not tuple or len(arguments) != 1 or type(arguments[0]) is not int or hosts is not None or
                self.runtime.__dict__.get('_primary_direct_scope') is not self or
                getattr(self.runtime, '_consumed_mgf', None) is not None or self.runtime._active_main is not None):
            return False
        from .primary_host_services import GuestExitRegistrar, _ExecutionLease, _EmptyCells
        from threading import get_native_id
        owner, runtime = self.close_owner, self.runtime
        registrar = owner.registrar
        frame = sys._getframe(1)
        current = None
        execute_source = None
        while frame is not None:
            if frame.f_code is PrimaryRuntime._execute_continued.__code__ and execute_source is None:
                if (frame.f_locals.get('self') is not runtime or frame.f_locals.get('name') != name or
                        frame.f_locals.get('arguments') is not arguments or frame.f_locals.get('hosts') is not None or
                        frame.f_back is None or frame.f_back.f_code is not _sync_execution.__code__ or
                        frame.f_back.f_back is None or frame.f_back.f_back.f_code is not PrimaryRuntime.execute.__code__ or
                        frame.f_back.f_back.f_locals.get('self') is not runtime or frame.f_back.f_back.f_back is None or
                        frame.f_back.f_back.f_back.f_code is not PrimaryRuntime.invoke.__code__ or
                        frame.f_back.f_back.f_back.f_locals.get('rva') != 0x35922FD):
                    return False
                execute_source = frame.f_locals
            if frame.f_code is GuestExitRegistrar.close.__code__ and frame.f_locals.get('self') is registrar:
                current = frame.f_locals
                break
            frame = frame.f_back
        source = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x35922FD)
        record = current.get('record') if current is not None else None
        leases = registrar._leases.get(get_native_id(), ())
        calls = runtime._program_calls
        return (current is not None and execute_source is not None and source is not None and source.get('vm') is current.get('vm') and
                source.get('cells') == () and type(current.get('vm')) is SimpleNamespace and
                type(current['vm'].cells) is _EmptyCells and record is not None and
                any(item is record for item in registrar._records) and record.status == 'invoking' and
                record.address == runtime.image_base + 0x35922FD and registrar._lifecycle == 'closing' and
                bool(leases) and type(leases[-1]) is _ExecutionLease and leases[-1].registrar is registrar and
                leases[-1].closing and leases[-1].active and not leases[-1].suspended and
                (not calls or len(calls) == 1 and calls[0]['name'] == name and calls[0]['arguments'] is arguments and
                 calls[0]['hosts'] is None))

    def _auxiliary_program(self, name, vm):
        from .primary_device_mix import run_primary_device_mix
        from .primary_device_record_cipher import run_primary_device_record_cipher
        from .primary_singleton_destroy import run_primary_singleton_destroy
        bodies = {'singleton-destroy': run_primary_singleton_destroy, 'device-mix': run_primary_device_mix,
                  'device-records': run_primary_device_record_cipher}
        if name not in bodies:
            return NotImplemented
        runtime = self.runtime
        if (type(vm) is not PrimaryVM or vm.runtime is not runtime or vm.memory is not runtime.memory or
                vm.image_base != runtime.image_base or sha256(vm.program.raw).hexdigest() != _PROGRAMS[name] or
                (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used) != (1, 0, None, True, 0) or
                runtime._active_failed or runtime._execute_thread != self.thread or not runtime._program_calls or
                runtime._program_calls[-1]['name'] != name or not runtime.vms or runtime.vms[-1] is not vm or
                vm.halted or vm.abort_reason is not None or any(getattr(vm, key) is not None for key in
                ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
                 'private_iv_native_pending'))):
            raise PrimarySemanticUnavailable('direct auxiliary helper requires its fixed fresh actual reader')
        owner = runtime._active_main
        if not self._valid_public() and not (self._valid_device() and name in ('device-records', 'device-mix')) and (type(owner) is not dict or owner.get('vm') is None or
                owner.get('thread') != self.thread or owner.get('generation') != runtime._main_generation):
            raise PrimarySemanticUnavailable('direct auxiliary helper lacks a public or actual Main owner')
        segment = dict(program=name, backend='EXISTING_DIRECT_HELPER', completed=False, referenceRecordCount=None)
        self.report['auxiliaryPrograms'].append(segment)
        result = bodies[name](vm)
        segment['completed'] = True
        return result

    def close(self):
        if self.closed:
            return self.report
        from .primary_sign_lifecycle import close_retained_execution
        if close_retained_execution(self.runtime, self):
            return self.report
        if self.installed and get_ident() != self.thread:
            raise PrimarySemanticUnavailable('direct composite scope must close on its installing thread')
        primary, failure = sys.exception(), None
        if self._refresh is not None or self._refresh_operation is not None:
            error = PrimarySemanticUnavailable('SDK scope closed with a retained refresh claim')
            if primary is not None:
                primary.add_note(str(error))
            else:
                failure = error
            for claim in (self._refresh_operation, self._refresh):
                if claim is not None:
                    claim.active = False
            self._refresh = self._refresh_operation = None
        if self.installed:
            for child in reversed(self.children):
                try:
                    child.close()
                except BaseException as error:
                    if primary is not None:
                        primary.add_note('direct child scope restoration failed: ' + type(error).__name__)
                    elif failure is None:
                        failure = error
            if self.driver is not None:
                try:
                    self.driver.close()
                except BaseException as error:
                    if primary is not None:
                        primary.add_note('direct Main driver restoration failed: ' + type(error).__name__)
                    elif failure is None:
                        failure = error
            owned = get_ident() == self.thread and self.runtime.__dict__.get('_primary_direct_scope') is self
            if owned:
                if self.had:
                    self.runtime._primary_direct_scope = self.prior
                else:
                    self.runtime.__dict__.pop('_primary_direct_scope', None)
            else:
                error = PrimarySemanticUnavailable('direct composite scope ownership changed during execution')
                if primary is not None:
                    primary.add_note(str(error))
                elif failure is None:
                    failure = error
            self.report['scopeRestored'] = owned and all(child.report.get('scopeRestored', False) for child in self.children) and (
                self.driver is None or self.driver.report.get('scopeRestored', False))
        if self._material_reuse is not None:
            self._material_reuse.active = False
            if self.worker_owner is not None and self.worker_owner.material_reuse is self._material_reuse:
                self.worker_owner.material_reuse = None
            self._material_reuse = None
        self.closed, self.installed = True, False
        self.runtime = self.public_owner = self.close_owner = self.initialization_owner = self.worker_owner = self.secondary_owner = self.notification_owner = self.device_owner = self.prior = self.driver = None
        self.children.clear()
        self._caller = self._status_host = self._audit = None
        self._status_transition = None
        if failure is not None:
            raise failure
        return self.report
