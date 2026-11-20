from threading import get_ident
from .errors import InputError
from .primary_main_mix import ENTRY, _execute_primary_main_mix
from .primary_main_prefix import PREFIX_ENTRIES, PREFIX_EXITS, execute_primary_main_prefix
from .primary_main_material_merge import ENTRY as MERGE_ENTRY, execute_primary_main_material_merge
from .primary_main_material_window import WINDOW_ENTRIES, WINDOW_EXITS, execute_primary_main_material_window
from .primary_main_material_continuation import CONTINUATION_ENTRIES, execute_primary_main_material_continuation
from .primary_main_rest import REST_ENTRY, TAIL_ENTRY, execute_primary_main_rest, execute_primary_main_tail
from .primary_main_material_getter import CONSUMER_ENTRIES, execute_primary_main_record_consumer, execute_primary_main_material_provider
from .primary_sign import PrimaryRuntime
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable


def empty_direct_report():
    return dict(backend='INDEPENDENT_MAIN_MIX', completeIndependentMain=False, genericReferenceTraceComplete=False, traceCoverage='REAL_GENERIC_RECORDS_OUTSIDE_SEMANTIC_SEGMENTS', semanticSegments=[], materialProviders=[], genericRecordCount=0, chargedRecordCount=0, providerRecordCount=0, entered=False, exit='NOT_ENTERED', scopeRestored=True, mainPrefixCoverage=dict(enabled=True, backend='DIRECT_MAIN_PREFIX' if True else 'GENERIC_REFERENCE', entries=[1, 32266] if True else [], normalExits=[31440, 36986], earlyReturnWord=66548, sourceRecordCount=7745, earlyReturnSourceRecordCount=1, childBackend='EXISTING_RUNTIME_HOSTS_WITH_RESIDUAL_GENERIC_CHILDREN', completeIndependentMain=False), host129Family=dict(backend='DIRECT_SOURCE_HOST129_FAMILY' if True else 'GENERIC_REFERENCE', enabled=True, completeIndependentMain=False), ecryptFamily=dict(backend='DIRECT_SOURCE_ECRYPT_FAMILY' if True else 'GENERIC_REFERENCE', enabled=True, completeIndependentMain=False), startupPolicyFamily=dict(backend='DIRECT_SOURCE_STARTUP_POLICY3_FAMILIES' if True else 'GENERIC_REFERENCE', enabled=True, completeIndependentMain=False), policyMaterialCoverage=dict(enabled=True, backend='DIRECT_HOST97_MATERIAL_BLOCK' if True else 'GENERIC_REFERENCE', status='NOT_ENTERED', parentCallWords=[132, 148, 164], completedCallWords=[], referenceRecordCount=0, completeIndependentMain=False), mainTailCoverage=dict(enabled=True, backend='DIRECT_MAIN_LITERAL_TAIL_WITH_PENDING_HOST129_FAMILY' if True else 'GENERIC_REFERENCE', entryWord=62638, exitWord=66548, sourceRecordCount=893, childGeneric=['host129'], host129Backend='PENDING_DIRECT_SOURCE_HOST129_FAMILY' if True else 'GENERIC_REFERENCE', otherHostBackend='EXISTING_MODEL_HOSTS', completeIndependentMain=False), mainRestCoverage=dict(enabled=True, backend='DIRECT_MAIN_HOST_FREE_REST' if True else 'GENERIC_REFERENCE', entryWord=45584, exitWord=62638, sourceRecordCount=3802, nextCallBackend='DIRECT_SOURCE_HOST129_FAMILY' if True else 'RESIDUAL_GENERIC_HOST129_CHILD', completeIndependentMain=False), materialContinuationCoverage=dict(enabled=True, backend='DIRECT_MAIN_MATERIAL_CONTINUATION' if True else 'GENERIC_REFERENCE', entryWord=41119, exitWord=45584, sourceRecordCount=987, newSourceRecordCount=963, reusedMixSourceRecordCount=24, providerBackend='EXISTING_DIRECT_MATERIAL_BLOCK', nextMainBackend='DIRECT_MAIN_HOST_FREE_REST' if True else 'GENERIC_MAIN_AT_45584', mixBudget='EXISTING_ATOMIC_24_RECORD_ADMISSION', completeIndependentMain=False), materialWindowCoverage=dict(enabled=True, backend='DIRECT_MAIN_MATERIAL_WINDOW' if True else 'GENERIC_REFERENCE', entryWord=37823, exitWord=41119, sourceRecordCount=725, newSourceRecordCount=500, reusedMergeSourceRecordCount=225, memsetBackend='EXISTING_DIRECT_RUNTIME_INVOKE', nextCallBackend='DIRECT_MAIN_MATERIAL_CONTINUATION_AT_41119' if True else 'GENERIC_MAIN_AT_41119', completeIndependentMain=False), materialMergeCoverage=dict(enabled=True, backend='DIRECT_MAIN_POST_AS_MATERIAL_MERGE' if True else 'GENERIC_REFERENCE', entryWord=38470, exitWord=39468, subsequentPublicationBackend='DIRECT_MAIN_MATERIAL_PUBLICATION_PREMIX' if True else 'GENERIC_MAIN_39468_TO_39948', completeIndependentMain=False), recordConsumerCoverage=dict(enabled=True, backend='DIRECT_MAIN_ENCODED_RECORD_CONSUMERS' if True else 'GENERIC_REFERENCE', entries=[31440, 36986] if True else [], producerBackend='DIRECT_MATERIAL_BLOCK_FOR_MAIN_S_A' if True else 'GENERIC_MATERIAL_BLOCK', contextInitializationBackend='GENERIC_MATERIAL_STATE', completeIndependentGetters=False))

class MainDirectDriver:
    def __init__(self, runtime, *, execution_report=None):
        self.runtime = runtime
        self.thread = get_ident()
        self.installed = False
        self.closed = False
        self.bindings = {}
        self.report = empty_direct_report()
        self.report.update(backend='DIRECT_MAIN_LITERAL_DRIVER', traceCoverage='NO_SYNTHETIC_MAIN_TRACE')
        if execution_report is not None:
            execution_report.clear()
            execution_report.update(self.report)
            self.report = execution_report

    def install(self):
        runtime, report, thread = self.runtime, self.report, self.thread
        if (self.installed or self.closed or get_ident() != thread or not runtime.primary_core or
                getattr(runtime, '_consumed_mgf', None) is not None):
            raise PrimarySemanticUnavailable('direct Main driver rejects replay or a stopped scope')
        for name in ('_run_primary_main', '_run_primary_material'):
            original = getattr(runtime, name)
            if (getattr(original, '__func__', None) is not getattr(PrimaryRuntime, name) or
                    getattr(original, '__self__', None) is not runtime):
                raise PrimarySemanticUnavailable('direct Main driver rejects a competing body scope')

        def run_material(vm):
            owner = runtime._active_main
            main = owner.get('vm') if type(owner) is dict else None
            if main is None or main.pc not in (444, 15003, 18257, 31410, 36956, 41128):
                raise PrimarySemanticUnavailable('complete direct material provider rejects an unselected Main source owner')
            source, signature = (main, 158)
            policy_provider = main.pc == 444
            if policy_provider:
                parents = [parent for parent in runtime.vms if parent is not main and parent is not vm and (not parent.halted)]
                if len(parents) != 1:
                    raise PrimarySemanticUnavailable('independent policy material requires its one active host97 parent')
                source = parents[0]
                row = {141: (132, (25, 17, 42, 9)), 157: (148, (45, 17, 46, 9)), 173: (164, (45, 46, 48, 9))}.get(source.pc)
                if row is None:
                    raise PrimarySemanticUnavailable('independent policy material requires its exact host97 source point')
                word, host_arguments = row
                signature = 26
                if getattr(source, '_primary_policy3_active_call', None) != (word, 41, host_arguments, 26, None):
                    raise PrimarySemanticUnavailable('independent policy material requires its actual parent host window')
            else:
                word, host_arguments = {15003: (14994, (235, 502, 502, 120)), 18257: (18248, (354, 158, 269, 124)), 31410: (31401, (235, 158, 502, 18)), 36956: (36947, (235, 158, 502, 41)), 41128: (41119, (354, 269, 311, 51))}[main.pc]
            if not report['entered'] or get_ident() != thread or owner.get('thread') != thread or (owner.get('generation') != runtime._main_generation) or (runtime._execute_thread != thread) or (main.runtime is not runtime) or (main.memory is not runtime.memory) or (vm.runtime is not runtime) or (source.runtime is not runtime) or (source.memory is not runtime.memory) or (not source.host_calls) or (source.host_calls[-1] != (word, runtime.image_base + 48122939, host_arguments, signature)):
                raise PrimarySemanticUnavailable('independent material provider requires the actual S/A Main host call')
            main_call_word = 432 if policy_provider else word
            segment = dict(mainCallWord=main_call_word, completed=False, referenceRecordCount=0)
            if policy_provider:
                segment.update(parentProgram='host97', parentCallWord=word)
            report['materialProviders'].append(segment)
            try:
                return execute_primary_main_material_provider(vm, execution_report=segment)
            finally:
                segment['mainCallWord'] = main_call_word
                report['providerRecordCount'] += segment['referenceRecordCount']
                if policy_provider:
                    segment.update(parentProgram='host97', parentCallWord=word)
                    coverage = report['policyMaterialCoverage']
                    entered = [item for item in report['materialProviders'] if item.get('parentProgram') == 'host97']
                    coverage['completedCallWords'] = [item['parentCallWord'] for item in entered if item['completed']]
                    coverage['referenceRecordCount'] = sum((item['referenceRecordCount'] for item in entered))
                    coverage['status'] = 'DIRECT_EXECUTED' if coverage['completedCallWords'] == [132, 148, 164] else 'DIRECT_INCOMPLETE'

        def run(vm, *, max_steps=1000000):
            from .primary_sign_lifecycle import retain_execution
            from .primary_main_prefix_stop import _current
            prefix = _current(runtime)
            if prefix is not None:
                max_steps = prefix.budget
            return retain_execution(runtime, _main_execution(runtime, report, thread, vm, max_steps=max_steps))

        for name, current in (('_run_primary_main', run), ('_run_primary_material', run_material)):
            self.bindings[name] = (name in runtime.__dict__, runtime.__dict__.get(name), current)
            setattr(runtime, name, current)
        self.installed = True
        report['scopeRestored'] = False
        return self

    def close(self):
        if self.closed:
            return self.report
        from .primary_sign_lifecycle import close_retained_execution
        if close_retained_execution(self.runtime, self):
            return self.report
        runtime, errors = self.runtime, []
        if get_ident() != self.thread:
            raise PrimarySemanticUnavailable('direct Main driver restore requires its installing thread')
        for name, (had, prior, current) in reversed(tuple(self.bindings.items())):
            if runtime.__dict__.get(name) is not current:
                errors.append(name)
                continue
            if had:
                setattr(runtime, name, prior)
            else:
                runtime.__dict__.pop(name, None)
        self.report['scopeRestored'] = not errors
        self.report['restoreError'] = ','.join(errors) if errors else None
        self.closed = True
        self.installed = False
        self.bindings.clear()
        self.runtime = None
        if errors:
            raise PrimarySemanticUnavailable('direct Main driver hook ownership changed: ' + ','.join(errors))
        return self.report


def _main_execution(runtime, report, thread, vm, *, max_steps=1000000):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    owner = runtime._active_main
    stack = runtime._program_calls
    arguments = stack[0]['arguments'] if stack else ()
    if report['entered'] or type(vm) is not PrimaryVM or vm.runtime is not runtime or (vm.memory is not runtime.memory) or (get_ident() != thread) or (type(owner) is not dict) or (owner.get('vm') is not vm) or (owner.get('thread') != thread) or (owner.get('generation') != runtime._main_generation) or (runtime._execute_thread != thread) or runtime._active_failed or (len(stack) != 1) or (stack[0]['name'] != 'main') or (stack[0]['arguments'] != tuple(arguments)) or (stack[0]['hosts'] is not None) or (getattr(vm.step, '__func__', None) is not PrimaryVM.step):
        raise PrimarySemanticUnavailable('independent Main mix requires the unobserved current Main owner')
    from .primary_main_prefix_stop import _current, _PrefixComplete
    prefix = _current(runtime)
    if prefix is not None:
        prefix.attach(vm)
    report['entered'] = True
    report['exit'] = 'RAISED'
    state = dict(execution='independent-main-mix', phase='running', retained_steps=0, semantic_record_count=0)
    vm.primary_main_state = state
    initial = len(vm.trace)
    charged = 0

    def charge():
        nonlocal charged
        if charged >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        charged += 1
        report['chargedRecordCount'] = charged
    try:
        while not vm.halted:
            if vm.abort_reason is not None:
                raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
            if True and (vm.pc, vm.block, vm.predecessor, vm.initial_block) in PREFIX_ENTRIES:
                segment = dict(kind='MAIN_PREFIX', entryWord=vm.pc, exitWord=PREFIX_EXITS[vm.pc], referenceRecordCount=0, completed=False)
                report['semanticSegments'].append(segment)
                prior_prefix_state = getattr(vm, 'primary_main_prefix_state', None)
                try:
                    execute_primary_main_prefix(vm, charge=charge)
                finally:
                    prefix_state = getattr(vm, 'primary_main_prefix_state', None)
                    if prefix_state is not prior_prefix_state:
                        segment.update(prefix_state)
                        state['semantic_record_count'] += prefix_state['referenceRecordCount']
                continue
            if True and (vm.pc, vm.block, vm.predecessor, vm.initial_block) == TAIL_ENTRY:
                segment = dict(kind='MAIN_LITERAL_TAIL', entryWord=62638, exitWord=66548, referenceRecordCount=0, completed=False)
                report['semanticSegments'].append(segment)
                prior_tail_state = getattr(vm, 'primary_main_tail_state', None)
                try:
                    execute_primary_main_tail(vm, charge=charge)
                finally:
                    tail_state = getattr(vm, 'primary_main_tail_state', None)
                    if tail_state is not prior_tail_state:
                        segment.update({key: value for key, value in tail_state.items() if not key.startswith('_')})
                        family_completed = any((item.get('program') == 'host129' and item.get('mainCallWord') == 62638 and item.get('completed') for item in report['host129Family'].get('semanticSegments', [])))
                        source_binding = runtime._host129_source_clock_binding
                        if family_completed and (not (source_binding is not None and source_binding.failed)):
                            segment['childGeneric'] = []
                            segment['host129Backend'] = 'DIRECT_SOURCE_HOST129_FAMILY'
                            segment['backend'] = 'DIRECT_MAIN_LITERAL_TAIL_WITH_DIRECT_HOST129_FAMILY'
                            report['mainTailCoverage']['childGeneric'] = []
                            report['mainTailCoverage']['host129Backend'] = 'DIRECT_SOURCE_HOST129_FAMILY'
                            report['mainTailCoverage']['backend'] = 'DIRECT_MAIN_LITERAL_TAIL_WITH_DIRECT_HOST129_FAMILY'
                        state['semantic_record_count'] += tail_state['referenceRecordCount']
                continue
            if True and (vm.pc, vm.block, vm.predecessor, vm.initial_block) == REST_ENTRY:
                segment = dict(kind='MAIN_HOST_FREE_REST', entryWord=45584, exitWord=62638, referenceRecordCount=0, completed=False)
                report['semanticSegments'].append(segment)
                prior_rest_state = getattr(vm, 'primary_main_rest_state', None)
                try:
                    execute_primary_main_rest(vm, charge=charge)
                finally:
                    rest_state = getattr(vm, 'primary_main_rest_state', None)
                    if rest_state is not prior_rest_state:
                        segment.update(rest_state)
                        state['semantic_record_count'] += rest_state['referenceRecordCount']
                continue
            if True and (vm.pc, vm.block, vm.predecessor, vm.initial_block) in CONTINUATION_ENTRIES:
                segment = dict(kind='MAIN_MATERIAL_CONTINUATION', entryWord=vm.pc, exitWord=None, referenceRecordCount=0, completed=False)
                report['semanticSegments'].append(segment)
                prior_continuation_state = getattr(vm, 'primary_main_material_continuation_state', None)
                try:
                    execute_primary_main_material_continuation(vm, charge=charge)
                finally:
                    continuation_state = getattr(vm, 'primary_main_material_continuation_state', None)
                    if continuation_state is not prior_continuation_state:
                        segment.update(continuation_state)
                        state['semantic_record_count'] += continuation_state['referenceRecordCount']
                continue
            if True and (vm.pc, vm.block, vm.predecessor, vm.initial_block) in WINDOW_ENTRIES:
                segment = dict(kind='MAIN_MATERIAL_INPUTS' if vm.pc == 37823 else 'MAIN_MATERIAL_PUBLICATION_PREMIX', entryWord=vm.pc, exitWord=WINDOW_EXITS[vm.pc], referenceRecordCount=0, completed=False)
                report['semanticSegments'].append(segment)
                prior_window_state = getattr(vm, 'primary_main_material_window_state', None)
                try:
                    execute_primary_main_material_window(vm, charge=charge)
                finally:
                    window_state = getattr(vm, 'primary_main_material_window_state', None)
                    if window_state is not prior_window_state:
                        segment.update(window_state)
                        state['semantic_record_count'] += window_state['referenceRecordCount']
                continue
            if True and vm.pc in CONSUMER_ENTRIES:
                segment = dict(kind='MAIN_ENCODED_RECORD_CONSUMER', entryWord=vm.pc, exitWord=CONSUMER_ENTRIES[vm.pc][1], referenceRecordCount=0, completed=False, producerBackend='DIRECT_MATERIAL_BLOCK_FOR_MAIN_S_A')
                report['semanticSegments'].append(segment)
                prior_consumer_state = getattr(vm, 'primary_main_record_consumer_state', None)
                try:
                    execute_primary_main_record_consumer(vm, charge=charge)
                finally:
                    consumer_state = getattr(vm, 'primary_main_record_consumer_state', None)
                    if consumer_state is not prior_consumer_state:
                        segment.update(consumer_state)
                        segment['producerBackend'] = 'DIRECT_MATERIAL_BLOCK_FOR_MAIN_S_A'
                        state['semantic_record_count'] += consumer_state['referenceRecordCount']
                continue
            if True and (vm.pc, vm.block, vm.predecessor, vm.initial_block) == MERGE_ENTRY:
                segment = dict(kind='MAIN_POST_AS_MATERIAL_MERGE', entryWord=38470, exitWord=39468, referenceRecordCount=0, completed=False)
                report['semanticSegments'].append(segment)
                prior_merge_state = getattr(vm, 'primary_main_material_merge_state', None)
                try:
                    execute_primary_main_material_merge(vm, charge=charge)
                finally:
                    merge_state = getattr(vm, 'primary_main_material_merge_state', None)
                    if merge_state is not prior_merge_state:
                        segment.update(merge_state)
                        segment['subsequentPublicationBackend'] = 'DIRECT_MAIN_MATERIAL_PUBLICATION_PREMIX'
                        state['semantic_record_count'] += merge_state['referenceRecordCount']
                continue
            at_entry = (vm.pc, vm.block, vm.predecessor, vm.initial_block) == ENTRY
            if not at_entry:
                raise PrimarySemanticUnavailable('complete direct Main has no literal route for its current source state')
            cost = 24
            if charged + cost > max_steps:
                raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
            charged += cost
            report['chargedRecordCount'] = charged
            if at_entry:
                segment = dict(entryWord=44933, exitWord=45040, referenceRecordCount=24, completed=False)
                report['semanticSegments'].append(segment)
                yield from _execute_primary_main_mix(vm)
                segment['completed'] = True
                state['semantic_record_count'] += 24
            else:
                raise PrimarySemanticUnavailable('complete direct Main has no literal route for its current source state')
        state['phase'] = 'complete'
        report['exit'] = 'RETURNED'
        return vm.result
    except _PrefixComplete as stopped:
        if (prefix is None or stopped.witness is not prefix.witness or not prefix.valid() or
                prefix.state != 'captured'):
            raise InputError('foreign prefix completion signal')
        prefix.state = 'stopped'
        state['phase'] = 'prefix9563'
        report['exit'] = 'PREFIX9563'
        return stopped.witness
    finally:
        state['retained_steps'] += len(vm.trace) - initial
        report['genericRecordCount'] = len(vm.trace) - initial
