"""Controlled client source-memory/API boundaries; never a native SDK run."""
import ctypes
import os
import time
from pathlib import Path
import sys
import threading
from contextlib import contextmanager, ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import patch

_RETAINED_CLIENT_FIXTURES = []

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / 'src'), str(Path(__file__).resolve().parent)]


def signer():
    from qq_nt_replica.primary_signer import PrimarySigner, SigningEnvironment
    return PrimarySigner(SigningEnvironment(cursor=None, process_path=b'C:/explicit/p.exe',
        module_path=b'C:/explicit/m.dll', stack_modules=()), initial_stack=None, primary_backend='direct')


class PhysicalThreads:
    """Python threads stand at physical CreateThread/bridge/Sleep, never source bodies."""
    join_sample_seconds = 5
    join_max_seconds = 120
    cleanup_seconds = 10
    def __init__(self, kernel):
        self.kernel = kernel
        self.original = kernel.call
        self.rows = {}
        self.next = 1000
        self.sleeps = []
        self.on_sleep = None
        self.sleep_result = None
        self.progress=[]
        self.srw_calls=[]
        self.on_srw=None
        self.joins=[]
        self.cleanup=[]
        self.capi_calls=[];self.on_capi=None

    def create(self, callback, argument, ready=None):
        self.next += 1; handle = self.next; registered = threading.Event()
        row = dict(handle=handle, thread_id=0, callback=callback, argument=argument, result=None, error=None)
        def run():
            row['thread_id'] = threading.get_native_id(); registered.set()
            if ready is not None: ready.wait()
            try: row['result'] = callback(argument)
            except BaseException as error: row['error'] = error
        row['thread'] = threading.Thread(target=run, name='controlled-client-source')
        self.rows[handle] = row; row['thread'].start()
        if not registered.wait(5): raise AssertionError('controlled thread did not register')
        return row

    def call(self, name, args):
        def integer(value): return int(getattr(value, 'value', value) or 0)
        if name == 'CreateThread':
            row = self.create(args[2], integer(args[3]))
            args[5]._obj.value = row['thread_id']
            return row['handle']
        if name == 'DuplicateHandle':
            source = integer(args[1]); self.next += 1
            self.rows[self.next] = self.rows[source]; args[3]._obj.value = self.next
            return 1
        if name == 'GetThreadId': return self.rows[integer(args[0])]['thread_id']
        if name in ('CryptAcquireContextW','CryptGenRandom','CryptReleaseContext'):
            provider=self.runtime.request_capi
            row=provider.operations[-1]
            self.capi_calls.append((name,row['phase']))
            if self.on_capi is not None:
                result=self.on_capi(name,args,row)
                if result is not None:return result
            if name=='CryptAcquireContextW':
                args[0]._obj.value=100+len(self.capi_calls)
                return 1
            if name=='CryptGenRandom':
                for index,value in enumerate((1).to_bytes(32,'little')):args[2][index]=value
            return 1
        if name == 'Sleep':
            self.sleeps.append(args[0])
            if self.on_sleep is not None: self.on_sleep(args[0])
            return self.sleep_result
        if name in ('AcquireSRWLockExclusive','ReleaseSRWLockExclusive'):
            pointer=integer(args[0]);cell=ctypes.c_uint64.from_address(pointer)
            self.srw_calls.append((name,pointer,cell.value))
            if self.on_srw is not None:self.on_srw(name,cell)
            cell.value=1 if name=='AcquireSRWLockExclusive' else 0
            return None
        return self.original(name, args)

    def join(self, handle):
        row=self.rows[handle];started=time.monotonic();cpu=time.process_time()
        previous=self._progress();stalled=0
        record=dict(handle=handle,started=started,samples=[],exited=False)
        self.joins.append(record)
        while row['thread'].is_alive():
            remaining=self.join_max_seconds-(time.monotonic()-started)
            if remaining<=0:break
            row['thread'].join(min(self.join_sample_seconds,remaining))
            if not row['thread'].is_alive():break
            current=self._progress();current_cpu=time.process_time()
            sample=dict(wall_seconds=time.monotonic()-started,cpu_seconds=current_cpu-cpu,**current)
            sample['stack']=self._stack(row['thread'].ident)
            progressing=current!=previous
            stalled=0 if progressing else stalled+1
            sample['progressing']=progressing
            record['samples'].append(sample);self.progress.append(sample)
            print('controlled_join_progress '+__import__('json').dumps(sample),flush=True)
            # A repeated fixed point does not justify another long blind wait.
            if stalled>=3:break
            previous,cpu=current,current_cpu
        record.update(exited=not row['thread'].is_alive(),wall_seconds=time.monotonic()-started)
        print('controlled_join_terminal '+__import__('json').dumps(dict(
            exited=record['exited'],wall_seconds=record['wall_seconds'],samples=len(record['samples']),
            phase_counts=self._phase_counts(),stack=self._stack(row['thread'].ident))),flush=True)
        if not record['exited']:raise AssertionError('controlled client thread remains live; progress recorded')
        if row['error'] is not None: raise row['error']
        return row

    def _progress(self):
        runtime=getattr(self,'runtime',None)
        return dict(writes=0 if runtime is None else len(runtime.memory.writes),
            regions=0 if runtime is None else len(runtime.memory._region_snapshot()),phase_counts=self._phase_counts(),
            lookup_fast_eligible=False if runtime is None else not runtime.memory._layout_poisoned,
            first_raw_escape=None if runtime is None else getattr(runtime.memory,'_layout_first_escape',None),
            programs=[] if runtime is None else
            [dict(pc=vm.pc,block=vm.block,halted=vm.halted,abort=vm.abort_reason,
                  host_calls=len(vm.host_calls),bootstrap=dict(getattr(vm,'primary_bootstrap_direct_state',{})))
             for vm in tuple(runtime.vms)])

    def _phase_counts(self):
        from collections import Counter
        return {name+':'+phase:count for (name,phase),count in Counter(self.capi_calls).items()}

    @staticmethod
    def _stack(identifier):
        frame=sys._current_frames().get(identifier);stack=[]
        while frame is not None and len(stack)<16:
            stack.append(dict(file=Path(frame.f_code.co_filename).name,function=frame.f_code.co_name,line=frame.f_lineno))
            frame=frame.f_back
        return stack

    def _cleanup_event(self,event,**fields):
        row=dict(event=event,**fields)
        if event in ('all_children_exited_before_fake_restore','failure_only_MODEL_abort','fake_ports_retained_for_live_children'):
            self.cleanup.append(row)
        print('controlled_fixture_cleanup '+__import__('json').dumps(row),flush=True)

    def _restored(self):
        self._cleanup_event('outer_fake_stack_restored',
            live_children=sum(row['thread'].is_alive() for row in {id(r):r for r in self.rows.values()}.values()),
            scalar_observer_closed=getattr(getattr(self,'scalar_entropy',None),'_closed',None))

    def quiesce(self, owner, stack):
        """Retain every fake port if bounded failure disposal cannot join a child."""
        service=owner._threads
        if service is not None:service._gate.set()
        bridge=getattr(self,'bridge',None)
        if bridge is not None:
            for launch in bridge.launches:launch.gate.set()
        started=time.monotonic();aborted=False
        while True:
            live={id(row):row for row in self.rows.values() if row['thread'].is_alive()}
            if not live:
                self._cleanup_event('all_children_exited_before_fake_restore',aborted=aborted)
                return
            elapsed=time.monotonic()-started
            if elapsed>=self.cleanup_seconds and not aborted:
                runtime=getattr(self,'runtime',None)
                if runtime is not None:
                    for vm in tuple(runtime.vms):
                        if not vm.halted and vm.abort_reason is None:vm.abort_reason='controlled test resource deadline'
                aborted=True
                self._cleanup_event('failure_only_MODEL_abort',children=len(live))
            if elapsed>=2*self.cleanup_seconds:
                held=stack.pop_all()
                debt=dict(stack=held,physical=self,owner=owner,children=list(live.values()))
                _RETAINED_CLIENT_FIXTURES.append(debt)
                self._cleanup_event('fake_ports_retained_for_live_children',children=len(live))
                raise AssertionError('controlled child not quiesced; fake ports retained, not restored')
            for row in live.values():row['thread'].join(min(.1,self.cleanup_seconds))


class PhysicalBridge:
    def __init__(self, physical):
        self.physical = physical; self.launches = []; self._closed = False
    def authorize_service(self, check):
        self.check = check; self.capability = object(); return self.capability
    def close(self):
        if any(launch.native['thread'].is_alive() for launch in self.launches):
            raise AssertionError('controlled bridge still has live children')
        self._closed=True
    @contextmanager
    def service_creation(self, capability):
        assert capability is self.capability and self.check()
        yield
    def acquire_worker_reference(self, base, callback):
        assert callback == base + 0x7879A0
        return SimpleNamespace(result=0, module=0)
    def launch(self, dispatch, context, *, module_reference, quiescence_check):
        assert self.check() and module_reference is None
        gate = threading.Event()
        row = self.physical.create(dispatch, context, gate)
        launch = SimpleNamespace(handle=row['handle'], thread_id=row['thread_id'], creation_error=0,
            joined=False, handle_closed=False, context=context, gate=gate, native=row)
        self.launches.append(launch); return launch


class FixtureLifetime(unittest.TestCase):
    def test_wait_requires_observed_progress_and_records_terminal_join(self):
        kernel=SimpleNamespace(call=lambda *args:None)
        physical=PhysicalThreads(kernel)
        physical.join_sample_seconds=.01;physical.join_max_seconds=.3
        physical.runtime=SimpleNamespace(memory=SimpleNamespace(writes=[]),vms=[])
        def progress(_):
            for index in range(12):
                physical.runtime.memory.writes.append(index)
                time.sleep(.005)
            return 7
        row=physical.create(progress,0)
        try:
            self.assertIs(physical.join(row['handle']),row)
            self.assertEqual(row['result'],7)
            self.assertTrue(physical.joins[-1]['exited'])
            self.assertGreaterEqual(len(physical.joins[-1]['samples']),2)
            self.assertTrue(any(sample['progressing'] for sample in physical.progress))
        finally:row['thread'].join(1)

    def test_failed_cleanup_retains_fake_ports_until_the_actual_child_exits(self):
        gate=threading.Event();observed=[];row=None;debt=None
        original=ctypes.WinDLL
        try:
            with self.assertRaisesRegex(AssertionError,'fake ports retained'):
                with client_factory() as (owner,kernel,physical):
                    physical.cleanup_seconds=.01
                    physical.join_sample_seconds=.01;physical.join_max_seconds=.04
                    def blocked(_):
                        gate.wait()
                        observed.append(ctypes.GetLastError())
                        return 0
                    row=physical.create(blocked,0)
                    with self.assertRaisesRegex(AssertionError,'progress recorded'):
                        physical.join(row['handle'])
            debt=next(item for item in _RETAINED_CLIENT_FIXTURES if item['physical'] is physical)
            self.assertTrue(row['thread'].is_alive())
            self.assertIs(ctypes.WinDLL('controlled-test-only'),kernel)
            self.assertEqual(ctypes.GetLastError(),0x1234)
            self.assertEqual(physical.cleanup[-1]['event'],'fake_ports_retained_for_live_children')
            gate.set();row['thread'].join(1)
            self.assertFalse(row['thread'].is_alive())
            self.assertEqual(observed,[0x1234])
        finally:
            gate.set()
            if row is not None:row['thread'].join(1)
            if debt is not None and not row['thread'].is_alive():
                debt['stack'].close();_RETAINED_CLIENT_FIXTURES.remove(debt)
        self.assertIs(ctypes.WinDLL,original)


class PhysicalCRTEnvironment:
    """Explicit physical PEB-input fixture; never reads this process's PEB."""
    def __init__(self):self.identity=(os.getpid(),threading.get_native_id());self.closed=False
    def current_identity(self):
        assert not self.closed and self.identity==(os.getpid(),threading.get_native_id())
        return self.identity
    def query_current_peb(self):self.current_identity();return 0x78000000
    def read_exact(self,address,size):
        self.current_identity()
        if (address,size)==(0x78000020,8):return (0x78001000).to_bytes(8,'little')
        if (address,size)==(0x78001008,4):return bytes(4)
        raise AssertionError('unexpected physical CRT environment field')
    def close(self):self.current_identity();self.closed=True


@contextmanager
def controlled_cached_apis(kernel, metadata):
    """Finite LastError metadata ports; never bind a cached native address."""
    original_abi=ctypes.WINFUNCTYPE
    values={};prototypes={}
    def get_error():
        tid=threading.get_native_id(); value=values.setdefault(tid,0x1234)
        metadata.append(('GetLastError',tid,value));return value
    def set_error(value):
        value=int(value)&0xFFFFFFFF;tid=threading.get_native_id();values[tid]=value
        metadata.append(('SetLastError',tid,value))
    def controlled_abi(*types,**kw):
        key=(types,tuple(sorted(kw.items())))
        if key in prototypes:return prototypes[key]
        factory=original_abi(*types,**kw)
        class Guard(type(factory)):
            def __call__(cls,value,*args,**kwargs):
                if isinstance(value,tuple):
                    if value==('SetLastError',kernel) and types==(None,ctypes.c_uint32) and not kw:
                        return set_error
                    raise AssertionError('uncontrolled cached native API binding')
                if not callable(value):raise AssertionError('uncontrolled native function address')
                return super().__call__(value,*args,**kwargs)
        prototype=Guard('_ControlledSourceABI',(ctypes._CFuncPtr,),dict(
            _flags_=factory._flags_,_argtypes_=factory._argtypes_,_restype_=factory._restype_))
        prototypes[key]=prototype
        return prototype
    with patch.object(ctypes,'GetLastError',side_effect=get_error), \
            patch.object(ctypes,'windll',SimpleNamespace(kernel32=kernel)), \
            patch.object(ctypes,'WINFUNCTYPE',side_effect=controlled_abi):
        yield get_error,set_error


@contextmanager
def client_factory(*,registration_failure=None,outer=False):
    """Actual factory/issuer/selected ctor with explicit physical CLI/CRT ports."""
    from test_primary_creator_domain import PhysicalKernel
    from qq_nt_replica import primary_windows_signer as windows
    from qq_nt_replica.primary_windows_command_line import _CommandLineBorrow
    kernel=PhysicalKernel();physical=PhysicalThreads(kernel);kernel.call=physical.call
    physical.metadata=[]
    class CommandLine:
        def __init__(self):self.identity=(os.getpid(),threading.get_native_id());self.closed=False
        def current_identity(self):
            assert not self.closed and self.identity==(os.getpid(),threading.get_native_id())
            return self.identity
        def capture(self,session,identity):
            assert identity==self.current_identity()
            # This physical input selects the actual source CRT family. No
            # allocator capability, branch result or constructor is mocked.
            raw=b'--notcmalloc\0'
            return _CommandLineBorrow(identity,session,0x7600000000,bytearray(raw+bytes(15)),len(raw))
        def close(self):self.closed=True
    constructors=('WindowsCallerAPIBackend','WindowsCallerBridge','WindowsCallerObservations','WindowsProviderObservations',
        'WindowsWorkerObservations','WindowsDeviceFileObservations','WindowsCoreObservations','WindowsDeviceProcessRecordObservations',
        'WindowsDeviceHardwareObservations','WindowsSystemRecordObservations','WindowsWMIObservations')
    with ExitStack() as stack:
        physical._fixture_stack=stack
        stack.callback(physical._restored)
        stack.enter_context(patch.object(ctypes,'WinDLL',return_value=kernel))
        stack.enter_context(patch.object(ctypes,'CDLL',side_effect=AssertionError('no actual DLL')))
        stack.enter_context(controlled_cached_apis(kernel,physical.metadata))
        stack.enter_context(patch('qq_nt_replica.primary_windows_crt_environment.WindowsCRTEnvironmentBackend',side_effect=PhysicalCRTEnvironment))
        stack.enter_context(patch('qq_nt_replica.primary_windows_command_line.WindowsCommandLineBackend',CommandLine))
        stack.enter_context(patch.object(windows,'_validated_paths',return_value=(Path('controlled.dll'),Path('controlled'))))
        for name in constructors:stack.enter_context(patch.object(windows,name))
        stack.enter_context(patch.object(windows.DeviceFactory,'windows'))
        stack.enter_context(patch.object(windows.WindowsSigner,'_host_environment',return_value=(b'C:/explicit/p.exe',None,())))
        stack.enter_context(patch.object(windows.WindowsSigner,'_initialize_notification_statics'))
        stack.enter_context(patch.object(windows.WindowsSigner,'diagnostics',new=property(lambda actual:{})))
        if outer:
            stack.enter_context(patch('qq_nt_replica.primary_windows_signer_setup.IndependentWindowsSetup'))
        if registration_failure is not None:
            from qq_nt_replica.primary_host_services import GuestExitRegistrar
            from qq_nt_replica.primary_client_configuration_startup import _INIT_ACTIVE
            original=GuestExitRegistrar.__call__;calls=[0]
            def register(registrar,callback):
                if registrar._runtime in _INIT_ACTIVE:
                    calls[0]+=1
                    result=registration_failure(calls[0],registrar,callback)
                    if result is not None:return callback,result
                return original(registrar,callback)
            stack.enter_context(patch.object(GuestExitRegistrar,'__call__',register))
        windows.WindowsDeviceFileObservations.return_value.pending_handles=0
        windows.WindowsDeviceFileObservations.return_value.cleanup_records=[]
        owner=windows.open_windows_signer(bridge_path='controlled.dll',storage_root='controlled',
            host_profile_string=b'explicit-model-profile',primary_backend='direct',
            **(dict(outer_login_config={},outer_sync_permit=lambda actual,operation:True) if outer else {}))
        physical.runtime=owner.signer.runtime
        try:
            yield owner,kernel,physical
        finally:
            physical.quiesce(owner,stack)


@contextmanager
def source_threads(*, observation=None, filetime=None, core_output=None):
    from qq_nt_replica import primary_windows_signer as windows
    with client_factory() as (owner, kernel, physical):
        service, runtime = owner._threads, owner.signer.runtime
        # This controlled physical core provides no registered dynamic exports.
        windows.WindowsCoreObservations.return_value._typed_exports={}
        windows.WindowsCallerObservations.return_value.filetime.return_value=116444736000000000
        if filetime is not None:windows.WindowsCallerObservations.return_value.filetime.side_effect=lambda:filetime(runtime)
        core_events=[];counter=[100000000];entropy=[0x10203040]
        def clock_output(actual,name,destination,*,purpose):
            if core_output is not None:
                value=core_output(actual,name,destination,purpose)
                if value is not None:return value
            if name=='QueryPerformanceCounter':counter[0]+=1000000
            values={'QueryPerformanceFrequency':10000000,'QueryPerformanceCounter':counter[0]}
            if name not in values:raise AssertionError('unprovided physical core output '+name)
            core_events.append((name,values[name]))
            actual.memory.store(destination,values[name],8,source='controlled physical '+name)
            return 1
        windows.WindowsCoreObservations.return_value.write_to.side_effect=clock_output
        def entropy_word():
            value=entropy[0].to_bytes(4,'little');entropy[0]=(entropy[0]+0x01010101)&0xFFFFFFFF
            core_events.append(('SystemFunction036',value));return value
        windows.WindowsCoreObservations.return_value.entropy_word.side_effect=entropy_word
        from qq_nt_replica.primary_windows_core_observations import WindowsCoreObservations
        class EntropyBackend:
            closed=False
            def request(self,name,output,count):
                if self.closed or (name,count)!=('SystemFunction036',4):
                    raise AssertionError('unprovided physical scalar entropy shape')
                output.raw=entropy_word()
                return 1
            def close(self):self.closed=True
        entropy_backend=EntropyBackend()
        scalar_entropy=WindowsCoreObservations(backend=entropy_backend)
        # Exercise the real success/FALSE projection over explicit physical
        # output, rather than letting an unconfigured Mock become entropy.
        windows.WindowsCoreObservations.return_value.random_bytes.side_effect=scalar_entropy.random_bytes
        physical.scalar_entropy=scalar_entropy
        def close_scalar_entropy():
            scalar_entropy.close()
            physical._cleanup_event('scalar_observer_closed',live_children=sum(
                row['thread'].is_alive() for row in {id(r):r for r in physical.rows.values()}.values()))
        physical._fixture_stack.callback(close_scalar_entropy)
        physical.runtime=runtime
        physical.core_events=core_events
        bridge = PhysicalBridge(physical); service.bind_worker_bridge(bridge);physical.bridge=bridge
        assert runtime._primary_allocator_selector.phase == 'complete'
        assert runtime._primary_allocator_selector.require_origin(runtime,'windows') is True
        def observe(r, name, arguments):
            if observation is not None:
                value = observation(r, name, arguments)
                if value is not None: return value
            if name == 'GetTickCount': return 7, b''
            if name == 'InitializeCriticalSectionEx': return 1, b''
            raise AssertionError('unprovided physical observation '+name)
        windows.WindowsWMIObservations.return_value.take.side_effect = observe
        yield owner, runtime, physical, bridge


def start_component(owner, runtime):
    from qq_nt_replica.primary_worker_consumer import _invoke
    service = owner._threads
    service.before_public_operation()
    try:
        with owner._registrar.operation():
            with service._native_crt_context():
                _invoke(runtime, 0x1C22D50)
    finally: service.after_public_operation()
    service._gate.set()
    return next(row for row in service._threads if row.get('_kind') == 'client_startup')


class StartupComponent(unittest.TestCase):
    def test_real_startup_selected_entry_first_boundary_and_early_close(self):
        from qq_nt_replica.primary_client_configuration_scope import image_for
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with source_threads() as (owner, r, physical, bridge):
            row = start_component(owner, r)
            physical.join(row['source_handle'])
            # This selected-entry fixture is not proof that the whole SDK calls 1C22D50.
            self.assertIn(row['state'], ('returned','host_failed'))
            if row['state'] == 'host_failed':
                import traceback
                raise AssertionError('options='+hex(r.memory.load(r.image_base+0x6749CC0,8))+
                    ' locale='+hex(r.memory.load(r.image_base+0x6D8E630,4))+'\n'+
                    ''.join(traceback.format_exception(owner._threads._failure)))
            self.assertEqual(r.memory.load(r.image_base+0x677CEA8,8),(1<<64)-1)
            raw = r.memory.load(r.image_base+0x6751DC0,8)
            self.assertNotEqual(raw,0)
            self.assertEqual(len(bridge.launches),1)
            image = image_for(r)
            self.assertIs(image.rows[0],row)
            with self.assertRaises(ExceptionGroup) as failure: owner.close()
            self.assertIsInstance(failure.exception.exceptions[0],PrimarySemanticUnavailable)

    def test_actual_cold_loop_null_transport_has_six_real_audits_and_ordinary_failure_callbacks(self):
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.primary_client_configuration_scope import image_for
        from qq_nt_replica.primary_windows_worker_bridge import NativeWorkerExit
        with source_threads() as (owner,r,physical,bridge):
            startup=start_component(owner,r); physical.join(startup['source_handle'])
            self.assertEqual(startup['state'],'returned')
            launch=bridge.launches[0]; launch.gate.set()
            finished=physical.join(launch.handle)
            self.assertEqual(finished['result'],NativeWorkerExit('ExitThread',0,0))
            self.assertIsNone(finished['error'])
            raw=r.memory.load(r.image_base+0x6751DC0,8)
            self.assertEqual(r.memory.load(raw+4,4),6)
            self.assertEqual(r.memory.load(raw+9,1),0)
            self.assertEqual(r.memory.load(raw+24,1),0)
            self.assertEqual(physical.sleeps,[0]+[100]*30+[60000,120000,180000,240000,300000,360000])
            image=image_for(r)
            producers=[value for kind,value in image.debts if kind=='producer']
            self.assertEqual(len(producers),6)
            self.assertTrue(all(value['claimed'] and value['audit_completed'] and value['completed'] for value in producers))
            self.assertEqual(len({value['frame'] for value in producers}),6)
            self.assertEqual(r.memory.load(r.image_base+0x6751AC0,8),0)
            labels=[label for address,data,label in r.memory.writes]
            self.assertEqual(labels.count('1C51934.configuration_failure_clear_inflight'),6)
            self.assertEqual(labels.count('1C50F90.configuration_count_lock_add'),6)
            self.assertFalse(any(label in ('request.sequence_advance','request.pending_key') for label in labels))
            self.assertFalse(any(event[0] in ('request.pending_dispatch','request.enhanced_pending_dispatch','configuration.native_sender_unavailable') for event in r.events))
            programs=next(row for row in owner._threads._secondary if row['_kind']=='client_loop')['direct_scope']
            self.assertEqual([row['program'] for row in programs['bootstrapPrograms']],['singleton-init','buffer-init'])
            self.assertTrue(all(row['completed'] for row in programs['bootstrapPrograms']))
            self.assertTrue(all(row['completed'] for row in programs['preMainStatus']['semanticSegments']))
            self.assertEqual(len(programs['preMainStatus']['semanticSegments']),7)
            self.assertNotEqual(r.memory.load(r.image_base+0x6D88CC0,8),0)
            with self.assertRaises(ExceptionGroup) as refusal:owner.close()
            self.assertIsInstance(refusal.exception.exceptions[0],PrimarySemanticUnavailable)

    def test_source_owner_mask_order_and_replaced_capture_refuse_before_entry_effects(self):
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_memory import UnknownMemory
        with source_threads() as (owner,r,physical,bridge):
            startup=start_component(owner,r);physical.join(startup['source_handle'])
            self.assertEqual(startup['state'],'returned')
            m=r.memory;b=r.image_base;raw=m.load(b+0x6751DC0,8)
            region,offset=m._span(raw,32)
            known={0,4,5,6,7,8,9,16,17,18,19,20,21,22,23,24}
            self.assertEqual(bytes(region.initialized),bytes(int(i in known) for i in range(32)))
            with self.assertRaises(UnknownMemory):m.read(raw,32)
            launch=bridge.launches[0]
            self.assertEqual((m.load(raw,1),m.load(raw+4,4),m.load(raw+8,1),m.load(raw+9,1),m.load(raw+16,8),m.load(raw+24,1)),(5,0,1,0,launch.handle,0))
            labels=[label for address,data,label in m.writes]
            ordered=('1C1B476.sdk_collection_publish','1C2326E.configuration_owner_publish',
                '1C2A322.configuration_started_claim','1C2A35D.configuration_thread_handle_publish')
            self.assertEqual([labels.index(label) for label in ordered],sorted(labels.index(label) for label in ordered))
            child=next(row for row in owner._threads._secondary if row['_kind']=='client_loop')
            control=child['_client_receipt']['control'];original,ignored=m._span(control,24)
            replacement=type(original)(original.address,memoryview(bytearray(original.data)),bytearray(original.initialized),original.name)
            index=next(i for i,x in enumerate(m._regions) if x is original)
            before=list(m.writes);metadata=list(physical.metadata)
            try:
                m._regions[index]=replacement;launch.gate.set()
                with self.assertRaises(InputError):physical.join(launch.handle)
                self.assertEqual(m.writes,before)
                self.assertEqual(physical.metadata,metadata)
                self.assertIsNone(child['_client_receipt'].get('entry_source'))
                self.assertEqual(m.load(raw+9,1),0)
            finally:m._regions[index]=original;replacement.data.release()

    def test_unissued_same_field_launch_copy_refused_before_source_entry_effects(self):
        from copy import copy
        from qq_nt_replica.errors import InputError
        with source_threads() as (owner,r,physical,bridge):
            startup=start_component(owner,r);physical.join(startup['source_handle'])
            self.assertEqual(startup['state'],'returned')
            child=next(row for row in owner._threads._secondary if row['_kind']=='client_loop')
            original=child['_launch'];replacement=copy(original)
            self.assertIsNot(original,replacement)
            before=list(r.memory.writes);metadata=list(physical.metadata)
            try:
                child['_launch']=replacement;original.gate.set()
                with self.assertRaises(InputError):physical.join(original.handle)
                self.assertEqual(r.memory.writes,before)
                self.assertEqual(physical.metadata,metadata)
                self.assertIsNone(child['_client_receipt'].get('entry_source'))
            finally:child['_launch']=original


class EarlyDebt(unittest.TestCase):
    def test_first_api_failure_retains_original_owner_and_rejects_all_retirement_bypasses(self):
        from qq_nt_replica import primary_client_configuration_scope as scope
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.errors import InputError
        failure = RuntimeError('controlled earliest startup GetTickCount failure')
        def observation(r, name, arguments):
            if name == 'GetTickCount': raise failure
        with source_threads(observation=observation) as (owner,r,physical,bridge):
            row = start_component(owner,r); physical.join(row['source_handle'])
            self.assertIs(owner._threads._failure,failure)
            self.assertEqual(r.memory.load(r.image_base+0x6751DC0,8),0)
            self.assertEqual(r.memory.load(r.image_base+0x6745268,8),0)
            self.assertEqual(bridge.launches,[])
            original = scope._OWNERS[owner]
            service = owner._threads
            checks = ((owner,'_signer',None),(owner,'_threads',None),(owner,'_threads',object()),
                (owner,'_registrar',object()),(owner.signer,'runtime',SimpleNamespace()),
                (r,'_shared_locale_source_epoch',object()),(owner,'_client_configuration_close',object()))
            for obj,name,value in checks:
                before=list(physical.kernel.calls)
                with self.subTest(name=name), patch.object(obj,name,value), patch.object(service,'prepare_close',side_effect=AssertionError('dangerous thread retirement')):
                    errors=owner._release_resources()
                    self.assertEqual(len(errors),1)
                    self.assertIsInstance(errors[0],(InputError,PrimarySemanticUnavailable))
                self.assertEqual(before,physical.kernel.calls)
            try:
                del scope._OWNERS[owner]
                self.assertIsInstance(owner._release_resources()[0],InputError)
            finally:scope._OWNERS[owner]=original
            with self.assertRaises(ExceptionGroup) as refusal: owner.close()
            self.assertIsInstance(refusal.exception.exceptions[0],PrimarySemanticUnavailable)

    def test_unqualified_raw_entries_reject_before_frame_mapping_or_writes(self):
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        s=signer(); r=s.runtime
        for rva in (0x1C50F70,0x1C50FE0,0x1C29F90,0x1C22D90):
            before=list(r.memory.writes); regions=list(r.memory._regions)
            with self.subTest(rva=rva),self.assertRaises(PrimarySemanticUnavailable):_invoke(r,rva,0x1234)
            self.assertEqual(r.memory.writes,before)
            self.assertEqual(r.memory._regions,regions)


class SleepLease(unittest.TestCase):
    def test_actual_startup_sleep_suspends_lease_allows_original_owner_and_close_cannot_cancel(self):
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.errors import InputError
        entered=threading.Event();release=threading.Event();seen=[]
        with source_threads() as (owner,r,physical,bridge):
            service=owner._threads
            def sleep(milliseconds):
                if seen:return
                tid=threading.get_native_id();lease=owner._registrar._leases[tid][-1]
                seen.append((milliseconds,tid,lease))
                self.assertTrue(lease.active and lease.suspended)
                self.assertFalse(service._execution.locked())
                self.assertIsNone(service._execution_tid)
                entered.set()
                if not release.wait(5):raise AssertionError('controlled sleep was not released')
            physical.on_sleep=sleep
            row=start_component(owner,r)
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(row['state'],'client_sleeping')
                tid=seen[0][1]
                saved=service._crt_domains[tid]['state']
                original_scope=saved['_primary_direct_scope']
                with self.assertRaises((InputError,PrimarySemanticUnavailable)):original_scope._require_live()
                service.before_public_operation()
                try:
                    with owner._registrar.operation():
                        with service._native_crt_context():
                            current=owner._registrar.current_lease()
                            self.assertTrue(current.active and not current.suspended)
                            self.assertIsNot(current,seen[0][2])
                            self.assertEqual(service._execution_tid,threading.get_native_id())
                finally:service.after_public_operation()
                self.assertEqual(row['state'],'client_sleeping')
                with self.assertRaises(ExceptionGroup) as refusal:owner.close()
                self.assertIsInstance(refusal.exception.exceptions[0],PrimarySemanticUnavailable)
                self.assertEqual(row['state'],'client_sleeping')
                self.assertEqual(physical.sleeps,[0])
            finally:release.set()
            physical.join(row['source_handle'])
            # close refused retirement, but its real owner remains cleanup_failed.
            # Resuming a wait must not make that owner eligible for later allocation.
            self.assertEqual(owner._state,'cleanup_failed')
            self.assertEqual(row['state'],'host_failed')
            self.assertIsInstance(row['_host_exception'],InputError)
            self.assertIn('early allocator issuer lost',str(row['_host_exception']))
            self.assertFalse(seen[0][2].active)
            self.assertEqual(physical.sleeps,[0])
            self.assertEqual(r.memory.load(r.image_base+0x677CEA8,8),0)
            self.assertEqual(r.memory.load(r.image_base+0x6751DC0,8),0)
            self.assertEqual(bridge.launches,[])

    def test_physical_sleep_failure_retains_first_error_and_does_not_continue_startup(self):
        failure=RuntimeError('controlled physical Sleep failure')
        with source_threads() as (owner,r,physical,bridge):
            def fail(milliseconds):raise failure
            physical.on_sleep=fail
            row=start_component(owner,r);physical.join(row['source_handle'])
            self.assertIs(owner._threads._failure,failure)
            self.assertEqual(row['state'],'host_failed')
            self.assertEqual(physical.sleeps,[0])
            self.assertEqual(r.memory.load(r.image_base+0x677CEA8,8),0)
            self.assertEqual(r.memory.load(r.image_base+0x6751DC0,8),0)
            self.assertEqual(bridge.launches,[])
            self.assertTrue(owner._threads._crt_domains)

    def test_sleep_resume_epoch_change_rejects_without_postwait_guest_writes(self):
        from qq_nt_replica.errors import InputError
        with source_threads() as (owner,r,physical,bridge):
            epoch=r._shared_locale_source_epoch; writes=[]
            def change(milliseconds):
                r._shared_locale_source_epoch=object();writes.append(len(r.memory.writes))
            physical.on_sleep=change
            try:
                row=start_component(owner,r);physical.join(row['source_handle'])
                self.assertEqual(row['state'],'host_failed')
                self.assertIsInstance(owner._threads._failure,InputError)
                self.assertEqual(len(r.memory.writes),writes[0])
                self.assertEqual(physical.sleeps,[0])
                self.assertEqual(r.memory.load(r.image_base+0x6751DC0,8),0)
            finally:r._shared_locale_source_epoch=epoch

    def test_sleep_failure_remains_first_error_when_epoch_also_breaks_domain_restore(self):
        failure=RuntimeError('controlled first physical Sleep error')
        with source_threads() as (owner,r,physical,bridge):
            epoch=r._shared_locale_source_epoch
            def change_and_fail(milliseconds):
                r._shared_locale_source_epoch=object();raise failure
            physical.on_sleep=change_and_fail
            try:
                row=start_component(owner,r);physical.join(row['source_handle'])
                self.assertIs(owner._threads._failure,failure)
                self.assertTrue(any('retained-domain restore failed' in note for note in failure.__notes__))
                self.assertEqual(physical.sleeps,[0])
                self.assertEqual(bridge.launches,[])
            finally:r._shared_locale_source_epoch=epoch


class Birth(unittest.TestCase):
    def test_original_fresh_exact_cells_neighbors_and_warm_validation(self):
        from qq_nt_replica.primary_client_configuration_scope import image_for
        from qq_nt_replica.primary_client_configuration import install_image
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        from qq_nt_replica.errors import InputError
        s = signer(); r = s.runtime; m = r.memory; b = r.image_base
        image = image_for(r)
        self.assertIs(image.source, s._shared_locale_image)
        self.assertIs(image.epoch, r._shared_locale_source_epoch)
        for rva in (0x6751DC0, 0x677CE90, 0x677CEA8):
            region, offset = m._span(b + rva, 8)
            self.assertEqual((region.address, offset, len(region.data)), (b + rva, 0, 8))
            self.assertEqual(m.read(b + rva, 8), bytes(8))
            for address in (b + rva - 1, b + rva + 8):
                if rva == 0x6751DC0 or address == b + 0x677CEA8 + 8:
                    with self.assertRaises(PrimaryMemoryLimit): m.read(address, 1)
                else:
                    # Independent tick/mutex/thread globals already own these neighbors.
                    adjacent, ignored = m._span(address, 1)
                    self.assertFalse(any(adjacent is owned for _, owned, _ in image.regions))
        m.store(b + 0x6751DC0, 0x1234, 8, source='controlled warm pointer')
        before = list(m.writes)
        self.assertIs(image_for(r), image)
        with self.assertRaises(InputError): install_image(s)
        self.assertEqual(m.load(b + 0x6751DC0, 8), 0x1234)
        self.assertEqual(before, m.writes)

    def test_all_intervals_preflight_overlap_and_matching_bytes_do_not_adopt(self):
        from qq_nt_replica.primary_memory import PrimaryMemory, PrimaryMemoryLimit
        original = PrimaryMemory.map
        for delta, size, initialized in ((0, 8, True), (7, 2, True), (3, 1, False)):
            memories = []
            def mapped(memory, address, buffer, **kw):
                result = original(memory, address, buffer, **kw)
                # Logger's final image mapping precedes the client installer.
                if not memories:
                    memories.append(memory)
                    original(memory, 0x180000000 + 0x6751DC0 + delta, bytearray(size),
                             initialized=initialized, name='controlled preexisting client conflict')
                return result
            with self.subTest(delta=delta, size=size), patch.object(PrimaryMemory, 'map', mapped):
                with self.assertRaisesRegex(PrimaryMemoryLimit, 'client configuration fresh image overlaps'): signer()
            self.assertFalse(any(x.address == 0x180000000 + 0x414ABD8 for x in memories[0]._regions))

    def test_memory_base_source_epoch_and_exact_region_replacement_refuse_without_write(self):
        from qq_nt_replica.primary_client_configuration_scope import image_for
        from qq_nt_replica.primary_memory import PrimaryMemory
        from qq_nt_replica.errors import InputError
        s = signer(); r = s.runtime; m = r.memory; source = r._shared_locale_source
        for obj, name, value in ((r,'memory',PrimaryMemory()), (r,'image_base',r.image_base+1),
                (r,'_primary_entry_owner',object()), (r,'_shared_locale_source',object()),
                (r,'_shared_locale_source_epoch',object()), (source,'epoch',object()),
                (s,'_shared_locale_image',object())):
            before = list(m.writes)
            with self.subTest(name=name), patch.object(obj, name, value):
                with self.assertRaises(InputError): image_for(r)
            self.assertEqual(before, m.writes)
        region, offset = m._span(r.image_base+0x6751DC0,8)
        copy = type(region)(region.address,memoryview(bytearray(region.data)),bytearray(region.initialized),region.name)
        index = next(i for i,x in enumerate(m._regions) if x is region)
        try:
            m._regions[index] = copy
            with self.assertRaises(InputError): image_for(r)
        finally:
            m._regions[index] = region; copy.data.release()


if __name__ == '__main__':
    unittest.main()
