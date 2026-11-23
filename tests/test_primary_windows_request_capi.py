"""Owned CAPI under the actual Client producer; all physical calls synthetic."""
import ctypes
import copy
from dataclasses import replace
import unittest
from unittest.mock import patch

from test_primary_client_configuration_request import client_factory,source_threads
from test_primary_client_configuration_startup import creator


class OwnedCapi(unittest.TestCase):
    def test_real_entropy_projection_uses_explicit_physical_bytes_and_preserves_false(self):
        from qq_nt_replica.primary_windows_core_observations import WindowsCoreObservations
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        class Backend:
            result=1;closed=False
            def request(self,name,output,count):
                self_name=name;self_count=count
                if (self_name,self_count)!=('SystemFunction036',4):raise AssertionError('unprovided physical input')
                output.raw=b'\x31\x32\x33\x34'
                return self.result
            def close(self):self.closed=True
        backend=Backend();observer=WindowsCoreObservations(backend=backend)
        try:
            value=observer.random_bytes(4)
            self.assertIs(type(value),bytes);self.assertEqual(len(value),4)
            backend.result=0
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'did not produce complete bytes'):observer.random_bytes(4)
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'returned false'):observer.entropy_word()
        finally:observer.close()
        self.assertTrue(backend.closed)

    def prefix(self,owner,r,physical,bridge):
        from qq_nt_replica.primary_client_configuration_startup import _own_client_configuration_input,_run_client_configuration_component
        with creator(owner):
            receipt=_own_client_configuration_input(owner,b'explicit-CAPI-component-input')
            _run_client_configuration_component(owner,receipt)
        owner._threads._gate.set()
        startup=next(row for row in owner._threads._threads if row.get('_kind')=='client_startup')
        physical.join(startup['source_handle'])
        self.assertEqual(startup['state'],'returned')
        bridge.launches[0].gate.set()
        return bridge.launches[0].handle

    def test_explicit_lazy_factory_binding_no_raw_provider_adoption_and_early_close_identity(self):
        from qq_nt_replica import primary_windows_request_capi as capi
        from qq_nt_replica.errors import InputError
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime;p=r.request_capi
            self.assertIs(capi._OWNERS[owner],p)
            self.assertIs(capi._RUNTIMES[r],p)
            self.assertIsNone(p.physical)
            self.assertEqual(p.operations,[])
            for phase in ('private','blinding'):
                with self.assertRaises(InputError):p.acquire(phase)
            self.assertEqual(p.operations,[])
            for obj,name,value in ((owner,'_signer',None),(owner,'_signer',object()),
                                   (r,'request_capi',None),(r,'request_capi',object()),
                                   (p,'physical',object()),
                                   (owner.signer,'runtime',object())):
                with self.subTest(name=name),patch.object(obj,name,value),patch.object(owner._threads,'prepare_close',side_effect=AssertionError('retirement before CAPI preflight')):
                    before=list(kernel.calls);errors=owner._release_resources()
                    self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],InputError)
                    self.assertEqual(kernel.calls,before)
            self.assertIsNone(p.physical)

    def test_source_generate_false_contract_does_not_invent_release_or_retry_branches(self):
        from qq_nt_replica.primary_request_capi import _generate,RequestCapiReplay,RequestCapiObservation as O,RequestCapiBuffer
        a=RequestCapiReplay([O('acquire','private',0,handle=9)])
        self.assertFalse(_generate(a,'private',RequestCapiBuffer()));self.assertEqual(a.consumed,1)
        a=RequestCapiReplay([O('acquire','private',1,handle=9),O('generate','private',0,output=b'\x01',handle=9),O('release','private',0,handle=9)])
        output=RequestCapiBuffer()
        self.assertTrue(_generate(a,'private',output));self.assertEqual(a.consumed,3)
        self.assertEqual(output._known,bytearray(b'\1'+bytes(31)))

    def test_actual_warm_material_branch_has_no_ticket_dll_or_capi_calls(self):
        from qq_nt_replica.primary_worker_consumer import _invoke
        with source_threads() as (owner,r,physical,bridge):
            # Standalone warm-branch fixture, not the cold continuous request.
            r.memory.store(r.image_base+0x677D0B8,1,1,source='explicit warm material fixture')
            r.memory.store(r.image_base+0x677D0D8,(1<<63)-1,8,source='explicit warm deadline fixture')
            with creator(owner):self.assertIsNone(_invoke(r,0x1C572E0))
            self.assertIsNone(r.request_capi.physical)
            self.assertEqual(r.request_capi.tickets,[])
            self.assertEqual(physical.capi_calls,[])
            # This fixture's unrelated bridge is a mock, not an unload receipt.
            # CAPI must retire normally before that existing host boundary.
            with self.assertRaises(ExceptionGroup):owner.close()
            self.assertTrue(any(row['stage']=='request_capi_terminal' and row['status']=='completed'
                                for row in owner._cleanup_outcomes))
            self.assertEqual(owner._cleanup_outcomes[-1]['stage'],'bridge_unload')
            self.assertTrue(r.request_capi.closed)

    def test_real_ordinary_false_paths_and_retained_handle_debt(self):
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica import primary_windows_request_capi as capi
        # Each alternative uses a new unmodified source runtime, never replaying
        # a failed Client producer or seeding material to bypass its real branch.
        for scenario in ('acquire_false','generate_false','release_false_retry'):
            print('controlled_CAPI_scenario '+scenario,flush=True)
            with self.subTest(scenario=scenario),source_threads() as (owner,r,physical,bridge):
                p=r.request_capi;private_generations=[0]
                def api(name,args,row):
                    if scenario=='acquire_false':
                        self.assertEqual(name,'CryptAcquireContextW');return 0
                    if scenario=='generate_false' and name=='CryptGenRandom':
                        args[2][0]=0x53
                        return 0
                    if scenario=='release_false_retry':
                        if name=='CryptAcquireContextW' and row['phase']=='blinding':return 0
                        if name=='CryptGenRandom':
                            private_generations[0]+=1
                            for i in range(32):args[2][i]=0 if private_generations[0]==1 else int(i==0)
                            return 1
                        if name=='CryptReleaseContext' and private_generations[0]==1:return 0
                physical.on_capi=api
                handle=self.prefix(owner,r,physical,bridge)
                with self.assertRaises(PrimarySemanticUnavailable) as stop:physical.join(handle)
                if scenario=='acquire_false':
                    self.assertEqual(physical.capi_calls,[('CryptAcquireContextW','private'),('CryptAcquireContextW','blinding')])
                    self.assertEqual(p.handles,[])
                    self.assertIn('native host RVA1be2f90',str(stop.exception))
                elif scenario=='generate_false':
                    self.assertEqual([name for name,phase in physical.capi_calls],['CryptAcquireContextW','CryptGenRandom','CryptReleaseContext'])
                    self.assertIn('unknown original caller scratch',str(stop.exception))
                    buffer=p.tickets[0].buffers['private']
                    self.assertEqual(buffer._data[0],0x53)
                    self.assertFalse(any(buffer._known))
                    self.assertFalse(p.handles[0]['live'])
                else:
                    self.assertIn('native host RVA1be2f90',str(stop.exception))
                    self.assertEqual([row['result'] for row in p.operations if row['operation']=='release'],[0,1])
                    self.assertEqual([phase for name,phase in physical.capi_calls if name=='CryptAcquireContextW'],['private','private','blinding'])
                    self.assertTrue(p.handles[0]['live']);self.assertFalse(p.handles[1]['live'])
                    with self.assertRaises(PrimarySemanticUnavailable):capi.preflight(owner)
                if scenario!='generate_false':
                    from qq_nt_replica.primary_client_configuration_scope import image_for
                    from qq_nt_replica.primary_memory import UnknownMemory
                    normal=next(value['normal_transport'] for kind,value in image_for(r).debts if kind=='producer')
                    self.assertTrue(normal.lock_held);self.assertEqual(normal.phase,'sender')
                    self.assertEqual(r.locks[normal.gate+56],1)
                    self.assertEqual(r.memory.load(normal.gate+40,8),1)
                    self.assertIn(normal.manager,r._constructed_request_managers)
                    self.assertEqual(r.memory.load(r.image_base+0x677D1C0,8),normal.manager)
                    node,digest=normal.records
                    from qq_nt_replica.primary_logger import _String
                    self.assertEqual(_String.read(r,node+32).value(),digest)
                    self.assertEqual(_String.read(r,node+56).value(),_String.read(r,normal.values[-1]).value())
                    self.assertEqual(normal.sender[0],r.image_base+0x1BE2F90)
                    self.assertEqual(normal.sender[1][-1],r.memory.load(normal.values[1]+128,8))
                    self.assertFalse(any(e[0]=='request.pending_dispatch' for e in r.events))
                self.assertIsNone(p.first_error)
                self.assertFalse(p.tickets[0].active)
                self.assertTrue(all(row['returned'] and row['recorded'] for row in p.operations))
                self.assertFalse(any(e[0]=='configuration.native_sender_unavailable' for e in r.events))

    def test_actual_api_and_record_failures_do_not_run_later_calls(self):
        from qq_nt_replica import primary_windows_request_capi as capi
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        for kind,operation in (('api','acquire'),('api','release'),('record','acquire'),('record','generate'),('record','release')):
            print('controlled_CAPI_scenario '+kind+'_'+operation,flush=True)
            failure=RuntimeError('controlled CAPI '+kind+' '+operation+' interruption')
            with self.subTest(kind=kind,operation=operation),source_threads() as (owner,r,physical,bridge):
                p=r.request_capi
                def api(name,args,row):
                    if kind=='api' and row['operation']==operation:raise failure
                physical.on_capi=api;original=p._record
                def record(row):
                    if kind=='record' and row['operation']==operation:raise failure
                    return original(row)
                with patch.object(p,'_record',side_effect=record):
                    handle=self.prefix(owner,r,physical,bridge)
                    with self.assertRaises(RuntimeError) as stopped:physical.join(handle)
                self.assertIs(stopped.exception,failure);self.assertIs(p.first_error,failure)
                row=p.operations[-1]
                self.assertEqual(row['operation'],operation)
                self.assertTrue(row['entered']);self.assertEqual(row['returned'],kind=='record')
                self.assertFalse(row['recorded'])
                self.assertFalse(p.tickets[0].active)
                expected={'acquire':1,'generate':2,'release':3}[operation]
                self.assertEqual(len(physical.capi_calls),expected)
                with self.assertRaises(PrimarySemanticUnavailable) as blocked:capi.preflight(owner)
                self.assertIs(blocked.exception.__cause__,failure)
                before=len(physical.capi_calls)
                with self.assertRaises(ExceptionGroup):owner.close()
                self.assertEqual(len(physical.capi_calls),before)

    def test_actual_ticket_identity_and_partial_physical_failure_keep_first_error_without_finally_release(self):
        from qq_nt_replica import primary_windows_request_capi as capi
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        failure=RuntimeError('controlled physical CAPI generation interruption')
        with source_threads() as (owner,r,physical,bridge):
            p=r.request_capi;probed=[]
            def api(name,args,row):
                if name!='CryptGenRandom':return
                t=row['ticket'];before=len(physical.capi_calls)
                h=t.history
                for obj,key,value in ((t.capi,'frame',t.frame+8),(t,'history',replace(h)),
                        (r,'_shared_locale_source_epoch',object()),(r,'request_capi',object()),
                        (p,'physical',object()),(p.physical,'library',object()),
                        (p.physical,'generate',object()),
                        (row['buffer'],'_data',bytearray(32)),(row['buffer'],'_known',bytearray(32))):
                    with patch.object(obj,key,value),self.assertRaises((InputError,PrimarySemanticUnavailable)):t.check('private',row['buffer'])
                copied=replace(h)
                with patch.dict(capi._HISTORY,{id(h.producer):copied}),self.assertRaises(InputError):t.check('private',row['buffer'])
                for address,region,size in t.regions:
                    index=next(i for i,item in enumerate(r.memory._regions) if item is region)
                    r.memory._regions[index]=copy.copy(region)
                    try:
                        with self.assertRaises(InputError):t.check('private',row['buffer'])
                    finally:r.memory._regions[index]=region
                self.assertEqual(len(physical.capi_calls),before)
                for phase,handle,buffer in (('blinding',row['handle'],row['buffer']),('private',row['handle']+1,row['buffer']),('private',row['handle'],object())):
                    with self.assertRaises(InputError):t.capi.generate(phase,handle,buffer)
                self.assertEqual(len(physical.capi_calls),before)
                self.assertFalse(h.claim.active);self.assertIsNone(h.claim.source)
                args[2][0]=0x65;probed.append(True);raise failure
            physical.on_capi=api
            handle=self.prefix(owner,r,physical,bridge)
            with self.assertRaises(RuntimeError) as caught:physical.join(handle)
            self.assertIs(caught.exception,failure);self.assertIs(p.first_error,failure)
            self.assertEqual(probed,[True]);self.assertEqual(len(physical.capi_calls),2)
            self.assertTrue(p.handles[0]['live'])
            row=p.operations[-1];self.assertTrue(row['entered']);self.assertFalse(row['returned']);self.assertFalse(row['recorded'])
            self.assertFalse(any(row['buffer']._known))
            self.assertEqual(row['buffer']._data[0],0x65)
            with self.assertRaises(PrimarySemanticUnavailable) as denied:capi.preflight(owner)
            self.assertIs(denied.exception.__cause__,failure)
            for obj,name,value in ((owner,'_signer',None),(r,'request_capi',None),(owner.signer,'runtime',object())):
                with patch.object(obj,name,value),patch.object(owner._threads,'prepare_close',side_effect=AssertionError('dangerous early retirement')):
                    before=len(physical.capi_calls);self.assertEqual(len(owner._release_resources()),1)
                    self.assertEqual(len(physical.capi_calls),before)
