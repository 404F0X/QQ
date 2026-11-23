"""Controlled actual normal helpers and original Client continuation; no native send."""
import unittest
from qq_nt_replica.primary_logger import _String
from qq_nt_replica.primary_memory import UnknownMemory, PrimaryMemoryLimit
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from qq_nt_replica.primary_worker_consumer import _invoke
from qq_nt_replica.primary_worker_response import _frame
from test_primary_client_configuration_request import client_factory,source_threads
from test_primary_client_configuration_startup import creator


class Normal(unittest.TestCase):
    def table(self,r):
        address=_invoke(r,0xB75000,24)
        for offset,value in ((0,address+8),(8,0),(16,0)):
            r.memory.store(address+offset,value,8,source='explicit component table ABI')
        return address

    def control(self,r,owners=1):
        c=_invoke(r,0xB75000,0xB8)
        for offset,value,width in ((0,r.image_base+0x414B4C8,8),(8,owners,4),(16,0,4)):
            r.memory.store(c+offset,value,width,source='explicit component shared record ABI')
        r.memory.write(c+24,bytes(160),source='explicit component record fields')
        return c

    def args(self,r,key,c):
        frame,rbp=_frame(r,0x178,'explicit component pending input/output')
        for offset,value in ((0,key),(8,c+24),(16,c)):
            r.memory.store(frame+offset,value,8,source='explicit component owning T24')
        return frame,frame+32

    def test_pending_actual_MOVE_duplicate_dispose_out_padding_and_source_order(self):
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                table=self.table(r);c=self.control(r);t,out=self.args(r,0,c)
                self.assertEqual(_invoke(r,0x1CF41A0,table,out,t),out)
                node=m.load(out,8)
                self.assertEqual((m.load(node+32,8),m.load(node+40,8),m.load(node+48,8)),(0,c+24,c))
                self.assertEqual(m.read(t+8,16),bytes(16));self.assertEqual(m.load(t,8),0)
                self.assertEqual(m.load(out+8,1),1);self.assertEqual(m.load(table+16,8),1)
                for address,width in ((out+9,7),(node+25,7)):
                    with self.assertRaises(UnknownMemory):m.read(address,width)
                labels=[w[2] for w in m.writes]
                order=['1CF41A0.candidate_key','1CF41DB.temporary_pair_clear','1CF41A0.link_publish',
                       '434C.pending_root_black','1CF41A0.count_publish','1CF41A0.out_inserted']
                self.assertEqual([labels.index(v) for v in order],sorted(labels.index(v) for v in order))
                other=self.control(r,owners=0);t2,out2=self.args(r,0,other)
                self.assertIn(other,r.allocations)
                before=len(m.writes)
                _invoke(r,0x1CF41A0,table,out2,t2)
                self.assertEqual((m.load(out2,8),m.load(out2+8,1),m.load(table+16,8)),(node,0,1))
                self.assertEqual(m.read(t2+8,16),bytes(16));self.assertEqual(m.load(c+8,4),1)
                self.assertNotIn(other,r.allocations)
                self.assertTrue(any(event[0]=='HeapFree' and event[-1]==other for event in r.events))
                with self.assertRaisesRegex(PrimaryMemoryLimit,'unmapped'):m.read(other,0xB8)
                self.assertTrue(any(label=='1CF41A0.candidate_key' for a,v,label in m.writes[before:]))
                with self.assertRaises(UnknownMemory):m.read(out2+9,7)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_duplicate_does_not_consume_or_restore_unknown_count(self):
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                table=self.table(r);t,out=self.args(r,3,self.control(r));_invoke(r,0x1CF41A0,table,out,t)
                node=m.load(out,8);m.forget(table+16,8,source='explicit unknown count fixture')
                region,offset=m._span(table+16,8);raw=bytes(region.data[offset:offset+8])
                t2,out2=self.args(r,3,self.control(r));_invoke(r,0x1CF41A0,table,out2,t2)
                self.assertEqual((m.load(out2,8),m.load(out2+8,1)),(node,0))
                self.assertEqual(bytes(region.data[offset:offset+8]),raw)
                with self.assertRaises(UnknownMemory):m.load(table+16,8)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_signed_noncold_attach_retains_MOVE_link_and_unknown_color_before_actual_4341(self):
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                table=self.table(r);t,out=self.args(r,0,self.control(r));_invoke(r,0x1CF41A0,table,out,t);root=m.load(out,8)
                t2,out2=self.args(r,(1<<64)-1,self.control(r))
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'RVA4341'):_invoke(r,0x1CF41A0,table,out2,t2)
                left=m.load(root,8);self.assertNotEqual(left,0);self.assertEqual(m.load(root+8,8),0)
                self.assertEqual(m.load(left+32,8),(1<<64)-1);self.assertEqual(m.load(table+16,8),1)
                self.assertEqual(m.read(t2+8,16),bytes(16))
                for address,width in ((left+24,1),(out2,9)):
                    with self.assertRaises(UnknownMemory):m.read(address,width)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_NULL_and_unknown_callback_are_read_only_after_actual_lock(self):
        from qq_nt_replica.primary_request_transport import _normal_registration
        for known in (True,False):
            with self.subTest(known=known),client_factory() as (owner,kernel,physical):
                r=owner.signer.runtime;m=r.memory
                with creator(owner):
                    f,rbp=_frame(r,0x178,'explicit component caller');callback=f+32
                    receiver=_invoke(r,0xB75000,64);record=self.control(r)
                    m.store(receiver+48,77,8,source='explicit original receiver sequence')
                    if known:m.store(callback+32,0,8,source='explicit NULL callback')
                    gate=_invoke(r,0xBA21A0);before=list(m.writes)
                    if known:self.assertEqual(_normal_registration(r,receiver,record,callback,rbp),gate)
                    else:
                        with self.assertRaises(UnknownMemory):_normal_registration(r,receiver,record,callback,rbp)
                    self.assertEqual(r.locks[gate+56],1)
                    self.assertEqual(m.load(receiver+48,8),77);self.assertEqual(m.writes,before)
                    self.assertEqual(r.events[-1],('EnterCriticalSection',gate+56))
                with self.assertRaises(ExceptionGroup):owner.close()

    def test_nonNULL_original_receiver_differs_from_gate_and_unchecked_owner_wraps(self):
        from qq_nt_replica.primary_request_transport import _normal_registration
        with source_threads() as (owner,r,physical,bridge):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                from qq_nt_replica.primary_super_reporter import install_image
                install_image(m,r.image_base)
                frame,rbp=_frame(r,0x178,'explicit normal registration ABI')
                callback=frame+16;active=frame+72
                m.store(active,r.image_base+0x433C478,8,source='explicit existing callback ABI')
                _String.construct(r,b'component callback').write_to(active+8)
                m.store(callback+32,active,8,source='explicit callback owner')
                receiver=_invoke(r,0xB75000,64);record=self.control(r,owners=0xFFFFFFFF)
                m.store(rbp+8,record+24,8,source='explicit caller shared value')
                gate=_invoke(r,0xBA21A0);self.assertNotEqual(receiver,gate)
                m.store(receiver+48,77,8,source='explicit original receiver counter')
                m.store(gate+48,123,8,source='explicit distinct gate counter')
                _normal_registration(r,receiver,record,callback,rbp)
                self.assertEqual(m.load(receiver+48,8),78);self.assertEqual(m.load(gate+48,8),123)
                self.assertEqual(m.load(record+128,8),77)
                self.assertEqual(m.load(m.load(gate+32,8)+32,8),77)
                self.assertEqual(m.load(record+8,4),0)
                self.assertEqual(m.read(rbp+0x88,16),bytes(16));self.assertEqual(r.locks[gate+56],1)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_manual_normal_admission_cannot_create_Client_authority(self):
        from qq_nt_replica.primary_client_configuration_scope import admit_normal
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime
            with creator(owner):
                before=list(r.memory.writes)
                with self.assertRaises(PrimarySemanticUnavailable):admit_normal(r,0,0,0,0,None,0,0,0)
                self.assertEqual(r.memory.writes,before)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_actual_scratch_initializer_order_tail_and_constant_read_failure(self):
        for failure in (False,True):
            with self.subTest(failure=failure),client_factory() as (owner,kernel,physical):
                r=owner.signer.runtime;m=r.memory
                with creator(owner):
                    frame,rbp=_frame(r,64,'explicit scratch ABI');before=len(m.writes)
                    if failure:
                        constant,offset=m._span(r.image_base+0x3FEED30,16)
                        constant.initialized[offset:offset+16]=bytes(16)  # controlled mask fault; readonly bytes untouched
                        before=len(m.writes)
                        with self.assertRaises(UnknownMemory):_invoke(r,0x1D04800,frame)
                        self.assertEqual([w[0] for w in m.writes[before:]],[frame+16])
                        with self.assertRaises(UnknownMemory):m.read(frame,16)
                    else:
                        self.assertIsNone(_invoke(r,0x1D04800,frame))
                        self.assertEqual([w[0] for w in m.writes[before:]],[frame+16,frame])
                        self.assertEqual(m.read(frame,16),bytes.fromhex('0123456789abcdeffedcba9876543210'))
                    self.assertEqual(m.read(frame+16,8),bytes(8))
                    with self.assertRaises(UnknownMemory):m.read(frame+24,8)
                with self.assertRaises(ExceptionGroup):owner.close()

    def test_empty_presend_returns_without_reading_invalid_manager_or_initializing_scratch(self):
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime
            with creator(owner):
                frame,rbp=_frame(r,24,'explicit empty input');_String.construct(r,b'').write_to(frame)
                self.assertIsNone(_invoke(r,0x1CE8160,0,0,frame,0,0))
                self.assertFalse(any(e[0]=='source.1CE81D6.1D04800' for e in r.events))
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_presend_real_children_keep_unknown_scratch_and_branch_effects(self):
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                manager=_invoke(r,0xB75000,64);m.write(manager,bytes(64),source='explicit manager branch ABI')
                m.store(manager+56,101,8,source='explicit manager count ABI')
                frame,rbp=_frame(r,0x178,'explicit presend caller');_String.construct(r,b'original').write_to(frame)
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'RVAc92ec4'):_invoke(r,0x1CE8160,manager,frame+24,frame,1234,7)
                event=next(e for e in reversed(r.events) if e[0]=='source.1CE8160.arguments');presend_rbp=event[-1]
                with self.assertRaises(UnknownMemory):m.read(presend_rbp-72,24)
                with self.assertRaises(UnknownMemory):m.read(presend_rbp+32,16)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_real_client_to_actual_presend_child(self):
        from qq_nt_replica.primary_client_configuration_startup import (
            _own_client_configuration_input as own, _run_client_configuration_component as run, getter)
        from qq_nt_replica.primary_logger import _String
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.errors import InputError
        from copy import copy
        from qq_nt_replica import primary_client_configuration_scope as client_scope
        from qq_nt_replica.primary_request_transport import _normal_registration
        probes=[]
        def physical_filetime(runtime):
            if client_scope._frame(_normal_registration.__code__,runtime) is not None:
                current=client_scope.current_request(runtime)
                normal=current.producer['normal_transport']
                self.assertIs(normal.validate(runtime),normal)
                before=list(runtime.memory.writes)
                with self.assertRaises(InputError):copy(normal).validate(runtime)
                probes.append('unissued receipt copy')
                for field in ('values','bindings'):
                    original=getattr(normal,field)
                    try:
                        setattr(normal,field,tuple(list(original)))
                        with self.assertRaises(InputError):normal.validate(runtime)
                    finally:setattr(normal,field,original)
                    probes.append('replaced '+field)
                region=normal.bindings[0][2];known=region.initialized
                try:
                    region.initialized=bytearray(known)
                    with self.assertRaises(InputError):normal.validate(runtime)
                finally:region.initialized=known
                probes.append('replaced known-map')
                epoch=current.image.epoch
                try:
                    current.image.epoch=object()
                    with self.assertRaises(InputError):normal.validate(runtime)
                finally:current.image.epoch=epoch
                probes.append('replaced epoch')
                try:
                    current.lease.suspended=True
                    with self.assertRaises(PrimarySemanticUnavailable):normal.validate(runtime)
                finally:current.lease.suspended=False
                probes.append('suspended lease')
                self.assertEqual(runtime.memory.writes,before)
            return 116444736000000000
        from test_primary_sdk_sender import observe_source_borrow
        borrow_observations=[]
        with observe_source_borrow(self,borrow_observations),source_threads(filetime=physical_filetime) as (owner,r,physical,bridge):
            with creator(owner):
                supplied=b'explicit-component-input-long-value'
                receipt=own(owner,supplied)
                self.assertEqual(receipt.origin,'MODEL_COMPONENT')
                self.assertIsNone(run(owner,receipt))
                self.assertTrue(receipt.frame['normal_return'])
                self.assertTrue(receipt.frame['bbb']['normal_return'])
                self.assertIsNone(r._client_session_log_pending)
                emitted=[event for event in r.events if event[0]=='source.D3A81F']
                self.assertEqual(emitted[-1][1:],(2,b'msf_security_sign_callback.cc',0x21,b'SetSessionId',b'[MSFSecuritySignCallback]->SetSessionId:'+supplied))
                self.assertEqual(r.memory.load(r.image_base+0x67535D0,4),2)
                for event in (e for e in r.events if e[0] in ('source.2F51.D3BE4F','source.3A60.D3BE4F')):
                    array,count=event[3],event[4]
                    for index in range(count):
                        slot=array+40*index
                        touched=set()
                        for address,raw,label in r.memory.writes:
                            if raw is not None:
                                touched.update(i-slot for i in range(max(slot,address),min(slot+40,address+len(raw))))
                        self.assertEqual(touched,set(range(8,16))|set(range(32,36)))
                self.assertEqual([event[1] for event in r.events if event[0]=='source.4CC9.normal_dtor'],[0x4D4C,0x4D55,0x4D5E])
                first=getter(r);second=getter(r,True)
                self.assertNotEqual(first,second)
                self.assertEqual(_String.read(r,first).value(),supplied)
                self.assertEqual(_String.read(r,second).value(),b'')
                self.assertNotEqual(r.memory.load(first+16,8),receipt.backing[0])
                header=receipt.frame['address']
                copied=[(address,raw) for address,raw,label in r.memory.writes
                        if raw is not None and address<=header+16 and header+24<=address+len(raw)]
                address,raw=copied[-1]
                copy_pointer=int.from_bytes(raw[header+16-address:header+24-address],'little')
                self.assertNotIn(copy_pointer,r._custom_allocator_backend.records)
                self.assertIn(receipt.backing[0],r._custom_allocator_backend.records)
                self.assertNotEqual(copy_pointer,r.memory.load(first+16,8))
                receiver=r.memory.load(r.image_base+0x6751AC0,8)
                self.assertNotEqual(receiver,0)
                from qq_nt_replica.primary_client_configuration_scope import validate_receiver
                validate_receiver(r,receiver)
                self.assertEqual(len({id(row) for row in physical.rows.values()}),1)
                port=r._client_source_srw
                self.assertEqual(port.state,'unheld')
                self.assertIsNone(port.pin)
                self.assertEqual([row['name'] for row in port.records],['AcquireSRWLockExclusive','ReleaseSRWLockExclusive'])
                self.assertIs(port.records[0]['token'],port.records[1]['token'])
                self.assertTrue(all(row['entered'] and row['returned'] and row['recorded'] and row['result'] is None for row in port.records))
                self.assertEqual([name for name,pointer,value in physical.srw_calls],['AcquireSRWLockExclusive','ReleaseSRWLockExclusive'])
                self.assertTrue(all(pointer!=r.image_base+0x6751830 for name,pointer,value in physical.srw_calls))
                state=r.memory.load(r.image_base+0x6751828,8)
                self.assertEqual(r.memory.read(state,3),b'\1\0\0')
                before=list(r.memory.writes)
                with self.assertRaises(InputError):run(owner,receipt)
                self.assertEqual(r.memory.writes,before)
            owner._threads._gate.set()
            startup=next(row for row in owner._threads._threads if row.get('_kind')=='client_startup')
            physical.join(startup['source_handle'])
            if startup['state']!='returned':
                import traceback
                self.fail(''.join(traceback.format_exception(owner._threads._failure)))
            child=next(row for row in owner._threads._secondary if row['_kind']=='client_loop')
            bridge.launches[0].gate.set()
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'1BE2FC1 IsBadCodePtr IAT4910108') as next_stop:
                try:
                    physical.join(bridge.launches[0].handle)
                except PrimarySemanticUnavailable as thrown:
                    # unittest clears captured tracebacks on context exit.
                    tb=thrown.__traceback__;source_invoke_args=None
                    while tb is not None:
                        values=tb.tb_frame.f_locals
                        if values.get('rva')==0x1BE2F90 and values.get('self') is r:
                            source_invoke_args=tuple(values['vm'].cells.value(i) for i in values['cells'])
                        tb=tb.tb_next
                    raise
            self.assertEqual(physical.capi_calls,[
                ('CryptAcquireContextW','private'),('CryptGenRandom','private'),('CryptReleaseContext','private'),
                ('CryptAcquireContextW','blinding'),('CryptGenRandom','blinding'),('CryptReleaseContext','blinding')])
            provider=r.request_capi
            self.assertIsNone(provider.first_error)
            self.assertTrue(all(row['entered'] and row['returned'] and row['recorded'] for row in provider.operations))
            self.assertTrue(all(not row['live'] for row in provider.handles))
            self.assertEqual(len(provider.tickets),1)
            self.assertFalse(provider.tickets[0].active)
            self.assertTrue(all(all(buffer._known) for buffer in provider.tickets[0].buffers.values()))
            self.assertFalse(provider.tickets[0].history.claim.active)
            self.assertIsNone(provider.tickets[0].history.claim.source)
            self.assertNotIn('requires the actual CAPI',str(next_stop.exception))
            print('controlled_owned_capi_next_stop '+str(next_stop.exception),flush=True)
            self.assertTrue(any(e[0]=='request.encoder_complete' for e in r.events))
            self.assertEqual(sum(e[0]=='source.1CE81D6.1D04800' for e in r.events),1)
            self.assertFalse(any(e[0]=='request.pending_dispatch' for e in r.events))
            self.assertFalse(any(label in ('request.sequence_advance','request.pending_key','request.pending_value',
                'request.pending_control','request.pending_owner_add') for address,raw,label in r.memory.writes))
            from qq_nt_replica.primary_client_configuration_scope import image_for
            producers=[issued for kind,issued in image_for(r).debts if kind=='producer']
            self.assertEqual(len(producers),1)
            self.assertTrue(producers[0]['claimed'])
            self.assertFalse(producers[0]['completed'])
            normal=producers[0]['normal_transport'];m=r.memory
            self.assertTrue(normal.lock_held);self.assertEqual(normal.phase,'sender')
            self.assertEqual(r.locks[normal.gate+56],1)
            receiver,record,callback,metadata,packet,call_frame,rbp,original=normal.values
            self.assertNotEqual(original,record+24)
            self.assertEqual(m.read(rbp+0x88,16),bytes(16))
            self.assertEqual(m.load(rbp+0x58,8),normal.node);self.assertEqual(m.load(rbp+0x60,1),1)
            self.assertEqual(m.load(normal.gate+40,8),1)
            with self.assertRaises(UnknownMemory):m.read(rbp+0x61,7)
            self.assertEqual(m.load(r.image_base+0x677D1C0,8),normal.manager)
            self.assertIn(normal.manager,r._constructed_request_managers)
            labels=[label for address,raw,label in m.writes]
            self.assertLess(labels.index('1CF41A0.count_publish'),labels.index('1CE7C8E.manager_zero64'))
            self.assertLess(labels.index('1CF3F0D.request_manager_tree_begin'),labels.index('1CE7CAD.manager_publish'))
            presend_frame,presend_rbp,manager,selected,actual_original,body,size=normal.presend
            self.assertEqual((selected,actual_original,body,size),(record+48,original,m.load(record+120,8),len(packet.value())))
            records_node,digest=normal.records
            self.assertEqual(_String.read(r,records_node+32).value(),digest)
            self.assertEqual(_String.read(r,records_node+56).value(),_String.read(r,original).value())
            self.assertEqual(digest,__import__('hashlib').md5(m.read(body,size)).digest())
            with self.assertRaises(UnknownMemory):m.read(records_node+50,6)
            target,args=normal.sender
            self.assertEqual(target,r.image_base+0x1BE2F90)
            self.assertEqual(args,(m.load(normal.gate+8,8),rbp-64,body,size,m.load(record+128,8)))
            self.assertEqual(_String.read(r,args[1]).value(),_String.read(r,record+48).value())
            self.assertNotEqual(m.load(args[1]+16,8),m.load(record+64,8))
            self.assertEqual(source_invoke_args,args)
            from qq_nt_replica import primary_client_configuration_scope as scope
            borrow=normal.sender_borrow;book=scope._SENDER_BORROWS[borrow]
            self.assertEqual(book['phase'],'failed');self.assertIs(book['failure'],next_stop.exception)
            self.assertIs(book['args'],args)
            self.assertEqual(borrow_observations,['entered','copied denied','foreign runtime denied','tuple cannot enter','journal nonauthority','fn/gate contents not revalidated'])
            probe_events=[e for e in r.events if e[0]=='source.1BE2FC1.probe_unavailable']
            self.assertEqual(probe_events,[('source.1BE2FC1.probe_unavailable',r.image_base+0x72B142,r.image_base+0x4910108)])
            with self.assertRaises(InputError):borrow.check(r)
            with self.assertRaises(InputError):__import__('copy').copy(borrow).check(r)
            self.assertFalse(any(name=='IsBadCodePtr' for name,*rest in physical.kernel.calls))

            erase=[(address,raw) for address,raw,label in m.writes if label.startswith('1D05590.erase') or label=='1D0590D.erase_QWORD']
            self.assertEqual([address for address,raw in erase[-6:]],[presend_rbp-72+offset for offset in (64,48,32,16,0,80)])
            self.assertTrue(all(raw==bytes(len(raw)) for address,raw in erase[-6:]))

            self.assertEqual(producers[0]['audit_exit'],dict(stage='complete',status_completed=True,
                status_wrapper_seen=True,material_wrapper_completed=True,material_used=False,normal_scope_return=True))
            observed=producers[0]['material_update_observed']
            self.assertEqual((observed['first']^observed['second'])&1,0)
            self.assertEqual(observed['target'],r.image_base+0x2DE8CAF)
            self.assertEqual((observed['seed_writes'],observed['index_writes']),(1,32))
            self.assertEqual(r.memory.load(child['task']+9,1),1)
            self.assertEqual(r.memory.load(child['task']+4,4),0)
            self.assertTrue(all(row['completed'] for row in child['direct_scope']['bootstrapPrograms']))
            self.assertFalse(any(e[0]=='configuration.native_sender_unavailable' for e in r.events))
            self.assertEqual(probes,['unissued receipt copy','replaced values','replaced bindings','replaced known-map','replaced epoch','suspended lease'])
            before=list(r.memory.writes)
            with self.assertRaises(PrimarySemanticUnavailable):normal.validate(r)
            self.assertEqual(r.memory.writes,before)
            with self.assertRaises(ExceptionGroup):owner.close()
        self.assertTrue(all(not row['thread'].is_alive() for row in physical.rows.values()))
        self.assertEqual(physical.cleanup[-1]['event'],'all_children_exited_before_fake_restore')
        self.assertFalse(physical.cleanup[-1]['aborted'])
        self.assertFalse(r.memory._layout_poisoned,getattr(r.memory,'_layout_first_escape',None))
        self.assertIsNone(getattr(r.memory,'_layout_first_escape',None))
        print('controlled_lookup_domain '+__import__('json').dumps(dict(
            fast_eligible=True,first_raw_escape=None,regions=len(r.memory._region_snapshot()))),flush=True)
        print('controlled_positive_terminal '+__import__('json').dumps(dict(
            joins=physical.joins,cleanup=physical.cleanup,live_children=0)),flush=True)
