"""Selected MODEL source-component checks, never natural SDK/application evidence."""
from contextlib import contextmanager
from copy import copy
import unittest

from test_primary_client_configuration_request import signer, source_threads


@contextmanager
def creator(owner):
    service = owner._threads
    service.before_public_operation()
    try:
        with owner._registrar.operation():
            with service._native_crt_context():
                yield
    finally:
        service.after_public_operation()


class StartupBirth(unittest.TestCase):
    def test_exact_fresh_objects_guards_and_unknown_neighbor_gaps(self):
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        from qq_nt_replica.primary_client_configuration_startup import validate_image
        owner = signer()
        r, m, b = owner.runtime, owner.memory, owner.image_base
        validate_image(r)
        for rva, size in ((0x674D230,24),(0x674D248,4),(0x674D280,24),(0x674D298,4),
                          (0x6D83BC8,24),(0x6D83BF0,24),(0x6D83C18,24)):
            region, offset = m._span(b+rva,size)
            self.assertEqual((region.address, len(region.data), offset),(b+rva,size,0))
            self.assertEqual(m.read(b+rva,size),bytes(size))
        for rva in (0x674D22F,0x674D24C,0x674D27F,0x674D29C):
            with self.assertRaises(PrimaryMemoryLimit):m.load(b+rva,1)

    def test_backing_epoch_and_repeat_are_rejected_without_guest_write(self):
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_client_configuration_startup import validate_image, install_fresh_globals
        owner=signer();r=owner.runtime;m=r.memory;b=r.image_base
        region,offset=m._span(b+0x674D230,24)
        replacement=type(region)(region.address,memoryview(bytearray(region.data)),bytearray(region.initialized),region.name)
        index=next(i for i,item in enumerate(m._regions) if item is region)
        before=list(m.writes)
        try:
            m._regions[index]=replacement
            with self.assertRaises(InputError):validate_image(r)
        finally:
            m._regions[index]=region;replacement.data.release()
        epoch=owner._shared_locale_image.epoch
        try:
            owner._shared_locale_image.epoch=object()
            with self.assertRaises(InputError):validate_image(r)
        finally:owner._shared_locale_image.epoch=epoch
        with self.assertRaises(InputError):install_fresh_globals(owner)
        self.assertEqual(m.writes,before)


class TypedComponent(unittest.TestCase):
    def test_distinct_getter_masks_warm_backing_and_actual_metadata_zero_character(self):
        from qq_nt_replica.primary_client_configuration_startup import _own_client_configuration_input as own, getter
        from qq_nt_replica.primary_logger import _String
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_worker_loop import _initialize
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                first,second=getter(r),getter(r,True)
                region,offset=r.memory._span(first,24)
                self.assertEqual(bytes(region.initialized[offset:offset+24]),bytes([1])*24)
                region,offset=r.memory._span(second,24)
                self.assertEqual(bytes(region.initialized[offset:offset+24]),bytes([1,1])+bytes(22))
                receipt=own(owner,b'actual-second-global-long-current-input')
                _invoke(r,0x75CEC0,second,receipt.header)
                pointer=r.memory.load(second+16,8)
                before=list(r.memory.writes)
                self.assertEqual(getter(r,True),second)
                self.assertEqual(r.memory.load(second+16,8),pointer)
                self.assertEqual(r.memory.writes,before)
                self.assertEqual(_String.read(r,first).value(),b'')
                self.assertEqual(_String.read(r,second).value(),b'actual-second-global-long-current-input')
                _initialize(r,1)
                self.assertEqual(_String.read(r,r.image_base+0x67516B8).value(),b'0')
                self.assertEqual(r.memory.read(r.image_base+0x67516B8,3),b'\x02\x30\0')
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_input_only_debt_blocks_none_foreign_owner_before_any_retirement(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from qq_nt_replica.primary_client_configuration_startup import _own_client_configuration_input as own
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.errors import InputError
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):receipt=own(owner,b'input exists before setter and threads')
            self.assertIsNone(receipt.frame)
            self.assertEqual(r.memory.load(r.image_base+0x6751AC0,8),0)
            self.assertEqual(physical.rows,{})
            service=owner._threads
            for obj,name,value in ((owner,'_signer',None),(owner,'_threads',None),
                                   (owner.signer,'runtime',SimpleNamespace()),(owner,'_registrar',object())):
                before=list(physical.kernel.calls)
                with self.subTest(name=name),patch.object(obj,name,value),patch.object(service,'prepare_close',side_effect=AssertionError('retirement tripwire')):
                    errors=owner._release_resources()
                    self.assertEqual(len(errors),1)
                    self.assertIsInstance(errors[0],(InputError,PrimarySemanticUnavailable))
                self.assertEqual(physical.kernel.calls,before)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_full_selected_entry_receiver_thread_and_first_request_boundary(self):
        from qq_nt_replica.primary_client_configuration_startup import (
            _own_client_configuration_input as own, _run_client_configuration_component as run, getter)
        from qq_nt_replica.primary_logger import _String
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.errors import InputError
        with source_threads() as (owner,r,physical,bridge):
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
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'client configured transport requires recovered source admission') as next_stop:
                physical.join(bridge.launches[0].handle)
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
            self.assertEqual(sum(e[0]=='configuration.configured_transport_unavailable' for e in r.events),1)
            self.assertFalse(any(e[0]=='request.pending_dispatch' for e in r.events))
            self.assertFalse(any(label in ('request.sequence_advance','request.pending_key','request.pending_value',
                'request.pending_control','request.pending_owner_add') for address,raw,label in r.memory.writes))
            from qq_nt_replica.primary_client_configuration_scope import image_for
            producers=[issued for kind,issued in image_for(r).debts if kind=='producer']
            self.assertEqual(len(producers),1)
            self.assertTrue(producers[0]['claimed'])
            self.assertFalse(producers[0]['completed'])
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

    def test_unissued_input_and_changed_mask_do_not_reach_source(self):
        from qq_nt_replica.primary_client_configuration_startup import (
            _own_client_configuration_input as own, _run_client_configuration_component as run)
        from qq_nt_replica.errors import InputError
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                receipt=own(owner,b'')
                before=list(r.memory.writes)
                for foreign in (None,receipt.header,copy(receipt)):
                    with self.assertRaises(InputError):run(owner,foreign)
                self.assertEqual(r.memory.writes,before)
                receipt.region.initialized[3]=1
                with self.assertRaises(InputError):run(owner,receipt)
                self.assertEqual(r.memory.writes,before)
                self.assertFalse(receipt.used)
            self.assertEqual(physical.rows,{})
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_original_upper_allocation_record_cannot_be_replaced_by_equal_fields(self):
        from qq_nt_replica.primary_client_configuration_startup import (
            _own_client_configuration_input as own,_run_client_configuration_component as run)
        from qq_nt_replica.errors import InputError
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                receipt=own(owner,b'long independent upper allocation receipt identity')
                pointer,record=receipt.storage_records[0]
                backend=r._custom_allocator_backend
                replacement=tuple(list(record))
                self.assertEqual(replacement,record);self.assertIsNot(replacement,record)
                before=list(r.memory.writes)
                try:
                    backend.records[pointer]=replacement
                    with self.assertRaisesRegex(InputError,'allocation receipt changed'):run(owner,receipt)
                    self.assertEqual(r.memory.writes,before)
                    self.assertFalse(receipt.used)
                    self.assertEqual(physical.rows,{})
                finally:backend.records[pointer]=record
            with self.assertRaises(ExceptionGroup):owner.close()


class SessionLogger(unittest.TestCase):
    def prepare(self,owner,r):
        from qq_nt_replica.primary_client_configuration_startup import _own_client_configuration_input as own, _SESSION_FILE
        from qq_nt_replica.primary_worker_response import _frame
        from qq_nt_replica.primary_worker_consumer import _invoke
        receipt=own(owner,b'independent-long-String-for-formatting-lifetime')
        copy,unused=_frame(r,24,'controlled actual 75B810 caller owning copy')
        _invoke(r,0x75B810,copy,receipt.header)
        b=r.image_base
        arguments=(b+0x3F6DE00,2,b+0x486ABAA+_SESSION_FILE.rfind(b'\\')+1,
                   0x21,b+0x4849C07,b+0x46629B0,copy)
        return receipt,copy,arguments

    def test_false_gate_consumes_only_caller_copy_once(self):
        from qq_nt_replica.primary_native_logger import enabled
        from qq_nt_replica.primary_worker_consumer import _invoke
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                receipt,copy,arguments=self.prepare(owner,r)
                enabled(r,2)
                r.memory.store(r.image_base+0x67535D0,3,4,source='explicit MODEL logging threshold input')
                copied=r.memory.load(copy+16,8)
                _invoke(r,0x4CC9,*arguments)
                self.assertNotIn(copied,r._custom_allocator_backend.records)
                self.assertIn(receipt.backing[0],r._custom_allocator_backend.records)
                self.assertIsNone(r._client_session_log_pending)
                self.assertEqual([event[1] for event in r.events if event[0]=='source.4CC9.normal_dtor'],[0x4D5E])
                self.assertFalse(any(event[0]=='source.D3A81F' for event in r.events))
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_unknown_formatter_argument_keeps_partial_output_variant_and_owning_copy(self):
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_logger import _String
        from qq_nt_replica.primary_memory import UnknownMemory
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                receipt,copy,arguments=self.prepare(owner,r)
                copied=r.memory.load(copy+16,8)
                r.memory.forget(copied,1,source='controlled unavailable CString payload')
                with self.assertRaises(UnknownMemory):_invoke(r,0x4CC9,*arguments)
                pending=r._client_session_log_pending
                self.assertEqual(pending['stage'],'4D16')
                self.assertEqual(_String.read(r,pending['rbp']-0x40).value(),b'SetSessionId:')
                array=pending['one_adapter']
                self.assertEqual(r.memory.load(array+8,8),copied)
                self.assertEqual(r.memory.load(array+0x20,4),11)
                region,offset=r.memory._span(array,40)
                self.assertEqual(bytes(region.initialized[offset:offset+40]),bytes(int(i in set(range(8,16))|set(range(32,36))) for i in range(40)))
                self.assertIn(copied,r._custom_allocator_backend.records)
                self.assertFalse(any(e[0]=='source.4CC9.normal_dtor' for e in r.events))
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_unavailable_sink_preserves_both_formatted_values_and_input_copy(self):
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_logger import _String
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                receipt,copy,arguments=self.prepare(owner,r)
                r.memory.store(r.image_base+0x6753528,0x1234,8,source='explicit MODEL nonempty D3 filter input')
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'D3AB8F'):_invoke(r,0x4CC9,*arguments)
                pending=r._client_session_log_pending
                self.assertEqual(pending['stage'],'4D43')
                first=_String.read(r,pending['rbp']-0x40)
                final=_String.read(r,pending['rbp']-0x28)
                self.assertEqual(first.value(),b'SetSessionId:independent-long-String-for-formatting-lifetime')
                self.assertEqual(final.value(),b'[MSFSecuritySignCallback]->'+first.value())
                self.assertIn(r.memory.load(copy+16,8),r._custom_allocator_backend.records)
                self.assertIn(first.get(16,8),r._custom_allocator_backend.records)
                self.assertIn(final.get(16,8),r._custom_allocator_backend.records)
                self.assertFalse(any(e[0]=='source.4CC9.normal_dtor' for e in r.events))
            with self.assertRaises(ExceptionGroup):owner.close()


class SourceFunctors(unittest.TestCase):
    def test_unqualified_receiver_is_rejected_before_client_status_material_or_ctor_vm(self):
        from qq_nt_replica.primary_client_configuration_startup import _own_client_configuration_input as own
        from qq_nt_replica.primary_client_configuration_scope import image_for
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from test_primary_client_configuration_request import start_component
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                own(owner,b'bare callback context cannot become positive client origin')
                _invoke(r,0xB9E850,r.image_base+0x72B142)
            startup=start_component(owner,r)
            physical.join(startup['source_handle'])
            if startup['state']!='returned':
                import traceback
                self.fail(''.join(traceback.format_exception(owner._threads._failure)))
            child=next(row for row in owner._threads._secondary if row['_kind']=='client_loop')
            before=len(r.vms)
            bridge.launches[0].gate.set()
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'completed literal 72B103/72B10A'):
                physical.join(bridge.launches[0].handle)
            self.assertEqual(len(r.vms),before)
            producers=[issued for item in image_for(r).debts if type(item) is tuple and len(item)==2 for kind,issued in (item,) if kind=='producer']
            self.assertEqual(len(producers),1)
            self.assertFalse(producers[0]['claimed'])
            self.assertFalse(producers[0]['completed'])
            self.assertEqual(r.memory.load(child['task']+9,1),1)
            self.assertEqual(r.memory.read(r.image_base+0x6D85F60,72),bytes(72))
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_bare_literal_callback_setter_publishes_but_cannot_qualify_client(self):
        from qq_nt_replica.primary_client_configuration_startup import _own_client_configuration_input as own
        from qq_nt_replica.primary_client_configuration_scope import validate_receiver
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.primary_logger import _String
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                receipt=own(owner,b'explicit input is not the actual 72B10A source frame')
                m,b=r.memory,r.image_base
                before=len(m.writes)
                _invoke(r,0xB9E850,b+0x72B142)
                pointer,control=m.load(b+0x6751AC0,8),m.load(b+0x6751AC8,8)
                self.assertEqual(pointer,control+24)
                self.assertEqual(m.load(pointer+8,8),b+0x72B142)
                self.assertEqual(m.load(control+8,4),0)
                self.assertEqual(_String.read(r,b+0x67516B8).value(),b'0')
                self.assertEqual(m.load(b+0x6751800,4)&1,1)
                labels=[label for address,raw,label in m.writes[before:]]
                self.assertLess(labels.index('B9F108.metadata_guard_claim'),labels.index('1CE2BEA.receiver_pointer'))
                self.assertLess(labels.index('1CE2BEA.receiver_pointer'),labels.index('1CE2BF2.receiver_control'))
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'completed literal 72B103/72B10A'):
                    validate_receiver(r,pointer)
                self.assertEqual(physical.rows,{})
                self.assertIsNone(receipt.frame)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_three_real_cold_swaps_preserve_padding_and_publish_in_order(self):
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_memory import UnknownMemory
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                m,b=r.memory,r.image_base
                before=len(m.writes)
                _invoke(r,0x2C5C7F0)
                writes=m.writes[before:]
                publications=[]
                for offset,vt,fn in ((0x6D83BC8,0x433B1F8,0x2C5C8F0),
                                     (0x6D83BF0,0x433B1F8,0x2C5C9A0),
                                     (0x6D83C18,0x433B2E8,0xB8E60)):
                    address=b+offset
                    self.assertEqual((m.load(address,8),m.load(address+8,8),m.load(address+24,8)),
                                     (b+vt,b+fn,address))
                    self.assertEqual(m.read(address+16,8),bytes(8))
                    self.assertFalse(any(p<address+24 and address+16<p+len(raw) for p,raw,label in writes))
                    pub=next(i for i,(p,raw,label) in enumerate(writes) if p==address+24)
                    copy_index=next(i for i,(p,raw,label) in enumerate(writes) if p==address+8)
                    self.assertLess(copy_index,pub);publications.append(pub)
                self.assertEqual(publications,sorted(publications))
                self.assertEqual(m.load(b+0x6751800,4),0)
                self.assertEqual(m.load(b+0x6751B30,4),0)
                self.assertEqual(physical.rows,{})


class UpdateInfo(unittest.TestCase):
    def test_real_zero_length_compare_repeated_branch_never_reads_unknown_struct_fields(self):
        from qq_nt_replica.primary_client_configuration_startup import _metadata_cold, getter, _own_client_configuration_input as own
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_worker_response import _frame
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                own(owner,b'explicit component debt before BBA ABI test')
                _metadata_cold(r)
                second=getter(r,True)
                record,unused=_frame(r,40,'controlled BBA pointer-struct ABI input')
                r.memory.store(record+0x18,second+1,8,source='controlled actual original uin CString ABI slot')
                region,offset=r.memory._span(record,40)
                original=(bytes(region.data),bytes(region.initialized))
                self.assertIsNone(_invoke(r,0xBBA000,record))
                self.assertIn(('source.BBA000.normal_repeated_return',record,0xBBB233),r.events)
                self.assertEqual((bytes(region.data),bytes(region.initialized)),original)
                self.assertEqual(bytes(region.initialized),bytes(int(0x18<=i<0x20) for i in range(40)))
                other=own(owner,b'a')
                r.memory.store(record+0x18,other.header+1,8,source='controlled different CString ABI input')
                original=(bytes(region.data),bytes(region.initialized))
                before=len([e for e in r.events if e[0]=='source.BBA000.normal_repeated_return'])
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'nonzero 75CB20'):_invoke(r,0xBBA000,record)
                self.assertEqual((bytes(region.data),bytes(region.initialized)),original)
                self.assertEqual(len([e for e in r.events if e[0]=='source.BBA000.normal_repeated_return']),before)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_compare_uses_strlen_first_and_nzero_three_way_result_without_default_memcmp(self):
        from qq_nt_replica.primary_client_configuration_startup import getter, _own_client_configuration_input as own
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_memory import UnknownMemory
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                empty=getter(r,True);one=own(owner,b'a')
                self.assertEqual(_invoke(r,0x75CB20,empty,empty+1),0)
                self.assertEqual(_invoke(r,0x75CB20,one.header,empty+1),1)
                self.assertEqual(_invoke(r,0x75CB20,empty,one.header+1),-1)
                before=list(r.memory.writes)
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'75CB92 -> 3EB1EE0'):
                    _invoke(r,0x75CB20,one.header,one.header+1)
                self.assertEqual(r.memory.writes,before)
                r.memory.forget(one.header+1,1,source='controlled unknown CString payload')
                with self.assertRaises(UnknownMemory):_invoke(r,0x75CB20,0xDEADBEEF,one.header+1)
            with self.assertRaises(ExceptionGroup):owner.close()


class SourceSRW(unittest.TestCase):
    def test_api_and_record_failures_retain_first_error_pin_publication_and_retirement_barrier(self):
        from unittest.mock import patch
        from qq_nt_replica.primary_client_configuration_startup import (
            _own_client_configuration_input as own,_run_client_configuration_component as run)
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        for direction,phase in (('Acquire','api'),('Release','api'),('Acquire','record'),('Release','record')):
            with self.subTest(direction=direction,phase=phase),source_threads() as (owner,r,physical,bridge):
                failure=RuntimeError('controlled '+direction+' '+phase+' failure')
                def physical_call(name,cell):
                    if phase=='api' and name.startswith(direction):
                        cell.value=0xABCDEF  # A physical partial effect, never guessed production SRW bits.
                        raise failure
                physical.on_srw=physical_call
                record=r.memory._record_native_write
                def bookkeeping(token,issuer,*,source):
                    if phase=='record' and source.startswith(direction):raise failure
                    return record(token,issuer,source=source)
                with creator(owner):
                    receipt=own(owner,b'original explicit MODEL input retained across SourceSRW failure')
                    with patch.object(r.memory,'_record_native_write',side_effect=bookkeeping):
                        with self.assertRaises(RuntimeError) as actual:run(owner,receipt)
                    self.assertIs(actual.exception,failure)
                    port=r._client_source_srw
                    self.assertIs(port.failures[0][2],failure)
                    self.assertFalse(port.active)
                    self.assertIsNotNone(port.pin)
                    last=port.records[-1]
                    self.assertTrue(last['entered'])
                    self.assertEqual((last['returned'],last['recorded']),(phase=='record',phase=='api'))
                    self.assertEqual(port.state,('acquire_unknown' if direction=='Acquire' else 'release_unknown') if phase=='api' else ('held' if direction=='Acquire' else 'unheld'))
                    expected=['AcquireSRWLockExclusive']+(['ReleaseSRWLockExclusive'] if direction=='Release' else [])
                    self.assertEqual([name for name,pointer,old in physical.srw_calls],expected)
                    pointer=r.memory.load(r.image_base+0x6751828,8)
                    if direction=='Acquire':self.assertEqual(pointer,0)
                    else:self.assertEqual(r.memory.read(pointer,3),bytes(3))
                    self.assertNotIn('normal_return',receipt.frame)
                    self.assertNotIn('normal_return',receipt.frame['bbb'])
                    self.assertEqual(physical.rows,{})
                    with self.assertRaises(PrimaryMemoryLimit):r.memory._assert_no_native_pin(r.image_base+0x67516B0,848)
                    before=list(r.memory.writes);calls=list(physical.srw_calls)
                    with self.assertRaises(InputError):run(owner,receipt)
                    self.assertEqual(r.memory.writes,before);self.assertEqual(physical.srw_calls,calls)
                service=owner._threads
                for obj,name,value in ((owner,'_signer',None),(owner,'_threads',None),(r,'_shared_locale_source_epoch',object())):
                    before=list(physical.kernel.calls);calls=list(physical.srw_calls)
                    with patch.object(obj,name,value),patch.object(service,'prepare_close',side_effect=AssertionError('dangerous retirement')):
                        errors=owner._release_resources()
                        self.assertEqual(len(errors),1)
                        self.assertIsInstance(errors[0],(InputError,PrimarySemanticUnavailable))
                    self.assertEqual(physical.kernel.calls,before);self.assertEqual(physical.srw_calls,calls)
                with self.assertRaises(ExceptionGroup):owner.close()

    def test_source_issuer_denies_raw_srw_before_api_and_atomic_exchange_only_changes_one_byte(self):
        from qq_nt_replica.primary_client_configuration_startup import _own_client_configuration_input as own
        from qq_nt_replica.primary_worker_consumer import _invoke
        from qq_nt_replica.primary_memory import UnknownMemory
        from qq_nt_replica.errors import InputError
        with source_threads() as (owner,r,physical,bridge):
            with creator(owner):
                own(owner,b'explicit atomic-byte and source-port ABI component')
                before=list(r.memory.writes)
                with self.assertRaises(InputError):_invoke(r,0x75AF50,r.image_base+0x6751830)
                self.assertEqual(r.memory.writes,before)
                self.assertEqual(physical.srw_calls,[])
                self.assertFalse(hasattr(r,'_client_source_srw'))
                gate=_invoke(r,0xBA21A0)
                r.memory.write(gate,b'\xA5\x5A\xC3\x3C',source='controlled current gate bytes')
                before=len(r.memory.writes)
                self.assertIsNone(_invoke(r,0x1CE2BC0,gate,0x1234))
                self.assertEqual(r.memory.read(gate,4),b'\x34\x5A\xC3\x3C')
                self.assertEqual(r.memory.writes[before:],[(gate,b'\x34','1CE2BC0.XCHG_BYTE')])
                self.assertIn(('source.1CE2BC0.DL_exchange',gate,0xA5,0x34),r.events)
                before=list(r.memory.writes)
                with self.assertRaises(InputError):_invoke(r,0x1CE2BC0,gate+1,1)
                self.assertEqual(r.memory.writes,before)
                r.memory.forget(gate,1,source='controlled unknown prior XCHG byte')
                before=list(r.memory.writes)
                with self.assertRaises(UnknownMemory):_invoke(r,0x1CE2BC0,gate,1)
                self.assertEqual(r.memory.writes,before)
            with self.assertRaises(ExceptionGroup):owner.close()


class InitializerStage(unittest.TestCase):
    def test_factory_executes_full_selected_ctor_with_actual_seven_exit_records(self):
        from test_primary_client_configuration_request import client_factory
        from qq_nt_replica.primary_client_configuration_startup import require_request_stage,run_request_model_stage
        from qq_nt_replica.primary_logger import _String,_Tree
        from qq_nt_replica.primary_request_transport import _COMMANDS
        from qq_nt_replica.errors import InputError
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime;b=r.image_base;m=r.memory
            stage=require_request_stage(r)
            self.assertEqual(stage['origin'],'MODEL_SOURCE_SELECTED_INIT_STAGE')
            self.assertEqual((stage['slot'],stage['target']),(b+0x4909ED8,b+0x1CF4360))
            self.assertFalse(stage['lease'].active)
            self.assertTrue(stage['constructor']['normal_return'])
            expected=[b+x for x in (0x1C54B50,0x1C54B70,0x1C54B80,0x1CE2AF0,0x1CE2B10,0x1CE2B30,0x1CE2B50)]
            rows=stage['constructor']['registrations']
            self.assertEqual([row['callback'] for row in rows],expected)
            self.assertTrue(all(row['returned'] and row['result']==0 and
                any(entry is row['registered_record'] for entry in owner._registrar._records) for row in rows))
            self.assertEqual(stage['untracked'],[])
            self.assertEqual(m.load(b+0x677D040,8),6)
            self.assertEqual(len(list(_Tree(r,b+0x677D030).nodes())),6)
            self.assertIn(b+0x677D048,r.locks)
            self.assertIn(('InitializeCriticalSection',b+0x677D048),r.events)
            self.assertEqual(m.read(b+0x677D070,24),bytes(24))
            values=[_String.read(r,b+0x677D160+24*i) for i in range(4)]
            self.assertEqual(tuple(value.value() for value in values),_COMMANDS)
            self.assertEqual(len({value.get(16,8) for value in values}),4)
            self.assertEqual(physical.rows,{})
            before=list(m.writes)
            with self.assertRaises(InputError):run_request_model_stage(owner)
            self.assertEqual(m.writes,before)
            token=r._client_request_init_receipt
            try:
                r._client_request_init_receipt=object()
                with self.assertRaises(Exception):require_request_stage(r)
            finally:r._client_request_init_receipt=token

    def test_unchecked_minus_one_still_finishes_ctor_but_retains_unregistered_debt(self):
        from test_primary_client_configuration_request import client_factory
        from qq_nt_replica.primary_client_configuration_startup import require_request_stage
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with client_factory(registration_failure=lambda n,registrar,callback:-1 if n==2 else None) as (owner,kernel,physical):
            r=owner.signer.runtime;stage=require_request_stage(r)
            self.assertEqual(stage['state'],'complete')
            rows=stage['constructor']['registrations']
            self.assertEqual(len(rows),7)
            self.assertTrue(all(row['returned'] for row in rows))
            self.assertEqual(rows[1]['result'],0xFFFFFFFF)
            self.assertIsNone(rows[1]['registered_record'])
            self.assertEqual(stage['untracked'],[rows[1]])
            self.assertEqual(len([row for row in rows if row['registered_record'] is not None]),6)
            self.assertEqual(r.memory.load(r.image_base+0x677D040,8),6)
            self.assertIn(r.image_base+0x677D048,r.locks)
            self.assertTrue(stage['constructor']['normal_return'])
            errors=owner._release_resources()
            self.assertEqual(len(errors),1)
            self.assertIsInstance(errors[0],PrimarySemanticUnavailable)
            self.assertEqual(physical.rows,{})

    def test_registration_exception_retains_first_error_partial_cs_and_no_completion(self):
        from test_primary_client_configuration_request import client_factory
        from qq_nt_replica.primary_client_configuration_startup import _INIT_ACTIVE,_INIT_STAGES
        failure=RuntimeError('controlled selected-stage second registration exception');captured=[]
        def register(n,registrar,callback):
            if n==2:
                captured.append(_INIT_ACTIVE[registrar._runtime]['owner'])
                raise failure
        with self.assertRaises(BaseExceptionGroup):
            with client_factory(registration_failure=register):self.fail('constructor must not return')
        self.assertEqual(len(captured),1)
        owner=captured[0];r=owner.signer.runtime;stage=_INIT_STAGES[owner]
        self.assertEqual(stage['state'],'failed')
        self.assertIs(stage['first_error'],failure)
        self.assertIsNone(stage['receipt'])
        self.assertFalse(stage['constructor']['normal_return'])
        self.assertEqual(len(stage['constructor']['registrations']),2)
        self.assertTrue(stage['constructor']['registrations'][0]['returned'])
        self.assertFalse(stage['constructor']['registrations'][1]['returned'])
        self.assertIn(r.image_base+0x677D048,r.locks)
        self.assertNotIn('1CF4DB2.request_archive_vector',[label for address,raw,label in r.memory.writes])
        self.assertEqual(owner._threads._threads,[])

    def test_public_legacy_constructor_cannot_replace_private_stage_completion(self):
        from test_primary_client_configuration_request import client_factory
        from qq_nt_replica.primary_client_configuration_startup import require_request_stage,_INIT_ATTEMPTS
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with client_factory() as (owner,kernel,physical):
            r=owner.signer.runtime;original=require_request_stage(r);receipt=original['receipt']
            with creator(owner):
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'already initialized'):
                    owner.signer.initialize_requests()
                self.assertIs(r._client_request_init_receipt,receipt)
                self.assertEqual(len(_INIT_ATTEMPTS[r]),2)
                self.assertIsNone(_INIT_ATTEMPTS[r][1]['private_stage'])
                with self.assertRaises(PrimarySemanticUnavailable):require_request_stage(r)
            with self.assertRaises(ExceptionGroup):owner.close()


if __name__=='__main__':unittest.main()
