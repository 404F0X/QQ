"""Controlled original-input/record source prefix; native DLL loading forbidden."""
import copy,unittest
from unittest.mock import patch
from test_primary_mmkv_file import connected


class Record(unittest.TestCase):
    def test_source_optional_masks_long_copycopy_move_and_same_persistent_input(self):
        from qq_nt_replica.primary_logger import _String
        for label,appid in (('missing',None),('null',None),('empty',''),('long','id'*30),('utf8','id-'+chr(0x8d26)*20)):
            issued=[]
            def instrument(functions,r,calls):
                case=self
                class Events(list):
                    def append(self,item):
                        super().append(item)
                        if item[0]=='source.D4F840.original_input':
                            q=r._login_input_pending;m=r.memory;p=q.input;region,off=m._span(p,0xa1)
                            mask=bytes(region.initialized[off+0x78:off+0xa1]);issued.append((q,p,mask))
                            case.assertEqual(m.load(p+0x90,1),int(appid is not None));case.assertEqual(m.load(p+0xa0,1),0)
                            if appid is None:case.assertEqual(mask,bytes([1])+bytes(23)+bytes([1])+bytes(15)+bytes([1]))
                            else:
                                case.assertEqual(_String.read(r,p+0x78).value(),appid.encode())
                                case.assertEqual(m.read(q.arg7,24),bytes(24));case.assertEqual(m.load(q.arg7+24,1),1)
                            if appid:
                                copied=[w for w in m.writes if w[2]=='logger.string_payload' and w[1]==appid.encode()+b'\0']
                                # Source75B810 adds independent payloads through its own write labels.
                                ptr=_String.read(r,p+0x78).get(16,8)
                                case.assertNotEqual(ptr,_String.read(r,q.converted_appid).get(16,8))
                                case.assertNotEqual(ptr,_String.read(r,q.optional).get(16,8))
                r.events=Events(r.events);return functions
            extra={} if label=='missing' else {'appid':appid}
            with self.subTest(case=label),connected({'config_extra':extra},transform=instrument) as (e,port):
                r=e['runtime'];m=r.memory;q,p,mask=issued[0];record=r._login_msf_record_pending
                self.assertIs(record['input'],q);self.assertEqual(port._WindowsMMKVHost__open['boundary'],0x72ec24)
                self.assertEqual(_String.read(r,record['record']+0x2a8).value(),b'' if appid is None else appid.encode())
                self.assertEqual(m.load(q.login+0x190,1),int(appid is not None));self.assertEqual(m.load(q.login+0x1a0,1),0)
                if appid:self.assertNotEqual(_String.read(r,q.login+0x178).get(16,8),_String.read(r,p+0x78).get(16,8))
                self.assertEqual([x[1] for x in r.events if x[0]=='source.6C4A20.same_input'],[p])

    def test_unsupported_present_and_unknown_boolean_keep_producer_effects(self):
        cases=({'appid':7},{'externalVersion':None})
        for extra in cases:
            expected='present appid' if 'appid' in extra else 'explicit supported known Boolean'
            with self.subTest(extra=extra),connected({'config_extra':extra,'early_input_failure':True,'expected_error':expected}) as (e,port):
                r=e['runtime'];q=r._login_input_pending;m=r.memory
                self.assertEqual(q.phase,'converting');self.assertEqual(m.load(q.optional+24,1),0)
                self.assertFalse(hasattr(r,'_ordinary_msf_pair_moved'))
                self.assertFalse([x for x in r.events if x[0]=='source.D4F840.original_input'])

    def test_receipt_instance_owner_epoch_scope_and_backing_refuse_without_writes(self):
        from qq_nt_replica.primary_login_msf_record import validate
        from qq_nt_replica.errors import InputError
        checks=[]
        def instrument(functions,r,calls):
            case=self
            class Events(list):
                def append(self,item):
                    super().append(item)
                    if item[0]=='source.D4F840.original_input':
                        q=r._login_input_pending;m=r.memory;case.assertIs(validate(r,q.login,q),q)
                        before=len(m.writes)
                        with case.assertRaises(InputError):validate(r,q.login,copy.copy(q))
                        with case.assertRaises(InputError):q.input=q.input+8
                        for obj,name,value in ((r,'image_base',r.image_base+8),(r,'_shared_locale_source_epoch',object()),(q.image,'epoch',object()),(q.allocator.source,'epoch',object()),(q.owner,'_signer',object()),(q.service,'_LoginService__owner',object()),(q.service,'_LoginService__control',q.control+8)):
                            with patch.object(obj,name,value):
                                with case.assertRaises(InputError):validate(r,q.login,q)
                        region,off=m._span(q.input,0xa1);old=region.data;other=memoryview(bytearray(old))
                        try:
                            region.data=other
                            with case.assertRaises(InputError):validate(r,q.login,q)
                        finally:region.data=old;other.release()
                        case.assertEqual(len(m.writes),before);checks.append(True)
            r.events=Events(r.events);return functions
        with connected(transform=instrument) as (e,port):
            r=e['runtime'];self.assertEqual(checks,[True]);q=r._login_input_pending
            with self.assertRaises(InputError):validate(r,q.login,q)

    def test_actual_record_masks_copies_weak_alias_and_virtual_arguments_retained(self):
        from qq_nt_replica.primary_logger import _String
        from qq_nt_replica.primary_memory import UnknownMemory
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;z=r._login_msf_record_pending;p=z['record'];q=z['input'];login=q.login
            self.assertEqual([_String.read(r,p+x).value() for x in (0x58,0x40,0x140)],[b'C:\\data\\nt_data',b'C:\\data\\nt_data',b'machine'])
            for offset in (0xa1,0xb9,0x329,0x10):
                with self.assertRaises(UnknownMemory):m.read(p+offset,1)
            self.assertEqual(m.load(p+0x328,1),1);self.assertEqual(m.load(p+0x1c8,4),0xffffffff)
            order=[w[0]-p for w in m.writes if w[2]=='29D9E.zero16_order'];self.assertEqual(order,[0x2e0,0x2d0,0x2c0])
            self.assertEqual((m.load(z['pair'],8),m.load(z['pair']+8,8)),(login+0x18,q.control))
            self.assertEqual(z['args'],(m.load(login+0x90,8),z['pair'],p));self.assertEqual(z['target'],r.image_base+0x72ec24)
            self.assertEqual(m.load(q.control+8,4),1) # global plus moved alias owner; wrapper already released by fixture.
            self.assertFalse([x for x in r.events if x[0] in ('source.1A51A','source.6C4A88')])
            before=e['file_api'].calls[:]
            with patch.object(e['owner']._threads,'prepare_close',side_effect=AssertionError('unsafe retire')):
                with self.assertRaises(ExceptionGroup):e['owner'].close()
            self.assertEqual(before,e['file_api'].calls);self.assertFalse(r._custom_allocator_backend.closed)

    def test_missing_boolean_is_not_default_false(self):
        value=dict(commonPath='C:\\data',clientVer='v',machineId='machine',platVer='p',hostName='h')
        with connected({'config_input':value,'early_input_failure':True,'expected_error':'no missing default'}) as (e,port):
            q=e['runtime']._login_input_pending
            self.assertEqual(q.phase,'converting');self.assertFalse(hasattr(e['runtime'],'_ordinary_msf_pair_moved'))
            from qq_nt_replica.primary_memory import UnknownMemory
            self.assertEqual(e['runtime'].memory.load(q.boolean_local,1),0)
            with self.assertRaises(UnknownMemory):e['runtime'].memory.read(q.arg7,1)

    def test_actual_weak_cas_failure_retry_live_zero_overflow_and_expired_throw(self):
        for initial in (0,0xfffffffe,0xffffffff):
            def instrument(functions,r,calls):
                store=r.memory.store;load=r.memory.load;armed=[];loads=[]
                def actual_store(address,value,size,**kw):
                    result=store(address,value,size,**kw)
                    if kw.get('source')=='46453.weak_object_first':
                        q=r._login_input_pending;store(q.control+8,initial,4,source='controlled weak count at actual helper entry');armed.append(q.control+8)
                    return result
                def actual_load(address,size,**kw):
                    value=load(address,size,**kw)
                    if armed and address==armed[0] and size==4 and initial==0:
                        loads.append(value)
                        if len(loads)==1:store(address,7,4,source='controlled race after first EAX load')
                    return value
                r.memory.store=actual_store;r.memory.load=actual_load;return functions
            opts={'expected_error':'3E6BB18'} if initial==0xffffffff else {}
            with self.subTest(initial=initial),connected(opts,transform=instrument) as (e,port):
                r=e['runtime'];m=r.memory;z=r._login_msf_record_pending;q=z['input'];ops=[x for x in r.events if x[0]=='source.75ADC8.MODEL_CAS']
                if initial==0xffffffff:
                    self.assertEqual(ops,[]);self.assertEqual(m.load(z['old_strong'],8),q.login);self.assertEqual(m.load(z['old_strong']+8,8),0)
                    self.assertEqual(m.read(z['exception']+8,16),bytes(16));self.assertEqual(m.load(z['exception'],8),r.image_base+0x3ebf9b8)
                    self.assertEqual(port._WindowsMMKVHost__open['boundary'],0x3e6bb18)
                else:
                    self.assertEqual(m.read(z['old_strong'],16),bytes(16));self.assertEqual(m.load(z['pair']+8,8),q.control)
                    if initial==0:self.assertEqual([(x[1],x[2],x[4]) for x in ops],[(0,7,False),(7,7,True)])
                    else:self.assertEqual(ops[0][1:5],(0xfffffffe,0xfffffffe,0xffffffff,True))
                self.assertFalse([w for w in m.writes if w[0]==q.control+0xc or w[0]==q.control+0x10 and w[2]=='75ADC8.MODEL_CMPXCHG_DWORD_success'])

    def test_partial_record_copy_and_post_weak_failures_retain_inputs_and_owners(self):
        for source in ('75CF8E.assign_new_length','6D4CB6.old_strong_moved_empty'):
            observed=[]
            def instrument(functions,r,calls):
                write=r.memory.write;store=r.memory.store
                def fail(address,kw):
                    z=getattr(r,'_login_msf_record_pending',None)
                    if z and (kw.get('source')==source or source=='75CF8E.assign_new_length' and address==z['record']+0x58+8 and kw.get('source')=='75CF8E.assign_new_length'):
                        observed.append(address);raise RuntimeError('controlled record source failure')
                def actual_write(address,data,**kw):
                    result=write(address,data,**kw);fail(address,kw);return result
                def actual_store(address,value,size,**kw):
                    result=store(address,value,size,**kw);fail(address,kw);return result
                r.memory.write=actual_write;r.memory.store=actual_store;return functions
            with self.subTest(source=source),connected({'expected_type':RuntimeError,'expected_error':'controlled record source failure','config_extra':{'commonPath':'C:\\long_component_name_for_record'}},transform=instrument) as (e,port):
                r=e['runtime'];self.assertTrue(observed);q=r._login_input_pending;z=r._login_msf_record_pending
                self.assertEqual(r.memory.load(q.input+0x90,1),0);self.assertTrue(all(r._ordinary_msf_pair_moved))
                self.assertFalse([x for x in r.events if x[0] in ('source.1A51A','source.6C4A88')])
                if source=='6D4CB6.old_strong_moved_empty':self.assertEqual(r.memory.load(z['pair']+8,8),q.control)

    def test_early_conversion_debt_blocks_close_before_any_retirement_and_is_owner_bound(self):
        from types import SimpleNamespace
        from qq_nt_replica.primary_login_msf_record import preflight_close
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with connected({'config_extra':{'appid':7,'clientVer':'v'*48},'early_input_failure':True,'expected_error':'present appid'}) as (e,port):
            owner=e['owner'];r=e['runtime'];q=r._login_input_pending
            from qq_nt_replica.primary_logger import _String
            pointer=_String.read(r,q.frame+24).get(16,8)
            self.assertIn(pointer,r._custom_allocator_backend.records)
            self.assertEqual(r.memory.read(pointer,49),b'v'*48+b'\0')
            self.assertIsNone(port._WindowsMMKVHost__open);self.assertIsNone(port._WindowsMMKVHost__origin)
            with patch.object(owner._threads,'prepare_close',side_effect=AssertionError('unsafe retire')):
                with self.assertRaises(ExceptionGroup):owner.close()
            self.assertFalse(r._custom_allocator_backend.closed)
            self.assertIn(pointer,r._custom_allocator_backend.records)
            self.assertIs(r._login_input_pending,q);self.assertEqual(q.phase,'converting')
            owner._state='open'
            with patch.object(r,'_shared_locale_source_epoch',object()):
                with self.assertRaises(InputError):preflight_close(owner)
            with self.assertRaises(InputError):preflight_close(SimpleNamespace(_signer=SimpleNamespace(runtime=r)))
            with self.assertRaises(PrimarySemanticUnavailable):preflight_close(owner)
            # Clearing diagnostics does not erase the private original-issued debt.
            r._login_input_pending=None
            with self.assertRaises(PrimarySemanticUnavailable):preflight_close(owner)
            r._login_input_pending=q
            class ColdRuntime:pass
            preflight_close(SimpleNamespace(_signer=SimpleNamespace(runtime=ColdRuntime())))

    def test_failure_after_actual_cas_keeps_count_and_unknown_out_control(self):
        from qq_nt_replica.primary_memory import UnknownMemory
        def instrument(functions,r,calls):
            store=r.memory.store
            def actual(address,value,size,**kw):
                result=store(address,value,size,**kw)
                if kw.get('source')=='75ADC8.MODEL_CMPXCHG_DWORD_success':raise RuntimeError('controlled post CAS record failure')
                return result
            r.memory.store=actual;return functions
        with connected({'expected_type':RuntimeError,'expected_error':'controlled post CAS'},transform=instrument) as (e,port):
            r=e['runtime'];m=r.memory;z=r._login_msf_record_pending;q=z['input']
            self.assertEqual(m.load(z['old_strong'],8),q.login)
            with self.assertRaises(UnknownMemory):m.read(z['old_strong']+8,8)
            with self.assertRaises(UnknownMemory):m.read(z['pair'],16)
            self.assertEqual(m.load(q.control+8,4),1)
            self.assertFalse([x for x in r.events if x[0]=='source.unavailable' and x[2]==0x6d4cca])
            self.assertEqual(q.phase,'persistent_copied')

    def test_five_independent_long_argument_copies_reverse_order_and_partial_allocation(self):
        from qq_nt_replica.primary_logger import _String
        from qq_nt_replica.primary_memory import UnknownMemory
        values=dict(commonPath='C:\\long_component_name_for_record',clientVer='v'*48,machineId='m'*48,platVer='p'*48,hostName='h'*48,externalVersion=True)
        for failing in (False,True):
            snapshots=[]
            def instrument(functions,r,calls):
                case=self;m=r.memory;mapping=m.map
                class Events(list):
                    def append(self,item):
                        super().append(item)
                        if item[0]=='source.D4FA97.D56F50':
                            q=r._login_input_pending
                            source=[_String.read(r,q.frame+24*i).get(16,8) for i in range(5)]
                            target=[_String.read(r,a).get(16,8) for a in q.argument_copies]
                            case.assertEqual(len(set(source+target)),10);snapshots.append((source,target))
                            case.assertTrue(all(p in r._custom_allocator_backend.records for p in source+target))
                def physical_map(address,data,**kw):
                    q=getattr(r,'_login_input_pending',None)
                    if failing and q and q.phase=='argument_copies' and q.copy_index==3 and kw.get('name')=='source custom owned storage':raise RuntimeError('controlled argument allocation storage failure')
                    return mapping(address,data,**kw)
                r.events=Events(r.events);m.map=physical_map;return functions
            options={'config_extra':values}
            if failing:options.update(early_input_failure=True,expected_type=RuntimeError,expected_error='controlled argument allocation storage failure')
            with self.subTest(failing=failing),connected(options,transform=instrument) as (e,port):
                r=e['runtime'];m=r.memory;q=r._login_input_pending
                copies=[x for x in r.events if x[0]=='source.D4F840.argument_COPY']
                self.assertEqual([x[1] for x in copies],[0xd4fa2d,0xd4fa3f,0xd4fa4f] if failing else [0xd4fa2d,0xd4fa3f,0xd4fa4f,0xd4fa5f,0xd4fa6f])
                if failing:
                    self.assertEqual(q.phase,'argument_copies');self.assertEqual(snapshots,[])
                    for index in range(5):self.assertIn(_String.read(r,q.frame+24*index).get(16,8),r._custom_allocator_backend.records)
                    for index in (4,3):self.assertIn(_String.read(r,q.argument_copies[index]).get(16,8),r._custom_allocator_backend.records)
                    with self.assertRaises(UnknownMemory):m.read(q.input,1)
                    self.assertFalse([x for x in r.events if x[0]=='source.D4FAA3.property_dtor'])
                else:
                    original,owned=snapshots[0]
                    self.assertEqual(m.load(q.input+0xa0,1),1);self.assertEqual(m.load(q.login+0x1a0,1),1)
                    self.assertTrue(all(p not in r._custom_allocator_backend.records for p in original))
                    self.assertTrue(all(p in r._custom_allocator_backend.records for p in owned))
                    self.assertEqual([m.load(q.input+24*i+16,8) for i in range(5)],owned)
                    self.assertEqual([x[1] for x in r.events if x[0]=='source.D4FAA3.property_dtor'],[q.frame+i for i in (96,72,48,24,0)])
                    for address in q.argument_copies:self.assertEqual(m.read(address,24),bytes(24))

    def test_original_owner_debt_blocks_signer_none_and_other_runtime_before_retirement(self):
        from types import SimpleNamespace
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_logger import _String
        with connected({'config_extra':{'appid':7,'clientVer':'v'*48},'early_input_failure':True,'expected_error':'present appid'}) as (e,port):
            owner=e['owner'];r=e['runtime'];q=r._login_input_pending;signer=owner._signer
            pointer=_String.read(r,q.frame+24).get(16,8);before=e['file_api'].calls[:]
            for replacement in (None,SimpleNamespace(runtime=type('ForeignRuntime',(),{})())):
                with self.subTest(replacement=replacement),patch.object(owner,'_signer',replacement),patch.object(owner._threads,'prepare_close',side_effect=AssertionError('unsafe thread/creator retirement')) as retirement:
                    errors=owner._release_resources()
                    self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],InputError);retirement.assert_not_called()
                    self.assertEqual(owner._cleanup_outcomes[-1]['stage'],'mmkv_early_debt')
                self.assertIs(owner._signer,signer);self.assertIn(pointer,r._custom_allocator_backend.records)
                self.assertEqual(r.memory.read(pointer,49),b'v'*48+b'\0');self.assertFalse(r._custom_allocator_backend.closed)
            self.assertEqual(e['file_api'].calls,before);self.assertIs(r._login_input_pending,q)

    def test_original_owner_anchor_rejects_missing_corrupt_registry_and_keeps_cold_path(self):
        from qq_nt_replica import primary_login_msf_record as subject
        from qq_nt_replica.errors import InputError
        from types import SimpleNamespace
        cold=[]
        def instrument(functions,r,calls):
            from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
            owner=for_runtime(r)._WindowsMMKVHost__owner
            for signer in (owner._signer,None):
                with patch.object(owner,'_signer',signer),patch.object(owner._threads,'prepare_close',side_effect=RuntimeError('controlled cold thread boundary')) as thread:
                    errors=owner._release_resources();self.assertEqual(len(errors),1)
                    self.assertEqual(str(errors[0]),'controlled cold thread boundary');thread.assert_called_once();cold.append(True)
            return functions
        with connected(transform=instrument) as (e,port):
            owner=e['owner'];r=e['runtime'];q=r._login_input_pending;row=subject._OWNERS[id(owner)]
            with patch.object(owner._threads,'prepare_close',side_effect=AssertionError('unsafe retire')) as retirement:
                del subject._ACTIVE[r]
                try:
                    errors=owner._release_resources();self.assertIsInstance(errors[0],InputError)
                finally:subject._ACTIVE[r]=q
                subject._ACTIVE[r]=copy.copy(q)
                try:
                    errors=owner._release_resources();self.assertIsInstance(errors[0],InputError)
                finally:subject._ACTIVE[r]=q
                del subject._OWNERS[id(owner)]
                try:
                    with patch.object(owner,'_signer',None):
                        errors=owner._release_resources();self.assertIsInstance(errors[0],InputError)
                finally:subject._OWNERS[id(owner)]=row
                subject._OWNERS[id(owner)]=(object(),q)
                try:
                    errors=owner._release_resources();self.assertIsInstance(errors[0],InputError)
                finally:subject._OWNERS[id(owner)]=row
                retirement.assert_not_called()
            self.assertEqual(cold,[True,True]);self.assertFalse(r._custom_allocator_backend.closed)

if __name__=='__main__':unittest.main()
