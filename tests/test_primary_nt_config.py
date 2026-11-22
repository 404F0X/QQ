"""Controlled ordinary matched-empty NT config source path."""
import unittest
from test_primary_mmkv_file import connected

class Config(unittest.TestCase):
    def test_real_empty_getter_selector_false_and_ordinary_ctor_boundary(self):
        from qq_nt_replica.primary_memory import UnknownMemory
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;b=r.image_base
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0x29d9e)
            self.assertEqual(m.load(b+0x674d420,1),0)
            self.assertNotEqual(m.load(b+0x674d424,4,signed=True),-1)
            self.assertNotEqual(m.load(b+0x674d2d0,4,signed=True),-1)
            obj,control=r._ordinary_msf_pair_moved
            self.assertEqual((m.load(b+0x674d2c0,8),m.load(b+0x674d2c8,8)),(obj,control))
            self.assertTrue(r._selector_config_history[-1]['caller_consumed'])



class Birth(unittest.TestCase):
    def signer(self):
        from qq_nt_replica.primary_signer import PrimarySigner,SigningEnvironment
        return PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/p.exe',module_path=b'C:/explicit/m.dll',stack_modules=()),initial_stack=None,primary_backend='direct')

    def test_exact_twenty_birth_neighbors_and_trusted_warm_preserved(self):
        from qq_nt_replica import primary_msf_selection as subject
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        signer=self.signer();r=signer.runtime;m=r.memory;b=r.image_base
        for offset,size in ((0x674d2c0,16),(0x674d2d0,4)):
            region,start=m._span(b+offset,size);self.assertEqual((region.address,start,len(region.data)),(b+offset,0,size));self.assertEqual(m.read(b+offset,size),bytes(size))
        for address in (b+0x674d2bf,b+0x674d2d4,b+0x674d2df):
            with self.assertRaises(PrimaryMemoryLimit):m.read(address,1)
        for offset,width,value in ((0x674d2c0,8,0x123),(0x674d2c8,8,0x456),(0x674d2d0,4,77)):
            m.store(b+offset,value,width,source='controlled trusted warm value')
        before=m.writes[:];subject._validate(r);self.assertEqual(m.writes,before)
        self.assertEqual((m.load(b+0x674d2c0,8),m.load(b+0x674d2c8,8),m.load(b+0x674d2d0,4)),(0x123,0x456,77))
        with self.assertRaises(Exception):subject.install_fresh_image(signer)
        with self.assertRaises(PrimaryMemoryLimit):signer._initialize_image()
        self.assertEqual(m.load(b+0x674d2c0,8),0x123)

    def test_preexisting_partial_and_unknown_mapping_rejected_before_either_birth(self):
        from qq_nt_replica.primary_memory import PrimaryMemory,PrimaryMemoryLimit
        from unittest.mock import patch
        original=PrimaryMemory.map;base=0x180000000
        for shift,size,known in ((7,1,True),(17,1,True),(15,2,True),(0,16,False)):
            memories=[]
            def mapped(memory,address,buffer,**kw):
                result=original(memory,address,buffer,**kw)
                if address==base+0x674d4d8 and not memories:
                    original(memory,base+0x674d2c0+shift,b'X'*size,name='controlled preexisting conflict',initialized=known);memories.append(memory)
                return result
            with self.subTest(shift=shift,known=known),patch.object(PrimaryMemory,'map',mapped):
                with self.assertRaisesRegex(PrimaryMemoryLimit,'ordinary MSF birth overlaps'):self.signer()
            memory=memories[0]
            self.assertFalse(any(x.address==base+0x674d2d0 and len(x.data)==4 for x in memory._regions))
            if shift!=0:self.assertFalse(any(x.address==base+0x674d2c0 and len(x.data)==16 for x in memory._regions))
            region,offset=memory._span(base+0x674d2c0+shift,size)
            self.assertEqual(bytes(region.initialized[offset:offset+size]),bytes([int(known)])*size)
            self.assertEqual(bytes(region.data[offset:offset+size]),b'X'*size)

    def test_memory_base_locale_epochs_and_exact_region_replacement_rejected(self):
        from qq_nt_replica import primary_msf_selection as subject
        from qq_nt_replica.primary_memory import PrimaryMemory
        from qq_nt_replica.errors import InputError
        from unittest.mock import patch
        signer=self.signer();r=signer.runtime;m=r.memory;image=r._shared_locale_source
        for obj,name,value in ((r,'memory',PrimaryMemory()),(r,'image_base',r.image_base+0x1000),(r,'_shared_locale_source',object()),(r,'_shared_locale_source_epoch',object()),(image,'epoch',object()),(signer,'_shared_locale_image',object())):
            before=len(m.writes)
            with self.subTest(name=name),patch.object(obj,name,value):
                with self.assertRaises(InputError):subject._validate(r)
            self.assertEqual(len(m.writes),before)
        for offset,size in ((0x674d2c0,16),(0x674d2d0,4),(0x3f6df58,8)):
            region,start=m._span(r.image_base+offset,size);index=next(i for i,x in enumerate(m._regions) if x is region)
            copy=type(region)(region.address,memoryview(bytearray(region.data)),bytearray(region.initialized),region.name)
            try:
                m._regions[index]=copy
                with self.assertRaises(InputError):subject._validate(r)
            finally:m._regions[index]=region;copy.data.release()

class Lookup(unittest.TestCase):
    def instrument(self,action):
        def instrument(functions,r,calls):
            class Events(list):
                def append(self,item):
                    super().append(item)
                    if item[0]=='source.7503EA.return':action(r)
            r.events=Events(r.events);return functions
        return instrument

    def test_actual_compare_hash_nested_snapshot_payload_and_no_output_write(self):
        from qq_nt_replica import primary_request_manager as request
        from qq_nt_replica.primary_memory import UnknownMemory,PrimaryMemoryLimit
        from unittest.mock import patch
        values=[];snapshots=[];payloads=[];comparisons=[];case=self
        original=request.hash_bytes
        def actual_hash(value):
            result=original(value)
            if len(value)==13:values.append((value,result))
            return result
        def instrument(functions,r,calls):
            m=r.memory;load=m.load;unmap=m.unmap;store=m.store
            class Events(list):
                def append(self,item):
                    super().append(item)
                    if item[0]=='source.NT_compare':comparisons.append(item)
                    if item[0]=='source.B98642.flag0':
                        address=item[1];region,off=m._span(address,18)
                        payloads.append(bytes(region.initialized[off:off+18]))
                        case.assertEqual(m.read(address,2),bytes(2))
                        with case.assertRaises(UnknownMemory):m.read(address+2,16)
                        case.assertEqual(m.read(r._selector_config_pending['output'],24),bytes(24))
            r.events=Events(r.events)
            def actual_unmap(address):
                p=getattr(r,'_selector_config_pending',None)
                if p and address==p.get('snapshot'):
                    from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
                    session=for_runtime(r)._WindowsMMKVHost__open;state=m.load(session['parent']+0xb0,8)
                    snapshots.append((m.read(address,0x70),m.load(state+8,8)))
                return unmap(address)
            m.unmap=actual_unmap;return functions
        with patch.object(request,'hash_bytes',side_effect=actual_hash),connected(transform=instrument) as (e,port):
            r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;h=r._selector_config_history[-1]
            self.assertEqual(values,[(b'107775_switch',original(b'107775_switch'))])
            self.assertEqual(payloads,[bytes([1,1])+bytes(16)])
            self.assertEqual(snapshots,[(m.read(s['files'][1].load(0x30),0x70),1)])
            self.assertEqual(s['private_cs'],'released');self.assertEqual(s['config_nested'].guard,None);self.assertEqual(s['config_outer'].guard,None)
            self.assertEqual(len(comparisons),2);node=m.load(r._nt_config_record.tree+8,8)
            self.assertEqual((comparisons[0][2],comparisons[1][3]),(m.load(node+0x30,8),m.load(node+0x30,8)))
            writes=[w for w in m.writes if w[0]==h['output']]
            self.assertTrue(writes);self.assertFalse([w for w in writes if 'payload' in w[2] or 'getter' in w[2]])
            self.assertEqual(len([x for x in e['file_api'].calls if x[0]=='LockFileEx']),6)
            self.assertEqual(s['config_outer'].root.address,s['outer_guard'].address)
            self.assertEqual(s['config_outer'].token,s['config_nested'].token)
            self.assertEqual(s['global_lock'],'released')
            with self.assertRaises(PrimaryMemoryLimit):m.read(h['payload'],18)

    def test_unconditional_loadcheck_d1_and_invalid_meta_skip_without_history_gate(self):
        from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
        for branch in ('D1zero','invalid_meta','version1'):
            def action(r):
                m=r.memory;s=for_runtime(r)._WindowsMMKVHost__open;p=s['parent']
                if branch=='D1zero':m.store(p+0xd1,0,1,source='controlled source field')
                elif branch=='invalid_meta':m.store(s['files'][1].address+0x18,(1<<64)-1,8,source='controlled invalid HANDLE')
                else:
                    m.store(m.load(p+0x98,8)+4,1,4,source='controlled cached version')
                    m.store(s['files'][1].load(0x30)+4,1,4,source='controlled mapped version')
            with self.subTest(branch=branch),connected(transform=self.instrument(action)) as (e,port):
                r=e['runtime'];self.assertEqual(port._WindowsMMKVHost__open['boundary'],0x29d9e)
                copies=[w for w in r.memory.writes if w[2]=='1BDA69F.actual_snapshot70_copy']
                self.assertEqual(len(copies),1 if branch=='version1' else 0)
                self.assertTrue([x for x in r.events if x[0]=='source.B98642.flag0'])

    def test_changed_metadata_c8_and_loadflag_keep_actual_partial_effects(self):
        from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
        for branch,expected in (('seq','seqDWORD'),('digest','digest changed'),('C8','nonzero C8'),('loadflag','reload branch')):
            def action(r):
                m=r.memory;s=for_runtime(r)._WindowsMMKVHost__open;p=s['parent']
                if branch in ('seq','digest'):m.store(s['files'][1].load(0x30)+(8 if branch=='seq' else 0),99,4,source='controlled mapped metadata change')
                else:m.store(p+(0xc8 if branch=='C8' else 0x88),1,1,source='controlled source flag')
            with self.subTest(branch=branch),connected({'expected_error':expected},transform=self.instrument(action)) as (e,port):
                r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;p=s['parent'];cfg=r._selector_config_pending
                self.assertEqual(m.read(cfg['output'],24),bytes(24));self.assertEqual(m.load(r.image_base+0x674d424,4,signed=True),-1)
                self.assertFalse([x for x in r.events if x[0]=='source.B98642.flag0']);self.assertEqual(s['private_cs'],'held')
                self.assertIsNotNone(s['config_outer'].guard);self.assertFalse(hasattr(r,'_ordinary_msf_pair_moved'))
                if branch in ('seq','digest'):
                    self.assertEqual(m.read(cfg['snapshot'],0x70),m.read(s['files'][1].load(0x30),0x70));self.assertIsNotNone(s['config_nested'].guard)
                if branch=='loadflag':self.assertEqual(m.load(p+0x88,1),0)
                if branch=='seq':self.assertIsNone(cfg['boundary'])

    def test_null_value_and_actual_key_miss_emit_exact_native_two_argument_log(self):
        from qq_nt_replica.primary_logger import _String
        for branch in ('null','different_key'):
            seen=[]
            def instrument(functions,r,calls):
                m=r.memory;store=m.store
                def actual(address,value,size,**kw):
                    if kw.get('source')=='65274.NT_guard_publish':
                        if branch=='null':
                            node=m.load(r._nt_misc_record.tree+8,8);m.store(node+0x38,0,8,source='controlled actual NULL NT value')
                        else:
                            ident=_String.read(r,r._selector_config_pending['identifier']);m.store(ident.get(16,8)+24,ord('z'),1,source='controlled actual key lastbyte')
                    result=store(address,value,size,**kw)
                    p=getattr(r,'_selector_config_pending',None)
                    if kw.get('source')=='308A.variant11' and p and p.get('log_array') and address==p['log_array']+72:
                        seen.append(tuple((m.load(p['log_array']+40*i+8,8),m.load(p['log_array']+40*i+32,4)) for i in range(2)))
                        for i in range(2):
                            region,off=m._span(p['log_array']+40*i,40)
                            self.assertEqual(bytes(region.initialized[off:off+40]),bytes(8)+bytes([1])*8+bytes(16)+bytes([1])*4+bytes(4))
                    return result
                m.store=actual;return functions
            with self.subTest(branch=branch),connected(transform=instrument) as (e,port):
                r=e['runtime'];self.assertEqual(port._WindowsMMKVHost__open['boundary'],0x29d9e)
                logs=[x for x in r.events if x[0]=='source.D3A81F' and x[1]==4]
                ident=b'nt_mmkv_msf_united_config' if branch=='null' else b'nt_mmkv_msf_united_confiz'
                self.assertEqual(logs, [('source.D3A81F',4,b'nt_wrapper_engine.cc',0x767,b'',b'get misc mmkv failed,  id='+ident+b' key:107775_switch')])
                self.assertEqual(len(seen),1);self.assertEqual([tag for pointer,tag in seen[0]],[11,11])
                self.assertFalse([x for x in r.events if x[0]=='source.B98642.flag0'])
                self.assertEqual([x[0] for x in r.events].count('source.62140.copy_dtor'),2)

    def test_missing_log_formatter_and_sink_failures_retain_source_arguments(self):
        from qq_nt_replica.primary_logger import _String
        for stage,tag in (('formatter',11),('sink',0xffffffff)):
            def instrument(functions,r,calls):
                m=r.memory;store=m.store;write=m.write
                def actual_store(address,value,size,**kw):
                    if kw.get('source')=='65274.NT_guard_publish':m.store(m.load(r._nt_misc_record.tree+8,8)+0x38,0,8,source='controlled null')
                    return store(address,value,size,**kw)
                def actual_write(address,data,**kw):
                    result=write(address,data,**kw);p=getattr(r,'_selector_config_pending',None)
                    if p and p.get('log_frame') and kw.get('source')=='508834.literal' and m.load(p['log_array']+32,4)==tag:raise RuntimeError('controlled config '+stage)
                    return result
                m.store=actual_store;m.write=actual_write;return functions
            with self.subTest(stage=stage),connected({'expected_type':RuntimeError,'expected_error':'controlled config '+stage},transform=instrument) as (e,port):
                r=e['runtime'];p=r._selector_config_pending;m=r.memory
                self.assertEqual([m.load(p['log_array']+40*i+32,4) for i in range(2)],[tag,tag])
                self.assertEqual(_String.read(r,p['missing_copies']).value(),b'107775_switch')
                self.assertEqual(_String.read(r,p['missing_copies']+24).value(),b'nt_mmkv_msf_united_config')
                self.assertFalse([x for x in r.events if x[0]=='source.62140.copy_dtor']);self.assertFalse(p.get('pair_consumed',False))
                self.assertEqual(m.load(r.image_base+0x674d424,4,signed=True),-1)

    def test_new_context_same_domain_old_context_retired_and_current_lease_required(self):
        from qq_nt_replica.primary_nt_misc_map import bind
        from qq_nt_replica.errors import InputError
        from unittest.mock import patch
        def instrument(functions,r,calls):
            store=r.memory.store
            def actual(address,value,size,**kw):
                result=store(address,value,size,**kw)
                if kw.get('source')=='65274.NT_guard_publish':raise RuntimeError('controlled config pause')
                return result
            r.memory.store=actual;return functions
        with connected({'expected_type':RuntimeError,'expected_error':'controlled config pause'},transform=instrument) as (e,port):
            r=e['runtime'];m=r.memory;old=r._nt_misc_record
            with e['owner']._registrar.operation():
                new=bind(r,r._selector_config_pending,'config');self.assertIs(new.domain,old.domain)
                before=len(m.writes)
                with self.assertRaises(InputError):old.read()
                expected=new.scratch(0)
                with e['owner']._registrar.current_lease().suspend():
                    with self.assertRaises(InputError):new.cas(expected,8,2)
                for obj,name,value in ((r,'_shared_locale_source_epoch',object()),(new.module,'epoch',object())):
                    with patch.object(obj,name,value):
                        with self.assertRaises(InputError):new.cas(expected,8,2)
                self.assertEqual(m.load(new.cell,8),0);self.assertEqual(len(m.writes),before+1)
                new.acquire();new.release();self.assertEqual(m.load(new.cell,8),0)

    def test_private_enter_denial_is_not_ordinary_false_and_close_preflight_stays_early(self):
        from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
        from unittest.mock import patch
        def instrument(functions,r,calls):
            port=for_runtime(r);old=port._WindowsMMKVHost__permit
            port._WindowsMMKVHost__permit=lambda owner,operation:False if getattr(r,'_selector_config_pending',None) and operation=='EnterCriticalSection' else old(owner,operation)
            return functions
        with connected({'expected_error':'scope denied'},transform=instrument) as (e,port):
            r=e['runtime'];p=r._selector_config_pending;s=port._WindowsMMKVHost__open
            self.assertEqual(s['global_lock'],'released');self.assertEqual(s['private_cs'],'enter_unknown')
            self.assertEqual(r.memory.load(r.image_base+0x674d424,4,signed=True),-1);self.assertEqual(r.memory.read(p['output'],24),bytes(24))
            self.assertFalse(hasattr(r,'_ordinary_msf_pair_moved'))
            with patch.object(e['owner']._threads,'prepare_close',side_effect=AssertionError('dangerous retirement')):
                with self.assertRaises(ExceptionGroup):e['owner'].close()
            self.assertFalse(r._custom_allocator_backend.closed)

    def test_unknown_or_one_length_output_is_not_silently_selected_false(self):
        from qq_nt_replica.primary_memory import UnknownMemory
        for branch,error,kind in (('unknown','unobserved local string field',UnknownMemory),('one','75CBE0',Exception)):
            def instrument(functions,r,calls):
                m=r.memory
                class Events(list):
                    def append(self,item):
                        super().append(item)
                        if item[0]=='source.65240.return':
                            output=r._selector_config_pending['output']
                            if branch=='unknown':m.forget(output,1,source='controlled unknown output tag')
                            else:m.store(output,2,1,source='controlled actual output length1')
                r.events=Events(r.events);return functions
            with self.subTest(branch=branch),connected({'expected_type':kind,'expected_error':error},transform=instrument) as (e,port):
                r=e['runtime'];m=r.memory
                self.assertEqual(m.load(r.image_base+0x674d424,4,signed=True),-1)
                self.assertFalse([w for w in m.writes if w[2]=='750843.selector_cache_false'])
                self.assertFalse(hasattr(r,'_ordinary_msf_pair_moved'))

    def test_filtered_missing_log_still_consumes_both_owned_copies_normally(self):
        def action(r):
            m=r.memory;node=m.load(r._nt_misc_record.tree+8,8)
            m.store(node+0x38,0,8,source='controlled NULL actual NT value')
            m.store(r.image_base+0x67535d0,5,4,source='controlled source threshold5')
        with connected(transform=self.instrument(action)) as (e,port):
            r=e['runtime'];p=r._selector_config_history[-1]
            self.assertTrue([x for x in r.events if x[0]=='source.62140'])
            self.assertFalse([x for x in r.events if x[0]=='source.D3A81F' and x[1]==4])
            self.assertEqual([x[0] for x in r.events].count('source.62140.copy_dtor'),2)
            self.assertNotIn('log_array',p);self.assertTrue(p['pair_consumed']);self.assertTrue(p['caller_consumed'])
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0x29d9e)

if __name__=='__main__':unittest.main()
