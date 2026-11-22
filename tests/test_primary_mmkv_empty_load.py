"""Continuous source empty-load/cache publication with synthetic physical ABI only."""
import ctypes as C
import unittest
from unittest.mock import patch
from test_primary_mmkv_file import connected


class EmptyLoad(unittest.TestCase):
    def test_continuous_factory_zero_load_cache_and_caller_stop(self):
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;p=s['parent']
            self.assertEqual((s['global_lock'],s['boundary']),('released',0xd3de50))
            self.assertEqual(m.load(p+0x78,8),0);self.assertEqual(m.load(p+0x88,1),0)
            self.assertEqual(m.load(m.load(p+0x98,8)+4,4),4)
            cache=m.load(r.image_base+0x6751388,8);node=m.load(cache+0x10,8)
            self.assertEqual((m.load(cache+8,8),m.load(cache+0x18,8),m.load(node+0x28,8)),(2,1,p))
            self.assertEqual(m.load(m.load(cache,8)+(m.load(node+8,8)&1)*8,8),cache+0x10)
            self.assertEqual(r._mmkv_caller_pending['raw'],p)
            self.assertEqual(m.load(r._mmkv_caller_pending['guard'],8),r._mmkv_caller_pending['interface']+0x3b0)
            self.assertEqual(m.load(r.image_base+0x674d418,8),1)
            obj=m.load(r.image_base+0x674c730,8);self.assertEqual(m.read(obj+0x90,16),bytes(16))

    def test_actual_zero_production_copy_crc_descriptor_logs_and_writeback(self):
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;p=s['parent'];main,crc=s['files'];meta=m.load(p+0x98,8)
            self.assertEqual([len(e['file_api'].data[f.load(0x18)]) for f in (main,crc)],[8192,8192])
            self.assertTrue(all(not any(e['file_api'].data[f.load(0x18)]) for f in (main,crc)))
            copies=[w for w in m.writes if w[2]=='1BDA25E.actual_Meta70_copy'];self.assertEqual(copies[0][1],bytes(0x70))
            events=[x for x in r.events if x[0]=='source.crc'];self.assertEqual(events[-1][2:],(0,main.load(0x30)+4,0))
            desc=m.load(p+0x80,8);self.assertEqual(tuple(m.load(desc+off,8) for off in (0,8,16)),(main.load(0x30)+4,8188,0))
            m.write(main.load(0x30)+4,b'X',source='observer borrowed descriptor alias')
            self.assertEqual(m.read(m.load(desc,8),1),b'X')
            self.assertEqual(m.read(meta,0x70),m.read(crc.load(0x30),0x70))
            order=[w[2] for w in m.writes]
            self.assertLess(order.index('1BD9BDB.selected_length_before_bounds'),order.index('B99A1B.actual_CRC_result'))
            self.assertLess(order.index('1BDF4D4.borrowed_descriptor'),order.index('1BDB38E.main_header0'))
            self.assertLess(order.index('1BD9F4E.version1'),order.index('1BD9F4E.version4'))
            self.assertLess(order.index('1BD9F4E.version4'),order.index('1BD98ED.loaded_byte0'))
            logs=[x for x in r.events if x[0]=='1BDF22C.arguments' and x[2]==b'MMKV_IO.cpp']
            self.assertEqual([x[4] for x in logs],[0x57,0x88]);self.assertEqual(logs[0][-1][-1].value,0)
            formatted=[x for x in e['stdio_calls'] if x[0]=='format' and x[4].startswith(b'loading [')]
            self.assertEqual(len(formatted),2);self.assertEqual(formatted[0][3],formatted[1][3]);self.assertTrue(formatted[1][4].endswith(b'version:0'))
            self.assertEqual(m.load(meta+4,4),4)

    def test_three_independent_keys_and_node_value_is_published_last(self):
        observed=[]
        def instrument(functions,r,calls):
            from qq_nt_replica.primary_logger import _String
            store=r.memory.store
            def actual(address,value,size,**kw):
                if kw.get('source')=='B9938A.cache_value_publish':
                    from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
                    session=for_runtime(r)._WindowsMMKVHost__open;node=address-0x28
                    keys=[_String.read(r,p) for p in (value,session['key'],node+0x10)]
                    self.assertEqual([key.value() for key in keys],[b'nt_mmkv_msf_united_config']*3)
                    self.assertEqual([key.get(0,8) for key in keys],[0x31,0x21,0x21])
                    pointers=[key.get(16,8) for key in keys];self.assertEqual(len(set(pointers)),3)
                    self.assertEqual(r.memory.load(address,8),0);observed.append(pointers)
                return store(address,value,size,**kw)
            r.memory.store=actual;return functions
        with connected(transform=instrument) as (e,port):
            self.assertEqual(len(observed),1);r=e['runtime']
            self.assertIn(observed[0][0],r._custom_allocator_backend.records);self.assertIn(observed[0][2],r._custom_allocator_backend.records)
            self.assertNotIn(observed[0][1],r._custom_allocator_backend.records)
            s=port._WindowsMMKVHost__open;self.assertEqual(s['global_lock'],'released')
            self.assertEqual([name for name,args in e['file_api'].calls].count('LeaveCriticalSection'),1)

    def test_getsize_false_is_not_a_history_guard(self):
        with connected({'size_false':True}) as (e,port):
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0xd3de50)
            self.assertFalse([x for x in e['file_api'].calls if x[0]=='GetLastError'])

    def test_partial_write_retains_bytes_and_real_reopen_not_fake_zero(self):
        with connected({'written':2048,'write_fail_at':2}) as (e,port):
            r=e['runtime'];m=r.memory;file=port._WindowsMMKVHost__open['files'][0]
            self.assertEqual(m.read(file.load(0x30)+2048,1),b'\xcc')
            stores=[int.from_bytes(x[1],'little') for x in m.writes if x[0]==file.address+0x38]
            self.assertIn(0,stores[1:]);self.assertEqual(stores[-1],8192)
            self.assertGreater(len([x for x in e['file_api'].calls if x[0]=='GetFileSizeEx']),2)
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0xd3de50)

    def test_nonzero_crc_stops_after_length_without_fake_result(self):
        main=bytearray(8192);main[:4]=(1).to_bytes(4,'little')
        with connected({'file_data':(bytes(main),bytes(8192)),'expected_error':'1BDF3E0'}) as (e,port):
            r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;p=s['parent']
            self.assertEqual(m.load(p+0x78,8),1);self.assertEqual(s['global_lock'],'held')
            self.assertFalse([x for x in m.writes if x[2]=='B99A1B.actual_CRC_result'])
            self.assertEqual(m.load(p+0x80,8),0);self.assertEqual(m.load(m.load(r.image_base+0x6751388,8)+8,8),0)
            self.assertEqual([x for x in r.events if x[0]=='source.crc'][-1][-1],1)

    def test_digest_mismatch_stops_at_recovery_after_actual_crc_store(self):
        meta=bytearray(8192);meta[:4]=(1).to_bytes(4,'little')
        with connected({'file_data':(bytes(8192),bytes(meta)),'expected_error':'1BDA3CA'}) as (e,port):
            r=e['runtime'];m=r.memory;p=port._WindowsMMKVHost__open['parent']
            self.assertTrue([x for x in m.writes if x[0]==p+0x8c and x[2]=='B99A1B.actual_CRC_result'])
            self.assertEqual(m.load(m.load(p+0x98,8),4),1);self.assertEqual(m.load(p+0x80,8),0)

    def test_meta_version_and_length_mismatch_log_rereads_actual_field(self):
        meta=bytearray(8192);meta[4:8]=(3).to_bytes(4,'little');meta[0x1c:0x20]=(2).to_bytes(4,'little');observed=[]
        def instrument(functions,r,calls):
            output=functions['__stdio_common_vfprintf']
            def actual(*args):
                result=output(*args)
                if b'actual size 0, meta actual size 2' in calls[-1][-1]:
                    from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
                    parent=for_runtime(r)._WindowsMMKVHost__open['parent'];m=r.memory
                    m.store(m.load(parent+0x98,8)+0x1c,0,4,source='physical log observer field change');observed.append(calls[-1][-1])
                return result
            functions['__stdio_common_vfprintf']=actual;return functions
        with connected({'file_data':(bytes(8192),bytes(meta))},transform=instrument) as (e,port):
            self.assertEqual(len(observed),1);self.assertTrue(observed[0].startswith(b'[W]'))
            r=e['runtime'];p=port._WindowsMMKVHost__open['parent'];self.assertEqual(r.memory.load(p+0x78,8),0)
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0xd3de50)

    def test_shared_state_same_overlapped_and_upgrade_downgrade_order(self):
        with connected() as (e,port):
            s=port._WindowsMMKVHost__open;outer=s['outer_guard'];inner=s['inner_guard'];m=e['runtime'].memory
            self.assertEqual(inner.address,outer.address);self.assertIs(inner.native,outer.native);self.assertIs(inner.token,outer.token)
            ov=C.addressof(outer.native)
            calls=[(name,args[1] if name=='LockFileEx' else None) for name,args in e['file_api'].calls if name in ('LockFileEx','UnlockFileEx') and args[-1]==ov]
            self.assertEqual(calls,[('LockFileEx',0),('UnlockFileEx',None),('LockFileEx',2),('LockFileEx',0),('UnlockFileEx',None),('UnlockFileEx',None)])
            self.assertEqual((m.load(outer.address+8,8),m.load(outer.address+16,8)),(0,0))
            self.assertIsNone(inner.guard);self.assertIsNone(outer.guard);self.assertFalse(outer.pinned)

    def test_upgrade_failure_recovery_failure_continues_without_false_counter(self):
        with connected({'lock_script':{4:(0,5),5:(0,6)}}) as (e,port):
            r=e['runtime'];s=port._WindowsMMKVHost__open;outer=s['outer_guard'];m=r.memory
            self.assertEqual((m.load(outer.address+8,8),m.load(outer.address+16,8)),(0,0))
            templates=[x[5] for x in r.events if x[0]=='1BDF22C.arguments']
            self.assertIn(b'fail to lock fd=%p, error:%d',templates);self.assertIn(b'fail to recover shared-lock fd=%p, error:%d',templates)
            self.assertEqual(s['boundary'],0xd3de50)

    def test_downgrade_ignored_shared_false_and_failed_unlock_are_distinct(self):
        for options,exclusive,pinned in (({'lock_script':{5:(0,7)}},0,False),({'unlock_script':{4:(0,5)}},1,True),({'unlock_script':{4:(0,0x9e)}},0,False)):
            with self.subTest(options=options),connected(options) as (e,port):
                r=e['runtime'];s=port._WindowsMMKVHost__open;outer=s['outer_guard'];inner=s['inner_guard'];m=r.memory
                self.assertEqual((m.load(outer.address+8,8),m.load(outer.address+16,8)),(0,exclusive))
                self.assertEqual(outer.pinned,pinned);self.assertIsNone(inner.guard);self.assertIsNone(outer.guard)
                if exclusive:self.assertEqual(e['file_api'].unlock_calls,4)
                self.assertEqual(s['boundary'],0xd3de50)

    def test_upgrade_exception_retains_guard_pin_and_no_descriptor(self):
        with connected({'lock_raise_at':4,'expected_type':RuntimeError,'expected_error':'controlled file API failure'}) as (e,port):
            r=e['runtime'];s=port._WindowsMMKVHost__open;p=s['parent'];self.assertEqual(s['global_lock'],'held')
            self.assertEqual(s['inner_guard'].guard,'published');self.assertTrue(s['outer_guard'].pinned)
            self.assertEqual(r.memory.load(p+0x80,8),0);self.assertTrue(port._WindowsMMKVHost__failures)

    def test_loaded_log_exception_preserves_writeback_and_outer_guard(self):
        def instrument(functions,r,calls):
            format=functions['__stdio_common_vsprintf']
            def actual(*args):
                if C.string_at(args[3]).startswith(b'loaded ['):raise RuntimeError('controlled loaded log failure')
                return format(*args)
            functions['__stdio_common_vsprintf']=actual;return functions
        with connected({'expected_type':RuntimeError,'expected_error':'controlled loaded log'},transform=instrument) as (e,port):
            r=e['runtime'];s=port._WindowsMMKVHost__open;p=s['parent'];m=r.memory
            self.assertEqual(m.load(m.load(p+0x98,8)+4,4),4);self.assertNotEqual(m.load(p+0x80,8),0)
            self.assertEqual(m.load(p+0x88,1),1);self.assertEqual(s['outer_guard'].guard,'published');self.assertIsNone(s['inner_guard'].guard)
            self.assertFalse([name for name,args in e['file_api'].calls if name=='LeaveCriticalSection'])

    def test_ordinary_invalid_metadata_keeps_constructor_and_narrow_wide_log(self):
        with connected({'open_false_crc':True}) as (e,port):
            r=e['runtime'];s=port._WindowsMMKVHost__open;p=s['parent'];m=r.memory
            self.assertEqual(s['boundary'],0xd3de50);self.assertEqual(m.load(m.load(p+0x98,8)+4,4),1)
            self.assertFalse([x for x in m.writes if x[2]=='1BDA25E.actual_Meta70_copy'])
            logs=[x for x in e['stdio_calls'] if x[0]=='format' and x[4].startswith(b'file [')]
            self.assertEqual(logs[-1][4],b'file [C] not valid')
            self.assertEqual(m.load(p+0x88,1),0);self.assertEqual(m.load(p+0x78,8),0)

    def test_late_publication_failure_preserves_node_null_value_and_key_debt(self):
        def instrument(functions,r,calls):
            store=r.memory.store
            def actual(address,value,size,**kw):
                if kw.get('source')=='B9938A.cache_value_publish':raise RuntimeError('controlled value publication failure')
                return store(address,value,size,**kw)
            r.memory.store=actual;return functions
        with connected({'expected_type':RuntimeError,'expected_error':'controlled value publication'},transform=instrument) as (e,port):
            from qq_nt_replica.primary_logger import _String
            r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;cache=m.load(r.image_base+0x6751388,8);node=m.load(cache+16,8)
            self.assertEqual((m.load(cache+8,8),m.load(cache+24,8),m.load(node+0x28,8)),(2,1,0))
            self.assertEqual(_String.read(r,s['key']).value(),b'nt_mmkv_msf_united_config')
            self.assertEqual(s['global_lock'],'held');self.assertEqual(r._mmkv_caller_pending['phase'],'open_incomplete')

    def test_leave_exception_preserves_cache_and_unknown_lock_without_caller_return(self):
        with connected({'raise':'LeaveCriticalSection'}) as (e,port):
            r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;cache=m.load(r.image_base+0x6751388,8);node=m.load(cache+16,8)
            self.assertEqual(m.load(node+0x28,8),s['parent']);self.assertEqual(s['global_lock'],'leave_unknown')
            self.assertEqual(r._mmkv_caller_pending['phase'],'open_incomplete');self.assertNotIn('raw',r._mmkv_caller_pending)
            self.assertTrue(m.load(s['global_guard'],8));self.assertTrue(port._WindowsMMKVHost__failures)

    def test_identifier_borrow_change_between_formats_keeps_pending_pin(self):
        from qq_nt_replica.errors import InputError
        def instrument(functions,r,calls):
            format=functions['__stdio_common_vsprintf'];changed=[]
            def actual(*args):
                result=format(*args)
                if C.string_at(args[3]).startswith(b'loading [') and not changed:
                    from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
                    p=for_runtime(r)._WindowsMMKVHost__open['parent'];r.memory.store(p+0x20,26,8,source='controlled replaced identifier header');changed.append(True)
                return result
            functions['__stdio_common_vsprintf']=actual;return functions
        with connected({'expected_type':InputError,'expected_error':'borrowed identifier lifetime'},transform=instrument) as (e,port):
            from qq_nt_replica.primary_windows_mmkv_stdio import for_runtime
            r=e['runtime'];stdio=for_runtime(r);s=port._WindowsMMKVHost__open;p=s['parent']
            self.assertTrue(stdio._WindowsMMKVStdio__widepins);self.assertTrue(stdio._WindowsMMKVStdio__records)
            self.assertEqual(r.memory.load(p+0x80,8),0);self.assertEqual(s['outer_guard'].guard,'published')

    def test_unsigned32_log_retains_high_dword(self):
        main=bytearray(8192);main[:4]=(0xffffffff).to_bytes(4,'little');meta=bytearray(8192);meta[4:8]=(3).to_bytes(4,'little')
        with connected({'file_data':(bytes(main),bytes(meta))}) as (e,port):
            lines=[x[4] for x in e['stdio_calls'] if x[0]=='format' and b'actual size 4294967295' in x[4]]
            self.assertTrue(lines);self.assertIn(b'meta actual size 0',lines[-1])
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0xd3de50)

    def test_emplace_rereads_cache_after_second_real_hash_without_cold_reset(self):
        def instrument(functions,r,calls):
            output=functions['__stdio_common_vfprintf']
            def actual(*args):
                result=output(*args)
                if b'loaded [nt_mmkv_msf_united_config]' in calls[-1][-1]:
                    cache=r.memory.load(r.image_base+0x6751388,8);r.memory.store(cache+8,1,8,source='controlled cache change before emplace')
                return result
            functions['__stdio_common_vfprintf']=actual;return functions
        with connected({'expected_error':'noncold MMKV map emplace'},transform=instrument) as (e,port):
            r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;cache=m.load(r.image_base+0x6751388,8)
            self.assertEqual(m.load(cache+8,8),1);self.assertEqual(m.load(cache+0x10,8),0)
            self.assertFalse([x for x in r.events if x[0]=='source.call' and x[1]==0x24c0])
            self.assertEqual(s['global_lock'],'held');self.assertEqual(m.load(s['parent'],8),0x31)

    def test_actual_meta_versions_and_flags_preserve_source_transitions(self):
        for version,flags,final_version,final_flags,c8 in ((6,0x123456789abcdef0,4,0,0),(4,1,4,1,1),(5,2,5,2,0)):
            meta=bytearray(8192);meta[4:8]=version.to_bytes(4,'little');meta[0x68:0x70]=flags.to_bytes(8,'little')
            with self.subTest(version=version),connected({'file_data':(bytes(8192),bytes(meta))}) as (e,port):
                r=e['runtime'];m=r.memory;p=port._WindowsMMKVHost__open['parent'];address=m.load(p+0x98,8)
                self.assertEqual((m.load(address+4,4),m.load(address+0x68,8),m.load(p+0xc8,1)),(final_version,final_flags,c8))
                self.assertEqual(m.read(address,0x70),m.read(port._WindowsMMKVHost__open['files'][1].load(0x30),0x70))
                if version==6:
                    values=[int.from_bytes(w[1],'little') for w in m.writes if w[0]==address+4]
                    self.assertIn(3,values);self.assertEqual(values[-1],4)

    def test_main_second_invalid_logs_parent_path_then_returns_without_inner_load(self):
        with connected({'open_false':True}) as (e,port):
            r=e['runtime'];m=r.memory;s=port._WindowsMMKVHost__open;p=s['parent']
            self.assertNotIn('inner_guard',s);self.assertEqual(m.load(p+0x80,8),0)
            self.assertFalse([x for x in r.events if x[0]=='source.crc'])
            logs=[x for x in r.events if x[0]=='1BDF22C.arguments' and x[2]==b'MMKV_IO.cpp']
            self.assertEqual([x[4] for x in logs],[0xc0,0x50])
            self.assertIs(logs[-1][-1][0].path,s['paths'][0]);self.assertEqual(m.load(p+0x88,1),0)
            self.assertEqual((s['global_lock'],s['boundary']),('released',0xd3de50))


class NativePrefix(unittest.TestCase):
    def test_native40_borrows_and_padding_cleanup_metadata_before_mmkv(self):
        snapshots=[];trace=[]
        def instrument(functions,r,calls):
            from qq_nt_replica.primary_logger import _String
            store=r.memory.store;load=r.memory.load
            class Events(list):
                def append(self,item):trace.append(('event',item));super().append(item)
            r.events=Events(r.events)
            def actual_store(address,value,size,**kw):
                trace.append(('store',kw.get('source'),address,value,size));return store(address,value,size,**kw)
            def actual_load(address,size,**kw):
                pending=getattr(r,'_mmkv_caller_pending',None)
                if pending and pending.get('log_frame')==address and size==8 and not snapshots:
                    array=pending['log_array'];m=r.memory;slots=[]
                    for index in range(3):
                        slot=array+40*index;region,start=m._span(slot,40);mask=bytes(region.initialized[start:start+40])
                        self.assertEqual(mask,bytes(8)+bytes([1])*8+bytes(16)+bytes([1])*4+bytes(4))
                        self.assertEqual(load(slot+0x20,4),11);slots.append(load(slot+8,8))
                    copies=[_String.read(r,pending[k]) for k in ('id_copy','path_copy','crypt_copy')]
                    self.assertEqual([x.value() for x in copies],[b'nt_mmkv_msf_united_config',b'',b''])
                    self.assertEqual(slots,[copies[0].get(16,8),pending['path_copy']+1,pending['crypt_copy']+1])
                    original=_String.read(r,pending['locals']);self.assertNotEqual(slots[0],original.get(16,8))
                    snapshots.append((dict(pending),slots))
                return load(address,size,**kw)
            r.memory.store=actual_store;r.memory.load=actual_load;return functions
        with connected(transform=instrument) as (e,port):
            self.assertEqual(len(snapshots),1);r=e['runtime'];pending,slots=snapshots[0];m=r.memory
            self.assertNotIn(slots[0],r._custom_allocator_backend.records)
            from qq_nt_replica.primary_logger import _String
            self.assertIn(_String.read(r,pending['locals']).get(16,8),r._custom_allocator_backend.records)
            copies=[x[1] for x in trace if x[0]=='event' and x[1][0]=='source.75B810'];self.assertEqual([x[1] for x in copies],[0x64cd9,0x64ce8,0x64cf7])
            cleanup=[x[2] for x in trace if x[:2]==('store','2896.variant11_RET')]
            self.assertEqual(cleanup,[pending['log_array']+80+32,pending['log_array']+40+32,pending['log_array']+32])
            events=[x for x in r.events if x[0]=='source.D3A81F' and x[2]==b'nt_wrapper_engine.cc']
            self.assertEqual(events[0][1:],(2,b'nt_wrapper_engine.cc',0x73c,b'',b'init misc mmkv, id=nt_mmkv_msf_united_config, path= crypt_key='))
            ntlog=next(i for i,x in enumerate(r.events) if x[0]=='source.64FBA');open_call=next(i for i,x in enumerate(r.events) if x[0]=='source.mmkv_open')
            self.assertLess(ntlog,open_call)
            destruct=[x[1] for x in r.events if x[0]=='source.64FBA.copy_dtor'];self.assertEqual(destruct,[pending['id_copy'],pending['path_copy'],pending['crypt_copy']])
            first_cleanup=next(i for i,x in enumerate(trace) if x[:2]==('store','2896.variant11_RET'))
            sink=next(i for i,x in enumerate(trace) if x[0]=='event' and x[1][0]=='source.D3A81F' and x[1][2]==b'nt_wrapper_engine.cc')
            self.assertLess(first_cleanup,sink)
            source_search=[x for x in r.events if x[0]=='source.3E6D680'][0]
            self.assertEqual(source_search[1:],(r.image_base+0x486b891,0x5c,r.image_base+0x486b8ae))

    def test_empty_byte_unknown_tail_wide_known_zero_and_caller_ownership(self):
        with connected() as (e,port):
            from qq_nt_replica.primary_memory import UnknownMemory
            r=e['runtime'];m=r.memory;p=r._mmkv_caller_pending;bytepath=p['bytepath'];wide=p['wide']
            region,offset=m._span(bytepath,24);self.assertEqual(bytes(region.initialized[offset:offset+24]),bytes([1,1])+bytes(22))
            self.assertEqual(m.read(bytepath,2),bytes(2))
            with self.assertRaises(UnknownMemory):m.read(bytepath+8,8)
            self.assertEqual(m.read(wide,24),bytes(24))
            self.assertTrue([x for x in r.events if x[0]=='source.discarded_unknown_long_candidate' and x[1]==bytepath+8])
            self.assertEqual([x for x in r.events if x[0]=='source.75C480'][-1][-1],(1<<64)-1)
            self.assertEqual(len([x for x in e['file_api'].calls if x[0]=='MultiByteToWideChar']),4)
            self.assertEqual(m.load(p['span'],8),p['locals']+0x19);self.assertEqual(m.load(p['span']+8,8),0)
            self.assertEqual(m.load(p['guard'],8),p['interface']+0x3b0)
            self.assertEqual(m.load(p['nt_pair'][0]+0x3c0,8),p['nt_pair'][0]+0x3c8)
            self.assertEqual(m.read(p['nt_pair'][0]+0x3c8,16),bytes(16))
            self.assertEqual(m.load(r.image_base+0x674d418,8),1)
            before=e['file_api'].calls[:]
            with patch.object(e['owner']._threads,'prepare_close',side_effect=AssertionError('dangerous retirement')):
                with self.assertRaises(ExceptionGroup):e['owner'].close()
            self.assertEqual(e['file_api'].calls,before);self.assertFalse(r._custom_allocator_backend.closed)

    def test_gate_uses_real_threshold_and_false_still_destroys_three_copies(self):
        def instrument(functions,r,calls):
            class Events(list):
                def append(self,item):
                    if item[0]=='source.75B810' and item[1]==0x64cd9:r.memory.store(r.image_base+0x67535d0,3,4,source='controlled warm threshold3')
                    super().append(item)
            r.events=Events(r.events);return functions
        with connected(transform=instrument) as (e,port):
            r=e['runtime'];self.assertEqual(r.memory.load(r.image_base+0x67535d0,4),3)
            self.assertTrue([w for w in r.memory.writes if w[2]=='D3AF48.threshold' and int.from_bytes(w[1],'little')==2])
            self.assertFalse([w for w in r.memory.writes if w[2]=='308A.variant11'])
            self.assertEqual(len([x for x in r.events if x[0]=='source.64FBA.copy_dtor']),3)
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0xd3de50)

    def test_actual_formatter_or_sink_write_failure_retains_native_arguments_and_copies(self):
        for stage,expected_tags in (('formatter',11),('sink',0xffffffff)):
            observed=[]
            def instrument(functions,r,calls):
                write=r.memory.write
                def actual(address,data,**kw):
                    result=write(address,data,**kw);pending=getattr(r,'_mmkv_caller_pending',None)
                    if pending and pending.get('log_frame') is not None and kw.get('source')=='508834.literal':
                        tag=r.memory.load(pending['log_array']+32,4)
                        if tag==expected_tags:
                            observed.append(address);raise RuntimeError('controlled NT '+stage+' failure')
                    return result
                r.memory.write=actual;return functions
            with self.subTest(stage=stage),connected({'expected_type':RuntimeError,'expected_error':'controlled NT '+stage},transform=instrument) as (e,port):
                from qq_nt_replica.primary_logger import _String
                from qq_nt_replica.primary_memory import UnknownMemory
                r=e['runtime'];m=r.memory;p=r._mmkv_caller_pending
                self.assertTrue(observed);self.assertIsNone(port._WindowsMMKVHost__open)
                self.assertEqual([m.load(p['log_array']+40*i+32,4) for i in range(3)],[expected_tags]*3)
                self.assertEqual(_String.read(r,p['id_copy']).value(),b'nt_mmkv_msf_united_config')
                self.assertIn(_String.read(r,p['id_copy']).get(16,8),r._custom_allocator_backend.records)
                self.assertFalse([x for x in r.events if x[0]=='source.64FBA.copy_dtor'])
                with self.assertRaises(UnknownMemory):m.read(p['bytepath'],1)
                before=e['file_api'].calls[:]
                with patch.object(e['owner']._threads,'prepare_close',side_effect=AssertionError('dangerous retirement')):
                    with self.assertRaises(ExceptionGroup):e['owner'].close()
                self.assertEqual(e['file_api'].calls,before);self.assertFalse(r._custom_allocator_backend.closed)


if __name__=='__main__':unittest.main()
