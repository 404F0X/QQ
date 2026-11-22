"""Synthetic API/ABI fixtures and finite File40 behavior checks; no OS file IO."""
import ctypes as C
import re,unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import contextmanager
import sys
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'src')]
from test_primary_mmkv_directory import read_wide


def file_ucrt(calls):
    def render(fmt,args):
        pattern=rb'%(ls|zu|[psdu])';parts=[];start=0
        for i,match in enumerate(re.finditer(pattern,fmt)):
            parts.append(fmt[start:match.start()]);kind=match[1];v=args[i]
            if kind==b'ls':parts.append(read_wide(v).encode())
            elif kind==b's':parts.append(C.string_at(v))
            elif kind==b'p':parts.append(('%016X'%v).encode())
            elif kind==b'zu':parts.append(str(v).encode())
            elif kind==b'u':parts.append(str(v&0xffffffff).encode())
            else:parts.append(str(C.c_int32(v&0xffffffff).value).encode())
            start=match.end()
        parts.append(fmt[start:]);return b''.join(parts)
    def format(options,buffer,capacity,fmt,locale,args):
        template=C.string_at(fmt);n=len(re.findall(rb'%(?:ls|zu|[psdu])',template));values=(C.c_uint64*n).from_address(args)
        text=render(template,values);calls.append(('format',options,capacity,args,text,tuple(values)))
        part=text[:capacity-1];C.memmove(buffer,part,len(part));C.c_ubyte.from_address(buffer+len(part)).value=0;return len(text)
    def output(options,file,fmt,locale,args):
        assert file==0x12345678;text=render(C.string_at(fmt),(C.c_uint64*5).from_address(args));calls.append(('stdout',options,file,text));return -1
    return {'__stdio_common_vsprintf':format,'__stdio_common_vfprintf':output,'__acrt_iob_func':lambda index:0x12345678}


class PhysicalFiles:
    def __init__(self,options):self.options=options;self.calls=[];self.buffers=[];self.handles={};self.next=options.get('handle_start',100);self.last=5;self.position={};self.sizes={};self.map_sizes={};self.map_files={};self.data={};self.write_calls=0;self.lock_calls=0;self.unlock_calls=0
    def __call__(self,name,*args):
        self.calls.append((name,args))
        if self.options.get('raise')==name:raise RuntimeError('controlled file API failure '+name)
        if name=='MultiByteToWideChar':
            assert args[:2]==(65001,0) and args[3]==-1
            raw=C.string_at(args[2]).decode('utf-8').encode('utf-16-le')+b'\0\0'
            if args[4] and self.options.get('convert_false'):return 0
            if args[4]:C.memmove(args[4],raw,len(raw))
            return len(raw)//2
        if name in ('EnterCriticalSection','LeaveCriticalSection'):return
        if name=='CreateFileW':
            assert args[1:]==(0xc0000000,7,0,4,0x80,0)
            if self.options.get('open_false') or self.options.get('open_false_crc') and read_wide(args[0]).endswith('.crc'):return (1<<64)-1
            self.next+=1;self.handles[self.next]=read_wide(args[0])
            initial=self.options.get('file_data')
            raw=initial[len(self.handles)-1] if initial is not None else b'\xcc'*self.options.get('initial_size',0)
            self.sizes[self.next]=len(raw);self.data[self.next]=bytearray(raw);return self.next
        if name=='GetLastError':return self.last if self.options.get('lock_script') or self.options.get('unlock_script') else self.options.get('last_error',self.last)
        if name=='LockFileEx':
            assert args[1:5] in ((2,0,1,0),(0,0,1,0));C.c_uint32.from_address(args[5]).value=0x1234
            self.lock_calls+=1
            if self.options.get('lock_raise_at')==self.lock_calls:raise RuntimeError('controlled file API failure LockFileEx')
            result,error=self.options.get('lock_script',{}).get(self.lock_calls,(0 if self.options.get('lock_false') else 1,self.options.get('last_error',5)));self.last=error;return result
        if name=='UnlockFileEx':
            self.unlock_calls+=1;result,error=self.options.get('unlock_script',{}).get(self.unlock_calls,(0 if self.options.get('unlock_false') else 1,self.options.get('last_error',5)));self.last=error;return result
        if name=='GetFileSizeEx':
            if self.options.get('size_false'):return 0
            C.c_uint64.from_address(args[1]).value=self.sizes[args[0]];return 1
        if name=='SetFilePointerEx':self.position[args[0]]=args[1];return 0 if self.options.get('seek_false') else 1
        if name=='SetEndOfFile':
            size=self.position[args[0]];old=self.data[args[0]]
            self.data[args[0]]=old[:size]+bytearray(b'\xcc'*max(0,size-len(old)));self.sizes[args[0]]=size;return 1
        if name=='WriteFile':
            assert C.string_at(args[1],args[2])==bytes(args[2]);self.write_calls+=1
            if self.options.get('write_fail_at')==self.write_calls:
                C.c_uint32.from_address(args[3]).value=0;return 0
            count=self.options.get('written',args[2]);C.c_uint32.from_address(args[3]).value=count
            start=self.position[args[0]];self.data[args[0]][start:start+count]=C.string_at(args[1],count);self.position[args[0]]+=count
            return 1
        if name=='CreateFileMappingW':
            if self.options.get('map_false') or not self.sizes[args[0]]:return 0
            self.next+=1;self.map_sizes[self.next]=self.sizes[args[0]];self.map_files[self.next]=args[0];return self.next
        if name=='MapViewOfFile':
            assert args[1:]==(0xf001f,0,0,0)
            raw=bytes(self.data[self.map_files[args[0]]]);data=C.create_string_buffer(raw,len(raw));self.buffers.append(data);return C.addressof(data)
        if name=='UnmapViewOfFile':return 0 if self.options.get('unmap_false') else 1
        if name=='CloseHandle':return 0 if self.options.get('close_false') else 1
        raise AssertionError(name)


@contextmanager
def connected(options=None,transform=None):
    import test_primary_login_host_init as host
    from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime
    e=host.AttachPhase()._scoped_native_port_case(directory={} if options is None else options,connected=True,defer_terminal=True,page_size=(options or {}).get('page',8192),stdio_transform=transform)
    r=e['runtime'];port=for_runtime(r)
    try:yield e,port
    finally:
        # Synthetic-only resources, never production force cleanup of native debt.
        for token,record in list(r.memory._PrimaryMemory__native_pins.items()):r.memory._unpin_native_span(token,record[3])


class FileChecks(unittest.TestCase):
    def test_two_file_parameters_real_native_alias_and_overlapped_lifetime(self):
        with connected() as (e,port):
            r=e['runtime'];session=port._WindowsMMKVHost__open
            self.assertEqual(len(session['files']),2)
            for f in session['files']:
                guest=f.load(0x30);record=port._WindowsMMKVHost__views[guest]
                C.c_ubyte.from_address(record['raw']).value=91;self.assertEqual(r.memory.read(guest,1),b'[')
                r.memory.write(guest+1,b'X',source='controlled guest mapping write');self.assertEqual(C.c_ubyte.from_address(record['raw']+1).value,88)
                self.assertEqual(f.load(0x38),8192)
            calls=e['file_api'].calls
            self.assertEqual(len([x for x in calls if x[0]=='CreateFileW']),2)
            lock=[x[1] for x in calls if x[0]=='LockFileEx'];unlock=[x[1] for x in calls if x[0]=='UnlockFileEx']
            self.assertEqual([x[5] for x in lock[:2]],[x[4] for x in unlock[:2]])
            self.assertEqual(lock[-1][1],0)

    def test_false_file_lock_continues_and_unlock9e_is_accepted(self):
        for options in ({'lock_false':True},{'unlock_false':True,'last_error':0x9e}):
            with connected(options) as (e,port):
                self.assertEqual(port._WindowsMMKVHost__open['boundary'],0xd3de50)
                self.assertEqual(len(port._WindowsMMKVHost__open['files']),2)

    def test_normal_destructor_double_close_pathlast_no_outer_free(self):
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
        with connected() as (e,port):
            r=e['runtime'];f=port._WindowsMMKVHost__open['files'][0];api=e['file_api'];address=f.address;api.options['close_false']=True
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVHost,'_api',side_effect=lambda name,result,types,*args:api(name,*args)),patch.object(WindowsMMKVStdio,'_load',return_value=file_ucrt([])):
                f.destroy()
            closes=[args for name,args in api.calls if name=='CloseHandle' and args[0]==f.load(0x18)]
            self.assertEqual(len(closes),2);self.assertIn(address,r._custom_allocator_backend.records)

    def test_view_borrow_preflight_revoking_denies_and_success_revokes_before_observer(self):
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
        with connected() as (e,port):
            r=e['runtime'];f=port._WindowsMMKVHost__open['files'][0];guest=f.load(0x30);api=e['file_api']
            token,view=r.memory._pin_native_span(guest,1,self);before=len(api.calls)
            call=lambda name,result,types,*args:api(name,*args)
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVHost,'_api',side_effect=call),patch.object(WindowsMMKVStdio,'_load',return_value=file_ucrt([])):
                with self.assertRaises(PrimaryMemoryLimit):f.clear()
                self.assertEqual(len(api.calls),before)
                r.memory._unpin_native_span(token,self);view.release()
                def observing(name,result,types,*args):
                    if name=='UnmapViewOfFile':
                        with self.assertRaises(PrimaryMemoryLimit):r.memory.read(guest,1)
                    return api(name,*args)
                with patch.object(WindowsMMKVHost,'_api',side_effect=observing):f.clear()
            with self.assertRaises(PrimaryMemoryLimit):r.memory.read(guest,1)
            self.assertNotIn(guest,port._WindowsMMKVHost__views)

    def test_unmap_false_clears_source_but_retains_unreadable_host_debt(self):
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
        with connected() as (e,port):
            r=e['runtime'];f=port._WindowsMMKVHost__open['files'][0];guest=f.load(0x30);api=e['file_api'];api.options['unmap_false']=True
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVHost,'_api',side_effect=lambda name,result,types,*args:api(name,*args)),patch.object(WindowsMMKVStdio,'_load',return_value=file_ucrt([])):f.clear()
            self.assertEqual(f.load(0x30),0);self.assertIn(guest,port._WindowsMMKVHost__views)
            with self.assertRaises(PrimaryMemoryLimit):r.memory.read(guest,1)

    def test_failed_revocation_bookkeeping_keeps_guest_access_denied(self):
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        with connected() as (e,port):
            r=e['runtime'];f=port._WindowsMMKVHost__open['files'][0];guest=f.load(0x30);api=e['file_api']
            class FailingRegions(list):
                def __delitem__(self,index):
                    if self[index].address==guest:raise RuntimeError('controlled post-unmap bookkeeping failure')
                    return super().__delitem__(index)
            r.memory._regions=FailingRegions(r.memory._regions)
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVHost,'_api',side_effect=lambda name,result,types,*args:api(name,*args)):
                with self.assertRaisesRegex(RuntimeError,'bookkeeping'):f.clear()
            with self.assertRaises(PrimaryMemoryLimit):r.memory.read(guest,1)

    def test_non4096_page_and_failed_resize_restore_memory_only_with_u64_log(self):
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
        with connected({'page':12288,'handle_start':0x1234000000000000}) as (e,port):
            f=port._WindowsMMKVHost__open['files'][0];api=e['file_api'];self.assertEqual(f.load(0x38),12288)
            api.options['seek_false']=True;logs=[];target=0x100005000
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVHost,'_api',side_effect=lambda name,result,types,*args:api(name,*args)),patch.object(WindowsMMKVStdio,'_load',return_value=file_ucrt(logs)):
                self.assertFalse(f.resize(target))
            self.assertEqual(f.load(0x38),12288)
            formatted=[row for row in logs if row[0]=='format']
            self.assertTrue(any(target in row[-1] for row in formatted))
            self.assertTrue(any(f.load(0x18) in row[-1] for row in e['stdio_calls'] if row[0]=='format'))

    def test_ordinary_open_failure_has_two_source_calls_per_file_and_continues(self):
        with connected({'open_false':True}) as (e,port):
            opens=[args for name,args in e['file_api'].calls if name=='CreateFileW']
            self.assertEqual(len(opens),6) # original two each, then both real reload positions
            self.assertEqual([read_wide(args[0]).endswith('.crc') for args in opens],[False,False,True,True,True,False])
            self.assertEqual(port._WindowsMMKVHost__open['global_lock'],'released')
            self.assertEqual(port._WindowsMMKVHost__open['boundary'],0xd3de50)
            narrow=[x for x in e['stdio_calls'] if x[0]=='format' and x[4].startswith(b'file [')]
            self.assertEqual(narrow[-1][4],b'file [C] not valid')
            self.assertFalse([x for x in e['file_api'].calls if x[0]=='LockFileEx'])

    def test_api_exception_or_permit_denial_retains_debt_before_retirement(self):
        with connected({'raise':'EnterCriticalSection'}) as (e,port):
            self.assertEqual(port._WindowsMMKVHost__open['global_lock'],'enter_unknown')
            self.assertTrue(port._WindowsMMKVHost__failures)
        with connected({'deny':'MapViewOfFile'}) as (e,port):
            session=port._WindowsMMKVHost__open
            self.assertEqual(session['global_lock'],'held');self.assertIsNone(session['boundary'])
            self.assertTrue(session['files'][0].load(0x28));self.assertEqual(session['files'][0].load(0x30),0)

    def test_failed_conversion_keeps_unknown_consumption_and_mode0_storage(self):
        with connected({'convert_false':True}) as (e,port):
            r=e['runtime'];session=port._WindowsMMKVHost__open
            self.assertEqual(session['global_lock'],'held');self.assertIsNone(session['boundary'])
            self.assertEqual(len(session['files']),0)
            retained=[item for item in session['buffers'] if isinstance(item,tuple)]
            self.assertTrue(retained);self.assertIn(retained[0][3],r._custom_allocator_backend.records)

    def test_failed_getsize_keeps_original_zero_field_without_geterror(self):
        with connected({'size_false':True}) as (e,port):
            r=e['runtime']
            for file in port._WindowsMMKVHost__open['files']:
                self.assertEqual(file.load(0x38),8192)
                zero_stores=[row for row in r.memory.writes if row[0]==file.address+0x38 and row[1]==bytes(8)]
                self.assertEqual(zero_stores,[])
            self.assertFalse([x for x in e['file_api'].calls if x[0]=='GetLastError'])

    def test_failed_unlock_keeps_source_counter_and_pin_after_guard_clears(self):
        with connected({'unlock_false':True,'last_error':5}) as (e,port):
            r=e['runtime'];lock=port._WindowsMMKVHost__open['locks'][0]
            self.assertIsNone(lock.guard);self.assertEqual(r.memory.load(lock.address+0x10,8),1)
            r.memory._validate_native_pin(lock.token,port)

    def test_zero_fill_partial_full_block_then_ignored_tail_count(self):
        with connected({'initial_size':11480,'page':4096,'written':0}) as (e,port):
            # 12288-11480=808; tail TRUE ignores its zero bytesWritten result.
            writes=[args for name,args in e['file_api'].calls if name=='WriteFile']
            self.assertEqual([args[2] for args in writes],[808,808])
            self.assertTrue(all(file.load(0x38)==12288 for file in port._WindowsMMKVHost__open['files']))

    def test_resize_raw_then_aligned_store_and_equal_short_circuit(self):
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
        with connected() as (e,port):
            r=e['runtime'];file=port._WindowsMMKVHost__open['files'][0];api=e['file_api'];start=len(r.memory.writes)
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVHost,'_api',side_effect=lambda name,result,types,*args:api(name,*args)),patch.object(WindowsMMKVStdio,'_load',return_value=file_ucrt([])):
                self.assertTrue(file.resize(9000))
                stores=[int.from_bytes(row[1],'little') for row in r.memory.writes[start:] if row[0]==file.address+0x38]
                self.assertEqual(stores,[9000,16384])
                before=(len(r.memory.writes),len(api.calls));self.assertTrue(file.resize(16384))
                self.assertEqual((len(r.memory.writes),len(api.calls)),before)

    def test_partial_write_failure_restores_only_memory_and_maps_actual_extended_file(self):
        with connected({'written':2048,'write_fail_at':2}) as (e,port):
            r=e['runtime'];first=port._WindowsMMKVHost__open['files'][0];api=e['file_api']
            stores=[int.from_bytes(row[1],'little') for row in r.memory.writes if row[0]==first.address+0x38]
            self.assertIn(0,stores[1:]);self.assertEqual(stores[-1],8192)
            self.assertEqual(first.load(0x38),8192);self.assertEqual(first.native_extent,8192)
            self.assertEqual(api.sizes[first.load(0x18)],8192)
            view=first.load(0x30);self.assertNotEqual(view,0)
            self.assertEqual(r.memory.read(view,2048),bytes(2048))
            self.assertEqual(r.memory.read(view+2048,1),b'\xcc')
            writes=[args[2] for name,args in api.calls if name=='WriteFile']
            self.assertEqual(writes[:2],[4096,4096])

    def test_map_failure_closes_file_before_unlocking_saved_old_handle(self):
        with connected({'map_false':True,'unlock_false':True,'last_error':0x9e}) as (e,port):
            calls=e['file_api'].calls;first=port._WindowsMMKVHost__open['files'][0]
            lock=next(args for name,args in calls if name=='LockFileEx')
            closed=next(i for i,(name,args) in enumerate(calls) if name=='CloseHandle' and args[0]==lock[0])
            unlocked=next(i for i,(name,args) in enumerate(calls) if name=='UnlockFileEx' and args[0]==lock[0])
            self.assertLess(closed,unlocked);self.assertEqual(first.load(0x18),(1<<64)-1)


class ViewIdentityChecks(unittest.TestCase):
    def replacements(self,e,port):
        from qq_nt_replica.primary_memory import PrimaryMemory
        from types import SimpleNamespace
        r=e['runtime'];o=e['owner'];signer=o._signer;allocator=r._custom_allocator_backend
        image=r._shared_locale_source;module=signer._module_sync_image
        return (
            ('issuer owner',port,'_WindowsMMKVHost__owner',object()),
            ('owner signer',o,'_signer',SimpleNamespace(runtime=r)),
            ('signer runtime',signer,'runtime',object()),
            ('issuer runtime',port,'_WindowsMMKVHost__runtime',object()),
            ('memory',r,'memory',PrimaryMemory()),
            ('image base',r,'image_base',r.image_base+0x1000),
            ('image source bridge',r,'_shared_locale_source',object()),
            ('image epoch bridge',r,'_shared_locale_source_epoch',object()),
            ('original image',signer,'_shared_locale_image',object()),
            ('image epoch',image,'epoch',object()),
            ('module epoch',module,'epoch',object()),
            ('module owner',module,'owner',object()),
            ('runtime allocator',r,'_custom_allocator_backend',object()),
            ('issuer allocator',port,'_WindowsMMKVHost__allocator',object()),
            ('allocator source',allocator,'source',SimpleNamespace(epoch=allocator.source.epoch)),
            ('allocator epoch',allocator.source,'epoch',object()),
            ('allocator bridge epoch',r,'_primary_allocator_selector_epoch',object()),
            ('allocator issuer',r,'_primary_allocator_issuer',object()),
            ('allocation issuer epoch',r._primary_allocator_issuer,'epoch',object()),
            ('terminal issuer',port,'_WindowsMMKVHost__terminal',True),
        )

    def test_stale_identity_rejects_direct_guest_read_write_pin_without_side_effects(self):
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;file=port._WindowsMMKVHost__open['files'][0];guest=file.load(0x30)
            raw=port._WindowsMMKVHost__views[guest]['raw'];original=m.read(guest,1)
            before=(len(m.writes),len(m._PrimaryMemory__native_pins),len(e['file_api'].calls))
            for name,target,attribute,replacement in self.replacements(e,port):
                with self.subTest(replacement=name),patch.object(target,attribute,replacement):
                    for operation in (lambda:m.read(guest,1),lambda:m.write(guest,b'Z',source='stale guest write'),lambda:m._pin_native_span(guest,1,self)):
                        with self.assertRaises((InputError,PrimaryMemoryLimit)):operation()
                    self.assertEqual(C.string_at(raw,1),original)
                    self.assertEqual((len(m.writes),len(m._PrimaryMemory__native_pins),len(e['file_api'].calls)),before)
                self.assertEqual(m.read(guest,1),original)
            self.assertEqual(r._primary_allocator_selector.phase,'complete')

    def test_identity_change_between_source_check_and_revoke_rejects_before_api(self):
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;file=port._WindowsMMKVHost__open['files'][0];guest=file.load(0x30)
            for name,target,attribute,replacement in self.replacements(e,port):
                original=getattr(target,attribute);load=file.load;count=[0];before=len(e['file_api'].calls)
                def changed_after_read(offset):
                    value=load(offset)
                    if offset==0x30:
                        count[0]+=1
                        if count[0]==2:setattr(target,attribute,replacement)
                    return value
                with self.subTest(replacement=name),e['owner']._registrar.operation(),patch.object(file,'load',side_effect=changed_after_read):
                    try:
                        with self.assertRaises((InputError,PrimaryMemoryLimit)):file.clear()
                    finally:setattr(target,attribute,original)
                self.assertEqual(count[0],2)
                self.assertEqual(len(e['file_api'].calls),before)
                self.assertEqual(port._WindowsMMKVHost__views[guest]['state'],'live')
                self.assertEqual(m.read(guest,1),b'\0')

    def test_unissued_same_type_receipt_copy_rejects_access_and_revoke(self):
        from dataclasses import replace
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;file=port._WindowsMMKVHost__open['files'][0];guest=file.load(0x30)
            issued=port._WindowsMMKVHost__views[guest];alias=m._PrimaryMemory__view_aliases[issued['token']]
            identity=alias[6];copy=replace(identity);self.assertIsNot(copy,identity)
            original=m.read(guest,1);before=(len(m.writes),len(m._PrimaryMemory__native_pins),len(e['file_api'].calls))
            alias[6]=copy
            try:
                for operation in (lambda:m.read(guest,1),lambda:m.write(guest,b'X',source='unissued receipt'),lambda:m._pin_native_span(guest,1,self)):
                    with self.assertRaisesRegex(InputError,'unissued native view identity'):operation()
                with e['owner']._registrar.operation():
                    with self.assertRaisesRegex(InputError,'unissued native view identity'):file.clear()
                self.assertEqual((len(m.writes),len(m._PrimaryMemory__native_pins),len(e['file_api'].calls)),before)
                self.assertEqual(C.string_at(issued['raw'],1),original)
                self.assertEqual((issued['state'],alias[2],r._primary_allocator_selector.phase),('live','live','complete'))
                self.assertEqual(file.load(0x30),guest)
            finally:alias[6]=identity
            self.assertEqual(m.read(guest,1),original)
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVHost,'_api',side_effect=lambda name,result,types,*args:e['file_api'](name,*args)),patch.object(WindowsMMKVStdio,'_load',return_value=file_ucrt([])):file.clear()
            self.assertEqual(file.load(0x30),0)
            with self.assertRaises(PrimaryMemoryLimit):m.read(guest,1)
            self.assertNotIn(guest,port._WindowsMMKVHost__views)

    def test_guest_access_needs_no_execution_lease_or_native_permit(self):
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;guest=port._WindowsMMKVHost__open['files'][0].load(0x30)
            with patch.object(e['owner']._registrar,'current_lease',side_effect=AssertionError('guest requested lease')),patch.object(port,'_WindowsMMKVHost__permit',side_effect=AssertionError('guest requested permit')):
                self.assertEqual(m.read(guest,1),b'\0');m.write(guest,b'A',source='ordinary guest alias write')
                token,view=m._pin_native_span(guest,1,self)
                self.assertEqual(bytes(view),b'A');m._unpin_native_span(token,self);view.release()

    def test_issued_region_replacement_backing_and_extent_are_rejected(self):
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;file=port._WindowsMMKVHost__open['files'][0];guest=file.load(0x30)
            region,_=m._span(guest,1);index=next(i for i,item in enumerate(m._regions) if item is region)
            other=type(region)(region.address,memoryview(bytearray(len(region.data))),bytearray(region.initialized),region.name)
            def attempt(address):
                for operation in (lambda:m.read(address,1),lambda:m.write(address,b'X',source='replaced view'),lambda:m._pin_native_span(address,1,self)):
                    with self.assertRaises((InputError,PrimaryMemoryLimit)):operation()
                before=len(e['file_api'].calls)
                with e['owner']._registrar.operation():
                    with self.assertRaises((InputError,PrimaryMemoryLimit)):file.clear()
                self.assertEqual(len(e['file_api'].calls),before)
            try:
                m._regions[index]=other;attempt(guest)
            finally:m._regions[index]=region;other.data.release()
            backing=region.data;replacement=backing[:-1]
            try:region.data=replacement;attempt(guest)
            finally:region.data=backing;replacement.release()
            try:
                region.address=guest+0x100000
                attempt(guest);attempt(region.address)
            finally:region.address=guest
            self.assertEqual(m.read(guest,1),b'\0')

    def test_independent_observer_after_unmap_before_source_clear_cannot_read_view(self):
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
        with connected() as (e,port):
            r=e['runtime'];m=r.memory;file=port._WindowsMMKVHost__open['files'][0];guest=file.load(0x30);api=e['file_api'];store=file.store;observed=[]
            def observer(offset,value):
                if offset==0x30:
                    self.assertEqual(value,0);self.assertEqual(file.load(0x30),guest)
                    self.assertEqual(api.calls[-1][0],'UnmapViewOfFile')
                    with self.assertRaises(PrimaryMemoryLimit):m.read(guest,1)
                    self.assertNotIn(guest,port._WindowsMMKVHost__views);observed.append('revoked before caller publication')
                return store(offset,value)
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVHost,'_api',side_effect=lambda name,result,types,*args:api(name,*args)),patch.object(WindowsMMKVStdio,'_load',return_value=file_ucrt([])),patch.object(file,'store',side_effect=observer):file.clear()
            self.assertEqual(observed,['revoked before caller publication'])


if __name__=='__main__':unittest.main()
