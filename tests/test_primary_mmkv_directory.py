"""Finite source directory and UTF16 ABI; every physical boundary is controlled."""
import ctypes as C
from contextlib import contextmanager
from unittest.mock import patch
import unittest
from pathlib import Path
import sys
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'src')]


def read_wide(pointer):
    # Windows WCHAR is16-bit even if these controlled checks run elsewhere.
    units=[]
    for index in range(201):
        value=C.c_uint16.from_address(pointer+2*index).value
        if not value:return bytes().join(x.to_bytes(2,'little') for x in units).decode('utf-16-le')
        units.append(value)
    raise AssertionError('unterminated finite WCHAR argument')


@contextmanager
def case(options=None,transform=None):
    from test_primary_login_host_init import AttachPhase
    from qq_nt_replica.primary_windows_mmkv_host_init import for_runtime as host_for
    from qq_nt_replica.primary_windows_mmkv_stdio import for_runtime as stdio_for
    evidence=AttachPhase()._scoped_native_port_case(directory={} if options is None else options,stdio_transform=transform,defer_terminal=True)
    r=evidence['runtime'];owner=evidence['owner'];host=host_for(r);stdio=stdio_for(r)
    try:yield evidence,host,stdio
    finally:
        # Synthetic-only cleanup after retention assertions; never production recovery.
        record=host._WindowsMMKVHost__directory
        if record is not None:
            try:r.memory._unpin_native_span(record[1],host);record[2].release()
            except Exception:pass
        for record in stdio._WindowsMMKVStdio__widepins.values():
            for arg,pin,view,native in record:
                r.memory._unpin_native_span(pin,stdio);view.release()
        for pin,(view,native) in stdio._WindowsMMKVStdio__pins.items():
            r.memory._unpin_native_span(pin,stdio);view.release()
        lock=host._WindowsMMKVHost__lock
        if lock is not None:
            r.memory._unpin_native_span(lock.token,host);lock.view.release()
        port=r._outer_sync_port
        for record in port._WindowsOuterSync__records.values():
            r.memory._unpin_native_span(record.token,port);record.view.release()


class Directory(unittest.TestCase):
    def test_real_prefix_exact_drive_queries_and_next_boundary(self):
        with case() as (e,host,stdio):
            r=e['runtime'];m=r.memory;b=r.image_base
            self.assertEqual(e['prefixes'],['C:','C:\\data','C:\\data\\nt_data','C:\\data\\nt_data\\mmkv'])
            self.assertEqual(m.load(b+0x67513c8,4),2)
            stopped=[x for x in r.events if x[0]=='source.unavailable'][-1]
            self.assertEqual((stopped[1],stopped[3:]),(0xb99200,(2,0,0,0)))
            obj=m.load(b+0x674c730,8);self.assertEqual(m.read(obj+0x90,16),bytes(16))
            self.assertIsNone(host._WindowsMMKVHost__directory)
            writes=[x for x in m.writes if x[2]=='1BD8FE3.write_backslash_even_final_NUL']
            dup=[x for x in m.writes if x[2]=='3E90050.duplicate_UTF16_with_NUL'][-1]
            self.assertEqual(writes[-1][0],dup[0]+len(dup[1])-2)
            frees=[x for x in r.events if x[0]=='HeapFree' and x[-1]==dup[0]]
            self.assertEqual(len(frees),1)
            globalptr=m.load(b+0x67513a8,8);self.assertNotEqual(dup[0],globalptr)
            self.assertEqual(m.read(globalptr,len(dup[1])),dup[1])
            logs=[x for x in r.events if x[0]=='1BDF22C.arguments']
            self.assertEqual(logs[-1][1:6],(1,b'MMKV.cpp',b'initializeMMKV',0xe9,b'root dir: %ls'))
            self.assertTrue([x for x in e['stdio_calls'] if x[0]=='stdout'][-1][3].endswith(b'root dir: C:\\data\\nt_data\\mmkv\n'))

    def test_create_success_and_both_ordinary_failures_log_original_root(self):
        for options,template in (({'attrs':0xffffffff},None),({'attrs':0x80000000},b'%ls attribute:%d not a directry'),({'attrs':0xffffffff,'create':0,'error':0x80000005},b'fail to create dir:%ls, %d')):
            with self.subTest(options=options),case(options) as (e,host,stdio):
                calls=e['api_calls'];r=e['runtime']
                if options.get('create')==0:
                    index=calls.index('CreateDirectoryW');self.assertEqual(calls[index+1],'GetLastError')
                    trace=options['trace'];index=trace.index(('api','CreateDirectoryW'));self.assertEqual(trace[index+1],('api','GetLastError'))
                logs=[x for x in r.events if x[0]=='1BDF22C.arguments']
                if template:
                    self.assertEqual(logs[-2][5],template)
                    self.assertEqual(logs[-2][6][0].pointer,r.memory.load(r.image_base+0x67513a8,8))
                    outputs=[x[3] for x in e['stdio_calls'] if x[0]=='stdout']
                    self.assertIn(b'-2147483643' if options.get('create')==0 else b'-2147483648',outputs[-2])
                self.assertEqual(logs[-1][5],b'root dir: %ls')
                self.assertIsNone(host._WindowsMMKVHost__directory)

    def test_wide_pin_lives_across_both_formats_and_output(self):
        seen=[]
        def alter(functions,r,calls):
            real=functions['__stdio_common_vsprintf'];out=functions['__stdio_common_vfprintf']
            def verify():
                from qq_nt_replica.primary_memory import PrimaryMemoryLimit
                with self.assertRaises(PrimaryMemoryLimit):r.memory.forget(r.memory.load(r.image_base+0x67513a8,8),2,source='test invalidation')
            def format(*args):
                if C.string_at(args[3])==b'root dir: %ls':
                    verify();vector=(C.c_uint64*1).from_address(args[5]);seen.append((args[5],vector[0],read_wide(vector[0])))
                    self.assertNotEqual(vector[0],r.memory.load(r.image_base+0x67513a8,8))
                return real(*args)
            def output(*args):
                if seen:verify();seen.append('output')
                return out(*args)
            functions['__stdio_common_vsprintf']=format;functions['__stdio_common_vfprintf']=output;return functions
        with case(transform=alter) as (e,host,stdio):
            self.assertEqual(len(seen),3);self.assertEqual(seen[0],seen[1]);self.assertEqual(seen[-1],'output')
            self.assertFalse(stdio._WindowsMMKVStdio__widepins)

    def test_exception_retains_workbuffer_and_blocks_terminal_without_free_retry(self):
        from qq_nt_replica.primary_mmkv_host_init import _directory,_WideArgument,_WIDE_TOKEN
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        with case() as (e,host,stdio):
            r=e['runtime'];owner=e['owner'];root=_WideArgument(r,r.image_base+0x6751398,_WIDE_TOKEN)
            failure=RuntimeError('controlled directory failure')
            with owner._registrar.operation(),patch.object(host,'_api',side_effect=failure):
                with self.assertRaises(RuntimeError) as caught:_directory(r,root)
                self.assertIs(caught.exception,failure)
                work=host._WindowsMMKVHost__directory[0]
                with self.assertRaises(PrimaryMemoryLimit):r.memory.forget(work.pointer,work.size,source='controlled premature invalidation')
                before=list(r.events)
                with self.assertRaises(PrimarySemanticUnavailable):_directory(r,root)
                self.assertEqual(r.events,before)
            owner._state='closing'
            with self.assertRaises(PrimarySemanticUnavailable):host.dispose_terminal()
            self.assertIn(work.pointer,r.allocations)

    def test_host_identity_lease_permit_and_foreign_buffer_rejected(self):
        from qq_nt_replica.primary_mmkv_host_init import _directory,_WideArgument,_WIDE_TOKEN
        from qq_nt_replica.errors import InputError
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with case() as (e,host,stdio):
            r=e['runtime'];owner=e['owner']
            with self.assertRaises(InputError):host._check(None)
            with owner._registrar.operation() as unused:
                with owner._registrar.current_lease().suspend():
                    with self.assertRaises(InputError):host._check(None)
                with self.assertRaises(InputError):host._directory_step(object())
                for field in ('_WindowsMMKVHost__epoch','_WindowsMMKVHost__base','_WindowsMMKVHost__pid','_WindowsMMKVHost__thread','_WindowsMMKVHost__memory'):
                    value=getattr(host,field);setattr(host,field,object())
                    with self.assertRaises(PrimarySemanticUnavailable):host._check(None)
                    setattr(host,field,value)
                host._WindowsMMKVHost__permit=lambda *args:False
                root=_WideArgument(r,r.image_base+0x6751398,_WIDE_TOKEN)
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'scope denied'):_directory(r,root)
            with owner._registrar.operation():
                before=list(r.events)
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'persistent native failure'):_directory(r,root)
                self.assertEqual(r.events,before)
            owner._state='closing'
            with self.assertRaises(PrimarySemanticUnavailable):host.dispose_terminal()

    def test_short_and_long_cstr_identity_and_forged_wide_rejected(self):
        from qq_nt_replica.primary_mmkv_host_init import _WideArgument,_WIDE_TOKEN
        from qq_nt_replica.primary_mmkv_log import log
        from qq_nt_replica.errors import InputError
        with case() as (e,host,stdio):
            r=e['runtime'];m=r.memory;address=r.image_base+0x6751398
            root=_WideArgument(r,address,_WIDE_TOKEN);self.assertEqual(root.pointer,m.load(address+16,8))
            raw='C:\\short'.encode('utf-16-le');m.write(address,bytes([len(raw)])+b'\0'+raw+bytes(24-2-len(raw)),source='controlled source short wide mechanical boundary')
            short=_WideArgument(r,address,_WIDE_TOKEN);self.assertEqual(short.pointer,address+2)
            with self.assertRaises(InputError):root.validate(r)
            from test_primary_mmkv_stdio import fake_ucrt
            from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
            with e['owner']._registrar.operation(),patch.object(WindowsMMKVStdio,'_load',return_value=fake_ucrt(e['stdio_calls'])):
                log(r,1,b'MMKV.cpp',b'initializeMMKV',0xe9,b'root dir: %ls',(short,))
                self.assertTrue([x for x in e['stdio_calls'] if x[0]=='stdout'][-1][3].endswith(b'root dir: C:\\short\n'))
                for arg in (b'C:\\short',address,object()):
                    with self.assertRaises(InputError):log(r,1,b'MMKV.cpp',b'initializeMMKV',0xe9,b'root dir: %ls',(arg,))

    def test_wide_output_exception_retains_borrow_and_terminal_blocks(self):
        from qq_nt_replica.primary_mmkv_host_init import _WideArgument,_WIDE_TOKEN
        from qq_nt_replica.primary_mmkv_log import log
        from qq_nt_replica.primary_windows_mmkv_stdio import WindowsMMKVStdio
        from qq_nt_replica.primary_memory import PrimaryMemoryLimit
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from test_primary_mmkv_stdio import fake_ucrt
        with case() as (e,host,stdio):
            r=e['runtime'];owner=e['owner'];root=_WideArgument(r,r.image_base+0x6751398,_WIDE_TOKEN)
            functions=fake_ucrt([]);failure=RuntimeError('controlled wide output failure')
            def fail(*args):raise failure
            functions['__stdio_common_vfprintf']=fail
            with owner._registrar.operation(),patch.object(WindowsMMKVStdio,'_load',return_value=functions):
                with self.assertRaises(RuntimeError) as caught:log(r,1,b'MMKV.cpp',b'initializeMMKV',0xe9,b'root dir: %ls',(root,))
                self.assertIs(caught.exception,failure)
            with self.assertRaises(PrimaryMemoryLimit):r.memory.forget(root.pointer,len(root.raw),source='premature root retirement')
            self.assertTrue(stdio._WindowsMMKVStdio__widepins)
            owner._state='closing'
            with self.assertRaises(PrimarySemanticUnavailable):stdio.dispose_terminal()

    def test_unknown_crt_allocation_domain_stops_and_preserves_first_failure(self):
        from qq_nt_replica.primary_mmkv_host_init import _directory,_WideArgument,_WIDE_TOKEN
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        with case() as (e,host,stdio):
            r=e['runtime'];owner=e['owner'];root=_WideArgument(r,r.image_base+0x6751398,_WIDE_TOKEN)
            invoke=r.invoke;failure=PrimarySemanticUnavailable('controlled CRT failure')
            def unavailable(vm,rva,cells):
                if rva==0x3e97020:raise failure
                return invoke(vm,rva,cells)
            with owner._registrar.operation(),patch.object(r,'invoke',side_effect=unavailable):
                with self.assertRaises(PrimarySemanticUnavailable) as caught:_directory(r,root)
                self.assertIs(caught.exception,failure)
                with self.assertRaises(PrimarySemanticUnavailable):_directory(r,root)
                self.assertIs(host._WindowsMMKVHost__failures[0],failure)
            owner._state='closing'
            with self.assertRaises(PrimarySemanticUnavailable):host.dispose_terminal()


if __name__=='__main__':unittest.main()
