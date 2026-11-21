"""Controlled UCRT boundary only; never loads a DLL or writes actual stdout."""
import ctypes as C


def fake_ucrt(calls):
    def render(fmt,args):
        if fmt==b'version %s, page size %d, arch %s':return fmt%(C.string_at(args[0]),C.c_int32(args[1]&0xffffffff).value,C.string_at(args[2]))
        if fmt==b'fail to init critical section:%d':return fmt%C.c_int32(args[0]&0xffffffff).value
        if fmt==b'[%s] <%s:%d::%s> %s\n':return fmt%(C.string_at(args[0]),C.string_at(args[1]),C.c_int32(args[2]&0xffffffff).value,C.string_at(args[3]),C.string_at(args[4]))
        raise AssertionError(fmt)
    def vsprintf(options,buffer,capacity,fmt,locale,args):
        template=C.string_at(fmt);count=3 if template.startswith(b'version') else 1
        raw=render(template,(C.c_uint64*count).from_address(args))
        calls.append(('format',options,capacity,args,raw))
        part=raw[:capacity-1];C.memmove(buffer,part,len(part));C.c_ubyte.from_address(buffer+len(part)).value=0
        return len(raw)
    def output(options,file,fmt,locale,args):
        assert file==0x12345678
        raw=render(C.string_at(fmt),(C.c_uint64*5).from_address(args))
        calls.append(('stdout',options,file,raw));return -1
    def iob(index):
        assert index==1;calls.append(('iob',index));return 0x12345678
    return {'__stdio_common_vsprintf':vsprintf,'__stdio_common_vfprintf':output,'__acrt_iob_func':iob}


import unittest,sys
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'src')]


class StdioSubunit(unittest.TestCase):
    def fixture(self,transform=None):
        from test_primary_login_host_init import AttachPhase
        return AttachPhase()._scoped_native_port_case(stdio_transform=transform)

    def test_source_birth_full_options_two_calls_stdout_and_independent_root(self):
        def alter(functions,r,calls):
            real=functions['__stdio_common_vsprintf']
            def format(*args):
                result=real(*args)
                if len([x for x in calls if x[0]=='format'])==1:
                    r.memory.store(r.image_base+0x6749cc0,0x10000000124,8,source='controlled current options update')
                return result
            functions['__stdio_common_vsprintf']=format;return functions
        evidence=self.fixture(alter);r=evidence['runtime'];calls=evidence['stdio_calls']
        formatted=[x for x in calls if x[0]=='format'];output=[x for x in calls if x[0]=='stdout']
        self.assertEqual([x[1] for x in formatted],[0x26,0x10000000126])
        self.assertEqual(formatted[0][3],formatted[1][3])
        self.assertEqual(output[0][1],0x10000000124)
        self.assertNotEqual(output[0][2],r.image_base+0x6744008)
        self.assertEqual([x for x in calls if x[0]=='iob'],[('iob',1)])
        self.assertEqual(r.memory.load(r.image_base+0x67513c8,4),2)
        local=[x[1][1] for x in r.events if x[0]=='Login byte paths and owned wide root'][-1]
        temporary=r.memory.load(local+112,8);global_pointer=r.memory.load(r.image_base+0x67513a8,8)
        self.assertNotEqual(temporary,global_pointer)
        self.assertEqual(r.memory.read(global_pointer,len(b'C:\\data\\nt_data\\mmkv')*2),b'C:\\data\\nt_data\\mmkv'.decode().encode('utf-16-le'))

    def test_ordinary_negative_empty_still_outputs_and_initial_buffer_unknown(self):
        def alter(functions,r,calls):
            from qq_nt_replica.primary_memory import UnknownMemory
            def format(options,buffer,capacity,fmt,locale,args):
                # Probe the pinned source view by its active frame, never an invalid pointer.
                frame=[x[1][1] for x in r.events if x[0]=='1BDF22C message and uninitialized16B buffer'][-1]
                with self.assertRaises(UnknownMemory):r.memory.read(frame+32,16)
                calls.append(('negative',options,capacity));return -1
            functions['__stdio_common_vsprintf']=format;return functions
        evidence=self.fixture(alter);calls=evidence['stdio_calls']
        self.assertEqual(len([x for x in calls if x[0]=='negative']),1)
        self.assertTrue([x for x in calls if x[0]=='stdout'][0][3].endswith(b'> \n'))

    def test_second_negative_is_ignored_size_stays_first_result(self):
        observed=[]
        def alter(functions,r,calls):
            real=functions['__stdio_common_vsprintf'];output=functions['__stdio_common_vfprintf']
            def format(*args):
                if not observed:
                    n=real(*args);observed.append(n);return n
                C.memmove(args[1],b'X\0',2);calls.append(('second_ignored',args[0],args[2],args[5]));return -1
            def print(*args):
                import sys
                f=sys._getframe(1);message=f.f_locals['message']
                observed.append(message.get(8,8));return output(*args)
            functions['__stdio_common_vsprintf']=format;functions['__stdio_common_vfprintf']=print;return functions
        evidence=self.fixture(alter)
        self.assertEqual(observed[0],observed[1])
        self.assertTrue([x for x in evidence['stdio_calls'] if x[0]=='stdout'][0][3].endswith(b'> X\n'))

    def test_warm_installer_epoch_and_region_replacement_refused(self):
        from qq_nt_replica.primary_crt_stdio_options import read_options,install_fresh_image
        from qq_nt_replica.errors import InputError
        evidence=self.fixture();r=evidence['runtime'];owner=evidence['owner']
        self.assertEqual(read_options(r),0x24)
        with self.assertRaises(InputError):install_fresh_image(owner.signer)
        issuer=r._primary_allocator_issuer;epoch=issuer.epoch;issuer.epoch=object()
        with self.assertRaises(InputError):read_options(r)
        issuer.epoch=epoch
        r.memory.unmap(r.image_base+0x6749cc0)
        r.memory.map(r.image_base+0x6749cc0,bytearray((0x24).to_bytes(8,'little')),name='replacement is not birth',initialized=True)
        with self.assertRaises(InputError):read_options(r)

    def test_native_and_record_failures_sticky_not_ordinary_negative(self):
        from test_primary_login_host_init import AttachPhase
        for failure in ('api','record','stdout'):
            with self.subTest(failure=failure):
                def alter(functions,r,calls):
                    if failure=='api':
                        def fail(*args):raise RuntimeError('controlled stdio native failure')
                        functions['__stdio_common_vsprintf']=fail
                    elif failure=='record':
                        original=r.memory._record_native_write
                        def record(token,issuer,*,source):
                            if source=='system_UCRT.vsprintf.actual_buffer':raise RuntimeError('controlled stdio record failure')
                            return original(token,issuer,source=source)
                        r.memory._record_native_write=record
                    else:
                        def fail(*args):raise RuntimeError('controlled stdio stdout failure')
                        functions['__stdio_common_vfprintf']=fail
                    return functions
                AttachPhase()._scoped_native_port_case(stdio_transform=alter,stdio_failure=True)

    def test_prerequisite_and_or_failures_preserve_exact_projection(self):
        from test_primary_login_host_init import AttachPhase
        for failure in ('thread','write'):
            with self.subTest(failure=failure):AttachPhase()._scoped_native_port_case(stage_failure=failure)

    def test_injected_small_resize_keeps_inline_zero_fill_and_second_format(self):
        def alter(functions,r,calls):
            def format(options,buffer,capacity,fmt,locale,args):
                raw=b'Q'*20;part=raw[:capacity-1]
                C.memmove(buffer,part,len(part));C.c_ubyte.from_address(buffer+len(part)).value=0
                calls.append(('format',options,capacity,args,raw));return 20
            functions['__stdio_common_vsprintf']=format;return functions
        evidence=self.fixture(alter)
        self.assertEqual([x[2] for x in evidence['stdio_calls'] if x[0]=='format'],[16,21])
        tags=[x[2] for x in evidence['runtime'].memory.writes]
        self.assertIn('75D0F0.short_length',tags);self.assertNotIn('75D0F0.buffer',tags)

    def test_actual_terminal_method_revokes_without_reset_or_fclose(self):
        from test_primary_login_host_init import AttachPhase
        from unittest.mock import patch
        from qq_nt_replica.primary_sign import PrimaryRuntime
        from qq_nt_replica.primary_windows_allocator_issuer import WindowsAllocatorIssuer
        from qq_nt_replica.primary_windows_mmkv_host_init import WindowsMMKVHost
        from qq_nt_replica.primary_crt_stdio_options import read_options
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        evidence=AttachPhase()._scoped_native_port_case(defer_terminal=True)
        owner=evidence['owner'];r=evidence['runtime'];value=r.memory.load(r.image_base+0x6749cc0,8)
        # Explicit controlled completion of mocked host resources, not real OS teardown.
        owner._files.pending_handles=0;owner._files.cleanup_records=[]
        owner._bridge._closed=True;owner._bridge._close_status='unloaded'
        with patch.object(PrimaryRuntime,'_crt_call',return_value=1),patch.object(WindowsAllocatorIssuer,'retire'),patch.object(WindowsMMKVHost,'_api',evidence['mmkv_api']):
            owner.close()
        self.assertEqual(owner._state,'closed')
        with self.assertRaises(PrimarySemanticUnavailable):read_options(r)
        self.assertEqual(r.memory.load(r.image_base+0x6749cc0,8),value)

if __name__=='__main__':unittest.main()
