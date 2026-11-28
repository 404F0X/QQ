"""Source-memory behavior, not native execution or a whole-message substitute."""
import hashlib
from types import SimpleNamespace
import unittest
from qq_nt_replica.primary_memory import PrimaryMemory,UnknownMemory,PrimaryMemoryLimit
from qq_nt_replica.primary_presend_stream import update,block,_copy
from qq_nt_replica.primary_worker_consumer import _invoke
from qq_nt_replica.primary_worker_response import _frame
from test_primary_client_configuration_request import client_factory
from test_primary_client_configuration_startup import creator


class Stream(unittest.TestCase):
    def test_boundaries_segmented_knownness_and_complete_erase(self):
        with client_factory() as (owner,k,physical):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                for length in (0,1,55,56,63,64,65,129):
                    with self.subTest(length=length):
                        context,unused=_frame(r,88,'explicit stream context');output,unused=_frame(r,16,'explicit digest')
                        data=bytes((i*17)&255 for i in range(length));pointer,unused=_frame(r,max(1,length),'explicit stream input')
                        if data:m.write(pointer,data,source='explicit test message')
                        _invoke(r,0x1D04800,context)
                        with self.assertRaises(UnknownMemory):m.read(context+24,64)
                        cut=min(length,13)
                        _invoke(r,0x1D05120,context,pointer,cut);_invoke(r,0x1D05120,context,pointer+cut,length-cut)
                        _invoke(r,0x1D05590,output,context)
                        self.assertEqual(m.read(output,16),hashlib.md5(data).digest())
                        self.assertEqual(m.read(context,88),bytes(88))
                with self.assertRaisesRegex(Exception,'3e67f50'):_invoke(r,0x3E67F50,0)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_count_carry_n0_and_high_unknown_retains_low_store(self):
        m=PrimaryMemory();m.map(0x1000,bytearray(88),name='ctx',initialized=True);r=SimpleNamespace(memory=m)
        m.store(0x1010,0xFFFFFFF8,4,source='counter');m.store(0x1014,7,4,source='counter')
        m.map(0x2000,b'a',name='input',initialized=True);update(r,0x1000,0x2000,1)
        self.assertEqual((m.load(0x1010,4),m.load(0x1014,4)),(0,8))
        update(r,0x1000,0xDEAD,1<<32);self.assertEqual(m.load(0x1010,4),0)
        m.forget(0x1014,4,source='fault')
        with self.assertRaises(UnknownMemory):update(r,0x1000,0xDEAD,0)
        self.assertEqual(m.writes[-1][2],'1D0514C.count_low')

    def test_copy_pair_load_failure_fill_partial_and_overlap(self):
        for count in (32,64):
            m=PrimaryMemory();m.map(0x1000,bytearray(88),name='ctx',initialized=True)
            m.map(0x2000,bytearray(b'a'*64),name='input',initialized=True);m.forget(0x2010,16,source='fault')
            with self.assertRaises(UnknownMemory):update(SimpleNamespace(memory=m),0x1000,0x2000,count)
            self.assertEqual(m.read(0x1018,16),bytes(16) if count==32 else b'a'*16)
        m=PrimaryMemory();m.map(0x1000,bytearray(88),name='ctx',initialized=True)
        m.store(0x1010,8,4,source='index1');m.write(0x1018,b'abcd',source='overlap')
        update(SimpleNamespace(memory=m),0x1000,0x1018,3)
        self.assertEqual(m.read(0x1018,4),b'aaaa')

    def test_block_oracle_alias_and_partial_feedforward(self):
        m=PrimaryMemory();iv=bytes.fromhex('0123456789abcdeffedcba9876543210')
        m.map(0x1000,bytearray(iv),name='state',initialized=True)
        m.map(0x2000,b'\x80'+bytes(63),name='block',initialized=True)
        block(SimpleNamespace(memory=m),0x1000,0x2000)
        self.assertEqual(m.read(0x1000,16),hashlib.md5(b'').digest())
        # Arbitrary state/input alias must equal an independent storage run.
        raw=bytes(range(64));other=PrimaryMemory();other.map(0x3000,bytearray(raw),name='alias',initialized=True)
        m2=PrimaryMemory();m2.map(0x1000,bytearray(raw[:16]),name='state',initialized=True);m2.map(0x2000,raw,name='input',initialized=True)
        block(SimpleNamespace(memory=m2),0x1000,0x2000);block(SimpleNamespace(memory=other),0x3000,0x3000)
        self.assertEqual(other.read(0x3000,16),m2.read(0x1000,16))
        f=PrimaryMemory();f.map(0x1000,bytearray(iv[:4]),name='first',initialized=True);f.map(0x1004,iv[4:8],name='readonly second',initialized=True);f.map(0x1008,bytearray(iv[8:]),name='rest',initialized=True);f.map(0x2000,b'\x80'+bytes(63),name='input',initialized=True)
        with self.assertRaises(PrimaryMemoryLimit):block(SimpleNamespace(memory=f),0x1000,0x2000)
        self.assertEqual(f.read(0x1000,4),hashlib.md5(b'').digest()[:4]);self.assertEqual(f.read(0x1004,4)+f.read(0x1008,8),iv[4:])

    def test_mutable_padding_partialunknown_and_replacement_denial(self):
        with client_factory() as (owner,k,physical):
            r=owner.signer.runtime;m=r.memory;pad=r.image_base+0x618C920
            with creator(owner):
                m.write(pad,b'\x81',source='actual mutable padding');m.forget(pad+63,1,source='unread tail')
                context,unused=_frame(r,88,'padding ctx');out,unused=_frame(r,16,'padding out');_invoke(r,0x1D04800,context);_invoke(r,0x1D05590,out,context)
                self.assertNotEqual(m.read(out,16),hashlib.md5(b'').digest());self.assertEqual(m.load(pad,1),0x81)
                context,unused=_frame(r,88,'padding fault ctx');_invoke(r,0x1D04800,context);m.forget(pad+32,1,source='read fault')
                with self.assertRaises(UnknownMemory):_invoke(r,0x1D05590,out,context)
                self.assertEqual(m.load(context+16,4),448)
                region,offset=m._span(pad,64);original=region.initialized
                try:
                    region.initialized=bytearray(original)
                    context,unused=_frame(r,88,'foreign mask ctx');_invoke(r,0x1D04800,context)
                    with self.assertRaisesRegex(Exception,'backing/mask'):_invoke(r,0x1D05590,out,context)
                finally:region.initialized=original
                from qq_nt_replica.primary_client_configuration_scope import image_for
                image=image_for(r);original_receipt=image.padding
                try:
                    image.padding=tuple(list(original_receipt))
                    context,unused=_frame(r,88,'foreign receipt ctx');_invoke(r,0x1D04800,context)
                    with self.assertRaisesRegex(Exception,'receipt replaced'):_invoke(r,0x1D05590,out,context)
                finally:image.padding=original_receipt
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_output_alias_rereads_and_no_erase_after_output_failure(self):
        with client_factory() as (owner,k,physical):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                ctx,unused=_frame(r,88,'alias ctx');_invoke(r,0x1D04800,ctx);before=len(m.writes);_invoke(r,0x1D05590,ctx+1,ctx)
                emitted=[raw for a,raw,label in m.writes[before:] if label=='1D05590.output_BYTE']
                self.assertEqual(emitted,[hashlib.md5(b'').digest()[:1]]*16)
                ctx,unused=_frame(r,88,'failure ctx');_invoke(r,0x1D04800,ctx)
                out=0x510000000000;m.map(out,bytearray(4),name='first output',initialized=False);m.map(out+4,bytes(12),name='readonly output',initialized=True);before=len(m.writes)
                with self.assertRaises(PrimaryMemoryLimit):_invoke(r,0x1D05590,out,ctx)
                self.assertEqual(m.read(out,4),hashlib.md5(b'').digest()[:4]);self.assertFalse(any(label.startswith('1D05590.erase') for a,raw,label in m.writes[before:]))
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_records80_independent_key_unknown_tail_guard_order_and_noncold(self):
        with client_factory() as (owner,k,physical):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                table=_invoke(r,0xB75000,24)
                for off,value in ((0,table+8),(8,0),(16,0)):m.store(table+off,value,8,source='explicit cold tree ABI')
                key,unused=_frame(r,24,'explicit digest String');m.store(key,0x20,1,source='tag');m.write(key+1,bytes(range(16))+b'\0',source='digest')
                slots,unused=_frame(r,32,'explicit tuples/out');m.store(slots,key,8,source='key tuple')
                _invoke(r,0x1BF8AC,table,slots+8,key,r.image_base+0x414AFA0,slots,0xDEAD)
                node=m.load(slots+8,8)
                self.assertEqual((m.load(slots+16,1),m.load(table+16,8)),(1,1))
                for a,n in ((node+25,7),(node+50,6),(slots+17,7)):
                    with self.assertRaises(UnknownMemory):m.read(a,n)
                self.assertEqual(m.read(node+56,24),bytes(24));self.assertEqual(m.read(node+33,16),bytes(range(16)))
                m.store(key+1,99,1,source='change caller');self.assertEqual(m.load(node+33,1),0)
                labels=[label for a,raw,label in m.writes]
                order=['1BF99A.guard_unconstructed','1BF9B5.guard_constructed','430F.records_link','432F.records_count','1BF928.guard_clear','43DD8.guard_reset','1BF936.records_out']
                self.assertEqual([labels.index(t) for t in order],sorted(labels.index(t) for t in order))
                from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'4075'):_invoke(r,0x1BF8AC,table,slots+8,key,r.image_base+0x414AFA0,slots,0xDEAD)
                self.assertEqual(m.load(table+16,8),1)
            with self.assertRaises(ExceptionGroup):owner.close()

    def test_partial_erase_preserves_completed_first_chunk_and_no_later_clear(self):
        from unittest.mock import patch
        with client_factory() as (owner,k,physical):
            r=owner.signer.runtime;m=r.memory
            with creator(owner):
                ctx,unused=_frame(r,88,'erase fault context');src,unused=_frame(r,55,'erase message');out,unused=_frame(r,16,'erase output')
                m.write(src,b'Q'*55,source='message');_invoke(r,0x1D04800,ctx);_invoke(r,0x1D05120,ctx,src,55)
                original=m.write;failure=RuntimeError('controlled PM second erase fault')
                def write(address,data,*,source):
                    if source=='1D05590.erase_XMM' and address==ctx+48:raise failure
                    return original(address,data,source=source)
                with patch.object(m,'write',side_effect=write):
                    with self.assertRaises(RuntimeError) as caught:_invoke(r,0x1D05590,out,ctx)
                self.assertIs(caught.exception,failure)
                self.assertEqual(m.read(out,16),hashlib.md5(b'Q'*55).digest())
                self.assertEqual(m.read(ctx+64,16),bytes(16));self.assertEqual(m.read(ctx+48,16),b'Q'*16)
                self.assertEqual(m.load(ctx+80,8),440)
            with self.assertRaises(ExceptionGroup):owner.close()
