"""Synthetic MODEL inputs, independent frame reader; no MSF/profile/server claim."""
import struct
import unittest
from unittest.mock import patch
from qq_nt_replica.primary_source_cold12 import SourceCold12Encoder, SourceCold12Options, SourceCold12Reserve
from qq_nt_replica.primary_source_cold12_counter import SourceCounter
from qq_nt_replica.primary_sso_tea import tea_encrypt, tea_decrypt, _block
from qq_nt_replica.primary_signature_result import PrimarySignatureResult
from qq_nt_replica.primary_sso_reserved import NativeReserveRecord
from qq_nt_replica.errors import InputError


class Inputs:
    def __init__(self):self.closed=False;self.calls=[]
    def entropy4(self):self.calls.append('seed');return (5489).to_bytes(4,'little')
    def host_marker(self):self.calls.append('marker');return 3
    def padding_bytes(self,n):self.calls.append(('padding',n));return bytes(range(n))
    def close(self):self.closed=True


def fields(raw):
    cursor=0;out={}
    def varint():
        nonlocal cursor
        result=shift=0
        while True:
            byte=raw[cursor];cursor+=1;result|=(byte&127)<<shift
            if byte<128:return result
            shift+=7
    while cursor<len(raw):
        tag=varint();number,kind=tag>>3,tag&7
        if kind==2:
            count=varint();value=raw[cursor:cursor+count];cursor+=count
        else:value=varint()
        out.setdefault(number,[]).append(value)
    return out


class Cold12(unittest.TestCase):
    def options(self,context13):
        return SourceCold12Options(0x12345678,b'option8',b'option20',
            SourceCold12Reserve(context13,b'',True,(NativeReserveRecord(b'n',b'v'),),0,b'last'))

    def test_source_frame_and_explicit_reserve_presence(self):
        for route in (0,12345):
            for optional in (None,b''):
                inputs=Inputs();encoder=SourceCold12Encoder(inputs,routing_number=route,own_inputs=False)
                request=encoder.prepare(b'EcdhAccess.SsoEstablishShareKey',b'payload')
                # Counter consumed before any supplied SIGN result or packet observations.
                self.assertEqual(inputs.calls,['seed'])
                frame=encoder.encode_signed(request,options=self.options(optional),signature_result=PrimarySignatureResult(b'S',b'E',b'T'))
                self.assertEqual(int.from_bytes(frame[:4],'big'),len(frame))
                self.assertEqual(frame[4:14],b'\0\0\0\x0c\x02\0\0\0\x04\0')
                route_size=int.from_bytes(frame[14:18],'big')
                self.assertEqual(frame[18:14+route_size],str(route).encode() if route else b'')
                plain=tea_decrypt(frame[14+route_size:],bytes(16))
                head_length,seq,dword0,fixed=struct.unpack_from('>4I',plain)
                self.assertEqual((seq,dword0,fixed),(request.wire_sequence,0x12345678,2052))
                self.assertEqual(plain[16:28],bytes(10)+b'\x03\0')
                cursor=28
                def blob(width=4):
                    nonlocal cursor
                    n=int.from_bytes(plain[cursor:cursor+width],'big');value=plain[cursor+width:cursor+n];cursor+=n;return value
                self.assertEqual([blob() for i in range(5)],[b'',request.command,b'',b'option20',b''])
                self.assertEqual(blob(2),b'option8');reserve=fields(blob());self.assertEqual(cursor,head_length)
                self.assertEqual(blob(),b'payload');self.assertEqual(cursor,len(plain))
                self.assertEqual(reserve[12],[b'option20']);self.assertEqual(13 in reserve,optional is not None)
                if optional is not None:self.assertEqual(reserve[13],[b''])
                self.assertEqual(reserve[26],[0]);self.assertEqual(reserve[32],[b'last'])
                self.assertEqual(fields(reserve[23][0]),{1:[b'n'],2:[b'v']})
                self.assertNotIn(15,reserve);self.assertEqual(reserve[16],[b''])
                self.assertEqual(reserve[21],[32]);self.assertEqual(fields(reserve[24][0]),{1:[b'S'],2:[b'E'],3:[b'T']})
                encoder.close();self.assertFalse(inputs.closed)

    def test_tea_entropy_header_all_pad_residues_and_block_kat(self):
        self.assertEqual(_block(0,0,(0,0,0,0)),(0xA889F798,0x182D8083))
        for n in range(1,9):
            data=b'x'*n;fill=10-((n+1)&7)
            for first in (0,0x57,0xF8):
                entropy=bytes([first])+b'r'*(fill-1)
                cipher=tea_encrypt(data,bytes(16),random_padding=entropy)
                self.assertEqual(tea_decrypt(cipher,bytes(16)),data)
                hi,lo=_block(*struct.unpack('>2I',cipher[:8]),(0,0,0,0),True)
                raw=struct.pack('>2I',hi,lo)
                self.assertEqual(raw[0],(first&0xF8)|((fill-3)&7))
                self.assertEqual(len(cipher),(n+10+7)//8*8)

    def test_counter_rejection_oldvalue_wrap_and_failure(self):
        with patch('qq_nt_replica.primary_source_cold12_counter.next_mt',side_effect=(10_000_000,0xFFFFFF,9_999_999)) as draw:
            counter=SourceCounter(lambda:b'\x01\0\0\0')
            self.assertEqual(draw.call_count,3);self.assertEqual(counter.next(),10_000_000)
        counter._value=0xFFFFFFFF
        self.assertEqual((counter.next(),counter.next()),(0xFFFFFFFF,0))
        # Independent standard MT19937 first word for seed5489; source incremental twist agrees.
        real=SourceCounter(lambda:(5489).to_bytes(4,'little'))
        self.assertEqual(real.next(),(3499211612&0xFFFFFF)+1)
        self.assertEqual(SourceCounter(lambda:bytes(4)).next(),(2357136044&0xFFFFFF)+1)
        with self.assertRaises(InputError):SourceCounter(lambda:b'bad')
        def failure():raise OSError('entropy failed')
        with self.assertRaises(OSError):SourceCounter(failure)

    def test_required_inputs_and_owned_failure_cleanup(self):
        inputs=Inputs();encoder=SourceCold12Encoder(inputs,routing_number=0,own_inputs=True)
        with self.assertRaises(InputError):encoder.prepare(b'unknown',b'')
        request=encoder.prepare(b'EcdhAccess.SsoSecureAccess',b'')
        with self.assertRaises(TypeError):encoder.encode_signed(request,signature_result=PrimarySignatureResult(b'S',b'',b''))
        self.assertEqual(encoder.counter._value,request.wire_sequence+1)
        encoder.close();self.assertTrue(inputs.closed)
        failed=Inputs();failed.entropy4=lambda:b'x'
        with self.assertRaises(InputError):SourceCold12Encoder(failed,routing_number=0,own_inputs=True)
        self.assertTrue(failed.closed)

if __name__=='__main__':unittest.main()
