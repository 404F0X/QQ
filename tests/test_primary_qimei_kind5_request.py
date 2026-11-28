"""Deterministic component cases; no native or external IO."""
from pathlib import Path
import sys, unittest, json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from types import SimpleNamespace
from qq_nt_replica.primary_qimei_settings import QimeiSettings
from qq_nt_replica.primary_qimei_reply import ReplySlot, parse_reply

class BusinessFlow(unittest.TestCase):
    def test_complete_controlled_request_and_settings_save(self, empty=False, save_fail=False):
        import base64
        from types import SimpleNamespace
        from qq_nt_replica.primary_qimei_kind5_request import QimeiKind5Request,ConfigHttpResponse
        from qq_nt_replica.primary_qimei_cache import _cbc
        from qq_nt_replica.primary_qimei_envelope import QimeiEnvelopeCodec,QimeiEnvelopeConfiguration
        from qq_nt_replica.primary_qimei_transport_codec import QimeiTransportCodec,DEFAULT_K,DEFAULT_IV
        from qq_nt_replica.primary_qimei_settings import QimeiSettings
        from qq_nt_replica.primary_qimei_transport_material import QimeiTransportMaterial
        events=[]
        codec=QimeiTransportCodec.__new__(QimeiTransportCodec)
        codec.random=SimpleNamespace(random_bytes=lambda count:b'A'*count)
        codec.clock=lambda:133000000000000000
        codec.crt=None
        class Settings(QimeiSettings):
            def refresh(self,**kwargs):events.append('refresh')
        settings=Settings(initialized=1)
        def produce(owner,kind,seq):
            self.assertEqual((owner,kind,seq),(b'owner',5,-1))
            return QimeiTransportMaterial((5,b'm',3,owner,b'v',b't',b'w',b'm',b'',b'c',b'b',b'n',seq))
        def send(request):
            outer=json.loads(request.body)
            self.assertEqual(outer['cpt'],'2')
            self.assertNotIn('ext',outer)
            self.assertNotIn('ky',outer)
            response=b'' if empty else b'\x0a\x03new\x10\x07'
            pad=16-len(response)%16
            body=json.dumps({'code':'0','data':base64.b64encode(_cbc(response+bytes([pad])*pad,DEFAULT_K,DEFAULT_IV)).decode()}).encode()
            events.append('HTTP')
            return ConfigHttpResponse(True,200,body)
        sources=SimpleNamespace(_check=lambda:None,clock=lambda:90000,wow64=lambda:1,
            os_classification=lambda:19,architecture=lambda:1)
        from qq_nt_replica.primary_qimei_settings_writer import QimeiSettingsWriter
        records=[]
        backend=SimpleNamespace(validate_path=lambda path:None,open_file=lambda path:object(),
            write_file=lambda token,data:events.append('save') or (0 if save_fail else len(data)),close_file=lambda token:None,
            path_exists=lambda path:False)
        def encode(data,context):
            records.append(data)
            return SimpleNamespace(value=b'controlled ciphertext')
        writer=QimeiSettingsWriter(backend,SimpleNamespace(encode_payload=encode),
            SimpleNamespace(produce=lambda observations:object()),None)
        settings.record[0x239:0x23d]=b'old\0'
        real_envelope=QimeiEnvelopeCodec()
        def envelope_encode(header,payload,**kwargs):
            self.assertIn(b'old',payload)
            self.assertNotIn(b'changed',payload)
            return real_envelope.encode(header,payload,**kwargs)
        handler=QimeiKind5Request(b'owner',settings,sources,SimpleNamespace(produce=produce),
            envelope=SimpleNamespace(encode=envelope_encode),configuration=QimeiEnvelopeConfiguration(),transport=codec,
            http=SimpleNamespace(send=send),writer=writer,convert_ansi=lambda data:data,
            sign_enabled=False,sequence=0xffffffff)
        settings.record[0x239:0x241]=b'changed\0'
        if empty:
            before=bytes(settings.record)
            self.assertFalse(handler.run())
            self.assertEqual(bytes(settings.record),before)
            self.assertEqual(settings.dirty,0)
            self.assertEqual(events,['refresh','HTTP'])
            self.assertEqual(handler.sequence,0x100000000)
            return
        self.assertTrue(handler.run())
        self.assertEqual(handler.sequence,0x100000000)
        self.assertEqual(settings.record[0x239:0x23d],b'new\0')
        self.assertEqual(settings.record[0x259:0x25d],b'\x07\0\0\0')
        self.assertEqual(settings.dirty,0 if save_fail else 1)
        self.assertEqual(events,['refresh','HTTP','refresh','save'])
        self.assertEqual(records,[bytes(settings.record)])

    def test_save_failure_does_not_revoke_consumer_success(self):
        self.test_complete_controlled_request_and_settings_save(save_fail=True)

    def test_valid_empty_decoded_body_skips_consumer(self):
        self.test_complete_controlled_request_and_settings_save(empty=True)


class SecondRecord(unittest.TestCase):
    def state(self):
        s=QimeiSettings(initialized=1,loaded=1)
        s.record[:]=b'z'*len(s.record)
        return s

    def apply(self,s,slots,status=2):
        saved=[]
        s.update_kind5_response(slots,clock=lambda:-1,writer=SimpleNamespace(save=lambda p,r:saved.append(r) or status))
        return saved

    def test_missing_cells_zero_only_prefix_and_preserve_first(self):
        s=self.state(); old=bytes(s.record)
        saved=self.apply(s,parse_reply(b'\x88\x01\x01',count=16).slots)
        self.assertEqual(s.record[:0x231],old[:0x231])
        self.assertEqual(s.record[0x239:0x259],b'z'*32)
        self.assertEqual(s.record[0x259:0x295],bytes(60))
        self.assertEqual(s.record[0x295:],old[0x295:])
        self.assertEqual(s.record[0x231:0x239],b'\xff'*8)
        self.assertEqual(saved,[bytes(s.record)])
        self.assertEqual(s.dirty,0)
        self.assertEqual(len(parse_reply(b'').slots),3)

    def test_string_length_index_unknown_tail_and_empty_name(self):
        s=self.state()
        self.apply(s,[ReplySlot(1,b''),ReplySlot(1,b'abcdef'),ReplySlot(4,b'ABCD'),ReplySlot(99)])
        self.assertEqual(s.record[0x239:0x259],b'\0'+b'z'*31)
        self.assertEqual(s.record[0x259:0x263],bytes(4)+b'ABCD'+bytes(2))
        self.assertEqual(s.record[0x263],ord('z'))
        s=self.state()
        self.apply(s,[ReplySlot(),ReplySlot(1,None),ReplySlot(4,b'ABCD')],status=0)
        self.assertEqual(s.record[0x259:0x25d],bytes(4))
        self.assertEqual(s.record[0x25d],ord('z'))
        self.assertEqual(s.dirty,1)

    def test_invalid_refresh_and_host_error_preserves_mutation(self):
        s=self.state(); events=[]
        s.refresh=lambda **kw:events.append('refresh')
        self.apply(s,None)
        self.assertEqual(events,['refresh'])
        def fail(*args):raise OSError('controlled')
        with self.assertRaises(OSError):
            s.update_kind5_response([ReplySlot()],clock=lambda:7,writer=SimpleNamespace(save=fail))
        self.assertEqual(int.from_bytes(s.record[0x231:0x239],'little'),7)
        self.assertEqual(s.dirty,0)

if __name__=='__main__':unittest.main()
