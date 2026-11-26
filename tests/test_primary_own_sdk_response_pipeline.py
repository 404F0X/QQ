"""MODEL protocol fixtures; never evidence of a server response."""
import unittest
from unittest.mock import patch
from types import SimpleNamespace as NS
import test_provider_cache_upper_delete as cache_fixture
from test_primary_own_sdk_request import Capi
from qq_nt_replica.primary_request_material import RequestMaterial
from qq_nt_replica.primary_request_random import RequestRandom
from qq_nt_replica.primary_request_encoder import encrypt_request_body
from qq_nt_replica.primary_logger import _String
from qq_nt_replica.errors import InputError

class OwnPipeline(unittest.TestCase):
    def fixture(self):
        r,reg=cache_fixture.CacheUpperDelete().fixture()
        s=r._primary_entry_owner
        s.initialize_own_sdk_request(request_capi=Capi(),clock_inputs=dict(wall_seconds=lambda:1,monotonic_ns=lambda:1,clock_ns=lambda:1),random_environment=NS(random_bytes=lambda n:bytes(n)))
        owner=s._own_sdk_request
        raw=bytearray(168);raw[:32]=bytes(range(32));raw[32:48]=b'\xff'*16;raw[48:80]=b'r'*32;raw[80]=1
        owner.material.current=RequestMaterial(bytes(raw));owner.material.random=RequestRandom(1)
        return s,r,reg
    def create(self,s):
        with patch('qq_nt_replica.primary_own_sdk_request.feature',return_value=0),patch('qq_nt_replica.primary_own_sdk_request._logger',return_value=1):
            return s.create_own_device_request(())
    def wire(self,request,payload):
        cipher=encrypt_request_body(payload,request.decode_material.key,bytes(12))
        self.assertLess(len(cipher),128)
        return b'\x0a'+bytes([len(cipher)])+cipher
    def test_failure_results_are_observable_without_poisoning_owner(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        from dataclasses import FrozenInstanceError
        s,r,reg=self.fixture()
        try:
            first=self.create(s); second=self.create(s)
            current=s._own_sdk_request.material.current
            # MODEL known status-node lookup; real normalization and completion execute.
            node=r._operator_new(64)
            _String.construct(r,b'MODEL downstream failure').write_to(node+40)
            try:
                with patch('qq_nt_replica.primary_request_response._status_node',return_value=node):
                    result=s.complete_own_device_request(first,b'\x10\xeb\x07',transport_status=0)
            finally:
                _String.read(r,node+40).destroy();r._free_allocation(node)
            self.assertEqual((result.outcome,result.stage,result.code),('failed','sdk_status',1003))
            self.assertFalse(result.cache_updated);self.assertIsNone(result.publication)
            with self.assertRaises(FrozenInstanceError):result.code=0
            self.assertFalse(s.failed);self.assertIs(s._own_sdk_request.material.current,current)
            self.assertEqual([q for q,b in s._own_sdk_request._pending],[second])
            malformed=s.complete_own_device_request(second,b'\x0a\x05',transport_status=0)
            self.assertEqual((malformed.outcome,malformed.stage,malformed.code),('failed','sdk_envelope',None))
            self.assertFalse(s.failed);self.assertEqual(s._own_sdk_request._pending,[])
            third=self.create(s)
            result=s.complete_own_device_request(third,b'',transport_status=9)
            self.assertEqual((result.stage,result.code),('transport',9))
        finally:reg.close();dispose_model_allocator(r)

    def test_settings_notification_return_resumes_real_auth_and_keeps_boundaries(self):
        from qq_nt_replica.primary_own_sdk_response import _decode
        from qq_nt_replica.primary_feature_notifications import _logger,register
        from qq_nt_replica.primary_logger import feature
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        for setting in (None, 7, 0, 1):
            s,r,reg=self.fixture();owner=s._own_sdk_request
            try:
                raw=bytearray(owner.material.current.raw);raw[80]=0
                owner.material.current=RequestMaterial(bytes(raw));request=self.create(s)
                with reg.operation():
                    logger=_logger(r);carrier=r._operator_new(40)
                    r.memory.write(carrier,bytes(40),source='MODEL source callable carrier')
                    r.memory.store(carrier+8,r.image_base+0x414A2C8,8,source='MODEL fixed constructor callable')
                    r.memory.store(carrier+32,carrier+8,8,source='MODEL inline owner')
                    register(r,logger,carrier)
                    settings=b'\x08\x00\x10\x00'+(b'' if setting is None else b'\x20'+bytes([setting]))
                    body=b'\x0a\x40'+bytes(64)+b'\x10\x01\x18\x02\x22\x01p'+b'\x2a'+bytes([len(settings)])+settings
                    if setting in (0,1):
                        with self.assertRaisesRegex(InputError if setting==0 else PrimarySemanticUnavailable,
                                'public completion operation' if setting==0 else 'feature4=1'):
                            _decode(owner,request,self.wire(request,body))
                        self.assertTrue(r._logger_locks[logger+112])
                    else:
                        # Real zero-signature verification rejects: notification return never authenticates.
                        self.assertEqual(_decode(owner,request,self.wire(request,body)),('auth',3,None))
                        self.assertFalse(r._logger_locks[logger+112])
                    self.assertEqual(owner.material.current.wall_deadline,2)
                    self.assertEqual(feature(r,logger,4),setting if setting in (0,1) else 2)
                    self.assertEqual(owner.material.current.payload_mode,0)
                    r._free_allocation(carrier)
            finally:reg.close();dispose_model_allocator(r)

    def test_cold0_source_fields_auth_and_reuse_with_model_srw_boundary(self):
        from qq_nt_replica import primary_client_configuration as client
        from qq_nt_replica.primary_feature_notifications import _logger,register
        from qq_nt_replica.primary_own_sdk_response import _decode
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        from qq_nt_replica.primary_logger import LoggerOutput
        for warm in (False,True):
            s,r,reg=self.fixture();owner=s._own_sdk_request;locks=[];messages=[]
            def srw(runtime,context,stage,address,acquire):
                # Explicit MODEL native boundary only; never issues Windows capability.
                locks.append((stage,address,acquire));return 0
            try:
                raw=bytearray(owner.material.current.raw);raw[80]=0;owner.material.current=RequestMaterial(bytes(raw));request=self.create(s)
                with reg.operation():
                    logger=_logger(r);carrier=r._operator_new(40)
                    r.memory.write(carrier,bytes(40),source='MODEL callable carrier')
                    r.memory.store(carrier+8,r.image_base+0x414A2C8,8,source='MODEL constructor callback')
                    r.memory.store(carrier+32,carrier+8,8,source='MODEL inline owner');register(r,logger,carrier)
                    target=123456;r.memory.store(r.image_base+0x677BD88,target,8,source='MODEL log target')
                    def output(message,tag,severity):
                        messages.append((message,tag,severity))
                        outer=r.memory.load(r.image_base+0x677CEE8,8)
                        manager=r.memory.load(outer,8)
                        return ((manager+8,b'\x01'),) if warm else ()
                    r.logger_output=LoggerOutput(target,output)
                    settings=b'\x08\x00\x10\x00\x18\x01\x20\x00'
                    body=b'\x0a\x40'+bytes(64)+b'\x10\x01\x18\x02\x22\x01p\x2a'+bytes([len(settings)])+settings
                    with patch.object(client,'_cold_srw',side_effect=srw):
                        if warm:
                            from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
                            with self.assertRaisesRegex(PrimarySemanticUnavailable,'noncold D45A00'):_decode(owner,request,self.wire(request,body))
                        else:
                            self.assertEqual(_decode(owner,request,self.wire(request,body)),('auth',3,None))
                            outer=r.memory.load(r.image_base+0x677CEE8,8);manager=r.memory.load(outer,8);worker=r.memory.load(manager+0x68,8)
                            self.assertEqual(r.memory.load(manager+0x18,4),0xE10)
                            self.assertEqual(r.memory.load(worker+0x18,4),0x78)
                            self.assertEqual(r.memory.load(worker+0x88,8),worker+0x90)
                            self.assertEqual(r.memory.read(manager+0x39,6),b'work1\0')
                            self.assertEqual(r.memory.read(worker+0x39,6),b'work0\0')
                            self.assertFalse(r._logger_locks[logger+112])
                            first=list(locks);self.assertEqual(len(first),8);self.assertEqual(len({a for _,a,_ in first}),4)
                            self.assertEqual(_decode(owner,request,self.wire(request,body)),('auth',3,None))
                            self.assertEqual(r.memory.load(r.image_base+0x677CEE8,8),outer)
                            self.assertEqual(len(locks),14)  # Reuse skips ctor W+A0.
                    self.assertTrue(messages)
                    self.assertTrue(all(m.endswith(b'stop...') and t==b'[FGESDK]' and level==1 for m,t,level in messages))
                    if warm:self.assertTrue(r._logger_locks[logger+112])
                    r._free_allocation(carrier)
            finally:reg.close();dispose_model_allocator(r)

    def test_mode0_current_reread_and_archive_signature_failure(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        from qq_nt_replica.primary_own_sdk_response import _decode
        s,r,reg=self.fixture()
        owner=s._own_sdk_request
        try:
            raw=bytearray(owner.material.current.raw);raw[80]=0
            owner.material.current=RequestMaterial(bytes(raw))
            request=self.create(s)
            # MODEL concurrent state transition after request snapshot; no server claim.
            raw=bytearray(owner.material.current.raw);raw[80]=1
            owner.material.current=RequestMaterial(bytes(raw))
            body=b'\x10\x01\x18\x02\x22\x01p\x2a\x02\x50\x01'
            with reg.operation():
                self.assertEqual(_decode(owner,request,self.wire(request,body)),('auth',0,b'p'))
            self.assertEqual(owner.material.current.wall_deadline,2)
            self.assertEqual(owner.material.current.monotonic_deadline,60)
            raw=bytearray(owner.material.current.raw);raw[80]=0
            owner.material.current=RequestMaterial(bytes(raw))
            rejected=b'\x0a\x40'+bytes(64)+body
            with reg.operation():
                self.assertEqual(_decode(owner,request,self.wire(request,rejected)),('auth',3,None))
            self.assertEqual(owner.material.current.wall_deadline,2)
            self.assertEqual(owner.material.current.payload_mode,0)
            raw=bytearray(owner.material.current.raw);raw[48]=ord('z')
            owner.material.current=RequestMaterial(bytes(raw))
            before=owner.material.current
            # Archive always verifies; a complete zero signature is rejected by real EC verifier.
            body=b'\x0a\x40'+bytes(64)+body
            with reg.operation():
                self.assertEqual(_decode(owner,request,self.wire(request,body)),('auth',3,None))
            self.assertIs(owner.material.current,before)
        finally:reg.close();dispose_model_allocator(r)

    def test_bound_snapshot_and_foreign_runtime_rejection(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        s,r,reg=self.fixture();other,foreign,foreignreg=self.fixture()
        try:
            pair=r.image_base+0x6751840
            _String.construct(r,b'first-bound').write_to(pair+48)
            first=self.create(s)
            _String.construct(r,b'second-bound').write_to(pair+48)
            second=self.create(s)
            self.assertEqual([bound for request,bound in s._own_sdk_request._pending],[b'first-bound',b'second-bound'])
            with self.assertRaises(InputError):other._own_sdk_request._take(first)
            self.assertEqual(len(s._own_sdk_request._pending),2)
        finally:
            s._own_sdk_request.close();other._own_sdk_request.close()
            reg.close();foreignreg.close();dispose_model_allocator(r);dispose_model_allocator(foreign)

    def test_nonempty_retains_cache_at_persist_boundary(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        s,r,reg=self.fixture()
        try:
            request=self.create(s)
            # MODEL explicit unbound provider branch; never an actual provider claim.
            provider=r._operator_new(8);table=r._operator_new(48)
            r.memory.store(provider,table,8,source='MODEL provider')
            r.memory.store(table+40,123,8,source='MODEL unbound callback')
            r.memory.store(r.image_base+0x677BE78,provider,8,source='MODEL provider slot')
            with self.assertRaisesRegex(PrimarySemanticUnavailable,'1BE5A54'):
                s.complete_own_device_request(request,self.wire(request,b'\x0a\x03abc\x10\x05'),transport_status=0)
            self.assertEqual(_String.read(r,r.image_base+0x6751840+24).value(),b'abc')
            self.assertEqual(r.memory.load(r.image_base+0x6751840+16,8),5)
            self.assertTrue(s.failed)
            self.assertTrue(r._logger_locks[r.image_base+0x6751840+0xE0])
            self.assertIsNone(r.__dict__.get('_primary_token_publication_claim'))
        finally:
            # Model heap objects are borrowed provider fixtures, not cache-owned strings.
            r._free_allocation(provider);r._free_allocation(table)
            reg.close();dispose_model_allocator(r)

    def test_public_rejections_preserve_other_pending_and_future_work(self):
        from dataclasses import replace
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        s,r,reg=self.fixture();other,foreign,foreignreg=self.fixture()
        try:
            first=self.create(s);second=self.create(s);foreign_request=self.create(other)
            s.cancel_own_device_request(first)
            for rejected in (first,replace(second),foreign_request):
                for complete in (False,True):
                    with self.subTest(complete=complete):
                        events=list(r.events);calls=s.calls;current=s._own_sdk_request.material.current
                        with self.assertRaises(InputError):
                            if complete:s.complete_own_device_request(rejected,b'',transport_status=0)
                            else:s.cancel_own_device_request(rejected)
                        self.assertFalse(s.failed)
                        self.assertEqual(r.events,events);self.assertEqual(s.calls,calls)
                        self.assertIs(s._own_sdk_request.material.current,current)
                        self.assertEqual([request for request,bound in s._own_sdk_request._pending],[second])
            # B still executes a real public completion (explicit MODEL transport failure).
            s.complete_own_device_request(second,b'',transport_status=5)
            self.assertFalse(s.failed);self.assertEqual(s._own_sdk_request._pending,[])
            third=self.create(s);s.cancel_own_device_request(third)
            self.assertFalse(s.failed)
            other.cancel_own_device_request(foreign_request)
        finally:reg.close();foreignreg.close();dispose_model_allocator(r);dispose_model_allocator(foreign)

    def test_archive_without_deadline_verifies_but_current_requires_it(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.primary_own_sdk_response import _decode
        s,r,reg=self.fixture();owner=s._own_sdk_request
        try:
            raw=bytearray(owner.material.current.raw);raw[80]=0
            owner.material.current=RequestMaterial(bytes(raw));request=self.create(s)
            body=b'\x0a\x40'+bytes(64)+b'\x10\x01\x22\x01p'
            before=owner.material.current
            with reg.operation():
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'current response deadline'):
                    _decode(owner,request,self.wire(request,body))
            self.assertIs(owner.material.current,before)
            raw=bytearray(before.raw);raw[48]^=1
            owner.material.current=RequestMaterial(bytes(raw));before=owner.material.current
            with reg.operation():
                self.assertEqual(_decode(owner,request,self.wire(request,body)),('auth',3,None))
            self.assertIs(owner.material.current,before)
        finally:reg.close();dispose_model_allocator(r)

    def test_transport_and_bad_gcm_never_install(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        s,r,reg=self.fixture()
        try:
            first=self.create(s);second=self.create(s)
            pair=r.image_base+0x6751840
            s.complete_own_device_request(first,b'not a response',transport_status=5)
            cipher=bytearray(self.wire(second,b'\x0a\x03abc'));cipher[-1]^=1
            s.complete_own_device_request(second,bytes(cipher),transport_status=0)
            self.assertEqual(r.memory.load(pair+0x64,4),2)
            self.assertEqual(_String.read(r,pair+24).value(),b'')
            self.assertNotIn('tokenFamilyPrograms',s.last_direct_report)
        finally:reg.close();dispose_model_allocator(r)

    def test_legacy_and_own_publication_reject_unqualified_callers(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        from qq_nt_replica.primary_tokens import publish_response_token, publish_own_response_token
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.primary_sign_lifecycle import public_call
        for publish in (publish_response_token,publish_own_response_token):
            s,r,reg=self.fixture()
            try:
                with self.assertRaises(PrimarySemanticUnavailable):
                    with public_call(s):publish(r,r.image_base+0x6751840)
                self.assertIsNone(r.__dict__.get('_primary_token_publication_claim'))
            finally:reg.close();dispose_model_allocator(r)

    def test_nonempty_nullprovider_model_dispatch_with_close_boundary(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        s,r,reg=self.fixture()
        try:
            self.assertEqual(r.memory.load(r.image_base+0x677BE78,8),0)
            request=self.create(s)
            result=s.complete_own_device_request(request,self.wire(request,b'\x0a\x03abc\x10\x05'),transport_status=0)
            self.assertEqual(result.publication['dispatch_result'],0)
            self.assertTrue(result.publication['root_completed'])
            self.assertFalse(result.publication['setter_completed'])
            self.assertFalse(result.publication['expire_completed'])
            programs=s.last_direct_report['tokenFamilyPrograms']
            self.assertEqual([x['program'] for x in programs],['source2583'])
            self.assertTrue(all(x['completed'] for x in programs))
            self.assertEqual(_String.read(r,r.image_base+0x6751840+24).value(),b'abc')
        finally:
            try:
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'installed runtime scope'):reg.close()
                self.assertEqual(reg._lifecycle,'cleanup_failed')
            finally:dispose_model_allocator(r)

    def test_empty_model_dispatch_and_explicit_close_boundary(self):
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        s,r,reg=self.fixture()
        try:
            request=self.create(s)
            _String.construct(r,b'old-cache').write_to(r.image_base+0x6751840+24)
            result=s.complete_own_device_request(request,self.wire(request,b'\x12\x00'),transport_status=0)
            self.assertEqual(result.publication['dispatch_result'],0)
            self.assertTrue(result.publication['root_completed'])
            self.assertFalse(result.publication['setter_completed'])
            self.assertFalse(result.publication['expire_completed'])
            programs=s.last_direct_report['tokenFamilyPrograms']
            self.assertEqual([x['program'] for x in programs],['source2583'])
            self.assertTrue(all(x['completed'] for x in programs))
            self.assertEqual(r.memory.load(r.image_base+0x6751840+0x64,4),0)
            self.assertEqual(s._own_sdk_request._pending,[])
            self.assertEqual(_String.read(r,r.image_base+0x6751840+24).value(),b'old-cache')
        finally:
            from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
            try:
                with self.assertRaisesRegex(PrimarySemanticUnavailable,'installed runtime scope'):
                    reg.close()
                self.assertEqual(reg._lifecycle,'cleanup_failed')
            finally:dispose_model_allocator(r)
    def test_two_outstanding_original_identity_cancel_and_close(self):
        from dataclasses import replace
        from qq_nt_replica.primary_custom_allocator import dispose_model_allocator
        s,r,reg=self.fixture()
        try:
            first=self.create(s);second=self.create(s)
            self.assertEqual(len(s._own_sdk_request._pending),2)
            with self.assertRaises(InputError):s._own_sdk_request.cancel_device_request(replace(first))
            s.cancel_own_device_request(first)
            with self.assertRaises(InputError):s._own_sdk_request._take(first)
            s._own_sdk_request.close()
            with self.assertRaises(InputError):s._own_sdk_request._take(second)
        finally:reg.close();dispose_model_allocator(r)

if __name__=='__main__':unittest.main()
