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
                self.assertEqual(_decode(owner,request,self.wire(request,body)),(0,b'p'))
            self.assertEqual(owner.material.current.wall_deadline,2)
            self.assertEqual(owner.material.current.monotonic_deadline,60)
            raw=bytearray(owner.material.current.raw);raw[80]=0
            owner.material.current=RequestMaterial(bytes(raw))
            rejected=b'\x0a\x40'+bytes(64)+body
            with reg.operation():
                self.assertEqual(_decode(owner,request,self.wire(request,rejected)),(3,None))
            self.assertEqual(owner.material.current.wall_deadline,2)
            self.assertEqual(owner.material.current.payload_mode,0)
            raw=bytearray(owner.material.current.raw);raw[48]=ord('z')
            owner.material.current=RequestMaterial(bytes(raw))
            before=owner.material.current
            # Archive always verifies; a complete zero signature is rejected by real EC verifier.
            body=b'\x0a\x40'+bytes(64)+body
            with reg.operation():
                self.assertEqual(_decode(owner,request,self.wire(request,body)),(3,None))
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
                self.assertEqual(_decode(owner,request,self.wire(request,body)),(3,None))
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
            self.assertEqual(result['dispatch_result'],0)
            self.assertTrue(result['root_completed'])
            self.assertFalse(result['setter_completed'])
            self.assertFalse(result['expire_completed'])
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
            self.assertEqual(result['dispatch_result'],0)
            self.assertTrue(result['root_completed'])
            self.assertFalse(result['setter_completed'])
            self.assertFalse(result['expire_completed'])
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
