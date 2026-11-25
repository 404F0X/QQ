import hashlib
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_signer import PrimarySigner, SigningEnvironment
from qq_nt_replica.primary_host_services import GuestExitRegistrar
from qq_nt_replica.primary_custom_allocator import install_model_allocator, dispose_model_allocator
from qq_nt_replica.primary_notification_files import FileSelectorMaterial
from qq_nt_replica.primary_material import _RuntimeResponseMaterial
from qq_nt_replica.primary_logger import _String
from qq_nt_replica.primary_sign_lifecycle import cleanup_main_allocations, region_at
from qq_nt_replica.errors import InputError

class CacheUpperDelete(unittest.TestCase):
    def fixture(self, crt=False):
        reg=GuestExitRegistrar()
        s=PrimarySigner(SigningEnvironment(cursor=None,process_path=b'C:/explicit/p.exe',module_path=b'C:/explicit/m.dll',stack_modules=(),exit_registration=reg),initial_stack=None,primary_backend='direct')
        r=s.runtime;reg.bind(r)
        raw=b'explicit --notcmalloc\0' if crt else b'explicit-model-custom\0'
        p=0x7600000000;initial=bytes(2)
        m=FileSelectorMaterial(initial,p,raw,'synthetic-test-input','explicit-model',hashlib.sha256(initial+p.to_bytes(8,'little')+raw).hexdigest())
        install_model_allocator(r,m,supplier=s.addresses.allocation)
        return r,reg

    def test_registered_cache_short_and_long_matching_families(self):
        for crt in (False,True):
            for short in (False,True):
                with self.subTest(crt=crt,short=short):
                    r,reg=self.fixture(crt);backend=r._custom_allocator_backend
                    vm=NS(main_owned_allocations=[]);r._active_main={'vm':vm,'generation':1}
                    deleted=[];original=backend.dispatch
                    def dispatch(rva,values):
                        result=original(rva,values)
                        if rva==0xB75029:deleted.append(values[0])
                        return result
                    try:
                        with patch.object(backend,'dispatch',side_effect=dispatch):
                            with reg.operation():
                                material=_RuntimeResponseMaterial(r);payloads=[]
                                for size in ((3,) if short else (30,31,100)):
                                    material.value=b'x'*size
                                    self.assertEqual(material.value,b'x'*size)
                                    if not short:
                                        pointer=_String.read(r,material.address+24).get(16,8)
                                        payloads.append(pointer)
                                        self.assertIn(pointer,backend.records)
                                        self.assertEqual(pointer in r.allocations,crt)
                                        self.assertFalse(vm.main_owned_allocations)
                                if not short:
                                    self.assertEqual(payloads[0],payloads[1]);self.assertNotEqual(payloads[1],payloads[2])
                                    region=region_at(r.memory,payloads[-1])
                                cleanup_main_allocations(r,vm)
                                self.assertEqual(material.value,b'x'*size)
                                if not short:self.assertIs(region_at(r.memory,payloads[-1]),region)
                            r._active_main=None
                            before=list(deleted);reg.close()
                            self.assertEqual(reg._lifecycle,'closed')
                            self.assertTrue(all(x.status=='completed' for x in reg._records))
                            if short:self.assertEqual(deleted,[])
                            else:
                                self.assertEqual(deleted[len(before):],[payloads[-1]])
                                self.assertEqual(deleted.count(payloads[0]),1)
                                self.assertEqual(deleted.count(payloads[-1]),1)
                            self.assertEqual(backend.records,{})
                    finally:
                        r._active_main=None;dispose_model_allocator(r)

    def test_unknown_or_wrong_family_is_not_freed(self):
        for wrong in (False,True):
            with self.subTest(wrong_family=wrong):
                r,reg=self.fixture();backend=r._custom_allocator_backend
                try:
                    with reg.operation():
                        material=_RuntimeResponseMaterial(r);material.value=b'x'*30
                        pointer=_String.read(r,material.address+24).get(16,8)
                        record=backend.records[pointer]
                        if wrong:backend.records[pointer]=record[:-1]+('CRT',)
                        else:del backend.records[pointer]
                    try:
                        with self.assertRaises(InputError):reg.close()
                        self.assertEqual(reg._lifecycle,'cleanup_failed')
                        self.assertTrue(any(x.status=='failed' for x in reg._records))
                        self.assertIsNotNone(region_at(r.memory,pointer))
                    finally:
                        # Restore only test-corrupted metadata for model resource disposal; never retry close.
                        backend.records[pointer]=record
                finally:dispose_model_allocator(r)

if __name__=='__main__':unittest.main()
