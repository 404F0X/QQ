import unittest
from test_primary_logger_bare_hex import ColdRepair
from qq_nt_replica.primary_device_cache import _WideString
class WideSource(unittest.TestCase):
    def test_threshold_units_clone_and_upper_ownership(self):
        r=ColdRepair().fixture();storage=r._custom_allocator_backend.storage
        for text in ('','a'*10,'a'*11,'Manufacturer','SerialNumber','汉字😀'*5):
            raw=text.encode('utf-16-le');size=len(raw)//2
            value=_WideString.construct(r,raw)
            self.assertEqual(value.value(),raw)
            self.assertEqual(bool(value.get(0,1)&1),size>10)
            clone=__import__('qq_nt_replica.primary_device_wmi',fromlist=['_clone_wide'])._clone_wide(r,value);self.assertEqual(clone.value(),raw)
            pointers=[]
            for item in (value,clone):
                if size>10:
                    pointer=item.get(16,8);pointers.append(pointer)
                    self.assertIn(pointer,storage.live);self.assertNotIn(pointer,r.allocations)
                    self.assertEqual(r.memory.read(pointer+len(raw),2),b'\0\0')
                item.destroy()
            if pointers:self.assertNotEqual(*pointers)
            for pointer in pointers:self.assertNotIn(pointer,storage.live)
