import unittest
from types import SimpleNamespace
from unittest.mock import patch
from test_primary_logger_bare_hex import ColdRepair
from qq_nt_replica import primary_logger as log, primary_device_cold as cold
from qq_nt_replica import primary_device_adapters as adapters, primary_device_records as records
from qq_nt_replica.primary_worker_consumer import _invoke

class Components(unittest.TestCase):
    def test_complete_component_formats_and_cpu_destination(self):
        r=ColdRepair().fixture();m=r.memory;b=r.image_base
        destination=r._operator_new(24)
        for options in (0,0x18,0x24):
            m.store(b+0x6749CC0,options,8,source='test')
            for eax,edx,want in ((0,0,b'0000000000000000'),(0xABCDEF,0x80000000,b'8000000000ABCDEF'),(0xFFFFFFFF,0xFFFFFFFF,b'FFFFFFFFFFFFFFFF')):
                r.worker_observations=SimpleNamespace(take=lambda *a:(None,(eax,0,0,edx)))
                self.assertEqual(cold.cpu_identifier(r,destination),destination)
                self.assertEqual(log._String.read(r,destination).value(),want)
            self.assertEqual(log._format(r,b'%d.%d.%d',(0xFFFFFFFF,0x80000000,1)),b'-1.-2147483648.1')
            self.assertEqual(log._format(r,b'%s:%d',(b'f.cc',0xFFFFFFFF)),b'f.cc:-1')
            self.assertEqual(log._format(r,b'%X/%08x',(0xABCDEF,0x123)),b'ABCDEF/00000123')
    def test_actual_device_insert_and_adapter_cache_vector_families(self):
        r=ColdRepair().fixture();m=r.memory;b=r.image_base
        head=b+0x6751D98
        m.write(head,bytes(24),source='test empty inline device tree');m.store(head,head+8,8,source='test')
        pair=r._operator_new(32);out=r._operator_new(16);nodes=[];strings=[]
        for key in (2,1,3):
            m.store(pair,key,4,source='test')
            value=log._String.construct(r,b'long-device-string'*5);strings.append(value.get(16,8));value.write_to(pair+8)
            records.insert_record(r,head,out,pair);nodes.append(m.load(out,8))
        upper=r._custom_allocator_backend;storage=upper.storage
        with patch.object(storage,'free',wraps=storage.free) as free,patch.object(r,'_free_allocation',wraps=r._free_allocation) as lower:
            records._destroy_record_tree(r,m.load(head+8,8))
        self.assertCountEqual([x.args[0] for x in free.call_args_list],strings)
        self.assertCountEqual([x.args[0] for x in lower.call_args_list],nodes)
        head=b+0x677BF68;m.write(head,bytes(24),source='test empty inline adapter tree');m.store(head,head+8,8,source='test')
        cache=[];vectors=[]
        source=r._operator_new(adapters._RECORD);m.write(source,bytes(adapters._RECORD),source='test record')
        for key in (2,1,3):
            node=adapters._cache_node(r,key);cache.append(node)
            adapters.copy_records(r,node+48,source,source+adapters._RECORD)
            vectors.append(m.load(node+48,8))
        with patch.object(storage,'free',wraps=storage.free) as free,patch.object(r,'_free_allocation',wraps=r._free_allocation) as lower:
            adapters.destroy_cache(r)
        self.assertCountEqual([x.args[0] for x in free.call_args_list],cache)
        self.assertCountEqual([x.args[0] for x in lower.call_args_list],vectors)
        self.assertTrue(set(cache+strings).isdisjoint(storage.live))
        self.assertTrue(set(cache+strings).isdisjoint(upper.records))
        from qq_nt_replica.errors import InputError
        with self.assertRaises(InputError):_invoke(r,0xB75029,cache[0])
        with self.assertRaises(InputError):_invoke(r,0xB75029,source)
