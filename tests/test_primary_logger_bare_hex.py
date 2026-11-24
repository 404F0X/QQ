import hashlib,unittest
from unittest.mock import patch
from test_primary_client_configuration_request import signer
from qq_nt_replica import primary_logger as log, primary_request_startup as startup
from qq_nt_replica.primary_worker_consumer import _invoke

class ColdRepair(unittest.TestCase):
    def fixture(self):
        from qq_nt_replica.primary_custom_allocator import install_model_allocator
        from qq_nt_replica.primary_notification_files import FileSelectorMaterial
        s=signer();r=s.runtime
        raw=b'explicit-model-custom\0';p=0x7600000000;initial=b'\0\0'
        m=FileSelectorMaterial(initial,p,raw,'synthetic-test-input','explicit-model',hashlib.sha256(initial+p.to_bytes(8,'little')+raw).hexdigest())
        install_model_allocator(r,m,supplier=s.addresses.allocation)
        return r
    def test_bare_hex_options_strict_and_sink(self):
        from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
        from qq_nt_replica.primary_memory import UnknownMemory
        r=self.fixture();m=r.memory;b=r.image_base
        for options in (0,0x18,0x24):
            m.store(b+0x6749CC0,options,8,source='test')
            for arg,want in ((0,b'0'),(0xABCDEF,b'abcdef'),(0x10000000A,b'a')):
                self.assertEqual(log._format(r,b'IW initialize : 0x%x',(arg,)),b'IW initialize : 0x'+want)
        for options in (0x18,0x24):
            m.store(b+0x6749CC0,options,8,source='test')
            for fmt in (b'%#x',b'%2x',b'%.2x',b'%lx'):
                with self.assertRaises(PrimarySemanticUnavailable):log._format(r,fmt,(1,))
            for args in ((),(None,),(True,)):
                with self.assertRaises(UnknownMemory):log._format(r,b'%x',args)
        seen=[];target=0x12345;m.store(b+0x677BD88,target,8,source='test')
        r.logger_output=log.LoggerOutput(target,lambda *args:seen.append(args) or ())
        with patch.object(log,'feature',return_value=1):
            self.assertIsNone(log.log(r,b'file.cc',1,b'IW initialize : 0x%x',b'tag',2,0x80004005))
        self.assertIn(b'IW initialize : 0x80004005',seen[0][0])
    def test_request_constructor_tree_upper_family_and_long_strings(self):
        r=self.fixture();m=r.memory;b=r.image_base
        def invoke(runtime,rva,*values):
            if rva in (0xB75000,0xB75029):return _invoke(runtime,rva,*values)
            return 0
        with patch('qq_nt_replica.primary_client_configuration_startup.constructor_enter',return_value={'private_stage':None,'registrations':[]}),patch.object(startup,'_invoke',side_effect=invoke):
            startup.construct(r)
        # Actual constructor has an inline sentinel at head+8, not an allocated header.
        head=b+0x677D030;root=m.load(head+8,8);self.assertTrue(root)
        table=log._Tree(r,head)
        for key in (0x100000,0x200000,0x300000):
            def initialize(node):
                m.store(node+32,key,4,source='test')
                log._String.construct(r,b'long-value-'*8).write_to(node+40)
            table.insert(key,64,initialize)
        live=set(r._custom_allocator_backend.storage.live)
        nodes=[]
        def walk(node):
            if node:
                walk(m.load(node,8));walk(m.load(node+8,8));nodes.append(node)
        walk(m.load(head+8,8));self.assertGreaterEqual(len(nodes),3)
        for node in nodes:self.assertNotIn(node,r.allocations)
        with self.assertRaises(Exception):r._free_allocation(nodes[0])
        strings=[m.load(node+56,8) for node in nodes if m.load(node+40,1)&1]
        storage=r._custom_allocator_backend.storage
        with patch.object(storage,'free',wraps=storage.free) as free:
            startup.invoke(r,0x1C54B50,())
        freed=[call.args[0] for call in free.call_args_list]
        for pointer in nodes+strings:
            self.assertEqual(freed.count(pointer),1)
            self.assertNotIn(pointer,r._custom_allocator_backend.records)
        from qq_nt_replica.primary_device_records import _destroy_record_tree
        lower=r._operator_new(64);m.write(lower,bytes(64),source='test lower node')
        log._String.construct(r,b'inline').write_to(lower+40)
        with self.assertRaises(Exception):_invoke(r,0xB75029,lower)
        self.assertIn(lower,r.allocations)
        _destroy_record_tree(r,lower)
        self.assertNotIn(lower,r.allocations)
        self.assertTrue(set(nodes).isdisjoint(r._custom_allocator_backend.storage.live))
        self.assertLess(len(r._custom_allocator_backend.storage.live),len(live))
