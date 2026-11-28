import ast
import os
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_memory import PrimaryMemory
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable,PrimaryProgramLimit,signed
from qq_nt_replica import primary_crt_stdio_options as options
from qq_nt_replica import primary_sign

class MainPrintf(unittest.TestCase):
    def setUp(self):
        # Compile the actual branch unchanged, avoiding unrelated VM dispatch setup.
        tree=ast.parse(Path(primary_sign.__file__).read_text(encoding='utf-8'))
        branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=='rva == 7346036')
        function=ast.FunctionDef(name='branch',args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=n) for n in ('self','vm','cells','argument_types','arg')],kwonlyargs=[],kw_defaults=[],defaults=[]),body=branch.body,decorator_list=[])
        namespace=dict(__name__=primary_sign.__name__,__package__=primary_sign.__package__,PrimarySemanticUnavailable=PrimarySemanticUnavailable,PrimaryProgramLimit=PrimaryProgramLimit,signed=signed)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),primary_sign.__file__,'exec'),namespace)
        self.branch=namespace['branch']
        self.memory=PrimaryMemory();self.runtime=NS(memory=self.memory,image_base=0)
        self.memory.map(0x6749cc0,bytearray(8),name='controlled qualified source stdio',initialized=True)
        self.memory.map(0x1000,bytearray(128),name='bounded formatter source',initialized=True)
        self.memory.write(0x1040,b'%d\0',source='fixed %d test format')
        region,offset=self.memory._span(0x6749cc0,8);birth=(self.memory,0,region,offset)
        epoch=object();issuer=NS(epoch=epoch);self.runtime._primary_allocator_issuer=issuer
        owner=NS(_state='open',_pid=os.getpid(),_thread=threading.get_native_id())
        record=dict(runtime=self.runtime,state='complete',mode='controlled',owner=owner,issuer=issuer,epoch=epoch,birth=birth)
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.dict(options._BIRTHS,{id(self.memory):birth}))
        stack.enter_context(patch.dict(options._PHASES,{id(self.runtime):record}))
        stack.enter_context(patch('qq_nt_replica.primary_module_sync.backend',return_value='controlled'))
    def render(self,value,option=0x24,capacity=32,output=0x1000,format_address=0x1040,tailwidth=4):
        self.memory.store(0x6749cc0,option,8,source='controlled source global options')
        self.memory.store(0x1060,value&0xffffffff,4,source='explicit DWORD')
        args=(output,capacity,format_address,value)
        vm=NS(program=NS(type=lambda n:NS(raw=7),size=lambda n:tailwidth),cells=NS(pointer=lambda n:0x1060))
        return self.branch(self.runtime,vm,(0,1,2,3),(2,7,2,3),lambda n:args[n])
    def test_global0_and24_signed_boundaries_identical(self):
        for value,expected in ((0,b'0'),(-1,b'-1'),(-2147483648,b'-2147483648'),(2147483647,b'2147483647')):
            for option in (0,0x24):
                self.assertEqual(self.render(value,option),len(expected))
                self.assertEqual(self.memory.read(0x1000,len(expected)+1),expected+b'\0')
    def test_rejection_boundaries_preserved(self):
        for option in (1,2,4,0x20,0x25,0x26,1<<63):
            with self.assertRaises(PrimarySemanticUnavailable):self.render(1,option)
        with self.assertRaises(PrimaryProgramLimit):self.render(123,capacity=3)
        with self.assertRaises(PrimaryProgramLimit):self.render(1,output=0x1040)
        self.memory.write(0x1040,b'%s\0',source='unsupported format')
        with self.assertRaises(PrimarySemanticUnavailable):self.render(1)
        with self.assertRaises(PrimarySemanticUnavailable):self.render(1,tailwidth=8)
    def test_qualified_epoch_guard_remains_active(self):
        self.runtime._primary_allocator_issuer.epoch=object()
        from qq_nt_replica.errors import InputError
        with self.assertRaises(InputError):self.render(1)
