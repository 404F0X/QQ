"""Independent old-linear oracle and normal/fallback lookup contracts."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import random
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from qq_nt_replica.primary_memory import PrimaryMemory,_Region,PrimaryMemoryLimit,UnknownMemory
from qq_nt_replica.errors import InputError


def linear(memory,address,size):
    # Frozen pre-optimization algorithm, independent of the new locator.
    if type(address) is not int or type(size) is not int or size<0:
        raise InputError('memory access address/size must be integers and size nonnegative')
    address&=(1<<64)-1
    if address+size>(1<<64):raise PrimaryMemoryLimit('wrapped memory access is outside the Python support domain')
    for region in memory._regions:
        offset=address-region.address
        if 0<=offset and offset+size<=len(region.data):
            for issuer,alias,state,start,length,backing,identity in memory._PrimaryMemory__view_aliases.values():
                if alias is region or address<start+length and start<address+size:
                    issuer._validate_view_identity(identity,memory)
                    if alias is not region or state!='live' or region.data is not backing or region.address!=start or len(region.data)!=length:
                        raise PrimaryMemoryLimit('native view replaced/revoking/unknown; guest access denied')
            return region,offset
    raise PrimaryMemoryLimit(f'unmapped primary memory access at 0x{address:x}, width {size}')


class Lookup(unittest.TestCase):
    def memory(self):
        m=PrimaryMemory()
        m.map(16,b'ab',name='readonly',initialized=True)
        m.map(18,bytearray(b'cde'),name='adjacent',initialized=True)
        m.map(32,bytearray(b'wxyz'),name='gap',initialized=False)
        return m

    def same(self,m,address,size):
        # Separate old-linear object: do not escape/poison the tested layout.
        oracle=SimpleNamespace(_regions=m._region_snapshot(),
            _PrimaryMemory__view_aliases=m._PrimaryMemory__view_aliases)
        try:expected=linear(oracle,address,size)
        except BaseException as error:
            with self.assertRaises(type(error)) as actual:m._span(address,size)
            self.assertEqual(str(actual.exception),str(error))
        else:
            actual=m._span(address,size)
            self.assertIs(actual[0],expected[0]);self.assertEqual(actual[1],expected[1])

    def test_normal_binary_is_used_and_matches_original_object_offset_and_rejections(self):
        m=self.memory();m.map((1<<64)-4,b'last',name='end',initialized=True)
        self.assertFalse(m._layout_poisoned)
        cases=[(a,s) for a in range(0,42) for s in (0,1,2,4,8)]
        cases += [(-1,0),(-1,1),(-1,2),(1<<64,0),(1<<64,1),(True,1),(16,False),(16,-1),('16',1),(16,1.0)]
        rng=random.Random(824)
        cases.extend((rng.randrange(-(1<<65),1<<65),rng.randrange(0,9)) for _ in range(200))
        with patch.object(m,'_binary_region',wraps=m._binary_region) as fast:
            for address,size in cases:self.same(m,address,size)
            self.assertGreater(fast.call_count,300)
        # Independently prove that _span consumes its fast locator's result.
        marker=_Region(18,memoryview(b'cde'),bytearray(b'\1'*3),'fast branch marker')
        with patch.object(m,'_binary_region',return_value=(marker,)):
            self.assertIs(m._span(18,1)[0],marker)
        self.assertFalse(m._layout_poisoned)

    def test_actual_token_enumeration_keeps_concrete_fast_and_foreign_getter_protocol(self):
        import itertools
        from qq_nt_replica import primary_windows_device_process_records as process
        from qq_nt_replica import primary_windows_device_hardware as hardware
        class Foreign:
            def __init__(self,regions):self.original=regions;self.reads=0
            @property
            def _regions(self):self.reads+=1;return self.original
            def _region_snapshot(self):raise AssertionError('foreign snapshot must not be invoked')
        class NoList:
            def _region_snapshot(self):raise AssertionError('missing-list snapshot must not be invoked')
        class Subclass(PrimaryMemory):
            @property
            def _regions(self):return self.original
            def _region_snapshot(self):raise AssertionError('subclass getter protocol must be retained')
        sentinel=RuntimeError('original foreign getter error')
        class Bad:
            @property
            def _regions(self):raise sentinel
        for module,kind,base,step,args in (
                (process,process.WindowsDeviceProcessRecordObservations,0x6D0000000000,0x200000,(17,b'abc')),
                (hardware,hardware.WindowsDeviceHardwareObservations,0x6E0000000000,0x10000,(17,))):
            # This exercises the actual pure token method, without constructing
            # physical backends or claiming a source-qualified observation.
            region=_Region(base+step,memoryview(b'x'),bytearray([1]),'occupied token')
            concrete=PrimaryMemory();concrete.map(base+step,b'x',name='occupied token',initialized=True)
            foreign=Foreign([region]);subclass=Subclass();subclass.original=[region]
            cases=((SimpleNamespace(memory=concrete),base+2*step),
                   (SimpleNamespace(memory=None),base+step),(SimpleNamespace(),base+step),
                   (SimpleNamespace(memory=foreign),base+2*step),
                   (SimpleNamespace(memory=NoList()),base+step),
                   (SimpleNamespace(memory=subclass),base+2*step))
            for runtime,expected in cases:
                with self.subTest(module=module.__name__,runtime_type=type(getattr(runtime,'memory',None)).__name__):
                    owner=object.__new__(kind);owner._runtime=runtime;owner._tokens={}
                    with patch.object(module,'_TOKENS',itertools.count(1)):
                        self.assertEqual(owner._token(*args),expected)
                        self.assertEqual(owner._token(*args),expected)
                    self.assertEqual(len(owner._tokens),1)
            self.assertFalse(concrete._layout_poisoned)
            self.assertNotIn('_layout_first_escape',concrete.__dict__)
            self.assertGreaterEqual(foreign.reads,2)
            self.assertIs(foreign.original[0],region)
            owner=object.__new__(kind);owner._runtime=SimpleNamespace(memory=Bad());owner._tokens={}
            with patch.object(module,'_TOKENS',itertools.count(1)):
                with self.assertRaises(RuntimeError) as caught:owner._token(*args)
            self.assertIs(caught.exception,sentinel);self.assertEqual(owner._tokens,{})

    def test_zero_width_adjacent_boundary_preserves_preceding_readonly_priority(self):
        m=self.memory()
        self.assertIs(m._span(18,0)[0],m._region_snapshot()[0])
        with self.assertRaisesRegex(PrimaryMemoryLimit,'readonly'):m.write(18,b'',source='zero-width')
        self.assertEqual(m.writes,[])
        for address in (16,18,21,32,36):self.same(m,address,0)

    def test_every_external_list_mutator_poison_is_sticky_even_on_exception(self):
        operations=(lambda a,r:a.append(r),lambda a,r:a.extend([r]),lambda a,r:a.insert(0,r),
            lambda a,r:a.__setitem__(0,r),lambda a,r:a.__setitem__(slice(0,1),[r]),
            lambda a,r:a.__delitem__(0),lambda a,r:a.clear(),lambda a,r:a.pop(),
            lambda a,r:a.remove(a[0]),lambda a,r:a.sort(key=lambda x:-x.address),
            lambda a,r:a.reverse(),lambda a,r:a.__iadd__([r]),lambda a,r:a.__imul__(2),
            lambda a,r:a.pop(999),lambda a,r:a.__setitem__(999,r))
        for operation in operations:
            with self.subTest(operation=operation):
                m=self.memory();regions=m._regions
                r=_Region(8,memoryview(bytearray(b'q')),bytearray([1]),'external')
                try:operation(regions,r)
                except (IndexError,ValueError):pass
                self.assertTrue(m._layout_poisoned)
                for address in (8,16,18,21,32,36):self.same(m,address,0);self.same(m,address,1)
                regions.sort(key=lambda r:r.address)
                with patch.object(m,'_binary_region',side_effect=AssertionError('regained trust')):
                    self.same(m,18,0)

    def test_region_rebinding_and_whole_list_assignment_preserve_actual_mutable_objects(self):
        for field,value in (('address',18),('data',memoryview(bytearray(b'longer')))):
            m=self.memory();r=m._region_snapshot()[0];old=getattr(r,field)
            setattr(r,field,value);self.assertTrue(m._layout_poisoned)
            for address in (16,18,20,22):self.same(m,address,0);self.same(m,address,1)
            setattr(r,field,old);self.assertTrue(m._layout_poisoned)
        m=self.memory();original=m._regions;foreign=list(reversed(original))
        m._regions=foreign;self.assertIs(m._regions,foreign)
        self.same(m,18,0)
        m._regions=original;self.assertTrue(m._layout_poisoned)
        m=self.memory();r=m._region_snapshot()[2];mask=bytearray(b'\1'*4)
        r.initialized=mask;r.name='renamed'
        self.assertFalse(m._layout_poisoned);self.assertEqual(m.read(32,4),b'wxyz')
        mask[1]=0
        with self.assertRaises(UnknownMemory):m.read(32,4)

    def test_internal_mutation_failure_and_reentrant_external_change_never_rollback(self):
        m=self.memory()
        with patch.object(m,'_binary_region',side_effect=AssertionError('fast during mutation')):m.unmap(32)
        self.assertFalse(m._layout_poisoned);self.same(m,32,1)
        m.map(32,b'new',name='new',initialized=True);self.assertFalse(m._layout_poisoned)
        failure=RuntimeError('exact foreign deletion failure')
        class FailingRegions(list):
            def __delitem__(self,index):raise failure
        foreign=FailingRegions(m._regions);m._regions=foreign
        with self.assertRaises(RuntimeError) as caught:m.unmap(32)
        self.assertIs(caught.exception,failure);self.assertIs(m._regions,foreign)
        self.assertEqual(m.read(32,3),b'new')
        class Guard:
            def guard_mapping(self,address,data):memory._regions.reverse()
        memory=self.memory();memory._consumed_mgf_guard=Guard()
        memory.map(50,b'added',name='added',initialized=True)
        self.assertTrue(memory._layout_poisoned)
        del memory._consumed_mgf_guard
        self.same(memory,18,0)
        failed=self.memory()
        with self.assertRaises(PrimaryMemoryLimit):failed.map(17,b'bad',name='overlap',initialized=True)
        self.assertTrue(failed._layout_poisoned);self.assertEqual(len(failed._region_snapshot()),3)

    def test_alias_validation_runs_after_every_lookup_and_before_state_rejection(self):
        m=self.memory();region=m._region_snapshot()[1];identity=object();calls=[];failure=RuntimeError('issuer stale')
        class Issuer:
            stale=False
            def _validate_view_identity(self,receipt,memory):
                calls.append((receipt,memory))
                if self.stale:raise failure
        issuer=Issuer();token=object()
        record=[issuer,region,'live',region.address,len(region.data),region.data,identity]
        m._PrimaryMemory__view_aliases[token]=record
        for _ in range(3):self.assertIs(m._span(18,1)[0],region)
        self.assertEqual(len(calls),3)
        for state in ('revoking','unknown'):
            record[2]=state;self.same(m,18,1)
        issuer.stale=True
        with self.assertRaises(RuntimeError) as got:m._span(18,1)
        self.assertIs(got.exception,failure)
        issuer.stale=False;record[2]='live';record[4]+=1
        self.same(m,18,1)

    def test_shared_masks_copy_forget_consumed_guard_and_write_extent_are_unchanged(self):
        m=PrimaryMemory();backing=bytearray(b'abcd')
        m.map(16,backing,name='shared-a',initialized=True);m.map(32,backing,name='shared-b',initialized=True)
        mask=bytearray(b'\1'*4)
        snapshot=m._region_snapshot();snapshot[0].initialized=snapshot[1].initialized=mask
        self.assertFalse(m._layout_poisoned)
        m.write(16,b'Q',source='shared-write');self.assertEqual(m.read(32,1),b'Q')
        self.assertEqual(m.write_extent(m.writes[-1]),1)
        with self.assertRaisesRegex(PrimaryMemoryLimit,'shared initialization'):m.forget(16,1,source='forget')
        m.map(48,bytearray(4),name='copy-target',initialized=True)
        mask[1]=0;m.copy_disjoint(48,16,4,label='unknown-copy')
        self.assertIsNone(m.writes[-1][1]);self.assertEqual(m.write_extent(m.writes[-1]),4)
        with self.assertRaises(UnknownMemory):m.read(48,4)
        failure=RuntimeError('consumed guard first')
        class Guard:
            def guard_overlap(self,*args):raise failure
        m._consumed_mgf_guard=Guard()
        with self.assertRaises(RuntimeError) as got:m.read('invalid',-1)
        self.assertIs(got.exception,failure)

    def test_actual_owned_storage_unmaps_before_release_and_preserves_failed_delete_effects(self):
        from types import SimpleNamespace
        from qq_nt_replica.primary_custom_allocator import _OwnedStorage
        for fail in (False,True):
            with self.subTest(fail=fail):
                memory=PrimaryMemory();runtime=SimpleNamespace(memory=memory,image_base=0)
                selector=SimpleNamespace(epoch=object(),validate=lambda r:None)
                supplier=SimpleNamespace(validate=lambda r:None,take=lambda r,size:256)
                hooks=SimpleNamespace(before_allocate=lambda:None,before_free=lambda:None)
                storage=_OwnedStorage(runtime,selector,hooks,supplier)
                pointer=storage.allocate(4,0,0xB75000);region=storage.live[pointer][0]
                failure=RuntimeError('foreign deletion stops actual storage release')
                if fail:
                    class FailingRegions(list):
                        def __delitem__(self,index):raise failure
                    memory._regions=FailingRegions(memory._regions)
                    with self.assertRaises(RuntimeError) as got:storage.free(pointer)
                    self.assertIs(got.exception,failure)
                    self.assertEqual(len(region.data),4)
                    self.assertIs(memory._span(pointer,4)[0],region)
                    self.assertIn(pointer,storage.live)
                    self.assertFalse(any(region.initialized))
                    self.assertEqual(storage.source_free_seen,[])
                else:
                    storage.free(pointer)
                    with self.assertRaises(ValueError):len(region.data)
                    with self.assertRaises(PrimaryMemoryLimit):memory._span(pointer,4)
                    self.assertNotIn(pointer,storage.live)
                    self.assertEqual(len(storage.source_free_seen),1)
                    self.assertFalse(memory._layout_poisoned)

    def test_raw_getter_poison_precedes_descriptor_mutation_and_restore_never_retrusts(self):
        for operation in (lambda raw,r:list.reverse(raw),
                          lambda raw,r:list.__setitem__(raw,0,r),
                          lambda raw,r:list.__setitem__(raw,slice(0,2),[r])):
            with self.subTest(operation=operation):
                m=self.memory();snapshot=m._region_snapshot()
                self.assertIs(type(snapshot),tuple);self.assertFalse(m._layout_poisoned)
                raw=m._regions
                self.assertIs(type(raw),list);self.assertTrue(m._layout_poisoned)
                self.assertEqual(m._region_snapshot(),snapshot)
                first_escape=dict(m._layout_first_escape)
                replacement=_Region(30,memoryview(b'12345678'),bytearray(b'\1'*8),'descriptor region')
                operation(raw,replacement)
                self.assertEqual(m._region_snapshot(),tuple(raw))
                with patch.object(m,'_binary_region',side_effect=AssertionError('descriptor regained fast domain')):
                    for address in (16,18,21,30,32,36):self.same(m,address,0);self.same(m,address,1)
                list.__setitem__(raw,slice(None),snapshot)
                m._regions=raw
                self.assertIs(m._regions,raw)
                self.assertTrue(m._layout_poisoned)
                self.assertEqual(m._layout_first_escape,first_escape)
                self.assertEqual(m._region_snapshot(),snapshot)

    def test_snapshot_is_live_order_original_identity_without_exposure_or_reviving_unmap(self):
        m=self.memory();before=m._region_snapshot();original=before[2]
        self.assertFalse(m._layout_poisoned)
        m.unmap(32)
        self.assertFalse(m._layout_poisoned)
        self.assertFalse(any(r is original for r in m._region_snapshot()))
        self.assertIs(before[2],original)
        with self.assertRaises(PrimaryMemoryLimit):m.read(32,1)
        m.map(32,b'new',name='new region',initialized=True)
        self.assertIsNot(m._span(32,1)[0],original)
        self.assertFalse(m._layout_poisoned)


if __name__=='__main__':unittest.main()
