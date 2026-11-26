import unittest
from unittest.mock import patch

from qq_nt_replica.primary_memory import PrimaryMemory, PrimaryMemoryLimit, UnknownMemory
from qq_nt_replica.primary_vm import PackedProgram, PrimaryProgramLimit, PrimaryVM, VMType


class SignedGE(unittest.TestCase):
    def fixture(self, width=4, *, typ=0, destination=3):
        program = PackedProgram(b'', 3, (), (), (VMType(7, (width * 8,)),), (),
                                0, (0, 0x0F0C8754, typ, 1, 2, destination), (), 0, 0)
        memory = PrimaryMemory()
        memory.map(0x1000, bytearray(96), name='cells', initialized=False)
        return PrimaryVM(program, memory, cells_address=0x1000,
                         arena_address=0x2000, arena_size=0)

    def test_signed_boundaries_and_equal(self):
        for width in (1, 2, 4, 8, 3):
            bits = 8 * (width if width in (1, 2, 4) else 8)
            for left, right, expected in ((1 << (bits - 1), 1, 0),
                                          (1, 1 << (bits - 1), 1),
                                          ((1 << bits) - 1, (1 << bits) - 1, 1)):
                with self.subTest(width=width, left=left, right=right):
                    vm = self.fixture(width)
                    vm.cells.set_value(1, left, width=8, source='test')
                    vm.cells.set_value(2, right, width=8, source='test')
                    record = vm.step()
                    self.assertEqual(vm.memory.load(vm.cells.pointer(3), 4), expected)
                    self.assertEqual(vm.pc, 6)
                    self.assertEqual(record.operands, (0, 1, 2, 3))

    def test_alias_reads_before_dword_write_and_preserves_metadata(self):
        vm = self.fixture(destination=1)
        pointer = vm.cells.pointer(1)
        vm.memory.write(pointer, bytes(range(24)), source='test')
        vm.cells.set_value(1, 0x80000000, width=4, source='test')
        vm.cells.set_value(2, 1, width=4, source='test')
        before = vm.memory.read(pointer, 24)
        vm.step()
        self.assertEqual(vm.memory.read(pointer, 24), bytes(4) + before[4:])
        with self.assertRaises(UnknownMemory):
            vm.memory.read(vm.cells.pointer(3), 1)

    def test_two_width_queries_and_unknown_upper_bytes_remain_unknown(self):
        vm = self.fixture()
        vm.cells.set_value(1, 0xFF, width=1, source='test')
        vm.cells.set_value(2, 0xFFFF, width=2, source='test')
        with patch.object(PackedProgram, 'size', side_effect=(1, 2)) as size:
            vm.step()
        self.assertEqual(size.call_count, 2)
        self.assertEqual(vm.memory.load(vm.cells.pointer(3), 4), 1)
        with self.assertRaises(UnknownMemory):
            vm.memory.read(vm.cells.pointer(3) + 4, 20)

    def test_invalid_type_and_cell_propagate_without_store(self):
        for typ, error in ((99, PrimaryProgramLimit), (0, UnknownMemory)):
            vm = self.fixture(typ=typ)
            with self.assertRaises(error):
                vm.step()
            self.assertEqual(vm.pc, 6)
            with self.assertRaises(UnknownMemory):
                vm.memory.read(vm.cells.pointer(3), 4)
        vm = self.fixture(destination=99)
        for cell in (1, 2):
            vm.cells.set_value(cell, 0, width=4, source='test')
        with self.assertRaises(PrimaryMemoryLimit):
            vm.step()
