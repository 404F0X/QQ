"""Source BODY2 invariants with synthetic current-memory tables, no oracle capture."""
from types import SimpleNamespace
import pytest
from qq_nt_replica.primary_memory import PrimaryMemory, UnknownMemory
from qq_nt_replica.primary_request_fingerprint_math import _column, TABLE_IMAGE_RVA, TABLE_IMAGE_SIZE


def fixture_memory():
    m = PrimaryMemory()
    tables = bytearray(TABLE_IMAGE_SIZE)
    tables[0x25000:0x40000] = bytes([0x12]) * 0x1b000
    m.map(TABLE_IMAGE_RVA, tables, name='synthetic source-shaped tables', initialized=True)
    m.map(0x1000, bytearray(range(16)), name='block', initialized=True)
    return m


def test_column_nibble_select_and_order():
    m = fixture_memory()
    _column(m, 0, 0x1000, 0, 0, 0, 0)
    # Zero DWORD lanes select low nibble2; constant packed slices combine to22.
    assert m.read(0x1000, 16) == bytes([0x22]*4) + bytes(range(4, 16))
    assert [w[0] for w in m.writes][-4:] == [0x1000, 0x1001, 0x1002, 0x1003]


def test_first_write_precedes_final_two_packed_reads():
    m = fixture_memory()
    original = m.load
    count = 0
    def load(address, width, **kwargs):
        nonlocal count
        if 0x4170ca0 + 0xb00 <= address < 0x4170ca0 + 0xb80:
            count += 1
            if count == 2:
                raise UnknownMemory('last pair unavailable')
        return original(address, width, **kwargs)
    m.load = load
    with pytest.raises(UnknownMemory, match='last pair'):
        _column(m, 0, 0x1000, 0, 0, 0, 0)
    assert m.read(0x1000, 4) == bytes([0x22, 1, 2, 3])

from qq_nt_replica.primary_request_fingerprint_math import apply_block_math, AUXILIARY_RVAS
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable


def full_runtime():
    m = fixture_memory()
    for row in range(16):
        m.write(TABLE_IMAGE_RVA + row*256, bytes([0x40+row])*256, source='test positional rows')
    m.map(AUXILIARY_RVAS[0], bytearray(12), name='current aux', initialized=True)
    m.writes.clear()
    return SimpleNamespace(memory=m, image_base=0)


def test_full_source_final_row_mapping():
    runtime = full_runtime()
    assert apply_block_math(runtime, 0x1000) is None
    assert runtime.memory.read(0x1000, 16) == bytes(0x40+r for r in
        (13,8,9,4,7,11,0,12,1,14,2,5,10,6,3,15))


def test_nonzero_current_aux_before_body_is_unsupported():
    runtime = full_runtime()
    runtime.memory.store(AUXILIARY_RVAS[0], 1, 4, source='test current update')
    with pytest.raises(PrimarySemanticUnavailable, match='1D2B996'):
        apply_block_math(runtime, 0x1000)
    assert runtime.memory.read(0x1000, 16) == bytes(range(16))


def test_nonzero_postbody_aux_preserves_column_writes():
    runtime = full_runtime()
    runtime.memory.store(AUXILIARY_RVAS[2], 1, 4, source='test current update')
    with pytest.raises(PrimarySemanticUnavailable, match='1D2C584'):
        apply_block_math(runtime, 0x1000)
    assert runtime.memory.read(0x1000, 16) == bytes([0x22]*4)+bytes(range(4,16))
