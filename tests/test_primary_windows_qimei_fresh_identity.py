import pytest

from qq_nt_replica.primary_device_hardware import AdapterBufferEffect
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
from qq_nt_replica.primary_windows_qimei_fresh_identity import source_disk_string, source_adapter_string, WindowsFreshIdentityHardware


def test_disk_source_predicate_and_bounds():
    for value, expected in [(b'A raw ', b'A raw '), (b'-raw', b' '), (b'9', b'9')]:
        raw = bytearray(1024)
        raw[16:20] = (24).to_bytes(4, 'little')
        raw[24:24+len(value)] = value
        assert source_disk_string(bytes(raw), 100) == expected
    raw[24] = 128
    with pytest.raises(QimeiRequestBoundary):
        source_disk_string(bytes(raw), 100)
    with pytest.raises(QimeiRequestBoundary):
        source_disk_string(bytes(raw), 20)


def adapter():
    raw, known = bytearray(704), bytearray(704)
    raw[404:408] = (3).to_bytes(4, 'little')
    raw[408:411] = b'\xaa\xbb\xcc'
    for start, size in [(12, 1), (272, 1), (404, 4), (408, 3), (448, 1)]:
        known[start:start+size] = b'\1' * size
    return AdapterBufferEffect(bytes(raw), bytes(known), ((0, None),))


def test_adapter_zero_extension_and_written_facts():
    assert source_adapter_string(adapter()) == b'aabbcc0000000000'
    effect = adapter()
    with pytest.raises(QimeiRequestBoundary):
        source_adapter_string(AdapterBufferEffect(effect.raw, bytes(704), effect.relocations))


def test_adapter_first_os_record_wins_without_sort():
    first = adapter()
    raw = first.raw + first.raw
    known = first.known + first.known
    # A numerically smaller later address must never replace first record.
    raw = raw[:1112] + b'\x01\x02\x03' + raw[1115:]
    assert source_adapter_string(AdapterBufferEffect(raw, known, ((0, 704), (704, None)))) == b'aabbcc0000000000'


class CPU:
    def __init__(self):
        self.calls = []

    def cpuid(self, leaf, subleaf):
        self.calls.append((leaf, subleaf))
        return (0, 0, 0, 0)


class API:
    def __init__(self):
        self.calls = []
        self.closed = False

    def request(self, name, args):
        self.calls.append((name, args))
        if name == 'GetWindowsDirectoryA': return 10, b'C:\\Windows\0', 0
        if name == 'CreateFileA': return (1 << 64)-1, b'', 5
        if name == 'LoadLibraryA': return 10, b'', 0
        if name == 'GetProcAddress': return 20, b'', 0
        if name == 'FreeLibrary': return 1, b'', 0
        if name == 'GetAdaptersInfo': return (0, (adapter(), 704), 0) if args[1] else (111, (None, 704), 0)
        raise AssertionError(name)

    def close(self): self.closed = True


def test_scripted_factory_fixed_leaves_space_and_cache():
    cpu, api = CPU(), API()
    hardware = WindowsFreshIdentityHardware(cpu, api=api)
    assert hardware.strings() == (b' ', b' ', b'aabbcc0000000000')
    assert hardware.strings() == (b' ', b' ', b'aabbcc0000000000')
    assert cpu.calls == [(x, 0) for x in (0x80000002, 0x80000003, 0x80000004)]
    assert [name for name, _ in api.calls].count('FreeLibrary') == 1
    hardware.close()
    assert api.closed


def test_close_failure_retains_ownership_and_borrowed_cpu():
    class Failing(API):
        def close(self): raise OSError('MODEL close failure')
    cpu, api = CPU(), Failing()
    hardware = WindowsFreshIdentityHardware(cpu, api=api)
    with pytest.raises(OSError): hardware.close()
    assert not hardware.closed
    assert hardware.cpu_source is cpu
