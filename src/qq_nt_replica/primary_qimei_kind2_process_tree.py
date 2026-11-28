"""Qimei 52230 RVAs 92963/AD762(mode0)/807C6: owning treeB producer.

No kind2 factory, treeA or downstream material consumer is supplied here.
"""
from dataclasses import dataclass
from .errors import InputError

SOURCE_SHA256 = 'a6100bce0de79ea52fe80a85acce2c24c615306fd3c2dedd119b51b0f26ebcc6'
ENTRY_SIZE = 568
INVALID_HANDLE_VALUE = (1 << 64) - 1


def _bool(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 32):
        raise InputError('process enumeration requires a backed BOOL DWORD')
    return bool(value & 0xFFFFFFFF)


def _acp(port, wide):
    count = port.call('WideCharToMultiByte', 0, 0, wide, -1, None, 0, None, None)
    if type(count) is not int or not 0 <= count <= 0x7FFFFFFF:
        raise InputError('process ACP conversion requires an actual nonnegative count')
    output = bytearray(count + 1)
    port.call('WideCharToMultiByte', 0, 0, wide, -1, output, count, None, None)
    # The extra zero is allocated but is outside the second call capacity.
    return bytes(output).split(b'\0', 1)[0]


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    parent_pid: int
    name: bytes
    second: bytes = b''


def enumerate_mode0(port):
    """Normal API FALSE ends iteration; host/backing exceptions propagate."""
    handle = port.call('CreateToolhelp32Snapshot', 2, 0)
    if type(handle) is not int or not -1 <= handle <= INVALID_HANDLE_VALUE:
        raise InputError('process snapshot requires a backed HANDLE')
    if handle in (-1, INVALID_HANDLE_VALUE):
        return ()
    entry = bytearray(ENTRY_SIZE)
    entry[:4] = ENTRY_SIZE.to_bytes(4, 'little')
    rows = []
    active = _bool(port.call('Process32FirstW', handle, entry))
    while active:
        if len(entry) != ENTRY_SIZE:
            raise InputError('process entry backing size changed')
        end = next((i for i in range(44, ENTRY_SIZE, 2) if entry[i:i+2] == b'\0\0'), None)
        if end is None:
            raise InputError('process entry has no backed UTF16 terminator')
        name = _acp(port, bytes(entry[44:end+2]))
        rows.append(ProcessRecord(int.from_bytes(entry[8:12], 'little'),
            int.from_bytes(entry[32:36], 'little'), name))
        active = _bool(port.call('Process32NextW', handle, entry))
    port.call('CloseHandle', handle)
    return tuple(rows)


def produce_process_tree(port):
    """92963: independent vector/name copies, nonempty case-sensitive byte set."""
    records = enumerate_mode0(port)
    copied = tuple(memoryview(row.name).tobytes() for row in records)
    return tuple(sorted({memoryview(name).tobytes() for name in copied if name}))
