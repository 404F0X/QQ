"""Complete conditional-normal host2252 16B mathematics for fixed QQ52230.

This does not execute or validate M/G/F gates, dispatch, or the native VM. Native
equivalence requires the frozen per-read normal gate/slot/ABI conditions, private
working memory, disjoint block/tables, and no interference, faults or concurrency.
It is not an all-state host, main signature function, or complete protocol.
"""

from hashlib import sha256
from pathlib import Path

from .errors import CapabilityUnavailable, InputError, LibraryLimitError
from . import primary_m16 as _m16

__all__ = ["normal_into", "COMPILED_TABLES"]

_BANKS = (
    ("pi", 64, "950371a100e35d80fb89f5bec4e5d943386fe24d9b8509d899515e7d338fdd05"),
    ("T", 491520, "04422fdc993c5e5db3dc3fee9b903876ab637053fd1425360617c31e5004a175"),
    ("N", 245760, "417b65b3a8ae9e038958879d7b00e8e67fc1b6c4b31832afb2049baa6f90f51c"),
    ("BYTE", 131072, "d001f42d66d504e12562c3c7dcf7906339f3013fc12341769af14bd4f90a5bcf"),
    ("TA", 163840, "bc00ddde10a759342a141e9015c8490aaab67437541533fffa0fab1d2a527a61"),
    ("TB", 163840, "f7fe444ee27216b24610d6026328dd6bd912e48ab2cbf0c23b28a14866585acc"),
)
_ASSET_DIR = Path(__file__).with_name("data") / "primary_host2252_qq52230"
_SIZE = 1196096
_T, _N, _BYTE, _TA, _TB = 0x40, 0x78040, 0xB4040, 0xD4040, 0xFC040
_RHO = (0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14)
_TREE = ((0, 2), (4, 6), (8, 10), (12, 14), (0, 4), (8, 12), (0, 8))


def _load_compiled_tables() -> bytes:
    parts = []
    for name, size, digest in _BANKS:
        try:
            data = (_ASSET_DIR / f"{name}.bin").read_bytes()
        except OSError as exc:
            raise CapabilityUnavailable(f"compiled host2252 bank {name} is unavailable") from exc
        if len(data) != size or sha256(data).hexdigest() != digest:
            raise CapabilityUnavailable(f"compiled host2252 bank {name} failed length/SHA256 validation")
        parts.append(data)
    return b"".join(parts)


COMPILED_TABLES = _load_compiled_tables()


def _view(buffer, name: str, minimum: int, *, writable: bool = False) -> memoryview:
    try:
        view = memoryview(buffer)
    except (TypeError, ValueError, BufferError) as exc:
        raise InputError(f"{name} must export a valid contiguous byte buffer") from exc
    if view.ndim != 1 or not view.c_contiguous or view.itemsize != 1 or view.format not in ("B", "b", "c"):
        raise InputError(f"{name} must be a one-dimensional contiguous B/b/c byte buffer")
    if view.nbytes < minimum or (writable and view.readonly):
        raise InputError(f"{name} needs at least {minimum} bytes" + (" and must be writable" if writable else ""))
    return view if view.format == "B" else view.cast("B")


def _m4_into(table, page: int, left, right, out) -> int:
    for k in range(4):
        a = left[k]
        b = right[k]
        high = table[page + 512 * k + ((a & 0xF0) | (b >> 4))]
        low = table[page + 512 * k + 256 + (((a << 4) & 0xFF) | (b & 15))]
        value = ((high << 4) & 0xFF) | (low & 15)
        out[k] = value
    return value


def _reduce_rows(tables, rows, first_page: int) -> None:
    pairs = tuple((i, i + 1) for i in range(0, 16, 2)) + _TREE
    for page, (a, b) in enumerate(pairs, first_page):
        start = _N + 8192 * page
        _m16.mix_into(tables[start:start + 8192], rows[a], rows[b], rows[a])


def _load_cell(tables, offset: int, out) -> None:
    value = int.from_bytes(tables[offset:offset + 4], "little")
    out[:] = value.to_bytes(4, "little")


def _bridge_into(block, tables) -> None:
    scratch = memoryview(bytearray(64))
    cells = [scratch[4 * c:4 * c + 4] for c in range(16)]
    for r in range(9):
        for j in range(0, 16, 4):
            for k in range(4):
                c = j + k
                value = block[_RHO[j // 4 + 4 * k]]
                _load_cell(tables, _TA + 4 * (4096 * r + 256 * c + value), cells[c])
            page = _T + 2048 * (24 * r + 6 * (j // 4))
            _m4_into(tables, page, cells[j], cells[j + 1], cells[j])
            _m4_into(tables, page + 2048, cells[j + 2], cells[j + 3], cells[j + 2])
            _m4_into(tables, page + 4096, cells[j], cells[j + 2], cells[j])
            # tmp[j] supplies all four indices and must be overwritten last.
            for k in (3, 2, 1, 0):
                c = j + k
                value = cells[j][k]
                _load_cell(tables, _TB + 4 * (4096 * r + 256 * c + value), cells[c])
            _m4_into(tables, page + 6144, cells[j], cells[j + 1], cells[j])
            _m4_into(tables, page + 8192, cells[j + 2], cells[j + 3], cells[j + 2])
            _m4_into(tables, page + 10240, cells[j], cells[j + 2], cells[j])
        for j in range(0, 16, 4):
            for k in range(4):
                block[j // 4 + 4 * k] = cells[j][k]


def _selector_at(tables, offset: int) -> int:
    selector = int.from_bytes(tables[offset:offset + 4], "little", signed=True)
    if not 0 <= selector < 16:
        raise LibraryLimitError(
            f"host2252 pi selector {selector} at offset {offset} exceeds this Python "
            "library's 0..15 support domain; previous block writes are retained"
        )
    return selector


def _expand_stage2(block, tables, rows) -> None:
    for i in range(0, 16, 4):
        for t in range(4):
            j = i + t
            selector = _selector_at(tables, 4 * (i // 4) + 16 * t)
            for lane in range(16):
                value = block[selector]
                rows[j][lane] = tables[_BYTE + 0x10000 + 4096 * j + 16 * value + lane]


def normal_into(block, *, tables) -> None:
    """Compute the entire conditional-normal 16B transform in place.

    tables is mandatory: choose fixed COMPILED_TABLES or current contiguous bank
    memory explicitly. Only block[:16] is written. Private/disjoint/no-interference
    memory and every frozen per-read gate/dispatch/ABI condition are caller premises;
    this function neither checks them nor simulates non-normal native/VM behavior.
    Structure errors precede writes. A signed pi selector outside 0..15 raises
    LibraryLimitError at its stage2 use point, retaining prior external writes.
    """
    block = _view(block, "block", 16, writable=True)
    tables = _view(tables, "tables", _SIZE)
    workspace = memoryview(bytearray(256))
    rows = [workspace[16 * i:16 * i + 16] for i in range(16)]
    for i in range(16):
        value = block[4 * (i % 4) + i // 4]
        start = _BYTE + 4096 * i + 16 * value
        loaded128 = bytes(tables[start:start + 16])
        rows[i][:] = loaded128
    _reduce_rows(tables, rows, 0)
    loaded128 = bytes(rows[0])
    block[:16] = loaded128
    _bridge_into(block, tables)
    _expand_stage2(block, tables, rows)
    _reduce_rows(tables, rows, 15)
    for i in range(16):
        block[i] = rows[0][4 * (i % 4) + i // 4]
