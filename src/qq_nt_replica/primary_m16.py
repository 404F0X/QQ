"""Parameterized primary host2252 M16 kernel for fixed QQ52230.

No real table values or table producer are supplied. This is one native kernel,
not the complete host2252, primary signer, or login protocol.
"""

from .errors import InputError


def _byte_view(buffer, name: str, minimum: int, *, writable: bool = False) -> memoryview:
    try:
        view = memoryview(buffer)
    except (TypeError, ValueError, BufferError) as exc:
        raise InputError(f"{name} must export a valid contiguous byte buffer") from exc
    if view.ndim != 1 or not view.c_contiguous or view.itemsize != 1 or view.format not in ("B", "b", "c"):
        raise InputError(f"{name} must be a one-dimensional contiguous B/b/c byte buffer")
    if view.nbytes < minimum:
        raise InputError(f"{name} must contain at least {minimum} bytes")
    if writable and view.readonly:
        raise InputError(f"{name} must be writable")
    return view if view.format == "B" else view.cast("B")


def mix_into(table, left, right, out) -> int:
    """Write exactly 16 bytes in native order and return the final byte as int.

    All four arguments are zero-copy buffer views. Table needs >=8192 bytes;
    left/right/out need >=16, and out must be writable. Overlapping views,
    including out==left and out aliasing table, retain current-memory semantics.
    The validation is this Python library's support domain, not native pointer
    validation. Concurrent mutation and native memory/stack faults are excluded.
    """
    t = _byte_view(table, "table", 8192)
    a_view = _byte_view(left, "left", 16)
    b_view = _byte_view(right, "right", 16)
    destination = _byte_view(out, "out", 16, writable=True)

    for k in range(16):
        # Preserve the five memory operations: A, B, table high, table low, out.
        a = a_view[k]
        b = b_view[k]
        high = t[512 * k + ((a & 0xF0) | (b >> 4))]
        low = t[512 * k + 256 + (((a << 4) & 0xFF) | (b & 0x0F))]
        value = ((high << 4) & 0xFF) | (low & 0x0F)
        destination[k] = value
    return value


def mix(table, left, right) -> bytes:
    """Allocate a separate 16-byte output using the caller's explicit table."""
    out = bytearray(16)
    mix_into(table, left, right, out)
    return bytes(out)
