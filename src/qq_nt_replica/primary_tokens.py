import hashlib
from pathlib import Path
from types import SimpleNamespace

from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed


_DATA = Path(__file__).with_name("data") / "primary_sign_qq52230"
_BANKS = (
    (0x655BD50, "source2581-hosts.bin", "f856e54b6a92ecfdffb5f528d55310b8f9623d7a3031a004913659aad7c73bb7"),
    (0x6556F98, "source2581-setter-hosts.bin", "78b21c3e03922d67ff4e1c1755b9e1c69b1700c1d04bd3b6a246959bd9466738"),
    (0x655BD90, "source2583-hosts.bin", "f856e54b6a92ecfdffb5f528d55310b8f9623d7a3031a004913659aad7c73bb7"),
    (0x6556FD0, "token-setter-hosts.bin", "7d357d00d30bc8d7960bdc0b2f49f7e7465da666016845c82c960e2445dc4d29"),
    (0x6556F20, "token-expire-hosts.bin", "3f2fef58d3380fdf492b0be0ab42a83643e8b80797285bfe7e2b6f563533dcb9"),
)


def install_image(memory, image_base):
    for rva, filename, expected in _BANKS:
        raw = (_DATA / filename).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise InputError("fixed token host bank identity mismatch: " + filename)
        relocated = b"".join((int.from_bytes(raw[index:index + 8], "little") - 0x180000000 + image_base)
                             .to_bytes(8, "little") for index in range(0, len(raw), 8))
        memory.map(image_base + rva, bytearray(relocated), name="fixed token host bank", initialized=True)
    memory.map(image_base + 0x6D88D74, bytearray(4), name="source2583 fresh PE zero fill", initialized=True)
    raw = (_DATA / "provider-token-alphabet.bin").read_bytes()
    if len(raw) != 68 or hashlib.sha256(raw).hexdigest() != "1991158b7d0f57d93eb566d95580962422772af6c21f0b6fd0f7d8981b0cd89a":
        raise InputError("fixed provider token alphabet constructor identity mismatch")
    memory.map(image_base + 0x6751510, bytearray(raw), name="source constructor-initialized provider token alphabet", initialized=True)


def provider_token(runtime, value):
    if not isinstance(value, bytes):
        raise InputError("provider token digest requires source bytes")
    memory, address = runtime.memory, runtime.image_base + 0x6751510
    if memory.load(address, 1) & 1:
        for index in range(64):
            byte = memory.load(address + 2 + index, 1)
            key = memory.load(address + 1, 1)
            memory.store(address + 2 + index, byte ^ ((index + 1) & 255) ^ key ^ 0x40, 1,
                         source="provider_token.alphabet_decode")
        memory.store(address + 66, 0, 1, source="provider_token.alphabet_terminator0")
        memory.store(address + 67, 0, 1, source="provider_token.alphabet_terminator1")
        memory.store(address, 0, 1, source="provider_token.alphabet_decoded_flag")
    alphabet = runtime._ansi_name(address + 2)
    if len(alphabet) != 64:
        raise PrimarySemanticUnavailable("provider token alphabet leaves the defined64-byte normal indexing domain")
    digest = hashlib.md5(value).digest()[:9]
    output = bytearray()
    for position in range(0, 9, 3):
        first, second, third = digest[position:position + 3]
        output.extend((alphabet[first >> 2], alphabet[((first & 3) << 4) | (second >> 4)],
                       alphabet[((second & 15) << 2) | (third >> 6)], alphabet[third & 63]))
    return bytes(output)


def construct_registry(runtime, address):
    memory, base = runtime.memory, runtime.image_base
    memory.store(address + 8, 0, 8, source="2DE910F.registry_root")
    memory.store(address + 16, 0, 8, source="2DE910F.registry_size")
    memory.store(address, address + 8, 8, source="2DE9113.registry_begin")
    for key, target in ((0x2581, 0x35A2B20), (0x2582, 0x35A2B8C), (0x2583, 0x35A2BF0)):
        parent, slot = address + 8, address + 8
        node = memory.load(slot, 8)
        while node:
            parent = node
            existing = memory.load(node + 32, 4, signed=True)
            if key == existing:
                raise PrimarySemanticUnavailable("fixed registry construction encountered an external duplicate key")
            slot = node if key < existing else node + 8
            node = memory.load(slot, 8)
        node = runtime._operator_new(48)
        memory.store(node + 32, key, 4, source="2DE9221.registry_key")
        memory.store(node + 40, base + target, 8, source="2DE9228.registry_callback")
        memory.store(node, 0, 8, source="4307.registry_left")
        memory.store(node + 8, 0, 8, source="4307.registry_right")
        memory.store(node + 16, parent, 8, source="430B.registry_parent")
        memory.store(slot, node, 8, source="430F.registry_link")
        first = memory.load(memory.load(address, 8), 8)
        if first:
            memory.store(address, first, 8, source="431D.registry_begin")
        root = memory.load(address + 8, 8)
        memory.store(node + 24, int(node == root), 1, source="434C.registry_color")
        if node != root and memory.load(parent + 24, 1) == 0:
            grand = memory.load(parent + 16, 8)
            if (memory.load(grand + 8, 8) != parent or memory.load(parent + 8, 8) != node or
                    memory.load(grand, 8) != 0 or memory.load(parent, 8) != 0 or grand != root):
                raise PrimarySemanticUnavailable("registry rebalancing leaves the fixed three-entry constructor domain")
            memory.store(parent + 24, 1, 1, source="43BE.registry_parent_black")
            memory.store(grand + 24, 0, 1, source="43C2.registry_grand_red")
            memory.store(grand + 8, 0, 8, source="43FE.registry_rotate_child")
            memory.store(parent + 16, memory.load(grand + 16, 8), 8, source="440F.registry_rotate_parent")
            memory.store(address + 8, parent, 8, source="441D.registry_rotate_root")
            memory.store(parent, grand, 8, source="4421.registry_rotate_left")
            memory.store(grand + 16, parent, 8, source="4424.registry_rotate_old_parent")
        memory.store(address + 16, (memory.load(address + 16, 8) + 1) & ((1 << 64) - 1), 8,
                     source="432F.registry_size_increment")
    return address


def publish_response_token(runtime, pointer):
    from .primary_token_family_direct import response_token_publication
    values = (pointer, 2, 0x2583)
    carrier = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    with response_token_publication(runtime, pointer, carrier):
        return runtime.invoke(carrier, 0x1BF7520, (0, 1, 2))


def dispatch_local(runtime, pointer, kind, key):
    from .primary_sdk import NativeByteReturn
    memory, base = runtime.memory, runtime.image_base
    registry = memory.load(base + 0x6D861C0, 8)
    if not registry:
        registry = runtime._operator_new(24)
        construct_registry(runtime, registry)
        memory.store(base + 0x6D861C0, registry, 8, source="2DE8C2C.registry_publish")
    sentinel = registry + 8
    node, candidate = memory.load(sentinel, 8), sentinel
    key = signed(key, 32)
    visited = 0
    while node:
        visited += 1
        if visited > 16384:
            raise PrimaryProgramLimit("registry lookup exceeds the bounded noncyclic tree domain")
        current = memory.load(node + 32, 4, signed=True)
        if current >= key:
            candidate, node = node, memory.load(node, 8)
        else:
            node = memory.load(node + 8, 8)
    if candidate == sentinel or key < memory.load(candidate + 32, 4, signed=True):
        return NativeByteReturn(255)
    target = memory.load(candidate + 40, 8)
    values = (pointer, kind & 0xFFFFFFFF)
    vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
    return runtime.invoke(vm, target - base, (0, 1))


def sort_expiry(runtime, address, count, width, comparator):
    if not width or not comparator or (not address and count):
        raise PrimarySemanticUnavailable("qsort invalid-parameter path needs CRT handler effects")
    if count * width > 1 << 20 or address + count * width >= 1 << 64:
        raise PrimaryProgramLimit("qsort range exceeds the bounded nonwrapping offline domain")
    if count < 2:
        return None
    memory = runtime.memory

    def compare(left, right):
        values = (left, right)
        vm = SimpleNamespace(cells=SimpleNamespace(value=lambda index: values[index]))
        result = runtime.invoke(vm, comparator - runtime.image_base, (0, 1))
        if type(result) is not int:
            raise PrimarySemanticUnavailable("qsort comparator needs a defined DWORD return")
        return signed(result, 32)

    def swap(left, right):
        if left == right:
            return
        for index in range(width):
            other = memory.load(right + index, 1)
            current = memory.load(left + index, 1)
            memory.store(left + index, other, 1, source="qsort.swap_left")
            memory.store(right + index, current, 1, source="qsort.swap_right")

    lo, hi, pending = address, address + (count - 1) * width, []
    while True:
        size = (hi - lo) // width + 1
        if size <= 8:
            while hi > lo:
                largest = lo
                for position in range(lo + width, hi + 1, width):
                    if compare(position, largest) > 0:
                        largest = position
                swap(largest, hi)
                hi -= width
            if not pending:
                return None
            lo, hi = pending.pop()
            continue
        mid = lo + (size // 2) * width
        if compare(lo, mid) > 0:
            swap(lo, mid)
        if compare(lo, hi) > 0:
            swap(lo, hi)
        if compare(mid, hi) > 0:
            swap(mid, hi)
        loguy, higuy = lo, hi
        while True:
            if loguy < mid:
                while True:
                    loguy += width
                    if loguy >= mid or compare(loguy, mid) > 0:
                        break
            if loguy >= mid:
                while True:
                    loguy += width
                    if loguy > hi or compare(loguy, mid) > 0:
                        break
            while True:
                previous_higuy = higuy
                higuy -= width
                if higuy <= mid or compare(higuy, mid) <= 0:
                    break
            if higuy < loguy:
                break
            swap(loguy, higuy)
            if mid == higuy:
                mid = loguy
        boundary = previous_higuy
        if mid < boundary:
            while True:
                boundary -= width
                if boundary <= mid or compare(boundary, mid) != 0:
                    break
        if mid >= boundary:
            while True:
                boundary -= width
                if boundary <= lo or compare(boundary, mid) != 0:
                    break
        if boundary - lo >= hi - loguy:
            if lo < boundary:
                pending.append((lo, boundary))
            if loguy < hi:
                lo = loguy
            elif pending:
                lo, hi = pending.pop()
            else:
                return None
        else:
            if loguy < hi:
                pending.append((loguy, hi))
            if lo < boundary:
                hi = boundary
            elif pending:
                lo, hi = pending.pop()
            else:
                return None
        if len(pending) > 62:
            raise PrimaryProgramLimit("qsort pending partitions exceed the native local stack")
