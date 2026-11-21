from .errors import InputError


def string_view(memory, address):
    tag = memory.load(address, 1)
    if tag & 1:
        return memory.load(address + 16, 8), memory.load(address + 8, 4)
    return address + 1, tag >> 1


def string_bytes(memory, address):
    pointer, length = string_view(memory, address)
    return memory.read(pointer, length) if length else b""


def write_string(memory, address, value, allocate):
    if not isinstance(value, bytes):
        raise InputError("native string value must be bytes")
    length = len(value)
    if length < 23:
        memory.store(address, length << 1, 1, source="2DE5B85.short_length")
        pointer = address + 1
    else:
        capacity = (length + 16) & ~15
        pointer = allocate(capacity, False)
        memory.store(address + 16, pointer, 8, source="2DE5BA7.long_pointer")
        memory.store(address, capacity | 1, 8, source="2DE5BAF.long_capacity")
        memory.store(address + 8, length, 8, source="2DE5BB2.long_length")
    if length:
        memory.write(pointer, value, source="2DE5BC1.string_copy")
    memory.store(pointer + length, 0, 1, source="2DE5BC6.terminator")
    return address
