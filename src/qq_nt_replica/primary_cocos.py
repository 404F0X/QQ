from .primary_vm import PrimaryProgramLimit


_MASK32 = 0xFFFFFFFF


def _rol(value, count):
    value &= _MASK32
    return ((value << count) | (value >> (32 - count))) & _MASK32


def decode_word(memory, pointer):
    value = memory.load(pointer, 8)
    length = memory.load(pointer + 9, 1)
    if length not in (1, 2, 4, 8):
        return 0
    state = memory.load(pointer + 8, 1)
    if not state:
        return 0
    result = 0
    for index in range(length):
        feedback = ((state >> 7) ^ (state >> 5) ^ (state >> 4) ^ (state >> 3)) & 1
        state = (((state << 1) | feedback) ^ ((0x37 + 0x9E * index) & 255)) & 255
        state = ((state << 3) | (state >> 5)) & 255
        state = state or (index ^ 0xA5)
        result |= (((value >> (8 * index)) & 255) ^ state) << (8 * index)
    return result


def seed_mt(memory, pointer, seed):
    value = seed & _MASK32
    memory.store(pointer, value, 4, source="2DE501C.MT_seed")
    for index in range(1, 624):
        value = (1812433253 * (value ^ (value >> 30)) + index) & _MASK32
        memory.store(pointer + 4 * index, value, 4, source="2DE5035.MT_seed")
    memory.store(pointer + 0x9C0, 0, 8, source="2DE5044.MT_index")


def next_mt(memory, pointer):
    index = memory.load(pointer + 0x9C0, 8)
    if index >= 624:
        raise PrimaryProgramLimit("MT state index lies outside its 624-word storage")
    following = (index + 1) % 624
    upper = memory.load(pointer + 4 * index, 4) & 0x80000000
    lower = memory.load(pointer + 4 * following, 4)
    value = ((upper | (lower & 0x7FFFFFFE)) >> 1) ^ memory.load(pointer + 4 * ((index + 397) % 624), 4)
    value ^= 0x9908B0DF if lower & 1 else 0
    memory.store(pointer + 4 * index, value, 4, source="00D07B.MT_twist")
    memory.store(pointer + 0x9C0, following, 8, source="00D090.MT_index")
    value ^= value >> 11
    value ^= (value << 7) & 0x9D2C5680
    value ^= (value << 15) & 0xEFC60000
    return (value ^ (value >> 18)) & _MASK32


def core8(memory, output, source):
    initial = [memory.load(source + 4 * index, 4) for index in range(16)]
    values = initial.copy()
    groups = ((3, 2, 1, 0), (6, 5, 4, 7), (9, 8, 11, 10), (12, 15, 14, 13),
              (3, 7, 11, 15), (6, 10, 14, 2), (9, 13, 1, 5), (12, 0, 4, 8))
    for _ in range(4):
        for a, b, c, d in groups:
            values[b] ^= _rol(values[a] + values[d], 7)
            values[c] ^= _rol(values[b] + values[a], 9)
            values[d] ^= _rol(values[c] + values[b], 13)
            values[a] ^= _rol(values[d] + values[c], 18)
    for index, (value, original) in enumerate(zip(values, initial)):
        memory.store(output + 4 * index, value + original, 4, source="35A2373.core8_publish")


def hash32(memory, pointer, length, seed):
    seed &= _MASK32
    if not pointer:
        value = (seed + 0x165667B1) & _MASK32
    else:
        remaining, offset = length, 0
        if remaining >= 16:
            accumulators = [(seed + 0x24234428) & _MASK32, (seed + 0x85EBCA77) & _MASK32,
                            seed, (seed + 0x61C8864F) & _MASK32]
            while remaining >= 16:
                for index in range(4):
                    word = memory.load(pointer + offset + 4 * index, 4)
                    accumulators[index] = (_rol(accumulators[index] + word * 0x85EBCA77, 13) * 0x9E3779B1) & _MASK32
                offset += 16
                remaining -= 16
            value = sum(_rol(item, count) for item, count in zip(accumulators, (1, 7, 12, 18))) & _MASK32
        else:
            value = (seed + 0x165667B1) & _MASK32
        value = (value + length) & _MASK32
        while remaining >= 4:
            word = memory.load(pointer + offset, 4)
            value = (_rol(value + word * 0xC2B2AE3D, 17) * 0x27D4EB2F) & _MASK32
            offset += 4
            remaining -= 4
        while remaining:
            value = (_rol(value + memory.load(pointer + offset, 1) * 0x165667B1, 11) * 0x9E3779B1) & _MASK32
            offset += 1
            remaining -= 1
    value = ((value ^ (value >> 15)) * 0x85EBCA77) & _MASK32
    value = ((value ^ (value >> 13)) * 0xC2B2AE3D) & _MASK32
    return value ^ (value >> 16)
