from .errors import InputError
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
import math
import struct


DELETE_FREE_CELL = 0x5E954D8
DEFAULT_FREE_RVA = 0x3E94F90


def destroy(runtime, node):
    if type(node) is not int or not 0 <= node < 1 << 64:
        raise InputError('JSON delete requires an unsigned64 node pointer')
    memory = runtime.memory
    count = 0

    def release(pointer):
        target = memory.load(runtime.image_base + DELETE_FREE_CELL, 8)
        if target != runtime.image_base + DEFAULT_FREE_RVA:
            raise PrimarySemanticUnavailable('JSON delete current free hook is outside the default CRT domain')
        runtime._free_allocation(pointer)

    def walk(current, depth):
        nonlocal count
        if current and depth > 64:
            raise PrimaryProgramLimit('JSON delete recursion exceeds the staged normal domain')
        while current:
            count += 1
            if count > 4096:
                raise PrimaryProgramLimit('JSON delete node count exceeds the staged normal domain')
            following = memory.load(current, 8)
            tag = memory.load(current + 0x18, 4)
            if not tag & 0x100:
                child = memory.load(current + 0x10, 8)
                if child:
                    walk(child, depth + 1)
                    tag = memory.load(current + 0x18, 4)
            if not tag & 0x100:
                value = memory.load(current + 0x20, 8)
                if value:
                    release(value)
                    tag = memory.load(current + 0x18, 4)
            if not tag & 0x200:
                key = memory.load(current + 0x38, 8)
                if key:
                    release(key)
            release(current)
            current = following

    walk(node, 0)


COMPACT_ALLOC_CELL = 0x64290E0
COMPACT_FREE_CELL = 0x64290E8
DEFAULT_MALLOC_RVA = 0x3E97020
_COMPACT_LIMIT = 1 << 20


def compact(runtime, node, depth=0, fmt=0, printbuffer=0):
    for value in (node, printbuffer):
        if type(value) is not int or not 0 <= value < 1 << 64:
            raise InputError('JSON compact requires unsigned64 pointer arguments')
    if type(depth) is not int or not 0 <= depth <= 0xFFFFFFFF or type(fmt) is not int or not 0 <= fmt <= 0xFFFFFFFF:
        raise InputError('JSON compact requires DWORD depth and format arguments')
    if printbuffer or fmt:
        raise PrimarySemanticUnavailable('JSON compact supports only format zero and a NULL printbuffer')
    memory = runtime.memory
    visits = 0

    def bounded(size):
        if not 0 <= size <= _COMPACT_LIMIT:
            raise PrimaryProgramLimit('JSON compact size exceeds the nonoverflow bounded domain')
        return size

    def allocate(size):
        bounded(size)
        target = memory.load(runtime.image_base + COMPACT_ALLOC_CELL, 8)
        if target != runtime.image_base + DEFAULT_MALLOC_RVA:
            raise PrimarySemanticUnavailable('JSON compact current malloc hook is outside the default CRT domain')
        return runtime._allocate(max(size, 1), False)

    def release(pointer):
        target = memory.load(runtime.image_base + COMPACT_FREE_CELL, 8)
        if target != runtime.image_base + DEFAULT_FREE_RVA:
            raise PrimarySemanticUnavailable('JSON compact current free hook is outside the default CRT domain')
        runtime._free_allocation(pointer)

    def put(pointer, raw):
        memory.write(pointer, raw, source='2DF54B0.compact')

    def cstring(pointer):
        raw = bytearray()
        for offset in range(_COMPACT_LIMIT):
            value = memory.load(pointer + offset, 1)
            if not value:
                return bytes(raw)
            raw.append(value)
        raise PrimaryProgramLimit('JSON compact CString exceeds the bounded domain')

    def copy_string(destination, source, terminated):
        for offset in range(_COMPACT_LIMIT):
            value = memory.load(source + offset, 1)
            if not value:
                if terminated:
                    put(destination + offset, b'\0')
                return offset
            put(destination + offset, bytes((value,)))
        raise PrimaryProgramLimit('JSON compact CString copy exceeds the bounded domain')

    def quote(pointer):
        raw = cstring(pointer)
        short = {8: 98, 9: 116, 10: 110, 12: 102, 13: 114, 34: 34, 92: 92}
        escaped = any(value < 32 or value in (34, 92) for value in raw)
        length = sum(2 if value in short else 6 if value < 32 else 1 for value in raw) if escaped else len(raw)
        output = allocate(bounded(length + 3))
        if not output:
            return 0
        put(output, b'"')
        if not escaped:
            length = copy_string(output + 1, pointer, True)
            put(output + length + 1, b'"')
            put(output + length + 2, b'\0')
            return output
        cursor = output + 1
        for offset in range(_COMPACT_LIMIT):
            value = memory.load(pointer + offset, 1)
            if not value:
                put(cursor, b'"\0')
                return output
            if value >= 32 and value not in (34, 92):
                put(cursor, bytes((value,)))
                cursor += 1
                continue
            put(cursor, b'\\')
            if value in short:
                put(cursor + 1, bytes((short[value],)))
                cursor += 2
            else:
                digits = b'0123456789abcdef'
                put(cursor + 1, b'u00' + bytes((digits[value >> 4], digits[value & 15])) + b'\0')
                cursor += 6
        raise PrimaryProgramLimit('JSON compact escaped copy exceeds the bounded domain')

    def number(current):
        raw = memory.read(current + 0x30, 8)
        value = struct.unpack('<d', raw)[0]
        if value == 0:
            output = allocate(2)
            if output:
                put(output, b'0\0')
            return output
        integer = memory.load(current + 0x28, 4, signed=True)
        if abs(float(integer) - value) <= 2.0 ** -52 and -2147483648 <= value <= 2147483647:
            output = allocate(21)
            if not output:
                return 0
            integer = memory.load(current + 0x28, 4, signed=True)
            magnitude, digits = abs(integer), bytearray()
            while True:
                quotient = (magnitude * 0xCCCCCCCD) >> 35
                digits.append(48 + magnitude - quotient * 10)
                magnitude = quotient
                if not magnitude:
                    break
            put(output, (b'-' if integer < 0 else b'') + bytes(reversed(digits)) + b'\0')
            return output
        output = allocate(64)
        if not output:
            return 0
        absolute = abs(value)
        integral = math.isfinite(value) and abs(float(math.floor(value)) - value) <= 2.0 ** -52
        pattern = b'%.0f' if integral and absolute < 1e60 else b'%e' if absolute < 1e-6 or absolute > 1e9 else b'%f'
        request = (0x51C872, 0x3E6EE80, pattern, 'binary64', int.from_bytes(raw, 'little'), 64, 0, 0x3100AC, 1)
        error = PrimarySemanticUnavailable('JSON compact requires the exact typed CRT floating formatter')
        error.crt_format_request = request
        raise error

    def walk(current, level):
        nonlocal visits
        if not current:
            return 0
        if level > 64:
            raise PrimaryProgramLimit('JSON compact recursion exceeds the bounded domain')
        visits += 1
        if visits > 4096:
            raise PrimaryProgramLimit('JSON compact node count exceeds the bounded domain')
        tag = memory.load(current + 0x18, 1)
        if tag > 6:
            return 0
        if tag < 3:
            raw = (b'false\0', b'true\0', b'null\0')[tag]
            output = allocate(len(raw))
            if output:
                put(output + 4, raw[4:])
                put(output, raw[:4])
            return output
        if tag == 3:
            return number(current)
        if tag == 4:
            return quote(memory.load(current + 0x20, 8))
        child = memory.load(current + 0x10, 8)
        if not child:
            output = allocate(3)
            if output:
                if tag == 5:
                    put(output + 2, b'\0')
                    put(output, b'[]')
                else:
                    put(output, b'{')
                    put(output + 1, b'}\0')
            return output
        count, cursor = 0, child
        while cursor:
            cursor = memory.load(cursor, 8)
            count += 1
            if count > 4096:
                raise PrimaryProgramLimit('JSON compact sibling count exceeds the bounded domain')
        values = allocate(count * 8)
        if not values:
            return 0
        if tag == 5:
            put(values, bytes(count * 8))
            size = 5
            child = memory.load(current + 0x10, 8)
            index = 0
            failed = False
            while child:
                result = walk(child, level + 1)
                memory.store(values + index * 8, result, 8, source='2DF5CE0.array_result')
                if not result:
                    failed = True
                    break
                size = bounded(size + len(cstring(result)) + 2)
                index += 1
                child = memory.load(child, 8)
            output = 0 if failed else allocate(size)
            if output:
                put(output, b'[\0')
                cursor = output + 1
                for index in range(count):
                    result = memory.load(values + index * 8, 8)
                    length = len(cstring(result))
                    if length:
                        put(cursor, memory.read(result, length))
                    cursor += length
                    if index + 1 < count:
                        put(cursor, b',')
                        cursor += 1
                        put(cursor, b'\0')
                    release(memory.load(values + index * 8, 8))
                release(values)
                put(cursor, b']\0')
                return output
            for index in range(count):
                result = memory.load(values + index * 8, 8)
                if result:
                    release(result)
            release(values)
            return 0
        keys = allocate(count * 8)
        if not keys:
            release(values)
            return 0
        put(values, bytes(count * 8))
        put(keys, bytes(count * 8))
        child = memory.load(current + 0x10, 8)
        index, size, failed = 0, 7, False
        while child:
            key = quote(memory.load(child + 0x38, 8))
            memory.store(keys + index * 8, key, 8, source='2DF6079.object_key_result')
            result = walk(child, level + 1)
            memory.store(values + index * 8, result, 8, source='2DF6095.object_value_result')
            if not key or not result:
                failed = True
            else:
                value_length = len(cstring(result))
                key_length = len(cstring(key))
                size = bounded(size + value_length + key_length + 2)
            index += 1
            child = memory.load(child, 8)
        output = 0 if failed else allocate(size)
        if output:
            put(output, b'{')
            cursor = output + 1
            put(cursor, b'\0')
            for index in range(count):
                key = memory.load(keys + index * 8, 8)
                length = len(cstring(key))
                if length:
                    put(cursor, memory.read(key, length))
                cursor += length
                put(cursor, b':')
                cursor += 1
                value = memory.load(values + index * 8, 8)
                copy_string(cursor, value, True)
                cursor += len(cstring(memory.load(values + index * 8, 8)))
                if index + 1 < count:
                    put(cursor, b',')
                    cursor += 1
                put(cursor, b'\0')
                release(memory.load(keys + index * 8, 8))
                release(memory.load(values + index * 8, 8))
            release(keys)
            release(values)
            put(cursor, b'}\0')
            return output
        for index in range(count):
            key = memory.load(keys + index * 8, 8)
            if key:
                release(key)
            value = memory.load(values + index * 8, 8)
            if value:
                release(value)
        release(keys)
        release(values)
        return 0

    return walk(node, depth)
