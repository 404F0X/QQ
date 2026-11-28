import hashlib
import json
from pathlib import Path
import struct

from .errors import InputError
from .primary_logger import _String, _cstring
from .primary_sdk_records import _MASK64, _index, _needed, _prime, _single, _unsigned_single
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = '0fe86090cde02b2faa7b7d514709f1501465238191d0814dc33d2b3d6b9c0993'
_LIMIT = 1 << 20
_K0 = 0xC3A5C85C97CB3127
_K1 = 0xB492B66FBE98F273
_K2 = 0x9AE16A3B2F90404F
_K3 = 0xC949D7C7509E6557


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/request-manager-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed request manager image identity mismatch')
    return json.loads(raw)


def _rotate(value, shift):
    value &= _MASK64
    shift &= 63
    return ((value << shift) | (value >> ((64 - shift) & 63))) & _MASK64


def _mix(value):
    value &= _MASK64
    return value ^ (value >> 47)


def _hash16(first, second):
    factor = 0x9DDFEA08EB382D69
    first = _mix(((first ^ second) * factor) & _MASK64)
    return (_mix(((second ^ first) * factor) & _MASK64) * factor) & _MASK64


def hash_bytes(value):
    length = len(value)

    def fetch(offset, width=8):
        return int.from_bytes(value[offset:offset + width], 'little')

    def weak(offset, first, second):
        a, b, c, d = (fetch(offset + index) for index in (0, 8, 16, 24))
        first = (first + a) & _MASK64
        second = _rotate(second + first + d, 43)
        middle = (first + b + c) & _MASK64
        return (middle + d) & _MASK64, (_rotate(middle, 20) + first + second) & _MASK64

    if length <= 16:
        if length > 8:
            last = fetch(length - 8)
            return _hash16(fetch(0), _rotate(last + length, -length)) ^ last
        if length >= 4:
            return _hash16(length + ((fetch(0, 4) << 3) & 0xFFFFFFFF), fetch(length - 4, 4))
        if not length:
            return _K2
        first = value[0] | (value[length >> 1] << 8)
        second = length | (value[-1] << 2)
        return (_mix(((first * _K2) ^ (second * _K3)) & _MASK64) * _K2) & _MASK64
    if length <= 32:
        first = (fetch(0) * _K1) & _MASK64
        second = fetch(8)
        third = (fetch(length - 8) * _K2) & _MASK64
        fourth = (fetch(length - 16) * _K0) & _MASK64
        return _hash16((_rotate(first - second, 21) + _rotate(third, 34) + fourth) & _MASK64,
                       (length + first + _rotate(second ^ _K3, 44) - third) & _MASK64)
    if length <= 64:
        middle, fourth, tail = fetch(16), fetch(24), fetch(length - 16)
        first = ((tail + length) * _K0 + fetch(0)) & _MASK64
        a, b = _rotate(first + fourth, 12), _rotate(first, 27)
        first = (first + fetch(8)) & _MASK64
        c = _rotate(first, 57)
        first = (first + middle) & _MASK64
        middle = (middle + fetch(length - 32)) & _MASK64
        last = (fetch(length - 8) + fourth) & _MASK64
        d, e = _rotate(last + middle, 12), _rotate(middle, 27)
        middle = (middle + fetch(length - 24)) & _MASK64
        f = _rotate(middle, 57)
        middle = (middle + tail) & _MASK64
        last = (last + middle) & _MASK64
        second = (e + fourth + f + d + _rotate(middle, 33) + first) & _MASK64
        first = (_rotate(first, 33) + c + b + a) & _MASK64
        last = ((last + first) * _K0 + second * _K2) & _MASK64
        return (_mix((_mix(last) * _K0 + first) & _MASK64) * _K2) & _MASK64
    first = fetch(length - 40)
    second = (fetch(length - 16) + fetch(length - 56)) & _MASK64
    third = _hash16((fetch(length - 48) + length) & _MASK64, fetch(length - 24))
    left = weak(length - 64, length, third)
    right = weak(length - 32, _K1 + second, first)
    first = (first * _K1 + fetch(0)) & _MASK64
    for offset in range(0, (length - 1) & ~63, 64):
        first = (_rotate(first + second + left[0] + fetch(offset + 8), 27) * _K1) & _MASK64
        second = (_rotate(second + left[1] + fetch(offset + 48), 22) * _K1) & _MASK64
        first ^= right[1]
        second = (second + left[0] + fetch(offset + 40)) & _MASK64
        third = (_rotate(third + right[0], 31) * _K1) & _MASK64
        left = weak(offset, left[1] * _K1, first + right[0])
        right = weak(offset + 32, third + right[1], second + fetch(offset + 16))
        first, third = third, first
    return _hash16((_hash16(left[0], right[0]) + _mix(second) * _K1 + third) & _MASK64,
                   (_hash16(left[1], right[1]) + first) & _MASK64)


def key_equal(runtime, first, second):
    left, right = _String.read(runtime, first), _String.read(runtime, second)
    left_size = left.get(8, 8) if left.get(0, 1) & 1 else left.get(0, 1) >> 1
    right_size = right.get(8, 8) if right.get(0, 1) & 1 else right.get(0, 1) >> 1
    if left_size != right_size:
        return False
    if left_size > _LIMIT:
        raise PrimaryProgramLimit('unordered String equality exceeds its bounded source domain')
    return not left_size or left.value() == right.value()


def lookup(runtime, address, output, key):
    memory = runtime.memory
    hashed = _invoke(runtime, 0x3C77E, address + 0x20, key)
    count = memory.load(address + 8, 8)
    found = 0
    if count:
        if count > _LIMIT:
            raise PrimaryProgramLimit('unordered String lookup bucket count exceeds its bounded source domain')
        bucket = _index(hashed, count)
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        current = memory.load(predecessor, 8) if predecessor else 0
        visited = set()
        while current:
            if current in visited or len(visited) >= _LIMIT:
                raise PrimaryProgramLimit('unordered String lookup traversal exceeds its bounded source domain')
            visited.add(current)
            cached = memory.load(current + 8, 8)
            if cached == hashed:
                if _invoke(runtime, 0x3CFCF, current + 0x10, key):
                    found = current
                    break
            elif _index(cached, count) != bucket:
                break
            current = memory.load(current, 8)
    memory.store(output, found, 8, source='8EE8C.unordered_lookup_output')
    return output


def raw_rehash(runtime, address, count):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x38, '3CDE2.request_manager_rehash_frame')
    if count >> 61:
        raise PrimarySemanticUnavailable('3CFC9 manager bucket allocation requires original2439 length exception')
    if count > _LIMIT:
        raise PrimaryProgramLimit('request manager bucket count exceeds the bounded source domain')
    buckets = runtime._operator_new(count * 8) if count else 0
    previous = memory.load(address, 8)
    memory.store(address, buckets, 8, source='3CF8E.request_manager_bucket_publish')
    if previous:
        runtime._free_allocation(previous)
    memory.store(address + 8, count, 8, source='3CE18.request_manager_bucket_count')
    if not count:
        memory.unmap(frame)
        return
    memory.write(buckets, bytes(count * 8), source='3CE26.request_manager_empty_buckets')
    current = memory.load(address + 16, 8)
    if current:
        current_bucket = _index(memory.load(current + 8, 8), count)
        memory.store(buckets + current_bucket * 8, address + 16, 8, source='3CEE6.request_manager_first_predecessor')
        for _ in range(_LIMIT):
            following = memory.load(current, 8)
            if not following:
                break
            bucket = _index(memory.load(following + 8, 8), count)
            if bucket == current_bucket:
                current = following
                continue
            predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
            if not predecessor:
                memory.store(memory.load(address, 8) + bucket * 8, current, 8,
                             source='3CF78.request_manager_new_predecessor')
                current, current_bucket = following, bucket
                continue
            last = following
            after = memory.load(last, 8)
            for _ in range(_LIMIT):
                if not after or _String.read(runtime, following + 16).value() != _String.read(runtime, after + 16).value():
                    break
                last, after = after, memory.load(after, 8)
            else:
                raise PrimaryProgramLimit('request manager equal-key run exceeds the bounded source domain')
            memory.store(current, after, 8, source='3CF58.request_manager_detach_run')
            predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
            memory.store(last, memory.load(predecessor, 8), 8, source='3CF66.request_manager_run_tail')
            memory.store(predecessor, following, 8, source='3CF70.request_manager_insert_run')
        else:
            raise PrimaryProgramLimit('request manager rehash traversal exceeds the bounded source domain')
    memory.unmap(frame)


def rehash(runtime, address, requested):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x20, '3CC9A.request_manager_capacity_frame')
    count = 2 if requested == 1 else requested if not requested & (requested - 1) else _prime(requested)
    previous = runtime.memory.load(address + 8, 8)
    if count < previous:
        needed = _needed(runtime, address, runtime.memory.load(address + 24, 8))
        if previous >= 3 and previous.bit_count() <= 1:
            needed = needed if needed < 2 else 1 << ((needed - 1).bit_length() & 63)
        else:
            needed = _prime(needed)
        count = max(count, needed)
        if count >= previous:
            runtime.memory.unmap(frame)
            return
    memory.unmap(frame)
    if count != previous:
        raw_rehash(runtime, address, count)


def insert(runtime, address, output, key_pointer, source):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x58, '92FC4.request_manager_insert_frame')
    value = _String.read(runtime, key_pointer).value()
    hashed = hash_bytes(value)
    count = memory.load(address + 8, 8)
    bucket = _index(hashed, count) if count else 0
    predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8) if count else 0
    current = memory.load(predecessor, 8) if predecessor else 0
    for _ in range(_LIMIT):
        if not current:
            break
        current_hash = memory.load(current + 8, 8)
        if current_hash != hashed and _index(current_hash, count) != bucket:
            break
        if _String.read(runtime, current + 16).value() == value:
            memory.store(output, current, 8, source='93268.request_manager_existing_node')
            memory.store(output + 8, 0, 1, source='9326B.request_manager_duplicate')
            memory.unmap(frame)
            return output
        current = memory.load(current, 8)
    else:
        raise PrimaryProgramLimit('request manager lookup exceeds the bounded source domain')
    node = runtime._operator_new(40)
    _String.read(runtime, source).clone().write_to(node + 16)
    memory.store(node + 8, hashed, 8, source='93310.request_manager_node_hash')
    memory.store(node, 0, 8, source='93314.request_manager_node_next')
    size = (memory.load(address + 24, 8) + 1) & _MASK64
    factor = struct.unpack('<f', memory.read(address + 32, 4))[0]
    if not count or _unsigned_single(size) > _single(_unsigned_single(count) * factor):
        required = _needed(runtime, address, size)
        growth = ((count * 2) | int(count < 3 or bool(count & (count - 1)))) & _MASK64
        rehash(runtime, address, max(growth, required))
        count = memory.load(address + 8, 8)
        bucket = _index(hashed, count)
    predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
    if predecessor:
        memory.store(node, memory.load(predecessor, 8), 8, source='931F5.request_manager_node_successor')
        memory.store(predecessor, node, 8, source='931FC.request_manager_bucket_insert')
    else:
        previous = memory.load(address + 16, 8)
        memory.store(node, previous, 8, source='9320D.request_manager_head_successor')
        memory.store(address + 16, node, 8, source='93214.request_manager_head_insert')
        memory.store(memory.load(address, 8) + bucket * 8, address + 16, 8, source='9321B.request_manager_head_predecessor')
        if previous:
            previous_bucket = _index(memory.load(previous + 8, 8), count)
            memory.store(memory.load(address, 8) + previous_bucket * 8, node, 8,
                         source='9324D.request_manager_previous_predecessor')
    memory.store(address + 24, size, 8, source='9325D.request_manager_node_count')
    memory.store(output, node, 8, source='93268.request_manager_inserted_node')
    memory.store(output + 8, 1, 1, source='9326B.request_manager_inserted')
    memory.unmap(frame)
    return output


def initialize_set(runtime, address, pair):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x30, '1224BDC.request_manager_set_frame')
    memory.write(address, bytes(32), source='1224BF1.request_manager_hash_initialization')
    memory.store(address + 32, 0x3F800000, 4, source='1224BF8.request_manager_load_factor')
    first, count = memory.load(pair, 8), memory.load(pair + 8, 8)
    _invoke(runtime, 0x28B53A, address, first, (first + count * 24) & _MASK64)
    memory.unmap(frame)
    return address


def insert_range(runtime, address, first, last):
    frame, _ = _frame(runtime, 0x38, '28B53A.request_manager_range_frame')
    for _ in range(4096):
        if first == last:
            runtime.memory.unmap(frame)
            return
        _invoke(runtime, 0x92FAA, address, frame + 0x20, first)
        first = (first + 24) & _MASK64
    raise PrimaryProgramLimit('request manager source range exceeds the bounded domain')


def construct(runtime, address):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x198, '1CF35E0.request_manager_constructor_frame')
    values = []
    for index, command in enumerate(_image()['commands']):
        for write in command['writes']:
            memory.store(rbp + write['offset'], write['value'], 1, source='1CF35E0.request_manager_command_initializer')
        flag = rbp + command['flag_offset']
        if memory.load(flag, 1) & 1:
            for offset in range(command['length']):
                value = memory.load(flag + offset + 2, 1) ^ (offset + 1) ^ memory.load(flag + 1, 1) ^ command['length']
                memory.store(flag + offset + 2, value, 1, source='1CF35E0.request_manager_command_decode')
            memory.store(flag + 2 + command['length'], 0, 1, source='1CF35E0.request_manager_command_terminator')
            memory.store(flag, 0, 1, source='1CF35E0.request_manager_command_flag_clear')
        value = _cstring(runtime, flag + 2)
        values.append(value)
        _String.construct(runtime, value).write_to(rbp - 72 + index * 24)
    memory.store(rbp - 88, rbp - 72, 8, source='1CF3EC8.request_manager_command_range')
    memory.store(rbp - 80, 4, 8, source='1CF3ECC.request_manager_command_count')
    _invoke(runtime, 0x1224BDC, address, rbp - 88)
    for offset in (0, -24, -48, -72):
        _String.read(runtime, rbp + offset).destroy()
    memory.write(address + 48, bytes(16), source='1CF3F08.request_manager_tree_initialization')
    memory.store(address + 40, address + 48, 8, source='1CF3F0D.request_manager_tree_begin')
    runtime.memory.unmap(frame)
    if not hasattr(runtime, '_constructed_request_managers'):
        runtime._constructed_request_managers = set()
    runtime._constructed_request_managers.add(address)
    runtime.events.append(('request.cache_manager_constructed', address, tuple(values)))
    return address


def invoke(runtime, rva, values):
    if rva == 0x3CFCF and len(values) == 2:
        return key_equal(runtime, *values)
    if rva == 0x8ED82 and len(values) == 3:
        return lookup(runtime, *values)
    if rva == 0x1CF35E0 and len(values) == 1:
        return construct(runtime, values[0])
    if rva == 0x1224BDC and len(values) == 2:
        return initialize_set(runtime, *values)
    if rva == 0x28B53A and len(values) == 3:
        return insert_range(runtime, *values)
    if rva == 0x92FAA and len(values) == 3:
        return insert(runtime, *values, values[2])
    if rva == 0x92FC4 and len(values) == 4:
        return insert(runtime, *values)
    if rva in (0x3CC9A, 0x3CDE2) and len(values) == 2:
        return (rehash if rva == 0x3CC9A else raw_rehash)(runtime, *values)
    if rva == 0x3C77E and len(values) == 2:
        return hash_bytes(_String.read(runtime, values[1]).value())
    if rva == 0x3C7D8 and len(values) == 2:
        first, last = values
    elif rva == 0x3C818 and len(values) == 3:
        first, last = values[1], values[1] + values[2]
    else:
        raise InputError('request manager native entry argument count mismatch')
    if not 0 <= last - first <= _LIMIT:
        raise PrimaryProgramLimit('request manager hash span exceeds the bounded source domain')
    return hash_bytes(runtime.memory.read(first, last - first) if last != first else b'')
