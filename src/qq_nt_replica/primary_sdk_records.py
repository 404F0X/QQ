import math
import struct

from .errors import InputError
from .primary_logger import _String, _decode, log
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _frame


_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20


def _single(value):
    try:
        return struct.unpack('<f', struct.pack('<f', value))[0]
    except OverflowError:
        return math.copysign(math.inf, value)


def _unsigned_single(value):
    def rounded(integer):
        shift = max(0, integer.bit_length() - 24)
        if not shift:
            return float(integer)
        whole, fraction = divmod(integer, 1 << shift)
        halfway = 1 << (shift - 1)
        whole += int(fraction > halfway or fraction == halfway and whole & 1)
        return float(whole << shift)

    if value < 1 << 63:
        return rounded(value)
    return rounded((value >> 1) | (value & 1)) * 2


def _needed(runtime, address, count):
    factor = struct.unpack('<f', runtime.memory.read(address + 32, 4))[0]
    numerator = _unsigned_single(count)
    value = (math.nan if not numerator else math.copysign(math.inf, factor)) if not factor else _single(numerator / factor)
    value = value if not math.isfinite(value) else float(math.ceil(value))

    def convert(number):
        return int(number) & _MASK64 if math.isfinite(number) and -(1 << 63) <= number < 1 << 63 else 1 << 63

    low = convert(value)
    high = convert(_single(value - (1 << 63)))
    return low | (high if low & (1 << 63) else 0)


def _prime(value):
    if value < 2:
        return 0 if not value else 2
    if value > _LIMIT:
        raise PrimaryProgramLimit('SDK record prime capacity exceeds the bounded execution domain')
    if value == 2:
        return 2
    candidate = value | 1
    while candidate <= _LIMIT:
        if all(candidate % divisor for divisor in range(3, math.isqrt(candidate) + 1, 2)):
            return candidate
        candidate += 2
    raise PrimaryProgramLimit('SDK record prime search exceeds the bounded execution domain')


def _index(value, count):
    return value & (count - 1) if not count & (count - 1) else value % count


def _rehash(runtime, address, count):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x28, '1BF5770.sdk_record_rehash_frame')
    if count >> 61:
        raise PrimarySemanticUnavailable('2439 SDK record bucket allocation requires its original length exception')
    if count > _LIMIT:
        raise PrimaryProgramLimit('SDK record bucket count exceeds the bounded execution domain')
    if not count:
        previous = memory.load(address, 8)
        memory.store(address, 0, 8, source='1BF57C9.sdk_empty_buckets')
        if previous:
            runtime._free_allocation(previous)
        memory.store(address + 8, 0, 8, source='1BF57DA.sdk_empty_bucket_count')
        memory.unmap(frame)
        return
    buckets = runtime._operator_new(count * 8)
    previous = memory.load(address, 8)
    memory.store(address, buckets, 8, source='1BF57A1.sdk_new_buckets')
    if previous:
        runtime._free_allocation(previous)
    memory.store(address + 8, count, 8, source='1BF57AE.sdk_bucket_count')
    for index in range(count):
        memory.store(memory.load(address, 8) + index * 8, 0, 8, source='1BF57F0.sdk_bucket_zero')
    current = memory.load(address + 16, 8)
    if not current:
        memory.unmap(frame)
        return
    current_bucket = _index(memory.load(current + 8, 8), count)
    memory.store(memory.load(address, 8) + current_bucket * 8, address + 16, 8, source='1BF58ED.sdk_first_predecessor')
    for _ in range(_LIMIT):
        following = memory.load(current, 8)
        if not following:
            memory.unmap(frame)
            return
        bucket = _index(memory.load(following + 8, 8), count)
        if bucket == current_bucket:
            current = following
            continue
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        if not predecessor:
            memory.store(memory.load(address, 8) + bucket * 8, current, 8, source='1BF59A4.sdk_new_predecessor')
            current, current_bucket = following, bucket
            continue
        last = following
        after = memory.load(last, 8)
        for _ in range(_LIMIT):
            if not after or memory.load(following + 16, 8) != memory.load(after + 16, 8):
                break
            last, after = after, memory.load(after, 8)
        else:
            raise PrimaryProgramLimit('SDK equal-key record run exceeds the bounded execution domain')
        memory.store(current, after, 8, source='1BF5985.sdk_detach_bucket_run')
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        memory.store(last, memory.load(predecessor, 8), 8, source='1BF5992.sdk_bucket_run_tail')
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        memory.store(predecessor, following, 8, source='1BF599C.sdk_insert_bucket_run')
    raise PrimaryProgramLimit('SDK record rehash traversal exceeds the bounded execution domain')


def rehash(runtime, address, requested):
    frame, _ = _frame(runtime, 0x28, '1BF5620.sdk_record_capacity_frame')
    count = 2 if requested == 1 else requested if not requested & (requested - 1) else _prime(requested)
    previous = runtime.memory.load(address + 8, 8)
    if count < previous:
        needed = _needed(runtime, address, runtime.memory.load(address + 24, 8))
        if previous >= 3 and previous.bit_count() <= 1:
            needed = needed if needed < 2 else (1 << ((needed - 1).bit_length() & 63))
        else:
            needed = _prime(needed)
        count = max(count, needed)
        if count >= previous:
            runtime.memory.unmap(frame)
            return
    if count != previous:
        runtime.memory.unmap(frame)
        return _rehash(runtime, address, count)
    runtime.memory.unmap(frame)


def _find(runtime, address, key, count):
    memory = runtime.memory
    if not count:
        return 0
    bucket = _index(key, count)
    predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
    if not predecessor:
        return 0
    for _ in range(_LIMIT):
        node = memory.load(predecessor, 8)
        if not node:
            return 0
        hashed = memory.load(node + 8, 8)
        if hashed == key:
            if memory.load(node + 16, 8) == key:
                return node
        elif _index(hashed, count) != bucket:
            return 0
        predecessor = node
    raise PrimaryProgramLimit('SDK record lookup exceeds the bounded execution domain')


def insert(runtime, address, output, key_pointer, pair, *, copy=False):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x38, '1C53770.sdk_record_copy_insert_frame' if copy else '1C53C90.sdk_record_move_insert_frame')
    rbp = frame + 0x30
    key = memory.load(key_pointer, 8)
    count = memory.load(address + 8, 8)
    node = _find(runtime, address, key, count)
    if node:
        memory.store(output, node, 8, source='sdk.record_existing_node')
        memory.store(output + 8, 0, 1, source='sdk.record_duplicate')
        memory.unmap(frame)
        return output
    node = runtime._operator_new(168)
    memory.store(rbp - 8, node, 8, source='sdk.record_temporary_owner')
    memory.store(node + 16, memory.load(pair, 8), 8, source='sdk.record_key')
    for offset in range(8, 152, 24):
        if copy:
            _String.read(runtime, pair + offset).clone().write_to(node + offset + 16)
        else:
            _String.read(runtime, pair + offset).write_to(node + offset + 16)
            memory.write(pair + offset, bytes(24), source='1C53C90.sdk_record_moved_source')
    memory.store(node + 8, key, 8, source='sdk.record_hash')
    memory.store(node, 0, 8, source='sdk.record_initial_next')
    size = (memory.load(address + 24, 8) + 1) & _MASK64
    factor = struct.unpack('<f', memory.read(address + 32, 4))[0]
    if _unsigned_single(size) > _single(_unsigned_single(count) * factor) or not count:
        required = _needed(runtime, address, size)
        growth = ((count * 2) | int(count < 3 or bool(count & (count - 1)))) & _MASK64
        rehash(runtime, address, max(growth, required))
        count = memory.load(address + 8, 8)
    bucket = _index(key, count)
    predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
    if predecessor:
        memory.store(node, memory.load(predecessor, 8), 8, source='sdk.record_bucket_successor')
        memory.store(predecessor, node, 8, source='sdk.record_bucket_insert')
    else:
        previous = memory.load(address + 16, 8)
        memory.store(node, previous, 8, source='sdk.record_head_successor')
        memory.store(address + 16, node, 8, source='sdk.record_head')
        memory.store(memory.load(address, 8) + bucket * 8, address + 16, 8, source='sdk.record_head_predecessor')
        if previous:
            previous_bucket = _index(memory.load(previous + 8, 8), count)
            memory.store(memory.load(address, 8) + previous_bucket * 8, node, 8, source='sdk.record_previous_head_predecessor')
    memory.store(address + 24, (memory.load(address + 24, 8) + 1) & _MASK64, 8, source='sdk.record_count')
    memory.store(output, node, 8, source='sdk.record_inserted_node')
    memory.store(output + 8, 1, 1, source='sdk.record_inserted')
    memory.unmap(frame)
    return output


def copy_map(runtime, output, source):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x40, '1C1B350.sdk_record_map_copy_frame')
    rbp = frame + 0x40
    memory.write(output + 16, bytes(16), source='1C1B36A.sdk_copy_root_count')
    memory.write(output, bytes(16), source='1C1B36E.sdk_copy_buckets')
    memory.store(output + 32, memory.load(source + 32, 4), 4, source='1C1B374.sdk_copy_load_factor')
    rehash(runtime, output, memory.load(source + 8, 8))
    node = memory.load(source + 16, 8)
    for _ in range(_LIMIT):
        if not node:
            memory.unmap(frame)
            return output
        insert(runtime, output, rbp - 0x20, node + 16, node + 16, copy=True)
        node = memory.load(node, 8)
    raise PrimaryProgramLimit('SDK record map copy exceeds the bounded execution domain')


def destroy_pair(runtime, pair):
    for offset in reversed(range(8, 152, 24)):
        _String.read(runtime, pair + offset).destroy()


def destroy_map(runtime, address):
    memory = runtime.memory
    node = memory.load(address + 16, 8)
    for _ in range(_LIMIT):
        if not node:
            buckets = memory.load(address, 8)
            memory.store(address, 0, 8, source='sdk.record_buckets_reset')
            if buckets:
                runtime._free_allocation(buckets)
            return
        following = memory.load(node, 8)
        destroy_pair(runtime, node + 16)
        runtime._free_allocation(node)
        node = following
    raise PrimaryProgramLimit('SDK global record destruction exceeds the bounded execution domain')


def destroy_global(runtime):
    frame, _ = _frame(runtime, 0x28, '1C03190.sdk_record_global_destruction_frame')
    destroy_map(runtime, runtime.image_base + 0x677CE58)
    runtime.memory.unmap(frame)


def produce(runtime, output):
    from .primary_sdk_collection import _image

    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x668, '1C03200.sdk_record_producer_frame')
    memory.store(rbp + 0x5E0, -2, 8, source='1C0321B.sdk_record_unwind_state')
    count = memory.load(base + 0x677CE70, 8)
    if not count:
        from .primary_sdk_probes import (cpu_detector, enumeration_detector, file_detector, first_detector,
                                        next_file_detector, next_service_detector, service_detector, value_detector)

        module_import = first_detector(runtime, rbp)
        module_import = file_detector(runtime, rbp, module_import)
        module_import = service_detector(runtime, rbp, module_import)
        value_detector(runtime, rbp, module_import)
        module_import = cpu_detector(runtime, rbp)
        module_import = next_file_detector(runtime, rbp, module_import)
        next_service_detector(runtime, rbp, module_import)
        module_import = cpu_detector(runtime, rbp, 'cached_cpu_detector')
        module_import = enumeration_detector(runtime, rbp, module_import)
        module_import = enumeration_detector(runtime, rbp, module_import, 'second_enumeration_detector')
        module_import = next_file_detector(runtime, rbp, module_import, 'third_file_detector')
        module_import = cpu_detector(runtime, rbp, 'second_cached_cpu_detector')
        module_import = enumeration_detector(runtime, rbp, module_import, 'third_enumeration_detector')
        next_file_detector(runtime, rbp, module_import, 'fourth_file_detector')
        cpu_detector(runtime, rbp, 'third_cached_cpu_detector')
        from .primary_sdk_probes import _literal
        from .primary_worker_consumer import _invoke

        tail = _image()['environment_probes']['cold_tail']
        if _invoke(runtime, tail['module_probe_rva']) & 0xFFFFFFFF:
            pair = rbp + 0x540
            memory.store(pair, tail['module_probe_key'], 8, source='1C18A89.sdk_module_record_key')
            memory.write(pair + 8, bytes(144), source='sdk.module_record_empty_strings')
            insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
            destroy_pair(runtime, pair)
        count = memory.load(base + 0x677CE70, 8)
        if not count:
            pair = rbp + 0x540
            memory.store(pair, tail['fallback_key'], 8, source='1C18B69.sdk_fallback_record_key')
            memory.write(pair + 8, bytes(144), source='sdk.fallback_record_empty_strings')
            insert(runtime, base + 0x677CE58, rbp + 0x478, pair, pair)
            destroy_pair(runtime, pair)
            count = memory.load(base + 0x677CE70, 8)
        template = _literal(runtime, rbp, tail['template'])
        filename = _literal(runtime, rbp, tail['file'])
        log(runtime, filename, tail['line'], template, bytes.fromhex(_image()['tag_hex']), 1, count)
    else:
        literals = _image()['record_producer_logs']
        log(runtime, _decode(literals['cached_file']), 15, _decode(literals['cached_template']),
            bytes.fromhex(_image()['tag_hex']), 1, count)
    copy_map(runtime, output, base + 0x677CE58)
    memory.unmap(frame)
    return output


def invoke(runtime, rva, values):
    if rva == 0x1C03200 and len(values) == 1:
        return produce(runtime, *values)
    if rva in (0x1C53C90, 0x1C53770) and len(values) == 4:
        return insert(runtime, *values, copy=rva == 0x1C53770)
    if rva == 0x1BF5620 and len(values) == 2:
        return rehash(runtime, *values)
    if rva == 0x1BF5770 and len(values) == 2:
        return _rehash(runtime, *values)
    if rva == 0x1C1B350 and len(values) == 2:
        return copy_map(runtime, *values)
    if rva == 0xBECD60 and len(values) == 1:
        return destroy_pair(runtime, *values)
    if rva == 0x1C03190 and not values:
        return destroy_global(runtime)
    if rva in (0x1C03150, 0x1C03170) and not values:
        pointer = runtime.image_base + (0x677CE28 if rva == 0x1C03150 else 0x677CE40)
        if runtime.memory.load(pointer, 1) & 1:
            runtime._free_allocation(runtime.memory.load(pointer + 16, 8))
        return None
    raise InputError('unsupported SDK record entry or argument count')
