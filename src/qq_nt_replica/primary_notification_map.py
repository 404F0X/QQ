import struct

from .errors import InputError
from .primary_logger import _String, _cstring
from .primary_request_manager import hash_bytes, rehash
from .primary_sdk_records import _MASK64, _index, _needed, _single, _unsigned_single
from .primary_vm import PrimaryProgramLimit
from .primary_worker_response import _frame


_LIMIT = 1 << 20


def construct_node(runtime, address, owner, hashed, moving_key, value):
    from .primary_worker_consumer import _invoke
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x48, '2E071C0.notification_map_node_frame')
    memory.store(frame + 0x40, _MASK64 - 1, 8, source='2E071D5.frame_sentinel')
    node = _invoke(runtime, 0xB75000, 64)
    memory.store(owner, node, 8, source='2E071FE.temporary_node')
    memory.store(owner + 8, address + 0x18, 8, source='2E07202.temporary_counter')
    memory.store(owner + 0x10, 0, 1, source='2E07206.temporary_unconstructed')
    memory.copy_disjoint(node + 0x20, moving_key + 0x10, 8, label='2E07213.move_key_tail')
    memory.copy_disjoint(node + 0x10, moving_key, 16, label='2E0721A.move_key_head')
    memory.write(moving_key, bytes(16), source='2E07221.clear_moved_key_head')
    memory.store(moving_key + 0x10, 0, 8, source='2E07224.clear_moved_key_tail')
    length = len(_cstring(runtime, value))
    if length >= _MASK64 - 15:
        raise PrimaryProgramLimit('notification map value length requires the original string length exception')
    destination = node + 0x28
    if length < 23:
        memory.store(destination, length * 2, 1, source='2E07252.value_short_flag')
        destination += 1
    else:
        memory.store(frame + 0x28, node + 0x10, 8, source='2E0725F.saved_key')
        memory.store(frame + 0x38, node, 8, source='2E07263.saved_node')
        memory.store(frame + 0x30, owner, 8, source='2E07267.saved_owner')
        capacity = (length + 16) & ~15
        destination = _invoke(runtime, 0xB75000, capacity)
        memory.store(node + 0x38, destination, 8, source='2E07285.value_long_pointer')
        memory.store(node + 0x28, capacity | 1, 8, source='2E0728D.value_long_capacity')
        memory.store(node + 0x30, length, 8, source='2E07291.value_long_length')
    if length:
        memory.copy_disjoint(destination, value, length, label='2E072A2.value_copy')
    memory.store(destination + length, 0, 1, source='2E072A7.value_terminator')
    memory.store(owner + 0x10, 1, 1, source='2E072AC.temporary_constructed')
    current = memory.load(owner, 8)
    memory.store(current + 8, hashed, 8, source='2E072B5.node_hash')
    memory.store(current, 0, 8, source='2E072B9.node_next')
    memory.unmap(frame)
    return owner


def insert(runtime, address, output, lookup_key, moving_key, value):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x68, '2E06D10.notification_map_insert_frame')
    owner = frame + 0x30
    memory.store(frame + 0x60, _MASK64 - 1, 8, source='2E06D25.frame_sentinel')
    memory.store(frame + 0x58, output, 8, source='2E06D33.saved_output')
    key = _String.read(runtime, lookup_key).value()
    hashed = hash_bytes(key)
    count = memory.load(address + 8, 8)
    if count:
        memory.store(frame + 0x48, moving_key, 8, source='2E06D6D.saved_move_key')
        memory.store(frame + 0x50, address, 8, source='2E06D71.saved_map')
        bucket = _index(hashed, count)
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        current = memory.load(predecessor, 8) if predecessor else 0
        for _ in range(_LIMIT):
            if not current:
                break
            current_hash = memory.load(current + 8, 8)
            if current_hash != hashed and _index(current_hash, count) != bucket:
                break
            if _String.read(runtime, current + 0x10).value() == key:
                memory.store(output, current, 8, source='2E0710E.existing_node')
                memory.store(output + 8, 0, 1, source='2E07111.duplicate')
                memory.unmap(frame)
                return output
            current = memory.load(current, 8)
        else:
            raise PrimaryProgramLimit('notification map lookup exceeds the bounded source domain')
    else:
        bucket = 0
    memory.store(frame + 0x20, value, 8, source='2E06F67.outgoing_value')
    construct_node(runtime, address, owner, hashed, moving_key, value)
    size = (memory.load(address + 0x18, 8) + 1) & _MASK64
    factor = struct.unpack('<f', memory.read(address + 0x20, 4))[0]
    if not count or _unsigned_single(size) > _single(_unsigned_single(count) * factor):
        required = _needed(runtime, address, size)
        growth = ((count * 2) | int(count < 3 or bool(count & (count - 1)))) & _MASK64
        rehash(runtime, address, max(growth, required))
        count = memory.load(address + 8, 8)
        bucket = _index(hashed, count)
    predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
    node = memory.load(owner, 8)
    if predecessor:
        memory.store(node, memory.load(predecessor, 8), 8, source='2E07092.bucket_successor')
        memory.store(predecessor, memory.load(owner, 8), 8, source='2E07099.bucket_insert')
    else:
        memory.store(node, memory.load(address + 0x10, 8), 8, source='2E070AA.head_successor')
        memory.store(address + 0x10, memory.load(owner, 8), 8, source='2E070B1.head_insert')
        memory.store(memory.load(address, 8) + bucket * 8, address + 0x10, 8, source='2E070B8.head_predecessor')
        previous = memory.load(memory.load(owner, 8), 8)
        if previous:
            previous_bucket = _index(memory.load(previous + 8, 8), count)
            memory.store(memory.load(address, 8) + previous_bucket * 8, memory.load(owner, 8), 8,
                         source='2E070FF.previous_predecessor')
    node = memory.load(owner, 8)
    memory.store(address + 0x18, memory.load(address + 0x18, 8) + 1, 8, source='2E07107.node_count')
    memory.store(output, node, 8, source='2E0710E.inserted_node')
    memory.store(output + 8, 1, 1, source='2E07111.inserted')
    memory.unmap(frame)
    return output


def invoke(runtime, rva, values):
    if rva not in (0x2E06D10, 0x2E071C0) or len(values) != 5:
        raise InputError('notification map native entry requires its five arguments')
    if any(type(value) is not int or not 0 <= value <= _MASK64 for value in values):
        raise InputError('notification map arguments require unsigned64 source values')
    return (insert if rva == 0x2E06D10 else construct_node)(runtime, *values)


def _copy_variant_string(runtime, destination, source):
    from .primary_worker_consumer import _invoke
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x28, '75B810.notification_variant_copy_frame')
    if not memory.load(source, 1) & 1:
        memory.copy_disjoint(destination + 16, source + 16, 8, label='75B825.copy_short_tail')
        memory.copy_disjoint(destination, source, 16, label='75B82C.copy_short_head')
    else:
        length = memory.load(source + 8, 8)
        pointer = memory.load(source + 16, 8)
        if length > _LIMIT:
            raise PrimaryProgramLimit('notification variant string copy exceeds the bounded source domain')
        if length <= 22:
            memory.store(destination, length * 2, 1, source='75B846.copy_short_flag')
            target = destination + 1
        else:
            capacity = (length | 15) + 1
            target = _invoke(runtime, 0xB75000, capacity)
            memory.store(destination + 16, target, 8, source='75B863.copy_long_pointer')
            memory.store(destination, capacity | 1, 8, source='75B86B.copy_long_capacity')
            memory.store(destination + 8, length, 8, source='75B86E.copy_long_length')
        memory.copy_disjoint(target, pointer, length + 1, label='75B87B.copy_payload_and_terminator')
    memory.unmap(frame)
    return destination


def construct_copy_node(runtime, address, owner, hashed, copying_key, value):
    from .primary_worker_consumer import _invoke
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x48, '35BD9E0.notification_copy_node_frame')
    memory.store(frame + 0x40, _MASK64 - 1, 8, source='35BD9F1.frame_sentinel')
    node = _invoke(runtime, 0xB75000, 64)
    memory.store(frame + 0x38, node, 8, source='35BDA16.saved_node')
    memory.store(owner, node, 8, source='35BDA1A.temporary_node')
    memory.store(owner + 8, address + 0x18, 8, source='35BDA1D.temporary_counter')
    memory.store(frame + 0x28, owner, 8, source='35BDA21.saved_owner')
    memory.store(owner + 0x10, 0, 1, source='35BDA25.temporary_unconstructed')
    _copy_variant_string(runtime, node + 0x10, copying_key)
    length = len(_cstring(runtime, value))
    if length >= _MASK64 - 15:
        memory.store(frame + 0x30, node + 0x10, 8, source='35BDACA.saved_key')
        raise PrimaryProgramLimit('notification variant value requires the original string length exception')
    destination = node + 0x28
    if length < 23:
        memory.store(destination, length * 2, 1, source='35BDA5A.value_short_flag')
        destination += 1
    else:
        memory.store(frame + 0x30, node + 0x10, 8, source='35BDA67.saved_key')
        capacity = (length + 16) & ~15
        destination = _invoke(runtime, 0xB75000, capacity)
        memory.store(node + 0x38, destination, 8, source='35BDA85.value_long_pointer')
        memory.store(node + 0x28, capacity | 1, 8, source='35BDA8D.value_long_capacity')
        memory.store(node + 0x30, length, 8, source='35BDA91.value_long_length')
    if length:
        memory.copy_disjoint(destination, value, length, label='35BDA9E.value_copy')
    memory.store(destination + length, 0, 1, source='35BDAA3.value_terminator')
    current_owner = memory.load(frame + 0x28, 8)
    memory.store(current_owner + 0x10, 1, 1, source='35BDAAB.temporary_constructed')
    current = memory.load(current_owner, 8)
    memory.store(current + 8, hashed, 8, source='35BDAB2.node_hash')
    memory.store(current, 0, 8, source='35BDAB6.node_next')
    memory.unmap(frame)
    return current_owner


def insert_variant(runtime, rva, address, output, lookup_key, source_key, value):
    memory = runtime.memory
    copying = rva == 0x35BD530
    frame_size = 0x68 if copying else 0x58
    frame, _ = _frame(runtime, frame_size, f'{rva:X}.notification_variant_insert_frame')
    memory.store(frame + frame_size - 8, _MASK64 - 1, 8, source=f'{rva:X}.frame_sentinel')
    if copying:
        memory.store(frame + 0x58, output, 8, source='35BD553.saved_output')
    key = _String.read(runtime, lookup_key).value()
    hashed = hash_bytes(key)
    count = memory.load(address + 8, 8)
    if not copying:
        memory.store(frame + 0x28, hashed, 8, source='35BDBDA.saved_hash')
    if count:
        memory.store(frame + (0x48 if copying else 0x38), source_key, 8, source=f'{rva:X}.saved_key')
        memory.store(frame + (0x50 if copying else 0x48), address, 8, source=f'{rva:X}.saved_map')
        bucket = _index(hashed, count)
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        if predecessor and not copying:
            memory.store(frame + 0x40, output, 8, source='35BDC97.saved_output')
        current = memory.load(predecessor, 8) if predecessor else 0
        for _ in range(_LIMIT):
            if not current:
                break
            current_hash = memory.load(current + 8, 8)
            if current_hash != hashed and _index(current_hash, count) != bucket:
                break
            if _String.read(runtime, current + 0x10).value() == key:
                memory.store(output, current, 8, source=f'{rva:X}.existing_node')
                memory.store(output + 8, 0, 1, source=f'{rva:X}.duplicate')
                memory.unmap(frame)
                return output
            current = memory.load(current, 8)
        else:
            raise PrimaryProgramLimit('notification variant lookup exceeds the bounded source domain')
    else:
        bucket = 0
    if copying:
        owner = frame + 0x30
        memory.store(frame + 0x20, value, 8, source='35BD787.outgoing_value')
        construct_copy_node(runtime, address, owner, hashed, source_key, value)
        node = memory.load(owner, 8)
    else:
        node = runtime._operator_new(64)
        memory.store(frame + 0x38, node + 0x10, 8, source='35BDDE6.saved_key_destination')
        memory.copy_disjoint(node + 0x20, source_key + 0x10, 8, label='35BDDEE.move_key_tail')
        memory.copy_disjoint(node + 0x10, source_key, 16, label='35BDDF5.move_key_head')
        memory.write(source_key, bytes(16), source='35BDDFC.clear_moved_key_head')
        memory.store(source_key + 0x10, 0, 8, source='35BDDFF.clear_moved_key_tail')
        memory.store(frame + 0x48, node, 8, source='35BDE07.saved_node')
        _copy_variant_string(runtime, node + 0x28, value)
        hashed = memory.load(frame + 0x28, 8)
        node = memory.load(frame + 0x48, 8)
        memory.store(node + 8, hashed, 8, source='35BDE22.node_hash')
        memory.store(node, 0, 8, source='35BDE26.node_next')
    size = (memory.load(address + 0x18, 8) + 1) & _MASK64
    factor = struct.unpack('<f', memory.read(address + 0x20, 4))[0]
    if not count or _unsigned_single(size) > _single(_unsigned_single(count) * factor):
        if not copying:
            memory.store(frame + 0x40, node + 0x28, 8, source='35BDE97.saved_value_destination')
        required = _needed(runtime, address, size)
        growth = ((count * 2) | int(count < 3 or bool(count & (count - 1)))) & _MASK64
        rehash(runtime, address, max(growth, required))
        count = memory.load(address + 8, 8)
        bucket = _index(hashed, count)
    predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
    if copying:
        node = memory.load(owner, 8)
    if predecessor:
        memory.store(node, memory.load(predecessor, 8), 8, source=f'{rva:X}.bucket_successor')
        memory.store(predecessor, node, 8, source=f'{rva:X}.bucket_insert')
    else:
        memory.store(node, memory.load(address + 0x10, 8), 8, source=f'{rva:X}.head_successor')
        memory.store(address + 0x10, node, 8, source=f'{rva:X}.head_insert')
        memory.store(memory.load(address, 8) + bucket * 8, address + 0x10, 8, source=f'{rva:X}.head_predecessor')
        previous = memory.load(node, 8)
        if previous:
            previous_bucket = _index(memory.load(previous + 8, 8), count)
            memory.store(memory.load(address, 8) + previous_bucket * 8, node, 8, source=f'{rva:X}.previous_predecessor')
    memory.store(address + 0x18, memory.load(address + 0x18, 8) + 1, 8, source=f'{rva:X}.node_count')
    memory.store(output, node, 8, source=f'{rva:X}.inserted_node')
    memory.store(output + 8, 1, 1, source=f'{rva:X}.inserted')
    memory.unmap(frame)
    return output


def invoke_variants(runtime, rva, values):
    if rva not in (0x35BD530, 0x35BDB80, 0x35BD9E0) or len(values) != 5:
        raise InputError('notification map variant requires its five source arguments')
    if any(type(value) is not int or not 0 <= value <= _MASK64 for value in values):
        raise InputError('notification map variant arguments require unsigned64 source values')
    if rva == 0x35BD9E0:
        return construct_copy_node(runtime, *values)
    return insert_variant(runtime, rva, *values)


def prepare_node(runtime, address, node):
    memory = runtime.memory
    key = _String.read(runtime, node + 16).value()
    hashed = memory.load(node + 8, 8)
    count = memory.load(address + 8, 8)
    if count:
        bucket = _index(hashed, count)
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        current = memory.load(predecessor, 8) if predecessor else 0
        for _ in range(_LIMIT):
            if not current:
                break
            current_hash = memory.load(current + 8, 8)
            if current_hash != hashed and _index(current_hash, count) != bucket:
                break
            if current_hash == hashed and _String.read(runtime, current + 16).value() == key:
                return current
            current = memory.load(current, 8)
        else:
            raise PrimaryProgramLimit('notification constructed-node lookup exceeds source bound')
    size = (memory.load(address + 24, 8) + 1) & _MASK64
    factor = struct.unpack('<f', memory.read(address + 32, 4))[0]
    if not count or _unsigned_single(size) > _single(_unsigned_single(count) * factor):
        growth = ((count * 2) | int(count < 3 or bool(count & (count - 1)))) & _MASK64
        rehash(runtime, address, max(growth, _needed(runtime, address, size)))
    return 0


def link_node(runtime, address, output, node):
    memory = runtime.memory
    previous = prepare_node(runtime, address, node)
    if previous:
        memory.store(output, previous, 8, source='2E074D0.existing_node')
        memory.store(output + 8, 0, 1, source='2E074D0.duplicate')
        return output
    count = memory.load(address + 8, 8)
    bucket = _index(memory.load(node + 8, 8), count)
    predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
    if predecessor:
        memory.store(node, memory.load(predecessor, 8), 8, source='2E07537.bucket_successor')
        memory.store(predecessor, node, 8, source='2E07537.bucket_insert')
    else:
        memory.store(node, memory.load(address + 16, 8), 8, source='2E07537.head_successor')
        memory.store(address + 16, node, 8, source='2E07537.head_insert')
        memory.store(memory.load(address, 8) + bucket * 8, address + 16, 8, source='2E07537.head_predecessor')
        following = memory.load(node, 8)
        if following:
            index = _index(memory.load(following + 8, 8), count)
            memory.store(memory.load(address, 8) + index * 8, node, 8, source='2E07537.next_predecessor')
    memory.store(address + 24, memory.load(address + 24, 8) + 1, 8, source='2E07537.node_count')
    memory.store(output, node, 8, source='2E07537.inserted_node')
    memory.store(output + 8, 1, 1, source='2E07537.inserted')
    return output


def insert_cstrings(runtime, address, output, key, value, *, move_value=False):
    from .primary_worker_consumer import _invoke
    memory = runtime.memory
    node = _invoke(runtime, 0xB75000, 64)
    _String.construct(runtime, _cstring(runtime, key)).write_to(node + 16)
    if move_value:
        memory.copy_disjoint(node + 40, value, 24, label='2E07C52.move_value')
        memory.write(value, bytes(24), source='2E07C69.clear_moved_value')
    else:
        _String.construct(runtime, _cstring(runtime, value)).write_to(node + 40)
    memory.store(node + 8, hash_bytes(_String.read(runtime, node + 16).value()), 8, source='2E073C4.node_hash')
    memory.store(node, 0, 8, source='2E073C8.node_next')
    link_node(runtime, address, output, node)
    if not memory.load(output + 8, 1):
        _String.read(runtime, node + 40).destroy()
        _String.read(runtime, node + 16).destroy()
        _invoke(runtime, 0xB75029, node)
    return output


def invoke_mandatory(runtime, rva, values):
    if rva in (0x2E07350, 0x2E07AB0) and len(values) == 4:
        return insert_cstrings(runtime, *values, move_value=rva == 0x2E07AB0)
    if rva == 0x2E074D0 and len(values) == 3:
        return link_node(runtime, *values)
    if rva == 0x2E077F0 and len(values) == 2:
        return prepare_node(runtime, *values)
    raise InputError('mandatory map wrapper requires its exact source ABI')
