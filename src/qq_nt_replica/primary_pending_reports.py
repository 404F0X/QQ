import struct

from .errors import InputError
from .primary_logger import _String, _cstring, _format, _srw
from .primary_sdk_records import _MASK64, _find, _index, _needed, _single, _unsigned_single, _prime
from .primary_worker_consumer import _append, _invoke
from .primary_worker_response import _frame
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_LIMIT = 1 << 20


def install_image(memory, base):
    memory.map(base + 0x677C0C0, bytearray(8), name='fixed pending report SRW PE zero fill', initialized=True)
    targets = (0x1BF3D40, 0x1BF3DB0, 0x1BF3DD0, 0x1BF3E40, 0x1BF3E90, 0x1BF3EE0)
    memory.map(base + 0x4148C38, b''.join((base + target).to_bytes(8, 'little') for target in targets),
               name='fixed pending report function vtable', initialized=True)
    targets = (0x1BF42A0, 0x1BF4300, 0x1BF4390, 0x1BF4450, 0x1BF4490, 0x1BF44D0)
    memory.map(base + 0x4148C88, b''.join((base + target).to_bytes(8, 'little') for target in targets),
               name='fixed pending report response vtable', initialized=True)
    memory.map(base + 0x46A6F72, b'%x%x%x%x\0', name='fixed pending command format literal', initialized=True)
    memory.map(base + 0x48A85B6, bytes.fromhex('4c6a6176612f6c616e672f537472696e'),
               name='fixed pending command key literal', initialized=True)


def _rehash(runtime, address, count):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x28, '1BF5770.pending_report_rehash_frame')
    if count >> 61:
        raise PrimarySemanticUnavailable('2439 pending report bucket allocation requires its original length exception')
    if count > _LIMIT:
        raise PrimaryProgramLimit('pending report bucket count exceeds the bounded execution domain')
    if not count:
        previous = memory.load(address, 8)
        memory.store(address, 0, 8, source='1BF57C9.pending_report_empty_buckets')
        if previous:
            _invoke(runtime, 0xB75029, previous)
        memory.store(address + 8, 0, 8, source='1BF57DA.pending_report_empty_bucket_count')
        memory.unmap(frame)
        return
    buckets = _invoke(runtime, 0xB75000, count * 8)
    previous = memory.load(address, 8)
    memory.store(address, buckets, 8, source='1BF57A1.pending_report_new_buckets')
    if previous:
        _invoke(runtime, 0xB75029, previous)
    memory.store(address + 8, count, 8, source='1BF57AE.pending_report_bucket_count')
    for index in range(count):
        memory.store(memory.load(address, 8) + index * 8, 0, 8, source='1BF57F0.pending_report_bucket_zero')
    current = memory.load(address + 16, 8)
    if not current:
        memory.unmap(frame)
        return
    current_bucket = _index(memory.load(current + 8, 8), count)
    memory.store(memory.load(address, 8) + current_bucket * 8, address + 16, 8, source='1BF58ED.pending_report_first_predecessor')
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
            memory.store(memory.load(address, 8) + bucket * 8, current, 8, source='1BF59A4.pending_report_new_predecessor')
            current, current_bucket = following, bucket
            continue
        last = following
        after = memory.load(last, 8)
        for _ in range(_LIMIT):
            if not after or memory.load(following + 16, 8) != memory.load(after + 16, 8):
                break
            last, after = after, memory.load(after, 8)
        else:
            raise PrimaryProgramLimit('pending equal-key report run exceeds the bounded execution domain')
        memory.store(current, after, 8, source='1BF5985.pending_report_detach_bucket_run')
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        memory.store(last, memory.load(predecessor, 8), 8, source='1BF5992.pending_report_bucket_run_tail')
        predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
        memory.store(predecessor, following, 8, source='1BF599C.pending_report_insert_bucket_run')
    raise PrimaryProgramLimit('pending report rehash traversal exceeds the bounded execution domain')


def rehash(runtime, address, requested):
    frame, _ = _frame(runtime, 0x28, '1BF5620.pending_report_capacity_frame')
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


def insert(runtime, address, output, key_pointer, pair):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x38, '1BF52B0.pending_report_insert_frame')
    key = memory.load(key_pointer, 8)
    count = memory.load(address + 8, 8)
    node = _find(runtime, address, key, count)
    if node:
        memory.store(output, node, 8, source='1BF55AF.pending_report_existing_node')
        memory.store(output + 8, 0, 1, source='1BF55B2.pending_report_duplicate')
        memory.unmap(frame)
        return output
    node = _invoke(runtime, 0xB75000, 56)
    memory.store(node + 16, memory.load(pair, 8), 8, source='1BF53EC.pending_report_key')
    _String.read(runtime, pair + 8).write_to(node + 24)
    memory.write(pair + 8, bytes(24), source='1BF5406.pending_report_payload_moved')
    memory.store(node + 48, memory.load(pair + 32, 1), 1, source='1BF541A.pending_report_mode')
    memory.store(node + 8, key, 8, source='1BF541D.pending_report_hash')
    memory.store(node, 0, 8, source='1BF5421.pending_report_initial_next')
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
        memory.store(node, memory.load(predecessor, 8), 8, source='1BF554B.pending_report_bucket_successor')
        memory.store(predecessor, node, 8, source='1BF554E.pending_report_bucket_insert')
    else:
        previous = memory.load(address + 16, 8)
        memory.store(node, previous, 8, source='1BF555B.pending_report_head_successor')
        memory.store(address + 16, node, 8, source='1BF555E.pending_report_head')
        memory.store(memory.load(address, 8) + bucket * 8, address + 16, 8,
                     source='1BF5562.pending_report_head_predecessor')
        if previous:
            previous_bucket = _index(memory.load(previous + 8, 8), count)
            memory.store(memory.load(address, 8) + previous_bucket * 8, node, 8,
                         source='1BF55A4.pending_report_previous_head_predecessor')
    memory.store(address + 24, (memory.load(address + 24, 8) + 1) & _MASK64, 8,
                 source='1BF55A8.pending_report_count')
    memory.store(output, node, 8, source='1BF55AF.pending_report_inserted_node')
    memory.store(output + 8, 1, 1, source='1BF55B2.pending_report_inserted')
    memory.unmap(frame)
    return output


def register(runtime, owner, payload, mode):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x90, '1BF33F0.pending_report_register_frame')
    _srw(runtime, base + 0x677C0C0, True)
    sequence = (memory.load(owner + 240, 8) + 1) & _MASK64
    memory.store(owner + 240, sequence, 8, source='1BF343D.pending_report_sequence')
    temporary = rbp - 32
    pair = rbp - 72
    _String.read(runtime, payload).clone().write_to(temporary)
    memory.store(temporary + 24, mode & 0xFFFFFFFF, 4, source='1BF3450.pending_report_temporary_mode')
    memory.store(pair, sequence, 8, source='1BF3453.pending_report_pair_key')
    _String.read(runtime, temporary).write_to(pair + 8)
    memory.write(temporary, bytes(24), source='1BF346A.pending_report_temporary_moved')
    memory.store(pair + 32, mode & 0xFFFFFFFF, 4, source='1BF3476.pending_report_pair_mode')
    insert(runtime, owner + 200, rbp - 88, pair, pair)
    _String.read(runtime, pair + 8).destroy()
    _String.read(runtime, temporary).destroy()
    _srw(runtime, base + 0x677C0C0, False)
    memory.unmap(frame)
    runtime.events.append(('request.pending_registered', owner, sequence))
    return sequence


def lookup(runtime, owner, output, sequence, output_mode):
    memory, base = runtime.memory, runtime.image_base
    frame, _ = _frame(runtime, 0x50, '1BF3530.pending_report_lookup_frame')
    temporary = frame + 0x28
    _srw(runtime, base + 0x677C0C0, True)
    node = _find(runtime, owner + 200, sequence, memory.load(owner + 208, 8))
    if not node:
        raise PrimarySemanticUnavailable('1BF369C pending report lookup requires original0102CC out_of_range exception')
    _String.read(runtime, node + 24).clone().write_to(temporary)
    mode = memory.load(node + 48, 1)
    memory.store(temporary + 24, mode, 1, source='1BF36B2.pending_report_lookup_mode')
    memory.store(output_mode, mode, 4, source='1BF36B5.pending_report_lookup_mode_output')
    _String.read(runtime, temporary).clone().write_to(output)
    _String.read(runtime, temporary).destroy()
    _srw(runtime, base + 0x677C0C0, False)
    memory.unmap(frame)
    return output


def extract(runtime, address, output, node):
    memory = runtime.memory
    count = memory.load(address + 8, 8)
    bucket = _index(memory.load(node + 8, 8), count)
    buckets = memory.load(address, 8)
    previous = memory.load(buckets + bucket * 8, 8)
    for _ in range(4096):
        current = memory.load(previous, 8)
        if current == node:
            break
        previous = current
    else:
        raise PrimaryProgramLimit('pending report extraction exceeds the bounded predecessor traversal')
    following = memory.load(node, 8)
    if previous == address + 16 or _index(memory.load(previous + 8, 8), count) != bucket:
        if not following or _index(memory.load(following + 8, 8), count) != bucket:
            memory.store(buckets + bucket * 8, 0, 8, source='1BF5CAE.pending_report_empty_bucket')
    if following:
        following_bucket = _index(memory.load(following + 8, 8), count)
        if following_bucket != bucket:
            memory.store(memory.load(address, 8) + following_bucket * 8, previous, 8,
                         source='1BF5CFA.pending_report_successor_bucket_predecessor')
    memory.store(previous, following, 8, source='1BF5D01.pending_report_unlink')
    memory.store(node, 0, 8, source='1BF5D04.pending_report_extracted_next')
    memory.store(address + 24, (memory.load(address + 24, 8) - 1) & _MASK64, 8,
                 source='1BF5D0B.pending_report_count')
    memory.store(output, node, 8, source='1BF5D14.pending_report_node_handle')
    memory.store(output + 8, address + 24, 8, source='1BF5D17.pending_report_node_allocator')
    memory.store(output + 16, 1, 1, source='1BF5D1B.pending_report_node_owned')
    return output


def erase(runtime, address, key_pointer):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x40, '1BF59E0.pending_report_erase_frame')
    count = memory.load(address + 8, 8)
    node = _find(runtime, address, memory.load(key_pointer, 8), count) if count else 0
    if not node:
        memory.unmap(frame)
        return 0
    handle = frame + 0x28
    _invoke(runtime, 0x1BF5B70, address, handle, node)
    node = memory.load(handle, 8)
    memory.store(handle, 0, 8, source='1BF5B34.pending_report_node_handle_released')
    if node:
        if memory.load(handle + 16, 1):
            _String.read(runtime, node + 24).destroy()
        _invoke(runtime, 0xB75029, node)
    memory.unmap(frame)
    return 1


def copy_capture(runtime, destination, source):
    memory = runtime.memory
    _String.read(runtime, source).clone().write_to(destination)
    memory.write(destination + 24, memory.read(source + 24, 16), source='1BF4203.pending_function_owner_and_sequence')
    _String.read(runtime, source + 40).clone().write_to(destination + 40)
    _String.read(runtime, source + 64).clone().write_to(destination + 64)
    return destination


def clone_function(runtime, source, destination=None):
    heap = destination is None
    if heap:
        destination = runtime._operator_new(104)
    runtime.memory.store(destination, runtime.image_base + 0x4148C38, 8,
                         source='1BF3DFB.pending_function_vtable' if heap else '1BF3DBB.pending_function_vtable')
    result = copy_capture(runtime, destination + 8, source + 8)
    return destination if heap else result


def destroy_function(runtime, pointer, deallocate=False, reset_vtable=False):
    if reset_vtable:
        runtime.memory.store(pointer, runtime.image_base + 0x4148C38, 8,
                             source='1BF3D52.pending_function_destructor_vtable')
    for offset in (72, 48, 8):
        _String.read(runtime, pointer + offset).destroy()
    if deallocate:
        runtime._free_allocation(pointer)


def clone_response(runtime, source, destination=None):
    heap = destination is None
    if heap:
        destination = runtime._operator_new(80)
    memory = runtime.memory
    memory.store(destination, runtime.image_base + 0x4148C88, 8,
                 source='1BF43B7.pending_response_clone_vtable' if heap else '1BF4321.pending_response_clone_vtable')
    memory.write(destination + 8, memory.read(source + 8, 16), source='1BF43BE.pending_response_clone_owner_and_sequence')
    for offset in (24, 48):
        _String.read(runtime, source + offset).clone().write_to(destination + offset)
    return destination if heap else destination + 48


def destroy_response(runtime, pointer, deallocate=False, reset_vtable=False):
    if reset_vtable:
        runtime.memory.store(pointer, runtime.image_base + 0x4148C88, 8,
                             source='1BF42B2.pending_response_destructor_vtable')
    for offset in (48, 24):
        _String.read(runtime, pointer + offset).destroy()
    if deallocate:
        runtime._free_allocation(pointer)


def destroy_failure_event(runtime, event):
    from .primary_task_exit import destroy_base_record
    runtime.memory.store(event, runtime.image_base + 0x4148CD8, 8,
                         source='1BF4B52.pending_failure_event_destructor_vtable')
    for offset in reversed(range(224, 392, 24)):
        _String.read(runtime, event + offset).destroy()
    destroy_base_record(runtime, event)


def respond(runtime, pointer, reply_pointer, reply_count, success_pointer, error_pointer):
    from .primary_worker_loop import _initialize
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x260, '1BF44D0.pending_response_frame')
    error = memory.load(error_pointer, 4)
    success = memory.load(success_pointer, 1)
    owner = memory.load(pointer + 8, 8)
    memory.store(rbp + 0x1D4, 0, 4, source='1BF4504.pending_response_initial_mode')
    sequence = memory.load(pointer + 16, 8)
    _invoke(runtime, 0x1BF3530, owner, rbp + 0x140, sequence, rbp + 0x1D4)
    memory.store(rbp - 72, memory.load(pointer + 16, 8), 8, source='1BF452C.pending_response_erase_key')
    _srw(runtime, base + 0x677C0C0, True)
    _invoke(runtime, 0x1BF59E0, owner + 200, rbp - 72)
    _srw(runtime, base + 0x677C0C0, False)
    mode = memory.load(rbp + 0x1D4, 4)
    if not success and mode <= 2:
        _invoke(runtime, 0x1BF2390, owner, 1, rbp + 0x140, pointer + 24, mode + 1, 0)
        event = rbp - 72
        memory.store(event, base + 0x4148CD8, 8, source='1BF463D.pending_failure_event_vtable')
        _String.construct(runtime, b'report_fail').write_to(event + 8)
        for offset in range(32, 200, 24):
            _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(event + offset)
        memory.write(event + 200, bytes(192), source='1BF4641.pending_failure_event_columns')
        _invoke(runtime, 0x75E9F0, rbp + 0x1A0, error)
        _String.read(runtime, rbp + 0x1A0).write_to(event + 224)
        _invoke(runtime, 0x75E7B0, rbp + 0x1A0, mode)
        _String.read(runtime, rbp + 0x1A0).write_to(event + 296)
        for offset in (0x158, 0x170):
            _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(rbp + offset)
        memory.write(rbp + 0x1A0, bytes(48), source='1BF4711.pending_failure_metadata_initialization')
        for source, target in ((0x170, 0x1A0), (0x158, 0x1B8)):
            _invoke(runtime, 0x75CEC0, rbp + target, rbp + source)
        _initialize(runtime, 1)
        _invoke(runtime, 0x1BE26C0, base + 0x67516B0, memory.load(base + 0x677DE28, 8),
                memory.load(base + 0x677DE30, 8))
        _invoke(runtime, 0x1BEEC40, owner, event, rbp + 0x1A0, 0)
        for offset in (0x1B8, 0x1A0, 0x170, 0x158):
            _String.read(runtime, rbp + offset).destroy()
        _invoke(runtime, 0x1BF4B40, event)
    _String.read(runtime, rbp + 0x140).destroy()
    memory.unmap(frame)
    runtime.events.append(('request.pending_response', owner, sequence, bool(success), error, mode))


def command(runtime, output):
    memory, base = runtime.memory, runtime.image_base
    formatted = _String.construct(runtime, _format(runtime, _cstring(runtime, base + 0x46A6F72),
                                                  (0x3E0, 0xF11, 0x191, 0x35B)))
    memory.write(output, bytes(24), source='1BF14B4.pending_command_empty_output')
    value = formatted.value()
    vector, capacity, decoded = 0, 0, bytearray()
    valid = not len(value) & 1
    if valid:
        for index in range(0, len(value), 2):
            pair = []
            for byte in value[index:index + 2]:
                if 65 <= byte <= 70:
                    byte += 32
                digit = byte - 87 if 97 <= byte <= 102 else byte - 48
                if not 0 <= digit < 16 or not (48 <= byte <= 57 or 97 <= byte <= 102):
                    valid = False
                    break
                pair.append(digit)
            if not valid:
                break
            byte = pair[0] * 16 + pair[1]
            if len(decoded) == capacity:
                capacity = max(1, capacity * 2)
                target = runtime._operator_new(capacity)
                memory.write(target, bytes(decoded) + bytes([byte]), source='1BF1636.pending_command_vector_growth')
                if vector:
                    runtime._free_allocation(vector)
                vector = target
            else:
                memory.store(vector + len(decoded), byte, 1, source='1BF1510.pending_command_vector_append')
            decoded.append(byte)
        if valid:
            temporary = _String.construct(runtime, bytes(decoded))
            result = _String.read(runtime, output)
            _append(result, temporary.value())
            result.write_to(output)
            temporary.destroy()
    if vector:
        runtime._free_allocation(vector)
    key = memory.read(base + 0x48A85B6, 16) + b'g;'
    result = _String.read(runtime, output)
    transformed = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(result.value()))
    if result.get(0, 1) & 1:
        memory.write(result.get(16, 8), transformed, source='1BF18B0.pending_command_xor')
    elif transformed:
        memory.write(output + 1, transformed, source='1BF18B0.pending_command_xor')
    formatted.destroy()
    return output


def send_pending(runtime, pointer):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0xD0, '1BF3EE0.pending_function_invoke_frame')
    owner = memory.load(pointer + 32, 8)
    gate = _invoke(runtime, 0xBA21A0)
    memory.store(rbp - 8, owner, 8, source='1BF3F14.pending_response_owner')
    memory.store(rbp, memory.load(pointer + 40, 8), 8, source='1BF3F1C.pending_response_sequence')
    for destination, source in ((rbp + 8, pointer + 48), (rbp + 32, pointer + 72)):
        _String.read(runtime, source).clone().write_to(destination)
    memory.store(rbp - 40, 0, 8, source='1BF3F3C.pending_response_empty_function')
    callback = runtime._operator_new(80)
    memory.store(callback, base + 0x4148C88, 8, source='1BF3F55.pending_response_vtable')
    memory.write(callback + 8, memory.read(rbp - 8, 16), source='1BF3F5C.pending_response_owner_and_sequence')
    for destination, source in ((callback + 24, rbp + 8), (callback + 48, rbp + 32)):
        _String.read(runtime, source).clone().write_to(destination)
    memory.store(rbp - 40, callback, 8, source='1BF3F89.pending_response_function_owner')
    for offset in (32, 8):
        _String.read(runtime, rbp + offset).destroy()
    tag = memory.load(pointer + 8, 1)
    if tag & 1:
        payload, count = memory.load(pointer + 24, 8), memory.load(pointer + 16, 4)
    else:
        payload, count = pointer + 9, tag >> 1
    _invoke(runtime, 0x1BF13C0, rbp - 32)
    _invoke(runtime, 0x1CE6920, gate, rbp - 32, payload, count, rbp - 72, pointer + 48, 1)
    memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva == 0x1BF3530 and len(values) == 4:
        return lookup(runtime, *values)
    if rva == 0x1BF59E0 and len(values) == 2:
        return erase(runtime, *values)
    if rva == 0x1BF5B70 and len(values) == 3:
        return extract(runtime, *values)
    if rva == 0x1BF4300 and len(values) == 2:
        return clone_response(runtime, *values)
    if rva == 0x1BF4390 and len(values) == 1:
        return clone_response(runtime, values[0])
    if rva in (0x1BF4450, 0x1BF4490) and len(values) == 1:
        return destroy_response(runtime, values[0], rva == 0x1BF4490)
    if rva == 0x1BF42A0 and len(values) == 2:
        destroy_response(runtime, values[0], bool(values[1] & 0xFFFFFFFF), True)
        return values[0]
    if rva == 0x1BF44D0 and len(values) == 5:
        return respond(runtime, *values)
    if rva == 0x1BF4B40 and len(values) == 1:
        return destroy_failure_event(runtime, values[0])
    if rva == 0x1BF33F0 and len(values) == 3:
        return register(runtime, *values)
    if rva == 0x1BF52B0 and len(values) == 4:
        return insert(runtime, *values)
    if rva == 0x1BF41E0 and len(values) == 2:
        return copy_capture(runtime, *values)
    if rva == 0x1BF3DB0 and len(values) == 2:
        return clone_function(runtime, *values)
    if rva == 0x1BF3DD0 and len(values) == 1:
        return clone_function(runtime, values[0])
    if rva in (0x1BF3E40, 0x1BF3E90) and len(values) == 1:
        return destroy_function(runtime, values[0], rva == 0x1BF3E90)
    if rva == 0x1BF3D40 and len(values) == 2:
        destroy_function(runtime, values[0], bool(values[1] & 0xFFFFFFFF), True)
        return values[0]
    if rva == 0x1BF13C0 and len(values) == 1:
        return command(runtime, values[0])
    if rva == 0x1BF3EE0 and len(values) == 1:
        return send_pending(runtime, values[0])
    raise InputError('pending report native entry argument count mismatch')
