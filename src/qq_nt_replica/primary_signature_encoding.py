from .errors import InputError
from .primary_sdk_blob import push_character
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke


_MASK64 = (1 << 64) - 1
_LIMIT = 1 << 20
_INITIAL = bytes.fromhex(
    '012020202020202020202020202020202020202020202020202020201a1e1e1a1a'
    '26262a2a2e2e2a2a26263a3a3e3e3a3a26262a2a2e6567656b6d6f6d6b6567740f0000')
_IMAGE = ((0x677C1C0, _INITIAL + bytes(4)),
          (0x48A7DA8, bytes.fromhex('3c3d3d005d3c3d0068747470733a2f2f')),
          (0x48A7E68, bytes.fromhex('203d003b090d0a3d003e3f20414e4420')),
          (0x4903C10, bytes.fromhex('0000c689919800004c68629700000b4e')))


def complete_image_segment(rva, raw):
    for address, complete in _IMAGE[1:]:
        if rva == address and len(raw) <= len(complete):
            if raw != complete[:len(raw)]:
                raise InputError('signature encoding source image prefix differs')
            return complete
    return raw


def install_image(memory, base):
    for rva, raw in _IMAGE:
        pointer = base + rva
        overlaps = [region for region in memory._regions
                    if pointer < region.address + len(region.data)
                    and region.address < pointer + len(raw)]
        if not overlaps:
            memory.map(pointer, bytearray(raw), initialized=True,
                       name='fixed primary signature encoding image')
        elif rva != 0x677C1C0:
            if memory.read(pointer, len(raw)) != raw:
                raise InputError('signature encoding image overlaps different source bytes')
        else:
            memory._span(pointer, len(raw))


def _temporary(runtime, size, name):
    observed, address, initial = runtime._next(runtime._temporaries, name, size)
    if observed != size or type(address) is not int or not 0 < address <= _MASK64 - size:
        raise InputError(name + ' requires its explicit private address and size')
    if initial is not None and (not isinstance(initial, bytes) or len(initial) != size):
        raise InputError(name + ' requires complete initial bytes or unknown storage')
    runtime.memory.map(address, bytearray(size) if initial is None else bytearray(initial),
                       name=name, initialized=initial is not None)
    return address


def _finish(runtime, address, size):
    runtime.memory.forget(address, size, source='signature_encoding.private_lifetime_end')
    if not runtime.retain_frames:
        runtime.memory.unmap(address)


def _copy(runtime, destination, source, size):
    if size:
        _invoke(runtime, 0x3EB1FE0, destination, source, size)


def _length(runtime, string):
    first = runtime.memory.load(string, 1)
    return runtime.memory.load(string + 8, 8) if first & 1 else first >> 1


def _data(runtime, string):
    return runtime.memory.load(string + 16, 8) if runtime.memory.load(string, 1) & 1 else string + 1


def _bounded(length):
    if length >= _MASK64 - 15:
        raise PrimaryProgramLimit('signature encoding string length enters the native length-error path')
    if length > _LIMIT:
        raise PrimaryProgramLimit('signature encoding string exceeds the bounded memory domain')


def _construct(runtime, destination, source, length):
    _bounded(length)
    memory = runtime.memory
    if length < 23:
        memory.store(destination, 2 * length, 1, source='signature_encoding.short_length')
        pointer = destination + 1
    else:
        physical = (length + 16) & ~15
        pointer = runtime._operator_new(physical)
        memory.store(destination + 16, pointer, 8, source='signature_encoding.heap_pointer')
        memory.store(destination, physical | 1, 8, source='signature_encoding.heap_capacity')
        memory.store(destination + 8, length, 8, source='signature_encoding.heap_length')
    _copy(runtime, pointer, source, length)
    memory.store(pointer + length, 0, 1, source='signature_encoding.construct_NUL')


def _clone(runtime, destination, source):
    memory = runtime.memory
    if not memory.load(source, 1) & 1:
        memory.copy_disjoint(destination + 16, source + 16, 8,
                             label='75B825.signature_encoding_short_tail')
        memory.copy_disjoint(destination, source, 16,
                             label='75B82C.signature_encoding_short_prefix')
        return
    length = memory.load(source + 8, 8)
    pointer = memory.load(source + 16, 8)
    _bounded(length)
    if length <= 22:
        memory.store(destination, 2 * length, 1, source='75B846.signature_encoding_short_length')
        target = destination + 1
    else:
        physical = (length | 15) + 1
        target = runtime._operator_new(physical)
        memory.store(destination + 16, target, 8, source='75B863.signature_encoding_clone_pointer')
        memory.store(destination, physical | 1, 8, source='75B86B.signature_encoding_clone_capacity')
        memory.store(destination + 8, length, 8, source='75B86E.signature_encoding_clone_length')
    _copy(runtime, target, pointer, length + 1)


def _destroy(runtime, string):
    if runtime.memory.load(string, 1) & 1:
        runtime._free_allocation(runtime.memory.load(string + 16, 8))


def _decode_alphabet(runtime):
    memory, begin = runtime.memory, runtime.image_base + 0x677C1C0
    if memory.load(begin, 1) & 1:
        for index in range(64):
            value = memory.load(begin + 2 + index, 1)
            seed = memory.load(begin + 1, 1)
            memory.store(begin + 2 + index, value ^ ((index + 1) & 255) ^ seed ^ 0x40, 1,
                         source='signature_encoding.alphabet_decode')
        memory.store(begin + 66, 0, 1, source='signature_encoding.alphabet_NUL')
        memory.store(begin + 67, 0, 1, source='signature_encoding.alphabet_extra_NUL')
        memory.store(begin, 0, 1, source='signature_encoding.alphabet_flag')
    return begin + 2


def _assign_cstring(runtime, string, source):
    memory = runtime.memory
    length = _invoke(runtime, 0x3EB2C10, source)
    _bounded(length)
    long = memory.load(string, 1) & 1
    capacity = (memory.load(string, 8) & ~1) - 1 if long else 22
    if capacity > _LIMIT:
        raise PrimaryProgramLimit('signature encoding assignment exceeds the bounded capacity domain')
    if length > capacity:
        previous = memory.load(string + 16, 8) if long else string + 1
        physical = (max(2 * capacity, length) | 15) + 1
        target = runtime._operator_new(physical)
        _copy(runtime, target, source, length)
        if capacity != 22:
            runtime._free_allocation(previous)
        memory.store(string + 16, target, 8, source='75BF89.signature_encoding_assign_pointer')
        memory.store(string, physical | 1, 8, source='75BF91.signature_encoding_assign_capacity')
        memory.store(string + 8, length, 8, source='75BFC6.signature_encoding_assign_heap_length')
    else:
        target = memory.load(string + 16, 8) if long else string + 1
        _copy(runtime, target, source, length)
        if memory.load(string, 1) & 1:
            memory.store(string + 8, length, 8, source='75BFC6.signature_encoding_assign_length')
        else:
            memory.store(string, 2 * length, 1, source='75BFC2.signature_encoding_assign_short_length')
    memory.store(target + length, 0, 1, source='75BFCA.signature_encoding_assign_NUL')


def _append_cstring(runtime, string, source):
    memory = runtime.memory
    count = _invoke(runtime, 0x3EB2C10, source)
    first = memory.load(string, 1)
    long = first & 1
    length = memory.load(string + 8, 8) if long else first >> 1
    capacity = (memory.load(string, 8) & ~1) - 1 if long else 22
    if length > capacity or capacity > _LIMIT or length + count > _LIMIT:
        raise PrimaryProgramLimit('signature encoding append exceeds the bounded growth domain')
    if capacity - length < count:
        previous = memory.load(string + 16, 8) if long else string + 1
        physical = (max(2 * capacity, length + count) | 15) + 1
        target = runtime._operator_new(physical)
        _copy(runtime, target, previous, length)
        _copy(runtime, target + length, source, count)
        if capacity != 22:
            runtime._free_allocation(previous)
        memory.store(string + 16, target, 8, source='75C28C.signature_encoding_append_pointer')
        memory.store(string, physical | 1, 8, source='75C294.signature_encoding_append_capacity')
        memory.store(string + 8, length + count, 8, source='75C297.signature_encoding_append_length')
    elif count:
        target = memory.load(string + 16, 8) if long else string + 1
        _copy(runtime, target + length, source, count)
        if memory.load(string, 1) & 1:
            memory.store(string + 8, length + count, 8, source='75C2BF.signature_encoding_append_length')
        else:
            memory.store(string, 2 * (length + count), 1,
                         source='75C2BB.signature_encoding_append_short_length')
    else:
        return
    memory.store(target + length + count, 0, 1, source='75C2C6.signature_encoding_append_NUL')


def encode(runtime, destination, source, alphabet):
    memory = runtime.memory
    memory.write(destination, bytes(16), source='1BFD596.signature_encoding_empty_prefix')
    memory.store(destination + 16, 0, 8, source='1BFD59D.signature_encoding_empty_tail')
    frame = _temporary(runtime, 112, 'signature encoding alphabet copy frame')
    temporary = frame + 24
    memory.store(frame + 64, _MASK64 - 1, 8, source='1BFD585.signature_encoding_exception_state')
    memory.store(frame + 48, destination, 8, source='1BFD599.signature_encoding_return_pointer')
    memory.store(frame + 63, 0, 1, source='1BFD5A5.signature_encoding_local_flag')
    _clone(runtime, temporary, alphabet)
    memory.store(frame + 8, source, 8, source='1BFD5BA.signature_encoding_input_pointer')
    if not _length(runtime, alphabet):
        _assign_cstring(runtime, temporary, _decode_alphabet(runtime))
    length = _length(runtime, source) & 0xFFFFFFFF
    memory.store(frame, source + 1, 8, source='1BFD678.signature_encoding_inline_pointer')
    if length > _LIMIT:
        raise PrimaryProgramLimit('signature encoding DWORD input exceeds the bounded iteration domain')
    for offset in range(0, length, 3):
        memory.store(frame + 56, 0, 4, source='1BFD6C9.signature_encoding_chunk_clear')
        count = min(3, length - offset)
        chunk = memory.read(_data(runtime, source) + offset, count)
        memory.write(frame + 56, chunk, source='1BFD701.signature_encoding_chunk_copy')
        first = chunk[0]
        second = chunk[1] if count >= 2 else 0
        third = chunk[2] if count == 3 else 0
        indices = (first >> 2, ((first << 4) & 0x30) | (second >> 4),
                   ((second & 15) << 2) | (third >> 6), third & 63)
        for index in indices[:count + 1]:
            character = memory.load(_data(runtime, temporary) + index, 1)
            push_character(runtime, destination, character)
        if count < 3:
            _append_cstring(runtime, destination,
                            runtime.image_base + (0x48A7DA9 if count == 1 else 0x48A7E6F))
        memory.store(frame + 56, 0, 4, source='1BFD6A0.signature_encoding_chunk_reset')
    _destroy(runtime, temporary)
    _finish(runtime, frame, 112)
    return destination


def encode_default(runtime, destination, source, parameter):
    alphabet = _decode_alphabet(runtime)
    length = _invoke(runtime, 0x3EB2C10, alphabet)
    _bounded(length)
    temporary = _temporary(runtime, 24, 'signature encoding default alphabet')
    _construct(runtime, temporary, alphabet, length)
    encode(runtime, destination, source, temporary)
    _destroy(runtime, temporary)
    _finish(runtime, temporary, 24)
    return destination


def copy_cstring(runtime, destination, source):
    memory = runtime.memory
    begin, offset = destination, 0
    for _ in range(_LIMIT + 8):
        if source & 7:
            value = memory.load(source, 1)
            memory.store(destination, value, 1, source='3EB2ACD.signature_encoding_copy_byte')
            if not value:
                return begin
            source += 1
            destination += 1
            offset += 1
            continue
        region, start = memory._span(source, 8)
        known = region.initialized[start:start + 8]
        if not all(known):
            if not any(flag and not byte for flag, byte in
                       zip(known, region.data[start:start + 8])):
                memory.load(source, 8)
            for index in range(8):
                byte = memory.load(source + index, 1)
                memory.store(destination + index, byte, 1,
                             source='3EB2B15.signature_encoding_proven_zero_tail')
                if not byte:
                    return begin
            raise AssertionError('known zero was not reached')
        value = memory.load(source, 8)
        marker = (((value + 0x7EFEFEFEFEFEFEFF) & _MASK64) ^ (~value & _MASK64))
        if not marker & 0x8101010101010100:
            memory.store(destination, value, 8, source='3EB2AE2.signature_encoding_copy_qword')
            source += 8
            destination += 8
            offset += 8
        else:
            for index in range(8):
                byte = (value >> (8 * index)) & 255
                memory.store(destination + index, byte, 1,
                             source='3EB2B15.signature_encoding_copy_tail')
                if not byte:
                    return begin
            source += 8
            destination += 8
            offset += 8
        if offset > _LIMIT:
            break
    raise PrimaryProgramLimit('signature encoding strcpy exceeds the bounded scan domain')


def bridge(runtime, destination, length_output, source, length):
    _bounded(length)
    memory = runtime.memory
    temporary = _temporary(runtime, 72, 'signature encoding bridge strings')
    parameter, result, input_string = temporary, temporary + 24, temporary + 48
    _construct(runtime, input_string, source, length)
    callback = memory.load(runtime.image_base + 0x6D85FF0, 8)
    if callback:
        empty = runtime.image_base + 0x4903C10
        _construct(runtime, parameter, empty, _invoke(runtime, 0x3EB2C10, empty))
        if callback != runtime.image_base + 0x1BFD3E0:
            raise PrimarySemanticUnavailable('signature encoding callback has no recovered body at ' + hex(callback))
        encode_default(runtime, result, input_string, parameter)
        _destroy(runtime, parameter)
    else:
        memory.write(result, bytes(16), source='2DE4DAA.signature_encoding_empty_result_prefix')
        memory.store(result + 16, 0, 8, source='2DE4DAF.signature_encoding_empty_result_tail')
    long = memory.load(result, 1) & 1
    length = memory.load(result + 8, 8) if long else memory.load(result, 1) >> 1
    memory.store(length_output, length, 8, source='2DE4D8A.signature_encoding_output_length')
    pointer = memory.load(result + 16, 8) if long else result + 1
    copy_cstring(runtime, destination, pointer)
    if long:
        runtime._free_allocation(pointer)
    _destroy(runtime, input_string)
    _finish(runtime, temporary, 72)
    return None


def invoke(runtime, rva, args):
    functions = {0x2DE4CBD: (bridge, 4), 0x1BFD3E0: (encode_default, 3),
                 0x1BFD570: (encode, 3), 0x3EB2AC0: (copy_cstring, 2)}
    function, count = functions[rva]
    if len(args) != count:
        raise InputError(hex(rva) + ' signature encoding argument count differs')
    return function(runtime, *args)
