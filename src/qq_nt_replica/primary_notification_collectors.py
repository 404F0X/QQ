from .errors import InputError
from .primary_vm import PrimaryProgramLimit
from .primary_logger import _String, _cstring
from .primary_caller import _api
from .primary_caller_diagnostics import _columns, report
from .primary_device_refresh import _StringVector
from .primary_device_collector import _convert_call, _new_array, _delete_array


_LIMIT=1 << 20


def publish(runtime, owner, scene, event, modules):
    first, second = _String.read(runtime, scene), _String.read(runtime, event)
    values = _columns(runtime, modules)
    report(runtime, runtime.worker_observations, _api, owner, first, second, values)
    first.destroy()
    second.destroy()
    for index in reversed(range(values.count)):
        values.at(index).destroy()
    runtime.memory.store(modules + 8, values.begin, 8, source='1CF677A.consumed_vector_end')
    if values.begin:
        runtime._free_allocation(values.begin)


def grow_push_copy(runtime, vector, value):
    target = _StringVector(runtime, vector)
    count = (target.end - target.begin) // 24
    capacity = max(2 * (target.capacity - target.begin) // 24, count + 1)
    if capacity * 24 > _LIMIT:
        raise PrimaryProgramLimit('notification String vector growth exceeds the bounded domain')
    storage = runtime._operator_new(capacity * 24)
    _String.read(runtime, value).clone().write_to(storage + count * 24)
    for index in reversed(range(count)):
        _String.read(runtime, target.begin + index * 24).write_to(storage + index * 24)
    runtime.memory.store(vector, storage, 8, source='48B6A.notification_vector_begin')
    runtime.memory.store(vector + 8, storage + (count + 1) * 24, 8, source='48B6A.notification_vector_end')
    runtime.memory.store(vector + 16, storage + capacity * 24, 8, source='48B6A.notification_vector_capacity')
    if target.begin:
        runtime._free_allocation(target.begin)


def wide_to_utf8(runtime, destination, source):
    memory = runtime.memory
    memory.write(destination, bytes(24), source='2E09A50.zero_result')
    pointer = memory.load(source + 16, 8) if memory.load(source, 1) & 1 else source + 2
    count = _convert_call(runtime, 'WideCharToMultiByte', pointer, None, 0)
    if count <= 0:
        return destination
    storage = _new_array(runtime, count)
    try:
        memory.write(storage, bytes(count), source='2E09AD3.zero_conversion_buffer')
        pointer = memory.load(source + 16, 8) if memory.load(source, 1) & 1 else source + 2
        _convert_call(runtime, 'WideCharToMultiByte', pointer, storage, count)
        memory.store(storage + count - 1, 0, 1, source='2E09B0B.conversion_terminator')
        _String.construct(runtime, _cstring(runtime, storage)).write_to(destination)
    except BaseException as primary:
        try:
            _delete_array(runtime, storage)
        except BaseException as cleanup:
            raise primary from cleanup
        raise
    else:
        _delete_array(runtime, storage)
    return destination


def invoke(runtime, rva, values):
    functions = {0x1CF64E0: (publish, 4), 0x48A5E: (grow_push_copy, 2),
                 0x2E09A50: (wide_to_utf8, 2)}
    if rva not in functions:
        raise InputError('unknown notification primitive source entry')
    function, count = functions[rva]
    if len(values) != count:
        raise InputError('notification primitive source argument count mismatch')
    return function(runtime, *values)


from dataclasses import dataclass
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_response import _frame
from .primary_notification_accounts import IniRawWrite


_ACCOUNTS_IMPORTS = {'FindFirstFileA': 0x490FD00, 'FindNextFileA': 0x490FD18,
                     'FindClose': 0x490FCF8, 'SHGetFolderPathA': 0x49107D8}
_ACCOUNTS_MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class AccountsApiReply:
    result: int
    writes: tuple

    def __post_init__(self):
        if type(self.result) is not int or not 0 <= self.result <= _ACCOUNTS_MASK64:
            raise InputError('accounts raw API result requires an unsigned64 integer')
        if type(self.writes) is not tuple or not all(isinstance(item, IniRawWrite) for item in self.writes):
            raise InputError('accounts raw API writes require ordered typed byte writes')


@dataclass(frozen=True)
class AccountsApiObservation:
    name: str
    arguments: tuple
    reply: AccountsApiReply

    def __post_init__(self):
        counts = {'FindFirstFileA': 2, 'FindNextFileA': 2, 'FindClose': 1, 'SHGetFolderPathA': 5}
        if self.name not in counts or type(self.arguments) is not tuple or len(self.arguments) != counts[self.name]:
            raise InputError('accounts raw API observation requires its exact named argument tuple')
        if any(type(value) is not int or not 0 <= value <= _ACCOUNTS_MASK64 for value in self.arguments):
            raise InputError('accounts raw API arguments require unsigned64 integers')
        if not isinstance(self.reply, AccountsApiReply):
            raise InputError('accounts raw API observation requires a typed reply')
        if self.name != 'FindFirstFileA' and self.reply.result > 0xFFFFFFFF:
            raise InputError('accounts BOOL/HRESULT result requires its explicit DWORD')
        if self.name == 'FindClose' and self.reply.writes:
            raise InputError('FindClose has no output buffer')


class AccountsObservations:
    def __init__(self, observations):
        self.observations = tuple(observations)
        if not all(isinstance(item, AccountsApiObservation) for item in self.observations):
            raise InputError('accounts observations require ordered typed raw API records')
        self.position = 0

    def take(self, runtime, name, arguments):
        if self.position == len(self.observations):
            raise UnknownMemory('missing accounts raw API observation: ' + name)
        item = self.observations[self.position]
        if (item.name, item.arguments) != (name, arguments):
            raise InputError('accounts raw API observation does not match the ordered source call')
        self.position += 1
        return item.reply


def install_accounts_observations(runtime, observations):
    if not isinstance(observations, AccountsObservations):
        raise InputError('typed accounts raw API stream required')
    runtime.notification_accounts_observations = observations


def _accounts_api(runtime, name, arguments, buffer=0, capacity=0):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _ACCOUNTS_IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('accounts current import is not bound: ' + name)
    observer = getattr(runtime, 'notification_accounts_observations', None)
    if not isinstance(observer, AccountsObservations):
        raise UnknownMemory('missing accounts typed raw API stream')
    reply = observer.take(runtime, name, arguments)
    if not isinstance(reply, AccountsApiReply):
        raise InputError('accounts raw API callback returned an untyped reply')
    AccountsApiObservation(name, arguments, reply)
    for write in reply.writes:
        if write.offset > capacity or len(write.data) > capacity - write.offset:
            raise InputError('accounts raw API write leaves its actual output buffer')
        if write.data:
            runtime.memory.write(buffer + write.offset, write.data, source='35A3D90.accounts_raw_API_write')
    return reply.result


def _accounts_header(runtime, address):
    memory = runtime.memory
    flag = memory.load(address, 1)
    return (memory.load(address + 16, 8), memory.load(address + 8, 8)) if flag & 1 else (address + 1, flag >> 1)


def accounts_filename(runtime, address):
    pointer, length = _accounts_header(runtime, address)
    if length > _LIMIT:
        raise PrimaryProgramLimit('accounts filename predicate exceeds the bounded source domain')
    for index in range(length):
        value = runtime.memory.load(pointer + index, 1)
        if value < 48 or value > 57:
            return 0
    return 1


def _accounts_copy_header(runtime, destination, source, label):
    runtime.memory.copy_disjoint(destination + 16, source + 16, 8, label=label + '.tail')
    runtime.memory.copy_disjoint(destination, source, 16, label=label + '.head')


def _accounts_construct(runtime, destination, pointer, length, capacity=None):
    memory = runtime.memory
    required = length if capacity is None else capacity
    if not 0 <= length <= required <= _LIMIT:
        raise PrimaryProgramLimit('accounts string construction exceeds the bounded source domain')
    if required < 23:
        memory.store(destination, length * 2, 1, source='accounts.construct_short_length')
        target = destination + 1
    else:
        physical = (required + 16) & ~15
        target = runtime._operator_new(physical)
        memory.store(destination + 16, target, 8, source='accounts.construct_long_pointer')
        memory.store(destination, physical | 1, 8, source='accounts.construct_long_capacity')
        memory.store(destination + 8, length, 8, source='accounts.construct_long_length')
    if length:
        memory.copy_disjoint(target, pointer, length, label='accounts.construct_payload')
    memory.store(target + length, 0, 1, source='accounts.construct_terminator')
    return destination


def _accounts_destroy(runtime, address):
    if runtime.memory.load(address, 1) & 1:
        runtime._free_allocation(runtime.memory.load(address + 16, 8))


def _accounts_grow_move(runtime, vector, value):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x58, 'C8924.accounts_vector_growth_frame')
    memory.store(frame + 0x50, _ACCOUNTS_MASK64 - 1, 8, source='C8935.frame_sentinel')
    begin, end, capacity = (memory.load(vector + offset, 8) for offset in (0, 8, 16))
    if not begin <= end <= capacity or (end - begin) % 24 or (capacity - begin) % 24:
        raise InputError('accounts vector requires its actual initialized aligned bounds')
    count, old_capacity = (end - begin) // 24, (capacity - begin) // 24
    new_capacity = max(count + 1, old_capacity * 2)
    if new_capacity * 24 > _LIMIT:
        raise PrimaryProgramLimit('accounts vector growth exceeds the bounded source domain')
    split = frame + 0x28
    memory.store(split + 24, 0, 8, source='48B1E.empty_split_capacity')
    memory.store(split + 32, vector + 24, 8, source='48B29.split_allocator')
    storage = runtime._operator_new(new_capacity * 24)
    for offset, pointer in ((0, storage), (16, storage + count * 24), (8, storage + count * 24), (24, storage + new_capacity * 24)):
        memory.store(split + offset, pointer, 8, source='48B14.split_bounds')
    target = memory.load(split + 16, 8)
    memory.copy_disjoint(target, value, 16, label='C8981.move_new_head')
    memory.copy_disjoint(target + 16, value + 16, 8, label='C8988.move_new_tail')
    memory.write(value, bytes(24), source='6270.clear_moved_new_string')
    memory.store(split + 16, target + 24, 8, source='C8994.split_end')
    old = end
    while old != begin:
        old -= 24
        target = memory.load(split + 8, 8) - 24
        _accounts_copy_header(runtime, target, old, '48C08.move_previous')
        memory.write(old, bytes(24), source='6270.clear_moved_previous_string')
        memory.store(split + 8, target, 8, source='48C3F.split_begin')
    for vector_offset, split_offset in ((0, 8), (8, 16), (16, 24)):
        previous = memory.load(vector + vector_offset, 8)
        replacement = memory.load(split + split_offset, 8)
        memory.store(vector + vector_offset, replacement, 8, source='48B6A.publish_vector')
        memory.store(split + split_offset, previous, 8, source='48B6A.retain_previous_storage')
    memory.store(split, memory.load(split + 8, 8), 8, source='48BBC.previous_storage_begin')
    if begin:
        runtime._free_allocation(begin)
    memory.unmap(frame)


def enumerate_accounts(runtime, path, vector, mode):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x1A8, '35A3930.accounts_enumeration_frame')
    pattern, name, find_data = rbp + 0xF0, rbp + 0x108, rbp - 0x58
    memory.store(rbp + 0x120, _ACCOUNTS_MASK64 - 1, 8, source='35A394B.frame_sentinel')
    memory.write(pattern, bytes(24), source='35A395F.empty_pattern')
    pointer, length = _accounts_header(runtime, path)
    memory.store(rbp + 0xE8, vector, 8, source='35A3999.saved_vector')
    _accounts_construct(runtime, pattern, pointer, length, length + 2)
    from .primary_worker_consumer import _append
    if memory.read(runtime.image_base + 0x48C7B93, 2) != b'\\*':
        raise PrimarySemanticUnavailable('accounts enumeration pattern literal is not bound')
    value = _String.read(runtime, pattern)
    _append(value, b'\\*')
    value.write_to(pattern)
    pattern_pointer, _ = _accounts_header(runtime, pattern)
    handle = _accounts_api(runtime, 'FindFirstFileA', (pattern_pointer, find_data), find_data, 320)
    if handle != _ACCOUNTS_MASK64:
        for _ in range(_LIMIT):
            attributes = memory.load(find_data, 1)
            eligible = bool(attributes & 0x10) == bool(mode & 0xFFFFFFFF)
            if eligible and memory.load(find_data + 0x2C, 2) != 0x2E:
                # ASM loads DWORD, but OR CX,AX uses only its low16; high16 are dead.
                word = memory.load(find_data + 0x2C, 2) ^ 0x2E2E
                byte = memory.load(find_data + 0x2E, 1)
                if ((word | byte) & 0xFFFF) != 0:
                    raw = _cstring(runtime, find_data + 0x2C)
                    _accounts_construct(runtime, name, find_data + 0x2C, len(raw))
                    if accounts_filename(runtime, name) and len(_cstring(runtime, find_data + 0x2C)) >= 6:
                        _accounts_destroy(runtime, name)
                        raw = _cstring(runtime, find_data + 0x2C)
                        if len(raw) <= 14:
                            _accounts_construct(runtime, name, find_data + 0x2C, len(raw))
                            end, capacity = memory.load(vector + 8, 8), memory.load(vector + 16, 8)
                            if end < capacity:
                                _accounts_copy_header(runtime, end, name, '35A3BE9.move_accepted_name')
                                memory.store(vector + 8, end + 24, 8, source='35A3BFB.vector_end')
                            else:
                                _accounts_grow_move(runtime, vector, name)
                                _accounts_destroy(runtime, name)
                    else:
                        _accounts_destroy(runtime, name)
            if not _accounts_api(runtime, 'FindNextFileA', (handle, find_data), find_data, 320):
                break
        else:
            raise PrimaryProgramLimit('accounts enumeration exceeds its bounded source domain')
        _accounts_api(runtime, 'FindClose', (handle,))
    _accounts_destroy(runtime, pattern)
    memory.unmap(frame)


def accounts_format_path(runtime, destination, maximum, format_pointer, argument):
    if maximum != 260:
        raise PrimarySemanticUnavailable('accounts formatter requires the source max_count260 domain')
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x48, '35A6940.accounts_format_frame')
    pattern = _cstring(runtime, format_pointer)
    allowed = (b'%s\\Tencent\\QQ\\Misc', b'%s\\Tencent\\TIM\\Misc', b'%s\\Tencent\\Users',
               b'%s\\QQ\\Crashpad\\log', b'%s\\Tencent Files')
    if pattern not in allowed:
        raise PrimarySemanticUnavailable('accounts formatter requires its source-closed single narrow-string format')
    if memory.load(runtime.image_base + 0x6749CC0, 8) & 3:
        raise PrimarySemanticUnavailable('accounts formatter current termination options require unsupported source branches')
    root = _cstring(runtime, argument)
    suffix = pattern[2:]
    length = len(root) + len(suffix)
    if length >= 260:
        raise PrimarySemanticUnavailable('accounts formatter overflow requires actual invalid-parameter and TLS errno semantics')
    if root:
        memory.copy_disjoint(destination, argument, len(root), label='35A6940.format_narrow_argument')
    memory.copy_disjoint(destination + len(root), format_pointer + 2, len(suffix), label='35A6940.format_literal_suffix')
    memory.store(destination + length, 0, 1, source='3E72305.format_terminator')
    memory.store(destination + 259, 0, 1, source='3E6F2D7.forced_buffer_terminator')
    memory.unmap(frame)
    return length


def _accounts_compare(runtime, first, second):
    a, an = _accounts_header(runtime, first)
    b, bn = _accounts_header(runtime, second)
    if max(an, bn) > _LIMIT:
        raise PrimaryProgramLimit('accounts comparison exceeds the bounded source domain')
    for index in range(min(an, bn)):
        av, bv = runtime.memory.load(a + index, 1), runtime.memory.load(b + index, 1)
        if av != bv:
            return -1 if av < bv else 1
    return (an > bn) - (an < bn)


def _accounts_equal(runtime, first, second):
    a, an = _accounts_header(runtime, first)
    b, bn = _accounts_header(runtime, second)
    if an != bn:
        return False
    if an > _LIMIT:
        raise PrimaryProgramLimit('accounts equality exceeds the bounded source domain')
    for index in range(an):
        if runtime.memory.load(a + index, 1) != runtime.memory.load(b + index, 1):
            return False
    return True


def _accounts_move_assign(runtime, destination, source):
    _accounts_destroy(runtime, destination)
    _accounts_copy_header(runtime, destination, source, '6284.move_assign')
    runtime.memory.store(source, 0, 2, source='62B7.clear_moved_WORD')


def _accounts_swap(runtime, first, second, temporary):
    _accounts_copy_header(runtime, temporary, first, 'accounts.sort_save')
    _accounts_copy_header(runtime, first, second, 'accounts.sort_exchange_first')
    _accounts_copy_header(runtime, second, temporary, 'accounts.sort_exchange_second')


def _accounts_small_sort(runtime, positions, temporary=None):
    count = len(positions)
    if count < 2:
        return 0
    size = {2: 0x68, 3: 0x48, 4: 0x40, 5: 0x58}[count]
    frame = None
    if count != 2:
        frame, _ = _frame(runtime, size, 'accounts.source_small_sort_frame')
        temporary = frame + (0x30 if count == 5 else 0x20)
    elif temporary is None:
        raise InputError('source two-string sort requires its actual caller temporary')
    less = lambda a, b: _accounts_compare(runtime, a, b) < 0
    if count == 2:
        swaps = int(less(positions[1], positions[0]))
        if swaps:
            _accounts_swap(runtime, positions[0], positions[1], temporary)
    elif count == 3:
        a, b, c = positions
        ba, cb = less(b, a), less(c, b)
        if ba and cb:
            _accounts_swap(runtime, a, c, temporary)
            swaps = 1
        elif ba:
            _accounts_swap(runtime, a, b, temporary)
            swaps = 1
            if less(c, b):
                _accounts_swap(runtime, b, c, temporary)
                swaps = 2
        elif cb:
            _accounts_swap(runtime, b, c, temporary)
            swaps = 1
            if less(b, a):
                _accounts_swap(runtime, a, b, temporary)
                swaps = 2
        else:
            swaps = 0
    else:
        swaps = _accounts_small_sort(runtime, positions[:-1])
        for index in reversed(range(1, count)):
            if not less(positions[index], positions[index - 1]):
                break
            _accounts_swap(runtime, positions[index - 1], positions[index], temporary)
            swaps += 1
    if frame is not None:
        runtime.memory.unmap(frame)
    return swaps


def _accounts_insertion(runtime, begin, end, incomplete=False):
    count = (end - begin) // 24
    frame, _ = _frame(runtime, 0x58 if incomplete else 0x38, 'accounts.source_insertion_frame')
    if count <= 5 and incomplete:
        _accounts_small_sort(runtime, tuple(begin + 24 * i for i in range(count)), frame + 0x30)
        runtime.memory.unmap(frame)
        return True
    _accounts_small_sort(runtime, (begin, begin + 24, begin + 48))
    temporary = frame + (0x30 if incomplete else 0x20)
    inserted = 0
    for current in range(begin + 72, end, 24):
        previous = current - 24
        if _accounts_compare(runtime, current, previous) < 0:
            _accounts_copy_header(runtime, temporary, current, 'accounts.insertion_save')
            runtime.memory.write(current, bytes(24), source='6270.clear_insertion_source')
            destination = current
            while True:
                _accounts_move_assign(runtime, destination, previous)
                destination = previous
                if destination == begin or _accounts_compare(runtime, temporary, previous - 24) >= 0:
                    break
                previous -= 24
            _accounts_move_assign(runtime, destination, temporary)
            _accounts_destroy(runtime, temporary)
            inserted += 1
            if incomplete and inserted == 8:
                runtime.memory.unmap(frame)
                return current + 24 == end
    runtime.memory.unmap(frame)
    return True


def _accounts_sift_down(runtime, begin, count, current):
    frame, _ = _frame(runtime, 0x38, 'C2F38.accounts_heap_sift_frame')
    temporary = frame + 0x20
    index = (current - begin) // 24
    if count >= 2 and index <= (count - 2) // 2:
        child = index * 2 + 1
        if child + 1 < count and _accounts_compare(runtime, begin + child * 24, begin + (child + 1) * 24) < 0:
            child += 1
        if _accounts_compare(runtime, begin + child * 24, current) >= 0:
            _accounts_copy_header(runtime, temporary, current, 'C2FD4.heap_saved_value')
            runtime.memory.write(current, bytes(24), source='6270.clear_heap_source')
            while True:
                _accounts_move_assign(runtime, current, begin + child * 24)
                current = begin + child * 24
                if child > (count - 2) // 2:
                    break
                next_child = child * 2 + 1
                if next_child + 1 < count and _accounts_compare(runtime, begin + next_child * 24, begin + (next_child + 1) * 24) < 0:
                    next_child += 1
                if _accounts_compare(runtime, begin + next_child * 24, temporary) < 0:
                    break
                child = next_child
            _accounts_move_assign(runtime, current, temporary)
            _accounts_destroy(runtime, temporary)
    runtime.memory.unmap(frame)


def _accounts_heap_sort(runtime, begin, end):
    memory = runtime.memory
    count = (end - begin) // 24
    for index in reversed(range(max(0, (count - 2) // 2 + 1))):
        _accounts_sift_down(runtime, begin, count, begin + index * 24)
    for count in reversed(range(2, count + 1)):
        frame, _ = _frame(runtime, 0x38, 'C30BD.accounts_pop_heap_frame')
        temporary = frame + 0x20
        _accounts_copy_header(runtime, temporary, begin, 'C30E8.save_heap_root')
        memory.write(begin, bytes(24), source='6270.clear_heap_root')
        hole = 0
        while hole <= (count - 2) // 2:
            child = hole * 2 + 1
            if child + 1 < count and _accounts_compare(runtime, begin + child * 24, begin + (child + 1) * 24) < 0:
                child += 1
            _accounts_move_assign(runtime, begin + hole * 24, begin + child * 24)
            hole = child
        last = begin + (count - 1) * 24
        if begin + hole * 24 == last:
            _accounts_move_assign(runtime, last, temporary)
        else:
            _accounts_move_assign(runtime, begin + hole * 24, last)
            _accounts_move_assign(runtime, last, temporary)
            if hole > 0 and _accounts_compare(runtime, begin + ((hole - 1) // 2) * 24, begin + hole * 24) < 0:
                up_frame, _ = _frame(runtime, 0x38, 'C31FE.accounts_sift_up_frame')
                saved = up_frame + 0x20
                _accounts_copy_header(runtime, saved, begin + hole * 24, 'C324F.save_heap_leaf')
                memory.write(begin + hole * 24, bytes(24), source='6270.clear_heap_leaf')
                while True:
                    parent = (hole - 1) // 2
                    _accounts_move_assign(runtime, begin + hole * 24, begin + parent * 24)
                    hole = parent
                    if hole == 0 or _accounts_compare(runtime, begin + ((hole - 1) // 2) * 24, saved) >= 0:
                        break
                _accounts_move_assign(runtime, begin + hole * 24, saved)
                _accounts_destroy(runtime, saved)
                memory.unmap(up_frame)
        _accounts_destroy(runtime, temporary)
        memory.unmap(frame)


def _accounts_sort(runtime, begin, end, depth, scratch):
    memory = runtime.memory
    if end < begin or (end - begin) % 24 or end - begin > _LIMIT:
        raise InputError('accounts sort requires bounded actual String24 vector bounds')
    frame, _ = _frame(runtime, 0x68, 'C21DD.accounts_sort_frame')
    memory.store(frame + 0x30, scratch, 8, source='C21F0.saved_comparator')
    temporary = frame + 0x40
    less = lambda a, b: _accounts_compare(runtime, a, b) < 0
    for _ in range(_LIMIT):
        count = (end - begin) // 24
        if count <= 5:
            _accounts_small_sort(runtime, tuple(begin + 24 * i for i in range(count)), temporary)
            break
        if count <= 6:
            _accounts_insertion(runtime, begin, end)
            break
        if depth == 0:
            _accounts_heap_sort(runtime, begin, end)
            break
        depth -= 1
        middle, last = begin + (count // 2) * 24, end - 24
        if count >= 1000:
            quarter = (count // 4) * 24
            swaps = _accounts_small_sort(runtime, (begin, begin + quarter, middle, middle + quarter, last))
        else:
            swaps = _accounts_small_sort(runtime, (begin, middle, last))
        left, right = begin, last
        equal_partition = False
        if not less(left, middle):
            while True:
                right -= 24
                if right == begin:
                    equal_partition = True
                    break
                if less(right, middle):
                    _accounts_swap(runtime, begin, right, temporary)
                    swaps += 1
                    break
        if equal_partition:
            left, right = begin + 24, last
            if not less(begin, right):
                while left != right and not less(begin, left):
                    left += 24
                if left == right:
                    break
                _accounts_swap(runtime, left, right, temporary)
                left += 24
            if left == right:
                break
            while True:
                while not less(begin, left):
                    left += 24
                right -= 24
                while less(begin, right):
                    right -= 24
                if left >= right:
                    break
                _accounts_swap(runtime, left, right, temporary)
                left += 24
            begin = left
            continue
        left = begin + 24
        if left < right:
            while True:
                while less(left, middle):
                    left += 24
                right -= 24
                while not less(right, middle):
                    right -= 24
                if left > right:
                    break
                _accounts_swap(runtime, left, right, temporary)
                swaps += 1
                if left == middle:
                    middle = right
                left += 24
        if left != middle and less(middle, left):
            _accounts_swap(runtime, left, middle, temporary)
            swaps += 1
        if swaps == 0:
            left_done = _accounts_insertion(runtime, begin, left, True)
            right_done = _accounts_insertion(runtime, left + 24, end, True)
            if right_done:
                if left_done:
                    break
                end = left
                continue
            if left_done:
                begin = left + 24
                continue
        if left - begin < end - left:
            _accounts_sort(runtime, begin, left, depth, scratch)
            begin = left + 24
        else:
            _accounts_sort(runtime, left + 24, end, depth, scratch)
            end = left
    else:
        raise PrimaryProgramLimit('accounts partition iteration exceeds its bounded source domain')
    memory.unmap(frame)


def _accounts_unique(runtime, begin, end, boundary):
    frame, _ = _frame(runtime, 0x38, 'C32B4.accounts_unique_frame')
    current = begin
    while current != end:
        following = current + 24
        if following == end:
            current = end
            break
        if _accounts_equal(runtime, current, following):
            break
        current = following
    runtime.memory.store(frame + 0x20, current, 8, source='C3343.first_adjacent_duplicate')
    if current != end:
        following = current + 48
        while following != end:
            if not _accounts_equal(runtime, current, following):
                current += 24
                _accounts_move_assign(runtime, current, following)
            following += 24
        current += 24
    runtime.memory.store(boundary, current, 8, source='C3326.unique_boundary')
    runtime.memory.unmap(frame)
    return boundary


_ACCOUNTS_LITERAL_RECIPES = (
    (304, 576, 39, '634651417650445e6d5c4a5e6a584c4f', 16),
    (920, 576, 39, '785d4a5a6d4b5f45764353', 40),
    (576, 848, 39, '634651417650445e77535a541450564e', 64),
    (888, 848, 39, '7576', -80),
    (920, 304, 39, '634651417650445e6d5c4a5e6a584c4f', 88),
    (888, 304, 39, '785d4a5a6d4b5f45764353', 112),
    (576, 304, 39, '7a6363425541765c485e77575e54144c4a4e', 136),
    (912, 304, 39, '7576', -56),
    (920, 304, 39, '634651417650445e6d5c4a5e6a584c4f', 160),
    (576, 304, 39, '624750407751455f76514d55494c6a4353', 184),
    (888, 304, 39, '634651417650445e77535a541450564e', 208),
    (912, 304, 39, '7576', -32),
    (888, 304, 39, '67474e7b495d6a4054427244504f', 232),
    (576, 304, 39, '624750407751455f76514d55494c6a4353', 256),
    (920, 304, 39, '634651417650445e77535a541450564e', 280),
    (912, 304, 39, '7576', -8),
    (920, 888, 39, '11446a65555d5158524b62686967774c5744', None),
    (920, 888, 39, '10456b64545c5059534a636c707767694c5544', None),
    (920, 888, 39, '13466867575f535a5049606e495c4a54', None),
    (920, 888, 39, '11446a60616f714f5d4c5649595f66494b40', None),
    (920, 888, 39, '13466867575f535a50491c7d53555d54', None),
)


def _accounts_literal(runtime, rbp, index):
    flag, counter, key, encoded, destination = _ACCOUNTS_LITERAL_RECIPES[index]
    memory = runtime.memory
    raw = bytes.fromhex(encoded)
    memory.store(rbp + flag, 1, 1, source='35A3D90.literal_encrypted_flag')
    memory.store(rbp + flag + 1, key, 1, source='35A3D90.literal_key')
    memory.write(rbp + flag + 2, raw + b'\0\0', source='35A3D90.literal_encoded_bytes')
    memory.store(rbp + counter, 0, 8, source='35A3D90.literal_counter')
    for offset in range(len(raw)):
        pointer = rbp + flag + 2 + offset
        value = memory.load(pointer, 1) ^ memory.load(rbp + flag + 1, 1) ^ ((offset + 1) & 255) ^ len(raw)
        memory.store(pointer, value, 1, source='35A3D90.literal_decode')
        memory.store(rbp + counter, offset + 1, 8, source='35A3D90.literal_increment')
    memory.write(rbp + flag + 2 + len(raw), b'\0\0', source='35A3D90.literal_terminators')
    memory.store(rbp + flag, 0, 1, source='35A3D90.literal_clear_flag')
    pointer = rbp + flag + 2
    if destination is not None:
        _accounts_construct(runtime, rbp + destination, pointer, len(raw))
        return rbp + destination
    return pointer


def _accounts_publish_flags(runtime, vector):
    memory = runtime.memory
    slot = runtime.image_base + 0x6751D70
    owner = memory.load(slot, 8)
    if owner:
        threshold = memory.load(owner + 12, 4)
    else:
        owner = runtime._operator_new(0x48)
        for offset in (0x38, 0x28, 0x18):
            memory.write(owner + offset, bytes(16), source='35A621E.zero_flag_block')
        memory.store(owner, 0xA00000014, 8, source='35A6234.flag_limits')
        memory.store(owner + 8, 0, 1, source='35A6237.initial_active')
        memory.store(owner + 12, 3, 4, source='35A623B.initial_threshold')
        memory.store(owner + 16, 0, 2, source='35A6242.initial_status_WORD')
        memory.store(owner + 18, 0, 1, source='35A6248.initial_status_BYTE')
        memory.store(slot, owner, 8, source='35A624C.publish_flag_owner')
        threshold = 3
    begin, end = memory.load(vector, 8), memory.load(vector + 8, 8)
    count = (((end - begin) >> 3) * 0xAAAAAAAB) & 0xFFFFFFFF
    memory.store(owner + 8, int(count != 0), 1, source='35A6267.accounts_active')
    signed_count = count if count < 0x80000000 else count - 0x100000000
    signed_threshold = threshold if threshold < 0x80000000 else threshold - 0x100000000
    if signed_threshold < signed_count:
        memory.store(owner + 17, 1, 1, source='35A62AA.sticky_account_threshold')


def collect_accounts(runtime, vector):
    memory = runtime.memory
    begin, end, capacity = (memory.load(vector + offset, 8) for offset in (0, 8, 16))
    if not begin <= end <= capacity or (end - begin) % 24 or (capacity - begin) % 24 or capacity - begin > _LIMIT:
        raise InputError('accounts producer requires its actual initialized String24 vector')
    frame, rbp = _frame(runtime, 0x438, '35A3D90.accounts_producer_frame')
    memory.store(rbp + 0x3B0, _ACCOUNTS_MASK64 - 1, 8, source='35A3DA7.frame_sentinel')
    from .primary_notification_accounts import ini_value
    retained = rbp + 0x350
    specifications = ((0, 0x10, 0x28, 0x40, -0x50),
                      (4, 0x58, 0x70, 0x88, -0x38),
                      (8, 0xA0, 0xB8, 0xD0, -0x20),
                      (12, 0xE8, 0x100, 0x118, -8))
    for index, key, section, filename, product in specifications:
        for literal in range(index, index + 4):
            _accounts_literal(runtime, rbp, literal)
        output = retained if index == 0 else rbp + 0x130
        memory.store(frame + 0x20, rbp + key, 8, source='35A3D90.outgoing_INI_key')
        ini_value(runtime, output, rbp + product, rbp + filename, rbp + section, rbp + key)
        if index:
            _accounts_destroy(runtime, retained)
            _accounts_copy_header(runtime, retained, output, '35A3D90.replace_retained_path')
        _, length = _accounts_header(runtime, retained)
        if length:
            enumerate_accounts(runtime, retained, vector, 1)
    root, buffer = rbp + 0x130, rbp + 0x240
    memory.write(root, bytes(260), source='35A5713.zero_folder_root')
    memory.write(buffer, bytes(260), source='35A5727.zero_format_buffer')
    memory.store(frame + 0x20, root, 8, source='35A572C.outgoing_folder_root')
    result = _accounts_api(runtime, 'SHGetFolderPathA', (0, 0x1A, 0, 0, root), root, 260)
    if result == 0:
        for index in range(16, 20):
            format_pointer = _accounts_literal(runtime, rbp, index)
            accounts_format_path(runtime, buffer, 260, format_pointer, root)
            raw = _cstring(runtime, buffer)
            destination = rbp + 0x398
            _accounts_construct(runtime, destination, buffer, len(raw))
            enumerate_accounts(runtime, destination, vector, 0 if index < 18 else 1)
            _accounts_destroy(runtime, destination)
    memory.store(frame + 0x20, root, 8, source='35A5EEE.outgoing_documents_root')
    result = _accounts_api(runtime, 'SHGetFolderPathA', (0, 5, 0, 0, root), root, 260)
    if result == 0:
        format_pointer = _accounts_literal(runtime, rbp, 20)
        accounts_format_path(runtime, buffer, 260, format_pointer, root)
        raw = _cstring(runtime, buffer)
        destination = rbp + 0x398
        _accounts_construct(runtime, destination, buffer, len(raw))
        enumerate_accounts(runtime, destination, vector, 0)
        _accounts_destroy(runtime, destination)
    begin, end = memory.load(vector, 8), memory.load(vector + 8, 8)
    count = (end - begin) // 24
    depth = 0
    remaining = count
    if end - begin >= 25:
        while True:
            depth += 2
            previous, remaining = remaining, remaining >> 1
            if previous <= 3:
                break
    boundary = rbp + 0x398
    _accounts_sort(runtime, begin, end, depth, boundary)
    _accounts_unique(runtime, begin, end, boundary)
    current = memory.load(boundary, 8)
    trailing = memory.load(vector + 8, 8)
    while trailing != current:
        trailing -= 24
        _accounts_destroy(runtime, trailing)
    memory.store(vector + 8, current, 8, source='35A61D0.compacted_vector_end')
    _accounts_publish_flags(runtime, vector)
    _accounts_destroy(runtime, retained)
    memory.unmap(frame)


def invoke_accounts(runtime, rva, values):
    functions = {0x35A3D90: (collect_accounts, 1), 0x35A3930: (enumerate_accounts, 3),
                 0x35A6940: (accounts_format_path, 4), 0x35A3730: (accounts_filename, 1),
                 0xC8924: (_accounts_grow_move, 2)}
    if rva not in functions or len(values) != functions[rva][1]:
        raise InputError('accounts source entry requires its exact argument count')
    if any(type(value) is not int or not 0 <= value <= _ACCOUNTS_MASK64 for value in values):
        raise InputError('accounts source arguments require unsigned64 values')
    return functions[rva][0](runtime, *values)
