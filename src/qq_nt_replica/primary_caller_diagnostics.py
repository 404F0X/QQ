import struct
from contextlib import ExitStack

from .errors import InputError
from .primary_device_collector import _converted_hardware
from .primary_logger import _String, log
from .primary_request_audit import _copy
from .primary_request_submit import _clone_row, _vector
from .primary_request_delay import precise_clock, timestamp
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed
from .primary_worker_consumer import _append, _invoke
from .primary_worker_loop import _initialize
from .primary_worker_response import _frame, _image as _response_image, _owner


_SOURCE = b'R:\\devops\\workspace\\p-824b74756ad64e12838601ccde6ecefb\\platforms\\Windows\\libsecxx\\envinfo\\WinUiReport.cpp'
_LIMIT = 4096


class _Strings:
    def __init__(self, runtime):
        self.runtime = runtime
        self.begin = self.count = self.capacity = 0

    def at(self, index):
        return _String.read(self.runtime, self.begin + index * 24)

    def reserve(self, count):
        if count <= self.capacity:
            return
        capacity = max(count, 2 * self.capacity)
        if capacity > _LIMIT:
            raise PrimaryProgramLimit('caller diagnostic columns exceed the bounded vector domain')
        storage = self.runtime._operator_new(capacity * 24)
        for index in reversed(range(self.count)):
            self.at(index).write_to(storage + index * 24)
            self.runtime.memory.write(self.begin + index * 24, bytes(24), source='caller.diagnostic_string_move')
        if self.begin:
            self.runtime._free_allocation(self.begin)
        self.begin, self.capacity = storage, capacity

    def push(self, value, clone=False):
        self.reserve(self.count + 1)
        (value.clone() if clone else value).write_to(self.begin + self.count * 24)
        self.count += 1

    def insert(self, index, value):
        if not 0 <= index <= self.count:
            raise InputError('caller diagnostic insertion requires a current vector position')
        self.reserve(self.count + 1)
        for offset in reversed(range(index, self.count)):
            self.at(offset).write_to(self.begin + (offset + 1) * 24)
        value.write_to(self.begin + index * 24)
        self.count += 1

    def clone(self):
        result = _Strings(self.runtime)
        if self.count:
            result.reserve(self.count)
            for index in range(self.count):
                result.push(self.at(index), clone=True)
        return result

    def extend(self, values):
        count = self.count + values.count
        if count > _LIMIT:
            raise PrimaryProgramLimit('caller diagnostic columns exceed the bounded vector domain')
        if count > self.capacity:
            capacity = max(count, 2 * self.capacity)
            if capacity > _LIMIT:
                raise PrimaryProgramLimit('caller diagnostic columns exceed the bounded vector domain')
            storage = self.runtime._operator_new(capacity * 24)
            for index in range(values.count):
                values.at(index).clone().write_to(storage + (self.count + index) * 24)
            for index in reversed(range(self.count)):
                self.at(index).write_to(storage + index * 24)
                self.runtime.memory.write(self.begin + index * 24, bytes(24), source='1BE884.column_move')
            if self.begin:
                self.runtime._free_allocation(self.begin)
            self.begin, self.capacity, self.count = storage, capacity, count
        else:
            for index in range(values.count):
                self.push(values.at(index), clone=True)

    def destroy(self):
        for index in reversed(range(self.count)):
            self.at(index).destroy()
        if self.begin:
            self.runtime._free_allocation(self.begin)
        self.begin = self.count = self.capacity = 0


def _effects(runtime, pointer, output, capacity, name):
    if not isinstance(output, bytes) or len(output) > capacity:
        raise InputError(name + ' requires bounded raw output bytes')
    if output:
        runtime.memory.write(pointer, output, source='caller.diagnostic_' + name)


def _buffer(runtime, pointer, capacity):
    raw = bytearray()
    for index in range(capacity):
        value = runtime.memory.load(pointer + index, 1)
        if not value:
            return bytes(raw)
        raw.append(value)
    raise PrimarySemanticUnavailable('caller diagnostic window text is not terminated inside its buffer')


def _window(runtime, observations, api, rbp):
    memory = runtime.memory
    window, output = api(runtime, observations, 'GetForegroundWindow')
    if output is not None:
        raise InputError('GetForegroundWindow has no output buffer')
    title, kind, rectangle, cursor, process = rbp + 0x480, rbp - 0x40, rbp + 0x360, rbp + 0x370, rbp + 0x5EC
    memory.write(title, bytes(260), source='1CF7090.window_title_zero')
    memory.write(kind, bytes(260), source='1CF70A1.window_class_zero')
    memory.store(process, 0, 4, source='1CF70A6.window_process_zero')
    visible = 1
    if window:
        for name, pointer in (('GetWindowTextA', title), ('GetClassNameA', kind)):
            result, output = api(runtime, observations, name, window, 259)
            _effects(runtime, pointer, output, 260, name)
        result, output = api(runtime, observations, 'GetWindowRect', window)
        _effects(runtime, rectangle, output, 16, 'GetWindowRect')
        visible, output = api(runtime, observations, 'IsWindowVisible', window)
        if output is not None:
            raise InputError('IsWindowVisible has no output buffer')
        result, output = api(runtime, observations, 'GetWindowThreadProcessId', window)
        if type(output) is int:
            if not 0 <= output <= 0xFFFFFFFF:
                raise InputError('GetWindowThreadProcessId requires a DWORD output effect')
            output = output.to_bytes(4, 'little')
        if output is not None:
            _effects(runtime, process, output, 4, 'GetWindowThreadProcessId')
    current, output = api(runtime, observations, 'GetCurrentProcessId')
    if output is not None:
        raise InputError('GetCurrentProcessId has no output buffer')
    result, output = api(runtime, observations, 'GetCursorPos')
    _effects(runtime, cursor, output, 8, 'GetCursorPos')
    left, top, right, bottom = struct.unpack('<4i', memory.read(rectangle, 16))
    x, y = struct.unpack('<2i', memory.read(cursor, 8))
    window_process = memory.load(process, 4)
    class_name = _String.construct(runtime, _buffer(runtime, kind, 260))
    value = _String.construct(runtime, _buffer(runtime, title, 260))
    original = value.value()
    _append(value, b'[')
    if value.get(0, 1) & 1:
        memory.write(value.get(16, 8), b'[' + original + b'\0', source='75C560.window_prefix_insert')
    else:
        value.set(1, b'[' + original + b'\0')
    _append(value, b',')
    _append(value, class_name.value())
    values = (signed(visible, 32), window_process, right, left, bottom, top, current & 0xFFFFFFFF, x, y)
    for number in values:
        _append(value, b',')
        _append(value, str(number).encode('ascii'))
    _append(value, b']')
    class_name.destroy()
    runtime.events.append(('caller.diagnostic_window', value.value()))
    return value


def _clone_record(runtime, destination, source):
    memory, base = runtime.memory, runtime.image_base
    memory.store(destination, base + 0x414B558, 8, source='1D00E75.caller_diagnostic_vtable')
    for offset in range(8, 200, 24):
        _String.read(runtime, source + offset).clone().write_to(destination + offset)
    for vector_offset in (200, 224):
        begin, end = (memory.load(source + vector_offset + offset, 8) for offset in (0, 8))
        if not begin <= end or (end - begin) % 24 or end - begin > 24 * _LIMIT:
            raise PrimaryProgramLimit('caller diagnostic record exceeds the bounded column domain')
        storage = runtime._operator_new(end - begin) if end != begin else 0
        for offset in range(0, end - begin, 24):
            _String.read(runtime, begin + offset).clone().write_to(storage + offset)
        for offset, value in ((0, storage), (8, storage + end - begin), (16, storage + end - begin)):
            memory.store(destination + vector_offset + offset, value, 8, source='1D00EF2.caller_diagnostic_columns')


def _cache_append(runtime, owner, record):
    memory, base = runtime.memory, runtime.image_base
    begin, end, limit = (memory.load(owner + offset, 8) for offset in (0, 8, 16))
    if not begin <= end <= limit or (end - begin) % 248 or (limit - begin) % 248:
        raise PrimarySemanticUnavailable('caller diagnostic cache requires its actual vector representation')
    count, capacity = (end - begin) // 248, (limit - begin) // 248
    if count >= _LIMIT:
        raise PrimaryProgramLimit('caller diagnostic cache exceeds the bounded record domain')
    if end == limit:
        capacity = max(count + 1, capacity * 2)
        if capacity > _LIMIT:
            raise PrimaryProgramLimit('caller diagnostic cache growth exceeds the bounded record domain')
        storage = runtime._operator_new(capacity * 248)
        _clone_record(runtime, storage + count * 248, record)
        for index in reversed(range(count)):
            source, destination = begin + index * 248, storage + index * 248
            _copy(runtime, source, destination, 248)
            memory.store(destination, base + 0x414B558, 8, source='1D00CE8.moved_diagnostic_vtable')
            memory.write(source + 8, bytes(240), source='1D00D17.moved_diagnostic_payload_empty')
        if begin:
            runtime._free_allocation(begin)
        begin = storage
    else:
        _clone_record(runtime, end, record)
    for offset, value in ((0, begin), (8, begin + (count + 1) * 248), (16, begin + capacity * 248)):
        memory.store(owner + offset, value, 8, source='1D00D47.caller_diagnostic_cache_publish')
    runtime.events.append(('caller.diagnostic_cached', owner, count + 1, capacity))


def _columns(runtime, address):
    values = _Strings(runtime)
    begin, end, limit = (runtime.memory.load(address + offset, 8) for offset in (0, 8, 16))
    if not begin <= end <= limit or (end - begin) % 24 or (limit - begin) % 24:
        raise PrimarySemanticUnavailable('caller diagnostic columns require their actual vector representation')
    values.begin, values.count, values.capacity = begin, (end - begin) // 24, (limit - begin) // 24
    if values.count > _LIMIT or values.capacity > _LIMIT:
        raise PrimaryProgramLimit('caller diagnostic columns exceed the bounded vector domain')
    return values


def _destroy_row(runtime, address):
    _String.read(runtime, address + 32).destroy()
    values = _columns(runtime, address + 8)
    if values.begin:
        runtime.memory.store(address + 16, values.begin, 8, source='BBD224.row_destroy_end')
    values.destroy()


def _callback_destroy(runtime, address):
    active = runtime.memory.load(address + 32, 8)
    if active:
        inline = active == address + 8
        target = runtime.memory.load(runtime.memory.load(active, 8) + (24 if inline else 32), 8)
        _invoke(runtime, target - runtime.image_base, active)


def _rows_append(runtime, packet, row):
    memory, base = runtime.memory, runtime.image_base
    begin, end, limit = (memory.load(packet + offset, 8) for offset in (32, 40, 48))
    count, capacity = (end - begin) // 56, (limit - begin) // 56
    if count >= _LIMIT:
        raise PrimaryProgramLimit('caller diagnostic batch exceeds the bounded row domain')
    if end == limit:
        capacity = max(count + 1, 2 * capacity)
        storage = runtime._operator_new(capacity * 56)
        _clone_row(runtime, storage + count * 56, row)
        for index in reversed(range(count)):
            source, destination = begin + index * 56, storage + index * 56
            _copy(runtime, source, destination, 56)
            memory.store(destination, base + 0x3FD7498, 8, source='BEE550.row_move_vtable')
            memory.write(source + 8, bytes(48), source='BEE578.row_move_empty')
        if begin:
            runtime._free_allocation(begin)
        begin = storage
    else:
        _clone_row(runtime, end, row)
    for offset, value in ((32, begin), (40, begin + (count + 1) * 56), (48, begin + capacity * 56)):
        memory.store(packet + offset, value, 8, source='BEE5D9.diagnostic_batch_rows')


def submit_cached(runtime, owner, cache, columns, callback):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x178, '1BF1AB0.caller_diagnostic_batch_frame')
    packet, row = rbp + 8, rbp + 0x88
    memory.write(packet, bytes(89), source='1BF1AF6.diagnostic_batch_initialization')
    memory.store(packet, base + 0x3FD73B8, 8, source='1BF1AF2.diagnostic_batch_vtable')
    memory.store(packet + 56, base + 0x3FD7428, 8, source='1BF1B0C.diagnostic_batch_nested_vtable')
    _initialize(runtime, 0)
    config = base + 0x67516B0
    _String.read(runtime, config + 8).clone().write_to(packet + 64)
    topic = b'0bc00077323'
    value = _String(runtime, bytes(24), bytes([1]) * 24)
    value.set(0, bytes([2 * len(topic)]))
    value.set(1, topic + b'\0')
    value.write_to(packet + 8)
    for record in _vector(runtime, cache, 248):
        table = memory.load(record, 8)
        if memory.load(table + 8, 8) != base + 0x1BFCA40:
            raise PrimarySemanticUnavailable('caller diagnostic cached record virtual columns are not bound')
        source = _columns(runtime, record + 224).clone()
        if not source.count:
            source.destroy()
            continue
        memory.write(row, bytes(56), source='1BF1C47.diagnostic_row_initialization')
        memory.store(row, base + 0x3FD7498, 8, source='1BF1C47.diagnostic_row_vtable')
        values = _Strings(runtime)
        for offset in (0x40, 0xA0, 0x70, 0x58):
            _initialize(runtime, 0)
            values.push(_String.read(runtime, config + offset), clone=True)
        values.extend(source)
        for index in range(values.count):
            current = values.at(index)
            if not current.value():
                _append(current, b' ')
                current.write_to(values.begin + index * 24)
        for offset, value in ((8, values.begin), (16, values.begin + values.count * 24),
                              (24, values.begin + values.capacity * 24)):
            memory.store(row + offset, value, 8, source='1BF0570.diagnostic_row_columns')
        _rows_append(runtime, packet, row)
        _destroy_row(runtime, row)
        source.destroy()
    output = rbp + 0x88
    _invoke(runtime, 0xBE1730, packet, output)
    gate = _invoke(runtime, 0xBA21A0)
    copied_callback = rbp - 0x20
    active = memory.load(callback + 32, 8)
    if not active:
        memory.store(copied_callback + 32, 0, 8, source='1BF1E13.empty_callback_copy')
    elif active == callback + 8:
        memory.store(copied_callback + 32, copied_callback + 8, 8, source='1BF1E19.inline_callback_copy')
        target = memory.load(memory.load(active, 8) + 8, 8) - base
        _invoke(runtime, target, active, copied_callback + 8)
    else:
        target = memory.load(memory.load(active, 8) + 16, 8) - base
        memory.store(copied_callback + 32, _invoke(runtime, target, active), 8, source='1BF1E13.heap_callback_copy')
    _invoke(runtime, 0x1BF13C0, rbp - 0x40)
    serialized = _String.read(runtime, output)
    pointer = serialized.get(16, 8) if serialized.get(0, 1) & 1 else output + 1
    runtime.events.append(('caller.diagnostic_serialized', serialized.value()))
    _invoke(runtime, 0x1CE6920, gate, rbp - 0x40, pointer, len(serialized.value()), copied_callback, columns, 1)
    serialized.destroy()
    _String.read(runtime, packet + 64).destroy()
    for row in reversed(list(_vector(runtime, packet + 32, 56))):
        _destroy_row(runtime, row)
    rows = memory.load(packet + 32, 8)
    if rows:
        runtime._free_allocation(rows)
    _String.read(runtime, packet + 8).destroy()
    _callback_destroy(runtime, callback)
    memory.unmap(frame)


def flush(runtime, owner):
    memory = runtime.memory
    records = list(_vector(runtime, owner, 248))
    if not records:
        return
    frame, rbp = _frame(runtime, 0x108, '1CF5E00.caller_diagnostic_flush_frame')
    log(runtime, _SOURCE, 32, b'report ui cache: %d', b'[FGESDK]', 1, len(records))
    _owner(runtime, _response_image())
    columns, callback = rbp - 0x10, rbp - 0x50
    memory.write(columns, bytes(48), source='1CF6161.diagnostic_flush_metadata')
    for offset in (0, 24):
        _String(runtime, bytes(24), bytes([1, 1]) + bytes(22)).write_to(columns + offset)
    memory.store(callback + 32, 0, 8, source='1CF614D.diagnostic_flush_empty_callback')
    submit_cached(runtime, runtime.image_base + 0x67519B8, owner, columns, callback)
    for record in reversed(records):
        memory.store(record, runtime.image_base + 0x414B558, 8, source='1CF6214.diagnostic_record_vtable')
        values = _columns(runtime, record + 224)
        if values.begin:
            memory.store(record + 232, values.begin, 8, source='1CF61F4.diagnostic_record_destroy_end')
        values.destroy()
        _invoke(runtime, 0xBCD740, record)
    memory.store(owner + 8, memory.load(owner, 8), 8, source='1CF625D.diagnostic_cache_clear')
    runtime.events.append(('caller.diagnostic_flushed', owner, len(records)))
    memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva == 0x1CF5E00 and len(values) == 1:
        return flush(runtime, values[0])
    if rva == 0x1BF1AB0 and len(values) == 4:
        return submit_cached(runtime, *values)
    raise InputError('caller diagnostic native entry argument count mismatch')


def _cache(runtime, owner, scene, event, columns):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x180, '1CF5610.caller_diagnostic_cache_frame')
    record = rbp - 0x48
    memory.store(record, base + 0x414B558, 8, source='1CF5699.caller_diagnostic_vtable')
    first = _String.construct(runtime, b'event')
    first.set(16, bytes(8))
    first.write_to(record + 8)
    for offset in range(32, 200, 24):
        _String(runtime, bytes(24), b'\1\1' + bytes(22)).write_to(record + offset)
    memory.write(record + 200, bytes(24), source='1CF5687.caller_diagnostic_base_columns_zero')
    values = _Strings(runtime)
    for value in (scene, _String.construct(runtime, b'-1'), _String.construct(runtime, b'-1'), event):
        values.push(value, clone=True)
    values.reserve(values.count + columns.count)
    for index in range(columns.count):
        values.push(columns.at(index), clone=True)
    precise_clock(runtime, rbp + 0xB0)
    timestamp(runtime, rbp + 0xE0, rbp + 0xB0)
    values.insert(5 if values.count >= 6 else values.count, _String.read(runtime, rbp + 0xE0))
    for offset, value in ((224, values.begin), (232, values.begin + values.count * 24),
                          (240, values.begin + values.capacity * 24)):
        memory.store(record + offset, value, 8, source='1CF58EC.caller_diagnostic_record_columns')
    _cache_append(runtime, owner, record)
    values.destroy()
    for offset in range(8, 200, 24):
        _String.read(runtime, record + offset).destroy()
    memory.unmap(frame)


def _route(runtime, owner, scene, event, columns, rbp):
    memory, base = runtime.memory, runtime.image_base
    _initialize(runtime, 1)
    configuration = base + 0x67516B0
    ready = False
    if len(_String.read(runtime, configuration + 0x108).value()) >= 3:
        mutex = base + 0x6751830
        if runtime.locks.get(mutex, 0):
            raise PrimarySemanticUnavailable('caller diagnostic state waits on its owned mutex')
        runtime.locks[mutex] = 1
        runtime.events.append(('75AF50.lock', mutex))
        state = memory.load(base + 0x6751828, 8)
        if not state:
            state = runtime._operator_new(3)
            memory.write(state, bytes(3), source='1CF7DFC.diagnostic_state_initialization')
            memory.store(base + 0x6751828, state, 8, source='1CF7E05.diagnostic_state_publish')
        runtime.locks[mutex] = 0
        runtime.events.append(('75AFC0.unlock', mutex))
        ready = memory.load(state, 1) != 0
    if ready:
        if memory.load(owner + 8, 8) != memory.load(owner, 8):
            _invoke(runtime, 0x1CF5E00, owner)
        manager = memory.load(base + 0x677DC88, 8)
        if not manager:
            manager = runtime._operator_new(208)
            _invoke(runtime, 0x1D00FC0, manager)
            memory.store(base + 0x677DC88, manager, 8, source='1CF7E5F.diagnostic_online_manager_publish')
        from .primary_caller_online import _write_columns
        forwarded = columns.clone()
        _write_columns(runtime, rbp + 0x450, forwarded)
        _invoke(runtime, 0x1CF9D70, manager, scene.value(), event.value(), rbp + 0x450)
        runtime.events.append(('caller.diagnostic_online', owner, manager))
        return
    _initialize(runtime, 1)
    if len(_String.read(runtime, configuration + 0x108).value()) >= 3:
        line, template = 117, b'[FGESDK] even data: channel not ready, add cache'
    else:
        line, template = 115, b'[FGESDK] even data: not login, add cache'
    log(runtime, _SOURCE, line, template, b'[FGESDK]', 1)
    forwarded = columns.clone()
    _cache(runtime, owner, scene, event, forwarded)
    forwarded.destroy()


def report(runtime, observations, api, owner, scene, event, modules):
    if b'message' in scene.value():
        return
    joined = argument = copied_scene = copied_event = columns = value = None
    frame = None
    try:
        joined = _String.construct(runtime, b'')
        for index in range(modules.count):
            previous = joined
            joined = (_String.concat(runtime, previous.value(), b',') if previous.value()
                      else modules.at(index).clone())
            try:
                if previous.value():
                    _append(joined, modules.at(index).value())
            finally:
                previous.destroy()
        frame, rbp = _frame(runtime, 0x798, '1CF6A10.caller_diagnostic_frame')
        copied_scene = scene.clone()
        copied_event = event.clone()
        argument = joined.clone()
        log(runtime, _SOURCE, 52, b'[FGESDK] event data: scene: %s, event_code: %s',
            b'[FGESDK]', 1, copied_scene.value(), copied_event.value())
        columns = _Strings(runtime)
        columns.push(argument, clone=True)
        value = _window(runtime, observations, api, rbp)
        value.write_to(rbp + 0xE0)
        previous = runtime.worker_observations
        runtime.worker_observations = observations
        try:
            converted = _converted_hardware(runtime, rbp + 0xE0)
            with ExitStack() as transfer:
                transfer.callback(converted.destroy)
                columns.push(converted)
                transfer.pop_all()
            _route(runtime, owner, copied_scene, copied_event, columns, rbp)
        finally:
            runtime.worker_observations = previous
    finally:
        with ExitStack() as cleanup:
            if frame is not None:
                cleanup.callback(runtime.memory.unmap, frame)
            for item in (joined, argument, copied_event, copied_scene, columns, value):
                if item is not None:
                    cleanup.callback(item.destroy)
