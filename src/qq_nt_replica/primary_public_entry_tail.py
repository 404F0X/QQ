from .primary_request_delay import precise_clock
from .primary_vm import PrimarySemanticUnavailable, signed
from .primary_worker_response import _frame


_MASK = (1 << 64) - 1


def install_image(memory, image_base):
    address = image_base + 0x6751D60
    if not any(region.address <= address and address + 32 <= region.address + len(region.data)
               for region in memory._regions):
        memory.map(address, bytearray(32), name='fixed public sampling PE zero fill', initialized=True)
    for rva, raw in ((0x677DD9C, bytes(20)), (0x618C970, (5).to_bytes(4, 'little'))):
        target = image_base + rva
        if not any(region.address <= target and target + len(raw) <= region.address + len(region.data) for region in memory._regions):
            memory.map(target, bytearray(raw), name='fixed public command observation image', initialized=True)


def _interval(runtime):
    from .primary_provider_init import _mutex
    memory, base = runtime.memory, runtime.image_base
    _mutex(runtime, base + 0x6751D68, True)
    pointer = memory.load(base + 0x6751D60, 8)
    if not pointer:
        pointer = runtime._operator_new(48)
        memory.store(pointer, 86400000, 4, source='public.interval_initial_dword')
        for offset in (4, 20, 30):
            memory.write(pointer + offset, bytes(16), source='public.interval_initial_zero')
        memory.store(base + 0x6751D60, pointer, 8, source='public.interval_publish')
    _mutex(runtime, base + 0x6751D68, False)
    return pointer


def _owner(runtime):
    memory, base = runtime.memory, runtime.image_base
    pointer = memory.load(base + 0x6751D70, 8)
    if not pointer:
        pointer = runtime._operator_new(72)
        for offset in (56, 40, 24):
            memory.write(pointer + offset, bytes(16), source='public.sample_owner_deque_zero')
        for offset, value, width in ((0, 0x0000000A00000014, 8), (8, 0, 1),
                                     (12, 3, 4), (16, 0, 2), (18, 0, 1)):
            memory.store(pointer + offset, value, width, source='public.sample_owner_field')
        memory.store(base + 0x6751D70, pointer, 8, source='public.sample_owner_publish')
    return pointer


def _store(runtime, address, value, source):
    runtime.memory.store(address, value & _MASK, 8, source=source)


def _move(runtime, destination, source, size):
    indices = range(0, size, 8) if destination <= source else reversed(range(0, size, 8))
    for index in indices:
        runtime.memory.copy_disjoint(destination + index, source + index, 8,
                                     label='BE0B10.deque_map_move')


def _map_insert(runtime, container, value, *, front):
    memory = runtime.memory
    if front:
        begin = memory.load(container + 8, 8)
        boundary = memory.load(container, 8)
        full = begin == boundary
    else:
        end = memory.load(container + 16, 8)
        boundary = memory.load(container + 24, 8)
        full = end == boundary
    if full:
        if front:
            base = boundary
            end = memory.load(container + 16, 8)
            limit = memory.load(container + 24, 8)
        else:
            base = memory.load(container, 8)
            begin = memory.load(container + 8, 8)
            limit = boundary
        spare = (limit - end if front else begin - base) // 8
        if spare:
            distance = (spare + 1) // 2 * 8
            moved = begin + distance if front else begin - distance
            _move(runtime, moved, begin, end - begin)
            if front:
                _store(runtime, container + 8, moved, 'BE152B.deque_map_begin')
                _store(runtime, container + 16, end + distance, 'BE1533.deque_map_end')
            else:
                _store(runtime, container + 16, end - distance, 'BE12C3.deque_map_end')
                _store(runtime, container + 8, moved, 'BE12CB.deque_map_begin')
            begin, end = moved, end + distance if front else end - distance
        else:
            capacity = (limit - base) // 8 * 2 or 1
            if capacity >= 1 << 61:
                raise PrimarySemanticUnavailable('deque map source length-error continuation is unavailable')
            storage = runtime._operator_new(capacity * 8)
            moved = storage + ((capacity + 3) // 4 if front else capacity // 4) * 8
            _move(runtime, moved, begin, end - begin)
            new_end = moved + end - begin
            for offset, item in ((0, storage), (8, moved), (16, new_end), (24, storage + capacity * 8)):
                _store(runtime, container + offset, item, 'BE1473.deque_map_publish')
            if base:
                runtime._free_allocation(base)
            begin, end = moved, new_end
    target = begin - 8 if front else end
    _store(runtime, target, value, 'BE1703.deque_map_pointer' if front else 'BE1496.deque_map_pointer')
    _store(runtime, container + (8 if front else 16), target if front else target + 8,
           'BE1713.deque_map_begin' if front else 'BE14A6.deque_map_end')


def _grow(runtime, container):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x88, 'BE0B10.deque_growth_frame')
    _store(runtime, rbp, _MASK - 1, 'BE0B2B.deque_growth_frame_state')
    start = memory.load(container + 32, 8)
    if start >= 512:
        _store(runtime, container + 32, start - 512, 'BE0B4C.deque_recycle_start')
        begin = memory.load(container + 8, 8)
        block = memory.load(begin, 8)
        _store(runtime, container + 8, begin + 8, 'BE0B5F.deque_recycle_begin')
        _map_insert(runtime, container, block, front=False)
    else:
        end = memory.load(container + 16, 8)
        limit = memory.load(container + 24, 8)
        begin = memory.load(container + 8, 8)
        base = memory.load(container, 8)
        count, capacity = (end - begin) // 8, (limit - base) // 8
        if count < capacity:
            block = runtime._operator_new(4096)
            if end == limit:
                _map_insert(runtime, container, block, front=True)
                current = memory.load(container + 8, 8)
                block = memory.load(current, 8)
                _store(runtime, container + 8, current + 8, 'BE0D4E.deque_rotation_begin')
            _map_insert(runtime, container, block, front=False)
        else:
            capacity = capacity * 2 or 1
            if capacity >= 1 << 61:
                raise PrimarySemanticUnavailable('deque map source length-error continuation is unavailable')
            storage = runtime._operator_new(capacity * 8)
            temporary = rbp - 0x30
            middle = storage + count * 8
            for offset, item in ((0, storage), (8, middle), (16, middle), (24, storage + capacity * 8)):
                _store(runtime, temporary + offset, item, 'BE0C55.deque_temporary_map')
            block = runtime._operator_new(4096)
            _store(runtime, middle, block, 'BE0E30.deque_new_block')
            _store(runtime, temporary + 16, middle + 8, 'BE0E37.deque_temporary_end')
            for address in reversed(range(begin, end, 8)):
                _map_insert(runtime, temporary, memory.load(address, 8), front=True)
            memory.copy_disjoint(container, temporary, 32, label='BE0E6B.deque_map_swap')
            if base:
                runtime._free_allocation(base)
    memory.unmap(frame)


def sample(runtime, owner):
    memory = runtime.memory
    frame, unused = _frame(runtime, 0x60, 'BE0960.public_sample_frame')
    _store(runtime, frame + 0x40, frame + 0x38, 'BE0974.public_sample_clock_pointer')
    precise_clock(runtime, memory.load(frame + 0x40, 8))
    container = owner + 0x18
    begin = memory.load(container + 8, 8)
    end = memory.load(container + 16, 8)
    extent = end - begin
    capacity = ((extent << 6) - 1) & _MASK if extent else 0
    size = memory.load(container + 40, 8)
    position = (size + memory.load(container + 32, 8)) & _MASK
    if capacity == position:
        _grow(runtime, container)
        begin = memory.load(container + 8, 8)
        position = (memory.load(container + 32, 8) + memory.load(container + 40, 8)) & _MASK
    block = memory.load(begin + (position >> 9) * 8, 8)
    now = memory.load(frame + 0x38, 8)
    _store(runtime, block + (position & 511) * 8, now, 'BE09E5.public_sample_append')
    _store(runtime, container + 40, memory.load(container + 40, 8) + 1, 'BE09E9.public_sample_size')
    _store(runtime, frame + 0x48, frame + 0x30, 'BE09F3.public_sample_threshold_pointer')
    memory.load(frame + 0x48, 8)
    threshold = (memory.load(frame + 0x38, 8) - 600000000) & _MASK
    _store(runtime, frame + 0x30, threshold, 'BE0A09.public_sample_threshold')
    while memory.load(container + 40, 8):
        begin = memory.load(container + 8, 8)
        start = memory.load(container + 32, 8)
        block = memory.load(begin + (start >> 9) * 8, 8)
        value = memory.load(block + (start & 511) * 8, 8)
        if signed(value, 64) >= signed(threshold, 64):
            break
        pair = memory.read(container + 32, 16)
        start = (int.from_bytes(pair[:8], 'little') + 1) & _MASK
        size = (int.from_bytes(pair[8:], 'little') - 1) & _MASK
        memory.write(container + 32, start.to_bytes(8, 'little') + size.to_bytes(8, 'little'),
                     source='BE0A6C.public_sample_pop')
        if start >= 1024:
            begin = memory.load(container + 8, 8)
            runtime._free_allocation(memory.load(begin, 8))
            _store(runtime, container + 8, begin + 8, 'BE0A90.public_sample_pop_map')
            _store(runtime, container + 32, memory.load(container + 32, 8) - 512,
                   'BE0A95.public_sample_pop_start')
    memory.unmap(frame)


def command_copy(runtime, address, command, *, owned=None):
    from .primary_worker_consumer import _invoke
    from .errors import InputError
    from .primary_logger import _String
    if not isinstance(command, bytes) or b'\0' in command:
        raise InputError('public command copy requires raw NUL-free bytes')
    size = len(command)
    if size >= (1 << 64) - 16:
        raise PrimarySemanticUnavailable('public command source length-error continuation is unavailable')
    if size <= 22:
        runtime.memory.store(address, size * 2, 1, source='public.command_short_tag')
        pointer = address + 1
    else:
        physical = (size | 15) + 1
        pointer = _invoke(runtime, 0xB75000, physical)
        if owned is not None:
            from .primary_sign_lifecycle import region_at
            owned.append((pointer, region_at(runtime.memory, pointer)))
        for offset, value in ((16, pointer), (0, physical | 1), (8, size)):
            _store(runtime, address + offset, value, 'public.command_long_header')
    if command:
        runtime.memory.write(pointer, command, source='BAE3F0.public_command_copy')
    runtime.memory.store(pointer + size, 0, 1, source='BAE3F5.public_command_terminator')
    return _String.read(runtime, address)


_COMMANDS = (b'2', b'205', b'2088', b'226', b'168', b'MessageSvc.PbSendMsg',
             b'OidbSvcTrpcTcp.0x11ec_1', b'OidbSvcTrpcTcp.0x758_1',
             b'OidbSvcTrpcTcp.0x7c2_5', b'OidbSvcTrpcTcp.0x6d9_4',
             b'OidbSvcTrpcTcp.0x11ec_1')


def _copy_command_string(runtime, destination, source, *, owned=None):
    from .primary_worker_consumer import _invoke
    memory = runtime.memory
    if not memory.load(source, 1) & 1:
        memory.copy_disjoint(destination + 16, source + 16, 8, label='75B825.command_tail_copy')
        memory.copy_disjoint(destination, source, 16, label='75B82C.command_head_copy')
    else:
        size = memory.load(source + 8, 8)
        pointer = _invoke(runtime, 0xB75000, (size | 15) + 1)
        if owned is not None:
            from .primary_sign_lifecycle import region_at
            owned.append((pointer, region_at(runtime.memory, pointer)))
        for offset, value in ((16, pointer), (0, ((size | 15) + 1) | 1), (8, size)):
            _store(runtime, destination + offset, value, '75B863.command_long_copy_header')
        memory.copy_disjoint(pointer, memory.load(source + 16, 8), size + 1,
                             label='75B87B.command_long_copy_payload')


def command_list_match(runtime, command_address):
    from .primary_logger import _String
    memory = runtime.memory
    frame, unused = _frame(runtime, 264, 'BAE972.public_command_list_temporaries')
    from .primary_sign_lifecycle import cleanup, region_at
    regions = [(frame, region_at(memory, frame))]
    owned = []
    try:
        for index, value in enumerate(_COMMANDS):
            command_copy(runtime, frame + index * 24, value, owned=owned)
        array = runtime._operator_new(264)
        owned.append((array, region_at(memory, array)))
        for index in range(11):
            _copy_command_string(runtime, array + index * 24, frame + index * 24, owned=owned)
        for index in reversed(range(11)):
            _String.read(runtime, frame + index * 24).destroy()
        result = 1
        command = _String.read(runtime, command_address).value()
        for index in range(11):
            selected = _String.read(runtime, array + index * 24).value()
            result = (command > selected) - (command < selected)
            if result == 0:
                break
        for index in reversed(range(11)):
            _String.read(runtime, array + index * 24).destroy()
        runtime._free_allocation(array)
        return result
    finally:
        cleanup(runtime, regions, owned)


_IMPORTS = {'FindWindowA': 0x4910528, 'StrStrIA': 0x4910B20,
            'GetCurrentProcessId': 0x490FDE8, 'GetClassNameA': 0x4910560,
            'GetForegroundWindow': 0x49105A0, 'GetWindowRect': 0x49105E8,
            'GetWindowTextA': 0x49105F0, 'GetWindowThreadProcessId': 0x4910608,
            'IsWindowVisible': 0x4910628}


def _target(runtime, name):
    target = runtime.memory.load(runtime.image_base + _IMPORTS[name], 8)
    if not target or target != runtime.worker_imports.get(name):
        raise PrimarySemanticUnavailable('public sampling current import is not bound: ' + name)
    return target


def _observe(runtime, name, arguments):
    from .errors import InputError
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('public sampling requires an explicit raw API observation: ' + name)
    value, effects = runtime.worker_observations.take(runtime, name, arguments)
    if type(value) is not int or not 0 <= value <= _MASK or effects is not None:
        raise InputError('public sampling requires an unsigned pointer result and no buffer effects')
    return value


def advance_counter(runtime, owner):
    memory, base = runtime.memory, runtime.image_base
    counter = (memory.load(base + 0x6751D78, 4) + 1) & 0xFFFFFFFF
    memory.store(base + 0x6751D78, counter, 4, source='BAE490.public_call_counter')
    target = memory.load(base + _IMPORTS['FindWindowA'], 8)
    value = memory.load(owner + 18, 1)
    number = signed(counter, 32)
    quotient = abs(number) // 10 * (-1 if number < 0 else 1)
    if number - quotient * 10 == 0 and not value:
        if not target or target != runtime.worker_imports.get('FindWindowA'):
            raise PrimarySemanticUnavailable('public sampling current import is not bound: FindWindowA')
        handle = _observe(runtime, 'FindWindowA', (b'WTWindow\0', 0))
        if handle:
            memory.store(owner + 18, 1, 1, source='BAE4EF.public_window_found')
            value = 1
        else:
            value = memory.load(owner + 18, 1)
    memory.store(owner + 18, int(bool(value)), 1, source='BAE716.public_window_canonical')


def sample_command(runtime, owner, command_address):
    from .primary_logger import _String
    command = _String.read(runtime, command_address).value()
    if command == b'wtlogin.trans_emp':
        return False
    _target(runtime, 'StrStrIA')
    matches = _observe(runtime, 'StrStrIA', (command + b'\0', b'login\0'))
    if not matches and command_list_match(runtime, command_address) != 0:
        return False
    sample(runtime, owner)
    threshold = runtime.memory.load(owner, 4, signed=True)
    count = runtime.memory.load(owner + 64, 4, signed=True)
    if threshold <= count:
        runtime.memory.store(owner + 16, 1, 1, source='BAE959.public_sample_threshold')
    return True


_SOURCE_FILE = b'R:/devops/workspace/p-824b74756ad64e12838601ccde6ecefb/platforms/Windows/libsecxx\\heartbeat/qssdk/qssdk_wrapper.h'


def emit_hfr(runtime, command_address):
    from .primary_logger import log
    from .primary_device_records import notify
    memory = runtime.memory
    argument = memory.load(command_address + 16, 8) if memory.load(command_address, 1) & 1 else command_address + 1
    log(runtime, _SOURCE_FILE, 0xEB, b'hfr %s', b'[FGESDK]', 1, argument)
    notify(runtime)


def tail(runtime, interval, command_address):
    from .primary_worker_loop import _initialize, _tick
    memory, base = runtime.memory, runtime.image_base
    _initialize(runtime, 1)
    configuration = base + 0x67516B0 + 0x28
    tag = memory.load(configuration + 0xE0, 1)
    length = memory.load(configuration + 0xE8, 8) if tag & 1 else tag >> 1
    if length < 4:
        return False
    owner = _owner(runtime)
    count = memory.load(owner + 64, 4, signed=True)
    threshold = memory.load(owner, 4, signed=True)
    if count > threshold:
        memory.store(owner, (threshold * 5) & 0xFFFFFFFF, 4, source='BAFECC.public_threshold_multiply')
    else:
        now = _tick(runtime)
        previous = memory.load(base + 0x6751D7C, 4)
        if previous and ((now - previous) & 0xFFFFFFFF) < memory.load(interval, 4):
            return False
        memory.store(base + 0x6751D7C, now, 4, source='BAFF09.public_previous_tick')
    emit_hfr(runtime, command_address)
    return True


_OBSERVED_COMMANDS = (b'OidbSvcTrpcTcp.0x7c2_5', b'MessageSvc.PbSendMsg', b'OidbSvcTrpcTcp.0x11ec_1')


def _window_api(runtime, name, *arguments):
    _target(runtime, name)
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('public command observer requires raw Windows observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _window_write(runtime, address, value, capacity, name):
    if value is None:
        return
    from .errors import InputError
    if type(value) is not bytes or len(value) > capacity:
        raise InputError('public command observer requires its actual raw output prefix: ' + name)
    runtime.memory.write(address, value, source='1D0EF20.' + name + '_raw_output')


def observe_command(runtime, command_address):
    from .primary_logger import _String, _cstring
    memory, base = runtime.memory, runtime.image_base
    frame, unused = _frame(runtime, 544, '1D0EF20.command_window_observer')
    command_object = _String.read(runtime, command_address)
    command = command_object.value()
    command_pointer = command_object.get(16, 8) if command_object.get(0, 1) & 1 else command_address + 1
    if command not in _OBSERVED_COMMANDS:
        memory.unmap(frame)
        return
    counter = (memory.load(base + 0x677DD9C, 4) + 1) & 0xFFFFFFFF
    memory.store(base + 0x677DD9C, counter, 4, source='1D0EF20.command_observation_counter')
    dividend, divisor = signed(counter, 32), memory.load(base + 0x618C970, 4, signed=True)
    if not divisor:
        raise ZeroDivisionError('public command observer signed division by zero')
    if dividend == -(1 << 31) and divisor == -1:
        raise OverflowError('public command observer signed division overflow')
    quotient = abs(dividend) // abs(divisor) * (-1 if (dividend < 0) != (divisor < 0) else 1)
    if dividend - quotient * divisor:
        memory.unmap(frame)
        return
    if dividend >= 11:
        memory.store(base + 0x618C970, (divisor * 2) & 0xFFFFFFFF, 4, source='1D0EF20.command_interval_double')
    window, effects = _window_api(runtime, 'GetForegroundWindow')
    if effects is not None:
        raise PrimarySemanticUnavailable('foreground window observation cannot write a buffer')
    title, kind, rectangle, process = frame, frame + 260, frame + 520, frame + 536
    memory.write(title, bytes(260), source='1D0EF20.command_title_zero')
    memory.write(kind, bytes(260), source='1D0EF20.command_class_zero')
    if not window:
        _window_log(runtime, 0xFE)
        memory.unmap(frame)
        return
    for name, pointer in (('GetWindowTextA', title), ('GetClassNameA', kind)):
        result, output = _window_api(runtime, name, window, 259)
        _window_write(runtime, pointer, output, 260, name)
    result, output = _window_api(runtime, 'GetWindowRect', window)
    _window_write(runtime, rectangle, output, 16, 'GetWindowRect')
    visible, output = _window_api(runtime, 'IsWindowVisible', window)
    if output is not None:
        raise PrimarySemanticUnavailable('window visibility observation cannot write a buffer')
    right = memory.load(rectangle + 8, 4)
    bottom = memory.load(rectangle + 12, 4)
    left = memory.load(rectangle, 4)
    width = signed((right - left) & 0xFFFFFFFF, 32)
    top = memory.load(rectangle + 4, 4)
    height = signed((bottom - top) & 0xFFFFFFFF, 32)
    result, output = _window_api(runtime, 'GetWindowThreadProcessId', window)
    if type(output) is int and 0 <= output <= 0xFFFFFFFF:
        memory.store(process, output, 4, source='1D0EF20.command_window_process_raw_output')
    elif output is not None:
        raise PrimarySemanticUnavailable('window process observation requires DWORD or unknown output')
    if memory.load(base + 0x677DDA0, 4, signed=True) < 3:
        text = _cstring(runtime, title)
        if text != b'QQ' or _cstring(runtime, kind) != b'Chrome_WidgetWin_1':
            _window_anomaly(runtime, 0x677DDA0, 0x118, 1, command_pointer, title, kind)
    if memory.load(base + 0x677DDA4, 4, signed=True) < 3:
        window_process = memory.load(process, 4)
        current, effects = _window_api(runtime, 'GetCurrentProcessId')
        if effects is not None:
            raise PrimarySemanticUnavailable('current process observation cannot write a buffer')
        if window_process != current:
            address = base + 0x677DDA4
            incremented = (memory.load(address, 4) + 1) & 0xFFFFFFFF
            memory.store(address, incremented, 4, source='1D0EF20.command_window_anomaly')
            current, effects = _window_api(runtime, 'GetCurrentProcessId')
            if effects is not None:
                raise PrimarySemanticUnavailable('current process observation cannot write a buffer')
            _window_log(runtime, 0x126, command_pointer, window_process, current, incremented)
            _window_feature(runtime, address, 0x20)
    if memory.load(base + 0x677DDA8, 4, signed=True) < 3 and (width < 100 or height < 100):
        _window_anomaly(runtime, 0x677DDA8, 0x134, 0x21, command_pointer, width, height)
    if memory.load(base + 0x677DDAC, 4, signed=True) < 3 and not visible:
        _window_anomaly(runtime, 0x677DDAC, 0x142, 0x22, command_pointer)
    memory.unmap(frame)


def _window_feature(runtime, address, bit):
    from .primary_worker_consumer import _invoke
    if runtime.memory.load(address, 4, signed=True) >= 3:
        _invoke(runtime, 0x1BF75A0, 1, bit, 1, 0)
        _invoke(runtime, 0x1BF8090, 1, bit, 1, 0)


def _window_anomaly(runtime, rva, line, bit, *arguments):
    memory, address = runtime.memory, runtime.image_base + rva
    incremented = (memory.load(address, 4) + 1) & 0xFFFFFFFF
    memory.store(address, incremented, 4, source='1D0EF20.command_window_anomaly')
    _window_log(runtime, line, *arguments, incremented)
    _window_feature(runtime, address, bit)


_WINDOW_SOURCE = bytes.fromhex('523a5c6465766f70735c776f726b73706163655c702d38323462373437353661643634653132383338363031636364653665636566625c706c6174666f726d735c57696e646f77735c6c696273656378785c656e76696e666f5c64657465637477696e646f772e637070')
_WINDOW_FORMATS = {0xFE: b'cwh is null', 0x118: b'%s, t: %s, c: %s, c: %d',
                   0x126: b'%s, p: %d, c: %d, c: %d', 0x134: b'%s, w: %d, h: %d, c: %d',
                   0x142: b'%s, v count: %d'}


def _window_log(runtime, line, *arguments):
    from .primary_logger import log
    return log(runtime, _WINDOW_SOURCE, line, _WINDOW_FORMATS[line], b'[FGESDK]', 1, *arguments)


def prepare(runtime, command):
    from .primary_sign_lifecycle import cleanup, region_at
    frame, unused = _frame(runtime, 24, 'BAE382.public_command_source_string')
    regions = [(frame, region_at(runtime.memory, frame))]
    owned = []
    try:
        interval = _interval(runtime)
        command_copy(runtime, frame, command, owned=owned)
        observe_command(runtime, frame)
        owner = _owner(runtime)
        advance_counter(runtime, owner)
        sample_command(runtime, owner, frame)
        tail(runtime, interval, frame)
    except BaseException:
        cleanup(runtime, regions, owned)
        raise
    runtime._public_command_owned = getattr(runtime, '_public_command_owned', {})
    runtime._public_command_owned[frame] = (regions, owned)
    return frame


def release(runtime, command_address):
    from .primary_logger import _String
    from .primary_sign_lifecycle import cleanup, region_at
    tracked = getattr(runtime, '_public_command_owned', {}).pop(command_address, None)
    if tracked is None:
        tracked = ([(command_address, region_at(runtime.memory, command_address))], [])
    try:
        _String.read(runtime, command_address).destroy()
    finally:
        cleanup(runtime, *tracked)
