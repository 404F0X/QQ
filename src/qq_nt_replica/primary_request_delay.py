import hashlib
import json
from pathlib import Path
import struct

from .errors import InputError
from .primary_logger import _String, _srw, construct, feature, log
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_MASK64 = (1 << 64) - 1
_IMAGE_SHA256 = 'b61d5b794c3de4a75cfb8008ebd0c3f8d04f6a8dd114224a41268ab397c0fe0f'


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'request-delay-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed request delay image identity mismatch')
    return json.loads(raw)


def _observe(runtime, name, arguments):
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('request delay requires an explicit CRT observation: ' + name)
    try:
        return runtime.worker_observations.take(runtime, name, arguments)
    except UnknownMemory as error:
        raise PrimarySemanticUnavailable('request delay requires an explicit CRT observation: ' + name) from error


def precise_clock(runtime, output):
    filetime = runtime._next(runtime._filetimes, 'GetSystemTimePreciseAsFileTime')
    if type(filetime) is not int or not 0 <= filetime <= _MASK64:
        raise InputError('precise FILETIME service value must be unsigned64')
    ticks = signed(filetime + 0xFE624E212AC18000, 64)
    high = (ticks * 0x6666666666666667) >> 64
    value = (high >> 2) + ((high & _MASK64) >> 63)
    runtime.memory.store(output, value, 8, source='759AC8.microseconds')
    return output


def seconds(runtime, pointer):
    value = runtime.memory.load(pointer, 8, signed=True)
    high = (value * 0x431BDE82D7B634DB) >> 64
    return ((high >> 18) + ((high & _MASK64) >> 63)) & _MASK64


def localtime(runtime, pointer):
    value = runtime.memory.load(pointer, 8, signed=True)
    result, raw = _observe(runtime, '_localtime64', (value,))
    if not result:
        if raw is not None:
            raise InputError('null localtime64 result must not provide a calendar buffer')
        return 0
    if not isinstance(raw, bytes) or len(raw) != 36 or result > _MASK64 - 36:
        raise InputError('localtime64 requires its complete nine-DWORD returned calendar buffer')
    if not any(region.address <= result < region.address + len(region.data) for region in runtime.memory._regions):
        runtime.memory.map(result, bytearray(raw), name='explicit CRT localtime64 calendar buffer', initialized=True)
    else:
        runtime.memory.write(result, raw, source='CRT.localtime64.observed_calendar')
    return result


def seed_random(runtime, seed):
    runtime.memory.store(runtime._crt_thread() + 40, seed & 0xFFFFFFFF, 4, source='3E98FE5.srand')
    return None


def random(runtime):
    pointer = runtime._crt_thread() + 40
    seed = (runtime.memory.load(pointer, 4) * 0x343FD + 0x269EC3) & 0xFFFFFFFF
    runtime.memory.store(pointer, seed, 4, source='3E9900C.rand_state')
    result = (seed >> 16) & 0x7FFF
    runtime.events.append(('request.delay_rand', result, seed))
    return result


def policy(runtime, output, pointer):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x38, '1D31950.delay_policy_frame')
    memory.store(frame + 40, _invoke(runtime, 0x759B00, pointer), 8, source='1D31973.calendar_seconds')
    calendar = _invoke(runtime, 0x3E88BE0, frame + 40)
    minute = memory.load(calendar + 4, 4, signed=True)
    hour = memory.load(calendar + 8, 4, signed=True)
    eligible = hour == 23 and minute == 59 or hour == 0 and minute <= 3
    delay = 0
    if eligible:
        tls = runtime.tls_base_address
        if tls is None:
            raise PrimarySemanticUnavailable('request delay requires the current original image TLS block')
        if not memory.load(tls + 0xBC2, 1):
            _invoke(runtime, 0x3E98FD8, _invoke(runtime, 0x3E8ED3C, 0) & 0xFFFFFFFF)
            memory.store(tls + 0xBC2, 1, 1, source='1D319E0.random_seeded')
        if (_invoke(runtime, 0x3E98FF0) >> 4) % 100 <= 49:
            delay = (240 + (_invoke(runtime, 0x3E98FF0) >> 4) % 420) * 1000000
    value = signed(memory.load(pointer, 8) + delay, 64)
    memory.store(output, value, 8, source='1D31A51.delay_deadline')
    memory.unmap(frame)
    runtime.events.append(('request.delay_policy', eligible, delay, value))
    return output


def _snapshot(runtime, pointer, size):
    region, offset = runtime.memory._span(pointer, size)
    return bytes(region.data[offset:offset + size]), bytes(region.initialized[offset:offset + size])


def _write(runtime, pointer, snapshot):
    raw, known = snapshot
    begin = 0
    while begin < len(raw):
        end = begin + 1
        while end < len(raw) and known[end] == known[begin]:
            end += 1
        if known[begin]:
            runtime.memory.write(pointer + begin, raw[begin:end], source='request.delay_record_move')
        else:
            runtime.memory.forget(pointer + begin, end - begin, source='request.delay_unobserved_padding')
        begin = end


def _clone_record(runtime, output, pointer):
    for offset in (0, 24, 48):
        _String.read(runtime, pointer + offset).clone().write_to(output + offset)
    _write(runtime, output + 72, _snapshot(runtime, pointer + 72, 25))


def _vector(runtime, pointer):
    values = tuple(runtime.memory.load(pointer + offset, 8) for offset in (0, 8, 16))
    begin, end, capacity = values
    if (not 0 <= begin <= end <= capacity <= _MASK64 or (end - begin) % 104 or
            (capacity - begin) % 104 or capacity - begin > 104 * 4096):
        raise PrimaryProgramLimit('request delay vector exceeds its bounded offline domain')
    return values


def grow(runtime, vector, pointer):
    memory = runtime.memory
    begin, end, capacity = _vector(runtime, vector)
    count = (end - begin) // 104
    count_capacity = (capacity - begin) // 104
    requested = max(count + 1, 2 * count_capacity)
    if requested > 4096:
        raise PrimaryProgramLimit('request delay vector growth exceeds its bounded offline domain')
    storage = runtime._operator_new(requested * 104)
    _clone_record(runtime, storage + count * 104, pointer)
    for index in reversed(range(count)):
        old, new = begin + index * 104, storage + index * 104
        for offset in (0, 24, 48):
            _String.read(runtime, old + offset).write_to(new + offset)
            memory.write(old + offset, bytes(24), source='1D324C0.moved_string_zero')
        _write(runtime, new + 72, _snapshot(runtime, old + 72, 25))
    for offset, value in ((0, storage), (8, storage + (count + 1) * 104), (16, storage + requested * 104)):
        memory.store(vector + offset, value, 8, source='1D325AB.vector_publish')
    if begin:
        runtime._free_allocation(begin)
    return None


def push_heap(runtime, begin, end, count):
    memory = runtime.memory
    if count < 2:
        return None
    if count > 4096 or end - begin != count * 104:
        raise PrimaryProgramLimit('request delay heap exceeds its bounded offline domain')
    hole = count - 1
    parent = (hole - 1) // 2
    last = begin + hole * 104
    deadline = memory.load(last + 80, 8, signed=True)
    if deadline >= memory.load(begin + parent * 104 + 80, 8, signed=True):
        return None
    saved = tuple(_String.read(runtime, last + offset) for offset in (0, 24, 48))
    tail = _snapshot(runtime, last + 72, 25)
    for offset in (0, 24, 48):
        memory.write(last + offset, bytes(24), source='1D320E2.heap_extract_zero')
    while True:
        destination, source = begin + hole * 104, begin + parent * 104
        for offset in (0, 24, 48):
            _String.read(runtime, destination + offset).destroy()
            _String.read(runtime, source + offset).write_to(destination + offset)
            memory.write(source + offset, bytes(2), source='1D321D6.heap_moved_string_reset')
        _write(runtime, destination + 72, _snapshot(runtime, source + 72, 25))
        hole = parent
        if not hole:
            break
        parent = (hole - 1) // 2
        if deadline >= memory.load(begin + parent * 104 + 80, 8, signed=True):
            break
    destination = begin + hole * 104
    for offset, value in zip((0, 24, 48), saved):
        _String.read(runtime, destination + offset).destroy()
        value.write_to(destination + offset)
    _write(runtime, destination + 72, tail)
    return None


def append(runtime, vector, pointer):
    begin, end, capacity = _vector(runtime, vector)
    if end < capacity:
        _clone_record(runtime, end, pointer)
        runtime.memory.store(vector + 8, end + 104, 8, source='1D31AE6.vector_end')
    else:
        _invoke(runtime, 0x1D32390, vector, pointer)
    begin, end, _ = _vector(runtime, vector)
    _invoke(runtime, 0x1D320A0, begin, end, 0, (end - begin) // 104)
    return None


def timestamp(runtime, output, pointer):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x158, '1CF5CB0.delay_timestamp_frame')
    ios = frame + 0xA0
    for offset in (0x38, 0x40, 0x58, 0x70):
        memory.store(ios + offset, 0, 8, source='760754.timestamp_stream_owned_storage')
    memory.store(frame + 0x148, _invoke(runtime, 0x759B00, pointer), 8, source='1CF5CD9.calendar_seconds')
    calendar = _invoke(runtime, 0x3E88BE0, frame + 0x148)
    raw = memory.read(calendar, 36)
    if not hasattr(runtime, '_request_delay_time_locale'):
        locale, effects = _observe(runtime, 'CRT.lc_locale_name', ())
        if locale != 0 or effects is not None:
            raise PrimarySemanticUnavailable('request delay time formatting requires the observed C locale')
        runtime._request_delay_time_locale = locale
    sec, minute, hour, day, month, year, weekday, yearday, dst = struct.unpack('<9i', raw)
    year += 1900
    month += 1
    if not (0 <= sec <= 60 and 0 <= minute <= 59 and 0 <= hour <= 23 and 1 <= day <= 31 and
            1 <= month <= 12 and 0 <= year <= 9999 and 0 <= weekday <= 6 and 0 <= yearday <= 365 and dst in (-1, 0, 1)):
        raise PrimarySemanticUnavailable('request delay time formatting leaves the recovered valid C-calendar domain')
    if bytes.fromhex(_image()['date_format_hex']) != b'%Y-%m-%d %H:%M:%S':
        raise InputError('fixed delay timestamp format mismatch')
    value = f'{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}'.encode('ascii')
    _String.construct(runtime, value).write_to(output)
    for offset in (0x38, 0x40, 0x58, 0x70):
        _invoke(runtime, 0x3E94F90, memory.load(ios + offset, 8))
    memory.unmap(frame)
    runtime.events.append(('request.delay_timestamp', raw, value))
    return output


def start(runtime, owner):
    memory = runtime.memory
    frame, _ = _frame(runtime, 0x40, '1C411C0.delay_thread_start_frame')
    _srw(runtime, owner + 16, True)
    if not memory.load(owner + 8, 1):
        memory.store(frame + 32, owner + 16, 8, source='1C411E9.saved_worker_lock')
        memory.store(owner + 8, 1, 1, source='1C411ED.worker_running')
        memory.store(frame + 40, owner, 8, source='1C411F1.worker_capture')
        _invoke(runtime, 0x1C412A0, frame + 48, frame + 40)
        raise PrimarySemanticUnavailable('request delay thread construction ownership is not implemented')
    _srw(runtime, owner + 16, False)
    memory.unmap(frame)
    return None


def admit(runtime, owner, kind, payload, columns):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x208, '1D30A90.delay_report_frame')
    configuration = memory.load(base + 0x67516A8, 8)
    if not configuration:
        configuration = runtime._operator_new(120)
        construct(runtime, configuration)
        memory.store(base + 0x67516A8, configuration, 8, source='1D30AE8.config_publish')
    image = _image()
    if feature(runtime, configuration, 17) != 1:
        log(runtime, bytes.fromhex(image['file_hex']), 35, bytes.fromhex(image['disabled_template_hex']),
            bytes.fromhex(image['tag_hex']), 1)
        memory.unmap(frame)
        return 0
    _invoke(runtime, 0x759A80, rbp + 72)
    _invoke(runtime, 0x1D31950, rbp + 80, rbp + 72)
    now, deadline = (memory.load(rbp + offset, 8, signed=True) for offset in (72, 80))
    if now >= deadline:
        memory.unmap(frame)
        return 0
    record = rbp + 176
    for output, source in zip((record, record + 24, record + 48), (payload, columns, columns + 24)):
        _String.read(runtime, source).clone().write_to(output)
    sequence = (memory.load(owner + 136, 8) + 1) & _MASK64
    memory.store(owner + 136, sequence, 8, source='1D30B5C.atomic_sequence')
    for offset, value in ((72, now), (80, deadline), (88, sequence)):
        memory.store(record + offset, value, 8, source='1D30BD0.delay_record')
    memory.store(record + 96, kind & 255, 1, source='1D30BED.record_kind')
    _invoke(runtime, 0x1CF5CB0, rbp + 24, rbp + 80)
    _invoke(runtime, 0x1CF5CB0, rbp + 48, rbp + 72)
    delay_seconds = signed(deadline - now, 64) // 1000000
    log(runtime, bytes.fromhex(image['file_hex']), 47, bytes.fromhex(image['accepted_template_hex']),
        bytes.fromhex(image['tag_hex']), 1, sequence, _String.read(runtime, rbp + 48).value(),
        _String.read(runtime, rbp + 24).value(), delay_seconds)
    _String.read(runtime, rbp + 48).destroy()
    _String.read(runtime, rbp + 24).destroy()
    _srw(runtime, owner + 96, True)
    _invoke(runtime, 0x1D31A70, owner + 104, record)
    if not memory.load(owner + 8, 1):
        _invoke(runtime, 0x1C411C0, owner)
    _srw(runtime, owner + 96, False)
    for offset in (48, 24, 0):
        _String.read(runtime, record + offset).destroy()
    memory.unmap(frame)
    runtime.events.append(('request.delay_enqueued', owner, sequence, now, deadline, kind & 255))
    return 1


def invoke(runtime, rva, values):
    handlers = {0x759A80: precise_clock, 0x759B00: seconds, 0x3E88BE0: localtime,
                0x3E98FD8: seed_random, 0x3E98FF0: random, 0x1D31950: policy,
                0x1D32390: grow, 0x1D31A70: append, 0x1CF5CB0: timestamp,
                0x1C411C0: start, 0x1D30A90: admit}
    if rva == 0x1D320A0:
        return push_heap(runtime, values[0], values[1], values[3])
    return handlers[rva](runtime, *values)
