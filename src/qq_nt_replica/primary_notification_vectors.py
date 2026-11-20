from dataclasses import dataclass

from .errors import InputError
from .primary_device_cache import _WideString
from .primary_device_collector import _delete_array, _new_array, _terminated
from .primary_device_refresh import _StringVector
from .primary_logger import _String, _cstring, feature
from .primary_memory import UnknownMemory
from .primary_notification_collectors import _accounts_equal, _accounts_sort, _accounts_unique, grow_push_copy
from .primary_request_manager import hash_bytes
from .primary_sdk_records import _index
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed
from .primary_worker import lower_unit
from .primary_worker_consumer import _append, _invoke
from .primary_worker_loop import _ensure_logger
from .primary_worker_response import _frame


_MASK = (1 << 64) - 1
_LIMIT = 1 << 20
_IMPORTS = {
    'GetCommandLineA': (0x490FDA0, 0, 64),
    'GetCurrentDirectoryA': (0x490FDD0, 2, 32),
    'EnumWindows': (0x4910520, 2, 32),
    'GetCurrentProcessId': (0x490FDE8, 0, 32),
    'GetWindowThreadProcessId': (0x4910608, 2, 32),
    'IsWindowVisible': (0x4910628, 1, 32),
    'GetClassNameA': (0x4910560, 3, 32),
    'GetWindowTextA': (0x49105F0, 3, 32),
    'CreateToolhelp32Snapshot': (0x490FC88, 2, 64),
    'Process32FirstW': (0x4910228, 2, 32),
    'Process32NextW': (0x4910238, 2, 32),
    'CloseHandle': (0x490FBD8, 1, 32),
    'PathRemoveExtensionW': (0x4910AD8, 1, 0),
    'IsDBCSLeadByte': (0x4910118, 1, 32),
    'MultiByteToWideChar': (0x49101F0, 6, 32),
    'WideCharToMultiByte': (0x4910460, 8, 32),
}
_CLASS_RECIPES = (
    '7e5f5d51575f4f63765a564342', '7d40464b415a5f0d77680e644957411579564a5a695452575d46',
    '614952484b407b7c434d4f4a5a7a455d6d00', '6b647a4f527e5643595054465a5f5f',
    '694c5e4177554f5d534f605e55', '75525f5e5d6b4850425e5346',
    '614e4e544949417c43474c40596e40524142', '150606040501', '6b6749564a506d5c5a535946',
    '7a6b0e7855574c4559597c5c4145', '6b504c5d685a5e7658564542', '6c454e4e5e556d44564d6a7f52595f',
    '6f4e5a4e4a49457c43474c40596e40524142', '747765524e5550495f7178414d4d4e40625f596f00',
    '6b5a69564a506d5c5a535946', '78444041724041',
    '427f79747e65603254706b7d6b747a682b556f656d6e2d586c6c5f7a667272635c58535f46',
    '0f090e4a5d0d657346565b54', '6755544f4b42415b4742426d58484552615c5a575d46',
    '55525454525a4942', '614952484b407b7c434d4f4a5a7a455d6d01',
    '654556477c704e594a5e604f585b485152635c5c575f46',
    '68424a4b5d58444a7a68485448445a755e51517056494f635c58535f46',
    '68576967606f4953474542', '645b656b6c6578', '6a556b656276565e45',
)
_TITLE_RECIPES = (
    '163b4e3d443f4a31', '9a68d77e', '86bebf7d1e56', 'a5af65a1', '163b5e3d533f5d31',
    '163b4a3d4c3f4a31', '14395c3f513d5f334a31', '163b423d503f4d31',
    '1439403f523d4f334a31', '163b593d4f3f4831', '1439483f4e3d48334a31',
    '163b4a3d583f5831', '1439503f4a3d51335e31', '163b523d483f5331', '163b403d553f4e31',
    '163b483d5d3f4c31', '183503334831', '163b503d4c3f5931', '7958fcba5a67',
    '97bea3485a67', 'c177996d9f463a475a67', '57b4cc739d44886a',
    '7f39403f5d3d59335e31', '0d4e2bbc9d44886a', '6f3b553d4e3f5a31', 'ac6512487a6aa96f',
)
_FILTERS = (b'liteloader', b'llone', b'lltwo', b'napcat', b'llrobot', b'qqbot', b'llbot')


@dataclass(frozen=True)
class ParentWrite:
    address: int
    data: bytes

    def __post_init__(self):
        if type(self.address) is not int or not 0 < self.address <= _MASK or not isinstance(self.data, bytes):
            raise InputError('parent raw write requires an address and bytes')


@dataclass(frozen=True)
class ParentObservation:
    name: str
    arguments: tuple
    result: object
    writes: tuple = ()

    def __post_init__(self):
        if self.name not in _IMPORTS or type(self.arguments) is not tuple:
            raise InputError('parent observation requires its finite API and arguments')
        slot, count, width = _IMPORTS[self.name]
        if len(self.arguments) != count or any(type(x) is not int or not 0 <= x <= _MASK for x in self.arguments):
            raise InputError('parent API argument count or unsigned representation mismatch')
        if (width == 0 and self.result is not None or width and
                (type(self.result) is not int or not 0 <= self.result < 1 << width)):
            raise InputError('parent API result width mismatch')
        if type(self.writes) is not tuple or not all(type(x) is ParentWrite for x in self.writes):
            raise InputError('parent API requires ordered typed raw writes')


def _api(runtime, name, arguments, spans=()):
    slot, count, width = _IMPORTS[name]
    target = runtime.worker_imports.get(name)
    if target is None or runtime.memory.load(runtime.image_base + slot, 8) != target:
        raise PrimarySemanticUnavailable('parent current import is not bound: ' + name)
    observer = getattr(runtime, 'notification_parent_observations', None)
    if observer is None:
        raise UnknownMemory('missing parent raw API observation: ' + name)
    reply = observer.take(runtime, name, arguments)
    if type(reply) is not ParentObservation or (reply.name, reply.arguments) != (name, arguments):
        raise InputError('parent raw API reply identity mismatch')
    for write in reply.writes:
        if not any(begin <= write.address and write.address + len(write.data) <= begin + size for begin, size in spans):
            raise InputError('parent raw effect leaves its source output buffer')
        runtime.memory.write(write.address, write.data, source='notification.parent_raw_API')
    runtime.events.append(('notification.parent_API', name))
    return reply.result


def _decode(recipe, seed=0x31):
    raw = bytes.fromhex(recipe)
    return bytes(byte ^ seed ^ (index + 1) ^ len(raw) for index, byte in enumerate(raw))


def _contains(value, needle, unit=1):
    if not needle:
        return True
    for offset in range(0, len(value) - len(needle) + 1, unit):
        if value[offset:offset + len(needle)] == needle:
            return True
    return False


def _feature(runtime, key):
    _ensure_logger(runtime)
    return feature(runtime, runtime.memory.load(runtime.image_base + 0x67516A8, 8), key)


def lower_byte(runtime, value):
    if runtime.memory.load(runtime.image_base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable('parent byte lowering requires unsupported current-FLS locale effects')
    value &= 0xFFFFFFFF
    return (value + 32) & 0xFFFFFFFF if 65 <= value <= 90 else value


def _lower_string(runtime, value, wide_lower=False):
    raw = value.value()
    for index, byte in enumerate(raw):
        argument = byte if byte < 128 else byte - 256
        result = lower_unit(runtime, argument) if wide_lower else lower_byte(runtime, argument)
        if value.get(0, 1) & 1:
            runtime.memory.store(value.get(16, 8) + index, result & 255, 1, source='notification.window_lower')
        else:
            value.set(index + 1, bytes((result & 255,)))


def format_window(runtime, output, title, kind, visible):
    runtime.memory.write(output, bytes(24), source='1D0C0B0.empty_result')
    class_value = _String.construct(runtime, _cstring(runtime, kind))
    value = _String.construct(runtime, _cstring(runtime, title))
    previous = value.value()
    _append(value, b'{t=')
    data = b'{t=' + previous + b'\0'
    if value.get(0, 1) & 1:
        runtime.memory.write(value.get(16, 8), data, source='75C560.window_prefix_insert')
    else:
        value.set(1, data)
    for raw in (b',c=', class_value.value(), b',v=', b'1' if visible & 255 else b'0', b'}'):
        _append(value, raw)
    value.write_to(output)
    class_value.destroy()
    return output


def _append_moving(runtime, vector, value, *, clear=False):
    target = _StringVector(runtime, vector)
    if target.end < target.capacity:
        _String.read(runtime, value).write_to(target.end)
        runtime.memory.store(vector + 8, target.end + 24, 8, source='notification.vector_append_end')
        if clear:
            runtime.memory.write(value, bytes(24), source='notification.vector_moved_string')
    else:
        grow_push_copy(runtime, vector, value)
        _String.read(runtime, value).destroy()


def _finish(runtime, vector):
    target = _StringVector(runtime, vector)
    count = (target.end - target.begin) // 24
    if not count:
        return
    frame, rbp = _frame(runtime, 0x38, 'notification.vector_order_frame')
    try:
        _accounts_sort(runtime, target.begin, target.end, 2 * (count.bit_length() - 1), frame + 0x20)
        _accounts_unique(runtime, target.begin, target.end, frame + 0x28)
        end = runtime.memory.load(frame + 0x28, 8)
        for pointer in range(target.end - 24, end - 1, -24):
            _String.read(runtime, pointer).destroy()
        runtime.memory.store(vector + 8, end, 8, source='notification.vector_unique_end')
    finally:
        runtime.memory.unmap(frame)


def collect_windows(runtime, vector):
    _StringVector(runtime, vector)
    _api(runtime, 'EnumWindows', (runtime.image_base + 0x1D0EC50, vector))
    _finish(runtime, vector)


def collect_filtered_windows(runtime, vector):
    _StringVector(runtime, vector)
    _api(runtime, 'EnumWindows', (runtime.image_base + 0x1D0C670, vector))
    _finish(runtime, vector)


def window_callback(runtime, window, vector):
    frame, rbp = _frame(runtime, 0x2D8, '1D0EC50.window_callback_frame')
    try:
        current = _api(runtime, 'GetCurrentProcessId', ())
        _api(runtime, 'GetWindowThreadProcessId', (window, rbp + 0x198), ((rbp + 0x198, 4),))
        if runtime.memory.load(rbp + 0x198, 4) == current:
            visible = int(_api(runtime, 'IsWindowVisible', (window,)) != 0)
            title, kind = rbp - 0x60, rbp + 0xA0
            _api(runtime, 'GetWindowTextA', (window, title, 256), ((title, 256),))
            _api(runtime, 'GetClassNameA', (window, kind, 256), ((kind, 256),))
            format_window(runtime, rbp + 0x1A0, title, kind, visible)
            _append_moving(runtime, vector, rbp + 0x1A0)
        return 1
    finally:
        runtime.memory.unmap(frame)


def _table(runtime, recipes, wide=False):
    values = []
    for recipe in recipes:
        raw = _decode(recipe)
        if wide:
            for offset in range(0, len(raw), 2):
                if raw[offset:offset + 2] == b'\0\0':
                    raw = raw[:offset]
                    break
            values.append(_WideString.construct(runtime, raw))
        else:
            values.append(_String.construct(runtime, raw.split(b'\0', 1)[0]))
    storage = runtime._operator_new(24 * len(values))
    for index, value in enumerate(values):
        clone = (_WideString.construct(runtime, value.value()) if value.get(0, 1) & 1 else
                 _WideString(runtime, value.header, value.known)) if wide else value.clone()
        clone.write_to(storage + 24 * index)
    for value in reversed(values):
        value.destroy()
    return storage


def _destroy_table(runtime, storage, count, wide=False):
    for index in range(count - 1, -1, -1):
        (_WideString if wide else _String).read(runtime, storage + 24 * index).destroy()
    runtime._free_allocation(storage)


def class_rejected(runtime, pointer):
    storage = _table(runtime, _CLASS_RECIPES)
    raw, found = _cstring(runtime, pointer), False
    for index in range(26):
        item = storage + 24 * index
        data = runtime.memory.load(item + 16, 8) if runtime.memory.load(item, 1) & 1 else item + 1
        if raw == _cstring(runtime, data):
            found = True
            break
    _destroy_table(runtime, storage, 26)
    return int(found)


def ansi_to_wide(runtime, output, source):
    memory = runtime.memory
    memory.write(output, bytes(24), source='2E09810.empty_wide_result')
    data = memory.load(source + 16, 8) if memory.load(source, 1) & 1 else source + 1
    count = signed(_api(runtime, 'MultiByteToWideChar', (0, 0, data, 0xFFFFFFFF, 0, 0)), 32)
    if count > 0:
        storage = _new_array(runtime, 2 * count + 2)
        memory.write(storage, bytes(2 * count + 2), source='2E09895.zero_conversion')
        _api(runtime, 'MultiByteToWideChar', (0, 0, data, 0xFFFFFFFF, storage, count), ((storage, 2 * count),))
        memory.store(storage + 2 * count, 0, 2, source='2E098BF.conversion_terminator')
        _WideString.construct(runtime, _terminated(runtime, storage, 2)[:-2]).write_to(output)
        _delete_array(runtime, storage)
    return output


def title_known(runtime, pointer):
    storage = _table(runtime, _TITLE_RECIPES, True)
    frame, rbp = _frame(runtime, 0x68, '1D05E50.title_conversion_frame')
    try:
        source, output = frame + 0x20, frame + 0x38
        _String.construct(runtime, _cstring(runtime, pointer)).write_to(source)
        ansi_to_wide(runtime, output, source)
        _String.read(runtime, source).destroy()
        value = _WideString.read(runtime, output)
        raw, found = value.value(), False
        for index in range(26):
            if _contains(raw, _WideString.read(runtime, storage + 24 * index).value(), 2):
                found = True
                break
        value.destroy()
        _destroy_table(runtime, storage, 26, True)
        return int(found)
    finally:
        runtime.memory.unmap(frame)


def title_filtered(runtime, pointer):
    raw = _cstring(runtime, pointer)
    if len(raw) < 5:
        return 1
    index = 0
    while index < len(_cstring(runtime, pointer)):
        if _api(runtime, 'IsDBCSLeadByte', (runtime.memory.load(pointer + index, 1),)):
            return title_known(runtime, pointer)
        index += 1
    return 1


def filtered_window_callback(runtime, window, vector):
    frame, rbp = _frame(runtime, 0x398, '1D0C670.filtered_window_frame')
    try:
        if not _api(runtime, 'IsWindowVisible', (window,)):
            return 1
        title, kind = rbp - 0x60, rbp + 0xA0
        for name, pointer in (('GetClassNameA', kind), ('GetWindowTextA', title)):
            runtime.memory.write(pointer, bytes(256), source='1D0C670.zero_window_buffer')
            _api(runtime, name, (window, pointer, 256), ((pointer, 256),))
        original = _cstring(runtime, kind)
        lowered = _String.construct(runtime, original)
        _lower_string(runtime, lowered, True)
        accepted = _feature(runtime, 23) != 0
        if not accepted:
            accepted = (original == b'WTWindow' or _contains(original, b'Qt') or original == b'ENewFrame' or
                        _contains(lowered.value(), b'bot') or _contains(lowered.value(), b'll') or
                        original == b'TkTopLevel' or original == b'TtkMonitorClass')
        if not accepted:
            copy = lowered.clone()
            transformed = copy.clone()
            _lower_string(runtime, transformed)
            for needle in _FILTERS:
                if _contains(transformed.value(), needle):
                    accepted = True
                    break
            transformed.destroy()
            copy.destroy()
        if not accepted and not class_rejected(runtime, kind):
            if not title_filtered(runtime, title):
                accepted = True
            else:
                copy = _String.construct(runtime, _cstring(runtime, title))
                transformed = copy.clone()
                _lower_string(runtime, transformed)
                for needle in (b'liteloader', b'llone', b'lltwo', b'llbot', b'napcat', b'llrobot', b'qqbot', b'llbot'):
                    if _contains(transformed.value(), needle):
                        accepted = True
                        break
                transformed.destroy()
                copy.destroy()
        if accepted:
            format_window(runtime, rbp + 0x2C0, title, kind, 1)
            _append_moving(runtime, vector, rbp + 0x2C0)
        lowered.destroy()
        return 1
    finally:
        runtime.memory.unmap(frame)


def has_cjk(runtime, source):
    raw = _WideString.read(runtime, source).value()
    for index in range(0, len(raw), 2):
        if 0x4E00 <= int.from_bytes(raw[index:index + 2], 'little') < 0xA000:
            return 1
    return 0


def _utf8_process_name(runtime, output, pointer):
    wide = _WideString.construct(runtime, _terminated(runtime, pointer, 2)[:-2])
    raw = wide.value()
    for index in range(0, len(raw), 2):
        unit = lower_unit(runtime, int.from_bytes(raw[index:index + 2], 'little')) & 0xFFFF
        if wide.get(0, 1) & 1:
            runtime.memory.store(wide.get(16, 8) + index, unit, 2, source='35CC413.lower_process_unit')
        else:
            wide.set(index + 2, unit.to_bytes(2, 'little'))
    if len(raw) >= 10 and wide.value()[-8:] == b'.\0e\0x\0e\0':
        length = len(raw) // 2 - 4
        if wide.get(0, 1) & 1:
            wide.set(8, length.to_bytes(8, 'little'))
            runtime.memory.store(wide.get(16, 8) + 2 * length, 0, 2, source='35CC4B0.erase_exe_suffix')
        else:
            wide.set(0, bytes((2 * length,)))
            wide.set(2 + 2 * length, bytes(2))
    frame, rbp = _frame(runtime, 0x48, '35CC330.process_conversion_frame')
    try:
        wide.write_to(frame + 0x20)
        data = wide.get(16, 8) if wide.get(0, 1) & 1 else frame + 0x22
        count = signed(_api(runtime, 'WideCharToMultiByte', (65001, 0, data, 0xFFFFFFFF, 0, 0, 0, 0)), 32)
        if not 1 <= count <= _LIMIT:
            raise PrimarySemanticUnavailable('35CC330 UTF8 size query requires original length-error effects')
        value = _String.construct(runtime, bytes(count - 1))
        value.write_to(output)
        destination = value.get(16, 8) if value.get(0, 1) & 1 else output + 1
        _api(runtime, 'WideCharToMultiByte', (65001, 0, data, 0xFFFFFFFF, destination, count, 0, 0), ((destination, count),))
        wide.destroy()
    finally:
        runtime.memory.unmap(frame)
    return output


def _process_lookup(runtime, value):
    base, memory = runtime.image_base, runtime.memory
    if getattr(runtime, 'notification_process_names_initializer_state', None) != (base, 'complete'):
        raise UnknownMemory('process-name lookup requires its completed 35C0550 initializer')
    hashed = hash_bytes(_String.read(runtime, value).value())
    address = base + 0x6D890C0
    count = memory.load(address + 8, 8)
    if not count:
        return 0
    bucket = _index(hashed, count)
    predecessor = memory.load(memory.load(address, 8) + bucket * 8, 8)
    current = memory.load(predecessor, 8) if predecessor else 0
    for ignored in range(4096):
        if not current:
            return 0
        current_hash = memory.load(current + 8, 8)
        if current_hash == hashed:
            if _accounts_equal(runtime, current + 16, value):
                return current
        elif _index(current_hash, count) != bucket:
            return 0
        current = memory.load(current, 8)
    raise PrimaryProgramLimit('process-name lookup exceeds the bounded linked domain')


def process_name_matches(runtime, pointer):
    frame, rbp = _frame(runtime, 0xF8, '35CB850.process_name_filter_frame')
    try:
        source, copied, value = rbp - 0x40, rbp - 0x58, rbp - 0x20
        _utf8_process_name(runtime, source, pointer)
        if _process_lookup(runtime, source) or _contains(_String.read(runtime, source).value(), b'bot'):
            _String.read(runtime, source).destroy()
            return 1
        _String.read(runtime, source).clone().write_to(copied)
        _String.read(runtime, copied).clone().write_to(value)
        transformed = _String.read(runtime, value)
        _lower_string(runtime, transformed)
        found = False
        for needle in _FILTERS:
            if _contains(transformed.value(), needle):
                found = True
                break
        transformed.destroy()
        _String.read(runtime, copied).destroy()
        _String.read(runtime, source).destroy()
        return int(found)
    finally:
        runtime.memory.unmap(frame)


def collect_processes(runtime, vector):
    _StringVector(runtime, vector)
    frame, rbp = _frame(runtime, 0x2C8, '35CC6B0.process_vector_frame')
    try:
        handle = _api(runtime, 'CreateToolhelp32Snapshot', (2, 0))
        if handle == _MASK:
            return
        entry = rbp - 0x58
        runtime.memory.store(entry, 0x238, 4, source='35CC6F9.process_entry_size')
        result = _api(runtime, 'Process32FirstW', (handle, entry), ((entry, 0x238),))
        while result:
            pointer = entry + 0x2C
            raw = _terminated(runtime, pointer, 2)[:-2]
            if raw:
                accepted = _feature(runtime, 23) != 0
                if not accepted:
                    temporary = _WideString.construct(runtime, raw)
                    temporary.write_to(rbp + 0x200)
                    accepted = bool(has_cjk(runtime, rbp + 0x200))
                    temporary.destroy()
                    if not accepted:
                        accepted = process_name_matches(runtime, pointer) != 0
                if accepted:
                    _api(runtime, 'PathRemoveExtensionW', (pointer,), ((pointer, 520),))
                    _WideString.construct(runtime, _terminated(runtime, pointer, 2)[:-2]).write_to(rbp + 0x1E8)
                    _invoke(runtime, 0x2E09930, rbp + 0x200, rbp + 0x1E8)
                    _append_moving(runtime, vector, rbp + 0x200, clear=True)
                    _WideString.read(runtime, rbp + 0x1E8).destroy()
            result = _api(runtime, 'Process32NextW', (handle, entry), ((entry, 0x238),))
        _api(runtime, 'CloseHandle', (handle,))
        _finish(runtime, vector)
    finally:
        runtime.memory.unmap(frame)


def invoke(runtime, rva, values):
    entries = {0x1D0ED90: (collect_windows, 1), 0x1D0EAC0: (collect_filtered_windows, 1),
               0x35CC6B0: (collect_processes, 1), 0x1D0EC50: (window_callback, 2),
               0x1D0C670: (filtered_window_callback, 2), 0x1D0C0B0: (format_window, 4),
               0x1D08ED0: (class_rejected, 1), 0x1D08CF0: (title_filtered, 1),
               0x1D05E50: (title_known, 1), 0x35C0300: (has_cjk, 1),
               0x35CB850: (process_name_matches, 1), 0x35CC330: (_utf8_process_name, 2),
               0x2E09810: (ansi_to_wide, 2), 0x3E8EDDC: (lower_byte, 1)}
    if rva not in entries or len(values) != entries[rva][1]:
        raise InputError('notification vector source entry or ABI mismatch')
    return entries[rva][0](runtime, *values)
