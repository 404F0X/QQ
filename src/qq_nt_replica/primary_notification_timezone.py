from .errors import InputError
from .primary_logger import _String, _cstring
from .primary_memory import UnknownMemory
from .primary_notification_collectors import wide_to_utf8
from .primary_notification_environment import _output, _terminated
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import _WideString
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame, _image as _response_image, _owner


_MARKER = 0x6D86AA4
_INITIAL = bytes.fromhex('0108756b6e617f69696d0000')
_IMPORTS = {'GetTimeZoneInformation': 0x4910000}


def install_image(memory, base):
    address = base + _MARKER
    overlaps = [region for region in memory._region_snapshot()
                if address < region.address + len(region.data) and region.address < address + 12]
    if not overlaps:
        memory.map(address, bytearray(12), name='timezone name PE zero fill', initialized=True)
    else:
        memory._span(address, 12)


def initialize_name(runtime):
    if getattr(runtime, 'notification_timezone_name_initialized', None) is not None:
        raise InputError('timezone name initializer lifecycle is already declared')
    marker = runtime.image_base + _MARKER
    for index, value in enumerate(_INITIAL):
        runtime.memory.store(marker + index, value, 1,
                             source=f'{0x2E10414 + index * 7:X}.timezone_name_initializer')
    runtime.notification_timezone_name_initialized = marker


def _name(runtime):
    memory, marker = runtime.memory, runtime.image_base + _MARKER
    if getattr(runtime, 'notification_timezone_name_initialized', None) != marker:
        raise PrimarySemanticUnavailable('timezone source initializer lifecycle is not qualified')
    if memory.load(marker, 1) & 1:
        if memory.read(marker, 12) != _INITIAL:
            raise PrimarySemanticUnavailable('timezone name marker differs from source initializer')
        for index in range(8):
            value = memory.load(marker + index + 2, 1)
            seed = memory.load(marker + 1, 1)
            memory.store(marker + index + 2, value ^ (index + 1) ^ seed ^ 8, 1,
                         source='2E0F68B.timezone_name_decode')
        memory.write(marker + 10, bytes(2), source='2E0F6A7.timezone_name_terminators')
        memory.store(marker, 0, 1, source='2E0F6B5.timezone_name_decoded')
    return _cstring(runtime, marker + 2)


def _timezone_api(runtime, destination):
    memory = runtime.memory
    expected = runtime.worker_imports.get('GetTimeZoneInformation')
    if expected is None or memory.load(runtime.image_base + _IMPORTS['GetTimeZoneInformation'], 8) != expected:
        raise PrimarySemanticUnavailable('timezone current import is not bound: GetTimeZoneInformation')
    observer = getattr(runtime, 'notification_environment_observations', None)
    if observer is None:
        observer = runtime.worker_observations
    if observer is None:
        raise UnknownMemory('missing timezone raw API observation: GetTimeZoneInformation')
    result, raw = observer.take(runtime, 'GetTimeZoneInformation', (172,))
    if type(result) is not int or not 0 <= result < 1 << 64:
        raise InputError('timezone raw API result requires unsigned pointer-width storage')
    _output(runtime, destination, raw, 172)
    return result & 0xFFFFFFFF


def _move(runtime, destination, source):
    _String.read(runtime, destination).destroy()
    _String.read(runtime, source).write_to(destination)
    runtime.memory.store(source, 0, 2, source='2E0F901.timezone_moved_temporary')


def collect(runtime):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x2F8, '2E0F5F0.timezone_frame')
    event, converted, wide = rbp + 0x68, rbp + 0x220, rbp + 0x258
    record_ready = False
    wide_ready = False
    converted_ready = False
    metadata_ready = False
    try:
        memory.store(rbp + 0x270, (1 << 64) - 2, 8, source='2E0F607.timezone_frame_sentinel')
        if _timezone_api(runtime, rbp - 0x48) == 0xFFFFFFFF:
            return
        temporary = _String.construct(runtime, _name(runtime))
        temporary.write_to(rbp + 0x208)
        temporary.clone().write_to(event + 8)
        for offset in range(32, 200, 24):
            memory.store(event + offset, 0, 2, source='2E0F778.timezone_empty_base_field')
        memory.write(event + 200, bytes(24), source='2E0F7B7.timezone_base_vector')
        memory.store(event, base + 0x41498D8, 8, source='2E0F7D0.timezone_event_vtable')
        memory.write(event + 224, bytes(168), source='2E0F7D4.timezone_empty_columns')
        record_ready = True
        temporary.destroy()
        for source, destination, remaining in ((rbp - 0x44, event + 224, 84),
                                                (rbp + 0x10, event + 248, 42)):
            value = _WideString.construct(runtime, _terminated(runtime, source, remaining))
            value.write_header(wide)
            wide_ready = True
            wide_to_utf8(runtime, converted, wide)
            converted_ready = True
            _move(runtime, destination, converted)
            converted_ready = False
            value.destroy()
            wide_ready = False
        _owner(runtime, _response_image())
        memory.store(wide, 0, 2, source='2E0FA08.timezone_empty_metadata_second')
        memory.store(rbp + 0x1F0, 0, 2, source='2E0FA11.timezone_empty_metadata_first')
        memory.write(converted, bytes(48), source='2E0FA1D.timezone_metadata_pair')
        _String.read(runtime, rbp + 0x1F0).clone().write_to(converted)
        _String.read(runtime, wide).clone().write_to(converted + 24)
        metadata_ready = True
        _invoke(runtime, 0x1BEFC10, base + 0x67519B8, event, converted, 1, 10, 0)
        for address in (converted + 24, converted, rbp + 0x1F0, wide):
            _String.read(runtime, address).destroy()
        metadata_ready = False
        record_ready = False
        _invoke(runtime, 0x1C2D0F0, event)
    except BaseException as primary:
        try:
            if converted_ready:
                _String.read(runtime, converted).destroy()
            if wide_ready:
                _WideString(runtime, address=wide).destroy()
            if metadata_ready:
                for address in (converted + 24, converted, rbp + 0x1F0, wide):
                    _String.read(runtime, address).destroy()
            if record_ready:
                record_ready = False
                _invoke(runtime, 0x1C2D0F0, event)
        except BaseException as cleanup:
            raise primary from cleanup
        raise
    finally:
        memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva != 0x2E0F5F0 or values:
        raise InputError('timezone collector requires its source entry and zero logical arguments')
    return collect(runtime)
