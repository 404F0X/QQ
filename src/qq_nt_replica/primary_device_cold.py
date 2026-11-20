import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_collector import _terminated
from .primary_logger import _cstring, _format, _String, log
from .primary_memory import PrimaryMemoryLimit, UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = 'b21264ac06c8a16c1220ab76444ac2793281b8d72de1bee1842ef40a9be6fe14'
_IMPORTS = {'CoInitializeEx': 0x4910850, 'CoCreateInstance': 0x4910830,
            'SysAllocString': 0x49108C8, 'SysFreeString': 0x49108E0,
            'CoSetProxyBlanket': 0x4910860, 'CoUninitialize': 0x4910880,
            'GetNativeSystemInfo': 0x490FF18, 'EnumDisplaySettingsW': 0x4910518,
            'GetSystemMetrics': 0x49105D0, 'GetKeyboardType': 0x49105B0,
            'IsDebuggerPresent': 0x4910120, 'GetSystemDefaultLCID': 0x490FF78,
            'GetSystemInfo': 0x490FFA0}
_FINALIZE_IMPORTS = {'CallNtPowerInformation': 0x49111D8}
_MASK64 = (1 << 64) - 1


def _image():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'device-cold-image.json'
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device cold collector image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device cold collector import identity mismatch')
    return image


def install_image(memory, image_base):
    for segment in _image()['segments']:
        memory.map(image_base + segment['rva'], bytearray.fromhex(segment['hex']),
                   name='fixed device cold collector image', initialized=True)


def _observe(runtime, name, arguments):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + (_IMPORTS | _FINALIZE_IMPORTS)[name], 8) != expected:
        raise PrimarySemanticUnavailable('device cold collector current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device cold collector OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _plain(runtime, name, arguments):
    result, effects = _observe(runtime, name, arguments)
    if effects != b'':
        raise InputError('device cold collector operation has no output buffer: ' + name)
    return result & 0xFFFFFFFF


def _output(runtime, address, effects, capacity, source):
    if isinstance(effects, tuple) and len(effects) == 1 and isinstance(effects[0], tuple) and len(effects[0]) == 2:
        raw, known = effects[0]
        if (not isinstance(raw, bytes) or not isinstance(known, bytes) or len(raw) != len(known) or
                len(raw) > capacity or any(value not in (0, 1) for value in known)):
            raise InputError('cold collector requires bounded sparse output: ' + source)
        start = 0
        while start < len(raw):
            if not known[start]:
                start += 1
                continue
            end = start + 1
            while end < len(raw) and known[end]:
                end += 1
            runtime.memory.write(address + start, raw[start:end], source=source)
            start = end
    else:
        if not isinstance(effects, bytes) or len(effects) > capacity:
            raise InputError('cold collector requires bounded raw output: ' + source)
        if effects:
            runtime.memory.write(address, effects, source=source)


def _foreign_output(runtime, effects):
    if not isinstance(effects, tuple) or len(effects) != 2:
        raise InputError('device COM output requires a pointer and explicit foreign memory images')
    pointer, images = effects
    if type(pointer) is not int or not 0 <= pointer <= _MASK64 or not isinstance(images, tuple) or len(images) > 32:
        raise InputError('device COM output requires a bounded unsigned pointer and foreign images')
    for address, raw in images:
        if (type(address) is not int or not 0 < address <= _MASK64 or not isinstance(raw, bytes)
                or not 0 < len(raw) <= 4096 or address + len(raw) > 1 << 64):
            raise InputError('device COM foreign image requires a bounded address and raw bytes')
        try:
            runtime.memory._span(address, len(raw))
        except PrimaryMemoryLimit:
            runtime.memory.map(address, bytearray(raw), name='observed device COM foreign memory', initialized=True)
        else:
            runtime.memory.write(address, raw, source='device.COM_output')
    return pointer


def _com(runtime, receiver, slot, name, arguments):
    target = runtime.memory.load(runtime.memory.load(receiver, 8) + slot, 8)
    if not target or runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('device COM current virtual target or OS observations are missing: ' + name)
    return runtime.worker_observations.take(runtime, name, (target, receiver, *arguments))


def _release(runtime, receiver):
    result, effects = _com(runtime, receiver, 16, 'IUnknown.Release', ())
    if effects != b'':
        raise InputError('device COM Release requires its explicit empty output effects')
    return result & 0xFFFFFFFF


def _log(runtime, line, *values):
    item = _image()['logs'][str(line)]
    runtime.events.append(('device.cold_log', line))
    return log(runtime, bytes.fromhex(item['source_file_hex']), line,
               bytes.fromhex(item['template_hex']), bytes.fromhex(item['tag_hex']), item['severity'], *values)


def connect_wmi(runtime):
    memory, base, image = runtime.memory, runtime.image_base, _image()
    frame, rbp = _frame(runtime, 0x120, '2E123C0.WMI_connection_frame')
    initialized = _plain(runtime, 'CoInitializeEx', (0, 0))
    _log(runtime, 44, initialized)
    memory.store(rbp - 0x38, 0, 8, source='2E1274A.empty_WMI_locator')
    result, effects = _observe(runtime, 'CoCreateInstance',
                               (memory.read(base + image['class_rva'], 16), 0, 1,
                                memory.read(base + image['interface_rva'], 16)))
    locator = _foreign_output(runtime, effects)
    memory.store(rbp - 0x38, locator, 8, source='2E12771.WMI_locator_output')
    if result & 0x80000000:
        _log(runtime, 63, result & 0xFFFFFFFF)
        _plain(runtime, 'CoUninitialize', ())
        memory.unmap(frame)
        return 0
    memory.store(rbp - 0x30, 0, 8, source='2E1277F.empty_WMI_services')
    wrapper = runtime._operator_new(24)
    memory.store(wrapper + 8, 0, 8, source='2E12795.BSTR_empty_ansi')
    memory.store(wrapper + 16, 1, 4, source='2E127A1.BSTR_refcount')
    namespace = _terminated(runtime, base + image['namespace_rva'], 2)
    bstr, raw = _observe(runtime, 'SysAllocString', (namespace,))
    if not isinstance(raw, bytes) or len(raw) > 4096 or type(bstr) is not int or not 0 <= bstr <= _MASK64:
        raise InputError('device BSTR requires an unsigned pointer and bounded raw UTF16 output')
    memory.store(wrapper, bstr, 8, source='2E127B9.BSTR_pointer')
    if not bstr:
        raise PrimarySemanticUnavailable('2E13749 actual BSTR allocation failure requires COM exception effects')
    if not raw:
        raise UnknownMemory('successful device BSTR allocation requires its actual character bytes')
    memory.map(bstr, bytearray(raw), name='observed device BSTR buffer', initialized=True)
    result, effects = _com(runtime, locator, 24, 'IWbemLocator.ConnectServer',
                           (bstr, 0, 0, 0, 0, 0, 0))
    services = _foreign_output(runtime, effects)
    memory.store(rbp - 0x30, services, 8, source='2E127FA.WMI_services_output')
    references = (memory.load(wrapper + 16, 4) - 1) & 0xFFFFFFFF
    memory.store(wrapper + 16, references, 4, source='2E12802.BSTR_release')
    if references == 0:
        current = memory.load(wrapper, 8)
        if current:
            _plain(runtime, 'SysFreeString', (current,))
            memory.unmap(current)
            memory.store(wrapper, 0, 8, source='2E12817.BSTR_cleared')
        if memory.load(wrapper + 8, 8):
            raise PrimarySemanticUnavailable('device BSTR cached ANSI ownership requires its actual array effects')
        runtime._free_allocation(wrapper)
    _release(runtime, memory.load(rbp - 0x38, 8))
    if result & 0x80000000:
        _log(runtime, 72, result & 0xFFFFFFFF)
        _plain(runtime, 'CoUninitialize', ())
        memory.unmap(frame)
        return 0
    services = memory.load(rbp - 0x30, 8)
    result = _plain(runtime, 'CoSetProxyBlanket', (services, 10, 0, 0, 3, 3, 0, 0))
    if result & 0x80000000:
        _log(runtime, 80, result)
        _release(runtime, memory.load(rbp - 0x30, 8))
        _plain(runtime, 'CoUninitialize', ())
        memory.unmap(frame)
        return 0
    _log(runtime, 85)
    services = memory.load(rbp - 0x30, 8)
    memory.unmap(frame)
    return services


def cleanup_wmi(runtime, receiver):
    _log(runtime, 90)
    if receiver:
        _release(runtime, receiver)
    _plain(runtime, 'CoUninitialize', ())


def architecture(runtime):
    frame, rbp = _frame(runtime, 0x60, '1BEE390.system_architecture_frame')
    runtime.memory.write(frame + 0x20, bytes(48), source='1BEE3A4.zero_SYSTEM_INFO')
    ignored, effects = _observe(runtime, 'GetNativeSystemInfo', ())
    if isinstance(effects, tuple) and len(effects) == 1 and isinstance(effects[0], tuple) and len(effects[0]) == 2:
        raw, known = effects[0]
        if (not isinstance(raw, bytes) or not isinstance(known, bytes) or len(raw) != len(known) or
                len(raw) > 48 or any(value not in (0, 1) for value in known)):
            raise InputError('device architecture requires bounded SYSTEM_INFO known-mask output')
        for index in range(min(2, len(raw))):
            if known[index]:
                runtime.memory.write(frame + 0x20 + index, raw[index:index + 1], source='1BEE3BB.SYSTEM_INFO_output')
    else:
        if not isinstance(effects, bytes) or len(effects) > 48:
            raise InputError('device architecture requires bounded SYSTEM_INFO output')
        runtime.memory.write(frame + 0x20, effects, source='1BEE3BB.SYSTEM_INFO_output')
    value = runtime.memory.load(frame + 0x20, 2)
    result = 4
    if value <= 12:
        table = runtime.image_base + _image()['architecture_table_rva']
        offset = runtime.memory.load(table + 4 * value, 4)
        offset -= (offset & 0x80000000) << 1
        targets = {0x1BEE3F8: 0, 0x1BEE3DE: 2, 0x1BEE3EC: 1, 0x1BEE3F3: 3, 0x1BEE3E5: 4}
        target = table + offset - runtime.image_base
        if target not in targets:
            raise PrimarySemanticUnavailable('device architecture current jump target is outside recovered cases')
        result = targets[target]
    runtime.memory.unmap(frame)
    return result


def cpu_identifier(runtime, destination):
    if runtime.worker_observations is None:
        raise UnknownMemory('device CPU identifier requires CPUID leaf1 observations')
    ignored, registers = runtime.worker_observations.take(runtime, 'CPUID', (1,))
    if (not isinstance(registers, tuple) or len(registers) != 4 or
            any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in registers)):
        raise InputError('device CPUID requires four explicit DWORD register outputs')
    raw = _format(runtime, _cstring(runtime, runtime.image_base + _image()['cpu_format_rva']),
                  (registers[3], registers[0]))
    if len(raw) >= 260:
        raise PrimarySemanticUnavailable('device CPU identifier current format exceeds its bounded stack buffer')
    value = _String.construct(runtime, raw)
    for index, known in enumerate(value.known):
        if known:
            runtime.memory.write(destination + index, bytes([value.header[index]]),
                                 source='2E15CA0.construct_CPU_identifier')
    return destination


def _display_maxima(environment):
    width, height = 0, 0
    for index in range(4096):
        result, current_width, current_height = environment.sample(index)
        if not result:
            break
        width = max(width, current_width)
        height = max(height, current_height)
    else:
        raise PrimaryProgramLimit('device display enumeration exceeds the bounded offline domain')
    return width, height


def _independent_display(runtime, owner):
    from .primary_windows_display_environment import WindowsDisplayEnvironment
    with WindowsDisplayEnvironment() as environment:
        width, height = _display_maxima(environment)
    memory = runtime.memory
    memory.store(owner + 0x460, width, 4, source='2E241E8.display_width')
    memory.store(owner + 0x464, height, 4, source='2E241F2.display_height')
    first = _plain(runtime, 'GetSystemMetrics', (0,))
    second = _plain(runtime, 'GetSystemMetrics', (1,))
    memory.store(owner + 0x58, first, 4, source='2E2420C.screen_width')
    memory.store(owner + 0x5C, second, 4, source='2E2420F.screen_height')


def display(runtime, owner):
    from .primary_device_provider import DeviceFactory
    factory = getattr(getattr(runtime, 'provider_profile', None), 'device_factory', None)
    if factory is not None:
        if not isinstance(factory, DeviceFactory):
            raise InputError('display environment requires the configured device factory')
        if factory.display_environment == 'independent_windows':
            return _independent_display(runtime, owner)
        if factory.display_environment != 'source_frame':
            raise InputError('display environment selection is outside the explicit supported modes')
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x128, '2E24080.display_modes_frame')
    width, height = 0, 0
    for index in range(4096):
        region, offset = memory._span(frame + 0x40, 220)
        preimage = bytes(region.data[offset:offset + 220]), bytes(region.initialized[offset:offset + 220])
        result, effects = _observe(runtime, 'EnumDisplaySettingsW', (0, index, preimage))
        _output(runtime, frame + 0x40, effects, 220, '2E24106.DEVMODEW_output')
        if not result & 0xFFFFFFFF:
            break
        width = max(width, memory.load(frame + 0xEC, 4))
        height = max(height, memory.load(frame + 0xF0, 4))
    else:
        raise PrimaryProgramLimit('device display enumeration exceeds the bounded offline domain')
    memory.store(owner + 0x460, width, 4, source='2E241E8.display_width')
    memory.store(owner + 0x464, height, 4, source='2E241F2.display_height')
    first = _plain(runtime, 'GetSystemMetrics', (0,))
    second = _plain(runtime, 'GetSystemMetrics', (1,))
    memory.store(owner + 0x58, first, 4, source='2E2420C.screen_width')
    memory.store(owner + 0x5C, second, 4, source='2E2420F.screen_height')
    memory.unmap(frame)


def capture_snapshot(runtime, owner, destination):
    if not runtime.memory.load(owner + 0x42A8, 1):
        from .primary_device_system import _image as system_image, hardware_profile, user_name
        from .primary_logger import _decode
        from .primary_worker_loop import _initialize

        memory, base = runtime.memory, runtime.image_base
        frame, rbp = _frame(runtime, 0x2D0, '2E15490.initial_collector_frame')
        services = connect_wmi(runtime)
        memory.store(owner, services, 8, source='2E154C8.collector_WMI_services')
        _invoke(runtime, 0x1BED930, rbp + 0xB8)
        buffer, capacity = rbp - 0x50, rbp + 0x244
        memory.write(buffer, bytes(260), source='2E154E3.zero_version_format_buffer')
        memory.store(capacity, 260, 4, source='2E154E8.initial_name_capacity')
        memory.store(owner + 8, memory.load(rbp + 0xB8, 4), 4, source='2E154F8.owner_version_class')
        memory.store(owner + 12, memory.load(rbp + 0xD8, 4), 4, source='2E15501.owner_WOW64_class')
        numbers = tuple(memory.load(rbp + offset, 4) for offset in (0xC0, 0xC4, 0xC8))
        format_image = system_image()['version_format']
        pattern = _decode(format_image)
        memory.write(rbp + 0xE0, bytes([0, format_image['seed']]) + pattern + b'\0\0',
                     source='2E15572.decoded_version_format')
        formatted = _format(runtime, pattern, numbers)
        if len(formatted) >= 260:
            raise PrimarySemanticUnavailable('device version format exceeds the actual bounded CRT buffer')
        memory.write(buffer, formatted + b'\0', source='2E15616.formatted_version')
        _invoke(runtime, 0x75BEB0, owner + 0xA0, buffer, len(_cstring(runtime, buffer)))
        value = _invoke(runtime, 0x1BEE390)
        memory.store(owner + 0x48, value, 4, source='2E1562F.owner_architecture')
        for name, offset in (('GetComputerNameA', 0x100), ('GetUserNameA', 0x148)):
            memory.write(buffer, bytes(260), source='2E15490.zero_name_buffer')
            if user_name(runtime, name, buffer, capacity):
                _invoke(runtime, 0x75BEB0, owner + offset, buffer, len(_cstring(runtime, buffer)))
        if hardware_profile(runtime, rbp + 0xE0):
            for offset, source in ((0xD0, rbp + 0x10B), (0xE8, rbp + 0xE4)):
                _invoke(runtime, 0x75BEB0, owner + offset, source, len(_cstring(runtime, source)))
        _initialize(runtime, 1)
        _invoke(runtime, 0x75CEC0, owner + 0x88, base + 0x6751720)
        temporaries = tuple(rbp + offset for offset in (0x1A0, 0x1C0, 0x1E0))
        for address in temporaries:
            memory.write(address, bytes(24), source='2E15490.initial_system_capture_String')
        if _invoke(runtime, 0x2E11020, owner + 0x78, *temporaries) & 0xFFFFFFFF:
            for offset, source in zip((0x118, 0xB8, 0x130), temporaries):
                _invoke(runtime, 0x75CEC0, owner + offset, source)
        from .primary_device_refresh import _observe as refresh_observe

        result, raw = refresh_observe(runtime, 'GetCursorPos', ())
        if not isinstance(raw, bytes) or len(raw) > 8:
            raise InputError('cold collector cursor requires bounded raw POINT effects')
        memory.write(rbp + 0x220, raw, source='2E1579A.cursor_output')
        if result & 0xFFFFFFFF:
            memory.copy_disjoint(owner + 0x4C, rbp + 0x220, 8, label='2E157AA.owner_cursor')
        memory.store(owner + 0x54, _plain(runtime, 'GetKeyboardType', (0,)), 4, source='2E157BE.owner_keyboard_type')
        _invoke(runtime, 0x3E8ED3C, rbp + 0x198)
        memory.store(owner + 0x60, memory.load(rbp + 0x198, 4), 4, source='2E157D3.owner_time64_low_DWORD')
        memory.store(owner + 0x6C, _plain(runtime, 'IsDebuggerPresent', ()), 4, source='2E157DC.owner_debugger_state')
        memory.copy_disjoint(rbp + 0x160, base + _image()['hypervisor_initial_rva'], 16,
                             label='2E1585E.initial_hypervisor_scratch')
        from .primary_device_hardware import _cpuid, _move

        registers = _cpuid(runtime, 1)
        hypervisor = int.from_bytes(registers[8:12], 'little') >> 31
        memory.store(rbp + 0x228, hypervisor, 4, source='2E15873.hypervisor_bit')
        if hypervisor:
            memory.store(owner + 0x68, 1, 4, source='2E158DB.owner_hypervisor_present')
        memory.store(owner + 0x64, 3 if hypervisor else 0, 4, source='2E15908.owner_hypervisor_class')
        memory.store(owner + 0x70, _plain(runtime, 'GetSystemDefaultLCID', ()), 4, source='2E15911.owner_system_LCID')
        ignored, raw = _observe(runtime, 'GetSystemInfo', ())
        _output(runtime, rbp + 0x160, raw, 48, '2E1591B.SYSTEM_INFO_output')
        memory.store(owner + 0x74, memory.load(rbp + 0x180, 4), 4, source='2E15927.owner_processor_count')
        _invoke(runtime, 0x2E15CA0, 0, rbp + 0x200)
        _move(runtime, owner + 0x160, rbp + 0x200)
        for entry in (0x2E15D90, 0x2E18240, 0x2E191B0, 0x2E1A7C0,
                      0x2E1D1B0, 0x2E1E160, 0x2E1F6D0, 0x2E20C10, 0x2E24080, 0x2E24240):
            _invoke(runtime, entry, owner)
        _invoke(runtime, 0x35E9640, owner + 0x730)
        _invoke(runtime, 0x35ECC50, owner + 0x19A0)
        result, raw = _observe(runtime, 'CallNtPowerInformation', (5, 0, 0, 32))
        _output(runtime, rbp + 0x200, raw, 32, '2E159E8.power_information_output')
        if not result & 0xFFFFFFFF:
            for index, offset in enumerate((0x698, 0x6B0, 0x6C8), 1):
                _invoke(runtime, 0x75E7B0, rbp + 0x228, memory.load(rbp + 0x200 + index, 1))
                _move(runtime, owner + offset, rbp + 0x228)
        services = memory.load(owner, 8)
        if services:
            cleanup_wmi(runtime, services)
        memory.store(owner + 0x42A8, 1, 1, source='2E15ACE.initial_collection_complete')
        for address in reversed(temporaries):
            _String.read(runtime, address).destroy()
        memory.unmap(frame)
    _invoke(runtime, 0x2E252A0, owner)
    return _invoke(runtime, 0x2E25B70, destination, owner + 8)


def invoke(runtime, rva, values):
    if rva == 0x2E123C0 and not values:
        return connect_wmi(runtime)
    if rva == 0x2E137F0 and len(values) == 2:
        return cleanup_wmi(runtime, values[1])
    if rva == 0x1BEE390 and not values:
        return architecture(runtime)
    if rva == 0x2E15CA0 and len(values) == 2:
        return cpu_identifier(runtime, values[1])
    if rva == 0x2E24080 and len(values) == 1:
        return display(runtime, values[0])
    if rva == 0x2E15490 and len(values) == 2:
        return capture_snapshot(runtime, *values)
    raise InputError('cold device collector source interface argument count mismatch')
