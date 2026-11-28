from .errors import InputError
from contextlib import nullcontext
from .primary_memory import UnknownMemory
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_response import _frame


_CPU = (0x40000000, 0x40000000)
_IMPORTS = {'OpenSCManagerW': 0x49109D0, 'OpenServiceA': 0x49109D8,
            'CloseServiceHandle': 0x4910938, 'RegOpenKeyExA': 0x4910A20,
            'RegQueryValueExA': 0x4910A40, 'RegCloseKey': 0x49109E0,
            'CreateFileA': 0x490FC28, 'DeviceIoControl': 0x490FCB8,
            'CloseHandle': 0x490FBD8}
_MACHINE_VALUES = ((b'SYSTEM\\CurrentControlSet\\iCafe8', b'Admin'),
                   (b'SOFTWARE\\EYOOCLIENTSTATUS', b'SuperLogin'),
                   (b'SYSTEM\\CurrentControlSet', b'superadmin'),
                   (b'SYSTEM\\nVos', b'SupperMode'))


def _cpu(runtime):
    from .primary_device_source_inputs import require_device_source_binding, take_device_source_observation
    require_device_source_binding(runtime)
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('device classification requires raw CPUID observations')
    result, words = take_device_source_observation(runtime, 'CPUID', _CPU)
    if (not isinstance(words, tuple) or len(words) != 4 or
            any(type(word) is not int or not 0 <= word <= 0xFFFFFFFF for word in words)):
        raise InputError('device classification requires four exact DWORD registers')
    return words[1:]


def _request(runtime, name, arguments, outputs=()):
    from .primary_device_source_inputs import require_device_source_binding, take_device_source_observation
    require_device_source_binding(runtime)
    expected = runtime.worker_imports.get(name)
    if not expected or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('device classification import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('device classification raw API observation is unavailable: ' + name)
    result, effects = take_device_source_observation(runtime, name, arguments)
    if type(result) is not int or not 0 <= result < 1 << 64:
        raise InputError('device classification raw API requires an unsigned result')
    if effects in (b'', ()):
        effects = ()
    if not isinstance(effects, tuple):
        raise InputError('device classification effects require address and raw bytes')
    for effect in effects:
        if not isinstance(effect, tuple) or len(effect) != 2:
            raise InputError('device classification effect shape')
        address, raw = effect
        if (type(address) is not int or not isinstance(raw, bytes) or
                not any(start <= address and address + len(raw) <= start + size for start, size in outputs)):
            raise InputError('device classification effect leaves its actual output')
        runtime.memory._span(address, len(raw))
    for address, raw in effects:
        if raw:
            runtime.memory.write(address, raw, source='hypervisor.' + name)
    return result


def _open_key(runtime, key, output):
    return _request(runtime, 'RegOpenKeyExA', (0xFFFFFFFF80000002, key + b'\0', 0, 0x20119, output),
                    ((output, 8),)) & 0xFFFFFFFF


def _service_present(runtime):
    manager = _request(runtime, 'OpenSCManagerW', (0, 0, 4))
    if not manager:
        return False
    service = _request(runtime, 'OpenServiceA', (manager, b'vmbusr\0', 4))
    if service:
        _request(runtime, 'CloseServiceHandle', (service,))
    _request(runtime, 'CloseServiceHandle', (manager,))
    return bool(service)


def _vmid_present(runtime, rbp):
    output = rbp + 0x780
    if _open_key(runtime, b'SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters', output):
        return False
    handle = runtime.memory.load(output, 8)
    status = _request(runtime, 'RegQueryValueExA', (handle, b'VirtualMachineId\0', 0, 0, 0, 0))
    _request(runtime, 'RegCloseKey', (handle,))
    return status & 0xFFFFFFFF == 0


def _storage_virtio(runtime, rbp):
    handle = _request(runtime, 'CreateFileA', (b'\\\\.\\PhysicalDrive0\0', 0x100080, 1, 0, 3, 0, 0))
    if handle == (1 << 64) - 1:
        return False
    address, unused = _frame(runtime, 4096, '2DA9F70.storage_descriptor')
    query, count = rbp + 0x200, rbp + 0x644
    runtime.memory.write(query, bytes(12), source='hypervisor.storage_query_zero')
    result = _request(runtime, 'DeviceIoControl',
                      (handle, 0x2D1400, query, 12, address, 4096, count, 0), ((address, 4096), (count, 4)))
    _request(runtime, 'CloseHandle', (handle,))
    matched = False
    if result & 0xFFFFFFFF:
        returned = runtime.memory.load(count, 4)
        if returned >= 40:
            offset = runtime.memory.load(address + 16, 4)
            if offset >= 4096:
                raise PrimarySemanticUnavailable('device classification vendor offset leaves its output buffer')
            value = bytearray()
            for index in range(offset, 4096):
                byte = runtime.memory.load(address + index, 1)
                if not byte:
                    matched = b'virtio' in bytes(value).lower()
                    break
                value.append(byte)
            else:
                raise PrimarySemanticUnavailable('device classification vendor is not terminated')
    runtime.memory.unmap(address)
    return matched


def _machine_positive(runtime, rbp, key, name, index):
    output, kind, data, size = rbp + 0x790 + index * 8, rbp + 0x6A0, rbp + 0x6B0, rbp + 0x6C0
    if _open_key(runtime, key, output):
        return False
    handle = runtime.memory.load(output, 8)
    runtime.memory.write(data, bytes(8), source='hypervisor.registry_data_zero')
    runtime.memory.store(size, 8, 4, source='hypervisor.registry_size_eight')
    runtime.memory.store(kind, 0, 4, source='hypervisor.registry_type_zero')
    status = _request(runtime, 'RegQueryValueExA', (handle, name + b'\0', 0, kind, data, size),
                      ((kind, 4), (data, 8), (size, 4)))
    _request(runtime, 'RegCloseKey', (handle,))
    return status & 0xFFFFFFFF == 0 and runtime.memory.load(data, 4) == 0


def _run(runtime, rbp):
    if _cpu(runtime) == (0x7263694D, 0x666F736F, 0x76482074):
        if not _service_present(runtime) and _vmid_present(runtime, rbp):
            return 4
    if _cpu(runtime) == (0x61774D56, 0x4D566572, 0x65726177):
        return 2
    if _cpu(runtime) == (0x786F4256, 0x786F4256, 0x786F4256):
        return 3
    if _cpu(runtime)[:2] == (0x4B4D564B, 0x564B4D56):
        return 5
    if _storage_virtio(runtime, rbp):
        return 5
    if _cpu(runtime) == (0x566E6558, 0x65584D4D, 0x4D4D566E):
        return 6
    words = _cpu(runtime)
    if words == (0x61726150, 0x6C656C6C, 0x76482073) or words[:2] == (0x206C7270, 0x65707968):
        return 7
    for index, (key, name) in enumerate(_MACHINE_VALUES):
        if _machine_positive(runtime, rbp, key, name, index):
            return 8
    output = rbp + 0x958
    status = _open_key(runtime, b'SYSTEM\\CurrentControlSet\\Enum\\vDisk\\Disk0', output)
    try:
        handle = runtime.memory.load(output, 8)
    except UnknownMemory as error:
        error.pc_rva = 0x2DAFA95
        raise
    _request(runtime, 'RegCloseKey', (handle,))
    return 8 if status == 0 else 0


def classify(runtime, *, key_preimage=None, windows=False):
    if key_preimage is not None and (not isinstance(key_preimage, bytes) or len(key_preimage) != 8):
        raise InputError('device classification key preimage requires exactly eight bytes or unknown')
    address, rbp = _frame(runtime, 0xC08, '2DA9F70.device_classification_frame')
    if key_preimage is not None:
        runtime.memory.write(rbp + 0x958, key_preimage, source='hypervisor.explicit_key_preimage')
    previous = runtime.worker_observations
    scope = nullcontext()
    if windows:
        from .primary_windows_hypervisor_observations import WindowsHypervisorObservations
        scope = WindowsHypervisorObservations(previous)
    try:
        with scope as observer:
            if windows:
                runtime.worker_observations = observer
            result = _run(runtime, rbp)
    finally:
        runtime.worker_observations = previous
        if windows:
            runtime.events.append(('device.windows_hypervisor_closed', tuple(scope.records),
                                   tuple(scope.cleanup_events), len(scope.handles), scope.closed))
    runtime.memory.unmap(address)
    runtime.events.append(('2DA9F70.return', result))
    return result
