from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_crt_thread import _critical
from .primary_thread_dispatch import _fallback_current as fallback_current


_MASK64 = (1 << 64) - 1
_MODULES = {1: 'api-ms-win-core-fibers-l1-1-2', 19: 'kernelbase',
            11: 'api-ms-win-core-winrt-l1-1-0', 21: 'api-ms-win-appmodel-runtime-l1-1-2'}
_RESOLVERS = {3: (b'FlsGetValue2', (1, 19), 0x4906A38, 0x45BFB90, 0x45BFB98),
              24: (b'RoInitialize', (11,), 0x4906418, 0x45BFBE0, 0x45BFBE4),
              25: (b'RoUninitialize', (11,), 0x4906408, 0x45BFBE4, 0x45BFBE8),
              27: (b'AppPolicyGetThreadInitializationType', (21,), 0x49064A8, 0x45BFBEC, 0x45BFBF0)}


def _api(runtime, name, *arguments):
    observer = getattr(runtime, 'crt_startup_observations', None)
    if observer is None:
        raise PrimarySemanticUnavailable('CRT startup observation is unavailable: ' + name)
    result, effects = observer.take(runtime, name, arguments)
    if effects not in ((), b''):
        raise InputError('CRT startup requires empty effects for ' + name)
    void = ('CRT.DeleteCriticalSection', 'SetLastError')
    if name in void:
        if result is not None:
            raise InputError('CRT startup requires void result for ' + name)
    elif type(result) is not int or not 0 <= result <= _MASK64:
        raise InputError('CRT startup requires unsigned native result for ' + name)
    return result


def install_cold_state(memory, base):
    ranges = ((0x6D8EA30, bytes(15 * 40)), (0x6D8EC88, bytes(4)),
              (0x6D8E968, bytes(1)), (0x6D8E970, bytes(24 * 8)),
              (0x7394000, bytes(0x100)), (0x6744470, b'\xff' * 4), (0x6D8F150, bytes(4)))
    for rva, data in ranges:
        begin, end = base + rva, base + rva + len(data)
        cursor = begin
        overlaps = [region for region in memory._regions
                    if region.address < end and begin < region.address + len(region.data)]
        for region in overlaps:
            if cursor < region.address:
                memory.map(cursor, bytearray(data[cursor - begin:region.address - begin]),
                           name='fixed CRT startup unmapped source bytes', initialized=True)
            cursor = max(cursor, min(end, region.address + len(region.data)))
        if cursor < end:
            memory.map(cursor, bytearray(data[cursor - begin:]),
                       name='fixed CRT startup unmapped source bytes', initialized=True)


def initialize_locks(runtime):
    memory, base = runtime.memory, runtime.image_base
    for identifier in range(15):
        result = _api(runtime, 'CRT.InitializeCriticalSectionEx', base + 0x6D8EA30 + identifier * 40, 4000, 0)
        if not result:
            destroy_locks(runtime, 0)
            return 0
        count = base + 0x6D8EC88
        memory.store(count, (memory.load(count, 4) + 1) & 0xFFFFFFFF, 4, source='3EA1F88.initialized_lock_count')
    return 1


def destroy_locks(runtime, terminating):
    memory, base = runtime.memory, runtime.image_base
    count_address = base + 0x6D8EC88
    count = memory.load(count_address, 4)
    if count > 15:
        raise PrimarySemanticUnavailable('CRT lock count exceeds the source initializer domain')
    while count:
        count -= 1
        _api(runtime, 'CRT.DeleteCriticalSection', base + 0x6D8EA30 + count * 40)
        memory.store(count_address, (memory.load(count_address, 4) - 1) & 0xFFFFFFFF,
                     4, source='3EA1FCD.initialized_lock_count_decrement')
    return 1


def resolve_getter(runtime):
    value = runtime.memory.load(runtime.image_base + 0x7394018, 8)
    if value == _MASK64:
        return 0
    if not value:
        value = resolve(runtime, 3, b'FlsGetValue2', (1, 19))
    return int(bool(value))


def resolve(runtime, slot, name, module_indices):
    if slot not in _RESOLVERS or (name, module_indices) != _RESOLVERS[slot][:2]:
        raise InputError('CRT resolver request differs from its fixed source allowlist')
    memory, base = runtime.memory, runtime.image_base
    procedure = 0
    for identifier in module_indices:
        address = base + 0x6D8E970 + identifier * 8
        module = memory.load(address, 8)
        if module == _MASK64:
            continue
        if not module:
            module = _api(runtime, 'LoadLibraryExW', _MODULES[identifier], 0, 0x800)
            if not module:
                if _api(runtime, 'GetLastError') == 87:
                    prefix = _MODULES[identifier].encode('utf-16-le')[:14]
                    if prefix not in ('api-ms-'.encode('utf-16-le'), 'ext-ms-'.encode('utf-16-le')):
                        module = _api(runtime, 'LoadLibraryExW', _MODULES[identifier], 0, 0)
                if not module:
                    memory.store(address, _MASK64, 8, source='3EA1DDB.unavailable_module_cache')
                    continue
            previous = memory.load(address, 8)
            memory.store(address, module, 8, source='3EA1E86.loaded_module_cache')
            if previous:
                _api(runtime, 'FreeLibrary', module)
        procedure = _api(runtime, 'GetProcAddress', module, name)
        break
    _critical(runtime, 14, True)
    page = base + 0x7394000
    if not _api(runtime, 'CRT.VirtualProtectCache', page, 0x100, 4):
        raise PrimarySemanticUnavailable('3EA1EB0 CRT cache protection failure requires its original termination')
    value = procedure or _MASK64
    _api(runtime, 'CRT.ExchangeCache', page + slot * 8, value)
    memory.store(page + slot * 8, value, 8, source='3EA1E40.resolved_procedure_cache')
    if not _api(runtime, 'CRT.VirtualProtectCache', page, 0x100, 2):
        raise PrimarySemanticUnavailable('3EA1EB0 CRT cache restore failure requires its original termination')
    _critical(runtime, 14, False)
    return procedure


def initialize_fls(runtime):
    memory, base = runtime.memory, runtime.image_base
    available = resolve_getter(runtime)
    memory.store(base + 0x6D8E968, available, 1, source='3EA0AD8.direct_FLS_getter_availability')
    identifier = _api(runtime, 'CRT.FlsAlloc', base + 0x3EA0CCC)
    memory.store(base + 0x6744470, identifier, 4, source='3EA0AE3.CRT_FLS_index')
    if identifier == 0xFFFFFFFF:
        return 0
    if current(runtime):
        return 1
    teardown_fls(runtime)
    return 0


def teardown_fls(runtime):
    memory, base = runtime.memory, runtime.image_base
    identifier = memory.load(base + 0x6744470, 4)
    if identifier != 0xFFFFFFFF:
        _api(runtime, 'CRT.FlsFree', identifier)
        memory.store(base + 0x6744470, 0xFFFFFFFF, 4, source='3EA0B20.CRT_FLS_index_reset')
    return 1


def current(runtime):
    memory, base = runtime.memory, runtime.image_base
    if not memory.load(base + 0x6D8E968, 1):
        return fallback_current(runtime)
    identifier = memory.load(base + 0x6744470, 4)
    value = 0 if identifier == 0xFFFFFFFF else _api(runtime, 'CRT.FlsGetValue2', identifier)
    if value == _MASK64:
        return 0
    if not value:
        from .primary_crt_thread import create
        value = create(runtime)
    return value


def initialize(runtime):
    if not initialize_locks(runtime):
        return 0
    from .primary_worker_consumer import _invoke
    _invoke(runtime, 0x3E6E398)
    return initialize_fls(runtime)


def fls_callback(runtime, pointer):
    if pointer:
        from .primary_crt_thread import destroy, free
        destroy(runtime, pointer)
        free(runtime, pointer)


def initialize_global_locale(runtime):
    # r598 table's first normal initializer: LEA; one store; MOV AL,1.
    pointer=runtime.image_base+0x6744A10
    runtime.memory.store(runtime.image_base+0x6D8F120,pointer,8,source='3E6E39F.publish_static_C_locale')
    return (pointer & ~0xFF) | 1


def invoke(runtime, rva, values):
    if rva == 0x3E6E398 and not values:
        return initialize_global_locale(runtime)
    if rva == 0x3EA1D04:
        if len(values) != 4 or values[0] not in _RESOLVERS:
            raise InputError('CRT resolver values differ from the source getter request')
        name, modules, export, begin, end = _RESOLVERS[values[0]]
        if tuple(values) != (values[0], runtime.image_base + export,
                             runtime.image_base + begin, runtime.image_base + end):
            raise InputError('CRT resolver values differ from the fixed source optional request')
        return resolve(runtime, values[0], name, modules)
    if rva in (0x3EA141C, 0x3EA140C) and len(values) == 1:
        return _api(runtime, 'CRT.FlsGetValue2' if rva == 0x3EA141C else 'FlsGetValue', values[0])
    entries = {0x3EA1F60: (initialize_locks, 0), 0x3EA0AC8: (initialize_fls, 0),
               0x3EA1CC0: (resolve_getter, 0), 0x3EA0CCC: (fls_callback, 1),
               0x3EA1FA8: (destroy_locks, 1), 0x3EA0B90: (current, 0),
               0x3EA0B0C: (teardown_fls, 0)}
    function, count = entries.get(rva, (None, None))
    if function is None or len(values) != count:
        raise InputError('unsupported finite CRT startup entry or argument count')
    result = function(runtime, *values)
    if rva in (0x3EA1F60, 0x3EA0AC8, 0x3EA1CC0, 0x3EA1FA8, 0x3EA0B0C):
        from .primary_sdk import NativeByteReturn
        return NativeByteReturn(result)
    return result
