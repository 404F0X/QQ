from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_crt_startup import resolve


_MASK64 = (1 << 64) - 1
_EXPORTS = {27: (b'AppPolicyGetThreadInitializationType', (21,)),
            24: (b'RoInitialize', (11,)), 25: (b'RoUninitialize', (11,))}


def _observe(runtime, name, arguments):
    observer = getattr(runtime, 'crt_startup_observations', None)
    if observer is None:
        raise PrimarySemanticUnavailable('CRT application source observation is unavailable: ' + name)
    return observer.take(runtime, name, arguments)


def _dword(result, name):
    if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
        raise InputError('CRT application requires an unsigned DWORD result: ' + name)
    return result


def _optional(runtime, slot):
    value = runtime.memory.load(runtime.image_base + 0x7394000 + slot * 8, 8)
    if value == _MASK64:
        return 0
    if not value:
        name, modules = _EXPORTS[slot]
        value = resolve(runtime, slot, name, modules)
    if type(value) is not int or not 0 <= value < _MASK64:
        raise InputError('CRT application resolver requires a known optional pointer or zero')
    return value


def process_flag(runtime):
    value, effects = _observe(runtime, 'CRT.ProcessParametersFlags', ())
    _dword(value, 'CRT.ProcessParametersFlags')
    if effects not in ((), b''):
        raise InputError('CRT process-parameter intrinsic has no model memory effects')
    return value >> 31


def app_policy(runtime, output):
    if type(output) is not int or not 0 <= output <= _MASK64:
        raise InputError('CRT AppPolicy requires an unsigned source output pointer')
    procedure = _optional(runtime, 27)
    if not procedure:
        runtime.events.append(('CRT.optional_api_missing', 'AppPolicyGetThreadInitializationType', 0xC0000225))
        return 0xC0000225
    result, effects = _observe(runtime, 'CRT.AppPolicyGetThreadInitializationType', (procedure, _MASK64 - 5, output))
    _dword(result, 'CRT.AppPolicyGetThreadInitializationType')
    if effects is not None:
        if not isinstance(effects, bytes) or len(effects) != 4:
            raise InputError('CRT AppPolicy output requires an observed four-byte write or no write')
        runtime.memory.write(output, effects, source='AppPolicyGetThreadInitializationType.output')
    return result


def ro_initialize(runtime, flags):
    _dword(flags, 'RoInitialize.flags')
    procedure = _optional(runtime, 24)
    if not procedure:
        runtime.events.append(('CRT.optional_api_missing', 'RoInitialize', 0))
        return 0
    result, effects = _observe(runtime, 'CRT.RoInitialize', (procedure, flags))
    _dword(result, 'CRT.RoInitialize')
    if effects not in ((), b''):
        raise InputError('CRT RoInitialize requires no model memory effects')
    return result


def ro_uninitialize(runtime):
    procedure = _optional(runtime, 25)
    if not procedure:
        runtime.events.append(('CRT.optional_api_missing', 'RoUninitialize', None))
        return None
    result, effects = _observe(runtime, 'CRT.RoUninitialize', (procedure,))
    if result is not None or effects not in ((), b''):
        raise InputError('CRT RoUninitialize requires a void result and no model memory effects')
    return None


def application(runtime):
    memory, base = runtime.memory, runtime.image_base
    value = memory.load(base + 0x6D8F150, 4)
    if value:
        return value
    size, address, initial = runtime._next(runtime._temporaries, 'CRT application private output', 4)
    if (size != 4 or type(address) is not int or not 0 < address <= _MASK64 - 4 or
            initial is not None and (not isinstance(initial, bytes) or len(initial) != 4)):
        raise InputError('CRT application requires its explicit four-byte source stack local')
    memory.map(address, bytearray(4) if initial is None else bytearray(initial),
               name='CRT application source stack local', initialized=initial is not None)
    try:
        memory.store(address, 0, 4, source='3EA4B77.application_policy_local_zero')
        if not process_flag(runtime):
            app_policy(runtime, address)
        value = 1 + int(memory.load(address, 4) == 1)
        memory.store(base + 0x6D8F150, value, 4, source='3EA4B9C.application_type_publication')
        return value
    finally:
        memory.forget(address, 4, source='CRT.application_local_lifetime_end')
        if not runtime.retain_frames:
            memory.unmap(address)


def initialize_thread(runtime, context):
    if application(runtime) == 2:
        result = ro_initialize(runtime, 1)
        if result == 0:
            runtime.memory.store(context + 0x20, 1, 1, source='3E81840.thread_runtime_initialized')


def uninitialize_thread(runtime, context):
    if runtime.memory.load(context + 0x20, 1):
        ro_uninitialize(runtime)


def invoke(runtime, rva, values):
    entries = {0x3EA4B68: (application, 0), 0x3EA4C1C: (process_flag, 0),
               0x3EA1AA8: (app_policy, 1), 0x3EA1958: (ro_initialize, 1),
               0x3EA19A8: (ro_uninitialize, 0)}
    function, count = entries.get(rva, (None, None))
    if function is None or len(values) != count:
        raise InputError('unsupported CRT application source entry or argument count')
    return function(runtime, *values)
