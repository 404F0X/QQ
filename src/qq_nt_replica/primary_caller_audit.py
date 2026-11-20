from .errors import InputError
from .primary_logger import _String
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _append, _invoke
from .primary_worker_response import _assign, _frame


_MASK64 = (1 << 64) - 1
_VIRTUALS = (0x1C00FC0, 0x1C00FF0, 0x1C010B0, 0x1C014C0)
_RULES = (b'sign_profile_reporter_enable', b'sign_profile_reporter_duration_threshold',
          b'sign_profile_reporter_sample')


def install_image(memory, base):
    for rva, raw in ((0x4148FC8, b''.join((base + value).to_bytes(8, 'little') for value in _VIRTUALS)),
                     (0x677CCA0, bytearray(24))):
        address = base + rva
        if any(region.address <= address and address + len(raw) <= region.address + len(region.data)
               for region in memory._regions):
            if memory.read(address, len(raw)) != raw:
                raise InputError('caller cost source image overlaps different bytes')
        else:
            memory.map(address, raw, name='fixed caller cost source image', initialized=True)


def _signed(value, width=64):
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


def _nanoseconds(runtime):
    memory, base = runtime.memory, runtime.image_base
    counter, frequency = runtime._next(runtime._qpc, 'caller cost QueryPerformanceCounter/Frequency')
    if type(counter) is not int or type(frequency) is not int or not 0 <= counter <= _MASK64:
        raise InputError('caller cost requires unsigned64 QPC and its successful frequency observation')
    if not 0 < frequency <= _MASK64:
        raise PrimarySemanticUnavailable('caller cost failed frequency requires an explicit native BOOL/output observation')
    if not memory.load(base + 0x677CCA8, 4):
        memory.store(base + 0x677CCA0, frequency, 8, source='1C01190.caller_cost_frequency')
        memory.store(base + 0x677CCA8, 1, 4, source='1C011A2.caller_cost_frequency_success')
        runtime.events.append(('QueryPerformanceFrequency', frequency))
    divisor = memory.load(base + 0x677CCA0, 8)
    runtime.events.append(('QueryPerformanceCounter', counter))
    numerator = (counter * 1000000000) & _MASK64
    if (numerator | divisor) >> 32:
        first, second = _signed(numerator), _signed(divisor)
        if second == 0 or first == -(1 << 63) and second == -1:
            raise PrimaryProgramLimit('caller cost native signed division fault')
        result = (abs(first) // abs(second)) * (-1 if (first < 0) != (second < 0) else 1)
    else:
        if not divisor:
            raise PrimaryProgramLimit('caller cost native unsigned division fault')
        result = numerator // divisor
    return result & _MASK64


def construct(runtime, record, command, policy, a, result, *, _owned=None):
    memory, base = runtime.memory, runtime.image_base
    memory.store(record, base + 0x3FD6A28, 8, source='1BF70F0.sign_cost_base_vtable')
    _invoke(runtime, 0x759B30, record + 8)
    memory.store(record + 16, 0, 8, source='1BF70FD.sign_cost_end')
    memory.store(record + 24, 1, 2, source='1BF7105.sign_cost_flags')
    memory.store(record + 28, 10000, 4, source='1BF710C.sign_cost_divisor')
    _String.construct(runtime, b'sign', _owned=_owned).clone(_owned=_owned).write_to(record + 32)
    memory.store(record, base + 0x4148FC8, 8, source='1BF713E.sign_cost_vtable')
    command.clone(_owned=_owned).write_to(record + 56)
    memory.store(record + 80, policy, 4, source='1BF715A.sign_cost_policy')
    a.clone(_owned=_owned).write_to(record + 88)
    result.clone(_owned=_owned).write_to(record + 112)
    a.destroy()
    result.destroy()
    return record


def metadata(runtime, record, output):
    _String.read(runtime, record + 56).clone().write_to(output)
    _String.construct(runtime, b'').write_to(output + 24)
    return output


def columns(runtime, record, event):
    memory, base = runtime.memory, runtime.image_base

    def field(offset, value):
        temporary = _String.construct(runtime, value)
        _assign(runtime, event + offset, temporary)
        temporary.destroy()

    _assign(runtime, event + 0x128, _String.read(runtime, record + 56))
    app_type = memory.load(base + 0x67516D0, 4, signed=True)
    field(0x140, str(app_type).encode('ascii'))
    policy = memory.load(record + 80, 4, signed=True)
    field(0x158, str(policy).encode('ascii'))
    field(0x170, str(_nanoseconds(runtime)).encode('ascii'))
    for source, destination in ((88, 0x188), (112, 0x1A0)):
        temporary = _String.construct(runtime, b'')
        for byte in _String.read(runtime, record + source).value().hex().encode('ascii'):
            _append(temporary, bytes([byte]))
        _String.read(runtime, event + destination).destroy()
        temporary.write_to(event + destination)
    return None


def _lookup(runtime, owner, name):
    memory = runtime.memory
    key = _String.construct(runtime, name)
    node, seen = memory.load(owner + 8, 8), set()
    while node:
        if node in seen or len(seen) >= 4096:
            raise PrimaryProgramLimit('caller cost rules exceed their bounded String map traversal')
        seen.add(node)
        current = _String.read(runtime, node + 32).value()
        if name == current:
            value = _String.read(runtime, node + 56).clone()
            key.destroy()
            return value
        node = memory.load(node + (0 if name < current else 8), 8)
    key.destroy()
    return _String.construct(runtime, b'')


def _atoi(value):
    raw = value.lstrip(b' \t\r\n\v\f')
    sign, index = 1, 0
    if raw[:1] in (b'+', b'-'):
        sign, index = (-1 if raw[:1] == b'-' else 1), 1
    result = 0
    while index < len(raw) and 48 <= raw[index] <= 57:
        result = result * 10 + raw[index] - 48
        index += 1
    result *= sign
    if not -(1 << 31) <= result < 1 << 31:
        raise PrimarySemanticUnavailable('caller cost atoi overflow remains outside the recovered normal input domain')
    return result


def divisor(runtime, record, duration):
    memory, base = runtime.memory, runtime.image_base
    owner = memory.load(base + 0x677CCB0, 8)
    if not owner:
        owner = runtime._operator_new(24)
        memory.write(owner, bytes(24), source='1C01506.sign_cost_rule_map')
        memory.store(owner, owner + 8, 8, source='1C01511.sign_cost_rule_begin')
        memory.store(base + 0x677CCB0, owner, 8, source='1C01514.sign_cost_rule_publish')
    fallback = lambda: memory.load(record + 28, 4)
    enable = _lookup(runtime, owner, _RULES[0])
    enabled = _atoi(enable.value())
    if enabled <= 0:
        result = fallback()
        enable.destroy()
        return result
    threshold = _lookup(runtime, owner, _RULES[1])
    limit = _atoi(threshold.value())
    if limit <= 0 or limit >= _signed(duration, 32):
        result = fallback()
        threshold.destroy()
        enable.destroy()
        return result
    sample = _lookup(runtime, owner, _RULES[2])
    value = _atoi(sample.value())
    result = value if ((value - 1) & 0xFFFFFFFF) < 0xF423F else fallback()
    sample.destroy()
    threshold.destroy()
    enable.destroy()
    return result


def finish(runtime, record):
    memory = runtime.memory
    if memory.load(record + 25, 1):
        return False
    memory.store(record + 25, 1, 1, source='1BF6E84.sign_cost_once')
    _invoke(runtime, 0x759B30, record + 16)
    _invoke(runtime, 0xBCDAD0, record)
    return True


def destroy(runtime, record):
    memory, base = runtime.memory, runtime.image_base
    memory.store(record, base + 0x4148FC8, 8, source='1BF73AA.sign_cost_derived_destructor')
    finish(runtime, record)
    for offset in (112, 88, 56):
        _String.read(runtime, record + offset).destroy()
    memory.store(record, base + 0x3FD6A28, 8, source='1BF73FC.sign_cost_base_destructor')
    finish(runtime, record)
    _String.read(runtime, record + 32).destroy()
    return None


def call(runtime, core, a, b, command, d, policy, *, borrowed_command=None):
    from .primary_sign_lifecycle import _sync_execution
    return _sync_execution(_call_continued(runtime, core, a, b, command, d, policy, borrowed_command=borrowed_command))


def _call_continued(runtime, core, a, b, command, d, policy, *, borrowed_command=None):
    from .primary_sign_lifecycle import require_execution_active
    require_execution_active(runtime)
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x228, '1BF6DA0.semantic_caller_cost_frame')
    from .primary_sign_lifecycle import cleanup, region_at
    regions = [(frame, region_at(memory, frame))]
    owned = []
    try:
        _invoke(runtime, 0x759B30, rbp)
        from .primary_signer import PrimarySigner
        if (getattr(core, '__func__', None) is PrimarySigner._sign_material_continued and
                getattr(core, '__self__', None) is getattr(runtime, '_primary_entry_owner', None)):
            result = yield from core(a, b, command, d, policy=policy)
        else:
            result = core(a, b, command, d, policy=policy)
        original_a, original_result = _String.construct(runtime, a, _owned=owned), _String.construct(runtime, result, _owned=owned)
        if borrowed_command is None:
            original_command = _String.construct(runtime, command, _owned=owned)
        else:
            if type(borrowed_command) is not int or not 0 < borrowed_command <= _MASK64 - 24:
                raise InputError('caller audit borrowed command requires a source String address')
            original_command = _String.read(runtime, borrowed_command)
            if original_command.value() != command:
                raise InputError('caller audit borrowed command differs from its current source bytes')
        copied_result, copied_a = original_result.clone(_owned=owned), original_a.clone(_owned=owned)
        record = rbp + 32
        construct(runtime, record, original_command, policy, copied_a, copied_result, _owned=owned)
        memory.store(record + 8, memory.load(rbp, 8), 8, source='1BF6E7C.sign_cost_original_start')
        finish(runtime, record)
        destroy(runtime, record)
        original_result.destroy()
        original_a.destroy()
        if borrowed_command is None:
            original_command.destroy()
        return result
    finally:
        cleanup(runtime, regions, owned)
