from .errors import InputError
from .primary_logger import _String, feature
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke, _logger
from .primary_worker_response import _frame


def _configured(runtime, receiver, tag, pointer, count, function, metadata, mode, frame, rbp):
    memory, base = runtime.memory, runtime.image_base
    record = runtime._operator_new(0xB8)
    memory.store(record + 8, 0, 4, source='1CE6E86.request_owner_count')
    memory.store(record + 16, 0, 4, source='1CE6E8D.request_weak_count')
    memory.store(record, base + 0x414B4C8, 8, source='1CE6E9B.request_record_vtable')
    memory.write(record + 24, bytes(160), source='1CE6EA5.request_record_fields')
    memory.store(rbp + 0x48, record, 8, source='1CE6ECF.request_control')
    memory.store(rbp + 8, record + 24, 8, source='1CE6EDA.request_value')
    _String.read(runtime, tag).clone().write_to(record + 24)
    count &= 0xFFFFFFFF
    payload = _String.construct(runtime, memory.read(pointer, count) if count else b'')
    payload.write_to(rbp + 0x80)
    _invoke(runtime, 0x1CC6E10, rbp + 0x10, rbp + 0x80, tag, rbp + 0x34, record + 0x48, rbp + 4)
    payload.destroy()
    packet = _String.read(runtime, rbp + 0x10)
    output = packet.get(16, 8) if packet.get(0, 1) & 1 else rbp + 0x11
    memory.store(record + 0x78, output, 8, source='1CE702A.encoded_request_pointer')
    status = memory.load(rbp + 0x34, 4)
    runtime.events.append(('worker.configured_request_encoded', record, output, len(packet.value()), status,
                           memory.load(rbp + 4, 4), frame))
    if status not in (0, 1):
        raise PrimarySemanticUnavailable('1CE7D19 nonstandard request status cleanup remains unavailable')
    from .primary_request_transport import dispatch
    return dispatch(runtime, receiver, record, function, metadata, status, packet, frame, rbp)


def handoff(runtime, receiver, tag, pointer, count, function, metadata, mode):
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x178, '1CE6920.device_handoff_frame')
    from .primary_notification_handoff_audit import handoff_audit
    with handoff_audit(runtime) as audit_claim:
        for audit_rva in (0x1BF75A0, 0x1BF8090):
            if audit_claim is None:
                _invoke(runtime, audit_rva, 1, 61, 1, 0)
            else:
                with audit_claim.step(audit_rva):
                    _invoke(runtime, audit_rva, 1, 61, 1, 0)
    if feature(runtime, _logger(runtime), 43) == 1:
        from .primary_request_transport import _clone_function, send_enhanced
        memory.write(rbp - 40, bytes(40), source='1CE6E3C.enhanced_callback_temporary')
        _clone_function(runtime, function, rbp - 32)
        payload = _String.construct(runtime, memory.read(pointer, count & 0xFFFFFFFF) if count & 0xFFFFFFFF else b'')
        payload.write_to(rbp + 0x80)
        try:
            send_enhanced(runtime, receiver, tag, rbp + 0x80, rbp - 40, metadata, mode)
        finally:
            from .primary_client_configuration_scope import normal_cleanup
            if normal_cleanup(runtime):
                payload.destroy()
        active = 0
    else:
        gate = _invoke(runtime, 0xBA21A0)
        if memory.load(gate + 8, 8):
            _configured(runtime, receiver, tag, pointer, count, function, metadata, mode, frame, rbp)
            active = 0
        else:
            active = memory.load(function + 32, 8)
    if active:
        target = memory.load(memory.load(active, 8) + 40, 8)
        if target not in (base + 0xBDCA30, base + 0x1BF44D0, base + 0x2DF14A0, base + 0x2DE0C10, base + 0x1C51410) and not (
                memory.load(active, 8) == base + 0x414BB08 and target == base + 0x1D27530):
            raise PrimarySemanticUnavailable('1CE6F84 current device response callback target is not bound')
        memory.write(rbp + 0x80, bytes(24), source='1CE6F39.empty_device_transport_reply')
        memory.store(rbp + 0x10, 907, 4, source='1CE6F52.missing_device_transport_error')
        memory.store(rbp + 0x34, 0, 1, source='1CE6B76.device_transport_success_flag')
        memory.store(rbp + 0x40, 0, 4, source='1CE6F5D.empty_device_transport_count')
        memory.store(rbp + 0x58, rbp + 0x81, 8, source='1CE6F64.empty_device_transport_pointer')
        _invoke(runtime, target - base, active, rbp + 0x58, rbp + 0x40, rbp + 0x34, rbp + 0x10)
    _String.read(runtime, tag).destroy()
    active = memory.load(function + 32, 8)
    if active:
        inline = active == function + 8
        target = memory.load(memory.load(active, 8) + (24 if inline else 32), 8)
        if memory.load(active, 8) in (base + 0x436EC18, base + 0x414ABD8, base + 0x414BB08) and target == base + (0x28F0 if inline else 0x1FE0):
            _invoke(runtime, target - base, active)
        elif memory.load(active, 8) == base + 0x433C478 and target == base + (0xB95880 if inline else 0xBED000):
            _invoke(runtime, target - base, active)
        elif target in (base + 0x1BF4450, base + 0x1BF4490, base + 0x1D02990, base + 0x1D029A0):
            _invoke(runtime, target - base, active)
        elif target == base + (0xBDC9F0 if inline else 0xBDCA00):
            _String.read(runtime, active + 16).destroy()
            if not inline:
                runtime._free_allocation(active)
        else:
            raise PrimarySemanticUnavailable('1CE7D81 current device callback destructor is not bound')
    memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    if rva == 0x1CE6920 and len(values) == 7:
        return handoff(runtime, *values)
    raise InputError('worker handoff source interface argument count mismatch')
