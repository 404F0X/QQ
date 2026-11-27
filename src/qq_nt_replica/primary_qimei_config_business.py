"""Source-derived kind3 and retained kind4 business composition.

This module is part of the pending vertical candidate, not an a2 entry point.
"""
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestState, RequestSlot, _signed
from .primary_qimei_adapter_sources import format_address
from .primary_qimei_reply import parse_reply


def conditional_kind3(owner, settings, *, settings_dependencies, usage_count,
                      instance_count, selector, selector_observations,
                      request_sources, dispatch, convert_ansi, io=None):
    """6A840/B0B2F; producer effects precede the signed instance-count gate."""
    limit = _signed(settings.flag(3, group=1, **settings_dependencies), 32)
    if limit <= 0:
        return False
    usage = usage_count()
    instances = instance_count(owner)
    if _signed(instances, 32) <= _signed(limit, 32):
        return False
    state = QimeiRequestState([RequestSlot() for unused in range(16)])
    state.set_string(1, b'ig')
    state.set_string(2, format_address(selector.select(selector_observations)))
    # Existing identity_3fafa preserves regeneration and main-record persistence.
    state.set_string(5, request_sources.identity_3fafa(**({} if io is None else dict(observations=io.request_observations, write_main=io.write_main))))
    state.set_string(6, str(_signed(usage, 32)).encode('ascii'))
    state.set_string(7, str(_signed(instances, 32)).encode('ascii'))
    def complete(body, result_code, status, server_code, context):
        # 52D66 does not install request-specific response fields. Common
        # decode/status results remain the dispatcher's observed outcome.
        return True
    dispatch.dispatch(owner, 3, state.encode(convert_ansi=convert_ansi), complete, None, **({} if io is None else dict(io=io)))
    return True


def retained_kind4(owner, settings, *, settings_dependencies, sources, writer,
                   dispatch, convert_ansi, io=None):
    """A3A34 business payload and A3B98 response on the retained provider path."""
    sources._check()
    with settings._lock:
        settings.refresh(**settings_dependencies)
        timestamp = int.from_bytes(settings.record[9:17], 'little')
        saved = bytes(settings.record[17:49]).split(b'\0', 1)[0]
    if (sources.clock() - timestamp) & ((1 << 64) - 1) < 86400:
        return False
    state = QimeiRequestState([RequestSlot() for unused in range(5)])
    state.set_string(1, saved)
    for number, value in enumerate((sources.wow64(), 2, sources.os_classification(), sources.architecture()), 2):
        state.set_u32(number, value)
    def complete(body, result_code, status, server_code, context):
        if status != 200 or result_code or server_code or not body:
            return False
        parsed = parse_reply(body, count=22)
        if not parsed.accepted:
            return False
        settings.update_response(parsed.slots, clock=sources.clock, writer=writer,
                                 **settings_dependencies)
        return True
    dispatch.dispatch(owner, 4, state.encode(convert_ansi=convert_ansi), complete, settings, **({} if io is None else dict(io=io)))
    return True
