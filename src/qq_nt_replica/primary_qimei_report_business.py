"""Source6BBCE QQ report group, direct kind13/context0 (no request handler)."""
import base64
from dataclasses import dataclass

from .primary_qimei_cache import _cbc
from .primary_qimei_extras import QimeiRequestExtras
from .primary_qimei_report_sources import QimeiReportValues
from .primary_qimei_request import QimeiRequestBoundary, _bytes, _signed, _varint


def report_string(report):
    if (not isinstance(report, QimeiReportValues) or type(report.available) is not bool
            or type(report.values) is not tuple or len(report.values) != 6):
        raise QimeiRequestBoundary('six Source Strings and DIL required')
    values = tuple(_bytes(value) for value in report.values)
    encoded = QimeiRequestExtras({str(i).encode('ascii'): value
        for i, value in enumerate(values, 1)} if report.available else {}).encode()
    return encoded if len(encoded) > 9 else b''


def report_payload(value, force):
    value = _bytes(value)
    if type(force) is not bool:
        raise QimeiRequestBoundary('Source kind13 bool required')
    encrypted = b''
    if value:
        padding = 16 - len(value) % 16
        encrypted = base64.b64encode(_cbc(value + bytes([padding]) * padding,
            b'18845cac36195f4a', b'2a77ed84a51b0b2e'))
    return b'\x0a\x03' + b'1.0' + b'\x12' + _varint(len(encrypted)) + encrypted + b'\x1a\x01' + (b'2' if force else b'1')


@dataclass
class QimeiReportOutcome:
    body: bytes = b''
    result_code: int = 1
    status: int = 0
    server_code: int = 0


def conditional_kind13(owner, settings, *, settings_dependencies, sources, dispatch, io=None):
    gate = _signed(settings.flag(14, group=0, **settings_dependencies), 32)
    if gate <= 0:
        return None
    force = gate == 2
    value = report_string(sources.collect(owner))
    if not value and not force:
        return None
    payload = report_payload(value, force)
    outcome = QimeiReportOutcome()
    if dispatch is None:
        return outcome
    def complete(body, result_code, status, server_code, context):
        outcome.body, outcome.result_code = body, result_code
        outcome.status, outcome.server_code = status, server_code
        # 620A1 still decodes/cleans up; context0 omits derived 53B3E only.
    dispatch.dispatch(owner, 13, payload, complete, None, **({} if io is None else dict(io=io)))
    return outcome
