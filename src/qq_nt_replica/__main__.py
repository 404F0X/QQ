"""JSON/hex command line interface; no network or native-module operations."""

import argparse
from dataclasses import fields
import json
from pathlib import Path
import re
import sys

from . import CapabilityUnavailable, FinalX, InputError, LoginRecord, OwnerState
from . import accept_server_handshake, apply_preverified_decrypted_inner
from . import build_auth, build_easy, build_request


def _object(value, names, context):
    if type(value) is not dict:
        raise InputError(f"{context} must be an object")
    missing, extra = set(names) - value.keys(), value.keys() - set(names)
    if missing or extra:
        raise InputError(f"{context}: missing={sorted(missing)}, unknown={sorted(extra)}")
    return value


def _hex_bytes(value, context):
    obj = _object(value, {"hex"}, context)
    encoded = obj["hex"]
    if not isinstance(encoded, str) or len(encoded) % 2 or re.fullmatch(r"[0-9a-fA-F]*", encoded) is None:
        raise InputError(f"{context}.hex must contain an even number of hexadecimal digits, without whitespace")
    return bytes.fromhex(encoded)


def _hex(value):
    return {"hex": value.hex()}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path):
    source = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8-sig")
    return json.loads(source, object_pairs_hook=_unique_object)


def _request(document, kind):
    obj = _object(document, {"x", "record"}, "request")
    x_data = _object(obj["x"], {f.name for f in fields(FinalX)}, "x")
    byte_names = {"s0", "s20", "s38", "s70", "s90", "v58", "v1a8"}
    x = FinalX(**{key: _hex_bytes(value, f"x.{key}") if key in byte_names else value for key, value in x_data.items()})
    record_data = _object(obj["record"], {f.name for f in fields(LoginRecord)}, "record")
    record = LoginRecord(**{
        key: _hex_bytes(value, f"record.{key}") if key.startswith("bytes_") else value
        for key, value in record_data.items()
    })
    if kind == "easy":
        result = build_easy(x, record.bytes_a0)
    elif kind == "auth":
        result = build_auth(x, record.bytes_1d0)
    else:
        result = build_request(x, record)
    return {
        "kind": result.kind, "selector": result.selector,
        "payload": _hex(result.payload) if result.payload is not None else None,
        "payload_length": len(result.payload) if result.payload is not None else None,
        "notice": result.notice, "builder_al": result.builder_al,
    }, 0 if result.payload is not None else 1


def _record(record):
    return {
        "key": record.key, "wire_kind": record.wire_kind,
        "value": _hex(record.value) if isinstance(record.value, bytes) else record.value,
        "start": record.start, "end": record.end, "raw": _hex(record.raw),
    }


def _run(run):
    return {"key": run.key, "family": run.family, "storage_class": run.storage_class,
            "records": [_record(record) for record in run.records]}


def _inner_reply(document):
    obj = _object(document, {"preverified_decrypted_inner", "owner"}, "inner-reply")
    owner_data = _object(obj["owner"], {"o30", "o48"}, "owner")
    owner = OwnerState(_hex_bytes(owner_data["o30"], "owner.o30"), _hex_bytes(owner_data["o48"], "owner.o48"))
    result = apply_preverified_decrypted_inner(_hex_bytes(obj["preverified_decrypted_inner"], "preverified_decrypted_inner"), owner)
    parsed = result.parse
    return {
        "trust_boundary": "caller supplied preverified and decrypted inner; no network acceptance performed",
        "parse": {
            "raw": _hex(parsed.raw), "parse_al": parsed.parse_al,
            "inspected_bytes": parsed.inspected_bytes, "consumed": parsed.consumed,
            "offset_semantics": "offline inspected prefix, not native fast/slow cursor",
            "ignored_suffix": _hex(parsed.ignored_suffix),
            "termination_reason": parsed.termination_reason, "field_start": parsed.field_start,
            "error": parsed.error, "records": [_record(record) for record in parsed.records],
            "family_runs": [_run(run) for run in parsed.family_runs],
            "current_fields": [_run(run) for run in parsed.current_fields],
        },
        "new30": _hex(result.new30) if result.new30 is not None else None,
        "new48": _hex(result.new48) if result.new48 is not None else None,
        "q": result.q,
        "events": [{"kind": event.kind, "value": _hex(event.value) if isinstance(event.value, bytes) else event.value} for event in result.events],
        "owner": {"o30": _hex(owner.o30), "o48": _hex(owner.o48)},
    }, 0 if parsed.parse_al else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    request = sub.add_parser("request", help="encode externally supplied final-X and record")
    request.add_argument("input", help="JSON path, or - for stdin")
    request.add_argument("--kind", choices=("auto", "easy", "auth"), default="auto")
    reply = sub.add_parser("inner-reply", help="consume caller-preverified/decrypted inner only")
    reply.add_argument("input", help="JSON path, or - for stdin")
    sub.add_parser("capabilities", help="list implemented and unavailable boundaries")
    sub.add_parser("server-reply", help="explicit unavailable full-handshake boundary")
    args = parser.parse_args(argv)
    try:
        if args.command == "request":
            result, status = _request(_read_json(args.input), args.kind)
        elif args.command == "inner-reply":
            result, status = _inner_reply(_read_json(args.input))
        elif args.command == "server-reply":
            accept_server_handshake(b"")
        else:
            result, status = {
                "implemented": ["conditional Easy/Auth request codec", "preverified/decrypted handshake inner family model and ordered local publication", "stateful PrimarySigner.sign(command,payload) with explicit host profile and OS environment", "Windows WinDevice hardware/CAPI/profile.dat2 producer and checkpoint persistence"],
                "unavailable": ["unknown telemetry fields", "server handshake verification and decryption", "handshake login-record installation/persistence", "transport and scheduling", "independent QQ login"],
            }, 0
    except CapabilityUnavailable as exc:
        print(json.dumps({"error": "unavailable", "detail": str(exc)}), file=sys.stderr)
        return 3
    except (InputError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": "input", "detail": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
