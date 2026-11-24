"""Replay one private login capture locally. No login, SDK factory or network."""
import argparse
import contextlib
import dataclasses
import hashlib
import json
from pathlib import Path
import runpy
import sys
import time
import traceback
from types import MappingProxyType

from trusted_login_capture import CAPTURE_ROOT, decode_value, ordered_tlvs


def _no_io(event, args):
    if event in ('socket.connect', 'socket.getaddrinfo', 'socket.bind', 'socket.sendto', 'ctypes.dlopen', 'ctypes.dlsym'):
        raise RuntimeError('OFFLINE_REPLAY_EXTERNAL_IO_DENIED')


def _private_json(value):
    if value is None or type(value) in (bool, int, float, str):
        return value
    if type(value) is bytes:
        return {'hex': value.hex(), 'length': len(value)}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {'type': type(value).__module__ + '.' + type(value).__qualname__,
            'fields': {f.name: _private_json(getattr(value, f.name)) for f in dataclasses.fields(value)}}
    if type(value) in (dict, MappingProxyType):
        return {str(key): _private_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_private_json(item) for item in value]
    return {'unserialized_type': type(value).__module__ + '.' + type(value).__qualname__}


def replay(directory, *, execute_parser=True):
    directory = Path(directory).resolve()
    if not directory.is_relative_to(CAPTURE_ROOT.resolve()):
        raise ValueError('PRIVATE_CAPTURE_DIRECTORY_REQUIRED')
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    if manifest['format'] != 'trusted-login-capture/1':
        raise ValueError('CAPTURE_FORMAT')
    events = [json.loads(line) for line in (directory / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
    result = dict(offline=True, online_proof=False, material_B_proof=False,
        capture_available=manifest['available'], capture_status=manifest['status'],
        not_reached=manifest['not_reached'], unserialized=manifest['unserialized'],
        ordered_tlvs=[], parser_runs=[])
    for event in events:
        if event['label'] == 'effective.parser':
            bindings = decode_value(event['values'], directory)
            for row in bindings['callables']:
                for identity in [row['source']] + [v['source'] for v in list(row['globals'].values()) + list(row['closure'].values()) if type(v) is dict and 'source' in v]:
                    if hashlib.sha256(Path(identity['path']).read_bytes()).hexdigest() != identity['sha256']:
                        raise ValueError('EFFECTIVE_PARSER_SOURCE_CHANGED')
    for event in events:
        if event['label'] != 'ticket.decoder.call':
            continue
        value = decode_value(event['values'], directory)
        if value['function'] == 'unpack_tlvs' and type(value['locals'].get('value')) is bytes:
            result['ordered_tlvs'].append(dict(layer=value['layer'],
                event=event['index'], structure=ordered_tlvs(value['locals']['value'])))
    if execute_parser:
        # These are the existing selected pure Python loaders and normal parser
        # composition. No Windows owner/factory is created.
        login_root = Path(manifest['login_root']).resolve()
        sys.path.insert(0, str(login_root))
        try:
            runpy.run_path(str(login_root / 'G/entry.py'))['load_api']()
            from login119_overlay import make_login_parser
            T = sys.modules['independent_login_ticket_exchange']
            types = {}
            for module in tuple(sys.modules.values()):
                path = getattr(module, '__file__', None)
                if path and Path(path).resolve().is_relative_to(login_root):
                    for cls in vars(module).values():
                        if isinstance(cls, type) and dataclasses.is_dataclass(cls):
                            types[cls.__module__ + '.' + cls.__qualname__] = cls
            for event in events:
                if event['label'] != 'ticket.decoder.call':
                    continue
                value = decode_value(event['values'], directory, dto_types=types)
                if value['function'] != 'parse_login_response':
                    continue
                local = value['locals']
                for name, parser in [('current_base_strict', T.parse_login_response),
                                     ('normal_worker_reference', make_login_parser(T.parse_login_response))]:
                    run = dict(parser=name, source_event=event['index'])
                    try:
                        output = parser(local['value'], device=local['device'], tickets=local['tickets'])
                        run.update(returned=True, result=output)
                    except BaseException as error:
                        run.update(returned=False, error_type=type(error).__name__,
                            code=getattr(error, 'code', None), traceback=''.join(traceback.format_exception(error)))
                    result['parser_runs'].append(run)
                break
        finally:
            sys.path.remove(str(login_root))
    result['replay_inputs_available'] = bool(result['parser_runs'])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--structure-only', action='store_true')
    options = parser.parse_args(argv)
    directory = options.directory.resolve()
    if not directory.is_relative_to(CAPTURE_ROOT.resolve()):
        parser.error('only the private capture root is accepted')
    token = time.time_ns()
    target = directory / f'offline-replay-{token}.json'
    sys.addaudithook(_no_io)
    with (directory / f'offline-replay-{token}.log').open('x', encoding='utf-8') as log:
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            try:
                result = replay(directory, execute_parser=not options.structure_only)
            except BaseException as error:
                result = dict(offline=True, online_proof=False, material_B_proof=False,
                    replay_failed=True, error_type=type(error).__name__,
                    traceback=''.join(traceback.format_exception(error)))
            with target.open('x', encoding='utf-8') as output:
                json.dump(_private_json(result), output, indent=2)
    # Never print the report body, keys, error text or material.
    print(json.dumps(dict(offline=True, report=str(target),
        replay_failed=result.get('replay_failed', False),
        parser_codes=[run.get('code') for run in result.get('parser_runs', [])])))
    return 1 if result.get('replay_failed') else 0


if __name__ == '__main__':
    raise SystemExit(main())
