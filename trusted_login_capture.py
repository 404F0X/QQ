"""Private, local application-frame capture for one explicitly owned login attempt.

Nothing in this module sends data or changes a protocol result. Bundle contents
are credentials: only paths/status belong in ordinary output.
"""
import contextlib
import dataclasses
import hashlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
import time
import traceback
import types


CAPTURE_ROOT = Path('G:/Hackergame/.codex-workflow/reports/pmhq-analysis-20261010/signature-audit-20261119/trusted-local-captures')
EXPECTED = ('session.inputs', 'fetch.prepared', 'fetch.response', 'fetch.accepted',
    'poll.prepared', 'poll.response', 'poll.accepted', 'getface.request',
    'getface.response', 'ticket.prepared', 'ticket.request', 'ticket.response',
    'ticket.accepted', 'registration.prepared', 'registration.request',
    'registration.response', 'registration.accepted', 'sign.input', 'sign.result')


def source_identity(path):
    path = Path(path).resolve()
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


class LoginCapture:
    def __init__(self, root, *, login_root, inputs, parameters):
        root = Path(root).resolve()
        if root != CAPTURE_ROOT.resolve():
            raise ValueError('TRUSTED_CAPTURE_ROOT_REQUIRED')
        root.mkdir(parents=True, exist_ok=True)
        self.path = Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%d-%H%M%S-'), dir=root))
        self.login_root = Path(login_root).resolve()
        self.available, self.closed = True, False
        self.sequence = 0
        self.observed, self.failures, self.unserialized = [], [], []
        self.dto_types, self.reader_types = set(), set()
        self._profile_active = False
        self._events = (self.path / 'events.jsonl').open('x', encoding='utf-8')
        # Fail before authentication unless both binary and text IO work.
        probe = self.path / 'io-probe.bin'
        probe.write_bytes(b'\x00\xffcapture\x00')
        if probe.read_bytes() != b'\x00\xffcapture\x00':
            raise OSError('TRUSTED_CAPTURE_IO_CHECK')
        probe.unlink()
        self.log_path = self.path / 'private-output.log'
        self.log_path.open('xb').close()
        self.metadata = dict(format='trusted-login-capture/1', login_root=str(self.login_root),
            python=sys.version, inputs=source_identity(inputs),
            input_binding=json.loads(Path(inputs).read_bytes()), parameters=parameters,
            boundary='application frames; failed socket partial state is recorded separately, not a complete TCP trace',
            offline_only=False)
        self._manifest('open')

    def _manifest(self, status):
        document = dict(self.metadata, status=status, available=self.available,
            events=self.sequence, observed=self.observed,
            not_reached=[name for name in EXPECTED if name not in self.observed],
            unserialized=self.unserialized, capture_failures=self.failures)
        (self.path / 'manifest.json').write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')

    def _failed(self, operation, error):
        self.available = False
        self.failures.append(dict(operation=operation, type=type(error).__name__))

    def configure(self, *apis):
        """Register the actual selected ordinary DTO/Reader classes, not runtimes."""
        try:
            modules = set()
            for api in apis:
                for value in vars(api).values():
                    if isinstance(value, type):
                        module = sys.modules.get(value.__module__)
                        if module is not None:
                            modules.add(module)
            for module in modules:
                path = getattr(module, '__file__', None)
                if not path or not Path(path).resolve().is_relative_to(self.login_root):
                    continue
                for value in vars(module).values():
                    if isinstance(value, type) and value.__module__ == module.__name__:
                        if dataclasses.is_dataclass(value):
                            self.dto_types.add(value)
                        elif value.__name__ in ('Reader', '_Reader'):
                            self.reader_types.add(value)
        except BaseException as error:
            self._failed('configure', error)

    def _encode(self, value, location, seen):
        if value is None or type(value) in (bool, int, float, str):
            return value
        identity = id(value)
        if identity in seen:
            return {'$ref': seen[identity]}
        token = len(seen) + 1
        seen[identity] = token
        if type(value) in (bytes, bytearray):
            name = f'blob-{self.sequence:05d}-{token:04d}.bin'
            data = bytes(value)
            (self.path / name).write_bytes(data)
            return {'$id': token, '$bytes': name, 'length': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        if type(value) in (list, tuple, set, frozenset):
            return {'$id': token, '$sequence': type(value).__name__, 'items': [
                self._encode(item, location + f'[{i}]', seen) for i, item in enumerate(value)]}
        if type(value) in (dict, types.MappingProxyType):
            return {'$id': token, '$mapping': [
                [self._encode(key, location + '.key', seen), self._encode(item, location + f'.item{i}', seen)]
                for i, (key, item) in enumerate(value.items())]}
        kind = type(value)
        name = kind.__module__ + '.' + kind.__qualname__
        if kind in self.dto_types:
            return {'$id': token, '$dto': name, 'fields': {
                field.name: self._encode(getattr(value, field.name), location + '.' + field.name, seen)
                for field in dataclasses.fields(value)}}
        if kind in self.reader_types:
            return {'$id': token, '$reader': name, 'fields': {
                field: self._encode(getattr(value, field), location + '.' + field, seen)
                for field in ('value', 'offset')}}
        # No arbitrary repr, pickle, object dictionary, GUI or native handle dump.
        record = dict(location=location, type=name, reason='not an ordinary selected DTO/container')
        self.unserialized.append(record)
        return {'$id': token, '$unserialized': record}

    def record(self, label, **values):
        if self.closed:
            return
        self.sequence += 1
        try:
            encoded = self._encode(values, label, {})
            self._events.write(json.dumps(dict(index=self.sequence, label=label,
                monotonic=time.monotonic(), values=encoded)) + '\n')
            self._events.flush()
            if label not in self.observed:
                self.observed.append(label)
        except BaseException as error:
            self._failed(label, error)

    def exception(self, label, error):
        """Full private chain and business decoder locals; never stdout."""
        seen = set()
        def describe(current):
            if current is None:
                return None
            if id(current) in seen:
                return {'cycle': True}
            seen.add(id(current))
            frames, tb = [], current.__traceback__
            while tb is not None:
                frame = tb.tb_frame
                path = Path(frame.f_code.co_filename).resolve()
                item = dict(file=str(path), function=frame.f_code.co_name, line=tb.tb_lineno)
                if path.is_relative_to(self.login_root) and ('candidate' in path.parts or 'login119_overlay' in path.parts):
                    item['locals'] = dict(frame.f_locals)
                frames.append(item)
                tb = tb.tb_next
            return dict(type=type(current).__module__ + '.' + type(current).__qualname__,
                code=getattr(current, 'code', None), args=current.args,
                text=str(current), traceback=''.join(traceback.format_exception(current)), frames=frames,
                suppress_context=current.__suppress_context__, cause=describe(current.__cause__),
                context=describe(current.__context__))
        try:
            self.record(label, exception=describe(error))
        except BaseException as failure:
            self._failed('exception', failure)

    def effective_parser(self, method):
        """Record the effective FunctionType globals/closures, not just T's file."""
        seen, rows = set(), []
        dependencies = ('parse_login_response', 'decode_sso_response', '_shared_decode',
            'tea_decrypt', 'unpack_tlvs', '_error_info', 'raw', 'api')
        def visit(function):
            if not isinstance(function, types.FunctionType) or id(function) in seen:
                return
            seen.add(id(function))
            code = function.__code__
            row = dict(id=len(rows) + 1, module=function.__module__, name=function.__qualname__,
                code_name=code.co_name, line=code.co_firstlineno, source=source_identity(code.co_filename),
                defaults=function.__defaults__, kwdefaults=function.__kwdefaults__, globals={}, closure={})
            rows.append(row)
            for name in dict.fromkeys(code.co_names + dependencies):
                if name not in function.__globals__:
                    continue
                value = function.__globals__[name]
                if isinstance(value, types.FunctionType):
                    row['globals'][name] = dict(module=value.__module__, name=value.__qualname__,
                        source=source_identity(value.__code__.co_filename), line=value.__code__.co_firstlineno)
                    if name in dependencies and Path(value.__code__.co_filename).resolve().is_relative_to(self.login_root):
                        visit(value)
                elif isinstance(value, type):
                    binding = dict(module=value.__module__, name=value.__qualname__)
                    try:
                        binding['source'] = source_identity(inspect.getfile(value))
                    except (OSError, TypeError):
                        binding['source_unavailable'] = True
                    row['globals'][name] = binding
                elif isinstance(value, types.ModuleType):
                    binding = dict(module=value.__name__)
                    if getattr(value, '__file__', None):
                        binding['source'] = source_identity(value.__file__)
                    row['globals'][name] = binding
                else:
                    row['globals'][name] = value
            for name, cell in zip(code.co_freevars, function.__closure__ or ()):
                value = cell.cell_contents
                if isinstance(value, types.FunctionType):
                    row['closure'][name] = dict(module=value.__module__, name=value.__qualname__,
                        source=source_identity(value.__code__.co_filename), line=value.__code__.co_firstlineno)
                    if Path(value.__code__.co_filename).resolve().is_relative_to(self.login_root):
                        visit(value)
                elif name == 'scope' and type(value) is dict:
                    row['closure'][name] = dict(globals_clone_keys=sorted(value))
                else:
                    row['closure'][name] = value
            return row
        try:
            visit(method)
            self.record('effective.parser', callables=rows)
        except BaseException as error:
            self._failed('effective.parser', error)

    @contextlib.contextmanager
    def ticket_scope(self):
        """Only pure ticket acceptance, never signing/VM execution or the network."""
        previous = sys.getprofile()
        if previous is not None:
            self.unserialized.append(dict(location='ticket.profile', reason='existing profiler preserved'))
            yield
            return
        names = {'parse_login_response', 'tea_decrypt', 'unpack_tlvs', 'decode_sso_response', '_shared_decode'}
        def collect(frame, event, result):
            if event not in ('call', 'return') or frame.f_code.co_name not in names:
                return
            path = Path(frame.f_code.co_filename).resolve()
            if not path.is_relative_to(self.login_root):
                return
            layer = 'ticket.outer'
            caller = frame
            while caller is not None:
                if caller.f_code.co_name == 'parse_login_response' and 'encrypted' in caller.f_locals:
                    layer = 'ticket.inner0119'
                    break
                caller = caller.f_back
            self.record('ticket.decoder.' + event, function=frame.f_code.co_name,
                file=str(path), line=frame.f_code.co_firstlineno, layer=layer,
                locals=dict(frame.f_locals), result=result,
                return_none_may_be_exception_unwind=(event == 'return' and result is None))
        def observe(frame, event, result):
            try:
                collect(frame, event, result)
            except BaseException as error:
                self._failed('ticket.profile', error)
        try:
            self._profile_active = True
            sys.setprofile(observe)
            yield
        except BaseException as error:
            sys.setprofile(previous)
            self.exception('ticket.exception', error)
            raise
        finally:
            sys.setprofile(previous)
            self._profile_active = False

    def close(self):
        if self.closed:
            return
        try:
            self._events.close()
        except BaseException as error:
            self._failed('events.close', error)
        try:
            self._manifest('closed' if self.available else 'incomplete')
        except BaseException as error:
            self._failed('manifest.close', error)
        self.closed = True


def decode_value(value, directory, *, dto_types=None, references=None):
    """Decode our data format only; never import/pickle arbitrary captured types."""
    directory = Path(directory).resolve()
    references = {} if references is None else references
    dto_types = {} if dto_types is None else dto_types
    if type(value) is not dict:
        return value
    if '$ref' in value:
        return references[value['$ref']]
    if '$bytes' in value:
        path = (directory / value['$bytes']).resolve()
        if path.parent != directory:
            raise ValueError('CAPTURE_BLOB_PATH')
        result = path.read_bytes()
        if len(result) != value['length'] or hashlib.sha256(result).hexdigest() != value['sha256']:
            raise ValueError('CAPTURE_BLOB_CHANGED')
    elif '$mapping' in value:
        result = {}
        references[value['$id']] = result
        for key, item in value['$mapping']:
            result[decode_value(key, directory, dto_types=dto_types, references=references)] = decode_value(item, directory, dto_types=dto_types, references=references)
    elif '$sequence' in value:
        result = [decode_value(item, directory, dto_types=dto_types, references=references) for item in value['items']]
        if value['$sequence'] == 'tuple':
            result = tuple(result)
    elif '$dto' in value and value['$dto'] in dto_types:
        fields = {name: decode_value(item, directory, dto_types=dto_types, references=references) for name, item in value['fields'].items()}
        result = dto_types[value['$dto']](**fields)
    else:
        result = dict(value)
    if '$id' in value:
        references[value['$id']] = result
    return result


def ordered_tlvs(value):
    """Lossless structural view; never used to accept a live response."""
    rows, first, offset = [], {}, 2
    if len(value) < 2:
        return dict(count=None, entries=rows, tail=value, complete=False)
    count = int.from_bytes(value[:2], 'big')
    for index in range(count):
        if offset + 4 > len(value):
            break
        start = offset
        tag = int.from_bytes(value[offset:offset+2], 'big')
        length = int.from_bytes(value[offset+2:offset+4], 'big')
        offset += 4
        raw = value[offset:offset+length]
        row = dict(index=index, tag=tag, length=length, header_offset=start,
            value_offset=offset, complete=len(raw) == length, value=raw)
        if tag in first:
            prior = rows[first[tag]]
            row.update(first_index=first[tag], same_value=(prior['value'] == raw if prior['complete'] and row['complete'] else None))
        else:
            first[tag] = index
        rows.append(row)
        if not row['complete']:
            offset += len(raw)
            break
        offset += length
    return dict(count=count, entries=rows, tail=value[offset:], complete=len(rows) == count and all(r['complete'] for r in rows))
