import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path


MAJOR_SHA256 = '3fdc17fa0512fd4b702f34a0025ffe4eca0a5c70229872f7fc0a0324bdfb5fdf'
QQNT_SHA256 = 'f6f35b8517da5c38ace8d4b6abad1abed42f61c8e706d23192a22d91c7620e59'
CACHE_SHA256 = '9b286999ef39ed2252969b8a37b9871170fa45b8a3984879b76e64342b084255'
CACHE_OFFSET = 0x11C4D0
CACHE_SIZE = 5689992
DEFAULT_MAJOR = Path('D:/QQ/versions/9.9.33-52230/resources/app/major.node')


class SourceConfigError(ValueError):
    pass


@dataclass(repr=False)
class CacheSymbols:
    objects: list = field(repr=False)
    root: dict = field(repr=False)
    consumed: int
    opaque_tail: bytes = field(repr=False)

    def __repr__(self):
        return f'CacheSymbols(objects={len(self.objects)}, consumed={self.consumed}, opaque_tail_length={len(self.opaque_tail)})'


class _Reader:
    def __init__(self, data, max_objects, max_steps):
        self.data = data
        self.p = 0
        self.objects = []
        self.hot = [None] * 8
        self.hot_next = 0
        self.max_objects = max_objects
        self.remaining = max_steps

    def take(self, size):
        if size < 0 or size > len(self.data) - self.p:
            raise SourceConfigError('truncated serialized data')
        start = self.p
        self.p += size
        return self.data[start:self.p]

    def uint30(self):
        if self.p >= len(self.data):
            raise SourceConfigError('truncated uint30')
        return int.from_bytes(self.take((self.data[self.p] & 3) + 1), 'little') >> 2

    def add_hot(self, value):
        self.hot[self.hot_next] = value
        self.hot_next = (self.hot_next + 1) % 8

    def value(self):
        self.remaining -= 1
        if self.remaining < 0:
            raise SourceConfigError('serialized operation budget exceeded')
        at = self.p
        tag = self.take(1)[0]
        if tag <= 3:
            size = self.uint30() * 4
            if size < 4 or size > len(self.data):
                raise SourceConfigError('invalid object size')
            obj = {'at': at, 'size': size, 'f': []}
            obj['map'] = yield
            if len(self.objects) >= self.max_objects:
                raise SourceConfigError('serialized object budget exceeded')
            obj['id'] = len(self.objects)
            self.objects.append(obj)
            filled = 4
            while filled < size:
                value = yield
                obj['f'].append((filled, value))
                filled += value.get('width', 4)
            if filled != size:
                raise SourceConfigError('serialized object slot overflow')
            obj['end'] = self.p
            return {'obj': obj}
        if tag == 5:
            return {'readonly_page': self.uint30(), 'readonly_offset': self.uint30()}
        if tag in (4, 6, 7, 8, 9):
            index = self.uint30()
            value = {'ref': tag, 'id': index}
            if tag == 4:
                if index >= len(self.objects):
                    raise SourceConfigError('invalid back reference')
                value['obj'] = self.objects[index]
                self.add_hot(value)
            elif tag == 7:
                self.add_hot(value)
            return value
        if tag in (0x1d, 0x21, 0x18):
            value = yield
            return {'weak': value} if tag == 0x18 else {'prefix': tag, 'value': value}
        if tag == 0x1e:
            return {'self': True}
        if tag == 0x1a:
            return {'resolve': self.uint30(), 'width': 0}
        if tag == 0x19:
            return {'pending': True}
        if tag == 0x17:
            return {'clearedweak': True}
        if tag == 0x0a:
            return {'nop': True, 'width': 0}
        if tag == 0x11 or 0x60 <= tag <= 0x7f:
            size = self.uint30() * 4 if tag == 0x11 else (tag - 0x60 + 1) * 4
            start = self.p
            return {'raw': self.take(size), 'at': start, 'width': size}
        if 0x40 <= tag <= 0x5f:
            return {'root': tag - 0x40}
        if 0x90 <= tag <= 0x97:
            value = self.hot[tag - 0x90]
            if value is None:
                raise SourceConfigError('uninitialized hot reference')
            return value
        if tag == 0x0c or 0x80 <= tag <= 0x8f:
            count = self.uint30() + 18 if tag == 0x0c else tag - 0x80 + 2
            return {'repeat': count, 'root': self.take(1)[0], 'width': count * 4}
        raise SourceConfigError(f'unsupported serialized tag at payload offset {at}')

    def read(self):
        stack = [self.value()]
        value = None
        while stack:
            try:
                stack[-1].send(value)
                stack.append(self.value())
                value = None
            except StopIteration as finished:
                stack.pop()
                value = finished.value
        return value


def parse_cached_data(blob, *, max_objects=200000, max_steps=4000000):
    if not isinstance(blob, bytes):
        raise TypeError('cached data must be bytes')
    if len(blob) < 32:
        raise SourceConfigError('truncated cached data header')
    header = struct.unpack('<8I', blob[:32])
    if header[0] != 0xC0DE0674:
        raise SourceConfigError('unsupported cached data magic')
    if header[1] != 0x12819A30:
        raise SourceConfigError('unsupported cached data version')
    if header[3:5] != (0x265B14D1, 3768945873) or header[6:] != (0, 0):
        raise SourceConfigError('unsupported cached data build header')
    if header[5] != len(blob) - 32:
        raise SourceConfigError('cached data payload length mismatch')
    reader = _Reader(blob[32:], max_objects, max_steps)
    root = reader.read()
    return CacheSymbols(reader.objects, root, reader.p, reader.data[reader.p:])


def _root(value):
    return value.get('root', value.get('id') if value.get('ref') == 7 else None)


def _slots(obj):
    result = {}
    for offset, value in obj['f']:
        if 'raw' in value:
            for i in range(0, len(value['raw']), 4):
                result[offset + i] = {'smi': int.from_bytes(value['raw'][i:i + 4], 'little', signed=True) >> 1}
        elif 'repeat' in value:
            for i in range(value['repeat']):
                result[offset + 4 * i] = {'root': value['root']}
        elif value.get('width', 4):
            result[offset] = value
    return result


def _text(value):
    obj = value.get('obj')
    if obj is None or _root(obj['map']) != 16:
        raise SourceConfigError('unsupported source string representation')
    fields = dict(obj['f'])
    raw = fields.get(4, {}).get('raw', b'')
    if len(raw) < 8:
        raise SourceConfigError('truncated source string')
    size = int.from_bytes(raw[4:8], 'little')
    if size > len(raw) - 8:
        raise SourceConfigError('invalid source string length')
    return raw[8:8 + size], CACHE_OFFSET + 32 + fields[4]['at'] + 8


@dataclass(frozen=True)
class SourceFact:
    name: str
    provenance: str
    status: str
    source_offset: int | None
    value: bytes | None = field(default=None, repr=False)

    def metadata(self):
        return {'field': self.name, 'provenance': self.provenance, 'status': self.status,
                'source_offset': self.source_offset,
                'length': None if self.value is None else len(self.value),
                'sha256': None if self.value is None else hashlib.sha256(self.value).hexdigest()}


@dataclass(frozen=True)
class SourceProfile:
    facts: tuple[SourceFact, ...]
    object_count: int
    opaque_tail_length: int

    def metadata(self):
        return {'status': 'fixed-source-default-only', 'effective_runtime': 'unresolved',
                'object_count': self.object_count, 'opaque_tail_length': self.opaque_tail_length,
                'fields': [fact.metadata() for fact in self.facts]}


def inspect_source_bytes(major, qqnt):
    if hashlib.sha256(major).hexdigest() != MAJOR_SHA256:
        raise SourceConfigError('fixed major source identity mismatch')
    if hashlib.sha256(qqnt).hexdigest() != QQNT_SHA256:
        raise SourceConfigError('fixed QQNT source identity mismatch')
    blob = major[CACHE_OFFSET:CACHE_OFFSET + CACHE_SIZE]
    if hashlib.sha256(blob).hexdigest() != CACHE_SHA256:
        raise SourceConfigError('fixed cached data identity mismatch')
    symbols = parse_cached_data(blob)
    if len(symbols.objects) != 126950 or len(symbols.opaque_tail) != 634:
        raise SourceConfigError('fixed source root boundary mismatch')
    by_offset = {CACHE_OFFSET + 32 + obj['at']: obj for obj in symbols.objects}
    boilerplate = by_offset[0x3624B4]
    if (_root(boilerplate['map']) != 70 or boilerplate['size'] != 96
            or boilerplate['end'] + CACHE_OFFSET + 32 != 0x3625CE
            or hashlib.sha256(major[0x3624B4:0x3625CE]).hexdigest() !=
            'ed0fa8d07f24ce0faca35fd07d81f7db03364ccfda8f3687e9bc1fbc71644dab'):
        raise SourceConfigError('fixed source boilerplate mismatch')
    slots = _slots(boilerplate)
    if [slots[i]['smi'] for i in (4, 8, 12)] != [20, 10, 8]:
        raise SourceConfigError('fixed source boilerplate layout mismatch')
    pairs = {}
    for offset in range(16, 96, 8):
        key, _ = _text(slots[offset])
        pairs[key] = slots[offset + 4]
    qua, origin = _text(pairs[b'qua'])
    if len(qua) != 27 or hashlib.sha256(qua).hexdigest() != '5d522859bd81b6ac77254548c771c630938294333fce9ef64fbc3dcd32943fb8':
        raise SourceConfigError('fixed source QUA mismatch')
    for offset, length, expected in (
            (0x3626BC, 143, '27867d60da3fdb9a83b10fe4fc4077a7ac280bb40f56dbceeb7abd775807430c'),
            (0x362CAD, 167, '200628e2ffa2aa85327ddacc4cd7e28ac0fb314f7bade1bb5074ea361aac2f46'),
            (0x363162, 56, '85f880e9e6bbc9babcd3f3b5b2022c2d20b9e3d08ba61d062b5c5b552cd09951'),
            (0x363024, 72, '72547726c94ef99696b8d08bb282a8d228c30501445ea79e4a5d2090fb841e4e')):
        if hashlib.sha256(major[offset:offset + length]).hexdigest() != expected:
            raise SourceConfigError('fixed source function identity mismatch')
    main_bc = by_offset[0x362437]
    main_cp = dict(main_bc['f'])[24].get('value', {}).get('obj')
    if (_root(main_bc['map']) != 49 or main_cp is None
            or _root(main_cp['map']) != 107 or _slots(main_cp)[16].get('obj') is not boilerplate):
        raise SourceConfigError('fixed constructor CP2 boilerplate mismatch')
    for sfi_offset, code_offset, expected_length in (
            (0x362433, 0x3626BC, 143), (0x362AA3, 0x362CAD, 167),
            (0x3630DA, 0x363162, 56), (0x362F78, 0x363024, 72)):
        function = by_offset[sfi_offset]
        bytecode = dict(function['f'])[4].get('value', {}).get('obj')
        if _root(function['map']) != 17 or bytecode is None or _root(bytecode['map']) != 49:
            raise SourceConfigError('fixed source function object mismatch')
        fields = dict(bytecode['f'])
        length = int.from_bytes(fields[8]['raw'], 'little', signed=True) >> 1
        raw = fields[28]
        if (length != expected_length or len(raw['raw']) < 12 + length
                or raw['at'] + CACHE_OFFSET + 32 + 12 != code_offset
                or raw['raw'][12:12 + length] != major[code_offset:code_offset + length]):
            raise SourceConfigError('fixed source bytecode layout mismatch')
    sfi = by_offset[0x362AA3]
    if _root(sfi['map']) != 17:
        raise SourceConfigError('fixed default function map mismatch')
    default_bc = dict(sfi['f'])[4].get('value', {}).get('obj')
    if default_bc is None or _root(default_bc['map']) != 49:
        raise SourceConfigError('fixed default bytecode map mismatch')
    cp = dict(default_bc['f'])[24].get('value', {}).get('obj')
    if cp is None:
        raise SourceConfigError('fixed default constant pool missing')
    default_templates = []
    for value in _slots(cp).values():
        obj = value.get('obj')
        if obj is not None and _root(obj['map']) == 70:
            template = _slots(obj)
            for offset in range(16, obj['size'], 8):
                key, _ = _text(template[offset])
                if key in (b'selfUin', b'selfUid', b'machineId'):
                    if _root(template[offset + 4]) != 5:
                        raise SourceConfigError('fixed default empty-string root mismatch')
                    default_templates.append(key)
    if set(default_templates) != {b'selfUin', b'selfUid', b'machineId'}:
        raise SourceConfigError('fixed default profile fields missing')
    return SourceProfile((SourceFact('qua', 'source-default', 'template-literal; effective-runtime-unresolved', origin, qua),
                          SourceFact('selfUin', 'caller-dependent', 'source-default-empty; runtime-unresolved', 0x362CAD, b''),
                          SourceFact('selfUid', 'caller-dependent', 'source-default-empty; runtime-unresolved', 0x362CAD, b''),
                          SourceFact('machineId', 'caller-dependent', 'source-default-empty; runtime-unresolved', 0x362CAD, b''),
                          SourceFact('qimei', 'SDK-produced', 'unresolved; external-SDK-response-required', None)),
                         len(symbols.objects), len(symbols.opaque_tail))


def inspect_fixed_source(major_path=DEFAULT_MAJOR, qqnt_path=None):
    major_path = Path(major_path)
    qqnt_path = major_path.parents[2] / 'QQNT.dll' if qqnt_path is None else Path(qqnt_path)
    return inspect_source_bytes(major_path.read_bytes(), qqnt_path.read_bytes())
