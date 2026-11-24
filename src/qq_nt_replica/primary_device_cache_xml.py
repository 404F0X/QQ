from .primary_device_cache import _data, _length, _XmlString
from .primary_device_collector import _delete_array, _new_array
from .primary_logger import _cstring, _String
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _frame


_SPACE = b' \t\r\n'
_LIMIT = 1 << 20


class _ParseFailure(Exception):
    pass


class _Element:
    def __init__(self, runtime):
        self.runtime = runtime
        self.pointer = runtime._operator_new(144)
        self.name = _XmlString(runtime)
        self.attributes, self.children = [], []

    def destroy(self):
        for pointer, name, value in self.attributes:
            value.destroy()
            name.destroy()
            self.runtime._free_allocation(pointer)
        for child in self.children:
            child.destroy()
        self.name.destroy()
        self.runtime._free_allocation(self.pointer)


class _Parser:
    def __init__(self, runtime, raw, errors, *, text_factory=_XmlString, element_factory=_Element, attribute_allocator=None):
        self.text=text_factory;self.element_factory=element_factory;self.attribute_allocator=attribute_allocator
        self.runtime, self.raw, self.position = runtime, raw, 0
        self.errors, self.error, self.nodes = errors, self.text(runtime), 0

    def fail(self, code):
        if self.error.pointer is None:
            self.error = self.text(self.runtime, bytes.fromhex(self.errors[str(code)]).split(b'\0', 1)[0])
        raise _ParseFailure

    def whitespace(self):
        while self.position < len(self.raw) and self.raw[self.position] in _SPACE:
            self.position += 1

    def name(self, destination):
        start = self.position
        if start == len(self.raw):
            return False
        byte = self.raw[start]
        if not (65 <= byte <= 90 or 97 <= byte <= 122 or byte in b'_:' or byte >= 128):
            return False
        self.position += 1
        while self.position < len(self.raw):
            byte = self.raw[self.position]
            if not (65 <= byte <= 90 or 97 <= byte <= 122 or 48 <= byte <= 57 or byte in b'_:-.' or byte >= 128):
                break
            self.position += 1
        destination._replace(self.raw[start:self.position], self.position - start)
        return True

    def character(self):
        start = self.position
        raw = self.raw
        if raw[start] == 38:
            end = raw.find(b';', start + 1)
            if end >= 0:
                token = raw[start + 1:end]
                entities = {b'amp': b'&', b'lt': b'<', b'gt': b'>', b'quot': b'"', b'apos': b"'"}
                if token in entities:
                    self.position = end + 1
                    return entities[token]
                if token.startswith(b'#'):
                    try:
                        code = int(token[2:], 16) if token.startswith(b'#x') else int(token[1:], 10)
                        value = chr(code).encode('utf-8')
                    except (ValueError, UnicodeError):
                        raise PrimarySemanticUnavailable('device cache numeric XML entity requires recovered invalid-codepoint behavior') from None
                    self.position = end + 1
                    return value
        byte = raw[start]
        count = 2 if 0xC0 <= byte < 0xE0 else 3 if 0xE0 <= byte < 0xF0 else 4 if 0xF0 <= byte < 0xF8 else 1
        if start + count > len(raw):
            raise PrimarySemanticUnavailable('device cache XML has an incomplete UTF8 sequence')
        self.position += count
        return raw[start:self.position]

    def attribute(self, element):
        pointer = self.runtime._operator_new(64) if self.attribute_allocator is None else self.attribute_allocator()
        name, value = self.text(self.runtime), self.text(self.runtime)
        element.attributes.append((pointer, name, value))
        if not self.name(name):
            self.fail(6)
        self.whitespace()
        if self.raw[self.position:self.position + 1] != b'=':
            self.fail(6)
        self.position += 1
        self.whitespace()
        quote = self.raw[self.position:self.position + 1]
        if quote not in (b'"', b"'"):
            raise PrimarySemanticUnavailable('device cache unquoted XML attributes require their original parser behavior')
        self.position += 1
        while self.position < len(self.raw) and self.raw[self.position:self.position + 1] != quote:
            value.append(self.character())
        if self.position == len(self.raw):
            self.fail(6)
        self.position += 1
        if any(other.value() == name.value() for _, other, _ in element.attributes[:-1]):
            raise PrimarySemanticUnavailable('device cache duplicate XML attribute requires its original error ownership')

    def element(self):
        self.nodes += 1
        if self.nodes > 4096:
            raise PrimaryProgramLimit('device cache XML exceeds its bounded node count')
        element = self.element_factory(self.runtime)
        mark = None
        try:
            if self.raw[self.position:self.position + 1] != b'<':
                self.fail(3)
            self.position += 1
            self.whitespace()
            if not self.name(element.name):
                self.fail(4)
            mark = self.text(self.runtime, b'</')
            mark.append(element.name.value())
            while True:
                self.whitespace()
                if self.raw[self.position:self.position + 2] == b'/>':
                    self.position += 2
                    return element
                if self.raw[self.position:self.position + 1] == b'>':
                    self.position += 1
                    break
                if self.position == len(self.raw):
                    self.fail(3)
                self.attribute(element)
            while True:
                self.whitespace()
                if self.position == len(self.raw):
                    self.fail(5)
                if self.raw[self.position:self.position + 2] == b'</':
                    close = mark.value()
                    if self.raw[self.position:self.position + len(close)] != close:
                        self.fail(8)
                    self.position += len(close)
                    self.whitespace()
                    if self.raw[self.position:self.position + 1] != b'>':
                        self.fail(8)
                    self.position += 1
                    return element
                if self.raw[self.position:self.position + 1] == b'<' and self.raw[self.position:self.position + 2] not in (b'<!', b'<?'):
                    child = self.element()
                    element.children.append(child)
                else:
                    raise PrimarySemanticUnavailable('device cache XML text,comment,declaration or unknown node requires its original parser behavior')
        except _ParseFailure:
            self.failed_root = element
            raise
        finally:
            if mark is not None:
                mark.destroy()


def parse(runtime, manager, source):
    from .primary_device_cache import _cstring_assign, _image
    from .primary_device_identifiers import _cache_node

    size = _length(runtime, source) & 0xFFFFFFFF
    data = _data(runtime, source)
    if size >= 1 << 31 or size > _LIMIT:
        raise PrimaryProgramLimit('device cache XML input exceeds its bounded signed32 domain')
    errors = _image()['xml_errors']
    if not size or not data:
        _XmlString(runtime, bytes.fromhex(errors['2']).split(b'\0', 1)[0]).destroy()
        return None
    memory = runtime.memory
    normalized = _XmlString(runtime)
    normalized._replace(b'', size)
    pointer = _new_array(runtime, size + 1)
    raw = memory.read(data, size)
    memory.write(pointer, raw + b'\0', source='3C72A40.xml_file_copy')
    raw = raw.split(b'\0', 1)[0]
    start = index = 0
    while index < len(raw):
        if raw[index] == 13:
            if index > start:
                normalized.append(raw[start:index])
            normalized.append(b'\n')
            index += 2 if raw[index:index + 2] == b'\r\n' else 1
            start = index
        elif raw[index] == 10:
            normalized.append(raw[start:index + 1])
            index += 1
            start = index
        else:
            index += 1
    if index > start:
        normalized.append(raw[start:index])
    _delete_array(runtime, pointer)
    parser = _Parser(runtime, normalized.value(), errors)
    roots, success = [], True
    try:
        parser.whitespace()
        if not parser.raw:
            parser.fail(12)
        while parser.position < len(parser.raw) and parser.raw[parser.position:parser.position + 1] == b'<':
            if parser.raw[parser.position:parser.position + 2] in (b'<!', b'<?'):
                raise PrimarySemanticUnavailable('device cache XML document declaration or comment requires its original node behavior')
            roots.append(parser.element())
            parser.whitespace()
    except _ParseFailure:
        success = False
        if hasattr(parser, 'failed_root'):
            roots.append(parser.failed_root)
    normalized.destroy()
    if success and roots:
        tag = _cstring(runtime, runtime.image_base + 0x47A5084)
        key_name = _cstring(runtime, runtime.image_base + 0x46A38A2)
        value_name = _cstring(runtime, runtime.image_base + 0x47AB262)
        for element in roots[0].children:
            if element.name.value() != tag:
                continue
            attributes = {name.value(): value for _, name, value in element.attributes}
            if key_name not in attributes or value_name not in attributes:
                continue
            key = _String.construct(runtime, attributes[key_name].value().split(b'\0', 1)[0])
            node, inserted = _cache_node(runtime, manager, key, move=True)
            value = attributes[value_name]
            if value.pointer is None:
                frame, _ = _frame(runtime, 1, '35F78B0.empty_xml_attribute')
                memory.store(frame, 0, 1, source='35F78B0.empty_xml_value')
                _cstring_assign(runtime, node + 56, frame)
                memory.unmap(frame)
            else:
                _cstring_assign(runtime, node + 56, value.pointer + 16)
            if not inserted:
                key.destroy()
    parser.error.destroy()
    for root in roots:
        root.destroy()
    return None


class _OwnedText:
    def __init__(self,runtime,raw=None):self.raw=b'' if raw is None else raw;self.pointer=None if raw is None else True
    def value(self):return self.raw
    def _replace(self,raw,size):self.raw=bytes(raw[:size]);self.pointer=True
    def append(self,raw):self.raw+=raw;self.pointer=True
    def destroy(self):pass

class _OwnedElement:
    def __init__(self,runtime):self.name=_OwnedText(None);self.attributes=[];self.children=[]
    def destroy(self):pass

def parse_owned_cache_xml(raw):
    """Same parser/control grammar on owning Python nodes, no source allocations."""
    from .primary_device_cache import _image
    if type(raw)is not bytes or len(raw)>_LIMIT:raise PrimaryProgramLimit('cache XML input outside finite domain')
    raw=raw.split(b'\0',1)[0].replace(b'\r\n',b'\n').replace(b'\r',b'\n')
    parser=_Parser(None,raw,_image()['xml_errors'],text_factory=_OwnedText,element_factory=_OwnedElement,attribute_allocator=lambda:None)
    roots=[]
    try:
        parser.whitespace()
        if not parser.raw:parser.fail(12)
        while parser.position<len(parser.raw) and parser.raw[parser.position:parser.position+1]==b'<':
            if parser.raw[parser.position:parser.position+2] in (b'<!',b'<?'):raise PrimarySemanticUnavailable('device cache XML declaration/comment behavior unavailable')
            roots.append(parser.element());parser.whitespace()
    except _ParseFailure:return False,()
    pairs=[]
    if roots:
        for child in roots[0].children:
            if child.name.value()!=b'config':continue
            attributes={name.value():value.value() for _,name,value in child.attributes}
            if b'key'in attributes and b'value'in attributes:pairs.append((attributes[b'key'].split(b'\0',1)[0],attributes[b'value'].split(b'\0',1)[0]))
    return True,tuple(pairs)
