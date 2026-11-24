import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_collector import _delete_array, _new_array, _terminated
from .primary_logger import _cstring, _String, _Tree, log
from .primary_memory import UnknownMemory
from .primary_sdk import assign_string
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_response import _frame


_IMAGE_SHA256 = '71099c6874f7938f5849d8e18f1050f2ea16c8181a58ccb688c36abf79e94104'
_LIMIT = 1 << 20
_MASK64 = (1 << 64) - 1
_IMPORTS = {'CreateFileW': 0x490FC40, 'GetLastError': 0x490FEA8, 'ReadFile': 0x4910288,
            'WriteFile': 0x4910470, 'FlushFileBuffers': 0x490FD58, 'CloseHandle': 0x490FBD8,
            'GetFileSize': 0x490FE78, 'CreateDirectoryW': 0x490FC08,
            'SHGetFolderPathW': 0x49107E0, 'PathFileExistsW': 0x4910AA8, 'Sleep': 0x4910368}


def _image():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230/device-cache-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device cache image identity mismatch')
    return json.loads(raw)


def install_image(memory, image_base):
    image = _image()
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device cache import identity mismatch')
    for segment in image['segments']:
        memory.map(image_base + segment['rva'], bytearray.fromhex(segment['hex']),
                   name='fixed observed device cache image', initialized=True)


def _observe(runtime, name, arguments):
    from .primary_device_collector import _IMPORTS as conversion_imports

    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + (_IMPORTS | conversion_imports)[name], 8) != expected:
        raise PrimarySemanticUnavailable('device cache current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device cache OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _plain(runtime, name, arguments):
    result, raw = _observe(runtime, name, arguments)
    if not isinstance(raw, bytes) or raw:
        raise InputError('device cache API has no output buffer: ' + name)
    return result


def _log(runtime, line, *values):
    item = _image()['logs'].get(str(line))
    if item is None:
        raise PrimarySemanticUnavailable('device cache log metadata has not been restored')
    runtime.events.append(('device.identifier_log', 'secconfig_center.cpp', line))
    return log(runtime, bytes.fromhex(item['source_file_hex']), line, bytes.fromhex(item['template_hex']),
               bytes.fromhex(item['tag_hex']), item['severity'], *values)


def _length(runtime, address):
    tag = runtime.memory.load(address, 1)
    return runtime.memory.load(address + 8, 8) if tag & 1 else tag >> 1


def _data(runtime, address, unit=1):
    return runtime.memory.load(address + 16, 8) if runtime.memory.load(address, 1) & 1 else address + unit


def _cstring_assign(runtime, destination, source):
    return assign_string(runtime, destination, source, len(_cstring(runtime, source)))


class _WideString(_String):
    @classmethod
    def construct(cls, runtime, value, capacity=None):
        if len(value) & 1:
            raise InputError('device cache wide String requires raw UTF16 units')
        size = len(value) // 2
        required = size if capacity is None else capacity
        if not size <= required <= _LIMIT // 2:
            raise PrimaryProgramLimit('device cache wide String exceeds its bounded offline domain')
        result = cls(runtime)
        if required <= 10:
            result.set(0, bytes([size * 2]))
            result.set(2, value + b'\0\0')
        else:
            units = (required | 7) + 1
            from .primary_worker_consumer import _invoke
            pointer = _invoke(runtime, 0xB75000, 2 * units)
            result.set(0, (units | 1).to_bytes(8, 'little'))
            result.set(8, size.to_bytes(8, 'little'))
            result.set(16, pointer.to_bytes(8, 'little'))
            runtime.memory.write(pointer, value + b'\0\0', source='device.cache_wide_payload')
        return result

    def value(self):
        if self.get(0, 1) & 1:
            size, pointer = self.get(8, 8), self.get(16, 8)
            if size > _LIMIT // 2:
                raise PrimaryProgramLimit('device cache current wide String exceeds its bounded offline domain')
            return self.runtime.memory.read(pointer, 2 * size)
        size = self.get(0, 1) >> 1
        if size > 10 or not all(self.known[2:2 + 2 * size]):
            raise UnknownMemory('device cache reads an unknown short wide String')
        return bytes(self.header[2:2 + 2 * size])


def crypt(runtime, key, key_length, destination, capacity, source, length, *, decode=False):
    def signed(value):
        value &= 0xFFFFFFFF
        return value if value < 1 << 31 else value - (1 << 32)

    key_length, capacity, length = map(signed, (key_length, capacity, length))
    third, fifth = (destination, source) if decode else (source, destination)
    for error, invalid in enumerate((not key, key_length <= 0, not third, capacity <= 0,
                                     not fifth, length <= 0, capacity < length), 1):
        if invalid:
            return (-error) & 0xFFFFFFFF
    if length > _LIMIT:
        raise PrimaryProgramLimit('device cache cipher exceeds its bounded offline domain')
    memory = runtime.memory
    state, index = list(range(256)), 0
    for position in range(256):
        index = (index + state[position] + memory.load(key + position % key_length, 1)) & 255
        state[position], state[index] = state[index], state[position]
    first = second = 0
    for position in range(length):
        first = (first + 1) & 255
        second = (second + state[first]) & 255
        state[first], state[second] = state[second], state[first]
        value = memory.load(source + position, 1) ^ state[(state[first] + state[second]) & 255]
        memory.store(destination + position, value, 1, source='3C71980.RC4' if decode else '3C71760.RC4')
    return 0


def _folder(runtime):
    result, raw = _observe(runtime, 'SHGetFolderPathW', (0, 26, 0, 0, 260))
    if not isinstance(raw, bytes) or len(raw) > 520 or len(raw) & 1:
        raise InputError('device cache folder query requires bounded raw UTF16 effects')
    if result & 0x80000000:
        return _WideString.construct(runtime, b''), 0
    terminator = next((i for i in range(0, len(raw), 2) if raw[i:i + 2] == b'\0\0'), None)
    if terminator is None:
        raise UnknownMemory('successful device cache folder query has no observed UTF16 terminator')
    memory, base = runtime.memory, runtime.image_base
    if memory.load(base + 0x6749CC0, 8) or memory.load(base + 0x6D8E630, 4):
        raise PrimarySemanticUnavailable('device cache path requires its observed default CRT formatting state')
    template = _terminated(runtime, base + 0x4904E18, 2)[:-2].decode('utf-16-le')
    if template.count('%s') != 1 or '%' in template.replace('%s', ''):
        raise PrimarySemanticUnavailable('device cache path format requires recovered wide printf conversions')
    narrow = raw[:terminator + 2].split(b'\0', 1)[0]
    value = template.replace('%s', ''.join(chr(x) for x in narrow)).encode('utf-16-le')
    if len(value) >= 520:
        raise PrimarySemanticUnavailable('device cache path formatting overflow requires its actual CRT error effects')
    return _WideString.construct(runtime, value, max(20, len(value) // 2) if len(value) > 20 else None), 1


def cache_filename(runtime, manager, destination):
    folder, result = _folder(runtime)
    value = folder.value()
    if not value:
        folder.destroy()
        return result
    suffix = _terminated(runtime, runtime.image_base + 0x4903FEC, 2)[:-2]
    output = _WideString.construct(runtime, value + suffix, len(value) // 2 + len(suffix) // 2)
    _WideString.read(runtime, destination).destroy()
    output.write_to(destination)
    directory = value + b'\0\0'
    if not _plain(runtime, 'PathFileExistsW', (directory,)) & 0xFFFFFFFF:
        if not _plain(runtime, 'CreateDirectoryW', (directory, 0)) & 0xFFFFFFFF:
            _log(runtime, 178, _plain(runtime, 'GetLastError', ()))
            folder.destroy()
            return 0
    filename = _terminated(runtime, _data(runtime, destination, 2), 2)
    result = _plain(runtime, 'PathFileExistsW', (filename,)) & 0xFFFFFFFF
    if not result:
        frame, _ = _frame(runtime, 24, '35F7FE0.cache_xml_frame')
        runtime.memory.write(frame, bytes(24), source='35F7FE0.empty_xml')
        serialize(runtime, manager, frame)
        result = write_file(runtime, 0, destination, frame)
        if not result:
            _log(runtime, 187, _plain(runtime, 'GetLastError', ()))
        _String.read(runtime, frame).destroy()
        runtime.memory.unmap(frame)
    folder.destroy()
    return int(bool(result))


def _wide_to_ansi(runtime, source, destination):
    value = _terminated(runtime, _data(runtime, source, 2), 2)
    result, raw = _observe(runtime, 'WideCharToMultiByte', (0, 0, value, -1, False, 0, 0, 0))
    if not isinstance(raw, bytes) or raw:
        raise InputError('device cache filename size query has no destination effects')
    count = result & 0xFFFFFFFF
    if not 0 < count < 1 << 31:
        return
    pointer = _new_array(runtime, count)
    runtime.memory.write(pointer, bytes(count), source='2E099B0.cache_conversion_zero')
    _, raw = _observe(runtime, 'WideCharToMultiByte', (0, 0, value, -1, True, count, 0, 0))
    if not isinstance(raw, bytes) or len(raw) > count:
        raise InputError('device cache filename conversion requires bounded raw output effects')
    runtime.memory.write(pointer, raw, source='2E099DC.cache_conversion_output')
    runtime.memory.store(pointer + count - 1, 0, 1, source='2E099E5.cache_conversion_nul')
    _cstring_assign(runtime, destination, pointer)
    _delete_array(runtime, pointer)


def write_file(runtime, ignored, filename, value):
    size = _length(runtime, value)
    if not size:
        _log(runtime, 266)
        return 0
    if size > _LIMIT:
        raise PrimaryProgramLimit('device cache file output exceeds its bounded offline domain')
    name = _terminated(runtime, _data(runtime, filename, 2), 2)
    handle = _plain(runtime, 'CreateFileW', (name, 0x40000000, 2, 0, 2, 0x80, 0))
    if handle == _MASK64:
        _log(runtime, 278)
        return 0
    pointer = runtime._operator_new(size)
    runtime.memory.write(pointer, bytes(size), source='35F962E.cache_cipher_zero')
    crypt(runtime, runtime.image_base + 0x4697CC4, 38, pointer, size, _data(runtime, value), size)
    ciphertext = runtime.memory.read(pointer, size)
    result = 1
    for payload, failed_line, short_line in ((hashlib.md5(ciphertext).digest(), 303, 309), (ciphertext, 318, 323)):
        success, raw = _observe(runtime, 'WriteFile', (handle, payload, len(payload), 0))
        if not isinstance(raw, bytes) or len(raw) != 4:
            raise InputError('device cache write requires its observed DWORD byte count')
        count = int.from_bytes(raw, 'little')
        if not success & 0xFFFFFFFF:
            _log(runtime, failed_line, _plain(runtime, 'GetLastError', ()))
            result = 0
            break
        if count != len(payload):
            _log(runtime, short_line, count)
            result = 0
            break
    if result:
        _plain(runtime, 'FlushFileBuffers', (handle,))
    _plain(runtime, 'CloseHandle', (handle,))
    if result:
        _log(runtime, 329)
    runtime._free_allocation(pointer)
    return result


def _read(runtime, handle, pointer, count):
    result, effects = _observe(runtime, 'ReadFile', (handle, count, 0))
    if (not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], bytes) or
            type(effects[1]) is not int or not 0 <= effects[1] <= count or len(effects[0]) != effects[1]):
        raise InputError('device cache read requires bounded bytes and an observed DWORD byte count')
    runtime.memory.write(pointer, effects[0], source='device.cache_ReadFile_output')
    return bool(result & 0xFFFFFFFF) and effects[1] == count


def read_file(runtime, manager, destination):
    memory = runtime.memory
    frame, _ = _frame(runtime, 80, '35F55D0.cache_reader_frame')
    memory.write(frame, bytes(48), source='35F55D0.empty_filename_and_ansi')
    cache_filename(runtime, manager, frame)
    _wide_to_ansi(runtime, frame, frame + 24)
    _log(runtime, 199, _data(runtime, frame + 24))
    _String.read(runtime, frame + 24).destroy()
    filename = _terminated(runtime, _data(runtime, frame, 2), 2)
    result, handle, pointer = 0, None, None
    if not _plain(runtime, 'PathFileExistsW', (filename,)) & 0xFFFFFFFF:
        _log(runtime, 201)
    else:
        for _ in range(10):
            opened = _plain(runtime, 'CreateFileW', (filename, 0x80000000, 1, 0, 3, 0x80, 0))
            if opened != _MASK64:
                handle = opened
                break
            _log(runtime, 209, _plain(runtime, 'GetLastError', ()))
            _plain(runtime, 'Sleep', (1,))
        if handle is not None:
            size = _plain(runtime, 'GetFileSize', (handle, 0)) & 0xFFFFFFFF
            if size == 0xFFFFFFFF:
                _log(runtime, 220, _plain(runtime, 'GetLastError', ()), size)
            else:
                memory.write(frame + 48, bytes(16), source='35F55D0.header_zero')
                if not _read(runtime, handle, frame + 48, 16):
                    _log(runtime, 229, _plain(runtime, 'GetLastError', ()))
                else:
                    count = (size - 16) & 0xFFFFFFFF
                    if count >= _LIMIT:
                        raise PrimaryProgramLimit('device cache file input exceeds its bounded offline domain')
                    pointer = runtime._operator_new(count + 1)
                    memory.write(pointer, bytes(count + 1), source='35F6304.cache_payload_zero')
                    if not _read(runtime, handle, pointer, count):
                        _log(runtime, 237, _plain(runtime, 'GetLastError', ()))
                    elif hashlib.md5(memory.read(pointer, count)).digest() != memory.read(frame + 48, 16):
                        _log(runtime, 247)
                    elif crypt(runtime, runtime.image_base + 0x4697CC4, 38, pointer, count, pointer, count, decode=True):
                        _log(runtime, 254)
                    else:
                        _cstring_assign(runtime, destination, pointer)
                        result = 1
            _plain(runtime, 'CloseHandle', (handle,))
    if pointer is not None:
        runtime._free_allocation(pointer)
    _WideString.read(runtime, frame).destroy()
    memory.unmap(frame)
    return result


class _XmlString:
    def __init__(self, runtime, value=b''):
        self.runtime, self.pointer, self.capacity = runtime, None, 0
        if value:
            self._replace(value, len(value))

    def value(self):
        if self.pointer is None:
            return b''
        memory = self.runtime.memory
        return memory.read(self.pointer + 16, memory.load(self.pointer, 8))

    def _replace(self, value, capacity):
        pointer = _new_array(self.runtime, (capacity + 27) & ~3)
        memory = self.runtime.memory
        memory.store(pointer, len(value), 8, source='3C74000.xml_string_size')
        memory.store(pointer + 8, capacity, 8, source='3C74000.xml_string_capacity')
        memory.write(pointer + 16, value + b'\0', source='3C74000.xml_string_payload')
        self.destroy()
        self.pointer, self.capacity = pointer, capacity

    def append(self, value):
        previous = self.value()
        size = len(previous) + len(value)
        if size > _LIMIT:
            raise PrimaryProgramLimit('device cache XML printer exceeds its bounded offline domain')
        if size > self.capacity:
            self._replace(previous, size + self.capacity)
        if self.pointer is not None:
            memory = self.runtime.memory
            memory.write(self.pointer + 16 + len(previous), value + b'\0', source='3C740B0.xml_append')
            memory.store(self.pointer, size, 8, source='3C740B0.xml_append_size')

    def destroy(self):
        if self.pointer is not None:
            _delete_array(self.runtime, self.pointer)
            self.pointer, self.capacity = None, 0


def _encode_attribute(runtime, value):
    result = _XmlString(runtime)
    entities = {38: b'&amp;', 60: b'&lt;', 62: b'&gt;', 34: b'&quot;', 39: b'&apos;'}
    index = 0
    while index < len(value):
        byte = value[index]
        if value[index:index + 3] == b'&#x':
            end = value.find(b';', index + 3)
            if end >= 0:
                for unit in value[index:end + 1]:
                    result.append(bytes([unit]))
                index = end + 1
                continue
        result.append(entities.get(byte, ('&#x%02X;' % byte).encode() if byte < 32 else bytes([byte])))
        index += 1
    return result


def serialize(runtime, manager, destination):
    memory, base = runtime.memory, runtime.image_base
    root_name = _cstring(runtime, base + 0x46B7B07)
    tag = _cstring(runtime, base + 0x47A5084)
    attribute_names = (_cstring(runtime, base + 0x46A38A2), _cstring(runtime, base + 0x47AB262))
    document, root = runtime._operator_new(112), runtime._operator_new(144)
    root_string, elements = _XmlString(runtime, root_name), []
    for node in _Tree(runtime, manager + 8).nodes():
        key, value = _String.read(runtime, node + 32).clone(), _String.read(runtime, node + 56).clone()
        element = runtime._operator_new(144)
        element_name = _XmlString(runtime, tag)
        attributes = []
        for name, current in zip(attribute_names, (key, value)):
            pointer = runtime._operator_new(64)
            attribute_name = _XmlString(runtime, name)
            attribute_value = _XmlString(runtime, current.value().split(b'\0', 1)[0])
            attributes.append((pointer, attribute_name, attribute_value))
        elements.append((element, element_name, attributes))
        value.destroy()
        key.destroy()
    indentation, newline, output = _XmlString(runtime, b'    '), _XmlString(runtime, b'\n'), _XmlString(runtime)
    output.append(b'<')
    output.append(root_string.value())
    output.append(b'>') if elements else output.append(b' />')
    output.append(newline.value())
    for _, element_name, attributes in elements:
        output.append(indentation.value())
        output.append(b'<')
        output.append(element_name.value())
        for _, name, value in attributes:
            output.append(b' ')
            encoded_name, encoded_value = _encode_attribute(runtime, name.value()), _encode_attribute(runtime, value.value())
            quote = b"'" if b'"' in value.value() else b'"'
            output.append(encoded_name.value())
            output.append(b'=' + quote)
            output.append(encoded_value.value())
            output.append(quote)
            encoded_value.destroy()
            encoded_name.destroy()
        output.append(b' />')
        output.append(newline.value())
    if elements:
        output.append(b'</')
        output.append(root_string.value())
        output.append(b'>')
        output.append(newline.value())
    _cstring_assign(runtime, destination, output.pointer + 16)
    newline.destroy()
    indentation.destroy()
    output.destroy()
    for element, element_name, attributes in elements:
        for pointer, name, value in attributes:
            value.destroy()
            name.destroy()
            runtime._free_allocation(pointer)
        element_name.destroy()
        runtime._free_allocation(element)
    root_string.destroy()
    runtime._free_allocation(root)
    runtime._free_allocation(document)
    return 1


def invoke(runtime, rva, values):
    from .primary_device_cache_xml import parse

    if rva in (0x3C71760, 0x3C71980):
        if len(values) != 6:
            raise InputError('device cache cipher source interface argument count mismatch')
        return crypt(runtime, *values, decode=rva == 0x3C71980)
    definitions = {0x35F55D0: (read_file, 2), 0x35F8E10: (write_file, 3), 0x35F8950: (serialize, 2),
                   0x35F78B0: (parse, 2)}
    function, count = definitions[rva]
    if len(values) != count:
        raise InputError('device cache source interface argument count mismatch')
    return function(runtime, *values)


def serialize_owned_cache_xml(values):
    """Source root/config/key/value format on owning Strings."""
    if type(values)is not dict or any(type(k)is not bytes or type(v)is not bytes for k,v in values.items()):raise InputError('cache XML requires owned byte pairs')
    def encode(raw):
        result=bytearray();index=0;entities={38:b'&amp;',60:b'&lt;',62:b'&gt;',34:b'&quot;',39:b'&apos;'}
        while index<len(raw):
            if raw[index:index+3]==b'&#x':
                end=raw.find(b';',index+3)
                if end>=0:result.extend(raw[index:end+1]);index=end+1;continue
            byte=raw[index];result.extend(entities.get(byte,('&#x%02X;'%byte).encode() if byte<32 else bytes([byte])));index+=1
        return bytes(result)
    output=b'<root>'+b'\n' if values else b'<root />\n'
    for key,value in sorted(values.items()):
        output+=b'    <config'
        for name,raw in ((b'key',key),(b'value',value.split(b'\0',1)[0])):
            quote=b"'" if b'"'in raw else b'"';output+=b' '+name+b'='+quote+encode(raw)+quote
        output+=b' />\n'
    return output+(b'</root>\n' if values else b'')
