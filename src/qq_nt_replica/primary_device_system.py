import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_device_collector import _terminated
from .primary_logger import _cstring
from .primary_memory import UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = 'ba7bf8932e63c375d18680dc9860f683d7ea8368716807c30db785bfa171c9b7'
_IMPORTS = {'GetCurrentProcess': 0x490FDE0, 'GetModuleHandleW': 0x490FF10,
            'GetProcAddress': 0x490FF40, 'GetVersionExW': 0x4910028,
            'GetComputerNameA': 0x490FDB0, 'GetUserNameA': 0x49109B0,
            'GetCurrentHwProfileA': 0x49109A8}


def _image():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230/device-system-image.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed device system image identity mismatch')
    image = json.loads(raw)
    if image['imports'] != _IMPORTS:
        raise InputError('fixed device system import identity mismatch')
    return image


def install_image(memory, image_base):
    for segment in _image()['segments']:
        memory.map(image_base + segment['rva'], bytearray.fromhex(segment['hex']),
                   name='fixed device system information image', initialized=True)


def _observe(runtime, name, arguments):
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('device system current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing device system OS observations: ' + name)
    return runtime.worker_observations.take(runtime, name, arguments)


def _plain(runtime, name, arguments):
    result, effects = _observe(runtime, name, arguments)
    if effects is not None and effects != b'':
        raise InputError('device system operation has no output buffer: ' + name)
    return result


def _resolve(runtime, module, name):
    image, base = _image(), runtime.image_base
    module_name = _terminated(runtime, base + image['modules'][module], 2)
    handle = _plain(runtime, 'GetModuleHandleW', (module_name,))
    symbol = _cstring(runtime, base + image['procedures'][name])
    target = _plain(runtime, 'GetProcAddress', (handle, symbol))
    if symbol != name.encode('ascii'):
        raise PrimarySemanticUnavailable('device system resolved a changed procedure name')
    return target


def _dynamic(runtime, target, name, arguments):
    if not target or runtime.worker_observations is None:
        raise UnknownMemory('device system requires its resolved target and explicit OS effects: ' + name)
    return runtime.worker_observations.take(runtime, name, (target, *arguments))


def _output(runtime, address, raw, size, name):
    if not isinstance(raw, bytes) or len(raw) > size:
        raise InputError('device system requires bounded raw output effects: ' + name)
    runtime.memory.write(address, raw, source=name)


def user_name(runtime, name, buffer, capacity):
    result, effects = _observe(runtime, name, (runtime.memory.load(capacity, 4),))
    if (not isinstance(effects, tuple) or len(effects) != 2 or not isinstance(effects[0], bytes)
            or len(effects[0]) > 260 or effects[1] is not None
            and (type(effects[1]) is not int or not 0 <= effects[1] <= 0xFFFFFFFF)):
        raise InputError('device name API requires bounded raw character bytes and explicit DWORD capacity effects')
    runtime.memory.write(buffer, effects[0], source=name + '.output')
    if effects[1] is not None:
        runtime.memory.store(capacity, effects[1], 4, source=name + '.capacity_output')
    return result & 0xFFFFFFFF


def hardware_profile(runtime, buffer):
    result, raw = _observe(runtime, 'GetCurrentHwProfileA', ())
    if isinstance(raw, tuple) and len(raw) == 2:
        data, known = raw
        if (not isinstance(data, bytes) or not isinstance(known, bytes) or len(data) != len(known)
                or len(data) > 124 or any(value not in (0, 1) for value in known)
                or not result & 0xFFFFFFFF and (data or known)):
            raise InputError('device hardware profile requires bounded bytes and an explicit byte known-mask')
        index = 0
        while index < len(data):
            if not known[index]:
                index += 1
                continue
            end = index + 1
            while end < len(data) and known[end]:
                end += 1
            runtime.memory.write(buffer + index, data[index:end], source='GetCurrentHwProfileA.output')
            index = end
    else:
        _output(runtime, buffer, raw, 124, 'GetCurrentHwProfileA.output')
    return result & 0xFFFFFFFF


def _version_class(major, minor, build):
    if major == 10:
        signed_build = build - ((build & 0x80000000) << 1)
        for threshold, result in ((19040, 16), (18362, 15)):
            if signed_build > threshold:
                return result
        if signed_build == 18362:
            return 14
        for threshold, result in ((17762, 13), (17133, 12), (16298, 11), (15062, 10)):
            if signed_build > threshold:
                return result
        return 9 if signed_build >= 14393 else 7
    signed_major = major - ((major & 0x80000000) << 1)
    if signed_major > 6:
        return 17
    if major == 6:
        return minor + 3 if minor < 3 else 6
    if major == 5 and minor:
        return 1 if minor == 1 else 2
    return 0


def _product_list(runtime, sentinel, values):
    memory = runtime.memory
    memory.store(sentinel, sentinel, 8, source='1BEDD40.empty_product_list_tail')
    memory.store(sentinel + 8, sentinel, 8, source='1BEDD40.empty_product_list_head')
    memory.store(sentinel + 16, 0, 8, source='1BEDD40.empty_product_list_size')
    tail = sentinel
    for count, code in enumerate(values, 1):
        node = runtime._operator_new(24)
        memory.store(node + 16, code, 4, source='1BEDD40.product_code')
        memory.store(node + 8, sentinel, 8, source='1BEDD40.product_next')
        memory.store(node, tail, 8, source='1BEDD40.product_previous')
        memory.store(tail + 8, node, 8, source='1BEDD40.product_link')
        memory.store(sentinel, node, 8, source='1BEDD40.product_tail')
        memory.store(sentinel + 16, count, 8, source='1BEDD40.product_list_size')
        tail = node


def _contains_product(runtime, sentinel, code):
    node = runtime.memory.load(sentinel + 8, 8)
    for index in range(64):
        if node == sentinel:
            return False
        if runtime.memory.load(node + 16, 4) == code:
            return True
        node = runtime.memory.load(node + 8, 8)
    raise PrimaryProgramLimit('device product list traversal exceeds its bounded source domain')


def _destroy_product_list(runtime, sentinel):
    memory = runtime.memory
    node = memory.load(sentinel + 8, 8)
    memory.store(sentinel, sentinel, 8, source='1BEDD40.clear_product_list_tail')
    memory.store(sentinel + 8, sentinel, 8, source='1BEDD40.clear_product_list_head')
    memory.store(sentinel + 16, 0, 8, source='1BEDD40.clear_product_list_size')
    for index in range(64):
        if node == sentinel:
            return
        following = memory.load(node + 8, 8)
        runtime._free_allocation(node)
        node = following
    raise PrimaryProgramLimit('device product list destruction exceeds its bounded source domain')


def classify_product(runtime, destination, ignored, product):
    frame, rbp = _frame(runtime, 0x88, '1BEDD40.product_classification_frame')
    first, second = rbp - 0x20, rbp - 0x48
    _product_list(runtime, first, (18, 8, 12, 10, 14, 15, 9, 25, 7, 13, 17))
    _product_list(runtime, second, (4, 70, 27, 6, 16))
    product &= 0xFFFFFFFF
    if _contains_product(runtime, first, product):
        result = 2
    elif _contains_product(runtime, second, product):
        result = 3
    elif product in (48, 1):
        result = 1
    elif ((product - 121) & 0xFFFFFFFF) <= 1:
        result = 4
    else:
        result = 0
    runtime.memory.store(destination + 4, result, 4, source='1BEDD40.product_subtype')
    _destroy_product_list(runtime, second)
    _destroy_product_list(runtime, first)
    runtime.memory.unmap(frame)


def product_information(runtime, destination, os_version):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x40, '1BEDC50.product_information_frame')
    memory.store(frame + 0x34, 0, 4, source='1BEDC6C.empty_product_code')
    major = memory.load(destination + 8, 4)
    if major in (6, 10):
        target = _resolve(runtime, 'kernel32.dll', 'GetProductInfo')
        if target:
            arguments = (memory.load(destination + 8, 4), memory.load(destination + 12, 4), 0, 0)
            ignored, raw = _dynamic(runtime, target, 'GetProductInfo', arguments)
            _output(runtime, frame + 0x34, raw, 4, '1BEDCB9.GetProductInfo_output')
        major = memory.load(destination + 8, 4)
    if major in (6, 10):
        _invoke(runtime, 0x1BEDD40, destination, os_version, memory.load(frame + 0x34, 4))
    else:
        result = 0
        if major == 5:
            suite = memory.load(os_version + 0x118, 2)
            minor = memory.load(destination + 12, 4)
            if minor == 1:
                result = int(not suite & 0x200)
            elif minor == 2:
                result = 1 if memory.load(os_version + 0x11A, 1) == 1 else (0 if suite & 0x8000 else 2)
        memory.store(destination + 4, result, 4, source='1BEDC50.legacy_product_subtype')
    memory.unmap(frame)


def system_version(runtime, destination):
    memory = runtime.memory
    frame, rbp = _frame(runtime, 0x270, '1BED930.system_version_frame')
    memory.store(destination, 0, 4, source='1BED952.initial_version_class')
    process = _plain(runtime, 'GetCurrentProcess', ())
    target = _resolve(runtime, 'kernel32.dll', 'IsWow64Process')
    wow = 0
    if target:
        memory.store(frame + 0x148, 0, 4, source='1BED986.initial_WOW64_BOOL')
        result, raw = _dynamic(runtime, target, 'IsWow64Process', (process,))
        _output(runtime, frame + 0x148, raw, 4, '1BED99C.IsWow64Process_output')
        wow = int(memory.load(frame + 0x148, 4) != 0) if result & 0xFFFFFFFF else 2
    memory.store(destination + 0x20, wow, 4, source='1BED9B9.WOW64_classification')
    version = frame + 0x148
    memory.write(version + 4, bytes(0x118), source='1BED9CC.zero_version_info')
    memory.store(version, 0x11C, 4, source='1BED9D1.version_info_size')
    ignored, raw = _observe(runtime, 'GetVersionExW', (memory.load(version, 4),))
    _output(runtime, version, raw, 0x11C, '1BED9E4.GetVersionExW_output')
    for offset in (4, 8, 12):
        memory.store(destination + offset + 4, memory.load(version + offset, 4), 4,
                     source='1BED930.version_number')
    major, minor, build = (memory.load(destination + offset, 4) for offset in (8, 12, 16))
    classification = _version_class(major, minor, build)
    if major == 6 and minor == 2:
        memory.store(destination, 5, 4, source='1BEDAFA.compatibility_version_class')
        target = _resolve(runtime, 'ntdll.dll', 'RtlGetNtVersionNumbers')
        if target:
            ignored, outputs = _dynamic(runtime, target, 'RtlGetNtVersionNumbers', ())
            if not isinstance(outputs, tuple) or len(outputs) != 3:
                raise InputError('device NT version requires three explicit DWORD output effects')
            for offset, raw in zip((8, 12, 16), outputs):
                _output(runtime, destination + offset, raw, 4, '1BEDB2F.RtlGetNtVersionNumbers_output')
            memory.store(destination + 16, memory.load(destination + 16, 2), 4,
                         source='1BEDB34.nt_build_low_word')
            classification = _version_class(*(memory.load(destination + offset, 4) for offset in (8, 12, 16)))
            memory.store(destination, classification, 4, source='1BEDBA7.resolved_version_class')
    else:
        memory.store(destination, classification, 4, source='1BEDBA7.version_class')
    for output, original in ((0x18, 0x114), (0x1C, 0x116)):
        memory.store(destination + output, memory.load(version + original, 2), 4,
                     source='1BED930.service_pack_word')
    memory.copy_disjoint(frame + 0x28, version, 0x11C, label='1BEDBD5.copy_version_for_product')
    _invoke(runtime, 0x1BEDC50, destination, frame + 0x28)
    memory.unmap(frame)
    return destination


def invoke(runtime, rva, values):
    if rva == 0x1BED930 and len(values) == 1:
        return system_version(runtime, values[0])
    if rva == 0x1BEDC50 and len(values) == 2:
        return product_information(runtime, *values)
    if rva == 0x1BEDD40 and len(values) == 3:
        return classify_product(runtime, *values)
    raise InputError('device system source interface argument count mismatch')
