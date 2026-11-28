from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


UNOBSERVED = object()
_LIMIT = 1 << 20
_IMPORTS = {
    'CryptAcquireContextA': 0x4910940, 'GetLastError': 0x490FEA8,
    'CryptGenKey': 0x4910968, 'InitializeSecurityDescriptor': 0x49109B8,
    'SetSecurityDescriptorDacl': 0x4910A60, 'CryptSetProvParam': 0x4910998,
    'CryptGetUserKey': 0x4910980, 'CryptExportPublicKeyInfo': 0x4910E28,
    'CryptDestroyKey': 0x4910960, 'CryptCreateHash': 0x4910950,
    'CryptHashData': 0x4910988, 'CryptGetHashParam': 0x4910978,
    'CryptDestroyHash': 0x4910958, 'CryptReleaseContext': 0x4910990,
}


def _api(runtime, name, arguments):
    from .primary_device_source_inputs import require_device_source_binding, take_device_source_observation
    require_device_source_binding(runtime)
    expected = runtime.worker_imports.get(name)
    if expected is None or runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != expected:
        raise PrimarySemanticUnavailable('native CAPI current import is not bound: ' + name)
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('native CAPI requires ordered API observations: ' + name)
    return take_device_source_observation(runtime, name, arguments)


def _plain(runtime, name, arguments):
    result, raw = _api(runtime, name, arguments)
    if raw != b'':
        raise InputError('native CAPI scalar API has no output effects: ' + name)
    return result


def _effects(runtime, address, width, raw, name):
    writes = ((0, raw),) if isinstance(raw, bytes) else raw
    if not isinstance(writes, tuple):
        raise InputError('native CAPI output requires bytes or offset/bytes pairs: ' + name)
    for item in writes:
        if (not isinstance(item, tuple) or len(item) != 2 or type(item[0]) is not int or
                not isinstance(item[1], bytes) or not 0 <= item[0] <= width or len(item[1]) > width - item[0]):
            raise InputError('native CAPI output effects leave their bounded buffer: ' + name)
        if item[1]:
            runtime.memory.write(address + item[0], item[1], source='2C5D590.' + name + '_output')


def _output_api(runtime, name, arguments, address, width):
    result, raw = _api(runtime, name, arguments)
    _effects(runtime, address, width, raw, name)
    return result & 0xFFFFFFFF


def _buffer_api(runtime, name, arguments, pointer, capacity, length):
    result, raw = _api(runtime, name, arguments)
    if not isinstance(raw, tuple) or len(raw) != 2:
        raise InputError('native CAPI buffer requires output effects and returned length: ' + name)
    _effects(runtime, pointer, capacity, raw[0], name)
    if raw[1] is not None:
        if type(raw[1]) is not int or not 0 <= raw[1] <= 0xFFFFFFFF:
            raise InputError('native CAPI returned length must be a DWORD: ' + name)
        runtime.memory.store(length, raw[1], 4, source='2C5D590.' + name + '_length')
    return result & 0xFFFFFFFF


def continue_public_key(runtime, rbp, output, *, expected_bits=UNOBSERVED):
    from .primary_device import _MATERIAL_KEY, _device_material_message, poly1305
    from .primary_device_native import _Vector

    if not isinstance(output, _Vector) or output.runtime is not runtime or output.size:
        raise InputError('native CAPI continuation requires its cleared output vector')
    if expected_bits is not UNOBSERVED and not isinstance(expected_bits, bytes):
        raise InputError('native CAPI expected bits must be explicit bytes')
    memory = runtime.memory
    provider_slot, generated_slot, key_slot = rbp + 0x9948, rbp + 0x9928, rbp + 0x98F8
    hash_slot, sd = rbp + 0x98A8, rbp + 0x9900
    size_slot, digest_size = rbp + 0x98F4, rbp + 0x988C
    method = 6
    memory.store(provider_slot, 0, 8, source='2C92F73.provider_zero')

    def select(code):
        memory.store(rbp + 0x5718, code, 8, source='2C5D590.public_key_error')

    def finish(code):
        return code == 0, code, method

    def release():
        _plain(runtime, 'CryptReleaseContext', (memory.load(provider_slot, 8), 0))

    if not _output_api(runtime, 'CryptAcquireContextA', (b'mWOLCtkGwuHtk\0', 0, 24, 0x60), provider_slot, 8):
        error = _plain(runtime, 'GetLastError', ()) & 0xFFFFFFFF
        memory.store(rbp + 0x9934, error, 4, source='2C9C14D.last_error')
        hresult = error if error == 0 or error & 0x80000000 else (error & 0xFFFF) | 0x80070000
        if hresult != 0x80090016:
            select(3)
            return finish(3)
        method = 5
        memory.store(rbp + 0x5726, method, 1, source='2C9C4BB.creation_method')
        if not _output_api(runtime, 'CryptAcquireContextA', (b'mWOLCtkGwuHtk\0', 0, 24, 0x68), provider_slot, 8):
            select(4)
            return finish(4)
        provider = memory.load(provider_slot, 8)
        if not _output_api(runtime, 'CryptGenKey', (provider, 2, 0x08000000), generated_slot, 8):
            select(5)
            release()
            return finish(5)
        for code, name, arguments in (
                (6, 'InitializeSecurityDescriptor', (sd, 1)),
                (7, 'SetSecurityDescriptorDacl', (sd, 1, 0, 0)),
                (8, 'CryptSetProvParam', (provider, 8, sd, 4))):
            result = (_plain(runtime, name, arguments) & 0xFFFFFFFF if code == 8 else
                      _output_api(runtime, name, arguments, sd, 40))
            if not result:
                select(code)
                _plain(runtime, 'CryptDestroyKey', (memory.load(generated_slot, 8),))
                release()
                return finish(code)
    provider = memory.load(provider_slot, 8)
    if not _output_api(runtime, 'CryptGetUserKey', (provider, 2), key_slot, 8):
        select(9)
        release()
        return finish(9)
    key = memory.load(key_slot, 8)
    memory.store(size_slot, 0, 4, source='2C9C91D.export_size_zero')
    if not _buffer_api(runtime, 'CryptExportPublicKeyInfo', (provider, 2, 0x10001, 0, 0), 0, 0, size_slot):
        select(10)
        _plain(runtime, 'CryptDestroyKey', (key,))
        release()
        return finish(10)
    size = memory.load(size_slot, 4)
    if not 40 <= size <= _LIMIT:
        raise PrimarySemanticUnavailable('native CAPI export size leaves the bounded structure domain')
    exported = _Vector(runtime, bytes(size))
    if not _buffer_api(runtime, 'CryptExportPublicKeyInfo', (provider, 2, 0x10001, exported.pointer, size), exported.pointer, size, size_slot):
        select(10)
        _plain(runtime, 'CryptDestroyKey', (key,))
        release()
        exported.destroy()
        return finish(10)
    count = memory.load(exported.pointer + 24, 4)
    pointer = memory.load(exported.pointer + 32, 8)
    if count and (not exported.pointer <= pointer <= exported.pointer + size or count > exported.pointer + size - pointer):
        raise PrimarySemanticUnavailable('native CAPI bits leave the bounded export buffer')
    bits = _Vector(runtime, memory.read(pointer, count) if count else b'')
    if expected_bits is not UNOBSERVED and bits.value() != expected_bits:
        raise InputError('native exported key bytes disagree with the explicit expected bits')
    _plain(runtime, 'CryptDestroyKey', (key,))
    memory.store(hash_slot, 0, 8, source='2C9CC7D.hash_zero')
    if not _output_api(runtime, 'CryptCreateHash', (provider, 0x800C, 0, 0), hash_slot, 8):
        select(11)
        release()
        bits.destroy()
        exported.destroy()
        return finish(11)
    digest_handle = memory.load(hash_slot, 8)
    if not _plain(runtime, 'CryptHashData', (digest_handle, bits.value(), 0)) & 0xFFFFFFFF:
        select(12)
        _plain(runtime, 'CryptDestroyHash', (digest_handle,))
        release()
        bits.destroy()
        exported.destroy()
        return finish(12)
    digest = _Vector(runtime, bytes(32))
    memory.store(digest_size, 32, 4, source='2C9CE37.digest_size')
    result = _buffer_api(runtime, 'CryptGetHashParam', (digest_handle, 2, 32, 0), digest.pointer, 32, digest_size)
    if not result or memory.load(digest_size, 4) != 32:
        select(13)
        _plain(runtime, 'CryptDestroyHash', (digest_handle,))
        release()
        digest.destroy()
        bits.destroy()
        exported.destroy()
        return finish(13)
    material = _Vector(runtime, digest.value()[:16])
    raw_message = _device_material_message(material.value())
    message = _Vector(runtime, raw_message[:16])
    message.append(raw_message[16:])
    tag = _Vector(runtime, poly1305(message.value(), _MATERIAL_KEY))
    material.append(tag.value())
    material.size = 22
    tag.destroy()
    message.destroy()
    output.append(material.value())
    for offset, value in ((0, output.pointer), (8, output.pointer + output.size),
                          (16, output.pointer + output.capacity)):
        memory.store(rbp + 0x5700 + offset, value, 8, source='2C5D590.public_key_output')
    _plain(runtime, 'CryptDestroyHash', (digest_handle,))
    release()
    material.destroy()
    digest.destroy()
    bits.destroy()
    exported.destroy()
    return finish(0)
