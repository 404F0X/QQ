import hmac

from .errors import InputError
from .primary_device import _MATERIAL_KEY, _PROFILE_KEY, _checkpoint_block, _device_material_message, checkpoint_hardware_invalidates, checkpoint_needs_update, checkpoint_stream_block, checkpoint_transform, device_environment_classification, encode_device_body, initial_device_profile, invalid_checkpoint_record, mix_device_bytes, new_checkpoint_record, poly1305
from .primary_device_collector import _append_material
from .primary_logger import _String
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_LIMIT = 1 << 20
_HARDWARE_EXPORTS = (
    (b'NtQuerySystemInformation', 0x6D83DE0),
    (b'LdrLoadDll', 0x6D83DE8),
    (b'LdrUnloadDll', 0x6D83DF0),
    (b'RtlQueryEnvironmentVariable_U', 0x6D83DF8),
    (b'LdrGetProcedureAddress', 0x6D83E00),
    (b'NtOpenDirectoryObject', 0x6D83E08),
    (b'NtQueryDirectoryObject', 0x6D83E10),
    (b'NtClose', 0x6D83E18))
_HARDWARE_FLAG = 0x6D83DD8
_IMPORTS = {'SHGetSpecialFolderPathA':0x49107E8,'GetFileAttributesA':0x490FE50,'CreateDirectoryA':0x490FC00,'CreateFileA':0x490FC28,
            'CloseHandle':0x490FBD8,'GetFileSize':0x490FE78,'ReadFile':0x4910288,'GetLastError':0x490FEA8,
            'WriteFile':0x4910470,'CryptAcquireContextW':0x4910948,'CryptGenRandom':0x4910970,'CryptReleaseContext':0x4910990,
            'CryptAcquireContextA':0x4910940,'CryptCreateHash':0x4910950,'CryptDestroyHash':0x4910958,
            'CryptDestroyKey':0x4910960,'CryptGetHashParam':0x4910978,'CryptGetUserKey':0x4910980,
            'CryptHashData':0x4910988,'CryptExportPublicKeyInfo':0x4910E28,
            'VerSetConditionMask':0x49103F8,'VerifyVersionInfoW':0x4910400,
            'CryptGenKey':0x4910968,'InitializeSecurityDescriptor':0x49109B8,
            'SetSecurityDescriptorDacl':0x4910A60,'CryptSetProvParam':0x4910998,
            'NtOpenDirectoryObject':0x6D83E08,'NtQueryDirectoryObject':0x6D83E10,
            'NtClose':0x6D83E18,'EnumDisplayDevicesW':0x4910508,
            'NtQuerySystemInformation':0x6D83DE0,'GetVolumeInformationW':0x4910038,
            'UuidCreateSequential':0x49111C8,
            'GetModuleHandleW':0x490FF10,'GetProcAddress':0x490FF40}


class _Vector:
    def __init__(self, runtime, value=b''):
        if not isinstance(value, bytes):
            raise InputError('native device vector requires exact bytes')
        if len(value)>_LIMIT:
            raise PrimaryProgramLimit('native device vector exceeds its bounded domain')
        self.runtime = runtime
        self.size = self.capacity = len(value)
        self.pointer = runtime._operator_new(self.capacity) if self.capacity else 0
        if self.size:
            runtime.memory.write(self.pointer,value,source='2C5D590.vector_construct')

    def value(self):
        return self.runtime.memory.read(self.pointer,self.size) if self.size else b''

    def append(self, value):
        if not isinstance(value, bytes):
            raise InputError('native device vector append requires exact bytes')
        total = self.size+len(value)
        if total>_LIMIT:
            raise PrimaryProgramLimit('native device vector growth exceeds its bounded domain')
        if total>self.capacity:
            capacity = max(2*self.capacity,total)
            if capacity>_LIMIT:
                raise PrimaryProgramLimit('native device vector capacity exceeds its bounded domain')
            pointer = self.runtime._operator_new(capacity)
            if self.size:
                self.runtime.memory.write(pointer,self.value(),source='2C5D590.vector_grow_prefix')
            if value:
                self.runtime.memory.write(pointer+self.size,value,source='2C5D590.vector_grow_suffix')
            if self.pointer:
                self.runtime._free_allocation(self.pointer)
            self.pointer,self.capacity = pointer,capacity
        elif value:
            self.runtime.memory.write(self.pointer+self.size,value,source='2C5D590.vector_append')
        self.size = total

    def clear(self):
        self.size = 0

    def destroy(self):
        if self.pointer:
            self.runtime._free_allocation(self.pointer)
        self.pointer = self.size = self.capacity = 0


class _Path:
    def __init__(self, runtime, directory, filename):
        if (not isinstance(directory,(bytes,_String)) or not isinstance(filename, bytes) or
                isinstance(directory,bytes) and b'\0' in directory or b'\0' in filename):
            raise InputError('native device path requires raw terminated-string contents')
        self.owns_directory = isinstance(directory,bytes)
        if self.owns_directory:
            temporary = _String.construct(runtime,directory)
            self.directory = temporary.clone()
            temporary.destroy()
        else:
            self.directory = directory
        self.filename = _String.construct(runtime,filename)
        self.path = _String.construct(runtime,self.directory.value())
        _append_material(runtime,self.path,b'\\'+self.filename.value())

    def value(self):
        return self.path.value()

    def destroy(self):
        self.filename.destroy()
        self.path.destroy()
        if self.owns_directory:
            self.directory.destroy()


def decode_profile(runtime, packet, *, copy_material=True):
    if not isinstance(packet,_Vector) or packet.runtime is not runtime or packet.size!=50:
        raise InputError('native profile decoder requires its fifty-byte input vector')
    raw = packet.value()
    nonce = _Vector(runtime,raw[38:50])
    stored = _Vector(runtime,raw[22:38])
    message = _Vector(runtime,raw[:22])
    message.append(bytes.fromhex('7843cb1424494cf7'))
    message.append((22).to_bytes(4,'little'))
    computed = _Vector(runtime,poly1305(message.value(),checkpoint_stream_block(nonce.value())[:32]))
    accepted = hmac.compare_digest(computed.value(),stored.value())
    computed.destroy()
    message.destroy()
    stored.destroy()
    nonce.destroy()
    if not accepted:
        return None
    stream = _checkpoint_block(_PROFILE_KEY,raw[38:50],0xBE44BB8A)
    clear = bytes(left^right for left,right in zip(raw[:22],stream))
    runtime.memory.write(packet.pointer,clear,source='2C5D590.profile_decrypt_in_place')
    return _Vector(runtime,clear) if copy_material else clear


def decode_checkpoint(runtime, packet):
    if not isinstance(packet,_Vector) or packet.runtime is not runtime or packet.size!=1028:
        raise InputError('native checkpoint decoder requires its1028-byte input vector')
    raw = packet.value()
    nonce = _Vector(runtime,raw[1016:1028])
    stored = _Vector(runtime,raw[1000:1016])
    message = _Vector(runtime,raw[:1000])
    message.append(bytes.fromhex('7843cb1424494cf7'))
    message.append((1000).to_bytes(4,'little'))
    computed = _Vector(runtime,poly1305(message.value(),checkpoint_stream_block(nonce.value())[:32]))
    accepted = hmac.compare_digest(computed.value(),stored.value())
    computed.destroy()
    message.destroy()
    stored.destroy()
    nonce.destroy()
    if not accepted:
        return None
    clear = checkpoint_transform(raw[:1000],raw[1016:1028])
    runtime.memory.write(packet.pointer,clear,source='2C5D590.checkpoint_decrypt_in_place')
    return clear if clear[:2]==b'\x01\0' else None


def encode_checkpoint(runtime, record, random_bytes):
    if not isinstance(record,bytes) or len(record)!=1000:
        raise InputError('native checkpoint writer requires its1000-byte source record')
    parts = [random_bytes(4) for _ in range(3)]
    if any(not isinstance(part,bytes) or len(part)!=4 for part in parts):
        raise InputError('native checkpoint nonce requires three exact random DWORDs')
    nonce = b''.join(parts)
    packet = _Vector(runtime,record)
    ciphertext = checkpoint_transform(packet.value(),nonce)
    runtime.memory.write(packet.pointer,ciphertext,source='2C5D590.checkpoint_encrypt_in_place')
    message = _Vector(runtime,ciphertext)
    message.append(bytes.fromhex('7843cb1424494cf7'))
    message.append((1000).to_bytes(4,'little'))
    tag = _Vector(runtime,poly1305(message.value(),checkpoint_stream_block(nonce)[:32]))
    packet.append(tag.value())
    packet.append(nonce)
    tag.destroy()
    message.destroy()
    return packet


def encode_device(runtime, material, method, classification, seconds, random_bytes):
    if (not isinstance(material,_Vector) or material.runtime is not runtime or material.size!=22 or
            type(method) is not int or not 0<=method<=255 or
            type(classification) is not int or not 0<=classification<=255):
        raise InputError('native device encoding requires its material vector and source header bytes')
    body = _Vector(runtime,bytes([method,classification])+material.value())
    material.destroy()
    encoded = encode_device_body(body.value(),seconds,random_bytes)
    temporary = _String.construct(runtime,encoded)
    result = temporary.clone()
    temporary.destroy()
    body.destroy()
    return result


def _material(runtime, seed):
    if not isinstance(seed,bytes) or len(seed)!=16:
        raise InputError('native device material requires sixteen seed bytes')
    material = _Vector(runtime,seed)
    raw_message = _device_material_message(material.value())
    message = _Vector(runtime,raw_message[:16])
    message.append(raw_message[16:])
    tag = _Vector(runtime,poly1305(message.value(),_MATERIAL_KEY))
    material.append(tag.value()[:6])
    tag.destroy()
    message.destroy()
    return material


def encode_profile(runtime, seed, random_bytes):
    if not isinstance(seed,bytes) or len(seed)!=16:
        raise InputError('native profile generation requires sixteen raw CAPI bytes')
    seed = bytearray(seed)
    seed[6] = (seed[6]&15)|64
    seed[8] = (seed[8]&63)|128
    material = _material(runtime,bytes(seed))
    clear = _Vector(runtime,material.value())
    parts = [random_bytes(4) for _ in range(3)]
    if any(not isinstance(part,bytes) or len(part)!=4 for part in parts):
        raise InputError('native profile nonce requires three exact random DWORDs')
    nonce = b''.join(parts)
    stream = _checkpoint_block(_PROFILE_KEY,nonce,0xBE44BB8A)
    ciphertext = bytes(left^right for left,right in zip(material.value(),stream))
    runtime.memory.write(material.pointer,ciphertext,source='2C5D590.new_profile_encrypt_in_place')
    message = _Vector(runtime,ciphertext)
    message.append(bytes.fromhex('7843cb1424494cf7'))
    message.append((22).to_bytes(4,'little'))
    tag = _Vector(runtime,poly1305(message.value(),checkpoint_stream_block(nonce)[:32]))
    material.append(tag.value())
    material.append(nonce)
    tag.destroy()
    message.destroy()
    return clear,material


def _api(runtime, name, arguments):
    from .primary_device_source_inputs import require_device_source_binding, take_device_source_observation
    require_device_source_binding(runtime)
    expected = runtime.worker_imports.get(name)
    actual = runtime.memory.load(runtime.image_base+_IMPORTS[name],8)
    dynamic = any(symbol.decode('ascii') == name for symbol, slot in _HARDWARE_EXPORTS)
    if expected is None or actual != expected or dynamic and not actual:
        raise PrimarySemanticUnavailable('native device current import is not bound: '+name)
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('native device requires raw file API observations: '+name)
    return take_device_source_observation(runtime,name,arguments)


def _plain(runtime, name, arguments):
    result,raw = _api(runtime,name,arguments)
    if not isinstance(raw,bytes) or raw:
        raise InputError('native device scalar API has no output effects: '+name)
    return result


def _hardware_available(runtime, rbp):
    memory, base = runtime.memory, runtime.image_base
    if memory.load(base + _HARDWARE_FLAG, 1) & 1:
        memory.store(rbp + 0x5784, 0, 4, source='2C5E337.hardware_lookup_cached_status')
        return True
    module = _plain(runtime, 'GetModuleHandleW', ('ntdll\0'.encode('utf-16-le'),))
    if type(module) is not int or not 0 <= module < 1 << 64:
        raise InputError('device hardware module requires an observed unsigned handle')
    resolved = []
    if module:
        for symbol, slot in _HARDWARE_EXPORTS:
            target = _plain(runtime, 'GetProcAddress', (module, symbol))
            if type(target) is not int or not 0 <= target < 1 << 64:
                raise InputError('device hardware export requires an observed unsigned target')
            memory.store(base + slot, target, 8, source='device.hardware_resolved_export')
            runtime.worker_imports[symbol.decode('ascii')] = target
            resolved.append(target)
    available = bool(module and all(resolved))
    if available:
        memory.store(base + _HARDWARE_FLAG, 1, 1, source='2C5EA03.hardware_lookup_complete')
    memory.store(rbp + 0x5784, 0 if available else 0xFFFFFFFF, 4,
                 source='device.hardware_lookup_status')
    if not available:
        memory.store(rbp + 0x575F, 0, 1, source='2C5EBBE.hardware_unavailable')
    runtime.events.append(('device.hardware_availability', available))
    return available


def _error(runtime, code, *, capture=True):
    return (code<<32)|((_plain(runtime,'GetLastError',())&0xFFFFFFFF) if capture else 0)


def _crypto_handle(runtime, name, arguments):
    result,raw = _api(runtime,name,arguments)
    if not result&0xFFFFFFFF:
        raise PrimarySemanticUnavailable('2C5D590 public-key failure cleanup remains unavailable: '+name)
    if not isinstance(raw,bytes) or len(raw)!=8:
        raise InputError('native device crypto handle requires eight observed bytes: '+name)
    return int.from_bytes(raw,'little')


def _public_key(runtime, observation):
    provider = _crypto_handle(runtime,'CryptAcquireContextA',(b'mWOLCtkGwuHtk\0',0,24,0x60))
    key = _crypto_handle(runtime,'CryptGetUserKey',(provider,2))
    result,effects = _api(runtime,'CryptExportPublicKeyInfo',(provider,2,0x10001,0,0))
    if not result&0xFFFFFFFF:
        raise PrimarySemanticUnavailable('2C5D590 public-key size-query failure cleanup remains unavailable')
    if not isinstance(effects,tuple) or len(effects)!=2 or effects[0]!=b'' or type(effects[1]) is not int:
        raise InputError('native public-key size query requires its raw bounded size')
    size = effects[1]
    if not 48<=size<=_LIMIT:
        raise PrimarySemanticUnavailable('2C5D590 public-key export size leaves the observed structure domain')
    exported = _Vector(runtime,bytes(size))
    result,effects = _api(runtime,'CryptExportPublicKeyInfo',(provider,2,0x10001,exported.pointer,size))
    if not result&0xFFFFFFFF:
        raise PrimarySemanticUnavailable('2C5D590 public-key export failure cleanup remains unavailable')
    if (not isinstance(effects,tuple) or len(effects)!=2 or not isinstance(effects[0],bytes) or
            len(effects[0])!=size or type(effects[1]) is not int or not 48<=effects[1]<=size):
        raise InputError('native public-key export requires the complete observed output buffer')
    runtime.memory.write(exported.pointer,effects[0],source='2C5D590.CryptExportPublicKeyInfo_output')
    count = runtime.memory.load(exported.pointer+24,4)
    pointer = runtime.memory.load(exported.pointer+32,8)
    if not count or not exported.pointer<=pointer<=exported.pointer+size or count>exported.pointer+size-pointer:
        raise PrimarySemanticUnavailable('2C5D590 public-key bits leave the observed exported-buffer domain')
    bits = _Vector(runtime,runtime.memory.read(pointer,count))
    if bits.value()!=observation.public_key_bits:
        raise InputError('native exported key bytes disagree with the source CAPI observation')
    _plain(runtime,'CryptDestroyKey',(key,))
    digest_handle = _crypto_handle(runtime,'CryptCreateHash',(provider,0x800C,0,0))
    if not _plain(runtime,'CryptHashData',(digest_handle,bits.value(),0))&0xFFFFFFFF:
        raise PrimarySemanticUnavailable('2C5D590 public-key hash-data failure cleanup remains unavailable')
    digest = _Vector(runtime,bytes(32))
    result,effects = _api(runtime,'CryptGetHashParam',(digest_handle,2,32,0))
    if not result&0xFFFFFFFF:
        raise PrimarySemanticUnavailable('2C5D590 public-key hash-output failure cleanup remains unavailable')
    if not isinstance(effects,tuple) or len(effects)!=2 or not isinstance(effects[0],bytes) or len(effects[0])!=32 or effects[1]!=32:
        raise InputError('native public-key digest requires all thirty-two observed output bytes')
    runtime.memory.write(digest.pointer,effects[0],source='2C5D590.CryptGetHashParam_output')
    material = _material(runtime,digest.value()[:16])
    output = _Vector(runtime,material.value())
    _plain(runtime,'CryptDestroyHash',(digest_handle,))
    _plain(runtime,'CryptReleaseContext',(provider,0))
    material.destroy()
    digest.destroy()
    bits.destroy()
    exported.destroy()
    return output


def _raw_public_key_gate(runtime, rbp, output):
    memory = runtime.memory
    vector, error, method = rbp + 0x5700, rbp + 0x5718, rbp + 0x5726
    for offset, value in ((0, output.pointer), (8, output.pointer + output.size),
                          (16, output.pointer + output.capacity)):
        memory.store(vector + offset, value, 8, source='2C5D590.public_key_vector_descriptor')
    memory.store(error, 0, 8, source='2C92E09.public_key_error_zero')
    memory.store(method, 6, 1, source='2C92E58.public_key_method')
    output.clear()
    memory.store(vector + 8, output.pointer, 8, source='2DD2222.public_key_vector_clear')
    version = rbp + 0x9960
    memory.write(version, bytes(284), source='2C92E76.public_key_version_zero')
    for offset, value, width in ((0, 284, 4), (4, 5, 4), (8, 1, 4), (276, 0, 2), (278, 0, 2)):
        memory.store(version + offset, value, width, source='2C92EC7.public_key_version_fields')
    mask = _plain(runtime, 'VerSetConditionMask', (0, 2, 3))
    if type(mask) is not int or not 0 <= mask < 1 << 64:
        raise InputError('version condition mask requires an unsigned64 return')
    mask = _plain(runtime, 'VerSetConditionMask', (mask, 1, 3))
    if type(mask) is not int or not 0 <= mask < 1 << 64:
        raise InputError('version condition mask requires an unsigned64 return')
    memory.store(rbp + 0x9958, mask, 8, source='2C92F30.public_key_condition_mask')
    memory.store(rbp + 0x9954, 3, 4, source='2C92F37.public_key_type_mask')
    result = _plain(runtime, 'VerifyVersionInfoW', (memory.read(version, 284), 3, mask))
    if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
        raise InputError('version verification requires an unsigned32 return')
    if result:
        return True
    memory.store(error, 2, 8, source='2C92F59.public_key_version_error')
    return False


def _acquire_public_key(runtime, rbp, factory, key, random_bytes, *, capture_error=True):
    from .primary_device import CapiObservation

    if factory.public_key_source in ('raw_os', 'windows'):
        from contextlib import nullcontext

        output = _Vector(runtime)
        observer = None
        scope = nullcontext()
        if factory.public_key_source == 'windows':
            from .primary_windows_capi import WindowsCapiObservations

            observer = WindowsCapiObservations(runtime, rbp, allow_creation=factory.allow_capi_creation)
            scope = observer
        try:
            with scope:
                if _raw_public_key_gate(runtime, rbp, output):
                    from .primary_device_capi import continue_public_key

                    success, error_code, method = continue_public_key(runtime, rbp, output)
                    if success:
                        return output, None, method, error_code
        finally:
            if observer is not None:
                statuses = tuple((row['name'], row['result'], row['count']) for row in observer.records)
                cleanup = tuple((row['name'], row.get('result'), row.get('error')) for row in observer.cleanup_records)
                runtime.events.append(('device.windows_capi_closed', statuses, cleanup,
                                       len(observer.pending_handles), observer.scratch_count))
                if observer.pending_handles or observer.scratch_count:
                    raise PrimarySemanticUnavailable('Windows CAPI cleanup left unresolved native resources')
        output.destroy()
        error_code = runtime.memory.load(rbp + 0x5718, 8)
        material, error, method = _profile(runtime, factory, key, random_bytes, capture_error=capture_error)
        runtime.memory.store(rbp + 0x5726, method, 1, source='2C5D590.profile_method')
        return material, error, method, error_code
    capi = factory.source.capi_public_key()
    if not isinstance(capi, CapiObservation):
        raise InputError('native device CAPI source requires its raw structured observation')
    if capi.error_code == 0:
        material, error, method = _public_key(runtime, capi), None, 6
    else:
        material, error, method = _profile(runtime, factory, key, random_bytes, capture_error=capture_error)
    return material, error, method, capi.error_code


def _device_time_seconds(runtime, factory):
    from .primary_device_source_inputs import require_device_source_binding, take_device_source_observation
    require_device_source_binding(runtime)
    if factory.device_time_source == 'filetime_seconds_projection':
        from .primary_sign import filetime_seconds

        filetime = runtime._next(runtime._filetimes, 'device source-used FILETIME seconds projection')
        seconds = filetime_seconds(filetime)
        if filetime < 116444736000000000 or seconds < 0:
            raise PrimarySemanticUnavailable('device FILETIME seconds projection requires the nonnegative normal time domain')
        runtime.events.append(('2D8D6A5.source_used_seconds_projection', filetime, seconds))
        return seconds
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('2C5D590 device time requires its explicit CRT observation')
    result, raw = take_device_source_observation(runtime, '_ftime64_s', ())
    if not isinstance(raw, bytes) or len(raw) != 14 or result != 0:
        raise PrimarySemanticUnavailable('2C5D590 device time failure or incomplete CRT output is unavailable')
    return int.from_bytes(raw[:8], 'little')


def _source(runtime, owner=None):
    from .primary_device_provider import DeviceFactory, _UNOBSERVED
    from .primary_device_storage import DirectoryCheckpointStorage
    from .primary_device_source_inputs import require_device_source_binding

    require_device_source_binding(runtime)

    factory = getattr(runtime.provider_profile,'device_factory',None)
    if not isinstance(factory,DeviceFactory):
        raise PrimarySemanticUnavailable('1BE6150 native device production requires its source adapter binding')
    if getattr(runtime, 'device_source_observations', None) is not None:
        if ((factory.enumeration_source, factory.public_key_source) != ('raw_os', 'raw_os') or
                factory.storage is not None or factory.injected_material is not None or
                factory.device_time_source != 'observed' or
                any(getattr(factory.environment, name, None) is not None for name in
                    ('device_checkpoint_preimage', 'device_checkpoint_knownmask', 'device_hypervisor_key_preimage'))):
            raise PrimarySemanticUnavailable('bound device source requires raw OS algorithms without computed-state overrides')
    if factory.cached_value:
        current = getattr(runtime,'_native_device_caches',{}).get(factory)
        if current is None or (owner is not None and current!=owner) or _String.read(runtime,current).value()!=factory.cached_value:
            raise PrimarySemanticUnavailable('1BE6150 source cache was produced outside the shared native memory;its allocation handoff is unavailable')
    if factory.storage is not None and not isinstance(factory.storage,DirectoryCheckpointStorage):
        raise PrimarySemanticUnavailable('1BE6150 native device requires an observed directory-backed storage root')
    if factory.refresh_observer is not _UNOBSERVED and factory.refresh_observer is not None:
        raise PrimarySemanticUnavailable('1BE6150 native observer must use the actual configuration binding')
    return factory


def _directory(runtime, factory, key, *, capture_error=True):
    if factory.public_key_source == 'raw_os' or factory.enumeration_source == 'raw_os':
        if factory.public_key_source != 'raw_os' or factory.enumeration_source != 'raw_os' or factory.storage is not None:
            raise PrimarySemanticUnavailable('raw device directory requires the matching raw OS sources without a storage override')
        result, raw = _api(runtime, 'SHGetSpecialFolderPathA', (0, 35, 1))
        if type(result) is not int or not 0 <= result <= 0xFFFFFFFF or not isinstance(raw, bytes) or len(raw) > 260:
            raise InputError('raw device Shell directory requires its BOOL and bounded ANSI output')
        if not result:
            return None, _error(runtime, 0xE, capture=capture_error)
        end = raw.find(b'\0')
        if not 0 < end <= 259:
            raise PrimarySemanticUnavailable('successful raw device Shell directory lacks its nonempty known ANSI terminator')
        root = raw[:end]
        root += (b'' if root.endswith(b'\\') else b'\\') + key
    elif factory.storage is None:
        try:
            root = str(factory.source.common_appdata()).encode('mbcs')+b'\\'+key
        except OSError as error:
            return None,(0xE<<32)|((getattr(error,'winerror',None) or error.errno or 0)&0xFFFFFFFF)
    else:
        root = str(factory.storage.directory).encode('mbcs')
    temporary = _String.construct(runtime,root)
    directory = temporary.clone()
    temporary.destroy()
    raw = directory.value()+b'\0'
    attributes = _plain(runtime,'GetFileAttributesA',(raw,))&0xFFFFFFFF
    if attributes==0xFFFFFFFF or not attributes&0x10:
        if not _plain(runtime,'CreateDirectoryA',(raw,))&0xFFFFFFFF:
            directory.destroy()
            return None,_error(runtime,0x17,capture=capture_error)
    return directory,None


def _open(runtime, path, *, write=False, create=False):
    return _plain(runtime,'CreateFileA',(path.value()+b'\0',0x40000000 if write else 0x80000000,
                                       0 if write else 1,1 if create else 2 if write else 3,2))


def _checkpoint(runtime, factory, key, *, record=None, random_bytes=None):
    directory,error = _directory(runtime,factory,key)
    if error is not None:
        return None if record is None else error
    path = _Path(runtime,directory,b'checkpoint.dat')
    handle = _open(runtime,path,write=record is not None)
    if handle==(1<<64)-1:
        path.destroy()
        directory.destroy()
        return None if record is None else 0x18
    if record is None:
        packet = _Vector(runtime,bytes(1028))
        ignored,effects = _api(runtime,'ReadFile',(handle,1028))
        if (not isinstance(effects,tuple) or len(effects)!=2 or not isinstance(effects[0],bytes) or
                len(effects[0])>1028 or type(effects[1]) is not int or not 0<=effects[1]<=len(effects[0])):
            raise InputError('native checkpoint read requires bounded raw bytes and its observed count')
        raw,count = effects
        if raw:
            runtime.memory.write(packet.pointer,raw,source='2C5D590.checkpoint_ReadFile_output')
        output = decode_checkpoint(runtime,packet) if count==1028 else None
        _plain(runtime,'CloseHandle',(handle,))
        packet.destroy()
        path.destroy()
        directory.destroy()
        return output
    if not callable(random_bytes):
        raise InputError('native checkpoint writer requires the shared entropy service')
    packet = encode_checkpoint(runtime,record,random_bytes)
    result,count = _api(runtime,'WriteFile',(handle,packet.value()))
    if type(count) is not int or not 0<=count<=1028:
        raise InputError('native checkpoint write requires its observed bounded DWORD byte count')
    _plain(runtime,'CloseHandle',(handle,))
    packet.destroy()
    path.destroy()
    directory.destroy()
    return None if result&0xFFFFFFFF and count==1028 else 0x19


def _new_profile(runtime, path, random_bytes):
    result,raw = _api(runtime,'CryptAcquireContextW',(0,0,1,0xF0000040))
    if not result&0xFFFFFFFF:
        raise PrimarySemanticUnavailable('2C5D590 profile random-device acquisition exception unwinding remains unavailable')
    if not isinstance(raw,bytes) or len(raw)!=8:
        raise InputError('native profile random provider requires an observed handle')
    provider = int.from_bytes(raw,'little')
    result,seed = _api(runtime,'CryptGenRandom',(provider,16))
    if not result&0xFFFFFFFF:
        raise PrimarySemanticUnavailable('2C5D590 profile random-device generation exception unwinding remains unavailable')
    if not isinstance(seed,bytes) or len(seed)!=16:
        raise InputError('native profile random generator requires all sixteen output bytes')
    _plain(runtime,'CryptReleaseContext',(provider,0))
    clear,packet = encode_profile(runtime,seed,random_bytes)
    handle = _open(runtime,path,write=True,create=True)
    output,error = None,None
    if handle==(1<<64)-1:
        error = 0x10
    else:
        result,count = _api(runtime,'WriteFile',(handle,packet.value()))
        if type(count) is not int or not 0<=count<=50:
            raise InputError('native profile write requires its observed bounded DWORD byte count')
        _plain(runtime,'CloseHandle',(handle,))
        if result&0xFFFFFFFF and count==50:
            output = _Vector(runtime,clear.value())
        else:
            error = 0x11
    clear.destroy()
    packet.destroy()
    return output,error


def _profile(runtime, factory, key, random_bytes, *, capture_error=True):
    directory,error = _directory(runtime,factory,key,capture_error=capture_error)
    if error is not None:
        return None,error,0
    path = _Path(runtime,directory,b'profile.dat2')
    if _plain(runtime,'GetFileAttributesA',(path.value()+b'\0',))&0xFFFFFFFF==0xFFFFFFFF:
        material,error = _new_profile(runtime,path,random_bytes)
        path.destroy()
        directory.destroy()
        return material,None if error is None else _error(runtime,error,capture=capture_error),3
    handle = _open(runtime,path)
    if handle==(1<<64)-1:
        path.destroy()
        directory.destroy()
        return None,_error(runtime,0x13,capture=capture_error),0
    packet = None
    if _plain(runtime,'GetFileSize',(handle,))&0xFFFFFFFF==50:
        packet = _Vector(runtime,bytes(50))
        ignored,effects = _api(runtime,'ReadFile',(handle,50))
        if (not isinstance(effects,tuple) or len(effects)!=2 or not isinstance(effects[0],bytes) or
                len(effects[0])>50 or type(effects[1]) is not int or not 0<=effects[1]<=len(effects[0])):
            raise InputError('native profile read requires bounded bytes and an observed byte count')
        raw,count = effects
        if raw:
            runtime.memory.write(packet.pointer,raw,source='2C5D590.profile_ReadFile_output')
    else:
        count = 0
    clear = decode_profile(runtime,packet,copy_material=False) if count==50 else None
    _plain(runtime,'CloseHandle',(handle,))
    if count!=50:
        if packet is not None:
            packet.destroy()
        path.destroy()
        directory.destroy()
        return None,_error(runtime,0x12,capture=capture_error),0
    material = _Vector(runtime,clear) if clear is not None else None
    packet.destroy()
    path.destroy()
    directory.destroy()
    return material,None if material is not None else _error(runtime,0x15,capture=capture_error),4


class _NativeEnumeration:
    def __init__(self, runtime, rbp, *, windows=False):
        from .primary_device_enumeration import DeviceEnumeration
        from .primary_worker import WorkerObservations

        if not runtime.memory.load(runtime.image_base + _HARDWARE_FLAG, 1) & 1:
            raise PrimarySemanticUnavailable('device hardware constructor requires its completed source lookup')

        class Transcript(WorkerObservations):
            def __init__(self):
                pass

            def take(self, current, name, arguments):
                return _api(current, name, arguments)

        literal = runtime.image_base + 0x4905276
        if not any(region.address <= literal < region.address + len(region.data)
                   for region in runtime.memory._regions):
            runtime.memory.map(literal, '\\GLOBAL??\0'.encode('utf-16le'),
                               name='fixed source GLOBAL?? literal', initialized=True)
        self.runtime, self.rbp, self.hardware = runtime, rbp, rbp - 0x40
        self.raw_fields = not windows
        runtime.memory.write(self.hardware, bytes(64), source='2C5ED09.hardware_zero')
        runtime.memory.store(rbp + 0x6428, self.hardware, 8, source='2C5ECE5.hardware_pointer')
        runtime.memory.store(rbp + 0x6430, 0xFFFFFFFF, 4, source='2C5ECDF.initial_com_gate')
        self.bridge = None
        if windows:
            from .primary_windows_enumeration import WindowsEnumerationObservations

            self.bridge = WindowsEnumerationObservations()
        self.stage = DeviceEnumeration(runtime, rbp, self.bridge if self.bridge is not None else Transcript())
        self.stage.initialize()

    def close(self):
        if self.bridge is None:
            return
        try:
            self.bridge.close()
        finally:
            statuses = tuple((name, result) for name, args, result, effects in self.bridge.records)
            cleanup = tuple(row[2:] for row in self.bridge.cleanup_records)
            self.runtime.events.append(('device.windows_enumeration_closed', statuses, cleanup,
                                        len(self.bridge.pending_handles), self.bridge.scratch_count))
        if self.bridge.pending_handles or self.bridge.scratch_count:
            raise PrimarySemanticUnavailable('Windows enumeration cleanup left unresolved native resources')

    def _field_api(self, name, arguments, outputs=()):
        from .primary_device_enumeration import _call
        stage = self
        class Transcript:
            def take(self, current, api, args):
                return _api(current, api, args)
        return _call(stage.runtime, Transcript(), name, arguments, outputs)

    def system_information_material(self):
        pointer = self.rbp + 0x63E0
        status = self._field_api('NtQuerySystemInformation', (1, pointer, 12, 0), ((pointer, 12),))
        material = None
        if status == 0:
            material = self.runtime.memory.read(pointer + 2, 4) + self.runtime.memory.read(pointer + 8, 4)
        return status, material

    def cpuid(self, leaf, subleaf=0):
        from .primary_device_source_inputs import require_device_source_binding, take_device_source_observation
        require_device_source_binding(self.runtime)
        if subleaf != 0 or leaf not in (0x80000002, 0x80000003, 0x80000004, 0x80000005, 0, 1, 2, 0x40000000):
            raise InputError('native device CPUID request leaves the source field domain')
        transcript = self.runtime.worker_observations
        if transcript is None:
            raise PrimarySemanticUnavailable('native device CPUID has no raw observation binding')
        result, words = take_device_source_observation(self.runtime, 'CPUID', (leaf, subleaf))
        if (not isinstance(words, tuple) or len(words) != 4 or
                any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in words)):
            raise InputError('native device CPUID requires four exact DWORD output registers')
        return words

    def volume_serial(self):
        memory, base = self.runtime.memory, self.runtime.image_base
        root = base + 0x4904E66
        literal = 'C:\\\0'.encode('utf-16le')
        containing = next((region for region in memory._regions
                           if region.address <= root and root + len(literal) <= region.address + len(region.data)), None)
        if containing is None:
            memory.map(root, bytearray(literal), name='fixed source volume root literal', initialized=True)
        elif memory.read(root, len(literal)) != literal:
            raise InputError('native device volume root literal differs from the fixed source')
        pointer = self.rbp + 0x5F2C
        memory.store(pointer, 0, 4, source='2C726E1.volume_serial_initial')
        status = self._field_api('GetVolumeInformationW', (root, 0, 0, pointer, 0, 0, 0, 0), ((pointer, 4),))
        return memory.load(pointer, 4) if status else None

    def uuid_tail(self):
        pointer = self.rbp + 0x5F18
        status = self._field_api('UuidCreateSequential', (pointer,), ((pointer, 16),))
        return status, self.runtime.memory.read(pointer + 10, 6) if status == 0 else None

    def object_collection(self):
        self.stage.object_collection(self.hardware)
        digest = self.runtime.memory.load(self.hardware + 4, 4)
        self.runtime.events.append(('2C6B17D.object_enumeration_complete', self.stage.tree.address,
                                    self.hardware, digest))
        return None, digest

    def display_collection(self):
        self.stage.display_collection(self.hardware)
        digest = self.runtime.memory.load(self.hardware + 20, 4)
        self.runtime.events.append(('2C769B9.display_enumeration_complete', self.stage.tree.address,
                                    self.hardware, digest))
        return (), digest


def _checkpoint_update(runtime, address, hardware, material, flagged):
    from .primary_memory import UnknownMemory
    try:
        if runtime.memory.load(address, 2) != 1:
            return True
    except UnknownMemory as error:
        error.pc_rva = 0x2D6DE53
        raise
    if runtime.memory.read(address + 72, 8) != mix_device_bytes(material).to_bytes(8, 'little'):
        return True
    if runtime.memory.load(address + 71, 1) != hardware[63]:
        return True
    if bool(runtime.memory.load(address + 81, 1) & 1) != flagged:
        return True
    distance = 0
    for index in range(3):
        previous = runtime.memory.load(address + 8 + index * 8, 8)
        current = int.from_bytes(hardware[index * 8:index * 8 + 8], 'little')
        distance += (previous ^ current).bit_count()
    return distance != 0


def _device_rand_s(runtime, destination, role):
    from .primary_device_source_inputs import DeviceSourceObservations, require_device_source_binding
    observer = require_device_source_binding(runtime)
    if observer is not None:
        if not isinstance(observer, DeviceSourceObservations):
            raise InputError('device random source binding has the wrong owner type')
        return observer.device_rand_s(runtime, destination, role)
    from .primary_request_runtime import random_s
    return random_s(runtime, destination)


def _header_random_bytes(runtime, destination, size):

    if type(size) is not int or size != 4:
        raise InputError('native device header entropy requests one DWORD')
    status = _device_rand_s(runtime, destination, 'HEADER')
    if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
        raise InputError('native device header requires an observed rand_s status DWORD')
    raw = runtime.memory.read(destination, 4)
    if not isinstance(raw, bytes) or len(raw) != 4:
        raise InputError('native device header requires its exact observed rand_s output DWORD')
    runtime.events.append(('2D8B065.header_rand_s', status))
    return raw


def _profile_nonce_random_bytes(runtime, destination, size):
    if type(size) is not int or size != 4:
        raise InputError('native profile nonce entropy requests one DWORD')
    status = _device_rand_s(runtime, destination, 'PROFILE_NONCE')
    if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
        raise InputError('native profile nonce requires an observed rand_s status DWORD')
    raw = runtime.memory.read(destination, 4)
    if not isinstance(raw, bytes) or len(raw) != 4:
        raise InputError('native profile nonce requires its exact observed rand_s output DWORD')
    runtime.events.append(('2CB2528.profile_nonce_rand_s', status))
    return raw


def _produce(runtime, output, secondary, key_address, factory):
    from .primary_device import CapiObservation
    from .primary_device_provider import DeviceResult
    from .primary_windows import collect_device_observations
    from .primary_device_hypervisor import classify
    from .primary_worker_response import _frame

    key = _String.read(runtime,key_address).value()
    if not key or b'\0' in key:
        raise InputError('native device producer requires its raw nonempty folder key')
    frame,rbp = _frame(runtime,0x1C148,'2C5D590.device_core_frame')
    hardware_pointer = rbp - 0x40
    runtime.memory.write(hardware_pointer, bytes(64), source='2C5DA13.outer_hardware_zero')
    def random_bytes(size):
        if type(size) is not int or size != 4:
            raise InputError('native checkpoint nonce entropy requests one DWORD')
        status = _device_rand_s(runtime,rbp+0x20,'CHECKPOINT_NONCE')
        if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
            raise InputError('native checkpoint nonce requires an observed rand_s status DWORD')
        raw = runtime.memory.read(rbp+0x20,4)
        if not isinstance(raw,bytes) or len(raw) != 4:
            raise InputError('native checkpoint nonce requires its exact observed rand_s output DWORD')
        runtime.events.append(('2C5D590.checkpoint_nonce_rand_s',status))
        return raw
    runtime._device_core_active = True
    available = _hardware_available(runtime, rbp)
    old_address = rbp + 0x1000
    if available:
        enumeration = (_NativeEnumeration(runtime, rbp, windows=factory.enumeration_source == 'windows')
                       if factory.enumeration_source != 'observed' else None)
        try:
            observations = collect_device_observations(factory.source, enumeration=enumeration)
        finally:
            if enumeration is not None:
                enumeration.close()
        if observations.object_names is not None or observations.displays:
            raise PrimarySemanticUnavailable('2C5D590 native object/display enumeration requires its container allocation lifetime')
        if factory.injected_material is not None:
            from dataclasses import replace
            observations = replace(observations,injected_material=factory.injected_material)
        hardware = initial_device_profile(observations)
        runtime.memory.write(hardware_pointer, hardware, source='device.hardware_fields')
        runtime.memory.write(old_address, bytes(1000), source='2C76B53.old_checkpoint_zero')
        record = _checkpoint(runtime,factory,key)
        if record is not None:
            runtime.memory.write(old_address, record, source='device.old_checkpoint_decoded_copy')
    else:
        hardware = runtime.memory.read(hardware_pointer, 64)
        record = None
    if not available:
        preimage = factory.environment.device_checkpoint_preimage
        mask = factory.environment.device_checkpoint_knownmask
        if preimage is not None:
            if (not isinstance(preimage, bytes) or len(preimage) > 1000 or
                    (mask is not None and (not isinstance(mask, bytes) or len(mask) != len(preimage) or
                                           any(value not in (0, 1) for value in mask)))):
                raise InputError('old checkpoint preimage requires at most 1000 bytes and an exact binary known mask')
            mask = bytes([1]) * len(preimage) if mask is None else mask
            for index, known in enumerate(mask):
                if known:
                    runtime.memory.write(old_address + index, preimage[index:index + 1],
                                         source='device.explicit_old_checkpoint_preimage')
                else:
                    runtime.memory.forget(old_address + index, 1, source='device.explicit_old_checkpoint_unknown')
        elif mask is not None:
            raise InputError('old checkpoint mask requires explicit bytes')
    checkpoint_errors = []
    def save(value):
        error = _checkpoint(runtime,factory,key,record=value,random_bytes=random_bytes)
        if error is not None:
            checkpoint_errors.append(error>>32 if error>0xFFFFFFFF else error)
        return error is None
    def acquire(*, capture_error=True):
        return _acquire_public_key(runtime, rbp, factory, key,
                                   lambda size: _profile_nonce_random_bytes(runtime,rbp+0x20,size),
                                   capture_error=capture_error)
    flagged = bool(record[81]&1) if record is not None else False
    if record is not None and checkpoint_hardware_invalidates(record,hardware):
        preliminary,error,method,capi = acquire(capture_error=False)
        if error is None:
            if mix_device_bytes(preliminary.value()).to_bytes(8,'little')==record[72:80]:
                if save(invalid_checkpoint_record(hardware)):
                    flagged = True
            preliminary.destroy()
    material,error,method,capi_error = acquire()
    if error is not None:
        factory.last_result = DeviceResult(b'',False,error,tuple(checkpoint_errors))
        runtime.memory.store(secondary,error,8,source='2C5D590.profile_error')
        runtime.memory.unmap(frame)
        runtime._device_core_active = False
        return 0
    if _checkpoint_update(runtime,old_address,hardware,material.value(),flagged):
        save(new_checkpoint_record(hardware,material.value(),method=method,flagged=flagged))
    classification = classify(runtime, key_preimage=factory.environment.device_hypervisor_key_preimage,
                              windows=factory.enumeration_source == 'windows')
    seconds = _device_time_seconds(runtime, factory) & 0xFFFFFFFF
    value = encode_device(runtime,material,method|(0x80 if flagged else 0),classification,seconds,
                          lambda size: _header_random_bytes(runtime,rbp+0x20,size))
    value.write_to(output)
    runtime.memory.store(secondary,capi_error,8,source='2C5D590.preserved_CAPI_error')
    factory.last_result = DeviceResult(value.value(),True,capi_error,tuple(checkpoint_errors))
    runtime.memory.unmap(frame)
    runtime._device_core_active = False
    return 1


def produce(runtime, output, secondary, key_address):
    factory = _source(runtime)
    try:
        return _produce(runtime,output,secondary,key_address,factory)
    finally:
        runtime._device_core_active = False
        if factory.close_source:
            factory.source.close()


def _failure(runtime, factory, owner, secondary, rbp):
    from .primary_device_records import _image
    from .primary_logger import log
    from .primary_postfetch import ProviderTelemetryRecord
    from .primary_worker_consumer import _invoke
    from .primary_worker_response import _assign, _image as _response_image, _owner

    memory,base = runtime.memory,runtime.image_base
    image = _image()
    item = image['refresh_failure_log']
    log(runtime,bytes.fromhex(item['source_file_hex']),item['line'],bytes.fromhex(item['template_hex']),
        bytes.fromhex(item['tag_hex']),item['severity'],secondary)
    _assign(runtime,owner,_String.construct(runtime,b''))
    factory.cached_value = _String.read(runtime,owner).value()
    factory.failure_reported = bool(memory.load(owner+24,1))
    runtime.events.append(('1BE6150.native_cache_publish',owner,0))
    if factory.failure_reported:
        return
    event = rbp+0x60
    memory.store(event,base+image['failure_event_vtable_rva'],8,source='1BE6939.device_failure_event_vtable')
    _String.construct(runtime,ProviderTelemetryRecord.device_failure(secondary).strings[0]).write_to(event+8)
    for offset in range(32,200,24):
        memory.store(event+offset,0,2,source='1BE68E1.device_failure_empty_field')
    memory.write(event+200,bytes(168),source='1BE6920.device_failure_columns')
    _owner(runtime,_response_image())
    columns = rbp+0x1D0
    memory.write(columns,bytes(48),source='1BE69A8.device_failure_metadata_initialization')
    for offset in (0,24):
        _assign(runtime,columns+offset,_String.construct(runtime,b''))
    _invoke(runtime,0x1BEFC10,base+0x67519B8,event,columns,1,10,0)
    for offset in (24,0):
        _String.read(runtime,columns+offset).destroy()
    memory.store(owner+24,1,1,source='1BE6A37.device_failure_report_commit')
    factory.failure_reported = True
    runtime.events.append(('1BE6A37.device_failure_report_commit',))
    for offset in list(range(344,223,-24))+list(range(176,7,-24)):
        _String.read(runtime,event+offset).destroy()


def refresh(runtime, owner):
    from .primary_device_identifiers import configure
    from .primary_device_provider import DeviceResult
    from .primary_device_records import _image
    from .primary_logger import log
    from .primary_sdk import NativeByteReturn
    from .primary_worker_consumer import _invoke
    from .primary_worker_response import _assign, _frame

    frame,rbp = _frame(runtime,0x2A8,'1BE6150.device_refresh_frame')
    current = _String.read(runtime,owner)
    if current.value():
        gate = _invoke(runtime,0x1CE2B70,runtime.image_base+0x6751AB8)
        if not isinstance(gate,NativeByteReturn):
            raise PrimarySemanticUnavailable('1BE6150 native refresh gate requires its known byte return')
        if not gate.value:
            item = _image()['refresh_rejected_log']
            log(runtime,bytes.fromhex(item['source_file_hex']),item['line'],bytes.fromhex(item['template_hex']),
                bytes.fromhex(item['tag_hex']),item['severity'],current.value())
            runtime.events.append(('1BE6A5D.native_cached_refresh_rejected',owner,len(current.value())))
            runtime.memory.unmap(frame)
            return None
    factory = _source(runtime,owner)
    _String.construct(runtime,b'').write_to(rbp+0x20)
    key = _String.construct(runtime,b'xfolder')
    key.write_to(rbp+8)
    success = produce(runtime,rbp+0x20,rbp,rbp+8)
    secondary = runtime.memory.load(rbp,8)
    value = _String.read(runtime,rbp+0x20)
    if not success:
        _failure(runtime,factory,owner,secondary,rbp)
    else:
        _assign(runtime,owner,value)
        factory.cached_value = _String.read(runtime,owner).value()
        factory.last_result = DeviceResult(factory.cached_value,True,secondary,factory.last_result.checkpoint_errors)
        if not hasattr(runtime,'_native_device_caches'):
            runtime._native_device_caches = {}
        runtime._native_device_caches[factory] = owner
        runtime.events.append(('1BE6150.native_cache_publish',owner,len(factory.cached_value)))
        _String.construct(runtime,b'qq_o_xd').write_to(rbp+0x60)
        configure(runtime,rbp+0x60,rbp+0x20)
        item = _image()['cached_getter_log']
        log(runtime,bytes.fromhex(item['source_file_hex']),101,b'x: %s',bytes.fromhex(item['tag_hex']),item['severity'],
            _String.read(runtime,owner).value())
        factory.cached_value = _String.read(runtime,owner).value()
    key.destroy()
    value.destroy()
    runtime.memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    if rva==0x2C5D590 and len(values)==3:
        return produce(runtime,*values)
    if rva==0x1BE6150 and len(values)==1:
        return refresh(runtime,*values)
    raise InputError('native device source interface argument count mismatch')
