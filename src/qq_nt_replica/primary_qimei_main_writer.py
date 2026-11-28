from .primary_qimei_cache import QimeiCacheCodec
from .primary_qimei_context import QimeiContextProducer
from .primary_qimei_extra_sources import QimeiExtraSources, _wide_cstring
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, _bytes, _integer, _signed
from .primary_qimei_storage import StorageBuffer


class QimeiMainWriter:
    _api = QimeiExtraSources._api
    _pointer = QimeiExtraSources._pointer

    def __init__(self, observations, *, codec, context=None, context_observations=None, acl_cache=None):
        if not isinstance(codec, QimeiCacheCodec):
            raise QimeiRequestError('source cache codec required')
        self.context = QimeiContextProducer() if context is None else context
        if not isinstance(self.context, QimeiContextProducer):
            raise QimeiRequestError('source context producer required')
        self.observations = observations
        self.codec = codec
        self.context_observations = observations if context_observations is None else context_observations
        self.acl_cache = set() if acl_cache is None else acl_cache
        if not isinstance(self.acl_cache, set):
            raise QimeiRequestError('source path cache set required')
        self.last_acl_code = None

    def _heap_allocate(self, length):
        if not 0 <= length <= 1 << 20:
            raise QimeiRequestBoundary('source writer allocation exceeds bounded backing')
        heap, unused = self._api('GetProcessHeap', (), width=64)
        pointer, unused = self._api('HeapAlloc', (heap, 8, length), width=64)
        return pointer

    def _heap_free(self, pointer):
        if pointer:
            heap, unused = self._api('GetProcessHeap', (), width=64)
            self._api('HeapFree', (heap, 0, pointer))

    def _username(self):
        buffer = StorageBuffer(bytes(8))
        pointer = 0
        try:
            status, output = self._api('NetWkstaUserGetInfo', (None, 1, buffer), {'buffer': buffer})
            pointer = int.from_bytes(output['buffer'].read(), 'little')
            if status or not pointer:
                return b''
            username = int.from_bytes(self._pointer(pointer, 8).read(0, 8), 'little')
            return _wide_cstring(self._pointer(username))
        finally:
            if pointer:
                self._api('NetApiBufferFree', (pointer,))

    def _wide_path(self, path):
        count, unused = self._api('MultiByteToWideChar', (0, 0, path, -1, None, 0))
        allocation = _signed(count + 1, 32)
        if not 0 < allocation <= (1 << 20) // 2:
            raise QimeiRequestBoundary('source wide path allocation exceeds bounded backing')
        data = StorageBuffer(bytes(allocation * 2))
        unused, output = self._api('MultiByteToWideChar', (0, 0, path, -1, data, _signed(count, 32)), {'data': data})
        return _wide_cstring(output['data'])

    def _sid(self, username):
        self._api('SetLastError', (0,))
        size, domain_size, sid_use = StorageBuffer(bytes(4)), StorageBuffer(bytes(4)), StorageBuffer(bytes(4))
        status, output = self._api('LookupAccountNameW', (None, username, None, size, None, domain_size, sid_use),
                                   {'size': size, 'domain_size': domain_size, 'sid_use': sid_use})
        if not status:
            error, unused = self._api('GetLastError', ())
            if error != 122:
                return 0
        length = int.from_bytes(output['size'].read(), 'little')
        domain_length = int.from_bytes(output['domain_size'].read(), 'little')
        sid = self._heap_allocate(length)
        if not sid:
            return 0
        domain = 0
        try:
            domain = self._heap_allocate(domain_length * 2)
            if domain:
                self._api('LookupAccountNameW', (None, username, sid, output['size'], domain, output['domain_size'], output['sid_use']),
                          {'size': output['size'], 'domain_size': output['domain_size'], 'sid_use': output['sid_use']})
            return sid
        except BaseException:
            self._heap_free(sid)
            raise
        finally:
            self._heap_free(domain)

    def _old_sd(self, path):
        self._api('SetLastError', (0,))
        needed = StorageBuffer(bytes(4))
        status, output = self._api('GetFileSecurityW', (path, 4, None, 0, needed), {'needed': needed})
        if not status:
            error, unused = self._api('GetLastError', ())
            if error != 122:
                return 0
        length = int.from_bytes(output['needed'].read(), 'little')
        pointer = self._heap_allocate(length)
        if pointer:
            try:
                self._api('GetFileSecurityW', (path, 4, pointer, length, output['needed']), {'needed': output['needed']})
            except BaseException:
                self._heap_free(pointer)
                raise
        return pointer

    def _get_ace(self, acl, index):
        ace = StorageBuffer(bytes(8))
        status, output = self._api('GetAce', (acl, index, ace), {'ace': ace})
        return status, int.from_bytes(output['ace'].read(), 'little')

    def _add_ace(self, acl, ace):
        header = self._pointer(ace, 4).read(0, 4)
        status, unused = self._api('AddAce', (acl, 2, 0xffffffff, ace, int.from_bytes(header[2:4], 'little')))
        return status

    def _dacl(self, old_sd, sid, new_sd, owned):
        present, old_acl, defaulted = StorageBuffer(bytes(4)), StorageBuffer(bytes(8)), StorageBuffer(bytes(4))
        status, output = self._api('GetSecurityDescriptorDacl', (old_sd, present, old_acl, defaulted),
                                  {'present': present, 'acl': old_acl, 'defaulted': defaulted})
        if not status:
            return 1, new_sd
        old_acl = int.from_bytes(output['acl'].read(), 'little')
        info = StorageBuffer(bytes(4) + (8).to_bytes(4, 'little') + bytes(4))
        if int.from_bytes(output['present'].read(), 'little') and old_acl:
            status, output = self._api('GetAclInformation', (old_acl, info, 12, 2), {'info': info})
            if not status:
                return 2, new_sd
            info = output['info']
        count = int.from_bytes(info.read(0, 4), 'little')
        if count > 65536:
            raise QimeiRequestBoundary('source ACE count exceeds bounded iteration')
        length, unused = self._api('GetLengthSid', (sid,))
        acl = self._heap_allocate(int.from_bytes(info.read(4, 4), 'little') + length + 8)
        if not acl:
            return 3, new_sd
        owned.append(acl)
        status, unused = self._api('InitializeAcl', (acl, int.from_bytes(info.read(4, 4), 'little') + length + 8, 2))
        if not status:
            return 4, new_sd
        index = 0
        while index < count:
            status, ace = self._get_ace(old_acl, index)
            if not status:
                break
            if self._pointer(ace, 4).read(1, 1)[0] & 0x10:
                break
            equal, unused = self._api('EqualSid', (sid, ace + 8))
            if not equal and not self._add_ace(acl, ace):
                break
            index += 1
        status, unused = self._api('AddAccessAllowedAceEx', (acl, 2, 3, 0x10000000, sid))
        if not status:
            return 5, new_sd
        code = 0
        while index < count:
            status, ace = self._get_ace(old_acl, index)
            if not status:
                code = 6
                break
            if not self._add_ace(acl, ace):
                code = 7
                break
            index += 1
        status, output = self._api('SetSecurityDescriptorDacl', (new_sd, 1, acl, 0), {'sd': new_sd})
        return (code if status else 8), output['sd']

    def _acl(self, path):
        username = self._username()
        if not username:
            return 1
        wide = self._wide_path(path)
        if not wide:
            return 2
        sid = old_sd = 0
        owned = []
        try:
            sid = self._sid(username)
            if not sid:
                return 3
            old_sd = self._old_sd(wide)
            if not old_sd:
                return 4
            new_sd = StorageBuffer(bytes(40))
            status, output = self._api('InitializeSecurityDescriptor', (new_sd, 1), {'sd': new_sd})
            if not status:
                return 5
            code, new_sd = self._dacl(old_sd, sid, output['sd'], owned)
            if code:
                return 60 + code
            control, revision = StorageBuffer(bytes(2)), StorageBuffer(bytes(4))
            status, output = self._api('GetSecurityDescriptorControl', (old_sd, control, revision),
                                       {'control': control, 'revision': revision})
            if not status:
                return 71
            bits = int.from_bytes(output['control'].read(), 'little')
            mask = 0x500 if bits & 0x400 else (0x1000 if bits & 0x1000 else 0)
            if mask:
                status, output = self._api('SetSecurityDescriptorControl', (new_sd, mask, mask), {'sd': new_sd})
                if not status:
                    return 72
                new_sd = output['sd']
            status, unused = self._api('SetFileSecurityW', (wide, 4, new_sd))
            return 0 if status else 73
        finally:
            for pointer in reversed(owned):
                self._heap_free(pointer)
            self._heap_free(old_sd)
            self._heap_free(sid)


    def __call__(self, path, payload):
        path, payload = _bytes(path), _bytes(payload)
        if len(payload) > (1 << 20) - 9:
            raise QimeiRequestBoundary('writer payload exceeds bounded source allocation')
        self.last_acl_code = None
        wrapper, unused = self._api('calloc', (1, len(payload) + 9), width=64)
        if not wrapper:
            return 1
        cipher_pointer = 0
        try:
            context = self.context.produce(self.context_observations)
            cipher_length = ((len(payload) + 8) // 16 + 1) * 16
            cipher_pointer, unused = self._api('malloc', (cipher_length,), width=64)
            if not cipher_pointer:
                return 3
            try:
                ciphertext = self.codec.encode_payload(payload, context=context).value
            except MemoryError:
                return 3
            if not ciphertext:
                return 3
            if len(ciphertext) != cipher_length:
                raise QimeiRequestError('cache codec output disagrees with source CBC allocation')
            stream, unused = self._api('fopen', (path, b'wb'), width=64)
            if not stream:
                return 2
            try:
                written, unused = self._api('fwrite', (ciphertext, 1, cipher_length, stream), width=64)
            finally:
                self._api('fclose', (stream,))
            if written != cipher_length:
                return 2
            if path:
                access, unused = self._api('_access', (path, 0))
                if access == 0:
                    enabled, unused = self._api('SHELL32.ordinal680', ())
                    if enabled and path not in self.acl_cache:
                        self.last_acl_code = self._acl(path)
                        self.acl_cache.add(path)
            return 0
        finally:
            self._api('free', (wrapper,))
            if cipher_pointer:
                self._api('free', (cipher_pointer,))
