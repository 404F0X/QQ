import ctypes
import os
import threading

from .primary_qimei_context import ContextObservationError
from .primary_qimei_observations import (CLASSIFIER_RULES, NETWORK_KEY, QimeiAdapterReply,
                                       QimeiApiReply, QimeiClassifierObservations, QimeiSelectorObservations, _cstring)
from .primary_qimei_storage import StorageBuffer
from .primary_windows_qimei_storage import _changes


class WindowsQimeiContextAPIBackend:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ContextObservationError('native Qimei context requires Windows x64')
        self._owner = os.getpid(), threading.get_native_id()
        self._keys = {}
        self._modules, self._targets, self._connections = {}, {}, set()
        self._library_path = None
        self.closed = False
        self.records = []
        self.registry = ctypes.WinDLL('advapi32', handle=ctypes.windll.advapi32._handle, use_last_error=True)
        self.kernel = ctypes.WinDLL('kernel32', handle=ctypes.windll.kernel32._handle, use_last_error=True)

    def _check(self):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise ContextObservationError('Qimei context API requires its open creator process and thread')

    def _call(self, name, result, types, args):
        self._check()
        if name == 'GetAdaptersInfo':
            function = ctypes.WINFUNCTYPE(result, *types)(args[0])
            value = function(*args[1:])
        else:
            if name == 'PathAppendW':
                library = ctypes.windll.shlwapi
            elif name == 'Netbios':
                library = ctypes.windll.netapi32
            else:
                library = self.registry if name.startswith('Reg') else self.kernel
            function = getattr(library, name)
            function.restype, function.argtypes = result, types
            value = function(*args)
        pointer = result is ctypes.c_void_p
        value = int(value or 0) & ((1 << 64) - 1 if pointer else 0xFFFFFFFF)
        self.records.append({'api': name, 'status': bool(value) if pointer else value})
        return value

    def request(self, name, args):
        self._check()
        if type(args) is not tuple:
            raise ContextObservationError('Qimei registry arguments require a tuple')
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        if name == 'GetSystemDirectoryW':
            if len(args) != 2 or not isinstance(args[0], StorageBuffer) or args[0].read() != bytes(520) or args[1] != 260:
                raise ContextObservationError('selector system directory differs from source allocation')
            output = ctypes.create_string_buffer(bytes(520), 520)
            result = self._call(name, u, (p, u), (output, 260))
            self._library_path = output.raw
            return QimeiApiReply(result, tuple(('data', offset, raw) for offset, raw in _changes(bytes(520), output.raw)))
        if name == 'PathAppendW':
            if (len(args) != 2 or not isinstance(args[0], StorageBuffer) or args[0].read() != self._library_path
                    or args[1] != 'iphlpapi.dll'.encode('utf-16le') + bytes(2)):
                raise ContextObservationError('selector path append differs from fixed source library')
            before = args[0].read()
            output, suffix = ctypes.create_string_buffer(before, 520), ctypes.create_string_buffer(args[1])
            result = self._call(name, i, (p, p), (output, suffix))
            self._library_path = output.raw
            return QimeiApiReply(result & 0xFFFFFFFF, tuple(('data', offset, raw) for offset, raw in _changes(before, output.raw)))
        if name == 'LoadLibraryW':
            if len(args) != 1 or self._library_path is None:
                raise ContextObservationError('selector library path has not been produced')
            end = next((offset for offset in range(0, 520, 2) if self._library_path[offset:offset + 2] == bytes(2)), None)
            if end is None or args[0] != self._library_path[:end + 2]:
                raise ContextObservationError('selector load differs from current source-built path')
            value = self._call(name, p, (p,), (ctypes.create_string_buffer(args[0]),))
            if value:
                self._modules[value] = self._modules.get(value, 0) + 1
            return QimeiApiReply(value)
        if name == 'GetProcAddress':
            if len(args) != 2 or args[0] not in self._modules or args[1] != b'GetAdaptersInfo':
                raise ContextObservationError('selector export lookup requires its owned source module')
            value = self._call(name, p, (p, ctypes.c_char_p), args)
            if value:
                self._targets[value] = args[0]
            return QimeiApiReply(value)
        if name == 'FreeLibrary':
            if len(args) != 1 or args[0] not in self._modules:
                raise ContextObservationError('selector unload requires an owned module reference')
            value = self._call(name, i, (p,), args)
            if value:
                self._modules[args[0]] -= 1
                if self._modules[args[0]] == 0:
                    del self._modules[args[0]]
                    self._targets = {target: module for target, module in self._targets.items() if module != args[0]}
            return QimeiApiReply(value & 0xFFFFFFFF)
        if name == 'GetAdaptersInfo':
            if (len(args) != 3 or args[0] not in self._targets or not isinstance(args[1], StorageBuffer)
                    or len(args[1].data) != 11264 or any(args[1].known) and not all(args[1].known) or not isinstance(args[2], StorageBuffer)
                    or args[2].read() != (11264).to_bytes(4, 'little')):
                raise ContextObservationError('adapter query differs from fixed known or unknown buffer')
            initialized = all(args[1].known)
            output = ctypes.create_string_buffer(args[1].read(), 11264) if initialized else ctypes.create_string_buffer(11264)
            count = ctypes.create_string_buffer(args[2].read(), 4)
            result = self._call(name, u, (p, p), (args[0], output, count))
            raw, base = output.raw, ctypes.addressof(output)
            known = b'\1' * 11264 if initialized else bytes(11264)
            if result == 0:
                from .primary_windows_device_hardware import adapter_buffer_effect
                effect = adapter_buffer_effect(raw, base)
                if not initialized:
                    known = effect.known
                buffer, node, visited = StorageBuffer(raw, known), 0, set()
                while node is not None:
                    if node in visited:
                        raise ContextObservationError('cyclic source adapter output')
                    visited.add(node)
                    self._connections.add(_cstring(buffer, node + 12, 260) + b'\\Connection')
                    following = int.from_bytes(buffer.read(node, 8), 'little')
                    node = following - base if following else None
            return QimeiAdapterReply(result, base, StorageBuffer(raw, known), StorageBuffer(count.raw))
        if name == 'Netbios':
            return self._netbios(args)
        if name in ('GetDriveTypeA', 'QueryDosDeviceA'):
            if not args or args[0] not in {bytes((letter, ord(':'))) for letter in range(ord('C'), ord('Z') + 1)}:
                raise ContextObservationError('drive classifier leaves the fixed source paths')
            if name == 'GetDriveTypeA' and len(args) == 1:
                return QimeiApiReply(self._call(name, u, (ctypes.c_char_p,), args))
            if (name != 'QueryDosDeviceA' or len(args) != 3 or not isinstance(args[1], StorageBuffer)
                    or args[1].read() != bytes(260) or type(args[2]) is not int or args[2] != 260):
                raise ContextObservationError('drive mapping differs from fixed source allocation')
            output = ctypes.create_string_buffer(args[1].read(), 260)
            result = self._call(name, u, (ctypes.c_char_p, p, u), (args[0], output, 260))
            return QimeiApiReply(result, tuple(('data', offset, data) for offset, data in _changes(args[1].read(), output.raw)))
        if name == 'RegOpenKeyExA':
            if len(args) != 5:
                raise ContextObservationError('invalid Qimei registry open arity')
            hive, path, options, access, output = args
            classifier = hive == 0xFFFFFFFF80000002 and path in {row[0] for row in CLASSIFIER_RULES} and access == 0x101
            selector = access == 0x20019 and (hive == 0xFFFFFFFF80000002 and path == NETWORK_KEY or
                self._keys.get(hive) == NETWORK_KEY and path in getattr(self, '_connections', ()))
            if (type(hive) is not int or not (classifier or selector)
                    or type(options) is not int or options != 0 or type(access) is not int
                    or not isinstance(output, StorageBuffer) or output.read() != bytes(8)):
                raise ContextObservationError('Qimei registry open leaves the fixed source query domain')
            buffer = ctypes.create_string_buffer(output.read(), 8)
            result = self._call(name, i, (p, ctypes.c_char_p, u, u, p), (hive, path, options, access, buffer))
            handle = int.from_bytes(buffer.raw, 'little')
            if handle:
                self._keys[handle] = path if hive == 0xFFFFFFFF80000002 else self._keys[hive] + b'\\' + path
            return QimeiApiReply(result, tuple(('handle', offset, data) for offset, data in _changes(output.read(), buffer.raw)))
        if name == 'RegQueryValueExA':
            if len(args) != 6:
                raise ContextObservationError('invalid Qimei registry query arity')
            handle, value_name, reserved, value_type, data, size = args
            key = self._keys.get(handle)
            classifier = (key, value_name) in CLASSIFIER_RULES and value_type is None
            selector = (isinstance(key, bytes) and key.startswith(NETWORK_KEY + b'\\') and key.endswith(b'\\Connection')
                        and value_name in (b'MediaSubType', b'PnpInstanceID') and isinstance(value_type, StorageBuffer)
                        and value_type.read() == (4 if value_name == b'MediaSubType' else 1).to_bytes(4, 'little'))
            if (type(handle) is not int or handle not in self._keys or not (classifier or selector)
                    or type(reserved) is not int or reserved != 0
                    or not isinstance(size, StorageBuffer) or len(size.data) != 4
                    or data is not None and (not isinstance(data, StorageBuffer) or len(data.data) != (260 if selector and value_name == b'PnpInstanceID' else 4))):
                raise ContextObservationError('Qimei registry value query leaves the fixed source domain')
            capacity = int.from_bytes(size.read(), 'little')
            if data is not None and capacity > len(data.data):
                raise ContextObservationError('native registry declared size exceeds actual source allocation')
            count = ctypes.create_string_buffer(size.read(), 4)
            buffer = ctypes.create_string_buffer(data.read(), len(data.data)) if data is not None else None
            type_buffer = ctypes.create_string_buffer(value_type.read(), 4) if value_type is not None else None
            result = self._call(name, i, (p, ctypes.c_char_p, p, p, p, p),
                                (handle, value_name, None, type_buffer, buffer, count))
            writes = [('size', offset, raw) for offset, raw in _changes(size.read(), count.raw)]
            if data is not None:
                writes.extend(('data', offset, raw) for offset, raw in _changes(data.read(), buffer.raw))
            if type_buffer is not None:
                writes.extend(('type', offset, raw) for offset, raw in _changes(value_type.read(), type_buffer.raw))
            return QimeiApiReply(result, tuple(writes))
        if name == 'RegCloseKey':
            if len(args) != 1 or type(args[0]) is not int or args[0] not in self._keys:
                raise ContextObservationError('Qimei registry close requires an owned key')
            result = self._call(name, i, (p,), args)
            if result == 0:
                del self._keys[args[0]]
            return QimeiApiReply(result)
        raise ContextObservationError('unsupported native Qimei context API')

    def _netbios(self, args):
        if len(args) != 2 or not isinstance(args[0], StorageBuffer) or len(args[0].data) != 96:
            raise ContextObservationError('NetBIOS requires the source Win64 NCB')
        before = args[0].read()
        command, lana = before[0], before[64]
        expected = bytearray(96)
        expected[0], expected[64] = command, lana
        capacity = {0x37: 256, 0x32: 0, 0x33: 600}.get(command)
        if capacity is None:
            raise ContextObservationError('unsupported source NetBIOS command')
        expected[16:18] = capacity.to_bytes(2, 'little')
        if command == 0x33:
            expected[18:20] = b'*\0'
        if before != bytes(expected) or command == 0x37 and lana != 0:
            raise ContextObservationError('NetBIOS leaves the fixed local source request domain')
        data = args[1]
        if ((capacity == 0 and data is not None) or capacity and (not isinstance(data, StorageBuffer) or len(data.data) != capacity)
                or command == 0x37 and any(data.known) or command == 0x33 and data.read() != bytes(600)):
            raise ContextObservationError('NetBIOS backing differs from source initialization')
        output = ctypes.create_string_buffer(capacity) if capacity else None
        ncb = ctypes.create_string_buffer(before, 96)
        if output is not None:
            ctypes.memmove(ctypes.addressof(ncb) + 8, ctypes.addressof(output).to_bytes(8, 'little'), 8)
        result = self._call('Netbios', ctypes.c_ubyte, (ctypes.c_void_p,), (ncb,))
        after = bytearray(ncb.raw)
        after[8:16] = bytes(8)
        writes = [('ncb', offset, raw) for offset, raw in _changes(before, bytes(after))]
        if command == 0x37 and result == 0:
            length = output.raw[0]
            writes.append(('data', 0, output.raw[:1 + length]))
        elif command == 0x33:
            writes.extend(('data', offset, raw) for offset, raw in _changes(bytes(600), output.raw))
        return QimeiApiReply(result, tuple(writes))

    def snapshot(self):
        return {'closed': self.closed, 'registry_keys': len(self._keys), 'API_calls': len(self.records)}

    def close(self):
        if self.closed:
            return
        self._check()
        for handle in tuple(self._keys):
            if self._call('RegCloseKey', ctypes.c_int32, (ctypes.c_void_p,), (handle,)) == 0:
                del self._keys[handle]
        for module, references in tuple(getattr(self, '_modules', {}).items()):
            for unused in range(references):
                self.request('FreeLibrary', (module,))
        if self._keys or getattr(self, '_modules', {}):
            raise ContextObservationError('Qimei registry cleanup retains owned keys')
        self.closed = True


class WindowsQimeiContextObservations:
    def __init__(self, observations=None, *, backend=None, adapter_preimage=None):
        if adapter_preimage is not None and (not isinstance(adapter_preimage, bytes) or len(adapter_preimage) != 11264):
            raise ContextObservationError('explicit adapter preimage requires exactly11264bytes')
        self.observations, self.backend = observations, backend
        self._adapter_preimage = adapter_preimage
        self._owner = os.getpid(), threading.get_native_id()
        self.classifier = QimeiClassifierObservations(self)
        self.selector = QimeiSelectorObservations(self)
        self.closed = False
        self.consumed = []
        self.storage = None

    def adapter_query_buffer(self):
        self._check()
        return StorageBuffer.unknown(11264) if self._adapter_preimage is None else StorageBuffer(self._adapter_preimage)

    def _check(self):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise ContextObservationError('Qimei context observations require their open creator process and thread')

    def read(self, *key):
        self._check()
        self.consumed.append(key)
        if key[:1] == ('classifier',):
            return self.classifier.read(*key)
        if key[:1] in (('adapters',), ('adapter',), ('netbios',)):
            return self.selector.read(*key)
        if key[:1] == ('storage',):
            if self.storage is None:
                from .primary_qimei_storage import NtStorageContextObservations
                from .primary_windows_qimei_storage import WindowsStorageObservations
                self.storage = NtStorageContextObservations(WindowsStorageObservations())
            return self.storage.read(*key)
        if key[:1] == ('qimei-api',) and len(key) >= 2:
            if self.backend is None:
                self.backend = WindowsQimeiContextAPIBackend()
            return self.backend.request(key[1], key[2:])
        if self.observations is None:
            raise ContextObservationError('Qimei selector observation requires an explicit producer')
        return self.observations.read(*key)

    def read_classifier_fallback(self):
        self._check()
        return self.classifier.read_classifier_fallback()

    def close(self):
        if self.closed:
            return
        self._check()
        errors = []
        if self.backend is not None:
            try:
                self.backend.close()
            except BaseException as error:
                errors.append(error)
        if self.storage is not None:
            try:
                self.storage.observations.close()
            except BaseException as error:
                errors.append(error)
        if errors:
            raise ContextObservationError('Qimei context cleanup did not release all owned resources') from errors[0]
        self.closed = True
