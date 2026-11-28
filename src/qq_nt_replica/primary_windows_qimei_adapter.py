import ctypes

from .primary_qimei_adapter_sources import INTERFACES_KEY
from .primary_qimei_context import ContextObservationError
from .primary_qimei_observations import QimeiApiReply, _cstring
from .primary_qimei_storage import StorageBuffer
from .primary_windows_qimei_context import WindowsQimeiContextAPIBackend
from .primary_windows_qimei_storage import _changes


class WindowsQimeiAdapterAPIBackend(WindowsQimeiContextAPIBackend):
    def __init__(self, *, allow_netbios_reset=False):
        if type(allow_netbios_reset) is not bool:
            raise ContextObservationError('NetBIOS reset policy requires explicit bool')
        super().__init__()
        self.allow_netbios_reset = allow_netbios_reset
        self._interface_paths = set()

    def request(self, name, args):
        self._check()
        if name == 'Netbios' and len(args) == 2 and isinstance(args[0], StorageBuffer) and args[0].read(0, 1) == b'\x32' and not self.allow_netbios_reset:
            raise ContextObservationError('source NetBIOS RESET requires enabled side-effect policy')
        if name == 'GetAdaptersInfo':
            reply = super().request(name, args)
            if reply.result == 0:
                node, visited = 0, set()
                while node is not None:
                    if node in visited or not 0 <= node <= 11264 - 704:
                        raise ContextObservationError('source adapter path lookup leaves bounded chain')
                    visited.add(node)
                    self._interface_paths.add(INTERFACES_KEY + b'\\' + _cstring(reply.output, node + 12, 260))
                    pointer = int.from_bytes(reply.output.read(node, 8), 'little')
                    node = pointer - reply.base if pointer else None
            return reply
        if name == 'RegOpenKeyExA' and len(args) == 5 and args[1] in self._interface_paths:
            root, path, options, access, output = args
            if root != 0xFFFFFFFF80000002 or options != 0 or access != 0x101 or not isinstance(output, StorageBuffer) or output.read() != bytes(8):
                raise ContextObservationError('interface registry open leaves fixed source contract')
            data = ctypes.create_string_buffer(output.read(), 8)
            result = self._call(name, ctypes.c_int32, (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p),
                (root, path, options, access, data))
            handle = int.from_bytes(data.raw, 'little')
            if handle:
                self._keys[handle] = path
            return QimeiApiReply(result, tuple(('handle', offset, value) for offset, value in _changes(output.read(), data.raw)))
        if name == 'RegQueryValueExA' and len(args) == 6 and self._keys.get(args[0]) in self._interface_paths:
            handle, value, reserved, kind, data, size = args
            if (value not in (b'DhcpIPAddress', b'IPAddress') or reserved != 0 or kind is not None or not isinstance(size, StorageBuffer)
                    or len(size.data) != 4 or data is not None and (not isinstance(data, StorageBuffer) or len(data.data) != 260)):
                raise ContextObservationError('interface registry query leaves fixed source contract')
            capacity = int.from_bytes(size.read(), 'little')
            if data is not None and capacity > len(data.data):
                raise ContextObservationError('interface registry size exceeds known backing')
            count = ctypes.create_string_buffer(size.read(), 4)
            output = None if data is None else ctypes.create_string_buffer(data.read(), len(data.data))
            result = self._call(name, ctypes.c_int32, (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p),
                (handle, value, None, None, output, count))
            writes = [('size', offset, raw) for offset, raw in _changes(size.read(), count.raw)]
            if data is not None:
                writes += [('data', offset, raw) for offset, raw in _changes(data.read(), output.raw)]
            return QimeiApiReply(result, tuple(writes))
        return super().request(name, args)
