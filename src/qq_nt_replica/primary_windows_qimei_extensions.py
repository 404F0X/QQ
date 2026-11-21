import ctypes
import os
from threading import get_ident

from .primary_qimei_extension_sources import EDGE_MACHINE_KEY, EDGE_USER_KEY, EDGE_VALUES, IDENTITY_VALUES, HARDWARE_CONFIG_KEY, HARDWARE_CURRENT_KEY, HARDWARE_VALUES, STAT_ROOTS
from .primary_qimei_extra_sources import HKCU
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError
from .primary_qimei_storage import StorageBuffer
from .primary_qimei_system_sources import HKLM
from .primary_windows_qimei_extras import WindowsQimeiExtraObservations


class WindowsQimeiExtensionObservations:
    def __init__(self, api=None):
        if ctypes.sizeof(ctypes.c_void_p) != 8 or api is None and os.name != 'nt':
            raise QimeiRequestError('source extension API requires Windows x64')
        self._thread, self._closed = get_ident(), False
        self._handles, self._calls = {}, {}
        self._modules, self._targets, self._events = {}, {}, set()
        self._kernel_module, self._process = None, None
        names = ('RegOpenKeyExA', 'RegQueryValueExA', 'RegCloseKey', '_localtime64_s', '_stat64',
                 'LoadLibraryA', 'FreeLibrary', 'GetProcAddress', 'GetCurrentProcess', 'GetModuleHandleA',
                 'OpenEventLogA', 'ReadEventLogA', 'CloseEventLog')
        if api is None:
            registry = ctypes.WinDLL('advapi32', use_last_error=True)
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            crt = ctypes.CDLL('ucrtbase')
            self._api = {name: getattr(crt if name.startswith('_') else registry if name.startswith(('Reg', 'OpenEvent', 'ReadEvent', 'CloseEvent')) else kernel, name) for name in names}
        else:
            self._api = {name: getattr(api, name) for name in names}
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        signatures = {'RegOpenKeyExA': (i, (p, ctypes.c_char_p, u, u, p)),
                      'RegQueryValueExA': (i, (p, ctypes.c_char_p, p, p, p, p)),
                      'RegCloseKey': (i, (p,)), '_localtime64_s': (i, (p, p)), '_stat64': (i, (ctypes.c_char_p, p)),
                      'LoadLibraryA': (p, (ctypes.c_char_p,)), 'FreeLibrary': (i, (p,)),
                      'GetProcAddress': (p, (p, ctypes.c_char_p)), 'GetCurrentProcess': (p, ()),
                      'GetModuleHandleA': (p, (ctypes.c_char_p,)), 'OpenEventLogA': (p, (ctypes.c_char_p, ctypes.c_char_p)),
                      'ReadEventLogA': (i, (p, u, u, p, u, p, p)), 'CloseEventLog': (i, (p,))}
        for name, (result, arguments) in signatures.items():
            self._api[name].restype, self._api[name].argtypes = result, arguments

    _check = WindowsQimeiExtraObservations._check
    _buffer = WindowsQimeiExtraObservations._buffer
    _reply = WindowsQimeiExtraObservations._reply

    def read(self, namespace, name, *args):
        self._check()
        u, i = ctypes.c_uint32, ctypes.c_int32
        if namespace != 'qimei-api' or name not in self._api and name not in ('GetSystemFirmwareTable', 'IsWow64Process'):
            raise QimeiRequestBoundary('unsupported source extension raw API')
        function = self._api.get(name)
        if name == 'RegOpenKeyExA':
            root, path, options, access, target = args
            allowed = root == HKLM and path in {row[0] for row in IDENTITY_VALUES}
            allowed = allowed or (root, path) in ((HKLM, EDGE_MACHINE_KEY), (HKCU, EDGE_USER_KEY))
            allowed = allowed or root == HKLM and path in (HARDWARE_CONFIG_KEY, HARDWARE_CURRENT_KEY)
            if not allowed or options != 0 or access != 0x101 or not isinstance(target, StorageBuffer) or target.read() != bytes(8):
                raise QimeiRequestBoundary('extension registry open leaves fixed readonly domain')
            output = self._buffer(target)
            self._calls[name] = self._calls.get(name, 0) + 1
            status = function(root, path, options, access, output)
            handle = int.from_bytes(bytes(output), 'little')
            if handle:
                self._handles[handle] = root, path
            return self._reply(status, {'handle': output})
        if name == 'RegQueryValueExA':
            handle, value, reserved, kind, target, size = args
            if handle not in self._handles:
                raise QimeiRequestBoundary('extension registry query requires owned handle')
            root, path = self._handles[handle]
            edge = path in (EDGE_MACHINE_KEY, EDGE_USER_KEY)
            allowed = value in EDGE_VALUES if edge else (path, value) in IDENTITY_VALUES
            allowed = allowed or path == HARDWARE_CONFIG_KEY and value == b'LastConfig' or path == HARDWARE_CURRENT_KEY and value in HARDWARE_VALUES
            capacity = 4 if edge and value == b'uid-create-time' else 260
            if (not allowed or reserved != 0 or kind is not None or not isinstance(size, StorageBuffer)
                    or len(size.data) != 4 or target is not None and
                    (not isinstance(target, StorageBuffer) or len(target.data) != capacity
                     or target.read() != bytes(capacity) or int.from_bytes(size.read(), 'little') > capacity)):
                raise QimeiRequestBoundary('extension registry query leaves fixed raw buffer contract')
            output, count = None if target is None else self._buffer(target), self._buffer(size)
            self._calls[name] = self._calls.get(name, 0) + 1
            status = function(handle, value, 0, None, output, count)
            return self._reply(status, {'size': count, **({} if output is None else {'data': output})})
        if name == 'RegCloseKey':
            handle, = args
            if handle not in self._handles:
                raise QimeiRequestBoundary('extension registry close requires owned handle')
            self._calls[name] = self._calls.get(name, 0) + 1
            status = function(handle)
            if status == 0:
                del self._handles[handle]
            return self._reply(status)
        if name in ('LoadLibraryA', 'GetModuleHandleA'):
            if args != ((b'kernel32.dll',) if name == 'LoadLibraryA' else (b'kernel32',)):
                raise QimeiRequestBoundary('extension module access leaves fixed kernel32 source')
            self._calls[name] = self._calls.get(name, 0) + 1
            value = function(*args) or 0
            if name == 'LoadLibraryA' and value:
                self._modules[value] = self._modules.get(value, 0) + 1
            if name == 'GetModuleHandleA':
                self._kernel_module = value
            return self._reply(value, width=64)
        if name == 'FreeLibrary':
            module, = args
            if module not in self._modules:
                raise QimeiRequestBoundary('extension library close requires owned reference')
            self._calls[name] = self._calls.get(name, 0) + 1
            result = function(module)
            if result:
                self._modules[module] -= 1
                if not self._modules[module]:
                    del self._modules[module]
                    self._targets = {target: entry for target, entry in self._targets.items() if entry[0] != module}
            return self._reply(result)
        if name == 'GetProcAddress':
            module, export = args
            if not (module in self._modules and export == b'GetSystemFirmwareTable' or
                    module == self._kernel_module and export == b'IsWow64Process'):
                raise QimeiRequestBoundary('extension export leaves source owned kernel32 domain')
            self._calls[name] = self._calls.get(name, 0) + 1
            target = function(module, export) or 0
            if target:
                self._targets[target] = module, export
            return self._reply(target, width=64)
        if name == 'GetSystemFirmwareTable':
            target, provider, table, data, size = args
            if (self._targets.get(target, (None, None))[1] != b'GetSystemFirmwareTable' or provider != 0x52534D42 or table != 0
                    or type(size) is not int or not 0 <= size <= 1 << 20
                    or data is None and size != 0 or data is not None and
                    (not isinstance(data, StorageBuffer) or len(data.data) != size or any(data.known))):
                raise QimeiRequestBoundary('firmware query leaves source RSMB buffer domain')
            output = None if data is None else self._buffer(data)
            call = ctypes.WINFUNCTYPE(u, u, u, ctypes.c_void_p, u)(target)
            self._calls[name] = self._calls.get(name, 0) + 1
            result = call(provider, table, output, size)
            if data is not None and result > size:
                raise QimeiRequestBoundary('firmware response exceeds source capacity')
            return self._reply(result, {} if output is None else {'data': bytes(output)[:result]})
        if name == 'GetCurrentProcess':
            if args:
                raise QimeiRequestBoundary('current process source has no arguments')
            self._calls[name] = self._calls.get(name, 0) + 1
            self._process = function() or 0
            return self._reply(self._process, width=64)
        if name == 'IsWow64Process':
            target, process, data = args
            if (self._targets.get(target, (None, None))[1] != b'IsWow64Process' or process != self._process
                    or not isinstance(data, StorageBuffer) or data.read() != bytes(4)):
                raise QimeiRequestBoundary('WOW64 query leaves source initial DWORD domain')
            output = self._buffer(data)
            call = ctypes.WINFUNCTYPE(i, ctypes.c_void_p, ctypes.c_void_p)(target)
            self._calls[name] = self._calls.get(name, 0) + 1
            return self._reply(call(process, output), {'value': output})
        if name == 'OpenEventLogA':
            if args != (None, b'System'):
                raise QimeiRequestBoundary('event open leaves local System log')
            self._calls[name] = self._calls.get(name, 0) + 1
            handle = function(*args) or 0
            if handle:
                self._events.add(handle)
            return self._reply(handle, width=64)
        if name == 'ReadEventLogA':
            handle, flags, offset, data, size, read, needed = args
            if (handle not in self._events or flags != 5 or offset != 0 or size != 4096
                    or not isinstance(data, StorageBuffer) or len(data.data) != size
                    or not isinstance(read, StorageBuffer) or read.read() != bytes(4)
                    or not isinstance(needed, StorageBuffer) or needed.read() != bytes(4)):
                raise QimeiRequestBoundary('event read leaves source fixed batch domain')
            output, count, required = self._buffer(data), self._buffer(read), self._buffer(needed)
            self._calls[name] = self._calls.get(name, 0) + 1
            return self._reply(function(handle, flags, offset, output, size, count, required),
                               {'data': output, 'read': count, 'needed': required})
        if name == 'CloseEventLog':
            handle, = args
            if handle not in self._events:
                raise QimeiRequestBoundary('event close requires owned handle')
            self._calls[name] = self._calls.get(name, 0) + 1
            result = function(handle)
            if result:
                self._events.remove(handle)
            return self._reply(result)
        if name == '_stat64':
            path, data = args
            chosen = STAT_ROOTS[:2]
            allowed = STAT_ROOTS + tuple(root + b'\\' + suffix for root in chosen
                                        for suffix in (b'kernel32.dll', b'user32.dll', b'ntdll.dll'))
            if path not in allowed or not isinstance(data, StorageBuffer) or len(data.data) != 56 or any(data.known):
                raise QimeiRequestBoundary('stat query leaves six fixed source path domain')
            output = self._buffer(data)
            self._calls[name] = self._calls.get(name, 0) + 1
            status = function(path, output)
            return self._reply(status, {'data': output} if status == 0 else {})
        target, seconds = args
        if (not isinstance(target, StorageBuffer) or target.read() != b'\xff' * 36
                or type(seconds) is not int or not 0 <= seconds <= 0xFFFFFFFF):
            raise QimeiRequestBoundary('extension localtime leaves source uint32 and initialized tm contract')
        output, value = self._buffer(target), ctypes.c_int64(seconds)
        self._calls[name] = self._calls.get(name, 0) + 1
        status = function(output, ctypes.byref(value))
        return self._reply(status, {'data': output})

    def metadata(self):
        return {'closed': self._closed, 'registry_handles': len(self._handles), 'event_handles': len(self._events),
                'module_references': sum(self._modules.values()),
                'heap_allocations_after': 0, 'API_calls': sum(self._calls.values())}

    def close(self):
        if self._closed:
            return
        self._check()
        for handle in tuple(self._handles):
            self.read('qimei-api', 'RegCloseKey', handle)
        for handle in tuple(self._events):
            self.read('qimei-api', 'CloseEventLog', handle)
        for module, count in tuple(self._modules.items()):
            for unused in range(count):
                self.read('qimei-api', 'FreeLibrary', module)
        if self._handles or self._events or self._modules:
            raise QimeiRequestBoundary('extension registry cleanup retains owned handles')
        self._targets.clear()
        self._closed = True
