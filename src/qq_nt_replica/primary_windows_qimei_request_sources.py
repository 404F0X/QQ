import ctypes

from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError
from .primary_qimei_request_sources import SETUP_LIBRARY, SETUP_EXPORTS, DISK_CLASS, COMPUTER_CLASS, DEVICE_PROPERTY
from .primary_windows_qimei_system import WindowsQimeiSystemObservations


class WindowsQimeiRequestObservations(WindowsQimeiSystemObservations):
    def __init__(self, api=None, *, cpu_source=None):
        super().__init__(api)
        names = {'LoadLibraryA': 'kernel32', 'FreeLibrary': 'kernel32', 'GetLogicalDrives': 'kernel32', 'GetDiskFreeSpaceA': 'kernel32',
                 'SetupDiGetClassDevsW': 'setupapi', 'SetupDiEnumDeviceInfo': 'setupapi', 'SetupDiDestroyDeviceInfoList': 'setupapi',
                 'SetupDiGetDeviceRegistryPropertyW': 'setupapi', 'SetupDiGetDevicePropertyW': 'setupapi',
                 'CoInitialize': 'ole32', 'CoCreateGuid': 'ole32', 'CoUninitialize': 'ole32'}
        if api is None:
            groups = {name: ctypes.WinDLL(name, use_last_error=True) for name in set(names.values()) if name != 'setupapi'}
            self._api.update({name: getattr(groups[group], name) for name, group in names.items() if group != 'setupapi'})
        else:
            self._api.update({name: getattr(api, name) for name in names})
        pointer, dword, integer = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        signatures = {
            'LoadLibraryA': (pointer, (ctypes.c_char_p,)), 'FreeLibrary': (integer, (pointer,)),
            'GetLogicalDrives': (dword, ()), 'GetDiskFreeSpaceA': (integer, (ctypes.c_char_p, pointer, pointer, pointer, pointer)),
            'SetupDiGetClassDevsW': (pointer, (pointer, pointer, pointer, dword)),
            'SetupDiEnumDeviceInfo': (integer, (pointer, dword, pointer)), 'SetupDiDestroyDeviceInfoList': (integer, (pointer,)),
            'SetupDiGetDeviceRegistryPropertyW': (integer, (pointer, pointer, dword, pointer, pointer, dword, pointer)),
            'SetupDiGetDevicePropertyW': (integer, (pointer, pointer, pointer, pointer, pointer, dword, pointer, dword)),
            'CoInitialize': (integer, (pointer,)), 'CoCreateGuid': (integer, (pointer,)), 'CoUninitialize': (None, ())
        }
        for name, (result, arguments) in signatures.items():
            if name in self._api:
                self._api[name].restype, self._api[name].argtypes = result, arguments
        self._setup_signatures = {name: signatures[name] for name, group in names.items() if group == 'setupapi'}
        self._injected_api = api is not None
        self._setup_modules, self._setup_targets, self._device_sets = {}, {}, set()
        self._invalid_device_set_seen = False
        self._com_balance = 0
        self._cpu_source, self._owns_cpu = cpu_source, False

    def _target(self, pointer, name):
        if pointer not in self._setup_targets or self._setup_targets[pointer][0] != name:
            raise QimeiRequestBoundary('SetupAPI call leaves owned fixed export')

    def _device_set(self, value):
        if value not in self._device_sets and not (value == 0xFFFFFFFFFFFFFFFF and self._invalid_device_set_seen):
            raise QimeiRequestBoundary('SetupAPI device set was not returned by this backend')

    def read(self, namespace, name, *args):
        self._check()
        if namespace != 'qimei-api':
            return super().read(namespace, name, *args)
        if name == 'GetProcAddress' and args[0] in self._setup_modules:
            module, symbol = args
            if symbol not in SETUP_EXPORTS + (b'SetupDiGetDeviceRegistryPropertyW', b'SetupDiGetDevicePropertyW'):
                raise QimeiRequestBoundary('SetupAPI export lookup leaves fixed source')
            self._calls[name] = self._calls.get(name, 0) + 1
            pointer = self._api[name](module, symbol) or 0
            if pointer:
                self._setup_targets[pointer] = (symbol.decode('ascii'), module)
                if not self._injected_api:
                    result, arguments = self._setup_signatures[symbol.decode('ascii')]
                    self._api[symbol.decode('ascii')] = ctypes.WINFUNCTYPE(result, *arguments)(pointer)
            return self._reply(pointer, width=64)
        if name == 'GetDriveTypeA' and len(args) == 1 and isinstance(args[0], bytes) and len(args[0]) == 3:
            path, = args
            if not b'C' <= path[:1] <= b'Z' or path[1:] != b':\\':
                raise QimeiRequestBoundary('disk drive query leaves source C-Z roots')
            self._calls[name] = self._calls.get(name, 0) + 1
            return self._reply(self._api[name](path))
        if name not in ('CPUID', 'LoadLibraryA', 'FreeLibrary', 'GetLogicalDrives', 'GetDiskFreeSpaceA', 'CoInitialize', 'CoCreateGuid', 'CoUninitialize',
                        'SetupDiGetClassDevsW', 'SetupDiEnumDeviceInfo', 'SetupDiDestroyDeviceInfoList', 'SetupDiGetDeviceRegistryPropertyW', 'SetupDiGetDevicePropertyW'):
            return super().read(namespace, name, *args)
        self._calls[name] = self._calls.get(name, 0) + 1
        function = self._api.get(name)
        if name == 'CPUID':
            leaf, subleaf, output = args
            if leaf not in (1, 0x80000002, 0x80000003, 0x80000004) or subleaf != 0 or len(output.data) != 16:
                raise QimeiRequestBoundary('request CPUID leaves fixed source leaves')
            if self._cpu_source is None:
                from .primary_windows import WindowsDeviceSource
                self._cpu_source, self._owns_cpu = WindowsDeviceSource(), True
            words = self._cpu_source.cpuid(leaf, subleaf)
            if type(words) is not tuple or len(words) != 4 or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in words):
                raise QimeiRequestError('CPUID must return four raw DWORD registers')
            return self._reply(0, {'data': b''.join(value.to_bytes(4, 'little') for value in words)})
        if name == 'LoadLibraryA':
            if args != (SETUP_LIBRARY,):
                raise QimeiRequestBoundary('request library load leaves SETUPAPI.dll')
            module = function(*args) or 0
            if module:
                self._setup_modules[module] = self._setup_modules.get(module, 0) + 1
            return self._reply(module, width=64)
        if name == 'FreeLibrary':
            module, = args
            if module not in self._setup_modules:
                raise QimeiRequestBoundary('request library reference is not owned')
            status = function(module)
            if status:
                self._setup_modules[module] -= 1
                if self._setup_modules[module] == 0:
                    del self._setup_modules[module]
                    self._setup_targets = {pointer: row for pointer, row in self._setup_targets.items() if row[1] != module}
            return self._reply(status)
        if name == 'GetLogicalDrives':
            return self._reply(function())
        if name == 'GetDiskFreeSpaceA':
            path, *targets = args
            if len(targets) != 4 or len(path) != 3 or not b'C' <= path[:1] <= b'Z' or path[1:] != b':\\' or any(len(value.data) != 4 for value in targets):
                raise QimeiRequestBoundary('disk space query leaves source root/buffers')
            data = [self._buffer(value) for value in targets]
            status = function(path, *data)
            return self._reply(status, dict(zip(('sectors', 'size', 'free', 'clusters'), data)))
        if name == 'CoInitialize':
            if args != (None,):
                raise QimeiRequestBoundary('source CoInitialize argument must be NULL')
            status = function(None)
            if not status & 0x80000000:
                self._com_balance += 1
            return self._reply(status)
        if name == 'CoUninitialize':
            if args or self._com_balance <= 0:
                raise QimeiRequestBoundary('source COM uninitialize has no owned successful initialize')
            function()
            self._com_balance -= 1
            return self._reply(0)
        if name == 'CoCreateGuid':
            target, = args
            if len(target.data) != 16:
                raise QimeiRequestBoundary('source GUID buffer has wrong size')
            data = self._buffer(target)
            return self._reply(function(data), {'data': data})
        if name == 'SetupDiGetClassDevsW':
            procedure, guid, enumerator, window, flags = args
            self._target(procedure, name)
            if guid not in (DISK_CLASS, COMPUTER_CLASS) or enumerator is not None or window is not None or flags != 10:
                raise QimeiRequestBoundary('device set query leaves fixed source')
            data = ctypes.create_string_buffer(guid, 16)
            device_set = (function(data, None, None, flags) or 0) & 0xFFFFFFFFFFFFFFFF
            if device_set == 0xFFFFFFFFFFFFFFFF:
                self._invalid_device_set_seen = True
            elif device_set:
                self._device_sets.add(device_set)
            return self._reply(device_set, width=64)
        procedure, device_set, *values = args
        self._target(procedure, name)
        self._device_set(device_set)
        if name == 'SetupDiDestroyDeviceInfoList':
            status = function(device_set)
            if status:
                self._device_sets.discard(device_set)
            return self._reply(status)
        if name == 'SetupDiEnumDeviceInfo':
            index, target = values
            if not 0 <= index <= 9 or len(target.data) != 32 or target.read(0, 4) != (32).to_bytes(4, 'little'):
                raise QimeiRequestBoundary('device enumeration leaves source ten-row/structure contract')
            data = self._buffer(target)
            return self._reply(function(device_set, index, data), {'info': data})
        info, *values = values
        if len(info.data) != 32:
            raise QimeiRequestBoundary('device callback structure has wrong size')
        info_data = self._buffer(info)
        if name == 'SetupDiGetDeviceRegistryPropertyW':
            prop, kind, target, capacity, required = values
            if prop != 12 or kind is not None or capacity != 8192 or len(target.data) != capacity or required is not None:
                raise QimeiRequestBoundary('disk callback leaves source friendly-name property')
            data = self._buffer(target)
            status = function(device_set, info_data, prop, None, data, capacity, None)
            return self._reply(status, {'info': info_data, 'data': data})
        if name == 'SetupDiGetDevicePropertyW':
            key, kind, target, capacity, required, flags = values
            if key != DEVICE_PROPERTY or capacity != 4096 or len(target.data) != capacity or len(kind.data) != 4 or len(required.data) != 4 or flags != 0:
                raise QimeiRequestBoundary('computer callback leaves fixed source property/buffers')
            key_data = ctypes.create_string_buffer(key, 20)
            kind_data, data, required_data = self._buffer(kind), self._buffer(target), self._buffer(required)
            status = function(device_set, info_data, key_data, kind_data, data, capacity, required_data, 0)
            return self._reply(status, {'info': info_data, 'type': kind_data, 'data': data, 'required': required_data})
        raise QimeiRequestBoundary('unimplemented request raw API')

    def metadata(self):
        return {**super().metadata(), 'setup_library_references': sum(self._setup_modules.values()), 'device_sets': len(self._device_sets),
                'COM_balance': self._com_balance, 'owned_CPU_helper': int(self._owns_cpu and self._cpu_source is not None)}

    def close(self):
        if not self._closed:
            self._check()
            if self._device_sets:
                self._calls['cleanup.LoadLibraryA'] = self._calls.get('cleanup.LoadLibraryA', 0) + 1
                module = self._api['LoadLibraryA'](SETUP_LIBRARY) or 0
                if not module:
                    raise QimeiRequestBoundary('request backend cannot reload owned SetupAPI cleanup library')
                self._setup_modules[module] = self._setup_modules.get(module, 0) + 1
                self._calls['cleanup.GetProcAddress'] = self._calls.get('cleanup.GetProcAddress', 0) + 1
                pointer = self._api['GetProcAddress'](module, b'SetupDiDestroyDeviceInfoList') or 0
                if not pointer:
                    raise QimeiRequestBoundary('request backend cannot resolve owned SetupAPI cleanup export')
                if not self._injected_api:
                    result, arguments = self._setup_signatures['SetupDiDestroyDeviceInfoList']
                    self._api['SetupDiDestroyDeviceInfoList'] = ctypes.WINFUNCTYPE(result, *arguments)(pointer)
            for device_set in tuple(self._device_sets):
                if self._api['SetupDiDestroyDeviceInfoList'](device_set):
                    self._device_sets.remove(device_set)
            for module, count in list(self._setup_modules.items()):
                for index in range(count):
                    if self._api['FreeLibrary'](module):
                        self._setup_modules[module] -= 1
                if self._setup_modules[module] == 0:
                    del self._setup_modules[module]
            while self._com_balance:
                self._api['CoUninitialize']()
                self._com_balance -= 1
            if self._owns_cpu and self._cpu_source is not None:
                self._cpu_source.close()
                self._cpu_source = None
            if self._device_sets or self._setup_modules:
                raise QimeiRequestBoundary('request backend could not close owned SetupAPI resources')
        super().close()
