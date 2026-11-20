import ctypes

from .primary_qimei_request import QimeiRequestBoundary
from .primary_qimei_transport_material import MODEL_KEYS
from .primary_qimei_system_sources import HKLM
from .primary_windows_qimei_system import WindowsQimeiSystemObservations


class WindowsQimeiTransportObservations(WindowsQimeiSystemObservations):
    def __init__(self, api=None):
        super().__init__(api)
        names = {'SHGetFolderPathA': 'shell32', 'GetPrivateProfileStringA': 'kernel32',
                 'GetSystemTimeAsFileTime': 'kernel32', 'CryptAcquireContextW': 'advapi32',
                 'CryptGenRandom': 'advapi32', 'CryptReleaseContext': 'advapi32', 'calloc': 'ucrtbase', 'free': 'ucrtbase'}
        groups = {} if api is not None else {name: ctypes.WinDLL(name, use_last_error=True) for name in set(names.values())}
        self._api.update({name: getattr(api if api is not None else groups[group], name) for name, group in names.items()})
        pointer, dword, integer = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        signatures = {
            'SHGetFolderPathA': (integer, (pointer, integer, pointer, dword, pointer)),
            'GetPrivateProfileStringA': (dword, (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, pointer, dword, ctypes.c_char_p)),
            'GetSystemTimeAsFileTime': (None, (pointer,)),
            'CryptAcquireContextW': (integer, (pointer, ctypes.c_wchar_p, ctypes.c_wchar_p, dword, dword)),
            'CryptGenRandom': (integer, (pointer, dword, pointer)),
            'CryptReleaseContext': (integer, (pointer, dword)),
            'calloc': (pointer, (ctypes.c_size_t, ctypes.c_size_t)), 'free': (None, (pointer,))
        }
        for name, (result, arguments) in signatures.items():
            self._api[name].restype, self._api[name].argtypes = result, arguments
        self._random_allocations = set()
        self._random_providers = set()
        self._profile_path = None

    def _allowed_registry(self, root, path):
        return root == HKLM and path in MODEL_KEYS or super()._allowed_registry(root, path)

    def _allowed_value(self, path, value):
        return path in MODEL_KEYS and value in (b'SystemFamily', b'SystemVersion') or super()._allowed_value(path, value)

    def read(self, namespace, name, *args):
        self._check()
        if namespace != 'qimei-api':
            raise QimeiRequestBoundary('unsupported transport observation namespace')
        if name not in ('SHGetFolderPathA', 'GetPrivateProfileStringA', 'GetSystemTimeAsFileTime',
                        'CryptAcquireContextW', 'CryptGenRandom', 'CryptReleaseContext', 'calloc', 'free'):
            return super().read(namespace, name, *args)
        self._calls[name] = self._calls.get(name, 0) + 1
        if name == 'calloc':
            count, size = args
            if count != 1 or type(size) is not int or not 32 <= size <= (1 << 20) + 32 or size % 32:
                raise QimeiRequestBoundary('random calloc leaves source allocation domain')
            pointer = self._api[name](count, size) or 0
            if pointer:
                self._random_allocations.add(pointer)
            return self._reply(pointer, width=64)
        if name == 'free':
            pointer, = args
            if pointer not in self._random_allocations:
                raise QimeiRequestBoundary('random free requires owned allocation')
            self._api[name](pointer)
            self._random_allocations.remove(pointer)
            return self._reply(0)
        if name == 'CryptAcquireContextW':
            target, container, provider, kind, flags = args
            if container is not None or provider is not None or kind != 1 or flags != 0xF0000000 or len(target.data) != 8:
                raise QimeiRequestBoundary('random acquisition leaves source parameters')
            data = self._buffer(target)
            status = self._api[name](data, None, None, kind, flags)
            if status:
                self._random_providers.add(int.from_bytes(bytes(data), 'little'))
            return self._reply(status, {'handle': data})
        if name == 'CryptGenRandom':
            provider, size, target = args
            if provider not in self._random_providers or size != 32 or len(target.data) != 32:
                raise QimeiRequestBoundary('random generation requires owned provider and 32-byte backing')
            data = self._buffer(target)
            status = self._api[name](provider, size, data)
            return self._reply(status, {'data': data})
        if name == 'CryptReleaseContext':
            provider, flags = args
            if provider not in self._random_providers or flags != 0:
                raise QimeiRequestBoundary('random release requires owned provider')
            status = self._api[name](provider, flags)
            self._random_providers.remove(provider)
            return self._reply(status)
        if name == 'GetSystemTimeAsFileTime':
            target, = args
            if len(target.data) != 8:
                raise QimeiRequestBoundary('FILETIME requires eight-byte backing')
            data = self._buffer(target)
            self._api[name](data)
            return self._reply(0, {'data': data})
        if name == 'SHGetFolderPathA':
            window, folder, token, flags, target = args
            if (window, folder, token, flags) != (0, 0x801A, 0, 0) or len(target.data) != 261:
                raise QimeiRequestBoundary('config1 folder query leaves source parameters')
            data = self._buffer(target)
            status = self._api[name](0, folder, 0, 0, data)
            raw = bytes(data)
            self._profile_path = None
            if (status & 0xFFFFFFFF) not in (1,) and not status & 0x80000000 and b'\0' in raw:
                self._profile_path = raw.split(b'\0', 1)[0] + b'\\Tencent\\beacon\\GlobalMgr.db'
            return self._reply(status, {'data': data})
        section, key, default, target, size, path = args
        if (section, key, default, size) != (b'Profile', b'config1', None, 33) or len(target.data) != 33 or self._profile_path is None or path != self._profile_path:
            raise QimeiRequestBoundary('config1 INI query leaves source read-only path')
        data = self._buffer(target)
        status = self._api[name](section, key, default, data, size, path)
        return self._reply(status, {'data': data})

    def close(self):
        if self._closed:
            return
        self._check()
        for provider in tuple(self._random_providers):
            self._api['CryptReleaseContext'](provider, 0)
            self._random_providers.remove(provider)
        for pointer in tuple(self._random_allocations):
            self._api['free'](pointer)
            self._random_allocations.remove(pointer)
        super().close()
