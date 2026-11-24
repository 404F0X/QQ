import ctypes
import os

from .primary_qimei_extra_sources import HKCU
from .primary_qimei_observations import CLASSIFIER_RULES
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError
from .primary_qimei_system_sources import HKLM, PROCESSOR_KEY, PROCESSOR_VALUES, WINDOWS_KEY, BIOS_KEY, BIOS_VALUES, KEYBOARD_KEY, COMPATIBILITY_KEY
from .primary_windows_qimei_extras import WindowsQimeiExtraObservations


class WindowsQimeiSystemObservations(WindowsQimeiExtraObservations):
    def __init__(self, api=None):
        super().__init__(api)
        names = {'GetCurrentProcess': 'kernel32', 'GetCurrentProcessId': 'kernel32', 'GetProcAddress': 'kernel32',
                 'GetComputerNameA': 'kernel32', 'GetUserNameA': 'advapi32', 'GetTimeZoneInformation': 'kernel32',
                 'GlobalMemoryStatusEx': 'kernel32', 'GetKeyboardLayoutList': 'user32', 'GetProcessHeap': 'kernel32',
                 'HeapAlloc': 'kernel32', 'HeapFree': 'kernel32', 'IsUserAnAdmin': 'shell32', '_localtime64_s': 'ucrtbase',
                 'GetDriveTypeA': 'kernel32', 'QueryDosDeviceA': 'kernel32', 'GetVersionExA':'kernel32', 'GetNativeSystemInfo':'kernel32', 'GetCursorPos':'user32'}
        if api is None:
            groups = {name: ctypes.WinDLL(name, use_last_error=True) for name in set(names.values())}
            self._api.update({name: getattr(groups[group], name) for name, group in names.items()})
        else:
            self._api.update({name: getattr(api, name) for name in names})
        pointer, dword, integer = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        signatures = {
            'GetCurrentProcess': (pointer, ()), 'GetCurrentProcessId': (dword, ()),
            'GetProcAddress': (pointer, (pointer, ctypes.c_char_p)), 'GetComputerNameA': (integer, (pointer, pointer)),
            'GetUserNameA': (integer, (pointer, pointer)), 'GetTimeZoneInformation': (dword, (pointer,)),
            'GlobalMemoryStatusEx': (integer, (pointer,)), 'GetKeyboardLayoutList': (integer, (integer, pointer)),
            'GetProcessHeap': (pointer, ()), 'HeapAlloc': (pointer, (pointer, dword, ctypes.c_size_t)),
            'HeapFree': (integer, (pointer, dword, pointer)), 'IsUserAnAdmin': (integer, ()),
            '_localtime64_s': (integer, (pointer, pointer)), 'GetDriveTypeA': (dword, (ctypes.c_char_p,)),
            'QueryDosDeviceA': (dword, (ctypes.c_char_p, pointer, dword)),
            'GetVersionExA':(integer,(pointer,)), 'GetNativeSystemInfo':(None,(pointer,)), 'GetCursorPos':(integer,(pointer,))
        }
        for name, (result, arguments) in signatures.items():
            self._api[name].restype, self._api[name].argtypes = result, arguments
        self._heaps = set()
        self._allocations = {}
        self._wow64_procedure = None
        self._kernel_module = None
        self._process = None
        self._platform_pid = os.getpid()
        self._ntdll_module = None
        self._ntdll_procedure = None

    def _allowed_registry(self, root, path):
        return ((root == HKLM and (path in (PROCESSOR_KEY, WINDOWS_KEY, BIOS_KEY) or path in {row[0] for row in CLASSIFIER_RULES} or path.startswith(KEYBOARD_KEY)
                                  or path.startswith(b'BCD00000000\\Objects\\')))
                or (root == HKCU and path == COMPATIBILITY_KEY))

    def _allowed_value(self, path, value):
        if (path, value) in CLASSIFIER_RULES:
            return True
        if path == PROCESSOR_KEY:
            return value in PROCESSOR_VALUES
        if path == BIOS_KEY:
            return value in BIOS_VALUES
        if path == WINDOWS_KEY:
            return value in (b'ProductName', b'CurrentMajorVersionNumber', b'CurrentMinorVersionNumber', b'CurrentBuild', b'InstallDate')
        if path.startswith(KEYBOARD_KEY):
            return value == b'Layout Text'
        if path.startswith(b'BCD00000000\\Objects\\'):
            return value == b'Element'
        return path == COMPATIBILITY_KEY

    def read(self, namespace, name, *args):
        self._check()
        if namespace=='qimei-api' and (name in ('GetVersionExA','GetNativeSystemInfo','GetCursorPos','RtlGetNtVersionNumbers') or
                name=='GetModuleHandleA' and args==(b'ntdll.dll',) or
                name=='GetProcAddress' and len(args)==2 and args[1]==b'RtlGetNtVersionNumbers'):
            return self._platform_read(name,args)

        if namespace != 'qimei-api':
            raise QimeiRequestBoundary('unsupported system observation namespace')
        if name == 'RegOpenKeyExA':
            root, path, reserved, access, target = args
            if not self._allowed_registry(root, path) or reserved != 0 or access != 0x101 or len(target.data) != 8:
                raise QimeiRequestBoundary('registry open leaves source system read-only paths')
            self._calls[name] = self._calls.get(name, 0) + 1
            data = self._buffer(target)
            status = self._api[name](root, path, reserved, access, data)
            handle = int.from_bytes(bytes(data), 'little')
            if handle:
                self._handles[handle] = path
            return self._reply(status, {'handle': data})
        if name == 'RegQueryValueExA':
            handle, key, reserved, type_pointer, target, size = args
            path = self._known_handle(handle)
            if reserved != 0 or type_pointer is not None or not self._allowed_value(path, key) or len(size.data) != 4:
                raise QimeiRequestBoundary('registry query leaves source system contract')
            size_buffer = self._buffer(size)
            data = None if target is None else self._buffer(target)
            if target is not None and int.from_bytes(size.read(), 'little') > len(target.data):
                raise QimeiRequestBoundary('registry size exceeds system buffer backing')
            self._calls[name] = self._calls.get(name, 0) + 1
            status = self._api[name](handle, key, 0, None, data, size_buffer)
            return self._reply(status, {'size': size_buffer, **({} if data is None else {'data': data})})
        if name == 'GetModuleHandleA' and args[0] == b'kernel32':
            self._calls[name] = self._calls.get(name, 0) + 1
            self._kernel_module = self._api[name](*args) or 0
            return self._reply(self._kernel_module, width=64)
        if name not in ('GetCurrentProcess', 'GetCurrentProcessId', 'GetProcAddress', 'IsWow64Process', 'GetComputerNameA', 'GetUserNameA',
                        'GetTimeZoneInformation', 'GlobalMemoryStatusEx', 'GetKeyboardLayoutList', 'GetProcessHeap', 'HeapAlloc', 'HeapFree', 'IsUserAnAdmin', '_localtime64_s', 'GetDriveTypeA', 'QueryDosDeviceA'):
            return super().read(namespace, name, *args)
        self._calls[name] = self._calls.get(name, 0) + 1
        if name in ('GetDriveTypeA', 'QueryDosDeviceA'):
            path = args[0]
            if not isinstance(path, bytes) or len(path) != 2 or not ord('C') <= path[0] <= ord('Z') or path[1:] != b':':
                raise QimeiRequestBoundary('drive classifier leaves source C-Z inputs')
            if name == 'GetDriveTypeA':
                return self._reply(self._api[name](path))
            path, target, count = args
            if count != 260 or len(target.data) != 260:
                raise QimeiRequestBoundary('drive mapping exceeds source buffer')
            data = self._buffer(target)
            return self._reply(self._api[name](path, data, count), {'data': data})
        if name in ('GetCurrentProcess', 'GetCurrentProcessId', 'IsUserAnAdmin', 'GetProcessHeap'):
            value = self._api[name]()
            if name == 'GetProcessHeap' and value:
                self._heaps.add(value)
            if name == 'GetCurrentProcess':
                self._process = (value or 0) & 0xFFFFFFFFFFFFFFFF
            return self._reply(value, width=64 if name in ('GetCurrentProcess', 'GetProcessHeap') else 32)
        if name == 'GetProcAddress':
            module, symbol = args
            if symbol != b'IsWow64Process' or self._kernel_module is None or module != self._kernel_module:
                raise QimeiRequestBoundary('system procedure lookup leaves fixed source')
            value = self._api[name](module, symbol)
            self._wow64_procedure = value
            return self._reply(value, width=64)
        if name == 'IsWow64Process':
            procedure, process, target = args
            if not procedure or procedure != self._wow64_procedure or process != self._process or len(target.data) != 4:
                raise QimeiRequestBoundary('system procedure call leaves owned lookup')
            data = self._buffer(target)
            function = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p)(procedure)
            return self._reply(function(process, data), {'value': data})
        if name in ('GetComputerNameA', 'GetUserNameA'):
            target, size = args
            data, size_buffer = self._buffer(target), self._buffer(size)
            if len(target.data) != 260 or len(size.data) != 4 or int.from_bytes(size.read(), 'little') > 260:
                raise QimeiRequestBoundary('machine name call exceeds source buffers')
            status = self._api[name](data, size_buffer)
            return self._reply(status, {'data': data, 'size': size_buffer})
        if name in ('GetTimeZoneInformation', 'GlobalMemoryStatusEx'):
            target, = args
            if len(target.data) != (172 if name == 'GetTimeZoneInformation' else 64):
                raise QimeiRequestBoundary('system structure has wrong size')
            data = self._buffer(target)
            return self._reply(self._api[name](data), {'data': data})
        if name == 'HeapAlloc':
            heap, flags, length = args
            if heap not in self._heaps or flags != 8 or not 0 < length <= 1 << 20:
                raise QimeiRequestBoundary('keyboard allocation leaves source bounded heap')
            pointer = self._api[name](heap, flags, length)
            if pointer:
                self._allocations[pointer] = (heap, length)
            return self._reply(pointer, width=64)
        if name == 'HeapFree':
            heap, flags, pointer = args
            if pointer not in self._allocations or self._allocations[pointer][0] != heap or flags != 0:
                raise QimeiRequestBoundary('keyboard free leaves owned heap')
            status = self._api[name](heap, flags, pointer)
            if status:
                del self._allocations[pointer]
            return self._reply(status)
        if name == 'GetKeyboardLayoutList':
            if args == (0, None):
                return self._reply(self._api[name](0, None))
            count, pointer, target = args
            if pointer not in self._allocations or count * 8 != self._allocations[pointer][1] or len(target.data) != count * 8:
                raise QimeiRequestBoundary('keyboard enumeration exceeds owned backing')
            before = target.read()
            ctypes.memmove(pointer, before, len(before))
            status = self._api[name](count, pointer)
            return self._reply(status, {'data': ctypes.string_at(pointer, len(before))})
        if name == '_localtime64_s':
            target, seconds = args
            if len(target.data) != 36 or not 0 <= seconds <= 0xFFFFFFFF:
                raise QimeiRequestBoundary('install date conversion leaves source domain')
            data = self._buffer(target)
            time = ctypes.c_int64(seconds)
            return self._reply(self._api[name](data, ctypes.byref(time)), {'data': data})
        raise QimeiRequestError('unsupported source system API')

    def metadata(self):
        return {**super().metadata(), 'heap_allocations_after': len(self._allocations)}

    def close(self):
        if not self._closed:
            self._check()
            for pointer, (heap, length) in list(self._allocations.items()):
                if self._api['HeapFree'](heap, 0, pointer):
                    del self._allocations[pointer]
            if self._allocations:
                raise QimeiRequestBoundary('system backend could not close owned heap allocations')
        super().close()

    def _platform_read(self,name,args):
        self._check()
        if os.getpid()!=self._platform_pid:raise QimeiRequestBoundary('platform backend belongs to its creator process')
        if name=='GetModuleHandleA':
            self._calls[name]=self._calls.get(name,0)+1
            self._ntdll_module=self._api[name](b'ntdll.dll') or 0
            return self._reply(self._ntdll_module,width=64)
        if name=='GetProcAddress':
            module,symbol=args
            if symbol!=b'RtlGetNtVersionNumbers' or self._ntdll_module is None or module!=self._ntdll_module:raise QimeiRequestBoundary('version module lookup is not owned')
            self._calls[name]=self._calls.get(name,0)+1
            self._ntdll_procedure=self._api[name](module,symbol) or 0
            return self._reply(self._ntdll_procedure,width=64)
        if name=='RtlGetNtVersionNumbers':
            proc,*targets=args
            if not proc or proc!=self._ntdll_procedure or len(targets)!=3 or any(len(t.data)!=4 for t in targets):raise QimeiRequestBoundary('version procedure/buffers are not owned')
            for t in targets:t.read()
            data=[self._buffer(t) for t in targets]
            ctypes.WINFUNCTYPE(None,*([ctypes.POINTER(ctypes.c_uint32)]*3))(proc)(*(ctypes.cast(d,ctypes.POINTER(ctypes.c_uint32)) for d in data))
            self._calls[name]=self._calls.get(name,0)+1
            return self._reply(0,dict(zip(('major','minor','build'),data)))
        target,=args;size={'GetVersionExA':148,'GetNativeSystemInfo':48,'GetCursorPos':8}[name]
        if len(target.data)!=size:raise QimeiRequestBoundary('platform structure has wrong backing size')
        target.read()
        if name=='GetVersionExA' and int.from_bytes(target.read(0,4),'little')!=148:raise QimeiRequestBoundary('version structure size missing')
        data=self._buffer(target);result=self._api[name](data)
        self._calls[name]=self._calls.get(name,0)+1
        return self._reply(0 if name=='GetNativeSystemInfo' else result,{'data':data})
