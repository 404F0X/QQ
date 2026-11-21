import ctypes
import _ctypes
import os
import threading
import itertools

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_device_wmi import _image


_CLSID = bytes.fromhex('11f890453a1dd011891f00aa004b2e24')
_IID = bytes.fromhex('87a612dc7f73cf11884d00aa004b2e24')
_TOKENS = itertools.count(1)
_UNBOUND = object()
_NAMESPACE = 'ROOT\\CIMV2'.encode('utf-16le') + bytes(2)
_SLOTS = {'locator': {'IUnknown.Release': 16, 'IWbemLocator.ConnectServer': 24},
          'services': {'IUnknown.Release': 16, 'IWbemServices.ExecQuery': 160},
          'enumerator': {'IUnknown.Release': 16, 'IEnumWbemClassObject.Next': 32},
          'object': {'IUnknown.Release': 16, 'IWbemClassObject.Get': 32}}


class _NativeWMI:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise PrimarySemanticUnavailable('Windows WMI requires native Win64')
        try:
            self._setup()
        except BaseException:
            self.close()
            raise

    def _setup(self):
        self.ole = ctypes.WinDLL('ole32', use_last_error=True)
        self.aut = ctypes.WinDLL('oleaut32', use_last_error=True)
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self._bind(self.ole, 'CoInitializeEx', [ctypes.c_void_p, ctypes.c_uint32], ctypes.c_int32)
        self._bind(self.ole, 'CoUninitialize', [], None)
        self._bind(self.ole, 'CoCreateInstance', [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int32)
        self._bind(self.ole, 'CoSetProxyBlanket', [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32], ctypes.c_int32)
        self._bind(self.aut, 'SysAllocString', [ctypes.c_void_p], ctypes.c_void_p)
        self._bind(self.aut, 'SysFreeString', [ctypes.c_void_p], None)
        self._bind(self.aut, 'SysStringLen', [ctypes.c_void_p], ctypes.c_uint32)
        self._bind(self.aut, 'VariantClear', [ctypes.c_void_p], ctypes.c_int32)
        self._bind(self.kernel, 'VirtualQuery', [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t], ctypes.c_size_t)
        self._bind(self.kernel, 'MultiByteToWideChar', [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_int32], ctypes.c_int32)
        self._bind(self.kernel, 'WideCharToMultiByte', [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int32)

    def _bind(self, dll, name, arguments, result):
        function = getattr(dll, name)
        function.argtypes, function.restype = arguments, result

    def invoke(self, pointer, slot, argument_types, *arguments):
        table = ctypes.c_void_p.from_address(pointer).value
        target = ctypes.c_void_p.from_address(table + slot).value
        function = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, *argument_types)(target)
        return function(pointer, *arguments) & 0xFFFFFFFF

    def initialize(self):
        return self.ole.CoInitializeEx(None, 0) & 0xFFFFFFFF

    def uninitialize(self):
        self.ole.CoUninitialize()

    def create(self):
        output = ctypes.c_void_p()
        clsid, iid = ctypes.create_string_buffer(_CLSID), ctypes.create_string_buffer(_IID)
        result = self.ole.CoCreateInstance(clsid, None, 1, iid, ctypes.byref(output))
        return result & 0xFFFFFFFF, output.value or 0

    def allocate(self, raw):
        buffer = ctypes.create_string_buffer(raw)
        return self.aut.SysAllocString(buffer) or 0

    def bstr(self, pointer):
        length = self.aut.SysStringLen(pointer)
        if length > 2047:
            raise PrimarySemanticUnavailable('native WMI BSTR exceeds source observation bound')
        return ctypes.string_at(pointer, length * 2) + bytes(2)

    def free(self, pointer):
        self.aut.SysFreeString(pointer)

    def connect(self, receiver, namespace):
        output = ctypes.c_void_p()
        result = self.invoke(receiver, 24, [ctypes.c_void_p] * 4 + [ctypes.c_int32] + [ctypes.c_void_p] * 2 + [ctypes.POINTER(ctypes.c_void_p)], namespace, None, None, None, 0, None, None, ctypes.byref(output))
        return result, output.value or 0

    def blanket(self, pointer):
        return self.ole.CoSetProxyBlanket(pointer, 10, 0, None, 3, 3, None, 0) & 0xFFFFFFFF

    def query(self, receiver, language, statement):
        output = ctypes.c_void_p()
        result = self.invoke(receiver, 160, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)], language, statement, 0x30, None, ctypes.byref(output))
        return result, output.value or 0

    def next(self, receiver):
        output, count = ctypes.c_void_p(), ctypes.c_uint32()
        result = self.invoke(receiver, 32, [ctypes.c_int32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)], -1, 1, ctypes.byref(output), ctypes.byref(count))
        return result, output.value or 0, count.value

    def get(self, receiver, name):
        variant, wide = ctypes.create_string_buffer(24), ctypes.create_string_buffer(name)
        result = self.invoke(receiver, 32, [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], wide, 0, variant, None, None)
        return result, bytes(variant)

    def clear(self, raw):
        variant = ctypes.create_string_buffer(raw, 24)
        result = self.aut.VariantClear(variant) & 0xFFFFFFFF
        return result, bytes(variant)

    def release(self, receiver):
        return self.invoke(receiver, 16, [])

    def virtual_query(self, pointer):
        buffer = ctypes.create_string_buffer(48)
        result = self.kernel.VirtualQuery(pointer, buffer, 48)
        return result, bytes(buffer) if result else b''

    def convert(self, name, arguments):
        page, flags, raw, count, output, capacity, *tail = arguments
        source = ctypes.create_string_buffer(raw)
        buffer = ctypes.create_string_buffer(capacity * (2 if name == 'MultiByteToWideChar' else 1)) if output else None
        function = getattr(self.kernel, name)
        args = [page, flags, source, count, buffer, capacity]
        if tail:
            args.extend([None, None])
        result = function(*args)
        size = result * (2 if name == 'MultiByteToWideChar' else 1)
        return result, bytes(buffer)[:size] if buffer is not None and result else b''

    def close(self):
        for name in ('kernel', 'aut', 'ole'):
            module = getattr(self, name, None)
            if module is not None:
                _ctypes.FreeLibrary(module._handle)
                setattr(self, name, None)


class WindowsWMIObservations:
    def __init__(self, fallback=None, *, backend=None):
        self.fallback, self.backend = fallback, backend
        self.pid, self.tid = os.getpid(), threading.get_native_id()
        self.closed = False
        self._runtime = _UNBOUND
        self.references = {}
        self.strings = {}
        self.variants = {}
        self.successful_initializations = 0
        self.events = []
        self.queries = {bytes.fromhex(value['query_hex']): tuple(bytes.fromhex(p) + bytes(2) for p in value['properties_hex']) for value in _image()['collectors'].values()}
        self.allowed_strings = {_NAMESPACE, 'WQL'.encode('utf-16le') + bytes(2), *self.queries}
        self.convertible = {b'WQL\0'}
        for properties in self.queries.values():
            self.convertible.update(properties)
            self.convertible.update(p.decode('utf-16le').encode('ascii') for p in properties)

    def _check(self):
        if os.getpid() != self.pid or threading.get_native_id() != self.tid or self.closed:
            raise InputError('Windows WMI observations require their open creator native thread')

    def _native(self):
        if self.backend is None:
            self.backend = _NativeWMI()
        return self.backend

    def bind(self, runtime):
        self._check()
        if self._runtime is not _UNBOUND and self._runtime is not runtime:
            raise InputError('Windows WMI observations require their unique bound runtime domain')
        self._runtime = runtime

    def _token(self):
        return 0x6D0000000000 + next(_TOKENS) * 0x10000

    def _foreign(self, pointer, kind, properties=()):
        if not pointer:
            return 0, ()
        token, table = self._token(), self._token()
        raw = bytearray(max(_SLOTS[kind].values()) + 8)
        targets = {}
        for name, slot in _SLOTS[kind].items():
            target = self._token()
            raw[slot:slot + 8] = target.to_bytes(8, 'little')
            targets[name] = target
        self.references[token] = (pointer, kind, targets, properties)
        return token, ((token, table.to_bytes(8, 'little')), (table, bytes(raw)))

    def _receiver(self, arguments, name, kind=None):
        if len(arguments) < 2:
            raise InputError('WMI COM call requires its virtual target and receiver')
        target, token, *rest = arguments
        record = self.references.get(token)
        if record is None or record[2].get(name) != target or kind is not None and record[1] != kind:
            raise InputError('WMI COM receiver or virtual target is outside its owned interface domain')
        return token, record, tuple(rest)

    def take(self, runtime, name, arguments):
        self._check()
        self.bind(runtime)
        known = {'CoInitializeEx', 'CoUninitialize', 'CoCreateInstance', 'SysAllocString', 'SysFreeString', 'CoSetProxyBlanket', 'VariantClear', 'VirtualQuery', 'MultiByteToWideChar', 'WideCharToMultiByte'} | {n for slots in _SLOTS.values() for n in slots}
        if name not in known:
            if self.fallback is None:
                raise PrimarySemanticUnavailable('Windows WMI observation is unsupported: ' + name)
            return self.fallback.take(runtime, name, arguments)
        foreign_shared = (name in ('MultiByteToWideChar', 'WideCharToMultiByte') and
                          (len(arguments) < 3 or arguments[2] not in self.convertible) or
                          name == 'VirtualQuery' and (not arguments or arguments[0] not in self.strings) or
                          name == 'VariantClear' and (not arguments or arguments[0] not in self.variants))
        if foreign_shared and self.fallback is not None:
            return self.fallback.take(runtime, name, arguments)
        unbalanced = name == 'CoUninitialize' and not self.successful_initializations
        result = self._take(name, tuple(arguments))
        self.events.append((name, int(bool(result[0])) if name == 'SysAllocString' else result[0]))
        if runtime is not None:
            if unbalanced:
                runtime.events.append(('worker.WMI_unbalanced_source_CoUninitialize',))
            else:
                runtime.events.append(('worker.API', name, arguments, *result))
        return result

    def _take(self, name, args):
        native = self._native()
        if name == 'CoInitializeEx':
            if args != (0, 0):
                raise InputError('WMI requires the source multithreaded COM initialization')
            result = native.initialize()
            if result in (0, 1):
                self.successful_initializations += 1
            return result, b''
        if name == 'CoUninitialize':
            if args:
                raise InputError('source CoUninitialize has no arguments')
            if self.successful_initializations:
                if self.successful_initializations == 1:
                    self._clear_variants()
                native.uninitialize()
                self.successful_initializations -= 1
                self.events.append(('source.COM_balance', 1))
            else:
                self.events.append(('source.COM_balance', 0))
            return 0, b''
        if name == 'CoCreateInstance':
            if args != (_CLSID, 0, 1, _IID):
                raise InputError('WMI class and interface must match the fixed source')
            result, pointer = native.create()
            return result, self._foreign(pointer, 'locator')
        if name == 'SysAllocString':
            if len(args) != 1 or args[0] not in self.allowed_strings:
                raise InputError('WMI BSTR input is outside the fixed source allowlist')
            pointer = native.allocate(args[0])
            if not pointer:
                return 0, b''
            token = self._token()
            self.strings[token] = (pointer, args[0], True)
            return token, native.bstr(pointer)
        if name == 'SysFreeString':
            if len(args) != 1 or args[0] not in self.strings or not self.strings[args[0]][2]:
                raise InputError('WMI BSTR is not an owned source allocation')
            native.free(self.strings[args[0]][0])
            del self.strings[args[0]]
            return 0, b''
        if name == 'CoSetProxyBlanket':
            if len(args) != 8 or args[1:] != (10, 0, 0, 3, 3, 0, 0) or args[0] not in self.references or self.references[args[0]][1] != 'services':
                raise InputError('WMI proxy blanket differs from its fixed source')
            return native.blanket(self.references[args[0]][0]), b''
        if name == 'VariantClear':
            if len(args) != 1 or args[0] not in self.variants:
                raise InputError('WMI VARIANT is outside the live native output domain')
            raw, token = self.variants[args[0]]
            result, output = native.clear(raw)
            if not result & 0x80000000:
                del self.variants[args[0]]
                if token:
                    self.strings.pop(token, None)
            if token and output[8:16] == raw[8:16]:
                output = output[:8] + token.to_bytes(8, 'little') + output[16:]
            return result, output
        if name == 'VirtualQuery':
            if len(args) != 2 or args[1] != 48 or args[0] not in self.strings:
                raise InputError('WMI VirtualQuery requires an owned BSTR')
            return native.virtual_query(self.strings[args[0]][0])
        if name in ('MultiByteToWideChar', 'WideCharToMultiByte'):
            if len(args) != (6 if name == 'MultiByteToWideChar' else 8) or args[0:2] != (0, 0) or args[2] not in self.convertible or type(args[4]) is not bool or not 0 <= args[5] <= 8192 or name == 'WideCharToMultiByte' and args[6:] != (0, 0):
                raise InputError('WMI conversion differs from its bounded source domain')
            unit = 1 if name == 'MultiByteToWideChar' else 2
            if args[3] != -1 and args[3] != len(args[2]) // unit:
                raise InputError('WMI conversion length differs from its source input')
            return native.convert(name, args)
        kind = {'IWbemLocator.ConnectServer': 'locator', 'IWbemServices.ExecQuery': 'services', 'IEnumWbemClassObject.Next': 'enumerator', 'IWbemClassObject.Get': 'object'}.get(name)
        token, record, rest = self._receiver(args, name, kind)
        pointer = record[0]
        if name == 'IUnknown.Release':
            if rest:
                raise InputError('IUnknown.Release has no source arguments')
            result = native.release(pointer)
            del self.references[token]
            return result, b''
        if name == 'IWbemLocator.ConnectServer':
            if len(rest) != 7 or rest[1:] != (0,) * 6 or rest[0] not in self.strings or self.strings[rest[0]][1] != _NAMESPACE:
                raise InputError('WMI namespace or connection options differ from fixed source')
            result, output = native.connect(pointer, self.strings[rest[0]][0])
            return result, self._foreign(output, 'services')
        if name == 'IWbemServices.ExecQuery':
            if len(rest) != 4 or rest[2:] != (0x30, 0) or any(p not in self.strings for p in rest[:2]):
                raise InputError('WMI query arguments differ from fixed source')
            language, statement = (self.strings[p] for p in rest[:2])
            if language[1] != 'WQL'.encode('utf-16le') + bytes(2) or statement[1] not in self.queries:
                raise InputError('WMI query is outside the fixed source allowlist')
            result, output = native.query(pointer, language[0], statement[0])
            return result, self._foreign(output, 'enumerator', self.queries[statement[1]])
        if name == 'IEnumWbemClassObject.Next':
            if rest != (0xFFFFFFFF, 1):
                raise InputError('WMI enumeration differs from fixed source')
            result, output, count = native.next(pointer)
            if count > 1:
                raise PrimarySemanticUnavailable('native WMI returned more than the source single object')
            current, images = self._foreign(output, 'object', record[3])
            return result, (current, count.to_bytes(4, 'little'), images)
        if name == 'IWbemClassObject.Get':
            if len(rest) != 4 or rest[1:] != (0, 0, 0) or rest[0] not in record[3]:
                raise InputError('WMI property differs from its fixed query property list')
            result, raw = native.get(pointer, rest[0])
            if len(raw) != 24:
                raise InputError('native WMI requires a Win64 VARIANT output')
            output, images, string_token = raw, (), 0
            pending = self._token()
            self.variants[pending] = (raw, 0)
            if int.from_bytes(raw[:2], 'little') == 8 and int.from_bytes(raw[8:16], 'little'):
                bstr = int.from_bytes(raw[8:16], 'little')
                string_token = self._token()
                self.strings[string_token] = (bstr, None, False)
                self.variants[pending] = (raw, string_token)
                value = native.bstr(bstr)
                self.convertible.add(value)
                end = next((i + 2 for i in range(0, len(value), 2) if value[i:i + 2] == bytes(2)), len(value))
                self.convertible.add(value[:end])
                images = ((string_token, value),)
                output = raw[:8] + string_token.to_bytes(8, 'little') + raw[16:]
            if output in self.variants:
                previous, previous_token = self.variants[output]
                if previous_token:
                    raise InputError('live WMI VARIANT token collision')
                cleared, ignored = native.clear(previous)
                if cleared & 0x80000000:
                    raise PrimarySemanticUnavailable('host WMI previous VARIANT cleanup failed')
                self.events.append(('host.VariantClear', cleared))
            self.variants[output] = (raw, string_token)
            del self.variants[pending]
            return result, (b'' if result & 0x80000000 else output, images)
        raise PrimarySemanticUnavailable('unimplemented fixed WMI operation: ' + name)

    def snapshot(self):
        if os.getpid() != self.pid or threading.get_native_id() != self.tid:
            raise InputError('Windows WMI snapshot requires its creator native thread')
        modules = sum(getattr(self.backend, name, None) is not None for name in ('kernel', 'aut', 'ole')) if isinstance(self.backend, _NativeWMI) else 0
        return {'native_thread_id': self.tid, 'interfaces': len(self.references), 'bstrs': len(self.strings), 'variants': len(self.variants), 'com_balances': self.successful_initializations, 'native_modules': modules, 'events': tuple(self.events), 'closed': self.closed}

    def _clear_variants(self):
        for output, (raw, token) in tuple(self.variants.items()):
            result, ignored = self.backend.clear(raw)
            if result & 0x80000000:
                raise PrimarySemanticUnavailable('host WMI VARIANT cleanup failed')
            del self.variants[output]
            if token:
                self.strings.pop(token, None)
            self.events.append(('host.VariantClear', result))

    def close(self):
        if self.closed:
            return
        self._check()
        if self.backend is not None:
            self._clear_variants()
            for token, (pointer, raw, owned) in tuple(self.strings.items()):
                if owned:
                    self.backend.free(pointer)
                    del self.strings[token]
                    self.events.append(('host.SysFreeString', 0))
            for token, record in reversed(tuple(self.references.items())):
                result = self.backend.release(record[0])
                del self.references[token]
                self.events.append(('host.IUnknown.Release', result))
            while self.successful_initializations:
                self.backend.uninitialize()
                self.successful_initializations -= 1
                self.events.append(('host.CoUninitialize', 0))
            close = getattr(self.backend, 'close', None)
            if close is not None:
                close()
        self.convertible.clear()
        self.closed = True
