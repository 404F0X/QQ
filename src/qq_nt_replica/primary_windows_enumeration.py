import ctypes
import os

from .errors import CapabilityUnavailable, InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker import WorkerObservations
from .primary_device_native import _HARDWARE_FLAG


_SLOTS = {'NtOpenDirectoryObject': 0x6D83E08, 'NtQueryDirectoryObject': 0x6D83E10,
          'NtClose': 0x6D83E18, 'EnumDisplayDevicesW': 0x4910508}


class _UnicodeString(ctypes.Structure):
    _fields_ = [('Length', ctypes.c_uint16), ('MaximumLength', ctypes.c_uint16), ('Buffer', ctypes.c_void_p)]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [('Length', ctypes.c_uint32), ('RootDirectory', ctypes.c_void_p),
                ('ObjectName', ctypes.POINTER(_UnicodeString)), ('Attributes', ctypes.c_uint32),
                ('SecurityDescriptor', ctypes.c_void_p), ('SecurityQualityOfService', ctypes.c_void_p)]


class _DisplayDevice(ctypes.Structure):
    _fields_ = [('cb', ctypes.c_uint32), ('DeviceName', ctypes.c_uint16 * 32),
                ('DeviceString', ctypes.c_uint16 * 128), ('StateFlags', ctypes.c_uint32),
                ('DeviceID', ctypes.c_uint16 * 128), ('DeviceKey', ctypes.c_uint16 * 128)]


class _WindowsAPIs:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise CapabilityUnavailable('Windows x64 enumeration APIs are required')
        self.nt = ctypes.WinDLL('ntdll')
        self.user = ctypes.WinDLL('user32')
        signatures = (
            (self.nt, 'NtOpenDirectoryObject', ctypes.c_int32,
             (ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.POINTER(_ObjectAttributes))),
            (self.nt, 'NtQueryDirectoryObject', ctypes.c_int32,
             (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_ubyte,
              ctypes.c_ubyte, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p)),
            (self.nt, 'NtClose', ctypes.c_int32, (ctypes.c_void_p,)),
            (self.user, 'EnumDisplayDevicesW', ctypes.c_int32,
             (ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_DisplayDevice), ctypes.c_uint32)))
        for library, name, result, arguments in signatures:
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            setattr(self, name, function)


def _u32(value):
    value = getattr(value, 'value', value)
    if type(value) is not int:
        raise InputError('Windows enumeration backend result must be an integer')
    return value & 0xFFFFFFFF


def _terminated(raw):
    for offset in range(0, len(raw), 2):
        if raw[offset:offset + 2] == b'\0\0':
            return raw[:offset + 2]
    raise CapabilityUnavailable('Windows enumeration output lacks a bounded UTF16 terminator')


class WindowsEnumerationObservations(WorkerObservations):
    def __init__(self, fallback=None, *, backend=None):
        super().__init__(())
        self.fallback, self.backend = fallback, backend
        self.records, self.cleanup_records, self.failures = [], [], []
        self._handles = {}

    @property
    def pending_handles(self):
        return tuple((handle, entry['state']) for handle, entry in self._handles.items())

    @property
    def scratch_count(self):
        return sum(entry['scratch'] is not None for entry in self._handles.values())

    def _api(self):
        if self.backend is None:
            self.backend = _WindowsAPIs()
        return self.backend

    def _record(self, runtime, name, args, result, effects):
        event = name, args, result, tuple(effects)
        self.records.append(event)
        return WorkerObservations((event,)).take(runtime, name, args)

    def take(self, runtime, name, arguments):
        try:
            if name not in _SLOTS:
                if self.fallback is None:
                    raise CapabilityUnavailable('Windows enumeration has no fallback for this API')
                return self.fallback.take(runtime, name, arguments)
            if not isinstance(arguments, tuple) or any(type(value) is not int or not 0 <= value < 1 << 64 for value in arguments):
                raise InputError('Windows enumeration requires unsigned raw argument tuples')
            expected = runtime.worker_imports.get(name)
            actual = runtime.memory.load(runtime.image_base + _SLOTS[name], 8)
            dynamic = name != 'EnumDisplayDevicesW'
            resolved = actual == expected and actual and runtime.memory.load(runtime.image_base + _HARDWARE_FLAG, 1) & 1 if dynamic else actual == expected
            if not expected or not resolved:
                raise PrimarySemanticUnavailable('Windows enumeration current API slot is not bound: ' + name)
            operation = {'NtOpenDirectoryObject': self._open, 'NtQueryDirectoryObject': self._query,
                         'NtClose': self._close_source, 'EnumDisplayDevicesW': self._display}[name]
            return operation(runtime, name, arguments)
        except BaseException:
            self.close()
            raise

    def _open(self, runtime, name, args):
        if len(args) != 3:
            raise InputError('NtOpenDirectoryObject requires three raw arguments')
        output, access, address = args
        memory = runtime.memory
        memory._span(output, 8)
        if access != 1 or memory.load(address, 4) != 48 or any(
                memory.load(address + offset, width) for offset, width in ((8, 8), (24, 4), (32, 8), (40, 8))):
            raise InputError('NtOpenDirectoryObject requires the source flags0/access1 attributes')
        unicode = memory.load(address + 16, 8)
        if memory.load(unicode, 2) != 18 or memory.load(unicode + 2, 2) != 20:
            raise InputError('NtOpenDirectoryObject requires the source UNICODE_STRING lengths')
        raw = memory.read(memory.load(unicode + 8, 8), 20)
        if raw != '\\GLOBAL??\0'.encode('utf-16le'):
            raise InputError('NtOpenDirectoryObject requires the source GLOBAL?? name')
        value = ctypes.create_string_buffer(raw, 20)
        native_name = _UnicodeString(18, 20, ctypes.addressof(value))
        attrs = _ObjectAttributes(48, None, ctypes.pointer(native_name), 0, None, None)
        if memory.load(output, 8) != 0:
            raise InputError('NtOpenDirectoryObject requires the source zero initial handle')
        handle = ctypes.c_void_p()
        memory.forget(output, 8, source='windows_enumeration.NtOpenDirectoryObject.potential_output')
        try:
            status = _u32(self._api().NtOpenDirectoryObject(ctypes.byref(handle), access, ctypes.byref(attrs)))
        except BaseException:
            if handle.value:
                self._handles[handle.value] = {'state': 'uncertain', 'scratch': None}
            raise
        observed = handle.value or 0
        if observed:
            if observed in self._handles:
                raise CapabilityUnavailable('Windows enumeration returned an already owned handle')
            self._handles[observed] = {'state': 'uncertain' if status & 0x80000000 else 'owned', 'scratch': None}
        return self._record(runtime, name, args, status, ((output, observed.to_bytes(8, 'little')),))

    def _query(self, runtime, name, args):
        if len(args) != 7:
            raise InputError('NtQueryDirectoryObject requires seven raw arguments')
        handle, output, size, single, restart, context_address, returned = args
        entry = self._handles.get(handle)
        if entry is None or entry['state'] != 'owned':
            raise InputError('NtQueryDirectoryObject requires this bridge opened handle')
        if size != 4096 or single != 0 or restart not in (0, 1) or returned != 0:
            raise InputError('NtQueryDirectoryObject requires the source 4096-byte bulk query')
        memory = runtime.memory
        memory._span(output, size)
        previous = memory.load(context_address, 4)
        context = ctypes.c_uint32(previous)
        if entry['scratch'] is None:
            entry['scratch'] = ctypes.create_string_buffer(4096)
        scratch = entry['scratch']
        memory.forget(output, size, source='windows_enumeration.NtQueryDirectoryObject.potential_output')
        memory.forget(context_address, 4, source='windows_enumeration.NtQueryDirectoryObject.potential_context')
        status = _u32(self._api().NtQueryDirectoryObject(handle, scratch, size, single, restart, ctypes.byref(context), None))
        effects = [(context_address, context.value.to_bytes(4, 'little'))]
        if not status & 0x80000000:
            count = (context.value - previous) & 0xFFFFFFFF
            try:
                if count > 128:
                    raise CapabilityUnavailable('Windows directory records exceed the source 4096-byte buffer')
                base = ctypes.addressof(scratch)
                for index in range(count):
                    offset = index * 32
                    length = int.from_bytes(scratch.raw[offset:offset + 2], 'little')
                    effects.append((output + offset, length.to_bytes(2, 'little')))
                    size = (length >> 1) * 2
                    if not size:
                        continue
                    pointer = int.from_bytes(scratch.raw[offset + 8:offset + 16], 'little')
                    relative = pointer - base
                    if not 0 <= relative <= 4096 - size:
                        raise CapabilityUnavailable('Windows directory name pointer leaves its source scratch buffer')
                    effects.append((output + offset + 8, (output + relative).to_bytes(8, 'little')))
                    effects.append((output + relative, ctypes.string_at(pointer, size)))
            except BaseException:
                self._record(runtime, name, args, status, effects[:1])
                self.failures.append((name, status, 'unsupported directory output layout'))
                raise
        return self._record(runtime, name, args, status, effects)

    def _close_source(self, runtime, name, args):
        if len(args) != 1 or args[0] not in self._handles:
            raise InputError('NtClose requires this bridge retained handle')
        handle = args[0]
        status = _u32(self._api().NtClose(handle))
        if not status & 0x80000000:
            del self._handles[handle]
        return self._record(runtime, name, args, status, ())

    def _display(self, runtime, name, args):
        if len(args) != 4:
            raise InputError('EnumDisplayDevicesW requires four raw arguments')
        parent, index, output, flags = args
        memory = runtime.memory
        memory._span(output, 0x348)
        if flags != 0 or index > 0xFFFFFFFF or memory.load(output, 4) != 0x348:
            raise InputError('EnumDisplayDevicesW requires the source cb/index/flags')
        native_parent = None
        if parent:
            raw = bytearray()
            for unit in range(32):
                value = memory.read(parent + unit * 2, 2)
                raw.extend(value)
                if value == b'\0\0':
                    break
            else:
                raise InputError('EnumDisplayDevicesW parent name has no bounded UTF16 terminator')
            native_parent = ctypes.create_string_buffer(bytes(raw), len(raw))
        native = _DisplayDevice()
        native.cb = 0x348
        memory.forget(output, 0x348, source='windows_enumeration.EnumDisplayDevicesW.potential_output')
        result = _u32(self._api().EnumDisplayDevicesW(native_parent, index, ctypes.byref(native), flags))
        effects = []
        if result:
            try:
                if not parent:
                    raw = ctypes.string_at(ctypes.addressof(native) + 4, 64)
                    effects.append((output + 4, _terminated(raw)))
                else:
                    effects.append((output + 0x144, native.StateFlags.to_bytes(4, 'little')))
                    if native.StateFlags & 1 and not native.StateFlags & 8:
                        raw = ctypes.string_at(ctypes.addressof(native) + 0x148, 256)
                        effects.append((output + 0x148, _terminated(raw)))
            except BaseException:
                self._record(runtime, name, args, result, effects)
                self.failures.append((name, result, 'unsupported display output layout'))
                raise
        return self._record(runtime, name, args, result, effects)

    def close(self):
        for handle, entry in tuple(self._handles.items()):
            try:
                status = _u32(self._api().NtClose(handle))
            except BaseException as error:
                self.cleanup_records.append(('cleanup.NtClose', handle, None, type(error).__name__, entry['state']))
                continue
            self.cleanup_records.append(('cleanup.NtClose', handle, status, entry['state']))
            if not status & 0x80000000:
                del self._handles[handle]
