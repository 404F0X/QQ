import ctypes
import os
import struct
import threading

from .primary_qimei_context import ContextObservationError
from .primary_qimei_storage import StorageApiReply, StorageBuffer


_MASK = (1 << 64) - 1


def _changes(before, after):
    changes, start = [], None
    for index, (old, new) in enumerate(zip(before, after)):
        if old != new and start is None:
            start = index
        elif old == new and start is not None:
            changes.append((start, after[start:index]))
            start = None
    if start is not None:
        changes.append((start, after[start:]))
    return tuple(changes)


class WindowsStorageAPIBackend:
    def __init__(self):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ContextObservationError('Qimei storage API requires Windows x64')
        self._owner = os.getpid(), threading.get_native_id()
        self._handles, self._allocations, self._pointers = {}, {}, set()
        self._heap = None
        self.closed = False
        self.records = []
        self.kernel = ctypes.WinDLL('kernel32', handle=ctypes.windll.kernel32._handle, use_last_error=True)

    def _check(self):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise ContextObservationError('storage API requires its open creator process and thread')

    def _call(self, name, result, types, values):
        self._check()
        function = getattr(self.kernel, name)
        function.restype, function.argtypes = result, types
        value = function(*values)
        self.records.append({'api': name, 'error': ctypes.get_last_error() & 0xFFFFFFFF})
        return value

    def _ioctl_arguments(self, args):
        if len(args) != 5:
            raise ContextObservationError('invalid storage IOCTL arity')
        handle, code, request, output, in_place = args
        if type(handle) is not int or handle not in self._handles or type(code) is not int:
            raise ContextObservationError('storage IOCTL requires an owned handle')
        if not isinstance(request, StorageBuffer) or not isinstance(output, StorageBuffer) or type(in_place) is not bool:
            raise ContextObservationError('storage IOCTL requires explicit buffers and alias flag')
        source, target = request.read(), output.read()
        path, access, share = self._handles[handle]
        physical = path.startswith('\\\\.\\PhysicalDrive')
        valid = False
        if code == 0x74080:
            valid = physical and access == 0xC0000000 and len(source) == 0 and len(target) == 24 and not in_place
        elif code == 0x2D1400:
            valid = physical and access == 0 and source == bytes(12) and len(target) == 2048 and not in_place
        elif code == 0x7C088 and physical and access == 0xC0000000:
            if share == 7:
                valid = len(source) == 33 and len(target) == 545 and in_place and source[10] == 0xEC
            else:
                disk = int(path.removeprefix('\\\\.\\PhysicalDrive'))
                expected = bytearray(32)
                struct.pack_into('<IH', expected, 0, 512, 0x100)
                expected[9], expected[12] = 0xA0 | ((disk & 1) << 4), disk
                if len(source) == 32 and source[10] in (0xEC, 0xA1):
                    expected[10] = source[10]
                    valid = source == bytes(expected) and len(target) == 528 and not in_place
        elif code == 0x4D008 and not physical:
            for unit in (0, 1):
                expected = bytearray(557)
                struct.pack_into('<I8sIIII', expected, 0, 28, b'SCSIDISK', 10000, 0x1B0501, 0, 529)
                expected[38], expected[40] = 0xEC, unit
                if source == bytes(expected[:60]) and target == bytes(expected) and in_place:
                    valid = True
        if not valid or in_place and source != target[:len(source)]:
            raise ContextObservationError('storage IOCTL leaves the fixed source query domain')
        return handle, code, source, target, in_place

    def request(self, name, args):
        self._check()
        if not isinstance(args, tuple):
            raise ContextObservationError('storage API arguments require a tuple')
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        if name == 'GetVersionExW':
            if len(args) != 1 or not isinstance(args[0], StorageBuffer):
                raise ContextObservationError('storage version requires its source buffer')
            before = args[0].read()
            if before != struct.pack('<I', 276) + bytes(272):
                raise ContextObservationError('storage version buffer differs from fixed source')
            output = ctypes.create_string_buffer(before, len(before))
            result = self._call(name, i, (p,), (output,))
            return StorageApiReply(result & 0xFFFFFFFF, _changes(before, output.raw))
        if name == 'CreateFileW':
            if len(args) != 7:
                raise ContextObservationError('invalid storage file-open arity')
            path, access, share, security, creation, flags, template = args
            physical = {rf'\\.\PhysicalDrive{disk}' for disk in range(16)}
            scsi = {rf'\\.\Scsi{disk}:' for disk in range(16)}
            valid = isinstance(path, str) and (path in physical and (access, share) in ((0xC0000000, 3), (0xC0000000, 7), (0, 3)) or
                     path in scsi and (access, share) == (0xC0000000, 3))
            if not valid or any(type(x) is not int for x in args[1:]) or (security, creation, flags, template) != (0, 3, 0, 0):
                raise ContextObservationError('storage open leaves the fixed source device domain')
            result = self._call(name, p, (ctypes.c_wchar_p, u, u, p, u, u, p), args)
            handle = int(result or 0) & _MASK
            if handle != _MASK:
                self._handles[handle] = path, access, share
            return handle
        if name == 'DeviceIoControl':
            handle, code, source, target, in_place = self._ioctl_arguments(args)
            output = ctypes.create_string_buffer(target, len(target))
            input_buffer = output if in_place else ctypes.create_string_buffer(source, len(source)) if source else None
            count = u()
            result = self._call(name, i, (p, u, p, u, p, u, ctypes.POINTER(u), p),
                                (handle, code, input_buffer, len(source), output, len(target), ctypes.byref(count), None))
            self.records[-1]['bytes_returned'] = count.value
            return StorageApiReply(result & 0xFFFFFFFF, _changes(target, output.raw))
        if name == 'CloseHandle':
            if len(args) != 1 or type(args[0]) is not int or args[0] not in self._handles:
                raise ContextObservationError('storage close requires an owned handle')
            result = self._call(name, i, (p,), args) & 0xFFFFFFFF
            if result:
                del self._handles[args[0]]
            return result
        if name == 'allocate':
            if args != (545,) or type(args[0]) is not int:
                raise ContextObservationError('storage allocation differs from fixed source size')
            if self._heap is None:
                self._heap = int(self._call('GetProcessHeap', p, (), ()) or 0)
                if not self._heap:
                    raise ContextObservationError('native process heap is unavailable')
            pointer = int(self._call('HeapAlloc', p, (p, u, ctypes.c_size_t), (self._heap, 0, 545)) or 0)
            if not pointer:
                return None
            self._pointers.add(pointer)
            buffer = StorageBuffer(ctypes.string_at(pointer, 545))
            self._allocations[id(buffer)] = buffer, pointer
            return buffer
        if name == 'free':
            if len(args) != 1 or id(args[0]) not in self._allocations or self._allocations[id(args[0])][0] is not args[0]:
                raise ContextObservationError('storage free requires the original owned allocation')
            pointer = self._allocations[id(args[0])][1]
            result = self._call('HeapFree', i, (p, u, p), (self._heap, 0, pointer))
            if not result:
                raise ContextObservationError('native storage allocation was not freed')
            self._pointers.remove(pointer)
            del self._allocations[id(args[0])]
            return None
        raise ContextObservationError('unsupported native storage API observation')

    def snapshot(self):
        return {'closed': self.closed, 'handles': len(self._handles), 'allocations': len(self._pointers),
                'API_calls': len(self.records)}

    def close(self):
        if self.closed:
            return
        self._check()
        p, u, i = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        for pointer in tuple(self._pointers):
            if self._call('HeapFree', i, (p, u, p), (self._heap, 0, pointer)):
                self._pointers.remove(pointer)
                self._allocations = {key: value for key, value in self._allocations.items() if value[1] != pointer}
        for handle in tuple(self._handles):
            if self._call('CloseHandle', i, (p,), (handle,)):
                del self._handles[handle]
        if self._pointers or self._handles:
            raise ContextObservationError('native storage cleanup retains owned resources')
        self.closed = True


class WindowsStorageObservations:
    def __init__(self, observations=None, *, backend=None):
        self.observations, self.backend = observations, backend
        self._owner = os.getpid(), threading.get_native_id()
        self.consumed = []
        self.closed = False

    def _check(self):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise ContextObservationError('storage observations require their open creator process and thread')

    def read(self, *key):
        self._check()
        self.consumed.append(key)
        if key[:1] != ('storage-api',):
            if self.observations is None:
                raise ContextObservationError('non-storage observation requires an explicit producer')
            return self.observations.read(*key)
        if len(key) < 2:
            raise ContextObservationError('storage observation requires an API name')
        if self.backend is None:
            self.backend = WindowsStorageAPIBackend()
        return self.backend.request(key[1], key[2:])

    def close(self):
        if self.closed:
            return
        self._check()
        if self.backend is not None:
            self.backend.close()
        self.closed = True
