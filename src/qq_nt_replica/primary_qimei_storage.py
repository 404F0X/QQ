import struct
from dataclasses import dataclass, field

from .primary_qimei_context import ContextObservationError


def _ascii(value):
    if not 0 <= value < 128:
        raise ContextObservationError('non-ASCII storage byte requires explicit CRT locale semantics')
    return value


def _space(value):
    return _ascii(value) in (9, 10, 11, 12, 13, 32)


def _print(value):
    return 32 <= value <= 126


def _alnum(value):
    value = _ascii(value)
    return 48 <= value <= 57 or 65 <= value <= 90 or 97 <= value <= 122


def _field_buffer(raw, offset, swap):
    if not isinstance(raw, bytes) or type(offset) is not int or not 0 <= offset < 1 << 32:
        raise ContextObservationError('storage field requires bytes and a DWORD offset')
    if type(swap) is not bool:
        raise ContextObservationError('storage field swap requires a boolean')
    output = bytearray(256)
    if offset == 0 or offset & 0x80000000:
        return output

    def read(index):
        if not 0 <= index < len(raw):
            raise ContextObservationError('storage field reads beyond declared bytes')
        return raw[index]

    def write(index, value):
        if not 0 <= index < len(output):
            raise ContextObservationError('storage field exceeds source 256-byte buffer')
        output[index] = value

    index, length, parity, good = offset, 0, 0, True
    while good:
        value = read(index)
        if value == 0:
            break
        value = _ascii(value)
        if 65 <= value <= 90:
            value += 32
        if _space(value):
            value = 48
        parity += 1
        write(length, (output[length] << 4) & 255)
        if 48 <= value <= 57:
            write(length, output[length] | (value - 48))
        elif 97 <= value <= 102:
            write(length, output[length] | (value - 87))
        else:
            good = False
            break
        if parity == 2:
            if output[length] and not _print(output[length]):
                good = False
                break
            write(length + 1, 0)
            length += 1
            parity = 0
        index += 1
    if not good:
        output[0] = 0
        index, length, good = offset, 0, True
        while True:
            value = read(index)
            if value == 0:
                break
            if not _print(value):
                good = False
                break
            write(length, value)
            length += 1
            index += 1
        if not good:
            length = 0
    write(length, 0)
    if swap:
        for index in range(0, length, 2):
            output[index], output[index + 1] = output[index + 1], output[index]
    first, last = -1, -1
    for index, value in enumerate(output):
        if value == 0:
            break
        if not _space(value):
            if first < 0:
                first = index
            last = index
    if first >= 0 and last >= 0:
        for index in range(first, last + 1):
            output[index - first] = output[index]
        write(last + 1 - first, 0)
    return output


def decode_storage_field(raw, offset, *, swap=False):
    return bytes(_field_buffer(raw, offset, swap)).split(b'\0', 1)[0]


def storage_descriptor(raw, *, swap_serial=False):
    if not isinstance(raw, bytes) or len(raw) < 28:
        raise ContextObservationError('storage descriptor requires readable offsets through byte 27')
    model_offset, firmware_offset, serial_offset = struct.unpack_from('<III', raw, 16)
    model = _field_buffer(raw, model_offset, False)
    firmware = _field_buffer(raw, firmware_offset, False)
    serial = _field_buffer(raw, serial_offset, swap_serial)
    if not _alnum(serial[0]) and not _alnum(serial[19]):
        return None
    return tuple(bytes(value).split(b'\0', 1)[0] for value in (serial, model, firmware))


class DescriptorContextObservations:
    def __init__(self, observations, *, swap_serial=False):
        if type(swap_serial) is not bool:
            raise ContextObservationError('descriptor swap requires a boolean')
        self.observations = observations
        self.swap_serial = swap_serial
        self._produced = False
        self._strings = None

    @property
    def consumed(self):
        return self.observations.consumed

    def read(self, *key):
        if not key or key[0] != 'storage':
            return self.observations.read(*key)
        if not self._produced:
            success = self.observations.read('storage-descriptor', 'query-success')
            if type(success) is not bool:
                raise ContextObservationError('descriptor query result requires a boolean')
            if not success:
                raise ContextObservationError('failed descriptor query requires remaining storage probes')
            strings = storage_descriptor(self.observations.read('storage-descriptor', 'bytes'),
                                         swap_serial=self.swap_serial)
            if strings is None:
                raise ContextObservationError('unaccepted descriptor serial requires remaining storage probes')
            self._strings = strings
            self._produced = True
        if key == ('storage', 'success'):
            return self._strings is not None
        if self._strings is None:
            raise ContextObservationError('descriptor did not produce storage strings')
        if key == ('storage', 'format'):
            return 'normalized'
        if len(key) == 2 and type(key[1]) is int and 0 <= key[1] <= 2:
            return self._strings[key[1]]
        raise ContextObservationError('unsupported descriptor storage consumer')


@dataclass(frozen=True)
class StorageBuffer:
    data: bytes = field(repr=False)
    known: bytes | None = field(default=None, repr=False)

    def __post_init__(self):
        if not isinstance(self.data, bytes):
            raise ContextObservationError('storage buffer requires bytes')
        if self.known is None:
            object.__setattr__(self, 'known', bytes([1]) * len(self.data))
        elif not isinstance(self.known, bytes) or len(self.known) != len(self.data) or any(x not in (0, 1) for x in self.known):
            raise ContextObservationError('invalid storage buffer knownness')

    @classmethod
    def unknown(cls, length):
        if type(length) is not int or length < 0:
            raise ContextObservationError('storage buffer length requires a nonnegative integer')
        return cls(bytes(length), bytes(length))

    def read(self, offset=0, length=None):
        length = len(self.data) - offset if length is None else length
        if type(offset) is not int or type(length) is not int or offset < 0 or length < 0 or offset + length > len(self.data):
            raise ContextObservationError('storage buffer read outside declared range')
        if not all(self.known[offset:offset + length]):
            raise ContextObservationError('unknown storage output consumed')
        return self.data[offset:offset + length]

    def write(self, offset, data):
        if type(offset) is not int or not isinstance(data, bytes) or offset < 0 or offset + len(data) > len(self.data):
            raise ContextObservationError('storage output write outside declared range')
        end = offset + len(data)
        return StorageBuffer(self.data[:offset] + data + self.data[end:],
                             self.known[:offset] + bytes([1]) * len(data) + self.known[end:])

    def prefix(self, length):
        if type(length) is not int or not 0 <= length <= len(self.data):
            raise ContextObservationError('storage input prefix outside declared range')
        return StorageBuffer(self.data[:length], self.known[:length])


@dataclass(frozen=True)
class StorageApiReply:
    result: int
    writes: tuple = field(default=(), repr=False)

    def apply(self, buffer, *, width=32):
        if type(self.result) is not int or not 0 <= self.result < 1 << width or not isinstance(self.writes, tuple):
            raise ContextObservationError('invalid storage API result')
        for row in self.writes:
            if not isinstance(row, tuple) or len(row) != 2:
                raise ContextObservationError('invalid storage API output span')
            buffer = buffer.write(*row)
        return buffer


class NtStorageProbe:
    def __init__(self, *, swap_serial=False, outputs=(b'', b'', b'')):
        if type(swap_serial) is not bool or type(outputs) is not tuple or len(outputs) != 3 or any(
                value is not None and not isinstance(value, bytes) for value in outputs):
            raise ContextObservationError('invalid initial NT storage state')
        self.swap_serial = swap_serial
        self.outputs = list(outputs)
        self.phase = 'new'
        self.disk = self.unit = self.handle = None
        self.allocation = None
        self.complete = self.failed = self.succeeded = False

    def _ioctl(self, observations, code, request, output, *, in_place=False):
        reply = observations.read('storage-api', 'DeviceIoControl', self.handle, code, request, output, in_place)
        if not isinstance(reply, StorageApiReply):
            raise ContextObservationError('storage IOCTL requires an explicit API reply')
        return reply.result, reply.apply(output)

    def _open(self, observations, path, access, share):
        handle = observations.read('storage-api', 'CreateFileW', path, access, share, 0, 3, 0, 0)
        if type(handle) is not int or not 0 <= handle < 1 << 64:
            raise ContextObservationError('storage open requires a raw handle value')
        self.handle = None if handle == (1 << 64) - 1 else handle
        return self.handle is not None

    def _close(self, observations):
        result = observations.read('storage-api', 'CloseHandle', self.handle)
        if type(result) is not int or not 0 <= result < 1 << 32:
            raise ContextObservationError('storage close requires a DWORD result')
        self.handle = None

    def _ata(self, buffer, base):
        for index, (first, last) in enumerate(((10, 19), (27, 46), (23, 26))):
            raw = buffer.read(base + first * 2, 2 * (last - first + 1))
            self.outputs[index] = b''.join(raw[i:i + 2][::-1] for i in range(0, len(raw), 2)).rstrip(b' ')

    def _finish(self, success):
        self.complete, self.succeeded = True, success
        return tuple(self.outputs) if success else None

    def produce(self, observations):
        if self.failed or self.phase != 'new':
            raise ContextObservationError('NT storage probe cannot replay an entry')
        try:
            return self._produce(observations)
        except BaseException:
            self.failed = True
            raise

    def _produce(self, observations):
        self.phase = 'version'
        version = StorageBuffer(struct.pack('<I', 276) + bytes(272))
        reply = observations.read('storage-api', 'GetVersionExW', version)
        if not isinstance(reply, StorageApiReply):
            raise ContextObservationError('storage version requires an explicit API reply')
        version = reply.apply(version)
        if int.from_bytes(version.read(16, 4), 'little') != 2:
            raise ContextObservationError('legacy non-NT storage port probing is not implemented')
        self.phase = 'smart'
        for self.disk in range(16):
            if not self._open(observations, rf'\\.\PhysicalDrive{self.disk}', 0xC0000000, 3):
                continue
            unused, version = self._ioctl(observations, 0x74080, StorageBuffer(b''), StorageBuffer(bytes(24)))
            bitmap = version.read(3, 1)[0]
            if bitmap:
                command = 0xA1 if bitmap >> self.disk & 0x10 else 0xEC
                request = bytearray(32)
                struct.pack_into('<I', request, 0, 512)
                struct.pack_into('<H', request, 4, 0x100)
                request[9], request[10], request[12] = 0xA0 | ((self.disk & 1) << 4), command, self.disk
                result, output = self._ioctl(observations, 0x7C088, StorageBuffer(bytes(request)), StorageBuffer(bytes(528)))
                if result == 1 and int.from_bytes(output.read(0, 4), 'little') >= 47:
                    self._ata(output, 16)
                    self._close(observations)
                    return self._finish(True)
            self._close(observations)
        self.phase = 'miniport'
        for self.disk in range(16):
            if not self._open(observations, rf'\\.\Scsi{self.disk}:', 0xC0000000, 3):
                continue
            for self.unit in range(2):
                output = bytearray(557)
                struct.pack_into('<I8sIIII', output, 0, 28, b'SCSIDISK', 10000, 0x1B0501, 0, 529)
                output[38], output[40] = 0xEC, self.unit
                buffer = StorageBuffer(bytes(output))
                result, output = self._ioctl(observations, 0x4D008, buffer.prefix(60), buffer, in_place=True)
                if result != 0 and output.read(44 + 54, 1)[0] != 0:
                    self._ata(output, 44)
                    self._close(observations)
                    return self._finish(True)
            self._close(observations)
        self.unit = None
        self.phase = 'descriptor'
        for self.disk in range(16):
            if not self._open(observations, rf'\\.\PhysicalDrive{self.disk}', 0, 3):
                continue
            result, output = self._ioctl(observations, 0x2D1400, StorageBuffer(bytes(12)), StorageBuffer(bytes(2048)))
            if result != 0:
                raw = output.read()
                strings = storage_descriptor(raw, swap_serial=self.swap_serial)
                if strings is not None:
                    self.outputs[:] = strings
                    self._close(observations)
                    return self._finish(True)
            self._close(observations)
        self.phase = 'final-identify'
        for self.disk in range(16):
            if not self._open(observations, rf'\\.\PhysicalDrive{self.disk}', 0xC0000000, 7):
                continue
            result, unused = self._ioctl(observations, 0x74080, StorageBuffer(b''), StorageBuffer(bytes(24)))
            if result != 0:
                allocation = observations.read('storage-api', 'allocate', 545)
                if allocation is not None:
                    if not isinstance(allocation, StorageBuffer) or len(allocation.data) != 545:
                        raise ContextObservationError('storage allocation requires a 545-byte preimage or NULL')
                    self.allocation = allocation
                    output = allocation.write(10, b'\xEC')
                    result, output = self._ioctl(observations, 0x7C088, output.prefix(33), output, in_place=True)
                    if result != 0 and int.from_bytes(output.read(0, 4), 'little') >= 47:
                        self._ata(output, 16)
                        free_result = observations.read('storage-api', 'free', allocation)
                        if free_result is not None:
                            raise ContextObservationError('storage free has no return value')
                        self.allocation = None
                        self._close(observations)
                        return self._finish(True)
                    free_result = observations.read('storage-api', 'free', allocation)
                    if free_result is not None:
                        raise ContextObservationError('storage free has no return value')
                    self.allocation = None
            self._close(observations)
        return self._finish(False)


class NtStorageContextObservations:
    def __init__(self, observations, *, swap_serial=False):
        self.observations = observations
        self.probe = NtStorageProbe(swap_serial=swap_serial)
        self._produced = False
        self._strings = None

    @property
    def consumed(self):
        return self.observations.consumed

    def read(self, *key):
        if not key or key[0] != 'storage':
            return self.observations.read(*key)
        if not self._produced:
            self._strings = self.probe.produce(self.observations)
            self._produced = True
        if key == ('storage', 'success'):
            return self._strings is not None
        if self._strings is None:
            raise ContextObservationError('NT storage probes did not produce strings')
        if key == ('storage', 'format'):
            return 'normalized'
        if len(key) == 2 and type(key[1]) is int and 0 <= key[1] <= 2:
            return self._strings[key[1]]
        raise ContextObservationError('unsupported NT storage consumer')
