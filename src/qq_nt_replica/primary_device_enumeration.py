from .errors import InputError
from .primary_device import _DEVICE_SEED, _sip_round
from .primary_logger import _Tree
from .primary_worker import WorkerObservations, _WideString, _units
from .primary_vm import PrimaryProgramLimit


_PREFIXES = tuple(value.encode('utf-16le') for value in (
    'PCI#', 'SCSI', 'HDAUDIO', 'SWD#SGDEVAPI', 'USB4#ROOT_DEVICE_ROUTER',
    'INTELAUDIO', 'USB#ROOT_HUB30'))
_LIMIT = 4096


def _call(runtime, transcript, name, arguments, outputs=()):
    result, effects = transcript.take(runtime, name, arguments)
    if not isinstance(effects, tuple):
        raise InputError('device enumeration effects require explicit address/bytes pairs')
    pending = []
    for effect in effects:
        if not isinstance(effect, tuple) or len(effect) != 2:
            raise InputError('device enumeration effect requires address and raw bytes')
        address, raw = effect
        if type(address) is not int or not isinstance(raw, bytes) or not any(
                start <= address and address + len(raw) <= start + size for start, size in outputs):
            raise InputError('device enumeration effect leaves the actual API output')
        runtime.memory._span(address, len(raw))
        pending.append((address, raw))
    for address, raw in pending:
        if raw:
            runtime.memory.write(address, raw, source='device_enumeration.' + name)
    return result & 0xFFFFFFFF


class UTF16Set(_Tree):
    def initialize(self):
        self.store(self.address, 0, self.address + 8)
        self.store(self.address, 8, 0)
        self.store(self.address, 16, 0)

    def insert_wide(self, value, *, move):
        key = _units(value.value())
        parent = slot = self.address + 8
        node = self.load(slot)
        for _ in range(_LIMIT):
            if not node:
                node = self.runtime._operator_new(56)
                if move:
                    value.write_header(node + 32)
                    value.runtime.memory.write(value.address, bytes(24), source='device_enumeration.move_reset')
                else:
                    value.clone_to(node + 32)
                self.memory.write(node, bytes(16), source='device_enumeration.children')
                self.store(node, 16, parent)
                self.store(slot, 0, node)
                begin = self.load(self.address)
                left = self.load(begin)
                if left:
                    self.store(self.address, 0, left)
                self.balance(self.load(self.address, 8), node)
                self.store(self.address, 16, self.load(self.address, 16) + 1)
                return node, True
            present = _units(_WideString(self.runtime, address=node + 32).value())
            if key == present:
                return node, False
            parent, slot = node, node + (0 if key < present else 8)
            node = self.load(slot)
        raise PrimaryProgramLimit('device enumeration tree exceeds its bounded domain')

    def _release(self):
        pending = [(self.load(self.address, 8), False)]
        seen = set()
        while pending:
            node, ready = pending.pop()
            if not node:
                continue
            if ready:
                _WideString(self.runtime, address=node + 32).destroy()
                self.runtime._free_allocation(node)
                continue
            if node in seen or len(seen) >= _LIMIT:
                raise PrimaryProgramLimit('device enumeration cleanup cycle or bound')
            seen.add(node)
            pending.extend(((node, True), (self.load(node, 8), False), (self.load(node), False)))

    def clear(self):
        self._release()
        self.initialize()

    def destroy(self):
        self._release()

    def digest(self):
        if not self.load(self.address, 16):
            return 0
        words = tuple(self.load(self.address, 24 + index * 8) for index in range(4))
        for node in self.nodes():
            for byte in _WideString(self.runtime, address=node + 32).value():
                a, b, c, d = words
                a, b, c, d = _sip_round((a ^ byte, b, c, d))
                words = d ^ (byte << 24), a, b, c
        a, b, c, d = words
        a, b, c, d = _sip_round((a, b, c ^ 255, d))
        a, b, c, d = _sip_round((a ^ c, b ^ d, c ^ 255, d))
        result = (a ^ b ^ c ^ d) & 0xFFFFFFFF
        for index, word in enumerate(_DEVICE_SEED):
            self.store(self.address, 24 + index * 8, word)
        return result


def _construct_at(runtime, address, raw):
    value = _WideString(runtime, address=address)
    length = len(_units(raw))
    if length <= 10:
        value.set(0, length * 2, 1, 'device_enumeration.short_tag')
        value._payload(raw, None, 'device_enumeration.short_payload')
    else:
        temporary = _WideString.construct(runtime, raw)
        temporary.write_header(address)
    return _WideString(runtime, address=address)


def _cwide(runtime, address, capacity):
    raw = bytearray()
    for index in range(capacity):
        unit = runtime.memory.read(address + index * 2, 2)
        if unit == b'\0\0':
            return bytes(raw)
        raw.extend(unit)
    raise PrimaryProgramLimit('device enumeration UTF16 string leaves its source buffer')


class DeviceEnumeration:
    def __init__(self, runtime, rbp, transcript):
        self.runtime, self.rbp = runtime, rbp
        self.transcript = transcript if isinstance(transcript, WorkerObservations) else WorkerObservations(transcript)
        self.tree = UTF16Set(runtime, rbp + 0x63F0)

    def initialize(self):
        self.tree.initialize()
        for index, word in enumerate(_DEVICE_SEED):
            self.tree.store(self.tree.address, 24 + index * 8, word)

    def clear(self):
        self.tree.clear()

    def destroy(self):
        self.tree.destroy()

    def object_collection(self, hardware):
        runtime, rbp = self.runtime, self.rbp
        memory = runtime.memory
        handle, attrs, name = rbp + 0x62D8, rbp + 0x6298, rbp + 0x62C8
        literal = runtime.image_base + 0x4905276
        if memory.read(literal, 20) != '\\GLOBAL??\0'.encode('utf-16le'):
            raise InputError('GLOBAL?? literal is not bound to the original source image')
        memory.store(handle, 0, 8, source='device_enumeration.handle')
        memory.store(name, 18, 2, source='device_enumeration.name_length')
        memory.store(name + 2, 20, 2, source='device_enumeration.name_capacity')
        memory.store(name + 8, literal, 8, source='device_enumeration.name_buffer')
        for offset, value, width in ((0, 48, 4), (8, 0, 8), (16, name, 8),
                                     (24, 0, 4), (32, 0, 8), (40, 0, 8)):
            memory.store(attrs + offset, value, width, source='device_enumeration.attributes')
        status = _call(runtime, self.transcript, 'NtOpenDirectoryObject', (handle, 1, attrs), ((handle, 8),))
        memory.store(rbp + 0x63DC, status, 4, source='device_enumeration.status')
        opened = memory.load(handle, 8)
        if status & 0x80000000 or not opened:
            return
        context = rbp + 0x6294
        memory.store(context, 0, 4, source='device_enumeration.context')
        memory.store(rbp + 0x6293, 1, 1, source='device_enumeration.restart')
        memory.store(rbp + 0x628C, 4096, 4, source='device_enumeration.capacity')
        buffer = runtime._allocate(4096, False, nullable=True)
        memory.store(rbp + 0x6280, buffer, 8, source='device_enumeration.buffer')
        if buffer:
            self.clear()
            previous = 0
            for batch in range(_LIMIT):
                memory.store(rbp + 0x6274, previous, 4, source='device_enumeration.previous_context')
                restart = memory.load(rbp + 0x6293, 1)
                status = _call(runtime, self.transcript, 'NtQueryDirectoryObject',
                               (opened, buffer, 4096, 0, restart, context, 0), ((buffer, 4096), (context, 4)))
                memory.store(rbp + 0x63DC, status, 4, source='device_enumeration.status')
                memory.store(rbp + 0x6293, 0, 1, source='device_enumeration.restart')
                if status & 0x80000000:
                    break
                current = memory.load(context, 4)
                count = (current - previous) & 0xFFFFFFFF
                if count > 128:
                    raise PrimaryProgramLimit('directory records leave the fixed 4096 byte buffer')
                for index in range(count):
                    record = buffer + index * 32
                    length = memory.load(record, 2) >> 1
                    raw = memory.read(memory.load(record + 8, 8), length * 2) if length else b''
                    memory.write(rbp + 0x6258, bytes(24), source='device_enumeration.full_empty')
                    full = _WideString(runtime, address=rbp + 0x6258)
                    full.assign(raw)
                    if raw.startswith(_PREFIXES):
                        units = _units(raw)
                        end = max((i for i, unit in enumerate(units) if unit == 35), default=len(units))
                        part = _construct_at(runtime, rbp + 0x6240, raw[:end * 2])
                        self.tree.insert_wide(part, move=True)
                        _WideString(runtime, address=rbp + 0x6240).destroy()
                    full.destroy()
                previous = current
                if status != 0x105:
                    break
            else:
                raise PrimaryProgramLimit('directory query exceeds the bounded batch count')
            if self.tree.load(self.tree.address, 16):
                memory.store(hardware + 4, self.tree.digest(), 4, source='device_enumeration.object_digest')
            runtime._free_allocation(buffer)
        _call(runtime, self.transcript, 'NtClose', (opened,))

    def display_collection(self, hardware):
        runtime, rbp = self.runtime, self.rbp
        memory = runtime.memory
        self.clear()
        primary, child = rbp + 0x5BD0, rbp + 0x5880
        memory.store(primary, 0x348, 4, source='device_enumeration.primary_size')
        for outer in range(_LIMIT):
            memory.store(rbp + 0x5BCC, outer, 4, source='device_enumeration.primary_index')
            result = _call(runtime, self.transcript, 'EnumDisplayDevicesW', (0, outer, primary, 0), ((primary, 0x348),))
            if not result:
                break
            memory.write(child, bytes(0x348), source='device_enumeration.child_zero')
            memory.store(child, 0x348, 4, source='device_enumeration.child_size')
            for inner in range(_LIMIT):
                memory.store(rbp + 0x587C, inner, 4, source='device_enumeration.child_index')
                result = _call(runtime, self.transcript, 'EnumDisplayDevicesW',
                               (primary + 4, inner, child, 0), ((child, 0x348),))
                if not result:
                    break
                flags = memory.load(child + 0x144, 4)
                if flags & 1 and not flags & 8:
                    raw = _cwide(runtime, child + 0x148, 128)
                    full = _construct_at(runtime, rbp + 0x5860, raw)
                    units = _units(raw)
                    end = next((i for i in range(9, len(units)) if units[i] == 92), len(units))
                    part = _construct_at(runtime, rbp + 0x5848, raw[:end * 2])
                    full.destroy()
                    part.write_header(rbp + 0x5860)
                    part.set(0, 0, 1, 'device_enumeration.move_reset')
                    part.set(2, 0, 2, 'device_enumeration.move_reset')
                    self.tree.insert_wide(_WideString(runtime, address=rbp + 0x5860), move=False)
                    _WideString(runtime, address=rbp + 0x5860).destroy()
                memory.write(child, bytes(0x348), source='device_enumeration.child_zero')
                memory.store(child, 0x348, 4, source='device_enumeration.child_size')
            else:
                raise PrimaryProgramLimit('display children exceed bounded enumeration')
            memory.write(primary, bytes(0x348), source='device_enumeration.primary_zero')
            memory.store(primary, 0x348, 4, source='device_enumeration.primary_size')
        else:
            raise PrimaryProgramLimit('display primaries exceed bounded enumeration')
        if self.tree.load(self.tree.address, 16):
            memory.store(hardware + 20, self.tree.digest(), 4, source='device_enumeration.display_digest')
        memory.store(hardware + 63, 1, 1, source='device_enumeration.hardware_ready')
        self.destroy()
