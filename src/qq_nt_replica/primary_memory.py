"""Byte-addressed current memory for the fixed primary program's pointers/cells.

Explicit addresses and initial bytes are inputs. Unmapped or uninitialized reads
are not silently replaced with zero. This is offline memory, never a native
pointer dereference or a view of a running QQ process.
"""

from dataclasses import dataclass

from .errors import CapabilityUnavailable, InputError, LibraryLimitError

_MASK64 = (1 << 64) - 1


class PrimaryMemoryLimit(LibraryLimitError):
    """An access lies outside this offline model's mapped support domain."""


class UnknownMemory(CapabilityUnavailable):
    """The program needs bytes whose producer/initial value has not been supplied."""


@dataclass
class _Region:
    address: int
    data: memoryview
    initialized: bytearray
    name: str


class PrimaryMemory:
    """Explicit mapped buffers, retaining aliases through their backing objects."""

    def __init__(self):
        self._regions = []
        self.__native_pins = {}
        self.writes = []
        self._write_extents = {}

    def _record_write(self, entry, size):
        if not self.writes:
            self._write_extents.clear()
        self.writes.append(entry)
        self._write_extents[id(entry)] = (entry, size)

    def write_extent(self, entry):
        record = self._write_extents.get(id(entry))
        return record[1] if record is not None and record[0] is entry else None

    def map(self, address: int, buffer, *, name: str, initialized: bool) -> None:
        if type(address) is not int or not 0 <= address <= _MASK64:
            raise InputError("memory address must be unsigned64")
        try:
            data = memoryview(buffer)
        except (TypeError, ValueError, BufferError) as exc:
            raise InputError("memory mapping needs a byte buffer") from exc
        if data.ndim != 1 or not data.c_contiguous or data.itemsize != 1 or data.format not in ("B", "b", "c"):
            raise InputError("memory mapping needs a 1D contiguous B/b/c buffer")
        data = data if data.format == "B" else data.cast("B")
        guard = getattr(self, '_consumed_mgf_guard', None)
        if guard is not None:
            guard.guard_mapping(address, data)
        end = address + len(data)
        if not data or end > (1 << 64):
            raise PrimaryMemoryLimit("empty/wrapped mapping is outside the Python memory support domain")
        if type(initialized) is not bool or not isinstance(name, str):
            raise InputError("mapping name and initialization status must be explicit")
        for region in self._regions:
            if address < region.address + len(region.data) and region.address < end:
                raise PrimaryMemoryLimit("overlapping virtual mappings would give one address multiple owners")
            if region.data.obj is data.obj and (not initialized or not all(region.initialized)):
                raise PrimaryMemoryLimit("multiple virtual mappings of an unknown backing need a shared initialization map")
        self._regions.append(_Region(address, data, bytearray([int(initialized)]) * len(data), name))
        self._regions.sort(key=lambda region: region.address)

    def _pin_native_span(self, address, size, issuer):
        region,offset=self._span(address,size)
        if region.data.readonly:raise PrimaryMemoryLimit('native span requires writable backing')
        token=object()
        self.__native_pins[token]=(region,offset,size,issuer,region.data)
        return token,region.data[offset:offset+size]

    def _assert_no_native_pin(self,address,size):
        region,offset=self._span(address,size)
        for pinned,start,length,issuer,backing in self.__native_pins.values():
            if pinned is region and offset<start+length and start<offset+size:
                raise PrimaryMemoryLimit('live native resource pins this allocation')

    def _validate_native_pin(self,token,issuer):
        record=self.__native_pins.get(token)
        if record is None or record[3] is not issuer:raise PrimaryMemoryLimit('unissued native write')
        region,offset,size,unused,backing=record
        actual,observed=self._span(region.address+offset,size)
        if actual is not region or observed!=offset or region.data is not backing:raise PrimaryMemoryLimit('native backing replaced')
        return record

    def _record_native_write(self,token,issuer,*,source):
        region,offset,size,unused,backing=self._validate_native_pin(token,issuer)
        region.initialized[offset:offset+size]=bytes([1])*size
        self._record_write((region.address+offset,bytes(region.data[offset:offset+size]),source),size)

    def _unpin_native_span(self,token,issuer):
        record=self.__native_pins.get(token)
        if record is None or record[3] is not issuer:raise PrimaryMemoryLimit('unissued native unpin')
        del self.__native_pins[token]

    def unmap(self, address: int) -> None:
        if type(address) is not int or not 0 <= address <= _MASK64:
            raise InputError("memory unmap address must be unsigned64")
        for index, region in enumerate(self._regions):
            if region.address == address:
                self._assert_no_native_pin(address,len(region.data))
                del self._regions[index]
                return
        raise PrimaryMemoryLimit(f"no primary memory mapping starts at 0x{address:x}")

    def _span(self, address: int, size: int):
        if type(address) is not int or type(size) is not int or size < 0:
            raise InputError("memory access address/size must be integers and size nonnegative")
        address &= _MASK64
        if address + size > (1 << 64):
            raise PrimaryMemoryLimit("wrapped memory access is outside the Python support domain")
        for region in self._regions:
            offset = address - region.address
            if 0 <= offset and offset + size <= len(region.data):
                return region, offset
        raise PrimaryMemoryLimit(f"unmapped primary memory access at 0x{address:x}, width {size}")

    def read(self, address: int, size: int) -> bytes:
        guard = getattr(self, '_consumed_mgf_guard', None)
        if guard is not None:
            guard.guard_overlap(address, size)
        region, offset = self._span(address, size)
        if not all(region.initialized[offset:offset + size]):
            raise UnknownMemory(f"primary program reads unknown bytes at 0x{address & _MASK64:x}, width {size}, region {region.name}")
        return bytes(region.data[offset:offset + size])

    def write(self, address: int, data: bytes, *, source: str) -> None:
        if not isinstance(data, bytes) or not isinstance(source, str):
            raise InputError("memory writes need explicit bytes and a source label")
        guard = getattr(self, '_consumed_mgf_guard', None)
        if guard is not None:
            guard.guard_overlap(address, len(data))
        region, offset = self._span(address, len(data))
        if region.data.readonly:
            raise PrimaryMemoryLimit(f"write to readonly primary memory region {region.name}")
        region.data[offset:offset + len(data)] = data
        region.initialized[offset:offset + len(data)] = b"\x01" * len(data)
        self._record_write((address & _MASK64, data, source), len(data))

    def load(self, address: int, width: int, *, signed: bool = False) -> int:
        if width not in (1, 2, 4, 8):
            raise InputError("primary scalar load width must be 1/2/4/8")
        return int.from_bytes(self.read(address, width), "little", signed=signed)

    def copy_disjoint(self, destination: int, source: int, size: int, *, label: str) -> None:
        if not isinstance(label, str):
            raise InputError("memory copy requires a source label")
        guard = getattr(self, '_consumed_mgf_guard', None)
        if guard is not None:
            guard.guard_overlap(source, size)
            guard.guard_overlap(destination, size)
        target, target_offset = self._span(destination, size)
        origin, origin_offset = self._span(source, size)
        if size and (destination & _MASK64) < (source & _MASK64) + size and (source & _MASK64) < (destination & _MASK64) + size:
            raise PrimaryMemoryLimit("memory copy requires disjoint virtual ranges")
        if target.data.readonly:
            raise PrimaryMemoryLimit(f"copy to readonly primary memory region {target.name}")
        if size and target is not origin and target.data.obj is origin.data.obj:
            raise PrimaryMemoryLimit("copy between shared backing mappings requires a proved native alias order")
        data = bytes(origin.data[origin_offset:origin_offset + size])
        known = origin.initialized[origin_offset:origin_offset + size]
        if not all(known) and sum(other.data.obj is target.data.obj for other in self._regions) > 1:
            raise PrimaryMemoryLimit("unknown copies on virtual aliases need a shared initialization map")
        target.data[target_offset:target_offset + size] = data
        target.initialized[target_offset:target_offset + size] = known
        self._record_write((destination & _MASK64, data if all(known) else None, label), size)

    def forget(self, address: int, size: int, *, source: str) -> None:
        """A native write occurred but its bytes/address are not yet known."""
        guard = getattr(self, '_consumed_mgf_guard', None)
        if guard is not None:
            guard.guard_overlap(address, size)
        region, offset = self._span(address, size)
        if sum(other.data.obj is region.data.obj for other in self._regions) > 1:
            raise PrimaryMemoryLimit("unknown writes on virtual aliases need a shared initialization map")
        if region.data.readonly:
            raise PrimaryMemoryLimit(f"unknown write to readonly region {region.name}")
        self._assert_no_native_pin(address,size)
        region.initialized[offset:offset + size] = bytes(size)
        self._record_write((address & _MASK64, None, source), size)

    def store(self, address: int, value: int, width: int, *, source: str) -> None:
        if width not in (1, 2, 4, 8) or type(value) is not int:
            raise InputError("primary scalar store needs an integer and width 1/2/4/8")
        self.write(address, (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little"), source=source)

    def initialize_cells(self, address: int, count: int) -> None:
        """Native normal ctor writes first16B and byte+10h, not padding+11..17h."""
        if type(count) is not int or not 0 <= count <= 0x10000:
            raise PrimaryMemoryLimit("cell count exceeds the normal reader's supported constructor domain")
        for index in range(count):
            start = (address + 24 * index) & _MASK64
            self.write(start, bytes(16), source="cell_ctor.zero16")
            self.store(start + 16, 0, 1, source="cell_ctor.clear_owned")


class PrimaryCells:
    """The actual ctx+A8 backing: 24-byte cells and width-preserving writes."""

    def __init__(self, memory: PrimaryMemory, address: int, count: int):
        if type(count) is not int or count < 1:
            raise InputError("cell count must be positive")
        self.memory, self.address, self.count = memory, address, count

    def pointer(self, index: int) -> int:
        if type(index) is not int or not 0 <= index < self.count:
            raise PrimaryMemoryLimit(f"cell index {index} outside mapped primary cells")
        return (self.address + 24 * index) & _MASK64

    def value(self, index: int) -> int:
        return self.memory.load(self.pointer(index), 8)

    def set_value(self, index: int, value: int, *, width: int, source: str) -> None:
        self.memory.store(self.pointer(index), value, width, source=source)

    def copy_q_clear_owned(self, source_index: int, destination_index: int) -> None:
        value = self.value(source_index)
        destination = self.pointer(destination_index)
        self.memory.store(destination, value, 8, source="L24.copy_q")
        self.memory.store(destination + 16, 0, 1, source="L24.clear_owned")
