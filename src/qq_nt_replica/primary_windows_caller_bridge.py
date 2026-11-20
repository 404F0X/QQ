import ctypes
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable


@dataclass(frozen=True)
class CallerUnwindStep:
    before: bytes
    pc: int
    entry: int
    image_base: int | None
    after: bytes | None
    unwind_result: int | None
    error: str | None = None


@dataclass(frozen=True)
class CallerStackSnapshot:
    sequence: int
    process_id: int
    thread_id: int
    capture_address: int | None
    frames: tuple[int, ...]
    context: bytes
    steps: tuple[CallerUnwindStep, ...]
    provenance: dict


WIRE_SIZE = 8904
CONTEXT_SIZE = 1232
STEP_SIZE = 2528


def _parse_wire(raw, requested, identity):
    if not isinstance(raw, bytes) or len(raw) != WIRE_SIZE:
        raise PrimarySemanticUnavailable('caller bridge invalid wire size')
    abi, size, status, error, pid, tid, count, frames_count = struct.unpack_from('<8I', raw)
    if abi != 1 or size != WIRE_SIZE:
        raise PrimarySemanticUnavailable('caller bridge ABI mismatch')
    if status:
        raise PrimarySemanticUnavailable(f'caller bridge status={status} win32_error={error}')
    if count > 3 or frames_count > 2 or not pid or not tid:
        raise PrimarySemanticUnavailable('caller bridge invalid counts or owner')
    sequence, export, site, low, high = struct.unpack_from('<5Q', raw, 32)
    if not sequence or not site or low >= high:
        raise PrimarySemanticUnavailable('caller bridge invalid capture boundary')
    if requested is not None and (not export or requested != export):
        raise PrimarySemanticUnavailable('caller bridge capture export mismatch')
    if requested is None and frames_count:
        raise PrimarySemanticUnavailable('caller bridge unsolicited backtrace')
    context = raw[88:1320]
    before_expected = context
    steps = []
    terminal = False
    for index in range(3):
        offset = 1320 + index * STEP_SIZE
        state, exception, reserved0, reserved1 = struct.unpack_from('<4I', raw, offset)
        if index >= count:
            if any(raw[offset:offset + STEP_SIZE]):
                raise PrimarySemanticUnavailable('caller bridge nonempty unused step')
            continue
        if terminal or state not in (1, 2, 3) or reserved0 or reserved1:
            raise PrimarySemanticUnavailable('caller bridge invalid step status')
        pc, entry, image, result, handler, establisher = struct.unpack_from('<6Q', raw, offset + 16)
        before = raw[offset + 64:offset + 1296]
        after = raw[offset + 1296:offset + STEP_SIZE]
        if before != before_expected or pc != struct.unpack_from('<Q', before, 248)[0]:
            raise PrimarySemanticUnavailable('caller bridge context chain mismatch')
        if state == 1:
            if entry or image or result or handler or establisher or exception or any(after):
                raise PrimarySemanticUnavailable('caller bridge invalid null lookup')
            step = CallerUnwindStep(before, pc, 0, None, None, None)
            terminal = True
        elif state == 3:
            if not exception or result or handler or establisher or any(after):
                raise PrimarySemanticUnavailable('caller bridge invalid exception record')
            step = CallerUnwindStep(before, pc, entry, image if entry else None, None, None,
                                    f'caller bridge collection exception=0x{exception:08x}')
            terminal = True
        else:
            if not entry or exception:
                raise PrimarySemanticUnavailable('caller bridge invalid completed unwind')
            step = CallerUnwindStep(before, pc, entry, image, after, result)
            before_expected = after
        steps.append(step)
    provenance = dict(identity, abi_version=abi, process_id=pid, thread_id=tid,
                      sequence=sequence, native_capture_site=site,
                      requested_capture_address=requested,
                      capture_boundary='self-written helper / Python FFI',
                      context_preimage='zeroed own helper buffer')
    return CallerStackSnapshot(sequence, pid, tid, requested,
                               struct.unpack_from('<2Q', raw, 72)[:frames_count],
                               context, tuple(steps), provenance)


class WindowsCallerBridge:
    def __init__(self, dll_path):
        self._closed = True
        self._busy = False
        path = Path(dll_path)
        if not path.is_absolute() or not path.is_file():
            raise PrimarySemanticUnavailable('caller bridge requires an existing absolute DLL path')
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise PrimarySemanticUnavailable('caller bridge requires Windows AMD64')
        try:
            manifest = json.loads(Path(str(path) + '.manifest.json').read_text(encoding='utf-8'))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            native = Path(__file__).parent / 'native'
            source = hashlib.sha256((native / 'primary_caller_bridge.c').read_bytes() +
                                    (native / 'primary_caller_bridge.h').read_bytes()).hexdigest()
            if (manifest['abi_version'] != 1 or manifest['architecture'] != 'AMD64' or
                    manifest['dll_sha256'] != digest or manifest['source_identity'] != source or
                    Path(manifest['output_dll']).resolve() != path.resolve()):
                raise ValueError('build identity mismatch')
            self._identity = {'build_identity': digest, 'source_identity': source}
            self._dll = ctypes.WinDLL(str(path.resolve()), use_last_error=True)
            self._capture = self._dll.pcbridge_capture_v1
            self._capture.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
            self._capture.restype = ctypes.c_uint32
            self._kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            self._kernel.GetCurrentThreadId.argtypes = []
            self._kernel.GetCurrentThreadId.restype = ctypes.c_uint32
            self._kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            self._kernel.FreeLibrary.restype = ctypes.c_int
            self._pid = os.getpid()
            self._tid = self._kernel.GetCurrentThreadId()
            self._closed = False
        except (OSError, ValueError, KeyError, AttributeError) as exc:
            if hasattr(self, '_dll'):
                import _ctypes
                _ctypes.FreeLibrary(self._dll._handle)
                self._dll = None
            raise PrimarySemanticUnavailable(f'caller bridge load verification failed: {exc}') from exc

    def _check_owner(self):
        if self._closed or self.__dict__.get('_capture') is None:
            raise InputError('caller bridge is closed')
        if os.getpid() != self._pid or self._kernel.GetCurrentThreadId() != self._tid:
            raise InputError('caller bridge process/thread owner mismatch')
        if self._busy:
            raise InputError('caller bridge capture is already in flight')

    def capture(self, capture_address=None):
        self._check_owner()
        if capture_address is not None and (type(capture_address) is not int or
                                             not 0 < capture_address < 1 << 64):
            raise InputError('capture address must be unsigned64 or None')
        self._busy = True
        try:
            if self._closed or self.__dict__.get('_capture') is None:
                raise InputError('caller bridge is closed')
            output = ctypes.create_string_buffer(WIRE_SIZE)
            result = self._capture(int(capture_address is not None), output, WIRE_SIZE)
            if result != struct.unpack_from('<I', output.raw, 8)[0]:
                raise PrimarySemanticUnavailable('caller bridge return/header status mismatch')
            snapshot = _parse_wire(output.raw, capture_address, self._identity)
            if snapshot.process_id != self._pid or snapshot.thread_id != self._tid:
                raise PrimarySemanticUnavailable('caller bridge native owner mismatch')
            return snapshot
        finally:
            self._busy = False

    def close(self):
        if self._closed or self.__dict__.get('_capture') is None:
            return
        self._check_owner()
        self._close_status = 'unload_unknown'
        if self.__dict__.pop('_capture', None) is None:
            return
        self._closed = True
        self._capture = None
        if not self._kernel.FreeLibrary(self._dll._handle):
            self._close_status = 'unload_failed'
            raise PrimarySemanticUnavailable('caller bridge FreeLibrary failed; bridge remains closed')
        self._dll = None
        self._close_status = 'unloaded'
