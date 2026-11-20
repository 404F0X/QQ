import sys
from contextlib import contextmanager
from threading import get_ident

from .errors import InputError
from .primary_device_integrity import _api, _log, _loaded, _loaded_cstring, inspect_module
from .primary_logger import _String, _cstring, feature
from .primary_notification_map import insert, insert_cstrings
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable, signed
from .primary_worker_consumer import _append, _invoke
from .primary_worker_response import _frame


_FACTORY = object()
_MASK = (1 << 64) - 1
_ENTRIES = (0x2DF7BF0, 0x2DF7630, 0x2DF8200, 0x2E01C70)
_DETECTORS = ((b'Kernel32.dll', b'CreateFileW', 255, 0, b'KCF'),
              (b'Kernel32.dll', b'FatalExit', 233, 1, b'KFE'),
              (b'ntdll.dll', b'KiUserExceptionDispatcher', 233, 1, b'NKED'),
              (b'ntdll.dll', b'LdrUnloadDll', 233, 1, b'NLULD'),
              (b'ntdll.dll', b'LdrLoadDll', 233, 1, b'NLLD'))


class _ProducerClaim:
    def __init__(self, runtime, rva, output, source, parent, factory):
        if factory is not _FACTORY:
            raise InputError('mandatory producer requires its source factory')
        self.runtime, self.rva, self.output, self.source, self.parent = runtime, rva, output, source, parent
        self.thread, self.generation, self.active = get_ident(), runtime._main_generation, True
        self.owner = getattr(getattr(runtime, '_primary_direct_scope', None), 'notification_owner', None)
        self.setting_index, self.setting_stage, self.material_used = 0, 'audit', False

    def valid(self):
        if not self.active or self.thread != get_ident() or self.generation != self.runtime._main_generation:
            return False
        frame = sys._getframe(1)
        while frame is not None and frame is not self.source:
            frame = frame.f_back
        expected = {0x2DF7BF0: initialize, 0x2DF7630: detect, 0x2DF8200: hooks_map, 0x2E01C70: material_map}
        return (frame is not None and frame.f_code is expected[self.rva].__code__ and
                frame.f_locals.get('runtime') is self.runtime and
                self.runtime.__dict__.get('_notification_mandatory_claim') is self and
                (self.owner is None or self.owner.valid()))


@contextmanager
def _producer(runtime, rva, output):
    parent = runtime.__dict__.get('_notification_mandatory_claim')
    if parent is not None and (type(parent) is not _ProducerClaim or not parent.valid() or
            parent.rva != 0x2DF8200 or rva not in (0x2DF7BF0, 0x2DF7630)):
        raise InputError('mandatory producer nesting differs from its source')
    claim = _ProducerClaim(runtime, rva, output, sys._getframe(2), parent, _FACTORY)
    scope = runtime.__dict__.get('_primary_direct_scope')
    if runtime.primary_backend == 'direct':
        from .primary_direct_scopes import PrimaryDirectScope
        from .primary_sign import PrimaryRuntime
        if type(scope) is not PrimaryDirectScope or not scope._valid_notification():
            raise PrimarySemanticUnavailable('mandatory producer requires its actual notification owner')
        if parent is None:
            frame = sys._getframe(1)
            while frame is not None and frame.f_code is not PrimaryRuntime.invoke.__code__:
                frame = frame.f_back
            if (frame is None or frame.f_locals.get('self') is not runtime or
                    frame.f_locals.get('rva') != rva):
                raise InputError('mandatory producer requires its actual routed source call')
    runtime._notification_mandatory_claim = claim
    observer = getattr(runtime, 'device_integrity_observations', None)
    entered = False
    try:
        if not claim.valid():
            raise InputError('mandatory producer lost its exact source frame')
        if callable(getattr(observer, 'begin', None)):
            observer.begin(runtime, rva, claim)
            entered = True
        yield claim
        if claim.owner is not None and rva == 0x2E01C70 and claim.source.f_locals.get('gate') == 1:
            local = claim.source.f_locals
            expected = int(local.get('qqnt_result') == 0) + int(local.get('wrapper_result') == 0)
            if local.get('logged') is not True or claim.setting_index != expected or claim.setting_stage != 'audit':
                raise PrimarySemanticUnavailable('notification producer did not finish its exact conditional settings')
    finally:
        primary, failure = sys.exception(), None
        if entered:
            try:
                observer.end(runtime, rva)
            except BaseException as error:
                failure = error
        claim.active = False
        if runtime.__dict__.get('_notification_mandatory_claim') is claim:
            if parent is None:
                runtime.__dict__.pop('_notification_mandatory_claim')
            else:
                runtime._notification_mandatory_claim = parent
        elif failure is None:
            failure = InputError('mandatory producer claim was replaced')
        claim.source = None
        if failure is not None:
            if primary is not None:
                primary.add_note('mandatory producer cleanup failed: ' + type(failure).__name__)
            else:
                raise failure


def _empty(runtime, output):
    runtime.memory.write(output, bytes(32), source='2DF7C17.empty_map')
    runtime.memory.store(output + 32, 0x3F800000, 4, source='2DF7C25.load_factor')


def _cstring_local(runtime, address, value):
    runtime.memory.write(address, value + b'\0', source='mandatory.decoded_source_literal')
    return address


def initialize(runtime, output):
    with _producer(runtime, 0x2DF7BF0, output):
        _empty(runtime, output)
        frame, _ = _frame(runtime, 0x180, '2DF7BF0.map_initializer_frame')
        memory, base = runtime.memory, runtime.image_base
        name = _cstring_local(runtime, frame, bytes(x ^ 7 ^ (i + 1) ^ 8 for i, x in enumerate(bytes.fromhex('5f5c425f246d646b'))))
        module = _api(runtime, 'GetModuleHandleA', (name,))
        value = b'1'
        if module:
            nt = module + int.from_bytes(_loaded(runtime, module + 60, 4), 'little', signed=True)
            directory = module + int.from_bytes(_loaded(runtime, nt + 136, 4), 'little')
            count = int.from_bytes(_loaded(runtime, directory + 24, 4), 'little')
            if count:
                functions = module + int.from_bytes(_loaded(runtime, directory + 28, 4), 'little')
                names = module + int.from_bytes(_loaded(runtime, directory + 32, 4), 'little')
                ordinals = module + int.from_bytes(_loaded(runtime, directory + 36, 4), 'little')
                if count > 1 << 20:
                    raise PrimaryProgramLimit('mandatory export traversal exceeds source bound')
                needles = tuple(_String.read(runtime, base + rva).value() for rva in (0x6D86630, 0x6D86648, 0x6D86660))
                for index in range(count):
                    pointer = module + int.from_bytes(_loaded(runtime, names + index * 4, 4), 'little')
                    text = _loaded_cstring(runtime, pointer)
                    if all(needle in text for needle in needles):
                        ordinal = int.from_bytes(_loaded(runtime, ordinals + index * 2, 2), 'little')
                        entry = module + int.from_bytes(_loaded(runtime, functions + ordinal * 4, 4), 'little')
                        value = b'1' if _loaded(runtime, entry, 1) == b'A' else b'0'
                        break
        headers = [frame + 32, frame + 56, frame + 80, frame + 104]
        first = _String.read(runtime, base + 0x6D86630).clone()
        first.write_to(headers[0])
        _append(first, b'-')
        _append(first, _String.read(runtime, base + 0x6D86648).value())
        first.write_to(headers[0])
        memory.copy_disjoint(headers[1], headers[0], 24, label='2DF7EAA.move_intermediate')
        memory.write(headers[0], bytes(24), source='2DF7EB9.clear_moved_intermediate')
        second = _String.read(runtime, headers[1])
        _append(second, b'-')
        second.write_to(headers[1])
        memory.copy_disjoint(headers[2], headers[1], 24, label='2DF7ED7.move_intermediate')
        memory.write(headers[1], bytes(24), source='2DF7EE6.clear_moved_intermediate')
        third = _String.read(runtime, headers[2])
        _append(third, _String.read(runtime, base + 0x6D86660).value())
        third.write_to(headers[2])
        memory.copy_disjoint(headers[3], headers[2], 24, label='2DF7F20.move_key')
        memory.write(headers[2], bytes(24), source='2DF7F2F.clear_moved_key')
        insert(runtime, output, frame + 136, headers[3], headers[3], _cstring_local(runtime, frame + 160, value))
        for header in reversed(headers):
            _String.read(runtime, header).destroy()
        memory.unmap(frame)
        return output


def detect(runtime, module_name, export_name, pattern, count, mode):
    with _producer(runtime, 0x2DF7630, 0):
        module = _api(runtime, 'GetModuleHandleA', (module_name,))
        if not module:
            _log(runtime, 0x8D, b'should load Kernel32.dll')
        function = _api(runtime, 'GetProcAddress', (module, export_name))
        remaining = signed(count, 32)
        mode &= 0xFFFFFFFF
        if remaining > 1 << 20:
            raise PrimaryProgramLimit('mandatory detector count exceeds source bound')
        for index in range(max(0, remaining)):
            if mode in (0, 1):
                equal = _loaded(runtime, (function + index) & _MASK, 1)[0] == runtime.memory.load(pattern + index, 1)
                if equal == (mode == 1):
                    return ((remaining - index) & 0xFFFFFF00) | 1
        return 0


def hooks_map(runtime, output):
    with _producer(runtime, 0x2DF8200, output):
        initialize(runtime, output)
        frame, _ = _frame(runtime, 0x100, '2DF8200.map_producer_frame')
        for module, export, byte, mode, key in _DETECTORS:
            module_name = _cstring_local(runtime, frame, module)
            export_name = _cstring_local(runtime, frame + 32, export)
            runtime.memory.store(frame + 80, byte, 1, source='2DF8200.source_pattern')
            result = detect(runtime, module_name, export_name, frame + 80, 1, mode)
            key_pointer = _cstring_local(runtime, frame + 88, key)
            value = _cstring_local(runtime, frame + 104, b'1' if result & 255 == 0 else b'0')
            insert_cstrings(runtime, output, frame + 128, key_pointer, value)
        runtime.memory.unmap(frame)
        return output


def material_map(runtime, output):
    with _producer(runtime, 0x2E01C70, output) as claim:
        _empty(runtime, output)
        from .primary_worker_loop import _ensure_logger
        from .primary_device_refresh import decimal_string
        _ensure_logger(runtime)
        gate = feature(runtime, runtime.memory.load(runtime.image_base + 0x67516A8, 8), 39)
        if gate != 1:
            _log(runtime, 0x249, b'csd closed')
            return output
        frame, _ = _frame(runtime, 0x100, '2E01C70.map_producer_frame')
        wrapper_name = _cstring_local(runtime, frame, b'wrapper.node')
        qqnt_name = _cstring_local(runtime, frame + 32, b'QQNT.dll')
        wrapper_result = inspect_module(runtime, wrapper_name) & 0xFFFFFFFF
        qqnt_result = inspect_module(runtime, qqnt_name) & 0xFFFFFFFF
        _log(runtime, 0x253, b'wrapper.node = %d', wrapper_result)
        _log(runtime, 0x254, b'QQNT.dll = %d', qqnt_result)
        logged = True
        for bit in ((19,) if qqnt_result == 0 else ()) + ((20,) if wrapper_result == 0 else ()):
            for setting_rva in (0x1BF75A0, 0x1BF8090):
                _invoke(runtime, setting_rva, 1, bit, 1, 0)
        for key, result in ((b'wrapper', wrapper_result), (b'QQNT', qqnt_result)):
            decimal_string(runtime, frame + 64, result)
            _cstring_local(runtime, frame + 96, key)
            insert_cstrings(runtime, output, frame + 128, frame + 96, frame + 64, move_value=True)
            _String.read(runtime, frame + 64).destroy()
        runtime.memory.unmap(frame)
        return output


def invoke(runtime, rva, values):
    counts = {0x2DF7BF0: 1, 0x2DF7630: 5, 0x2DF8200: 1, 0x2E01C70: 1}
    if rva not in counts or len(values) != counts[rva] or any(type(v) is not int or not 0 <= v <= _MASK for v in values):
        raise InputError('mandatory producer requires its exact pointer-width source ABI')
    return {0x2DF7BF0: initialize, 0x2DF7630: detect, 0x2DF8200: hooks_map, 0x2E01C70: material_map}[rva](runtime, *values)
