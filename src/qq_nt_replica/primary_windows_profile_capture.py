import ctypes as C
import hashlib
import os
from pathlib import Path
import sys
import threading

from .errors import InputError
from .primary_provider_init import ProviderInitializationMetadata
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows_signer import open_windows_signer


WRAPPER = Path('D:/QQ/versions/9.9.33-52230/resources/app/wrapper.node')
WRAPPER_SHA = '63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'
_SOURCE_GUARDS = {'wrapper_sha256': '63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0', 'arch': 'x64', 'config_rva': 108336816, 'lock_rva': 108337104, 'ready_pointer_rva': 108337192, 'guards': [{'rva': 12190320, 'hex': '55415741565657534881ec5803000048'}, {'rva': 7712592, 'hex': '4883ec28e847c8020085c075054883c4'}, {'rva': 7712704, 'hex': '554883ec30488d6c243048c745f8feff'}, {'rva': 7894944, 'hex': '4883ec28ff151684180431c04883c428c3'}, {'rva': 7895008, 'hex': '4883ec28ff15ae8a180431c04883c428c3'}]}


class ProfileCaptureBoundary(PrimarySemanticUnavailable):
    pass


class Module(C.Structure):
    _fields_ = [('size', C.c_uint32), ('module_id', C.c_uint32), ('pid', C.c_uint32),
                ('global_usage', C.c_uint32), ('process_usage', C.c_uint32), ('base', C.c_void_p),
                ('image_size', C.c_uint32), ('module', C.c_void_p), ('name', C.c_wchar * 256),
                ('path', C.c_wchar * 260)]


def digest(value):
    return {'length': len(value), 'sha256': hashlib.sha256(value).hexdigest()}


def string_layout(header, address):
    if len(header) != 24:
        raise ProfileCaptureBoundary('String_header_size')
    if header[0] & 1:
        capacity = int.from_bytes(header[:8], 'little') & ~1
        length = int.from_bytes(header[8:16], 'little')
        pointer = int.from_bytes(header[16:24], 'little')
        if not capacity or length >= capacity or not pointer:
            raise ProfileCaptureBoundary('String_long_layout')
    else:
        length, pointer = header[0] >> 1, address + 1
        if length > 22:
            raise ProfileCaptureBoundary('String_short_layout')
    if length + 1 > 4096:
        raise ProfileCaptureBoundary('String_data_budget')
    return pointer, length


def metadata_from_values(values):
    uin = values['UIN']
    if not uin or any(value < 48 or value > 57 for value in uin):
        raise ProfileCaptureBoundary('UIN_not_unsigned_decimal')
    significant = uin.lstrip(b'0') or b'0'
    if len(significant) > 20 or len(significant) == 20 and significant > b'18446744073709551615':
        raise ProfileCaptureBoundary('UIN_outside_uint64')
    numeric_uin = int(significant)
    cstr = lambda value: value.split(b'\0', 1)[0]
    metadata = ProviderInitializationMetadata(cstr(values['Qimei']), cstr(values['QUA']), uin, cstr(values['machineId']))
    return metadata, numeric_uin


def read_profile_metadata(read, base, report=None):
    report = {} if report is None else report
    report['stage'] = 'mapped_code_guards'
    source_guards = _SOURCE_GUARDS
    def code_guards():
        for item in source_guards['guards']:
            expected = bytes.fromhex(item['hex'])
            if read(base + item['rva'], len(expected)) != expected:
                raise ProfileCaptureBoundary('mapped_code_guard')
    code_guards()
    report['stage'] = 'ready_SRW_pre'
    lock = read(base + 0x67517D0, 8)
    if any(lock):
        raise ProfileCaptureBoundary('SRW_not_zero_pre')
    pointer = read(base + 0x6751828, 8)
    address = int.from_bytes(pointer, 'little')
    if not address:
        raise ProfileCaptureBoundary('ready_pointer_null')
    ready = read(address + 1, 1)
    if not ready[0]:
        raise ProfileCaptureBoundary('not_ready')
    report['stage'] = 'four_fields_first'
    layout = [('QUA', 0x40), ('Qimei', 0x58), ('machineId', 0x70), ('UIN', 0x108)]
    captured = []
    for name, offset in layout:
        obj = base + 0x67516B0 + offset
        header = read(obj, 24)
        data_address, length = string_layout(header, obj)
        data = read(data_address, length + 1)
        if data[-1] != 0:
            raise ProfileCaptureBoundary('String_terminator')
        captured.append((name, obj, header, data_address, data))
    report['stage'] = 'four_fields_second'
    for name, obj, header, data_address, data in captured:
        if read(obj, 24) != header or read(data_address, len(data)) != data:
            raise ProfileCaptureBoundary('String_observation_changed')
    report['stage'] = 'ready_SRW_post'
    if read(address + 1, 1) != ready or read(base + 0x6751828, 8) != pointer:
        raise ProfileCaptureBoundary('ready_observation_changed')
    if read(base + 0x67517D0, 8) != lock:
        raise ProfileCaptureBoundary('SRW_not_zero_post')
    code_guards()
    report['stage'] = 'RAM_metadata_consumer'
    values = {name: data[:-1] for name, obj, header, data_address, data in captured}
    metadata, numeric_uin = metadata_from_values(values)
    report['fields'] = {name: digest(value) for name, value in values.items()}
    report['metadata'] = {name: digest(getattr(metadata, name)) for name in ('field_08', 'field_10', 'field_18', 'field_20')}
    report['UIN_uint64_valid'] = 0 <= numeric_uin < 1 << 64
    report['UIN_canonical_decimal'] = str(numeric_uin).encode('ascii') == values['UIN']
    report['status'] = 'optimistic_four_metadata_observed'
    report['consistency'] = 'two_equal_observations_ready_equal_SRW_zero_endpoints_not_atomic'
    report['bound_to_signcall'] = False
    report['provider_started'] = False
    report['sign_calls'] = 0
    return metadata, report


def _select_process(api, owned, report, *, selection='newest'):
    if not isinstance(selection, str) or selection not in ('newest', 'oldest'):
        raise InputError('main profile selection requires newest or oldest')
    import psutil

    signatures = {
        'CreateToolhelp32Snapshot': (C.c_void_p, [C.c_uint32, C.c_uint32]),
        'Module32FirstW': (C.c_int32, [C.c_void_p, C.POINTER(Module)]),
        'Module32NextW': (C.c_int32, [C.c_void_p, C.POINTER(Module)]),
        'OpenProcess': (C.c_void_p, [C.c_uint32, C.c_int32, C.c_uint32]),
        'GetProcessTimes': (C.c_int32, [C.c_void_p, C.POINTER(C.c_uint64), C.POINTER(C.c_uint64), C.POINTER(C.c_uint64), C.POINTER(C.c_uint64)]),
        'CloseHandle': (C.c_int32, [C.c_void_p]),
        'ReadProcessMemory': (C.c_int32, [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)])}
    for name, (result, args) in signatures.items():
        getattr(api, name).restype, getattr(api, name).argtypes = result, args

    def close(handle):
        if not api.CloseHandle(handle):
            raise ProfileCaptureBoundary('CloseHandle')
        owned.remove(handle)

    report['stage'] = 'metadata'
    candidates = [p for p in psutil.process_iter(['pid', 'name']) if (p.info['name'] or '').lower() == 'qq.exe']
    report['QQ_candidates'] = len(candidates)
    if len(candidates) > 64:
        raise ProfileCaptureBoundary('candidate_limit')
    eligible = []
    main_candidates = []
    main_count = 0
    for process in candidates:
        args = process.cmdline()
        if any(arg == '--type' or arg.startswith('--type=') for arg in args):
            continue
        main_count += 1
        report['main_candidates'] = main_count
        if main_count > 8:
            raise ProfileCaptureBoundary('main_candidate_limit')
        created = process.create_time()
        main_candidates.append((created, process.pid, process))
    if selection == 'oldest' and main_candidates:
        main_candidates = [min(main_candidates, key=lambda candidate: candidate[:2])]
    for created, _, process in main_candidates:
        if Path(process.exe()).name.lower() != 'qq.exe':
            raise ProfileCaptureBoundary('process_metadata_race')
        snapshot = api.CreateToolhelp32Snapshot(0x18, process.pid)
        if snapshot in (None, C.c_void_p(-1).value):
            raise ProfileCaptureBoundary('module_snapshot')
        owned.add(snapshot)
        entry, count = Module(), 0
        entry.size = C.sizeof(Module)
        success = api.Module32FirstW(snapshot, C.byref(entry))
        if not success:
            raise ProfileCaptureBoundary('module_first')
        found = []
        while success:
            count += 1
            report['module_entries'] += 1
            if count > 512:
                raise ProfileCaptureBoundary('module_limit')
            if entry.name.lower() == 'wrapper.node':
                if Path(entry.path).resolve() != WRAPPER.resolve() or entry.image_size != 0x7419000:
                    raise ProfileCaptureBoundary('module_version')
                found.append((int(entry.base), entry.image_size))
            success = api.Module32NextW(snapshot, C.byref(entry))
        if C.get_last_error() != 18:
            raise ProfileCaptureBoundary('module_next')
        close(snapshot)
        if len(found) > 1:
            raise ProfileCaptureBoundary('duplicate_module')
        if found:
            eligible.append((created, process.pid, found[0]))
    if not eligible or hashlib.sha256(WRAPPER.read_bytes()).hexdigest() != WRAPPER_SHA:
        raise ProfileCaptureBoundary('fixed_module_missing')
    created, pid, (base, image_size) = max(eligible)
    process = psutil.Process(pid)
    if process.create_time() != created:
        raise ProfileCaptureBoundary('PID_race')
    handle = api.OpenProcess(0x1010, False, pid)
    if not handle:
        raise ProfileCaptureBoundary('OpenProcess')
    owned.add(handle)
    times = [C.c_uint64() for _ in range(4)]
    if not api.GetProcessTimes(handle, *(C.byref(value) for value in times)) or abs(times[0].value / 10000000 - 11644473600 - created) > 0.00001:
        raise ProfileCaptureBoundary('handle_creation_race')
    report['module'] = {'sha256': WRAPPER_SHA, 'ASLR_base': base, 'SizeOfImage': image_size}
    target_identity = {'pid': pid, 'creation_filetime_100ns': times[0].value, 'selection': selection}
    return handle, base, target_identity



class CapturedMainProfile:
    def __init__(self, metadata, summary):
        if not isinstance(metadata, ProviderInitializationMetadata):
            raise InputError('capture requires typed main metadata')
        self._metadata = metadata
        self.summary = summary
        self._target_identity = dict(summary['target_identity']) if 'target_identity' in summary else None
        self._identity = os.getpid(), threading.get_native_id()
        self._used = False

    @property
    def target_identity(self):
        return None if self._target_identity is None else dict(self._target_identity)

    def __repr__(self):
        return '<CapturedMainProfile raw fields retained only in RAM>'

    def consume(self, *, bridge_path, storage_root, command, payload, initial_stack=None,
                private_context_tail=None, worker_bridge_path=None):
        if self._used or self._identity != (os.getpid(), threading.get_native_id()):
            raise InputError('captured metadata requires its single owning process/thread consumption')
        if not isinstance(command, bytes) or b'\0' in command or not isinstance(payload, bytes):
            raise InputError('explicit command and payload bytes required')
        if initial_stack is not None and (not isinstance(initial_stack, bytes) or len(initial_stack) != 16):
            raise InputError('private temporary preimage requires exactly sixteen explicit bytes or unknown')
        if private_context_tail is not None and (not isinstance(private_context_tail, bytes) or len(private_context_tail) != 4):
            raise InputError('provider private tail requires exactly four explicit bytes or unknown')
        self._used = True
        owner = None
        try:
            owner = open_windows_signer(bridge_path=bridge_path, storage_root=storage_root,
                                        host_profile_string=self._metadata.field_10, initial_stack=initial_stack,
                                        worker_bridge_path=worker_bridge_path)
            with owner:
                owner.initialize_provider(self._metadata, private_context_tail=private_context_tail)
                result = owner.sign_result(command, payload)
                if owner.diagnostics['factory_cache_length'] == 0:
                    raise ProfileCaptureBoundary('sign completed without complete device provider consumption')
            return result, owner.diagnostics
        except BaseException as error:
            if owner is not None:
                error.profile_capture_signer_diagnostics = owner.diagnostics
            raise
        finally:
            self._metadata = None


def capture_main_profile(*, selection='newest'):
    if not isinstance(selection, str) or selection not in ('newest', 'oldest'):
        raise InputError('main profile selection requires newest or oldest')
    if sys.platform != 'win32' or C.sizeof(C.c_void_p) != 8 or C.sizeof(Module) != 1080:
        raise ProfileCaptureBoundary('Windows AMD64 main profile capture required')
    api = C.WinDLL('kernel32', use_last_error=True)
    owned = set()
    report = {'memory_calls': 0, 'memory_bytes': 0, 'module_entries': 0}
    try:
        handle, base, target_identity = _select_process(api, owned, report, selection=selection)
        def read(address, length):
            if not 0 < length <= 4096 or not 0x10000 <= address < (1 << 47) or address + length >= 1 << 47:
                raise ProfileCaptureBoundary('read_domain')
            if report['memory_calls'] >= 32 or report['memory_bytes'] + length > 33158:
                raise ProfileCaptureBoundary('read_budget')
            data, count = C.create_string_buffer(length), C.c_size_t()
            report['memory_calls'] += 1
            report['memory_bytes'] += length
            if not api.ReadProcessMemory(handle, address, data, length, C.byref(count)) or count.value != length:
                raise ProfileCaptureBoundary('ReadProcessMemory')
            return data.raw
        metadata, fields = read_profile_metadata(read, base, report)
        report.update(fields)
        report['target_identity'] = dict(target_identity)
        return CapturedMainProfile(metadata, report)
    except BaseException as error:
        error.profile_capture_summary = report
        raise
    finally:
        for handle in tuple(owned):
            if api.CloseHandle(handle):
                owned.remove(handle)
        report['owned_handles'] = len(owned)
        if owned:
            raise ProfileCaptureBoundary('main capture retains owned process/module handles')
