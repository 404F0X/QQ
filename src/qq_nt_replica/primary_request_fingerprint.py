"""Source fingerprint normal-return mathematics on the current request runtime.

This is not physical Native ABI, read-validity, fault or unwind certification.
The first predicate uses current owned category/config trees; no QQ snapshot is
consulted. The retained programs run the existing scalar VM, not a new runtime.
"""
import hashlib
from pathlib import Path

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable, PrimaryProgramLimit
from .primary_request_encoder import _bytes, _aes_block, _image
from .primary_worker_consumer import _invoke, _zero_string
from .primary_worker_response import _frame
from .primary_logger import _String, feature, construct

_DATA = Path(__file__).with_name('data') / 'primary_sign_qq52230'
PARENT_HOSTS = (0x41B1CA0, 0x1D2C9BA, 0x3E97020, 0x3EB2680,
                0x3EB1FE0, 0x1D2CA42, 0x618CB00, 0x1D2C690,
                0x3EB1EE0, 0x3E94F90)
NESTED_HOSTS = (0x1D2AB3E, 0x41AFCA0)
ASSETS = ((0x41B1CA0, 'request-fingerprint-vm-key.bin', 16,
           'c045eedf69d256794ea4b4ea0cc0a6da07d51267579b50e0d71bbf80c66bc638'),
          (0x41AFCA0, 'request-fingerprint-nested-table.bin', 8192,
           'aa033bd1ed00c2486e9e5e5502f791f6322025cc99d0d589c2bbb4a6afd8b00f'),
          (0x414BCA0, 'request-fingerprint-host-tables.bin', 0x64000,
           '09dfc50c5c610b7f660fbb953fdf628679c9e43904114cd6d7b7beefb7f12bb3'))


def install_image(memory, image_base):
    for rva, name, size, digest in ASSETS:
        raw = (_DATA / name).read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise InputError('fixed fingerprint asset identity mismatch: ' + name)
        memory.map(image_base + rva, bytearray(raw), name='fixed Source fingerprint ' + name,
                   initialized=True)
    # Both addresses lie beyond .data SizeOfRawData (PE virtual zero-fill).
    for rva, size in ((0x677C210, 8), (0x677E1B0, 1)):
        memory.map(image_base + rva, bytearray(size), name='Source fingerprint PE zero fill', initialized=True)


def _first_predicate(runtime):
    memory, base = runtime.memory, runtime.image_base
    root = base + 0x677C210
    node, candidate = memory.load(root, 8), root
    for _ in range(4096):
        if not node:
            break
        key = memory.load(node + 32, 4, signed=True)
        if key >= 0:
            candidate = node
        node = memory.load(node + (8 if key < 0 else 0), 8)
    else:
        raise PrimaryProgramLimit('fingerprint category lookup exceeds bounded traversal')
    if candidate == root or memory.load(candidate + 32, 4, signed=True) > 0:
        return False
    pointer = memory.load(base + 0x67516A8, 8)
    if not pointer:
        pointer = _invoke(runtime, 0xB75000, 120)
        construct(runtime, pointer)
        memory.store(base + 0x67516A8, pointer, 8, source='1BF8235.logger_publish')
    return feature(runtime, pointer, memory.load(candidate + 36, 4)) == 1


def source_request_fingerprint(runtime, digest32, nonce16):
    _bytes(digest32, 32, 'Source fingerprint digest')
    _bytes(nonce16, 16, 'Source fingerprint nonce')
    # Registration precedes provider selection, as 1BF74E0 -> 1BF6670.
    runtime.register_sdk_callbacks()
    first = _first_predicate(runtime)
    latch = runtime.image_base + 0x677E1B0
    if first and runtime.memory.load(latch, 1) == 0:
        from .primary_sdk import NativeByteReturn
        target = runtime.memory.load(runtime.image_base + 0x677DF98, 8)
        if not target:
            raise PrimarySemanticUnavailable('fingerprint Boolean callback is absent')
        result = _invoke(runtime, target - runtime.image_base)
        if type(result) is not NativeByteReturn:
            raise PrimarySemanticUnavailable('fingerprint Boolean return is not the Source byte return')
        runtime.memory.store(latch, result.value & 255, 1, source='1D2CD40.provider_latch')
        if not result.value & 255:
            # This bounded production contract admits the actual Source B8E60
            # callback only; arbitrary replacement callbacks are not supported.
            raise PrimarySemanticUnavailable('fingerprint callback outside length-preserving provider domain')
    frame, _ = _frame(runtime, 144, 'Source fingerprint request locals')
    memory = runtime.memory
    memory.write(frame, nonce16, source='fingerprint.borrowed_nonce')
    memory.write(frame + 16, digest32, source='fingerprint.borrowed_digest')
    output = _zero_string(runtime)
    output.write_to(frame + 80)
    source = _String.construct(runtime, digest32)
    source.write_to(frame + 48)
    try:
        target = memory.load(runtime.image_base + 0x677DF80, 8)
        if not target:
            raise PrimarySemanticUnavailable('fingerprint String callback is absent')
        _invoke(runtime, target - runtime.image_base, frame + 48, frame + 80)
        source.destroy()
        source = None
        produced = _String.read(runtime, frame + 80)
        provider_output_length = len(produced.value())
        if provider_output_length != 32:
            raise PrimarySemanticUnavailable('fingerprint provider is not the Source length32 producer')
        runtime.execute('request-fingerprint', (frame, provider_output_length, frame + 16, 32, frame + 104), PARENT_HOSTS)
        return nonce16 + memory.read(frame + 104, 32)
    finally:
        if source is not None:
            source.destroy()
        _String.read(runtime, frame + 80).destroy()


def invoke_host(runtime, vm, rva, cells):
    values = tuple(vm.cells.value(index) for index in cells)
    memory = runtime.memory
    if rva == 0x1D2AB3E:
        from .primary_request_fingerprint_math import apply_block_math
        apply_block_math(runtime, values[0])
    elif rva == 0x1D2C690:
        runtime.execute('request-fingerprint-nested', values, NESTED_HOSTS)
    elif rva == 0x1D2C9BA:
        source, size, destination, key, nonce = values
        if size > 0xFFFFFFFF:
            raise PrimaryProgramLimit('fingerprint CTR length outside Source DWORD domain')
        raw_key = memory.read(key, 16)
        counter = int.from_bytes(memory.read(nonce, 16), 'big')
        memory.copy_disjoint(destination, source, size, label='1D2CA0F.input_copy')
        box = bytes.fromhex(_image()['aes_sbox_hex'])
        for offset in range(0, size, 16):
            stream = _aes_block(((counter + offset // 16) & ((1 << 128) - 1)).to_bytes(16, 'big'), raw_key, box)
            raw = memory.read(destination + offset, min(16, size - offset))
            memory.write(destination + offset, bytes(a ^ b for a, b in zip(raw, stream)), source='1D2AA0F.CTR')
    elif rva == 0x1D2CA42:
        pointer, size, table, mask = values
        if size > 0x7FFFFFFF or mask not in (0xF0, 0x0F):
            raise PrimarySemanticUnavailable('fingerprint nibble transform outside finite Source domain')
        shift = ((((mask * 8) & 255) + 0x88) & 255) >> 1
        for index in range(size):
            value = memory.load(pointer + index, 1)
            low = (memory.load(table + (((2 * index + 1) & 31) * 16) + (value & 15), 1) & mask) >> (shift & 31)
            high = (memory.load(table + (((2 * index) & 31) * 16) + (value >> 4), 1) & mask) >> (shift & 31)
            memory.store(pointer + index, ((high << 4) | low) & 255, 1, source='1D2CB2A.nibble_transform')
    elif rva == 0x3EB1EE0:
        left, right, size = values
        a, b = memory.read(left, size), memory.read(right, size)
        return (a > b) - (a < b)
    return None


def execute_program(scope, name, vm):
    from .primary_sign import _PROGRAMS, PrimaryRuntime
    from .primary_direct_scopes import _source_locals
    runtime = scope.runtime
    call = _source_locals(source_request_fingerprint.__code__, runtime)
    if (call is None or not scope._valid_public() or
            hashlib.sha256(vm.program.raw).hexdigest() != _PROGRAMS[name]):
        raise PrimarySemanticUnavailable('fingerprint reader lacks its genuine public Source operation')
    if name == 'request-fingerprint':
        expected = (call['frame'], 32, call['frame'] + 16, 32, call['frame'] + 104)
        if runtime._program_calls[-1]['arguments'] != expected:
            raise PrimarySemanticUnavailable('fingerprint reader arguments differ from Source facade')
    else:
        host = _source_locals(PrimaryRuntime.invoke.__code__, runtime, rva=0x1D2C690)
        if (host is None or host.get('vm') is not runtime.vms[-2] or
                runtime._program_calls[-1]['arguments'] !=
                tuple(host['vm'].cells.value(index) for index in host['cells']) or
                runtime._program_calls[-2]['name'] != 'request-fingerprint'):
            raise PrimarySemanticUnavailable('nested fingerprint reader lacks its actual parent host call')
    return vm.run(max_steps=1_000_000)
