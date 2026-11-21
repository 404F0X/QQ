import re
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from filetime_replay import FiletimeReplay, FILETIME_CODES
from cursor_replay import CursorReplay, CURSOR_CODES
from resolver_replay import ResolverReplay, RESOLVER_CODES
from qq_nt_replica.primary_consumed_mgf import SOURCE_SHA256, SourceIdentity

MAX_INPUT_BYTES = 1 << 20

INPUT_FIELDS = (('a', 1, 2), ('b', 3, 4), ('command', 5, 6), ('d', 10, 11))

class AdapterError(ValueError):
    pass

def require(ok, code):
    if not ok:
        raise AdapterError(code)

def u64(value):
    require(type(value) is int and 0 <= value < 1 << 64, 'INVALID_U64')
    return value

def pointer(value, *, zero=False):
    require(type(value) is str and re.fullmatch('0x[0-9a-fA-F]{1,16}', value) is not None, 'INVALID_POINTER')
    result = int(value, 16)
    require(zero or result != 0, 'NULL_POINTER')
    return result

def arguments_from_wire(values):
    require(type(values) is list and len(values) == 12, 'ARGUMENT_SHAPE')
    return validate_arguments(tuple((pointer(value, zero=True) if i in (1, 3, 5, 7, 8, 10) else value for i, value in enumerate(values))))

def validate_arguments(arguments):
    require(type(arguments) is tuple and len(arguments) == 12, 'ARGUMENT_SHAPE')
    for value in arguments:
        u64(value)
    require(arguments[0] == 4 and arguments[9] == 2, 'UNSUPPORTED_MODE_POLICY')
    require(arguments[7] > 0 and arguments[8] > 0, 'OUTPUT_POINTER')
    require(arguments[7] + 128 <= 1 << 64 and arguments[8] + 4 <= 1 << 64, 'OUTPUT_RANGE')
    return arguments

@dataclass(frozen=True, repr=False)
class BufferPlan:
    arguments: tuple
    inputs: tuple
    output_pointer: int
    output_length_pointer: int

def overlap(a, size_a, b, size_b):
    return bool(size_a and size_b and (a < b + size_b) and (b < a + size_a))

def plan_buffers(arguments, inputs):
    arguments = validate_arguments(arguments)
    require(type(inputs) is dict and set(inputs) == {row[0] for row in INPUT_FIELDS}, 'INPUT_SHAPE')
    ranges = []
    total = 0
    for name, pi, li in INPUT_FIELDS:
        data = inputs[name]
        address, size = (arguments[pi], arguments[li])
        require(type(data) is bytes and len(data) == size, 'INPUT_LENGTH')
        require(size <= MAX_INPUT_BYTES and address + size <= 1 << 64 and (not size or address > 0), 'INPUT_RANGE')
        total += size
        if size:
            ranges.append((address, data))
    require(total <= MAX_INPUT_BYTES, 'INPUT_BUDGET')
    out, outlen = arguments[7:9]
    require(not overlap(out, 128, outlen, 4), 'OUTPUT_ALIAS_UNSUPPORTED')
    for address, data in ranges:
        require(not overlap(address, len(data), out, 128) and (not overlap(address, len(data), outlen, 4)), 'INPUT_OUTPUT_ALIAS_UNSUPPORTED')
    merged = []
    for address, data in sorted(ranges, key=lambda row: row[0]):
        if not merged or address > merged[-1][0] + len(merged[-1][1]):
            merged.append((address, data))
            continue
        start, previous = merged[-1]
        offset = address - start
        common = min(len(data), len(previous) - offset)
        require(previous[offset:offset + common] == data[:common], 'INPUT_ALIAS_CONFLICT')
        if offset + len(data) > len(previous):
            merged[-1] = (start, previous + data[common:])
    return BufferPlan(arguments, tuple(merged), out, outlen)

class ModelBudgetExceeded(Exception):
    pass

@contextmanager
def model_budget(seconds, clock=time.monotonic):
    require(type(seconds) in (int, float) and 1 <= seconds <= 120, 'MODEL_BUDGET_ARGUMENT')
    deadline = clock() + seconds
    previous = sys.getprofile()
    calls = 0

    def observe(frame, event, arg):
        nonlocal calls
        calls += 1
        if calls % 256 == 0 and clock() >= deadline:
            raise ModelBudgetExceeded()
    try:
        sys.setprofile(observe)
        yield
        if clock() >= deadline:
            raise ModelBudgetExceeded()
    finally:
        sys.setprofile(previous)

def _hex_bytes(value, count):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(count * 2) + '}', value) is not None, 'WARM_FIELD_BYTES')
    return bytes.fromhex(value)

def build_warm_inputs(producer, *, identity, metadata):
    from qq_nt_replica.primary_warm_core_inputs import LAYOUT, WarmCoreIdentity, WarmCoreContainerInputs, TokenEntry, GuidEntry
    keys = {'schema', 'layout', 'capturePoint', 'containerPointer', 'singletonSiteWord', 'fields', 'controls', 'coherence', 'identity'}
    require(type(producer) is dict and set(producer) == keys and (producer['schema'] == 'main96-warm-container-v1') and (producer['layout'] == LAYOUT) and (producer['capturePoint'] == 'main408-singleton-normal-leave-before414') and (type(producer['singletonSiteWord']) is int) and (producer['singletonSiteWord'] == 408), 'WARM_SCHEMA')
    require(producer['coherence'] == {'doubleReadEqual': True} and type(producer['coherence']['doubleReadEqual']) is bool, 'WARM_COHERENCE')
    owner = producer['identity']
    require(type(owner) is dict and set(owner) == {'mainEpoch', 'thread', 'readerInvocation'} and (owner['mainEpoch'] == metadata['mainEpoch']) and (type(owner['thread']) is int) and (owner['thread'] == metadata['thread']) and (type(owner['readerInvocation']) is int) and (owner['readerInvocation'] == metadata['readerInvocation']), 'WARM_IDENTITY')
    fields = producer['fields']
    names = {'field0', 'field2', 'field3', 'field4', 'field5', 'field6', 'field7', 'field9', 'field12', 'field14', 'field15', 'field16', 'field17', 'field19', 'field22', 'field23'}
    require(type(fields) is dict and set(fields) == names, 'WARM_FIELDS')
    tokens, guids = (fields['field7'], fields['field9'])
    require(type(tokens) is list and len(tokens) == 50 and (type(guids) is list) and (len(guids) == 5), 'WARM_RECORD_COUNT')
    require(all((type(row) is dict and set(row) == {'encoded', 'selector', 'enabled'} for row in tokens)) and all((type(row) is dict and set(row) == {'encoded', 'selector', 'marker'} for row in guids)), 'WARM_RECORD_SCHEMA')
    control = producer['controls']
    require(type(control) is dict and set(control) == {'x', 'y', 'class6'}, 'WARM_CONTROLS')
    for name in ('field22', 'field23'):
        require(type(fields[name]) is str and re.fullmatch('0x[0-9a-f]{16}', fields[name]) is not None, 'WARM_U64')
    warm_identity = WarmCoreIdentity(identity, metadata['processCreationIdentity'], metadata['moduleLoadGeneration'], metadata['thread'], metadata['readerInvocation'], pointer(producer['containerPointer']), producer['layout'], producer['capturePoint'])
    return WarmCoreContainerInputs(warm_identity, fields['field0'], _hex_bytes(fields['field2'], 16), fields['field3'], fields['field4'], fields['field5'], _hex_bytes(fields['field6'], 64), tuple((TokenEntry(_hex_bytes(row['encoded'], 4), row['selector'], row['enabled']) for row in tokens)), tuple((GuidEntry(_hex_bytes(row['encoded'], 33), row['selector'], row['marker']) for row in guids)), fields['field12'], fields['field14'], fields['field15'], fields['field16'], fields['field17'], fields['field19'], int(fields['field22'], 16), int(fields['field23'], 16), control['x'], control['y'], control['class6'])

def build_effective_environment(wire, *, identity, metadata):
    from qq_nt_replica.primary_main_environment_inputs import MainEnvironmentIdentity, MainEnvironmentInputs, QualifiedCursorFunction, QualifiedMD5Callback
    row = wire.get('effectiveEnvironment')
    keys = {'schema', 'capturePoint', 'cursorPointer', 'cursorIdentity', 'md5CallbackPointer', 'md5CallbackIdentity', 'prngStateU32', 'frameCount', 'frames', 'identity', 'contextProfileVerified', 'doubleReadEqual'}
    require(type(row) is dict and set(row) == keys and (row['schema'] == 'main96-effective-environment-v1') and (row['capturePoint'] == 'effective-main-evaluator-entry'), 'EFFECTIVE_ENVIRONMENT_SCHEMA')
    require(wire.get('_effectiveEnvironmentClaimed') is not True, 'EFFECTIVE_ENVIRONMENT_REUSED')
    require(row['contextProfileVerified'] is True and row['doubleReadEqual'] is True, 'EFFECTIVE_ENVIRONMENT_COHERENCE')
    owner = row['identity']
    require(type(owner) is dict and set(owner) == {'mainEpoch', 'thread', 'readerInvocation', 'context', 'evaluatorBP', 'evaluatorEntryRSP', 'mainEntryRSP'}, 'EFFECTIVE_ENVIRONMENT_IDENTITY')
    require(type(owner['mainEpoch']) is str and owner['mainEpoch'] == metadata['mainEpoch'] and all((type(owner[k]) is int and owner[k] == metadata[k] for k in ('thread', 'readerInvocation'))), 'EFFECTIVE_ENVIRONMENT_IDENTITY')
    for name in ('context', 'evaluatorBP'):
        require(pointer(owner[name]) == pointer(wire['identity'][name]), 'EFFECTIVE_ENVIRONMENT_IDENTITY')
    require(pointer(owner['mainEntryRSP']) == pointer(wire['entryRSP']) and pointer(owner['evaluatorEntryRSP']) >= 280 and (pointer(owner['evaluatorBP']) == pointer(owner['evaluatorEntryRSP']) - 280), 'EFFECTIVE_ENVIRONMENT_IDENTITY')

    def raw_u64(value, code):
        require(type(value) is str and re.fullmatch('0x[0-9a-f]{16}', value) is not None, code)
        return int(value, 16)
    cursor = raw_u64(row['cursorPointer'], 'EFFECTIVE_ENVIRONMENT_CURSOR')
    count, frames = (row['frameCount'], row['frames'])
    require(type(count) is int and 0 <= count <= 4 and (type(frames) is list) and (len(frames) == count), 'EFFECTIVE_ENVIRONMENT_FRAMES')
    frames = tuple((raw_u64(value, 'EFFECTIVE_ENVIRONMENT_FRAMES') for value in frames))
    typed_identity = MainEnvironmentIdentity(identity, metadata['processCreationIdentity'], metadata['moduleLoadGeneration'], metadata['thread'], metadata['readerInvocation'], metadata['mainEpoch'], True, True)
    qualified = None
    if cursor == 0:
        require(row['cursorIdentity'] is None, 'EFFECTIVE_ENVIRONMENT_CURSOR')
    else:

        class IdentityValidator:
            pointer = CursorReplay.pointer

            def require(self, ok, code):
                require(ok, 'EFFECTIVE_ENVIRONMENT_CURSOR')
        CursorReplay.api_identity(IdentityValidator(), row['cursorIdentity'])
        require(pointer(row['cursorIdentity']['resolvedAddress']) == cursor, 'EFFECTIVE_ENVIRONMENT_CURSOR')
        qualified = QualifiedCursorFunction(typed_identity, cursor, pointer(row['cursorIdentity']['sourceModule']['base']))
    for event in wire.get('cursorEvents', []):
        if event.get('resolverLink') is None:
            require(pointer(event['slotAtEntry'], zero=True) == cursor and (not event['called'] or (cursor != 0 and event['apiIdentity'] == row['cursorIdentity'])), 'EFFECTIVE_ENVIRONMENT_CURSOR')
    md5_pointer = raw_u64(row['md5CallbackPointer'], 'EFFECTIVE_ENVIRONMENT_IDENTITY')
    md5 = None
    md5_identity = row['md5CallbackIdentity']
    if md5_pointer == 0:
        require(md5_identity is None, 'EFFECTIVE_ENVIRONMENT_IDENTITY')
    else:
        require(type(md5_identity) is dict and set(md5_identity) == {'kind', 'sourcePeSha256', 'moduleGeneration', 'callbackRva', 'implementationRva', 'sourceModule'}, 'EFFECTIVE_ENVIRONMENT_IDENTITY')
        require(md5_identity['kind'] == 'REGISTERED_MD5' and md5_identity['sourcePeSha256'] == SOURCE_SHA256 == wire['identity']['sourcePeSha256'] and (md5_identity['moduleGeneration'] == metadata['moduleLoadGeneration'] == wire['identity']['moduleGeneration']), 'EFFECTIVE_ENVIRONMENT_IDENTITY')
        require(type(md5_identity['callbackRva']) is int and md5_identity['callbackRva'] == 29348816 and (type(md5_identity['implementationRva']) is int) and (md5_identity['implementationRva'] == 30432528), 'EFFECTIVE_ENVIRONMENT_IDENTITY')
        module = md5_identity['sourceModule']
        require(type(module) is dict and set(module) == {'name', 'path', 'base', 'size'} and (type(module['name']) is str) and (module['name'].lower() == 'wrapper.node') and (type(module['path']) is str) and (0 < len(module['path']) <= 32768) and (type(module['size']) is int) and (30432528 + 32 <= module['size'] < 1 << 64), 'EFFECTIVE_ENVIRONMENT_IDENTITY')
        base = pointer(module['base'])
        require(base == metadata['imageBase'] == pointer(wire['identity']['moduleBase']) and base + module['size'] < 1 << 64 and (md5_pointer == base + 29348816), 'EFFECTIVE_ENVIRONMENT_IDENTITY')
        md5 = QualifiedMD5Callback(typed_identity, md5_pointer, base)
    prng_state = row['prngStateU32']
    require(type(prng_state) is int and 0 <= prng_state <= 4294967295, 'EFFECTIVE_ENVIRONMENT_PRNG_STATE')
    result = MainEnvironmentInputs(typed_identity, qualified, count, frames, md5, prng_initial_u32=prng_state)
    wire['_effectiveEnvironmentClaimed'] = True
    return result
