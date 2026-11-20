import sys
from contextlib import contextmanager
from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable, signed


PROGRAM_SHA256 = {
    'source2583': 'cddde1eb11604d2ed98f936f7e84c33f6442423948fa3f2a480ac1acea9ed490',
    'token-setter': '5fa8d78f68f7fe6d6081d1587f521e6aa2a731d9afa8f2158c21ba9aff6e112a',
    'token-expire': '952cdf6c4d6dcd3595627de08fe71a7a34925ec69a83a7ad996f5e445fa62522'}
_CLAIM_FACTORY = object()


class _PublicationClaim:
    def __init__(self, runtime, scope, owner, publication, source, pointer, kind, key, caller, carrier, region, factory):
        if factory is not _CLAIM_FACTORY:
            raise PrimarySemanticUnavailable('token publication requires its actual source factory')
        self.runtime, self.scope, self.owner = runtime, scope, owner
        self.publication, self.source, self.region = publication, source, region
        self.pointer, self.kind, self.key, self.caller, self.carrier = pointer, kind, key, caller, carrier
        self.thread, self.serial, self.generation = get_ident(), owner.serial, runtime._main_generation
        self.parent_calls = tuple(runtime._program_calls)
        self.nonce = object()
        self.active = True
        self.root = self.root_call = self.setter = self.setter_call = self.expire = None


def _source_frame(code, **values):
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is code:
            local = frame.f_locals
            if all(local.get(key) == value if type(value) in (int, str, tuple) else local.get(key) is value
                   for key, value in values.items()):
                return frame
        frame = frame.f_back
    return None


def _origin(runtime, caller, token):
    from .primary_material import ProviderMaterial
    from .primary_source_postfetch import refresh
    if caller == 'initial':
        frame = _source_frame(ProviderMaterial._read.__code__, self=runtime.provider_material, runtime=runtime, token=token,
                              environment=runtime.provider_environment, profile=runtime.provider_profile)
        if frame is not None and runtime.locks.get(runtime.image_base + 0x67518F0) == 1:
            return frame
    elif caller == 'postfetch':
        frame = _source_frame(ProviderMaterial.refresh.__code__, self=runtime.provider_material, runtime=runtime, token=token)
        if frame is not None:
            return frame
        frame = _source_frame(refresh.__code__, runtime=runtime, token=token)
        if frame is not None:
            return frame
    return None


def _publication_owner(runtime, scope, caller, source):
    from .primary_sign_lifecycle import _PublicDirectOwner, _SecondaryPostfetchOwner
    from .primary_source_postfetch import refresh
    from .primary_sign import PrimaryRuntime
    owner = scope.public_owner
    if type(owner) is _PublicDirectOwner:
        return owner if runtime.__dict__.get('_primary_public_direct_owner') is owner else None
    owner = scope.secondary_owner
    if (type(owner) is _SecondaryPostfetchOwner and
            runtime.__dict__.get('_primary_secondary_postfetch_owner') is owner and caller == 'postfetch' and
            source is not None and source.f_code is refresh.__code__ and
            source.f_locals.get('runtime') is runtime and owner.source is not None and
            _source_frame(PrimaryRuntime.invoke.__code__, self=runtime, rva=0x3E81800,
                          vm=owner.source.f_locals.get('vm'), cells=(0,)) is not None):
        return owner
    return None


@contextmanager
def _token_publication(runtime, pointer, kind, key, caller, carrier):
    scope = runtime.__dict__.get('_primary_direct_scope')
    if scope is None:
        yield
        return
    from .primary_direct_scopes import PrimaryDirectScope
    from .primary_sign import PrimaryRuntime
    from .primary_sign_lifecycle import region_at
    publication = _source_frame(PrimaryRuntime.publish_provider_token.__code__, self=runtime, address=pointer, caller=caller, vm=carrier)
    source = None if publication is None else _origin(runtime, caller, publication.f_locals.get('token'))
    owner = _publication_owner(runtime, scope, caller, source) if type(scope) is PrimaryDirectScope else None
    region = region_at(runtime.memory, pointer)
    if (type(scope) is not PrimaryDirectScope or scope.runtime is not runtime or owner is None or
            owner.runtime is not runtime or owner.thread != get_ident() or not owner.valid() or
            publication is None or publication.f_locals.get('size') != 5 or publication.f_locals.get('values') != (pointer, kind, key) or
            source is None or kind != 1 or key != 0x2583 or type(pointer) is not int or
            region is None or len(region.data) != 5 or region.name != 'provider token local' or
            runtime._active_main is not None or runtime._program_calls or runtime._execute_depth != 0 or
            runtime._execute_thread is not None or runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            runtime.__dict__.get('_primary_token_publication_claim') is not None):
        raise PrimarySemanticUnavailable('token family requires its actual one-use preMain material publication and private local')
    scope._require_live()
    claim = _PublicationClaim(runtime, scope, owner, publication, source, pointer, kind, key, caller, carrier, region, _CLAIM_FACTORY)
    runtime._primary_token_publication_claim = claim
    try:
        yield
        if claim.root is None or not claim.root.halted or claim.root.pc != 188:
            raise PrimarySemanticUnavailable('token publication did not complete its actual source root')
    finally:
        claim.active = False
        claim.publication = claim.source = None
        if runtime.__dict__.get('_primary_token_publication_claim') is claim:
            runtime.__dict__.pop('_primary_token_publication_claim')


def _response_origin_valid(claim):
    from .primary_request_transport import _complete, _Map
    from .primary_signer import PrimarySigner
    from .primary_tokens import publish_response_token
    from .primary_worker_response import respond
    runtime, source, publication, memory = claim.runtime, claim.source, claim.publication, claim.runtime.memory
    if (source is None or publication is None or claim.caller != 'response' or claim.kind != 2 or
            claim.key != 0x2583 or source.f_code is not respond.__code__ or
            _source_frame(respond.__code__, runtime=runtime) is not source or
            publication.f_code is not publish_response_token.__code__ or
            _source_frame(publish_response_token.__code__, runtime=runtime, pointer=claim.pointer) is not publication or
            publication.f_locals.get('carrier') is not claim.carrier or
            publication.f_locals.get('values') != (claim.pointer, 2, 0x2583) or
            claim.scope.public_owner is not claim.owner or not claim.scope._valid_public()):
        return False
    local = source.f_locals
    region = claim.region
    complete = _source_frame(_complete.__code__, runtime=runtime, consume_command=False)
    public = _source_frame(PrimarySigner.complete_request.__code__, self=claim.owner.signer)
    if (complete is None or public is None or region.name != 'BDCAD0.device_response_frame' or
            len(region.data) != 0x1A8 or local.get('frame') != region.address or
            local.get('rbp') != region.address + 0x80 or claim.pointer != region.address + 0x110 or
            local.get('auxiliary') is None or memory.read(claim.pointer, 5) != local['auxiliary'] + b'\0'):
        return False
    actual = complete.f_locals
    if any(local.get(left) != actual.get(right) for left, right in
            (('capture', 'active_capture'), ('pointer', 'result_pointer'), ('size', 'result_count'),
             ('success', 'business_success'), ('error', 'business_error')) if left != 'capture'):
        return False
    active, node, record = (actual.get(key) for key in ('active', 'node', 'record'))
    sequence = actual.get('sequence')
    if any(type(value) is not int or value <= 0 for value in (active, node, record)) or type(sequence) is not int:
        return False
    signed = sequence - (1 << 64) if sequence >> 63 else sequence
    if (local.get('capture') != active + 8 or actual.get('target') != runtime.image_base + 0xBDCA30 or
            _Map(runtime, runtime.image_base + 0x6751AB8 + 24).find(signed) != node or
            memory.load(node + 48, 8) != record or memory.load(node + 40, 8) != record + 24 or
            memory.load(record + 168, 8) != active or
            memory.load(memory.load(active, 8) + 40, 8) != runtime.image_base + 0xBDCA30):
        return False
    token = local.get('token')
    if token is None:
        return False
    if token.get(0, 1) & 1:
        auxiliary = memory.read(token.get(16, 8), 4)
    else:
        if not all(token.known[1:5]):
            return False
        auxiliary = bytes(token.header[1:5])
    return local['auxiliary'] == auxiliary


@contextmanager
def response_token_publication(runtime, pointer, carrier):
    if getattr(runtime, 'primary_backend', 'reference') != 'direct':
        yield
        return
    from .primary_direct_scopes import PrimaryDirectScope
    from .primary_sign_lifecycle import region_at
    from .primary_tokens import publish_response_token
    from .primary_worker_response import respond
    scope = runtime.__dict__.get('_primary_direct_scope')
    source = _source_frame(respond.__code__, runtime=runtime)
    publication = _source_frame(publish_response_token.__code__, runtime=runtime, pointer=pointer)
    if (type(scope) is not PrimaryDirectScope or not scope._valid_public() or
            source is None or publication is None or runtime._active_main is not None or
            runtime._program_calls or runtime._execute_depth or runtime._execute_thread is not None or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            runtime.__dict__.get('_primary_token_publication_claim') is not None):
        raise PrimarySemanticUnavailable('response publication requires its actual public completion source')
    claim = _PublicationClaim(runtime, scope, scope.public_owner, publication, source, pointer, 2, 0x2583,
                              'response', carrier, region_at(runtime.memory, source.f_locals.get('frame')), _CLAIM_FACTORY)
    if claim.region is None or not _response_origin_valid(claim):
        raise PrimarySemanticUnavailable('response publication lost its actual private token local or pending callback')
    runtime._primary_token_publication_claim = claim
    try:
        yield
        if not _response_origin_valid(claim) or claim.root is None or not claim.root.halted or claim.root.pc != 188:
            raise PrimarySemanticUnavailable('response publication did not complete its original source root')
    finally:
        claim.active = False
        claim.publication = claim.source = None
        if runtime.__dict__.get('_primary_token_publication_claim') is claim:
            runtime.__dict__.pop('_primary_token_publication_claim')
        elif sys.exception() is None:
            raise PrimarySemanticUnavailable('response publication claim changed before exit')


def _publication_origin_valid(claim):
    from .primary_sign import PrimaryRuntime
    if claim.caller == 'response':
        return _response_origin_valid(claim)
    return (_source_frame(PrimaryRuntime.publish_provider_token.__code__, self=claim.runtime, address=claim.pointer,
                          caller=claim.caller, vm=claim.carrier) is claim.publication and
            _origin(claim.runtime, claim.caller, claim.publication.f_locals.get('token')) is claim.source)


def _authorize(vm, name):
    from .primary_sign import PrimaryRuntime
    from .primary_sign_lifecycle import region_at
    from .primary_tokens import dispatch_local
    runtime = vm.runtime
    claim = getattr(runtime, '_primary_token_publication_claim', None)
    if (runtime is None or type(claim) is not _PublicationClaim or not claim.active or claim.runtime is not runtime or
            claim.thread != get_ident() or claim.owner.thread != get_ident() or not claim.owner.valid() or
            claim.owner.serial != claim.serial or runtime._main_generation != claim.generation or
            runtime.__dict__.get('_primary_direct_scope') is not claim.scope or
            _publication_owner(runtime, claim.scope, claim.caller, claim.source) is not claim.owner or runtime._active_main is not None or
            runtime._active_failed or runtime._execute_thread != get_ident() or getattr(runtime, '_consumed_mgf', None) is not None or
            vm.memory is not runtime.memory or vm.image_base != runtime.image_base or not runtime.vms or runtime.vms[-1] is not vm or
            region_at(runtime.memory, claim.region.address if claim.caller == 'response' else claim.pointer) is not claim.region or
            not _publication_origin_valid(claim)):
        raise PrimarySemanticUnavailable('token family lost its actual publication source, public owner or private local')
    claim.scope._require_live()
    reader = _source_frame(PrimaryRuntime._execute_program.__code__, self=runtime, name=name)
    publication = _source_frame(PrimaryRuntime.invoke.__code__, self=runtime, rva=0x1BF7520, vm=claim.carrier, cells=(0, 1, 2))
    dispatch = _source_frame(dispatch_local.__code__, runtime=runtime, pointer=claim.pointer, kind=claim.kind, key=claim.key)
    calls = runtime._program_calls
    count = {'source2583': 1, 'token-setter': 2, 'token-expire': 3}[name]
    if (reader is None or reader.f_locals.get('vm') is not vm or publication is None or dispatch is None or
            len(calls) != len(claim.parent_calls) + count or runtime._execute_depth != len(calls) or
            any(a is not b for a, b in zip(calls, claim.parent_calls)) or
            tuple(row['name'] for row in calls[-count:]) != ('source2583', 'token-setter', 'token-expire')[:count] or
            any(row['hosts'] is not None for row in calls[-count:]) or reader.f_locals.get('arguments') != calls[-1]['arguments']):
        raise PrimarySemanticUnavailable('token family requires its exact actual registry and current source stack')
    if name == 'source2583':
        wrapper = _source_frame(PrimaryRuntime.invoke.__code__, self=runtime, rva=0x35A2BF0)
        if claim.root is not None or calls[-1]['arguments'] != (runtime.image_base + 0x6D88D74, claim.pointer, claim.kind) or wrapper is None:
            raise PrimarySemanticUnavailable('token root publication is replayed or has a foreign ABI')
        claim.root, claim.root_call = vm, calls[-1]
    else:
        parent = claim.root if name == 'token-setter' else claim.setter
        word, pc, block, predecessor, callee, arguments, signature, destination, rva = (
            (171, 181, 9, (5,), 36, (22, 24, 17, 2), 42, 37, 0x3592274) if name == 'token-setter' else
            (360, 367, 12, (7, 15), 66, (0, 65), 37, None, 0x35921C2))
        wrapper = _source_frame(PrimaryRuntime.invoke.__code__, self=runtime, rva=rva)
        native = _source_frame(_host.__code__, runtime=runtime, vm=parent)
        parent_name = 'source2583' if name == 'token-setter' else 'token-setter'
        if (type(parent) is not PrimaryVM or parent.runtime is not runtime or parent.memory is not runtime.memory or parent.halted or
                sha256(parent.program.raw).hexdigest() != PROGRAM_SHA256[parent_name] or
                (parent.pc, parent.block, parent.initial_block) != (pc, block, False) or parent.predecessor not in predecessor or
                len(runtime.vms) < 2 or runtime.vms[-2] is not parent or calls[-2] is not (claim.root_call if count == 2 else claim.setter_call) or
                not parent.host_calls or parent.host_calls[-1] != (word, runtime.image_base + rva, arguments, signature) or
                getattr(parent, '_primary_token_family_active_call', None) != (claim.nonce, word, callee, arguments, signature, destination) or
                native is None or wrapper is None or wrapper.f_locals.get('vm') is not parent or wrapper.f_locals.get('cells') != arguments or
                (claim.setter is not None if count == 2 else claim.expire is not None)):
            raise PrimarySemanticUnavailable('token child requires its actual one-use parent source callback and ABI')
        if count == 2:
            claim.setter, claim.setter_call = vm, calls[-1]
        else:
            root_reader = _source_frame(PrimaryRuntime._execute_program.__code__, self=runtime, name='source2583')
            root = claim.root
            if (calls[-3] is not claim.root_call or root_reader is None or root_reader.f_locals.get('vm') is not root or
                    root.halted or (root.pc, root.block, root.predecessor, root.initial_block) != (181, 9, 5, False) or
                    getattr(root, '_primary_token_family_active_call', None) != (claim.nonce, 171, 36, (22, 24, 17, 2), 42, 37)):
                raise PrimarySemanticUnavailable('token expiry lost its original publication root')
            claim.expire = vm
    return claim


def execute_primary_token_family(vm, name, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or name not in PROGRAM_SHA256 or sha256(vm.program.raw).hexdigest() != PROGRAM_SHA256[name] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used) != (1, 0, None, True, 0) or
            vm.halted or vm.abort_reason is not None or vm.trace or vm.host_calls or vm.auxiliary is not None or
            any(getattr(vm, key) is not None for key in ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native', 'private_iv_native_pending'))):
        raise PrimarySemanticUnavailable('token family requires its fixed fresh nonpending source reader')
    _authorize(vm, name)
    state = dict(program=name, backend='DIRECT_TOKEN_FAMILY_LITERAL', completed=False, referenceRecordCount=0,
                 traceComplete=False, completeIndependentMain=False, controlDomain='NONWAITING_ONCE10_FINITE_G_F_ALTERNATE_ERRORS')
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_token_family_direct_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    {'source2583': _source2583, 'token-setter': _token_setter, 'token-expire': _token_expire}[name](vm, tick)
    state['completed'] = True
    return vm.result


def _host(vm, word, callee, arguments, signature, destination):
    runtime = vm.runtime
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    claim = getattr(runtime, '_primary_token_publication_claim', None)
    nonce = claim.nonce if type(claim) is _PublicationClaim else None
    if sha256(vm.program.raw).hexdigest() == PROGRAM_SHA256['source2583'] and word == 171 and address != vm.image_base + 0x3592274:
        raise PrimarySemanticUnavailable('token current container callback is unavailable')
    vm._primary_token_family_active_call = (nonce, word, callee, arguments, signature, destination)
    try:
        result = _invoke_host(vm, address, arguments, signature, argument_types=vm.program.type(signature).parameters[3:])
    finally:
        vm._primary_token_family_active_call = None
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')



def _read_pair_control(vm):
    x = signed(vm.memory.load(vm.image_base + 108519860, 4), 32)
    y = signed(vm.memory.load(vm.image_base + 108519864, 4), 32)
    return (x * x + y * y & 4294967295 | abs(x) + abs(y) & 4294967295) >> 31


def _convert(vm, width, source, destination):
    alternate = False
    if width == 1 or width >= 4:
        alternate = _read_pair_control(vm)
    if width >= 4:
        if vm.memory.load(vm.image_base + 108519868, 4) == 2147483648:
            raise PrimarySemanticUnavailable('independent record consumer mask wait is unavailable')
        if width >= 8:
            vm.memory.load(vm.image_base + 108519868, 4)
            if vm.memory.load(vm.image_base + 108519868, 4) == 2147483648:
                raise PrimarySemanticUnavailable('independent record consumer mask wait is unavailable')
    value = vm.memory.load(vm.cells.pointer(source), width)
    vm.memory.store(vm.cells.pointer(destination), value, 8, source='once10.first_type_zeroextend_or_q')
    if width == 1 and alternate:
        value = vm.memory.load(vm.cells.pointer(source), 1)
        vm.memory.store(vm.cells.pointer(destination), value, 8, source='once10.first_type_zeroextend_or_q')


def _pointer(vm, word, typ, base, destination, indices):
    vm.pc = word + 6
    offset = 0
    for ordinal, index_cell in enumerate(indices):
        vm.pc = word + 7 + ordinal
        index = vm.memory.load(vm.cells.pointer(index_cell), 4)
        if ordinal == 0:
            delta = vm.program.size(typ) * index
        else:
            delta, typ = vm._indexed_offset(typ, index)
        offset = offset + delta & 18446744073709551615
    vm._write(destination, vm.cells.value(base) + offset, 8, 'high.indexed_pointer_q')


def _phi(vm, word, operands):
    destination, count, *pairs = operands
    matched = False
    for ordinal in range(count):
        source, predecessor = pairs[2 * ordinal:2 * ordinal + 2]
        vm.pc = word + 5 + 2 * ordinal
        if not matched and vm.predecessor == predecessor:
            vm._write(destination, vm.cells.value(source), 8, 'L9.phi_q')
            matched = True
    vm.pc = word + 3 + 2 * count


def _single(vm):
    x = vm.memory.load(vm.image_base + 0x6D86090, 4)
    y = signed(vm.memory.load(vm.image_base + 0x6D86094, 4), 32)
    return ((((x*x) & 0xFFFFFFFF) | (abs(y) & 0xFFFFFFFF)) >> 31) & 1


def _source2583(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(7, 3)
            tick(4)
            vm.pc = 5
            tick(5)
            vm.pc = 8
            vm.auxiliary = (0, 1282564948)
            tick(8)
            vm.pc = 13
            vm._write(5, int(memory.load(cells.pointer(1), 8, signed=True) != memory.load(cells.pointer(4), 8, signed=True)), 4, 'L27.comparison')
            tick(13)
            vm.pc = 17
            vm._jump(1 if cells.value(5) != 0 else 2)
            continue
        if vm.block == 1:
            tick(17)
            vm.pc = 21
            vm._jump(3 if cells.value(6) != 0 else 4)
            continue
        if vm.block == 3:
            tick(21)
            vm.pc = 23
            vm._jump(5)
            continue
        if vm.block == 4:
            tick(23)
            vm.pc = 25
            vm._jump(6)
            continue
        if vm.block == 6:
            tick(25)
            _phi(vm, 25, (7, 2, 8, 4, 9, 7))
            tick(32)
            _pointer(vm, 32, 0, 1, 10, (7,))
            tick(39)
            vm.pc = 43
            value = memory.load(cells.value(10), 1)
            vm._write(11, value, 4, 'high.load')
            tick(43)
            vm.pc = 48
            cells.copy_q_clear_owned(11, 12)
            tick(48)
            vm.pc = 49
            tick(49)
            vm.pc = 52
            vm.auxiliary = (0, 1988244340)
            tick(52)
            vm.pc = 57
            vm._write(14, int(memory.load(cells.pointer(12), 4, signed=True) != memory.load(cells.pointer(13), 4, signed=True)), 4, 'L30.comparison')
            tick(57)
            vm.pc = 61
            vm._jump(7 if cells.value(14) != 0 else 8)
            continue
        if vm.block == 7:
            tick(61)
            vm.pc = 62
            tick(62)
            vm.pc = 65
            vm.auxiliary = (0, 709922818)
            tick(65)
            vm.pc = 70
            vm._write(9, memory.load(cells.pointer(7), 8, signed=True) + memory.load(cells.pointer(15), 8, signed=True), 8, 'once1.integer')
            tick(70)
            vm.pc = 72
            vm._jump(6)
            continue
        if vm.block == 8:
            tick(72)
            vm.pc = 77
            vm._write(16, cells.value(7) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 81
                width = vm.program.size(32209)
                vm._write(17, cells.value(12649) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(77)
            vm.pc = 79
            vm._jump(5)
            continue
        if vm.block == 5:
            tick(79)
            _phi(vm, 79, (17, 2, 13, 3, 16, 8))
            tick(86)
            vm.pc = 87
            tick(87)
            vm.pc = 90
            vm.auxiliary = (0, 1583507795)
            tick(90)
            vm.pc = 95
            vm._write(19, int(memory.load(cells.pointer(17), 4, signed=True) == memory.load(cells.pointer(18), 4, signed=True)), 4, 'once17.integer')
            tick(95)
            vm.pc = 99
            vm._jump(9 if cells.value(19) != 0 else 10)
            continue
        if vm.block == 9:
            tick(99)
            vm.pc = 105
            _host(vm, 99, 21, (), 11, 20)
            tick(105)
            vm.pc = 110
            cells.copy_q_clear_owned(20, 22)
            tick(110)
            vm.pc = 115
            cells.copy_q_clear_owned(3, 23)
            tick(115)
            _pointer(vm, 115, 7, 3, 24, (8, 8))
            tick(123)
            vm.pc = 132
            _host(vm, 123, 26, (24, 13, 27), 36, 25)
            tick(132)
            vm.pc = 137
            cells.copy_q_clear_owned(17, 28)
            tick(137)
            vm.pc = 146
            _host(vm, 137, 30, (24, 1, 28), 38, 29)
            tick(146)
            _pointer(vm, 146, 34, 22, 31, (13, 32))
            tick(154)
            _pointer(vm, 154, 26, 31, 33, (8, 34))
            tick(162)
            vm.pc = 166
            value = memory.load(cells.value(33), 8)
            vm._write(35, value, 8, 'high.load')
            tick(166)
            vm.pc = 171
            cells.copy_q_clear_owned(35, 36)
            tick(171)
            vm.pc = 181
            _host(vm, 171, 36, (22, 24, 17, 2), 42, 37)
            tick(181)
            vm.pc = 183
            vm._jump(10)
            continue
        if vm.block == 10:
            tick(183)
            vm.pc = 185
            vm._jump(2)
            continue
        if vm.block == 2:
            tick(185)
            vm.pc = 188
            vm.result = memory.load(cells.pointer(38), 1, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('bootstrap left its fixed source blocks')


def _token_setter(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(3, 4)
            tick(4)
            vm.pc = 7
            vm._allocate(30, 5)
            tick(7)
            vm.pc = 8
            tick(8)
            vm.pc = 11
            vm.auxiliary = (0, 532830308)
            tick(11)
            vm.pc = 16
            vm._write(7, int(memory.load(cells.pointer(0), 8, signed=True) != memory.load(cells.pointer(6), 8, signed=True)), 4, 'L30.comparison')
            tick(16)
            vm.pc = 19
            vm.auxiliary = (0, 501367444)
            tick(19)
            vm.pc = 24
            vm._write(9, int(memory.load(cells.pointer(1), 8, signed=True) != memory.load(cells.pointer(8), 8, signed=True)), 4, 'L30.comparison')
            tick(24)
            vm.pc = 27
            vm.auxiliary = (0, 46621)
            tick(27)
            vm.pc = 32
            vm._write(10, memory.load(cells.pointer(7), 1, signed=True) & memory.load(cells.pointer(9), 1, signed=True), 8, 'typed.selector1.q')
            tick(32)
            vm.pc = 35
            vm.auxiliary = (0, 52583)
            tick(35)
            vm.pc = 41
            vm._write(12, memory.load(cells.pointer(10), 1, signed=True) ^ memory.load(cells.pointer(11), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(41)
            vm.pc = 44
            vm.auxiliary = (0, 348292228)
            tick(44)
            vm.pc = 49
            vm._write(14, int(memory.load(cells.pointer(2), 4, signed=True) != memory.load(cells.pointer(13), 4, signed=True)), 4, 'L30.comparison')
            tick(49)
            vm.pc = 52
            vm.auxiliary = (0, 13283)
            tick(52)
            vm.pc = 57
            vm._write(15, memory.load(cells.pointer(12), 1, signed=True) | memory.load(cells.pointer(14), 1, signed=True), 8, 'typed.selector2.q')
            tick(57)
            vm.pc = 61
            vm._jump(1 if cells.value(15) != 0 else 2)
            continue
        if vm.block == 1:
            tick(61)
            vm.pc = 63
            vm._jump(3)
            continue
        if vm.block == 2:
            tick(63)
            vm.pc = 64
            tick(64)
            vm.pc = 67
            vm.auxiliary = (0, 597859604)
            tick(67)
            vm.pc = 72
            vm._write(17, int(memory.load(cells.pointer(3), 4, signed=True) != memory.load(cells.pointer(16), 4, signed=True)), 4, 'L30.comparison')
            tick(72)
            vm.pc = 75
            vm.auxiliary = (0, 1257428308)
            tick(75)
            vm.pc = 80
            vm._write(19, int(memory.load(cells.pointer(3), 4, signed=True) != memory.load(cells.pointer(18), 4, signed=True)), 4, 'L30.comparison')
            tick(80)
            vm.pc = 85
            vm._write(20, memory.load(cells.pointer(17), 1, signed=True) & memory.load(cells.pointer(19), 1, signed=True), 8, 'L13.binary_q')
            tick(85)
            vm.pc = 89
            vm._jump(4 if cells.value(20) != 0 else 5)
            continue
        if vm.block == 4:
            tick(89)
            vm.pc = 91
            vm._jump(3)
            continue
        if vm.block == 5:
            tick(91)
            vm.pc = 98
            _host(vm, 91, 21, (0, 11), 34, None)
            tick(98)
            vm.pc = 103
            cells.copy_q_clear_owned(4, 22)
            tick(103)
            _pointer(vm, 103, 3, 4, 23, (24, 24))
            tick(111)
            _pointer(vm, 111, 25, 0, 25, (26, 18))
            tick(119)
            _pointer(vm, 119, 3, 25, 27, (24, 24))
            tick(127)
            vm.pc = 131
            vm._jump(6 if cells.value(11) != 0 else 7)
            continue
        if vm.block == 6:
            tick(131)
            vm.pc = 133
            vm._jump(8)
            continue
        if vm.block == 8:
            tick(133)
            _phi(vm, 133, (28, 2, 27, 6, 29, 9))
            tick(140)
            _phi(vm, 140, (30, 2, 23, 6, 31, 9))
            tick(147)
            _phi(vm, 147, (32, 2, 33, 6, 34, 9))
            tick(154)
            vm.pc = 155
            tick(155)
            vm.pc = 158
            vm.auxiliary = (0, 354484226)
            tick(158)
            vm.pc = 163
            vm._write(34, memory.load(cells.pointer(32), 8, signed=True) + memory.load(cells.pointer(35), 8, signed=True), 8, 'once1.integer')
            tick(163)
            vm.pc = 168
            vm._write(36, int(cells.value(32) > cells.value(24)), 4, 'L31.comparison')
            tick(168)
            vm.pc = 172
            vm._jump(9 if cells.value(36) != 0 else 10)
            continue
        if vm.block == 9:
            tick(172)
            _pointer(vm, 172, 2, 28, 29, (16,))
            tick(179)
            vm.pc = 183
            value = memory.load(cells.value(28), 1)
            vm._write(37, value, 4, 'high.load')
            tick(183)
            _pointer(vm, 183, 2, 30, 31, (16,))
            tick(190)
            vm.pc = 194
            pointer = cells.value(30)
            value = memory.load(cells.pointer(37), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(194)
            vm.pc = 196
            vm._jump(8)
            continue
        if vm.block == 10:
            tick(196)
            vm.pc = 198
            vm._jump(7)
            continue
        if vm.block == 7:
            tick(198)
            _pointer(vm, 198, 25, 0, 38, (26, 39))
            tick(206)
            _pointer(vm, 206, 5, 38, 40, (24, 24))
            tick(214)
            vm.pc = 218
            vm._jump(11 if cells.value(11) != 0 else 12)
            continue
        if vm.block == 11:
            tick(218)
            vm.pc = 222
            value = memory.load(cells.value(40), 1)
            vm._write(41, value, 4, 'high.load')
            tick(222)
            vm.pc = 224
            vm._jump(13)
            continue
        if vm.block == 13:
            tick(224)
            _phi(vm, 224, (42, 2, 41, 11, 43, 14))
            tick(231)
            _phi(vm, 231, (44, 2, 24, 11, 45, 14))
            tick(238)
            vm.pc = 243
            vm._write(46, int(cells.value(44) < cells.value(33)), 4, 'once18.unsigned_q')
            tick(243)
            vm.pc = 247
            vm._jump(14 if cells.value(46) != 0 else 15)
            continue
        if vm.block == 14:
            tick(247)
            vm.pc = 252
            _convert(vm, 4, 42, 47)
            tick(252)
            vm.pc = 253
            tick(253)
            vm.pc = 256
            vm.auxiliary = (0, 1871913475)
            tick(256)
            vm.pc = 261
            vm._write(49, memory.load(cells.pointer(44), 8, signed=True) * memory.load(cells.pointer(48), 8, signed=True), 8, 'once0.integer')
            tick(261)
            vm.pc = 266
            vm._write(50, cells.value(49) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 270
                width = vm.program.size(360601030)
                vm._write(50, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(266)
            vm.pc = 271
            _convert(vm, 4, 50, 51)
            tick(271)
            vm.pc = 274
            vm.auxiliary = (0, 39188)
            tick(274)
            vm.pc = 280
            vm._write(52, memory.load(cells.pointer(47), 4, signed=True) ^ memory.load(cells.pointer(51), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(280)
            _pointer(vm, 280, 3, 4, 53, (24, 44))
            tick(288)
            vm.pc = 292
            value = memory.load(cells.value(53), 1)
            vm._write(54, value, 4, 'high.load')
            tick(292)
            vm.pc = 297
            _convert(vm, 4, 54, 55)
            tick(297)
            vm.pc = 300
            vm.auxiliary = (0, 22637)
            tick(300)
            vm.pc = 306
            vm._write(56, memory.load(cells.pointer(55), 4, signed=True) ^ memory.load(cells.pointer(52), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(306)
            vm.pc = 311
            vm._write(57, cells.value(56) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 315
                width = vm.program.size(218307768)
                vm._write(53, cells.value(57) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(311)
            vm.pc = 315
            pointer = cells.value(53)
            value = memory.load(cells.pointer(57), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(315)
            vm.pc = 318
            vm.auxiliary = (0, 306815492)
            tick(318)
            vm.pc = 323
            vm._write(59, memory.load(cells.pointer(47), 4, signed=True) * memory.load(cells.pointer(58), 4, signed=True), 8, 'once0.integer')
            tick(323)
            vm.pc = 326
            vm.auxiliary = (0, 718753793)
            tick(326)
            vm.pc = 331
            vm._write(61, memory.load(cells.pointer(59), 4, signed=True) + memory.load(cells.pointer(60), 4, signed=True), 8, 'once1.integer')
            tick(331)
            vm.pc = 336
            vm._write(43, cells.value(61) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 340
                width = vm.program.size(40891)
                vm._write(92657197, cells.value(458735618) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(336)
            vm.pc = 339
            vm.auxiliary = (0, 458735618)
            tick(339)
            vm.pc = 344
            vm._write(45, memory.load(cells.pointer(44), 8, signed=True) + memory.load(cells.pointer(62), 8, signed=True), 8, 'once1.integer')
            tick(344)
            vm.pc = 346
            vm._jump(13)
            continue
        if vm.block == 15:
            tick(346)
            vm.pc = 348
            vm._jump(12)
            continue
        if vm.block == 12:
            tick(348)
            _pointer(vm, 348, 3, 4, 63, (24, 64))
            tick(356)
            vm.pc = 360
            value = memory.load(cells.value(63), 1)
            vm._write(65, value, 4, 'high.load')
            tick(360)
            vm.pc = 367
            _host(vm, 360, 66, (0, 65), 37, None)
            tick(367)
            vm.pc = 372
            cells.copy_q_clear_owned(5, 67)
            tick(372)
            vm.pc = 381
            _host(vm, 372, 69, (67, 26, 70), 39, 68)
            tick(381)
            _pointer(vm, 381, 30, 5, 71, (24, 24))
            tick(389)
            vm.pc = 393
            vm._jump(16 if cells.value(11) != 0 else 17)
            continue
        if vm.block == 16:
            tick(393)
            vm.pc = 395
            vm._jump(18)
            continue
        if vm.block == 18:
            tick(395)
            _phi(vm, 395, (72, 2, 71, 16, 73, 19))
            tick(402)
            _phi(vm, 402, (74, 2, 70, 16, 75, 19))
            tick(409)
            vm.pc = 410
            tick(410)
            vm.pc = 413
            vm.auxiliary = (0, 1021333506)
            tick(413)
            vm.pc = 418
            vm._write(75, memory.load(cells.pointer(74), 8, signed=True) + memory.load(cells.pointer(35), 8, signed=True), 8, 'once1.integer')
            tick(418)
            vm.pc = 423
            vm._write(76, int(cells.value(74) > cells.value(24)), 4, 'L31.comparison')
            tick(423)
            vm.pc = 427
            vm._jump(19 if cells.value(76) != 0 else 20)
            continue
        if vm.block == 19:
            tick(427)
            _pointer(vm, 427, 2, 72, 73, (16,))
            tick(434)
            vm.pc = 438
            pointer = cells.value(72)
            value = memory.load(cells.pointer(77), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(438)
            vm.pc = 440
            vm._jump(18)
            continue
        if vm.block == 20:
            tick(440)
            vm.pc = 442
            vm._jump(17)
            continue
        if vm.block == 17:
            tick(442)
            vm.pc = 444
            vm._jump(21)
            continue
        if vm.block == 21:
            tick(444)
            _phi(vm, 444, (78, 2, 26, 17, 79, 22))
            tick(451)
            vm.pc = 452
            tick(452)
            vm.pc = 455
            vm.auxiliary = (0, 483555141)
            tick(455)
            vm.pc = 460
            a = memory.load(cells.pointer(78), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(80), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(81, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(460)
            vm.pc = 464
            vm._jump(23 if cells.value(81) != 0 else 24)
            continue
        if vm.block == 24:
            tick(464)
            vm.pc = 466
            vm._jump(25)
            continue
        if vm.block == 23:
            tick(466)
            _pointer(vm, 466, 25, 0, 82, (26, 83))
            tick(474)
            vm.pc = 479
            cells.copy_q_clear_owned(78, 84)
            tick(479)
            _pointer(vm, 479, 8, 82, 85, (24, 84))
            tick(487)
            _pointer(vm, 487, 7, 85, 86, (26, 87))
            tick(495)
            vm.pc = 499
            value = memory.load(cells.value(86), 1)
            vm._write(88, value, 4, 'high.load')
            tick(499)
            vm.pc = 500
            tick(500)
            vm.pc = 503
            vm.auxiliary = (0, 485643316)
            tick(503)
            vm.pc = 508
            vm._write(89, int(memory.load(cells.pointer(88), 1, signed=True) != memory.load(cells.pointer(77), 1, signed=True)), 4, 'L27.comparison')
            tick(508)
            vm.pc = 512
            vm._jump(26 if cells.value(89) != 0 else 22)
            continue
        if vm.block == 26:
            tick(512)
            _pointer(vm, 512, 7, 85, 90, (26, 13))
            tick(520)
            vm.pc = 524
            value = memory.load(cells.value(90), 1)
            vm._write(91, value, 4, 'high.load')
            tick(524)
            vm.pc = 529
            _convert(vm, 4, 91, 92)
            tick(529)
            vm.pc = 530
            tick(530)
            vm.pc = 533
            vm.auxiliary = (0, 270667891)
            tick(533)
            extra = _single(vm)
            vm.pc = 538
            left_pointer = cells.pointer(92)
            right_pointer = cells.pointer(3)
            destination_pointer = cells.pointer(93)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 542
                left_pointer = cells.pointer(27)
                right_pointer = cells.pointer(93)
                destination_pointer = cells.pointer(22)
                width = vm.program.size(51035)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(51035)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 542
                left_pointer = cells.pointer(27)
                right_pointer = cells.pointer(93)
                destination_pointer = cells.pointer(22)
                width = vm.program.size(51035)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(51035)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(538)
            vm.pc = 542
            vm._jump(27 if cells.value(93) != 0 else 22)
            continue
        if vm.block == 27:
            tick(542)
            _pointer(vm, 542, 7, 85, 94, (26, 26))
            tick(550)
            _pointer(vm, 550, 6, 94, 95, (24, 24))
            tick(558)
            vm.pc = 562
            vm._jump(28 if cells.value(11) != 0 else 29)
            continue
        if vm.block == 28:
            tick(562)
            vm.pc = 564
            vm._jump(30)
            continue
        if vm.block == 30:
            tick(564)
            _phi(vm, 564, (96, 2, 95, 28, 97, 31))
            tick(571)
            _phi(vm, 571, (98, 2, 71, 28, 99, 31))
            tick(578)
            _phi(vm, 578, (100, 2, 101, 28, 102, 31))
            tick(585)
            vm.pc = 586
            tick(586)
            vm.pc = 589
            vm.auxiliary = (0, 1513410562)
            tick(589)
            vm.pc = 594
            vm._write(102, memory.load(cells.pointer(100), 8, signed=True) + memory.load(cells.pointer(35), 8, signed=True), 8, 'once1.integer')
            tick(594)
            vm.pc = 599
            vm._write(103, int(cells.value(100) > cells.value(24)), 4, 'L31.comparison')
            tick(599)
            vm.pc = 603
            vm._jump(31 if cells.value(103) != 0 else 32)
            continue
        if vm.block == 31:
            tick(603)
            _pointer(vm, 603, 2, 96, 97, (16,))
            tick(610)
            vm.pc = 614
            value = memory.load(cells.value(96), 1)
            vm._write(104, value, 4, 'high.load')
            tick(614)
            _pointer(vm, 614, 2, 98, 99, (16,))
            tick(621)
            vm.pc = 625
            pointer = cells.value(98)
            value = memory.load(cells.pointer(104), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(625)
            vm.pc = 627
            vm._jump(30)
            continue
        if vm.block == 32:
            tick(627)
            vm.pc = 629
            vm._jump(29)
            continue
        if vm.block == 29:
            tick(629)
            _pointer(vm, 629, 7, 85, 105, (26, 18))
            tick(637)
            vm.pc = 641
            value = memory.load(cells.value(105), 1)
            vm._write(106, value, 4, 'high.load')
            tick(641)
            vm.pc = 645
            vm._jump(33 if cells.value(11) != 0 else 34)
            continue
        if vm.block == 33:
            tick(645)
            vm.pc = 650
            _convert(vm, 8, 106, 107)
            tick(650)
            _pointer(vm, 650, 5, 38, 108, (24, 107))
            tick(658)
            vm.pc = 662
            value = memory.load(cells.value(108), 1)
            vm._write(109, value, 4, 'high.load')
            tick(662)
            vm.pc = 664
            vm._jump(35)
            continue
        if vm.block == 35:
            tick(664)
            _phi(vm, 664, (110, 2, 24, 33, 111, 36))
            tick(671)
            _phi(vm, 671, (112, 2, 109, 33, 113, 36))
            tick(678)
            vm.pc = 683
            vm._write(114, int(cells.value(110) < cells.value(101)), 4, 'once18.unsigned_q')
            tick(683)
            vm.pc = 687
            vm._jump(36 if cells.value(114) != 0 else 37)
            continue
        if vm.block == 36:
            tick(687)
            vm.pc = 692
            _convert(vm, 4, 112, 115)
            tick(692)
            vm.pc = 693
            tick(693)
            vm.pc = 696
            vm.auxiliary = (0, 255181316)
            tick(696)
            vm.pc = 701
            vm._write(116, memory.load(cells.pointer(110), 8, signed=True) * memory.load(cells.pointer(48), 8, signed=True), 8, 'once0.integer')
            tick(701)
            vm.pc = 704
            vm.auxiliary = (0, 1368326145)
            tick(704)
            vm.pc = 709
            vm._write(117, memory.load(cells.pointer(116), 8, signed=True) + memory.load(cells.pointer(107), 8, signed=True), 8, 'once1.integer')
            tick(709)
            vm.pc = 714
            vm._write(118, cells.value(117) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 718
                width = vm.program.size(360601030)
                vm._write(118, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(714)
            vm.pc = 719
            _convert(vm, 4, 118, 119)
            tick(719)
            vm.pc = 722
            vm.auxiliary = (0, 39173)
            tick(722)
            vm.pc = 728
            vm._write(120, memory.load(cells.pointer(115), 4, signed=True) ^ memory.load(cells.pointer(119), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(728)
            _pointer(vm, 728, 30, 5, 121, (24, 110))
            tick(736)
            vm.pc = 740
            value = memory.load(cells.value(121), 1)
            vm._write(122, value, 4, 'high.load')
            tick(740)
            vm.pc = 745
            _convert(vm, 4, 122, 123)
            tick(745)
            vm.pc = 750
            vm._write(124, memory.load(cells.pointer(123), 4, signed=True) ^ memory.load(cells.pointer(120), 4, signed=True), 8, 'L14.binary_q')
            tick(750)
            vm.pc = 755
            vm._write(125, cells.value(124) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 759
                width = vm.program.size(218307768)
                vm._write(121, cells.value(125) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(755)
            vm.pc = 759
            pointer = cells.value(121)
            value = memory.load(cells.pointer(125), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(759)
            vm.pc = 762
            vm.auxiliary = (0, 1260270083)
            tick(762)
            vm.pc = 767
            vm._write(126, memory.load(cells.pointer(115), 4, signed=True) * memory.load(cells.pointer(58), 4, signed=True), 8, 'once0.integer')
            tick(767)
            vm.pc = 770
            vm.auxiliary = (0, 615636994)
            tick(770)
            vm.pc = 775
            vm._write(127, memory.load(cells.pointer(126), 4, signed=True) + memory.load(cells.pointer(60), 4, signed=True), 8, 'once1.integer')
            tick(775)
            vm.pc = 780
            vm._write(113, cells.value(127) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 784
                width = vm.program.size(46249)
                vm._write(92657197, cells.value(970977281) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(780)
            vm.pc = 783
            vm.auxiliary = (0, 970977281)
            tick(783)
            vm.pc = 788
            vm._write(111, memory.load(cells.pointer(110), 8, signed=True) + memory.load(cells.pointer(62), 8, signed=True), 8, 'once1.integer')
            tick(788)
            vm.pc = 790
            vm._jump(35)
            continue
        if vm.block == 37:
            tick(790)
            vm.pc = 792
            vm._jump(34)
            continue
        if vm.block == 34:
            tick(792)
            vm.pc = 796
            value = memory.load(cells.value(71), 1)
            vm._write(128, value, 4, 'high.load')
            tick(796)
            vm.pc = 801
            _convert(vm, 4, 128, 129)
            tick(801)
            vm.pc = 805
            value = memory.load(cells.value(1), 1)
            vm._write(130, value, 4, 'high.load')
            tick(805)
            vm.pc = 810
            _convert(vm, 4, 130, 131)
            tick(810)
            vm.pc = 811
            tick(811)
            vm.pc = 814
            vm.auxiliary = (0, 2040665715)
            tick(814)
            extra = _single(vm)
            vm.pc = 819
            left_pointer = cells.pointer(129)
            right_pointer = cells.pointer(131)
            destination_pointer = cells.pointer(132)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 823
                left_pointer = cells.pointer(38)
                right_pointer = cells.pointer(132)
                destination_pointer = cells.pointer(22)
                width = vm.program.size(1091)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(1091)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 823
                left_pointer = cells.pointer(38)
                right_pointer = cells.pointer(132)
                destination_pointer = cells.pointer(22)
                width = vm.program.size(1091)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(1091)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(819)
            vm.pc = 823
            vm._jump(38 if cells.value(132) != 0 else 22)
            continue
        if vm.block == 38:
            tick(823)
            _pointer(vm, 823, 30, 5, 133, (24, 62))
            tick(831)
            vm.pc = 835
            value = memory.load(cells.value(133), 1)
            vm._write(134, value, 4, 'high.load')
            tick(835)
            vm.pc = 840
            _convert(vm, 4, 134, 135)
            tick(840)
            _pointer(vm, 840, 2, 1, 136, (62,))
            tick(847)
            vm.pc = 851
            value = memory.load(cells.value(136), 1)
            vm._write(137, value, 4, 'high.load')
            tick(851)
            vm.pc = 856
            _convert(vm, 4, 137, 138)
            tick(856)
            vm.pc = 857
            tick(857)
            vm.pc = 860
            vm.auxiliary = (0, 1229105747)
            tick(860)
            vm.pc = 865
            vm._write(139, int(memory.load(cells.pointer(135), 4, signed=True) == memory.load(cells.pointer(138), 4, signed=True)), 4, 'once17.integer')
            tick(865)
            vm.pc = 869
            vm._jump(39 if cells.value(139) != 0 else 22)
            continue
        if vm.block == 39:
            tick(869)
            _pointer(vm, 869, 30, 5, 140, (24, 141))
            tick(877)
            vm.pc = 881
            value = memory.load(cells.value(140), 1)
            vm._write(142, value, 4, 'high.load')
            tick(881)
            vm.pc = 886
            _convert(vm, 4, 142, 143)
            tick(886)
            _pointer(vm, 886, 2, 1, 144, (141,))
            tick(893)
            vm.pc = 897
            value = memory.load(cells.value(144), 1)
            vm._write(145, value, 4, 'high.load')
            tick(897)
            vm.pc = 902
            _convert(vm, 4, 145, 146)
            tick(902)
            vm.pc = 903
            tick(903)
            vm.pc = 906
            vm.auxiliary = (0, 172115619)
            tick(906)
            vm.pc = 911
            vm._write(147, int(memory.load(cells.pointer(143), 4, signed=True) == memory.load(cells.pointer(146), 4, signed=True)), 4, 'once17.integer')
            tick(911)
            vm.pc = 915
            vm._jump(40 if cells.value(147) != 0 else 22)
            continue
        if vm.block == 40:
            tick(915)
            _pointer(vm, 915, 30, 5, 148, (24, 64))
            tick(923)
            vm.pc = 927
            value = memory.load(cells.value(148), 1)
            vm._write(149, value, 4, 'high.load')
            tick(927)
            vm.pc = 932
            _convert(vm, 4, 149, 150)
            tick(932)
            _pointer(vm, 932, 2, 1, 151, (64,))
            tick(939)
            vm.pc = 943
            value = memory.load(cells.value(151), 1)
            vm._write(152, value, 4, 'high.load')
            tick(943)
            vm.pc = 948
            _convert(vm, 4, 152, 153)
            tick(948)
            vm.pc = 949
            tick(949)
            vm.pc = 952
            vm.auxiliary = (0, 1125292035)
            tick(952)
            extra = _single(vm)
            vm.pc = 957
            left_pointer = cells.pointer(150)
            right_pointer = cells.pointer(153)
            destination_pointer = cells.pointer(154)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 961
                left_pointer = cells.pointer(41)
                right_pointer = cells.pointer(154)
                destination_pointer = cells.pointer(22)
                width = vm.program.size(5249)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(5249)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 961
                left_pointer = cells.pointer(41)
                right_pointer = cells.pointer(154)
                destination_pointer = cells.pointer(22)
                width = vm.program.size(5249)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(5249)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(957)
            vm.pc = 961
            vm._jump(41 if cells.value(154) != 0 else 22)
            continue
        if vm.block == 41:
            tick(961)
            vm.pc = 968
            _host(vm, 961, 21, (0, 155), 34, None)
            tick(968)
            vm.pc = 970
            vm._jump(25)
            continue
        if vm.block == 22:
            tick(970)
            vm.pc = 971
            tick(971)
            vm.pc = 974
            vm.auxiliary = (0, 1761681410)
            tick(974)
            vm.pc = 979
            vm._write(79, memory.load(cells.pointer(78), 4, signed=True) + memory.load(cells.pointer(16), 4, signed=True), 8, 'once1.integer')
            tick(979)
            vm.pc = 981
            vm._jump(21)
            continue
        if vm.block == 25:
            tick(981)
            _phi(vm, 981, (156, 2, 16, 41, 157, 24))
            tick(988)
            vm.pc = 989
            tick(989)
            vm.pc = 992
            vm.auxiliary = (0, 1609730563)
            tick(992)
            extra = _single(vm)
            vm.pc = 997
            left_pointer = cells.pointer(156)
            right_pointer = cells.pointer(157)
            destination_pointer = cells.pointer(158)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 1001
                left_pointer = cells.pointer(42)
                right_pointer = cells.pointer(158)
                destination_pointer = cells.pointer(43)
                width = vm.program.size(49794)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(49794)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 1001
                left_pointer = cells.pointer(42)
                right_pointer = cells.pointer(158)
                destination_pointer = cells.pointer(43)
                width = vm.program.size(49794)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(49794)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(997)
            vm.pc = 1001
            vm._jump(42 if cells.value(158) != 0 else 43)
            continue
        if vm.block == 42:
            tick(1001)
            vm.pc = 1003
            vm._jump(44)
            continue
        if vm.block == 44:
            tick(1003)
            _phi(vm, 1003, (159, 2, 26, 42, 160, 45))
            tick(1010)
            vm.pc = 1011
            tick(1011)
            vm.pc = 1014
            vm.auxiliary = (0, 1751264293)
            tick(1014)
            vm.pc = 1019
            a = memory.load(cells.pointer(159), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(80), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(161, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(1019)
            vm.pc = 1023
            vm._jump(46 if cells.value(161) != 0 else 47)
            continue
        if vm.block == 47:
            tick(1023)
            vm.pc = 1025
            vm._jump(48)
            continue
        if vm.block == 46:
            tick(1025)
            _pointer(vm, 1025, 25, 0, 162, (26, 83))
            tick(1033)
            vm.pc = 1038
            cells.copy_q_clear_owned(159, 163)
            tick(1038)
            _pointer(vm, 1038, 8, 162, 164, (24, 163))
            tick(1046)
            _pointer(vm, 1046, 7, 164, 165, (26, 87))
            tick(1054)
            vm.pc = 1058
            value = memory.load(cells.value(165), 1)
            vm._write(166, value, 4, 'high.load')
            tick(1058)
            vm.pc = 1059
            tick(1059)
            vm.pc = 1062
            vm.auxiliary = (0, 1306706388)
            tick(1062)
            vm.pc = 1067
            vm._write(167, int(memory.load(cells.pointer(166), 1, signed=True) != memory.load(cells.pointer(77), 1, signed=True)), 4, 'L27.comparison')
            tick(1067)
            vm.pc = 1071
            vm._jump(45 if cells.value(167) != 0 else 49)
            continue
        if vm.block == 49:
            tick(1071)
            vm.pc = 1073
            vm._jump(48)
            continue
        if vm.block == 45:
            tick(1073)
            vm.pc = 1074
            tick(1074)
            vm.pc = 1077
            vm.auxiliary = (0, 1425641473)
            tick(1077)
            vm.pc = 1082
            vm._write(160, memory.load(cells.pointer(159), 4, signed=True) + memory.load(cells.pointer(16), 4, signed=True), 8, 'once1.integer')
            tick(1082)
            vm.pc = 1084
            vm._jump(44)
            continue
        if vm.block == 48:
            tick(1084)
            _phi(vm, 1084, (168, 2, 159, 49, 169, 47))
            tick(1091)
            vm.pc = 1092
            tick(1092)
            vm.pc = 1095
            vm.auxiliary = (0, 1456612163)
            tick(1095)
            extra = _single(vm)
            vm.pc = 1100
            left_pointer = cells.pointer(168)
            right_pointer = cells.pointer(169)
            destination_pointer = cells.pointer(170)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 1104
                left_pointer = cells.pointer(50)
                right_pointer = cells.pointer(170)
                destination_pointer = cells.pointer(51)
                width = vm.program.size(61001)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(61001)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 1104
                left_pointer = cells.pointer(50)
                right_pointer = cells.pointer(170)
                destination_pointer = cells.pointer(51)
                width = vm.program.size(61001)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(61001)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(1100)
            vm.pc = 1104
            vm._jump(50 if cells.value(170) != 0 else 51)
            continue
        if vm.block == 50:
            tick(1104)
            vm.pc = 1106
            vm._jump(52)
            continue
        if vm.block == 52:
            tick(1106)
            _phi(vm, 1106, (171, 2, 168, 50, 172, 53))
            tick(1113)
            _phi(vm, 1113, (173, 2, 169, 50, 174, 53))
            tick(1120)
            _phi(vm, 1120, (175, 2, 26, 50, 176, 53))
            tick(1127)
            vm.pc = 1128
            tick(1128)
            vm.pc = 1131
            vm.auxiliary = (0, 745731269)
            tick(1131)
            vm.pc = 1136
            a = memory.load(cells.pointer(175), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(80), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(177, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(1136)
            vm.pc = 1140
            vm._jump(54 if cells.value(177) != 0 else 55)
            continue
        if vm.block == 55:
            tick(1140)
            vm.pc = 1141
            tick(1141)
            vm.pc = 1144
            vm.auxiliary = (0, 1341271619)
            tick(1144)
            vm.pc = 1149
            vm._write(178, int(memory.load(cells.pointer(171), 4, signed=True) == memory.load(cells.pointer(169), 4, signed=True)), 4, 'once17.integer')
            tick(1149)
            vm.pc = 1153
            vm._jump(56 if cells.value(178) != 0 else 57)
            continue
        if vm.block == 54:
            tick(1153)
            _pointer(vm, 1153, 25, 0, 179, (26, 83))
            tick(1161)
            vm.pc = 1166
            cells.copy_q_clear_owned(175, 180)
            tick(1166)
            _pointer(vm, 1166, 8, 179, 181, (24, 180))
            tick(1174)
            _pointer(vm, 1174, 7, 181, 182, (26, 87))
            tick(1182)
            vm.pc = 1186
            value = memory.load(cells.value(182), 1)
            vm._write(183, value, 4, 'high.load')
            tick(1186)
            vm.pc = 1187
            tick(1187)
            vm.pc = 1190
            vm.auxiliary = (0, 2009209844)
            tick(1190)
            vm.pc = 1195
            vm._write(184, int(memory.load(cells.pointer(183), 1, signed=True) != memory.load(cells.pointer(77), 1, signed=True)), 4, 'L30.comparison')
            tick(1195)
            vm.pc = 1199
            vm._jump(58 if cells.value(184) != 0 else 53)
            continue
        if vm.block == 58:
            tick(1199)
            _pointer(vm, 1199, 7, 181, 185, (26, 13))
            tick(1207)
            vm.pc = 1211
            value = memory.load(cells.value(185), 1)
            vm._write(186, value, 4, 'high.load')
            tick(1211)
            vm.pc = 1216
            _convert(vm, 4, 186, 187)
            tick(1216)
            vm.pc = 1217
            tick(1217)
            vm.pc = 1220
            vm.auxiliary = (0, 1891817507)
            tick(1220)
            vm.pc = 1225
            vm._write(188, int(memory.load(cells.pointer(187), 4, signed=True) == memory.load(cells.pointer(3), 4, signed=True)), 4, 'once17.integer')
            tick(1225)
            vm.pc = 1229
            vm._jump(59 if cells.value(188) != 0 else 53)
            continue
        if vm.block == 59:
            tick(1229)
            _pointer(vm, 1229, 7, 181, 189, (26, 16))
            tick(1237)
            vm.pc = 1241
            value = memory.load(cells.value(189), 4)
            vm._write(190, value, 4, 'high.load')
            tick(1241)
            _pointer(vm, 1241, 25, 0, 191, (26, 26))
            tick(1249)
            vm.pc = 1253
            value = memory.load(cells.value(191), 4)
            vm._write(192, value, 4, 'high.load')
            tick(1253)
            vm.pc = 1258
            vm._write(193, memory.load(cells.pointer(190), 4, signed=True) ^ memory.load(cells.pointer(192), 4, signed=True), 8, 'L14.binary_q')
            tick(1258)
            vm.pc = 1263
            vm._write(194, int(cells.value(193) < cells.value(173)), 4, 'once18.unsigned_q')
            tick(1263)
            vm.pc = 1267
            vm._jump(60 if cells.value(194) != 0 else 61)
            continue
        if vm.block == 60:
            tick(1267)
            vm.pc = 1269
            vm._jump(61)
            continue
        if vm.block == 61:
            tick(1269)
            _phi(vm, 1269, (195, 2, 175, 60, 171, 59))
            tick(1276)
            _phi(vm, 1276, (196, 2, 193, 60, 173, 59))
            tick(1283)
            vm.pc = 1285
            vm._jump(53)
            continue
        if vm.block == 53:
            tick(1285)
            _phi(vm, 1285, (172, 3, 195, 61, 171, 58, 171, 54))
            tick(1294)
            _phi(vm, 1294, (174, 3, 196, 61, 173, 58, 173, 54))
            tick(1303)
            vm.pc = 1304
            tick(1304)
            vm.pc = 1307
            vm.auxiliary = (0, 971911169)
            tick(1307)
            vm.pc = 1312
            vm._write(176, memory.load(cells.pointer(175), 4, signed=True) + memory.load(cells.pointer(16), 4, signed=True), 8, 'once1.integer')
            tick(1312)
            vm.pc = 1314
            vm._jump(52)
            continue
        if vm.block == 56:
            tick(1314)
            vm.pc = 1316
            vm._jump(62)
            continue
        if vm.block == 62:
            tick(1316)
            _phi(vm, 1316, (197, 2, 171, 56, 198, 63))
            tick(1323)
            _phi(vm, 1323, (199, 2, 169, 56, 200, 63))
            tick(1330)
            _phi(vm, 1330, (201, 2, 26, 56, 202, 63))
            tick(1337)
            vm.pc = 1338
            tick(1338)
            vm.pc = 1341
            vm.auxiliary = (0, 1962043813)
            tick(1341)
            vm.pc = 1346
            a = memory.load(cells.pointer(201), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(80), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(203, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(1346)
            vm.pc = 1350
            vm._jump(64 if cells.value(203) != 0 else 65)
            continue
        if vm.block == 65:
            tick(1350)
            vm.pc = 1352
            vm._jump(57)
            continue
        if vm.block == 64:
            tick(1352)
            _pointer(vm, 1352, 25, 0, 204, (26, 83))
            tick(1360)
            vm.pc = 1365
            cells.copy_q_clear_owned(201, 205)
            tick(1365)
            _pointer(vm, 1365, 8, 204, 206, (24, 205))
            tick(1373)
            _pointer(vm, 1373, 7, 206, 207, (26, 87))
            tick(1381)
            vm.pc = 1385
            value = memory.load(cells.value(207), 1)
            vm._write(208, value, 4, 'high.load')
            tick(1385)
            vm.pc = 1386
            tick(1386)
            vm.pc = 1389
            vm.auxiliary = (0, 1203937700)
            tick(1389)
            vm.pc = 1394
            vm._write(209, int(memory.load(cells.pointer(208), 1, signed=True) != memory.load(cells.pointer(77), 1, signed=True)), 4, 'L27.comparison')
            tick(1394)
            vm.pc = 1398
            vm._jump(66 if cells.value(209) != 0 else 63)
            continue
        if vm.block == 66:
            tick(1398)
            _pointer(vm, 1398, 7, 206, 210, (26, 16))
            tick(1406)
            vm.pc = 1410
            value = memory.load(cells.value(210), 4)
            vm._write(211, value, 4, 'high.load')
            tick(1410)
            _pointer(vm, 1410, 25, 0, 212, (26, 26))
            tick(1418)
            vm.pc = 1422
            value = memory.load(cells.value(212), 4)
            vm._write(213, value, 4, 'high.load')
            tick(1422)
            vm.pc = 1427
            vm._write(214, memory.load(cells.pointer(211), 4, signed=True) ^ memory.load(cells.pointer(213), 4, signed=True), 8, 'L14.binary_q')
            tick(1427)
            vm.pc = 1432
            vm._write(215, int(cells.value(214) < cells.value(199)), 4, 'once18.unsigned_q')
            tick(1432)
            vm.pc = 1436
            vm._jump(67 if cells.value(215) != 0 else 68)
            continue
        if vm.block == 67:
            tick(1436)
            vm.pc = 1438
            vm._jump(68)
            continue
        if vm.block == 68:
            tick(1438)
            _phi(vm, 1438, (216, 2, 201, 67, 197, 66))
            tick(1445)
            _phi(vm, 1445, (217, 2, 214, 67, 199, 66))
            tick(1452)
            vm.pc = 1454
            vm._jump(63)
            continue
        if vm.block == 63:
            tick(1454)
            _phi(vm, 1454, (198, 2, 216, 68, 197, 64))
            tick(1461)
            _phi(vm, 1461, (200, 2, 217, 68, 199, 64))
            tick(1468)
            vm.pc = 1469
            tick(1469)
            vm.pc = 1472
            vm.auxiliary = (0, 1314877442)
            tick(1472)
            vm.pc = 1477
            vm._write(202, memory.load(cells.pointer(201), 4, signed=True) + memory.load(cells.pointer(16), 4, signed=True), 8, 'once1.integer')
            tick(1477)
            vm.pc = 1479
            vm._jump(62)
            continue
        if vm.block == 57:
            tick(1479)
            _phi(vm, 1479, (218, 2, 197, 65, 171, 55))
            tick(1486)
            vm.pc = 1488
            vm._jump(51)
            continue
        if vm.block == 51:
            tick(1488)
            _phi(vm, 1488, (219, 2, 218, 57, 168, 48))
            tick(1495)
            _pointer(vm, 1495, 25, 0, 220, (26, 83))
            tick(1503)
            vm.pc = 1508
            cells.copy_q_clear_owned(219, 221)
            tick(1508)
            _pointer(vm, 1508, 8, 220, 222, (24, 221))
            tick(1516)
            _pointer(vm, 1516, 7, 222, 223, (26, 87))
            tick(1524)
            vm.pc = 1528
            value = memory.load(cells.value(223), 1)
            vm._write(224, value, 4, 'high.load')
            tick(1528)
            vm.pc = 1529
            tick(1529)
            vm.pc = 1532
            vm.auxiliary = (0, 2003970868)
            tick(1532)
            vm.pc = 1537
            vm._write(225, int(memory.load(cells.pointer(224), 1, signed=True) != memory.load(cells.pointer(77), 1, signed=True)), 4, 'L30.comparison')
            tick(1537)
            vm.pc = 1541
            vm._jump(69 if cells.value(225) != 0 else 70)
            continue
        if vm.block == 69:
            tick(1541)
            _pointer(vm, 1541, 25, 0, 226, (26, 227))
            tick(1549)
            vm.pc = 1553
            value = memory.load(cells.value(226), 4)
            vm._write(228, value, 4, 'high.load')
            tick(1553)
            _pointer(vm, 1553, 25, 0, 229, (26, 26))
            tick(1561)
            vm.pc = 1565
            value = memory.load(cells.value(229), 4)
            vm._write(230, value, 4, 'high.load')
            tick(1565)
            vm.pc = 1566
            tick(1566)
            vm.pc = 1569
            vm.auxiliary = (0, 48495)
            tick(1569)
            vm.pc = 1575
            vm._write(231, memory.load(cells.pointer(228), 4, signed=True) ^ memory.load(cells.pointer(230), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1575)
            vm.pc = 1580
            vm._write(232, int(cells.value(231) > cells.value(26)), 4, 'L31.comparison')
            tick(1580)
            vm.pc = 1584
            vm._jump(71 if cells.value(232) != 0 else 72)
            continue
        if vm.block == 71:
            tick(1584)
            vm.pc = 1585
            tick(1585)
            vm.pc = 1588
            vm.auxiliary = (0, 1560342529)
            tick(1588)
            vm.pc = 1593
            vm._write(233, memory.load(cells.pointer(231), 4, signed=True) + memory.load(cells.pointer(169), 4, signed=True), 8, 'once1.integer')
            tick(1593)
            vm.pc = 1595
            vm._jump(72)
            continue
        if vm.block == 72:
            tick(1595)
            _phi(vm, 1595, (234, 2, 233, 71, 231, 69))
            tick(1602)
            vm.pc = 1606
            value = memory.load(cells.value(229), 4)
            vm._write(235, value, 4, 'high.load')
            tick(1606)
            vm.pc = 1607
            tick(1607)
            vm.pc = 1610
            vm.auxiliary = (0, 39765)
            tick(1610)
            vm.pc = 1616
            vm._write(236, memory.load(cells.pointer(234), 4, signed=True) ^ memory.load(cells.pointer(235), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1616)
            vm.pc = 1620
            pointer = cells.value(226)
            value = memory.load(cells.pointer(236), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(1620)
            vm.pc = 1622
            vm._jump(70)
            continue
        if vm.block == 70:
            tick(1622)
            vm.pc = 1627
            cells.copy_q_clear_owned(222, 237)
            tick(1627)
            vm.pc = 1631
            vm._jump(73 if cells.value(11) != 0 else 74)
            continue
        if vm.block == 73:
            tick(1631)
            vm.pc = 1633
            vm._jump(75)
            continue
        if vm.block == 75:
            tick(1633)
            _phi(vm, 1633, (238, 2, 239, 73, 240, 76))
            tick(1640)
            _phi(vm, 1640, (241, 2, 237, 73, 242, 76))
            tick(1647)
            vm.pc = 1648
            tick(1648)
            vm.pc = 1651
            vm.auxiliary = (0, 1259286529)
            tick(1651)
            vm.pc = 1656
            vm._write(240, memory.load(cells.pointer(238), 8, signed=True) + memory.load(cells.pointer(35), 8, signed=True), 8, 'once1.integer')
            tick(1656)
            vm.pc = 1661
            vm._write(243, int(cells.value(238) > cells.value(24)), 4, 'L31.comparison')
            tick(1661)
            vm.pc = 1665
            vm._jump(76 if cells.value(243) != 0 else 77)
            continue
        if vm.block == 76:
            tick(1665)
            _pointer(vm, 1665, 2, 241, 242, (16,))
            tick(1672)
            vm.pc = 1676
            pointer = cells.value(241)
            value = memory.load(cells.pointer(77), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1676)
            vm.pc = 1678
            vm._jump(75)
            continue
        if vm.block == 77:
            tick(1678)
            vm.pc = 1680
            vm._jump(74)
            continue
        if vm.block == 74:
            tick(1680)
            _pointer(vm, 1680, 7, 222, 244, (26, 26))
            tick(1688)
            _pointer(vm, 1688, 6, 244, 245, (24, 24))
            tick(1696)
            vm.pc = 1701
            _convert(vm, 8, 2, 246)
            tick(1701)
            vm.pc = 1705
            vm._jump(78 if cells.value(9) != 0 else 79)
            continue
        if vm.block == 78:
            tick(1705)
            vm.pc = 1707
            vm._jump(80)
            continue
        if vm.block == 80:
            tick(1707)
            _phi(vm, 1707, (247, 2, 246, 78, 248, 81))
            tick(1714)
            _phi(vm, 1714, (249, 2, 245, 78, 250, 81))
            tick(1721)
            _phi(vm, 1721, (251, 2, 1, 78, 252, 81))
            tick(1728)
            vm.pc = 1729
            tick(1729)
            vm.pc = 1732
            vm.auxiliary = (0, 1520234497)
            tick(1732)
            vm.pc = 1737
            vm._write(248, memory.load(cells.pointer(247), 8, signed=True) + memory.load(cells.pointer(35), 8, signed=True), 8, 'once1.integer')
            tick(1737)
            vm.pc = 1742
            vm._write(253, int(cells.value(247) > cells.value(24)), 4, 'L31.comparison')
            tick(1742)
            vm.pc = 1746
            vm._jump(81 if cells.value(253) != 0 else 82)
            continue
        if vm.block == 81:
            tick(1746)
            _pointer(vm, 1746, 2, 251, 252, (16,))
            tick(1753)
            vm.pc = 1757
            value = memory.load(cells.value(251), 1)
            vm._write(254, value, 4, 'high.load')
            tick(1757)
            _pointer(vm, 1757, 2, 249, 250, (16,))
            tick(1764)
            vm.pc = 1768
            pointer = cells.value(249)
            value = memory.load(cells.pointer(254), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1768)
            vm.pc = 1770
            vm._jump(80)
            continue
        if vm.block == 82:
            tick(1770)
            vm.pc = 1772
            vm._jump(79)
            continue
        if vm.block == 79:
            tick(1772)
            _pointer(vm, 1772, 25, 0, 255, (26, 26))
            tick(1780)
            vm.pc = 1784
            value = memory.load(cells.value(255), 4)
            vm._write(256, value, 4, 'high.load')
            tick(1784)
            vm.pc = 1789
            vm._write(257, memory.load(cells.pointer(256), 4, signed=True) ^ memory.load(cells.pointer(219), 4, signed=True), 8, 'L14.binary_q')
            tick(1789)
            vm.pc = 1790
            tick(1790)
            vm.pc = 1793
            vm.auxiliary = (0, 47735)
            tick(1793)
            vm.pc = 1799
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(258, memory.load(cells.pointer(257), 4, signed=True) ^ memory.load(cells.pointer(3), 4, signed=True), 8, 'typed.selector5.q')
            tick(1799)
            vm.pc = 1804
            vm._write(259, cells.value(258) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1808
                width = vm.program.size(360601030)
                vm._write(259, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1804)
            vm.pc = 1809
            _convert(vm, 4, 259, 260)
            tick(1809)
            vm.pc = 1814
            vm._write(261, memory.load(cells.pointer(260), 4, signed=True) & memory.load(cells.pointer(80), 4, signed=True), 8, 'L13.binary_q')
            tick(1814)
            vm.pc = 1819
            vm._write(262, cells.value(261) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1823
                width = vm.program.size(252598635)
                vm._write(7, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1819)
            _pointer(vm, 1819, 7, 222, 263, (26, 18))
            tick(1827)
            vm.pc = 1831
            pointer = cells.value(263)
            value = memory.load(cells.pointer(262), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1831)
            vm.pc = 1835
            vm._jump(83 if cells.value(11) != 0 else 84)
            continue
        if vm.block == 83:
            tick(1835)
            vm.pc = 1839
            vm._jump(85 if cells.value(11) != 0 else 84)
            continue
        if vm.block == 85:
            tick(1839)
            vm.pc = 1844
            _convert(vm, 8, 262, 264)
            tick(1844)
            _pointer(vm, 1844, 5, 38, 265, (24, 264))
            tick(1852)
            vm.pc = 1856
            value = memory.load(cells.value(265), 1)
            vm._write(266, value, 4, 'high.load')
            tick(1856)
            vm.pc = 1858
            vm._jump(86)
            continue
        if vm.block == 86:
            tick(1858)
            _phi(vm, 1858, (267, 2, 24, 85, 268, 87))
            tick(1865)
            _phi(vm, 1865, (269, 2, 266, 85, 270, 87))
            tick(1872)
            vm.pc = 1877
            vm._write(271, int(cells.value(267) < cells.value(101)), 4, 'once18.unsigned_q')
            tick(1877)
            vm.pc = 1881
            vm._jump(87 if cells.value(271) != 0 else 88)
            continue
        if vm.block == 87:
            tick(1881)
            vm.pc = 1886
            _convert(vm, 4, 269, 272)
            tick(1886)
            vm.pc = 1887
            tick(1887)
            vm.pc = 1890
            vm.auxiliary = (0, 1161056771)
            tick(1890)
            vm.pc = 1895
            vm._write(273, memory.load(cells.pointer(267), 8, signed=True) * memory.load(cells.pointer(48), 8, signed=True), 8, 'once0.integer')
            tick(1895)
            vm.pc = 1898
            vm.auxiliary = (0, 1567567873)
            tick(1898)
            vm.pc = 1903
            vm._write(274, memory.load(cells.pointer(273), 8, signed=True) + memory.load(cells.pointer(264), 8, signed=True), 8, 'once1.integer')
            tick(1903)
            vm.pc = 1908
            vm._write(275, cells.value(274) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1912
                width = vm.program.size(360601030)
                vm._write(275, cells.value(2) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1908)
            vm.pc = 1913
            _convert(vm, 4, 275, 276)
            tick(1913)
            vm.pc = 1916
            vm.auxiliary = (0, 27159)
            tick(1916)
            vm.pc = 1922
            vm._write(277, memory.load(cells.pointer(272), 4, signed=True) ^ memory.load(cells.pointer(276), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1922)
            _pointer(vm, 1922, 6, 244, 278, (24, 267))
            tick(1930)
            vm.pc = 1934
            value = memory.load(cells.value(278), 1)
            vm._write(279, value, 4, 'high.load')
            tick(1934)
            vm.pc = 1939
            _convert(vm, 4, 279, 280)
            tick(1939)
            vm.pc = 1942
            vm.auxiliary = (0, 38989)
            tick(1942)
            vm.pc = 1948
            vm._write(281, memory.load(cells.pointer(280), 4, signed=True) ^ memory.load(cells.pointer(277), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1948)
            vm.pc = 1953
            vm._write(282, cells.value(281) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1957
                width = vm.program.size(218307768)
                vm._write(278, cells.value(282) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1953)
            vm.pc = 1957
            pointer = cells.value(278)
            value = memory.load(cells.pointer(282), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(1957)
            vm.pc = 1960
            vm.auxiliary = (0, 1321894403)
            tick(1960)
            vm.pc = 1965
            vm._write(283, memory.load(cells.pointer(272), 4, signed=True) * memory.load(cells.pointer(58), 4, signed=True), 8, 'once0.integer')
            tick(1965)
            vm.pc = 1968
            vm.auxiliary = (0, 1057017857)
            tick(1968)
            vm.pc = 1973
            vm._write(284, memory.load(cells.pointer(283), 4, signed=True) + memory.load(cells.pointer(60), 4, signed=True), 8, 'once1.integer')
            tick(1973)
            vm.pc = 1978
            vm._write(270, cells.value(284) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 1982
                width = vm.program.size(51460)
                vm._write(92657197, cells.value(617545729) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(1978)
            vm.pc = 1981
            vm.auxiliary = (0, 617545729)
            tick(1981)
            vm.pc = 1986
            vm._write(268, memory.load(cells.pointer(267), 8, signed=True) + memory.load(cells.pointer(62), 8, signed=True), 8, 'once1.integer')
            tick(1986)
            vm.pc = 1988
            vm._jump(86)
            continue
        if vm.block == 88:
            tick(1988)
            vm.pc = 1990
            vm._jump(84)
            continue
        if vm.block == 84:
            tick(1990)
            vm.pc = 1997
            _host(vm, 1990, 286, (287,), 46, 285)
            tick(1997)
            vm.pc = 2002
            vm._write(288, cells.value(285) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 2006
                width = vm.program.size(104927175)
                vm._write(289, cells.value(255) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(2002)
            vm.pc = 2006
            value = memory.load(cells.value(255), 4)
            vm._write(289, value, 4, 'high.load')
            tick(2006)
            vm.pc = 2007
            tick(2007)
            vm.pc = 2010
            vm.auxiliary = (0, 65053)
            tick(2010)
            vm.pc = 2016
            vm._write(290, memory.load(cells.pointer(288), 4, signed=True) ^ memory.load(cells.pointer(289), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(2016)
            _pointer(vm, 2016, 7, 222, 291, (26, 16))
            tick(2024)
            vm.pc = 2028
            pointer = cells.value(291)
            value = memory.load(cells.pointer(290), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(2028)
            vm.pc = 2033
            vm._write(292, cells.value(3) & 255, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 2037
                width = vm.program.size(252598635)
                vm._write(7, cells.value(1) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(2033)
            _pointer(vm, 2033, 7, 222, 293, (26, 13))
            tick(2041)
            vm.pc = 2045
            pointer = cells.value(293)
            value = memory.load(cells.pointer(292), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2045)
            vm.pc = 2049
            pointer = cells.value(223)
            value = memory.load(cells.pointer(294), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2049)
            _pointer(vm, 2049, 7, 222, 295, (26, 296))
            tick(2057)
            vm.pc = 2061
            pointer = cells.value(295)
            value = memory.load(cells.pointer(77), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(2061)
            _pointer(vm, 2061, 25, 0, 297, (26, 227))
            tick(2069)
            vm.pc = 2073
            value = memory.load(cells.value(297), 4)
            vm._write(298, value, 4, 'high.load')
            tick(2073)
            vm.pc = 2077
            value = memory.load(cells.value(255), 4)
            vm._write(299, value, 4, 'high.load')
            tick(2077)
            vm.pc = 2080
            vm.auxiliary = (0, 52046)
            tick(2080)
            vm.pc = 2086
            vm._write(300, memory.load(cells.pointer(298), 4, signed=True) ^ memory.load(cells.pointer(299), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(2086)
            vm.pc = 2089
            vm.auxiliary = (0, 207425537)
            tick(2089)
            vm.pc = 2094
            vm._write(301, memory.load(cells.pointer(300), 4, signed=True) + memory.load(cells.pointer(16), 4, signed=True), 8, 'once1.integer')
            tick(2094)
            vm.pc = 2099
            vm._write(302, memory.load(cells.pointer(301), 4, signed=True) ^ memory.load(cells.pointer(299), 4, signed=True), 8, 'L14.binary_q')
            tick(2099)
            vm.pc = 2103
            pointer = cells.value(297)
            value = memory.load(cells.pointer(302), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(2103)
            vm.pc = 2110
            _host(vm, 2103, 21, (0, 155), 34, None)
            tick(2110)
            vm.pc = 2112
            vm._jump(43)
            continue
        if vm.block == 43:
            tick(2112)
            _phi(vm, 2112, (303, 2, 26, 84, 16, 25))
            tick(2119)
            vm.pc = 2121
            vm._jump(3)
            continue
        if vm.block == 3:
            tick(2121)
            _phi(vm, 2121, (304, 3, 169, 1, 169, 4, 303, 43))
            tick(2130)
            vm.pc = 2133
            vm.result = memory.load(cells.pointer(304), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('bootstrap left its fixed source blocks')


def _token_expire(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 0:
            tick(1)
            vm.pc = 4
            vm._allocate(31, 2)
            tick(4)
            vm.pc = 7
            vm._allocate(31, 3)
            tick(7)
            vm.pc = 10
            vm._allocate(31, 4)
            tick(10)
            vm.pc = 13
            vm._allocate(33, 5)
            tick(13)
            vm.pc = 20
            _host(vm, 13, 7, (8,), 36, 6)
            tick(20)
            vm.pc = 25
            vm._write(9, cells.value(6) & 4294967295, 8, 'once9.mask_q')
            if _read_pair_control(vm):
                vm.pc = 29
                width = vm.program.size(360589883)
                vm._write(2, cells.value(32) & ((1 << ((8 * width) & 63)) - 1), 8, "once9.mask_q")
            tick(25)
            vm.pc = 30
            cells.copy_q_clear_owned(2, 10)
            tick(30)
            vm.pc = 39
            _host(vm, 30, 12, (10, 13, 14), 38, 11)
            tick(39)
            vm.pc = 41
            vm._jump(1)
            continue
        if vm.block == 1:
            tick(41)
            _phi(vm, 41, (15, 2, 13, 0, 16, 2))
            tick(48)
            _phi(vm, 48, (17, 2, 13, 0, 18, 2))
            tick(55)
            vm.pc = 56
            tick(56)
            vm.pc = 59
            vm.auxiliary = (0, 378729893)
            tick(59)
            vm.pc = 64
            a = memory.load(cells.pointer(15), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(19), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(20, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(64)
            vm.pc = 68
            vm._jump(3 if cells.value(20) != 0 else 4)
            continue
        if vm.block == 4:
            tick(68)
            vm.pc = 69
            tick(69)
            vm.pc = 72
            vm.auxiliary = (0, 598898787)
            tick(72)
            vm.pc = 77
            vm._write(21, int(memory.load(cells.pointer(17), 4, signed=True) == memory.load(cells.pointer(13), 4, signed=True)), 4, 'once17.integer')
            tick(77)
            vm.pc = 81
            vm._jump(5 if cells.value(21) != 0 else 6)
            continue
        if vm.block == 3:
            tick(81)
            _pointer(vm, 81, 26, 0, 22, (13, 23))
            tick(89)
            vm.pc = 94
            cells.copy_q_clear_owned(15, 24)
            tick(94)
            _pointer(vm, 94, 9, 22, 25, (26, 24))
            tick(102)
            _pointer(vm, 102, 8, 25, 27, (13, 28))
            tick(110)
            vm.pc = 114
            value = memory.load(cells.value(27), 1)
            vm._write(29, value, 4, 'high.load')
            tick(114)
            vm.pc = 115
            tick(115)
            vm.pc = 118
            vm.auxiliary = (0, 1544733668)
            tick(118)
            vm.pc = 123
            vm._write(31, int(memory.load(cells.pointer(29), 1, signed=True) != memory.load(cells.pointer(30), 1, signed=True)), 4, 'L27.comparison')
            tick(123)
            vm.pc = 127
            vm._jump(7 if cells.value(31) != 0 else 2)
            continue
        if vm.block == 7:
            tick(127)
            vm.pc = 132
            cells.copy_q_clear_owned(17, 32)
            tick(132)
            _pointer(vm, 132, 31, 2, 33, (26, 32))
            tick(140)
            _pointer(vm, 140, 30, 33, 34, (13, 13))
            tick(148)
            vm.pc = 152
            pointer = cells.value(34)
            value = memory.load(cells.pointer(15), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(152)
            _pointer(vm, 152, 8, 25, 35, (13, 36))
            tick(160)
            vm.pc = 164
            value = memory.load(cells.value(35), 4)
            vm._write(37, value, 4, 'high.load')
            tick(164)
            _pointer(vm, 164, 26, 0, 38, (13, 13))
            tick(172)
            vm.pc = 176
            value = memory.load(cells.value(38), 4)
            vm._write(39, value, 4, 'high.load')
            tick(176)
            vm.pc = 177
            tick(177)
            vm.pc = 180
            vm.auxiliary = (0, 22613)
            tick(180)
            vm.pc = 186
            vm._write(40, memory.load(cells.pointer(37), 4, signed=True) ^ memory.load(cells.pointer(39), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(186)
            _pointer(vm, 186, 30, 33, 41, (13, 36))
            tick(194)
            vm.pc = 198
            pointer = cells.value(41)
            value = memory.load(cells.pointer(40), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(198)
            _pointer(vm, 198, 8, 25, 42, (13, 43))
            tick(206)
            vm.pc = 210
            value = memory.load(cells.value(42), 1)
            vm._write(44, value, 4, 'high.load')
            tick(210)
            _pointer(vm, 210, 30, 33, 45, (13, 46))
            tick(218)
            vm.pc = 222
            pointer = cells.value(45)
            value = memory.load(cells.pointer(44), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(222)
            vm.pc = 225
            vm.auxiliary = (0, 1416896514)
            tick(225)
            vm.pc = 230
            vm._write(47, memory.load(cells.pointer(17), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(230)
            vm.pc = 232
            vm._jump(2)
            continue
        if vm.block == 2:
            tick(232)
            _phi(vm, 232, (18, 2, 47, 7, 17, 3))
            tick(239)
            vm.pc = 240
            tick(240)
            vm.pc = 243
            vm.auxiliary = (0, 1978257410)
            tick(243)
            vm.pc = 248
            vm._write(16, memory.load(cells.pointer(15), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(248)
            vm.pc = 250
            vm._jump(1)
            continue
        if vm.block == 5:
            tick(250)
            vm.pc = 252
            vm._jump(8)
            continue
        if vm.block == 6:
            tick(252)
            vm.pc = 257
            cells.copy_q_clear_owned(17, 48)
            tick(257)
            _pointer(vm, 257, 31, 2, 49, (26, 26))
            tick(265)
            vm.pc = 270
            cells.copy_q_clear_owned(49, 50)
            tick(270)
            vm.pc = 279
            _host(vm, 270, 51, (50, 48, 52, 53), 47, None)
            tick(279)
            vm.pc = 284
            cells.copy_q_clear_owned(3, 54)
            tick(284)
            vm.pc = 293
            _host(vm, 284, 12, (54, 13, 14), 38, 55)
            tick(293)
            vm.pc = 298
            cells.copy_q_clear_owned(4, 56)
            tick(298)
            vm.pc = 307
            _host(vm, 298, 12, (56, 13, 14), 38, 57)
            tick(307)
            vm.pc = 309
            vm._jump(9)
            continue
        if vm.block == 9:
            tick(309)
            _phi(vm, 309, (58, 2, 13, 6, 59, 10))
            tick(316)
            _phi(vm, 316, (60, 2, 13, 6, 61, 10))
            tick(323)
            _phi(vm, 323, (62, 2, 13, 6, 63, 10))
            tick(330)
            vm.pc = 331
            tick(331)
            vm.pc = 334
            vm.auxiliary = (0, 1235402341)
            tick(334)
            vm.pc = 339
            a = memory.load(cells.pointer(58), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(17), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(64, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(339)
            vm.pc = 343
            vm._jump(11 if cells.value(64) != 0 else 12)
            continue
        if vm.block == 12:
            tick(343)
            vm.pc = 348
            cells.copy_q_clear_owned(5, 65)
            tick(348)
            vm.pc = 357
            _host(vm, 348, 12, (65, 13, 67), 38, 66)
            tick(357)
            vm.pc = 359
            vm._jump(13)
            continue
        if vm.block == 11:
            tick(359)
            vm.pc = 364
            cells.copy_q_clear_owned(58, 68)
            tick(364)
            _pointer(vm, 364, 31, 2, 69, (26, 68))
            tick(372)
            _pointer(vm, 372, 30, 69, 70, (13, 46))
            tick(380)
            vm.pc = 384
            value = memory.load(cells.value(70), 1)
            vm._write(71, value, 4, 'high.load')
            tick(384)
            vm.pc = 389
            _convert(vm, 4, 71, 72)
            tick(389)
            vm.pc = 390
            tick(390)
            vm.pc = 393
            vm.auxiliary = (0, 1137837683)
            tick(393)
            vm.pc = 398
            vm._write(73, int(memory.load(cells.pointer(72), 4, signed=True) == memory.load(cells.pointer(36), 4, signed=True)), 4, 'once17.integer')
            tick(398)
            vm.pc = 402
            vm._jump(14 if cells.value(73) != 0 else 15)
            continue
        if vm.block == 14:
            tick(402)
            vm.pc = 403
            tick(403)
            vm.pc = 406
            vm.auxiliary = (0, 1968824321)
            tick(406)
            vm.pc = 411
            vm._write(74, memory.load(cells.pointer(62), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(411)
            vm.pc = 416
            cells.copy_q_clear_owned(62, 75)
            tick(416)
            _pointer(vm, 416, 31, 3, 76, (26, 75))
            tick(424)
            vm.pc = 429
            cells.copy_q_clear_owned(76, 77)
            tick(429)
            vm.pc = 434
            cells.copy_q_clear_owned(69, 78)
            tick(434)
            vm.pc = 443
            _host(vm, 434, 80, (77, 78, 52), 49, 79)
            tick(443)
            vm.pc = 445
            vm._jump(10)
            continue
        if vm.block == 15:
            tick(445)
            vm.pc = 446
            tick(446)
            vm.pc = 449
            vm.auxiliary = (0, 1912954881)
            tick(449)
            vm.pc = 454
            vm._write(81, memory.load(cells.pointer(60), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(454)
            vm.pc = 459
            cells.copy_q_clear_owned(60, 82)
            tick(459)
            _pointer(vm, 459, 31, 4, 83, (26, 82))
            tick(467)
            vm.pc = 472
            cells.copy_q_clear_owned(83, 84)
            tick(472)
            vm.pc = 477
            cells.copy_q_clear_owned(69, 85)
            tick(477)
            vm.pc = 486
            _host(vm, 477, 80, (84, 85, 52), 49, 86)
            tick(486)
            vm.pc = 488
            vm._jump(10)
            continue
        if vm.block == 10:
            tick(488)
            _phi(vm, 488, (61, 2, 60, 14, 81, 15))
            tick(495)
            _phi(vm, 495, (63, 2, 74, 14, 62, 15))
            tick(502)
            vm.pc = 503
            tick(503)
            vm.pc = 506
            vm.auxiliary = (0, 1266737153)
            tick(506)
            vm.pc = 511
            vm._write(59, memory.load(cells.pointer(58), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(511)
            vm.pc = 513
            vm._jump(9)
            continue
        if vm.block == 13:
            tick(513)
            _phi(vm, 513, (87, 2, 13, 12, 88, 16))
            tick(520)
            _phi(vm, 520, (89, 2, 13, 12, 90, 16))
            tick(527)
            _phi(vm, 527, (91, 2, 13, 12, 92, 16))
            tick(534)
            _phi(vm, 534, (93, 2, 13, 12, 94, 16))
            tick(541)
            vm.pc = 542
            tick(542)
            vm.pc = 545
            vm.auxiliary = (0, 1207066133)
            tick(545)
            vm.pc = 550
            a = memory.load(cells.pointer(93), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(62), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(95, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(550)
            vm.pc = 554
            vm._jump(17 if cells.value(95) != 0 else 18)
            continue
        if vm.block == 18:
            tick(554)
            vm.pc = 556
            vm._jump(19)
            continue
        if vm.block == 17:
            tick(556)
            vm.pc = 561
            cells.copy_q_clear_owned(93, 96)
            tick(561)
            _pointer(vm, 561, 31, 3, 97, (26, 96))
            tick(569)
            _pointer(vm, 569, 30, 97, 98, (13, 36))
            tick(577)
            vm.pc = 581
            value = memory.load(cells.value(98), 4)
            vm._write(99, value, 4, 'high.load')
            tick(581)
            vm.pc = 582
            tick(582)
            vm.pc = 585
            vm.auxiliary = (0, 46913)
            tick(585)
            vm.pc = 590
            vm._write(100, memory.load(cells.pointer(9), 4, signed=True) - memory.load(cells.pointer(99), 4, signed=True), 8, 'typed.selector0.q')
            tick(590)
            vm.pc = 595
            vm._write(102, int(cells.value(100) >= cells.value(101)), 4, "once20.unsigned_q")
            tick(595)
            vm.pc = 600
            _convert(vm, 1, 102, 103)
            tick(600)
            vm.pc = 604
            vm._jump(20 if cells.value(102) != 0 else 21)
            continue
        if vm.block == 21:
            tick(604)
            vm.pc = 605
            tick(605)
            vm.pc = 608
            vm.auxiliary = (0, 1513803778)
            tick(608)
            vm.pc = 613
            vm._write(104, memory.load(cells.pointer(89), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(613)
            vm.pc = 616
            vm.auxiliary = (0, 814030849)
            tick(616)
            vm.pc = 621
            vm._write(105, memory.load(cells.pointer(91), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(621)
            vm.pc = 623
            vm._jump(16)
            continue
        if vm.block == 20:
            tick(623)
            vm.pc = 624
            tick(624)
            vm.pc = 627
            vm.auxiliary = (0, 941773125)
            tick(627)
            vm.pc = 632
            a = memory.load(cells.pointer(91), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(46), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(106, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(632)
            vm.pc = 635
            vm.auxiliary = (0, 4877)
            tick(635)
            vm.pc = 640
            vm._write(107, memory.load(cells.pointer(102), 1, signed=True) & memory.load(cells.pointer(106), 1, signed=True), 8, 'typed.selector1.q')
            tick(640)
            vm.pc = 644
            vm._jump(22 if cells.value(107) != 0 else 23)
            continue
        if vm.block == 22:
            tick(644)
            vm.pc = 645
            tick(645)
            vm.pc = 648
            vm.auxiliary = (0, 966361089)
            tick(648)
            vm.pc = 653
            vm._write(108, memory.load(cells.pointer(91), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(653)
            vm.pc = 656
            vm.auxiliary = (0, 1719865345)
            tick(656)
            vm.pc = 661
            vm._write(109, memory.load(cells.pointer(89), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(661)
            vm.pc = 663
            vm._jump(16)
            continue
        if vm.block == 23:
            tick(663)
            vm.pc = 664
            tick(664)
            vm.pc = 667
            vm.auxiliary = (0, 205824002)
            tick(667)
            vm.pc = 672
            vm._write(110, memory.load(cells.pointer(87), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(672)
            vm.pc = 677
            _convert(vm, 8, 87, 111)
            tick(677)
            _pointer(vm, 677, 33, 5, 112, (26, 111))
            tick(685)
            vm.pc = 689
            pointer = cells.value(112)
            value = memory.load(cells.pointer(99), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(689)
            vm.pc = 691
            vm._jump(16)
            continue
        if vm.block == 16:
            tick(691)
            _phi(vm, 691, (88, 3, 87, 22, 110, 23, 87, 21))
            tick(700)
            _phi(vm, 700, (90, 3, 109, 22, 89, 23, 104, 21))
            tick(709)
            _phi(vm, 709, (92, 3, 108, 22, 91, 23, 105, 21))
            tick(718)
            vm.pc = 719
            tick(719)
            vm.pc = 722
            vm.auxiliary = (0, 1071104002)
            tick(722)
            vm.pc = 727
            vm._write(94, memory.load(cells.pointer(93), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(727)
            vm.pc = 729
            vm._jump(13)
            continue
        if vm.block == 19:
            tick(729)
            _phi(vm, 729, (113, 2, 87, 18, 114, 24))
            tick(736)
            _phi(vm, 736, (115, 2, 89, 18, 116, 24))
            tick(743)
            _phi(vm, 743, (117, 2, 13, 18, 118, 24))
            tick(750)
            _phi(vm, 750, (119, 2, 13, 18, 120, 24))
            tick(757)
            vm.pc = 758
            tick(758)
            vm.pc = 761
            vm.auxiliary = (0, 1192387205)
            tick(761)
            vm.pc = 766
            a = memory.load(cells.pointer(119), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(60), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(121, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(766)
            vm.pc = 770
            vm._jump(25 if cells.value(121) != 0 else 26)
            continue
        if vm.block == 26:
            tick(770)
            vm.pc = 772
            vm._jump(27)
            continue
        if vm.block == 25:
            tick(772)
            vm.pc = 777
            cells.copy_q_clear_owned(119, 122)
            tick(777)
            _pointer(vm, 777, 31, 4, 123, (26, 122))
            tick(785)
            _pointer(vm, 785, 30, 123, 124, (13, 36))
            tick(793)
            vm.pc = 797
            value = memory.load(cells.value(124), 4)
            vm._write(125, value, 4, 'high.load')
            tick(797)
            vm.pc = 798
            tick(798)
            vm.pc = 801
            vm.auxiliary = (0, 38713)
            tick(801)
            vm.pc = 806
            vm._write(126, memory.load(cells.pointer(9), 4, signed=True) - memory.load(cells.pointer(125), 4, signed=True), 8, 'typed.selector0.q')
            tick(806)
            vm.pc = 811
            vm._write(127, int(cells.value(126) >= cells.value(101)), 4, "once20.unsigned_q")
            tick(811)
            vm.pc = 816
            _convert(vm, 1, 127, 128)
            tick(816)
            vm.pc = 820
            vm._jump(28 if cells.value(127) != 0 else 29)
            continue
        if vm.block == 29:
            tick(820)
            vm.pc = 821
            tick(821)
            vm.pc = 824
            vm.auxiliary = (0, 253890561)
            tick(824)
            vm.pc = 829
            vm._write(129, memory.load(cells.pointer(115), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(829)
            vm.pc = 832
            vm.auxiliary = (0, 468566017)
            tick(832)
            vm.pc = 837
            vm._write(130, memory.load(cells.pointer(117), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(837)
            vm.pc = 839
            vm._jump(24)
            continue
        if vm.block == 28:
            tick(839)
            vm.pc = 840
            tick(840)
            vm.pc = 843
            vm.auxiliary = (0, 1043510549)
            tick(843)
            vm.pc = 848
            a = memory.load(cells.pointer(117), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(46), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(131, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(848)
            vm.pc = 851
            vm.auxiliary = (0, 57615)
            tick(851)
            vm.pc = 856
            vm._write(132, memory.load(cells.pointer(127), 1, signed=True) & memory.load(cells.pointer(131), 1, signed=True), 8, 'typed.selector1.q')
            tick(856)
            vm.pc = 860
            vm._jump(30 if cells.value(132) != 0 else 31)
            continue
        if vm.block == 30:
            tick(860)
            vm.pc = 861
            tick(861)
            vm.pc = 864
            vm.auxiliary = (0, 253276161)
            tick(864)
            vm.pc = 869
            vm._write(133, memory.load(cells.pointer(117), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(869)
            vm.pc = 872
            vm.auxiliary = (0, 1726906370)
            tick(872)
            vm.pc = 877
            vm._write(134, memory.load(cells.pointer(115), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(877)
            vm.pc = 879
            vm._jump(24)
            continue
        if vm.block == 31:
            tick(879)
            vm.pc = 880
            tick(880)
            vm.pc = 883
            vm.auxiliary = (0, 1120776194)
            tick(883)
            vm.pc = 888
            vm._write(135, memory.load(cells.pointer(113), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(888)
            vm.pc = 893
            _convert(vm, 8, 113, 136)
            tick(893)
            _pointer(vm, 893, 33, 5, 137, (26, 136))
            tick(901)
            vm.pc = 905
            pointer = cells.value(137)
            value = memory.load(cells.pointer(125), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(905)
            vm.pc = 907
            vm._jump(24)
            continue
        if vm.block == 24:
            tick(907)
            _phi(vm, 907, (114, 3, 113, 30, 135, 31, 113, 29))
            tick(916)
            _phi(vm, 916, (116, 3, 134, 30, 115, 31, 129, 29))
            tick(925)
            _phi(vm, 925, (118, 3, 133, 30, 117, 31, 130, 29))
            tick(934)
            vm.pc = 935
            tick(935)
            vm.pc = 938
            vm.auxiliary = (0, 258674690)
            tick(938)
            vm.pc = 943
            vm._write(120, memory.load(cells.pointer(119), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(943)
            vm.pc = 945
            vm._jump(19)
            continue
        if vm.block == 27:
            tick(945)
            _phi(vm, 945, (138, 2, 13, 26, 139, 32))
            tick(952)
            vm.pc = 957
            vm._write(140, int(cells.value(138) < cells.value(113)), 4, 'once18.unsigned_q')
            tick(957)
            vm.pc = 961
            vm._jump(33 if cells.value(140) != 0 else 34)
            continue
        if vm.block == 34:
            tick(961)
            _pointer(vm, 961, 26, 0, 141, (13, 13))
            tick(969)
            vm.pc = 973
            value = memory.load(cells.value(141), 4)
            vm._write(142, value, 4, 'high.load')
            tick(973)
            vm.pc = 974
            tick(974)
            vm.pc = 977
            vm.auxiliary = (0, 56124)
            tick(977)
            vm.pc = 983
            vm._write(143, memory.load(cells.pointer(115), 4, signed=True) ^ memory.load(cells.pointer(142), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(983)
            _pointer(vm, 983, 26, 0, 144, (13, 145))
            tick(991)
            vm.pc = 995
            pointer = cells.value(144)
            value = memory.load(cells.pointer(143), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(995)
            vm.pc = 997
            vm._jump(8)
            continue
        if vm.block == 33:
            tick(997)
            vm.pc = 999
            vm._jump(35)
            continue
        if vm.block == 35:
            tick(999)
            _phi(vm, 999, (146, 2, 13, 33, 147, 36))
            tick(1006)
            vm.pc = 1007
            tick(1007)
            vm.pc = 1010
            vm.auxiliary = (0, 2059587621)
            tick(1010)
            vm.pc = 1015
            a = memory.load(cells.pointer(146), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(19), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(148, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(1015)
            vm.pc = 1019
            vm._jump(37 if cells.value(148) != 0 else 38)
            continue
        if vm.block == 38:
            tick(1019)
            vm.pc = 1021
            vm._jump(32)
            continue
        if vm.block == 37:
            tick(1021)
            _pointer(vm, 1021, 26, 0, 149, (13, 23))
            tick(1029)
            vm.pc = 1034
            cells.copy_q_clear_owned(146, 150)
            tick(1034)
            _pointer(vm, 1034, 9, 149, 151, (26, 150))
            tick(1042)
            _pointer(vm, 1042, 8, 151, 152, (13, 36))
            tick(1050)
            vm.pc = 1054
            value = memory.load(cells.value(152), 4)
            vm._write(153, value, 4, 'high.load')
            tick(1054)
            _pointer(vm, 1054, 26, 0, 154, (13, 13))
            tick(1062)
            vm.pc = 1066
            value = memory.load(cells.value(154), 4)
            vm._write(155, value, 4, 'high.load')
            tick(1066)
            vm.pc = 1067
            tick(1067)
            vm.pc = 1070
            vm.auxiliary = (0, 31245)
            tick(1070)
            vm.pc = 1076
            vm._write(156, memory.load(cells.pointer(153), 4, signed=True) ^ memory.load(cells.pointer(155), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(1076)
            vm.pc = 1081
            cells.copy_q_clear_owned(138, 157)
            tick(1081)
            _pointer(vm, 1081, 33, 5, 158, (26, 157))
            tick(1089)
            vm.pc = 1093
            value = memory.load(cells.value(158), 4)
            vm._write(159, value, 4, 'high.load')
            tick(1093)
            vm.pc = 1096
            vm.auxiliary = (0, 1004689411)
            tick(1096)
            extra = _single(vm)
            vm.pc = 1101
            left_pointer = cells.pointer(159)
            right_pointer = cells.pointer(156)
            destination_pointer = cells.pointer(160)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 1105
                left_pointer = cells.pointer(39)
                right_pointer = cells.pointer(160)
                destination_pointer = cells.pointer(40)
                width = vm.program.size(2244)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(2244)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 1105
                left_pointer = cells.pointer(39)
                right_pointer = cells.pointer(160)
                destination_pointer = cells.pointer(40)
                width = vm.program.size(2244)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(2244)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(1101)
            vm.pc = 1105
            vm._jump(39 if cells.value(160) != 0 else 40)
            continue
        if vm.block == 39:
            tick(1105)
            vm.pc = 1110
            cells.copy_q_clear_owned(151, 161)
            tick(1110)
            vm.pc = 1119
            _host(vm, 1110, 12, (161, 13, 52), 38, 162)
            tick(1119)
            vm.pc = 1121
            vm._jump(41)
            continue
        if vm.block == 40:
            tick(1121)
            vm.pc = 1123
            vm._jump(41)
            continue
        if vm.block == 41:
            tick(1123)
            _phi(vm, 1123, (163, 2, 164, 39, 13, 40))
            tick(1130)
            vm.pc = 1131
            tick(1131)
            vm.pc = 1134
            vm.auxiliary = (0, 1806833507)
            tick(1134)
            extra = _single(vm)
            vm.pc = 1139
            left_pointer = cells.pointer(163)
            right_pointer = cells.pointer(13)
            destination_pointer = cells.pointer(165)
            a = memory.load(left_pointer, 4, signed=True)
            b = memory.load(right_pointer, 4, signed=True)
            memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if extra:
                vm.pc = 1143
                left_pointer = cells.pointer(36)
                right_pointer = cells.pointer(165)
                destination_pointer = cells.pointer(32)
                width = vm.program.size(816)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(816)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            if _read_pair_control(vm):
                vm.pc = 1143
                left_pointer = cells.pointer(36)
                right_pointer = cells.pointer(165)
                destination_pointer = cells.pointer(32)
                width = vm.program.size(816)
                a = memory.load(left_pointer, width if width in (1,2,4) else 8, signed=True)
                width = vm.program.size(816)
                b = memory.load(right_pointer, width if width in (1,2,4) else 8, signed=True)
                memory.store(destination_pointer, int(a == b), 4, source='L26.comparison')
            tick(1139)
            vm.pc = 1143
            vm._jump(36 if cells.value(165) != 0 else 32)
            continue
        if vm.block == 36:
            tick(1143)
            vm.pc = 1144
            tick(1144)
            vm.pc = 1147
            vm.auxiliary = (0, 1866928130)
            tick(1147)
            vm.pc = 1152
            vm._write(147, memory.load(cells.pointer(146), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(1152)
            vm.pc = 1154
            vm._jump(35)
            continue
        if vm.block == 32:
            tick(1154)
            vm.pc = 1155
            tick(1155)
            vm.pc = 1158
            vm.auxiliary = (0, 462692353)
            tick(1158)
            vm.pc = 1163
            vm._write(139, memory.load(cells.pointer(138), 4, signed=True) + memory.load(cells.pointer(36), 4, signed=True), 8, 'once1.integer')
            tick(1163)
            vm.pc = 1165
            vm._jump(27)
            continue
        if vm.block == 8:
            tick(1165)
            vm.pc = 1166
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('bootstrap left its fixed source blocks')
