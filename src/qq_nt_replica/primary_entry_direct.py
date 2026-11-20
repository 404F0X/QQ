import sys
from hashlib import sha256
from threading import get_ident

from .errors import InputError
from .primary_ecrypt import _indexed_pointer, _store_cell
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable


PROGRAM_SHA256 = {'entry-prepare': 'da98f1ee6c39ffa41336ddc19681e0f1aaefbbdfa585ebda02442f3dbe0a5370',
                  'sdk-table-init': '999cd6aa948d3562adac0b15dcd9985a2edfe600faa4e643e6a8da7ad837e4fa'}
STATIC_RECORD_COUNT = {'entry-prepare': 83, 'sdk-table-init': 10}


def _source_frame(code, instance):
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is code:
            values = frame.f_locals
            if values.get('self', values.get('runtime')) is instance:
                return values
        frame = frame.f_back
    return None


def _invoke_frame(runtime, rva):
    from .primary_sign import PrimaryRuntime
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is PrimaryRuntime.invoke.__code__:
            values = frame.f_locals
            if values.get('self') is runtime and values.get('rva') == rva:
                return values
        frame = frame.f_back
    return None


def _authorize(vm, name):
    from .primary_caller import prepare
    from .primary_direct_scopes import PrimaryDirectScope
    from .primary_sign import PrimaryRuntime
    from .primary_signer import PrimarySigner
    runtime = vm.runtime
    scope = getattr(runtime, '_primary_direct_scope', None)
    if (type(scope) is not PrimaryDirectScope or scope.runtime is not runtime or
            vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            not runtime.primary_core or runtime._active_main is not None or runtime._active_failed or
            runtime._execute_thread != get_ident() or runtime._execute_depth != 1 or
            runtime._program_calls != [dict(name=name, arguments=(), hosts=None)] or
            not runtime.vms or runtime.vms[-1] is not vm):
        raise PrimarySemanticUnavailable('entry family requires its actual public initialized reader')
    scope._require_live()
    if not scope._valid_public():
        raise PrimarySemanticUnavailable('entry family lacks its original public owner')
    reader = _source_frame(PrimaryRuntime._execute_program.__code__, runtime)
    if (reader is None or reader.get('vm') is not vm or reader.get('name') != name or
            reader.get('arguments') != () or reader.get('hosts') is not None or
            getattr(vm, '_primary_entry_direct_used', False)):
        raise PrimarySemanticUnavailable('entry family requires its one-use fresh source reader')
    if name == 'sdk-table-init':
        registration = _source_frame(PrimaryRuntime.register_sdk_callbacks.__code__, runtime)
        initialize = _source_frame(PrimaryRuntime._initialize_sdk_table.__code__, runtime)
        if (registration is None or initialize is None or _invoke_frame(runtime, 0x1D2C850) is None or
                registration.get('lock') != runtime.image_base + 0x677C230 or
                runtime.locks.get(runtime.image_base + 0x677C230) != 1):
            raise PrimarySemanticUnavailable('SDK table requires its actual locked source registration')
        caller = scope._caller
        preparation = _source_frame(prepare.__code__, runtime)
        if caller is not None:
            caller = scope._require_caller()
            if (preparation is None or preparation.get('command') is not caller.command or
                    _invoke_frame(runtime, 0x1BF8090) is None):
                raise PrimarySemanticUnavailable('SDK table lacks its actual caller prepare wrapper')
        else:
            adapter = _source_frame(PrimaryRuntime._execute_caller_adapter_continued.__code__, runtime)
            sign = _source_frame(PrimarySigner._sign_body.__code__, scope.public_owner.signer)
            if (adapter is None or sign is None or adapter.get('classification') not in (1, 2) or
                    adapter.get('command') != sign.get('command') or
                    getattr(adapter.get('core'), '__self__', None) is not scope.public_owner.signer or
                    getattr(adapter.get('core'), '__func__', None) is not PrimarySigner._sign_material_continued):
                raise PrimarySemanticUnavailable('SDK table lacks its actual public caller adapter')
    else:
        bridge = _source_frame(PrimaryRuntime._execute_primary_continued.__code__, runtime)
        strings = _source_frame(PrimaryRuntime._execute_string_adapter_continued.__code__, runtime)
        material = _source_frame(PrimarySigner._sign_material_continued.__code__, scope.public_owner.signer)
        if bridge is None or strings is None or material is None:
            raise PrimarySemanticUnavailable('entry preparation lacks its actual public string bridge')
        workspace, stack = material.get('workspace'), strings.get('stack_address')
        if (type(workspace) is not int or stack != workspace + 256 or strings.get('sret') != workspace + 96 or
                tuple(strings.get(key) for key in ('a', 'b', 'command', 'd')) !=
                (workspace, workspace + 24, workspace + 48, workspace + 72) or
                bridge.get('selected') != 1 or bridge.get('target') != runtime.image_base + 0x2DE862D):
            raise PrimarySemanticUnavailable('entry preparation has a foreign string adapter owner')
        arguments = (4, strings.get('a_pointer'), strings.get('a_length'), strings.get('b_pointer'),
                     strings.get('b_length'), strings.get('command_pointer'), strings.get('command_length'),
                     stack + 0x70, stack + 0x6C, strings.get('policy') & 0xFFFFFFFF,
                     strings.get('d_pointer'), strings.get('d_length'))
        if bridge.get('arguments') != arguments:
            raise PrimarySemanticUnavailable('entry preparation has a foreign twelve-argument bridge ABI')
    vm._primary_entry_direct_used = True


def execute_primary_entry(vm, name, *, max_steps=1_000_000, execution_report=None):
    if type(max_steps) is not int or max_steps < 1:
        raise InputError('max_steps must be a positive integer')
    if (type(vm) is not PrimaryVM or name not in PROGRAM_SHA256 or
            sha256(vm.program.raw).hexdigest() != PROGRAM_SHA256[name] or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.arena_used, vm.auxiliary) !=
            (1, 0, None, True, 0, None) or vm.halted or vm.abort_reason is not None or vm.trace or vm.host_calls or
            any(getattr(vm, key) is not None for key in ('pending_once10', 'pending_once9', 'pending_l26',
                'pending_variadic', 'pending_native', 'private_iv_native_pending'))):
        raise PrimarySemanticUnavailable('entry family requires its fixed fresh nonpending source')
    _authorize(vm, name)
    state = dict(program=name, backend='DIRECT_ENTRY_LITERAL', sourceRecordCount=STATIC_RECORD_COUNT[name],
                 referenceRecordCount=0, completed=False, traceComplete=False, completeIndependentMain=False,
                 controlDomain='FIXED_SOURCE_WITH_NO_GF_ONCE9_ONCE10_OR_L26')
    if execution_report is not None:
        execution_report.clear()
        execution_report.update(state)
        state = execution_report
    vm.primary_entry_direct_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if state['referenceRecordCount'] >= max_steps:
            raise PrimaryProgramLimit(f'Python execution limit after{max_steps} instructions at word{vm.pc}')
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    {'entry-prepare': _entry_prepare, 'sdk-table-init': _sdk_table}[name](vm, tick)
    state['completed'] = True
    return vm.result


def _host(vm, word, end, signature, callee, arguments, destination):
    from .primary_sign import _invoke_host
    vm.pc = end
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    typ = vm.program.type(signature)
    result = _invoke_host(vm, address, arguments, signature, argument_types=typ.parameters[3:3 + len(arguments)])
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')


def _entry_prepare(vm, tick):
    tick(1)
    vm.pc = 4
    vm._allocate(4, 0)
    tick(4)
    vm.pc = 7
    vm._allocate(6, 1)
    tick(7)
    vm.pc = 12
    vm.cells.copy_q_clear_owned(0, 2)
    tick(12)
    _host(vm, 12, 21, 10, 4, (2, 5, 6), 3)
    for word, destination, index, source in (
            (21, 7, 8, 9), (33, 10, 11, 12), (45, 13, 14, 15),
            (57, 16, 17, 18), (69, 19, 20, 18), (81, 21, 22, 23),
            (93, 24, 25, 15), (105, 26, 27, 18), (117, 28, 29, 18)):
        tick(word)
        _indexed_pointer(vm, word, destination, 4, 0, (8, index))
        tick(word + 8)
        _store_cell(vm, word + 8, 1, source, destination)
    tick(129)
    _host(vm, 129, 136, 14, 31, (7,), 30)
    tick(136)
    vm.pc = 137
    tick(137)
    vm.pc = 140
    vm.auxiliary = (0, 1600295843)
    tick(140)
    vm.pc = 145
    vm._write(33, int(vm._signed_cell(30, 13) == vm._signed_cell(32, 13)), 4, 'once17.integer')
    tick(145)
    vm.pc = 149
    vm._jump(1 if vm.cells.value(33) != 0 else 2)
    if vm.block == 1:
        tick(149)
        vm.pc = 151
        vm._jump(3)
    else:
        tick(151)
        vm.pc = 156
        vm.cells.copy_q_clear_owned(1, 34)
        tick(156)
        _host(vm, 156, 165, 10, 4, (34, 5, 36), 35)
        for word, destination, index, source in (
                (165, 37, 8, 38), (177, 39, 11, 12), (189, 40, 14, 18),
                (201, 41, 17, 42), (213, 43, 20, 44), (225, 45, 22, 46),
                (237, 47, 25, 12), (249, 48, 27, 49), (261, 50, 29, 51),
                (273, 52, 53, 54), (285, 55, 6, 56), (297, 57, 58, 12),
                (309, 59, 60, 44), (321, 61, 62, 63), (333, 64, 65, 66),
                (345, 67, 68, 69), (357, 70, 71, 44), (369, 72, 73, 63),
                (381, 74, 75, 66), (393, 76, 77, 78), (405, 79, 80, 51),
                (417, 81, 82, 44), (429, 83, 84, 63), (441, 85, 86, 54)):
            tick(word)
            _indexed_pointer(vm, word, destination, 6, 1, (8, index))
            tick(word + 8)
            _store_cell(vm, word + 8, 1, source, destination)
        tick(453)
        _host(vm, 453, 461, 19, 88, (30, 37), 87)
        tick(461)
        vm.pc = 466
        vm.cells.copy_q_clear_owned(87, 89)
        tick(466)
        vm.pc = 468
        vm._jump(3)
    tick(468)
    vm.pc = 475
    if vm.predecessor == 1:
        value = vm.cells.value(91)
    elif vm.predecessor == 2:
        value = vm.cells.value(89)
    else:
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(90, value, 8, 'L9.phi_q')
    tick(475)
    vm.pc = 478
    vm.result, vm.halted = vm._signed_cell(90, 1) & ((1 << 64) - 1), True


def _sdk_table(vm, tick):
    tick(1)
    _indexed_pointer(vm, 1, 0, 5, 1, (2, 2))
    tick(9)
    _host(vm, 9, 17, 9, 4, (0, 5), 3)
    tick(17)
    vm.pc = 21
    vm._jump(1 if vm.cells.value(3) != 0 else 2)
    if vm.block == 2:
        tick(21)
        _indexed_pointer(vm, 21, 6, 12, 7, (8, 8, 8))
        tick(30)
        _indexed_pointer(vm, 30, 9, 5, 1, (2, 2))
        tick(38)
        _host(vm, 38, 47, 15, 11, (6, 9, 5), 10)
        tick(47)
        _indexed_pointer(vm, 47, 12, 5, 1, (2, 2))
        tick(55)
        _host(vm, 55, 64, 17, 14, (12, 8, 5), 13)
        tick(64)
        vm.pc = 66
        vm._jump(1)
    tick(66)
    vm.pc, vm.halted, vm.result = 67, True, None
