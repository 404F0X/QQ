from .primary_vm import PrimarySemanticUnavailable


def _host(vm, word, consumed, callee, arguments, signature, destination):
    from .primary_sign import _invoke_host

    vm.pc = consumed
    address = vm.cells.value(callee)
    vm.host_calls.append((word, address, arguments, signature))
    result = _invoke_host(vm, address, arguments, signature)
    vm._write(destination, result, 8, 'high.native_result_q')


def commit_primary_source2583(vm):
    if vm.pc != 1:
        return False
    state = vm.primary_source2583_state = {'phase': 'private_buffer', 'length': None,
                                          'completed_hosts': 0, 'retained_steps': 0}
    vm.pc = 4
    vm._allocate(7, 3)
    vm.pc = 8
    vm.auxiliary = (0, 1282564948)
    vm.pc = 13
    value = int(vm._signed_cell(1, 3) != vm._signed_cell(4, 3))
    vm._write(5, value, 4, 'L27.comparison')
    vm.pc = 17
    vm._jump(1 if vm.cells.value(5) else 2)
    if vm.block != 2:
        vm.pc = 21
        vm._jump(3 if vm.cells.value(6) else 4)
        if vm.block == 3:
            vm._jump(5)
        else:
            vm._jump(6)
            state['phase'] = 'string_length'
            while True:
                vm.pc = 32
                if vm.predecessor == 4:
                    selected = 8
                elif vm.predecessor == 7:
                    selected = 9
                else:
                    raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
                vm._write(7, vm.cells.value(selected), 8, 'L9.phi_q')
                vm.pc = 39
                offset = vm.memory.load(vm.cells.pointer(7), 4)
                vm._write(10, vm.cells.value(1) + offset, 8, 'high.indexed_pointer_q')
                vm.pc = 43
                value = vm.memory.load(vm.cells.value(10), 1)
                vm._write(11, value, 4, 'high.load')
                vm.pc = 48
                vm.cells.copy_q_clear_owned(11, 12)
                vm.pc = 52
                vm.auxiliary = (0, 1988244340)
                vm.pc = 57
                value = int(vm._signed_cell(12, 4) != vm._signed_cell(13, 4))
                vm._write(14, value, 4, 'L30.comparison')
                vm.pc = 61
                vm._jump(7 if vm.cells.value(14) else 8)
                if vm.block == 8:
                    break
                vm.pc = 65
                vm.auxiliary = (0, 709922818)
                vm.pc = 70
                value = vm._signed_cell(7, 10) + vm._signed_cell(15, 10)
                vm._write(9, value, 8, 'once1.integer')
                vm._jump(6)
            vm.pc = 77
            vm._write(16, vm.cells.value(7) & 0xFFFFFFFF, 8, 'once9.mask_q')
            vm._jump(5)
        vm.pc = 86
        if vm.predecessor == 3:
            selected = 13
        elif vm.predecessor == 8:
            selected = 16
        else:
            raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
        value = vm.cells.value(selected)
        vm._write(17, value, 8, 'L9.phi_q')
        state['length'] = value & 0xFFFFFFFF
        vm.pc = 90
        vm.auxiliary = (0, 1583507795)
        vm.pc = 95
        value = int(vm._signed_cell(17, 4) == vm._signed_cell(18, 4))
        vm._write(19, value, 4, 'once17.integer')
        vm.pc = 99
        vm._jump(9 if vm.cells.value(19) else 10)
        if vm.block == 9:
            state['phase'] = 'singleton'
            _host(vm, 99, 105, 21, (), 11, 20)
            state['completed_hosts'] += 1
            vm.pc = 110
            vm.cells.copy_q_clear_owned(20, 22)
            vm.pc = 115
            vm.cells.copy_q_clear_owned(3, 23)
            vm.pc = 122
            offset = 5 * vm.memory.load(vm.cells.pointer(8), 4)
            vm.pc = 123
            offset += vm.memory.load(vm.cells.pointer(8), 4)
            vm._write(24, vm.cells.value(3) + offset, 8, 'high.indexed_pointer_q')
            state['phase'] = 'copy_input'
            _host(vm, 123, 132, 26, (24, 13, 27), 36, 25)
            state['completed_hosts'] += 1
            vm.pc = 137
            vm.cells.copy_q_clear_owned(17, 28)
            _host(vm, 137, 146, 30, (24, 1, 28), 38, 29)
            state['completed_hosts'] += 1
            vm.pc = 153
            offset = 1328 * vm.memory.load(vm.cells.pointer(13), 4)
            vm.pc = 154
            delta, _ = vm._indexed_offset(34, vm.memory.load(vm.cells.pointer(32), 4))
            offset += delta
            vm._write(31, vm.cells.value(22) + offset, 8, 'high.indexed_pointer_q')
            vm.pc = 161
            offset = 24 * vm.memory.load(vm.cells.pointer(8), 4)
            vm.pc = 162
            delta, _ = vm._indexed_offset(26, vm.memory.load(vm.cells.pointer(34), 4))
            offset += delta
            vm._write(33, vm.cells.value(31) + offset, 8, 'high.indexed_pointer_q')
            vm.pc = 166
            value = vm.memory.load(vm.cells.value(33), 8)
            vm._write(35, value, 8, 'high.load')
            vm.pc = 171
            vm.cells.copy_q_clear_owned(35, 36)
            state['phase'] = 'commit'
            _host(vm, 171, 181, 36, (22, 24, 17, 2), 42, 37)
            state['completed_hosts'] += 1
            vm._jump(10)
        vm._jump(2)
    vm.pc = 188
    vm.result = vm._signed_cell(38, 0) & ((1 << 64) - 1)
    vm.halted = True
    state['phase'] = 'complete'
    return True
