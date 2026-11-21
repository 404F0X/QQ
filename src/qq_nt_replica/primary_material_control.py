from .primary_material_prepare import _address, _lookup
from .primary_material_rounds import _less, _load, _next, _pointer, _store


_LOOKUP = {'cells': (3558, 3560, 3561, 3562, 3563, 3564, 3565, 3566, 3567, 3568, 3569, 3570, 3571, 3572, 3573,
           3574, 3575, 3576, 3577, 3578, 3579, 3580, 3581, 3582, 3583, 3584, 3585, 3586, 3587, 3588,
           3589, 3590, 3591, 3592, 3593, 3594, 3595, 3596, 3597, 3598, 3599, 3600, 3601, 3602, 3603,
           3604, 3605, 3606, 3607, 3608, 3609, 3610, 3611, 3612, 3613, 3614, 3615, 3616),
 'auxiliary': {3560: 215302145,
               3565: 53260,
               3570: 1345509107,
               3573: 22637,
               3574: 50230,
               3578: 848468483,
               3581: 1330828611,
               3587: 1562034691,
               3591: 64548,
               3592: 315875843,
               3598: 1165677059,
               3601: 59399,
               3602: 1476370947,
               3605: 252338691,
               3608: 31757,
               3609: 771584516,
               3612: 26671,
               3613: 1421558275,
               3614: 1483929187,
               3616: 2007149171},
 'flag0': (3601, 3608, 3612),
 'comparisons': (3570, 3578)}


def prepare_primary_material_control(vm):
    vm.primary_material_control_state = {'phase': 'capture', 'lookups': 0,
                                        'integrity_markers': 0, 'cleared_bytes': 0,
                                        'published_bytes': 0, 'retained_steps': 0}
    state = vm.primary_material_control_state
    vm.cells.copy_q_clear_owned(12, 3554)
    _store(vm, 145, 12, 8)
    state['cleared_bytes'] += 8
    initial = True
    state['phase'] = 'lookup'
    while True:
        vm._write(3555, vm.cells.value(145 if initial else 3556),
                  8, 'material_control.index_phi')
        if not _less(vm, 3555, 163, 3557):
            break
        node, missing = _lookup(vm, 0, 3555, 3559, state, recipe=_LOOKUP)
        if vm.cells.value(missing):
            _pointer(vm, 3554, 3555, 3621)
            _store(vm, 235, 3621, 1)
        else:
            _address(vm, 79, node, 3617, 145, 311)
            _load(vm, 3617, 3618, 8)
            _load(vm, 3618, 3619, 1)
            _pointer(vm, 3554, 3555, 3620)
            _store(vm, 3619, 3620, 1)
        state['published_bytes'] += 1
        vm.auxiliary = (0, 517787649)
        _next(vm, 3555, 163, 3556)
        initial = False
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 25696, 605, 602, False
    state['phase'] = 'complete'
    return True
