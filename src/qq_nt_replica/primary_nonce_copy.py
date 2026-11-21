from .primary_material_prepare import _address, _auxiliary, _binary
from .primary_material_rounds import _load, _store


_RECIPE = {
    'auxiliary': {997: 1428332628, 1005: 29773, 1006: 1807895764,
                  1010: 661417985, 1015: 5183, 1016: 1846733988,
                  1017: 1980934646, 1018: 13093, 1022: 2076348417,
                  1028: 1559402406, 1035: 1927213057, 1039: 1598195574,
                  1043: 2022846465, 1047: 401752422, 1051: 864890882,
                  1057: 695345446, 1061: 1423974402, 1065: 422714566,
                  1069: 957874178, 1073: 1252134134, 1079: 376571782},
    'flag0': (),
}


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'nonce_copy.phi')


def _phis(vm, destinations, sources):
    for destination, source in zip(destinations, sources):
        _phi(vm, destination, source)


def _condition(vm, left, right, destination, *, greater=False):
    _auxiliary(vm, _RECIPE, destination)
    typ = 3 if greater else 7
    first, second = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    vm._write(destination, int(first > second if greater else first != second),
              4, 'nonce_copy.condition')
    return bool(vm.cells.value(destination))


def _advance(vm, source, destination, source_next, value, destination_next, width, state, *, wide=False):
    _address(vm, 3 if width == 4 else 1, source, source_next, 163)
    _load(vm, source, value, width)
    _address(vm, 3 if width == 4 else 1, destination, destination_next, 163)
    _store(vm, value, destination, width, wide=wide)
    state['copied_bytes'] += width


def copy_primary_nonce(vm):
    vm.primary_nonce_copy_state = {'phase': 'copy', 'copied_bytes': 0, 'retained_steps': 0}
    state = vm.primary_nonce_copy_state
    _address(vm, 54, 90, 993, 145, 145)
    _address(vm, 54, 90, 994, 145, 145)
    vm.cells.copy_q_clear_owned(994, 995)
    _binary(vm, _RECIPE, 995, 169, 996, 7, 'and')
    selected = _condition(vm, 996, 145, 997)
    if selected:
        _advance(vm, 952, 994, 998, 999, 1000, 1, state)
    _phis(vm, (1001, 1002, 1003), (311, 1000, 998) if selected else (149, 994, 952))
    vm.cells.copy_q_clear_owned(1002, 1004)
    _binary(vm, _RECIPE, 1004, 169, 1005, 7, 'and')
    selected = _condition(vm, 1005, 145, 1006)
    if selected:
        _advance(vm, 1003, 1002, 1007, 1008, 1009, 1, state)
        _binary(vm, _RECIPE, 1001, 396, 1010, 3, 'add')
    _phis(vm, (1011, 1012, 1013), (1010, 1009, 1007) if selected else (1001, 1002, 1003))
    vm.cells.copy_q_clear_owned(1012, 1014)
    _binary(vm, _RECIPE, 1014, 169, 1015, 7, 'and')
    _condition(vm, 1015, 145, 1016)
    _condition(vm, 1011, 158, 1017, greater=True)
    _binary(vm, _RECIPE, 1016, 1017, 1018, 98, 'and')
    selected = bool(vm.cells.value(1018))
    if selected:
        _advance(vm, 1013, 1012, 1019, 1020, 1021, 1, state)
        _binary(vm, _RECIPE, 1011, 396, 1022, 3, 'add')
    _phis(vm, (1023, 1024, 1025), (1022, 1021, 1019) if selected else (1011, 1012, 1013))
    vm.cells.copy_q_clear_owned(1024, 1026)
    vm.cells.copy_q_clear_owned(1025, 1027)
    selected = _condition(vm, 1023, 149, 1028, greater=True)
    if selected:
        _address(vm, 1, 1025, 1029, 172)
        vm.cells.copy_q_clear_owned(1029, 1030)
        _load(vm, 1027, 1031, 4)
        _address(vm, 1, 1024, 1032, 172)
        vm.cells.copy_q_clear_owned(1032, 1033)
        _store(vm, 1031, 1026, 4)
        state['copied_bytes'] += 4
        _binary(vm, _RECIPE, 1023, 1034, 1035, 3, 'add')
    _phis(vm, (1036, 1037, 1038), (1035, 1033, 1030) if selected else (1023, 1026, 1027))
    for remaining, destination, source, condition, source_next, value, destination_next, following, outputs in (
            (1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, (1044, 1045, 1046)),
            (1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, (1052, 1053, 1054))):
        selected = _condition(vm, remaining, 149, condition, greater=True)
        if selected:
            _advance(vm, source, destination, source_next, value, destination_next, 4, state)
            _binary(vm, _RECIPE, remaining, 1034, following, 3, 'add')
        _phis(vm, outputs, (following, destination_next, source_next) if selected else
              (remaining, destination, source))
    vm.cells.copy_q_clear_owned(1053, 1055)
    vm.cells.copy_q_clear_owned(1054, 1056)
    for remaining, destination, source, condition, source_next, value, destination_next, following, outputs in (
            (1052, 1055, 1056, 1057, 1058, 1059, 1060, 1061, (1062, 1063, 1064)),
            (1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, (1070, 1071, 1072))):
        selected = _condition(vm, remaining, 158, condition, greater=True)
        if selected:
            _advance(vm, source, destination, source_next, value, destination_next, 1, state,
                     wide=condition == 1065)
            _binary(vm, _RECIPE, remaining, 396, following, 3, 'add')
        _phis(vm, outputs, (following, destination_next, source_next) if selected else
              (remaining, destination, source))
    selected = _condition(vm, 1070, 158, 1073, greater=True)
    if selected:
        _advance(vm, 1072, 1071, 1074, 1075, 1076, 1, state)
    _phis(vm, (1077, 1078), (1076, 1074) if selected else (1071, 1072))
    if _condition(vm, 1070, 269, 1079, greater=True):
        _load(vm, 1078, 1080, 1)
        _store(vm, 1080, 1077, 1, wide=True)
        state['copied_bytes'] += 1
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 6925, 150, 149, False
    state['phase'] = 'complete'
    return True
