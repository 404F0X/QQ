from .primary_material_prepare import _address, _lookup
from .primary_material_rounds import _less, _load, _next, _pointer, _store
from .primary_rolling_state import _shift
from .primary_vm import PrimarySemanticUnavailable


_LOOKUPS = ({'cells': (4117,
            4118,
            4119,
            4120,
            4121,
            4122,
            4123,
            4124,
            4125,
            4126,
            4127,
            4128,
            4129,
            4130,
            4131,
            4132,
            4133,
            4134,
            4135,
            4136,
            4137,
            4138,
            4139,
            4140,
            4141,
            4142,
            4143,
            4144,
            4145,
            4146,
            4147,
            4148,
            4149,
            4150,
            4151,
            4152,
            4153,
            4154,
            4155,
            4156,
            4157,
            4158,
            4159,
            4160,
            4161,
            4162,
            4163,
            4164,
            4165,
            4166,
            4167,
            4168,
            4169,
            4170,
            4171,
            4172,
            4173,
            4174),
  'auxiliary': {4118: 1618292738,
                4123: 17453,
                4124: 63860,
                4128: 1743928899,
                4136: 1455560819,
                4139: 1943152851,
                4144: 28495,
                4145: 715874819,
                4150: 1058529796,
                4156: 1365672452,
                4159: 55366,
                4160: 611578371,
                4163: 508621315,
                4167: 710988291,
                4171: 1721762308,
                4172: 1994584995,
                4174: 1278381011},
  'flag0': (4159,),
  'comparisons': (4128, 4139, 4172, 4174)},
 {'cells': (4185,
            4186,
            4187,
            4188,
            4189,
            4190,
            4191,
            4192,
            4193,
            4194,
            4195,
            4196,
            4197,
            4198,
            4199,
            4200,
            4201,
            4202,
            4203,
            4204,
            4205,
            4206,
            4207,
            4208,
            4209,
            4210,
            4211,
            4212,
            4213,
            4214,
            4215,
            4216,
            4217,
            4218,
            4219,
            4220,
            4221,
            4222,
            4223,
            4224,
            4225,
            4226,
            4227,
            4228,
            4229,
            4230,
            4231,
            4232,
            4233,
            4234,
            4235,
            4236,
            4237,
            4238,
            4239,
            4240,
            4241,
            4242),
  'auxiliary': {4186: 1669210113,
                4191: 33351,
                4196: 684891235,
                4199: 28278,
                4204: 1476570787,
                4207: 702689091,
                4212: 6751,
                4213: 1872327172,
                4218: 811016708,
                4223: 27141,
                4224: 264815107,
                4228: 806261252,
                4230: 47447,
                4231: 661697028,
                4234: 19012,
                4235: 461632004,
                4238: 59911,
                4239: 1875984899,
                4240: 181548547,
                4242: 1031947859},
  'flag0': (4223,),
  'comparisons': (4196, 4204, 4240, 4242)})


def _flags(vm, state):
    if vm.predecessor not in (662, 658, 665):
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    vm._write(4094, vm.cells.value(158 if vm.predecessor == 665 else 269),
              8, 'material_join.environment_phi')
    vm.auxiliary = (0, 56908)
    vm._write(4095, vm._signed_cell(4094, 3) ^ vm._signed_cell(269, 3),
              8, 'material_join.environment_xor')
    vm.execute_once(10, (7, 3, 4095, 4096))
    state['qword_conversions'] += 1
    vm.auxiliary = (0, 50868)
    _shift(vm, 3730, 502, 4097, 30207, 4)
    state['key_shifts'] += 1
    vm._write(4099, vm._signed_cell(4097, 3) & vm._signed_cell(4098, 3),
              8, 'material_join.environment_mask')
    vm.execute_once(10, (7, 3, 4099, 4100))
    state['qword_conversions'] += 1
    for source, count, destination, auxiliary, word in (
            (3845, 4101, 4102, 37839, 30225),
            (4096, 305, 4103, 30340, 30233),
            (3959, 4104, 4105, 29628, 30241)):
        vm.auxiliary = (0, auxiliary)
        _shift(vm, source, count, destination, word, 8)
        state['key_shifts'] += 1


def _word(vm, number, state):
    (index, following, condition, captured, base, key_base,
     value_pointer_pointer, value_pointer, byte, target, empty_target,
     auxiliary) = (
        (4114, 4115, 4116, 4113, 20, 3272, 4175, 4176, 4177, 4178, 4179, 916701185),
        (4182, 4183, 4184, 4181, 19, 3408, 4243, 4244, 4245, 4246, 4247, 1965318145),
    )[number]
    vm.execute_once(15, (2, 8, base, captured))
    _store(vm, 145, base, 8)
    state['cleared_bytes'] += 8
    initial = True
    while True:
        vm._write(index, vm.cells.value(145 if initial else following),
                  8, 'material_join.word_index')
        if not _less(vm, index, 184, condition):
            break
        node, missing = _lookup(vm, 0, index, key_base, state, recipe=_LOOKUPS[number])
        if vm.cells.value(missing):
            _pointer(vm, captured, index, empty_target)
            _store(vm, 235, empty_target, 1)
        else:
            _address(vm, 79, node, value_pointer_pointer, 145, 311)
            _load(vm, value_pointer_pointer, value_pointer, 8)
            _load(vm, value_pointer, byte, 1)
            _pointer(vm, captured, index, target)
            _store(vm, byte, target, 1, wide=number == 0)
        state['word_bytes'] += 1
        vm.auxiliary = (0, auxiliary)
        _next(vm, index, 163, following)
        initial = False
    if number == 0:
        _load(vm, 20, 4180, 8)


def join_primary_material_keys(vm):
    vm.primary_material_join_state = {'phase': 'flags', 'key_shifts': 0,
                                    'qword_conversions': 0, 'phi_keys': 0,
                                    'lookups': 0, 'word_bytes': 0,
                                    'cleared_bytes': 0, 'integrity_markers': 0,
                                    'retained_steps': 0, 'entry': vm.pc}
    state = vm.primary_material_join_state
    predecessor = vm.predecessor
    if vm.pc == 30180:
        _flags(vm, state)
        predecessor = 660
    if predecessor not in (660, 605):
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    state['phase'] = 'join'
    for destination, source in ((4106, 3889), (4107, 4105), (4108, 4103),
                                 (4109, 4032), (4110, 4029), (4111, 4102), (4112, 4100)):
        vm._write(destination, vm.cells.value(145 if predecessor == 605 else source),
                  8, 'material_join.key_phi')
        state['phi_keys'] += 1
    state['phase'] = 'words'
    _word(vm, 0, state)
    _word(vm, 1, state)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 31269, 680, 677, False
    state['phase'] = 'complete'
    return True
