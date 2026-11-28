from .primary_material_generation import _retained
from .primary_material_prepare import _address, _binary, _equal, _mask, _right
from .primary_material_rounds import _less, _load, _store
from .primary_rolling_state import _shift
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_RECIPE = {'auxiliary': {718: 512278530,
               712: 1517383682,
               744: 1891807043,
               746: 1339184723,
               748: 473079139,
               749: 2096268067,
               754: 18151,
               755: 43134,
               757: 22636,
               766: 34926,
               768: 13311,
               771: 41911,
               782: 35390,
               789: 805306370,
               790: 1426246675,
               793: 55295,
               794: 8030,
               796: 32118,
               804: 43295,
               805: 27517,
               813: 414154754,
               814: 947021347,
               817: 47045,
               829: 60716,
               853: 1113821185,
               837: 1611546625,
               868: 2013831169,
               870: 55407,
               872: 24391,
               874: 38478,
               876: 1511498243,
               879: 1978671105,
               881: 24932,
               883: 607301634,
               892: 869838849,
               894: 306913282,
               896: 760967169,
               900: 48134,
               901: 13374,
               902: 1166332419,
               905: 1312591873,
               907: 1373192194,
               914: 503947266,
               916: 1564344321,
               918: 1926230018,
               920: 28262,
               922: 35148,
               923: 16678,
               924: 2029322755,
               927: 1613631490,
               721: 760991746},
 'flag0': (755, 794),
 'comparisons': (746, 749)}
_ROUNDS = ((752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 4529),
 (769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 4656),
 (791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 4820),
 (815, 816, 817, 818, 819, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 5011))


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'material_bootstrap.phi')


def _copy(vm, source, destination):
    vm.cells.copy_q_clear_owned(source, destination)


def _random(vm, cells, state):
    first, following, high, mixed, tail, folded, masked, product, shifted, byte, result = cells
    _load(vm, 865, first, 4)
    _binary(vm, _RECIPE, first, 867, following, 3, 'add')
    _store(vm, following, 865, 4)
    _right(vm, following, 504, high, 4)
    _binary(vm, _RECIPE, following, high, mixed, 3, 'xor')
    _right(vm, mixed, 328, tail, 4)
    _binary(vm, _RECIPE, mixed, tail, folded, 3, 'xor')
    _binary(vm, _RECIPE, folded, 873, masked, 3, 'and')
    _binary(vm, _RECIPE, masked, 875, product, 3, 'mul')
    _right(vm, product, 502, shifted, 4)
    _mask(vm, shifted, byte, 1)
    _binary(vm, _RECIPE, byte, 354, result, 1, 'add')
    state['generator_calls'] += 1


def _fill(vm, state):
    if vm.predecessor not in (89, 100):
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    source = 145 if vm.predecessor == 89 else 712
    while True:
        _phi(vm, 711, source)
        if not _less(vm, 711, 713, 714):
            break
        _load(vm, 715, 716, 8)
        _binary(vm, _RECIPE, 716, 717, 718, 7, 'add')
        _store(vm, 718, 715, 8)
        _address(vm, 7, 710, 719, 711)
        _store(vm, 718, 719, 8)
        state['filled_qwords'] += 1
        _binary(vm, _RECIPE, 711, 163, 712, 7, 'add')
        source = 712


def _pointers(vm, state):
    initial = True
    while True:
        _phi(vm, 720, 145 if initial else 721)
        if not _less(vm, 720, 421, 722):
            break
        _random(vm, (866, 868, 869, 870, 871, 872, 874, 876, 877, 878, 879), state)
        _binary(vm, _RECIPE, 879, 880, 881, 1, 'and')
        _binary(vm, _RECIPE, 881, 882, 883, 1, 'add')
        vm.execute_once(10, (7, 1, 883, 884))
        _address(vm, 84, 110, 885, 145, 884)
        _load(vm, 111, 886, 4)
        vm.execute_once(10, (7, 3, 886, 887))
        _address(vm, 1, 885, 888, 887)
        _address(vm, 80, 108, 889, 145, 720)
        _copy(vm, 889, 890)
        _store(vm, 888, 890, 8)
        _binary(vm, _RECIPE, 881, 891, 892, 1, 'add')
        vm.execute_once(10, (3, 1, 892, 893))
        _binary(vm, _RECIPE, 886, 893, 894, 3, 'add')
        _store(vm, 894, 111, 4)
        _random(vm, (895, 896, 897, 898, 899, 900, 901, 902, 903, 904, 905), state)
        _binary(vm, _RECIPE, 905, 880, 906, 1, 'and')
        _binary(vm, _RECIPE, 906, 882, 907, 1, 'add')
        vm.execute_once(10, (7, 1, 907, 908))
        _address(vm, 84, 110, 909, 145, 908)
        _load(vm, 111, 910, 4)
        vm.execute_once(10, (7, 3, 910, 911))
        _address(vm, 1, 909, 912, 911)
        _address(vm, 82, 109, 913, 145, 720)
        _store(vm, 912, 913, 8)
        _binary(vm, _RECIPE, 906, 344, 914, 1, 'add')
        vm.execute_once(10, (3, 1, 914, 915))
        _binary(vm, _RECIPE, 910, 915, 916, 3, 'add')
        _store(vm, 916, 111, 4)
        _random(vm, (917, 918, 919, 920, 921, 922, 923, 924, 925, 926, 927), state)
        _load(vm, 913, 928, 8)
        _store(vm, 927, 928, 1)
        _binary(vm, _RECIPE, 720, 163, 721, 7, 'add')
        state['generated_records'] += 1
        initial = False


def _round(vm, number, state):
    (x_pointer, x, left, first_xor, right, feedback, y_pointer, y,
     z_pointer, z, w_pointer, w, w_right, w_xor, result, word) = _ROUNDS[number]
    _address(vm, 90, 730, x_pointer, 145, 158)
    _load(vm, x_pointer, x, 4)
    if left in _RECIPE['auxiliary']:
        vm.auxiliary = (0, _RECIPE['auxiliary'][left])
    _shift(vm, x, 590, left, word, 4)
    _binary(vm, _RECIPE, x, left, first_xor, 3, 'xor')
    _right(vm, first_xor, 502, right, 4)
    _binary(vm, _RECIPE, first_xor, right, feedback, 3, 'xor')
    _address(vm, 90, 730, y_pointer, 145, 269)
    _load(vm, y_pointer, y, 4)
    _store(vm, y, x_pointer, 4)
    _address(vm, 90, 730, z_pointer, 145, 311)
    _load(vm, z_pointer, z, 4)
    _store(vm, z, y_pointer, 4)
    _address(vm, 90, 730, w_pointer, 145, 149)
    _load(vm, w_pointer, w, 4)
    _store(vm, w, z_pointer, 4)
    _right(vm, w, 592, w_right, 4)
    _binary(vm, _RECIPE, w, w_right, w_xor, 3, 'xor')
    _binary(vm, _RECIPE, w_xor, feedback, result, 3, 'xor')
    _store(vm, result, w_pointer, 4)
    state['state_rounds'] += 1
    return result


def _seed(vm, state):
    _copy(vm, 112, 723)
    _copy(vm, 111, 724)
    _address(vm, 82, 109, 725, 145, 145)
    _address(vm, 80, 108, 726, 145, 145)
    _copy(vm, 112, 727)
    _retained(vm, 4343, 104, 102, 1, state)
    state['native_calls'] += 1
    _address(vm, 91, 112, 730, 145, 328)
    _mask(vm, 724, 731, 4)
    _address(vm, 90, 730, 732, 145, 158)
    _store(vm, 731, 732, 4)
    _right(vm, 724, 205, 733, 8)
    _mask(vm, 733, 734, 4)
    _address(vm, 90, 730, 735, 145, 269)
    _store(vm, 734, 735, 4)
    _right(vm, 724, 421, 736, 8)
    _mask(vm, 736, 737, 4)
    _address(vm, 90, 730, 738, 145, 311)
    _store(vm, 737, 738, 4)
    _right(vm, 724, 739, 740, 8)
    _mask(vm, 740, 741, 4)
    _address(vm, 90, 730, 742, 145, 149)
    _store(vm, 741, 742, 4)
    _load(vm, 732, 743, 4)
    if _equal(vm, _RECIPE, 743, 158, 744, 3):
        _load(vm, 735, 745, 4)
        if _equal(vm, _RECIPE, 745, 158, 746, 3):
            _load(vm, 738, 747, 4)
            _equal(vm, _RECIPE, 747, 158, 748, 3, read=False)
            _equal(vm, _RECIPE, 741, 158, 749, 3, read=False)
            _binary(vm, _RECIPE, 748, 749, 750, 98, 'and')
            if vm.cells.value(750):
                _store(vm, 751, 732, 4)
                state['zero_seed_fallback'] = True
    result = _round(vm, 0, state)
    vm.execute_once(10, (7, 3, result, 767))
    vm.auxiliary = (0, _RECIPE['auxiliary'][768])
    _shift(vm, 767, 421, 768, 4636, 8)
    result = _round(vm, 1, state)
    vm.execute_once(10, (7, 3, result, 784))
    vm._write(785, vm._signed_cell(768, 7) | vm._signed_cell(784, 7),
              8, 'material_bootstrap.seed_or')
    _address(vm, 91, 112, 786, 145, 391)
    _store(vm, 785, 786, 8)
    _copy(vm, 726, 787)


def _shuffle(vm, number, state):
    bound, following, condition, converted, modulo, first, first_value, second, second_value = (
        (788, 789, 790, 806, 807, 808, 809, 810, 811),
        (812, 813, 814, 830, 831, 832, 833, 834, 835),
    )[number]
    base = 725 if number else 787
    initial = True
    while True:
        _phi(vm, bound, 421 if initial else following)
        _binary(vm, _RECIPE, bound, 233, following, 7, 'add')
        if _equal(vm, _RECIPE, following, 145, condition, 7):
            break
        result = _round(vm, number + 2, state)
        vm.execute_once(10, (7, 3, result, converted))
        left, divisor = vm.cells.value(converted), vm.cells.value(bound)
        if divisor == 0:
            raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
        vm._write(modulo, left % divisor, 8, 'material_bootstrap.unsigned_modulo')
        _address(vm, 2, base, first, following)
        _load(vm, first, first_value, 8)
        _address(vm, 2, base, second, modulo)
        _load(vm, second, second_value, 8)
        _store(vm, second_value, first, 8)
        _store(vm, first_value, second, 8)
        state['shuffle_swaps'] += 1
        initial = False


def _nodes(vm, state):
    initial = True
    while True:
        _phi(vm, 836, 145 if initial else 837)
        if not _less(vm, 836, 421, 838):
            break
        _address(vm, 78, 726, 839, 836)
        _load(vm, 839, 840, 8)
        _address(vm, 79, 840, 841, 145, 158)
        _store(vm, 158, 841, 4)
        _load(vm, 839, 842, 8)
        _address(vm, 79, 842, 843, 145, 269)
        _store(vm, 271, 843, 2)
        _address(vm, 2, 725, 844, 836)
        _load(vm, 844, 845, 8)
        _load(vm, 839, 846, 8)
        _address(vm, 79, 846, 847, 145, 311)
        _store(vm, 845, 847, 8)
        _load(vm, 839, 848, 8)
        _address(vm, 79, 848, 849, 145, 311)
        _load(vm, 849, 850, 8)
        _store(vm, 235, 850, 1)
        if _less(vm, 836, 851, 852):
            _binary(vm, _RECIPE, 836, 163, 853, 7, 'add')
            _address(vm, 78, 726, 854, 853)
            _load(vm, 854, 855, 8)
            source = 855
        else:
            source = 857
        _phi(vm, 856, source)
        _load(vm, 839, 858, 8)
        _address(vm, 79, 858, 859, 145, 149)
        _store(vm, 856, 859, 8)
        _load(vm, 839, 860, 8)
        _address(vm, 79, 860, 861, 145, 360)
        _store(vm, 158, 861, 4)
        _binary(vm, _RECIPE, 836, 163, 837, 7, 'add')
        state['initialized_nodes'] += 1
        initial = False
    _load(vm, 726, 862, 8)
    _address(vm, 91, 112, 863, 145, 158)
    _store(vm, 862, 863, 8)
    _address(vm, 91, 112, 864, 145, 269)
    _store(vm, 862, 864, 8)


def bootstrap_primary_material(vm):
    vm.primary_material_bootstrap_state = {'phase': 'fill', 'filled_qwords': 0,
                                          'generator_calls': 0, 'generated_records': 0,
                                          'state_rounds': 0, 'shuffle_swaps': 0,
                                          'initialized_nodes': 0, 'native_calls': 0,
                                          'zero_seed_fallback': False, 'retained_steps': 0}
    state = vm.primary_material_bootstrap_state
    _fill(vm, state)
    state['phase'] = 'pointers'
    _pointers(vm, state)
    state['phase'] = 'seed'
    _seed(vm, state)
    state['phase'] = 'shuffle'
    _shuffle(vm, 0, state)
    _shuffle(vm, 1, state)
    state['phase'] = 'nodes'
    _nodes(vm, state)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 5774, 120, 118, False
    state['phase'] = 'complete'
    return True
