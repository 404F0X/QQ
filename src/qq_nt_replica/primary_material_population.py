from .primary_material_prepare import _address, _binary, _equal, _mask, _right
from .primary_material_rounds import _less, _load, _store
from .primary_vm import PrimarySemanticUnavailable


_AUXILIARY = {'auxiliary': {3273: 1822613505,
               3276: 1092790531,
               3282: 44918,
               3286: 903006099,
               3290: 63253,
               3294: 324145491,
               3297: 1858228355,
               3302: 35431,
               3303: 1217167876,
               3307: 10303,
               3308: 1410839043,
               3313: 36372,
               3314: 410051075,
               3317: 64093,
               3318: 1560736259,
               3320: 35438,
               3321: 1168028164,
               3324: 52559,
               3325: 1762001411,
               3329: 364347908,
               3330: 1540500115,
               3332: 1678923267,
               3338: 6980,
               3342: 1900174739,
               3348: 762286082,
               3355: 922900899,
               3352: 917516290,
               3367: 1272599044,
               3371: 18517,
               3372: 662958596,
               3377: 7476,
               3378: 1373147651,
               3382: 1919451652,
               3384: 56116,
               3385: 1517781508,
               3388: 8055,
               3389: 1970950659,
               3393: 859595268,
               3398: 6270,
               3400: 45892,
               3267: 1718030337,
               3409: 2078879746,
               3412: 348301267,
               3418: 32326,
               3422: 826459331,
               3426: 29791,
               3430: 738330147,
               3433: 1043481395,
               3438: 32029,
               3439: 1371103748,
               3444: 1366143491,
               3450: 513008132,
               3453: 28223,
               3454: 1568670212,
               3457: 261083652,
               3460: 16252,
               3461: 1964966404,
               3464: 28236,
               3465: 1215177219,
               3466: 594729251,
               3468: 2087909235,
               3474: 11271,
               3478: 1134736035,
               3484: 1618550785,
               3490: 622995619,
               3487: 2014842881,
               3501: 47701,
               3502: 1158832643,
               3507: 1770058244,
               3513: 1574986244,
               3516: 64383,
               3517: 1966883331,
               3519: 11831,
               3520: 2123481604,
               3523: 47719,
               3524: 215052803,
               3527: 40060,
               3528: 1216459267,
               3533: 36629,
               3403: 1560387586,
               3537: 1115475969,
               3541: 48439,
               3542: 25871,
               3543: 363123204,
               3546: 768524290,
               3263: 568549377,
               3553: 1191373683,
               3552: 1168707585},
 'flag0': (3313, 3384, 3438, 3453, 3501),
 'comparisons': (3294, 3330, 3332, 3355, 3422, 3433, 3468, 3490, 3553)}
_RECIPES = (
    {**_AUXILIARY, 'cells': (3271, 3273, 3277, 3278, 3279, 3280, 3281, 3282, 3283, 3284, 3285, 3286, 3287, 3288, 3289,
           3290, 3291, 3292, 3293, 3294, 3295, 3296, 3297, 3298, 3299, 3300, 3301, 3302, 3303, 3304,
           3305, 3306, 3307, 3308, 3309, 3310, 3311, 3312, 3313, 3314, 3315, 3316, 3317, 3318, 3319,
           3320, 3321, 3322, 3323, 3324, 3325, 3326, 3327, 3328, 3329, 3330, 3331, 3332),
 'loop': (3266, 3267, 3268, 3269, 3270, 3271, 3272, 3273, 3274, 3275, 3276),
 'insert': (3333, 3334, 3335, 3336, 3337, 3338, 3339, 3340, 3341, 3342, 3343, 3344, 3345, 3346,
            3347, 3348, 3349, 3350, 3352, 3353, 3354, 3355, 3356, 3357, 3358, 3359, 3360, 3361,
            3362, 3363),
 'checksum': (3364, 3365, 3366, 3367, 3368, 3369, 3370, 3371, 3372, 3373, 3374, 3375, 3376, 3377,
              3378, 3379, 3380, 3381, 3382, 3383, 3384, 3385, 3386, 3387, 3388, 3389, 3390, 3391,
              3392, 3393),
 'tail': (3394, 3395, 3396, 3397, 3398, 3400, 3401),
 'wide_key': False},
    {**_AUXILIARY, 'cells': (3407, 3409, 3413, 3414, 3415, 3416, 3417, 3418, 3419, 3420, 3421, 3422, 3423, 3424, 3425,
           3426, 3427, 3428, 3429, 3430, 3431, 3432, 3433, 3434, 3435, 3436, 3437, 3438, 3439, 3440,
           3441, 3442, 3443, 3444, 3445, 3446, 3447, 3448, 3449, 3450, 3451, 3452, 3453, 3454, 3455,
           3456, 3457, 3458, 3459, 3460, 3461, 3462, 3463, 3464, 3465, 3466, 3467, 3468),
 'loop': (3402, 3403, 3404, 3405, 3406, 3407, 3408, 3409, 3410, 3411, 3412),
 'insert': (3469, 3470, 3471, 3472, 3473, 3474, 3475, 3476, 3477, 3478, 3479, 3480, 3481, 3482,
            3483, 3484, 3485, 3486, 3487, 3488, 3489, 3490, 3491, 3492, 3493, 3494, 3495, 3496,
            3497, 3498),
 'checksum': (3499, 3500, 3501, 3502, 3503, 3504, 3505, 3506, 3507, 3508, 3509, 3510, 3511, 3512,
              3513, 3514, 3515, 3516, 3517, 3518, 3519, 3520, 3521, 3522, 3523, 3524, 3525, 3526,
              3527, 3528),
 'tail': (3529, 3530, 3531, 3532, 3533, 3534, 3535),
 'wide_key': True},
)


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'material_population.phi')


def _generate(vm, state):
    if vm.predecessor not in (554, 563):
        raise PrimarySemanticUnavailable('PHI has no matching original predecessor')
    source = 158 if vm.predecessor == 554 else 3263
    while True:
        _phi(vm, 3262, source)
        if not _less(vm, 3262, 477, 3264):
            break
        _load(vm, 865, 3536, 4)
        _binary(vm, _AUXILIARY, 3536, 867, 3537, 3, 'add')
        _store(vm, 3537, 865, 4)
        _right(vm, 3537, 504, 3538, 4)
        _binary(vm, _AUXILIARY, 3537, 3538, 3539, 3, 'xor')
        _right(vm, 3539, 328, 3540, 4)
        _binary(vm, _AUXILIARY, 3539, 3540, 3541, 3, 'xor')
        _binary(vm, _AUXILIARY, 3541, 873, 3542, 3, 'and')
        _binary(vm, _AUXILIARY, 3542, 875, 3543, 3, 'mul')
        _right(vm, 3543, 502, 3544, 4)
        _mask(vm, 3544, 3545, 1)
        _binary(vm, _AUXILIARY, 3545, 354, 3546, 1, 'add')
        vm.execute_once(10, (7, 3, 3262, 3547))
        _address(vm, 49, 129, 3548, 145, 3547)
        _store(vm, 3546, 3548, 1)
        state['generated_bytes'] += 1
        _binary(vm, _AUXILIARY, 3262, 269, 3263, 3, 'add')
        source = 3263
    _address(vm, 49, 129, 3265, 145, 145)


def _clear(vm, recipe, cells, pointer, count, state, *, pointer_first=False):
    remaining, following, cursor, next_cursor, condition = cells
    initial = True
    while True:
        if pointer_first:
            _phi(vm, cursor, pointer if initial else next_cursor)
            _phi(vm, remaining, count if initial else following)
        else:
            _phi(vm, remaining, count if initial else following)
            _phi(vm, cursor, pointer if initial else next_cursor)
        if _equal(vm, recipe, remaining, 145, condition, 7):
            break
        _binary(vm, recipe, remaining, 233, following, 7, 'add')
        _address(vm, 1, cursor, next_cursor, 163)
        _store(vm, 235, cursor, 1)
        state['cleared_bytes'] += 1
        initial = False


def _find(vm, recipe, state):
    (masked, key, high_key, seed_pointer, seed, low_seed, masked_seed, bucket_xor,
     bucket_index, bucket_pointer, bucket, empty_bucket, high_seed, short_seed,
     node_xor, node_mask, node_index, node_pointer, node, empty_node,
     key_pointer, stored_key, same_key, checksum_pointer, checksum,
     identifier_pointer, identifier, first_xor, first_product, second_key_pointer,
     second_key, key_dword, second_xor, second_product, value_pointer_pointer,
     value_pointer, pointer_cast, pointer_low, third_xor, third_product,
     pointer_right, pointer_high, fourth_xor, fourth_product, seed_low,
     fifth_xor, fifth_product, seed_right, seed_high, sixth_xor, sixth_product,
     byte, byte_dword, seventh_xor, seventh_product, valid, result, missing) = recipe['cells']
    _right(vm, key, 280, high_key, 2)
    _address(vm, 91, 112, seed_pointer, 145, 391)
    _load(vm, seed_pointer, seed, 8)
    _mask(vm, seed, low_seed, 2)
    _binary(vm, recipe, low_seed, 1134, masked_seed, 18, 'and')
    _binary(vm, recipe, high_key, masked_seed, bucket_xor, 18, 'xor')
    source = bucket_xor
    vm.execute_once(10, (7, 18, source, bucket_index))
    _address(vm, 91, 112, bucket_pointer, 145, 311, bucket_index)
    _load(vm, bucket_pointer, bucket, 8)
    selected = 857
    if not _equal(vm, recipe, bucket, 1140, empty_bucket, 86):
        _right(vm, seed, 184, high_seed, 8)
        _mask(vm, high_seed, short_seed, 2)
        _binary(vm, recipe, short_seed, key, node_xor, 18, 'xor')
        _binary(vm, recipe, node_xor, 1134, node_mask, 18, 'and')
        vm.execute_once(10, (7, 18, node_mask, node_index))
        _address(vm, 78, bucket, node_pointer, node_index)
        _load(vm, node_pointer, node, 8)
        if _equal(vm, recipe, node, 857, empty_node, 78):
            selected = node
        else:
            _address(vm, 79, node, key_pointer, 145, 269)
            _load(vm, key_pointer, stored_key, 2)
            if _equal(vm, recipe, stored_key, key, same_key, 18):
                _address(vm, 79, node, checksum_pointer, 145, 360)
                _load(vm, checksum_pointer, checksum, 4)
                _address(vm, 79, node, identifier_pointer, 145, 158)
                _load(vm, identifier_pointer, identifier, 4)
                _binary(vm, recipe, identifier, 1157, first_xor, 3, 'xor')
                _binary(vm, recipe, first_xor, 1159, first_product, 3, 'mul')
                _address(vm, 79, node, second_key_pointer, 145, 269)
                _load(vm, second_key_pointer, second_key, 2)
                vm.execute_once(10, (3, 18, second_key, key_dword))
                _binary(vm, recipe, first_product, key_dword, second_xor, 3, 'xor')
                _binary(vm, recipe, second_xor, 1159, second_product, 3, 'mul')
                _address(vm, 79, node, value_pointer_pointer, 145, 311)
                _load(vm, value_pointer_pointer, value_pointer, 8)
                vm.execute_once(15, (7, 2, value_pointer, pointer_cast))
                _mask(vm, pointer_cast, pointer_low, 4)
                _binary(vm, recipe, second_product, pointer_low, third_xor, 3, 'xor')
                _binary(vm, recipe, third_xor, 1159, third_product, 3, 'mul')
                _right(vm, pointer_cast, 421, pointer_right, 8)
                _mask(vm, pointer_right, pointer_high, 4)
                _binary(vm, recipe, third_product, pointer_high, fourth_xor, 3, 'xor')
                _binary(vm, recipe, fourth_xor, 1159, fourth_product, 3, 'mul')
                _mask(vm, seed, seed_low, 4)
                _binary(vm, recipe, fourth_product, seed_low, fifth_xor, 3, 'xor')
                _binary(vm, recipe, fifth_xor, 1159, fifth_product, 3, 'mul')
                _right(vm, seed, 421, seed_right, 8)
                _mask(vm, seed_right, seed_high, 4)
                _binary(vm, recipe, fifth_product, seed_high, sixth_xor, 3, 'xor')
                _binary(vm, recipe, sixth_xor, 1159, sixth_product, 3, 'mul')
                _load(vm, value_pointer, byte, 1)
                vm.execute_once(10, (3, 1, byte, byte_dword))
                _binary(vm, recipe, sixth_product, byte_dword, seventh_xor, 3, 'xor')
                _binary(vm, recipe, seventh_xor, 1159, seventh_product, 3, 'mul')
                if not _equal(vm, recipe, checksum, seventh_product, valid, 3):
                    _store(vm, 1188, checksum_pointer, 4)
                    state['integrity_markers'] += 1
                selected = node
    vm._write(result, vm.cells.value(selected), 8, 'material_prepare.node_phi')
    _equal(vm, recipe, result, 857, missing, 78, read=False)
    state['lookups'] += 1
    return result, missing


def _checksum(vm, recipe, node, seed, state):
    (identifier_pointer, identifier, first_xor, first_product, key_pointer,
     key, key_dword, second_xor, second_product, value_pointer_pointer,
     value_pointer, pointer_cast, pointer_low, third_xor, third_product,
     pointer_right, pointer_high, fourth_xor, fourth_product, seed_low,
     fifth_xor, fifth_product, seed_right, seed_high, sixth_xor, sixth_product,
     byte, byte_dword, seventh_xor, seventh_product) = recipe['checksum']
    _address(vm, 79, node, identifier_pointer, 145, 158)
    _load(vm, identifier_pointer, identifier, 4)
    _binary(vm, recipe, identifier, 1157, first_xor, 3, 'xor')
    _binary(vm, recipe, first_xor, 1159, first_product, 3, 'mul')
    _address(vm, 79, node, key_pointer, 145, 269)
    _load(vm, key_pointer, key, 2)
    vm.execute_once(10, (3, 18, key, key_dword))
    _binary(vm, recipe, first_product, key_dword, second_xor, 3, 'xor')
    _binary(vm, recipe, second_xor, 1159, second_product, 3, 'mul')
    _address(vm, 79, node, value_pointer_pointer, 145, 311)
    _load(vm, value_pointer_pointer, value_pointer, 8)
    vm.cells.copy_q_clear_owned(value_pointer, pointer_cast)
    _mask(vm, pointer_cast, pointer_low, 4)
    _binary(vm, recipe, second_product, pointer_low, third_xor, 3, 'xor')
    _binary(vm, recipe, third_xor, 1159, third_product, 3, 'mul')
    _right(vm, pointer_cast, 421, pointer_right, 8)
    _mask(vm, pointer_right, pointer_high, 4)
    _binary(vm, recipe, third_product, pointer_high, fourth_xor, 3, 'xor')
    _binary(vm, recipe, fourth_xor, 1159, fourth_product, 3, 'mul')
    _mask(vm, seed, seed_low, 4)
    _binary(vm, recipe, fourth_product, seed_low, fifth_xor, 3, 'xor')
    _binary(vm, recipe, fifth_xor, 1159, fifth_product, 3, 'mul')
    _right(vm, seed, 421, seed_right, 8)
    _mask(vm, seed_right, seed_high, 4)
    _binary(vm, recipe, fifth_product, seed_high, sixth_xor, 3, 'xor')
    _binary(vm, recipe, sixth_xor, 1159, sixth_product, 3, 'mul')
    _load(vm, value_pointer, byte, 1)
    vm.execute_once(10, (3, 1, byte, byte_dword))
    _binary(vm, recipe, sixth_product, byte_dword, seventh_xor, 3, 'xor')
    _binary(vm, recipe, seventh_xor, 1159, seventh_product, 3, 'mul')
    state['checksums'] += 1
    return seventh_product


def _insert(vm, recipe, state):
    (_, _, _, _, value, _, _, key, free_pointer, _, _) = recipe['loop']
    (high_key, seed_pointer, seed, low_seed, masked_seed, bucket_xor,
     bucket_index, bucket_pointer, bucket, empty_bucket, count_pointer,
     count, full, new_bucket, current_count, next_count, captured_bucket,
     clear_count, clear_next, clear_pointer, clear_next_pointer, clear_condition,
     selected_bucket, node, next_pointer, following, key_pointer,
     value_pointer_pointer, value_pointer, current_seed) = recipe['insert']
    _right(vm, key, 280, high_key, 2)
    _address(vm, 91, 112, seed_pointer, 145, 391)
    _load(vm, seed_pointer, seed, 8)
    _mask(vm, seed, low_seed, 2)
    _binary(vm, recipe, low_seed, 1134, masked_seed, 18, 'and')
    _binary(vm, recipe, high_key, masked_seed, bucket_xor, 18, 'xor')
    vm.execute_once(10, (7, 18, bucket_xor, bucket_index))
    _address(vm, 91, 112, bucket_pointer, 145, 311, bucket_index)
    _load(vm, bucket_pointer, bucket, 8)
    selected = bucket
    if _equal(vm, recipe, bucket, 1140, empty_bucket, 86):
        _address(vm, 91, 112, count_pointer, 145, 360)
        _load(vm, count_pointer, count, 8)
        vm._write(full, int(vm.cells.value(count) > vm.cells.value(203)),
                  4, 'material_population.capacity')
        if vm.cells.value(full):
            state['capacity_skips'] += 1
            return
        _address(vm, 91, 112, new_bucket, 145, 149, count, 145)
        _store(vm, new_bucket, bucket_pointer, 8)
        _load(vm, count_pointer, current_count, 8)
        _binary(vm, recipe, current_count, 163, next_count, 7, 'add')
        _store(vm, next_count, count_pointer, 8)
        vm.cells.copy_q_clear_owned(new_bucket, captured_bucket)
        _clear(vm, recipe, (clear_count, clear_next, clear_pointer,
                           clear_next_pointer, clear_condition),
               captured_bucket, 3351, state)
        state['new_buckets'] += 1
        selected = new_bucket
    _phi(vm, selected_bucket, selected)
    _load(vm, free_pointer, node, 8)
    _address(vm, 79, node, next_pointer, 145, 149)
    _load(vm, next_pointer, following, 8)
    _store(vm, following, free_pointer, 8)
    _address(vm, 79, node, key_pointer, 145, 269)
    _store(vm, key, key_pointer, 2, wide=recipe['wide_key'])
    _address(vm, 79, node, value_pointer_pointer, 145, 311)
    _load(vm, value_pointer_pointer, value_pointer, 8)
    _store(vm, value, value_pointer, 1, wide=True)
    _load(vm, seed_pointer, current_seed, 8)
    checksum = _checksum(vm, recipe, node, current_seed, state)
    checksum_pointer, converted_key, latest_seed, high_seed, node_xor, node_index, target = recipe['tail']
    _address(vm, 79, node, checksum_pointer, 145, 360)
    _store(vm, checksum, checksum_pointer, 4)
    vm.execute_once(10, (7, 18, key, converted_key))
    _load(vm, seed_pointer, latest_seed, 8)
    _right(vm, latest_seed, 184, high_seed, 8)
    _binary(vm, recipe, high_seed, converted_key, node_xor, 7, 'xor')
    _binary(vm, recipe, node_xor, 3399, node_index, 7, 'and')
    _address(vm, 78, selected_bucket, target, node_index)
    _store(vm, node, target, 8)
    state['inserted_nodes'] += 1


def _populate(vm, recipe, state):
    (index, following, condition, source_pointer, value, masked, key_base,
     key, free_pointer, free, empty) = recipe['loop']
    initial = True
    while True:
        _phi(vm, index, 145 if initial else following)
        if not _less(vm, index, 190, condition):
            break
        _address(vm, 1, 3265, source_pointer, index)
        _load(vm, source_pointer, value, 1)
        _mask(vm, index, masked, 2)
        _binary(vm, recipe, masked, key_base, key, 18, 'add')
        _address(vm, 91, 112, free_pointer, 145, 269)
        _load(vm, free_pointer, free, 8)
        if _equal(vm, recipe, free, 857, empty, 78):
            state['empty_free_skips'] += 1
        else:
            _, missing = _find(vm, recipe, state)
            if vm.cells.value(missing):
                _insert(vm, recipe, state)
            else:
                state['existing_skips'] += 1
        _binary(vm, recipe, index, 163, following, 7, 'add')
        initial = False


def populate_primary_material(vm):
    vm.primary_material_population_state = {'phase': 'generate', 'generated_bytes': 0,
                                           'lookups': 0, 'integrity_markers': 0,
                                           'inserted_nodes': 0, 'new_buckets': 0,
                                           'checksums': 0, 'cleared_bytes': 0,
                                           'empty_free_skips': 0, 'existing_skips': 0,
                                           'capacity_skips': 0, 'retained_steps': 0}
    state = vm.primary_material_population_state
    _generate(vm, state)
    state['phase'] = 'first_storage'
    _populate(vm, _RECIPES[0], state)
    state['phase'] = 'second_storage'
    _populate(vm, _RECIPES[1], state)
    state['phase'] = 'clear'
    _clear(vm, _AUXILIARY, (3551, 3552, 3549, 3550, 3553),
           3265, 190, state, pointer_first=True)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 25207, 601, 599, False
    state['phase'] = 'complete'
    return True
