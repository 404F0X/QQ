from .primary_material_generation import _retained
from .primary_material_prepare import _address, _right
from .primary_material_rounds import _less, _load, _store
from .primary_material_state import _comparison


_NAMES = {3642: (29, 29,
        ((145, 3642, 179, 1, False), (163, 3643, 164, 1, False), (166, 3644, 644, 1, False),
         (169, 3645, 167, 1, False), (172, 3646, 167, 1, False), (175, 3647, 182, 1, False),
         (178, 3648, 644, 1, True), (181, 3649, 167, 1, False), (184, 3650, 167, 1, False))),
 3653: (31, 43,
        ((145, 3653, 1532, 1, False), (163, 3654, 3655, 1, False), (166, 3656, 3657, 1, False),
         (169, 3658, 3659, 1, False), (172, 3660, 3655, 1, False), (175, 3661, 3662, 1, False),
         (178, 3663, 638, 1, False), (181, 3664, 3665, 1, False), (184, 3666, 182, 1, False),
         (187, 3667, 3668, 1, False), (190, 3669, 3662, 1, False), (193, 3670, 3662, 1, False))),
 3673: (49, 94,
        ((145, 3673, 3674, 1, True), (163, 3675, 3674, 1, False), (166, 3676, 3677, 1, False),
         (169, 3678, 3679, 1, False), (172, 3680, 167, 1, False), (175, 3681, 197, 1, False),
         (178, 3682, 164, 1, False), (181, 3683, 3684, 1, False), (184, 3685, 170, 1, False),
         (187, 3686, 3687, 1, False), (190, 3688, 211, 1, False), (193, 3689, 182, 1, False),
         (196, 3690, 644, 1, False), (199, 3691, 167, 1, True), (201, 3692, 167, 1, False))),
 3695: (31, 30,
        ((145, 3695, 161, 1, False), (163, 3696, 3687, 1, False), (166, 3697, 197, 1, False),
         (169, 3698, 214, 1, False), (172, 3699, 214, 1, False), (175, 3700, 185, 1, True),
         (178, 3701, 3687, 1, True), (181, 3702, 182, 1, False), (184, 3703, 179, 1, False),
         (187, 3704, 170, 1, False), (190, 3705, 644, 1, False), (193, 3706, 185, 1, True))),
 3736: (31, 43,
        ((145, 3736, 3737, 1, True), (163, 3738, 185, 1, False), (166, 3739, 3687, 1, False),
         (169, 3740, 179, 1, True), (172, 3741, 185, 1, False), (175, 3742, 167, 1, False),
         (178, 3743, 638, 1, False), (181, 3744, 3665, 1, False), (184, 3745, 182, 1, False),
         (187, 3746, 644, 1, False), (190, 3747, 167, 1, False), (193, 3748, 167, 1, False),
         (196, 3749, 235, 1, False))),
 3754: (21, 24,
        ((145, 3754, 633, 1, True), (163, 3755, 185, 1, False), (166, 3756, 164, 1, False),
         (169, 3757, 3758, 1, False), (172, 3759, 170, 1, False), (175, 3760, 644, 1, False),
         (178, 3761, 641, 1, True), (181, 3762, 167, 1, False), (184, 3763, 185, 1, False),
         (187, 3764, 3765, 1, False), (190, 3766, 176, 1, False), (193, 3767, 167, 1, False),
         (196, 3768, 185, 1, True), (199, 3769, 3659, 1, False), (201, 3770, 197, 1, True),
         (203, 3771, 211, 1, False), (205, 3772, 185, 1, False), (208, 3773, 3774, 1, False),
         (210, 3775, 235, 1, False))),
 3787: (43, 72,
        ((145, 3787, 3788, 1, False), (163, 3789, 3788, 1, False), (166, 3790, 182, 1, False),
         (169, 3791, 185, 1, False), (172, 3792, 188, 1, True), (175, 3793, 185, 1, False),
         (178, 3794, 235, 1, False))),
 3798: (41, 3731,
        ((163, 3798, 3799, 1, False), (166, 3800, 3758, 1, False), (169, 3801, 182, 1, False),
         (172, 3802, 185, 1, False), (175, 3803, 188, 1, False), (178, 3804, 185, 1, False),
         (181, 3805, 235, 1, False))),
 3808: (58, 92,
        ((145, 3808, 3788, 1, False), (163, 3809, 176, 1, False), (166, 3810, 3668, 1, False),
         (169, 3811, 176, 1, False), (172, 3812, 197, 1, False), (175, 3813, 179, 1, False),
         (178, 3814, 182, 1, False), (181, 3815, 185, 1, False), (184, 3816, 188, 1, False),
         (187, 3817, 185, 1, False), (190, 3818, 235, 1, False))),
 3821: (23, 26,
        ((145, 3821, 3659, 1, False), (163, 3822, 3797, 1, True), (166, 3823, 3788, 1, False),
         (169, 3824, 3788, 1, False), (172, 3825, 182, 1, False), (175, 3826, 185, 1, False),
         (178, 3827, 188, 1, True), (181, 3828, 185, 1, False), (184, 3829, 235, 1, True))),
 3864: (19, 23,
        ((145, 3864, 3865, 2, False), (163, 3866, 3865, 2, False), (166, 3867, 3868, 2, False),
         (169, 3869, 3408, 2, True), (172, 3870, 3871, 2, False), (175, 3872, 3408, 2, False),
         (178, 3873, 285, 2, False))),
 3894: (21, 24,
        ((145, 3894, 648, 1, False), (163, 3895, 194, 1, False), (166, 3896, 3687, 1, False),
         (169, 3897, 170, 1, False), (172, 3898, 211, 1, False), (175, 3899, 185, 1, False),
         (178, 3900, 206, 1, True), (181, 3901, 3902, 1, False), (184, 3903, 176, 1, False),
         (187, 3904, 644, 1, False), (190, 3905, 173, 1, False), (193, 3906, 185, 1, False),
         (196, 3907, 164, 1, False), (199, 3908, 3902, 1, True), (201, 3909, 176, 1, False),
         (203, 3910, 179, 1, False), (205, 3911, 206, 1, False), (208, 3912, 3913, 1, False))),
 3914: (54, 90, ((145, 3914, 3788, 1, False), (163, 3915, 3788, 1, False))),
 3918: (58, 92,
        ((145, 3918, 641, 1, False), (163, 3919, 3920, 1, False), (166, 3921, 185, 1, False),
         (169, 3922, 3687, 1, False), (172, 3923, 638, 1, False), (175, 3924, 3665, 1, False),
         (178, 3925, 182, 1, True), (181, 3926, 644, 1, True), (184, 3927, 167, 1, False),
         (187, 3928, 167, 1, False), (190, 3929, 235, 1, True))),
 3934: (56, 91,
        ((145, 3934, 3765, 1, False), (163, 3935, 176, 1, True), (166, 3936, 179, 1, False),
         (169, 3937, 644, 1, False), (172, 3938, 3902, 1, False), (175, 3939, 176, 1, False),
         (178, 3940, 179, 1, False), (181, 3941, 644, 1, False), (184, 3942, 170, 1, False),
         (187, 3943, 161, 1, False), (190, 3944, 3774, 1, False), (193, 3945, 235, 1, False))),
 3962: (58, 92,
        ((145, 3962, 641, 1, False), (163, 3963, 3920, 1, False), (166, 3964, 185, 1, False),
         (169, 3965, 3687, 1, False), (172, 3966, 638, 1, False), (175, 3967, 3665, 1, False),
         (178, 3968, 182, 1, False), (181, 3969, 644, 1, False), (184, 3970, 167, 1, False),
         (187, 3971, 167, 1, False), (190, 3972, 235, 1, False))),
 3977: (56, 91,
        ((145, 3977, 3765, 1, False), (163, 3978, 176, 1, False), (166, 3979, 179, 1, False),
         (169, 3980, 644, 1, False), (172, 3981, 3902, 1, False), (175, 3982, 176, 1, False),
         (178, 3983, 179, 1, False), (181, 3984, 644, 1, True), (184, 3985, 170, 1, False),
         (187, 3986, 161, 1, True), (190, 3987, 3774, 1, False), (193, 3988, 235, 1, False))),
 3995: (23, 26,
        ((145, 3995, 3902, 1, False), (163, 3996, 3797, 1, False), (166, 3997, 3902, 1, True),
         (169, 3998, 176, 1, False), (172, 3999, 179, 1, True), (175, 4000, 644, 1, False),
         (178, 4001, 170, 1, False), (181, 4002, 161, 1, False), (184, 4003, 235, 1, False))),
 4006: (13, 21,
        ((145, 4006, 206, 1, False), (163, 4007, 3655, 1, False), (166, 4008, 3662, 1, False),
         (169, 4009, 206, 1, False), (172, 4010, 4011, 1, False), (175, 4012, 176, 1, False),
         (178, 4013, 644, 1, False), (181, 4014, 185, 1, True), (184, 4015, 3677, 1, True),
         (187, 4016, 161, 1, False), (190, 4017, 179, 1, False), (193, 4018, 185, 1, False),
         (196, 4019, 3687, 1, False))),
 4037: (31, 43,
        ((145, 4037, 3737, 1, False), (163, 4038, 185, 1, True), (166, 4039, 3687, 1, False),
         (169, 4040, 179, 1, True), (172, 4041, 185, 1, False), (175, 4042, 167, 1, False),
         (178, 4043, 638, 1, False), (181, 4044, 3665, 1, False), (184, 4045, 182, 1, False),
         (187, 4046, 644, 1, False), (190, 4047, 167, 1, False), (193, 4048, 167, 1, False),
         (196, 4049, 235, 1, False))),
 4054: (21, 24,
        ((145, 4054, 633, 1, False), (163, 4055, 185, 1, False), (166, 4056, 164, 1, True),
         (169, 4057, 3758, 1, False), (172, 4058, 170, 1, False), (175, 4059, 644, 1, False),
         (178, 4060, 641, 1, True), (181, 4061, 167, 1, False), (184, 4062, 185, 1, False),
         (187, 4063, 3765, 1, False), (190, 4064, 176, 1, False), (193, 4065, 167, 1, False),
         (196, 4066, 185, 1, False), (199, 4067, 3659, 1, False), (201, 4068, 197, 1, False),
         (203, 4069, 211, 1, False), (205, 4070, 185, 1, False), (208, 4071, 3774, 1, False),
         (210, 4072, 235, 1, False)))}
_AUXILIARY = {3625: 26020,
 3709: 341972452,
 3711: 786598324,
 3712: 62492,
 3717: 953327395,
 3722: 1586666067,
 3724: 1849856179,
 3726: 1753402131,
 3728: 1985127219,
 3628: 1470189570,
 3751: 243417955,
 3780: 990002931,
 3783: 793947299,
 3831: 739388563,
 3833: 1089660851,
 3835: 990020195,
 3837: 1395840083,
 3844: 4415,
 3851: 1700935091,
 3857: 1498588787,
 3878: 197318099,
 3879: 620113922,
 3882: 1408374243,
 3884: 1960972518,
 3931: 1795339507,
 3950: 1737652099,
 3953: 1379073635,
 3956: 734196915,
 3974: 2093088851,
 3992: 299022339,
 4021: 1932707987,
 4023: 1898110787,
 4027: 400731411,
 4030: 949109603,
 4051: 1078095619,
 4076: 1603429155,
 4081: 976387987,
 4085: 1483903875,
 4089: 389154147,
 4093: 2081599907}
_CALL_BLOCKS = {25788: 617,
 25805: 617,
 25930: 617,
 26091: 617,
 26288: 617,
 26441: 617,
 26491: 619,
 26513: 622,
 26520: 622,
 26541: 624,
 26562: 625,
 26583: 626,
 26652: 618,
 26669: 618,
 26834: 618,
 26862: 629,
 27099: 629,
 27142: 631,
 27164: 633,
 27178: 633,
 27381: 633,
 27530: 633,
 27647: 633,
 27668: 634,
 27689: 636,
 27710: 637,
 27806: 639,
 27849: 642,
 27870: 643,
 27891: 644,
 27998: 644,
 28030: 644,
 28050: 646,
 28113: 640,
 28130: 640,
 28387: 640,
 28528: 640,
 28556: 648,
 28709: 648,
 28744: 650,
 28765: 651,
 28812: 649,
 28953: 649,
 28981: 653,
 29134: 653,
 29177: 655,
 29302: 655,
 29467: 655,
 29488: 656,
 29569: 654,
 29586: 654,
 29751: 654,
 29778: 659,
 30015: 659,
 30063: 661,
 30085: 663,
 30099: 663,
 30128: 664,
 30157: 665}


def _auxiliary(vm, destination):
    if destination in _AUXILIARY:
        vm.auxiliary = (0, _AUXILIARY[destination])


def _native(vm, word, state):
    _retained(vm, word, _CALL_BLOCKS[word], vm.predecessor, 1, state)
    state['native_calls'] += 1


def _name(vm, first, state):
    typ, base, entries = _NAMES[first]
    for index, destination, value, width, wide in entries:
        _address(vm, typ, base, destination, 145, index)
        _store(vm, value, destination, width, wide=wide)
        state['name_units'] += 1


def _copy(vm, source, destination):
    vm.cells.copy_q_clear_owned(source, destination)


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'material_environment.phi')


def _compare(vm, left, right, destination, typ, *, guarded=False, unequal=False,
             greater=False, unsigned=False):
    _auxiliary(vm, destination)
    if guarded:
        _comparison(vm)
    if unsigned:
        first, second = vm.cells.value(left), vm.cells.value(right)
    else:
        first, second = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    value = first > second if greater else first != second if unequal else first == second
    vm._write(destination, int(value), 4, 'material_environment.comparison')


def _choose(vm, condition, typ, true, false, destination):
    source = true if vm.cells.value(condition) else false
    vm._write(destination, vm._signed_cell(source, typ), 8, 'material_environment.selection')


def _add(vm, left, right, destination, typ):
    _auxiliary(vm, destination)
    vm._write(destination, vm._signed_cell(left, typ) + vm._signed_cell(right, typ),
              8, 'material_environment.add')


def _word_left(vm):
    _auxiliary(vm, 3625)
    first = vm.memory.load(vm.image_base + 0x6D86090, 4)
    second = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((first * first) & 0xFFFFFFFF) | (abs(second) & 0xFFFFFFFF)) >> 31
    amount = vm.memory.load(vm.cells.pointer(280), 4)
    value = 0
    if not amount & 0x80000000 and amount < 32:
        value = vm.memory.load(vm.cells.pointer(284), 2, signed=True) & 0xFFFFFFFF
        value <<= amount
    vm._write(3625, value, 4, 'material_environment.word_left')
    if extra:
        vm.pc = 25723
        vm.execute_typed(tuple(vm._operand() for _ in range(4)))


def _modules(vm, state):
    initial = True
    while True:
        _phi(vm, 3627, 285 if initial else 3628)
        _load(vm, 3629, 3630, 2)
        if not _less(vm, 3627, 3630, 3631):
            break
        vm.execute_once(10, (7, 18, 3627, 3632))
        _address(vm, 166, 3634, 3633, 145, 3632)
        _load(vm, 3633, 3635, 8)
        _copy(vm, 27, 3636)
        _store(vm, 660, 27, 8)
        _address(vm, 15, 28, 3637, 145, 145)
        _native(vm, 25788, state)
        _address(vm, 29, 29, 3640, 145, 145)
        _native(vm, 25805, state)
        _name(vm, 3642, state)
        _address(vm, 31, 43, 3651, 145, 145)
        _native(vm, 25930, state)
        _name(vm, 3653, state)
        _address(vm, 49, 94, 3671, 145, 145)
        _native(vm, 26091, state)
        _name(vm, 3673, state)
        _address(vm, 31, 30, 3693, 145, 145)
        _native(vm, 26288, state)
        _name(vm, 3695, state)
        _native(vm, 26441, state)
        state['module_rows'] += 1
        _compare(vm, 3707, 158, 3709, 3, unequal=True)
        _load(vm, 27, 3710, 8)
        _compare(vm, 3710, 660, 3711, 26, unequal=True)
        _auxiliary(vm, 3712)
        vm._write(3712, vm._signed_cell(3709, 98) & vm._signed_cell(3711, 98),
                  8, 'material_environment.module_available')
        if not vm.cells.value(3712):
            break
        _address(vm, 15, 28, 3713, 145, 145)
        _native(vm, 26491, state)
        _compare(vm, 3714, 158, 3717, 3, guarded=True)
        if vm.cells.value(3717):
            break
        _native(vm, 26513, state)
        _native(vm, 26520, state)
        _compare(vm, 3720, 158, 3722, 3)
        predecessor = 623
        if not vm.cells.value(3722):
            _native(vm, 26541, state)
            _compare(vm, 3723, 158, 3724, 3)
            if not vm.cells.value(3724):
                _native(vm, 26562, state)
                _compare(vm, 3725, 158, 3726, 3, guarded=True)
                if not vm.cells.value(3726):
                    _native(vm, 26583, state)
                    _compare(vm, 3727, 158, 3728, 3, guarded=True)
                    if not vm.cells.value(3728):
                        predecessor = 626
        _phi(vm, 3729, 279 if predecessor == 626 else 216)
        if not vm.cells.value(3729):
            break
        _add(vm, 3627, 274, 3628, 18)
        initial = False
    _choose(vm, 3631, 3, 269, 158, 3730)


def _filename_flag(vm, state):
    _copy(vm, 25, 3731)
    _address(vm, 15, 28, 3732, 145, 145)
    _native(vm, 26652, state)
    _address(vm, 31, 43, 3734, 145, 145)
    _native(vm, 26669, state)
    _name(vm, 3736, state)
    _native(vm, 26834, state)
    _compare(vm, 3750, 660, 3751, 26, guarded=True)
    source = 3779
    if not vm.cells.value(3751):
        _address(vm, 21, 24, 3752, 145, 145)
        _native(vm, 26862, state)
        _name(vm, 3754, state)
        _native(vm, 27099, state)
        _copy(vm, 3776, 3777)
        source = 3777
    _phi(vm, 3778, source)
    _compare(vm, 3778, 3779, 3780, 171, guarded=True)
    result_source = 158
    if not vm.cells.value(3780):
        _address(vm, 15, 28, 3781, 145, 145)
        _native(vm, 27142, state)
        _compare(vm, 3782, 158, 3783, 3)
        result_source = 3843
        if not vm.cells.value(3783):
            _native(vm, 27164, state)
            _address(vm, 43, 72, 3785, 145, 145)
            _native(vm, 27178, state)
            _name(vm, 3787, state)
            _copy(vm, 25, 3795)
            _store(vm, 145, 25, 8)
            _copy(vm, 25, 3796)
            _store(vm, 3797, 3796, 1)
            _name(vm, 3798, state)
            _address(vm, 58, 92, 3806, 145, 145)
            _native(vm, 27381, state)
            _name(vm, 3808, state)
            _address(vm, 23, 26, 3819, 145, 145)
            _native(vm, 27530, state)
            _name(vm, 3821, state)
            predecessor = 633
            for word, call_result, comparison, block in (
                    (27647, 3830, 3831, 634), (27668, 3832, 3833, 636),
                    (27689, 3834, 3835, 637), (27710, 3836, 3837, 638)):
                _native(vm, word, state)
                _compare(vm, call_result, 158, comparison, 3, guarded=comparison != 3837)
                if not vm.cells.value(comparison):
                    break
                predecessor = block
            if predecessor == 638:
                _load(vm, 3808, 3838, 1)
                _copy(vm, 3838, 3839)
            _phi(vm, 3840, 3839 if predecessor == 638 else 154)
            _phi(vm, 3841, 279 if predecessor == 638 else 216)
            result_source = 3843 if vm.cells.value(3841) else 3840
    _phi(vm, 3842, result_source)
    _auxiliary(vm, 3844)
    vm._write(3844, vm._signed_cell(3842, 3) & vm._signed_cell(269, 3),
              8, 'material_environment.filename_flag')
    vm.execute_once(10, (7, 3, 3844, 3845))


def _process_flag(vm, state):
    _compare(vm, 3626, 3846, 3847, 18, greater=True, unsigned=True)
    source = 145
    if vm.cells.value(3847):
        _native(vm, 27806, state)
        _copy(vm, 233, 3850)
        _compare(vm, 3848, 3850, 3851, 2, guarded=True)
        result_source = 158
        if not vm.cells.value(3851):
            _copy(vm, 22, 3852)
            _address(vm, 16, 22, 3853, 145, 158)
            _store(vm, 3854, 3853, 4)
            _native(vm, 27849, state)
            _compare(vm, 3855, 158, 3857, 3)
            if vm.cells.value(3857):
                _native(vm, 27870, state)
                _phi(vm, 3886, 158)
            else:
                initial = True
                while True:
                    _phi(vm, 3860, 158 if initial else 3861)
                    _copy(vm, 23, 3862)
                    _native(vm, 27891, state)
                    _name(vm, 3864, state)
                    _address(vm, 16, 22, 3874, 145, 404, 145)
                    _copy(vm, 3874, 3875)
                    _native(vm, 27998, state)
                    _compare(vm, 3876, 158, 3878, 3)
                    _add(vm, 3860, 269, 3879, 3)
                    _choose(vm, 3878, 3, 3879, 3860, 3861)
                    state['process_rows'] += 1
                    _native(vm, 28030, state)
                    _compare(vm, 3880, 158, 3882, 3)
                    if vm.cells.value(3882):
                        break
                    initial = False
                _native(vm, 28050, state)
                _compare(vm, 3861, 311, 3884, 3, greater=True)
                _choose(vm, 3884, 3, 158, 269, 3885)
                _phi(vm, 3886, 3885)
            result_source = 3886
        _phi(vm, 3887, result_source)
        _copy(vm, 3887, 3888)
        source = 3888
    _phi(vm, 3889, source)


def _window_flags(vm, state):
    _address(vm, 21, 24, 3890, 145, 145)
    _native(vm, 28113, state)
    _address(vm, 54, 90, 3892, 145, 145)
    _native(vm, 28130, state)
    _name(vm, 3894, state)
    _name(vm, 3914, state)
    _address(vm, 58, 92, 3916, 145, 145)
    _native(vm, 28387, state)
    _name(vm, 3918, state)
    _native(vm, 28528, state)
    _compare(vm, 3930, 660, 3931, 26)
    source = 3949
    if not vm.cells.value(3931):
        _address(vm, 56, 91, 3932, 145, 145)
        _native(vm, 28556, state)
        _name(vm, 3934, state)
        _native(vm, 28709, state)
        _copy(vm, 3946, 3947)
        source = 3947
    _phi(vm, 3948, source)
    _compare(vm, 3948, 3949, 3950, 185)
    source = 269
    if not vm.cells.value(3950):
        _native(vm, 28744, state)
        _compare(vm, 3951, 3952, 3953, 183)
        if not vm.cells.value(3953):
            _native(vm, 28765, state)
            _compare(vm, 3954, 158, 3956, 3)
            _choose(vm, 3956, 3, 269, 158, 3957)
            source = 3957
    _phi(vm, 3958, source)
    vm.execute_once(10, (7, 3, 3958, 3959))
    _address(vm, 58, 92, 3960, 145, 145)
    _native(vm, 28812, state)
    _name(vm, 3962, state)
    _native(vm, 28953, state)
    _compare(vm, 3973, 660, 3974, 26)
    source = 3949
    if not vm.cells.value(3974):
        _address(vm, 56, 91, 3975, 145, 145)
        _native(vm, 28981, state)
        _name(vm, 3977, state)
        _native(vm, 29134, state)
        _copy(vm, 3989, 3990)
        source = 3990
    _phi(vm, 3991, source)
    _compare(vm, 3991, 3949, 3992, 185, guarded=True)
    source = 158
    if not vm.cells.value(3992):
        _address(vm, 23, 26, 3993, 145, 145)
        _native(vm, 29177, state)
        _name(vm, 3995, state)
        _address(vm, 13, 21, 4004, 145, 145)
        _native(vm, 29302, state)
        _name(vm, 4006, state)
        _native(vm, 29467, state)
        _compare(vm, 4020, 3952, 4021, 183)
        source = 269
        if vm.cells.value(4021):
            _native(vm, 29488, state)
            _compare(vm, 4022, 3952, 4023, 183)
            _choose(vm, 4023, 3, 149, 311, 4024)
            source = 4024
        _phi(vm, 4025, source)
        source = 4025
    _phi(vm, 4026, source)
    _compare(vm, 4026, 269, 4027, 3)
    _choose(vm, 4027, 7, 4028, 145, 4029)
    _compare(vm, 4026, 311, 4030, 3, guarded=True)
    _choose(vm, 4030, 7, 4031, 145, 4032)


def _final_filename(vm, state):
    _address(vm, 15, 28, 4033, 145, 145)
    _native(vm, 29569, state)
    _address(vm, 31, 43, 4035, 145, 145)
    _native(vm, 29586, state)
    _name(vm, 4037, state)
    _native(vm, 29751, state)
    _compare(vm, 4050, 660, 4051, 26)
    source = 3779
    if not vm.cells.value(4051):
        _address(vm, 21, 24, 4052, 145, 145)
        _native(vm, 29778, state)
        _name(vm, 4054, state)
        _native(vm, 30015, state)
        _copy(vm, 4073, 4074)
        source = 4074
    _phi(vm, 4075, source)
    _compare(vm, 4075, 3779, 4076, 171, guarded=True)
    predecessor = 658
    if not vm.cells.value(4076):
        _address(vm, 15, 28, 4077, 145, 145)
        _copy(vm, 4078, 4079)
        _native(vm, 30063, state)
        _compare(vm, 4080, 158, 4081, 3, guarded=True)
        predecessor = 662
        if not vm.cells.value(4081):
            _native(vm, 30085, state)
            _address(vm, 192, 4083, 4082, 145, 145)
            _native(vm, 30099, state)
            _compare(vm, 4084, 158, 4085, 3, guarded=True)
            if vm.cells.value(4085):
                _address(vm, 49, 4087, 4086, 145, 145)
                _native(vm, 30128, state)
                _compare(vm, 4088, 158, 4089, 3)
                if vm.cells.value(4089):
                    _address(vm, 31, 4091, 4090, 145, 145)
                    _native(vm, 30157, state)
                    _compare(vm, 4092, 158, 4093, 3)
                    if vm.cells.value(4093):
                        predecessor = 665
    return predecessor


def produce_primary_environment(vm):
    vm.primary_material_environment_state = {'phase': 'control', 'module_rows': 0,
                                            'process_rows': 0, 'name_units': 0,
                                            'native_calls': 0, 'retained_steps': 0}
    state = vm.primary_material_environment_state
    _load(vm, 12, 3622, 8)
    vm._write(3623, vm.cells.value(3622) & 255, 8, 'material_environment.control_mask')
    _store(vm, 3623, 130, 1)
    _right(vm, 284, 280, 3624, 2)
    _word_left(vm)
    vm._write(3626, vm._signed_cell(3624, 18) | vm._signed_cell(3625, 18),
              8, 'material_environment.word_swap')
    if not vm.cells.value(142):
        vm.pc, vm.block, vm.predecessor, vm.initial_block = 30248, 614, 605, False
        state['phase'] = 'complete'
        state['enabled'] = False
        return True
    state['enabled'] = True
    state['phase'] = 'modules'
    _modules(vm, state)
    state['phase'] = 'filename'
    _filename_flag(vm, state)
    state['phase'] = 'processes'
    _process_flag(vm, state)
    state['phase'] = 'windows'
    _window_flags(vm, state)
    state['phase'] = 'final_filename'
    predecessor = _final_filename(vm, state)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 30180, 660, predecessor, False
    state['phase'] = 'complete'
    return True
