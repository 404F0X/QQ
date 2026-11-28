from .primary_material_generation import _retained
from .primary_material_rounds import _less, _load, _next, _pointer, _store
from .primary_material_state import _comparison, _flag0
from .primary_rolling_state import _shift


_LOOKUPS = ({'cells': (4592,
            4593,
            4594,
            4595,
            4596,
            4597,
            4598,
            4599,
            4600,
            4601,
            4602,
            4603,
            4604,
            4605,
            4606,
            4607,
            4608,
            4609,
            4610,
            4611,
            4612,
            4613,
            4614,
            4615,
            4616,
            4617,
            4618,
            4619,
            4620,
            4621,
            4622,
            4623,
            4624,
            4625,
            4626,
            4627,
            4628,
            4629,
            4630,
            4631,
            4632,
            4633,
            4634,
            4635,
            4636,
            4637,
            4638,
            4639,
            4640,
            4641,
            4642,
            4643,
            4644,
            4645,
            4646,
            4647,
            4648,
            4649),
  'auxiliary': {4593: 610844674,
                4598: 58636,
                4599: 52007,
                4603: 573754355,
                4607: 17428,
                4611: 1053991491,
                4614: 1890728771,
                4619: 38916,
                4620: 407171588,
                4624: 40311,
                4625: 2117284355,
                4630: 8038,
                4631: 755069443,
                4635: 1123328516,
                4638: 1369674243,
                4642: 1019216387,
                4645: 64638,
                4646: 1462243844,
                4647: 1991424867,
                4649: 1351784675},
  'flag0': (4624, 4645),
  'comparisons': (4614,)},
 {'cells': (4660,
            4662,
            4663,
            4664,
            4665,
            4666,
            4667,
            4668,
            4669,
            4670,
            4671,
            4672,
            4673,
            4674,
            4675,
            4676,
            4677,
            4678,
            4679,
            4680,
            4681,
            4682,
            4683,
            4684,
            4685,
            4686,
            4687,
            4688,
            4689,
            4690,
            4691,
            4692,
            4693,
            4694,
            4695,
            4696,
            4697,
            4698,
            4699,
            4700,
            4701,
            4702,
            4703,
            4704,
            4705,
            4706,
            4707,
            4708,
            4709,
            4710,
            4711,
            4712,
            4713,
            4714,
            4715,
            4716,
            4717,
            4718),
  'auxiliary': {4662: 1626714113,
                4668: 6205,
                4672: 952296259,
                4675: 28437,
                4680: 691171763,
                4683: 1283602035,
                4688: 48206,
                4689: 357999108,
                4693: 44582,
                4694: 2122985988,
                4700: 2126234115,
                4703: 14436,
                4704: 1266610691,
                4707: 654758403,
                4711: 1875362308,
                4714: 38948,
                4715: 510886404,
                4716: 334665267,
                4718: 992101427},
  'flag0': (4703,),
  'comparisons': (4672, 4680, 4716)},
 {'cells': (None,
            None,
            None,
            4729,
            4730,
            4731,
            4732,
            None,
            4733,
            4734,
            4735,
            4736,
            4737,
            4738,
            4739,
            4740,
            4741,
            4742,
            4743,
            4744,
            4745,
            4746,
            4747,
            4748,
            4749,
            4750,
            4751,
            4752,
            4753,
            4754,
            4755,
            4756,
            4757,
            4758,
            4759,
            4760,
            4761,
            4762,
            4763,
            4764,
            4765,
            4766,
            4767,
            4768,
            4769,
            4770,
            4771,
            4772,
            4773,
            4774,
            4775,
            4776,
            4777,
            4778,
            4779,
            4780,
            4781,
            4782),
  'auxiliary': {4732: 62500,
                4736: 243435683,
                4739: 23861,
                4740: 28765,
                4744: 1175628707,
                4747: 1440889987,
                4752: 35196,
                4753: 1964290564,
                4758: 1522000388,
                4763: 60532,
                4764: 213774851,
                4767: 23916,
                4768: 1462465028,
                4770: 51532,
                4771: 1274589700,
                4775: 1611899395,
                4779: 1968792067,
                4780: 2000877619,
                4782: 930267043},
  'flag0': (),
  'comparisons': (4736, 4744, 4782)},
 {'cells': (4798,
            4799,
            4800,
            4801,
            4802,
            4803,
            4804,
            4805,
            4806,
            4807,
            4808,
            4809,
            4810,
            4811,
            4812,
            4813,
            4814,
            4815,
            4816,
            4817,
            4818,
            4819,
            4820,
            4821,
            4822,
            4823,
            4824,
            4825,
            4826,
            4827,
            4828,
            4829,
            4830,
            4831,
            4832,
            4833,
            4834,
            4835,
            4836,
            4837,
            4838,
            4839,
            4840,
            4841,
            4842,
            4843,
            4844,
            4845,
            4846,
            4847,
            4848,
            4849,
            4850,
            4851,
            4852,
            4853,
            4854,
            4855),
  'auxiliary': {4799: 1877319681,
                4809: 691204003,
                4812: 23574,
                4817: 1330809683,
                4820: 1999818083,
                4825: 18774,
                4826: 1165984259,
                4831: 605524484,
                4836: 35655,
                4837: 1764184580,
                4840: 39735,
                4841: 815628803,
                4843: 48253,
                4844: 257610244,
                4847: 51325,
                4848: 202519044,
                4851: 20031,
                4852: 2017014275,
                4853: 1544699651,
                4855: 1588752227},
  'flag0': (4812, 4840, 4843, 4847),
  'comparisons': (4853,)},
 {'cells': (4866,
            4867,
            4868,
            4869,
            4870,
            4871,
            4872,
            4873,
            4874,
            4875,
            4876,
            4877,
            4878,
            4879,
            4880,
            4881,
            4882,
            4883,
            4884,
            4885,
            4886,
            4887,
            4888,
            4889,
            4890,
            4891,
            4892,
            4893,
            4894,
            4895,
            4896,
            4897,
            4898,
            4899,
            4900,
            4901,
            4902,
            4903,
            4904,
            4905,
            4906,
            4907,
            4908,
            4909,
            4910,
            4911,
            4912,
            4913,
            4914,
            4915,
            4916,
            4917,
            4918,
            4919,
            4920,
            4921,
            4922,
            4923),
  'auxiliary': {4867: 258666498,
                4873: 60255,
                4877: 1736607571,
                4880: 27454,
                4881: 13839,
                4885: 325212243,
                4888: 1643274611,
                4893: 47692,
                4894: 2077815300,
                4899: 1224401411,
                4905: 1470611971,
                4908: 52022,
                4909: 709087747,
                4911: 27446,
                4912: 812937732,
                4915: 10326,
                4916: 1112093188,
                4919: 6182,
                4920: 864166404,
                4921: 347236499,
                4923: 1105341523},
  'flag0': (4880, 4915, 4919),
  'comparisons': (4877, 4885, 4888)})


def _address(vm, typ, base, destination, *indices):
    offset = 0
    for ordinal, cell in enumerate(indices):
        index = vm.memory.load(vm.cells.pointer(cell), 4)
        if ordinal == 0:
            delta = vm.program.size(typ) * index
        else:
            delta, typ = vm._indexed_offset(typ, index)
        offset = (offset + delta) & 0xFFFFFFFFFFFFFFFF
    vm._write(destination, vm.cells.value(base) + offset, 8, 'material_prepare.address')


def _auxiliary(vm, recipe, destination):
    if destination in recipe['auxiliary']:
        vm.auxiliary = (0, recipe['auxiliary'][destination])


def _binary(vm, recipe, left, right, destination, typ, operation):
    _auxiliary(vm, recipe, destination)
    if destination in recipe['flag0']:
        _flag0(vm)
    first, second = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    if operation == 'xor':
        value = first ^ second
    elif operation == 'and':
        value = first & second
    elif operation == 'add':
        value = first + second
    else:
        value = first * second
    vm._write(destination, value, 8, 'material_prepare.' + operation)


def _equal(vm, recipe, left, right, destination, typ, *, read=True):
    _auxiliary(vm, recipe, destination)
    if destination in recipe['comparisons']:
        _comparison(vm)
    vm._write(destination, int(vm._signed_cell(left, typ) == vm._signed_cell(right, typ)),
              4, 'material_prepare.equal')
    if read:
        return bool(vm.cells.value(destination))


def _mask(vm, source, destination, width):
    vm._write(destination, vm.cells.value(source) & ((1 << (width * 8)) - 1),
              8, 'material_prepare.mask')


def _right(vm, source, count, destination, width):
    value = vm.memory.load(vm.cells.pointer(source), width)
    amount = vm.memory.load(vm.cells.pointer(count), 1)
    vm._write(destination, value >> (amount & (63 if width == 8 else 31)),
              8 if width == 8 else 4, 'material_prepare.right')


def _lookup(vm, number, index, key_base, state, *, recipe=None):
    if recipe is None:
        recipe = _LOOKUPS[number]
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
    if number != 2:
        _mask(vm, index, masked, 2)
        _binary(vm, recipe, masked, key_base, key, 18, 'add')
        _right(vm, key, 280, high_key, 2)
    else:
        key = key_base
    _address(vm, 91, 112, seed_pointer, 145, 391)
    _load(vm, seed_pointer, seed, 8)
    _mask(vm, seed, low_seed, 2)
    _binary(vm, recipe, low_seed, 1134, masked_seed, 18, 'and')
    if number == 2:
        source = masked_seed
    else:
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


def _read_word(vm, number, pointer_cell, output, base_key, cells, auxiliaries, state):
    index, following, condition, value_pointer_pointer, value_pointer, byte, target, empty_target = cells
    initial = True
    while True:
        vm._write(index, vm.cells.value(145 if initial else following),
                  8, 'material_prepare.word_index')
        if not _less(vm, index, 163 if number == 1 else 184, condition):
            break
        node, missing = _lookup(vm, number, index, base_key, state)
        if vm.cells.value(missing):
            _pointer(vm, pointer_cell, index, empty_target)
            _store(vm, 235, empty_target, 1)
        else:
            _address(vm, 79, node, value_pointer_pointer, 145, 311)
            _load(vm, value_pointer_pointer, value_pointer, 8)
            _load(vm, value_pointer, byte, 1)
            _pointer(vm, pointer_cell, index, target)
            _store(vm, byte, target, 1)
        state['word_bytes'] += 1
        vm.auxiliary = (0, auxiliaries)
        _next(vm, index, 163, following)
        initial = False
    _load(vm, output, 4724 if number == 1 else 4861 if number == 3 else 4929, 8)


def _publish(vm, state):
    initial = True
    while True:
        vm._write(4589, vm.cells.value(145 if initial else 4590),
                  8, 'material_prepare.publish_index')
        if not _less(vm, 4589, 184, 4591):
            break
        node, missing = _lookup(vm, 0, 4589, 3272, state)
        if not vm.cells.value(missing):
            _address(vm, 194, 4391, 4650, 145, 4589)
            _load(vm, 4650, 4651, 8)
            _pointer(vm, 4262, 4651, 4652)
            _load(vm, 4652, 4653, 1)
            _address(vm, 79, node, 4654, 145, 311)
            _load(vm, 4654, 4655, 8)
            _store(vm, 4653, 4655, 1)
            state['published_bytes'] += 1
        vm.auxiliary = (0, 758747137)
        _next(vm, 4589, 163, 4590)
        initial = False


def _cursor(vm, state):
    _load(vm, 4930, 4931, 8)
    vm.auxiliary = (0, 1037194771)
    _comparison(vm)
    vm._write(4933, int(vm._signed_cell(4931, 197) == vm._signed_cell(4932, 197)),
              4, 'material_prepare.empty_cursor_function')
    previous = 817
    if vm.cells.value(4933):
        _address(vm, 58, 92, 4934, 145, 145)
        _retained(vm, 36360, 825, 817, 1, state)
        state['name_memsets'] += 1
        for index, source, target in zip((145, 163, 166, 169, 172, 175, 178, 181, 184, 187, 190),
                                         (641, 3920, 185, 3687, 638, 3665, 182, 644, 167, 167, 235),
                                         range(4936, 4947)):
            _address(vm, 58, 92, target, 145, index)
            _store(vm, source, target, 1, wide=target == 4944)
        _retained(vm, 36501, 825, 817, 1, state)
        state['module_calls'] += 1
        vm.auxiliary = (0, 2049054643)
        vm._write(4948, int(vm._signed_cell(4947, 26) == vm._signed_cell(660, 26)),
                  4, 'material_prepare.module_absent')
        previous = 825
        if not vm.cells.value(4948):
            _address(vm, 31, 43, 4949, 145, 145)
            _retained(vm, 36529, 828, 825, 1, state)
            state['name_memsets'] += 1
            for index, source, target in zip((145, 163, 166, 169, 172, 175, 178, 181, 184, 187, 190, 193, 196),
                                             (633, 185, 164, 648, 641, 3687, 3920, 170, 3687, 3679, 170, 3920, 235),
                                             range(4951, 4964)):
                _address(vm, 31, 43, target, 145, index)
                _store(vm, source, target, 1, wide=target == 4956)
            _retained(vm, 36694, 828, 825, 1, state)
            state['procedure_calls'] += 1
            vm.execute_once(15, (199, 198, 4930, 4965))
            _store(vm, 4964, 4965, 8)
            previous = 828
        previous = 827
    vm.execute_once(15, (2, 34, 44, 4966))
    _retained(vm, 36720, 826, previous, 1, state)
    state['cursor_calls'] += 1


def _keys(vm, state):
    _address(vm, 33, 44, 4968, 145, 158)
    _load(vm, 4968, 4969, 4)
    vm.auxiliary = (0, 49943)
    vm._write(4970, vm._signed_cell(4969, 3) & vm._signed_cell(873, 3),
              8, 'material_prepare.masked_point_x')
    vm.execute_once(10, (7, 3, 4970, 4971))
    _address(vm, 33, 44, 4972, 145, 269)
    _load(vm, 4972, 4973, 4)
    vm.execute_once(10, (7, 3, 4973, 4974))
    vm.execute_once(15, (2, 36, 45, 4975))
    _retained(vm, 36774, 826, vm.predecessor, 1, state)
    state['key_memsets'] += 1
    _address(vm, 35, 45, 4977, 145, 145)
    vm.auxiliary = (0, 41981)
    _shift(vm, 4971, 739, 4978, 36794, 8)
    _store(vm, 4978, 4977, 8)
    state['key_qwords'] += 1
    _address(vm, 35, 45, 4979, 145, 163)
    vm.auxiliary = (0, 5622)
    _shift(vm, 4969, 375, 4980, 36814, 4)
    vm._write(4982, vm._signed_cell(4980, 3) & vm._signed_cell(4981, 3),
              8, 'material_prepare.masked_point_x_high')
    vm.execute_once(10, (7, 3, 4982, 4983))
    _store(vm, 4983, 4979, 8)
    state['key_qwords'] += 1
    _address(vm, 35, 45, 4984, 145, 166)
    vm.auxiliary = (0, 32917)
    _shift(vm, 4974, 4985, 4986, 36844, 8)
    _store(vm, 4986, 4984, 8)
    state['key_qwords'] += 1
    _address(vm, 35, 45, 4987, 145, 169)
    vm.auxiliary = (0, 46044)
    _shift(vm, 4973, 4988, 4989, 36864, 4)
    vm.auxiliary = (0, 42302)
    vm._write(4991, vm._signed_cell(4989, 3) & vm._signed_cell(4990, 3),
              8, 'material_prepare.masked_point_y_high')
    vm.execute_once(10, (7, 3, 4991, 4992))
    _store(vm, 4992, 4987, 8)
    state['key_qwords'] += 1
    for index, source, count, shifted, target, auxiliary, word in (
            (172, 4793, 4994, 4995, 4993, 61623, 36897),
            (175, 4792, 4997, 4998, 4996, 41908, 36917)):
        _address(vm, 35, 45, target, 145, index)
        vm.auxiliary = (0, auxiliary)
        _shift(vm, source, count, shifted, word, 8)
        _store(vm, shifted, target, 8)
        state['key_qwords'] += 1


def prepare_primary_material_chain(vm):
    vm.primary_material_prepare_state = {'phase': 'publish', 'lookups': 0,
                                       'published_bytes': 0, 'word_bytes': 0,
                                       'flag_writes': 0, 'integrity_markers': 0,
                                       'timer_calls': 0, 'module_calls': 0,
                                       'procedure_calls': 0, 'cursor_calls': 0,
                                       'name_memsets': 0, 'key_memsets': 0,
                                       'key_qwords': 0, 'retained_steps': 0}
    state = vm.primary_material_prepare_state
    _publish(vm, state)
    vm.execute_once(15, (2, 8, 31, 4656))
    _store(vm, 145, 31, 8)
    state['phase'] = 'flag'
    _read_word(vm, 1, 4656, 31, 4661, tuple(range(4657, 4660)) + tuple(range(4719, 4724)),
               919519234, state)
    _retained(vm, 34861, 788, 785, 1, state)
    state['timer_calls'] += 1
    vm.execute_once(10, (7, 98, 4725, 4726))
    vm.auxiliary = (0, 47478)
    vm._write(4727, vm._signed_cell(4724, 7) ^ vm._signed_cell(4726, 7),
              8, 'material_prepare.timer_flag_xor')
    _mask(vm, 4727, 4728, 1)
    node, missing = _lookup(vm, 2, None, 4661, state)
    if not vm.cells.value(missing):
        _address(vm, 79, node, 4783, 145, 311)
        _load(vm, 4783, 4784, 8)
        _store(vm, 4728, 4784, 1)
        state['flag_writes'] += 1
    _load(vm, 101, 4785, 8)
    vm.execute_once(15, (2, 7, 4785, 4786))
    _address(vm, 49, 4788, 4787, 145, 145)
    _retained(vm, 35309, 801, 802 if state['flag_writes'] else 796, 1, state)
    state['module_calls'] += 1
    vm.auxiliary = (0, 1490200355)
    _comparison(vm)
    vm._write(4790, int(vm._signed_cell(4789, 26) == vm._signed_cell(660, 26)),
              4, 'material_prepare.first_module_absent')
    vm._write(4791, vm._signed_cell(158 if vm.cells.value(4790) else 269, 3),
              8, 'material_prepare.module_flag')
    vm.execute_once(10, (7, 3, 4791, 4792))
    vm.execute_once(10, (7, 3, 613, 4793))
    state['phase'] = 'words'
    vm.execute_once(15, (2, 8, 42, 4794))
    _store(vm, 145, 42, 8)
    _read_word(vm, 3, 4794, 42, 3272, tuple(range(4795, 4798)) + tuple(range(4856, 4861)),
               302563330, state)
    vm.execute_once(15, (2, 8, 37, 4862))
    _store(vm, 145, 37, 8)
    _read_word(vm, 4, 4862, 37, 3408, tuple(range(4863, 4866)) + tuple(range(4924, 4929)),
               2116296705, state)
    state['phase'] = 'cursor'
    _cursor(vm, state)
    state['phase'] = 'keys'
    _keys(vm, state)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 36926, 826, vm.predecessor, False
    state['phase'] = 'complete'
    return True
