from .primary_material_generation import _retained
from .primary_material_prepare import _address, _auxiliary, _binary, _equal, _flag0, _mask
from .primary_material_rounds import _less, _load, _store
from .primary_vm import PrimaryProgramLimit


_RECIPE = {
    'auxiliary': {296: 2042780867, 293: 2014314498, 309: 2060635555,
                  306: 970293250, 314: 1816580097, 322: 1619509250,
                  337: 2072068612, 338: 15446, 341: 27965, 343: 861983235,
                  331: 1465397249, 333: 510480386, 353: 40231,
                  356: 867058179, 350: 606085122, 368: 28006,
                  371: 1224561155, 365: 2025791489, 382: 51263,
                  383: 40814, 385: 1146228246, 390: 462524418,
                  399: 61969, 400: 606040066, 406: 1404218787,
                  394: 917229570, 408: 2101503507, 417: 1085427315,
                  414: 1973280770, 420: 1661526018, 429: 1923084290,
                  446: 1769697796, 447: 1610846210, 452: 261874179,
                  441: 1015447554, 443: 1261555714, 456: 9077,
                  464: 1174572531, 467: 8589, 472: 870334465,
                  474: 63226, 486: 23359, 496: 14413, 499: 1570628100,
                  494: 1825234945, 507: 60437, 511: 551684531,
                  514: 1455588852, 515: 63295, 523: 347230227,
                  527: 1371574274, 535: 1718345730, 551: 1565594116,
                  552: 711917569, 556: 60492, 557: 1918272003,
                  548: 1107496962, 546: 1666121729, 560: 575860371,
                  565: 301117603, 570: 1234322531, 575: 978502243,
                  517: 311808001, 585: 27717, 587: 57644,
                  588: 1735533843, 598: 1259053058, 606: 1221726210,
                  618: 2105735731, 620: 33192, 661: 1700962835,
                  665: 1048772099, 672: 796055029, 677: 59101,
                  671: 757772290, 685: 403419137},
    'flag0': (338, 341, 368, 507),
    'comparisons': (296, 417, 565, 570, 618),
}


def _phi(vm, destination, source):
    vm._write(destination, vm.cells.value(source), 8, 'signature_context.phi')


def _op(vm, left, right, destination, typ, operation):
    if operation not in ('or', 'sub'):
        _binary(vm, _RECIPE, left, right, destination, typ, operation)
        return
    _auxiliary(vm, _RECIPE, destination)
    first, second = vm._signed_cell(left, typ), vm._signed_cell(right, typ)
    vm._write(destination, first | second if operation == 'or' else first - second,
              8, 'signature_context.' + operation)


def _eq(vm, left, right, destination, typ):
    return _equal(vm, _RECIPE, left, right, destination, typ)


def _compare(vm, left, right, destination, typ, operation):
    _auxiliary(vm, _RECIPE, destination)
    if operation == 'ne':
        value = vm._signed_cell(left, typ) != vm._signed_cell(right, typ)
    elif operation == 'gt':
        value = vm._signed_cell(left, typ) > vm._signed_cell(right, typ)
    else:
        value = vm.cells.value(left) > vm.cells.value(right)
    vm._write(destination, int(value), 4, 'signature_context.compare')
    return bool(vm.cells.value(destination))


def _select(vm, condition, true, false, destination, typ):
    source = true if vm.cells.value(condition) else false
    vm._write(destination, vm._signed_cell(source, typ), 8, 'signature_context.select')


def _remainder(vm, left, right, destination, *, signed=False):
    first = vm._signed_cell(left, 3) if signed else vm.cells.value(left)
    second = vm._signed_cell(right, 3) if signed else vm.cells.value(right)
    if not second or (signed and first == -(1 << 63) and second == -1):
        message = ('native signed IDIV64 fault outside ordinary execution' if signed else
                   'native unsigned DIV fault outside ordinary execution')
        raise PrimaryProgramLimit(message)
    if signed:
        quotient = abs(first) // abs(second) * (-1 if (first < 0) != (second < 0) else 1)
        value = first - quotient * second
    else:
        value = first % second
    vm._write(destination, value, 8, 'signature_context.remainder')


def _left(vm, source, count, destination, typ, word):
    _auxiliary(vm, _RECIPE, destination)
    first = vm.memory.load(vm.image_base + 0x6D86090, 4)
    second = vm.memory.load(vm.image_base + 0x6D86094, 4, signed=True)
    extra = (((first * first) & 0xFFFFFFFF) | (abs(second) & 0xFFFFFFFF)) >> 31
    amount = vm.memory.load(vm.cells.pointer(count), 4)
    value = 0
    if not amount & 0x80000000 and amount < 32:
        value = (vm._signed_cell(source, typ) & 0xFFFFFFFF) << amount
    vm._write(destination, value, 4, 'signature_context.left')
    if extra:
        vm.pc = word + 5
        vm.execute_typed(tuple(vm._operand() for _ in range(4)))


def _native(vm, word, block, predecessor, state):
    _retained(vm, word, block, predecessor, 1, state)


def _zero(vm, cells, state):
    remaining, initial, following, pointer, base, next_pointer, condition = cells
    first = True
    while True:
        _phi(vm, remaining, initial if first else following)
        _phi(vm, pointer, base if first else next_pointer)
        if _eq(vm, remaining, 145, condition, 7):
            return
        _op(vm, remaining, 233, following, 7, 'add')
        _address(vm, 1, pointer, next_pointer, 163)
        _store(vm, 235, pointer, 1)
        state['cleared_bytes'] += 1
        first = False


def _copy(vm, source, destination, dword_limit, byte_limit, cells, state, *, wide=False):
    index, following, condition, read_pointer, read_cast, value, write_pointer, write_cast, tail, tail_next, tail_condition, tail_read, tail_value, tail_write = cells
    first = True
    while True:
        _phi(vm, index, 145 if first else following)
        if not _less(vm, index, dword_limit, condition):
            break
        _address(vm, 1, source, read_pointer, index)
        vm.cells.copy_q_clear_owned(read_pointer, read_cast)
        _load(vm, read_cast, value, 4)
        _address(vm, 1, destination, write_pointer, index)
        vm.cells.copy_q_clear_owned(write_pointer, write_cast)
        _store(vm, value, write_cast, 4)
        state['copied_bytes'] += 4
        _op(vm, index, 172, following, 7, 'add')
        first = False
    first = True
    while True:
        _phi(vm, tail, dword_limit if first else tail_next)
        if not _less(vm, tail, byte_limit, tail_condition):
            return
        _address(vm, 1, source, tail_read, tail)
        _load(vm, tail_read, tail_value, 1)
        _address(vm, 1, destination, tail_write, tail)
        _store(vm, tail_value, tail_write, 1, wide=wide)
        state['copied_bytes'] += 1
        _op(vm, tail, 163, tail_next, 7, 'add')
        first = False


def _decode_scalar(vm, cells, state, *, wide=False, condition_first=False):
    seed, initial, next_seed, condition, control, value, mixed, result, constant, multiplied = cells
    first = True
    while True:
        if condition_first:
            _phi(vm, condition, 216 if first else 279)
            _phi(vm, seed, initial if first else next_seed)
        else:
            _phi(vm, seed, initial if first else next_seed)
            _phi(vm, condition, 216 if first else 279)
        if not vm.cells.value(condition):
            return
        _load(vm, 97, value, 1)
        _op(vm, seed, value, mixed, 1, 'xor')
        _op(vm, mixed, constant, result, 1, 'xor')
        _store(vm, result, 97, 1, wide=wide)
        state['decoded_bytes'] += 1
        _op(vm, seed, 342, multiplied, 1, 'mul')
        _op(vm, multiplied, 344, next_seed, 1, 'add')
        first = False


def _decode_record(vm, state):
    vm.cells.copy_q_clear_owned(407, 409)
    _address(vm, 64, 98, 410, 145, 145)
    _address(vm, 64, 98, 411, 145, 145)
    _zero(vm, (412, 413, 414, 415, 411, 416, 417), state)
    _address(vm, 117, 148, 418, 145, 404, 409, 158, 145)
    _copy(vm, 418, 411, 421, 430,
          (419, 420, 422, 423, 424, 425, 426, 427, 428, 429, 431, 432, 433, 434), state)
    _address(vm, 117, 148, 435, 145, 404, 409, 269)
    _load(vm, 435, 436, 1)
    vm.execute_once(10, (7, 1, 436, 437))
    _address(vm, 117, 148, 438, 145, 328, 437)
    _load(vm, 438, 439, 1)
    first = True
    while True:
        _phi(vm, 440, 439 if first else 441)
        _phi(vm, 442, 145 if first else 443)
        if not _less(vm, 442, 430, 444):
            break
        _mask(vm, 442, 445, 1)
        _op(vm, 445, 336, 446, 1, 'mul')
        _op(vm, 446, 436, 447, 1, 'add')
        _op(vm, 440, 447, 448, 1, 'xor')
        _address(vm, 64, 98, 449, 145, 442)
        _load(vm, 449, 450, 1)
        _op(vm, 450, 448, 451, 1, 'xor')
        _store(vm, 451, 449, 1)
        state['decoded_bytes'] += 1
        _op(vm, 440, 342, 452, 1, 'mul')
        _op(vm, 452, 344, 441, 1, 'add')
        _op(vm, 442, 163, 443, 7, 'add')
        first = False
    _native(vm, 2353, 54, 52, state)
    _op(vm, 453, 455, 456, 3, 'and')
    _remainder(vm, 456, 457, 458)
    vm.execute_once(10, (7, 3, 458, 459))
    _address(vm, 117, 148, 460, 145, 328, 459)
    _load(vm, 460, 461, 1)
    _op(vm, 461, 462, 463, 1, 'and')
    _eq(vm, 463, 235, 464, 1)
    _select(vm, 464, 354, 463, 465, 1)
    vm.execute_once(10, (18, 1, 465, 466))
    _left(vm, 466, 280, 467, 18, 2419)
    vm.execute_once(10, (7, 1, 465, 468))
    _address(vm, 64, 98, 469, 145, 468)
    _load(vm, 469, 470, 1)
    _op(vm, 470, 471, 472, 1, 'add')
    vm.execute_once(10, (18, 1, 472, 473))
    _op(vm, 467, 473, 474, 18, 'or')
    _address(vm, 75, 106, 475, 145, 476)
    _store(vm, 474, 475, 2)


def _record_selection(vm, state):
    _address(vm, 117, 148, 386, 145, 387)
    _load(vm, 386, 388, 1)
    vm.execute_once(10, (3, 1, 388, 389))
    _op(vm, 389, 360, 390, 3, 'add')
    _remainder(vm, 390, 391, 392)
    first = True
    while True:
        _phi(vm, 393, 158 if first else 394)
        _phi(vm, 395, 396 if first else 397)
        if not _less(vm, 393, 391, 398):
            _phi(vm, 407, 395)
            break
        _op(vm, 392, 393, 399, 3, 'sub')
        _op(vm, 399, 391, 400, 3, 'add')
        _remainder(vm, 400, 391, 401, signed=True)
        vm.cells.copy_q_clear_owned(401, 402)
        _address(vm, 117, 148, 403, 145, 404, 402, 311)
        _load(vm, 403, 405, 1)
        empty = _eq(vm, 405, 235, 406, 1)
        _select(vm, 406, 395, 401, 397, 3)
        if not empty:
            _phi(vm, 407, 397)
            break
        _op(vm, 393, 269, 394, 3, 'add')
        first = False
    if not _eq(vm, 407, 396, 408, 3):
        state['selected_record'] = vm._signed_cell(407, 3)
        _decode_record(vm, state)


def _commands(vm, state):
    first = True
    while True:
        _phi(vm, 516, 158 if first else 517)
        if not _less(vm, 516, 518, 519):
            return
        vm.execute_once(10, (7, 3, 516, 520))
        _address(vm, 117, 148, 521, 145, 476, 520, 149)
        _load(vm, 521, 522, 1)
        if _eq(vm, 522, 235, 523, 1):
            pass
        else:
            _address(vm, 117, 148, 524, 145, 476, 520, 158, 145)
            _address(vm, 66, 99, 525, 145, 145)
            _copy(vm, 524, 525, 172, 172,
                  (526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539),
                  state, wide=True)
            _address(vm, 117, 148, 540, 145, 476, 520, 311)
            _load(vm, 540, 541, 1)
            vm.execute_once(10, (7, 1, 541, 542))
            _address(vm, 117, 148, 543, 145, 328, 542)
            _load(vm, 543, 544, 1)
            first_byte = True
            while True:
                _phi(vm, 545, 145 if first_byte else 546)
                _phi(vm, 547, 544 if first_byte else 548)
                if not _less(vm, 545, 172, 549):
                    break
                _mask(vm, 545, 550, 1)
                _op(vm, 550, 336, 551, 1, 'mul')
                _op(vm, 551, 541, 552, 1, 'add')
                _op(vm, 547, 552, 553, 1, 'xor')
                _address(vm, 66, 99, 554, 145, 545)
                _load(vm, 554, 555, 1)
                _op(vm, 555, 553, 556, 1, 'xor')
                _store(vm, 556, 554, 1)
                state['decoded_bytes'] += 1
                _op(vm, 547, 342, 557, 1, 'mul')
                _op(vm, 557, 344, 548, 1, 'add')
                _op(vm, 545, 163, 546, 7, 'add')
                first_byte = False
            _load(vm, 525, 558, 1)
            _load(vm, 10, 559, 1)
            matched = _eq(vm, 558, 559, 560, 1)
            if matched:
                _address(vm, 66, 99, 561, 145, 163)
                _load(vm, 561, 562, 1)
                _address(vm, 1, 10, 563, 163)
                _load(vm, 563, 564, 1)
                matched = _eq(vm, 562, 564, 565, 1)
            if matched:
                _address(vm, 66, 99, 566, 145, 166)
                _load(vm, 566, 567, 1)
                _address(vm, 1, 10, 568, 166)
                _load(vm, 568, 569, 1)
                matched = _eq(vm, 567, 569, 570, 1)
            if matched:
                _address(vm, 66, 99, 571, 145, 169)
                _load(vm, 571, 572, 1)
                _address(vm, 1, 10, 573, 169)
                _load(vm, 573, 574, 1)
                matched = _eq(vm, 572, 574, 575, 1)
            if matched:
                _address(vm, 75, 106, 576, 145, 404)
                _store(vm, 354, 576, 1)
                state['command_match'] = True
                return
        _op(vm, 516, 269, 517, 3, 'add')
        first = False


def _caller_one(vm, state):
    _native(vm, 3591, 86, 83, state)
    _address(vm, 56, 91, 628, 145, 145)
    _native(vm, 3608, 86, 83, state)
    _address(vm, 56, 91, 630, 145, 145)
    for destination, index, value in ((630, None, 206), (631, 163, 206),
                                      (632, 166, 633), (634, 169, 185),
                                      (635, 172, 164), (636, 175, 633),
                                      (637, 178, 638), (639, 181, 633),
                                      (640, 184, 641), (642, 187, 176),
                                      (643, 190, 644)):
        if index is not None:
            _address(vm, 56, 91, destination, 145, index)
        _store(vm, value, destination, 1)
    _address(vm, 58, 92, 645, 145, 145)
    _native(vm, 3757, 86, 83, state)
    for destination, index, value in ((647, 145, 648), (649, 163, 170),
                                      (650, 166, 211), (651, 169, 211),
                                      (652, 172, 170), (653, 175, 179),
                                      (654, 178, 182), (655, 181, 644),
                                      (656, 184, 167), (657, 187, 167)):
        _address(vm, 58, 92, destination, 145, index)
        _store(vm, value, destination, 1)
    _native(vm, 3886, 86, 83, state)
    predecessor = 86
    if not _eq(vm, 658, 660, 661, 26):
        _native(vm, 3906, 91, 86, state)
        predecessor = 91
        if not _eq(vm, 662, 664, 665, 136):
            vm.cells.copy_q_clear_owned(662, 666)
            _native(vm, 3932, 92, 91, state)
            _address(vm, 60, 93, 668, 145, 145)
            _address(vm, 60, 93, 669, 145, 145)
            first = True
            while True:
                _phi(vm, 670, 158 if first else 671)
                _auxiliary(vm, _RECIPE, 672)
                left = vm._signed_cell(670, 3) & 0xFFFFFFFFFFFFFFFF
                right = vm._signed_cell(375, 3) & 0xFFFFFFFFFFFFFFFF
                difference = (left - right) & 0xFFFFFFFFFFFFFFFF
                overflow = ((left ^ difference) & (left ^ right)) >> 63
                vm._write(672, (difference >> 63) | overflow, 4, 'signature_context.n_or_v')
                if not vm.cells.value(672):
                    break
                vm.execute_once(10, (7, 3, 670, 673))
                _address(vm, 1, 299, 674, 673)
                _load(vm, 674, 675, 1)
                vm.execute_once(10, (3, 1, 675, 676))
                _left(vm, 670, 269, 677, 3, 4002)
                vm.execute_once(10, (7, 3, 677, 678))
                _address(vm, 1, 669, 679, 678)
                _address(vm, 66, 681, 680, 145, 145)
                _native(vm, 4027, 94, 93, state)
                _op(vm, 670, 269, 671, 3, 'add')
                first = False
            first = True
            while True:
                _phi(vm, 684, 158 if first else 685)
                if not _less(vm, 684, 686, 687):
                    break
                vm.execute_once(10, (7, 3, 684, 688))
                _address(vm, 60, 93, 689, 145, 688)
                _load(vm, 689, 690, 1)
                _compare(vm, 690, 691, 692, 1, 'ugt')
                _op(vm, 684, 269, 685, 3, 'add')
                first = False
            _native(vm, 4066, 98, 96, state)
            predecessor = 98
    _address(vm, 62, 95, 693, 145, 145)
    _native(vm, 4118, 90, predecessor, state)
    vm.cells.copy_q_clear_owned(96, 696)
    _store(vm, 145, 96, 8)
    _address(vm, 62, 95, 697, 145, 145)
    _native(vm, 4144, 90, predecessor, state)
    _address(vm, 1, 299, 699, 166)
    _load(vm, 699, 700, 1)
    _store(vm, 700, 615, 1)


def prepare_primary_signature_context(vm):
    vm.primary_signature_context_state = {'phase': 'initialise', 'cleared_bytes': 0,
                                          'copied_bytes': 0, 'decoded_bytes': 0,
                                          'selected_record': None, 'command_match': False,
                                          'caller_path': None, 'retained_steps': 0}
    state = vm.primary_signature_context_state
    predecessor = vm.predecessor
    vm.cells.copy_q_clear_owned(102, 286)
    _store(vm, 145, 102, 8)
    _native(vm, 1160, 15, predecessor, state)
    _address(vm, 70, 103, 289, 145, 145)
    _address(vm, 70, 103, 290, 145, 145)
    _zero(vm, (291, 292, 293, 294, 290, 295, 296), state)
    _address(vm, 72, 104, 297, 145, 145)
    _native(vm, 1243, 18, 16, state)
    _address(vm, 72, 104, 299, 145, 145)
    _native(vm, 1260, 18, 16, state)
    _address(vm, 49, 105, 302, 145, 145)
    _address(vm, 75, 106, 303, 145, 158, 145)
    _zero(vm, (304, 305, 306, 307, 303, 308, 309), state)
    _native(vm, 1335, 21, 19, state)
    _address(vm, 117, 148, 310, 145, 311, 145)
    _address(vm, 75, 106, 312, 145, 158, 145)
    _copy(vm, 310, 312, 205, 205,
          (313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326), state)
    state['phase'] = 'decode'
    _address(vm, 117, 148, 327, 145, 328, 145)
    _load(vm, 327, 329, 1)
    first = True
    while True:
        _phi(vm, 330, 329 if first else 331)
        _phi(vm, 332, 145 if first else 333)
        if not _less(vm, 332, 205, 334):
            break
        _mask(vm, 332, 335, 1)
        _op(vm, 335, 336, 337, 1, 'mul')
        _op(vm, 337, 330, 338, 1, 'xor')
        _address(vm, 75, 106, 339, 145, 158, 332)
        _load(vm, 339, 340, 1)
        _op(vm, 338, 340, 341, 1, 'xor')
        _store(vm, 341, 339, 1)
        state['decoded_bytes'] += 1
        _op(vm, 330, 342, 343, 1, 'mul')
        _op(vm, 343, 344, 331, 1, 'add')
        _op(vm, 332, 163, 333, 7, 'add')
        first = False
    _address(vm, 117, 148, 345, 145, 149, 145)
    _load(vm, 345, 346, 1)
    _store(vm, 346, 97, 1)
    _address(vm, 117, 148, 347, 145, 328, 163)
    _load(vm, 347, 348, 1)
    _decode_scalar(vm, (349, 348, 350, 351, 0, 352, 353, 355, 354, 356), state)
    _load(vm, 97, 357, 1)
    _address(vm, 75, 106, 358, 145, 269)
    _store(vm, 357, 358, 1)
    _address(vm, 117, 148, 359, 145, 360, 145)
    _load(vm, 359, 361, 1)
    _store(vm, 361, 97, 1)
    _address(vm, 117, 148, 362, 145, 328, 166)
    _load(vm, 362, 363, 1)
    _decode_scalar(vm, (364, 363, 365, 366, 0, 367, 368, 370, 369, 371), state)
    _load(vm, 97, 372, 1)
    _address(vm, 75, 106, 373, 145, 311)
    _store(vm, 372, 373, 1)
    _address(vm, 117, 148, 374, 145, 375)
    _load(vm, 374, 376, 4)
    _address(vm, 117, 148, 377, 145, 158)
    _load(vm, 377, 378, 4)
    _address(vm, 75, 106, 379, 145, 158, 163)
    _load(vm, 379, 380, 1)
    vm.execute_once(10, (3, 1, 380, 381))
    _op(vm, 378, 381, 382, 3, 'xor')
    _op(vm, 376, 382, 383, 3, 'xor')
    _address(vm, 75, 106, 384, 145, 360)
    _store(vm, 383, 384, 4)
    if _compare(vm, 383, 158, 385, 3, 'gt'):
        _record_selection(vm, state)
    elif vm.cells.value(142):
        _store(vm, 477, 384, 4)
    _address(vm, 117, 148, 478, 145, 479)
    _load(vm, 478, 480, 4)
    _load(vm, 377, 481, 4)
    _address(vm, 75, 106, 482, 145, 158, 166)
    _load(vm, 482, 483, 1)
    vm.execute_once(10, (3, 1, 483, 484))
    _op(vm, 481, 484, 485, 3, 'xor')
    _op(vm, 480, 485, 486, 3, 'xor')
    _address(vm, 75, 106, 487, 145, 391)
    _store(vm, 486, 487, 4)
    _address(vm, 117, 148, 488, 145, 391, 145)
    _load(vm, 488, 489, 1)
    _store(vm, 489, 97, 1)
    _address(vm, 117, 148, 490, 145, 328, 169)
    _load(vm, 490, 491, 1)
    _decode_scalar(vm, (493, 491, 494, 492, 0, 495, 496, 498, 497, 499), state,
                   wide=True, condition_first=True)
    _load(vm, 97, 500, 1)
    _address(vm, 75, 106, 501, 145, 502, 145)
    _store(vm, 500, 501, 1)
    _address(vm, 117, 148, 503, 145, 504)
    _load(vm, 503, 505, 4)
    _load(vm, 377, 506, 4)
    _op(vm, 505, 506, 507, 3, 'xor')
    _address(vm, 75, 106, 508, 145, 149)
    _store(vm, 507, 508, 4, wide=True)
    _address(vm, 66, 99, 509, 145, 145)
    _native(vm, 2701, 58, 56, state)
    _eq(vm, 9, 311, 511, 3)
    _op(vm, 511, 142, 512, 98, 'and')
    _compare(vm, 10, 513, 514, 2, 'ne')
    _op(vm, 512, 514, 515, 98, 'and')
    state['phase'] = 'commands'
    if vm.cells.value(515):
        _commands(vm, state)
    else:
        _address(vm, 75, 106, 577, 145, 404)
        _store(vm, 354, 577, 1, wide=True)
    _address(vm, 117, 148, 578, 145, 579)
    _load(vm, 578, 580, 8)
    _store(vm, 580, 101, 8)
    _address(vm, 117, 148, 581, 145, 582)
    _load(vm, 581, 583, 8)
    _load(vm, 578, 584, 8)
    _op(vm, 583, 584, 585, 7, 'xor')
    _op(vm, 585, 586, 587, 7, 'and')
    if not _eq(vm, 587, 145, 588, 7):
        _address(vm, 75, 106, 589, 145, 590)
        _store(vm, 354, 589, 1)
        predecessor = 78
    else:
        predecessor = 63
    _address(vm, 117, 148, 591, 145, 592)
    _load(vm, 591, 593, 1)
    _address(vm, 75, 106, 594, 145, 387)
    _store(vm, 593, 594, 1)
    _native(vm, 3323, 77, predecessor, state)
    _address(vm, 75, 106, 595, 145, 158, 145)
    _address(vm, 49, 105, 596, 145, 145)
    _copy(vm, 595, 596, 205, 205,
          (597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610), state)
    _address(vm, 75, 106, 611, 145, 590)
    _load(vm, 611, 612, 1)
    vm.execute_once(10, (3, 1, 612, 613))
    _address(vm, 74, 107, 614, 145, 145)
    _address(vm, 74, 107, 615, 145, 145)
    _store(vm, 616, 615, 1)
    vm.execute_once(10, (7, 3, 11, 617))
    state['phase'] = 'caller'
    if vm.cells.value(9) == vm.cells.value(311):
        state['caller_path'] = 'case2'
        _eq(vm, 10, 513, 618, 2)
        _less(vm, 617, 172, 619)
        _op(vm, 618, 619, 620, 98, 'or')
        if vm.cells.value(620):
            _store(vm, 616, 615, 1)
        else:
            _address(vm, 49, 94, 621, 145, 145)
            _native(vm, 3547, 88, 85, state)
            _address(vm, 49, 94, 623, 145, 145)
            _native(vm, 3564, 88, 85, state)
            _address(vm, 49, 94, 625, 145, 166)
            _load(vm, 625, 626, 1)
            _store(vm, 626, 615, 1)
    elif vm.cells.value(9) == vm.cells.value(269):
        state['caller_path'] = 'case1'
        _caller_one(vm, state)
    else:
        state['caller_path'] = 'default'
        _store(vm, 616, 615, 1)
    _address(vm, 75, 106, 701, 145, 387)
    _load(vm, 701, 702, 1)
    _op(vm, 702, 354, 703, 1, 'xor')
    vm.execute_once(10, (3, 1, 703, 704))
    vm.cells.copy_q_clear_owned(108, 705)
    vm.cells.copy_q_clear_owned(109, 706)
    _address(vm, 84, 110, 707, 145, 145)
    vm.cells.copy_q_clear_owned(111, 708)
    _store(vm, 158, 111, 4)
    _address(vm, 84, 110, 709, 145, 145)
    vm.cells.copy_q_clear_owned(709, 710)
    vm.pc, vm.block, vm.predecessor, vm.initial_block = 4240, 99, 89, False
    state['phase'] = 'complete'
    return True
