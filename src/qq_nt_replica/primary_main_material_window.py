from hashlib import sha256
from threading import get_ident

from .primary_main_material_getter import _convert, _equal, _pair_control, _phi, _pointer, _single_control
from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable


WINDOW_ENTRIES = frozenset(((37823, 829, 852, False), (37823, 829, 826, False),
                            (37823, 829, 830, False), (39468, 910, 908, False)))
WINDOW_EXITS = {37823: 38470, 39468: 41119}


def execute_primary_main_material_window(vm, *, charge=None):
    if (type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != MAIN_SHA256 or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) not in WINDOW_ENTRIES):
        raise PrimarySemanticUnavailable('independent material window requires its fixed Main entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            type(owner) is not dict or owner.get('vm') is not vm or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._execute_thread != get_ident() or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            len(runtime._program_calls) != 1 or runtime._program_calls[0]['name'] != 'main' or
            runtime._program_calls[0]['hosts'] is not None):
        raise PrimarySemanticUnavailable('independent material window requires the current Main owner without replay')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent material window cannot enter a stopped or pending body')
    entry = vm.pc
    state = dict(entryWord=entry, exitWord=WINDOW_EXITS[entry],
                 backend='DIRECT_MAIN_MATERIAL_INPUTS' if entry == 37823 else 'DIRECT_MAIN_MATERIAL_PUBLICATION_PREMIX',
                 referenceRecordCount=0, completed=False, traceComplete=False,
                 memsetBackend='EXISTING_DIRECT_RUNTIME_INVOKE', completeIndependentMain=False)
    vm.primary_main_material_window_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if charge is not None:
            charge()
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    if entry == 37823:
        _material_inputs(vm, tick)
    else:
        _material_publication_premix(vm, tick)
    state['completed'] = True
    return state


def _memset_host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    if address != vm.image_base + 0x2DE8580:
        raise PrimarySemanticUnavailable('independent material window requires its fixed direct memset binding')
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    result = _invoke_host(vm, address, arguments, signature,
                          argument_types=vm.program.type(signature).parameters[3:])
    vm._write(destination, result, 8, 'high.native_result_q')



def _material_inputs(vm, tick):
    cells, memory = vm.cells, vm.memory
    while vm.pc != 38470:
        if vm.block == 829:
            tick(37823)
            _pointer(vm, 37823, 37, 52, 5114, (145, 145))
            tick(37831)
            _pointer(vm, 37831, 37, 53, 5115, (145, 145))
            tick(37839)
            _pointer(vm, 37839, 37, 54, 5116, (145, 145))
            tick(37847)
            _pointer(vm, 37847, 37, 55, 5117, (145, 145))
            tick(37855)
            _pointer(vm, 37855, 37, 52, 5118, (145, 145))
            tick(37863)
            vm.pc = 37865
            vm._jump(853)
            continue
        if vm.block == 853:
            tick(37865)
            _phi(vm, 37865, (5119, 2, 145, 829, 5120, 854))
            tick(37872)
            vm.pc = 37877
            vm._write(5121, int(cells.value(5119) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(37877)
            vm.pc = 37881
            vm._jump(854 if cells.value(5121) != 0 else 855)
            continue
        if vm.block == 855:
            tick(37881)
            _pointer(vm, 37881, 37, 47, 5122, (145, 145))
            tick(37889)
            vm.pc = 37898
            _memset_host(vm, 37889, 157, (5122, 158, 4386), 121, 5123)
            tick(37898)
            vm.pc = 37900
            vm._jump(856)
            continue
        if vm.block == 854:
            tick(37900)
            vm.pc = 37901
            tick(37901)
            vm.pc = 37904
            vm.auxiliary = (0, 45991)
            tick(37904)
            _single_control(vm)
            vm.pc = 37909
            count = memory.load(cells.pointer(169), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(5119) << count
            vm._write(5124, value, 8, "typed.selector3.q")
            tick(37909)
            vm.pc = 37914
            value = memory.load(cells.pointer(5113), 8)
            count = memory.load(cells.pointer(5124), 1)
            vm._write(5125, value >> (count & 63), 8, 'once8.logical_shift')
            tick(37914)
            vm.pc = 37919
            vm._write(5126, cells.value(5125) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(37919)
            _pointer(vm, 37919, 194, 4391, 5127, (145, 5119))
            tick(37927)
            vm.pc = 37931
            value = memory.load(cells.value(5127), 8)
            vm._write(5128, value, 8, 'high.load')
            tick(37931)
            _pointer(vm, 37931, 1, 5118, 5129, (5128,))
            tick(37938)
            vm.pc = 37942
            pointer = cells.value(5129)
            value = memory.load(cells.pointer(5126), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37942)
            vm.pc = 37945
            vm.auxiliary = (0, 1664798721)
            tick(37945)
            vm.pc = 37950
            vm._write(5120, memory.load(cells.pointer(5119), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(37950)
            vm.pc = 37952
            vm._jump(853)
            continue
        if vm.block == 856:
            tick(37952)
            _phi(vm, 37952, (5130, 2, 145, 855, 5131, 857))
            tick(37959)
            vm.pc = 37964
            vm._write(5132, int(cells.value(5130) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(37964)
            vm.pc = 37968
            vm._jump(857 if cells.value(5132) != 0 else 858)
            continue
        if vm.block == 857:
            tick(37968)
            _pointer(vm, 37968, 194, 4391, 5133, (145, 5130))
            tick(37976)
            vm.pc = 37980
            value = memory.load(cells.value(5133), 8)
            vm._write(5134, value, 8, 'L5.unsigned_load')
            tick(37980)
            _pointer(vm, 37980, 37, 47, 5135, (145, 5134))
            tick(37988)
            vm.pc = 37992
            pointer = cells.value(5135)
            value = memory.load(cells.pointer(354), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(37992)
            vm.pc = 37993
            tick(37993)
            vm.pc = 37996
            vm.auxiliary = (0, 2116636673)
            tick(37996)
            vm.pc = 38001
            vm._write(5131, memory.load(cells.pointer(5130), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38001)
            vm.pc = 38003
            vm._jump(856)
            continue
        if vm.block == 858:
            tick(38003)
            _phi(vm, 38003, (5136, 2, 5137, 859, 145, 856))
            tick(38010)
            vm.pc = 38015
            vm._write(5138, int(cells.value(5136) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(38015)
            vm.pc = 38019
            vm._jump(860 if cells.value(5138) != 0 else 861)
            continue
        if vm.block == 860:
            tick(38019)
            _pointer(vm, 38019, 37, 47, 5139, (145, 5136))
            tick(38027)
            vm.pc = 38031
            value = memory.load(cells.value(5139), 1)
            vm._write(5140, value, 4, 'L5.unsigned_load')
            tick(38031)
            vm.pc = 38032
            tick(38032)
            vm.pc = 38035
            vm.auxiliary = (0, 1535297635)
            tick(38035)
            _equal(vm, 38040, 1, 5140, 235, 5141)
            tick(38040)
            vm.pc = 38044
            vm._jump(862 if cells.value(5141) != 0 else 859)
            continue
        if vm.block == 862:
            tick(38044)
            _pointer(vm, 38044, 1, 5118, 5142, (203,))
            tick(38051)
            vm.pc = 38055
            value = memory.load(cells.value(5142), 1)
            vm._write(5143, value, 4, 'high.load')
            tick(38055)
            _pointer(vm, 38055, 1, 5118, 5144, (4409,))
            tick(38062)
            vm.pc = 38066
            value = memory.load(cells.value(5144), 1)
            vm._write(5145, value, 4, 'high.load')
            tick(38066)
            vm.pc = 38067
            tick(38067)
            vm.pc = 38070
            vm.auxiliary = (0, 27743)
            tick(38070)
            vm.pc = 38076
            vm._write(5146, memory.load(cells.pointer(5143), 1, signed=True) ^ memory.load(cells.pointer(5145), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(38076)
            vm.pc = 38081
            vm._write(5147, cells.value(5136) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(38081)
            vm.pc = 38084
            vm.auxiliary = (0, 56085)
            tick(38084)
            vm.pc = 38090
            vm._write(5148, memory.load(cells.pointer(5146), 1, signed=True) ^ memory.load(cells.pointer(5147), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(38090)
            _pointer(vm, 38090, 1, 5118, 5149, (5136,))
            tick(38097)
            vm.pc = 38101
            pointer = cells.value(5149)
            value = memory.load(cells.pointer(5148), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(38101)
            vm.pc = 38103
            vm._jump(859)
            continue
        if vm.block == 859:
            tick(38103)
            vm.pc = 38104
            tick(38104)
            vm.pc = 38107
            vm.auxiliary = (0, 2021552129)
            tick(38107)
            vm.pc = 38112
            vm._write(5137, memory.load(cells.pointer(5136), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38112)
            vm.pc = 38114
            vm._jump(858)
            continue
        if vm.block == 861:
            tick(38114)
            _pointer(vm, 38114, 37, 53, 5150, (145, 145))
            tick(38122)
            vm.pc = 38124
            vm._jump(863)
            continue
        if vm.block == 863:
            tick(38124)
            _phi(vm, 38124, (5151, 2, 145, 861, 5152, 864))
            tick(38131)
            vm.pc = 38136
            vm._write(5153, int(cells.value(5151) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(38136)
            vm.pc = 38140
            vm._jump(864 if cells.value(5153) != 0 else 865)
            continue
        if vm.block == 865:
            tick(38140)
            _pointer(vm, 38140, 37, 47, 5154, (145, 145))
            tick(38148)
            vm.pc = 38157
            _memset_host(vm, 38148, 157, (5154, 158, 4386), 121, 5155)
            tick(38157)
            vm.pc = 38159
            vm._jump(866)
            continue
        if vm.block == 864:
            tick(38159)
            vm.pc = 38160
            tick(38160)
            vm.pc = 38163
            vm.auxiliary = (0, 24973)
            tick(38163)
            _single_control(vm)
            vm.pc = 38168
            count = memory.load(cells.pointer(169), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(5151) << count
            vm._write(5156, value, 8, "typed.selector3.q")
            tick(38168)
            vm.pc = 38173
            value = memory.load(cells.pointer(4861), 8)
            count = memory.load(cells.pointer(5156), 1)
            vm._write(5157, value >> (count & 63), 8, 'once8.logical_shift')
            tick(38173)
            vm.pc = 38178
            vm._write(5158, cells.value(5157) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(38178)
            _pointer(vm, 38178, 194, 4391, 5159, (145, 5151))
            tick(38186)
            vm.pc = 38190
            value = memory.load(cells.value(5159), 8)
            vm._write(5160, value, 8, 'high.load')
            tick(38190)
            _pointer(vm, 38190, 1, 5150, 5161, (5160,))
            tick(38197)
            vm.pc = 38201
            pointer = cells.value(5161)
            value = memory.load(cells.pointer(5158), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(38201)
            vm.pc = 38204
            vm.auxiliary = (0, 1163079681)
            tick(38204)
            vm.pc = 38209
            vm._write(5152, memory.load(cells.pointer(5151), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38209)
            vm.pc = 38211
            vm._jump(863)
            continue
        if vm.block == 866:
            tick(38211)
            _phi(vm, 38211, (5162, 2, 145, 865, 5163, 867))
            tick(38218)
            vm.pc = 38223
            vm._write(5164, int(cells.value(5162) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(38223)
            vm.pc = 38227
            vm._jump(867 if cells.value(5164) != 0 else 868)
            continue
        if vm.block == 867:
            tick(38227)
            _pointer(vm, 38227, 194, 4391, 5165, (145, 5162))
            tick(38235)
            vm.pc = 38239
            value = memory.load(cells.value(5165), 8)
            vm._write(5166, value, 8, 'high.load')
            tick(38239)
            _pointer(vm, 38239, 37, 47, 5167, (145, 5166))
            tick(38247)
            vm.pc = 38251
            pointer = cells.value(5167)
            value = memory.load(cells.pointer(354), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(38251)
            vm.pc = 38252
            tick(38252)
            vm.pc = 38255
            vm.auxiliary = (0, 1424850945)
            tick(38255)
            vm.pc = 38260
            vm._write(5163, memory.load(cells.pointer(5162), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38260)
            vm.pc = 38262
            vm._jump(866)
            continue
        if vm.block == 868:
            tick(38262)
            _phi(vm, 38262, (5168, 2, 5169, 869, 145, 866))
            tick(38269)
            vm.pc = 38274
            vm._write(5170, int(cells.value(5168) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(38274)
            vm.pc = 38278
            vm._jump(870 if cells.value(5170) != 0 else 871)
            continue
        if vm.block == 870:
            tick(38278)
            _pointer(vm, 38278, 37, 47, 5171, (145, 5168))
            tick(38286)
            vm.pc = 38290
            value = memory.load(cells.value(5171), 1)
            vm._write(5172, value, 4, 'high.load')
            tick(38290)
            vm.pc = 38291
            tick(38291)
            vm.pc = 38294
            vm.auxiliary = (0, 1595068771)
            tick(38294)
            vm.pc = 38299
            vm._write(5173, int(memory.load(cells.pointer(5172), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(38299)
            vm.pc = 38303
            vm._jump(872 if cells.value(5173) != 0 else 869)
            continue
        if vm.block == 872:
            tick(38303)
            _pointer(vm, 38303, 1, 5150, 5174, (203,))
            tick(38310)
            vm.pc = 38314
            value = memory.load(cells.value(5174), 1)
            vm._write(5175, value, 4, 'high.load')
            tick(38314)
            _pointer(vm, 38314, 1, 5150, 5176, (4409,))
            tick(38321)
            vm.pc = 38325
            value = memory.load(cells.value(5176), 1)
            vm._write(5177, value, 4, 'high.load')
            tick(38325)
            vm.pc = 38326
            tick(38326)
            vm.pc = 38329
            vm.auxiliary = (0, 55365)
            tick(38329)
            vm.pc = 38335
            vm._write(5178, memory.load(cells.pointer(5175), 1, signed=True) ^ memory.load(cells.pointer(5177), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(38335)
            vm.pc = 38340
            vm._write(5179, cells.value(5168) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(38340)
            vm.pc = 38343
            vm.auxiliary = (0, 44055)
            tick(38343)
            vm.pc = 38349
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5180, memory.load(cells.pointer(5178), 1, signed=True) ^ memory.load(cells.pointer(5179), 1, signed=True), 8, 'typed.selector5.q')
            tick(38349)
            _pointer(vm, 38349, 1, 5150, 5181, (5168,))
            tick(38356)
            vm.pc = 38360
            pointer = cells.value(5181)
            value = memory.load(cells.pointer(5180), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(38360)
            vm.pc = 38362
            vm._jump(869)
            continue
        if vm.block == 869:
            tick(38362)
            vm.pc = 38363
            tick(38363)
            vm.pc = 38366
            vm.auxiliary = (0, 1058361346)
            tick(38366)
            vm.pc = 38371
            vm._write(5169, memory.load(cells.pointer(5168), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38371)
            vm.pc = 38373
            vm._jump(868)
            continue
        if vm.block == 871:
            tick(38373)
            _pointer(vm, 38373, 37, 54, 5182, (145, 145))
            tick(38381)
            vm.pc = 38383
            vm._jump(873)
            continue
        if vm.block == 873:
            tick(38383)
            _phi(vm, 38383, (5183, 2, 145, 871, 5184, 874))
            tick(38390)
            vm.pc = 38395
            vm._write(5185, int(cells.value(5183) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(38395)
            vm.pc = 38399
            vm._jump(874 if cells.value(5185) != 0 else 875)
            continue
        if vm.block == 875:
            tick(38399)
            _pointer(vm, 38399, 37, 47, 5186, (145, 145))
            tick(38407)
            vm.pc = 38416
            _memset_host(vm, 38407, 157, (5186, 158, 4386), 121, 5187)
            tick(38416)
            vm.pc = 38418
            vm._jump(876)
            continue
        if vm.block == 874:
            tick(38418)
            vm.pc = 38419
            tick(38419)
            vm.pc = 38422
            vm.auxiliary = (0, 8356)
            tick(38422)
            _single_control(vm)
            vm.pc = 38427
            count = memory.load(cells.pointer(169), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(5183) << count
            vm._write(5188, value, 8, "typed.selector3.q")
            tick(38427)
            vm.pc = 38432
            value = memory.load(cells.pointer(4929), 8)
            count = memory.load(cells.pointer(5188), 1)
            vm._write(5189, value >> (count & 63), 8, 'once8.logical_shift')
            tick(38432)
            vm.pc = 38437
            vm._write(5190, cells.value(5189) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(38437)
            _pointer(vm, 38437, 194, 4391, 5191, (145, 5183))
            tick(38445)
            vm.pc = 38449
            value = memory.load(cells.value(5191), 8)
            vm._write(5192, value, 8, 'high.load')
            tick(38449)
            _pointer(vm, 38449, 1, 5182, 5193, (5192,))
            tick(38456)
            vm.pc = 38460
            pointer = cells.value(5193)
            value = memory.load(cells.pointer(5190), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(38460)
            vm.pc = 38463
            vm.auxiliary = (0, 506359810)
            tick(38463)
            vm.pc = 38468
            vm._write(5184, memory.load(cells.pointer(5183), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38468)
            vm.pc = 38470
            vm._jump(873)
            continue
        raise PrimarySemanticUnavailable('independent material window left its source-bound blocks')


def _material_publication_premix(vm, tick):
    cells, memory = vm.cells, vm.memory
    while vm.pc != 41119:
        if vm.block == 910:
            tick(39468)
            vm.pc = 39470
            vm._jump(916)
            continue
        if vm.block == 916:
            tick(39470)
            _phi(vm, 39470, (5322, 2, 145, 910, 5323, 917))
            tick(39477)
            vm.pc = 39482
            vm._write(5324, int(cells.value(5322) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(39482)
            vm.pc = 39486
            vm._jump(918 if cells.value(5324) != 0 else 919)
            continue
        if vm.block == 918:
            tick(39486)
            vm.pc = 39491
            vm._write(5325, cells.value(5322) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39491)
            vm.pc = 39492
            tick(39492)
            vm.pc = 39495
            vm.auxiliary = (0, 871337986)
            tick(39495)
            vm.pc = 39500
            vm._write(5326, memory.load(cells.pointer(5325), 2, signed=True) + memory.load(cells.pointer(3272), 2, signed=True), 8, 'once1.integer')
            tick(39500)
            vm.pc = 39505
            value = memory.load(cells.pointer(5326), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(5327, value >> (count & 31), 4, 'once8.logical_shift')
            tick(39505)
            _pointer(vm, 39505, 91, 112, 5328, (145, 391))
            tick(39513)
            vm.pc = 39517
            value = memory.load(cells.value(5328), 8)
            vm._write(5329, value, 8, 'high.load')
            tick(39517)
            vm.pc = 39522
            vm._write(5330, cells.value(5329) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39522)
            vm.pc = 39527
            vm._write(5331, memory.load(cells.pointer(5330), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(39527)
            vm.pc = 39530
            vm.auxiliary = (0, 43854)
            tick(39530)
            vm.pc = 39536
            vm._write(5332, memory.load(cells.pointer(5327), 2, signed=True) ^ memory.load(cells.pointer(5331), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(39536)
            vm.pc = 39541
            _convert(vm, 8, 5332, 5333)
            tick(39541)
            _pointer(vm, 39541, 91, 112, 5334, (145, 311, 5333))
            tick(39550)
            vm.pc = 39554
            value = memory.load(cells.value(5334), 8)
            vm._write(5335, value, 8, 'high.load')
            tick(39554)
            vm.pc = 39557
            vm.auxiliary = (0, 683809827)
            tick(39557)
            _equal(vm, 39562, 8, 5335, 1140, 5336)
            tick(39562)
            vm.pc = 39566
            vm._jump(920 if cells.value(5336) != 0 else 921)
            continue
        if vm.block == 921:
            tick(39566)
            vm.pc = 39571
            value = memory.load(cells.pointer(5329), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(5337, value >> (count & 63), 8, 'once8.logical_shift')
            tick(39571)
            vm.pc = 39576
            vm._write(5338, cells.value(5337) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39576)
            vm.pc = 39581
            vm._write(5339, memory.load(cells.pointer(5338), 2, signed=True) ^ memory.load(cells.pointer(5326), 2, signed=True), 8, 'L14.binary_q')
            tick(39581)
            vm.pc = 39582
            tick(39582)
            vm.pc = 39585
            vm.auxiliary = (0, 45908)
            tick(39585)
            vm.pc = 39590
            vm._write(5340, memory.load(cells.pointer(5339), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(39590)
            vm.pc = 39595
            _convert(vm, 8, 5340, 5341)
            tick(39595)
            _pointer(vm, 39595, 78, 5335, 5342, (5341,))
            tick(39602)
            vm.pc = 39606
            value = memory.load(cells.value(5342), 8)
            vm._write(5343, value, 8, 'high.load')
            tick(39606)
            vm.pc = 39609
            vm.auxiliary = (0, 1789031059)
            tick(39609)
            vm.pc = 39614
            vm._write(5344, int(memory.load(cells.pointer(5343), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(39614)
            vm.pc = 39618
            vm._jump(920 if cells.value(5344) != 0 else 922)
            continue
        if vm.block == 922:
            tick(39618)
            _pointer(vm, 39618, 79, 5343, 5345, (145, 269))
            tick(39626)
            vm.pc = 39630
            value = memory.load(cells.value(5345), 2)
            vm._write(5346, value, 4, 'high.load')
            tick(39630)
            vm.pc = 39631
            tick(39631)
            vm.pc = 39634
            vm.auxiliary = (0, 1041372803)
            tick(39634)
            vm.pc = 39639
            vm._write(5347, int(memory.load(cells.pointer(5346), 2, signed=True) == memory.load(cells.pointer(5326), 2, signed=True)), 4, 'once17.integer')
            tick(39639)
            vm.pc = 39643
            vm._jump(923 if cells.value(5347) != 0 else 920)
            continue
        if vm.block == 923:
            tick(39643)
            _pointer(vm, 39643, 79, 5343, 5348, (145, 360))
            tick(39651)
            vm.pc = 39655
            value = memory.load(cells.value(5348), 4)
            vm._write(5349, value, 4, 'high.load')
            tick(39655)
            _pointer(vm, 39655, 79, 5343, 5350, (145, 158))
            tick(39663)
            vm.pc = 39667
            value = memory.load(cells.value(5350), 4)
            vm._write(5351, value, 4, 'high.load')
            tick(39667)
            vm.pc = 39672
            vm._write(5352, memory.load(cells.pointer(5351), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'L14.binary_q')
            tick(39672)
            vm.pc = 39673
            tick(39673)
            vm.pc = 39676
            vm.auxiliary = (0, 1611301380)
            tick(39676)
            vm.pc = 39681
            vm._write(5353, memory.load(cells.pointer(5352), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(39681)
            _pointer(vm, 39681, 79, 5343, 5354, (145, 269))
            tick(39689)
            vm.pc = 39693
            value = memory.load(cells.value(5354), 2)
            vm._write(5355, value, 4, 'high.load')
            tick(39693)
            vm.pc = 39698
            _convert(vm, 4, 5355, 5356)
            tick(39698)
            vm.pc = 39701
            vm.auxiliary = (0, 20333)
            tick(39701)
            vm.pc = 39707
            vm._write(5357, memory.load(cells.pointer(5353), 4, signed=True) ^ memory.load(cells.pointer(5356), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(39707)
            vm.pc = 39710
            vm.auxiliary = (0, 1666040323)
            tick(39710)
            vm.pc = 39715
            vm._write(5358, memory.load(cells.pointer(5357), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(39715)
            _pointer(vm, 39715, 79, 5343, 5359, (145, 311))
            tick(39723)
            vm.pc = 39727
            value = memory.load(cells.value(5359), 8)
            vm._write(5360, value, 8, 'high.load')
            tick(39727)
            vm.pc = 39732
            cells.copy_q_clear_owned(5360, 5361)
            tick(39732)
            vm.pc = 39737
            vm._write(5362, cells.value(5361) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39737)
            vm.pc = 39740
            vm.auxiliary = (0, 10861)
            tick(39740)
            vm.pc = 39746
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5363, memory.load(cells.pointer(5358), 4, signed=True) ^ memory.load(cells.pointer(5362), 4, signed=True), 8, 'typed.selector5.q')
            tick(39746)
            vm.pc = 39749
            vm.auxiliary = (0, 1014391300)
            tick(39749)
            vm.pc = 39754
            vm._write(5364, memory.load(cells.pointer(5363), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(39754)
            vm.pc = 39759
            value = memory.load(cells.pointer(5361), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5365, value >> (count & 63), 8, 'once8.logical_shift')
            tick(39759)
            vm.pc = 39764
            vm._write(5366, cells.value(5365) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39764)
            vm.pc = 39767
            vm.auxiliary = (0, 43349)
            tick(39767)
            vm.pc = 39773
            vm._write(5367, memory.load(cells.pointer(5364), 4, signed=True) ^ memory.load(cells.pointer(5366), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(39773)
            vm.pc = 39776
            vm.auxiliary = (0, 1309045251)
            tick(39776)
            vm.pc = 39781
            vm._write(5368, memory.load(cells.pointer(5367), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(39781)
            vm.pc = 39786
            vm._write(5369, cells.value(5329) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39786)
            vm.pc = 39791
            vm._write(5370, memory.load(cells.pointer(5368), 4, signed=True) ^ memory.load(cells.pointer(5369), 4, signed=True), 8, 'L14.binary_q')
            tick(39791)
            vm.pc = 39794
            vm.auxiliary = (0, 2063708676)
            tick(39794)
            vm.pc = 39799
            vm._write(5371, memory.load(cells.pointer(5370), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(39799)
            vm.pc = 39804
            value = memory.load(cells.pointer(5329), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5372, value >> (count & 63), 8, 'once8.logical_shift')
            tick(39804)
            vm.pc = 39809
            vm._write(5373, cells.value(5372) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39809)
            vm.pc = 39812
            vm.auxiliary = (0, 63869)
            tick(39812)
            vm.pc = 39818
            vm._write(5374, memory.load(cells.pointer(5371), 4, signed=True) ^ memory.load(cells.pointer(5373), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(39818)
            vm.pc = 39821
            vm.auxiliary = (0, 2074440196)
            tick(39821)
            vm.pc = 39826
            vm._write(5375, memory.load(cells.pointer(5374), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(39826)
            vm.pc = 39830
            value = memory.load(cells.value(5360), 1)
            vm._write(5376, value, 4, 'high.load')
            tick(39830)
            vm.pc = 39835
            _convert(vm, 4, 5376, 5377)
            tick(39835)
            vm.pc = 39838
            vm.auxiliary = (0, 60774)
            tick(39838)
            vm.pc = 39844
            vm._write(5378, memory.load(cells.pointer(5375), 4, signed=True) ^ memory.load(cells.pointer(5377), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(39844)
            vm.pc = 39847
            vm.auxiliary = (0, 2019869187)
            tick(39847)
            vm.pc = 39852
            vm._write(5379, memory.load(cells.pointer(5378), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(39852)
            vm.pc = 39855
            vm.auxiliary = (0, 1631780275)
            tick(39855)
            _equal(vm, 39860, 4, 5349, 5379, 5380)
            tick(39860)
            vm.pc = 39864
            vm._jump(920 if cells.value(5380) != 0 else 924)
            continue
        if vm.block == 924:
            tick(39864)
            vm.pc = 39868
            pointer = cells.value(5348)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(39868)
            vm.pc = 39870
            vm._jump(920)
            continue
        if vm.block == 920:
            tick(39870)
            _phi(vm, 39870, (5381, 5, 857, 918, 857, 922, 5343, 923, 5343, 924, 5343, 921))
            tick(39883)
            vm.pc = 39884
            tick(39884)
            vm.pc = 39887
            vm.auxiliary = (0, 780289283)
            tick(39887)
            _equal(vm, 39892, 8, 5381, 857, 5382)
            tick(39892)
            vm.pc = 39896
            vm._jump(917 if cells.value(5382) != 0 else 925)
            continue
        if vm.block == 925:
            tick(39896)
            _pointer(vm, 39896, 194, 4391, 5383, (145, 5322))
            tick(39904)
            vm.pc = 39908
            value = memory.load(cells.value(5383), 8)
            vm._write(5384, value, 8, 'high.load')
            tick(39908)
            _pointer(vm, 39908, 1, 5000, 5385, (5384,))
            tick(39915)
            vm.pc = 39919
            value = memory.load(cells.value(5385), 1)
            vm._write(5386, value, 4, 'high.load')
            tick(39919)
            _pointer(vm, 39919, 79, 5381, 5387, (145, 311))
            tick(39927)
            vm.pc = 39931
            value = memory.load(cells.value(5387), 8)
            vm._write(5388, value, 8, 'L5.unsigned_load')
            tick(39931)
            vm.pc = 39935
            pointer = cells.value(5388)
            value = memory.load(cells.pointer(5386), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(39935)
            vm.pc = 39937
            vm._jump(917)
            continue
        if vm.block == 917:
            tick(39937)
            vm.pc = 39938
            tick(39938)
            vm.pc = 39941
            vm.auxiliary = (0, 1863536641)
            tick(39941)
            vm.pc = 39946
            vm._write(5323, memory.load(cells.pointer(5322), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(39946)
            vm.pc = 39948
            vm._jump(916)
            continue
        if vm.block == 919:
            tick(39948)
            _pointer(vm, 39948, 75, 106, 5389, (145, 391))
            tick(39956)
            vm.pc = 39960
            value = memory.load(cells.value(5389), 4)
            vm._write(5390, value, 4, 'high.load')
            tick(39960)
            _pointer(vm, 39960, 75, 106, 5391, (145, 360))
            tick(39968)
            vm.pc = 39972
            value = memory.load(cells.value(5391), 4)
            vm._write(5392, value, 4, 'high.load')
            tick(39972)
            _pointer(vm, 39972, 75, 106, 5393, (145, 149))
            tick(39980)
            vm.pc = 39984
            value = memory.load(cells.value(5393), 4)
            vm._write(5394, value, 4, 'high.load')
            tick(39984)
            vm.pc = 39985
            tick(39985)
            vm.pc = 39988
            vm.auxiliary = (0, 49239)
            tick(39988)
            vm.pc = 39993
            vm._write(5396, memory.load(cells.pointer(5394), 4, signed=True) & memory.load(cells.pointer(5395), 4, signed=True), 8, 'typed.selector1.q')
            tick(39993)
            vm.pc = 39998
            vm._write(5398, int(cells.value(5396) > cells.value(5397)), 4, 'L31.comparison')
            tick(39998)
            vm.pc = 40003
            vm._write(5400, memory.load(cells.pointer(5392), 4, signed=True) & memory.load(cells.pointer(5399), 4, signed=True), 8, 'L13.binary_q')
            tick(40003)
            vm.pc = 40006
            vm.auxiliary = (0, 1706186115)
            tick(40006)
            _equal(vm, 40011, 4, 5400, 158, 5401)
            tick(40011)
            vm.pc = 40016
            vm._write(5402, int(cells.value(5390) > cells.value(269)), 4, 'L31.comparison')
            tick(40016)
            vm.pc = 40021
            cells.copy_q_clear_owned(56, 5403)
            tick(40021)
            vm.pc = 40025
            pointer = cells.value(56)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(40025)
            vm.pc = 40027
            vm._jump(926)
            continue
        if vm.block == 926:
            tick(40027)
            _phi(vm, 40027, (5404, 2, 145, 919, 5405, 927))
            tick(40034)
            vm.pc = 40039
            vm._write(5406, int(cells.value(5404) < cells.value(166)), 4, 'once18.unsigned_q')
            tick(40039)
            vm.pc = 40043
            vm._jump(928 if cells.value(5406) != 0 else 929)
            continue
        if vm.block == 928:
            tick(40043)
            vm.pc = 40048
            vm._write(5407, cells.value(5404) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40048)
            vm.pc = 40049
            tick(40049)
            vm.pc = 40052
            vm.auxiliary = (0, 354177026)
            tick(40052)
            vm.pc = 40057
            vm._write(5409, memory.load(cells.pointer(5407), 2, signed=True) + memory.load(cells.pointer(5408), 2, signed=True), 8, 'once1.integer')
            tick(40057)
            vm.pc = 40062
            value = memory.load(cells.pointer(5409), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(5410, value >> (count & 31), 4, 'once8.logical_shift')
            tick(40062)
            _pointer(vm, 40062, 91, 112, 5411, (145, 391))
            tick(40070)
            vm.pc = 40074
            value = memory.load(cells.value(5411), 8)
            vm._write(5412, value, 8, 'high.load')
            tick(40074)
            vm.pc = 40079
            vm._write(5413, cells.value(5412) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40079)
            vm.pc = 40082
            vm.auxiliary = (0, 36916)
            tick(40082)
            vm.pc = 40087
            vm._write(5414, memory.load(cells.pointer(5413), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(40087)
            vm.pc = 40090
            vm.auxiliary = (0, 65309)
            tick(40090)
            vm.pc = 40096
            vm._write(5415, memory.load(cells.pointer(5410), 2, signed=True) ^ memory.load(cells.pointer(5414), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(40096)
            vm.pc = 40101
            _convert(vm, 8, 5415, 5416)
            tick(40101)
            _pointer(vm, 40101, 91, 112, 5417, (145, 311, 5416))
            tick(40110)
            vm.pc = 40114
            value = memory.load(cells.value(5417), 8)
            vm._write(5418, value, 8, 'high.load')
            tick(40114)
            vm.pc = 40117
            vm.auxiliary = (0, 1457670499)
            tick(40117)
            _equal(vm, 40122, 8, 5418, 1140, 5419)
            tick(40122)
            vm.pc = 40126
            vm._jump(930 if cells.value(5419) != 0 else 931)
            continue
        if vm.block == 931:
            tick(40126)
            vm.pc = 40131
            value = memory.load(cells.pointer(5412), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(5420, value >> (count & 63), 8, 'once8.logical_shift')
            tick(40131)
            vm.pc = 40136
            vm._write(5421, cells.value(5420) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40136)
            vm.pc = 40137
            tick(40137)
            vm.pc = 40140
            vm.auxiliary = (0, 15471)
            tick(40140)
            vm.pc = 40146
            vm._write(5422, memory.load(cells.pointer(5421), 2, signed=True) ^ memory.load(cells.pointer(5409), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(40146)
            vm.pc = 40149
            vm.auxiliary = (0, 21093)
            tick(40149)
            vm.pc = 40154
            vm._write(5423, memory.load(cells.pointer(5422), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(40154)
            vm.pc = 40159
            _convert(vm, 8, 5423, 5424)
            tick(40159)
            _pointer(vm, 40159, 78, 5418, 5425, (5424,))
            tick(40166)
            vm.pc = 40170
            value = memory.load(cells.value(5425), 8)
            vm._write(5426, value, 8, 'high.load')
            tick(40170)
            vm.pc = 40173
            vm.auxiliary = (0, 1031986067)
            tick(40173)
            _equal(vm, 40178, 8, 5426, 857, 5427)
            tick(40178)
            vm.pc = 40182
            vm._jump(930 if cells.value(5427) != 0 else 932)
            continue
        if vm.block == 932:
            tick(40182)
            _pointer(vm, 40182, 79, 5426, 5428, (145, 269))
            tick(40190)
            vm.pc = 40194
            value = memory.load(cells.value(5428), 2)
            vm._write(5429, value, 4, 'high.load')
            tick(40194)
            vm.pc = 40195
            tick(40195)
            vm.pc = 40198
            vm.auxiliary = (0, 1856111763)
            tick(40198)
            vm.pc = 40203
            vm._write(5430, int(memory.load(cells.pointer(5429), 2, signed=True) == memory.load(cells.pointer(5409), 2, signed=True)), 4, 'once17.integer')
            tick(40203)
            vm.pc = 40207
            vm._jump(933 if cells.value(5430) != 0 else 930)
            continue
        if vm.block == 933:
            tick(40207)
            _pointer(vm, 40207, 79, 5426, 5431, (145, 360))
            tick(40215)
            vm.pc = 40219
            value = memory.load(cells.value(5431), 4)
            vm._write(5432, value, 4, 'high.load')
            tick(40219)
            _pointer(vm, 40219, 79, 5426, 5433, (145, 158))
            tick(40227)
            vm.pc = 40231
            value = memory.load(cells.value(5433), 4)
            vm._write(5434, value, 4, 'high.load')
            tick(40231)
            vm.pc = 40232
            tick(40232)
            vm.pc = 40235
            vm.auxiliary = (0, 60951)
            tick(40235)
            vm.pc = 40241
            vm._write(5435, memory.load(cells.pointer(5434), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(40241)
            vm.pc = 40244
            vm.auxiliary = (0, 1322217988)
            tick(40244)
            vm.pc = 40249
            vm._write(5436, memory.load(cells.pointer(5435), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40249)
            _pointer(vm, 40249, 79, 5426, 5437, (145, 269))
            tick(40257)
            vm.pc = 40261
            value = memory.load(cells.value(5437), 2)
            vm._write(5438, value, 4, 'high.load')
            tick(40261)
            vm.pc = 40266
            _convert(vm, 4, 5438, 5439)
            tick(40266)
            vm.pc = 40269
            vm.auxiliary = (0, 57102)
            tick(40269)
            vm.pc = 40275
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5440, memory.load(cells.pointer(5436), 4, signed=True) ^ memory.load(cells.pointer(5439), 4, signed=True), 8, 'typed.selector5.q')
            tick(40275)
            vm.pc = 40278
            vm.auxiliary = (0, 1712546308)
            tick(40278)
            vm.pc = 40283
            vm._write(5441, memory.load(cells.pointer(5440), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40283)
            _pointer(vm, 40283, 79, 5426, 5442, (145, 311))
            tick(40291)
            vm.pc = 40295
            value = memory.load(cells.value(5442), 8)
            vm._write(5443, value, 8, 'high.load')
            tick(40295)
            vm.pc = 40300
            cells.copy_q_clear_owned(5443, 5444)
            tick(40300)
            vm.pc = 40305
            vm._write(5445, cells.value(5444) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40305)
            vm.pc = 40310
            vm._write(5446, memory.load(cells.pointer(5441), 4, signed=True) ^ memory.load(cells.pointer(5445), 4, signed=True), 8, 'L14.binary_q')
            tick(40310)
            vm.pc = 40313
            vm.auxiliary = (0, 469488132)
            tick(40313)
            vm.pc = 40318
            vm._write(5447, memory.load(cells.pointer(5446), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40318)
            vm.pc = 40323
            value = memory.load(cells.pointer(5444), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5448, value >> (count & 63), 8, 'once8.logical_shift')
            tick(40323)
            vm.pc = 40328
            vm._write(5449, cells.value(5448) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40328)
            vm.pc = 40333
            vm._write(5450, memory.load(cells.pointer(5447), 4, signed=True) ^ memory.load(cells.pointer(5449), 4, signed=True), 8, 'L14.binary_q')
            tick(40333)
            vm.pc = 40336
            vm.auxiliary = (0, 462094851)
            tick(40336)
            vm.pc = 40341
            vm._write(5451, memory.load(cells.pointer(5450), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40341)
            vm.pc = 40346
            vm._write(5452, cells.value(5412) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40346)
            vm.pc = 40349
            vm.auxiliary = (0, 63790)
            tick(40349)
            vm.pc = 40355
            vm._write(5453, memory.load(cells.pointer(5451), 4, signed=True) ^ memory.load(cells.pointer(5452), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(40355)
            vm.pc = 40358
            vm.auxiliary = (0, 1677455875)
            tick(40358)
            vm.pc = 40363
            vm._write(5454, memory.load(cells.pointer(5453), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40363)
            vm.pc = 40368
            value = memory.load(cells.pointer(5412), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5455, value >> (count & 63), 8, 'once8.logical_shift')
            tick(40368)
            vm.pc = 40373
            vm._write(5456, cells.value(5455) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40373)
            vm.pc = 40376
            vm.auxiliary = (0, 32285)
            tick(40376)
            vm.pc = 40382
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5457, memory.load(cells.pointer(5454), 4, signed=True) ^ memory.load(cells.pointer(5456), 4, signed=True), 8, 'typed.selector5.q')
            tick(40382)
            vm.pc = 40385
            vm.auxiliary = (0, 355410436)
            tick(40385)
            vm.pc = 40390
            vm._write(5458, memory.load(cells.pointer(5457), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40390)
            vm.pc = 40394
            value = memory.load(cells.value(5443), 1)
            vm._write(5459, value, 4, 'high.load')
            tick(40394)
            vm.pc = 40399
            _convert(vm, 4, 5459, 5460)
            tick(40399)
            vm.pc = 40402
            vm.auxiliary = (0, 39806)
            tick(40402)
            vm.pc = 40408
            vm._write(5461, memory.load(cells.pointer(5458), 4, signed=True) ^ memory.load(cells.pointer(5460), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(40408)
            vm.pc = 40411
            vm.auxiliary = (0, 1921364484)
            tick(40411)
            vm.pc = 40416
            vm._write(5462, memory.load(cells.pointer(5461), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40416)
            vm.pc = 40419
            vm.auxiliary = (0, 1187131395)
            tick(40419)
            vm.pc = 40424
            vm._write(5463, int(memory.load(cells.pointer(5432), 4, signed=True) == memory.load(cells.pointer(5462), 4, signed=True)), 4, 'once17.integer')
            tick(40424)
            vm.pc = 40428
            vm._jump(930 if cells.value(5463) != 0 else 934)
            continue
        if vm.block == 934:
            tick(40428)
            vm.pc = 40432
            pointer = cells.value(5431)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(40432)
            vm.pc = 40434
            vm._jump(930)
            continue
        if vm.block == 930:
            tick(40434)
            _phi(vm, 40434, (5464, 5, 857, 928, 857, 932, 5426, 933, 5426, 934, 5426, 931))
            tick(40447)
            vm.pc = 40448
            tick(40448)
            vm.pc = 40451
            vm.auxiliary = (0, 1041418995)
            tick(40451)
            vm.pc = 40456
            vm._write(5465, int(memory.load(cells.pointer(5464), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(40456)
            vm.pc = 40460
            vm._jump(935 if cells.value(5465) != 0 else 936)
            continue
        if vm.block == 936:
            tick(40460)
            _pointer(vm, 40460, 79, 5464, 5466, (145, 311))
            tick(40468)
            vm.pc = 40472
            value = memory.load(cells.value(5466), 8)
            vm._write(5467, value, 8, 'high.load')
            tick(40472)
            vm.pc = 40476
            value = memory.load(cells.value(5467), 1)
            vm._write(5468, value, 4, 'high.load')
            tick(40476)
            _pointer(vm, 40476, 1, 5403, 5469, (5404,))
            tick(40483)
            vm.pc = 40487
            pointer = cells.value(5469)
            value = memory.load(cells.pointer(5468), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(40487)
            vm.pc = 40489
            vm._jump(927)
            continue
        if vm.block == 935:
            tick(40489)
            _pointer(vm, 40489, 1, 5403, 5470, (5404,))
            tick(40496)
            vm.pc = 40500
            pointer = cells.value(5470)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(40500)
            vm.pc = 40502
            vm._jump(927)
            continue
        if vm.block == 927:
            tick(40502)
            vm.pc = 40503
            tick(40503)
            vm.pc = 40506
            vm.auxiliary = (0, 913473537)
            tick(40506)
            vm.pc = 40511
            vm._write(5405, memory.load(cells.pointer(5404), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(40511)
            vm.pc = 40513
            vm._jump(926)
            continue
        if vm.block == 929:
            tick(40513)
            vm.pc = 40517
            value = memory.load(cells.value(56), 8)
            vm._write(5471, value, 8, 'high.load')
            tick(40517)
            vm.pc = 40522
            cells.copy_q_clear_owned(46, 5472)
            tick(40522)
            vm.pc = 40526
            pointer = cells.value(46)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(40526)
            vm.pc = 40528
            vm._jump(937)
            continue
        if vm.block == 937:
            tick(40528)
            _phi(vm, 40528, (5473, 2, 145, 929, 5474, 938))
            tick(40535)
            vm.pc = 40540
            vm._write(5475, int(cells.value(5473) < cells.value(166)), 4, 'once18.unsigned_q')
            tick(40540)
            vm.pc = 40544
            vm._jump(939 if cells.value(5475) != 0 else 940)
            continue
        if vm.block == 939:
            tick(40544)
            vm.pc = 40549
            vm._write(5476, cells.value(5473) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40549)
            vm.pc = 40550
            tick(40550)
            vm.pc = 40553
            vm.auxiliary = (0, 1619914754)
            tick(40553)
            vm.pc = 40558
            vm._write(5478, memory.load(cells.pointer(5476), 2, signed=True) + memory.load(cells.pointer(5477), 2, signed=True), 8, 'once1.integer')
            tick(40558)
            vm.pc = 40563
            value = memory.load(cells.pointer(5478), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(5479, value >> (count & 31), 4, 'once8.logical_shift')
            tick(40563)
            _pointer(vm, 40563, 91, 112, 5480, (145, 391))
            tick(40571)
            vm.pc = 40575
            value = memory.load(cells.value(5480), 8)
            vm._write(5481, value, 8, 'high.load')
            tick(40575)
            vm.pc = 40580
            vm._write(5482, cells.value(5481) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40580)
            vm.pc = 40585
            vm._write(5483, memory.load(cells.pointer(5482), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(40585)
            vm.pc = 40588
            vm.auxiliary = (0, 11100)
            tick(40588)
            vm.pc = 40594
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5484, memory.load(cells.pointer(5479), 2, signed=True) ^ memory.load(cells.pointer(5483), 2, signed=True), 8, 'typed.selector5.q')
            tick(40594)
            vm.pc = 40599
            _convert(vm, 8, 5484, 5485)
            tick(40599)
            _pointer(vm, 40599, 91, 112, 5486, (145, 311, 5485))
            tick(40608)
            vm.pc = 40612
            value = memory.load(cells.value(5486), 8)
            vm._write(5487, value, 8, 'L5.unsigned_load')
            tick(40612)
            vm.pc = 40615
            vm.auxiliary = (0, 1655856755)
            tick(40615)
            _equal(vm, 40620, 8, 5487, 1140, 5488)
            tick(40620)
            vm.pc = 40624
            vm._jump(941 if cells.value(5488) != 0 else 942)
            continue
        if vm.block == 942:
            tick(40624)
            vm.pc = 40629
            value = memory.load(cells.pointer(5481), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(5489, value >> (count & 63), 8, 'once8.logical_shift')
            tick(40629)
            vm.pc = 40634
            vm._write(5490, cells.value(5489) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40634)
            vm.pc = 40635
            tick(40635)
            vm.pc = 40638
            vm.auxiliary = (0, 43582)
            tick(40638)
            vm.pc = 40644
            vm._write(5491, memory.load(cells.pointer(5490), 2, signed=True) ^ memory.load(cells.pointer(5478), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(40644)
            vm.pc = 40647
            vm.auxiliary = (0, 63078)
            tick(40647)
            vm.pc = 40652
            vm._write(5492, memory.load(cells.pointer(5491), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(40652)
            vm.pc = 40657
            _convert(vm, 8, 5492, 5493)
            tick(40657)
            _pointer(vm, 40657, 78, 5487, 5494, (5493,))
            tick(40664)
            vm.pc = 40668
            value = memory.load(cells.value(5494), 8)
            vm._write(5495, value, 8, 'L5.unsigned_load')
            tick(40668)
            vm.pc = 40671
            vm.auxiliary = (0, 345113843)
            tick(40671)
            vm.pc = 40676
            vm._write(5496, int(memory.load(cells.pointer(5495), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(40676)
            vm.pc = 40680
            vm._jump(941 if cells.value(5496) != 0 else 943)
            continue
        if vm.block == 943:
            tick(40680)
            _pointer(vm, 40680, 79, 5495, 5497, (145, 269))
            tick(40688)
            vm.pc = 40692
            value = memory.load(cells.value(5497), 2)
            vm._write(5498, value, 4, 'high.load')
            tick(40692)
            vm.pc = 40693
            tick(40693)
            vm.pc = 40696
            vm.auxiliary = (0, 1174549043)
            tick(40696)
            _equal(vm, 40701, 2, 5498, 5478, 5499)
            tick(40701)
            vm.pc = 40705
            vm._jump(944 if cells.value(5499) != 0 else 941)
            continue
        if vm.block == 944:
            tick(40705)
            _pointer(vm, 40705, 79, 5495, 5500, (145, 360))
            tick(40713)
            vm.pc = 40717
            value = memory.load(cells.value(5500), 4)
            vm._write(5501, value, 4, 'high.load')
            tick(40717)
            _pointer(vm, 40717, 79, 5495, 5502, (145, 158))
            tick(40725)
            vm.pc = 40729
            value = memory.load(cells.value(5502), 4)
            vm._write(5503, value, 4, 'high.load')
            tick(40729)
            vm.pc = 40730
            tick(40730)
            vm.pc = 40733
            vm.auxiliary = (0, 40460)
            tick(40733)
            vm.pc = 40739
            vm._write(5504, memory.load(cells.pointer(5503), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(40739)
            vm.pc = 40742
            vm.auxiliary = (0, 910885379)
            tick(40742)
            vm.pc = 40747
            vm._write(5505, memory.load(cells.pointer(5504), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40747)
            _pointer(vm, 40747, 79, 5495, 5506, (145, 269))
            tick(40755)
            vm.pc = 40759
            value = memory.load(cells.value(5506), 2)
            vm._write(5507, value, 4, 'high.load')
            tick(40759)
            vm.pc = 40764
            _convert(vm, 4, 5507, 5508)
            tick(40764)
            vm.pc = 40767
            vm.auxiliary = (0, 6469)
            tick(40767)
            vm.pc = 40773
            vm._write(5509, memory.load(cells.pointer(5505), 4, signed=True) ^ memory.load(cells.pointer(5508), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(40773)
            vm.pc = 40776
            vm.auxiliary = (0, 1620644356)
            tick(40776)
            vm.pc = 40781
            vm._write(5510, memory.load(cells.pointer(5509), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40781)
            _pointer(vm, 40781, 79, 5495, 5511, (145, 311))
            tick(40789)
            vm.pc = 40793
            value = memory.load(cells.value(5511), 8)
            vm._write(5512, value, 8, 'high.load')
            tick(40793)
            vm.pc = 40798
            cells.copy_q_clear_owned(5512, 5513)
            tick(40798)
            vm.pc = 40803
            vm._write(5514, cells.value(5513) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40803)
            vm.pc = 40806
            vm.auxiliary = (0, 56150)
            tick(40806)
            vm.pc = 40812
            vm._write(5515, memory.load(cells.pointer(5510), 4, signed=True) ^ memory.load(cells.pointer(5514), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(40812)
            vm.pc = 40815
            vm.auxiliary = (0, 717685252)
            tick(40815)
            vm.pc = 40820
            vm._write(5516, memory.load(cells.pointer(5515), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40820)
            vm.pc = 40825
            value = memory.load(cells.pointer(5513), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5517, value >> (count & 63), 8, 'once8.logical_shift')
            tick(40825)
            vm.pc = 40830
            vm._write(5518, cells.value(5517) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40830)
            vm.pc = 40833
            vm.auxiliary = (0, 63773)
            tick(40833)
            vm.pc = 40839
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5519, memory.load(cells.pointer(5516), 4, signed=True) ^ memory.load(cells.pointer(5518), 4, signed=True), 8, 'typed.selector5.q')
            tick(40839)
            vm.pc = 40842
            vm.auxiliary = (0, 667640324)
            tick(40842)
            vm.pc = 40847
            vm._write(5520, memory.load(cells.pointer(5519), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40847)
            vm.pc = 40852
            vm._write(5521, cells.value(5481) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40852)
            vm.pc = 40857
            vm._write(5522, memory.load(cells.pointer(5520), 4, signed=True) ^ memory.load(cells.pointer(5521), 4, signed=True), 8, 'L14.binary_q')
            tick(40857)
            vm.pc = 40860
            vm.auxiliary = (0, 413176323)
            tick(40860)
            vm.pc = 40865
            vm._write(5523, memory.load(cells.pointer(5522), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40865)
            vm.pc = 40870
            value = memory.load(cells.pointer(5481), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5524, value >> (count & 63), 8, 'once8.logical_shift')
            tick(40870)
            vm.pc = 40875
            vm._write(5525, cells.value(5524) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(40875)
            vm.pc = 40878
            vm.auxiliary = (0, 63495)
            tick(40878)
            vm.pc = 40884
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5526, memory.load(cells.pointer(5523), 4, signed=True) ^ memory.load(cells.pointer(5525), 4, signed=True), 8, 'typed.selector5.q')
            tick(40884)
            vm.pc = 40887
            vm.auxiliary = (0, 1826812420)
            tick(40887)
            vm.pc = 40892
            vm._write(5527, memory.load(cells.pointer(5526), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40892)
            vm.pc = 40896
            value = memory.load(cells.value(5512), 1)
            vm._write(5528, value, 4, 'high.load')
            tick(40896)
            vm.pc = 40901
            _convert(vm, 4, 5528, 5529)
            tick(40901)
            vm.pc = 40904
            vm.auxiliary = (0, 55348)
            tick(40904)
            vm.pc = 40910
            vm._write(5530, memory.load(cells.pointer(5527), 4, signed=True) ^ memory.load(cells.pointer(5529), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(40910)
            vm.pc = 40913
            vm.auxiliary = (0, 1915027971)
            tick(40913)
            vm.pc = 40918
            vm._write(5531, memory.load(cells.pointer(5530), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(40918)
            vm.pc = 40921
            vm.auxiliary = (0, 1582452531)
            tick(40921)
            _equal(vm, 40926, 4, 5501, 5531, 5532)
            tick(40926)
            vm.pc = 40930
            vm._jump(941 if cells.value(5532) != 0 else 945)
            continue
        if vm.block == 945:
            tick(40930)
            vm.pc = 40934
            pointer = cells.value(5500)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(40934)
            vm.pc = 40936
            vm._jump(941)
            continue
        if vm.block == 941:
            tick(40936)
            _phi(vm, 40936, (5533, 5, 857, 939, 857, 943, 5495, 944, 5495, 945, 5495, 942))
            tick(40949)
            vm.pc = 40950
            tick(40950)
            vm.pc = 40953
            vm.auxiliary = (0, 738379811)
            tick(40953)
            _equal(vm, 40958, 8, 5533, 857, 5534)
            tick(40958)
            vm.pc = 40962
            vm._jump(946 if cells.value(5534) != 0 else 947)
            continue
        if vm.block == 947:
            tick(40962)
            _pointer(vm, 40962, 79, 5533, 5535, (145, 311))
            tick(40970)
            vm.pc = 40974
            value = memory.load(cells.value(5535), 8)
            vm._write(5536, value, 8, 'high.load')
            tick(40974)
            vm.pc = 40978
            value = memory.load(cells.value(5536), 1)
            vm._write(5537, value, 4, 'L5.unsigned_load')
            tick(40978)
            _pointer(vm, 40978, 1, 5472, 5538, (5473,))
            tick(40985)
            vm.pc = 40989
            pointer = cells.value(5538)
            value = memory.load(cells.pointer(5537), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(40989)
            vm.pc = 40991
            vm._jump(938)
            continue
        if vm.block == 946:
            tick(40991)
            _pointer(vm, 40991, 1, 5472, 5539, (5473,))
            tick(40998)
            vm.pc = 41002
            pointer = cells.value(5539)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(41002)
            vm.pc = 41004
            vm._jump(938)
            continue
        if vm.block == 938:
            tick(41004)
            vm.pc = 41005
            tick(41005)
            vm.pc = 41008
            vm.auxiliary = (0, 1917911042)
            tick(41008)
            vm.pc = 41013
            vm._write(5474, memory.load(cells.pointer(5473), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(41013)
            vm.pc = 41015
            vm._jump(937)
            continue
        if vm.block == 940:
            tick(41015)
            vm.pc = 41019
            value = memory.load(cells.value(46), 8)
            vm._write(5540, value, 8, 'high.load')
            tick(41019)
            vm.pc = 41024
            cells.copy_q_clear_owned(57, 5541)
            tick(41024)
            _pointer(vm, 41024, 39, 57, 5542, (145, 145))
            tick(41032)
            vm.pc = 41039
            selected = 4251 if cells.value(5402) != 0 else 145
            vm._write(5543, memory.load(cells.pointer(selected), 8, signed=True), 8, 'L7.selected_q')
            tick(41039)
            vm.pc = 41043
            pointer = cells.value(5542)
            value = memory.load(cells.pointer(5543), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(41043)
            _pointer(vm, 41043, 39, 57, 5544, (145, 163))
            tick(41051)
            vm.pc = 41058
            selected = 5545 if cells.value(5398) != 0 else 145
            vm._write(5546, memory.load(cells.pointer(selected), 8, signed=True), 8, 'L7.selected_q')
            tick(41058)
            vm.pc = 41062
            pointer = cells.value(5544)
            value = memory.load(cells.pointer(5546), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(41062)
            _pointer(vm, 41062, 39, 57, 5547, (145, 166))
            tick(41070)
            vm.pc = 41077
            selected = 145 if cells.value(5401) != 0 else 5548
            vm._write(5549, memory.load(cells.pointer(selected), 8, signed=True), 8, 'L7.selected_q')
            tick(41077)
            vm.pc = 41081
            pointer = cells.value(5547)
            value = memory.load(cells.pointer(5549), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(41081)
            _pointer(vm, 41081, 37, 58, 5550, (145, 145))
            tick(41089)
            vm.pc = 41090
            tick(41090)
            vm.pc = 41093
            vm.auxiliary = (0, 28943)
            tick(41093)
            vm.pc = 41098
            vm._write(5552, memory.load(cells.pointer(5540), 8, signed=True) & memory.load(cells.pointer(5551), 8, signed=True), 8, 'typed.selector1.q')
            tick(41098)
            vm.pc = 41101
            vm.auxiliary = (0, 54861)
            tick(41101)
            vm.pc = 41106
            vm._write(5553, memory.load(cells.pointer(5471), 8, signed=True) & memory.load(cells.pointer(5551), 8, signed=True), 8, 'typed.selector1.q')
            tick(41106)
            _pointer(vm, 41106, 37, 58, 5554, (145, 145))
            tick(41114)
            vm.pc = 41119
            cells.copy_q_clear_owned(51, 5555)
            continue
        raise PrimarySemanticUnavailable('independent material window left its source-bound blocks')
