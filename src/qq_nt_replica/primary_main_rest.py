from hashlib import sha256
from threading import get_ident

from .primary_main_material_getter import _convert, _equal, _pair_control, _phi, _pointer, _single_control
from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable


REST_ENTRY = (45584, 1063, 1060, False)
REST_EXIT = (62638, 1529, 1527, False)


def execute_primary_main_rest(vm, *, charge=None):
    if (type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != MAIN_SHA256 or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) != REST_ENTRY):
        raise PrimarySemanticUnavailable('independent Main rest requires its fixed entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            type(owner) is not dict or owner.get('vm') is not vm or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._execute_thread != get_ident() or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            len(runtime._program_calls) != 1 or runtime._program_calls[0]['name'] != 'main' or
            runtime._program_calls[0]['hosts'] is not None):
        raise PrimarySemanticUnavailable('independent Main rest requires the current owner without replay')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent Main rest cannot enter a stopped or pending body')
    state = dict(entryWord=45584, exitWord=62638, backend='DIRECT_MAIN_HOST_FREE_REST',
                 referenceRecordCount=0, completed=False, traceComplete=False,
                 completeIndependentMain=False, nextCallBackend='RESIDUAL_GENERIC_HOST129_CHILD')
    vm.primary_main_rest_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if charge is not None:
            charge()
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    _main_rest(vm, tick)
    state['completed'] = True
    return state



def _main_rest(vm, tick):
    cells, memory = vm.cells, vm.memory
    while vm.pc != 62638:
        if vm.block == 1063:
            tick(45584)
            vm.pc = 45589
            cells.copy_q_clear_owned(131, 6153)
            tick(45589)
            vm.pc = 45593
            pointer = cells.value(131)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(45593)
            vm.pc = 45598
            cells.copy_q_clear_owned(60, 6154)
            tick(45598)
            vm.pc = 45602
            pointer = cells.value(60)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='L6.store_integer')
            tick(45602)
            vm.pc = 45604
            vm._jump(1071)
            continue
        if vm.block == 1071:
            tick(45604)
            _phi(vm, 45604, (6155, 2, 145, 1063, 6156, 1072))
            tick(45611)
            vm.pc = 45616
            vm._write(6157, int(cells.value(6155) < cells.value(163)), 4, 'once18.unsigned_q')
            tick(45616)
            vm.pc = 45620
            vm._jump(1073 if cells.value(6157) != 0 else 1074)
            continue
        if vm.block == 1073:
            tick(45620)
            vm.pc = 45625
            vm._write(6158, cells.value(6155) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45625)
            vm.pc = 45626
            tick(45626)
            vm.pc = 45629
            vm.auxiliary = (0, 2067685377)
            tick(45629)
            vm.pc = 45634
            vm._write(6160, memory.load(cells.pointer(6158), 2, signed=True) + memory.load(cells.pointer(6159), 2, signed=True), 8, 'once1.integer')
            tick(45634)
            vm.pc = 45639
            value = memory.load(cells.pointer(6160), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(6161, value >> (count & 31), 4, 'once8.logical_shift')
            tick(45639)
            _pointer(vm, 45639, 91, 112, 6162, (145, 391))
            tick(45647)
            vm.pc = 45651
            value = memory.load(cells.value(6162), 8)
            vm._write(6163, value, 8, 'high.load')
            tick(45651)
            vm.pc = 45656
            vm._write(6164, cells.value(6163) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45656)
            vm.pc = 45659
            vm.auxiliary = (0, 17742)
            tick(45659)
            vm.pc = 45664
            vm._write(6165, memory.load(cells.pointer(6164), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(45664)
            vm.pc = 45669
            vm._write(6166, memory.load(cells.pointer(6161), 2, signed=True) ^ memory.load(cells.pointer(6165), 2, signed=True), 8, 'L14.binary_q')
            tick(45669)
            vm.pc = 45674
            _convert(vm, 8, 6166, 6167)
            tick(45674)
            _pointer(vm, 45674, 91, 112, 6168, (145, 311, 6167))
            tick(45683)
            vm.pc = 45687
            value = memory.load(cells.value(6168), 8)
            vm._write(6169, value, 8, 'high.load')
            tick(45687)
            vm.pc = 45690
            vm.auxiliary = (0, 2089988899)
            tick(45690)
            vm.pc = 45695
            vm._write(6170, int(memory.load(cells.pointer(6169), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(45695)
            vm.pc = 45699
            vm._jump(1075 if cells.value(6170) != 0 else 1076)
            continue
        if vm.block == 1076:
            tick(45699)
            vm.pc = 45704
            value = memory.load(cells.pointer(6163), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(6171, value >> (count & 63), 8, 'once8.logical_shift')
            tick(45704)
            vm.pc = 45709
            vm._write(6172, cells.value(6171) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45709)
            vm.pc = 45710
            tick(45710)
            vm.pc = 45713
            vm.auxiliary = (0, 11582)
            tick(45713)
            vm.pc = 45719
            vm._write(6173, memory.load(cells.pointer(6172), 2, signed=True) ^ memory.load(cells.pointer(6160), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(45719)
            vm.pc = 45722
            vm.auxiliary = (0, 46397)
            tick(45722)
            vm.pc = 45727
            vm._write(6174, memory.load(cells.pointer(6173), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(45727)
            vm.pc = 45732
            _convert(vm, 8, 6174, 6175)
            tick(45732)
            _pointer(vm, 45732, 78, 6169, 6176, (6175,))
            tick(45739)
            vm.pc = 45743
            value = memory.load(cells.value(6176), 8)
            vm._write(6177, value, 8, 'high.load')
            tick(45743)
            vm.pc = 45746
            vm.auxiliary = (0, 1333957747)
            tick(45746)
            vm.pc = 45751
            vm._write(6178, int(memory.load(cells.pointer(6177), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(45751)
            vm.pc = 45755
            vm._jump(1075 if cells.value(6178) != 0 else 1077)
            continue
        if vm.block == 1077:
            tick(45755)
            _pointer(vm, 45755, 79, 6177, 6179, (145, 269))
            tick(45763)
            vm.pc = 45767
            value = memory.load(cells.value(6179), 2)
            vm._write(6180, value, 4, 'high.load')
            tick(45767)
            vm.pc = 45768
            tick(45768)
            vm.pc = 45771
            vm.auxiliary = (0, 174216851)
            tick(45771)
            vm.pc = 45776
            vm._write(6181, int(memory.load(cells.pointer(6180), 2, signed=True) == memory.load(cells.pointer(6160), 2, signed=True)), 4, 'once17.integer')
            tick(45776)
            vm.pc = 45780
            vm._jump(1078 if cells.value(6181) != 0 else 1075)
            continue
        if vm.block == 1078:
            tick(45780)
            _pointer(vm, 45780, 79, 6177, 6182, (145, 360))
            tick(45788)
            vm.pc = 45792
            value = memory.load(cells.value(6182), 4)
            vm._write(6183, value, 4, 'high.load')
            tick(45792)
            _pointer(vm, 45792, 79, 6177, 6184, (145, 158))
            tick(45800)
            vm.pc = 45804
            value = memory.load(cells.value(6184), 4)
            vm._write(6185, value, 4, 'high.load')
            tick(45804)
            vm.pc = 45805
            tick(45805)
            vm.pc = 45808
            vm.auxiliary = (0, 23628)
            tick(45808)
            vm.pc = 45814
            vm._write(6186, memory.load(cells.pointer(6185), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(45814)
            vm.pc = 45817
            vm.auxiliary = (0, 1813230084)
            tick(45817)
            vm.pc = 45822
            vm._write(6187, memory.load(cells.pointer(6186), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45822)
            _pointer(vm, 45822, 79, 6177, 6188, (145, 269))
            tick(45830)
            vm.pc = 45834
            value = memory.load(cells.value(6188), 2)
            vm._write(6189, value, 4, 'high.load')
            tick(45834)
            vm.pc = 45839
            _convert(vm, 4, 6189, 6190)
            tick(45839)
            vm.pc = 45842
            vm.auxiliary = (0, 36222)
            tick(45842)
            vm.pc = 45848
            vm._write(6191, memory.load(cells.pointer(6187), 4, signed=True) ^ memory.load(cells.pointer(6190), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(45848)
            vm.pc = 45851
            vm.auxiliary = (0, 766640643)
            tick(45851)
            vm.pc = 45856
            vm._write(6192, memory.load(cells.pointer(6191), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45856)
            _pointer(vm, 45856, 79, 6177, 6193, (145, 311))
            tick(45864)
            vm.pc = 45868
            value = memory.load(cells.value(6193), 8)
            vm._write(6194, value, 8, 'high.load')
            tick(45868)
            vm.pc = 45873
            cells.copy_q_clear_owned(6194, 6195)
            tick(45873)
            vm.pc = 45878
            vm._write(6196, cells.value(6195) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45878)
            vm.pc = 45883
            vm._write(6197, memory.load(cells.pointer(6192), 4, signed=True) ^ memory.load(cells.pointer(6196), 4, signed=True), 8, 'L14.binary_q')
            tick(45883)
            vm.pc = 45886
            vm.auxiliary = (0, 1920463363)
            tick(45886)
            vm.pc = 45891
            vm._write(6198, memory.load(cells.pointer(6197), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45891)
            vm.pc = 45896
            value = memory.load(cells.pointer(6195), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6199, value >> (count & 63), 8, 'once8.logical_shift')
            tick(45896)
            vm.pc = 45901
            vm._write(6200, cells.value(6199) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45901)
            vm.pc = 45906
            vm._write(6201, memory.load(cells.pointer(6198), 4, signed=True) ^ memory.load(cells.pointer(6200), 4, signed=True), 8, 'L14.binary_q')
            tick(45906)
            vm.pc = 45909
            vm.auxiliary = (0, 855859716)
            tick(45909)
            vm.pc = 45914
            vm._write(6202, memory.load(cells.pointer(6201), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45914)
            vm.pc = 45919
            vm._write(6203, cells.value(6163) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45919)
            vm.pc = 45922
            vm.auxiliary = (0, 63764)
            tick(45922)
            vm.pc = 45928
            vm._write(6204, memory.load(cells.pointer(6202), 4, signed=True) ^ memory.load(cells.pointer(6203), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(45928)
            vm.pc = 45931
            vm.auxiliary = (0, 2070143492)
            tick(45931)
            vm.pc = 45936
            vm._write(6205, memory.load(cells.pointer(6204), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45936)
            vm.pc = 45941
            value = memory.load(cells.pointer(6163), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6206, value >> (count & 63), 8, 'once8.logical_shift')
            tick(45941)
            vm.pc = 45946
            vm._write(6207, cells.value(6206) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45946)
            vm.pc = 45949
            vm.auxiliary = (0, 55935)
            tick(45949)
            vm.pc = 45955
            vm._write(6208, memory.load(cells.pointer(6205), 4, signed=True) ^ memory.load(cells.pointer(6207), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(45955)
            vm.pc = 45958
            vm.auxiliary = (0, 808841731)
            tick(45958)
            vm.pc = 45963
            vm._write(6209, memory.load(cells.pointer(6208), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45963)
            vm.pc = 45967
            value = memory.load(cells.value(6194), 1)
            vm._write(6210, value, 4, 'L5.unsigned_load')
            tick(45967)
            vm.pc = 45972
            _convert(vm, 4, 6210, 6211)
            tick(45972)
            vm.pc = 45975
            vm.auxiliary = (0, 31831)
            tick(45975)
            vm.pc = 45981
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6212, memory.load(cells.pointer(6209), 4, signed=True) ^ memory.load(cells.pointer(6211), 4, signed=True), 8, 'typed.selector5.q')
            tick(45981)
            vm.pc = 45984
            vm.auxiliary = (0, 1969762819)
            tick(45984)
            vm.pc = 45989
            vm._write(6213, memory.load(cells.pointer(6212), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45989)
            vm.pc = 45992
            vm.auxiliary = (0, 1492300691)
            tick(45992)
            _equal(vm, 45997, 4, 6183, 6213, 6214)
            tick(45997)
            vm.pc = 46001
            vm._jump(1075 if cells.value(6214) != 0 else 1079)
            continue
        if vm.block == 1079:
            tick(46001)
            vm.pc = 46005
            pointer = cells.value(6182)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(46005)
            vm.pc = 46007
            vm._jump(1075)
            continue
        if vm.block == 1075:
            tick(46007)
            _phi(vm, 46007, (6215, 5, 857, 1073, 857, 1077, 6177, 1078, 6177, 1079, 6177, 1076))
            tick(46020)
            vm.pc = 46021
            tick(46021)
            vm.pc = 46024
            vm.auxiliary = (0, 1153605155)
            tick(46024)
            _equal(vm, 46029, 8, 6215, 857, 6216)
            tick(46029)
            vm.pc = 46033
            vm._jump(1080 if cells.value(6216) != 0 else 1081)
            continue
        if vm.block == 1081:
            tick(46033)
            _pointer(vm, 46033, 79, 6215, 6217, (145, 311))
            tick(46041)
            vm.pc = 46045
            value = memory.load(cells.value(6217), 8)
            vm._write(6218, value, 8, 'high.load')
            tick(46045)
            vm.pc = 46049
            value = memory.load(cells.value(6218), 1)
            vm._write(6219, value, 4, 'high.load')
            tick(46049)
            _pointer(vm, 46049, 1, 6154, 6220, (6155,))
            tick(46056)
            vm.pc = 46060
            pointer = cells.value(6220)
            value = memory.load(cells.pointer(6219), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(46060)
            vm.pc = 46062
            vm._jump(1072)
            continue
        if vm.block == 1080:
            tick(46062)
            _pointer(vm, 46062, 1, 6154, 6221, (6155,))
            tick(46069)
            vm.pc = 46073
            pointer = cells.value(6221)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(46073)
            vm.pc = 46075
            vm._jump(1072)
            continue
        if vm.block == 1072:
            tick(46075)
            vm.pc = 46076
            tick(46076)
            vm.pc = 46079
            vm.auxiliary = (0, 1476374529)
            tick(46079)
            vm.pc = 46084
            vm._write(6156, memory.load(cells.pointer(6155), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(46084)
            vm.pc = 46086
            vm._jump(1071)
            continue
        if vm.block == 1074:
            tick(46086)
            vm.pc = 46090
            value = memory.load(cells.value(60), 8)
            vm._write(6222, value, 8, 'high.load')
            tick(46090)
            vm.pc = 46095
            vm._write(6223, cells.value(6222) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46095)
            vm.pc = 46100
            cells.copy_q_clear_owned(131, 6224)
            tick(46100)
            vm.pc = 46104
            pointer = cells.value(6224)
            value = memory.load(cells.pointer(6223), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(46104)
            vm.pc = 46109
            cells.copy_q_clear_owned(61, 6225)
            tick(46109)
            vm.pc = 46113
            pointer = cells.value(61)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(46113)
            vm.pc = 46115
            vm._jump(1082)
            continue
        if vm.block == 1082:
            tick(46115)
            _phi(vm, 46115, (6226, 2, 145, 1074, 6227, 1083))
            tick(46122)
            vm.pc = 46127
            vm._write(6228, int(cells.value(6226) < cells.value(163)), 4, 'once18.unsigned_q')
            tick(46127)
            vm.pc = 46131
            vm._jump(1084 if cells.value(6228) != 0 else 1085)
            continue
        if vm.block == 1084:
            tick(46131)
            vm.pc = 46136
            vm._write(6229, cells.value(6226) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46136)
            vm.pc = 46137
            tick(46137)
            vm.pc = 46140
            vm.auxiliary = (0, 1359777794)
            tick(46140)
            vm.pc = 46145
            vm._write(6230, memory.load(cells.pointer(6229), 2, signed=True) + memory.load(cells.pointer(1381), 2, signed=True), 8, 'once1.integer')
            tick(46145)
            vm.pc = 46150
            value = memory.load(cells.pointer(6230), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(6231, value >> (count & 31), 4, 'once8.logical_shift')
            tick(46150)
            _pointer(vm, 46150, 91, 112, 6232, (145, 391))
            tick(46158)
            vm.pc = 46162
            value = memory.load(cells.value(6232), 8)
            vm._write(6233, value, 8, 'high.load')
            tick(46162)
            vm.pc = 46167
            vm._write(6234, cells.value(6233) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46167)
            vm.pc = 46172
            vm._write(6235, memory.load(cells.pointer(6234), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(46172)
            vm.pc = 46175
            vm.auxiliary = (0, 59701)
            tick(46175)
            vm.pc = 46181
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6236, memory.load(cells.pointer(6231), 2, signed=True) ^ memory.load(cells.pointer(6235), 2, signed=True), 8, 'typed.selector5.q')
            tick(46181)
            vm.pc = 46186
            _convert(vm, 8, 6236, 6237)
            tick(46186)
            _pointer(vm, 46186, 91, 112, 6238, (145, 311, 6237))
            tick(46195)
            vm.pc = 46199
            value = memory.load(cells.value(6238), 8)
            vm._write(6239, value, 8, 'high.load')
            tick(46199)
            vm.pc = 46202
            vm.auxiliary = (0, 937615587)
            tick(46202)
            vm.pc = 46207
            vm._write(6240, int(memory.load(cells.pointer(6239), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(46207)
            vm.pc = 46211
            vm._jump(1086 if cells.value(6240) != 0 else 1087)
            continue
        if vm.block == 1087:
            tick(46211)
            vm.pc = 46216
            value = memory.load(cells.pointer(6233), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(6241, value >> (count & 63), 8, 'once8.logical_shift')
            tick(46216)
            vm.pc = 46221
            vm._write(6242, cells.value(6241) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46221)
            vm.pc = 46222
            tick(46222)
            vm.pc = 46225
            vm.auxiliary = (0, 40197)
            tick(46225)
            vm.pc = 46231
            vm._write(6243, memory.load(cells.pointer(6242), 2, signed=True) ^ memory.load(cells.pointer(6230), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(46231)
            vm.pc = 46236
            vm._write(6244, memory.load(cells.pointer(6243), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(46236)
            vm.pc = 46241
            _convert(vm, 8, 6244, 6245)
            tick(46241)
            _pointer(vm, 46241, 78, 6239, 6246, (6245,))
            tick(46248)
            vm.pc = 46252
            value = memory.load(cells.value(6246), 8)
            vm._write(6247, value, 8, 'high.load')
            tick(46252)
            vm.pc = 46255
            vm.auxiliary = (0, 934453939)
            tick(46255)
            vm.pc = 46260
            vm._write(6248, int(memory.load(cells.pointer(6247), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(46260)
            vm.pc = 46264
            vm._jump(1086 if cells.value(6248) != 0 else 1088)
            continue
        if vm.block == 1088:
            tick(46264)
            _pointer(vm, 46264, 79, 6247, 6249, (145, 269))
            tick(46272)
            vm.pc = 46276
            value = memory.load(cells.value(6249), 2)
            vm._write(6250, value, 4, 'high.load')
            tick(46276)
            vm.pc = 46277
            tick(46277)
            vm.pc = 46280
            vm.auxiliary = (0, 492967555)
            tick(46280)
            _equal(vm, 46285, 2, 6250, 6230, 6251)
            tick(46285)
            vm.pc = 46289
            vm._jump(1089 if cells.value(6251) != 0 else 1086)
            continue
        if vm.block == 1089:
            tick(46289)
            _pointer(vm, 46289, 79, 6247, 6252, (145, 360))
            tick(46297)
            vm.pc = 46301
            value = memory.load(cells.value(6252), 4)
            vm._write(6253, value, 4, 'L5.unsigned_load')
            tick(46301)
            _pointer(vm, 46301, 79, 6247, 6254, (145, 158))
            tick(46309)
            vm.pc = 46313
            value = memory.load(cells.value(6254), 4)
            vm._write(6255, value, 4, 'high.load')
            tick(46313)
            vm.pc = 46314
            tick(46314)
            vm.pc = 46317
            vm.auxiliary = (0, 34900)
            tick(46317)
            vm.pc = 46323
            vm._write(6256, memory.load(cells.pointer(6255), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(46323)
            vm.pc = 46326
            vm.auxiliary = (0, 1057268228)
            tick(46326)
            vm.pc = 46331
            vm._write(6257, memory.load(cells.pointer(6256), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(46331)
            _pointer(vm, 46331, 79, 6247, 6258, (145, 269))
            tick(46339)
            vm.pc = 46343
            value = memory.load(cells.value(6258), 2)
            vm._write(6259, value, 4, 'high.load')
            tick(46343)
            vm.pc = 46348
            _convert(vm, 4, 6259, 6260)
            tick(46348)
            vm.pc = 46351
            vm.auxiliary = (0, 60012)
            tick(46351)
            vm.pc = 46357
            vm._write(6261, memory.load(cells.pointer(6257), 4, signed=True) ^ memory.load(cells.pointer(6260), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(46357)
            vm.pc = 46360
            vm.auxiliary = (0, 857076227)
            tick(46360)
            vm.pc = 46365
            vm._write(6262, memory.load(cells.pointer(6261), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(46365)
            _pointer(vm, 46365, 79, 6247, 6263, (145, 311))
            tick(46373)
            vm.pc = 46377
            value = memory.load(cells.value(6263), 8)
            vm._write(6264, value, 8, 'high.load')
            tick(46377)
            vm.pc = 46382
            cells.copy_q_clear_owned(6264, 6265)
            tick(46382)
            vm.pc = 46387
            vm._write(6266, cells.value(6265) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46387)
            vm.pc = 46390
            vm.auxiliary = (0, 57149)
            tick(46390)
            vm.pc = 46396
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6267, memory.load(cells.pointer(6262), 4, signed=True) ^ memory.load(cells.pointer(6266), 4, signed=True), 8, 'typed.selector5.q')
            tick(46396)
            vm.pc = 46399
            vm.auxiliary = (0, 1813594628)
            tick(46399)
            vm.pc = 46404
            vm._write(6268, memory.load(cells.pointer(6267), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(46404)
            vm.pc = 46409
            value = memory.load(cells.pointer(6265), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6269, value >> (count & 63), 8, 'once8.logical_shift')
            tick(46409)
            vm.pc = 46414
            vm._write(6270, cells.value(6269) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46414)
            vm.pc = 46417
            vm.auxiliary = (0, 28164)
            tick(46417)
            vm.pc = 46423
            vm._write(6271, memory.load(cells.pointer(6268), 4, signed=True) ^ memory.load(cells.pointer(6270), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(46423)
            vm.pc = 46426
            vm.auxiliary = (0, 865038851)
            tick(46426)
            vm.pc = 46431
            vm._write(6272, memory.load(cells.pointer(6271), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(46431)
            vm.pc = 46436
            vm._write(6273, cells.value(6233) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46436)
            vm.pc = 46439
            vm.auxiliary = (0, 48766)
            tick(46439)
            vm.pc = 46445
            vm._write(6274, memory.load(cells.pointer(6272), 4, signed=True) ^ memory.load(cells.pointer(6273), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(46445)
            vm.pc = 46448
            vm.auxiliary = (0, 1169523203)
            tick(46448)
            vm.pc = 46453
            vm._write(6275, memory.load(cells.pointer(6274), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(46453)
            vm.pc = 46458
            value = memory.load(cells.pointer(6233), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6276, value >> (count & 63), 8, 'once8.logical_shift')
            tick(46458)
            vm.pc = 46463
            vm._write(6277, cells.value(6276) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46463)
            vm.pc = 46466
            vm.auxiliary = (0, 19252)
            tick(46466)
            vm.pc = 46472
            vm._write(6278, memory.load(cells.pointer(6275), 4, signed=True) ^ memory.load(cells.pointer(6277), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(46472)
            vm.pc = 46475
            vm.auxiliary = (0, 1727480324)
            tick(46475)
            vm.pc = 46480
            vm._write(6279, memory.load(cells.pointer(6278), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(46480)
            vm.pc = 46484
            value = memory.load(cells.value(6264), 1)
            vm._write(6280, value, 4, 'high.load')
            tick(46484)
            vm.pc = 46489
            _convert(vm, 4, 6280, 6281)
            tick(46489)
            vm.pc = 46494
            vm._write(6282, memory.load(cells.pointer(6279), 4, signed=True) ^ memory.load(cells.pointer(6281), 4, signed=True), 8, 'L14.binary_q')
            tick(46494)
            vm.pc = 46497
            vm.auxiliary = (0, 1474232835)
            tick(46497)
            vm.pc = 46502
            vm._write(6283, memory.load(cells.pointer(6282), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(46502)
            vm.pc = 46505
            vm.auxiliary = (0, 1001554451)
            tick(46505)
            vm.pc = 46510
            vm._write(6284, int(memory.load(cells.pointer(6253), 4, signed=True) == memory.load(cells.pointer(6283), 4, signed=True)), 4, 'once17.integer')
            tick(46510)
            vm.pc = 46514
            vm._jump(1086 if cells.value(6284) != 0 else 1090)
            continue
        if vm.block == 1090:
            tick(46514)
            vm.pc = 46518
            pointer = cells.value(6252)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(46518)
            vm.pc = 46520
            vm._jump(1086)
            continue
        if vm.block == 1086:
            tick(46520)
            _phi(vm, 46520, (6285, 5, 857, 1084, 857, 1088, 6247, 1089, 6247, 1090, 6247, 1087))
            tick(46533)
            vm.pc = 46534
            tick(46534)
            vm.pc = 46537
            vm.auxiliary = (0, 781357971)
            tick(46537)
            vm.pc = 46542
            vm._write(6286, int(memory.load(cells.pointer(6285), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(46542)
            vm.pc = 46546
            vm._jump(1091 if cells.value(6286) != 0 else 1092)
            continue
        if vm.block == 1092:
            tick(46546)
            _pointer(vm, 46546, 79, 6285, 6287, (145, 311))
            tick(46554)
            vm.pc = 46558
            value = memory.load(cells.value(6287), 8)
            vm._write(6288, value, 8, 'high.load')
            tick(46558)
            vm.pc = 46562
            value = memory.load(cells.value(6288), 1)
            vm._write(6289, value, 4, 'high.load')
            tick(46562)
            _pointer(vm, 46562, 1, 6225, 6290, (6226,))
            tick(46569)
            vm.pc = 46573
            pointer = cells.value(6290)
            value = memory.load(cells.pointer(6289), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(46573)
            vm.pc = 46575
            vm._jump(1083)
            continue
        if vm.block == 1091:
            tick(46575)
            _pointer(vm, 46575, 1, 6225, 6291, (6226,))
            tick(46582)
            vm.pc = 46586
            pointer = cells.value(6291)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(46586)
            vm.pc = 46588
            vm._jump(1083)
            continue
        if vm.block == 1083:
            tick(46588)
            vm.pc = 46589
            tick(46589)
            vm.pc = 46592
            vm.auxiliary = (0, 554209281)
            tick(46592)
            vm.pc = 46597
            vm._write(6227, memory.load(cells.pointer(6226), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(46597)
            vm.pc = 46599
            vm._jump(1082)
            continue
        if vm.block == 1085:
            tick(46599)
            vm.pc = 46603
            value = memory.load(cells.value(61), 8)
            vm._write(6292, value, 8, 'high.load')
            tick(46603)
            vm.pc = 46608
            vm._write(6293, cells.value(6292) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(46608)
            vm.pc = 46612
            pointer = cells.value(290)
            value = memory.load(cells.pointer(6293), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(46612)
            _pointer(vm, 46612, 70, 103, 6294, (145, 187))
            tick(46620)
            vm.pc = 46625
            cells.copy_q_clear_owned(6294, 6295)
            tick(46625)
            vm.pc = 46626
            tick(46626)
            vm.pc = 46629
            vm.auxiliary = (0, 21532)
            tick(46629)
            vm.pc = 46634
            vm._write(6296, memory.load(cells.pointer(6295), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(46634)
            _pointer(vm, 46634, 1, 2080, 6297, (163,))
            tick(46641)
            vm.pc = 46645
            value = memory.load(cells.value(2080), 1)
            vm._write(6298, value, 4, 'high.load')
            tick(46645)
            _pointer(vm, 46645, 1, 6294, 6299, (163,))
            tick(46652)
            vm.pc = 46656
            pointer = cells.value(6294)
            value = memory.load(cells.pointer(6298), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(46656)
            vm.pc = 46661
            cells.copy_q_clear_owned(6299, 6300)
            tick(46661)
            vm.pc = 46666
            vm._write(6301, memory.load(cells.pointer(6300), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(46666)
            vm.pc = 46669
            vm.auxiliary = (0, 1527950308)
            tick(46669)
            vm.pc = 46674
            vm._write(6302, int(memory.load(cells.pointer(6301), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(46674)
            vm.pc = 46676
            vm._jump(1093)
            continue
        if vm.block == 1093:
            tick(46676)
            vm.pc = 46681
            cells.copy_q_clear_owned(6299, 6303)
            tick(46681)
            vm.pc = 46682
            tick(46682)
            vm.pc = 46685
            vm.auxiliary = (0, 21092)
            tick(46685)
            vm.pc = 46690
            vm._write(6304, memory.load(cells.pointer(6303), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(46690)
            vm.pc = 46693
            vm.auxiliary = (0, 549623844)
            tick(46693)
            vm.pc = 46698
            vm._write(6305, int(memory.load(cells.pointer(6304), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(46698)
            vm.pc = 46701
            vm.auxiliary = (0, 228751318)
            tick(46701)
            vm.pc = 46706
            vm._write(6306, int(memory.load(cells.pointer(158), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(46706)
            vm.pc = 46709
            vm.auxiliary = (0, 45893)
            tick(46709)
            vm.pc = 46714
            vm._write(6307, memory.load(cells.pointer(6305), 1, signed=True) & memory.load(cells.pointer(6306), 1, signed=True), 8, 'typed.selector1.q')
            tick(46714)
            vm.pc = 46718
            vm._jump(1094 if cells.value(6307) != 0 else 1095)
            continue
        if vm.block == 1094:
            tick(46718)
            _pointer(vm, 46718, 1, 6297, 6308, (163,))
            tick(46725)
            vm.pc = 46729
            value = memory.load(cells.value(6297), 1)
            vm._write(6309, value, 4, 'high.load')
            tick(46729)
            _pointer(vm, 46729, 1, 6299, 6310, (163,))
            tick(46736)
            vm.pc = 46740
            pointer = cells.value(6299)
            value = memory.load(cells.pointer(6309), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(46740)
            vm.pc = 46741
            tick(46741)
            vm.pc = 46744
            vm.auxiliary = (0, 469270530)
            tick(46744)
            vm.pc = 46749
            vm._write(6311, memory.load(cells.pointer(158), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(46749)
            vm.pc = 46751
            vm._jump(1095)
            continue
        if vm.block == 1095:
            tick(46751)
            _phi(vm, 46751, (6312, 2, 6311, 1094, 158, 1093))
            tick(46758)
            _phi(vm, 46758, (6313, 2, 6310, 1094, 6299, 1093))
            tick(46765)
            _phi(vm, 46765, (6314, 2, 6308, 1094, 6297, 1093))
            tick(46772)
            vm.pc = 46777
            cells.copy_q_clear_owned(6313, 6315)
            tick(46777)
            vm.pc = 46782
            cells.copy_q_clear_owned(6314, 6316)
            tick(46782)
            vm.pc = 46783
            tick(46783)
            vm.pc = 46786
            vm.auxiliary = (0, 2090996486)
            tick(46786)
            vm.pc = 46791
            vm._write(6317, int(memory.load(cells.pointer(6312), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(46791)
            vm.pc = 46795
            vm._jump(1096 if cells.value(6317) != 0 else 1097)
            continue
        if vm.block == 1096:
            tick(46795)
            _pointer(vm, 46795, 1, 6314, 6318, (172,))
            tick(46802)
            vm.pc = 46807
            cells.copy_q_clear_owned(6318, 6319)
            tick(46807)
            vm.pc = 46811
            value = memory.load(cells.value(6316), 4)
            vm._write(6320, value, 4, 'high.load')
            tick(46811)
            _pointer(vm, 46811, 1, 6313, 6321, (172,))
            tick(46818)
            vm.pc = 46823
            cells.copy_q_clear_owned(6321, 6322)
            tick(46823)
            vm.pc = 46827
            pointer = cells.value(6315)
            value = memory.load(cells.pointer(6320), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(46827)
            vm.pc = 46828
            tick(46828)
            vm.pc = 46831
            vm.auxiliary = (0, 1368502273)
            tick(46831)
            vm.pc = 46836
            vm._write(6323, memory.load(cells.pointer(6312), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(46836)
            vm.pc = 46838
            vm._jump(1097)
            continue
        if vm.block == 1097:
            tick(46838)
            _phi(vm, 46838, (6324, 2, 6323, 1096, 6312, 1095))
            tick(46845)
            _phi(vm, 46845, (6325, 2, 6322, 1096, 6315, 1095))
            tick(46852)
            _phi(vm, 46852, (6326, 2, 6319, 1096, 6316, 1095))
            tick(46859)
            vm.pc = 46860
            tick(46860)
            vm.pc = 46863
            vm.auxiliary = (0, 647104742)
            tick(46863)
            vm.pc = 46868
            vm._write(6327, int(memory.load(cells.pointer(6324), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(46868)
            vm.pc = 46872
            vm._jump(1098 if cells.value(6327) != 0 else 1099)
            continue
        if vm.block == 1098:
            tick(46872)
            _pointer(vm, 46872, 3, 6326, 6328, (163,))
            tick(46879)
            vm.pc = 46883
            value = memory.load(cells.value(6326), 4)
            vm._write(6329, value, 4, 'high.load')
            tick(46883)
            _pointer(vm, 46883, 3, 6325, 6330, (163,))
            tick(46890)
            vm.pc = 46894
            pointer = cells.value(6325)
            value = memory.load(cells.pointer(6329), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(46894)
            vm.pc = 46895
            tick(46895)
            vm.pc = 46898
            vm.auxiliary = (0, 705097729)
            tick(46898)
            vm.pc = 46903
            vm._write(6331, memory.load(cells.pointer(6324), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(46903)
            vm.pc = 46905
            vm._jump(1099)
            continue
        if vm.block == 1099:
            tick(46905)
            _phi(vm, 46905, (6332, 2, 6331, 1098, 6324, 1097))
            tick(46912)
            _phi(vm, 46912, (6333, 2, 6330, 1098, 6325, 1097))
            tick(46919)
            _phi(vm, 46919, (6334, 2, 6328, 1098, 6326, 1097))
            tick(46926)
            vm.pc = 46927
            tick(46927)
            vm.pc = 46930
            vm.auxiliary = (0, 291644358)
            tick(46930)
            vm.pc = 46935
            vm._write(6335, int(memory.load(cells.pointer(6332), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(46935)
            vm.pc = 46939
            vm._jump(1100 if cells.value(6335) != 0 else 1101)
            continue
        if vm.block == 1100:
            tick(46939)
            _pointer(vm, 46939, 3, 6334, 6336, (163,))
            tick(46946)
            vm.pc = 46950
            value = memory.load(cells.value(6334), 4)
            vm._write(6337, value, 4, 'high.load')
            tick(46950)
            _pointer(vm, 46950, 3, 6333, 6338, (163,))
            tick(46957)
            vm.pc = 46961
            pointer = cells.value(6333)
            value = memory.load(cells.pointer(6337), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(46961)
            vm.pc = 46962
            tick(46962)
            vm.pc = 46965
            vm.auxiliary = (0, 965750785)
            tick(46965)
            vm.pc = 46970
            vm._write(6339, memory.load(cells.pointer(6332), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(46970)
            vm.pc = 46972
            vm._jump(1101)
            continue
        if vm.block == 1101:
            tick(46972)
            _phi(vm, 46972, (6340, 2, 6339, 1100, 6332, 1099))
            tick(46979)
            _phi(vm, 46979, (6341, 2, 6338, 1100, 6333, 1099))
            tick(46986)
            _phi(vm, 46986, (6342, 2, 6336, 1100, 6334, 1099))
            tick(46993)
            vm.pc = 46998
            cells.copy_q_clear_owned(6341, 6343)
            tick(46998)
            vm.pc = 47003
            cells.copy_q_clear_owned(6342, 6344)
            tick(47003)
            vm.pc = 47004
            tick(47004)
            vm.pc = 47007
            vm.auxiliary = (0, 1358041446)
            tick(47007)
            vm.pc = 47012
            vm._write(6345, int(memory.load(cells.pointer(6340), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(47012)
            vm.pc = 47016
            vm._jump(1102 if cells.value(6345) != 0 else 1103)
            continue
        if vm.block == 1102:
            tick(47016)
            _pointer(vm, 47016, 1, 6344, 6346, (163,))
            tick(47023)
            vm.pc = 47027
            value = memory.load(cells.value(6344), 1)
            vm._write(6347, value, 4, 'L5.unsigned_load')
            tick(47027)
            _pointer(vm, 47027, 1, 6343, 6348, (163,))
            tick(47034)
            vm.pc = 47038
            pointer = cells.value(6343)
            value = memory.load(cells.pointer(6347), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(47038)
            vm.pc = 47039
            tick(47039)
            vm.pc = 47042
            vm.auxiliary = (0, 1722703874)
            tick(47042)
            vm.pc = 47047
            vm._write(6349, memory.load(cells.pointer(6340), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(47047)
            vm.pc = 47049
            vm._jump(1103)
            continue
        if vm.block == 1103:
            tick(47049)
            _phi(vm, 47049, (6350, 2, 6349, 1102, 6340, 1101))
            tick(47056)
            _phi(vm, 47056, (6351, 2, 6348, 1102, 6343, 1101))
            tick(47063)
            _phi(vm, 47063, (6352, 2, 6346, 1102, 6344, 1101))
            tick(47070)
            vm.pc = 47071
            tick(47071)
            vm.pc = 47074
            vm.auxiliary = (0, 483572022)
            tick(47074)
            vm.pc = 47079
            vm._write(6353, int(memory.load(cells.pointer(6350), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(47079)
            vm.pc = 47083
            vm._jump(1104 if cells.value(6353) != 0 else 1105)
            continue
        if vm.block == 1104:
            tick(47083)
            _pointer(vm, 47083, 1, 6352, 6354, (163,))
            tick(47090)
            vm.pc = 47094
            value = memory.load(cells.value(6352), 1)
            vm._write(6355, value, 4, 'high.load')
            tick(47094)
            _pointer(vm, 47094, 1, 6351, 6356, (163,))
            tick(47101)
            vm.pc = 47105
            pointer = cells.value(6351)
            value = memory.load(cells.pointer(6355), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(47105)
            vm.pc = 47106
            tick(47106)
            vm.pc = 47109
            vm.auxiliary = (0, 1170898946)
            tick(47109)
            vm.pc = 47114
            vm._write(6357, memory.load(cells.pointer(6350), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(47114)
            vm.pc = 47116
            vm._jump(1105)
            continue
        if vm.block == 1105:
            tick(47116)
            _phi(vm, 47116, (6358, 2, 6357, 1104, 6350, 1103))
            tick(47123)
            _phi(vm, 47123, (6359, 2, 6356, 1104, 6351, 1103))
            tick(47130)
            _phi(vm, 47130, (6360, 2, 6354, 1104, 6352, 1103))
            tick(47137)
            vm.pc = 47138
            tick(47138)
            vm.pc = 47141
            vm.auxiliary = (0, 630343030)
            tick(47141)
            vm.pc = 47146
            vm._write(6361, int(memory.load(cells.pointer(6358), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(47146)
            vm.pc = 47150
            vm._jump(1106 if cells.value(6361) != 0 else 1107)
            continue
        if vm.block == 1106:
            tick(47150)
            _pointer(vm, 47150, 1, 6360, 6362, (163,))
            tick(47157)
            vm.pc = 47161
            value = memory.load(cells.value(6360), 1)
            vm._write(6363, value, 4, 'high.load')
            tick(47161)
            _pointer(vm, 47161, 1, 6359, 6364, (163,))
            tick(47168)
            vm.pc = 47172
            pointer = cells.value(6359)
            value = memory.load(cells.pointer(6363), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(47172)
            vm.pc = 47174
            vm._jump(1107)
            continue
        if vm.block == 1107:
            tick(47174)
            _phi(vm, 47174, (6365, 2, 6364, 1106, 6359, 1105))
            tick(47181)
            _phi(vm, 47181, (6366, 2, 6362, 1106, 6360, 1105))
            tick(47188)
            vm.pc = 47189
            tick(47189)
            vm.pc = 47192
            vm.auxiliary = (0, 1301418998)
            tick(47192)
            vm.pc = 47197
            vm._write(6367, int(memory.load(cells.pointer(6358), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(47197)
            vm.pc = 47201
            vm._jump(1108 if cells.value(6367) != 0 else 1109)
            continue
        if vm.block == 1108:
            tick(47201)
            vm.pc = 47205
            value = memory.load(cells.value(6366), 1)
            vm._write(6368, value, 4, 'high.load')
            tick(47205)
            vm.pc = 47209
            pointer = cells.value(6365)
            value = memory.load(cells.pointer(6368), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(47209)
            vm.pc = 47211
            vm._jump(1109)
            continue
        if vm.block == 1109:
            tick(47211)
            vm.pc = 47216
            cells.copy_q_clear_owned(132, 6369)
            tick(47216)
            vm.pc = 47221
            cells.copy_q_clear_owned(62, 6370)
            tick(47221)
            vm.pc = 47225
            pointer = cells.value(62)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(47225)
            vm.pc = 47227
            vm._jump(1110)
            continue
        if vm.block == 1110:
            tick(47227)
            _phi(vm, 47227, (6371, 2, 145, 1109, 6372, 1111))
            tick(47234)
            vm.pc = 47239
            vm._write(6373, int(cells.value(6371) < cells.value(166)), 4, 'once18.unsigned_q')
            tick(47239)
            vm.pc = 47243
            vm._jump(1112 if cells.value(6373) != 0 else 1113)
            continue
        if vm.block == 1112:
            tick(47243)
            vm.pc = 47248
            vm._write(6374, cells.value(6371) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(47248)
            vm.pc = 47249
            tick(47249)
            vm.pc = 47252
            vm.auxiliary = (0, 1665748993)
            tick(47252)
            vm.pc = 47257
            vm._write(6376, memory.load(cells.pointer(6374), 2, signed=True) + memory.load(cells.pointer(6375), 2, signed=True), 8, 'once1.integer')
            tick(47257)
            vm.pc = 47262
            value = memory.load(cells.pointer(6376), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(6377, value >> (count & 31), 4, 'once8.logical_shift')
            tick(47262)
            _pointer(vm, 47262, 91, 112, 6378, (145, 391))
            tick(47270)
            vm.pc = 47274
            value = memory.load(cells.value(6378), 8)
            vm._write(6379, value, 8, 'high.load')
            tick(47274)
            vm.pc = 47279
            vm._write(6380, cells.value(6379) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(47279)
            vm.pc = 47282
            vm.auxiliary = (0, 29262)
            tick(47282)
            vm.pc = 47287
            vm._write(6381, memory.load(cells.pointer(6380), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(47287)
            vm.pc = 47290
            vm.auxiliary = (0, 59508)
            tick(47290)
            vm.pc = 47296
            vm._write(6382, memory.load(cells.pointer(6377), 2, signed=True) ^ memory.load(cells.pointer(6381), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(47296)
            vm.pc = 47301
            _convert(vm, 8, 6382, 6383)
            tick(47301)
            _pointer(vm, 47301, 91, 112, 6384, (145, 311, 6383))
            tick(47310)
            vm.pc = 47314
            value = memory.load(cells.value(6384), 8)
            vm._write(6385, value, 8, 'high.load')
            tick(47314)
            vm.pc = 47317
            vm.auxiliary = (0, 1285694435)
            tick(47317)
            _equal(vm, 47322, 8, 6385, 1140, 6386)
            tick(47322)
            vm.pc = 47326
            vm._jump(1114 if cells.value(6386) != 0 else 1115)
            continue
        if vm.block == 1115:
            tick(47326)
            vm.pc = 47331
            value = memory.load(cells.pointer(6379), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(6387, value >> (count & 63), 8, 'once8.logical_shift')
            tick(47331)
            vm.pc = 47336
            vm._write(6388, cells.value(6387) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(47336)
            vm.pc = 47337
            tick(47337)
            vm.pc = 47340
            vm.auxiliary = (0, 64349)
            tick(47340)
            vm.pc = 47346
            vm._write(6389, memory.load(cells.pointer(6388), 2, signed=True) ^ memory.load(cells.pointer(6376), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(47346)
            vm.pc = 47349
            vm.auxiliary = (0, 49182)
            tick(47349)
            vm.pc = 47354
            vm._write(6390, memory.load(cells.pointer(6389), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(47354)
            vm.pc = 47359
            _convert(vm, 8, 6390, 6391)
            tick(47359)
            _pointer(vm, 47359, 78, 6385, 6392, (6391,))
            tick(47366)
            vm.pc = 47370
            value = memory.load(cells.value(6392), 8)
            vm._write(6393, value, 8, 'L5.unsigned_load')
            tick(47370)
            vm.pc = 47373
            vm.auxiliary = (0, 1997724099)
            tick(47373)
            _equal(vm, 47378, 8, 6393, 857, 6394)
            tick(47378)
            vm.pc = 47382
            vm._jump(1114 if cells.value(6394) != 0 else 1116)
            continue
        if vm.block == 1116:
            tick(47382)
            _pointer(vm, 47382, 79, 6393, 6395, (145, 269))
            tick(47390)
            vm.pc = 47394
            value = memory.load(cells.value(6395), 2)
            vm._write(6396, value, 4, 'high.load')
            tick(47394)
            vm.pc = 47395
            tick(47395)
            vm.pc = 47398
            vm.auxiliary = (0, 1428316963)
            tick(47398)
            vm.pc = 47403
            vm._write(6397, int(memory.load(cells.pointer(6396), 2, signed=True) == memory.load(cells.pointer(6376), 2, signed=True)), 4, 'once17.integer')
            tick(47403)
            vm.pc = 47407
            vm._jump(1117 if cells.value(6397) != 0 else 1114)
            continue
        if vm.block == 1117:
            tick(47407)
            _pointer(vm, 47407, 79, 6393, 6398, (145, 360))
            tick(47415)
            vm.pc = 47419
            value = memory.load(cells.value(6398), 4)
            vm._write(6399, value, 4, 'high.load')
            tick(47419)
            _pointer(vm, 47419, 79, 6393, 6400, (145, 158))
            tick(47427)
            vm.pc = 47431
            value = memory.load(cells.value(6400), 4)
            vm._write(6401, value, 4, 'high.load')
            tick(47431)
            vm.pc = 47436
            vm._write(6402, memory.load(cells.pointer(6401), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'L14.binary_q')
            tick(47436)
            vm.pc = 47437
            tick(47437)
            vm.pc = 47440
            vm.auxiliary = (0, 464474627)
            tick(47440)
            vm.pc = 47445
            vm._write(6403, memory.load(cells.pointer(6402), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(47445)
            _pointer(vm, 47445, 79, 6393, 6404, (145, 269))
            tick(47453)
            vm.pc = 47457
            value = memory.load(cells.value(6404), 2)
            vm._write(6405, value, 4, 'high.load')
            tick(47457)
            vm.pc = 47462
            _convert(vm, 4, 6405, 6406)
            tick(47462)
            vm.pc = 47465
            vm.auxiliary = (0, 38999)
            tick(47465)
            vm.pc = 47471
            vm._write(6407, memory.load(cells.pointer(6403), 4, signed=True) ^ memory.load(cells.pointer(6406), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(47471)
            vm.pc = 47474
            vm.auxiliary = (0, 911843843)
            tick(47474)
            vm.pc = 47479
            vm._write(6408, memory.load(cells.pointer(6407), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(47479)
            _pointer(vm, 47479, 79, 6393, 6409, (145, 311))
            tick(47487)
            vm.pc = 47491
            value = memory.load(cells.value(6409), 8)
            vm._write(6410, value, 8, 'high.load')
            tick(47491)
            vm.pc = 47496
            cells.copy_q_clear_owned(6410, 6411)
            tick(47496)
            vm.pc = 47501
            vm._write(6412, cells.value(6411) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(47501)
            vm.pc = 47504
            vm.auxiliary = (0, 23357)
            tick(47504)
            vm.pc = 47510
            vm._write(6413, memory.load(cells.pointer(6408), 4, signed=True) ^ memory.load(cells.pointer(6412), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(47510)
            vm.pc = 47513
            vm.auxiliary = (0, 871789059)
            tick(47513)
            vm.pc = 47518
            vm._write(6414, memory.load(cells.pointer(6413), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(47518)
            vm.pc = 47523
            value = memory.load(cells.pointer(6411), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6415, value >> (count & 63), 8, 'once8.logical_shift')
            tick(47523)
            vm.pc = 47528
            vm._write(6416, cells.value(6415) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(47528)
            vm.pc = 47531
            vm.auxiliary = (0, 32565)
            tick(47531)
            vm.pc = 47537
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6417, memory.load(cells.pointer(6414), 4, signed=True) ^ memory.load(cells.pointer(6416), 4, signed=True), 8, 'typed.selector5.q')
            tick(47537)
            vm.pc = 47540
            vm.auxiliary = (0, 1120371204)
            tick(47540)
            vm.pc = 47545
            vm._write(6418, memory.load(cells.pointer(6417), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(47545)
            vm.pc = 47550
            vm._write(6419, cells.value(6379) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(47550)
            vm.pc = 47553
            vm.auxiliary = (0, 36420)
            tick(47553)
            vm.pc = 47559
            vm._write(6420, memory.load(cells.pointer(6418), 4, signed=True) ^ memory.load(cells.pointer(6419), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(47559)
            vm.pc = 47562
            vm.auxiliary = (0, 1116549636)
            tick(47562)
            vm.pc = 47567
            vm._write(6421, memory.load(cells.pointer(6420), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(47567)
            vm.pc = 47572
            value = memory.load(cells.pointer(6379), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6422, value >> (count & 63), 8, 'once8.logical_shift')
            tick(47572)
            vm.pc = 47577
            vm._write(6423, cells.value(6422) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(47577)
            vm.pc = 47582
            vm._write(6424, memory.load(cells.pointer(6421), 4, signed=True) ^ memory.load(cells.pointer(6423), 4, signed=True), 8, 'L14.binary_q')
            tick(47582)
            vm.pc = 47585
            vm.auxiliary = (0, 1966731779)
            tick(47585)
            vm.pc = 47590
            vm._write(6425, memory.load(cells.pointer(6424), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(47590)
            vm.pc = 47594
            value = memory.load(cells.value(6410), 1)
            vm._write(6426, value, 4, 'high.load')
            tick(47594)
            vm.pc = 47599
            _convert(vm, 4, 6426, 6427)
            tick(47599)
            vm.pc = 47602
            vm.auxiliary = (0, 7191)
            tick(47602)
            vm.pc = 47608
            vm._write(6428, memory.load(cells.pointer(6425), 4, signed=True) ^ memory.load(cells.pointer(6427), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(47608)
            vm.pc = 47611
            vm.auxiliary = (0, 656282115)
            tick(47611)
            vm.pc = 47616
            vm._write(6429, memory.load(cells.pointer(6428), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(47616)
            vm.pc = 47619
            vm.auxiliary = (0, 803371075)
            tick(47619)
            _equal(vm, 47624, 4, 6399, 6429, 6430)
            tick(47624)
            vm.pc = 47628
            vm._jump(1114 if cells.value(6430) != 0 else 1118)
            continue
        if vm.block == 1118:
            tick(47628)
            vm.pc = 47632
            pointer = cells.value(6398)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(47632)
            vm.pc = 47634
            vm._jump(1114)
            continue
        if vm.block == 1114:
            tick(47634)
            _phi(vm, 47634, (6431, 5, 857, 1112, 857, 1116, 6393, 1117, 6393, 1118, 6393, 1115))
            tick(47647)
            vm.pc = 47648
            tick(47648)
            vm.pc = 47651
            vm.auxiliary = (0, 1892822787)
            tick(47651)
            vm.pc = 47656
            vm._write(6432, int(memory.load(cells.pointer(6431), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(47656)
            vm.pc = 47660
            vm._jump(1119 if cells.value(6432) != 0 else 1120)
            continue
        if vm.block == 1120:
            tick(47660)
            _pointer(vm, 47660, 79, 6431, 6433, (145, 311))
            tick(47668)
            vm.pc = 47672
            value = memory.load(cells.value(6433), 8)
            vm._write(6434, value, 8, 'high.load')
            tick(47672)
            vm.pc = 47676
            value = memory.load(cells.value(6434), 1)
            vm._write(6435, value, 4, 'high.load')
            tick(47676)
            _pointer(vm, 47676, 1, 6370, 6436, (6371,))
            tick(47683)
            vm.pc = 47687
            pointer = cells.value(6436)
            value = memory.load(cells.pointer(6435), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(47687)
            vm.pc = 47689
            vm._jump(1111)
            continue
        if vm.block == 1119:
            tick(47689)
            _pointer(vm, 47689, 1, 6370, 6437, (6371,))
            tick(47696)
            vm.pc = 47700
            pointer = cells.value(6437)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(47700)
            vm.pc = 47702
            vm._jump(1111)
            continue
        if vm.block == 1111:
            tick(47702)
            vm.pc = 47703
            tick(47703)
            vm.pc = 47706
            vm.auxiliary = (0, 668164098)
            tick(47706)
            vm.pc = 47711
            vm._write(6372, memory.load(cells.pointer(6371), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(47711)
            vm.pc = 47713
            vm._jump(1110)
            continue
        if vm.block == 1113:
            tick(47713)
            vm.pc = 47717
            value = memory.load(cells.value(62), 8)
            vm._write(6438, value, 8, 'high.load')
            tick(47717)
            vm.pc = 47722
            vm._write(6439, cells.value(6438) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(47722)
            vm.pc = 47726
            pointer = cells.value(132)
            value = memory.load(cells.pointer(6439), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(47726)
            _pointer(vm, 47726, 70, 103, 6440, (145, 190))
            tick(47734)
            vm.pc = 47739
            cells.copy_q_clear_owned(6440, 6441)
            tick(47739)
            vm.pc = 47740
            tick(47740)
            vm.pc = 47743
            vm.auxiliary = (0, 17469)
            tick(47743)
            vm.pc = 47748
            vm._write(6442, memory.load(cells.pointer(6441), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(47748)
            _pointer(vm, 47748, 1, 6369, 6443, (163,))
            tick(47755)
            vm.pc = 47759
            value = memory.load(cells.value(6369), 1)
            vm._write(6444, value, 4, 'high.load')
            tick(47759)
            _pointer(vm, 47759, 1, 6440, 6445, (163,))
            tick(47766)
            vm.pc = 47770
            pointer = cells.value(6440)
            value = memory.load(cells.pointer(6444), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(47770)
            vm.pc = 47775
            cells.copy_q_clear_owned(6445, 6446)
            tick(47775)
            vm.pc = 47780
            vm._write(6447, memory.load(cells.pointer(6446), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(47780)
            vm.pc = 47783
            vm.auxiliary = (0, 170006612)
            tick(47783)
            vm.pc = 47788
            vm._write(6448, int(memory.load(cells.pointer(6447), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(47788)
            vm.pc = 47792
            vm._jump(1121 if cells.value(6448) != 0 else 1122)
            continue
        if vm.block == 1121:
            tick(47792)
            _pointer(vm, 47792, 1, 6443, 6449, (163,))
            tick(47799)
            vm.pc = 47803
            value = memory.load(cells.value(6443), 1)
            vm._write(6450, value, 4, 'high.load')
            tick(47803)
            _pointer(vm, 47803, 1, 6445, 6451, (163,))
            tick(47810)
            vm.pc = 47814
            pointer = cells.value(6445)
            value = memory.load(cells.pointer(6450), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(47814)
            vm.pc = 47816
            vm._jump(1122)
            continue
        if vm.block == 1122:
            tick(47816)
            _phi(vm, 47816, (6452, 2, 158, 1121, 269, 1113))
            tick(47823)
            _phi(vm, 47823, (6453, 2, 6451, 1121, 6445, 1113))
            tick(47830)
            _phi(vm, 47830, (6454, 2, 6449, 1121, 6443, 1113))
            tick(47837)
            vm.pc = 47842
            cells.copy_q_clear_owned(6453, 6455)
            tick(47842)
            vm.pc = 47847
            vm._write(6456, memory.load(cells.pointer(6455), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(47847)
            vm.pc = 47848
            tick(47848)
            vm.pc = 47851
            vm.auxiliary = (0, 1952622532)
            tick(47851)
            vm.pc = 47856
            vm._write(6457, int(memory.load(cells.pointer(6456), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(47856)
            vm.pc = 47859
            vm.auxiliary = (0, 736254566)
            tick(47859)
            vm.pc = 47864
            vm._write(6458, int(memory.load(cells.pointer(6452), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(47864)
            vm.pc = 47867
            vm.auxiliary = (0, 54876)
            tick(47867)
            vm.pc = 47872
            vm._write(6459, memory.load(cells.pointer(6457), 1, signed=True) & memory.load(cells.pointer(6458), 1, signed=True), 8, 'typed.selector1.q')
            tick(47872)
            vm.pc = 47876
            vm._jump(1123 if cells.value(6459) != 0 else 1124)
            continue
        if vm.block == 1123:
            tick(47876)
            _pointer(vm, 47876, 1, 6454, 6460, (163,))
            tick(47883)
            vm.pc = 47887
            value = memory.load(cells.value(6454), 1)
            vm._write(6461, value, 4, 'high.load')
            tick(47887)
            _pointer(vm, 47887, 1, 6453, 6462, (163,))
            tick(47894)
            vm.pc = 47898
            pointer = cells.value(6453)
            value = memory.load(cells.pointer(6461), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(47898)
            vm.pc = 47899
            tick(47899)
            vm.pc = 47902
            vm.auxiliary = (0, 265117697)
            tick(47902)
            vm.pc = 47907
            vm._write(6463, memory.load(cells.pointer(6452), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(47907)
            vm.pc = 47909
            vm._jump(1124)
            continue
        if vm.block == 1124:
            tick(47909)
            _phi(vm, 47909, (6464, 2, 6463, 1123, 6452, 1122))
            tick(47916)
            _phi(vm, 47916, (6465, 2, 6462, 1123, 6453, 1122))
            tick(47923)
            _phi(vm, 47923, (6466, 2, 6460, 1123, 6454, 1122))
            tick(47930)
            vm.pc = 47935
            cells.copy_q_clear_owned(6465, 6467)
            tick(47935)
            vm.pc = 47940
            cells.copy_q_clear_owned(6466, 6468)
            tick(47940)
            vm.pc = 47941
            tick(47941)
            vm.pc = 47944
            vm.auxiliary = (0, 1794254006)
            tick(47944)
            vm.pc = 47949
            vm._write(6469, int(memory.load(cells.pointer(6464), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(47949)
            vm.pc = 47953
            vm._jump(1125 if cells.value(6469) != 0 else 1126)
            continue
        if vm.block == 1125:
            tick(47953)
            _pointer(vm, 47953, 1, 6466, 6470, (172,))
            tick(47960)
            vm.pc = 47965
            cells.copy_q_clear_owned(6470, 6471)
            tick(47965)
            vm.pc = 47969
            value = memory.load(cells.value(6468), 4)
            vm._write(6472, value, 4, 'high.load')
            tick(47969)
            _pointer(vm, 47969, 1, 6465, 6473, (172,))
            tick(47976)
            vm.pc = 47981
            cells.copy_q_clear_owned(6473, 6474)
            tick(47981)
            vm.pc = 47985
            pointer = cells.value(6467)
            value = memory.load(cells.pointer(6472), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(47985)
            vm.pc = 47986
            tick(47986)
            vm.pc = 47989
            vm.auxiliary = (0, 1265029122)
            tick(47989)
            vm.pc = 47994
            vm._write(6475, memory.load(cells.pointer(6464), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(47994)
            vm.pc = 47996
            vm._jump(1126)
            continue
        if vm.block == 1126:
            tick(47996)
            _phi(vm, 47996, (6476, 2, 6475, 1125, 6464, 1124))
            tick(48003)
            _phi(vm, 48003, (6477, 2, 6474, 1125, 6467, 1124))
            tick(48010)
            _phi(vm, 48010, (6478, 2, 6471, 1125, 6468, 1124))
            tick(48017)
            vm.pc = 48018
            tick(48018)
            vm.pc = 48021
            vm.auxiliary = (0, 930233750)
            tick(48021)
            vm.pc = 48026
            vm._write(6479, int(memory.load(cells.pointer(6476), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(48026)
            vm.pc = 48030
            vm._jump(1127 if cells.value(6479) != 0 else 1128)
            continue
        if vm.block == 1127:
            tick(48030)
            _pointer(vm, 48030, 3, 6478, 6480, (163,))
            tick(48037)
            vm.pc = 48041
            value = memory.load(cells.value(6478), 4)
            vm._write(6481, value, 4, 'high.load')
            tick(48041)
            _pointer(vm, 48041, 3, 6477, 6482, (163,))
            tick(48048)
            vm.pc = 48052
            pointer = cells.value(6477)
            value = memory.load(cells.pointer(6481), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(48052)
            vm.pc = 48053
            tick(48053)
            vm.pc = 48056
            vm.auxiliary = (0, 408748034)
            tick(48056)
            vm.pc = 48061
            vm._write(6483, memory.load(cells.pointer(6476), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(48061)
            vm.pc = 48063
            vm._jump(1128)
            continue
        if vm.block == 1128:
            tick(48063)
            _phi(vm, 48063, (6484, 2, 6483, 1127, 6476, 1126))
            tick(48070)
            _phi(vm, 48070, (6485, 2, 6482, 1127, 6477, 1126))
            tick(48077)
            _phi(vm, 48077, (6486, 2, 6480, 1127, 6478, 1126))
            tick(48084)
            vm.pc = 48085
            tick(48085)
            vm.pc = 48088
            vm.auxiliary = (0, 1581443958)
            tick(48088)
            vm.pc = 48093
            vm._write(6487, int(memory.load(cells.pointer(6484), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(48093)
            vm.pc = 48097
            vm._jump(1129 if cells.value(6487) != 0 else 1130)
            continue
        if vm.block == 1129:
            tick(48097)
            _pointer(vm, 48097, 3, 6486, 6488, (163,))
            tick(48104)
            vm.pc = 48108
            value = memory.load(cells.value(6486), 4)
            vm._write(6489, value, 4, 'L5.unsigned_load')
            tick(48108)
            _pointer(vm, 48108, 3, 6485, 6490, (163,))
            tick(48115)
            vm.pc = 48119
            pointer = cells.value(6485)
            value = memory.load(cells.pointer(6489), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(48119)
            vm.pc = 48120
            tick(48120)
            vm.pc = 48123
            vm.auxiliary = (0, 1514639361)
            tick(48123)
            vm.pc = 48128
            vm._write(6491, memory.load(cells.pointer(6484), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(48128)
            vm.pc = 48130
            vm._jump(1130)
            continue
        if vm.block == 1130:
            tick(48130)
            _phi(vm, 48130, (6492, 2, 6491, 1129, 6484, 1128))
            tick(48137)
            _phi(vm, 48137, (6493, 2, 6490, 1129, 6485, 1128))
            tick(48144)
            _phi(vm, 48144, (6494, 2, 6488, 1129, 6486, 1128))
            tick(48151)
            vm.pc = 48156
            cells.copy_q_clear_owned(6493, 6495)
            tick(48156)
            vm.pc = 48161
            cells.copy_q_clear_owned(6494, 6496)
            tick(48161)
            vm.pc = 48162
            tick(48162)
            vm.pc = 48165
            vm.auxiliary = (0, 834836966)
            tick(48165)
            vm.pc = 48170
            vm._write(6497, int(memory.load(cells.pointer(6492), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(48170)
            vm.pc = 48174
            vm._jump(1131 if cells.value(6497) != 0 else 1132)
            continue
        if vm.block == 1131:
            tick(48174)
            _pointer(vm, 48174, 1, 6496, 6498, (163,))
            tick(48181)
            vm.pc = 48185
            value = memory.load(cells.value(6496), 1)
            vm._write(6499, value, 4, 'high.load')
            tick(48185)
            _pointer(vm, 48185, 1, 6495, 6500, (163,))
            tick(48192)
            vm.pc = 48196
            pointer = cells.value(6495)
            value = memory.load(cells.pointer(6499), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48196)
            vm.pc = 48197
            tick(48197)
            vm.pc = 48200
            vm.auxiliary = (0, 1926709249)
            tick(48200)
            vm.pc = 48205
            vm._write(6501, memory.load(cells.pointer(6492), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(48205)
            vm.pc = 48207
            vm._jump(1132)
            continue
        if vm.block == 1132:
            tick(48207)
            _phi(vm, 48207, (6502, 2, 6501, 1131, 6492, 1130))
            tick(48214)
            _phi(vm, 48214, (6503, 2, 6500, 1131, 6495, 1130))
            tick(48221)
            _phi(vm, 48221, (6504, 2, 6498, 1131, 6496, 1130))
            tick(48228)
            vm.pc = 48229
            tick(48229)
            vm.pc = 48232
            vm.auxiliary = (0, 930264294)
            tick(48232)
            vm.pc = 48237
            vm._write(6505, int(memory.load(cells.pointer(6502), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(48237)
            vm.pc = 48241
            vm._jump(1133 if cells.value(6505) != 0 else 1134)
            continue
        if vm.block == 1133:
            tick(48241)
            _pointer(vm, 48241, 1, 6504, 6506, (163,))
            tick(48248)
            vm.pc = 48252
            value = memory.load(cells.value(6504), 1)
            vm._write(6507, value, 4, 'high.load')
            tick(48252)
            _pointer(vm, 48252, 1, 6503, 6508, (163,))
            tick(48259)
            vm.pc = 48263
            pointer = cells.value(6503)
            value = memory.load(cells.pointer(6507), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48263)
            vm.pc = 48264
            tick(48264)
            vm.pc = 48267
            vm.auxiliary = (0, 1410027522)
            tick(48267)
            vm.pc = 48272
            vm._write(6509, memory.load(cells.pointer(6502), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(48272)
            vm.pc = 48274
            vm._jump(1134)
            continue
        if vm.block == 1134:
            tick(48274)
            _phi(vm, 48274, (6510, 2, 6509, 1133, 6502, 1132))
            tick(48281)
            _phi(vm, 48281, (6511, 2, 6508, 1133, 6503, 1132))
            tick(48288)
            _phi(vm, 48288, (6512, 2, 6506, 1133, 6504, 1132))
            tick(48295)
            vm.pc = 48296
            tick(48296)
            vm.pc = 48299
            vm.auxiliary = (0, 891429750)
            tick(48299)
            vm.pc = 48304
            vm._write(6513, int(memory.load(cells.pointer(6510), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(48304)
            vm.pc = 48308
            vm._jump(1135 if cells.value(6513) != 0 else 1136)
            continue
        if vm.block == 1135:
            tick(48308)
            _pointer(vm, 48308, 1, 6512, 6514, (163,))
            tick(48315)
            vm.pc = 48319
            value = memory.load(cells.value(6512), 1)
            vm._write(6515, value, 4, 'high.load')
            tick(48319)
            _pointer(vm, 48319, 1, 6511, 6516, (163,))
            tick(48326)
            vm.pc = 48330
            pointer = cells.value(6511)
            value = memory.load(cells.pointer(6515), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48330)
            vm.pc = 48332
            vm._jump(1136)
            continue
        if vm.block == 1136:
            tick(48332)
            _phi(vm, 48332, (6517, 2, 6516, 1135, 6511, 1134))
            tick(48339)
            _phi(vm, 48339, (6518, 2, 6514, 1135, 6512, 1134))
            tick(48346)
            vm.pc = 48347
            tick(48347)
            vm.pc = 48350
            vm.auxiliary = (0, 1396857926)
            tick(48350)
            vm.pc = 48355
            vm._write(6519, int(memory.load(cells.pointer(6510), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(48355)
            vm.pc = 48359
            vm._jump(1137 if cells.value(6519) != 0 else 1138)
            continue
        if vm.block == 1137:
            tick(48359)
            vm.pc = 48363
            value = memory.load(cells.value(6518), 1)
            vm._write(6520, value, 4, 'high.load')
            tick(48363)
            vm.pc = 48367
            pointer = cells.value(6517)
            value = memory.load(cells.pointer(6520), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48367)
            vm.pc = 48369
            vm._jump(1138)
            continue
        if vm.block == 1138:
            tick(48369)
            _pointer(vm, 48369, 70, 103, 6521, (145, 196))
            tick(48377)
            vm.pc = 48382
            cells.copy_q_clear_owned(6521, 6522)
            tick(48382)
            vm.pc = 48383
            tick(48383)
            vm.pc = 48386
            vm.auxiliary = (0, 25604)
            tick(48386)
            vm.pc = 48391
            vm._write(6523, memory.load(cells.pointer(6522), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(48391)
            vm.pc = 48394
            vm.auxiliary = (0, 1339195508)
            tick(48394)
            vm.pc = 48399
            vm._write(6524, int(memory.load(cells.pointer(6523), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(48399)
            vm.pc = 48403
            vm._jump(1139 if cells.value(6524) != 0 else 1140)
            continue
        if vm.block == 1139:
            tick(48403)
            _pointer(vm, 48403, 1, 2081, 6525, (163,))
            tick(48410)
            vm.pc = 48414
            value = memory.load(cells.value(2081), 1)
            vm._write(6526, value, 4, 'high.load')
            tick(48414)
            _pointer(vm, 48414, 1, 6521, 6527, (163,))
            tick(48421)
            vm.pc = 48425
            pointer = cells.value(6521)
            value = memory.load(cells.pointer(6526), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48425)
            vm.pc = 48427
            vm._jump(1140)
            continue
        if vm.block == 1140:
            tick(48427)
            _phi(vm, 48427, (6528, 2, 269, 1139, 311, 1138))
            tick(48434)
            _phi(vm, 48434, (6529, 2, 6527, 1139, 6521, 1138))
            tick(48441)
            _phi(vm, 48441, (6530, 2, 6525, 1139, 2081, 1138))
            tick(48448)
            vm.pc = 48453
            cells.copy_q_clear_owned(6529, 6531)
            tick(48453)
            vm.pc = 48454
            tick(48454)
            vm.pc = 48457
            vm.auxiliary = (0, 41541)
            tick(48457)
            vm.pc = 48462
            vm._write(6532, memory.load(cells.pointer(6531), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(48462)
            vm.pc = 48465
            vm.auxiliary = (0, 1095918196)
            tick(48465)
            vm.pc = 48470
            vm._write(6533, int(memory.load(cells.pointer(6532), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(48470)
            vm.pc = 48473
            vm.auxiliary = (0, 343077942)
            tick(48473)
            vm.pc = 48478
            vm._write(6534, int(memory.load(cells.pointer(6528), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(48478)
            vm.pc = 48481
            vm.auxiliary = (0, 5502)
            tick(48481)
            vm.pc = 48486
            vm._write(6535, memory.load(cells.pointer(6533), 1, signed=True) & memory.load(cells.pointer(6534), 1, signed=True), 8, 'typed.selector1.q')
            tick(48486)
            vm.pc = 48490
            vm._jump(1141 if cells.value(6535) != 0 else 1142)
            continue
        if vm.block == 1141:
            tick(48490)
            _pointer(vm, 48490, 1, 6530, 6536, (163,))
            tick(48497)
            vm.pc = 48501
            value = memory.load(cells.value(6530), 1)
            vm._write(6537, value, 4, 'high.load')
            tick(48501)
            _pointer(vm, 48501, 1, 6529, 6538, (163,))
            tick(48508)
            vm.pc = 48512
            pointer = cells.value(6529)
            value = memory.load(cells.pointer(6537), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48512)
            vm.pc = 48513
            tick(48513)
            vm.pc = 48516
            vm.auxiliary = (0, 959197185)
            tick(48516)
            vm.pc = 48521
            vm._write(6539, memory.load(cells.pointer(6528), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(48521)
            vm.pc = 48523
            vm._jump(1142)
            continue
        if vm.block == 1142:
            tick(48523)
            _phi(vm, 48523, (6540, 2, 6539, 1141, 6528, 1140))
            tick(48530)
            _phi(vm, 48530, (6541, 2, 6538, 1141, 6529, 1140))
            tick(48537)
            _phi(vm, 48537, (6542, 2, 6536, 1141, 6530, 1140))
            tick(48544)
            vm.pc = 48549
            cells.copy_q_clear_owned(6541, 6543)
            tick(48549)
            vm.pc = 48550
            tick(48550)
            vm.pc = 48553
            vm.auxiliary = (0, 53517)
            tick(48553)
            vm.pc = 48558
            vm._write(6544, memory.load(cells.pointer(6543), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(48558)
            vm.pc = 48561
            vm.auxiliary = (0, 1542642628)
            tick(48561)
            vm.pc = 48566
            vm._write(6545, int(memory.load(cells.pointer(6544), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(48566)
            vm.pc = 48569
            vm.auxiliary = (0, 682762198)
            tick(48569)
            vm.pc = 48574
            vm._write(6546, int(memory.load(cells.pointer(6540), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(48574)
            vm.pc = 48577
            vm.auxiliary = (0, 13852)
            tick(48577)
            vm.pc = 48582
            vm._write(6547, memory.load(cells.pointer(6545), 1, signed=True) & memory.load(cells.pointer(6546), 1, signed=True), 8, 'typed.selector1.q')
            tick(48582)
            vm.pc = 48586
            vm._jump(1143 if cells.value(6547) != 0 else 1144)
            continue
        if vm.block == 1143:
            tick(48586)
            _pointer(vm, 48586, 1, 6542, 6548, (163,))
            tick(48593)
            vm.pc = 48597
            value = memory.load(cells.value(6542), 1)
            vm._write(6549, value, 4, 'high.load')
            tick(48597)
            _pointer(vm, 48597, 1, 6541, 6550, (163,))
            tick(48604)
            vm.pc = 48608
            pointer = cells.value(6541)
            value = memory.load(cells.pointer(6549), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48608)
            vm.pc = 48609
            tick(48609)
            vm.pc = 48612
            vm.auxiliary = (0, 1262415874)
            tick(48612)
            vm.pc = 48617
            vm._write(6551, memory.load(cells.pointer(6540), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(48617)
            vm.pc = 48619
            vm._jump(1144)
            continue
        if vm.block == 1144:
            tick(48619)
            _phi(vm, 48619, (6552, 2, 6551, 1143, 6540, 1142))
            tick(48626)
            _phi(vm, 48626, (6553, 2, 6550, 1143, 6541, 1142))
            tick(48633)
            _phi(vm, 48633, (6554, 2, 6548, 1143, 6542, 1142))
            tick(48640)
            vm.pc = 48645
            cells.copy_q_clear_owned(6553, 6555)
            tick(48645)
            vm.pc = 48650
            cells.copy_q_clear_owned(6554, 6556)
            tick(48650)
            vm.pc = 48651
            tick(48651)
            vm.pc = 48654
            vm.auxiliary = (0, 775030886)
            tick(48654)
            vm.pc = 48659
            vm._write(6557, int(memory.load(cells.pointer(6552), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(48659)
            vm.pc = 48663
            vm._jump(1145 if cells.value(6557) != 0 else 1146)
            continue
        if vm.block == 1145:
            tick(48663)
            _pointer(vm, 48663, 1, 6554, 6558, (172,))
            tick(48670)
            vm.pc = 48675
            cells.copy_q_clear_owned(6558, 6559)
            tick(48675)
            vm.pc = 48679
            value = memory.load(cells.value(6556), 4)
            vm._write(6560, value, 4, 'high.load')
            tick(48679)
            _pointer(vm, 48679, 1, 6553, 6561, (172,))
            tick(48686)
            vm.pc = 48691
            cells.copy_q_clear_owned(6561, 6562)
            tick(48691)
            vm.pc = 48695
            pointer = cells.value(6555)
            value = memory.load(cells.pointer(6560), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(48695)
            vm.pc = 48696
            tick(48696)
            vm.pc = 48699
            vm.auxiliary = (0, 1515745281)
            tick(48699)
            vm.pc = 48704
            vm._write(6563, memory.load(cells.pointer(6552), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(48704)
            vm.pc = 48706
            vm._jump(1146)
            continue
        if vm.block == 1146:
            tick(48706)
            _phi(vm, 48706, (6564, 2, 6563, 1145, 6552, 1144))
            tick(48713)
            _phi(vm, 48713, (6565, 2, 6562, 1145, 6555, 1144))
            tick(48720)
            _phi(vm, 48720, (6566, 2, 6559, 1145, 6556, 1144))
            tick(48727)
            vm.pc = 48728
            tick(48728)
            vm.pc = 48731
            vm.auxiliary = (0, 822234646)
            tick(48731)
            vm.pc = 48736
            vm._write(6567, int(memory.load(cells.pointer(6564), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(48736)
            vm.pc = 48740
            vm._jump(1147 if cells.value(6567) != 0 else 1148)
            continue
        if vm.block == 1147:
            tick(48740)
            _pointer(vm, 48740, 3, 6566, 6568, (163,))
            tick(48747)
            vm.pc = 48751
            value = memory.load(cells.value(6566), 4)
            vm._write(6569, value, 4, 'high.load')
            tick(48751)
            _pointer(vm, 48751, 3, 6565, 6570, (163,))
            tick(48758)
            vm.pc = 48762
            pointer = cells.value(6565)
            value = memory.load(cells.pointer(6569), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(48762)
            vm.pc = 48763
            tick(48763)
            vm.pc = 48766
            vm.auxiliary = (0, 1565057025)
            tick(48766)
            vm.pc = 48771
            vm._write(6571, memory.load(cells.pointer(6564), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(48771)
            vm.pc = 48773
            vm._jump(1148)
            continue
        if vm.block == 1148:
            tick(48773)
            _phi(vm, 48773, (6572, 2, 6571, 1147, 6564, 1146))
            tick(48780)
            _phi(vm, 48780, (6573, 2, 6570, 1147, 6565, 1146))
            tick(48787)
            _phi(vm, 48787, (6574, 2, 6568, 1147, 6566, 1146))
            tick(48794)
            vm.pc = 48795
            tick(48795)
            vm.pc = 48798
            vm.auxiliary = (0, 294798678)
            tick(48798)
            vm.pc = 48803
            vm._write(6575, int(memory.load(cells.pointer(6572), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(48803)
            vm.pc = 48807
            vm._jump(1149 if cells.value(6575) != 0 else 1150)
            continue
        if vm.block == 1149:
            tick(48807)
            _pointer(vm, 48807, 3, 6574, 6576, (163,))
            tick(48814)
            vm.pc = 48818
            value = memory.load(cells.value(6574), 4)
            vm._write(6577, value, 4, 'high.load')
            tick(48818)
            _pointer(vm, 48818, 3, 6573, 6578, (163,))
            tick(48825)
            vm.pc = 48829
            pointer = cells.value(6573)
            value = memory.load(cells.pointer(6577), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(48829)
            vm.pc = 48830
            tick(48830)
            vm.pc = 48833
            vm.auxiliary = (0, 1122840577)
            tick(48833)
            vm.pc = 48838
            vm._write(6579, memory.load(cells.pointer(6572), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(48838)
            vm.pc = 48840
            vm._jump(1150)
            continue
        if vm.block == 1150:
            tick(48840)
            _phi(vm, 48840, (6580, 2, 6579, 1149, 6572, 1148))
            tick(48847)
            _phi(vm, 48847, (6581, 2, 6578, 1149, 6573, 1148))
            tick(48854)
            _phi(vm, 48854, (6582, 2, 6576, 1149, 6574, 1148))
            tick(48861)
            vm.pc = 48866
            cells.copy_q_clear_owned(6581, 6583)
            tick(48866)
            vm.pc = 48871
            cells.copy_q_clear_owned(6582, 6584)
            tick(48871)
            vm.pc = 48872
            tick(48872)
            vm.pc = 48875
            vm.auxiliary = (0, 524437718)
            tick(48875)
            vm.pc = 48880
            vm._write(6585, int(memory.load(cells.pointer(6580), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(48880)
            vm.pc = 48884
            vm._jump(1151 if cells.value(6585) != 0 else 1152)
            continue
        if vm.block == 1151:
            tick(48884)
            _pointer(vm, 48884, 1, 6584, 6586, (163,))
            tick(48891)
            vm.pc = 48895
            value = memory.load(cells.value(6584), 1)
            vm._write(6587, value, 4, 'high.load')
            tick(48895)
            _pointer(vm, 48895, 1, 6583, 6588, (163,))
            tick(48902)
            vm.pc = 48906
            pointer = cells.value(6583)
            value = memory.load(cells.pointer(6587), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48906)
            vm.pc = 48907
            tick(48907)
            vm.pc = 48910
            vm.auxiliary = (0, 2124398593)
            tick(48910)
            vm.pc = 48915
            vm._write(6589, memory.load(cells.pointer(6580), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(48915)
            vm.pc = 48917
            vm._jump(1152)
            continue
        if vm.block == 1152:
            tick(48917)
            _phi(vm, 48917, (6590, 2, 6589, 1151, 6580, 1150))
            tick(48924)
            _phi(vm, 48924, (6591, 2, 6588, 1151, 6583, 1150))
            tick(48931)
            _phi(vm, 48931, (6592, 2, 6586, 1151, 6584, 1150))
            tick(48938)
            vm.pc = 48939
            tick(48939)
            vm.pc = 48942
            vm.auxiliary = (0, 1484926134)
            tick(48942)
            vm.pc = 48947
            vm._write(6593, int(memory.load(cells.pointer(6590), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(48947)
            vm.pc = 48951
            vm._jump(1153 if cells.value(6593) != 0 else 1154)
            continue
        if vm.block == 1153:
            tick(48951)
            _pointer(vm, 48951, 1, 6592, 6594, (163,))
            tick(48958)
            vm.pc = 48962
            value = memory.load(cells.value(6592), 1)
            vm._write(6595, value, 4, 'high.load')
            tick(48962)
            _pointer(vm, 48962, 1, 6591, 6596, (163,))
            tick(48969)
            vm.pc = 48973
            pointer = cells.value(6591)
            value = memory.load(cells.pointer(6595), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(48973)
            vm.pc = 48974
            tick(48974)
            vm.pc = 48977
            vm.auxiliary = (0, 1524838402)
            tick(48977)
            vm.pc = 48982
            vm._write(6597, memory.load(cells.pointer(6590), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(48982)
            vm.pc = 48984
            vm._jump(1154)
            continue
        if vm.block == 1154:
            tick(48984)
            _phi(vm, 48984, (6598, 2, 6597, 1153, 6590, 1152))
            tick(48991)
            _phi(vm, 48991, (6599, 2, 6596, 1153, 6591, 1152))
            tick(48998)
            _phi(vm, 48998, (6600, 2, 6594, 1153, 6592, 1152))
            tick(49005)
            vm.pc = 49006
            tick(49006)
            vm.pc = 49009
            vm.auxiliary = (0, 2011320710)
            tick(49009)
            vm.pc = 49014
            vm._write(6601, int(memory.load(cells.pointer(6598), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(49014)
            vm.pc = 49018
            vm._jump(1155 if cells.value(6601) != 0 else 1156)
            continue
        if vm.block == 1155:
            tick(49018)
            _pointer(vm, 49018, 1, 6600, 6602, (163,))
            tick(49025)
            vm.pc = 49029
            value = memory.load(cells.value(6600), 1)
            vm._write(6603, value, 4, 'high.load')
            tick(49029)
            _pointer(vm, 49029, 1, 6599, 6604, (163,))
            tick(49036)
            vm.pc = 49040
            pointer = cells.value(6599)
            value = memory.load(cells.pointer(6603), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49040)
            vm.pc = 49042
            vm._jump(1156)
            continue
        if vm.block == 1156:
            tick(49042)
            _phi(vm, 49042, (6605, 2, 6604, 1155, 6599, 1154))
            tick(49049)
            _phi(vm, 49049, (6606, 2, 6602, 1155, 6600, 1154))
            tick(49056)
            vm.pc = 49057
            tick(49057)
            vm.pc = 49060
            vm.auxiliary = (0, 274889942)
            tick(49060)
            vm.pc = 49065
            vm._write(6607, int(memory.load(cells.pointer(6598), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(49065)
            vm.pc = 49069
            vm._jump(1157 if cells.value(6607) != 0 else 1158)
            continue
        if vm.block == 1157:
            tick(49069)
            vm.pc = 49073
            value = memory.load(cells.value(6606), 1)
            vm._write(6608, value, 4, 'high.load')
            tick(49073)
            vm.pc = 49077
            pointer = cells.value(6605)
            value = memory.load(cells.pointer(6608), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49077)
            vm.pc = 49079
            vm._jump(1158)
            continue
        if vm.block == 1158:
            tick(49079)
            vm.pc = 49081
            vm._jump(1159)
            continue
        if vm.block == 1159:
            tick(49081)
            _phi(vm, 49081, (6609, 2, 2080, 1158, 6610, 1160))
            tick(49088)
            _phi(vm, 49088, (6611, 2, 172, 1158, 6612, 1160))
            tick(49095)
            vm.pc = 49096
            tick(49096)
            vm.pc = 49099
            vm.auxiliary = (0, 822244467)
            tick(49099)
            vm.pc = 49104
            vm._write(6613, int(memory.load(cells.pointer(6611), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(49104)
            vm.pc = 49108
            vm._jump(1161 if cells.value(6613) != 0 else 1160)
            continue
        if vm.block == 1160:
            tick(49108)
            vm.pc = 49109
            tick(49109)
            vm.pc = 49112
            vm.auxiliary = (0, 1169231873)
            tick(49112)
            vm.pc = 49117
            vm._write(6612, memory.load(cells.pointer(6611), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(49117)
            _pointer(vm, 49117, 1, 6609, 6610, (163,))
            tick(49124)
            vm.pc = 49128
            pointer = cells.value(6609)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49128)
            vm.pc = 49130
            vm._jump(1159)
            continue
        if vm.block == 1161:
            tick(49130)
            _pointer(vm, 49130, 70, 103, 6614, (145, 184))
            tick(49138)
            vm.pc = 49143
            cells.copy_q_clear_owned(6614, 6615)
            tick(49143)
            vm.pc = 49144
            tick(49144)
            vm.pc = 49147
            vm.auxiliary = (0, 13437)
            tick(49147)
            vm.pc = 49152
            vm._write(6616, memory.load(cells.pointer(6615), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(49152)
            vm.pc = 49155
            vm.auxiliary = (0, 426929860)
            tick(49155)
            vm.pc = 49160
            vm._write(6617, int(memory.load(cells.pointer(6616), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(49160)
            vm.pc = 49164
            vm._jump(1162 if cells.value(6617) != 0 else 1163)
            continue
        if vm.block == 1162:
            tick(49164)
            _pointer(vm, 49164, 1, 130, 6618, (163,))
            tick(49171)
            vm.pc = 49175
            value = memory.load(cells.value(130), 1)
            vm._write(6619, value, 4, 'high.load')
            tick(49175)
            _pointer(vm, 49175, 1, 6614, 6620, (163,))
            tick(49182)
            vm.pc = 49186
            pointer = cells.value(6614)
            value = memory.load(cells.pointer(6619), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49186)
            vm.pc = 49188
            vm._jump(1163)
            continue
        if vm.block == 1163:
            tick(49188)
            _phi(vm, 49188, (6621, 2, 158, 1162, 269, 1161))
            tick(49195)
            _phi(vm, 49195, (6622, 2, 6620, 1162, 6614, 1161))
            tick(49202)
            _phi(vm, 49202, (6623, 2, 6618, 1162, 130, 1161))
            tick(49209)
            vm.pc = 49214
            cells.copy_q_clear_owned(6622, 6624)
            tick(49214)
            vm.pc = 49215
            tick(49215)
            vm.pc = 49218
            vm.auxiliary = (0, 41580)
            tick(49218)
            vm.pc = 49223
            vm._write(6625, memory.load(cells.pointer(6624), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(49223)
            vm.pc = 49226
            vm.auxiliary = (0, 377641780)
            tick(49226)
            vm.pc = 49231
            vm._write(6626, int(memory.load(cells.pointer(6625), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(49231)
            vm.pc = 49234
            vm.auxiliary = (0, 1440898358)
            tick(49234)
            vm.pc = 49239
            vm._write(6627, int(memory.load(cells.pointer(6621), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(49239)
            vm.pc = 49242
            vm.auxiliary = (0, 33910)
            tick(49242)
            vm.pc = 49247
            vm._write(6628, memory.load(cells.pointer(6626), 1, signed=True) & memory.load(cells.pointer(6627), 1, signed=True), 8, 'typed.selector1.q')
            tick(49247)
            vm.pc = 49251
            vm._jump(1164 if cells.value(6628) != 0 else 1165)
            continue
        if vm.block == 1164:
            tick(49251)
            _pointer(vm, 49251, 1, 6623, 6629, (163,))
            tick(49258)
            vm.pc = 49262
            value = memory.load(cells.value(6623), 1)
            vm._write(6630, value, 4, 'high.load')
            tick(49262)
            _pointer(vm, 49262, 1, 6622, 6631, (163,))
            tick(49269)
            vm.pc = 49273
            pointer = cells.value(6622)
            value = memory.load(cells.pointer(6630), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49273)
            vm.pc = 49274
            tick(49274)
            vm.pc = 49277
            vm.auxiliary = (0, 2124496897)
            tick(49277)
            vm.pc = 49282
            vm._write(6632, memory.load(cells.pointer(6621), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(49282)
            vm.pc = 49284
            vm._jump(1165)
            continue
        if vm.block == 1165:
            tick(49284)
            _phi(vm, 49284, (6633, 2, 6632, 1164, 6621, 1163))
            tick(49291)
            _phi(vm, 49291, (6634, 2, 6631, 1164, 6622, 1163))
            tick(49298)
            _phi(vm, 49298, (6635, 2, 6629, 1164, 6623, 1163))
            tick(49305)
            vm.pc = 49310
            cells.copy_q_clear_owned(6634, 6636)
            tick(49310)
            vm.pc = 49311
            tick(49311)
            vm.pc = 49314
            vm.auxiliary = (0, 53822)
            tick(49314)
            vm.pc = 49319
            vm._write(6637, memory.load(cells.pointer(6636), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(49319)
            vm.pc = 49322
            vm.auxiliary = (0, 229828596)
            tick(49322)
            vm.pc = 49327
            vm._write(6638, int(memory.load(cells.pointer(6637), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(49327)
            vm.pc = 49330
            vm.auxiliary = (0, 1840419414)
            tick(49330)
            vm.pc = 49335
            vm._write(6639, int(memory.load(cells.pointer(6633), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(49335)
            vm.pc = 49338
            vm.auxiliary = (0, 17270)
            tick(49338)
            vm.pc = 49343
            vm._write(6640, memory.load(cells.pointer(6638), 1, signed=True) & memory.load(cells.pointer(6639), 1, signed=True), 8, 'typed.selector1.q')
            tick(49343)
            vm.pc = 49347
            vm._jump(1166 if cells.value(6640) != 0 else 1167)
            continue
        if vm.block == 1166:
            tick(49347)
            _pointer(vm, 49347, 1, 6635, 6641, (163,))
            tick(49354)
            vm.pc = 49358
            value = memory.load(cells.value(6635), 1)
            vm._write(6642, value, 4, 'high.load')
            tick(49358)
            _pointer(vm, 49358, 1, 6634, 6643, (163,))
            tick(49365)
            vm.pc = 49369
            pointer = cells.value(6634)
            value = memory.load(cells.pointer(6642), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49369)
            vm.pc = 49370
            tick(49370)
            vm.pc = 49373
            vm.auxiliary = (0, 708505602)
            tick(49373)
            vm.pc = 49378
            vm._write(6644, memory.load(cells.pointer(6633), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(49378)
            vm.pc = 49380
            vm._jump(1167)
            continue
        if vm.block == 1167:
            tick(49380)
            _phi(vm, 49380, (6645, 2, 6644, 1166, 6633, 1165))
            tick(49387)
            _phi(vm, 49387, (6646, 2, 6643, 1166, 6634, 1165))
            tick(49394)
            _phi(vm, 49394, (6647, 2, 6641, 1166, 6635, 1165))
            tick(49401)
            vm.pc = 49406
            cells.copy_q_clear_owned(6646, 6648)
            tick(49406)
            vm.pc = 49411
            cells.copy_q_clear_owned(6647, 6649)
            tick(49411)
            vm.pc = 49412
            tick(49412)
            vm.pc = 49415
            vm.auxiliary = (0, 948079958)
            tick(49415)
            vm.pc = 49420
            vm._write(6650, int(memory.load(cells.pointer(6645), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(49420)
            vm.pc = 49424
            vm._jump(1168 if cells.value(6650) != 0 else 1169)
            continue
        if vm.block == 1168:
            tick(49424)
            _pointer(vm, 49424, 1, 6647, 6651, (172,))
            tick(49431)
            vm.pc = 49436
            cells.copy_q_clear_owned(6651, 6652)
            tick(49436)
            vm.pc = 49440
            value = memory.load(cells.value(6649), 4)
            vm._write(6653, value, 4, 'high.load')
            tick(49440)
            _pointer(vm, 49440, 1, 6646, 6654, (172,))
            tick(49447)
            vm.pc = 49452
            cells.copy_q_clear_owned(6654, 6655)
            tick(49452)
            vm.pc = 49456
            pointer = cells.value(6648)
            value = memory.load(cells.pointer(6653), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(49456)
            vm.pc = 49457
            tick(49457)
            vm.pc = 49460
            vm.auxiliary = (0, 2072657922)
            tick(49460)
            vm.pc = 49465
            vm._write(6656, memory.load(cells.pointer(6645), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(49465)
            vm.pc = 49467
            vm._jump(1169)
            continue
        if vm.block == 1169:
            tick(49467)
            _phi(vm, 49467, (6657, 2, 6656, 1168, 6645, 1167))
            tick(49474)
            _phi(vm, 49474, (6658, 2, 6655, 1168, 6648, 1167))
            tick(49481)
            _phi(vm, 49481, (6659, 2, 6652, 1168, 6649, 1167))
            tick(49488)
            vm.pc = 49489
            tick(49489)
            vm.pc = 49492
            vm.auxiliary = (0, 627186614)
            tick(49492)
            vm.pc = 49497
            vm._write(6660, int(memory.load(cells.pointer(6657), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(49497)
            vm.pc = 49501
            vm._jump(1170 if cells.value(6660) != 0 else 1171)
            continue
        if vm.block == 1170:
            tick(49501)
            _pointer(vm, 49501, 3, 6659, 6661, (163,))
            tick(49508)
            vm.pc = 49512
            value = memory.load(cells.value(6659), 4)
            vm._write(6662, value, 4, 'high.load')
            tick(49512)
            _pointer(vm, 49512, 3, 6658, 6663, (163,))
            tick(49519)
            vm.pc = 49523
            pointer = cells.value(6658)
            value = memory.load(cells.pointer(6662), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(49523)
            vm.pc = 49524
            tick(49524)
            vm.pc = 49527
            vm.auxiliary = (0, 464629761)
            tick(49527)
            vm.pc = 49532
            vm._write(6664, memory.load(cells.pointer(6657), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(49532)
            vm.pc = 49534
            vm._jump(1171)
            continue
        if vm.block == 1171:
            tick(49534)
            _phi(vm, 49534, (6665, 2, 6664, 1170, 6657, 1169))
            tick(49541)
            _phi(vm, 49541, (6666, 2, 6663, 1170, 6658, 1169))
            tick(49548)
            _phi(vm, 49548, (6667, 2, 6661, 1170, 6659, 1169))
            tick(49555)
            vm.pc = 49556
            tick(49556)
            vm.pc = 49559
            vm.auxiliary = (0, 1655858390)
            tick(49559)
            vm.pc = 49564
            vm._write(6668, int(memory.load(cells.pointer(6665), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(49564)
            vm.pc = 49568
            vm._jump(1172 if cells.value(6668) != 0 else 1173)
            continue
        if vm.block == 1172:
            tick(49568)
            _pointer(vm, 49568, 3, 6667, 6669, (163,))
            tick(49575)
            vm.pc = 49579
            value = memory.load(cells.value(6667), 4)
            vm._write(6670, value, 4, 'high.load')
            tick(49579)
            _pointer(vm, 49579, 3, 6666, 6671, (163,))
            tick(49586)
            vm.pc = 49590
            pointer = cells.value(6666)
            value = memory.load(cells.pointer(6670), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(49590)
            vm.pc = 49591
            tick(49591)
            vm.pc = 49594
            vm.auxiliary = (0, 759496706)
            tick(49594)
            vm.pc = 49599
            vm._write(6672, memory.load(cells.pointer(6665), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(49599)
            vm.pc = 49601
            vm._jump(1173)
            continue
        if vm.block == 1173:
            tick(49601)
            _phi(vm, 49601, (6673, 2, 6672, 1172, 6665, 1171))
            tick(49608)
            _phi(vm, 49608, (6674, 2, 6671, 1172, 6666, 1171))
            tick(49615)
            _phi(vm, 49615, (6675, 2, 6669, 1172, 6667, 1171))
            tick(49622)
            vm.pc = 49627
            cells.copy_q_clear_owned(6674, 6676)
            tick(49627)
            vm.pc = 49632
            cells.copy_q_clear_owned(6675, 6677)
            tick(49632)
            vm.pc = 49633
            tick(49633)
            vm.pc = 49636
            vm.auxiliary = (0, 1643259542)
            tick(49636)
            vm.pc = 49641
            vm._write(6678, int(memory.load(cells.pointer(6673), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(49641)
            vm.pc = 49645
            vm._jump(1174 if cells.value(6678) != 0 else 1175)
            continue
        if vm.block == 1174:
            tick(49645)
            _pointer(vm, 49645, 1, 6677, 6679, (163,))
            tick(49652)
            vm.pc = 49656
            value = memory.load(cells.value(6677), 1)
            vm._write(6680, value, 4, 'high.load')
            tick(49656)
            _pointer(vm, 49656, 1, 6676, 6681, (163,))
            tick(49663)
            vm.pc = 49667
            pointer = cells.value(6676)
            value = memory.load(cells.pointer(6680), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49667)
            vm.pc = 49668
            tick(49668)
            vm.pc = 49671
            vm.auxiliary = (0, 312168450)
            tick(49671)
            vm.pc = 49676
            vm._write(6682, memory.load(cells.pointer(6673), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(49676)
            vm.pc = 49678
            vm._jump(1175)
            continue
        if vm.block == 1175:
            tick(49678)
            _phi(vm, 49678, (6683, 2, 6682, 1174, 6673, 1173))
            tick(49685)
            _phi(vm, 49685, (6684, 2, 6681, 1174, 6676, 1173))
            tick(49692)
            _phi(vm, 49692, (6685, 2, 6679, 1174, 6677, 1173))
            tick(49699)
            vm.pc = 49700
            tick(49700)
            vm.pc = 49703
            vm.auxiliary = (0, 1781705798)
            tick(49703)
            vm.pc = 49708
            vm._write(6686, int(memory.load(cells.pointer(6683), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(49708)
            vm.pc = 49712
            vm._jump(1176 if cells.value(6686) != 0 else 1177)
            continue
        if vm.block == 1176:
            tick(49712)
            _pointer(vm, 49712, 1, 6685, 6687, (163,))
            tick(49719)
            vm.pc = 49723
            value = memory.load(cells.value(6685), 1)
            vm._write(6688, value, 4, 'high.load')
            tick(49723)
            _pointer(vm, 49723, 1, 6684, 6689, (163,))
            tick(49730)
            vm.pc = 49734
            pointer = cells.value(6684)
            value = memory.load(cells.pointer(6688), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49734)
            vm.pc = 49735
            tick(49735)
            vm.pc = 49738
            vm.auxiliary = (0, 1317318658)
            tick(49738)
            vm.pc = 49743
            vm._write(6690, memory.load(cells.pointer(6683), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(49743)
            vm.pc = 49745
            vm._jump(1177)
            continue
        if vm.block == 1177:
            tick(49745)
            _phi(vm, 49745, (6691, 2, 6690, 1176, 6683, 1175))
            tick(49752)
            _phi(vm, 49752, (6692, 2, 6689, 1176, 6684, 1175))
            tick(49759)
            _phi(vm, 49759, (6693, 2, 6687, 1176, 6685, 1175))
            tick(49766)
            vm.pc = 49767
            tick(49767)
            vm.pc = 49770
            vm.auxiliary = (0, 898790870)
            tick(49770)
            vm.pc = 49775
            vm._write(6694, int(memory.load(cells.pointer(6691), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(49775)
            vm.pc = 49779
            vm._jump(1178 if cells.value(6694) != 0 else 1179)
            continue
        if vm.block == 1178:
            tick(49779)
            _pointer(vm, 49779, 1, 6693, 6695, (163,))
            tick(49786)
            vm.pc = 49790
            value = memory.load(cells.value(6693), 1)
            vm._write(6696, value, 4, 'high.load')
            tick(49790)
            _pointer(vm, 49790, 1, 6692, 6697, (163,))
            tick(49797)
            vm.pc = 49801
            pointer = cells.value(6692)
            value = memory.load(cells.pointer(6696), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49801)
            vm.pc = 49803
            vm._jump(1179)
            continue
        if vm.block == 1179:
            tick(49803)
            _phi(vm, 49803, (6698, 2, 6697, 1178, 6692, 1177))
            tick(49810)
            _phi(vm, 49810, (6699, 2, 6695, 1178, 6693, 1177))
            tick(49817)
            vm.pc = 49818
            tick(49818)
            vm.pc = 49821
            vm.auxiliary = (0, 1358096518)
            tick(49821)
            vm.pc = 49826
            vm._write(6700, int(memory.load(cells.pointer(6691), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(49826)
            vm.pc = 49830
            vm._jump(1180 if cells.value(6700) != 0 else 1181)
            continue
        if vm.block == 1180:
            tick(49830)
            vm.pc = 49834
            value = memory.load(cells.value(6699), 1)
            vm._write(6701, value, 4, 'high.load')
            tick(49834)
            vm.pc = 49838
            pointer = cells.value(6698)
            value = memory.load(cells.pointer(6701), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49838)
            vm.pc = 49840
            vm._jump(1181)
            continue
        if vm.block == 1181:
            tick(49840)
            _pointer(vm, 49840, 70, 103, 6702, (145, 6703))
            tick(49848)
            vm.pc = 49853
            cells.copy_q_clear_owned(6702, 6704)
            tick(49853)
            vm.pc = 49854
            tick(49854)
            vm.pc = 49857
            vm.auxiliary = (0, 40964)
            tick(49857)
            vm.pc = 49862
            vm._write(6705, memory.load(cells.pointer(6704), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(49862)
            _pointer(vm, 49862, 1, 2614, 6706, (163,))
            tick(49869)
            vm.pc = 49873
            value = memory.load(cells.value(2614), 1)
            vm._write(6707, value, 4, 'high.load')
            tick(49873)
            _pointer(vm, 49873, 1, 6702, 6708, (163,))
            tick(49880)
            vm.pc = 49884
            pointer = cells.value(6702)
            value = memory.load(cells.pointer(6707), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49884)
            vm.pc = 49889
            cells.copy_q_clear_owned(6708, 6709)
            tick(49889)
            vm.pc = 49894
            vm._write(6710, memory.load(cells.pointer(6709), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(49894)
            vm.pc = 49897
            vm.auxiliary = (0, 371373476)
            tick(49897)
            vm.pc = 49902
            vm._write(6711, int(memory.load(cells.pointer(6710), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(49902)
            vm.pc = 49906
            vm._jump(1182 if cells.value(6711) != 0 else 1183)
            continue
        if vm.block == 1182:
            tick(49906)
            _pointer(vm, 49906, 1, 6706, 6712, (163,))
            tick(49913)
            vm.pc = 49917
            value = memory.load(cells.value(6706), 1)
            vm._write(6713, value, 4, 'high.load')
            tick(49917)
            _pointer(vm, 49917, 1, 6708, 6714, (163,))
            tick(49924)
            vm.pc = 49928
            pointer = cells.value(6708)
            value = memory.load(cells.pointer(6713), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(49928)
            vm.pc = 49930
            vm._jump(1183)
            continue
        if vm.block == 1183:
            tick(49930)
            _phi(vm, 49930, (6715, 2, 504, 1182, 479, 1181))
            tick(49937)
            _phi(vm, 49937, (6716, 2, 6714, 1182, 6708, 1181))
            tick(49944)
            _phi(vm, 49944, (6717, 2, 6712, 1182, 6706, 1181))
            tick(49951)
            vm.pc = 49956
            cells.copy_q_clear_owned(6716, 6718)
            tick(49956)
            vm.pc = 49961
            vm._write(6719, memory.load(cells.pointer(6718), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(49961)
            vm.pc = 49962
            tick(49962)
            vm.pc = 49965
            vm.auxiliary = (0, 377643700)
            tick(49965)
            vm.pc = 49970
            vm._write(6720, int(memory.load(cells.pointer(6719), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(49970)
            vm.pc = 49973
            vm.auxiliary = (0, 242379782)
            tick(49973)
            vm.pc = 49978
            vm._write(6721, int(memory.load(cells.pointer(6715), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(49978)
            vm.pc = 49983
            vm._write(6722, memory.load(cells.pointer(6720), 1, signed=True) & memory.load(cells.pointer(6721), 1, signed=True), 8, 'L13.binary_q')
            tick(49983)
            vm.pc = 49987
            vm._jump(1184 if cells.value(6722) != 0 else 1185)
            continue
        if vm.block == 1184:
            tick(49987)
            _pointer(vm, 49987, 1, 6717, 6723, (163,))
            tick(49994)
            vm.pc = 49998
            value = memory.load(cells.value(6717), 1)
            vm._write(6724, value, 4, 'L5.unsigned_load')
            tick(49998)
            _pointer(vm, 49998, 1, 6716, 6725, (163,))
            tick(50005)
            vm.pc = 50009
            pointer = cells.value(6716)
            value = memory.load(cells.pointer(6724), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50009)
            vm.pc = 50010
            tick(50010)
            vm.pc = 50013
            vm.auxiliary = (0, 1922813954)
            tick(50013)
            vm.pc = 50018
            vm._write(6726, memory.load(cells.pointer(6715), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(50018)
            vm.pc = 50020
            vm._jump(1185)
            continue
        if vm.block == 1185:
            tick(50020)
            _phi(vm, 50020, (6727, 2, 6726, 1184, 6715, 1183))
            tick(50027)
            _phi(vm, 50027, (6728, 2, 6725, 1184, 6716, 1183))
            tick(50034)
            _phi(vm, 50034, (6729, 2, 6723, 1184, 6717, 1183))
            tick(50041)
            vm.pc = 50046
            cells.copy_q_clear_owned(6728, 6730)
            tick(50046)
            vm.pc = 50051
            cells.copy_q_clear_owned(6729, 6731)
            tick(50051)
            vm.pc = 50052
            tick(50052)
            vm.pc = 50055
            vm.auxiliary = (0, 1779620198)
            tick(50055)
            vm.pc = 50060
            vm._write(6732, int(memory.load(cells.pointer(6727), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(50060)
            vm.pc = 50064
            vm._jump(1186 if cells.value(6732) != 0 else 1187)
            continue
        if vm.block == 1186:
            tick(50064)
            _pointer(vm, 50064, 1, 6729, 6733, (172,))
            tick(50071)
            vm.pc = 50076
            cells.copy_q_clear_owned(6733, 6734)
            tick(50076)
            vm.pc = 50080
            value = memory.load(cells.value(6731), 4)
            vm._write(6735, value, 4, 'high.load')
            tick(50080)
            _pointer(vm, 50080, 1, 6728, 6736, (172,))
            tick(50087)
            vm.pc = 50092
            cells.copy_q_clear_owned(6736, 6737)
            tick(50092)
            vm.pc = 50096
            pointer = cells.value(6730)
            value = memory.load(cells.pointer(6735), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(50096)
            vm.pc = 50097
            tick(50097)
            vm.pc = 50100
            vm.auxiliary = (0, 961454082)
            tick(50100)
            vm.pc = 50105
            vm._write(6738, memory.load(cells.pointer(6727), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(50105)
            vm.pc = 50107
            vm._jump(1187)
            continue
        if vm.block == 1187:
            tick(50107)
            _phi(vm, 50107, (6739, 2, 6738, 1186, 6727, 1185))
            tick(50114)
            _phi(vm, 50114, (6740, 2, 6737, 1186, 6730, 1185))
            tick(50121)
            _phi(vm, 50121, (6741, 2, 6734, 1186, 6731, 1185))
            tick(50128)
            vm.pc = 50129
            tick(50129)
            vm.pc = 50132
            vm.auxiliary = (0, 1548896934)
            tick(50132)
            vm.pc = 50137
            vm._write(6742, int(memory.load(cells.pointer(6739), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(50137)
            vm.pc = 50141
            vm._jump(1188 if cells.value(6742) != 0 else 1189)
            continue
        if vm.block == 1188:
            tick(50141)
            _pointer(vm, 50141, 3, 6741, 6743, (163,))
            tick(50148)
            vm.pc = 50152
            value = memory.load(cells.value(6741), 4)
            vm._write(6744, value, 4, 'high.load')
            tick(50152)
            _pointer(vm, 50152, 3, 6740, 6745, (163,))
            tick(50159)
            vm.pc = 50163
            pointer = cells.value(6740)
            value = memory.load(cells.pointer(6744), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(50163)
            vm.pc = 50164
            tick(50164)
            vm.pc = 50167
            vm.auxiliary = (0, 1262899202)
            tick(50167)
            vm.pc = 50172
            vm._write(6746, memory.load(cells.pointer(6739), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(50172)
            vm.pc = 50174
            vm._jump(1189)
            continue
        if vm.block == 1189:
            tick(50174)
            _phi(vm, 50174, (6747, 2, 6746, 1188, 6739, 1187))
            tick(50181)
            _phi(vm, 50181, (6748, 2, 6745, 1188, 6740, 1187))
            tick(50188)
            _phi(vm, 50188, (6749, 2, 6743, 1188, 6741, 1187))
            tick(50195)
            vm.pc = 50196
            tick(50196)
            vm.pc = 50199
            vm.auxiliary = (0, 584244726)
            tick(50199)
            vm.pc = 50204
            vm._write(6750, int(memory.load(cells.pointer(6747), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(50204)
            vm.pc = 50208
            vm._jump(1190 if cells.value(6750) != 0 else 1191)
            continue
        if vm.block == 1190:
            tick(50208)
            _pointer(vm, 50208, 3, 6749, 6751, (163,))
            tick(50215)
            vm.pc = 50219
            value = memory.load(cells.value(6749), 4)
            vm._write(6752, value, 4, 'high.load')
            tick(50219)
            _pointer(vm, 50219, 3, 6748, 6753, (163,))
            tick(50226)
            vm.pc = 50230
            pointer = cells.value(6748)
            value = memory.load(cells.pointer(6752), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(50230)
            vm.pc = 50231
            tick(50231)
            vm.pc = 50234
            vm.auxiliary = (0, 2078175233)
            tick(50234)
            vm.pc = 50239
            vm._write(6754, memory.load(cells.pointer(6747), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(50239)
            vm.pc = 50241
            vm._jump(1191)
            continue
        if vm.block == 1191:
            tick(50241)
            _phi(vm, 50241, (6755, 2, 6754, 1190, 6747, 1189))
            tick(50248)
            _phi(vm, 50248, (6756, 2, 6753, 1190, 6748, 1189))
            tick(50255)
            _phi(vm, 50255, (6757, 2, 6751, 1190, 6749, 1189))
            tick(50262)
            vm.pc = 50267
            cells.copy_q_clear_owned(6756, 6758)
            tick(50267)
            vm.pc = 50272
            cells.copy_q_clear_owned(6757, 6759)
            tick(50272)
            vm.pc = 50273
            tick(50273)
            vm.pc = 50276
            vm.auxiliary = (0, 843250086)
            tick(50276)
            vm.pc = 50281
            vm._write(6760, int(memory.load(cells.pointer(6755), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(50281)
            vm.pc = 50285
            vm._jump(1192 if cells.value(6760) != 0 else 1193)
            continue
        if vm.block == 1192:
            tick(50285)
            _pointer(vm, 50285, 1, 6759, 6761, (163,))
            tick(50292)
            vm.pc = 50296
            value = memory.load(cells.value(6759), 1)
            vm._write(6762, value, 4, 'high.load')
            tick(50296)
            _pointer(vm, 50296, 1, 6758, 6763, (163,))
            tick(50303)
            vm.pc = 50307
            pointer = cells.value(6758)
            value = memory.load(cells.pointer(6762), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50307)
            vm.pc = 50308
            tick(50308)
            vm.pc = 50311
            vm.auxiliary = (0, 1419780097)
            tick(50311)
            vm.pc = 50316
            vm._write(6764, memory.load(cells.pointer(6755), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(50316)
            vm.pc = 50318
            vm._jump(1193)
            continue
        if vm.block == 1193:
            tick(50318)
            _phi(vm, 50318, (6765, 2, 6764, 1192, 6755, 1191))
            tick(50325)
            _phi(vm, 50325, (6766, 2, 6763, 1192, 6758, 1191))
            tick(50332)
            _phi(vm, 50332, (6767, 2, 6761, 1192, 6759, 1191))
            tick(50339)
            vm.pc = 50340
            tick(50340)
            vm.pc = 50343
            vm.auxiliary = (0, 1447225094)
            tick(50343)
            vm.pc = 50348
            vm._write(6768, int(memory.load(cells.pointer(6765), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(50348)
            vm.pc = 50352
            vm._jump(1194 if cells.value(6768) != 0 else 1195)
            continue
        if vm.block == 1194:
            tick(50352)
            _pointer(vm, 50352, 1, 6767, 6769, (163,))
            tick(50359)
            vm.pc = 50363
            value = memory.load(cells.value(6767), 1)
            vm._write(6770, value, 4, 'high.load')
            tick(50363)
            _pointer(vm, 50363, 1, 6766, 6771, (163,))
            tick(50370)
            vm.pc = 50374
            pointer = cells.value(6766)
            value = memory.load(cells.pointer(6770), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50374)
            vm.pc = 50375
            tick(50375)
            vm.pc = 50378
            vm.auxiliary = (0, 1218453506)
            tick(50378)
            vm.pc = 50383
            vm._write(6772, memory.load(cells.pointer(6765), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(50383)
            vm.pc = 50385
            vm._jump(1195)
            continue
        if vm.block == 1195:
            tick(50385)
            _phi(vm, 50385, (6773, 2, 6772, 1194, 6765, 1193))
            tick(50392)
            _phi(vm, 50392, (6774, 2, 6771, 1194, 6766, 1193))
            tick(50399)
            _phi(vm, 50399, (6775, 2, 6769, 1194, 6767, 1193))
            tick(50406)
            vm.pc = 50407
            tick(50407)
            vm.pc = 50410
            vm.auxiliary = (0, 245506726)
            tick(50410)
            vm.pc = 50415
            vm._write(6776, int(memory.load(cells.pointer(6773), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(50415)
            vm.pc = 50419
            vm._jump(1196 if cells.value(6776) != 0 else 1197)
            continue
        if vm.block == 1196:
            tick(50419)
            _pointer(vm, 50419, 1, 6775, 6777, (163,))
            tick(50426)
            vm.pc = 50430
            value = memory.load(cells.value(6775), 1)
            vm._write(6778, value, 4, 'high.load')
            tick(50430)
            _pointer(vm, 50430, 1, 6774, 6779, (163,))
            tick(50437)
            vm.pc = 50441
            pointer = cells.value(6774)
            value = memory.load(cells.pointer(6778), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50441)
            vm.pc = 50443
            vm._jump(1197)
            continue
        if vm.block == 1197:
            tick(50443)
            _phi(vm, 50443, (6780, 2, 6779, 1196, 6774, 1195))
            tick(50450)
            _phi(vm, 50450, (6781, 2, 6777, 1196, 6775, 1195))
            tick(50457)
            vm.pc = 50458
            tick(50458)
            vm.pc = 50461
            vm.auxiliary = (0, 1341314534)
            tick(50461)
            vm.pc = 50466
            vm._write(6782, int(memory.load(cells.pointer(6773), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(50466)
            vm.pc = 50470
            vm._jump(1198 if cells.value(6782) != 0 else 1199)
            continue
        if vm.block == 1198:
            tick(50470)
            vm.pc = 50474
            value = memory.load(cells.value(6781), 1)
            vm._write(6783, value, 4, 'high.load')
            tick(50474)
            vm.pc = 50478
            pointer = cells.value(6780)
            value = memory.load(cells.pointer(6783), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50478)
            vm.pc = 50480
            vm._jump(1199)
            continue
        if vm.block == 1199:
            tick(50480)
            _pointer(vm, 50480, 70, 103, 6784, (145, 4997))
            tick(50488)
            vm.pc = 50493
            cells.copy_q_clear_owned(6784, 6785)
            tick(50493)
            vm.pc = 50494
            tick(50494)
            vm.pc = 50497
            vm.auxiliary = (0, 59252)
            tick(50497)
            vm.pc = 50502
            vm._write(6786, memory.load(cells.pointer(6785), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(50502)
            _pointer(vm, 50502, 1, 3012, 6787, (163,))
            tick(50509)
            vm.pc = 50513
            value = memory.load(cells.value(3012), 1)
            vm._write(6788, value, 4, 'L5.unsigned_load')
            tick(50513)
            _pointer(vm, 50513, 1, 6784, 6789, (163,))
            tick(50520)
            vm.pc = 50524
            pointer = cells.value(6784)
            value = memory.load(cells.pointer(6788), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50524)
            vm.pc = 50529
            cells.copy_q_clear_owned(6789, 6790)
            tick(50529)
            vm.pc = 50532
            vm.auxiliary = (0, 29701)
            tick(50532)
            vm.pc = 50537
            vm._write(6791, memory.load(cells.pointer(6790), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(50537)
            vm.pc = 50540
            vm.auxiliary = (0, 580026468)
            tick(50540)
            vm.pc = 50545
            vm._write(6792, int(memory.load(cells.pointer(6791), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(50545)
            vm.pc = 50549
            vm._jump(1200 if cells.value(6792) != 0 else 1201)
            continue
        if vm.block == 1200:
            tick(50549)
            _pointer(vm, 50549, 1, 6787, 6793, (163,))
            tick(50556)
            vm.pc = 50560
            value = memory.load(cells.value(6787), 1)
            vm._write(6794, value, 4, 'high.load')
            tick(50560)
            _pointer(vm, 50560, 1, 6789, 6795, (163,))
            tick(50567)
            vm.pc = 50571
            pointer = cells.value(6789)
            value = memory.load(cells.pointer(6794), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50571)
            vm.pc = 50573
            vm._jump(1201)
            continue
        if vm.block == 1201:
            tick(50573)
            _phi(vm, 50573, (6796, 2, 476, 1200, 502, 1199))
            tick(50580)
            _phi(vm, 50580, (6797, 2, 6795, 1200, 6789, 1199))
            tick(50587)
            _phi(vm, 50587, (6798, 2, 6793, 1200, 6787, 1199))
            tick(50594)
            vm.pc = 50599
            cells.copy_q_clear_owned(6797, 6799)
            tick(50599)
            vm.pc = 50600
            tick(50600)
            vm.pc = 50603
            vm.auxiliary = (0, 13359)
            tick(50603)
            vm.pc = 50608
            vm._write(6800, memory.load(cells.pointer(6799), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(50608)
            vm.pc = 50611
            vm.auxiliary = (0, 396546532)
            tick(50611)
            vm.pc = 50616
            vm._write(6801, int(memory.load(cells.pointer(6800), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(50616)
            vm.pc = 50619
            vm.auxiliary = (0, 1286791382)
            tick(50619)
            vm.pc = 50624
            vm._write(6802, int(memory.load(cells.pointer(6796), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(50624)
            vm.pc = 50627
            vm.auxiliary = (0, 33644)
            tick(50627)
            vm.pc = 50632
            vm._write(6803, memory.load(cells.pointer(6801), 1, signed=True) & memory.load(cells.pointer(6802), 1, signed=True), 8, 'typed.selector1.q')
            tick(50632)
            vm.pc = 50636
            vm._jump(1202 if cells.value(6803) != 0 else 1203)
            continue
        if vm.block == 1202:
            tick(50636)
            _pointer(vm, 50636, 1, 6798, 6804, (163,))
            tick(50643)
            vm.pc = 50647
            value = memory.load(cells.value(6798), 1)
            vm._write(6805, value, 4, 'high.load')
            tick(50647)
            _pointer(vm, 50647, 1, 6797, 6806, (163,))
            tick(50654)
            vm.pc = 50658
            pointer = cells.value(6797)
            value = memory.load(cells.pointer(6805), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50658)
            vm.pc = 50659
            tick(50659)
            vm.pc = 50662
            vm.auxiliary = (0, 1763786753)
            tick(50662)
            vm.pc = 50667
            vm._write(6807, memory.load(cells.pointer(6796), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(50667)
            vm.pc = 50669
            vm._jump(1203)
            continue
        if vm.block == 1203:
            tick(50669)
            _phi(vm, 50669, (6808, 2, 6807, 1202, 6796, 1201))
            tick(50676)
            _phi(vm, 50676, (6809, 2, 6806, 1202, 6797, 1201))
            tick(50683)
            _phi(vm, 50683, (6810, 2, 6804, 1202, 6798, 1201))
            tick(50690)
            vm.pc = 50695
            cells.copy_q_clear_owned(6809, 6811)
            tick(50695)
            vm.pc = 50700
            cells.copy_q_clear_owned(6810, 6812)
            tick(50700)
            vm.pc = 50701
            tick(50701)
            vm.pc = 50704
            vm.auxiliary = (0, 792865878)
            tick(50704)
            vm.pc = 50709
            vm._write(6813, int(memory.load(cells.pointer(6808), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(50709)
            vm.pc = 50713
            vm._jump(1204 if cells.value(6813) != 0 else 1205)
            continue
        if vm.block == 1204:
            tick(50713)
            _pointer(vm, 50713, 1, 6810, 6814, (172,))
            tick(50720)
            vm.pc = 50725
            cells.copy_q_clear_owned(6814, 6815)
            tick(50725)
            vm.pc = 50729
            value = memory.load(cells.value(6812), 4)
            vm._write(6816, value, 4, 'high.load')
            tick(50729)
            _pointer(vm, 50729, 1, 6809, 6817, (172,))
            tick(50736)
            vm.pc = 50741
            cells.copy_q_clear_owned(6817, 6818)
            tick(50741)
            vm.pc = 50745
            pointer = cells.value(6811)
            value = memory.load(cells.pointer(6816), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(50745)
            vm.pc = 50746
            tick(50746)
            vm.pc = 50749
            vm.auxiliary = (0, 768802818)
            tick(50749)
            vm.pc = 50754
            vm._write(6819, memory.load(cells.pointer(6808), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(50754)
            vm.pc = 50756
            vm._jump(1205)
            continue
        if vm.block == 1205:
            tick(50756)
            _phi(vm, 50756, (6820, 2, 6819, 1204, 6808, 1203))
            tick(50763)
            _phi(vm, 50763, (6821, 2, 6818, 1204, 6811, 1203))
            tick(50770)
            _phi(vm, 50770, (6822, 2, 6815, 1204, 6812, 1203))
            tick(50777)
            vm.pc = 50778
            tick(50778)
            vm.pc = 50781
            vm.auxiliary = (0, 1860318886)
            tick(50781)
            vm.pc = 50786
            vm._write(6823, int(memory.load(cells.pointer(6820), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(50786)
            vm.pc = 50790
            vm._jump(1206 if cells.value(6823) != 0 else 1207)
            continue
        if vm.block == 1206:
            tick(50790)
            _pointer(vm, 50790, 3, 6822, 6824, (163,))
            tick(50797)
            vm.pc = 50801
            value = memory.load(cells.value(6822), 4)
            vm._write(6825, value, 4, 'high.load')
            tick(50801)
            _pointer(vm, 50801, 3, 6821, 6826, (163,))
            tick(50808)
            vm.pc = 50812
            pointer = cells.value(6821)
            value = memory.load(cells.pointer(6825), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(50812)
            vm.pc = 50813
            tick(50813)
            vm.pc = 50816
            vm.auxiliary = (0, 908066818)
            tick(50816)
            vm.pc = 50821
            vm._write(6827, memory.load(cells.pointer(6820), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(50821)
            vm.pc = 50823
            vm._jump(1207)
            continue
        if vm.block == 1207:
            tick(50823)
            _phi(vm, 50823, (6828, 2, 6827, 1206, 6820, 1205))
            tick(50830)
            _phi(vm, 50830, (6829, 2, 6826, 1206, 6821, 1205))
            tick(50837)
            _phi(vm, 50837, (6830, 2, 6824, 1206, 6822, 1205))
            tick(50844)
            vm.pc = 50845
            tick(50845)
            vm.pc = 50848
            vm.auxiliary = (0, 787658470)
            tick(50848)
            vm.pc = 50853
            vm._write(6831, int(memory.load(cells.pointer(6828), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(50853)
            vm.pc = 50857
            vm._jump(1208 if cells.value(6831) != 0 else 1209)
            continue
        if vm.block == 1208:
            tick(50857)
            _pointer(vm, 50857, 3, 6830, 6832, (163,))
            tick(50864)
            vm.pc = 50868
            value = memory.load(cells.value(6830), 4)
            vm._write(6833, value, 4, 'high.load')
            tick(50868)
            _pointer(vm, 50868, 3, 6829, 6834, (163,))
            tick(50875)
            vm.pc = 50879
            pointer = cells.value(6829)
            value = memory.load(cells.pointer(6833), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(50879)
            vm.pc = 50880
            tick(50880)
            vm.pc = 50883
            vm.auxiliary = (0, 1875836930)
            tick(50883)
            vm.pc = 50888
            vm._write(6835, memory.load(cells.pointer(6828), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(50888)
            vm.pc = 50890
            vm._jump(1209)
            continue
        if vm.block == 1209:
            tick(50890)
            _phi(vm, 50890, (6836, 2, 6835, 1208, 6828, 1207))
            tick(50897)
            _phi(vm, 50897, (6837, 2, 6834, 1208, 6829, 1207))
            tick(50904)
            _phi(vm, 50904, (6838, 2, 6832, 1208, 6830, 1207))
            tick(50911)
            vm.pc = 50916
            cells.copy_q_clear_owned(6837, 6839)
            tick(50916)
            vm.pc = 50921
            cells.copy_q_clear_owned(6838, 6840)
            tick(50921)
            vm.pc = 50922
            tick(50922)
            vm.pc = 50925
            vm.auxiliary = (0, 1293088278)
            tick(50925)
            vm.pc = 50930
            vm._write(6841, int(memory.load(cells.pointer(6836), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(50930)
            vm.pc = 50934
            vm._jump(1210 if cells.value(6841) != 0 else 1211)
            continue
        if vm.block == 1210:
            tick(50934)
            _pointer(vm, 50934, 1, 6840, 6842, (163,))
            tick(50941)
            vm.pc = 50945
            value = memory.load(cells.value(6840), 1)
            vm._write(6843, value, 4, 'high.load')
            tick(50945)
            _pointer(vm, 50945, 1, 6839, 6844, (163,))
            tick(50952)
            vm.pc = 50956
            pointer = cells.value(6839)
            value = memory.load(cells.pointer(6843), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(50956)
            vm.pc = 50957
            tick(50957)
            vm.pc = 50960
            vm.auxiliary = (0, 770842625)
            tick(50960)
            vm.pc = 50965
            vm._write(6845, memory.load(cells.pointer(6836), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(50965)
            vm.pc = 50967
            vm._jump(1211)
            continue
        if vm.block == 1211:
            tick(50967)
            _phi(vm, 50967, (6846, 2, 6845, 1210, 6836, 1209))
            tick(50974)
            _phi(vm, 50974, (6847, 2, 6844, 1210, 6839, 1209))
            tick(50981)
            _phi(vm, 50981, (6848, 2, 6842, 1210, 6840, 1209))
            tick(50988)
            vm.pc = 50989
            tick(50989)
            vm.pc = 50992
            vm.auxiliary = (0, 926088246)
            tick(50992)
            vm.pc = 50997
            vm._write(6849, int(memory.load(cells.pointer(6846), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(50997)
            vm.pc = 51001
            vm._jump(1212 if cells.value(6849) != 0 else 1213)
            continue
        if vm.block == 1212:
            tick(51001)
            _pointer(vm, 51001, 1, 6848, 6850, (163,))
            tick(51008)
            vm.pc = 51012
            value = memory.load(cells.value(6848), 1)
            vm._write(6851, value, 4, 'L5.unsigned_load')
            tick(51012)
            _pointer(vm, 51012, 1, 6847, 6852, (163,))
            tick(51019)
            vm.pc = 51023
            pointer = cells.value(6847)
            value = memory.load(cells.pointer(6851), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51023)
            vm.pc = 51024
            tick(51024)
            vm.pc = 51027
            vm.auxiliary = (0, 1113677825)
            tick(51027)
            vm.pc = 51032
            vm._write(6853, memory.load(cells.pointer(6846), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(51032)
            vm.pc = 51034
            vm._jump(1213)
            continue
        if vm.block == 1213:
            tick(51034)
            _phi(vm, 51034, (6854, 2, 6853, 1212, 6846, 1211))
            tick(51041)
            _phi(vm, 51041, (6855, 2, 6852, 1212, 6847, 1211))
            tick(51048)
            _phi(vm, 51048, (6856, 2, 6850, 1212, 6848, 1211))
            tick(51055)
            vm.pc = 51056
            tick(51056)
            vm.pc = 51059
            vm.auxiliary = (0, 1100106550)
            tick(51059)
            vm.pc = 51064
            vm._write(6857, int(memory.load(cells.pointer(6854), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(51064)
            vm.pc = 51068
            vm._jump(1214 if cells.value(6857) != 0 else 1215)
            continue
        if vm.block == 1214:
            tick(51068)
            _pointer(vm, 51068, 1, 6856, 6858, (163,))
            tick(51075)
            vm.pc = 51079
            value = memory.load(cells.value(6856), 1)
            vm._write(6859, value, 4, 'high.load')
            tick(51079)
            _pointer(vm, 51079, 1, 6855, 6860, (163,))
            tick(51086)
            vm.pc = 51090
            pointer = cells.value(6855)
            value = memory.load(cells.pointer(6859), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51090)
            vm.pc = 51092
            vm._jump(1215)
            continue
        if vm.block == 1215:
            tick(51092)
            _phi(vm, 51092, (6861, 2, 6860, 1214, 6855, 1213))
            tick(51099)
            _phi(vm, 51099, (6862, 2, 6858, 1214, 6856, 1213))
            tick(51106)
            vm.pc = 51107
            tick(51107)
            vm.pc = 51110
            vm.auxiliary = (0, 1537386326)
            tick(51110)
            vm.pc = 51115
            vm._write(6863, int(memory.load(cells.pointer(6854), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(51115)
            vm.pc = 51119
            vm._jump(1216 if cells.value(6863) != 0 else 1217)
            continue
        if vm.block == 1216:
            tick(51119)
            vm.pc = 51123
            value = memory.load(cells.value(6862), 1)
            vm._write(6864, value, 4, 'high.load')
            tick(51123)
            vm.pc = 51127
            pointer = cells.value(6861)
            value = memory.load(cells.pointer(6864), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51127)
            vm.pc = 51129
            vm._jump(1217)
            continue
        if vm.block == 1217:
            tick(51129)
            vm.pc = 51131
            vm._jump(1218)
            continue
        if vm.block == 1218:
            tick(51131)
            _phi(vm, 51131, (6865, 2, 2614, 1217, 6866, 1219))
            tick(51138)
            _phi(vm, 51138, (6867, 2, 421, 1217, 6868, 1219))
            tick(51145)
            vm.pc = 51146
            tick(51146)
            vm.pc = 51149
            vm.auxiliary = (0, 1703032563)
            tick(51149)
            _equal(vm, 51154, 8, 6867, 145, 6869)
            tick(51154)
            vm.pc = 51158
            vm._jump(1220 if cells.value(6869) != 0 else 1219)
            continue
        if vm.block == 1219:
            tick(51158)
            vm.pc = 51159
            tick(51159)
            vm.pc = 51162
            vm.auxiliary = (0, 613056513)
            tick(51162)
            vm.pc = 51167
            vm._write(6868, memory.load(cells.pointer(6867), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(51167)
            _pointer(vm, 51167, 1, 6865, 6866, (163,))
            tick(51174)
            vm.pc = 51178
            pointer = cells.value(6865)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51178)
            vm.pc = 51180
            vm._jump(1218)
            continue
        if vm.block == 1220:
            tick(51180)
            _pointer(vm, 51180, 70, 103, 6870, (145, 6871))
            tick(51188)
            vm.pc = 51193
            cells.copy_q_clear_owned(6870, 6872)
            tick(51193)
            vm.pc = 51194
            tick(51194)
            vm.pc = 51197
            vm.auxiliary = (0, 17436)
            tick(51197)
            vm.pc = 51202
            vm._write(6873, memory.load(cells.pointer(6872), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(51202)
            _pointer(vm, 51202, 1, 1198, 6874, (163,))
            tick(51209)
            vm.pc = 51213
            value = memory.load(cells.value(1198), 1)
            vm._write(6875, value, 4, 'high.load')
            tick(51213)
            _pointer(vm, 51213, 1, 6870, 6876, (163,))
            tick(51220)
            vm.pc = 51224
            pointer = cells.value(6870)
            value = memory.load(cells.pointer(6875), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51224)
            vm.pc = 51229
            cells.copy_q_clear_owned(6876, 6877)
            tick(51229)
            vm.pc = 51234
            vm._write(6878, memory.load(cells.pointer(6877), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(51234)
            vm.pc = 51237
            vm.auxiliary = (0, 703775444)
            tick(51237)
            vm.pc = 51242
            vm._write(6879, int(memory.load(cells.pointer(6878), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(51242)
            vm.pc = 51244
            vm._jump(1221)
            continue
        if vm.block == 1221:
            tick(51244)
            vm.pc = 51249
            cells.copy_q_clear_owned(6876, 6880)
            tick(51249)
            vm.pc = 51254
            vm._write(6881, memory.load(cells.pointer(6880), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(51254)
            vm.pc = 51255
            tick(51255)
            vm.pc = 51258
            vm.auxiliary = (0, 979511972)
            tick(51258)
            vm.pc = 51263
            vm._write(6882, int(memory.load(cells.pointer(6881), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(51263)
            vm.pc = 51266
            vm.auxiliary = (0, 2006114694)
            tick(51266)
            vm.pc = 51271
            vm._write(6883, int(memory.load(cells.pointer(158), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(51271)
            vm.pc = 51276
            vm._write(6884, memory.load(cells.pointer(6882), 1, signed=True) & memory.load(cells.pointer(6883), 1, signed=True), 8, 'L13.binary_q')
            tick(51276)
            vm.pc = 51280
            vm._jump(1222 if cells.value(6884) != 0 else 1223)
            continue
        if vm.block == 1222:
            tick(51280)
            _pointer(vm, 51280, 1, 6874, 6885, (163,))
            tick(51287)
            vm.pc = 51291
            value = memory.load(cells.value(6874), 1)
            vm._write(6886, value, 4, 'high.load')
            tick(51291)
            _pointer(vm, 51291, 1, 6876, 6887, (163,))
            tick(51298)
            vm.pc = 51302
            pointer = cells.value(6876)
            value = memory.load(cells.pointer(6886), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51302)
            vm.pc = 51303
            tick(51303)
            vm.pc = 51306
            vm.auxiliary = (0, 1057398785)
            tick(51306)
            vm.pc = 51311
            vm._write(6888, memory.load(cells.pointer(158), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(51311)
            vm.pc = 51313
            vm._jump(1223)
            continue
        if vm.block == 1223:
            tick(51313)
            _phi(vm, 51313, (6889, 2, 6888, 1222, 158, 1221))
            tick(51320)
            _phi(vm, 51320, (6890, 2, 6887, 1222, 6876, 1221))
            tick(51327)
            _phi(vm, 51327, (6891, 2, 6885, 1222, 6874, 1221))
            tick(51334)
            vm.pc = 51339
            cells.copy_q_clear_owned(6890, 6892)
            tick(51339)
            vm.pc = 51344
            cells.copy_q_clear_owned(6891, 6893)
            tick(51344)
            vm.pc = 51345
            tick(51345)
            vm.pc = 51348
            vm.auxiliary = (0, 1239565574)
            tick(51348)
            vm.pc = 51353
            vm._write(6894, int(memory.load(cells.pointer(6889), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(51353)
            vm.pc = 51357
            vm._jump(1224 if cells.value(6894) != 0 else 1225)
            continue
        if vm.block == 1224:
            tick(51357)
            _pointer(vm, 51357, 1, 6891, 6895, (172,))
            tick(51364)
            vm.pc = 51369
            cells.copy_q_clear_owned(6895, 6896)
            tick(51369)
            vm.pc = 51373
            value = memory.load(cells.value(6893), 4)
            vm._write(6897, value, 4, 'L5.unsigned_load')
            tick(51373)
            _pointer(vm, 51373, 1, 6890, 6898, (172,))
            tick(51380)
            vm.pc = 51385
            cells.copy_q_clear_owned(6898, 6899)
            tick(51385)
            vm.pc = 51389
            pointer = cells.value(6892)
            value = memory.load(cells.pointer(6897), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(51389)
            vm.pc = 51390
            tick(51390)
            vm.pc = 51393
            vm.auxiliary = (0, 1414975489)
            tick(51393)
            vm.pc = 51398
            vm._write(6900, memory.load(cells.pointer(6889), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(51398)
            vm.pc = 51400
            vm._jump(1225)
            continue
        if vm.block == 1225:
            tick(51400)
            _phi(vm, 51400, (6901, 2, 6900, 1224, 6889, 1223))
            tick(51407)
            _phi(vm, 51407, (6902, 2, 6899, 1224, 6892, 1223))
            tick(51414)
            _phi(vm, 51414, (6903, 2, 6896, 1224, 6893, 1223))
            tick(51421)
            vm.pc = 51422
            tick(51422)
            vm.pc = 51425
            vm.auxiliary = (0, 1426259814)
            tick(51425)
            vm.pc = 51430
            vm._write(6904, int(memory.load(cells.pointer(6901), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(51430)
            vm.pc = 51434
            vm._jump(1226 if cells.value(6904) != 0 else 1227)
            continue
        if vm.block == 1226:
            tick(51434)
            _pointer(vm, 51434, 3, 6903, 6905, (163,))
            tick(51441)
            vm.pc = 51445
            value = memory.load(cells.value(6903), 4)
            vm._write(6906, value, 4, 'high.load')
            tick(51445)
            _pointer(vm, 51445, 3, 6902, 6907, (163,))
            tick(51452)
            vm.pc = 51456
            pointer = cells.value(6902)
            value = memory.load(cells.pointer(6906), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(51456)
            vm.pc = 51457
            tick(51457)
            vm.pc = 51460
            vm.auxiliary = (0, 957808641)
            tick(51460)
            vm.pc = 51465
            vm._write(6908, memory.load(cells.pointer(6901), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(51465)
            vm.pc = 51467
            vm._jump(1227)
            continue
        if vm.block == 1227:
            tick(51467)
            _phi(vm, 51467, (6909, 2, 6908, 1226, 6901, 1225))
            tick(51474)
            _phi(vm, 51474, (6910, 2, 6907, 1226, 6902, 1225))
            tick(51481)
            _phi(vm, 51481, (6911, 2, 6905, 1226, 6903, 1225))
            tick(51488)
            vm.pc = 51489
            tick(51489)
            vm.pc = 51492
            vm.auxiliary = (0, 873600486)
            tick(51492)
            vm.pc = 51497
            vm._write(6912, int(memory.load(cells.pointer(6909), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(51497)
            vm.pc = 51501
            vm._jump(1228 if cells.value(6912) != 0 else 1229)
            continue
        if vm.block == 1228:
            tick(51501)
            _pointer(vm, 51501, 3, 6911, 6913, (163,))
            tick(51508)
            vm.pc = 51512
            value = memory.load(cells.value(6911), 4)
            vm._write(6914, value, 4, 'high.load')
            tick(51512)
            _pointer(vm, 51512, 3, 6910, 6915, (163,))
            tick(51519)
            vm.pc = 51523
            pointer = cells.value(6910)
            value = memory.load(cells.pointer(6914), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(51523)
            vm.pc = 51524
            tick(51524)
            vm.pc = 51527
            vm.auxiliary = (0, 2072596482)
            tick(51527)
            vm.pc = 51532
            vm._write(6916, memory.load(cells.pointer(6909), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(51532)
            vm.pc = 51534
            vm._jump(1229)
            continue
        if vm.block == 1229:
            tick(51534)
            _phi(vm, 51534, (6917, 2, 6916, 1228, 6909, 1227))
            tick(51541)
            _phi(vm, 51541, (6918, 2, 6915, 1228, 6910, 1227))
            tick(51548)
            _phi(vm, 51548, (6919, 2, 6913, 1228, 6911, 1227))
            tick(51555)
            vm.pc = 51560
            cells.copy_q_clear_owned(6918, 6920)
            tick(51560)
            vm.pc = 51565
            cells.copy_q_clear_owned(6919, 6921)
            tick(51565)
            vm.pc = 51566
            tick(51566)
            vm.pc = 51569
            vm.auxiliary = (0, 1094888102)
            tick(51569)
            vm.pc = 51574
            vm._write(6922, int(memory.load(cells.pointer(6917), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(51574)
            vm.pc = 51578
            vm._jump(1230 if cells.value(6922) != 0 else 1231)
            continue
        if vm.block == 1230:
            tick(51578)
            _pointer(vm, 51578, 1, 6921, 6923, (163,))
            tick(51585)
            vm.pc = 51589
            value = memory.load(cells.value(6921), 1)
            vm._write(6924, value, 4, 'high.load')
            tick(51589)
            _pointer(vm, 51589, 1, 6920, 6925, (163,))
            tick(51596)
            vm.pc = 51600
            pointer = cells.value(6920)
            value = memory.load(cells.pointer(6924), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51600)
            vm.pc = 51601
            tick(51601)
            vm.pc = 51604
            vm.auxiliary = (0, 1912668162)
            tick(51604)
            vm.pc = 51609
            vm._write(6926, memory.load(cells.pointer(6917), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(51609)
            vm.pc = 51611
            vm._jump(1231)
            continue
        if vm.block == 1231:
            tick(51611)
            _phi(vm, 51611, (6927, 2, 6926, 1230, 6917, 1229))
            tick(51618)
            _phi(vm, 51618, (6928, 2, 6925, 1230, 6920, 1229))
            tick(51625)
            _phi(vm, 51625, (6929, 2, 6923, 1230, 6921, 1229))
            tick(51632)
            vm.pc = 51633
            tick(51633)
            vm.pc = 51636
            vm.auxiliary = (0, 2041772838)
            tick(51636)
            vm.pc = 51641
            vm._write(6930, int(memory.load(cells.pointer(6927), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(51641)
            vm.pc = 51645
            vm._jump(1232 if cells.value(6930) != 0 else 1233)
            continue
        if vm.block == 1232:
            tick(51645)
            _pointer(vm, 51645, 1, 6929, 6931, (163,))
            tick(51652)
            vm.pc = 51656
            value = memory.load(cells.value(6929), 1)
            vm._write(6932, value, 4, 'high.load')
            tick(51656)
            _pointer(vm, 51656, 1, 6928, 6933, (163,))
            tick(51663)
            vm.pc = 51667
            pointer = cells.value(6928)
            value = memory.load(cells.pointer(6932), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51667)
            vm.pc = 51668
            tick(51668)
            vm.pc = 51671
            vm.auxiliary = (0, 1371103234)
            tick(51671)
            vm.pc = 51676
            vm._write(6934, memory.load(cells.pointer(6927), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(51676)
            vm.pc = 51678
            vm._jump(1233)
            continue
        if vm.block == 1233:
            tick(51678)
            _phi(vm, 51678, (6935, 2, 6934, 1232, 6927, 1231))
            tick(51685)
            _phi(vm, 51685, (6936, 2, 6933, 1232, 6928, 1231))
            tick(51692)
            _phi(vm, 51692, (6937, 2, 6931, 1232, 6929, 1231))
            tick(51699)
            vm.pc = 51700
            tick(51700)
            vm.pc = 51703
            vm.auxiliary = (0, 1891805542)
            tick(51703)
            vm.pc = 51708
            vm._write(6938, int(memory.load(cells.pointer(6935), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(51708)
            vm.pc = 51712
            vm._jump(1234 if cells.value(6938) != 0 else 1235)
            continue
        if vm.block == 1234:
            tick(51712)
            _pointer(vm, 51712, 1, 6937, 6939, (163,))
            tick(51719)
            vm.pc = 51723
            value = memory.load(cells.value(6937), 1)
            vm._write(6940, value, 4, 'high.load')
            tick(51723)
            _pointer(vm, 51723, 1, 6936, 6941, (163,))
            tick(51730)
            vm.pc = 51734
            pointer = cells.value(6936)
            value = memory.load(cells.pointer(6940), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51734)
            vm.pc = 51736
            vm._jump(1235)
            continue
        if vm.block == 1235:
            tick(51736)
            _phi(vm, 51736, (6942, 2, 6941, 1234, 6936, 1233))
            tick(51743)
            _phi(vm, 51743, (6943, 2, 6939, 1234, 6937, 1233))
            tick(51750)
            vm.pc = 51751
            tick(51751)
            vm.pc = 51754
            vm.auxiliary = (0, 1948415766)
            tick(51754)
            vm.pc = 51759
            vm._write(6944, int(memory.load(cells.pointer(6935), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(51759)
            vm.pc = 51763
            vm._jump(1236 if cells.value(6944) != 0 else 1237)
            continue
        if vm.block == 1236:
            tick(51763)
            vm.pc = 51767
            value = memory.load(cells.value(6943), 1)
            vm._write(6945, value, 4, 'high.load')
            tick(51767)
            vm.pc = 51771
            pointer = cells.value(6942)
            value = memory.load(cells.pointer(6945), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(51771)
            vm.pc = 51773
            vm._jump(1237)
            continue
        if vm.block == 1237:
            tick(51773)
            vm.pc = 51778
            cells.copy_q_clear_owned(133, 6946)
            tick(51778)
            vm.pc = 51783
            cells.copy_q_clear_owned(63, 6947)
            tick(51783)
            vm.pc = 51787
            pointer = cells.value(63)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(51787)
            vm.pc = 51789
            vm._jump(1238)
            continue
        if vm.block == 1238:
            tick(51789)
            _phi(vm, 51789, (6948, 2, 145, 1237, 6949, 1239))
            tick(51796)
            vm.pc = 51801
            vm._write(6950, int(cells.value(6948) < cells.value(166)), 4, 'once18.unsigned_q')
            tick(51801)
            vm.pc = 51805
            vm._jump(1240 if cells.value(6950) != 0 else 1241)
            continue
        if vm.block == 1240:
            tick(51805)
            vm.pc = 51810
            vm._write(6951, cells.value(6948) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(51810)
            vm.pc = 51811
            tick(51811)
            vm.pc = 51814
            vm.auxiliary = (0, 860135426)
            tick(51814)
            vm.pc = 51819
            vm._write(6953, memory.load(cells.pointer(6951), 2, signed=True) + memory.load(cells.pointer(6952), 2, signed=True), 8, 'once1.integer')
            tick(51819)
            vm.pc = 51824
            value = memory.load(cells.pointer(6953), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(6954, value >> (count & 31), 4, 'once8.logical_shift')
            tick(51824)
            _pointer(vm, 51824, 91, 112, 6955, (145, 391))
            tick(51832)
            vm.pc = 51836
            value = memory.load(cells.value(6955), 8)
            vm._write(6956, value, 8, 'high.load')
            tick(51836)
            vm.pc = 51841
            vm._write(6957, cells.value(6956) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(51841)
            vm.pc = 51846
            vm._write(6958, memory.load(cells.pointer(6957), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(51846)
            vm.pc = 51849
            vm.auxiliary = (0, 48764)
            tick(51849)
            vm.pc = 51855
            vm._write(6959, memory.load(cells.pointer(6954), 2, signed=True) ^ memory.load(cells.pointer(6958), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(51855)
            vm.pc = 51860
            _convert(vm, 8, 6959, 6960)
            tick(51860)
            _pointer(vm, 51860, 91, 112, 6961, (145, 311, 6960))
            tick(51869)
            vm.pc = 51873
            value = memory.load(cells.value(6961), 8)
            vm._write(6962, value, 8, 'high.load')
            tick(51873)
            vm.pc = 51876
            vm.auxiliary = (0, 420643075)
            tick(51876)
            vm.pc = 51881
            vm._write(6963, int(memory.load(cells.pointer(6962), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(51881)
            vm.pc = 51885
            vm._jump(1242 if cells.value(6963) != 0 else 1243)
            continue
        if vm.block == 1243:
            tick(51885)
            vm.pc = 51890
            value = memory.load(cells.pointer(6956), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(6964, value >> (count & 63), 8, 'once8.logical_shift')
            tick(51890)
            vm.pc = 51895
            vm._write(6965, cells.value(6964) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(51895)
            vm.pc = 51896
            tick(51896)
            vm.pc = 51899
            vm.auxiliary = (0, 20052)
            tick(51899)
            vm.pc = 51905
            vm._write(6966, memory.load(cells.pointer(6965), 2, signed=True) ^ memory.load(cells.pointer(6953), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(51905)
            vm.pc = 51910
            vm._write(6967, memory.load(cells.pointer(6966), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(51910)
            vm.pc = 51915
            _convert(vm, 8, 6967, 6968)
            tick(51915)
            _pointer(vm, 51915, 78, 6962, 6969, (6968,))
            tick(51922)
            vm.pc = 51926
            value = memory.load(cells.value(6969), 8)
            vm._write(6970, value, 8, 'high.load')
            tick(51926)
            vm.pc = 51929
            vm.auxiliary = (0, 989987955)
            tick(51929)
            vm.pc = 51934
            vm._write(6971, int(memory.load(cells.pointer(6970), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(51934)
            vm.pc = 51938
            vm._jump(1242 if cells.value(6971) != 0 else 1244)
            continue
        if vm.block == 1244:
            tick(51938)
            _pointer(vm, 51938, 79, 6970, 6972, (145, 269))
            tick(51946)
            vm.pc = 51950
            value = memory.load(cells.value(6972), 2)
            vm._write(6973, value, 4, 'high.load')
            tick(51950)
            vm.pc = 51951
            tick(51951)
            vm.pc = 51954
            vm.auxiliary = (0, 520275171)
            tick(51954)
            _equal(vm, 51959, 2, 6973, 6953, 6974)
            tick(51959)
            vm.pc = 51963
            vm._jump(1245 if cells.value(6974) != 0 else 1242)
            continue
        if vm.block == 1245:
            tick(51963)
            _pointer(vm, 51963, 79, 6970, 6975, (145, 360))
            tick(51971)
            vm.pc = 51975
            value = memory.load(cells.value(6975), 4)
            vm._write(6976, value, 4, 'high.load')
            tick(51975)
            _pointer(vm, 51975, 79, 6970, 6977, (145, 158))
            tick(51983)
            vm.pc = 51987
            value = memory.load(cells.value(6977), 4)
            vm._write(6978, value, 4, 'L5.unsigned_load')
            tick(51987)
            vm.pc = 51988
            tick(51988)
            vm.pc = 51991
            vm.auxiliary = (0, 44414)
            tick(51991)
            vm.pc = 51997
            vm._write(6979, memory.load(cells.pointer(6978), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(51997)
            vm.pc = 52000
            vm.auxiliary = (0, 415875588)
            tick(52000)
            vm.pc = 52005
            vm._write(6980, memory.load(cells.pointer(6979), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(52005)
            _pointer(vm, 52005, 79, 6970, 6981, (145, 269))
            tick(52013)
            vm.pc = 52017
            value = memory.load(cells.value(6981), 2)
            vm._write(6982, value, 4, 'high.load')
            tick(52017)
            vm.pc = 52022
            _convert(vm, 4, 6982, 6983)
            tick(52022)
            vm.pc = 52025
            vm.auxiliary = (0, 47429)
            tick(52025)
            vm.pc = 52031
            vm._write(6984, memory.load(cells.pointer(6980), 4, signed=True) ^ memory.load(cells.pointer(6983), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(52031)
            vm.pc = 52034
            vm.auxiliary = (0, 509227524)
            tick(52034)
            vm.pc = 52039
            vm._write(6985, memory.load(cells.pointer(6984), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(52039)
            _pointer(vm, 52039, 79, 6970, 6986, (145, 311))
            tick(52047)
            vm.pc = 52051
            value = memory.load(cells.value(6986), 8)
            vm._write(6987, value, 8, 'high.load')
            tick(52051)
            vm.pc = 52056
            cells.copy_q_clear_owned(6987, 6988)
            tick(52056)
            vm.pc = 52061
            vm._write(6989, cells.value(6988) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(52061)
            vm.pc = 52064
            vm.auxiliary = (0, 52023)
            tick(52064)
            vm.pc = 52070
            vm._write(6990, memory.load(cells.pointer(6985), 4, signed=True) ^ memory.load(cells.pointer(6989), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(52070)
            vm.pc = 52073
            vm.auxiliary = (0, 1919078915)
            tick(52073)
            vm.pc = 52078
            vm._write(6991, memory.load(cells.pointer(6990), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(52078)
            vm.pc = 52083
            value = memory.load(cells.pointer(6988), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6992, value >> (count & 63), 8, 'once8.logical_shift')
            tick(52083)
            vm.pc = 52088
            vm._write(6993, cells.value(6992) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(52088)
            vm.pc = 52093
            vm._write(6994, memory.load(cells.pointer(6991), 4, signed=True) ^ memory.load(cells.pointer(6993), 4, signed=True), 8, 'L14.binary_q')
            tick(52093)
            vm.pc = 52096
            vm.auxiliary = (0, 1823003139)
            tick(52096)
            vm.pc = 52101
            vm._write(6995, memory.load(cells.pointer(6994), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(52101)
            vm.pc = 52106
            vm._write(6996, cells.value(6956) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(52106)
            vm.pc = 52109
            vm.auxiliary = (0, 63519)
            tick(52109)
            vm.pc = 52115
            vm._write(6997, memory.load(cells.pointer(6995), 4, signed=True) ^ memory.load(cells.pointer(6996), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(52115)
            vm.pc = 52118
            vm.auxiliary = (0, 1372955140)
            tick(52118)
            vm.pc = 52123
            vm._write(6998, memory.load(cells.pointer(6997), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(52123)
            vm.pc = 52128
            value = memory.load(cells.pointer(6956), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6999, value >> (count & 63), 8, 'once8.logical_shift')
            tick(52128)
            vm.pc = 52133
            vm._write(7000, cells.value(6999) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(52133)
            vm.pc = 52136
            vm.auxiliary = (0, 15647)
            tick(52136)
            vm.pc = 52142
            vm._write(7001, memory.load(cells.pointer(6998), 4, signed=True) ^ memory.load(cells.pointer(7000), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(52142)
            vm.pc = 52145
            vm.auxiliary = (0, 663806467)
            tick(52145)
            vm.pc = 52150
            vm._write(7002, memory.load(cells.pointer(7001), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(52150)
            vm.pc = 52154
            value = memory.load(cells.value(6987), 1)
            vm._write(7003, value, 4, 'high.load')
            tick(52154)
            vm.pc = 52159
            _convert(vm, 4, 7003, 7004)
            tick(52159)
            vm.pc = 52164
            vm._write(7005, memory.load(cells.pointer(7002), 4, signed=True) ^ memory.load(cells.pointer(7004), 4, signed=True), 8, 'L14.binary_q')
            tick(52164)
            vm.pc = 52167
            vm.auxiliary = (0, 1416053251)
            tick(52167)
            vm.pc = 52172
            vm._write(7006, memory.load(cells.pointer(7005), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(52172)
            vm.pc = 52175
            vm.auxiliary = (0, 975364723)
            tick(52175)
            _equal(vm, 52180, 4, 6976, 7006, 7007)
            tick(52180)
            vm.pc = 52184
            vm._jump(1242 if cells.value(7007) != 0 else 1246)
            continue
        if vm.block == 1246:
            tick(52184)
            vm.pc = 52188
            pointer = cells.value(6975)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(52188)
            vm.pc = 52190
            vm._jump(1242)
            continue
        if vm.block == 1242:
            tick(52190)
            _phi(vm, 52190, (7008, 5, 857, 1240, 857, 1244, 6970, 1245, 6970, 1246, 6970, 1243))
            tick(52203)
            vm.pc = 52204
            tick(52204)
            vm.pc = 52207
            vm.auxiliary = (0, 1398941523)
            tick(52207)
            vm.pc = 52212
            vm._write(7009, int(memory.load(cells.pointer(7008), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(52212)
            vm.pc = 52216
            vm._jump(1247 if cells.value(7009) != 0 else 1248)
            continue
        if vm.block == 1248:
            tick(52216)
            _pointer(vm, 52216, 79, 7008, 7010, (145, 311))
            tick(52224)
            vm.pc = 52228
            value = memory.load(cells.value(7010), 8)
            vm._write(7011, value, 8, 'high.load')
            tick(52228)
            vm.pc = 52232
            value = memory.load(cells.value(7011), 1)
            vm._write(7012, value, 4, 'high.load')
            tick(52232)
            _pointer(vm, 52232, 1, 6947, 7013, (6948,))
            tick(52239)
            vm.pc = 52243
            pointer = cells.value(7013)
            value = memory.load(cells.pointer(7012), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52243)
            vm.pc = 52245
            vm._jump(1239)
            continue
        if vm.block == 1247:
            tick(52245)
            _pointer(vm, 52245, 1, 6947, 7014, (6948,))
            tick(52252)
            vm.pc = 52256
            pointer = cells.value(7014)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52256)
            vm.pc = 52258
            vm._jump(1239)
            continue
        if vm.block == 1239:
            tick(52258)
            vm.pc = 52259
            tick(52259)
            vm.pc = 52262
            vm.auxiliary = (0, 1008070658)
            tick(52262)
            vm.pc = 52267
            vm._write(6949, memory.load(cells.pointer(6948), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(52267)
            vm.pc = 52269
            vm._jump(1238)
            continue
        if vm.block == 1241:
            tick(52269)
            vm.pc = 52273
            value = memory.load(cells.value(63), 8)
            vm._write(7015, value, 8, 'high.load')
            tick(52273)
            vm.pc = 52278
            vm._write(7016, cells.value(7015) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(52278)
            vm.pc = 52282
            pointer = cells.value(133)
            value = memory.load(cells.pointer(7016), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(52282)
            _pointer(vm, 52282, 70, 103, 7017, (145, 7018))
            tick(52290)
            vm.pc = 52295
            cells.copy_q_clear_owned(7017, 7019)
            tick(52295)
            vm.pc = 52296
            tick(52296)
            vm.pc = 52299
            vm.auxiliary = (0, 5222)
            tick(52299)
            vm.pc = 52304
            vm._write(7020, memory.load(cells.pointer(7019), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(52304)
            _pointer(vm, 52304, 1, 6946, 7021, (163,))
            tick(52311)
            vm.pc = 52315
            value = memory.load(cells.value(6946), 1)
            vm._write(7022, value, 4, 'high.load')
            tick(52315)
            _pointer(vm, 52315, 1, 7017, 7023, (163,))
            tick(52322)
            vm.pc = 52326
            pointer = cells.value(7017)
            value = memory.load(cells.pointer(7022), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52326)
            vm.pc = 52331
            cells.copy_q_clear_owned(7023, 7024)
            tick(52331)
            vm.pc = 52334
            vm.auxiliary = (0, 57396)
            tick(52334)
            vm.pc = 52339
            vm._write(7025, memory.load(cells.pointer(7024), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(52339)
            vm.pc = 52342
            vm.auxiliary = (0, 647139620)
            tick(52342)
            vm.pc = 52347
            vm._write(7026, int(memory.load(cells.pointer(7025), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(52347)
            vm.pc = 52351
            vm._jump(1249 if cells.value(7026) != 0 else 1250)
            continue
        if vm.block == 1249:
            tick(52351)
            _pointer(vm, 52351, 1, 7021, 7027, (163,))
            tick(52358)
            vm.pc = 52362
            value = memory.load(cells.value(7021), 1)
            vm._write(7028, value, 4, 'high.load')
            tick(52362)
            _pointer(vm, 52362, 1, 7023, 7029, (163,))
            tick(52369)
            vm.pc = 52373
            pointer = cells.value(7023)
            value = memory.load(cells.pointer(7028), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52373)
            vm.pc = 52375
            vm._jump(1250)
            continue
        if vm.block == 1250:
            tick(52375)
            _phi(vm, 52375, (7030, 2, 158, 1249, 269, 1241))
            tick(52382)
            _phi(vm, 52382, (7031, 2, 7029, 1249, 7023, 1241))
            tick(52389)
            _phi(vm, 52389, (7032, 2, 7027, 1249, 7021, 1241))
            tick(52396)
            vm.pc = 52401
            cells.copy_q_clear_owned(7031, 7033)
            tick(52401)
            vm.pc = 52406
            vm._write(7034, memory.load(cells.pointer(7033), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(52406)
            vm.pc = 52407
            tick(52407)
            vm.pc = 52410
            vm.auxiliary = (0, 1538405028)
            tick(52410)
            vm.pc = 52415
            vm._write(7035, int(memory.load(cells.pointer(7034), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(52415)
            vm.pc = 52418
            vm.auxiliary = (0, 439539510)
            tick(52418)
            vm.pc = 52423
            vm._write(7036, int(memory.load(cells.pointer(7030), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(52423)
            vm.pc = 52426
            vm.auxiliary = (0, 50533)
            tick(52426)
            vm.pc = 52431
            vm._write(7037, memory.load(cells.pointer(7035), 1, signed=True) & memory.load(cells.pointer(7036), 1, signed=True), 8, 'typed.selector1.q')
            tick(52431)
            vm.pc = 52435
            vm._jump(1251 if cells.value(7037) != 0 else 1252)
            continue
        if vm.block == 1251:
            tick(52435)
            _pointer(vm, 52435, 1, 7032, 7038, (163,))
            tick(52442)
            vm.pc = 52446
            value = memory.load(cells.value(7032), 1)
            vm._write(7039, value, 4, 'high.load')
            tick(52446)
            _pointer(vm, 52446, 1, 7031, 7040, (163,))
            tick(52453)
            vm.pc = 52457
            pointer = cells.value(7031)
            value = memory.load(cells.pointer(7039), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52457)
            vm.pc = 52458
            tick(52458)
            vm.pc = 52461
            vm.auxiliary = (0, 863232001)
            tick(52461)
            vm.pc = 52466
            vm._write(7041, memory.load(cells.pointer(7030), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(52466)
            vm.pc = 52468
            vm._jump(1252)
            continue
        if vm.block == 1252:
            tick(52468)
            _phi(vm, 52468, (7042, 2, 7041, 1251, 7030, 1250))
            tick(52475)
            _phi(vm, 52475, (7043, 2, 7040, 1251, 7031, 1250))
            tick(52482)
            _phi(vm, 52482, (7044, 2, 7038, 1251, 7032, 1250))
            tick(52489)
            vm.pc = 52494
            cells.copy_q_clear_owned(7043, 7045)
            tick(52494)
            vm.pc = 52499
            cells.copy_q_clear_owned(7044, 7046)
            tick(52499)
            vm.pc = 52500
            tick(52500)
            vm.pc = 52503
            vm.auxiliary = (0, 171104022)
            tick(52503)
            vm.pc = 52508
            vm._write(7047, int(memory.load(cells.pointer(7042), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(52508)
            vm.pc = 52512
            vm._jump(1253 if cells.value(7047) != 0 else 1254)
            continue
        if vm.block == 1253:
            tick(52512)
            _pointer(vm, 52512, 1, 7044, 7048, (172,))
            tick(52519)
            vm.pc = 52524
            cells.copy_q_clear_owned(7048, 7049)
            tick(52524)
            vm.pc = 52528
            value = memory.load(cells.value(7046), 4)
            vm._write(7050, value, 4, 'high.load')
            tick(52528)
            _pointer(vm, 52528, 1, 7043, 7051, (172,))
            tick(52535)
            vm.pc = 52540
            cells.copy_q_clear_owned(7051, 7052)
            tick(52540)
            vm.pc = 52544
            pointer = cells.value(7045)
            value = memory.load(cells.pointer(7050), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(52544)
            vm.pc = 52545
            tick(52545)
            vm.pc = 52548
            vm.auxiliary = (0, 1818001409)
            tick(52548)
            vm.pc = 52553
            vm._write(7053, memory.load(cells.pointer(7042), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(52553)
            vm.pc = 52555
            vm._jump(1254)
            continue
        if vm.block == 1254:
            tick(52555)
            _phi(vm, 52555, (7054, 2, 7053, 1253, 7042, 1252))
            tick(52562)
            _phi(vm, 52562, (7055, 2, 7052, 1253, 7045, 1252))
            tick(52569)
            _phi(vm, 52569, (7056, 2, 7049, 1253, 7046, 1252))
            tick(52576)
            vm.pc = 52577
            tick(52577)
            vm.pc = 52580
            vm.auxiliary = (0, 1404193158)
            tick(52580)
            vm.pc = 52585
            vm._write(7057, int(memory.load(cells.pointer(7054), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(52585)
            vm.pc = 52589
            vm._jump(1255 if cells.value(7057) != 0 else 1256)
            continue
        if vm.block == 1255:
            tick(52589)
            _pointer(vm, 52589, 3, 7056, 7058, (163,))
            tick(52596)
            vm.pc = 52600
            value = memory.load(cells.value(7056), 4)
            vm._write(7059, value, 4, 'high.load')
            tick(52600)
            _pointer(vm, 52600, 3, 7055, 7060, (163,))
            tick(52607)
            vm.pc = 52611
            pointer = cells.value(7055)
            value = memory.load(cells.pointer(7059), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(52611)
            vm.pc = 52612
            tick(52612)
            vm.pc = 52615
            vm.auxiliary = (0, 1611870209)
            tick(52615)
            vm.pc = 52620
            vm._write(7061, memory.load(cells.pointer(7054), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(52620)
            vm.pc = 52622
            vm._jump(1256)
            continue
        if vm.block == 1256:
            tick(52622)
            _phi(vm, 52622, (7062, 2, 7061, 1255, 7054, 1254))
            tick(52629)
            _phi(vm, 52629, (7063, 2, 7060, 1255, 7055, 1254))
            tick(52636)
            _phi(vm, 52636, (7064, 2, 7058, 1255, 7056, 1254))
            tick(52643)
            vm.pc = 52644
            tick(52644)
            vm.pc = 52647
            vm.auxiliary = (0, 1537405414)
            tick(52647)
            vm.pc = 52652
            vm._write(7065, int(memory.load(cells.pointer(7062), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(52652)
            vm.pc = 52656
            vm._jump(1257 if cells.value(7065) != 0 else 1258)
            continue
        if vm.block == 1257:
            tick(52656)
            _pointer(vm, 52656, 3, 7064, 7066, (163,))
            tick(52663)
            vm.pc = 52667
            value = memory.load(cells.value(7064), 4)
            vm._write(7067, value, 4, 'high.load')
            tick(52667)
            _pointer(vm, 52667, 3, 7063, 7068, (163,))
            tick(52674)
            vm.pc = 52678
            pointer = cells.value(7063)
            value = memory.load(cells.pointer(7067), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(52678)
            vm.pc = 52679
            tick(52679)
            vm.pc = 52682
            vm.auxiliary = (0, 464855042)
            tick(52682)
            vm.pc = 52687
            vm._write(7069, memory.load(cells.pointer(7062), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(52687)
            vm.pc = 52689
            vm._jump(1258)
            continue
        if vm.block == 1258:
            tick(52689)
            _phi(vm, 52689, (7070, 2, 7069, 1257, 7062, 1256))
            tick(52696)
            _phi(vm, 52696, (7071, 2, 7068, 1257, 7063, 1256))
            tick(52703)
            _phi(vm, 52703, (7072, 2, 7066, 1257, 7064, 1256))
            tick(52710)
            vm.pc = 52715
            cells.copy_q_clear_owned(7071, 7073)
            tick(52715)
            vm.pc = 52720
            cells.copy_q_clear_owned(7072, 7074)
            tick(52720)
            vm.pc = 52721
            tick(52721)
            vm.pc = 52724
            vm.auxiliary = (0, 1509066134)
            tick(52724)
            vm.pc = 52729
            vm._write(7075, int(memory.load(cells.pointer(7070), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(52729)
            vm.pc = 52733
            vm._jump(1259 if cells.value(7075) != 0 else 1260)
            continue
        if vm.block == 1259:
            tick(52733)
            _pointer(vm, 52733, 1, 7074, 7076, (163,))
            tick(52740)
            vm.pc = 52744
            value = memory.load(cells.value(7074), 1)
            vm._write(7077, value, 4, 'high.load')
            tick(52744)
            _pointer(vm, 52744, 1, 7073, 7078, (163,))
            tick(52751)
            vm.pc = 52755
            pointer = cells.value(7073)
            value = memory.load(cells.pointer(7077), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52755)
            vm.pc = 52756
            tick(52756)
            vm.pc = 52759
            vm.auxiliary = (0, 916750337)
            tick(52759)
            vm.pc = 52764
            vm._write(7079, memory.load(cells.pointer(7070), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(52764)
            vm.pc = 52766
            vm._jump(1260)
            continue
        if vm.block == 1260:
            tick(52766)
            _phi(vm, 52766, (7080, 2, 7079, 1259, 7070, 1258))
            tick(52773)
            _phi(vm, 52773, (7081, 2, 7078, 1259, 7073, 1258))
            tick(52780)
            _phi(vm, 52780, (7082, 2, 7076, 1259, 7074, 1258))
            tick(52787)
            vm.pc = 52788
            tick(52788)
            vm.pc = 52791
            vm.auxiliary = (0, 1909635590)
            tick(52791)
            vm.pc = 52796
            vm._write(7083, int(memory.load(cells.pointer(7080), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(52796)
            vm.pc = 52800
            vm._jump(1261 if cells.value(7083) != 0 else 1262)
            continue
        if vm.block == 1261:
            tick(52800)
            _pointer(vm, 52800, 1, 7082, 7084, (163,))
            tick(52807)
            vm.pc = 52811
            value = memory.load(cells.value(7082), 1)
            vm._write(7085, value, 4, 'high.load')
            tick(52811)
            _pointer(vm, 52811, 1, 7081, 7086, (163,))
            tick(52818)
            vm.pc = 52822
            pointer = cells.value(7081)
            value = memory.load(cells.pointer(7085), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52822)
            vm.pc = 52823
            tick(52823)
            vm.pc = 52826
            vm.auxiliary = (0, 1826926593)
            tick(52826)
            vm.pc = 52831
            vm._write(7087, memory.load(cells.pointer(7080), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(52831)
            vm.pc = 52833
            vm._jump(1262)
            continue
        if vm.block == 1262:
            tick(52833)
            _phi(vm, 52833, (7088, 2, 7087, 1261, 7080, 1260))
            tick(52840)
            _phi(vm, 52840, (7089, 2, 7086, 1261, 7081, 1260))
            tick(52847)
            _phi(vm, 52847, (7090, 2, 7084, 1261, 7082, 1260))
            tick(52854)
            vm.pc = 52855
            tick(52855)
            vm.pc = 52858
            vm.auxiliary = (0, 1228077190)
            tick(52858)
            vm.pc = 52863
            vm._write(7091, int(memory.load(cells.pointer(7088), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(52863)
            vm.pc = 52867
            vm._jump(1263 if cells.value(7091) != 0 else 1264)
            continue
        if vm.block == 1263:
            tick(52867)
            _pointer(vm, 52867, 1, 7090, 7092, (163,))
            tick(52874)
            vm.pc = 52878
            value = memory.load(cells.value(7090), 1)
            vm._write(7093, value, 4, 'high.load')
            tick(52878)
            _pointer(vm, 52878, 1, 7089, 7094, (163,))
            tick(52885)
            vm.pc = 52889
            pointer = cells.value(7089)
            value = memory.load(cells.pointer(7093), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52889)
            vm.pc = 52891
            vm._jump(1264)
            continue
        if vm.block == 1264:
            tick(52891)
            _phi(vm, 52891, (7095, 2, 7094, 1263, 7089, 1262))
            tick(52898)
            _phi(vm, 52898, (7096, 2, 7092, 1263, 7090, 1262))
            tick(52905)
            vm.pc = 52906
            tick(52906)
            vm.pc = 52909
            vm.auxiliary = (0, 1900177046)
            tick(52909)
            vm.pc = 52914
            vm._write(7097, int(memory.load(cells.pointer(7088), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(52914)
            vm.pc = 52918
            vm._jump(1265 if cells.value(7097) != 0 else 1266)
            continue
        if vm.block == 1265:
            tick(52918)
            vm.pc = 52922
            value = memory.load(cells.value(7096), 1)
            vm._write(7098, value, 4, 'high.load')
            tick(52922)
            vm.pc = 52926
            pointer = cells.value(7095)
            value = memory.load(cells.pointer(7098), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(52926)
            vm.pc = 52928
            vm._jump(1266)
            continue
        if vm.block == 1266:
            tick(52928)
            _pointer(vm, 52928, 70, 103, 7099, (145, 7100))
            tick(52936)
            vm.pc = 52941
            cells.copy_q_clear_owned(7099, 7101)
            tick(52941)
            vm.pc = 52942
            tick(52942)
            vm.pc = 52945
            vm.auxiliary = (0, 37741)
            tick(52945)
            vm.pc = 52950
            vm._write(7102, memory.load(cells.pointer(7101), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(52950)
            _pointer(vm, 52950, 1, 1199, 7103, (163,))
            tick(52957)
            vm.pc = 52961
            value = memory.load(cells.value(1199), 1)
            vm._write(7104, value, 4, 'high.load')
            tick(52961)
            _pointer(vm, 52961, 1, 7099, 7105, (163,))
            tick(52968)
            vm.pc = 52972
            pointer = cells.value(7099)
            value = memory.load(cells.pointer(7104), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(52972)
            vm.pc = 52977
            cells.copy_q_clear_owned(7105, 7106)
            tick(52977)
            vm.pc = 52980
            vm.auxiliary = (0, 21006)
            tick(52980)
            vm.pc = 52985
            vm._write(7107, memory.load(cells.pointer(7106), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(52985)
            vm.pc = 52988
            vm.auxiliary = (0, 1054009444)
            tick(52988)
            vm.pc = 52993
            vm._write(7108, int(memory.load(cells.pointer(7107), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(52993)
            vm.pc = 52997
            vm._jump(1267 if cells.value(7108) != 0 else 1268)
            continue
        if vm.block == 1267:
            tick(52997)
            _pointer(vm, 52997, 1, 7103, 7109, (163,))
            tick(53004)
            vm.pc = 53008
            value = memory.load(cells.value(7103), 1)
            vm._write(7110, value, 4, 'high.load')
            tick(53008)
            _pointer(vm, 53008, 1, 7105, 7111, (163,))
            tick(53015)
            vm.pc = 53019
            pointer = cells.value(7105)
            value = memory.load(cells.pointer(7110), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(53019)
            vm.pc = 53021
            vm._jump(1268)
            continue
        if vm.block == 1268:
            tick(53021)
            _phi(vm, 53021, (7112, 2, 311, 1267, 149, 1266))
            tick(53028)
            _phi(vm, 53028, (7113, 2, 7111, 1267, 7105, 1266))
            tick(53035)
            _phi(vm, 53035, (7114, 2, 7109, 1267, 7103, 1266))
            tick(53042)
            vm.pc = 53047
            cells.copy_q_clear_owned(7113, 7115)
            tick(53047)
            vm.pc = 53052
            vm._write(7116, memory.load(cells.pointer(7115), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(53052)
            vm.pc = 53053
            tick(53053)
            vm.pc = 53056
            vm.auxiliary = (0, 1002629588)
            tick(53056)
            vm.pc = 53061
            vm._write(7117, int(memory.load(cells.pointer(7116), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(53061)
            vm.pc = 53064
            vm.auxiliary = (0, 487781190)
            tick(53064)
            vm.pc = 53069
            vm._write(7118, int(memory.load(cells.pointer(7112), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(53069)
            vm.pc = 53074
            vm._write(7119, memory.load(cells.pointer(7117), 1, signed=True) & memory.load(cells.pointer(7118), 1, signed=True), 8, 'L13.binary_q')
            tick(53074)
            vm.pc = 53078
            vm._jump(1269 if cells.value(7119) != 0 else 1270)
            continue
        if vm.block == 1269:
            tick(53078)
            _pointer(vm, 53078, 1, 7114, 7120, (163,))
            tick(53085)
            vm.pc = 53089
            value = memory.load(cells.value(7114), 1)
            vm._write(7121, value, 4, 'high.load')
            tick(53089)
            _pointer(vm, 53089, 1, 7113, 7122, (163,))
            tick(53096)
            vm.pc = 53100
            pointer = cells.value(7113)
            value = memory.load(cells.pointer(7121), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(53100)
            vm.pc = 53101
            tick(53101)
            vm.pc = 53104
            vm.auxiliary = (0, 768278529)
            tick(53104)
            vm.pc = 53109
            vm._write(7123, memory.load(cells.pointer(7112), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(53109)
            vm.pc = 53111
            vm._jump(1270)
            continue
        if vm.block == 1270:
            tick(53111)
            _phi(vm, 53111, (7124, 2, 7123, 1269, 7112, 1268))
            tick(53118)
            _phi(vm, 53118, (7125, 2, 7122, 1269, 7113, 1268))
            tick(53125)
            _phi(vm, 53125, (7126, 2, 7120, 1269, 7114, 1268))
            tick(53132)
            vm.pc = 53137
            cells.copy_q_clear_owned(7125, 7127)
            tick(53137)
            vm.pc = 53142
            cells.copy_q_clear_owned(7126, 7128)
            tick(53142)
            vm.pc = 53143
            tick(53143)
            vm.pc = 53146
            vm.auxiliary = (0, 1355946534)
            tick(53146)
            vm.pc = 53151
            vm._write(7129, int(memory.load(cells.pointer(7124), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(53151)
            vm.pc = 53155
            vm._jump(1271 if cells.value(7129) != 0 else 1272)
            continue
        if vm.block == 1271:
            tick(53155)
            _pointer(vm, 53155, 1, 7126, 7130, (172,))
            tick(53162)
            vm.pc = 53167
            cells.copy_q_clear_owned(7130, 7131)
            tick(53167)
            vm.pc = 53171
            value = memory.load(cells.value(7128), 4)
            vm._write(7132, value, 4, 'L5.unsigned_load')
            tick(53171)
            _pointer(vm, 53171, 1, 7125, 7133, (172,))
            tick(53178)
            vm.pc = 53183
            cells.copy_q_clear_owned(7133, 7134)
            tick(53183)
            vm.pc = 53187
            pointer = cells.value(7127)
            value = memory.load(cells.pointer(7132), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(53187)
            vm.pc = 53188
            tick(53188)
            vm.pc = 53191
            vm.auxiliary = (0, 766480385)
            tick(53191)
            vm.pc = 53196
            vm._write(7135, memory.load(cells.pointer(7124), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(53196)
            vm.pc = 53198
            vm._jump(1272)
            continue
        if vm.block == 1272:
            tick(53198)
            _phi(vm, 53198, (7136, 2, 7135, 1271, 7124, 1270))
            tick(53205)
            _phi(vm, 53205, (7137, 2, 7134, 1271, 7127, 1270))
            tick(53212)
            _phi(vm, 53212, (7138, 2, 7131, 1271, 7128, 1270))
            tick(53219)
            vm.pc = 53220
            tick(53220)
            vm.pc = 53223
            vm.auxiliary = (0, 1942131686)
            tick(53223)
            vm.pc = 53228
            vm._write(7139, int(memory.load(cells.pointer(7136), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(53228)
            vm.pc = 53232
            vm._jump(1273 if cells.value(7139) != 0 else 1274)
            continue
        if vm.block == 1273:
            tick(53232)
            _pointer(vm, 53232, 3, 7138, 7140, (163,))
            tick(53239)
            vm.pc = 53243
            value = memory.load(cells.value(7138), 4)
            vm._write(7141, value, 4, 'high.load')
            tick(53243)
            _pointer(vm, 53243, 3, 7137, 7142, (163,))
            tick(53250)
            vm.pc = 53254
            pointer = cells.value(7137)
            value = memory.load(cells.pointer(7141), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(53254)
            vm.pc = 53255
            tick(53255)
            vm.pc = 53258
            vm.auxiliary = (0, 1213505537)
            tick(53258)
            vm.pc = 53263
            vm._write(7143, memory.load(cells.pointer(7136), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(53263)
            vm.pc = 53265
            vm._jump(1274)
            continue
        if vm.block == 1274:
            tick(53265)
            _phi(vm, 53265, (7144, 2, 7143, 1273, 7136, 1272))
            tick(53272)
            _phi(vm, 53272, (7145, 2, 7142, 1273, 7137, 1272))
            tick(53279)
            _phi(vm, 53279, (7146, 2, 7140, 1273, 7138, 1272))
            tick(53286)
            vm.pc = 53287
            tick(53287)
            vm.pc = 53290
            vm.auxiliary = (0, 1490206598)
            tick(53290)
            vm.pc = 53295
            vm._write(7147, int(memory.load(cells.pointer(7144), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(53295)
            vm.pc = 53299
            vm._jump(1275 if cells.value(7147) != 0 else 1276)
            continue
        if vm.block == 1275:
            tick(53299)
            _pointer(vm, 53299, 3, 7146, 7148, (163,))
            tick(53306)
            vm.pc = 53310
            value = memory.load(cells.value(7146), 4)
            vm._write(7149, value, 4, 'high.load')
            tick(53310)
            _pointer(vm, 53310, 3, 7145, 7150, (163,))
            tick(53317)
            vm.pc = 53321
            pointer = cells.value(7145)
            value = memory.load(cells.pointer(7149), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(53321)
            vm.pc = 53322
            tick(53322)
            vm.pc = 53325
            vm.auxiliary = (0, 569761794)
            tick(53325)
            vm.pc = 53330
            vm._write(7151, memory.load(cells.pointer(7144), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(53330)
            vm.pc = 53332
            vm._jump(1276)
            continue
        if vm.block == 1276:
            tick(53332)
            _phi(vm, 53332, (7152, 2, 7151, 1275, 7144, 1274))
            tick(53339)
            _phi(vm, 53339, (7153, 2, 7150, 1275, 7145, 1274))
            tick(53346)
            _phi(vm, 53346, (7154, 2, 7148, 1275, 7146, 1274))
            tick(53353)
            vm.pc = 53358
            cells.copy_q_clear_owned(7153, 7155)
            tick(53358)
            vm.pc = 53363
            cells.copy_q_clear_owned(7154, 7156)
            tick(53363)
            vm.pc = 53364
            tick(53364)
            vm.pc = 53367
            vm.auxiliary = (0, 746760902)
            tick(53367)
            vm.pc = 53372
            vm._write(7157, int(memory.load(cells.pointer(7152), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(53372)
            vm.pc = 53376
            vm._jump(1277 if cells.value(7157) != 0 else 1278)
            continue
        if vm.block == 1277:
            tick(53376)
            _pointer(vm, 53376, 1, 7156, 7158, (163,))
            tick(53383)
            vm.pc = 53387
            value = memory.load(cells.value(7156), 1)
            vm._write(7159, value, 4, 'high.load')
            tick(53387)
            _pointer(vm, 53387, 1, 7155, 7160, (163,))
            tick(53394)
            vm.pc = 53398
            pointer = cells.value(7155)
            value = memory.load(cells.pointer(7159), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(53398)
            vm.pc = 53399
            tick(53399)
            vm.pc = 53402
            vm.auxiliary = (0, 968597505)
            tick(53402)
            vm.pc = 53407
            vm._write(7161, memory.load(cells.pointer(7152), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(53407)
            vm.pc = 53409
            vm._jump(1278)
            continue
        if vm.block == 1278:
            tick(53409)
            _phi(vm, 53409, (7162, 2, 7161, 1277, 7152, 1276))
            tick(53416)
            _phi(vm, 53416, (7163, 2, 7160, 1277, 7155, 1276))
            tick(53423)
            _phi(vm, 53423, (7164, 2, 7158, 1277, 7156, 1276))
            tick(53430)
            vm.pc = 53431
            tick(53431)
            vm.pc = 53434
            vm.auxiliary = (0, 1759659910)
            tick(53434)
            vm.pc = 53439
            vm._write(7165, int(memory.load(cells.pointer(7162), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(53439)
            vm.pc = 53443
            vm._jump(1279 if cells.value(7165) != 0 else 1280)
            continue
        if vm.block == 1279:
            tick(53443)
            _pointer(vm, 53443, 1, 7164, 7166, (163,))
            tick(53450)
            vm.pc = 53454
            value = memory.load(cells.value(7164), 1)
            vm._write(7167, value, 4, 'high.load')
            tick(53454)
            _pointer(vm, 53454, 1, 7163, 7168, (163,))
            tick(53461)
            vm.pc = 53465
            pointer = cells.value(7163)
            value = memory.load(cells.pointer(7167), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(53465)
            vm.pc = 53466
            tick(53466)
            vm.pc = 53469
            vm.auxiliary = (0, 2077736962)
            tick(53469)
            vm.pc = 53474
            vm._write(7169, memory.load(cells.pointer(7162), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(53474)
            vm.pc = 53476
            vm._jump(1280)
            continue
        if vm.block == 1280:
            tick(53476)
            _phi(vm, 53476, (7170, 2, 7169, 1279, 7162, 1278))
            tick(53483)
            _phi(vm, 53483, (7171, 2, 7168, 1279, 7163, 1278))
            tick(53490)
            _phi(vm, 53490, (7172, 2, 7166, 1279, 7164, 1278))
            tick(53497)
            vm.pc = 53498
            tick(53498)
            vm.pc = 53501
            vm.auxiliary = (0, 1707269462)
            tick(53501)
            vm.pc = 53506
            vm._write(7173, int(memory.load(cells.pointer(7170), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(53506)
            vm.pc = 53510
            vm._jump(1281 if cells.value(7173) != 0 else 1282)
            continue
        if vm.block == 1281:
            tick(53510)
            _pointer(vm, 53510, 1, 7172, 7174, (163,))
            tick(53517)
            vm.pc = 53521
            value = memory.load(cells.value(7172), 1)
            vm._write(7175, value, 4, 'high.load')
            tick(53521)
            _pointer(vm, 53521, 1, 7171, 7176, (163,))
            tick(53528)
            vm.pc = 53532
            pointer = cells.value(7171)
            value = memory.load(cells.pointer(7175), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(53532)
            vm.pc = 53534
            vm._jump(1282)
            continue
        if vm.block == 1282:
            tick(53534)
            _phi(vm, 53534, (7177, 2, 7176, 1281, 7171, 1280))
            tick(53541)
            _phi(vm, 53541, (7178, 2, 7174, 1281, 7172, 1280))
            tick(53548)
            vm.pc = 53549
            tick(53549)
            vm.pc = 53552
            vm.auxiliary = (0, 1559374118)
            tick(53552)
            vm.pc = 53557
            vm._write(7179, int(memory.load(cells.pointer(7170), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(53557)
            vm.pc = 53561
            vm._jump(1283 if cells.value(7179) != 0 else 1284)
            continue
        if vm.block == 1283:
            tick(53561)
            vm.pc = 53565
            value = memory.load(cells.value(7178), 1)
            vm._write(7180, value, 4, 'high.load')
            tick(53565)
            vm.pc = 53569
            pointer = cells.value(7177)
            value = memory.load(cells.pointer(7180), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(53569)
            vm.pc = 53571
            vm._jump(1284)
            continue
        if vm.block == 1284:
            tick(53571)
            vm.pc = 53576
            cells.copy_q_clear_owned(134, 7181)
            tick(53576)
            vm.pc = 53581
            cells.copy_q_clear_owned(64, 7182)
            tick(53581)
            vm.pc = 53585
            pointer = cells.value(64)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(53585)
            vm.pc = 53587
            vm._jump(1285)
            continue
        if vm.block == 1285:
            tick(53587)
            _phi(vm, 53587, (7183, 2, 145, 1284, 7184, 1286))
            tick(53594)
            vm.pc = 53599
            vm._write(7185, int(cells.value(7183) < cells.value(166)), 4, 'once18.unsigned_q')
            tick(53599)
            vm.pc = 53603
            vm._jump(1287 if cells.value(7185) != 0 else 1288)
            continue
        if vm.block == 1287:
            tick(53603)
            vm.pc = 53608
            vm._write(7186, cells.value(7183) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(53608)
            vm.pc = 53609
            tick(53609)
            vm.pc = 53612
            vm.auxiliary = (0, 460447745)
            tick(53612)
            vm.pc = 53617
            vm._write(7188, memory.load(cells.pointer(7186), 2, signed=True) + memory.load(cells.pointer(7187), 2, signed=True), 8, 'once1.integer')
            tick(53617)
            vm.pc = 53622
            value = memory.load(cells.pointer(7188), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(7189, value >> (count & 31), 4, 'once8.logical_shift')
            tick(53622)
            _pointer(vm, 53622, 91, 112, 7190, (145, 391))
            tick(53630)
            vm.pc = 53634
            value = memory.load(cells.value(7190), 8)
            vm._write(7191, value, 8, 'high.load')
            tick(53634)
            vm.pc = 53639
            vm._write(7192, cells.value(7191) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(53639)
            vm.pc = 53642
            vm.auxiliary = (0, 17748)
            tick(53642)
            vm.pc = 53647
            vm._write(7193, memory.load(cells.pointer(7192), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(53647)
            vm.pc = 53650
            vm.auxiliary = (0, 15366)
            tick(53650)
            vm.pc = 53656
            vm._write(7194, memory.load(cells.pointer(7189), 2, signed=True) ^ memory.load(cells.pointer(7193), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(53656)
            vm.pc = 53661
            _convert(vm, 8, 7194, 7195)
            tick(53661)
            _pointer(vm, 53661, 91, 112, 7196, (145, 311, 7195))
            tick(53670)
            vm.pc = 53674
            value = memory.load(cells.value(7196), 8)
            vm._write(7197, value, 8, 'high.load')
            tick(53674)
            vm.pc = 53677
            vm.auxiliary = (0, 376628035)
            tick(53677)
            vm.pc = 53682
            vm._write(7198, int(memory.load(cells.pointer(7197), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(53682)
            vm.pc = 53686
            vm._jump(1289 if cells.value(7198) != 0 else 1290)
            continue
        if vm.block == 1290:
            tick(53686)
            vm.pc = 53691
            value = memory.load(cells.pointer(7191), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(7199, value >> (count & 63), 8, 'once8.logical_shift')
            tick(53691)
            vm.pc = 53696
            vm._write(7200, cells.value(7199) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(53696)
            vm.pc = 53697
            tick(53697)
            vm.pc = 53700
            vm.auxiliary = (0, 27164)
            tick(53700)
            vm.pc = 53706
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(7201, memory.load(cells.pointer(7200), 2, signed=True) ^ memory.load(cells.pointer(7188), 2, signed=True), 8, 'typed.selector5.q')
            tick(53706)
            vm.pc = 53711
            vm._write(7202, memory.load(cells.pointer(7201), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(53711)
            vm.pc = 53716
            _convert(vm, 8, 7202, 7203)
            tick(53716)
            _pointer(vm, 53716, 78, 7197, 7204, (7203,))
            tick(53723)
            vm.pc = 53727
            value = memory.load(cells.value(7204), 8)
            vm._write(7205, value, 8, 'high.load')
            tick(53727)
            vm.pc = 53730
            vm.auxiliary = (0, 2113061587)
            tick(53730)
            vm.pc = 53735
            vm._write(7206, int(memory.load(cells.pointer(7205), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(53735)
            vm.pc = 53739
            vm._jump(1289 if cells.value(7206) != 0 else 1291)
            continue
        if vm.block == 1291:
            tick(53739)
            _pointer(vm, 53739, 79, 7205, 7207, (145, 269))
            tick(53747)
            vm.pc = 53751
            value = memory.load(cells.value(7207), 2)
            vm._write(7208, value, 4, 'high.load')
            tick(53751)
            vm.pc = 53752
            tick(53752)
            vm.pc = 53755
            vm.auxiliary = (0, 673365075)
            tick(53755)
            vm.pc = 53760
            vm._write(7209, int(memory.load(cells.pointer(7208), 2, signed=True) == memory.load(cells.pointer(7188), 2, signed=True)), 4, 'once17.integer')
            tick(53760)
            vm.pc = 53764
            vm._jump(1292 if cells.value(7209) != 0 else 1289)
            continue
        if vm.block == 1292:
            tick(53764)
            _pointer(vm, 53764, 79, 7205, 7210, (145, 360))
            tick(53772)
            vm.pc = 53776
            value = memory.load(cells.value(7210), 4)
            vm._write(7211, value, 4, 'high.load')
            tick(53776)
            _pointer(vm, 53776, 79, 7205, 7212, (145, 158))
            tick(53784)
            vm.pc = 53788
            value = memory.load(cells.value(7212), 4)
            vm._write(7213, value, 4, 'high.load')
            tick(53788)
            vm.pc = 53793
            vm._write(7214, memory.load(cells.pointer(7213), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'L14.binary_q')
            tick(53793)
            vm.pc = 53794
            tick(53794)
            vm.pc = 53797
            vm.auxiliary = (0, 360657412)
            tick(53797)
            vm.pc = 53802
            vm._write(7215, memory.load(cells.pointer(7214), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(53802)
            _pointer(vm, 53802, 79, 7205, 7216, (145, 269))
            tick(53810)
            vm.pc = 53814
            value = memory.load(cells.value(7216), 2)
            vm._write(7217, value, 4, 'high.load')
            tick(53814)
            vm.pc = 53819
            _convert(vm, 4, 7217, 7218)
            tick(53819)
            vm.pc = 53822
            vm.auxiliary = (0, 56413)
            tick(53822)
            vm.pc = 53828
            vm._write(7219, memory.load(cells.pointer(7215), 4, signed=True) ^ memory.load(cells.pointer(7218), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(53828)
            vm.pc = 53831
            vm.auxiliary = (0, 454189571)
            tick(53831)
            vm.pc = 53836
            vm._write(7220, memory.load(cells.pointer(7219), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(53836)
            _pointer(vm, 53836, 79, 7205, 7221, (145, 311))
            tick(53844)
            vm.pc = 53848
            value = memory.load(cells.value(7221), 8)
            vm._write(7222, value, 8, 'high.load')
            tick(53848)
            vm.pc = 53853
            cells.copy_q_clear_owned(7222, 7223)
            tick(53853)
            vm.pc = 53858
            vm._write(7224, cells.value(7223) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(53858)
            vm.pc = 53861
            vm.auxiliary = (0, 18716)
            tick(53861)
            vm.pc = 53867
            vm._write(7225, memory.load(cells.pointer(7220), 4, signed=True) ^ memory.load(cells.pointer(7224), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(53867)
            vm.pc = 53870
            vm.auxiliary = (0, 1621971459)
            tick(53870)
            vm.pc = 53875
            vm._write(7226, memory.load(cells.pointer(7225), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(53875)
            vm.pc = 53880
            value = memory.load(cells.pointer(7223), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(7227, value >> (count & 63), 8, 'once8.logical_shift')
            tick(53880)
            vm.pc = 53885
            vm._write(7228, cells.value(7227) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(53885)
            vm.pc = 53890
            vm._write(7229, memory.load(cells.pointer(7226), 4, signed=True) ^ memory.load(cells.pointer(7228), 4, signed=True), 8, 'L14.binary_q')
            tick(53890)
            vm.pc = 53893
            vm.auxiliary = (0, 1816199684)
            tick(53893)
            vm.pc = 53898
            vm._write(7230, memory.load(cells.pointer(7229), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(53898)
            vm.pc = 53903
            vm._write(7231, cells.value(7191) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(53903)
            vm.pc = 53906
            vm.auxiliary = (0, 32343)
            tick(53906)
            vm.pc = 53912
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(7232, memory.load(cells.pointer(7230), 4, signed=True) ^ memory.load(cells.pointer(7231), 4, signed=True), 8, 'typed.selector5.q')
            tick(53912)
            vm.pc = 53915
            vm.auxiliary = (0, 1723363844)
            tick(53915)
            vm.pc = 53920
            vm._write(7233, memory.load(cells.pointer(7232), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(53920)
            vm.pc = 53925
            value = memory.load(cells.pointer(7191), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(7234, value >> (count & 63), 8, 'once8.logical_shift')
            tick(53925)
            vm.pc = 53930
            vm._write(7235, cells.value(7234) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(53930)
            vm.pc = 53933
            vm.auxiliary = (0, 14431)
            tick(53933)
            vm.pc = 53939
            vm._write(7236, memory.load(cells.pointer(7233), 4, signed=True) ^ memory.load(cells.pointer(7235), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(53939)
            vm.pc = 53942
            vm.auxiliary = (0, 1258336771)
            tick(53942)
            vm.pc = 53947
            vm._write(7237, memory.load(cells.pointer(7236), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(53947)
            vm.pc = 53951
            value = memory.load(cells.value(7222), 1)
            vm._write(7238, value, 4, 'L5.unsigned_load')
            tick(53951)
            vm.pc = 53956
            _convert(vm, 4, 7238, 7239)
            tick(53956)
            vm.pc = 53959
            vm.auxiliary = (0, 11572)
            tick(53959)
            vm.pc = 53965
            vm._write(7240, memory.load(cells.pointer(7237), 4, signed=True) ^ memory.load(cells.pointer(7239), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(53965)
            vm.pc = 53968
            vm.auxiliary = (0, 708071940)
            tick(53968)
            vm.pc = 53973
            vm._write(7241, memory.load(cells.pointer(7240), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(53973)
            vm.pc = 53976
            vm.auxiliary = (0, 1496450243)
            tick(53976)
            vm.pc = 53981
            vm._write(7242, int(memory.load(cells.pointer(7211), 4, signed=True) == memory.load(cells.pointer(7241), 4, signed=True)), 4, 'once17.integer')
            tick(53981)
            vm.pc = 53985
            vm._jump(1289 if cells.value(7242) != 0 else 1293)
            continue
        if vm.block == 1293:
            tick(53985)
            vm.pc = 53989
            pointer = cells.value(7210)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(53989)
            vm.pc = 53991
            vm._jump(1289)
            continue
        if vm.block == 1289:
            tick(53991)
            _phi(vm, 53991, (7243, 5, 857, 1287, 857, 1291, 7205, 1292, 7205, 1293, 7205, 1290))
            tick(54004)
            vm.pc = 54005
            tick(54005)
            vm.pc = 54008
            vm.auxiliary = (0, 1828851075)
            tick(54008)
            vm.pc = 54013
            vm._write(7244, int(memory.load(cells.pointer(7243), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(54013)
            vm.pc = 54017
            vm._jump(1294 if cells.value(7244) != 0 else 1295)
            continue
        if vm.block == 1295:
            tick(54017)
            _pointer(vm, 54017, 79, 7243, 7245, (145, 311))
            tick(54025)
            vm.pc = 54029
            value = memory.load(cells.value(7245), 8)
            vm._write(7246, value, 8, 'high.load')
            tick(54029)
            vm.pc = 54033
            value = memory.load(cells.value(7246), 1)
            vm._write(7247, value, 4, 'high.load')
            tick(54033)
            _pointer(vm, 54033, 1, 7182, 7248, (7183,))
            tick(54040)
            vm.pc = 54044
            pointer = cells.value(7248)
            value = memory.load(cells.pointer(7247), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54044)
            vm.pc = 54046
            vm._jump(1286)
            continue
        if vm.block == 1294:
            tick(54046)
            _pointer(vm, 54046, 1, 7182, 7249, (7183,))
            tick(54053)
            vm.pc = 54057
            pointer = cells.value(7249)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54057)
            vm.pc = 54059
            vm._jump(1286)
            continue
        if vm.block == 1286:
            tick(54059)
            vm.pc = 54060
            tick(54060)
            vm.pc = 54063
            vm.auxiliary = (0, 1723752449)
            tick(54063)
            vm.pc = 54068
            vm._write(7184, memory.load(cells.pointer(7183), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(54068)
            vm.pc = 54070
            vm._jump(1285)
            continue
        if vm.block == 1288:
            tick(54070)
            vm.pc = 54074
            value = memory.load(cells.value(64), 8)
            vm._write(7250, value, 8, 'high.load')
            tick(54074)
            vm.pc = 54079
            vm._write(7251, cells.value(7250) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(54079)
            vm.pc = 54083
            pointer = cells.value(134)
            value = memory.load(cells.pointer(7251), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(54083)
            _pointer(vm, 54083, 70, 103, 7252, (145, 7253))
            tick(54091)
            vm.pc = 54096
            cells.copy_q_clear_owned(7252, 7254)
            tick(54096)
            vm.pc = 54101
            vm._write(7255, memory.load(cells.pointer(7254), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(54101)
            _pointer(vm, 54101, 1, 7181, 7256, (163,))
            tick(54108)
            vm.pc = 54112
            value = memory.load(cells.value(7181), 1)
            vm._write(7257, value, 4, 'high.load')
            tick(54112)
            _pointer(vm, 54112, 1, 7252, 7258, (163,))
            tick(54119)
            vm.pc = 54123
            pointer = cells.value(7252)
            value = memory.load(cells.pointer(7257), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54123)
            vm.pc = 54128
            cells.copy_q_clear_owned(7258, 7259)
            tick(54128)
            vm.pc = 54133
            vm._write(7260, memory.load(cells.pointer(7259), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(54133)
            vm.pc = 54134
            tick(54134)
            vm.pc = 54137
            vm.auxiliary = (0, 272796308)
            tick(54137)
            vm.pc = 54142
            vm._write(7261, int(memory.load(cells.pointer(7260), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(54142)
            vm.pc = 54146
            vm._jump(1296 if cells.value(7261) != 0 else 1297)
            continue
        if vm.block == 1296:
            tick(54146)
            _pointer(vm, 54146, 1, 7256, 7262, (163,))
            tick(54153)
            vm.pc = 54157
            value = memory.load(cells.value(7256), 1)
            vm._write(7263, value, 4, 'L5.unsigned_load')
            tick(54157)
            _pointer(vm, 54157, 1, 7258, 7264, (163,))
            tick(54164)
            vm.pc = 54168
            pointer = cells.value(7258)
            value = memory.load(cells.pointer(7263), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54168)
            vm.pc = 54170
            vm._jump(1297)
            continue
        if vm.block == 1297:
            tick(54170)
            _phi(vm, 54170, (7265, 2, 158, 1296, 269, 1288))
            tick(54177)
            _phi(vm, 54177, (7266, 2, 7264, 1296, 7258, 1288))
            tick(54184)
            _phi(vm, 54184, (7267, 2, 7262, 1296, 7256, 1288))
            tick(54191)
            vm.pc = 54196
            cells.copy_q_clear_owned(7266, 7268)
            tick(54196)
            vm.pc = 54201
            vm._write(7269, memory.load(cells.pointer(7268), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(54201)
            vm.pc = 54202
            tick(54202)
            vm.pc = 54205
            vm.auxiliary = (0, 1090710628)
            tick(54205)
            vm.pc = 54210
            vm._write(7270, int(memory.load(cells.pointer(7269), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(54210)
            vm.pc = 54213
            vm.auxiliary = (0, 2100437798)
            tick(54213)
            vm.pc = 54218
            vm._write(7271, int(memory.load(cells.pointer(7265), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(54218)
            vm.pc = 54221
            vm.auxiliary = (0, 4644)
            tick(54221)
            vm.pc = 54226
            vm._write(7272, memory.load(cells.pointer(7270), 1, signed=True) & memory.load(cells.pointer(7271), 1, signed=True), 8, 'typed.selector1.q')
            tick(54226)
            vm.pc = 54230
            vm._jump(1298 if cells.value(7272) != 0 else 1299)
            continue
        if vm.block == 1298:
            tick(54230)
            _pointer(vm, 54230, 1, 7267, 7273, (163,))
            tick(54237)
            vm.pc = 54241
            value = memory.load(cells.value(7267), 1)
            vm._write(7274, value, 4, 'high.load')
            tick(54241)
            _pointer(vm, 54241, 1, 7266, 7275, (163,))
            tick(54248)
            vm.pc = 54252
            pointer = cells.value(7266)
            value = memory.load(cells.pointer(7274), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54252)
            vm.pc = 54253
            tick(54253)
            vm.pc = 54256
            vm.auxiliary = (0, 314507266)
            tick(54256)
            vm.pc = 54261
            vm._write(7276, memory.load(cells.pointer(7265), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(54261)
            vm.pc = 54263
            vm._jump(1299)
            continue
        if vm.block == 1299:
            tick(54263)
            _phi(vm, 54263, (7277, 2, 7276, 1298, 7265, 1297))
            tick(54270)
            _phi(vm, 54270, (7278, 2, 7275, 1298, 7266, 1297))
            tick(54277)
            _phi(vm, 54277, (7279, 2, 7273, 1298, 7267, 1297))
            tick(54284)
            vm.pc = 54289
            cells.copy_q_clear_owned(7278, 7280)
            tick(54289)
            vm.pc = 54294
            cells.copy_q_clear_owned(7279, 7281)
            tick(54294)
            vm.pc = 54295
            tick(54295)
            vm.pc = 54298
            vm.auxiliary = (0, 549627622)
            tick(54298)
            vm.pc = 54303
            vm._write(7282, int(memory.load(cells.pointer(7277), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(54303)
            vm.pc = 54307
            vm._jump(1300 if cells.value(7282) != 0 else 1301)
            continue
        if vm.block == 1300:
            tick(54307)
            _pointer(vm, 54307, 1, 7279, 7283, (172,))
            tick(54314)
            vm.pc = 54319
            cells.copy_q_clear_owned(7283, 7284)
            tick(54319)
            vm.pc = 54323
            value = memory.load(cells.value(7281), 4)
            vm._write(7285, value, 4, 'high.load')
            tick(54323)
            _pointer(vm, 54323, 1, 7278, 7286, (172,))
            tick(54330)
            vm.pc = 54335
            cells.copy_q_clear_owned(7286, 7287)
            tick(54335)
            vm.pc = 54339
            pointer = cells.value(7280)
            value = memory.load(cells.pointer(7285), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(54339)
            vm.pc = 54340
            tick(54340)
            vm.pc = 54343
            vm.auxiliary = (0, 418906114)
            tick(54343)
            vm.pc = 54348
            vm._write(7288, memory.load(cells.pointer(7277), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(54348)
            vm.pc = 54350
            vm._jump(1301)
            continue
        if vm.block == 1301:
            tick(54350)
            _phi(vm, 54350, (7289, 2, 7288, 1300, 7277, 1299))
            tick(54357)
            _phi(vm, 54357, (7290, 2, 7287, 1300, 7280, 1299))
            tick(54364)
            _phi(vm, 54364, (7291, 2, 7284, 1300, 7281, 1299))
            tick(54371)
            vm.pc = 54372
            tick(54372)
            vm.pc = 54375
            vm.auxiliary = (0, 274865670)
            tick(54375)
            vm.pc = 54380
            vm._write(7292, int(memory.load(cells.pointer(7289), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(54380)
            vm.pc = 54384
            vm._jump(1302 if cells.value(7292) != 0 else 1303)
            continue
        if vm.block == 1302:
            tick(54384)
            _pointer(vm, 54384, 3, 7291, 7293, (163,))
            tick(54391)
            vm.pc = 54395
            value = memory.load(cells.value(7291), 4)
            vm._write(7294, value, 4, 'high.load')
            tick(54395)
            _pointer(vm, 54395, 3, 7290, 7295, (163,))
            tick(54402)
            vm.pc = 54406
            pointer = cells.value(7290)
            value = memory.load(cells.pointer(7294), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(54406)
            vm.pc = 54407
            tick(54407)
            vm.pc = 54410
            vm.auxiliary = (0, 863834113)
            tick(54410)
            vm.pc = 54415
            vm._write(7296, memory.load(cells.pointer(7289), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(54415)
            vm.pc = 54417
            vm._jump(1303)
            continue
        if vm.block == 1303:
            tick(54417)
            _phi(vm, 54417, (7297, 2, 7296, 1302, 7289, 1301))
            tick(54424)
            _phi(vm, 54424, (7298, 2, 7295, 1302, 7290, 1301))
            tick(54431)
            _phi(vm, 54431, (7299, 2, 7293, 1302, 7291, 1301))
            tick(54438)
            vm.pc = 54439
            tick(54439)
            vm.pc = 54442
            vm.auxiliary = (0, 897776102)
            tick(54442)
            vm.pc = 54447
            vm._write(7300, int(memory.load(cells.pointer(7297), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(54447)
            vm.pc = 54451
            vm._jump(1304 if cells.value(7300) != 0 else 1305)
            continue
        if vm.block == 1304:
            tick(54451)
            _pointer(vm, 54451, 3, 7299, 7301, (163,))
            tick(54458)
            vm.pc = 54462
            value = memory.load(cells.value(7299), 4)
            vm._write(7302, value, 4, 'L5.unsigned_load')
            tick(54462)
            _pointer(vm, 54462, 3, 7298, 7303, (163,))
            tick(54469)
            vm.pc = 54473
            pointer = cells.value(7298)
            value = memory.load(cells.pointer(7302), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(54473)
            vm.pc = 54474
            tick(54474)
            vm.pc = 54477
            vm.auxiliary = (0, 1171255297)
            tick(54477)
            vm.pc = 54482
            vm._write(7304, memory.load(cells.pointer(7297), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(54482)
            vm.pc = 54484
            vm._jump(1305)
            continue
        if vm.block == 1305:
            tick(54484)
            _phi(vm, 54484, (7305, 2, 7304, 1304, 7297, 1303))
            tick(54491)
            _phi(vm, 54491, (7306, 2, 7303, 1304, 7298, 1303))
            tick(54498)
            _phi(vm, 54498, (7307, 2, 7301, 1304, 7299, 1303))
            tick(54505)
            vm.pc = 54510
            cells.copy_q_clear_owned(7306, 7308)
            tick(54510)
            vm.pc = 54515
            cells.copy_q_clear_owned(7307, 7309)
            tick(54515)
            vm.pc = 54516
            tick(54516)
            vm.pc = 54519
            vm.auxiliary = (0, 1728231686)
            tick(54519)
            vm.pc = 54524
            vm._write(7310, int(memory.load(cells.pointer(7305), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(54524)
            vm.pc = 54528
            vm._jump(1306 if cells.value(7310) != 0 else 1307)
            continue
        if vm.block == 1306:
            tick(54528)
            _pointer(vm, 54528, 1, 7309, 7311, (163,))
            tick(54535)
            vm.pc = 54539
            value = memory.load(cells.value(7309), 1)
            vm._write(7312, value, 4, 'high.load')
            tick(54539)
            _pointer(vm, 54539, 1, 7308, 7313, (163,))
            tick(54546)
            vm.pc = 54550
            pointer = cells.value(7308)
            value = memory.load(cells.pointer(7312), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54550)
            vm.pc = 54551
            tick(54551)
            vm.pc = 54554
            vm.auxiliary = (0, 517001218)
            tick(54554)
            vm.pc = 54559
            vm._write(7314, memory.load(cells.pointer(7305), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(54559)
            vm.pc = 54561
            vm._jump(1307)
            continue
        if vm.block == 1307:
            tick(54561)
            _phi(vm, 54561, (7315, 2, 7314, 1306, 7305, 1305))
            tick(54568)
            _phi(vm, 54568, (7316, 2, 7313, 1306, 7308, 1305))
            tick(54575)
            _phi(vm, 54575, (7317, 2, 7311, 1306, 7309, 1305))
            tick(54582)
            vm.pc = 54583
            tick(54583)
            vm.pc = 54586
            vm.auxiliary = (0, 1192375270)
            tick(54586)
            vm.pc = 54591
            vm._write(7318, int(memory.load(cells.pointer(7315), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(54591)
            vm.pc = 54595
            vm._jump(1308 if cells.value(7318) != 0 else 1309)
            continue
        if vm.block == 1308:
            tick(54595)
            _pointer(vm, 54595, 1, 7317, 7319, (163,))
            tick(54602)
            vm.pc = 54606
            value = memory.load(cells.value(7317), 1)
            vm._write(7320, value, 4, 'high.load')
            tick(54606)
            _pointer(vm, 54606, 1, 7316, 7321, (163,))
            tick(54613)
            vm.pc = 54617
            pointer = cells.value(7316)
            value = memory.load(cells.pointer(7320), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54617)
            vm.pc = 54618
            tick(54618)
            vm.pc = 54621
            vm.auxiliary = (0, 1626316802)
            tick(54621)
            vm.pc = 54626
            vm._write(7322, memory.load(cells.pointer(7315), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(54626)
            vm.pc = 54628
            vm._jump(1309)
            continue
        if vm.block == 1309:
            tick(54628)
            _phi(vm, 54628, (7323, 2, 7322, 1308, 7315, 1307))
            tick(54635)
            _phi(vm, 54635, (7324, 2, 7321, 1308, 7316, 1307))
            tick(54642)
            _phi(vm, 54642, (7325, 2, 7319, 1308, 7317, 1307))
            tick(54649)
            vm.pc = 54650
            tick(54650)
            vm.pc = 54653
            vm.auxiliary = (0, 676481830)
            tick(54653)
            vm.pc = 54658
            vm._write(7326, int(memory.load(cells.pointer(7323), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(54658)
            vm.pc = 54662
            vm._jump(1310 if cells.value(7326) != 0 else 1311)
            continue
        if vm.block == 1310:
            tick(54662)
            _pointer(vm, 54662, 1, 7325, 7327, (163,))
            tick(54669)
            vm.pc = 54673
            value = memory.load(cells.value(7325), 1)
            vm._write(7328, value, 4, 'high.load')
            tick(54673)
            _pointer(vm, 54673, 1, 7324, 7329, (163,))
            tick(54680)
            vm.pc = 54684
            pointer = cells.value(7324)
            value = memory.load(cells.pointer(7328), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54684)
            vm.pc = 54686
            vm._jump(1311)
            continue
        if vm.block == 1311:
            tick(54686)
            _phi(vm, 54686, (7330, 2, 7329, 1310, 7324, 1309))
            tick(54693)
            _phi(vm, 54693, (7331, 2, 7327, 1310, 7325, 1309))
            tick(54700)
            vm.pc = 54701
            tick(54701)
            vm.pc = 54704
            vm.auxiliary = (0, 482520822)
            tick(54704)
            vm.pc = 54709
            vm._write(7332, int(memory.load(cells.pointer(7323), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(54709)
            vm.pc = 54713
            vm._jump(1312 if cells.value(7332) != 0 else 1313)
            continue
        if vm.block == 1312:
            tick(54713)
            vm.pc = 54717
            value = memory.load(cells.value(7331), 1)
            vm._write(7333, value, 4, 'L5.unsigned_load')
            tick(54717)
            vm.pc = 54721
            pointer = cells.value(7330)
            value = memory.load(cells.pointer(7333), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54721)
            vm.pc = 54723
            vm._jump(1313)
            continue
        if vm.block == 1313:
            tick(54723)
            _pointer(vm, 54723, 70, 103, 7334, (145, 7335))
            tick(54731)
            vm.pc = 54736
            cells.copy_q_clear_owned(7334, 7336)
            tick(54736)
            vm.pc = 54737
            tick(54737)
            vm.pc = 54740
            vm.auxiliary = (0, 10036)
            tick(54740)
            vm.pc = 54745
            vm._write(7337, memory.load(cells.pointer(7336), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(54745)
            _pointer(vm, 54745, 1, 1280, 7338, (163,))
            tick(54752)
            vm.pc = 54756
            value = memory.load(cells.value(1280), 1)
            vm._write(7339, value, 4, 'L5.unsigned_load')
            tick(54756)
            _pointer(vm, 54756, 1, 7334, 7340, (163,))
            tick(54763)
            vm.pc = 54767
            pointer = cells.value(7334)
            value = memory.load(cells.pointer(7339), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54767)
            vm.pc = 54772
            cells.copy_q_clear_owned(7340, 7341)
            tick(54772)
            vm.pc = 54775
            vm.auxiliary = (0, 14117)
            tick(54775)
            vm.pc = 54780
            vm._write(7342, memory.load(cells.pointer(7341), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(54780)
            vm.pc = 54783
            vm.auxiliary = (0, 2103588948)
            tick(54783)
            vm.pc = 54788
            vm._write(7343, int(memory.load(cells.pointer(7342), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(54788)
            vm.pc = 54792
            vm._jump(1314 if cells.value(7343) != 0 else 1315)
            continue
        if vm.block == 1314:
            tick(54792)
            _pointer(vm, 54792, 1, 7338, 7344, (163,))
            tick(54799)
            vm.pc = 54803
            value = memory.load(cells.value(7338), 1)
            vm._write(7345, value, 4, 'high.load')
            tick(54803)
            _pointer(vm, 54803, 1, 7340, 7346, (163,))
            tick(54810)
            vm.pc = 54814
            pointer = cells.value(7340)
            value = memory.load(cells.pointer(7345), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54814)
            vm.pc = 54816
            vm._jump(1315)
            continue
        if vm.block == 1315:
            tick(54816)
            _phi(vm, 54816, (7347, 2, 311, 1314, 149, 1313))
            tick(54823)
            _phi(vm, 54823, (7348, 2, 7346, 1314, 7340, 1313))
            tick(54830)
            _phi(vm, 54830, (7349, 2, 7344, 1314, 7338, 1313))
            tick(54837)
            vm.pc = 54842
            cells.copy_q_clear_owned(7348, 7350)
            tick(54842)
            vm.pc = 54847
            vm._write(7351, memory.load(cells.pointer(7350), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(54847)
            vm.pc = 54848
            tick(54848)
            vm.pc = 54851
            vm.auxiliary = (0, 489874004)
            tick(54851)
            vm.pc = 54856
            vm._write(7352, int(memory.load(cells.pointer(7351), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(54856)
            vm.pc = 54859
            vm.auxiliary = (0, 1630704710)
            tick(54859)
            vm.pc = 54864
            vm._write(7353, int(memory.load(cells.pointer(7347), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(54864)
            vm.pc = 54867
            vm.auxiliary = (0, 22351)
            tick(54867)
            vm.pc = 54872
            vm._write(7354, memory.load(cells.pointer(7352), 1, signed=True) & memory.load(cells.pointer(7353), 1, signed=True), 8, 'typed.selector1.q')
            tick(54872)
            vm.pc = 54876
            vm._jump(1316 if cells.value(7354) != 0 else 1317)
            continue
        if vm.block == 1316:
            tick(54876)
            _pointer(vm, 54876, 1, 7349, 7355, (163,))
            tick(54883)
            vm.pc = 54887
            value = memory.load(cells.value(7349), 1)
            vm._write(7356, value, 4, 'high.load')
            tick(54887)
            _pointer(vm, 54887, 1, 7348, 7357, (163,))
            tick(54894)
            vm.pc = 54898
            pointer = cells.value(7348)
            value = memory.load(cells.pointer(7356), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(54898)
            vm.pc = 54899
            tick(54899)
            vm.pc = 54902
            vm.auxiliary = (0, 1467908097)
            tick(54902)
            vm.pc = 54907
            vm._write(7358, memory.load(cells.pointer(7347), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(54907)
            vm.pc = 54909
            vm._jump(1317)
            continue
        if vm.block == 1317:
            tick(54909)
            _phi(vm, 54909, (7359, 2, 7358, 1316, 7347, 1315))
            tick(54916)
            _phi(vm, 54916, (7360, 2, 7357, 1316, 7348, 1315))
            tick(54923)
            _phi(vm, 54923, (7361, 2, 7355, 1316, 7349, 1315))
            tick(54930)
            vm.pc = 54935
            cells.copy_q_clear_owned(7360, 7362)
            tick(54935)
            vm.pc = 54940
            cells.copy_q_clear_owned(7361, 7363)
            tick(54940)
            vm.pc = 54941
            tick(54941)
            vm.pc = 54944
            vm.auxiliary = (0, 1753395206)
            tick(54944)
            vm.pc = 54949
            vm._write(7364, int(memory.load(cells.pointer(7359), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(54949)
            vm.pc = 54953
            vm._jump(1318 if cells.value(7364) != 0 else 1319)
            continue
        if vm.block == 1318:
            tick(54953)
            _pointer(vm, 54953, 1, 7361, 7365, (172,))
            tick(54960)
            vm.pc = 54965
            cells.copy_q_clear_owned(7365, 7366)
            tick(54965)
            vm.pc = 54969
            value = memory.load(cells.value(7363), 4)
            vm._write(7367, value, 4, 'high.load')
            tick(54969)
            _pointer(vm, 54969, 1, 7360, 7368, (172,))
            tick(54976)
            vm.pc = 54981
            cells.copy_q_clear_owned(7368, 7369)
            tick(54981)
            vm.pc = 54985
            pointer = cells.value(7362)
            value = memory.load(cells.pointer(7367), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(54985)
            vm.pc = 54986
            tick(54986)
            vm.pc = 54989
            vm.auxiliary = (0, 2023878657)
            tick(54989)
            vm.pc = 54994
            vm._write(7370, memory.load(cells.pointer(7359), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(54994)
            vm.pc = 54996
            vm._jump(1319)
            continue
        if vm.block == 1319:
            tick(54996)
            _phi(vm, 54996, (7371, 2, 7370, 1318, 7359, 1317))
            tick(55003)
            _phi(vm, 55003, (7372, 2, 7369, 1318, 7362, 1317))
            tick(55010)
            _phi(vm, 55010, (7373, 2, 7366, 1318, 7363, 1317))
            tick(55017)
            vm.pc = 55018
            tick(55018)
            vm.pc = 55021
            vm.auxiliary = (0, 1483884246)
            tick(55021)
            vm.pc = 55026
            vm._write(7374, int(memory.load(cells.pointer(7371), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(55026)
            vm.pc = 55030
            vm._jump(1320 if cells.value(7374) != 0 else 1321)
            continue
        if vm.block == 1320:
            tick(55030)
            _pointer(vm, 55030, 3, 7373, 7375, (163,))
            tick(55037)
            vm.pc = 55041
            value = memory.load(cells.value(7373), 4)
            vm._write(7376, value, 4, 'high.load')
            tick(55041)
            _pointer(vm, 55041, 3, 7372, 7377, (163,))
            tick(55048)
            vm.pc = 55052
            pointer = cells.value(7372)
            value = memory.load(cells.pointer(7376), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(55052)
            vm.pc = 55053
            tick(55053)
            vm.pc = 55056
            vm.auxiliary = (0, 957640705)
            tick(55056)
            vm.pc = 55061
            vm._write(7378, memory.load(cells.pointer(7371), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(55061)
            vm.pc = 55063
            vm._jump(1321)
            continue
        if vm.block == 1321:
            tick(55063)
            _phi(vm, 55063, (7379, 2, 7378, 1320, 7371, 1319))
            tick(55070)
            _phi(vm, 55070, (7380, 2, 7377, 1320, 7372, 1319))
            tick(55077)
            _phi(vm, 55077, (7381, 2, 7375, 1320, 7373, 1319))
            tick(55084)
            vm.pc = 55085
            tick(55085)
            vm.pc = 55088
            vm.auxiliary = (0, 721582182)
            tick(55088)
            vm.pc = 55093
            vm._write(7382, int(memory.load(cells.pointer(7379), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(55093)
            vm.pc = 55097
            vm._jump(1322 if cells.value(7382) != 0 else 1323)
            continue
        if vm.block == 1322:
            tick(55097)
            _pointer(vm, 55097, 3, 7381, 7383, (163,))
            tick(55104)
            vm.pc = 55108
            value = memory.load(cells.value(7381), 4)
            vm._write(7384, value, 4, 'high.load')
            tick(55108)
            _pointer(vm, 55108, 3, 7380, 7385, (163,))
            tick(55115)
            vm.pc = 55119
            pointer = cells.value(7380)
            value = memory.load(cells.pointer(7384), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(55119)
            vm.pc = 55120
            tick(55120)
            vm.pc = 55123
            vm.auxiliary = (0, 465022977)
            tick(55123)
            vm.pc = 55128
            vm._write(7386, memory.load(cells.pointer(7379), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(55128)
            vm.pc = 55130
            vm._jump(1323)
            continue
        if vm.block == 1323:
            tick(55130)
            _phi(vm, 55130, (7387, 2, 7386, 1322, 7379, 1321))
            tick(55137)
            _phi(vm, 55137, (7388, 2, 7385, 1322, 7380, 1321))
            tick(55144)
            _phi(vm, 55144, (7389, 2, 7383, 1322, 7381, 1321))
            tick(55151)
            vm.pc = 55156
            cells.copy_q_clear_owned(7388, 7390)
            tick(55156)
            vm.pc = 55161
            cells.copy_q_clear_owned(7389, 7391)
            tick(55161)
            vm.pc = 55162
            tick(55162)
            vm.pc = 55165
            vm.auxiliary = (0, 1131566454)
            tick(55165)
            vm.pc = 55170
            vm._write(7392, int(memory.load(cells.pointer(7387), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(55170)
            vm.pc = 55174
            vm._jump(1324 if cells.value(7392) != 0 else 1325)
            continue
        if vm.block == 1324:
            tick(55174)
            _pointer(vm, 55174, 1, 7391, 7393, (163,))
            tick(55181)
            vm.pc = 55185
            value = memory.load(cells.value(7391), 1)
            vm._write(7394, value, 4, 'high.load')
            tick(55185)
            _pointer(vm, 55185, 1, 7390, 7395, (163,))
            tick(55192)
            vm.pc = 55196
            pointer = cells.value(7390)
            value = memory.load(cells.pointer(7394), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55196)
            vm.pc = 55197
            tick(55197)
            vm.pc = 55200
            vm.auxiliary = (0, 1624580098)
            tick(55200)
            vm.pc = 55205
            vm._write(7396, memory.load(cells.pointer(7387), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(55205)
            vm.pc = 55207
            vm._jump(1325)
            continue
        if vm.block == 1325:
            tick(55207)
            _phi(vm, 55207, (7397, 2, 7396, 1324, 7387, 1323))
            tick(55214)
            _phi(vm, 55214, (7398, 2, 7395, 1324, 7390, 1323))
            tick(55221)
            _phi(vm, 55221, (7399, 2, 7393, 1324, 7391, 1323))
            tick(55228)
            vm.pc = 55229
            tick(55229)
            vm.pc = 55232
            vm.auxiliary = (0, 1426196598)
            tick(55232)
            vm.pc = 55237
            vm._write(7400, int(memory.load(cells.pointer(7397), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(55237)
            vm.pc = 55241
            vm._jump(1326 if cells.value(7400) != 0 else 1327)
            continue
        if vm.block == 1326:
            tick(55241)
            _pointer(vm, 55241, 1, 7399, 7401, (163,))
            tick(55248)
            vm.pc = 55252
            value = memory.load(cells.value(7399), 1)
            vm._write(7402, value, 4, 'L5.unsigned_load')
            tick(55252)
            _pointer(vm, 55252, 1, 7398, 7403, (163,))
            tick(55259)
            vm.pc = 55263
            pointer = cells.value(7398)
            value = memory.load(cells.pointer(7402), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55263)
            vm.pc = 55264
            tick(55264)
            vm.pc = 55267
            vm.auxiliary = (0, 509915138)
            tick(55267)
            vm.pc = 55272
            vm._write(7404, memory.load(cells.pointer(7397), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(55272)
            vm.pc = 55274
            vm._jump(1327)
            continue
        if vm.block == 1327:
            tick(55274)
            _phi(vm, 55274, (7405, 2, 7404, 1326, 7397, 1325))
            tick(55281)
            _phi(vm, 55281, (7406, 2, 7403, 1326, 7398, 1325))
            tick(55288)
            _phi(vm, 55288, (7407, 2, 7401, 1326, 7399, 1325))
            tick(55295)
            vm.pc = 55296
            tick(55296)
            vm.pc = 55299
            vm.auxiliary = (0, 1376942102)
            tick(55299)
            vm.pc = 55304
            vm._write(7408, int(memory.load(cells.pointer(7405), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(55304)
            vm.pc = 55308
            vm._jump(1328 if cells.value(7408) != 0 else 1329)
            continue
        if vm.block == 1328:
            tick(55308)
            _pointer(vm, 55308, 1, 7407, 7409, (163,))
            tick(55315)
            vm.pc = 55319
            value = memory.load(cells.value(7407), 1)
            vm._write(7410, value, 4, 'high.load')
            tick(55319)
            _pointer(vm, 55319, 1, 7406, 7411, (163,))
            tick(55326)
            vm.pc = 55330
            pointer = cells.value(7406)
            value = memory.load(cells.pointer(7410), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55330)
            vm.pc = 55332
            vm._jump(1329)
            continue
        if vm.block == 1329:
            tick(55332)
            _phi(vm, 55332, (7412, 2, 7411, 1328, 7406, 1327))
            tick(55339)
            _phi(vm, 55339, (7413, 2, 7409, 1328, 7407, 1327))
            tick(55346)
            vm.pc = 55347
            tick(55347)
            vm.pc = 55350
            vm.auxiliary = (0, 1839352758)
            tick(55350)
            vm.pc = 55355
            vm._write(7414, int(memory.load(cells.pointer(7405), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(55355)
            vm.pc = 55359
            vm._jump(1330 if cells.value(7414) != 0 else 1331)
            continue
        if vm.block == 1330:
            tick(55359)
            vm.pc = 55363
            value = memory.load(cells.value(7413), 1)
            vm._write(7415, value, 4, 'high.load')
            tick(55363)
            vm.pc = 55367
            pointer = cells.value(7412)
            value = memory.load(cells.pointer(7415), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55367)
            vm.pc = 55369
            vm._jump(1331)
            continue
        if vm.block == 1331:
            tick(55369)
            vm.pc = 55371
            vm._jump(1332)
            continue
        if vm.block == 1332:
            tick(55371)
            _phi(vm, 55371, (7416, 2, 1198, 1331, 7417, 1333))
            tick(55378)
            _phi(vm, 55378, (7418, 2, 205, 1331, 7419, 1333))
            tick(55385)
            vm.pc = 55386
            tick(55386)
            vm.pc = 55389
            vm.auxiliary = (0, 1130547011)
            tick(55389)
            vm.pc = 55394
            vm._write(7420, int(memory.load(cells.pointer(7418), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(55394)
            vm.pc = 55398
            vm._jump(1334 if cells.value(7420) != 0 else 1333)
            continue
        if vm.block == 1333:
            tick(55398)
            vm.pc = 55399
            tick(55399)
            vm.pc = 55402
            vm.auxiliary = (0, 1123930114)
            tick(55402)
            vm.pc = 55407
            vm._write(7419, memory.load(cells.pointer(7418), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(55407)
            _pointer(vm, 55407, 1, 7416, 7417, (163,))
            tick(55414)
            vm.pc = 55418
            pointer = cells.value(7416)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55418)
            vm.pc = 55420
            vm._jump(1332)
            continue
        if vm.block == 1334:
            tick(55420)
            _pointer(vm, 55420, 70, 103, 7421, (145, 201))
            tick(55428)
            vm.pc = 55433
            cells.copy_q_clear_owned(7421, 7422)
            tick(55433)
            vm.pc = 55434
            tick(55434)
            vm.pc = 55437
            vm.auxiliary = (0, 20812)
            tick(55437)
            vm.pc = 55442
            vm._write(7423, memory.load(cells.pointer(7422), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(55442)
            _pointer(vm, 55442, 1, 1520, 7424, (163,))
            tick(55449)
            vm.pc = 55453
            value = memory.load(cells.value(1520), 1)
            vm._write(7425, value, 4, 'L5.unsigned_load')
            tick(55453)
            _pointer(vm, 55453, 1, 7421, 7426, (163,))
            tick(55460)
            vm.pc = 55464
            pointer = cells.value(7421)
            value = memory.load(cells.pointer(7425), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55464)
            vm.pc = 55469
            cells.copy_q_clear_owned(7426, 7427)
            tick(55469)
            vm.pc = 55474
            vm._write(7428, memory.load(cells.pointer(7427), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(55474)
            vm.pc = 55477
            vm.auxiliary = (0, 324161252)
            tick(55477)
            vm.pc = 55482
            vm._write(7429, int(memory.load(cells.pointer(7428), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(55482)
            vm.pc = 55484
            vm._jump(1335)
            continue
        if vm.block == 1335:
            tick(55484)
            vm.pc = 55489
            cells.copy_q_clear_owned(7426, 7430)
            tick(55489)
            vm.pc = 55490
            tick(55490)
            vm.pc = 55493
            vm.auxiliary = (0, 13110)
            tick(55493)
            vm.pc = 55498
            vm._write(7431, memory.load(cells.pointer(7430), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(55498)
            vm.pc = 55501
            vm.auxiliary = (0, 2011316308)
            tick(55501)
            vm.pc = 55506
            vm._write(7432, int(memory.load(cells.pointer(7431), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(55506)
            vm.pc = 55509
            vm.auxiliary = (0, 693304630)
            tick(55509)
            vm.pc = 55514
            vm._write(7433, int(memory.load(cells.pointer(158), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(55514)
            vm.pc = 55519
            vm._write(7434, memory.load(cells.pointer(7432), 1, signed=True) & memory.load(cells.pointer(7433), 1, signed=True), 8, 'L13.binary_q')
            tick(55519)
            vm.pc = 55523
            vm._jump(1336 if cells.value(7434) != 0 else 1337)
            continue
        if vm.block == 1336:
            tick(55523)
            _pointer(vm, 55523, 1, 7424, 7435, (163,))
            tick(55530)
            vm.pc = 55534
            value = memory.load(cells.value(7424), 1)
            vm._write(7436, value, 4, 'high.load')
            tick(55534)
            _pointer(vm, 55534, 1, 7426, 7437, (163,))
            tick(55541)
            vm.pc = 55545
            pointer = cells.value(7426)
            value = memory.load(cells.pointer(7436), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55545)
            vm.pc = 55546
            tick(55546)
            vm.pc = 55549
            vm.auxiliary = (0, 1522708482)
            tick(55549)
            vm.pc = 55554
            vm._write(7438, memory.load(cells.pointer(158), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(55554)
            vm.pc = 55556
            vm._jump(1337)
            continue
        if vm.block == 1337:
            tick(55556)
            _phi(vm, 55556, (7439, 2, 7438, 1336, 158, 1335))
            tick(55563)
            _phi(vm, 55563, (7440, 2, 7437, 1336, 7426, 1335))
            tick(55570)
            _phi(vm, 55570, (7441, 2, 7435, 1336, 7424, 1335))
            tick(55577)
            vm.pc = 55582
            cells.copy_q_clear_owned(7440, 7442)
            tick(55582)
            vm.pc = 55587
            cells.copy_q_clear_owned(7441, 7443)
            tick(55587)
            vm.pc = 55588
            tick(55588)
            vm.pc = 55591
            vm.auxiliary = (0, 1547862326)
            tick(55591)
            vm.pc = 55596
            vm._write(7444, int(memory.load(cells.pointer(7439), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(55596)
            vm.pc = 55600
            vm._jump(1338 if cells.value(7444) != 0 else 1339)
            continue
        if vm.block == 1338:
            tick(55600)
            _pointer(vm, 55600, 1, 7441, 7445, (172,))
            tick(55607)
            vm.pc = 55612
            cells.copy_q_clear_owned(7445, 7446)
            tick(55612)
            vm.pc = 55616
            value = memory.load(cells.value(7443), 4)
            vm._write(7447, value, 4, 'high.load')
            tick(55616)
            _pointer(vm, 55616, 1, 7440, 7448, (172,))
            tick(55623)
            vm.pc = 55628
            cells.copy_q_clear_owned(7448, 7449)
            tick(55628)
            vm.pc = 55632
            pointer = cells.value(7442)
            value = memory.load(cells.pointer(7447), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(55632)
            vm.pc = 55633
            tick(55633)
            vm.pc = 55636
            vm.auxiliary = (0, 1315332097)
            tick(55636)
            vm.pc = 55641
            vm._write(7450, memory.load(cells.pointer(7439), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(55641)
            vm.pc = 55643
            vm._jump(1339)
            continue
        if vm.block == 1339:
            tick(55643)
            _phi(vm, 55643, (7451, 2, 7450, 1338, 7439, 1337))
            tick(55650)
            _phi(vm, 55650, (7452, 2, 7449, 1338, 7442, 1337))
            tick(55657)
            _phi(vm, 55657, (7453, 2, 7446, 1338, 7443, 1337))
            tick(55664)
            vm.pc = 55665
            tick(55665)
            vm.pc = 55668
            vm.auxiliary = (0, 2032275814)
            tick(55668)
            vm.pc = 55673
            vm._write(7454, int(memory.load(cells.pointer(7451), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(55673)
            vm.pc = 55677
            vm._jump(1340 if cells.value(7454) != 0 else 1341)
            continue
        if vm.block == 1340:
            tick(55677)
            _pointer(vm, 55677, 3, 7453, 7455, (163,))
            tick(55684)
            vm.pc = 55688
            value = memory.load(cells.value(7453), 4)
            vm._write(7456, value, 4, 'high.load')
            tick(55688)
            _pointer(vm, 55688, 3, 7452, 7457, (163,))
            tick(55695)
            vm.pc = 55699
            pointer = cells.value(7452)
            value = memory.load(cells.pointer(7456), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(55699)
            vm.pc = 55700
            tick(55700)
            vm.pc = 55703
            vm.auxiliary = (0, 562475010)
            tick(55703)
            vm.pc = 55708
            vm._write(7458, memory.load(cells.pointer(7451), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(55708)
            vm.pc = 55710
            vm._jump(1341)
            continue
        if vm.block == 1341:
            tick(55710)
            _phi(vm, 55710, (7459, 2, 7458, 1340, 7451, 1339))
            tick(55717)
            _phi(vm, 55717, (7460, 2, 7457, 1340, 7452, 1339))
            tick(55724)
            _phi(vm, 55724, (7461, 2, 7455, 1340, 7453, 1339))
            tick(55731)
            vm.pc = 55732
            tick(55732)
            vm.pc = 55735
            vm.auxiliary = (0, 775038790)
            tick(55735)
            vm.pc = 55740
            vm._write(7462, int(memory.load(cells.pointer(7459), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(55740)
            vm.pc = 55744
            vm._jump(1342 if cells.value(7462) != 0 else 1343)
            continue
        if vm.block == 1342:
            tick(55744)
            _pointer(vm, 55744, 3, 7461, 7463, (163,))
            tick(55751)
            vm.pc = 55755
            value = memory.load(cells.value(7461), 4)
            vm._write(7464, value, 4, 'high.load')
            tick(55755)
            _pointer(vm, 55755, 3, 7460, 7465, (163,))
            tick(55762)
            vm.pc = 55766
            pointer = cells.value(7460)
            value = memory.load(cells.pointer(7464), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(55766)
            vm.pc = 55767
            tick(55767)
            vm.pc = 55770
            vm.auxiliary = (0, 1424969729)
            tick(55770)
            vm.pc = 55775
            vm._write(7466, memory.load(cells.pointer(7459), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(55775)
            vm.pc = 55777
            vm._jump(1343)
            continue
        if vm.block == 1343:
            tick(55777)
            _phi(vm, 55777, (7467, 2, 7466, 1342, 7459, 1341))
            tick(55784)
            _phi(vm, 55784, (7468, 2, 7465, 1342, 7460, 1341))
            tick(55791)
            _phi(vm, 55791, (7469, 2, 7463, 1342, 7461, 1341))
            tick(55798)
            vm.pc = 55803
            cells.copy_q_clear_owned(7468, 7470)
            tick(55803)
            vm.pc = 55808
            cells.copy_q_clear_owned(7469, 7471)
            tick(55808)
            vm.pc = 55809
            tick(55809)
            vm.pc = 55812
            vm.auxiliary = (0, 2008165286)
            tick(55812)
            vm.pc = 55817
            vm._write(7472, int(memory.load(cells.pointer(7467), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(55817)
            vm.pc = 55821
            vm._jump(1344 if cells.value(7472) != 0 else 1345)
            continue
        if vm.block == 1344:
            tick(55821)
            _pointer(vm, 55821, 1, 7471, 7473, (163,))
            tick(55828)
            vm.pc = 55832
            value = memory.load(cells.value(7471), 1)
            vm._write(7474, value, 4, 'high.load')
            tick(55832)
            _pointer(vm, 55832, 1, 7470, 7475, (163,))
            tick(55839)
            vm.pc = 55843
            pointer = cells.value(7470)
            value = memory.load(cells.pointer(7474), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55843)
            vm.pc = 55844
            tick(55844)
            vm.pc = 55847
            vm.auxiliary = (0, 254103553)
            tick(55847)
            vm.pc = 55852
            vm._write(7476, memory.load(cells.pointer(7467), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(55852)
            vm.pc = 55854
            vm._jump(1345)
            continue
        if vm.block == 1345:
            tick(55854)
            _phi(vm, 55854, (7477, 2, 7476, 1344, 7467, 1343))
            tick(55861)
            _phi(vm, 55861, (7478, 2, 7475, 1344, 7470, 1343))
            tick(55868)
            _phi(vm, 55868, (7479, 2, 7473, 1344, 7471, 1343))
            tick(55875)
            vm.pc = 55876
            tick(55876)
            vm.pc = 55879
            vm.auxiliary = (0, 803372390)
            tick(55879)
            vm.pc = 55884
            vm._write(7480, int(memory.load(cells.pointer(7477), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(55884)
            vm.pc = 55888
            vm._jump(1346 if cells.value(7480) != 0 else 1347)
            continue
        if vm.block == 1346:
            tick(55888)
            _pointer(vm, 55888, 1, 7479, 7481, (163,))
            tick(55895)
            vm.pc = 55899
            value = memory.load(cells.value(7479), 1)
            vm._write(7482, value, 4, 'high.load')
            tick(55899)
            _pointer(vm, 55899, 1, 7478, 7483, (163,))
            tick(55906)
            vm.pc = 55910
            pointer = cells.value(7478)
            value = memory.load(cells.pointer(7482), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55910)
            vm.pc = 55911
            tick(55911)
            vm.pc = 55914
            vm.auxiliary = (0, 920023042)
            tick(55914)
            vm.pc = 55919
            vm._write(7484, memory.load(cells.pointer(7477), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(55919)
            vm.pc = 55921
            vm._jump(1347)
            continue
        if vm.block == 1347:
            tick(55921)
            _phi(vm, 55921, (7485, 2, 7484, 1346, 7477, 1345))
            tick(55928)
            _phi(vm, 55928, (7486, 2, 7483, 1346, 7478, 1345))
            tick(55935)
            _phi(vm, 55935, (7487, 2, 7481, 1346, 7479, 1345))
            tick(55942)
            vm.pc = 55943
            tick(55943)
            vm.pc = 55946
            vm.auxiliary = (0, 701676502)
            tick(55946)
            vm.pc = 55951
            vm._write(7488, int(memory.load(cells.pointer(7485), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(55951)
            vm.pc = 55955
            vm._jump(1348 if cells.value(7488) != 0 else 1349)
            continue
        if vm.block == 1348:
            tick(55955)
            _pointer(vm, 55955, 1, 7487, 7489, (163,))
            tick(55962)
            vm.pc = 55966
            value = memory.load(cells.value(7487), 1)
            vm._write(7490, value, 4, 'high.load')
            tick(55966)
            _pointer(vm, 55966, 1, 7486, 7491, (163,))
            tick(55973)
            vm.pc = 55977
            pointer = cells.value(7486)
            value = memory.load(cells.pointer(7490), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(55977)
            vm.pc = 55979
            vm._jump(1349)
            continue
        if vm.block == 1349:
            tick(55979)
            _phi(vm, 55979, (7492, 2, 7491, 1348, 7486, 1347))
            tick(55986)
            _phi(vm, 55986, (7493, 2, 7489, 1348, 7487, 1347))
            tick(55993)
            vm.pc = 55994
            tick(55994)
            vm.pc = 55997
            vm.auxiliary = (0, 1382209382)
            tick(55997)
            vm.pc = 56002
            vm._write(7494, int(memory.load(cells.pointer(7485), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(56002)
            vm.pc = 56006
            vm._jump(1350 if cells.value(7494) != 0 else 1351)
            continue
        if vm.block == 1350:
            tick(56006)
            vm.pc = 56010
            value = memory.load(cells.value(7493), 1)
            vm._write(7495, value, 4, 'high.load')
            tick(56010)
            vm.pc = 56014
            pointer = cells.value(7492)
            value = memory.load(cells.pointer(7495), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(56014)
            vm.pc = 56016
            vm._jump(1351)
            continue
        if vm.block == 1351:
            tick(56016)
            vm.pc = 56021
            cells.copy_q_clear_owned(135, 7496)
            tick(56021)
            vm.pc = 56026
            cells.copy_q_clear_owned(65, 7497)
            tick(56026)
            vm.pc = 56030
            pointer = cells.value(65)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(56030)
            vm.pc = 56032
            vm._jump(1352)
            continue
        if vm.block == 1352:
            tick(56032)
            _phi(vm, 56032, (7498, 2, 145, 1351, 7499, 1353))
            tick(56039)
            vm.pc = 56044
            vm._write(7500, int(cells.value(7498) < cells.value(166)), 4, 'once18.unsigned_q')
            tick(56044)
            vm.pc = 56048
            vm._jump(1354 if cells.value(7500) != 0 else 1355)
            continue
        if vm.block == 1354:
            tick(56048)
            vm.pc = 56053
            vm._write(7501, cells.value(7498) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(56053)
            vm.pc = 56054
            tick(56054)
            vm.pc = 56057
            vm.auxiliary = (0, 1364344834)
            tick(56057)
            vm.pc = 56062
            vm._write(7502, memory.load(cells.pointer(7501), 2, signed=True) + memory.load(cells.pointer(5408), 2, signed=True), 8, 'once1.integer')
            tick(56062)
            vm.pc = 56067
            value = memory.load(cells.pointer(7502), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(7503, value >> (count & 31), 4, 'once8.logical_shift')
            tick(56067)
            _pointer(vm, 56067, 91, 112, 7504, (145, 391))
            tick(56075)
            vm.pc = 56079
            value = memory.load(cells.value(7504), 8)
            vm._write(7505, value, 8, 'high.load')
            tick(56079)
            vm.pc = 56084
            vm._write(7506, cells.value(7505) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(56084)
            vm.pc = 56089
            vm._write(7507, memory.load(cells.pointer(7506), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(56089)
            vm.pc = 56092
            vm.auxiliary = (0, 24135)
            tick(56092)
            vm.pc = 56098
            vm._write(7508, memory.load(cells.pointer(7503), 2, signed=True) ^ memory.load(cells.pointer(7507), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(56098)
            vm.pc = 56103
            _convert(vm, 8, 7508, 7509)
            tick(56103)
            _pointer(vm, 56103, 91, 112, 7510, (145, 311, 7509))
            tick(56112)
            vm.pc = 56116
            value = memory.load(cells.value(7510), 8)
            vm._write(7511, value, 8, 'high.load')
            tick(56116)
            vm.pc = 56119
            vm.auxiliary = (0, 1736612547)
            tick(56119)
            vm.pc = 56124
            vm._write(7512, int(memory.load(cells.pointer(7511), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(56124)
            vm.pc = 56128
            vm._jump(1356 if cells.value(7512) != 0 else 1357)
            continue
        if vm.block == 1357:
            tick(56128)
            vm.pc = 56133
            value = memory.load(cells.pointer(7505), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(7513, value >> (count & 63), 8, 'once8.logical_shift')
            tick(56133)
            vm.pc = 56138
            vm._write(7514, cells.value(7513) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(56138)
            vm.pc = 56139
            tick(56139)
            vm.pc = 56142
            vm.auxiliary = (0, 52532)
            tick(56142)
            vm.pc = 56148
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(7515, memory.load(cells.pointer(7514), 2, signed=True) ^ memory.load(cells.pointer(7502), 2, signed=True), 8, 'typed.selector5.q')
            tick(56148)
            vm.pc = 56151
            vm.auxiliary = (0, 25422)
            tick(56151)
            vm.pc = 56156
            vm._write(7516, memory.load(cells.pointer(7515), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(56156)
            vm.pc = 56161
            _convert(vm, 8, 7516, 7517)
            tick(56161)
            _pointer(vm, 56161, 78, 7511, 7518, (7517,))
            tick(56168)
            vm.pc = 56172
            value = memory.load(cells.value(7518), 8)
            vm._write(7519, value, 8, 'high.load')
            tick(56172)
            vm.pc = 56175
            vm.auxiliary = (0, 1592919251)
            tick(56175)
            _equal(vm, 56180, 8, 7519, 857, 7520)
            tick(56180)
            vm.pc = 56184
            vm._jump(1356 if cells.value(7520) != 0 else 1358)
            continue
        if vm.block == 1358:
            tick(56184)
            _pointer(vm, 56184, 79, 7519, 7521, (145, 269))
            tick(56192)
            vm.pc = 56196
            value = memory.load(cells.value(7521), 2)
            vm._write(7522, value, 4, 'high.load')
            tick(56196)
            vm.pc = 56197
            tick(56197)
            vm.pc = 56200
            vm.auxiliary = (0, 1237451987)
            tick(56200)
            _equal(vm, 56205, 2, 7522, 7502, 7523)
            tick(56205)
            vm.pc = 56209
            vm._jump(1359 if cells.value(7523) != 0 else 1356)
            continue
        if vm.block == 1359:
            tick(56209)
            _pointer(vm, 56209, 79, 7519, 7524, (145, 360))
            tick(56217)
            vm.pc = 56221
            value = memory.load(cells.value(7524), 4)
            vm._write(7525, value, 4, 'L5.unsigned_load')
            tick(56221)
            _pointer(vm, 56221, 79, 7519, 7526, (145, 158))
            tick(56229)
            vm.pc = 56233
            value = memory.load(cells.value(7526), 4)
            vm._write(7527, value, 4, 'high.load')
            tick(56233)
            vm.pc = 56234
            tick(56234)
            vm.pc = 56237
            vm.auxiliary = (0, 59695)
            tick(56237)
            vm.pc = 56243
            vm._write(7528, memory.load(cells.pointer(7527), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(56243)
            vm.pc = 56246
            vm.auxiliary = (0, 2127876612)
            tick(56246)
            vm.pc = 56251
            vm._write(7529, memory.load(cells.pointer(7528), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(56251)
            _pointer(vm, 56251, 79, 7519, 7530, (145, 269))
            tick(56259)
            vm.pc = 56263
            value = memory.load(cells.value(7530), 2)
            vm._write(7531, value, 4, 'high.load')
            tick(56263)
            vm.pc = 56268
            _convert(vm, 4, 7531, 7532)
            tick(56268)
            vm.pc = 56271
            vm.auxiliary = (0, 15927)
            tick(56271)
            vm.pc = 56277
            vm._write(7533, memory.load(cells.pointer(7529), 4, signed=True) ^ memory.load(cells.pointer(7532), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(56277)
            vm.pc = 56280
            vm.auxiliary = (0, 207024643)
            tick(56280)
            vm.pc = 56285
            vm._write(7534, memory.load(cells.pointer(7533), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(56285)
            _pointer(vm, 56285, 79, 7519, 7535, (145, 311))
            tick(56293)
            vm.pc = 56297
            value = memory.load(cells.value(7535), 8)
            vm._write(7536, value, 8, 'high.load')
            tick(56297)
            vm.pc = 56302
            cells.copy_q_clear_owned(7536, 7537)
            tick(56302)
            vm.pc = 56307
            vm._write(7538, cells.value(7537) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(56307)
            vm.pc = 56312
            vm._write(7539, memory.load(cells.pointer(7534), 4, signed=True) ^ memory.load(cells.pointer(7538), 4, signed=True), 8, 'L14.binary_q')
            tick(56312)
            vm.pc = 56315
            vm.auxiliary = (0, 317669892)
            tick(56315)
            vm.pc = 56320
            vm._write(7540, memory.load(cells.pointer(7539), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(56320)
            vm.pc = 56325
            value = memory.load(cells.pointer(7537), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(7541, value >> (count & 63), 8, 'once8.logical_shift')
            tick(56325)
            vm.pc = 56330
            vm._write(7542, cells.value(7541) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(56330)
            vm.pc = 56333
            vm.auxiliary = (0, 19462)
            tick(56333)
            vm.pc = 56339
            vm._write(7543, memory.load(cells.pointer(7540), 4, signed=True) ^ memory.load(cells.pointer(7542), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(56339)
            vm.pc = 56342
            vm.auxiliary = (0, 1611674115)
            tick(56342)
            vm.pc = 56347
            vm._write(7544, memory.load(cells.pointer(7543), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(56347)
            vm.pc = 56352
            vm._write(7545, cells.value(7505) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(56352)
            vm.pc = 56355
            vm.auxiliary = (0, 18796)
            tick(56355)
            vm.pc = 56361
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(7546, memory.load(cells.pointer(7544), 4, signed=True) ^ memory.load(cells.pointer(7545), 4, signed=True), 8, 'typed.selector5.q')
            tick(56361)
            vm.pc = 56364
            vm.auxiliary = (0, 1876509188)
            tick(56364)
            vm.pc = 56369
            vm._write(7547, memory.load(cells.pointer(7546), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(56369)
            vm.pc = 56374
            value = memory.load(cells.pointer(7505), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(7548, value >> (count & 63), 8, 'once8.logical_shift')
            tick(56374)
            vm.pc = 56379
            vm._write(7549, cells.value(7548) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(56379)
            vm.pc = 56382
            vm.auxiliary = (0, 7749)
            tick(56382)
            vm.pc = 56388
            vm._write(7550, memory.load(cells.pointer(7547), 4, signed=True) ^ memory.load(cells.pointer(7549), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(56388)
            vm.pc = 56391
            vm.auxiliary = (0, 708375044)
            tick(56391)
            vm.pc = 56396
            vm._write(7551, memory.load(cells.pointer(7550), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(56396)
            vm.pc = 56400
            value = memory.load(cells.value(7536), 1)
            vm._write(7552, value, 4, 'L5.unsigned_load')
            tick(56400)
            vm.pc = 56405
            _convert(vm, 4, 7552, 7553)
            tick(56405)
            vm.pc = 56408
            vm.auxiliary = (0, 35919)
            tick(56408)
            vm.pc = 56414
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(7554, memory.load(cells.pointer(7551), 4, signed=True) ^ memory.load(cells.pointer(7553), 4, signed=True), 8, 'typed.selector5.q')
            tick(56414)
            vm.pc = 56417
            vm.auxiliary = (0, 368722436)
            tick(56417)
            vm.pc = 56422
            vm._write(7555, memory.load(cells.pointer(7554), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(56422)
            vm.pc = 56425
            vm.auxiliary = (0, 269658307)
            tick(56425)
            vm.pc = 56430
            vm._write(7556, int(memory.load(cells.pointer(7525), 4, signed=True) == memory.load(cells.pointer(7555), 4, signed=True)), 4, 'once17.integer')
            tick(56430)
            vm.pc = 56434
            vm._jump(1356 if cells.value(7556) != 0 else 1360)
            continue
        if vm.block == 1360:
            tick(56434)
            vm.pc = 56438
            pointer = cells.value(7524)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(56438)
            vm.pc = 56440
            vm._jump(1356)
            continue
        if vm.block == 1356:
            tick(56440)
            _phi(vm, 56440, (7557, 5, 857, 1354, 857, 1358, 7519, 1359, 7519, 1360, 7519, 1357))
            tick(56453)
            vm.pc = 56454
            tick(56454)
            vm.pc = 56457
            vm.auxiliary = (0, 639827907)
            tick(56457)
            vm.pc = 56462
            vm._write(7558, int(memory.load(cells.pointer(7557), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(56462)
            vm.pc = 56466
            vm._jump(1361 if cells.value(7558) != 0 else 1362)
            continue
        if vm.block == 1362:
            tick(56466)
            _pointer(vm, 56466, 79, 7557, 7559, (145, 311))
            tick(56474)
            vm.pc = 56478
            value = memory.load(cells.value(7559), 8)
            vm._write(7560, value, 8, 'high.load')
            tick(56478)
            vm.pc = 56482
            value = memory.load(cells.value(7560), 1)
            vm._write(7561, value, 4, 'high.load')
            tick(56482)
            _pointer(vm, 56482, 1, 7497, 7562, (7498,))
            tick(56489)
            vm.pc = 56493
            pointer = cells.value(7562)
            value = memory.load(cells.pointer(7561), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(56493)
            vm.pc = 56495
            vm._jump(1353)
            continue
        if vm.block == 1361:
            tick(56495)
            _pointer(vm, 56495, 1, 7497, 7563, (7498,))
            tick(56502)
            vm.pc = 56506
            pointer = cells.value(7563)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(56506)
            vm.pc = 56508
            vm._jump(1353)
            continue
        if vm.block == 1353:
            tick(56508)
            vm.pc = 56509
            tick(56509)
            vm.pc = 56512
            vm.auxiliary = (0, 1863020546)
            tick(56512)
            vm.pc = 56517
            vm._write(7499, memory.load(cells.pointer(7498), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(56517)
            vm.pc = 56519
            vm._jump(1352)
            continue
        if vm.block == 1355:
            tick(56519)
            vm.pc = 56523
            value = memory.load(cells.value(65), 8)
            vm._write(7564, value, 8, 'high.load')
            tick(56523)
            vm.pc = 56528
            vm._write(7565, cells.value(7564) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(56528)
            vm.pc = 56532
            pointer = cells.value(135)
            value = memory.load(cells.pointer(7565), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(56532)
            _pointer(vm, 56532, 70, 103, 7566, (145, 203))
            tick(56540)
            vm.pc = 56545
            cells.copy_q_clear_owned(7566, 7567)
            tick(56545)
            vm.pc = 56550
            vm._write(7568, memory.load(cells.pointer(7567), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(56550)
            _pointer(vm, 56550, 1, 7496, 7569, (163,))
            tick(56557)
            vm.pc = 56561
            value = memory.load(cells.value(7496), 1)
            vm._write(7570, value, 4, 'high.load')
            tick(56561)
            _pointer(vm, 56561, 1, 7566, 7571, (163,))
            tick(56568)
            vm.pc = 56572
            pointer = cells.value(7566)
            value = memory.load(cells.pointer(7570), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(56572)
            vm.pc = 56577
            cells.copy_q_clear_owned(7571, 7572)
            tick(56577)
            vm.pc = 56578
            tick(56578)
            vm.pc = 56581
            vm.auxiliary = (0, 18213)
            tick(56581)
            vm.pc = 56586
            vm._write(7573, memory.load(cells.pointer(7572), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(56586)
            vm.pc = 56589
            vm.auxiliary = (0, 1553073652)
            tick(56589)
            vm.pc = 56594
            vm._write(7574, int(memory.load(cells.pointer(7573), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(56594)
            vm.pc = 56598
            vm._jump(1363 if cells.value(7574) != 0 else 1364)
            continue
        if vm.block == 1363:
            tick(56598)
            _pointer(vm, 56598, 1, 7569, 7575, (163,))
            tick(56605)
            vm.pc = 56609
            value = memory.load(cells.value(7569), 1)
            vm._write(7576, value, 4, 'high.load')
            tick(56609)
            _pointer(vm, 56609, 1, 7571, 7577, (163,))
            tick(56616)
            vm.pc = 56620
            pointer = cells.value(7571)
            value = memory.load(cells.pointer(7576), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(56620)
            vm.pc = 56622
            vm._jump(1364)
            continue
        if vm.block == 1364:
            tick(56622)
            _phi(vm, 56622, (7578, 2, 158, 1363, 269, 1355))
            tick(56629)
            _phi(vm, 56629, (7579, 2, 7577, 1363, 7571, 1355))
            tick(56636)
            _phi(vm, 56636, (7580, 2, 7575, 1363, 7569, 1355))
            tick(56643)
            vm.pc = 56648
            cells.copy_q_clear_owned(7579, 7581)
            tick(56648)
            vm.pc = 56653
            vm._write(7582, memory.load(cells.pointer(7581), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(56653)
            vm.pc = 56654
            tick(56654)
            vm.pc = 56657
            vm.auxiliary = (0, 271776708)
            tick(56657)
            vm.pc = 56662
            vm._write(7583, int(memory.load(cells.pointer(7582), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(56662)
            vm.pc = 56665
            vm.auxiliary = (0, 1434625846)
            tick(56665)
            vm.pc = 56670
            vm._write(7584, int(memory.load(cells.pointer(7578), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(56670)
            vm.pc = 56673
            vm.auxiliary = (0, 5204)
            tick(56673)
            vm.pc = 56678
            vm._write(7585, memory.load(cells.pointer(7583), 1, signed=True) & memory.load(cells.pointer(7584), 1, signed=True), 8, 'typed.selector1.q')
            tick(56678)
            vm.pc = 56682
            vm._jump(1365 if cells.value(7585) != 0 else 1366)
            continue
        if vm.block == 1365:
            tick(56682)
            _pointer(vm, 56682, 1, 7580, 7586, (163,))
            tick(56689)
            vm.pc = 56693
            value = memory.load(cells.value(7580), 1)
            vm._write(7587, value, 4, 'high.load')
            tick(56693)
            _pointer(vm, 56693, 1, 7579, 7588, (163,))
            tick(56700)
            vm.pc = 56704
            pointer = cells.value(7579)
            value = memory.load(cells.pointer(7587), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(56704)
            vm.pc = 56705
            tick(56705)
            vm.pc = 56708
            vm.auxiliary = (0, 814170114)
            tick(56708)
            vm.pc = 56713
            vm._write(7589, memory.load(cells.pointer(7578), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(56713)
            vm.pc = 56715
            vm._jump(1366)
            continue
        if vm.block == 1366:
            tick(56715)
            _phi(vm, 56715, (7590, 2, 7589, 1365, 7578, 1364))
            tick(56722)
            _phi(vm, 56722, (7591, 2, 7588, 1365, 7579, 1364))
            tick(56729)
            _phi(vm, 56729, (7592, 2, 7586, 1365, 7580, 1364))
            tick(56736)
            vm.pc = 56741
            cells.copy_q_clear_owned(7591, 7593)
            tick(56741)
            vm.pc = 56746
            cells.copy_q_clear_owned(7592, 7594)
            tick(56746)
            vm.pc = 56747
            tick(56747)
            vm.pc = 56750
            vm.auxiliary = (0, 955427622)
            tick(56750)
            vm.pc = 56755
            vm._write(7595, int(memory.load(cells.pointer(7590), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(56755)
            vm.pc = 56759
            vm._jump(1367 if cells.value(7595) != 0 else 1368)
            continue
        if vm.block == 1367:
            tick(56759)
            _pointer(vm, 56759, 1, 7592, 7596, (172,))
            tick(56766)
            vm.pc = 56771
            cells.copy_q_clear_owned(7596, 7597)
            tick(56771)
            vm.pc = 56775
            value = memory.load(cells.value(7594), 4)
            vm._write(7598, value, 4, 'L5.unsigned_load')
            tick(56775)
            _pointer(vm, 56775, 1, 7591, 7599, (172,))
            tick(56782)
            vm.pc = 56787
            cells.copy_q_clear_owned(7599, 7600)
            tick(56787)
            vm.pc = 56791
            pointer = cells.value(7593)
            value = memory.load(cells.pointer(7598), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(56791)
            vm.pc = 56792
            tick(56792)
            vm.pc = 56795
            vm.auxiliary = (0, 263983106)
            tick(56795)
            vm.pc = 56800
            vm._write(7601, memory.load(cells.pointer(7590), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(56800)
            vm.pc = 56802
            vm._jump(1368)
            continue
        if vm.block == 1368:
            tick(56802)
            _phi(vm, 56802, (7602, 2, 7601, 1367, 7590, 1366))
            tick(56809)
            _phi(vm, 56809, (7603, 2, 7600, 1367, 7593, 1366))
            tick(56816)
            _phi(vm, 56816, (7604, 2, 7597, 1367, 7594, 1366))
            tick(56823)
            vm.pc = 56824
            tick(56824)
            vm.pc = 56827
            vm.auxiliary = (0, 1101163590)
            tick(56827)
            vm.pc = 56832
            vm._write(7605, int(memory.load(cells.pointer(7602), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(56832)
            vm.pc = 56836
            vm._jump(1369 if cells.value(7605) != 0 else 1370)
            continue
        if vm.block == 1369:
            tick(56836)
            _pointer(vm, 56836, 3, 7604, 7606, (163,))
            tick(56843)
            vm.pc = 56847
            value = memory.load(cells.value(7604), 4)
            vm._write(7607, value, 4, 'high.load')
            tick(56847)
            _pointer(vm, 56847, 3, 7603, 7608, (163,))
            tick(56854)
            vm.pc = 56858
            pointer = cells.value(7603)
            value = memory.load(cells.pointer(7607), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(56858)
            vm.pc = 56859
            tick(56859)
            vm.pc = 56862
            vm.auxiliary = (0, 1119862786)
            tick(56862)
            vm.pc = 56867
            vm._write(7609, memory.load(cells.pointer(7602), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(56867)
            vm.pc = 56869
            vm._jump(1370)
            continue
        if vm.block == 1370:
            tick(56869)
            _phi(vm, 56869, (7610, 2, 7609, 1369, 7602, 1368))
            tick(56876)
            _phi(vm, 56876, (7611, 2, 7608, 1369, 7603, 1368))
            tick(56883)
            _phi(vm, 56883, (7612, 2, 7606, 1369, 7604, 1368))
            tick(56890)
            vm.pc = 56891
            tick(56891)
            vm.pc = 56894
            vm.auxiliary = (0, 1840446614)
            tick(56894)
            vm.pc = 56899
            vm._write(7613, int(memory.load(cells.pointer(7610), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(56899)
            vm.pc = 56903
            vm._jump(1371 if cells.value(7613) != 0 else 1372)
            continue
        if vm.block == 1371:
            tick(56903)
            _pointer(vm, 56903, 3, 7612, 7614, (163,))
            tick(56910)
            vm.pc = 56914
            value = memory.load(cells.value(7612), 4)
            vm._write(7615, value, 4, 'L5.unsigned_load')
            tick(56914)
            _pointer(vm, 56914, 3, 7611, 7616, (163,))
            tick(56921)
            vm.pc = 56925
            pointer = cells.value(7611)
            value = memory.load(cells.pointer(7615), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(56925)
            vm.pc = 56926
            tick(56926)
            vm.pc = 56929
            vm.auxiliary = (0, 464150530)
            tick(56929)
            vm.pc = 56934
            vm._write(7617, memory.load(cells.pointer(7610), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(56934)
            vm.pc = 56936
            vm._jump(1372)
            continue
        if vm.block == 1372:
            tick(56936)
            _phi(vm, 56936, (7618, 2, 7617, 1371, 7610, 1370))
            tick(56943)
            _phi(vm, 56943, (7619, 2, 7616, 1371, 7611, 1370))
            tick(56950)
            _phi(vm, 56950, (7620, 2, 7614, 1371, 7612, 1370))
            tick(56957)
            vm.pc = 56962
            cells.copy_q_clear_owned(7619, 7621)
            tick(56962)
            vm.pc = 56967
            cells.copy_q_clear_owned(7620, 7622)
            tick(56967)
            vm.pc = 56968
            tick(56968)
            vm.pc = 56971
            vm.auxiliary = (0, 883082726)
            tick(56971)
            vm.pc = 56976
            vm._write(7623, int(memory.load(cells.pointer(7618), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(56976)
            vm.pc = 56980
            vm._jump(1373 if cells.value(7623) != 0 else 1374)
            continue
        if vm.block == 1373:
            tick(56980)
            _pointer(vm, 56980, 1, 7622, 7624, (163,))
            tick(56987)
            vm.pc = 56991
            value = memory.load(cells.value(7622), 1)
            vm._write(7625, value, 4, 'L5.unsigned_load')
            tick(56991)
            _pointer(vm, 56991, 1, 7621, 7626, (163,))
            tick(56998)
            vm.pc = 57002
            pointer = cells.value(7621)
            value = memory.load(cells.pointer(7625), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(57002)
            vm.pc = 57003
            tick(57003)
            vm.pc = 57006
            vm.auxiliary = (0, 857706497)
            tick(57006)
            vm.pc = 57011
            vm._write(7627, memory.load(cells.pointer(7618), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(57011)
            vm.pc = 57013
            vm._jump(1374)
            continue
        if vm.block == 1374:
            tick(57013)
            _phi(vm, 57013, (7628, 2, 7627, 1373, 7618, 1372))
            tick(57020)
            _phi(vm, 57020, (7629, 2, 7626, 1373, 7621, 1372))
            tick(57027)
            _phi(vm, 57027, (7630, 2, 7624, 1373, 7622, 1372))
            tick(57034)
            vm.pc = 57035
            tick(57035)
            vm.pc = 57038
            vm.auxiliary = (0, 641863990)
            tick(57038)
            vm.pc = 57043
            vm._write(7631, int(memory.load(cells.pointer(7628), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(57043)
            vm.pc = 57047
            vm._jump(1375 if cells.value(7631) != 0 else 1376)
            continue
        if vm.block == 1375:
            tick(57047)
            _pointer(vm, 57047, 1, 7630, 7632, (163,))
            tick(57054)
            vm.pc = 57058
            value = memory.load(cells.value(7630), 1)
            vm._write(7633, value, 4, 'high.load')
            tick(57058)
            _pointer(vm, 57058, 1, 7629, 7634, (163,))
            tick(57065)
            vm.pc = 57069
            pointer = cells.value(7629)
            value = memory.load(cells.pointer(7633), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57069)
            vm.pc = 57070
            tick(57070)
            vm.pc = 57073
            vm.auxiliary = (0, 1718661122)
            tick(57073)
            vm.pc = 57078
            vm._write(7635, memory.load(cells.pointer(7628), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(57078)
            vm.pc = 57080
            vm._jump(1376)
            continue
        if vm.block == 1376:
            tick(57080)
            _phi(vm, 57080, (7636, 2, 7635, 1375, 7628, 1374))
            tick(57087)
            _phi(vm, 57087, (7637, 2, 7634, 1375, 7629, 1374))
            tick(57094)
            _phi(vm, 57094, (7638, 2, 7632, 1375, 7630, 1374))
            tick(57101)
            vm.pc = 57102
            tick(57102)
            vm.pc = 57105
            vm.auxiliary = (0, 1831995846)
            tick(57105)
            vm.pc = 57110
            vm._write(7639, int(memory.load(cells.pointer(7636), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(57110)
            vm.pc = 57114
            vm._jump(1377 if cells.value(7639) != 0 else 1378)
            continue
        if vm.block == 1377:
            tick(57114)
            _pointer(vm, 57114, 1, 7638, 7640, (163,))
            tick(57121)
            vm.pc = 57125
            value = memory.load(cells.value(7638), 1)
            vm._write(7641, value, 4, 'high.load')
            tick(57125)
            _pointer(vm, 57125, 1, 7637, 7642, (163,))
            tick(57132)
            vm.pc = 57136
            pointer = cells.value(7637)
            value = memory.load(cells.pointer(7641), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57136)
            vm.pc = 57138
            vm._jump(1378)
            continue
        if vm.block == 1378:
            tick(57138)
            _phi(vm, 57138, (7643, 2, 7642, 1377, 7637, 1376))
            tick(57145)
            _phi(vm, 57145, (7644, 2, 7640, 1377, 7638, 1376))
            tick(57152)
            vm.pc = 57153
            tick(57153)
            vm.pc = 57156
            vm.auxiliary = (0, 289553734)
            tick(57156)
            vm.pc = 57161
            vm._write(7645, int(memory.load(cells.pointer(7636), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(57161)
            vm.pc = 57165
            vm._jump(1379 if cells.value(7645) != 0 else 1380)
            continue
        if vm.block == 1379:
            tick(57165)
            vm.pc = 57169
            value = memory.load(cells.value(7644), 1)
            vm._write(7646, value, 4, 'high.load')
            tick(57169)
            vm.pc = 57173
            pointer = cells.value(7643)
            value = memory.load(cells.pointer(7646), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57173)
            vm.pc = 57175
            vm._jump(1380)
            continue
        if vm.block == 1380:
            tick(57175)
            _pointer(vm, 57175, 70, 103, 7647, (145, 208))
            tick(57183)
            vm.pc = 57188
            cells.copy_q_clear_owned(7647, 7648)
            tick(57188)
            vm.pc = 57193
            vm._write(7649, memory.load(cells.pointer(7648), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(57193)
            _pointer(vm, 57193, 1, 1766, 7650, (163,))
            tick(57200)
            vm.pc = 57204
            value = memory.load(cells.value(1766), 1)
            vm._write(7651, value, 4, 'high.load')
            tick(57204)
            _pointer(vm, 57204, 1, 7647, 7652, (163,))
            tick(57211)
            vm.pc = 57215
            pointer = cells.value(7647)
            value = memory.load(cells.pointer(7651), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57215)
            vm.pc = 57220
            cells.copy_q_clear_owned(7652, 7653)
            tick(57220)
            vm.pc = 57225
            vm._write(7654, memory.load(cells.pointer(7653), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(57225)
            vm.pc = 57226
            tick(57226)
            vm.pc = 57229
            vm.auxiliary = (0, 1477579140)
            tick(57229)
            vm.pc = 57234
            vm._write(7655, int(memory.load(cells.pointer(7654), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(57234)
            vm.pc = 57238
            vm._jump(1381 if cells.value(7655) != 0 else 1382)
            continue
        if vm.block == 1381:
            tick(57238)
            _pointer(vm, 57238, 1, 7650, 7656, (163,))
            tick(57245)
            vm.pc = 57249
            value = memory.load(cells.value(7650), 1)
            vm._write(7657, value, 4, 'high.load')
            tick(57249)
            _pointer(vm, 57249, 1, 7652, 7658, (163,))
            tick(57256)
            vm.pc = 57260
            pointer = cells.value(7652)
            value = memory.load(cells.pointer(7657), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57260)
            vm.pc = 57262
            vm._jump(1382)
            continue
        if vm.block == 1382:
            tick(57262)
            _phi(vm, 57262, (7659, 2, 328, 1381, 476, 1380))
            tick(57269)
            _phi(vm, 57269, (7660, 2, 7658, 1381, 7652, 1380))
            tick(57276)
            _phi(vm, 57276, (7661, 2, 7656, 1381, 7650, 1380))
            tick(57283)
            vm.pc = 57288
            cells.copy_q_clear_owned(7660, 7662)
            tick(57288)
            vm.pc = 57293
            vm._write(7663, memory.load(cells.pointer(7662), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(57293)
            vm.pc = 57294
            tick(57294)
            vm.pc = 57297
            vm.auxiliary = (0, 1085431556)
            tick(57297)
            vm.pc = 57302
            vm._write(7664, int(memory.load(cells.pointer(7663), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(57302)
            vm.pc = 57305
            vm.auxiliary = (0, 1496490790)
            tick(57305)
            vm.pc = 57310
            vm._write(7665, int(memory.load(cells.pointer(7659), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(57310)
            vm.pc = 57315
            vm._write(7666, memory.load(cells.pointer(7664), 1, signed=True) & memory.load(cells.pointer(7665), 1, signed=True), 8, 'L13.binary_q')
            tick(57315)
            vm.pc = 57319
            vm._jump(1383 if cells.value(7666) != 0 else 1384)
            continue
        if vm.block == 1383:
            tick(57319)
            _pointer(vm, 57319, 1, 7661, 7667, (163,))
            tick(57326)
            vm.pc = 57330
            value = memory.load(cells.value(7661), 1)
            vm._write(7668, value, 4, 'high.load')
            tick(57330)
            _pointer(vm, 57330, 1, 7660, 7669, (163,))
            tick(57337)
            vm.pc = 57341
            pointer = cells.value(7660)
            value = memory.load(cells.pointer(7668), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57341)
            vm.pc = 57342
            tick(57342)
            vm.pc = 57345
            vm.auxiliary = (0, 615227394)
            tick(57345)
            vm.pc = 57350
            vm._write(7670, memory.load(cells.pointer(7659), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(57350)
            vm.pc = 57352
            vm._jump(1384)
            continue
        if vm.block == 1384:
            tick(57352)
            _phi(vm, 57352, (7671, 2, 7670, 1383, 7659, 1382))
            tick(57359)
            _phi(vm, 57359, (7672, 2, 7669, 1383, 7660, 1382))
            tick(57366)
            _phi(vm, 57366, (7673, 2, 7667, 1383, 7661, 1382))
            tick(57373)
            vm.pc = 57378
            cells.copy_q_clear_owned(7672, 7674)
            tick(57378)
            vm.pc = 57383
            cells.copy_q_clear_owned(7673, 7675)
            tick(57383)
            vm.pc = 57384
            tick(57384)
            vm.pc = 57387
            vm.auxiliary = (0, 448934054)
            tick(57387)
            vm.pc = 57392
            vm._write(7676, int(memory.load(cells.pointer(7671), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(57392)
            vm.pc = 57396
            vm._jump(1385 if cells.value(7676) != 0 else 1386)
            continue
        if vm.block == 1385:
            tick(57396)
            _pointer(vm, 57396, 1, 7673, 7677, (172,))
            tick(57403)
            vm.pc = 57408
            cells.copy_q_clear_owned(7677, 7678)
            tick(57408)
            vm.pc = 57412
            value = memory.load(cells.value(7675), 4)
            vm._write(7679, value, 4, 'high.load')
            tick(57412)
            _pointer(vm, 57412, 1, 7672, 7680, (172,))
            tick(57419)
            vm.pc = 57424
            cells.copy_q_clear_owned(7680, 7681)
            tick(57424)
            vm.pc = 57428
            pointer = cells.value(7674)
            value = memory.load(cells.pointer(7679), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(57428)
            vm.pc = 57429
            tick(57429)
            vm.pc = 57432
            vm.auxiliary = (0, 820768769)
            tick(57432)
            vm.pc = 57437
            vm._write(7682, memory.load(cells.pointer(7671), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(57437)
            vm.pc = 57439
            vm._jump(1386)
            continue
        if vm.block == 1386:
            tick(57439)
            _phi(vm, 57439, (7683, 2, 7682, 1385, 7671, 1384))
            tick(57446)
            _phi(vm, 57446, (7684, 2, 7681, 1385, 7674, 1384))
            tick(57453)
            _phi(vm, 57453, (7685, 2, 7678, 1385, 7675, 1384))
            tick(57460)
            vm.pc = 57461
            tick(57461)
            vm.pc = 57464
            vm.auxiliary = (0, 629312982)
            tick(57464)
            vm.pc = 57469
            vm._write(7686, int(memory.load(cells.pointer(7683), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(57469)
            vm.pc = 57473
            vm._jump(1387 if cells.value(7686) != 0 else 1388)
            continue
        if vm.block == 1387:
            tick(57473)
            _pointer(vm, 57473, 3, 7685, 7687, (163,))
            tick(57480)
            vm.pc = 57484
            value = memory.load(cells.value(7685), 4)
            vm._write(7688, value, 4, 'high.load')
            tick(57484)
            _pointer(vm, 57484, 3, 7684, 7689, (163,))
            tick(57491)
            vm.pc = 57495
            pointer = cells.value(7684)
            value = memory.load(cells.pointer(7688), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(57495)
            vm.pc = 57496
            tick(57496)
            vm.pc = 57499
            vm.auxiliary = (0, 517922817)
            tick(57499)
            vm.pc = 57504
            vm._write(7690, memory.load(cells.pointer(7683), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(57504)
            vm.pc = 57506
            vm._jump(1388)
            continue
        if vm.block == 1388:
            tick(57506)
            _phi(vm, 57506, (7691, 2, 7690, 1387, 7683, 1386))
            tick(57513)
            _phi(vm, 57513, (7692, 2, 7689, 1387, 7684, 1386))
            tick(57520)
            _phi(vm, 57520, (7693, 2, 7687, 1387, 7685, 1386))
            tick(57527)
            vm.pc = 57528
            tick(57528)
            vm.pc = 57531
            vm.auxiliary = (0, 1556266790)
            tick(57531)
            vm.pc = 57536
            vm._write(7694, int(memory.load(cells.pointer(7691), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(57536)
            vm.pc = 57540
            vm._jump(1389 if cells.value(7694) != 0 else 1390)
            continue
        if vm.block == 1389:
            tick(57540)
            _pointer(vm, 57540, 3, 7693, 7695, (163,))
            tick(57547)
            vm.pc = 57551
            value = memory.load(cells.value(7693), 4)
            vm._write(7696, value, 4, 'high.load')
            tick(57551)
            _pointer(vm, 57551, 3, 7692, 7697, (163,))
            tick(57558)
            vm.pc = 57562
            pointer = cells.value(7692)
            value = memory.load(cells.pointer(7696), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(57562)
            vm.pc = 57563
            tick(57563)
            vm.pc = 57566
            vm.auxiliary = (0, 1073332225)
            tick(57566)
            vm.pc = 57571
            vm._write(7698, memory.load(cells.pointer(7691), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(57571)
            vm.pc = 57573
            vm._jump(1390)
            continue
        if vm.block == 1390:
            tick(57573)
            _phi(vm, 57573, (7699, 2, 7698, 1389, 7691, 1388))
            tick(57580)
            _phi(vm, 57580, (7700, 2, 7697, 1389, 7692, 1388))
            tick(57587)
            _phi(vm, 57587, (7701, 2, 7695, 1389, 7693, 1388))
            tick(57594)
            vm.pc = 57599
            cells.copy_q_clear_owned(7700, 7702)
            tick(57599)
            vm.pc = 57604
            cells.copy_q_clear_owned(7701, 7703)
            tick(57604)
            vm.pc = 57605
            tick(57605)
            vm.pc = 57608
            vm.auxiliary = (0, 2002952230)
            tick(57608)
            vm.pc = 57613
            vm._write(7704, int(memory.load(cells.pointer(7699), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(57613)
            vm.pc = 57617
            vm._jump(1391 if cells.value(7704) != 0 else 1392)
            continue
        if vm.block == 1391:
            tick(57617)
            _pointer(vm, 57617, 1, 7703, 7705, (163,))
            tick(57624)
            vm.pc = 57628
            value = memory.load(cells.value(7703), 1)
            vm._write(7706, value, 4, 'L5.unsigned_load')
            tick(57628)
            _pointer(vm, 57628, 1, 7702, 7707, (163,))
            tick(57635)
            vm.pc = 57639
            pointer = cells.value(7702)
            value = memory.load(cells.pointer(7706), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57639)
            vm.pc = 57640
            tick(57640)
            vm.pc = 57643
            vm.auxiliary = (0, 813707265)
            tick(57643)
            vm.pc = 57648
            vm._write(7708, memory.load(cells.pointer(7699), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(57648)
            vm.pc = 57650
            vm._jump(1392)
            continue
        if vm.block == 1392:
            tick(57650)
            _phi(vm, 57650, (7709, 2, 7708, 1391, 7699, 1390))
            tick(57657)
            _phi(vm, 57657, (7710, 2, 7707, 1391, 7702, 1390))
            tick(57664)
            _phi(vm, 57664, (7711, 2, 7705, 1391, 7703, 1390))
            tick(57671)
            vm.pc = 57672
            tick(57672)
            vm.pc = 57675
            vm.auxiliary = (0, 803378966)
            tick(57675)
            vm.pc = 57680
            vm._write(7712, int(memory.load(cells.pointer(7709), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(57680)
            vm.pc = 57684
            vm._jump(1393 if cells.value(7712) != 0 else 1394)
            continue
        if vm.block == 1393:
            tick(57684)
            _pointer(vm, 57684, 1, 7711, 7713, (163,))
            tick(57691)
            vm.pc = 57695
            value = memory.load(cells.value(7711), 1)
            vm._write(7714, value, 4, 'high.load')
            tick(57695)
            _pointer(vm, 57695, 1, 7710, 7715, (163,))
            tick(57702)
            vm.pc = 57706
            pointer = cells.value(7710)
            value = memory.load(cells.pointer(7714), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57706)
            vm.pc = 57707
            tick(57707)
            vm.pc = 57710
            vm.auxiliary = (0, 1826013185)
            tick(57710)
            vm.pc = 57715
            vm._write(7716, memory.load(cells.pointer(7709), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(57715)
            vm.pc = 57717
            vm._jump(1394)
            continue
        if vm.block == 1394:
            tick(57717)
            _phi(vm, 57717, (7717, 2, 7716, 1393, 7709, 1392))
            tick(57724)
            _phi(vm, 57724, (7718, 2, 7715, 1393, 7710, 1392))
            tick(57731)
            _phi(vm, 57731, (7719, 2, 7713, 1393, 7711, 1392))
            tick(57738)
            vm.pc = 57739
            tick(57739)
            vm.pc = 57742
            vm.auxiliary = (0, 1398958422)
            tick(57742)
            vm.pc = 57747
            vm._write(7720, int(memory.load(cells.pointer(7717), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(57747)
            vm.pc = 57751
            vm._jump(1395 if cells.value(7720) != 0 else 1396)
            continue
        if vm.block == 1395:
            tick(57751)
            _pointer(vm, 57751, 1, 7719, 7721, (163,))
            tick(57758)
            vm.pc = 57762
            value = memory.load(cells.value(7719), 1)
            vm._write(7722, value, 4, 'high.load')
            tick(57762)
            _pointer(vm, 57762, 1, 7718, 7723, (163,))
            tick(57769)
            vm.pc = 57773
            pointer = cells.value(7718)
            value = memory.load(cells.pointer(7722), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57773)
            vm.pc = 57775
            vm._jump(1396)
            continue
        if vm.block == 1396:
            tick(57775)
            _phi(vm, 57775, (7724, 2, 7723, 1395, 7718, 1394))
            tick(57782)
            _phi(vm, 57782, (7725, 2, 7721, 1395, 7719, 1394))
            tick(57789)
            vm.pc = 57790
            tick(57790)
            vm.pc = 57793
            vm.auxiliary = (0, 1787986134)
            tick(57793)
            vm.pc = 57798
            vm._write(7726, int(memory.load(cells.pointer(7717), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(57798)
            vm.pc = 57802
            vm._jump(1397 if cells.value(7726) != 0 else 1398)
            continue
        if vm.block == 1397:
            tick(57802)
            vm.pc = 57806
            value = memory.load(cells.value(7725), 1)
            vm._write(7727, value, 4, 'high.load')
            tick(57806)
            vm.pc = 57810
            pointer = cells.value(7724)
            value = memory.load(cells.pointer(7727), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57810)
            vm.pc = 57812
            vm._jump(1398)
            continue
        if vm.block == 1398:
            tick(57812)
            vm.pc = 57814
            vm._jump(1399)
            continue
        if vm.block == 1399:
            tick(57814)
            _phi(vm, 57814, (7728, 2, 1520, 1398, 7729, 1400))
            tick(57821)
            _phi(vm, 57821, (7730, 2, 205, 1398, 7731, 1400))
            tick(57828)
            vm.pc = 57829
            tick(57829)
            vm.pc = 57832
            vm.auxiliary = (0, 1860307011)
            tick(57832)
            vm.pc = 57837
            vm._write(7732, int(memory.load(cells.pointer(7730), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(57837)
            vm.pc = 57841
            vm._jump(1401 if cells.value(7732) != 0 else 1400)
            continue
        if vm.block == 1400:
            tick(57841)
            vm.pc = 57842
            tick(57842)
            vm.pc = 57845
            vm.auxiliary = (0, 763572225)
            tick(57845)
            vm.pc = 57850
            vm._write(7731, memory.load(cells.pointer(7730), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(57850)
            _pointer(vm, 57850, 1, 7728, 7729, (163,))
            tick(57857)
            vm.pc = 57861
            pointer = cells.value(7728)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57861)
            vm.pc = 57863
            vm._jump(1399)
            continue
        if vm.block == 1401:
            tick(57863)
            _pointer(vm, 57863, 70, 103, 7733, (145, 7734))
            tick(57871)
            vm.pc = 57876
            cells.copy_q_clear_owned(7733, 7735)
            tick(57876)
            vm.pc = 57877
            tick(57877)
            vm.pc = 57880
            vm.auxiliary = (0, 17717)
            tick(57880)
            vm.pc = 57885
            vm._write(7736, memory.load(cells.pointer(7735), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(57885)
            _pointer(vm, 57885, 1, 2292, 7737, (163,))
            tick(57892)
            vm.pc = 57896
            value = memory.load(cells.value(2292), 1)
            vm._write(7738, value, 4, 'high.load')
            tick(57896)
            _pointer(vm, 57896, 1, 7733, 7739, (163,))
            tick(57903)
            vm.pc = 57907
            pointer = cells.value(7733)
            value = memory.load(cells.pointer(7738), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57907)
            vm.pc = 57912
            cells.copy_q_clear_owned(7739, 7740)
            tick(57912)
            vm.pc = 57917
            vm._write(7741, memory.load(cells.pointer(7740), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(57917)
            vm.pc = 57920
            vm.auxiliary = (0, 1979906948)
            tick(57920)
            vm.pc = 57925
            vm._write(7742, int(memory.load(cells.pointer(7741), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(57925)
            vm.pc = 57929
            vm._jump(1402 if cells.value(7742) != 0 else 1403)
            continue
        if vm.block == 1402:
            tick(57929)
            _pointer(vm, 57929, 1, 7737, 7743, (163,))
            tick(57936)
            vm.pc = 57940
            value = memory.load(cells.value(7737), 1)
            vm._write(7744, value, 4, 'high.load')
            tick(57940)
            _pointer(vm, 57940, 1, 7739, 7745, (163,))
            tick(57947)
            vm.pc = 57951
            pointer = cells.value(7739)
            value = memory.load(cells.pointer(7744), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(57951)
            vm.pc = 57953
            vm._jump(1403)
            continue
        if vm.block == 1403:
            tick(57953)
            _phi(vm, 57953, (7746, 2, 328, 1402, 476, 1401))
            tick(57960)
            _phi(vm, 57960, (7747, 2, 7745, 1402, 7739, 1401))
            tick(57967)
            _phi(vm, 57967, (7748, 2, 7743, 1402, 7737, 1401))
            tick(57974)
            vm.pc = 57979
            cells.copy_q_clear_owned(7747, 7749)
            tick(57979)
            vm.pc = 57984
            vm._write(7750, memory.load(cells.pointer(7749), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(57984)
            vm.pc = 57985
            tick(57985)
            vm.pc = 57988
            vm.auxiliary = (0, 723670644)
            tick(57988)
            vm.pc = 57993
            vm._write(7751, int(memory.load(cells.pointer(7750), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(57993)
            vm.pc = 57996
            vm.auxiliary = (0, 742536886)
            tick(57996)
            vm.pc = 58001
            vm._write(7752, int(memory.load(cells.pointer(7746), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(58001)
            vm.pc = 58004
            vm.auxiliary = (0, 20495)
            tick(58004)
            vm.pc = 58009
            vm._write(7753, memory.load(cells.pointer(7751), 1, signed=True) & memory.load(cells.pointer(7752), 1, signed=True), 8, 'typed.selector1.q')
            tick(58009)
            vm.pc = 58013
            vm._jump(1404 if cells.value(7753) != 0 else 1405)
            continue
        if vm.block == 1404:
            tick(58013)
            _pointer(vm, 58013, 1, 7748, 7754, (163,))
            tick(58020)
            vm.pc = 58024
            value = memory.load(cells.value(7748), 1)
            vm._write(7755, value, 4, 'high.load')
            tick(58024)
            _pointer(vm, 58024, 1, 7747, 7756, (163,))
            tick(58031)
            vm.pc = 58035
            pointer = cells.value(7747)
            value = memory.load(cells.pointer(7755), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(58035)
            vm.pc = 58036
            tick(58036)
            vm.pc = 58039
            vm.auxiliary = (0, 1018384385)
            tick(58039)
            vm.pc = 58044
            vm._write(7757, memory.load(cells.pointer(7746), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(58044)
            vm.pc = 58046
            vm._jump(1405)
            continue
        if vm.block == 1405:
            tick(58046)
            _phi(vm, 58046, (7758, 2, 7757, 1404, 7746, 1403))
            tick(58053)
            _phi(vm, 58053, (7759, 2, 7756, 1404, 7747, 1403))
            tick(58060)
            _phi(vm, 58060, (7760, 2, 7754, 1404, 7748, 1403))
            tick(58067)
            vm.pc = 58072
            cells.copy_q_clear_owned(7759, 7761)
            tick(58072)
            vm.pc = 58077
            cells.copy_q_clear_owned(7760, 7762)
            tick(58077)
            vm.pc = 58078
            tick(58078)
            vm.pc = 58081
            vm.auxiliary = (0, 1194518166)
            tick(58081)
            vm.pc = 58086
            vm._write(7763, int(memory.load(cells.pointer(7758), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(58086)
            vm.pc = 58090
            vm._jump(1406 if cells.value(7763) != 0 else 1407)
            continue
        if vm.block == 1406:
            tick(58090)
            _pointer(vm, 58090, 1, 7760, 7764, (172,))
            tick(58097)
            vm.pc = 58102
            cells.copy_q_clear_owned(7764, 7765)
            tick(58102)
            vm.pc = 58106
            value = memory.load(cells.value(7762), 4)
            vm._write(7766, value, 4, 'high.load')
            tick(58106)
            _pointer(vm, 58106, 1, 7759, 7767, (172,))
            tick(58113)
            vm.pc = 58118
            cells.copy_q_clear_owned(7767, 7768)
            tick(58118)
            vm.pc = 58122
            pointer = cells.value(7761)
            value = memory.load(cells.pointer(7766), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(58122)
            vm.pc = 58123
            tick(58123)
            vm.pc = 58126
            vm.auxiliary = (0, 1213992962)
            tick(58126)
            vm.pc = 58131
            vm._write(7769, memory.load(cells.pointer(7758), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(58131)
            vm.pc = 58133
            vm._jump(1407)
            continue
        if vm.block == 1407:
            tick(58133)
            _phi(vm, 58133, (7770, 2, 7769, 1406, 7758, 1405))
            tick(58140)
            _phi(vm, 58140, (7771, 2, 7768, 1406, 7761, 1405))
            tick(58147)
            _phi(vm, 58147, (7772, 2, 7765, 1406, 7762, 1405))
            tick(58154)
            vm.pc = 58155
            tick(58155)
            vm.pc = 58158
            vm.auxiliary = (0, 376623734)
            tick(58158)
            vm.pc = 58163
            vm._write(7773, int(memory.load(cells.pointer(7770), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(58163)
            vm.pc = 58167
            vm._jump(1408 if cells.value(7773) != 0 else 1409)
            continue
        if vm.block == 1408:
            tick(58167)
            _pointer(vm, 58167, 3, 7772, 7774, (163,))
            tick(58174)
            vm.pc = 58178
            value = memory.load(cells.value(7772), 4)
            vm._write(7775, value, 4, 'high.load')
            tick(58178)
            _pointer(vm, 58178, 3, 7771, 7776, (163,))
            tick(58185)
            vm.pc = 58189
            pointer = cells.value(7771)
            value = memory.load(cells.pointer(7775), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(58189)
            vm.pc = 58190
            tick(58190)
            vm.pc = 58193
            vm.auxiliary = (0, 1965588481)
            tick(58193)
            vm.pc = 58198
            vm._write(7777, memory.load(cells.pointer(7770), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(58198)
            vm.pc = 58200
            vm._jump(1409)
            continue
        if vm.block == 1409:
            tick(58200)
            _phi(vm, 58200, (7778, 2, 7777, 1408, 7770, 1407))
            tick(58207)
            _phi(vm, 58207, (7779, 2, 7776, 1408, 7771, 1407))
            tick(58214)
            _phi(vm, 58214, (7780, 2, 7774, 1408, 7772, 1407))
            tick(58221)
            vm.pc = 58222
            tick(58222)
            vm.pc = 58225
            vm.auxiliary = (0, 1861378614)
            tick(58225)
            vm.pc = 58230
            vm._write(7781, int(memory.load(cells.pointer(7778), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(58230)
            vm.pc = 58234
            vm._jump(1410 if cells.value(7781) != 0 else 1411)
            continue
        if vm.block == 1410:
            tick(58234)
            _pointer(vm, 58234, 3, 7780, 7782, (163,))
            tick(58241)
            vm.pc = 58245
            value = memory.load(cells.value(7780), 4)
            vm._write(7783, value, 4, 'high.load')
            tick(58245)
            _pointer(vm, 58245, 3, 7779, 7784, (163,))
            tick(58252)
            vm.pc = 58256
            pointer = cells.value(7779)
            value = memory.load(cells.pointer(7783), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(58256)
            vm.pc = 58257
            tick(58257)
            vm.pc = 58260
            vm.auxiliary = (0, 1413505026)
            tick(58260)
            vm.pc = 58265
            vm._write(7785, memory.load(cells.pointer(7778), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(58265)
            vm.pc = 58267
            vm._jump(1411)
            continue
        if vm.block == 1411:
            tick(58267)
            _phi(vm, 58267, (7786, 2, 7785, 1410, 7778, 1409))
            tick(58274)
            _phi(vm, 58274, (7787, 2, 7784, 1410, 7779, 1409))
            tick(58281)
            _phi(vm, 58281, (7788, 2, 7782, 1410, 7780, 1409))
            tick(58288)
            vm.pc = 58293
            cells.copy_q_clear_owned(7787, 7789)
            tick(58293)
            vm.pc = 58298
            cells.copy_q_clear_owned(7788, 7790)
            tick(58298)
            vm.pc = 58299
            tick(58299)
            vm.pc = 58302
            vm.auxiliary = (0, 737330022)
            tick(58302)
            vm.pc = 58307
            vm._write(7791, int(memory.load(cells.pointer(7786), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(58307)
            vm.pc = 58311
            vm._jump(1412 if cells.value(7791) != 0 else 1413)
            continue
        if vm.block == 1412:
            tick(58311)
            _pointer(vm, 58311, 1, 7790, 7792, (163,))
            tick(58318)
            vm.pc = 58322
            value = memory.load(cells.value(7790), 1)
            vm._write(7793, value, 4, 'high.load')
            tick(58322)
            _pointer(vm, 58322, 1, 7789, 7794, (163,))
            tick(58329)
            vm.pc = 58333
            pointer = cells.value(7789)
            value = memory.load(cells.pointer(7793), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(58333)
            vm.pc = 58334
            tick(58334)
            vm.pc = 58337
            vm.auxiliary = (0, 857976833)
            tick(58337)
            vm.pc = 58342
            vm._write(7795, memory.load(cells.pointer(7786), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(58342)
            vm.pc = 58344
            vm._jump(1413)
            continue
        if vm.block == 1413:
            tick(58344)
            _phi(vm, 58344, (7796, 2, 7795, 1412, 7786, 1411))
            tick(58351)
            _phi(vm, 58351, (7797, 2, 7794, 1412, 7789, 1411))
            tick(58358)
            _phi(vm, 58358, (7798, 2, 7792, 1412, 7790, 1411))
            tick(58365)
            vm.pc = 58366
            tick(58366)
            vm.pc = 58369
            vm.auxiliary = (0, 550641206)
            tick(58369)
            vm.pc = 58374
            vm._write(7799, int(memory.load(cells.pointer(7796), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(58374)
            vm.pc = 58378
            vm._jump(1414 if cells.value(7799) != 0 else 1415)
            continue
        if vm.block == 1414:
            tick(58378)
            _pointer(vm, 58378, 1, 7798, 7800, (163,))
            tick(58385)
            vm.pc = 58389
            value = memory.load(cells.value(7798), 1)
            vm._write(7801, value, 4, 'high.load')
            tick(58389)
            _pointer(vm, 58389, 1, 7797, 7802, (163,))
            tick(58396)
            vm.pc = 58400
            pointer = cells.value(7797)
            value = memory.load(cells.pointer(7801), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(58400)
            vm.pc = 58401
            tick(58401)
            vm.pc = 58404
            vm.auxiliary = (0, 408166402)
            tick(58404)
            vm.pc = 58409
            vm._write(7803, memory.load(cells.pointer(7796), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(58409)
            vm.pc = 58411
            vm._jump(1415)
            continue
        if vm.block == 1415:
            tick(58411)
            _phi(vm, 58411, (7804, 2, 7803, 1414, 7796, 1413))
            tick(58418)
            _phi(vm, 58418, (7805, 2, 7802, 1414, 7797, 1413))
            tick(58425)
            _phi(vm, 58425, (7806, 2, 7800, 1414, 7798, 1413))
            tick(58432)
            vm.pc = 58433
            tick(58433)
            vm.pc = 58436
            vm.auxiliary = (0, 1556279942)
            tick(58436)
            vm.pc = 58441
            vm._write(7807, int(memory.load(cells.pointer(7804), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(58441)
            vm.pc = 58445
            vm._jump(1416 if cells.value(7807) != 0 else 1417)
            continue
        if vm.block == 1416:
            tick(58445)
            _pointer(vm, 58445, 1, 7806, 7808, (163,))
            tick(58452)
            vm.pc = 58456
            value = memory.load(cells.value(7806), 1)
            vm._write(7809, value, 4, 'high.load')
            tick(58456)
            _pointer(vm, 58456, 1, 7805, 7810, (163,))
            tick(58463)
            vm.pc = 58467
            pointer = cells.value(7805)
            value = memory.load(cells.pointer(7809), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(58467)
            vm.pc = 58469
            vm._jump(1417)
            continue
        if vm.block == 1417:
            tick(58469)
            _phi(vm, 58469, (7811, 2, 7810, 1416, 7805, 1415))
            tick(58476)
            _phi(vm, 58476, (7812, 2, 7808, 1416, 7806, 1415))
            tick(58483)
            vm.pc = 58484
            tick(58484)
            vm.pc = 58487
            vm.auxiliary = (0, 1509066710)
            tick(58487)
            vm.pc = 58492
            vm._write(7813, int(memory.load(cells.pointer(7804), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(58492)
            vm.pc = 58496
            vm._jump(1418 if cells.value(7813) != 0 else 1419)
            continue
        if vm.block == 1418:
            tick(58496)
            vm.pc = 58500
            value = memory.load(cells.value(7812), 1)
            vm._write(7814, value, 4, 'high.load')
            tick(58500)
            vm.pc = 58504
            pointer = cells.value(7811)
            value = memory.load(cells.pointer(7814), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(58504)
            vm.pc = 58506
            vm._jump(1419)
            continue
        if vm.block == 1419:
            tick(58506)
            vm.pc = 58508
            vm._jump(1420)
            continue
        if vm.block == 1420:
            tick(58508)
            _phi(vm, 58508, (7815, 2, 2292, 1419, 7816, 1421))
            tick(58515)
            _phi(vm, 58515, (7817, 2, 184, 1419, 7818, 1421))
            tick(58522)
            vm.pc = 58523
            tick(58523)
            vm.pc = 58526
            vm.auxiliary = (0, 1038283683)
            tick(58526)
            vm.pc = 58531
            vm._write(7819, int(memory.load(cells.pointer(7817), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(58531)
            vm.pc = 58535
            vm._jump(1422 if cells.value(7819) != 0 else 1421)
            continue
        if vm.block == 1421:
            tick(58535)
            vm.pc = 58536
            tick(58536)
            vm.pc = 58539
            vm.auxiliary = (0, 308527105)
            tick(58539)
            vm.pc = 58544
            vm._write(7818, memory.load(cells.pointer(7817), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(58544)
            _pointer(vm, 58544, 1, 7815, 7816, (163,))
            tick(58551)
            vm.pc = 58555
            pointer = cells.value(7815)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(58555)
            vm.pc = 58557
            vm._jump(1420)
            continue
        if vm.block == 1422:
            tick(58557)
            vm.pc = 58562
            cells.copy_q_clear_owned(136, 7820)
            tick(58562)
            vm.pc = 58564
            vm._jump(1423)
            continue
        if vm.block == 1423:
            tick(58564)
            _phi(vm, 58564, (7821, 2, 7822, 1422, 7823, 1424))
            tick(58571)
            _phi(vm, 58571, (7824, 2, 6614, 1422, 7825, 1424))
            tick(58578)
            _phi(vm, 58578, (7826, 2, 7827, 1422, 7828, 1424))
            tick(58585)
            vm.pc = 58586
            tick(58586)
            vm.pc = 58589
            vm.auxiliary = (0, 647162739)
            tick(58589)
            vm.pc = 58594
            vm._write(7829, int(memory.load(cells.pointer(7821), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(58594)
            vm.pc = 58598
            vm._jump(1425 if cells.value(7829) != 0 else 1424)
            continue
        if vm.block == 1424:
            tick(58598)
            vm.pc = 58599
            tick(58599)
            vm.pc = 58602
            vm.auxiliary = (0, 1774469122)
            tick(58602)
            vm.pc = 58607
            vm._write(7823, memory.load(cells.pointer(7821), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(58607)
            vm.pc = 58610
            vm.auxiliary = (0, 922137091)
            tick(58610)
            vm.pc = 58615
            vm._write(7831, memory.load(cells.pointer(7826), 4, signed=True) * memory.load(cells.pointer(7830), 4, signed=True), 8, 'once0.integer')
            tick(58615)
            _pointer(vm, 58615, 1, 7824, 7825, (163,))
            tick(58622)
            vm.pc = 58626
            value = memory.load(cells.value(7824), 1)
            vm._write(7832, value, 4, 'high.load')
            tick(58626)
            vm.pc = 58631
            _convert(vm, 4, 7832, 7833)
            tick(58631)
            vm.pc = 58634
            vm.auxiliary = (0, 1020203009)
            tick(58634)
            vm.pc = 58639
            vm._write(7828, memory.load(cells.pointer(7831), 4, signed=True) + memory.load(cells.pointer(7833), 4, signed=True), 8, 'once1.integer')
            tick(58639)
            vm.pc = 58641
            vm._jump(1423)
            continue
        if vm.block == 1425:
            tick(58641)
            vm.pc = 58646
            value = memory.load(cells.pointer(7826), 4)
            count = memory.load(cells.pointer(375), 1)
            vm._write(7834, value >> (count & 31), 4, 'once8.logical_shift')
            tick(58646)
            vm.pc = 58647
            tick(58647)
            vm.pc = 58650
            vm.auxiliary = (0, 61294)
            tick(58650)
            vm.pc = 58656
            vm._write(7835, memory.load(cells.pointer(7826), 4, signed=True) ^ memory.load(cells.pointer(7834), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(58656)
            vm.pc = 58659
            vm.auxiliary = (0, 1975804419)
            tick(58659)
            vm.pc = 58664
            vm._write(7837, memory.load(cells.pointer(7835), 4, signed=True) * memory.load(cells.pointer(7836), 4, signed=True), 8, 'once0.integer')
            tick(58664)
            vm.pc = 58669
            value = memory.load(cells.pointer(7837), 4)
            count = memory.load(cells.pointer(7838), 1)
            vm._write(7839, value >> (count & 31), 4, 'once8.logical_shift')
            tick(58669)
            vm.pc = 58672
            vm.auxiliary = (0, 22791)
            tick(58672)
            vm.pc = 58678
            vm._write(7840, memory.load(cells.pointer(7837), 4, signed=True) ^ memory.load(cells.pointer(7839), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(58678)
            vm.pc = 58681
            vm.auxiliary = (0, 18005)
            tick(58681)
            vm.pc = 58686
            vm._write(7841, memory.load(cells.pointer(7840), 4, signed=True) & memory.load(cells.pointer(937), 4, signed=True), 8, 'typed.selector1.q')
            tick(58686)
            vm.pc = 58691
            value = memory.load(cells.pointer(7841), 4)
            count = memory.load(cells.pointer(939), 1)
            vm._write(7842, value >> (count & 31), 4, 'once8.logical_shift')
            tick(58691)
            vm.pc = 58696
            vm._write(7843, memory.load(cells.pointer(7840), 4, signed=True) & memory.load(cells.pointer(941), 4, signed=True), 8, 'L13.binary_q')
            tick(58696)
            vm.pc = 58701
            value = memory.load(cells.pointer(7843), 4)
            count = memory.load(cells.pointer(502), 1)
            vm._write(7844, value >> (count & 31), 4, 'once8.logical_shift')
            tick(58701)
            vm.pc = 58706
            vm._write(7845, memory.load(cells.pointer(7840), 4, signed=True) & memory.load(cells.pointer(944), 4, signed=True), 8, 'L13.binary_q')
            tick(58706)
            vm.pc = 58709
            vm.auxiliary = (0, 20629)
            tick(58709)
            _single_control(vm)
            vm.pc = 58714
            count = memory.load(cells.pointer(502), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(7845), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(7846, value, 4, 'typed.selector3.d')
            tick(58714)
            vm.pc = 58719
            vm._write(7847, memory.load(cells.pointer(7840), 4, signed=True) & memory.load(cells.pointer(873), 4, signed=True), 8, 'L13.binary_q')
            tick(58719)
            vm.pc = 58722
            vm.auxiliary = (0, 22172)
            tick(58722)
            _single_control(vm)
            vm.pc = 58727
            count = memory.load(cells.pointer(939), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(7847), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(7848, value, 4, 'typed.selector3.d')
            tick(58727)
            vm.pc = 58732
            vm._write(7849, memory.load(cells.pointer(7842), 4, signed=True) | memory.load(cells.pointer(7844), 4, signed=True), 8, 'L15.binary_q')
            tick(58732)
            vm.pc = 58737
            vm._write(7850, memory.load(cells.pointer(7846), 4, signed=True) | memory.load(cells.pointer(7848), 4, signed=True), 8, 'L15.binary_q')
            tick(58737)
            vm.pc = 58740
            vm.auxiliary = (0, 59298)
            tick(58740)
            vm.pc = 58745
            vm._write(7851, memory.load(cells.pointer(7849), 4, signed=True) | memory.load(cells.pointer(7850), 4, signed=True), 8, 'typed.selector2.q')
            tick(58745)
            vm.pc = 58749
            pointer = cells.value(136)
            value = memory.load(cells.pointer(7851), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(58749)
            vm.pc = 58752
            vm.auxiliary = (0, 41724)
            tick(58752)
            _single_control(vm)
            vm.pc = 58757
            count = memory.load(cells.pointer(269), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(7851), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(7852, value, 4, 'typed.selector3.d')
            tick(58757)
            vm.pc = 58762
            cells.copy_q_clear_owned(7853, 7854)
            tick(58762)
            vm.pc = 58767
            vm._write(7855, int(cells.value(136) < cells.value(7854)), 4, 'once18.unsigned_q')
            tick(58767)
            vm.pc = 58774
            selected = 311 if cells.value(7855) != 0 else 158
            vm._write(7856, memory.load(cells.pointer(selected), 4, signed=True), 8, 'L7.selected_q')
            tick(58774)
            vm.pc = 58777
            vm.auxiliary = (0, 314609665)
            tick(58777)
            vm.pc = 58782
            vm._write(7857, memory.load(cells.pointer(7852), 4, signed=True) + memory.load(cells.pointer(7856), 4, signed=True), 8, 'once1.integer')
            tick(58782)
            _pointer(vm, 58782, 1, 6224, 7858, (163,))
            tick(58789)
            vm.pc = 58794
            cells.copy_q_clear_owned(7858, 7859)
            tick(58794)
            vm.pc = 58797
            vm.auxiliary = (0, 49236)
            tick(58797)
            vm.pc = 58802
            vm._write(7860, memory.load(cells.pointer(7859), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(58802)
            _pointer(vm, 58802, 1, 7820, 7861, (163,))
            tick(58809)
            vm.pc = 58813
            value = memory.load(cells.value(7820), 1)
            vm._write(7862, value, 4, 'high.load')
            tick(58813)
            _pointer(vm, 58813, 1, 7858, 7863, (163,))
            tick(58820)
            vm.pc = 58824
            pointer = cells.value(7858)
            value = memory.load(cells.pointer(7862), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(58824)
            vm.pc = 58829
            cells.copy_q_clear_owned(7863, 7864)
            tick(58829)
            vm.pc = 58834
            vm._write(7865, memory.load(cells.pointer(7864), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(58834)
            vm.pc = 58837
            vm.auxiliary = (0, 1340242260)
            tick(58837)
            vm.pc = 58842
            vm._write(7866, int(memory.load(cells.pointer(7865), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(58842)
            vm.pc = 58846
            vm._jump(1426 if cells.value(7866) != 0 else 1427)
            continue
        if vm.block == 1426:
            tick(58846)
            _pointer(vm, 58846, 1, 7861, 7867, (163,))
            tick(58853)
            vm.pc = 58857
            value = memory.load(cells.value(7861), 1)
            vm._write(7868, value, 4, 'L5.unsigned_load')
            tick(58857)
            _pointer(vm, 58857, 1, 7863, 7869, (163,))
            tick(58864)
            vm.pc = 58868
            pointer = cells.value(7863)
            value = memory.load(cells.pointer(7868), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(58868)
            vm.pc = 58870
            vm._jump(1427)
            continue
        if vm.block == 1427:
            tick(58870)
            _phi(vm, 58870, (7870, 2, 311, 1426, 149, 1425))
            tick(58877)
            _phi(vm, 58877, (7871, 2, 7869, 1426, 7863, 1425))
            tick(58884)
            _phi(vm, 58884, (7872, 2, 7867, 1426, 7861, 1425))
            tick(58891)
            vm.pc = 58896
            cells.copy_q_clear_owned(7871, 7873)
            tick(58896)
            vm.pc = 58901
            vm._write(7874, memory.load(cells.pointer(7873), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(58901)
            vm.pc = 58902
            tick(58902)
            vm.pc = 58905
            vm.auxiliary = (0, 1103264116)
            tick(58905)
            vm.pc = 58910
            vm._write(7875, int(memory.load(cells.pointer(7874), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(58910)
            vm.pc = 58913
            vm.auxiliary = (0, 1859286918)
            tick(58913)
            vm.pc = 58918
            vm._write(7876, int(memory.load(cells.pointer(7870), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(58918)
            vm.pc = 58921
            vm.auxiliary = (0, 21853)
            tick(58921)
            vm.pc = 58926
            vm._write(7877, memory.load(cells.pointer(7875), 1, signed=True) & memory.load(cells.pointer(7876), 1, signed=True), 8, 'typed.selector1.q')
            tick(58926)
            vm.pc = 58930
            vm._jump(1428 if cells.value(7877) != 0 else 1429)
            continue
        if vm.block == 1428:
            tick(58930)
            _pointer(vm, 58930, 1, 7872, 7878, (163,))
            tick(58937)
            vm.pc = 58941
            value = memory.load(cells.value(7872), 1)
            vm._write(7879, value, 4, 'high.load')
            tick(58941)
            _pointer(vm, 58941, 1, 7871, 7880, (163,))
            tick(58948)
            vm.pc = 58952
            pointer = cells.value(7871)
            value = memory.load(cells.pointer(7879), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(58952)
            vm.pc = 58953
            tick(58953)
            vm.pc = 58956
            vm.auxiliary = (0, 518885378)
            tick(58956)
            vm.pc = 58961
            vm._write(7881, memory.load(cells.pointer(7870), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(58961)
            vm.pc = 58963
            vm._jump(1429)
            continue
        if vm.block == 1429:
            tick(58963)
            _phi(vm, 58963, (7882, 2, 7881, 1428, 7870, 1427))
            tick(58970)
            _phi(vm, 58970, (7883, 2, 7880, 1428, 7871, 1427))
            tick(58977)
            _phi(vm, 58977, (7884, 2, 7878, 1428, 7872, 1427))
            tick(58984)
            vm.pc = 58989
            cells.copy_q_clear_owned(7883, 7885)
            tick(58989)
            vm.pc = 58994
            cells.copy_q_clear_owned(7884, 7886)
            tick(58994)
            vm.pc = 58995
            tick(58995)
            vm.pc = 58998
            vm.auxiliary = (0, 1056077446)
            tick(58998)
            vm.pc = 59003
            vm._write(7887, int(memory.load(cells.pointer(7882), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(59003)
            vm.pc = 59007
            vm._jump(1430 if cells.value(7887) != 0 else 1431)
            continue
        if vm.block == 1430:
            tick(59007)
            _pointer(vm, 59007, 1, 7884, 7888, (172,))
            tick(59014)
            vm.pc = 59019
            cells.copy_q_clear_owned(7888, 7889)
            tick(59019)
            vm.pc = 59023
            value = memory.load(cells.value(7886), 4)
            vm._write(7890, value, 4, 'high.load')
            tick(59023)
            _pointer(vm, 59023, 1, 7883, 7891, (172,))
            tick(59030)
            vm.pc = 59035
            cells.copy_q_clear_owned(7891, 7892)
            tick(59035)
            vm.pc = 59039
            pointer = cells.value(7885)
            value = memory.load(cells.pointer(7890), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(59039)
            vm.pc = 59040
            tick(59040)
            vm.pc = 59043
            vm.auxiliary = (0, 1274970114)
            tick(59043)
            vm.pc = 59048
            vm._write(7893, memory.load(cells.pointer(7882), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(59048)
            vm.pc = 59050
            vm._jump(1431)
            continue
        if vm.block == 1431:
            tick(59050)
            _phi(vm, 59050, (7894, 2, 7893, 1430, 7882, 1429))
            tick(59057)
            _phi(vm, 59057, (7895, 2, 7892, 1430, 7885, 1429))
            tick(59064)
            _phi(vm, 59064, (7896, 2, 7889, 1430, 7886, 1429))
            tick(59071)
            vm.pc = 59072
            tick(59072)
            vm.pc = 59075
            vm.auxiliary = (0, 486682006)
            tick(59075)
            vm.pc = 59080
            vm._write(7897, int(memory.load(cells.pointer(7894), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(59080)
            vm.pc = 59084
            vm._jump(1432 if cells.value(7897) != 0 else 1433)
            continue
        if vm.block == 1432:
            tick(59084)
            _pointer(vm, 59084, 3, 7896, 7898, (163,))
            tick(59091)
            vm.pc = 59095
            value = memory.load(cells.value(7896), 4)
            vm._write(7899, value, 4, 'high.load')
            tick(59095)
            _pointer(vm, 59095, 3, 7895, 7900, (163,))
            tick(59102)
            vm.pc = 59106
            pointer = cells.value(7895)
            value = memory.load(cells.pointer(7899), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(59106)
            vm.pc = 59107
            tick(59107)
            vm.pc = 59110
            vm.auxiliary = (0, 1418792962)
            tick(59110)
            vm.pc = 59115
            vm._write(7901, memory.load(cells.pointer(7894), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(59115)
            vm.pc = 59117
            vm._jump(1433)
            continue
        if vm.block == 1433:
            tick(59117)
            _phi(vm, 59117, (7902, 2, 7901, 1432, 7894, 1431))
            tick(59124)
            _phi(vm, 59124, (7903, 2, 7900, 1432, 7895, 1431))
            tick(59131)
            _phi(vm, 59131, (7904, 2, 7898, 1432, 7896, 1431))
            tick(59138)
            vm.pc = 59139
            tick(59139)
            vm.pc = 59142
            vm.auxiliary = (0, 1001551222)
            tick(59142)
            vm.pc = 59147
            vm._write(7905, int(memory.load(cells.pointer(7902), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(59147)
            vm.pc = 59151
            vm._jump(1434 if cells.value(7905) != 0 else 1435)
            continue
        if vm.block == 1434:
            tick(59151)
            _pointer(vm, 59151, 3, 7904, 7906, (163,))
            tick(59158)
            vm.pc = 59162
            value = memory.load(cells.value(7904), 4)
            vm._write(7907, value, 4, 'L5.unsigned_load')
            tick(59162)
            _pointer(vm, 59162, 3, 7903, 7908, (163,))
            tick(59169)
            vm.pc = 59173
            pointer = cells.value(7903)
            value = memory.load(cells.pointer(7907), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(59173)
            vm.pc = 59174
            tick(59174)
            vm.pc = 59177
            vm.auxiliary = (0, 359325697)
            tick(59177)
            vm.pc = 59182
            vm._write(7909, memory.load(cells.pointer(7902), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(59182)
            vm.pc = 59184
            vm._jump(1435)
            continue
        if vm.block == 1435:
            tick(59184)
            _phi(vm, 59184, (7910, 2, 7909, 1434, 7902, 1433))
            tick(59191)
            _phi(vm, 59191, (7911, 2, 7908, 1434, 7903, 1433))
            tick(59198)
            _phi(vm, 59198, (7912, 2, 7906, 1434, 7904, 1433))
            tick(59205)
            vm.pc = 59210
            cells.copy_q_clear_owned(7911, 7913)
            tick(59210)
            vm.pc = 59215
            cells.copy_q_clear_owned(7912, 7914)
            tick(59215)
            vm.pc = 59216
            tick(59216)
            vm.pc = 59219
            vm.auxiliary = (0, 1131566662)
            tick(59219)
            vm.pc = 59224
            vm._write(7915, int(memory.load(cells.pointer(7910), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(59224)
            vm.pc = 59228
            vm._jump(1436 if cells.value(7915) != 0 else 1437)
            continue
        if vm.block == 1436:
            tick(59228)
            _pointer(vm, 59228, 1, 7914, 7916, (163,))
            tick(59235)
            vm.pc = 59239
            value = memory.load(cells.value(7914), 1)
            vm._write(7917, value, 4, 'L5.unsigned_load')
            tick(59239)
            _pointer(vm, 59239, 1, 7913, 7918, (163,))
            tick(59246)
            vm.pc = 59250
            pointer = cells.value(7913)
            value = memory.load(cells.pointer(7917), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(59250)
            vm.pc = 59251
            tick(59251)
            vm.pc = 59254
            vm.auxiliary = (0, 669741057)
            tick(59254)
            vm.pc = 59259
            vm._write(7919, memory.load(cells.pointer(7910), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(59259)
            vm.pc = 59261
            vm._jump(1437)
            continue
        if vm.block == 1437:
            tick(59261)
            _phi(vm, 59261, (7920, 2, 7919, 1436, 7910, 1435))
            tick(59268)
            _phi(vm, 59268, (7921, 2, 7918, 1436, 7913, 1435))
            tick(59275)
            _phi(vm, 59275, (7922, 2, 7916, 1436, 7914, 1435))
            tick(59282)
            vm.pc = 59283
            tick(59283)
            vm.pc = 59286
            vm.auxiliary = (0, 675451894)
            tick(59286)
            vm.pc = 59291
            vm._write(7923, int(memory.load(cells.pointer(7920), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(59291)
            vm.pc = 59295
            vm._jump(1438 if cells.value(7923) != 0 else 1439)
            continue
        if vm.block == 1438:
            tick(59295)
            _pointer(vm, 59295, 1, 7922, 7924, (163,))
            tick(59302)
            vm.pc = 59306
            value = memory.load(cells.value(7922), 1)
            vm._write(7925, value, 4, 'high.load')
            tick(59306)
            _pointer(vm, 59306, 1, 7921, 7926, (163,))
            tick(59313)
            vm.pc = 59317
            pointer = cells.value(7921)
            value = memory.load(cells.pointer(7925), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(59317)
            vm.pc = 59318
            tick(59318)
            vm.pc = 59321
            vm.auxiliary = (0, 405528578)
            tick(59321)
            vm.pc = 59326
            vm._write(7927, memory.load(cells.pointer(7920), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(59326)
            vm.pc = 59328
            vm._jump(1439)
            continue
        if vm.block == 1439:
            tick(59328)
            _phi(vm, 59328, (7928, 2, 7927, 1438, 7920, 1437))
            tick(59335)
            _phi(vm, 59335, (7929, 2, 7926, 1438, 7921, 1437))
            tick(59342)
            _phi(vm, 59342, (7930, 2, 7924, 1438, 7922, 1437))
            tick(59349)
            vm.pc = 59350
            tick(59350)
            vm.pc = 59353
            vm.auxiliary = (0, 1196599510)
            tick(59353)
            vm.pc = 59358
            vm._write(7931, int(memory.load(cells.pointer(7928), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(59358)
            vm.pc = 59362
            vm._jump(1440 if cells.value(7931) != 0 else 1441)
            continue
        if vm.block == 1440:
            tick(59362)
            _pointer(vm, 59362, 1, 7930, 7932, (163,))
            tick(59369)
            vm.pc = 59373
            value = memory.load(cells.value(7930), 1)
            vm._write(7933, value, 4, 'high.load')
            tick(59373)
            _pointer(vm, 59373, 1, 7929, 7934, (163,))
            tick(59380)
            vm.pc = 59384
            pointer = cells.value(7929)
            value = memory.load(cells.pointer(7933), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(59384)
            vm.pc = 59386
            vm._jump(1441)
            continue
        if vm.block == 1441:
            tick(59386)
            _phi(vm, 59386, (7935, 2, 7934, 1440, 7929, 1439))
            tick(59393)
            _phi(vm, 59393, (7936, 2, 7932, 1440, 7930, 1439))
            tick(59400)
            vm.pc = 59401
            tick(59401)
            vm.pc = 59404
            vm.auxiliary = (0, 897772214)
            tick(59404)
            vm.pc = 59409
            vm._write(7937, int(memory.load(cells.pointer(7928), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(59409)
            vm.pc = 59413
            vm._jump(1442 if cells.value(7937) != 0 else 1443)
            continue
        if vm.block == 1442:
            tick(59413)
            vm.pc = 59417
            value = memory.load(cells.value(7936), 1)
            vm._write(7938, value, 4, 'high.load')
            tick(59417)
            vm.pc = 59421
            pointer = cells.value(7935)
            value = memory.load(cells.pointer(7938), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(59421)
            vm.pc = 59423
            vm._jump(1443)
            continue
        if vm.block == 1443:
            tick(59423)
            vm.pc = 59427
            value = memory.load(cells.value(6224), 1)
            vm._write(7939, value, 4, 'high.load')
            tick(59427)
            vm.pc = 59432
            _convert(vm, 4, 7939, 7940)
            tick(59432)
            vm.pc = 59434
            vm._jump(1444)
            continue
        if vm.block == 1444:
            tick(59434)
            _phi(vm, 59434, (7941, 2, 158, 1443, 7942, 1445))
            tick(59441)
            vm.pc = 59446
            vm._write(7943, int(cells.value(7941) < cells.value(360)), 4, 'once18.unsigned_q')
            tick(59446)
            vm.pc = 59450
            vm._jump(1445 if cells.value(7943) != 0 else 1446)
            continue
        if vm.block == 1445:
            tick(59450)
            vm.pc = 59455
            vm._write(7944, memory.load(cells.pointer(7941), 4, signed=True) ^ memory.load(cells.pointer(7940), 4, signed=True), 8, 'L14.binary_q')
            tick(59455)
            vm.pc = 59456
            tick(59456)
            vm.pc = 59459
            vm.auxiliary = (0, 1823449604)
            tick(59459)
            vm.pc = 59464
            vm._write(7945, memory.load(cells.pointer(7944), 4, signed=True) * memory.load(cells.pointer(867), 4, signed=True), 8, 'once0.integer')
            tick(59464)
            vm.pc = 59469
            value = memory.load(cells.pointer(7945), 4)
            count = memory.load(cells.pointer(375), 1)
            vm._write(7946, value >> (count & 31), 4, 'once8.logical_shift')
            tick(59469)
            vm.pc = 59472
            vm.auxiliary = (0, 18542)
            tick(59472)
            vm.pc = 59478
            vm._write(7947, memory.load(cells.pointer(7945), 4, signed=True) ^ memory.load(cells.pointer(7946), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(59478)
            vm.pc = 59483
            _convert(vm, 8, 7941, 7948)
            tick(59483)
            _pointer(vm, 59483, 1, 7858, 7949, (7948,))
            tick(59490)
            vm.pc = 59494
            value = memory.load(cells.value(7949), 1)
            vm._write(7950, value, 4, 'high.load')
            tick(59494)
            vm.pc = 59499
            vm._write(7951, cells.value(7947) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(59499)
            vm.pc = 59504
            vm._write(7952, memory.load(cells.pointer(7950), 1, signed=True) ^ memory.load(cells.pointer(7951), 1, signed=True), 8, 'L14.binary_q')
            tick(59504)
            vm.pc = 59508
            pointer = cells.value(7949)
            value = memory.load(cells.pointer(7952), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(59508)
            vm.pc = 59511
            vm.auxiliary = (0, 318242817)
            tick(59511)
            vm.pc = 59516
            vm._write(7942, memory.load(cells.pointer(7941), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(59516)
            vm.pc = 59518
            vm._jump(1444)
            continue
        if vm.block == 1446:
            tick(59518)
            vm.pc = 59522
            value = memory.load(cells.value(6224), 1)
            vm._write(7953, value, 4, 'high.load')
            tick(59522)
            vm.pc = 59527
            cells.copy_q_clear_owned(66, 7954)
            tick(59527)
            vm.pc = 59531
            pointer = cells.value(66)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(59531)
            vm.pc = 59533
            vm._jump(1447)
            continue
        if vm.block == 1447:
            tick(59533)
            _phi(vm, 59533, (7955, 2, 145, 1446, 7956, 1448))
            tick(59540)
            vm.pc = 59545
            vm._write(7957, int(cells.value(7955) < cells.value(163)), 4, 'once18.unsigned_q')
            tick(59545)
            vm.pc = 59549
            vm._jump(1449 if cells.value(7957) != 0 else 1450)
            continue
        if vm.block == 1449:
            tick(59549)
            vm.pc = 59554
            vm._write(7958, cells.value(7955) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(59554)
            vm.pc = 59555
            tick(59555)
            vm.pc = 59558
            vm.auxiliary = (0, 403759106)
            tick(59558)
            vm.pc = 59563
            vm._write(7959, memory.load(cells.pointer(7958), 2, signed=True) + memory.load(cells.pointer(1381), 2, signed=True), 8, 'once1.integer')
            tick(59563)
            vm.pc = 59568
            value = memory.load(cells.pointer(7959), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(7960, value >> (count & 31), 4, 'once8.logical_shift')
            tick(59568)
            _pointer(vm, 59568, 91, 112, 7961, (145, 391))
            tick(59576)
            vm.pc = 59580
            value = memory.load(cells.value(7961), 8)
            vm._write(7962, value, 8, 'high.load')
            tick(59580)
            vm.pc = 59585
            vm._write(7963, cells.value(7962) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(59585)
            vm.pc = 59590
            vm._write(7964, memory.load(cells.pointer(7963), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(59590)
            vm.pc = 59593
            vm.auxiliary = (0, 14878)
            tick(59593)
            vm.pc = 59599
            vm._write(7965, memory.load(cells.pointer(7960), 2, signed=True) ^ memory.load(cells.pointer(7964), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(59599)
            vm.pc = 59604
            _convert(vm, 8, 7965, 7966)
            tick(59604)
            _pointer(vm, 59604, 91, 112, 7967, (145, 311, 7966))
            tick(59613)
            vm.pc = 59617
            value = memory.load(cells.value(7967), 8)
            vm._write(7968, value, 8, 'high.load')
            tick(59617)
            vm.pc = 59620
            vm.auxiliary = (0, 1797402499)
            tick(59620)
            vm.pc = 59625
            vm._write(7969, int(memory.load(cells.pointer(7968), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(59625)
            vm.pc = 59629
            vm._jump(1451 if cells.value(7969) != 0 else 1452)
            continue
        if vm.block == 1452:
            tick(59629)
            vm.pc = 59634
            value = memory.load(cells.pointer(7962), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(7970, value >> (count & 63), 8, 'once8.logical_shift')
            tick(59634)
            vm.pc = 59639
            vm._write(7971, cells.value(7970) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(59639)
            vm.pc = 59644
            vm._write(7972, memory.load(cells.pointer(7971), 2, signed=True) ^ memory.load(cells.pointer(7959), 2, signed=True), 8, 'L14.binary_q')
            tick(59644)
            vm.pc = 59649
            vm._write(7973, memory.load(cells.pointer(7972), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(59649)
            vm.pc = 59654
            _convert(vm, 8, 7973, 7974)
            tick(59654)
            _pointer(vm, 59654, 78, 7968, 7975, (7974,))
            tick(59661)
            vm.pc = 59665
            value = memory.load(cells.value(7975), 8)
            vm._write(7976, value, 8, 'high.load')
            tick(59665)
            vm.pc = 59666
            tick(59666)
            vm.pc = 59669
            vm.auxiliary = (0, 1137870531)
            tick(59669)
            vm.pc = 59674
            vm._write(7977, int(memory.load(cells.pointer(7976), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(59674)
            vm.pc = 59678
            vm._jump(1451 if cells.value(7977) != 0 else 1453)
            continue
        if vm.block == 1453:
            tick(59678)
            _pointer(vm, 59678, 79, 7976, 7978, (145, 269))
            tick(59686)
            vm.pc = 59690
            value = memory.load(cells.value(7978), 2)
            vm._write(7979, value, 4, 'high.load')
            tick(59690)
            vm.pc = 59691
            tick(59691)
            vm.pc = 59694
            vm.auxiliary = (0, 825362627)
            tick(59694)
            _equal(vm, 59699, 2, 7979, 7959, 7980)
            tick(59699)
            vm.pc = 59703
            vm._jump(1454 if cells.value(7980) != 0 else 1451)
            continue
        if vm.block == 1454:
            tick(59703)
            _pointer(vm, 59703, 79, 7976, 7981, (145, 360))
            tick(59711)
            vm.pc = 59715
            value = memory.load(cells.value(7981), 4)
            vm._write(7982, value, 4, 'high.load')
            tick(59715)
            _pointer(vm, 59715, 79, 7976, 7983, (145, 158))
            tick(59723)
            vm.pc = 59727
            value = memory.load(cells.value(7983), 4)
            vm._write(7984, value, 4, 'high.load')
            tick(59727)
            vm.pc = 59728
            tick(59728)
            vm.pc = 59731
            vm.auxiliary = (0, 11135)
            tick(59731)
            vm.pc = 59737
            vm._write(7985, memory.load(cells.pointer(7984), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(59737)
            vm.pc = 59740
            vm.auxiliary = (0, 1424822788)
            tick(59740)
            vm.pc = 59745
            vm._write(7986, memory.load(cells.pointer(7985), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(59745)
            _pointer(vm, 59745, 79, 7976, 7987, (145, 269))
            tick(59753)
            vm.pc = 59757
            value = memory.load(cells.value(7987), 2)
            vm._write(7988, value, 4, 'high.load')
            tick(59757)
            vm.pc = 59762
            _convert(vm, 4, 7988, 7989)
            tick(59762)
            vm.pc = 59767
            vm._write(7990, memory.load(cells.pointer(7986), 4, signed=True) ^ memory.load(cells.pointer(7989), 4, signed=True), 8, 'L14.binary_q')
            tick(59767)
            vm.pc = 59770
            vm.auxiliary = (0, 1117827587)
            tick(59770)
            vm.pc = 59775
            vm._write(7991, memory.load(cells.pointer(7990), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(59775)
            _pointer(vm, 59775, 79, 7976, 7992, (145, 311))
            tick(59783)
            vm.pc = 59787
            value = memory.load(cells.value(7992), 8)
            vm._write(7993, value, 8, 'high.load')
            tick(59787)
            vm.pc = 59792
            cells.copy_q_clear_owned(7993, 7994)
            tick(59792)
            vm.pc = 59797
            vm._write(7995, cells.value(7994) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(59797)
            vm.pc = 59802
            vm._write(7996, memory.load(cells.pointer(7991), 4, signed=True) ^ memory.load(cells.pointer(7995), 4, signed=True), 8, 'L14.binary_q')
            tick(59802)
            vm.pc = 59805
            vm.auxiliary = (0, 560894468)
            tick(59805)
            vm.pc = 59810
            vm._write(7997, memory.load(cells.pointer(7996), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(59810)
            vm.pc = 59815
            value = memory.load(cells.pointer(7994), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(7998, value >> (count & 63), 8, 'once8.logical_shift')
            tick(59815)
            vm.pc = 59820
            vm._write(7999, cells.value(7998) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(59820)
            vm.pc = 59823
            vm.auxiliary = (0, 61220)
            tick(59823)
            vm.pc = 59829
            vm._write(8000, memory.load(cells.pointer(7997), 4, signed=True) ^ memory.load(cells.pointer(7999), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(59829)
            vm.pc = 59832
            vm.auxiliary = (0, 358420995)
            tick(59832)
            vm.pc = 59837
            vm._write(8001, memory.load(cells.pointer(8000), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(59837)
            vm.pc = 59842
            vm._write(8002, cells.value(7962) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(59842)
            vm.pc = 59845
            vm.auxiliary = (0, 23645)
            tick(59845)
            vm.pc = 59851
            vm._write(8003, memory.load(cells.pointer(8001), 4, signed=True) ^ memory.load(cells.pointer(8002), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(59851)
            vm.pc = 59854
            vm.auxiliary = (0, 808952323)
            tick(59854)
            vm.pc = 59859
            vm._write(8004, memory.load(cells.pointer(8003), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(59859)
            vm.pc = 59864
            value = memory.load(cells.pointer(7962), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(8005, value >> (count & 63), 8, 'once8.logical_shift')
            tick(59864)
            vm.pc = 59869
            vm._write(8006, cells.value(8005) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(59869)
            vm.pc = 59872
            vm.auxiliary = (0, 18967)
            tick(59872)
            vm.pc = 59878
            vm._write(8007, memory.load(cells.pointer(8004), 4, signed=True) ^ memory.load(cells.pointer(8006), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(59878)
            vm.pc = 59881
            vm.auxiliary = (0, 1661960707)
            tick(59881)
            vm.pc = 59886
            vm._write(8008, memory.load(cells.pointer(8007), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(59886)
            vm.pc = 59890
            value = memory.load(cells.value(7993), 1)
            vm._write(8009, value, 4, 'high.load')
            tick(59890)
            vm.pc = 59895
            _convert(vm, 4, 8009, 8010)
            tick(59895)
            vm.pc = 59898
            vm.auxiliary = (0, 65110)
            tick(59898)
            vm.pc = 59904
            vm._write(8011, memory.load(cells.pointer(8008), 4, signed=True) ^ memory.load(cells.pointer(8010), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(59904)
            vm.pc = 59907
            vm.auxiliary = (0, 2126500356)
            tick(59907)
            vm.pc = 59912
            vm._write(8012, memory.load(cells.pointer(8011), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(59912)
            vm.pc = 59915
            vm.auxiliary = (0, 1936879427)
            tick(59915)
            _equal(vm, 59920, 4, 7982, 8012, 8013)
            tick(59920)
            vm.pc = 59924
            vm._jump(1451 if cells.value(8013) != 0 else 1455)
            continue
        if vm.block == 1455:
            tick(59924)
            vm.pc = 59928
            pointer = cells.value(7981)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(59928)
            vm.pc = 59930
            vm._jump(1451)
            continue
        if vm.block == 1451:
            tick(59930)
            _phi(vm, 59930, (8014, 5, 857, 1449, 857, 1453, 7976, 1454, 7976, 1455, 7976, 1452))
            tick(59943)
            vm.pc = 59944
            tick(59944)
            vm.pc = 59947
            vm.auxiliary = (0, 1326631699)
            tick(59947)
            _equal(vm, 59952, 8, 8014, 857, 8015)
            tick(59952)
            vm.pc = 59956
            vm._jump(1456 if cells.value(8015) != 0 else 1457)
            continue
        if vm.block == 1457:
            tick(59956)
            _pointer(vm, 59956, 79, 8014, 8016, (145, 311))
            tick(59964)
            vm.pc = 59968
            value = memory.load(cells.value(8016), 8)
            vm._write(8017, value, 8, 'high.load')
            tick(59968)
            vm.pc = 59972
            value = memory.load(cells.value(8017), 1)
            vm._write(8018, value, 4, 'high.load')
            tick(59972)
            _pointer(vm, 59972, 1, 7954, 8019, (7955,))
            tick(59979)
            vm.pc = 59983
            pointer = cells.value(8019)
            value = memory.load(cells.pointer(8018), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(59983)
            vm.pc = 59985
            vm._jump(1448)
            continue
        if vm.block == 1456:
            tick(59985)
            _pointer(vm, 59985, 1, 7954, 8020, (7955,))
            tick(59992)
            vm.pc = 59996
            pointer = cells.value(8020)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(59996)
            vm.pc = 59998
            vm._jump(1448)
            continue
        if vm.block == 1448:
            tick(59998)
            vm.pc = 59999
            tick(59999)
            vm.pc = 60002
            vm.auxiliary = (0, 1123540994)
            tick(60002)
            vm.pc = 60007
            vm._write(7956, memory.load(cells.pointer(7955), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(60007)
            vm.pc = 60009
            vm._jump(1447)
            continue
        if vm.block == 1450:
            tick(60009)
            vm.pc = 60013
            value = memory.load(cells.value(66), 8)
            vm._write(8021, value, 8, 'high.load')
            tick(60013)
            vm.pc = 60018
            vm._write(8022, cells.value(8021) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(60018)
            vm.pc = 60019
            tick(60019)
            vm.pc = 60022
            vm.auxiliary = (0, 22559)
            tick(60022)
            vm.pc = 60028
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8023, memory.load(cells.pointer(7953), 1, signed=True) ^ memory.load(cells.pointer(8022), 1, signed=True), 8, 'typed.selector5.q')
            tick(60028)
            vm.pc = 60031
            vm.auxiliary = (0, 27397)
            tick(60031)
            vm.pc = 60037
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8025, memory.load(cells.pointer(8023), 1, signed=True) ^ memory.load(cells.pointer(8024), 1, signed=True), 8, 'typed.selector5.q')
            tick(60037)
            vm.pc = 60041
            pointer = cells.value(6224)
            value = memory.load(cells.pointer(8025), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(60041)
            _pointer(vm, 60041, 70, 103, 8026, (145, 163))
            tick(60049)
            vm.pc = 60054
            cells.copy_q_clear_owned(8026, 8027)
            tick(60054)
            vm.pc = 60057
            vm.auxiliary = (0, 17236)
            tick(60057)
            vm.pc = 60062
            vm._write(8028, memory.load(cells.pointer(8027), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(60062)
            _pointer(vm, 60062, 1, 6224, 8029, (163,))
            tick(60069)
            vm.pc = 60073
            value = memory.load(cells.value(6224), 1)
            vm._write(8030, value, 4, 'high.load')
            tick(60073)
            _pointer(vm, 60073, 1, 8026, 8031, (163,))
            tick(60080)
            vm.pc = 60084
            pointer = cells.value(8026)
            value = memory.load(cells.pointer(8030), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(60084)
            vm.pc = 60089
            cells.copy_q_clear_owned(8031, 8032)
            tick(60089)
            vm.pc = 60094
            vm._write(8033, memory.load(cells.pointer(8032), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(60094)
            vm.pc = 60097
            vm.auxiliary = (0, 498248004)
            tick(60097)
            vm.pc = 60102
            vm._write(8034, int(memory.load(cells.pointer(8033), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(60102)
            vm.pc = 60104
            vm._jump(1458)
            continue
        if vm.block == 1458:
            tick(60104)
            vm.pc = 60109
            cells.copy_q_clear_owned(8031, 8035)
            tick(60109)
            vm.pc = 60110
            tick(60110)
            vm.pc = 60113
            vm.auxiliary = (0, 61476)
            tick(60113)
            vm.pc = 60118
            vm._write(8036, memory.load(cells.pointer(8035), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(60118)
            vm.pc = 60121
            vm.auxiliary = (0, 2042799556)
            tick(60121)
            vm.pc = 60126
            vm._write(8037, int(memory.load(cells.pointer(8036), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(60126)
            vm.pc = 60129
            vm.auxiliary = (0, 990005190)
            tick(60129)
            vm.pc = 60134
            vm._write(8038, int(memory.load(cells.pointer(158), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(60134)
            vm.pc = 60137
            vm.auxiliary = (0, 30557)
            tick(60137)
            vm.pc = 60142
            vm._write(8039, memory.load(cells.pointer(8037), 1, signed=True) & memory.load(cells.pointer(8038), 1, signed=True), 8, 'typed.selector1.q')
            tick(60142)
            vm.pc = 60146
            vm._jump(1459 if cells.value(8039) != 0 else 1460)
            continue
        if vm.block == 1459:
            tick(60146)
            _pointer(vm, 60146, 1, 8029, 8040, (163,))
            tick(60153)
            vm.pc = 60157
            value = memory.load(cells.value(8029), 1)
            vm._write(8041, value, 4, 'high.load')
            tick(60157)
            _pointer(vm, 60157, 1, 8031, 8042, (163,))
            tick(60164)
            vm.pc = 60168
            pointer = cells.value(8031)
            value = memory.load(cells.pointer(8041), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(60168)
            vm.pc = 60169
            tick(60169)
            vm.pc = 60172
            vm.auxiliary = (0, 1928228865)
            tick(60172)
            vm.pc = 60177
            vm._write(8043, memory.load(cells.pointer(158), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(60177)
            vm.pc = 60179
            vm._jump(1460)
            continue
        if vm.block == 1460:
            tick(60179)
            _phi(vm, 60179, (8044, 2, 8043, 1459, 158, 1458))
            tick(60186)
            _phi(vm, 60186, (8045, 2, 8042, 1459, 8031, 1458))
            tick(60193)
            _phi(vm, 60193, (8046, 2, 8040, 1459, 8029, 1458))
            tick(60200)
            vm.pc = 60205
            cells.copy_q_clear_owned(8045, 8047)
            tick(60205)
            vm.pc = 60210
            cells.copy_q_clear_owned(8046, 8048)
            tick(60210)
            vm.pc = 60211
            tick(60211)
            vm.pc = 60214
            vm.auxiliary = (0, 678564454)
            tick(60214)
            vm.pc = 60219
            vm._write(8049, int(memory.load(cells.pointer(8044), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(60219)
            vm.pc = 60223
            vm._jump(1461 if cells.value(8049) != 0 else 1462)
            continue
        if vm.block == 1461:
            tick(60223)
            _pointer(vm, 60223, 1, 8046, 8050, (172,))
            tick(60230)
            vm.pc = 60235
            cells.copy_q_clear_owned(8050, 8051)
            tick(60235)
            vm.pc = 60239
            value = memory.load(cells.value(8048), 4)
            vm._write(8052, value, 4, 'high.load')
            tick(60239)
            _pointer(vm, 60239, 1, 8045, 8053, (172,))
            tick(60246)
            vm.pc = 60251
            cells.copy_q_clear_owned(8053, 8054)
            tick(60251)
            vm.pc = 60255
            pointer = cells.value(8047)
            value = memory.load(cells.pointer(8052), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(60255)
            vm.pc = 60256
            tick(60256)
            vm.pc = 60259
            vm.auxiliary = (0, 1410031617)
            tick(60259)
            vm.pc = 60264
            vm._write(8055, memory.load(cells.pointer(8044), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(60264)
            vm.pc = 60266
            vm._jump(1462)
            continue
        if vm.block == 1462:
            tick(60266)
            _phi(vm, 60266, (8056, 2, 8055, 1461, 8044, 1460))
            tick(60273)
            _phi(vm, 60273, (8057, 2, 8054, 1461, 8047, 1460))
            tick(60280)
            _phi(vm, 60280, (8058, 2, 8051, 1461, 8048, 1460))
            tick(60287)
            vm.pc = 60288
            tick(60288)
            vm.pc = 60291
            vm.auxiliary = (0, 833785846)
            tick(60291)
            vm.pc = 60296
            vm._write(8059, int(memory.load(cells.pointer(8056), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(60296)
            vm.pc = 60300
            vm._jump(1463 if cells.value(8059) != 0 else 1464)
            continue
        if vm.block == 1463:
            tick(60300)
            _pointer(vm, 60300, 3, 8058, 8060, (163,))
            tick(60307)
            vm.pc = 60311
            value = memory.load(cells.value(8058), 4)
            vm._write(8061, value, 4, 'high.load')
            tick(60311)
            _pointer(vm, 60311, 3, 8057, 8062, (163,))
            tick(60318)
            vm.pc = 60322
            pointer = cells.value(8057)
            value = memory.load(cells.pointer(8061), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(60322)
            vm.pc = 60323
            tick(60323)
            vm.pc = 60326
            vm.auxiliary = (0, 1519923202)
            tick(60326)
            vm.pc = 60331
            vm._write(8063, memory.load(cells.pointer(8056), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(60331)
            vm.pc = 60333
            vm._jump(1464)
            continue
        if vm.block == 1464:
            tick(60333)
            _phi(vm, 60333, (8064, 2, 8063, 1463, 8056, 1462))
            tick(60340)
            _phi(vm, 60340, (8065, 2, 8062, 1463, 8057, 1462))
            tick(60347)
            _phi(vm, 60347, (8066, 2, 8060, 1463, 8058, 1462))
            tick(60354)
            vm.pc = 60355
            tick(60355)
            vm.pc = 60358
            vm.auxiliary = (0, 1889717238)
            tick(60358)
            vm.pc = 60363
            vm._write(8067, int(memory.load(cells.pointer(8064), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(60363)
            vm.pc = 60367
            vm._jump(1465 if cells.value(8067) != 0 else 1466)
            continue
        if vm.block == 1465:
            tick(60367)
            _pointer(vm, 60367, 3, 8066, 8068, (163,))
            tick(60374)
            vm.pc = 60378
            value = memory.load(cells.value(8066), 4)
            vm._write(8069, value, 4, 'high.load')
            tick(60378)
            _pointer(vm, 60378, 3, 8065, 8070, (163,))
            tick(60385)
            vm.pc = 60389
            pointer = cells.value(8065)
            value = memory.load(cells.pointer(8069), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(60389)
            vm.pc = 60390
            tick(60390)
            vm.pc = 60393
            vm.auxiliary = (0, 1976250369)
            tick(60393)
            vm.pc = 60398
            vm._write(8071, memory.load(cells.pointer(8064), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(60398)
            vm.pc = 60400
            vm._jump(1466)
            continue
        if vm.block == 1466:
            tick(60400)
            _phi(vm, 60400, (8072, 2, 8071, 1465, 8064, 1464))
            tick(60407)
            _phi(vm, 60407, (8073, 2, 8070, 1465, 8065, 1464))
            tick(60414)
            _phi(vm, 60414, (8074, 2, 8068, 1465, 8066, 1464))
            tick(60421)
            vm.pc = 60426
            cells.copy_q_clear_owned(8073, 8075)
            tick(60426)
            vm.pc = 60431
            cells.copy_q_clear_owned(8074, 8076)
            tick(60431)
            vm.pc = 60432
            tick(60432)
            vm.pc = 60435
            vm.auxiliary = (0, 955410230)
            tick(60435)
            vm.pc = 60440
            vm._write(8077, int(memory.load(cells.pointer(8072), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(60440)
            vm.pc = 60444
            vm._jump(1467 if cells.value(8077) != 0 else 1468)
            continue
        if vm.block == 1467:
            tick(60444)
            _pointer(vm, 60444, 1, 8076, 8078, (163,))
            tick(60451)
            vm.pc = 60455
            value = memory.load(cells.value(8076), 1)
            vm._write(8079, value, 4, 'high.load')
            tick(60455)
            _pointer(vm, 60455, 1, 8075, 8080, (163,))
            tick(60462)
            vm.pc = 60466
            pointer = cells.value(8075)
            value = memory.load(cells.pointer(8079), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(60466)
            vm.pc = 60467
            tick(60467)
            vm.pc = 60470
            vm.auxiliary = (0, 1063964673)
            tick(60470)
            vm.pc = 60475
            vm._write(8081, memory.load(cells.pointer(8072), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(60475)
            vm.pc = 60477
            vm._jump(1468)
            continue
        if vm.block == 1468:
            tick(60477)
            _phi(vm, 60477, (8082, 2, 8081, 1467, 8072, 1466))
            tick(60484)
            _phi(vm, 60484, (8083, 2, 8080, 1467, 8075, 1466))
            tick(60491)
            _phi(vm, 60491, (8084, 2, 8078, 1467, 8076, 1466))
            tick(60498)
            vm.pc = 60499
            tick(60499)
            vm.pc = 60502
            vm.auxiliary = (0, 2085795334)
            tick(60502)
            vm.pc = 60507
            vm._write(8085, int(memory.load(cells.pointer(8082), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(60507)
            vm.pc = 60511
            vm._jump(1469 if cells.value(8085) != 0 else 1470)
            continue
        if vm.block == 1469:
            tick(60511)
            _pointer(vm, 60511, 1, 8084, 8086, (163,))
            tick(60518)
            vm.pc = 60522
            value = memory.load(cells.value(8084), 1)
            vm._write(8087, value, 4, 'high.load')
            tick(60522)
            _pointer(vm, 60522, 1, 8083, 8088, (163,))
            tick(60529)
            vm.pc = 60533
            pointer = cells.value(8083)
            value = memory.load(cells.pointer(8087), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(60533)
            vm.pc = 60534
            tick(60534)
            vm.pc = 60537
            vm.auxiliary = (0, 1778274306)
            tick(60537)
            vm.pc = 60542
            vm._write(8089, memory.load(cells.pointer(8082), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(60542)
            vm.pc = 60544
            vm._jump(1470)
            continue
        if vm.block == 1470:
            tick(60544)
            _phi(vm, 60544, (8090, 2, 8089, 1469, 8082, 1468))
            tick(60551)
            _phi(vm, 60551, (8091, 2, 8088, 1469, 8083, 1468))
            tick(60558)
            _phi(vm, 60558, (8092, 2, 8086, 1469, 8084, 1468))
            tick(60565)
            vm.pc = 60566
            tick(60566)
            vm.pc = 60569
            vm.auxiliary = (0, 1257415782)
            tick(60569)
            vm.pc = 60574
            vm._write(8093, int(memory.load(cells.pointer(8090), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(60574)
            vm.pc = 60578
            vm._jump(1471 if cells.value(8093) != 0 else 1472)
            continue
        if vm.block == 1471:
            tick(60578)
            _pointer(vm, 60578, 1, 8092, 8094, (163,))
            tick(60585)
            vm.pc = 60589
            value = memory.load(cells.value(8092), 1)
            vm._write(8095, value, 4, 'high.load')
            tick(60589)
            _pointer(vm, 60589, 1, 8091, 8096, (163,))
            tick(60596)
            vm.pc = 60600
            pointer = cells.value(8091)
            value = memory.load(cells.pointer(8095), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(60600)
            vm.pc = 60602
            vm._jump(1472)
            continue
        if vm.block == 1472:
            tick(60602)
            _phi(vm, 60602, (8097, 2, 8096, 1471, 8091, 1470))
            tick(60609)
            _phi(vm, 60609, (8098, 2, 8094, 1471, 8092, 1470))
            tick(60616)
            vm.pc = 60617
            tick(60617)
            vm.pc = 60620
            vm.auxiliary = (0, 1858228470)
            tick(60620)
            vm.pc = 60625
            vm._write(8099, int(memory.load(cells.pointer(8090), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(60625)
            vm.pc = 60629
            vm._jump(1473 if cells.value(8099) != 0 else 1474)
            continue
        if vm.block == 1473:
            tick(60629)
            vm.pc = 60633
            value = memory.load(cells.value(8098), 1)
            vm._write(8100, value, 4, 'high.load')
            tick(60633)
            vm.pc = 60637
            pointer = cells.value(8097)
            value = memory.load(cells.pointer(8100), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(60637)
            vm.pc = 60639
            vm._jump(1474)
            continue
        if vm.block == 1474:
            tick(60639)
            vm.pc = 60644
            cells.copy_q_clear_owned(137, 8101)
            tick(60644)
            vm.pc = 60649
            cells.copy_q_clear_owned(67, 8102)
            tick(60649)
            vm.pc = 60653
            pointer = cells.value(67)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(60653)
            vm.pc = 60655
            vm._jump(1475)
            continue
        if vm.block == 1475:
            tick(60655)
            _phi(vm, 60655, (8103, 2, 145, 1474, 8104, 1476))
            tick(60662)
            vm.pc = 60667
            vm._write(8105, int(cells.value(8103) < cells.value(166)), 4, 'once18.unsigned_q')
            tick(60667)
            vm.pc = 60671
            vm._jump(1477 if cells.value(8105) != 0 else 1478)
            continue
        if vm.block == 1477:
            tick(60671)
            vm.pc = 60676
            vm._write(8106, cells.value(8103) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(60676)
            vm.pc = 60677
            tick(60677)
            vm.pc = 60680
            vm.auxiliary = (0, 410243074)
            tick(60680)
            vm.pc = 60685
            vm._write(8107, memory.load(cells.pointer(8106), 2, signed=True) + memory.load(cells.pointer(3272), 2, signed=True), 8, 'once1.integer')
            tick(60685)
            vm.pc = 60690
            value = memory.load(cells.pointer(8107), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(8108, value >> (count & 31), 4, 'once8.logical_shift')
            tick(60690)
            _pointer(vm, 60690, 91, 112, 8109, (145, 391))
            tick(60698)
            vm.pc = 60702
            value = memory.load(cells.value(8109), 8)
            vm._write(8110, value, 8, 'high.load')
            tick(60702)
            vm.pc = 60707
            vm._write(8111, cells.value(8110) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(60707)
            vm.pc = 60712
            vm._write(8112, memory.load(cells.pointer(8111), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(60712)
            vm.pc = 60715
            vm.auxiliary = (0, 6269)
            tick(60715)
            vm.pc = 60721
            vm._write(8113, memory.load(cells.pointer(8108), 2, signed=True) ^ memory.load(cells.pointer(8112), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(60721)
            vm.pc = 60726
            _convert(vm, 8, 8113, 8114)
            tick(60726)
            _pointer(vm, 60726, 91, 112, 8115, (145, 311, 8114))
            tick(60735)
            vm.pc = 60739
            value = memory.load(cells.value(8115), 8)
            vm._write(8116, value, 8, 'high.load')
            tick(60739)
            vm.pc = 60742
            vm.auxiliary = (0, 1133691843)
            tick(60742)
            _equal(vm, 60747, 8, 8116, 1140, 8117)
            tick(60747)
            vm.pc = 60751
            vm._jump(1479 if cells.value(8117) != 0 else 1480)
            continue
        if vm.block == 1480:
            tick(60751)
            vm.pc = 60756
            value = memory.load(cells.pointer(8110), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(8118, value >> (count & 63), 8, 'once8.logical_shift')
            tick(60756)
            vm.pc = 60761
            vm._write(8119, cells.value(8118) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(60761)
            vm.pc = 60762
            tick(60762)
            vm.pc = 60765
            vm.auxiliary = (0, 31524)
            tick(60765)
            vm.pc = 60771
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8120, memory.load(cells.pointer(8119), 2, signed=True) ^ memory.load(cells.pointer(8107), 2, signed=True), 8, 'typed.selector5.q')
            tick(60771)
            vm.pc = 60776
            vm._write(8121, memory.load(cells.pointer(8120), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(60776)
            vm.pc = 60781
            _convert(vm, 8, 8121, 8122)
            tick(60781)
            _pointer(vm, 60781, 78, 8116, 8123, (8122,))
            tick(60788)
            vm.pc = 60792
            value = memory.load(cells.value(8123), 8)
            vm._write(8124, value, 8, 'high.load')
            tick(60792)
            vm.pc = 60795
            vm.auxiliary = (0, 2012401171)
            tick(60795)
            vm.pc = 60800
            vm._write(8125, int(memory.load(cells.pointer(8124), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(60800)
            vm.pc = 60804
            vm._jump(1479 if cells.value(8125) != 0 else 1481)
            continue
        if vm.block == 1481:
            tick(60804)
            _pointer(vm, 60804, 79, 8124, 8126, (145, 269))
            tick(60812)
            vm.pc = 60816
            value = memory.load(cells.value(8126), 2)
            vm._write(8127, value, 4, 'high.load')
            tick(60816)
            vm.pc = 60817
            tick(60817)
            vm.pc = 60820
            vm.auxiliary = (0, 1577234147)
            tick(60820)
            _equal(vm, 60825, 2, 8127, 8107, 8128)
            tick(60825)
            vm.pc = 60829
            vm._jump(1482 if cells.value(8128) != 0 else 1479)
            continue
        if vm.block == 1482:
            tick(60829)
            _pointer(vm, 60829, 79, 8124, 8129, (145, 360))
            tick(60837)
            vm.pc = 60841
            value = memory.load(cells.value(8129), 4)
            vm._write(8130, value, 4, 'L5.unsigned_load')
            tick(60841)
            _pointer(vm, 60841, 79, 8124, 8131, (145, 158))
            tick(60849)
            vm.pc = 60853
            value = memory.load(cells.value(8131), 4)
            vm._write(8132, value, 4, 'high.load')
            tick(60853)
            vm.pc = 60858
            vm._write(8133, memory.load(cells.pointer(8132), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'L14.binary_q')
            tick(60858)
            vm.pc = 60859
            tick(60859)
            vm.pc = 60862
            vm.auxiliary = (0, 1825374723)
            tick(60862)
            vm.pc = 60867
            vm._write(8134, memory.load(cells.pointer(8133), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(60867)
            _pointer(vm, 60867, 79, 8124, 8135, (145, 269))
            tick(60875)
            vm.pc = 60879
            value = memory.load(cells.value(8135), 2)
            vm._write(8136, value, 4, 'high.load')
            tick(60879)
            vm.pc = 60884
            _convert(vm, 4, 8136, 8137)
            tick(60884)
            vm.pc = 60887
            vm.auxiliary = (0, 23084)
            tick(60887)
            vm.pc = 60893
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8138, memory.load(cells.pointer(8134), 4, signed=True) ^ memory.load(cells.pointer(8137), 4, signed=True), 8, 'typed.selector5.q')
            tick(60893)
            vm.pc = 60896
            vm.auxiliary = (0, 557150723)
            tick(60896)
            vm.pc = 60901
            vm._write(8139, memory.load(cells.pointer(8138), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(60901)
            _pointer(vm, 60901, 79, 8124, 8140, (145, 311))
            tick(60909)
            vm.pc = 60913
            value = memory.load(cells.value(8140), 8)
            vm._write(8141, value, 8, 'L5.unsigned_load')
            tick(60913)
            vm.pc = 60918
            cells.copy_q_clear_owned(8141, 8142)
            tick(60918)
            vm.pc = 60923
            vm._write(8143, cells.value(8142) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(60923)
            vm.pc = 60926
            vm.auxiliary = (0, 35340)
            tick(60926)
            vm.pc = 60932
            vm._write(8144, memory.load(cells.pointer(8139), 4, signed=True) ^ memory.load(cells.pointer(8143), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(60932)
            vm.pc = 60935
            vm.auxiliary = (0, 252154371)
            tick(60935)
            vm.pc = 60940
            vm._write(8145, memory.load(cells.pointer(8144), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(60940)
            vm.pc = 60945
            value = memory.load(cells.pointer(8142), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(8146, value >> (count & 63), 8, 'once8.logical_shift')
            tick(60945)
            vm.pc = 60950
            vm._write(8147, cells.value(8146) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(60950)
            vm.pc = 60953
            vm.auxiliary = (0, 48996)
            tick(60953)
            vm.pc = 60959
            vm._write(8148, memory.load(cells.pointer(8145), 4, signed=True) ^ memory.load(cells.pointer(8147), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(60959)
            vm.pc = 60962
            vm.auxiliary = (0, 865735172)
            tick(60962)
            vm.pc = 60967
            vm._write(8149, memory.load(cells.pointer(8148), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(60967)
            vm.pc = 60972
            vm._write(8150, cells.value(8110) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(60972)
            vm.pc = 60975
            vm.auxiliary = (0, 63549)
            tick(60975)
            vm.pc = 60981
            vm._write(8151, memory.load(cells.pointer(8149), 4, signed=True) ^ memory.load(cells.pointer(8150), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(60981)
            vm.pc = 60984
            vm.auxiliary = (0, 1764508163)
            tick(60984)
            vm.pc = 60989
            vm._write(8152, memory.load(cells.pointer(8151), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(60989)
            vm.pc = 60994
            value = memory.load(cells.pointer(8110), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(8153, value >> (count & 63), 8, 'once8.logical_shift')
            tick(60994)
            vm.pc = 60999
            vm._write(8154, cells.value(8153) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(60999)
            vm.pc = 61002
            vm.auxiliary = (0, 11550)
            tick(61002)
            vm.pc = 61008
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8155, memory.load(cells.pointer(8152), 4, signed=True) ^ memory.load(cells.pointer(8154), 4, signed=True), 8, 'typed.selector5.q')
            tick(61008)
            vm.pc = 61011
            vm.auxiliary = (0, 660955651)
            tick(61011)
            vm.pc = 61016
            vm._write(8156, memory.load(cells.pointer(8155), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(61016)
            vm.pc = 61020
            value = memory.load(cells.value(8141), 1)
            vm._write(8157, value, 4, 'high.load')
            tick(61020)
            vm.pc = 61025
            _convert(vm, 4, 8157, 8158)
            tick(61025)
            vm.pc = 61030
            vm._write(8159, memory.load(cells.pointer(8156), 4, signed=True) ^ memory.load(cells.pointer(8158), 4, signed=True), 8, 'L14.binary_q')
            tick(61030)
            vm.pc = 61033
            vm.auxiliary = (0, 1625051652)
            tick(61033)
            vm.pc = 61038
            vm._write(8160, memory.load(cells.pointer(8159), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(61038)
            vm.pc = 61041
            vm.auxiliary = (0, 1288889411)
            tick(61041)
            _equal(vm, 61046, 4, 8130, 8160, 8161)
            tick(61046)
            vm.pc = 61050
            vm._jump(1479 if cells.value(8161) != 0 else 1483)
            continue
        if vm.block == 1483:
            tick(61050)
            vm.pc = 61054
            pointer = cells.value(8129)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(61054)
            vm.pc = 61056
            vm._jump(1479)
            continue
        if vm.block == 1479:
            tick(61056)
            _phi(vm, 61056, (8162, 5, 857, 1477, 857, 1481, 8124, 1482, 8124, 1483, 8124, 1480))
            tick(61069)
            vm.pc = 61070
            tick(61070)
            vm.pc = 61073
            vm.auxiliary = (0, 1552081555)
            tick(61073)
            vm.pc = 61078
            vm._write(8163, int(memory.load(cells.pointer(8162), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(61078)
            vm.pc = 61082
            vm._jump(1484 if cells.value(8163) != 0 else 1485)
            continue
        if vm.block == 1485:
            tick(61082)
            _pointer(vm, 61082, 79, 8162, 8164, (145, 311))
            tick(61090)
            vm.pc = 61094
            value = memory.load(cells.value(8164), 8)
            vm._write(8165, value, 8, 'high.load')
            tick(61094)
            vm.pc = 61098
            value = memory.load(cells.value(8165), 1)
            vm._write(8166, value, 4, 'high.load')
            tick(61098)
            _pointer(vm, 61098, 1, 8102, 8167, (8103,))
            tick(61105)
            vm.pc = 61109
            pointer = cells.value(8167)
            value = memory.load(cells.pointer(8166), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61109)
            vm.pc = 61111
            vm._jump(1476)
            continue
        if vm.block == 1484:
            tick(61111)
            _pointer(vm, 61111, 1, 8102, 8168, (8103,))
            tick(61118)
            vm.pc = 61122
            pointer = cells.value(8168)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61122)
            vm.pc = 61124
            vm._jump(1476)
            continue
        if vm.block == 1476:
            tick(61124)
            vm.pc = 61125
            tick(61125)
            vm.pc = 61128
            vm.auxiliary = (0, 517660674)
            tick(61128)
            vm.pc = 61133
            vm._write(8104, memory.load(cells.pointer(8103), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(61133)
            vm.pc = 61135
            vm._jump(1475)
            continue
        if vm.block == 1478:
            tick(61135)
            vm.pc = 61139
            value = memory.load(cells.value(67), 8)
            vm._write(8169, value, 8, 'high.load')
            tick(61139)
            vm.pc = 61144
            vm._write(8170, cells.value(8169) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(61144)
            vm.pc = 61148
            pointer = cells.value(137)
            value = memory.load(cells.pointer(8170), 2)
            memory.store(pointer, value, 2, source='high.store')
            tick(61148)
            _pointer(vm, 61148, 70, 103, 8171, (145, 166))
            tick(61156)
            vm.pc = 61161
            cells.copy_q_clear_owned(8171, 8172)
            tick(61161)
            vm.pc = 61162
            tick(61162)
            vm.pc = 61165
            vm.auxiliary = (0, 29023)
            tick(61165)
            vm.pc = 61170
            vm._write(8173, memory.load(cells.pointer(8172), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(61170)
            _pointer(vm, 61170, 1, 8101, 8174, (163,))
            tick(61177)
            vm.pc = 61181
            value = memory.load(cells.value(8101), 1)
            vm._write(8175, value, 4, 'L5.unsigned_load')
            tick(61181)
            _pointer(vm, 61181, 1, 8171, 8176, (163,))
            tick(61188)
            vm.pc = 61192
            pointer = cells.value(8171)
            value = memory.load(cells.pointer(8175), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61192)
            vm.pc = 61197
            cells.copy_q_clear_owned(8176, 8177)
            tick(61197)
            vm.pc = 61200
            vm.auxiliary = (0, 54606)
            tick(61200)
            vm.pc = 61205
            vm._write(8178, memory.load(cells.pointer(8177), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(61205)
            vm.pc = 61208
            vm.auxiliary = (0, 635621460)
            tick(61208)
            vm.pc = 61213
            vm._write(8179, int(memory.load(cells.pointer(8178), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(61213)
            vm.pc = 61217
            vm._jump(1486 if cells.value(8179) != 0 else 1487)
            continue
        if vm.block == 1486:
            tick(61217)
            _pointer(vm, 61217, 1, 8174, 8180, (163,))
            tick(61224)
            vm.pc = 61228
            value = memory.load(cells.value(8174), 1)
            vm._write(8181, value, 4, 'high.load')
            tick(61228)
            _pointer(vm, 61228, 1, 8176, 8182, (163,))
            tick(61235)
            vm.pc = 61239
            pointer = cells.value(8176)
            value = memory.load(cells.pointer(8181), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61239)
            vm.pc = 61241
            vm._jump(1487)
            continue
        if vm.block == 1487:
            tick(61241)
            _phi(vm, 61241, (8183, 2, 158, 1486, 269, 1478))
            tick(61248)
            _phi(vm, 61248, (8184, 2, 8182, 1486, 8176, 1478))
            tick(61255)
            _phi(vm, 61255, (8185, 2, 8180, 1486, 8174, 1478))
            tick(61262)
            vm.pc = 61267
            cells.copy_q_clear_owned(8184, 8186)
            tick(61267)
            vm.pc = 61272
            vm._write(8187, memory.load(cells.pointer(8186), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(61272)
            vm.pc = 61273
            tick(61273)
            vm.pc = 61276
            vm.auxiliary = (0, 1861369812)
            tick(61276)
            vm.pc = 61281
            vm._write(8188, int(memory.load(cells.pointer(8187), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(61281)
            vm.pc = 61284
            vm.auxiliary = (0, 1955727126)
            tick(61284)
            vm.pc = 61289
            vm._write(8189, int(memory.load(cells.pointer(8183), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(61289)
            vm.pc = 61292
            vm.auxiliary = (0, 54308)
            tick(61292)
            vm.pc = 61297
            vm._write(8190, memory.load(cells.pointer(8188), 1, signed=True) & memory.load(cells.pointer(8189), 1, signed=True), 8, 'typed.selector1.q')
            tick(61297)
            vm.pc = 61301
            vm._jump(1488 if cells.value(8190) != 0 else 1489)
            continue
        if vm.block == 1488:
            tick(61301)
            _pointer(vm, 61301, 1, 8185, 8191, (163,))
            tick(61308)
            vm.pc = 61312
            value = memory.load(cells.value(8185), 1)
            vm._write(8192, value, 4, 'high.load')
            tick(61312)
            _pointer(vm, 61312, 1, 8184, 8193, (163,))
            tick(61319)
            vm.pc = 61323
            pointer = cells.value(8184)
            value = memory.load(cells.pointer(8192), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61323)
            vm.pc = 61324
            tick(61324)
            vm.pc = 61327
            vm.auxiliary = (0, 1868652546)
            tick(61327)
            vm.pc = 61332
            vm._write(8194, memory.load(cells.pointer(8183), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(61332)
            vm.pc = 61334
            vm._jump(1489)
            continue
        if vm.block == 1489:
            tick(61334)
            _phi(vm, 61334, (8195, 2, 8194, 1488, 8183, 1487))
            tick(61341)
            _phi(vm, 61341, (8196, 2, 8193, 1488, 8184, 1487))
            tick(61348)
            _phi(vm, 61348, (8197, 2, 8191, 1488, 8185, 1487))
            tick(61355)
            vm.pc = 61360
            cells.copy_q_clear_owned(8196, 8198)
            tick(61360)
            vm.pc = 61365
            cells.copy_q_clear_owned(8197, 8199)
            tick(61365)
            vm.pc = 61366
            tick(61366)
            vm.pc = 61369
            vm.auxiliary = (0, 1047694998)
            tick(61369)
            vm.pc = 61374
            vm._write(8200, int(memory.load(cells.pointer(8195), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(61374)
            vm.pc = 61378
            vm._jump(1490 if cells.value(8200) != 0 else 1491)
            continue
        if vm.block == 1490:
            tick(61378)
            _pointer(vm, 61378, 1, 8197, 8201, (172,))
            tick(61385)
            vm.pc = 61390
            cells.copy_q_clear_owned(8201, 8202)
            tick(61390)
            vm.pc = 61394
            value = memory.load(cells.value(8199), 4)
            vm._write(8203, value, 4, 'high.load')
            tick(61394)
            _pointer(vm, 61394, 1, 8196, 8204, (172,))
            tick(61401)
            vm.pc = 61406
            cells.copy_q_clear_owned(8204, 8205)
            tick(61406)
            vm.pc = 61410
            pointer = cells.value(8198)
            value = memory.load(cells.pointer(8203), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(61410)
            vm.pc = 61411
            tick(61411)
            vm.pc = 61414
            vm.auxiliary = (0, 1012019202)
            tick(61414)
            vm.pc = 61419
            vm._write(8206, memory.load(cells.pointer(8195), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(61419)
            vm.pc = 61421
            vm._jump(1491)
            continue
        if vm.block == 1491:
            tick(61421)
            _phi(vm, 61421, (8207, 2, 8206, 1490, 8195, 1489))
            tick(61428)
            _phi(vm, 61428, (8208, 2, 8205, 1490, 8198, 1489))
            tick(61435)
            _phi(vm, 61435, (8209, 2, 8202, 1490, 8199, 1489))
            tick(61442)
            vm.pc = 61443
            tick(61443)
            vm.pc = 61446
            vm.auxiliary = (0, 1705178134)
            tick(61446)
            vm.pc = 61451
            vm._write(8210, int(memory.load(cells.pointer(8207), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(61451)
            vm.pc = 61455
            vm._jump(1492 if cells.value(8210) != 0 else 1493)
            continue
        if vm.block == 1492:
            tick(61455)
            _pointer(vm, 61455, 3, 8209, 8211, (163,))
            tick(61462)
            vm.pc = 61466
            value = memory.load(cells.value(8209), 4)
            vm._write(8212, value, 4, 'high.load')
            tick(61466)
            _pointer(vm, 61466, 3, 8208, 8213, (163,))
            tick(61473)
            vm.pc = 61477
            pointer = cells.value(8208)
            value = memory.load(cells.pointer(8212), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(61477)
            vm.pc = 61478
            tick(61478)
            vm.pc = 61481
            vm.auxiliary = (0, 1109508097)
            tick(61481)
            vm.pc = 61486
            vm._write(8214, memory.load(cells.pointer(8207), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(61486)
            vm.pc = 61488
            vm._jump(1493)
            continue
        if vm.block == 1493:
            tick(61488)
            _phi(vm, 61488, (8215, 2, 8214, 1492, 8207, 1491))
            tick(61495)
            _phi(vm, 61495, (8216, 2, 8213, 1492, 8208, 1491))
            tick(61502)
            _phi(vm, 61502, (8217, 2, 8211, 1492, 8209, 1491))
            tick(61509)
            vm.pc = 61510
            tick(61510)
            vm.pc = 61513
            vm.auxiliary = (0, 384961286)
            tick(61513)
            vm.pc = 61518
            vm._write(8218, int(memory.load(cells.pointer(8215), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(61518)
            vm.pc = 61522
            vm._jump(1494 if cells.value(8218) != 0 else 1495)
            continue
        if vm.block == 1494:
            tick(61522)
            _pointer(vm, 61522, 3, 8217, 8219, (163,))
            tick(61529)
            vm.pc = 61533
            value = memory.load(cells.value(8217), 4)
            vm._write(8220, value, 4, 'high.load')
            tick(61533)
            _pointer(vm, 61533, 3, 8216, 8221, (163,))
            tick(61540)
            vm.pc = 61544
            pointer = cells.value(8216)
            value = memory.load(cells.pointer(8220), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(61544)
            vm.pc = 61545
            tick(61545)
            vm.pc = 61548
            vm.auxiliary = (0, 1474297857)
            tick(61548)
            vm.pc = 61553
            vm._write(8222, memory.load(cells.pointer(8215), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(61553)
            vm.pc = 61555
            vm._jump(1495)
            continue
        if vm.block == 1495:
            tick(61555)
            _phi(vm, 61555, (8223, 2, 8222, 1494, 8215, 1493))
            tick(61562)
            _phi(vm, 61562, (8224, 2, 8221, 1494, 8216, 1493))
            tick(61569)
            _phi(vm, 61569, (8225, 2, 8219, 1494, 8217, 1493))
            tick(61576)
            vm.pc = 61581
            cells.copy_q_clear_owned(8224, 8226)
            tick(61581)
            vm.pc = 61586
            cells.copy_q_clear_owned(8225, 8227)
            tick(61586)
            vm.pc = 61587
            tick(61587)
            vm.pc = 61590
            vm.auxiliary = (0, 750915286)
            tick(61590)
            vm.pc = 61595
            vm._write(8228, int(memory.load(cells.pointer(8223), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(61595)
            vm.pc = 61599
            vm._jump(1496 if cells.value(8228) != 0 else 1497)
            continue
        if vm.block == 1496:
            tick(61599)
            _pointer(vm, 61599, 1, 8227, 8229, (163,))
            tick(61606)
            vm.pc = 61610
            value = memory.load(cells.value(8227), 1)
            vm._write(8230, value, 4, 'high.load')
            tick(61610)
            _pointer(vm, 61610, 1, 8226, 8231, (163,))
            tick(61617)
            vm.pc = 61621
            pointer = cells.value(8226)
            value = memory.load(cells.pointer(8230), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61621)
            vm.pc = 61622
            tick(61622)
            vm.pc = 61625
            vm.auxiliary = (0, 2118991873)
            tick(61625)
            vm.pc = 61630
            vm._write(8232, memory.load(cells.pointer(8223), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(61630)
            vm.pc = 61632
            vm._jump(1497)
            continue
        if vm.block == 1497:
            tick(61632)
            _phi(vm, 61632, (8233, 2, 8232, 1496, 8223, 1495))
            tick(61639)
            _phi(vm, 61639, (8234, 2, 8231, 1496, 8226, 1495))
            tick(61646)
            _phi(vm, 61646, (8235, 2, 8229, 1496, 8227, 1495))
            tick(61653)
            vm.pc = 61654
            tick(61654)
            vm.pc = 61657
            vm.auxiliary = (0, 289576374)
            tick(61657)
            vm.pc = 61662
            vm._write(8236, int(memory.load(cells.pointer(8233), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(61662)
            vm.pc = 61666
            vm._jump(1498 if cells.value(8236) != 0 else 1499)
            continue
        if vm.block == 1498:
            tick(61666)
            _pointer(vm, 61666, 1, 8235, 8237, (163,))
            tick(61673)
            vm.pc = 61677
            value = memory.load(cells.value(8235), 1)
            vm._write(8238, value, 4, 'high.load')
            tick(61677)
            _pointer(vm, 61677, 1, 8234, 8239, (163,))
            tick(61684)
            vm.pc = 61688
            pointer = cells.value(8234)
            value = memory.load(cells.pointer(8238), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61688)
            vm.pc = 61689
            tick(61689)
            vm.pc = 61692
            vm.auxiliary = (0, 1368739842)
            tick(61692)
            vm.pc = 61697
            vm._write(8240, memory.load(cells.pointer(8233), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(61697)
            vm.pc = 61699
            vm._jump(1499)
            continue
        if vm.block == 1499:
            tick(61699)
            _phi(vm, 61699, (8241, 2, 8240, 1498, 8233, 1497))
            tick(61706)
            _phi(vm, 61706, (8242, 2, 8239, 1498, 8234, 1497))
            tick(61713)
            _phi(vm, 61713, (8243, 2, 8237, 1498, 8235, 1497))
            tick(61720)
            vm.pc = 61721
            tick(61721)
            vm.pc = 61724
            vm.auxiliary = (0, 1024597158)
            tick(61724)
            vm.pc = 61729
            vm._write(8244, int(memory.load(cells.pointer(8241), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(61729)
            vm.pc = 61733
            vm._jump(1500 if cells.value(8244) != 0 else 1501)
            continue
        if vm.block == 1500:
            tick(61733)
            _pointer(vm, 61733, 1, 8243, 8245, (163,))
            tick(61740)
            vm.pc = 61744
            value = memory.load(cells.value(8243), 1)
            vm._write(8246, value, 4, 'high.load')
            tick(61744)
            _pointer(vm, 61744, 1, 8242, 8247, (163,))
            tick(61751)
            vm.pc = 61755
            pointer = cells.value(8242)
            value = memory.load(cells.pointer(8246), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61755)
            vm.pc = 61757
            vm._jump(1501)
            continue
        if vm.block == 1501:
            tick(61757)
            _phi(vm, 61757, (8248, 2, 8247, 1500, 8242, 1499))
            tick(61764)
            _phi(vm, 61764, (8249, 2, 8245, 1500, 8243, 1499))
            tick(61771)
            vm.pc = 61772
            tick(61772)
            vm.pc = 61775
            vm.auxiliary = (0, 321051462)
            tick(61775)
            vm.pc = 61780
            vm._write(8250, int(memory.load(cells.pointer(8241), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(61780)
            vm.pc = 61784
            vm._jump(1502 if cells.value(8250) != 0 else 1503)
            continue
        if vm.block == 1502:
            tick(61784)
            vm.pc = 61788
            value = memory.load(cells.value(8249), 1)
            vm._write(8251, value, 4, 'high.load')
            tick(61788)
            vm.pc = 61792
            pointer = cells.value(8248)
            value = memory.load(cells.pointer(8251), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61792)
            vm.pc = 61794
            vm._jump(1503)
            continue
        if vm.block == 1503:
            tick(61794)
            _pointer(vm, 61794, 70, 103, 8252, (145, 172))
            tick(61802)
            vm.pc = 61807
            cells.copy_q_clear_owned(8252, 8253)
            tick(61807)
            vm.pc = 61812
            vm._write(8254, memory.load(cells.pointer(8253), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(61812)
            vm.pc = 61813
            tick(61813)
            vm.pc = 61816
            vm.auxiliary = (0, 1227009140)
            tick(61816)
            vm.pc = 61821
            vm._write(8255, int(memory.load(cells.pointer(8254), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(61821)
            vm.pc = 61825
            vm._jump(1504 if cells.value(8255) != 0 else 1505)
            continue
        if vm.block == 1504:
            tick(61825)
            _pointer(vm, 61825, 1, 7858, 8256, (163,))
            tick(61832)
            vm.pc = 61836
            value = memory.load(cells.value(7858), 1)
            vm._write(8257, value, 4, 'high.load')
            tick(61836)
            _pointer(vm, 61836, 1, 8252, 8258, (163,))
            tick(61843)
            vm.pc = 61847
            pointer = cells.value(8252)
            value = memory.load(cells.pointer(8257), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(61847)
            vm.pc = 61849
            vm._jump(1505)
            continue
        if vm.block == 1505:
            tick(61849)
            _phi(vm, 61849, (8259, 2, 149, 1504, 360, 1503))
            tick(61856)
            _phi(vm, 61856, (8260, 2, 8258, 1504, 8252, 1503))
            tick(61863)
            _phi(vm, 61863, (8261, 2, 8256, 1504, 7858, 1503))
            tick(61870)
            vm.pc = 61875
            cells.copy_q_clear_owned(8260, 8262)
            tick(61875)
            vm.pc = 61876
            tick(61876)
            vm.pc = 61879
            vm.auxiliary = (0, 28717)
            tick(61879)
            vm.pc = 61884
            vm._write(8263, memory.load(cells.pointer(8262), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'typed.selector1.q')
            tick(61884)
            vm.pc = 61887
            vm.auxiliary = (0, 850570404)
            tick(61887)
            vm.pc = 61892
            vm._write(8264, int(memory.load(cells.pointer(8263), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L27.comparison')
            tick(61892)
            vm.pc = 61895
            vm.auxiliary = (0, 789714774)
            tick(61895)
            vm.pc = 61900
            vm._write(8265, int(memory.load(cells.pointer(8259), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(61900)
            vm.pc = 61903
            vm.auxiliary = (0, 20828)
            tick(61903)
            vm.pc = 61908
            vm._write(8266, memory.load(cells.pointer(8264), 1, signed=True) & memory.load(cells.pointer(8265), 1, signed=True), 8, 'typed.selector1.q')
            tick(61908)
            vm.pc = 61912
            vm._jump(1506 if cells.value(8266) != 0 else 1507)
            continue
        if vm.block == 1506:
            tick(61912)
            _pointer(vm, 61912, 1, 8261, 8267, (163,))
            tick(61919)
            vm.pc = 61923
            value = memory.load(cells.value(8261), 1)
            vm._write(8268, value, 4, 'high.load')
            tick(61923)
            _pointer(vm, 61923, 1, 8260, 8269, (163,))
            tick(61930)
            vm.pc = 61934
            pointer = cells.value(8260)
            value = memory.load(cells.pointer(8268), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(61934)
            vm.pc = 61935
            tick(61935)
            vm.pc = 61938
            vm.auxiliary = (0, 556998657)
            tick(61938)
            vm.pc = 61943
            vm._write(8270, memory.load(cells.pointer(8259), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(61943)
            vm.pc = 61945
            vm._jump(1507)
            continue
        if vm.block == 1507:
            tick(61945)
            _phi(vm, 61945, (8271, 2, 8270, 1506, 8259, 1505))
            tick(61952)
            _phi(vm, 61952, (8272, 2, 8269, 1506, 8260, 1505))
            tick(61959)
            _phi(vm, 61959, (8273, 2, 8267, 1506, 8261, 1505))
            tick(61966)
            vm.pc = 61971
            cells.copy_q_clear_owned(8272, 8274)
            tick(61971)
            vm.pc = 61976
            vm._write(8275, memory.load(cells.pointer(8274), 8, signed=True) & memory.load(cells.pointer(169), 8, signed=True), 8, 'L13.binary_q')
            tick(61976)
            vm.pc = 61977
            tick(61977)
            vm.pc = 61980
            vm.auxiliary = (0, 1353842916)
            tick(61980)
            vm.pc = 61985
            vm._write(8276, int(memory.load(cells.pointer(8275), 8, signed=True) != memory.load(cells.pointer(145), 8, signed=True)), 4, 'L30.comparison')
            tick(61985)
            vm.pc = 61988
            vm.auxiliary = (0, 170021334)
            tick(61988)
            vm.pc = 61993
            vm._write(8277, int(memory.load(cells.pointer(8271), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(61993)
            vm.pc = 61996
            vm.auxiliary = (0, 12807)
            tick(61996)
            vm.pc = 62001
            vm._write(8278, memory.load(cells.pointer(8276), 1, signed=True) & memory.load(cells.pointer(8277), 1, signed=True), 8, 'typed.selector1.q')
            tick(62001)
            vm.pc = 62005
            vm._jump(1508 if cells.value(8278) != 0 else 1509)
            continue
        if vm.block == 1508:
            tick(62005)
            _pointer(vm, 62005, 1, 8273, 8279, (163,))
            tick(62012)
            vm.pc = 62016
            value = memory.load(cells.value(8273), 1)
            vm._write(8280, value, 4, 'high.load')
            tick(62016)
            _pointer(vm, 62016, 1, 8272, 8281, (163,))
            tick(62023)
            vm.pc = 62027
            pointer = cells.value(8272)
            value = memory.load(cells.pointer(8280), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(62027)
            vm.pc = 62028
            tick(62028)
            vm.pc = 62031
            vm.auxiliary = (0, 513769473)
            tick(62031)
            vm.pc = 62036
            vm._write(8282, memory.load(cells.pointer(8271), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(62036)
            vm.pc = 62038
            vm._jump(1509)
            continue
        if vm.block == 1509:
            tick(62038)
            _phi(vm, 62038, (8283, 2, 8282, 1508, 8271, 1507))
            tick(62045)
            _phi(vm, 62045, (8284, 2, 8281, 1508, 8272, 1507))
            tick(62052)
            _phi(vm, 62052, (8285, 2, 8279, 1508, 8273, 1507))
            tick(62059)
            vm.pc = 62064
            cells.copy_q_clear_owned(8284, 8286)
            tick(62064)
            vm.pc = 62069
            cells.copy_q_clear_owned(8285, 8287)
            tick(62069)
            vm.pc = 62070
            tick(62070)
            vm.pc = 62073
            vm.auxiliary = (0, 220333462)
            tick(62073)
            vm.pc = 62078
            vm._write(8288, int(memory.load(cells.pointer(8283), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(62078)
            vm.pc = 62082
            vm._jump(1510 if cells.value(8288) != 0 else 1511)
            continue
        if vm.block == 1510:
            tick(62082)
            _pointer(vm, 62082, 1, 8285, 8289, (172,))
            tick(62089)
            vm.pc = 62094
            cells.copy_q_clear_owned(8289, 8290)
            tick(62094)
            vm.pc = 62098
            value = memory.load(cells.value(8287), 4)
            vm._write(8291, value, 4, 'high.load')
            tick(62098)
            _pointer(vm, 62098, 1, 8284, 8292, (172,))
            tick(62105)
            vm.pc = 62110
            cells.copy_q_clear_owned(8292, 8293)
            tick(62110)
            vm.pc = 62114
            pointer = cells.value(8286)
            value = memory.load(cells.pointer(8291), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(62114)
            vm.pc = 62115
            tick(62115)
            vm.pc = 62118
            vm.auxiliary = (0, 659922946)
            tick(62118)
            vm.pc = 62123
            vm._write(8294, memory.load(cells.pointer(8283), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(62123)
            vm.pc = 62125
            vm._jump(1511)
            continue
        if vm.block == 1511:
            tick(62125)
            _phi(vm, 62125, (8295, 2, 8294, 1510, 8283, 1509))
            tick(62132)
            _phi(vm, 62132, (8296, 2, 8293, 1510, 8286, 1509))
            tick(62139)
            _phi(vm, 62139, (8297, 2, 8290, 1510, 8287, 1509))
            tick(62146)
            vm.pc = 62147
            tick(62147)
            vm.pc = 62150
            vm.auxiliary = (0, 1336028150)
            tick(62150)
            vm.pc = 62155
            vm._write(8298, int(memory.load(cells.pointer(8295), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(62155)
            vm.pc = 62159
            vm._jump(1512 if cells.value(8298) != 0 else 1513)
            continue
        if vm.block == 1512:
            tick(62159)
            _pointer(vm, 62159, 3, 8297, 8299, (163,))
            tick(62166)
            vm.pc = 62170
            value = memory.load(cells.value(8297), 4)
            vm._write(8300, value, 4, 'high.load')
            tick(62170)
            _pointer(vm, 62170, 3, 8296, 8301, (163,))
            tick(62177)
            vm.pc = 62181
            pointer = cells.value(8296)
            value = memory.load(cells.pointer(8300), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(62181)
            vm.pc = 62182
            tick(62182)
            vm.pc = 62185
            vm.auxiliary = (0, 266928129)
            tick(62185)
            vm.pc = 62190
            vm._write(8302, memory.load(cells.pointer(8295), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(62190)
            vm.pc = 62192
            vm._jump(1513)
            continue
        if vm.block == 1513:
            tick(62192)
            _phi(vm, 62192, (8303, 2, 8302, 1512, 8295, 1511))
            tick(62199)
            _phi(vm, 62199, (8304, 2, 8301, 1512, 8296, 1511))
            tick(62206)
            _phi(vm, 62206, (8305, 2, 8299, 1512, 8297, 1511))
            tick(62213)
            vm.pc = 62214
            tick(62214)
            vm.pc = 62217
            vm.auxiliary = (0, 990007094)
            tick(62217)
            vm.pc = 62222
            vm._write(8306, int(memory.load(cells.pointer(8303), 4, signed=True) > memory.load(cells.pointer(149), 4, signed=True)), 4, 'L25.comparison')
            tick(62222)
            vm.pc = 62226
            vm._jump(1514 if cells.value(8306) != 0 else 1515)
            continue
        if vm.block == 1514:
            tick(62226)
            _pointer(vm, 62226, 3, 8305, 8307, (163,))
            tick(62233)
            vm.pc = 62237
            value = memory.load(cells.value(8305), 4)
            vm._write(8308, value, 4, 'high.load')
            tick(62237)
            _pointer(vm, 62237, 3, 8304, 8309, (163,))
            tick(62244)
            vm.pc = 62248
            pointer = cells.value(8304)
            value = memory.load(cells.pointer(8308), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(62248)
            vm.pc = 62249
            tick(62249)
            vm.pc = 62252
            vm.auxiliary = (0, 202272770)
            tick(62252)
            vm.pc = 62257
            vm._write(8310, memory.load(cells.pointer(8303), 4, signed=True) + memory.load(cells.pointer(1034), 4, signed=True), 8, 'once1.integer')
            tick(62257)
            vm.pc = 62259
            vm._jump(1515)
            continue
        if vm.block == 1515:
            tick(62259)
            _phi(vm, 62259, (8311, 2, 8310, 1514, 8303, 1513))
            tick(62266)
            _phi(vm, 62266, (8312, 2, 8309, 1514, 8304, 1513))
            tick(62273)
            _phi(vm, 62273, (8313, 2, 8307, 1514, 8305, 1513))
            tick(62280)
            vm.pc = 62285
            cells.copy_q_clear_owned(8312, 8314)
            tick(62285)
            vm.pc = 62290
            cells.copy_q_clear_owned(8313, 8315)
            tick(62290)
            vm.pc = 62291
            tick(62291)
            vm.pc = 62294
            vm.auxiliary = (0, 2041761862)
            tick(62294)
            vm.pc = 62299
            vm._write(8316, int(memory.load(cells.pointer(8311), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(62299)
            vm.pc = 62303
            vm._jump(1516 if cells.value(8316) != 0 else 1517)
            continue
        if vm.block == 1516:
            tick(62303)
            _pointer(vm, 62303, 1, 8315, 8317, (163,))
            tick(62310)
            vm.pc = 62314
            value = memory.load(cells.value(8315), 1)
            vm._write(8318, value, 4, 'high.load')
            tick(62314)
            _pointer(vm, 62314, 1, 8314, 8319, (163,))
            tick(62321)
            vm.pc = 62325
            pointer = cells.value(8314)
            value = memory.load(cells.pointer(8318), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(62325)
            vm.pc = 62326
            tick(62326)
            vm.pc = 62329
            vm.auxiliary = (0, 617844738)
            tick(62329)
            vm.pc = 62334
            vm._write(8320, memory.load(cells.pointer(8311), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(62334)
            vm.pc = 62336
            vm._jump(1517)
            continue
        if vm.block == 1517:
            tick(62336)
            _phi(vm, 62336, (8321, 2, 8320, 1516, 8311, 1515))
            tick(62343)
            _phi(vm, 62343, (8322, 2, 8319, 1516, 8314, 1515))
            tick(62350)
            _phi(vm, 62350, (8323, 2, 8317, 1516, 8315, 1515))
            tick(62357)
            vm.pc = 62358
            tick(62358)
            vm.pc = 62361
            vm.auxiliary = (0, 1143140662)
            tick(62361)
            vm.pc = 62366
            vm._write(8324, int(memory.load(cells.pointer(8321), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(62366)
            vm.pc = 62370
            vm._jump(1518 if cells.value(8324) != 0 else 1519)
            continue
        if vm.block == 1518:
            tick(62370)
            _pointer(vm, 62370, 1, 8323, 8325, (163,))
            tick(62377)
            vm.pc = 62381
            value = memory.load(cells.value(8323), 1)
            vm._write(8326, value, 4, 'high.load')
            tick(62381)
            _pointer(vm, 62381, 1, 8322, 8327, (163,))
            tick(62388)
            vm.pc = 62392
            pointer = cells.value(8322)
            value = memory.load(cells.pointer(8326), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(62392)
            vm.pc = 62393
            tick(62393)
            vm.pc = 62396
            vm.auxiliary = (0, 459046913)
            tick(62396)
            vm.pc = 62401
            vm._write(8328, memory.load(cells.pointer(8321), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(62401)
            vm.pc = 62403
            vm._jump(1519)
            continue
        if vm.block == 1519:
            tick(62403)
            _phi(vm, 62403, (8329, 2, 8328, 1518, 8321, 1517))
            tick(62410)
            _phi(vm, 62410, (8330, 2, 8327, 1518, 8322, 1517))
            tick(62417)
            _phi(vm, 62417, (8331, 2, 8325, 1518, 8323, 1517))
            tick(62424)
            vm.pc = 62425
            tick(62425)
            vm.pc = 62428
            vm.auxiliary = (0, 420654086)
            tick(62428)
            vm.pc = 62433
            vm._write(8332, int(memory.load(cells.pointer(8329), 4, signed=True) > memory.load(cells.pointer(158), 4, signed=True)), 4, 'L25.comparison')
            tick(62433)
            vm.pc = 62437
            vm._jump(1520 if cells.value(8332) != 0 else 1521)
            continue
        if vm.block == 1520:
            tick(62437)
            _pointer(vm, 62437, 1, 8331, 8333, (163,))
            tick(62444)
            vm.pc = 62448
            value = memory.load(cells.value(8331), 1)
            vm._write(8334, value, 4, 'L5.unsigned_load')
            tick(62448)
            _pointer(vm, 62448, 1, 8330, 8335, (163,))
            tick(62455)
            vm.pc = 62459
            pointer = cells.value(8330)
            value = memory.load(cells.pointer(8334), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(62459)
            vm.pc = 62461
            vm._jump(1521)
            continue
        if vm.block == 1521:
            tick(62461)
            _phi(vm, 62461, (8336, 2, 8335, 1520, 8330, 1519))
            tick(62468)
            _phi(vm, 62468, (8337, 2, 8333, 1520, 8331, 1519))
            tick(62475)
            vm.pc = 62476
            tick(62476)
            vm.pc = 62479
            vm.auxiliary = (0, 479352214)
            tick(62479)
            vm.pc = 62484
            vm._write(8338, int(memory.load(cells.pointer(8329), 4, signed=True) > memory.load(cells.pointer(269), 4, signed=True)), 4, 'L25.comparison')
            tick(62484)
            vm.pc = 62488
            vm._jump(1522 if cells.value(8338) != 0 else 1523)
            continue
        if vm.block == 1522:
            tick(62488)
            vm.pc = 62492
            value = memory.load(cells.value(8337), 1)
            vm._write(8339, value, 4, 'L5.unsigned_load')
            tick(62492)
            vm.pc = 62496
            pointer = cells.value(8336)
            value = memory.load(cells.pointer(8339), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(62496)
            vm.pc = 62498
            vm._jump(1523)
            continue
        if vm.block == 1523:
            tick(62498)
            vm.pc = 62500
            vm._jump(1524)
            continue
        if vm.block == 1524:
            tick(62500)
            _phi(vm, 62500, (8340, 2, 6224, 1523, 8341, 1525))
            tick(62507)
            _phi(vm, 62507, (8342, 2, 175, 1523, 8343, 1525))
            tick(62514)
            vm.pc = 62515
            tick(62515)
            vm.pc = 62518
            vm.auxiliary = (0, 932336659)
            tick(62518)
            _equal(vm, 62523, 8, 8342, 145, 8344)
            tick(62523)
            vm.pc = 62527
            vm._jump(1526 if cells.value(8344) != 0 else 1525)
            continue
        if vm.block == 1525:
            tick(62527)
            vm.pc = 62528
            tick(62528)
            vm.pc = 62531
            vm.auxiliary = (0, 1111588865)
            tick(62531)
            vm.pc = 62536
            vm._write(8343, memory.load(cells.pointer(8342), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(62536)
            _pointer(vm, 62536, 1, 8340, 8341, (163,))
            tick(62543)
            vm.pc = 62547
            pointer = cells.value(8340)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(62547)
            vm.pc = 62549
            vm._jump(1524)
            continue
        if vm.block == 1526:
            tick(62549)
            _pointer(vm, 62549, 70, 138, 8345, (145, 145))
            tick(62557)
            _pointer(vm, 62557, 70, 138, 8346, (145, 145))
            tick(62565)
            vm.pc = 62567
            vm._jump(1527)
            continue
        if vm.block == 1527:
            tick(62567)
            _phi(vm, 62567, (8347, 2, 292, 1526, 8348, 1528))
            tick(62574)
            _phi(vm, 62574, (8349, 2, 8346, 1526, 8350, 1528))
            tick(62581)
            vm.pc = 62582
            tick(62582)
            vm.pc = 62585
            vm.auxiliary = (0, 991080659)
            tick(62585)
            _equal(vm, 62590, 8, 8347, 145, 8351)
            tick(62590)
            vm.pc = 62594
            vm._jump(1529 if cells.value(8351) != 0 else 1528)
            continue
        if vm.block == 1528:
            tick(62594)
            vm.pc = 62595
            tick(62595)
            vm.pc = 62598
            vm.auxiliary = (0, 1417269250)
            tick(62598)
            vm.pc = 62603
            vm._write(8348, memory.load(cells.pointer(8347), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(62603)
            _pointer(vm, 62603, 1, 8349, 8350, (163,))
            tick(62610)
            vm.pc = 62614
            pointer = cells.value(8349)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(62614)
            vm.pc = 62616
            vm._jump(1527)
            continue
        if vm.block == 1529:
            tick(62616)
            vm.pc = 62621
            cells.copy_q_clear_owned(139, 8352)
            tick(62621)
            vm.pc = 62625
            pointer = cells.value(139)
            value = memory.load(cells.pointer(158), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(62625)
            _pointer(vm, 62625, 94, 140, 8353, (145, 145))
            tick(62633)
            vm.pc = 62638
            cells.copy_q_clear_owned(141, 8354)
            continue
        raise PrimarySemanticUnavailable('independent Main rest left its source-bound blocks')



TAIL_ENTRY = (62638, 1529, 1527, False)


def execute_primary_main_tail(vm, *, charge=None):
    if (type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != MAIN_SHA256 or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) != TAIL_ENTRY):
        raise PrimarySemanticUnavailable('independent Main literal tail requires its fixed entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            type(owner) is not dict or owner.get('vm') is not vm or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._execute_thread != get_ident() or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            len(runtime._program_calls) != 1 or runtime._program_calls[0]['name'] != 'main' or
            runtime._program_calls[0]['hosts'] is not None):
        raise PrimarySemanticUnavailable('independent Main literal tail requires its current owner without replay')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent Main literal tail cannot enter a stopped or pending body')
    state = dict(entryWord=62638, exitWord=66548, backend='DIRECT_MAIN_LITERAL_TAIL_WITH_GENERIC_HOST129',
                 referenceRecordCount=0, completed=False, traceComplete=False,
                 childGeneric=['host129'], completeIndependentMain=False)
    vm.primary_main_tail_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if charge is not None:
            charge()
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    _main_tail(vm, tick)
    state['completed'] = True
    return vm.result


class _DirectM16Pending:
    def __init__(self, vm, address, arguments, signature, argument_types):
        self.vm, self.runtime, self.memory = vm, vm.runtime, vm.memory
        self.owner = vm.runtime._active_main
        self.root = vm.runtime._program_calls[0]
        self.generation, self.thread = vm.runtime._main_generation, get_ident()
        self.program, self.cells = vm.program, vm.cells
        self.frame = (vm.cells.address, vm.arena_address, vm.arena_size, vm.image_base)
        self.regions = tuple(r for r in vm.memory._regions if r.address in self.frame[:2])
        self.site = (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.auxiliary)
        self.arguments, self.signature, self.argument_types = arguments, signature, argument_types
        self.address, self.call_index = address, len(vm.host_calls) - 1
        self.root_arguments = self.root['arguments']
        self.state = vm.primary_main_tail_state
        self.retry = tuple(getattr(vm.runtime, name, False) for name in
                           ('host2252_stage1_retry', 'host2252_stage2_g_retry',
                            'host2252_final_f_retry', 'host2252_control_m'))
        self.pending, self.stage, self.pointer = None, None, None
        self.started = self.running = self.completed = self.paused = self.terminal = False

    def validate(self, vm, *, returned=False):
        runtime = self.runtime
        if (type(self) is not _DirectM16Pending or self.vm is not vm or runtime is None or
                type(vm) is not PrimaryVM or vm.runtime is not runtime or vm.memory is not self.memory or
                vm.program is not self.program or sha256(vm.program.raw).hexdigest() != MAIN_SHA256 or
                vm.cells is not self.cells or self.frame != (vm.cells.address, vm.arena_address, vm.arena_size, vm.image_base) or
                any(not any(current is original for current in vm.memory._regions) for original in self.regions) or
                runtime.memory is not self.memory or runtime.image_base != vm.image_base or
                runtime._active_main is not self.owner or type(self.owner) is not dict or
                self.owner.get('vm') is not vm or self.owner.get('thread') != self.thread or
                self.owner.get('generation') != self.generation or runtime._main_generation != self.generation or
                get_ident() != self.thread or runtime._execute_thread != self.thread or runtime._active_failed or
                getattr(runtime, '_consumed_mgf', None) is not None or len(runtime._program_calls) != 1 or
                runtime._program_calls[0] is not self.root or self.root['name'] != 'main' or
                self.root['arguments'] != self.root_arguments or self.root['hosts'] is not None or
                vm.primary_main_tail_state is not self.state or self.state.get('_m16_pending') is not self or
                self.state['completed'] or self.site != (vm.pc, vm.block, vm.predecessor, vm.initial_block, vm.auxiliary) or
                self.site[:2] != (65839, 1645) or vm.halted or vm.abort_reason is not None or
                self.running or self.terminal or len(vm.host_calls) != self.call_index + 1 or
                vm.host_calls[self.call_index] != (65833, self.address, self.arguments, self.signature) or
                self.address != vm.image_base + 0x359253D or self.arguments != (84,) or self.signature != 205 or
                self.retry != tuple(getattr(runtime, name, False) for name in
                                    ('host2252_stage1_retry', 'host2252_stage2_g_retry',
                                     'host2252_final_f_retry', 'host2252_control_m')) or
                any(getattr(vm, name) is not None for name in
                    ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'private_iv_native_pending')) or
                (vm.pending_native is not None if returned else vm.pending_native is not self)):
            raise PrimarySemanticUnavailable('direct Main M16 continuation owner or source site changed')
        if returned:
            if not self.completed or not self.paused or runtime._host2252_pending is not None:
                raise PrimarySemanticUnavailable('direct Main M16 continuation has not returned')
        elif self.started:
            pending = runtime._host2252_pending
            if (not self.paused or pending is not self.pending or type(pending) is not dict or
                    pending.get('stage1') is not self.stage or pending.get('vm') is not vm or
                    pending.get('cells') != (84,) or pending.get('pointer') != self.pointer):
                raise PrimarySemanticUnavailable('direct Main M16 exclusive retry state changed')
        elif runtime._host2252_pending is not None:
            raise PrimarySemanticUnavailable('direct Main M16 cannot replace an existing retry')

    def resume(self, vm):
        self.validate(vm)
        self.running = True
        self.started = True
        from .primary_sign import _invoke_host
        from .primary_vm import PrimaryExecutionPaused
        try:
            _invoke_host(vm, self.address, self.arguments, self.signature, argument_types=self.argument_types)
        except PrimaryExecutionPaused:
            pending = self.runtime._host2252_pending
            if type(pending) is dict and pending.get('vm') is vm and pending.get('cells') == (84,):
                if self.pending is None:
                    self.pending, self.stage, self.pointer = pending, pending['stage1'], pending['pointer']
                self.paused = True
                self.state['m16PauseCount'] = self.state.get('m16PauseCount', 0) + 1
            else:
                self.terminal = True
            raise
        except BaseException:
            self.terminal = True
            raise
        else:
            if vm.pending_native is not self or self.runtime._host2252_pending is not None:
                self.terminal = True
                raise PrimarySemanticUnavailable('direct Main M16 completed without its exclusive pending owner')
            self.completed = True
            vm.pending_native = None
        finally:
            self.running = False

    def release(self):
        if self.state is not None and self.state.get('_m16_pending') is self:
            self.state.pop('_m16_pending')
        self.vm = self.runtime = self.memory = self.owner = self.root = None
        self.program = self.cells = self.state = self.pending = self.stage = None
        self.regions = ()
        self.terminal = True


def resume_primary_main_tail(vm, *, charge=None):
    state = getattr(vm, 'primary_main_tail_state', None)
    token = state.get('_m16_pending') if type(state) is dict else None
    if type(token) is not _DirectM16Pending or not token.paused:
        raise PrimarySemanticUnavailable('direct Main tail requires its original live M16 continuation')
    if token.completed:
        token.validate(vm, returned=True)
    else:
        token.resume(vm)
        token.validate(vm, returned=True)
    token.release()
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if charge is not None:
            charge()
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    _main_tail(vm, tick)
    state['completed'] = True
    return vm.result


def _tail_host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    expected = {62638: 0x2DE577E, 64770: 0x2DE8580, 64779: 0x2DE4C36,
                64832: 0x3592430, 65472: 0x3592430, 65833: 0x359253D, 66402: 0x2DE57A6}[word]
    if address != vm.image_base + expected:
        raise PrimarySemanticUnavailable('independent Main literal tail requires its fixed host binding')
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    if word == 65833 and any(getattr(vm.runtime, name, False) for name in
                            ('host2252_stage1_retry', 'host2252_stage2_g_retry',
                             'host2252_final_f_retry', 'host2252_control_m')):
        token = _DirectM16Pending(vm, address, arguments, signature,
                                  vm.program.type(signature).parameters[3:])
        vm.primary_main_tail_state['_m16_pending'] = token
        vm.pending_native = token
        token.resume(vm)
        token.release()
        return
    result = _invoke_host(vm, address, arguments, signature,
                          argument_types=vm.program.type(signature).parameters[3:])
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')
    if (word, callee, arguments, signature, destination) == (62638, 454, (), 129, 8355):
        from .primary_main_stage_observation import observe_main_stage
        observe_main_stage(vm, word)



def _main_tail(vm, tick):
    cells, memory = vm.cells, vm.memory
    while not vm.halted:
        if vm.block == 1529:
            tick(62638)
            vm.pc = 62644
            _tail_host(vm, 62638, 454, (), 129, 8355)
            tick(62644)
            vm.pc = 62649
            _convert(vm, 8, 8355, 8356)
            tick(62649)
            _pointer(vm, 62649, 96, 141, 8357, (145, 145))
            tick(62657)
            vm.pc = 62658
            tick(62658)
            vm.pc = 62661
            vm.auxiliary = (0, 1722188292)
            tick(62661)
            vm.pc = 62666
            vm._write(8359, memory.load(cells.pointer(8356), 8, signed=True) * memory.load(cells.pointer(8358), 8, signed=True), 8, 'once0.integer')
            tick(62666)
            vm.pc = 62669
            vm.auxiliary = (0, 417660930)
            tick(62669)
            vm.pc = 62674
            vm._write(8361, memory.load(cells.pointer(8359), 8, signed=True) + memory.load(cells.pointer(8360), 8, signed=True), 8, 'once1.integer')
            tick(62674)
            vm.pc = 62679
            vm._write(8362, cells.value(8361) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(62679)
            vm.pc = 62684
            vm._write(8364, memory.load(cells.pointer(8362), 4, signed=True) & memory.load(cells.pointer(8363), 4, signed=True), 8, 'L13.binary_q')
            tick(62684)
            vm.pc = 62688
            pointer = cells.value(8357)
            value = memory.load(cells.pointer(8364), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(62688)
            vm.pc = 62693
            vm._write(8365, cells.value(8361) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(62693)
            vm.pc = 62698
            vm._write(8367, memory.load(cells.pointer(8365), 4, signed=True) & memory.load(cells.pointer(8366), 4, signed=True), 8, 'L13.binary_q')
            tick(62698)
            vm.pc = 62701
            vm.auxiliary = (0, 1224143364)
            tick(62701)
            vm.pc = 62706
            vm._write(8369, memory.load(cells.pointer(8367), 4, signed=True) * memory.load(cells.pointer(8368), 4, signed=True), 8, 'once0.integer')
            tick(62706)
            vm.pc = 62709
            vm.auxiliary = (0, 807809025)
            tick(62709)
            vm.pc = 62714
            vm._write(8371, memory.load(cells.pointer(8369), 4, signed=True) + memory.load(cells.pointer(8370), 4, signed=True), 8, 'once1.integer')
            tick(62714)
            vm.pc = 62717
            vm.auxiliary = (0, 4668)
            tick(62717)
            vm.pc = 62722
            vm._write(8372, memory.load(cells.pointer(8371), 4, signed=True) & memory.load(cells.pointer(8363), 4, signed=True), 8, 'typed.selector1.q')
            tick(62722)
            _pointer(vm, 62722, 3, 8357, 8373, (163,))
            tick(62729)
            vm.pc = 62733
            pointer = cells.value(8373)
            value = memory.load(cells.pointer(8372), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(62733)
            vm.pc = 62738
            cells.copy_q_clear_owned(141, 8374)
            tick(62738)
            _pointer(vm, 62738, 94, 140, 8375, (145, 145))
            tick(62746)
            vm.pc = 62748
            vm._jump(1530)
            continue
        if vm.block == 1530:
            tick(62748)
            _phi(vm, 62748, (8376, 2, 145, 1529, 8377, 1531))
            tick(62755)
            vm.pc = 62760
            vm._write(8378, int(cells.value(8376) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(62760)
            vm.pc = 62764
            vm._jump(1531 if cells.value(8378) != 0 else 1532)
            continue
        if vm.block == 1531:
            tick(62764)
            _pointer(vm, 62764, 1, 8374, 8379, (8376,))
            tick(62771)
            vm.pc = 62776
            cells.copy_q_clear_owned(8379, 8380)
            tick(62776)
            vm.pc = 62780
            value = memory.load(cells.value(8380), 4)
            vm._write(8381, value, 4, 'high.load')
            tick(62780)
            _pointer(vm, 62780, 1, 8375, 8382, (8376,))
            tick(62787)
            vm.pc = 62792
            cells.copy_q_clear_owned(8382, 8383)
            tick(62792)
            vm.pc = 62796
            pointer = cells.value(8383)
            value = memory.load(cells.pointer(8381), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(62796)
            vm.pc = 62797
            tick(62797)
            vm.pc = 62800
            vm.auxiliary = (0, 1467203585)
            tick(62800)
            vm.pc = 62805
            vm._write(8377, memory.load(cells.pointer(8376), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(62805)
            vm.pc = 62807
            vm._jump(1530)
            continue
        if vm.block == 1532:
            tick(62807)
            _phi(vm, 62807, (8384, 2, 8385, 1533, 184, 1530))
            tick(62814)
            vm.pc = 62819
            vm._write(8386, int(cells.value(8384) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(62819)
            vm.pc = 62823
            vm._jump(1533 if cells.value(8386) != 0 else 1534)
            continue
        if vm.block == 1533:
            tick(62823)
            _pointer(vm, 62823, 1, 8374, 8387, (8384,))
            tick(62830)
            vm.pc = 62834
            value = memory.load(cells.value(8387), 1)
            vm._write(8388, value, 4, 'high.load')
            tick(62834)
            _pointer(vm, 62834, 1, 8375, 8389, (8384,))
            tick(62841)
            vm.pc = 62845
            pointer = cells.value(8389)
            value = memory.load(cells.pointer(8388), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(62845)
            vm.pc = 62846
            tick(62846)
            vm.pc = 62849
            vm.auxiliary = (0, 1165856770)
            tick(62849)
            vm.pc = 62854
            vm._write(8385, memory.load(cells.pointer(8384), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(62854)
            vm.pc = 62856
            vm._jump(1532)
            continue
        if vm.block == 1534:
            tick(62856)
            _pointer(vm, 62856, 94, 140, 8390, (145, 184))
            tick(62864)
            _pointer(vm, 62864, 43, 72, 8391, (145, 145))
            tick(62872)
            _pointer(vm, 62872, 43, 72, 8392, (145, 145))
            tick(62880)
            vm.pc = 62884
            pointer = cells.value(8392)
            value = memory.load(cells.pointer(4560), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(62884)
            _pointer(vm, 62884, 43, 72, 8393, (145, 163))
            tick(62892)
            vm.pc = 62894
            vm._jump(1535)
            continue
        if vm.block == 1535:
            tick(62894)
            _phi(vm, 62894, (8394, 2, 145, 1534, 8395, 1536))
            tick(62901)
            vm.pc = 62906
            vm._write(8396, int(cells.value(8394) < cells.value(172)), 4, 'once18.unsigned_q')
            tick(62906)
            vm.pc = 62910
            vm._jump(1536 if cells.value(8396) != 0 else 1537)
            continue
        if vm.block == 1536:
            tick(62910)
            _pointer(vm, 62910, 1, 8374, 8397, (8394,))
            tick(62917)
            vm.pc = 62922
            cells.copy_q_clear_owned(8397, 8398)
            tick(62922)
            vm.pc = 62926
            value = memory.load(cells.value(8398), 4)
            vm._write(8399, value, 4, 'high.load')
            tick(62926)
            _pointer(vm, 62926, 1, 8393, 8400, (8394,))
            tick(62933)
            vm.pc = 62938
            cells.copy_q_clear_owned(8400, 8401)
            tick(62938)
            vm.pc = 62942
            pointer = cells.value(8401)
            value = memory.load(cells.pointer(8399), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(62942)
            vm.pc = 62943
            tick(62943)
            vm.pc = 62946
            vm.auxiliary = (0, 916975618)
            tick(62946)
            vm.pc = 62951
            vm._write(8395, memory.load(cells.pointer(8394), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(62951)
            vm.pc = 62953
            vm._jump(1535)
            continue
        if vm.block == 1537:
            tick(62953)
            _phi(vm, 62953, (8402, 2, 8403, 1538, 172, 1535))
            tick(62960)
            vm.pc = 62965
            vm._write(8404, int(cells.value(8402) < cells.value(172)), 4, 'once18.unsigned_q')
            tick(62965)
            vm.pc = 62969
            vm._jump(1538 if cells.value(8404) != 0 else 1539)
            continue
        if vm.block == 1538:
            tick(62969)
            _pointer(vm, 62969, 1, 8374, 8405, (8402,))
            tick(62976)
            vm.pc = 62980
            value = memory.load(cells.value(8405), 1)
            vm._write(8406, value, 4, 'high.load')
            tick(62980)
            _pointer(vm, 62980, 1, 8393, 8407, (8402,))
            tick(62987)
            vm.pc = 62991
            pointer = cells.value(8407)
            value = memory.load(cells.pointer(8406), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(62991)
            vm.pc = 62992
            tick(62992)
            vm.pc = 62995
            vm.auxiliary = (0, 1619091457)
            tick(62995)
            vm.pc = 63000
            vm._write(8403, memory.load(cells.pointer(8402), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(63000)
            vm.pc = 63002
            vm._jump(1537)
            continue
        if vm.block == 1539:
            tick(63002)
            vm.pc = 63004
            vm._jump(1540)
            continue
        if vm.block == 1540:
            tick(63004)
            _phi(vm, 63004, (8408, 2, 158, 1539, 8409, 1541))
            tick(63011)
            _phi(vm, 63011, (8410, 2, 271, 1539, 8411, 1541))
            tick(63018)
            vm.pc = 63023
            vm._write(8412, int(cells.value(8408) < cells.value(391)), 4, 'once18.unsigned_q')
            tick(63023)
            vm.pc = 63027
            vm._jump(1542 if cells.value(8412) != 0 else 1543)
            continue
        if vm.block == 1543:
            tick(63027)
            vm.pc = 63032
            value = memory.load(cells.pointer(8410), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(8413, value >> (count & 31), 4, 'once8.logical_shift')
            tick(63032)
            vm.pc = 63037
            vm._write(8414, cells.value(8413) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(63037)
            _pointer(vm, 63037, 43, 72, 8415, (145, 175))
            tick(63045)
            vm.pc = 63049
            pointer = cells.value(8415)
            value = memory.load(cells.pointer(8414), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63049)
            vm.pc = 63054
            vm._write(8416, cells.value(8410) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(63054)
            _pointer(vm, 63054, 43, 72, 8417, (145, 178))
            tick(63062)
            vm.pc = 63066
            pointer = cells.value(8417)
            value = memory.load(cells.pointer(8416), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63066)
            vm.pc = 63068
            vm._jump(1544)
            continue
        if vm.block == 1542:
            tick(63068)
            vm.pc = 63073
            _convert(vm, 8, 8408, 8418)
            tick(63073)
            _pointer(vm, 63073, 43, 72, 8419, (145, 8418))
            tick(63081)
            vm.pc = 63085
            value = memory.load(cells.value(8419), 1)
            vm._write(8420, value, 4, 'high.load')
            tick(63085)
            vm.pc = 63090
            _convert(vm, 2, 8420, 8421)
            tick(63090)
            vm.pc = 63091
            tick(63091)
            vm.pc = 63094
            vm.auxiliary = (0, 51151)
            tick(63094)
            _single_control(vm)
            vm.pc = 63099
            count = memory.load(cells.pointer(280), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8421), 2, signed=True) & 0xFFFFFFFF) << count
            vm._write(8422, value, 4, 'typed.selector3.d')
            tick(63099)
            vm.pc = 63102
            vm.auxiliary = (0, 16134)
            tick(63102)
            vm.pc = 63108
            vm._write(8423, memory.load(cells.pointer(8422), 2, signed=True) ^ memory.load(cells.pointer(8410), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(63108)
            vm.pc = 63110
            vm._jump(1545)
            continue
        if vm.block == 1545:
            tick(63110)
            _phi(vm, 63110, (8424, 2, 158, 1542, 8425, 1546))
            tick(63117)
            _phi(vm, 63117, (8411, 2, 8423, 1542, 8426, 1546))
            tick(63124)
            vm.pc = 63129
            vm._write(8427, int(cells.value(8424) < cells.value(502)), 4, 'once18.unsigned_q')
            tick(63129)
            vm.pc = 63133
            vm._jump(1546 if cells.value(8427) != 0 else 1541)
            continue
        if vm.block == 1541:
            tick(63133)
            vm.pc = 63134
            tick(63134)
            vm.pc = 63137
            vm.auxiliary = (0, 813899777)
            tick(63137)
            vm.pc = 63142
            vm._write(8409, memory.load(cells.pointer(8408), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(63142)
            vm.pc = 63144
            vm._jump(1540)
            continue
        if vm.block == 1546:
            tick(63144)
            vm.pc = 63145
            tick(63145)
            vm.pc = 63148
            vm.auxiliary = (0, 435323606)
            tick(63148)
            vm.pc = 63153
            vm._write(8428, int(memory.load(cells.pointer(8411), 2, signed=True) > memory.load(cells.pointer(271), 2, signed=True)), 4, 'L25.comparison')
            tick(63153)
            vm.pc = 63156
            vm.auxiliary = (0, 17326)
            tick(63156)
            _single_control(vm)
            vm.pc = 63161
            count = memory.load(cells.pointer(274), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8411), 2, signed=True) & 0xFFFFFFFF) << count
            vm._write(8429, value, 4, 'typed.selector3.d')
            tick(63161)
            vm.pc = 63164
            vm.auxiliary = (0, 56909)
            tick(63164)
            vm.pc = 63170
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8431, memory.load(cells.pointer(8429), 2, signed=True) ^ memory.load(cells.pointer(8430), 2, signed=True), 8, 'typed.selector5.q')
            tick(63170)
            vm.pc = 63173
            vm.auxiliary = (0, 17351)
            tick(63173)
            _single_control(vm)
            vm.pc = 63178
            count = memory.load(cells.pointer(274), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8411), 2, signed=True) & 0xFFFFFFFF) << count
            vm._write(8432, value, 4, 'typed.selector3.d')
            tick(63178)
            vm.pc = 63185
            selected = 8432 if cells.value(8428) != 0 else 8431
            vm._write(8426, memory.load(cells.pointer(selected), 2, signed=True), 8, 'L7.selected_q')
            tick(63185)
            vm.pc = 63188
            vm.auxiliary = (0, 910303234)
            tick(63188)
            vm.pc = 63193
            vm._write(8425, memory.load(cells.pointer(8424), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(63193)
            vm.pc = 63195
            vm._jump(1545)
            continue
        if vm.block == 1544:
            tick(63195)
            _phi(vm, 63195, (8433, 2, 145, 1543, 8434, 1547))
            tick(63202)
            _phi(vm, 63202, (8435, 2, 158, 1543, 8436, 1547))
            tick(63209)
            vm.pc = 63214
            vm._write(8437, int(cells.value(8435) < cells.value(476)), 4, 'once18.unsigned_q')
            tick(63214)
            vm.pc = 63218
            vm._jump(1547 if cells.value(8437) != 0 else 1548)
            continue
        if vm.block == 1548:
            tick(63218)
            vm.pc = 63220
            vm._jump(1549)
            continue
        if vm.block == 1547:
            tick(63220)
            vm.pc = 63221
            tick(63221)
            vm.pc = 63224
            vm.auxiliary = (0, 24748)
            tick(63224)
            _single_control(vm)
            vm.pc = 63229
            count = memory.load(cells.pointer(184), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(8433) << count
            vm._write(8438, value, 8, "typed.selector3.q")
            tick(63229)
            vm.pc = 63234
            _convert(vm, 8, 8435, 8439)
            tick(63234)
            _pointer(vm, 63234, 43, 72, 8440, (145, 8439))
            tick(63242)
            vm.pc = 63246
            value = memory.load(cells.value(8440), 1)
            vm._write(8441, value, 4, 'high.load')
            tick(63246)
            vm.pc = 63251
            _convert(vm, 8, 8441, 8442)
            tick(63251)
            vm.pc = 63256
            vm._write(8434, memory.load(cells.pointer(8438), 8, signed=True) | memory.load(cells.pointer(8442), 8, signed=True), 8, 'L15.binary_q')
            tick(63256)
            vm.pc = 63259
            vm.auxiliary = (0, 1274765313)
            tick(63259)
            vm.pc = 63264
            vm._write(8436, memory.load(cells.pointer(8435), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(63264)
            vm.pc = 63266
            vm._jump(1544)
            continue
        if vm.block == 1549:
            tick(63266)
            _phi(vm, 63266, (8443, 2, 8433, 1548, 8444, 1550))
            tick(63273)
            _phi(vm, 63273, (8445, 2, 8433, 1548, 8446, 1550))
            tick(63280)
            _phi(vm, 63280, (8447, 2, 145, 1548, 8448, 1550))
            tick(63287)
            vm.pc = 63292
            a, b = cells.value(8443), cells.value(8449)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(8450, a % b, 8, 'L17.unsigned_q_division')
            tick(63292)
            vm.pc = 63293
            tick(63293)
            vm.pc = 63296
            vm.auxiliary = (0, 1886525907)
            tick(63296)
            vm.pc = 63301
            vm._write(8451, int(memory.load(cells.pointer(8445), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(63301)
            vm.pc = 63305
            vm._jump(1551 if cells.value(8451) != 0 else 1552)
            continue
        if vm.block == 1552:
            tick(63305)
            vm.pc = 63306
            tick(63306)
            vm.pc = 63309
            vm.auxiliary = (0, 29487)
            tick(63309)
            vm.pc = 63314
            vm._write(8452, memory.load(cells.pointer(8445), 8, signed=True) & memory.load(cells.pointer(163), 8, signed=True), 8, 'typed.selector1.q')
            tick(63314)
            vm.pc = 63317
            vm.auxiliary = (0, 1631747315)
            tick(63317)
            _equal(vm, 63322, 8, 8452, 145, 8453)
            tick(63322)
            vm.pc = 63326
            vm._jump(1550 if cells.value(8453) != 0 else 1553)
            continue
        if vm.block == 1553:
            tick(63326)
            vm.pc = 63327
            tick(63327)
            vm.pc = 63330
            vm.auxiliary = (0, 358367233)
            tick(63330)
            vm.pc = 63335
            vm._write(8454, memory.load(cells.pointer(8447), 8, signed=True) + memory.load(cells.pointer(8450), 8, signed=True), 8, 'once1.integer')
            tick(63335)
            vm.pc = 63340
            a, b = cells.value(8454), cells.value(8449)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(8455, a % b, 8, 'L17.unsigned_q_division')
            tick(63340)
            vm.pc = 63342
            vm._jump(1550)
            continue
        if vm.block == 1550:
            tick(63342)
            _phi(vm, 63342, (8448, 2, 8455, 1553, 8447, 1552))
            tick(63349)
            vm.pc = 63350
            tick(63350)
            vm.pc = 63353
            vm.auxiliary = (0, 22511)
            tick(63353)
            _single_control(vm)
            vm.pc = 63358
            count = memory.load(cells.pointer(163), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(8450) << count
            vm._write(8444, value, 8, "typed.selector3.q")
            tick(63358)
            vm.pc = 63363
            value = memory.load(cells.pointer(8445), 8)
            count = memory.load(cells.pointer(163), 1)
            vm._write(8446, value >> (count & 63), 8, 'once8.logical_shift')
            tick(63363)
            vm.pc = 63365
            vm._jump(1549)
            continue
        if vm.block == 1551:
            tick(63365)
            _phi(vm, 63365, (8456, 2, 8457, 1554, 8447, 1549))
            tick(63372)
            _phi(vm, 63372, (8458, 2, 8459, 1554, 476, 1549))
            tick(63379)
            vm.pc = 63380
            tick(63380)
            vm.pc = 63383
            vm.auxiliary = (0, 488789542)
            tick(63383)
            vm.pc = 63388
            vm._write(8460, int(memory.load(cells.pointer(8458), 4, signed=True) > memory.load(cells.pointer(396), 4, signed=True)), 4, 'L25.comparison')
            tick(63388)
            vm.pc = 63392
            vm._jump(1554 if cells.value(8460) != 0 else 1555)
            continue
        if vm.block == 1554:
            tick(63392)
            vm.pc = 63397
            vm._write(8461, cells.value(8456) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(63397)
            vm.pc = 63402
            cells.copy_q_clear_owned(8458, 8462)
            tick(63402)
            _pointer(vm, 63402, 1, 8390, 8463, (8462,))
            tick(63409)
            vm.pc = 63413
            pointer = cells.value(8463)
            value = memory.load(cells.pointer(8461), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63413)
            vm.pc = 63418
            value = memory.load(cells.pointer(8456), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(8457, value >> (count & 63), 8, 'once8.logical_shift')
            tick(63418)
            vm.pc = 63419
            tick(63419)
            vm.pc = 63422
            vm.auxiliary = (0, 1214251009)
            tick(63422)
            vm.pc = 63427
            vm._write(8459, memory.load(cells.pointer(8458), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(63427)
            vm.pc = 63429
            vm._jump(1551)
            continue
        if vm.block == 1555:
            tick(63429)
            _pointer(vm, 63429, 94, 140, 8464, (145, 205))
            tick(63437)
            _pointer(vm, 63437, 96, 141, 8465, (145, 163))
            tick(63445)
            vm.pc = 63450
            cells.copy_q_clear_owned(8465, 8466)
            tick(63450)
            _pointer(vm, 63450, 43, 72, 8467, (145, 145))
            tick(63458)
            _pointer(vm, 63458, 43, 72, 8468, (145, 145))
            tick(63466)
            vm.pc = 63470
            pointer = cells.value(8468)
            value = memory.load(cells.pointer(4560), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63470)
            _pointer(vm, 63470, 43, 72, 8469, (145, 163))
            tick(63478)
            vm.pc = 63480
            vm._jump(1556)
            continue
        if vm.block == 1556:
            tick(63480)
            _phi(vm, 63480, (8470, 2, 145, 1555, 8471, 1557))
            tick(63487)
            vm.pc = 63492
            vm._write(8472, int(cells.value(8470) < cells.value(172)), 4, 'once18.unsigned_q')
            tick(63492)
            vm.pc = 63496
            vm._jump(1557 if cells.value(8472) != 0 else 1558)
            continue
        if vm.block == 1557:
            tick(63496)
            _pointer(vm, 63496, 1, 8466, 8473, (8470,))
            tick(63503)
            vm.pc = 63508
            cells.copy_q_clear_owned(8473, 8474)
            tick(63508)
            vm.pc = 63512
            value = memory.load(cells.value(8474), 4)
            vm._write(8475, value, 4, 'high.load')
            tick(63512)
            _pointer(vm, 63512, 1, 8469, 8476, (8470,))
            tick(63519)
            vm.pc = 63524
            cells.copy_q_clear_owned(8476, 8477)
            tick(63524)
            vm.pc = 63528
            pointer = cells.value(8477)
            value = memory.load(cells.pointer(8475), 4)
            memory.store(pointer, value, 4, source='L6.store_integer')
            tick(63528)
            vm.pc = 63529
            tick(63529)
            vm.pc = 63532
            vm.auxiliary = (0, 1863897089)
            tick(63532)
            vm.pc = 63537
            vm._write(8471, memory.load(cells.pointer(8470), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(63537)
            vm.pc = 63539
            vm._jump(1556)
            continue
        if vm.block == 1558:
            tick(63539)
            _phi(vm, 63539, (8478, 2, 8479, 1559, 172, 1556))
            tick(63546)
            vm.pc = 63551
            vm._write(8480, int(cells.value(8478) < cells.value(172)), 4, 'once18.unsigned_q')
            tick(63551)
            vm.pc = 63555
            vm._jump(1559 if cells.value(8480) != 0 else 1560)
            continue
        if vm.block == 1559:
            tick(63555)
            _pointer(vm, 63555, 1, 8466, 8481, (8478,))
            tick(63562)
            vm.pc = 63566
            value = memory.load(cells.value(8481), 1)
            vm._write(8482, value, 4, 'high.load')
            tick(63566)
            _pointer(vm, 63566, 1, 8469, 8483, (8478,))
            tick(63573)
            vm.pc = 63577
            pointer = cells.value(8483)
            value = memory.load(cells.pointer(8482), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63577)
            vm.pc = 63578
            tick(63578)
            vm.pc = 63581
            vm.auxiliary = (0, 259362818)
            tick(63581)
            vm.pc = 63586
            vm._write(8479, memory.load(cells.pointer(8478), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(63586)
            vm.pc = 63588
            vm._jump(1558)
            continue
        if vm.block == 1560:
            tick(63588)
            vm.pc = 63590
            vm._jump(1561)
            continue
        if vm.block == 1561:
            tick(63590)
            _phi(vm, 63590, (8484, 2, 158, 1560, 8485, 1562))
            tick(63597)
            _phi(vm, 63597, (8486, 2, 271, 1560, 8487, 1562))
            tick(63604)
            vm.pc = 63609
            vm._write(8488, int(cells.value(8484) < cells.value(391)), 4, 'once18.unsigned_q')
            tick(63609)
            vm.pc = 63613
            vm._jump(1563 if cells.value(8488) != 0 else 1564)
            continue
        if vm.block == 1564:
            tick(63613)
            vm.pc = 63618
            value = memory.load(cells.pointer(8486), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(8489, value >> (count & 31), 4, 'once8.logical_shift')
            tick(63618)
            vm.pc = 63623
            vm._write(8490, cells.value(8489) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(63623)
            _pointer(vm, 63623, 43, 72, 8491, (145, 175))
            tick(63631)
            vm.pc = 63635
            pointer = cells.value(8491)
            value = memory.load(cells.pointer(8490), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63635)
            vm.pc = 63640
            vm._write(8492, cells.value(8486) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(63640)
            _pointer(vm, 63640, 43, 72, 8493, (145, 178))
            tick(63648)
            vm.pc = 63652
            pointer = cells.value(8493)
            value = memory.load(cells.pointer(8492), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63652)
            vm.pc = 63654
            vm._jump(1565)
            continue
        if vm.block == 1563:
            tick(63654)
            vm.pc = 63659
            _convert(vm, 8, 8484, 8494)
            tick(63659)
            _pointer(vm, 63659, 43, 72, 8495, (145, 8494))
            tick(63667)
            vm.pc = 63671
            value = memory.load(cells.value(8495), 1)
            vm._write(8496, value, 4, 'high.load')
            tick(63671)
            vm.pc = 63676
            _convert(vm, 2, 8496, 8497)
            tick(63676)
            vm.pc = 63677
            tick(63677)
            vm.pc = 63680
            vm.auxiliary = (0, 62405)
            tick(63680)
            _single_control(vm)
            vm.pc = 63685
            count = memory.load(cells.pointer(280), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8497), 2, signed=True) & 0xFFFFFFFF) << count
            vm._write(8498, value, 4, 'typed.selector3.d')
            tick(63685)
            vm.pc = 63688
            vm.auxiliary = (0, 65340)
            tick(63688)
            vm.pc = 63694
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8499, memory.load(cells.pointer(8498), 2, signed=True) ^ memory.load(cells.pointer(8486), 2, signed=True), 8, 'typed.selector5.q')
            tick(63694)
            vm.pc = 63696
            vm._jump(1566)
            continue
        if vm.block == 1566:
            tick(63696)
            _phi(vm, 63696, (8500, 2, 158, 1563, 8501, 1567))
            tick(63703)
            _phi(vm, 63703, (8487, 2, 8499, 1563, 8502, 1567))
            tick(63710)
            vm.pc = 63715
            vm._write(8503, int(cells.value(8500) < cells.value(502)), 4, 'once18.unsigned_q')
            tick(63715)
            vm.pc = 63719
            vm._jump(1567 if cells.value(8503) != 0 else 1562)
            continue
        if vm.block == 1562:
            tick(63719)
            vm.pc = 63720
            tick(63720)
            vm.pc = 63723
            vm.auxiliary = (0, 867803137)
            tick(63723)
            vm.pc = 63728
            vm._write(8485, memory.load(cells.pointer(8484), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(63728)
            vm.pc = 63730
            vm._jump(1561)
            continue
        if vm.block == 1567:
            tick(63730)
            vm.pc = 63731
            tick(63731)
            vm.pc = 63734
            vm.auxiliary = (0, 1257400614)
            tick(63734)
            vm.pc = 63739
            vm._write(8504, int(memory.load(cells.pointer(8487), 2, signed=True) > memory.load(cells.pointer(271), 2, signed=True)), 4, 'L25.comparison')
            tick(63739)
            vm.pc = 63742
            vm.auxiliary = (0, 16524)
            tick(63742)
            _single_control(vm)
            vm.pc = 63747
            count = memory.load(cells.pointer(274), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8487), 2, signed=True) & 0xFFFFFFFF) << count
            vm._write(8505, value, 4, 'typed.selector3.d')
            tick(63747)
            vm.pc = 63750
            vm.auxiliary = (0, 56157)
            tick(63750)
            vm.pc = 63756
            vm._write(8506, memory.load(cells.pointer(8505), 2, signed=True) ^ memory.load(cells.pointer(8430), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(63756)
            vm.pc = 63759
            vm.auxiliary = (0, 41415)
            tick(63759)
            _single_control(vm)
            vm.pc = 63764
            count = memory.load(cells.pointer(274), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8487), 2, signed=True) & 0xFFFFFFFF) << count
            vm._write(8507, value, 4, 'typed.selector3.d')
            tick(63764)
            vm.pc = 63771
            selected = 8507 if cells.value(8504) != 0 else 8506
            vm._write(8502, memory.load(cells.pointer(selected), 2, signed=True), 8, 'L7.selected_q')
            tick(63771)
            vm.pc = 63774
            vm.auxiliary = (0, 1524424706)
            tick(63774)
            vm.pc = 63779
            vm._write(8501, memory.load(cells.pointer(8500), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(63779)
            vm.pc = 63781
            vm._jump(1566)
            continue
        if vm.block == 1565:
            tick(63781)
            _phi(vm, 63781, (8508, 2, 145, 1564, 8509, 1568))
            tick(63788)
            _phi(vm, 63788, (8510, 2, 158, 1564, 8511, 1568))
            tick(63795)
            vm.pc = 63800
            vm._write(8512, int(cells.value(8510) < cells.value(476)), 4, 'once18.unsigned_q')
            tick(63800)
            vm.pc = 63804
            vm._jump(1568 if cells.value(8512) != 0 else 1569)
            continue
        if vm.block == 1569:
            tick(63804)
            vm.pc = 63806
            vm._jump(1570)
            continue
        if vm.block == 1568:
            tick(63806)
            vm.pc = 63807
            tick(63807)
            vm.pc = 63810
            vm.auxiliary = (0, 58838)
            tick(63810)
            _single_control(vm)
            vm.pc = 63815
            count = memory.load(cells.pointer(184), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(8508) << count
            vm._write(8513, value, 8, "typed.selector3.q")
            tick(63815)
            vm.pc = 63820
            _convert(vm, 8, 8510, 8514)
            tick(63820)
            _pointer(vm, 63820, 43, 72, 8515, (145, 8514))
            tick(63828)
            vm.pc = 63832
            value = memory.load(cells.value(8515), 1)
            vm._write(8516, value, 4, 'L5.unsigned_load')
            tick(63832)
            vm.pc = 63837
            _convert(vm, 8, 8516, 8517)
            tick(63837)
            vm.pc = 63842
            vm._write(8509, memory.load(cells.pointer(8513), 8, signed=True) | memory.load(cells.pointer(8517), 8, signed=True), 8, 'L15.binary_q')
            tick(63842)
            vm.pc = 63845
            vm.auxiliary = (0, 1878536193)
            tick(63845)
            vm.pc = 63850
            vm._write(8511, memory.load(cells.pointer(8510), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(63850)
            vm.pc = 63852
            vm._jump(1565)
            continue
        if vm.block == 1570:
            tick(63852)
            _phi(vm, 63852, (8518, 2, 8508, 1569, 8519, 1571))
            tick(63859)
            _phi(vm, 63859, (8520, 2, 8508, 1569, 8521, 1571))
            tick(63866)
            _phi(vm, 63866, (8522, 2, 145, 1569, 8523, 1571))
            tick(63873)
            vm.pc = 63878
            a, b = cells.value(8518), cells.value(8524)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(8525, a % b, 8, 'L17.unsigned_q_division')
            tick(63878)
            vm.pc = 63879
            tick(63879)
            vm.pc = 63882
            vm.auxiliary = (0, 1544737283)
            tick(63882)
            _equal(vm, 63887, 8, 8520, 145, 8526)
            tick(63887)
            vm.pc = 63891
            vm._jump(1572 if cells.value(8526) != 0 else 1573)
            continue
        if vm.block == 1573:
            tick(63891)
            vm.pc = 63892
            tick(63892)
            vm.pc = 63895
            vm.auxiliary = (0, 57966)
            tick(63895)
            vm.pc = 63900
            vm._write(8527, memory.load(cells.pointer(8520), 8, signed=True) & memory.load(cells.pointer(163), 8, signed=True), 8, 'typed.selector1.q')
            tick(63900)
            vm.pc = 63903
            vm.auxiliary = (0, 1190302115)
            tick(63903)
            vm.pc = 63908
            vm._write(8528, int(memory.load(cells.pointer(8527), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(63908)
            vm.pc = 63912
            vm._jump(1571 if cells.value(8528) != 0 else 1574)
            continue
        if vm.block == 1574:
            tick(63912)
            vm.pc = 63913
            tick(63913)
            vm.pc = 63916
            vm.auxiliary = (0, 1621966850)
            tick(63916)
            vm.pc = 63921
            vm._write(8529, memory.load(cells.pointer(8522), 8, signed=True) + memory.load(cells.pointer(8525), 8, signed=True), 8, 'once1.integer')
            tick(63921)
            vm.pc = 63926
            a, b = cells.value(8529), cells.value(8524)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(8530, a % b, 8, 'L17.unsigned_q_division')
            tick(63926)
            vm.pc = 63928
            vm._jump(1571)
            continue
        if vm.block == 1571:
            tick(63928)
            _phi(vm, 63928, (8523, 2, 8530, 1574, 8522, 1573))
            tick(63935)
            vm.pc = 63936
            tick(63936)
            vm.pc = 63939
            vm.auxiliary = (0, 29181)
            tick(63939)
            _single_control(vm)
            vm.pc = 63944
            count = memory.load(cells.pointer(163), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(8525) << count
            vm._write(8519, value, 8, "typed.selector3.q")
            tick(63944)
            vm.pc = 63949
            value = memory.load(cells.pointer(8520), 8)
            count = memory.load(cells.pointer(163), 1)
            vm._write(8521, value >> (count & 63), 8, 'once8.logical_shift')
            tick(63949)
            vm.pc = 63951
            vm._jump(1570)
            continue
        if vm.block == 1572:
            tick(63951)
            _phi(vm, 63951, (8531, 2, 8532, 1575, 8522, 1570))
            tick(63958)
            _phi(vm, 63958, (8533, 2, 8534, 1575, 476, 1570))
            tick(63965)
            vm.pc = 63966
            tick(63966)
            vm.pc = 63969
            vm.auxiliary = (0, 1754449910)
            tick(63969)
            vm.pc = 63974
            vm._write(8535, int(memory.load(cells.pointer(8533), 4, signed=True) > memory.load(cells.pointer(396), 4, signed=True)), 4, 'L25.comparison')
            tick(63974)
            vm.pc = 63978
            vm._jump(1575 if cells.value(8535) != 0 else 1576)
            continue
        if vm.block == 1575:
            tick(63978)
            vm.pc = 63983
            vm._write(8536, cells.value(8531) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(63983)
            vm.pc = 63988
            cells.copy_q_clear_owned(8533, 8537)
            tick(63988)
            _pointer(vm, 63988, 1, 8464, 8538, (8537,))
            tick(63995)
            vm.pc = 63999
            pointer = cells.value(8538)
            value = memory.load(cells.pointer(8536), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(63999)
            vm.pc = 64004
            value = memory.load(cells.pointer(8531), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(8532, value >> (count & 63), 8, 'once8.logical_shift')
            tick(64004)
            vm.pc = 64005
            tick(64005)
            vm.pc = 64008
            vm.auxiliary = (0, 509247489)
            tick(64008)
            vm.pc = 64013
            vm._write(8534, memory.load(cells.pointer(8533), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(64013)
            vm.pc = 64015
            vm._jump(1572)
            continue
        if vm.block == 1576:
            tick(64015)
            vm.pc = 64020
            vm._write(8539, cells.value(7857) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(64020)
            vm.pc = 64025
            cells.copy_q_clear_owned(80, 8540)
            tick(64025)
            vm.pc = 64027
            vm._jump(1577)
            continue
        if vm.block == 1577:
            tick(64027)
            _phi(vm, 64027, (8541, 2, 1157, 1576, 8542, 1578))
            tick(64034)
            _phi(vm, 64034, (8543, 2, 145, 1576, 8544, 1578))
            tick(64041)
            vm.pc = 64046
            vm._write(8546, int(cells.value(8543) < cells.value(8545)), 4, 'once18.unsigned_q')
            tick(64046)
            vm.pc = 64050
            vm._jump(1578 if cells.value(8546) != 0 else 1579)
            continue
        if vm.block == 1578:
            tick(64050)
            _pointer(vm, 64050, 1, 290, 8547, (8543,))
            tick(64057)
            vm.pc = 64061
            value = memory.load(cells.value(8547), 1)
            vm._write(8548, value, 4, 'high.load')
            tick(64061)
            vm.pc = 64066
            _convert(vm, 4, 8548, 8549)
            tick(64066)
            vm.pc = 64071
            vm._write(8550, memory.load(cells.pointer(8541), 4, signed=True) ^ memory.load(cells.pointer(8549), 4, signed=True), 8, 'L14.binary_q')
            tick(64071)
            vm.pc = 64072
            tick(64072)
            vm.pc = 64075
            vm.auxiliary = (0, 1624818179)
            tick(64075)
            vm.pc = 64080
            vm._write(8552, memory.load(cells.pointer(8550), 4, signed=True) * memory.load(cells.pointer(8551), 4, signed=True), 8, 'once0.integer')
            tick(64080)
            vm.pc = 64083
            vm.auxiliary = (0, 611435011)
            tick(64083)
            vm.pc = 64088
            vm._write(8554, memory.load(cells.pointer(8550), 4, signed=True) * memory.load(cells.pointer(8553), 4, signed=True), 8, 'once0.integer')
            tick(64088)
            vm.pc = 64093
            value = memory.load(cells.pointer(8552), 4)
            count = memory.load(cells.pointer(592), 1)
            vm._write(8555, value >> (count & 31), 4, 'once8.logical_shift')
            tick(64093)
            vm.pc = 64096
            vm.auxiliary = (0, 21153)
            tick(64096)
            vm.pc = 64101
            vm._write(8542, memory.load(cells.pointer(8554), 4, signed=True) | memory.load(cells.pointer(8555), 4, signed=True), 8, 'typed.selector2.q')
            tick(64101)
            vm.pc = 64104
            vm.auxiliary = (0, 655912961)
            tick(64104)
            vm.pc = 64109
            vm._write(8544, memory.load(cells.pointer(8543), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(64109)
            vm.pc = 64111
            vm._jump(1577)
            continue
        if vm.block == 1579:
            tick(64111)
            vm.pc = 64116
            value = memory.load(cells.pointer(8541), 4)
            count = memory.load(cells.pointer(375), 1)
            vm._write(8556, value >> (count & 31), 4, 'once8.logical_shift')
            tick(64116)
            vm.pc = 64117
            tick(64117)
            vm.pc = 64120
            vm.auxiliary = (0, 20084)
            tick(64120)
            vm.pc = 64126
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8557, memory.load(cells.pointer(8541), 4, signed=True) ^ memory.load(cells.pointer(8556), 4, signed=True), 8, 'typed.selector5.q')
            tick(64126)
            vm.pc = 64130
            pointer = cells.value(80)
            value = memory.load(cells.pointer(8557), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(64130)
            _pointer(vm, 64130, 47, 81, 8558, (145, 145))
            tick(64138)
            _pointer(vm, 64138, 47, 81, 8559, (145, 145))
            tick(64146)
            vm.pc = 64148
            vm._jump(1580)
            continue
        if vm.block == 1580:
            tick(64148)
            _phi(vm, 64148, (8560, 2, 8561, 1579, 8562, 1581))
            tick(64155)
            _phi(vm, 64155, (8563, 2, 8559, 1579, 8564, 1581))
            tick(64162)
            vm.pc = 64163
            tick(64163)
            vm.pc = 64166
            vm.auxiliary = (0, 2049053443)
            tick(64166)
            vm.pc = 64171
            vm._write(8565, int(memory.load(cells.pointer(8560), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(64171)
            vm.pc = 64175
            vm._jump(1582 if cells.value(8565) != 0 else 1581)
            continue
        if vm.block == 1581:
            tick(64175)
            vm.pc = 64176
            tick(64176)
            vm.pc = 64179
            vm.auxiliary = (0, 860647426)
            tick(64179)
            vm.pc = 64184
            vm._write(8562, memory.load(cells.pointer(8560), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(64184)
            _pointer(vm, 64184, 1, 8563, 8564, (163,))
            tick(64191)
            vm.pc = 64195
            pointer = cells.value(8563)
            value = memory.load(cells.pointer(235), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(64195)
            vm.pc = 64197
            vm._jump(1580)
            continue
        if vm.block == 1582:
            tick(64197)
            vm.pc = 64199
            vm._jump(1583)
            continue
        if vm.block == 1583:
            tick(64199)
            _phi(vm, 64199, (8566, 2, 145, 1582, 8567, 1584))
            tick(64206)
            vm.pc = 64211
            vm._write(8569, int(cells.value(8566) < cells.value(8568)), 4, 'once18.unsigned_q')
            tick(64211)
            vm.pc = 64215
            vm._jump(1584 if cells.value(8569) != 0 else 1585)
            continue
        if vm.block == 1584:
            tick(64215)
            _pointer(vm, 64215, 1, 290, 8570, (8566,))
            tick(64222)
            vm.pc = 64227
            cells.copy_q_clear_owned(8570, 8571)
            tick(64227)
            vm.pc = 64231
            value = memory.load(cells.value(8571), 4)
            vm._write(8572, value, 4, 'L5.unsigned_load')
            tick(64231)
            _pointer(vm, 64231, 1, 8559, 8573, (8566,))
            tick(64238)
            vm.pc = 64243
            cells.copy_q_clear_owned(8573, 8574)
            tick(64243)
            vm.pc = 64247
            pointer = cells.value(8574)
            value = memory.load(cells.pointer(8572), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(64247)
            vm.pc = 64248
            tick(64248)
            vm.pc = 64251
            vm.auxiliary = (0, 1214820353)
            tick(64251)
            vm.pc = 64256
            vm._write(8567, memory.load(cells.pointer(8566), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(64256)
            vm.pc = 64258
            vm._jump(1583)
            continue
        if vm.block == 1585:
            tick(64258)
            _phi(vm, 64258, (8575, 2, 8576, 1586, 8568, 1583))
            tick(64265)
            vm.pc = 64270
            vm._write(8577, int(cells.value(8575) < cells.value(8545)), 4, 'once18.unsigned_q')
            tick(64270)
            vm.pc = 64274
            vm._jump(1586 if cells.value(8577) != 0 else 1587)
            continue
        if vm.block == 1586:
            tick(64274)
            _pointer(vm, 64274, 1, 290, 8578, (8575,))
            tick(64281)
            vm.pc = 64285
            value = memory.load(cells.value(8578), 1)
            vm._write(8579, value, 4, 'high.load')
            tick(64285)
            _pointer(vm, 64285, 1, 8559, 8580, (8575,))
            tick(64292)
            vm.pc = 64296
            pointer = cells.value(8580)
            value = memory.load(cells.pointer(8579), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(64296)
            vm.pc = 64297
            tick(64297)
            vm.pc = 64300
            vm.auxiliary = (0, 765898754)
            tick(64300)
            vm.pc = 64305
            vm._write(8576, memory.load(cells.pointer(8575), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(64305)
            vm.pc = 64307
            vm._jump(1585)
            continue
        if vm.block == 1587:
            tick(64307)
            _pointer(vm, 64307, 47, 81, 8581, (145, 8545))
            tick(64315)
            vm.pc = 64317
            vm._jump(1588)
            continue
        if vm.block == 1588:
            tick(64317)
            _phi(vm, 64317, (8582, 2, 145, 1587, 8583, 1589))
            tick(64324)
            vm.pc = 64329
            vm._write(8584, int(cells.value(8582) < cells.value(172)), 4, 'once18.unsigned_q')
            tick(64329)
            vm.pc = 64333
            vm._jump(1589 if cells.value(8584) != 0 else 1590)
            continue
        if vm.block == 1589:
            tick(64333)
            _pointer(vm, 64333, 1, 8540, 8585, (8582,))
            tick(64340)
            vm.pc = 64345
            cells.copy_q_clear_owned(8585, 8586)
            tick(64345)
            vm.pc = 64349
            value = memory.load(cells.value(8586), 4)
            vm._write(8587, value, 4, 'high.load')
            tick(64349)
            _pointer(vm, 64349, 1, 8581, 8588, (8582,))
            tick(64356)
            vm.pc = 64361
            cells.copy_q_clear_owned(8588, 8589)
            tick(64361)
            vm.pc = 64365
            pointer = cells.value(8589)
            value = memory.load(cells.pointer(8587), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(64365)
            vm.pc = 64366
            tick(64366)
            vm.pc = 64369
            vm.auxiliary = (0, 1010561025)
            tick(64369)
            vm.pc = 64374
            vm._write(8583, memory.load(cells.pointer(8582), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(64374)
            vm.pc = 64376
            vm._jump(1588)
            continue
        if vm.block == 1590:
            tick(64376)
            _phi(vm, 64376, (8590, 2, 8591, 1591, 172, 1588))
            tick(64383)
            vm.pc = 64388
            vm._write(8592, int(cells.value(8590) < cells.value(172)), 4, 'once18.unsigned_q')
            tick(64388)
            vm.pc = 64392
            vm._jump(1591 if cells.value(8592) != 0 else 1592)
            continue
        if vm.block == 1591:
            tick(64392)
            _pointer(vm, 64392, 1, 8540, 8593, (8590,))
            tick(64399)
            vm.pc = 64403
            value = memory.load(cells.value(8593), 1)
            vm._write(8594, value, 4, 'high.load')
            tick(64403)
            _pointer(vm, 64403, 1, 8581, 8595, (8590,))
            tick(64410)
            vm.pc = 64414
            pointer = cells.value(8595)
            value = memory.load(cells.pointer(8594), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(64414)
            vm.pc = 64415
            tick(64415)
            vm.pc = 64418
            vm.auxiliary = (0, 1313804289)
            tick(64418)
            vm.pc = 64423
            vm._write(8591, memory.load(cells.pointer(8590), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(64423)
            vm.pc = 64425
            vm._jump(1590)
            continue
        if vm.block == 1592:
            tick(64425)
            _pointer(vm, 64425, 49, 94, 8596, (145, 145))
            tick(64433)
            _pointer(vm, 64433, 49, 94, 8597, (145, 145))
            tick(64441)
            vm.pc = 64443
            vm._jump(1593)
            continue
        if vm.block == 1593:
            tick(64443)
            _phi(vm, 64443, (8598, 2, 205, 1592, 8599, 1594))
            tick(64450)
            _phi(vm, 64450, (8600, 2, 8597, 1592, 8601, 1594))
            tick(64457)
            vm.pc = 64458
            tick(64458)
            vm.pc = 64461
            vm.auxiliary = (0, 1957885891)
            tick(64461)
            _equal(vm, 64466, 8, 8598, 145, 8602)
            tick(64466)
            vm.pc = 64470
            vm._jump(1595 if cells.value(8602) != 0 else 1594)
            continue
        if vm.block == 1594:
            tick(64470)
            vm.pc = 64471
            tick(64471)
            vm.pc = 64474
            vm.auxiliary = (0, 2065223681)
            tick(64474)
            vm.pc = 64479
            vm._write(8599, memory.load(cells.pointer(8598), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(64479)
            _pointer(vm, 64479, 1, 8600, 8601, (163,))
            tick(64486)
            vm.pc = 64490
            pointer = cells.value(8600)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(64490)
            vm.pc = 64492
            vm._jump(1593)
            continue
        if vm.block == 1595:
            tick(64492)
            _pointer(vm, 64492, 49, 82, 8603, (145, 145))
            tick(64500)
            _pointer(vm, 64500, 49, 82, 8604, (145, 145))
            tick(64508)
            vm.pc = 64510
            vm._jump(1596)
            continue
        if vm.block == 1596:
            tick(64510)
            _phi(vm, 64510, (8605, 2, 205, 1595, 8606, 1597))
            tick(64517)
            _phi(vm, 64517, (8607, 2, 8604, 1595, 8608, 1597))
            tick(64524)
            vm.pc = 64525
            tick(64525)
            vm.pc = 64528
            vm.auxiliary = (0, 1806846147)
            tick(64528)
            _equal(vm, 64533, 8, 8605, 145, 8609)
            tick(64533)
            vm.pc = 64537
            vm._jump(1598 if cells.value(8609) != 0 else 1597)
            continue
        if vm.block == 1597:
            tick(64537)
            vm.pc = 64538
            tick(64538)
            vm.pc = 64541
            vm.auxiliary = (0, 1814835201)
            tick(64541)
            vm.pc = 64546
            vm._write(8606, memory.load(cells.pointer(8605), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(64546)
            _pointer(vm, 64546, 1, 8607, 8608, (163,))
            tick(64553)
            vm.pc = 64557
            pointer = cells.value(8607)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(64557)
            vm.pc = 64559
            vm._jump(1596)
            continue
        if vm.block == 1598:
            tick(64559)
            _pointer(vm, 64559, 49, 83, 8610, (145, 145))
            tick(64567)
            _pointer(vm, 64567, 49, 83, 8611, (145, 145))
            tick(64575)
            vm.pc = 64577
            vm._jump(1599)
            continue
        if vm.block == 1599:
            tick(64577)
            _phi(vm, 64577, (8612, 2, 205, 1598, 8613, 1600))
            tick(64584)
            _phi(vm, 64584, (8614, 2, 8611, 1598, 8615, 1600))
            tick(64591)
            vm.pc = 64592
            tick(64592)
            vm.pc = 64595
            vm.auxiliary = (0, 883096755)
            tick(64595)
            _equal(vm, 64600, 8, 8612, 145, 8616)
            tick(64600)
            vm.pc = 64604
            vm._jump(1601 if cells.value(8616) != 0 else 1600)
            continue
        if vm.block == 1600:
            tick(64604)
            vm.pc = 64605
            tick(64605)
            vm.pc = 64608
            vm.auxiliary = (0, 1120735233)
            tick(64608)
            vm.pc = 64613
            vm._write(8613, memory.load(cells.pointer(8612), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(64613)
            _pointer(vm, 64613, 1, 8614, 8615, (163,))
            tick(64620)
            vm.pc = 64624
            pointer = cells.value(8614)
            value = memory.load(cells.pointer(235), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(64624)
            vm.pc = 64626
            vm._jump(1599)
            continue
        if vm.block == 1601:
            tick(64626)
            vm.pc = 64628
            vm._jump(1602)
            continue
        if vm.block == 1602:
            tick(64628)
            _phi(vm, 64628, (8617, 2, 145, 1601, 8618, 1603))
            tick(64635)
            vm.pc = 64640
            vm._write(8619, int(cells.value(8617) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(64640)
            vm.pc = 64644
            vm._jump(1603 if cells.value(8619) != 0 else 1604)
            continue
        if vm.block == 1603:
            tick(64644)
            _pointer(vm, 64644, 1, 8375, 8620, (8617,))
            tick(64651)
            vm.pc = 64656
            cells.copy_q_clear_owned(8620, 8621)
            tick(64656)
            vm.pc = 64660
            value = memory.load(cells.value(8621), 4)
            vm._write(8622, value, 4, 'L5.unsigned_load')
            tick(64660)
            _pointer(vm, 64660, 1, 8611, 8623, (8617,))
            tick(64667)
            vm.pc = 64672
            cells.copy_q_clear_owned(8623, 8624)
            tick(64672)
            vm.pc = 64676
            pointer = cells.value(8624)
            value = memory.load(cells.pointer(8622), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(64676)
            vm.pc = 64677
            tick(64677)
            vm.pc = 64680
            vm.auxiliary = (0, 966074369)
            tick(64680)
            vm.pc = 64685
            vm._write(8618, memory.load(cells.pointer(8617), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(64685)
            vm.pc = 64687
            vm._jump(1602)
            continue
        if vm.block == 1604:
            tick(64687)
            _phi(vm, 64687, (8625, 2, 8626, 1605, 184, 1602))
            tick(64694)
            vm.pc = 64699
            vm._write(8627, int(cells.value(8625) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(64699)
            vm.pc = 64703
            vm._jump(1605 if cells.value(8627) != 0 else 1606)
            continue
        if vm.block == 1605:
            tick(64703)
            _pointer(vm, 64703, 1, 8375, 8628, (8625,))
            tick(64710)
            vm.pc = 64714
            value = memory.load(cells.value(8628), 1)
            vm._write(8629, value, 4, 'high.load')
            tick(64714)
            _pointer(vm, 64714, 1, 8611, 8630, (8625,))
            tick(64721)
            vm.pc = 64725
            pointer = cells.value(8630)
            value = memory.load(cells.pointer(8629), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(64725)
            vm.pc = 64726
            tick(64726)
            vm.pc = 64729
            vm.auxiliary = (0, 1272332290)
            tick(64729)
            vm.pc = 64734
            vm._write(8626, memory.load(cells.pointer(8625), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(64734)
            vm.pc = 64736
            vm._jump(1604)
            continue
        if vm.block == 1606:
            tick(64736)
            vm.pc = 64738
            vm._jump(1607)
            continue
        if vm.block == 1607:
            tick(64738)
            _phi(vm, 64738, (8631, 2, 502, 1606, 8632, 1608))
            tick(64745)
            _phi(vm, 64745, (8633, 2, 479, 1606, 8634, 1608))
            tick(64752)
            vm.pc = 64753
            tick(64753)
            vm.pc = 64756
            vm.auxiliary = (0, 440572518)
            tick(64756)
            vm.pc = 64761
            vm._write(8635, int(memory.load(cells.pointer(8633), 4, signed=True) > memory.load(cells.pointer(476), 4, signed=True)), 4, 'L25.comparison')
            tick(64761)
            vm.pc = 64765
            vm._jump(1608 if cells.value(8635) != 0 else 1609)
            continue
        if vm.block == 1609:
            tick(64765)
            vm.pc = 64770
            cells.copy_q_clear_owned(84, 8636)
            tick(64770)
            vm.pc = 64779
            _tail_host(vm, 64770, 157, (8636, 158, 205), 121, 8637)
            tick(64779)
            vm.pc = 64786
            _tail_host(vm, 64779, 8639, (8640,), 203, 8638)
            tick(64786)
            vm.pc = 64791
            bits = memory.load(cells.pointer(8638), 4)
            from .primary_x86_float import ScalarSSEUnavailable, cvttss2si_i64_low_dword
            try:
                value = cvttss2si_i64_low_dword(bits, vm.scalar_sse_state)
            except ScalarSSEUnavailable as error:
                raise PrimarySemanticUnavailable(str(error)) from error
            vm._write(8641, value & 0xFFFFFFFF, 8, 'L21.float32_i64_low_dword_q')
            tick(64791)
            vm.pc = 64792
            tick(64792)
            vm.pc = 64795
            vm.auxiliary = (0, 1088610165)
            tick(64795)
            vm.pc = 64800
            a = memory.load(cells.pointer(8641), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(4098), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(8642, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(64800)
            vm.pc = 64807
            selected = 8641 if cells.value(8642) != 0 else 4098
            vm._write(8643, memory.load(cells.pointer(selected), 4, signed=True), 8, 'L7.selected_q')
            tick(64807)
            vm.pc = 64810
            vm.auxiliary = (0, 38085)
            tick(64810)
            _single_control(vm)
            vm.pc = 64815
            count = memory.load(cells.pointer(360), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8641), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(8644, value, 4, 'typed.selector3.d')
            tick(64815)
            vm.pc = 64818
            vm.auxiliary = (0, 13162)
            tick(64818)
            vm.pc = 64823
            vm._write(8646, memory.load(cells.pointer(8644), 4, signed=True) - memory.load(cells.pointer(8645), 4, signed=True), 8, 'typed.selector0.q')
            tick(64823)
            vm.pc = 64828
            cells.copy_q_clear_owned(85, 8647)
            tick(64828)
            vm.pc = 64832
            pointer = cells.value(85)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(64832)
            vm.pc = 64838
            _tail_host(vm, 64832, 8649, (), 135, 8648)
            tick(64838)
            vm.pc = 64840
            vm._jump(1610)
            continue
        if vm.block == 1608:
            tick(64840)
            vm.pc = 64841
            tick(64841)
            vm.pc = 64844
            vm.auxiliary = (0, 1461403650)
            tick(64844)
            vm.pc = 64849
            vm._write(8651, memory.load(cells.pointer(8633), 4, signed=True) + memory.load(cells.pointer(8650), 4, signed=True), 8, 'once1.integer')
            tick(64849)
            vm.pc = 64854
            _convert(vm, 8, 8651, 8652)
            tick(64854)
            _pointer(vm, 64854, 1, 8375, 8653, (8652,))
            tick(64861)
            vm.pc = 64865
            value = memory.load(cells.value(8653), 1)
            vm._write(8654, value, 4, 'high.load')
            tick(64865)
            vm.pc = 64869
            value = memory.load(cells.value(8611), 1)
            vm._write(8655, value, 4, 'high.load')
            tick(64869)
            _pointer(vm, 64869, 49, 83, 8656, (145, 172))
            tick(64877)
            vm.pc = 64881
            value = memory.load(cells.value(8656), 1)
            vm._write(8657, value, 4, 'high.load')
            tick(64881)
            vm.pc = 64884
            vm.auxiliary = (0, 1262301699)
            tick(64884)
            vm.pc = 64889
            vm._write(8658, memory.load(cells.pointer(8655), 1, signed=True) * memory.load(cells.pointer(8657), 1, signed=True), 8, 'once0.integer')
            tick(64889)
            vm.pc = 64892
            vm.auxiliary = (0, 61471)
            tick(64892)
            vm.pc = 64897
            vm._write(8660, memory.load(cells.pointer(8658), 1, signed=True) & memory.load(cells.pointer(8659), 1, signed=True), 8, 'typed.selector1.q')
            tick(64897)
            vm.pc = 64900
            vm.auxiliary = (0, 10316)
            tick(64900)
            vm.pc = 64906
            vm._write(8661, memory.load(cells.pointer(8660), 1, signed=True) ^ memory.load(cells.pointer(8654), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(64906)
            vm.pc = 64909
            vm.auxiliary = (0, 1715732482)
            tick(64909)
            vm.pc = 64914
            vm._write(8632, memory.load(cells.pointer(8631), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(64914)
            vm.pc = 64919
            _convert(vm, 8, 8631, 8662)
            tick(64919)
            _pointer(vm, 64919, 49, 83, 8663, (145, 8662))
            tick(64927)
            vm.pc = 64931
            pointer = cells.value(8663)
            value = memory.load(cells.pointer(8661), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(64931)
            vm.pc = 64934
            vm.auxiliary = (0, 1069027329)
            tick(64934)
            vm.pc = 64939
            vm._write(8634, memory.load(cells.pointer(8633), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(64939)
            vm.pc = 64941
            vm._jump(1607)
            continue
        if vm.block == 1610:
            tick(64941)
            _phi(vm, 64941, (8664, 2, 158, 1609, 8665, 1611))
            tick(64948)
            vm.pc = 64949
            tick(64949)
            vm.pc = 64952
            vm.auxiliary = (0, 1892871781)
            tick(64952)
            vm.pc = 64957
            a = memory.load(cells.pointer(8664), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(8643), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(8666, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(64957)
            vm.pc = 64961
            vm._jump(1612 if cells.value(8666) != 0 else 1613)
            continue
        if vm.block == 1613:
            tick(64961)
            vm.pc = 64962
            tick(64962)
            vm.pc = 64965
            vm.auxiliary = (0, 9950)
            tick(64965)
            _single_control(vm)
            vm.pc = 64970
            count = memory.load(cells.pointer(360), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8643), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(8667, value, 4, 'typed.selector3.d')
            tick(64970)
            vm.pc = 64974
            pointer = cells.value(139)
            value = memory.load(cells.pointer(8667), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(64974)
            _pointer(vm, 64974, 1, 8375, 8668, (184,))
            tick(64981)
            vm.pc = 64986
            _convert(vm, 8, 8667, 8669)
            tick(64986)
            _pointer(vm, 64986, 1, 8346, 8670, (8669,))
            tick(64993)
            vm.pc = 64995
            vm._jump(1614)
            continue
        if vm.block == 1614:
            tick(64995)
            _phi(vm, 64995, (8671, 2, 145, 1613, 8672, 1615))
            tick(65002)
            vm.pc = 65007
            vm._write(8673, int(cells.value(8671) < cells.value(205)), 4, 'once18.unsigned_q')
            tick(65007)
            vm.pc = 65011
            vm._jump(1615 if cells.value(8673) != 0 else 1616)
            continue
        if vm.block == 1615:
            tick(65011)
            _pointer(vm, 65011, 1, 8668, 8674, (8671,))
            tick(65018)
            vm.pc = 65023
            cells.copy_q_clear_owned(8674, 8675)
            tick(65023)
            vm.pc = 65027
            value = memory.load(cells.value(8675), 4)
            vm._write(8676, value, 4, 'high.load')
            tick(65027)
            _pointer(vm, 65027, 1, 8670, 8677, (8671,))
            tick(65034)
            vm.pc = 65039
            cells.copy_q_clear_owned(8677, 8678)
            tick(65039)
            vm.pc = 65043
            pointer = cells.value(8678)
            value = memory.load(cells.pointer(8676), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(65043)
            vm.pc = 65044
            tick(65044)
            vm.pc = 65047
            vm.auxiliary = (0, 1309261826)
            tick(65047)
            vm.pc = 65052
            vm._write(8672, memory.load(cells.pointer(8671), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(65052)
            vm.pc = 65054
            vm._jump(1614)
            continue
        if vm.block == 1616:
            tick(65054)
            _phi(vm, 65054, (8679, 2, 8680, 1617, 205, 1614))
            tick(65061)
            vm.pc = 65066
            vm._write(8681, int(cells.value(8679) < cells.value(205)), 4, 'once18.unsigned_q')
            tick(65066)
            vm.pc = 65070
            vm._jump(1617 if cells.value(8681) != 0 else 1618)
            continue
        if vm.block == 1617:
            tick(65070)
            _pointer(vm, 65070, 1, 8668, 8682, (8679,))
            tick(65077)
            vm.pc = 65081
            value = memory.load(cells.value(8682), 1)
            vm._write(8683, value, 4, 'high.load')
            tick(65081)
            _pointer(vm, 65081, 1, 8670, 8684, (8679,))
            tick(65088)
            vm.pc = 65092
            pointer = cells.value(8684)
            value = memory.load(cells.pointer(8683), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(65092)
            vm.pc = 65093
            tick(65093)
            vm.pc = 65096
            vm.auxiliary = (0, 457379842)
            tick(65096)
            vm.pc = 65101
            vm._write(8680, memory.load(cells.pointer(8679), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(65101)
            vm.pc = 65103
            vm._jump(1616)
            continue
        if vm.block == 1618:
            tick(65103)
            vm.pc = 65107
            value = memory.load(cells.value(139), 4)
            vm._write(8685, value, 4, 'high.load')
            tick(65107)
            vm.pc = 65108
            tick(65108)
            vm.pc = 65111
            vm.auxiliary = (0, 408961025)
            tick(65111)
            vm.pc = 65116
            vm._write(8686, memory.load(cells.pointer(8685), 4, signed=True) + memory.load(cells.pointer(375), 4, signed=True), 8, 'once1.integer')
            tick(65116)
            vm.pc = 65119
            vm.auxiliary = (0, 38189)
            tick(65119)
            vm.pc = 65124
            vm._write(8687, memory.load(cells.pointer(8539), 1, signed=True) & memory.load(cells.pointer(354), 1, signed=True), 8, 'typed.selector1.q')
            tick(65124)
            vm.pc = 65127
            vm.auxiliary = (0, 40500)
            tick(65127)
            vm.pc = 65133
            vm._write(8688, memory.load(cells.pointer(8687), 1, signed=True) ^ memory.load(cells.pointer(354), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(65133)
            vm.pc = 65138
            _convert(vm, 4, 8688, 8689)
            tick(65138)
            vm.pc = 65141
            vm.auxiliary = (0, 18243)
            tick(65141)
            vm.pc = 65146
            vm._write(8690, memory.load(cells.pointer(8686), 4, signed=True) - memory.load(cells.pointer(8689), 4, signed=True), 8, 'typed.selector0.q')
            tick(65146)
            vm.pc = 65151
            value = memory.load(cells.pointer(8690), 4)
            count = memory.load(cells.pointer(269), 1)
            vm._write(8691, value >> (count & 31), 4, 'once8.logical_shift')
            tick(65151)
            vm.pc = 65153
            vm._jump(1619)
            continue
        if vm.block == 1612:
            tick(65153)
            vm.pc = 65157
            value = memory.load(cells.value(85), 8)
            vm._write(8692, value, 8, 'high.load')
            tick(65157)
            vm.pc = 65162
            vm._write(8694, int(cells.value(8692) < cells.value(8693)), 4, 'once18.unsigned_q')
            tick(65162)
            vm.pc = 65166
            vm._jump(1620 if cells.value(8694) != 0 else 1621)
            continue
        if vm.block == 1620:
            tick(65166)
            vm.pc = 65167
            tick(65167)
            vm.pc = 65170
            vm.auxiliary = (0, 13675)
            tick(65170)
            vm.pc = 65175
            vm._write(8695, memory.load(cells.pointer(8693), 8, signed=True) - memory.load(cells.pointer(8692), 8, signed=True), 8, 'typed.selector0.q')
            tick(65175)
            vm.pc = 65180
            vm._write(8696, int(cells.value(8695) < cells.value(205)), 4, 'once18.unsigned_q')
            tick(65180)
            vm.pc = 65187
            selected = 8695 if cells.value(8696) != 0 else 205
            vm._write(8697, memory.load(cells.pointer(selected), 8, signed=True), 8, 'L7.selected_q')
            tick(65187)
            _pointer(vm, 65187, 1, 8559, 8698, (8692,))
            tick(65194)
            vm.pc = 65199
            vm._write(8699, memory.load(cells.pointer(8697), 8, signed=True) & memory.load(cells.pointer(1732), 8, signed=True), 8, 'L13.binary_q')
            tick(65199)
            vm.pc = 65201
            vm._jump(1622)
            continue
        if vm.block == 1622:
            tick(65201)
            _phi(vm, 65201, (8700, 2, 145, 1620, 8701, 1623))
            tick(65208)
            vm.pc = 65213
            vm._write(8702, int(cells.value(8700) < cells.value(8699)), 4, 'once18.unsigned_q')
            tick(65213)
            vm.pc = 65217
            vm._jump(1623 if cells.value(8702) != 0 else 1624)
            continue
        if vm.block == 1623:
            tick(65217)
            _pointer(vm, 65217, 1, 8698, 8703, (8700,))
            tick(65224)
            vm.pc = 65229
            cells.copy_q_clear_owned(8703, 8704)
            tick(65229)
            vm.pc = 65233
            value = memory.load(cells.value(8704), 4)
            vm._write(8705, value, 4, 'high.load')
            tick(65233)
            _pointer(vm, 65233, 1, 8597, 8706, (8700,))
            tick(65240)
            vm.pc = 65245
            cells.copy_q_clear_owned(8706, 8707)
            tick(65245)
            vm.pc = 65249
            pointer = cells.value(8707)
            value = memory.load(cells.pointer(8705), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(65249)
            vm.pc = 65250
            tick(65250)
            vm.pc = 65253
            vm.auxiliary = (0, 217382914)
            tick(65253)
            vm.pc = 65258
            vm._write(8701, memory.load(cells.pointer(8700), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(65258)
            vm.pc = 65260
            vm._jump(1622)
            continue
        if vm.block == 1624:
            tick(65260)
            _phi(vm, 65260, (8708, 2, 8709, 1625, 8699, 1622))
            tick(65267)
            vm.pc = 65272
            vm._write(8710, int(cells.value(8708) < cells.value(8697)), 4, 'once18.unsigned_q')
            tick(65272)
            vm.pc = 65276
            vm._jump(1625 if cells.value(8710) != 0 else 1626)
            continue
        if vm.block == 1625:
            tick(65276)
            _pointer(vm, 65276, 1, 8698, 8711, (8708,))
            tick(65283)
            vm.pc = 65287
            value = memory.load(cells.value(8711), 1)
            vm._write(8712, value, 4, 'high.load')
            tick(65287)
            _pointer(vm, 65287, 1, 8597, 8713, (8708,))
            tick(65294)
            vm.pc = 65298
            pointer = cells.value(8713)
            value = memory.load(cells.pointer(8712), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(65298)
            vm.pc = 65299
            tick(65299)
            vm.pc = 65302
            vm.auxiliary = (0, 1766141953)
            tick(65302)
            vm.pc = 65307
            vm._write(8709, memory.load(cells.pointer(8708), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(65307)
            vm.pc = 65309
            vm._jump(1624)
            continue
        if vm.block == 1626:
            tick(65309)
            vm.pc = 65311
            vm._jump(1621)
            continue
        if vm.block == 1621:
            tick(65311)
            _phi(vm, 65311, (8714, 2, 8697, 1626, 145, 1612))
            tick(65318)
            vm.pc = 65323
            vm._write(8715, cells.value(8714) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(65323)
            vm.pc = 65324
            tick(65324)
            vm.pc = 65327
            vm.auxiliary = (0, 1080174166)
            tick(65327)
            vm.pc = 65332
            vm._write(8716, int(memory.load(cells.pointer(8715), 4, signed=True) > memory.load(cells.pointer(396), 4, signed=True)), 4, 'L25.comparison')
            tick(65332)
            vm.pc = 65335
            vm.auxiliary = (0, 1855084228)
            tick(65335)
            vm.pc = 65340
            vm._write(8717, int(memory.load(cells.pointer(8715), 4, signed=True) != memory.load(cells.pointer(375), 4, signed=True)), 4, 'L27.comparison')
            tick(65340)
            vm.pc = 65345
            vm._write(8718, memory.load(cells.pointer(8716), 1, signed=True) & memory.load(cells.pointer(8717), 1, signed=True), 8, 'L13.binary_q')
            tick(65345)
            vm.pc = 65349
            vm._jump(1627 if cells.value(8718) != 0 else 1628)
            continue
        if vm.block == 1627:
            tick(65349)
            vm.pc = 65350
            tick(65350)
            vm.pc = 65353
            vm.auxiliary = (0, 862036483)
            tick(65353)
            vm.pc = 65358
            vm._write(8720, memory.load(cells.pointer(8714), 8, signed=True) * memory.load(cells.pointer(8719), 8, signed=True), 8, 'once0.integer')
            tick(65358)
            vm.pc = 65361
            vm.auxiliary = (0, 1059966977)
            tick(65361)
            vm.pc = 65366
            vm._write(8722, memory.load(cells.pointer(8720), 8, signed=True) + memory.load(cells.pointer(8721), 8, signed=True), 8, 'once1.integer')
            tick(65366)
            vm.pc = 65369
            vm.auxiliary = (0, 18704)
            tick(65369)
            vm.pc = 65374
            count = memory.load(cells.pointer(421), 4)
            if count & 0x80000000 or count >= 64:
                value = 0
            else:
                value = cells.value(8722)
                if count and value == 0x8000000000000000:
                    value -= 1
                value >>= count
            vm._write(8723, value, 8, "typed.selector4.q")
            tick(65374)
            vm.pc = 65377
            vm.auxiliary = (0, 58828)
            tick(65377)
            _single_control(vm)
            vm.pc = 65382
            count = memory.load(cells.pointer(421), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(8714) << count
            vm._write(8724, value, 8, "typed.selector3.q")
            tick(65382)
            vm.pc = 65385
            vm.auxiliary = (0, 39273)
            tick(65385)
            vm.pc = 65390
            count = memory.load(cells.pointer(421), 4)
            if count & 0x80000000 or count >= 64:
                value = 0
            else:
                value = cells.value(8724)
                if count and value == 0x8000000000000000:
                    value -= 1
                value >>= count
            vm._write(8725, value, 8, "typed.selector4.q")
            tick(65390)
            _pointer(vm, 65390, 49, 94, 8726, (145, 8725))
            tick(65398)
            vm.pc = 65400
            vm._jump(1629)
            continue
        if vm.block == 1629:
            tick(65400)
            _phi(vm, 65400, (8727, 2, 8723, 1627, 8728, 1630))
            tick(65407)
            _phi(vm, 65407, (8729, 2, 8726, 1627, 8730, 1630))
            tick(65414)
            vm.pc = 65415
            tick(65415)
            vm.pc = 65418
            vm.auxiliary = (0, 351407379)
            tick(65418)
            _equal(vm, 65423, 8, 8727, 145, 8731)
            tick(65423)
            vm.pc = 65427
            vm._jump(1631 if cells.value(8731) != 0 else 1630)
            continue
        if vm.block == 1630:
            tick(65427)
            vm.pc = 65428
            tick(65428)
            vm.pc = 65431
            vm.auxiliary = (0, 408305665)
            tick(65431)
            vm.pc = 65436
            vm._write(8728, memory.load(cells.pointer(8727), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(65436)
            _pointer(vm, 65436, 1, 8729, 8730, (163,))
            tick(65443)
            vm.pc = 65447
            pointer = cells.value(8729)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(65447)
            vm.pc = 65449
            vm._jump(1629)
            continue
        if vm.block == 1631:
            tick(65449)
            vm.pc = 65451
            vm._jump(1628)
            continue
        if vm.block == 1628:
            tick(65451)
            vm.pc = 65452
            tick(65452)
            vm.pc = 65455
            vm.auxiliary = (0, 1574854658)
            tick(65455)
            vm.pc = 65460
            vm._write(8665, memory.load(cells.pointer(8664), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(65460)
            vm.pc = 65463
            vm.auxiliary = (0, 933427205)
            tick(65463)
            vm.pc = 65468
            a = memory.load(cells.pointer(8665), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            b = memory.load(cells.pointer(8643), 4, signed=True) & 0xFFFFFFFFFFFFFFFF
            difference = (a - b) & 0xFFFFFFFFFFFFFFFF
            vm._write(8732, (difference >> 63) | (((a ^ difference) & (a ^ b)) >> 63), 4, 'L29.n_or_v_comparison')
            tick(65468)
            vm.pc = 65472
            vm._jump(1632 if cells.value(8732) != 0 else 1633)
            continue
        if vm.block == 1633:
            tick(65472)
            vm.pc = 65478
            _tail_host(vm, 65472, 8649, (), 135, 8733)
            tick(65478)
            vm.pc = 65483
            cells.copy_q_clear_owned(86, 8734)
            tick(65483)
            vm.pc = 65488
            a, b = cells.value(8733), cells.value(8735)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(8736, a // b, 8, 'L18.unsigned_q_division')
            tick(65488)
            vm.pc = 65493
            a, b = cells.value(8736), cells.value(8735)
            if b == 0:
                raise PrimaryProgramLimit('native unsigned DIV fault outside ordinary execution')
            vm._write(8737, a % b, 8, 'L17.unsigned_q_division')
            tick(65493)
            vm.pc = 65498
            vm._write(8738, cells.value(8737) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(65498)
            vm.pc = 65499
            tick(65499)
            vm.pc = 65502
            vm.auxiliary = (0, 13439)
            tick(65502)
            vm.pc = 65507
            vm._write(8740, memory.load(cells.pointer(8738), 4, signed=True) & memory.load(cells.pointer(8739), 4, signed=True), 8, 'typed.selector1.q')
            tick(65507)
            vm.pc = 65512
            vm._write(8741, int(cells.value(8733) > cells.value(8648)), 4, 'L31.comparison')
            tick(65512)
            vm.pc = 65517
            cells.copy_q_clear_owned(8649, 8742)
            tick(65517)
            vm.pc = 65522
            vm._write(8743, int(cells.value(8742) < cells.value(7853)), 4, 'once18.unsigned_q')
            tick(65522)
            vm.pc = 65527
            vm._write(8744, memory.load(cells.pointer(8741), 1, signed=True) & memory.load(cells.pointer(8743), 1, signed=True), 8, 'L13.binary_q')
            tick(65527)
            vm.pc = 65532
            _convert(vm, 4, 8744, 8745)
            tick(65532)
            vm.pc = 65537
            vm._write(8746, memory.load(cells.pointer(8740), 4, signed=True) | memory.load(cells.pointer(8745), 4, signed=True), 8, 'L15.binary_q')
            tick(65537)
            vm.pc = 65541
            pointer = cells.value(86)
            value = memory.load(cells.pointer(8746), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(65541)
            vm.pc = 65544
            vm.auxiliary = (0, 21787)
            tick(65544)
            vm.pc = 65549
            vm._write(8747, memory.load(cells.pointer(375), 4, signed=True) - memory.load(cells.pointer(8646), 4, signed=True), 8, 'typed.selector0.q')
            tick(65549)
            vm.pc = 65554
            _convert(vm, 8, 8747, 8748)
            tick(65554)
            _pointer(vm, 65554, 49, 94, 8749, (145, 8748))
            tick(65562)
            vm.pc = 65564
            vm._jump(1634)
            continue
        if vm.block == 1634:
            tick(65564)
            _phi(vm, 65564, (8750, 2, 8751, 1635, 145, 1633))
            tick(65571)
            vm.pc = 65576
            vm._write(8752, int(cells.value(8750) < cells.value(169)), 4, 'once18.unsigned_q')
            tick(65576)
            vm.pc = 65580
            vm._jump(1635 if cells.value(8752) != 0 else 1636)
            continue
        if vm.block == 1635:
            tick(65580)
            _pointer(vm, 65580, 1, 8734, 8753, (8750,))
            tick(65587)
            vm.pc = 65591
            value = memory.load(cells.value(8753), 1)
            vm._write(8754, value, 4, 'high.load')
            tick(65591)
            _pointer(vm, 65591, 1, 8749, 8755, (8750,))
            tick(65598)
            vm.pc = 65602
            pointer = cells.value(8755)
            value = memory.load(cells.pointer(8754), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(65602)
            vm.pc = 65603
            tick(65603)
            vm.pc = 65606
            vm.auxiliary = (0, 367214593)
            tick(65606)
            vm.pc = 65611
            vm._write(8751, memory.load(cells.pointer(8750), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(65611)
            vm.pc = 65613
            vm._jump(1634)
            continue
        if vm.block == 1636:
            tick(65613)
            vm.pc = 65618
            _convert(vm, 8, 8646, 8756)
            tick(65618)
            vm.pc = 65619
            tick(65619)
            vm.pc = 65622
            vm.auxiliary = (0, 861446145)
            tick(65622)
            vm.pc = 65627
            vm._write(8758, memory.load(cells.pointer(8756), 8, signed=True) + memory.load(cells.pointer(8757), 8, signed=True), 8, 'once1.integer')
            tick(65627)
            vm.pc = 65630
            vm.auxiliary = (0, 50150)
            tick(65630)
            _single_control(vm)
            vm.pc = 65635
            count = memory.load(cells.pointer(939), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8646), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(8759, value, 4, 'typed.selector3.d')
            tick(65635)
            vm.pc = 65638
            vm.auxiliary = (0, 12147)
            tick(65638)
            vm.pc = 65643
            count = memory.load(cells.pointer(939), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8759), 4, signed=True) & 0xFFFFFFFF) >> count
            vm._write(8760, value, 4, 'typed.selector4.d')
            tick(65643)
            vm.pc = 65646
            vm.auxiliary = (0, 59163)
            tick(65646)
            vm.pc = 65651
            vm._write(8761, memory.load(cells.pointer(592), 4, signed=True) - memory.load(cells.pointer(8646), 4, signed=True), 8, 'typed.selector0.q')
            tick(65651)
            vm.pc = 65656
            _convert(vm, 8, 8761, 8762)
            tick(65656)
            _pointer(vm, 65656, 49, 94, 8763, (145, 8762))
            tick(65664)
            vm.pc = 65666
            vm._jump(1637)
            continue
        if vm.block == 1637:
            tick(65666)
            _phi(vm, 65666, (8764, 2, 8758, 1636, 8765, 1638))
            tick(65673)
            _phi(vm, 65673, (8766, 2, 8763, 1636, 8767, 1638))
            tick(65680)
            vm.pc = 65681
            tick(65681)
            vm.pc = 65684
            vm.auxiliary = (0, 928175491)
            tick(65684)
            vm.pc = 65689
            vm._write(8768, int(memory.load(cells.pointer(8764), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(65689)
            vm.pc = 65693
            vm._jump(1639 if cells.value(8768) != 0 else 1638)
            continue
        if vm.block == 1638:
            tick(65693)
            vm.pc = 65694
            tick(65694)
            vm.pc = 65697
            vm.auxiliary = (0, 1314566145)
            tick(65697)
            vm.pc = 65702
            vm._write(8765, memory.load(cells.pointer(8764), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(65702)
            vm.pc = 65707
            vm._write(8769, cells.value(8760) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(65707)
            _pointer(vm, 65707, 1, 8766, 8767, (163,))
            tick(65714)
            vm.pc = 65718
            pointer = cells.value(8766)
            value = memory.load(cells.pointer(8769), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(65718)
            vm.pc = 65720
            vm._jump(1637)
            continue
        if vm.block == 1639:
            tick(65720)
            vm.pc = 65722
            vm._jump(1632)
            continue
        if vm.block == 1632:
            tick(65722)
            vm.pc = 65724
            vm._jump(1640)
            continue
        if vm.block == 1640:
            tick(65724)
            _phi(vm, 65724, (8770, 2, 158, 1632, 8771, 1641))
            tick(65731)
            vm.pc = 65736
            vm._write(8772, int(cells.value(8770) < cells.value(375)), 4, 'once18.unsigned_q')
            tick(65736)
            vm.pc = 65740
            vm._jump(1641 if cells.value(8772) != 0 else 1642)
            continue
        if vm.block == 1642:
            tick(65740)
            vm.pc = 65742
            vm._jump(1643)
            continue
        if vm.block == 1643:
            tick(65742)
            _phi(vm, 65742, (8773, 2, 158, 1642, 8774, 1644))
            tick(65749)
            vm.pc = 65754
            vm._write(8775, int(cells.value(8773) < cells.value(375)), 4, 'once18.unsigned_q')
            tick(65754)
            vm.pc = 65758
            vm._jump(1644 if cells.value(8775) != 0 else 1645)
            continue
        if vm.block == 1644:
            tick(65758)
            vm.pc = 65763
            _convert(vm, 8, 8773, 8776)
            tick(65763)
            _pointer(vm, 65763, 1, 8597, 8777, (8776,))
            tick(65770)
            vm.pc = 65774
            value = memory.load(cells.value(8777), 1)
            vm._write(8778, value, 4, 'high.load')
            tick(65774)
            vm.pc = 65779
            cells.copy_q_clear_owned(84, 8779)
            tick(65779)
            vm.pc = 65780
            tick(65780)
            vm.pc = 65783
            vm.auxiliary = (0, 17550)
            tick(65783)
            _single_control(vm)
            vm.pc = 65788
            count = memory.load(cells.pointer(311), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8773), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(8780, value, 4, 'typed.selector3.d')
            tick(65788)
            vm.pc = 65793
            vm._write(8781, memory.load(cells.pointer(8780), 4, signed=True) & memory.load(cells.pointer(387), 4, signed=True), 8, 'L13.binary_q')
            tick(65793)
            vm.pc = 65798
            value = memory.load(cells.pointer(8773), 4)
            count = memory.load(cells.pointer(311), 1)
            vm._write(8782, value >> (count & 31), 4, 'once8.logical_shift')
            tick(65798)
            vm.pc = 65801
            vm.auxiliary = (0, 1965559810)
            tick(65801)
            vm.pc = 65806
            vm._write(8783, memory.load(cells.pointer(8781), 4, signed=True) + memory.load(cells.pointer(8782), 4, signed=True), 8, 'once1.integer')
            tick(65806)
            vm.pc = 65811
            _convert(vm, 8, 8783, 8784)
            tick(65811)
            _pointer(vm, 65811, 49, 8779, 8785, (145, 8784))
            tick(65819)
            vm.pc = 65823
            pointer = cells.value(8785)
            value = memory.load(cells.pointer(8778), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(65823)
            vm.pc = 65826
            vm.auxiliary = (0, 1814487041)
            tick(65826)
            vm.pc = 65831
            vm._write(8774, memory.load(cells.pointer(8773), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(65831)
            vm.pc = 65833
            vm._jump(1643)
            continue
        if vm.block == 1645:
            if vm.pc == 65833:
                tick(65833)
                vm.pc = 65839
                _tail_host(vm, 65833, 8786, (84,), 205, None)
            elif vm.pc != 65839:
                raise PrimarySemanticUnavailable('direct Main M16 requires its exact initial or resumed site')
            tick(65839)
            vm.pc = 65841
            vm._jump(1646)
            continue
        if vm.block == 1646:
            tick(65841)
            _phi(vm, 65841, (8787, 2, 158, 1645, 8788, 1647))
            tick(65848)
            vm.pc = 65853
            vm._write(8789, int(cells.value(8787) < cells.value(375)), 4, 'once18.unsigned_q')
            tick(65853)
            vm.pc = 65857
            vm._jump(1647 if cells.value(8789) != 0 else 1648)
            continue
        if vm.block == 1647:
            tick(65857)
            vm.pc = 65862
            cells.copy_q_clear_owned(84, 8790)
            tick(65862)
            vm.pc = 65863
            tick(65863)
            vm.pc = 65866
            vm.auxiliary = (0, 62125)
            tick(65866)
            _single_control(vm)
            vm.pc = 65871
            count = memory.load(cells.pointer(311), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(8787), 4, signed=True) & 0xFFFFFFFF) << count
            vm._write(8791, value, 4, 'typed.selector3.d')
            tick(65871)
            vm.pc = 65874
            vm.auxiliary = (0, 50948)
            tick(65874)
            vm.pc = 65879
            vm._write(8792, memory.load(cells.pointer(8791), 4, signed=True) & memory.load(cells.pointer(387), 4, signed=True), 8, 'typed.selector1.q')
            tick(65879)
            vm.pc = 65884
            value = memory.load(cells.pointer(8787), 4)
            count = memory.load(cells.pointer(311), 1)
            vm._write(8793, value >> (count & 31), 4, 'once8.logical_shift')
            tick(65884)
            vm.pc = 65887
            vm.auxiliary = (0, 1518899201)
            tick(65887)
            vm.pc = 65892
            vm._write(8794, memory.load(cells.pointer(8792), 4, signed=True) + memory.load(cells.pointer(8793), 4, signed=True), 8, 'once1.integer')
            tick(65892)
            vm.pc = 65897
            _convert(vm, 8, 8794, 8795)
            tick(65897)
            _pointer(vm, 65897, 49, 8790, 8796, (145, 8795))
            tick(65905)
            vm.pc = 65909
            value = memory.load(cells.value(8796), 1)
            vm._write(8797, value, 4, 'high.load')
            tick(65909)
            vm.pc = 65914
            _convert(vm, 8, 8787, 8798)
            tick(65914)
            _pointer(vm, 65914, 1, 8604, 8799, (8798,))
            tick(65921)
            vm.pc = 65925
            pointer = cells.value(8799)
            value = memory.load(cells.pointer(8797), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(65925)
            vm.pc = 65928
            vm.auxiliary = (0, 1219084289)
            tick(65928)
            vm.pc = 65933
            vm._write(8788, memory.load(cells.pointer(8787), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(65933)
            vm.pc = 65935
            vm._jump(1646)
            continue
        if vm.block == 1648:
            tick(65935)
            vm.pc = 65937
            vm._jump(1649)
            continue
        if vm.block == 1649:
            tick(65937)
            _phi(vm, 65937, (8800, 2, 145, 1648, 8801, 1650))
            tick(65944)
            vm.pc = 65949
            vm._write(8802, int(cells.value(8800) < cells.value(205)), 4, 'once18.unsigned_q')
            tick(65949)
            vm.pc = 65953
            vm._jump(1650 if cells.value(8802) != 0 else 1651)
            continue
        if vm.block == 1650:
            tick(65953)
            _pointer(vm, 65953, 1, 8604, 8803, (8800,))
            tick(65960)
            vm.pc = 65965
            cells.copy_q_clear_owned(8803, 8804)
            tick(65965)
            vm.pc = 65969
            value = memory.load(cells.value(8804), 4)
            vm._write(8805, value, 4, 'high.load')
            tick(65969)
            _pointer(vm, 65969, 1, 8611, 8806, (8800,))
            tick(65976)
            vm.pc = 65981
            cells.copy_q_clear_owned(8806, 8807)
            tick(65981)
            vm.pc = 65985
            pointer = cells.value(8807)
            value = memory.load(cells.pointer(8805), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(65985)
            vm.pc = 65986
            tick(65986)
            vm.pc = 65989
            vm.auxiliary = (0, 1472790529)
            tick(65989)
            vm.pc = 65994
            vm._write(8801, memory.load(cells.pointer(8800), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(65994)
            vm.pc = 65996
            vm._jump(1649)
            continue
        if vm.block == 1651:
            tick(65996)
            _phi(vm, 65996, (8808, 2, 8809, 1652, 205, 1649))
            tick(66003)
            vm.pc = 66008
            vm._write(8810, int(cells.value(8808) < cells.value(205)), 4, 'once18.unsigned_q')
            tick(66008)
            vm.pc = 66012
            vm._jump(1652 if cells.value(8810) != 0 else 1653)
            continue
        if vm.block == 1652:
            tick(66012)
            _pointer(vm, 66012, 1, 8604, 8811, (8808,))
            tick(66019)
            vm.pc = 66023
            value = memory.load(cells.value(8811), 1)
            vm._write(8812, value, 4, 'L5.unsigned_load')
            tick(66023)
            _pointer(vm, 66023, 1, 8611, 8813, (8808,))
            tick(66030)
            vm.pc = 66034
            pointer = cells.value(8813)
            value = memory.load(cells.pointer(8812), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(66034)
            vm.pc = 66035
            tick(66035)
            vm.pc = 66038
            vm.auxiliary = (0, 907075586)
            tick(66038)
            vm.pc = 66043
            vm._write(8809, memory.load(cells.pointer(8808), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(66043)
            vm.pc = 66045
            vm._jump(1651)
            continue
        if vm.block == 1653:
            tick(66045)
            vm.pc = 66049
            value = memory.load(cells.value(85), 8)
            vm._write(8814, value, 8, 'high.load')
            tick(66049)
            _pointer(vm, 66049, 1, 8346, 8815, (8814,))
            tick(66056)
            vm.pc = 66058
            vm._jump(1654)
            continue
        if vm.block == 1654:
            tick(66058)
            _phi(vm, 66058, (8816, 2, 145, 1653, 8817, 1655))
            tick(66065)
            vm.pc = 66070
            vm._write(8818, int(cells.value(8816) < cells.value(205)), 4, 'once18.unsigned_q')
            tick(66070)
            vm.pc = 66074
            vm._jump(1655 if cells.value(8818) != 0 else 1656)
            continue
        if vm.block == 1655:
            tick(66074)
            _pointer(vm, 66074, 1, 8604, 8819, (8816,))
            tick(66081)
            vm.pc = 66086
            cells.copy_q_clear_owned(8819, 8820)
            tick(66086)
            vm.pc = 66090
            value = memory.load(cells.value(8820), 4)
            vm._write(8821, value, 4, 'high.load')
            tick(66090)
            _pointer(vm, 66090, 1, 8815, 8822, (8816,))
            tick(66097)
            vm.pc = 66102
            cells.copy_q_clear_owned(8822, 8823)
            tick(66102)
            vm.pc = 66106
            pointer = cells.value(8823)
            value = memory.load(cells.pointer(8821), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(66106)
            vm.pc = 66107
            tick(66107)
            vm.pc = 66110
            vm.auxiliary = (0, 1769906177)
            tick(66110)
            vm.pc = 66115
            vm._write(8817, memory.load(cells.pointer(8816), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(66115)
            vm.pc = 66117
            vm._jump(1654)
            continue
        if vm.block == 1656:
            tick(66117)
            _phi(vm, 66117, (8824, 2, 8825, 1657, 205, 1654))
            tick(66124)
            vm.pc = 66129
            vm._write(8826, int(cells.value(8824) < cells.value(205)), 4, 'once18.unsigned_q')
            tick(66129)
            vm.pc = 66133
            vm._jump(1657 if cells.value(8826) != 0 else 1611)
            continue
        if vm.block == 1657:
            tick(66133)
            _pointer(vm, 66133, 1, 8604, 8827, (8824,))
            tick(66140)
            vm.pc = 66144
            value = memory.load(cells.value(8827), 1)
            vm._write(8828, value, 4, 'high.load')
            tick(66144)
            _pointer(vm, 66144, 1, 8815, 8829, (8824,))
            tick(66151)
            vm.pc = 66155
            pointer = cells.value(8829)
            value = memory.load(cells.pointer(8828), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(66155)
            vm.pc = 66156
            tick(66156)
            vm.pc = 66159
            vm.auxiliary = (0, 616136705)
            tick(66159)
            vm.pc = 66164
            vm._write(8825, memory.load(cells.pointer(8824), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(66164)
            vm.pc = 66166
            vm._jump(1656)
            continue
        if vm.block == 1611:
            tick(66166)
            vm.pc = 66167
            tick(66167)
            vm.pc = 66170
            vm.auxiliary = (0, 17582)
            tick(66170)
            _single_control(vm)
            vm.pc = 66175
            count = memory.load(cells.pointer(421), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(8714) << count
            vm._write(8830, value, 8, "typed.selector3.q")
            tick(66175)
            vm.pc = 66178
            vm.auxiliary = (0, 48187)
            tick(66178)
            vm.pc = 66183
            count = memory.load(cells.pointer(421), 4)
            if count & 0x80000000 or count >= 64:
                value = 0
            else:
                value = cells.value(8830)
                if count and value == 0x8000000000000000:
                    value -= 1
                value >>= count
            vm._write(8831, value, 8, "typed.selector4.q")
            tick(66183)
            vm.pc = 66187
            value = memory.load(cells.value(85), 8)
            vm._write(8832, value, 8, 'high.load')
            tick(66187)
            vm.pc = 66190
            vm.auxiliary = (0, 705306626)
            tick(66190)
            vm.pc = 66195
            vm._write(8833, memory.load(cells.pointer(8832), 8, signed=True) + memory.load(cells.pointer(8831), 8, signed=True), 8, 'once1.integer')
            tick(66195)
            vm.pc = 66199
            pointer = cells.value(85)
            value = memory.load(cells.pointer(8833), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(66199)
            vm.pc = 66201
            vm._jump(1610)
            continue
        if vm.block == 1641:
            tick(66201)
            vm.pc = 66206
            _convert(vm, 8, 8770, 8834)
            tick(66206)
            _pointer(vm, 66206, 49, 83, 8835, (145, 8834))
            tick(66214)
            vm.pc = 66218
            value = memory.load(cells.value(8835), 1)
            vm._write(8836, value, 4, 'high.load')
            tick(66218)
            _pointer(vm, 66218, 49, 94, 8837, (145, 8834))
            tick(66226)
            vm.pc = 66230
            value = memory.load(cells.value(8837), 1)
            vm._write(8838, value, 4, 'high.load')
            tick(66230)
            vm.pc = 66231
            tick(66231)
            vm.pc = 66234
            vm.auxiliary = (0, 51493)
            tick(66234)
            vm.pc = 66240
            vm._write(8839, memory.load(cells.pointer(8838), 1, signed=True) ^ memory.load(cells.pointer(8836), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(66240)
            vm.pc = 66244
            pointer = cells.value(8837)
            value = memory.load(cells.pointer(8839), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(66244)
            vm.pc = 66247
            vm.auxiliary = (0, 363421697)
            tick(66247)
            vm.pc = 66252
            vm._write(8771, memory.load(cells.pointer(8770), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(66252)
            vm.pc = 66254
            vm._jump(1640)
            continue
        if vm.block == 1619:
            tick(66254)
            _phi(vm, 66254, (8840, 2, 158, 1618, 8841, 1658))
            tick(66261)
            _phi(vm, 66261, (8842, 2, 8691, 1618, 8843, 1658))
            tick(66268)
            _phi(vm, 66268, (8844, 2, 158, 1618, 8845, 1658))
            tick(66275)
            vm.pc = 66279
            value = memory.load(cells.value(139), 4)
            vm._write(8846, value, 4, 'high.load')
            tick(66279)
            vm.pc = 66280
            tick(66280)
            vm.pc = 66283
            vm.auxiliary = (0, 1921880066)
            tick(66283)
            vm.pc = 66288
            vm._write(8847, memory.load(cells.pointer(8846), 4, signed=True) + memory.load(cells.pointer(375), 4, signed=True), 8, 'once1.integer')
            tick(66288)
            vm.pc = 66293
            vm._write(8848, int(cells.value(8844) < cells.value(8847)), 4, 'once18.unsigned_q')
            tick(66293)
            vm.pc = 66297
            vm._jump(1658 if cells.value(8848) != 0 else 1659)
            continue
        if vm.block == 1658:
            tick(66297)
            vm.pc = 66298
            tick(66298)
            vm.pc = 66301
            vm.auxiliary = (0, 45156)
            tick(66301)
            vm.pc = 66306
            vm._write(8849, memory.load(cells.pointer(8844), 4, signed=True) & memory.load(cells.pointer(269), 4, signed=True), 8, 'typed.selector1.q')
            tick(66306)
            vm.pc = 66309
            vm.auxiliary = (0, 64788)
            tick(66309)
            vm.pc = 66315
            vm._write(8850, memory.load(cells.pointer(8849), 4, signed=True) ^ memory.load(cells.pointer(8689), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(66315)
            vm.pc = 66318
            vm.auxiliary = (0, 1007620612)
            tick(66318)
            vm.pc = 66323
            vm._write(8851, memory.load(cells.pointer(8850), 4, signed=True) * memory.load(cells.pointer(1093), 4, signed=True), 8, 'once0.integer')
            tick(66323)
            vm.pc = 66328
            vm._write(8852, memory.load(cells.pointer(8851), 4, signed=True) | memory.load(cells.pointer(269), 4, signed=True), 8, 'L15.binary_q')
            tick(66328)
            vm.pc = 66331
            vm.auxiliary = (0, 813486596)
            tick(66331)
            vm.pc = 66336
            vm._write(8853, memory.load(cells.pointer(8852), 4, signed=True) * memory.load(cells.pointer(8844), 4, signed=True), 8, 'once0.integer')
            tick(66336)
            vm.pc = 66339
            vm.auxiliary = (0, 1364553730)
            tick(66339)
            vm.pc = 66344
            vm._write(8843, memory.load(cells.pointer(8842), 4, signed=True) + memory.load(cells.pointer(8853), 4, signed=True), 8, 'once1.integer')
            tick(66344)
            vm.pc = 66349
            cells.copy_q_clear_owned(8843, 8854)
            tick(66349)
            _pointer(vm, 66349, 1, 8346, 8855, (8854,))
            tick(66356)
            vm.pc = 66360
            value = memory.load(cells.value(8855), 1)
            vm._write(8856, value, 4, 'high.load')
            tick(66360)
            vm.pc = 66365
            _convert(vm, 4, 8856, 8857)
            tick(66365)
            vm.pc = 66370
            vm._write(8858, memory.load(cells.pointer(8840), 4, signed=True) & memory.load(cells.pointer(873), 4, signed=True), 8, 'L13.binary_q')
            tick(66370)
            vm.pc = 66373
            vm.auxiliary = (0, 7541)
            tick(66373)
            vm.pc = 66379
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(8841, memory.load(cells.pointer(8858), 4, signed=True) ^ memory.load(cells.pointer(8857), 4, signed=True), 8, 'typed.selector5.q')
            tick(66379)
            vm.pc = 66384
            vm._write(8859, cells.value(8841) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(66384)
            vm.pc = 66388
            pointer = cells.value(8855)
            value = memory.load(cells.pointer(8859), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(66388)
            vm.pc = 66391
            vm.auxiliary = (0, 2017640450)
            tick(66391)
            vm.pc = 66396
            vm._write(8845, memory.load(cells.pointer(8844), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(66396)
            vm.pc = 66398
            vm._jump(1619)
            continue
        if vm.block == 1659:
            tick(66398)
            vm.pc = 66402
            pointer = cells.value(139)
            value = memory.load(cells.pointer(8847), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(66402)
            vm.pc = 66413
            _tail_host(vm, 66402, 8860, (5, 6, 8346, 8861, 1, 2), 207, None)
            tick(66413)
            vm.pc = 66417
            value = memory.load(cells.value(139), 4)
            vm._write(8862, value, 4, 'high.load')
            tick(66417)
            vm.pc = 66422
            _convert(vm, 8, 8862, 8863)
            tick(66422)
            vm.pc = 66427
            vm._write(8864, memory.load(cells.pointer(8863), 8, signed=True) & memory.load(cells.pointer(1732), 8, signed=True), 8, 'L13.binary_q')
            tick(66427)
            vm.pc = 66429
            vm._jump(1660)
            continue
        if vm.block == 1660:
            tick(66429)
            _phi(vm, 66429, (8865, 2, 145, 1659, 8866, 1661))
            tick(66436)
            vm.pc = 66441
            vm._write(8867, int(cells.value(8865) < cells.value(8864)), 4, 'once18.unsigned_q')
            tick(66441)
            vm.pc = 66445
            vm._jump(1661 if cells.value(8867) != 0 else 1662)
            continue
        if vm.block == 1661:
            tick(66445)
            _pointer(vm, 66445, 1, 8346, 8868, (8865,))
            tick(66452)
            vm.pc = 66457
            cells.copy_q_clear_owned(8868, 8869)
            tick(66457)
            vm.pc = 66461
            value = memory.load(cells.value(8869), 4)
            vm._write(8870, value, 4, 'high.load')
            tick(66461)
            _pointer(vm, 66461, 1, 7, 8871, (8865,))
            tick(66468)
            vm.pc = 66473
            cells.copy_q_clear_owned(8871, 8872)
            tick(66473)
            vm.pc = 66477
            pointer = cells.value(8872)
            value = memory.load(cells.pointer(8870), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(66477)
            vm.pc = 66478
            tick(66478)
            vm.pc = 66481
            vm.auxiliary = (0, 767430658)
            tick(66481)
            vm.pc = 66486
            vm._write(8866, memory.load(cells.pointer(8865), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(66486)
            vm.pc = 66488
            vm._jump(1660)
            continue
        if vm.block == 1662:
            tick(66488)
            _phi(vm, 66488, (8873, 2, 8874, 1663, 8864, 1660))
            tick(66495)
            vm.pc = 66500
            vm._write(8875, int(cells.value(8873) < cells.value(8863)), 4, 'once18.unsigned_q')
            tick(66500)
            vm.pc = 66504
            vm._jump(1663 if cells.value(8875) != 0 else 1664)
            continue
        if vm.block == 1663:
            tick(66504)
            _pointer(vm, 66504, 1, 8346, 8876, (8873,))
            tick(66511)
            vm.pc = 66515
            value = memory.load(cells.value(8876), 1)
            vm._write(8877, value, 4, 'high.load')
            tick(66515)
            _pointer(vm, 66515, 1, 7, 8878, (8873,))
            tick(66522)
            vm.pc = 66526
            pointer = cells.value(8878)
            value = memory.load(cells.pointer(8877), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(66526)
            vm.pc = 66527
            tick(66527)
            vm.pc = 66530
            vm.auxiliary = (0, 1111830530)
            tick(66530)
            vm.pc = 66535
            vm._write(8874, memory.load(cells.pointer(8873), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(66535)
            vm.pc = 66537
            vm._jump(1662)
            continue
        if vm.block == 1664:
            tick(66537)
            vm.pc = 66541
            value = memory.load(cells.value(139), 4)
            vm._write(8879, value, 4, 'high.load')
            tick(66541)
            vm.pc = 66545
            pointer = cells.value(8)
            value = memory.load(cells.pointer(8879), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(66545)
            vm.pc = 66547
            vm._jump(3)
            continue
        if vm.block == 3:
            tick(66547)
            vm.pc = 66548
            vm.halted = True
            continue
        raise PrimarySemanticUnavailable('independent Main literal tail left its source-bound blocks')
