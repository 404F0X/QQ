from hashlib import sha256
from threading import get_ident

from .primary_main_material_getter import _pair_control, _phi, _pointer, _single_control
from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable


ENTRY = (38470, 876, 875, False)
EXIT = (39468, 910, 908, False)


def execute_primary_main_material_merge(vm, *, charge=None):
    if (type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != MAIN_SHA256 or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) != ENTRY):
        raise PrimarySemanticUnavailable('independent post-AS merge requires its fixed Main entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            type(owner) is not dict or owner.get('vm') is not vm or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._execute_thread != get_ident() or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            len(runtime._program_calls) != 1 or runtime._program_calls[0]['name'] != 'main' or
            runtime._program_calls[0]['hosts'] is not None):
        raise PrimarySemanticUnavailable('independent post-AS merge requires the current Main owner without replay')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent post-AS merge cannot enter a stopped or pending body')
    state = dict(entryWord=38470, exitWord=39468, backend='DIRECT_MAIN_POST_AS_MATERIAL_MERGE',
                 referenceRecordCount=0, completed=False, traceComplete=False,
                 subsequentPublicationBackend='GENERIC_MAIN_39468_TO_39948', completeIndependentMain=False)
    vm.primary_main_material_merge_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if charge is not None:
            charge()
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    _merge_material(vm, tick)
    state['completed'] = True
    return state



def _merge_material(vm, tick):
    cells, memory = vm.cells, vm.memory
    while vm.pc != 39468:
        if vm.block == 876:
            tick(38470)
            _phi(vm, 38470, (5194, 2, 145, 875, 5195, 877))
            tick(38477)
            vm.pc = 38482
            vm._write(5196, int(cells.value(5194) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(38482)
            vm.pc = 38486
            vm._jump(877 if cells.value(5196) != 0 else 878)
            continue
        if vm.block == 877:
            tick(38486)
            _pointer(vm, 38486, 194, 4391, 5197, (145, 5194))
            tick(38494)
            vm.pc = 38498
            value = memory.load(cells.value(5197), 8)
            vm._write(5198, value, 8, 'high.load')
            tick(38498)
            _pointer(vm, 38498, 37, 47, 5199, (145, 5198))
            tick(38506)
            vm.pc = 38510
            pointer = cells.value(5199)
            value = memory.load(cells.pointer(354), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(38510)
            vm.pc = 38511
            tick(38511)
            vm.pc = 38514
            vm.auxiliary = (0, 1420423169)
            tick(38514)
            vm.pc = 38519
            vm._write(5195, memory.load(cells.pointer(5194), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38519)
            vm.pc = 38521
            vm._jump(876)
            continue
        if vm.block == 878:
            tick(38521)
            _phi(vm, 38521, (5200, 2, 5201, 879, 145, 876))
            tick(38528)
            vm.pc = 38533
            vm._write(5202, int(cells.value(5200) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(38533)
            vm.pc = 38537
            vm._jump(880 if cells.value(5202) != 0 else 881)
            continue
        if vm.block == 880:
            tick(38537)
            _pointer(vm, 38537, 37, 47, 5203, (145, 5200))
            tick(38545)
            vm.pc = 38549
            value = memory.load(cells.value(5203), 1)
            vm._write(5204, value, 4, 'high.load')
            tick(38549)
            vm.pc = 38550
            tick(38550)
            vm.pc = 38553
            vm.auxiliary = (0, 1857166451)
            tick(38553)
            vm.pc = 38558
            vm._write(5205, int(memory.load(cells.pointer(5204), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(38558)
            vm.pc = 38562
            vm._jump(882 if cells.value(5205) != 0 else 879)
            continue
        if vm.block == 882:
            tick(38562)
            _pointer(vm, 38562, 1, 5182, 5206, (203,))
            tick(38569)
            vm.pc = 38573
            value = memory.load(cells.value(5206), 1)
            vm._write(5207, value, 4, 'high.load')
            tick(38573)
            _pointer(vm, 38573, 1, 5182, 5208, (4409,))
            tick(38580)
            vm.pc = 38584
            value = memory.load(cells.value(5208), 1)
            vm._write(5209, value, 4, 'high.load')
            tick(38584)
            vm.pc = 38585
            tick(38585)
            vm.pc = 38588
            vm.auxiliary = (0, 7967)
            tick(38588)
            vm.pc = 38594
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5210, memory.load(cells.pointer(5207), 1, signed=True) ^ memory.load(cells.pointer(5209), 1, signed=True), 8, 'typed.selector5.q')
            tick(38594)
            vm.pc = 38599
            vm._write(5211, cells.value(5200) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(38599)
            vm.pc = 38602
            vm.auxiliary = (0, 44126)
            tick(38602)
            vm.pc = 38608
            vm._write(5212, memory.load(cells.pointer(5210), 1, signed=True) ^ memory.load(cells.pointer(5211), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(38608)
            _pointer(vm, 38608, 1, 5182, 5213, (5200,))
            tick(38615)
            vm.pc = 38619
            pointer = cells.value(5213)
            value = memory.load(cells.pointer(5212), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(38619)
            vm.pc = 38621
            vm._jump(879)
            continue
        if vm.block == 879:
            tick(38621)
            vm.pc = 38622
            tick(38622)
            vm.pc = 38625
            vm.auxiliary = (0, 862154754)
            tick(38625)
            vm.pc = 38630
            vm._write(5201, memory.load(cells.pointer(5200), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38630)
            vm.pc = 38632
            vm._jump(878)
            continue
        if vm.block == 881:
            tick(38632)
            _pointer(vm, 38632, 37, 55, 5214, (145, 145))
            tick(38640)
            vm.pc = 38642
            vm._jump(883)
            continue
        if vm.block == 883:
            tick(38642)
            _phi(vm, 38642, (5215, 2, 145, 881, 5216, 884))
            tick(38649)
            vm.pc = 38654
            vm._write(5217, int(cells.value(5215) < cells.value(4409)), 4, 'once18.unsigned_q')
            tick(38654)
            vm.pc = 38658
            vm._jump(884 if cells.value(5217) != 0 else 885)
            continue
        if vm.block == 884:
            tick(38658)
            _pointer(vm, 38658, 1, 5150, 5218, (5215,))
            tick(38665)
            vm.pc = 38670
            cells.copy_q_clear_owned(5218, 5219)
            tick(38670)
            vm.pc = 38674
            value = memory.load(cells.value(5219), 4)
            vm._write(5220, value, 4, 'high.load')
            tick(38674)
            _pointer(vm, 38674, 1, 5214, 5221, (5215,))
            tick(38681)
            vm.pc = 38686
            cells.copy_q_clear_owned(5221, 5222)
            tick(38686)
            vm.pc = 38690
            pointer = cells.value(5222)
            value = memory.load(cells.pointer(5220), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(38690)
            vm.pc = 38691
            tick(38691)
            vm.pc = 38694
            vm.auxiliary = (0, 1459851266)
            tick(38694)
            vm.pc = 38699
            vm._write(5216, memory.load(cells.pointer(5215), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(38699)
            vm.pc = 38701
            vm._jump(883)
            continue
        if vm.block == 885:
            tick(38701)
            _phi(vm, 38701, (5223, 2, 5224, 886, 4409, 883))
            tick(38708)
            vm.pc = 38713
            vm._write(5225, int(cells.value(5223) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(38713)
            vm.pc = 38717
            vm._jump(886 if cells.value(5225) != 0 else 887)
            continue
        if vm.block == 886:
            tick(38717)
            _pointer(vm, 38717, 1, 5150, 5226, (5223,))
            tick(38724)
            vm.pc = 38728
            value = memory.load(cells.value(5226), 1)
            vm._write(5227, value, 4, 'high.load')
            tick(38728)
            _pointer(vm, 38728, 1, 5214, 5228, (5223,))
            tick(38735)
            vm.pc = 38739
            pointer = cells.value(5228)
            value = memory.load(cells.pointer(5227), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(38739)
            vm.pc = 38740
            tick(38740)
            vm.pc = 38743
            vm.auxiliary = (0, 1123385346)
            tick(38743)
            vm.pc = 38748
            vm._write(5224, memory.load(cells.pointer(5223), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38748)
            vm.pc = 38750
            vm._jump(885)
            continue
        if vm.block == 887:
            tick(38750)
            vm.pc = 38752
            vm._jump(888)
            continue
        if vm.block == 888:
            tick(38752)
            _phi(vm, 38752, (5229, 2, 145, 887, 5230, 889))
            tick(38759)
            vm.pc = 38764
            vm._write(5231, int(cells.value(5229) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(38764)
            vm.pc = 38768
            vm._jump(889 if cells.value(5231) != 0 else 890)
            continue
        if vm.block == 889:
            tick(38768)
            _pointer(vm, 38768, 194, 4391, 5232, (145, 5229))
            tick(38776)
            vm.pc = 38780
            value = memory.load(cells.value(5232), 8)
            vm._write(5233, value, 8, 'high.load')
            tick(38780)
            _pointer(vm, 38780, 1, 5150, 5234, (5233,))
            tick(38787)
            vm.pc = 38791
            value = memory.load(cells.value(5234), 1)
            vm._write(5235, value, 4, 'high.load')
            tick(38791)
            _pointer(vm, 38791, 1, 5182, 5236, (5233,))
            tick(38798)
            vm.pc = 38802
            value = memory.load(cells.value(5236), 1)
            vm._write(5237, value, 4, 'high.load')
            tick(38802)
            vm.pc = 38803
            tick(38803)
            vm.pc = 38806
            vm.auxiliary = (0, 39476)
            tick(38806)
            vm.pc = 38812
            vm._write(5238, memory.load(cells.pointer(5237), 1, signed=True) ^ memory.load(cells.pointer(5235), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(38812)
            _pointer(vm, 38812, 1, 5214, 5239, (5233,))
            tick(38819)
            vm.pc = 38823
            pointer = cells.value(5239)
            value = memory.load(cells.pointer(5238), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(38823)
            vm.pc = 38826
            vm.auxiliary = (0, 363528193)
            tick(38826)
            vm.pc = 38831
            vm._write(5230, memory.load(cells.pointer(5229), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38831)
            vm.pc = 38833
            vm._jump(888)
            continue
        if vm.block == 890:
            tick(38833)
            vm.pc = 38835
            vm._jump(891)
            continue
        if vm.block == 891:
            tick(38835)
            _phi(vm, 38835, (5240, 2, 145, 890, 5241, 892))
            tick(38842)
            vm.pc = 38847
            vm._write(5242, int(cells.value(5240) < cells.value(4409)), 4, 'once18.unsigned_q')
            tick(38847)
            vm.pc = 38851
            vm._jump(892 if cells.value(5242) != 0 else 893)
            continue
        if vm.block == 892:
            tick(38851)
            _pointer(vm, 38851, 1, 5118, 5243, (5240,))
            tick(38858)
            vm.pc = 38863
            cells.copy_q_clear_owned(5243, 5244)
            tick(38863)
            vm.pc = 38867
            value = memory.load(cells.value(5244), 4)
            vm._write(5245, value, 4, 'high.load')
            tick(38867)
            _pointer(vm, 38867, 1, 5000, 5246, (5240,))
            tick(38874)
            vm.pc = 38879
            cells.copy_q_clear_owned(5246, 5247)
            tick(38879)
            vm.pc = 38883
            pointer = cells.value(5247)
            value = memory.load(cells.pointer(5245), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(38883)
            vm.pc = 38884
            tick(38884)
            vm.pc = 38887
            vm.auxiliary = (0, 1622765569)
            tick(38887)
            vm.pc = 38892
            vm._write(5241, memory.load(cells.pointer(5240), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(38892)
            vm.pc = 38894
            vm._jump(891)
            continue
        if vm.block == 893:
            tick(38894)
            _phi(vm, 38894, (5248, 2, 5249, 894, 4409, 891))
            tick(38901)
            vm.pc = 38906
            vm._write(5250, int(cells.value(5248) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(38906)
            vm.pc = 38910
            vm._jump(894 if cells.value(5250) != 0 else 895)
            continue
        if vm.block == 894:
            tick(38910)
            _pointer(vm, 38910, 1, 5118, 5251, (5248,))
            tick(38917)
            vm.pc = 38921
            value = memory.load(cells.value(5251), 1)
            vm._write(5252, value, 4, 'high.load')
            tick(38921)
            _pointer(vm, 38921, 1, 5000, 5253, (5248,))
            tick(38928)
            vm.pc = 38932
            pointer = cells.value(5253)
            value = memory.load(cells.pointer(5252), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(38932)
            vm.pc = 38933
            tick(38933)
            vm.pc = 38936
            vm.auxiliary = (0, 1218560002)
            tick(38936)
            vm.pc = 38941
            vm._write(5249, memory.load(cells.pointer(5248), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(38941)
            vm.pc = 38943
            vm._jump(893)
            continue
        if vm.block == 895:
            tick(38943)
            vm.pc = 38945
            vm._jump(896)
            continue
        if vm.block == 896:
            tick(38945)
            _phi(vm, 38945, (5254, 2, 145, 895, 5255, 897))
            tick(38952)
            vm.pc = 38957
            vm._write(5256, int(cells.value(5254) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(38957)
            vm.pc = 38961
            vm._jump(897 if cells.value(5256) != 0 else 898)
            continue
        if vm.block == 897:
            tick(38961)
            _pointer(vm, 38961, 194, 4391, 5257, (145, 5254))
            tick(38969)
            vm.pc = 38973
            value = memory.load(cells.value(5257), 8)
            vm._write(5258, value, 8, 'high.load')
            tick(38973)
            _pointer(vm, 38973, 1, 5118, 5259, (5258,))
            tick(38980)
            vm.pc = 38984
            value = memory.load(cells.value(5259), 1)
            vm._write(5260, value, 4, 'high.load')
            tick(38984)
            _pointer(vm, 38984, 1, 5214, 5261, (5258,))
            tick(38991)
            vm.pc = 38995
            value = memory.load(cells.value(5261), 1)
            vm._write(5262, value, 4, 'high.load')
            tick(38995)
            vm.pc = 38996
            tick(38996)
            vm.pc = 38999
            vm.auxiliary = (0, 25480)
            tick(38999)
            vm.pc = 39004
            vm._write(5263, memory.load(cells.pointer(5260), 1, signed=True) | memory.load(cells.pointer(5262), 1, signed=True), 8, 'typed.selector2.q')
            tick(39004)
            _pointer(vm, 39004, 1, 5000, 5264, (5258,))
            tick(39011)
            vm.pc = 39015
            pointer = cells.value(5264)
            value = memory.load(cells.pointer(5263), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(39015)
            vm.pc = 39018
            vm.auxiliary = (0, 1870946305)
            tick(39018)
            vm.pc = 39023
            vm._write(5255, memory.load(cells.pointer(5254), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(39023)
            vm.pc = 39025
            vm._jump(896)
            continue
        if vm.block == 898:
            tick(39025)
            vm.pc = 39027
            vm._jump(899)
            continue
        if vm.block == 899:
            tick(39027)
            _phi(vm, 39027, (5265, 2, 145, 898, 5266, 900))
            tick(39034)
            vm.pc = 39039
            vm._write(5267, int(cells.value(5265) < cells.value(178)), 4, 'once18.unsigned_q')
            tick(39039)
            vm.pc = 39043
            vm._jump(901 if cells.value(5267) != 0 else 902)
            continue
        if vm.block == 902:
            tick(39043)
            vm.pc = 39045
            vm._jump(903)
            continue
        if vm.block == 903:
            tick(39045)
            _phi(vm, 39045, (5268, 2, 145, 902, 5269, 904))
            tick(39052)
            vm.pc = 39057
            vm._write(5270, int(cells.value(5268) < cells.value(4409)), 4, 'once18.unsigned_q')
            tick(39057)
            vm.pc = 39061
            vm._jump(904 if cells.value(5270) != 0 else 905)
            continue
        if vm.block == 904:
            tick(39061)
            _pointer(vm, 39061, 1, 5000, 5271, (5268,))
            tick(39068)
            vm.pc = 39073
            cells.copy_q_clear_owned(5271, 5272)
            tick(39073)
            vm.pc = 39077
            value = memory.load(cells.value(5272), 4)
            vm._write(5273, value, 4, 'high.load')
            tick(39077)
            _pointer(vm, 39077, 1, 5000, 5274, (5268,))
            tick(39084)
            vm.pc = 39089
            cells.copy_q_clear_owned(5274, 5275)
            tick(39089)
            vm.pc = 39093
            pointer = cells.value(5275)
            value = memory.load(cells.pointer(5273), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(39093)
            vm.pc = 39094
            tick(39094)
            vm.pc = 39097
            vm.auxiliary = (0, 1425694721)
            tick(39097)
            vm.pc = 39102
            vm._write(5269, memory.load(cells.pointer(5268), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(39102)
            vm.pc = 39104
            vm._jump(903)
            continue
        if vm.block == 905:
            tick(39104)
            _phi(vm, 39104, (5276, 2, 5277, 906, 4409, 903))
            tick(39111)
            vm.pc = 39116
            vm._write(5278, int(cells.value(5276) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(39116)
            vm.pc = 39120
            vm._jump(906 if cells.value(5278) != 0 else 907)
            continue
        if vm.block == 906:
            tick(39120)
            _pointer(vm, 39120, 1, 5000, 5279, (5276,))
            tick(39127)
            vm.pc = 39131
            value = memory.load(cells.value(5279), 1)
            vm._write(5280, value, 4, 'high.load')
            tick(39131)
            _pointer(vm, 39131, 1, 5000, 5281, (5276,))
            tick(39138)
            vm.pc = 39142
            pointer = cells.value(5281)
            value = memory.load(cells.pointer(5280), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(39142)
            vm.pc = 39143
            tick(39143)
            vm.pc = 39146
            vm.auxiliary = (0, 356995074)
            tick(39146)
            vm.pc = 39151
            vm._write(5277, memory.load(cells.pointer(5276), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(39151)
            vm.pc = 39153
            vm._jump(905)
            continue
        if vm.block == 907:
            tick(39153)
            vm.pc = 39155
            vm._jump(908)
            continue
        if vm.block == 908:
            tick(39155)
            _phi(vm, 39155, (5282, 2, 145, 907, 5283, 909))
            tick(39162)
            vm.pc = 39167
            vm._write(5284, int(cells.value(5282) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(39167)
            vm.pc = 39171
            vm._jump(909 if cells.value(5284) != 0 else 910)
            continue
        if vm.block == 909:
            tick(39171)
            _pointer(vm, 39171, 194, 4391, 5285, (145, 5282))
            tick(39179)
            vm.pc = 39183
            value = memory.load(cells.value(5285), 8)
            vm._write(5286, value, 8, 'high.load')
            tick(39183)
            _pointer(vm, 39183, 1, 5000, 5287, (5286,))
            tick(39190)
            vm.pc = 39194
            value = memory.load(cells.value(5287), 1)
            vm._write(5288, value, 4, 'high.load')
            tick(39194)
            _pointer(vm, 39194, 1, 5182, 5289, (5286,))
            tick(39201)
            vm.pc = 39205
            value = memory.load(cells.value(5289), 1)
            vm._write(5290, value, 4, 'high.load')
            tick(39205)
            vm.pc = 39206
            tick(39206)
            vm.pc = 39209
            vm.auxiliary = (0, 7703)
            tick(39209)
            vm.pc = 39215
            vm._write(5291, memory.load(cells.pointer(5290), 1, signed=True) ^ memory.load(cells.pointer(5288), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(39215)
            _pointer(vm, 39215, 1, 5000, 5292, (5286,))
            tick(39222)
            vm.pc = 39226
            pointer = cells.value(5292)
            value = memory.load(cells.pointer(5291), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(39226)
            vm.pc = 39229
            vm.auxiliary = (0, 1064558593)
            tick(39229)
            vm.pc = 39234
            vm._write(5283, memory.load(cells.pointer(5282), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(39234)
            vm.pc = 39236
            vm._jump(908)
            continue
        if vm.block == 901:
            tick(39236)
            _pointer(vm, 39236, 7, 4977, 5293, (5265,))
            tick(39243)
            vm.pc = 39247
            value = memory.load(cells.value(5293), 8)
            vm._write(5294, value, 8, 'high.load')
            tick(39247)
            vm.pc = 39251
            pointer = cells.value(38)
            value = memory.load(cells.pointer(4560), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(39251)
            vm.pc = 39253
            vm._jump(911)
            continue
        if vm.block == 911:
            tick(39253)
            _phi(vm, 39253, (5295, 2, 145, 901, 5296, 912))
            tick(39260)
            vm.pc = 39265
            vm._write(5297, int(cells.value(5295) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(39265)
            vm.pc = 39269
            vm._jump(912 if cells.value(5297) != 0 else 913)
            continue
        if vm.block == 912:
            tick(39269)
            _pointer(vm, 39269, 1, 5000, 5298, (5295,))
            tick(39276)
            vm.pc = 39280
            value = memory.load(cells.value(5298), 1)
            vm._write(5299, value, 4, 'high.load')
            tick(39280)
            _pointer(vm, 39280, 1, 5000, 5300, (5295,))
            tick(39287)
            vm.pc = 39291
            pointer = cells.value(5300)
            value = memory.load(cells.pointer(5299), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(39291)
            vm.pc = 39295
            value = memory.load(cells.value(38), 1)
            vm._write(5301, value, 4, 'high.load')
            tick(39295)
            vm.pc = 39300
            vm._write(5302, memory.load(cells.pointer(5299), 1, signed=True) ^ memory.load(cells.pointer(5301), 1, signed=True), 8, 'L14.binary_q')
            tick(39300)
            vm.pc = 39304
            pointer = cells.value(5300)
            value = memory.load(cells.pointer(5302), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(39304)
            vm.pc = 39308
            value = memory.load(cells.value(38), 1)
            vm._write(5303, value, 4, 'high.load')
            tick(39308)
            vm.pc = 39309
            tick(39309)
            vm.pc = 39312
            vm.auxiliary = (0, 44390)
            tick(39312)
            vm.pc = 39318
            vm._write(5304, memory.load(cells.pointer(5302), 1, signed=True) ^ memory.load(cells.pointer(5303), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(39318)
            vm.pc = 39322
            pointer = cells.value(5300)
            value = memory.load(cells.pointer(5304), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(39322)
            vm.pc = 39325
            vm.auxiliary = (0, 607559681)
            tick(39325)
            vm.pc = 39330
            vm._write(5296, memory.load(cells.pointer(5295), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(39330)
            vm.pc = 39332
            vm._jump(911)
            continue
        if vm.block == 913:
            tick(39332)
            vm.pc = 39334
            vm._jump(914)
            continue
        if vm.block == 914:
            tick(39334)
            _phi(vm, 39334, (5305, 2, 145, 913, 5306, 915))
            tick(39341)
            vm.pc = 39346
            vm._write(5307, int(cells.value(5305) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(39346)
            vm.pc = 39350
            vm._jump(915 if cells.value(5307) != 0 else 900)
            continue
        if vm.block == 915:
            tick(39350)
            vm.pc = 39351
            tick(39351)
            vm.pc = 39354
            vm.auxiliary = (0, 9357)
            tick(39354)
            _single_control(vm)
            vm.pc = 39359
            count = memory.load(cells.pointer(169), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(5305) << count
            vm._write(5308, value, 8, "typed.selector3.q")
            tick(39359)
            vm.pc = 39364
            value = memory.load(cells.pointer(5294), 8)
            count = memory.load(cells.pointer(5308), 1)
            vm._write(5309, value >> (count & 63), 8, 'once8.logical_shift')
            tick(39364)
            vm.pc = 39369
            vm._write(5310, cells.value(5309) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39369)
            _pointer(vm, 39369, 194, 4391, 5311, (145, 5305))
            tick(39377)
            vm.pc = 39381
            value = memory.load(cells.value(5311), 8)
            vm._write(5312, value, 8, 'high.load')
            tick(39381)
            _pointer(vm, 39381, 1, 5000, 5313, (5312,))
            tick(39388)
            vm.pc = 39392
            value = memory.load(cells.value(5313), 1)
            vm._write(5314, value, 4, 'high.load')
            tick(39392)
            vm.pc = 39397
            vm._write(5315, cells.value(5309) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(39397)
            vm.pc = 39400
            vm.auxiliary = (0, 35150)
            tick(39400)
            vm.pc = 39406
            vm._write(5316, memory.load(cells.pointer(5315), 1, signed=True) ^ memory.load(cells.pointer(4582), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(39406)
            vm.pc = 39409
            vm.auxiliary = (0, 30294)
            tick(39409)
            vm.pc = 39414
            vm._write(5317, memory.load(cells.pointer(5314), 1, signed=True) & memory.load(cells.pointer(5316), 1, signed=True), 8, 'typed.selector1.q')
            tick(39414)
            vm.pc = 39417
            vm.auxiliary = (0, 56341)
            tick(39417)
            vm.pc = 39423
            vm._write(5318, memory.load(cells.pointer(5314), 1, signed=True) ^ memory.load(cells.pointer(4582), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(39423)
            vm.pc = 39428
            vm._write(5319, memory.load(cells.pointer(5310), 1, signed=True) & memory.load(cells.pointer(5318), 1, signed=True), 8, 'L13.binary_q')
            tick(39428)
            vm.pc = 39431
            vm.auxiliary = (0, 5337)
            tick(39431)
            vm.pc = 39436
            vm._write(5320, memory.load(cells.pointer(5317), 1, signed=True) | memory.load(cells.pointer(5319), 1, signed=True), 8, 'typed.selector2.q')
            tick(39436)
            _pointer(vm, 39436, 1, 5000, 5321, (5312,))
            tick(39443)
            vm.pc = 39447
            pointer = cells.value(5321)
            value = memory.load(cells.pointer(5320), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(39447)
            vm.pc = 39450
            vm.auxiliary = (0, 1621307394)
            tick(39450)
            vm.pc = 39455
            vm._write(5306, memory.load(cells.pointer(5305), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(39455)
            vm.pc = 39457
            vm._jump(914)
            continue
        if vm.block == 900:
            tick(39457)
            vm.pc = 39458
            tick(39458)
            vm.pc = 39461
            vm.auxiliary = (0, 1521324034)
            tick(39461)
            vm.pc = 39466
            vm._write(5266, memory.load(cells.pointer(5265), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(39466)
            vm.pc = 39468
            vm._jump(899)
            continue
        raise PrimarySemanticUnavailable('independent post-AS merge left its source-bound blocks')
