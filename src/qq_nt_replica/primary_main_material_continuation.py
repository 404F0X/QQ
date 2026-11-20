from hashlib import sha256
from threading import get_ident

from .primary_main_material_getter import _convert, _equal, _pair_control, _phi, _pointer, _single_control, _switch
from .primary_main_mix import MAIN_SHA256
from .primary_vm import PrimaryVM, PrimaryProgramLimit, PrimarySemanticUnavailable


CONTINUATION_ENTRIES = frozenset(((41119, 940, 937, False), (41128, 940, 937, False),
                                  (45040, 1046, 1059, False), (45040, 1046, 1054, False)))


def execute_primary_main_material_continuation(vm, *, charge=None):
    if (type(vm) is not PrimaryVM or sha256(vm.program.raw).hexdigest() != MAIN_SHA256 or
            (vm.pc, vm.block, vm.predecessor, vm.initial_block) not in CONTINUATION_ENTRIES):
        raise PrimarySemanticUnavailable('independent continuation requires its fixed Main entry')
    runtime = vm.runtime
    owner = getattr(runtime, '_active_main', None)
    if (runtime is None or vm.memory is not runtime.memory or vm.image_base != runtime.image_base or
            type(owner) is not dict or owner.get('vm') is not vm or owner.get('thread') != get_ident() or
            owner.get('generation') != runtime._main_generation or runtime._execute_thread != get_ident() or
            runtime._active_failed or getattr(runtime, '_consumed_mgf', None) is not None or
            len(runtime._program_calls) != 1 or runtime._program_calls[0]['name'] != 'main' or
            runtime._program_calls[0]['hosts'] is not None):
        raise PrimarySemanticUnavailable('independent continuation requires the current Main owner without replay')
    if vm.halted or vm.abort_reason is not None or any(getattr(vm, name) is not None for name in
            ('pending_once10', 'pending_once9', 'pending_l26', 'pending_variadic', 'pending_native',
             'private_iv_native_pending')):
        raise PrimarySemanticUnavailable('independent continuation cannot enter a stopped or pending body')
    state = dict(entryWord=vm.pc, exitWord=None, backend='DIRECT_MAIN_MATERIAL_CONTINUATION',
                 referenceRecordCount=0, completed=False, traceComplete=False,
                 completeIndependentMain=False, continuationComplete=False, yieldedMix=False,
                 providerBackend='EXISTING_DIRECT_MATERIAL_BLOCK', mixBackend='EXISTING_DIRECT_24_RECORD_MIX')
    vm.primary_main_material_continuation_state = state
    def tick(word):
        if vm.abort_reason is not None:
            raise PrimaryProgramLimit('active VM was aborted: ' + vm.abort_reason)
        if charge is not None:
            charge()
        state['referenceRecordCount'] += 1
        vm.pc = word + 1
    _material_continuation(vm, tick)
    state.update(exitWord=vm.pc, completed=True, continuationComplete=vm.pc == 45584, yieldedMix=vm.pc == 44933)
    return state


def _continuation_host(vm, word, callee, arguments, signature, destination):
    address = vm.cells.value(callee)
    expected = 0x2DE4C3B if word == 41119 else 0x2DE8580
    if address != vm.image_base + expected:
        raise PrimarySemanticUnavailable('independent continuation requires its fixed source host binding')
    vm.host_calls.append((word, address, arguments, signature))
    from .primary_sign import _invoke_host
    result = _invoke_host(vm, address, arguments, signature,
                          argument_types=vm.program.type(signature).parameters[3:])
    if destination is not None:
        vm._write(destination, result, 8, 'high.native_result_q')



def _material_continuation(vm, tick):
    cells, memory = vm.cells, vm.memory
    while vm.pc not in (44933, 45584):
        if vm.block == 940:
            if vm.pc == 41119:
                tick(41119)
                vm.pc = 41128
                _continuation_host(vm, 41119, 2176, (354, 269, 311, 51), 158, None)
            tick(41128)
            vm.pc = 41133
            cells.copy_q_clear_owned(49, 5556)
            tick(41133)
            _pointer(vm, 41133, 41, 69, 5557, (145, 145))
            tick(41141)
            _pointer(vm, 41141, 41, 70, 5558, (145, 145))
            tick(41149)
            vm.pc = 41154
            cells.copy_q_clear_owned(50, 5559)
            tick(41154)
            vm.pc = 41158
            pointer = cells.value(50)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(41158)
            _pointer(vm, 41158, 11, 51, 5560, (145, 158))
            tick(41166)
            vm.pc = 41170
            value = memory.load(cells.value(5560), 8)
            vm._write(5561, value, 8, 'high.load')
            tick(41170)
            vm.pc = 41174
            pointer = cells.value(49)
            value = memory.load(cells.pointer(5561), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(41174)
            _pointer(vm, 41174, 11, 51, 5562, (145, 269))
            tick(41182)
            vm.pc = 41186
            value = memory.load(cells.value(5562), 1)
            vm._write(5563, value, 4, 'high.load')
            tick(41186)
            _pointer(vm, 41186, 11, 51, 5564, (145, 311))
            tick(41194)
            vm.pc = 41198
            value = memory.load(cells.value(5564), 1)
            vm._write(5565, value, 4, 'high.load')
            tick(41198)
            vm.pc = 41203
            _convert(vm, 4, 5565, 5566)
            tick(41203)
            _switch(vm, 41203, (5565, 948, 4, 354, 949, 369, 949, 152, 949, 2188, 949))
            continue
        if vm.block == 949:
            tick(41215)
            vm.pc = 41216
            tick(41216)
            vm.pc = 41219
            vm.auxiliary = (0, 177347315)
            tick(41219)
            vm.pc = 41224
            vm._write(5567, int(memory.load(cells.pointer(5563), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(41224)
            vm.pc = 41228
            vm._jump(948 if cells.value(5567) != 0 else 950)
            continue
        if vm.block == 950:
            tick(41228)
            vm.pc = 41233
            _convert(vm, 8, 5565, 5568)
            tick(41233)
            _pointer(vm, 41233, 41, 69, 5569, (145, 145))
            tick(41241)
            vm.pc = 41242
            tick(41242)
            vm.pc = 41245
            vm.auxiliary = (0, 54884)
            tick(41245)
            vm.pc = 41250
            vm._write(5570, memory.load(cells.pointer(5568), 8, signed=True) & memory.load(cells.pointer(1732), 8, signed=True), 8, 'typed.selector1.q')
            tick(41250)
            vm.pc = 41252
            vm._jump(951)
            continue
        if vm.block == 951:
            tick(41252)
            _phi(vm, 41252, (5571, 2, 145, 950, 5572, 952))
            tick(41259)
            vm.pc = 41264
            vm._write(5573, int(cells.value(5571) < cells.value(5570)), 4, 'once18.unsigned_q')
            tick(41264)
            vm.pc = 41268
            vm._jump(952 if cells.value(5573) != 0 else 953)
            continue
        if vm.block == 952:
            tick(41268)
            _pointer(vm, 41268, 1, 5556, 5574, (5571,))
            tick(41275)
            vm.pc = 41280
            cells.copy_q_clear_owned(5574, 5575)
            tick(41280)
            vm.pc = 41284
            value = memory.load(cells.value(5575), 4)
            vm._write(5576, value, 4, 'high.load')
            tick(41284)
            _pointer(vm, 41284, 1, 5569, 5577, (5571,))
            tick(41291)
            vm.pc = 41296
            cells.copy_q_clear_owned(5577, 5578)
            tick(41296)
            vm.pc = 41300
            pointer = cells.value(5578)
            value = memory.load(cells.pointer(5576), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(41300)
            vm.pc = 41301
            tick(41301)
            vm.pc = 41304
            vm.auxiliary = (0, 1461284865)
            tick(41304)
            vm.pc = 41309
            vm._write(5572, memory.load(cells.pointer(5571), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(41309)
            vm.pc = 41311
            vm._jump(951)
            continue
        if vm.block == 953:
            tick(41311)
            _phi(vm, 41311, (5579, 2, 5580, 954, 5570, 951))
            tick(41318)
            vm.pc = 41323
            vm._write(5581, int(cells.value(5579) < cells.value(5568)), 4, 'once18.unsigned_q')
            tick(41323)
            vm.pc = 41327
            vm._jump(954 if cells.value(5581) != 0 else 955)
            continue
        if vm.block == 954:
            tick(41327)
            _pointer(vm, 41327, 1, 5556, 5582, (5579,))
            tick(41334)
            vm.pc = 41338
            value = memory.load(cells.value(5582), 1)
            vm._write(5583, value, 4, 'L5.unsigned_load')
            tick(41338)
            _pointer(vm, 41338, 1, 5569, 5584, (5579,))
            tick(41345)
            vm.pc = 41349
            pointer = cells.value(5584)
            value = memory.load(cells.pointer(5583), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(41349)
            vm.pc = 41350
            tick(41350)
            vm.pc = 41353
            vm.auxiliary = (0, 260325378)
            tick(41353)
            vm.pc = 41358
            vm._write(5580, memory.load(cells.pointer(5579), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(41358)
            vm.pc = 41360
            vm._jump(953)
            continue
        if vm.block == 955:
            tick(41360)
            vm.pc = 41365
            value = memory.load(cells.pointer(5563), 1)
            count = memory.load(cells.pointer(336), 1)
            vm._write(5585, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41365)
            vm.pc = 41370
            value = memory.load(cells.pointer(5563), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(5586, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41370)
            vm.pc = 41371
            tick(41371)
            vm.pc = 41374
            vm.auxiliary = (0, 56365)
            tick(41374)
            vm.pc = 41380
            vm._write(5587, memory.load(cells.pointer(5585), 1, signed=True) ^ memory.load(cells.pointer(5586), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(41380)
            vm.pc = 41385
            value = memory.load(cells.pointer(5563), 1)
            count = memory.load(cells.pointer(152), 1)
            vm._write(5588, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41385)
            vm.pc = 41390
            vm._write(5589, memory.load(cells.pointer(5587), 1, signed=True) ^ memory.load(cells.pointer(5588), 1, signed=True), 8, 'L14.binary_q')
            tick(41390)
            vm.pc = 41395
            value = memory.load(cells.pointer(5563), 1)
            count = memory.load(cells.pointer(497), 1)
            vm._write(5590, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41395)
            vm.pc = 41398
            vm.auxiliary = (0, 59966)
            tick(41398)
            vm.pc = 41404
            vm._write(5591, memory.load(cells.pointer(5589), 1, signed=True) ^ memory.load(cells.pointer(5590), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(41404)
            vm.pc = 41409
            vm._write(5592, memory.load(cells.pointer(5591), 1, signed=True) & memory.load(cells.pointer(354), 1, signed=True), 8, 'L13.binary_q')
            tick(41409)
            vm.pc = 41412
            vm.auxiliary = (0, 33230)
            tick(41412)
            _single_control(vm)
            vm.pc = 41417
            count = memory.load(cells.pointer(354), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(5563), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(5593, value, 4, 'typed.selector3.d')
            tick(41417)
            vm.pc = 41420
            vm.auxiliary = (0, 13219)
            tick(41420)
            vm.pc = 41425
            vm._write(5594, memory.load(cells.pointer(5593), 1, signed=True) | memory.load(cells.pointer(5592), 1, signed=True), 8, 'typed.selector2.q')
            tick(41425)
            vm.pc = 41430
            vm._write(5595, memory.load(cells.pointer(5594), 1, signed=True) ^ memory.load(cells.pointer(1645), 1, signed=True), 8, 'L14.binary_q')
            tick(41430)
            vm.pc = 41433
            vm.auxiliary = (0, 50940)
            tick(41433)
            _single_control(vm)
            vm.pc = 41438
            count = memory.load(cells.pointer(497), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(5595), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(5596, value, 4, 'typed.selector3.d')
            tick(41438)
            vm.pc = 41443
            value = memory.load(cells.pointer(5595), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(5597, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41443)
            vm.pc = 41448
            vm._write(5598, memory.load(cells.pointer(5596), 1, signed=True) | memory.load(cells.pointer(5597), 1, signed=True), 8, 'L15.binary_q')
            tick(41448)
            vm.pc = 41451
            vm.auxiliary = (0, 1944232579)
            tick(41451)
            vm.pc = 41456
            vm._write(5599, int(memory.load(cells.pointer(5598), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(41456)
            vm.pc = 41463
            selected = 2222 if cells.value(5599) != 0 else 5598
            vm._write(5600, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(41463)
            _pointer(vm, 41463, 41, 70, 5601, (145, 145))
            tick(41471)
            vm.pc = 41475
            pointer = cells.value(5601)
            value = memory.load(cells.pointer(5600), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(41475)
            vm.pc = 41477
            vm._jump(956)
            continue
        if vm.block == 956:
            tick(41477)
            _phi(vm, 41477, (5602, 2, 269, 955, 5603, 957))
            tick(41484)
            vm.pc = 41489
            vm._write(5604, int(cells.value(5602) < cells.value(5566)), 4, 'once18.unsigned_q')
            tick(41489)
            vm.pc = 41493
            vm._jump(957 if cells.value(5604) != 0 else 958)
            continue
        if vm.block == 957:
            tick(41493)
            vm.pc = 41494
            tick(41494)
            vm.pc = 41497
            vm.auxiliary = (0, 464523266)
            tick(41497)
            vm.pc = 41502
            vm._write(5605, memory.load(cells.pointer(5602), 4, signed=True) + memory.load(cells.pointer(396), 4, signed=True), 8, 'once1.integer')
            tick(41502)
            vm.pc = 41507
            _convert(vm, 8, 5605, 5606)
            tick(41507)
            _pointer(vm, 41507, 41, 70, 5607, (145, 5606))
            tick(41515)
            vm.pc = 41519
            value = memory.load(cells.value(5607), 1)
            vm._write(5608, value, 4, 'high.load')
            tick(41519)
            vm.pc = 41524
            value = memory.load(cells.pointer(5608), 1)
            count = memory.load(cells.pointer(336), 1)
            vm._write(5609, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41524)
            vm.pc = 41529
            value = memory.load(cells.pointer(5608), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(5610, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41529)
            vm.pc = 41534
            vm._write(5611, memory.load(cells.pointer(5609), 1, signed=True) ^ memory.load(cells.pointer(5610), 1, signed=True), 8, 'L14.binary_q')
            tick(41534)
            vm.pc = 41539
            value = memory.load(cells.pointer(5608), 1)
            count = memory.load(cells.pointer(152), 1)
            vm._write(5612, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41539)
            vm.pc = 41544
            vm._write(5613, memory.load(cells.pointer(5611), 1, signed=True) ^ memory.load(cells.pointer(5612), 1, signed=True), 8, 'L14.binary_q')
            tick(41544)
            vm.pc = 41549
            value = memory.load(cells.pointer(5608), 1)
            count = memory.load(cells.pointer(497), 1)
            vm._write(5614, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41549)
            vm.pc = 41554
            vm._write(5615, memory.load(cells.pointer(5613), 1, signed=True) ^ memory.load(cells.pointer(5614), 1, signed=True), 8, 'L14.binary_q')
            tick(41554)
            vm.pc = 41557
            vm.auxiliary = (0, 62037)
            tick(41557)
            vm.pc = 41562
            vm._write(5616, memory.load(cells.pointer(5615), 1, signed=True) & memory.load(cells.pointer(354), 1, signed=True), 8, 'typed.selector1.q')
            tick(41562)
            vm.pc = 41565
            vm.auxiliary = (0, 38293)
            tick(41565)
            _single_control(vm)
            vm.pc = 41570
            count = memory.load(cells.pointer(354), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(5608), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(5617, value, 4, 'typed.selector3.d')
            tick(41570)
            vm.pc = 41573
            vm.auxiliary = (0, 13305)
            tick(41573)
            vm.pc = 41578
            vm._write(5618, memory.load(cells.pointer(5617), 1, signed=True) | memory.load(cells.pointer(5616), 1, signed=True), 8, 'typed.selector2.q')
            tick(41578)
            vm.pc = 41583
            vm._write(5619, cells.value(5602) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(41583)
            vm.pc = 41586
            vm.auxiliary = (0, 1826112003)
            tick(41586)
            vm.pc = 41591
            vm._write(5620, memory.load(cells.pointer(5619), 1, signed=True) * memory.load(cells.pointer(2243), 1, signed=True), 8, 'once0.integer')
            tick(41591)
            vm.pc = 41594
            vm.auxiliary = (0, 1160695809)
            tick(41594)
            vm.pc = 41599
            vm._write(5621, memory.load(cells.pointer(5620), 1, signed=True) + memory.load(cells.pointer(1645), 1, signed=True), 8, 'once1.integer')
            tick(41599)
            vm.pc = 41604
            vm._write(5622, memory.load(cells.pointer(5621), 1, signed=True) ^ memory.load(cells.pointer(5618), 1, signed=True), 8, 'L14.binary_q')
            tick(41604)
            vm.pc = 41607
            vm.auxiliary = (0, 38301)
            tick(41607)
            _single_control(vm)
            vm.pc = 41612
            count = memory.load(cells.pointer(497), 4)
            value = 0 if count & 0x80000000 or count >= 32 else (memory.load(cells.pointer(5622), 1, signed=True) & 0xFFFFFFFF) << count
            vm._write(5623, value, 4, 'typed.selector3.d')
            tick(41612)
            vm.pc = 41617
            value = memory.load(cells.pointer(5622), 1)
            count = memory.load(cells.pointer(1641), 1)
            vm._write(5624, value >> (count & 31), 4, 'once8.logical_shift')
            tick(41617)
            vm.pc = 41620
            vm.auxiliary = (0, 34688)
            tick(41620)
            vm.pc = 41625
            vm._write(5625, memory.load(cells.pointer(5623), 1, signed=True) | memory.load(cells.pointer(5624), 1, signed=True), 8, 'typed.selector2.q')
            tick(41625)
            vm.pc = 41628
            vm.auxiliary = (0, 1528982067)
            tick(41628)
            vm.pc = 41633
            vm._write(5626, int(memory.load(cells.pointer(5625), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(41633)
            vm.pc = 41638
            vm._write(5627, cells.value(5602) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(41638)
            vm.pc = 41641
            vm.auxiliary = (0, 59663)
            tick(41641)
            vm.pc = 41647
            vm._write(5628, memory.load(cells.pointer(5627), 1, signed=True) ^ memory.load(cells.pointer(2222), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(41647)
            vm.pc = 41654
            selected = 5628 if cells.value(5626) != 0 else 5625
            vm._write(5629, memory.load(cells.pointer(selected), 1, signed=True), 8, 'L7.selected_q')
            tick(41654)
            vm.pc = 41659
            _convert(vm, 8, 5602, 5630)
            tick(41659)
            _pointer(vm, 41659, 41, 70, 5631, (145, 5630))
            tick(41667)
            vm.pc = 41671
            pointer = cells.value(5631)
            value = memory.load(cells.pointer(5629), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(41671)
            vm.pc = 41674
            vm.auxiliary = (0, 1420312578)
            tick(41674)
            vm.pc = 41679
            vm._write(5603, memory.load(cells.pointer(5602), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(41679)
            vm.pc = 41681
            vm._jump(956)
            continue
        if vm.block == 958:
            tick(41681)
            _phi(vm, 41681, (5632, 2, 5633, 959, 158, 956))
            tick(41688)
            vm.pc = 41693
            vm._write(5634, int(cells.value(5632) < cells.value(5566)), 4, 'once18.unsigned_q')
            tick(41693)
            vm.pc = 41697
            vm._jump(959 if cells.value(5634) != 0 else 960)
            continue
        if vm.block == 959:
            tick(41697)
            vm.pc = 41702
            _convert(vm, 8, 5632, 5635)
            tick(41702)
            _pointer(vm, 41702, 41, 70, 5636, (145, 5635))
            tick(41710)
            vm.pc = 41714
            value = memory.load(cells.value(5636), 1)
            vm._write(5637, value, 4, 'high.load')
            tick(41714)
            _pointer(vm, 41714, 41, 69, 5638, (145, 5635))
            tick(41722)
            vm.pc = 41726
            value = memory.load(cells.value(5638), 1)
            vm._write(5639, value, 4, 'high.load')
            tick(41726)
            vm.pc = 41731
            vm._write(5640, memory.load(cells.pointer(5639), 1, signed=True) ^ memory.load(cells.pointer(5637), 1, signed=True), 8, 'L14.binary_q')
            tick(41731)
            vm.pc = 41735
            pointer = cells.value(5638)
            value = memory.load(cells.pointer(5640), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(41735)
            vm.pc = 41736
            tick(41736)
            vm.pc = 41739
            vm.auxiliary = (0, 353312769)
            tick(41739)
            vm.pc = 41744
            vm._write(5633, memory.load(cells.pointer(5632), 4, signed=True) + memory.load(cells.pointer(269), 4, signed=True), 8, 'once1.integer')
            tick(41744)
            vm.pc = 41746
            vm._jump(958)
            continue
        if vm.block == 960:
            tick(41746)
            vm.pc = 41751
            vm._write(5641, memory.load(cells.pointer(5568), 8, signed=True) & memory.load(cells.pointer(1732), 8, signed=True), 8, 'L13.binary_q')
            tick(41751)
            vm.pc = 41753
            vm._jump(961)
            continue
        if vm.block == 961:
            tick(41753)
            _phi(vm, 41753, (5642, 2, 145, 960, 5643, 962))
            tick(41760)
            vm.pc = 41765
            vm._write(5644, int(cells.value(5642) < cells.value(5641)), 4, 'once18.unsigned_q')
            tick(41765)
            vm.pc = 41769
            vm._jump(962 if cells.value(5644) != 0 else 963)
            continue
        if vm.block == 962:
            tick(41769)
            _pointer(vm, 41769, 1, 5569, 5645, (5642,))
            tick(41776)
            vm.pc = 41781
            cells.copy_q_clear_owned(5645, 5646)
            tick(41781)
            vm.pc = 41785
            value = memory.load(cells.value(5646), 4)
            vm._write(5647, value, 4, 'high.load')
            tick(41785)
            _pointer(vm, 41785, 1, 5559, 5648, (5642,))
            tick(41792)
            vm.pc = 41797
            cells.copy_q_clear_owned(5648, 5649)
            tick(41797)
            vm.pc = 41801
            pointer = cells.value(5649)
            value = memory.load(cells.pointer(5647), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(41801)
            vm.pc = 41802
            tick(41802)
            vm.pc = 41805
            vm.auxiliary = (0, 858497026)
            tick(41805)
            vm.pc = 41810
            vm._write(5643, memory.load(cells.pointer(5642), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(41810)
            vm.pc = 41812
            vm._jump(961)
            continue
        if vm.block == 963:
            tick(41812)
            _phi(vm, 41812, (5650, 2, 5651, 964, 5641, 961))
            tick(41819)
            vm.pc = 41824
            vm._write(5652, int(cells.value(5650) < cells.value(5568)), 4, 'once18.unsigned_q')
            tick(41824)
            vm.pc = 41828
            vm._jump(964 if cells.value(5652) != 0 else 965)
            continue
        if vm.block == 964:
            tick(41828)
            _pointer(vm, 41828, 1, 5569, 5653, (5650,))
            tick(41835)
            vm.pc = 41839
            value = memory.load(cells.value(5653), 1)
            vm._write(5654, value, 4, 'high.load')
            tick(41839)
            _pointer(vm, 41839, 1, 5559, 5655, (5650,))
            tick(41846)
            vm.pc = 41850
            pointer = cells.value(5655)
            value = memory.load(cells.pointer(5654), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(41850)
            vm.pc = 41851
            tick(41851)
            vm.pc = 41854
            vm.auxiliary = (0, 810115074)
            tick(41854)
            vm.pc = 41859
            vm._write(5651, memory.load(cells.pointer(5650), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(41859)
            vm.pc = 41861
            vm._jump(963)
            continue
        if vm.block == 965:
            tick(41861)
            vm.pc = 41863
            vm._jump(966)
            continue
        if vm.block == 966:
            tick(41863)
            _phi(vm, 41863, (5656, 2, 184, 965, 5657, 967))
            tick(41870)
            _phi(vm, 41870, (5658, 2, 5569, 965, 5659, 967))
            tick(41877)
            vm.pc = 41878
            tick(41878)
            vm.pc = 41881
            vm.auxiliary = (0, 2055381427)
            tick(41881)
            vm.pc = 41886
            vm._write(5660, int(memory.load(cells.pointer(5656), 8, signed=True) == memory.load(cells.pointer(145), 8, signed=True)), 4, 'once17.integer')
            tick(41886)
            vm.pc = 41890
            vm._jump(968 if cells.value(5660) != 0 else 967)
            continue
        if vm.block == 967:
            tick(41890)
            vm.pc = 41891
            tick(41891)
            vm.pc = 41894
            vm.auxiliary = (0, 965365762)
            tick(41894)
            vm.pc = 41899
            vm._write(5657, memory.load(cells.pointer(5656), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(41899)
            _pointer(vm, 41899, 1, 5658, 5659, (163,))
            tick(41906)
            vm.pc = 41910
            pointer = cells.value(5658)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(41910)
            vm.pc = 41912
            vm._jump(966)
            continue
        if vm.block == 968:
            tick(41912)
            vm.pc = 41914
            vm._jump(969)
            continue
        if vm.block == 969:
            tick(41914)
            _phi(vm, 41914, (5661, 2, 184, 968, 5662, 970))
            tick(41921)
            _phi(vm, 41921, (5663, 2, 5601, 968, 5664, 970))
            tick(41928)
            vm.pc = 41929
            tick(41929)
            vm.pc = 41932
            vm.auxiliary = (0, 922887891)
            tick(41932)
            _equal(vm, 41937, 8, 5661, 145, 5665)
            tick(41937)
            vm.pc = 41941
            vm._jump(971 if cells.value(5665) != 0 else 970)
            continue
        if vm.block == 970:
            tick(41941)
            vm.pc = 41942
            tick(41942)
            vm.pc = 41945
            vm.auxiliary = (0, 202170369)
            tick(41945)
            vm.pc = 41950
            vm._write(5662, memory.load(cells.pointer(5661), 8, signed=True) + memory.load(cells.pointer(233), 8, signed=True), 8, 'once1.integer')
            tick(41950)
            _pointer(vm, 41950, 1, 5663, 5664, (163,))
            tick(41957)
            vm.pc = 41961
            pointer = cells.value(5663)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(41961)
            vm.pc = 41963
            vm._jump(969)
            continue
        if vm.block == 971:
            tick(41963)
            vm.pc = 41967
            value = memory.load(cells.value(50), 8)
            vm._write(5666, value, 8, 'high.load')
            tick(41967)
            vm.pc = 41969
            vm._jump(948)
            continue
        if vm.block == 948:
            tick(41969)
            _phi(vm, 41969, (5667, 3, 5666, 971, 145, 940, 145, 949))
            tick(41978)
            _pointer(vm, 41978, 37, 52, 5668, (145, 145))
            tick(41986)
            _pointer(vm, 41986, 37, 53, 5669, (145, 145))
            tick(41994)
            _pointer(vm, 41994, 37, 54, 5670, (145, 145))
            tick(42002)
            _pointer(vm, 42002, 37, 55, 5671, (145, 145))
            tick(42010)
            _pointer(vm, 42010, 37, 52, 5672, (145, 145))
            tick(42018)
            vm.pc = 42020
            vm._jump(972)
            continue
        if vm.block == 972:
            tick(42020)
            _phi(vm, 42020, (5673, 2, 145, 948, 5674, 973))
            tick(42027)
            vm.pc = 42032
            vm._write(5675, int(cells.value(5673) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(42032)
            vm.pc = 42036
            vm._jump(973 if cells.value(5675) != 0 else 974)
            continue
        if vm.block == 974:
            tick(42036)
            _pointer(vm, 42036, 37, 47, 5676, (145, 145))
            tick(42044)
            vm.pc = 42053
            _continuation_host(vm, 42044, 157, (5676, 158, 4386), 121, 5677)
            tick(42053)
            vm.pc = 42055
            vm._jump(975)
            continue
        if vm.block == 973:
            tick(42055)
            vm.pc = 42056
            tick(42056)
            vm.pc = 42059
            vm.auxiliary = (0, 41093)
            tick(42059)
            _single_control(vm)
            vm.pc = 42064
            count = memory.load(cells.pointer(169), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(5673) << count
            vm._write(5678, value, 8, "typed.selector3.q")
            tick(42064)
            vm.pc = 42069
            value = memory.load(cells.pointer(5667), 8)
            count = memory.load(cells.pointer(5678), 1)
            vm._write(5679, value >> (count & 63), 8, 'once8.logical_shift')
            tick(42069)
            vm.pc = 42074
            vm._write(5680, cells.value(5679) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(42074)
            _pointer(vm, 42074, 194, 4391, 5681, (145, 5673))
            tick(42082)
            vm.pc = 42086
            value = memory.load(cells.value(5681), 8)
            vm._write(5682, value, 8, 'L5.unsigned_load')
            tick(42086)
            _pointer(vm, 42086, 1, 5672, 5683, (5682,))
            tick(42093)
            vm.pc = 42097
            pointer = cells.value(5683)
            value = memory.load(cells.pointer(5680), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42097)
            vm.pc = 42100
            vm.auxiliary = (0, 963497986)
            tick(42100)
            vm.pc = 42105
            vm._write(5674, memory.load(cells.pointer(5673), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42105)
            vm.pc = 42107
            vm._jump(972)
            continue
        if vm.block == 975:
            tick(42107)
            _phi(vm, 42107, (5684, 2, 145, 974, 5685, 976))
            tick(42114)
            vm.pc = 42119
            vm._write(5686, int(cells.value(5684) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(42119)
            vm.pc = 42123
            vm._jump(976 if cells.value(5686) != 0 else 977)
            continue
        if vm.block == 976:
            tick(42123)
            _pointer(vm, 42123, 194, 4391, 5687, (145, 5684))
            tick(42131)
            vm.pc = 42135
            value = memory.load(cells.value(5687), 8)
            vm._write(5688, value, 8, 'high.load')
            tick(42135)
            _pointer(vm, 42135, 37, 47, 5689, (145, 5688))
            tick(42143)
            vm.pc = 42147
            pointer = cells.value(5689)
            value = memory.load(cells.pointer(354), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42147)
            vm.pc = 42148
            tick(42148)
            vm.pc = 42151
            vm.auxiliary = (0, 816648194)
            tick(42151)
            vm.pc = 42156
            vm._write(5685, memory.load(cells.pointer(5684), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42156)
            vm.pc = 42158
            vm._jump(975)
            continue
        if vm.block == 977:
            tick(42158)
            _phi(vm, 42158, (5690, 2, 5691, 978, 145, 975))
            tick(42165)
            vm.pc = 42170
            vm._write(5692, int(cells.value(5690) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(42170)
            vm.pc = 42174
            vm._jump(979 if cells.value(5692) != 0 else 980)
            continue
        if vm.block == 979:
            tick(42174)
            _pointer(vm, 42174, 37, 47, 5693, (145, 5690))
            tick(42182)
            vm.pc = 42186
            value = memory.load(cells.value(5693), 1)
            vm._write(5694, value, 4, 'high.load')
            tick(42186)
            vm.pc = 42187
            tick(42187)
            vm.pc = 42190
            vm.auxiliary = (0, 2039651507)
            tick(42190)
            vm.pc = 42195
            vm._write(5695, int(memory.load(cells.pointer(5694), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(42195)
            vm.pc = 42199
            vm._jump(981 if cells.value(5695) != 0 else 978)
            continue
        if vm.block == 981:
            tick(42199)
            _pointer(vm, 42199, 1, 5672, 5696, (203,))
            tick(42206)
            vm.pc = 42210
            value = memory.load(cells.value(5696), 1)
            vm._write(5697, value, 4, 'high.load')
            tick(42210)
            _pointer(vm, 42210, 1, 5672, 5698, (4409,))
            tick(42217)
            vm.pc = 42221
            value = memory.load(cells.value(5698), 1)
            vm._write(5699, value, 4, 'high.load')
            tick(42221)
            vm.pc = 42226
            vm._write(5700, memory.load(cells.pointer(5697), 1, signed=True) ^ memory.load(cells.pointer(5699), 1, signed=True), 8, 'L14.binary_q')
            tick(42226)
            vm.pc = 42231
            vm._write(5701, cells.value(5690) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(42231)
            vm.pc = 42232
            tick(42232)
            vm.pc = 42235
            vm.auxiliary = (0, 31533)
            tick(42235)
            vm.pc = 42241
            vm._write(5702, memory.load(cells.pointer(5700), 1, signed=True) ^ memory.load(cells.pointer(5701), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(42241)
            _pointer(vm, 42241, 1, 5672, 5703, (5690,))
            tick(42248)
            vm.pc = 42252
            pointer = cells.value(5703)
            value = memory.load(cells.pointer(5702), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42252)
            vm.pc = 42254
            vm._jump(978)
            continue
        if vm.block == 978:
            tick(42254)
            vm.pc = 42255
            tick(42255)
            vm.pc = 42258
            vm.auxiliary = (0, 1413263361)
            tick(42258)
            vm.pc = 42263
            vm._write(5691, memory.load(cells.pointer(5690), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42263)
            vm.pc = 42265
            vm._jump(977)
            continue
        if vm.block == 980:
            tick(42265)
            _pointer(vm, 42265, 37, 53, 5704, (145, 145))
            tick(42273)
            vm.pc = 42275
            vm._jump(982)
            continue
        if vm.block == 982:
            tick(42275)
            _phi(vm, 42275, (5705, 2, 145, 980, 5706, 983))
            tick(42282)
            vm.pc = 42287
            vm._write(5707, int(cells.value(5705) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(42287)
            vm.pc = 42291
            vm._jump(983 if cells.value(5707) != 0 else 984)
            continue
        if vm.block == 984:
            tick(42291)
            _pointer(vm, 42291, 37, 47, 5708, (145, 145))
            tick(42299)
            vm.pc = 42308
            _continuation_host(vm, 42299, 157, (5708, 158, 4386), 121, 5709)
            tick(42308)
            vm.pc = 42310
            vm._jump(985)
            continue
        if vm.block == 983:
            tick(42310)
            vm.pc = 42311
            tick(42311)
            vm.pc = 42314
            vm.auxiliary = (0, 21476)
            tick(42314)
            _single_control(vm)
            vm.pc = 42319
            count = memory.load(cells.pointer(169), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(5705) << count
            vm._write(5710, value, 8, "typed.selector3.q")
            tick(42319)
            vm.pc = 42324
            value = memory.load(cells.pointer(5553), 8)
            count = memory.load(cells.pointer(5710), 1)
            vm._write(5711, value >> (count & 63), 8, 'once8.logical_shift')
            tick(42324)
            vm.pc = 42329
            vm._write(5712, cells.value(5711) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(42329)
            _pointer(vm, 42329, 194, 4391, 5713, (145, 5705))
            tick(42337)
            vm.pc = 42341
            value = memory.load(cells.value(5713), 8)
            vm._write(5714, value, 8, 'high.load')
            tick(42341)
            _pointer(vm, 42341, 1, 5704, 5715, (5714,))
            tick(42348)
            vm.pc = 42352
            pointer = cells.value(5715)
            value = memory.load(cells.pointer(5712), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42352)
            vm.pc = 42355
            vm.auxiliary = (0, 567377922)
            tick(42355)
            vm.pc = 42360
            vm._write(5706, memory.load(cells.pointer(5705), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42360)
            vm.pc = 42362
            vm._jump(982)
            continue
        if vm.block == 985:
            tick(42362)
            _phi(vm, 42362, (5716, 2, 145, 984, 5717, 986))
            tick(42369)
            vm.pc = 42374
            vm._write(5718, int(cells.value(5716) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(42374)
            vm.pc = 42378
            vm._jump(986 if cells.value(5718) != 0 else 987)
            continue
        if vm.block == 986:
            tick(42378)
            _pointer(vm, 42378, 194, 4391, 5719, (145, 5716))
            tick(42386)
            vm.pc = 42390
            value = memory.load(cells.value(5719), 8)
            vm._write(5720, value, 8, 'high.load')
            tick(42390)
            _pointer(vm, 42390, 37, 47, 5721, (145, 5720))
            tick(42398)
            vm.pc = 42402
            pointer = cells.value(5721)
            value = memory.load(cells.pointer(354), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42402)
            vm.pc = 42403
            tick(42403)
            vm.pc = 42406
            vm.auxiliary = (0, 1676267522)
            tick(42406)
            vm.pc = 42411
            vm._write(5717, memory.load(cells.pointer(5716), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42411)
            vm.pc = 42413
            vm._jump(985)
            continue
        if vm.block == 987:
            tick(42413)
            _phi(vm, 42413, (5722, 2, 5723, 988, 145, 985))
            tick(42420)
            vm.pc = 42425
            vm._write(5724, int(cells.value(5722) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(42425)
            vm.pc = 42429
            vm._jump(989 if cells.value(5724) != 0 else 990)
            continue
        if vm.block == 989:
            tick(42429)
            _pointer(vm, 42429, 37, 47, 5725, (145, 5722))
            tick(42437)
            vm.pc = 42441
            value = memory.load(cells.value(5725), 1)
            vm._write(5726, value, 4, 'high.load')
            tick(42441)
            vm.pc = 42442
            tick(42442)
            vm.pc = 42445
            vm.auxiliary = (0, 672286851)
            tick(42445)
            vm.pc = 42450
            vm._write(5727, int(memory.load(cells.pointer(5726), 1, signed=True) == memory.load(cells.pointer(235), 1, signed=True)), 4, 'once17.integer')
            tick(42450)
            vm.pc = 42454
            vm._jump(991 if cells.value(5727) != 0 else 988)
            continue
        if vm.block == 991:
            tick(42454)
            _pointer(vm, 42454, 1, 5704, 5728, (203,))
            tick(42461)
            vm.pc = 42465
            value = memory.load(cells.value(5728), 1)
            vm._write(5729, value, 4, 'high.load')
            tick(42465)
            _pointer(vm, 42465, 1, 5704, 5730, (4409,))
            tick(42472)
            vm.pc = 42476
            value = memory.load(cells.value(5730), 1)
            vm._write(5731, value, 4, 'high.load')
            tick(42476)
            vm.pc = 42481
            vm._write(5732, memory.load(cells.pointer(5729), 1, signed=True) ^ memory.load(cells.pointer(5731), 1, signed=True), 8, 'L14.binary_q')
            tick(42481)
            vm.pc = 42486
            vm._write(5733, cells.value(5722) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(42486)
            vm.pc = 42487
            tick(42487)
            vm.pc = 42490
            vm.auxiliary = (0, 52078)
            tick(42490)
            vm.pc = 42496
            vm._write(5734, memory.load(cells.pointer(5732), 1, signed=True) ^ memory.load(cells.pointer(5733), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(42496)
            _pointer(vm, 42496, 1, 5704, 5735, (5722,))
            tick(42503)
            vm.pc = 42507
            pointer = cells.value(5735)
            value = memory.load(cells.pointer(5734), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(42507)
            vm.pc = 42509
            vm._jump(988)
            continue
        if vm.block == 988:
            tick(42509)
            vm.pc = 42510
            tick(42510)
            vm.pc = 42513
            vm.auxiliary = (0, 922370050)
            tick(42513)
            vm.pc = 42518
            vm._write(5723, memory.load(cells.pointer(5722), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42518)
            vm.pc = 42520
            vm._jump(987)
            continue
        if vm.block == 990:
            tick(42520)
            _pointer(vm, 42520, 37, 54, 5736, (145, 145))
            tick(42528)
            vm.pc = 42530
            vm._jump(992)
            continue
        if vm.block == 992:
            tick(42530)
            _phi(vm, 42530, (5737, 2, 145, 990, 5738, 993))
            tick(42537)
            vm.pc = 42542
            vm._write(5739, int(cells.value(5737) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(42542)
            vm.pc = 42546
            vm._jump(993 if cells.value(5739) != 0 else 994)
            continue
        if vm.block == 994:
            tick(42546)
            _pointer(vm, 42546, 37, 47, 5740, (145, 145))
            tick(42554)
            vm.pc = 42563
            _continuation_host(vm, 42554, 157, (5740, 158, 4386), 121, 5741)
            tick(42563)
            vm.pc = 42565
            vm._jump(995)
            continue
        if vm.block == 993:
            tick(42565)
            vm.pc = 42566
            tick(42566)
            vm.pc = 42569
            vm.auxiliary = (0, 41108)
            tick(42569)
            _single_control(vm)
            vm.pc = 42574
            count = memory.load(cells.pointer(169), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(5737) << count
            vm._write(5742, value, 8, "typed.selector3.q")
            tick(42574)
            vm.pc = 42579
            value = memory.load(cells.pointer(5552), 8)
            count = memory.load(cells.pointer(5742), 1)
            vm._write(5743, value >> (count & 63), 8, 'once8.logical_shift')
            tick(42579)
            vm.pc = 42584
            vm._write(5744, cells.value(5743) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(42584)
            _pointer(vm, 42584, 194, 4391, 5745, (145, 5737))
            tick(42592)
            vm.pc = 42596
            value = memory.load(cells.value(5745), 8)
            vm._write(5746, value, 8, 'high.load')
            tick(42596)
            _pointer(vm, 42596, 1, 5736, 5747, (5746,))
            tick(42603)
            vm.pc = 42607
            pointer = cells.value(5747)
            value = memory.load(cells.pointer(5744), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42607)
            vm.pc = 42610
            vm.auxiliary = (0, 2021953537)
            tick(42610)
            vm.pc = 42615
            vm._write(5738, memory.load(cells.pointer(5737), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42615)
            vm.pc = 42617
            vm._jump(992)
            continue
        if vm.block == 995:
            tick(42617)
            _phi(vm, 42617, (5748, 2, 145, 994, 5749, 996))
            tick(42624)
            vm.pc = 42629
            vm._write(5750, int(cells.value(5748) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(42629)
            vm.pc = 42633
            vm._jump(996 if cells.value(5750) != 0 else 997)
            continue
        if vm.block == 996:
            tick(42633)
            _pointer(vm, 42633, 194, 4391, 5751, (145, 5748))
            tick(42641)
            vm.pc = 42645
            value = memory.load(cells.value(5751), 8)
            vm._write(5752, value, 8, 'high.load')
            tick(42645)
            _pointer(vm, 42645, 37, 47, 5753, (145, 5752))
            tick(42653)
            vm.pc = 42657
            pointer = cells.value(5753)
            value = memory.load(cells.pointer(354), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42657)
            vm.pc = 42658
            tick(42658)
            vm.pc = 42661
            vm.auxiliary = (0, 465104897)
            tick(42661)
            vm.pc = 42666
            vm._write(5749, memory.load(cells.pointer(5748), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42666)
            vm.pc = 42668
            vm._jump(995)
            continue
        if vm.block == 997:
            tick(42668)
            _phi(vm, 42668, (5754, 2, 5755, 998, 145, 995))
            tick(42675)
            vm.pc = 42680
            vm._write(5756, int(cells.value(5754) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(42680)
            vm.pc = 42684
            vm._jump(999 if cells.value(5756) != 0 else 1000)
            continue
        if vm.block == 999:
            tick(42684)
            _pointer(vm, 42684, 37, 47, 5757, (145, 5754))
            tick(42692)
            vm.pc = 42696
            value = memory.load(cells.value(5757), 1)
            vm._write(5758, value, 4, 'high.load')
            tick(42696)
            vm.pc = 42697
            tick(42697)
            vm.pc = 42700
            vm.auxiliary = (0, 1404183011)
            tick(42700)
            _equal(vm, 42705, 1, 5758, 235, 5759)
            tick(42705)
            vm.pc = 42709
            vm._jump(1001 if cells.value(5759) != 0 else 998)
            continue
        if vm.block == 1001:
            tick(42709)
            _pointer(vm, 42709, 1, 5736, 5760, (203,))
            tick(42716)
            vm.pc = 42720
            value = memory.load(cells.value(5760), 1)
            vm._write(5761, value, 4, 'high.load')
            tick(42720)
            _pointer(vm, 42720, 1, 5736, 5762, (4409,))
            tick(42727)
            vm.pc = 42731
            value = memory.load(cells.value(5762), 1)
            vm._write(5763, value, 4, 'high.load')
            tick(42731)
            vm.pc = 42736
            vm._write(5764, memory.load(cells.pointer(5761), 1, signed=True) ^ memory.load(cells.pointer(5763), 1, signed=True), 8, 'L14.binary_q')
            tick(42736)
            vm.pc = 42741
            vm._write(5765, cells.value(5754) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(42741)
            vm.pc = 42742
            tick(42742)
            vm.pc = 42745
            vm.auxiliary = (0, 30982)
            tick(42745)
            vm.pc = 42751
            vm._write(5766, memory.load(cells.pointer(5764), 1, signed=True) ^ memory.load(cells.pointer(5765), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(42751)
            _pointer(vm, 42751, 1, 5736, 5767, (5754,))
            tick(42758)
            vm.pc = 42762
            pointer = cells.value(5767)
            value = memory.load(cells.pointer(5766), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42762)
            vm.pc = 42764
            vm._jump(998)
            continue
        if vm.block == 998:
            tick(42764)
            vm.pc = 42765
            tick(42765)
            vm.pc = 42768
            vm.auxiliary = (0, 209780738)
            tick(42768)
            vm.pc = 42773
            vm._write(5755, memory.load(cells.pointer(5754), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42773)
            vm.pc = 42775
            vm._jump(997)
            continue
        if vm.block == 1000:
            tick(42775)
            _pointer(vm, 42775, 37, 55, 5768, (145, 145))
            tick(42783)
            vm.pc = 42785
            vm._jump(1002)
            continue
        if vm.block == 1002:
            tick(42785)
            _phi(vm, 42785, (5769, 2, 145, 1000, 5770, 1003))
            tick(42792)
            vm.pc = 42797
            vm._write(5771, int(cells.value(5769) < cells.value(4409)), 4, 'once18.unsigned_q')
            tick(42797)
            vm.pc = 42801
            vm._jump(1003 if cells.value(5771) != 0 else 1004)
            continue
        if vm.block == 1003:
            tick(42801)
            _pointer(vm, 42801, 1, 5704, 5772, (5769,))
            tick(42808)
            vm.pc = 42813
            cells.copy_q_clear_owned(5772, 5773)
            tick(42813)
            vm.pc = 42817
            value = memory.load(cells.value(5773), 4)
            vm._write(5774, value, 4, 'high.load')
            tick(42817)
            _pointer(vm, 42817, 1, 5768, 5775, (5769,))
            tick(42824)
            vm.pc = 42829
            cells.copy_q_clear_owned(5775, 5776)
            tick(42829)
            vm.pc = 42833
            pointer = cells.value(5776)
            value = memory.load(cells.pointer(5774), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(42833)
            vm.pc = 42834
            tick(42834)
            vm.pc = 42837
            vm.auxiliary = (0, 1219366913)
            tick(42837)
            vm.pc = 42842
            vm._write(5770, memory.load(cells.pointer(5769), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(42842)
            vm.pc = 42844
            vm._jump(1002)
            continue
        if vm.block == 1004:
            tick(42844)
            _phi(vm, 42844, (5777, 2, 5778, 1005, 4409, 1002))
            tick(42851)
            vm.pc = 42856
            vm._write(5779, int(cells.value(5777) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(42856)
            vm.pc = 42860
            vm._jump(1005 if cells.value(5779) != 0 else 1006)
            continue
        if vm.block == 1005:
            tick(42860)
            _pointer(vm, 42860, 1, 5704, 5780, (5777,))
            tick(42867)
            vm.pc = 42871
            value = memory.load(cells.value(5780), 1)
            vm._write(5781, value, 4, 'high.load')
            tick(42871)
            _pointer(vm, 42871, 1, 5768, 5782, (5777,))
            tick(42878)
            vm.pc = 42882
            pointer = cells.value(5782)
            value = memory.load(cells.pointer(5781), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(42882)
            vm.pc = 42883
            tick(42883)
            vm.pc = 42886
            vm.auxiliary = (0, 2029441026)
            tick(42886)
            vm.pc = 42891
            vm._write(5778, memory.load(cells.pointer(5777), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42891)
            vm.pc = 42893
            vm._jump(1004)
            continue
        if vm.block == 1006:
            tick(42893)
            vm.pc = 42895
            vm._jump(1007)
            continue
        if vm.block == 1007:
            tick(42895)
            _phi(vm, 42895, (5783, 2, 145, 1006, 5784, 1008))
            tick(42902)
            vm.pc = 42907
            vm._write(5785, int(cells.value(5783) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(42907)
            vm.pc = 42911
            vm._jump(1008 if cells.value(5785) != 0 else 1009)
            continue
        if vm.block == 1008:
            tick(42911)
            _pointer(vm, 42911, 194, 4391, 5786, (145, 5783))
            tick(42919)
            vm.pc = 42923
            value = memory.load(cells.value(5786), 8)
            vm._write(5787, value, 8, 'high.load')
            tick(42923)
            _pointer(vm, 42923, 1, 5704, 5788, (5787,))
            tick(42930)
            vm.pc = 42934
            value = memory.load(cells.value(5788), 1)
            vm._write(5789, value, 4, 'high.load')
            tick(42934)
            _pointer(vm, 42934, 1, 5736, 5790, (5787,))
            tick(42941)
            vm.pc = 42945
            value = memory.load(cells.value(5790), 1)
            vm._write(5791, value, 4, 'high.load')
            tick(42945)
            vm.pc = 42946
            tick(42946)
            vm.pc = 42949
            vm.auxiliary = (0, 18452)
            tick(42949)
            vm.pc = 42955
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5792, memory.load(cells.pointer(5791), 1, signed=True) ^ memory.load(cells.pointer(5789), 1, signed=True), 8, 'typed.selector5.q')
            tick(42955)
            _pointer(vm, 42955, 1, 5768, 5793, (5787,))
            tick(42962)
            vm.pc = 42966
            pointer = cells.value(5793)
            value = memory.load(cells.pointer(5792), 4)
            memory.store(pointer, value, 1, source='L6.store_integer')
            tick(42966)
            vm.pc = 42969
            vm.auxiliary = (0, 456081410)
            tick(42969)
            vm.pc = 42974
            vm._write(5784, memory.load(cells.pointer(5783), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(42974)
            vm.pc = 42976
            vm._jump(1007)
            continue
        if vm.block == 1009:
            tick(42976)
            vm.pc = 42978
            vm._jump(1010)
            continue
        if vm.block == 1010:
            tick(42978)
            _phi(vm, 42978, (5794, 2, 145, 1009, 5795, 1011))
            tick(42985)
            vm.pc = 42990
            vm._write(5796, int(cells.value(5794) < cells.value(4409)), 4, 'once18.unsigned_q')
            tick(42990)
            vm.pc = 42994
            vm._jump(1011 if cells.value(5796) != 0 else 1012)
            continue
        if vm.block == 1011:
            tick(42994)
            _pointer(vm, 42994, 1, 5672, 5797, (5794,))
            tick(43001)
            vm.pc = 43006
            cells.copy_q_clear_owned(5797, 5798)
            tick(43006)
            vm.pc = 43010
            value = memory.load(cells.value(5798), 4)
            vm._write(5799, value, 4, 'high.load')
            tick(43010)
            _pointer(vm, 43010, 1, 5554, 5800, (5794,))
            tick(43017)
            vm.pc = 43022
            cells.copy_q_clear_owned(5800, 5801)
            tick(43022)
            vm.pc = 43026
            pointer = cells.value(5801)
            value = memory.load(cells.pointer(5799), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(43026)
            vm.pc = 43027
            tick(43027)
            vm.pc = 43030
            vm.auxiliary = (0, 1172070402)
            tick(43030)
            vm.pc = 43035
            vm._write(5795, memory.load(cells.pointer(5794), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(43035)
            vm.pc = 43037
            vm._jump(1010)
            continue
        if vm.block == 1012:
            tick(43037)
            _phi(vm, 43037, (5802, 2, 5803, 1013, 4409, 1010))
            tick(43044)
            vm.pc = 43049
            vm._write(5804, int(cells.value(5802) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(43049)
            vm.pc = 43053
            vm._jump(1013 if cells.value(5804) != 0 else 1014)
            continue
        if vm.block == 1013:
            tick(43053)
            _pointer(vm, 43053, 1, 5672, 5805, (5802,))
            tick(43060)
            vm.pc = 43064
            value = memory.load(cells.value(5805), 1)
            vm._write(5806, value, 4, 'high.load')
            tick(43064)
            _pointer(vm, 43064, 1, 5554, 5807, (5802,))
            tick(43071)
            vm.pc = 43075
            pointer = cells.value(5807)
            value = memory.load(cells.pointer(5806), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43075)
            vm.pc = 43076
            tick(43076)
            vm.pc = 43079
            vm.auxiliary = (0, 662102018)
            tick(43079)
            vm.pc = 43084
            vm._write(5803, memory.load(cells.pointer(5802), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(43084)
            vm.pc = 43086
            vm._jump(1012)
            continue
        if vm.block == 1014:
            tick(43086)
            vm.pc = 43088
            vm._jump(1015)
            continue
        if vm.block == 1015:
            tick(43088)
            _phi(vm, 43088, (5808, 2, 145, 1014, 5809, 1016))
            tick(43095)
            vm.pc = 43100
            vm._write(5810, int(cells.value(5808) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(43100)
            vm.pc = 43104
            vm._jump(1016 if cells.value(5810) != 0 else 1017)
            continue
        if vm.block == 1016:
            tick(43104)
            _pointer(vm, 43104, 194, 4391, 5811, (145, 5808))
            tick(43112)
            vm.pc = 43116
            value = memory.load(cells.value(5811), 8)
            vm._write(5812, value, 8, 'L5.unsigned_load')
            tick(43116)
            _pointer(vm, 43116, 1, 5672, 5813, (5812,))
            tick(43123)
            vm.pc = 43127
            value = memory.load(cells.value(5813), 1)
            vm._write(5814, value, 4, 'L5.unsigned_load')
            tick(43127)
            _pointer(vm, 43127, 1, 5768, 5815, (5812,))
            tick(43134)
            vm.pc = 43138
            value = memory.load(cells.value(5815), 1)
            vm._write(5816, value, 4, 'high.load')
            tick(43138)
            vm.pc = 43139
            tick(43139)
            vm.pc = 43142
            vm.auxiliary = (0, 62130)
            tick(43142)
            vm.pc = 43147
            vm._write(5817, memory.load(cells.pointer(5814), 1, signed=True) | memory.load(cells.pointer(5816), 1, signed=True), 8, 'typed.selector2.q')
            tick(43147)
            _pointer(vm, 43147, 1, 5554, 5818, (5812,))
            tick(43154)
            vm.pc = 43158
            pointer = cells.value(5818)
            value = memory.load(cells.pointer(5817), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43158)
            vm.pc = 43161
            vm.auxiliary = (0, 1068539906)
            tick(43161)
            vm.pc = 43166
            vm._write(5809, memory.load(cells.pointer(5808), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(43166)
            vm.pc = 43168
            vm._jump(1015)
            continue
        if vm.block == 1017:
            tick(43168)
            vm.pc = 43170
            vm._jump(1018)
            continue
        if vm.block == 1018:
            tick(43170)
            _phi(vm, 43170, (5819, 2, 145, 1017, 5820, 1019))
            tick(43177)
            vm.pc = 43182
            vm._write(5821, int(cells.value(5819) < cells.value(169)), 4, 'once18.unsigned_q')
            tick(43182)
            vm.pc = 43186
            vm._jump(1020 if cells.value(5821) != 0 else 1021)
            continue
        if vm.block == 1021:
            tick(43186)
            vm.pc = 43188
            vm._jump(1022)
            continue
        if vm.block == 1022:
            tick(43188)
            _phi(vm, 43188, (5822, 2, 145, 1021, 5823, 1023))
            tick(43195)
            vm.pc = 43200
            vm._write(5824, int(cells.value(5822) < cells.value(4409)), 4, 'once18.unsigned_q')
            tick(43200)
            vm.pc = 43204
            vm._jump(1023 if cells.value(5824) != 0 else 1024)
            continue
        if vm.block == 1023:
            tick(43204)
            _pointer(vm, 43204, 1, 5554, 5825, (5822,))
            tick(43211)
            vm.pc = 43216
            cells.copy_q_clear_owned(5825, 5826)
            tick(43216)
            vm.pc = 43220
            value = memory.load(cells.value(5826), 4)
            vm._write(5827, value, 4, 'high.load')
            tick(43220)
            _pointer(vm, 43220, 1, 5554, 5828, (5822,))
            tick(43227)
            vm.pc = 43232
            cells.copy_q_clear_owned(5828, 5829)
            tick(43232)
            vm.pc = 43236
            pointer = cells.value(5829)
            value = memory.load(cells.pointer(5827), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(43236)
            vm.pc = 43237
            tick(43237)
            vm.pc = 43240
            vm.auxiliary = (0, 1767981057)
            tick(43240)
            vm.pc = 43245
            vm._write(5823, memory.load(cells.pointer(5822), 8, signed=True) + memory.load(cells.pointer(172), 8, signed=True), 8, 'once1.integer')
            tick(43245)
            vm.pc = 43247
            vm._jump(1022)
            continue
        if vm.block == 1024:
            tick(43247)
            _phi(vm, 43247, (5830, 2, 5831, 1025, 4409, 1022))
            tick(43254)
            vm.pc = 43259
            vm._write(5832, int(cells.value(5830) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(43259)
            vm.pc = 43263
            vm._jump(1025 if cells.value(5832) != 0 else 1026)
            continue
        if vm.block == 1025:
            tick(43263)
            _pointer(vm, 43263, 1, 5554, 5833, (5830,))
            tick(43270)
            vm.pc = 43274
            value = memory.load(cells.value(5833), 1)
            vm._write(5834, value, 4, 'high.load')
            tick(43274)
            _pointer(vm, 43274, 1, 5554, 5835, (5830,))
            tick(43281)
            vm.pc = 43285
            pointer = cells.value(5835)
            value = memory.load(cells.pointer(5834), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43285)
            vm.pc = 43286
            tick(43286)
            vm.pc = 43289
            vm.auxiliary = (0, 1424011266)
            tick(43289)
            vm.pc = 43294
            vm._write(5831, memory.load(cells.pointer(5830), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(43294)
            vm.pc = 43296
            vm._jump(1024)
            continue
        if vm.block == 1026:
            tick(43296)
            vm.pc = 43298
            vm._jump(1027)
            continue
        if vm.block == 1027:
            tick(43298)
            _phi(vm, 43298, (5836, 2, 145, 1026, 5837, 1028))
            tick(43305)
            vm.pc = 43310
            vm._write(5838, int(cells.value(5836) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(43310)
            vm.pc = 43314
            vm._jump(1028 if cells.value(5838) != 0 else 1029)
            continue
        if vm.block == 1028:
            tick(43314)
            _pointer(vm, 43314, 194, 4391, 5839, (145, 5836))
            tick(43322)
            vm.pc = 43326
            value = memory.load(cells.value(5839), 8)
            vm._write(5840, value, 8, 'L5.unsigned_load')
            tick(43326)
            _pointer(vm, 43326, 1, 5554, 5841, (5840,))
            tick(43333)
            vm.pc = 43337
            value = memory.load(cells.value(5841), 1)
            vm._write(5842, value, 4, 'L5.unsigned_load')
            tick(43337)
            _pointer(vm, 43337, 1, 5736, 5843, (5840,))
            tick(43344)
            vm.pc = 43348
            value = memory.load(cells.value(5843), 1)
            vm._write(5844, value, 4, 'high.load')
            tick(43348)
            vm.pc = 43349
            tick(43349)
            vm.pc = 43352
            vm.auxiliary = (0, 43110)
            tick(43352)
            vm.pc = 43358
            vm._write(5845, memory.load(cells.pointer(5844), 1, signed=True) ^ memory.load(cells.pointer(5842), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(43358)
            _pointer(vm, 43358, 1, 5554, 5846, (5840,))
            tick(43365)
            vm.pc = 43369
            pointer = cells.value(5846)
            value = memory.load(cells.pointer(5845), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43369)
            vm.pc = 43372
            vm.auxiliary = (0, 607469569)
            tick(43372)
            vm.pc = 43377
            vm._write(5837, memory.load(cells.pointer(5836), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(43377)
            vm.pc = 43379
            vm._jump(1027)
            continue
        if vm.block == 1020:
            tick(43379)
            _pointer(vm, 43379, 7, 5542, 5847, (5819,))
            tick(43386)
            vm.pc = 43390
            value = memory.load(cells.value(5847), 8)
            vm._write(5848, value, 8, 'high.load')
            tick(43390)
            vm.pc = 43394
            pointer = cells.value(48)
            value = memory.load(cells.pointer(4560), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43394)
            vm.pc = 43396
            vm._jump(1030)
            continue
        if vm.block == 1030:
            tick(43396)
            _phi(vm, 43396, (5849, 2, 145, 1020, 5850, 1031))
            tick(43403)
            vm.pc = 43408
            vm._write(5851, int(cells.value(5849) < cells.value(4386)), 4, 'once18.unsigned_q')
            tick(43408)
            vm.pc = 43412
            vm._jump(1031 if cells.value(5851) != 0 else 1032)
            continue
        if vm.block == 1031:
            tick(43412)
            _pointer(vm, 43412, 1, 5554, 5852, (5849,))
            tick(43419)
            vm.pc = 43423
            value = memory.load(cells.value(5852), 1)
            vm._write(5853, value, 4, 'L5.unsigned_load')
            tick(43423)
            _pointer(vm, 43423, 1, 5554, 5854, (5849,))
            tick(43430)
            vm.pc = 43434
            pointer = cells.value(5854)
            value = memory.load(cells.pointer(5853), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43434)
            vm.pc = 43438
            value = memory.load(cells.value(48), 1)
            vm._write(5855, value, 4, 'high.load')
            tick(43438)
            vm.pc = 43439
            tick(43439)
            vm.pc = 43442
            vm.auxiliary = (0, 39508)
            tick(43442)
            vm.pc = 43448
            vm._write(5856, memory.load(cells.pointer(5853), 1, signed=True) ^ memory.load(cells.pointer(5855), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(43448)
            vm.pc = 43452
            pointer = cells.value(5854)
            value = memory.load(cells.pointer(5856), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43452)
            vm.pc = 43456
            value = memory.load(cells.value(48), 1)
            vm._write(5857, value, 4, 'high.load')
            tick(43456)
            vm.pc = 43461
            vm._write(5858, memory.load(cells.pointer(5856), 1, signed=True) ^ memory.load(cells.pointer(5857), 1, signed=True), 8, 'L14.binary_q')
            tick(43461)
            vm.pc = 43465
            pointer = cells.value(5854)
            value = memory.load(cells.pointer(5858), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43465)
            vm.pc = 43468
            vm.auxiliary = (0, 1868382209)
            tick(43468)
            vm.pc = 43473
            vm._write(5850, memory.load(cells.pointer(5849), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(43473)
            vm.pc = 43475
            vm._jump(1030)
            continue
        if vm.block == 1032:
            tick(43475)
            vm.pc = 43477
            vm._jump(1033)
            continue
        if vm.block == 1033:
            tick(43477)
            _phi(vm, 43477, (5859, 2, 145, 1032, 5860, 1034))
            tick(43484)
            vm.pc = 43489
            vm._write(5861, int(cells.value(5859) < cells.value(184)), 4, 'once18.unsigned_q')
            tick(43489)
            vm.pc = 43493
            vm._jump(1034 if cells.value(5861) != 0 else 1019)
            continue
        if vm.block == 1034:
            tick(43493)
            vm.pc = 43494
            tick(43494)
            vm.pc = 43497
            vm.auxiliary = (0, 5030)
            tick(43497)
            _single_control(vm)
            vm.pc = 43502
            count = memory.load(cells.pointer(169), 4)
            value = 0 if count & 0x80000000 or count >= 64 else cells.value(5859) << count
            vm._write(5862, value, 8, "typed.selector3.q")
            tick(43502)
            vm.pc = 43507
            value = memory.load(cells.pointer(5848), 8)
            count = memory.load(cells.pointer(5862), 1)
            vm._write(5863, value >> (count & 63), 8, 'once8.logical_shift')
            tick(43507)
            vm.pc = 43512
            vm._write(5864, cells.value(5863) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43512)
            _pointer(vm, 43512, 194, 4391, 5865, (145, 5859))
            tick(43520)
            vm.pc = 43524
            value = memory.load(cells.value(5865), 8)
            vm._write(5866, value, 8, 'high.load')
            tick(43524)
            _pointer(vm, 43524, 1, 5554, 5867, (5866,))
            tick(43531)
            vm.pc = 43535
            value = memory.load(cells.value(5867), 1)
            vm._write(5868, value, 4, 'high.load')
            tick(43535)
            vm.pc = 43540
            vm._write(5869, cells.value(5863) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43540)
            vm.pc = 43543
            vm.auxiliary = (0, 15934)
            tick(43543)
            vm.pc = 43549
            vm._write(5870, memory.load(cells.pointer(5869), 1, signed=True) ^ memory.load(cells.pointer(4582), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(43549)
            vm.pc = 43552
            vm.auxiliary = (0, 46150)
            tick(43552)
            vm.pc = 43557
            vm._write(5871, memory.load(cells.pointer(5868), 1, signed=True) & memory.load(cells.pointer(5870), 1, signed=True), 8, 'typed.selector1.q')
            tick(43557)
            vm.pc = 43560
            vm.auxiliary = (0, 36462)
            tick(43560)
            vm.pc = 43566
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5872, memory.load(cells.pointer(5868), 1, signed=True) ^ memory.load(cells.pointer(4582), 1, signed=True), 8, 'typed.selector5.q')
            tick(43566)
            vm.pc = 43569
            vm.auxiliary = (0, 22319)
            tick(43569)
            vm.pc = 43574
            vm._write(5873, memory.load(cells.pointer(5864), 1, signed=True) & memory.load(cells.pointer(5872), 1, signed=True), 8, 'typed.selector1.q')
            tick(43574)
            vm.pc = 43579
            vm._write(5874, memory.load(cells.pointer(5871), 1, signed=True) | memory.load(cells.pointer(5873), 1, signed=True), 8, 'L15.binary_q')
            tick(43579)
            _pointer(vm, 43579, 1, 5554, 5875, (5866,))
            tick(43586)
            vm.pc = 43590
            pointer = cells.value(5875)
            value = memory.load(cells.pointer(5874), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(43590)
            vm.pc = 43593
            vm.auxiliary = (0, 665317378)
            tick(43593)
            vm.pc = 43598
            vm._write(5860, memory.load(cells.pointer(5859), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(43598)
            vm.pc = 43600
            vm._jump(1033)
            continue
        if vm.block == 1019:
            tick(43600)
            vm.pc = 43601
            tick(43601)
            vm.pc = 43604
            vm.auxiliary = (0, 216170498)
            tick(43604)
            vm.pc = 43609
            vm._write(5820, memory.load(cells.pointer(5819), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(43609)
            vm.pc = 43611
            vm._jump(1018)
            continue
        if vm.block == 1029:
            tick(43611)
            vm.pc = 43613
            vm._jump(1035)
            continue
        if vm.block == 1035:
            tick(43613)
            _phi(vm, 43613, (5876, 2, 145, 1029, 5877, 1036))
            tick(43620)
            vm.pc = 43625
            vm._write(5878, int(cells.value(5876) < cells.value(166)), 4, 'once18.unsigned_q')
            tick(43625)
            vm.pc = 43629
            vm._jump(1037 if cells.value(5878) != 0 else 1038)
            continue
        if vm.block == 1037:
            tick(43629)
            vm.pc = 43634
            vm._write(5879, cells.value(5876) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43634)
            vm.pc = 43635
            tick(43635)
            vm.pc = 43638
            vm.auxiliary = (0, 1916948482)
            tick(43638)
            vm.pc = 43643
            vm._write(5880, memory.load(cells.pointer(5879), 2, signed=True) + memory.load(cells.pointer(5408), 2, signed=True), 8, 'once1.integer')
            tick(43643)
            vm.pc = 43648
            value = memory.load(cells.pointer(5880), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(5881, value >> (count & 31), 4, 'once8.logical_shift')
            tick(43648)
            _pointer(vm, 43648, 91, 112, 5882, (145, 391))
            tick(43656)
            vm.pc = 43660
            value = memory.load(cells.value(5882), 8)
            vm._write(5883, value, 8, 'high.load')
            tick(43660)
            vm.pc = 43665
            vm._write(5884, cells.value(5883) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43665)
            vm.pc = 43668
            vm.auxiliary = (0, 9997)
            tick(43668)
            vm.pc = 43673
            vm._write(5885, memory.load(cells.pointer(5884), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(43673)
            vm.pc = 43676
            vm.auxiliary = (0, 44412)
            tick(43676)
            vm.pc = 43682
            vm._write(5886, memory.load(cells.pointer(5881), 2, signed=True) ^ memory.load(cells.pointer(5885), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(43682)
            vm.pc = 43687
            _convert(vm, 8, 5886, 5887)
            tick(43687)
            _pointer(vm, 43687, 91, 112, 5888, (145, 311, 5887))
            tick(43696)
            vm.pc = 43700
            value = memory.load(cells.value(5888), 8)
            vm._write(5889, value, 8, 'L5.unsigned_load')
            tick(43700)
            vm.pc = 43703
            vm.auxiliary = (0, 1505921731)
            tick(43703)
            vm.pc = 43708
            vm._write(5890, int(memory.load(cells.pointer(5889), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(43708)
            vm.pc = 43712
            vm._jump(1039 if cells.value(5890) != 0 else 1040)
            continue
        if vm.block == 1040:
            tick(43712)
            vm.pc = 43717
            value = memory.load(cells.pointer(5883), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(5891, value >> (count & 63), 8, 'once8.logical_shift')
            tick(43717)
            vm.pc = 43722
            vm._write(5892, cells.value(5891) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43722)
            vm.pc = 43727
            vm._write(5893, memory.load(cells.pointer(5892), 2, signed=True) ^ memory.load(cells.pointer(5880), 2, signed=True), 8, 'L14.binary_q')
            tick(43727)
            vm.pc = 43732
            vm._write(5894, memory.load(cells.pointer(5893), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(43732)
            vm.pc = 43737
            _convert(vm, 8, 5894, 5895)
            tick(43737)
            _pointer(vm, 43737, 78, 5889, 5896, (5895,))
            tick(43744)
            vm.pc = 43748
            value = memory.load(cells.value(5896), 8)
            vm._write(5897, value, 8, 'high.load')
            tick(43748)
            vm.pc = 43749
            tick(43749)
            vm.pc = 43752
            vm.auxiliary = (0, 840081811)
            tick(43752)
            vm.pc = 43757
            vm._write(5898, int(memory.load(cells.pointer(5897), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(43757)
            vm.pc = 43761
            vm._jump(1039 if cells.value(5898) != 0 else 1041)
            continue
        if vm.block == 1041:
            tick(43761)
            _pointer(vm, 43761, 79, 5897, 5899, (145, 269))
            tick(43769)
            vm.pc = 43773
            value = memory.load(cells.value(5899), 2)
            vm._write(5900, value, 4, 'high.load')
            tick(43773)
            vm.pc = 43774
            tick(43774)
            vm.pc = 43777
            vm.auxiliary = (0, 2001897731)
            tick(43777)
            _equal(vm, 43782, 2, 5900, 5880, 5901)
            tick(43782)
            vm.pc = 43786
            vm._jump(1042 if cells.value(5901) != 0 else 1039)
            continue
        if vm.block == 1042:
            tick(43786)
            _pointer(vm, 43786, 79, 5897, 5902, (145, 360))
            tick(43794)
            vm.pc = 43798
            value = memory.load(cells.value(5902), 4)
            vm._write(5903, value, 4, 'high.load')
            tick(43798)
            _pointer(vm, 43798, 79, 5897, 5904, (145, 158))
            tick(43806)
            vm.pc = 43810
            value = memory.load(cells.value(5904), 4)
            vm._write(5905, value, 4, 'high.load')
            tick(43810)
            vm.pc = 43811
            tick(43811)
            vm.pc = 43814
            vm.auxiliary = (0, 34821)
            tick(43814)
            vm.pc = 43820
            vm._write(5906, memory.load(cells.pointer(5905), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(43820)
            vm.pc = 43823
            vm.auxiliary = (0, 666944004)
            tick(43823)
            vm.pc = 43828
            vm._write(5907, memory.load(cells.pointer(5906), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(43828)
            _pointer(vm, 43828, 79, 5897, 5908, (145, 269))
            tick(43836)
            vm.pc = 43840
            value = memory.load(cells.value(5908), 2)
            vm._write(5909, value, 4, 'high.load')
            tick(43840)
            vm.pc = 43845
            _convert(vm, 4, 5909, 5910)
            tick(43845)
            vm.pc = 43848
            vm.auxiliary = (0, 31533)
            tick(43848)
            vm.pc = 43854
            vm._write(5911, memory.load(cells.pointer(5907), 4, signed=True) ^ memory.load(cells.pointer(5910), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(43854)
            vm.pc = 43857
            vm.auxiliary = (0, 869331460)
            tick(43857)
            vm.pc = 43862
            vm._write(5912, memory.load(cells.pointer(5911), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(43862)
            _pointer(vm, 43862, 79, 5897, 5913, (145, 311))
            tick(43870)
            vm.pc = 43874
            value = memory.load(cells.value(5913), 8)
            vm._write(5914, value, 8, 'high.load')
            tick(43874)
            vm.pc = 43879
            cells.copy_q_clear_owned(5914, 5915)
            tick(43879)
            vm.pc = 43884
            vm._write(5916, cells.value(5915) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43884)
            vm.pc = 43889
            vm._write(5917, memory.load(cells.pointer(5912), 4, signed=True) ^ memory.load(cells.pointer(5916), 4, signed=True), 8, 'L14.binary_q')
            tick(43889)
            vm.pc = 43892
            vm.auxiliary = (0, 457257476)
            tick(43892)
            vm.pc = 43897
            vm._write(5918, memory.load(cells.pointer(5917), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(43897)
            vm.pc = 43902
            value = memory.load(cells.pointer(5915), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5919, value >> (count & 63), 8, 'once8.logical_shift')
            tick(43902)
            vm.pc = 43907
            vm._write(5920, cells.value(5919) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43907)
            vm.pc = 43910
            vm.auxiliary = (0, 15487)
            tick(43910)
            vm.pc = 43916
            vm._write(5921, memory.load(cells.pointer(5918), 4, signed=True) ^ memory.load(cells.pointer(5920), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(43916)
            vm.pc = 43919
            vm.auxiliary = (0, 1516552707)
            tick(43919)
            vm.pc = 43924
            vm._write(5922, memory.load(cells.pointer(5921), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(43924)
            vm.pc = 43929
            vm._write(5923, cells.value(5883) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43929)
            vm.pc = 43934
            vm._write(5924, memory.load(cells.pointer(5922), 4, signed=True) ^ memory.load(cells.pointer(5923), 4, signed=True), 8, 'L14.binary_q')
            tick(43934)
            vm.pc = 43937
            vm.auxiliary = (0, 1159156228)
            tick(43937)
            vm.pc = 43942
            vm._write(5925, memory.load(cells.pointer(5924), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(43942)
            vm.pc = 43947
            value = memory.load(cells.pointer(5883), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5926, value >> (count & 63), 8, 'once8.logical_shift')
            tick(43947)
            vm.pc = 43952
            vm._write(5927, cells.value(5926) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(43952)
            vm.pc = 43955
            vm.auxiliary = (0, 15716)
            tick(43955)
            vm.pc = 43961
            vm._write(5928, memory.load(cells.pointer(5925), 4, signed=True) ^ memory.load(cells.pointer(5927), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(43961)
            vm.pc = 43964
            vm.auxiliary = (0, 768131587)
            tick(43964)
            vm.pc = 43969
            vm._write(5929, memory.load(cells.pointer(5928), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(43969)
            vm.pc = 43973
            value = memory.load(cells.value(5914), 1)
            vm._write(5930, value, 4, 'high.load')
            tick(43973)
            vm.pc = 43978
            _convert(vm, 4, 5930, 5931)
            tick(43978)
            vm.pc = 43983
            vm._write(5932, memory.load(cells.pointer(5929), 4, signed=True) ^ memory.load(cells.pointer(5931), 4, signed=True), 8, 'L14.binary_q')
            tick(43983)
            vm.pc = 43986
            vm.auxiliary = (0, 1071849988)
            tick(43986)
            vm.pc = 43991
            vm._write(5933, memory.load(cells.pointer(5932), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(43991)
            vm.pc = 43994
            vm.auxiliary = (0, 1194470531)
            tick(43994)
            _equal(vm, 43999, 4, 5903, 5933, 5934)
            tick(43999)
            vm.pc = 44003
            vm._jump(1039 if cells.value(5934) != 0 else 1043)
            continue
        if vm.block == 1043:
            tick(44003)
            vm.pc = 44007
            pointer = cells.value(5902)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(44007)
            vm.pc = 44009
            vm._jump(1039)
            continue
        if vm.block == 1039:
            tick(44009)
            _phi(vm, 44009, (5935, 5, 857, 1037, 857, 1041, 5897, 1042, 5897, 1043, 5897, 1040))
            tick(44022)
            vm.pc = 44023
            tick(44023)
            vm.pc = 44026
            vm.auxiliary = (0, 879887827)
            tick(44026)
            _equal(vm, 44031, 8, 5935, 857, 5936)
            tick(44031)
            vm.pc = 44035
            vm._jump(1036 if cells.value(5936) != 0 else 1044)
            continue
        if vm.block == 1044:
            tick(44035)
            _pointer(vm, 44035, 194, 4391, 5937, (145, 5876))
            tick(44043)
            vm.pc = 44047
            value = memory.load(cells.value(5937), 8)
            vm._write(5938, value, 8, 'high.load')
            tick(44047)
            _pointer(vm, 44047, 1, 5554, 5939, (5938,))
            tick(44054)
            vm.pc = 44058
            value = memory.load(cells.value(5939), 1)
            vm._write(5940, value, 4, 'high.load')
            tick(44058)
            _pointer(vm, 44058, 79, 5935, 5941, (145, 311))
            tick(44066)
            vm.pc = 44070
            value = memory.load(cells.value(5941), 8)
            vm._write(5942, value, 8, 'high.load')
            tick(44070)
            vm.pc = 44074
            pointer = cells.value(5942)
            value = memory.load(cells.pointer(5940), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(44074)
            vm.pc = 44076
            vm._jump(1036)
            continue
        if vm.block == 1036:
            tick(44076)
            vm.pc = 44077
            tick(44077)
            vm.pc = 44080
            vm.auxiliary = (0, 1971949569)
            tick(44080)
            vm.pc = 44085
            vm._write(5877, memory.load(cells.pointer(5876), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(44085)
            vm.pc = 44087
            vm._jump(1035)
            continue
        if vm.block == 1038:
            tick(44087)
            vm.pc = 44091
            value = memory.load(cells.value(130), 1)
            vm._write(5943, value, 4, 'high.load')
            tick(44091)
            vm.pc = 44093
            vm._jump(1045)
            continue
        if vm.block == 1045:
            tick(44093)
            _phi(vm, 44093, (5944, 2, 5945, 1046, 145, 1038))
            tick(44100)
            vm.pc = 44105
            vm._write(5946, int(cells.value(5944) < cells.value(190)), 4, 'once18.unsigned_q')
            tick(44105)
            vm.pc = 44109
            vm._jump(1047 if cells.value(5946) != 0 else 1048)
            continue
        if vm.block == 1047:
            tick(44109)
            vm.pc = 44114
            vm._write(5947, cells.value(5944) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44114)
            vm.pc = 44115
            tick(44115)
            vm.pc = 44118
            vm.auxiliary = (0, 655683585)
            tick(44118)
            vm.pc = 44123
            vm._write(5948, memory.load(cells.pointer(5947), 2, signed=True) + memory.load(cells.pointer(3272), 2, signed=True), 8, 'once1.integer')
            tick(44123)
            vm.pc = 44128
            value = memory.load(cells.pointer(5948), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(5949, value >> (count & 31), 4, 'once8.logical_shift')
            tick(44128)
            _pointer(vm, 44128, 91, 112, 5950, (145, 391))
            tick(44136)
            vm.pc = 44140
            value = memory.load(cells.value(5950), 8)
            vm._write(5951, value, 8, 'high.load')
            tick(44140)
            vm.pc = 44145
            vm._write(5952, cells.value(5951) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44145)
            vm.pc = 44150
            vm._write(5953, memory.load(cells.pointer(5952), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(44150)
            vm.pc = 44155
            vm._write(5954, memory.load(cells.pointer(5949), 2, signed=True) ^ memory.load(cells.pointer(5953), 2, signed=True), 8, 'L14.binary_q')
            tick(44155)
            vm.pc = 44160
            _convert(vm, 8, 5954, 5955)
            tick(44160)
            _pointer(vm, 44160, 91, 112, 5956, (145, 311, 5955))
            tick(44169)
            vm.pc = 44173
            value = memory.load(cells.value(5956), 8)
            vm._write(5957, value, 8, 'high.load')
            tick(44173)
            vm.pc = 44176
            vm.auxiliary = (0, 1086510211)
            tick(44176)
            vm.pc = 44181
            vm._write(5958, int(memory.load(cells.pointer(5957), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(44181)
            vm.pc = 44185
            vm._jump(1049 if cells.value(5958) != 0 else 1050)
            continue
        if vm.block == 1050:
            tick(44185)
            vm.pc = 44190
            value = memory.load(cells.pointer(5951), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(5959, value >> (count & 63), 8, 'once8.logical_shift')
            tick(44190)
            vm.pc = 44195
            vm._write(5960, cells.value(5959) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44195)
            vm.pc = 44196
            tick(44196)
            vm.pc = 44199
            vm.auxiliary = (0, 23326)
            tick(44199)
            vm.pc = 44205
            vm._write(5961, memory.load(cells.pointer(5960), 2, signed=True) ^ memory.load(cells.pointer(5948), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(44205)
            vm.pc = 44210
            vm._write(5962, memory.load(cells.pointer(5961), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(44210)
            vm.pc = 44215
            _convert(vm, 8, 5962, 5963)
            tick(44215)
            _pointer(vm, 44215, 78, 5957, 5964, (5963,))
            tick(44222)
            vm.pc = 44226
            value = memory.load(cells.value(5964), 8)
            vm._write(5965, value, 8, 'high.load')
            tick(44226)
            vm.pc = 44229
            vm.auxiliary = (0, 1201818723)
            tick(44229)
            vm.pc = 44234
            vm._write(5966, int(memory.load(cells.pointer(5965), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(44234)
            vm.pc = 44238
            vm._jump(1049 if cells.value(5966) != 0 else 1051)
            continue
        if vm.block == 1051:
            tick(44238)
            _pointer(vm, 44238, 79, 5965, 5967, (145, 269))
            tick(44246)
            vm.pc = 44250
            value = memory.load(cells.value(5967), 2)
            vm._write(5968, value, 4, 'high.load')
            tick(44250)
            vm.pc = 44251
            tick(44251)
            vm.pc = 44254
            vm.auxiliary = (0, 1692579523)
            tick(44254)
            _equal(vm, 44259, 2, 5968, 5948, 5969)
            tick(44259)
            vm.pc = 44263
            vm._jump(1052 if cells.value(5969) != 0 else 1049)
            continue
        if vm.block == 1052:
            tick(44263)
            _pointer(vm, 44263, 79, 5965, 5970, (145, 360))
            tick(44271)
            vm.pc = 44275
            value = memory.load(cells.value(5970), 4)
            vm._write(5971, value, 4, 'high.load')
            tick(44275)
            _pointer(vm, 44275, 79, 5965, 5972, (145, 158))
            tick(44283)
            vm.pc = 44287
            value = memory.load(cells.value(5972), 4)
            vm._write(5973, value, 4, 'high.load')
            tick(44287)
            vm.pc = 44288
            tick(44288)
            vm.pc = 44291
            vm.auxiliary = (0, 10343)
            tick(44291)
            vm.pc = 44297
            vm._write(5974, memory.load(cells.pointer(5973), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(44297)
            vm.pc = 44300
            vm.auxiliary = (0, 217977348)
            tick(44300)
            vm.pc = 44305
            vm._write(5975, memory.load(cells.pointer(5974), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44305)
            _pointer(vm, 44305, 79, 5965, 5976, (145, 269))
            tick(44313)
            vm.pc = 44317
            value = memory.load(cells.value(5976), 2)
            vm._write(5977, value, 4, 'high.load')
            tick(44317)
            vm.pc = 44322
            _convert(vm, 4, 5977, 5978)
            tick(44322)
            vm.pc = 44327
            vm._write(5979, memory.load(cells.pointer(5975), 4, signed=True) ^ memory.load(cells.pointer(5978), 4, signed=True), 8, 'L14.binary_q')
            tick(44327)
            vm.pc = 44330
            vm.auxiliary = (0, 1368805891)
            tick(44330)
            vm.pc = 44335
            vm._write(5980, memory.load(cells.pointer(5979), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44335)
            _pointer(vm, 44335, 79, 5965, 5981, (145, 311))
            tick(44343)
            vm.pc = 44347
            value = memory.load(cells.value(5981), 8)
            vm._write(5982, value, 8, 'high.load')
            tick(44347)
            vm.pc = 44352
            cells.copy_q_clear_owned(5982, 5983)
            tick(44352)
            vm.pc = 44357
            vm._write(5984, cells.value(5983) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44357)
            vm.pc = 44360
            vm.auxiliary = (0, 27495)
            tick(44360)
            vm.pc = 44366
            vm._write(5985, memory.load(cells.pointer(5980), 4, signed=True) ^ memory.load(cells.pointer(5984), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(44366)
            vm.pc = 44369
            vm.auxiliary = (0, 505369091)
            tick(44369)
            vm.pc = 44374
            vm._write(5986, memory.load(cells.pointer(5985), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44374)
            vm.pc = 44379
            value = memory.load(cells.pointer(5983), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5987, value >> (count & 63), 8, 'once8.logical_shift')
            tick(44379)
            vm.pc = 44384
            vm._write(5988, cells.value(5987) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44384)
            vm.pc = 44387
            vm.auxiliary = (0, 63844)
            tick(44387)
            vm.pc = 44393
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(5989, memory.load(cells.pointer(5986), 4, signed=True) ^ memory.load(cells.pointer(5988), 4, signed=True), 8, 'typed.selector5.q')
            tick(44393)
            vm.pc = 44396
            vm.auxiliary = (0, 1208173060)
            tick(44396)
            vm.pc = 44401
            vm._write(5990, memory.load(cells.pointer(5989), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44401)
            vm.pc = 44406
            vm._write(5991, cells.value(5951) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44406)
            vm.pc = 44409
            vm.auxiliary = (0, 31236)
            tick(44409)
            vm.pc = 44415
            vm._write(5992, memory.load(cells.pointer(5990), 4, signed=True) ^ memory.load(cells.pointer(5991), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(44415)
            vm.pc = 44418
            vm.auxiliary = (0, 1173856772)
            tick(44418)
            vm.pc = 44423
            vm._write(5993, memory.load(cells.pointer(5992), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44423)
            vm.pc = 44428
            value = memory.load(cells.pointer(5951), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(5994, value >> (count & 63), 8, 'once8.logical_shift')
            tick(44428)
            vm.pc = 44433
            vm._write(5995, cells.value(5994) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44433)
            vm.pc = 44436
            vm.auxiliary = (0, 6663)
            tick(44436)
            vm.pc = 44442
            vm._write(5996, memory.load(cells.pointer(5993), 4, signed=True) ^ memory.load(cells.pointer(5995), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(44442)
            vm.pc = 44445
            vm.auxiliary = (0, 1560777219)
            tick(44445)
            vm.pc = 44450
            vm._write(5997, memory.load(cells.pointer(5996), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44450)
            vm.pc = 44454
            value = memory.load(cells.value(5982), 1)
            vm._write(5998, value, 4, 'L5.unsigned_load')
            tick(44454)
            vm.pc = 44459
            _convert(vm, 4, 5998, 5999)
            tick(44459)
            vm.pc = 44462
            vm.auxiliary = (0, 60677)
            tick(44462)
            vm.pc = 44468
            vm._write(6000, memory.load(cells.pointer(5997), 4, signed=True) ^ memory.load(cells.pointer(5999), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(44468)
            vm.pc = 44471
            vm.auxiliary = (0, 2126193156)
            tick(44471)
            vm.pc = 44476
            vm._write(6001, memory.load(cells.pointer(6000), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44476)
            vm.pc = 44479
            vm.auxiliary = (0, 2034423523)
            tick(44479)
            vm.pc = 44484
            vm._write(6002, int(memory.load(cells.pointer(5971), 4, signed=True) == memory.load(cells.pointer(6001), 4, signed=True)), 4, 'once17.integer')
            tick(44484)
            vm.pc = 44488
            vm._jump(1049 if cells.value(6002) != 0 else 1053)
            continue
        if vm.block == 1053:
            tick(44488)
            vm.pc = 44492
            pointer = cells.value(5970)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(44492)
            vm.pc = 44494
            vm._jump(1049)
            continue
        if vm.block == 1049:
            tick(44494)
            _phi(vm, 44494, (6003, 5, 857, 1047, 857, 1051, 5965, 1052, 5965, 1053, 5965, 1050))
            tick(44507)
            vm.pc = 44512
            vm._write(6004, cells.value(5944) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44512)
            vm.pc = 44513
            tick(44513)
            vm.pc = 44516
            vm.auxiliary = (0, 819556353)
            tick(44516)
            vm.pc = 44521
            vm._write(6005, memory.load(cells.pointer(6004), 2, signed=True) + memory.load(cells.pointer(3408), 2, signed=True), 8, 'once1.integer')
            tick(44521)
            vm.pc = 44526
            value = memory.load(cells.pointer(6005), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(6006, value >> (count & 31), 4, 'once8.logical_shift')
            tick(44526)
            _pointer(vm, 44526, 91, 112, 6007, (145, 391))
            tick(44534)
            vm.pc = 44538
            value = memory.load(cells.value(6007), 8)
            vm._write(6008, value, 8, 'high.load')
            tick(44538)
            vm.pc = 44543
            vm._write(6009, cells.value(6008) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44543)
            vm.pc = 44546
            vm.auxiliary = (0, 12845)
            tick(44546)
            vm.pc = 44551
            vm._write(6010, memory.load(cells.pointer(6009), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(44551)
            vm.pc = 44554
            vm.auxiliary = (0, 24125)
            tick(44554)
            vm.pc = 44560
            vm._write(6011, memory.load(cells.pointer(6006), 2, signed=True) ^ memory.load(cells.pointer(6010), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(44560)
            vm.pc = 44565
            _convert(vm, 8, 6011, 6012)
            tick(44565)
            _pointer(vm, 44565, 91, 112, 6013, (145, 311, 6012))
            tick(44574)
            vm.pc = 44578
            value = memory.load(cells.value(6013), 8)
            vm._write(6014, value, 8, 'high.load')
            tick(44578)
            vm.pc = 44581
            vm.auxiliary = (0, 498205827)
            tick(44581)
            _equal(vm, 44586, 8, 6014, 1140, 6015)
            tick(44586)
            vm.pc = 44590
            vm._jump(1054 if cells.value(6015) != 0 else 1055)
            continue
        if vm.block == 1055:
            tick(44590)
            vm.pc = 44595
            value = memory.load(cells.pointer(6008), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(6016, value >> (count & 63), 8, 'once8.logical_shift')
            tick(44595)
            vm.pc = 44600
            vm._write(6017, cells.value(6016) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44600)
            vm.pc = 44601
            tick(44601)
            vm.pc = 44604
            vm.auxiliary = (0, 61007)
            tick(44604)
            vm.pc = 44610
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6018, memory.load(cells.pointer(6017), 2, signed=True) ^ memory.load(cells.pointer(6005), 2, signed=True), 8, 'typed.selector5.q')
            tick(44610)
            vm.pc = 44615
            vm._write(6019, memory.load(cells.pointer(6018), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'L13.binary_q')
            tick(44615)
            vm.pc = 44620
            _convert(vm, 8, 6019, 6020)
            tick(44620)
            _pointer(vm, 44620, 78, 6014, 6021, (6020,))
            tick(44627)
            vm.pc = 44631
            value = memory.load(cells.value(6021), 8)
            vm._write(6022, value, 8, 'high.load')
            tick(44631)
            vm.pc = 44634
            vm.auxiliary = (0, 447883395)
            tick(44634)
            vm.pc = 44639
            vm._write(6023, int(memory.load(cells.pointer(6022), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(44639)
            vm.pc = 44643
            vm._jump(1054 if cells.value(6023) != 0 else 1056)
            continue
        if vm.block == 1056:
            tick(44643)
            _pointer(vm, 44643, 79, 6022, 6024, (145, 269))
            tick(44651)
            vm.pc = 44655
            value = memory.load(cells.value(6024), 2)
            vm._write(6025, value, 4, 'high.load')
            tick(44655)
            vm.pc = 44656
            tick(44656)
            vm.pc = 44659
            vm.auxiliary = (0, 1298301235)
            tick(44659)
            vm.pc = 44664
            vm._write(6026, int(memory.load(cells.pointer(6025), 2, signed=True) == memory.load(cells.pointer(6005), 2, signed=True)), 4, 'once17.integer')
            tick(44664)
            vm.pc = 44668
            vm._jump(1057 if cells.value(6026) != 0 else 1054)
            continue
        if vm.block == 1057:
            tick(44668)
            _pointer(vm, 44668, 79, 6022, 6027, (145, 360))
            tick(44676)
            vm.pc = 44680
            value = memory.load(cells.value(6027), 4)
            vm._write(6028, value, 4, 'high.load')
            tick(44680)
            _pointer(vm, 44680, 79, 6022, 6029, (145, 158))
            tick(44688)
            vm.pc = 44692
            value = memory.load(cells.value(6029), 4)
            vm._write(6030, value, 4, 'high.load')
            tick(44692)
            vm.pc = 44697
            vm._write(6031, memory.load(cells.pointer(6030), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'L14.binary_q')
            tick(44697)
            vm.pc = 44698
            tick(44698)
            vm.pc = 44701
            vm.auxiliary = (0, 813105668)
            tick(44701)
            vm.pc = 44706
            vm._write(6032, memory.load(cells.pointer(6031), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44706)
            _pointer(vm, 44706, 79, 6022, 6033, (145, 269))
            tick(44714)
            vm.pc = 44718
            value = memory.load(cells.value(6033), 2)
            vm._write(6034, value, 4, 'high.load')
            tick(44718)
            vm.pc = 44723
            _convert(vm, 4, 6034, 6035)
            tick(44723)
            vm.pc = 44728
            vm._write(6036, memory.load(cells.pointer(6032), 4, signed=True) ^ memory.load(cells.pointer(6035), 4, signed=True), 8, 'L14.binary_q')
            tick(44728)
            vm.pc = 44731
            vm.auxiliary = (0, 1824637444)
            tick(44731)
            vm.pc = 44736
            vm._write(6037, memory.load(cells.pointer(6036), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44736)
            _pointer(vm, 44736, 79, 6022, 6038, (145, 311))
            tick(44744)
            vm.pc = 44748
            value = memory.load(cells.value(6038), 8)
            vm._write(6039, value, 8, 'high.load')
            tick(44748)
            vm.pc = 44753
            cells.copy_q_clear_owned(6039, 6040)
            tick(44753)
            vm.pc = 44758
            vm._write(6041, cells.value(6040) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44758)
            vm.pc = 44761
            vm.auxiliary = (0, 22878)
            tick(44761)
            vm.pc = 44767
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6042, memory.load(cells.pointer(6037), 4, signed=True) ^ memory.load(cells.pointer(6041), 4, signed=True), 8, 'typed.selector5.q')
            tick(44767)
            vm.pc = 44770
            vm.auxiliary = (0, 2078827011)
            tick(44770)
            vm.pc = 44775
            vm._write(6043, memory.load(cells.pointer(6042), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44775)
            vm.pc = 44780
            value = memory.load(cells.pointer(6040), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6044, value >> (count & 63), 8, 'once8.logical_shift')
            tick(44780)
            vm.pc = 44785
            vm._write(6045, cells.value(6044) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44785)
            vm.pc = 44790
            vm._write(6046, memory.load(cells.pointer(6043), 4, signed=True) ^ memory.load(cells.pointer(6045), 4, signed=True), 8, 'L14.binary_q')
            tick(44790)
            vm.pc = 44793
            vm.auxiliary = (0, 1017745923)
            tick(44793)
            vm.pc = 44798
            vm._write(6047, memory.load(cells.pointer(6046), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44798)
            vm.pc = 44803
            vm._write(6048, cells.value(6008) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44803)
            vm.pc = 44806
            vm.auxiliary = (0, 27181)
            tick(44806)
            vm.pc = 44812
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6049, memory.load(cells.pointer(6047), 4, signed=True) ^ memory.load(cells.pointer(6048), 4, signed=True), 8, 'typed.selector5.q')
            tick(44812)
            vm.pc = 44815
            vm.auxiliary = (0, 364573188)
            tick(44815)
            vm.pc = 44820
            vm._write(6050, memory.load(cells.pointer(6049), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44820)
            vm.pc = 44825
            value = memory.load(cells.pointer(6008), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6051, value >> (count & 63), 8, 'once8.logical_shift')
            tick(44825)
            vm.pc = 44830
            vm._write(6052, cells.value(6051) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(44830)
            vm.pc = 44833
            vm.auxiliary = (0, 27719)
            tick(44833)
            vm.pc = 44839
            vm._write(6053, memory.load(cells.pointer(6050), 4, signed=True) ^ memory.load(cells.pointer(6052), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(44839)
            vm.pc = 44842
            vm.auxiliary = (0, 361517572)
            tick(44842)
            vm.pc = 44847
            vm._write(6054, memory.load(cells.pointer(6053), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44847)
            vm.pc = 44851
            value = memory.load(cells.value(6039), 1)
            vm._write(6055, value, 4, 'high.load')
            tick(44851)
            vm.pc = 44856
            _convert(vm, 4, 6055, 6056)
            tick(44856)
            vm.pc = 44859
            vm.auxiliary = (0, 6197)
            tick(44859)
            vm.pc = 44865
            vm._write(6057, memory.load(cells.pointer(6054), 4, signed=True) ^ memory.load(cells.pointer(6056), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(44865)
            vm.pc = 44868
            vm.auxiliary = (0, 616210948)
            tick(44868)
            vm.pc = 44873
            vm._write(6058, memory.load(cells.pointer(6057), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(44873)
            vm.pc = 44876
            vm.auxiliary = (0, 1609731699)
            tick(44876)
            _equal(vm, 44881, 4, 6028, 6058, 6059)
            tick(44881)
            vm.pc = 44885
            vm._jump(1054 if cells.value(6059) != 0 else 1058)
            continue
        if vm.block == 1058:
            tick(44885)
            vm.pc = 44889
            pointer = cells.value(6027)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(44889)
            vm.pc = 44891
            vm._jump(1054)
            continue
        if vm.block == 1054:
            tick(44891)
            _phi(vm, 44891, (6060, 5, 857, 1049, 857, 1056, 6022, 1057, 6022, 1058, 6022, 1055))
            tick(44904)
            vm.pc = 44905
            tick(44905)
            vm.pc = 44908
            vm.auxiliary = (0, 1779584500)
            tick(44908)
            vm.pc = 44913
            vm._write(6061, int(memory.load(cells.pointer(6003), 8, signed=True) != memory.load(cells.pointer(857), 8, signed=True)), 4, 'L27.comparison')
            tick(44913)
            vm.pc = 44916
            vm.auxiliary = (0, 884125924)
            tick(44916)
            vm.pc = 44921
            vm._write(6062, int(memory.load(cells.pointer(6060), 8, signed=True) != memory.load(cells.pointer(857), 8, signed=True)), 4, 'L27.comparison')
            tick(44921)
            vm.pc = 44924
            vm.auxiliary = (0, 53582)
            tick(44924)
            vm.pc = 44929
            vm._write(6063, memory.load(cells.pointer(6061), 1, signed=True) & memory.load(cells.pointer(6062), 1, signed=True), 8, 'typed.selector1.q')
            tick(44929)
            vm.pc = 44933
            vm._jump(1059 if cells.value(6063) != 0 else 1046)
            continue
        if vm.block == 1046:
            tick(45040)
            vm.pc = 45041
            tick(45041)
            vm.pc = 45044
            vm.auxiliary = (0, 764198913)
            tick(45044)
            vm.pc = 45049
            vm._write(5945, memory.load(cells.pointer(5944), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(45049)
            vm.pc = 45051
            vm._jump(1045)
            continue
        if vm.block == 1048:
            tick(45051)
            vm.pc = 45055
            value = memory.load(cells.value(130), 1)
            vm._write(6081, value, 4, 'high.load')
            tick(45055)
            vm.pc = 45060
            cells.copy_q_clear_owned(59, 6082)
            tick(45060)
            vm.pc = 45064
            pointer = cells.value(59)
            value = memory.load(cells.pointer(145), 8)
            memory.store(pointer, value, 8, source='high.store')
            tick(45064)
            vm.pc = 45066
            vm._jump(1060)
            continue
        if vm.block == 1060:
            tick(45066)
            _phi(vm, 45066, (6083, 2, 145, 1048, 6084, 1061))
            tick(45073)
            vm.pc = 45078
            vm._write(6085, int(cells.value(6083) < cells.value(163)), 4, 'once18.unsigned_q')
            tick(45078)
            vm.pc = 45082
            vm._jump(1062 if cells.value(6085) != 0 else 1063)
            continue
        if vm.block == 1062:
            tick(45082)
            vm.pc = 45087
            vm._write(6086, cells.value(6083) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45087)
            vm.pc = 45088
            tick(45088)
            vm.pc = 45091
            vm.auxiliary = (0, 760512513)
            tick(45091)
            vm.pc = 45096
            vm._write(6087, memory.load(cells.pointer(6086), 2, signed=True) + memory.load(cells.pointer(1381), 2, signed=True), 8, 'once1.integer')
            tick(45096)
            vm.pc = 45101
            value = memory.load(cells.pointer(6087), 2)
            count = memory.load(cells.pointer(280), 1)
            vm._write(6088, value >> (count & 31), 4, 'once8.logical_shift')
            tick(45101)
            _pointer(vm, 45101, 91, 112, 6089, (145, 391))
            tick(45109)
            vm.pc = 45113
            value = memory.load(cells.value(6089), 8)
            vm._write(6090, value, 8, 'high.load')
            tick(45113)
            vm.pc = 45118
            vm._write(6091, cells.value(6090) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45118)
            vm.pc = 45121
            vm.auxiliary = (0, 5988)
            tick(45121)
            vm.pc = 45126
            vm._write(6092, memory.load(cells.pointer(6091), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(45126)
            vm.pc = 45131
            vm._write(6093, memory.load(cells.pointer(6088), 2, signed=True) ^ memory.load(cells.pointer(6092), 2, signed=True), 8, 'L14.binary_q')
            tick(45131)
            vm.pc = 45136
            _convert(vm, 8, 6093, 6094)
            tick(45136)
            _pointer(vm, 45136, 91, 112, 6095, (145, 311, 6094))
            tick(45145)
            vm.pc = 45149
            value = memory.load(cells.value(6095), 8)
            vm._write(6096, value, 8, 'high.load')
            tick(45149)
            vm.pc = 45152
            vm.auxiliary = (0, 179457779)
            tick(45152)
            vm.pc = 45157
            vm._write(6097, int(memory.load(cells.pointer(6096), 8, signed=True) == memory.load(cells.pointer(1140), 8, signed=True)), 4, 'once17.integer')
            tick(45157)
            vm.pc = 45161
            vm._jump(1064 if cells.value(6097) != 0 else 1065)
            continue
        if vm.block == 1065:
            tick(45161)
            vm.pc = 45166
            value = memory.load(cells.pointer(6090), 8)
            count = memory.load(cells.pointer(184), 1)
            vm._write(6098, value >> (count & 63), 8, 'once8.logical_shift')
            tick(45166)
            vm.pc = 45171
            vm._write(6099, cells.value(6098) & 65535, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45171)
            vm.pc = 45172
            tick(45172)
            vm.pc = 45175
            vm.auxiliary = (0, 39727)
            tick(45175)
            vm.pc = 45181
            vm._write(6100, memory.load(cells.pointer(6099), 2, signed=True) ^ memory.load(cells.pointer(6087), 2, signed=True), 8, 'high.flag1_xor_q')
            tick(45181)
            vm.pc = 45184
            vm.auxiliary = (0, 33909)
            tick(45184)
            vm.pc = 45189
            vm._write(6101, memory.load(cells.pointer(6100), 2, signed=True) & memory.load(cells.pointer(1134), 2, signed=True), 8, 'typed.selector1.q')
            tick(45189)
            vm.pc = 45194
            _convert(vm, 8, 6101, 6102)
            tick(45194)
            _pointer(vm, 45194, 78, 6096, 6103, (6102,))
            tick(45201)
            vm.pc = 45205
            value = memory.load(cells.value(6103), 8)
            vm._write(6104, value, 8, 'high.load')
            tick(45205)
            vm.pc = 45208
            vm.auxiliary = (0, 1245901315)
            tick(45208)
            vm.pc = 45213
            vm._write(6105, int(memory.load(cells.pointer(6104), 8, signed=True) == memory.load(cells.pointer(857), 8, signed=True)), 4, 'once17.integer')
            tick(45213)
            vm.pc = 45217
            vm._jump(1064 if cells.value(6105) != 0 else 1066)
            continue
        if vm.block == 1066:
            tick(45217)
            _pointer(vm, 45217, 79, 6104, 6106, (145, 269))
            tick(45225)
            vm.pc = 45229
            value = memory.load(cells.value(6106), 2)
            vm._write(6107, value, 4, 'high.load')
            tick(45229)
            vm.pc = 45230
            tick(45230)
            vm.pc = 45233
            vm.auxiliary = (0, 400732579)
            tick(45233)
            vm.pc = 45238
            vm._write(6108, int(memory.load(cells.pointer(6107), 2, signed=True) == memory.load(cells.pointer(6087), 2, signed=True)), 4, 'once17.integer')
            tick(45238)
            vm.pc = 45242
            vm._jump(1067 if cells.value(6108) != 0 else 1064)
            continue
        if vm.block == 1067:
            tick(45242)
            _pointer(vm, 45242, 79, 6104, 6109, (145, 360))
            tick(45250)
            vm.pc = 45254
            value = memory.load(cells.value(6109), 4)
            vm._write(6110, value, 4, 'L5.unsigned_load')
            tick(45254)
            _pointer(vm, 45254, 79, 6104, 6111, (145, 158))
            tick(45262)
            vm.pc = 45266
            value = memory.load(cells.value(6111), 4)
            vm._write(6112, value, 4, 'high.load')
            tick(45266)
            vm.pc = 45267
            tick(45267)
            vm.pc = 45270
            vm.auxiliary = (0, 11300)
            tick(45270)
            vm.pc = 45276
            vm._write(6113, memory.load(cells.pointer(6112), 4, signed=True) ^ memory.load(cells.pointer(1157), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(45276)
            vm.pc = 45279
            vm.auxiliary = (0, 402780675)
            tick(45279)
            vm.pc = 45284
            vm._write(6114, memory.load(cells.pointer(6113), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45284)
            _pointer(vm, 45284, 79, 6104, 6115, (145, 269))
            tick(45292)
            vm.pc = 45296
            value = memory.load(cells.value(6115), 2)
            vm._write(6116, value, 4, 'high.load')
            tick(45296)
            vm.pc = 45301
            _convert(vm, 4, 6116, 6117)
            tick(45301)
            vm.pc = 45304
            vm.auxiliary = (0, 47972)
            tick(45304)
            vm.pc = 45310
            vm._write(6118, memory.load(cells.pointer(6114), 4, signed=True) ^ memory.load(cells.pointer(6117), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(45310)
            vm.pc = 45313
            vm.auxiliary = (0, 1725145603)
            tick(45313)
            vm.pc = 45318
            vm._write(6119, memory.load(cells.pointer(6118), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45318)
            _pointer(vm, 45318, 79, 6104, 6120, (145, 311))
            tick(45326)
            vm.pc = 45330
            value = memory.load(cells.value(6120), 8)
            vm._write(6121, value, 8, 'high.load')
            tick(45330)
            vm.pc = 45335
            cells.copy_q_clear_owned(6121, 6122)
            tick(45335)
            vm.pc = 45340
            vm._write(6123, cells.value(6122) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45340)
            vm.pc = 45343
            vm.auxiliary = (0, 39036)
            tick(45343)
            vm.pc = 45349
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6124, memory.load(cells.pointer(6119), 4, signed=True) ^ memory.load(cells.pointer(6123), 4, signed=True), 8, 'typed.selector5.q')
            tick(45349)
            vm.pc = 45352
            vm.auxiliary = (0, 1324167683)
            tick(45352)
            vm.pc = 45357
            vm._write(6125, memory.load(cells.pointer(6124), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45357)
            vm.pc = 45362
            value = memory.load(cells.pointer(6122), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6126, value >> (count & 63), 8, 'once8.logical_shift')
            tick(45362)
            vm.pc = 45367
            vm._write(6127, cells.value(6126) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45367)
            vm.pc = 45370
            vm.auxiliary = (0, 19470)
            tick(45370)
            vm.pc = 45376
            vm._write(6128, memory.load(cells.pointer(6125), 4, signed=True) ^ memory.load(cells.pointer(6127), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(45376)
            vm.pc = 45379
            vm.auxiliary = (0, 304243204)
            tick(45379)
            vm.pc = 45384
            vm._write(6129, memory.load(cells.pointer(6128), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45384)
            vm.pc = 45389
            vm._write(6130, cells.value(6090) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45389)
            vm.pc = 45392
            vm.auxiliary = (0, 51775)
            tick(45392)
            vm.pc = 45398
            vm._write(6131, memory.load(cells.pointer(6129), 4, signed=True) ^ memory.load(cells.pointer(6130), 4, signed=True), 8, 'high.flag1_xor_q')
            tick(45398)
            vm.pc = 45401
            vm.auxiliary = (0, 809681411)
            tick(45401)
            vm.pc = 45406
            vm._write(6132, memory.load(cells.pointer(6131), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45406)
            vm.pc = 45411
            value = memory.load(cells.pointer(6090), 8)
            count = memory.load(cells.pointer(421), 1)
            vm._write(6133, value >> (count & 63), 8, 'once8.logical_shift')
            tick(45411)
            vm.pc = 45416
            vm._write(6134, cells.value(6133) & 4294967295, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45416)
            vm.pc = 45419
            vm.auxiliary = (0, 32061)
            tick(45419)
            vm.pc = 45425
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6135, memory.load(cells.pointer(6132), 4, signed=True) ^ memory.load(cells.pointer(6134), 4, signed=True), 8, 'typed.selector5.q')
            tick(45425)
            vm.pc = 45428
            vm.auxiliary = (0, 1068425731)
            tick(45428)
            vm.pc = 45433
            vm._write(6136, memory.load(cells.pointer(6135), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45433)
            vm.pc = 45437
            value = memory.load(cells.value(6121), 1)
            vm._write(6137, value, 4, 'high.load')
            tick(45437)
            vm.pc = 45442
            _convert(vm, 4, 6137, 6138)
            tick(45442)
            vm.pc = 45447
            vm._write(6139, memory.load(cells.pointer(6136), 4, signed=True) ^ memory.load(cells.pointer(6138), 4, signed=True), 8, 'L14.binary_q')
            tick(45447)
            vm.pc = 45450
            vm.auxiliary = (0, 1116377603)
            tick(45450)
            vm.pc = 45455
            vm._write(6140, memory.load(cells.pointer(6139), 4, signed=True) * memory.load(cells.pointer(1159), 4, signed=True), 8, 'once0.integer')
            tick(45455)
            vm.pc = 45458
            vm.auxiliary = (0, 1026711603)
            tick(45458)
            _equal(vm, 45463, 4, 6110, 6140, 6141)
            tick(45463)
            vm.pc = 45467
            vm._jump(1064 if cells.value(6141) != 0 else 1068)
            continue
        if vm.block == 1068:
            tick(45467)
            vm.pc = 45471
            pointer = cells.value(6109)
            value = memory.load(cells.pointer(1188), 4)
            memory.store(pointer, value, 4, source='high.store')
            tick(45471)
            vm.pc = 45473
            vm._jump(1064)
            continue
        if vm.block == 1064:
            tick(45473)
            _phi(vm, 45473, (6142, 5, 857, 1062, 857, 1066, 6104, 1067, 6104, 1068, 6104, 1065))
            tick(45486)
            vm.pc = 45487
            tick(45487)
            vm.pc = 45490
            vm.auxiliary = (0, 804453715)
            tick(45490)
            _equal(vm, 45495, 8, 6142, 857, 6143)
            tick(45495)
            vm.pc = 45499
            vm._jump(1069 if cells.value(6143) != 0 else 1070)
            continue
        if vm.block == 1070:
            tick(45499)
            _pointer(vm, 45499, 79, 6142, 6144, (145, 311))
            tick(45507)
            vm.pc = 45511
            value = memory.load(cells.value(6144), 8)
            vm._write(6145, value, 8, 'high.load')
            tick(45511)
            vm.pc = 45515
            value = memory.load(cells.value(6145), 1)
            vm._write(6146, value, 4, 'high.load')
            tick(45515)
            _pointer(vm, 45515, 1, 6082, 6147, (6083,))
            tick(45522)
            vm.pc = 45526
            pointer = cells.value(6147)
            value = memory.load(cells.pointer(6146), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(45526)
            vm.pc = 45528
            vm._jump(1061)
            continue
        if vm.block == 1069:
            tick(45528)
            _pointer(vm, 45528, 1, 6082, 6148, (6083,))
            tick(45535)
            vm.pc = 45539
            pointer = cells.value(6148)
            value = memory.load(cells.pointer(235), 1)
            memory.store(pointer, value, 1, source='high.store')
            tick(45539)
            vm.pc = 45541
            vm._jump(1061)
            continue
        if vm.block == 1061:
            tick(45541)
            vm.pc = 45542
            tick(45542)
            vm.pc = 45545
            vm.auxiliary = (0, 1218732033)
            tick(45545)
            vm.pc = 45550
            vm._write(6084, memory.load(cells.pointer(6083), 8, signed=True) + memory.load(cells.pointer(163), 8, signed=True), 8, 'once1.integer')
            tick(45550)
            vm.pc = 45552
            vm._jump(1060)
            continue
        if vm.block == 1063:
            tick(45552)
            vm.pc = 45556
            value = memory.load(cells.value(59), 8)
            vm._write(6149, value, 8, 'high.load')
            tick(45556)
            vm.pc = 45561
            vm._write(6150, cells.value(6149) & 255, 8, 'once9.mask_q')
            _pair_control(vm)
            tick(45561)
            vm.pc = 45562
            tick(45562)
            vm.pc = 45565
            vm.auxiliary = (0, 40270)
            tick(45565)
            vm.pc = 45571
            vm._write(6151, memory.load(cells.pointer(6081), 1, signed=True) ^ memory.load(cells.pointer(6150), 1, signed=True), 8, 'high.flag1_xor_q')
            tick(45571)
            vm.pc = 45574
            vm.auxiliary = (0, 14862)
            tick(45574)
            vm.pc = 45580
            repeats = 2 if memory.load(vm.image_base + 0x677E1BC, 4) == 0x80000000 else 1
            for repeat in range(repeats):
                vm._write(6152, memory.load(cells.pointer(6151), 1, signed=True) ^ memory.load(cells.pointer(246), 1, signed=True), 8, 'typed.selector5.q')
            tick(45580)
            vm.pc = 45584
            pointer = cells.value(130)
            value = memory.load(cells.pointer(6152), 1)
            memory.store(pointer, value, 1, source='high.store')
            continue
        raise PrimarySemanticUnavailable('independent continuation left its source-bound blocks')
