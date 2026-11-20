from hashlib import sha256

from .local113_episode_validation import overlap, require
from .primary_sign import arena_reservation, load_program
from .primary_vm import PrimaryProgramLimit, PrimaryVM


PINS = {0x2DE4C87: ('host129-prepare', '0c413db7cc56ecdbb6f14b0f9e0c63444b06fa7aab13643db353d0f105682540'), 0x2DE5A3F: ('host129-select', 'f6fde5d2d386a51ac92f65329d946b0a53adcfdea554d996c6e38082802e33f1')}


def scalar_value(rva, argument):
    require(rva in PINS and type(argument) is int, 'SCALAR_HELPER_TARGET')
    value = argument & 0xFFFFFFFF
    return value | 40 if rva == 0x2DE5A3F else (value | 32) & 0xFFFFFFF7


def execute_prefix_scalar(runtime, parent, rva, cells, argument_types):
    from .primary_main_prefix_stop import _input_owner
    owner = _input_owner(runtime)
    require(owner is not None and owner.valid() and rva in PINS and parent.runtime is runtime and parent.memory is runtime.memory and parent.abort_reason is None, 'SCALAR_HELPER_OWNER')
    source = runtime._host129_api_binding.source
    source._host(runtime, parent)
    active = getattr(parent, '_primary_host129_active_call', None)
    require(type(active) is tuple and len(active) == 5, 'SCALAR_HELPER_CALL')
    word, callee, arguments, signature, destination = active
    require(cells == arguments and len(cells) == 1 and argument_types == parent.program.type(signature).parameters[3:] and parent.cells.value(callee) == runtime.image_base + rva and parent.host_calls[-1] == (word, runtime.image_base + rva, cells, signature) and parent.program.type(signature).parameters[2] == 1, 'SCALAR_HELPER_ABI')
    name, digest = PINS[rva]
    program = load_program(name)
    require(sha256(program.raw).hexdigest() == digest and program.host_cells == (), 'SCALAR_HELPER_SOURCE_PIN')
    sequence = runtime.__dict__.setdefault('_local113_helper_counts', [])
    base = 0xE000000000000000 + len(sequence) * 0x10000
    spans = ((base, (program.cell_count + 1) * 24), (base + 0x8000, max(arena_reservation(program), 1)))
    require(not any(overlap(address, size, region.address, len(region.data)) for address, size in spans for region in runtime.memory._regions) and not any(overlap(address, size, a, n) for address, size in spans for a, n in runtime._local113_frame_plan.reserved()), 'SCALAR_HELPER_PRIVATE_ALIAS')
    mapped = []
    try:
        for address, size in spans:
            runtime.memory.map(address, bytearray(size), name='model-private pure scalar helper', initialized=False)
            mapped.append((address, size))
        vm = PrimaryVM(program, runtime.memory, cells_address=spans[0][0], arena_address=spans[1][0], arena_size=spans[1][1], image_base=runtime.image_base, runtime=runtime, scalar_sse_state=runtime.scalar_sse_state)
        argument = parent.cells.value(cells[0]) & 0xFFFFFFFF
        vm.initialize((argument,), ())
        state = dict(program=name, referenceRecordCount=0, completed=False, modelPrivate=True)
        sequence.append(state)
        def tick(word):
            require(owner.valid() and runtime._local113_frame_plan.active[-1][1] is parent, 'SCALAR_HELPER_OWNER_CHANGED')
            if parent.abort_reason is not None or vm.abort_reason is not None:
                raise PrimaryProgramLimit('scalar helper aborted')
            if state['referenceRecordCount'] >= 1000000:
                raise PrimaryProgramLimit('scalar helper record budget exhausted')
            state['referenceRecordCount'] += 1
        if name == 'host129-select':
            from .primary_support_core import run_primary_host129_select
            run_primary_host129_select(vm, charge=tick)
        else:
            from .primary_host129_prepare import run_primary_host129_prepare
            run_primary_host129_prepare(vm, charge=tick)
        require(vm.halted and vm.arena_used == 0 and (vm.result & 0xFFFFFFFF) == scalar_value(rva, argument), 'SCALAR_HELPER_MATH')
        state['completed'] = True
        return vm.result
    finally:
        for address, size in reversed(mapped):
            runtime.memory.forget(address, size, source='model_private_scalar.release')
            runtime.memory.unmap(address)
