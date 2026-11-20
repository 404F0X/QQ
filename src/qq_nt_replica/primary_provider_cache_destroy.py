from .primary_sdk import _invoke_values, release_weak


def _release_owner(runtime, slot):
    memory = runtime.memory
    control = memory.load(slot, 8)
    if control:
        previous = memory.load(control + 8, 4)
        memory.store(control + 8, (previous - 1) & 0xFFFFFFFF, 4,
                     source='D46BDD.cache_owner_release')
        if previous == 0:
            target = memory.load(memory.load(control, 8) + 8, 8)
            _invoke_values(runtime, target, (control,))


def _destroy_string(runtime, address):
    if runtime.memory.load(address, 1) & 1:
        runtime._free_allocation(runtime.memory.load(address + 16, 8))


def destroy_cache(runtime, address=None):
    address = runtime.image_base + 0x6751840 if address is None else address
    _destroy_string(runtime, address + 0x130)
    _release_owner(runtime, address + 0x120)
    _release_owner(runtime, address + 0x118)
    for offset in (0xE8, 0x88, 0x70, 0x48, 0x30, 0x18):
        _destroy_string(runtime, address + offset)
    memory = runtime.memory
    control = memory.load(address + 8, 8)
    if control:
        previous = memory.load(control + 8, 4)
        memory.store(control + 8, (previous - 1) & 0xFFFFFFFF, 4,
                     source='BCD2E6.cache_control_release')
        if previous == 0:
            target = memory.load(memory.load(control, 8) + 8, 8)
            _invoke_values(runtime, target, (control,))
            release_weak(runtime, control)
