from .primary_logger import _String
from .primary_notification_thread import destroy_context
from .primary_vm import PrimaryProgramLimit


def destroy_configuration(runtime):
    memory, base = runtime.memory, runtime.image_base
    begin = memory.load(base + 0x67517D8, 8)
    if begin:
        end = memory.load(base + 0x67517E0, 8)
        if end < begin or (end - begin) % 24:
            raise PrimaryProgramLimit('BCD020 configuration vector has an invalid begin/end domain')
        if end != begin:
            memory._span(begin, end - begin)
        cursor = end
        while cursor != begin:
            cursor -= 24
            _String.read(runtime, cursor).destroy()
        allocation = memory.load(base + 0x67517D8, 8)
        memory.store(base + 0x67517E0, begin, 8, source='BCD074.configuration_vector_end')
        runtime._free_allocation(allocation)
    destroy_context(runtime, base + 0x67516D8)
    _String.read(runtime, base + 0x67516B8).destroy()
