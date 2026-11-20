from .errors import InputError
from .primary_common_guid import CommonG3Guid
from .primary_memory import PrimaryMemoryLimit


class CommonGuidExport:
    def __init__(self, producer):
        if type(producer) is not CommonG3Guid:
            raise InputError('COMMON_GUID_OWN_PRODUCER')
        self.producer = producer
        self.runtime = None
        self.address = None

    def bind(self, runtime, address):
        if self.runtime is not None or type(address) is not int or not 0 < address < 1 << 64:
            raise InputError('COMMON_GUID_VIRTUAL_BINDING')
        self.runtime, self.address = runtime, address
        runtime._common_guid_export = self

    def validate(self, vm, cells, argument_types, signature=139):
        from .primary_sign import load_program
        if (vm.runtime is not self.runtime or vm.memory is not self.runtime.memory or
                vm.program.raw != load_program('main').raw or signature != 139 or
                vm.program.type(signature).parameters != (0, 3, 1, 2) or
                tuple(cells) != (299,) or argument_types != (2,) or
                vm.pc != 3939 or vm.block != 92 or not vm.host_calls or
                vm.host_calls[-1] != (3932, self.address, (299,), 139)):
            raise InputError('COMMON_GUID_MAIN_CALL_ABI')

    def invoke(self, vm, cells, argument_types):
        self.validate(vm, cells, argument_types)
        output = vm.cells.value(cells[0])
        if output:
            region, offset = vm.memory._span(output, 16)
            if region.data.readonly:
                raise PrimaryMemoryLimit('COMMON_GUID_OUTPUT_READONLY')
        return self.producer.invoke(vm.memory, output)
