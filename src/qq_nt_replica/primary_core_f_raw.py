from contextlib import nullcontext

from .errors import InputError
from .primary_consumed_mgf import host_read as original_host_read


def binding_for(runtime):
    from core_f_raw_inputs import CoreFReadBinding
    binding = runtime.__dict__.get('_core_f_raw_binding')
    if type(binding) is not CoreFReadBinding or binding.runtime is not runtime:
        raise InputError('qualified Core F binding is absent or replaced')
    return binding


def host_read(state, rva, posts, classified, family):
    binding = getattr(state.memory, '_core_f_raw_binding', None)
    if binding is None:
        if getattr(state.memory, '_core_f_raw_required', False) and family == 'final.F':
            raise InputError('qualified Core F primitive lost its binding')
        return original_host_read(state, rva, posts, classified, family)
    if family != 'final.F':
        binding._live()
        return original_host_read(state, rva, posts, classified, family)
    return binding_for(binding.runtime).read(state, rva, posts, classified, family)


def retry_scope(runtime, vm, cells, pointer):
    if runtime.__dict__.get('_core_invocation_owner') is None:
        return nullcontext()
    return binding_for(runtime).scope(runtime, vm, cells, pointer)
