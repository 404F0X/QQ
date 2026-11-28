from .primary_core_f_raw import host_read as f_host_read


FAMILIES = frozenset(('stage1.M', 'control.M', 'pair.M', 'final.M', 'stage2.G'))


def host_read(state, rva, posts, classified, family):
    if family in FAMILIES and (getattr(state.memory, '_core_mg_raw_required', False) or
                              getattr(state.memory, '_core_mg_raw_binding', None) is not None):
        from core_mg_raw_inputs import binding_for_memory
        return binding_for_memory(state.memory).read(state, rva, posts, classified, family)
    return f_host_read(state, rva, posts, classified, family)
