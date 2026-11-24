"""Recovered independent stages of 52359, not a complete payload producer."""
from .primary_qimei_request import QimeiRequestBoundary, _integer, _signed


def _tree(tree):
    if type(tree) is not tuple or any(type(value) is not bytes for value in tree):
        raise QimeiRequestBoundary('explicit ordered owning String tree required')
    if tuple(sorted(set(tree))) != tree:
        raise QimeiRequestBoundary('source tree order/uniqueness is not established')
    return tree


def module_suffix_signal(tree):
    result=0
    for value in _tree(tree):
        result=0
        if value.endswith(b'\\SbieDll.dll'):
            result|=1
    return result


def populate_module_initial(owner,state,tree,settings,*,settings_dependencies=None):
    """52843..52892 only: cell33 flag gate, then independent cell35."""
    tree=_tree(tree)
    dependencies={} if settings_dependencies is None else dict(settings_dependencies)
    flag=settings.flag(3,group=1,**dependencies)
    if _signed(flag,32)>0:state.set_u32(34,module_suffix_signal(tree))
    if tree:state.set_string(36,memoryview(tree[0]).tobytes())
    return state


def tree_list(tree,mode):
    output=b''
    for value in _tree(tree):
        if _integer(mode)&255:
            index=value.rfind(b'\\')
            if _signed(index,32)>0:value=value[index+1:]
        if output:output+=b'#'
        output+=value
    return memoryview(output).tobytes()


def populate_module_list_later(owner,state,tree,settings,*,settings_dependencies=None):
    """529AD..529F3 only; intervening consumers are NOT supplied here."""
    tree=_tree(tree)
    dependencies={} if settings_dependencies is None else dict(settings_dependencies)
    if _integer(settings.flag(13,group=1,**dependencies))&0xFFFFFFFF:
        state.set_string(45,tree_list(tree,1))
    return state


def populate_base_prefix(state,system):
    """5249A..52507 only, before mandatory machine-name group."""
    state.set_u32(1,system.process_id())
    state.set_u32(3,system.wow64())
    state.set_u32(6,system.is_admin())
    executable=system.executable_path()
    if executable.accepted:
        state.set_string(2,executable.value)
        compatibility=system.compatibility_flags(executable.value)
        if compatibility.accepted:state.set_string(7,compatibility.value)
    return state


def populate_platform_stage(state,system):
    """Contiguous5250C..52662, after base prefix and before flag-controlled fields."""
    names=system.machine_names()
    if names.accepted:
        state.set_string(4,names.values[0]);state.set_string(5,names.values[1])
    state.set_u32(10,system.os_classification())
    memory=system.memory_status()
    if memory.accepted:
        state.set_u32(11,memory.values[0])
        for number,value in enumerate(memory.values[1:],12):state.set_u64(number,value)
    state.set_u32(18,system.architecture())
    cursor=system.cursor_position()
    if cursor.accepted:
        state.set_u32(19,cursor.values[0]);state.set_u32(20,cursor.values[1])
    return state


def populate_local_tail(state,system):
    """Contiguous52667..526BB only, before settings-refresh-controlled stages."""
    state.set_u32(21,system.keyboard_type())
    state.set_u32(22,system.system_metric(0))
    state.set_u32(23,system.system_metric(1))
    state.set_u64(24,system.request_time())
    return state
