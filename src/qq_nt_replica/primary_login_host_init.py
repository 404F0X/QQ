"""Source Login preselection producers; no implicit process-attach or host IO."""
from .primary_logger import _String, _Tree
from .primary_worker_consumer import _invoke


def empty_tree(runtime, header):
    runtime.memory.store(header,header+8,8,source='3CEA.begin')
    runtime.memory.write(header+8,bytes(16),source='3CEA.root_count')


def insert_directory(runtime, header, key, value):
    """6A8FE normal64B node ABI; only balancing reuses the logger primitive."""
    memory=runtime.memory
    parent=slot=header+8
    node=memory.load(slot,8)
    while node:
        present=memory.load(node+32,4,signed=True)
        if present==key:return node
        parent=node;slot=node+(0 if key<present else 8)
        node=memory.load(slot,8)
    node=_invoke(runtime,0xB75000,64)
    memory.store(node+32,key,4,source='13E1A.key')
    value.clone().write_to(node+40)
    memory.write(node,bytes(16),source='42FC.children')
    memory.store(node+16,parent,8,source='42FC.parent')
    memory.store(slot,node,8,source='42FC.link')
    begin=memory.load(header,8)
    left=memory.load(begin,8)
    if left:memory.store(header,left,8,source='42FC.begin')
    _Tree(runtime,header).balance(memory.load(header+8,8),node)
    memory.store(header+16,memory.load(header+16,8)+1,8,source='42FC.count')
    return node


def copy_directory_tree(runtime, source, destination):
    empty_tree(runtime,destination)
    def visit(node):
        if node:
            visit(runtime.memory.load(node,8))
            insert_directory(runtime,destination,runtime.memory.load(node+32,4,signed=True),_String.read(runtime,node+40))
            visit(runtime.memory.load(node+8,8))
    visit(runtime.memory.load(source+8,8))


def destroy_directory_tree(runtime, header):
    def visit(node):
        if node:
            visit(runtime.memory.load(node,8));visit(runtime.memory.load(node+8,8))
            _String.read(runtime,node+40).destroy()
            _invoke(runtime,0xB75029,node)
    visit(runtime.memory.load(header+8,8))


def move_directory_tree(runtime, source, destination):
    memory=runtime.memory
    memory.write(destination,memory.read(source,24),source='1E9C6.header_move')
    root=memory.load(destination+8,8)
    if root:memory.store(root+16,destination+8,8,source='1E9C6.root_parent')
    else:memory.store(destination,destination+8,8,source='1E9C6.empty_begin')
    empty_tree(runtime,source)


def publish_hostname(runtime, value):
    """6BE2A0/6BE322; image cells must already exist from model birth."""
    from .primary_shared_locale import resolve_current_module_tls
    receipt=resolve_current_module_tls(runtime)
    memory=runtime.memory;guard=runtime.image_base+0x674c708
    destination=runtime.image_base+0x674c6f0
    if memory.load(guard,4,signed=True)>memory.load(receipt.epoch_address,4,signed=True):
        runtime._locale_thread_header(guard)
        if memory.load(guard,4,signed=True)==-1:
            memory.write(destination,bytes(24),source='6BE300.zero24')
            _invoke(runtime,0x6270,destination)
            runtime._locale_thread_footer(guard)
    cloned=value.clone()
    _String.read(runtime,destination).destroy()
    cloned.write_to(destination)
    return destination


def directory_map(runtime):
    from .primary_login_model_attach import validate_birth
    from .primary_shared_locale import resolve_current_module_tls
    from .primary_worker_response import _frame
    validate_birth(runtime);receipt=resolve_current_module_tls(runtime)
    memory=runtime.memory;base=runtime.image_base;guard=base+0x674c760;header=base+0x674c748
    if memory.load(guard,4,signed=True)>memory.load(receipt.epoch_address,4,signed=True):
        runtime._locale_thread_header(guard)
        if memory.load(guard,4,signed=True)==-1:
            frame,unused=_frame(runtime,160,'6D3B12 directory range and temporary tree')
            values=[]
            for index,(key,raw) in enumerate(((6,b'Emoji'),(9,b'Log'),(10,b'msf'),(11,b'Login'))):
                value=_String.construct(runtime,raw);values.append(value)
                memory.store(frame+index*32,key,4,source='6D3B12.range_key')
                value.write_to(frame+index*32+8)
            temporary=frame+128;empty_tree(runtime,temporary)
            for index in range(4):
                insert_directory(runtime,temporary,memory.load(frame+index*32,4,signed=True),_String.read(runtime,frame+index*32+8))
            move_directory_tree(runtime,temporary,header)
            destroy_directory_tree(runtime,temporary)
            for value in reversed(values):value.destroy()
            memory.unmap(frame)
            runtime._locale_thread_footer(guard)
    return header


def msf_directory(runtime, common_path):
    from .primary_worker_response import _frame
    source=directory_map(runtime)
    local,unused=_frame(runtime,24,'6D922A owned directory map copy')
    copy_directory_tree(runtime,source,local)
    node=runtime.memory.load(local+8,8)
    while node:
        key=runtime.memory.load(node+32,4,signed=True)
        if key==10:break
        node=runtime.memory.load(node+(0 if 10<key else 8),8)
    suffix=b'' if not node else _String.read(runtime,node+40).value()
    result=_String.construct(runtime,b'' if not suffix else common_path.value()+b'\\'+suffix)
    destroy_directory_tree(runtime,local);runtime.memory.unmap(local)
    return result


def publish_msf_directory(runtime, owned_value):
    from .primary_login_model_attach import require_complete
    destination=require_complete(runtime)
    copied=owned_value.clone()
    _String.read(runtime,destination).destroy();copied.write_to(destination)
    owned_value.destroy()
    return destination
