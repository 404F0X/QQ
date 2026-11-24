import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _String, _Tree, log
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable


_SCHEMA_SHA256 = '483bd6ea72aa36627ff6000c4761690c2f5f2c0ceac61684b5ac4fc3efa121c2'
_IMAGE_SHA256 = '0ee6806eb4bcd291a79becc6aeb145bf26c00e0b73cb1fc291b6b6c492fe15e1'


def _image():
    raw = (Path(__file__).with_name('data')/'primary_sign_qq52230/device-record-producer-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=_IMAGE_SHA256:
        raise InputError('fixed device record producer image identity mismatch')
    return json.loads(raw)


def install_image(memory, image_base):
    image = _image()
    for segment in image['segments']:
        raw = bytearray.fromhex(segment['hex'])
        for offset in segment['relocations']:
            value = int.from_bytes(raw[offset:offset+8],'little')-image['image_base']+image_base
            raw[offset:offset+8] = value.to_bytes(8,'little')
        memory.map(image_base+segment['rva'],raw,name='fixed device record producer image',initialized=True)


def _locked_singleton(runtime, slot, mutex, size, constructor):
    from .primary_worker_consumer import _invoke

    memory,base = runtime.memory,runtime.image_base
    pointer = base+mutex
    if runtime.locks.get(pointer,0):
        raise PrimarySemanticUnavailable('device record producer singleton waits on its owned mutex')
    runtime.locks[pointer] = 1
    runtime.events.append(('75AF50.lock',pointer))
    result = memory.load(base+slot,8)
    if not result:
        result = runtime._operator_new(size)
        _invoke(runtime,constructor,result)
        memory.store(base+slot,result,8,source='device_record.singleton_publish')
    runtime.locks[pointer] = 0
    runtime.events.append(('75AFC0.unlock',pointer))
    return result


def _link_record(runtime, address, node):
    tree = _Tree(runtime,address)
    key = tree.load(node,32,4)
    key -= (key&0x80000000)<<1
    parent = slot = address+8
    current = tree.load(slot)
    for _ in range(4096):
        if not current:
            runtime.memory.write(node,bytes(16),source='1D3DB90.record_children')
            tree.store(node,16,parent)
            tree.store(slot,0,node)
            left = tree.load(tree.load(address))
            if left:
                tree.store(address,0,left)
            tree.balance(tree.load(address,8),node)
            tree.store(address,16,(tree.load(address,16)+1)&((1<<64)-1))
            return node,1
        present = tree.load(current,32,4)
        present -= (present&0x80000000)<<1
        if key==present:
            _String.read(runtime,node+40).destroy()
            runtime._free_allocation(node)
            return current,0
        parent,slot = current,current+(0 if key<present else 8)
        current = tree.load(slot)
    raise PrimaryProgramLimit('device record insertion exceeds the bounded offline tree')


def insert_record(runtime, address, output, pair, *, cstring=False):
    memory = runtime.memory
    node = runtime._operator_new(64)
    memory.store(node+32,memory.load(pair,4),4,source='1D3DB90.record_key')
    if cstring:
        _String.construct(runtime,_cstring(memory,memory.load(pair+8,8))).write_to(node+40)
    else:
        _String.read(runtime,pair+8).write_to(node+40)
        memory.write(pair+8,bytes(24),source='1D3DB90.moved_record_source')
    pointer,inserted = _link_record(runtime,address,node)
    memory.store(output,pointer,8,source='1D3DB90.record_result')
    memory.store(output+8,inserted,1,source='1D3DB90.record_inserted')
    return output


def cached_value(runtime, owner, output):
    value = _String.read(runtime,owner)
    if not value.value():
        from .primary_device_native import refresh
        refresh(runtime,owner)
        value = _String.read(runtime,owner)
    item = _image()['cached_getter_log']
    log(runtime,bytes.fromhex(item['source_file_hex']),44,bytes.fromhex(item['template_hex']),
        bytes.fromhex(item['tag_hex']),item['severity'],value.value())
    value.clone().write_to(output)
    return output


def process_age(runtime):
    from .primary_device_collector import _require_material_import
    from .primary_device_process_records import _call
    from .primary_worker_response import _frame

    frame,rbp = _frame(runtime,0x60,'2E11550.process_age_frame')
    handle = _call(runtime,'GetCurrentProcess',())
    result = _call(runtime,'GetProcessTimes',(handle,),tuple((frame+offset,8) for offset in (0x50,0x48,0x40,0x38)))
    value = 0
    if result&0xFFFFFFFF:
        created = runtime.memory.load(frame+0x50,8)
        _require_material_import(runtime,'GetSystemTimeAsFileTime')
        now = runtime._next(runtime._filetimes,'GetSystemTimeAsFileTime')
        if type(now) is not int or not 0<=now<(1<<64):
            raise InputError('process age requires an unsigned observed FILETIME')
        runtime.memory.store(frame+0x30,now,8,source='2E1159A.current_FILETIME')
        value = (((now-created)&((1<<64)-1))//10000)&0xFFFFFFFF
    runtime.memory.unmap(frame)
    return value


def notify(runtime):
    from .primary_worker_consumer import _invoke

    memory,base = runtime.memory,runtime.image_base
    handle = _invoke(runtime,memory.load(base+0x490FC80,8)-base,0,0,base+0x1C29910,3000,0,0)
    if type(handle) is not int or not 0<=handle<(1<<64):
        raise PrimarySemanticUnavailable('1C298C0 notification requires its observed pointer-width thread handle')
    memory.store(base+0x677CE98,handle,8,source='1C298EC.notification_thread_handle')
    target = runtime.worker_imports.get('CloseHandle')
    if target is None or memory.load(base+0x490FBD8,8)!=target:
        raise PrimarySemanticUnavailable('1C298C0 current CloseHandle import is not bound')
    if runtime.worker_observations is None:
        raise PrimarySemanticUnavailable('1C298C0 requires its CloseHandle observation')
    result,raw = runtime.worker_observations.take(runtime,'CloseHandle',(handle,))
    if not isinstance(raw,bytes) or raw:
        raise InputError('notification CloseHandle observation has no memory outputs')
    return result


def produce(runtime, owner, output):
    from .primary_device_cache import _length
    from .primary_device_collector import _converted_hardware
    from .primary_worker_consumer import _copy_records, _destroy_tree, _invoke
    from .primary_worker_loop import _initialize
    from .primary_worker_response import _frame

    memory,base = runtime.memory,runtime.image_base
    frame,rbp = _frame(runtime,0x4388,'1D332F0.record_producer_frame')
    internal = owner+8
    _destroy_tree(runtime,internal)
    memory.store(internal,internal+8,8,source='1D33341.empty_record_begin')
    memory.write(internal+8,bytes(16),source='1D33348.empty_record_root_count')
    snapshot = rbp-0x58
    for offset,size in ((-0x58,8),(-0x50,4),(-0x48,80),(8,8),(0x28,0x609),(0x6B8,16),(0x6C8,8)):
        memory.write(rbp+offset,bytes(size),source='1D332F0.initial_snapshot')
    for offset in (*range(0x638,0x6A8,16),0x6A2):
        memory.write(rbp+offset,bytes(16),source='1D3339A.initial_snapshot_tail')
    collector = _locked_singleton(runtime,0x677E4E0,0x677E4D0,0x42B0,0x2E12310)
    _invoke(runtime,0x2E15490,collector,snapshot)
    pair,scratch = rbp+0x42B0,rbp+0x4248
    memory.store(pair,0,4,source='1D33429.version_key')
    memory.store(pair+8,memory.load(owner,8),8,source='1D33433.version_source')
    insert_record(runtime,internal,scratch,pair,cstring=True)
    for field in _schema()['fields'][1:]:
        kind,key = field['kind'],field['key']
        temporary = None
        if kind in ('u8','u32','u64'):
            width = {'u8':1,'u32':4,'u64':8}[kind]
            value = _String.construct(runtime,str(memory.load(snapshot+field['offset'],width)).encode('ascii'))
        elif kind=='join_u32':
            raw = bytes.fromhex(field['separator_hex']).join(str(memory.load(snapshot+offset,4)).encode('ascii') for offset in field['offsets'])
            value = _String.construct(runtime,raw)
        elif kind=='device_value':
            current = _locked_singleton(runtime,0x6751838,0x677E4D8,32,0x1BE5CD0)
            cached_value(runtime,current,pair+8)
            value = _String.read(runtime,pair+8)
        elif kind.startswith('sdk'):
            _initialize(runtime,1)
            value = _String.read(runtime,base+0x67516B0+0x28+int(kind[3:],16)).clone()
        elif kind in ('cstring','ansi_cstring'):
            value = _String.construct(runtime,_cstring(memory,snapshot+field['offset']))
            if kind=='ansi_cstring':
                value.write_to(rbp+0x4278)
                temporary = value
                value = _converted_hardware(runtime,rbp+0x4278)
        elif kind=='ansi_string':
            value = _converted_hardware(runtime,snapshot+field['offset'])
        else:
            value = _String.read(runtime,snapshot+field['offset']).clone()
        memory.store(pair,key,4,source='1D332F0.record_key')
        value.write_to(pair+8)
        insert_record(runtime,internal,scratch,pair)
        if temporary is not None:
            temporary.destroy()
    records = [(memory.load(node+32,4),_String.read(runtime,node+40)) for node in _Tree(runtime,internal).nodes()]
    _copy_records(runtime,records,output)
    if process_age(runtime)>=0x927C1:
        _initialize(runtime,1)
        if _length(runtime,base+0x67516B0+0x28+0xE0)>=4:
            counter = base+0x677E4C8
            memory.store(counter,(memory.load(counter,4)+1)&0xFFFFFFFF,4,source='1D38D8C.notification_count')
            _invoke(runtime,0x1C298C0)
    _invoke(runtime,0x1D3CF00,snapshot)
    memory.unmap(frame)
    return 0


def _destroy_record_tree(runtime, node):
    if not node:
        return
    _destroy_record_tree(runtime, runtime.memory.load(node, 8))
    _destroy_record_tree(runtime, runtime.memory.load(node + 8, 8))
    _String.read(runtime, node + 40).destroy()
    runtime._free_allocation(node)


def invoke(runtime, rva, values):
    from .primary_worker_consumer import _invoke

    if rva == 0xBEE430:
        if values:
            raise InputError('device record producer exit takes no arguments')
        return _destroy_record_tree(runtime, runtime.memory.load(runtime.image_base + 0x6751DA0, 8))
    if rva==0xBEE3C0 and len(values)==2:
        memory,base = runtime.memory,runtime.image_base
        guard = memory.load(base+0x6751DB8,4)
        if not guard&1:
            memory.store(base+0x6751DB8,guard|1,4,source='BEE3E9.producer_guard')
            memory.store(base+0x6751D90,base+0x48AD62E,8,source='BEE3F6.version_pointer')
            memory.write(base+0x6751DA0,bytes(16),source='BEE400.producer_root_count')
            memory.store(base+0x6751D98,base+0x6751DA0,8,source='BEE40E.producer_begin')
            memory.store(base+0x6751DB0,9,4,source='BEE415.producer_setting')
            _invoke(runtime,0x3E680B4,base+0xBEE430)
        return produce(runtime,base+0x6751D90,values[1])
    if rva==0x1D332F0 and len(values)==2:
        return produce(runtime,*values)
    if rva==0x1BE5CD0 and len(values)==1:
        runtime.memory.write(values[0],bytes(25),source='1BE5CD0.cache_constructor')
        return values[0]
    if rva==0x1BE77F0 and len(values)==2:
        return cached_value(runtime,*values)
    if rva==0x2E11550 and not values:
        return process_age(runtime)
    if rva==0x1C298C0 and not values:
        return notify(runtime)
    if rva in (0x1D3D970,0x1D3DB90) and len(values)==3:
        return insert_record(runtime,*values,cstring=rva==0x1D3D970)
    raise InputError('device record producer source interface argument count mismatch')


def _schema():
    path = Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'device-record-fields.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _SCHEMA_SHA256:
        raise InputError('fixed device record field schema identity mismatch')
    return json.loads(raw)


def _cstring(memory, address):
    value = bytearray()
    for index in range(1 << 20):
        current = memory.read(address + index, 1)[0]
        if not current:
            return bytes(value)
        value.append(current)
    raise PrimaryProgramLimit('device record C string exceeds the bounded offline domain')


def device_record_values(runtime, snapshot, *, version, device_value, sdk_fields, ansi_to_utf8):
    if type(snapshot) is not int or not 0 < snapshot <= (1 << 64) - 0x42A8:
        raise InputError('device record snapshot requires a nonwrapping source address')
    if not isinstance(version, bytes) or not isinstance(device_value, bytes):
        raise InputError('device record version and cached device value require source bytes')
    if (not isinstance(sdk_fields, dict) or set(sdk_fields) != {0x30, 0x48, 0x78} or
            any(not isinstance(value, bytes) for value in sdk_fields.values())):
        raise InputError('device records require SDK source strings at30,48,78')
    if not callable(ansi_to_utf8):
        raise InputError('device record ANSI conversion requires its external OS observation adapter')
    memory, values = runtime.memory, []
    for field in _schema()['fields']:
        kind = field['kind']
        if kind in ('u8', 'u32', 'u64'):
            width = {'u8': 1, 'u32': 4, 'u64': 8}[kind]
            value = str(memory.load(snapshot + field['offset'], width)).encode('ascii')
        elif kind == 'join_u32':
            value = bytes.fromhex(field['separator_hex']).join(
                str(memory.load(snapshot + offset, 4)).encode('ascii') for offset in field['offsets'])
        elif kind == 'version':
            value = version.split(b'\0', 1)[0]
        elif kind == 'device_value':
            value = device_value
        elif kind.startswith('sdk'):
            value = sdk_fields[int(kind[3:], 16)]
        else:
            address = snapshot + field['offset']
            value = (_cstring(memory, address) if kind in ('cstring', 'ansi_cstring')
                     else _String.read(runtime, address).value())
            if kind in ('ansi_string', 'ansi_cstring'):
                value = ansi_to_utf8(value.split(b'\0', 1)[0])
                if not isinstance(value, bytes) or b'\0' in value:
                    raise InputError('device ANSI conversion must return its complete NUL-free source String value')
        values.append((field['key'], value))
    return tuple(values)
