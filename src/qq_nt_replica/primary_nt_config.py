"""Finite NT65240 ordinary matched-empty config lookup; unsupported paths retain effects."""
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
from .primary_logger import _String
from .primary_mmkv_load import valid


def stop(r,site,target,reason):
    r._selector_config_pending['boundary']=target;r.events.append(('source.unavailable',target,site))
    raise PrimarySemanticUnavailable(reason)


def loadcheck(r,port,parent):
    m=r.memory;s=port._WindowsMMKVHost__open
    if m.load(parent+0x88,1):
        m.store(parent+0x88,0,1,source='1BDA5E2.clear_load_flag')
        stop(r,0x1bda5e2,0x1bd957c,'957C reload branch unavailable')
    if not m.load(parent+0xd1,1):return
    meta_file=s['files'][1]
    if not valid(meta_file):return
    nested=s['outer_guard'].borrow_shared(m.load(parent+0xb8,8));s['config_nested']=nested;nested.acquire()
    snapshot,unused=_frame(r,0x70,'1BDA65E snapshot Meta70')
    m.store(snapshot,0x100000000,8,source='1BDA65E.snapshot_initial_version1')
    m.write(snapshot+8,bytes(0x68),source='1BDA65E.snapshot_initial_rest')
    m.copy_disjoint(snapshot,meta_file.load(0x30),0x70,label='1BDA69F.actual_snapshot70_copy')
    r._selector_config_pending['snapshot']=snapshot
    cached=m.load(parent+0x98,8)
    if m.load(cached+8,4)!=m.load(snapshot+8,4):stop(r,None,None,'1BDA5E2 cached.seqDWORD != snapshot.seqDWORD; first unimplemented log callsite/target UNKNOWN')
    if m.load(cached,4)!=m.load(snapshot,4):stop(r,0x1bda6d4,0x1bd8640,'metadata digest changed reload unavailable')
    nested.release();m.unmap(snapshot)


def get_string(r,port,parent,key,output):
    if not _String.read(r,key).value():return False
    m=r.memory;s=port._WindowsMMKVHost__open
    if parent!=s['parent']:raise InputError('getter requires original owned MMKV parent')
    cs_guard,unused=_frame(r,8,'B995F0 parent private CS guard')
    m.store(cs_guard,m.load(parent+0xa8,8),8,source='B995F0.parent_guard_publish')
    port._parent_cs(parent,True)
    outer=s['outer_guard'].borrow_shared(m.load(parent+0xb8,8));s['config_outer']=outer;outer.acquire()
    if m.load(parent+0xc8,1):stop(r,0x1bdb4f4,0x1bdb520,'1BDB520 nonzero C8 getter unavailable')
    loadcheck(r,port,parent) # Source calls this unconditionally, including parent88=0.
    dictionary=m.load(parent+(0x68 if m.load(parent+0xa0,8) else 0x60),8)
    found,unused=_frame(r,8,'8ED82 config dictionary iterator')
    _invoke(r,0x8ed82,dictionary,found,key)
    if m.load(found,8):stop(r,0x1bdb42c,None,'nonempty dictionary payload producer unavailable')
    payload,unused=_frame(r,18,'B982EC packed empty payload')
    m.store(payload,0,1,source='B982EC.empty_flag');m.store(payload+1,0,1,source='B982EC.empty_count')
    r._selector_config_pending['payload']=payload
    count=m.load(payload+2,8) if m.load(payload,1) else m.load(payload+1,1)
    if count:stop(r,0xb9aa49,0x1be1c82,'nonempty config codec unavailable')
    # B98642 flag0 is a genuine no-free return. No output mutation accompanies FALSE.
    r.events.append(('source.B98642.flag0',payload));m.unmap(payload);m.unmap(found)
    outer.release();port._parent_cs(parent,False)
    m.store(cs_guard,0,8,source='19A1.parent_guard_clear');m.unmap(cs_guard)
    return False


def lookup(r,interface,identifier,key,output):
    from .primary_nt_misc_map import bind
    from .primary_windows_mmkv_host_init import for_runtime
    p=r._selector_config_pending;m=r.memory;port=for_runtime(r)
    frame,unused=_frame(r,16,'65240 actual NT guard and iterator')
    p.update(interface=interface,guard=frame)
    m.store(frame,interface+0x3b0,8,source='65274.NT_guard_publish')
    bound=bind(r,p,'config');r._nt_config_record=bound
    bound.acquire();bound.find(identifier,frame+8)
    node=m.load(frame+8,8);raw=m.load(node+0x38,8) if node!=bound.tree+8 else 0
    bound.release();p['released_nt_guard']=m.load(frame,8)
    if raw:result=get_string(r,port,raw,key,output)
    else:
        copies,unused=_frame(r,48,'652D0 missing-config copies')
        _invoke(r,0x75b810,copies,key);_invoke(r,0x75b810,copies+24,identifier)
        p['missing_copies']=copies
        from .primary_native_logger import nt_config_missing,nt_file_basename
        nt_config_missing(r,nt_file_basename(r),copies+24,copies)
        m.unmap(copies);result=False
    p['nt_context_finished']=True;m.unmap(frame)
    r.events.append(('source.65240.return',bool(result)))
    return result
