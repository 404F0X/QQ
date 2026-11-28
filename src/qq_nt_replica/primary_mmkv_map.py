"""Finite first48B MMKV cache-map publication, distinct from40B set insertion."""
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


def emplace(r,cache,key):
    m=r.memory
    hashed=_invoke(r,0x3c77e,cache+0x20,key)
    count=m.load(cache+8,8)
    pointer=m.load(cache,8);head=m.load(cache+0x10,8);size=m.load(cache+0x18,8);factor=m.load(cache+0x20,4)
    if count or pointer or head or size or factor!=0x3f800000:raise PrimarySemanticUnavailable('noncold MMKV map emplace outside finite source domain')
    r.events.append(('source.call',0x24c0,0x30))
    node=_invoke(r,0xb75000,0x30)
    guard,_=_frame(r,16,'8F3AA temporary node guard')
    m.store(guard,node,8,source='8F3AA.node_guard')
    _invoke(r,0x75b810,node+0x10,key)
    m.store(node+0x28,0,8,source='8F3AA.value_NULL')
    m.store(guard+8,1,1,source='8F3AA.key_ready')
    m.store(node+8,hashed,8,source='8F3AA.hash');m.store(node,0,8,source='8F3AA.next0')
    # Actual size0/factor1 requires request1; both fixed CPU paths yield1.
    r.events.append(('source.rehash',0x3cc9a,1,2));r.events.append(('source.call',0x24c0,16))
    buckets=_invoke(r,0xb75000,16)
    m.store(cache,buckets,8,source='3CF8E.MMKV_bucket_publish')
    m.store(cache+8,2,8,source='3CE18.MMKV_bucket_count')
    m.write(buckets,bytes(16),source='3CE26.MMKV_empty_buckets')
    m.store(node,m.load(cache+0x10,8),8,source='8F2FF.node_next')
    m.store(cache+0x10,node,8,source='8F306.cache_head')
    m.store(buckets+(hashed&1)*8,cache+0x10,8,source='8F30D.bucket_predecessor_head_address')
    m.store(guard,0,8,source='8F34F.node_guard_clear')
    m.store(cache+0x18,m.load(cache+0x18,8)+1,8,source='8F34F.cache_size')
    m.unmap(guard)
    return node+0x28
