"""Finite normal ordinary MSF380 construction/publisher; timers remain unstarted."""
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame
from .primary_logger import _String
from .primary_sdk import _add_owner,_release_owner


def _vt(r,p,rows,source):
    for offset,table in rows:r.memory.store(p+offset,r.image_base+table,8,source=source)


def _move(r,destination,source):
    _String.read(r,source).write_to(destination)
    _invoke(r,0x6270,source)
    r.events.append(('source.ordinary_String_MOVE',destination,source))


def _timer(r,p,table):
    m=r.memory
    m.store(p,r.image_base+0x3fed6a8,8,source='D3024C.core_vptr')
    for offset in (8,0x18):m.write(p+offset,bytes(16),source='D3024C.zero16')
    m.store(p+0x28,0xffffffff,4,source='D3024C.invalid')
    m.write(p+0x30,bytes(16),source='D3024C.zero16')
    for offset,size in ((0x40,4),(0x48,8),(0x50,4),(0x58,8),(0x60,4),(0x68,1)):
        m.store(p+offset,0,size,source='D3024C.core_field')
    m.store(p,r.image_base+table,8,source='D30896/D30AC0.timer_vptr')
    m.store(p+0x80,r.image_base+0x2338,8,source='D30896/D30AC0.callback80')
    m.store(p+0x88,r.image_base+0x236a,8,source='D30896/D30AC0.callback88')


def construct(r,p):
    m=r.memory;pending=r._ordinary_msf_pending
    pending['phase']='constructor';frame,unused=_frame(r,72,'ordinary base String MOVE chain')
    pending['constructor_frame']=frame
    _String.construct(r,b'').write_to(frame)
    _vt(r,p,((0,0x3f6ea78),(8,0x3ec1ef8),(0x10,0x3f6eb08),(0x18,0x3f6eb70)),'7377C4.base_vptr')
    _move(r,frame+24,frame);_move(r,frame+48,frame+24)
    m.store(p+0x20,r.image_base+0x3f6ebe0,8,source='737938.child_vptr')
    _move(r,p+0x28,frame+48);_String.read(r,frame+48).destroy()
    m.store(p+0x20,r.image_base+0x3f6eba8,8,source='7378E8.child_vptr')
    _String.read(r,frame+24).destroy()
    _vt(r,p,((0,0x3f6e668),(8,0x3f6e768),(0x10,0x3f6e958),(0x18,0x3f6e9a0),(0x20,0x3f6e9b8)),'7377C4.interface_vptr')
    _String.read(r,frame).destroy();m.unmap(frame);pending['base_finished']=True
    m.write(p+0x40,bytes(16),source='72DF56.selfweak_empty')
    _vt(r,p,((0,0x3f6ded8),(8,0x3f6dfd8),(0x10,0x3f6e1c8),(0x18,0x3f6e210),(0x20,0x3f6e228)),'72DF56.final_vptr')
    for offset in (0x50,0x60,0x70,0x80,0x90):m.write(p+offset,bytes(16),source='72DF56.zero16')
    m.store(p+0xa0,0,8,source='72DF56.fieldA0')
    _timer(r,p+0xa8,0x3fed6d8);_timer(r,p+0x138,0x3fed6d8)
    for offset in (0x1c8,0x1d8):m.write(p+offset,bytes(16),source='72DF56.zero16')
    m.store(p+0x1e8,0x3f800000,4,source='72DF56.load_factor')
    for offset in (0x1f0,0x208,0x220,0x238,0x250):_invoke(r,0x6270,p+offset)
    m.store(p+0x268,0,2,source='72DF56.word268')
    m.store(p+0x270,0,1,source='730EF8.optional_byte')
    _invoke(r,0x6270,p+0x278);m.store(p+0x290,0,8,source='730EF8.qword20')
    _String.construct(r,b'\0').write_to(p+0x298)
    _invoke(r,0x6270,p+0x2b0)
    m.store(p+0x2c8,0,4,source='72DF56.field2C8')
    m.store(p+0x2e0,r.image_base+0x2338,8,source='72DF56.callback2E0')
    m.store(p+0x2e8,r.image_base+0x236a,8,source='72DF56.callback2E8')
    _timer(r,p+0x2f0,0x3fed718)
    pending['phase']='constructed';r.events.append(('source.72DF56.return',p));return p


def publish(r,p):
    m=r.memory;b=r.image_base;pending=r._ordinary_msf_pending
    local,unused=_frame(r,8,'73CFA6 unique local owner')
    pending['unique_frame']=local;pending['unique']=p;pending['phase']='publishing'
    m.store(local,p,8,source='73CFA6.local_unique')
    m.store(b+0x674d2c0,p,8,source='73CFA6.object_publish')
    control=_invoke(r,0xb75000,0x28);pending['control']=control
    m.store(control+8,0,4,source='73CFA6.strong')
    m.store(control+0x10,0,4,source='73CFA6.weak')
    m.store(control,b+0x3f6f4d8,8,source='73CFA6.control_vptr')
    m.store(control+0x18,p,8,source='73CFA6.control_object')
    m.store(b+0x674d2c8,control,8,source='73CFA6.control_publish')
    m.store(local,0,8,source='73CFA6.local_unique_clear');pending['unique']=0
    _add_owner(r,control)
    m.store(control+0x10,m.load(control+0x10,4)+1,4,source='1687C.selfweak_add')
    m.store(p+0x40,p,8,source='1687C.selfweak_object')
    m.store(p+0x48,control,8,source='1687C.selfweak_control')
    _release_owner(r,control)
    m.unmap(local);pending['phase']='published';r.events.append(('source.73CFA6.return',p,control))


def get_pair(r,output):
    from .primary_msf_selection import _validate
    from .primary_shared_locale import resolve_current_module_tls
    _validate(r);m=r.memory;b=r.image_base;guard=b+0x674d2d0
    receipt=resolve_current_module_tls(r)
    if m.load(guard,4,signed=True)>m.load(receipt.epoch_address,4,signed=True):
        r._locale_thread_header(guard)
        if m.load(guard,4,signed=True)==-1:
            p=_invoke(r,0xb75000,0x380)
            r._ordinary_msf_pending=dict(allocation=p,guard=guard,phase='allocated')
            construct(r,p);publish(r,p)
            r._locale_thread_footer(guard)
            r._ordinary_msf_pending['phase']='footer_finished'
    # Source getter re-reads after the actual footer, then copies and retains.
    p=m.load(b+0x674d2c0,8);m.store(output,p,8,source='72DE9B.output_object')
    control=m.load(b+0x674d2c8,8);m.store(output+8,control,8,source='72DE9B.output_control')
    if control:_add_owner(r,control)
    r.events.append(('source.72DE38.return',output,p,control))
    return output
