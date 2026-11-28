"""Private limited-MODEL creator qualification; never worker LIVE or Original origin."""
import os,sys,threading
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
_CREATORS={}


class _Creator:
    def __init__(self,owner):
        if sys._getframe(1).f_code is not grant.__code__:raise InputError('creator issuer is factory-private')
        self.owner=owner;self.service=owner._threads;self.runtime=owner.signer.runtime
        self.registrar=owner._registrar;self.memory=self.runtime.memory;self.base=self.runtime.image_base
        self.source=self.runtime._shared_locale_source;self.epoch=self.source.epoch;self.kind=self.source.source_kind
        self.thread=(os.getpid(),threading.get_ident(),threading.get_native_id())
        self.allocator_epoch=self.runtime._primary_allocator_selector.epoch
        self.domain=None;self.receipts={};self.ptd=None;self.failures=[];self.state='issued';self.events=[]

    def validate(self,*,lease=True,closing=False):
        from .primary_windows_signer import WindowsSigner
        from .primary_windows_threads import WindowsSDKThreadService
        from .primary_host_services import _ExecutionLease
        o=self.owner;r=self.runtime;s=self.service
        if (type(o) is not WindowsSigner or type(s) is not WindowsSDKThreadService or _CREATORS.get(id(r)) is not self or
                self.state=='terminal' or self.thread!=(os.getpid(),threading.get_ident(),threading.get_native_id()) or
                o._signer.runtime is not r or o._threads is not s or o._registrar is not self.registrar or
                s._runtime is not r or s._registrar is not self.registrar or s._closed or
                r.memory is not self.memory or r.image_base!=self.base or r._shared_locale_source is not self.source or
                self.source.epoch is not self.epoch or self.source.source_kind!=self.kind or
                r._primary_allocator_selector.epoch is not self.allocator_epoch or
                getattr(s._observer_factory,'__self__',None) is not o or getattr(s._observer_factory,'__func__',None) is not WindowsSigner._worker_services):
            raise InputError('creator issuer identity/epoch/thread changed')
        self.source.validate_image(r)
        if closing:
            if o._state!='closing' or o._busy or not s._closing:raise InputError('creator closing role not active')
        elif o._state not in ('constructing','open'):raise InputError('creator public owner not active')
        if lease:
            if not s._active_owner or s._execution_tid!=self.thread[2] or not s._execution.locked():raise InputError('creator lease lacks actual owner execution ownership')
            current=self.registrar.current_lease()
            if type(current) is not _ExecutionLease or current.registrar is not self.registrar or not current.active or current.suspended or current.thread_id!=self.thread[2]:
                raise InputError('creator role requires active unsuspended original lease')
        return self


def grant(owner):
    from .primary_windows_signer import WindowsSigner,open_windows_signer
    from .primary_windows_threads import WindowsSDKThreadService
    from .primary_host_services import GuestExitRegistrar
    f=sys._getframe(1)
    if (f.f_code is not open_windows_signer.__code__ or f.f_locals.get('owner') is not owner or type(owner) is not WindowsSigner or
            owner._state!='constructing' or owner._crt is not None or owner._pid!=os.getpid() or owner._thread!=threading.get_native_id() or
            type(owner._threads) is not WindowsSDKThreadService or type(owner._registrar) is not GuestExitRegistrar):
        raise InputError('creator grant requires actual post-bind/pre-CRT factory point')
    r=owner.signer.runtime;s=owner._threads
    if id(r) in _CREATORS or s._runtime is not r or s._registrar is not owner._registrar or s._owner!=(owner._pid,owner._thread) or s._threads or s._secondary or s._crt_domains or s._closed:
        raise InputError('creator grant cannot adopt existing service/domain')
    record=_Creator(owner);_CREATORS[id(r)]=record
    record.validate(lease=False)


def _for_service(service):
    record=_CREATORS.get(id(service._runtime))
    if record is None or record.service is not service:return None
    return record


def _for_runtime(runtime):
    record=_CREATORS.get(id(runtime))
    if record is None or record.runtime is not runtime:return None
    return record


def _journal(runtime):
    record=_for_runtime(runtime)
    if record is None or record.thread[2]!=threading.get_native_id():return None
    record.validate(closing=record.owner._state=='closing')
    return record


def _ptd_create(runtime,phase,pointer=0):
    from . import primary_crt_thread as crt
    f=sys._getframe(1)
    if f.f_code is not crt.create.__code__ or f.f_locals.get('runtime') is not runtime:raise InputError('PTD journal requires source create')
    record=_journal(runtime)
    if record is None:return
    if phase=='begin':
        if record.ptd is not None:raise PrimarySemanticUnavailable('creator PTD cannot be re-created/adopted')
        record.ptd=dict(state='creating',runtime=runtime,epoch=record.epoch,slot=runtime.memory.load(runtime.image_base+0x6744470,4),pointer=None,allocation=None,fls=[],initialized=False,cleanup=False,consumed=False,failure=None)
    elif phase=='allocated':
        item=record.ptd;region,offset=runtime.memory._span(pointer,0x3c8)
        if offset or runtime.allocations.get(pointer)!=0x3c8:raise InputError('creator PTD allocation identity mismatch')
        item['pointer']=pointer;item['allocation']=(region,offset,0x3c8)
    elif phase=='initialized':record.ptd['initialized']=True;record.ptd['state']='initialized'
    elif phase=='returned_zero':
        item=record.ptd;crt=record.owner._crt
        item['state']='failed_unpublished' if not crt._values.get((record.thread[2],item['slot'])) and not any(x['exception'] is not None for x in item['fls']) else 'retained_native_publication'


def _ptd_failure(runtime,error):
    from . import primary_crt_thread as crt
    if sys._getframe(1).f_code is not crt.create.__code__:raise InputError('PTD failure journal requires source create')
    record=_journal(runtime)
    if record and record.ptd:
        item=record.ptd
        if item['failure'] is None:item['failure']=error
        item['state']='published_partial' if any(x.get('value')==item['pointer'] and x.get('result') for x in item['fls']) else 'failed_unpublished'


def _fls_attempt(observations,name,slot,value,token,storage):
    from .primary_windows_crt import WindowsCRTObservations
    f=sys._getframe(1)
    if type(observations) is not WindowsCRTObservations or f.f_code is not WindowsCRTObservations._fls.__code__ or f.f_locals.get('self') is not observations:raise InputError('FLS journal requires actual observer')
    r=observations._runtime;record=_journal(r)
    if record is None:return None
    if record.owner._crt is not observations or observations._owner!=(record.thread[0],record.thread[2]):raise InputError('creator FLS observer identity mismatch')
    if record.ptd is None:return None
    item=record.ptd
    if slot!=item['slot']:raise InputError('creator FLS slot changed')
    attempt=dict(observer=observations,slot=slot,value=value,token=token,storage=storage,result=None,error=None,exception=None)
    item['fls'].append(attempt)
    return attempt


def _fls_return(observations,attempt,result,error,exception=None):
    from .primary_windows_crt import WindowsCRTObservations
    if sys._getframe(1).f_code is not WindowsCRTObservations._fls.__code__:raise InputError('FLS completion journal requires actual observer')
    if attempt is not None:
        record=_journal(observations._runtime)
        if not any(row is attempt for row in record.ptd['fls']):raise InputError('foreign FLS journal completion')
        attempt.update(result=result,error=error,exception=exception)


def _ptd_cleanup(runtime,phase,pointer):
    from . import primary_crt_thread as crt
    if sys._getframe(1).f_code is not crt.cleanup.__code__:raise InputError('PTD cleanup journal requires source cleanup')
    record=_journal(runtime)
    if record is None:return
    item=record.ptd
    if item is None or item['pointer']!=pointer or not item['initialized'] or item['state']=='published_partial':raise PrimarySemanticUnavailable('creator PTD lacks complete initialization identity')
    if phase=='begin':
        if item['cleanup'] or item['consumed']:raise PrimarySemanticUnavailable('creator PTD cleanup already attempted/consumed')
        region,offset=runtime.memory._span(pointer,0x3c8)
        if region is not item['allocation'][0] or offset:raise InputError('creator PTD region replaced')
        item['cleanup']=True
    elif phase=='consumed':item['consumed']=True;item['state']='source_consumed'


def _register_domain(service,domain):
    from .primary_windows_threads import WindowsSDKThreadService
    f=sys._getframe(1)
    if f.f_code is not WindowsSDKThreadService._creator_crt_context.__wrapped__.__code__ or f.f_locals.get('self') is not service:raise InputError('creator domain requires original context producer')
    record=_for_service(service);record.validate()
    if record.domain is not None:raise InputError('creator domain cannot rebind')
    tls=domain['tls'];region,offset=record.memory._span(tls,0xd78)
    if offset or record.runtime.allocations.get(tls)!=0xd78 or service._crt_domains.get(record.thread[2]) is not domain:raise InputError('creator D78 publication identity mismatch')
    record.domain=dict(value=domain,tls=tls,region=region,active=False,retired=False,services_exit=False,failure=None)


def _associate_ptd(service):
    record=_for_service(service);record.validate(closing=record.owner._state=='closing')
    item=record.ptd;crt=record.owner._crt
    if item is None or not item['initialized'] or item['consumed'] or item['cleanup']:
        raise PrimarySemanticUnavailable('creator context lacks complete unconsumed PTD provenance')
    token=crt._values.get((record.thread[2],item['slot']));native=crt._tokens.get(token)
    publications=[x for x in item['fls'] if x['value']==item['pointer'] and x['result'] and x['token']==token and x['storage'] is (None if native is None else native[0])]
    if not publications or native is None or native[1:]!=(item['pointer'],record.thread[2],item['slot']):raise InputError('creator inherited PTD slot/token identity not proven')
    region,offset=record.memory._span(item['pointer'],0x3c8)
    if region is not item['allocation'][0] or offset:raise InputError('creator inherited PTD allocation replaced')
    if item.get('last_get')!=(crt,item['slot'],token,native):raise InputError('creator PTD inheritance lacks actual current getter identity')
    item['native_identity']=(crt,token,native)
    return item['pointer']


def _validate_domain(service,domain,*,active=True):
    record=_for_service(service)
    if record is None:raise InputError('creator issuer missing')
    record.validate(closing=record.owner._state=='closing')
    d=record.domain;r=record.runtime
    if d is None or d['value'] is not domain or d['retired'] or service._crt_domains.get(record.thread[2]) is not domain or domain.get('services_closed') is not False:
        raise InputError('creator domain publication/lifetime changed')
    region,offset=r.memory._span(d['tls'],0xd78)
    if region is not d['region'] or offset or domain['tls']!=d['tls'] or r.tls_base_address!=d['tls'] or r.tls_epoch_address!=d['tls']+0xa8:
        raise InputError('creator aliases/D78 backing changed')
    r.memory.load(d['tls']+0xa8,4)
    if active and not d['active']:raise InputError('creator consumer is not active')
    return record


def _mint_receipt(runtime,service,domain,receipt):
    from .primary_shared_locale import _activate_creator_module_tls
    if sys._getframe(1).f_code is not _activate_creator_module_tls.__code__:raise InputError('creator receipt issuer is private')
    record=_validate_domain(service,domain)
    record.receipts.clear()
    record.receipts[receipt]=(runtime,record.source,domain,record.epoch,record.domain['tls'],record.domain['region'])


def _validate_receipt(receipt,runtime,source):
    record=_for_runtime(runtime)
    if record is None:raise InputError('creator receipt issuer missing')
    row=record.receipts.get(receipt)
    if row is None or row!=(runtime,source,receipt.domain,source.epoch,receipt.tls_base,receipt.region) or receipt.service is not record.service:
        raise InputError('foreign/retargeted creator receipt')
    _validate_domain(record.service,receipt.domain)
    if record.ptd and record.ptd['consumed']:raise InputError('creator receipt cannot revive consumed PTD')


def _safe_restore(service,values):
    record=_for_service(service)
    if record and record.ptd and record.ptd['consumed'] and values.get('crt_thread_address')==record.ptd['pointer']:
        values=dict(values);values['crt_thread_address']=None
    return values


def _revoke_receipt(runtime,receipt):
    from .primary_shared_locale import _invalidate_module_tls
    if sys._getframe(1).f_code is not _invalidate_module_tls.__code__:raise InputError('creator revocation requires actual TLS invalidation')
    record=_for_runtime(runtime)
    if record:record.receipts.pop(receipt,None)


def _fls_get(observations,slot,token,native):
    from .primary_windows_crt import WindowsCRTObservations
    if sys._getframe(1).f_code is not WindowsCRTObservations._fls.__code__:raise InputError('PTD get journal requires actual observer')
    record=_journal(observations._runtime)
    if record and record.ptd:
        if native[1]==(1<<64)-1:
            record.ptd['sentinel_get']=(observations,slot,token,native)
            return
        if native[1:]!=(record.ptd['pointer'],record.thread[2],record.ptd['slot']):raise InputError('creator actual FLS getter differs from issued PTD')
        record.ptd['last_get']=(observations,slot,token,native)


def _closing_ids(service):
    record=_for_service(service)
    if record is None:return set()
    if record.state=='terminal':return set()
    record.validate(lease=False,closing=True)
    if getattr(record,'pending_unpublished',None) is not None:raise PrimarySemanticUnavailable('creator retains unknown partial services/aliases')
    item=record.ptd
    if item and (item['state'] in ('published_partial','retained_native_publication') or any(x['exception'] is not None for x in item['fls'])):
        raise PrimarySemanticUnavailable('creator PTD publication/initialization remains partial or unknown')
    if record.domain is None:
        crt=record.owner._crt
        if item is None or item['state']=='failed_unpublished':return set()
        token=crt._values.get((record.thread[2],item['slot']));native=crt._tokens.get(token)
        publications=[x for x in item['fls'] if x['value']==item['pointer'] and x['result'] and x['token']==token and x['storage'] is (None if native is None else native[0])]
        if (not item['initialized'] or item['cleanup'] or not publications or native is None or
                native[1:]!=(item['pointer'],record.thread[2],item['slot']) or
                crt._callbacks_active or crt._callback_failure is not None):
            raise PrimarySemanticUnavailable('creator standalone PTD publication/cleanup identity unknown')
        region,offset=record.memory._span(item['pointer'],0x3c8)
        if region is not item['allocation'][0] or offset:raise InputError('creator standalone PTD region replaced')
        return {record.thread[2]}
    d=record.domain;domain=d['value'];r=record.runtime
    crt=record.owner._crt;snapshot=crt.snapshot()
    region,offset=r.memory._span(d['tls'],0xd78)
    if (d['active'] or d['retired'] or domain.get('services_closed') is not False or region is not d['region'] or offset or
            service._crt_domains.get(record.thread[2]) is not domain or service._active_owner or service._execution.locked() or
            service._module_pending or service._holder_active or service._holder_failure is not None or
            snapshot['callbacks_active'] or snapshot['callback_failure'] is not None or
            item is None or not item['initialized']):
        raise PrimarySemanticUnavailable('creator is not quiescent/fully initialized for ordered close')
    identity=item.get('native_identity')
    if item['consumed']:
        cleared=any(x['value']==0 and x['result'] for x in item['fls']) or item.get('callback_returned')
        if not cleared or crt._values.get((record.thread[2],item['slot'])):raise PrimarySemanticUnavailable('consumed creator PTD native retirement unknown')
    elif item['cleanup'] or identity is None or identity[0] is not crt or crt._values.get((record.thread[2],item['slot']))!=identity[1] or crt._tokens.get(identity[1]) is not identity[2]:
        raise PrimarySemanticUnavailable('creator PTD borrow identity unknown')
    return {record.thread[2]}


def _close_lease_active(service):
    record=_for_service(service)
    lease=None if record is None else getattr(record,'close_lease',None)
    if lease is None:return False
    record.validate(closing=True)
    return (lease.active and not lease.suspended and lease.registrar is record.registrar and
            any(current is lease for current in record.registrar._leases.get(record.thread[2],())))


def _source_cleanup_allowed(service):
    record=_for_service(service)
    if record is None:return True
    record.validate(closing=True)
    item=record.ptd
    if item is None or item['state']=='failed_unpublished':return True
    if item['consumed']:
        crt=record.owner._crt
        if crt._values.get((record.thread[2],item['slot'])):raise PrimarySemanticUnavailable('creator source-consumed PTD still natively published; no repeated clear')
        return False
    if not item['initialized'] or item['cleanup']:raise PrimarySemanticUnavailable('creator PTD cleanup partial/already attempted')
    return True


def _retire_domain(service):
    record=_for_service(service);record.validate(closing=True)
    if record.domain is None:return
    d=record.domain;item=record.ptd;crt=record.owner._crt
    if item is None or not item['consumed'] or crt._values.get((record.thread[2],item['slot'])) or crt._callbacks_active or crt._callback_failure is not None:
        raise PrimarySemanticUnavailable('creator native PTD/clear/callback obligation retained')
    try:d['value']['services'].__exit__(None,None,None)
    except BaseException as error:
        d['failure']=error
        if not record.failures:record.failures.append(error)
        raise
    d['value']['services_closed']=True;d['services_exit']=True


def _finish_domain(service):
    record=_for_service(service)
    if record is None:return
    if record.domain is not None:
        d=record.domain
        if not d['services_exit'] or d['active'] or record.receipts:raise PrimarySemanticUnavailable('creator services/receipt still active')
        record.runtime._free_allocation(d['tls'])
        del service._crt_domains[record.thread[2]];d['retired']=True
    record.state='terminal'


def _callback_ptd(observations,token,phase):
    from .primary_windows_crt import WindowsCRTObservations
    if sys._getframe(1).f_code is not WindowsCRTObservations._cleanup_token.__code__:raise InputError('creator callback journal requires actual FLS observer')
    record=_for_runtime(observations._runtime)
    if record is None or record.thread[2]!=threading.get_native_id():return
    record.validate(lease=False,closing=record.owner._state=='closing')
    item=record.ptd;native=observations._tokens.get(token)
    if item is None or native is None or native[1:]!=(item['pointer'],record.thread[2],item['slot']) or not item['initialized']:
        raise PrimarySemanticUnavailable('creator FLS callback lacks complete PTD provenance')
    if phase=='begin':
        if item['cleanup'] or item['consumed']:raise PrimarySemanticUnavailable('creator PTD already consumed/cleanup attempted')
        item['cleanup']=True
    else:item['consumed']=True;item['state']='source_consumed';item['callback_returned']=True
