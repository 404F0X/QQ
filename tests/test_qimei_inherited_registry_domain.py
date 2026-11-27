"""MODEL leaf APIs only: real Request -> System -> Extra dispatch and helpers."""
import pytest
from qq_nt_replica.primary_qimei_extra_sources import QimeiExtraSources, ADVERTISING_KEY, EDGE_PROFILES_KEY, HKCU
from qq_nt_replica.primary_qimei_system_sources import HKLM, WINDOWS_KEY
from qq_nt_replica.primary_windows_qimei_request_sources import WindowsQimeiRequestObservations
from qq_nt_replica.primary_qimei_storage import StorageBuffer
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary

class Leaf:
 def __init__(self, call): self.call=call
 def __call__(self,*args): return self.call(*args)
class API:
 def __init__(self): self.calls=[];self.paths={};self.failure=0;self.query_failure=0
 def __getattr__(self,name):
  def call(*a):
   self.calls.append((name,a[:2]))
   if name=='RegOpenKeyExA':
    h=len(self.paths)+1;self.paths[h]=a[1];a[4][:]=h.to_bytes(8,'little');return 0
   if name=='RegQueryValueExA':
    if self.query_failure:return self.query_failure
    value=self.model_values.get((self.paths[a[0]],a[1]),b'\0') if hasattr(type(self),'model_values') else (b'ad-id\0' if self.paths[a[0]]==ADVERTISING_KEY else b'duplicate\0')
    a[5][:]=len(value).to_bytes(4,'little')
    if a[4] is not None:a[4][:len(value)]=value
    return 0
   if name=='RegEnumKeyExA':
    if a[1]>=2:return 259
    value=(b'A' if a[1]==0 else b'B')+b'\0';a[2][:len(value)]=value;return 0
   if name=='RegCloseKey':return self.failure
   raise AssertionError('unexpected leaf '+name)
  leaf=Leaf(call);setattr(self,name,leaf);return leaf

def make():
 api=API();return api,WindowsQimeiRequestObservations(api=api)
def open_key(obs,path,root=HKCU,access=0x101):
 return obs.read('qimei-api','RegOpenKeyExA',root,path,0,access,StorageBuffer(bytes(8)))
def test_helpers_and_owned_close_failure():
 api,obs=make();extra=QimeiExtraSources(obs)
 assert extra.advertising_id().value==b'ad-id'
 assert extra.edge_id().value==b'duplicate#duplicate'
 assert not obs._handles
 assert sum(n=='RegQueryValueExA' for n,a in api.calls)==6
 assert sum(n=='RegEnumKeyExA' for n,a in api.calls)==3
 api.query_failure=5
 assert not extra.advertising_id().accepted
 assert not obs._handles
 open_key(obs,ADVERTISING_KEY);h=next(iter(obs._handles));api.failure=5
 assert obs.read('qimei-api','RegCloseKey',h).result==5
 assert h in obs._handles
 with pytest.raises(QimeiRequestBoundary):obs.close()
 assert h in obs._handles
 api.failure=0;obs.close();assert not obs._handles

def test_system_domain_and_rejections_before_leaf():
 api,obs=make()
 open_key(obs,WINDOWS_KEY,HKLM);h=next(iter(obs._handles))
 obs.read('qimei-api','RegQueryValueExA',h,b'ProductName',0,None,None,StorageBuffer(bytes(4)))
 obs.read('qimei-api','RegCloseKey',h)
 for root,path,access in [(HKLM,ADVERTISING_KEY,0x101),(HKCU,b'unknown',0x101),(HKCU,ADVERTISING_KEY,0x108),(HKCU,EDGE_PROFILES_KEY,0x101),(HKCU,EDGE_PROFILES_KEY+b'\\A',0x108)]:
  before=len(api.calls)
  with pytest.raises(QimeiRequestBoundary):open_key(obs,path,root,access)
  assert len(api.calls)==before
 open_key(obs,ADVERTISING_KEY);h=next(iter(obs._handles))
 for handle,key in [(h,b'MUID'),(999,b'id')]:
  before=len(api.calls)
  with pytest.raises(QimeiRequestBoundary):obs.read('qimei-api','RegQueryValueExA',handle,key,0,None,None,StorageBuffer(bytes(4)))
  assert len(api.calls)==before
 obs.close()

@pytest.mark.parametrize('hit',[0,1,2,3,None])
def test_model_fallback_order_cache_and_finite_domain(hit):
 from qq_nt_replica.primary_qimei_transport_material import QimeiTransportGlobals,MODEL_KEYS
 from qq_nt_replica.primary_qimei_system_sources import QimeiSystemSources
 from qq_nt_replica.primary_qimei_request_sources import QimeiRequestSources
 from qq_nt_replica.primary_windows_qimei_extensions import WindowsQimeiExtensionObservations
 from qq_nt_replica.primary_qimei_settings import QimeiSettings
 order=[(path,name) for name in (b'SystemFamily',b'SystemVersion') for path in MODEL_KEYS]
 class ModelAPI(API):
  model_values={} if hit is None else {order[hit]:b'model-value\0'}
 api=ModelAPI();obs=WindowsQimeiRequestObservations(api=api)
 # Real extension helper returns its empty six values after ordinary load failure.
 extapi=API();extapi.LoadLibraryA=Leaf(lambda *a:0)
 extport=WindowsQimeiExtensionObservations(api=extapi)
 extension=QimeiRequestSources(obs,extension_observations=extport)
 settings=QimeiSettings();settings.initialize_owned_path(path=b'owned-model-settings')
 globals=QimeiTransportGlobals(obs);system=QimeiSystemSources(obs)
 deps={'read_file':lambda path:b''}
 expected=b'' if hit is None else b'model-value'
 assert globals.model(extension,system,settings,settings_dependencies=deps)==expected
 queries=[(api.paths[a[0]],a[1]) for name,a in api.calls if name=='RegQueryValueExA']
 assert queries==[pair for pair in order[:4 if hit is None else hit+1] for unused in range(2)]
 count=len(api.calls)
 assert globals.model(extension,system,settings,settings_dependencies=deps)==expected
 assert len(api.calls)==count and not obs._handles
 before=len(api.calls)
 with pytest.raises(QimeiRequestBoundary):open_key(obs,MODEL_KEYS[0]+b'X',HKLM)
 assert len(api.calls)==before
 open_key(obs,MODEL_KEYS[0],HKLM);h=next(iter(obs._handles));before=len(api.calls)
 with pytest.raises(QimeiRequestBoundary):obs.read('qimei-api','RegQueryValueExA',h,b'SystemFamilyX',0,None,None,StorageBuffer(bytes(4)))
 assert len(api.calls)==before
 obs.close();extport.close()
