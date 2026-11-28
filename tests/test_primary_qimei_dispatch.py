import base64,json,unittest
from types import SimpleNamespace as NS
from qq_nt_replica.primary_qimei_dispatch import QimeiSourceDispatch,QimeiDispatchState,QimeiCarrierPort,CarrierOutcome
from qq_nt_replica.primary_qimei_request_pipeline import QimeiRequestPipeline
from qq_nt_replica.primary_qimei_kind2_request import QimeiKind2Request
from qq_nt_replica.primary_qimei_request_state import QimeiModuleRequestState
from qq_nt_replica.primary_qimei_cache import _cbc
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
class Carrier(QimeiCarrierPort):
    def __init__(self,fn):self.fn=fn
    def perform(self,request):return self.fn(request)
class Dispatch(unittest.TestCase):
    def fixture(self,state=None):
        events=[];requests=[]
        def produce(owner,kind,seq):events.append(('material',owner,kind,seq));return NS(serialize=lambda:b'header')
        def envelope(header,payload,**kw):events.append(('envelope',header,payload));return b'envelope'
        def transport(value,**kw):
            events.append(('transport',value,kw));n=len(requests)+1
            req=NS(body=b'body'+bytes([n]),key=bytes([n])*16,iv=bytes([9])*16);requests.append(req);return req
        d=QimeiSourceDispatch(QimeiDispatchState(0) if state is None else state,NS(produce=produce),envelope=NS(encode=envelope),configuration=object(),transport=NS(encode=transport),carrier=None,sign_enabled=False)
        return d,events,requests
    def reply(self,req,body=b'\x10\x01'):
        padding=16-len(body)%16;cipher=_cbc(body+bytes([padding])*padding,req.key,req.iv,decrypt=False)
        return json.dumps({'code':'0','data':base64.b64encode(cipher).decode()}).encode()
    def request(self,d):
        ticks=iter([0,1,2])
        return QimeiKind2Request(b'owner',NS(populate=lambda owner,state:state.set_u32(1,7)),convert_ansi=lambda b:b,allocate_slots=lambda n:True,dispatch=d,module_state=QimeiModuleRequestState(0),clock_milliseconds=lambda:next(ticks),allocate_response=lambda *a:True)
    def test_actual_run_encode_projection_completion(self):
        d,e,reqs=self.fixture();d.carrier=Carrier(lambda http:CarrierOutcome(self.reply(reqs[-1]),999))
        r=self.request(d);self.assertTrue(r.run());self.assertEqual(r.module_state.read_mask(),4)
        self.assertEqual(e[0],('material',b'owner',2,0));self.assertEqual(e[1],('envelope',b'header',b'\x08\x07'))
        kw=e[2][2];self.assertEqual((kw['mode'],kw['long_names'],kw['extra'].values),(1,False,{b'app_key':b'owner'}));self.assertEqual(d.state.pending,{})
    def test_shared_counter_wrap_nested_request_owned_key_context(self):
        state=QimeiDispatchState(0xFFFFFFFFFFFFFFFF);d,e,reqs=self.fixture(state);seen=[]
        def perform(http):
            current=reqs[-1]
            if len(reqs)==1:
                self.assertEqual(len(state.pending),1)
                d.dispatch(b'inner',2,b'inner',lambda *a:seen.append(a),'inner-context')
            return CarrierOutcome(self.reply(current),500)
        d.carrier=Carrier(perform)
        d.dispatch(b'outer',2,b'outer',lambda *a:seen.append(a),'outer-context')
        self.assertEqual([x[3] for x in e if x[0]=='material'],[-1,0]);self.assertEqual(state.sequence,1)
        self.assertEqual([x[-1] for x in seen],['inner-context','outer-context']);self.assertTrue(all(x[:4]==(b'\x10\x01',0,200,0) for x in seen));self.assertEqual(state.pending,{})
    def test_empty_raw_status_errors_and_missing_backend(self):
        d,e,reqs=self.fixture()
        with self.assertRaises(QimeiRequestBoundary):self.request(d).run()
        self.assertEqual(e,[]);self.assertEqual(d.state.sequence,0)
        seen=[];d.carrier=Carrier(lambda http:CarrierOutcome(b'',503));d.dispatch(b'o',2,b'p',lambda *a:seen.append(a),None)
        self.assertEqual(seen,[(b'',8,503,0,None)])
        error=RuntimeError('controlled carrier')
        def fail(http):raise error
        d.carrier=Carrier(fail)
        with self.assertRaises(RuntimeError) as raised:d.dispatch(b'o',2,b'p',lambda *a:None,None)
        self.assertIs(raised.exception,error);self.assertEqual(len(d.state.pending),1)
    def test_generic_prepare_compatibility_controlled_existing_method(self):
        d,e,reqs=self.fixture();producer=NS(owner=b'o',populate=lambda:NS(encode=lambda **kw:b'generic51'))
        fixture=NS(request_producer=producer,material_producer=d.material_producer,envelope=d.envelope,configuration=d.configuration,transport=d.transport,sign_enabled=False,convert_ansi=lambda b:b)
        got=QimeiRequestPipeline.prepare(fixture,b'o',4,-1)
        self.assertEqual(e[0],('material',b'o',4,0xFFFFFFFF));self.assertEqual(e[1],('envelope',b'header',b'generic51'));self.assertEqual(e[2][2]['mode'],2);self.assertEqual(got.sequence,0xFFFFFFFF)

        from qq_nt_replica.primary_qimei_extras import QimeiRequestExtras
        extra=QimeiRequestExtras({b'x':b'old'})
        def populate():
            extra.values[b'x']=b'changed'
            return NS(encode=lambda **kw:b'generic51')
        producer.populate=populate
        QimeiRequestPipeline.prepare(fixture,b'o',4,1,extra=extra)
        self.assertEqual(e[-1][2]['extra'].values,{b'x':b'old'})
