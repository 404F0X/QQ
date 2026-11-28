import unittest
from unittest.mock import Mock
from qq_nt_replica.primary_qimei_kind2_request import QimeiKind2Request
from qq_nt_replica.primary_qimei_request import RequestSlot,QimeiRequestBoundary
class Request(unittest.TestCase):
    def request(self,producer=None,allocation=None):
        return QimeiKind2Request(b'owner',Mock() if producer is None else producer,convert_ansi=lambda b:b,allocate_slots=Mock(return_value=True) if allocation is None else allocation,dispatch=Mock(),module_state=__import__('qq_nt_replica.primary_qimei_request_state',fromlist=['QimeiModuleRequestState']).QimeiModuleRequestState(0),clock_milliseconds=Mock(side_effect=[0,1,2]),allocate_response=lambda *a:True)
    def test_constructor_zero_state_producer_and_serializer(self):
        producer=Mock()
        def populate(owner,state):
            self.assertEqual(owner,b'owner');self.assertEqual(state.slots,[RequestSlot() for _ in range(48)])
            state.set_u32(1,3);state.slots[1]=RequestSlot(99,b'present');state.set_u32(3,9)
        producer.populate.side_effect=populate;r=self.request(producer)
        self.assertEqual((r.kind,r.count,r.response_count,r.success),(2,48,1,False))
        self.assertEqual(r.produce_payload(),b'\x08\x03');producer.populate.assert_called_once();r.allocate_slots.assert_called_once_with(768)
        self.assertTrue(r.consume_response(b'any'));self.assertFalse(r.success)
    def test_null_and_exceptions(self):
        producer=Mock();r=self.request(producer,Mock(return_value=False))
        self.assertEqual(r.produce_payload(),b'');producer.populate.assert_not_called()
        error=RuntimeError('controlled handler')
        r=self.request(allocation=Mock(side_effect=error))
        with self.assertRaises(RuntimeError) as raised:r.produce_payload()
        self.assertIs(raised.exception,error)
        producer.populate.side_effect=error;r=self.request(producer)
        with self.assertRaises(RuntimeError) as raised:r.produce_payload()
        self.assertIs(raised.exception,error)

    def test_original_partial_boundary_and_absent_tag_skip(self):
        producer=Mock()
        def populate(owner,state):
            state.set_u32(1,3)
            state.slots[1]=RequestSlot(99,None)
            state.slots[2]=object()
        producer.populate.side_effect=populate
        with self.assertRaises(QimeiRequestBoundary) as raised:self.request(producer).produce_payload()
        self.assertEqual(raised.exception.slot_index,2)
        self.assertEqual(raised.exception.partial,b'\x08\x03')

    def test_completion_priority_count1_missing_and_old_success(self):
        from qq_nt_replica.primary_qimei_kind2_request import source_completion
        r=self.request()
        for http,server,local,want in ((500,9,7,b'{"net":"500"}'),(200,9,7,b'{"sever":"9"}'),(200,0,-1,b'{"local":"4294967295"}')):
            r.receive(b'\x10\x01',result_code=local,http_status=http,server_code=server)
            self.assertEqual(r.error,want);self.assertFalse(r.success)
        r.receive(b'\x10\x01',result_code=1,http_status=0,server_code=9)
        self.assertTrue(r.success) # accepted missing field1, HTTP0 selects net0
        for body in (b'',b'\x0b'):
            r.receive(body,result_code=0,http_status=200,server_code=0)
            self.assertTrue(r.success)
        r.receive(b'x',result_code=9,http_status=500,server_code=0);self.assertTrue(r.success)
        self.assertIsNone(source_completion(b'x',0,0,0,None))
        r=self.request();r.receive(b'\x0b',result_code=0,http_status=200,server_code=0);self.assertFalse(r.success)
        r=self.request();r.allocate_response=Mock(return_value=False)
        r.receive(b'\x10\x01',result_code=0,http_status=200,server_code=0)
        self.assertFalse(r.success);r.allocate_response.assert_called_once_with('slots',None,17)
        r=self.request();source_completion(b'',1,0,0,r);self.assertFalse(r.success)
        self.assertFalse(hasattr(r,'qimei'))
    def test_payload_once_limits_dispatch_return_and_required_hooks(self):
        for limit in (-1,0,1):
            r=self.request();events=[]
            r.payload_producer.populate.side_effect=lambda *args:events.append('payload')
            def dispatch(owner,kind,payload,callback,context):
                events.append('dispatch');self.assertEqual((owner,kind,payload),(b'owner',2,b''))
                callback(b'\x10\x01',0,200,0,context)
                return False
            r.dispatch.dispatch.side_effect=dispatch
            self.assertEqual(r.run(limit),limit==1)
            self.assertEqual(events,['payload','dispatch'] if limit==1 else ['payload'])
            self.assertEqual(r.module_state.read_mask(),4 if limit==1 else 0);self.assertEqual(r.clock_milliseconds.call_count,3)
        r=self.request();r.dispatch.dispatch.return_value=True
        self.assertFalse(r.run());self.assertEqual(r.module_state.read_mask(),0)
        r=self.request()
        with self.assertRaises(QimeiRequestBoundary):r.run(2)
        r.payload_producer.populate.assert_not_called()
