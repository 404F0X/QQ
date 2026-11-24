import unittest
from unittest.mock import Mock
from qq_nt_replica.primary_qimei_application_binding import bind_application,derive_application_msf_path
from qq_nt_replica.primary_qimei_application import APPLICATION_OWNER,QimeiApplication
from qq_nt_replica.primary_qimei_sdk import QimeiSdkContexts
from qq_nt_replica.primary_qimei_settings import QimeiSettings,default_flag_arrays
from qq_nt_replica.primary_qimei_observations import QimeiApiReply
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
class Observations:
    def __init__(self,events,fail=False):self.events=events;self.fail=fail
    def read(self,kind,name,*args):
        self.events.append(name)
        if self.fail:raise RuntimeError('controlled settings failure')
        assert name=='SHGetSpecialFolderPathA'
        return QimeiApiReply(0)
class Reader:
    def __init__(self,events):self.events=events;self.count=0
    def read(self):
        assert self.count==0
        self.count+=1;self.events.append('read');return QimeiApplication(b'controlled-GUID!')
    def metadata(self):return dict(used=True,closed=True,file_handles=0,local_allocations=0,selected_read_length=32,unsafe='must not expose')
class Binding(unittest.TestCase):
    def test_path_finite_literal_projection(self):
        self.assertEqual(derive_application_msf_path('D:\\Profile-1'), 'D:\\Profile-1\\nt_data\\msf')
        self.assertEqual(derive_application_msf_path(r'D:\p\nt_data\msf'),r'D:\p\nt_data\msf\nt_data\msf')
        for value in ('relative','D:/Profile','D:\\has space','D:\\æ±‰','\\\\host\\share','D:\\p\\..\\q'):
            factory=Mock()
            with self.assertRaises(QimeiRequestBoundary):bind_application(value,contexts=QimeiSdkContexts(),settings_by_owner={},settings_observations=Mock(),reader_factory=factory)
            factory.assert_not_called()
    def test_read_defaults_configure_same_owner_warm_and_repr(self):
        events=[];reader=Reader(events);factory=Mock(return_value=reader);contexts=QimeiSdkContexts();pool={}
        binding=bind_application('D:\\Profile',contexts=contexts,settings_by_owner=pool,settings_observations=Observations(events),reader_factory=factory)
        self.assertEqual(events,['read','SHGetSpecialFolderPathA','SHGetSpecialFolderPathA']);self.assertEqual(reader.count,1)
        self.assertEqual(factory.call_args.args,('D:\\Profile\\nt_data\\msf',))
        self.assertIn('explanation only',factory.call_args.kwargs['source_binding'])
        self.assertIs(binding.context,contexts.get(APPLICATION_OWNER));self.assertIs(binding.settings,pool[APPLICATION_OWNER]);self.assertEqual(binding.context.option,1)
        first,second=default_flag_arrays();self.assertEqual(binding.settings.record[0x31:0x31+len(first)],first);self.assertEqual(binding.settings.record[0x259:0x259+len(second)],second)
        self.assertEqual(binding.reader_metadata,dict(used=True,closed=True,file_handles=0,local_allocations=0,selected_read_length=32))
        self.assertNotIn('GUID',repr(binding));self.assertNotIn('controlled',repr(binding))
        binding.settings.record[0x31]=99
        later=bind_application('D:\\Profile',contexts=contexts,settings_by_owner=pool,settings_observations=Observations(events,True),reader_factory=Mock(return_value=Reader(events)))
        self.assertIs(later.settings,binding.settings);self.assertIs(later.context,binding.context);self.assertEqual(later.settings.record[0x31],99)
    def test_reader_error_and_wrong_type_do_not_mutate_pools(self):
        for result in (RuntimeError('controlled reader'),object()):
            contexts=QimeiSdkContexts();pool={};reader=Mock()
            if isinstance(result,Exception):reader.read.side_effect=result
            else:reader.read.return_value=result
            with self.assertRaises((RuntimeError,QimeiRequestBoundary)):bind_application('D:\\P',contexts=contexts,settings_by_owner=pool,settings_observations=Mock(),reader_factory=Mock(return_value=reader))
            self.assertEqual(pool,{});self.assertEqual(contexts.contexts,{})
    def test_initialize_failure_keeps_inserted_settings_and_no_context(self):
        contexts=QimeiSdkContexts();pool={};events=[]
        with self.assertRaises(RuntimeError):bind_application('D:\\P',contexts=contexts,settings_by_owner=pool,settings_observations=Observations(events,True),reader_factory=Mock(return_value=Reader(events)))
        self.assertIn(APPLICATION_OWNER,pool);self.assertEqual(pool[APPLICATION_OWNER].initialized,0);self.assertEqual(contexts.contexts,{})
