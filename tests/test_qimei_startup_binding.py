import unittest
from qq_nt_replica.primary_qimei_application_binding import (
    bind_application, start_application, StartupCallbackState, ApplicationBinding)
from qq_nt_replica.primary_qimei_sdk import QimeiSdkContexts
from qq_nt_replica.primary_qimei_application import QimeiApplication
from qq_nt_replica.primary_qimei_observations import QimeiApiReply
from qq_nt_replica.primary_qimei_records import StartupState, RecordObservations
from qq_nt_replica.primary_qimei_context import QimeiContextProducer
from qq_nt_replica.primary_qimei_cache import QimeiCacheCodec
from qq_nt_replica.primary_source_config import SourceProfile, SourceFact
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary

BASE = b'X:\\model\\Tencent\\qimei'
SELECTED = bytes.fromhex('102030405060')

class Folders:
    def __init__(self, statuses=(1,), directory=True):
        self.statuses=iter(statuses);self.calls=[];self.directory=directory
    def read(self, kind, name, *args):
        self.calls.append((name,args))
        if name=='SHGetSpecialFolderPathA':
            result=next(self.statuses)
            return QimeiApiReply(result, (('data',0,b'X:\\model\0'),) if result else ())
        if name=='PathIsDirectoryA':return QimeiApiReply(int(self.directory or args[0]!=BASE))
        if name=='CreateDirectoryA':return QimeiApiReply(1)
        raise AssertionError(name)

class Reader:
    def read(self):return QimeiApplication(b'controlled-GUID!')
    def metadata(self):return {}

class Startup(unittest.TestCase):
    def setUp(self):
        self.contexts=QimeiSdkContexts()
        self.binding=bind_application('X:\\model',contexts=self.contexts,settings_by_owner={},
            settings_observations=Folders((0,0)),reader_factory=lambda *a,**k:Reader())
        self.state=StartupState.cold();self.callback=StartupCallbackState()
        self.codec=QimeiCacheCodec()
        self.profile=SourceProfile((SourceFact('qua','source-default','known',0,b'model-qua'),),0,0)
    def obs(self, identity=None, main=None, base=BASE):
        values={('open','identity1',base+b'\\Configv2.ini'):identity is not None,
                ('allocate','main',53):True,('ciphertext','main',base+b'\\Global.db'):main or b''}
        if identity is not None:
            cipher=self.codec.encode_payload(identity,context=b'').value
            values.update({('file-length','identity1',base+b'\\Configv2.ini'):len(cipher),
                ('allocate','identity1',len(cipher)):True,
                ('ciphertext','identity1',base+b'\\Configv2.ini'):cipher})
        return RecordObservations(values,codec=self.codec,
            context_producer=QimeiContextProducer(context=b'',initialized=True))
    def runstage(self, observations=None, folders=None, **kw):
        args=dict(startup=self.state,callback_state=self.callback,callback=None,arg7=object(),
            observations=observations or self.obs(),folder_observations=folders or Folders(),
            selector=lambda:SELECTED,source_profile=self.profile,uin=1,machine_id=b'model-machine')
        args.update(kw);return start_application(self.binding,**args)
    def test_raw_cipher_to_profile_and_original_binding(self):
        main=self.codec.encode_records(b'a'*16,b'b'*37,context=b'').value
        obs=self.obs(b'{"0":"102030405060"}',main)
        result=self.runstage(obs)
        self.assertIs(result.binding,self.binding);self.assertTrue(result.identity_unchanged)
        self.assertEqual(self.state.main.get(1),b'b'*37)
        self.assertEqual(result.profile.record1,b'b'*37)
        self.assertNotIn(('base-path',),obs.values)
    def test_cross_appid_once_and_callback_null_gate(self):
        first=object();self.runstage(arg7=None,callback=first)
        self.assertEqual(self.state.once,0);self.assertIs(self.callback.callback,first)
        self.runstage(callback=object());self.assertEqual(self.state.once,1)
        second=self.contexts.get(b'ordinary-other');second.configure(None,b'x\0y',None,257)
        self.binding=ApplicationBinding(second.owner,self.binding.settings,second,{})
        folders=Folders(())
        result=self.runstage(folders=folders,callback=object())
        self.assertIsNone(result.identity_unchanged);self.assertEqual(folders.calls,[])
        self.assertIs(self.callback.callback,first);self.assertEqual(second.strings(),(b'',b'x',b''));self.assertEqual(second.option,1)
    def test_folder_fallback_and_create(self):
        folder=Folders((0,1),False);self.runstage(folders=folder)
        self.assertEqual([x[1][2:] for x in folder.calls if x[0]=='SHGetSpecialFolderPathA'],[(0x23,1),(0x1a,1)])
        self.assertIn(('CreateDirectoryA',(BASE,0)),folder.calls)
    def test_both_folders_fail_and_ordinary_read_failure_once(self):
        folder=Folders((0,0));r=self.runstage(self.obs(base=b''),folder)
        self.assertTrue(r.identity_unchanged);self.assertEqual(self.state.main.path,b'');self.assertEqual(self.state.once,1)
        self.assertEqual(len(folder.calls),2)
    def test_preferred_skips_fallback(self):
        folder=Folders((1,));self.runstage(folders=folder)
        self.assertEqual(len([x for x in folder.calls if x[0]=='SHGetSpecialFolderPathA']),1)
    def test_identity_changed_skips_main(self):
        obs=self.obs(b'{"0":"ffffffffffff"}')
        obs.values.pop(('ciphertext','main',BASE+b'\\Global.db'))
        r=self.runstage(obs);self.assertFalse(r.identity_unchanged)
        self.assertEqual(self.state.identity1.get(0),b'');self.assertEqual(self.state.once,1)
    def test_exception_preserves_prefix_and_no_once(self):
        def fail(*args):raise RuntimeError('controlled')
        with self.assertRaises(RuntimeError):self.runstage(observe=fail)
        self.assertEqual(self.state.once,0)
        def later(event,store,record):
            if store.name=='main' and event=='append':raise RuntimeError('later')
        with self.assertRaises(RuntimeError):self.runstage(observe=later)
        self.assertEqual(len(self.state.identity1.records),3);self.assertEqual(self.state.once,0)
    def test_no_predecoded_or_parse_override(self):
        obs=self.obs();obs.values[('decode','main',BASE+b'\\Global.db',53)]=object()
        with self.assertRaises(QimeiRequestBoundary):self.runstage(obs)
        self.assertEqual(self.state.once,0)

    def test_bad_cipher_normal_return_still_once(self):
        obs=self.obs(main=b'bad ciphertext')
        result=self.runstage(obs)
        self.assertTrue(result.identity_unchanged)
        self.assertEqual(self.state.once,1)
        self.assertIsNone(result.profile.record1)

    def test_falsey_callback_and_gate_are_nonnull(self):
        self.runstage(callback=0,arg7=False)
        self.assertEqual(self.state.once,1)
        self.runstage(callback=object())
        self.assertIs(self.callback.callback,0)
