import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from qq_nt_replica.primary_windows_signer_setup import IndependentWindowsSetup, business_metadata, BUSINESS_QUA
from qq_nt_replica.errors import InputError

class BusinessSetup(unittest.TestCase):
    def test_cold_profile_and_identity(self):
        m=business_metadata(uin=18446744073709551615,machine_id=b'own-id')
        self.assertEqual((m.field_08,m.field_10,m.field_18,m.field_20),(b'',BUSINESS_QUA,b'18446744073709551615',b'own-id'))
        for uin,identity in ((True,b'id'),(-1,b'id'),(1<<64,b'id'),(1,b''),(1,b'a\0b')):
            with self.assertRaises(InputError):business_metadata(uin=uin,machine_id=identity)

    def owner(self, initialize):
        row=dict(role='bootstrap',state='created_pending',host_failure=None,handle=123,thread_id=456,source_completed=False)
        runtime=NS(image_base=0,memory=NS(load=lambda address,size:1 if size==1 else 123),raw_core_observations='prior')
        runtime.attach_host129_raw_api_inputs=lambda inputs:self.events.append(('attach',inputs))
        return NS(_state='open',_busy=False,_caller='caller',initialize_provider=initialize,
            _threads=NS(_failure=None,snapshot=lambda:dict(closed=False,draining=False,execution_locked=False,threads=[row])),signer=NS(runtime=runtime,environment=NS()))

    def test_business_runs_shared_initializer_and_host_binding(self):
        self.events=[]
        owner=self.owner(lambda metadata,**kw:self.events.append(('initialize',metadata,kw)))
        delegate=NS(bind=lambda r:self.events.append(('delegate',r)),bind_caller=lambda caller:None,close=lambda:None)
        source=NS(bind=lambda r:self.events.append(('source',r)),close=lambda:None)
        setup=IndependentWindowsSetup(owner)
        with patch('qq_nt_replica.primary_windows_signer_setup.WindowsCoreObservations',return_value=delegate), patch('qq_nt_replica.primary_windows_signer_setup.WindowsHost129Source',return_value=source), patch('qq_nt_replica.primary_windows_signer_setup.Host129RawAPIInputs',side_effect=lambda *a,**kw:(a,kw)):
            setup.prepare_business(uin=42,machine_id=b'own-id')
        self.assertEqual([e[0] for e in self.events],['initialize','delegate','source','attach'])
        self.assertEqual(self.events[0][2],dict(private_context_tail=None))
        self.assertEqual(setup.state,'ready')
        self.assertEqual(owner.signer.runtime.raw_core_observations,'prior')
        with self.assertRaises(InputError):setup.prepare_business(uin=42,machine_id=b'own-id')
        setup.close()

    def test_original_initialization_exception_and_failed_state(self):
        error=RuntimeError('original')
        def fail(*a,**kw):raise error
        setup=IndependentWindowsSetup(self.owner(fail))
        with self.assertRaises(RuntimeError) as caught:setup.prepare_business(uin=1,machine_id=b'id')
        self.assertIs(caught.exception,error)
        self.assertEqual(setup.state,'failed')
        setup.close()

    def test_modes_rejected_before_native_construction(self):
        from qq_nt_replica.primary_windows_signer import open_windows_signer
        for extra in (dict(outer_login_config={}),dict(independent_provider_metadata=object())):
            with self.assertRaises(InputError):open_windows_signer(bridge_path='unused',storage_root='unused',host_profile_string=BUSINESS_QUA,own_business_config=dict(uin=1,machine_id=b'id'),**extra)

    def test_binding_failure_retains_source_for_close(self):
        self.events=[]; error=RuntimeError('bind-original'); closed=[]
        owner=self.owner(lambda *a,**kw:None)
        delegate=NS(bind=lambda r:None,bind_caller=lambda c:None,close=lambda:closed.append('delegate'))
        def fail(r):raise error
        source=NS(bind=fail,close=lambda:closed.append('source'))
        setup=IndependentWindowsSetup(owner)
        with patch('qq_nt_replica.primary_windows_signer_setup.WindowsCoreObservations',return_value=delegate),patch('qq_nt_replica.primary_windows_signer_setup.WindowsHost129Source',return_value=source):
            with self.assertRaises(RuntimeError) as caught:setup.prepare_business(uin=1,machine_id=b'id')
        self.assertIs(caught.exception,error)
        self.assertEqual(setup.state,'failed')
        self.assertEqual(owner.signer.runtime.raw_core_observations,'prior')
        setup.close();self.assertEqual(closed,['source','delegate'])

    def test_factory_preserves_hook_before_business_prepare(self):
        # Exercise the actual factory branch ordering without constructing OS ports.
        import ast
        from pathlib import Path
        import qq_nt_replica.primary_windows_signer as module
        tree=ast.parse(Path(module.__file__).read_text())
        factory=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='open_windows_signer')
        body=next(n for n in factory.body if isinstance(n,ast.Try)).body
        start=next(i for i,n in enumerate(body) if isinstance(n,ast.If) and ast.unparse(n.test)=='construction_setup is not None')
        tail=body[start:]
        self.events=[]
        owner=self.owner(lambda metadata,**kw:self.events.append(('initialize',metadata,kw)))
        owner._independent_setup=None
        delegate=NS(bind=lambda r:None,bind_caller=lambda c:None,close=lambda:None)
        source=NS(bind=lambda r:None,close=lambda:None)
        config=dict(uin=1,machine_id=b'id')
        namespace=dict(__name__=module.__name__,__package__=module.__package__,owner=owner,construction_setup=lambda o:self.events.append(('hook',o)),outer_login_config=None,
            business=business_metadata(**config),own_business_config=config,independent_provider_metadata=None)
        segment=ast.Module(body=tail[:-1],type_ignores=[])
        with patch('qq_nt_replica.primary_windows_signer_setup.WindowsCoreObservations',return_value=delegate),patch('qq_nt_replica.primary_windows_signer_setup.WindowsHost129Source',return_value=source),patch('qq_nt_replica.primary_windows_signer_setup.Host129RawAPIInputs',return_value=object()):
            exec(compile(ast.fix_missing_locations(segment),module.__file__,'exec'),namespace)
        self.assertEqual([e[0] for e in self.events],['hook','initialize','attach'])
        owner._independent_setup.close()
