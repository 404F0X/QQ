"""Focused creator restoration / destructor scope ordering, without native resources."""
import ast
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from qq_nt_replica import primary_sign_lifecycle
from qq_nt_replica.primary_windows_signer import WindowsSigner


class CloseScope(unittest.TestCase):
    def test_creator_restore_precedes_close_scope_and_exception_restores_domain(self):
        source = ast.parse(Path(__import__('inspect').getfile(WindowsSigner)).read_text())
        release = next(n for n in ast.walk(source) if isinstance(n, ast.FunctionDef) and n.name == 'release_guest')
        for threaded in (False, True):
            for failing in (False, True):
                with self.subTest(threaded=threaded, failing=failing):
                    runtime = SimpleNamespace(domain='original', scope=None)
                    seen = []
                    @contextmanager
                    def creator():
                        old = runtime.domain, runtime.scope
                        runtime.domain, runtime.scope = 'creator', None
                        try:
                            yield
                        finally:
                            runtime.domain, runtime.scope = old
                    @contextmanager
                    def close_call(*args):
                        old = runtime.scope
                        runtime.scope = 'installed'
                        try:
                            yield
                        finally:
                            runtime.scope = old
                    failure = ValueError('controlled destructor failure')
                    def close():
                        seen.append((runtime.domain, runtime.scope))
                        if failing:
                            raise failure
                    owner = SimpleNamespace(_signer=object(), _threads=SimpleNamespace(closing_context=creator) if threaded else None,
                        _registrar=SimpleNamespace(snapshot=lambda: {'bound': True}, close=close))
                    namespace = {'self': owner, '__package__': 'qq_nt_replica'}
                    exec(compile(ast.Module(body=[release], type_ignores=[]), '<release_guest>', 'exec'), namespace)
                    with patch.object(primary_sign_lifecycle, 'close_call', close_call):
                        if failing:
                            with self.assertRaises(ValueError) as raised:
                                namespace['release_guest']()
                            self.assertIs(raised.exception, failure)
                        else:
                            namespace['release_guest']()
                    self.assertEqual(seen, [('creator' if threaded else 'original', 'installed')])
                    self.assertEqual((runtime.domain, runtime.scope), ('original', None))
