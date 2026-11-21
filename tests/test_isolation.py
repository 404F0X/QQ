import importlib
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import signature_core as entry


class IsolationChecks(unittest.TestCase):
    def test_fresh_sources_and_owned_close(self):
        previous = None
        for _ in range(2):
            core = entry.load_core()
            with core.activate():
                package = importlib.import_module('qq_nt_replica')
                self.assertIsNot(package, previous)
                previous = package
                for key in core.binding['_sources']:
                    core.source(key)
                for module in (*core.modules.values(), *core.sources.values()):
                    self.assertTrue(Path(module.__file__).resolve().is_relative_to(entry.ROOT / 'src'))
                names = set(core.modules) | set(core.sources)
            core.close()
            self.assertTrue(names.isdisjoint(sys.modules))

    def test_foreign_namespace_rejected(self):
        core = entry.load_core()
        with patch.dict(sys.modules, {'qq_nt_replica': types.ModuleType('qq_nt_replica')}):
            with self.assertRaises(ValueError):
                with core.activate():
                    self.fail('foreign namespace accepted')
        core.close()

    def test_close_preserves_foreign_replacement(self):
        core = entry.load_core()
        with core.activate():
            importlib.import_module('qq_nt_replica')
        owned = core.modules['qq_nt_replica']
        foreign = types.ModuleType('qq_nt_replica')
        sys.modules['qq_nt_replica'] = foreign
        try:
            with self.assertRaises(ValueError):
                core.close()
            self.assertIs(sys.modules['qq_nt_replica'], foreign)
        finally:
            sys.modules['qq_nt_replica'] = owned
            core.close()

    def test_manifest_and_source_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in ('source-manifest.json', 'source-manifest.sha256'):
                shutil.copyfile(entry.ROOT / name, root / name)
            shutil.copytree(entry.ROOT / 'src', root / 'src')
            with patch.object(entry, 'ROOT', root):
                core = entry.load_core()
                core.close()
                source = root / 'src/qq_nt_replica/errors.py'
                original = source.read_bytes()
                source.write_bytes(original + b'\n# tampered\n')
                with self.assertRaises(ValueError):
                    entry.load_core()
                source.write_bytes(original)
                with (root / 'source-manifest.json').open('ab') as stream:
                    stream.write(b' ')
                with self.assertRaises(ValueError):
                    entry.load_core()


if __name__ == '__main__':
    unittest.main()
