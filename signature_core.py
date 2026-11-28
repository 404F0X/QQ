"""Manifest-pinned, isolated access to the signature source model."""
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
import types
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parent


def require(value):
    if not value:
        raise ValueError('PREFIX_ISOLATED_SOURCE_PIN_OR_OWNERSHIP')


class _Source(importlib.abc.Loader):
    def __init__(self, owner, relative):
        self.owner, self.relative = owner, relative

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        row = self.owner.binding[self.relative]
        raw = self.owner.read(row)
        module.__file__, module.__cached__ = row['path'], None
        self.owner.modules[module.__name__] = module
        exec(compile(raw, row['path'], 'exec'), module.__dict__)


class _Finder(importlib.abc.MetaPathFinder):
    def __init__(self, owner):
        self.owner = owner

    def find_spec(self, fullname, path=None, target=None):
        if fullname != 'qq_nt_replica' and not fullname.startswith('qq_nt_replica.'):
            return None
        relative = fullname.replace('.', '/')
        package = relative + '/__init__.py'
        relative = package if package in self.owner.binding else relative + '.py'
        require(relative in self.owner.binding)
        return importlib.util.spec_from_file_location(
            fullname, self.owner.binding[relative]['path'],
            loader=_Source(self.owner, relative),
            submodule_search_locations=[] if relative == package else None)


class IsolatedCore:
    def __init__(self):
        raw = (ROOT / 'source-manifest.json').read_bytes()
        require(hashlib.sha256(raw).hexdigest() ==
                (ROOT / 'source-manifest.sha256').read_text().strip())
        manifest = json.loads(raw)
        self.binding = {'_sources': {}}
        for item in manifest['files']:
            relative = item['path']
            path = (ROOT / relative).resolve()
            require(path.is_relative_to(ROOT / 'src'))
            row = {'path': str(path), 'sha256': item['sha256']}
            if 'source_key' in item:
                row['dependencies'] = item['dependencies']
                self.binding['_sources'][item['source_key']] = row
            else:
                require(relative.startswith('src/'))
                self.binding[relative[4:]] = row
            self.read(row)
        for row in self.binding['_sources'].values():
            row['dependencies'] = {key: self.binding['_sources'][key]
                                   for key in row['dependencies']}
        self.modules, self.sources = {}, {}
        self.finder = _Finder(self)
        self.active = self.closed = False

    @staticmethod
    def read(row):
        raw = Path(row['path']).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == row['sha256'])
        return raw

    @contextmanager
    def activate(self):
        require(not self.active and not self.closed and not any(
            n == 'qq_nt_replica' or n.startswith('qq_nt_replica.') for n in sys.modules))
        self.active = True
        sys.meta_path.insert(0, self.finder)
        try:
            yield self
        finally:
            sys.meta_path.remove(self.finder)
            self.active = False

    def source(self, key):
        require(self.active and not self.closed and key in self.binding['_sources'])
        if key not in self.sources:
            row = self.binding['_sources'][key]
            for name, item in row['dependencies'].items():
                if name not in self.sources:
                    self._load_source(name, item)
            self._load_source(key, row)
        return self.sources[key]

    def _load_source(self, key, row):
        require(key not in sys.modules)
        raw = self.read(row)
        module = types.ModuleType(key)
        module.__file__ = row['path']
        sys.modules[key] = module
        self.sources[key] = module
        exec(compile(raw, row['path'], 'exec'), module.__dict__)

    def close(self):
        require(not self.active)
        for collection in (self.modules, self.sources):
            for name, module in collection.items():
                require(sys.modules.get(name) is module)
                sys.modules.pop(name)
            collection.clear()
        self.closed = True


def load_core():
    return IsolatedCore()
