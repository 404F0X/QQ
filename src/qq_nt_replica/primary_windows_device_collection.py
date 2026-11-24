"""Explicit OWN_STORES for independent collector inputs, never QQ path redirection."""
import json
from pathlib import Path
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_device_cache_xml import parse_owned_cache_xml
from .primary_device_cache import serialize_owned_cache_xml

class OwnIdentifierStores:
    def __init__(self,root,state_id,*,registry):
        self.root=Path(root)
        if not self.root.is_absolute() or self.root.drive.upper()!='G:' or type(state_id)is not str or not state_id or any(not (c.isascii() and (c.isalnum() or c in '_-')) for c in state_id):raise InputError('explicit owned G store root and finite state id required')
        self.namespace='Software\\404F0X\\QQReplica\\Signature\\'+state_id
        self.registry=registry;self.config_path=self.root/'configuration.json';self.cache_path=self.root/'Seconfig.dat';self.cache=None;self.io_errors=[]
    def _configuration(self):
        try:raw=self.config_path.read_bytes()
        except FileNotFoundError:return {}
        value=json.loads(raw)
        if type(value)is not dict:raise InputError('own configuration file is not a map')
        return {bytes.fromhex(k):bytes.fromhex(v) for k,v in value.items()}
    def read_config(self,key):return self._configuration().get(key)
    def write_config(self,key,value):
        data=self._configuration();data[key]=value;self.root.mkdir(parents=True,exist_ok=True)
        self.config_path.write_text(json.dumps({k.hex():v.hex() for k,v in data.items()},sort_keys=True)+'\n')
    def _cache(self):
        if self.cache is not None:return self.cache
        try:raw=self.cache_path.read_bytes()
        except FileNotFoundError:
            raw=serialize_owned_cache_xml({})
            try:self.root.mkdir(parents=True,exist_ok=True);self.cache_path.write_bytes(raw)
            except OSError as error:self.io_errors.append(('cache-create',getattr(error,'winerror',None) or error.errno));raw=b''
        except OSError as error:self.io_errors.append(('cache-read',getattr(error,'winerror',None) or error.errno));raw=b''
        success,pairs=parse_owned_cache_xml(raw)
        self.cache=dict(pairs) if success else {}
        return self.cache
    def read_cache(self,key):return self._cache().get(key)
    def write_cache(self,key,value):self._cache()[key]=value
    def flush_cache(self):
        try:self.root.mkdir(parents=True,exist_ok=True);self.cache_path.write_bytes(serialize_owned_cache_xml(self._cache()))
        except OSError as error:self.io_errors.append(('cache-flush',getattr(error,'winerror',None) or error.errno));return False
        return True
    def read_registry(self,key):return self.registry.read(self.namespace,key)
    def write_registry(self,key,value):return self.registry.write(self.namespace,key,value)
    def delete_registry(self,key):return self.registry.delete(self.namespace,key)

class WindowsOwnIdentifierRegistry:
    """Only explicit own namespace. No original QQProtect aliases or fallback."""
    def _namespace(self,path):
        if not path.startswith('Software\\404F0X\\QQReplica\\Signature\\'):raise InputError('registry path is outside OWN_STORES')
    def read(self,path,name):
        import winreg
        self._namespace(path)
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,path,0,0x20019) as key:value,kind=winreg.QueryValueEx(key,name.decode('ascii'))
        except OSError:return None
        if kind!=winreg.REG_SZ or type(value)is not str:raise PrimarySemanticUnavailable('own registry value is outside REG_SZ identifier domain')
        raw=value.encode('mbcs')+b'\0'
        if len(raw)>256:return None
        return raw.split(b'\0',1)[0]
    def write(self,path,name,value):
        import winreg
        self._namespace(path)
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,path,0,0x20006) as key:winreg.SetValueEx(key,name.decode('ascii'),0,winreg.REG_SZ,value.decode('ascii'))
        except OSError:return False
        return True
    def delete(self,path,name):
        import winreg
        self._namespace(path)
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,path,0,2) as key:winreg.DeleteValue(key,name.decode('ascii'))
        except OSError:return False
        return True


class WindowsDeviceCollectionObservations:
    """Finite observation composition over own collection data, without a VM."""
    def __init__(self, *, components=None, source_factory=None, helpers=None,
                 display_factory=None):
        import os
        import threading
        self._owner = os.getpid(), threading.get_native_id()
        self.closed = False
        self._data = None
        self._source = None
        self._random_environment = None
        self._ansi_conversion = None
        self._source_factory = source_factory
        self._helpers = {} if helpers is None else dict(helpers)
        self._display_factory = display_factory
        self._displays = []
        self._close_attempted = set()
        self._close_errors = {}
        if components is None:
            from .primary_windows_worker_observations import WindowsWorkerObservations
            from .primary_windows_provider_observations import WindowsProviderObservations
            from .primary_windows_system_records import WindowsSystemRecordObservations
            from .primary_windows_device_hardware import WindowsDeviceHardwareObservations
            from .primary_windows_device_process_records import WindowsDeviceProcessRecordObservations
            worker = WindowsWorkerObservations()
            provider = WindowsProviderObservations(worker, source=self)
            system = WindowsSystemRecordObservations(provider)
            hardware = WindowsDeviceHardwareObservations(system, adapter_environment='independent_windows')
            process = WindowsDeviceProcessRecordObservations(hardware)
            components = (process, hardware, system, provider, worker)
        self._components = tuple(components)
        if not self._components:
            raise InputError('collection composition requires observation ports')

    def _check(self):
        import os
        import threading
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('collection observations require their open creator process/thread')

    def take(self, data, name, args):
        self._check()
        if self._data is not None and self._data is not data:
            raise InputError('collection observations require their original own data')
        self._data = data
        # Existing ports alone decide foreign-site fallthrough. Never catch a
        # native boundary or a malformed owned request as an unsupported site.
        return self._components[0].take(data, name, args)

    def cpuid(self, leaf, subleaf=0):
        self._check()
        if self._source is None:
            factory = self._source_factory
            if factory is None:
                from .primary_windows import WindowsDeviceSource
                factory = WindowsDeviceSource
            self._source = factory()
        return self._source.cpuid(leaf, subleaf)

    def filetime(self):
        self._check()
        if 'filetime' in self._helpers:
            value = self._helpers['filetime']()
        else:
            if self._data is None:
                raise PrimarySemanticUnavailable('FILETIME requires bound own collection data')
            result, raw = self.take(self._data, 'GetSystemTimeAsFileTime', ())
            if result is not None or type(raw) is not bytes or len(raw) != 8:
                raise InputError('FILETIME requires void result and actual eight output bytes')
            value = int.from_bytes(raw, 'little')
        if type(value) is not int or not 0 <= value < 1 << 64:
            raise InputError('FILETIME requires uint64')
        return value

    def random_device_word(self):
        self._check()
        helper = self._helpers.get('random_device_word')
        if helper is None:
            # 35F4E50 -> 7603B0.system_word -> random_s: one DWORD,
            # then the caller seeds MT. Never return an MT output here.
            if self._random_environment is None:
                from .primary_device_value_producer import WindowsDeviceValueEnvironment
                self._random_environment = WindowsDeviceValueEnvironment()
            raw = self._random_environment.random_bytes(4)
            if type(raw) is not bytes or len(raw) != 4:
                raise InputError('source random_device requires exactly four output bytes')
            value = int.from_bytes(raw, 'little')
        else:
            value = helper()
        if type(value) is not int or not 0 <= value < 1 << 32:
            raise InputError('random_device requires its actual uint32 seed')
        return value

    def ansi_to_utf8(self, value):
        self._check()
        if type(value) is not bytes or b'\0' in value:
            raise InputError('ANSI conversion requires owning CString bytes without NUL')
        helper = self._helpers.get('ansi_to_utf8')
        if helper is None:
            if self._ansi_conversion is None:
                from .primary_qimei_request import WindowsAnsiConversion
                self._ansi_conversion = WindowsAnsiConversion()
            helper = self._ansi_conversion
        output = helper(value)
        if type(output) is not bytes:
            raise InputError('ANSI conversion requires owning UTF8 bytes')
        return output

    def display_environment(self):
        self._check()
        factory = self._display_factory
        if factory is None:
            from .primary_windows_display_environment import WindowsDisplayEnvironment
            factory = WindowsDisplayEnvironment
        environment = factory()
        self._displays.append(environment)
        return environment

    def snapshot(self):
        def state(port):
            snapshot = getattr(port, 'snapshot', None)
            if callable(snapshot):
                return snapshot()
            return {'closed': getattr(port, 'closed', getattr(port, '_closed', None)),
                    'resource_balance': 'unknown'}
        return {'closed': self.closed, 'components': tuple(state(p) for p in self._components),
                'source_created': self._source is not None,
                'random_environment_created': self._random_environment is not None,
                'ansi_conversion_created': self._ansi_conversion is not None,
                'close_failures': tuple(self._close_errors.values()),
                'displays': tuple(state(p) for p in self._displays)}

    def close(self):
        if self.closed:
            return
        self._check()
        ports = (*self._displays, *self._components,
                 *((self._source,) if self._source is not None else ()),
                 *((self._random_environment,) if self._random_environment is not None else ()))
        first = None
        for port in ports:
            token = id(port)
            if token in self._close_attempted:
                continue
            self._close_attempted.add(token)
            try:
                port.close()
            except BaseException as error:
                self._close_errors[token] = type(error).__name__
                if first is None:
                    first = error
        if first is not None:
            raise first
        if self._close_errors:
            raise PrimarySemanticUnavailable('collection cleanup has unresolved prior failures')
        self.closed = True
