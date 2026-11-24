"""Owning WMI first-row port; importing this module performs no native calls."""
from dataclasses import dataclass
import os
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_device_wmi import _image
from .primary_windows_wmi import _NativeWMI, _NAMESPACE


@dataclass(frozen=True)
class WmiPropertyResult:
    property_id: bytes
    key_ansi: bytes
    get_hresult: int
    variant_type: int | None
    state: str
    value_ansi: bytes


@dataclass(frozen=True)
class WmiQueryResult:
    state: str
    exec_hresult: int | None
    next_hresult: int | None
    returned_count: int | None
    properties: tuple[WmiPropertyResult, ...]


class OwnedWmiSession:
    @classmethod
    def open(cls, *, backend=None):
        self = cls()
        self.pid, self.tid = os.getpid(), threading.get_native_id()
        self.closed = False
        self.backend = backend if backend is not None else _NativeWMI()
        self.references, self.strings, self.variants = [], [], []
        self.com_balance, self.services, self.events = 0, 0, []
        self.hresults = {}
        try:
            hr = self.backend.initialize() & 0xffffffff
            self.hresults['initialize'] = hr
            self.com_balance = int(hr in (0, 1))
            hr, locator = self.backend.create()
            self.hresults['create'] = hr & 0xffffffff
            self._own(locator)
            if hr & 0x80000000:
                self._uninitialize()
                return self
            if not locator:
                raise PrimarySemanticUnavailable('successful null WMI locator')
            namespace = self._allocate(_NAMESPACE)
            hr, services = self.backend.connect(locator, namespace)
            self.hresults['connect'] = hr & 0xffffffff
            self._own(services)
            self._free(namespace)
            self._release(locator)
            if hr & 0x80000000:
                self._uninitialize()
                return self
            if not services:
                raise PrimarySemanticUnavailable('successful null WMI services')
            hr = self.backend.blanket(services) & 0xffffffff
            self.hresults['blanket'] = hr
            if hr & 0x80000000:
                self._release(services)
                self._uninitialize()
            else:
                self.services = services
            return self
        except BaseException:
            self.close()
            raise

    def _check(self):
        if self.closed or (self.pid, self.tid) != (os.getpid(), threading.get_native_id()):
            raise InputError('WMI session requires its open creator process/native thread')

    def _own(self, pointer):
        if pointer:
            self.references.append(pointer)
        return pointer

    def _allocate(self, raw):
        pointer = self.backend.allocate(raw)
        if not pointer:
            raise PrimarySemanticUnavailable('WMI BSTR allocation failed')
        self.strings.append(pointer)
        return pointer

    def _free(self, pointer):
        self.backend.free(pointer)
        self.strings.remove(pointer)

    def _release(self, pointer):
        result = self.backend.release(pointer)
        self.events.append(('Release', result))
        self.references.remove(pointer)

    def _uninitialize(self):
        self.events.append(('source.CoUninitialize_balance', self.com_balance))
        if self.com_balance:
            self.backend.uninitialize()
            self.com_balance -= 1

    def _convert(self, name, raw, count, tail=()):
        args = (0, 0, raw, count, False, 0) + tail
        size, effects = getattr(self.backend, 'convert_owned', self.backend.convert)(name, args)
        if effects:
            raise InputError('conversion size query returned destination effects')
        size &= 0xffffffff
        if name == 'WideCharToMultiByte' and not 0 < size < 1 << 31:
            return b''
        if not 0 < size < 4096:
            raise PrimarySemanticUnavailable('WMI conversion outside supported allocation domain')
        result, effects = getattr(self.backend, 'convert_owned', self.backend.convert)(name, (0, 0, raw, count, True, size) + tail)
        capacity = size * (2 if name == 'MultiByteToWideChar' else 1)
        if not isinstance(effects, bytes) or len(effects) > capacity:
            raise InputError('invalid WMI conversion effects')
        if name == 'MultiByteToWideChar':
            if not result:
                raise PrimarySemanticUnavailable('ANSI BSTR conversion failed')
            if len(effects) != capacity:
                raise PrimarySemanticUnavailable('uninitialized UTF16 conversion backing')
            return effects
        buffer = bytearray(capacity)
        buffer[:len(effects)] = effects
        buffer[-1] = 0
        return bytes(buffer).split(b'\0', 1)[0]

    def _ansi(self, wide):
        return self._convert('WideCharToMultiByte', wide, -1, (0, 0))

    def _property(self, pointer, property_id):
        hr, raw = self.backend.get(pointer, property_id + b'\0\0')
        hr &= 0xffffffff
        key = self._ansi(property_id + b'\0\0')
        if hr & 0x80000000:
            return WmiPropertyResult(property_id, key, hr, None, 'get_failed', b'')
        if not isinstance(raw, bytes) or len(raw) != 24:
            raise PrimarySemanticUnavailable('unknown VARIANT backing')
        kind = int.from_bytes(raw[:2], 'little')
        value, state = b'', 'unsupported_type'
        if kind in (3, 22, 23):
            number = int.from_bytes(raw[8:12], 'little', signed=True)
            value, state = str(number).encode('ascii'), 'value'
        elif kind == 8:
            pending = {'raw': raw, 'state': 'unvalidated'}
            self.variants.append(pending)
            address = int.from_bytes(raw[8:16], 'little')
            valid = False
            if address >= 0x10000:
                count, info = self.backend.virtual_query(address)
                if count and len(info) < 37:
                    raise PrimarySemanticUnavailable('unknown VirtualQuery protection backing')
                valid = bool(count) and not info[36] & 1
            state = 'invalid_bstr'
            if valid:
                pending['state'] = 'valid_unattempted'
                wide = self.backend.cstring_wide(address)
                value = self._ansi(wide)
                state = 'value' if value else 'empty'
                self._clear_variant(pending)
        return WmiPropertyResult(property_id, key, hr, kind, state, value)

    def _clear_variant(self, pending):
        # Once attempted, backing may have changed even on failure/exception.
        pending['state'] = 'clear_failed_unknown'
        cleared, ignored = self.backend.clear(pending['raw'])
        if not cleared & 0x80000000:
            self.variants.remove(pending)
        else:
            self.events.append(('VariantClear_failed', cleared))

    def query_first(self, spec_id):
        self._check()
        definition = _image()['collectors'][str(spec_id)]
        if not self.services:
            return WmiQueryResult('no_services', None, None, None, ())
        statement = self._allocate(bytes.fromhex(definition['query_hex']))
        language = self._allocate(self._convert('MultiByteToWideChar', b'WQL\0', 4))
        hr, enumerator = self.backend.query(self.services, language, statement)
        hr &= 0xffffffff
        self._own(enumerator)
        self._free(language)
        self._free(statement)
        if hr & 0x80000000:
            return WmiQueryResult('exec_failed', hr, None, None, ())
        if not enumerator:
            raise PrimarySemanticUnavailable('successful null WMI enumerator')
        next_hr, pointer, count = self.backend.next(enumerator)
        next_hr, count = next_hr & 0xffffffff, count & 0xffffffff
        self._own(pointer)
        properties = ()
        if count:
            if not pointer:
                raise PrimarySemanticUnavailable('nonzero WMI count with null object')
            properties = tuple(self._property(pointer, bytes.fromhex(p)) for p in definition['properties_hex'])
            self._release(pointer)
        self._release(enumerator)
        return WmiQueryResult('row' if count else 'no_object', hr, next_hr, count, properties)

    def snapshot(self):
        return dict(pid=self.pid, native_thread_id=self.tid, closed=self.closed,
                    interfaces=len(self.references), bstrs=len(self.strings),
                    variants=len(self.variants),
                    variant_states=tuple(p['state'] for p in self.variants),
                    com_balances=self.com_balance,
                    hresults=dict(self.hresults), events=tuple(self.events))

    def close(self):
        if self.closed:
            return
        self._check()
        for pending in tuple(self.variants):
            if pending['state'] == 'valid_unattempted':
                self._clear_variant(pending)
        for pointer in reversed(tuple(self.strings)):
            self._free(pointer)
        for pointer in reversed(tuple(self.references)):
            self._release(pointer)
        self.services = 0
        self._uninitialize()
        self.backend.close()
        self.closed = True
