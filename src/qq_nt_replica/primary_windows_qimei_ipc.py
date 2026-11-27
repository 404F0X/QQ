"""Dedicated Win32 IPC ports. Construction is lazy: no DLL load until first IO."""
import ctypes as C
import os
import threading
from dataclasses import dataclass, replace
from .primary_qimei_ipc import IPCError, QimeiIPCPool


class _Lease:
    """Issued identity only; caller-added attributes have no authority."""
    pass


@dataclass(frozen=True)
class _Resource:
    owner: bytes
    kind: str
    raw: int
    runtime: object
    epoch: object
    closed: bool = False


class WindowsQimeiIPCBackend:
    def __init__(self, *, physical_namespace):
        if (type(physical_namespace) is not bytes or not 1 <= len(physical_namespace) <= 64
                or any(c not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in physical_namespace)):
            raise IPCError("explicit bounded ASCII Own IPC namespace required")
        self.__physical_namespace = physical_namespace
        self._pool = None
        self._leases = set()
        self.__resources = {}
        self._kernel = None
        self.records = []
        self._disposing = False

    @property
    def physical_namespace(self):
        return self.__physical_namespace

    def _physical_name(self, logical):
        if type(logical) is not bytes or len(logical) != 32 or any(c not in b'0123456789ABCDEF' for c in logical):
            raise IPCError('Source logical IPC hash required')
        return b'Local\\QQReplicaOwnIPC_' + self.__physical_namespace + b'_' + logical

    def bind(self, pool):
        if self._pool is not None:
            raise IPCError('IPC backend already bound')
        self._pool = pool

    def _check(self):
        if self._pool is None:
            raise IPCError('unbound IPC backend')
        # Terminal management is permitted only on the original epoch/thread.
        if self._pool.terminal and not self._disposing:
            raise IPCError('terminal IPC backend cannot resume source IO')
        self._pool._check(_host_cleanup=self._disposing)
        if self._pool.identity != (os.getpid(), threading.get_native_id()) and self._pool.active != 1:
            raise IPCError('worker backend requires active publish operation')

    def _creator_only(self):
        self._pool._check(_host_cleanup=True)
        if self._pool.identity != (os.getpid(), threading.get_native_id()):
            raise IPCError('IPC resource construction/disposal requires creator')

    def _call(self, name, result, types, args):
        self._check()
        if self._pool.identity != (os.getpid(), threading.get_native_id()) and name not in (
                'SetEvent','CloseHandle','WaitForSingleObject','ResetEvent'):
            raise IPCError('worker Native IPC call leaves publish domain')
        if self._kernel is None:
            if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
                raise IPCError('IPC backend requires Windows x64')
            self._kernel = C.WinDLL('kernel32', use_last_error=True)
        fn = getattr(self._kernel, name)
        fn.restype, fn.argtypes = result, types
        value = fn(*args)
        self.records.append((name, bool(value) if result is C.c_void_p else value))
        return value

    def _new(self, owner, kind, raw):
        if not raw:
            return None
        self._check()
        lease = _Lease()
        self.__resources[lease] = _Resource(
            owner, kind, raw, self._pool.runtime, self._pool.epoch)
        self._leases.add(lease)
        return lease

    def _raw(self, owner, lease, kind):
        self._check()
        if self._pool.identity != (os.getpid(), threading.get_native_id()) and not (
                self._pool._executor._permits(owner) or self._pool._executor._permits_operation(owner, 'counter')):
            raise IPCError('worker resource owner differs from current task')
        record = self.__resources.get(lease) if type(lease) is _Lease else None
        if (record is None or record.closed or record.owner != owner or record.kind != kind or
                record.runtime is not self._pool.runtime or record.epoch is not self._pool.epoch):
            raise IPCError('foreign, closed or wrong-owner IPC resource')
        return record.raw

    def open_mapping(self, owner, name):
        self._creator_only()
        return self._new(owner, 'mapping', self._call('OpenFileMappingA', C.c_void_p,
            (C.c_uint32,C.c_int32,C.c_char_p), (6,0,self._physical_name(name))))

    def create_mapping(self, owner, name):
        self._creator_only()
        return self._new(owner, 'mapping', self._call('CreateFileMappingA', C.c_void_p,
            (C.c_void_p,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_char_p),
            (C.c_void_p(-1),None,4,0,0x400,self._physical_name(name))))

    def map_view(self, owner, mapping):
        self._creator_only()
        raw = self._raw(owner,mapping,'mapping')
        return self._new(owner,'view',self._call('MapViewOfFile',C.c_void_p,
            (C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_size_t),(raw,6,0,0,0x400)))

    def read_view(self, owner, view):
        self._check()
        if self._pool.identity != (os.getpid(), threading.get_native_id()) and not (
                self._pool._executor._permits_operation(owner, 'consume') or
                self._pool._executor._permits_operation(owner, 'counter')):
            raise IPCError('read requires qualified business task')
        return C.string_at(self._raw(owner,view,'view'),41)

    def write_view(self, owner, view, raw):
        if type(raw) is not bytes or len(raw)!=41:
            raise IPCError('mapping write requires exact41')
        C.memmove(self._raw(owner,view,'view'),raw,41)

    def allocate_event_wrapper(self, owner):
        self._creator_only()
        self._check()
        return object()

    def allocate_cache(self, owner):
        self._creator_only()
        self._check()
        return bytearray(42)  # Own Python backing; not a Native HeapAlloc implementation.

    def open_event(self, owner, name):
        self._creator_only()
        return self._new(owner,'event',self._call('OpenEventA',C.c_void_p,
            (C.c_uint32,C.c_int32,C.c_char_p),(0x1F0003,0,self._physical_name(name))))

    def create_event(self, owner, name):
        self._creator_only()
        return self._new(owner,'event',self._call('CreateEventA',C.c_void_p,
            (C.c_void_p,C.c_int32,C.c_int32,C.c_char_p),(None,0,0,self._physical_name(name))))

    def wait_event(self, owner, event):
        return self._call('WaitForSingleObject',C.c_uint32,(C.c_void_p,C.c_uint32),
                          (self._raw(owner,event,'event'),30000))

    def _event(self, api, owner, event):
        return self._call(api,C.c_int32,(C.c_void_p,),(self._raw(owner,event,'event'),))

    def set_event(self, owner, event): return self._event('SetEvent',owner,event)
    def reset_event(self, owner, event): return self._event('ResetEvent',owner,event)

    def _close(self, owner, lease, kind, api):
        self._disposing = True
        try:
            result=self._call(api,C.c_int32,(C.c_void_p,),(self._raw(owner,lease,kind),))
            if result:
                self.__resources[lease] = replace(self.__resources[lease], closed=True)
                self._leases.remove(lease)
            return result
        finally:
            self._disposing = False

    def close_event(self, owner, event): return self._close(owner,event,'event','CloseHandle')
    def close_mapping(self, owner, mapping):
        self._creator_only()
        return self._close(owner,mapping,'mapping','CloseHandle')
    def unmap_view(self, owner, view):
        self._creator_only()
        return self._close(owner,view,'view','UnmapViewOfFile')


def create_windows_qimei_ipc(runtime, epoch, current_epoch, *, physical_namespace):
    return QimeiIPCPool(runtime,epoch,current_epoch,WindowsQimeiIPCBackend(physical_namespace=physical_namespace))
