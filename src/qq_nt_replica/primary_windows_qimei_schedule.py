"""Own epoch timer/mutex hosting. No DLL is loaded until an explicit call.

Physical mutexes deliberately do not interoperate with QQ objects. Source
predicate/results and timer periods are retained; teardown is Own host policy.
"""
import ctypes as C
import hashlib
import os
import threading

from .primary_qimei_request import QimeiRequestBoundary


class NativeQimeiScheduleAPI:
    def __init__(self, check):
        self.check = check
        self.libraries = {}

    def call(self, name, result, types, *args):
        self.check()
        if os.name != 'nt':
            raise QimeiRequestBoundary('Windows Qimei scheduler required')
        group = 'ucrtbase' if name == '_mktime64' else 'kernel32'
        if group not in self.libraries:
            self.libraries[group] = C.WinDLL(group, use_last_error=True)
        fn = getattr(self.libraries[group], name)
        fn.restype, fn.argtypes = result, types
        value = fn(*args)
        return value, C.get_last_error()

    def thunk(self, callback):
        return C.WINFUNCTYPE(None, C.c_void_p, C.c_ubyte)(callback)

    def close(self):
        self.check()
        from _ctypes import FreeLibrary
        for name, library in tuple(self.libraries.items()):
            FreeLibrary(library._handle)
            del self.libraries[name]

    def image_size(self):
        base, error = self.call('GetModuleHandleA', C.c_void_p, (C.c_char_p,), None)
        if not base:
            return 0
        # The base belongs to this live process, not an external address.
        if C.string_at(base, 2) != b'MZ':
            return 0
        offset = int.from_bytes(C.string_at(base + 0x3c, 4), 'little')
        if C.string_at(base + offset, 4) != b'PE\0\0':
            return 0
        return int.from_bytes(C.string_at(base + offset + 0x50, 4), 'little')

    def timestamp_ms(self):
        local = (C.c_uint16 * 8)()
        self.call('GetLocalTime', None, (C.c_void_p,), C.byref(local))
        year, month, week, day, hour, minute, second, millis = local
        tm = (C.c_int32 * 9)(second, minute, hour, day, month - 1, year - 1900, 0, 0, 0)
        seconds, error = self.call('_mktime64', C.c_int64, (C.c_void_p,), C.byref(tm))
        return (seconds * 1000 + millis) & 0xffffffffffffffff


class OwnQimeiSchedule:
    def __init__(self, runtime, epoch, current_epoch, *, namespace, api=None):
        if (type(namespace) is not bytes or len(namespace) != 32 or
                any(c not in b'0123456789abcdefABCDEF' for c in namespace)):
            raise QimeiRequestBoundary('random128 hex Own epoch namespace required')
        self.runtime, self.epoch, self.current_epoch = runtime, epoch, current_epoch
        self.creator = threading.get_native_id()
        self.namespace = namespace
        self.api = NativeQimeiScheduleAPI(self._native_check) if api is None else api
        self.lock = threading.RLock()
        self.queue = None
        self.timers = []
        self.mutexes = []
        self.diagnostics = []
        self.errors = []
        self.sealed = False
        self.quiescent = False
        self._coord = None
        self._instance = None
        self._callback_threads = threading.local()

    def _native_check(self):
        if self.current_epoch(self.runtime) is not self.epoch:
            raise QimeiRequestBoundary('scheduler stale epoch')

    def check(self):
        if self.current_epoch(self.runtime) is not self.epoch or self.quiescent:
            raise QimeiRequestBoundary('scheduler epoch unavailable')

    def _call(self, name, result, types, *args):
        self.check()
        value, error = self.api.call(name, result, types, *args)
        self.diagnostics.append((name, bool(value), error))
        return value, error

    def _name(self, domain, digest):
        return b'Local\\QQReplicaOwn' + domain + b'_' + self.namespace + b'_' + digest

    def _probe(self, name):
        handle, error = self._call('OpenMutexA', C.c_void_p,
                                  (C.c_uint32, C.c_int32, C.c_char_p), 0x1f0001, 0, name)
        if handle:
            ok, close_error = self._call('CloseHandle', C.c_int32, (C.c_void_p,), handle)
            if not ok:
                self.mutexes.append(handle)
                raise OSError(close_error, 'temporary mutex close failed')
            return False
        handle, create_error = self._call('CreateMutexA', C.c_void_p,
                                         (C.c_void_p, C.c_int32, C.c_char_p), None, 0, name)
        if handle:
            self.mutexes.append(handle)
        # Source boolean describes Open NULL even when Create failed.
        return True

    def coordination(self, appid):
        with self.lock:
            if self._coord is None:
                self._coord = self._probe(self._name(b'Coord', hashlib.md5(appid).hexdigest().upper().encode()))
            return self._coord

    def timestamp_ms(self):
        self.check()
        return self.api.timestamp_ms()

    def dynamic50000(self, appid):
        with self.lock:
            if self._coord:
                return True
            self._coord = self._probe(self._name(b'Coord', hashlib.md5(appid).hexdigest().upper().encode()))
            return not self._coord

    def instance_count(self, appid):
        with self.lock:
            if self._instance is not None:
                return self._instance
            size = self.api.image_size()
            count = 0
            for index in range(1, 101):
                logical = hashlib.md5(b'x5sg8bj0' + appid + str((size + index) & 0xffffffff).encode()).hexdigest().upper().encode()
                # Keep the exact Source digest as the logical key; isolate physical IO.
                name = self._name(b'Instance', logical)
                handle, error = self._call('OpenMutexA', C.c_void_p,
                                          (C.c_uint32, C.c_int32, C.c_char_p), 0x1f0001, 0, name)
                count = index
                if handle:
                    ok, error = self._call('CloseHandle', C.c_int32, (C.c_void_p,), handle)
                    if not ok:
                        self.mutexes.append(handle)
                        raise OSError(error, 'instance mutex close failed')
                    continue
                handle, error = self._call('CreateMutexA', C.c_void_p,
                                          (C.c_void_p, C.c_int32, C.c_char_p), None, 0, name)
                if handle:
                    self.mutexes.append(handle)
                break
            self._instance = count
            return count

    def register(self, app, period, callback):
        with self.lock:
            if self.sealed:
                raise QimeiRequestBoundary('timer admission sealed')
            if self.queue is None:
                self.queue, error = self._call('CreateTimerQueue', C.c_void_p, ())
                if not self.queue:
                    raise OSError(error, 'CreateTimerQueue failed')
            record = {'app': app, 'handle': None, 'thunk': None, 'pending': False}
            def invoke(context, fired):
                self._callback_threads.active = True
                self._callback_threads.record = record
                try:
                    with self.lock:
                        self.check()
                        if self.sealed:
                            return
                    callback(record)
                except BaseException as error:
                    self.errors.append(error)  # Never throw through the C ABI.
                finally:
                    self._callback_threads.active = False
                    self._callback_threads.record = None
            record['thunk'] = self.api.thunk(invoke)
            self.timers.append(record)  # Pin before API can invoke callback.
            handle = C.c_void_p()
            ok, error = self._call('CreateTimerQueueTimer', C.c_int32,
                (C.POINTER(C.c_void_p), C.c_void_p, C.c_void_p, C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32),
                C.byref(handle), self.queue, record['thunk'], None, period, period, 0)
            record['handle'] = handle.value
            if not ok:
                self.diagnostics.append(('timer_registration_failed', error))
            return record

    def callback_admitted(self, record, app):
        return (getattr(self._callback_threads, 'active', False) and
                getattr(self._callback_threads, 'record', None) is record and
                record in self.timers and record['app'] is app)

    def unregister(self, record):
        with self.lock:
            if record not in self.timers or not record['handle']:
                raise QimeiRequestBoundary('unowned/unregistered timer')
            ok, error = self._call('DeleteTimerQueueTimer', C.c_int32,
                (C.c_void_p, C.c_void_p, C.c_void_p), self.queue, record['handle'], None)
            if not ok and error != 997:
                raise OSError(error, 'timer deletion debt retained')
            record['pending'] = not bool(ok)

    def close_queue(self):
        if threading.get_native_id() != self.creator or getattr(self._callback_threads, 'active', False):
            raise QimeiRequestBoundary('queue wait requires creator outside callback')
        with self.lock:
            self.sealed = True
        if self.quiescent:
            return
        # Never wait while holding a module, timer or worker lock.
        if self.queue:
            ok, error = self._call('DeleteTimerQueueEx', C.c_int32,
                (C.c_void_p, C.c_void_p), self.queue, C.c_void_p(-1))
            if not ok:
                raise OSError(error, 'queue close debt; backing retained')
        self.queue = None
        self.quiescent = True

    def close_mutexes(self):
        if not self.quiescent or threading.get_native_id() != self.creator:
            raise QimeiRequestBoundary('mutex release requires creator queue quiescence')
        errors = []
        for handle in tuple(self.mutexes):
            value, error = self.api.call('CloseHandle', C.c_int32, (C.c_void_p,), handle)
            if value:
                self.mutexes.remove(handle)
            else:
                errors.append(OSError(error, 'mutex close debt retained'))
        if errors:
            raise ExceptionGroup('mutex cleanup debt', errors)
        self.api.close()
        self.timers.clear()
