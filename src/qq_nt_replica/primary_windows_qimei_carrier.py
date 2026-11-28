"""Finite synchronous A3352 WinINet byte carrier; no curl table is owned.

Thread soft-wait statuses and certificate diagnostic bookkeeping are unsupported.
Construction never loads Windows libraries. Calls require an explicit permit.
"""
import ctypes as C
import os
import threading
from .primary_qimei_dispatch import QimeiCarrierPort, CarrierOutcome
from .primary_qimei_request import QimeiRequestBoundary
from .primary_qimei_request_pipeline import QimeiHttpRequest

UA = QimeiHttpRequest.__dataclass_fields__['headers'].default[1][1]
FLAGS = 0x80E03000
P, D, S = C.c_void_p, C.c_uint32, C.c_char_p
PROTOTYPES = {
    'InternetOpenA': (P, (S,D,S,S,D)),
    'InternetConnectA': (P, (P,S,C.c_uint16,S,S,D,D,C.c_size_t)),
    'HttpOpenRequestA': (P, (P,S,S,S,S,C.POINTER(S),D,C.c_size_t)),
    'HttpSendRequestA': (C.c_int32, (P,S,D,P,D)),
    'InternetReadFile': (C.c_int32, (P,P,D,C.POINTER(D))),
    'InternetCloseHandle': (C.c_int32, (P,)),
}

class WinInetFailure(QimeiRequestBoundary):
    def __init__(self, phase, error, body, sent, read_count=None):
        super().__init__('WinINet carrier failed at '+phase)
        self.phase, self.error, self.partial_body = phase, error, body
        self.send_return_success, self.read_count = sent, read_count
        self.send_attempted = False
        self.remote_send_unknown = False
        self.close_results = ()

class NativeWinInetPort:
    """Caller must close after the last perform, including exceptional completion.

    This port owns one loader reference, released explicitly by FreeLibrary;
    dropping Python references is not a release. Unclosed Internet handles block
    module release. A failed close leaves ownership available for diagnosis/retry.
    """
    def __init__(self, *, permit):
        self.permit = permit
        self.owner = (os.getpid(), threading.get_native_id())
        self.library = None
        self.closed = False
        self.active = False
        self.handles = set()
    def _owner_check(self):
        if self.owner != (os.getpid(), threading.get_native_id()):
            raise QimeiRequestBoundary('WinINet owner unavailable')
    def check(self):
        self._owner_check()
        if self.closed or not self.permit():
            raise QimeiRequestBoundary('WinINet scope unavailable')
    def _load(self):
        if os.name != 'nt' or C.sizeof(P) != 8:
            raise QimeiRequestBoundary('Windows x64 WinINet required')
        return C.WinDLL('wininet', use_last_error=True)
    def _release(self, handle):
        # CPython Windows primitive raises OSError on failed FreeLibrary and
        # does not acquire a second kernel32 loader reference.
        from _ctypes import FreeLibrary
        FreeLibrary(handle)
    def close(self):
        self._owner_check()
        if self.closed: return
        if self.active or self.handles:
            raise QimeiRequestBoundary('WinINet outstanding calls/handle ownership')
        if self.library is not None:
            self._release(self.library._handle)
            self.library = None
        self.closed = True
    def call(self, name, *args):
        self.check()
        if self.active: raise QimeiRequestBoundary('WinINet call already active')
        self.active = True
        try:
            if self.library is None: self.library = self._load()
            fn = getattr(self.library, name)
            fn.restype, fn.argtypes = PROTOTYPES[name]
            value = fn(*args)
            if name in ('InternetOpenA', 'InternetConnectA', 'HttpOpenRequestA') and value:
                self.handles.add(value)
            elif name == 'InternetCloseHandle' and value:
                self.handles.discard(args[0])
            return value
        finally:
            self.active = False
    def error(self):
        return C.get_last_error()

class WindowsQimeiCarrier(QimeiCarrierPort):
    """One request per call, no retries/status query; scripted port is injectable.

    Failed reads raise with raw partial state (not the Source partial/status-zero
    branch). Close results are retained; failed release never becomes success.
    Native calls can block; 3000 ms is not a cancellation deadline.
    """
    curl_table = None
    def __init__(self, port):
        self.port = port
        self.close_results = ()
        self.active = False
    def perform(self, request):
        if not isinstance(request, QimeiHttpRequest) or request != QimeiHttpRequest(request.body):
            raise QimeiRequestBoundary('fixed source Qimei HTTP request required')
        if not isinstance(request.body, bytes) or len(request.body) > 0xffffffff:
            raise QimeiRequestBoundary('DWORD byte body required')
        if self.active: raise QimeiRequestBoundary('carrier borrow already active')
        self.port.check()
        self.active = True
        handles, closes, chunks = [], [], []
        sent = False
        attempted = False
        self.send_attempted = False
        self.send_return_success = False
        failure = None
        def call(name, *args): return self.port.call(name, *args)
        def opened(name, *args):
            value = call(name, *args)
            if not value: raise WinInetFailure(name, self.port.error(), b'', sent)
            handles.append(value)
            return value
        try:
            session = opened('InternetOpenA', UA, 1, None, None, 0)
            connection = opened('InternetConnectA', session, b'snowflake.qq.com', 443, None, None, 3, 0, 0)
            handle = opened('HttpOpenRequestA', connection, b'POST', b'/ola/v2', b'HTTP/1.1', None, None, FLAGS, 0)
            body = C.create_string_buffer(request.body)
            attempted = self.send_attempted = True
            if not call('HttpSendRequestA', handle, b'Content-Type: application/json', 0xffffffff, body, len(request.body)):
                raise WinInetFailure('HttpSendRequestA', self.port.error(), b'', False)
            sent = self.send_return_success = True
            while True:
                data, count = C.create_string_buffer(4096), D()
                ok = call('InternetReadFile', handle, data, 4095, C.byref(count))
                error = self.port.error() if not ok else None
                if not ok or count.value > 4095:
                    failure_state = WinInetFailure('InternetReadFile', error, b''.join(chunks), True, count.value)
                    failure_state.raw_read_buffer = data.raw
                    raise failure_state
                if not count.value: break
                chunks.append(data.raw[:count.value])
        except BaseException as exc:
            if not isinstance(exc, WinInetFailure):
                wrapped = WinInetFailure('native_call_exception', None, b''.join(chunks), sent)
                failure = wrapped
                raise wrapped from exc
            failure = exc
            raise
        finally:
            try:
                for handle in reversed(handles):
                    ok = call('InternetCloseHandle', handle)
                    closes.append((handle, bool(ok), None if ok else self.port.error()))
                self.close_results = tuple(closes)
                if isinstance(failure, WinInetFailure):
                    failure.close_results = self.close_results
                    failure.send_attempted = attempted
                    failure.remote_send_unknown = attempted
                if failure is None and any(not item[1] for item in closes):
                    exc = WinInetFailure('InternetCloseHandle', next(item[2] for item in closes if not item[1]), b''.join(chunks), sent)
                    exc.close_results = self.close_results
                    exc.send_attempted = attempted
                    exc.remote_send_unknown = attempted
                    raise exc
            finally:
                self.active = False
        return CarrierOutcome(b''.join(chunks), 0)

