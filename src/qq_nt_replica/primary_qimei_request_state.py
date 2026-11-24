"""Module-shared 3FE14 mask; explicit initial state, not a live epoch binding."""
import threading
from .primary_qimei_request import QimeiRequestBoundary,_integer
class QimeiModuleRequestState:
    def __init__(self,initial_mask,*,mutex=None):
        self._mask=_integer(initial_mask)&0xFFFFFFFF
        self._mutex=threading.Lock() if mutex is None else mutex
    def publish(self,kind):
        bit=1<<(_integer(kind)&31)
        if not self._mutex.acquire():raise QimeiRequestBoundary('source module mutex acquire failed')
        try:self._mask=(self._mask|bit)&0xFFFFFFFF
        finally:self._mutex.release()
    def read_mask(self):
        if not self._mutex.acquire():raise QimeiRequestBoundary('source module mutex acquire failed')
        try:return self._mask
        finally:self._mutex.release()
