"""Explicit F90 component observations do not qualify the genuine Client probe."""
import unittest
from types import SimpleNamespace
from qq_nt_replica.primary_memory import PrimaryMemory,UnknownMemory
from qq_nt_replica.primary_vm import PrimarySemanticUnavailable
from qq_nt_replica.errors import InputError
from qq_nt_replica.primary_sdk import _sender_core,invoke
from qq_nt_replica.primary_client_configuration_scope import _SenderBorrow,finish_sender


from contextlib import contextmanager
@contextmanager
def observe_source_borrow(test,observations):
    # Qualification probes only; no observation or raw callback is supplied.
    import threading
    from copy import copy
    from qq_nt_replica import primary_client_configuration_scope as scope
    previous=threading.getprofile()
    def profile(frame,event,arg):
        if event!='call' or frame.f_code is not scope._SenderBorrow.probe.__code__ or observations:return
        borrow=frame.f_locals['self'];runtime=frame.f_locals['runtime']
        test.assertIs(borrow.check(runtime),borrow)
        record=scope._SENDER_BORROWS[borrow]
        test.assertEqual(record['phase'],'entered')
        before=list(runtime.memory.writes)
        with test.assertRaises(InputError):copy(borrow).check(runtime)
        with test.assertRaises(InputError):borrow.check(object())
        with test.assertRaises(InputError):scope.enter_sender(runtime,tuple(list(record['args'])))
        normal=record['normal'];old=normal.sender_borrow
        try:
            normal.sender_borrow=copy(borrow)
            test.assertIs(borrow.check(runtime),borrow)
        finally:normal.sender_borrow=old
        test.assertEqual(runtime.memory.writes,before)
        # Entered structure stays valid when probe reentry changes contents.
        memory=runtime.memory;receiver=record['args'][0];gate=normal.gate
        fn=memory.load(receiver+8,8);current=memory.load(gate+8,8)
        try:
            memory.store(receiver+8,0x123456,8,source='controlled entered fn mutation')
            memory.store(gate+8,0,8,source='controlled entered gate mutation')
            test.assertIs(borrow.check(runtime),borrow)
        finally:
            memory.store(receiver+8,fn,8,source='restore controlled fn mutation')
            memory.store(gate+8,current,8,source='restore controlled gate mutation')
        observations.extend(['entered','copied denied','foreign runtime denied','tuple cannot enter','journal nonauthority','fn/gate contents not revalidated'])
    threading.setprofile(profile)
    try:yield
    finally:threading.setprofile(previous)


class Component:
    def __init__(self,probe=0,callback=None):self.verdict=probe;self.callback=callback;self.events=[];self.on_probe=None
    def check(self,runtime):pass
    def probe(self,runtime,fn):
        self.events.append(('probe',fn))
        if self.on_probe is not None:self.on_probe(runtime,fn)
        if isinstance(self.verdict,BaseException):raise self.verdict
        return self.verdict
    def raw(self,runtime,fn,args):
        self.events.append(('raw',fn,args))
        if fn==0:raise PrimarySemanticUnavailable('component fn1 unresolved')
        if self.callback is not None:return self.callback(runtime,fn,args)


class Sender(unittest.TestCase):
    def context(self,fn=0x111,heap=False):
        m=PrimaryMemory();m.map(0x1000,bytearray(16),name='component receiver',initialized=True)
        # Only tag and optional heap-pointer are known: length and CString data
        # are intentionally absent from the support domain.
        m.map(0x2000,bytearray(24),name='component command',initialized=False)
        m.store(0x1008,fn,8,source='fn');m.store(0x2000,int(heap),1,source='tag')
        if heap:m.store(0x2010,0x5000,8,source='heap ptr')
        freed=[];tail=object()
        def dispatch(vm,rva,cells):
            if rva!=0xB75029:raise AssertionError('unexpected component helper')
            freed.append(tuple(vm.cells.value(i) for i in cells));return tail
        return SimpleNamespace(memory=m,invoke=dispatch),freed,tail

    def test_NULL_fn_consumes_without_probe_or_body_count_sequence_access(self):
        for heap in (False,True):
            r,freed,tail=self.context(fn=0,heap=heap);a=Component();before=list(r.memory.writes)
            result=_sender_core(r,0x1000,0x2000,object(),object(),object(),a)
            self.assertEqual(a.events,[]);self.assertEqual(freed,[(0x5000,)] if heap else [])
            self.assertIs(result,tail) if heap else self.assertEqual(result,0x2000)
            self.assertEqual(r.memory.writes,before)

    def test_bodyNULL_still_probes_and_guard_skip_no_completion(self):
        for verdict in (0,1,0xFFFFFFFF):
            r,freed,tail=self.context(heap=True);a=Component(verdict)
            self.assertIs(_sender_core(r,0x1000,0x2000,0,0,0xFEDCBA9876543210,a),tail)
            self.assertEqual(a.events,[('probe',0x111)]);self.assertEqual(freed,[(0x5000,)])
            self.assertEqual((r.memory.load(0x2000,1),r.memory.load(0x2010,8)),(1,0x5000))

    def test_probe_zero_count0_fn1_reread_raw4_without_len_or_cstring_scan(self):
        r,freed,tail=self.context();a=Component()
        a.on_probe=lambda runtime,fn:runtime.memory.store(0x1008,0x222,8,source='reentry changes fn')
        self.assertEqual(_sender_core(r,0x1000,0x2000,0xBAD,1<<32,-1,a),0x2000)
        self.assertEqual(a.events,[('probe',0x111),('raw',0x222,(0x2001,0xBAD,0,(1<<64)-1))]);self.assertEqual(freed,[])
        with self.assertRaises(UnknownMemory):r.memory.load(0x2008,8)

    def test_fn1_unknown_or_NULL_is_not_skip_and_does_not_consume(self):
        for unknown in (False,True):
            r,freed,tail=self.context(heap=True);a=Component()
            def change(runtime,fn):
                if unknown:runtime.memory.forget(0x1008,8,source='unknown fn1')
                else:runtime.memory.store(0x1008,0,8,source='NULL fn1')
            a.on_probe=change
            with self.assertRaises(UnknownMemory if unknown else PrimarySemanticUnavailable):_sender_core(r,0x1000,0x2000,0xBAD,1,3,a)
            self.assertEqual(freed,[]);self.assertEqual(sum(e[0]=='probe' for e in a.events),1)

    def test_probe_unknown_and_exceptions_do_not_consume_or_complete(self):
        error=RuntimeError('component probe exception')
        for verdict in (None,True,1<<32,error):
            r,freed,tail=self.context(heap=True);a=Component(verdict)
            with self.assertRaises(RuntimeError if verdict is error else PrimarySemanticUnavailable):_sender_core(r,0x1000,0x2000,9,1,7,a)
            self.assertEqual(freed,[]);self.assertFalse(any(e[0]=='raw' for e in a.events))

    def test_callback_changes_current_tag_pointer_and_errors_have_no_finally_free(self):
        for initial_heap in (False,True):
            r,freed,tail=self.context(heap=initial_heap)
            def callback(runtime,fn,args):
                runtime.memory.store(0x2000,int(not initial_heap),1,source='current tag')
                runtime.memory.store(0x2010,0x6000,8,source='current ptr')
                return False
            a=Component(callback=callback);result=_sender_core(r,0x1000,0x2000,9,7,1<<63,a)
            self.assertEqual(freed,[] if initial_heap else [(0x6000,)])
            self.assertIs(result,tail) if not initial_heap else self.assertEqual(result,0x2000)
            self.assertEqual(r.memory.load(0x2010,8),0x6000)
        r,freed,tail=self.context(heap=True);error=RuntimeError('component callback exception')
        def fail(*args):raise error
        with self.assertRaises(RuntimeError) as caught:_sender_core(r,0x1000,0x2000,9,7,11,Component(callback=fail))
        self.assertIs(caught.exception,error);self.assertEqual(freed,[])

    def test_bare_forged_copied_or_journal_cannot_issue_borrow(self):
        r,freed,tail=self.context()
        with self.assertRaises(InputError):_SenderBorrow(object())
        fake=object.__new__(_SenderBorrow)
        with self.assertRaises(InputError):fake.check(r)
        with self.assertRaises(InputError):finish_sender(r,fake)
        with self.assertRaises(InputError):invoke(r,0x1BE2F90,(0x1000,0x2000,9,1,0))
        self.assertEqual(freed,[])
