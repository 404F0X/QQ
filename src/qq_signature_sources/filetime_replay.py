import re
import sys
from hashlib import sha256
from threading import get_ident

MAIN_SHA256 = '28afc919ac1b8783ecbe6ddea52ebba5ea41492573609fa7cf634467ecaa00b9'
FILETIME_CODES = frozenset({'FILETIME_TAPE_SCHEMA','FILETIME_TAPE_OWNER','FILETIME_TAPE_ORDER','FILETIME_TAPE_VALUE','FILETIME_TAPE_CLAIMED','FILETIME_ORIGIN_UNSUPPORTED','FILETIME_CONTEXT','FILETIME_EXHAUSTED','FILETIME_EXTRA','FILETIME_ABORTED'})


class FiletimeReplay:
    def __init__(self, wire, identity, metadata, reject):
        self.reject = reject
        self.runtime = None
        self.closed = self.finished = False
        self.token = None
        self.index = 0
        self.last_host_index = -1
        self.thread = get_ident()
        self.identity = identity
        self.rows = []
        self.sequences = []
        self.cursor_peer = None
        self.resolver_peer = None
        self.observed_count = None
        self.claimed = False
        self.require(wire.get('_filetimeClaimed') is not True,'FILETIME_TAPE_CLAIMED')
        rows = wire.get('filetimeEvents')
        self.require(type(rows) is list and len(rows) <= 64,'FILETIME_TAPE_SCHEMA')
        previous = 0
        keys = {'origin','apiKind','siteWord','consumedPC','helperRva','occurrence','seq','rawU64','normalReturn','mainEpoch','thread','readerInvocation'}
        for index, row in enumerate(rows):
            self.require(type(row) is dict and set(row) == keys,'FILETIME_TAPE_SCHEMA')
            self.require(row['mainEpoch'] == metadata['mainEpoch'] and row['thread'] == metadata['thread'] and type(row['thread']) is int and row['readerInvocation'] == metadata['readerInvocation'] and type(row['readerInvocation']) is int,'FILETIME_TAPE_OWNER')
            self.require(row['origin'] == 'MAIN_22033_SECONDS' and row['apiKind'] == 'GetSystemTimeAsFileTime' and type(row['siteWord']) is int and row['siteWord'] == 22033 and type(row['consumedPC']) is int and row['consumedPC'] == 22040 and type(row['helperRva']) is int and row['helperRva'] == 0x3E8ED3C and row['normalReturn'] is True,'FILETIME_ORIGIN_UNSUPPORTED')
            self.require(type(row['occurrence']) is int and row['occurrence'] == index+1 and type(row['seq']) is int and previous < row['seq'] < (1 << 53),'FILETIME_TAPE_ORDER')
            raw = row['rawU64']
            self.require(type(raw) is str and re.fullmatch(r'0x[0-9a-f]{16}',raw) is not None,'FILETIME_TAPE_VALUE')
            previous = row['seq']
            self.rows.append(int(raw,16))
            self.sequences.append(row['seq'])
        other_sequences = {row['seq'] for row in wire['host129Groups'] + wire['mainClockEvents']}
        self.require(not any(row['seq'] in other_sequences for row in rows),'FILETIME_TAPE_ORDER')
        wire['_filetimeClaimed'] = True
        self.observed_count = len(rows)
        self.claimed = True

    def require(self, value, code):
        if not value:
            self.close()
            self.reject(code)

    def install(self, runtime):
        self.require(self.runtime is None and not self.closed,'FILETIME_TAPE_CLAIMED')
        self.runtime = runtime
        self.original_invoke = runtime.invoke
        self.original_next = runtime._next
        runtime.invoke = self.invoke
        runtime._next = self.next

    def context(self, vm, rva, cells, argument_types):
        runtime = self.runtime
        owner = runtime._active_main
        stack = runtime._program_calls
        binding = runtime._main_clock_binding
        self.require(not self.closed and not self.finished and get_ident() == self.thread and owner is not None and owner['vm'] is vm and owner['thread'] == self.thread and owner['generation'] == self.identity.generation and runtime._main_generation == self.identity.generation and runtime._execute_thread == self.thread and not runtime._active_failed,'FILETIME_CONTEXT')
        self.require(len(stack) == 1 and stack[0]['name'] == 'main' and stack[0]['arguments'] == self.identity.main_arguments and stack[0]['hosts'] is None and runtime.image_base == self.identity.image_base and vm.runtime is runtime and binding is not None and binding._row is not None and binding._row.source_identity is self.identity and binding._vm is vm,'FILETIME_CONTEXT')
        self.require(sha256(vm.program.raw).hexdigest() == MAIN_SHA256 and vm.pc == 22040 and tuple(vm.program.words[22033:22040]) == (0x014A3DB9,160,0,3105,3106,0,3107) and vm.host_calls and vm.host_calls[-1] == (22033,runtime.image_base+0x2DE57A1,(3107,),160) and rva == 0x2DE57A1 and cells == (3107,) and argument_types == (8,) and vm.cells.value(3106) == runtime.image_base+0x2DE57A1 and vm.program.type(160).raw == 0x15 and vm.program.type(160).parameters == (0,7,1,8) and vm.program.size(7) == 8 and vm.program.size(8) == 8,'FILETIME_ORIGIN_UNSUPPORTED')

    def invoke(self, vm, rva, cells, *, argument_types=None):
        self.require(self.token is None,'FILETIME_CONTEXT')
        if rva != 0x2DE57A1:
            return self.original_invoke(vm,rva,cells,argument_types=argument_types)
        try:
            from qq_nt_replica.primary_sign import _invoke_host
            from qq_nt_replica.primary_vm import PrimaryVM
            caller = sys._getframe(1)
            from cursor_replay import CursorReplay
            cursor = self.cursor_peer
            resolver = self.resolver_peer
            if caller.f_code is CursorReplay.invoke.__code__ and cursor is not None and cursor.original_invoke == self.invoke and (self.runtime.invoke == cursor.invoke or resolver is not None and self.runtime.invoke == resolver.invoke and resolver.original_invoke == cursor.invoke):
                caller = caller.f_back
            from resolver_replay import ResolverReplay
            if resolver is not None and caller.f_code is ResolverReplay.invoke.__code__ and self.runtime.invoke == resolver.invoke and resolver.original_invoke == (cursor.invoke if cursor is not None else self.invoke):
                caller = caller.f_back
            self.require(caller.f_code is _invoke_host.__code__ and caller.f_back is not None and caller.f_back.f_code is PrimaryVM.step.__code__ and type(vm.host_calls) is list,'FILETIME_CONTEXT')
            self.context(vm,rva,cells,argument_types)
            index = len(vm.host_calls)-1
            self.require(index > self.last_host_index,'FILETIME_CONTEXT')
            self.last_host_index = index
            self.token = [vm,rva,cells,argument_types,index,False]
            result = self.original_invoke(vm,rva,cells,argument_types=argument_types)
            self.require(self.token is not None and self.token[5],'FILETIME_CONTEXT')
            return result
        except BaseException:
            self.close()
            raise
        finally:
            self.token = None

    def next(self, stream, name, *arguments):
        if stream is not self.runtime._filetimes:
            return self.original_next(stream,name,*arguments)
        try:
            token = self.token
            self.require(token is not None and name == 'GetSystemTimeAsFileTime' and not arguments and not token[5],'FILETIME_ORIGIN_UNSUPPORTED')
            vm,rva,cells,types,index,used = token
            self.context(vm,rva,cells,types)
            self.require(len(vm.host_calls)-1 == index,'FILETIME_CONTEXT')
            self.require(self.index < len(self.rows),'FILETIME_EXHAUSTED')
            peer = self.cursor_peer
            self.require(peer is None or peer.index == len(peer.rows) or self.sequences[self.index] < peer.sequences[peer.index],'FILETIME_TAPE_ORDER')
            peer = self.resolver_peer
            self.require(peer is None or peer.index == len(peer.rows) or self.sequences[self.index] < peer.sequences[peer.index],'FILETIME_TAPE_ORDER')
            value = self.rows[self.index]
            self.rows[self.index] = None
            self.index += 1
            token[5] = True
            self.runtime.events.append((name,value))
            return value
        except BaseException:
            self.close()
            raise

    def finish(self):
        self.require(not self.closed and not self.finished and self.runtime is not None and self.token is None and get_ident() == self.thread and not self.runtime._active_failed and self.runtime._active_main is None and not self.runtime._program_calls,'FILETIME_ABORTED')
        self.require(self.index == len(self.rows),'FILETIME_EXTRA')
        self.finished = True
        self.rows.clear()

    def snapshot(self):
        return {'observed':self.observed_count,'consumed':self.index if self.observed_count is not None else None,'finished':self.finished,'claimed':self.claimed}

    def close(self):
        self.closed = True
        self.rows.clear()
        self.sequences.clear()
        self.cursor_peer = None
        self.resolver_peer = None
        self.token = None
        if self.runtime is not None:
            self.runtime.invoke = self.original_invoke
            self.runtime._next = self.original_next
        self.identity = None
