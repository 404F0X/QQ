import re
import sys
from hashlib import sha256
from threading import get_ident

MAIN_SHA256 = '28afc919ac1b8783ecbe6ddea52ebba5ea41492573609fa7cf634467ecaa00b9'
CURSOR_CODES = frozenset({'CURSOR_TAPE_SCHEMA','CURSOR_TAPE_OWNER','CURSOR_TAPE_ORDER','CURSOR_TAPE_VALUE','CURSOR_TAPE_CLAIMED','CURSOR_ORIGIN_UNSUPPORTED','CURSOR_CONTEXT','CURSOR_EXHAUSTED','CURSOR_EXTRA','CURSOR_ABORTED','CURSOR_API_IDENTITY'})


class CursorReplay:
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
        self.filetime_peer = None
        self.resolver_peer = None
        self.observed_count = None
        self.claimed = False
        self.effective_entry = 'effectiveEnvironment' in wire
        self.require(wire.get('_cursorClaimed') is not True,'CURSOR_TAPE_CLAIMED')
        rows = wire.get('cursorEvents')
        self.require(type(rows) is list and len(rows) <= 64,'CURSOR_TAPE_SCHEMA')
        keys = {'origin','apiKind','siteWord','consumedPC','signature','calleeRva','occurrence','seq','mainEpoch','thread','readerInvocation','normalReturn','called','boolU32','point','failurePolicy','slotAtEntry','outputPointer','apiIdentity','resolverLink'}
        previous = 0
        others = {row['seq'] for row in wire['host129Groups'] + wire['mainClockEvents'] + wire.get('filetimeEvents',[])}
        for index,row in enumerate(rows):
            self.require(type(row) is dict and set(row) == keys,'CURSOR_TAPE_SCHEMA')
            self.require(type(row['mainEpoch']) is str and row['mainEpoch'] == metadata['mainEpoch'] and all(type(row[key]) is int and row[key] == metadata[key] for key in ('thread','readerInvocation')),'CURSOR_TAPE_OWNER')
            self.require(row['origin'] == 'MAIN_36720_WRAPPER' and row['apiKind'] == 'GetCursorPos' and row['failurePolicy'] == 'wrapper-discard' and row['normalReturn'] is True and all(type(row[key]) is int and row[key] == value for key,value in (('siteWord',36720),('consumedPC',36726),('signature',200),('calleeRva',0x2DE52D5))),'CURSOR_ORIGIN_UNSUPPORTED')
            self.require(type(row['occurrence']) is int and row['occurrence'] == index+1 and type(row['seq']) is int and previous < row['seq'] < 1<<53 and row['seq'] not in others,'CURSOR_TAPE_ORDER')
            previous = row['seq']
            self.pointer(row['slotAtEntry'],zero=True)
            self.pointer(row['outputPointer'])
            self.require(type(row['called']) is bool,'CURSOR_TAPE_VALUE')
            if not row['called']:
                self.require(row['boolU32'] is None and row['point'] is None and row['apiIdentity'] is None,'CURSOR_TAPE_VALUE')
                value = None
            else:
                self.api_identity(row['apiIdentity'])
                result = row['boolU32']
                self.require(type(result) is int and 0 <= result < 1<<32,'CURSOR_TAPE_VALUE')
                if result == 0:
                    self.require(row['point'] is None,'CURSOR_TAPE_VALUE')
                    value = (0,None,None)
                else:
                    self.require(type(row['point']) is str and re.fullmatch('[0-9a-f]{16}',row['point']) is not None,'CURSOR_TAPE_VALUE')
                    point = bytes.fromhex(row['point'])
                    value = (result,int.from_bytes(point[:4],'little',signed=True),int.from_bytes(point[4:],'little',signed=True))
            link=row['resolverLink']
            self.require(link is None or type(link) is dict and set(link)=={'moduleSeq','procedureSeq','sourceResultU64','slotPublicationVerified'} and link['slotPublicationVerified'] is True and all(type(link[k]) is int and 0<link[k]<row['seq'] for k in ('moduleSeq','procedureSeq')) and type(link['sourceResultU64']) is str and re.fullmatch('0x[0-9a-f]{16}',link['sourceResultU64']) is not None,'CURSOR_API_IDENTITY')
            self.require(link is None or type(wire.get('resolverEvents')) is list,'CURSOR_API_IDENTITY')
            self.rows.append((row['called'],value))
            self.sequences.append(row['seq'])
        wire['_cursorClaimed'] = True
        self.observed_count = len(rows)
        self.claimed = True

    def require(self, value, code):
        if not value:
            self.close()
            self.reject(code)

    def pointer(self, value, zero=False):
        self.require(type(value) is str and re.fullmatch('0x(?:0|[1-9a-f][0-9a-f]*)',value) is not None,'CURSOR_API_IDENTITY')
        number = int(value,16)
        self.require((0 if zero else 1) <= number < 1<<64,'CURSOR_API_IDENTITY')
        return number

    def api_identity(self, row):
        self.require(type(row) is dict and set(row) == {'exportName','sourceModule','resolvedAddress','resolvedModule'} and row['exportName'] == 'GetCursorPos','CURSOR_API_IDENTITY')
        for key in ('sourceModule','resolvedModule'):
            module = row[key]
            self.require(type(module) is dict and set(module) == {'name','path','base','size'} and all(type(module[name]) is str and module[name] and '\x00' not in module[name] for name in ('name','path')) and type(module['size']) is int and 0 < module['size'] < 1<<32,'CURSOR_API_IDENTITY')
            base = self.pointer(module['base'])
            self.require(base+module['size'] < 1<<64,'CURSOR_API_IDENTITY')
        self.require(row['sourceModule']['name'].lower() == 'user32.dll' and row['sourceModule']['path'].replace('\\','/').split('/')[-1].lower() == 'user32.dll','CURSOR_API_IDENTITY')
        address = self.pointer(row['resolvedAddress'])
        final = row['resolvedModule']
        self.require(int(final['base'],16) <= address < int(final['base'],16)+final['size'],'CURSOR_API_IDENTITY')

    def install(self, runtime):
        self.require(self.runtime is None and not self.closed,'CURSOR_TAPE_CLAIMED')
        self.runtime = runtime
        self.original_invoke = runtime.invoke
        self.original_next = runtime._next
        from filetime_replay import FiletimeReplay
        if getattr(self.original_invoke,'__func__',None) is FiletimeReplay.invoke:
            self.filetime_peer = self.original_invoke.__self__
            self.require(self.filetime_peer.identity is self.identity,'CURSOR_CONTEXT')
            self.filetime_peer.cursor_peer = self
        runtime.invoke = self.invoke
        runtime._next = self.next

    def context(self, vm, rva, cells, argument_types):
        runtime = self.runtime
        owner = runtime._active_main
        binding = runtime._main_clock_binding
        stack = runtime._program_calls
        self.require(not self.closed and not self.finished and get_ident() == self.thread and owner is not None and owner['vm'] is vm and owner['thread'] == self.thread and owner['generation'] == self.identity.generation and runtime._main_generation == self.identity.generation and runtime._execute_thread == self.thread and not runtime._active_failed,'CURSOR_CONTEXT')
        self.require(len(stack) == 1 and stack[0]['name'] == 'main' and stack[0]['arguments'] == self.identity.main_arguments and stack[0]['hosts'] is None and runtime.image_base == self.identity.image_base and vm.runtime is runtime and binding is not None and binding._row is not None and binding._row.source_identity is self.identity and binding._vm is vm,'CURSOR_CONTEXT')
        self.require(sha256(vm.program.raw).hexdigest() == MAIN_SHA256 and vm.pc == 36726 and tuple(vm.program.words[36720:36726]) == (0x014A3DB9,200,0,4967,0,44) and vm.host_calls and vm.host_calls[-1] == (36720,runtime.image_base+0x2DE52D5,(44,),200) and rva == 0x2DE52D5 and cells == (44,) and argument_types == (34,) and vm.cells.value(4967) == runtime.image_base+0x2DE52D5 and vm.program.type(200).raw == 0x15 and vm.program.type(200).parameters == (0,0,1,34) and vm.program.type(0).raw == 2 and vm.program.size(34) == 8,'CURSOR_ORIGIN_UNSUPPORTED')

    def invoke(self, vm, rva, cells, *, argument_types=None):
        self.require(self.token is None,'CURSOR_CONTEXT')
        if rva != 0x2DE52D5:
            return self.original_invoke(vm,rva,cells,argument_types=argument_types)
        try:
            from qq_nt_replica.primary_sign import _invoke_host
            from qq_nt_replica.primary_vm import PrimaryVM
            caller = sys._getframe(1)
            from resolver_replay import ResolverReplay
            peer = self.resolver_peer
            if peer is not None and caller.f_code is ResolverReplay.invoke.__code__ and self.runtime.invoke == peer.invoke and peer.original_invoke == self.invoke:
                caller = caller.f_back
            self.require(caller.f_code is _invoke_host.__code__ and caller.f_back is not None and caller.f_back.f_code is PrimaryVM.step.__code__ and type(vm.host_calls) is list,'CURSOR_CONTEXT')
            self.context(vm,rva,cells,argument_types)
            index = len(vm.host_calls)-1
            self.require(index > self.last_host_index,'CURSOR_CONTEXT')
            self.last_host_index = index
            self.require(self.index < len(self.rows),'CURSOR_EXHAUSTED')
            peer = self.filetime_peer
            self.require(peer is None or peer.index == len(peer.rows) or self.sequences[self.index] < peer.sequences[peer.index],'CURSOR_TAPE_ORDER')
            peer = self.resolver_peer
            self.require(peer is None or peer.index == len(peer.rows) or self.sequences[self.index] < peer.sequences[peer.index],'CURSOR_TAPE_ORDER')
            if peer is not None:
                peer.check_cursor_publication(self.index,vm)
            called,value = self.rows[self.index]
            self.token = [vm,rva,cells,argument_types,index,False,called]
            if self.effective_entry:
                self.require(self.runtime.memory.load(self.runtime.image_base+0x6D86000,8) == (self.runtime.cursor_position_address if called else 0),'CURSOR_CONTEXT')
            else:
                self.runtime.memory.store(self.runtime.image_base+0x6D86000,self.runtime.cursor_position_address if called else 0,8,source='source-qualified cursor branch')
            result = self.original_invoke(vm,rva,cells,argument_types=argument_types)
            self.require(self.token is not None and self.token[5] == called,'CURSOR_CONTEXT')
            if not called:
                self.rows[self.index] = None
                self.index += 1
            return result
        except BaseException:
            self.close()
            raise
        finally:
            self.token = None

    def next(self, stream, name, *arguments):
        if stream is not self.runtime._cursor_position:
            return self.original_next(stream,name,*arguments)
        try:
            token = self.token
            self.require(token is not None and token[6] and not token[5] and name == 'GetCursorPos' and not arguments,'CURSOR_ORIGIN_UNSUPPORTED')
            vm,rva,cells,types,index,used,called = token
            self.context(vm,rva,cells,types)
            self.require(len(vm.host_calls)-1 == index and self.index < len(self.rows),'CURSOR_CONTEXT')
            value = self.rows[self.index][1]
            self.rows[self.index] = None
            self.index += 1
            token[5] = True
            self.runtime.events.append((name,value))
            return value
        except BaseException:
            self.close()
            raise

    def finish(self):
        self.require(not self.closed and not self.finished and self.runtime is not None and self.token is None and get_ident() == self.thread and not self.runtime._active_failed and self.runtime._active_main is None and not self.runtime._program_calls,'CURSOR_ABORTED')
        self.require(self.index == len(self.rows),'CURSOR_EXTRA')
        self.finished = True
        self.rows.clear()

    def snapshot(self):
        return {'kind':'WRAPPER_ROWS','observed':self.observed_count,'consumed':self.index if self.observed_count is not None else None,'finished':self.finished,'claimed':self.claimed}

    def close(self):
        self.closed = True
        self.rows.clear()
        self.sequences.clear()
        if self.filetime_peer is not None:
            self.filetime_peer.cursor_peer = None
        self.filetime_peer = None
        self.resolver_peer = None
        self.token = None
        if self.runtime is not None:
            self.runtime.invoke = self.original_invoke
            self.runtime._next = self.original_next
        self.identity = None
