import re
import sys
from hashlib import sha256
from threading import get_ident

MAIN_SHA256 = '28afc919ac1b8783ecbe6ddea52ebba5ea41492573609fa7cf634467ecaa00b9'
MODULE_SITES = {3886:(3893,658,647),26834:(26841,3750,3736),28528:(28535,3930,3918),28953:(28960,3973,3962),29751:(29758,4050,4037),35309:(35316,4789,4787),36501:(36508,4947,4936)}
PROCEDURE_SITES = {3906:(3914,662,658,630),27099:(27107,3776,3750,3754),28709:(28717,3946,3930,3934),29134:(29142,3989,3973,3977),30015:(30023,4073,4050,4054),36694:(36702,4964,4947,4951)}
RESOLVER_REQUEST_STAGE = 'VERIFIED_TAPE_REQUEST'
RESOLVER_CODES = frozenset({'RESOLVER_TAPE_SCHEMA','RESOLVER_TAPE_OWNER','RESOLVER_TAPE_ORDER','RESOLVER_TAPE_VALUE','RESOLVER_TAPE_CLAIMED','RESOLVER_ORIGIN_UNSUPPORTED','RESOLVER_CONTEXT','RESOLVER_EXHAUSTED','RESOLVER_EXTRA','RESOLVER_ABORTED','RESOLVER_API_IDENTITY','RESOLVER_QUERY','RESOLVER_EXPORT_UNSUPPORTED','RESOLVER_EXPORT_ABI','RESOLVER_MODULE_LINEAGE','RESOLVER_CURSOR_LINK','RESOLVER_ADMISSION','RESOLVER_HANDLE_USE_UNSUPPORTED'})


class ResolverReplay:
    def __init__(self, wire, identity, metadata, reject):
        self.reject = reject
        self.runtime = None
        self.closed = self.finished = False
        self.token = None
        self.index = 0
        self.last_host_index = -1
        self.failure_site = None
        self.thread = get_ident()
        self.identity = identity
        self.rows = []
        self.sequences = []
        self.sites = []
        self.modules = {}
        self.cursor_publications = {}
        self.admissions = ()
        self._issued_admissions = self.admissions
        self.admitted_count = 0
        self.observed_count = None
        self.claimed = False
        self.cursor_peer = self.filetime_peer = None
        self.provider_active = False
        self.site_counts = {}
        self.require(wire.get('_resolverClaimed') is not True,'RESOLVER_TAPE_CLAIMED')
        validation=wire.get('captureValidation')
        self.require(type(validation) is dict and validation.get('resolverSource')=='main-fixed13-ffi-normal-leave' and type(validation.get('resolverANSIByteCap')) is int and validation['resolverANSIByteCap']==4096 and validation.get('resolverReturnABI')=='pointer8-abi1-flags14','RESOLVER_TAPE_SCHEMA')
        rows = wire.get('resolverEvents')
        self.require(type(rows) is list and len(rows) <= 128,'RESOLVER_TAPE_SCHEMA')
        keys = {'origin','apiKind','siteWord','consumedPC','signature','destinationCell','functionCell','argumentCells','mainEpoch','thread','readerInvocation','occurrence','siteOccurrence','seq','normalReturn','arguments','resultU64','apiIdentity','resultModule','requestedModule','exportIdentity','resultKind'}
        previous = 0
        other = {row['seq'] for row in wire['host129Groups']+wire['mainClockEvents']+wire.get('filetimeEvents',[])+wire.get('cursorEvents',[])}
        for index,row in enumerate(rows):
            self.require(type(row) is dict and set(row) == keys,'RESOLVER_TAPE_SCHEMA')
            self.require(type(row['mainEpoch']) is str and row['mainEpoch'] == metadata['mainEpoch'] and all(type(row[k]) is int and row[k] == metadata[k] for k in ('thread','readerInvocation')),'RESOLVER_TAPE_OWNER')
            module = row['apiKind'] == 'GetModuleHandleA'
            table = MODULE_SITES if module else PROCEDURE_SITES
            site = row['siteWord']
            self.require(row['origin'] == 'MAIN_RESOLVER_PAIR' and row['apiKind'] in ('GetModuleHandleA','GetProcAddress') and type(site) is int and site in table and row['normalReturn'] is True,'RESOLVER_ORIGIN_UNSUPPORTED')
            pc,dest,*args = table[site]
            sig,callee = (133,659) if module else (137,663)
            self.require(all(type(row[k]) is int and row[k] == v for k,v in (('consumedPC',pc),('signature',sig),('destinationCell',dest),('functionCell',callee))) and type(row['argumentCells']) is list and all(type(v) is int for v in row['argumentCells']) and row['argumentCells'] == args,'RESOLVER_ORIGIN_UNSUPPORTED')
            self.site_counts[site] = self.site_counts.get(site,0)+1
            self.require(type(row['occurrence']) is int and row['occurrence'] == index+1 and type(row['siteOccurrence']) is int and row['siteOccurrence'] == self.site_counts[site] and type(row['seq']) is int and previous < row['seq'] < 1<<53 and row['seq'] not in other,'RESOLVER_TAPE_ORDER')
            previous = row['seq']
            self.api_identity(row['apiIdentity'],row['apiKind'],'kernel32.dll')
            query = row['arguments']
            self.require(type(query) is dict and set(query) == {'moduleName','moduleHandle','procedure'},'RESOLVER_QUERY')
            if module:
                name = self.query(query['moduleName'],null=True)
                self.require(query['moduleHandle'] is None and query['procedure'] is None and row['requestedModule'] is None and row['exportIdentity'] is None,'RESOLVER_QUERY')
                arguments = (name,)
            else:
                self.require(query['moduleName'] is None and row['resultModule'] is None,'RESOLVER_QUERY')
                arguments = (self.u64(query['moduleHandle']),self.query(query['procedure'],null=False))
            result = self.u64(row['resultU64'])
            if result == 0:
                self.require(row['resultKind'] == 'null' and row['resultModule'] is None and row['exportIdentity'] is None,'RESOLVER_TAPE_VALUE')
            elif module:
                self.require(row['resultKind'] == 'module' and self.module(row['resultModule'])[2] == result,'RESOLVER_MODULE_LINEAGE')
            else:
                self.require(row['resultKind'] in ('export','opaque'),'RESOLVER_TAPE_VALUE')
            if not module:
                self.module(row['requestedModule'])
            self.rows.append({'api':row['apiKind'],'site':site,'pc':pc,'dest':dest,'callee':callee,'sig':sig,'cells':tuple(args),'arguments':arguments,'result':result,'module':self.module(row['resultModule']) if module and result else None,'requested':self.module(row['requestedModule']) if not module else None,'export':row['exportIdentity'],'kind':row['resultKind'],'sequence':row['seq']})
            self.sequences.append(row['seq'])
            self.sites.append(site)
        by_sequence={row['sequence']:row for row in self.rows}
        for cursor_index,cursor in enumerate(wire.get('cursorEvents',[])):
            preceding=[row for row in self.rows if row['site']==36694 and row['sequence']<cursor['seq']]
            link=cursor.get('resolverLink')
            if not preceding:
                self.require(link is None,'RESOLVER_CURSOR_LINK')
                continue
            self.require(type(link) is dict and set(link)=={'moduleSeq','procedureSeq','sourceResultU64','slotPublicationVerified'} and link['slotPublicationVerified'] is True,'RESOLVER_CURSOR_LINK')
            procedure=preceding[-1]
            self.require(type(link['procedureSeq']) is int and link['procedureSeq']==procedure['sequence'] and type(link['moduleSeq']) is int and link['moduleSeq'] in by_sequence,'RESOLVER_CURSOR_LINK')
            module=by_sequence[link['moduleSeq']]
            prior_modules=[row for row in self.rows if row['site']==36501 and row['sequence']<procedure['sequence']]
            self.require(prior_modules and prior_modules[-1] is module,'RESOLVER_CURSOR_LINK')
            self.require(module['site']==36501 and module['sequence']<procedure['sequence'] and module['result']==procedure['arguments'][0] and self.u64(link['sourceResultU64'])==procedure['result'],'RESOLVER_CURSOR_LINK')
            if cursor['called']:
                self.require(procedure['result']!=0 and cursor['apiIdentity']==procedure['export'],'RESOLVER_CURSOR_LINK')
            self.cursor_publications[cursor_index]=procedure['result']
        self.site_counts.clear()
        wire['_resolverClaimed'] = True
        self.observed_count = len(rows)
        self.claimed = True

    def require(self, value, code):
        if not value:
            self.close()
            self.reject(code)

    def u64(self, value):
        self.require(type(value) is str and re.fullmatch('0x[0-9a-f]{16}',value) is not None,'RESOLVER_TAPE_VALUE')
        return int(value,16)

    def pointer(self, value):
        self.require(type(value) is str and re.fullmatch('0x[1-9a-f][0-9a-f]*',value) is not None and 0 < int(value,16) < 1<<64,'RESOLVER_API_IDENTITY')
        return int(value,16)

    def module(self, row):
        self.require(type(row) is dict and set(row) == {'name','path','base','size'} and all(type(row[k]) is str and row[k] and '\x00' not in row[k] for k in ('name','path')) and type(row['size']) is int and 0 < row['size'] < 1<<32,'RESOLVER_MODULE_LINEAGE')
        base = self.pointer(row['base'])
        self.require(base+row['size'] < 1<<64,'RESOLVER_MODULE_LINEAGE')
        return (row['name'],row['path'],base,row['size'])

    def api_identity(self, row, name, library):
        self.require(type(row) is dict and set(row) == {'exportName','sourceModule','resolvedAddress','resolvedModule'} and row['exportName'] == name,'RESOLVER_API_IDENTITY')
        source = self.module(row['sourceModule']);target = self.module(row['resolvedModule'])
        self.require(source[0].lower() == library and source[1].replace('\\','/').split('/')[-1].lower() == library,'RESOLVER_API_IDENTITY')
        address = self.pointer(row['resolvedAddress'])
        self.require(target[2] <= address < target[2]+target[3],'RESOLVER_API_IDENTITY')
        return source,address

    def query(self, row, *, null):
        self.require(type(row) is dict and set(row) == {'kind','hex','ordinal','terminated'},'RESOLVER_QUERY')
        if row['kind'] == 'null':
            self.require(null and all(row[k] is None for k in ('hex','ordinal','terminated')),'RESOLVER_QUERY')
            return None
        self.require(row['kind'] == 'ansi' and row['ordinal'] is None and row['terminated'] is True and type(row['hex']) is str and len(row['hex']) <= 8192 and re.fullmatch('(?:[0-9a-f]{2})*',row['hex']) is not None,'RESOLVER_QUERY')
        value = bytes.fromhex(row['hex'])
        self.require(b'\x00' not in value,'RESOLVER_QUERY')
        return value

    def install(self, runtime):
        self.require(self.runtime is None and not self.closed,'RESOLVER_TAPE_CLAIMED')
        self.runtime = runtime
        self.original_invoke = runtime.invoke
        self.original_next = runtime._next
        self.original_module = runtime._module_handles
        self.original_procedure = runtime._procedure_lookup
        self.watermark = len(runtime.events)
        from cursor_replay import CursorReplay
        from filetime_replay import FiletimeReplay
        if getattr(self.original_invoke,'__func__',None) is CursorReplay.invoke:
            self.cursor_peer = self.original_invoke.__self__
            self.require(self.cursor_peer.identity is self.identity,'RESOLVER_CONTEXT')
            self.cursor_peer.resolver_peer = self
            candidate = self.cursor_peer.original_invoke
        else:
            candidate = self.original_invoke
        if getattr(candidate,'__func__',None) is FiletimeReplay.invoke:
            self.filetime_peer = candidate.__self__
            self.require(self.filetime_peer.identity is self.identity,'RESOLVER_CONTEXT')
            self.filetime_peer.resolver_peer = self
        runtime._module_handles = self.module_provider
        runtime._procedure_lookup = self.procedure_provider
        runtime.invoke = self.invoke
        runtime._next = self.next

    def module_provider(self, name):
        self.require(self.provider_active and self.token is not None and self.token['row']['api'] == 'GetModuleHandleA' and self.token['row']['arguments'] == (name,),'RESOLVER_CONTEXT')
        return self.token['expected']

    def procedure_provider(self, module, name):
        self.require(self.provider_active and self.token is not None and self.token['row']['api'] == 'GetProcAddress' and self.token['row']['arguments'] == (module,name),'RESOLVER_CONTEXT')
        return self.token['expected']

    def context_source(self, vm, row, rva, cells, types):
        runtime=self.runtime;owner=runtime._active_main;stack=runtime._program_calls;binding=runtime._main_clock_binding
        self.require(not self.closed and not self.finished and get_ident() == self.thread and owner is not None and owner['vm'] is vm and owner['thread'] == self.thread and owner['generation'] == self.identity.generation and runtime._main_generation == self.identity.generation and runtime._execute_thread == self.thread and not runtime._active_failed,'RESOLVER_CONTEXT')
        self.require(len(stack) == 1 and stack[0]['name'] == 'main' and stack[0]['arguments'] == self.identity.main_arguments and stack[0]['hosts'] is None and runtime.image_base == self.identity.image_base and vm.runtime is runtime and binding is not None and binding._row is not None and binding._row.source_identity is self.identity and binding._vm is vm,'RESOLVER_CONTEXT')
        module=row['api']=='GetModuleHandleA';address=runtime.module_lookup_address if module else runtime.procedure_lookup_address
        record=(0x014A3DB9,row['sig'],0,row['dest'],row['callee'],0,*row['cells'])
        expected_types=(2,) if module else (26,2)
        parameters=(0,26,1,2) if module else (0,136,2,26,2)
        self.require(sha256(vm.program.raw).hexdigest() == MAIN_SHA256 and vm.pc == row['pc'] and tuple(vm.program.words[row['site']:row['pc']]) == record and vm.host_calls and vm.host_calls[-1] == (row['site'],address,row['cells'],row['sig']) and vm.cells.value(row['callee']) == address and rva+runtime.image_base == address and cells == row['cells'] and types == expected_types and vm.program.type(row['sig']).raw == 0x15 and vm.program.type(row['sig']).parameters == parameters and all(vm.program.size(k)==8 for k in expected_types),'RESOLVER_ORIGIN_UNSUPPORTED')

    def context(self, vm, row, rva, cells, types):
        self.context_source(vm,row,rva,cells,types)
        runtime=self.runtime
        module=row['api']=='GetModuleHandleA'
        actual=tuple(runtime.memory.load(vm.cells.pointer(cell),8) for cell in cells)
        if module:
            query=(runtime._ansi_name(actual[0]) if actual[0] else None,)
        else:
            self.require(actual[1]>0xFFFF,'RESOLVER_QUERY')
            query=(actual[0],runtime._ansi_name(actual[1]))
        self.require(query == row['arguments'],'RESOLVER_QUERY')

    def verified_request(self, vm, rva, cells, types):
        module=rva+self.runtime.image_base == self.runtime.module_lookup_address
        table=MODULE_SITES if module else PROCEDURE_SITES
        candidates=[(site,values) for site,values in table.items() if values[0]==vm.pc]
        self.require(len(candidates)==1,'RESOLVER_ORIGIN_UNSUPPORTED')
        site,(pc,dest,*arguments)=candidates[0]
        row={'api':'GetModuleHandleA' if module else 'GetProcAddress','site':site,'pc':pc,'dest':dest,'callee':659 if module else 663,'sig':133 if module else 137,'cells':tuple(arguments)}
        self.context_source(vm,row,rva,cells,types)
        self.require(len(vm.host_calls)-1>self.last_host_index,'RESOLVER_CONTEXT')
        return {'apiKind':row['api'],'siteWord':site,'consumedPC':pc,'stage':RESOLVER_REQUEST_STAGE}

    def expected(self, row):
        if row['api'] == 'GetModuleHandleA':
            handle=row['result']
            if handle and handle in self.modules:self.require(self.modules[handle] == row['module'],'RESOLVER_MODULE_LINEAGE')
            return (row['arguments'][0],handle)
        handle,name=row['arguments']
        self.require(handle in self.modules and self.modules[handle] == row['requested'] and row['requested'][2] == handle,'RESOLVER_MODULE_LINEAGE')
        if row['result'] == 0:return (handle,name,0)
        self.require(row['kind']=='export' and row['requested'][0].lower()=='user32.dll' and name==b'GetCursorPos','RESOLVER_EXPORT_UNSUPPORTED')
        source,address=self.api_identity(row['export'],'GetCursorPos','user32.dll')
        self.require(source == row['requested'] and address == row['result'],'RESOLVER_MODULE_LINEAGE')
        from qq_nt_replica.primary_core_dynamic_exports import lookup_export
        definition=lookup_export('user32.dll',name)
        self.require(type(definition) is dict and definition['supported'] is True and definition['handler_key']=='GetCursorPos' and definition['result_signed'] is False and definition['result_width']==32 and definition['argument_widths']==(64,) and definition['argument_kinds']==('output',) and definition['call_path']=='nativecall' and definition['effects']=='output8; success_all_else_changed_bytes' and definition['argument_domain']==(),'RESOLVER_EXPORT_ABI')
        self.require(type(self.runtime.cursor_position_address) is int and self.runtime.cursor_position_address>0,'RESOLVER_EXPORT_ABI')
        return (handle,name,self.runtime.cursor_position_address)

    def invoke(self, vm, rva, cells, *, argument_types=None):
        runtime=self.runtime;address=rva+runtime.image_base
        if self.token is not None or address in (runtime.module_lookup_address,runtime.procedure_lookup_address):
            self.failure_site=None
        self.require(self.token is None,'RESOLVER_CONTEXT')
        if address in {runtime.module_filename_address,*runtime.module_filename_aliases} and cells:
            handle=runtime.memory.load(vm.cells.pointer(cells[0]),8)
            self.require(handle not in self.modules,'RESOLVER_HANDLE_USE_UNSUPPORTED')
        if address not in (runtime.module_lookup_address,runtime.procedure_lookup_address):
            return self.original_invoke(vm,rva,cells,argument_types=argument_types)
        try:
            from qq_nt_replica.primary_sign import _invoke_host
            from qq_nt_replica.primary_vm import PrimaryVM
            caller=sys._getframe(1)
            self.require(caller.f_code is _invoke_host.__code__ and caller.f_back is not None and caller.f_back.f_code is PrimaryVM.step.__code__ and type(vm.host_calls) is list,'RESOLVER_CONTEXT')
            self.failure_site=self.verified_request(vm,rva,cells,argument_types)
            self.require(self.index<len(self.rows),'RESOLVER_EXHAUSTED')
            row=self.rows[self.index]
            self.context(vm,row,rva,cells,argument_types)
            for peer in (self.filetime_peer,self.cursor_peer):self.require(peer is None or peer.index == len(peer.rows) or row['sequence'] < peer.sequences[peer.index],'RESOLVER_TAPE_ORDER')
            host_index=len(vm.host_calls)-1
            self.require(host_index>self.last_host_index,'RESOLVER_CONTEXT');self.last_host_index=host_index
            expected=self.expected(row)
            self.token={'row':row,'vm':vm,'rva':rva,'cells':cells,'types':argument_types,'hostIndex':host_index,'used':False,'expected':expected,'eventIndex':None}
            result=self.original_invoke(vm,rva,cells,argument_types=argument_types)
            token=self.token
            self.require(token is not None and token['used'] and result == expected[-1] and type(result) is int,'RESOLVER_ADMISSION')
            self.context(vm,row,rva,cells,argument_types)
            event_index=token['eventIndex'];event=(row['api'],expected)
            self.require(type(event_index) is int and event_index>=self.watermark and event_index<len(runtime.events) and self.matches(runtime.events[event_index],event) and (not self.admissions or event_index>self.admissions[-1][0]),'RESOLVER_ADMISSION')
            self.admissions += ((event_index,row['sequence'],host_index,row['site'],event,row['result'],expected[-1]),)
            self._issued_admissions = self.admissions
            self.admitted_count += 1
            if row['api']=='GetModuleHandleA' and row['result']:self.modules[row['result']]=row['module']
            return result
        except BaseException:
            self.close()
            raise
        finally:
            self.token=None;self.provider_active=False

    def next(self, stream, name, *arguments):
        if stream is not self.runtime._module_handles and stream is not self.runtime._procedure_lookup:
            return self.original_next(stream,name,*arguments)
        try:
            token=self.token
            if token is None:self.failure_site=None
            self.require(token is not None and not token['used'] and name==token['row']['api'] and arguments==token['row']['arguments'] and stream is (self.runtime._module_handles if name=='GetModuleHandleA' else self.runtime._procedure_lookup),'RESOLVER_CONTEXT')
            self.context(token['vm'],token['row'],token['rva'],token['cells'],token['types'])
            self.require(len(token['vm'].host_calls)-1 == token['hostIndex'],'RESOLVER_CONTEXT')
            start=len(self.runtime.events)
            self.provider_active=True
            try:value=self.original_next(stream,name,*arguments)
            finally:self.provider_active=False
            self.require(self.matches((name,value),(name,token['expected'])) and len(self.runtime.events)==start+1 and self.matches(self.runtime.events[start],(name,token['expected'])),'RESOLVER_ADMISSION')
            token['used']=True;token['eventIndex']=start
            self.rows[self.index]=None;self.index+=1
            return value
        except BaseException:
            self.close()
            raise

    def finish(self):
        self.require(not self.closed and not self.finished and self.runtime is not None and self.token is None and get_ident()==self.thread and not self.runtime._active_failed and self.runtime._active_main is None and not self.runtime._program_calls,'RESOLVER_ABORTED')
        self.require(self.index==len(self.rows),'RESOLVER_EXTRA')
        self.require(self.admissions is self._issued_admissions and len(self.admissions)==self.index and len({row[0] for row in self.admissions})==self.index,'RESOLVER_ADMISSION')
        previous_index=self.watermark-1
        previous_host=-1
        for ordinal,(index,sequence,host,site,event,native_result,model_target) in enumerate(self.admissions):
            self.require(type(index) is int and previous_index<index<len(self.runtime.events) and type(host) is int and previous_host<host and sequence==self.sequences[ordinal] and site==self.sites[ordinal] and self.matches(self.runtime.events[index],event) and type(native_result) is int and type(model_target) is int and event[1][-1]==model_target and (native_result==model_target if site in MODULE_SITES or native_result==0 else model_target==self.runtime.cursor_position_address),'RESOLVER_ADMISSION')
            previous_index=index;previous_host=host
        self.admissions=tuple(self.admissions)
        self.finished=True
        self.failure_site=None
        self.rows.clear()

    def check_cursor_publication(self, index, vm):
        self.require(not self.closed and self.cursor_peer is not None,'RESOLVER_CURSOR_LINK')
        if index in self.cursor_publications:
            slot=self.runtime.image_base+0x6D86000
            self.require(vm.cells.value(4930)==slot and vm.cells.value(4965)==slot,'RESOLVER_CURSOR_LINK')
            expected=self.runtime.cursor_position_address if self.cursor_publications[index] else 0
            self.require(self.runtime.memory.load(self.runtime.image_base+0x6D86000,8)==expected,'RESOLVER_CURSOR_LINK')

    def matches(self, event, expected):
        return type(event) is tuple and len(event)==2 and type(event[0]) is str and event[0]==expected[0] and type(event[1]) is tuple and event[1]==expected[1] and tuple(type(value) for value in event[1])==tuple(type(value) for value in expected[1])

    def admits(self, index, event):
        self.require(self.finished and not self.closed and self.admissions is self._issued_admissions,'RESOLVER_ADMISSION')
        matches=[row for row in self.admissions if row[0]==index]
        return len(matches)==1 and self.matches(event,matches[0][4])

    def snapshot(self):
        return {'kind':'RESOLVER_ROWS','observed':self.observed_count,'consumed':self.index if self.observed_count is not None else None,'admitted':self.admitted_count,'finished':self.finished,'claimed':self.claimed,'failureSite':dict(self.failure_site) if self.failure_site is not None else None}

    def close(self):
        self.closed=True
        self.rows.clear();self.sequences.clear();self.sites.clear();self.modules.clear();self.cursor_publications.clear()
        self.admissions=();self._issued_admissions=self.admissions;self.site_counts.clear()
        self.token=None;self.provider_active=False
        if self.runtime is not None:
            self.runtime.invoke=self.original_invoke;self.runtime._next=self.original_next
            self.runtime._module_handles=self.original_module;self.runtime._procedure_lookup=self.original_procedure
        for peer in (self.cursor_peer,self.filetime_peer):
            if peer is not None:peer.resolver_peer=None
        self.cursor_peer=self.filetime_peer=None
        self.identity=None
