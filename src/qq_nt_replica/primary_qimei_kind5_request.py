"""Finite reached-kind5 callsite only; does not run the enclosing post task."""
from .primary_qimei_config_request import ConfigHttpResponse, WindowsQimeiConfigTransport
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestState, RequestSlot
from .primary_qimei_reply import parse_reply
from .primary_qimei_request_pipeline import QimeiHttpRequest
from .primary_qimei_extras import QimeiRequestExtras
from .primary_qimei_transport_codec import decode_transport_reply


class QimeiKind5Request:
    def __init__(self,owner,settings,sources,material_producer,*,envelope,configuration,transport,
                 http,writer,convert_ansi,sign_enabled,settings_dependencies=None,sequence=0):
        if type(owner) is not bytes or not owner or b'\0' in owner:
            raise QimeiRequestBoundary('source owner C string required')
        self.owner,self.settings,self.sources=owner,settings,sources
        self.material_producer,self.envelope,self.configuration=material_producer,envelope,configuration
        self.transport,self.http,self.writer=transport,http,writer
        self.convert_ansi,self.sign_enabled=convert_ansi,sign_enabled
        self.dependencies={} if settings_dependencies is None else dict(settings_dependencies)
        self.sequence=sequence & ((1<<64)-1)
        self.sources._check()
        self.settings.refresh(**self.dependencies)
        self.timestamp=int.from_bytes(self.settings.record[0x231:0x239],'little')
        backing=bytes(self.settings.record[0x239:])
        end=backing.find(b'\0')
        if end<0:
            raise QimeiRequestBoundary('kind5 snapshot C string exceeds known backing')
        self.saved=backing[:end]

    def run(self):
        self.sources._check()
        state=QimeiRequestState([RequestSlot() for _ in range(5)])
        state.set_string(1,self.saved)
        for number,value in enumerate((self.sources.wow64(),2,self.sources.os_classification(),self.sources.architecture()),2):
            state.set_u32(number,value)
        payload=state.encode(convert_ansi=self.convert_ansi)
        sequence=self.sequence & 0xffffffff
        if sequence & 0x80000000:sequence-=1<<32
        self.sequence=(self.sequence+1)&((1<<64)-1)
        header=self.material_producer.produce(self.owner,5,sequence).serialize()
        envelope=self.envelope.encode(header,payload,configuration=self.configuration)
        request=self.transport.encode(envelope,mode=2,long_names=False,extra=QimeiRequestExtras(),
            configuration=self.configuration,sign_enabled=self.sign_enabled)
        response=self.http.send(QimeiHttpRequest(request.body))
        if not isinstance(response,ConfigHttpResponse):
            raise QimeiRequestBoundary('typed config HTTP response required')
        decoded=decode_transport_reply(request,response.body,send_success=response.send_success)
        if response.status!=200 or decoded.result_code or decoded.server_code:
            return False
        if not decoded.body:
            return False
        parsed=parse_reply(decoded.body,count=16)
        if not parsed.accepted:return False
        self.settings.update_kind5_response(parsed.slots,clock=self.sources.clock,writer=self.writer,**self.dependencies)
        return True


def create_windows_qimei_kind5_request(runtime,epoch,current_epoch,*,owner,settings,material_producer,
        envelope,configuration,transport,convert_ansi,sign_enabled,codec,context_producer,observations,
        platform_permit,file_permit,http_permit,settings_dependencies,sequence=0):
    from .primary_windows_qimei_config import WindowsQimeiConfigSources
    from .primary_windows_qimei_settings_writer import create_windows_qimei_settings_writer
    sources=WindowsQimeiConfigSources(runtime,epoch,current_epoch,permit=platform_permit)
    writer=create_windows_qimei_settings_writer(runtime,epoch,current_epoch,path=settings.path,
        permit=file_permit,codec=codec,context_producer=context_producer,observations=observations)
    http=WindowsQimeiConfigTransport(runtime,epoch,current_epoch,permit=http_permit)
    return QimeiKind5Request(owner,settings,sources,material_producer,envelope=envelope,
        configuration=configuration,transport=transport,http=http,writer=writer,
        convert_ansi=convert_ansi,sign_enabled=sign_enabled,settings_dependencies=settings_dependencies,
        sequence=sequence)
