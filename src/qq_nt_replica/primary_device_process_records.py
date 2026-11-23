import hashlib
import json
from pathlib import Path
import struct
from dataclasses import dataclass

from .errors import InputError
from .primary_device_cache import _WideString
from .primary_device_collector import _terminated
from .primary_device_system_records import bounded_copy, utf8_string, _format_into
from .primary_logger import _String
from .primary_memory import PrimaryMemoryLimit, UnknownMemory
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke
from .primary_worker_response import _frame


_IMAGE_SHA256 = 'f4be47de60c59103b946943d92861ec463efdaabcda75457332edff2ed74a279'
_LIMIT = 1 << 20


@dataclass(frozen=True)
class ProcessBufferEffect:
    spans: tuple


def _image():
    raw = (Path(__file__).with_name('data')/'primary_sign_qq52230/device-process-record-image.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _IMAGE_SHA256:
        raise InputError('fixed process record image identity mismatch')
    return json.loads(raw)


_IMPORTS = _image()['imports']


def install_image(memory, image_base):
    for segment in _image()['segments']:
        address, raw = image_base+segment['rva'],bytes.fromhex(segment['hex'])
        try:
            memory._span(address,len(raw))
        except PrimaryMemoryLimit:
            overlaps = [region for region in memory._region_snapshot() if address<region.address+len(region.data) and region.address<address+len(raw)]
            if overlaps:
                first = min(address,*(region.address for region in overlaps))
                last = max(address+len(raw),*(region.address+len(region.data) for region in overlaps))
                merged,known = bytearray(last-first),bytearray(last-first)
                for region in overlaps:
                    if not all(region.initialized):
                        raise InputError('shared process record fixed image contains unknown bytes')
                    start = region.address-first
                    merged[start:start+len(region.data)] = region.data
                    known[start:start+len(region.data)] = b'\1'*len(region.data)
                for offset,value in enumerate(raw,address-first):
                    if known[offset] and merged[offset]!=value:
                        raise InputError('shared process record image identity mismatch')
                    merged[offset],known[offset] = value,1
                if not all(known):
                    raise InputError('shared process record image has an unobserved gap')
                for region in overlaps:
                    memory.unmap(region.address)
                memory.map(first,merged,name='shared fixed process record image',initialized=True)
            else:
                memory.map(address,bytearray(raw),name='fixed process record image',initialized=True)
        else:
            if memory.read(address,len(raw)) != raw:
                raise InputError('shared process record image identity mismatch')


def _literal(runtime, name, width=1):
    return _terminated(runtime,runtime.image_base+_image()['roles'][name],width)


def _observe(runtime, name, arguments):
    if name != 'NtQueryInformationProcess':
        target = runtime.worker_imports.get(name)
        if target is None or runtime.memory.load(runtime.image_base+_IMPORTS[name],8) != target:
            raise PrimarySemanticUnavailable('process record current import is not bound: '+name)
    if runtime.worker_observations is None:
        raise UnknownMemory('missing process record OS observations: '+name)
    return runtime.worker_observations.take(runtime,name,arguments)


def _call(runtime, name, arguments, outputs=()):
    result,effects = _observe(runtime,name,arguments)
    if not outputs:
        if effects is not None and not (type(effects) is bytes and effects == b''):
            raise InputError('process record operation requires empty output effects: '+name)
        return result
    if not isinstance(effects,tuple) or len(effects) != len(outputs):
        raise InputError('process record operation requires raw output buffers: '+name)
    for raw,(address,capacity) in zip(effects,outputs):
        if type(raw) is ProcessBufferEffect:
            end = 0
            for offset,data in raw.spans:
                if type(offset) is not int or type(data) is not bytes or not data or offset < end or offset+len(data)>capacity or not address:
                    raise InputError('process record sparse output exceeds its actual buffer: '+name)
                runtime.memory.write(address+offset,data,source='process_record.'+name)
                end = offset+len(data)
            continue
        if not isinstance(raw,bytes) or len(raw)>capacity or raw and not address:
            raise InputError('process record output exceeds its actual buffer: '+name)
        if raw:
            runtime.memory.write(address,raw,source='process_record.'+name)
    return result


def _images(runtime, images):
    if not isinstance(images,tuple) or len(images)>32:
        raise InputError('process record provider requires bounded foreign images')
    for address,raw in images:
        if type(address) is not int or not 0<address<(1<<64) or not isinstance(raw,bytes) or not 0<len(raw)<=_LIMIT or address+len(raw)>1<<64:
            raise InputError('process record foreign image requires a bounded address and raw bytes')
        try:
            runtime.memory._span(address,len(raw))
        except PrimaryMemoryLimit:
            runtime.memory.map(address,bytearray(raw),name='observed process record foreign image',initialized=True)
        else:
            runtime.memory.write(address,raw,source='process_record.foreign_output')


def _data(runtime, address, width=1):
    return runtime.memory.load(address+16,8) if runtime.memory.load(address,1)&1 else address+width


def wide_string(runtime, destination, source):
    memory = runtime.memory
    if not source or not memory.load(source,1):
        memory.store(destination,0,1,source='3C71430.empty_wide_tag')
        memory.store(destination+2,0,2,source='3C71430.empty_wide_payload')
        return destination
    raw = _terminated(runtime,source,1)
    args = (65001,0,raw,-1)
    count = _call(runtime,'MultiByteToWideChar',(*args,False,0))&0xFFFFFFFF
    if not count or count&0x80000000:
        memory.store(destination,0,1,source='3C71430.failed_wide_tag')
        memory.store(destination+2,0,2,source='3C71430.failed_wide_payload')
        return destination
    if count>_LIMIT//2:
        raise PrimaryProgramLimit('process record wide conversion exceeds the offline domain')
    value = _WideString.construct(runtime,bytes(2*count))
    value.write_to(destination)
    pointer = _data(runtime,destination,2)
    _call(runtime,'MultiByteToWideChar',(*args,True,count),((pointer,2*count),))
    value = _WideString.read(runtime,destination)
    if value.get(0,1)&1:
        value.set(8,(count-1).to_bytes(8,'little'))
        memory.store(pointer+2*(count-1),0,2,source='3C71430.resize_wide_terminator')
    else:
        value.set(0,bytes([2*(count-1)]))
        value.set(2*count,b'\0\0')
    value.write_to(destination)
    return destination


def basename(runtime, source, destination, capacity):
    if not destination or not capacity:
        return None
    runtime.memory.store(destination,0,1,source='35ED8F0.initial_basename')
    if source:
        raw = _terminated(runtime,source,1)[:-1]
        offset = raw.rfind(b'\\')
        if offset<0:
            offset = raw.rfind(b'/')
        bounded_copy(runtime,destination,capacity,source+offset+1)
    return None


def _fold(value):
    return value+32 if 65<=value<=90 else value


def find_wide_case_insensitive(runtime, source, needle):
    if not source or not needle:
        return 0
    raw = _terminated(runtime,needle,2)[:-2]
    units = struct.unpack('<'+'H'*(len(raw)//2),raw)
    if not units:
        return source
    memory = runtime.memory
    for index in range(_LIMIT//2):
        if not memory.load(source+2*index,2):
            return 0
        for offset,unit in enumerate(units):
            value = memory.load(source+2*(index+offset),2)
            if not value:
                return 0
            if _fold(value) != _fold(unit):
                break
        else:
            return source+2*index
    raise PrimaryProgramLimit('process record wide search exceeds the offline domain')


def rewrite_system32(runtime, source, destination, capacity):
    if not source or not destination or capacity<16:
        return 0
    runtime.memory.store(destination,0,2,source='35EDD40.initial_rewritten_path')
    return 0


def filetime_text(runtime, source, destination, capacity):
    if not destination or not capacity:
        return None
    memory = runtime.memory
    memory.store(destination,0,1,source='35EDA10.initial_calendar_output')
    if not source:
        return None
    frame,local = _frame(runtime,0x88,'35EDA10.calendar_frame')
    calendar = frame+0x58
    memory.write(calendar,bytes(16),source='35EDA10.initial_SYSTEMTIME')
    if _call(runtime,'FileTimeToSystemTime',(memory.read(source,8),),((calendar,16),))&0xFFFFFFFF:
        values = struct.unpack('<8H',memory.read(calendar,16))
        _format_into(runtime,destination,capacity,_literal(runtime,'calendar_format')[:-1].decode('ascii'),
                     (values[0],values[1],values[3],values[4],values[5],values[6]))
    memory.unmap(frame)
    return None


def version_text(runtime, destination, capacity, source, length):
    frame,local = _frame(runtime,0x2040,'35EF450.version_text_frame')
    if not destination or not capacity:
        runtime.memory.unmap(frame)
        return None
    memory = runtime.memory
    if not source or not length:
        memory.store(destination,0,1,source='35EF450.empty_version_text')
    else:
        if length>_LIMIT//2:
            raise PrimaryProgramLimit('process record version string scan exceeds the offline domain')
        count = 0
        while count<length and memory.load(source+2*count,2):
            count += 1
        if not count:
            memory.store(destination,0,1,source='35EF450.empty_version_text')
        else:
            count = min(count,4095)
            memory.write(frame+0x20,memory.read(source,2*count)+b'\0\0',source='35EF450.bounded_wide_version')
            string = frame+0x2020
            utf8_string(runtime,string,frame+0x20)
            bounded_copy(runtime,destination,capacity,_data(runtime,string))
            _String.read(runtime,string).destroy()
    memory.unmap(frame)
    return None


def certificate_name(runtime, source, destination, capacity):
    memory = runtime.memory
    frame,rbp = _frame(runtime,0x178,'35EE6C0.certificate_frame')
    encoding,content,form,store,message = rbp+0xCC,rbp+0xD0,rbp+0xD4,rbp+0xD8,rbp+0xE8
    for pointer,width in ((encoding,4),(content,4),(form,4),(store,8),(message,8)):
        memory.store(pointer,0,width,source='35EE6C0.initial_certificate_outputs')
    queried = _call(runtime,'CryptQueryObject',(1,_terminated(runtime,source,2),0x400,2,0,True,True,True,True,True,False),
                    ((encoding,4),(content,4),(form,4),(store,8),(message,8)))&0xFFFFFFFF
    current_store,current_message = memory.load(store,8),memory.load(message,8)
    success,buffer,certificate = 0,0,0
    if queried and current_message:
        size_pointer = rbp+0xE0
        memory.store(size_pointer,0,4,source='35EE6C0.initial_signer_size')
        sized = _call(runtime,'CryptMsgGetParam',(current_message,6,0,False,0),((size_pointer,4),))&0xFFFFFFFF
        size = memory.load(size_pointer,4)
        if sized and 0<size<=0xFFFFF:
            buffer = _invoke(runtime,0x3E97020,size)
            fill_size = rbp+0xE4
            memory.store(fill_size,size,4,source='35EE6C0.initial_signer_capacity')
            filled = _call(runtime,'CryptMsgGetParam',(current_message,6,0,True,size),((buffer,size),(fill_size,4)))&0xFFFFFFFF
            if filled and memory.load(fill_size,4)<=size:
                cert_info = rbp-0x20
                memory.write(cert_info,bytes(208),source='35EE6C0.initial_CERT_INFO')
                for target,origin in ((cert_info+0x30,buffer+8),(cert_info+8,buffer+24)):
                    try:
                        blob = memory.read(origin,16)
                    except UnknownMemory:
                        memory.write(target,memory.read(origin,4),source='35EE6C0.CERT_INFO_blob_size')
                        memory.write(target+8,memory.read(origin+8,8),source='35EE6C0.CERT_INFO_blob_pointer')
                    else:
                        memory.write(target,blob,source='35EE6C0.CERT_INFO_blob')
                if current_store:
                    certificate = _call(runtime,'CertFindCertificateInStore',
                        (current_store,0x10001,0,0xB0000,memory.read(cert_info,208),0))
                if certificate:
                    oid = _literal(runtime,'certificate_oid')[:-1]
                    count = _call(runtime,'CertGetNameStringW',(certificate,3,0,oid,False,0))&0xFFFFFFFF
                    if 2<=count<=4095:
                        name_buffer = _invoke(runtime,0x3E92E00,count,2)
                        named = _call(runtime,'CertGetNameStringW',(certificate,3,0,oid,True,count),((name_buffer,2*count),))&0xFFFFFFFF
                        if named>=2:
                            memory.store(name_buffer+2*(count-1),0,2,source='35EE6C0.certificate_name_terminator')
                            string = rbp+0xB0
                            utf8_string(runtime,string,name_buffer)
                            bounded_copy(runtime,destination,capacity,_data(runtime,string))
                            _String.read(runtime,string).destroy()
                        _invoke(runtime,0x3E94F90,name_buffer)
                    success = int(memory.load(destination,1)!=0)
            memory.write(buffer,bytes(size),source='35EE6C0.clear_signer_buffer')
            _invoke(runtime,0x3E94F90,buffer)
            if certificate:
                _call(runtime,'CertFreeCertificateContext',(certificate,))
    if current_message:
        _call(runtime,'CryptMsgClose',(current_message,))
    if current_store:
        _call(runtime,'CertCloseStore',(current_store,0))
    memory.unmap(frame)
    return success


def certificate_output(runtime, source, destination, capacity):
    if source and destination and capacity:
        runtime.memory.store(destination,0,1,source='35EDBB0.initial_certificate_name')
        certificate_name(runtime,source,destination,capacity)
    return None


def _version_query(runtime, buffer, query, pointer, length):
    memory = runtime.memory
    memory.store(pointer,0,8,source='35EEAA0.initial_version_pointer')
    memory.store(length,0,4,source='35EEAA0.initial_version_length')
    result,effects = _observe(runtime,'VerQueryValueW',(buffer,query))
    if not isinstance(effects,tuple) or len(effects)!=3:
        raise InputError('process record version query requires raw pointer,length and images')
    raw_pointer,raw_length,images = effects
    for raw,address,capacity in ((raw_pointer,pointer,8),(raw_length,length,4)):
        if not isinstance(raw,bytes) or len(raw)>capacity:
            raise InputError('process record version output exceeds its scalar buffer')
        memory.write(address,raw,source='35EEAA0.VerQueryValueW_output')
    _images(runtime,images)
    return result&0xFFFFFFFF,memory.load(pointer,8),memory.load(length,4)


def version_resources(runtime, source, company, company_capacity, product, product_capacity, version, version_capacity):
    memory,image = runtime.memory,_image()
    frame,local = _frame(runtime,0x248,'35EEAA0.version_frame')
    path = _terminated(runtime,source,2)
    size = _call(runtime,'GetFileVersionInfoSizeW',(path,),((frame+0x48,4),))&0xFFFFFFFF
    if size:
        if size>_LIMIT:
            raise PrimaryProgramLimit('process record version resource exceeds the offline domain')
        buffer = _invoke(runtime,0x3E97020,size)
        memory.write(buffer,bytes(size),source='35EEAA0.initial_version_resource')
        if _call(runtime,'GetFileVersionInfoW',(path,0,size,True),((buffer,size),))&0xFFFFFFFF:
            result,translations,length = _version_query(runtime,buffer,_literal(runtime,'translation',2),frame+0xE0,frame+0xDC)
            if result and translations and length>=4:
                fields = ((company,company_capacity,'CompanyName'),(product,product_capacity,'ProductName'),(version,version_capacity,'FileVersion'))
                for index in range(length//4):
                    for destination,capacity,key in fields:
                        if destination and capacity and not memory.load(destination,1):
                            language,codepage = struct.unpack('<HH',memory.read(translations+4*index,4))
                            template = _terminated(runtime,runtime.image_base+image['version_templates'][key],2)[:-2].decode('utf-16-le')
                            query = (template%(language,codepage)).encode('utf-16-le')+b'\0\0'
                            if len(query)>256:
                                raise PrimarySemanticUnavailable('process record wide snprintf overflow is not recovered')
                            memory.write(frame+0xF0,query,source='35EEAA0.version_subblock_format')
                            memory.store(frame+0x1EE,0,2,source='35EEAA0.version_subblock_terminator')
                            result,pointer,units = _version_query(runtime,buffer,_terminated(runtime,frame+0xF0,2),frame+0xD0,frame+0xCC)
                            if result and pointer and units>=2:
                                version_text(runtime,destination,capacity,pointer,units)
                    if all(not destination or not capacity or memory.load(destination,1) for destination,capacity,key in fields):
                        break
        _invoke(runtime,0x3E94F90,buffer)
    memory.unmap(frame)
    return None


def version_outputs(runtime, source, company, company_capacity, product, product_capacity, version, version_capacity):
    if not source:
        return None
    for destination,capacity in ((company,company_capacity),(product,product_capacity),(version,version_capacity)):
        if destination and capacity:
            runtime.memory.store(destination,0,1,source='35EDC70.initial_version_output')
    return version_resources(runtime,source,company,company_capacity,product,product_capacity,version,version_capacity)


def _utf8_copy(runtime, string, source, destination, capacity):
    utf8_string(runtime,string,source)
    bounded_copy(runtime,destination,capacity,_data(runtime,string))
    _String.read(runtime,string).destroy()


def _process_times(runtime, handle, pointers):
    for pointer in pointers:
        runtime.memory.store(pointer,0,8,source='35ECC50.initial_process_FILETIME')
    return _call(runtime,'GetProcessTimes',(handle,),tuple((pointer,8) for pointer in pointers))&0xFFFFFFFF


def _image_name(runtime, handle, buffer, length):
    runtime.memory.store(length,4096,4,source='35ECC50.initial_process_path_capacity')
    return _call(runtime,'QueryFullProcessImageNameW',(handle,0,True,4096),((buffer,8192),(length,4)))&0xFFFFFFFF


def _file_attributes(runtime, path, local, destination):
    memory = runtime.memory
    memory.write(local,bytes(36),source='35ECC50.initial_file_attributes')
    if _call(runtime,'GetFileAttributesExW',(_terminated(runtime,path,2),0),((local,36),))&0xFFFFFFFF:
        memory.store(destination,(memory.load(local+28,4)<<32)|memory.load(local+32,4),8,source='35ECC50.executable_size')
        for source,offset in ((local+20,8),(local+4,16)):
            value = memory.load(source,8)
            seconds = (value-116444736000000000)//10000000 if value>=116444736000000000 else 0
            memory.store(destination+offset,seconds,8,source='35ECC50.executable_FILETIME_seconds')


def capture(runtime, destination):
    frame,rbp = _frame(runtime,0xB8,'35ECC50.process_record_frame')
    memory = runtime.memory
    if not destination:
        memory.unmap(frame)
        return None
    memory.write(destination,bytes(0x2908),source='35ECC50.zero_process_record')
    memory.store(destination,_call(runtime,'GetCurrentProcessId',())&0xFFFFFFFF,4,source='35ECC50.process_id')
    memory.store(rbp-0x20,0,8,source='35ECC50.initial_creation_time')
    handle = _call(runtime,'GetCurrentProcess',())
    _process_times(runtime,handle,(rbp-0x20,rbp-0x10,rbp+0x28,rbp-0x18))
    first = _invoke(runtime,0x3E92E00,4096,2)
    second = _invoke(runtime,0x3E92E00,4096,2)
    current = _call(runtime,'GetCurrentProcess',())
    if _image_name(runtime,current,first,rbp-0x18) and memory.load(rbp-0x18,4):
        _utf8_copy(runtime,rbp-0x10,first,destination+8,1024)
        basename(runtime,destination+8,destination+0x408,512)
        selected = second if rewrite_system32(runtime,first,second,4096) else first
        _file_attributes(runtime,selected,rbp-0x10,destination+0x608)
    _invoke(runtime,0x3E94F90,first)
    _invoke(runtime,0x3E94F90,second)
    command,images = _observe(runtime,'GetCommandLineW',())
    _images(runtime,images)
    if command:
        _utf8_copy(runtime,rbp-0x10,command,destination+0xB60,1024)
    length = _call(runtime,'GetCurrentDirectoryW',(0,False))&0xFFFFFFFF
    if 1<=length<=32767:
        directory = _invoke(runtime,0x3E92E00,length+1,2)
        if _call(runtime,'GetCurrentDirectoryW',(length,True),((directory,2*length),))&0xFFFFFFFF:
            _utf8_copy(runtime,rbp-0x10,directory,destination+0xF60,1024)
        _invoke(runtime,0x3E94F90,directory)
    if memory.load(rbp-0x20,8):
        filetime_text(runtime,rbp-0x20,destination+0x1360,64)
    wide_string(runtime,rbp-0x10,destination+8)
    wide = _WideString.read(runtime,rbp-0x10)
    size = wide.get(8,8) if wide.get(0,1)&1 else wide.get(0,1)>>1
    if size:
        rewritten = _invoke(runtime,0x3E92E00,4096,2)
        path = _data(runtime,rbp-0x10,2)
        selected = rewritten if rewrite_system32(runtime,path,rewritten,4096) else path
        certificate_output(runtime,selected,destination+0x620,256)
        version_outputs(runtime,selected,destination+0x720,512,destination+0x920,512,destination+0xB20,64)
        _invoke(runtime,0x3E94F90,rewritten)
    wide.destroy()
    module = _call(runtime,'GetModuleHandleA',(_literal(runtime,'module')[:-1],))
    if module:
        target = _call(runtime,'GetProcAddress',(module,_literal(runtime,'procedure')[:-1]))
        if target:
            memory.write(rbp-0x10,bytes(48),source='35ECC50.initial_PROCESS_BASIC_INFORMATION')
            memory.store(rbp+0x28,0,4,source='35ECC50.initial_query_return_length')
            current = _call(runtime,'GetCurrentProcess',())
            status = _call(runtime,'NtQueryInformationProcess',(target,current,0,48),((rbp-0x10,48),(rbp+0x28,4)))&0xFFFFFFFF
            if not status&0x80000000:
                memory.store(destination+4,memory.load(rbp+0x18,4),4,source='35ECC50.parent_process_id')
    parent = memory.load(destination+4,4)
    if parent and parent!=memory.load(destination,4):
        handle = _call(runtime,'OpenProcess',(0x1000,0,parent))
        if handle:
            timed = _process_times(runtime,handle,(rbp-0x18,rbp-0x40,rbp-0x38,rbp-0x30))
            created,parent_created = memory.load(rbp-0x20,8),memory.load(rbp-0x18,8)
            if not (timed and created and parent_created and created<parent_created):
                first = _invoke(runtime,0x3E92E00,4096,2)
                second = _invoke(runtime,0x3E92E00,4096,2)
                if _image_name(runtime,handle,first,rbp-0x24) and memory.load(rbp-0x24,4):
                    _utf8_copy(runtime,rbp-0x10,first,destination+0x13A0,1024)
                    basename(runtime,destination+0x13A0,destination+0x17A0,512)
                    memory.store(destination+0x1EF8,1,1,source='35ECC50.parent_image_present')
                    selected = second if rewrite_system32(runtime,first,second,4096) else first
                    _file_attributes(runtime,selected,rbp-0x10,destination+0x19A0)
                    certificate_output(runtime,selected,destination+0x19B8,256)
                    version_outputs(runtime,selected,destination+0x1AB8,512,destination+0x1CB8,512,destination+0x1EB8,64)
                _invoke(runtime,0x3E94F90,first)
                _invoke(runtime,0x3E94F90,second)
            _call(runtime,'CloseHandle',(handle,))
    memory.unmap(frame)
    return None


def invoke(runtime, rva, values):
    functions = {0x35ECC50:(capture,1),0x3C71430:(wide_string,2),0x35ED8F0:(basename,3),
                 0x35EDA10:(filetime_text,3),0x35EDD40:(rewrite_system32,3),0x35EE0A0:(find_wide_case_insensitive,2),
                 0x35EDBB0:(certificate_output,3),0x35EE6C0:(certificate_name,3),
                 0x35EDC70:(version_outputs,7),0x35EEAA0:(version_resources,7),0x35EF450:(version_text,4)}
    if rva not in functions or len(values)!=functions[rva][1]:
        raise InputError('process record source interface argument count mismatch')
    return functions[rva][0](runtime,*values)
