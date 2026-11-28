"""Independent record request generation; no receiver admission or send."""
from dataclasses import dataclass
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_worker_consumer import serialize_device_records
from .primary_request_material import RequestMaterialState,RequestMaterial

@dataclass(frozen=True,repr=False)
class SdkRecordRequest:
    command: bytes
    body: bytes
    sdk_sequence: int
    encoded: object
    decode_material: RequestMaterial
    serialized_records: bytes

def create_record_request(records,metadata,*,feature46,tag,material_state,sdk_sequence,a2,commands,encoding_inputs,cipher_inputs=None):
    """Explicit resolved A2; SDK sequence is distinct from message_id/wire sequence.

    Retains this request's immutable material snapshot for subsequent decoding.
    No pending state, response receipt or native receiver qualification is created.
    """
    if type(feature46) is not int or not 0<=feature46<=0xFFFFFFFF:
        raise InputError('explicit observed feature46 DWORD required')
    if type(a2) is not bool or type(commands) is not tuple or len(commands)!=4 or any(type(x)is not bytes or not x for x in commands):
        raise InputError('resolved A2 and four initialized commands required')
    if type(sdk_sequence)is not int or not 0<=sdk_sequence<=0xFFFFFFFFFFFFFFFF:
        raise InputError('explicit SDK sequence required')
    if not isinstance(material_state,RequestMaterialState) or type(encoding_inputs)is not dict:
        raise InputError('material state and explicit encoding inputs required')
    stage=encode_record_request(records,metadata,feature46=feature46,tag=tag,material_state=material_state,
        encoding_inputs=encoding_inputs,cipher_inputs=cipher_inputs)
    return finish_record_request(stage,sdk_sequence=sdk_sequence,a2=a2,commands=commands)

@dataclass(frozen=True,repr=False)
class EncodedRecordRequest:
    encoded: object
    decode_material: RequestMaterial
    serialized_records: bytes

def encode_record_request(records,metadata,*,feature46,tag,material_state,encoding_inputs,cipher_inputs=None):
    if type(feature46) is not int or not 0<=feature46<=0xFFFFFFFF:
        raise InputError('explicit observed feature46 DWORD required')
    if not isinstance(material_state,RequestMaterialState) or type(encoding_inputs)is not dict:
        raise InputError('material state and explicit encoding inputs required')
    encrypted=b''
    if feature46==1:
        if type(cipher_inputs)is not dict:
            raise PrimarySemanticUnavailable('feature46 ON requires explicit consistent17B/PID/time/formatter inputs')
        from .primary_device_record_cipher import encrypt_device_records
        encrypted=encrypt_device_records(records,**cipher_inputs)
    payload=serialize_device_records(records,metadata,encrypted)
    encoded=material_state.encode(tag,payload,**encoding_inputs)
    return EncodedRecordRequest(encoded,material_state.current,payload)

def finish_record_request(stage,*,sdk_sequence,a2,commands):
    if type(a2) is not bool or type(commands) is not tuple or len(commands)!=4 or any(type(x)is not bytes or not x for x in commands):
        raise InputError('resolved A2 and four initialized commands required')
    if type(sdk_sequence)is not int or not 0<=sdk_sequence<=0xFFFFFFFFFFFFFFFF:
        raise InputError('explicit SDK sequence required')
    encoded=stage.encoded
    command=commands[int(a2)*2+int(encoded.status==0)]
    return SdkRecordRequest(command,encoded.request.wire,sdk_sequence,encoded,stage.decode_material,stage.serialized_records)
