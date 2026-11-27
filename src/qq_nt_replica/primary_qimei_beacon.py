"""Normal AA02C beacon inputs; no native calls at import/construction."""
from dataclasses import dataclass, field
from .primary_qimei_context import QimeiSelectorState
from .primary_qimei_extra_sources import QimeiExtraSources
from .primary_qimei_request import QimeiRequestBoundary
from .primary_qimei_storage import NtStorageProbe, StorageBuffer


@dataclass(frozen=True)
class BeaconInputs:
    selected6: bytes = field(repr=False)
    storage: tuple = field(repr=False)
    brand: bytes = field(repr=False)
    selector_status: int
    storage_status: int
    cpu_status: int


class QimeiBeaconInputProducer:
    """Source order7E138→7C724(R9B1)→7B098; exceptions remain errors."""
    _api = QimeiExtraSources._api

    def __init__(self, selector, selector_observations, storage_observations, cpu_observations):
        if not isinstance(selector, QimeiSelectorState):
            raise QimeiRequestBoundary('source selector state required')
        self.selector = selector
        self.selector_observations = selector_observations
        self.storage_observations = storage_observations
        self.observations = cpu_observations

    def produce(self):
        selected = self.selector.select(self.selector_observations)
        # 7F653 sets AL1 on every ordinary return, including compiled-selected6.
        selector_status = 1
        probe = NtStorageProbe(swap_serial=True)
        storage_result = probe.produce(self.storage_observations)
        storage_status = int(storage_result is not None)
        storage = tuple(probe.outputs)
        if any(type(value) is not bytes for value in storage):
            raise QimeiRequestBoundary('beacon storage partial output is unknown')
        brand = bytearray()
        for leaf in (0x80000002, 0x80000003, 0x80000004):
            data = StorageBuffer.unknown(16)
            unused, output = self._api('CPUID', (leaf, 0, data), {'data': data})
            brand.extend(output['data'].read())
        if len(brand) != 48:
            raise QimeiRequestBoundary('beacon CPUID requires three complete register sets')
        brand = bytes(brand).split(b'\0', 1)[0]
        return BeaconInputs(selected, storage, brand, selector_status, storage_status, int(bool(brand)))


import hashlib
import re
from threading import RLock


def _ascii(value):
    if type(value) is not bytes or any(byte>=128 for byte in value):
        raise QimeiRequestBoundary('beacon nonASCII/locale semantics unavailable')
    return value.split(b'\0',1)[0]


def scan_pairs(value):
    """A8B16 initialized accumulator, including carry after failed ASCII scans."""
    value=_ascii(value)
    if len(value)!=32:raise QimeiRequestBoundary('scanner requires32 readable bytes')
    result=bytearray();accumulator=0
    for offset in range(0,32,2):
        part=value[offset:offset+2].lstrip()
        match=re.match(rb'([+-]?)([0-9a-fA-F]+)',part)
        if match:
            accumulator=int(match[2],16)*(-1 if match[1]==b'-' else 1)&0xffffffff
        result.append(accumulator&255)
    return bytes(result)


def validate(inputs,old,output):
    selector=_ascii(inputs.selected6.hex().encode())
    storage=b''.join(_ascii(value) for value in inputs.storage)
    brand=_ascii(inputs.brand)
    md5=lambda value:hashlib.md5(value).hexdigest().encode()
    digests=(md5(selector) if inputs.selector_status else b'',
             md5(storage) if inputs.storage_status else b'',md5(brand) if inputs.cpu_status else b'')
    strings=tuple(_ascii(value) for value in old[:4]);flag=old[4]
    equal=all(strings[index].lower()==digests[index-1].lower() for index in (3,1,2))
    if equal:
        if len(strings[0])!=32:return False,False,digests
        output[:]=scan_pairs(strings[0])
    total=inputs.selector_status+inputs.storage_status+inputs.cpu_status
    present=sum(bool(value) for value in strings[1:])
    accepted=equal and total<=present
    if flag or not inputs.selector_status:return accepted,False,digests
    if not strings[1] or not strings[2] or total==3:return False,False,digests
    if total<present:return False,True,digests
    return accepted,False,digests


class QimeiBeacon:
    """One instance per source module epoch; no owner-keyed reset or retry."""
    def __init__(self,producer,backend):
        self.producer,self.backend=producer,backend
        self._raw=bytearray(16)  # Actual mapped132000 initial bytes.
        self._once=0;self._lock=RLock()

    def raw(self, *, backend=None, producer=None):
        backend = self.backend if backend is None else backend
        producer = self.producer if producer is None else producer
        with self._lock:
            backend.check()
            if self._once==1:return bytes(self._raw)
            if self._once:raise QimeiRequestBoundary('beacon once incomplete after host exception')
            self._once=0xff
            inputs=producer.produce()
            if inputs.selector_status!=1:raise QimeiRequestBoundary('non-normal selector return unavailable')
            handle,path,status=backend.open_main()
            add_cpu=False
            try:
                if handle is not None and status==0x50:
                    accepted,add_cpu,digests=validate(inputs,backend.read_config(path),self._raw)
                else:accepted=False;digests=None
                if not accepted:
                    text=inputs.selected6.hex().encode()
                    if inputs.storage_status:text+=b''.join(_ascii(v) for v in inputs.storage)
                    if add_cpu:text+=_ascii(inputs.brand)
                    self._raw[:]=hashlib.md5(text).digest()
                    if digests is None:
                        unused,unused2,digests=validate(inputs,(b'',b'',b'',b'',1),bytearray(16))
                    if handle is not None:backend.persist(handle,path,bytes(self._raw),digests)
            finally:
                if handle is not None:backend.close(handle)
            self._once=1
            return bytes(self._raw)

    def refresh(self, *, backend=None, producer=None):
        backend = self.backend if backend is None else backend
        backend.check()
        value=backend.read_outer()
        if value is None:return self.raw(backend=backend, producer=producer).hex().encode()
        value=_ascii(value)
        if len(value)!=32:return self.raw(backend=backend, producer=producer).hex().encode()
        if any(byte not in b'0123456789abcdefABCDEF' for byte in value):
            raise QimeiRequestBoundary('outer6914D malformed/unwritten scanf domain unavailable')
        return bytes.fromhex(value.decode()).hex().encode()
