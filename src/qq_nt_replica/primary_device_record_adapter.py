"""Purpose-specific host inputs for the existing device-records PrimaryVM body."""
import hashlib,json
from pathlib import Path
from .errors import InputError
from .primary_memory import PrimaryMemory
from .primary_vm import PrimaryVM,PrimarySemanticUnavailable,signed
from .primary_sign import load_program,arena_reservation
from .primary_device_record_cipher import run_primary_device_record_cipher
from .primary_worker_consumer import DeviceRecord

_HOSTS=(0x2DE942F,0x3EB2680,0x3592167,0x35922AC,0x3E92E00,0x2DE9317,0x3E98FD8,0x3E98FF0,0x4852891,0x701774,0x3EB2C10,0x3E97020,0x3E94F90,0x4903C0F,0x3EB1FE0)
class RecordCipherHost:
    def __init__(self,state17,process_id,wall_seconds,formatter_options):
        if type(state17)is not bytes or len(state17)!=17:raise InputError('consistent immutable material16/seed8 required')
        if type(process_id)is not int or not 0<=process_id<=0xFFFFFFFF:raise InputError('explicit process DWORD required')
        if type(wall_seconds)is not int or not -(1<<63)<=wall_seconds<1<<63:raise InputError('explicit signed wall seconds required')
        if type(formatter_options)is not int or formatter_options not in (0,0x24):raise PrimarySemanticUnavailable('record formatter supports explicit options0 or normal0x24 only')
        # Legacy-wide/standard-rounding bits do not affect this bounded narrow %d.
        self.state17=state17;self.pid=process_id;self.wall=wall_seconds;self.random=None
        self.memory=PrimaryMemory();self.image_base=0x180000000;self.next=0x500000000;self.owned={}
        image_raw=(Path(__file__).with_name('data')/'primary_sign_qq52230/runtime-image.json').read_bytes()
        if hashlib.sha256(image_raw).hexdigest()!='e844089712cb75d370a08339a4f743e451a328b9482b8bf98fa12f5df5d4fed3':raise InputError('fixed fresh image identity mismatch')
        segment=json.loads(image_raw)['segments'][0]
        if segment['rva']!='677E1B4' or segment['raw_bytes']!=0 or segment['section']!='.data' or segment['relocations']:raise InputError('fresh control segment mismatch')
        raw=bytes.fromhex(segment['hex'])
        if len(raw)!=12:raise InputError('fresh control segment length mismatch')
        self.memory.map(self.image_base+0x677E1B4,bytearray(raw),name='fixed fresh record control image',initialized=True)
        for start,size in ((0x6D86090,8),):
            row=next(row for row in json.loads(image_raw)['segments'] if int(row['rva'],16)<=start and start+size<=int(row['rva'],16)+len(bytes.fromhex(row['hex'])))
            offset=start-int(row['rva'],16)
            self.memory.map(self.image_base+start,bytearray(bytes.fromhex(row['hex'])[offset:offset+size]),name='fixed fresh record G controls',initialized=True)
        self.singleton=self.allocate(0x1A)
        self.memory.write(self.singleton+6,state17[:16],source='explicit consistent material16')
        self.memory.store(self.singleton+0x19,state17[16],1,source='explicit consistent seed8')
        for offset,data in ((0x4852891,b'%d\0'),(0x4903C0F,b'\0'),(0x4903C10,b'\0')):self.memory.map(self.image_base+offset,data,name='fixed record string',initialized=True)
    def allocate(self,size):
        if not 0<=size<=1<<20:raise InputError('record allocation exceeds finite domain')
        p=self.next;self.next+=max(0x1000,(size+0xFFF)&~0xFFF);self.memory.map(p,bytearray(max(size,1)),name='record algorithm storage',initialized=False);self.owned[p]=size;return p
    def free(self,p):
        if p:
            if p not in self.owned:raise InputError('record free requires owned allocation')
            self.memory.unmap(p);del self.owned[p]
    def invoke(self,vm,rva,cells,*,argument_types=None):
        args=tuple(vm.cells.value(i) for i in cells);m=self.memory
        if rva==0x2DE942F:m.store(args[0],self.pid,4,source='isolated PID');return None
        if rva==0x3592167:return self.singleton
        if rva==0x35922AC:
            if args[0]!=self.singleton:raise InputError('record mix input identity mismatch')
            raw=bytearray(m.read(self.singleton+6,16));seed=m.load(self.singleton+0x19,1)
            for i in range(16):raw[i]^=seed^((i*7)&255);seed=(seed*13+17)&255
            m.write(args[1],bytes(raw),source='existing device mix projection');return None
        if rva==0x3EB2680:m.write(args[0],bytes([args[1]&255])*args[2],source='record memset');return args[0]
        if rva==0x3EB1FE0:m.copy_disjoint(args[0],args[1],args[2],label='record memcpy');return args[0]
        if rva==0x3E92E00:
            p=self.allocate(args[0]*args[1]);m.write(p,bytes(args[0]*args[1]),source='record calloc');return p
        if rva==0x3E97020:return self.allocate(args[0])
        if rva==0x3E94F90:self.free(args[0]);return None
        if rva==0x2DE9317:
            if args[0]:m.store(args[0],self.wall&((1<<64)-1),8,source='record time')
            return self.wall&((1<<64)-1)
        if rva==0x3E98FD8:self.random=args[0]&0xFFFFFFFF;return None
        if rva==0x3E98FF0:
            if self.random is None:raise PrimarySemanticUnavailable('record rand before source srand')
            self.random=(self.random*0x343FD+0x269EC3)&0xFFFFFFFF;return self.random>>16&0x7FFF
        if rva==0x3EB2C10:
            p=args[0]
            for n in range(1<<20):
                if m.load(p+n,1)==0:return n
            raise InputError('record strlen exceeds finite backing')
        if rva==0x701774:
            if m.read(args[2],3)!=b'%d\0':raise PrimarySemanticUnavailable('record format must be source %d')
            raw=str(signed(args[3],32)).encode()
            if len(raw)>=args[1]:raise PrimarySemanticUnavailable('record formatter truncation unsupported')
            m.write(args[0],raw+b'\0',source='record decimal');return len(raw)
        raise PrimarySemanticUnavailable('unimplemented isolated record host '+hex(rva))
    def encrypt(self,records):
        try:
            if type(records)is not tuple or any(type(r)is not DeviceRecord for r in records):raise InputError('typed ordered records required')
            array=self.allocate(24*len(records));self.memory.write(array,bytes(24*len(records)),source='record input')
            for i,row in enumerate(records):
                p=self.allocate(len(row.value)+1);self.memory.write(p,row.value+b'\0',source='record input bytes')
                for off,v,w in ((0,row.key,4),(8,p,8),(16,len(row.value),4)):self.memory.store(array+i*24+off,v,w,source='record input row')
            out=self.allocate(8);length=self.allocate(4)
            program=load_program('device-records');cells=self.allocate((program.cell_count+1)*32);arena=self.allocate(arena_reservation(program))
            vm=PrimaryVM(program,self.memory,cells_address=cells,arena_address=arena,arena_size=arena_reservation(program),runtime=self)
            vm.initialize((array,len(records),out,length),tuple(self.image_base+r for r in _HOSTS));run_primary_device_record_cipher(vm)
            return self.memory.read(self.memory.load(out,8),self.memory.load(length,4))
        finally:
            for p in tuple(self.owned):self.free(p)
