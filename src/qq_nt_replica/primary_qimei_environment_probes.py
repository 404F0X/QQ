"""Fixed source56739/5A480, shared122880 and whole flag1 projections."""
from .primary_qimei_request import QimeiRequestBoundary,_integer
from .primary_qimei_storage import StorageBuffer
VMWARE_FILES=(b'C:\\WINDOWS\\system32\\drivers\\vmscsi.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\vmmouse.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\vmx_svga.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\vmxnet.sys', b'C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\vmusbmouse.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\vmrawdsk.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\vmmemctl.sys', b'C:\\Windows\\System32\\vmGuestLib.dl', b'C:\\Windows\\System32\\vmhgfs.dl', b'C:\\Windows\\System32\\vm3dservice.exe', b'C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe')
VBOX_FILES=(b'C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\VBoxSF.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\VBoxMouse.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\VBoxWddm.sys', b'C:\\WINDOWS\\system32\\DRIVERS\\VBoxVideo.sys')
SYSTEM_INFORMATION_KEYS=(br'SYSTEM\ControlSet001\Control\SystemInformation',br'SYSTEM\CurrentControlSet\Control\SystemInformation')
REGISTRY_PROBES=tuple((key,name) for key in (br'HARDWARE\DESCRIPTION\System\BIOS',)+SYSTEM_INFORMATION_KEYS for name in (b'SystemManufacturer',b'SystemProductName'))
class RedirectionCache:
    """Caller-shared source module cache bound to one owning API backend."""
    def __init__(self,port):self.port=port;self.pointer=0;self.normal_tail_completed=True
    def apply(self,enabled):
        if not self.pointer:self.pointer=self.port.resolve_redirection()
        if self.pointer:self.port.redirect(self.pointer,enabled)
class QimeiEnvironmentProbes:
    def __init__(self,cache,system):self.cache=cache;self.system=system
    def cpuid_pair(self):
        words=self.cache.port.cpuid_leaf1()
        if type(words)is not tuple or len(words)!=4 or any(type(v)is not int or not 0<=v<=0xFFFFFFFF for v in words):raise QimeiRequestBoundary('actual four CPUID DWORDs required')
        return (3,1) if words[2]&0x80000000 else (0,0)
    def _run(self,paths,registry):
        self.cache.normal_tail_completed=False
        self.cache.apply(False)
        hit=0
        for path in paths:
            if _integer(self.cache.port.path_exists(path))&0xFFFFFFFF:hit=1;break
        if not hit and registry:
            for key,name in REGISTRY_PROBES:
                code,data=self.system.registry_value(key,name,StorageBuffer(bytes(260)))
                if code==0:
                    raw=data.read();end=raw.find(b'\0')
                    if end<0:raise QimeiRequestBoundary('successful probe String exceeds actual NUL backing')
                    if b'VMware' in raw[:end]:hit=1;break
        self.cache.apply(True)
        self.cache.normal_tail_completed=True
        return hit
    def vmware(self):return self._run(VMWARE_FILES,True)
    def virtualbox(self):return self._run(VBOX_FILES,False)

    def debugger(self):
        port=self.cache.port
        local=port.debugger_present()
        if local is not None and _integer(local)&0xFFFFFFFF:return 1
        remote=port.remote_debugger()
        if remote is not None and _integer(remote)&0xFFFFFFFF:return 2
        kernel=port.kernel_debugger()
        if kernel is not None:
            status,data=kernel
            if type(data)is not bytes or len(data)!=2:raise QimeiRequestBoundary('actual two-byte debugger information required')
            status=_integer(status)&0xFFFFFFFF
            if status<0x80000000 and data[1]==0:return 3
        accepted,registers=port.debug_registers()
        if len(registers)!=4 or any(type(v)is not int or not 0<=v<=0xFFFFFFFFFFFFFFFF for v in registers):raise QimeiRequestBoundary('actual four debug QWORDs required')
        return 6 if _integer(accepted)&0xFFFFFFFF and any(registers) else 0
