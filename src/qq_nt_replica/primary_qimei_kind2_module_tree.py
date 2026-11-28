"""Fixed Qimei 52230 92542(flags0x32,sleep0) module treeA producer."""
from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
SOURCE_SHA256 = 'a6100bce0de79ea52fe80a85acce2c24c615306fd3c2dedd119b51b0f26ebcc6'
PATTERNS = (b':\\program files (x86)\\microsoft\\', b':\\program files (x86)\\microsoft visual studio\\', b':\\program files (x86)\\cisco\\', b':\\program files (x86)\\tencent\\', b':\\program files (x86)\\wxwork\\', b':\\program files (x86)\\ioa\\', b':\\program files (x86)\\360\\', b':\\program files (x86)\\bonjour\\', b':\\program files (x86)\\sogouinput\\', b':\\program files (x86)\\nvidia corporation\\', b':\\program files (x86)\\kingsoft\\', b':\\program files (x86)\\sangfor\\', b':\\program files (x86)\\windows defender\\', b':\\program files (x86)\\qianxin\\tianqing\\', b':\\program files (x86)\\common files\\microsoft shared\\', b':\\program files\\huawei\\', b':\\program files\\common files\\microsoft shared\\', b':\\program files\\microsoft office\\', b':\\program files\\windowsapps\\microsoft', b':\\program files\\microsoft vs code\\', b':\\program files\\microsoft visual studio\\', b':\\program files\\bonjour\\', b':\\program files\\mcafee\\', b':\\program files\\windows defender\\', b':\\program files\\nvidia corporation\\', b':\\program files\\360\\', b':\\program files\\internet explorer\\', b':\\windows\\systemapps\\', b':\\windows\\microsoft.net\\', b':\\windows\\winsxs\\', b':\\windows\\apppatch\\', b':\\windows\\netease\\', b':\\windows\\explorer.exe', b':\\windows\\sysmon.exe', b':\\windows\\servicing\\trustedinstaller.exe', b':\\windows\\immersivecontrolpanel\\systemsettings.exe', b':\\windows\\cxsvc\\cxaudiosvc.exe', b':\\windows\\system32\\', b':\\windows\\syswow64\\', b':\\programdata\\microsoft\\', b':\\programdata\\a-volute\\', b':\\inetpub\\ftproot\\', b':\\360safe\\safemon\\')


def _lower(value, indicator):
    if type(indicator) is not int or indicator != 0:
        raise PrimarySemanticUnavailable('Qimei source CRT1249E0 nonzero lowercase branch is unrecovered')
    return bytes(byte+32 if 65 <= byte <= 90 else byte for byte in value)


def filter_fixed(path, *, crt_lowercase_indicator):
    value=_lower(path,crt_lowercase_indicator)
    found=value.find(b'?\\')
    if found>=0:value=value[found+2:]
    return len(value)>=2 and any(value[1:].startswith(pattern) for pattern in PATTERNS)


def _cstring(buffer):
    try:end=buffer.index(0)
    except ValueError:raise InputError('module path lacks an actual backed NUL') from None
    return bytes(buffer[:end])


def _dword(value):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise InputError('module API requires an actual DWORD')
    return value


def filter_executable(port,path, *, crt_lowercase_indicator):
    buffer=bytearray(260)
    returned=_dword(port.call('GetModuleFileNameA',0,buffer,260))
    directory=_cstring(buffer) if returned else b''
    slash=directory.rfind(b'\\')
    if slash>=0:directory=directory[:slash+1]
    directory=_lower(directory,crt_lowercase_indicator);value=_lower(path,crt_lowercase_indicator)
    if value.startswith(directory):return True
    for part in (b'\\qq\\',b'\\sogouinput\\'):
        found=directory.find(part)
        if found>=0 and value.startswith(directory[:found+len(part)]):return True
    return False


def produce_module_tree(port, *, crt_lowercase_indicator):
    """Explicit CRT state is required; no real caller binding is established."""
    pid=_dword(port.call('GetCurrentProcessId'))
    handle=port.call('OpenProcess',0x410,0,pid)
    if type(handle) is not int or not 0 <= handle < (1<<64):
        raise InputError('module OpenProcess requires backed HANDLE')
    if not handle:return ()
    modules=bytearray(8192);needed=bytearray(4)
    status=port.call('EnumProcessModules',handle,modules,8192,needed)
    if type(status) is not int or not -(1<<31) <= status < (1<<32):
        raise InputError('module enumeration requires BOOL DWORD')
    output=set()
    if status & 0xFFFFFFFF:
        count=int.from_bytes(needed,'little')
        if len(modules)!=8192 or len(needed)!=4 or count>8192:
            raise PrimarySemanticUnavailable('module enumeration exceeds actual HMODULE backing')
        for offset in range(0,(count>>3)*8,8):
            module=int.from_bytes(modules[offset:offset+8],'little');buffer=bytearray(260)
            returned=_dword(port.call('GetModuleFileNameExA',handle,module,buffer,260))
            if returned and buffer[0]:
                path=_cstring(buffer)
                if filter_fixed(path,crt_lowercase_indicator=crt_lowercase_indicator):continue
                if filter_executable(port,path,crt_lowercase_indicator=crt_lowercase_indicator):continue
                output.add(memoryview(path).tobytes())
    port.call('CloseHandle',handle)
    return tuple(sorted(output))
