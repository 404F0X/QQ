"""Fixed wrapper63112... C6EBEA legacy selector, not DB import/decoding."""
from .errors import InputError
SOURCE_SHA256='63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0'
def _bool(value):
    if type(value)is not int or not -(1<<31)<=value<(1<<32):raise InputError('actual BOOL DWORD required')
    return bool(value&0xFFFFFFFF)
def _cstring(buffer,size):
    if len(buffer)!=size:raise InputError('legacy path backing size changed')
    try:return bytes(buffer[:buffer.index(0)])
    except ValueError:raise InputError('legacy path lacks backed NUL') from None
def select_legacy_path(port):
    folder=bytearray(260)
    if not _bool(port.call('SHGetSpecialFolderPathA',0,folder,0x2E,0)):return b''
    ini=_cstring(folder,260)+b'\\Tencent\\QQ\\UserDataInfo.ini'
    root=bytearray(261)
    port.call('GetPrivateProfileStringA',b'UserDataSet',b'UserDataSavePath',b'',root,260,ini)
    root=_cstring(root,261)
    for product in (b'QQ',b'TIM'):
        path=root+b'\\All Users\\'+product+b'\\Registry2.0.db'
        if _bool(port.call('PathFileExistsA',path)):return memoryview(path).tobytes()
    folder=bytearray(260)
    port.call('SHGetSpecialFolderPathA',0,folder,5,0)
    base=_cstring(folder,260)+b'\\Tencent Files\\All Users\\'
    path=base+b'QQ\\Registry2.0.db'
    if _bool(port.call('PathFileExistsA',path)):return memoryview(path).tobytes()
    return base+b'TIM\\Registry2.0.db'
def legacy_import_precheck(port,path):
    """C6DB51 separate existence check; TRUE does not establish import success."""
    return _bool(port.call('PathFileExistsA',path))
