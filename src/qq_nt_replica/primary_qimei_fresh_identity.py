"""Own device policy; not native MSF restoration or server acceptance proof."""
import hashlib
import json
import os
from pathlib import Path
import threading

from .primary_qimei_application import QimeiApplication
from .primary_qimei_request import QimeiRequestBoundary

POLICY = 'OWN_FRESH_HARDWARE_IDENTITY/wrapper63112-C6D07C-v1'


def source_cpu_string(registers):
    if len(registers) != 3 or any(len(row) != 4 for row in registers):
        raise QimeiRequestBoundary('three fixed CPUID register quadruples required')
    if any(type(x) is not int or not 0 <= x <= 0xffffffff for row in registers for x in row):
        raise QimeiRequestBoundary('CPUID registers must be DWORDs')
    raw = b''.join(x.to_bytes(4, 'little') for row in registers for x in row) + b'\0'
    return raw.split(b'\0', 1)[0] if raw[0] else b' '


def source_digest(disk, cpu, third):
    if any(type(x) is not bytes for x in (disk, cpu, third)):
        raise QimeiRequestBoundary('Source hardware strings require bytes')
    return hashlib.md5(disk + cpu + third).digest()


class OwnFreshHardwareIdentity:
    def __init__(self, profile_path, machine_info_path, hardware):
        self.profile_path = Path(profile_path)
        self.machine_info_path = Path(machine_info_path)
        self.hardware = hardware
        self._owner = os.getpid(), threading.get_native_id()
        self._application = None
        self.failure = None
        self.persisted_prefix = b''
        self.closed = False

    def _check(self):
        if self.closed or self._owner != (os.getpid(), threading.get_native_id()):
            raise QimeiRequestBoundary('identity requires open creator process/thread')

    def application(self):
        self._check()
        if self.failure is not None:
            raise QimeiRequestBoundary('first identity attempt failed; no resampling') from self.failure
        if self._application is not None:
            return self._application
        try:
            binding = str(self.profile_path.absolute())
            try:
                with self.profile_path.open('rb') as stream:
                    raw = stream.read(8193)
            except FileNotFoundError:
                # Only an absent leaf with an existing directory qualifies as fresh.
                if not self.profile_path.parent.is_dir() or self.profile_path.is_symlink():
                    raise QimeiRequestBoundary('profile absence is not qualified')
                try:
                    self.machine_info_path.lstat()
                except FileNotFoundError:
                    if not self.machine_info_path.parent.is_dir():
                        raise QimeiRequestBoundary('machine-info parent absent')
                else:
                    raise QimeiRequestBoundary('existing machine-info outside fresh policy')
                disk, cpu, third = self.hardware.strings()
                guid = source_digest(disk, cpu, third)
                raw = json.dumps(dict(format='OwnQimeiDevice', version=1, policy=POLICY,
                                      device_binding=binding, guid=guid.hex()), sort_keys=True).encode('ascii')
                # Exclusive creation refuses a concurrent profile; never overwrite.
                with self.profile_path.open('xb', buffering=0) as stream:
                    offset = 0
                    while offset < len(raw):
                        count = stream.write(raw[offset:])
                        if not count:
                            raise OSError('profile write made no progress')
                        offset += count
                        self.persisted_prefix = raw[:offset]
                    os.fsync(stream.fileno())
            else:
                if len(raw) > 8192:
                    raise QimeiRequestBoundary('oversized Own profile')
                record = json.loads(raw)
                if (set(record) != {'format', 'version', 'policy', 'device_binding', 'guid'} or
                        record['format'] != 'OwnQimeiDevice' or type(record['version']) is not int or
                        record['version'] != 1 or record['policy'] != POLICY or record['device_binding'] != binding or
                        type(record['guid']) is not str or len(record['guid']) != 32 or
                        any(c not in '0123456789abcdef' for c in record['guid'])):
                    raise QimeiRequestBoundary('invalid or unsupported Own profile')
                guid = bytes.fromhex(record['guid'])
            self._application = QimeiApplication(guid)
            return self._application
        except Exception as error:
            self.failure = error
            raise

    def close(self):
        if self.closed:
            return
        self._check()
        self.hardware.close()
        self.closed = True
