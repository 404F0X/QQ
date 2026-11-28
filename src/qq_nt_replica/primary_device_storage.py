from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import secrets

from .errors import InputError
from .primary_device import device_material, encode_checkpoint, encode_profile


@dataclass(frozen=True)
class CheckpointRead:
    value: bytes | None
    error: int | None = None
    internal_error: int | None = None
    created: bool = False


@dataclass(frozen=True)
class CheckpointWrite:
    success: bool
    error: int | None = None


class MemoryCheckpointStorage:
    def __init__(self, value=None, *, profile=None):
        if value is not None and not isinstance(value, bytes):
            raise InputError("memory checkpoint must be exact file bytes or absent")
        self.value = value
        self.profile = profile
        self.reads = 0
        self.writes = 0

    def ensure_directory(self):
        return None

    def read(self):
        self.reads += 1
        return CheckpointRead(self.value[:1028] if self.value is not None else None,
                              None if self.value is not None else 2)

    def read_profile(self):
        if self.profile is None:
            return CheckpointRead(None, 2, 0x13)
        if not isinstance(self.profile, bytes):
            raise InputError("memory profile.dat2 requires raw observed bytes")
        return (CheckpointRead(self.profile) if len(self.profile) == 50 else
                CheckpointRead(None, 0, 0x12))

    def write(self, value):
        if not isinstance(value, bytes) or len(value) != 1028:
            raise InputError("checkpoint storage writes exactly 1028 file bytes")
        self.value = value
        self.writes += 1

    def write_record(self, record, random_bytes):
        self.write(encode_checkpoint(record, random_bytes))
        return CheckpointWrite(True)


class DirectoryCheckpointStorage:
    def __init__(self, common_appdata):
        self.directory = Path(common_appdata) / "xfolder"
        self.path = self.directory / "checkpoint.dat"
        self.profile_path = self.directory / "profile.dat2"

    def ensure_directory(self):
        if os.name == "nt":
            _WindowsCheckpointFiles().ensure_directory(self.directory)
        else:
            self.directory.mkdir(exist_ok=True)

    def read(self):
        if os.name == "nt":
            return _WindowsCheckpointFiles().read(self.path)
        try:
            with self.path.open("rb") as stream:
                return CheckpointRead(stream.read(1028))
        except OSError as error:
            return CheckpointRead(None, getattr(error, "winerror", None) or error.errno)

    def write(self, value):
        if not isinstance(value, bytes) or len(value) != 1028:
            raise InputError("checkpoint storage writes exactly 1028 file bytes")
        self.ensure_directory()
        if os.name == "nt":
            _WindowsCheckpointFiles().write(self.path, value)
            return
        with self.path.open("wb") as stream:
            written = stream.write(value)
            if written != len(value):
                raise OSError("short checkpoint write")

    def write_record(self, record, random_bytes):
        if os.name == "nt":
            return _WindowsCheckpointFiles().write_record(self.path, record, random_bytes)
        try:
            stream = self.path.open("wb")
        except OSError:
            return CheckpointWrite(False, 0x18)
        try:
            with stream:
                packet = encode_checkpoint(record, random_bytes)
                if stream.write(packet) != 1028:
                    return CheckpointWrite(False, 0x19)
        except OSError:
            return CheckpointWrite(False, 0x19)
        return CheckpointWrite(True)

    def read_profile(self, *, random_bytes=None):
        if os.name == "nt":
            return _WindowsCheckpointFiles().read_profile(self.profile_path, random_bytes or secrets.token_bytes)
        try:
            stream = self.profile_path.open("rb")
        except OSError as error:
            return CheckpointRead(None, error.errno, 0x13)
        with stream:
            if os.fstat(stream.fileno()).st_size != 50:
                return CheckpointRead(None, 0, 0x12)
            value = stream.read(50)
            return CheckpointRead(value) if len(value) == 50 else CheckpointRead(None, 0, 0x12)


class _WindowsCheckpointFiles:
    def __init__(self):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        pointer = ctypes.c_void_p
        self.create = self.kernel.CreateFileA
        self.create.argtypes = (wintypes.LPCSTR, wintypes.DWORD, wintypes.DWORD, pointer,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        self.create.restype = wintypes.HANDLE
        self.close = self.kernel.CloseHandle
        self.close.argtypes, self.close.restype = (wintypes.HANDLE,), wintypes.BOOL
        for name in ("ReadFile", "WriteFile"):
            function = getattr(self.kernel, name)
            function.argtypes = (wintypes.HANDLE, pointer, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), pointer)
            function.restype = wintypes.BOOL
        self.attributes = self.kernel.GetFileAttributesA
        self.attributes.argtypes, self.attributes.restype = (wintypes.LPCSTR,), wintypes.DWORD
        self.mkdir = self.kernel.CreateDirectoryA
        self.mkdir.argtypes, self.mkdir.restype = (wintypes.LPCSTR, pointer), wintypes.BOOL
        self.size = self.kernel.GetFileSize
        self.size.argtypes, self.size.restype = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)), wintypes.DWORD
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.acquire = self.advapi.CryptAcquireContextW
        self.acquire.argtypes = (ctypes.POINTER(ctypes.c_size_t), wintypes.LPCWSTR, wintypes.LPCWSTR,
                                 wintypes.DWORD, wintypes.DWORD)
        self.acquire.restype = wintypes.BOOL
        self.generate = self.advapi.CryptGenRandom
        self.generate.argtypes = (ctypes.c_size_t, wintypes.DWORD, pointer)
        self.generate.restype = wintypes.BOOL
        self.release = self.advapi.CryptReleaseContext
        self.release.argtypes, self.release.restype = (ctypes.c_size_t, wintypes.DWORD), wintypes.BOOL

    def ensure_directory(self, directory):
        path = str(directory).encode("mbcs")
        attributes = self.attributes(path)
        if attributes == 0xFFFFFFFF or not attributes & 0x10:
            if not self.mkdir(path, None):
                raise ctypes.WinError(ctypes.get_last_error())

    def read(self, path):
        handle = self.create(str(path).encode("mbcs"), 0x80000000, 1, None, 3, 2, None)
        if handle == ctypes.c_void_p(-1).value:
            return CheckpointRead(None, ctypes.get_last_error())
        try:
            output, size = ctypes.create_string_buffer(1028), wintypes.DWORD()
            self.kernel.ReadFile(handle, output, 1028, ctypes.byref(size), None)
            return CheckpointRead(output.raw[:size.value])
        finally:
            self.close(handle)

    def write(self, path, value):
        handle = self.create(str(path).encode("mbcs"), 0x40000000, 0, None, 2, 2, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            data, size = ctypes.create_string_buffer(value), wintypes.DWORD()
            if not self.kernel.WriteFile(handle, data, 1028, ctypes.byref(size), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if size.value != 1028:
                raise OSError("short checkpoint write")
        finally:
            self.close(handle)

    def write_record(self, path, record, random_bytes):
        handle = self.create(str(path).encode("mbcs"), 0x40000000, 0, None, 2, 2, None)
        if handle == ctypes.c_void_p(-1).value:
            return CheckpointWrite(False, 0x18)
        try:
            value = encode_checkpoint(record, random_bytes)
            data, size = ctypes.create_string_buffer(value), wintypes.DWORD()
            succeeded = self.kernel.WriteFile(handle, data, 1028, ctypes.byref(size), None)
            return CheckpointWrite(True) if succeeded and size.value == 1028 else CheckpointWrite(False, 0x19)
        finally:
            self.close(handle)

    def _new_profile(self, random_bytes):
        handle = ctypes.c_size_t()
        if not self.acquire(ctypes.byref(handle), None, None, 1, 0xF0000040):
            raise RuntimeError("profile random_device acquisition failed")
        raw = ctypes.create_string_buffer(16)
        try:
            if not self.generate(handle.value, 16, raw):
                raise RuntimeError("profile random_device generation failed")
        finally:
            self.release(handle.value, 0)
        seed = bytearray(raw.raw)
        seed[6] = (seed[6] & 15) | 64
        seed[8] = (seed[8] & 63) | 128
        return encode_profile(device_material(bytes(seed)), random_bytes)

    def read_profile(self, path, random_bytes):
        encoded = str(path).encode("mbcs")
        missing = self.attributes(encoded) == 0xFFFFFFFF
        packet = self._new_profile(random_bytes) if missing else None
        access, share, creation = (0x40000000, 0, 1) if missing else (0x80000000, 1, 3)
        handle = self.create(encoded, access, share, None, creation, 2, None)
        if handle == ctypes.c_void_p(-1).value:
            return CheckpointRead(None, ctypes.get_last_error(), 0x10 if missing else 0x13)
        value, error = None, None
        try:
            if missing:
                data, size = ctypes.create_string_buffer(packet), wintypes.DWORD()
                succeeded = self.kernel.WriteFile(handle, data, 50, ctypes.byref(size), None)
                if succeeded and size.value == 50:
                    value = packet
                else:
                    error = 0x11
            elif self.size(handle, None) != 50:
                error = 0x12
            else:
                output, size = ctypes.create_string_buffer(50), wintypes.DWORD()
                self.kernel.ReadFile(handle, output, 50, ctypes.byref(size), None)
                if size.value == 50:
                    value = output.raw
                else:
                    error = 0x12
        finally:
            self.close(handle)
        return CheckpointRead(value, ctypes.get_last_error(), error, missing and value is not None)
